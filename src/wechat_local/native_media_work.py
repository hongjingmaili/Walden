"""Bounded native media backlog and persistent, local-only result cache.
The message poll only enqueues; this owned child performs capture/decode/ASR.
"""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
from .native_deadline import check_deadline
from .native_mirror_store import MirrorError
from .native_mirror_sync import mirror_root
from .live_readonly import readonly_database_uri

VERSION='local-media-v1-small-1be3a9b2'
BATCH=32
MAX_ATTEMPTS=3
RETRY_SECONDS=(30,120,600)


def _json(v):return json.dumps(v,sort_keys=True,separators=(',',':'))
def _binding(config):
    from .native_scope_contract import mode,binding,query_scope_guard
    query_scope_guard(config)
    if mode(config)=='account':
        if (Path(config['mirror_root'])/'request-window.json').exists():raise MirrorError('media_store_binding')
        return _json(binding(config))
    base=[config['account_id'],config['source_generation'],config['mirror_scope']]
    # Window authority belongs to the existing protected request proof, never
    # to an unknown SourceConfig key. Ordinary daily stores have no such proof.
    from .native_follow_policy import Store
    proof=Store(config['mirror_root']).read('request-window.json')
    if proof is not None:
        from .native_target_request import window_spec
        binding=proof.get('binding') if type(proof) is dict else None
        if type(binding) is not list or len(binding)!=4 or len(config['mirror_scope'])!=1 or binding[:3]!=base[:2]+[config['mirror_scope'][0]]:raise MirrorError('media_store_binding')
        window=binding[3]
        if type(window) is not dict or window.get('kind') not in ('latest','date'):raise MirrorError('media_store_binding')
        try:
            canonical=window_spec(latest=window.get('limit')) if window['kind']=='latest' else window_spec(since=window.get('since'),until=window.get('until'),timezone=window.get('timezone'))
        except (ValueError,TypeError,KeyError,MirrorError):raise MirrorError('media_store_binding') from None
        if canonical!=window:raise MirrorError('media_store_binding')
        base.append(window)
    return _json(base)

def media_key(source):return hashlib.sha256(_json(source).encode()).hexdigest()


def _connect(config,write=False):
    import stat
    from .native_scope_contract import query_scope_guard
    token=query_scope_guard(config)
    root=mirror_root(config,create=False);path=root/'media-work.sqlite'
    if path.is_symlink():raise MirrorError('media_store_binding')
    if not write and not path.is_file():return None
    if write:
        fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        try:info=os.fstat(fd)
        finally:os.close(fd)
    else:info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:
        raise MirrorError('media_store_binding')
    class Guarded(sqlite3.Connection):
        def commit(self):
            query_scope_guard(config,token);value=super().commit();query_scope_guard(config,token);return value
        def executescript(self,sql):
            query_scope_guard(config,token);value=super().executescript(sql);query_scope_guard(config,token);return value
        def __exit__(self,*args):
            try:query_scope_guard(config,token)
            except BaseException:super().rollback();raise
            value=super().__exit__(*args);query_scope_guard(config,token);return value
    query_scope_guard(config,token)
    c=sqlite3.connect(str(path) if write else readonly_database_uri(path),uri=not write,timeout=.1,factory=Guarded)
    try:
        # An existing foreign sidecar is rejected before DDL, chmod or any write.
        if info.st_size and c.execute('SELECT value FROM binding').fetchall()!=[(_binding(config),)]:raise MirrorError('media_store_binding')
        if write:
            c.executescript('CREATE TABLE IF NOT EXISTS binding(id INTEGER PRIMARY KEY CHECK(id=1),value TEXT NOT NULL);'
                'CREATE TABLE IF NOT EXISTS jobs(key TEXT PRIMARY KEY,username TEXT NOT NULL,source TEXT NOT NULL,kind TEXT NOT NULL,'
                'status TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,due REAL NOT NULL DEFAULT 0,lease REAL NOT NULL DEFAULT 0,result TEXT,reason TEXT,version TEXT NOT NULL);'
                'CREATE INDEX IF NOT EXISTS media_due ON jobs(status,due);'
                'CREATE TABLE IF NOT EXISTS checkpoints(shard TEXT,table_name TEXT,local_id INTEGER NOT NULL,PRIMARY KEY(shard,table_name));'
                'CREATE TABLE IF NOT EXISTS transcripts(payload_sha TEXT,version TEXT,status TEXT NOT NULL,result TEXT,PRIMARY KEY(payload_sha,version));')
            c.execute('INSERT OR IGNORE INTO binding(id,value) VALUES(1,?)',(_binding(config),));c.commit()
        else:c.execute('PRAGMA query_only=ON')
        if c.execute('SELECT value FROM binding').fetchall()!=[(_binding(config),)]:raise MirrorError('media_store_binding')
        query_scope_guard(config,token)
        return c
    except BaseException:c.close();raise


def _media_authorized(config,username,source):
    from .native_scope_contract import mode,authorized
    if mode(config)=='selected':
        if username not in config['mirror_scope']:raise MirrorError('media_scope')
        return
    value=json.loads(source) if type(source) is str else source
    proof=authorized(config,None,shard=value['shard'],table=value['table'])
    if username not in (proof.get('username'),proof['ref']):raise MirrorError('media_scope')
    return proof


def _media_targets(config,shard):
    from .native_scope_contract import mode,registry,member
    if mode(config)=='selected':return [(u,'Msg_'+hashlib.md5(u.encode()).hexdigest()) for u in config['mirror_scope']]
    with registry(config) as db:
        return [(p.get('username') or p['ref'],t) for (t,) in db.execute('SELECT table_name FROM members WHERE shard=? ORDER BY table_name',(shard,)) for p in [member(config,db,shard,t)] if p.get('supported')]


def enqueue(config,username,source,kind):
    _media_authorized(config,username,source)
    if kind not in ('image','audio'):raise MirrorError('media_scope')
    c=_connect(config,True)
    try:
        with c:c.execute('INSERT OR IGNORE INTO jobs(key,username,source,kind,status,version) VALUES(?,?,?,?,?,?)',
            (media_key(source),username,_json(source),kind,'pending',config.get('media_transcriber_version',VERSION)))
    finally:c.close()


def enqueue_rows(config,shard,table,username,columns,rows):
    """Called once per copied batch, never does codec, ASR or Source reads."""
    from .source_records import RawMessage,_content_fingerprint
    jobs=[]
    for row in rows:
        if len(row)==len(columns)+1:row=row[1:]  # Original copier uses SELECT rowid,*.
        if len(row)!=len(columns):raise MirrorError('media_row_shape')
        item=dict(zip(columns,row));kind=item.get('local_type')
        if type(kind) is not int or kind&65535 not in (3,34):continue
        msg=RawMessage(item['local_id'],item.get('server_id'),kind,item['create_time'],item['real_sender_id'],item['message_content'],item['WCDB_CT_message_content'])
        source=dict(account_id=config['account_id'],source_generation=config['source_generation'],shard=shard,table=table,
                    local_id=item['local_id'],content_sha256=_content_fingerprint(msg))
        jobs.append((media_key(source),username,_json(source),'image' if kind&65535==3 else 'audio','pending',config.get('media_transcriber_version',VERSION)))
    if not jobs:return
    c=_connect(config,True)
    try:
        with c:c.executemany('INSERT OR IGNORE INTO jobs(key,username,source,kind,status,version) VALUES(?,?,?,?,?,?)',jobs)
    finally:c.close()


def mark_enqueue_repair(config,shard,table,low):
    """Native writer already owns .writer.lock; persist a tiny bounded rewind hint."""
    from .native_mirror_media import _read_private,_write_private
    root=mirror_root(config,create=False);name=shard+'.'+table+'.json'
    try:low=min(low,json.loads(_read_private(root,('media-repair',),name,4096))['low'])
    except FileNotFoundError:pass
    _write_private(root,('media-repair',),name,_json({'low':max(0,low)}).encode())


def _consume_repair(config,c,shard,table):
    from .native_mirror_media import _read_private
    from .native_mirror_sync import writer_lock
    root=mirror_root(config,create=False);name=shard+'.'+table+'.json';path=root/'media-repair'/name
    try:
        with writer_lock(root,0):
            raw=_read_private(root,('media-repair',),name,4096);low=json.loads(raw)['low']
            need=type(low) is int and low>=0
            if not need:raise MirrorError('media_repair_invalid')
            previous=c.execute('SELECT local_id FROM checkpoints WHERE shard=? AND table_name=?',(shard,table)).fetchone()
            with c:c.execute('INSERT OR REPLACE INTO checkpoints VALUES(?,?,?)',(shard,table,min(low,previous[0]) if previous else low))
            if not path.is_symlink() and path.resolve().parent==(root/'media-repair').resolve() and _read_private(root,('media-repair',),name,4096)==raw:path.unlink()
    except FileNotFoundError:pass
    except MirrorError as error:
        if str(error)!='sync_busy':raise


def backfill(config,limit=BATCH,*,diagnostic=None):
    from .native_scope_contract import mode
    if mode(config)=='account':return _backfill_account(config,limit,diagnostic=diagnostic)
    """One total bounded page across local shards/scopes, with durable checkpoints."""
    from .common import quote_identifier as qi
    root=mirror_root(config,create=False);c=_connect(config,True);count=0
    try:
        # Local roster only; Source discovery remains in the original message copier.
        for path in sorted(root.glob('message_*.db'))+sorted(root.glob('biz_message_*.db')):
            for username,table in _media_targets(config,path.name):
                check_deadline()
                _consume_repair(config,c,path.name,table)
                mark=c.execute('SELECT local_id FROM checkpoints WHERE shard=? AND table_name=?',(path.name,table)).fetchone()
                low=mark[0] if mark else 0
                with sqlite3.connect(readonly_database_uri(path),uri=True) as messages:
                    messages.execute('PRAGMA query_only=ON');messages.execute('BEGIN')
                    if messages.execute('SELECT * FROM __walden_binding').fetchall()!=[(config['account_id'],config['source_generation'],path.name)]:raise MirrorError('media_store_binding')
                    if not messages.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone():continue
                    columns=[r[1] for r in messages.execute('PRAGMA table_info('+qi(table)+')')]
                    selected=messages.execute('SELECT * FROM '+qi(table)+' WHERE local_id>? ORDER BY local_id LIMIT ?',(low,min(BATCH,max(0,limit-count)))).fetchall()
                # Advance only after enqueue has committed; a crash may repeat a page, never lose it.
                enqueue_rows(config,path.name,table,username,columns,selected)
                if selected:
                    high=max(r[columns.index('local_id')] for r in selected)
                    with c:c.execute('INSERT OR REPLACE INTO checkpoints VALUES(?,?,?)',(path.name,table,high))
                    count+=len(selected)
                if count>=limit:return count
        return count
    finally:c.close()


def image_decoder_binding(config):
    return hashlib.sha256(_json([config.get('image_ffmpeg'),config.get('media_transcriber_version',VERSION)]).encode()).hexdigest()


def local_result(config,source):
    """Read-only query path: no queue creation, Source, runtime probe, decoder or ASR."""
    try:
        c=_connect(config)
        if c is None:return None
        try:row=c.execute('SELECT status,result,reason,version FROM jobs WHERE key=?',(media_key(source),)).fetchone()
        finally:c.close()
        if not row:return None
        value=json.loads(row[1]) if row[1] else {}
        value['status']=row[0] if row[0]!='running' else 'pending'
        if row[2]:value['reason']=row[2]
        transcript=value.get('transcript') or {}
        if row[3]!=config.get('media_transcriber_version',VERSION) or (transcript.get('status')=='ready' and transcript.get('source')!='wechat_native_transcript' and transcript.get('pipeline_version')!=config.get('media_transcriber_version',VERSION)):
            value['status']='pending';value['transcript']={'status':'pending','text':None,'reason':'transcriber_version_changed'}
        root=mirror_root(config,create=False)
        def present(path):
            try:
                item=Path(path);target=item.resolve(strict=True)
                return item.is_absolute() and not item.is_symlink() and target.is_relative_to(root) and target.is_file()
            except (OSError,ValueError,TypeError):return False
        audio=value.get('audio')
        if audio and audio.get('local_path') and not present(audio['local_path']):
            value['audio']={'status':'failed','reason':'local_audio_missing'}
        image=value.get('image')
        if image and image.get('representations'):
            rows=[];missing=False;available=0
            for item in image['representations']:
                declares_file=item.get('status')=='decoded' or ('path' in item and not item.get('status'))
                if declares_file and not present(item.get('path')):
                    missing=True;item=dict(item,status='unavailable',reason='local_image_missing');item.pop('path',None)
                elif declares_file:available+=1
                rows.append(item)
            value['image']=image=dict(image,representations=rows)
            if missing:image.update(status='partial' if available else 'failed',reason='local_image_missing')
            unsupported=any(r.get('reason')=='image_decoder_unavailable' for r in rows)
            current=image_decoder_binding(config)
            image['redecode_pending']=bool(value.get('captured') and unsupported and config.get('image_ffmpeg') and image.get('decoder_binding')!=current)
        return value
    except (OSError,ValueError,sqlite3.Error,MirrorError):return {'status':'failed','reason':'local_media_unavailable'}


def _set_job(config,key,status,result,reason=None,now=None,*,immediate=False,claim=None):
    c=_connect(config,True)
    try:
        with c:
            row=c.execute('SELECT attempts,status,lease FROM jobs WHERE key=?',(key,)).fetchone()
            if row is None:return False
            if claim is not None and (row[1]!='running' or (row[2],row[0])!=claim):return False
            n=row[0]+int(status in ('ready','failed') and row[1]=='running')
            due=0 if immediate else (time.time() if now is None else now)+RETRY_SECONDS[min(max(n-1,0),2)]
            return bool(c.execute('UPDATE jobs SET status=?,result=?,reason=?,due=?,lease=?,attempts=? WHERE key=? AND status=? AND lease=? AND attempts=?',
                (status,_json(result),reason,due,row[2] if status=='running' else 0,n,key,row[1],row[2],row[0])).rowcount)
    finally:c.close()


def _release_media_claims(config,jobs,lease):
    if not jobs:return
    c=_connect(config,True)
    try:
        with c:
            for key,username,raw,kind,attempts,previous in jobs:
                c.execute("UPDATE jobs SET status='pending',lease=0,due=0 WHERE key=? AND status='running' AND lease=? AND attempts=?",(key,lease,attempts))
    finally:c.close()


def _transcript(config,payload,transcriber,wav_payload=None):
    """Content+pipeline cache survives jobs/processes; includes recognizer/model provenance."""
    from .voice_transcript import LocalTranscription
    sha=hashlib.sha256(payload).hexdigest();version=config.get('media_transcriber_version',VERSION)
    c=_connect(config,True)
    try:
        cached=c.execute('SELECT result FROM transcripts WHERE payload_sha=? AND version=? AND status=?',(sha,version,'ready')).fetchone()
        if cached:return json.loads(cached[0])
    finally:c.close()
    if transcriber is None:raise MirrorError('voice_runtime_unconfigured')
    check_deadline()
    recognized=transcriber.transcribe_wav(payload,wav_payload) if wav_payload is not None and hasattr(transcriber,'transcribe_wav') else transcriber.transcribe(payload)
    check_deadline()
    if not isinstance(recognized,LocalTranscription) or not recognized.text:raise MirrorError('local_transcription_failed')
    result=dict(status='ready',text=recognized.text,source='local_whisper_cpp',confidence=recognized.confidence,
                recognizer_version=recognized.recognizer_version,model_sha256=recognized.model_sha256,pipeline_version=version,payload_sha256=sha)
    c=_connect(config,True)
    try:
        with c:c.execute('INSERT OR REPLACE INTO transcripts VALUES(?,?,?,?)',(sha,version,'ready',_json(result)))
    finally:c.close()
    return result


def run_media(config,opener,*,transcriber=None,decoder=None,limit=4,now=None,selected_sources=None,local_only=False):
    """Called only in a separately owned finite child. ASR never holds mirror writer lock."""
    from .native_mirror_media import frozen_message,capture_window_images,save_voices,voice_key,_read_private,_write_private
    from .native_mirror_sync import writer_lock
    from .voice_transcript import _native_transcript,MAX_PACKED_INFO_BYTES
    root=mirror_root(config,create=False);tick=time.time() if now is None else now
    backfill_state=dict(status='not_requested',rows=0,complete=False)
    if selected_sources is None:
        if local_only:raise MirrorError('media_selected_required')
        backfill_state['status']='processed_page';backfill_state['rows']=backfill(config,diagnostic=backfill_state)
    keys=None if selected_sources is None else [media_key(s) for s in selected_sources]
    if keys==[]:return dict(media_completed=0,media_attempted=0,source_messages_queried=0)
    clause='' if keys is None else ' AND key IN ('+','.join('?' for _ in keys)+')'
    args=[] if keys is None else keys
    c=_connect(config,True)
    try:
        with c:
            version=config.get('media_transcriber_version',VERSION)
            changed=c.execute('SELECT key,result FROM jobs WHERE version<>?'+clause+' LIMIT ?',tuple([version]+args+[BATCH])).fetchall()
            for key,previous in changed:
                saved=json.loads(previous) if previous else {}
                saved['transcript']={'status':'pending','text':None,'reason':'transcriber_version_changed'}
                c.execute("UPDATE jobs SET status='pending',attempts=0,due=0,lease=0,version=?,result=? WHERE key=?",(version,_json(saved),key))
            c.execute("UPDATE jobs SET status='failed',reason='retry_limit',lease=0 WHERE status='running' AND lease<=? AND attempts>=?"+clause,tuple([tick,MAX_ATTEMPTS]+args))
            c.execute("UPDATE jobs SET status='pending',lease=0 WHERE status='running' AND lease<=? AND attempts<?"+clause,tuple([tick,MAX_ATTEMPTS]+args))
            jobs=c.execute("SELECT key,username,source,kind,attempts,result FROM jobs WHERE status IN ('pending','failed') AND attempts<? AND due<=?"+clause+" ORDER BY due,key LIMIT ?",tuple([MAX_ATTEMPTS,tick]+args+[max(1,min(limit,BATCH))])).fetchall()
            eligible=[]
            for key,username,raw,kind,attempts,previous in jobs:
                proof=_media_authorized(config,username,json.loads(raw))
                if proof is not None and proof.get('username') is None:
                    # Waiting consumes neither a codec attempt nor its retry cap.
                    # Moving due into the future yields queue head to known jobs.
                    c.execute("UPDATE jobs SET status='pending',reason='identity_pending',due=?,lease=0 WHERE key=?",(tick+30,key));continue
                if proof is not None:
                    username=proof['username']
                    c.execute('UPDATE jobs SET username=? WHERE key=?',(username,key))
                eligible.append((key,username,raw,kind,attempts,previous))
                c.execute("UPDATE jobs SET status='running',lease=? WHERE key=?",(tick+180,key))
            jobs=eligible
    finally:c.close()
    completed=0
    try:
        for key,username,raw,kind,attempts,previous in jobs:
            check_deadline();source=json.loads(raw);current={'source':source,'content':{'kind':kind}};result=json.loads(previous) if previous else {}
            try:
                proof=_media_authorized(config,username,source)
                if proof is not None and proof.get('username') is None:raise MirrorError('media_unknown_conversation_identity')
                if selected_sources is not None and source not in selected_sources:raise MirrorError('media_scope')
                item=frozen_message(config,root,current)
                # Only exact selected identities are captured. This brief phase yields writer ownership before codec/ASR.
                if kind=='image':
                    if not config.get('image_database') or not config.get('image_attachments_root'):
                        raise MirrorError('image_source_unconfigured')
                    if local_only:
                        from .native_mirror_media import decode_window_image
                        from .image_runtime import ImageMessageIdentity
                        from zoneinfo import ZoneInfo
                        identity=ImageMessageIdentity(username,item['server_id'],item['local_id'],item['create_time'],item['local_type'],ZoneInfo(config.get('query_timezone','UTC')))
                        image=decode_window_image(dict(config,image_output_root=str(root/'media-images')),root,identity,source)
                        if image.get('status') not in ('decoded','partial'):raise MirrorError('local_image_not_ready')
                        image['decoder_binding']=image_decoder_binding(config)
                        completed+=int(_set_job(config,key,'ready',{'captured':True,'image':image},claim=(tick+180,attempts)));continue
                    gaps=capture_window_images(dict(config,image_output_root=str(root/'media-images')),root,{'selected_username':username,'messages':[current]},opener)
                    image=current.get('image',{})
                    if image.get('status') not in ('decoded','partial'):raise MirrorError('local_image_not_ready')
                    image['decoder_binding']=image_decoder_binding(config)
                    result={'image':image};completed+=int(_set_job(config,key,'ready',result,claim=(tick+180,attempts)));continue
                exact={(source['shard'],source['table'],source['local_id'])}
                row=tuple(item.get(f) for f in ('server_id','local_id','create_time','local_type','packed_info_data','real_sender_id','message_content','WCDB_CT_message_content'))
                audio_key=voice_key(config,source['shard'],username,row)
                state=None
                try:
                    saved=json.loads(_read_private(root,('voice-state',),audio_key+'.json',8192))
                    if saved.get('saved'):state=saved
                except (OSError,ValueError):pass
                if state is None:
                    if local_only:raise MirrorError('local_audio_not_saved')
                    save_voices(config,root,[username],opener,selected=exact)
                    state=json.loads(_read_private(root,('voice-state',),audio_key+'.json',8192))
                if not state.get('saved'):raise MirrorError('local_audio_not_saved')
                payload=_read_private(root,('voice-payloads',),audio_key+'.silk',16*1024*1024)
                sha=hashlib.sha256(payload).hexdigest()
                if sha!=state['sha256']:raise MirrorError('local_audio_changed')
                if (result.get('audio') or {}).get('status')!='ready':
                    result['audio']=dict(status='saved',local_path=str(root/'voice-payloads'/(audio_key+'.silk')),sha256=sha,content_type='audio/silk')
                wav=None
                try:
                    decoded=json.loads(_read_private(root,('voice-playback',),sha+'.json',8192))
                    if decoded.get('decode_version')==('pilk-pcm24k-v1:'+config.get('media_transcriber_version',VERSION)):
                        saved_wav=_read_private(root,('voice-playback',),sha+'.wav',64*1024*1024+4096)
                        if hashlib.sha256(saved_wav).hexdigest()==decoded['sha256']:wav=saved_wav
                except (OSError,ValueError,KeyError):pass
                if wav is None and decoder is not None:
                    wav=decoder(payload);check_deadline();_write_private(root,('voice-playback',),sha+'.wav',wav)
                    _write_private(root,('voice-playback',),sha+'.json',_json({'decode_version':'pilk-pcm24k-v1:'+config.get('media_transcriber_version',VERSION),'sha256':hashlib.sha256(wav).hexdigest()}).encode())
                if wav is not None:
                    result['audio']=dict(status='ready',local_path=str(root/'voice-playback'/(sha+'.wav')),sha256=hashlib.sha256(wav).hexdigest(),content_type='audio/wav',decode_version='pilk-pcm24k-v1:'+config.get('media_transcriber_version',VERSION))
                # Persist playable audio before starting the expensive operation, including before any failure.
                _set_job(config,key,'running',dict(result,transcript={'status':'pending','text':None}),claim=(tick+180,attempts))
                packed=item.get('packed_info_data');native,text=_native_transcript(packed) if isinstance(packed,bytes) and len(packed)<=MAX_PACKED_INFO_BYTES else ('missing',None)
                if native=='available':result['transcript']={'status':'ready','text':text,'source':'wechat_native_transcript'}
                else:result['transcript']=_transcript(config,payload,transcriber,wav)
                completed+=int(_set_job(config,key,'ready',result,claim=(tick+180,attempts)))
            except Exception as error:
                check_deadline()
                from .local_voice_runtime import LocalVoiceRuntimeError
                safe_runtime={'runtime_unavailable','decoder_unavailable','whisper_unavailable','model_unavailable','decode_unavailable','transcription_unavailable'}
                reason=str(error) if isinstance(error,MirrorError) or isinstance(error,LocalVoiceRuntimeError) and str(error) in safe_runtime else 'local_media_processing_failed'
                result.setdefault('transcript',{'status':'failed','text':None})
                if kind=='audio':result['transcript']=dict(result.get('transcript',{}),status='failed',reason=reason)
                _set_job(config,key,'failed',result,reason,now=tick,claim=(tick+180,attempts))
    finally:_release_media_claims(config,jobs,tick+180)
    return dict(media_completed=completed,media_attempted=len(jobs),media_backfill=backfill_state,source_messages_queried=0)


# Independent from the ASR/decode version: changing OCR never requeues audio.
IMAGE_PIPELINE_VERSION = 'apple-vision-ocr-v1'
IMAGE_ADMISSION = 64
IMAGE_RESERVED_SQL = "(status IN ('pending','running') OR (status='failed' AND attempts<%d))" % MAX_ATTEMPTS


IMAGE_BUSY_SECONDS = 1.0


def _image_retry(action):
    """Retry only SQLite busy/locked, bounded by monotonic budget and owned deadline."""
    until = time.monotonic() + IMAGE_BUSY_SECONDS
    while True:
        check_deadline()
        try:
            return action()
        except sqlite3.OperationalError as error:
            code = getattr(error, 'sqlite_errorcode', None)
            busy = (code & 255) in (5, 6) if type(code) is int else str(error) in (
                'database is locked', 'database table is locked', 'database schema is locked')
            remaining = until - time.monotonic()
            if not busy or remaining <= 0:
                raise
            check_deadline()
            time.sleep(min(.02, remaining))


def _image_sql(c, sql, values=()):
    return _image_retry(lambda: c.execute(sql, values))


def _image_connect(config):
    return _image_retry(lambda: _image_open(config))


def _image_open(config):
    c = _connect(config, True)
    try:
        objects = {row[0] for row in c.execute("SELECT name FROM sqlite_master WHERE name IN ('image_derivations','image_ocr_cache','image_checked')")}
        columns = {row[1] for row in c.execute('PRAGMA table_info(image_derivations)')}
        if len(objects) == 3 and {'claim', 'checked'} <= columns:
            return c
        c.execute('BEGIN IMMEDIATE')
        c.execute('CREATE TABLE IF NOT EXISTS image_derivations('
                  'key TEXT NOT NULL,version TEXT NOT NULL,engine TEXT NOT NULL,source TEXT NOT NULL,'
                  'representation TEXT NOT NULL,upstream TEXT NOT NULL,status TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,'
                  'due REAL NOT NULL DEFAULT 0,lease REAL NOT NULL DEFAULT 0,result TEXT,reason TEXT,'
                  'PRIMARY KEY(key,version,engine))')
        c.execute('CREATE TABLE IF NOT EXISTS image_ocr_cache('
                  'sha TEXT,version TEXT,engine TEXT,result TEXT NOT NULL,PRIMARY KEY(sha,version,engine))')
        columns = {row[1] for row in c.execute('PRAGMA table_info(image_derivations)')}
        for name, definition in (('claim', "TEXT NOT NULL DEFAULT ''"), ('checked', 'INTEGER NOT NULL DEFAULT 0')):
            if name not in columns:
                c.execute('ALTER TABLE image_derivations ADD COLUMN ' + name + ' ' + definition)
        c.execute('CREATE INDEX IF NOT EXISTS image_checked ON image_derivations(checked)')
        c.commit()
        return c
    except BaseException:
        c.rollback()
        c.close()
        raise


def _image_payload(config, representation):
    """Read one existing decoded PNG through pinned, no-follow directory handles."""
    import struct
    from .native_mirror_media import _read_private
    root = mirror_root(config, create=False)
    path = Path(representation['path'])
    if not path.is_absolute() or '..' in path.parts:
        raise MirrorError('ocr_image_binding')
    try:
        relative = path.relative_to(root)
    except ValueError:
        raise MirrorError('ocr_image_binding') from None
    raw = _read_private(root, relative.parts[:-1], relative.name, 32 * 1024 * 1024)
    if not raw.startswith(b'\x89PNG\r\n\x1a\n') or len(raw) < 24:
        raise MirrorError('ocr_image_invalid')
    width, height = struct.unpack('>II', raw[16:24])
    if not width or not height or width * height > 25_000_000:
        raise MirrorError('ocr_image_invalid')
    return raw, hashlib.sha256(raw).hexdigest()


def enqueue_image_derivations(config, *, engine, version=IMAGE_PIPELINE_VERSION, limit=BATCH):
    """Hash bounded snapshots without writer ownership; admit with current-row checks."""
    c = _image_connect(config)
    count = 0
    try:
        verify = _image_sql(c, "SELECT rowid,representation,status,upstream,checked FROM image_derivations WHERE version=? AND engine=? AND status IN ('ready','invalidated') ORDER BY checked,rowid LIMIT ?", (version, engine, max(0, min(BATCH, limit)))).fetchall()
        active = _image_sql(c, 'SELECT count(*) FROM image_derivations WHERE ' + IMAGE_RESERVED_SQL + " AND (status='running' OR (version=? AND engine=?))", (version, engine)).fetchone()[0]
        allowance = max(0, min(BATCH, limit, IMAGE_ADMISSION - active))
        rows = _image_sql(c, "SELECT j.key,j.username,j.source,j.result FROM jobs j WHERE j.kind='image' AND j.status='ready' "
                         "AND NOT EXISTS (SELECT 1 FROM image_derivations d WHERE d.key=j.key AND d.version=? AND d.engine=? AND (d.upstream=j.result OR d.status='running')) "
                         "ORDER BY j.key LIMIT ?", (version, engine, allowance)).fetchall()
        verified = []
        for row in verify:
            check_deadline()
            rep = json.loads(row[1])
            try:
                _, digest = _image_payload(config, rep)
                valid = digest == rep.get('decoded_sha256')
            except (OSError, ValueError, KeyError, MirrorError):
                valid = False
            verified.append((row, valid))
        prepared = []
        for key, username, source, raw in rows:
            check_deadline()
            _media_authorized(config,username,source)
            value = json.loads(raw or '{}')
            candidates = [r for r in value.get('image', {}).get('representations', [])
                          if r.get('status') == 'decoded' and r.get('path')]
            if not candidates:
                rep, status, reason = {}, 'failed', 'ocr_decoded_image_missing'
            else:
                rep = dict(max(candidates, key=lambda r: (r.get('size', [0, 0])[0] * r.get('size', [0, 0])[1], r['path'])))
                try:
                    _, digest = _image_payload(config, rep)
                    rep['decoded_sha256'] = digest
                    status, reason = 'pending', None
                except (OSError, ValueError, KeyError, MirrorError):
                    status, reason = 'rejected', 'ocr_image_binding'
            prepared.append((key, username, source, raw, rep, status, reason))
        _image_sql(c, 'BEGIN IMMEDIATE')
        checked = _image_sql(c, 'SELECT COALESCE(MAX(checked),0)+1 FROM image_derivations').fetchone()[0]
        for (rowid, representation, state, upstream, prior_checked), valid in verified:
            _image_sql(c, 'UPDATE image_derivations SET checked=?,status=?,reason=? WHERE rowid=? AND representation=? AND status=? AND upstream=? AND checked=?',
                       (checked, 'ready' if valid else 'invalidated', None if valid else 'decoded_payload_changed', rowid, representation, state, upstream, prior_checked))
        _image_sql(c, "UPDATE image_derivations SET status='superseded',lease=0,claim='' WHERE status IN ('pending','failed') AND (version<>? OR engine<>?)", (version, engine))
        capacity = max(0, IMAGE_ADMISSION - _image_sql(c, 'SELECT count(*) FROM image_derivations WHERE ' + IMAGE_RESERVED_SQL).fetchone()[0])
        _image_sql(c, "UPDATE image_derivations SET status='pending',attempts=0,due=0 WHERE rowid IN (SELECT rowid FROM image_derivations WHERE status='superseded' AND version=? AND engine=? LIMIT ?)", (version, engine, capacity))
        available = max(0, IMAGE_ADMISSION - _image_sql(c, 'SELECT count(*) FROM image_derivations WHERE ' + IMAGE_RESERVED_SQL).fetchone()[0])
        for key, username, source, raw, rep, status, reason in prepared:
            current = _image_sql(c, 'SELECT username,source,result,kind,status FROM jobs WHERE key=?', (key,)).fetchone()
            if current != (username, source, raw, 'image', 'ready'):
                continue
            prior = _image_sql(c, 'SELECT upstream,status,attempts FROM image_derivations WHERE key=? AND version=? AND engine=?', (key, version, engine)).fetchone()
            if prior and (prior[0] == raw or prior[1] == 'running'):
                continue
            reserved = bool(prior and (prior[1] in ('pending', 'running') or prior[1] == 'failed' and prior[2] < MAX_ATTEMPTS))
            needed = status in ('pending', 'failed')
            if needed and not reserved and not available:
                continue
            _image_sql(c, 'INSERT INTO image_derivations(key,version,engine,source,representation,upstream,status,reason) VALUES(?,?,?,?,?,?,?,?) '
                       "ON CONFLICT(key,version,engine) DO UPDATE SET representation=excluded.representation,upstream=excluded.upstream,status=excluded.status,reason=excluded.reason,attempts=0,due=0,lease=0,result=NULL,claim='',checked=0",
                       (key, version, engine, source, _json(rep), raw, status, reason))
            available += int(reserved) - int(needed)
            count += 1
        _image_retry(c.commit)
        return count
    except BaseException:
        c.rollback()
        raise
    finally:
        c.close()


def local_image_derivation(config, source, *, engine, version=IMAGE_PIPELINE_VERSION):
    """Read stored OCR plus one bounded PNG hash; no OCR, writes, or queue creation."""
    c = _connect(config)
    if c is None:
        return None
    try:
        if not c.execute("SELECT 1 FROM sqlite_master WHERE name='image_derivations'").fetchone():
            return None
        row = c.execute('SELECT d.status,d.result,d.reason,d.upstream,j.result,d.representation FROM image_derivations d JOIN jobs j ON j.key=d.key WHERE d.key=? AND d.version=? AND d.engine=?',
                        (media_key(source), version, engine)).fetchone()
        if not row:
            return None
        payload_valid = row[0] != 'invalidated'
        if row[0] == 'ready':
            try:
                rep = json.loads(row[5])
                _, digest = _image_payload(config, rep)
                payload_valid = digest == rep.get('decoded_sha256')
            except (OSError, ValueError, KeyError, MirrorError):
                payload_valid = False
        if row[3] != row[4] or not payload_valid:
            return dict(status='pending', reason='decoded_representation_changed' if row[3] != row[4] else 'decoded_payload_changed',
                        ocr={'status': 'pending', 'text': None},
                        description={'status': 'unconfigured', 'text': None, 'reason': 'description_model_unconfigured'})
        value = json.loads(row[1]) if row[1] else {}
        return dict(value, status='pending' if row[0] == 'running' else row[0], reason=row[2],
                    description={'status': 'unconfigured', 'text': None, 'reason': 'description_model_unconfigured'})
    finally:
        c.close()


def run_image_derivations(config, *, recognizer=None, limit=4, now=None, version=IMAGE_PIPELINE_VERSION):
    """Finite owned-media phase: only decoded local files, no Source/decode fallback."""
    tick = time.time() if now is None else now
    engine = recognizer.identity if recognizer is not None else 'unconfigured'
    enqueue_image_derivations(config, engine=engine, version=version)
    c = _image_connect(config)
    try:
        _image_sql(c, 'BEGIN IMMEDIATE')
        _image_sql(c, "UPDATE image_derivations SET status='failed',reason='retry_limit',lease=0,claim='' WHERE status='running' AND lease<=? AND attempts>=?", (tick, MAX_ATTEMPTS))
        _image_sql(c, "UPDATE image_derivations SET status='pending',lease=0,claim='' WHERE status='running' AND lease<=? AND attempts<?", (tick, MAX_ATTEMPTS))
        candidates = _image_sql(c, "SELECT key,source,representation,attempts,upstream FROM image_derivations WHERE version=? AND engine=? "
                              "AND status IN ('pending','failed') AND attempts<? AND due<=? ORDER BY attempts DESC,due,key LIMIT ?",
                              (version, engine, MAX_ATTEMPTS, tick, max(0, min(limit, BATCH)))).fetchall()
        import secrets
        rows = []
        for row in candidates:
            token = secrets.token_hex(16)
            _image_sql(c, "UPDATE image_derivations SET status='running',attempts=attempts+1,lease=?,claim=? WHERE key=? AND version=? AND engine=?", (tick + 180, token, row[0], version, engine))
            rows.append((*row, token))
        _image_retry(c.commit)
    except BaseException:
        c.rollback()
        raise
    finally:
        c.close()
    completed = stale = 0
    for key, source, representation, attempts, upstream, token in rows:
        check_deadline()
        rep = json.loads(representation)
        result = dict(source=json.loads(source), representation=rep, pipeline_version=version,
                      engine_identity=engine, description={'status': 'unconfigured', 'text': None, 'reason': 'description_model_unconfigured'})
        status, reason = 'failed', None
        try:
            if recognizer is None:
                status, reason = 'unconfigured', 'ocr_runtime_unconfigured'
                result['ocr'] = dict(status=status, text=None, reason=reason)
            else:
                payload, sha = _image_payload(config, rep)
                if sha != rep.get('decoded_sha256'):
                    raise MirrorError('ocr_image_changed')
                result['decoded_sha256'] = sha
                c = _image_connect(config)
                try:
                    cached = _image_sql(c, 'SELECT result FROM image_ocr_cache WHERE sha=? AND version=? AND engine=?', (sha, version, engine)).fetchone()
                finally:
                    c.close()
                recognized = json.loads(cached[0]) if cached else recognizer.recognize_png(payload, timeout=30)
                check_deadline()
                if type(recognized) is not dict or type(recognized.get('text')) is not str:
                    raise MirrorError('ocr_result_invalid')
                _, current_sha = _image_payload(config, rep)
                if current_sha != sha:
                    raise MirrorError('ocr_image_changed')
                result['ocr'] = dict(recognized, status='ready' if recognized['text'] else 'empty')
                status = 'ready'
        except sqlite3.OperationalError:
            raise
        except Exception:
            check_deadline()
            reason = 'local_ocr_failed'
            result['ocr'] = dict(status='failed', text=None, reason=reason)
        result['processed_at'] = tick
        c = _image_connect(config)
        try:
            _image_sql(c, 'BEGIN IMMEDIATE')
            changed = _image_sql(c, "UPDATE image_derivations SET status=?,result=?,reason=?,lease=0,claim='',due=?,checked=(SELECT COALESCE(MAX(checked),0)+1 FROM image_derivations) WHERE key=? AND version=? AND engine=? AND status='running' AND claim=? AND attempts=? AND lease=? AND representation=? AND upstream=? AND EXISTS (SELECT 1 FROM jobs j WHERE j.key=image_derivations.key AND j.result=?)",
                                 (status, _json(result), reason, tick + RETRY_SECONDS[min(attempts, 2)], key, version, engine,
                                  token, attempts + 1, tick + 180, representation, upstream, upstream)).rowcount
            if changed and status == 'ready':
                _image_sql(c, 'INSERT OR IGNORE INTO image_ocr_cache VALUES(?,?,?,?)', (sha, version, engine, _json(recognized)))
            _image_retry(c.commit)
            if changed:
                completed += int(status == 'ready')
            else:
                stale += 1
        except BaseException:
            c.rollback()
            raise
        finally:
            c.close()
    return dict(image_ocr_attempted=len(rows), image_ocr_completed=completed, image_ocr_stale=stale, source_messages_queried=0)




def _backfill_note(config,status,rows):
    from .native_mirror_media import _write_private,_read_private
    from .native_scope_contract import query_scope_guard
    before=query_scope_guard(config)
    binding=hashlib.sha256(_binding(config).encode()).hexdigest()
    try:
        prior=json.loads(_read_private(mirror_root(config,create=False),('media-state',),'backfill.json',4096))
        if prior.get('binding_digest')!=binding:raise MirrorError('media_backfill_binding')
    except FileNotFoundError:pass
    value=dict(binding_digest=hashlib.sha256(_binding(config).encode()).hexdigest(),observed_at=time.time(),status=status,rows=rows,complete=False)
    _write_private(mirror_root(config,create=False),('media-state',),'backfill.json',_json(value).encode())
    query_scope_guard(config,before)


def backfill_status(config):
    from .native_mirror_media import _read_private
    try:
        value=json.loads(_read_private(mirror_root(config,create=False),('media-state',),'backfill.json',4096))
        valid=(value.get('binding_digest')==hashlib.sha256(_binding(config).encode()).hexdigest()
            and value.get('status') in ('processed_page','pending_writer','pending_cursor_changed')
            and type(value.get('rows')) is int and value['rows']>=0 and type(value.get('observed_at')) in (int,float)
            and 0<=time.time()-value['observed_at']<=300 and value.get('complete') is False)
        if valid:return {k:value[k] for k in ('observed_at','status','rows','complete')}
    except (OSError,ValueError,TypeError,MirrorError):pass
    return dict(status='unknown',complete=False)


def _backfill_account(config,limit,*,diagnostic=None):
    import contextlib
    from . import native_scope_contract as sc
    from .common import quote_identifier as qi
    from .native_mirror_sync import writer_lock,_account_registry_commit
    root=mirror_root(config,create=False);count=0;before=sc.query_scope_guard(config);queue=_connect(config,True)
    def finish(status):
        _backfill_note(config,status,count)
        if diagnostic is not None:diagnostic.update(status=status,rows=count,complete=False)
        return count
    try:
        with sc.registry(config) as db:
            expected=sc.state(db,'media_backfill',['',''])
            rows=db.execute('SELECT shard,table_name FROM members WHERE (shard,table_name)>(?,?) ORDER BY shard,table_name LIMIT 64',tuple(expected)).fetchall()
            if not rows:rows=db.execute('SELECT shard,table_name FROM members ORDER BY shard,table_name LIMIT 64').fetchall()
            entries=[(shard,table,sc.member(config,db,shard,table)) for shard,table in rows]
        for shard,table,proof in entries:
            check_deadline();sc.query_scope_guard(config,before)
            if proof.get('supported') and (root/shard).is_file():
                username=proof.get('username') or proof['ref'];_consume_repair(config,queue,shard,table)
                checkpoint=queue.execute('SELECT local_id FROM checkpoints WHERE shard=? AND table_name=?',(shard,table)).fetchone();low=checkpoint[0] if checkpoint else 0
                conn=sqlite3.connect(readonly_database_uri(root/shard),uri=True)
                try:
                    conn.execute('PRAGMA query_only=ON')
                    if conn.execute('SELECT * FROM __walden_binding').fetchall()!=[(config['account_id'],config['source_generation'],shard)]:raise MirrorError('media_store_binding')
                    progress=conn.execute('SELECT value FROM __walden_progress WHERE table_name=?',(table,)).fetchone()
                    selected=[]
                    if progress is not None:
                        fact=json.loads(progress[0])
                        if fact.get('source_identity')!=proof['source_identity'] or fact.get('source_header_sha256')!=proof['header']:raise MirrorError('scope_copy_proof')
                        columns=[r[1] for r in conn.execute('PRAGMA table_info('+qi(table)+')')]
                        selected=conn.execute('SELECT * FROM '+qi(table)+' WHERE local_id>? ORDER BY local_id LIMIT ?',(low,max(0,min(BATCH,limit-count)))).fetchall()
                finally:conn.close()
                check_deadline();sc.query_scope_guard(config,before)
                if selected:
                    enqueue_rows(config,shard,table,username,columns,selected)
                    high=max(r[columns.index('local_id')] for r in selected)
                    with queue:queue.execute('INSERT OR REPLACE INTO checkpoints VALUES(?,?,?)',(shard,table,high))
                    count+=len(selected)
            check_deadline()
            with contextlib.ExitStack() as stack:
                try:stack.enter_context(writer_lock(root,0))
                except MirrorError as error:
                    if str(error)!='sync_busy':raise
                    check_deadline();sc.query_scope_guard(config,before);return finish('pending_writer')
                check_deadline();sc.query_scope_guard(config,before)
                with sc.registry(config,write=True) as db:
                    current=sc.state(db,'media_backfill',['',''])
                    if current!=expected:return finish('pending_cursor_changed')
                    live=sc.member(config,db,shard,table)
                    if any(live.get(k)!=proof.get(k) for k in ('source_identity','header','schema_sha256','ref')):raise MirrorError('scope_copy_proof')
                    sc.save(db,'media_backfill',[shard,table]);_account_registry_commit(db)
                check_deadline();sc.query_scope_guard(config,before)
            expected=[shard,table]
            if count>=limit:break
        check_deadline();sc.query_scope_guard(config,before);return finish('processed_page')
    finally:queue.close()


from .failure_evidence import _register
_register(_set_job,_release_media_claims,run_media,_backfill_note,backfill_status,_backfill_account)
