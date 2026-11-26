"""Bounded native media backlog and persistent, local-only result cache.
The message poll only enqueues; this owned child performs capture/decode/ASR.
"""
from collections import OrderedDict
from contextlib import contextmanager, nullcontext
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
from .native_deadline import check_deadline
from . import native_media_segment as media_segment
from .native_mirror_store import MirrorError
from .native_mirror_sync import mirror_root
from .live_readonly import readonly_database_uri

VERSION='local-media-v1-small-1be3a9b2'
BATCH=32
MAX_ATTEMPTS=3
BACKFILL_PROOF_SECONDS = .025
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


def _connect(config,write=False,*,existing_only=False):
    import stat
    from .native_scope_contract import query_scope_guard
    token=query_scope_guard(config)
    root=mirror_root(config,create=False);path=root/'media-work.sqlite'
    if path.is_symlink():raise MirrorError('media_store_binding')
    if not write and not path.is_file():return None
    if write:
        flags = os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK
        if not existing_only:
            flags |= os.O_CREAT
        fd=os.open(path,flags,0o600)
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
    location = str(path) if write and not existing_only else readonly_database_uri(path)
    if write and existing_only:
        location = location.replace('mode=ro','mode=rw')
    c=sqlite3.connect(location,uri=not write or existing_only,timeout=.1,factory=Guarded)
    try:
        # An existing foreign sidecar is rejected before DDL, chmod or any write.
        if info.st_size and c.execute('SELECT value FROM binding').fetchall()!=[(_binding(config),)]:raise MirrorError('media_store_binding')
        if write and not existing_only:
            c.executescript('CREATE TABLE IF NOT EXISTS binding(id INTEGER PRIMARY KEY CHECK(id=1),value TEXT NOT NULL);'
                'CREATE TABLE IF NOT EXISTS jobs(key TEXT PRIMARY KEY,username TEXT NOT NULL,source TEXT NOT NULL,kind TEXT NOT NULL,'
                'status TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,due REAL NOT NULL DEFAULT 0,lease REAL NOT NULL DEFAULT 0,result TEXT,reason TEXT,version TEXT NOT NULL,recent_at REAL NOT NULL DEFAULT 0,arrival TEXT NOT NULL DEFAULT \'legacy\');'
                'CREATE INDEX IF NOT EXISTS media_due ON jobs(status,due);'
                'CREATE TABLE IF NOT EXISTS checkpoints(shard TEXT,table_name TEXT,local_id INTEGER NOT NULL,PRIMARY KEY(shard,table_name));'
                'CREATE TABLE IF NOT EXISTS transcripts(payload_sha TEXT,version TEXT,status TEXT NOT NULL,result TEXT,PRIMARY KEY(payload_sha,version));'
                'CREATE TABLE IF NOT EXISTS media_dispatch(id INTEGER PRIMARY KEY CHECK(id=1),turn INTEGER NOT NULL,recent_kind INTEGER NOT NULL,history_kind INTEGER NOT NULL,ocr_admit_turn INTEGER NOT NULL DEFAULT 0,ocr_run_turn INTEGER NOT NULL DEFAULT 0);'
                'INSERT OR IGNORE INTO media_dispatch(id,turn,recent_kind,history_kind) VALUES(1,0,0,0);'
                'CREATE TABLE IF NOT EXISTS partial_media_scan('
                'slot TEXT NOT NULL,scope TEXT NOT NULL,pos TEXT NOT NULL,PRIMARY KEY(slot,scope));')
            if 'recent_at' not in {r[1] for r in c.execute('PRAGMA table_info(jobs)')}:
                # Old jobs remain old; migration time is never an arrival stamp.
                c.execute('BEGIN IMMEDIATE')
                if 'recent_at' not in {r[1] for r in c.execute('PRAGMA table_info(jobs)')}:
                    c.execute('ALTER TABLE jobs ADD COLUMN recent_at REAL NOT NULL DEFAULT 0')
                    c.execute("ALTER TABLE jobs ADD COLUMN arrival TEXT NOT NULL DEFAULT 'legacy'")
                c.commit()
            if 'ocr_admit_turn' not in {r[1] for r in c.execute('PRAGMA table_info(media_dispatch)')}:
                c.execute('BEGIN IMMEDIATE')
                if 'ocr_admit_turn' not in {r[1] for r in c.execute('PRAGMA table_info(media_dispatch)')}:
                    c.execute('ALTER TABLE media_dispatch ADD COLUMN ocr_admit_turn INTEGER NOT NULL DEFAULT 0')
                    c.execute('ALTER TABLE media_dispatch ADD COLUMN ocr_run_turn INTEGER NOT NULL DEFAULT 0')
                c.commit()
            c.execute('CREATE INDEX IF NOT EXISTS media_recent ON jobs(status,kind,recent_at,due,key)')
            c.execute('INSERT OR IGNORE INTO binding(id,value) VALUES(1,?)',(_binding(config),));c.commit()
        elif not write:c.execute('PRAGMA query_only=ON')
        if c.execute('SELECT value FROM binding').fetchall()!=[(_binding(config),)]:raise MirrorError('media_store_binding')
        query_scope_guard(config,token)
        return c
    except BaseException:c.close();raise


class PartialMediaScope:
    """Current per-item guard plus bounded prefilter for an owned partial round."""
    def __init__(self, config, anchors, validate=None):
        from contextlib import closing
        from . import native_scope_contract as sc
        from .native_table_cursor import pending_key
        self.config = config
        self.anchors = anchors
        # Round shard rosters can rotate. Only this position carries over;
        # every page is filtered and each candidate authorized for this round.
        self.scan_binding = [config['account_id'], config['source_generation']]
        self.validate = validate
        self.root = mirror_root(config, create=False)
        self.blocked = []
        self.shards = []
        with sc.registry(config, snapshot=False) as registry:
            for shard, anchor in sorted(anchors.items()):
                if sc.state(registry, 'shard_anchor:' + shard) != anchor:
                    raise MirrorError('scope_source_conflict')
                prefix = pending_key(shard, '')
                paused = registry.execute('SELECT key FROM state WHERE key>=? AND key<? LIMIT 257',
                                          (prefix, prefix+'~')).fetchall()
                if len(paused) > 256:
                    continue
                path = self.root / shard
                if not path.exists():
                    continue  # No committed mirror bytes on this shard yet.
                sc._safe(path)
                with closing(sqlite3.connect(readonly_database_uri(path),uri=True,timeout=.1)) as local:
                    if local.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='__walden_cursor_epochs'").fetchone():
                        epochs = local.execute('SELECT DISTINCT table_name FROM __walden_cursor_epochs LIMIT 257').fetchall()
                        if len(epochs)>256:
                            continue
                        self.blocked.extend(shard+':'+t for t, in epochs)
                self.blocked.extend(key.removeprefix('table_cursor:') for key, in paused)
                self.shards.append(shard)

    def member_filter(self, shard, table):
        return (f" AND {shard} IN (SELECT value FROM json_each(?)) "
                f"AND ({shard}||':'||{table}) NOT IN (SELECT value FROM json_each(?))",
                [_json(self.shards), _json(self.blocked)])

    def job_filter(self, column):
        src = f"CASE WHEN json_valid({column}) THEN {column} ELSE '{{}}' END"
        where, args = self.member_filter(f"json_extract({src},'$.shard')", f"json_extract({src},'$.table')")
        return (where + f" AND json_type({src},'$.table_generation') IS NULL"
                f" AND json_extract({src},'$.account_id')=? AND json_extract({src},'$.source_generation')=?",
                args + [self.config['account_id'], self.config['source_generation']])

    def frozen(self, username, source):
        from .native_mirror_media import MediaItemDeferred, frozen_message
        from .native_scope_contract import TABLE
        import re
        if (type(source) is not dict or source.get('shard') not in self.shards
                or type(source.get('table')) is not str or not TABLE.fullmatch(source['table'])
                or type(source.get('local_id')) is not int or source['local_id']<=0
                or type(source.get('content_sha256')) is not str or not re.fullmatch('[0-9a-f]{64}',source['content_sha256'])):
            raise MediaItemDeferred('media_job_stale')
        target=source['shard']+':'+source['table']
        if target in self.blocked or self.validate is not None and not self.validate(source['shard']):
            raise MediaItemDeferred('media_job_stale')
        try:
            return frozen_message(self.config, self.root, dict(source=source,media_username=username),
                                  expected_anchor=self.anchors[source['shard']])
        except MediaItemDeferred as error:
            if str(error)=='cursor_generation_media_unavailable' and 'table_generation' not in source:
                self.blocked.append(target)
            raise
        except MirrorError as error:
            if str(error) != 'scope_table_unregistered':
                raise
            raise MediaItemDeferred('media_job_stale') from None


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


def enqueue_rows(config,shard,table,username,columns,rows,*,arrival=None,preview=False):
    """Called once per copied batch, never does codec, ASR or Source reads."""
    from .source_records import RawMessage,_content_fingerprint
    jobs=[];observed=time.time();hint=None
    fresh=(type(arrival)is dict and set(arrival)=={'kind','before_tail','prior_max','through_tail','prior_checked_at','observed_at'}
        and arrival.get('kind')=='tail_increment'
        and all(type(arrival[k])is int for k in ('before_tail','prior_max','through_tail','prior_checked_at','observed_at'))
        and 0<=arrival['prior_max']==arrival['before_tail']<arrival['through_tail']
        and 0<=arrival['prior_checked_at']<arrival['observed_at']
        and 0<=observed-arrival['observed_at']<=60)
    for row in rows:
        if len(row)==len(columns)+1:row=row[1:]  # Original copier uses SELECT rowid,*.
        if len(row)!=len(columns):raise MirrorError('media_row_shape')
        item=dict(zip(columns,row));kind=item.get('local_type')
        if type(kind) is not int or kind&65535 not in (3,34):continue
        msg=RawMessage(item['local_id'],item.get('server_id'),kind,item['create_time'],item['real_sender_id'],item['message_content'],item['WCDB_CT_message_content'])
        source=dict(account_id=config['account_id'],source_generation=config['source_generation'],shard=shard,table=table,
                    local_id=item['local_id'],content_sha256=_content_fingerprint(msg))
        recent=bool(fresh and arrival['before_tail']<item['local_id']<=arrival['through_tail']
                    and type(item.get('create_time')) is int
                    and arrival['prior_checked_at']<item['create_time']<=arrival['observed_at']
                    and 0<=observed-item['create_time']<=300)
        jobs.append((media_key(source),username,_json(source),'image' if kind&65535==3 else 'audio','pending',config.get('media_transcriber_version',VERSION),observed if recent else 0,_json(arrival)if recent else 'unproven_or_history'))
        if preview and recent and kind&65535==3 and type(item.get('server_id')) is int and item['server_id']>0:
            hint = len(jobs)-1
    if not jobs:return None
    c=_connect(config,True)
    accepted=None
    insert='INSERT OR IGNORE INTO jobs(key,username,source,kind,status,version,recent_at,arrival) VALUES(?,?,?,?,?,?,?,?)'
    try:
        with c:
            if hint is None:
                c.executemany(insert,jobs)
            else:
                c.executemany(insert,jobs[:hint])
                if c.execute(insert,jobs[hint]).rowcount==1:
                    accepted=jobs[hint][0]
                c.executemany(insert,jobs[hint+1:])
    finally:c.close()
    return accepted


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


def backfill(config,limit=BATCH,*,diagnostic=None,source_scope=None):
    from .native_scope_contract import mode
    if mode(config)=='account':return _backfill_account(config,limit,diagnostic=diagnostic,source_scope=source_scope)
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


def image_decoder_binding(config, *, ffmpeg=None):
    path = config.get('image_ffmpeg') if ffmpeg is None else str(ffmpeg)
    return hashlib.sha256(_json([path,config.get('media_transcriber_version',VERSION)]).encode()).hexdigest()


def local_result(config,source):
    """Read-only query path: no queue creation, Source, runtime probe, decoder or ASR."""
    try:
        c=_connect(config)
        if c is None:return None
        try:row=c.execute('SELECT status,result,reason,version,kind FROM jobs WHERE key=?',(media_key(source),)).fetchone()
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
            image['redecode_pending']=bool(row[0]=='ready' and image.get('status')=='partial' and unsupported
                                           and config.get('image_ffmpeg') and image.get('decoder_binding')!=current)
        if row[4]=='image' and row[3]==config.get('media_transcriber_version',VERSION) and not any(
                rep.get('status')=='decoded' for rep in value.get('image',{}).get('representations',[])):
            from .native_image_preview import local_preview
            preview = local_preview(root, source)
            if preview is not None:
                value['image'] = preview
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


def _partial_page(c, sql, args, order, limit, slot, binding):
    """Read the next bounded keyset page, wrapping only after reaching the end."""
    scope = media_key(binding)
    saved = c.execute('SELECT pos FROM partial_media_scan WHERE slot=? AND scope=?', (slot,scope)).fetchone()
    prior = saved[0] if saved else None
    fields = ','.join(order)
    ordered = ' ORDER BY '+fields+' LIMIT ?'
    rows = []
    if prior is not None:
        position = json.loads(prior)
        placeholders = ','.join('?' for _ in order)
        rows = c.execute(sql+f' AND ({fields})>({placeholders})'+ordered, (*args,*position,limit)).fetchall()
    if not rows:
        rows = c.execute(sql+ordered, (*args,limit)).fetchall()
    width = len(order)
    return [(row[:-width],row[-width:]) for row in rows], (slot,scope,prior)


def _advance_partial_scan(c, checkpoint, outcome):
    """Remember the rejected prefix without changing a job or its selection turn."""
    slot, scope, prior = checkpoint
    saved = c.execute('SELECT pos FROM partial_media_scan WHERE slot=? AND scope=?', (slot,scope)).fetchone()
    if (saved[0] if saved else None) != prior:
        return  # OCR may have released the writer while reading a PNG.
    pos = None
    for rank, eligible in outcome:
        if eligible is None:
            break
        if eligible:
            pos = None
            break
        pos = _json(rank)
    if pos == prior or not outcome or outcome[0][1] is None:
        return
    if pos is None:
        c.execute('DELETE FROM partial_media_scan WHERE slot=? AND scope=?', (slot,scope))
        return
    c.execute('INSERT OR REPLACE INTO partial_media_scan(slot,scope,pos) VALUES(?,?,?)', (slot,scope,pos))
    c.execute('DELETE FROM partial_media_scan WHERE slot=? AND rowid NOT IN '
              '(SELECT rowid FROM partial_media_scan WHERE slot=? ORDER BY rowid DESC LIMIT 64)', (slot,slot))


def _select_jobs(c,tick,limit,keys,source_scope=None,admit=None):
    """Durable 3 recent : 1 historical turns; each lane alternates image/audio.

    Empty kinds/lanes lend their slot. In a continuously eligible mixed queue,
    history receives every fourth selection and each history kind every eighth.
    Cursor advances in the same SQLite transaction as claims, including failures.
    """
    turn,new_kind,old_kind=c.execute('SELECT turn,recent_kind,history_kind FROM media_dispatch WHERE id=1').fetchone()
    if type(turn)is not int or not 0<=turn<4 or any(type(x)is not int or x not in (0,1)for x in (new_kind,old_kind)):raise MirrorError('media_store_binding')
    result=[];chosen=[]
    for _ in range(max(1,min(limit,BATCH))):
        preferred='recent'if turn<3 else 'history';row=None;selected_lane=None
        for lane in (preferred,'history'if preferred=='recent'else'recent'):
            kind_turn=new_kind if lane=='recent'else old_kind
            for kind in (('image','audio')if kind_turn==0 else('audio','image')):
                lane_match='recent_at'+('>?'if lane=='recent'else'<=?')
                if source_scope is None:
                    args=[MAX_ATTEMPTS,tick,kind,tick-600]
                    where="status IN ('pending','failed') AND attempts<? AND due<=? AND kind=? AND "+lane_match
                else:
                    where="((status IN ('pending','failed') AND due<=?) OR (status='running' AND lease<=?)) AND attempts<? AND version=? AND kind=? AND "+lane_match
                    args=[tick,tick,MAX_ATTEMPTS,source_scope.config.get('media_transcriber_version',VERSION),kind,tick-600]
                    clause, params = source_scope.job_filter('source')
                    where += clause;args += params
                if keys is not None:where+=' AND key IN ('+','.join('?'for _ in keys)+')';args+=keys
                if chosen:where+=' AND key NOT IN ('+','.join('?'for _ in chosen)+')';args+=chosen
                columns = 'SELECT key,username,source,kind,attempts,result'
                if source_scope is None:
                    row = c.execute(columns+' FROM jobs WHERE '+where+' ORDER BY due,key LIMIT 1', args).fetchone()
                else:
                    binding = [source_scope.scan_binding, source_scope.config.get('media_transcriber_version',VERSION),
                               sorted(keys) if keys is not None else None]
                    page, checkpoint = _partial_page(c, columns+',due,key FROM jobs WHERE '+where, args,
                                                     ('due','key'), 8, f'media:{lane}:{kind}', binding)
                    outcomes = []
                    for item, rank in page:
                        eligible = admit(item)
                        outcomes.append((rank,eligible))
                        if eligible:
                            row = item
                            break
                    _advance_partial_scan(c, checkpoint, outcomes)
                if row:selected_lane=lane;break
            if row:break
        if row is None:break
        result.append(row);chosen.append(row[0]);turn=(turn+1)%4
        if selected_lane=='recent':new_kind=1-new_kind
        else:old_kind=1-old_kind
    if result:c.execute('UPDATE media_dispatch SET turn=?,recent_kind=?,history_kind=? WHERE id=1',(turn,new_kind,old_kind))
    return result


def _release_scoped_claims(config, jobs, lease, *, preserve_result=False):
    """Undo only this caller's still-owned reservations, byte for byte."""
    if not jobs:
        return
    c=_connect(config,True)
    try:
        with c:
            for key, attempts, before in jobs:
                c.execute("UPDATE jobs SET username=?,status=?,due=?,lease=?,result=CASE WHEN ? THEN result ELSE ? END,reason=? "
                          "WHERE key=? AND status='running' AND lease=? AND attempts=?",
                          (*before[:4], preserve_result, *before[4:], key,lease,attempts))
    finally:
        c.close()


def run_media(config,opener,*,transcriber=None,decoder=None,limit=4,now=None,selected_sources=None,local_only=False,yield_check=None,backfill_page=True,systemic_source_errors=False,source_scope=None):
    """Called only in a separately owned finite child. ASR never holds mirror writer lock."""
    from .native_mirror_media import MediaItemDeferred,frozen_message,capture_window_images,save_voices,voice_key,_voice_payload_name,_read_private,_write_private
    from .native_mirror_sync import writer_lock
    from .voice_transcript import _native_transcript,MAX_PACKED_INFO_BYTES
    root=mirror_root(config,create=False);tick=time.time() if now is None else now
    cooperative=media_segment.active()
    backfill_state=dict(status='not_requested',rows=0,complete=False)
    if selected_sources is None:
        if local_only:raise MirrorError('media_selected_required')
        if backfill_page:backfill_state['status']='processed_page';backfill_state['rows']=backfill(config,diagnostic=backfill_state,source_scope=source_scope)
    keys=None if selected_sources is None else [media_key(s) for s in selected_sources]
    if keys==[]:return dict(media_completed=0,media_attempted=0,source_messages_queried=0)
    clause='' if keys is None else ' AND key IN ('+','.join('?' for _ in keys)+')'
    args=[] if keys is None else keys
    if source_scope is None:
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
        finally:c.close()
    completed=attempted=selected_count=0;all_claims=[];scoped_claims=[];yielded=None
    segment_yielded=False
    try:
        for _ in range(max(1,min(limit,BATCH))):
            check_deadline()
            yielded=yield_check() if yield_check is not None else None
            if yielded:break
            admitted = None
            def admit(row):
                nonlocal admitted
                try:
                    admitted=source_scope.frozen(row[1],json.loads(row[2]))
                    return True
                except MediaItemDeferred:
                    return False

            c=_connect(config,True)
            try:
                with (writer_lock(root,0) if source_scope is not None else nullcontext()), c:
                    c.execute('BEGIN IMMEDIATE')
                    jobs=_select_jobs(c,tick,1,keys,source_scope,admit if source_scope is not None else None)
                    if not jobs:break
                    media_segment.checkpoint('claim')
                    selected_count+=1
                    key,username,raw,kind,attempts,previous=jobs[0]
                    if source_scope is not None or cooperative:
                        before=c.execute('SELECT username,status,due,lease,result,reason FROM jobs WHERE key=?',(key,)).fetchone()
                        scoped_claims.append((key,attempts,before))
                    if source_scope is None:
                        proof=_media_authorized(config,username,json.loads(raw))
                        if proof is not None and proof.get('username') is None:
                            c.execute("UPDATE jobs SET status='pending',reason='identity_pending',due=?,lease=0 WHERE key=?",(tick+30,key));continue
                        if proof is not None:
                            username=proof['username'];c.execute('UPDATE jobs SET username=? WHERE key=?',(username,key))
                        all_claims.append((key,username,raw,kind,attempts,previous))
                    c.execute("UPDATE jobs SET status='running',lease=? WHERE key=?",(tick+180,key))
            except MirrorError as error:
                if source_scope is None or str(error)!='sync_busy':
                    raise
                yielded='writer_busy'
                break
            finally:c.close()
            attempted+=1
            check_deadline();source=json.loads(raw);current={'source':source,'content':{'kind':kind}};result=json.loads(previous) if previous else {}
            @contextmanager
            def capture_guard():
                with writer_lock(root,0):
                    yield source_scope.frozen(username,source)

            def publish(status, data, reason=None, now=None):
                if source_scope is None:
                    return _set_job(config,key,status,data,reason,now=now,claim=(tick+180,attempts))
                with writer_lock(root,0):
                    source_scope.frozen(username,source)
                    return _set_job(config,key,status,data,reason,now=now,claim=(tick+180,attempts))
            try:
                if selected_sources is not None and source not in selected_sources:raise MirrorError('media_scope')
                if source_scope is None:
                    proof=_media_authorized(config,username,source)
                    if proof is not None and proof.get('username') is None:raise MirrorError('media_unknown_conversation_identity')
                    item=frozen_message(config,root,current)
                else:
                    item=admitted
                # Partial capture and publication are checked separately. Codecs
                # and ASR remain outside the mirror writer lock.
                if kind=='image':
                    if not config.get('image_database') or not config.get('image_attachments_root'):
                        raise MirrorError('image_source_unconfigured')
                    from .native_image_settings import decoder_path
                    ffmpeg = decoder_path(config,root)
                    output_root = root/'media-images'
                    if local_only:
                        from .native_mirror_media import decode_window_image
                        from .image_runtime import ImageMessageIdentity
                        from zoneinfo import ZoneInfo
                        identity=ImageMessageIdentity(username,item['server_id'],item['local_id'],item['create_time'],item['local_type'],ZoneInfo(config.get('query_timezone','UTC')))
                        image=decode_window_image(config,root,identity,source,output_root=output_root,ffmpeg=ffmpeg)
                        if image.get('status') not in ('decoded','partial'):raise MirrorError('local_image_not_ready')
                        image['decoder_binding']=image_decoder_binding(config,ffmpeg=ffmpeg)
                        check_deadline()
                        completed+=int(publish('ready',{'captured':True,'image':image}));continue
                    window = {'selected_username':username,'messages':[current]}
                    media_segment.checkpoint('capture')
                    if source_scope is None:
                        capture_window_images(config,root,window,opener,output_root=output_root,ffmpeg=ffmpeg)
                        image=current.get('image',{})
                    else:
                        from .native_mirror_media import decode_window_image
                        from .image_runtime import ImageMessageIdentity
                        from zoneinfo import ZoneInfo
                        capture_window_images(config,root,window,opener,
                                              decode=False,capture_guard=capture_guard)
                        if current.get('image',{}).get('status')!='saved':
                            raise MirrorError('local_image_not_ready')
                        identity=ImageMessageIdentity(username,item['server_id'],item['local_id'],item['create_time'],item['local_type'],ZoneInfo(config.get('query_timezone','UTC')))
                        image=decode_window_image(config,root,identity,source,output_root=output_root,ffmpeg=ffmpeg)
                    if image.get('status') not in ('decoded','partial'):raise MirrorError('local_image_not_ready')
                    image['decoder_binding']=image_decoder_binding(config,ffmpeg=ffmpeg)
                    check_deadline()
                    result={'image':image};completed+=int(publish('ready',result));continue
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
                    media_segment.checkpoint('capture')
                    if source_scope is None:
                        save_voices(config,root,[username],opener,selected=exact)
                    else:
                        save_voices(config,root,[username],opener,selected=exact,capture_guard=capture_guard)
                    state=json.loads(_read_private(root,('voice-state',),audio_key+'.json',8192))
                if not state.get('saved'):raise MirrorError('local_audio_not_saved')
                audio_file=_voice_payload_name(audio_key,state)
                payload=_read_private(root,('voice-payloads',),audio_file,16*1024*1024)
                sha=hashlib.sha256(payload).hexdigest()
                if sha!=state['sha256']:raise MirrorError('local_audio_changed')
                if (result.get('audio') or {}).get('status')!='ready':
                    result['audio']=dict(status='saved',local_path=str(root/'voice-payloads'/audio_file),sha256=sha,content_type='audio/silk')
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
                publish('running',dict(result,transcript={'status':'pending','text':None}))
                packed=item.get('packed_info_data');native,text=_native_transcript(packed) if isinstance(packed,bytes) and len(packed)<=MAX_PACKED_INFO_BYTES else ('missing',None)
                if native=='available':result['transcript']={'status':'ready','text':text,'source':'wechat_native_transcript'}
                else:result['transcript']=_transcript(config,payload,transcriber,wav)
                completed+=int(publish('ready',result))
            except MediaItemDeferred:
                continue
            except Exception as error:
                if source_scope is not None and isinstance(error,MirrorError) and str(error)=='sync_busy':
                    yielded='writer_busy'
                    break
                check_deadline()
                if systemic_source_errors and (isinstance(error,sqlite3.Error) or isinstance(error,MirrorError) and str(error) in {'media_source_unavailable','source_replaced','media_store_binding','media_scope','source_identity_mismatch','scope_source_conflict','scope_member_proof','scope_copy_proof','media_source_round_changed'}):raise
                from .local_voice_runtime import LocalVoiceRuntimeError
                safe_runtime={'runtime_unavailable','decoder_unavailable','whisper_unavailable','model_unavailable','decode_unavailable','transcription_unavailable'}
                reason=str(error) if isinstance(error,MirrorError) or isinstance(error,LocalVoiceRuntimeError) and str(error) in safe_runtime else 'local_media_processing_failed'
                result.setdefault('transcript',{'status':'failed','text':None})
                if kind=='audio':result['transcript']=dict(result.get('transcript',{}),status='failed',reason=reason)
                try:
                    publish('failed',result,reason,now=tick)
                except MediaItemDeferred:
                    continue
                except MirrorError as error:
                    if source_scope is None or str(error)!='sync_busy':
                        raise
                    yielded='writer_busy'
                    break
    except media_segment.SegmentYield:
        segment_yielded=True
        raise
    finally:
        if segment_yielded:
            _release_scoped_claims(config,scoped_claims,tick+180,preserve_result=True)
        else:
            _release_media_claims(config,all_claims,tick+180)
            if source_scope is not None:
                _release_scoped_claims(config,scoped_claims,tick+180)
    return dict(media_completed=completed,media_attempted=attempted,media_selected=selected_count,media_yield=yielded,media_backfill=backfill_state,source_messages_queried=0)


# Independent from the ASR/decode version: changing OCR never requeues audio.
IMAGE_PIPELINE_VERSION = 'apple-vision-ocr-v1'
IMAGE_ADMISSION = 64
IMAGE_RESERVED_SQL = "(status IN ('pending','running') OR (status='failed' AND attempts<%d))" % MAX_ATTEMPTS


IMAGE_BUSY_SECONDS = 1.0


def _sqlite_lock_error(error):
    code = getattr(error, 'sqlite_errorcode', None)
    if type(code) is int:
        return (code & 255) in (5, 6)
    return str(error) in ('database is locked', 'database table is locked', 'database schema is locked')


def _image_retry(action):
    """Retry only SQLite busy/locked, bounded by monotonic budget and owned deadline."""
    until = time.monotonic() + IMAGE_BUSY_SECONDS
    while True:
        check_deadline()
        try:
            return action()
        except sqlite3.OperationalError as error:
            remaining = until - time.monotonic()
            if not _sqlite_lock_error(error) or remaining <= 0:
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


def _image_payload(config, representation, *, statistics=None):
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
    if statistics is not None:statistics['payload_read_attempts']+=1
    try:raw = _read_private(root, relative.parts[:-1], relative.name, 32 * 1024 * 1024)
    except BaseException:
        if statistics is not None:statistics['payload_read_failures']+=1
        raise
    if statistics is not None:
        statistics['payload_reads']+=1;statistics['payload_bytes']+=len(raw)
    if not raw.startswith(b'\x89PNG\r\n\x1a\n') or len(raw) < 24:
        raise MirrorError('ocr_image_invalid')
    width, height = struct.unpack('>II', raw[16:24])
    if not width or not height or width * height > 25_000_000:
        raise MirrorError('ocr_image_invalid')
    return raw, hashlib.sha256(raw).hexdigest()


def _select_ocr(c,engine,version,tick,limit,*,admit,source_scope=None,current=None):
    field='ocr_admit_turn' if admit else 'ocr_run_turn'
    turn=c.execute('SELECT '+field+' FROM media_dispatch WHERE id=1').fetchone()[0]
    if type(turn)is not int or not 0<=turn<4:raise MirrorError('media_store_binding')
    lanes=[];scans={}
    count=min(BATCH,max(0,limit)*(8 if current else 1))
    if not count:
        return [],turn,turn,scans
    for recent in (True,False):
        if admit:
            columns="SELECT j.key,j.username,j.source,j.result"
            where=(" FROM jobs j WHERE j.kind='image' AND j.status='ready' "
                   "AND NOT EXISTS (SELECT 1 FROM image_derivations d WHERE d.key=j.key AND d.version=? AND d.engine=? AND (d.upstream=j.result OR d.status='running')) ")
            params=[version,engine];order='j.key'
        else:
            columns="SELECT d.key,d.source,d.representation,d.attempts,d.upstream,j.username"
            where=(" FROM image_derivations d JOIN jobs j ON j.key=d.key "
                   "WHERE d.version=? AND d.engine=? AND d.attempts<? ")
            params=[version,engine,MAX_ATTEMPTS,tick];order='d.attempts DESC,d.due,d.key'
            if source_scope is None:
                where+="AND d.status IN ('pending','failed') AND d.due<=? "
            else:
                where+="AND d.source=j.source AND ((d.status IN ('pending','failed') AND d.due<=?) OR (d.status='running' AND d.lease<=?)) "
                params.append(tick)
        where+='AND j.recent_at'+('>?'if recent else'<=?')
        params.append(tick-600)
        if source_scope is None:
            lanes.append(_image_sql(c,columns+where+' ORDER BY '+order+' LIMIT ?',(*params,count)).fetchall())
            continue
        clause, arguments = source_scope.job_filter('j.source')
        rank_columns = ('j.key',) if admit else ('-d.attempts','d.due','d.key')
        slot = ('ocr:admit:' if admit else 'ocr:run:') + ('recent' if recent else 'history')
        page, checkpoint = _partial_page(c,columns+','+','.join(rank_columns)+where+clause,
                                         (*params,*arguments),rank_columns,count,slot,[source_scope.scan_binding,engine,version])
        if admit:
            lanes.append([row for row,rank in page])
            scans[checkpoint] = {row[0]:rank for row,rank in page}
        else:
            eligible = [(row,rank,current(row)) for row,rank in page]
            lanes.append([row for row,rank,approved in eligible if approved])
            # Only the proven rejected prefix moves a missed lane. The result
            # below records which lane actually used its eligible head.
            scans[checkpoint] = eligible
    result=[];cursor=turn
    for _ in range(max(0,min(BATCH,limit))):
        chosen=0 if cursor<3 else 1
        if not lanes[chosen]:chosen=1-chosen
        if not lanes[chosen]:break
        result.append(lanes[chosen].pop(0));cursor=(cursor+1)%4
    if current is not None:
        picked = {row[0] for row in result}
        for checkpoint, page in scans.items():
            _advance_partial_scan(c,checkpoint,[(rank,(row[0] in picked or None) if approved else False)
                                                 for row,rank,approved in page])
    return result,turn,cursor,scans


def enqueue_image_derivations(config, *, engine, version=IMAGE_PIPELINE_VERSION, limit=BATCH, statistics=None, source_scope=None):
    """Hash bounded snapshots without writer ownership; admit with current-row checks."""
    c = _image_connect(config)
    count = 0
    try:
        allowed, args = source_scope.job_filter('d.source') if source_scope is not None else ('',[])
        columns = "SELECT d.rowid,d.representation,d.status,d.upstream,d.checked,d.source,j.username"
        where = (" FROM image_derivations d JOIN jobs j ON j.key=d.key WHERE d.version=? AND d.engine=? "
                 "AND d.status IN ('ready','invalidated')"+allowed)
        verify_limit = max(0, min(BATCH,limit))
        verify_scan = None
        if source_scope is None or not verify_limit:
            verify = _image_sql(c,columns+where+" ORDER BY d.checked,d.rowid LIMIT ?",(version,engine,*args,verify_limit)).fetchall()
        else:
            page, verify_scan = _partial_page(c,columns+',d.checked,d.rowid'+where,(version,engine,*args),
                                              ('d.checked','d.rowid'),verify_limit,'ocr:verify',
                                              [source_scope.scan_binding,engine,version])
            verify = [row for row,rank in page]
        active = _image_sql(c, 'SELECT count(*) FROM image_derivations WHERE ' + IMAGE_RESERVED_SQL + " AND (status='running' OR (version=? AND engine=?))", (version, engine)).fetchone()[0]
        allowance = max(0, min(BATCH, limit, IMAGE_ADMISSION - active))
        rows,admit_turn,_,admission_scans = _select_ocr(c,engine,version,time.time(),allowance,admit=True,source_scope=source_scope)
        if statistics is not None:
            statistics['verified']+=len(verify);statistics['admission_checked']+=len(rows)
        verified = []
        verify_outcomes = {}
        for row in verify:
            check_deadline()
            eligible = _ocr_source_current(source_scope,row[6],row[5])
            if not eligible:
                verify_outcomes[row[0]] = eligible
                continue
            rep = json.loads(row[1])
            try:
                payload, digest = _image_payload(config, rep,statistics=statistics)
                valid = digest == rep.get('decoded_sha256')
            except (OSError, ValueError, KeyError, MirrorError):
                valid = False
            verified.append((row, valid))
        prepared = []
        admission_outcomes = {}
        for key, username, source, raw in rows:
            check_deadline()
            eligible = _ocr_source_current(source_scope,username,source)
            if not eligible:
                admission_outcomes[key] = eligible
                continue
            _media_authorized(config,username,source)
            value = json.loads(raw or '{}')
            candidates = [r for r in value.get('image', {}).get('representations', [])
                          if r.get('status') == 'decoded' and r.get('path')]
            if not candidates:
                rep, status, reason = {}, 'failed', 'ocr_decoded_image_missing'
            else:
                rep = dict(max(candidates, key=lambda r: (r.get('size', [0, 0])[0] * r.get('size', [0, 0])[1], r['path'])))
                try:
                    payload, digest = _image_payload(config, rep,statistics=statistics)
                    rep['decoded_sha256'] = digest
                    status, reason = 'pending', None
                except (OSError, ValueError, KeyError, MirrorError):
                    status, reason = 'rejected', 'ocr_image_binding'
            prepared.append((key, username, source, raw, rep, status, reason))
        from .native_mirror_sync import writer_lock
        with writer_lock(source_scope.root,0) if source_scope is not None else nullcontext():
            _image_sql(c, 'BEGIN IMMEDIATE')
            checked = _image_sql(c, 'SELECT COALESCE(MAX(checked),0)+1 FROM image_derivations').fetchone()[0]
            for (rowid, representation, state, upstream, prior_checked, source, username), valid in verified:
                eligible = _ocr_item_current(source_scope,username,source)
                verify_outcomes[rowid] = eligible
                if not eligible:
                    continue
                _image_sql(c, 'UPDATE image_derivations SET checked=?,status=?,reason=? WHERE rowid=? AND representation=? AND status=? AND upstream=? AND checked=?',
                           (checked, 'ready' if valid else 'invalidated', None if valid else 'decoded_payload_changed', rowid, representation, state, upstream, prior_checked))
            if source_scope is None:
                _image_sql(c, "UPDATE image_derivations SET status='superseded',lease=0,claim='' WHERE status IN ('pending','failed') AND (version<>? OR engine<>?)", (version, engine))
                capacity = max(0, IMAGE_ADMISSION - _image_sql(c, 'SELECT count(*) FROM image_derivations WHERE ' + IMAGE_RESERVED_SQL).fetchone()[0])
                _image_sql(c, "UPDATE image_derivations SET status='pending',attempts=0,due=0 WHERE rowid IN (SELECT rowid FROM image_derivations WHERE status='superseded' AND version=? AND engine=? LIMIT ?)", (version, engine, capacity))
            available = max(0, IMAGE_ADMISSION - _image_sql(c, 'SELECT count(*) FROM image_derivations WHERE ' + IMAGE_RESERVED_SQL).fetchone()[0])
            for key, username, source, raw, rep, status, reason in prepared:
                eligible = _ocr_item_current(source_scope,username,source)
                admission_outcomes[key] = eligible
                if not eligible:
                    continue
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
            if verify_scan is not None:
                _advance_partial_scan(c,verify_scan,[(rank,verify_outcomes.get(row[0])) for row,rank in page])
            for checkpoint, ranks in admission_scans.items():
                _advance_partial_scan(c,checkpoint,[(rank,admission_outcomes.get(key)) for key,rank in ranks.items()])
            if count and not _image_sql(c,'UPDATE media_dispatch SET ocr_admit_turn=? WHERE id=1 AND ocr_admit_turn=?',((admit_turn+count)%4,admit_turn)).rowcount:
                c.rollback();return 0
            _image_retry(c.commit)
            return count
    except MirrorError as error:
        c.rollback()
        if source_scope is None or str(error)!='sync_busy':
            raise
        return 0
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


def _ocr_item_current(scope, username, source):
    if scope is None:
        return True
    from .native_mirror_media import MediaItemDeferred
    try:
        scope.frozen(username,json.loads(source))
        return True
    except MediaItemDeferred:
        return False


def _ocr_source_current(scope, username, source):
    if scope is None:
        return True
    from .native_mirror_sync import writer_lock
    try:
        with writer_lock(scope.root,0):
            return _ocr_item_current(scope,username,source)
    except MirrorError as error:
        if str(error) != 'sync_busy':
            raise
        return None   # A busy writer does not prove the queue position stale.


def _release_scoped_ocr(config, claims, version, engine, lease):
    if not claims:
        return
    c=_image_connect(config)
    try:
        with c:
            for key, before, attempts, token in claims:
                _image_sql(c,"UPDATE image_derivations SET status=?,attempts=?,lease=?,claim=? "
                           "WHERE key=? AND version=? AND engine=? AND status='running' AND attempts=? AND lease=? AND claim=?",
                           (*before,key,version,engine,attempts+1,lease,token))
    finally:
        c.close()


def run_image_derivations(config, *, recognizer=None, limit=4, now=None, version=IMAGE_PIPELINE_VERSION, maintenance_limit=None, source_scope=None):
    """Finite owned-media phase: only decoded local files, no Source/decode fallback."""
    media_segment.checkpoint('claim')
    tick = time.time() if now is None else now
    engine = recognizer.identity if recognizer is not None else 'unconfigured'
    maintenance=dict(verified=0,admission_checked=0,payload_read_attempts=0,payload_read_failures=0,payload_reads=0,payload_bytes=0)
    execution=dict(payload_read_attempts=0,payload_read_failures=0,payload_reads=0,payload_bytes=0)
    if maintenance_limit is None:
        enqueue_image_derivations(config, engine=engine, version=version,source_scope=source_scope)
    elif maintenance_limit>0:
        enqueue_image_derivations(config, engine=engine, version=version,limit=min(1,maintenance_limit),statistics=maintenance,source_scope=source_scope)
    from .native_mirror_sync import writer_lock
    claims=[]
    rows=[]
    c = _image_connect(config)
    try:
        with writer_lock(source_scope.root,0) if source_scope is not None else nullcontext():
            _image_sql(c, 'BEGIN IMMEDIATE')
            if source_scope is None:
                _image_sql(c, "UPDATE image_derivations SET status='failed',reason='retry_limit',lease=0,claim='' WHERE status='running' AND lease<=? AND attempts>=?", (tick, MAX_ATTEMPTS))
                _image_sql(c, "UPDATE image_derivations SET status='pending',lease=0,claim='' WHERE status='running' AND lease<=? AND attempts<?", (tick, MAX_ATTEMPTS))
            current=(lambda row:_ocr_item_current(source_scope,row[5],row[1])) if source_scope is not None else None
            candidates,run_turn,next_turn,_ = _select_ocr(c,engine,version,tick,limit,admit=False,source_scope=source_scope,current=current)
            if candidates:_image_sql(c,'UPDATE media_dispatch SET ocr_run_turn=? WHERE id=1 AND ocr_run_turn=?',(next_turn,run_turn))
            import secrets
            for row in candidates:
                media_segment.checkpoint('claim')
                token = secrets.token_hex(16)
                if source_scope is not None or media_segment.active():
                    before=_image_sql(c,'SELECT status,attempts,lease,claim FROM image_derivations WHERE key=? AND version=? AND engine=?',
                                      (row[0],version,engine)).fetchone()
                    claims.append((row[0],before,row[3],token))
                _image_sql(c, "UPDATE image_derivations SET status='running',attempts=attempts+1,lease=?,claim=? WHERE key=? AND version=? AND engine=?", (tick + 180, token, row[0], version, engine))
                rows.append((*row, token))
            _image_retry(c.commit)
    except MirrorError as error:
        c.rollback()
        if source_scope is None or str(error)!='sync_busy':
            raise
        rows.clear()
    except BaseException:
        c.rollback()
        raise
    finally:
        c.close()
    completed = stale = 0
    segment_yielded = False
    try:
        for key, source, representation, attempts, upstream, username, token in rows:
            check_deadline()
            eligible = _ocr_source_current(source_scope,username,source)
            rep = json.loads(representation) if eligible else {}
            result = dict(source=json.loads(source), representation=rep, pipeline_version=version,
                          engine_identity=engine, description={'status': 'unconfigured', 'text': None, 'reason': 'description_model_unconfigured'})
            status, reason = 'failed', None
            try:
                if not eligible:
                    pass
                elif recognizer is None:
                    status, reason = 'unconfigured', 'ocr_runtime_unconfigured'
                    result['ocr'] = dict(status=status, text=None, reason=reason)
                else:
                    payload, sha = _image_payload(config, rep,statistics=execution)
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
                    _, current_sha = _image_payload(config, rep,statistics=execution)
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
            from contextlib import ExitStack
            from .native_mirror_media import MediaItemDeferred
            from .native_mirror_sync import writer_lock
            with ExitStack() as lock:
                if source_scope is not None and eligible:
                    try:
                        lock.enter_context(writer_lock(source_scope.root,0))
                        source_scope.frozen(username,json.loads(source))
                    except MirrorError as error:
                        if not isinstance(error,MediaItemDeferred) and str(error)!='sync_busy':raise
                        eligible=False
                c = _image_connect(config)
                try:
                    _image_sql(c, 'BEGIN IMMEDIATE')
                    if not eligible:
                        c.rollback()
                        continue
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
    except media_segment.SegmentYield:
        segment_yielded=True
        raise
    finally:
        if source_scope is not None or segment_yielded:
            _release_scoped_ocr(config,claims,version,engine,tick+180)
    return dict(image_ocr_attempted=len(rows), image_ocr_completed=completed, image_ocr_stale=stale, source_messages_queried=0,image_ocr_maintenance=maintenance,image_ocr_execution=execution)




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


def _backfill_account(config,limit,*,diagnostic=None,source_scope=None):
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
        check_deadline()
        try:
            # Pin just this page in a read transaction before copying any mirror rows.
            with sc.registry(config, snapshot=False) as db:
                sc._registry_page_size(db)
                expected=sc.state(db,'media_backfill',['',''])
                allowed, arguments = source_scope.member_filter('shard','table_name') if source_scope is not None else ('',[])
                base='SELECT shard,table_name FROM members WHERE '
                ordered=' ORDER BY shard,table_name LIMIT 64'
                rows=db.execute(base+'(shard,table_name)>(?,?)'+allowed+ordered,(*expected,*arguments)).fetchall()
                if not rows:rows=db.execute(base+'1=1'+allowed+ordered,arguments).fetchall()
                observations = OrderedDict()
                entries = []
                until = time.monotonic() + BACKFILL_PROOF_SECONDS
                for shard, table in rows:
                    if entries and time.monotonic() >= until:
                        break
                    proof = sc.member(config,db,shard,table,_observations=observations)
                    entries.append((shard,table,proof))
                db.rollback()  # Release the read lock before the context's fresh binding check.
        except sqlite3.OperationalError as error:
            if not _sqlite_lock_error(error):
                raise
            check_deadline()
            sc.query_scope_guard(config,before)
            return finish('pending_writer')
        for shard,table,proof in entries:
            check_deadline();sc.query_scope_guard(config,before)
            selected=[]
            if proof.get('supported') and (root/shard).is_file():
                username=proof.get('username') or proof['ref']
                if source_scope is None:
                    _consume_repair(config,queue,shard,table)
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
                def enqueue_page():
                    enqueue_rows(config,shard,table,username,columns,selected)
                    high=max(r[columns.index('local_id')] for r in selected)
                    with queue:queue.execute('INSERT OR REPLACE INTO checkpoints VALUES(?,?,?)',(shard,table,high))
                if selected and source_scope is None:
                    enqueue_page()
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
                if selected and source_scope is not None:
                    from .native_mirror_media import MediaItemDeferred
                    from .source_records import RawMessage,_content_fingerprint
                    record=dict(zip(columns,selected[0]))
                    message=RawMessage(record['local_id'],record.get('server_id'),record['local_type'],record['create_time'],
                                       record['real_sender_id'],record['message_content'],record['WCDB_CT_message_content'])
                    sample=dict(account_id=config['account_id'],source_generation=config['source_generation'],shard=shard,
                                table=table,local_id=message.local_id,content_sha256=_content_fingerprint(message))
                    try:
                        source_scope.frozen(username,sample)
                    except MediaItemDeferred:
                        pass
                    else:
                        enqueue_page()
                        count+=len(selected)
                with sc.registry(config,write=True) as db:
                    sc.save(db,'media_backfill',[shard,table]);_account_registry_commit(db)
                check_deadline();sc.query_scope_guard(config,before)
            expected=[shard,table]
            if count>=limit:break
        check_deadline();sc.query_scope_guard(config,before);return finish('processed_page')
    finally:queue.close()


from .failure_evidence import _register
_register(_set_job,_release_media_claims,run_media,_backfill_note,backfill_status,_backfill_account)
