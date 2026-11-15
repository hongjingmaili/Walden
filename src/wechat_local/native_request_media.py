"""Exact final request selection: Source capture in30s child, codecs in local worker."""
import hashlib,json
from pathlib import Path
from .native_deadline import check_deadline
from .native_mirror_store import MirrorError
from .native_follow_policy import Store,digest
from .native_target_request import need


def selected(config,window):
    from .native_target_request import local_result,_proof,_cache_window_complete
    proof=_proof(config,window)
    need(proof and proof.get('complete') and _cache_window_complete(config,proof),'request_cache_incomplete')
    local=local_result(config,window,media=False)
    need(local['status']=='ready' and local.get('result') is not None,'request_cache_incomplete')
    messages=local['result']['messages']
    # These are GLOBAL final result.messages, not per-shard proof candidates.
    for row in messages:
        source=row['source']
        need(source['account_id']==config['account_id'] and source['source_generation']==config['source_generation'] and source['table']=='Msg_'+hashlib.md5(config['mirror_scope'][0].encode()).hexdigest() and source['local_id'] in proof['shards'][source['shard']]['members'],'request_media_scope')
    return messages,proof


def progress_sources(config,messages):
    """Pure cache read: presentation gaps do not decide owned scheduling."""
    from .native_media_work import local_result
    pending=[]
    for item in messages:
        kind=item['content']['kind']
        configured=bool(config.get('image_database') and config.get('image_attachments_root')) if kind=='image' else bool(config.get('voice_databases') and config.get('voice_runtime_root') and config.get('voice_python')) if kind=='audio' else False
        if not configured:continue
        value=local_result(config,item['source'])
        if value is None or value.get('status')=='pending':pending.append(item['source'])
        elif value.get('status')=='ready' and kind=='image' and (value.get('image',{}).get('reason')=='local_image_missing' or value.get('image',{}).get('redecode_pending')):pending.append(item['source'])
        elif value.get('status')=='ready' and kind=='audio' and value.get('audio',{}).get('reason')=='local_audio_missing':pending.append(item['source'])
    return pending


def project(result,config=None):
    states=[]
    for item in result['messages']:
        kind=item['content']['kind']
        if kind=='image':
            value=item.get('image',{});status='ready' if value.get('status')=='decoded' else 'failed' if value.get('status') in ('failed','unavailable') else value.get('media_status',value.get('status','pending'))
            if value.get('status')=='partial':status='partial';value.setdefault('reason','local_image_partial')
            if config is not None and not (config.get('image_database') and config.get('image_attachments_root')):status='unconfigured';value.setdefault('reason','image_source_unconfigured')
            item['media']=dict(status=status,reason=value.get('reason'),presentation='local_decoded_preview_no_OCR');states.append(status)
        elif kind=='audio':
            value=item.get('voice',{});audio=value.get('audio',{});transcript=value.get('transcript',{})
            status='ready' if audio.get('status')=='ready' and transcript.get('status')=='ready' else value.get('status','pending')
            if status=='ready' and audio.get('status')!='ready':status='unconfigured' if not config or not config.get('voice_runtime_root') else 'pending'
            if config is not None and (not config.get('voice_databases') or not config.get('voice_runtime_root') and status!='ready'):status='unconfigured';value.setdefault('reason','voice_source_or_runtime_unconfigured')
            item['media']=dict(status=status,reason=value.get('reason'),audio_status=audio.get('status','pending'),transcript_status=transcript.get('status','pending'));states.append(status)
        elif kind=='quote':
            attrs=item['content'].get('attributes',{});text=attrs.get('referenced_text')
            item['reference']=dict(status='ready' if text else 'missing',origin='embedded_message' if text else 'out_of_window_or_missing',content=text,referenced_type=attrs.get('referenced_type'),actor_label=attrs.get('referenced_actor_label'),source_followed=False,actor_label_provenance='message_claim_not_verified',external_message_status='not_resolved_no_history_follow',quoted_media_status='not_resolved' if attrs.get('referenced_type') in ('3','34') else 'not_requested')
            if not text:states.append('partial')
    result['media_completion']='failed' if 'failed' in states else 'unconfigured' if 'unconfigured' in states else 'partial' if 'partial' in states else 'pending' if any(v!='ready' for v in states) else 'ready'
    result['body_status']='ready'
    result['media_work_pending']=bool(progress_sources(config,result['messages'])) if config is not None else False


def capture(config,window):
    """Only called inside request Source child holding original+cache writer locks."""
    from . import native_media_work as work
    from .native_mirror_media import frozen_message,capture_window_images,save_voices,voice_key,_read_private,_image_key
    from .image_runtime import ImageMessageIdentity
    from .live_readonly import read_private_passphrase,open_encrypted_readonly
    from zoneinfo import ZoneInfo
    root=Path(config['mirror_root']);messages,proof=selected(config,window);phase_sources=progress_sources(config,messages);queued=[];username=config['mirror_scope'][0];secret=[None]
    def opener(path):
        check_deadline()
        if secret[0] is None:secret[0]=read_private_passphrase(Path(config['passphrase_file']))
        return open_encrypted_readonly(path,secret[0])[0]
    def source_stable(shard):
        expected=proof['shards'][shard];path=Path(config['message_root'])/shard
        need(not path.is_symlink(),'source_replaced');stamp=path.stat()
        with path.open('rb') as f:header=hashlib.sha256(f.read(16)).hexdigest()
        after=path.stat();need([stamp.st_dev,stamp.st_ino]==[after.st_dev,after.st_ino]==expected['source_identity'] and header==expected['source_header_sha256'],'source_replaced')
    required=False
    try:
        for current in messages:
            check_deadline();kind=current['content']['kind']
            if kind not in ('image','audio'):continue
            source=current['source']
            if source not in phase_sources:continue
            cached=work.local_result(config,source)
            if cached and cached.get('status')=='ready' and (kind=='image' and cached.get('image',{}).get('status')=='decoded' or kind=='audio' and cached.get('audio',{}).get('status')=='ready' and cached.get('transcript',{}).get('status')=='ready'):continue
            work.enqueue(config,username,source,kind);key=work.media_key(source)
            configured=bool(config.get('image_database') and config.get('image_attachments_root')) if kind=='image' else bool(config.get('voice_databases'))
            if not configured:
                work._set_job(config,key,'unconfigured',{},kind+'_source_unconfigured');continue
            item=frozen_message(config,root,current)
            audio_key=None
            try:
                if kind=='image':
                    identity=ImageMessageIdentity(username,item['server_id'],item['local_id'],item['create_time'],item['local_type'],ZoneInfo(config.get('query_timezone','UTC')))
                    try:
                        state=json.loads(_read_private(root,('bounded-images',_image_key(identity,source)),'state.json',65536))
                        saved=bool(cached and cached.get('captured')) and state.get('saved') is True and state.get('message')==source and state.get('account')==config['account_id'] and state.get('generation')==config['source_generation']
                    except (OSError,ValueError):saved=False
                    if cached and cached.get('image',{}).get('redecode_pending'):
                        if saved:
                            try:
                                for rep in state['representations']:
                                    check_deadline();raw=_read_private(root,('bounded-images',_image_key(identity,source)),rep['sha256'],32*1024*1024)
                                    need(hashlib.sha256(raw).hexdigest()==rep['sha256'],'local_image_payload_missing')
                            except (OSError,ValueError,KeyError,TypeError):saved=False
                        need(saved,'local_image_payload_missing')
                    if not saved:
                        source_stable(source['shard'])
                        gaps=capture_window_images(config,root,{'selected_username':username,'messages':[current]},opener,decode=False)
                        need(current.get('image',{}).get('status')=='saved','request_image_capture_failed')
                        source_stable(source['shard'])
                    value={'captured':True,'image':cached['image'] if cached and cached.get('image',{}).get('redecode_pending') else {'status':'pending','reason':'local_decode_pending'}}
                else:
                    row=tuple(item.get(f) for f in ('server_id','local_id','create_time','local_type','packed_info_data','real_sender_id','message_content','WCDB_CT_message_content'));audio_key=voice_key(config,source['shard'],username,row)
                    try:state=json.loads(_read_private(root,('voice-state',),audio_key+'.json',8192));saved=bool(cached and cached.get('captured')) and state.get('saved') is True
                    except (OSError,ValueError):saved=False
                    if not saved:
                        source_stable(source['shard'])
                        save_voices(config,root,[username],opener,selected={(source['shard'],source['table'],source['local_id'])})
                        source_stable(source['shard'])
                    state=json.loads(_read_private(root,('voice-state',),audio_key+'.json',8192));need(state.get('saved') is True,'request_audio_capture_failed')
                    value={'captured':True,'audio':{'status':'saved'},'transcript':{'status':'pending','text':None}}
                    from .native_mirror_media import voice_capture_evidence
                    value['capture']=dict(voice_capture_evidence(state),source=source,window=window)
                work._set_job(config,key,'pending',value,immediate=True);queued.append(source);required=True
            except (MirrorError,OSError,ValueError,KeyError,TypeError) as error:
                if isinstance(error,MirrorError) and str(error)=='source_replaced':raise
                check_deadline();failure_result={'image':cached['image'],'captured':bool(cached.get('captured'))} if kind=='image' and cached and cached.get('image') else {}
                if kind=='audio':
                    from .native_mirror_media import voice_capture_evidence
                    try:failed_state=json.loads(_read_private(root,('voice-state',),audio_key+'.json',8192)) if type(audio_key) is str else {}
                    except (OSError,ValueError):failed_state={}
                    failure_result['capture']=dict(voice_capture_evidence(failed_state,error),source=source,window=window)
                work._set_job(config,key,'failed',failure_result,'request_'+kind+'_capture_failed')
        Store(root).atomic('request-media-selection.json',dict(window=window,proof_digest=digest(proof),sources=[m['source'] for m in messages],work_sources=queued,source_binding=[config['account_id'],config['source_generation'],username]))
        return required
    finally:secret[0]=None


def run(config,record_path,*,transcriber=None,decoder=None):
    from .native_target_request import read,validate
    from .native_follow_grant import load
    from .native_media_work import run_media,BATCH
    record=json.loads(read(record_path));grant=load(record['follow_grant'],record['follow_grant_sha256']);validate(grant)
    need(grant.get('media')=={'images':True,'audio':True,'references':True},'request_media_authorization_conflict')
    messages,proof=selected(config,grant['window']);sources=[m['source'] for m in messages]
    marker=Store(config['mirror_root']).read('request-media-selection.json')
    need(marker and marker.get('window')==grant['window'] and marker.get('proof_digest')==digest(proof) and marker.get('sources')==sources and marker.get('source_binding')==[config['account_id'],config['source_generation'],config['mirror_scope'][0]],'request_media_selection_changed')
    phase_sources=marker.get('work_sources');need(type(phase_sources) is list and all(s in sources for s in phase_sources),'request_media_selection_changed')
    pending=progress_sources(config,messages);sources=[s for s in phase_sources if s in pending]
    def no_source(*a,**k):raise MirrorError('request_local_media_source_forbidden')
    for _ in range((len(sources)+BATCH-1)//BATCH):
        check_deadline();out=run_media(config,no_source,transcriber=transcriber,decoder=decoder,limit=BATCH,selected_sources=sources,local_only=True)
        if not out['media_attempted']:break
    return dict(gaps=[],request_media_complete=True)


from .failure_evidence import _register
_register(selected,progress_sources,project,capture,run)
