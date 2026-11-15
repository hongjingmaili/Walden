"""Copy only exact resource-bound image bytes into the private mirror."""
import hashlib
import os
import sqlite3
import stat
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from .common import quote_identifier as qi
from .native_deadline import check_deadline
from .image_runtime import ImageMessageIdentity, ImageUnavailable, _bound_file, _resource_facts
import json


def frozen_message(config, root, current):
    from .source_records import RawMessage, _content_fingerprint
    source = current['source']
    path = root / source['shard']
    with sqlite3.connect(readonly_database_uri(path), uri=True) as connection:
        connection.execute('PRAGMA query_only=ON')
        connection.execute('BEGIN')
        if connection.execute('SELECT * FROM __walden_binding').fetchall() != [(config['account_id'], config['source_generation'], path.name)]:
            raise MirrorError('source_identity_mismatch')
        columns = [row[1] for row in connection.execute('PRAGMA table_info(' + qi(source['table']) + ')')]
        row = connection.execute('SELECT * FROM ' + qi(source['table']) + ' WHERE local_id=?', (source['local_id'],)).fetchone()
    if row is None:
        raise MirrorError('media_message_changed')
    item = dict(zip(columns, row))
    message = RawMessage(item['local_id'], item.get('server_id'), item['local_type'], item['create_time'], item['real_sender_id'], item['message_content'], item['WCDB_CT_message_content'])
    if _content_fingerprint(message) != source['content_sha256']:
        raise MirrorError('media_message_changed')
    return item


def capture_window_images(config, root, window, opener, *, decode=True):
    check_deadline()
    gaps = []
    resources = None
    try:
        for current in window['messages']:
            check_deadline()
            if current['content']['kind'] != 'image':
                continue
            current['image'] = {'status': 'unavailable', 'reason': 'local_image_not_saved'}
            try:
                item = frozen_message(config, root, current)
                identity = ImageMessageIdentity(window['selected_username'], item['server_id'], item['local_id'], item['create_time'], item['local_type'], ZoneInfo(config.get('query_timezone', 'UTC')))
                key = _image_key(identity, current['source'])
                _write_private(root, ('bounded-images', key), 'state.json', b'{"saved":false}')
            except (MirrorError, TypeError, ValueError, OSError):
                check_deadline()
                current['image']['reason'] = 'image_identity_unavailable'
                gaps.append('image_identity_unavailable')
                continue
            try:
                if resources is None:
                    path = Path(config['image_database']).resolve()
                    source_root = Path(config.get('live_db_root', config['message_root'])).resolve()
                    if source_root not in path.parents:
                        raise ImageUnavailable('image_source_outside_root')
                    check_deadline()
                    resources = opener(path)
                    resources.execute('BEGIN')
                check_deadline()
                bound = _bound_file(resources, identity, Path(config['image_attachments_root']))
                facts = _image_resource_hash(resources, identity)
                representations = []
                for (size, _), payload in zip(bound.files, bound._hardlink_bytes):
                    if payload is None:
                        raise ImageUnavailable('image_attachment_changed')
                    digest = hashlib.sha256(payload).hexdigest()
                    _write_private(root, ('bounded-images', key), digest, payload)
                    representations.append({'size': size, 'sha256': digest})
                state = {'saved': True, 'account': config['account_id'], 'generation': config['source_generation'], 'resource': facts, 'message': current['source'], 'representations': representations, 'expected': list(bound.expected_sizes), 'missing': list(bound.missing_sizes)}
                _write_private(root, ('bounded-images', key), 'state.json', json.dumps(state).encode())
                current['image'] = decode_window_image(config, root, identity, current['source']) if decode else {'status':'saved'}
            except (ImageUnavailable, OSError, ValueError, KeyError) as error:
                check_deadline()
                gaps.append(error.code if isinstance(error, ImageUnavailable) else 'image_capture_unavailable')
    finally:
        if resources is not None:
            resources.close()
    return gaps


def _read_private(root, parts, name, limit):
    handles = []
    try:
        parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        handles.append(parent)
        for part in parts:
            parent = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            handles.append(parent)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, 'rb') as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise ValueError('media_size')
            return source.read(limit + 1)
    finally:
        for fd in reversed(handles):
            os.close(fd)


def decode_window_image(config, root, identity, message_source=None):
    from .image_runtime import _decode_image_bytes, read_private_image_config
    parts = ('bounded-images', _image_key(identity, message_source))
    try:
        state = json.loads(_read_private(root, parts, 'state.json', 65536))
        if (message_source is not None and state.get('message') != message_source) or not state.get('saved') or state['account'] != config['account_id'] or state['generation'] != config['source_generation']:
            raise ValueError('binding')
        codes, scope = read_private_image_config(Path(config['image_key_config'])) if config.get('image_key_config') else ((), '')
        decoded = []
        for representation in state['representations']:
            digest = representation['sha256']
            if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
                raise ValueError('digest')
            payload = _read_private(root, parts, digest, 32 * 1024 * 1024)
            if hashlib.sha256(payload).hexdigest() != digest:
                raise ValueError('digest')
            result = _decode_image_bytes(payload, output_root=Path(config['image_output_root']), key_codes=codes, account_scope=scope, ffmpeg=Path(config['image_ffmpeg']) if config.get('image_ffmpeg') else None)
            decoded.append(dict(resource_size_bytes=representation['size'], **result))
        count = sum(row['status'] == 'decoded' for row in decoded)
        return {'status': 'decoded' if count == len(decoded) and not state['missing'] else 'partial' if count else 'unavailable', 'representations': decoded, 'expected_resource_sizes': state['expected'], 'missing_resource_sizes': state['missing']}
    except (OSError, ValueError, KeyError, TypeError):
        return {'status': 'unavailable', 'reason': 'local_image_not_saved'}


def _image_key(identity, message_source=None):
    return hashlib.sha256(repr((identity.conversation_id, identity.server_id, identity.local_id, identity.create_time, identity.local_type, tuple(sorted((message_source or {}).items())))).encode()).hexdigest()


def _image_resource_hash(resource, identity):
    message, packed, sizes = _resource_facts(resource, identity)
    return hashlib.sha256(repr((message, packed, sizes)).encode()).hexdigest()


def image_saved(resource, identity, root, message_source):
    path = root / 'image-state' / (_image_key(identity, message_source) + '.json')
    try:
        if path.is_symlink() or path.stat().st_size > 4096:
            return False
        state = json.loads(path.read_text())
        return state == {'resource': _image_resource_hash(resource, identity), 'saved': True, 'message': message_source}
    except (OSError, ValueError, ImageUnavailable):
        return False
from .live_readonly import readonly_database_uri
from .native_mirror_store import MirrorError


def _write_private(root, parts, name, payload):
    """Walk pinned directory descriptors; atomically replace one private file."""
    import secrets
    handles = []
    temporary = None
    try:
        # The caller's mirror root was validated by mirror_root; pin it before
        # traversing descendants. Never resolve a descendant symlink.
        root.mkdir(mode=0o700, exist_ok=True)
        parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        handles.append(parent)
        for part in parts:
            if part in ('', '.', '..') or '/' in part:
                raise MirrorError('invalid_media_path')
            try:
                os.mkdir(part, 0o700, dir_fd=parent)
            except FileExistsError:
                pass
            parent = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            handles.append(parent)
            os.fchmod(parent, 0o700)
        if name in ('', '.', '..') or '/' in name:
            raise MirrorError('invalid_media_path')
        temporary = '.media-' + secrets.token_hex(16)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        temporary = None
    finally:
        if temporary is not None:
            os.unlink(temporary, dir_fd=parent)
        for fd in reversed(handles):
            os.close(fd)


def save_images(config, root, scope):
    """Called under the mirror writer lock, after message/resource copying."""
    check_deadline()
    if not config.get('image_attachments_root') or not (root / 'image-resources.db').is_file():
        return []
    gaps = []
    with sqlite3.connect(readonly_database_uri(root / 'image-resources.db'), uri=True) as resource:
        resource.execute('PRAGMA query_only=ON')
        resource.execute('BEGIN')
        if resource.execute('SELECT * FROM __walden_binding').fetchall() != [(config['account_id'], config['source_generation'], 'image-resources.db')]:
            raise MirrorError('image_source_identity_mismatch')
        for path in sorted(root.glob('message_*.db')) + sorted(root.glob('biz_message_*.db')):
            with sqlite3.connect(readonly_database_uri(path), uri=True) as messages:
                messages.execute('PRAGMA query_only=ON')
                messages.execute('BEGIN')
                if messages.execute('SELECT * FROM __walden_binding').fetchall() != [(config['account_id'], config['source_generation'], path.name)]:
                    raise MirrorError('source_identity_mismatch')
                for username in scope:
                    table = 'Msg_' + hashlib.md5(username.encode()).hexdigest()
                    if not messages.execute('SELECT 1 FROM sqlite_master WHERE type=\'table\' AND name=?', (table,)).fetchone():
                        continue
                    columns = [row[1] for row in messages.execute('PRAGMA table_info(' + qi(table) + ')')]
                    for row in messages.execute('SELECT * FROM ' + qi(table) + ' WHERE (local_type & 65535)=3'):
                        check_deadline()
                        item = dict(zip(columns, row))
                        from .source_records import RawMessage, _content_fingerprint
                        message = RawMessage(item['local_id'], item.get('server_id'), item['local_type'], item['create_time'], item['real_sender_id'], item['message_content'], item['WCDB_CT_message_content'])
                        source_identity = dict(account_id=config['account_id'], source_generation=config['source_generation'], shard=path.name, table=table, local_id=item['local_id'], content_sha256=_content_fingerprint(message))
                        created = item['create_time']
                        try:
                            identity = ImageMessageIdentity(username, item.get('server_id'), item['local_id'], created, item['local_type'], ZoneInfo(config.get('query_timezone', 'UTC')))
                            state_name = _image_key(identity, source_identity) + '.json'
                            _write_private(root, ('image-state',), state_name, b'{"saved":false}')
                            resource_hash = _image_resource_hash(resource, identity)
                            check_deadline()
                            bound = _bound_file(resource, identity, Path(config['image_attachments_root']))
                            folder = root / 'image-attachments' / hashlib.md5(username.encode()).hexdigest() / datetime.fromtimestamp(created, identity.display_timezone).strftime('%Y-%m') / 'Img'
                            for (_, source), payload in zip(bound.files, bound._hardlink_bytes):
                                if payload is None:
                                    raise ImageUnavailable('image_attachment_changed')
                                _write_private(root, folder.relative_to(root).parts, source.name, payload)
                            if bound.missing_sizes:
                                gaps.append('image_attachment_missing')
                            else:
                                _write_private(root, ('image-state',), state_name, json.dumps({'resource': resource_hash, 'saved': True, 'message': source_identity}).encode())
                        except (ImageUnavailable, ValueError, TypeError) as error:
                            check_deadline()
                            gaps.append(error.code if isinstance(error, ImageUnavailable) else 'image_identity_unavailable')
    return sorted(set(gaps))


def local_voice(config, root, shard, username, item, transcriber=None):
    """Strict local result read. The compatibility transcriber argument is never called."""
    check_deadline()
    from .voice_transcript import _native_transcript, MAX_PACKED_INFO_BYTES
    from .source_records import RawMessage, _content_fingerprint
    from .native_media_work import local_result
    packed=item.get('packed_info_data')
    native,text=_native_transcript(packed) if isinstance(packed,bytes) and len(packed)<=MAX_PACKED_INFO_BYTES else ('missing',None)
    message=RawMessage(item['local_id'],item.get('server_id'),item['local_type'],item['create_time'],item['real_sender_id'],item['message_content'],item['WCDB_CT_message_content'])
    source=dict(account_id=config['account_id'],source_generation=config['source_generation'],shard=shard,
                table='Msg_'+hashlib.md5(username.encode()).hexdigest(),local_id=item['local_id'],content_sha256=_content_fingerprint(message))
    cached=local_result(config,source) or {'status':'pending'}
    result={'status':cached['status'],'audio':cached.get('audio',{'status':'pending'}),
            'transcript':cached.get('transcript',{'status':'pending','text':None})}
    if text:
        result['transcript']={'status':'ready','text':text,'source':'wechat_native_transcript'}
    if cached.get('reason'):result['reason']=cached['reason']
    if cached.get('capture'):result['capture']=cached['capture']
    return result


def voice_key(config, shard, username, row):
    return hashlib.sha256(repr((config['account_id'], config['source_generation'], shard, username, tuple(row))).encode()).hexdigest()


def safe_voice_audio(value):
    if type(value) is not dict:return {}
    result={}
    enums={'association_status':{'not_read','not_needed','unavailable','ambiguous','identity_mismatch','unique'},'payload_status':{'unknown','empty','available'},'format':{'silk','unknown'},'decode_status':{'not_attempted','source_changed','unavailable','transcribed'}}
    for key,allowed in enums.items():
        item=value.get(key)
        if key in value and item is None and key=='format':result[key]=None
        elif type(item) is str and item in allowed:result[key]=item
    for key in ('match_count','byte_count'):
        item=value.get(key)
        if type(item) is int and item>=0:result[key]=item
        elif key in value and item is None and key=='byte_count':result[key]=None
    if type(value.get('source_complete')) is bool:result['source_complete']=value['source_complete']
    sha=value.get('audio_payload_sha256')
    if 'audio_payload_sha256' in value and sha is None:result['audio_payload_sha256']=None
    elif type(sha) is str and len(sha)==64 and all(c in '0123456789abcdef' for c in sha):result['audio_payload_sha256']=sha
    return result


def safe_voice_failure(error,stage):
    from .source_setup import SourceSetupError
    known=(PermissionError,FileNotFoundError,TimeoutError,OSError,ValueError,KeyError,TypeError,sqlite3.Error,sqlite3.OperationalError,sqlite3.DatabaseError,sqlite3.IntegrityError,SourceSetupError,MirrorError)
    name=type(error).__name__ if type(error) in known else 'OSError' if isinstance(error,OSError) else 'sqlite3.Error' if isinstance(error,sqlite3.Error) else 'UnknownError'
    cause=error if isinstance(error,OSError) else error.__cause__ if isinstance(error.__cause__,OSError) else None
    number=getattr(cause,'errno',None);code=getattr(error,'sqlite_errorcode',None)
    if type(code) is not int and isinstance(error.__cause__,sqlite3.Error):code=getattr(error.__cause__,'sqlite_errorcode',None)
    return dict(stage=stage if stage in ('voice_source_validate','voice_source_open','voice_capture','request_audio_capture') else 'unknown',exception_class=name,errno=number if type(number) is int else None,sqlite_errorcode=code if type(code) is int else None)


def voice_capture_evidence(state,error=None,stage='request_audio_capture'):
    state=state if type(state) is dict else {}
    failure=state.get('capture_failure');clean=None
    if type(failure) is dict:
        names={'PermissionError','FileNotFoundError','TimeoutError','OSError','ValueError','KeyError','TypeError','Error','OperationalError','DatabaseError','IntegrityError','SourceSetupError','MirrorError','sqlite3.Error','UnknownError'}
        stages={'voice_source_validate','voice_source_open','voice_capture','request_audio_capture','unknown'}
        if type(failure.get('exception_class')) is str and type(failure.get('stage')) is str and failure['exception_class'] in names and failure['stage'] in stages:
            clean={k:failure[k] for k in ('stage','exception_class')}
            for key in ('errno','sqlite_errorcode'):clean[key]=failure.get(key) if type(failure.get(key)) is int else None
    audio=safe_voice_audio(state.get('audio'))
    return dict(receipt_status='observed' if audio else 'unknown',audio=audio,failure=clean or (safe_voice_failure(error,stage) if error is not None else None))


def save_voices(config, root, scope, opener, *, selected=None):
    check_deadline()
    from contextlib import ExitStack
    from .source_setup import require_complete_voice_source, SourceSetupError
    from .voice_transcript import NativeVoiceIdentity, capture_bound_voice, _native_transcript, MAX_PACKED_INFO_BYTES
    gaps = []
    with ExitStack() as stack:
        connections = None
        unavailable = False
        source_failure=None
        for path in sorted(root.glob('message_*.db')) + sorted(root.glob('biz_message_*.db')):
            message = stack.enter_context(sqlite3.connect(readonly_database_uri(path), uri=True))
            message.execute('PRAGMA query_only=ON')
            message.execute('BEGIN')
            if message.execute('SELECT * FROM __walden_binding').fetchall() != [(config['account_id'], config['source_generation'], path.name)]:
                raise MirrorError('source_identity_mismatch')
            for username in scope:
                table = 'Msg_' + hashlib.md5(username.encode()).hexdigest()
                columns = {row[1] for row in message.execute('PRAGMA table_info(' + qi(table) + ')')}
                if not {'local_type', 'server_id', 'local_id', 'create_time'}.issubset(columns):
                    continue
                packed_column = 'packed_info_data' if 'packed_info_data' in columns else 'NULL'
                ids=sorted(local for shard,target,local in selected if shard==path.name and target==table) if selected is not None else None
                if ids is not None and not ids:continue
                sql='SELECT server_id,local_id,create_time,local_type,'+packed_column+',real_sender_id,message_content,WCDB_CT_message_content FROM '+qi(table)+' WHERE (local_type & 65535)=34'
                args=()
                if ids is not None:
                    if len(ids)>128:raise MirrorError('media_window_too_large')
                    sql+=' AND local_id IN ('+','.join('?' for _ in ids)+')';args=tuple(ids)
                for server, local, created, kind, packed, sender, content, compression in message.execute(sql,args):
                    key = voice_key(config, path.name, username, (server, local, created, kind, packed, sender, content, compression))
                    _write_private(root, ('voice-state',), key + '.json', b'{"saved":false}')
                    if connections is None:
                        connections = []
                        try:
                            capture_stage='voice_source_validate'
                            require_complete_voice_source(config)
                            for source in config['voice_databases']:
                                source = Path(source).resolve()
                                source_root = Path(config.get('live_db_root', config['message_root'])).resolve()
                                if source_root not in source.parents:
                                    raise MirrorError('voice_source_outside_root')
                                check_deadline()
                                capture_stage='voice_source_open'
                                connection = opener(source)
                                stack.callback(connection.close)
                                connection.execute('BEGIN')
                                connections.append(connection)
                        except (SourceSetupError, MirrorError, OSError, sqlite3.Error) as error:
                            if isinstance(error,MirrorError) and str(error)=='source_replaced':raise
                            check_deadline()
                            unavailable = True;source_failure=safe_voice_failure(error,capture_stage)
                    check_deadline()
                    capture_failure=source_failure
                    try:audio, payload = capture_bound_voice(connections, username, NativeVoiceIdentity(server, local, created), source_unavailable=unavailable)
                    except (SourceSetupError, MirrorError, OSError, sqlite3.Error,ValueError,KeyError,TypeError) as error:
                        if isinstance(error,MirrorError) and str(error)=='source_replaced':raise
                        check_deadline()
                        audio={};payload=None;capture_failure=safe_voice_failure(error,'voice_capture')
                    safe_audio=safe_voice_audio(audio)
                    _write_private(root,('voice-state',),key+'.json',json.dumps(dict(saved=False,audio=safe_audio,capture_failure=capture_failure)).encode())
                    if payload is None:
                        gaps.append('voice_source_unavailable')
                        continue
                    _write_private(root, ('voice-payloads',), key + '.silk', payload)
                    state = {'saved': True, 'sha256': hashlib.sha256(payload).hexdigest(), 'audio': safe_audio}
                    _write_private(root, ('voice-state',), key + '.json', json.dumps(state).encode())
    return sorted(set(gaps))
