"""One current-tail preview using the existing owned media worker."""
from contextlib import closing, contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from zoneinfo import ZoneInfo

from .image_runtime import (
    ImageMessageIdentity, ImageUnavailable, MAX_PREVIEW_INPUT_BYTES, MAX_PREVIEW_PIXELS,
    _V2_MAGIC, _bound_file, _decode_image_bytes, _resource_facts, read_private_image_config,
)
from .native_deadline import check_deadline
from .native_mirror_store import MirrorError

MAX_SECONDS = 6
MAX_AGE = 30
PREVIEW_PNG_BYTES = 6 * 1024 * 1024
_SHA = re.compile('[0-9a-f]{64}')
_SHARD = re.compile(r'(?:biz_)?message_[0-9]{1,20}\.db')


def hint(value):
    """Narrow child control frame, never a private path or conversation."""
    if type(value) is not dict or set(value) != {'key','shard','anchor'}:
        return None
    shard, key, anchor = value['shard'],value['key'],value['anchor']
    if (type(key) is not str or not _SHA.fullmatch(key) or type(shard) is not str or not _SHARD.fullmatch(shard)
            or type(anchor) is not dict or set(anchor) != {'source_identity','header'}):
        return None
    ids, header = anchor['source_identity'],anchor['header']
    if (type(ids) is list and len(ids)==2 and all(type(n) is int and 0<=n<2**64 for n in ids)
            and type(header) is str and _SHA.fullmatch(header)):
        return value
    return None


def _job(config, ref):
    from .native_media_work import VERSION, _connect, media_key
    from .native_scope_contract import TABLE
    c = _connect(config)
    if c is None:
        raise MirrorError('preview_job_deferred')
    with closing(c):
        row = c.execute('SELECT username,source,kind,status,attempts,due,lease,result,reason,version,recent_at,arrival '
                        'FROM jobs WHERE key=?',(ref['key'],)).fetchone()
    if not row or row[2:9] != ('image','pending',0,0.0,0.0,None,None) or row[9]!=config.get('media_transcriber_version',VERSION):
        raise MirrorError('preview_job_deferred')
    who, source, recent, arrival = row[0],json.loads(row[1]),row[10],json.loads(row[11])
    if (type(who) is not str or not who or type(source) is not dict or source.get('shard')!=ref['shard']
            or type(source.get('table')) is not str or not TABLE.fullmatch(source['table'])
            or media_key(source)!=ref['key'] or type(recent) not in (int,float) or not 0<=time.time()-recent<=MAX_AGE
            or type(arrival) is not dict or arrival.get('kind')!='tail_increment'):
        raise MirrorError('preview_job_deferred')
    return row,who,source


def _private_png(root, parts):
    from .native_mirror_media import _open_private
    with _open_private(root,parts,'preview.png') as stream:
        stamp = os.fstat(stream.fileno())
        if (not stat.S_ISREG(stamp.st_mode) or stamp.st_uid!=os.getuid() or stamp.st_nlink!=1
                or stat.S_IMODE(stamp.st_mode)!=0o600 or not 0<stamp.st_size<=PREVIEW_PNG_BYTES):
            raise MirrorError('preview_cache_invalid')
        return [stamp.st_dev,stamp.st_ino,stamp.st_size,stamp.st_mtime_ns,stamp.st_ctime_ns]


def local_preview(root, source):
    """Read only the independently published representation, never its decoder."""
    from .native_mirror_media import _read_private
    from .native_media_work import media_key
    parts = ('image-previews',media_key(source))
    try:
        receipt = json.loads(_read_private(root,parts,'state.json',8192))
        if receipt.get('source')!=source or _private_png(root,parts)!=receipt.get('png'):
            return None
        size, previews, expected = receipt['size'],receipt['resource_size_bytes'],receipt['expected_resource_sizes']
        if (type(size) is not list or len(size)!=2 or any(type(n) is not int or n<=0 for n in size)
                or size[0]*size[1]>MAX_PREVIEW_PIXELS
                or type(expected) is not list or not 2<=len(expected)<=8
                or any(type(n) is not int or n<=0 for n in expected) or sorted(set(expected))!=expected
                or previews!=expected[0] or previews>MAX_PREVIEW_INPUT_BYTES):
            return None
        rep=dict(status='decoded',path=str(root.joinpath(*parts,'preview.png')),size=size,
                 resource_size_bytes=previews,first_frame_only=False)
        return dict(status='partial',representations=[rep],expected_resource_sizes=expected,
                    missing_resource_sizes=[],pending_resource_sizes=expected[1:],early_preview=True)
    except (OSError,KeyError,TypeError,ValueError,MirrorError):
        return None


@contextmanager
def _staging_lock(parent):
    fd=os.open('.stage.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=parent)
    try:
        node=os.fstat(fd)
        if not stat.S_ISREG(node.st_mode) or node.st_uid!=os.getuid() or node.st_nlink!=1 or stat.S_IMODE(node.st_mode)!=0o600:
            raise MirrorError('preview_cache_invalid')
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise MirrorError('sync_busy') from None
        yield
    finally:
        os.close(fd)


def _publish(root, key, receipt, png, guard):
    """Stage one private directory and reveal PNG and receipt in a single rename."""
    from .native_scope_add import directory
    from .native_media_work import _json

    cache = root/'image-previews'
    cache.mkdir(mode=0o700,exist_ok=True)
    if cache.is_symlink() or stat.S_IMODE(cache.lstat().st_mode)!=0o700:
        raise MirrorError('preview_cache_invalid')
    staged='.stage'
    files=('preview.png','state.json')
    with directory(cache) as parent, _staging_lock(parent):
        try:
            os.mkdir(staged,0o700,dir_fd=parent)
        except FileExistsError:
            pass
        fd=os.open(staged,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        published=False
        owned_stage=False
        def remove_staged():
            for name in files:
                try:os.unlink(name,dir_fd=fd)
                except FileNotFoundError:pass
        def write(name,data):
            opened=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
            with os.fdopen(opened,'wb') as stream:
                os.fchmod(stream.fileno(),0o600)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
                return os.fstat(stream.fileno())
        try:
            node=os.fstat(fd)
            if node.st_uid!=os.getuid() or stat.S_IMODE(node.st_mode)!=0o700 or set(os.listdir(fd))-set(files):
                raise MirrorError('preview_cache_invalid')
            owned_stage=True
            remove_staged()
            photo=write('preview.png',png)
            receipt['png']=[photo.st_dev,photo.st_ino,photo.st_size,photo.st_mtime_ns,photo.st_ctime_ns]
            write('state.json',_json(receipt).encode())
            os.fsync(fd)
            with guard():
                try:os.stat(key,dir_fd=parent,follow_symlinks=False)
                except FileNotFoundError:pass
                else:raise MirrorError('preview_cache_invalid')
                live=os.stat(staged,dir_fd=parent,follow_symlinks=False)
                if (live.st_dev,live.st_ino)!=(node.st_dev,node.st_ino):
                    raise MirrorError('preview_cache_invalid')
                os.rename(staged,key,src_dir_fd=parent,dst_dir_fd=parent)
                published=True
            os.fsync(parent)
        finally:
            try:
                if owned_stage and not published and set(os.listdir(fd))<=set(files):
                    remove_staged()
                    os.rmdir(staged,dir_fd=parent)
            finally:
                os.close(fd)


def run(config, ref, opener, *, validate):
    """Early lane has one preview and leaves primary media, OCR and claims intact."""
    from .native_media_dispatch import _admission, resource_state
    from .native_media_work import PartialMediaScope
    from .native_mirror_media import MediaItemDeferred
    from .native_mirror_sync import mirror_root, writer_lock
    from .live_readonly import LiveReadonlyError

    result = dict(gaps=[],preview_reason='preview_deferred',preview_attempted=0,preview_published=0,
                  resource_opens=0,source_messages_queried=0)
    root = mirror_root(config,create=False)
    try:
        reason = _admission(config)
        if reason:
            return dict(result,preview_reason=reason)
        metrics = resource_state()
        result['media_resource_samples']=[metrics]
        if metrics['reason']:
            return dict(result,preview_reason=metrics['reason'])
        check_deadline()
        def scope_current(_shard):
            validate()
            return True
        scope = PartialMediaScope(config,{ref['shard']:ref['anchor']},scope_current)
        with writer_lock(root,0):
            validate()
            row, who, source = _job(config,ref)
            if local_preview(root,source) is not None:
                return dict(result,preview_reason='preview_already_published')
            item = scope.frozen(who,source)
        identity = ImageMessageIdentity(who,item['server_id'],item['local_id'],item['create_time'],
                                        item['local_type'],ZoneInfo(config.get('query_timezone','UTC')))
        path = Path(config['image_database'])
        source_root = Path(config.get('live_db_root',config['message_root'])).resolve()
        if path.is_symlink() or source_root not in path.resolve().parents:
            return dict(result,preview_reason='preview_source_deferred')

        def resource_identity():
            def stamp(name):
                node = name.lstat()
                if not stat.S_ISREG(node.st_mode):
                    raise MirrorError('preview_source_deferred')
                return node.st_dev,node.st_ino,node.st_size,node.st_mtime_ns,node.st_ctime_ns
            try:wal=stamp(path.with_name(path.name+'-wal'))
            except FileNotFoundError:wal=None
            return stamp(path),wal

        def current():
            with writer_lock(root,0):
                check_deadline()
                validate()
                if _job(config,ref)[0]!=row or scope.frozen(who,source)!=item:
                    raise MirrorError('preview_job_deferred')

        current()
        original_node = resource_identity()[0]
        result['preview_attempted']=1
        result['preview_started_at_ns']=time.time_ns()
        with closing(opener(path)) as db:
            result['resource_opens']=1
            before = resource_identity()
            if before[0]!=original_node:
                return dict(result,preview_reason='preview_source_deferred')
            version = db.execute('PRAGMA data_version').fetchone()
            db.execute('BEGIN')
            facts = _resource_facts(db,identity,preview_only=True)
            bound = _bound_file(db,identity,Path(config['image_attachments_root']),_facts=facts,preview_only=True)
            if not db.in_transaction or len(bound.files)!=1 or bound._hardlink_bytes[0] is None:
                return dict(result,preview_reason='preview_source_deferred')
            current()
            raw = bound._hardlink_bytes[0]
            codes, account = read_private_image_config(Path(config['image_key_config'])) if raw.startswith(_V2_MAGIC) and config.get('image_key_config') else ((), '')
            decoded = _decode_image_bytes(raw,output_root=root,key_codes=codes,account_scope=account,preview_only=True)
            if decoded['status']!='decoded':
                return dict(result,preview_reason='preview_decode_unavailable')
            png=decoded['png']
            check_deadline()
            if not 0<len(png)<=PREVIEW_PNG_BYTES or not db.in_transaction:
                return dict(result,preview_reason='preview_decode_unavailable')
            db.rollback()
            if db.execute('PRAGMA data_version').fetchone()!=version or resource_identity()!=before:
                return dict(result,preview_reason='preview_source_deferred')
            receipt = dict(source=source,size=decoded['size'],resource_size_bytes=bound.files[0][0],
                           expected_resource_sizes=list(bound.expected_sizes))

            @contextmanager
            def publish_guard():
                with writer_lock(root,0):
                    check_deadline()
                    validate()
                    if _job(config,ref)[0]!=row or scope.frozen(who,source)!=item or resource_identity()!=before:
                        raise MirrorError('preview_job_deferred')
                    yield

            _publish(root,ref['key'],receipt,png,publish_guard)
        return dict(result,preview_reason='preview_published',preview_published=1,preview_published_at_ns=time.time_ns())
    except ImageUnavailable:
        return dict(result,preview_reason='preview_representation_unavailable')
    except (MediaItemDeferred,MirrorError,OSError,ValueError,TypeError,KeyError,sqlite3.Error,LiveReadonlyError) as error:
        reason = str(error)
        safe = {'sync_busy','preview_job_deferred','preview_source_deferred','schedule_deadline_expired',
                'media_source_round_changed'}
        return dict(result,preview_reason=reason if reason in safe else 'preview_deferred')
