"""Repair one ready account image from its existing, bound local attachment."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from tempfile import TemporaryDirectory
from uuid import uuid4
from zoneinfo import ZoneInfo

from .image_runtime import (
    MAX_INPUT_BYTES, MAX_OUTPUT_BYTES, ImageMessageIdentity, ImageUnavailable,
    _V2_MAGIC, _decode_image_bytes, _explicit_decoder, read_private_image_config,
)
from .native_deadline import check_deadline
from .native_image_settings import decoder_path
from .native_media_work import VERSION, _connect, _json, image_decoder_binding, media_key
from .native_mirror_media import _image_key, _open_private, _write_private, frozen_message
from .native_mirror_store import MirrorError
from .native_mirror_sync import mirror_root, writer_lock
from .native_scope_add import directory, identity, need
from .native_scope_contract import SHARD, TABLE, _safe, member, mode, registry

_SHA = re.compile(r'[0-9a-f]{64}')
_IMAGES = ('media-images',)


def _job(db, key):
    row = db.execute('SELECT * FROM jobs WHERE key=?', (key,)).fetchone()
    need(row is not None, 'image_redecode_job_unavailable')
    return row


def _bound_job(config, root, key, row):
    _, username, raw, kind, status, _, _, _, result, _, version = row[:11]
    need(kind == 'image' and status == 'ready' and version == config.get('media_transcriber_version', VERSION),
         'image_redecode_job_unavailable')
    source = json.loads(raw)
    need(type(source) is dict and media_key(source) == key
         and source.get('account_id') == config['account_id']
         and source.get('source_generation') == config['source_generation']
         and 'table_generation' not in source and type(source.get('local_id')) is int and source['local_id'] > 0
         and type(source.get('shard')) is str and SHARD.fullmatch(source['shard'])
         and type(source.get('table')) is str and TABLE.fullmatch(source['table'])
         and type(source.get('content_sha256')) is str and _SHA.fullmatch(source['content_sha256']),
         'image_redecode_job_binding')
    with registry(config, snapshot=False) as index:
        proof = member(config, index, source['shard'], source['table'])
        need(type(username) is str and username and proof.get('username') == username
             and proof.get('supported') is True and proof.get('available') is True, 'image_redecode_job_binding')
        anchor = {k:proof[k] for k in ('source_identity','header')}
    item = frozen_message(config, root, {'source': source, 'media_username': username},
                          expected_anchor=anchor, local_only=True)
    reference = ImageMessageIdentity(username, item['server_id'], item['local_id'], item['create_time'],
                                     item['local_type'], ZoneInfo(config.get('query_timezone','UTC')))
    return source, reference, json.loads(result)


def _private_file(root, parts, name, limit, *, read=False, expected_size=None):
    with _open_private(root, parts, name) as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600
             and info.st_nlink == 1 and 0 < info.st_size <= limit
             and expected_size in (None, info.st_size), 'image_redecode_file_binding')
        facts = identity(info)
        if not read:
            return facts
        data = stream.read(limit+1)
        need(len(data) == info.st_size and identity(os.fstat(stream.fileno())) == facts, 'image_redecode_file_binding')
        return facts, data


def _saved_plan(config, root, parts, source, old, binding):
    stamp, raw = _private_file(root, parts, 'state.json', 65536, read=True)
    state = json.loads(raw)
    need(type(state) is dict and state.get('saved') is True and state.get('message') == source
         and state.get('account') == config['account_id'] and state.get('generation') == config['source_generation']
         and type(state.get('resource')) is str and _SHA.fullmatch(state['resource']), 'image_redecode_saved_binding')
    image = old['image']
    reps, saved = image['representations'], state['representations']
    need(image.get('status') == 'partial' and image.get('decoder_binding') != binding
         and type(reps) is list and type(saved) is list and 1 < len(reps) == len(saved) <= 8
         and type(state['expected']) is list and type(state['missing']) is list
         and state['expected'] == image.get('expected_resource_sizes')
         and state['missing'] == image.get('missing_resource_sizes'), 'image_redecode_saved_binding')
    sizes = []
    for rep, bound in zip(reps,saved):
        size = rep['resource_size_bytes']
        digest = bound['sha256']
        need(type(size) is int and 0 < size <= MAX_INPUT_BYTES and type(bound['size']) is int and bound['size'] == size
             and type(digest) is str and _SHA.fullmatch(digest), 'image_redecode_saved_binding')
        sizes.append(size)
    need(len(set(sizes)) == len(sizes) and sum(sizes) <= 2*MAX_INPUT_BYTES
         and sorted(sizes + state['missing']) == state['expected'], 'image_redecode_saved_binding')
    need(any(rep.get('status') == 'decoded' for rep in reps)
         and any(rep.get('status') == 'unavailable' and rep.get('reason') == 'image_decoder_unavailable' for rep in reps),
         'image_redecode_job_unavailable')
    return stamp, saved, image


def _preview_name(root, rep):
    path = Path(rep['path'])
    need(path == root.joinpath(*_IMAGES,path.name) and path.suffix == '.png', 'image_redecode_file_binding')
    return path.name


def redecode(config, key, *, validate_profile):
    """Use only cached bytes and publish only the current exact job result."""
    need(type(key) is str and _SHA.fullmatch(key) and mode(config) == 'account', 'image_redecode_job_reference')
    root = mirror_root(config, create=False)
    ffmpeg = decoder_path(config,root)
    if ffmpeg is None:
        raise MirrorError('image_decoder_config_invalid')
    binding = image_decoder_binding(config,ffmpeg=ffmpeg)
    try:
        tool = _explicit_decoder(str(ffmpeg))
    except ImageUnavailable as error:
        raise MirrorError(error.code) from error
    tool_stat = identity(tool.stat())
    store = root/'media-work.sqlite'
    with writer_lock(root, 0):
        validate_profile()
        need(store.is_file(), 'image_redecode_job_unavailable')
        store_id = _safe(store)
        db = _connect(config)
        need(db is not None, 'image_redecode_job_unavailable')
        with closing(db):
            need(_safe(store) == store_id, 'image_redecode_job_changed')
            row = _job(db,key)
        source, reference, old = _bound_job(config,root,key,row)
        parts = ('bounded-images',_image_key(reference,source))
        stamp, saved, image = _saved_plan(config, root, parts, source, old, binding)
    key_config = None
    output = root.joinpath(*_IMAGES)
    files = [(parts,'state.json',65536,stamp)]
    writes = {}
    reps = []
    keep_output = False
    try:
        with TemporaryDirectory(prefix='.image-redecode-',dir=root) as stage:
            for old_rep, bound in zip(image['representations'],saved):
                check_deadline()
                size, digest = bound['size'], bound['sha256']
                raw_stamp, raw = _private_file(root,parts,digest,MAX_INPUT_BYTES,read=True,expected_size=size)
                files.append((parts,digest,MAX_INPUT_BYTES,raw_stamp))
                need(hashlib.sha256(raw).hexdigest() == digest, 'image_redecode_saved_digest')
                if old_rep['status'] == 'decoded':
                    name = _preview_name(root,old_rep)
                    files.append((_IMAGES,name,MAX_OUTPUT_BYTES,_private_file(root,_IMAGES,name,MAX_OUTPUT_BYTES)))
                if old_rep['status'] != 'unavailable' or old_rep.get('reason') != 'image_decoder_unavailable':
                    reps.append(old_rep)
                    continue
                if raw.startswith(_V2_MAGIC) and key_config is None and config.get('image_key_config'):
                    key_config = read_private_image_config(Path(config['image_key_config']))
                codes, scope = key_config or ((), '')
                converted = _decode_image_bytes(raw, output_root=Path(stage), key_codes=codes, account_scope=scope, ffmpeg=tool)
                need(converted.get('status') == 'decoded', 'image_redecode_failed')
                with open(converted['path'],'rb') as stream:
                    png = stream.read(MAX_OUTPUT_BYTES+1)
                need(0 < len(png) <= MAX_OUTPUT_BYTES, 'image_redecode_failed')
                name = 'redecode-'+uuid4().hex+'.png'
                _write_private(root,_IMAGES,name,png)
                written = _private_file(root,_IMAGES,name,MAX_OUTPUT_BYTES)
                writes[name] = written
                files.append((_IMAGES,name,MAX_OUTPUT_BYTES,written))
                reps.append(dict(converted,path=str(output/name),resource_size_bytes=size))
        status = 'decoded' if all(rep['status']=='decoded' for rep in reps) and not image['missing_resource_sizes'] else 'partial'
        updated_image = dict(image,status=status,representations=reps,decoder_binding=binding)
        with writer_lock(root,0), closing(_connect(config,True,existing_only=True)) as db:
            db.execute('BEGIN IMMEDIATE')
            check_deadline()
            validate_profile()
            need(_safe(store) == store_id and _job(db,key) == row, 'image_redecode_job_changed')
            need(_bound_job(config,root,key,row)[:2] == (source,reference), 'image_redecode_job_changed')
            for location, name, limit, expected in files:
                need(_private_file(root,location,name,limit) == expected, 'image_redecode_file_changed')
            try:
                current_setting = decoder_path(config,root)
                current_tool = _explicit_decoder(str(current_setting)) if current_setting is not None else None
                same_tool = current_setting == ffmpeg and current_tool == tool and identity(current_tool.stat()) == tool_stat
            except ImageUnavailable:
                same_tool = False
            need(same_tool, 'image_decoder_config_invalid')
            need(db.execute('UPDATE jobs SET result=? WHERE key=? AND result=?',
                            (_json(dict(old,image=updated_image)),key,row[8])).rowcount == 1, 'image_redecode_job_changed')
            # The guarded commit checks scope on both sides of the actual
            # SQLite commit. A later guard error cannot undo a physical commit.
            try:
                db.commit()
            finally:
                keep_output = not db.in_transaction
    finally:
        if not keep_output and writes:
            with directory(output) as fd:
                for name, proof in writes.items():
                    try:
                        if identity(os.stat(name,dir_fd=fd,follow_symlinks=False)) == proof:
                            os.unlink(name,dir_fd=fd)
                    except FileNotFoundError:
                        pass
    return {'status':'redecoded','representations_repaired':len(writes),'source_opens':0,'gaps':[]}
