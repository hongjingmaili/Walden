"""Project only existing, exactly bound local OCR into selected query images."""
import hashlib
import json
import sqlite3
from . import native_media_work as media
from .native_mirror_store import MirrorError


def engine_identity(root):
    # Constructor computes identity only; never prepare, compile or recognize.
    from .local_image_runtime import LocalVisionRecognizer
    return LocalVisionRecognizer(root/'image-ocr-runtime').identity


def _result(status, reason, text=None, **facts):
    return dict(ocr=dict(status=status,text=text,reason=reason,**facts),
                description=dict(status='unconfigured',text=None,reason='description_model_unconfigured'))


def local_ocr(config, source, username, image, *, engine):
    """No schema/queue writes, Source, codecs, OCR or subprocesses; one selected image."""
    from .native_scope_contract import authorized
    authorized(config,username,shard=source['shard'],table=source['table'])
    if (source.get('account_id')!=config['account_id']
        or source.get('source_generation')!=config['source_generation']
        or source.get('table')!='Msg_'+hashlib.md5(username.encode()).hexdigest()):
        raise MirrorError('media_scope')
    c=None
    try:
        c=media._connect(config)
        if c is None:return _result('missing','ocr_cache_missing')
        c.execute('BEGIN')
        if not c.execute("SELECT 1 FROM sqlite_master WHERE name='image_derivations'").fetchone():
            return _result('missing','ocr_cache_missing')
        sql=('SELECT j.username,j.source,j.kind,j.status,j.version,j.result,'
             'd.source,d.status,d.result,d.upstream,d.representation '
             'FROM jobs j JOIN image_derivations d ON d.key=j.key '
             'WHERE j.key=? AND d.version=? AND d.engine=?')
        parameters=(media.media_key(source),media.IMAGE_PIPELINE_VERSION,engine)
        row=c.execute(sql,parameters).fetchone()
        if row is None:return _result('missing','ocr_cache_missing')
        user,job_source,kind,job_status,version,upstream,derived_source,state,raw,derived_upstream,representation=row
        if (user!=username or job_source!=media._json(source) or derived_source!=media._json(source)
            or kind!='image' or version!=config.get('media_transcriber_version',media.VERSION)):
            return _result('pending','ocr_binding_changed')
        if job_status!='ready' or upstream!=derived_upstream:
            return _result('pending','ocr_upstream_changed')
        if state in ('pending','running','invalidated','superseded'):
            return _result('pending','ocr_pending' if state in ('pending','running') else 'ocr_binding_changed')
        if state in ('failed','rejected','unconfigured'):
            return _result('unconfigured' if state=='unconfigured' else 'failed','ocr_'+state)
        if state!='ready':return _result('unknown','ocr_state_unknown')
        value=json.loads(raw);rep=json.loads(representation)
        if (media._json(value.get('source'))!=media._json(source) or value.get('pipeline_version')!=media.IMAGE_PIPELINE_VERSION
            or value.get('engine_identity')!=engine or value.get('representation')!=rep):
            return _result('pending','ocr_binding_changed')
        base={k:v for k,v in rep.items() if k!='decoded_sha256'}
        if base not in image.get('representations',[]) or base.get('status')!='decoded':
            return _result('pending','ocr_representation_changed')
        # Require the selected representation in both the current query image and
        # its exact immutable job upstream; never chase a result-provided path.
        if base not in json.loads(upstream).get('image',{}).get('representations',[]):
            return _result('pending','ocr_representation_changed')
        try:
            _,digest=media._image_payload(config,rep)
        except (OSError,ValueError,KeyError,TypeError,MirrorError):
            return _result('pending','ocr_payload_unavailable')
        # End the snapshot and recheck current rows after filesystem I/O. A worker
        # commit while PNG was being read must not expose the prior ready text.
        c.rollback()
        if c.execute(sql,parameters).fetchone()!=row:
            return _result('pending','ocr_upstream_changed')
        if digest!=rep.get('decoded_sha256') or digest!=value.get('decoded_sha256'):
            return _result('pending','ocr_decoded_payload_changed')
        ocr=value.get('ocr',{})
        text=ocr.get('text')
        if (type(text) is not str or ocr.get('status')!=('ready' if text else 'empty')):
            return _result('failed','ocr_result_invalid')
        return _result('ready' if text else 'empty',None,text,
                       pipeline_version=media.IMAGE_PIPELINE_VERSION,engine_identity=engine,decoded_sha256=digest)
    except (sqlite3.Error,OSError):
        return _result('unknown','ocr_store_unavailable')
    except (ValueError,TypeError,KeyError,AttributeError):
        return _result('failed','ocr_cache_invalid')
    finally:
        if c is not None:c.close()
