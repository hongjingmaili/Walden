"""Progress-gated small media batches inside the existing owned child deadline."""
import math
import os
import sqlite3
import subprocess
import time
from pathlib import Path

from .native_deadline import _current, check_deadline
from .native_media_segment import checkpoint
from .native_mirror_store import MirrorError
from .live_readonly import LiveReadonlyError

BATCH_ITEMS = 4
MAX_BATCHES = 8
MAX_ITEMS = 32
MAX_OWNED_RSS_KIB = 1536 * 1024


def resource_state():
    """Known owned group RSS and host load only; unreadable metrics cause yield."""
    from . import native_process as process
    try:
        cpus = os.cpu_count()
        load = os.getloadavg()[0]
        if type(cpus) is not int or cpus < 1 or not math.isfinite(load) or load < 0:
            return dict(reason='metrics_unavailable')
        me = process.identity(os.getpid())
        if not me or me['uid'] != os.getuid():
            return dict(reason='metrics_unavailable')
        group = process.group_members(me['pgid'], me['uid'])
        members = {v['pid']: v for v in group}
        if me['pid'] not in members:
            return dict(reason='metrics_unavailable')
        result = subprocess.run(['/bin/ps', '-p', ','.join(map(str, members)), '-o', 'pid=,rss='],
                                capture_output=True, text=True, timeout=1)
        rows = [line.split() for line in result.stdout.splitlines()]
        if result.returncode or any(len(row) != 2 for row in rows):
            return dict(reason='metrics_unavailable')
        readings = {int(pid): int(rss) for pid, rss in rows}
        if set(readings) != set(members) or any(rss < 0 for rss in readings.values()):
            return dict(reason='metrics_unavailable')
        if any(not process.same_generation(process.identity(pid), member) for pid, member in members.items()):
            return dict(reason='metrics_unavailable')
        rss = sum(readings.values())
        return dict(reason='resource_pressure' if rss >= MAX_OWNED_RSS_KIB or load >= cpus * 1.25 else None,
                    owned_rss_kib=rss, owned_processes=len(members), host_load_1m=load, host_cpus=cpus)
    except (OSError, ValueError, TypeError, KeyError, MirrorError, subprocess.SubprocessError):
        return dict(reason='metrics_unavailable')


def _admission(config):
    from .native_mirror_sync import writer_lock, mirror_root
    check_deadline()
    checkpoint('claim')
    deadline = _current.get()
    if deadline is not None and deadline.remaining() < 2:
        return 'deadline_near'
    try:
        with writer_lock(mirror_root(config, create=False), 0):
            pass
    except MirrorError as error:
        if str(error) != 'sync_busy':
            raise
        return 'writer_busy'
    return None


def _eligible(config, engine, source_scope=None):
    from .native_media_work import _connect, MAX_ATTEMPTS, IMAGE_PIPELINE_VERSION
    c = _connect(config)
    if c is None:
        return False
    try:
        tick = time.time()
        where, args = source_scope.job_filter('source') if source_scope is not None else ('', [])
        if c.execute("SELECT 1 FROM jobs WHERE status IN ('pending','failed') AND attempts<? AND due<=?" + where + " LIMIT 1",
                     (MAX_ATTEMPTS, tick, *args)).fetchone():
            return True
        if c.execute("SELECT 1 FROM image_derivations WHERE version=? AND engine=? AND status IN ('pending','failed') AND attempts<? AND due<=?" + where + " LIMIT 1",
                     (IMAGE_PIPELINE_VERSION, engine, MAX_ATTEMPTS, tick, *args)).fetchone():
            return True
        where, args = source_scope.job_filter('j.source') if source_scope is not None else ('', [])
        return c.execute("SELECT 1 FROM jobs j WHERE kind='image' AND status='ready' AND NOT EXISTS "
                         "(SELECT 1 FROM image_derivations d WHERE d.key=j.key AND d.version=? AND d.engine=? "
                         "AND (d.upstream=j.result OR d.status='running'))" + where + " LIMIT 1",
                         (IMAGE_PIPELINE_VERSION, engine, *args)).fetchone() is not None
    finally:
        c.close()


def run(config, opener, *, transcriber=None, decoder=None, recognizer=None, media_sources=None, media_validate=None):
    from .native_media_work import run_media, run_image_derivations, _sqlite_lock_error, PartialMediaScope
    start = time.monotonic()
    result = dict(media_completed=0, media_attempted=0, media_selected=0, image_ocr_completed=0,
                  image_ocr_attempted=0, image_ocr_stale=0, media_batches=0,
                  source_messages_queried=0, media_resource_samples=[],
                  image_ocr_maintenance=dict(verified=0,admission_checked=0,payload_read_attempts=0,payload_read_failures=0,payload_reads=0,payload_bytes=0),
                  image_ocr_execution=dict(payload_read_attempts=0,payload_read_failures=0,payload_reads=0,payload_bytes=0))
    source_error = [False]
    scope = None

    def source(path):
        check_deadline()
        if source_error[0]:
            raise MirrorError('media_source_unavailable')
        try:
            return opener(path)
        except (OSError, sqlite3.Error, LiveReadonlyError):
            source_error[0] = True
            raise MirrorError('media_source_unavailable') from None

    reason = 'batch_cap'
    for batch in range(MAX_BATCHES):
        reason = _admission(config)
        if reason:
            break
        metrics = resource_state()
        result['media_resource_samples'].append(metrics)
        check_deadline()
        reason = metrics['reason']
        if reason:
            break
        remaining = MAX_ITEMS - result['media_selected'] - result['image_ocr_attempted']
        if remaining <= 0:
            reason = 'item_cap'
            break
        try:
            if batch == 0 and media_sources is not None:
                scope = PartialMediaScope(config, media_sources, media_validate)
            scoped = {'source_scope':scope} if scope is not None else {}
            # Reserve one of four item opportunities for OCR; capture/ASR and OCR
            # share this child. Claims happen one at a time, not four in advance.
            media = run_media(config, source, transcriber=transcriber, decoder=decoder,
                              limit=min(3, remaining), yield_check=lambda: _admission(config),
                              backfill_page=batch == 0, systemic_source_errors=True, **scoped)
            result['media_backfill'] = media['media_backfill'] if batch == 0 else result['media_backfill']
            for key in ('media_completed', 'media_attempted', 'media_selected'):
                result[key] += media[key]
            result['media_batches'] += 1
            reason = media.get('media_yield') or _admission(config)
            if reason:
                break
            used = media['media_selected']
            ocr=dict(image_ocr_completed=0,image_ocr_attempted=0,image_ocr_stale=0)
            for opportunity in range(min(BATCH_ITEMS-used,remaining-used)):
                reason=_admission(config)
                if reason:break
                one=run_image_derivations(config,recognizer=recognizer,limit=1,maintenance_limit=int(opportunity==0),**scoped)
                for category in ('image_ocr_maintenance','image_ocr_execution'):
                    for key in result[category]:result[category][key]+=one[category][key]
                for key in ocr:
                    ocr[key]+=one[key];result[key]+=one[key]
                if not one['image_ocr_attempted']:break
            if reason:break
            if source_error[0]:
                raise MirrorError('media_source_unavailable')
        except sqlite3.OperationalError as error:
            if not _sqlite_lock_error(error):
                raise
            reason = 'media_store_busy'
            break
        if media['media_completed'] + ocr['image_ocr_completed'] <= 0:
            reason = 'no_progress'
            break
        if result['media_selected'] + result['image_ocr_attempted'] >= MAX_ITEMS:
            reason = 'item_cap'
            break
        engine = recognizer.identity if recognizer is not None else 'unconfigured'
        try:
            eligible = _eligible(config, engine, **scoped)
        except sqlite3.OperationalError as error:
            if not _sqlite_lock_error(error):
                raise
            reason = 'media_store_busy'
            break
        if not eligible:
            reason = 'eligible_empty'
            break
    else:
        reason='batch_cap'
    result.update(media_dispatch_reason=reason, media_elapsed_seconds=time.monotonic() - start,
                  media_item_cap=MAX_ITEMS, media_batch_item_cap=BATCH_ITEMS,media_maintenance_object_cap=2*MAX_BATCHES,media_total_object_opportunity_cap=MAX_ITEMS+2*MAX_BATCHES,
                  media_deadline='inherited_owned_child_deadline_not_reset')
    check_deadline()
    return result


from .failure_evidence import _register
_register(resource_state, _admission, _eligible, run)
