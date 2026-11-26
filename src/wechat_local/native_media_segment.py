"""Cooperative yield for an ordinary child whose hard limit is the active segment."""
from contextlib import contextmanager
from contextvars import ContextVar
import json
import re
import time

from .native_deadline import continuous_ns
from .native_mirror_store import MirrorError

YIELD_EXIT = 76
CLEANUP_SECONDS = 8
# Reserve cleanup plus stage headroom. ASR's own timeout exceeds both kinds
# of child budget; allow it when there is headroom and keep the hard alarm.
STAGE_SECONDS = {
    'claim': 4, 'capture': 3, 'image_decode': 3, 'image_ffmpeg': 25,
    'voice_decode': 30, 'voice_asr': 40, 'ocr_build': 60, 'ocr_inference': 30,
}
_active = ContextVar('walden_media_segment', default=None)


class SegmentYield(BaseException):
    """Used at an explicit safe checkpoint, after hard-deadline checks."""


class YieldResult(dict):
    """Only the installed owned-media action can produce the reserved exit."""


def segment_limited(parent, child):
    return (type(child) is dict
            and child.get('wall_until') == parent['wall_until']
            and child.get('continuous_until') == parent['continuous_until']
            and type(child.get('continuous_start')) is int
            and parent['continuous_start'] <= child['continuous_start']
            and 0 < child['continuous_until']-child['continuous_start'] <= 120_000_000_000)


def bind(plan, token, record, runtime, child):
    if (type(plan) is not dict or type(token) is not str or re.fullmatch('[0-9a-f]{32}', token) is None
            or plan.get('token') != token or plan.get('operation') != record['operation']
            or plan.get('grant_sha256') != record['follow_grant_sha256']
            or type(plan.get('attempt')) is not int or plan['attempt'] <= 0
            or type(runtime.get('media_attempts')) is not int
            or plan['attempt'] != runtime['media_attempts'] or plan.get('child_deadline') != child
            or type(plan.get('started_wall_ns')) is not int
            or not segment_limited(record['deadline'], child)):
        raise MirrorError('media_segment_binding')
    return plan


def _at_checkpoint(plan, stage, wall, tick):
    child = plan['child_deadline']
    if type(stage) is not str or stage not in STAGE_SECONDS or type(wall) is not int or type(tick) is not int:
        return False
    wall_left = child['wall_until']-wall/1e9
    tick_left = (child['continuous_until']-tick)/1e9
    return (wall >= plan['started_wall_ns'] and tick >= child['continuous_start']
            and 0 < min(wall_left, tick_left) < CLEANUP_SECONDS+STAGE_SECONDS[stage])


@contextmanager
def activate(plan):
    token = _active.set((plan,))
    try:
        yield
    finally:
        _active.reset(token)


def active():
    value = _active.get()
    return value is not None and value[0] is not None


def ordinary_owned():
    return _active.get() is not None


def checkpoint(stage):
    value = _active.get()
    if value is None or value[0] is None:
        return
    plan = value[0]
    wall, tick = time.time_ns(), continuous_ns()
    child = plan['child_deadline']
    if wall/1e9 >= child['wall_until'] or not child['continuous_start'] <= tick < child['continuous_until']:
        raise MirrorError('schedule_deadline_expired')
    if _at_checkpoint(plan, stage, wall, tick):
        raise SegmentYield(stage, wall, tick)


def receipt(plan, pid, yielded):
    stage, wall, tick = yielded.args
    return YieldResult(gaps=[], media_dispatch_reason='segment_end_yield', media_segment_yield=dict(
        plan=plan, child_pid=pid, stage=stage, checkpoint_wall_ns=wall, checkpoint_continuous_ns=tick,
        released_wall_ns=time.time_ns(), released_continuous_ns=continuous_ns()))


def verified(plan, pid, code, output, *, wall, tick):
    if code != YIELD_EXIT or not plan:
        return None
    try:
        data = json.loads(output)
        if (type(data) is not dict or set(data) != {'gaps','media_dispatch_reason','media_segment_yield'}
                or data['gaps'] != [] or data['media_dispatch_reason'] != 'segment_end_yield'):
            return None
        proof = data['media_segment_yield']
        if (type(proof) is not dict or set(proof) != {
                'plan','child_pid','stage','checkpoint_wall_ns','checkpoint_continuous_ns',
                'released_wall_ns','released_continuous_ns'}
                or json.dumps(proof['plan'],sort_keys=True) != json.dumps(plan,sort_keys=True)
                or type(proof['child_pid']) is not int or proof['child_pid'] != pid
                or not _at_checkpoint(plan, proof['stage'], proof['checkpoint_wall_ns'],
                                      proof['checkpoint_continuous_ns'])):
            return None
        w, t = proof['released_wall_ns'], proof['released_continuous_ns']
        child = plan['child_deadline']
        if (type(w) is not int or type(t) is not int
                or not proof['checkpoint_wall_ns'] <= w <= wall
                or not proof['checkpoint_continuous_ns'] <= t <= tick
                or w/1e9 >= child['wall_until'] or t >= child['continuous_until']):
            return None
        return {name: value for name,value in proof.items() if name != 'plan'}
    except (ValueError, TypeError, KeyError):
        return None
