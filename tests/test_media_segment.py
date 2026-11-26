"""Direct clock/protocol checks plus SQLite cleanup at interrupted media stages."""
from copy import deepcopy
from contextlib import closing
import json
import subprocess
from types import SimpleNamespace

import pytest
from test_media_priority import queue
from wechat_local import image_runtime, native_media_dispatch as dispatch
from wechat_local import native_media_segment as segment, native_media_work as work
from wechat_local import native_mirror_media as mirror_media
from wechat_local.native_mirror_store import MirrorError

SECOND = 10**9
START = 100 * SECOND
WALL_START = 1_700_000_000 * SECOND
PARENT = dict(continuous_start=START, continuous_until=START+180*SECOND,
              wall_until=(WALL_START+180*SECOND)/SECOND)


def clocks(monkeypatch, seconds_left):
    now = PARENT['continuous_until']-int(seconds_left*SECOND)
    wall = WALL_START+now-START
    monkeypatch.setattr(segment, 'continuous_ns', lambda:now)
    monkeypatch.setattr(segment, 'time', SimpleNamespace(time_ns=lambda:wall))
    return wall,now


def plan():
    return dict(operation='worker-test', grant_sha256='b'*64, token='c'*32,
                attempt=1, started_wall_ns=WALL_START+100*SECOND,
                child_deadline=dict(PARENT,continuous_start=START+100*SECOND))


def valid_yield(monkeypatch):
    grant = plan()
    now = clocks(monkeypatch, 47)
    with segment.activate(grant), pytest.raises(segment.SegmentYield) as caught:
        segment.checkpoint('voice_asr')
    result = segment.receipt(grant, 47, caught.value)
    return grant, result, now


def test_authentic_stage_proof_and_exact_budget_type(monkeypatch):
    facts, receipt, (wall,tick) = valid_yield(monkeypatch)
    root = dict(operation=facts['operation'], follow_grant_sha256=facts['grant_sha256'], deadline=PARENT)
    assert segment.bind(facts, facts['token'], root, {'media_attempts':1}, facts['child_deadline']) == facts
    verified = segment.verified(facts, 47, segment.YIELD_EXIT, json.dumps(receipt),wall=wall,tick=tick)
    assert verified['stage']=='voice_asr' and verified['checkpoint_continuous_ns']==tick
    for wrong in (dict(root,follow_grant_sha256='f'*64), dict(root,deadline=dict(PARENT,wall_until=PARENT['wall_until']+30))):
        with pytest.raises(MirrorError,match='media_segment_binding'):
            segment.bind(facts,facts['token'],wrong,{'media_attempts':1},facts['child_deadline'])
    assert not segment.segment_limited(PARENT,dict(facts['child_deadline'],wall_until=PARENT['wall_until']-5))
    assert not segment.segment_limited(PARENT,dict(facts['child_deadline'],continuous_until=PARENT['continuous_until']-5))


def test_rejects_forged_unknown_or_incomplete_segments(monkeypatch):
    facts, receipt, (wall,tick) = valid_yield(monkeypatch)
    checks = [('child_pid',True),('child_pid',48),('stage','stage_unknown'),
              ('stage','claim'),('released_continuous_ns',tick+1),('checkpoint_wall_ns',wall-120*SECOND),
              ('plan',dict(facts,operation='other')),('plan',dict(facts,grant_sha256='f'*64)),
              ('plan',dict(facts,token='d'*32)), ('plan',dict(facts,attempt=True))]
    for field,value in checks:
        fake = deepcopy(receipt)
        fake['media_segment_yield'][field] = value
        assert segment.verified(facts,47,segment.YIELD_EXIT,json.dumps(fake),wall=wall,tick=tick) is None
    for code,data in ((0,json.dumps(receipt)),(-14,json.dumps(receipt)),(76,b''),(76,b'{}'),(76,b'!oversize!')):
        assert segment.verified(facts,47,code,data,wall=wall,tick=tick) is None


def test_asr_has_a_forward_service_window_and_a_hard_end(monkeypatch):
    facts = plan()
    with segment.activate(facts):
        clocks(monkeypatch, 50)
        segment.checkpoint('voice_asr')
        clocks(monkeypatch, .1)
        with pytest.raises(segment.SegmentYield):
            segment.checkpoint('voice_asr')
        clocks(monkeypatch, 0)
        with pytest.raises(MirrorError,match='schedule_deadline_expired'):
            segment.checkpoint('voice_asr')
    with segment.activate(None):
        segment.checkpoint('voice_asr')
        assert segment.ordinary_owned() and not segment.active()


def test_true_ffmpeg_failure_remains_an_image_error(monkeypatch):
    clocks(monkeypatch, 50)
    def reject(*args,**kwargs):
        raise subprocess.TimeoutExpired('synthetic-decoder',25)
    monkeypatch.setattr(image_runtime.subprocess,'run',reject)
    with segment.activate(plan()), pytest.raises(image_runtime.ImageUnavailable) as caught:
        image_runtime._hevc_first_frame(b'wxgf\x00\x00\x00\x01\x40payload','/synthetic-decoder')
    assert caught.value.code=='image_decode_unavailable'


def test_full_scope_true_source_failure_uses_existing_claim_cleanup(queue, monkeypatch):
    config,add,_,_=queue
    add(1)
    clocks(monkeypatch, 50)
    monkeypatch.setattr(dispatch,'resource_state',lambda:dict(reason=None))
    def source_fails(config,root,window,opener,**kwargs):
        return opener(config['image_database'])
    def unavailable(_):
        raise PermissionError('synthetic opener refusal')
    monkeypatch.setattr(mirror_media,'capture_window_images',source_fails)
    with segment.activate(plan()), pytest.raises(MirrorError,match='media_source_unavailable'):
        dispatch.run(config,unavailable)
    with closing(work._connect(config)) as c:
        assert c.execute('SELECT status,attempts,lease FROM jobs').fetchone()==('pending',0,0)


def test_full_ocr_yield_restores_claim_and_derivation_resumes_once(queue,monkeypatch):
    config,add,run,_=queue
    add(1)
    assert run()['media_completed']==1
    class Recognizer:
        identity = 'synthetic-ocr-segment-test'
        def recognize_png(self, payload, timeout):
            assert payload.startswith(b'\x89PNG')
            segment.checkpoint('ocr_inference')
            return dict(text='resolved synthetic',confidence=1)
    recognizer=Recognizer()
    with closing(work._connect(config)) as c:
        job = c.execute('SELECT result FROM jobs').fetchone()
    clocks(monkeypatch, 30)
    with segment.activate(plan()), pytest.raises(segment.SegmentYield) as caught:
        work.run_image_derivations(config,recognizer=recognizer,limit=1)
    assert caught.value.args[0]=='ocr_inference'
    with closing(work._connect(config)) as c:
        assert c.execute('SELECT status,attempts,lease,claim FROM image_derivations').fetchone()==('pending',0,0,'')
        assert c.execute('SELECT result FROM jobs').fetchone()==job
    assert work.run_image_derivations(config,recognizer=recognizer,limit=1)['image_ocr_completed']==1
    assert work.run_image_derivations(config,recognizer=recognizer,limit=1)['image_ocr_attempted']==0
    with closing(work._connect(config)) as c:
        assert c.execute('SELECT status,attempts,lease,claim FROM image_derivations').fetchall()==[('ready',1,0,'')]
        assert c.execute('SELECT COUNT(*) FROM image_ocr_cache').fetchone()==(1,)
