import json,os
from pathlib import Path
from types import SimpleNamespace
import pytest
from wechat_local import failure_evidence as evidence,native_follow as follow,native_schedule as schedule
from wechat_local.native_mirror_store import MirrorError


def test_existing_task_id_is_reused_without_minting_authority(tmp_path,monkeypatch):
    monkeypatch.setenv('XDG_STATE_HOME',str(tmp_path));task=evidence.begin('sync');token=evidence._current.set(task)
    try:assert evidence.current_task_id()==task['task_id']
    finally:evidence._current.reset(token)
    assert evidence.current_task_id() is None


@pytest.mark.parametrize('attempted,returned,outcome,expected',[
    (False,False,'in_progress','unknown'),(False,False,'failed','not_attempted_by_this_call'),
    (True,False,'failed','attempted_unknown'),(True,True,'failed','api_returned')])
def test_disposition_is_call_local_and_does_not_include_exception_text(attempted,returned,outcome,expected):
    value=follow._preparation_fact(dict(phase='os_submit',submit_attempted=attempted,submit_returned=returned),outcome,error=OSError('private parameter/body/path'))
    assert value['submit_disposition']==expected
    assert len(json.dumps(value).encode())<512 and 'private' not in json.dumps(value)
    assert follow.preparation_diagnostic(dict(worker_preparation=value))==value


def test_old_or_invalid_optional_diagnostic_is_not_authority():
    assert follow.preparation_diagnostic({}) is None
    assert follow.preparation_diagnostic(dict(worker_preparation={'phase':[]})) is None
    value=follow._preparation_fact({},'failed');assert value['submit_disposition']=='unknown'


@pytest.mark.parametrize('fault,phase,attempted,returned',[
    ('read','preflight_os_read',False,False),('prepared','prepared_callback',False,False),
    ('submit','os_submit',True,False),('after','post_submit_guard',True,True)])
def test_real_configure_boundaries_preserve_primary_and_receipts(tmp_path,fault,phase,attempted,returned):
    config=dict(account_id='synthetic',source_generation='synthetic');profile=tmp_path/'profile.json';profile.write_text(json.dumps(config));profile.chmod(0o600)
    exe=tmp_path/'sync';exe.write_text('synthetic executable metadata');exe.chmod(0o700)
    context=dict(domain='kSMDomainUserLaunchd',uid=os.getuid(),security_session=1)
    class Run:
        def __init__(self):self.context=context;self.job=None;self.calls=0
        def observe(self,target):
            if fault=='read' or fault=='after' and self.job is not None:raise OSError('synthetic external read unavailable')
            return dict(target=target,state='present',argv=self.job['ProgramArguments'],operation=schedule._argv_operation(self.job['ProgramArguments']))if self.job else dict(target=target,state='absent')
        def submit(self,payload):
            self.calls+=1
            if fault=='submit':raise OSError('synthetic submit response unavailable')
            self.job=payload
        def pid(self,target):return None
    run=Run();trace={}
    def prepared(_):
        if fault=='prepared':raise PermissionError('synthetic control publication failure')
    expected=PermissionError if fault=='prepared' else MirrorError
    with pytest.raises(expected):schedule.configure(config,profile,exe,tmp_path/'services',True,runner=run,prepared=prepared,_prepare_trace=trace)
    assert trace==dict(phase=phase,submit_attempted=attempted,submit_returned=returned)
    assert run.calls==int(attempted)
    if fault=='prepared':
        receipts=list((tmp_path/'services').glob('*.submission'));assert len(receipts)==1
        assert json.loads(receipts[0].read_text())['status']=='not_submitted'
