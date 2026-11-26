import copy
import json
import pytest
from wechat_local import failure_evidence as evidence,native_follow as follow


def test_terminal_diagnostic_roundtrips_original_exit_and_rejects_untrusted_values(monkeypatch):
    task=dict(schema_version=2,task_id='1'*32,kind='sync',status='started',stage='schedule',
              started_at='2026-11-18T00:00:00+00:00',content_redacted=True,missing_events=[],
              process=dict(pid=100,uid=1,operation_id='2'*32,operation_verified=True))
    token=evidence._current.set(task);writes=[]
    monkeypatch.setattr(evidence,'_persist',lambda task,event:writes.append(event))
    try:
        evidence.bounded_terminal(stop_reason='requested',remove_accepted=True,final_registration='owned',
            signal_received_before_cleanup=True,group_sigterm_sent=True,group_sigkill_sent=False,
            parent_deadline_expired=False,child_exit=-15,attempts=4)
        assert evidence._validate(task,'1'*32)['worker_terminal']['child_exit']==-15
        assert task['worker_terminal']['stop_reason']=='requested' and task['worker_terminal']['final_registration']=='owned'
        assert writes==['worker_terminal'] and 'exit_code' not in task
        invalid=copy.deepcopy(task);invalid['worker_terminal']['stop_reason']='private-sentinel'
        with pytest.raises(ValueError):evidence._validate(invalid,'1'*32)
        invalid=copy.deepcopy(task);invalid['worker_terminal']['remove_accepted']=1
        with pytest.raises(ValueError):evidence._validate(invalid,'1'*32)
        evidence.bounded_terminal(stop_reason='private-sentinel',remove_accepted='private-sentinel',final_registration=['private-sentinel'],
            signal_received_before_cleanup=False,group_sigterm_sent=False,group_sigkill_sent=False,
            parent_deadline_expired=False,child_exit='private-sentinel',attempts='private-sentinel')
        assert 'private-sentinel' not in json.dumps(task)
    finally:evidence._current.reset(token)


def test_listener_diagnostic_is_bounded_and_validates_only_fixed_metadata():
    runtime={};segment=dict(operation='3'*32)
    for attempt in range(20):
        follow._record_worker_observation(runtime,segment,dict(observation_diagnostic=dict(
            reason='runtime_ordinary_change',stage='final',attempt=attempt,retries=1,recovered=True,
            status_before='running',status_after='running',runtime_file_replaced=True)))
    values=follow.worker_observations(runtime)
    assert len(values)==8 and values[0]['attempt']==12 and values[-1]['attempt']==19
    invalid=copy.deepcopy(runtime);invalid['worker_observations'][0]['reason']=['private-sentinel']
    assert follow.worker_observations(invalid)==[]
    invalid=copy.deepcopy(runtime);invalid['worker_observations'][0]['arbitrary']='private-sentinel'
    assert follow.worker_observations(invalid)==[]
    follow._record_worker_observation(runtime,segment,dict(observation_diagnostic=dict(reason='private-sentinel')),stop_context='worker_unknown')
    assert 'private-sentinel' not in json.dumps(follow.worker_observations(runtime))
