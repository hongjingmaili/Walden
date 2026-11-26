import time
from pathlib import Path

import pytest

from wechat_local import native_follow
from wechat_local import native_follow_schedule as schedule
from wechat_local import native_background


def test_follow_is_started_once_at_login_and_never_launchd_restarted():
    policy = dict(label='org.walden.synthetic', executable='/synthetic/bin/wechat-local-sync',
                  snapshot='/synthetic/config.json', environment={}, generation='a'*32)
    payload = native_follow._payload(policy, '/synthetic/policy.json')
    assert payload['RunAtLoad'] is True
    assert payload['KeepAlive'] is False
    assert payload['ThrottleInterval'] >= 30
    assert not {'StartInterval','StartCalendarInterval'} & payload.keys()


def test_vnode_names_are_captured_before_refresh_and_unknown_events_fall_back(tmp_path):
    from types import SimpleNamespace
    from wechat_local.native_follow_events import VnodeHints
    for name in ('message_7.db','message_7.db-wal','message_7.db-shm','contact.db'):
        (tmp_path/name).touch()
    class Queue:
        batches=[]
        closed=False

        def control(self, changes, _limit, _timeout):
            if changes is not None:
                return []
            return self.batches.pop(0) if self.batches else []

        def close(self):
            self.closed=True
    queue=Queue()
    backend=SimpleNamespace(kqueue=lambda:queue,kevent=lambda ident,**kw:SimpleNamespace(ident=ident,**kw),
        KQ_FILTER_VNODE=1,KQ_EV_ADD=2,KQ_EV_ENABLE=4,KQ_EV_CLEAR=8,KQ_NOTE_WRITE=16,
        KQ_NOTE_DELETE=32,KQ_NOTE_RENAME=64,KQ_NOTE_ATTRIB=128,KQ_NOTE_EXTEND=256,KQ_NOTE_REVOKE=512,
        KQ_EV_ERROR=1024)
    with_hint=VnodeHints(tmp_path,backend=backend,clock=lambda:0)
    try:
        def event(name):
            fd=next(fd for fd,(path,_) in with_hint.fds.items() if path.name==name)
            return SimpleNamespace(ident=fd,fflags=16,flags=0)
        queue.batches=[[event('message_7.db-wal')],[event('message_7.db-shm')]]
        assert with_hint.wait(0)==2
        assert with_hint.shard_generations=={'message_7.db':2}
        assert with_hint.fallback_generation==0
        queue.batches=[[event('contact.db')],[]]
        with_hint.wait(0)
        assert with_hint.fallback_generation==3
        assert with_hint.shard_generations=={'message_7.db':2}
        queue.batches=[[event('message_7.db')]*256,[]]
        with_hint.wait(0)
        assert with_hint.fallback_generation==4
        assert with_hint.shard_generations=={'message_7.db':4}
    finally:
        with_hint.close()
    assert queue.closed and with_hint.fds=={}


def test_only_known_configuration_and_contract_failures_are_permanent():
    for reason in ('scope_registry_binding','source_identity_mismatch','invalid_source_configuration'):
        detail = schedule.failure_details([reason])
        assert detail == {'failure_class':'permanent','failure_reason':reason}
    for reason in ('source_unavailable','sync_busy','local_registry_read_busy',
                   'local_image_not_ready','whisper_unavailable','some arbitrary string'):
        assert schedule.failure_details([reason]) == {'failure_class':'retryable'}


def test_completed_attempt_retains_only_known_owned_child_failure_reason():
    runtime = dict(operation='job', attempts=1)
    native_background._completed_attempt(
        runtime, 2, b'{"failure_class":"permanent","failure_reason":"scope_registry_binding"}')
    assert runtime['last_completed']['failure_class']=='permanent'
    assert runtime['last_completed']['failure_reason']=='scope_registry_binding'
    native_background._completed_attempt(
        runtime, 2, b'{"failure_class":"permanent","failure_reason":"/untrusted/path"}')
    assert runtime['last_completed']['failure_class']=='retryable'
    assert 'failure_reason' not in runtime['last_completed']


def test_active_media_failure_has_separate_cadence_that_survives_next_worker(monkeypatch):
    monkeypatch.setattr(native_background, 'continuous_ns', lambda: 10 * 10**9)
    base = schedule.plan(None, wall=10, continuous=10 * 10**9, interval=30)
    runtime = dict(operation='first', media_attempts=1)
    result = native_background._update_media_cadence(
        base, runtime, 2, b'{"failure_reason":"media_store_binding"}')
    assert result['media']['mode'] == 'blocked'
    assert result['media']['failure_reason'] == 'media_store_binding'
    assert result['due']

    next_runtime = schedule.plan(result, wall=1000, continuous=1000*10**9, interval=30)
    assert next_runtime['due']
    assert not schedule.plan(next_runtime['media'], wall=1000, continuous=1000*10**9, interval=30)['due']


def test_owned_child_pipe_closes_and_only_unreaped_handles_get_killed():
    import subprocess
    import sys

    normal = subprocess.Popen([sys.executable, '-I', '-c', 'print("finished")'],
                              stdout=subprocess.PIPE)
    with normal:
        normal.wait(timeout=3)
        output = bytearray()
        assert native_background._reap_child(normal, output) == 0
        assert normal.stdout.closed and output == b'finished\n'
    with subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(30)']) as late:
        native_background._kill_and_reap_children((normal, late))
        assert normal.returncode == 0
        assert late.returncode == -9


def test_failure_retention_limits_terminal_records_and_keeps_active_evidence(tmp_path, monkeypatch):
    import json
    import os
    import time

    from wechat_local import failure_evidence

    monkeypatch.setenv('XDG_STATE_HOME', str(tmp_path))
    directory = tmp_path/'walden'/'failures'
    directory.parent.mkdir(mode=0o700)
    directory.mkdir(mode=0o700)
    now = time.time_ns()
    for index in range(204):
        ident = f'{index:032x}'
        path = directory/(ident+'.json')
        status = {201:'started',202:'pending'}.get(index,'failed')
        path.write_text(json.dumps(dict(schema_version=2, content_redacted=True,
                                        task_id=ident, status=status)))
        path.chmod(0o600)
        stamp = now - index*10**9 if index < 203 else now - 8*24*3600*10**9
        os.utime(path,ns=(stamp,stamp))
    assert failure_evidence.prune_terminal(now_ns=now) == 2
    assert len(list(directory.glob('0*.json'))) == 202
    assert (directory/(f'{201:032x}'+'.json')).exists()
    assert (directory/(f'{202:032x}'+'.json')).exists()
    assert json.loads((directory/'retention-last.json').read_text())['task_id'] == f'{203:032x}'


def test_failure_boundary_limits_a_terminal_burst_between_periodic_scans(tmp_path, monkeypatch):
    import json
    import os
    import time

    from wechat_local import failure_evidence

    monkeypatch.setenv('XDG_STATE_HOME', str(tmp_path))

    @failure_evidence.boundary('sync')
    def fail():
        return 2

    directory = tmp_path/'walden'/'failures'
    directory.parent.mkdir(mode=0o700)
    directory.mkdir(mode=0o700)
    old = directory/('0'*32+'.json')
    old.write_text(json.dumps(dict(schema_version=2,content_redacted=True,status='started',task_id=old.stem)))
    old.chmod(0o600)
    stamp = time.time_ns()-8*24*3600*10**9
    os.utime(old,ns=(stamp,stamp))
    decoded_old = []
    loads = json.loads

    def watch_legacy(raw, *args, **kwargs):
        result = loads(raw,*args,**kwargs)
        if type(result) is dict and result.get('task_id') == old.stem:
            decoded_old.append(result['task_id'])
        return result

    monkeypatch.setattr(failure_evidence.json,'loads',watch_legacy)
    assert fail()==2
    marker = directory/'retention-scan'
    first_scan = loads(marker.read_bytes())['checked_at_ns']
    for _ in range(204):
        assert fail()==2
    remaining = list(directory.glob('[0-9a-f]'*32+'.json'))
    assert len(remaining)==201 and old in remaining
    scan = loads(marker.read_bytes())
    assert scan['checked_at_ns']==first_scan
    assert scan['retired']==1 and len(scan['kept'])==200
    assert {path.name for path in remaining if path!=old}==set(scan['kept'])
    assert decoded_old==[old.stem]
    assert (directory/'retention-last.json').is_file()


def test_launchagent_retention_keeps_three_exact_profile_backups(tmp_path):
    import plistlib

    from wechat_local.native_follow_policy import Store
    from wechat_local.native_schedule import _create

    store = Store(tmp_path/'follow',create=True)
    agent = tmp_path/'org.walden.synthetic.plist'
    policy = dict(label=agent.stem,executable='/synthetic/bin/sync',snapshot='/synthetic/source.json',
                  environment={},generation='b'*32,agent_path=str(agent))
    path = store.immutable('policy.'+'b'*32+'.json',policy)
    data = plistlib.dumps(native_follow._payload(policy,path))
    for number in range(5):
        _create(agent.with_name(agent.name+f'.disabled-{number}'),data)
    outsider = tmp_path/'somebody-else.plist.disabled-1'
    _create(outsider,data)
    assert native_follow._prune_disabled_agents(store,agent)==2
    assert sorted(item.name for item in tmp_path.glob(agent.name+'.disabled-*')) == [
        agent.name+f'.disabled-{n}' for n in (2,3,4)]
    assert outsider.exists() and store.read('listener-retirement.json')['preserved']==3


def test_worker_retention_requires_detachment_and_resumes_a_partial_removal(tmp_path, monkeypatch):
    import base64
    import hashlib
    import json

    import pytest
    from wechat_local.native_follow_policy import Store
    from wechat_local.native_mirror_store import MirrorError
    from wechat_local.native_schedule import _create, _read

    store = Store(tmp_path/'follow',create=True)
    generation, listener, grant, operation = ('a'*32,'b'*32,'c'*32,'d'*32)
    services = store.path('workers.'+listener)
    services.mkdir(mode=0o700)
    locator = store.immutable('grant.'+grant+'.json',dict(
        kind='active', instance_nonce=listener, policy_generation=generation,
        nonce=grant,store_root=str(store.root)))
    grant_hash = hashlib.sha256(locator.read_bytes()).hexdigest()
    record = services/'worker.owned'
    segment = dict(record=str(record),operation=operation,descriptor=dict(path=str(locator),sha256=grant_hash))
    plist = services/'worker.plist.disabled-11'
    _create(plist,b'exact archived plist')
    before_plist = _read(plist)
    owned = services/'worker.owned.disabled-11'
    _create(owned,json.dumps(dict(operation=operation,follow_grant=str(locator),
                       follow_grant_sha256=grant_hash,plist_identity=before_plist[1],
                       plist_sha256=hashlib.sha256(before_plist[0]).hexdigest())).encode())
    unknown = services/'unrelated-proof.json'
    _create(unknown,b'must stay')
    store.immutable('current.json',dict(nonce=listener))
    name = 'instance.'+listener+'.json'
    runtime = dict(operation=listener,policy_generation=generation,services=str(services),
                   segment=segment,unsettled_activity=None,grant_nonce=grant)
    store.immutable(name,runtime)
    with pytest.raises(MirrorError,match='follow_retirement_active_reference'):
        native_follow._retire_stopped_worker(store,segment,services)
    assert locator.exists() and owned.exists() and plist.exists()
    retired = dict(segment=segment,services=str(services),policy_generation=generation,context=None)
    store.atomic(name,dict(runtime,segment=None,grant_nonce=None,retirement_pending=retired))
    unlink = Path.unlink

    def fail_after_plist(path, *args, **kwargs):
        if path == owned:
            raise OSError('synthetic interruption after partial removal')
        return unlink(path,*args,**kwargs)

    with monkeypatch.context() as context:
        context.setattr(Path,'unlink',fail_after_plist)
        with pytest.raises(OSError,match='partial removal'):
            native_follow._retire_stopped_worker(store,segment,services)
    assert not plist.exists() and locator.exists() and owned.exists()
    other = 'e'*32
    other_services = store.path('workers.'+other)
    other_services.mkdir(mode=0o700)
    store.immutable('instance.'+other+'.json',dict(runtime,operation=other,services=str(other_services),
                    segment=None,grant_nonce=None,retirement_pending=retired))
    store.atomic('current.json',dict(nonce=other))
    assert native_follow._retire_stopped_worker(store,segment,services)==2
    assert all(not path.exists() for path in (locator,owned,plist))
    backup = store.read('worker-retirement.json')
    assert base64.b64decode(backup['files'][plist.name]) == before_plist[0]
    assert unknown.exists()


def test_owned_worker_control_output_is_bounded_but_explicit_cli_keeps_details(monkeypatch, capsys, tmp_path):
    import json

    from wechat_local import native_mirror_cli

    result = {'gaps':['scope_registry_binding'], 'sources':[{'synthetic':'x'*900}]*100}
    monkeypatch.setenv('XDG_STATE_HOME', str(tmp_path/'state'))
    monkeypatch.delenv('WALDEN_FOLLOW_CONTROL_RESULT', raising=False)
    monkeypatch.setattr(native_mirror_cli, 'load_source_config', lambda *args, **kwargs: {})
    monkeypatch.setattr(native_mirror_cli, 'run_owned_once', lambda *args, **kwargs: dict(result))
    args = ['once','--source-config','/synthetic/profile.json','--operation-record','/synthetic/record.owned']
    assert native_mirror_cli.main(args)==1
    external = capsys.readouterr().out
    assert len(external.encode()) > 65536 and json.loads(external)['sources'] == result['sources']
    monkeypatch.setenv('WALDEN_FOLLOW_CONTROL_RESULT','1')
    assert native_mirror_cli.main(args)==1
    internal = capsys.readouterr().out.encode()
    assert len(internal) < 65536 and 'sources' not in json.loads(internal)
    worker = dict(operation='test',attempts=1)
    native_background._completed_attempt(worker,1,internal)
    assert worker['last_completed']['failure_reason'] == 'scope_registry_binding'


def test_local_table_gaps_do_not_latch_global_source_conflict():
    import json

    gaps = ['unsupported_message_schema','source_schema_changed','source_shard_missing','source_table_missing']
    encoded = json.dumps(schedule.control_result({'gaps':gaps,'sources':['x'*70000]})).encode()
    assert set(json.loads(encoded)['gaps']) == set(gaps)
    worker = dict(operation='test',attempts=1)
    native_background._completed_attempt(worker,1,encoded)
    assert worker['last_completed']['failure_class']=='retryable'
    assert worker['last_completed']['source_conflicts']==[]


@pytest.mark.parametrize('case', ['watch_idle','watch_active','late_source_failure',
                                  'drain_spawn_busy','drain_spawn_permanent'])
def test_listener_settles_old_worker_before_reopening_or_granting(tmp_path, monkeypatch, case):
    import json
    import os
    import time
    from types import SimpleNamespace

    from wechat_local import native_follow_config, native_follow_grant, native_schedule
    from wechat_local.native_follow_policy import Store, digest, encoded
    from wechat_local.native_mirror_store import MirrorError

    store = Store(tmp_path/'follow',create=True)
    generation = '1'*32
    config = {'message_root':str(tmp_path/'synthetic-source'), 'mirror_root':str(tmp_path/'mirror')}
    policy = dict(label='org.walden.synthetic', executable='/synthetic/sync', generation=generation,
                  environment={},snapshot=str(tmp_path/'snapshot'), profile_path=str(tmp_path/'profile'),
                  store_root=str(store.root),source_signature=digest(config),
                  settings=dict(executable='/synthetic/app',poll=2,drain=30,drain_interval=5,
                                interval=30,round=30,segment=180))
    path = store.immutable('policy.'+generation+'.json',policy)
    store.atomic('intent.json',dict(enabled=True,generation=generation))
    leader = dict(pid=os.getpid(),uid=os.getuid(),pgid=os.getpid(),start=[1,2])
    context = dict(domain='kSMDomainUserLaunchd',uid=os.getuid(),security_session=1)
    run = SimpleNamespace(context=context,pid=lambda _:leader['pid'])
    kernel = SimpleNamespace(identity=lambda _:leader, require_own_leader=lambda _:None,
                             same_generation=lambda actual,saved:actual==saved,
                             group_members=lambda *_:[leader])
    clock = SimpleNamespace(seconds=0)
    start_wall, start_tick = time.time(), native_follow.continuous_ns()
    monkeypatch.setattr(native_follow,'time',SimpleNamespace(time=lambda:start_wall+clock.seconds,
                                time_ns=lambda:int((start_wall+clock.seconds)*10**9)))
    monkeypatch.setattr(native_follow,'continuous_ns',lambda:start_tick+clock.seconds*10**9)
    monkeypatch.setattr(native_follow,'_observe',lambda *args:'owned')
    monkeypatch.setattr(native_follow,'_material',lambda _:'installed')
    monkeypatch.setattr(native_follow,'load_source_config',lambda *args, **kwargs:config)
    opens, closes, stops, grants = [], [], [], []
    epoch = dict(pid=100,uid=os.getuid(),start=[1,1])
    app = dict(state='absent',epoch=None) if case=='watch_idle' else dict(state='running',epoch=epoch)
    disabled = dict(enabled=False,generation=generation)
    drain_failure = case.startswith('drain_spawn')

    def start_failing_drain(cfg, owned, operation, grant, descriptor):
        facts = descriptor['deadline']
        report_config = dict(operation=operation,deadline=facts,target='synthetic.worker',
            interval_seconds=5,config_sha256='synthetic',os_context=context,follow_grant=descriptor['path'],
            follow_grant_sha256=descriptor['sha256'])
        payload = dict(ProgramArguments=['/synthetic/sync'],EnvironmentVariables={})
        deadline = SimpleNamespace(facts=facts,check=lambda:None,check_revocation=lambda **_:None,
                                   remaining=lambda:20)
        owned.write_bytes(encoded(report_config))

        def spawn(*_, **__):
            if case=='drain_spawn_permanent':
                raise FileNotFoundError('synthetic installed runner unavailable')
            raise OSError('synthetic temporary spawn refusal')

        with monkeypatch.context() as worker:
            worker.setattr(native_background,'arm_fatal',lambda *_:None)
            worker.setattr(native_background,'_control',lambda *_:(report_config,payload,deadline))
            worker.setattr(native_follow_config,'settings',lambda _:dict(poll=2))
            worker.setattr(native_follow_grant,'load',lambda *_:grant)
            worker.setattr(native_schedule,'_observe',lambda *_:'absent')
            worker.setattr(native_schedule,'_config_digest',lambda *_:'synthetic')
            with pytest.raises(MirrorError,match='schedule_child_spawn_failed'):
                native_background.run_bounded(cfg,tmp_path/'profile',owned,operation_token=operation,
                                              transport=run,process=kernel,spawn=spawn)

    def configure(config, _snapshot, _exe, services, _enable, *, runner, follow_grant, prepared, _prepare_trace=None):
        grant = store.read(Path(follow_grant['path']).name)
        grants.append((grant['kind'],clock.seconds))
        operation = f'{len(grants):032x}'
        plist = services/(native_follow._schedule_label(config,follow_grant)+'.plist')
        prepared(dict(operation=operation,record=str(plist.with_suffix('.owned')),
                      grant=follow_grant,os_context=runner.context))
        if grant['kind']=='drain' and drain_failure:
            assert grants==[('active',0),('drain',0)]
            owned = plist.with_suffix('.owned')
            owned.touch(mode=0o600)
            start_failing_drain(config,owned,operation,grant,follow_grant)
            return plist
        for suffix, record in (
            ('.owned', dict(operation=operation)),
            ('.runtime', dict(operation=operation,attempts=1,
                              last_completed=dict(operation=operation,attempt=1,exit_code=0))),
        ):
            record_path = plist.with_suffix(suffix)
            record_path.write_bytes(encoded(record))
            record_path.chmod(0o600)
        return plist

    def stop_segment(*_):
        state = native_follow._runtime(store)
        assert state['admission'] is False and state['segment'] is not None
        stops.append(clock.seconds)
        if case=='watch_active' and len(stops)==1:
            raise OSError('synthetic worker stop busy')
        return True

    def retire_worker(_store, segment, _services, *, terminal):
        owned = Path(segment['record'])
        runtime = owned.with_suffix('.runtime')
        if case=='late_source_failure':
            terminal(dict(attempts=2,last_completed=dict(operation=segment['operation'],attempt=2,
                exit_code=2,failure_class='permanent',failure_reason='scope_registry_binding')))
        if drain_failure and segment['kind']=='drain':
            terminal(json.loads(runtime.read_bytes()))
        owned.unlink()
        runtime.unlink()
        return 1

    monkeypatch.setattr(native_follow,'configure',configure)
    monkeypatch.setattr(native_follow,'_writer_state',lambda _:'free')
    monkeypatch.setattr(native_follow,'_stop_segment',stop_segment)
    monkeypatch.setattr(native_follow,'_retire_stopped_worker',retire_worker)
    def worker_status(_policy, segment, *_):
        return dict(registration='absent',stop_confirmed=True,
                    gaps=['synthetic_terminal_report_late'] if drain_failure and segment['kind']=='drain' else [])
    monkeypatch.setattr(native_follow,'_segment_status',worker_status)
    waits = 0

    class Events:
        identity=[1,2]
        generation=1

        def wait(self,_):
            nonlocal waits
            waits += 1
            if case=='late_source_failure':
                if waits==1:
                    app.update(state='absent',epoch=None)
                else:
                    state = native_follow._runtime(store)
                    assert state['source_schedule']['failure_reason']=='scope_registry_binding'
                    store.atomic('intent.json',disabled)
                return 1
            if drain_failure:
                if waits==1:
                    app.update(state='absent',epoch=None)
                if waits==3:
                    state = native_follow._runtime(store)
                    cadence = state['source_schedule']
                    assert state['round']['last_completed'] is None
                    assert state['round']['admission_failure']['kind']=='source_spawn'
                    assert state['segment'] is state['retirement_pending'] is None
                    assert cadence['mode']==('blocked' if case=='drain_spawn_permanent' else 'backoff')
                    if cadence['mode']=='backoff':
                        assert cadence['next_due_continuous_ns']-cadence['last_checked_continuous_ns']==300*10**9
                    assert grants==[('active',0),('drain',0)]
                    store.atomic('intent.json',disabled)
                return 1
            if len(opens)==1:
                raise OSError('synthetic event delivery loss')
            store.atomic('intent.json',disabled)
            return 1

        def close(self):
            closes.append(clock.seconds)

    def make_events(_):
        if case=='watch_active' and opens:
            assert stops==[0,300] and native_follow._runtime(store)['segment'] is None
        opens.append(clock.seconds)
        return Events()

    def sleep(seconds):
        clock.seconds += seconds
        assert clock.seconds <= 302

    assert native_follow.run_listener(path,digest(policy),operation_token=generation,run=run,
        process=kernel, app_observer=lambda _:dict(app),
        event_factory=make_events, sleep=sleep) == {'enabled':False,'gaps':[]}
    if case=='watch_idle':
        assert opens==closes==[0,300] and not stops and not grants
    elif case=='watch_active':
        assert opens==closes==[0,300] and stops==[0,300,300]
        assert grants==[('active',0),('active',300)]
    elif drain_failure:
        assert opens==closes==[0] and stops==[0,0] and grants==[('active',0),('drain',0)]
    else:
        assert opens==closes==[0] and stops==[0] and grants==[('active',0)]


def test_drain_cannot_clear_active_media_cadence_and_terminal_report_is_adopted():
    runtime = {'source_schedule': {'mode':'normal','media':{'mode':'blocked'}}}
    native_follow._adopt_worker_cadence(runtime, {'kind':'drain'}, {'source_schedule':{'mode':'normal'}}, interval=30)
    assert runtime['source_schedule']['media']['mode']=='blocked'
    native_follow._adopt_worker_cadence(runtime, {'kind':'active'},
                                        {'source_schedule':{'mode':'backoff','backoff':300}}, interval=30)
    assert runtime['source_schedule']['media']['mode']=='blocked'
    native_follow._adopt_worker_cadence(runtime, {'kind':'active'},
                                        {'source_schedule':{'mode':'backoff','media':{'mode':'blocked',
                                            'failure_reason':'media_store_binding'}}}, interval=30)
    assert runtime['source_schedule']['media']['failure_reason']=='media_store_binding'


def test_failure_retention_closes_only_a_proved_ended_birth(tmp_path, monkeypatch):
    import json
    import os
    import time

    from wechat_local import failure_evidence, native_process

    monkeypatch.setenv('XDG_STATE_HOME',str(tmp_path))
    directory = tmp_path/'walden'/'failures'
    directory.parent.mkdir(mode=0o700)
    directory.mkdir(mode=0o700)
    now = time.time_ns()
    old = now - 8*24*3600*10**9
    cases = [(100,'started',[1,2]),(101,'started',None),(102,'pending',[1,2]),(103,'started',[1,2])]
    for pid,status,birth in cases:
        ident = f'{pid:032x}'
        actor = dict(pid=pid,uid=os.getuid(),operation_verified=True)
        if birth is not None:
            actor.update(start=birth,pgid=pid)
        path = directory/(ident+'.json')
        path.write_text(json.dumps(dict(schema_version=2,content_redacted=True,task_id=ident,
                                        status=status, process=actor)))
        path.chmod(0o600)
        os.utime(path,ns=(old,old))
    monkeypatch.setattr(native_process,'identity',lambda pid: {'start':[1,2]} if pid==103 else None)
    monkeypatch.setattr(native_process,'group_members',lambda pgid,_uid: [] if pgid==102 else [{'pid':7}])
    assert failure_evidence.prune_terminal(now_ns=now)==2
    for pid in (101,103):
        assert (directory/(f'{pid:032x}'+'.json')).exists()
    backed_up = json.loads((directory/'retention-last.json').read_text())
    assert backed_up['terminal_observation']=='recorded_process_ended'


@pytest.mark.parametrize('case', ['descendants','spawn_busy','spawn_permanent','partial'])
def test_owned_runner_reaps_before_readmission_and_transfers_spawn_failure(tmp_path, monkeypatch, case):
    import json
    import os
    import signal
    import time
    from types import SimpleNamespace
    import pytest
    from wechat_local import native_background as background, native_follow_grant as grant, native_schedule
    from wechat_local import native_follow_policy as policy
    from wechat_local.native_mirror_store import MirrorError

    root = tmp_path
    store = policy.Store(root)
    follow_nonce = '1' * 32
    store.immutable('instance.' + follow_nonce + '.json', dict(hint_generation=0))
    operation = '2' * 32
    target = 'synthetic.follow.target'
    config = {} if case=='partial' else dict(image_database='synthetic')
    clock = SimpleNamespace(tick=0.)
    epoch = 10000
    segment_seconds = 5 if case=='partial' else 1200
    def relative_clock():
        return clock.tick
    def wall():
        return epoch + clock.tick
    def wall_ns():
        return round(wall() * 1_000_000_000)
    def continuous():
        return round(clock.tick * 1_000_000_000)
    def sleep(duration):
        clock.tick += max(.001, duration)
    fake_time = SimpleNamespace(monotonic=relative_clock, time=wall, time_ns=wall_ns, sleep=__import__('time').sleep)
    facts = dict(wall_until=epoch + segment_seconds, continuous_start=0,
                 continuous_until=segment_seconds * 1_000_000_000)
    follow = dict(kind='active', instance_nonce=follow_nonce, store_root=str(root), round_seconds=1 if case=='partial' else 600)
    record = dict(operation=operation, follow_grant='grant', follow_grant_sha256='synthetic',
                  interval_seconds=1, config_sha256='synthetic', deadline=facts,
                  target=target, os_context={})
    payload = dict(ProgramArguments=['/synthetic/executable'], EnvironmentVariables={})
    deadline = SimpleNamespace(facts=facts, check=lambda: None, check_revocation=lambda **_: None,
                               remaining=lambda:max(0., segment_seconds-clock.tick))
    monkeypatch.setattr(grant, 'load', lambda *args: follow)
    monkeypatch.setattr(background, '_control', lambda *args:(record, payload, deadline))
    monkeypatch.setattr(background, 'arm_fatal', lambda *args: None)
    final = {}
    monkeypatch.setattr(background, '_runtime_write', lambda _path,value,**_:final.update(value))
    monkeypatch.setattr(background, 'time', fake_time)
    monkeypatch.setattr(background, 'continuous_ns', continuous)
    if case=='partial':
        frame=dict(gaps=['source_shard_retry_pending'],partial_source=dict(successful_shards=1,retrying_shards=1))
        def control_output(_child,output):
            output.clear();output.extend(json.dumps(frame).encode())
        monkeypatch.setattr(background,'_drain_output',control_output)
    elif case=='descendants':
        def control_output(child, output):
            output.clear()
            if child.action=='once':
                output.extend(b'{"gaps":[],"source_opens":1}')
        monkeypatch.setattr(background,'_drain_output',control_output)
    monkeypatch.setattr(native_schedule, '_read', lambda *args:(json.dumps(record).encode(), [1, 1]))
    monkeypatch.setattr(native_schedule, '_config_digest', lambda *args:'synthetic')
    monkeypatch.setattr(native_schedule, '_observe', lambda *args:'absent')

    leader = dict(pid=os.getpid(), uid=os.getuid(), pgid=os.getpid(), start=[1, 2])
    raw = []
    media = []
    orphans = []
    overlap = []

    class Child:
        def __init__(self, pid, action):
            self.pid = pid
            self.action = action
            self.stdout = None
            self.returncode = None
            self.waited = False
            self.born = clock.tick

        def poll(self):
            if self.returncode is None:
                if case=='partial' and clock.tick>=self.born+.05:
                    self.returncode=1
                elif self.action == 'once' and self is raw[0] and clock.tick >= .05:
                    self.returncode = 0
                elif self.action == 'media' and self is media[0] and clock.tick >= 2:
                    self.returncode = -signal.SIGALRM
                    orphans.append(60001)
            return self.returncode

        def wait(self, timeout=None):
            self.waited = True
            return self.poll()

        def kill(self):
            self.returncode = -signal.SIGKILL

    def spawn(argv, **_):
        if case == 'spawn_busy':
            raise OSError('synthetic temporary spawn refusal')
        if case == 'spawn_permanent':
            raise FileNotFoundError('synthetic installed runner unavailable')
        action = argv[1]
        roster = raw if action == 'once' else media
        child = Child(70000+len(raw)+len(media),action)
        if action == 'media' and roster and orphans:
            overlap.append((round(clock.tick, 2), raw[-1].poll(), tuple(orphans)))
            clock.tick = segment_seconds + 1
        roster.append(child)
        return child

    def group_members(_group, _uid):
        return [leader]+[dict(pid=pid) for pid in orphans]+[
            dict(pid=child.pid) for child in raw+media if child.poll() is None]

    def signal_group(expected, signum):
        assert expected == leader and signum == signal.SIGTERM
        orphans.clear()
        for child in raw+media:
            if child.poll() is None:
                child.returncode = -signum

    kernel = SimpleNamespace(identity=lambda _pid:leader, require_own_leader=lambda _leader:None,
                             group_members=group_members, signal_own_group=signal_group)
    transport = SimpleNamespace(pid=lambda _target:os.getpid())
    settings = __import__('wechat_local.native_follow_config', fromlist=['settings'])
    monkeypatch.setattr(settings, 'settings', lambda _:dict(poll=2))
    if case=='partial':
        with pytest.raises(MirrorError,match='schedule_child_failed'):
            background.run_bounded(config,root/'profile.json',root/'record.owned',
                operation_token=operation,transport=transport,process=kernel,spawn=spawn,sleep=sleep)
        assert len(raw)>=2 and not media
        assert all(child.returncode==1 and child.waited for child in raw)
        assert final['child_exit']==1 and 'cleanup_pending' not in final
        assert final['last_completed']['exit_code']==1
        assert final['last_completed']['failure_class']=='partial_retryable'
        assert final['last_completed']['observation'] is None
        assert final['source_schedule']['mode']=='normal'
        return
    error = 'schedule_child_failed' if case == 'descendants' else 'schedule_child_spawn_failed'
    with pytest.raises(MirrorError, match=error):
        background.run_bounded(config, root/'profile.json', root/'record.owned',
                               operation_token=operation, transport=transport, process=kernel,
                               spawn=spawn, sleep=sleep)
    if case == 'descendants':
        assert len(raw) == 2 and len(media) == 1
        assert overlap == [] and orphans == []
        assert all(child.waited for child in raw+media)
    else:
        assert raw==media==[]
        assert final['attempts']==1 and final.get('last_completed') is None
        attempt = final['attempt_record']
        assert attempt['phase']=='spawn_failed' and attempt['child_identity'] is None and attempt['child_pid'] is None
        fresh = {}
        native_follow._adopt_worker_cadence(fresh, {'kind':'active','operation':operation}, final, interval=30)
        cadence = fresh['source_schedule']
        assert cadence['mode'] == ('backoff' if case == 'spawn_busy' else 'blocked')
        assert not schedule.plan(cadence,wall=99999,continuous=299*10**9,interval=30)['due']
        assert schedule.plan(cadence,wall=99999,continuous=300*10**9,interval=30)['due'] == (case=='spawn_busy')


def test_explicit_disable_retires_exact_legacy_material_then_enable_uses_new_policy(tmp_path, monkeypatch):
    import os
    import plistlib
    from types import SimpleNamespace

    import pytest
    from wechat_local.native_follow_policy import Store, digest, profile_id
    from wechat_local.native_mirror_store import MirrorError
    from wechat_local.native_schedule import _create

    store = Store(tmp_path/'follow',create=True)
    agents = tmp_path/'agents'
    agents.mkdir(mode=0o700)
    profile, executable = tmp_path/'profile.json', tmp_path/'bin'/'wechat-local-sync'
    config = dict(mirror_scope=['synthetic'],mirror_root=str(tmp_path/'mirror'),self_identity={'bound':True},
                  runtime_python=str(executable.parent/'python'),
                  window_cli=str(executable.parent/'wechat-local-window'),
                  reply_cli=str(executable.parent/'wechat-local-reply'))
    generation = '1'*32
    label = 'org.walden.native.follow.'+profile_id(profile)
    agent = agents/(label+'.plist')
    path = store.path('policy.'+generation+'.json')
    policy = dict(generation=generation,label=label,executable=str(executable),environment={},
                  snapshot=str(tmp_path/'snapshot.json'),profile_path=str(profile),
                  agent_path=str(agent),policy_path=str(path),store_root=str(store.root),
                  source_signature=digest(config))
    store.immutable(path.name,policy)
    store.immutable('intent.json',dict(enabled=True,generation=generation))
    legacy = native_follow._legacy_payload(policy,path)
    _create(agent,plistlib.dumps(legacy))
    registered = [legacy]
    removed = []
    context = dict(domain='kSMDomainUserLaunchd',uid=os.getuid(),security_session=1)

    def observe(_run, _target, payload=None):
        if not registered:
            return 'absent'
        return 'owned' if payload==registered[0] else 'unknown'

    def remove(_target, *, wait=True):
        removed.append(registered.pop())

    run = SimpleNamespace(context=context,remove=remove,submit=registered.append)
    monkeypatch.setattr(native_follow,'_observe',observe)
    assert native_follow._material(policy)=='unknown'
    with pytest.raises(MirrorError,match='follow_login_material_unknown'):
        native_follow.enable(config,profile,executable,run=run,root=store.root,agents=agents)
    assert native_follow.disable(profile,run=run,root=store.root)['disabled_confirmed']
    assert removed==[legacy] and not agent.exists()
    assert len(list(agents.glob(agent.name+'.disabled-*')))==1
    assert native_follow.enable(config,profile,executable,run=run,root=store.root,agents=agents)['enabled']
    assert registered[0]['KeepAlive'] is False and registered[0]['ThrottleInterval']==30
    assert store.read('intent.json')['generation'] != generation


@pytest.mark.parametrize('case', [
    'self_remove','no_signal','external_stop','revoked_during_remove','receiver_changed',
    'context_changed','unknown_registration','failed_body',
])
def test_deadline_handoff_keeps_its_exit_cause_and_verifies_receiver(tmp_path, monkeypatch, case):
    import hashlib
    import json
    import os
    import plistlib
    import signal
    import sys
    import time
    from types import SimpleNamespace

    from wechat_local import native_background as background, native_follow_grant as grants
    from wechat_local import native_schedule
    from wechat_local.native_deadline import Deadline, continuous_ns
    from wechat_local.native_follow_policy import Store, digest, encoded
    from wechat_local.native_mirror_store import MirrorError

    from wechat_local import failure_evidence
    terminal=[]
    monkeypatch.setattr(failure_evidence,'bounded_terminal',lambda **value:terminal.append(value))
    store = Store(tmp_path/'follow',create=True)
    generation, instance, nonce, operation = '1'*32,'2'*32,'3'*32,'4'*32
    context = dict(domain='kSMDomainUserLaunchd',uid=os.getuid(),security_session=1)
    services = store.root/('workers.'+instance)
    services.mkdir(mode=0o700)
    config = {'synthetic':'source'}
    profile = tmp_path/'profile.json'
    profile.write_bytes(encoded(config)); profile.chmod(0o600)
    facts = Deadline.create(5).facts
    grant = dict(kind='active',store_root=str(store.root),nonce=nonce,instance_nonce=instance,
                 policy_generation=generation,source_sha256=digest(config),os_context=context,
                 deadline=facts,round_seconds=1)
    grant_path = store.immutable('grant.'+nonce+'.json',grant)
    descriptor = dict(path=str(grant_path),sha256=hashlib.sha256(grant_path.read_bytes()).hexdigest(),
                      label_id='a'*20+'.'+instance,interval_seconds=30)
    label = native_schedule._schedule_label(config,descriptor)
    record_path = services/(label+'.owned')
    executable = str(Path(sys.executable).parent/'wechat-local-sync')
    argv = native_schedule._follow_args(
        [executable,'bounded','--source-config',str(profile),'--operation-record',str(record_path)],descriptor)
    payload = dict(Label=label,ProgramArguments=argv+['--operation-token',operation],
                   EnvironmentVariables={'WALDEN_OPERATION_ID':operation})
    plist = record_path.with_suffix('.plist')
    plist.write_bytes(plistlib.dumps(payload)); plist.chmod(0o600)
    raw, identity = native_schedule._read(plist)
    target = '/'.join((context['domain'],str(os.getuid()),'1',label))
    record = dict(operation=operation,os_context=context,preflight='absent',plist_identity=identity,
                  plist_sha256=hashlib.sha256(raw).hexdigest(),config_sha256=native_schedule._config_facts(config),
                  target=target,deadline=facts,follow_grant=str(grant_path),
                  follow_grant_sha256=descriptor['sha256'],interval_seconds=30)
    record_path.write_bytes(encoded(record)); record_path.chmod(0o600)
    leader = dict(pid=os.getpid(),uid=os.getuid(),pgid=os.getpid(),start=[1,2],status=2)
    receiver = dict(pid=100,uid=os.getuid(),pgid=100,start=[3,4],status=2)
    listener_label = 'org.walden.synthetic.listener'
    parent = dict(operation=instance,grant_nonce=nonce,context=context,leader=receiver,
                  binding_valid=True,listener_argv=['synthetic-listener','--operation-token',instance],
                  segment=dict(operation=operation,kind='active'),hint_generation=0)
    store.immutable('instance.'+instance+'.json',parent)
    store.immutable('current.json',dict(nonce=instance))
    store.immutable('intent.json',dict(enabled=True,generation=generation))
    store.immutable('policy.'+generation+'.json',dict(source_signature=digest(config),
                   profile_path=str(profile),label=listener_label))
    tick = continuous_ns()
    clock = SimpleNamespace(seconds=0,removed=False,waits=0,spawned=0)
    fake_time = SimpleNamespace(time=time.time,time_ns=time.time_ns,
                                monotonic=lambda:clock.seconds,sleep=time.sleep)
    monkeypatch.setattr(background,'time',fake_time)
    monkeypatch.setattr(background,'continuous_ns',lambda:tick+int(clock.seconds*1e9))
    monkeypatch.setattr(background,'arm_fatal',lambda *_:None)
    fake_deadline = Deadline(facts,wall=fake_time.time,continuous=lambda:tick+int(clock.seconds*1e9))

    def check_revocation(**_):
        grants._enabled_intent(store,grant)
        grants._instance_runtime(store,grant)

    fake_deadline.check_revocation = check_revocation
    monkeypatch.setattr(grants,'from_record',lambda *_:fake_deadline)
    monkeypatch.setattr(grants,'load',lambda *_:grant)
    from wechat_local import native_follow_config
    monkeypatch.setattr(native_follow_config,'settings',lambda _:dict(poll=2))

    class Child:
        pid = 200
        stdout = None
        returncode = 2 if case=='failed_body' else 0

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            clock.waits += 1
            return self.returncode

    def spawn(*_,**__):
        clock.spawned += 1
        return Child()

    def send_stop():
        signal.getsignal(signal.SIGTERM)(signal.SIGTERM,None)

    def sleep(seconds):
        clock.seconds += max(.01,seconds)
        if case=='external_stop':
            send_stop()

    def remove(which, *, wait):
        assert which==target and wait is False
        clock.removed = True
        if case=='revoked_during_remove':
            store.atomic('intent.json',dict(enabled=False,generation=generation))
        elif case=='receiver_changed':
            store.atomic('current.json',dict(nonce='9'*32))
        if case!='no_signal':
            send_stop()  # The OS requests termination while self-removal is completing.

    def observe(which):
        assert which==target
        if clock.removed and case=='unknown_registration':
            return None
        return dict(target=target,state='present',argv=payload['ProgramArguments'],operation=operation)

    api = SimpleNamespace(current_context=lambda:dict(context,security_session=2)
                           if clock.removed and case=='context_changed' else context,
                          get=lambda _:dict(ProgramArguments=parent['listener_argv'],PID=receiver['pid']))
    transport = SimpleNamespace(context=context,api=api,pid=lambda _:os.getpid(),
                                observe=observe,remove=remove)
    kernel = SimpleNamespace(identity=lambda pid:leader if pid==os.getpid() else receiver,
                             same_generation=lambda a,b:a==b,require_own_leader=lambda _:None,
                             group_members=lambda *_:[leader])
    runtime_path = record_path.with_suffix('.runtime')
    if case in ('self_remove','no_signal'):
        result = background.run_bounded(config,profile,record_path,operation_token=operation,
                                         transport=transport,process=kernel,spawn=spawn,sleep=sleep)
        assert isinstance(result,background.CleanupPending)
        assert result['stopped'] is result['registration_absent'] is result['source_authority'] is False
        assert result['body_status']=='succeeded' and result['operation']==operation
        saved = json.loads(runtime_path.read_bytes())
        assert saved['stop_reason']=='deadline' and saved['status']=='cleanup_pending'
        assert saved['cleanup_pending']['receiver_instance']==instance
        assert background.cleanup_handoff_status(saved,record,context)['state']=='pending'
        assert clock.spawned==clock.waits==1
    else:
        expected = dict(external_stop='schedule_state_unknown',revoked_during_remove='follow_revoked',
                        receiver_changed='follow_instance_changed',context_changed='follow_instance_changed',
                        unknown_registration='schedule_state_unknown',failed_body='schedule_child_failed')
        with pytest.raises(MirrorError,match=expected[case]):
            background.run_bounded(config,profile,record_path,operation_token=operation,
                                   transport=transport,process=kernel,spawn=spawn,sleep=sleep)
        saved = json.loads(runtime_path.read_bytes())
        assert 'cleanup_pending' not in saved
        assert saved['stop_reason']==('requested' if case=='external_stop' else 'failure' if case=='failed_body' else 'deadline')
    assert clock.removed
    assert len(terminal)==1
    assert terminal[0]['stop_reason']==saved['stop_reason']
    assert terminal[0]['child_exit']==saved['child_exit']
    if 'cleanup_observation' in saved:
        assert terminal[0]['remove_accepted']==saved['cleanup_observation']['remove_accepted']
        assert terminal[0]['final_registration']==saved['cleanup_observation']['registration']
    else:
        assert terminal[0]['remove_accepted'] is True and terminal[0]['final_registration']=='owned'
    if case in ('self_remove','no_signal','external_stop','unknown_registration','failed_body'):
        assert saved['group_drained']


def _source_attempt_for_media(monkeypatch, code, frame, *, expired=False, attempt_fields=None):
    """Use the normal owned-child completion projection, with a pinned attempt."""
    import json
    monkeypatch.setattr(native_background, 'continuous_ns', lambda: 100)
    op='a'*32
    attempt=dict(operation=op,attempt=2,child_pid=70,phase='spawned',
                 round_deadline=dict(wall_until=10**12,continuous_start=50,continuous_until=99 if expired else 200),
                 spawn_wall_ns=time.time_ns()-1,spawn_continuous_ns=60)
    attempt.update(attempt_fields or {})
    runtime=dict(operation=op,attempts=2,attempt_record=attempt,child_pid=70,child_exit=code)
    encoded=json.dumps(schedule.control_result(frame)).encode() if isinstance(frame,dict) else frame
    native_background._completed_attempt(runtime,code,encoded)
    return runtime


def test_media_source_uses_only_same_verified_terminal_partial(monkeypatch):
    anchor={'source_identity':[2,3],'header':'d'*64}
    frame=dict(gaps=['source_table_cursor_pending'],source_opens=1,
               partial_source=dict(successful_shards=1,retrying_shards=0,paused_tables=2),
               media_sources={'message_7.db':anchor})
    accepted=_source_attempt_for_media(monkeypatch,1,frame)
    assert native_background._active_media_sources(accepted)=={'message_7.db':anchor}
    for undo in (dict(child_pid=81),dict(attempts=3),dict(admission_failure={'kind':'source_spawn'}),
                 dict(child_exit=2)):
        assert native_background._active_media_sources(dict(accepted,**undo)) is False
    for rejected in (dict(frame,media_sources=None),dict(frame,source_opens=0),
                     dict(frame,gaps=['source_table_cursor_pending','scope_source_conflict'])):
        assert native_background._active_media_sources(_source_attempt_for_media(monkeypatch,1,rejected)) is False
    assert native_background._active_media_sources(_source_attempt_for_media(monkeypatch,1,frame,expired=True)) is False


@pytest.mark.parametrize('code,frame,expired',[
    (0,b'{"truncated":',False),(0,b'',False),
    (0,dict(gaps=[],source_opens=0),False),
    (0,dict(gaps=[],source_opens=2),True),
    (0,dict(gaps=[],source_opens=2,failure_reason='source_replaced'),False),
    (0,dict(gaps=[],source_opens=2,failure_class='retryable'),False),
    (0,b'{"gaps":[],"source_opens":2,"failure_reason":[]}',False),
    (1,dict(gaps=['scope_source_conflict'],source_opens=2),False),
])
def test_media_source_rejects_unknown_success_or_global_failure(monkeypatch,code,frame,expired):
    observed=_source_attempt_for_media(monkeypatch,code,frame,expired=expired)
    assert native_background._active_media_sources(observed) is False


def test_media_source_accepts_a_well_formed_current_success(monkeypatch):
    observed=_source_attempt_for_media(monkeypatch,0,dict(gaps=[],source_opens=1))
    assert native_background._active_media_sources(observed) is None


@pytest.mark.parametrize('facts',[None, [], {}, {'wall_until':10**12,'continuous_until':200},
                                {'wall_until':True,'continuous_start':50,'continuous_until':200},
                                {'wall_until':10**12,'continuous_start':50,'continuous_until':'200'},
                                {'wall_until':10**12,'continuous_start':80,'continuous_until':200}])
@pytest.mark.parametrize('code',[0,1])
def test_media_source_requires_proven_round_clock(monkeypatch,facts,code):
    anchor={'source_identity':[2,3],'header':'d'*64}
    frame=dict(gaps=[],source_opens=1) if code==0 else dict(
        gaps=['source_table_cursor_pending'],source_opens=1,
        partial_source=dict(successful_shards=1,retrying_shards=0,paused_tables=2),
        media_sources={'message_7.db':anchor})
    observed=_source_attempt_for_media(monkeypatch,code,frame,attempt_fields={'round_deadline':facts})
    assert observed['last_completed']['termination']['round_deadline_expired'] is None
    assert native_background._active_media_sources(observed) is False


def test_media_source_requires_typed_completion_and_round_nodes(monkeypatch):
    observed=_source_attempt_for_media(monkeypatch,0,dict(gaps=[],source_opens=1))
    completed=observed['last_completed']
    for invalid in (
        dict(observed,last_completed=[]),
        dict(observed,attempt_record=[]),
        dict(observed,last_completed=dict(completed,termination=[])),
        dict(observed,last_completed={k:v for k,v in completed.items() if k!='completed_at_ns'}),
        dict(observed,last_completed=dict(completed,source_conflicts={})),
        dict(observed,last_completed=dict(completed,exit_code=False)),
    ):
        assert native_background._active_media_sources(invalid) is False
