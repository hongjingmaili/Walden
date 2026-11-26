import hashlib,json,os,plistlib,sys
from pathlib import Path
from types import SimpleNamespace
import pytest
from wechat_local import native_follow as follow,native_schedule as schedule
from wechat_local.native_follow_policy import Store,digest,encoded
from wechat_local.native_deadline import Deadline
from wechat_local.native_mirror_store import MirrorError

@pytest.fixture
def terminal(tmp_path,monkeypatch):
    from wechat_local import native_follow_terminal as recovery
    profile=tmp_path/'profile.json';snapshot=tmp_path/'snapshot.json';mirror=tmp_path/'mirror';mirror.mkdir(mode=0o700)
    (tmp_path/'source').mkdir(mode=0o700)
    config=dict(mirror_root=str(mirror),message_root=str(tmp_path/'source'),synthetic=True)
    for p in (profile,snapshot):p.write_bytes(encoded(config));p.chmod(0o600)
    exe=tmp_path/'wechat-local-sync';exe.write_text('#!/bin/sh\n');exe.chmod(0o700)
    store=Store(tmp_path/'follow',create=True);generation='a'*32;instance='b'*32;operation='c'*32;nonce='d'*32
    snapshot=store.path('source.'+generation+'.json');snapshot.write_bytes(encoded(config));snapshot.chmod(0o600)
    node=(tmp_path/'source').stat();store.immutable('event-root.'+generation+'.json',dict(identity=[node.st_dev,node.st_ino]))
    old=dict(domain='kSMDomainUserLaunchd',uid=os.getuid(),security_session=12,session_attributes=0x6030)
    current=dict(old,session_attributes=0x2030)
    policy=dict(generation=generation,profile_path=str(profile),snapshot=str(snapshot),source_signature=digest(config),
        executable=str(exe),label='org.walden.synthetic.follow',store_root=str(store.root),environment={})
    policy['policy_path']=str(store.path('policy.'+generation+'.json'));policy['agent_path']=str(tmp_path/'listener.plist')
    store.immutable('policy.'+generation+'.json',policy);store.immutable('intent.json',dict(enabled=True,generation=generation))
    Path(policy['agent_path']).write_bytes(plistlib.dumps(follow._payload(policy,policy['policy_path'])));Path(policy['agent_path']).chmod(0o600)
    services=store.root/('workers.'+instance);services.mkdir(mode=0o700)
    grant=dict(kind='active',store_root=str(store.root),nonce=nonce,instance_nonce=instance,policy_generation=generation,
        source_sha256=digest(config),os_context=old,deadline=Deadline.create(30).facts,round_seconds=20)
    grantpath=store.immutable('grant.'+nonce+'.json',grant)
    descriptor=dict(path=str(grantpath),sha256=digest(grant),label_id='a'*20+'.'+instance,interval_seconds=30)
    label=schedule._schedule_label(config,descriptor);recordpath=services/(label+'.owned')
    target='/'.join((old['domain'],str(old['uid']),str(old['security_session']),label))
    args=schedule._follow_args([str(exe),'bounded','--source-config',str(snapshot),'--operation-record',str(recordpath)],descriptor)
    payload=dict(Label=label,ProgramArguments=args+['--operation-token',operation],EnvironmentVariables={'WALDEN_OPERATION_ID':operation})
    plist=recordpath.with_suffix('.plist');plist.write_bytes(plistlib.dumps(payload));plist.chmod(0o600)
    raw,identity=schedule._read(plist)
    record=dict(operation=operation,os_context=old,target=target,preflight='absent',plist_identity=identity,
        plist_sha256=hashlib.sha256(raw).hexdigest(),config_sha256=schedule._config_facts(config),deadline=grant['deadline'],
        follow_grant=str(grantpath),follow_grant_sha256=digest(grant),interval_seconds=30)
    recordpath.write_bytes(encoded(record));recordpath.chmod(0o600)
    worker=dict(pid=201,pgid=201,uid=os.getuid(),start=[1,2]);leader=dict(pid=202,pgid=202,uid=os.getuid(),start=[2,3])
    runtime=dict(operation=operation,os_context=old,leader=worker,status='stopped',child_identity=None)
    rp=recordpath.with_suffix('.runtime');rp.write_bytes(encoded(runtime));rp.chmod(0o600)
    segment=dict(operation=operation,record=str(recordpath),descriptor=descriptor,kind='active')
    parent=dict(operation=instance,policy_generation=generation,context=old,leader=leader,admission=False,binding_valid=True,
        segment=segment,services=str(services),grant_nonce=nonce,unsettled_activity=None,retirement_pending=None)
    store.immutable('instance.'+instance+'.json',parent);store.immutable('current.json',dict(nonce=instance))
    jobs={target:payload,follow._target(SimpleNamespace(context=current),policy['label']):follow._payload(policy,policy['policy_path'])}
    process=SimpleNamespace(identity=lambda pid:None,drained=lambda _:True,same_generation=lambda a,b:a==b)
    class Run:
        context=current
        def __init__(self):self.process=process;self.removed=[];self.mode=None
        def observe(self,t):
            if self.mode=='unknown':return None
            v=jobs.get(t)
            return dict(target=t,state='present',argv=v['ProgramArguments'],operation=schedule._argv_operation(v['ProgramArguments'])) if v else dict(target=t,state='absent')
        def pid(self,t):return None
        def remove(self,t,wait=True):self.removed.append(t);jobs.pop(t,None)
    run=Run()
    monkeypatch.setattr(recovery,'load_source_config',lambda path,physical=False:json.loads(Path(path).read_bytes()))
    monkeypatch.setattr(follow,'load_source_config',recovery.load_source_config)
    monkeypatch.setattr(recovery,'_source_proof',lambda config:('synthetic-anchor',))
    value=SimpleNamespace(profile=profile,config=config,store=store,policy=policy,parent=parent,run=run,record=record,
        recordpath=recordpath,grantpath=grantpath,worker=worker,leader=leader,generation=generation,old=old,current=current,recovery=recovery)
    value.origin=origin(value)
    with pytest.raises(MirrorError):follow.disable(value.profile,run=value.run,root=value.store.root)
    return value

def call(t,**kw):
    return t.recovery.recover(t.profile,expected_source_sha256=hashlib.sha256(t.profile.read_bytes()).hexdigest(),
        expected_policy_generation=t.generation,authorize=True,run=t.run,root=t.store.root,**dict(t.origin,**kw))

def test_exact_dead_generation_is_terminally_retired_without_editing_old_proofs(terminal):
    t=terminal;old_instance=t.store.path('instance.'+t.parent['operation']+'.json').read_bytes();old_grant=t.grantpath.read_bytes();old_record=t.recordpath.read_bytes()
    result=call(t)
    assert result['disabled_confirmed'] is True and result['source_authority'] is False
    assert t.store.read('intent.json')['enabled'] is False and len(t.run.removed)==2
    assert t.store.path('instance.'+t.parent['operation']+'.json').read_bytes()==old_instance
    assert t.grantpath.read_bytes()==old_grant
    assert next(t.recordpath.parent.glob(t.recordpath.name+'.disabled-*')).read_bytes()==old_record
    assert follow._runtime(t.store)['segment'] is None

@pytest.mark.parametrize('case',['live_pid','live_group','foreign','unknown','other_delta','config_changed','grant_changed','source_changed','enabled','wrong_policy','unsettled','same_context','attrs_extra','live_child','root_changed'])
def test_terminal_recovery_rejects_unproven_or_live_generations_before_revocation(terminal,case):
    t=terminal
    if case=='live_pid':t.run.process.identity=lambda pid:t.worker if pid==201 else None
    elif case=='live_group':t.run.process.drained=lambda _:False
    elif case=='foreign':t.run.observe=lambda target:dict(target=target,state='present',argv=['foreign'],operation='e'*32)
    elif case=='unknown':t.run.mode='unknown'
    elif case=='other_delta':t.run.context=dict(t.current,security_session=13)
    elif case=='same_context':t.run.context=dict(t.old)
    elif case=='attrs_extra':t.run.context=dict(t.current,session_attributes=t.current['session_attributes']^0x10)
    elif case=='live_child':
        rp=t.recordpath.with_suffix('.runtime');w=json.loads(rp.read_bytes());w['media_child_pid']=901;rp.write_bytes(encoded(w))
        t.run.process.identity=lambda pid:dict(pid=901) if pid==901 else None
    elif case=='config_changed':t.profile.write_bytes(encoded(dict(t.config,synthetic=False)))
    elif case=='root_changed':t.store.atomic('event-root.'+t.generation+'.json',dict(identity=[1,2]))
    elif case=='grant_changed':t.grantpath.write_bytes(encoded(dict(kind='request')))
    elif case=='source_changed':t.recovery._source_proof=lambda _:(_ for _ in ()).throw(MirrorError('source_changed'))
    elif case=='enabled':t.store.atomic('intent.json',dict(enabled=True,generation=t.generation))
    elif case=='wrong_policy':t.generation='f'*32
    elif case=='unsettled':
        t.parent['unsettled_activity']={'different':'operation'};t.store.atomic('instance.'+t.parent['operation']+'.json',t.parent)
    with pytest.raises((MirrorError,OSError)):call(t)
    assert t.run.removed==[]
    assert t.store.read('intent.json')['enabled'] is (case=='enabled')


def test_ordinary_disable_still_refuses_the_retired_context(terminal):
    t=terminal
    with pytest.raises(MirrorError,match='schedule_state_unknown'):
        follow.disable(t.profile,run=t.run,root=t.store.root)
    assert not t.run.removed


def test_terminal_authority_cannot_enable_or_be_forged(terminal):
    t=terminal
    with pytest.raises(MirrorError):
        schedule.configure(t.config,t.policy['snapshot'],t.policy['executable'],t.parent['services'],True,
                           runner=t.run,follow_grant=t.parent['segment']['descriptor'],_terminal_retirement=object())
    with pytest.raises(MirrorError):
        schedule.configure(t.config,t.policy['snapshot'],t.policy['executable'],t.parent['services'],False,
                           runner=t.run,follow_grant=t.parent['segment']['descriptor'],_terminal_retirement=object())
    assert not t.run.removed


from test_account_sync_status import item

def test_source_metadata_proof_uses_the_real_receipt_and_all_pinned_headers(item):
    from wechat_local.native_follow_terminal import _source_proof
    from wechat_local import native_scope_contract as sc
    with sc.registry(item['config'],write=True) as db:
        sc.save(db,'shard_anchor:message_0.db',dict(source_identity=item['live_identity'],header=item['live_header']));db.commit()
    proof=_source_proof(item['config'])
    assert len(proof[1])>=1
    source=Path(item['message_root'])/'message_0.db'
    before=source.read_bytes()
    # Synthetic encrypted bytes only; alter the fixed file header in place.
    with source.open('r+b') as fh:fh.write(bytes([before[0]^1]))
    with pytest.raises(MirrorError):_source_proof(item['config'])


def test_installed_cli_route_requires_explicit_current_policy_and_no_source_authority(terminal,monkeypatch,capsys):
    from wechat_local import native_mirror_cli as cli
    t=terminal
    monkeypatch.setattr(cli,'load_source_config',t.recovery.load_source_config)
    monkeypatch.setattr(t.recovery,'default_root',lambda _:t.store.root)
    monkeypatch.setattr(schedule,'LaunchctlTransport',lambda:t.run)
    code=cli.main(['follow-recover-terminal','--source-config',str(t.profile),'--authorize-terminal-recovery',
                  '--expected-source-sha256',hashlib.sha256(t.profile.read_bytes()).hexdigest(),
                  '--expected-policy-generation',t.generation,
                  '--terminal-revoked-origin',str(t.origin['revoked_origin']),
                  '--terminal-revoked-origin-sha256',t.origin['revoked_origin_sha256']])
    value=json.loads(capsys.readouterr().out)
    assert code==0 and value['disabled_confirmed'] is True and value['source_authority'] is False


def test_nonempty_public_pid_and_busy_writer_refuse_without_removal(terminal):
    from wechat_local.native_mirror_sync import writer_lock
    t=terminal
    t.run.pid=lambda _:900
    with pytest.raises(MirrorError):call(t)
    assert t.store.read('intent.json')['enabled'] is False and not t.run.removed
    t.run.pid=lambda _:None
    with writer_lock(Path(t.config['mirror_root']),0):
        with pytest.raises(MirrorError,match='sync_busy'):call(t)
    assert t.store.read('intent.json')['enabled'] is False and not t.run.removed


def test_original_source_grant_is_never_accepted_during_or_after_retirement(terminal,monkeypatch):
    from wechat_local import native_follow_grant as grants,source_setup
    t=terminal;grant=json.loads(t.grantpath.read_bytes())
    monkeypatch.setattr(source_setup,'load_source_config',t.recovery.load_source_config)
    api=SimpleNamespace(context=t.current)
    with pytest.raises(MirrorError,match='follow_revoked'):
        grants.validate(grant,api=api,process=t.run.process)
    call(t)
    with pytest.raises(MirrorError,match='follow_revoked'):
        grants.validate(grant,api=api,process=t.run.process)


def origin(t):
    value=dict(schema='walden.follow.terminal-origin/1',enabled=True,policy_generation=t.policy['generation'],
        profile_sha256=hashlib.sha256(t.profile.read_bytes()).hexdigest(),
        policy_sha256=hashlib.sha256(Path(t.policy['policy_path']).read_bytes()).hexdigest(),
        instance_sha256=hashlib.sha256(t.store.path('instance.'+t.parent['operation']+'.json').read_bytes()).hexdigest(),
        old_context=t.old,current_context=t.current)
    path=t.profile.parent/'terminal-origin.json';path.write_bytes(encoded(value));path.chmod(0o600)
    return dict(revoked_origin=path,revoked_origin_sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def test_exact_formal_revocation_can_continue_terminal_retirement_only(terminal):
    t=terminal;proof=origin(t)
    with pytest.raises(MirrorError):follow.disable(t.profile,run=t.run,root=t.store.root)
    assert t.store.read('intent.json')['enabled'] is False
    result=call(t,**proof)
    assert result['disabled_confirmed'] and result['source_authority'] is False
    assert t.store.read('intent.json')['enabled'] is False
    # Reentry cannot silently renew, reinterpret the new terminal view, or
    # adopt another old operation. It remains safely disabled.
    with pytest.raises(MirrorError):call(t,**proof)
    assert t.store.read('intent.json')['enabled'] is False


@pytest.mark.parametrize('field',['enabled','profile_sha256','policy_sha256','instance_sha256','old_context','current_context'])
def test_revoked_continuation_rejects_mismatched_preflight(terminal,field):
    t=terminal;proof=origin(t)
    with pytest.raises(MirrorError):follow.disable(t.profile,run=t.run,root=t.store.root)
    value=json.loads(proof['revoked_origin'].read_bytes());value[field]=None
    proof['revoked_origin'].write_bytes(encoded(value));proof['revoked_origin_sha256']=hashlib.sha256(proof['revoked_origin'].read_bytes()).hexdigest()
    with pytest.raises(MirrorError):call(t,**proof)
    assert not t.run.removed and t.store.read('intent.json')['enabled'] is False


def test_reappearing_listener_after_revocation_remains_refused_and_disabled(terminal):
    t=terminal;proof=origin(t)
    with pytest.raises(MirrorError):follow.disable(t.profile,run=t.run,root=t.store.root)
    t.run.pid=lambda target:203
    with pytest.raises(MirrorError):call(t,**proof)
    assert not t.run.removed and t.store.read('intent.json')['enabled'] is False


def test_resurrected_listener_after_formal_revocation_exits_before_events_or_source(terminal):
    t=terminal;proof=origin(t)
    with pytest.raises(MirrorError):follow.disable(t.profile,run=t.run,root=t.store.root)
    leader=dict(pid=os.getpid(),pgid=os.getpid(),uid=os.getuid(),start=[8,9])
    process=SimpleNamespace(identity=lambda pid:leader,require_own_leader=lambda _:None)
    t.run.pid=lambda _:os.getpid()
    def forbidden(*args,**kwargs):raise AssertionError('no Source/event admission after revocation')
    result=follow.run_listener(Path(t.policy['policy_path']),hashlib.sha256(Path(t.policy['policy_path']).read_bytes()).hexdigest(),
        operation_token=t.generation,run=t.run,process=process,event_factory=forbidden,app_observer=forbidden)
    assert result==dict(enabled=False,gaps=[])
    assert t.store.read('intent.json')['enabled'] is False


def test_resurrected_old_worker_cannot_pass_its_original_control_boundary(terminal):
    from wechat_local.native_background import _control
    t=terminal
    with pytest.raises(MirrorError,match='schedule_state_unknown'):
        _control(t.config,t.policy['snapshot'],t.recordpath,t.run,t.record['operation'])
    assert t.run.removed==[]


def test_listener_remove_failure_resumes_only_the_same_verified_worker_archives(terminal):
    t=terminal;remove=t.run.remove;failed=[False]
    def stop(target,wait=True):
        if target.endswith('/'+t.policy['label']) and not failed[0]:
            failed[0]=True;raise OSError('synthetic observer failure')
        return remove(target,wait=wait)
    t.run.remove=stop
    with pytest.raises(OSError):call(t)
    assert not t.recordpath.exists() and t.store.read('intent.json')['enabled'] is False
    assert call(t)['disabled_confirmed'] is True
    assert t.store.read('intent.json')['enabled'] is False


def test_missing_worker_files_without_this_transactions_pins_are_not_completion(terminal):
    t=terminal;t.recordpath.rename(t.recordpath.with_name(t.recordpath.name+'.disabled-1'))
    with pytest.raises((MirrorError,OSError)):call(t)
    assert t.store.read('intent.json')['enabled'] is False and not t.run.removed


@pytest.mark.parametrize('case',['enabled','missing_origin','wrong_hash'])
def test_real_cli_rejects_unrevoked_or_unbound_terminal_requests(terminal,monkeypatch,capsys,case):
    from wechat_local import native_mirror_cli as cli
    t=terminal
    monkeypatch.setattr(cli,'load_source_config',t.recovery.load_source_config)
    monkeypatch.setattr(t.recovery,'default_root',lambda _:t.store.root)
    monkeypatch.setattr(schedule,'LaunchctlTransport',lambda:t.run)
    argv=['follow-recover-terminal','--source-config',str(t.profile),'--authorize-terminal-recovery',
          '--expected-source-sha256',hashlib.sha256(t.profile.read_bytes()).hexdigest(),
          '--expected-policy-generation',t.generation]
    if case=='enabled':t.store.atomic('intent.json',dict(enabled=True,generation=t.generation))
    if case!='missing_origin':argv+=['--terminal-revoked-origin',str(t.origin['revoked_origin']),
        '--terminal-revoked-origin-sha256',t.origin['revoked_origin_sha256'] if case!='wrong_hash' else '0'*64]
    code=cli.main(argv);result=json.loads(capsys.readouterr().out)
    assert code==2 and 'error' in result and not t.run.removed
    assert t.store.read('intent.json')['enabled'] is (case=='enabled')


@pytest.mark.parametrize('case',['foreign','unknown','live_pid','delta','archive_changed'])
def test_failed_terminal_transaction_never_adopts_changed_resume_facts(terminal,case):
    t=terminal;remove=t.run.remove
    def fail(target,wait=True):
        if target.endswith('/'+t.policy['label']):raise OSError('synthetic remove failure')
        return remove(target,wait=wait)
    t.run.remove=fail
    with pytest.raises(OSError):call(t)
    t.run.remove=remove;before=len(t.run.removed)
    if case=='foreign':t.run.observe=lambda target:dict(target=target,state='present',argv=['foreign'],operation='e'*32)
    elif case=='unknown':t.run.mode='unknown'
    elif case=='live_pid':t.run.pid=lambda _:777
    elif case=='delta':t.run.context=dict(t.current,security_session=13)
    else:
        archive=next(t.recordpath.parent.glob(t.recordpath.name+'.disabled-*'));archive.write_bytes(archive.read_bytes()+b' ')
    with pytest.raises((MirrorError,OSError)):call(t)
    assert len(t.run.removed)==before and t.store.read('intent.json')['enabled'] is False


def test_interrupted_worker_archive_resumes_only_its_exact_pinned_files(terminal,monkeypatch):
    t=terminal;rename=Path.rename;failed=[False]
    def interrupt(path,destination):
        if path==t.recordpath and not failed[0]:
            failed[0]=True;raise OSError('synthetic archive interruption')
        return rename(path,destination)
    monkeypatch.setattr(Path,'rename',interrupt)
    with pytest.raises(OSError):call(t)
    assert t.recordpath.exists() and not t.recordpath.with_suffix('.plist').exists()
    assert call(t)['disabled_confirmed'] is True
    assert t.store.read('intent.json')['enabled'] is False
