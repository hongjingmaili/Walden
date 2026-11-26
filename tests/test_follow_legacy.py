"""Real private control/scope/locks; only public OS facts are substituted."""
import hashlib,json,os,sys
from pathlib import Path
from types import SimpleNamespace
import pytest
from wechat_local import native_follow as follow,native_follow_legacy as legacy,native_process as kernel
from wechat_local import native_schedule as schedule,native_scope_contract as scope,native_follow_grant as grants
from wechat_local.native_follow_policy import Store,digest,encoded
from wechat_local.native_mirror_store import MirrorError
import test_reboot_tolerance as fixture

@pytest.fixture
def item(tmp_path,monkeypatch):
    v=fixture.setup(str(tmp_path));config=v['config'];root=Path(config['mirror_root']);root.chmod(0o700)
    config.update(runtime_python=sys.executable,window_cli=str(Path(sys.executable).parent/'wechat-local-window'),
        reply_cli=str(Path(sys.executable).parent/'wechat-local-reply'),passphrase_file=str(tmp_path/'unused-passphrase'))
    receipt=tmp_path/'receipt.json';scope.create(receipt,scope.encoded(dict(state='committed',contract=scope.fixed(config),
        new_config_sha256=scope.digest(config),legacy_current_sha256=None)))
    scope.create(root/scope.CURRENT,scope.encoded(dict(schema='walden.account.scope.current/1',contract=scope.fixed(config),
        receipt=str(receipt),receipt_sha256=hashlib.sha256(receipt.read_bytes()).hexdigest())))
    (root/'.writer.lock').touch(mode=0o600)
    profile=tmp_path/'profile.json';scope.create(profile,scope.encoded(config))
    home=tmp_path/'home';agents=home/'Library/LaunchAgents';agents.mkdir(parents=True,mode=0o700)
    monkeypatch.setattr(follow.pwd,'getpwuid',lambda uid:SimpleNamespace(pw_dir=str(home)))
    store=Store(tmp_path/'follow',create=True)
    with store.locked():pass
    generation='a'*32;instance='b'*32;nonce='c'*32
    snapshot=store.immutable('source.'+generation+'.json',config)
    old=dict(domain='kSMDomainUserLaunchd',uid=os.getuid(),security_session=12,session_attributes=8240)
    policy=dict(generation=generation,profile_path=str(profile),source_signature=digest(config),snapshot=str(snapshot),
        executable=str(Path(sys.executable).parent/'wechat-local-sync'),label='org.walden.native.follow.'+follow.profile_id(profile),
        store_root=str(store.root),environment={})
    policy.update(policy_path=str(store.path('policy.'+generation+'.json')),agent_path=str(agents/(policy['label']+'.plist')))
    store.immutable('policy.'+generation+'.json',policy);store.immutable('intent.json',dict(enabled=False,generation=generation))
    grant=dict(kind='active',nonce=nonce,store_root=str(store.root),instance_nonce=instance,policy_generation=generation,
        source_sha256=digest(config),os_context=old)
    gp=store.immutable('grant.'+nonce+'.json',grant);descriptor=dict(path=str(gp),sha256=digest(grant),label_id=follow.profile_id(profile)+'.'+instance)
    services=store.root/('workers.'+instance);services.mkdir(mode=0o700)
    label=schedule._schedule_label(config,descriptor)
    runtime=dict(operation=instance,store_root=str(store.root),policy_generation=generation,admission=False,binding_valid=True,
        context=old,leader=dict(pid=99999,pgid=99999,uid=os.getuid(),start=[1,2]),grant_nonce=nonce,services=str(services),
        segment=dict(kind='active',operation=None,submission='pending',record=str(services/(label+'.owned')),descriptor=descriptor),
        unsettled_activity=None,retirement_pending=None)
    store.immutable('instance.'+instance+'.json',runtime);store.immutable('current.json',dict(nonce=instance))
    s=Path(config['message_root']).stat();store.immutable('event-root.'+generation+'.json',dict(identity=[s.st_dev,s.st_ino]))
    class Run:
        context=old;mode='absent'
        def observe(self,target):return dict(target=target,state='absent') if self.mode=='absent' else None
        def pid(self,target):return None
    boot=['11111111-1111-1111-1111-111111111111'];monkeypatch.setattr(kernel,'boot_session',lambda:boot[0])
    return SimpleNamespace(profile=profile,store=store,config=config,generation=generation,runtime=runtime,grant=grant,
                           boot=boot,run=Run(),old_bytes=store.path('instance.'+instance+'.json').read_bytes())

def make(t):
    return legacy.plan(t.profile,expected_source_sha256=hashlib.sha256(t.profile.read_bytes()).hexdigest(),
        expected_policy_generation=t.generation,authorize=True,run=t.run,root=t.store.root)

def apply(t,p,**kw):
    return legacy.apply(t.profile,retirement_id=p['retirement_id'],plan_sha256=p['plan_sha256'],authorize=True,
                        run=t.run,root=t.store.root,**kw)

def test_same_boot_never_retires(item):
    t=item;p=make(t)
    with pytest.raises(MirrorError,match='legacy_retirement_unproven'):apply(t,p)
    assert follow._runtime(t.store)['segment']['operation'] is None
    assert make(t)==p

def test_cross_boot_keeps_unknown_and_old_grant_revoked_even_after_new_policy(item):
    t=item;p=make(t);t.boot[0]='22222222-2222-2222-2222-222222222222'
    assert apply(t,p)['disabled_confirmed']
    assert t.store.path('instance.'+t.runtime['operation']+'.json').read_bytes()==t.old_bytes
    current=follow._runtime(t.store);assert legacy.current_proof(t.store,current)
    with pytest.raises(MirrorError,match='follow_revoked'):grants.validate(t.grant)
    t.store.atomic('intent.json',dict(enabled=True,generation='d'*32))
    with pytest.raises(MirrorError,match='follow_revoked'):grants.validate(t.grant)
    before=t.store.path('current.json').read_bytes()
    assert apply(t,p)['current_state_not_rewritten']
    assert t.store.path('current.json').read_bytes()==before

@pytest.mark.parametrize('phase',['prepared','published'])
def test_actual_child_exit_at_persistent_boundary_then_resume(item,phase):
    t=item;p=make(t);t.boot[0]='22222222-2222-2222-2222-222222222222'
    pid=os.fork()
    if pid==0:
        apply(t,p,_checkpoint=lambda point:os._exit(73)if point==phase else None);os._exit(99)
    _,status=os.waitpid(pid,0);assert os.waitstatus_to_exitcode(status)==73
    assert not t.store.path('legacy-completed.'+t.generation+'.json').exists()
    assert apply(t,p)['disabled_confirmed']
    assert apply(t,p)['state']=='already_retired_no_republication'

@pytest.mark.parametrize('change',['profile','plan_inode','intent','writer_inode','root_inode','job_unknown','worker_receipt'])
def test_wrong_or_competing_facts_reject_preserving_old_pending(item,change):
    t=item;p=make(t);t.boot[0]='22222222-2222-2222-2222-222222222222'
    if change=='profile':t.profile.write_bytes(encoded(dict(t.config,query_timezone='UTC')))
    elif change=='plan_inode':
        path=t.store.path('legacy-plan.'+t.generation+'.json');raw=path.read_bytes();path.rename(path.with_suffix('.kept'));scope.create(path,raw)
    elif change=='intent':t.store.atomic('intent.json',dict(enabled=True,generation=t.generation))
    elif change=='writer_inode':
        path=Path(t.config['mirror_root'])/'.writer.lock';path.rename(path.with_suffix('.kept'));path.touch(mode=0o600)
    elif change=='root_inode':
        path=Path(t.config['mirror_root']);path.rename(path.with_name('mirror-kept'));path.mkdir(mode=0o700)
    elif change=='job_unknown':t.run.mode='unknown'
    elif change=='worker_receipt':scope.create(Path(t.runtime['segment']['record']),b'{}\n')
    with pytest.raises((MirrorError,OSError,ValueError)):apply(t,p)
    assert t.store.path('instance.'+t.runtime['operation']+'.json').read_bytes()==t.old_bytes
    assert not t.store.path('legacy-completed.'+t.generation+'.json').exists()

def test_postpublication_same_bytes_current_replacement_rejected(item):
    t=item;p=make(t);t.boot[0]='22222222-2222-2222-2222-222222222222'
    def changed(phase):
        if phase=='published':
            path=t.store.path('current.json');raw=path.read_bytes();path.rename(path.with_suffix('.kept'));scope.create(path,raw)
    with pytest.raises(MirrorError):apply(t,p,_checkpoint=changed)
    assert not t.store.path('legacy-completed.'+t.generation+'.json').exists()

def test_completed_current_same_bytes_unknown_inode_is_not_strict(item):
    t=item;p=make(t);t.boot[0]='22222222-2222-2222-2222-222222222222';apply(t,p)
    path=t.store.path('current.json');raw=path.read_bytes();path.rename(path.with_suffix('.kept'));scope.create(path,raw)
    with pytest.raises(MirrorError):legacy.current_proof(t.store,follow._runtime(t.store))

def test_busy_existing_writer_refuses_without_replacing_lock(item):
    import fcntl
    t=item;p=make(t);t.boot[0]='22222222-2222-2222-2222-222222222222'
    lock=Path(t.config['mirror_root'])/'.writer.lock';before=lock.stat().st_ino
    with lock.open('r+b') as fd:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with pytest.raises(MirrorError,match='sync_busy'):apply(t,p)
    assert lock.stat().st_ino==before and follow._runtime(t.store)==t.runtime

def test_boot_change_during_plan_never_returns_success(item,monkeypatch):
    t=item;values=iter(['11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222'])
    monkeypatch.setattr(kernel,'boot_session',lambda:next(values))
    with pytest.raises(MirrorError):make(t)
    assert follow._runtime(t.store)==t.runtime

def test_public_boot_api_fails_closed_without_valid_kernel_uuid(monkeypatch):
    from wechat_local.native_process import boot_session
    monkeypatch.setattr(kernel.subprocess,'run',lambda *a,**k:SimpleNamespace(returncode=0,stdout=b'not-a-boot-uuid'))
    with pytest.raises(MirrorError,match='follow_boot_generation_unknown'):boot_session()

def test_completed_live_proof_rejects_replaced_lock_while_old_fd_is_held(item):
    import fcntl
    t=item;p=make(t);t.boot[0]='22222222-2222-2222-2222-222222222222';apply(t,p)
    path=Path(t.config['mirror_root'])/'.writer.lock'
    with path.open('r+b')as fd:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        path.rename(path.with_suffix('.kept'));path.touch(mode=0o600)
        with pytest.raises(MirrorError):legacy.current_proof(t.store,follow._runtime(t.store))
        status=follow.status(t.profile,run=t.run,root=t.store.root)
        assert not status['disabled_confirmed'] and not status['activity_stop_confirmed']
    # Historical idempotency is not a current quiescence claim or a rewind.
    before=t.store.path('current.json').read_bytes()
    assert apply(t,p)['current_state_not_rewritten']
    assert t.store.path('current.json').read_bytes()==before

@pytest.mark.parametrize('observation',['present','unknown','pid','wrong_uid','wrong_session'])
def test_completed_live_proof_observes_original_exact_worker_and_context(item,observation):
    t=item;p=make(t);t.boot[0]='22222222-2222-2222-2222-222222222222';apply(t,p)
    label=schedule._schedule_label(t.config,t.runtime['segment']['descriptor']);queries=[]
    class After:
        context=(dict(t.run.context,uid=os.getuid()+1)if observation=='wrong_uid'else
                 dict(t.run.context,security_session=13)if observation=='wrong_session'else t.run.context)
        def observe(self,target):
            queries.append(target)
            if target.endswith('/'+label):
                return None if observation=='unknown'else dict(target=target,state='present'if observation=='present'else'absent')
            return dict(target=target,state='absent')
        def pid(self,target):return 123 if observation=='pid'and target.endswith('/'+label)else None
    if observation=='wrong_uid':
        with pytest.raises(MirrorError):follow.status(t.profile,run=After(),root=t.store.root)
        return
    status=follow.status(t.profile,run=After(),root=t.store.root)
    assert not status['disabled_confirmed'] and not status['activity_stop_confirmed']
    if observation not in ('wrong_uid','wrong_session'):assert any(x.endswith('/'+label)for x in queries)

def test_current_control_republication_by_normal_stop_remains_usable(item,monkeypatch):
    t=item;p=make(t);t.boot[0]='22222222-2222-2222-2222-222222222222';apply(t,p)
    # Only the OS identity collector is substituted; no guard returns success.
    monkeypatch.setattr(kernel,'identity',lambda pid:None)
    assert follow.disable(t.profile,run=t.run,root=t.store.root)['disabled_confirmed']
    assert follow.status(t.profile,run=t.run,root=t.store.root)['disabled_confirmed']
