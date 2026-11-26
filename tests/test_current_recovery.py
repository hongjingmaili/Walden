import hashlib,json,os
from pathlib import Path
from types import SimpleNamespace
import pytest
from wechat_local import native_follow as follow,native_follow_legacy as old,native_schedule as schedule
from wechat_local import native_follow_current_recovery as recovery
from wechat_local.native_mirror_store import MirrorError
from wechat_local.native_follow_policy import encoded,digest
from test_follow_legacy import item,make

@pytest.fixture
def incident(item,monkeypatch):
    t=item;p=make(t);g=t.generation;plan=t.store.path('legacy-plan.'+g+'.json');owner=t.store.path('legacy-owner.'+g+'.json')
    sh=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    fact=lambda p:[p.stat().st_dev,p.stat().st_ino]
    receipt=t.profile.parent/'preboot-receipt.json';value=dict(plan_id=g,plan_sha256=p['plan_sha256'],plan_path=str(plan),plan_path_identity=fact(plan),owner_path=str(owner),owner_path_identity=fact(owner),owner_path_sha256=sh(owner),profile_sha256=sh(t.profile),scope_sha256=json.loads(plan.read_text())['view']['scope_sha256'],boot_sha256=hashlib.sha256(t.boot[0].encode()).hexdigest())
    receipt.write_bytes(encoded(value));receipt.chmod(0o600)
    t.inputs=dict(expected_source_sha256=sh(t.profile),legacy_retirement_id=g,legacy_plan_sha256=p['plan_sha256'],legacy_owner_sha256=sh(owner),preboot_receipt=receipt,preboot_receipt_sha256=sh(receipt),authorize=True,run=t.run,root=t.store.root)
    t.boot[0]='22222222-2222-2222-2222-222222222222'
    rd=schedule._read
    def remounted(p):
        data,identity=rd(p);return data,[identity[0]+2,identity[1]]
    monkeypatch.setattr(schedule,'_read',remounted)
    with pytest.raises(MirrorError):old.apply(t.profile,retirement_id=g,plan_sha256=p['plan_sha256'],authorize=True,run=t.run,root=t.store.root)
    t.originals={str(x):x.read_bytes()for x in [plan,owner,t.store.path('instance.'+t.runtime['operation']+'.json'),t.store.path('event-root.'+g+'.json')]}
    return t

def prepare(t):return recovery.plan(t.profile,**t.inputs)
def recover(t,p,**extra):return recovery.apply(t.profile,witness_id=p['witness_id'],witness_fingerprint=p['witness_fingerprint'],authorize=True,run=t.run,root=t.store.root,**extra)

def test_current_witness_retires_without_rewriting_old_evidence(incident):
    t=incident;p=prepare(t);assert recover(t,p)['disabled_confirmed']
    assert all(Path(n).read_bytes()==data for n,data in t.originals.items())
    assert recovery.current_proof(t.store,follow._runtime(t.store),profile_path=t.profile)
    assert follow.status(t.profile,run=t.run,root=t.store.root)['disabled_confirmed']
    assert recover(t,p)['current_state_not_rewritten']

@pytest.mark.parametrize('point',['prepared','published'])
def test_real_persistent_exit_then_recover(incident,point):
    t=incident;p=prepare(t);pid=os.fork()
    if pid==0:
        recover(t,p,_checkpoint=lambda phase:os._exit(73)if phase==point else None);os._exit(99)
    _,status=os.waitpid(pid,0);assert os.waitstatus_to_exitcode(status)==73
    assert recover(t,p)['disabled_confirmed']
    assert recover(t,p)['current_state_not_rewritten']

@pytest.mark.parametrize('change',['account','writer_inode','job_unknown','sameboot','anchor_hash'])
def test_missing_or_competing_current_evidence_refuses(incident,change):
    t=incident
    if change=='account':
        v=json.loads(t.profile.read_text());v['account_id']='other';t.profile.write_bytes(encoded(v))
    elif change=='writer_inode':
        p=Path(t.config['mirror_root'])/'.writer.lock';p.rename(p.with_suffix('.retained'));p.touch(mode=0o600)
    elif change=='job_unknown':t.run.mode='unknown'
    elif change=='sameboot':t.boot[0]='11111111-1111-1111-1111-111111111111'
    elif change=='anchor_hash':t.inputs['legacy_owner_sha256']='0'*64
    with pytest.raises((MirrorError,OSError)):prepare(t)
    assert follow._runtime(t.store)==t.runtime


def test_competing_existing_writer_rejects_without_creating_lock(incident):
    import fcntl
    t=incident;lock=Path(t.config['mirror_root'])/'.writer.lock';before=lock.stat().st_ino
    with lock.open('r+b')as fd:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with pytest.raises(MirrorError,match='sync_busy'):prepare(t)
    assert lock.stat().st_ino==before


def test_wrong_current_volume_rejects_even_with_matching_content(incident,monkeypatch):
    from wechat_local import native_follow_identity as identity
    t=incident;ino=t.profile.stat().st_ino;volume=identity._volume
    monkeypatch.setattr(identity,'_volume',lambda fd:'00'*16 if os.fstat(fd).st_ino==ino else volume(fd))
    with pytest.raises(MirrorError):prepare(t)


def test_second_kernel_change_between_witness_and_apply_refuses(incident):
    t=incident;p=prepare(t);t.boot[0]='33333333-3333-3333-3333-333333333333'
    with pytest.raises(MirrorError):recover(t,p)
    assert follow._runtime(t.store)==t.runtime


def test_same_content_new_witness_object_cannot_be_adopted(incident):
    t=incident;p=prepare(t);path=t.store.path(recovery._name('ticket',t.generation));raw=path.read_bytes()
    path.rename(path.with_suffix('.kept'));path.write_bytes(raw);path.chmod(0o600)
    with pytest.raises(MirrorError):recover(t,p)


def test_after_publication_replaced_lock_remains_not_strict(incident):
    import fcntl
    t=incident;p=prepare(t);recover(t,p);lock=Path(t.config['mirror_root'])/'.writer.lock'
    with lock.open('r+b')as fd:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);lock.rename(lock.with_suffix('.kept'));lock.touch(mode=0o600)
        status=follow.status(t.profile,run=t.run,root=t.store.root)
        assert not status['disabled_confirmed']and not status['activity_stop_confirmed']


def test_after_publication_job_reappearance_refuses_current_strict(incident):
    t=incident;p=prepare(t);recover(t,p);t.run.mode='unknown'
    status=follow.status(t.profile,run=t.run,root=t.store.root)
    assert not status['disabled_confirmed']


def test_actual_old_grant_denied_and_historical_repeat_never_republishes(incident):
    from wechat_local import native_follow_grant as grants
    t=incident;p=prepare(t);recover(t,p)
    with pytest.raises(MirrorError,match='follow_revoked'):grants.validate(t.grant)
    # Component only: constructed later generation, not a claimed SDK policy renewal.
    t.store.atomic('intent.json',dict(enabled=True,generation='d'*32));t.store.atomic('current.json',dict(nonce='e'*32))
    before={str(x):x.read_bytes()for x in (t.store.path('intent.json'),t.store.path('current.json'))}
    assert recover(t,p)['current_state_not_rewritten']
    assert before=={n:Path(n).read_bytes()for n in before}
    with pytest.raises(MirrorError,match='follow_revoked'):grants.validate(t.grant)


def test_normal_stop_republication_not_forced_back_to_old_intent_inode(incident,monkeypatch):
    from wechat_local import native_process as kernel
    t=incident;p=prepare(t);recover(t,p);monkeypatch.setattr(kernel,'identity',lambda pid:None)
    assert follow.disable(t.profile,run=t.run,root=t.store.root)['disabled_confirmed']
    assert follow.status(t.profile,run=t.run,root=t.store.root)['disabled_confirmed']
