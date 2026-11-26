"""Local storage conversion; synthetic metadata only, no OS/Source stubs."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import pytest
from wechat_local import native_scope_contract as sc
from wechat_local import native_registry_reuse as reuse
from wechat_local import native_registry_migrate as migration
from wechat_local.native_follow_policy import digest
from wechat_local.native_mirror_store import MirrorError

TABLE='Msg_'+'1'*32
SCHEMA='a'*64

@pytest.fixture
def item(tmp_path,monkeypatch):
    root=tmp_path.resolve();monkeypatch.setenv('XDG_STATE_HOME',str(root/'state'))
    private=root/'private';private.mkdir(mode=0o700)
    mirror=root/'mirror';mirror.mkdir(mode=0o700)
    source=root/'source';source.mkdir(mode=0o700)
    config=dict(mirror_scope_mode='account',scope_contract_id='1'*32,account_id='synthetic-account',source_generation='synthetic-generation',
                mirror_root=str(mirror),live_db_root=str(source),message_root=str(source))
    profile=private/'source.json';sc.create(profile,sc.encoded(config))
    with sc.registry(config,write=True,initialize=True) as db:
        for n in range(5):
            observation=dict(contract=sc.fixed(config),shard='message_0.db',source_identity=[1,2],header='b'*64,
                             query_only=True,at_ns=n,schema_cookie=1,tables=[[TABLE,SCHEMA],[TABLE,SCHEMA]],
                             tables_ref='unknown old field retained',legacy_extra={'order':[3,2,1]})
            sc._register_members(config,db,observation,[dict(table=TABLE,schema_sha256=SCHEMA,username='synthetic-peer',supported=True,available=True)])
        db.commit()
    sc.create(mirror/'.writer.lock',b'')
    receipt=dict(state='committed',contract=sc.fixed(config),new_config_sha256=sc.digest(config),legacy_current_sha256=None)
    sc.create(mirror/'receipt.json',sc.encoded(receipt))
    sc.create(mirror/sc.CURRENT,sc.encoded(dict(schema='walden.account.scope.current/1',contract=sc.fixed(config),receipt=str(mirror/'receipt.json'),receipt_sha256=sc.sha(sc.encoded(receipt)))))
    return config,profile,mirror

def convert(item,**kwargs):
    config,profile,_=item
    return migration.migrate(config,profile,confirmed=True,expected_source_sha256=digest(config),**kwargs)

def test_conversion_preserves_old_authority_and_current_proof(item):
    config,_,root=item;old=migration.file_hash(root/sc.REGISTRY)
    with sc.registry(config) as db:before=sc.member(config,db,'message_0.db',TABLE)
    result=convert(item)
    assert result['observations']==5 and result['current_observations']==1 and result['lists']==1
    storage=root/('__walden_registry_'+result['generation'])
    assert migration.file_hash(storage/'old.db')==old
    assert not (root/migration.PENDING).exists()
    with sc.registry(config) as db:
        assert sc.member(config,db,'message_0.db',TABLE)==before
        assert reuse.seen(config,db,'message_0.db',TABLE) is True
        assert reuse.binding(db)!=sc.fixed(config)  # Old 091 exact binding gate.
    assert convert(item)['status']=='preserved_existing_registry'

def test_missing_confirmation_has_no_side_effect(item):
    config,profile,root=item;names=set(root.iterdir());old=migration.file_hash(root/sc.REGISTRY)
    result=migration.migrate(config,profile)
    assert result['status']=='confirmation_required' and set(root.iterdir())==names
    assert migration.file_hash(root/sc.REGISTRY)==old

@pytest.mark.parametrize('point',['prepared','built','auxiliary_published','exchanged','old_preserved','receipt'])
def test_publication_interruption_resumes_same_generation(item,point):
    def stop(name):
        if name==point:raise KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):convert(item,_checkpoint=stop)
    config,_,root=item
    with pytest.raises(MirrorError,match='registry_migration_pending'):
        with sc.registry(config):pass
    result=convert(item)
    assert result['status']=='registry_reused'
    with sc.registry(config) as db:assert sc.member(config,db,'message_0.db',TABLE)['supported'] is True

def test_main_and_archive_rollback_together(item):
    config,_,_=item;convert(item)
    with sc.registry(config,write=True) as db:
        old_counts=sc.state(db,'history_counts')
        observation=dict(contract=sc.fixed(config),shard='message_0.db',source_identity=[1,2],header='b'*64,
                         query_only=True,at_ns=999,tables=[[TABLE,SCHEMA]])
        oid=reuse.store(config,db,observation)
        db.rollback()
        assert sc.state(db,'history_counts')==old_counts
        assert db.execute('SELECT 1 FROM observations WHERE id=?',(oid,)).fetchone() is None
        alias,_,_=reuse.attached(config,db,int(oid[0],16)%reuse.BUCKETS,write=True)
        assert db.execute('SELECT 1 FROM '+alias+'.records WHERE id=?',(oid,)).fetchone() is None

def test_historical_index_loss_does_not_become_first_seen(item):
    config,_,_=item;convert(item)
    with sc.registry(config,write=True) as db:
        db.execute('DELETE FROM history_members');db.commit()
    with sc.registry(config) as db:
        with pytest.raises(MirrorError,match='registry_reuse_history_invalid'):reuse.seen(config,db,'message_0.db',TABLE)

def test_archive_replacement_is_rejected_before_commit(item):
    import shutil
    config,_,root=item;convert(item)
    with sc.registry(config,write=True) as db:
        alias,path,_=reuse.attached(config,db,0,write=True)
        path.rename(path.with_suffix('.preserved'))
        shutil.copyfile(path.with_suffix('.preserved'),path);path.chmod(0o600)
        with pytest.raises(MirrorError,match='registry_reuse_archive_changed'):reuse.commit(config,db)

def test_shared_read_budget_is_not_reset_for_next_object(item):
    config,_,root=item;convert(item)
    with sc.registry(config) as db:
        budget=reuse._reading.get();budget.bytes=16*1024*1024
        with pytest.raises(MirrorError,match='registry_reuse_read_budget'):sc.member(config,db,'message_0.db',TABLE)

def test_partial_build_uses_one_new_owned_attempt_without_deleting_old(item,monkeypatch):
    original=reuse._immutable;fired=[]
    def stop(path,raw):
        result=original(path,raw)
        if path.parent.name=='lists' and not fired:
            fired.append(path);raise KeyboardInterrupt()
        return result
    monkeypatch.setattr(reuse,'_immutable',stop)
    with pytest.raises(KeyboardInterrupt):convert(item)
    old_artifact=fired[0];old_hash=migration.file_hash(old_artifact)
    monkeypatch.setattr(reuse,'_immutable',original)
    result=convert(item)
    assert result['status']=='registry_reused'
    assert old_artifact.exists() and migration.file_hash(old_artifact)==old_hash
    assert len(list(item[2].glob('.registry-reuse-stage-*')))==1
    assert not (item[2]/migration.RETRY).exists()

def test_same_bytes_new_inode_stage_file_is_not_adopted(item):
    import shutil
    def stop(name):
        if name=='built':raise KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):convert(item,_checkpoint=stop)
    config,_,root=item
    stage=next(root.glob('.registry-reuse-stage-*'));path=stage/'0.db'
    path.rename(stage/'foreign-preserved.db');shutil.copyfile(stage/'foreign-preserved.db',path);path.chmod(0o600)
    with pytest.raises(MirrorError,match='registry_migration_stage_changed'):convert(item)
    assert (root/migration.PENDING).exists()

def test_archive_records_cannot_be_updated_deleted_or_replaced(item):
    _,_,root=item;result=convert(item);folder=root/('__walden_registry_'+result['generation'])
    for path in folder.glob('[0-7].db'):
        with sqlite3.connect(path) as db:
            row=db.execute('SELECT id,proof FROM records LIMIT 1').fetchone()
            if row is None:continue
            for sql,args in [('UPDATE records SET proof=proof WHERE id=?',(row[0],)),('DELETE FROM records WHERE id=?',(row[0],)),('INSERT OR REPLACE INTO records VALUES(?,?)',row)]:
                with pytest.raises(sqlite3.IntegrityError,match='history_immutable'):db.execute(sql,args)

def test_metadata_budget_refuses_before_creating_list_object(item):
    import time
    from wechat_local.native_account_witness import WorkBudgetStop
    config,_,root=item;convert(item)
    observation=dict(contract=sc.fixed(config),shard='message_0.db',source_identity=[1,2],header='b'*64,
                     query_only=True,at_ns=10,tables=[['Msg_'+'2'*32,SCHEMA]])
    before={str(p.relative_to(root)) for p in root.rglob('*')}
    with sc.registry(config,write=True) as db:
        budget=dict(until=time.monotonic()+20,tail_probe=dict(bytes=1048500,ceiling=1048576))
        with pytest.raises(WorkBudgetStop):reuse.store(config,db,observation,budget=budget)
    assert {str(p.relative_to(root)) for p in root.rglob('*')}==before


@pytest.mark.parametrize('endpoint',[sc.selection,sc.authorized])
def test_username_checks_reuse_only_one_transaction_observation(item,monkeypatch,endpoint):
    config,_,_=item
    other='Msg_'+'2'*32
    observation=dict(contract=sc.fixed(config),shard='message_0.db',source_identity=[1,2],header='b'*64,query_only=True,at_ns=20,tables=[[TABLE,SCHEMA],[other,SCHEMA]])
    with sc.registry(config,write=True) as db:
        sc._register_members(config,db,observation,[dict(table=t,schema_sha256=SCHEMA,username='synthetic-peer',supported=True,available=True) for t in (TABLE,other)])
        db.commit()
    convert(item)
    original=reuse._read;reads=[]
    def read(path):
        if path.parent.name=='lists':reads.append(path)
        return original(path)
    monkeypatch.setattr(reuse,'_read',read)
    for call in range(2):
        with pytest.raises(MirrorError,match='scope_not_authorized'):endpoint(config,username='synthetic-unregistered')
        assert len(reads)==call+1  # Shared within call, freshly verified next call.


def test_recovery_does_not_adopt_same_byte_foreign_old_backup(item):
    import shutil
    def stop(point):
        if point=='exchanged':raise KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):convert(item,_checkpoint=stop)
    root=item[2];published=next(root.glob('__walden_registry_*'))
    original=published/'main.db';foreign=published/'old.db';shutil.copyfile(original,foreign);foreign.chmod(0o600)
    expected=original.stat().st_ino;actual=foreign.stat().st_ino
    with pytest.raises(MirrorError,match='registry_migration_publication_unknown'):convert(item)
    assert original.stat().st_ino==expected and foreign.stat().st_ino==actual
    assert (root/migration.PENDING).exists()


def test_actual_profile_change_before_swap_is_not_confirmed(item):
    config,profile,root=item;original=migration.file_hash(root/sc.REGISTRY)
    def change(point):
        if point=='built':profile.write_bytes(sc.encoded(dict(config,query_timezone='Europe/London')))
    with pytest.raises(MirrorError,match='registry_migration_profile_changed'):convert(item,_checkpoint=change)
    assert migration.file_hash(root/sc.REGISTRY)==original
    assert (root/migration.PENDING).exists()


def test_migration_rejects_original_member_contradiction_before_publication(item):
    config,_,root=item
    with sc.registry(config,write=True) as db:
        proof=json.loads(db.execute('SELECT proof FROM members').fetchone()[0]);proof['ref']='0'*64
        db.execute('UPDATE members SET proof=?',(json.dumps(proof,sort_keys=True),));db.commit()
    original=migration.file_hash(root/sc.REGISTRY)
    with pytest.raises(MirrorError,match='scope_member_proof'):convert(item)
    assert migration.file_hash(root/sc.REGISTRY)==original
    assert (root/migration.PENDING).exists()
    assert not list(root.glob('__walden_registry_*'))


@pytest.mark.parametrize('point',['auxiliary_published','exchanged','receipt'])
def test_published_new_main_cannot_be_replaced_by_same_bytes(item,point):
    import shutil
    config,_,root=item;original=migration.file_hash(root/sc.REGISTRY)
    def replace(name):
        if name!=point:return
        folder=next(root.glob('__walden_registry_*'))
        path=folder/'main.db' if name=='auxiliary_published' else root/sc.REGISTRY
        saved=root/'original-new-main.preserved';path.rename(saved);shutil.copyfile(saved,path);path.chmod(0o600)
    with pytest.raises(MirrorError,match='registry_migration_(stage_changed|publication_unknown)'):convert(item,_checkpoint=replace)
    assert (root/migration.PENDING).exists()
    assert (root/'original-new-main.preserved').exists()
    if point=='auxiliary_published':assert migration.file_hash(root/sc.REGISTRY)==original


def test_recovery_requires_exact_sealed_canonical_new_inode(item):
    import shutil
    def stop(point):
        if point=='exchanged':raise KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):convert(item,_checkpoint=stop)
    root=item[2];path=root/sc.REGISTRY;preserved=root/'owned-new-main.preserved'
    path.rename(preserved);shutil.copyfile(preserved,path);path.chmod(0o600)
    with pytest.raises(MirrorError,match='registry_migration_publication_unknown'):convert(item)
    assert (root/migration.PENDING).exists() and preserved.exists()


def test_read_budget_window_relaxed_and_enforces_time_bytes_and_deadline(item, monkeypatch):
    from wechat_local.native_deadline import Deadline, _current

    config, _, _ = item
    convert(item)
    assert reuse.READ_SECONDS >= 10.0

    clock = [1000.0]
    monkeypatch.setattr(reuse.time, 'monotonic', lambda: clock[0])

    with sc.registry(config) as db:
        budget = reuse._reading.get()
        assert budget.until == pytest.approx(1000.0 + reuse.READ_SECONDS)

        # Exceeding old 2s cap (e.g. 3.5s scan under concurrent sync) succeeds.
        clock[0] = 1003.5
        assert sc.member(config, db, 'message_0.db', TABLE)['supported'] is True

        # Active tighter deadline is still enforced via check_deadline().
        expired_deadline = Deadline(
            dict(wall_until=100.0, continuous_start=1, continuous_until=2_000_000_000),
            wall=lambda: 200.0,
            continuous=lambda: 3_000_000_000,
        )
        token = _current.set(expired_deadline)
        try:
            with pytest.raises(MirrorError, match='schedule_deadline_expired'):
                budget.check()
        finally:
            _current.reset(token)

        # Exceeding relaxed READ_SECONDS still raises registry_reuse_read_budget.
        clock[0] = 1000.0 + reuse.READ_SECONDS + 0.1
        with pytest.raises(MirrorError, match='registry_reuse_read_budget'):
            sc.member(config, db, 'message_0.db', TABLE)

        # Byte cap (16 MiB) still enforced even when within time budget.
        clock[0] = 1001.0
        budget.bytes = 16 * 1024 * 1024
        with pytest.raises(MirrorError, match='registry_reuse_read_budget'):
            budget.take(1)
