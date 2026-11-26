"""Only direct restore helpers and unchanged ordinary scope fences."""
import hashlib
import json
import sqlite3
import pytest
from wechat_local import native_scope_contract as sc
from wechat_local import native_shard_restore as restore
from wechat_local.native_mirror_store import MirrorError,MirrorStore
from wechat_local.source_records import SourceKey
from test_registry_reuse import item


def test_normal_token_keeps_current_proof(item):
    config,_,_=item
    assert sc.token(config)==sc._account_current_proof(config)


def test_source_and_alias_outputs_refuse_without_creation(item):
    config,profile,root=item
    source=profile.parent.parent/'source'
    alias=profile.parent.parent/'source-alias'
    alias.symlink_to(source,target_is_directory=True)
    for path in (source/'maintenance-plan.json',alias/'maintenance-plan.json'):
        with pytest.raises(MirrorError,match='shard_restore_source_overlap'):
            restore._layout(config,output=path)
        assert not path.exists()


def test_protected_reference_is_not_a_replacement(item):
    config,profile,root=item
    reference=profile.parent/'private-reference';reference.touch(mode=0o600)
    config=dict(config,passphrase_file=str(reference))
    with pytest.raises(MirrorError,match='shard_restore_protected_path'):
        restore._layout(config,replacement=reference)


def test_private_plan_and_stage_are_disjoint(item):
    config,profile,root=item
    restore._layout(config,output=profile.parent/'restore-plan.json',replacement=profile.parent/'equivalent.db',state_root=root/'.shard-restore-fixture')


def test_stage_directory_identity_is_not_relearned(tmp_path):
    stage=tmp_path/'stage';stage.mkdir(mode=0o700)
    expected=restore.files._directory_info(stage)
    stage.rename(tmp_path/'original-stage');stage.mkdir(mode=0o700)
    with pytest.raises(MirrorError,match='shard_restore_stage_changed'):
        restore._stage(stage,expected)


@pytest.mark.parametrize('name',['.account-scope.pending','.scope-add.pending'])
def test_old_pending_fences_remain_unconditional(item,name):
    config,_,root=item
    sc.create(root/name,sc.encoded(dict(schema=restore.FORMAT,owner='single_local_shard')))
    for fn in (lambda:sc.token(config),lambda:sc.loaded_scope_guard('unused',config)):
        with pytest.raises(MirrorError,match='scope_mode_pending'):fn()


def test_summary_covers_rows_schema_sequence_and_observed(tmp_path):
    root=tmp_path.resolve();table='Msg_'+'1'*32
    key=SourceKey('synthetic-account','synthetic-generation','message_0.db',table)
    old=root/'old.db';new=root/'new.db';store=MirrorStore(old,key)
    ddl='CREATE TABLE '+table+'(local_id INTEGER PRIMARY KEY AUTOINCREMENT,server_id INTEGER,local_type INTEGER,create_time INTEGER,real_sender_id INTEGER,message_content TEXT,WCDB_CT_message_content INTEGER)'
    store.ensure_table(key,ddl)
    with sqlite3.connect(old)as db:db.execute('CREATE INDEX synthetic_time ON '+table+'(create_time)')
    pg=dict(H=2,history=2,tail=2)
    store.apply_batch(key,table,[(1,1,11,1,1700000001,1,'synthetic-one',0),(2,2,12,1,1700000002,1,'synthetic-two',0)],pg)
    with sqlite3.connect(old)as a,sqlite3.connect(new)as b:a.backup(b)
    new.chmod(0o600)
    a=restore._summary(old);b=restore._summary(new,require_integrity=True)
    assert a==b and a['tables'][table]['rows']==2
    assert '__walden_progress' in a['tables'] and '__walden_observed' in a['tables'] and 'sqlite_sequence' in a['tables']
