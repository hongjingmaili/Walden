"""Fresh setup publication intersects real r4 account admission; external attestation only is synthetic."""
import json
from pathlib import Path
import sqlite3

import pytest

from test_first_install_onboarding import item, invoke, account_args, TABLE
from wechat_local import source_setup as setup, native_scope_contract as scope
from wechat_local import native_deadline as deadlines, native_follow_grant as grants
from wechat_local import native_mirror_sync as sync, native_account_witness as witness
from wechat_local.native_follow_policy import digest


def admitted_round(config,monkeypatch):
    # Unit boundary: the following separate installed-console harness exercises
    # actual listener/SDK-minted grants and real grant validation. Here only the
    # external attestation is replaced; the original registry/transaction guards
    # and the actual FollowDeadline are retained.
    monkeypatch.setattr(grants,'validate',lambda grant:None)
    deadline=grants.FollowDeadline(deadlines.Deadline.create(30).facts,
        dict(kind='active',source_sha256=digest(config)))
    with deadlines.activate_deadline(deadline):
        return sync.sync_once(config,[],capture_media=False)


def test_fresh_final_binding_enters_mandatory_admission_and_allows_legitimate_registry_growth(item,capsys,monkeypatch):
    assert invoke(item,capsys,account_args(item))[0]==0
    config=setup.load_source_config(item['profile']);root=Path(config['mirror_root'])
    with scope.registry(config) as db:
        assert db.execute('SELECT value FROM binding').fetchall()==[(json.dumps(scope.fixed(config),sort_keys=True),)]
        assert db.execute('SELECT count(*) FROM members').fetchone()==(0,)
        assert scope.state(db,'account_work') is None
    publication=item['profile'].with_name('.source.json.account-publication.json').read_bytes()
    actual=sync._account_registry_admit;calls=[]
    def checked(*args):
        result=actual(*args);calls.append(True);return result
    monkeypatch.setattr(sync,'_account_registry_admit',checked)
    value=admitted_round(config,monkeypatch)
    assert not value['gaps'] and value['rows_written']>0 and len(calls)>=2
    assert value['new_tail']['metadata_bytes']<=1048576 and value['rows_read']<=2000
    with scope.registry(config) as db:
        assert db.execute('SELECT count(*) FROM members').fetchone()==(1,)
    with sqlite3.connect(root/'message_0.db') as db:
        assert db.execute('SELECT count(*) FROM '+TABLE).fetchone()==(2,)
    # The initial publication certificate must not be reused as a current
    # registry-content witness after legitimate owned transactions have grown it.
    profile=item['profile'].read_bytes();count=item['service'].submits
    code,report=invoke(item,capsys,account_args(item))
    assert code==0 and report['initialization']['status']=='preserved_existing_copy'
    assert item['profile'].read_bytes()==profile and item['service'].submits==count
    assert item['profile'].with_name('.source.json.account-publication.json').read_bytes()==publication


@pytest.mark.parametrize('change',['binding','trigger'])
def test_fresh_setup_cannot_bypass_registry_reservation_guards_without_optional_coverage(item,capsys,monkeypatch,change):
    assert invoke(item,capsys,account_args(item))[0]==0
    config=setup.load_source_config(item['profile']);root=Path(config['mirror_root']);original=witness.AccountWitness.registry
    injected=[];opens=[];source_open=sync.open_encrypted_readonly
    def observed_open(*args,**kwargs):
        opens.append(True);return source_open(*args,**kwargs)
    def raced(owner,path,raw):
        assert not owner.registry_witness_enabled
        if not injected:
            injected.append(True)
            with sqlite3.connect(path) as foreign:
                if change=='binding':foreign.execute('UPDATE binding SET value=?',('{}',))
                else:foreign.execute('CREATE TRIGGER foreign_state AFTER INSERT ON state BEGIN SELECT 1; END')
        return original(owner,path,raw)
    monkeypatch.setattr(witness.AccountWitness,'registry',raced)
    monkeypatch.setattr(sync,'open_encrypted_readonly',observed_open)
    expected='scope_registry_binding' if change=='binding' else 'local_trigger_unsupported'
    with pytest.raises(sync.MirrorError,match=expected):admitted_round(config,monkeypatch)
    assert injected and not opens and not (root/'message_0.db').exists()
