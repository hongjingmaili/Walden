"""Synthetic reproductions from the 0.8.5 real-sample scheduling investigation."""
from pathlib import Path
import time

import pytest
import test_account_sync_status as fixture
from test_account_sync_status import item
from wechat_local import native_mirror_sync as sync, native_scope_contract as scope


@pytest.mark.parametrize('item',[{'mirror_account_shards':4}],indirect=True)
def test_budget_exhaustion_does_not_skip_the_unopened_priority_shard(item,monkeypatch):
    fixture.seed_round_tables(item,first_max=2)
    for number in range(1,4):fixture.copy_synthetic_shard(item,f'message_{number}.db')
    hints={f'message_{number}.db':1 for number in range(4)}
    copy=sync._account_copy_table
    expired=False
    def copy_then_expire(*args,**kwargs):
        nonlocal expired
        result=copy(*args,**kwargs)
        if not expired:
            args[7]['until']=time.monotonic()-1
            expired=True
        return result
    monkeypatch.setattr(sync,'_account_copy_table',copy_then_expire)
    first=fixture.hinted_round(item,monkeypatch,shards=hints)
    assert not first['gaps'] and first['source_opens']==1
    with scope.registry(item['config']) as registry:
        assert scope.state(registry,'tail_shard_after')==fixture.fixture.SHARD
    second=fixture.hinted_round(item,monkeypatch,shards=hints)
    assert second['sources'][0]['shard']=='message_1.db'


@pytest.mark.parametrize('item',[{'mirror_account_shards':4}],indirect=True)
def test_all_fresh_shard_hints_use_available_source_slots_before_ordinary_discovery(item,monkeypatch):
    fixture.seed_round_tables(item,first_max=2)
    for number in range(1,5):fixture.copy_synthetic_shard(item,f'message_{number}.db')
    seen=[]
    probe=sync._account_tail_probe
    def probe_and_record(*args,**kwargs):
        seen.append(args[3].name)
        return probe(*args,**kwargs)
    monkeypatch.setattr(sync,'_account_tail_probe',probe_and_record)
    hinted={f'message_{number}.db':1 for number in (0,1,3,4)}
    result=fixture.hinted_round(item,monkeypatch,shards=hinted)
    assert not result['gaps'] and result['source_opens']==4
    assert set(seen)==set(hinted)
    with scope.registry(item['config']) as registry:
        assert scope.state(registry,'history_shard_after') is None
