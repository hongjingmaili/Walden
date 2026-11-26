import json,sqlite3
from pathlib import Path
import pytest
import test_account_sync_status as f
from test_account_sync_status import item

@pytest.mark.parametrize('item',[{'mirror_account_shards':4,'mirror_account_rows':1,'mirror_account_tables':1}],indirect=True)
@pytest.mark.parametrize('hints',['none','fixed'])
def test_quiet_historical_sources_each_receive_completed_import_opportunity(item,monkeypatch,hints):
    rows=[(1,1,1,1000,0,'synthetic',0)]
    f.seed_tables(item,[(f'Msg_{n:032x}',0,1,rows) for n in range(85)])
    targets={f.fixture.SHARD:Path(item['local_path'])}
    for n in range(1,6):targets[f'message_{n}.db']=f.copy_synthetic_shard(item,f'message_{n}.db')
    # Existing empty sender progress is a normal stable importer input. Its
    # contract is {} and it counts against the same import page as production.
    for path in targets.values():
        with sqlite3.connect(path) as db:db.execute("INSERT OR REPLACE INTO __walden_progress VALUES('Name2Id','{}')")
    observations=[]
    for number in range(18):
        result=(f.authorized_round(item) if hints=='none' else f.hinted_round(item,monkeypatch,shards={name:1 for name in targets}))
        assert not result['gaps'] and result['new_tail']['remaining_known_debt_shards']==0
        assert result['source_opens']<=4
        observations.append(dict(round=number,known_complete=result['new_tail']['known_debt_import_complete'],
            probe_complete=result['new_tail']['probe_complete'],copied=[s['shard'] for s in result['sources']]))
    history={}
    for shard,path in targets.items():
        with sqlite3.connect(path) as db:
            history[shard]=sum(json.loads(raw).get('history',0) for raw, in db.execute('SELECT value FROM __walden_progress'))
    print(json.dumps(dict(message_tables_per_shard=85,source_count=6,hints=hints,no_tail=True,
                         observations=observations,history_rows_by_shard=history)))
    assert all(value>0 for value in history.values())
    if hints=='fixed':
        from wechat_local import native_scope_contract as sc
        with sc.registry(item['config']) as registry:
            assert all(sc.state(registry,'tail_hints')['shards'].get(name)==1 for name in targets)


@pytest.mark.parametrize('item',[{'mirror_account_shards':4}],indirect=True)
def test_deferred_history_source_does_not_advance_its_opportunity_cursor(item,monkeypatch):
    import time
    from wechat_local import native_mirror_sync as sync,native_scope_contract as sc
    f.seed_round_tables(item,first_max=1)
    f.copy_synthetic_shard(item,'message_1.db')
    probe=sync._account_tail_probe
    def probe_then_expire(*args,**kwargs):
        state=probe(*args,**kwargs)
        args[6]['until']=time.monotonic()-1
        return state
    monkeypatch.setattr(sync,'_account_tail_probe',probe_then_expire)
    result=f.authorized_round(item)
    assert not result['gaps'] and result['source_attempts']==1
    with sc.registry(item['config']) as registry:
        assert sc.state(registry,'history_shard_after') is None
