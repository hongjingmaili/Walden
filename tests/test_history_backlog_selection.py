import json
import sqlite3
from pathlib import Path
import pytest
import test_account_sync_status as f
from test_account_sync_status import item

@pytest.mark.parametrize('item',[{'mirror_account_shards':4,'mirror_account_tables':1,'mirror_account_rows':1}],indirect=True)
@pytest.mark.parametrize('migration',[None,'legacy','stale_marker'])
def test_completed_sources_do_not_spend_the_only_history_opportunity_before_known_backlog(item,migration):
    tables=[f'Msg_{n:032x}' for n in range(85)]
    rows=[(1,1,1,1000,0,'synthetic',0)]
    f.seed_tables(item,[(name,1,1,rows) for name in tables])
    paths={f.fixture.SHARD:Path(item['local_path'])}
    for n in range(1,6):paths[f'message_{n}.db']=f.copy_synthetic_shard(item,f'message_{n}.db')
    for path in paths.values():
        with sqlite3.connect(path) as db:db.execute("INSERT OR REPLACE INTO __walden_progress VALUES('Name2Id','{}')")
    target=paths['message_5.db']
    with sqlite3.connect(target) as db:
        for name in tables:
            value=json.loads(db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(name,)).fetchone()[0])
            value.update(history=0,history_complete=False)
            db.execute('UPDATE __walden_progress SET value=? WHERE table_name=?',(json.dumps(value),name))
            db.execute('DELETE FROM "'+name+'"')
    from wechat_local import native_scope_contract as sc
    if migration:
        with sc.registry(item['config'],write=True) as registry:
            position=dict(shard='message_3.db',table=tables[40])
            sc.save(registry,'tail_debt_cursor',position)
            sc.save(registry,'round_number',10)
            sc.save(registry,'history_shard_after','message_3.db')
            if migration=='stale_marker':
                sc.save(registry,'history_backlog_scan',dict(started_from_beginning=True,complete=True,cursor=position,round_number=7))
            sc.save(registry,'history_backlog:'+f.fixture.SHARD,True)
            sc.save(registry,'history_backlog:message_5.db',False)
            registry.commit()
        partial=f.authorized_round(item)
        assert partial['new_tail']['known_debt_import_complete'] is True
        with sc.registry(item['config']) as registry:
            assert sc.state(registry,'history_backlog_scan')['complete'] is False
            assert sc.state(registry,'history_shard_after')=='message_3.db'
        with sqlite3.connect(target) as db:
            for table in tables:
                value=json.loads(db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(table,)).fetchone()[0])
                assert (value['H'],value['history'],value['tail'])==(1,0,1)
                assert db.execute('SELECT count(*) FROM "'+table+'"').fetchone()[0]==0
    results=[]
    for _ in range(3):
        value=f.authorized_round(item);results.append(value)
        assert not value['gaps'] and value['source_attempts']<=4 and value['source_opens']<=4
    assert results[-1]['new_tail']['known_debt_import_complete'] is True
    with sc.registry(item['config']) as registry:
        scan=sc.state(registry,'history_backlog_scan')
        assert scan['started_from_beginning'] is scan['complete'] is True
        assert scan['cursor']==dict(shard='',table='')
        assert scan['round_number']==sc.state(registry,'round_number')
        assert sc.state(registry,'history_backlog:'+f.fixture.SHARD) is False
        assert sc.state(registry,'history_backlog:message_5.db') is True
    assert any(row['shard']=='message_5.db' and row['history']>0 for row in results[-1]['sources'])
    with sqlite3.connect(target) as db:
        assert sum(db.execute('SELECT count(*) FROM "'+table+'" WHERE local_id<=1').fetchone()[0] for table in tables)==1


@pytest.mark.parametrize('item',[{'mirror_account_shards':1,'mirror_account_tables':1,'mirror_account_rows':1}],indirect=True)
def test_table_history_cursor_crosses_completed_prefix_to_debt_after_first_page(item):
    from wechat_local import native_scope_contract as sc
    names=[f'Msg_{n:032x}' for n in range(300)]
    rows=[(1,1,1,1000,0,'synthetic',0)]
    f.seed_tables(item,[(name,1 if n<299 else 0,1,rows) for n,name in enumerate(names)])
    for _ in range(2):assert not f.authorized_round(item)['gaps']
    with sc.registry(item['config']) as registry:
        assert sc.state(registry,'history_copy:'+f.fixture.SHARD)['after']==names[255]
    with sqlite3.connect(item['local_path']) as db:
        assert db.execute('SELECT count(*) FROM "'+names[-1]+'"').fetchone()[0]==0
    for _ in range(2):assert not f.authorized_round(item)['gaps']
    with sqlite3.connect(item['local_path']) as db:
        value=json.loads(db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(names[-1],)).fetchone()[0])
        assert value['history']==1 and db.execute('SELECT count(*) FROM "'+names[-1]+'"').fetchone()[0]==1
