from pathlib import Path
from types import SimpleNamespace
import pytest
from wechat_local.native_follow_events import VnodeHints
from wechat_local.native_mirror_store import MirrorError


def watcher(root):
    class Queue:
        batches=[]
        def control(self,changes,_limit,_timeout):
            if changes is not None:return []
            return self.batches.pop(0) if self.batches else []
        def close(self):pass
    queue=Queue();backend=SimpleNamespace(kqueue=lambda:queue,kevent=lambda ident,**kw:SimpleNamespace(ident=ident,**kw),
        KQ_FILTER_VNODE=1,KQ_EV_ADD=2,KQ_EV_ENABLE=4,KQ_EV_CLEAR=8,KQ_NOTE_WRITE=16,KQ_NOTE_DELETE=32,KQ_NOTE_RENAME=64,
        KQ_NOTE_ATTRIB=128,KQ_NOTE_EXTEND=256,KQ_NOTE_REVOKE=512,KQ_EV_ERROR=1024)
    return VnodeHints(root,backend=backend,clock=lambda:0),queue


def event(watch,path,*,fflags=16,flags=0):
    fd=next(fd for fd,(label,_) in watch.fds.items() if label==path)
    return SimpleNamespace(ident=fd,fflags=fflags,flags=flags)


@pytest.fixture
def watched(tmp_path):
    for name in ('message_7.db','message_7.db-shm'):(tmp_path/name).touch()
    watch,queue=watcher(tmp_path)
    yield tmp_path,watch,queue
    watch.close()


def test_shm_only_remains_dirty_fallback_without_fresh_numeric_priority(watched):
    root,watch,queue=watched
    queue.batches=[[event(watch,root/'message_7.db-shm')],[]]
    assert watch.wait(0)==2 and watch.fallback_generation==2 and watch.shard_generations=={}


def test_shm_cannot_refresh_or_discard_an_unconsumed_real_db_hint(watched):
    root,watch,queue=watched
    queue.batches=[[event(watch,root/'message_7.db')],[]];watch.wait(0)
    assert watch.shard_generations=={'message_7.db':2}
    queue.batches=[[event(watch,root/'message_7.db-shm')],[]];watch.wait(0)
    assert watch.shard_generations=={'message_7.db':2} and watch.fallback_generation==3


def test_missing_wal_created_after_initial_watch_is_numeric_priority(watched):
    root,watch,queue=watched
    (root/'message_7.db-wal').touch();queue.batches=[[event(watch,root)],[]];watch.wait(0)
    assert watch.shard_generations=={'message_7.db':2} and watch.fallback_generation==2
    assert any(path==root/'message_7.db-wal' for path,_ in watch.fds.values())


def test_replaced_wal_is_detected_even_when_only_directory_event_arrives(watched):
    root,watch,queue=watched;wal=root/'message_7.db-wal';wal.touch()
    queue.batches=[[event(watch,root)],[]];watch.wait(0)
    wal.unlink();wal.write_bytes(b'synthetic new inode')
    queue.batches=[[event(watch,root)],[]];watch.wait(0)
    assert watch.shard_generations=={'message_7.db':3}


def test_unchanged_fd_keeps_pending_real_event_across_shm_refresh(watched):
    root,watch,queue=watched;original=event(watch,root/'message_7.db')
    queue.batches=[[event(watch,root/'message_7.db-shm')],[]];watch.wait(0)
    assert original.ident in watch.fds
    queue.batches=[[original],[]];watch.wait(0)
    assert watch.shard_generations=={'message_7.db':3}


def test_new_shm_file_does_not_become_numeric_priority(watched):
    root,watch,queue=watched;(root/'message_8.db-shm').touch();queue.batches=[[event(watch,root)],[]];watch.wait(0)
    assert watch.shard_generations=={} and watch.fallback_generation==2


@pytest.mark.parametrize('kind',['revoke','error','unknown','overflow'])
def test_shm_classification_keeps_failclosed_and_unknown_fallback(watched,kind):
    root,watch,queue=watched
    value=event(watch,root/'message_7.db-shm',fflags=512 if kind=='revoke' else 16,flags=1024 if kind=='error' else 0)
    if kind=='unknown':value=SimpleNamespace(ident=99999,fflags=16,flags=0)
    queue.batches=[[value]*256 if kind=='overflow' else [value],[]]
    if kind in ('revoke','error'):
        with pytest.raises(MirrorError):watch.wait(0)
        assert watch.conflict
    else:
        watch.wait(0);assert watch.fallback_generation==2 and watch.shard_generations=={}


def test_directory_subscription_survives_wal_creation_during_refresh(watched,monkeypatch):
    from wechat_local import native_follow_events as module
    root,watch,queue=watched;root_event=event(watch,root);listdir=module.os.listdir;created=[False]
    def arriving(fd):
        result=listdir(fd)
        if not created[0]:
            created[0]=True;(root/'message_7.db-wal').touch()
        return result
    monkeypatch.setattr(module.os,'listdir',arriving)
    queue.batches=[[event(watch,root/'message_7.db-shm')],[]];watch.wait(0)
    # The retained directory watch still delivers the event queued while the
    # new descriptor inventory was being built. No pathname or Source open.
    assert root_event.ident in watch.fds
    queue.batches=[[root_event],[]];watch.wait(0)
    assert watch.shard_generations=={'message_7.db':3}


import json,sqlite3
import test_account_sync_status as f
from test_account_sync_status import item
from wechat_local import native_mirror_sync as sync,native_scope_contract as sc


def setup_sources(item):
    table='Msg_'+format(1,'032x');rows=[(1,1,1,1000,0,'synthetic',0)]
    f.seed_tables(item,[(table,1,1,rows)]);paths={f.fixture.SHARD:Path(item['local_path'])}
    for n in range(1,9):paths[f'message_{n}.db']=f.copy_synthetic_shard(item,f'message_{n}.db')
    target=paths['message_8.db']
    with sqlite3.connect(target) as db:
        value=json.loads(db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(table,)).fetchone()[0]);value.update(history=0,history_complete=False)
        db.execute('UPDATE __walden_progress SET value=? WHERE table_name=?',(json.dumps(value),table));db.execute('DELETE FROM "'+table+'"')
    return table,target


def configured_round(item,monkeypatch,watch,opened):
    def run(fx):
        def factory(path):
            opened.append(path.name);db=sqlite3.connect(fx['source_db']);db.execute('PRAGMA query_only=ON');return db
        return sync._account_sync(fx['config'],connection_factory=factory)
    monkeypatch.setattr(f.fixture,'run_full_account_sync',run)
    monkeypatch.setattr(sync,'_account_tail_hints',lambda config,grant:(dict(watch.shard_generations),bool(watch.fallback_generation)))
    return f.authorized_round(item)


@pytest.mark.parametrize('item',[{'mirror_account_shards':4}],indirect=True)
def test_repeated_eight_shm_sources_do_not_starve_unhinted_known_history(item,monkeypatch):
    table,target=setup_sources(item);root=Path(item['message_root'])
    for n in range(8):(root/f'message_{n}.db-shm').touch()
    watch,queue=watcher(root);opened=[];history=0
    try:
        for _ in range(12):
            queue.batches=[[event(watch,root/f'message_{n}.db-shm') for n in range(8)],[]];watch.wait(0)
            result=configured_round(item,monkeypatch,watch,opened)
            assert not result['gaps'] and result['source_attempts']<=4 and result['source_opens']<=4
            with sqlite3.connect(target) as db:history=json.loads(db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(table,)).fetchone()[0])['history']
            if history:break
        assert history==1
        assert 'message_8.db' in opened
    finally:watch.close()


@pytest.mark.parametrize('item',[{'mirror_account_shards':4}],indirect=True)
def test_four_real_data_sources_keep_new_tail_before_history_without_extra_opens(item,monkeypatch):
    table,target=setup_sources(item);root=Path(item['message_root']);watch,queue=watcher(root);opened=[]
    try:
        for local_id in range(2,5):
            with sqlite3.connect(item['source_db']) as db:db.execute('INSERT INTO "'+table+'" VALUES(?,?,?,?,?,?,?)',(local_id,1,1,1000,0,'synthetic new tail',0))
            queue.batches=[[event(watch,root/f'message_{n}.db') for n in range(4)],[]];watch.wait(0)
            before=len(opened);result=configured_round(item,monkeypatch,watch,opened)
            assert not result['gaps'] and result['source_attempts']<=4 and result['source_opens']<=4
            assert 'message_8.db' not in opened[before:]
            assert len(result['sources'])==4 and result['rows_read']==4
            assert all(row['tail']==local_id for row in result['sources'])
            with sqlite3.connect(target) as db:assert json.loads(db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(table,)).fetchone()[0])['history']==0
    finally:watch.close()


@pytest.mark.parametrize('item',[{'mirror_account_shards':4}],indirect=True)
def test_known_unhinted_tail_debt_still_precedes_history_under_shm_fallback(item,monkeypatch):
    table,target=setup_sources(item);root=Path(item['message_root']);(root/'message_0.db-shm').touch()
    with sqlite3.connect(item['source_db']) as db:db.execute('INSERT INTO "'+table+'" VALUES(?,?,?,?,?,?,?)',(2,1,1,1000,0,'synthetic known tail',0))
    with sqlite3.connect(item['local_path']) as db:
        progress=json.loads(db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(table,)).fetchone()[0]);progress['target']=2
        db.execute('UPDATE __walden_progress SET value=? WHERE table_name=?',(json.dumps(progress),table))
    watch,queue=watcher(root);opened=[]
    try:
        queue.batches=[[event(watch,root/'message_0.db-shm')],[]];watch.wait(0)
        assert not watch.shard_generations and watch.fallback_generation
        result=configured_round(item,monkeypatch,watch,opened)
        assert not result['gaps'] and result['new_tail']['known_debt_shards']==1
        assert opened[0]=='message_0.db' and result['sources'][0]['tail']==2
        assert result['source_attempts']<=4 and result['source_opens']<=4
        with sqlite3.connect(target) as db:assert json.loads(db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(table,)).fetchone()[0])['history']==0
    finally:watch.close()


def test_root_replacement_remains_failclosed(watched):
    root,watch,queue=watched;signal=event(watch,root);moved=root.with_name(root.name+'-retired');root.rename(moved);root.mkdir()
    queue.batches=[[signal],[]]
    with pytest.raises(MirrorError):watch.wait(0)
    assert watch.conflict


def test_repeated_soft_refresh_retains_subscriptions_without_fd_growth(watched):
    import os
    root,watch,queue=watched;original=set(watch.fds);baseline=len(os.listdir('/dev/fd'))
    for _ in range(20):
        queue.batches=[[event(watch,root/'message_7.db-shm')],[]];watch.wait(0)
        assert set(watch.fds)==original
    assert len(os.listdir('/dev/fd'))==baseline and watch.shard_generations=={}


def test_native_kqueue_keeps_real_db_event_queued_during_soft_refresh(tmp_path,monkeypatch):
    import select
    from wechat_local import native_follow_events as module
    if not hasattr(select,'kqueue'):pytest.skip('native kqueue unavailable')
    db=tmp_path/'message_7.db';shm=tmp_path/'message_7.db-shm';db.touch();shm.touch()
    watch=VnodeHints(tmp_path);listdir=module.os.listdir;injected=[False]
    try:
        original_fd=next(fd for fd,(path,_) in watch.fds.items() if path==db)
        def arriving(fd):
            names=listdir(fd)
            if not injected[0]:injected[0]=True;db.write_bytes(b'synthetic queued DB change')
            return names
        monkeypatch.setattr(module.os,'listdir',arriving)
        shm.write_bytes(b'synthetic coordination')
        assert watch.wait(1)==2 and watch.shard_generations=={} and watch.fallback_generation==2
        assert original_fd in watch.fds
        watch.wait(1)
        assert watch.shard_generations=={'message_7.db':3}
        wal=tmp_path/'message_7.db-wal';wal.write_bytes(b'synthetic new WAL')
        watch.wait(1)
        assert watch.shard_generations=={'message_7.db':4}
        assert any(path==wal for path,_ in watch.fds.values())
    finally:watch.close()
