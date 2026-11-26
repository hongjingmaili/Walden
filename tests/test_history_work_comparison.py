"""Fixed-input011/012 experiment. Each process imports exactly one package."""
import hashlib,json,os,sqlite3,time
from pathlib import Path
from collections import Counter
from test_incremental_history_work import Driver,seed,count_history,formal_local,HISTORY,NEW,USERNAME
from test_account_sync_status import item
from wechat_local import __version__,native_mirror_sync as sync,native_scope_contract as sc


def vector(item):
    with sqlite3.connect(item['local_path']) as db:
        state=[]
        for table,raw in db.execute('SELECT table_name,value FROM __walden_progress ORDER BY table_name'):
            if table=='Name2Id':continue
            p=json.loads(raw);count=db.execute('SELECT count(*) FROM "'+table+'"').fetchone()[0]
            state.append([table,p['H'],p['history'],p['tail'],p['target'],count])
    return hashlib.sha256(json.dumps(state).encode()).hexdigest()


def test_twenty_round_comparison_and_controlled_new_messages(item,monkeypatch,capsys):
    seed(item,count=1100);d=Driver(item);label=os.environ.get('WALDEN_COMPARISON_LABEL',__version__);results=[]
    try:
        initialized=[];started=time.monotonic()
        target=int(os.environ.get('WALDEN_INITIAL_HISTORY','500'))
        def initialized_ready():
            with sc.registry(item['config']) as db:
                work=sc.state(db,'account_work')
                return (work or {}).get('ready') is True if hasattr(sync,'_account_work_start') else sc.state(db,'tail_probe:message_0.db',{}).get('complete') is True
        while (count_history(item)<target or len(initialized)<6 or not initialized_ready()) and len(initialized)<24:
            value=d.round();assert not value['gaps'];initialized.append(value)
        assert count_history(item)==target and initialized_ready()
        initialization_seconds=time.monotonic()-started;initial_vector=vector(item);counts=[];reasons=Counter()
        copy=sync._account_copy_table;batch_rows=[]
        def observed_copy(*args,**kwargs):
            value=copy(*args,**kwargs)
            if value is not None:batch_rows.append(value['rows']);assert value['rows']<=500
            return value
        with monkeypatch.context() as m:
            m.setattr(sync,'_account_copy_table',observed_copy)
            for index in range(20):
                before=count_history(item);begun=time.monotonic();value=d.round();added=count_history(item)-before
                assert not value['gaps'];assert value['source_opens']<=4 and value['source_attempts']<=4
                assert value['rows_read']<=2000 and value['new_tail']['metadata_bytes']<=1048576 and value['new_tail']['metadata_tables']<=1024
                reason=('history_added' if added else 'incomplete_local_import' if not value['new_tail']['known_debt_import_complete'] else 'table_cursor_or_discovery')
                reasons[reason]+=1;counts.append(added);results.append(dict(round=index+1,history_added=added,reason=reason,source_opens=value['source_opens'],source_attempts=value['source_attempts'],rows_read=value['rows_read'],elapsed=time.monotonic()-begun,new_tail=value['new_tail']))
        if hasattr(sync,'_account_work_start'):assert all(n>=500 for n in counts),counts
        # Synthetic commit time is measured explicitly; no OS cadence/SLA claim.
        with sqlite3.connect(item['source_db']) as db:db.execute('INSERT INTO "'+NEW+'" VALUES(2,2,1,1700000000,0,?,0)',('controlled-before-round',))
        commit=time.monotonic();d.controlled_commit_mono=commit;d.controlled_expected_id=2
        d.notify();new_results=[]
        for opportunity in range(1,5):
            value=d.round();new_results.append(value)
            if hasattr(sync,'_account_work_start'):
                assert opportunity==1 and any(v['table']==NEW and v['tail']>=2 for v in value['sources']),value
            if any(v['table']==NEW and v['tail']>=2 for v in value['sources']):break
        rc,query=formal_local(item,monkeypatch,capsys,2);assert rc==0 and query['gaps']==[]
        latency=time.monotonic()-commit
        # Sustained known tail pressure: actual Source commits exceed existing
        # row budget. H may wait; pending target must never be lost on growth.
        sustained=[];next_id=3
        for _ in range(4):
            with sqlite3.connect(item['source_db']) as db:db.executemany('INSERT INTO "'+NEW+'" VALUES(?,?,?,?,?,?,?)',[(n,n,1,1700000001,0,'continuous-tail',0) for n in range(next_id,next_id+2500)])
            next_id+=2500;d.notify();before=count_history(item)
            with sqlite3.connect(item['local_path']) as db:tail_before=db.execute('SELECT count(*) FROM "'+NEW+'"').fetchone()[0]
            value=d.round();added=count_history(item)-before
            with sqlite3.connect(item['local_path']) as db:actual_tail_added=db.execute('SELECT count(*) FROM "'+NEW+'"').fetchone()[0]-tail_before
            if hasattr(sync,'_account_work_start'):assert actual_tail_added>0,value
            assert added==0 and value['rows_read']<=2000 and value['source_opens']<=4
            if hasattr(sync,'_account_work_start'):
                with sc.registry(item['config']) as db:
                    pending=sc.state(db,'tail_probe:message_0.db')['pending']
                    assert [NEW,next_id-1] in pending
            sustained.append(dict(history_added=added,actual_tail_rows_added=actual_tail_added,rows_read=value['rows_read'],tail=[v['tail'] for v in value['sources'] if v['table']==NEW],source_opens=value['source_opens']))
        report=dict(label=label,package_version=__version__,source_model='same generated1100tables/one30000rowHdebt/onecompletequerytarget; OS events and encryption replaced, actual account copy/metadata/budgets/local-window chain',initial_state='legitimately initialized warm state; no cache/fresh/completeness fixture injection',initialization_rounds=len(initialized),initialization_seconds=initialization_seconds,initialization_metadata_tables=sum(v['new_tail']['metadata_tables'] for v in initialized),initialization_metadata_bytes=sum(v['new_tail']['metadata_bytes'] for v in initialized),initialization_source_opens=sum(v['source_opens'] for v in initialized),initial_actual_history_rows=500,initial_progress_and_count_sha256=initial_vector,quiet_rounds=20,history_advancing_rounds=sum(n>0 for n in counts),actual_history_rows_added=sum(counts),nonadvancing_reasons=dict(reasons),max_actual_batch_rows=max(batch_rows),rounds=results,new_message=dict(commit_to_formal_query_seconds=latency,round_opportunities=opportunity,formal_exit=rc,formal_source_opens=query['source_opens'],formal_gaps=query['gaps'],round_results=new_results,timing_scope='controlled synthetic commit->immediate round opportunities->real parsed local window, not30s production cadence'),continuous_tail=sustained)
        output=Path(os.environ.get('WALDEN_COMPARISON_OUTPUT','../comparison-'+label+'.json'));output.write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({k:v for k,v in report.items() if k not in ('rounds','continuous_tail')}))
    finally:d.close()
