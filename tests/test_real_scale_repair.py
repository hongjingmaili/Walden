"""Real account budget/copy paths; all Source bodies and identities generated.
OS grant ownership/encryption are external replacements only in this component
harness; installed listener entry separately covers actual grants and control.
"""
import json,shutil,sqlite3,hashlib
from pathlib import Path
import pytest
from wechat_local import native_account_witness as aw,native_follow_grant as fg,native_mirror_sync as sync,native_scope_contract as sc
from wechat_local.live_readonly import readonly_database_uri
from real_scale_fixture import create,Driver,sql_counts,global_sql_counts,table_name
import test_reboot_tolerance as fixture

@pytest.fixture(scope='module')
def large(request):
    item=create(unregistered_new=getattr(request,'param',False));root=Path(item['root']);snapshot=root/'initial-mirror';shutil.copytree(item['mirror_root'],snapshot);item['initial_mirror']=str(snapshot);item['resets']=0;return item

def fresh(item):
    mirror=Path(item['mirror_root']);base=Path(item['base']);assert base.name.startswith('synthetic-scale-') and base in mirror.parents
    item['resets']+=1;mirror.rename(Path(item['root'])/('previous-mirror-'+str(item['resets'])));shutil.copytree(item['initial_mirror'],mirror)

@pytest.fixture
def driver(large,monkeypatch):
    fresh(large);monkeypatch.setenv('XDG_STATE_HOME',str(Path(large['base'])/'state'));monkeypatch.setattr(fg,'validate',lambda *args,**kwargs:None)
    def run(item):
        def factory(path):
            db=sqlite3.connect(readonly_database_uri(path),uri=True);db.execute('PRAGMA query_only=ON');return db
        return sync._account_sync(item['config'],connection_factory=factory)
    monkeypatch.setattr(fixture,'run_full_account_sync',run);d=Driver(large)
    try:yield d
    finally:d.close()

@pytest.mark.parametrize('coverage',[True,False])
def test_full_scale_mandatory_guard_finalizes_within_unchanged_cap(driver,monkeypatch,coverage):
    if not coverage:
        value=driver.store.read('instance.'+driver.operation+'.json');value['shard_hints'].pop('coverage_version');driver.store.atomic('instance.'+driver.operation+'.json',value)
    owners=[];original=aw.AccountWitness.__init__
    def capture(self,*args,**kwargs):original(self,*args,**kwargs);owners.append(self)
    monkeypatch.setattr(aw.AccountWitness,'__init__',capture);before=sql_counts(driver.item);rows=[]
    for n in range(8):
        start=len(owners);value=driver.round();assert not value['gaps'];assert value['source_opens']<=4 and value['rows_read']<=2000
        assert all(owner.budget['tail_probe']['bytes']<=1048576 for owner in owners[start:]);rows.append(dict(round=n+1,source_opens=value['source_opens'],new_tail=value['new_tail'],actual_count=sql_counts(driver.item)))
    out=Path(__file__).resolve().parents[2]/'evidence'/('account-cap-'+str(coverage)+'.json');out.write_text(json.dumps(dict(coverage=coverage,before=before,rounds=rows),indent=2)+'\n')

@pytest.mark.parametrize('large',[True],indirect=True)
def test_full_scale_quiet_scan_converges_and_materializes_historical_rows(driver):
    # This is the trusted-new-registration variant, not permission to adopt the
    # legacy absent member in the real failure input. That RED remains sealed.
    from real_scale_fixture import table_name
    table=table_name(15,2)
    actual=driver.item['shards'][15]['name']
    with sc.registry(driver.item['config']) as db:
        assert db.execute('SELECT 1 FROM members WHERE shard=? AND table_name=?',(actual,table)).fetchone() is None
        assert db.execute('SELECT 1 FROM observations WHERE instr(proof,?)>0',(table,)).fetchone() is None
    with sqlite3.connect(Path(driver.item['message_root'])/actual) as source:
        assert source.execute('SELECT 1 FROM sqlite_master WHERE name=?',(table,)).fetchone() is None
        spec=json.loads((Path(__file__).parent/'fixtures/real_scale_metadata.json').read_text())
        source.execute(spec['canonical_message_ddl'].replace('Msg_{table}',table))
    driver.notify(shard=actual)
    before=sql_counts(driver.item);rows=[]
    for n in range(60):
        value=driver.round()
        with sc.registry(driver.item['config']) as db:
            work=sc.state(db,'account_work') or {};cursor=sc.state(db,'tail_debt_cursor');scan=sc.state(db,'history_backlog_scan')
        rows.append(dict(round=n+1,source_opens=value['source_opens'],gaps=value['gaps'],new_tail=value['new_tail'],actual_count=sql_counts(driver.item),cursor=cursor,scan=scan,work={k:work.get(k) for k in ('ready','imported','reconcile')}))
        if work.get('ready') is True:break
    out=Path(__file__).resolve().parents[2]/'evidence'/'new-registration-history-convergence.json';out.write_text(json.dumps(dict(input_variant='trusted-new-registration',before=before,rounds=rows),indent=2)+'\n');assert rows[-1]['work']['ready'] is True,rows
    advancing=[];cohort=[];quiet=[]
    for _ in range(20):
        prior=global_sql_counts(driver.item);cohort_prior=sql_counts(driver.item)['rows']
        value=driver.round();after=global_sql_counts(driver.item);delta=after['rows']-prior['rows']
        advancing.append(delta);cohort.append(sql_counts(driver.item)['rows']-cohort_prior)
        quiet.append(dict(before=prior,after=after,source_opens=value['source_opens'],rows_read=value['rows_read'],gaps=value['gaps'],new_tail=value['new_tail'],sources=value['sources']))
        assert delta>=0
        if not delta:
            # A quiet hint is not proof of remaining trusted metadata capacity.
            # Accept a zero only with the actual bounded-stop evidence, or
            # honest prefix movement across already materialized suffix rows.
            assert value['new_tail'].get('work_budget_limited') or value['new_tail'].get('probe_limited') or after['history']>prior['history'],quiet[-1]
        assert value['source_opens']<=4 and value['rows_read']<=2000 and value['new_tail']['metadata_bytes']<=1048576
    out.with_name('new-registration-history-quiet20.json').write_text(json.dumps(dict(initialization_rounds=len(rows),global_actual_rows_added=advancing,original46_actual_rows_added=cohort,global_total=sum(advancing),original46_total=sum(cohort),rounds=quiet),indent=2)+'\n');assert sum(advancing)>=10000,advancing


@pytest.mark.parametrize('large',[False],indirect=True)
def test_real_shape_explicit_registered_legacy_reconcile_then_actual_history_progress(driver,monkeypatch):
    from wechat_local import native_account_reconcile as repair
    item=driver.item;target=table_name(15,2);shard=item['shards'][15]['name']
    with sc.registry(item['config']) as db:
        proof=sc.member(item['config'],db,shard,target)
        assert db.execute('SELECT count(*) FROM members').fetchone()==(4447,)
    initial=dict(global_count=global_sql_counts(item),original46=sql_counts(item))
    plan=repair.authorize(item['config'],proof['ref']);repair.authorize(item['config'],proof['ref'],confirmed=True,expected_source_sha256=plan['source_sha256'])
    def existing_messages():
        values={}
        for shape in item['shards']:
            path=Path(item['mirror_root'])/shape['name']
            if shape['name']!=shard:values[shape['name']]=hashlib.sha256(path.read_bytes()).hexdigest();continue
            with sqlite3.connect(path) as db:
                tables=[r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name GLOB 'Msg_*'") if r[0]!=target]
                rows={name:hashlib.sha256(repr(db.execute('SELECT * FROM '+name+' ORDER BY rowid').fetchall()).encode()).hexdigest() for name in tables}
                rows['progress']=hashlib.sha256(repr(db.execute('SELECT * FROM __walden_progress WHERE table_name<>? ORDER BY table_name',(target,)).fetchall()).encode()).hexdigest()
                rows['observed']=hashlib.sha256(repr(db.execute('SELECT * FROM __walden_observed WHERE table_name<>? ORDER BY table_name,local_id,fingerprint',(target,)).fetchall()).encode()).hexdigest()
                values[shape['name']]=rows
        return values
    original=repair.consume;actions=[]
    def bounded_action(*args,**kwargs):
        before=existing_messages();value=original(*args,**kwargs);after=existing_messages()
        actions.append(dict(before=before,after=after,result=value));assert before==after
        return value
    monkeypatch.setattr(repair,'consume',bounded_action);rounds=[]
    for n in range(80):
        value=driver.round()
        with sc.registry(item['config']) as db:work=sc.state(db,'account_work') or {}
        rounds.append(dict(round=n+1,result=value,work_ready=work.get('ready'),global_count=global_sql_counts(item),original46=sql_counts(item)))
        if actions and work.get('ready'):break
    assert actions and actions[0]['result'] and rounds[-1]['work_ready'] is True
    assert any(v['result']['account_scope']['prior_coverage_unknown'] for v in rounds)
    quiet=[]
    for _ in range(20):
        before=global_sql_counts(item);value=driver.round();after=global_sql_counts(item)
        assert not value['gaps'] and value['account_scope']['prior_coverage_unknown']
        assert value['new_tail']['metadata_bytes']<=1048576 and value['source_opens']<=4 and value['rows_read']<=2000
        if after['rows']==before['rows']:assert value['new_tail'].get('work_budget_limited') or value['new_tail'].get('probe_limited') or after['history']>before['history']
        quiet.append(dict(before=before,after=after,result=value,original46=sql_counts(item)))
    final=dict(global_count=global_sql_counts(item),original46=sql_counts(item))
    evidence=dict(input_variant='registered-legacy-three-absent-explicit-reconcile',initial=initial,actions=actions,initialization_rounds=rounds,quiet20=quiet,final=final)
    out=Path(__file__).resolve().parents[2]/'evidence'/'registered-legacy-reconcile-scale.json';out.write_text(json.dumps(evidence,indent=2)+'\n')
    assert final['global_count']['rows']-initial['global_count']['rows']>=10000
    assert final['original46']['rows']>initial['original46']['rows']
