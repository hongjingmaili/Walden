"""Owned, explicitly authorized one-shot committed-source recovery role."""
import hashlib,json,sys,time,uuid,sqlite3
from pathlib import Path
from .native_follow_policy import Store,digest
from .native_target_request import read,need,root_for
from .native_deadline import Deadline,continuous_ns,check_deadline
from .native_mirror_sync import mirror_root,writer_lock
from .native_mirror_store import MirrorError
from . import native_source_recovery as core

KIND='source_recovery'


def profile(config,root):
    result=dict(config);bin=Path(sys.executable).parent
    result.update(runtime_python=str(bin/'python'),window_cli=str(bin/'wechat-local-window'),reply_cli=str(bin/'wechat-local-reply'),mirror_root=str(root/'worker-cache'))
    return result


def source(grant):
    from .source_setup import load_source_config
    need(hashlib.sha256(read(grant['source_profile'])).hexdigest()==grant['source_raw_sha256'],'recovery_source_conflict')
    original=load_source_config(Path(grant['source_profile']),physical=False)
    need(digest(original)==grant['source_signature'],'recovery_source_conflict');core.anchors(original)
    return original


def validate(grant):
    from .public_service import PublicService
    from .native_follow_app import matches
    from .native_schedule import _config_facts
    need(grant.get('kind')==KIND and grant.get('authorized') is True and grant.get('scope')=='committed_daily_only' and type(grant.get('accept')) is bool,'recovery_authorization_required')
    need(type(grant.get('auxiliary_refresh',False)) is bool and (not grant.get('auxiliary_refresh') or grant.get('auxiliary_snapshot_root')==str(Path(grant['root'])/'auxiliary')),'recovery_auxiliary_authority')
    need(grant.get('round_seconds')==30 and grant.get('interval_seconds')==1 and 0<grant['deadline']['continuous_until']-grant['deadline']['continuous_start']<=180000000000,'recovery_budget_invalid');Deadline(grant['deadline']).check()
    need(PublicService().context==grant['os_context'],'recovery_context_changed');original=source(grant);derived=profile(original,Path(grant['root']))
    need(digest(derived)==grant['snapshot_sha256'] and _config_facts(derived)==grant['config_sha256'] and json.loads(read(grant['snapshot']))==derived,'recovery_snapshot_conflict')
    state=Store(grant['store_root']).read('recovery.json');need(state and state.get('active_grant_sha256')==digest(grant) and state.get('source_profile')==grant['source_profile'] and state.get('accept')==grant['accept'],'recovery_state_conflict')
    frozen=json.loads(read(grant['local_snapshot']));need(digest(frozen)==grant['expected_local_sha256'] and core.anchors(original)==frozen['anchors'],'recovery_expected_changed')
    need(matches(grant['app_epoch'],grant['app_executable']) is True,'recovery_app_unavailable')
    return original


def local_plan(config):
    with writer_lock(mirror_root(config,create=False),0):value=core.plan(config)
    snapshot=value['snapshot']
    return dict(status='ready',stage='recovery_local_plan',expected_local_sha256=value['expected_local_sha256'],scope_digest=digest(snapshot['anchors']),database_count=len(snapshot['databases']),committed_rows=sum(t['rows']['count'] for d in snapshot['databases'] for t in d['tables']),source_opened=False,local_mutated=False)


def prepare(config,config_path,*,expected_source_sha256,expected_local_sha256,authorize=False,accept=False,refresh_auxiliary=False,root=None,run=None):
    from .source_setup import load_source_config
    from .native_schedule import configure,LaunchctlTransport,_config_facts
    from .native_follow_config import settings
    from .native_follow_app import observe
    need(type(accept) is bool and hashlib.sha256(read(config_path)).hexdigest()==expected_source_sha256 and load_source_config(Path(config_path),physical=False)==config,'recovery_source_conflict')
    need(type(refresh_auxiliary) is bool and (not refresh_auxiliary or config.get('encrypted_contact_database')),'recovery_auxiliary_authority')
    if not authorize:return dict(status='needs_recovery_authorization',source_opened=False,local_mutated=False)
    root=root_for(config,root)/'source-recovery'/digest([digest(config),'committed_daily_only'])[:32];Store(root.parent,create=True);store=Store(root,create=True)
    with store.locked():
        # Each invocation declares exactly one finite role. Never hide unknown old workers.
        previous=store.read('current.json')
        if previous is None:need(all(p.name=='.walden-schedule.lock' for p in store.root.iterdir()),'recovery_authority_missing')
        if previous:
            pointer=Path(previous['record']);need(pointer.name=='recovery.json' and pointer.parent.parent==root and len(pointer.parent.name)==32 and all(c in '0123456789abcdef' for c in pointer.parent.name),'recovery_authority_missing')
            old=status(previous['record'],config=config,config_path=config_path,run=run)
            if old['owned'].get('stop_confirmed') is not True:return old
        run=run or LaunchctlTransport();app_executable=settings(config)['executable'];app=observe(app_executable)
        need(app.get('state')=='running' and app.get('epoch'),'recovery_app_unavailable')
        with writer_lock(mirror_root(config,create=False),0):frozen=core.plan(config)
        need(frozen['expected_local_sha256']==expected_local_sha256,'recovery_expected_changed')
        need(len(json.dumps(frozen['snapshot']).encode())<1024*1024,'recovery_snapshot_too_large')
        nonce=uuid.uuid4().hex;unit=Store(root/nonce,create=True);derived=profile(config,unit.root);Store(derived['mirror_root'],create=True)
        with writer_lock(mirror_root(derived,create=False),0):pass
        snapshot=unit.immutable('source.json',derived);local=unit.immutable('local-snapshot.json',frozen['snapshot'])
        grant=dict(kind=KIND,scope='committed_daily_only',authorized=True,accept=accept,auxiliary_refresh=refresh_auxiliary,auxiliary_snapshot_root=str(unit.root/'auxiliary'),nonce=nonce,instance_nonce=nonce,store_root=str(unit.root),root=str(unit.root),source_profile=str(Path(config_path).absolute()),source_raw_sha256=expected_source_sha256,source_signature=digest(config),snapshot=str(snapshot),snapshot_sha256=digest(derived),config_sha256=_config_facts(derived),local_snapshot=str(local),expected_local_sha256=expected_local_sha256,deadline=Deadline.create(180).facts,round_seconds=30,interval_seconds=1,consumed_hint_generation=-1,os_context=run.context,app_epoch=app['epoch'],app_executable=app_executable)
        path=unit.immutable('grant.'+nonce+'.json',grant);descriptor=dict(path=str(path),sha256=digest(grant),deadline=grant['deadline'],interval_seconds=1,label_id=digest([config['account_id'],config['source_generation'],KIND])[:20]+'.'+nonce)
        state=dict(id=nonce,source_profile=grant['source_profile'],profile=str(snapshot),accept=accept,active_grant_sha256=digest(grant),descriptor=descriptor,services=str(unit.root/'workers'))
        unit.atomic('recovery.json',state)
        # Persist admission BEFORE submit: unknown declarations never become an empty cohort.
        store.atomic('current.json',dict(record=str(unit.path('recovery.json'))))
        def prepared(value):state.update(operation=value['operation'],record=value['record'],os_context=value['os_context']);unit.atomic('recovery.json',state)
        configure(derived,snapshot,Path(sys.executable).parent/'wechat-local-sync',unit.root/'workers',True,runner=run,follow_grant=descriptor,prepared=prepared)
        return dict(status='pending',stage='source_recovery',recovery_record=str(unit.path('recovery.json')),accept=accept,source_opened=None,local_mutated=None)


def execute(config,record_path,*,connection_factory=None):
    from .native_follow_grant import load
    from .source_setup import load_source_config
    record=json.loads(read(record_path));grant=load(record['follow_grant'],record['follow_grant_sha256']);original=validate(grant);store=Store(grant['store_root']);state=store.read('recovery.json')
    need(state.get('operation')==record['operation'] and str(Path(state['record']).absolute())==str(Path(record_path).absolute()),'recovery_operation_conflict')
    with Store(store.root/'execution',create=True).locked():
        need(store.read('attempt.json') is None,'recovery_already_attempted')
        attempt=dict(operation=record['operation'],source_binding_digest=grant['source_signature'],snapshot_digest=grant['snapshot_sha256'],expected_local_sha256=grant['expected_local_sha256'],accept=grant['accept'],state='started',started_wall_ns=time.time_ns(),started_continuous_ns=continuous_ns())
        store.immutable('attempt.json',attempt)
        try:
            need(load_source_config(Path(grant['snapshot']),physical=True)==config,'recovery_snapshot_conflict')
            if connection_factory is None:
                from .live_readonly import read_private_passphrase,open_encrypted_readonly
                secret=[None]
                def connection_factory(path):
                    check_deadline()
                    if secret[0] is None:secret[0]=read_private_passphrase(Path(original['passphrase_file']))
                    return open_encrypted_readonly(path,secret[0])[0]
            with writer_lock(mirror_root(original,create=False),0),writer_lock(mirror_root(config,create=False),0):
                check_deadline();validate(grant)
                receipt=core.verify(original,json.loads(read(grant['local_snapshot'])),connection_factory=connection_factory,accept=grant['accept'],nonce=grant['nonce'],grant_digest=digest(grant),commit_check=lambda:validate(grant),refresh_auxiliary=grant.get('auxiliary_refresh',False),stage_root=grant.get('auxiliary_snapshot_root'))
            store.atomic('result.json',dict(attempt,state='completed',accepted=bool(receipt['accepted']),receipt=receipt,ended_wall_ns=time.time_ns(),ended_continuous_ns=continuous_ns()))
        except (MirrorError,OSError,sqlite3.Error) as error:
            code=str(error);safe=code if code in CODES else 'recovery_guard_or_device_failed'
            diagnostic=core.safe_difference(getattr(error,'recovery_difference',None)) if safe in ('recovery_row_mismatch','recovery_mapping_changed','recovery_schema_changed','recovery_mapping_schema_changed') else core.safe_difference(None)
            store.atomic('result.json',dict(attempt,state='failed',accepted=False,reason=safe,diagnostic=diagnostic,ended_wall_ns=time.time_ns(),ended_continuous_ns=continuous_ns()));raise
    return dict(gaps=[],source_recovery_complete=True)


def status(path,*,config,config_path,run=None):
    from .native_schedule import inspect_status
    store=Store(Path(path).parent);state=store.read(Path(path).name);grant=json.loads(read(state['descriptor']['path']))
    need(grant.get('kind')==KIND and grant.get('scope')=='committed_daily_only' and grant.get('authorized') is True and type(grant.get('accept')) is bool and grant.get('round_seconds')==30 and digest(grant)==state['descriptor']['sha256']==state['active_grant_sha256'],'recovery_state_conflict');original=source(grant)
    need(digest(config)==grant['source_signature'] and str(Path(config_path).absolute())==grant['source_profile'],'recovery_source_conflict')
    derived=json.loads(read(state['profile']));expected=profile(original,Path(grant['root']))
    # Read-only historical observation uses the exact protected runtime triple.
    # Source execute/validate still require this caller's current runtime profile.
    runtime=Path(derived['runtime_python']);need(runtime.is_absolute() and derived['window_cli']==str(runtime.parent/'wechat-local-window') and derived['reply_cli']==str(runtime.parent/'wechat-local-reply'),'recovery_snapshot_conflict')
    for key in ('runtime_python','window_cli','reply_cli'):expected[key]=derived[key]
    need(derived==expected and digest(derived)==grant['snapshot_sha256'],'recovery_snapshot_conflict')
    observed=inspect_status(derived,state['profile'],runtime.parent/'wechat-local-sync',state['services'],runner=run,follow_grant=state['descriptor']);result=store.read('result.json') or store.read('attempt.json')
    if result:need(result.get('operation')==state.get('operation') and result.get('source_binding_digest')==grant['source_signature'] and result.get('expected_local_sha256')==grant['expected_local_sha256'],'recovery_result_conflict')
    if result and result.get('state')!='completed':result=dict(result,accepted=False,diagnostic=core.safe_difference(result.get('diagnostic')))
    frozen=json.loads(read(grant['local_snapshot']));need(digest(frozen)==grant['expected_local_sha256'] and frozen['anchors']==core.anchors(original),'recovery_expected_changed')
    committed=core.committed_receipt(frozen,grant['nonce'],digest(grant)) if grant['accept'] else None
    if committed and (not result or result.get('state')!='completed'):result=dict(result or {},state='completed',accepted=True,receipt=committed,completion='atomic_receipt_after_worker_exit')
    from .native_schedule import _writer_state
    observed['maintenance_writer_lock']=_writer_state(original)
    observed['worker_stop_confirmed']=observed.get('stop_confirmed')
    observed['stop_confirmed']=observed.get('stop_confirmed') is True and observed['maintenance_writer_lock']=='free'
    stopped=observed.get('stop_confirmed') is True
    outcome='ready' if stopped and (committed or observed.get('last_completed_exit_code')==0 and result and result.get('state')=='completed') else 'failed' if stopped else 'pending'
    return dict(status=outcome,stage='source_recovery',recovery_record=str(path),accept=grant['accept'],auxiliary_refresh=grant.get('auxiliary_refresh',False),result=result,owned=observed,source_opened=False,local_mutated=False,stop_observed_wall_ns=time.time_ns(),stop_observed_continuous_ns=continuous_ns())


from .failure_evidence import _register
_register(profile,source,validate,local_plan,prepare,execute,status)


CODES=core.CODES|frozenset(['recovery_auxiliary_authority','recovery_already_attempted', 'recovery_app_unavailable', 'recovery_authority_missing', 'recovery_authorization_required', 'recovery_budget_invalid', 'recovery_context_changed', 'recovery_expected_changed', 'recovery_operation_conflict', 'recovery_result_conflict', 'recovery_snapshot_conflict', 'recovery_snapshot_too_large', 'recovery_source_conflict', 'recovery_state_conflict'])
