"""One explicitly authorized same-source directory discovery; never SQL or keys."""
import hashlib,json,os,time,uuid
from pathlib import Path
from .native_follow_policy import Store,digest
from .native_deadline import Deadline,continuous_ns,check_deadline
from .native_mirror_store import MirrorError
from .native_target_request import read,need,root_for,cache_profile,require_source_round

KIND='directory_probe'


def profile(config,root):
    result=cache_profile(config,'directory-only',{'kind':KIND},root)
    # Keep the original declared usernames: SourceSetup's nonempty-scope guard
    # stays strict. This role is dispatched only to execute(), never sync/media.
    from .native_scope_contract import mode,limited
    if mode(config)=='account':raise MirrorError('account_directory_uses_local_registry')
    result=limited(result,list(config['mirror_scope']),root/'cache')
    return result


def source(grant):
    from .source_setup import load_source_config
    need(hashlib.sha256(read(grant['source_profile'])).hexdigest()==grant['source_raw_sha256'],'probe_source_conflict')
    original=load_source_config(Path(grant['source_profile']),physical=False)
    need(digest(original)==grant['source_signature'],'probe_source_conflict')
    return original


def validate(grant):
    from .public_service import PublicService
    from .native_follow_app import matches
    from .native_schedule import _config_facts
    need(grant.get('kind')==KIND and grant.get('authorized') is True and grant.get('scope')=='directory_discovery_once','probe_authorization_required')
    need(grant.get('round_seconds')==30 and grant.get('interval_seconds')==1 and 0<grant['deadline']['continuous_until']-grant['deadline']['continuous_start']<=60000000000,'probe_budget_invalid')
    Deadline(grant['deadline']).check()
    need(PublicService().context==grant['os_context'],'probe_context_changed')
    original=source(grant);derived=profile(original,Path(grant['root']))
    need(digest(derived)==grant['snapshot_sha256'] and _config_facts(derived)==grant['config_sha256'] and json.loads(read(grant['snapshot']))==derived,'probe_snapshot_conflict')
    state=Store(grant['store_root']).read('probe.json')
    need(state and state.get('active_grant_sha256')==digest(grant) and state.get('source_profile')==grant['source_profile'],'probe_state_conflict')
    need(matches(grant['app_epoch'],grant['app_executable']) is True,'probe_app_unavailable')
    return original


def prepare(config,config_path,*,expected_sha256,authorize=False,root=None,run=None):
    from .native_scope_contract import mode
    if mode(config)=='account':raise MirrorError('account_directory_uses_local_registry')
    from .native_schedule import configure,LaunchctlTransport,_config_facts
    from .native_follow_app import observe
    from .native_follow_config import settings
    need(type(expected_sha256) is str and len(expected_sha256)==64 and all(c in '0123456789abcdef' for c in expected_sha256) and hashlib.sha256(read(config_path)).hexdigest()==expected_sha256,'probe_source_conflict')
    from .source_setup import load_source_config
    need(load_source_config(Path(config_path),physical=False)==config and type(config.get('self_identity')) is dict,'probe_source_conflict')
    if not authorize:return dict(status='needs_directory_authorization',stage='directory_discovery',source_metadata_attempted=False)
    root=root_for(config,root)/'directory-probes'/digest([digest(config),'directory_discovery_once'])[:32]
    # Store.locked is the existing private nonblocking operation lock, not a queue.
    Store(root.parent,create=True);store=Store(root,create=True)
    with store.locked():
        if store.read('probe.json') is not None:return status(store.path('probe.json'),config=config,config_path=config_path,run=run)
        run=run or LaunchctlTransport();app_executable=settings(config)['executable'];app=observe(app_executable)
        need(app.get('state')=='running' and app.get('epoch'),'probe_app_unavailable')
        derived=profile(config,root);Store(derived['mirror_root'],create=True)
        from .native_mirror_sync import writer_lock
        with writer_lock(Path(derived['mirror_root']),0):pass
        snapshot=store.immutable('source.json',derived)
        grant=dict(kind=KIND,scope='directory_discovery_once',authorized=True,nonce=uuid.uuid4().hex,instance_nonce=root.name,store_root=str(root),root=str(root),source_profile=str(Path(config_path).absolute()),source_raw_sha256=expected_sha256,source_signature=digest(config),snapshot=str(snapshot),snapshot_sha256=digest(derived),config_sha256=_config_facts(derived),deadline=Deadline.create(60).facts,round_seconds=30,interval_seconds=1,consumed_hint_generation=-1,os_context=run.context,app_epoch=app['epoch'],app_executable=app_executable)
        path=store.immutable('grant.'+grant['nonce']+'.json',grant)
        descriptor=dict(path=str(path),sha256=digest(grant),deadline=grant['deadline'],interval_seconds=1,label_id=digest([config['account_id'],config['source_generation'],KIND])[:20]+'.'+root.name)
        state=dict(id=root.name,source_profile=grant['source_profile'],profile=str(snapshot),active_grant_sha256=digest(grant),descriptor=descriptor,services=str(root/'workers'))
        store.atomic('probe.json',state)
        def prepared(value):
            state.update(operation=value['operation'],record=value['record'],os_context=value['os_context']);store.atomic('probe.json',state)
        configure(derived,snapshot,Path(__import__('sys').executable).parent/'wechat-local-sync',root/'workers',True,runner=run,follow_grant=descriptor,prepared=prepared)
        return dict(status='pending',stage='directory_discovery',probe_record=str(store.path('probe.json')),source_metadata_attempted=None,source_sql_access='not_tested')


def execute(config,record_path):
    """Called by run_owned_once in place of ALL ordinary/forwarded actions."""
    from .native_follow_grant import load
    from .native_mirror_sync import mirror_root,writer_lock
    from .source_setup import load_source_config,SourceSetupError
    from .source_catalog import discover_numeric_shards,LiveCatalogError
    record=json.loads(read(record_path));grant=load(record['follow_grant'],record['follow_grant_sha256']);original=validate(grant)
    store=Store(grant['store_root']);state=store.read('probe.json')
    need(state.get('operation')==record['operation'] and str(Path(state['record']).absolute())==str(Path(record_path).absolute()),'probe_operation_conflict')
    with Store(store.root/'execution',create=True).locked():
        if store.read('attempt.json') is not None:return dict(gaps=[],directory_probe_complete=True,probe_already_attempted=True)
        result=dict(schema_version=1,stage='directory_discovery',boundary='source_preflight',state='started',access='unknown',errno=None,exception_class=None,directory_calls=0,pid=os.getpid(),ppid=os.getppid(),uid=os.getuid(),operation=record['operation'],operation_verified=True,context_verified=True,os_context=grant['os_context'],source_role=KIND,source_binding_digest=grant['source_signature'],snapshot_digest=grant['snapshot_sha256'],declaration_validated=True,binding_validated=False,started_wall_ns=time.time_ns(),started_continuous_ns=continuous_ns(),attempted_wall_ns=None,attempted_continuous_ns=None,ended_wall_ns=None,ended_continuous_ns=None,responsible_actor='unknown',source_sql_access='not_tested')
        store.immutable('attempt.json',result)
        try:
            check_deadline();need(load_source_config(Path(grant['snapshot']),physical=True)==config,'probe_snapshot_conflict')
            result.update(boundary='writer_lock',binding_validated=True)
            with writer_lock(mirror_root(original,create=False),0):
                with writer_lock(mirror_root(config,create=False),0):
                    check_deadline();validate(grant)
                    result.update(boundary='directory_discovery',directory_calls=1,attempted_wall_ns=time.time_ns(),attempted_continuous_ns=continuous_ns())
                    store.atomic('result.json',result)
                    shards=discover_numeric_shards(Path(config['message_root']))
                    result.update(access='success',shard_count=len(shards))
        except OSError as error:
            result.update(access='denied' if isinstance(error,PermissionError) else 'error',errno=error.errno if type(error.errno) is int else None,exception_class=type(error).__name__ if type(error) in (PermissionError,FileNotFoundError,TimeoutError,OSError) else 'OSError')
        except SourceSetupError as error:
            cause=error.__cause__
            result.update(access='denied' if isinstance(cause,PermissionError) else 'error',errno=cause.errno if isinstance(cause,OSError) and type(cause.errno) is int else None,exception_class='SourceSetupError')
        except LiveCatalogError:
            result.update(access='error',exception_class='LiveCatalogError')
        except MirrorError:
            result.update(access='error',exception_class='MirrorError',failure='guard_or_lock_rejected')
        result.update(state='completed',ended_wall_ns=time.time_ns(),ended_continuous_ns=continuous_ns())
        store.atomic('result.json',result)
    return dict(gaps=[],directory_probe_complete=True)


def status(path,*,config,config_path,run=None):
    from .native_schedule import inspect_status
    store=Store(Path(path).parent);state=store.read(Path(path).name);grant=json.loads(read(state['descriptor']['path']))
    need(grant.get('kind')==KIND and grant.get('scope')=='directory_discovery_once' and grant.get('authorized') is True and digest(grant)==state['descriptor']['sha256']==state['active_grant_sha256'],'probe_state_conflict')
    original=source(grant);need(digest(config)==grant['source_signature'] and str(Path(config_path).absolute())==grant['source_profile'],'probe_source_conflict')
    derived=json.loads(read(state['profile']));need(derived==profile(original,Path(grant['root'])) and digest(derived)==grant['snapshot_sha256'],'probe_snapshot_conflict')
    observed=inspect_status(derived,state['profile'],Path(__import__('sys').executable).parent/'wechat-local-sync',state['services'],runner=run,follow_grant=state['descriptor'])
    result=store.read('result.json') or store.read('attempt.json')
    if result:
        need(result.get('operation')==state['operation'] and result.get('source_binding_digest')==grant['source_signature'] and result.get('snapshot_digest')==grant['snapshot_sha256'] and type(result.get('directory_calls')) is int and result['directory_calls'] in (0,1),'probe_result_conflict')
    stopped=observed.get('stop_confirmed') is True
    outcome='ready' if stopped and observed.get('last_completed_exit_code')==0 and result and result.get('state')=='completed' else 'failed' if stopped else 'pending'
    if stopped and (not result or result.get('state')!='completed'):
        result=dict(result or {},access='timeout' if observed.get('last_completed_exit_code')==-14 else 'unknown',errno=None,ended_wall_ns=None,ended_continuous_ns=None)
    return dict(status=outcome,stage='directory_discovery',probe_record=str(path),result=result,owned=observed,stop_observed_wall_ns=time.time_ns(),stop_observed_continuous_ns=continuous_ns(),source_sql_access='not_tested')


from .failure_evidence import _register
_register(profile,source,validate,prepare,execute,status)
