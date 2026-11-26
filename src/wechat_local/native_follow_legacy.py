"""Explicit cross-kernel retirement of a revoked legacy null-operation slot.

No cancellation, Source authority, service control, data mutation or retrospective
submission claim. A prospective pinned boot generation is mandatory.
"""
import hashlib
import base64
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

from .native_mirror_store import MirrorError
from .native_follow_policy import Store,default_root,digest,encoded
from .source_setup import load_source_config
from . import native_follow as follow,native_schedule as schedule,native_process as kernel
from . import native_scope_contract as scope


def _need(ok):
    if not ok:raise MirrorError('follow_legacy_retirement_unproven')


def _hex(value,size=32):return type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}',value) is not None


def _dir(path):
    path=Path(path);s=path.lstat()
    _need(path.is_absolute() and path.resolve()==path and stat.S_ISDIR(s.st_mode)
          and s.st_uid==os.getuid() and not s.st_mode&0o022)
    return [s.st_dev,s.st_ino]


def _pin(path):
    raw,identity=schedule._read(Path(path))
    return dict(identity=identity,sha256=hashlib.sha256(raw).hexdigest())


def _absent(path):
    try:Path(path).lstat()
    except FileNotFoundError:return
    _need(False)


def _names(generation):
    _need(_hex(generation))
    return ('legacy-plan.'+generation+'.json','legacy-proved.'+generation+'.json',
            'legacy-completed.'+generation+'.json')


def _environment(profile,run,store):
    config=load_source_config(profile,physical=False)
    _need(scope.mode(config)=='account')
    token=scope.query_scope_guard(config)
    intent,policy=follow._policy(store);runtime=follow._runtime(store)
    _need(policy is not None and runtime is not None and intent==dict(enabled=False,generation=policy['generation'])
          and policy['profile_path']==str(profile) and policy['store_root']==str(store.root)
          and policy['policy_path']==str(store.path('policy.'+policy['generation']+'.json'))
          and policy['snapshot']==str(store.path('source.'+policy['generation']+'.json'))
          and policy['source_signature']==digest(config)
          and load_source_config(Path(policy['snapshot']),physical=False)==config
          and runtime.get('policy_generation')==policy['generation'] and runtime.get('admission') is False
          and runtime.get('binding_valid') is True and runtime.get('store_root')==str(store.root)
          and not runtime.get('unsettled_activity') and not runtime.get('retirement_pending'))
    _need(run.context.get('uid')==os.getuid() and run.context.get('domain')=='kSMDomainUserLaunchd')
    return config,token,policy,runtime


def _snapshot(profile,config,token,policy,runtime,store,run,*,published=False):
    segment=runtime.get('segment');instance=runtime.get('operation')
    _need(_hex(instance) and type(segment) is dict and segment.get('kind') in ('active','drain')
          and segment.get('submission')=='pending' and segment.get('operation') is None)
    leader=runtime.get('leader')
    _need(type(leader) is dict and leader.get('uid')==os.getuid()
          and type(leader.get('pid')) is int and leader['pid']>0 and leader.get('pgid')==leader['pid']
          and type(leader.get('start')) is list and len(leader['start'])==2
          and all(type(x) is int and x>=0 for x in leader['start']))
    services=Path(runtime['services']);record=Path(segment['record']);descriptor=segment['descriptor']
    _need(services==store.root/('workers.'+instance) and record.parent==services
          and descriptor.get('label_id')==follow.profile_id(profile)+'.'+instance)
    label=schedule._schedule_label(config,descriptor)
    _need(record.name==label+'.owned')
    grant_path=Path(descriptor['path']);grant=json.loads(schedule._read(grant_path)[0])
    _need(_hex(grant.get('nonce')) and grant_path==store.path('grant.'+grant['nonce']+'.json')
          and descriptor['sha256']==digest(grant) and runtime.get('grant_nonce')==grant['nonce']
          and grant.get('store_root')==str(store.root) and grant.get('instance_nonce')==instance
          and grant.get('policy_generation')==policy['generation'] and grant.get('source_sha256')==digest(config)
          and grant.get('kind')==segment['kind'] and grant.get('os_context')==runtime.get('context'))
    for ext in ('.owned','.runtime','.plist','.active','.starting','.submission'):_absent(record.with_suffix(ext))
    agent=Path(policy['agent_path'])
    _need(agent.name==policy['label']+'.plist' and agent.parent==follow._home()/'Library/LaunchAgents')
    _absent(agent)
    for name in (policy['label'],label):
        target=follow._target(run,name)
        _need(schedule._observe(run,target)=='absent' and run.pid(target) is None)
    _need(follow._material(policy)=='absent')
    paths=[profile,Path(policy['snapshot']),Path(policy['policy_path']),grant_path,
           store.path('intent.json'),store.path('current.json'),store.path('instance.'+instance+'.json'),
           store.path('event-root.'+policy['generation']+'.json')]
    message=Path(config['message_root']);message_identity=_dir(message)
    _need(store.read('event-root.'+policy['generation']+'.json')==dict(identity=message_identity))
    directories={str(p):_dir(p)for p in (store.root,services,Path(config['mirror_root']),agent.parent,message)}
    # Both locks must already exist; recovery never substitutes a new lock.
    locks={str(p):_pin(p)for p in (store.root/'.walden-schedule.lock',Path(config['mirror_root'])/'.writer.lock')}
    result=dict(files={str(p):_pin(p)for p in paths},directories=directories,locks=locks,
                scope_sha256=digest(token),context=dict(run.context))
    scope.query_scope_guard(config,token)
    _need((published or follow._runtime(store)==runtime)
          and follow._policy(store)==(dict(enabled=False,generation=policy['generation']),policy))
    return result


def _load(store,generation,expected):
    _need(_hex(expected,64));path=store.path(_names(generation)[0]);raw,_=schedule._read(path)
    _need(hashlib.sha256(raw).hexdigest()==expected)
    plan=json.loads(raw)
    _need(plan.get('schema')=='walden.follow.legacy-boot-plan/1' and plan.get('generation')==generation
          and plan.get('store_root')==str(store.root) and _hex(plan.get('terminal_nonce')))
    owner=store.read('legacy-owner.'+generation+'.json')
    _need(owner==dict(schema='walden.follow.legacy-boot-owner/1',plan_pin=_pin(path)))
    return plan


def plan(profile_path,*,expected_source_sha256,expected_policy_generation,authorize=False,run=None,root=None):
    from .native_mirror_sync import writer_lock
    _need(authorize is True and _hex(expected_source_sha256,64) and _hex(expected_policy_generation))
    profile=Path(profile_path).absolute();store=Store(root or default_root(profile));run=run or schedule.LaunchctlTransport()
    config=load_source_config(profile,physical=False);mirror=Path(config['mirror_root'])
    # Validate before acquiring primitives which would otherwise create files.
    prior_locks={str(p):_pin(p)for p in (store.root/'.walden-schedule.lock',mirror/'.writer.lock')}
    with store.locked(),writer_lock(mirror,0):
        config,token,policy,runtime=_environment(profile,run,store)
        _need(policy['generation']==expected_policy_generation and _pin(profile)['sha256']==expected_source_sha256)
        boot=kernel.boot_session();view=_snapshot(profile,config,token,policy,runtime,store,run)
        _need(view['locks']==prior_locks)
        name=_names(policy['generation'])[0];existing=store.read(name)
        if existing is None:
            value=dict(schema='walden.follow.legacy-boot-plan/1',generation=policy['generation'],
                profile=str(profile),store_root=str(store.root),profile_sha256=expected_source_sha256,
                instance=runtime['operation'],view=view,boot=boot,at_ns=time.time_ns(),terminal_nonce=uuid.uuid4().hex,
                historical_submission='unknown',historical_sql='unknown',source_authority=False)
            _need(len(encoded(value))<=65536 and kernel.boot_session()==boot)
            store.immutable(name,value)
        else:
            _need(existing.get('profile_sha256')==expected_source_sha256 and existing.get('view')==view
                  and existing.get('boot')==boot and existing.get('instance')==runtime['operation'])
        owner_name='legacy-owner.'+policy['generation']+'.json'
        owner=dict(schema='walden.follow.legacy-boot-owner/1',plan_pin=_pin(store.path(name)))
        if store.read(owner_name) is None:store.immutable(owner_name,owner)
        else:_need(store.read(owner_name)==owner)
        _need(kernel.boot_session()==boot and _snapshot(profile,config,token,policy,runtime,store,run)==view)
        raw,_=schedule._read(store.path(name))
        return dict(state='planned_not_retired',retirement_id=policy['generation'],plan_sha256=hashlib.sha256(raw).hexdigest(),
                    source_authority=False,disabled_confirmed=False,requires_new_kernel_generation=True)


def _terminal(plan,runtime,context,boot,plan_sha):
    # Preserve old state in its original immutable file, not as current authority.
    value=dict(runtime,operation=plan['terminal_nonce'],context=dict(context),admission=False,state='disabled',
        segment=None,grant_nonce=None,unsettled_activity=None,retirement_pending=None,activity_stop_confirmed=True,
        source_schedule=None,observed_catchup_complete=None,observed_as_of=None,catchup_pending=True,
        pending_reasons=['historical_outcome_unknown'],legacy_retirement=dict(generation=plan['generation'],
            plan_sha256=plan_sha,boot=boot,historical_submission='unknown',historical_sql='unknown'))
    return value


def current_proof(store,runtime,*,require_current=True):
    """Receipt-backed proof for the new terminal nonce only; never old unknowns."""
    proof=runtime.get('legacy_retirement');_need(type(proof) is dict)
    plan=_load(store,proof['generation'],proof['plan_sha256']);names=_names(proof['generation'])
    receipt=store.read(names[1]);completed=store.read(names[2]);seal=store.read('legacy-seal.'+proof['generation']+'.json')
    _need(type(seal) is dict)
    for path,pin in seal['files'].items():_need(_pin(path)==pin)
    if require_current:
        _need(store.read('current.json')==dict(nonce=runtime['operation'])
              and _pin(store.path('current.json'))==seal['current_pin'])
        for path,pin in plan['view']['directories'].items():_need(_dir(path)==pin)
        for path,pin in plan['view']['locks'].items():_need(_pin(path)==pin)
        # Mutable intent/current may legitimately be republished by an explicit
        # stop; no other original current authority may be silently adopted.
        for path,pin in plan['view']['files'].items():
            if Path(path) not in (store.path('intent.json'),store.path('current.json')):_need(_pin(path)==pin)
        config=load_source_config(Path(plan['profile']),physical=False)
        _need(digest(scope.query_scope_guard(config))==plan['view']['scope_sha256']
              and store.read('intent.json')==dict(enabled=False,generation=plan['generation']))
    _need(type(receipt) is dict and receipt.get('schema')=='walden.follow.legacy-boot-proof/1'
          and receipt.get('plan_sha256')==proof['plan_sha256'] and receipt.get('terminal_nonce')==runtime['operation']==plan['terminal_nonce']
          and receipt.get('terminal_sha256')==digest(runtime) and receipt.get('old_boot')==plan['boot']
          and receipt.get('new_boot')==proof['boot'] and receipt['old_boot']!=receipt['new_boot']
          and completed==dict(schema='walden.follow.legacy-boot-completed/1',plan_sha256=proof['plan_sha256'],
                             receipt_sha256=digest(receipt),seal_sha256=digest(seal),terminal_nonce=runtime['operation']))
    return True


def current_status(store,runtime,run):
    """Current strict is a fresh observation, never the historical receipt alone."""
    current_proof(store,runtime)
    proof=runtime['legacy_retirement'];plan=_load(store,proof['generation'],proof['plan_sha256'])
    config=load_source_config(Path(plan['profile']),physical=False)
    _need(run.context.get('uid')==os.getuid() and run.context.get('domain')==plan['view']['context']['domain'])
    _need(run.context==runtime.get('context') or schedule._retired_context_delta(runtime.get('context'),run.context))
    policy=store.read('policy.'+plan['generation']+'.json');old=store.read('instance.'+plan['instance']+'.json')
    for label in (policy['label'],schedule._schedule_label(config,old['segment']['descriptor'])):
        target=follow._target(run,label)
        _need(schedule._observe(run,target)=='absent' and run.pid(target) is None)
    _need(follow._material(policy)=='absent')
    for ext in ('.owned','.runtime','.plist','.active','.starting','.submission'):
        _absent(Path(old['segment']['record']).with_suffix(ext))
    state=schedule._writer_state(config)
    current_proof(store,runtime)
    for label in (policy['label'],schedule._schedule_label(config,old['segment']['descriptor'])):
        target=follow._target(run,label)
        _need(schedule._observe(run,target)=='absent' and run.pid(target) is None)
    return state


def apply(profile_path,*,retirement_id,plan_sha256,authorize=False,run=None,root=None,_checkpoint=lambda phase:None):
    from .native_mirror_sync import writer_lock
    _need(authorize is True);profile=Path(profile_path).absolute();store=Store(root or default_root(profile))
    run=run or schedule.LaunchctlTransport();plan=_load(store,retirement_id,plan_sha256)
    _need(plan['profile']==str(profile));config=load_source_config(profile,physical=False);mirror=Path(config['mirror_root'])
    _pin(store.root/'.walden-schedule.lock');_pin(mirror/'.writer.lock')
    with store.locked(),writer_lock(mirror,0):
        names=_names(retirement_id);receipt=store.read(names[1]);completed=store.read(names[2])
        if completed is not None:
            original=store.read('instance.'+plan['terminal_nonce']+'.json');current_proof(store,original,require_current=False)
            return dict(state='already_retired_no_republication',source_authority=False,historical_submission='unknown',
                        historical_sql='unknown',current_state_not_rewritten=True)
        boot=kernel.boot_session();_need(boot!=plan['boot'])
        # Same account/profile and original disabled intent must survive the boot.
        current=store.read('current.json');published=current==dict(nonce=plan['terminal_nonce'])
        old=store.read('instance.'+plan['instance']+'.json')
        _need(type(old) is dict)
        if published:
            _need(receipt is not None and receipt.get('new_boot')==boot)
            active=follow._runtime(store);_need(digest(active)==receipt['terminal_sha256'])
            _need(_pin(profile)['sha256']==plan['profile_sha256'])
            policy=store.read('policy.'+retirement_id+'.json')
            terminal=active
        else:
            config,token,policy,runtime=_environment(profile,run,store)
            _need(runtime['operation']==plan['instance'])
            view=_snapshot(profile,config,token,policy,runtime,store,run)
            # Current security session may change after reboot; file/account facts cannot.
            _need({k:v for k,v in view.items() if k!='context'}=={k:v for k,v in plan['view'].items() if k!='context'}
                  and view['context']['domain']==plan['view']['context']['domain'] and view['context']['uid']==plan['view']['context']['uid'])
            terminal=_terminal(plan,runtime,run.context,boot,plan_sha256)
            wanted=dict(schema='walden.follow.legacy-boot-proof/1',plan_sha256=plan_sha256,
                old_boot=plan['boot'],new_boot=boot,terminal_nonce=plan['terminal_nonce'],terminal_sha256=digest(terminal),
                historical_submission='unknown',historical_sql='unknown',source_authority=False)
            evidence=dict(schema='walden.follow.legacy-control-archive/1',files={path:dict(pin=pin,
                raw_base64=base64.b64encode(schedule._read(Path(path))[0]).decode('ascii'))
                for path,pin in plan['view']['files'].items()})
            _need(len(encoded(evidence))<=65536)
            evidence_name='legacy-evidence.'+retirement_id+'.json'
            if store.read(evidence_name) is None:store.immutable(evidence_name,evidence)
            else:_need(store.read(evidence_name)==evidence)
            if receipt is None:
                store.immutable('instance.'+plan['terminal_nonce']+'.json',terminal)
                store.immutable(names[1],wanted);receipt=wanted
            else:_need(receipt==wanted and store.read('instance.'+plan['terminal_nonce']+'.json')==terminal)
            staged=store.path('legacy-current.'+retirement_id+'.json')
            oldcopy=store.path('legacy-old-current.'+retirement_id+'.json')
            oldraw=schedule._read(store.path('current.json'))[0]
            if not oldcopy.exists():schedule._create(oldcopy,oldraw);schedule._sync_dir(store.root)
            _need(schedule._read(oldcopy)[0]==oldraw)
            if not staged.exists():store.immutable(staged.name,dict(nonce=plan['terminal_nonce']))
            wanted_seal=dict(schema='walden.follow.legacy-boot-seal/1',files={str(p):_pin(p)for p in (
                store.path(_names(retirement_id)[0]),store.path('legacy-owner.'+retirement_id+'.json'),
                store.path('instance.'+plan['terminal_nonce']+'.json'),store.path(names[1]),store.path(evidence_name),oldcopy)},
                current_pin=_pin(staged))
            seal_name='legacy-seal.'+retirement_id+'.json'
            if store.read(seal_name) is None:store.immutable(seal_name,wanted_seal)
            else:_need(store.read(seal_name)==wanted_seal)
            _checkpoint('prepared')
            # A callback/crash test is outside product guards; revalidate full facts.
            fresh=_snapshot(profile,config,token,policy,runtime,store,run)
            _need(fresh==view and kernel.boot_session()==boot)
            seal=store.read(seal_name)
            for path,pin in seal['files'].items():_need(_pin(path)==pin)
            _need(_pin(staged)==seal['current_pin'])
            os.replace(staged,store.path('current.json'));schedule._sync_dir(store.root)
            _checkpoint('published')
        _need(kernel.boot_session()==boot)
        # Full post-publication/retry checks precede completing the new view.
        seal=store.read('legacy-seal.'+retirement_id+'.json');_need(type(seal) is dict)
        for path,pin in seal['files'].items():_need(_pin(path)==pin)
        _need(_pin(store.path('current.json'))==seal['current_pin'])
        token=scope.query_scope_guard(config)
        fresh=_snapshot(profile,config,token,policy,old,store,run,published=True)
        for part in ('files','directories','locks'):
            for path,pin in plan['view'][part].items():
                if part=='files' and Path(path)==store.path('current.json'):continue
                _need(fresh[part].get(path)==pin)
        _need(fresh['scope_sha256']==plan['view']['scope_sha256'] and fresh['context']['uid']==plan['view']['context']['uid']
              and fresh['context']['domain']==plan['view']['context']['domain'] and kernel.boot_session()==boot)
        _need(store.read('current.json')==dict(nonce=plan['terminal_nonce']) and follow._runtime(store)==terminal)
        store.immutable(names[2],dict(schema='walden.follow.legacy-boot-completed/1',plan_sha256=plan_sha256,
                                   receipt_sha256=digest(receipt),seal_sha256=digest(seal),terminal_nonce=plan['terminal_nonce']))
        current_proof(store,terminal)
        return dict(state='retired_after_kernel_change',disabled_confirmed=True,source_authority=False,
                    original_generation_terminated_by_kernel_change=True,historical_submission='unknown',historical_sql='unknown')


from .failure_evidence import _register
_register(_need,_dir,_pin,_absent,_names,_environment,_snapshot,_load,plan,_terminal,current_proof,current_status,apply)
