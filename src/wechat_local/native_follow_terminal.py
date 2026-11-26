"""Explicit dead-generation retirement. This capability never admits Source work."""
import hashlib
import json
import os
import plistlib
from pathlib import Path
import re
import time
import uuid

from .native_mirror_store import MirrorError
from .native_follow_policy import Store,default_root,digest
from .source_setup import load_source_config
from . import native_follow as follow,native_schedule as schedule

_SEAL=object()


def _need(value):
    if not value:raise MirrorError('follow_terminal_recovery_unproven')


def _source_proof(config):
    """Existing account receipt + pinned file identity/header, no SQL on Source."""
    from . import native_scope_contract as scope
    from .native_source_recovery import source_stamp
    _need(scope.mode(config)=='account')
    token=scope.query_scope_guard(config)
    with scope.registry(config,snapshot=False) as db:
        rows=db.execute("SELECT key,value FROM state WHERE key LIKE 'shard_anchor:%' ORDER BY key LIMIT 1025").fetchall()
        _need(0<len(rows)<=1024)
        for key,value in rows:
            shard=key[len('shard_anchor:'):];_need(scope.SHARD.fullmatch(shard) is not None)
            anchor=json.loads(value)
            actual=source_stamp(Path(config['message_root'])/shard,config)
            _need(actual==dict(source_identity=anchor['source_identity'],source_header_sha256=anchor['header']))
    scope.query_scope_guard(config,token)
    return (token,tuple(rows))


class _TerminalRetirement:
    pass


def _dead(process,leader):
    _need(type(leader) is dict and leader.get('uid')==os.getuid()
          and type(leader.get('pid')) is int and leader['pid']>0 and leader.get('pgid')==leader['pid'])
    # A reused PID is unknown here, even if its birth differs. No signals.
    _need(process.identity(leader['pid']) is None and process.drained(leader) is True)


def _check(authority):
    _need(type(authority) is _TerminalRetirement and getattr(authority,'seal',None) is _SEAL)
    _need(authority.run.context==authority.context and schedule._retired_context_delta(authority.old_context,authority.context))
    for path,value in authority.pins.items():_need(schedule._read(path)==value)
    node=Path(authority.config['message_root']);st=node.lstat()
    _need(node.resolve()==node.absolute() and node.is_dir() and (st.st_dev,st.st_ino)==authority.root_identity)
    _need(_source_proof(authority.config)==authority.source)
    for leader in authority.leaders:_dead(authority.run.process,leader)
    for pid in authority.child_pids:_need(authority.run.process.identity(pid) is None)
    for target,payload in authority.jobs:
        _need(schedule._observe(authority.run,target,payload) in ('owned','absent') and authority.run.pid(target) is None)
    for path,value in authority.pins.items():_need(schedule._read(path)==value)


def verify_configure(authority,config,config_path,executable,directory,descriptor,record,run):
    """Private sealed check at the existing disable boundary; enabled is forbidden."""
    _check(authority)
    _need(run is authority.run and config==authority.config and str(config_path)==authority.policy['snapshot']
          and str(executable)==authority.policy['executable'] and str(directory)==authority.runtime['services']
          and descriptor==authority.segment['descriptor'] and record==authority.record)
    return authority.old_context


def _pinned_archive(path,pin):
    """Only this transaction's exact original inode/bytes may resume retirement."""
    if path.exists() or path.is_symlink():
        raw,identity=schedule._read(path)
        _need(pin==dict(sha256=hashlib.sha256(raw).hexdigest(),identity=identity))
        return path
    matches=[]
    for candidate in path.parent.glob(path.name+'.disabled-*'):
        suffix=candidate.name[len(path.name):]
        if re.fullmatch(r'\.disabled-[0-9]+',suffix) is None:continue
        raw,identity=schedule._read(candidate)
        if pin==dict(sha256=hashlib.sha256(raw).hexdigest(),identity=identity):matches.append(candidate)
    _need(len(matches)==1)
    return matches[0]


def _receipt_leaders(paths,record,payload,context,worker,process):
    leaders=[];raw=schedule._read(paths['.owned'])[0]
    for ext in ('.starting','.submission'):
        if ext not in paths:continue
        value=json.loads(schedule._read(paths[ext])[0])
        _need(value.get('operation')==record['operation'] and value.get('record_sha256')==hashlib.sha256(raw).hexdigest()
              and value.get('os_context')==context)
        if ext=='.starting':
            _need(value.get('plist_sha256')==record['plist_sha256'] and value.get('argv')==payload['ProgramArguments']
                  and value.get('admitted') is False and value.get('status')=='starting')
        else:_need(value.get('status') in ('not_submitted','pending','accepted'))
        leader=value.get('leader')
        if leader is not None:
            _need(process.same_generation(leader,worker['leader']));leaders.append(leader)
    return leaders


def _recover(profile_path,*,expected_source_sha256,expected_policy_generation,authorize=False,run=None,root=None,revoked_origin=None,revoked_origin_sha256=None):
    """Continue only the explicitly selected formally revoked same-source policy.

    Failure after durable revocation stays revoked. No implicit renewal, Source
    recovery ticket, context normalization, key access, or history change occurs.
    """
    from .native_mirror_sync import writer_lock,mirror_root
    _need(authorize is True and type(expected_policy_generation) is str
          and re.fullmatch('[0-9a-f]{32}',expected_policy_generation) is not None
          and type(expected_source_sha256) is str and re.fullmatch('[0-9a-f]{64}',expected_source_sha256) is not None)
    profile_path=Path(profile_path).absolute();store=Store(root or default_root(profile_path));run=run or schedule.LaunchctlTransport()
    config=load_source_config(profile_path,physical=False)
    with store.locked(),writer_lock(mirror_root(config,create=False),0):
        intent,policy=follow._policy(store);runtime=follow._runtime(store)
        _need(intent is not None and intent['enabled'] is False and intent['generation']==expected_policy_generation
              and policy['profile_path']==str(profile_path) and policy['store_root']==str(store.root)
              and policy['policy_path']==str(store.path('policy.'+expected_policy_generation+'.json'))
              and policy['source_signature']==digest(config) and runtime is not None
              and runtime['policy_generation']==expected_policy_generation and runtime.get('admission') is False
              and runtime.get('binding_valid') is True and not runtime.get('unsettled_activity') and not runtime.get('retirement_pending'))
        _need(schedule._retired_context_delta(runtime['context'],run.context))
        root_pin=store.path('event-root.'+expected_policy_generation+'.json')
        root_path=Path(config['message_root']);root_stat=root_path.lstat()
        _need(root_path.resolve()==root_path.absolute() and root_path.is_dir()
              and json.loads(schedule._read(root_pin)[0])==dict(identity=[root_stat.st_dev,root_stat.st_ino]))
        snapshot=Path(policy['snapshot']);_need(snapshot==store.path('source.'+expected_policy_generation+'.json'))
        _need(load_source_config(snapshot,physical=False)==config)
        segment=runtime.get('segment');_need(type(segment) is dict and segment.get('kind') in ('active','drain'))
        services=Path(runtime['services']);record_path=Path(segment['record']);descriptor=segment['descriptor']
        _need(services==store.root/('workers.'+runtime['operation']) and record_path.parent==services and record_path.suffix=='.owned')
        grant_path=Path(descriptor['path']);_need(grant_path.parent==store.root)
        ticket_path=store.path('terminal-recovery.'+policy['generation']+'.json')
        ticket=store.read(ticket_path.name)
        worker_paths={}
        if ticket is None:
            for ext in ('.plist','.owned','.runtime','.active','.starting','.submission'):
                item=record_path.with_suffix(ext)
                if item.exists() or item.is_symlink():worker_paths[ext]=item
            agent_path=Path(policy['agent_path'])
            _need(follow._material(policy)=='installed')
        else:
            _need(ticket.get('schema')=='walden.follow.terminal-retirement/1'
                  and ticket.get('policy_generation')==policy['generation'] and ticket.get('original_instance')==runtime['operation']
                  and ticket.get('old_context')==runtime['context'] and ticket.get('current_context')==run.context
                  and ticket.get('profile_sha256')==expected_source_sha256 and ticket.get('source_authority') is False
                  and ticket.get('origin_sha256')==revoked_origin_sha256)
            pins=ticket['worker_pins'];_need(type(pins) is dict and {'.owned','.runtime','.plist'}<=set(pins)
                and set(pins)<={'.plist','.owned','.runtime','.active','.starting','.submission'})
            worker_paths={ext:_pinned_archive(record_path.with_suffix(ext),pin) for ext,pin in pins.items()}
            suffixes={str(path)[len(str(record_path.with_suffix(ext))):] for ext,path in worker_paths.items() if path!=record_path.with_suffix(ext)}
            _need(len(suffixes)<=1)
            # A missing live optional file cannot be hidden by this transaction.
            for ext in {'.active','.starting','.submission'}-set(pins):
                _need(not record_path.with_suffix(ext).exists() and not record_path.with_suffix(ext).is_symlink())
            agent_path=_pinned_archive(Path(policy['agent_path']),ticket['listener_pin'])
        _need({'.owned','.runtime','.plist'}<=set(worker_paths))
        grant=json.loads(schedule._read(grant_path)[0]);record=json.loads(schedule._read(worker_paths['.owned'])[0])
        _need(grant_path==store.path('grant.'+grant['nonce']+'.json') and digest(grant)==descriptor['sha256']
              and grant.get('kind')==segment['kind'] and grant.get('instance_nonce')==runtime['operation']
              and grant.get('store_root')==str(store.root) and grant.get('policy_generation')==policy['generation']
              and grant.get('source_sha256')==digest(config) and grant.get('os_context')==runtime['context']
              and runtime.get('grant_nonce')==grant['nonce'] and record.get('operation')==segment['operation']
              and record.get('os_context')==runtime['context'] and record.get('follow_grant')==str(grant_path)
              and record.get('follow_grant_sha256')==descriptor['sha256'])
        label=schedule._schedule_label(config,descriptor);_need(record_path.name==label+'.owned')
        worker_payload=plistlib.loads(schedule._read(worker_paths['.plist'])[0])
        _need(schedule._read(agent_path)[0]==plistlib.dumps(follow._payload(policy,policy['policy_path'])))
        raw,identity=schedule._read(worker_paths['.plist'])
        expected_args=schedule._follow_args([policy['executable'],'bounded','--source-config',policy['snapshot'],'--operation-record',str(record_path)],descriptor)
        _need(record.get('target')==follow._target(run,label) and record.get('preflight')=='absent'
              and record.get('plist_identity')==identity and record.get('plist_sha256')==hashlib.sha256(raw).hexdigest()
              and record.get('config_sha256')==schedule._config_facts(config) and worker_payload.get('Label')==label
              and worker_payload.get('ProgramArguments')==expected_args+['--operation-token',record['operation']]
              and worker_payload.get('EnvironmentVariables',{}).get('WALDEN_OPERATION_ID')==record['operation'])
        from .native_deadline import Deadline
        Deadline(record['deadline'])  # Validate original facts; this is not Source admission.
        worker=json.loads(schedule._read(worker_paths['.runtime'])[0])
        _need(worker.get('operation')==record['operation'] and worker.get('os_context')==runtime['context'])
        # All persisted operation leaders, including startup/submission, must be
        # the same dead generation. Never rely just on an absent public PID.
        leaders=[runtime['leader'],worker['leader']]
        leaders.extend(_receipt_leaders(worker_paths,record,worker_payload,runtime['context'],worker,run.process))
        # Finished child PIDs may remain in runtime. They must be absent too;
        # their absence cannot substitute for the enclosing group proof.
        child_pids=[]
        for field in ('child_pid','media_child_pid'):
            pid=worker.get(field)
            if pid is not None:
                _need(type(pid) is int and pid>0 and run.process.identity(pid) is None);child_pids.append(pid)
        attempt=worker.get('attempt_record') or {}
        _need(type(attempt) is dict)
        child=attempt.get('child_identity')
        if child is not None:
            _need(type(child) is dict and run.process.identity(child['pid']) is None)
        authority_pids=child_pids+([child['pid']] if child is not None else [])
        authority=_TerminalRetirement();authority.seal=_SEAL;authority.config=config;authority.run=run;authority.context=dict(run.context)
        authority.old_context=runtime['context'];authority.policy=policy;authority.runtime=runtime;authority.segment=segment;authority.record=record
        authority.root_identity=(root_stat.st_dev,root_stat.st_ino);authority.leaders=leaders;authority.child_pids=authority_pids;authority.source=_source_proof(config)
        authority.jobs=[(follow._target(run,policy['label']),follow._payload(policy,policy['policy_path'])),(record['target'],worker_payload)]
        paths=[profile_path,snapshot,root_pin,Path(policy['policy_path']),agent_path,grant_path,
               store.path('intent.json'),store.path('current.json'),store.path('instance.'+runtime['operation']+'.json')]
        paths.extend(worker_paths.values())
        authority.pins={path:schedule._read(path) for path in paths}
        if ticket is not None:authority.pins[ticket_path]=schedule._read(ticket_path)
        _need(hashlib.sha256(authority.pins[profile_path][0]).hexdigest()==expected_source_sha256)
        if intent['enabled'] is False:
            _need(revoked_origin is not None and type(revoked_origin_sha256) is str)
            origin_path=Path(revoked_origin).absolute();origin_raw,origin_identity=schedule._read(origin_path)
            _need(hashlib.sha256(origin_raw).hexdigest()==revoked_origin_sha256)
            origin=json.loads(origin_raw)
            _need(origin==dict(schema='walden.follow.terminal-origin/1',enabled=True,
                policy_generation=policy['generation'],profile_sha256=expected_source_sha256,
                policy_sha256=hashlib.sha256(authority.pins[Path(policy['policy_path'])][0]).hexdigest(),
                instance_sha256=hashlib.sha256(authority.pins[store.path('instance.'+runtime['operation']+'.json')][0]).hexdigest(),
                old_context=runtime['context'],current_context=run.context))
            authority.pins[origin_path]=(origin_raw,origin_identity)
        else:_need(False)
        _check(authority)
        receipt=dict(schema='walden.follow.terminal-retirement/1',at_ns=time.time_ns(),policy_generation=policy['generation'],
            original_instance=runtime['operation'],old_context=runtime['context'],current_context=run.context,session_attributes_xor=0x4000,
            source_authority=False,source_signature=digest(config),profile_sha256=expected_source_sha256,
            origin_sha256=revoked_origin_sha256,source_proof_sha256=digest(authority.source),
            worker_pins={ext:dict(sha256=hashlib.sha256(schedule._read(path)[0]).hexdigest(),identity=schedule._read(path)[1]) for ext,path in worker_paths.items()},
            listener_pin=dict(sha256=hashlib.sha256(schedule._read(agent_path)[0]).hexdigest(),identity=schedule._read(agent_path)[1]),
            original_instance_sha256=hashlib.sha256(authority.pins[store.path('instance.'+runtime['operation']+'.json')][0]).hexdigest(),
            operation=segment['operation'],groups_drained=True,writer_exclusive=True)
        # Original records/grants/context remain byte-for-byte intact. The
        # receipt describes terminal authority, never a Source acceptance.
        if ticket is None:
            store.immutable(ticket_path.name,receipt)
            authority.pins[ticket_path]=schedule._read(ticket_path)
        else:
            # The existing immutable transaction, not a newly guessed archive,
            # binds this retry. No changed Source proof can continue it.
            _need(ticket['source_proof_sha256']==digest(authority.source)
                  and ticket['original_instance_sha256']==receipt['original_instance_sha256'])
        if all(path==record_path.with_suffix(ext) for ext,path in worker_paths.items()):
            schedule.configure(config,snapshot,policy['executable'],services,False,runner=run,
                               follow_grant=descriptor,_terminal_retirement=authority)
        else:
            _need(schedule._observe(run,record['target'],worker_payload)=='absent' and run.pid(record['target']) is None)
            suffix=next(str(path)[len(str(record_path.with_suffix(ext))):] for ext,path in worker_paths.items() if path!=record_path.with_suffix(ext))
            _check(authority)
            for ext,path in worker_paths.items():
                if path==record_path.with_suffix(ext):
                    destination=path.with_name(path.name+suffix)
                    _need(not destination.exists() and not destination.is_symlink() and schedule._read(path)==authority.pins[path])
                    path.rename(destination)
            schedule._sync_dir(services)
        # The worker files are now archives; the listener stays independently
        # pinned and revalidated immediately before removal.
        authority.pins={path:value for path,value in authority.pins.items() if path.parent!=services}
        _check(authority)
        target,payload=authority.jobs[0]
        if schedule._observe(run,target,payload)=='owned':run.remove(target,wait=True)
        _need(schedule._observe(run,target,payload)=='absent' and run.pid(target) is None)
        _check(authority)
        agent=Path(policy['agent_path']);_need(schedule._read(agent_path)==authority.pins[agent_path])
        if agent_path==agent:
            agent.rename(agent.with_name(agent.name+'.disabled-'+str(time.time_ns())));schedule._sync_dir(agent.parent)
        # Publish a new disabled terminal view; preserve the original instance
        # instead of rewriting its old authority or in-flight evidence.
        nonce=uuid.uuid4().hex
        terminal=dict(runtime,operation=nonce,admission=False,state='disabled',segment=None,grant_nonce=None,
                      unsettled_activity=None,retirement_pending=None,activity_stop_confirmed=True)
        store.immutable('instance.'+nonce+'.json',terminal);store.atomic('current.json',dict(nonce=nonce))
        store.immutable('terminal-completed.'+nonce+'.json',dict(receipt,completed_at_ns=time.time_ns(),registration='absent'))
    return dict(enabled=False,disabled_confirmed=True,source_authority=False,old_policy_generation=policy['generation'],
                listener_registration='absent',worker_registration='absent',groups_drained=True,writer_lock='free',gaps=[])


def recover(profile_path,*,expected_source_sha256,expected_policy_generation,authorize=False,run=None,root=None,revoked_origin=None,revoked_origin_sha256=None):
    try:
        return _recover(profile_path,expected_source_sha256=expected_source_sha256,
                        expected_policy_generation=expected_policy_generation,authorize=authorize,run=run,root=root,
                        revoked_origin=revoked_origin,revoked_origin_sha256=revoked_origin_sha256)
    except (KeyError,TypeError,ValueError,AttributeError):
        raise MirrorError('follow_terminal_recovery_unproven') from None


from .failure_evidence import _register
_register(_need,_source_proof,_dead,_check,verify_configure,_pinned_archive,_receipt_leaders,_recover,recover)
