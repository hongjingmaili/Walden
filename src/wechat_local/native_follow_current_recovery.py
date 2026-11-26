"""Explicit retirement-only adoption of a current protected namespace.

This establishes NEW current authority; it never repairs historical volume pins,
submission or SQL evidence, reanchors Source, controls a service or grants work.
Same-Mac/non-migration remains a trusted operator precondition.
"""
import base64
import contextlib
import contextvars
import stat
import math
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import uuid
from .native_mirror_store import MirrorError
from .native_follow_policy import Store,default_root,digest,encoded
from . import native_follow as follow,native_follow_legacy as legacy,native_follow_identity as identity
from . import native_scope_contract as scope,native_schedule as schedule,native_process as kernel
from .source_setup import load_source_config,_decode_source_config


def _need(ok):
    if not ok:raise MirrorError('follow_current_recovery_unproven')

def _hex(value,size=64):return type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}',value) is not None

_reading_config=contextvars.ContextVar('current_recovery_reading_config',default=None)


def _locations(config,store_root=None,*paths):
    # Reuse the established Source/credential lexical, resolved and directory-ID
    # alias boundary before opening any new recovery input body or output.
    from .native_shard_restore import _layout
    try:
        _layout(config,state_root=store_root)
        for path in paths:_layout(config,replacement=Path(path))
    except (MirrorError,OSError,ValueError,RuntimeError):
        raise MirrorError('follow_current_recovery_unproven') from None


def _protected_ids(config):
    values=[config[k]for k in ('passphrase_file','session_database','encrypted_contact_database','image_database','image_key_config','image_credentials_status')if config.get(k)]
    values+=list(config.get('voice_databases',[]));found=set()
    for value in values:
        try:s=Path(value).stat()
        except FileNotFoundError:continue
        found.add((s.st_dev,s.st_ino))
    return found


def _read_input(path,config):
    path=Path(path);_locations(config,None,path)
    _need(path.is_absolute()and path.resolve()==path)
    # Pure metadata rejection comes first, including hard-link credential aliases.
    named=path.lstat();_need(stat.S_ISREG(named.st_mode)and named.st_uid==os.getuid()
        and stat.S_IMODE(named.st_mode)==0o600 and named.st_nlink==1 and named.st_size<=65536)
    _need((named.st_dev,named.st_ino)not in _protected_ids(config))
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        opened=os.fstat(fd);_need(identity._stamp(opened)==identity._stamp(named))
        _locations(config,None,path)
        _need(path.resolve()==path and (opened.st_dev,opened.st_ino)not in _protected_ids(config)
              and identity._stamp(opened)==identity._stamp(path.lstat()))
        birth=getattr(opened,'st_birthtime',None)
        _need(type(birth)is float and math.isfinite(birth)and birth>0)
        volume=identity._volume(fd)
        # No body is read until the opened FD and its current named role pass.
        raw=os.read(fd,65537);_need(len(raw)==opened.st_size and len(raw)<=65536)
        _need(identity._volume(fd)==volume and identity._stamp(opened)==identity._stamp(os.fstat(fd))
              and identity._stamp(opened)==identity._stamp(path.lstat()))
        ident=dict(volume_uuid=volume,inode=opened.st_ino,birthtime_hex=birth.hex(),kind=stat.S_IFMT(opened.st_mode),uid=opened.st_uid,mode=stat.S_IMODE(opened.st_mode))
        return raw,dict(identity=ident,sha256=hashlib.sha256(raw).hexdigest())
    finally:os.close(fd)


def _raw(path):
    config=_reading_config.get();_need(config is not None)
    return _read_input(path,config)[0]


def _pin(path):
    config=_reading_config.get()
    # Only internal lock helpers may be called without an external profile.
    return identity.pin(Path(path))if config is None else _read_input(path,config)[1]


def _json(path):return json.loads(_raw(path))


@contextlib.contextmanager
def _guarded(profile_path,root):
    config=load_source_config(Path(profile_path),physical=False)
    _locations(config,root)
    token=_reading_config.set(config)
    try:yield config
    finally:_reading_config.reset(token)


def _dir(path):return identity.pin(Path(path),directory=True)

def _read_optional(store,name):
    try:return _json(store.path(name))
    except FileNotFoundError:return None


def _name(role,generation):
    _need(_hex(generation,32) and role in ('view','ticket','archive','old-plan','old-owner','old-receipt','terminal','proof','seal','current','old-current','completed'))
    return 'current-recovery-'+role+'.'+generation+'.json'

@contextlib.contextmanager
def _locks(store,mirror):
    """The existing flock contracts, opened without O_CREAT; never a replacement lock."""
    paths=(store.root/'.walden-schedule.lock',mirror/'.writer.lock');pins={str(p):_pin(p)for p in paths};fds=[]
    try:
        for p in paths:
            fd=os.open(p,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK);fds.append((p,fd))
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise MirrorError('sync_busy') from None
            st=os.fstat(fd);named=p.lstat()
            _need((st.st_dev,st.st_ino)==(named.st_dev,named.st_ino) and _pin(p)==pins[str(p)])
        yield
        for p,fd in fds:
            st=os.fstat(fd);named=p.lstat()
            _need((st.st_dev,st.st_ino)==(named.st_dev,named.st_ino) and _pin(p)==pins[str(p)])
    finally:
        for p,fd in reversed(fds):os.close(fd)


def _basis(store,profile,source_sha,generation,plan_sha,owner_sha,receipt_path,receipt_sha):
    _need(all(_hex(x)for x in (source_sha,plan_sha,owner_sha,receipt_sha))and _hex(generation,32))
    oldplan=store.path('legacy-plan.'+generation+'.json');oldowner=store.path('legacy-owner.'+generation+'.json')
    receipt_path=Path(receipt_path).absolute();paths=dict(plan=oldplan,owner=oldowner,receipt=receipt_path)
    config=_reading_config.get();_need(config is not None)
    _locations(config,store.root,*paths.values())
    raw={name:_raw(p)for name,p in paths.items()}
    for name,expected in (('plan',plan_sha),('owner',owner_sha),('receipt',receipt_sha)):
        _need(hashlib.sha256(raw[name]).hexdigest()==expected)
    p=json.loads(raw['plan']);o=json.loads(raw['owner']);r=json.loads(raw['receipt'])
    _need(p.get('schema')=='walden.follow.legacy-boot-plan/1'and p.get('generation')==generation
          and p.get('profile')==str(profile)and p.get('store_root')==str(store.root)and p.get('profile_sha256')==source_sha
          and o.get('schema')=='walden.follow.legacy-boot-owner/1'and o.get('plan_pin',{}).get('sha256')==plan_sha
          and r.get('plan_id')==generation and r.get('plan_sha256')==plan_sha and r.get('plan_path')==str(oldplan)
          and r.get('owner_path')==str(oldowner)and r.get('owner_path_sha256')==owner_sha
          and r.get('plan_path_identity')==o['plan_pin'].get('identity')and r.get('profile_sha256')==source_sha
          and r.get('scope_sha256')==p.get('view',{}).get('scope_sha256')
          and r.get('boot_sha256')==hashlib.sha256(p['boot'].encode()).hexdigest())
    # Supplementary wrong-object rejection, NOT historical volume continuity.
    for name,key in (('plan','plan_path_identity'),('owner','owner_path_identity')):
        _need(_pin(paths[name])['identity']['inode']==r[key][1])
    return dict(generation=generation,source_sha256=source_sha,plan_sha256=plan_sha,owner_sha256=owner_sha,
                receipt_sha256=receipt_sha,receipt_path=str(receipt_path),plan=p,raw=raw,paths=paths)


def _facts(profile,store,run,basis,*,terminal=None):
    c=_reading_config.get();_need(c is not None and scope.mode(c)=='account')
    p=basis['plan'];generation=basis['generation'];expected=p['view']['files']
    _locations(c,store.root,*map(Path,expected))
    bodies={}
    for path,pin in expected.items():
        raw=_raw(path)
        if terminal is None or Path(path)!=store.path('current.json'):_need(hashlib.sha256(raw).hexdigest()==pin['sha256'])
        bodies[path]=raw
    policy_path=store.path('policy.'+generation+'.json');instance_path=store.path('instance.'+p['instance']+'.json')
    _need(str(policy_path)in bodies and str(instance_path)in bodies and str(profile)in bodies)
    policy=json.loads(bodies[str(policy_path)]);old=json.loads(bodies[str(instance_path)])
    intent=json.loads(bodies[str(store.path('intent.json'))]);current=json.loads(bodies[str(store.path('current.json'))])
    wanted_nonce=old['operation']if terminal is None else terminal['operation']
    _need(current==dict(nonce=wanted_nonce))
    active=_json(store.path('instance.'+wanted_nonce+'.json'))
    _need(type(policy)is dict and type(old)is dict and intent==dict(enabled=False,generation=generation)
          and policy.get('generation')==generation and policy.get('profile_path')==str(profile)
          and policy.get('store_root')==str(store.root)and policy.get('policy_path')==str(policy_path)
          and policy.get('snapshot')==str(store.path('source.'+generation+'.json'))
          and policy.get('source_signature')==digest(c)and str(Path(policy['snapshot']))in bodies
          and _decode_source_config(bodies[str(Path(policy['snapshot']))])==c
          and active.get('policy_generation')==generation and active.get('admission')is False
          and active.get('binding_valid')is True and active.get('store_root')==str(store.root)
          and not active.get('unsettled_activity')and not active.get('retirement_pending')
          and run.context.get('uid')==os.getuid()and run.context.get('domain')=='kSMDomainUserLaunchd')
    token=scope.query_scope_guard(c)
    _need(p['instance']==old.get('operation')and(active==old if terminal is None else active==terminal)
          and hashlib.sha256(bodies[str(profile)]).hexdigest()==basis['source_sha256']
          and digest(token)==p['view']['scope_sha256'])
    segment=old.get('segment');leader=old.get('leader')
    _need(type(segment) is dict and segment.get('kind')in ('active','drain')and segment.get('operation')is None
          and segment.get('submission')=='pending'and type(leader)is dict and leader.get('uid')==os.getuid()
          and type(leader.get('pid'))is int and leader['pid']>0 and leader.get('pgid')==leader['pid'])
    services=Path(old['services']);record=Path(segment['record']);descriptor=segment['descriptor'];grant_path=Path(descriptor['path'])
    _need(services==store.root/('workers.'+old['operation'])and record.parent==services
          and descriptor.get('label_id')==follow.profile_id(profile)+'.'+old['operation'])
    grant=json.loads(_raw(grant_path));label=schedule._schedule_label(c,descriptor)
    _need(record.name==label+'.owned'and grant_path==store.path('grant.'+grant['nonce']+'.json')
          and descriptor['sha256']==digest(grant)and old.get('grant_nonce')==grant.get('nonce')
          and grant.get('store_root')==str(store.root)and grant.get('instance_nonce')==old['operation']
          and grant.get('policy_generation')==generation and grant.get('source_sha256')==digest(c)
          and grant.get('kind')==segment['kind']and grant.get('os_context')==old.get('context'))
    for ext in ('.owned','.runtime','.plist','.active','.starting','.submission'):legacy._absent(record.with_suffix(ext))
    agent=Path(policy['agent_path']);home=follow._home()
    _need(agent.name==policy['label']+'.plist'and agent.parent==home/'Library/LaunchAgents')
    legacy._absent(agent);_need(follow._material(policy)=='absent')
    for name in (policy['label'],label):
        target=follow._target(run,name);_need(schedule._observe(run,target)=='absent'and run.pid(target)is None)
    paths=[profile,Path(policy['snapshot']),Path(policy['policy_path']),grant_path,store.path('intent.json'),
           store.path('current.json'),store.path('instance.'+old['operation']+'.json'),store.path('event-root.'+generation+'.json')]
    dirs=[store.root,services,Path(c['mirror_root']),agent.parent,Path(c['message_root'])]
    locks=[store.root/'.walden-schedule.lock',Path(c['mirror_root'])/'.writer.lock']
    _need(set(map(str,paths))==set(p['view']['files'])and set(map(str,dirs))==set(p['view']['directories'])
          and set(map(str,locks))==set(p['view']['locks'])and len(paths)==8 and len(dirs)==5 and len(locks)==2)
    files={str(x):_pin(x)for x in paths};directories={str(x):_dir(x)for x in dirs};lockpins={str(x):_pin(x)for x in locks}
    for path,pin in files.items():
        if terminal is not None and Path(path)==store.path('current.json'):continue
        expected=p['view']['files'][path]
        _need(pin['sha256']==expected['sha256']and pin['identity']['inode']==expected['identity'][1])
    for path,pin in directories.items():_need(pin['inode']==p['view']['directories'][path][1])
    for path,pin in lockpins.items():
        expected=p['view']['locks'][path];_need(pin['sha256']==expected['sha256']and pin['identity']['inode']==expected['identity'][1])
    # Old event-root is historical control content only. No Source reanchor.
    _need(_read_optional(store,'event-root.'+generation+'.json')==dict(identity=p['view']['directories'][c['message_root']]))
    extras={name:_pin(path)for name,path in basis['paths'].items()};homepin=_dir(home);volume=homepin['volume_uuid']
    _need(all(x['identity']['volume_uuid']==volume for x in [*files.values(),*lockpins.values(),*extras.values()])
          and all(x['volume_uuid']==volume for x in directories.values()))
    scope.query_scope_guard(c,token)
    _need(_json(store.path('current.json'))==dict(nonce=wanted_nonce)and _json(store.path('instance.'+wanted_nonce+'.json'))==active
          and _json(store.path('intent.json'))==intent and _json(policy_path)==policy)
    return dict(files=files,directories=directories,locks=lockpins,basis=extras,home=dict(path=str(home),identity=homepin),
                scope_sha256=digest(token),context=dict(run.context)),c,old


def _same(now,before,store,*,published=False):
    for part in ('files','directories','locks','basis'):
        for path,pin in before[part].items():
            if published and part=='files'and Path(path)==store.path('current.json'):continue
            _need(now[part].get(path)==pin)
    _need(now['home']==before['home']and now['scope_sha256']==before['scope_sha256']and now['context']==before['context'])


def _create_raw(store,name,raw):
    _need(len(raw)<=65536);path=store.path(name);config=_reading_config.get();_need(config is not None)
    _locations(config,store.root,path);_need(store.root.resolve()==store.root)
    parent=os.open(store.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        before=os.fstat(parent);_need(identity._stamp(before)==identity._stamp(store.root.lstat()))
        _locations(config,store.root,path)
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        try:
            view=memoryview(raw)
            while view:
                count=os.write(fd,view);_need(count>0);view=view[count:]
            os.fsync(fd)
        finally:os.close(fd)
        os.fsync(parent)
        after=os.fstat(parent);named=store.root.lstat()
        _need((before.st_dev,before.st_ino)==(after.st_dev,after.st_ino)==(named.st_dev,named.st_ino))
        _locations(config,store.root,path)
    finally:os.close(parent)


def _immutable(store,name,value):
    _create_raw(store,name,encoded(value));return store.path(name)


def _plan(profile_path,*,expected_source_sha256,legacy_retirement_id,legacy_plan_sha256,legacy_owner_sha256,
         preboot_receipt,preboot_receipt_sha256,authorize=False,run=None,root=None):
    _need(authorize is True);profile=Path(profile_path).absolute();store=Store(root or default_root(profile));run=run or schedule.LaunchctlTransport()
    c=_reading_config.get();_need(c is not None);_need(hashlib.sha256(_raw(profile)).hexdigest()==expected_source_sha256);basis=_basis(store,profile,expected_source_sha256,legacy_retirement_id,
        legacy_plan_sha256,legacy_owner_sha256,preboot_receipt,preboot_receipt_sha256);generation=basis['generation']
    with _locks(store,Path(c['mirror_root'])):
        boot=kernel.boot_session();_need(boot!=basis['plan']['boot'])
        facts,c,old=_facts(profile,store,run,basis)
        ticket_path=store.path(_name('ticket',generation))
        if ticket_path.exists():
            value=_load(store,generation,digest(_pin(ticket_path)))
            _need(value['view']['boot']==boot);_same(facts,value['view']['current'],store)
        else:
            for role in ('view','archive','old-plan','old-owner','old-receipt'):legacy._absent(store.path(_name(role,generation)))
            archive=dict(schema='walden.follow.current-recovery-control-archive/1',historical_submission='unknown',historical_sql='unknown',
                files={path:dict(pin=facts['files'][path],raw_base64=base64.b64encode(_raw(path)).decode('ascii'))for path in facts['files']})
            _need(len(encoded(archive))<=65536)
            view=dict(schema='walden.follow.current-recovery-view/1',generation=generation,profile=str(profile),store_root=str(store.root),
                boot=boot,old_boot=basis['plan']['boot'],current=facts,original=dict(source_sha256=expected_source_sha256,
                generation=generation,plan_sha256=legacy_plan_sha256,owner_sha256=legacy_owner_sha256,
                receipt_path=str(Path(preboot_receipt).absolute()),receipt_sha256=preboot_receipt_sha256),
                terminal_nonce=uuid.uuid4().hex,old_instance=old['operation'],historical_object_continuity='unproven',source_authority=False)
            _need(len(encoded(view))<=65536)
            for role,key in (('old-plan','plan'),('old-owner','owner'),('old-receipt','receipt')):_create_raw(store,_name(role,generation),basis['raw'][key])
            _immutable(store,_name('archive',generation),archive);_immutable(store,_name('view',generation),view)
            ticket=dict(schema='walden.follow.current-recovery-ticket/1',generation=generation,files={str(store.path(_name(role,generation))):_pin(store.path(_name(role,generation)))for role in ('view','archive','old-plan','old-owner','old-receipt')})
            _immutable(store,_name('ticket',generation),ticket)
        latest,_,_=_facts(profile,store,run,basis);_same(latest,facts,store);_need(kernel.boot_session()==boot)
        return dict(state='current_recovery_witness_created',witness_id=generation,witness_fingerprint=digest(_pin(ticket_path)),
                    historical_submission='unknown',historical_sql='unknown',historical_object_continuity='unproven',source_authority=False)


def _load(store,generation,fingerprint):
    _need(_hex(fingerprint));ticket_path=store.path(_name('ticket',generation));_need(digest(_pin(ticket_path))==fingerprint)
    ticket=_read_optional(store,ticket_path.name);_need(ticket.get('schema')=='walden.follow.current-recovery-ticket/1'and ticket.get('generation')==generation)
    expected={str(store.path(_name(role,generation)))for role in ('view','archive','old-plan','old-owner','old-receipt')}
    _need(set(ticket['files'])==expected)
    for path,pin in ticket['files'].items():_need(_pin(path)==pin)
    view=_read_optional(store,_name('view',generation));_need(view.get('schema')=='walden.follow.current-recovery-view/1'and view.get('generation')==generation
        and view.get('store_root')==str(store.root)and view.get('source_authority')is False and legacy._hex(view.get('terminal_nonce')))
    return dict(ticket=ticket,view=view,fingerprint=fingerprint)


def _basis_from_view(store,view):
    x=view['original']
    return _basis(store,Path(view['profile']),x['source_sha256'],x['generation'],x['plan_sha256'],x['owner_sha256'],Path(x['receipt_path']),x['receipt_sha256'])


def _current_proof(store,runtime,*,require_current=True):
    proof=runtime.get('current_recovery');_need(type(proof)is dict)
    loaded=_load(store,proof['generation'],proof['witness_fingerprint']);v=loaded['view'];g=v['generation']
    seal=_read_optional(store,_name('seal',g));receipt=_read_optional(store,_name('proof',g));completed=_read_optional(store,_name('completed',g))
    _need(type(seal)is dict and type(receipt)is dict)
    for path,pin in seal['files'].items():_need(_pin(path)==pin)
    _need(receipt.get('terminal_sha256')==digest(runtime)and receipt.get('witness_fingerprint')==proof['witness_fingerprint']
          and runtime['operation']==v['terminal_nonce']and receipt.get('old_boot')==v['old_boot']
          and receipt.get('new_boot')==v['boot']and v['boot']!=v['old_boot']
          and completed==dict(schema='walden.follow.current-recovery-completed/1',proof_sha256=digest(receipt),seal_sha256=digest(seal)))
    if require_current:
        _need(_read_optional(store,'current.json')==dict(nonce=runtime['operation'])and _pin(store.path('current.json'))==seal['current_pin'])
        expected=v['current'];_need(_dir(Path(expected['home']['path']))==expected['home']['identity'])
        for path,pin in expected['directories'].items():_need(_dir(path)==pin)
        for path,pin in expected['locks'].items():_need(_pin(path)==pin)
        for path,pin in expected['files'].items():
            if Path(path)not in (store.path('intent.json'),store.path('current.json')):_need(_pin(path)==pin)
        basis=_basis_from_view(store,v)
        for role,pin in expected['basis'].items():_need(_pin(basis['paths'][role])==pin)
        c=load_source_config(Path(v['profile']),physical=False)
        _need(digest(scope.query_scope_guard(c))==expected['scope_sha256']and _read_optional(store,'intent.json')==dict(enabled=False,generation=g))
    return True


def _current_status(store,runtime,run):
    current_proof(store,runtime);loaded=_load(store,runtime['current_recovery']['generation'],runtime['current_recovery']['witness_fingerprint']);v=loaded['view']
    _need(run.context==runtime.get('context')or schedule._retired_context_delta(runtime.get('context'),run.context))
    policy=_read_optional(store,'policy.'+v['generation']+'.json');old=_read_optional(store,'instance.'+v['old_instance']+'.json')
    c=load_source_config(Path(v['profile']),physical=False);label=schedule._schedule_label(c,old['segment']['descriptor'])
    for attempt in range(2):
        for name in (policy['label'],label):
            target=follow._target(run,name);_need(schedule._observe(run,target)=='absent'and run.pid(target)is None)
        _need(follow._material(policy)=='absent')
        for ext in ('.owned','.runtime','.plist','.active','.starting','.submission'):legacy._absent(Path(old['segment']['record']).with_suffix(ext))
        current_proof(store,runtime)
        if attempt==0:writer=schedule._writer_state(c)
    return writer


def _apply(profile_path,*,witness_id,witness_fingerprint,authorize=False,run=None,root=None,_checkpoint=lambda phase:None):
    _need(authorize is True);profile=Path(profile_path).absolute();store=Store(root or default_root(profile));run=run or schedule.LaunchctlTransport()
    loaded=_load(store,witness_id,witness_fingerprint);v=loaded['view'];g=v['generation'];_need(v['profile']==str(profile))
    c=_reading_config.get();_need(c is not None)
    with _locks(store,Path(c['mirror_root'])):
        completed=_read_optional(store,_name('completed',g))
        if completed is not None:
            original=_read_optional(store,'instance.'+v['terminal_nonce']+'.json');current_proof(store,original,require_current=False)
            return dict(state='already_recovered_no_republication',current_state_not_rewritten=True,source_authority=False)
        boot=kernel.boot_session();_need(boot==v['boot']and boot!=v['old_boot'])
        basis=_basis_from_view(store,v);published=_read_optional(store,'current.json')==dict(nonce=v['terminal_nonce'])
        old=_read_optional(store,'instance.'+v['old_instance']+'.json')
        terminal=dict(old,operation=v['terminal_nonce'],context=dict(v['current']['context']),admission=False,state='disabled',segment=None,
            grant_nonce=None,unsettled_activity=None,retirement_pending=None,activity_stop_confirmed=True,source_schedule=None,
            observed_catchup_complete=None,observed_as_of=None,catchup_pending=True,pending_reasons=['historical_outcome_unknown'],
            current_recovery=dict(generation=g,witness_fingerprint=witness_fingerprint,historical_object_continuity='unproven',historical_submission='unknown',historical_sql='unknown'))
        terminal.pop('legacy_retirement',None)
        now,_,_=_facts(profile,store,run,basis,terminal=terminal if published else None);_same(now,v['current'],store,published=published)
        receipt=dict(schema='walden.follow.current-recovery-proof/1',witness_fingerprint=witness_fingerprint,old_boot=v['old_boot'],new_boot=boot,
                     terminal_sha256=digest(terminal),source_authority=False,historical_submission='unknown',historical_sql='unknown',historical_object_continuity='unproven')
        if not published:
            for name,value in (('instance.'+v['terminal_nonce']+'.json',terminal),(_name('proof',g),receipt)):
                if _read_optional(store,name)is None:_immutable(store,name,value)
                else:_need(_read_optional(store,name)==value)
            oldcopy=store.path(_name('old-current',g));staged=store.path(_name('current',g));raw=_raw(store.path('current.json'))
            if not oldcopy.exists():_create_raw(store,oldcopy.name,raw)
            _need(_raw(oldcopy)==raw)
            if not staged.exists():_immutable(store,staged.name,dict(nonce=v['terminal_nonce']))
            wanted=dict(schema='walden.follow.current-recovery-seal/1',files={str(p):_pin(p)for p in (store.path(_name('ticket',g)),store.path('instance.'+v['terminal_nonce']+'.json'),store.path(_name('proof',g)),oldcopy)},current_pin=_pin(staged))
            if _read_optional(store,_name('seal',g))is None:_immutable(store,_name('seal',g),wanted)
            else:_need(_read_optional(store,_name('seal',g))==wanted)
            _checkpoint('prepared');_load(store,g,witness_fingerprint);fresh,_,_=_facts(profile,store,run,basis);_same(fresh,now,store);_need(kernel.boot_session()==boot)
            seal=_read_optional(store,_name('seal',g))
            for path,pin in seal['files'].items():_need(_pin(path)==pin)
            _need(_pin(staged)==seal['current_pin']);os.replace(staged,store.path('current.json'));schedule._sync_dir(store.root);_checkpoint('published')
        _need(kernel.boot_session()==boot);_load(store,g,witness_fingerprint);_need(_read_optional(store,'instance.'+v['terminal_nonce']+'.json')==terminal and _read_optional(store,_name('proof',g))==receipt)
        seal=_read_optional(store,_name('seal',g))
        for path,pin in seal['files'].items():_need(_pin(path)==pin)
        _need(_pin(store.path('current.json'))==seal['current_pin'])
        after,_,_=_facts(profile,store,run,basis,terminal=terminal);_same(after,v['current'],store,published=True);_need(kernel.boot_session()==boot)
        _immutable(store,_name('completed',g),dict(schema='walden.follow.current-recovery-completed/1',proof_sha256=digest(receipt),seal_sha256=digest(seal)))
        current_proof(store,terminal)
        return dict(state='current_state_recovered',disabled_confirmed=True,source_authority=False,historical_submission='unknown',historical_sql='unknown',historical_object_continuity='unproven')

def plan(profile_path,**kwargs):
    try:
        with _guarded(profile_path,kwargs.get('root')or default_root(profile_path)):
            return _plan(profile_path,**kwargs)
    except (KeyError,TypeError,AttributeError,ValueError):
        raise MirrorError('follow_current_recovery_unproven') from None


def apply(profile_path,**kwargs):
    try:
        with _guarded(profile_path,kwargs.get('root')or default_root(profile_path)):
            return _apply(profile_path,**kwargs)
    except (KeyError,TypeError,AttributeError,ValueError):
        raise MirrorError('follow_current_recovery_unproven') from None


def current_proof(store,runtime,*,require_current=True,profile_path=None):
    if _reading_config.get()is not None:return _current_proof(store,runtime,require_current=require_current)
    _need(profile_path is not None)
    with _guarded(profile_path,store.root):return _current_proof(store,runtime,require_current=require_current)


def current_status(store,runtime,run,*,profile_path):
    with _guarded(profile_path,store.root):return _current_status(store,runtime,run)

from .failure_evidence import _register
_register(_need,_locations,_protected_ids,_read_input,_raw,_pin,_dir,_json,_read_optional,_name,_basis,_facts,_same,_create_raw,_immutable,_plan,plan,_load,_basis_from_view,_current_proof,current_proof,_current_status,current_status,_apply,apply)
