"""Explicit one-target current qualification; never evidence of old continuity."""
import contextlib,json,os,pwd,re,stat,uuid
from pathlib import Path
from .native_mirror_store import MirrorError
from . import native_scope_contract as sc,native_account_copy_init as ci
from .native_follow_policy import digest
from .native_follow_identity import _volume
SCHEMA='walden.account.current-copy-reconcile/2'

def need(ok):
    if not ok:raise MirrorError('account_reconcile_current_unproven')

def ident(fd,path):
    node=os.fstat(fd);named=Path(path).lstat();birth=getattr(node,'st_birthtime',None)
    need((node.st_dev,node.st_ino)==(named.st_dev,named.st_ino)and node.st_uid==os.getuid()
         and type(birth)is float and birth>0 and not node.st_mode&0o022
         and stat.S_IFMT(node.st_mode) in (stat.S_IFREG,stat.S_IFDIR))
    if stat.S_ISREG(node.st_mode):need(node.st_nlink==1)
    return dict(volume_uuid=_volume(fd),inode=node.st_ino,birthtime_hex=birth.hex(),kind=stat.S_IFMT(node.st_mode),uid=node.st_uid,mode=stat.S_IMODE(node.st_mode))

@contextlib.contextmanager
def opened(path,config,*,directory=False,expected=None):
    path=Path(path);need(path.is_absolute()and path.resolve()==path)
    named=path.lstat();need(stat.S_ISDIR(named.st_mode)if directory else stat.S_ISREG(named.st_mode))
    if not directory:
        from .native_follow_current_recovery import _protected_ids
        need((named.st_dev,named.st_ino)not in _protected_ids(config))
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        pin=ident(fd,path);need(pin==expected if expected is not None else True)
        yield fd,pin
        need(ident(fd,path)==pin)
    finally:os.close(fd)

def pin(path,config,*,directory=False):
    with opened(path,config,directory=directory)as(fd,value):return value

def roots(config):
    home=Path(pwd.getpwuid(os.getuid()).pw_dir).absolute();need(home.resolve()==home)
    return dict(home=home,mirror=Path(config['mirror_root']),message=Path(config['message_root']),live=Path(config['live_db_root']))

def validate_roots(config,confirmation,budget=None):
    if budget is not None:ci.charge(budget,1024)
    values={k:pin(p,config,directory=True)for k,p in roots(config).items()}
    need(values==confirmation['roots'])
    need(len({v['volume_uuid']for v in values.values()})==1)
    return values['home']['volume_uuid']

def decode(config,value,raw):
    from . import native_account_reconcile as repair
    need(type(value)is dict and set(value)=={'schema','legacy_raw','legacy_sha256','confirmation'})
    need(value['schema']==SCHEMA and type(value['legacy_raw'])is str)
    old=value['legacy_raw'].encode();need(sc.sha(old)==value['legacy_sha256'])
    legacy=repair.decode_legacy(config,old);c=value['confirmation']
    need(type(c)is dict and set(c)in ({'profile','profile_sha256','source_sha256','scope_sha256','target_ref','generation','roots','local','authority','continuity'},{'profile','profile_sha256','source_sha256','scope_sha256','target_ref','generation','roots','local','authority','continuity','withheld_refs'}))
    withheld_refs(c.get('withheld_refs',[]),legacy['target_ref'])
    need(c['source_sha256']==digest(config)and c['scope_sha256']==sc.digest(sc.fixed(config))
         and c['target_ref']==legacy['target_ref']and c['generation']==legacy['generation']
         and c['authority']=='current_target_and_shard_identity_only'and c['continuity']=='unknown')
    return dict(legacy,request_sha256=sc.sha(raw),_current=c,_legacy_sha256=value['legacy_sha256'])

def profile_check(config,c,budget=None):
    from .native_follow_current_recovery import _read_input
    size=Path(c['profile']).lstat().st_size
    if budget is not None:ci.charge(budget,size+128)
    raw,_=_read_input(Path(c['profile']),config);need(len(raw)==size)
    need(sc.sha(raw)==c['profile_sha256']and json.loads(raw)==config)

def withheld_refs(refs,target):
    need(type(refs)in (list,tuple)and len(refs)<=2 and len(set(refs))==len(refs))
    need(all(type(r)is str and re.fullmatch("[0-9a-f]{64}",r)and r!=target for r in refs))
    return sorted(refs)

def confirm(config,profile,target,expected,withheld=()):
    withheld=withheld_refs(withheld,target)
    from . import native_account_reconcile as repair
    root=Path(config['mirror_root']);raw,fact=sc.read(root/repair.NAME)
    value=json.loads(raw)
    if value.get('schema')==SCHEMA:
        request=decode(config,value,raw);need(request['_legacy_sha256']==expected and request['target_ref']==target)
        profile_check(config,request['_current']);need(request['_current'].get('withheld_refs',[])==withheld)
        return dict(status='current_qualification_requested',target_ref=target,source_opens=0,request_sha256=sc.sha(raw),prior_coverage_unknown=True)
    need(sc.sha(raw)==expected);request=repair.decode_legacy(config,raw);need(request['target_ref']==target)
    budget=__import__(__package__+'.native_mirror_sync',fromlist=['_account_budget'])._account_budget(config);budget['tail_probe']=dict(bytes=0,ceiling=1048576)
    with sc.registry(config,snapshot=False)as registry:
        need(ci.read(registry,request['shard'],request['table'],budget)is None)
        member=repair.member(config,registry,request['shard'],request['table'],budget)
        need(all(member[k]==request['proof'][k]for k in ('ref','schema_sha256','header'))and member['source_identity'][1]==request['proof']['source_identity'][1])
        need(member.get('supported')is True and member.get('available')is True)
        for ref in withheld:
            rows=registry.execute("SELECT table_name FROM members WHERE shard=? AND json_extract(proof,'$.ref')=? LIMIT 2",(request['shard'],ref)).fetchall()
            need(len(rows)==1);table=rows[0][0];other=repair.member(config,registry,request['shard'],table,budget)
            need(other['ref']==ref and other.get('supported')is True and other.get('available')is True and ci.read(registry,request['shard'],table,budget)is None)
            repair.absent(config,request['shard'],table)
    repair.absent(config,request['shard'],request['table'])
    from .native_shard_restore import _layout
    _layout(config)
    rootpins={k:pin(p,config,directory=True)for k,p in roots(config).items()};need(len({v['volume_uuid']for v in rootpins.values()})==1)
    local=pin(root/request['shard'],config);need(local['volume_uuid']==rootpins['home']['volume_uuid'])
    from .native_follow_current_recovery import _read_input
    profile_raw,_=_read_input(Path(profile).absolute(),config)
    c=dict(profile=str(Path(profile).absolute()),profile_sha256=sc.sha(profile_raw),source_sha256=digest(config),scope_sha256=sc.digest(sc.fixed(config)),target_ref=target,generation=request['generation'],roots=rootpins,local=local,authority='current_target_and_shard_identity_only',continuity='unknown',withheld_refs=withheld)
    profile_check(config,c);before=sc.query_scope_guard(config)
    archive=root/('.account-copy-reconcile.previous.'+expected+'.json')
    if archive.exists():need(sc.read(archive)[0]==raw)
    else:sc.create(archive,raw)
    new=dict(schema=SCHEMA,legacy_raw=raw.decode(),legacy_sha256=expected,confirmation=c);encoded=sc.encoded(new);need(len(encoded)<=16384)
    temp=root/('.account-copy-reconcile.current.'+uuid.uuid4().hex+'.json');sc.create(temp,encoded)
    try:
        need(sc.read(root/repair.NAME)==(raw,fact));validate_roots(config,c);need(pin(root/request['shard'],config)==local)
        repair.absent(config,request['shard'],request['table']);sc.query_scope_guard(config,before)
        os.replace(temp,root/repair.NAME)
        from .native_schedule import _sync_dir
        _sync_dir(root)
    finally:
        if temp.exists():temp.unlink()
    return dict(status='current_qualification_requested',target_ref=target,source_opens=0,request_sha256=sc.sha(encoded),prior_coverage_unknown=True)

def key(request):return 'reconcile_current:'+request['request_sha256']

def state(registry,request,budget):
    row=registry.execute('SELECT length(CAST(value AS BLOB))FROM state WHERE key=?',(key(request),)).fetchone();ci.charge(budget,16)
    if row is None:return None
    need(row[0]<=4096);ci.charge(budget,row[0]);value=sc.state(registry,key(request))
    need(value.get('request_sha256')==request['request_sha256']and value.get('generation')==request['generation']and value.get('target_ref')==request['target_ref'])
    return value

def local_check(config,request,budget=None):
    c=request['_current'];profile_check(config,c,budget);volume=validate_roots(config,c,budget)
    if budget is not None:ci.charge(budget,256)
    path=Path(config['mirror_root'])/request['shard']
    with opened(path,config,expected=c['local'])as(fd,value):
        need(value['volume_uuid']==volume);node=os.fstat(fd);return[node.st_dev,node.st_ino]

def pending(config,registry,request,budget):
    from . import native_account_reconcile as repair
    value=ci.read(registry,request['shard'],request['table'],budget)
    if value is not None:
        need(value.get('generation')==request['generation']and value.get('reconcile_request_sha256')==request['request_sha256']and value.get('prior_coverage_unknown')is True)
        if value['status']=='completed':ci.completed_binding(config,request['proof'],value);return None
    local=local_check(config,request,budget);proof=repair.member(config,registry,request['shard'],request['table'],budget)
    need(all(proof[k]==request['proof'][k]for k in ('ref','header','schema_sha256'))and proof['source_identity'][1]==request['proof']['source_identity'][1])
    current=state(registry,request,budget)
    if value is None:repair.absent(config,request['shard'],request['table'])
    elif current is not None:
        node=(Path(config['message_root'])/request['shard']).lstat()
        if value['local']==local and current['physical_source']==[node.st_dev,node.st_ino]and value['proof']==ci.binding(config,proof):
            # Original receipt validates owned progress/table/observed below.
            effective=dict(request,local=local,proof=ci.binding(config,proof));return repair.pending_legacy(config,registry,effective,budget)
    source_node=(Path(config['message_root'])/request['shard']).lstat()
    needed=current is None or current.get('physical_source')!=[source_node.st_dev,source_node.st_ino]
    return dict(request,local=local,_qualification_needed=needed)

def _checkpoint(stage):pass

@contextlib.contextmanager
def source_guard(config,request,budget,expected=None):
    c=request['_current'];volume=validate_roots(config,c,budget);path=Path(config['message_root'])/request['shard']
    with opened(path,config,expected=expected)as(fd,source):
        need(source['volume_uuid']==volume and source['inode']==request['proof']['source_identity'][1])
        def check():
            from .native_deadline import check_deadline
            check_deadline();ci.charge(budget,256)
            need(ident(fd,path)==source);local_check(config,request,budget)
            from . import native_account_reconcile as repair
            request_path=Path(config['mirror_root'])/repair.NAME;size=request_path.lstat().st_size;need(size<=16384);ci.charge(budget,size+64)
            body=sc.read(request_path)[0];need(len(body)==size)
            need(sc.sha(body)==request['request_sha256'])
        check();yield fd,source,check;check()

def _qualify(config,registry,request,budget,deadline,connection_factory,result):
    """Only real active consume calls this; connection/DDL precede new authority."""
    from . import native_account_reconcile as repair,native_mirror_sync as sync
    from .native_deadline import _current
    from .native_follow_grant import FollowDeadline
    from .native_follow_policy import Store
    need(isinstance(deadline,FollowDeadline)and _current.get()is deadline and deadline.grant.get('kind')=='active'and deadline.grant.get('source_sha256')==digest(config))
    deadline.check()
    policy=Store(deadline.grant['store_root']).read('policy.'+deadline.grant['policy_generation']+'.json')
    need(policy is not None and policy.get('profile_path')==request['_current']['profile']and policy.get('source_signature')==digest(config))
    prior=state(registry,request,budget);ticket=admission(registry,request,budget)
    need(ticket is None or ticket.get('phase')!='blocked')
    expected=prior['source']if prior else ticket.get('source')if ticket else None
    with source_guard(config,request,budget,expected)as(fd,source,check):
        if ticket is None:
            ticket=dict(request_sha256=request['request_sha256'],legacy_sha256=request['_legacy_sha256'],target_ref=request['target_ref'],generation=request['generation'],phase='bound',source=source,authority='tentative_object_only')
            ci.charge(budget,len(sc.encoded(ticket)));sc.save(registry,admission_key(request),ticket)
            check();sync._account_registry_commit(registry,config=config,budget=budget);check()
        path=Path(config['message_root'])/request['shard'];node=os.fstat(fd);physical=[node.st_dev,node.st_ino]
        ci.charge(budget,16);os.lseek(fd,0,os.SEEK_SET);need(sc.sha(os.read(fd,16))==request['proof']['header'])
        conn=connection_factory(path);result['source_attempts']+=1;result['source_opens']+=1
        try:
            conn.set_progress_handler(lambda:int(time_monotonic()>=budget['until']),1000)
            ci.charge(budget,16);need(conn.execute('PRAGMA query_only').fetchone()==(1,));conn.execute('BEGIN')
            size=sync._account_source_read(conn,"SELECT length(CAST(sql AS BLOB))FROM sqlite_master WHERE type='table'AND name=?",(request['table'],),stage='source_copy').fetchone();need(size is not None);ci.charge(budget,size[0])
            ddl=sync._account_source_read(conn,"SELECT sql FROM sqlite_master WHERE type='table'AND name=?",(request['table'],),stage='source_copy').fetchone()
            need(ddl is not None and len(ddl[0].encode())==size[0]and sc.sha(ddl[0].encode())==request['proof']['schema_sha256']);check()
            cookie=conn.execute('PRAGMA schema_version').fetchone()
            object_check=check
            def check():
                object_check();ci.charge(budget,24+len(ddl[0].encode()))
                need(conn.execute('PRAGMA query_only').fetchone()==(1,)and conn.execute('PRAGMA schema_version').fetchone()==cookie
                     and sync._account_source_read(conn,"SELECT sql FROM sqlite_master WHERE type='table'AND name=?",(request['table'],),stage='source_copy').fetchone()==ddl)
            receipt=dict(request_sha256=request['request_sha256'],generation=request['generation'],target_ref=request['target_ref'],source=source,physical_source=physical,local=request['_current']['local'],history_continuity='unknown',authority='only_requested_copy')
            ci.charge(budget,len(sc.encoded(receipt))+512)
            _checkpoint('qualified_before_commit')
            anchor=sc.state(registry,'shard_anchor:'+request['shard'])
            need(anchor['source_identity'][1]==source['inode']and anchor['header']==request['proof']['header'])
            def publish(raw):
                check()
                if ci.read(raw,request['shard'],request['table'],budget)is None:repair.absent(config,request['shard'],request['table'])
                sc.save(raw,key(request),receipt)
                value=ci.read(raw,request['shard'],request['table'],budget)
                if value is not None and value['status']=='prepared':
                    need(value['generation']==request['generation']and value.get('reconcile_request_sha256')==request['request_sha256'])
                    value['local']=local_check(config,request);value['proof']['source_identity']=physical;ci.save(raw,value,budget)
            if anchor['source_identity']!=physical:
                registry.commit();registry.suspend(atomic=True);owner=registry.owner
                try:
                    sync._auto_reanchor_renumbered_shard(config,registry.raw,path,anchor,physical,anchor['header'],budget=budget,_qualified_check=check,_qualified_publish=publish)
                except BaseException:
                    try:registry._begin()
                    except BaseException:pass
                    raise
                else:registry._begin()
            else:
                registry.execute('SAVEPOINT reconcile_current')
                try:publish(registry);check()
                except BaseException:
                    registry.execute('ROLLBACK TO reconcile_current');registry.execute('RELEASE reconcile_current');raise
                registry.execute('RELEASE reconcile_current');sync._account_registry_commit(registry,config=config,budget=budget);check()
            _checkpoint('qualified_committed');return receipt
        finally:conn.set_progress_handler(None,0);conn.close()

def time_monotonic():
    import time
    return time.monotonic()

@contextlib.contextmanager
def copy_guard(config,registry,path,table,budget):
    from . import native_account_reconcile as repair
    request=repair.read(config,budget)
    if request is None or '_current'not in request or(request['shard'],request['table'])!=(path.name,table):yield None;return
    value=ci.read(registry,path.name,table,budget)
    if value is None or value['status']=='completed':yield None;return
    proof=state(registry,request,budget);need(proof is not None)
    with source_guard(config,request,budget,proof['source'])as(fd,source,check):yield check

def schedule_admission(config,runtime,policy):
    """Consume one explicit request token, never a general retry reset."""
    from . import native_account_reconcile as repair
    if runtime.get('segment')or runtime.get('unsettled_activity')or runtime.get('retirement_pending'):return None
    request=repair.read(config)
    if request is None or '_current'not in request:return None
    token=request['request_sha256'];old=runtime.get('reconcile_current_admission')or{}
    if old.get('token')==token:return None
    with sc.registry(config,snapshot=False)as ledger:
        b=dict(tail_probe=dict(bytes=0,ceiling=1048576))
        done=ci.read(ledger,request['shard'],request['table'],b)
        if done is not None and done['status']=='completed':
            need(done.get('generation')==request['generation']and done.get('reconcile_request_sha256')==token);return None
        ticket=admission(ledger,request,b)
    c=request['_current'];need(c['profile']==policy['profile_path']and policy['source_signature']==digest(config))
    local_check(config,request)
    prior=runtime.get('source_schedule')or{};updated=dict(prior)
    if ticket is not None and ticket.get('phase')=='blocked':
        if prior.get('mode')not in ('blocked','backoff')or prior.get('failure_reason')in ('account_reconcile_source_conflict','account_reconcile_current_unproven'):
            updated.update(mode='blocked',failure_reason='account_reconcile_current_unproven',next_due_at_ns=None,next_due_continuous_ns=None,due=False)
    elif ticket is None and prior.get('mode')=='blocked'and prior.get('failure_reason')=='account_reconcile_source_conflict':
        from .native_deadline import continuous_ns
        import time
        updated.update(mode='normal',next_due_at_ns=time.time_ns(),next_due_continuous_ns=continuous_ns(),due=True)
    # Other failure/backoff clocks and completion/error evidence are untouched.
    return dict(source_schedule=updated,reconcile_current_admission=dict(token=token,legacy_sha256=request['_legacy_sha256'],target_ref=request['target_ref'],profile_sha256=c['profile_sha256'],scope_sha256=c['scope_sha256'],prior_schedule=prior))


def admission_key(request):return 'reconcile_qualification:'+request['request_sha256']

def admission(registry,request,budget):
    row=registry.execute('SELECT length(CAST(value AS BLOB))FROM state WHERE key=?',(admission_key(request),)).fetchone();ci.charge(budget,16)
    if row is None:return None
    need(row[0]<=4096);ci.charge(budget,row[0]);v=sc.state(registry,admission_key(request))
    need(v.get('request_sha256')==request['request_sha256']and v.get('legacy_sha256')==request['_legacy_sha256']and v.get('generation')==request['generation']and v.get('target_ref')==request['target_ref']and v.get('phase')in ('bound','blocked'))
    return v

def qualify(config,registry,request,budget,deadline,connection_factory,result):
    from .native_deadline import _current
    from .native_follow_grant import FollowDeadline
    from .native_account_witness import WorkChanged
    need(isinstance(deadline,FollowDeadline)and _current.get()is deadline and deadline.grant.get('kind')=='active'and deadline.grant.get('source_sha256')==digest(config))
    deadline.check()
    try:return _qualify(config,registry,request,budget,deadline,connection_factory,result)
    except MirrorError as error:
        if isinstance(error,WorkChanged):raise
        from .native_follow_schedule import failure_details
        if failure_details([str(error)])['failure_class']=='permanent':
            # Best effort under the original mandatory guard only; never mask
            # the original error or claim a failed publication succeeded.
            try:
                deadline.check();old=admission(registry,request,budget)or dict(request_sha256=request['request_sha256'],legacy_sha256=request['_legacy_sha256'],target_ref=request['target_ref'],generation=request['generation'],source=None)
                old.update(phase='blocked',authority='none',failure_reason='account_reconcile_current_unproven')
                ci.charge(budget,len(sc.encoded(old)));sc.save(registry,admission_key(request),old)
                from .native_mirror_sync import _account_registry_commit
                _account_registry_commit(registry,config=config,budget=budget)
            except Exception:pass
        raise


def withheld(config,registry,request,path,table,proof,conn,identity,ddl,budget):
    """Only explicit refs, with fresh positive identity and absence: no write grant."""
    if request is None or proof['ref']not in request['_current'].get('withheld_refs',[]):return False
    from . import native_account_reconcile as repair
    from .native_deadline import _current
    from .native_follow_grant import FollowDeadline
    deadline=_current.get()
    need(isinstance(deadline,FollowDeadline)and deadline.grant.get('kind')=='active'and deadline.grant.get('source_sha256')==digest(config))
    deadline.check();sc.query_scope_guard(config)
    need(path.name==request['shard']and table!=request['table']and proof.get('supported')is True and proof.get('available')is True)
    positive=state(registry,request,budget);need(positive is not None)
    with source_guard(config,request,budget,positive['source'])as(fd,_pin,check):
        node=os.fstat(fd);need([node.st_dev,node.st_ino]==identity==proof['source_identity'])
        ci.charge(budget,16+len(ddl.encode())+32);os.lseek(fd,0,os.SEEK_SET)
        need(sc.sha(os.read(fd,16))==proof['header']and sc.sha(ddl.encode())==proof['schema_sha256'])
        need(conn.execute('PRAGMA query_only').fetchone()==(1,))
        need(conn.execute("SELECT sql FROM sqlite_master WHERE type='table'AND name=?",(table,)).fetchone()==(ddl,))
        need(ci.read(registry,path.name,table,budget)is None)
        need(repair.absent(config,path.name,table)==local_check(config,request,budget))
        check();sc.query_scope_guard(config);deadline.check()
    return True

def ordinary_check(config,registry,request,path,budget):
    # A historical target receipt is not this ongoing classification's current
    # Source proof. Reject wrong objects before the ordinary Source body open.
    if request is None or not request['_current'].get('withheld_refs')or path.name!=request['shard']:return
    positive=state(registry,request,budget);need(positive is not None)
    sc.query_scope_guard(config)
    with source_guard(config,request,budget,positive['source']):pass
