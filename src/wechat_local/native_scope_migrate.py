"""Finite selected-to-account mode migration, local typed preservation only.

No Source/key open, no service submission/removal, no automatic reverse migration.
Original scope-add proof/actor files remain byte-for-byte historical objects.
"""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import uuid
from . import native_scope_contract as sc
from . import native_scope_add as old
from .native_mirror_store import MirrorError
from .live_readonly import readonly_database_uri


def _replace(path,data,expected):
    path=Path(path)
    with old.directory(path.parent) as parent:
        prior=sc._optional(path);old.need(prior==expected,'account_migration_cas')
        temp=path.with_name('.account-mode-'+uuid.uuid4().hex+'.tmp');old.create(temp,data)
        old.need(sc._optional(path)==expected,'account_migration_cas')
        os.replace(temp.name,path.name,src_dir_fd=parent,dst_dir_fd=parent);os.fsync(parent)


def _schema(path):
    conn=sqlite3.connect(readonly_database_uri(path),uri=True)
    try:
        conn.execute('PRAGMA query_only=ON');conn.execute('BEGIN')
        return old.effects(conn)
    finally:conn.close()


def summaries(config):
    """Exact typed row/rowid+schema summary, not file SHA or count alone."""
    from .native_deadline import check_deadline
    root=Path(config['mirror_root']);values={}
    names=sorted([p.name for p in root.glob('message_*.db')]+[p.name for p in root.glob('biz_message_*.db')])
    names+=[n for n in ('contact.db','session.db','media-work.sqlite','__walden_status.db') if (root/n).is_file()]
    for name in names:
        check_deadline();path=root/name;sc._safe(path);values[name]=_schema(path)
    derived={}
    for directory in ('media-images','media-audio','media-ocr'):
        parent=root/directory
        if not parent.exists():continue
        old.need(not parent.is_symlink(),'account_migration_unsafe_derived')
        for path in sorted(parent.glob('**/*')):
            old.need(not path.is_symlink(),'account_migration_unsafe_derived')
            if path.is_file():
                check_deadline();sc._safe(path)
                with path.open('rb') as stream:
                    import hashlib
                    h=hashlib.sha256()
                    for block in iter(lambda:stream.read(1024*1024),b''):check_deadline();h.update(block)
                derived[str(path.relative_to(root))]=h.hexdigest()
    return dict(schema='walden.account.preservation/1',databases=values,derived=derived)


def _plan(path,expected):
    raw,fact=old.read(path);old.need(expected is not None and sc.sha(raw)==expected,'account_migration_plan_pin')
    p=json.loads(raw);old.need(p.get('schema')=='walden.account.migration.plan/1'
        and p.get('tool_sha256')==sc.sha(Path(__file__).read_bytes()),'account_migration_plan_invalid')
    return p,raw


def plan(profile,path):
    from .source_setup import load_source_config
    profile=Path(profile).absolute();path=Path(path).absolute();config=load_source_config(profile,physical=False)
    old.need(sc.mode(config)=='selected','account_migration_selected_required');sc.query_scope_guard(config)
    root=Path(config['mirror_root']);old.need(sc._optional(root/sc.CURRENT) is None,'account_migration_already_account');sc._pending(root)
    raw,fact=old.read(profile);new=dict(config);new.pop('mirror_scope');new.update(mirror_scope_mode='account',scope_contract_id=uuid.uuid4().hex)
    store,follow=old._follow(profile,config)
    policy=store.read('policy.'+follow['generation']+'.json');runtime=store.read('instance.'+follow['nonce']+'.json')
    legacy=sc._optional(root/'.scope-add.current');legacy_receipt=None
    if legacy is not None:legacy_receipt=sc.sha(old.read(json.loads(legacy)['receipt'])[0])
    summary=summaries(config)
    facts={name:dict(identity=list(sc._safe(root/name)),size=(root/name).stat().st_size) for name in summary['databases']}
    p=dict(schema='walden.account.migration.plan/1',profile=str(profile),old_config=config,new_config=new,
        old_config_hex=raw.hex(),new_config_hex=sc.encoded(new).hex(),old_profile=fact,contract=sc.fixed(new),
        legacy_current_sha256=sc.sha(legacy) if legacy is not None else None,legacy_receipt_sha256=legacy_receipt,
        preservation=summary,databases=facts,follow=follow,policy=policy,runtime=runtime,
        state_root=str(path.with_suffix('.attempt')),tool_sha256=sc.sha(Path(__file__).read_bytes()))
    old.create(path,sc.encoded(p))
    return dict(status='planned',plan=str(path),plan_sha256=sc.sha(sc.encoded(p)),preservation=summary,source_opened=False)


def _control_facts(p,run):
    """Local immutable control image; no config loader, Source or authority mint."""
    from . import native_follow as f
    from . import native_schedule as sdk
    config=p['old_config'];profile=Path(p['profile']);store=f.Store(f.default_root(profile))
    intent,policy=f._policy(store);runtime=f._runtime(store)
    old.need(policy==p['policy'] and runtime.get('operation')==p['follow']['nonce']
        and runtime==p['runtime'] and intent.get('enabled') is False,'account_migration_follow_changed')
    paths=[store.path('intent.json'),store.path('current.json'),store.path('policy.'+p['follow']['generation']+'.json'),
        store.path('instance.'+p['follow']['nonce']+'.json'),Path(policy['snapshot'])]
    slot=None;worker=None
    if runtime.get('segment'):
        descriptor=runtime['segment']['descriptor']
        label=sdk._schedule_label(config,descriptor);active=Path(runtime['services'])/(label+'.plist')
        slot=sdk._slot_view(active,archives=True)
        old.need(not active.exists(),'account_migration_active_slot')
        archives=list(active.parent.glob(active.name+'.disabled-*'))
        old.need(bool(archives),'account_migration_archive_required')
        def order(item):
            suffix=item.name[len(active.name+'.disabled-'):]
            old.need(suffix.isdecimal(),'account_migration_archive_invalid');return int(suffix)
        selected=max(archives,key=order);suffix=selected.name[len(active.name):]
        record=active.with_suffix('.owned').with_name(active.with_suffix('.owned').name+suffix)
        state=active.with_suffix('.runtime').with_name(active.with_suffix('.runtime').name+suffix)
        paths.extend([selected,record,state,Path(descriptor['path'])])
        raw,_=old.read(record);r=json.loads(raw);raw,_=old.read(state);worker=json.loads(raw)
        expected=run.context['domain']+'/'+str(run.context['uid'])+'/'+str(run.context['security_session'])+'/'+label
        old.need(r.get('target')==expected and r.get('os_context')==run.context and worker.get('operation')==r.get('operation')
            and worker.get('os_context')==run.context and worker.get('leader') is not None,'account_migration_worker_binding')
    files=[dict(path=str(path),fact=old.read(path)[1]) for path in paths]
    return json.loads(json.dumps(dict(files=files,slot=slot,listener=runtime['leader'],worker=worker,
        listener_target=f._target(run,policy['label']),worker_target=expected if worker is not None else None),sort_keys=True))


def _quiescent(p,*,initial=False,writer_held=False):
    """SDK authenticates free before pending; critical section owns exclusivity."""
    from . import native_follow as f
    from .native_schedule import LaunchctlTransport,_observe,_writer_state
    run=LaunchctlTransport();old.need(run.context==p['follow']['context'],'account_migration_context_changed')
    before=_control_facts(p,run)
    if initial:
        # The original SDK is used only while its normal loader and free-writer
        # prerequisites hold. This is neither a pending nor retired capability.
        proof=old.full_stop(Path(p['profile']),p['old_config'],p['follow'])
    else:
        proof=json.loads(old.read(Path(p['state_root'])/'quiescence.json')[0])
        old.need(proof.get('control')==before,'account_migration_control_changed')
    old.need(f.kernel.drained(before['listener']),'account_migration_group_not_drained')
    if before['worker'] is not None:old.need(run.process.drained(before['worker']['leader']),'account_migration_activity_not_drained')
    old.need(_observe(run,before['listener_target'])=='absent','account_migration_listener_not_absent')
    if before['worker_target'] is not None:old.need(_observe(run,before['worker_target'])=='absent','account_migration_worker_not_absent')
    if not writer_held:old.need(_writer_state(p['old_config'])=='free','account_migration_writer_busy')
    old.need(run.context==p['follow']['context'] and _control_facts(p,run)==before,'account_migration_control_changed')
    return dict(control=before,sdk_stop=proof if initial else proof.get('sdk_stop'),group_drained=True,
        writer_lock='owned_exclusive' if writer_held else 'free',context=run.context)


def _legacy(p):
    root=Path(p['old_config']['mirror_root']);raw=sc._optional(root/'.scope-add.current')
    old.need((sc.sha(raw) if raw is not None else None)==p['legacy_current_sha256'],'account_migration_legacy_changed')
    if raw is not None:
        current=json.loads(raw);receipt=old.read(current['receipt'])[0]
        old.need(sc.sha(receipt)==current['receipt_sha256']==p['legacy_receipt_sha256'],'account_migration_legacy_changed')


def _backup(p,root):
    target=Path(p['state_root'])
    if target.exists():
        complete=json.loads(old.read(target/'backup-complete.json')[0])
        old.need(complete.get('preservation')==p['preservation'] and complete.get('plan')==sc.digest(p),'account_migration_backup_invalid')
        old.need(old.read(target/'old-profile.json')[0]==bytes.fromhex(p['old_config_hex']),'account_migration_backup_invalid')
        for name in p['databases']:old.need(_schema(target/name)==p['preservation']['databases'][name],'account_migration_backup_changed')
        return
    target.mkdir(mode=0o700)
    old.create(target/'old-profile.json',bytes.fromhex(p['old_config_hex']))
    for name in p['databases']:
        source=root/name;sc._safe(source);destination=target/name
        fd=os.open(destination,os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW,0o600);os.close(fd)
        left=sqlite3.connect(readonly_database_uri(source),uri=True);right=sqlite3.connect(destination)
        try:left.execute('PRAGMA query_only=ON');left.backup(right);right.commit()
        finally:left.close();right.close()
        old.need(_schema(destination)==p['preservation']['databases'][name],'account_migration_backup_changed')
    old.create(target/'backup-complete.json',sc.encoded(dict(preservation=p['preservation'],plan=sc.digest(p))))


def _verify_backup(p):
    target=Path(p['state_root'])
    with old.directory(target) as parent:
        info=os.fstat(parent);old.need(info.st_uid==os.getuid() and info.st_mode&0o077==0,'account_migration_backup_invalid')
    allowed=set(p['databases'])|{'old-profile.json','backup-complete.json','quiescence.json','new-profile-stage.json','receipt.json','marker-pending.json','marker-receipt.json','marker-current.json','publications-prepared.json'}
    allowed.add('.receipt.json.stage-'+p['new_config'][sc.ID])
    old.need({v.name for v in target.iterdir()}<=allowed,'account_migration_backup_tree_changed')
    complete=json.loads(old.read(target/'backup-complete.json')[0])
    old.need(complete==dict(preservation=p['preservation'],plan=sc.digest(p)),'account_migration_backup_invalid')
    old.need(old.read(target/'old-profile.json')[0]==bytes.fromhex(p['old_config_hex']),'account_migration_backup_invalid')
    for name in p['databases']:
        path=target/name;sc._safe(path)
        conn=sqlite3.connect(readonly_database_uri(path),uri=True)
        try:
            conn.execute('PRAGMA query_only=ON');conn.execute('BEGIN')
            old.need(conn.execute('PRAGMA integrity_check').fetchall()==[('ok',)],'account_migration_backup_corrupt')
            old.need(old.effects(conn)==p['preservation']['databases'][name],'account_migration_backup_changed')
        finally:conn.close()


def _stable_fact(fact):
    return dict(sha256=fact['sha256'],parent=fact['parent'],stat={k:v for k,v in fact['stat'].items() if k not in ('ctime_ns',)})


def _marker(p,key,path,data,*,check=False,prepare=False):
    """One named migration marker; pinned staging inode survives rename crash."""
    journal=Path(p['state_root'])/('marker-'+key+'.json');path=Path(path)
    entry=sc._optional(journal)
    if entry is None:
        old.need(not check and sc._optional(path) is None,'account_migration_marker_unproven')
        stage=path.with_name('.'+path.name+'.stage-'+p['new_config'][sc.ID])
        old.need(not stage.exists(),'account_migration_prepare_unproven')
        fact=old.create(stage,data);entry=sc.encoded(dict(path=str(path),stage=str(stage),fact=fact))
        old.create(journal,entry)
    value=json.loads(entry);old.need(value['path']==str(path) and value['stage']==str(path.with_name('.'+path.name+'.stage-'+p['new_config'][sc.ID])),'account_migration_marker_changed')
    if prepare:
        old.need(sc._optional(path) is None and old.read(Path(value['stage']))==(data,value['fact']),'account_migration_marker_stage_changed');return
    # An exclusive hard-link publication may crash before unlinking its stage.
    # Recover only both exact names of the one pre-recorded inode, never unknowns.
    stage_path=Path(value['stage'])
    try:
        target_info=path.lstat();stage_info=stage_path.lstat()
    except FileNotFoundError:pass
    else:
        expected=value['fact']['stat']
        actual=old.identity(target_info)
        wanted={k:v for k,v in expected.items() if k not in ('ctime_ns','nlink')}
        old.need({k:v for k,v in actual.items() if k not in ('ctime_ns','nlink')}==wanted
            and old.identity(stage_info)==actual and actual['nlink']==2,'account_migration_marker_changed')
        with old.directory(path.parent) as parent:
            fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
            with os.fdopen(fd,'rb') as stream:raw=stream.read(4*1024*1024+1)
            old.need(raw==data and old.identity(path.lstat())==actual and old.identity(stage_path.lstat())==actual,'account_migration_marker_changed')
            os.unlink(stage_path.name,dir_fd=parent);os.fsync(parent)
    raw=sc._optional(path)
    if raw is not None:
        old.need(raw==data and _stable_fact(old.read(path)[1])==_stable_fact(value['fact']),'account_migration_marker_changed');return
    old.need(not check,'account_migration_marker_missing');stage=Path(value['stage'])
    old.need(old.read(stage)==(data,value['fact']),'account_migration_marker_stage_changed')
    with old.directory(path.parent) as parent:
        old.need(sc._optional(path) is None,'account_migration_marker_changed')
        os.link(stage.name,path.name,src_dir_fd=parent,dst_dir_fd=parent,follow_symlinks=False)
        os.unlink(stage.name,dir_fd=parent);os.fsync(parent)
    old.need(_stable_fact(old.read(path)[1])==_stable_fact(value['fact']),'account_migration_marker_changed')


def _profile_stage(p,*,prepare=False):
    """Durable private stage fact precedes rename, including crash after CAS."""
    profile=Path(p['profile']);journal=Path(p['state_root'])/'new-profile-stage.json'
    new=bytes.fromhex(p['new_config_hex']);old_raw=bytes.fromhex(p['old_config_hex'])
    raw,fact=old.read(profile);entry=sc._optional(journal)
    if entry is None:
        old.need(prepare,'account_migration_preparation_missing')
        old.need(raw==old_raw and fact==p['old_profile'],'account_migration_config_changed')
        stage=profile.with_name('.'+profile.name+'.account-stage-'+p['new_config'][sc.ID])
        old.need(not stage.exists(),'account_migration_prepare_unproven')
        stage_fact=old.create(stage,new)
        entry=sc.encoded(dict(path=str(stage),fact=stage_fact,old_profile=p['old_profile']))
        old.create(journal,entry)
    stage=json.loads(entry);old.need(stage.get('old_profile')==p['old_profile'],'account_migration_stage_invalid')
    expected_path=profile.with_name('.'+profile.name+'.account-stage-'+p['new_config'][sc.ID])
    old.need(stage['path']==str(expected_path),'account_migration_stage_invalid')
    raw,fact=old.read(profile)
    if raw==new:
        old.need(_stable_fact(fact)==_stable_fact(stage['fact']),'account_migration_published_profile_changed');return profile,new,None,stage
    old.need(raw==old_raw and fact==p['old_profile'],'account_migration_config_changed')
    staged,staged_fact=old.read(expected_path)
    old.need(staged==new and staged_fact==stage['fact'],'account_migration_stage_changed')
    return profile,new,expected_path,stage


def _publish_profile(p):
    profile,new,expected_path,stage=_profile_stage(p)
    if expected_path is None:return
    with old.directory(profile.parent) as parent:
        old.need(old.read(profile)[1]==p['old_profile'] and old.read(expected_path)[1]==stage['fact'],'account_migration_config_changed')
        os.replace(expected_path.name,profile.name,src_dir_fd=parent,dst_dir_fd=parent);os.fsync(parent)
    final,final_fact=old.read(profile)
    old.need(final==new and _stable_fact(final_fact)==_stable_fact(stage['fact']),'account_migration_published_profile_changed')


def _publication_values(p,expected):
    config=p['new_config'];attempt=Path(p['state_root']);root=Path(config['mirror_root'])
    receipt=dict(schema='walden.account.migration.receipt/1',state='committed',plan_sha256=expected,contract=sc.fixed(config),
        new_config_sha256=sc.digest(config),old_config_sha256=sc.digest(p['old_config']),legacy_current_sha256=p['legacy_current_sha256'],
        legacy_receipt_sha256=p['legacy_receipt_sha256'],preservation=p['preservation'],stop_snapshots=[dict(path=p['follow']['snapshot_path'],config_sha256=sc.digest(p['old_config']))])
    receipt_path=attempt/'receipt.json';value=dict(schema='walden.account.scope.current/1',contract=sc.fixed(config),receipt=str(receipt_path),receipt_sha256=sc.sha(sc.encoded(receipt)))
    return [('pending',root/sc.PENDING,sc.encoded(dict(plan_sha256=expected,profile=p['profile'],state_root=str(attempt)))),
        ('receipt',receipt_path,sc.encoded(receipt)),('current',root/sc.CURRENT,sc.encoded(value))]


def _prepare_publications(p,expected):
    """All unjournaled creation windows precede pending/registry/media/C effects."""
    attempt=Path(p['state_root']);complete=attempt/'publications-prepared.json'
    if not complete.exists():
        _profile_stage(p,prepare=True)
        for key,path,data in _publication_values(p,expected):_marker(p,key,path,data,prepare=True)
        facts={name:old.read(attempt/name)[1] for name in ('new-profile-stage.json','marker-pending.json','marker-receipt.json','marker-current.json')}
        old.create(complete,sc.encoded(dict(plan=expected,facts=facts)))
    value=json.loads(old.read(complete)[0]);old.need(value.get('plan')==expected,'account_migration_preparation_changed')
    old.need(value.get('facts')=={name:old.read(attempt/name)[1] for name in ('new-profile-stage.json','marker-pending.json','marker-receipt.json','marker-current.json')},'account_migration_preparation_changed')
    _profile_stage(p)
    for key,path,data in _publication_values(p,expected):
        _marker(p,key,path,data,check=path.exists(),prepare=not path.exists())


def _seed(p,config):
    """Only authenticated legacy selected tables; not a fake full inventory."""
    import hashlib
    root=Path(config['mirror_root']);path=root/sc.REGISTRY;seeds=[]
    # The immutable, repeatedly typed-verified backup is the seed authority.
    for name in p['databases']:
        if not sc.SHARD.fullmatch(name):continue
        conn=sqlite3.connect(readonly_database_uri(Path(p['state_root'])/name),uri=True)
        try:
            conn.execute('PRAGMA query_only=ON')
            old.need(conn.execute('SELECT * FROM __walden_binding').fetchall()==[(config['account_id'],config['source_generation'],name)],'account_migration_binding')
            for username in p['old_config']['mirror_scope']:
                table='Msg_'+hashlib.md5(username.encode()).hexdigest();row=conn.execute('SELECT value FROM __walden_progress WHERE table_name=?',(table,)).fetchone()
                if row is None:continue
                progress=json.loads(row[0]);ddl=conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone()
                old.need(ddl is not None,'account_migration_table_missing');schema=sc.sha(ddl[0].encode())
                observation=dict(contract=sc.fixed(config),shard=name,source_identity=progress['source_identity'],header=progress['source_header_sha256'],query_only=True,tables=[[table,schema]],legacy_commit=p['legacy_receipt_sha256'],legacy_config=sc.digest(p['old_config']))
                seeds.append((observation,dict(table=table,schema_sha256=schema,username=username,supported=True,legacy=True)))
        finally:conn.close()
    expected={};observations={};anchors={}
    for observation,item in seeds:
        shard=observation['shard'];table=item['table'];oid=sc.digest(observation)
        expected[(shard,table)]=dict(item,observation=oid,ref=sc.target_ref(config,shard,table),source_identity=observation['source_identity'],header=observation['header'])
        observations[oid]=observation;anchor=dict(source_identity=observation['source_identity'],header=observation['header'])
        old.need(shard not in anchors or anchors[shard]==anchor,'account_migration_seed_conflict');anchors[shard]=anchor
    with sc.registry(config,write=True,initialize=not path.exists()) as db:
        actual={(shard,table):json.loads(proof) for shard,table,proof in db.execute('SELECT shard,table_name,proof FROM members')}
        old.need(all(key in expected and value==expected[key] for key,value in actual.items()),'account_migration_seed_foreign')
        prior_obs={oid:json.loads(proof) for oid,proof in db.execute('SELECT id,proof FROM observations')}
        old.need(all(key in observations and value==observations[key] for key,value in prior_obs.items()),'account_migration_seed_foreign')
        roster=[name for name in p['databases'] if sc.SHARD.fullmatch(name)]
        allowed_state={'shard_anchor_schema':1,'roster':roster}
        allowed_state.update({'shard_anchor:'+name:anchor for name,anchor in anchors.items()})
        old.need(all(key in allowed_state and json.loads(value)==allowed_state[key] for key,value in db.execute('SELECT key,value FROM state')),'account_migration_seed_foreign')
        for observation,item in seeds:sc._register_members(config,db,observation,[item])
        sc.save(db,'roster',roster)
        old.need({(shard,table):json.loads(proof) for shard,table,proof in db.execute('SELECT shard,table_name,proof FROM members')}==expected,'account_migration_seed_incomplete')
        old.need(all(sc.state(db,'shard_anchor:'+name)==anchor for name,anchor in anchors.items()),'account_migration_seed_incomplete')
        for shard,table in expected:sc.member(config,db,shard,table)
        db.commit()


def _media(p,config):
    from .native_media_work import _json
    root=Path(config['mirror_root']);path=root/'media-work.sqlite'
    if not path.exists():return
    old_binding=_json(sc.binding(p['old_config']));new_binding=_json(sc.binding(config));sc._safe(path)
    c=sqlite3.connect(path)
    try:
        c.execute('BEGIN IMMEDIATE');value=c.execute('SELECT value FROM binding').fetchall()
        old.need(value in ([(old_binding,)],[(new_binding,)]),'account_migration_media_binding')
        old.need(old.effects(c)==p['preservation']['databases']['media-work.sqlite'],'account_migration_media_data_changed')
        if value==[(old_binding,)]:c.execute('UPDATE binding SET value=? WHERE id=1',(new_binding,))
        c.commit()
    finally:c.close()


def apply(path,expected):
    p,raw=_plan(path,expected);root=Path(p['old_config']['mirror_root']);profile=Path(p['profile']);attempt=Path(p['state_root'])
    current=sc._optional(root/sc.CURRENT) if not (root/sc.PENDING).exists() else None
    if current is not None:
        value=json.loads(current);receipt=json.loads(old.read(value['receipt'])[0])
        old.need(receipt.get('plan_sha256')==expected,'account_migration_current_conflict')
        if sc._optional(root/sc.PENDING) is None:return status(path,expected)
    from .native_mirror_sync import writer_lock
    with old.directory(root) as parent:
        fd=os.open('.account-migration.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600,dir_fd=parent)
    writer=contextlib.ExitStack()
    try:
        old.need(os.fstat(fd).st_uid==os.getuid() and os.fstat(fd).st_mode&0o077==0,'account_migration_unsafe_lock')
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise MirrorError('account_migration_busy') from None
        _legacy(p)
        pending_path=root/sc.PENDING
        if pending_path.exists() and pending_path.lstat().st_nlink==2:
            _verify_backup(p);_quiescent(p)
            _marker(p,'pending',pending_path,sc.encoded(dict(plan_sha256=expected,profile=str(profile),state_root=str(attempt))))
        pending=sc._optional(pending_path)
        if pending is None:
            profile_raw,profile_fact=old.read(profile)
            old.need(profile_raw==bytes.fromhex(p['old_config_hex']) and profile_fact==p['old_profile'],'account_migration_config_changed')
            stop=_quiescent(p,initial=True)
            writer.enter_context(writer_lock(root,0))
            old.need(summaries(p['old_config'])==p['preservation'],'account_migration_data_changed')
            _backup(p,root)
            stop_path=attempt/'quiescence.json';prior_stop=sc._optional(stop_path)
            if prior_stop is None:old.create(stop_path,sc.encoded(stop))
            else:old.need(prior_stop==sc.encoded(stop),'account_migration_control_changed')
            _prepare_publications(p,expected)
            _marker(p,'pending',root/sc.PENDING,sc.encoded(dict(plan_sha256=expected,profile=str(profile),state_root=str(attempt))))
        else:
            old.need(json.loads(pending).get('plan_sha256')==expected,'account_migration_pending_conflict')
            _marker(p,'pending',root/sc.PENDING,pending,check=True)
            _verify_backup(p)
            _quiescent(p)
            writer.enter_context(writer_lock(root,0))
        with contextlib.nullcontext():
            _legacy(p);old.need(summaries(p['old_config'])==p['preservation'],'account_migration_data_changed')
            _prepare_publications(p,expected)
            config=p['new_config'];_seed(p,config);_media(p,config)
            _verify_backup(p)
            _publish_profile(p)
            old.need(summaries(config)==p['preservation'],'account_migration_preservation_failed')
            _quiescent(p,writer_held=True)
            _verify_backup(p)
            _publish_profile(p)
            for key,target,data in _publication_values(p,expected):
                if key!='pending':_marker(p,key,target,data)
            old.need(old.read(profile)[0]==bytes.fromhex(p['new_config_hex']) and json.loads(old.read(root/sc.PENDING)[0]).get('plan_sha256')==expected,'account_migration_commit_changed')
            _marker(p,'pending',root/sc.PENDING,old.read(root/sc.PENDING)[0],check=True)
            with old.directory(root) as parent:os.unlink(sc.PENDING,dir_fd=parent);os.fsync(parent)
        return status(path,expected)
    finally:
        writer.close();os.close(fd)


def status(path,expected):
    p,_=_plan(path,expected);root=Path(p['new_config']['mirror_root']);pending=sc._optional(root/sc.PENDING);current=sc._optional(root/sc.CURRENT)
    if pending is not None:
        old.need(json.loads(pending).get('plan_sha256')==expected,'account_migration_pending_conflict')
        return dict(status='pending',plan_sha256=expected,source_opened=False,recovery='same_plan_roll_forward')
    if current is None:
        attempt=Path(p['state_root'])
        if attempt.exists() and not (attempt/'publications-prepared.json').exists():
            raw,fact=old.read(Path(p['profile']))
            old.need(raw==bytes.fromhex(p['old_config_hex']) and fact==p['old_profile'] and not (root/sc.REGISTRY).exists(),'account_migration_preparation_unknown')
            _verify_backup(p)
            return dict(status='preparation_incomplete',plan_sha256=expected,source_opened=False,external_effects=False,
                recovery='preserve_unproven_files_manual_review_before_new_attempt')
        return dict(status='planned',plan_sha256=expected,source_opened=False)
    sc.query_scope_guard(p['new_config']);value=json.loads(current);receipt=json.loads(old.read(value['receipt'])[0]);old.need(receipt['plan_sha256']==expected,'account_migration_current_conflict')
    return dict(status='account_scope_committed',plan_sha256=expected,contract_id=p['new_config'][sc.ID],preservation=receipt['preservation'],source_opened=False)

from .failure_evidence import _register
_register(_replace,summaries,plan,apply,status,_quiescent,_control_facts,_verify_backup,_publish_profile,_profile_stage,_marker,_prepare_publications,_publication_values,_seed,_media)
