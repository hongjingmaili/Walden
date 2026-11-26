"""Generated account-scale metadata/message fixture; never uses a real source.
The specification retains only anonymous distributions/lengths and watermarks
from earlier private stopped metadata. Every identity and body is synthetic.
"""
import hashlib,json,os,sqlite3,tempfile,time
from pathlib import Path
from wechat_local import native_scope_contract as sc
from wechat_local.native_mirror_store import MirrorStore
from wechat_local.source_records import SourceKey
from test_reboot_tolerance import make_config
from test_incremental_history_work import Driver
SPEC=Path(__file__).parent/'fixtures/real_scale_metadata.json'
USERNAME='synthetic-new-priority'
NEW='Msg_'+hashlib.md5(USERNAME.encode()).hexdigest()

def table_name(shard,index):
    return NEW if (shard,index)==(0,0) else 'Msg_'+format((shard+1)*10000+index,'032x')
def padded(value,goal):
    current=json.dumps(value,sort_keys=True)
    if len(current.encode())>=goal:return value
    candidate=dict(value,_synthetic_padding='');size=len(json.dumps(candidate,sort_keys=True).encode())
    if size<=goal:candidate['_synthetic_padding']='p'*(goal-size);return candidate
    return value

def create(*, unregistered_new=False):
    spec=json.loads(SPEC.read_text());base=Path(tempfile.mkdtemp(prefix='synthetic-scale-',dir=Path(__file__).resolve().parents[2]/'evidence'));chosen=None
    for n in range(201):
        parent=base/('scope'+'x'*n)
        config=make_config(parent/'message',parent/'mirror')
        short=len(json.dumps(sc.fixed(config),sort_keys=True).encode());extra=spec['binding_serialized_bytes']-short
        if 0<=extra<=240:
            config=make_config(parent/'message',parent/('mirror'+'p'*extra));chosen=(parent,config);break
    assert chosen is not None
    parent,config=chosen;messages=Path(config['message_root']);mirror=Path(config['mirror_root']);messages.mkdir(parents=True,mode=0o700);mirror.mkdir(mode=0o700)
    assert len(json.dumps(sc.fixed(config),sort_keys=True).encode())==1095
    names=sorted([f'biz_message_{i}.db' for i in range(6)]+[f'message_{i}.db' for i in range(12)])
    shapes=[];progress_sizes=[];member_sizes=[]
    for shape,name in zip(spec['shards'],names):
        source=messages/name;local=mirror/name
        with sqlite3.connect(source) as src:
            src.execute('CREATE TABLE Name2Id(user_name TEXT)');src.execute('INSERT INTO Name2Id VALUES(?)',(USERNAME,))
        store=MirrorStore(local,SourceKey(config['account_id'],config['source_generation'],name,'Name2Id'))
        by_index=iter(shape['progress']);member_progress={}
        for member in shape['members']:
            if member['has_progress']:member_progress[member['member_index']]=next(by_index)
        schema={};counts={};initial={};source_stat=source.stat();identity=[source_stat.st_dev,source_stat.st_ino];header=hashlib.sha256(source.read_bytes()[:16]).hexdigest()
        with sqlite3.connect(source) as src,sqlite3.connect(local) as dst:
            dst.execute('CREATE TABLE Name2Id(user_name TEXT)');dst.execute('INSERT INTO Name2Id VALUES(?)',(USERNAME,));dst.execute('INSERT OR REPLACE INTO __walden_progress VALUES(?,?)',('Name2Id','{}'))
            for member in shape['members']:
                idx=member['member_index'];table=table_name(shape['shard_index'],idx);p=member_progress.get(idx)
                if unregistered_new and p is None:continue
                ddl=spec['canonical_message_ddl'].replace('Msg_{table}',table);src.execute(ddl);schema[table]=sc.sha(ddl.encode())
                maximum=max(p['H'],p['tail'],p['target']) if p else 0
                insert='INSERT INTO '+table+'(local_id,server_id,local_type,real_sender_id,create_time,message_content) VALUES(?,?,?,?,?,?)'
                def rows(ids):return ((i,i,1,1,1600000000,'synthetic message') for i in ids)
                src.executemany(insert,rows(range(1,maximum+1)));counts[table]=maximum
                if p is None:continue
                dst.execute(ddl);dst.executemany(insert,rows(range(1,p['history']+1)));dst.executemany(insert,rows(range(p['H']+1,p['tail']+1)))
                value=dict(H=p['H'],history=p['history'],tail=p['tail'],target=p['target'],history_complete=p['complete'],checked_at=1600000000,source_identity=identity,source_header_sha256=header)
                value=padded(value,p['progress_json_bytes']);encoded=json.dumps(value,sort_keys=True);progress_sizes.append(len(encoded.encode())-p['progress_json_bytes']);dst.execute('INSERT INTO __walden_progress VALUES(?,?)',(table,encoded));initial[table]=dict(history=p['history'],H=p['H'],tail=p['tail'])
            cookie=src.execute('PRAGMA schema_version').fetchone()[0]
        source.chmod(0o600);local.chmod(0o600);shapes.append(dict(shape=shape,name=name,path=source,local=local,identity=identity,header=header,schema=schema,cookie=cookie,counts=counts,initial=initial))
    with sc.registry(config,write=True,initialize=True) as db:
        for shard in shapes:
            shape=shard['shape'];tables=list(shard['schema'])
            used=set()
            for group in shape['active_observation_groups']:
                members=[m for m in shape['members'] if m['observation_group']==group['group_index'] and table_name(shape['shard_index'],m['member_index']) in shard['schema']];group_tables=[table_name(shape['shard_index'],m['member_index']) for m in members]
                group_tables+=(t for t in tables if t not in group_tables)
                group_tables=group_tables[:group['table_count']]
                observation=dict(contract=sc.fixed(config),shard=shard['name'],source_identity=shard['identity'],header=shard['header'],query_only=True,schema_cookie=shard['cookie'],at_ns=1600000000000000000+group['group_index'],tables=[[t,shard['schema'][t]] for t in group_tables]);observation=padded(observation,group['bytes']);obsid=sc.digest(observation);used.add(len(json.dumps(observation,sort_keys=True).encode()))
                items=[]
                for member in members:
                    table=table_name(shape['shard_index'],member['member_index']);item=dict(table=table,schema_sha256=shard['schema'][table],username=USERNAME if table==NEW else None,supported=member['supported'],available=member['available'],inventory_pass='f'*32)
                    proof=dict(item,observation=obsid,ref=sc.target_ref(config,shard['name'],table),source_identity=shard['identity'],header=shard['header']);p=padded(proof,member['member_proof_bytes'])
                    if '_synthetic_padding' in p:item['_synthetic_padding']=p['_synthetic_padding']
                    items.append(item);member_sizes.append(len(json.dumps(p,sort_keys=True).encode())-member['member_proof_bytes'])
                sc._register_members(config,db,observation,items)
            remaining=max(0,len(shape['observation_sizes'])-len(shape['active_observation_groups']))
            for i in range(remaining):
                size=shape['observation_sizes'][i];observation=dict(contract=sc.fixed(config),shard=shard['name'],source_identity=shard['identity'],header=shard['header'],query_only=True,schema_cookie=0,at_ns=1600000001000000000+i,tables=[]);observation=padded(observation,size);db.execute('INSERT OR IGNORE INTO observations VALUES(?,?)',(sc.digest(observation),json.dumps(observation,sort_keys=True)))
            sc.save(db,'inventory:'+shard['name'],dict(after='',cookie=shard['cookie'],pass_cookie=shard['cookie'],complete=True,refresh_requested=False,pass_id='f'*32))
            sc.save(db,'copy:'+shard['name'],'');sc.save(db,'history_copy:'+shard['name'],dict(after='',regular_next=False))
        while db.execute('SELECT count(*) FROM observations').fetchone()[0]<spec['synthetic_observation_target']:
            n=db.execute('SELECT count(*) FROM observations').fetchone()[0];first=shapes[0]
            value=dict(contract=sc.fixed(config),shard=first['name'],source_identity=first['identity'],header=first['header'],query_only=True,schema_cookie=0,at_ns=1600000002000000000+n,tables=[])
            value=padded(value,18000);db.execute('INSERT INTO observations VALUES(?,?)',(sc.digest(value),json.dumps(value,sort_keys=True)))
        sc.save(db,'roster',names);sc.save(db,'account_work',dict(ready=False,imported=False,reconcile=True));sc.save(db,'tail_debt_cursor',dict(shard='',table=''));sc.save(db,'history_backlog_scan',{});sc.save(db,'round_number',101);db.commit()
    receipt=parent/'receipt.json';raw=sc.encoded(dict(state='committed',contract=sc.fixed(config),new_config_sha256=sc.digest(config),legacy_current_sha256=None));sc.create(receipt,raw);sc.create(mirror/sc.CURRENT,sc.encoded(dict(schema='walden.account.scope.current/1',contract=sc.fixed(config),receipt=str(receipt),receipt_sha256=sc.sha(raw))));sc.create(mirror/'.writer.lock',b'')
    registry=mirror/sc.REGISTRY
    # Reproduce physical SQLite scale without real historical observation data.
    with sqlite3.connect(registry) as db:
        target=spec['synthetic_registry_target_bytes'];page=db.execute('PRAGMA page_size').fetchone()[0];pages=db.execute('PRAGMA page_count').fetchone()[0]
        if pages<target//page:
            db.execute('CREATE TABLE synthetic_padding(value BLOB)');pages=db.execute('PRAGMA page_count').fetchone()[0];db.execute('INSERT INTO synthetic_padding VALUES(zeroblob(?))',((target//page-pages)*(page-4),))
    cohort=[dict(shard=names[v['shard_index']],table=table_name(v['shard_index'],v['member_index']),H=v['H']) for v in spec['anonymous_original46']]
    result=dict(config=config,message_root=str(messages),mirror_root=str(mirror),source_db=str(shapes[0]['path']),local_path=str(shapes[0]['local']),shards=shapes,root=parent,cohort=cohort,registry=str(registry),base=base)
    (base/'input-manifest.json').write_text(json.dumps(dict(input_variant='before-true-source-addition' if unregistered_new else 'legacy-missing-copy',spec_sha256=hashlib.sha256(SPEC.read_bytes()).hexdigest(),members=4446 if unregistered_new else 4447,progress=4446,observations=6978,registry_bytes=registry.stat().st_size,binding_bytes=1095,progress_size_delta_minmax=[min(progress_sizes),max(progress_sizes)],member_size_delta_minmax=[min(member_sizes),max(member_sizes)],all_messages='generated synthetic',all_identities='generated synthetic',cohort=cohort),indent=2)+'\n')
    return result

def sql_counts(item):
    rows=[]
    for v in item['cohort']:
        with sqlite3.connect(Path(item['mirror_root'])/v['shard']) as db:
            value=json.loads(db.execute('SELECT value FROM __walden_progress WHERE table_name=?',(v['table'],)).fetchone()[0]);count=db.execute('SELECT count(*) FROM '+v['table']+' WHERE local_id<=?',(v['H'],)).fetchone()[0];rows.append((count,value['history'],value['H'],value['history_complete']))
    return dict(rows=sum(v[0] for v in rows),history=sum(v[1] for v in rows),completed=sum(v[3] and v[1]>=v[2] for v in rows))


def global_sql_counts(item):
    """Actual local SQL rows through each original H, separate from cursors."""
    rows=history=0
    for shard in item['shards']:
        with sqlite3.connect(Path(item['mirror_root'])/Path(shard['path']).name) as db:
            for table,raw in db.execute("SELECT table_name,value FROM __walden_progress WHERE table_name GLOB 'Msg_*'").fetchall():
                value=json.loads(raw);history+=value['history']
                rows+=db.execute('SELECT count(*) FROM '+table+' WHERE local_id<=?',(value['H'],)).fetchone()[0]
    return dict(rows=rows,history=history)
