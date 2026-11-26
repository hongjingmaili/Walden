"""Explicit strong recovery: verify only committed local IDs, then one attached-DB CAS.
No normal sync guard is relaxed. No message Source body is copied or returned.
"""
import hashlib,json,os,re,sqlite3,stat,struct
from pathlib import Path
from contextlib import ExitStack,closing
from .native_mirror_store import MirrorError,MirrorStore,RawText,lossless_text_rows
from .source_records import SourceKey
from .native_mirror_sync import mirror_root,writer_lock
from .live_readonly import readonly_database_uri
from .native_follow_policy import digest
from .native_deadline import check_deadline
from .common import quote_identifier as qi

PREFIX='recovery_'

def need(value,code):
    if not value:raise MirrorError(PREFIX+code)


def scalar(value):
    if value is None:return ['null']
    if type(value) is int:return ['integer',str(value)]
    if type(value) is float:return ['real',struct.pack('>d',value).hex()]
    if type(value) is str:return ['text',value.encode('utf-8').hex()]
    if type(value) is RawText:return ['text',value.data.hex()]
    if type(value) is bytes:return ['blob',value.hex()]
    raise MirrorError('recovery_unsupported_value')


def row_hash(row):
    # Exact original canonical JSON encoding, including the final newline.
    # Scalar payloads are only decimal/hex ASCII, never arbitrary JSON strings.
    values=[];append=values.append;pack=struct.pack
    for value in row:
        value_type=type(value)
        if value is None:append('["null"]');continue
        if value_type is int:kind='integer';payload=str(value)
        elif value_type is float:kind='real';payload=pack('>d',value).hex()
        elif value_type is str:kind='text';payload=value.encode('utf-8').hex()
        elif value_type is RawText:kind='text';payload=value.data.hex()
        elif value_type is bytes:kind='blob';payload=value.hex()
        else:raise MirrorError('recovery_unsupported_value')
        append(f'["{kind}","{payload}"]')
    return hashlib.sha256(('['+','.join(values)+']\n').encode('ascii')).hexdigest()


DIFFERENCE_ENUMS={
 'kind':{'missing_row','row_count','column_count','type_change','value_change','schema_change'},
 'stage':{'committed_rows','limited_name2id','schema'},
 'database_role':{'message','auxiliary'},
 'table_role':{'committed_message','auxiliary_snapshot','scope_self_sender_mapping'},
 'expected_storage':{'null','integer','real','text','blob'},'actual_storage':{'null','integer','real','text','blob'},
 'expected_python':{'NoneType','int','float','str','RawText','bytes'},'actual_python':{'NoneType','int','float','str','RawText','bytes'}}
DIFFERENCE_INTS={'database_index','table_index','column_index','row_ordinal','compared_rows_total','compared_rows_in_table','batch_rows','returned_rows','expected_columns','actual_columns'}


def safe_difference(value):
    if type(value) is not dict:return dict(available=False,kind='unknown')
    result={'available':True}
    for key,allowed in DIFFERENCE_ENUMS.items():
        item=value.get(key)
        if item is None:continue
        if type(item) is not str or item not in allowed:return dict(available=False,kind='unknown')
        result[key]=item
    for key in DIFFERENCE_INTS:
        item=value.get(key)
        if item is None:continue
        if type(item) is not int or not 0<=item<=9223372036854775807:return dict(available=False,kind='unknown')
        result[key]=item
    if not {'kind','stage','database_role','table_role','database_index','table_index','compared_rows_total'}<=result.keys():return dict(available=False,kind='unknown')
    return result


def difference_error(code,context,**difference):
    error=MirrorError('recovery_'+code)
    error.recovery_difference=safe_difference(dict(context,**difference))
    raise error


def compare_batch(expected,actual,context,counts,*,code='row_mismatch'):
    """The original exact typed fingerprint comparator; inspect only its first failure.
    Diagnostic fields contain ordinals/categories/counts, never row IDs/values/hashes.
    """
    got={r[0]:r for r in actual};base=dict(context,batch_rows=len(expected),returned_rows=len(actual))
    for ordinal,row in enumerate(expected):
        current=got.get(row[0]);where=dict(base,row_ordinal=counts['table'],compared_rows_total=counts['total'],compared_rows_in_table=counts['table'])
        if current is None:difference_error(code,where,kind='missing_row')
        if len(current)!=len(row):difference_error(code,where,kind='column_count',expected_columns=len(row),actual_columns=len(current))
        if row_hash(current)!=row_hash(row):
            for index,(old,new) in enumerate(zip(row,current)):
                a,b=scalar(old),scalar(new)
                if a!=b:
                    difference_error(code,where,kind='type_change' if a[0]!=b[0] else 'value_change',column_index=index,expected_storage=a[0],actual_storage=b[0],expected_python=type(old).__name__,actual_python=type(new).__name__)
            difference_error(code,where,kind='value_change')
        counts['table']+=1;counts['total']+=1
    if len(got)!=len(expected):difference_error(code,dict(base,compared_rows_total=counts['total'],compared_rows_in_table=counts['table']),kind='row_count')


def compare_schema(actual,expected,context,counts,*,code='schema_changed'):
    if actual==expected:return
    a,b=expected['columns'],actual['columns'];column=next((i+1 for i,(x,y) in enumerate(zip(a,b)) if x!=y),min(len(a),len(b))+1 if len(a)!=len(b) else None)
    difference_error(code,dict(context,stage='schema',compared_rows_total=counts['total'],compared_rows_in_table=0),kind='schema_change',column_index=column,expected_columns=len(a),actual_columns=len(b))


def private(path):
    path=Path(path);info=path.lstat()
    need(path.is_absolute() and stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_uid==os.getuid() and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600,'local_file_unsafe')
    with path.open('rb') as f:header=f.read(20)
    need(len(header)==20 and header[:16]==b'SQLite format 3\x00','local_format_unsupported')
    need(header[18:20]==b'\x01\x01','atomic_mode_unsupported')
    return [info.st_dev,info.st_ino]


def connect(path):
    private(path);c=sqlite3.connect(readonly_database_uri(Path(path)),uri=True);c.execute('PRAGMA query_only=ON');return c


def schema(c,table):
    sql=c.execute('SELECT sql FROM sqlite_master WHERE type=\'table\' AND name=?',(table,)).fetchone()
    need(sql and not table.startswith('__walden_'),'schema_missing')
    return dict(sql=sql[0],columns=[list(r) for r in c.execute('PRAGMA table_xinfo('+qi(table)+')')])


def rows(c,table,ids=None):
    if ids is not None and len(ids)>128:
        for start in range(0,len(ids),128):
            check_deadline();yield from rows(c,table,ids[start:start+128])
        return
    sql='SELECT rowid,* FROM '+qi(table)
    if ids is not None:sql+=' WHERE rowid IN ('+','.join('?' for _ in ids)+')'
    sql+=' ORDER BY rowid'
    with lossless_text_rows(c):
        for row in c.execute(sql,tuple(ids or ())):yield row


def row_summary(c,table):
    sha=hashlib.sha256();count=0;highest=0
    for row in rows(c,table):
        if count%128==0:check_deadline()
        need(type(row[0]) is int,'rowid_invalid');sha.update(bytes.fromhex(row_hash(row)));count+=1;highest=max(highest,row[0])
    return dict(count=count,max_rowid=highest,sha256=sha.hexdigest())


def anchors(config):
    from .source_setup import _confirmed_self_username
    name=_confirmed_self_username(config,physical=True);need(name,'self_unconfirmed')
    from .native_scope_contract import mode
    need(mode(config)=='selected','account_source_recovery_requires_registry_proof')
    scope=config.get('mirror_scope');need(type(scope) is list and scope and all(type(s) is str for s in scope),'scope_invalid')
    return dict(account_id=config['account_id'],source_generation=config['source_generation'],self_username=name,live_db_root=str(Path(config['live_db_root']).resolve()),message_root=str(Path(config['message_root']).resolve()),scope=list(scope))


def selected_names(c,tables,anchor):
    desc=schema(c,'Name2Id');cols=[r[1] for r in desc['columns']];need('user_name' in cols,'mapping_schema_missing');at=cols.index('user_name')+1
    wanted=set(anchor['scope']+[anchor['self_username']]);ids=set()
    for table in tables:
        columns=[r[1] for r in schema(c,table)['columns']];need('real_sender_id' in columns,'sender_schema_missing')
        for row in c.execute('SELECT DISTINCT real_sender_id FROM '+qi(table)):
            need(type(row[0]) is int,'sender_mapping_missing');ids.add(row[0])
    byid={r[0]:r for r in rows(c,'Name2Id',sorted(ids))} if ids else {}
    need(set(byid)==ids,'sender_mapping_missing')
    for row in c.execute('SELECT rowid FROM Name2Id WHERE user_name IN ('+','.join('?' for _ in wanted)+')',tuple(sorted(wanted))):ids.add(row[0])
    selected=[r for r in rows(c,'Name2Id',sorted(ids))];names={r[at] for r in selected}
    need(wanted<=names,'self_or_scope_mapping_missing')
    return dict(schema=desc,rows=[[r[0],row_hash(r)] for r in selected])


RECEIPT='__walden_verified_source_recovery'
RECEIPT_SQL='CREATE TABLE '+RECEIPT+'(nonce TEXT PRIMARY KEY,receipt TEXT NOT NULL)'
RECEIPT_SCHEMA=[['index','sqlite_autoindex_'+RECEIPT+'_1',RECEIPT,None],['table',RECEIPT,RECEIPT,RECEIPT_SQL]]


def local_effects(c,alias='main',*,_summaries=None):
    """Only same-connection SQLite state: COMMIT must have the declared effects."""
    prefix=qi(alias)+'.'
    objects=[list(r) for r in c.execute('SELECT type,name,tbl_name,sql FROM '+prefix+'sqlite_master ORDER BY type,name')]
    need(not any(r[0]=='trigger' for r in objects),'local_trigger_unsupported')
    receipt_schema=[r for r in objects if r[2]==RECEIPT]
    need(not receipt_schema or receipt_schema==RECEIPT_SCHEMA,'receipt_schema_unsupported')
    stable={}
    for kind,name,table,sql in objects:
        if kind!='table' or name in ('__walden_progress',RECEIPT):continue
        sha=hashlib.sha256();count=0;highest=0
        with lossless_text_rows(c):
            for row in c.execute('SELECT rowid,* FROM '+prefix+qi(name)+' ORDER BY rowid'):
                if count%128==0:check_deadline()
                need(type(row[0]) is int,'rowid_invalid');sha.update(bytes.fromhex(row_hash(row)));count+=1;highest=max(highest,row[0])
        if _summaries is not None:_summaries[name]=dict(count=count,max_rowid=highest,sha256=sha.hexdigest())
        stable[name]=dict(count=count,sha256=sha.hexdigest())
    progress=[list(r) for r in c.execute('SELECT table_name,value FROM '+prefix+'__walden_progress ORDER BY table_name')]
    receipts=[list(r) for r in c.execute('SELECT nonce,receipt FROM '+prefix+qi(RECEIPT)+' ORDER BY nonce')] if receipt_schema else []
    return dict(schema=objects,stable_tables=stable,progress=progress,receipts=receipts)


def plan(config):
    """Strict local fingerprint only; no Source paths opened, metadata files written or DDL."""
    anchor=anchors(config);root=mirror_root(config,create=False);expected={'Msg_'+hashlib.md5(s.encode()).hexdigest() for s in anchor['scope']};databases=[]
    paths=sorted(p for p in root.iterdir() if re.fullmatch(r'(?:biz_)?message_[0-9]+\.db',p.name))
    need(not (root/'request-window.json').exists(),'daily_scope_required')
    need(paths,'local_snapshot_missing')
    sources=[(p,Path(anchor['message_root'])/p.name,'message') for p in paths]
    for key,name in (('encrypted_contact_database','contact.db'),('session_database','session.db')):
        need(not (root/name).exists() or config.get(key),'auxiliary_scope_missing')
        if config.get(key):need((root/name).is_file(),'auxiliary_snapshot_missing');sources.append((root/name,Path(config[key]),'auxiliary'))
    for path,source,kind in sources:
        check_deadline();identity=private(path)
        with connect(path) as c:
            cap=next((int(r[0].split('=')[1]) for r in c.execute('PRAGMA compile_options') if r[0].startswith('MAX_ATTACHED=')),10)
            need(len(sources)-1<=cap,'atomic_attach_limit')
            c.execute('BEGIN');binding=c.execute('SELECT * FROM __walden_binding').fetchall();need(binding==[(anchor['account_id'],anchor['source_generation'],path.name)],'binding_changed')
            need(c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='__walden_cursor_epochs'").fetchone() is None,
                 'account_source_recovery_requires_registry_proof')
            names=[r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '__walden_%' ORDER BY name")]
            if kind=='message':need(set(names)-{'Name2Id'}<=expected,'unscoped_local_table');tables=[t for t in names if t in expected]
            else:tables=names
            need(tables,'snapshot_tables_missing');summaries={};entry=dict(name=path.name,path=str(path),source=str(source),kind=kind,local_identity=identity,binding=list(binding[0]),tables=[],effects=local_effects(c,_summaries=summaries))
            for table in tables:
                description=schema(c,table);found=c.execute('SELECT value FROM __walden_progress WHERE table_name=?',(table,)).fetchone();need(found,'progress_missing');progress=json.loads(found[0]);need(type(progress.get('source_identity')) is list and len(progress['source_identity'])==2 and all(type(v) is int and v>=0 for v in progress['source_identity']),'old_identity_missing')
                columns=[r[1] for r in description['columns']]
                if kind=='message':
                    need({'local_id','real_sender_id'}<=set(columns),'schema_missing')
                    need(all(type(progress.get(k)) is int and progress[k]>=0 for k in ('H','history','tail')) and (progress.get('target') is None or type(progress['target']) is int and progress['target']>=0),'progress_invalid')
                summary=dict(summaries[table])
                if kind=='message':summary['max_local_id']=c.execute('SELECT MAX(local_id) FROM '+qi(table)).fetchone()[0] or 0
                entry['tables'].append(dict(name=table,schema=description,progress=found[0],rows=summary))
            if kind=='message':entry['names']=selected_names(c,tables,anchor)
            elif path.name=='contact.db':
                need('contact' in names and 'username' in [r[1] for r in schema(c,'contact')['columns']],'contact_self_schema_missing')
                need(c.execute('SELECT 1 FROM contact WHERE username=? LIMIT 1',(anchor['self_username'],)).fetchone(),'contact_self_missing')
            databases.append(entry)
    value=dict(version=1,anchors=anchor,databases=databases)
    return dict(expected_local_sha256=digest(value),snapshot=value)


def source_stamp(path,anchor):
    path=Path(path);need(not path.is_symlink() and Path(anchor['live_db_root']) in path.resolve().parents,'source_outside_root')
    before=path.stat()
    with path.open('rb') as f:header=hashlib.sha256(f.read(16)).hexdigest()
    after=path.stat();need((before.st_dev,before.st_ino)==(after.st_dev,after.st_ino),'source_changed')
    return dict(source_identity=[before.st_dev,before.st_ino],source_header_sha256=header)


def atomic_preflight(c,aliases):
    cap=next((int(r[0].split('=')[1]) for r in c.execute('PRAGMA compile_options') if r[0].startswith('MAX_ATTACHED=')),10)
    need(len(aliases)-1<=cap,'atomic_attach_limit')
    for alias in aliases:
        need(c.execute('PRAGMA '+alias+'.journal_mode').fetchone()[0] in ('delete','truncate','persist'),'atomic_mode_unsupported')
        need(c.execute('PRAGMA '+alias+'.synchronous').fetchone()[0]>=2,'atomic_sync_unsupported')


def artifact_hash(path):
    path=Path(path);info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o400,'auxiliary_artifact_invalid')
    sha=hashlib.sha256()
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        need([os.fstat(fd).st_dev,os.fstat(fd).st_ino]==[info.st_dev,info.st_ino],'auxiliary_artifact_changed')
        while True:
            check_deadline();data=os.read(fd,1048576)
            if not data:break
            sha.update(data)
    finally:os.close(fd)
    return sha.hexdigest()


def artifact_ro(path):
    artifact_hash(path)
    c=sqlite3.connect(readonly_database_uri(Path(path)),uri=True);c.execute('PRAGMA query_only=ON');return c


def copy_database(source,path):
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
    with closing(sqlite3.connect(path)) as target,target:source.backup(target,pages=128,progress=lambda *a:check_deadline())


def freeze_artifact(path,effects):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:os.fchmod(fd,0o400);os.fsync(fd)
    finally:os.close(fd)
    fd=os.open(Path(path).parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    return dict(path=str(path),sha256=artifact_hash(path),effects_sha256=digest(effects))


def paced_rows(connection,table):
    for number,row in enumerate(rows(connection,table)):
        if number%128==0:check_deadline()
        yield row


def capture_contact_snapshot(remote,local,database,anchor,stage_root,before,db_index,counts):
    """Original complete auxiliary snapshot semantics, with durable original retained.
    All mutations here are private stage files, never the original mirror.
    """
    need(database['kind']=='auxiliary' and database['name']=='contact.db','auxiliary_refresh_scope')
    root=Path(stage_root);need(root.is_absolute() and not root.exists() and not root.parent.is_symlink() and stat.S_IMODE(root.parent.stat().st_mode)==0o700 and root.parent.stat().st_uid==os.getuid(),'auxiliary_stage_invalid');root.mkdir(mode=0o700)
    parent=os.open(root.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(parent)
    finally:os.close(parent)
    old=root/'contact.before.db';new=root/'contact.current.db'
    copy_database(local,old)
    with sqlite3.connect(readonly_database_uri(old),uri=True) as archived:need(local_effects(archived)==database['effects'],'auxiliary_archive_mismatch')
    old_artifact=freeze_artifact(old,database['effects'])
    with artifact_ro(old) as archived:copy_database(archived,new)
    names={t['name'] for t in database['tables']};need('contact' in names and not any(n.startswith('Msg_') for n in names),'auxiliary_refresh_scope')
    expected_indexes=[r for r in database['effects']['schema'] if r[0]=='index' and r[2] in names]
    actual_indexes=[list(r) for r in remote.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE type='index' ORDER BY type,name") if r[2] in names]
    need(actual_indexes==expected_indexes,'auxiliary_index_schema_changed')
    progress_updates={};source_summaries={};observed=int(__import__('time').time())
    with closing(sqlite3.connect(new)) as target,target:
        for table_index,table in enumerate(database['tables']):
            name=table['name'];context=dict(stage='schema',database_index=db_index,database_role='auxiliary',table_index=table_index,table_role='auxiliary_snapshot')
            compare_schema(schema(remote,name),table['schema'],context,counts)
            key=SourceKey(anchor['account_id'],anchor['source_generation'],database['name'],name);store=MirrorStore.bound_transaction(new,key,target)
            progress=json.loads(table['progress']);progress.update(checked_at=observed,source_identity=before['source_identity'])
            if 'source_header_sha256' in progress:progress['source_header_sha256']=before['source_header_sha256']
            # Reuse the existing lossless replace_snapshot writer; stage starts as
            # the exact old full DB so indexes/sequences/metadata semantics match.
            total=dict(count=0,max_rowid=0);hasher=hashlib.sha256()
            def source_rows():
                for row in paced_rows(remote,name):
                    need(type(row[0]) is int,'rowid_invalid');hasher.update(bytes.fromhex(row_hash(row)));total['count']+=1;total['max_rowid']=max(total['max_rowid'],row[0]);yield row
            store.apply_batch(key,name,source_rows(),progress,replace_snapshot=True,_connection=target,_complete_snapshot=True)
            source_summaries[name]=dict(total,sha256=hasher.hexdigest())
            progress_updates[name]=json.dumps(progress,sort_keys=True)
        need(target.execute('SELECT 1 FROM contact WHERE username=? LIMIT 1',(anchor['self_username'],)).fetchone(),'contact_self_missing')
    with sqlite3.connect(readonly_database_uri(new),uri=True) as staged:
        stage_summaries={};new_effects=local_effects(staged,_summaries=stage_summaries)
        need(all(stage_summaries[name]==value for name,value in source_summaries.items()),'auxiliary_capture_mismatch')
    need(new_effects['schema']==database['effects']['schema'],'auxiliary_capture_effect')
    for name,value in database['effects']['stable_tables'].items():
        if name not in names and name!='sqlite_sequence':need(new_effects['stable_tables'][name]==value,'auxiliary_capture_effect')
    need(new_effects['progress']==[[name,progress_updates.get(name,value)] for name,value in database['effects']['progress']] and new_effects['receipts']==database['effects']['receipts'],'auxiliary_capture_effect')
    new_artifact=freeze_artifact(new,new_effects)
    return dict(mode='new_complete_authorized_contact_snapshot',old_archive=old_artifact,new_snapshot=new_artifact,observed_at=observed,tables=source_summaries,progress=progress_updates,effects=new_effects)


def verify(config,snapshot,*,connection_factory,accept=False,nonce=None,grant_digest=None,commit_check=None,refresh_auxiliary=False,stage_root=None):
    """Caller holds original writer lock and existing owned Source30 deadline.
    Read only originally committed rowids. One SQLite super-journal transaction for accept.
    """
    check_deadline();need(plan(config)['snapshot']==snapshot,'expected_changed');anchor=anchors(config);need(anchor==snapshot['anchors'],'anchors_changed');witness=[];counts=dict(total=0,table=0);auxiliary={}
    need(type(refresh_auxiliary) is bool and (not refresh_auxiliary or stage_root and config.get('encrypted_contact_database')),'auxiliary_refresh_authority')
    with ExitStack() as stack:
        for db_index,database in enumerate(snapshot['databases']):
            check_deadline();before=source_stamp(database['source'],anchor);remote=connection_factory(Path(database['source']));stack.callback(remote.close)
            need(remote.execute('PRAGMA query_only').fetchone()==(1,),'source_not_readonly');need(remote.execute('PRAGMA encoding').fetchone()==('UTF-8',),'source_encoding');remote.execute('BEGIN')
            local=stack.enter_context(connect(database['path']));local.execute('BEGIN')
            if database['kind']=='auxiliary':
                names={r[0] for r in remote.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")};need(names=={t['name'] for t in database['tables']},'schema_changed')
            if refresh_auxiliary and database['kind']=='auxiliary' and database['name']=='contact.db':
                auxiliary[db_index]=capture_contact_snapshot(remote,local,database,anchor,stage_root,before,db_index,counts)
                after=source_stamp(database['source'],anchor);need(before==after,'source_changed');witness.append(dict(name=database['name'],**after));continue
            for table_index,table in enumerate(database['tables']):
                check_deadline();name=table['name'];counts['table']=0
                context=dict(stage='committed_rows',database_index=db_index,database_role=database['kind'],table_index=table_index,table_role='committed_message' if database['kind']=='message' else 'auxiliary_snapshot')
                compare_schema(schema(remote,name),table['schema'],context,counts)
                if database['kind']=='message':
                    cols=[r[1] for r in table['schema']['columns']];need(next(r[5] for r in table['schema']['columns'] if r[1]=='local_id')==1,'source_pk_missing')
                    p=json.loads(table['progress']);maximum=remote.execute('SELECT MAX(local_id) FROM '+qi(name)).fetchone()[0]
                    maximum=0 if maximum is None else maximum
                    floor=max([table['rows']['max_local_id']]+[p[k] for k in ('H','tail','target') if type(p.get(k)) is int]);need(type(maximum) is int and maximum>=floor,'watermark_rollback')
                batch=[]
                def check_batch():
                    actual=list(rows(remote,name,[r[0] for r in batch]));compare_batch(batch,actual,context,counts)
                for row in rows(local,name):
                    batch.append(row)
                    if len(batch)==128:check_deadline();check_batch();batch=[]
                if batch:check_deadline();check_batch()
            if database['kind']=='message':
                frozen=database['names'];counts['table']=0
                context=dict(stage='limited_name2id',database_index=db_index,database_role='message',table_index=len(database['tables']),table_role='scope_self_sender_mapping')
                compare_schema(schema(remote,'Name2Id'),frozen['schema'],context,counts,code='mapping_schema_changed')
                ids=[r[0] for r in frozen['rows']]
                for start in range(0,len(ids),128):
                    check_deadline();selected=ids[start:start+128]
                    compare_batch(list(rows(local,'Name2Id',selected)),list(rows(remote,'Name2Id',selected)),context,counts,code='mapping_changed')
            after=source_stamp(database['source'],anchor);need(before==after,'source_changed');witness.append(dict(name=database['name'],**after))
        need(plan(config)['snapshot']==snapshot,'expected_changed');check_deadline()
        # No Source connection remains open when mutating only verified local identity metadata.
    if commit_check:commit_check()
    for database,new in zip(snapshot['databases'],witness):need(source_stamp(database['source'],anchor)=={k:new[k] for k in ('source_identity','source_header_sha256')},'source_changed')
    receipt=dict(version=1,nonce=nonce,expected_local_sha256=digest(snapshot),witness_sha256=digest(witness),grant_sha256=grant_digest,verified_sources=witness,verified_rows=sum(t['rows']['count'] for d in snapshot['databases'] for t in d['tables']),accepted=bool(accept),anchors_sha256=digest(anchor),snapshot_semantics='per_database_readonly_transaction_not_global_source_snapshot',row_hash='typed_rowid_and_all_source_columns_v1')
    receipt['auxiliary_refresh']=bool(auxiliary)
    if auxiliary:
        receipt['verified_rows']=sum(t['rows']['count'] for index,d in enumerate(snapshot['databases']) if index not in auxiliary for t in d['tables'])
        receipt['message_verified_rows']=sum(t['rows']['count'] for d in snapshot['databases'] if d['kind']=='message' for t in d['tables'])
        receipt['auxiliary_refreshed_rows']=sum(t['count'] for value in auxiliary.values() for t in value['tables'].values())
        receipt['auxiliary_snapshots']=[dict(database_index=index,mode=value['mode'],old_archive=value['old_archive'],new_snapshot=value['new_snapshot'],observed_at=value['observed_at'],table_counts={name:summary['count'] for name,summary in value['tables'].items()}) for index,value in auxiliary.items()]
    if not accept:return receipt
    need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce) and type(grant_digest) is str and len(grant_digest)==64,'accept_authority_missing')
    paths=[d['path'] for d in snapshot['databases']];c=sqlite3.connect(readonly_database_uri(Path(paths[0])).replace('mode=ro','mode=rw'),uri=True,isolation_level=None)
    try:
        cap=next((int(r[0].split('=')[1]) for r in c.execute('PRAGMA compile_options') if r[0].startswith('MAX_ATTACHED=')),10)
        need(len(paths)-1<=cap,'atomic_attach_limit')
        # Attach only frozen existing private files, never create a receipt database.
        for n,path in enumerate(paths[1:],1):private(path);c.execute('ATTACH DATABASE ? AS d'+str(n),(readonly_database_uri(Path(path)).replace('mode=ro','mode=rw'),))
        aliases=['main']+['d'+str(n) for n in range(1,len(paths))];atomic_preflight(c,aliases);c.execute('BEGIN IMMEDIATE')
        try:
            for alias,database in zip(aliases,snapshot['databases']):
                need(private(database['path'])==database['local_identity'],'local_replaced')
                need(c.execute('SELECT * FROM '+alias+'.__walden_binding').fetchall()==[tuple(database['binding'])],'binding_changed')
                for table in database['tables']:need(c.execute('SELECT value FROM '+alias+'.__walden_progress WHERE table_name=?',(table['name'],)).fetchone()==(table['progress'],),'expected_changed')
            need(plan(config)['snapshot']==snapshot,'expected_changed')
            check_deadline()
            if commit_check:commit_check()
            for database,new in zip(snapshot['databases'],witness):need(source_stamp(database['source'],anchor)=={k:new[k] for k in ('source_identity','source_header_sha256')},'source_changed')
            c.execute('CREATE TABLE IF NOT EXISTS __walden_verified_source_recovery(nonce TEXT PRIMARY KEY,receipt TEXT NOT NULL)')
            for index,(alias,database,new) in enumerate(zip(aliases,snapshot['databases'],witness)):
                if index in auxiliary:
                    captured=auxiliary[index]
                    need(artifact_hash(captured['old_archive']['path'])==captured['old_archive']['sha256'] and artifact_hash(captured['new_snapshot']['path'])==captured['new_snapshot']['sha256'],'auxiliary_artifact_changed')
                    with artifact_ro(captured['new_snapshot']['path']) as staged:
                        for table in database['tables']:
                            key=SourceKey(anchor['account_id'],anchor['source_generation'],database['name'],table['name']);store=MirrorStore.bound_transaction(database['path'],key,c,alias)
                            store.apply_batch(key,table['name'],paced_rows(staged,table['name']),json.loads(captured['progress'][table['name']]),replace_snapshot=True,_connection=c,_database=alias,_complete_snapshot=True)
                    continue
                for table in database['tables']:
                    progress=json.loads(table['progress']);progress['source_identity']=new['source_identity']
                    if database['kind']=='message' or 'source_header_sha256' in progress:progress['source_header_sha256']=new['source_header_sha256']
                    changed=c.execute('UPDATE '+alias+'.__walden_progress SET value=? WHERE table_name=? AND value=?',(json.dumps(progress,sort_keys=True),table['name'],table['progress']));need(changed.rowcount==1,'expected_changed')
            receipt_text=json.dumps(receipt,sort_keys=True)
            c.execute('INSERT INTO __walden_verified_source_recovery VALUES(?,?)',(nonce,receipt_text))
            # Read uncommitted state on THIS attached connection; external RO connections
            # cannot see trigger/constraint effects and cannot establish this postcondition.
            import copy
            for index,(alias,database,new) in enumerate(zip(aliases,snapshot['databases'],witness)):
                expected=copy.deepcopy(auxiliary[index]['effects'] if index in auxiliary else database['effects']);updates={}
                for table in ([] if index in auxiliary else database['tables']):
                    value=json.loads(table['progress']);value['source_identity']=new['source_identity']
                    if database['kind']=='message' or 'source_header_sha256' in value:value['source_header_sha256']=new['source_header_sha256']
                    updates[table['name']]=json.dumps(value,sort_keys=True)
                expected['progress']=[[name,updates.get(name,value)] for name,value in expected['progress']]
                if alias=='main':
                    if not any(r[2]==RECEIPT for r in expected['schema']):expected['schema']=sorted(expected['schema']+RECEIPT_SCHEMA,key=lambda r:(r[0],r[1]))
                    expected['receipts']=sorted(expected['receipts']+[[nonce,receipt_text]],key=lambda r:r[0])
                need(local_effects(c,alias)==expected,'postcondition_failed')
            check_deadline();c.execute('COMMIT')
        except BaseException:c.execute('ROLLBACK');raise
    finally:c.close()
    return receipt


def committed_receipt(snapshot,nonce,grant_sha256):
    """Read the same-transaction authority after a child died post-COMMIT.
    This is historical verified acceptance, never a fresh Source observation.
    """
    database=snapshot['databases'][0]
    with connect(database['path']) as c:
        need(c.execute('SELECT * FROM __walden_binding').fetchall()==[tuple(database['binding'])],'binding_changed')
        if not c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='__walden_verified_source_recovery'").fetchone():return None
        row=c.execute('SELECT receipt FROM __walden_verified_source_recovery WHERE nonce=?',(nonce,)).fetchone()
        if row is None:return None
        receipt=json.loads(row[0])
    need(receipt.get('accepted') is True and receipt.get('nonce')==nonce and receipt.get('grant_sha256')==grant_sha256 and receipt.get('expected_local_sha256')==digest(snapshot),'receipt_conflict')
    need([v.get('name') for v in receipt.get('verified_sources',[])]==[d['name'] for d in snapshot['databases']] and receipt.get('witness_sha256')==digest(receipt['verified_sources']),'receipt_conflict')
    if receipt.get('auxiliary_refresh'):
        retained=receipt.get('auxiliary_snapshots');need(type(retained) is list and len(retained)==1,'auxiliary_archive_mismatch')
        for item in retained:
            index=item['database_index'];need(snapshot['databases'][index]['name']=='contact.db' and item['mode']=='new_complete_authorized_contact_snapshot' and item['old_archive']['effects_sha256']==digest(snapshot['databases'][index]['effects']),'auxiliary_archive_mismatch')
            for key in ('old_archive','new_snapshot'):
                artifact=item[key];need(artifact_hash(artifact['path'])==artifact['sha256'],'auxiliary_artifact_changed')
                with artifact_ro(artifact['path']) as archived:need(digest(local_effects(archived))==artifact['effects_sha256'],'auxiliary_archive_mismatch')
    return receipt


CODES=frozenset(['recovery_auxiliary_artifact_invalid','recovery_auxiliary_artifact_changed','recovery_auxiliary_refresh_scope','recovery_auxiliary_stage_invalid','recovery_auxiliary_archive_mismatch','recovery_auxiliary_index_schema_changed','recovery_auxiliary_capture_mismatch','recovery_auxiliary_capture_effect','recovery_auxiliary_refresh_authority','recovery_local_trigger_unsupported','recovery_receipt_schema_unsupported','recovery_postcondition_failed','recovery_daily_scope_required', 'recovery_accept_authority_missing', 'recovery_anchors_changed', 'recovery_atomic_attach_limit', 'recovery_atomic_mode_unsupported', 'recovery_atomic_sync_unsupported', 'recovery_auxiliary_scope_missing', 'recovery_auxiliary_snapshot_missing', 'recovery_binding_changed', 'recovery_contact_self_missing', 'recovery_contact_self_schema_missing', 'recovery_expected_changed', 'recovery_local_file_unsafe', 'recovery_local_format_unsupported', 'recovery_local_replaced', 'recovery_local_snapshot_missing', 'recovery_mapping_changed', 'recovery_mapping_schema_changed', 'recovery_mapping_schema_missing', 'recovery_old_identity_missing', 'recovery_progress_invalid', 'recovery_progress_missing', 'recovery_receipt_conflict', 'recovery_row_mismatch', 'recovery_rowid_invalid', 'recovery_schema_changed', 'recovery_schema_missing', 'recovery_scope_invalid', 'recovery_self_or_scope_mapping_missing', 'recovery_self_unconfirmed', 'recovery_sender_mapping_missing', 'recovery_sender_schema_missing', 'recovery_snapshot_tables_missing', 'recovery_source_changed', 'recovery_source_encoding', 'recovery_source_not_readonly', 'recovery_source_outside_root', 'recovery_source_pk_missing', 'recovery_unscoped_local_table', 'recovery_unsupported_value', 'recovery_watermark_rollback'])


from .failure_evidence import _register
_register(artifact_hash,artifact_ro,copy_database,freeze_artifact,paced_rows,capture_contact_snapshot,safe_difference,difference_error,compare_batch,compare_schema,local_effects,need,scalar,row_hash,private,connect,schema,rows,row_summary,anchors,selected_names,plan,source_stamp,atomic_preflight,verify,committed_receipt)
