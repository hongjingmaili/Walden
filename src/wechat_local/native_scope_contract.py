"""Explicit fixed scope contracts and protected local table membership.

No Source opens, key access, service control or implicit all-scope conversion.
Registry observations are produced only by the admitted bounded synchronizer.
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time as _time
import uuid as _uuid
from .native_mirror_store import MirrorError
from .native_scope_add import read,create,need,sha,encoded
from .live_readonly import readonly_database_uri

MODE='mirror_scope_mode'
ID='scope_contract_id'
REGISTRY='__walden_account_scope.db'
PENDING='.account-scope.pending'
CURRENT='.account-scope.current'
TABLE=re.compile(r'Msg_[0-9a-f]{32}\Z')
SHARD=re.compile(r'(?:biz_)?message_[0-9]+\.db\Z')
# Bound both private metadata backups and the owned round's direct status view.
_REGISTRY_MAX_BYTES = 128 * 1024 * 1024

def digest(value):return sha(encoded(value))

def mode(config):
    value=config.get(MODE,'selected')
    need(value in ('selected','account'),'scope_mode_invalid')
    if value=='selected':
        members=config.get('mirror_scope')
        need(type(members) is list and members
             and all(type(s) is str and s and s.strip()==s and s!='*' for s in members)
             and len(members)==len(set(members)),'scope_invalid')
        need(ID not in config,'scope_mode_ambiguous')
    else:
        need('mirror_scope' not in config and type(config.get(ID)) is str
             and re.fullmatch('[0-9a-f]{32}',config[ID]) is not None,'scope_mode_ambiguous')
    return value

def fixed(config):
    need(mode(config)=='account','account_scope_required')
    def path(key):
        value=config.get(key);need(type(value) is str and Path(value).is_absolute(),'scope_root_invalid')
        need('..' not in Path(value).parts,'scope_root_invalid')
        return os.path.abspath(value)
    return dict(schema='walden.account.scope/1',mode='account',id=config[ID],
        account_id=config['account_id'],source_generation=config['source_generation'],
        live_db_root=path('live_db_root'),message_root=path('message_root'),mirror_root=path('mirror_root'),
        self_identity=config.get('self_identity'))

def binding(config):
    return fixed(config) if mode(config)=='account' else [config['account_id'],config['source_generation'],config['mirror_scope']]

def limited(config,targets,root):
    """Explicit downscope for an existing independently protected role/window."""
    result=dict(config);result.pop(MODE,None);result.pop(ID,None)
    result.update(mirror_scope=list(targets),mirror_root=str(root));mode(result)
    return result

def _optional(path):
    try:return read(path)[0]
    except FileNotFoundError:return None

def _pending(root):
    for name in (PENDING,'.scope-add.pending'):
        try:(root/name).lstat()
        except FileNotFoundError:pass
        else:raise MirrorError('scope_mode_pending')

def token(config):
    root=Path(config['mirror_root']);_pending(root)
    current=_optional(root/CURRENT)
    if current is None:
        need(mode(config)=='selected','account_scope_not_committed')
        from .native_scope_add import query_scope_guard
        query_scope_guard(config)
        return ('selected',None)
    need(mode(config)=='account','scope_mode_stale')
    value=json.loads(current);need(value.get('schema')=='walden.account.scope.current/1'
         and value.get('contract')==fixed(config),'scope_mode_stale')
    receipt_raw=read(value['receipt'])[0];receipt=json.loads(receipt_raw)
    need(sha(receipt_raw)==value.get('receipt_sha256') and receipt.get('state')=='committed'
         and receipt.get('contract')==fixed(config) and receipt.get('new_config_sha256')==digest(config),'account_scope_receipt_invalid')
    legacy=_optional(root/'.scope-add.current')
    need((sha(legacy) if legacy is not None else None)==receipt.get('legacy_current_sha256'),'legacy_scope_current_changed')
    if legacy is not None:
        old=json.loads(legacy);old_receipt=read(old['receipt'])[0]
        need(sha(old_receipt)==old.get('receipt_sha256')==receipt.get('legacy_receipt_sha256')
             and json.loads(old_receipt).get('state')=='committed','legacy_scope_receipt_changed')
    _pending(root)
    need(_optional(root/CURRENT)==current,'scope_mode_changed')
    return ('account',sha(current))

def query_scope_guard(config,before=None):
    if not config.get('mirror_root'):return None
    current=token(config)
    if before is not None:need(before==current,'scope_mode_changed')
    return current

def loaded_scope_guard(profile,config):
    root=Path(config.get('mirror_root','/nonexistent'));_pending(root)
    if _optional(root/CURRENT) is None:
        from .native_scope_add import loaded_scope_guard as legacy
        return legacy(profile,config)
    # Existing authenticated old snapshots remain readable for original SDK Stop,
    # but query and Source entry still call the normal current-mode guard.
    current=json.loads(read(root/CURRENT)[0]);receipt=json.loads(read(current['receipt'])[0])
    for snapshot in receipt.get('stop_snapshots',[]):
        if str(Path(profile).absolute())==snapshot.get('path'):
            need(digest(config)==snapshot.get('config_sha256'),'scope_snapshot_changed');return
    query_scope_guard(config)

def target_ref(config,shard,table):
    need(SHARD.fullmatch(shard) and TABLE.fullmatch(table),'scope_table_invalid')
    return digest([fixed(config),shard,table])

def _safe(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        value=os.fstat(fd);need(stat.S_ISREG(value.st_mode) and value.st_uid==os.getuid()
            and stat.S_IMODE(value.st_mode)==0o600 and value.st_nlink==1,'scope_registry_unsafe')
        return (value.st_dev,value.st_ino)
    finally:os.close(fd)

def _registry_page_size(conn):
    page_size=conn.execute('PRAGMA page_size').fetchone()[0];pages=conn.execute('PRAGMA page_count').fetchone()[0]
    need(page_size*pages<=_REGISTRY_MAX_BYTES,'local_registry_snapshot_budget')
    return page_size


def _registry_snapshot(conn):
    """One coherent metadata snapshot; no disk read lock survives the copy."""
    import time
    from .native_deadline import _current
    page_size=_registry_page_size(conn)
    snapshot=sqlite3.connect(':memory:',timeout=.1);started=time.monotonic();deadline=_current.get()
    def progress(status,remaining,total):
        if deadline is not None:deadline.check()
        if status in (5,6) and time.monotonic()-started>=.1:raise MirrorError('local_registry_read_busy')
        need(total*page_size<=_REGISTRY_MAX_BYTES and time.monotonic()-started<=2.,'local_registry_snapshot_budget')
    try:
        conn.backup(snapshot,pages=64,progress=progress,sleep=0)
        return snapshot
    except BaseException:
        snapshot.close();raise


@contextlib.contextmanager
def registry(config,*,write=False,initialize=False,snapshot=True):
    need(mode(config)=='account','account_scope_required');before=None if write else query_scope_guard(config);root=Path(config['mirror_root']);path=root/REGISTRY
    # Same protected-directory checks as immutable existing scope transactions.
    from .native_scope_add import directory
    with directory(root):pass
    if initialize:
        fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
    identity=_safe(path)
    conn=sqlite3.connect(str(path) if write else readonly_database_uri(path),uri=not write,timeout=.1)
    try:
        if initialize:
            conn.executescript('CREATE TABLE binding(value TEXT NOT NULL);'
                'CREATE TABLE observations(id TEXT PRIMARY KEY,proof TEXT NOT NULL);'
                'CREATE TABLE members(shard TEXT,table_name TEXT,proof TEXT NOT NULL,PRIMARY KEY(shard,table_name));'
                'CREATE TABLE state(key TEXT PRIMARY KEY,value TEXT NOT NULL);')
            conn.execute('INSERT INTO binding VALUES(?)',(json.dumps(fixed(config),sort_keys=True),))
            conn.execute('INSERT INTO state VALUES(?,?)',('shard_anchor_schema','1'));conn.commit()
        need(conn.execute('SELECT value FROM binding').fetchall()==[(json.dumps(fixed(config),sort_keys=True),)],'scope_registry_binding')
        need(state(conn,'shard_anchor_schema')==1,'scope_registry_schema')
        if not write and snapshot:
            copied=_registry_snapshot(conn);conn.close();conn=copied
            need(conn.execute('SELECT value FROM binding').fetchall()==[(json.dumps(fixed(config),sort_keys=True),)],'scope_registry_binding')
            need(state(conn,'shard_anchor_schema')==1,'scope_registry_schema')
        if not write:conn.execute('PRAGMA query_only=ON');conn.execute('BEGIN')
        yield conn
        need(_safe(path)==identity,'scope_registry_replaced')
        if not write:
            query_scope_guard(config,before)
            fresh=sqlite3.connect(readonly_database_uri(path),uri=True,timeout=.1)
            try:
                fresh.execute('PRAGMA query_only=ON')
                need(fresh.execute('SELECT value FROM binding').fetchall()==[(json.dumps(fixed(config),sort_keys=True),)],'scope_registry_binding')
                need(state(fresh,'shard_anchor_schema')==1,'scope_registry_schema')
            finally:fresh.close()
            need(_safe(path)==identity,'scope_registry_replaced');query_scope_guard(config,before)
    finally:conn.close()

def state(conn,key,default=None):
    row=conn.execute('SELECT value FROM state WHERE key=?',(key,)).fetchone()
    return json.loads(row[0]) if row else default

def save(conn,key,value):conn.execute('INSERT OR REPLACE INTO state VALUES(?,?)',(key,json.dumps(value,sort_keys=True)))

def register(config,conn,observation,members):
    """Admitted active/drain only; migration uses its authenticated seed path."""
    from .native_deadline import _current
    from .native_follow_grant import FollowDeadline
    from .native_follow_policy import digest as source_digest
    deadline=_current.get()
    need(isinstance(deadline,FollowDeadline) and deadline.grant.get('kind') in ('active','drain')
         and deadline.grant.get('source_sha256')==source_digest(config),'account_source_role_required')
    deadline.check()
    return _register_members(config,conn,observation,members)


def _register_members(config,conn,observation,members):
    """Private primitive, also used after pinned legacy migration preservation."""
    need(observation.get('contract')==fixed(config) and observation.get('query_only') is True
         and SHARD.fullmatch(observation.get('shard','')) and type(observation.get('source_identity')) is list
         and len(observation['source_identity'])==2 and re.fullmatch('[0-9a-f]{64}',observation.get('header','')),'scope_observation_invalid')
    anchor=dict(source_identity=observation['source_identity'],header=observation['header'])
    prior_anchor=state(conn,'shard_anchor:'+observation['shard'],None)
    need(prior_anchor is None or prior_anchor==anchor,'scope_source_conflict')
    if prior_anchor is None:
        need(conn.execute('SELECT 1 FROM members WHERE shard=? LIMIT 1',(observation['shard'],)).fetchone() is None,'scope_shard_anchor_missing')
        save(conn,'shard_anchor:'+observation['shard'],anchor)
    obs_id=digest(observation);conn.execute('INSERT OR IGNORE INTO observations VALUES(?,?)',(obs_id,json.dumps(observation,sort_keys=True)))
    for item in members:
        table=item['table'];need(TABLE.fullmatch(table) and [table,item['schema_sha256']] in observation['tables'],'scope_member_invalid')
        old=conn.execute('SELECT proof FROM members WHERE shard=? AND table_name=?',(observation['shard'],table)).fetchone()
        proof=dict(item,observation=obs_id,ref=target_ref(config,observation['shard'],table),source_identity=observation['source_identity'],header=observation['header'])
        if old:
            prior=json.loads(old[0]);need(all(prior.get(k)==proof.get(k) for k in ('source_identity','header','schema_sha256')),'scope_source_conflict')
            need(prior.get('username') in (None,proof.get('username')),'conversation_identity_conflict')
        conn.execute('INSERT OR REPLACE INTO members VALUES(?,?,?)',(observation['shard'],table,json.dumps(proof,sort_keys=True)))

def member(config,conn,shard,table):
    row=conn.execute('SELECT proof FROM members WHERE shard=? AND table_name=?',(shard,table)).fetchone();need(row is not None,'scope_table_unregistered')
    proof=json.loads(row[0]);obs=conn.execute('SELECT proof FROM observations WHERE id=?',(proof.get('observation'),)).fetchone()
    need(obs is not None,'scope_member_proof');observation=json.loads(obs[0])
    need(digest(observation)==proof['observation'] and observation.get('contract')==fixed(config)
         and observation.get('shard')==shard and observation.get('query_only') is True
         and [table,proof.get('schema_sha256')] in observation.get('tables',[])
         and proof.get('source_identity')==observation.get('source_identity') and proof.get('header')==observation.get('header')
         and proof.get('ref')==target_ref(config,shard,table),'scope_member_proof')
    need(state(conn,'shard_anchor:'+shard,None)==dict(source_identity=proof['source_identity'],header=proof['header']),'scope_source_conflict')
    return proof

def authorized(config,username=None,*,shard=None,table=None):
    if mode(config)=='selected':
        need(username in config['mirror_scope'],'scope_not_authorized');return
    query_scope_guard(config)
    with registry(config,snapshot=shard is None) as conn:
        if shard is not None:
            proof=member(config,conn,shard,table);need(username is None or proof.get('username')==username,'scope_not_authorized');return proof
        need(type(username) is str and username,'scope_not_authorized')
        rows=conn.execute('SELECT shard,table_name FROM members').fetchall()
        need(any(member(config,conn,s,t).get('username')==username for s,t in rows),'scope_not_authorized')

def selection(config,username=None,ref=None):
    before=query_scope_guard(config)
    with registry(config) as conn:
        rows=conn.execute('SELECT shard,table_name FROM members ORDER BY shard,table_name').fetchall()
        selected=[(s,t,member(config,conn,s,t)) for s,t in rows if (ref is None or target_ref(config,s,t)==ref)]
        selected=[v for v in selected if ref is not None or v[2].get('username')==username]
        need(selected,'scope_not_authorized')
    query_scope_guard(config,before);return selected

from .failure_evidence import _register
_register(mode,fixed,binding,limited,token,query_scope_guard,loaded_scope_guard,registry,register,member,authorized,selection)


def account_status(config,*,offset=0,limit=100,include_targets=False,_writer_locked=False):
    """Read local metadata. Only an owning writer may keep a direct read transaction."""
    from .native_deadline import Deadline, _current, check_deadline
    before=query_scope_guard(config)
    deadline=_current.get() if _writer_locked else None
    need(type(offset) is int and offset>=0 and type(limit) is int and 1<=limit<=1000,'scope_pagination')
    targets=[];counts=dict(registered=0,copied=0,raw_complete=0,identity_unknown=0,unsupported=0)
    gaps=[];watermarks=[]
    root=Path(config['mirror_root'])
    with registry(config,snapshot=not _writer_locked) as db:
        if _writer_locked:
            check_deadline()
            _registry_page_size(db)
        roster=state(db,'roster',[]);inventory=[]
        last=state(db,'last_attempt',{});gaps+=last.get('gaps',[])
        local_progress={}
        for shard in roster:
            # Check the clocks during the local scan. The enclosing status call
            # also revalidates the complete grant on entry and exit.
            if deadline is not None:Deadline.check(deadline)
            inventory.append(state(db,'inventory:'+shard,{}))
            gaps+=state(db,'gaps:'+shard,[])
            path=root/shard
            if not path.is_file():continue
            _safe(path)
            conn=sqlite3.connect(readonly_database_uri(path),uri=True)
            try:
                conn.execute('PRAGMA query_only=ON')
                need(conn.execute('SELECT * FROM __walden_binding').fetchall()==[(config['account_id'],config['source_generation'],shard)],'source_identity_mismatch')
                progress_by_table={}
                for index,(table,value) in enumerate(conn.execute('SELECT table_name,value FROM __walden_progress')):
                    if deadline is not None and index%64==0:Deadline.check(deadline)
                    progress_by_table[table]=json.loads(value)
                local_progress[shard]=progress_by_table
            finally:conn.close()
        inventory_complete=bool(roster) and all(v.get('complete') is True for v in inventory)
        for shard,table in db.execute('SELECT shard,table_name FROM members ORDER BY shard,table_name'):
            if deadline is not None and counts['registered']%64==0:Deadline.check(deadline)
            proof=member(config,db,shard,table);counts['registered']+=1
            if proof.get('username') is None:counts['identity_unknown']+=1
            if not proof.get('supported'):counts['unsupported']+=1;gaps.append('unsupported_message_schema')
            if proof.get('available') is False:gaps.append('source_table_missing')
            progress=local_progress.get(shard,{}).get(table)
            complete=False
            if progress:
                need(progress.get('source_identity')==proof['source_identity'] and progress.get('source_header_sha256')==proof['header'],'scope_copy_proof')
                counts['copied']+=1
                complete=bool(type(progress.get('target')) is int and progress.get('history_complete') and progress['history']>=progress['H'] and progress['tail']>=progress['target'])
                if complete:counts['raw_complete']+=1
                watermarks.append(progress.get('checked_at'))
            if include_targets and offset<=counts['registered']-1<offset+limit:
                targets.append(dict(target_ref=proof['ref'],username=proof.get('username'),identity_status='resolved' if proof.get('username') else 'unknown',shard=shard,table=table,copied=progress is not None,raw_complete=complete,supported=proof.get('supported') is True))
    from .native_media_work import backfill_status
    media_backfill=backfill_status(config)
    query_scope_guard(config,before)
    if _writer_locked:
        check_deadline()
    raw_complete=bool(inventory_complete and counts['registered'] and counts['raw_complete']==counts['registered'] and not counts['unsupported'] and not gaps)
    return dict(scope_mode='account',account_authorized=True,contract_id=config[ID],inventory_complete=inventory_complete,
        inventory_refresh_requested_shards=sum(v.get('refresh_requested') is True for v in inventory),inventory_evidence='last_bounded_stable_pass_not_atomic_current_source',
        counts=counts,raw_messages_complete=raw_complete,identity_complete=counts['identity_unknown']==0,
        known_backlog=not raw_complete,last_full_observation=min((v.get('checked_at_ns',0) for v in inventory),default=None) if inventory_complete else None,
        copied_as_of=min((n for n in watermarks if type(n) is int),default=None),atomic_global_snapshot=False,
        recent_coverage='not_proven_by_history_tail',media_complete='separate_worker_status',media_backfill=media_backfill,gaps=sorted(set(gaps)),targets=targets,offset=offset,limit=limit,
        next_offset=offset+limit if offset+limit<counts['registered'] else None,source_opens=0)

# ---------------------------------------------------------------------------
# Account-mode source re-anchor after a verified same-source device-number
# renumber (macOS APFS data-volume device id reassigned on reboot / re-mount).
#
# This is a supported-product capability gap: when the live WeChat shard volume
# is re-mounted and the operating system re-assigns st_dev while st_ino and the
# first-16-byte header are unchanged, the source is provably the *same* file,
# but the scope-contract registry anchor (pinned to the old st_dev) does not
# match and the synchronizer raises scope_source_conflict. That mismatch can
# recur on every reboot, so the re-anchor is intentionally repeatable, gated,
# and auditable rather than a one-shot patch.
#
# Hard precondition (same-source proof): per shard, the live file must keep the
# same inode and the same header as the anchored proof while ONLY st_dev differs.
# A differing inode or header is a real source change and is rejected (never
# overwritten). native_mirror_sync:525 is NOT relaxed; this only pre-updates the
# registry anchor + member proofs + the referenced observations row, and the
# local mirror __walden_progress metadata, to the verified-live identity so the
# per-shard comparison there passes for a genuine renumber.
# ---------------------------------------------------------------------------

REANCHOR_KIND = 'account_source_reanchor'


def _live_shard_identity(message_root):
    """Live source identity exactly as the synchronizer computes it
    (native_mirror_sync.py:522-523): [st_dev, st_ino] and sha256(first16bytes)."""
    root = Path(message_root)
    out = {}
    if root.is_dir():
        for name in os.listdir(root):
            if SHARD.fullmatch(name):
                p = root / name
                try:
                    st = p.stat()
                except OSError:
                    continue
                identity = [st.st_dev, st.st_ino]
                try:
                    with p.open('rb') as fh:
                        header_hash = hashlib.sha256(fh.read(16)).hexdigest()
                except OSError:
                    continue
                out[name] = (identity, header_hash)
    return out


def stale_shards(config, conn):
    """Read-only fingerprint: classify each anchored shard vs the live source.

    result shard -> one of:
      'renumber' : prior anchor header+inode match live, only st_dev differs -> re-anchorable
      'changed'  : header or inode differ -> real source change, NOT re-anchorable (rejected)
      'current'  : prior anchor already matches live -> nothing to do (idempotent)
      'missing'  : live source file absent -> cannot prove same-source (skipped, non-fatal)
    """
    live = _live_shard_identity(config['message_root'])
    result = {}
    for (key,) in conn.execute("SELECT key FROM state WHERE key LIKE 'shard_anchor:%'"):
        shard = key[len('shard_anchor:'):]
        prior = state(conn, key)
        if shard not in live:
            result[shard] = 'missing'
            continue
        live_identity, live_header = live[shard]
        prior_identity = prior['source_identity']
        prior_header = prior['header']
        if prior_identity == live_identity and prior_header == live_header:
            result[shard] = 'current'
            continue
        inode_ok = prior_identity[1] == live_identity[1]
        header_ok = prior_header == live_header
        if inode_ok and header_ok and prior_identity[0] != live_identity[0]:
            result[shard] = 'renumber'
        else:
            result[shard] = 'changed'
    return result


def reanchor_sources(config, conn, *, grant):
    """Account-mode re-anchor of registry shard_anchor:* + member proofs (and the
    referenced observations) + local mirror __walden_progress after a verified
    same-source device-number renumber.

    Explicit authorization gate; same-source proof is a hard precondition; writes
    an audit receipt into the registry. Registry changes are a single transaction
    (rolled back on any failure); local metadata updates are idempotent and
    re-runnable. Does not relax identity/source guards.
    """
    need(grant and grant.get('accept') is True and grant.get('authorized') is True
         and grant.get('kind') == REANCHOR_KIND
         and type(grant.get('nonce')) is str and grant.get('nonce'),
         'account_reanchor_authorization_required')
    from .native_follow_policy import digest as source_digest
    need(grant.get('source_sha256') == source_digest(config), 'account_reanchor_source_conflict')
    nonce = grant['nonce']
    contract = fixed(config)
    live = _live_shard_identity(config['message_root'])
    root = Path(config['mirror_root'])
    # Phase 1: read-only same-source proof for every anchored shard. Abort before
    # any mutation if a shard's proof fails or the live source is missing.
    plans = []
    rejected = []
    missing = []
    for (key,) in conn.execute("SELECT key FROM state WHERE key LIKE 'shard_anchor:%'"):
        shard = key[len('shard_anchor:'):]
        prior = state(conn, key)
        if shard not in live:
            missing.append(shard)
            continue
        live_identity, live_header = live[shard]
        prior_identity = prior['source_identity']
        prior_header = prior['header']
        if prior_identity == live_identity and prior_header == live_header:
            continue  # already current -> nothing to do (idempotent)
        inode_ok = prior_identity[1] == live_identity[1]
        header_ok = prior_header == live_header
        if not (inode_ok and header_ok and prior_identity[0] != live_identity[0]):
            # Real source change (inode or header differ, or st_dev unchanged) -> reject.
            rejected.append(shard)
            continue
        plans.append((shard, key, prior_identity, prior_header, live_identity, live_header))
    if rejected:
        # Never partially re-anchor when any shard's same-source proof fails.
        raise MirrorError('account_reanchor_source_changed')
    # Phase 2: apply registry updates (staged; committed last) so the operation is
    # atomic at the registry layer.
    changes = {}
    for (shard, key, prior_identity, prior_header, live_identity, live_header) in plans:
        members_rows = conn.execute(
            'SELECT table_name, proof FROM members WHERE shard=?', (shard,)).fetchall()
        member_proofs = [(t, json.loads(p)) for t, p in members_rows]
        for _, proof in member_proofs:
            need(proof.get('source_identity') == prior_identity
                 and proof.get('header') == prior_header,
                 'account_reanchor_member_inconsistent')
        # Fresh observation for the verified-live identity (keeps member() proof
        # checks consistent: proof.source_identity == observation.source_identity
        # == proof['observation']). Schema sha256 is preserved from existing proofs.
        observation = dict(contract=contract, shard=shard, source_identity=live_identity,
                           header=live_header, query_only=True, schema_cookie=None,
                           at_ns=_time.time_ns(),
                           tables=[[t, proof['schema_sha256']] for t, proof in member_proofs])
        obs_id = digest(observation)
        conn.execute('INSERT OR IGNORE INTO observations VALUES(?,?)',
                     (obs_id, json.dumps(observation, sort_keys=True)))
        for table_name, proof in member_proofs:
            proof['source_identity'] = live_identity
            proof['header'] = live_header
            proof['observation'] = obs_id
            conn.execute('UPDATE members SET proof=? WHERE shard=? AND table_name=?',
                         (json.dumps(proof, sort_keys=True), shard, table_name))
        save(conn, key, dict(source_identity=live_identity, header=live_header))
        changes[shard] = dict(prior_identity=prior_identity, prior_header=prior_header,
                              new_identity=live_identity, new_header=live_header)
    # Phase 3: local __walden_progress metadata update (same-source, idempotent).
    # The synchronizer validates progress.source_identity against the live identity
    # at its copy step (native_mirror_sync.py:342-343 / :660) and raises
    # 'source_replaced' otherwise, so the local metadata must also be advanced.
    for (shard, key, prior_identity, prior_header, live_identity, live_header) in plans:
        local_path = root / shard
        if not local_path.is_file():
            continue
        lconn = sqlite3.connect(str(local_path), timeout=0.1)
        try:
            for table_name, raw in lconn.execute(
                    "SELECT table_name, value FROM __walden_progress").fetchall():
                progress = json.loads(raw)
                if (progress.get('source_identity') == prior_identity
                        and progress.get('source_header_sha256') == prior_header):
                    progress['source_identity'] = live_identity
                    progress['source_header_sha256'] = live_header
                    lconn.execute('UPDATE __walden_progress SET value=? WHERE table_name=?',
                                  (json.dumps(progress, sort_keys=True), table_name))
            lconn.commit()
        finally:
            lconn.close()
    # Phase 4: audit receipt (registry, committed with the anchor changes).
    receipt = dict(nonce=nonce, kind=REANCHOR_KIND, at_wall_ns=_time.time_ns(),
                   config_sha256=source_digest(config),
                   expected_source_sha256=grant.get('source_sha256'),
                   changes=changes,
                   summary=dict(renumbered=sorted(changes),
                                rejected=rejected, missing=missing,
                                unchanged=len([s for s in live if s not in changes])))
    save(conn, 'source_reanchor_receipt:' + nonce, receipt)
    try:
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return dict(renumbered=sorted(changes), rejected=rejected, missing=missing,
                changes=changes, receipt_nonce=nonce)


def reanchor_cli(config, config_path, *, expected_source_sha256, authorize=False, accept=False):
    """CLI entry for `account-scope-reanchor`. Read-only fingerprint unless
    explicitly authorized; then acquires the mirror writer lock and re-anchors
    under a single-shot grant. Never runs without --authorize-source-verification
    --accept-verified-identity and a matching --expected-source-sha256."""
    from .native_mirror_sync import writer_lock, mirror_root
    root = mirror_root(config, create=False)
    timeout = float(config.get('mirror_lock_timeout', 10))
    with writer_lock(root, timeout), registry(config, write=True) as conn:
        fingerprint = stale_shards(config, conn)
        if not (authorize and accept):
            return dict(status='needs_reanchor_authorization', stage='account_reanchor_plan',
                        fingerprint=fingerprint, source_opened=True, local_mutated=False)
        grant = dict(kind=REANCHOR_KIND, authorized=True, accept=True,
                     source_sha256=expected_source_sha256, nonce=_uuid.uuid4().hex)
        result = reanchor_sources(config, conn, grant=grant)
    result['status'] = 'completed'
    result['stage'] = 'account_reanchor'
    result['source_opened'] = True
    result['local_mutated'] = True
    return result


_register(_registry_page_size,_registry_snapshot,account_status,_register_members,state,save,_safe,_optional,_pending,target_ref)
