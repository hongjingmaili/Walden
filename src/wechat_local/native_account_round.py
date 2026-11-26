"""Bounded round evidence and positive history hints; neither grants authority."""
import hashlib
import json
import time
from .native_mirror_store import MirrorError

TURN='history_fair_turn'
HEAD='history_fair_head:'
MAX_TAIL=3

def target(shard,table):return hashlib.sha256((shard+'\0'+table).encode()).hexdigest()

class Evidence:
    def __init__(self):self.started=time.monotonic();self.events=[];self.dropped=0
    def add(self,stage,reason,**values):
        try:self._add(stage,reason,**values)
        except Exception:self.dropped+=1  # Diagnostic failure never replaces a guard/commit error.
    def _add(self,stage,reason,**values):
        # Callers provide only fixed enums, integers and technical digests.
        limit=64 if stage in ('terminal','independent_status') else 62
        if len(self.events)>=limit:self.dropped+=1;return
        row=dict(stage=stage,reason=reason,elapsed_ms=max(0,int((time.monotonic()-self.started)*1000)),**values)
        if len(json.dumps(self.events+[row]).encode())>16384:self.dropped+=1;return
        self.events.append(row)
        from .failure_evidence import round_evidence
        round_evidence(self.result())
    def result(self):return dict(version=1,events=list(self.events),dropped=self.dropped)

def _read(registry,key,budget,default):
    from .native_account_copy_init import charge
    from .native_scope_contract import state
    row=registry.execute('SELECT length(CAST(value AS BLOB)) FROM state WHERE key=?',(key,)).fetchone()
    size=0 if row is None else row[0]
    if type(size) is not int or not 0<=size<=4096:raise MirrorError('account_fairness_invalid')
    charge(budget,size+8)
    return state(registry,key,default)

def _save(registry,key,value,budget,*,paid=False):
    from .native_account_copy_init import charge
    from .native_scope_contract import save
    raw=json.dumps(value,sort_keys=True).encode()
    if len(raw)>4096:raise MirrorError('account_fairness_invalid')
    if not paid:charge(budget,len(raw)+len(key.encode()))
    save(registry,key,value)

def start(registry,paths,budget,round_number,instance):
    """A prior unfinished round keeps its debt, not a false zero counter."""
    from .native_account_copy_init import charge
    value=_read(registry,TURN,budget,None)
    if value is None:value=dict(version=1,streak=0,finished=round_number,instance=instance,after='')
    if (type(value) is not dict or value.get('version')!=1 or type(value.get('streak')) is not int
            or not 0<=value['streak']<=MAX_TAIL or type(value.get('finished')) is not int
            or type(value.get('after')) is not str):raise MirrorError('account_fairness_invalid')
    interrupted=value['finished']!=round_number or value.get('instance')!=instance
    if interrupted:
        # Persist the single uncertain-round allowance before Source copying.
        # A second restart cannot mint another allowance from the same debt.
        value['streak']=MAX_TAIL if value.get('recovery_tail_reserved') else max(value['streak'],MAX_TAIL-1)
        value['recovery_tail_reserved']=True
    value.update(inflight=round_number+1,instance=instance)
    # Pay the bounded entry/final publication even if body work later defers.
    charge(budget,2048)
    _save(registry,TURN,value,budget,paid=True)
    heads={}
    for path in paths:
        head=_read(registry,HEAD+path.name,budget,None)
        if head is not None:
            if (type(head) is not dict or set(head)!={'table','source_identity','header','H','history'}
                    or type(head['H']) is not int or head['H']<1
                    or type(head.get('history')) is not int or not 0<=head['history']<head['H']):raise MirrorError('account_fairness_invalid')
            heads[path.name]=head
    budget['_fair_turn']=value;budget['_fair_heads']=heads
    return interrupted

def remember(registry,shard,table,progress,anchor,budget):
    """Called only for positive original pinned progress under the writer."""
    heads=budget.get('_fair_heads')
    if heads is None or shard in heads or progress.get('initial_suffix_pending'):return
    if not 0<=progress['history']<progress['H']:return
    value=dict(table=table,source_identity=anchor['source_identity'],header=anchor['header'],H=progress['H'],history=progress['history'])
    _save(registry,HEAD+shard,value,budget);heads[shard]=value

def choose(paths,ready,budget,priority):
    heads=budget.get('_fair_heads',{});turn=budget.get('_fair_turn',{})
    if not heads or priority and turn.get('streak',0)<MAX_TAIL:return None
    candidates=[p for p in paths if p.name in heads and ready.get(p.name)]
    return min(candidates,key=lambda p:(p.name<=turn.get('after',''),p.name)) if candidates else None

def recover_generation_head(registry, shard, table, progress, archives, budget):
    """A committed rotation can survive a crash before the registry update."""
    head = budget['_fair_heads'].get(shard)
    if head is None or head['table'] != table:
        return False
    if progress['H'] == head['H'] and head['history'] <= progress['history']:
        return True
    if not any(prior['H'] == head['H'] and head['history'] <= prior['history'] for prior in archives):
        raise MirrorError('scope_copy_proof')
    if progress['history'] >= progress['H']:
        registry.execute('DELETE FROM state WHERE key=?', (HEAD+shard,))
        budget['_fair_heads'].pop(shard)
        return False
    changed = dict(head, H=progress['H'], history=progress['history'])
    _save(registry, HEAD+shard, changed, budget)
    budget['_fair_heads'][shard]=changed
    return True


def prepare(registry,shard,table,progress,budget,*,history,proof):
    """Pay publication and reserve its guarded COMMIT before a local batch."""
    from .native_account_copy_init import charge
    from .native_account_witness import _COMMIT_CHECK_BYTES,WorkBudgetStop
    turn=budget.get('_fair_turn')
    if turn is None:return
    cost=getattr(getattr(registry,'owner',None),'admit_cost',0)+_COMMIT_CHECK_BYTES
    if budget['tail_probe']['bytes']+cost+2048>budget['tail_probe']['ceiling']:
        raise WorkBudgetStop('account_fairness_publication_budget',budget_kind='metadata_bytes',limit=budget['tail_probe']['ceiling'],used=budget['tail_probe']['bytes'],required=cost+2048)
    charge(budget,2048)
    if history:
        head=budget['_fair_heads'].get(shard)
        if (head is None or head['table']!=table or progress is None
                or progress.get('source_identity')!=proof['source_identity']
                or progress.get('source_header_sha256')!=proof['header']
                or progress.get('H')!=head['H'] or progress.get('initial_suffix_pending')
                or type(progress.get('history')) is not int or not head['history']<=progress['history']<=head['H']):raise MirrorError('scope_copy_proof')
        if progress['history']>head['history']:
            updated=dict(turn,streak=0,recovery_tail_reserved=False,after=shard)
            changed=dict(head,history=progress['history'])
            registry.execute('SAVEPOINT fair_ack')
            try:
                if progress['history']>=head['H']:registry.execute('DELETE FROM state WHERE key=?',(HEAD+shard,))
                else:_save(registry,HEAD+shard,changed,budget,paid=True)
                _save(registry,TURN,updated,budget,paid=True)
            except BaseException:
                registry.execute('ROLLBACK TO fair_ack');registry.execute('RELEASE fair_ack');raise
            registry.execute('RELEASE fair_ack')
            budget['_fair_turn']=updated
            if progress['history']>=head['H']:budget['_fair_heads'].pop(shard)
            else:budget['_fair_heads'][shard]=changed
            return 'history_already_committed'
    probe=budget['tail_probe']
    budget['_fair_publication_reserve']=(probe['ceiling'],probe.get('finish_reserve',0))
    probe['ceiling']-=cost
    probe['finish_reserve']=probe.get('finish_reserve',0)+cost


def release(budget):
    """Restore the body ceiling before spending the actual guarded COMMIT fee."""
    previous=budget.pop('_fair_publication_reserve',None)
    if previous is not None:
        budget['tail_probe']['ceiling'],budget['tail_probe']['finish_reserve']=previous

def committed(registry,shard,table,entry,budget):
    turn=budget.get('_fair_turn')
    if turn is None:return
    updated=dict(turn);kind=entry['batch_kind'];progress=entry['progress']
    if kind=='tail' and entry['tail_advanced']:updated['streak']=min(MAX_TAIL,updated['streak']+1)
    elif kind=='history' and entry['history_advanced']:updated.update(streak=0,after=shard,recovery_tail_reserved=False)
    head=budget['_fair_heads'].get(shard)
    changed=dict(head,history=progress['history']) if head is not None and head['table']==table and kind in ('history','cursor_generation') else head
    if changed is not head and kind=='cursor_generation':
        changed['H']=progress['H']
    remove=head is not None and head['table']==table and progress['history']>=changed['H']
    registry.execute('SAVEPOINT fair_service')
    try:
        if remove:registry.execute('DELETE FROM state WHERE key=?',(HEAD+shard,))
        elif changed is not head:_save(registry,HEAD+shard,changed,budget,paid=True)
        _save(registry,TURN,updated,budget,paid=True)
    except BaseException:
        registry.execute('ROLLBACK TO fair_service');registry.execute('RELEASE fair_service');raise
    registry.execute('RELEASE fair_service')
    budget['_fair_turn']=updated
    if remove:budget['_fair_heads'].pop(shard)
    elif changed is not head:budget['_fair_heads'][shard]=changed


def finish(registry,budget):
    turn=budget.get('_fair_turn')
    if turn is not None:
        turn['finished']=turn['inflight'];_save(registry,TURN,turn,budget,paid=True)

def deferred(evidence,budget,reason,error=None,*,location=None,fact=None):
    """No re-entry into authorization/Source/status to format a diagnostic."""
    probe=budget.get('tail_probe',{})
    if error is not None:
        code=error.args[0] if error.args and type(error.args[0]) is str else None
        if code in ('registry_reuse_history_deferred','account_reconcile_source_budget','account_copy_init_observation_deferred'):reason='time'
        elif code in (None,'account_fairness_publication_budget','account_work_budget'):reason='metadata'
    fact=fact or getattr(error,'budget_fact',None) or {}
    details={k:fact[k] for k in ('limit','used','required') if type(fact.get(k)) is int and fact[k]>=0}
    if fact.get('kind') in ('metadata_bytes','metadata_ms','source_ms','rows','row_bytes','tables','metadata_tables','tail_queue'):details['stop_kind']=fact['kind']
    elif reason=='time':details.update(stop_kind='source_ms',limit=20000,used=max(0,int((time.monotonic()-budget.get('started',budget['until']-20))*1000)))
    elif reason=='rows':details.update(stop_kind='rows',limit=budget['rows'],used=budget['used_rows'])
    elif reason=='bytes':details.update(stop_kind='row_bytes',limit=budget['bytes'],used=budget['used_bytes'])
    elif reason=='tables':details.update(stop_kind='tables',limit=budget['tables'],used=budget['used_tables'])
    elif reason=='metadata':details.update(stop_kind='metadata_bytes',limit=probe.get('ceiling',1048576),used=probe.get('bytes',0))
    if location is not None:details['at_stage']=location
    evidence.add('budget','deferred_'+reason,**details,metadata_used=probe.get('bytes',0),metadata_limit=probe.get('ceiling',1048576),rows_used=budget['used_rows'],rows_limit=budget['rows'])


def probe_stop(budget,location,reason,**fact):
    """One memory-only cause per bounded probe call; no per-row log or reads."""
    if budget.get('_probe_stop') is None:
        budget['_probe_stop']=dict(location=location,reason=reason,**fact)


def emit_probe(evidence,budget):
    fact=budget.pop('_probe_stop',None)
    if fact is None:return
    location=fact.pop('location');reason=fact.pop('reason')
    if 'kind' in fact:deferred(evidence,budget,reason,location=location,fact=fact)
    else:evidence.add('selection',reason,at_stage=location)


def probe_time(budget,location):
    probe=budget['tail_probe'];now=time.monotonic()
    if now>=budget['until']:
        probe_stop(budget,location,'time',kind='source_ms',limit=max(0,int((budget['until']-budget.get('started',budget['until']-20))*1000)),used=max(0,int((now-budget.get('started',budget['until']-20))*1000)))
    elif 'started' in probe:
        probe_stop(budget,location,'time',kind='metadata_ms',limit=max(0,int((probe['until']-probe['started'])*1000)),used=max(0,int((now-probe['started'])*1000)))
    else:probe_stop(budget,location,'probe_time_limit_unknown')


def _discovery_anchor(value):
    return (type(value)is dict and len(value)==2 and set(value)=={'source_identity','header'}
            and type(value['source_identity'])is list and len(value['source_identity'])==2
            and all(type(n)is int and 0<=n<2**63 for n in value['source_identity'])
            and type(value['header'])is str and len(value['header'])==64
            and all(c in '0123456789abcdef'for c in value['header']))


def _discovery_origin(value):
    if (type(value)is not dict or len(value)!=3 or set(value)!={'instance','sequence','anchor'}
            or type(value['instance'])is not str or len(value['instance'])!=32
            or any(c not in '0123456789abcdef'for c in value['instance'])
            or type(value['sequence'])is not int or not 0<value['sequence']<2**63
            or not _discovery_anchor(value['anchor'])):
        raise MirrorError('account_discovery_origin_invalid')
    return value


def restore_discovery(registry,paths,budget,previous,instance,*,states=None):
    """Latch a charged prefix atomically; an incomplete latch keeps old epoch.

    Nothing here grants authority or asserts freshness. The caller defers Source
    work after a budget stop, so it cannot replace the old consumed-instance map
    before every still-positive old chain has a durable origin.
    """
    from . import native_scope_contract as sc
    from .native_account_copy_init import charge
    from .native_account_witness import WorkBudgetStop
    previous=previous if type(previous)is dict else {}
    old=previous.get('instance');watermarks=previous.get('shards',{})
    old_valid=(type(old)is str and len(old)==32 and all(c in '0123456789abcdef'for c in old) and 'shards'in previous and type(watermarks)is dict)
    debt=set();updates=[];tokens={};stop=None
    try:
        for path in paths:
            key='tail_probe:'+path.name;state=sc.state(registry,key,None)if states is None else states.get(path.name)
            anchor=None
            if type(state)is not dict:continue
            origin=state.get('discovery_origin');token=state.get('token');consumed=watermarks.get(path.name,0)if old_valid else None
            comparable=type(consumed)is int and 0<=consumed<2**63
            updated=None
            if origin is not None:
                origin=_discovery_origin(origin);charge(budget,len(json.dumps(origin,sort_keys=True).encode())+16)
                if (state.get('complete')is True and not state.get('pending')
                        or old_valid and old==origin['instance']and comparable and consumed>=origin['sequence']):
                    updated=dict(state);updated.pop('discovery_origin');origin=None
            elif (old_valid and old!=instance and state.get('complete')is False
                    and type(token)is list and len(token)in(2,3)and token[0]==old
                    and (len(token)==2 or type(token[2])is int and 0<=token[2]<2**63)
                    and type(token[1])is int and 0<token[1]<2**63 and comparable and token[1]>consumed):
                anchor=sc.state(registry,'shard_anchor:'+path.name,None)
                if not _discovery_anchor(anchor):continue
                origin=dict(instance=old,sequence=token[1],anchor=anchor)
                charge(budget,len(json.dumps(anchor,sort_keys=True).encode())+16)
                updated=dict(state,discovery_origin=origin)
            if updated is not None:
                # All known materialization/publication is paid before any SQL
                # mutation; successful prefix can safely survive a later stop.
                charge(budget,len(json.dumps(updated,sort_keys=True).encode())+len(key.encode()))
                updates.append((key,updated))
            if origin is not None:
                if anchor is None:
                    anchor=sc.state(registry,'shard_anchor:'+path.name,None)
                    charge(budget,len(json.dumps(anchor,sort_keys=True).encode())+16)
                if not _discovery_anchor(anchor):continue
                # Stale provenance remains evidence, never new-Source authority.
                if anchor==origin['anchor']:
                    debt.add(path.name);tokens[path.name]=list(token)if type(token)is list else None
    except WorkBudgetStop as error:stop=error
    registry.execute('SAVEPOINT discovery_origins')
    try:
        for key,value in updates:sc.save(registry,key,value)
    except BaseException:
        registry.execute('ROLLBACK TO discovery_origins');registry.execute('RELEASE discovery_origins');raise
    registry.execute('RELEASE discovery_origins')
    if stop is not None:raise stop
    budget['_discovery_tokens']=tokens
    return debt


def discovery_has_new_hint(name,hints,instance,budget):
    token=budget.get('_discovery_tokens',{}).get(name)
    previous=token[1]if type(token)is list and len(token)in(2,3)and token[0]==instance and type(token[1])is int and token[1]>=0 else 0
    return hints.get(name,0)>previous


def finish_discovery(state,anchor,budget):
    """No lineage deletion until real full discovery and pending service end."""
    origin=state.get('discovery_origin')
    if origin is None:return state
    _discovery_origin(origin)
    if state.get('complete')is True and not state.get('pending')and origin['anchor']==anchor:
        from .native_account_copy_init import charge
        updated=dict(state);updated.pop('discovery_origin')
        charge(budget,len(json.dumps(updated,sort_keys=True).encode())+32)
        return updated
    return state
