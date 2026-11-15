"""Read pinned native copies only, without source opens or event materialization."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import asdict
from pathlib import Path

from .common import quote_identifier as qi
from .message_parser import RawRevisionInput, _decode_raw_content, _structured_content
from .source_records import RawMessage, SourceKey, _content_fingerprint, observed_association_conflict
from .source_catalog import LiveCatalog, LiveShard, SHARD_NAME_PATTERN
from .live_identity import LiveIdentityAdapter
from .source_setup import _confirmed_self_username
from .live_readonly import readonly_database_uri
from .native_mirror_store import MirrorError
from .native_mirror_sync import mirror_root


def _attempt_gaps(root, usernames):
    path = root / '__walden_status.db'
    gaps = []
    if path.is_file():
        with sqlite3.connect(readonly_database_uri(path), uri=True) as status:
            for username in usernames:
                state = status.execute('SELECT gaps FROM attempts WHERE scope=?', (hashlib.sha256(username.encode()).hexdigest(),)).fetchone()
                if state:
                    gaps.extend(json.loads(state[0]))
    return sorted(set(gaps))


def _recent_observation(value):
    """Recognize the bounded v1 producer record; malformed optional facts are absent."""
    import re
    if not isinstance(value, dict) or type(value.get('version')) is not int or value['version'] != 1:
        return None
    token = value.get('observation_id')
    since, through = value.get('since'), value.get('through')
    members = value.get('member_local_ids')
    if (not isinstance(token, str) or re.fullmatch(r'[0-9a-f]{32}', token) is None
            or type(since) is not int or type(through) is not int
            or not 0 <= through <= 9223372036854775807 or since != through - 86400
            or type(value.get('timestamp_integrity')) is not bool
            or not isinstance(members, list) or len(members) > 20000
            or any(type(i) is not int or not 1 <= i <= 9223372036854775807 for i in members)
            or len(set(members)) != len(members)):
        return None
    return value


def _request_range(config, root, username, request, states, ordered):
    """Prove only a bounded source-observation vector, never source-now freshness."""
    unknown = dict(status='unknown', reason='observation_evidence_missing', as_of=None)
    path = root / '__walden_status.db'
    if not path.is_file():
        return unknown
    with sqlite3.connect(readonly_database_uri(path), uri=True) as status:
        if not status.execute("SELECT 1 FROM sqlite_master WHERE name='successful_observations'").fetchone():
            return unknown
        row = status.execute('SELECT value FROM successful_observations WHERE scope=?', (hashlib.sha256(username.encode()).hexdigest(),)).fetchone()
    if row is None:
        return unknown
    try:
        proof = json.loads(row[0])
    except (ValueError, TypeError):
        return unknown
    if not isinstance(proof, dict):
        return unknown
    import os
    expected_binding = dict(account_id=config['account_id'], source_generation=config['source_generation'], message_root=os.path.abspath(Path(config['message_root']).expanduser()))
    # A genuine typed binding conflict is never hidden by optional-format failure.
    for field, expected_value in expected_binding.items():
        if isinstance(proof.get(field), str) and proof[field] != expected_value:
            raise MirrorError('source_identity_mismatch')
    if any(not isinstance(proof.get(field), str) for field in expected_binding):
        return unknown
    import re
    roster = proof.get('source_roster')
    if (type(proof.get('version')) is not int or proof['version'] != 1
            or not isinstance(proof.get('observation_id'), str)
            or re.fullmatch(r'[0-9a-f]{32}', proof['observation_id']) is None
            or proof.get('atomic_global_snapshot') is not False
            or not isinstance(roster, dict) or not roster
            or any(not isinstance(name, str) or SHARD_NAME_PATTERN.fullmatch(name) is None or type(present) is not bool for name, present in roster.items())):
        return unknown
    expected = {name for name, present in roster.items() if present}
    if not roster or set(states) != expected:
        return dict(unknown, reason='source_observation_vector_mismatch')
    observations = {}
    for shard, (state, present) in states.items():
        observed = _recent_observation(state.get('recent_observation'))
        if (observed is None or observed.get('observation_id') != proof.get('observation_id')
                or observed.get('timestamp_integrity') is not True or not present):
            return dict(unknown, reason='source_observation_vector_mismatch')
        members = observed.get('member_local_ids')
        if not isinstance(members, list):
            return dict(unknown, reason='observation_member_limit')
        observations[shard] = (observed, set(members))
    if not observations:
        return unknown
    since = max(observed['since'] for observed, _ in observations.values())
    through = min(observed['through'] for observed, _ in observations.values())
    prefix = ordered[:int(request.get('offset', 0)) + int(request.get('limit', 100))]
    for item in prefix:
        observed, members = observations[item['source']['shard']]
        stamp = item['create_time']
        if type(stamp) is not int or not since <= stamp <= through or item['local_id'] not in members:
            return dict(unknown, reason='requested_order_not_observed')
    if 'start' in request or 'end' in request:
        if not since <= request.get('start', -9223372036854775808) <= request.get('end', 9223372036854775807) <= through:
            return dict(unknown, reason='requested_time_outside_observation')
    elif len(prefix) < int(request.get('offset', 0)) + int(request.get('limit', 100)):
        return dict(unknown, reason='requested_page_exceeds_recent_observation')
    return dict(status='observed_vector_covered', reason='complete_recent_predicate',
                as_of={shard: observed['through'] for shard, (observed, _) in observations.items()}, ordering='create_time,local_id,shard; stable seconds, not real-time arrival order',
                since=since, through=through, observation_id=proof['observation_id'])


def query_local(config, request, *, alias_context=None, transcriber=None, membership=None):
    from .native_scope_contract import query_scope_guard
    scope_token=query_scope_guard(config)
    from .native_scope_contract import mode,authorized,selection
    account=mode(config)=='account'
    if account and request.get('target_ref') is not None:return _query_table_ref(config,request)
    started = time.monotonic()
    root = mirror_root(config, create=False)
    for candidate in root.glob('*.db'):
        if candidate.is_symlink():
            raise MirrorError('mirror_symlink')
    username = request.get('username')
    resolution = None
    if username is None and request.get('query'):
        from .confirmed_aliases import AliasError, load_alias_context, local_contact_snapshot
        contact_checked_at = None
        try:
            if alias_context is None:
                alias_context = load_alias_context(config)
            with local_contact_snapshot(config) as (contact, snapshot):
                contact_checked_at = snapshot['checked_at']
                class LocalCatalog:
                    shards = ()
                proof = snapshot.get('source_identity')
                valid_proof = isinstance(proof, list) and len(proof) == 2 and all(type(v) is int and v >= 0 for v in proof)
                adapter = LiveIdentityAdapter(LocalCatalog(), contact_connection=contact, alias_context=alias_context,
                                              contact_source_identity=tuple(proof) if valid_proof else None)
                adapter.begin_scan()
                resolution, _ = adapter.resolve_contact(request['query'], _kind=request.get('target_kind'))
        except AliasError as error:
            if error.reason == 'contact_source_identity_mismatch':
                raise MirrorError('contact_source_identity_mismatch') from None
            resolution = dict(status='unavailable', reason=error.reason, candidates=[], total_candidates=0)
        if resolution.get('status') != 'resolved':
            # The name is unresolved, so no target scope can be selected yet.
            # Auxiliary failures affect the shared contact snapshot; do not
            # attach unrelated message failures from another authorized scope.
            auxiliary_gaps = [gap for gap in _attempt_gaps(root, config.get('mirror_scope', [])) if gap == 'auxiliary_source_unavailable_or_unsupported']
            unavailable = resolution.get('status') == 'unavailable'
            gaps = auxiliary_gaps + [resolution.get('reason', 'local_contacts_unavailable') if unavailable else 'target_unresolved']
            query_scope_guard(config)
            return dict(messages=[], resolution=resolution, coverage={'history_complete':False}, synced_at=contact_checked_at, freshness='stale' if auxiliary_gaps or unavailable else 'local_snapshot', gaps=sorted(set(gaps)), source_opens=0, elapsed_seconds=time.monotonic() - started)
        username = resolution['selected_username']
    authorized(config,username)
    account_selection=selection(config,username=username) if account else None
    table = 'Msg_' + hashlib.md5(username.encode()).hexdigest()
    limit = int(request.get('limit', 100))
    offset = int(request.get('offset', 0))
    if not 1 <= limit <= 1000 or offset < 0:
        raise MirrorError('invalid_pagination')
    # Media query consumes only persistent worker results, never keys/codecs/ASR.
    messages, gaps, states = [], [], []
    observation_states = {}
    gaps.extend(_attempt_gaps(root, [username]))
    parse_seconds = 0
    # No access to message_root, credentials, EventStore or AgentStore here.
    paths = sorted(root.glob('message_*.db')) + sorted(root.glob('biz_message_*.db'))
    if account:paths=[root/s for s,t,_ in account_selection]

    for path in paths:
        conn = sqlite3.connect(readonly_database_uri(path), uri=True)
        contact_connection = None
        try:
            conn.execute('PRAGMA query_only=ON')
            conn.execute('BEGIN')
            binding = conn.execute('SELECT * FROM __walden_binding').fetchall()
            if binding != [(config['account_id'], config['source_generation'], path.name)]:
                raise MirrorError('source_identity_mismatch')
            row = conn.execute('SELECT value FROM __walden_progress WHERE table_name=?', (table,)).fetchone()
            if row is None:
                continue
            state = json.loads(row[0])
            if account:
                proof=authorized(config,username,shard=path.name,table=table)
                if state.get('source_identity')!=proof['source_identity'] or state.get('source_header_sha256')!=proof['header']:raise MirrorError('scope_copy_proof')
            states.append(state)
            observed = _recent_observation(state.get('recent_observation'))
            members = observed['member_local_ids'] if observed is not None else None
            present = isinstance(members, list) and len(members) <= 20000 and all(type(i) is int for i in members) and len(set(members)) == len(members)
            if present:
                for at in range(0, len(members), 500):
                    chunk = members[at:at+500]
                    count = conn.execute('SELECT count(*) FROM ' + qi(table) + ' WHERE local_id IN (' + ','.join('?' for _ in chunk) + ')', chunk).fetchone()[0]
                    if count != len(chunk):
                        present = False
                        break
            observation_states[path.name] = (state, present)
            catalog = LiveCatalog([LiveShard(path, conn)])
            if (root / 'contact.db').is_file():
                contact_connection = sqlite3.connect(readonly_database_uri(root / 'contact.db'), uri=True)
                contact_connection.execute('PRAGMA query_only=ON')
                contact_connection.execute('BEGIN')
                if contact_connection.execute('SELECT * FROM __walden_binding').fetchall() != [(config['account_id'], config['source_generation'], 'contact.db')]:
                    raise MirrorError('contact_source_identity_mismatch')
            adapter = LiveIdentityAdapter(catalog, self_username=_confirmed_self_username(config, physical=False), conversation_username=username, contact_connection=contact_connection)
            adapter.begin_scan()
            source_key = SourceKey(config['account_id'], config['source_generation'], path.name, table)
            columns = [item[1] for item in conn.execute('PRAGMA table_info(' + qi(table) + ')')]
            predicate='';parameters=[request.get('start',-9223372036854775808),request.get('end',9223372036854775807)]
            if membership is not None:
                ids=membership.get(path.name,[])
                if type(ids) is not list or len(ids)>501 or any(type(i) is not int or i<=0 for i in ids):raise MirrorError('request_membership_invalid')
                predicate=' AND local_id IN ('+','.join('?' for _ in ids)+')' if ids else ' AND 0'
                if ids and conn.execute('SELECT count(*) FROM '+qi(table)+predicate.replace(' AND ',' WHERE ',1),tuple(ids)).fetchone()[0]!=len(ids):raise MirrorError('request_cache_incomplete')
                parameters+=ids
            rows=conn.execute('SELECT * FROM '+qi(table)+' WHERE create_time>=? AND create_time<=?'+predicate+' ORDER BY create_time DESC,local_id DESC LIMIT ?',tuple(parameters+[limit+offset])).fetchall()
            for row in rows:
                item = dict(zip(columns, row))
                raw = item['message_content']
                message = RawMessage(item['local_id'], item.get('server_id'), item['local_type'], item['create_time'], item['real_sender_id'], raw, item['WCDB_CT_message_content'], raw_source=item.get('source'), source_compression_type=item.get('WCDB_CT_source'))
                fingerprint = _content_fingerprint(message)
                expected = (str(message.server_id) if message.server_id is not None else None, message.local_type, message.create_time, message.real_sender_id, fingerprint)
                observed = conn.execute('SELECT * FROM __walden_observed WHERE local_id=?', (message.local_id,)).fetchall()
                if observed_association_conflict([(table, message.local_id, expected)], observed):
                    gaps.append('conversation_attribution_conflict')
                revision = RawRevisionInput(fingerprint, 1, str(item['server_id']) if item.get('server_id') is not None else None, item['local_type'], item['create_time'], item['real_sender_id'], raw, 'text' if isinstance(raw, str) else 'blob' if raw is not None else 'null', item['WCDB_CT_message_content'], '2000-01-01T00:00:00.000000+00:00')
                parse_start = time.monotonic()
                decoded = _decode_raw_content(revision)
                quality = set(decoded.quality_codes)
                sender = adapter.sender_identity(source_key, message)
                direction = adapter.direction(source_key, message)
                readable = decoded.text
                if (username.endswith('@chatroom') and direction == 'inbound'
                        and isinstance(sender, str) and isinstance(readable, str)
                        and readable.startswith(sender + ':\n')):
                    readable = readable[len(sender) + 2:]
                kind, text, attrs = _structured_content(item['local_type'] & 65535, readable, quality)
                parse_seconds += time.monotonic() - parse_start
                messages.append(dict(local_id=item['local_id'], create_time=item['create_time'], sender_username=sender, text=text, content=dict(kind=kind, text=text, attributes=attrs, raw_text=decoded.text), quality_codes=sorted(quality), source=dict(account_id=config['account_id'], source_generation=config['source_generation'], shard=path.name, table=table, local_id=item['local_id'], content_sha256=fingerprint)))
                current = messages[-1]
                current['direction'] = direction
                sender_name = adapter.sender_display_name(source_key, message)
                current['sender_display_name'] = sender_name if sender_name and sender_name != sender else 'unknown'
                current['source_facts'] = adapter.source_facts(source_key, message)
                current['_media_identity'] = item

        finally:
            if contact_connection is not None:
                contact_connection.close()
            conn.close()
    if not states:
        gaps.append('scope_not_copied')
    messages.sort(key=lambda row: (type(row['create_time']) is int, row['create_time'] if type(row['create_time']) is int else 0, row['local_id'], row['source']['shard']), reverse=True)
    request_range = dict(status='unknown',reason='account_recent_vector_not_proven',as_of=None) if account else _request_range(config, root, username, request, observation_states, messages)
    if request_range['status'] != 'observed_vector_covered':
        if not all(state['history_complete'] for state in states):
            gaps.append('history_incomplete')
        if any(state['tail'] < state['target'] for state in states):
            gaps.append('tail_incomplete')
    if 'conversation_attribution_conflict' in gaps:
        request_range = dict(status='unknown', reason='conversation_attribution_conflict', as_of=None)
    selected = [] if 'conversation_attribution_conflict' in gaps else list(reversed(messages[offset:offset + limit]))
    for current in messages:
        if current not in selected:
            current.pop('_media_identity', None)
    image_ocr_engine = None
    for current in selected:
        item = current.pop('_media_identity')
        if current['content']['kind'] == 'audio' and request.get('voice_transcripts'):
            from .native_mirror_media import local_voice
            current['voice'] = local_voice(config, root, current['source']['shard'], username, item, transcriber)
        if current['content']['kind'] == 'image' and request.get('images'):
            from .native_media_work import local_result
            cached=local_result(config,current['source']) or {'status':'pending'}
            current['image']=dict(cached.get('image',{}),media_status=cached['status'])
            if not cached.get('image'):current['image'].update(status=cached['status'],reason=cached.get('reason','local_image_pending'))
            from .native_image_query import engine_identity, local_ocr
            if image_ocr_engine is None:image_ocr_engine=engine_identity(root)
            current['image'].update(local_ocr(config,current['source'],username,current['image'],engine=image_ocr_engine))
    result = dict(selected_username=username, messages=selected, coverage=dict(history_complete=bool(states) and all(s['history_complete'] for s in states), rechecked_since=max((s['rechecked_since'] for s in states if type(s.get('rechecked_since')) is int), default=None), arbitrary_old_changes_verified=False, request_range=request_range, atomic_global_snapshot=False, history_progress=[dict(shard=shard, H=state['H'], history=state['history'], tail=state['tail'], target=state['target'], per_batch_checked_at=state['checked_at']) for shard, (state, _) in observation_states.items()]), synced_at_semantics='minimum_per_batch_checked_at_not_scope_completion', last_attempt_at=None, last_complete_observation_at=None, synced_at=min((s['checked_at'] for s in states), default=None), freshness='stale' if gaps else 'local_snapshot', gaps=sorted(set(gaps)), source_opens=0, parse_seconds=parse_seconds, elapsed_seconds=time.monotonic() - started)
    if resolution is not None:
        result['resolution'] = resolution
    query_scope_guard(config)
    query_scope_guard(config,scope_token)
    return result


def _query_table_ref(config,request):
    """A registered table ref is not a guessed person or a Source fallback."""
    from .native_scope_contract import query_scope_guard,selection,authorized
    if request.get('username') is not None or request.get('query') is not None:raise MirrorError('scope_target_ambiguous')
    token=query_scope_guard(config);selected=selection(config,ref=request['target_ref']);root=mirror_root(config,create=False)
    limit=request.get('limit',100);offset=request.get('offset',0)
    if type(limit) is not int or not 1<=limit<=1000 or type(offset) is not int or offset<0:raise MirrorError('invalid_pagination')
    messages=[];states=[];gaps=[]
    for shard,table,proof in selected:
        path=root/shard
        if not path.is_file():gaps.append('scope_not_copied');continue
        from .native_scope_contract import _safe
        _safe(path)
        conn=sqlite3.connect(readonly_database_uri(path),uri=True)
        try:
            conn.execute('PRAGMA query_only=ON');conn.execute('BEGIN')
            if conn.execute('SELECT * FROM __walden_binding').fetchall()!=[(config['account_id'],config['source_generation'],shard)]:raise MirrorError('source_identity_mismatch')
            progress=conn.execute('SELECT value FROM __walden_progress WHERE table_name=?',(table,)).fetchone()
            if progress is None:gaps.append('scope_not_copied');continue
            state=json.loads(progress[0]);states.append(state)
            if state.get('source_identity')!=proof['source_identity'] or state.get('source_header_sha256')!=proof['header']:raise MirrorError('scope_copy_proof')
            columns=[r[1] for r in conn.execute('PRAGMA table_info('+qi(table)+')')]
            rows=conn.execute('SELECT * FROM '+qi(table)+' WHERE create_time>=? AND create_time<=? ORDER BY create_time DESC,local_id DESC LIMIT ?',(request.get('start',-9223372036854775808),request.get('end',9223372036854775807),limit+offset)).fetchall()
            for row in rows:
                item=dict(zip(columns,row));raw=item['message_content'];message=RawMessage(item['local_id'],item.get('server_id'),item['local_type'],item['create_time'],item['real_sender_id'],raw,item['WCDB_CT_message_content'])
                fingerprint=_content_fingerprint(message);expected=(str(message.server_id) if message.server_id is not None else None,message.local_type,message.create_time,message.real_sender_id,fingerprint)
                observed=conn.execute('SELECT * FROM __walden_observed WHERE local_id=?',(message.local_id,)).fetchall()
                if observed_association_conflict([(table,message.local_id,expected)],observed):raise MirrorError('conversation_attribution_conflict')
                revision=RawRevisionInput(fingerprint,1,str(message.server_id) if message.server_id is not None else None,message.local_type,message.create_time,message.real_sender_id,raw,'text' if isinstance(raw,str) else 'blob' if raw is not None else 'null',item['WCDB_CT_message_content'],'2000-01-01T00:00:00.000000+00:00')
                decoded=_decode_raw_content(revision);quality=set(decoded.quality_codes);quality.add('conversation_identity_unresolved')
                kind,text,attrs=_structured_content(item['local_type']&65535,decoded.text,quality)
                source=dict(account_id=config['account_id'],source_generation=config['source_generation'],shard=shard,table=table,local_id=item['local_id'],content_sha256=fingerprint)
                value=dict(local_id=item['local_id'],create_time=item['create_time'],sender_username=None,sender_display_name='unknown',direction='unknown',text=text,content=dict(kind=kind,text=text,attributes=attrs,raw_text=decoded.text),quality_codes=sorted(quality),source=source,target_ref=proof['ref'])
                if kind in ('image','audio') and (request.get('images') or request.get('voice_transcripts')):
                    from .native_media_work import local_result
                    value['media']=local_result(config,source) or dict(status='pending',reason='identity_or_attachment_unavailable')
                messages.append(value)
        finally:conn.close()
    messages.sort(key=lambda v:(v['create_time'],v['local_id'],v['source']['shard']),reverse=True)
    complete=bool(states) and all(type(s.get('target')) is int and s.get('history_complete') and s['history']>=s['H'] and s['tail']>=s['target'] for s in states)
    if not complete:gaps.append('history_incomplete')
    query_scope_guard(config,token)
    return dict(target_ref=request['target_ref'],selected_username=None,identity_status='unknown',messages=list(reversed(messages[offset:offset+limit])),coverage=dict(history_complete=complete,raw_table_complete=complete,identity_complete=False,atomic_global_snapshot=False,request_range=dict(status='unknown',reason='no_recent_range_observation')),gaps=sorted(set(gaps)),source_opens=0,freshness='local_snapshot',synced_at=min((s.get('checked_at',0) for s in states),default=None))

from .failure_evidence import _register
_register(query_local,_query_table_ref)
