"""Synthetic AUTO reanchor checks against the installed package."""
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

from wechat_local import native_scope_contract as sc
from wechat_local import native_mirror_sync as sync
from wechat_local import native_deadline as nd
from wechat_local import native_follow_grant as nfg
from wechat_local.native_follow_policy import digest as source_digest
from wechat_local.native_mirror_store import MirrorError

SCHEMA = '0' * 64
TABLE = 'Msg_' + 'a' * 32
SHARD = 'message_0.db'


# ---------------------------------------------------------------------------
# Config / fixture
# ---------------------------------------------------------------------------
def make_config(message_root, mirror_root):
    return dict(
        mirror_scope_mode='account',
        scope_contract_id='11111111111111111111111111111111',
        account_id='local-11111111-1111-4111-8111-111111111111',
        source_generation='generation-22222222-2222-4222-8222-222222222222',
        live_db_root=str(message_root),
        message_root=str(message_root),
        mirror_root=str(mirror_root),
    )


def setup(dirpath, *, dev_delta=1000, inode_delta=0, header=None,
          anchor_extra=None, no_anchor=False, no_members=False,
          member_supported=False, make_source_db=False):
    """Build a fake live shard + registry anchor + member proof + local progress,
    all pinned to a STALE st_dev (real st_dev + dev_delta) while inode+header match
    the live file. Returns a dict of paths / identities. No real data involved.
    """
    message_root = os.path.join(dirpath, 'message')
    mirror_root = os.path.join(dirpath, 'mirror')
    os.makedirs(message_root)
    os.makedirs(mirror_root)
    live_path = os.path.join(message_root, SHARD)
    with open(live_path, 'wb') as fh:
        fh.write(b'\x12\x34\x56\x78' * 4 + b'\x00' * 48)  # 64 bytes; stable header
    st = os.stat(live_path)
    live_identity = [st.st_dev, st.st_ino]
    with open(live_path, 'rb') as fh:
        live_header = hashlib.sha256(fh.read(16)).hexdigest()

    # Layers are pinned to the OLD identity; header may be overridden to simulate
    # a real header change (a different source).
    prior_identity = [st.st_dev + dev_delta, st.st_ino + inode_delta]
    prior_header = header if header is not None else live_header
    config = make_config(message_root, mirror_root)

    with sc.registry(config, write=True, initialize=True) as conn:
        if not no_anchor:
            anchor = dict(source_identity=prior_identity, header=prior_header)
            if anchor_extra:
                anchor.update(anchor_extra)
            conn.execute('INSERT INTO state VALUES(?,?)',
                         ('shard_anchor:' + SHARD,
                          json.dumps(anchor, sort_keys=True)))
        old_obs = dict(contract=sc.fixed(config), shard=SHARD,
                       source_identity=prior_identity, header=prior_header,
                       query_only=True, schema_cookie=None, at_ns=0,
                       tables=[[TABLE, SCHEMA]])
        old_obs_id = sc.digest(old_obs)
        conn.execute('INSERT OR IGNORE INTO observations VALUES(?,?)',
                     (old_obs_id, json.dumps(old_obs, sort_keys=True)))
        if not no_members:
            proof = dict(source_identity=prior_identity, header=prior_header,
                         schema_sha256=SCHEMA, table=TABLE, username=None,
                         supported=member_supported, available=True,
                         observation=old_obs_id,
                         ref=sc.target_ref(config, SHARD, TABLE))
            conn.execute('INSERT INTO members VALUES(?,?,?)',
                         (SHARD, TABLE, json.dumps(proof, sort_keys=True)))
        conn.execute('INSERT OR REPLACE INTO state VALUES(?,?)',
                     ('roster', json.dumps([SHARD], sort_keys=True)))
        conn.commit()

    # Local mirror db: __walden_binding + __walden_progress pinned to prior_identity.
    local_path = os.path.join(mirror_root, SHARD)
    lconn = sqlite3.connect(local_path)
    try:
        lconn.execute('CREATE TABLE __walden_binding(account TEXT, generation TEXT, shard TEXT)')
        lconn.execute('INSERT INTO __walden_binding VALUES(?,?,?)',
                      (config['account_id'], config['source_generation'], SHARD))
        lconn.execute('CREATE TABLE __walden_progress(table_name TEXT PRIMARY KEY, value TEXT NOT NULL)')
        lconn.execute('INSERT INTO __walden_progress VALUES(?,?)',
                      (TABLE, json.dumps(dict(source_identity=prior_identity,
                                              source_header_sha256=prior_header), sort_keys=True)))
        lconn.commit()
    finally:
        lconn.close()
    os.chmod(local_path, 0o600)  # account_status()/_safe() requirement

    source_db = None
    if make_source_db:
        # Separate plain SQLite (not discovered as a numeric shard) used only as
        # the custom connection_factory source in the end-to-end round.
        source_db = os.path.join(dirpath, 'source.sqlite')
        sconn = sqlite3.connect(source_db)
        try:
            sconn.execute('CREATE TABLE Name2Id(user_name TEXT)')
            sconn.commit()
        finally:
            sconn.close()

    return dict(config=config, live_path=live_path, message_root=message_root,
                mirror_root=mirror_root, local_path=local_path,
                live_identity=live_identity, live_header=live_header,
                prior_identity=prior_identity, prior_header=prior_header,
                source_db=source_db)


# ---------------------------------------------------------------------------
# Raw state readers (independent sqlite connections; test-only)
# ---------------------------------------------------------------------------
def reg_state(config, key, default=None):
    p = os.path.join(config['mirror_root'], sc.REGISTRY)
    c = sqlite3.connect(p)
    try:
        row = c.execute('SELECT value FROM state WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else default
    finally:
        c.close()


def reg_members(config, shard):
    p = os.path.join(config['mirror_root'], sc.REGISTRY)
    c = sqlite3.connect(p)
    try:
        return {t: json.loads(v) for t, v in c.execute(
            'SELECT table_name,proof FROM members WHERE shard=?', (shard,)).fetchall()}
    finally:
        c.close()


def reg_observation(config, obs_id):
    p = os.path.join(config['mirror_root'], sc.REGISTRY)
    c = sqlite3.connect(p)
    try:
        row = c.execute('SELECT proof FROM observations WHERE id=?', (obs_id,)).fetchone()
        return json.loads(row[0]) if row else None
    finally:
        c.close()


def read_progress(config, fx):
    c = sqlite3.connect(fx['local_path'])
    try:
        row = c.execute('SELECT value FROM __walden_progress WHERE table_name=?', (TABLE,)).fetchone()
        return json.loads(row[0]) if row else None
    finally:
        c.close()


def snapshot(config, fx):
    return dict(anchor=reg_state(config, 'shard_anchor:' + SHARD),
                members=reg_members(config, SHARD),
                progress=read_progress(config, fx),
                receipt=reg_state(config, 'source_st_dev_renumber_receipt:' + SHARD))


# ---------------------------------------------------------------------------
# Authorization stubs: only the OUTER, process/service-scope machinery.
# All identity-critical functions (guard, register, member, account_status) stay
# REAL. These stubs are unrelated to the st_dev-renumber comparison under test.
# ---------------------------------------------------------------------------
def install_stubs(config):
    grant = dict(kind='active', source_sha256=source_digest(config))
    facts = dict(wall_until=1e9, continuous_start=0, continuous_until=3600000000000)
    dl = nfg.FollowDeadline(facts, grant, wall=lambda: 0.0, continuous=lambda: 1)
    token = nd._current.set(dl)
    originals = dict(validate=nfg.validate,
                     query_scope_guard=sc.query_scope_guard,
                     token_fn=sc.token)
    nfg.validate = lambda g, **kw: None
    sc.query_scope_guard = lambda cfg, before=None: ('account', 'stub-token')
    sc.token = lambda cfg: ('account', 'stub-token')
    return token, originals


def restore_stubs(token, originals):
    nd._current.reset(token)
    nfg.validate = originals['validate']
    sc.query_scope_guard = originals['query_scope_guard']
    sc.token = originals['token_fn']


# ---------------------------------------------------------------------------
# Faithful "round replay": runs the EXACT identity-critical sequence of
# _account_sync's per-shard loop (:522-525, :529, :566-568, :591, :637/:660) and
# account_status (:291) with REAL production functions. A clean return means a
# full round can complete with no scope_source_conflict / source_replaced.
# ---------------------------------------------------------------------------
def replay_round(config, fx):
    stamp = os.stat(fx['live_path'])
    identity = [stamp.st_dev, stamp.st_ino]
    with open(fx['live_path'], 'rb') as fh:
        header_hash = hashlib.sha256(fh.read(16)).hexdigest()
    result = {}
    with sc.registry(config, write=True) as registry:
        # :524-525 exact per-shard comparison (+ narrow AUTO tolerance)
        sync._account_shard_anchor_check(config, registry, Path(fx['live_path']),
                                         identity, header_hash, result=result)
        # :529 first register (empty members)
        sc.register(config, registry,
                    dict(contract=sc.fixed(config), shard=SHARD,
                         source_identity=identity, header=header_hash,
                         query_only=True, tables=[]), [])
        # :566-568 second register with a fresh observation + members
        observation = dict(contract=sc.fixed(config), shard=SHARD,
                           source_identity=identity, header=header_hash,
                           query_only=True, schema_cookie=0,
                           tables=[[TABLE, SCHEMA]], at_ns=time.time_ns())
        members = [dict(table=TABLE, schema_sha256=SCHEMA, username=None,
                        supported=True, available=True, inventory_pass='pass')]
        sc.register(config, registry, observation, members)
        # :591 copy-loop member() proof check
        sc.member(config, registry, SHARD, TABLE)
        # :637 -> :660 copy-loop source_replaced guard (progress identity)
        prog = read_progress(config, fx)
        if (prog.get('source_identity') != identity
                or prog.get('source_header_sha256') != header_hash):
            raise MirrorError('source_replaced')
        # :581 registry commit
        registry.commit()
    # account_status():291 scope_copy_proof (local progress vs member proof)
    status = sc.account_status(config)
    return result, status, identity, header_hash


# ---------------------------------------------------------------------------
# Repin the 3 mutable identity layers to another stale st_dev (inode+header
# unchanged) to simulate a LATER reboot renumber.
# ---------------------------------------------------------------------------
def repin(config, fx, stale2_dev):
    p = os.path.join(config['mirror_root'], sc.REGISTRY)
    c = sqlite3.connect(p)
    try:
        anchor = json.loads(c.execute(
            'SELECT value FROM state WHERE key=?', ('shard_anchor:' + SHARD,)).fetchone()[0])
        newprior = [stale2_dev, anchor['source_identity'][1]]
        c.execute('UPDATE state SET value=? WHERE key=?',
                  (json.dumps(dict(source_identity=newprior, header=anchor['header']), sort_keys=True),
                   'shard_anchor:' + SHARD))
        (raw,) = c.execute('SELECT proof FROM members WHERE shard=? AND table_name=?',
                           (SHARD, TABLE)).fetchone()
        proof = json.loads(raw)
        proof['source_identity'] = newprior
        (observation_raw,) = c.execute('SELECT proof FROM observations WHERE id=?',
                                       (proof['observation'],)).fetchone()
        observation = json.loads(observation_raw)
        observation['source_identity'] = newprior
        proof['observation'] = sc.digest(observation)
        c.execute('INSERT OR IGNORE INTO observations VALUES(?,?)',
                  (proof['observation'], json.dumps(observation, sort_keys=True)))
        c.execute('UPDATE members SET proof=? WHERE shard=? AND table_name=?',
                  (json.dumps(proof, sort_keys=True), SHARD, TABLE))
        c.commit()
    finally:
        c.close()
    lc = sqlite3.connect(fx['local_path'])
    try:
        (raw,) = lc.execute('SELECT value FROM __walden_progress WHERE table_name=?',
                            (TABLE,)).fetchone()
        progress = json.loads(raw)
        progress['source_identity'] = newprior
        lc.execute('UPDATE __walden_progress SET value=? WHERE table_name=?',
                   (json.dumps(progress, sort_keys=True), TABLE))
        lc.commit()
    finally:
        lc.close()
    return newprior


def check(cond, msg):
    if not cond:
        raise AssertionError('FAIL: ' + msg)
    print('  PASS: ' + msg)


# ---------------------------------------------------------------------------
# End-to-end: invoke the REAL _account_sync once with a synthetic environment.
# ---------------------------------------------------------------------------
def run_full_account_sync(fx):
    config = fx['config']
    source_db = fx['source_db']

    def factory(path):
        c = sqlite3.connect(source_db)
        c.execute('PRAGMA query_only=ON')
        return c

    return sync._account_sync(config, connection_factory=factory)


def main():
    tmp = tempfile.mkdtemp(prefix='reboot-test-', dir=ROOT)
    installed = []  # (token, originals) per case, restored in reverse
    failures = 0
    try:
        def fresh(name, **kw):
            d = os.path.join(tmp, name)
            os.makedirs(d)
            return setup(d, **kw)

        # ---- [1] (a) renumber -> tolerated, all 4 layers advanced, round completes ----
        try:
            fx = fresh('a')
            cfg = fx['config']
            installed.append(install_stubs(cfg))
            before = snapshot(cfg, fx)
            check(before['receipt'] is None, '[a] no AUTO receipt before the round')
            # RED control: prove this fixture genuinely trips the ORIGINAL
            # exact-equality guard (anchor != live observation), i.e. without the
            # change the round WOULD be blocked by scope_source_conflict.
            live_obs = dict(source_identity=fx['live_identity'], header=fx['live_header'])
            check(before['anchor'] != live_obs,
                  '[a] RED control: baseline exact-equality guard WOULD raise scope_source_conflict')
            check(before['anchor']['source_identity'][1] == fx['live_identity'][1]
                  and before['anchor']['header'] == fx['live_header']
                  and before['anchor']['source_identity'][0] != fx['live_identity'][0],
                  '[a] RED control: difference is st_dev ONLY (same inode+header)')
            result, status, identity, h = replay_round(cfg, fx)
            after = snapshot(cfg, fx)
            # layer 1: anchor
            check(after['anchor']['source_identity'] == identity, '[a] layer1 shard_anchor advanced to live identity')
            check(after['anchor']['header'] == h, '[a] layer1 header preserved')
            # layer 2: member proof + referenced observation + member() holds
            proof = after['members'][TABLE]
            check(proof['source_identity'] == identity, '[a] layer2 member proof identity advanced')
            check(proof['header'] == h, '[a] layer2 member proof header preserved')
            check(proof['schema_sha256'] == SCHEMA, '[a] layer2 schema_sha256 preserved')
            check(proof['ref'] == sc.target_ref(cfg, SHARD, TABLE), '[a] layer2 ref preserved')
            obs = reg_observation(cfg, proof['observation'])
            check(obs is not None and obs['source_identity'] == identity,
                  '[a] layer2 fresh observation for live identity exists and is referenced')
            with sc.registry(cfg, write=True) as conn:
                sc.member(cfg, conn, SHARD, TABLE)  # must NOT raise
            check(True, '[a] layer2 sc.member() proof check passes (no scope_source_conflict)')
            # layer 3: local __walden_progress
            check(after['progress']['source_identity'] == identity, '[a] layer3 local progress identity advanced')
            check(after['progress']['source_header_sha256'] == h, '[a] layer3 local progress header preserved')
            # round-level: result field + account_status scope_copy_proof
            check(bool(result.get('auto_st_dev_renumber')), '[a] result carries an AUTO tolerance signal')
            check(result['auto_st_dev_renumber'][0]['auto'] is True, '[a] result signal marked AUTO')
            check(status['counts']['copied'] >= 1, '[a] account_status scope_copy_proof passed (copied>=1, no raise)')
            check('scope_source_conflict' not in status['gaps'], '[a] no scope_source_conflict gap')
            print('[1] (a) renumber tolerated, 4 layers advanced, round completes: OK')
        except Exception as e:
            failures += 1
            print('[1] (a) EXCEPTION ' + repr(e))

        # ---- [2] (e) audit signal present, DISTINCT, marked AUTO ----
        try:
            fx = fresh('e')
            cfg = fx['config']
            installed.append(install_stubs(cfg))
            replay_round(cfg, fx)
            rec = reg_state(cfg, 'source_st_dev_renumber_receipt:' + SHARD)
            check(rec is not None, '[e] AUTO receipt key source_st_dev_renumber_receipt:<shard> present')
            check(rec.get('kind') == 'auto_st_dev_renumber', '[e] receipt kind is the AUTO kind')
            check(rec.get('auto') is True, '[e] receipt explicitly marked AUTO')
            check(rec.get('shard') == SHARD, '[e] receipt bound to the shard')
            check('old_st_dev' in rec and 'new_st_dev' in rec and rec['old_st_dev'] != rec['new_st_dev'],
                  '[e] receipt records old/new st_dev')
            check(rec.get('st_ino') == fx['live_identity'][1], '[e] receipt records inode')
            check(rec.get('header') == fx['live_header'], '[e] receipt records header hash')
            check(type(rec.get('at_wall_ns')) is int, '[e] receipt records timestamp')
            check(rec['old_source_identity'][0] != rec['new_source_identity'][0]
                  and rec['old_source_identity'][1] == rec['new_source_identity'][1],
                  '[e] receipt records old/new identities (only st_dev differs)')
            # distinct from P1's manual receipt namespace
            check(reg_state(cfg, 'source_reanchor_receipt:test-nonce') is None,
                  '[e] P1 manual source_reanchor_receipt:<nonce> NOT written by AUTO path')
            print('[2] (e) distinct AUTO audit signal: OK')
        except Exception as e:
            failures += 1
            print('[2] (e) EXCEPTION ' + repr(e))

        # ---- [3] (b) real source change: inode differs -> STILL conflict, NO writes ----
        try:
            fx = fresh('b_inode', inode_delta=7)
            cfg = fx['config']
            installed.append(install_stubs(cfg))
            before = snapshot(cfg, fx)
            raised = None
            try:
                replay_round(cfg, fx)
            except MirrorError as e:
                raised = e.args[0]
            check(raised == 'scope_source_conflict', '[b-inode] differing inode STILL raises scope_source_conflict')
            after = snapshot(cfg, fx)
            check(after == before, '[b-inode] NO writes (anchor/member/progress/receipt unchanged)')
            print('[3] (b) inode change rejected, no writes: OK')
        except Exception as e:
            failures += 1
            print('[3] (b-inode) EXCEPTION ' + repr(e))

        # ---- [4] (b) real source change: header differs -> STILL conflict, NO writes ----
        try:
            fx = fresh('b_header', header='f' * 64)
            cfg = fx['config']
            installed.append(install_stubs(cfg))
            before = snapshot(cfg, fx)
            raised = None
            try:
                replay_round(cfg, fx)
            except MirrorError as e:
                raised = e.args[0]
            check(raised == 'scope_source_conflict', '[b-header] differing header STILL raises scope_source_conflict')
            after = snapshot(cfg, fx)
            check(after == before, '[b-header] NO writes (anchor/member/progress/receipt unchanged)')
            print('[4] (b) header change rejected, no writes: OK')
        except Exception as e:
            failures += 1
            print('[4] (b-header) EXCEPTION ' + repr(e))

        # ---- [5] (c) repeated renumber: re-pin to another stale st_dev, re-run ----
        try:
            fx = fresh('c')
            cfg = fx['config']
            installed.append(install_stubs(cfg))
            replay_round(cfg, fx)  # first renumber converges to live
            stale2 = fx['live_identity'][0] + 2000
            newprior = repin(cfg, fx, stale2)
            check(newprior[1] == fx['live_identity'][1], '[c] repeated renumber keeps the same inode')
            result2, status2, identity, h = replay_round(cfg, fx)
            after = snapshot(cfg, fx)
            check(after['anchor']['source_identity'] == identity, '[c] anchor re-converges to live identity')
            check(after['members'][TABLE]['source_identity'] == identity, '[c] member proof re-converges')
            check(after['progress']['source_identity'] == identity, '[c] local progress re-converges')
            check(bool(result2.get('auto_st_dev_renumber')), '[c] AUTO tolerance fires again')
            rec = after['receipt']
            check(rec['old_st_dev'] == stale2 and rec['new_st_dev'] == identity[0],
                  '[c] receipt records the NEW renumber (old=stale2, new=live)')
            print('[5] (c) repeated renumber handled again: OK')
        except Exception as e:
            failures += 1
            print('[5] (c) EXCEPTION ' + repr(e))

        # ---- [6] (d) idempotency: second identical run is a no-op ----
        try:
            fx = fresh('d')
            cfg = fx['config']
            installed.append(install_stubs(cfg))
            r1, s1, identity, h = replay_round(cfg, fx)
            rec1 = reg_state(cfg, 'source_st_dev_renumber_receipt:' + SHARD)
            r2, s2, _, _ = replay_round(cfg, fx)
            rec2 = reg_state(cfg, 'source_st_dev_renumber_receipt:' + SHARD)
            check(not r2.get('auto_st_dev_renumber'), '[d] second run emits NO new AUTO tolerance signal')
            check(rec1 == rec2, '[d] audit receipt NOT rewritten on second identical run')
            check(reg_state(cfg, 'shard_anchor:' + SHARD)['source_identity'] == identity,
                  '[d] anchor stays at live identity (converged)')
            print('[6] (d) idempotency: OK')
        except Exception as e:
            failures += 1
            print('[6] (d) EXCEPTION ' + repr(e))

        # ---- [7] (f) source missing -> blocked, NOT silently swallowed, NO writes ----
        try:
            fx = fresh('f')
            cfg = fx['config']
            installed.append(install_stubs(cfg))
            stamp = os.stat(fx['live_path'])
            identity = [stamp.st_dev, stamp.st_ino]
            with open(fx['live_path'], 'rb') as fh:
                header_hash = hashlib.sha256(fh.read(16)).hexdigest()
            before = snapshot(cfg, fx)
            os.remove(fx['live_path'])  # source disappears before tolerance re-proof
            raised = None
            with sc.registry(cfg, write=True) as registry:
                try:
                    sync._account_shard_anchor_check(cfg, registry, Path(fx['live_path']),
                                                     identity, header_hash)
                except MirrorError as e:
                    raised = e.args[0]
            check(raised == 'scope_source_conflict',
                  '[f] missing source refused with scope_source_conflict (not tolerated/swallowed)')
            after = snapshot(cfg, fx)
            check(after == before, '[f] NO writes on a missing source')
            print('[7] (f) missing source blocked, no writes: OK')
        except Exception as e:
            failures += 1
            print('[7] (f) EXCEPTION ' + repr(e))

        # ---- [8] bonus: malformed anchor rejected; None anchor unchanged ----
        try:
            fx = fresh('g_malformed', anchor_extra={'unexpected': 1})
            cfg = fx['config']
            installed.append(install_stubs(cfg))
            raised = None
            try:
                replay_round(cfg, fx)
            except MirrorError as e:
                raised = e.args[0]
            check(raised == 'scope_source_conflict', '[bonus] malformed anchor (extra key) STILL raises scope_source_conflict')
            check(reg_state(cfg, 'source_st_dev_renumber_receipt:' + SHARD) is None,
                  '[bonus] malformed anchor wrote NO AUTO receipt')

            fx2 = fresh('g_none', no_anchor=True, no_members=True)
            cfg2 = fx2['config']
            installed.append(install_stubs(cfg2))
            stamp = os.stat(fx2['live_path'])
            ident = [stamp.st_dev, stamp.st_ino]
            with open(fx2['live_path'], 'rb') as fh:
                hh = hashlib.sha256(fh.read(16)).hexdigest()
            with sc.registry(cfg2, write=True) as registry:
                ret = sync._account_shard_anchor_check(cfg2, registry, Path(fx2['live_path']), ident, hh)
            check(ret is None, '[bonus] None anchor handling unchanged (no comparison, no raise)')
            check(reg_state(cfg2, 'source_st_dev_renumber_receipt:' + SHARD) is None,
                  '[bonus] None anchor NOT auto-tolerated (no receipt)')
            print('[8] bonus: malformed/None anchor handling unchanged: OK')
        except Exception as e:
            failures += 1
            print('[8] bonus EXCEPTION ' + repr(e))

        # ---- [9] end-to-end: REAL _account_sync round completes, no identity guards ----
        try:
            fx = fresh('h', make_source_db=True)
            cfg = fx['config']
            installed.append(install_stubs(cfg))
            result = run_full_account_sync(fx)
            check(isinstance(result, dict) and 'account_scope' in result,
                  '[e2e] _account_sync returned a completed round result')
            gaps = result.get('gaps', [])
            check('scope_source_conflict' not in gaps, '[e2e] NO scope_source_conflict gap in the round')
            check('source_replaced' not in gaps, '[e2e] NO source_replaced gap in the round')
            last = reg_state(cfg, 'last_attempt', {})
            check('scope_source_conflict' not in last.get('gaps', []),
                  '[e2e] last_attempt gaps contain no scope_source_conflict')
            check(reg_state(cfg, 'shard_anchor:' + SHARD)['source_identity'] == fx['live_identity'],
                  '[e2e] anchor advanced to live identity by the real loop')
            check(read_progress(cfg, fx)['source_identity'] == fx['live_identity'],
                  '[e2e] local progress advanced to live identity by the real loop')
            rec = reg_state(cfg, 'source_st_dev_renumber_receipt:' + SHARD)
            check(rec is not None and rec.get('auto') is True, '[e2e] AUTO receipt written by the real loop')
            check(bool(result.get('auto_st_dev_renumber')), '[e2e] result carries AUTO tolerance signal')
            print('[9] (end-to-end) full _account_sync round completes, no scope_source_conflict/source_replaced: OK')
        except Exception as e:
            failures += 1
            import traceback
            print('[9] (end-to-end) EXCEPTION ' + repr(e))
            traceback.print_exc()

        if failures:
            print('\nRESULT: %d FAILURE(S)' % failures)
            sys.exit(1)
        print('\nRESULT: ALL CHECKS PASSED')
    finally:
        for token, originals in reversed(installed):
            try:
                restore_stubs(token, originals)
            except Exception:
                pass
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    main()
