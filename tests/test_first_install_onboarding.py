"""Product setup entry and real local sync/contract; OS and SQLCipher boundaries are synthetic."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys

import pytest

from wechat_local import source_setup as setup
from wechat_local import native_onboarding as onboard
from wechat_local import native_follow as follow
from wechat_local import native_mirror_sync as sync
from wechat_local import native_scope_contract as scope

USERNAME = 'synthetic_peer'
TABLE = 'Msg_' + hashlib.md5(USERNAME.encode()).hexdigest()


class Service:
    def __init__(self):
        self.context = dict(domain='kSMDomainUserLaunchd', uid=os.getuid(), security_session=1)
        self.payload = None
        self.submits = 0
        self.fail = False

    def observe(self, target):
        if self.payload is None:
            return dict(target=target, state='absent')
        args = self.payload['ProgramArguments']
        return dict(target=target, state='present', argv=args, operation=args[args.index('--operation-token') + 1])

    def submit(self, payload):
        if self.fail:
            raise OSError('synthetic service failure')
        self.payload = payload
        self.submits += 1


def plain(path, _secret):
    conn = sqlite3.connect('file:' + str(path) + '?mode=ro', uri=True)
    conn.execute('PRAGMA query_only=ON')
    return conn, 32


@pytest.fixture
def item(tmp_path, monkeypatch):
    # Resolve macOS /var alias: scope primitives require a canonical private path.
    root = tmp_path.resolve()
    source = root / 'account'
    message = source / 'db_storage/message'
    message.mkdir(parents=True)
    db = message / 'message_0.db'
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE Name2Id(user_name TEXT)')
        conn.execute('INSERT INTO Name2Id VALUES(?)', (USERNAME,))
        conn.execute('CREATE TABLE ' + TABLE + '(local_id INTEGER PRIMARY KEY, local_type INTEGER, create_time INTEGER, real_sender_id INTEGER, message_content TEXT, WCDB_CT_message_content INTEGER)')
        conn.executemany('INSERT INTO ' + TABLE + ' VALUES(?,1,1,1,?,0)', [(1, 'synthetic one'), (2, 'synthetic two')])
    db.chmod(0o600)
    private = root / 'private'
    private.mkdir(mode=0o700)
    key = private / 'passphrase.bin'
    key.write_bytes(b's' * 32)
    key.chmod(0o600)
    bin_dir = root / 'bin'
    bin_dir.mkdir()
    for name in ('python','wechat-local-setup','wechat-local-window','wechat-local-reply','wechat-local-sync'):
        path = bin_dir / name
        path.touch(mode=0o700)
    monkeypatch.setattr(sys, 'argv', [str(bin_dir / 'wechat-local-setup')])
    monkeypatch.setattr(sys, 'executable', str(bin_dir / 'python'))
    monkeypatch.setattr(setup, 'open_encrypted_readonly', plain)
    monkeypatch.setattr(sync, 'open_encrypted_readonly', plain)
    monkeypatch.setattr(follow, '_home', lambda: root / 'home')
    monkeypatch.setenv('XDG_STATE_HOME', str(root / 'state'))
    service = Service()
    monkeypatch.setattr(follow, 'LaunchctlTransport', lambda: service)
    profile = private / 'source.json'
    args = ['--account-root', str(source), '--confirm-self-username', 'synthetic_self',
            '--mirror-username', USERNAME, '--passphrase-file', str(key), '--config', str(profile),
            '--data-home', str(root / 'data'), '--timezone', 'UTC', '--start-sync', '--confirmed']
    return dict(root=root, args=args, profile=profile, service=service, key=key, db=db)


def invoke(item, capsys, args=None):
    code = setup.main(item['args'] if args is None else args)
    return code, json.loads(capsys.readouterr().out)


def account_args(item):
    args = list(item['args'])
    i = args.index('--mirror-username')
    del args[i:i+2]
    return args + ['--account-scope']


def test_selected_product_entry_connects_and_repeats_without_reset(item, capsys):
    code, report = invoke(item, capsys)
    assert code == 0 and report['stage'] == 'background_registered', report
    assert report['background']['state'] == 'starting'
    assert report['history_complete'] is None
    config = setup.load_source_config(item['profile'])
    mirrored = Path(config['mirror_root']) / 'message_0.db'
    with sqlite3.connect(mirrored) as conn:
        assert conn.execute('SELECT count(*) FROM ' + TABLE).fetchone() == (2,)
    before = item['profile'].read_bytes(), mirrored.read_bytes()
    code, report = invoke(item, capsys)
    assert code == 0 and report['initialization']['status'] == 'preserved_existing_copy'
    assert before == (item['profile'].read_bytes(), mirrored.read_bytes())
    assert item['service'].submits == 1


@pytest.mark.parametrize('mode', ['missing_confirmation', 'missing_identity', 'missing_scope', 'both_scopes'])
def test_confirmation_rejections_have_no_side_effects(item, capsys, mode):
    args = list(item['args'])
    if mode == 'missing_confirmation':
        args.remove('--confirmed')
    elif mode in ('missing_identity', 'missing_scope'):
        name = '--confirm-self-username' if mode == 'missing_identity' else '--mirror-username'
        i = args.index(name); del args[i:i+2]
    else:
        args.append('--account-scope')
    code, report = invoke(item, capsys, args)
    assert code == 2 and report['stage'] == 'confirmation'
    assert not item['profile'].exists() and not item['profile'].with_name('.source.json.onboarding.lock').exists()
    assert item['service'].submits == 0


def test_config_failure_stops_before_init_and_service(item, capsys):
    item['key'].unlink()
    code, report = invoke(item, capsys)
    assert code == 2 and report['stage'] == 'configuration'
    assert not item['profile'].exists() and item['service'].submits == 0


@pytest.mark.parametrize('outcome', ['failed', 'cancelled'])
def test_capture_failure_or_cancel_never_initializes(item, capsys, monkeypatch, outcome):
    from wechat_local import credential_capture as capture
    args = list(item['args']); i = args.index('--passphrase-file'); del args[i:i+2]
    item['key'].unlink()
    args += ['--acquire-passphrase','--wechat-executable',str(item['root']/'app'),
             '--wechat-data-home',str(item['root']/'wechat'), '--lldb-executable',str(item['root']/'lldb')]
    def external(**kwargs):
        if outcome == 'cancelled':
            raise KeyboardInterrupt
        return dict(status='capture_stage_failed')
    monkeypatch.setattr(capture, 'capture_and_save_passphrase', external)
    code, report = invoke(item, capsys, args)
    assert code == 2 and report['stage'] == 'configuration'
    assert report['status'] == ('onboarding_cancelled' if outcome == 'cancelled' else 'onboarding_failed')
    assert not item['profile'].exists() and item['service'].submits == 0


def test_init_failure_retries_same_profile_without_capture(item, capsys):
    with sqlite3.connect(item['db']) as conn:
        conn.execute('DROP TABLE ' + TABLE)
    code, report = invoke(item, capsys)
    assert code == 2 and report['stage'] == 'initialization' and item['service'].submits == 0
    before = item['profile'].read_bytes()
    with sqlite3.connect(item['db']) as conn:
        conn.execute('CREATE TABLE ' + TABLE + '(local_id INTEGER PRIMARY KEY, local_type INTEGER, create_time INTEGER, real_sender_id INTEGER, message_content TEXT, WCDB_CT_message_content INTEGER)')
    code, report = invoke(item, capsys)
    assert code == 0 and item['profile'].read_bytes() == before


def test_enable_failure_retries_existing_intent_once(item, capsys):
    item['service'].fail = True
    code, report = invoke(item, capsys)
    assert code == 2 and report['stage'] == 'background_enable'
    assert report['background_enabled'] is True and report['background']['listener_registration'] == 'absent'
    before = item['profile'].read_bytes()
    item['service'].fail = False
    code, report = invoke(item, capsys)
    assert code == 0 and item['service'].submits == 1 and item['profile'].read_bytes() == before


@pytest.mark.parametrize('change', ['source','identity','scope','account_scope','destination'])
def test_existing_binding_conflicts_never_expand_or_replace(item, capsys, change):
    assert invoke(item, capsys)[0] == 0
    before = item['profile'].read_bytes()
    args = list(item['args'])
    option, value = {'source':('--account-root',str(item['root']/'other')),
                     'identity':('--confirm-self-username','other_self'),
                     'scope':('--mirror-username','other_peer'),
                     'destination':('--data-home',str(item['root']/'other-data')),
                     'account_scope':('--mirror-username',None)}[change]
    i=args.index(option)
    if value is None:
        del args[i:i+2]; args += ['--account-scope']
    else:
        args[i+1]=value
    code, report = invoke(item, capsys, args)
    assert code == 2 and report['stage'] == 'configuration'
    assert before == item['profile'].read_bytes() and item['service'].submits == 1


def test_account_initialization_commits_empty_contract_then_registers(item, capsys):
    code, report = invoke(item, capsys, account_args(item))
    assert code == 0 and report['initialization']['copy_pending'], report
    config = setup.load_source_config(item['profile'])
    assert scope.query_scope_guard(config)[0] == 'account'
    with scope.registry(config) as conn:
        assert conn.execute('SELECT count(*) FROM members').fetchone() == (0,)
    assert report['coverage']['raw_messages_complete'] is False
    assert report['history_complete'] is None and item['service'].submits == 1
    assert invoke(item, capsys, account_args(item))[0] == 0
    assert item['service'].submits == 1


@pytest.mark.parametrize('cut', ['registry','writer_lock','receipt','current','publication_record','publication'])
def test_account_staging_interruption_retries_without_trusting_partial_stage(item, capsys, monkeypatch, cut):
    original_create, original_publish = scope.create, onboard._publish_directory
    fired = []
    def interrupted_create(path, raw):
        value = original_create(path, raw)
        if (cut == 'receipt' and path.name == '.first-install-receipt.json') or (cut == 'writer_lock' and path.name == '.writer.lock') or (cut == 'current' and path.name == scope.CURRENT) or (cut == 'publication_record' and path.name.endswith('.account-publication.json')):
            fired.append(True); raise KeyboardInterrupt
        return value
    def interrupted_publish(staged, target):
        if cut == 'publication':
            fired.append(True); raise KeyboardInterrupt
        return original_publish(staged, target)
    monkeypatch.setattr(scope, 'create', interrupted_create)
    monkeypatch.setattr(onboard, '_publish_directory', interrupted_publish)
    if cut == 'registry':
        original_registry = scope.registry
        from contextlib import contextmanager
        @contextmanager
        def registry(config, **kwargs):
            with original_registry(config, **kwargs) as conn:
                yield conn
            if kwargs.get('initialize'):
                fired.append(True); raise KeyboardInterrupt
        monkeypatch.setattr(scope, 'registry', registry)
    code, report = invoke(item, capsys, account_args(item))
    assert fired and code == 2 and report['stage'] == 'initialization'
    config = setup.load_source_config(item['profile'])
    assert not Path(config['mirror_root']).exists() and item['service'].submits == 0
    monkeypatch.setattr(scope, 'create', original_create)
    monkeypatch.setattr(onboard, '_publish_directory', original_publish)
    if cut == 'registry': monkeypatch.setattr(scope, 'registry', original_registry)
    assert invoke(item, capsys, account_args(item))[0] == 0


def test_account_unknown_destination_is_never_repaired(item, capsys, monkeypatch):
    original = onboard.initialize_account
    def occupied(config, profile, **kwargs):
        root=Path(config['mirror_root']); root.mkdir(parents=True, mode=0o700)
        (root/'unknown').write_text('untouched')
        return original(config, profile, **kwargs)
    monkeypatch.setattr(onboard,'initialize_account',occupied)
    code, report=invoke(item,capsys,account_args(item))
    assert code==2 and report['stage']=='initialization' and item['service'].submits==0
    config=setup.load_source_config(item['profile'])
    assert (Path(config['mirror_root'])/'unknown').read_text()=='untouched'


def test_exclusive_setup_rejects_competing_execution(item, capsys):
    with onboard._exclusive(item['profile']):
        code, report=invoke(item,capsys)
    assert code==2 and report['error']=='onboarding_busy'
    assert not item['profile'].exists() and item['service'].submits==0


def test_plain_setup_still_only_configures(item, capsys):
    args=[a for a in item['args'] if a not in ('--start-sync','--confirmed')]
    code, report=invoke(item,capsys,args)
    assert code==0 and report['status']=='configured' and report['next_step']=='init'
    config=setup.load_source_config(item['profile'])
    assert not Path(config['mirror_root']).exists() and item['service'].submits==0


def test_successful_capture_flows_into_copy_and_background(item, capsys, monkeypatch):
    from wechat_local import credential_capture as capture
    args=list(item['args']); i=args.index('--passphrase-file'); del args[i:i+2]
    item['key'].unlink()
    args += ['--wechat-executable',str(item['root']/'app'),'--wechat-data-home',str(item['root']/'wechat'),
             '--lldb-executable',str(item['root']/'lldb')]
    calls=[]
    def external(**kwargs):
        calls.append('capture')
        key=item['key'];key.write_bytes(b's'*32);key.chmod(0o600)
        info,parent=key.stat(),key.parent.stat()
        identity=(info.st_dev,info.st_ino)
        kwargs['_validation_observations'].update(credential=b's'*32,credential_identity=identity,
            credential_parent_identity=(parent.st_dev,parent.st_ino))
        return dict(status='captured_and_verified',passphrase_file=str(key),_passphrase_identity=identity,
                    diagnostics=dict(validation='completed',persistence='completed',cleanup='confirmed'))
    monkeypatch.setattr(capture,'capture_and_save_passphrase',external)
    code,report=invoke(item,capsys,args)
    assert code==0 and calls==['capture'] and item['service'].submits==1,report
    assert report['configuration']['credential_capture']=='captured_and_verified'
    # Retry with the same confirmed selection reuses the bound profile and never captures again.
    assert invoke(item,capsys,args)[0]==0 and calls==['capture']


def test_configuration_change_between_init_and_enable_is_rejected(item,capsys,monkeypatch):
    original=sync.sync_once
    def changed(config,*args,**kwargs):
        result=original(config,*args,**kwargs)
        updated=dict(config,mirror_scope=['other_peer'])
        item['profile'].write_text(json.dumps(updated))
        return result
    monkeypatch.setattr(sync,'sync_once',changed)
    code,report=invoke(item,capsys)
    assert code==2 and report['stage']=='background_enable' and report['error']=='onboarding_configuration_changed'
    assert item['service'].submits==0


def test_account_exclusive_publish_never_replaces_racing_destination(item,capsys,monkeypatch):
    original=onboard._publish_directory
    def racing(staged,target):
        target.mkdir(mode=0o700)
        return original(staged,target)
    monkeypatch.setattr(onboard,'_publish_directory',racing)
    code,report=invoke(item,capsys,account_args(item))
    assert code==2 and report['stage']=='initialization' and item['service'].submits==0
    config=setup.load_source_config(item['profile'])
    assert list(Path(config['mirror_root']).iterdir())==[]


@pytest.mark.parametrize('corruption',['receipt','registry','current','pending'])
def test_committed_account_corruption_is_not_repaired_or_enabled(item,capsys,monkeypatch,corruption):
    # Prepare normally but make the OS registration fail so no active service remains.
    item['service'].fail=True
    code,report=invoke(item,capsys,account_args(item))
    assert code==2 and report['stage']=='background_enable'
    config=setup.load_source_config(item['profile'])
    root=Path(config['mirror_root'])
    path=root/({'receipt':'.first-install-receipt.json','registry':scope.REGISTRY,
                'current':scope.CURRENT,'pending':scope.PENDING}[corruption])
    if corruption=='registry':
        with sqlite3.connect(path) as conn:conn.execute('UPDATE binding SET value=?',('{}',))
    else:
        path.write_text('{}');path.chmod(0o600)
    before=path.read_bytes()
    item['service'].fail=False
    code,report=invoke(item,capsys,account_args(item))
    assert code==2 and item['service'].submits==0
    assert path.read_bytes()==before


def test_first_account_contract_admits_existing_owned_sync_only(item,capsys,monkeypatch):
    from wechat_local import native_follow_grant as grants
    from wechat_local import native_deadline as deadlines
    from wechat_local.native_follow_policy import digest
    assert invoke(item,capsys,account_args(item))[0]==0
    config=setup.load_source_config(item['profile'])
    with pytest.raises(onboard.MirrorError,match='account_source_role_required'):
        sync.sync_once(config,[],initialize=True)
    # Only the external OS/process attestation is substituted; the installed
    # FollowDeadline type, source digest, contract and sync admission stay real.
    monkeypatch.setattr(grants,'validate',lambda grant:None)
    deadline=grants.FollowDeadline(dict(wall_until=30.,continuous_start=0,continuous_until=30_000_000_000),
        dict(kind='active',source_sha256=digest(config)),wall=lambda:0.,continuous=lambda:1)
    with deadlines.activate_deadline(deadline):
        result=sync.sync_once(config,[])
    assert not result['gaps'],result
    with scope.registry(config) as conn:
        assert conn.execute('SELECT count(*) FROM members').fetchone()==(1,)
        shell=scope.state(conn,'copy_shell:message_0.db')
        assert shell and (Path(config['mirror_root'])/shell['stage']).is_file()
    assert not (Path(config['mirror_root'])/'message_0.db').exists()
    # A second original owned round publishes the exact persisted shell and
    # observes the initial suffix; no foreground authority is manufactured.
    deadline=grants.FollowDeadline(dict(wall_until=30.,continuous_start=0,continuous_until=30_000_000_000),
        dict(kind='active',source_sha256=digest(config)),wall=lambda:0.,continuous=lambda:1)
    with deadlines.activate_deadline(deadline):
        result=sync.sync_once(config,[])
    assert not result['gaps'],result
    with sqlite3.connect(Path(config['mirror_root'])/'message_0.db') as conn:
        assert conn.execute('SELECT count(*) FROM '+TABLE).fetchone()==(2,)
        progress=json.loads(conn.execute('SELECT value FROM __walden_progress WHERE table_name=?',(TABLE,)).fetchone()[0])
        assert progress['history']==0 and progress['H']==2 and not progress['initial_suffix_pending']


@pytest.mark.parametrize('inside',['config','data'])
def test_source_contained_outputs_rejected_before_any_lock_write(item,capsys,inside):
    args=list(item['args']);source=item['db'].parents[2]
    target=source/'new-output'
    option='--config' if inside=='config' else '--data-home'
    args[args.index(option)+1]=str(target/'source.json' if inside=='config' else target)
    before={str(p.relative_to(source)):p.read_bytes() for p in source.rglob('*') if p.is_file()}
    code,report=invoke(item,capsys,args)
    after={str(p.relative_to(source)):p.read_bytes() for p in source.rglob('*') if p.is_file()}
    assert code==2 and report['stage']=='configuration'
    assert not target.exists() and not item['profile'].with_name('.source.json.onboarding.lock').exists()
    assert before==after and item['service'].submits==0


def test_published_account_missing_never_recreates_empty_copy(item,capsys):
    item['service'].fail=True
    assert invoke(item,capsys,account_args(item))[0]==2
    config=setup.load_source_config(item['profile']);root=Path(config['mirror_root'])
    before={p.name:p.read_bytes() for p in root.iterdir()}
    preserved=root.with_name(root.name+'.preserved');root.rename(preserved)
    item['service'].fail=False
    code,report=invoke(item,capsys,account_args(item))
    assert code==2 and report['error']=='onboarding_initialized_copy_missing'
    assert not root.exists() and item['service'].submits==0
    assert before=={p.name:p.read_bytes() for p in preserved.iterdir()}


@pytest.mark.parametrize('material',['missing','wrong_length','wrong_key'])
def test_saved_credentials_are_revalidated_before_retry_side_effects(item,capsys,monkeypatch,material):
    from wechat_local.live_readonly import LiveReadonlyError
    item['service'].fail=True
    assert invoke(item,capsys,account_args(item))[0]==2
    config=setup.load_source_config(item['profile']);root=Path(config['mirror_root'])
    before={p.name:p.read_bytes() for p in root.iterdir()}
    if material=='missing':item['key'].unlink()
    else:item['key'].write_bytes(b'bad' if material=='wrong_length' else b'w'*32)
    original=setup._metadata_connection
    def crypto_boundary(path,secret):
        if secret!=b's'*32:raise LiveReadonlyError('synthetic HMAC mismatch')
        return original(path,secret)
    monkeypatch.setattr(setup,'_metadata_connection',crypto_boundary)
    item['service'].fail=False
    code,report=invoke(item,capsys,account_args(item))
    assert code==2 and report['stage']=='credential_validation'
    assert report['error']=='onboarding_credentials_unavailable' and not report['background_enable_attempted']
    assert item['service'].submits==0 and before=={p.name:p.read_bytes() for p in root.iterdir()}
    item['key'].write_bytes(b's'*32);item['key'].chmod(0o600)
    assert invoke(item,capsys,account_args(item))[0]==0


def test_unknown_account_profile_without_creation_proof_cannot_initialize(item,capsys):
    result=setup.prepare_account_source(item['db'].parents[2],passphrase_file=item['key'],
        config_path=item['profile'],data_home=item['root']/'data',runtime_python=Path(sys.executable),
        window_cli=Path(sys.executable).parent/'wechat-local-window',reply_cli=Path(sys.executable).parent/'wechat-local-reply',
        confirm_self_username='synthetic_self',query_timezone='UTC',mirror_scope_mode='account')
    assert result['status']=='configured'
    config=setup.load_source_config(item['profile'])
    code,report=invoke(item,capsys,account_args(item))
    assert code==2 and report['error']=='onboarding_profile_provenance_required'
    assert not Path(config['mirror_root']).exists() and item['service'].submits==0


@pytest.mark.parametrize('tamper',['file','directory','witness'])
def test_unpublished_account_stage_requires_exact_publication_ownership(item,capsys,monkeypatch,tamper):
    original=onboard._publish_directory
    monkeypatch.setattr(onboard,'_publish_directory',lambda *args:(_ for _ in ()).throw(KeyboardInterrupt()))
    assert invoke(item,capsys,account_args(item))[0]==2
    witness=item['profile'].with_name('.source.json.account-publication.json')
    record=json.loads(witness.read_text());staged=Path(record['stage'])
    if tamper=='file':(staged/scope.CURRENT).write_text('{}')
    elif tamper=='directory':
        staged.rename(staged.with_name(staged.name+'.preserved'));staged.mkdir(mode=0o700)
    else:
        record['config_sha256']='0'*64;witness.write_text(json.dumps(record))
    monkeypatch.setattr(onboard,'_publish_directory',original)
    config=setup.load_source_config(item['profile'])
    code,report=invoke(item,capsys,account_args(item))
    assert code==2 and not Path(config['mirror_root']).exists() and item['service'].submits==0


@pytest.mark.parametrize('replace_key',[False,True])
def test_cancel_after_capture_cleans_only_owned_unpublished_credential(item,capsys,monkeypatch,replace_key):
    from wechat_local import credential_capture as capture
    args=list(item['args']);i=args.index('--passphrase-file');del args[i:i+2];item['key'].unlink()
    args += ['--wechat-executable',str(item['root']/'app'),'--wechat-data-home',str(item['root']/'wechat'),
             '--lldb-executable',str(item['root']/'lldb')]
    def external(**kwargs):
        key=item['key'];key.write_bytes(b's'*32);key.chmod(0o600)
        info,parent=key.stat(),key.parent.stat();identity=(info.st_dev,info.st_ino)
        kwargs['_validation_observations'].update(credential=b's'*32,credential_identity=identity,
            credential_parent_identity=(parent.st_dev,parent.st_ino))
        return dict(status='captured_and_verified',passphrase_file=str(key),_passphrase_identity=identity,
                    diagnostics=dict(validation='completed',persistence='completed',cleanup='confirmed'))
    original=setup._metadata_connection
    def interrupted(*args,**kwargs):
        if replace_key:
            replacement=item['key'].with_name('foreign.bin');replacement.write_bytes(b'f'*32);replacement.chmod(0o600)
            replacement.replace(item['key'])
        raise KeyboardInterrupt
    monkeypatch.setattr(capture,'capture_and_save_passphrase',external)
    monkeypatch.setattr(setup,'_metadata_connection',interrupted)
    code,report=invoke(item,capsys,args)
    assert code==2 and report['status']=='onboarding_cancelled' and not item['profile'].exists()
    assert item['service'].submits==0
    monkeypatch.setattr(setup,'_metadata_connection',original)
    if replace_key:assert item['key'].read_bytes()==b'f'*32
    else:
        assert not item['key'].exists()
        assert invoke(item,capsys,args)[0]==0


@pytest.mark.parametrize('damage', ['files_list','files_null','files_nested','files_wrong_keys',
    'digest_number','digest_null','digest_list','digest_short','digest_upper',
    'stage_list','identity_dict','identity_short','identity_bool','identity_negative'])
def test_publication_record_types_fail_with_phase_and_preserve_evidence(item,capsys,monkeypatch,damage):
    original=onboard._publish_directory
    monkeypatch.setattr(onboard,'_publish_directory',lambda *args:(_ for _ in ()).throw(KeyboardInterrupt()))
    assert invoke(item,capsys,account_args(item))[0]==2
    path=item['profile'].with_name('.source.json.account-publication.json')
    value=json.loads(path.read_text());stage=Path(value['stage'])
    if damage=='files_list':value['files']=list(value['files'])
    elif damage=='files_null':value['files']=None
    elif damage=='files_nested':value['files']=[{}]
    elif damage=='files_wrong_keys':value['files']={'unknown':'0'*64}
    elif damage.startswith('digest_'):
        value['files'][scope.REGISTRY]={'digest_number':1,'digest_null':None,'digest_list':[],
            'digest_short':'0'*63,'digest_upper':'A'*64}[damage]
    elif damage=='stage_list':value['stage']=[]
    elif damage=='identity_dict':value['directory_identity']={}
    elif damage=='identity_short':value['directory_identity']=[1,2]
    elif damage=='identity_bool':value['directory_identity']=[True,2,3]
    else:value['directory_identity']=[-1,2,3]
    path.write_text(json.dumps(value));before=path.read_bytes()
    stage_before={p.name:p.read_bytes() for p in stage.iterdir()}
    monkeypatch.setattr(onboard,'_publish_directory',original)
    code,report=invoke(item,capsys,account_args(item))
    assert code==2 and report['stage']=='initialization'
    assert report['error']=='onboarding_publication_binding_invalid'
    assert path.read_bytes()==before and stage_before=={p.name:p.read_bytes() for p in stage.iterdir()}
    assert not report['background_enable_attempted'] and item['service'].submits==0


@pytest.mark.parametrize('damage',['list','null','contract_list','contract_number','contract_short'])
def test_creation_record_types_fail_with_phase_without_repair(item,capsys,monkeypatch,damage):
    original=setup._metadata_connection
    monkeypatch.setattr(setup,'_metadata_connection',lambda *args:(_ for _ in ()).throw(KeyboardInterrupt()))
    assert invoke(item,capsys,account_args(item))[0]==2
    path=item['profile'].with_name('.source.json.account-creation.json');value=json.loads(path.read_text())
    if damage=='list':value=list(value)
    elif damage=='null':value=None
    else:value['scope_contract_id']={'contract_list':[],'contract_number':1,'contract_short':'0'*31}[damage]
    path.write_text(json.dumps(value));before=path.read_bytes()
    monkeypatch.setattr(setup,'_metadata_connection',original)
    code,report=invoke(item,capsys,account_args(item))
    assert code==2 and report['stage']=='configuration' and report['error']=='onboarding_profile_provenance_invalid'
    assert not item['profile'].exists() and item['service'].submits==0 and path.read_bytes()==before


def test_first_account_publishes_formal_writer_lock_contract(item,capsys):
    from wechat_local.native_schedule import _writer_state
    code,report=invoke(item,capsys,account_args(item));assert code==0,report
    config=setup.load_source_config(item['profile']);root=Path(config['mirror_root']);lock=root/'.writer.lock'
    assert scope.read(lock)[0]==b'' and lock.stat().st_nlink==1
    assert _writer_state(config)=='free'
    record=json.loads(item['profile'].with_name('.source.json.account-publication.json').read_text())
    assert record['files']['.writer.lock']==hashlib.sha256(b'').hexdigest()


@pytest.mark.parametrize('damage',['missing_file','old_three_file_stage'])
def test_account_missing_initial_writer_lock_is_not_repaired(item,capsys,monkeypatch,damage):
    original=onboard._publish_directory
    if damage=='old_three_file_stage':
        monkeypatch.setattr(onboard,'_publish_directory',lambda *args:(_ for _ in ()).throw(KeyboardInterrupt()))
    else:item['service'].fail=True
    assert invoke(item,capsys,account_args(item))[0]==2
    config=setup.load_source_config(item['profile']);root=Path(config['mirror_root'])
    path=item['profile'].with_name('.source.json.account-publication.json');record=json.loads(path.read_text())
    target=Path(record['stage']) if damage=='old_three_file_stage' else root
    (target/'.writer.lock').unlink()
    if damage=='old_three_file_stage':
        del record['files']['.writer.lock'];path.write_text(json.dumps(record))
    before={p.name:p.read_bytes() for p in target.iterdir()}
    monkeypatch.setattr(onboard,'_publish_directory',original);item['service'].fail=False
    code,report=invoke(item,capsys,account_args(item))
    assert code==2 and report['error']=='onboarding_writer_lock_missing'
    assert not (target/'.writer.lock').exists() and before=={p.name:p.read_bytes() for p in target.iterdir()}
    assert item['service'].submits==0
