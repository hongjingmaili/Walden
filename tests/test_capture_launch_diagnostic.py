"""Installed setup and an owned synthetic debugger diagnostic channel."""
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys

import pytest


pytestmark = pytest.mark.skipif(sys.platform != 'darwin', reason='requires macOS lipo')
DEBUGGER = '''#!/usr/bin/python3
import ast
import json
import os
from pathlib import Path
import sys
import time

scenario = SCENARIO
first = Path(sys.argv[2]).read_text().splitlines()[0]
embedded = ast.literal_eval(ast.parse(first.removeprefix('script '), mode='eval').body.args[0])
invocation = ast.parse(embedded).body[-1].value
_, _, _, diagnostic, token, _, _ = ast.literal_eval(invocation.args[0].value)
stages = dict.fromkeys(('target_create', 'environment', 'breakpoint', 'launch',
                       'breakpoint_hit', 'capture_write', 'target_termination'), 'not_started')
for step in ('target_create', 'environment', 'breakpoint'):
    stages[step] = 'completed'
stages['launch'] = 'failed'
result = dict(version=1, token=token, debugger_pid=os.getpid(), stages=stages,
              last_started='launch', last_completed='breakpoint', failed_stage='launch',
              elapsed_ms=3, target_pid=os.getpid(), target_state='exited',
              target_exit='unexpected', target_exit_status=9, target_exit_description=None,
              command_error=None, breakpoint_commands='not_entered', failure_detail='launch_unconfirmed',
              stop_source='none', stop_state='unknown', stop_facts=[], stop_threads_omitted=0,
              stop_error=None)
if scenario == 'uncertain-target':
    result['target_state'] = 'stopped'
elif scenario == 'invalid-channel':
    result['token'] = 'synthetic-invalid'
elif scenario == 'breakpoint-failed':
    stages.update(breakpoint='failed', launch='not_started')
    result.update(last_started='breakpoint', last_completed='environment', failed_stage='breakpoint',
                  failure_detail='setup_command_failed', target_pid=None, target_state='unknown',
                  target_exit='unknown', target_exit_status=None)
Path(diagnostic).write_text(json.dumps(result))
if scenario == 'timeout':
    time.sleep(4)
raise SystemExit(4 if scenario == 'debugger-failed' else 0)
'''


@pytest.mark.parametrize(('scenario', 'status', 'reason'), [
    ('launch-exit', 'capture_stage_failed', 'target_exited_during_launch'),
    ('uncertain-target', 'capture_stage_failed', None),
    ('breakpoint-failed', 'capture_stage_failed', None),
    ('invalid-channel', 'capture_diagnostic_invalid', None),
    ('debugger-failed', 'debugger_failed', None),
    ('timeout', 'debugger_cleanup_uncertain', 'debugger_timeout'),
])
def test_installed_setup_reports_validated_launch_exit(tmp_path, scenario, status, reason):
    root = tmp_path.resolve()
    source_home = root / 'synthetic-data'
    account = source_home / 'Documents' / 'xwechat_files' / 'synthetic_account'
    source = account / 'db_storage' / 'message'
    source.mkdir(parents=True)
    (source / 'message_0.db').write_bytes(b'never opened: test ends before validation')
    executable = root / 'Synthetic.app' / 'Contents' / 'MacOS' / 'Synthetic'
    executable.parent.mkdir(parents=True)
    shutil.copyfile('/usr/bin/true', executable)
    executable.chmod(0o755)
    (executable.parents[1] / 'Info.plist').write_bytes(plistlib.dumps({
        'CFBundleIdentifier': 'com.tencent.xinWeChat',
        'CFBundleExecutable': 'Synthetic',
    }))
    lldb = root / 'synthetic-lldb'
    lldb.write_text(DEBUGGER.replace('SCENARIO', repr(scenario)))
    lldb.chmod(0o700)
    config = root / 'output' / 'config.json'
    config.parent.mkdir(mode=0o700)
    private_tmp = root / 'tmp'
    private_tmp.mkdir(mode=0o700)
    setup = Path(sys.executable).parent / 'wechat-local-setup'
    argv = [str(setup), '--account-root', str(account), '--acquire-passphrase',
            '--wechat-executable', str(executable), '--wechat-data-home', str(source_home),
            '--lldb-executable', str(lldb), '--config', str(config),
            '--data-home', str(config.parent), '--mirror-username', 'synthetic_contact',
            '--timezone', 'Asia/Shanghai', '--capture-timeout', '0.6' if scenario == 'timeout' else '5']
    env = dict(os.environ, TMPDIR=str(private_tmp))
    env.pop('PYTHONPATH', None)
    result = subprocess.run(argv, text=True, capture_output=True, env=env, timeout=10)
    assert result.returncode == 2, result.stderr
    reported = json.loads(result.stdout)
    assert reported['status'] == status
    assert reported.get('failure_reason') == reason
    if scenario == 'launch-exit':
        diagnostics = reported['diagnostics']
        assert diagnostics['channel'] == 'valid'
        assert diagnostics['target_exit_status'] == 9
        assert diagnostics['validation'] == diagnostics['persistence'] == 'not_started'
        assert diagnostics['target_cleanup'] == diagnostics['group_cleanup'] == 'confirmed'
        assert not diagnostics['debugger_timeout'] and not diagnostics['debugger_cancelled']
    assert not config.exists()
    assert not config.with_name('passphrase.bin').exists()
