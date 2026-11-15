"""MAC signing tests using a synthetic app and no debugger or credentials."""
import json
import os
import plistlib
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from wechat_local import credential_capture as capture


pytestmark = pytest.mark.skipif(sys.platform != 'darwin', reason='requires macOS codesign')
FINDER_INFO = 'com.apple.FinderInfo'
RESOURCE_FORK = 'com.apple.ResourceFork'
KEEP_ATTRIBUTE = 'org.example.capture-test'


def _xattr(*args):
    return subprocess.run(['/usr/bin/xattr', *map(str, args)], check=True, capture_output=True).stdout


@pytest.fixture
def bundle_pair(tmp_path):
    parent = tmp_path.resolve()
    bundle = parent / 'Synthetic.app'
    source = bundle / 'Contents' / 'MacOS' / 'Synthetic'
    source.parent.mkdir(parents=True)
    shutil.copyfile('/usr/bin/true', source)
    source.chmod(0o755)
    (source.parents[1] / 'Info.plist').write_bytes(plistlib.dumps({
        'CFBundleExecutable': source.name,
        'CFBundleIdentifier': 'com.tencent.xinWeChat',
        'CFBundlePackageType': 'APPL',
    }))
    root, lock, error = capture._client_root(parent / 'config.json')
    assert root is not None and lock is not None and error is None
    try:
        yield bundle, source, root
    finally:
        capture._release_client_lock(root, lock)


def test_preparation_removes_only_forbidden_copy_attributes(bundle_pair):
    bundle, source, root = bundle_pair
    resources = bundle / 'Contents' / 'Resources'
    resources.mkdir()
    nested = resources / 'nested'
    nested.mkdir()
    resource = nested / 'data'
    resource.write_bytes(b'data')
    read_only = nested / 'read-only'
    read_only.write_bytes(b'read only')
    read_only.chmod(0o444)
    (resources / 'internal-link').symlink_to('nested/data')
    _xattr('-wx', FINDER_INFO, (b'TEXTttxt' + b'\0' * 24).hex(), nested)
    _xattr('-w', RESOURCE_FORK, 'fork', resource)
    _xattr('-w', KEEP_ATTRIBUTE, 'preserved', resource)

    result, error, detail = capture._prepare_reusable_client(root, source)

    assert error is None, (error, detail)
    copied = result.parents[2]
    target_nested = copied / nested.relative_to(bundle)
    target_resource = copied / resource.relative_to(bundle)
    assert FINDER_INFO.encode() not in _xattr(target_nested).splitlines()
    assert RESOURCE_FORK.encode() not in _xattr(target_resource).splitlines()
    assert _xattr('-p', KEEP_ATTRIBUTE, target_resource).strip() == b'preserved'
    assert _xattr('-p', RESOURCE_FORK, resource).strip() == b'fork'
    assert FINDER_INFO.encode() in _xattr(nested).splitlines()
    target_read_only = copied / read_only.relative_to(bundle)
    assert target_read_only.stat().st_mode & 0o777 == 0o444
    assert not _xattr(target_read_only)
    assert (copied / 'Contents' / 'Resources' / 'internal-link').is_symlink()
    subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(copied)],
                   check=True, capture_output=True)


def test_clean_copy_and_cached_copy_use_strict_verification(bundle_pair, monkeypatch):
    _, source, root = bundle_pair
    official = capture._run_preparation_command
    steps = []

    def trace(step, argv):
        steps.append((step, argv))
        return official(step, argv)

    monkeypatch.setattr(capture, '_run_preparation_command', trace)
    first = capture._prepare_reusable_client(root, source)
    assert first[0] is not None and first[1:] == (None, None)
    assert [step for step, _ in steps] == ['copy', 'sign', 'verify']
    steps.clear()
    assert capture._prepare_reusable_client(root, source) == first
    assert len(steps) == 1 and steps[0][0] == 'verify'
    assert '--deep' in steps[0][1] and '--strict' in steps[0][1]


@pytest.mark.parametrize('link', ['symlink', 'hardlink'])
def test_external_or_shared_entry_is_rejected_before_signing(bundle_pair, monkeypatch, link):
    bundle, source, root = bundle_pair
    outside = bundle.parent / 'outside'
    outside.write_bytes(b'outside')
    _xattr('-wx', FINDER_INFO, (b'TEXTttxt' + b'\0' * 24).hex(), outside)
    official = capture._run_preparation_command
    steps = []

    def with_link(step, argv):
        steps.append(step)
        ok, error = official(step, argv)
        if step == 'copy' and ok:
            path = Path(argv[-1]) / 'Contents' / 'unsafe'
            if link == 'symlink':
                path.symlink_to(outside)
            else:
                os.link(outside, path)
        return ok, error

    monkeypatch.setattr(capture, '_run_preparation_command', with_link)
    assert capture._prepare_reusable_client(root, source) == (None, 'preparation_unsafe_bundle', None)
    assert steps == ['copy']
    assert outside.read_bytes() == b'outside'
    assert FINDER_INFO.encode() in _xattr(outside).splitlines()
    assert json.loads((root / 'owner.json').read_text())['client'] is None


def test_signing_failure_never_commits_reusable_copy(bundle_pair, monkeypatch):
    _, source, root = bundle_pair
    official = capture._run_preparation_command
    steps = []

    def signing_error(step, argv):
        steps.append(step)
        if step == 'sign':
            argv = [*argv[:-1], str(Path(argv[-1]) / 'missing-target')]
        return official(step, argv)

    monkeypatch.setattr(capture, '_run_preparation_command', signing_error)
    result, error, detail = capture._prepare_reusable_client(root, source)
    assert result is None and error == 'preparation_sign_failed' and detail
    assert steps == ['copy', 'sign']
    assert json.loads((root / 'owner.json').read_text())['client'] is None


@pytest.mark.parametrize('replacement', ['symlink', 'hardlink', 'bundle', 'bundle-cycle'])
def test_copy_changes_after_safety_check_fail_closed(bundle_pair, monkeypatch, replacement):
    bundle, source, root = bundle_pair
    outside = bundle.parent / 'outside'
    outside.write_bytes(b'outside')
    _xattr('-wx', FINDER_INFO, (b'TEXTttxt' + b'\0' * 24).hex(), outside)
    safe = capture._safe_copied_bundle
    official = capture._run_preparation_command
    steps = []

    def substitute(copy):
        assert safe(copy)
        if replacement in {'bundle', 'bundle-cycle'}:
            saved = copy.with_name('saved.app')
            copy.rename(saved)
            if replacement == 'bundle-cycle':
                copy.symlink_to(copy.name)
            else:
                shutil.copytree(saved, copy)
        else:
            path = copy / 'Contents' / 'changed'
            if replacement == 'symlink':
                path.symlink_to(outside)
            else:
                os.link(outside, path)
        return True

    def trace(step, argv):
        steps.append(step)
        return official(step, argv)

    monkeypatch.setattr(capture, '_safe_copied_bundle', substitute)
    monkeypatch.setattr(capture, '_run_preparation_command', trace)
    result, error, detail = capture._prepare_reusable_client(root, source)
    assert result is None and error == 'preparation_xattr_failed'
    assert detail and str(outside) not in detail
    assert steps == ['copy']
    assert _xattr('-p', FINDER_INFO, outside)
    assert json.loads((root / 'owner.json').read_text())['client'] is None
