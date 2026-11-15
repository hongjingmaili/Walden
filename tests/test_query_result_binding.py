"""Synthetic registered-installation fixtures and the capture-time boundary."""
import base64
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "tools" / "query_result.py"
spec = importlib.util.spec_from_file_location("query_result_binding", SOURCE)
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)

WINDOW = "wechat-local-window"
SYNC = "wechat-local-sync"
REPLY = "wechat-local-reply"
ENTRY_POINTS = {
    WINDOW: "wechat_local.native_window:console_main",
    SYNC: "wechat_local.native_mirror_cli:console_main",
    REPLY: "wechat_local.reply_workflow:reply_cli_main",
}


def register_installation(root, xdg, selected, launchers):
    """Write synthetic install metadata for the precise fixture executable bytes."""
    venv = root / "fixture-venv"
    bin_dir = venv / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    runtime = bin_dir / "python"
    if not runtime.is_symlink():
        runtime.symlink_to(sys.executable)
    (venv / "pyvenv.cfg").write_text("synthetic fixture\n", encoding="utf-8")
    dist = venv / "lib/python3.9/site-packages/wechat_local_readonly-0.7.9.dist-info"
    dist.mkdir(parents=True, exist_ok=True)
    (dist / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: wechat-local-readonly\nVersion: 0.7.9\n", encoding="utf-8")
    (dist / "entry_points.txt").write_text(
        "[console_scripts]\n" + "".join(f"{k} = {v}\n" for k, v in ENTRY_POINTS.items()), encoding="utf-8")
    rows = io.StringIO()
    writer = csv.writer(rows)
    for name, data in launchers.items():
        path = bin_dir / name
        data = (b"#!" + os.fsencode(runtime) + b"\n" + data.split(b"\n", 1)[1])
        path.write_bytes(data)
        path.chmod(0o700)
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
        writer.writerow(["../../../bin/" + name, "sha256=" + digest, len(data)])
    (dist / "RECORD").write_text(rows.getvalue(), encoding="utf-8")
    config = xdg / "wechat-local/current-source.json"
    config.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    config.write_text(json.dumps({
        "runtime_python": str(runtime),
        "window_cli": str(bin_dir / WINDOW),
        "reply_cli": str(bin_dir / REPLY),
        "ignore": "SYNTHETIC_SECRET_SENTINEL",
    }), encoding="utf-8")
    config.chmod(0o600)
    return config, bin_dir / selected


@pytest.fixture
def install(tmp_path, monkeypatch):
    tmp_path = tmp_path.resolve()
    xdg = tmp_path / "config"
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    monkeypatch.setattr(q.tempfile, "gettempdir", lambda: str(output))
    counter = tmp_path / "calls"
    body = (f"#!{sys.executable}\nfrom pathlib import Path\nimport sys,json\n"
            f"with Path({str(counter)!r}).open('a') as h: h.write(json.dumps(sys.argv[1:])+'\\n')\n"
            "print('{\"status\":\"ready\",\"messages\":[]}')\n").encode()
    config, window = register_installation(tmp_path, xdg, WINDOW, {
        WINDOW: body, SYNC: body, REPLY: body})
    return config, window, counter


def test_missing_source_refuses_before_execution(install):
    _, window, counter = install
    with pytest.raises(q.Refusal, match="source-config"):
        q.capture([str(window), "--latest"])
    assert not counter.exists()


def test_same_name_outside_installation_refuses(install, tmp_path):
    config, window, counter = install
    fake = tmp_path / WINDOW
    fake.write_bytes(window.read_bytes())
    fake.chmod(0o700)
    with pytest.raises(q.Refusal):
        q.capture([str(fake), "--source-config", str(config), "--latest"])
    assert not counter.exists()


def test_tampered_registered_executable_refuses(install):
    config, window, counter = install
    window.write_bytes(window.read_bytes() + b"# arbitrary replacement\n")
    with pytest.raises(q.Refusal):
        q.capture([str(window), "--source-config", str(config), "--latest"])
    assert not counter.exists()


def test_adjacent_sync_executable_requires_install_record(install):
    config, window, counter = install
    sync = window.with_name(SYNC)
    sync.write_bytes(sync.read_bytes() + b"# arbitrary replacement\n")
    with pytest.raises(q.Refusal):
        q.capture([str(sync), "request", "--source-config", str(config),
                   "--contact-query", "synthetic", "--latest", "20"])
    assert not counter.exists()


@pytest.mark.parametrize("extras", [
    ["--source-config", "/somewhere/else.json"],
    ["--source-config", "--latest"],
    ["--read-mode", "local", "--read-mode=local"],
    ["--read-m", "local"],
    ["-h"],
    ["--", "--latest"],
    ["--configured-images=refresh"],
    ["--voice-runtime-root", "/arbitrary/root", "--voice-python", "/arbitrary/program"],
])
def test_duplicate_abbreviated_injected_or_unknown_arguments_refuse(install, extras):
    config, window, counter = install
    with pytest.raises(q.Refusal):
        q.capture([str(window), "--source-config", str(config), *extras])
    assert not counter.exists()


def test_missing_current_profile_refuses(install):
    config, window, counter = install
    config.unlink()
    with pytest.raises(q.Refusal):
        q.capture([str(window), "--source-config", str(config)])
    assert not counter.exists()


def test_alternate_profile_rejected_even_with_valid_registered_entry(install):
    config, window, counter = install
    other = config.with_name("alternate.json")
    other.write_bytes(config.read_bytes())
    other.chmod(0o600)
    with pytest.raises(q.Refusal, match="source-config"):
        q.capture([str(window), "--source-config", str(other)])
    assert not counter.exists()


def test_bound_window_forwards_local_mode_once_and_no_profile_values(install):
    config, window, counter = install
    record = q.capture([str(window), "--source-config=" + str(config), "--latest"])
    forwarded = json.loads(counter.read_text())
    index = forwarded.index("--read-mode")
    assert forwarded[index + 1] == "local"
    assert forwarded.count("--read-mode") == 1
    assert forwarded.count("--voice-transcripts") == 1
    assert "SYNTHETIC_SECRET_SENTINEL" not in record.read_text()
    assert q.page(record)[0]["preflight_checks"]["config_sha256_computed"] is True


def test_symlinked_profile_refuses(install):
    config, window, counter = install
    target = config.with_name("moved-profile.json")
    config.rename(target)
    config.symlink_to(target)
    with pytest.raises(q.Refusal):
        q.capture([str(window), "--source-config", str(config), "--latest"])
    assert not counter.exists()


def test_launcher_symlink_refuses_even_when_target_bytes_match(install):
    config, window, counter = install
    target = window.with_name("moved-launcher")
    window.rename(target)
    window.symlink_to(target)
    with pytest.raises((q.Refusal, OSError)):
        q.capture([str(window), "--source-config", str(config), "--latest"])
    assert not counter.exists()


def test_registered_entries_cannot_use_different_installations(install):
    config, window, counter = install
    data = json.loads(config.read_text())
    data["reply_cli"] = "/elsewhere/wechat-local-reply"
    config.write_text(json.dumps(data))
    with pytest.raises(q.Refusal, match="share the installed environment"):
        q.capture([str(window), "--source-config", str(config), "--latest"])
    assert not counter.exists()


def test_profile_change_before_launch_refuses(install, monkeypatch):
    config, window, counter = install
    original = q.new_directory

    def create_and_change(directory):
        output = original(directory)
        profile = json.loads(config.read_text())
        profile["ignore"] = "changed"
        config.write_text(json.dumps(profile))
        return output

    monkeypatch.setattr(q, "new_directory", create_and_change)
    with pytest.raises(q.Refusal, match="changed before execution"):
        q.capture([str(window), "--source-config", str(config), "--latest"])
    assert not counter.exists()
