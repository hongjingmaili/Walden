"""Synthetic CLI/files only; all test writes stay in the supplied pytest basetemp."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

from test_query_result_binding import register_installation, WINDOW, SYNC, REPLY

SOURCE = Path(__file__).resolve().parents[1] / "tools/query_result.py"
spec = importlib.util.spec_from_file_location("query_result_tool", SOURCE)
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)
REAL_REPO = q.REPO_ROOT


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    repo, safe = tmp_path / "synthetic-repo", tmp_path / "safe-temp"
    repo.mkdir(mode=0o700)
    safe.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path.resolve() / "config"))
    monkeypatch.setattr(q, "REPO_ROOT", repo)
    monkeypatch.setattr(q.tempfile, "gettempdir", lambda: str(safe))
    return repo, safe


def payload(n=20):
    return dict(status="ready", source_observed_at="2026-11-10T05:00:00+08:00",
                coverage=dict(status="complete", start="fixture-start", end="fixture-end"),
                identity=dict(status="ok", account="synthetic"), media=dict(status="ready"),
                partition_hashes=[format(i, "064x") for i in range(8)],
                future_metadata=dict(unknown=True), messages=[dict(
                    id=i, timestamp="2026-11-10T05:00:00+08:00", text="原文 " + str(i),
                    sender_username="fixture_" + str(i), direction="outgoing" if i % 2 else "incoming",
                    classification="private", quote=dict(text="引用", attributes=dict(kind="link", title="原题", future=[1, 2])),
                    image=dict(status="ready", parsed=dict(text="图片文字"), path="/synthetic/image.png"),
                    voice=dict(status="ready", transcript="完整转写", playback_url="/synthetic/voice.wav"),
                    future_message_field=dict(nested=["保留", i]), fragment_hashes=["f" * 64]) for i in range(n)])


def stub(tmp_path, data, err=b"", exit_code=0, name="wechat-local-window"):
    tmp_path = tmp_path.resolve()
    counter = tmp_path / (name + "-calls.jsonl")
    raw = data if type(data) is bytes else (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode()
    stdout_file = tmp_path / "fixture-stdout"
    stderr_file = tmp_path / "fixture-stderr"
    stdout_file.write_bytes(raw)
    stderr_file.write_bytes(err)
    code = "#!" + sys.executable + "\nimport os,sys,json\nfrom pathlib import Path\n"
    code += "assert 'PYTHONPATH' not in os.environ and 'PYTHONHOME' not in os.environ\n"
    code += "fd=os.open(" + repr(str(counter)) + ",os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)\n"
    code += "os.write(fd,(json.dumps(sys.argv[1:])+'\\n').encode());os.close(fd)\n"
    code += f"os.write(1,Path({str(stdout_file)!r}).read_bytes());os.write(2,Path({str(stderr_file)!r}).read_bytes())\n"
    code += "os.kill(os.getpid(),15)\n" if exit_code == -15 else f"raise SystemExit({exit_code})\n"
    _, path = register_installation(tmp_path, q.config_root().parent, name,
                                    {entry: code.encode() for entry in (WINDOW, SYNC, REPLY)})
    return path, counter, raw


def bound_argv(argv):
    if any(arg.partition("=")[0] == "--source-config" for arg in argv[1:]):
        return argv
    return [*argv, "--source-config", str(q.current_source_config())]


def capture(argv, *args):
    return q.capture(bound_argv(argv), *args)


def test_twenty_complete_messages_and_private_byte_exact_copy(tmp_path, monkeypatch, sandbox):
    original = payload()
    cli, counter, raw = stub(tmp_path, original, b"diagnostic\n")
    monkeypatch.setenv("PYTHONPATH", "/forbidden/source")
    argv = [str(cli), "--latest", "20", "--configured-images", "--voice-transcripts"]
    record = capture(argv)
    view, code = q.page(record)
    assert code == 0 and view["original_exit"] == 0 and view["business_status"] == "ready"
    assert (view["total_messages"], view["start"], view["end"], view["remaining"], view["messages_displayed"]) == (20, 1, 20, 0, 20)
    assert view["messages"] == original["messages"]  # Every nested/unknown/message hash field survives.
    assert view["context"]["coverage"] == original["coverage"]
    assert view["context"]["identity"] == original["identity"] and view["context"]["media"] == original["media"]
    assert view["context"]["source_observed_at"] == original["source_observed_at"]
    assert view["context"]["future_metadata"] == original["future_metadata"]
    assert "partition_hashes" not in view["context"] and view["omitted_metadata_keys"] == ["partition_hashes"]
    assert (record.parent / "stdout.bin").read_bytes() == raw
    assert (record.parent / "stderr.bin").read_bytes() == b"diagnostic\n" and view["stderr"] == "diagnostic\n"
    expected = [*bound_argv(argv), "--read-mode", "local"]
    assert json.loads(counter.read_text()) == expected[1:]
    assert json.loads(record.read_text())["argv"] == expected
    assert stat.S_IMODE(record.parent.stat().st_mode) == 0o700
    for f in record.parent.iterdir():
        assert stat.S_IMODE(f.stat().st_mode) == 0o600 and f.stat().st_nlink == 1 and f.stat().st_uid == os.getuid()


def test_message_pages_and_new_runs_never_implicitly_reuse(tmp_path, sandbox):
    original = payload(45)
    cli, counter, _ = stub(tmp_path, original)
    first = capture([str(cli)])
    assert q.page(first)[0]["remaining"] == 25
    assert q.page(first, 21, 20)[0]["messages"] == original["messages"][20:40]
    assert q.page(first, 41, 20)[0]["messages"] == original["messages"][40:]
    assert len(counter.read_text().splitlines()) == 1
    second = capture([str(cli)])
    assert first.parent != second.parent and len(counter.read_text().splitlines()) == 2


@pytest.mark.parametrize("problem", ["business", "nested", "identity", "coverage", "media", "error", "cli"])
def test_failures_and_observations_cannot_turn_into_success(tmp_path, sandbox, problem):
    data = payload(1)
    code = 0
    if problem == "business": data["status"] = "failed"
    elif problem == "nested": data["body"] = dict(status="failed")
    elif problem == "identity": data["identity_conflicts"] = [dict(expected="a", observed="b")]
    elif problem == "coverage": data["coverage"] = dict(status="incomplete", gaps=["missing interval"])
    elif problem == "media": data["messages"][0]["voice"]["status"] = "capture_failed"
    elif problem == "error": data["error"] = "fixture failure"
    else: code = 7
    cli, counter, raw = stub(tmp_path, data, b"complete error evidence\n", code)
    record = capture([str(cli)])
    view, wrapper = q.page(record)
    assert wrapper == (7 if code else 2) and view["original_exit"] == code
    assert view["outcome"] == "cli_failed" and view["stderr"] == "complete error evidence\n"
    assert view["messages"] == data["messages"] and view["context"]["source_observed_at"] == data["source_observed_at"]
    assert (record.parent / "stdout.bin").read_bytes() == raw and len(counter.read_text().splitlines()) == 1


@pytest.mark.parametrize("raw", [b"not JSON\n", b'{"status":"ready","status":"failed","messages":[]}', b"{\"x\":NaN}", b"\xff\x00", b'{"messages":[{"future":1.234567890123456789}],"status":"ready"}', b'{"messages":[],"x":1e400}', b'{"messages":[{"text":"\\ud800"}]}'])
def test_invalid_ambiguous_and_binary_stdout_is_explicit_raw_fallback(tmp_path, sandbox, raw):
    cli, counter, _ = stub(tmp_path, raw, b"parse diagnostic\n")
    record = capture([str(cli)])
    view, code = q.page(record)
    assert code == 2 and view["original_exit"] == 0 and view["display"] == "raw_chunk_required"
    chunk = q.page(record, raw="stdout")[0]["chunk"]
    restored = base64.b64decode(chunk["data_base64"]) if chunk["unit"] == "bytes_base64" else chunk["text"].encode()
    assert restored == raw and view["stderr"] == "parse diagnostic\n"
    assert len(counter.read_text().splitlines()) == 1


def test_long_message_and_stderr_chunks_without_query_or_silent_truncation(tmp_path, sandbox):
    data = payload(1)
    data["messages"][0]["text"] = "完整长消息🙂" * 6000
    cli, counter, raw = stub(tmp_path, data, b"x" * 12000)
    record = capture([str(cli)])
    view, code = q.page(record)
    assert code == 0 and view["display"] == "raw_chunk_required" and view["messages_displayed"] == 0
    assert view["total_messages"] == 1 and view["remaining"] == 1 and "messages" not in view
    assert view["stderr_requires_raw_chunk"] is True
    text = raw.decode()
    pieces = [q.page(record, raw="stdout", offset=i, length=4000)[0]["chunk"]["text"] for i in range(0, len(text), 4000)]
    assert "".join(pieces) == text
    assert q.page(record, raw="stderr", offset=8000, length=4000)[0]["chunk"]["text"] == "x" * 4000
    assert len(counter.read_text().splitlines()) == 1


@pytest.mark.parametrize("unknown", [dict(other=[1, 2]), dict(messages=[], body=dict(messages=[])), dict(status={"future": "keep"}), dict(status=["future"])])
def test_unknown_or_ambiguous_schema_keeps_raw_and_unknown_hash_shapes(tmp_path, sandbox, unknown):
    unknown["partition_hashes"] = dict(status="failed", unexpected="must not hide")
    cli, counter, raw = stub(tmp_path, unknown)
    record = capture([str(cli)])
    view, code = q.page(record)
    assert view["display"] == "raw_chunk_required" and code == 2
    assert q.page(record, raw="stdout")[0]["chunk"]["text"].encode() == raw
    assert len(counter.read_text().splitlines()) == 1


@pytest.mark.parametrize("bad", ["mode", "parent", "symlink", "parent_symlink", "hardlink", "tamper", "uid"])
def test_page_rejects_unsafe_or_changed_copies(tmp_path, monkeypatch, sandbox, bad):
    cli, _, _ = stub(tmp_path, payload(1))
    record = capture([str(cli)])
    path = record
    if bad == "mode": record.chmod(0o644)
    elif bad == "parent": record.parent.chmod(0o755)
    elif bad == "symlink": path = record.parent / "alias.json"; path.symlink_to(record)
    elif bad == "parent_symlink":
        alias = sandbox[1] / "alias"; alias.symlink_to(record.parent, target_is_directory=True); path = alias / record.name
    elif bad == "hardlink": os.link(record, record.parent / "other.json")
    elif bad == "tamper": (record.parent / "stdout.bin").write_bytes(b"foreign")
    else:
        uid = os.getuid(); monkeypatch.setattr(q.os, "getuid", lambda: uid + 1)
    with pytest.raises((q.Refusal, OSError)):
        q.page(path)


def test_repo_temp_and_existing_directory_refuse_before_cli(tmp_path, sandbox):
    cli, counter, _ = stub(tmp_path, payload(1))
    with pytest.raises(q.Refusal): q.new_directory(REAL_REPO / "never-query-copy")
    existing = sandbox[1] / "existing"; existing.mkdir(mode=0o700)
    sentinel = existing / "sentinel"; sentinel.write_bytes(b"keep")
    with pytest.raises(FileExistsError): capture([str(cli)], existing)
    assert sentinel.read_bytes() == b"keep" and not counter.exists()


@pytest.mark.parametrize("args", [["--authorize-copy"], ["--refresh"], ["--refresh-auxiliary"], ["--read-mode", "refresh"], ["--read-mode=refresh"], ["--author"], ["--authorize-c"], ["--refresh-aux"], ["--read-m", "refresh"]])
def test_no_capture_refresh_or_added_authority(tmp_path, sandbox, args):
    cli, counter, _ = stub(tmp_path, payload())
    with pytest.raises(q.Refusal): capture([str(cli)] + args)
    assert not counter.exists() and list(sandbox[1].iterdir()) == []


def test_sync_read_only_allowlist_and_no_arbitrary_launcher(tmp_path, sandbox):
    cli, counter, _ = stub(tmp_path, payload(0), name="wechat-local-sync")
    capture([str(cli), "request-status", "--request-record", str(tmp_path / "fixture-request.json")])
    with pytest.raises(q.Refusal): capture([str(cli), "status"])
    capture([str(cli), "request", "--contact-query", "fixture", "--latest", "20"])
    with pytest.raises(q.Refusal): capture([str(cli), "follow-enable"])
    with pytest.raises(q.Refusal): capture(["/bin/sh", "-c", "echo unsafe"])
    assert len(counter.read_text().splitlines()) == 2


def test_cli_integration_only_explicit_same_copy_pages(tmp_path, sandbox):
    repo, safe = sandbox
    (repo / "tools").mkdir(mode=0o700)
    script = repo / "tools/query_result.py"; script.write_bytes(SOURCE.read_bytes())
    cli, counter, _ = stub(tmp_path, dict(status="failed", messages=[dict(text="完整错误结果")]), b"original stderr\n")
    env = dict(os.environ, TMPDIR=str(safe), PYTHONDONTWRITEBYTECODE="1")
    first = subprocess.run([sys.executable, "-B", str(script), "run", "--", *bound_argv([str(cli)])], env=env, capture_output=True, text=True)
    assert first.returncode == 2
    result = json.loads(first.stdout)
    second = subprocess.run([sys.executable, "-B", str(script), "page", "--result-file", result["result_file"]], env=env, capture_output=True, text=True)
    assert second.returncode == 2 and json.loads(second.stdout)["original_exit"] == 0
    assert json.loads(second.stdout)["messages"] == [dict(text="完整错误结果")]
    assert len(counter.read_text().splitlines()) == 1


@pytest.mark.parametrize("path", q.MESSAGE_PATHS)
def test_each_supported_container_keeps_all_other_fields(tmp_path, sandbox, path):
    original = payload(2)
    messages = original.pop("messages")
    cursor = original
    for key in path[:-1]:
        cursor[key] = dict(status="ready", future_container_field="retain")
        cursor = cursor[key]
    cursor[path[-1]] = messages
    cli, counter, raw = stub(tmp_path, original)
    view, code = q.page(capture([str(cli)]))
    assert code == 0 and view["messages"] == messages and view["total_messages"] == 2
    assert (Path(view["stdout_file"])).read_bytes() == raw
    assert len(counter.read_text().splitlines()) == 1


def test_unknown_hash_metadata_shape_is_not_removed(tmp_path, sandbox):
    original = payload(1)
    original["partition_hashes"] = dict(status="failed", future=["retain"])
    cli, _, _ = stub(tmp_path, original)
    view, code = q.page(capture([str(cli)]))
    assert code == 2 and view["context"]["partition_hashes"] == original["partition_hashes"]
    assert view["omitted_metadata_keys"] == []


def test_signal_exit_preserves_original_and_reports_actual_wrapper_exit(tmp_path, sandbox):
    cli, counter, _ = stub(tmp_path, payload(1), exit_code=-15)
    record = capture([str(cli)])
    view, code = q.page(record)
    assert view["original_exit"] == -15 and view["wrapper_exit"] == code == 143
    assert view["outcome"] == "cli_failed" and len(counter.read_text().splitlines()) == 1


def native_payload(shape, dense=False):
    import copy
    messages = payload(20)["messages"]
    for index, message in enumerate(messages):
        if not dense:
            for field, owner in (("quote", 0), ("image", 1), ("voice", 2)):
                if index != owner:
                    message.pop(field)
        message["source"] = dict(source_header_sha256="b" * 64, source_identity=[10, index], unknown_source="keep")
    coverage = dict(atomic_global_snapshot=False,
                    binding=["fixture-account", "generation", "alice", dict(kind="latest", limit=20)],
                    complete=True, shards={"message_" + str(i) + ".db": dict(
                        checked_at=123, complete=True, present=True, members=list(range(1, 502)),
                        source_header_sha256="a" * 64, source_identity=[1, i + 1], unknown_shard="keep") for i in range(12)},
                    unknown_coverage=dict(keep=True))
    coverage["shards"]["future-format"] = dict(checked_at=None, complete=False, present=False,
        members=[dict(future=1)], source_identity=[True, 2], source_header_sha256=dict(future="keep"), reason="future format")
    progress = dict(unknown=True, source_header_sha256="c" * 64, members=[1, 2], source_identity=[3, 4])
    inner = dict(selected_username="alice", messages=messages, coverage=copy.deepcopy(coverage),
                 synced_at_semantics="fixture-complete-observation", last_attempt_at=123,
                 last_complete_observation_at=120, synced_at=120, freshness=dict(observed_at=120),
                 gaps=[], source_opens=0, parse_seconds=0.25, elapsed_seconds=0.5,
                 media_completion=dict(status="ready", unknown=True), body_status="ready", media_work_pending=False,
                 request_range=dict(status="request_window_covered", window=dict(kind="latest", limit=20),
                                    atomic_global_snapshot=False, as_of=dict(message_0=120)), future_result=dict(keep=True))
    inner["coverage"]["history_progress"] = progress
    if shape == "flat":
        return dict(inner, status="ready", source_opened=False)
    if shape == "history-only":
        inner["coverage"] = dict(history_progress=progress, unknown_coverage=True)
    return dict(status="ready", body_status="ready", coverage=coverage, result=inner,
                source_opened=False, future_outer=dict(reason="keep"))


@pytest.mark.parametrize("shape", ["nested", "flat", "history-only"])
def test_native_shape_compacts_only_known_shard_fields(tmp_path, sandbox, shape):
    data = native_payload(shape)
    cli, counter, raw = stub(tmp_path, data)
    record = capture([str(cli)])
    original = (record.parent / "stdout.bin").read_bytes()
    view, code = q.page(record)
    body = data if shape == "flat" else data["result"]
    shown = view["context"] if shape == "flat" else view["context"]["result"]
    assert code == 0 and view["display"] == "messages" and view["messages"] == body["messages"]
    assert (view["total_messages"], view["messages_displayed"], view["remaining"]) == (20, 20, 0)
    assert len(q.encode(view)) <= q.DISPLAY_LIMIT
    for key, value in body.items():
        if key not in {"messages", "coverage"}: assert shown[key] == value
    assert shown["coverage"]["history_progress"] == body["coverage"]["history_progress"]
    coverage_pairs = [(shown["coverage"], body["coverage"])]
    if shape != "flat":
        coverage_pairs.append((view["context"]["coverage"], data["coverage"]))
        assert view["context"]["source_opened"] is False and view["context"]["future_outer"] == data["future_outer"]
    for projected, full in coverage_pairs:
        for key, value in full.items():
            if key != "shards": assert projected[key] == value
        if "shards" not in full: continue
        assert projected["shards"]["future-format"] == full["shards"]["future-format"]
        for name, row in full["shards"].items():
            if name == "future-format": continue
            assert projected["shards"][name] == {k: v for k, v in row.items() if k not in {"members", "source_header_sha256", "source_identity"}}
    for group in view["coverage_omissions"]:
        assert group["path"] in [["coverage", "shards"], ["result", "coverage", "shards"]]
        assert set(group["fields"]) == {"members", "source_header_sha256", "source_identity"}
        for names in group["fields"].values():
            assert len(names) == 12 and "future-format" not in names
        assert set(group["member_counts"].values()) == {501}
    assert (record.parent / "stdout.bin").read_bytes() == original == raw
    assert q.page(record, raw="stdout", length=1000)[0]["chunk"]["text"] == raw.decode()[:1000]
    assert len(counter.read_text().splitlines()) == 1


@pytest.mark.parametrize("data", [dict(status="failed", reason="fixture", source_opened=False),
    dict(status="needs_target_copy", reason="outside mirror", source_opened=False),
    dict(status="ready", body_status="needs_target_copy", reason="not captured", result=None, source_opened=False)])
def test_status_only_envelopes_preserve_all_context(tmp_path, sandbox, data):
    data = dict(data, coverage=dict(complete=False), future_field=dict(keep=True))
    cli, counter, raw = stub(tmp_path, data)
    record = capture([str(cli)])
    view, code = q.page(record)
    assert code == 2 and view["display"] == "status" and view["context"] == data
    assert view["total_messages"] is None and view["messages_displayed"] == 0 and "messages" not in view
    assert (record.parent / "stdout.bin").read_bytes() == raw and len(counter.read_text().splitlines()) == 1


@pytest.mark.parametrize("mode", [None, "stdout", "stderr"])
def test_many_media_failures_have_bounded_samples_and_all_original_evidence(tmp_path, sandbox, mode):
    messages = [dict(text="保留" + str(i), voice=dict(status="capture_failed"), future_field=True) for i in range(1000)]
    data = dict(status="failed", messages=messages)
    cli, counter, raw = stub(tmp_path, data, b"full diagnostic\n" * 1000)
    record = capture([str(cli)])
    view, code = q.page(record, raw=mode)
    assert code == 2 and len(q.encode(view)) <= q.DISPLAY_LIMIT
    assert view["issues_total"] == 1001 and len(view["issues"]) <= 20
    assert view["issues_omitted"] == 1001 - len(view["issues"]) and view["issues_raw_hint"]
    if mode is None:
        assert view["messages"] == messages[:20] and view["total_messages"] == 1000 and view["remaining"] == 980
    assert q.page(record, 21, 20)[0]["messages"] == messages[20:40]
    assert (record.parent / "stdout.bin").read_bytes() == raw and len(counter.read_text().splitlines()) == 1


@pytest.mark.parametrize("mode", [None, "stdout"])
def test_unknown_long_header_fields_cannot_overflow_any_page(tmp_path, sandbox, mode):
    data = dict(status="very_long_" * 10000 + "_failed", messages=[dict(text="keep")])
    cli, counter, raw = stub(tmp_path, data)
    record = capture([str(cli)])
    saved = json.loads(record.read_text())
    saved.update(spawn_error="future_error_" * 10000, captured_at="unknown_time_" * 10000)
    record.write_text(json.dumps(saved))  # Synthetic private record; no real user file.
    view, code = q.page(record, raw=mode)
    assert code == 2 and len(q.encode(view)) <= q.DISPLAY_LIMIT
    assert view["business_status"] is None and view["spawn_error"] is None
    assert view["omitted_header_fields"]["business_status"] == "stdout_file"
    assert view["omitted_header_fields"]["spawn_error"] == "result_file"
    assert view["issues_total"] == 2 and view["issues_omitted"] == 2
    assert (record.parent / "stdout.bin").read_bytes() == raw and len(counter.read_text().splitlines()) == 1


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_control_character_raw_chunks_are_explicitly_bounded_and_contiguous(tmp_path, sandbox, stream):
    original = b"\0" * 16000
    cli, counter, _ = stub(tmp_path, original, original)
    record = capture([str(cli)])
    pieces, offset = [], 0
    while offset < len(original):
        view, code = q.page(record, raw=stream, offset=offset, length=8000)
        assert code == 2 and len(q.encode(view)) <= q.DISPLAY_LIMIT
        chunk = view["chunk"]
        assert chunk["offset"] == offset and chunk["end"] > offset
        assert chunk["requested_length"] == 8000
        if len(chunk["text"]) < min(8000, len(original) - offset): assert chunk["adjusted_for_display_limit"]
        pieces.append(chunk["text"])
        offset = chunk["end"]
    assert "".join(pieces).encode() == original
    assert (record.parent / (stream + ".bin")).read_bytes() == original
    assert len(counter.read_text().splitlines()) == 1


def test_dense_twenty_messages_keep_explicit_raw_fallback_instead_of_clipping(tmp_path, sandbox):
    data = native_payload("nested", dense=True)
    cli, counter, raw = stub(tmp_path, data)
    record = capture([str(cli)])
    view, code = q.page(record)
    assert code == 0 and view["display"] == "raw_chunk_required" and "messages" not in view
    assert view["total_messages"] == view["remaining"] == 20 and view["messages_displayed"] == 0
    assert len(q.encode(view)) <= q.DISPLAY_LIMIT
    assert (record.parent / "stdout.bin").read_bytes() == raw
    assert q.page(record, raw="stdout", length=1000)[0]["chunk"]["text"] == raw.decode()[:1000]
    assert len(counter.read_text().splitlines()) == 1


@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("field,value", [("source_identity", [-1, 2]), ("members", [0]), ("members", [-1])])
def test_native_coverage_invalid_ranges_remain_visible(nested, field, value):
    import copy
    row = dict(source_header_sha256="a" * 64, source_identity=[1, 2], members=[1, 2], present=True, unknown="keep")
    row[field] = value
    body = dict(messages=[dict(text="whole", source=dict(source_identity=[-1, 2], members=[0]))],
                coverage=dict(shards={"message.db": row}))
    data = dict(status="ready", result=body) if nested else dict(body, status="ready")
    before = copy.deepcopy(data)
    messages, context, omitted, coverage = q.messages_and_context(data)
    shown = context["result"] if nested else context
    assert shown["coverage"]["shards"]["message.db"][field] == value
    assert shown["coverage"]["shards"]["message.db"]["unknown"] == "keep"
    assert messages == body["messages"] and data == before
    assert context["status"] == data["status"]
    assert all("message.db" not in group["fields"].get(field, []) for group in coverage)


def test_native_coverage_zero_identity_and_empty_members_are_legal():
    row = dict(source_identity=[0, 0], members=[], present=True)
    data = dict(status="ready", messages=[dict(text="whole")], coverage=dict(shards={"message.db": row}))
    messages, context, omitted, coverage = q.messages_and_context(data)
    assert context["coverage"]["shards"]["message.db"] == dict(present=True)
    assert coverage[0]["fields"]["source_identity"] == ["message.db"]
    assert coverage[0]["fields"]["members"] == ["message.db"]
    assert coverage[0]["member_counts"] == {"message.db": 0}
    assert messages == data["messages"] and row == dict(source_identity=[0, 0], members=[], present=True)


def raw_text_message(kind="image"):
    return dict(sender_username="fixture", direction="inbound", classification="private",
        text=None, content=dict(kind=kind, text=None, attributes=dict(unknown="keep", raw_text="nested field stays"),
            raw_text='<msg><img aeskey="FAKE_ATTACHMENT_KEY">' + "x" * 5000 + '</img></msg>', other_xml="<keep/>"),
        image=dict(status="decoded", media_status="ready", representations=[dict(status="decoded", path="/synthetic/image.png", unknown="keep")], missing_resource_sizes=[]),
        voice=dict(status="ready", transcript=dict(status="ready", text="完整转写", unknown="keep"),
                   audio=dict(status="ready", local_path="/synthetic/audio.wav", content_type="audio/wav")),
        source=dict(content_sha256="a" * 64), future_message=dict(raw_text="outer nested stays"))


@pytest.mark.parametrize("variant", ["image", "partial_image", "text", "quote", "audio_transcript", "audio_wav"])
def test_raw_text_known_representation_projects_only_the_one_field(variant):
    import copy
    message = raw_text_message()
    if variant == "partial_image":
        message["image"].update(status="partial", media_status="failed", reason="one missing", missing_resource_sizes=[123])
        message["image"]["representations"].append(dict(status="unavailable", reason="missing"))
    elif variant == "text":
        message["content"].update(kind="text", text="exact text", raw_text="exact text")
        message["text"] = "exact text"
    elif variant == "quote":
        message["content"].update(kind="quote", attributes=dict(title="回复原文", referenced_text="引用原文", referenced_actor_label="姓名", referenced_type="1", unknown=dict(raw_text="keep")))
    elif variant.startswith("audio"):
        message["content"]["kind"] = "audio"
        if variant == "audio_wav": message["voice"]["transcript"] = dict(status="pending", text=None)
        else: message["voice"]["audio"] = dict(status="failed", reason="audio missing")
    before = copy.deepcopy(message)
    shown, omitted = q.project_message_slice([message], 7)
    expected = copy.deepcopy(before)
    del expected["content"]["raw_text"]
    assert shown == [expected] and message == before
    assert shown[0] is not message and shown[0]["content"] is not message["content"]
    assert omitted == [dict(message_index=7, path=["content", "raw_text"], kind=message["content"]["kind"])]


@pytest.mark.parametrize("variant", ["unknown", "voice_alias", "only_raw", "empty_image", "empty_representations", "empty_image_path", "failed_image", "direct_image_path", "pending_image_path", "text_mismatch", "text_whitespace", "text_empty", "text_top_mismatch", "quote_no_title", "quote_no_reference", "quote_empty_reference", "audio_no_transcript", "audio_empty_transcript", "audio_saved_silk", "audio_empty_path"])
def test_raw_text_unknown_empty_or_insufficient_representation_is_retained(variant):
    import copy
    message = raw_text_message()
    content = message["content"]
    if variant == "unknown": content["kind"] = "future"
    elif variant == "voice_alias": content["kind"] = "voice"
    elif variant == "only_raw": message = dict(content=dict(kind="image", raw_text=content["raw_text"]))
    elif variant == "empty_image": message["image"] = {}
    elif variant == "empty_representations": message["image"]["representations"] = []
    elif variant == "empty_image_path": message["image"]["representations"][0]["path"] = " "
    elif variant == "failed_image": message["image"]["status"] = "unavailable"
    elif variant == "direct_image_path": message["image"] = dict(status="decoded", path="/synthetic/unknown-layout.png")
    elif variant == "pending_image_path": message["image"]["representations"][0]["status"] = "pending"
    elif variant.startswith("text"):
        content.update(kind="text", text="visible", raw_text="different")
        if variant == "text_whitespace": content.update(text="visible", raw_text="visible ")
        if variant == "text_empty": content.update(text="", raw_text="")
        if variant == "text_top_mismatch": content.update(text="visible", raw_text="visible"); message["text"] = "other"
    elif variant.startswith("quote"):
        content.update(kind="quote", attributes=dict(title="回复", referenced_text="引用"))
        if variant == "quote_no_title": content["attributes"].pop("title")
        elif variant == "quote_no_reference": content["attributes"].pop("referenced_text")
        else: content["attributes"]["referenced_text"] = " "
    else:
        content["kind"] = "audio"
        message["voice"] = dict(status="pending", transcript=dict(status="pending", text=None), audio={})
        if variant == "audio_empty_transcript": message["voice"]["transcript"] = dict(status="ready", text=" ")
        if variant == "audio_saved_silk": message["voice"]["audio"] = dict(status="saved", local_path="/synthetic/audio.silk", content_type="audio/silk")
        if variant == "audio_empty_path": message["voice"]["audio"] = dict(status="ready", local_path="", content_type="audio/wav")
    before = copy.deepcopy(message)
    shown, omitted = q.project_message_slice([message], 1)
    assert shown == [before] and message == before and omitted == []


@pytest.mark.parametrize("nested", [False, True])
def test_raw_text_five_images_fit_and_all_pages_use_global_indices(tmp_path, sandbox, nested):
    messages = [dict(raw_text_message(), local_id=i) for i in range(5)]
    body = dict(messages=messages)
    data = dict(status="ready", result=body) if nested else dict(status="ready", **body)
    cli, counter, raw = stub(tmp_path, data, b"original stderr\n")
    record = capture([str(cli)])
    saved = {name: (record.parent / name).read_bytes() for name in ("result.json", "stdout.bin", "stderr.bin")}
    view, code = q.page(record)
    assert code == 0 and view["display"] == "messages" and view["messages_displayed"] == 5
    assert (view["total_messages"], view["start"], view["end"], view["remaining"]) == (5, 1, 5, 0)
    assert "FAKE_ATTACHMENT_KEY" not in q.encode(view).decode()
    assert len(q.encode(view)) <= q.DISPLAY_LIMIT
    assert [row["message_index"] for row in view["message_omissions"]] == [1, 2, 3, 4, 5]
    collected = []
    for start in (1, 3, 5):
        part, _ = q.page(record, start, 2)
        collected.extend(part["messages"])
        assert [row["message_index"] for row in part["message_omissions"]] == list(range(start, part["end"] + 1))
        assert all(row["path"] == ["content", "raw_text"] for row in part["message_omissions"])
    assert collected == view["messages"]
    text, offset, pieces = raw.decode(), 0, []
    while offset < len(text):
        chunk = q.page(record, raw="stdout", offset=offset, length=8000)[0]["chunk"]
        pieces.append(chunk["text"]); offset = chunk["end"]
    assert "".join(pieces).encode() == raw
    assert all((record.parent / name).read_bytes() == value for name, value in saved.items())
    assert len(counter.read_text().splitlines()) == 1


@pytest.mark.parametrize("variant", ["unknown", "empty_image", "long_text"])
def test_raw_text_fallback_does_not_claim_displayed_omissions(tmp_path, sandbox, variant):
    message = raw_text_message()
    if variant == "unknown": message["content"]["kind"] = "future"
    elif variant == "empty_image": message["image"] = {}
    else:
        text = "完整长文" * 10000
        message["text"] = text
        message["content"].update(kind="text", text=text, raw_text=text)
    if variant != "long_text": message["content"]["raw_text"] *= 6
    cli, counter, raw = stub(tmp_path, dict(status="ready", messages=[message]))
    record = capture([str(cli)])
    view, _ = q.page(record)
    assert view["display"] == "raw_chunk_required" and view["messages_displayed"] == 0
    assert "message_omissions" not in view and "messages" not in view
    assert (record.parent / "stdout.bin").read_bytes() == raw and len(counter.read_text().splitlines()) == 1


def test_raw_text_audio_projection_preserves_failure_and_every_media_field(tmp_path, sandbox):
    message = raw_text_message("audio")
    message["voice"].update(status="capture_failed", reason="saved native transcript only")
    message["voice"]["audio"] = dict(status="failed", reason="no playback", future="keep")
    cli, counter, raw = stub(tmp_path, dict(status="ready", messages=[message]))
    record = capture([str(cli)])
    view, code = q.page(record)
    assert code == 2 and view["messages"][0]["voice"] == message["voice"]
    assert "raw_text" not in view["messages"][0]["content"]
    assert view["message_omissions"][0]["message_index"] == 1
    assert (record.parent / "stdout.bin").read_bytes() == raw and len(counter.read_text().splitlines()) == 1


# ---------------------------------------------------------------- A1–A4 query-chain supplement
def test_a1_source_opened_rejected_end_to_end(tmp_path, sandbox):
    """A1: a result that reports it opened/touched the live source is refused (real guard)."""
    data = payload(1); data["source_opened"] = True
    cli, _, _ = stub(tmp_path, data)
    with pytest.raises(q.Refusal):
        q.page(capture([str(cli)]))


def test_a3_scope_source_conflict_classified_and_escalated(tmp_path, sandbox):
    """A3: a source/identity conflict surfaces structured classification + escalate, no
    generic throw; the existing structured-failure behavior (code 2) is preserved."""
    data = payload(1); data["source_conflicts"] = [dict(expected="a", observed="b")]
    cli, _, _ = stub(tmp_path, data)
    view, code = q.page(capture([str(cli)]))
    assert view["cli_error_classification"]["category"] == "scope_source_conflict"
    assert view["escalate"] is True and view["need_user_clarification"] is False
    assert code == 2 and view["outcome"] == "cli_failed"


@pytest.mark.parametrize("range_reason", [
    "observation_evidence_missing",
    "account_recent_vector_not_proven",
    "requested_order_not_observed",
    "requested_time_outside_observation",
    "requested_page_exceeds_recent_observation",
])
def test_formal_local_result_preserves_optional_unknown_metadata_as_success(tmp_path, sandbox, range_reason):
    messages = [dict(text="synthetic", source_facts=dict(
        mentions=dict(status="unknown", at_self="unknown", notify_all="unknown")))]
    coverage = dict(history_complete=True, request_range=dict(
        status="unknown", reason=range_reason, as_of=None))
    data = dict(messages=messages, coverage=coverage, source_opens=0, gaps=[], freshness="local_snapshot")
    cli, _, _ = stub(tmp_path, data)
    if range_reason in {"requested_order_not_observed", "requested_time_outside_observation"}:
        request = ["--request", "2020-01-15到2020-01-15", "--timezone", "Asia/Shanghai"]
    else:
        request = ["--latest", "20"]
    view, code = q.page(capture([str(cli), *request]))

    assert code == 0
    assert view["outcome"] == "cli_returned" and view["issues"] == []
    assert view["messages"] == messages
    assert view["context"]["coverage"] == coverage


@pytest.mark.parametrize("failure", ["gap", "mention_failure", "range_conflict", "other_unknown", "command_exit"])
def test_optional_unknown_metadata_does_not_hide_other_failures(tmp_path, sandbox, failure):
    mentions = dict(status="unknown")
    request_range = dict(status="unknown", reason="account_recent_vector_not_proven", as_of=None)
    data = dict(messages=[dict(text="synthetic", source_facts=dict(mentions=mentions))],
                coverage=dict(history_complete=True, request_range=request_range),
                source_opens=0, gaps=[], freshness="local_snapshot")
    if failure == "gap":
        data["gaps"].append("history_incomplete")
    elif failure == "mention_failure":
        mentions["status"] = "failed"
    elif failure == "range_conflict":
        request_range["reason"] = "conversation_attribution_conflict"
    elif failure == "other_unknown":
        # A key made to look like a known path must not receive its exemption.
        data["messages[0].source_facts.mentions"] = dict(status="unknown")
    cli, _, _ = stub(tmp_path, data, exit_code=1 if failure == "command_exit" else 0)
    view, code = q.page(capture([str(cli)]))
    assert code == (1 if failure == "command_exit" else 2)
    assert view["outcome"] == "cli_failed"
    if failure != "command_exit":
        assert view["issues_total"] == 1
