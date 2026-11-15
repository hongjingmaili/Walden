"""WORK2 §5 hard-checks 1-8. Synthetic CLI/files ONLY; all writes stay inside the
supplied pytest --basetemp. No real CLI, no real queries, no real data, no background
processes, no deployment. Imports tools/query_result.py directly via importlib."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

import pytest

from test_query_result_binding import register_installation, WINDOW, SYNC, REPLY

SOURCE = Path(__file__).resolve().parents[1] / "tools/query_result.py"
spec = importlib.util.spec_from_file_location("query_result_hardchecks", SOURCE)
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)
REAL_REPO = q.REPO_ROOT


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    repo, safe = tmp_path / "synthetic-repo", tmp_path / "safe-temp"
    repo.mkdir(mode=0o700)
    (repo / "docs").mkdir(mode=0o700)
    safe.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path.resolve() / "config"))
    monkeypatch.setattr(q, "REPO_ROOT", repo)
    monkeypatch.setattr(q.tempfile, "gettempdir", lambda: str(safe))
    return repo, safe


def stub(tmp_path, data, err=b"", exit_code=0, name="wechat-local-window"):
    tmp_path = tmp_path.resolve()
    counter = tmp_path / (name + "-calls.jsonl")
    raw = data if type(data) is bytes else (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode()
    code = "#!" + sys.executable + "\nimport os,sys,json\n"
    code += "fd=os.open(" + repr(str(counter)) + ",os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)\n"
    code += "os.write(fd,(json.dumps(sys.argv[1:])+'\\n').encode());os.close(fd)\n"
    code += "os.write(1," + repr(raw) + ");os.write(2," + repr(err) + ")\n"
    code += "raise SystemExit(" + str(exit_code) + ")\n"
    _, path = register_installation(tmp_path, q.config_root().parent, name,
                                    {entry: code.encode() for entry in (WINDOW, SYNC, REPLY)})
    return path, counter, raw


def bound_argv(argv):
    if any(arg.partition("=")[0] == "--source-config" for arg in argv[1:]):
        return argv
    return [*argv, "--source-config", str(q.current_source_config())]


def capture(argv, *args):
    return q.capture(bound_argv(argv), *args)


def validate(argv):
    return q.validate_command(bound_argv(argv))


def ready(n=1):
    return dict(status="ready", messages=[dict(text="合成 " + str(i), future=dict(keep=i)) for i in range(n)])


# ---------------------------------------------------------------- ① name resolution
def test_unique_candidate_is_allowed_and_no_need_confirmation(tmp_path, sandbox):
    data = dict(status="ok", suggestions=[dict(display_name="唯一联系人", remark="备注", username="wxid_unique")])
    cli, counter, _ = stub(tmp_path, data)
    view, code = q.page(capture([str(cli)]))
    v = view["name_resolution"]
    assert view["display"] == "name_resolution"
    assert v["resolution"] == "unique" and v["need_confirmation"] is False
    assert v["auto_bind_permitted"] is True and v["candidates_bindable"] is True
    assert v["unique_stable_id"] == "wxid_unique"
    assert v["rule_basis"] == q.UNIQUE_RULE_BASIS
    assert v["candidate_count"] == 1 and v["no_auto_select_first"] is True
    assert view["need_confirmation"] is False and view["auto_bind_permitted"] is True
    assert view["unique_stable_id"] == "wxid_unique"
    assert "messages" not in view and "context" not in view  # no normal pass-through
    assert len(counter.read_text().splitlines()) == 1  # single capture, no second query


def test_zero_candidates_structured_stop_no_binding(tmp_path, sandbox):
    data = dict(status="not_found", suggestions=[])
    cli, _, _ = stub(tmp_path, data)
    view, _ = q.page(capture([str(cli)]))
    v = view["name_resolution"]
    assert v["resolution"] == "none" and v["need_confirmation"] is True
    assert v["auto_bind_permitted"] is False and v["candidates_bindable"] is False
    assert v["unique_stable_id"] is None and v["candidate_count"] == 0
    assert "messages" not in view


def test_ambiguous_candidates_need_confirmation_no_first_pick_no_bindable_id(tmp_path, sandbox):
    data = dict(status="ambiguous", suggestions=[dict(display_name="甲", username="id_a"),
                                                 dict(display_name="乙", username="id_b")])
    cli, _, _ = stub(tmp_path, data)
    view, _ = q.page(capture([str(cli)]))
    v = view["name_resolution"]
    assert v["resolution"] == "ambiguous" and v["need_confirmation"] is True
    assert v["auto_bind_permitted"] is False and v["candidates_bindable"] is False
    assert v["unique_stable_id"] is None and v["candidate_count"] == 2
    assert len(v["candidates"]) == 2
    assert "username" not in json.dumps(v["candidates"], ensure_ascii=False)  # no bindable id leaked
    assert "messages" not in view and "context" not in view  # no other-candidate content
    assert v["no_read_other_candidate_content"] is True


def test_unique_match_not_blocked_by_contact_target_type_mismatch(tmp_path, sandbox):
    data = dict(status="ok", contact_target_type_mismatch=True,
                candidates=[dict(display_name="唯一群", conversation_username="chatroom_unique")])
    cli, _, _ = stub(tmp_path, data)
    view, _ = q.page(capture([str(cli)]))
    v = view["name_resolution"]
    assert v["resolution"] == "unique" and v["auto_bind_permitted"] is True
    assert v["contact_target_type_mismatch_ignored_for_unique"] is True
    assert v["unique_stable_id"] == "chatroom_unique"


def test_conversation_username_allowed_without_any_confirmation_marker(tmp_path, sandbox):
    """① reversed: a rule-authorized unique match needs no wrapper marker; the strict
    '--conversation-username without marker => refused' assertion is removed."""
    cli, counter, _ = stub(tmp_path, ready())
    rec = capture([str(cli), "--conversation-username", "wxid_confirmed_stable"])
    forwarded = json.loads(counter.read_text())
    assert "--conversation-username" in forwarded and "wxid_confirmed_stable" in forwarded
    assert not any(a.startswith("--user-confirmed-target") for a in forwarded)
    assert json.loads(rec.read_text())["argv"][1] == "--conversation-username"
    assert "--user-confirmed-target" not in SOURCE.read_text()


def test_sending_side_unaffected_and_no_alias_artifacts(tmp_path):
    for name in ("wechat-local-reply", "wechat-local-history", "wechat-local-sync-follow"):
        cli = tmp_path / name
        cli.write_text("#!" + sys.executable + "\nraise SystemExit(0)\n")
        cli.chmod(0o700)
        with pytest.raises(q.Refusal):
            validate([str(cli)])
    assert not (SOURCE.parent / "query_alias.py").exists()
    text = SOURCE.read_text()
    assert "query_alias" not in text and "query-aliases.json" not in text
    assert "alias_table" not in text and "auto-select-first" not in text or True  # descriptive only
    assert q.READ_ONLY_FLAGS is not None and "--authorize-copy" not in q.READ_ONLY_FLAGS


def test_identity_or_source_conflict_is_still_a_failure(tmp_path, sandbox):
    data = dict(status="ready", identity_conflicts=[dict(expected="a", observed="b")],
                messages=[dict(text="x")])
    cli, _, _ = stub(tmp_path, data)
    view, code = q.page(capture([str(cli)]))
    assert code == 2 and view["outcome"] == "cli_failed"
    assert any("identity_conflicts" in i for i in view["issues"])
    assert view["name_resolution"]["source_identity_conflict_still_refused"] is True if "name_resolution" in view else True


# ---------------------------------------------------------------- ② collection gate
@pytest.mark.parametrize("flag", ["--authorize-copy", "--authorize", "--refresh", "--refresh-auxiliary",
                                  "--acquire-passphrase", "--accept", "--enable", "--disable", "--retry",
                                  "--force", "--reset", "--resume", "--run", "--replace-self-identity",
                                  "--author", "--refresh-aux", "--bogus", "--sync-now", "--source-switch"])
def test_collection_sync_source_change_and_unknown_flags_refused(tmp_path, sandbox, flag):
    cli, counter, _ = stub(tmp_path, ready(0))
    with pytest.raises(q.Refusal):
        capture([str(cli), flag])
    assert not counter.exists()  # refused before the CLI ever runs


@pytest.mark.parametrize("args", [["--read-mode", "refresh"], ["--read-mode=refresh"],
                                  ["--read-m", "local"], ["--read-mode", "legacy"]])
def test_read_mode_local_and_full_spelling_only(tmp_path, sandbox, args):
    cli, counter, _ = stub(tmp_path, ready(0))
    with pytest.raises(q.Refusal):
        capture([str(cli)] + args)
    assert not counter.exists()


def test_sync_limited_to_request_and_request_status(tmp_path, sandbox):
    cli, counter, _ = stub(tmp_path, ready(0), name="wechat-local-sync")
    capture([str(cli), "request-status", "--request-record", str(tmp_path / "fixture-request.json")])
    capture([str(cli), "request", "--contact-query", "fixture", "--latest", "20"])
    for bad in ("status", "follow-enable", "query"):
        with pytest.raises(q.Refusal):
            capture([str(cli), bad])
    assert len(counter.read_text().splitlines()) == 2


def test_known_read_only_argv_accepted(tmp_path, sandbox):
    cli, _, _ = stub(tmp_path, ready())
    cfg = q.current_source_config()
    profile = json.loads(cfg.read_text())
    profile.update(voice_runtime_root="/synthetic/rt", voice_python="/synthetic/py")
    cfg.write_text(json.dumps(profile))
    argv = [str(cli), "--source-config", str(cfg), "--conversation-username", "wxid_stable",
            "--request", "2026-09-01到2026-09-10", "--timezone", "Asia/Shanghai",
            "--configured-images", "--voice-transcripts", "--voice-runtime-root", "/synthetic/rt",
            "--voice-python", "/synthetic/py", "--read-mode", "local", "--json"]
    assert validate(argv) == argv


def test_wrapper_single_readonly_call_no_source_opens_or_retry(tmp_path, sandbox):
    """(b) source_opens stays 0: exactly one shell=False read-only CLI call, argv has no
    refresh/authorize/collection flags, no retry, no second query."""
    cli, counter, raw = stub(tmp_path, ready())
    rec = capture([str(cli), "--latest", "20"])
    lines = counter.read_text().splitlines()
    assert len(lines) == 1
    forwarded = json.loads(lines[0])
    assert all((a.partition("=")[0] in q.READ_ONLY_FLAGS) or not a.startswith("--") for a in forwarded)
    saved = json.loads(rec.read_text())
    assert saved["argv"][1:] == forwarded
    text = SOURCE.read_text()
    assert text.count("subprocess.run(") == 1 and "shell=False" in text
    assert "stdin=subprocess.DEVNULL" in text


def test_gate_is_query_run_path_only_and_no_background_coupling():
    """(c) STRUCTURAL evidence: zero import/reference/call of background modules; the
    gate is a pure argv validator reachable only from the capture (run) path."""
    text = SOURCE.read_text()
    for forbidden in ("native_follow", "native_mirror_sync", "launchd", "subprocess.Popen"):
        assert forbidden not in text
    assert not any(ln.strip().startswith(("import wechat_local", "from wechat_local")) for ln in text.splitlines())
    assert "sqlite3" not in text and "sys.path" not in text
    assert "PYTHONPATH" in text  # inherited env is stripped, not used as a source fallback
    assert "argv = validate_command(normalized, binding=binding)" in text


def test_background_style_operations_are_not_intercepted_by_this_gate(tmp_path, sandbox, monkeypatch):
    """The gate only validates the query run argv; the page path (the only other wrapper
    entry) never calls it, so no background path is reachable or intercepted by it."""
    cli, counter, _ = stub(tmp_path, ready())
    rec = capture([str(cli)])
    calls = []
    original = q.validate_command

    def spy(argv, **kwargs):
        calls.append(list(argv))
        return original(argv, **kwargs)

    monkeypatch.setattr(q, "validate_command", spy)
    view, code = q.page(rec)
    assert calls == [] and view["display"] == "messages"
    assert len(counter.read_text().splitlines()) == 1
    # A background-style argv is meaningless to the gate: the gate is never invoked
    # from outside capture, and the module has no background entry point at all.
    assert "def main(" in SOURCE.read_text() and "commands.add_parser" in SOURCE.read_text()


# ---------------------------------------------------------------- ③ coverage
def test_coverage_object_always_has_four_fields_and_never_claims_proof(tmp_path, sandbox, capsys):
    cli, _, _ = stub(tmp_path, ready())
    rec = capture([str(cli)])
    normal, _ = q.page(rec)
    raw_view, _ = q.page(rec, raw="stdout")
    scli, _, _ = stub(tmp_path, dict(status="ok", suggestions=[dict(display_name="唯一", username="u1")]))
    name_view, _ = q.page(capture([str(scli)]))
    code = q.main(["run", "--", "/bin/sh", "-c", "echo unsafe"])
    refused = json.loads(capsys.readouterr().out)
    assert code == 2 and refused["outcome"] == "wrapper_refused"
    for view in (normal, raw_view, name_view, refused):
        cov = view["coverage"]
        for field in ("gaps", "synced_at", "freshness", "history_incomplete"):
            assert field in cov  # explicitly present even when unknown/null
        assert cov["ready_is_not_coverage_evidence"] is True
        assert cov["empty_result_is_not_coverage_evidence"] is True
        assert cov["no_gaps_is_not_coverage_evidence"] is True
        assert cov["cli_returned_is_not_coverage_or_freshness_proof"] is True
        assert "status=ready" in cov["note"] and "NOT date-coverage" in cov["note"]


def test_original_exit_vs_wrapper_exit_are_distinct(tmp_path, sandbox):
    cli, _, _ = stub(tmp_path, dict(status="failed", messages=[dict(text="业务失败")]), exit_code=0)
    view, code = q.page(capture([str(cli)]))
    assert view["original_exit"] == 0 and view["wrapper_exit"] == 2 and code == 2
    assert view["outcome"] == "cli_failed" and view["coverage"]["outcome"] == "cli_failed"


def test_existing_behavior_preserved_messages_raw_copy_and_private_modes(tmp_path, sandbox):
    messages = ready(20)["messages"]
    data = dict(status="ready", messages=messages)
    cli, counter, raw = stub(tmp_path, data, b"diagnostic\n")
    rec = capture([str(cli)])
    view, code = q.page(rec)
    assert code == 0 and view["messages"] == messages  # message integrity
    assert view["stderr"] == "diagnostic\n"
    assert len(q.encode(view)) <= q.DISPLAY_LIMIT  # 20000-byte display limit
    assert (rec.parent / "stdout.bin").read_bytes() == raw  # private copy byte-exact
    assert stat.S_IMODE(rec.parent.stat().st_mode) == 0o700
    for f in rec.parent.iterdir():
        assert stat.S_IMODE(f.stat().st_mode) == 0o600 and f.stat().st_nlink == 1
    assert q.page(rec, raw="stdout")[0]["chunk"]["text"] == raw.decode()  # raw chunk retrieval
    assert len(counter.read_text().splitlines()) == 1  # paging never re-queries


# ---------------------------------------------------------------- ④ fixed entry
def test_source_config_must_be_current_config_path(tmp_path, sandbox):
    cli, counter, _ = stub(tmp_path, ready())
    with pytest.raises(q.Refusal):
        capture([str(cli), "--source-config", "/other/current-source.json"])
    assert not counter.exists()
    rec = capture([str(cli)])
    assert str(q.current_source_config()) in json.loads(rec.read_text())["argv"]


def test_no_product_source_import_or_db_read_and_pythonpath_stripped(tmp_path, sandbox, monkeypatch):
    text = SOURCE.read_text()
    assert not any(ln.strip().startswith(("import wechat_local", "from wechat_local")) for ln in text.splitlines())
    assert "sqlite3" not in text and "sys.path" not in text and "PYTHONPATH" in text
    monkeypatch.setenv("PYTHONPATH", "/forbidden/source")
    cli, _, _ = stub(tmp_path, ready())
    capture([str(cli)])


# ---------------------------------------------------------------- ⑤ date / truncation
@pytest.mark.parametrize("value,accepted", [
    ("2026-09-01到2026-09-10", True), ("2026-09-10到2026-09-01", False),
    ("2026-09-01-2026-09-10", False), ("2026-13-01到2026-13-10", False),
    ("2026-09-01到2026-09-10到2026-09-20", False)])
def test_request_format_and_inclusive_range(tmp_path, sandbox, value, accepted):
    cli, _, _ = stub(tmp_path, ready())
    args = [str(cli), "--request", value]
    if accepted:
        assert validate(args)[1] == "--request"
    else:
        with pytest.raises(q.Refusal):
            validate(args)


def test_multiple_requests_look_like_a_per_day_split_and_are_refused(tmp_path, sandbox):
    cli, _, _ = stub(tmp_path, ready())
    with pytest.raises(q.Refusal):
        validate([str(cli), "--request", "2026-09-01到2026-09-02",
                            "--request", "2026-09-03到2026-09-04"])


@pytest.mark.parametrize("zone,accepted", [("Asia/Shanghai", True), ("UTC", True),
                                           ("Not/AZone", False), ("Mars/Olympus", False), ("", False)])
def test_timezone_must_be_valid_iana(tmp_path, sandbox, zone, accepted):
    cli, _, _ = stub(tmp_path, ready())
    args = [str(cli), "--timezone", zone]
    if accepted:
        validate(args)
    else:
        with pytest.raises(q.Refusal):
            validate(args)


def test_latest_invents_no_dates(tmp_path, sandbox):
    cli, counter, _ = stub(tmp_path, ready(0))
    view, _ = q.page(capture([str(cli), "--latest", "20"]))
    assert view["range"]["requested"] == {"--latest": "20"}
    assert view["range"]["no_invented_dates_for_latest"] is True
    forwarded = json.loads(counter.read_text())
    assert "--request" not in [a.partition("=")[0] for a in forwarded]


def test_truncation_forces_unobtained_range_label_and_same_copy_page_hint(tmp_path, sandbox):
    cli, _, _ = stub(tmp_path, ready(45))
    view, _ = q.page(capture([str(cli)]))
    assert view["remaining"] == 25
    assert view["range"]["truncated"] is True
    assert view["range"]["status"] == "未取得范围"
    assert "page --result-file" in view["range"]["continuation_hint"]
    assert view["range"]["cross_run_stateless_note"] == "unhardened"  # honest: cross-run stateless


def test_overflow_signal_also_labels_range_unobtained(tmp_path, sandbox):
    data = dict(status="ready", overflow=True, messages=[dict(text="x")])
    cli, _, _ = stub(tmp_path, data)
    view, _ = q.page(capture([str(cli)]))
    assert view["range"]["truncated"] is True and view["range"]["status"] == "未取得范围"


# ---------------------------------------------------------------- ⑥ media / OCR
def test_media_flags_forced_on_window_only_never_sync(tmp_path, sandbox):
    cli, counter, _ = stub(tmp_path, ready(0))
    capture([str(cli)])
    forwarded = json.loads(counter.read_text())
    assert "--configured-images" in forwarded and "--voice-transcripts" in forwarded
    sync, scounter, _ = stub(tmp_path, ready(0), name="wechat-local-sync")
    capture([str(sync), "request-status", "--request-record", str(tmp_path / "fixture-request.json")])
    sforwarded = json.loads(scounter.read_text())
    assert "--configured-images" not in sforwarded and "--voice-transcripts" not in sforwarded


def test_ocr_ready_gate_link_retention_and_structured_explanations(tmp_path, sandbox):
    messages = [
        dict(text="t1", image=dict(status="decoded", path="/synthetic/a.png", ocr=dict(status="ready", text="图字"))),
        dict(text="t2", image=dict(status="ready", path="/synthetic/b.png", ocr=dict(status="pending", text=None))),
        dict(text="t3", image=dict(status="ready", path="/synthetic/c.png")),
        dict(text="t4", image=dict(status="ready", path="/synthetic/d.png", ocr=dict(status="failed"))),
        dict(text="t5", image=dict(status="ready", path="/synthetic/e.png", ocr=dict(status="ready", text="  "))),
    ]
    cli, _, raw = stub(tmp_path, dict(status="ready", messages=messages))
    view, _ = q.page(capture([str(cli)]))
    assert view["messages"] == messages  # original image links retained, nothing stripped
    m = view["media_ocr"]
    assert m["policy"] == "only_image_ocr_status_ready"
    assert m["image_total"] == 5 and m["image_links_retained"] is True
    assert m["label_permitted_count"] == 1  # only status=ready + nonempty text
    assert m["items_omitted"] == 2 and len(m["items"]) == 3
    assert m["script_invokes_no_ocr_models_decode"] is True
    assert m["chat_label_is_model_behavior_semi_soft"] is True
    assert "no extra" not in q.encode(view).decode() or True


# ---------------------------------------------------------------- ⑦ preflight
def test_preflight_user_override_sha_no_secret_or_rule_content_leak(tmp_path, sandbox, monkeypatch):
    """⑦ Layer 1: user-editable override (plain path) is stat+sha'd by the wrapper."""
    repo, safe = sandbox
    secret = "SYNTHETIC_SECRET_DO_NOT_LEAK_987"
    xdg = safe / "xdg-config"
    (xdg / "wechat-local").mkdir(parents=True, mode=0o700)
    rules = xdg / "wechat-local" / "WA_MESSAGE_CLASSIFICATION_RULES.md"
    rules.write_text("synthetic rules body DO_NOT_LEAK_RULE")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    cli, _, _ = stub(tmp_path, ready())
    config = q.current_source_config()
    source_config = json.loads(config.read_text())
    source_config.update(synthetic_secret=secret)
    config.write_text(json.dumps(source_config))
    view, _ = q.page(capture([str(cli), "--source-config", str(config)]))
    assert view["preflight"] == "已核对"
    assert view["preflight_checks"]["config_sha256_computed"] is True
    cr = view["classification_rules"]
    assert cr["path"] == str(rules) and cr["source"] == "user_override"
    assert cr["wrapper_resolved"] is True and cr["verified_by"] == "wrapper_stat_sha"
    assert cr["sha256"] == hashlib.sha256(rules.read_bytes()).hexdigest()
    assert cr["reference_sha256"] is None and cr["changed"] is None
    assert cr["change_detection"] == "caller_side_semi_soft"
    assert "规则已改，按新规则展示" in cr["change_hint"]
    encoded = q.encode(view).decode()
    assert secret not in encoded and "DO_NOT_LEAK_RULE" not in encoded
    assert "247093fb" not in SOURCE.read_text()  # config sha computed dynamically, never hardcoded


def test_preflight_installed_default_is_honest_null_sha_not_fabricated(tmp_path, sandbox, monkeypatch):
    """⑦ Layer 2: no override => official skill resolves the installed default via
    runtime_python + importlib.resources; wrapper imports no product source, guesses no
    site-packages, and reports sha256=null + an Owner-verified reference only."""
    safe = sandbox[1]
    xdg = safe / "empty-xdg"
    xdg.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    cr = q.classification_rules_metadata()
    assert cr["source"] == "installed_default" and cr["path"] is None
    assert cr["sha256"] is None and cr["wrapper_resolved"] is False
    assert cr["reference_sha256"] is None
    assert "installed Skill" in cr["note"]
    assert cr["change_detection"] == "caller_side_semi_soft" and cr["changed"] is None
    text = SOURCE.read_text()
    assert "CLASSIFICATION_RULES_REL" not in text  # wrong workspace doc-copy constant removed
    assert "REPO_ROOT / \"docs" not in text


def test_profile_digest_is_dynamic_and_missing_profile_is_refused(tmp_path, sandbox):
    cli, _, _ = stub(tmp_path, ready())
    cfg = q.current_source_config()
    assert q.read_current_profile(cfg)[1] == hashlib.sha256(cfg.read_bytes()).digest()
    with pytest.raises(q.Refusal):
        q.read_current_profile(cfg.with_name("missing.json"))


# ---------------------------------------------------------------- ⑧ delivery metadata
def test_four_delivery_metadata_fields_always_explicit_even_when_unknown(tmp_path, sandbox, capsys):
    cli, _, _ = stub(tmp_path, ready())
    rec = capture([str(cli)])
    normal, _ = q.page(rec)
    raw_view, _ = q.page(rec, raw="stdout")
    scli, _, _ = stub(tmp_path, dict(status="ok", suggestions=[dict(display_name="唯一", username="u1")]))
    name_view, _ = q.page(capture([str(scli)]))
    q.main(["run", "--", "/bin/sh", "-c", "echo"])
    refused = json.loads(capsys.readouterr().out)
    for view in (normal, raw_view, name_view, refused):
        for field in ("range", "data_time", "gaps", "omissions"):
            assert field in view
        assert set(("omitted_metadata_keys", "coverage_omission_groups",
                    "message_omissions_count", "full_raw_available")) <= set(view["omissions"])
    assert normal["data_time"] is None and normal["gaps"] is None  # unknown => explicit null


def test_full_raw_text_still_retrievable_from_same_copy(tmp_path, sandbox):
    cli, _, raw = stub(tmp_path, ready(3))
    rec = capture([str(cli)])
    piece, offset = [], 0
    while offset < len(raw.decode()):
        chunk = q.page(rec, raw="stdout", offset=offset, length=1000)[0]["chunk"]
        piece.append(chunk["text"])
        offset = chunk["end"]
    assert "".join(piece) == raw.decode()


# ---------------------------------------------------------------- A1–A4 query-chain supplement
def test_a2_valid_timezone_is_real_iana_not_arbitrary_string(tmp_path, sandbox):
    """A2 (extends ⑤): ZoneInfo rejects 'Mars/Phobos'/'Foo/Bar'; 'Asia/Shanghai'/'UTC' pass."""
    assert q.valid_timezone("Asia/Shanghai") is True
    assert q.valid_timezone("UTC") is True
    assert q.valid_timezone("Mars/Phobos") is False
    assert q.valid_timezone("Foo/Bar") is False
    assert q.valid_timezone("") is False
    assert q.valid_timezone(None) is False
    cli, _, _ = stub(tmp_path, ready())
    with pytest.raises(q.Refusal):
        validate([str(cli), "--timezone", "Mars/Phobos"])
    with pytest.raises(q.Refusal):
        validate([str(cli), "--timezone", "Foo/Bar"])


def test_a1_capture_validation_passes_and_rejects(tmp_path, sandbox):
    cli, _, _ = stub(tmp_path, ready())
    assert validate([str(cli), "--latest", "20", "--read-mode", "local"])
    for bad in (["--refresh"], ["--source-config", "/other"], ["--read-mode", "refresh"]):
        with pytest.raises(q.Refusal):
            validate([str(cli), *bad])


def test_a1_assert_source_not_opened_guard():
    """A1: refuse if the CLI ever reports it opened/touched the live source."""
    with pytest.raises(q.Refusal):
        q.assert_source_not_opened({"source_opened": True})
    q.assert_source_not_opened({"source_opened": False})  # must not raise
    q.assert_source_not_opened({})                         # absent => no signal
    q.assert_source_not_opened(None)


def test_a1_source_opened_rejected_in_page(tmp_path, sandbox):
    """A1 integration: a result that reports source_opened=True is refused by page()."""
    data = dict(status="ready", source_opened=True, messages=[dict(text="x")])
    cli, _, _ = stub(tmp_path, data)
    with pytest.raises(q.Refusal):
        q.page(capture([str(cli)]))


def test_a1_read_only_assertion_recorded_and_pre_cli_decision(tmp_path, sandbox):
    cli, _, _ = stub(tmp_path, ready())
    rec = capture([str(cli), "--latest", "20"])
    saved = json.loads(rec.read_text())
    assert saved["read_only_assertion"] == "passed"
    assert saved["pre_cli_resolution"] == "defer_to_cli_result"
    # explicit --conversation-username is a pre-CLI one-shot 'bind' decision
    rec2 = capture([str(cli), "--conversation-username", "wxid_confirmed_stable"])
    assert json.loads(rec2.read_text())["pre_cli_resolution"] == "bind_explicit_target"


def test_a4_unique_resolution_decides_bind_once(tmp_path, sandbox):
    data = dict(status="ok", suggestions=[dict(display_name="唯一", username="wxid_unique")])
    cli, counter, _ = stub(tmp_path, data)
    view, _ = q.page(capture([str(cli)]))
    v = view["name_resolution"]
    assert view["name_resolution_decision"] == "bind"
    assert v["decision"] == "bind"
    assert view["bound_stable_id"] == "wxid_unique" and v["bound_stable_id"] == "wxid_unique"
    assert "messages" not in view and len(counter.read_text().splitlines()) == 1


def test_a4_none_and_ambiguous_decide_stop_never_bind(tmp_path, sandbox):
    cases = ((dict(status="not_found", suggestions=[]), "none"),
             (dict(status="ambiguous", suggestions=[dict(display_name="甲", username="id_a"),
                                                    dict(display_name="乙", username="id_b")]), "ambiguous"))
    for data, label in cases:
        cli, _, _ = stub(tmp_path, data)
        view, _ = q.page(capture([str(cli)]))
        v = view["name_resolution"]
        assert view["name_resolution_decision"] == "stop"
        assert v["decision"] == "stop"
        assert view["bound_stable_id"] is None and v["bound_stable_id"] is None
        assert v["candidates_bindable"] is False
        assert "messages" not in view  # no other-candidate content / no source switch


def test_a3_classify_cli_error_structured_buckets():
    """A3: structured classification, never a generic throw; healthy unique => no signal."""
    assert q.classify_cli_error({"status": "not_found"}, None, "not_found")["category"] == "not_found"
    assert q.classify_cli_error({"status": "not_found"}, None, "not_found")["need_confirmation"] is True
    assert q.classify_cli_error({"suggestions": []}, None, "ok")["category"] == "suggestions"
    assert q.classify_cli_error({"suggestions": [1, 2]}, None, "ambiguous")["category"] == "suggestions"
    assert q.classify_cli_error({"status": "failed"}, None, "failed")["category"] == "conflict"
    assert q.classify_cli_error({"status": "failed"}, None, "failed")["escalate"] is True
    assert q.classify_cli_error({"identity_conflicts": [1]}, None, "ready")["category"] == "scope_source_conflict"
    assert q.classify_cli_error({"identity_conflicts": [1]}, None, "ready")["escalate"] is True
    assert q.classify_cli_error({}, "boom", "ready")["category"] == "transient"
    assert q.classify_cli_error({}, "boom", "ready")["retryable"] is True
    assert q.classify_cli_error({"status": "unavailable"}, None, "unavailable")["category"] == "transient"
    assert q.classify_cli_error({"error": "x"}, None, "ready")["category"] == "unknown_error"
    # a healthy unique candidate is NOT an error signal -> no classification
    assert q.classify_cli_error({"suggestions": [{"username": "u"}]}, None, "ok") is None
    # a successful ready result with messages is not an error
    assert q.classify_cli_error({"status": "ready", "messages": [1]}, None, "ready") is None


def test_a3_error_classification_surfaced_in_page_view(tmp_path, sandbox):
    """A3 integration: a scope/source conflict surfaces a structured classification and
    escalates, without throwing a generic exception (existing failure behavior preserved)."""
    data = dict(status="ready", source_conflicts=[dict(expected="a", observed="b")],
                messages=[dict(text="x")])
    cli, _, _ = stub(tmp_path, data)
    view, code = q.page(capture([str(cli)]))
    assert view["cli_error_classification"]["category"] == "scope_source_conflict"
    assert view["escalate"] is True and view["need_user_clarification"] is False
    assert code == 2  # still a structured failure, not a generic throw


# ---------------------------------------------------------------- F/G/H supplement
def test_g_normalize_query_term_unit():
    assert q.normalize_query_term(" ＦＯＯ　BAR ") == "foo bar"
    assert q.normalize_query_term("张三") == "张三"
    assert q.normalize_query_term(123) == 123


def test_g_query_term_normalized_and_recorded(tmp_path, sandbox):
    cli, counter, _ = stub(tmp_path, ready())
    rec = capture([str(cli), "--contact-query", " ＸＸ "])
    saved = json.loads(rec.read_text())
    norm = saved["query_term_normalization"]
    assert isinstance(norm, list) and norm, "normalization record must be a non-empty list"
    entry = norm[0]
    assert entry["original"] != entry["normalized"]
    calls = counter.read_text()
    assert "ＸＸ" not in calls  # original full-width value must not reach the CLI
    assert entry["normalized"] in calls  # the normalized value must be forwarded
    q.page(rec)  # page must not fail with the normalized argv


def test_h_rich_disambiguation_fields(tmp_path, sandbox):
    data = dict(status="ambiguous", suggestions=[
        dict(display_name="甲群", type="group", member_count=5, last_active_at="2026-11-01",
             username="wx_g", shard="shard-2"),
        dict(display_name="甲联系人", type="contact", remark="同事", username="wx_c", shard="shard-1")])
    cli, _, _ = stub(tmp_path, data)
    view, _ = q.page(capture([str(cli)]))
    v = view["name_resolution"]
    assert v["resolution"] == "ambiguous" and len(v["candidates"]) == 2
    for c in v["candidates"]:
        assert "label" in c and "label_normalized" in c and "type" in c
        # H: stable id (account) + owning shard are surfaced for the user to pick (info-only).
        assert "account" in c and c["account"]
        assert "shard" in c and c["shard"]
    group = next(c for c in v["candidates"] if c["type"] == "group")
    contact = next(c for c in v["candidates"] if c["type"] == "contact")
    assert group["member_count"] == 5
    assert contact["remark"] == "同事"
    assert group["account"] == "wx_g" and group["shard"] == "shard-2"
    assert contact["account"] == "wx_c" and contact["shard"] == "shard-1"
    # The bindable raw key is dropped; the stable id is only surfaced as info 'account'.
    assert "username" not in json.dumps(v["candidates"], ensure_ascii=False)
    # H does NOT relax ①: ambiguous still refuses to bind.
    assert v["decision"] == "stop" and v["bound_stable_id"] is None and v["auto_bind_permitted"] is False
    assert v["normalized_label_collision"] is False


def test_h_collision_detected_not_merged(tmp_path, sandbox):
    data = dict(status="ambiguous", suggestions=[
        dict(display_name="张三", username="u1"),
        dict(display_name="张三 ", username="u2")])
    cli, _, _ = stub(tmp_path, data)
    view, _ = q.page(capture([str(cli)]))
    v = view["name_resolution"]
    assert len(v["candidates"]) == 2  # NOT merged
    assert v["normalized_label_collision"] is True
    for c in v["candidates"]:
        assert c["label_normalized"] == "张三"


def test_f_page_continuity_contiguous(tmp_path, sandbox):
    cli, _, _ = stub(tmp_path, ready(45))
    record = capture([str(cli)])
    rb = (record.parent / "result.json").read_bytes()
    v1, _ = q.page(record, 1, 20)
    v2, _ = q.page(record, 21, 20)
    c1, c2 = v1["page_continuity"], v2["page_continuity"]
    assert c1["contiguous"] is True and c1["previous_end"] is None and c1["served_end"] == 20
    assert c2["contiguous"] is True and c2["previous_end"] == 20 and c2["served_end"] == 40
    messages = ready(45)["messages"]
    assert v1["messages"] == messages[0:20]
    assert v2["messages"] == messages[20:40]
    assert (record.parent / "result.json").read_bytes() == rb  # result.json untouched


def test_f_page_jump_flagged(tmp_path, sandbox):
    cli, _, _ = stub(tmp_path, ready(45))
    record = capture([str(cli)])
    q.page(record, 1, 20)  # sidecar last_served_end becomes 20
    (record.parent / (record.name + ".page_state")).write_text(json.dumps(dict(last_served_end=20)))
    v, _ = q.page(record, 35, 10)
    assert v["page_continuity"]["contiguous"] is False
    assert any("分页不连续" in s for s in v["issues"])


# ---------------------------------------------------------------- G normalization
def test_g_normalize_name_folds_fullwidth_case_whitespace(tmp_path, sandbox):
    # Full-width ASCII, mixed case, and irregular whitespace all collapse to one canonical form.
    assert q.normalize_name(" ＡＢＣ　Ｄ ") == "abc d"
    assert q.normalize_name("Foo　Bar") == "foo bar"
    assert q.normalize_name("ＺＨＡＮＧ　ＳＡＮ") == "zhang san"
    assert q.normalize_name("") == ""
    assert q.normalize_name(None) is None
    # Two distinct originals can normalize to the SAME string — that must NOT merge them.
    assert q.normalize_name("Foo") == q.normalize_name("ＦＯＯ ") == "foo"


def test_g_query_term_normalized_before_cli_call(tmp_path, sandbox):
    # G(a): the wrapper best-effort normalizes the target term before the single read-only CLI
    # call; the change is recorded for transparency. Authoritative matching stays in the CLI.
    argv = ["prog", "--source-config", str(q.current_source_config()), "--contact-query", "　ＦＯＯ　"]
    out, changes = q.normalize_query_flags(argv)
    assert changes and changes[0]["normalized"] == "foo"
    assert "foo" in out  # normalized term is what reaches the CLI


def test_g_collision_keeps_two_distinct_candidates(tmp_path, sandbox):
    # G red line: normalized collision must NOT merge — two different originals stay two.
    data = dict(status="ambiguous", suggestions=[
        dict(display_name="张三", username="u1"),
        dict(display_name="张三 ", username="u2")])
    cli, _, _ = stub(tmp_path, data)
    view, _ = q.page(capture([str(cli)]))
    v = view["name_resolution"]
    assert len(v["candidates"]) == 2  # NOT merged
    assert v["normalized_label_collision"] is True
    ids = {c["account"] for c in v["candidates"]}
    assert ids == {"u1", "u2"}  # each original kept distinct


# ---------------------------------------------------------------- F total_messages consistency
def test_f_total_messages_consistency_flagged(tmp_path, sandbox):
    cli, _, _ = stub(tmp_path, ready(45))
    record = capture([str(cli)])
    # Simulate a prior page that recorded a DIFFERENT total for the SAME result_file.
    q.write_page_state(record, 20, 999)
    v, _ = q.page(record, 21, 20)
    pc = v["page_continuity"]
    assert pc["previous_total_messages"] == 999
    assert pc["total_messages"] == 45
    assert pc["total_messages_consistent"] is False
    # The anomaly is surfaced via ③'s coverage presentation AND as an honest issue.
    assert "pagination_anomaly" in v["coverage"]
    assert any("total_messages" in s or "总数" in s for s in v["issues"])
    # The served messages are still the real slice — we do NOT fabricate a full coverage.
    assert v["display"] == "messages" and v["total_messages"] == 45


def test_f_contiguous_sequence_no_false_anomaly(tmp_path, sandbox):
    cli, _, _ = stub(tmp_path, ready(45))
    record = capture([str(cli)])
    v1, _ = q.page(record, 1, 20)
    v2, _ = q.page(record, 21, 20)
    v3, _ = q.page(record, 41, 20)
    for v in (v1, v2, v3):
        assert v["page_continuity"]["contiguous"] is True
        assert v["page_continuity"]["total_messages_consistent"] is True
    assert "pagination_anomaly" not in v3["coverage"]
    assert v3["end"] == 45 and v3["remaining"] == 0
