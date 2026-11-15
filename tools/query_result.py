#!/usr/bin/env python3
"""Capture one explicitly chosen installed read-only CLI; page its private copy."""
import argparse
import base64
import datetime
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import subprocess
import tempfile
import unicodedata

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "walden-query-result/1"
DISPLAY_LIMIT = 20000
REDUNDANT = {"internal_source_hashes", "partition_hashes", "fragment_hashes"}
# The operator's current profile, independent of the command being wrapped, is
# the trust root for this tool. The profile and its installed package are local
# trusted inputs, not an authentication boundary against the same OS user.
WINDOW_ENTRY = "wechat-local-window"
SYNC_ENTRY = "wechat-local-sync"
REPLY_ENTRY = "wechat-local-reply"
PACKAGE_ENTRIES = {
    WINDOW_ENTRY: "wechat_local.native_window:console_main",
    SYNC_ENTRY: "wechat_local.native_mirror_cli:console_main",
}
RULES_CHANGE_HINT = "compare sha256 with last run; changed => 规则已改，按新规则展示"
# ⑥ read-only media params forced on for window queries (never for sync).
MEDIA_FLAGS = ("--configured-images", "--voice-transcripts")
DATE_RANGE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})到(\d{4})-(\d{2})-(\d{2})$")
IANA_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_+.-]*(/[A-Za-z0-9_+.-]+)+$")
MESSAGE_PATHS = (("messages",), ("body", "messages"), ("result", "messages"),
                 ("result", "body", "messages"))

WINDOW_SWITCHES = frozenset((*MEDIA_FLAGS, "--json"))
WINDOW_VALUES = frozenset({
    "--source-config", "--conversation-username", "--contact-query", "--group-query",
    "--request", "--timezone", "--latest", "--voice-runtime-root", "--voice-python",
    "--read-mode",
})
READ_ONLY_FLAGS = WINDOW_SWITCHES | WINDOW_VALUES
SYNC_VALUES = {
    "request": frozenset({"--source-config", "--contact-query", "--target-ref",
                          "--target-ref-sha256", "--latest", "--since", "--until", "--timezone"}),
    "request-status": frozenset({"--source-config", "--request-record"}),
}

UNIQUE_RULE_BASIS = "installed CLI result and current query instructions"
SUGGESTION_KEYS = ("suggestions", "candidates")
# Ordered identifier keys used ONLY to surface the CLI-reported stable id for a UNIQUE
# match. For 0/ambiguous matches, stable ids are stripped from candidate display info.
STABLE_ID_KEYS = ("conversation_username", "username", "stable_id", "selected_username",
                  "wxid", "user_name", "user_id", "userid", "id")
# Identifier-like keys dropped from candidate DISPLAY info so 0/ambiguous results never
# hand back a bindable stable id. For a unique match the stable id is surfaced once,
# explicitly, as `unique_stable_id` with `auto_bind_permitted`.
SUGGESTION_ID_KEYS = {
    "username", "user_name", "user_id", "userid", "wxid", "chatroom", "chatroom_id",
    "conversation_username", "conversation-username", "stable_id", "stable_username",
    "selected_username", "target", "target_id", "id", "alias",
}
UNIQUE_GUIDANCE = (
    "ONE-SHOT wrapper decision: exactly one candidate (unique match) => decision='bind'; the "
    "CLI-reported unique stable id is bound to --conversation-username and the wrapper proceeds "
    "to read, with NO further user confirmation. The wrapper only "
    "classifies the captured result: it does NOT run a second query, resolve names, read the DB, "
    "or treat a suggestion as identity proof. A contact_target_type_mismatch flag does not block a "
    "unique match. Sending/reply still needs an explicit target + full body; real source/identity "
    "change or source conflict is still refused; no alias table/script and no scope expansion. The "
    "wrapper never defers this bind decision to a vague 'later step'."
)
NONE_GUIDANCE = (
    "ONE-SHOT wrapper decision: 0 candidates => decision='stop' (structured stop). "
    "need_confirmation=true; do NOT bind, guess any target, auto-select, or switch "
    "account/source. Ask the user to clarify."
)
AMBIGUOUS_GUIDANCE = (
    "ONE-SHOT wrapper decision: multiple candidates => decision='stop' (structured stop). "
    "need_confirmation=true; candidates are listed but bindable=false: do NOT auto-select the "
    "first, do NOT read other candidates' content, do NOT switch account/source, do NOT bind "
    "any stable id. A name/short name/one substring suggestion is not identity proof or read "
    "authorization. Ask the user to choose."
)


class Refusal(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise Refusal(reason)


def inside(path, root):
    return path == root or root in path.parents


def absolute(path):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "absolute path without '..' required")
    return path


def directory_fd(path):
    """Open every component without following links, including ancestor links."""
    path = absolute(path)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            other = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = other
        return fd
    except BaseException:
        os.close(fd)
        raise


def private_directory(path):
    fd = directory_fd(path)
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(fd)
        raise Refusal("result parent must be current-UID private 0700")
    return fd


def read_private(path):
    path = absolute(path)
    parent = private_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, "rb") as handle:
            before = os.fstat(handle.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                    and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600,
                    "result must be private current-UID regular 0600 with one link")
            data = handle.read()
            after = os.fstat(handle.fileno())
            fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
            require(fields(before) == fields(after) and len(data) == after.st_size,
                    "result changed while reading")
        return data
    finally:
        os.close(parent)


def flag_value(argv, flag):
    """Value of --flag=value or --flag value, or None when absent."""
    for index, arg in enumerate(argv[1:], 1):
        name, sep, inline = arg.partition("=")
        if name == flag:
            return inline if sep else (argv[index + 1] if index + 1 < len(argv) else None)
    return None


def normalize_name(value):
    """G canonical name normalization (parent-specified name). Best-effort: NFKC +
    full-width->half-width ASCII (U+FF01..U+FF5E -> 0x21..0x7E) + casefold + collapse
    internal/edge whitespace. Never raises; on any failure returns the original value.
    Used by G(a) before the CLI call and G(b) for wrapper-side candidate comparison/
    presentation. RED LINE: normalization is comparison/presentation only — it never
    merges two distinct candidates; see name_resolution_determination.normalized_label_collision."""
    if not isinstance(value, str) or not value:
        return value
    try:
        t = unicodedata.normalize("NFKC", value)
        t = "".join(chr(ord(c) - 0xFEE0) if 0xFF01 <= ord(c) <= 0xFF5E else c for c in t)
        t = t.casefold()
        t = " ".join(t.split())
        return t
    except Exception:
        return value


# Backwards-compatible alias: G is the canonical name; normalize_query_term is still used
# internally by normalize_query_flags / suggestion_display.
normalize_query_term = normalize_name


def normalize_query_flags(argv):
    """G: best-effort normalize --contact-query/--group-query values before the single
    read-only CLI call. Returns (argv, changes) where changes lists
    {flag, original, normalized} for any value that changed (transparency)."""
    changes = []
    out = list(argv)
    for i, arg in enumerate(out[1:], 1):
        name, sep, value = arg.partition("=")
        raw = value if sep else (out[i + 1] if i + 1 < len(out) else "")
        if name in ("--contact-query", "--group-query") and raw:
            n = normalize_query_term(raw)
            if n != raw:
                changes.append(dict(flag=name, original=raw, normalized=n))
                if sep:
                    out[i] = name + "=" + n
                else:
                    out[i + 1] = n
    return out, changes


def valid_timezone(value):
    """A2 (extends ⑤): a REAL IANA timezone, not an arbitrary string. Authoritative
    validation uses the IANA tz database via `zoneinfo.ZoneInfo`; the strict IANA-shape
    regex (IANA_RE) is only a fallback when the zoneinfo module or its tz database is
    entirely unavailable (documented semi-soft fallback). A value like 'Mars/Phobos' is
    rejected by ZoneInfo, not merely by shape."""
    if type(value) is not str or not value or "\0" in value:
        return False
    try:
        from zoneinfo import ZoneInfo
    except ImportError:
        return bool(IANA_RE.match(value)) or value == "UTC"
    # If even UTC cannot be resolved there is no usable tz database here: fall back.
    try:
        ZoneInfo("UTC")
    except Exception:
        return bool(IANA_RE.match(value)) or value == "UTC"
    # Real validation against the IANA tz database.
    try:
        ZoneInfo(value)
        return True
    except Exception:
        return False


def validate_request_range(value):
    """Require one inclusive calendar range with the start no later than the end."""
    match = DATE_RANGE_RE.match(value)
    require(match is not None, "--request must be YYYY-MM-DD到YYYY-MM-DD (inclusive)")
    sy, sm, sd, ey, em, ed = match.groups()
    try:
        start = datetime.date(int(sy), int(sm), int(sd))
        end = datetime.date(int(ey), int(em), int(ed))
    except ValueError:
        raise Refusal("--request contains an invalid calendar date")
    require(start <= end, "--request start must not be after end")


def config_root():
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = absolute(xdg) if xdg else absolute(Path.home() / ".config")
    return base / "wechat-local"


def current_source_config():
    return config_root() / "current-source.json"


def rules_override_path():
    return config_root() / "WA_MESSAGE_CLASSIFICATION_RULES.md"


def classification_rules_metadata():
    override = rules_override_path()
    if override.is_file():
        try:
            with open(override, "rb") as handle:
                digest = hashlib.sha256(handle.read()).hexdigest()
            return dict(path=str(override), sha256=digest, source="user_override",
                        wrapper_resolved=True, verified_by="wrapper_stat_sha",
                        reference_sha256=None, changed=None,
                        change_hint=RULES_CHANGE_HINT,
                        change_detection="caller_side_semi_soft", note=None)
        except OSError:
            pass
    return dict(path=None, sha256=None, source="installed_default",
                wrapper_resolved=False, verified_by="official_skill",
                reference_sha256=None, changed=None,
                change_hint=RULES_CHANGE_HINT,
                change_detection="caller_side_semi_soft",
                note="Resolve the installed default using the current installed Skill.")


def read_current_profile(path):
    try:
        raw = read_private(path)
        profile = parse_json(raw)
    except (OSError, Refusal, ValueError, RecursionError):
        raise Refusal("current --source-config is missing, unsafe, or invalid") from None
    require(type(profile) is dict, "current --source-config must be an object")
    return profile, hashlib.sha256(raw).digest()


def profile_entry(profile, key):
    value = profile.get(key)
    require(type(value) is str and "\0" not in value, "current profile entry is invalid")
    return absolute(value)


def launcher_has_runtime(raw, runtime):
    # pip may use a /bin/sh trampoline for long paths or paths with spaces.
    lines = raw.splitlines()
    if lines[:1] == [b"#!" + os.fsencode(runtime)]:
        return True
    if len(lines) < 3 or lines[0] != b"#!/bin/sh" or lines[2] != b"' '''":
        return False
    try:
        return shlex.split(os.fsdecode(lines[1])) == ["exec", str(runtime), "$0", "$@"]
    except ValueError:
        return False


def verify_installed_entry(executable, runtime):
    venv = runtime.parent.parent
    require(runtime.parent == venv / "bin" and (venv / "pyvenv.cfg").is_file()
            and runtime.is_file() and os.access(runtime, os.X_OK), "current runtime is not an installed venv")
    require(not inside(venv.resolve(strict=True), REPO_ROOT.resolve()),
            "workspace/source CLI is forbidden")
    locations = [str(p) for p in (venv / "lib").glob("python*/site-packages") if p.is_dir()]
    packages = list(metadata.distributions(name="wechat-local-readonly", path=locations))
    require(len(packages) == 1, "current runtime must identify exactly one Walden installation")
    package = packages[0]
    entries = [entry.value for entry in package.entry_points
               if entry.group == "console_scripts" and entry.name == executable.name]
    require(entries == [PACKAGE_ENTRIES[executable.name]], "installed Walden entry point is invalid")
    records = [item for item in (package.files or ()) if item.name == executable.name
               and Path(os.path.abspath(package.locate_file(item))) == executable]
    require(len(records) == 1 and records[0].hash is not None
            and records[0].hash.mode == "sha256", "Walden entry point is missing its installation hash")
    expected = records[0]
    parent = directory_fd(executable.parent)
    try:
        fd = os.open(executable.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                    and info.st_nlink == 1 and not (info.st_mode & 0o022)
                    and bool(info.st_mode & stat.S_IXUSR) and info.st_size == expected.size
                    and 0 < info.st_size <= 16384, "installed Walden launcher is unsafe")
            raw = handle.read(info.st_size + 1)
    finally:
        os.close(parent)
    digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    require(len(raw) == expected.size and digest == expected.hash.value
            and launcher_has_runtime(raw, runtime),
            "installed Walden launcher does not match its runtime and installation hash")


def parse_query_args(argv, executable, profile_path, profile):
    is_window = executable.name == WINDOW_ENTRY
    positional_count = 1 if is_window else 2
    if not is_window:
        require(len(argv) > 1 and argv[1] in SYNC_VALUES, "sync supports request/request-status only")
    values = WINDOW_VALUES if is_window else SYNC_VALUES[argv[1]]
    switches = WINDOW_SWITCHES if is_window else frozenset()
    found = {}
    index = positional_count
    while index < len(argv):
        flag, equals, value = argv[index].partition("=")
        require(flag in values or flag in switches, "unsupported read-only flag or positional argument")
        require(flag not in found, "duplicate read-only flag")
        index += 1
        if flag in switches:
            require(not equals, "read-only switch does not take a value")
            found[flag] = None
            continue
        if not equals and index < len(argv) and not argv[index].startswith("-"):
            value = argv[index]
            index += 1
        if flag == "--latest" and not equals and not value and is_window:
            value = "20"
        require(bool(value) and not value.startswith("-"), "missing or invalid read-only flag value")
        found[flag] = value
    require(found.get("--source-config") == str(profile_path),
            "--source-config must be the explicit current profile")
    if "--latest" in found:
        latest = found["--latest"]
        require(re.fullmatch(r"[0-9]{1,3}", latest) and 1 <= int(latest) <= 100,
                "--latest must be in the range 1–100")
    if "--timezone" in found:
        require(valid_timezone(found["--timezone"]), "--timezone must be a valid IANA zone")
    if is_window:
        require(found.get("--read-mode", "local") == "local", "only local read mode is supported")
        targets = {"--conversation-username", "--contact-query", "--group-query"}
        require(len(targets & found.keys()) <= 1, "query targets are mutually exclusive")
        require(not {"--request", "--latest"} <= found.keys(), "request and latest are mutually exclusive")
        for flag, key in (("--voice-runtime-root", "voice_runtime_root"), ("--voice-python", "voice_python")):
            if flag in found:
                require(found[flag] == profile.get(key), "voice overrides must match the configured runtime")
        require(("--voice-python" in found) == ("--voice-runtime-root" in found),
                "voice runtime overrides require both configured paths")
        if "--request" in found:
            validate_request_range(found["--request"])
        args = list(argv)
        if "--read-mode" not in found:
            args.extend(("--read-mode", "local"))
        args.extend(flag for flag in MEDIA_FLAGS if flag not in found)
        return args
    if argv[1] == "request-status":
        require("--request-record" in found, "request-status requires a request record")
        absolute(found["--request-record"])
    else:
        require(("--contact-query" in found) != ("--target-ref" in found),
                "request requires exactly one contact query or target reference")
        require(("--target-ref" in found) == ("--target-ref-sha256" in found),
                "target reference requires its hash")
        if "--target-ref" in found:
            absolute(found["--target-ref"])
            require(re.fullmatch(r"[0-9a-f]{64}", found["--target-ref-sha256"]),
                    "target reference hash must be SHA-256")
        dated = {"--since", "--until", "--timezone"}
        require(("--latest" in found and not ({"--since", "--until"} & found.keys()))
                or ("--latest" not in found and dated <= found.keys()),
                "request requires latest or one complete timestamp range")
        if "--since" in found:
            since, until = found["--since"], found["--until"]
            require(re.fullmatch(r"[0-9]{1,20}", since) and re.fullmatch(r"[0-9]{1,20}", until)
                    and int(since) <= int(until), "request timestamps must be ordered integers")
    return list(argv)


def validate_command(argv, *, binding=None):
    require(bool(argv) and all(type(arg) is str and "\0" not in arg for arg in argv),
            "explicit CLI argv required")
    executable = absolute(argv[0])
    require(executable.name in {WINDOW_ENTRY, SYNC_ENTRY}, "unsupported read-only entry name")
    path = current_source_config()
    profile = read_current_profile(path)[0] if binding is None else binding[0]
    runtime = profile_entry(profile, "runtime_python")
    bin_dir = runtime.parent
    require(profile_entry(profile, "window_cli") == bin_dir / WINDOW_ENTRY
            and profile_entry(profile, "reply_cli") == bin_dir / REPLY_ENTRY
            and (bin_dir / REPLY_ENTRY).is_file(), "current profile entries must share the installed environment")
    require(argv[0] == str(bin_dir / executable.name), "CLI must be the exact configured installed entry")
    normalized = parse_query_args(argv, executable, path, profile)
    verify_installed_entry(executable, runtime)
    return normalized


def assert_source_not_opened(result):
    """A1: if the CLI ever reports it opened/touched the live source, refuse. Real guard."""
    if type(result) is dict and result.get("source_opened") is True:
        raise Refusal("CLI reported it opened/touched the live source; read-only guarantee violated")


def pre_cli_resolution_decision(argv):
    """A4: one-shot resolution decision made BEFORE the CLI call when possible. An explicit
    --conversation-username is a user-authorized unique target, so the wrapper decides 'bind'
    pre-CLI; otherwise resolution is deferred to the CLI result (handled post-CLI by
    name_resolution_determination). The wrapper never auto-selects or switches source; this is
    a decision, not an action."""
    args = list(argv)
    for index, arg in enumerate(args[1:], 1):
        name, _, value = arg.partition("=")
        if name == "--conversation-username" and not value and index + 1 < len(args):
            value = args[index + 1]
        if name == "--conversation-username" and value:
            return "bind_explicit_target"
    return "defer_to_cli_result"


def new_directory(explicit=None):
    root = Path(tempfile.gettempdir()).resolve(strict=True)
    require(not inside(root, REPO_ROOT.resolve()), "system temporary root is inside repository")
    target = absolute(explicit) if explicit else root / ("walden-query-" + secrets.token_hex(16))
    require(inside(target.parent, root) and not inside(target, REPO_ROOT.resolve()),
            "result directory must be in system temporary area, outside repository")
    parent = directory_fd(target.parent)
    try:
        os.mkdir(target.name, 0o700, dir_fd=parent)  # Existing names always refuse; no retry/overwrite.
        fd = os.open(target.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            os.fchmod(fd, 0o700)
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)
    return target


def exclusive(parent, name):
    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    os.fchmod(fd, 0o600)
    return os.fdopen(fd, "w+b")


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def parse_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON keys: use raw chunks")
            result[key] = value
        return result
    def invalid_constant(value):
        raise ValueError("non-JSON numeric constant")
    def number(value):
        from decimal import Decimal
        parsed = float(value)
        require(Decimal(str(parsed)) == Decimal(value), "numeric precision requires raw chunks")
        return parsed
    result = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid_constant, parse_float=number)
    encode(result)  # Unpaired Unicode escapes also require a lossless raw view.
    return result


def analyse(raw, original_exit, spawn_error=None):
    try:
        result = parse_json(raw)
    except (ValueError, UnicodeError, Refusal, RecursionError):
        return None, None, ["stdout is not unambiguous UTF-8 JSON; use raw chunks"], 1, original_exit or 2
    status = result.get("status") if type(result) is dict else None
    issues, total = [], 0
    def issue(text):
        nonlocal total
        total += 1
        if len(issues) < 20 and len(text.encode("utf-8")) <= 240:
            issues.append(text)
    def visit(value, path="result"):
        if type(value) is dict:
            for key, item in value.items():
                label = path + "." + key
                if key in {"status", "body_status"} and type(item) is str and (item in {"failed", "error", "conflict", "incomplete", "unavailable", "not_found", "partial", "pending", "blocked", "unknown", "invalid", "needs_target_copy"}
                        or item.endswith(("_failed", "_conflict", "_unavailable"))):
                    issue(label + "=" + item)
                if key in {"gaps", "identity_conflicts", "source_conflicts", "identity_conflict", "error", "errors"} and item:
                    issue(label + " is nonempty")
                if key in {"overflow", "truncated", "has_more"} and item is True:
                    issue(label + "=true")
                visit(item, label)
        elif type(value) is list:
            for index, item in enumerate(value):
                visit(item, path + "[" + str(index) + "]")
    visit(result)
    if spawn_error:
        issue("CLI could not start: " + spawn_error)
    return result, status, issues, total, original_exit or (2 if total or spawn_error else 0)


def capture(argv, directory=None):
    require(bool(argv) and all(type(arg) is str and "\0" not in arg for arg in argv),
            "explicit CLI argv required")
    profile_path = current_source_config()
    binding = read_current_profile(profile_path)
    normalized, query_normalizations = normalize_query_flags(argv)
    argv = validate_command(normalized, binding=binding)
    pre_cli = pre_cli_resolution_decision(argv)
    rules = classification_rules_metadata()
    folder = new_directory(directory)
    parent = private_directory(folder)
    try:
        with exclusive(parent, "stdout.bin") as stdout, exclusive(parent, "stderr.bin") as stderr, exclusive(parent, "result.json") as record:
            original_exit = None
            spawn_error = None
            env = dict(os.environ)
            for name in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP"):
                env.pop(name, None)
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            env["PYTHONNOUSERSITE"] = "1"
            require(read_current_profile(profile_path)[1] == binding[1],
                    "current --source-config changed before execution")
            try:
                original_exit = subprocess.run(argv, shell=False, stdin=subprocess.DEVNULL,
                                               stdout=stdout, stderr=stderr, env=env, check=False).returncode
            except OSError as error:
                spawn_error = type(error).__name__
                stderr.write((str(error) + "\n").encode("utf-8"))
            for stream in (stdout, stderr):
                stream.flush()
                os.fsync(stream.fileno())
                stream.seek(0)
            out, err = stdout.read(), stderr.read()
            saved = dict(schema=SCHEMA, argv=argv, captured_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                         original_exit=original_exit, spawn_error=spawn_error,
                         read_only_assertion="passed", pre_cli_resolution=pre_cli,
                         preflight="已核对",
                         preflight_checks=dict(config_sha256_computed=True),
                         classification_rules=rules,
                         query_term_normalization=query_normalizations,
                         stdout_sha256=hashlib.sha256(out).hexdigest(), stderr_sha256=hashlib.sha256(err).hexdigest())
            record.write(encode(saved) + b"\n")
            record.flush()
            os.fsync(record.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)
    return folder / "result.json"


def load_result(path):
    path = absolute(path)
    require(not inside(path.resolve(strict=True), REPO_ROOT.resolve()), "result files must stay outside repository")
    saved = parse_json(read_private(path))
    require(type(saved) is dict and saved.get("schema") == SCHEMA, "not a query result record")
    require(saved.get("original_exit") is None or (type(saved.get("original_exit")) is int and -255 <= saved["original_exit"] <= 255), "invalid original exit")
    require(saved.get("spawn_error") is None or type(saved["spawn_error"]) is str, "invalid spawn error")
    out, err = read_private(path.parent / "stdout.bin"), read_private(path.parent / "stderr.bin")
    require(hashlib.sha256(out).hexdigest() == saved.get("stdout_sha256")
            and hashlib.sha256(err).hexdigest() == saved.get("stderr_sha256"), "captured stream changed")
    return path, saved, out, err


def project_coverage(context):
    """Only these two known shard maps; never recurse into messages/history."""
    omissions = []
    for prefix in (("coverage",), ("result", "coverage")):
        cursor = context
        for key in prefix[:-1]:
            if type(cursor.get(key)) is not dict:
                break
            cursor[key] = dict(cursor[key])
            cursor = cursor[key]
        else:
            coverage = cursor.get(prefix[-1])
            if type(coverage) is not dict or type(coverage.get("shards")) is not dict:
                continue
            coverage = dict(coverage)
            cursor[prefix[-1]] = coverage
            shards = coverage["shards"] = dict(coverage["shards"])
            fields = {key: [] for key in ("source_header_sha256", "source_identity", "members")}
            counts = {}
            for name, value in shards.items():
                if type(value) is not dict:
                    continue
                row = dict(value)
                hashed, identity, members = row.get("source_header_sha256"), row.get("source_identity"), row.get("members")
                known = dict(source_header_sha256=type(hashed) is str and len(hashed) == 64 and all(c in "0123456789abcdef" for c in hashed),
                             source_identity=type(identity) is list and len(identity) == 2 and all(type(v) is int and v >= 0 for v in identity),
                             members=type(members) is list and all(type(v) is int and v > 0 for v in members))
                for field, valid in known.items():
                    if valid:
                        del row[field]
                        fields[field].append(name)
                        if field == "members":
                            counts[name] = len(members)
                shards[name] = row
            if any(fields.values()):
                omissions.append(dict(path=list(prefix) + ["shards"], fields={key: names for key, names in fields.items() if names}, member_counts=counts))
    return omissions


def messages_and_context(result):
    candidates = []
    slots_present = False
    for path in MESSAGE_PATHS:
        item = result
        for key in path[:-1]:
            item = item.get(key) if type(item) is dict else None
        slots_present |= type(item) is dict and path[-1] in item
        item = item.get(path[-1]) if type(item) is dict else None
        if type(item) is list and all(type(message) is dict for message in item):
            candidates.append((path, item))
    status_only = (not candidates and not slots_present and type(result) is dict
                   and result.get("result") is None
                   and ((type(result.get("status")) is str and result.get("status") in {"failed", "needs_target_copy"})
                        or result.get("body_status") == "needs_target_copy"))
    require(len(candidates) == 1 or status_only, "unknown or ambiguous message schema; use raw chunks")
    context = dict(result)
    messages = None
    if candidates:
        path, messages = candidates[0]
        cursor = context
        for key in path[:-1]:
            cursor[key] = dict(cursor[key])
            cursor = cursor[key]
        del cursor[path[-1]]
    omitted = sorted(key for key in REDUNDANT.intersection(context)
                     if type(context[key]) is list and all(type(value) is str and len(value) == 64
                     and all(c in "0123456789abcdef" for c in value) for value in context[key]))
    for key in omitted:
        del context[key]
    return messages, context, omitted, project_coverage(context)


def project_message_slice(messages, start):
    """Omit only a known redundant raw_text from copies of displayed messages."""
    def nonempty(value):
        return type(value) is str and bool(value.strip())
    shown, omissions = [], []
    for index, message in enumerate(messages, start):
        content = message.get("content")
        enough = False
        kind = content.get("kind") if type(content) is dict else None
        if type(content) is dict and nonempty(content.get("raw_text")):
            if kind == "text":
                enough = (nonempty(content.get("text")) and content["raw_text"] == content["text"]
                          and message.get("text", content["text"]) == content["text"])
            elif kind == "quote":
                attributes = content.get("attributes")
                enough = (type(attributes) is dict and nonempty(attributes.get("title"))
                          and nonempty(attributes.get("referenced_text")))
            elif kind == "image":
                image = message.get("image")
                enough = (type(image) is dict and image.get("status") in ("decoded", "partial")
                          and type(image.get("representations")) is list and any(
                              type(row) is dict and row.get("status") == "decoded" and nonempty(row.get("path"))
                              for row in image["representations"]))
            elif kind == "audio":
                voice = message.get("voice")
                if type(voice) is dict:
                    transcript, audio = voice.get("transcript"), voice.get("audio")
                    enough = ((type(transcript) is dict and transcript.get("status") == "ready" and nonempty(transcript.get("text")))
                              or (type(audio) is dict and audio.get("status") == "ready" and nonempty(audio.get("local_path"))
                                  and audio.get("content_type") == "audio/wav"))
        if enough:
            message = dict(message)
            message["content"] = dict(content)
            del message["content"]["raw_text"]
            omissions.append(dict(message_index=index, path=["content", "raw_text"], kind=kind))
        shown.append(message)
    return shown, omissions


def finish_view(view, code):
    """Bound diagnostics and explicit raw slices; never clip a message object."""
    hidden = {}
    for field in ("business_status", "spawn_error", "captured_at", "coverage_omissions"):
        if field in view and len(encode(view[field])) > (4096 if field == "coverage_omissions" else 1024):
            view[field] = None
            hidden[field] = "result_file" if field in {"spawn_error", "captured_at"} else "stdout_file"
    if hidden:
        view["omitted_header_fields"] = hidden
    for field in ("stderr", "stderr_base64"):
        if field in view and len(encode(view[field])) > 4000:
            del view[field]
            view["stderr_requires_raw_chunk"] = True
    # A sample can shrink further to reserve space for full message objects.
    while view["issues"] and len(encode(view)) > DISPLAY_LIMIT:
        view["issues"].pop()
    view["issues_omitted"] = view["issues_total"] - len(view["issues"])
    if view["issues_omitted"]:
        view["issues_raw_hint"] = "page --result-file RESULT --raw stdout --offset 0 --length 4000"
    if len(encode(view)) > DISPLAY_LIMIT and view["display"] in {"messages", "status"}:
        view.pop("messages", None)
        view.pop("message_omissions", None)
        view.update(requested_start=view["start"], requested_end=view["end"],
                    start=0 if view["total_messages"] is not None else None,
                    end=0 if view["total_messages"] is not None else None,
                    remaining=view["total_messages"], messages_displayed=0,
                    display="raw_chunk_required", reason="view too large; no message text was truncated",
                    raw_hint="page --result-file RESULT --raw stdout --offset 0 --length 4000")
        if len(encode(view)) > DISPLAY_LIMIT:
            view.pop("context", None)
            view["context_requires_raw_chunk"] = True
    while len(encode(view)) > DISPLAY_LIMIT and view["display"] == "raw_chunk":
        chunk = view["chunk"]
        data = chunk["text"] if chunk["unit"] == "unicode_characters" else base64.b64decode(chunk["data_base64"])
        require(len(data) > 1, "raw header cannot fit display limit")
        data = data[:max(1, len(data) // 2)]
        if chunk["unit"] == "unicode_characters":
            chunk["text"] = data
        else:
            chunk["data_base64"] = base64.b64encode(data).decode()
        chunk.update(end=chunk["offset"] + len(data), remaining=chunk["total"] - chunk["offset"] - len(data), adjusted_for_display_limit=True)
    require(len(encode(view)) <= DISPLAY_LIMIT, "view header cannot fit display limit; full copy is retained")
    return view, code


def coverage_determination(result, outcome):
    """§5 hard-check ③: UNIFIED coverage determination, ALWAYS emitted.
    `gaps`, `synced_at`, `freshness`, `history_incomplete` are explicitly present even
    when unknown/null. This object NEVER claims coverage: status=ready / empty result /
    'no gaps' / 'cli_returned' are NOT date-coverage or freshness evidence. Values are
    copied from the CLI result only when explicitly present; the wrapper derives NO
    'covered/complete/fresh' conclusion and never lets cli_returned be proof."""
    d = result if type(result) is dict else {}

    def pick(key):
        for scope in (d, d.get("result"), d.get("body"), d.get("coverage")):
            if type(scope) is dict and key in scope:
                return scope[key]
        return None

    return dict(
        gaps=pick("gaps"), synced_at=pick("synced_at"),
        freshness=pick("freshness"), history_incomplete=pick("history_incomplete"),
        outcome=outcome, determination="unknown_unless_explicitly_evidenced",
        ready_is_not_coverage_evidence=True, empty_result_is_not_coverage_evidence=True,
        no_gaps_is_not_coverage_evidence=True,
        cli_returned_is_not_coverage_or_freshness_proof=True,
        note=("status=ready / empty / 'no gaps' / cli_returned are NOT date-coverage "
              "evidence; gaps/synced_at/freshness/history_incomplete stay explicit "
              "even when null. original_exit/wrapper_exit/outcome are separate."),
    )


def suggestion_display(candidate):
    """Display-only projection for an ambiguous/none candidate list (H). Surfaces enough
    distinguishing info (remark / display name / account-or-stable-id / member count /
    owning shard) so the USER can pick in ONE message. RED LINE (G): candidates are NEVER
    merged by label_normalized — two distinct originals stay two entries even when their
    normalized labels collide. The stable id here is INFORMATIONAL ONLY (key 'account'); it
    is not bindable: auto-bind still happens only for a UNIQUE match via unique_stable_id,
    so showing it does NOT relax ①. No extra source open, no new data pull — only fields the
    CLI already returned."""
    if type(candidate) is not dict:
        return candidate
    display = {k: v for k, v in candidate.items() if k not in SUGGESTION_ID_KEYS}
    name = (candidate.get("display_name") or candidate.get("remark") or candidate.get("nickname")
            or candidate.get("name") or candidate.get("title") or "")
    if type(name) is str and name.strip():
        display["label"] = name.strip()
        display["label_normalized"] = normalize_name(name)
    else:
        display["label"] = None
        display["label_normalized"] = None
    # H: distinguishing fields already returned by the CLI (no extra source open / no new pull).
    sid = candidate_stable_id(candidate)
    if sid:
        display["account"] = sid  # informational only; not a bind directive
    shard = candidate.get("shard") or candidate.get("source") or candidate.get("scope")
    if shard not in (None, ""):
        display["shard"] = shard
    for f in ("type", "kind", "is_group", "member_count", "members_count",
              "last_active_at", "last_message_at", "remark", "nickname"):
        v = candidate.get(f)
        if v not in (None, ""):
            display.setdefault(f, v)
    return display


def candidate_stable_id(candidate):
    """The CLI-reported stable id for a UNIQUE match only (never guesses)."""
    if type(candidate) is not dict:
        return None
    for key in STABLE_ID_KEYS:
        value = candidate.get(key)
        if type(value) is str and value.strip():
            return value
    return None


def extract_candidates(result):
    """§5 hard-check ①: return the raw suggestions/candidates list when the shape is
    present (top level or in a known result/body container), else None. The wrapper does
    NOT resolve names; it only classifies what the installed CLI already reported."""
    if type(result) is not dict:
        return None
    for scope in [result] + [result.get(k) for k in ("result", "body")]:
        if type(scope) is not dict:
            continue
        for key in SUGGESTION_KEYS:
            value = scope.get(key)
            if type(value) is list:
                return value
    return None


def classify_cli_error(result, spawn_error, status):
    """A3: classify CLI execution errors into structured buckets; never a generic throw.
    Returns {category, action, need_confirmation, retryable, escalate, reason} or None when
    there is no CLI error signal. Categories:
      transient             -> retryable (CLI could not start / indeterminate state)
      not_found             -> need clarification
      suggestions           -> need clarification (ambiguous / 0 candidates)
      conflict              -> escalate (generic CLI failure)
      scope_source_conflict -> escalate (real identity/source conflict; refuse to switch)
      unknown_error         -> escalate (unclassified)
    The wrapper never auto-resolves these; it surfaces the structured verdict so the caller
    decides (clarify / retry / escalate)."""
    def has(key):
        return type(result) is dict and key in result and result[key]
    text = ""
    if type(result) is dict:
        for key in ("error", "errors", "message", "detail"):
            val = result.get(key)
            if type(val) is str:
                text += val + " "
            elif type(val) is list:
                text += " ".join(str(v) for v in val if type(v) is str) + " "
    text = text.lower()
    if spawn_error:
        msg = str(spawn_error)
        if len(msg) > 200:
            msg = msg[:200] + "...(truncated; %d bytes total)" % len(msg)
        return dict(category="transient", action="retry", need_confirmation=False,
                    retryable=True, escalate=False, reason="CLI could not start: " + msg)
    if status == "not_found" or "not found" in text or "no such" in text:
        return dict(category="not_found", action="clarify", need_confirmation=True,
                    retryable=False, escalate=False, reason="target not found; ask user to clarify the target")
    if has("identity_conflicts") or has("source_conflicts") or status == "conflict" \
       or "source_conflict" in text or "identity_conflict" in text:
        return dict(category="scope_source_conflict", action="escalate", need_confirmation=False,
                    retryable=False, escalate=True,
                    reason="source/identity conflict; refuse to switch source/identity, escalate to user")
    cands = extract_candidates(result) if type(result) is dict else None
    if type(cands) is list and len(cands) != 1:
        return dict(category="suggestions", action="clarify", need_confirmation=True,
                    retryable=False, escalate=False,
                    reason="multiple/ambiguous or zero candidates; ask user to disambiguate")
    if status in ("failed", "error", "invalid"):
        return dict(category="conflict", action="escalate", need_confirmation=False,
                    retryable=False, escalate=True, reason="CLI reported failure; escalate to user")
    if status in ("unavailable", "pending", "blocked", "partial", "unknown"):
        return dict(category="transient", action="retry", need_confirmation=False,
                    retryable=True, escalate=False, reason="transient/indeterminate CLI state; retryable")
    if "error" in text or has("error") or has("errors"):
        return dict(category="unknown_error", action="escalate", need_confirmation=False,
                    retryable=False, escalate=True, reason="unclassified CLI error; escalate to user")
    return None


def name_resolution_determination(result):
    """UNIFIED structured verdict for a candidate shape. UNIQUE => user-authorized
    auto-bind permitted; NONE / AMBIGUOUS => structured stop, no bind, no auto-select."""
    raw = extract_candidates(result)
    count = len(raw)
    mismatch = bool(result.get("contact_target_type_mismatch")) if type(result) is dict else False
    display = [suggestion_display(c) for c in raw]
    labels = [d.get("label_normalized") for d in display if d.get("label_normalized")]
    normalized_label_collision = bool(display) and len(labels) != len(set(labels))
    common = dict(
        candidate_count=count, candidates=display,
        normalized_label_collision=normalized_label_collision,
        no_auto_select_first=True, no_read_other_candidate_content=True,
        no_account_or_source_switch=True,
        sending_reply_still_requires_explicit_target_and_full_body=True,
        source_identity_conflict_still_refused=True,
    )
    if count == 1:
        common.update(resolution="unique", need_confirmation=False,
                      auto_bind_permitted=True, candidates_bindable=True,
                      unique_stable_id=candidate_stable_id(raw[0]),
                      decision="bind", bound_stable_id=candidate_stable_id(raw[0]),
                      rule_basis=UNIQUE_RULE_BASIS,
                      contact_target_type_mismatch_ignored_for_unique=mismatch,
                      guidance=UNIQUE_GUIDANCE)
    elif count == 0:
        common.update(resolution="none", need_confirmation=True,
                      auto_bind_permitted=False, candidates_bindable=False,
                      unique_stable_id=None, decision="stop", bound_stable_id=None,
                      rule_basis=None,
                      contact_target_type_mismatch_ignored_for_unique=False,
                      guidance=NONE_GUIDANCE)
    else:
        common.update(resolution="ambiguous", need_confirmation=True,
                      auto_bind_permitted=False, candidates_bindable=False,
                      unique_stable_id=None, decision="stop", bound_stable_id=None,
                      rule_basis=None,
                      contact_target_type_mismatch_ignored_for_unique=False,
                      guidance=AMBIGUOUS_GUIDANCE)
    return common


def finalize_name_resolution(view, exit_code):
    """Bound the structured name_resolution object; never add message pass-through."""
    verdict = view["name_resolution"]
    while len(encode(view)) > DISPLAY_LIMIT and verdict["candidates"]:
        verdict["candidates"].pop()
        verdict["candidates_truncated"] = True
    require(len(encode(view)) <= DISPLAY_LIMIT, "name_resolution header cannot fit; use raw chunks")
    return view, exit_code


def media_ocr_determination(messages):
    """⑥: structured OCR status gating. Only image.ocr.status=='ready' permits the
    '图片文字（本地OCR）' label; empty/incomplete/failed/missing OCR are explained per
    item (bounded sample, full detail stays in the private raw copy). Original image
    links are always retained. The script itself never runs OCR/models/decode/source
    fetch; chat-level labeling is model behavior (semi-soft)."""
    items, total = [], 0
    if type(messages) is list:
        for index, message in enumerate(messages, 1):
            if type(message) is not dict or type(message.get("image")) is not dict:
                continue
            total += 1
            ocr = message["image"].get("ocr")
            status = ocr.get("status") if type(ocr) is dict else None
            text = ocr.get("text") if type(ocr) is dict else None
            if status == "ready" and type(text) is str and text.strip():
                reason, permitted = "ocr_ready_label_permitted", True
            elif status == "ready":
                reason, permitted = "ocr_ready_empty_text", False
            elif status in ("pending", "incomplete", "running"):
                reason, permitted = "ocr_incomplete", False
            elif status in ("failed", "error"):
                reason, permitted = "ocr_failed", False
            else:
                reason, permitted = "ocr_missing", False
            items.append(dict(index=index, status=status, reason=reason, label_permitted=permitted))
    shown = items[:3]
    return dict(policy="only_image_ocr_status_ready", image_total=total,
                image_links_retained=True,
                label_permitted_count=sum(1 for row in items if row["label_permitted"]),
                items=shown, items_omitted=max(0, len(items) - len(shown)),
                script_invokes_no_ocr_models_decode=True,
                chat_label_is_model_behavior_semi_soft=True)


def apply_delivery_metadata(view, result, saved, path, issues, messages=None):
    """⑧ `range/data_time/gaps/omissions` are ALWAYS present even when unknown; ⑤
    truncation forces 未取得范围 + same-copy page hint; ⑦ preflight marker; ⑥ media/OCR
    status. All compact; full original still readable from the same private copy."""
    d = result if type(result) is dict else {}
    argv = saved.get("argv", [])
    requested = None
    for flag in ("--request", "--latest"):
        value = flag_value(argv, flag)
        if value is not None:
            requested = {flag: value}
            break
    flagged = any(("overflow=true" in i or "truncated=true" in i or "has_more=true" in i)
                  for i in issues)
    truncated = bool(flagged or view.get("remaining"))
    view["range"] = dict(requested=requested,
                         status="未取得范围" if truncated else "本页按已取得结果",
                         truncated=truncated,
                         continuation_hint=("page --result-file " + str(path) + " --start <上一页end加1> --count 20"
                                            if truncated else None),
                         no_invented_dates_for_latest=True,
                         cross_run_stateless_note="unhardened")
    data_time = None
    for scope in (d, d.get("result"), d.get("coverage")):
        if type(scope) is dict:
            for key in ("source_observed_at", "synced_at", "observed_at", "freshness"):
                if key in scope:
                    data_time = scope[key]
                    break
        if data_time is not None:
            break
    view["data_time"] = data_time
    gaps = None
    for scope in (d, d.get("coverage"), d.get("result")):
        if type(scope) is dict and "gaps" in scope:
            gaps = scope["gaps"]
            break
    view["gaps"] = gaps
    view["omissions"] = dict(
        omitted_metadata_keys=list(view.get("omitted_metadata_keys") or []),
        coverage_omission_groups=len(view.get("coverage_omissions") or []),
        message_omissions_count=len(view.get("message_omissions") or []),
        full_raw_available=True)
    view["media_ocr"] = media_ocr_determination(messages if messages is not None else view.get("messages"))
    view["preflight"] = saved.get("preflight", "未执行(旧记录)")
    view["preflight_checks"] = saved.get("preflight_checks", {})
    # ⑦ classification_rules {path, sha256, source} + change hint (semi-soft).
    view["classification_rules"] = saved.get("classification_rules", q_unknown_rules())
    return view


def q_unknown_rules():
    """⑦ honest default when no preflight ran (e.g. wrapper_refused before capture)."""
    return dict(path=None, sha256=None, source="unknown", wrapper_resolved=False,
                verified_by="none", reference_sha256=None, changed=None,
                change_hint=RULES_CHANGE_HINT, change_detection="caller_side_semi_soft",
                note="preflight did not run; sha256=null (not fabricated).")


# --- F: pagination continuity (separate sidecar; never touches result.json/stdout.bin/stderr.bin) ---
def _page_state_path(result_file):
    p = Path(result_file)
    return p.parent / (p.name + ".page_state")


def read_page_state(result_file):
    """Return (last_served_end, total_messages) from the sidecar, or (None, None). The
    sidecar is a SEPARATE file from result.json/stdout.bin/stderr.bin, so reading/writing it
    never touches the read-only captured copy or the live source."""
    try:
        data = json.loads(_page_state_path(result_file).read_text(encoding="utf-8"))
        v = data.get("last_served_end")
        t = data.get("total_messages")
        return (int(v) if type(v) is int else None, int(t) if type(t) is int else None)
    except Exception:
        return (None, None)


def write_page_state(result_file, end, total_messages):
    try:
        p = _page_state_path(result_file)
        fd = os.open(str(p), os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, json.dumps(dict(last_served_end=int(end),
                                         total_messages=int(total_messages))).encode("utf-8"))
        finally:
            os.close(fd)
    except Exception:
        pass


def page(path, start=1, count=20, raw=None, offset=0, length=4000):
    require(type(start) is int and start >= 1 and type(count) is int and count >= 1, "positive message range required")
    require(type(offset) is int and offset >= 0 and type(length) is int and 1 <= length <= 8000, "invalid raw chunk range")
    path, saved, out, err = load_result(path)
    result, status, issues, total_issues, exit_code = analyse(out, saved["original_exit"], saved.get("spawn_error"))
    exit_code = 128 + abs(exit_code) if exit_code < 0 else exit_code
    # A1: real read-only backstop — refuse if the CLI reports it opened/touched the source.
    assert_source_not_opened(result)
    view = dict(result_file=str(path), original_exit=saved["original_exit"], wrapper_exit=exit_code,
                business_status=status, issues=issues, issues_total=total_issues, issues_full_source="stdout_file",
                captured_at=saved.get("captured_at"), stdout_file=str(path.parent / "stdout.bin"),
                stderr_file=str(path.parent / "stderr.bin"), stderr_bytes=len(err), spawn_error=saved.get("spawn_error"),
                total_messages=None, start=None, end=None, remaining=None, messages_displayed=0,
                outcome="cli_failed" if exit_code else "cli_returned")
    # A3: classify any CLI execution error into structured buckets (never a generic throw).
    cli_cls = classify_cli_error(result, saved.get("spawn_error"), status)
    if cli_cls is not None:
        view["cli_error_classification"] = cli_cls
        view["escalate"] = cli_cls["escalate"]
        view["need_user_clarification"] = cli_cls["need_confirmation"]
        view["retryable"] = cli_cls["retryable"]
    # ③: UNIFIED coverage determination is ALWAYS present (also on raw/refused paths).
    view["coverage"] = coverage_determination(result, view["outcome"])
    # ⑤⑥⑦⑧: delivery metadata is ALWAYS present, even on raw/refusal/name_resolution
    # paths (defaults are explicit, never fabricated). Recomputed after messages below.
    apply_delivery_metadata(view, result, saved, path, issues)
    if raw:
        require(raw in {"stdout", "stderr"}, "unknown raw stream")
        data = out if raw == "stdout" else err
        try:
            text = data.decode("utf-8")
            chunk = dict(unit="unicode_characters", text=text[offset:offset + length], total=len(text))
        except UnicodeError:
            chunk = dict(unit="bytes_base64", data_base64=base64.b64encode(data[offset:offset + length]).decode(), total=len(data))
        require(offset <= chunk["total"], "raw offset exceeds total")
        chunk.update(offset=offset, end=min(offset + length, chunk["total"]), remaining=max(0, chunk["total"] - offset - length), requested_length=length)
        view.update(display="raw_chunk", stream=raw, chunk=chunk)
        return finish_view(view, exit_code)
    # ① (new §5): any suggestions/candidates shape => structured name_resolution
    # verdict (unique / none / ambiguous). No normal status/messages pass-through;
    # only a UNIQUE match is user-authorized to be bound (by the caller, later).
    if extract_candidates(result) is not None:
        verdict = name_resolution_determination(result)
        # A4: the wrapper's one-shot resolution decision is explicit and binding here.
        require(verdict["decision"] != "stop" or verdict["bound_stable_id"] is None,
                "structured stop must not carry a bindable stable id")
        view.update(display="name_resolution", name_resolution=verdict,
                    need_confirmation=verdict["need_confirmation"],
                    auto_bind_permitted=verdict["auto_bind_permitted"],
                    unique_stable_id=verdict["unique_stable_id"],
                    name_resolution_decision=verdict["decision"],
                    bound_stable_id=verdict["bound_stable_id"])
        return finalize_name_resolution(view, exit_code)
    if len(err) <= 8000:
        try:
            view["stderr"] = err.decode("utf-8")
        except UnicodeError:
            view["stderr_base64"] = base64.b64encode(err).decode()
    else:
        view["stderr_requires_raw_chunk"] = True
    messages = None
    try:
        require(result is not None, "invalid JSON; use raw chunks")
        messages, context, omitted, coverage = messages_and_context(result)
        view.update(context=context, omitted_metadata_keys=omitted, coverage_omissions=coverage)
        if messages is None:
            view.update(display="status", reason="known status has no message result; message count is unknown")
        else:
            require(start <= max(1, len(messages)), "message start exceeds total")
            end = min(start - 1 + count, len(messages))
            prev_end, prev_total = read_page_state(path)
            contiguous = prev_end is None or start == prev_end + 1
            total_consistent = prev_total is None or prev_total == len(messages)
            view["page_continuity"] = dict(
                previous_end=prev_end, requested_start=start,
                expected_start=(prev_end + 1 if prev_end is not None else start),
                served_end=end, contiguous=contiguous,
                previous_total_messages=prev_total, total_messages=len(messages),
                total_messages_consistent=total_consistent)
            # F: never silently emit incomplete data; surface any gap/overlap as an honest
            # coverage anomaly (③ presentation), not a silent truncation.
            anomalies = []
            if prev_end is not None and not contiguous:
                anomalies.append(dict(kind="pagination_discontinuity",
                                      previous_end=prev_end, requested_start=start,
                                      note="页码跳号/重叠；缺口消息未补取，已取得的消息未伪造补全"))
            if prev_total is not None and not total_consistent:
                anomalies.append(dict(kind="total_messages_changed_across_pages",
                                      previous_total_messages=prev_total,
                                      total_messages=len(messages),
                                      note="同一 result_file 跨页 total_messages 不一致，可能源副本被改动；覆盖以实际取得为准"))
            if anomalies:
                view["coverage"] = dict(view["coverage"], pagination_anomaly=anomalies)
                for a in anomalies:
                    if a["kind"] == "pagination_discontinuity":
                        issues.append("分页不连续：上一页结束于 %d，本页从 %d 开始，可能存在跳号或覆盖缺口；缺口消息未补取" % (prev_end, start))
                    else:
                        issues.append("分页总数不一致：上一页 total_messages=%s，本页=%d；可能源副本已变，覆盖以实际取得为准" % (prev_total, len(messages)))
            write_page_state(path, end, len(messages))
            shown, message_omissions = project_message_slice(messages[start - 1:end], start)
            view.update(display="messages", total_messages=len(messages), start=start if messages else 0,
                        end=end, remaining=len(messages) - end, messages_displayed=end - start + 1 if messages else 0,
                        messages=shown)
            if message_omissions:
                view["message_omissions"] = message_omissions
    except Refusal as error:
        view.update(display="raw_chunk_required", reason=str(error),
                    raw_hint="page --result-file RESULT --raw stdout --offset 0 --length 4000")
    # Final pass: range/omissions/media_ocr reflect the actual message page (⑤⑥⑧).
    apply_delivery_metadata(view, result, saved, path, issues, messages)
    return finish_view(view, exit_code)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--directory", help="optional NEW directory inside system temp; existing names refuse")
    run.add_argument("--count", type=int, default=20)
    run.add_argument("cli", nargs=argparse.REMAINDER)
    read = commands.add_parser("page")
    read.add_argument("--result-file", required=True)
    read.add_argument("--start", type=int, default=1)
    read.add_argument("--count", type=int, default=20)
    read.add_argument("--raw", choices=("stdout", "stderr"))
    read.add_argument("--offset", type=int, default=0)
    read.add_argument("--length", type=int, default=4000)
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            require(args.count >= 1, "positive message count required")
            cli = args.cli[1:] if args.cli[:1] == ["--"] else args.cli
            view, code = page(capture(cli, args.directory), count=args.count)
        else:
            view, code = page(args.result_file, args.start, args.count, args.raw, args.offset, args.length)
        print(encode(view).decode("utf-8"))
        return code if 0 <= code <= 255 else 128 + abs(code)
    except (Refusal, OSError, ValueError, RecursionError) as error:
        detail = str(error)
        omitted = len(detail.encode("utf-8")) > 1024
        view = dict(outcome="wrapper_refused", original_exit=None, wrapper_exit=2,
                    error="wrapper diagnostic exceeds display budget" if omitted else detail,
                    error_requires_external_diagnostic=omitted)
        # ③: unified coverage determination is ALWAYS present, even on a refusal.
        view["coverage"] = coverage_determination(None, "wrapper_refused")
        # ⑧: the four delivery-metadata fields are explicit even when unknown.
        view["range"] = dict(requested=None, status="未取得范围", truncated=False,
                             continuation_hint=None, no_invented_dates_for_latest=True,
                             cross_run_stateless_note="unhardened")
        view["data_time"] = None
        view["gaps"] = None
        view["omissions"] = dict(omitted_metadata_keys=[], coverage_omission_groups=0,
                                 message_omissions_count=0, full_raw_available=False)
        # ⑦: rules metadata explicit even on a refusal (no sha obtained, not fabricated).
        view["classification_rules"] = q_unknown_rules()
        print(encode(view).decode("utf-8"))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
