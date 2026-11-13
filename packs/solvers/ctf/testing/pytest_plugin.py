"""Test markers for the master suite, plus the end-of-run "not run" report. Loaded by the root
conftest.py (pytest_plugins). Contract: docs/CONTRACTS.md section 9 (unit B-001 defined it, B-001d
made the report complete and added strict mode).

    @pytest.mark.needs_tool("radare2")       skip unless the binary is on PATH or in the venv bin
    @pytest.mark.needs_tool("py:cv2")        skip unless the Python module is importable
    @pytest.mark.needs_realdata              skip unless ctf.paths.realdata_root() is a directory
    @pytest.mark.needs_realdata("toolkit_x") ... and that subfolder exists under it (several marks:
                                             every named subfolder must exist)
    @pytest.mark.needs_loopback              skip unless this process can bind and connect on 127.0.0.1
    @pytest.mark.needs_jit                   skip unless a child process can run JIT code (and Unicorn)
    @pytest.mark.live                        never runs unless --run-live (or CTF_RUN_LIVE=1)
    @pytest.mark.slow                        a tag only: runs by default; deselect with -m "not slow"

needs_loopback and needs_jit (B-192, ctf/testing/capabilities.py) are for sandboxes: Codex's
workspace-write sandbox denies loopback bind and kills Unicorn. When the loopback probe fails, an
unmarked test that fails with a socket denial (EPERM/EACCES with no file name) is reported as not
run under needs_loopback too, so a sandboxed run does not show fake-service tests as failures. On a
host with loopback nothing changes: such a failure stays a failure.

A test that needs something absent is reported as NOT RUN with the reason, never passed. At the end
of every run the terminal report lists every test that did not run: marker skips, hand-written
skips, xfails, and parts of a test that the test itself reports as not run (see record_not_run).
The header counts them by kind (needs_tool, needs_realdata, live, skip, xfail, known-fail) and the
body groups them by reason. Never turn a missing dependency into a pass.

Strict mode: with CTF_STRICT_TESTS=1 (or --strict-not-run) a run in which anything did not run
exits 1 even when every test that ran passed, so CI and the pre-event gate cannot mistake a
partly-run suite for a green one.
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pytest

# The shared 127.0.0.1 port-0 harness (B-153): importing the fixture here registers `loopback` for
# every test; a sandbox-denied bind fails with a GATE-ENV marker, which the gate reports as ENV.
from .loopback import loopback_fixture  # noqa: E402,F401

MARKERS = (
    "needs_tool(name, ...): skip unless each named binary (or py:<module>) is available",
    "needs_realdata(subdir=None): skip unless the real-data corpus (CTF_REALDATA) is present",
    "needs_loopback: skip unless this process can bind and connect on 127.0.0.1 (sandboxes deny it)",
    "needs_jit: skip unless a child process can run JIT code and Unicorn (Codex's sandbox kills it)",
    "live: talks to a live service; never runs unless --run-live or CTF_RUN_LIVE=1",
    "slow: slow test; runs by default, deselect with -m 'not slow'",
)

# A test that ran but could not run all of itself (a real-data script with a known failing check, say)
# appends (reason, label) pairs under this user_properties key; they are reported like skips.
NOT_RUN_PROPERTY = "ctf_not_run"

_NOT_RUN_KEY = pytest.StashKey[list]()
_CONFIG: dict = {}  # the session config; reports do not carry it

KINDS = ("needs_realdata", "needs_tool", "needs_loopback", "needs_jit", "live", "known-fail", "xfail",
         "skip")


def pytest_addoption(parser):
    parser.addoption("--run-live", action="store_true", default=False,
                     help="run tests marked live (they contact real services)")
    parser.addoption("--strict-not-run", action="store_true", default=False,
                     help="exit 1 when any test did not run (same as CTF_STRICT_TESTS=1)")


def pytest_configure(config):
    for m in MARKERS:
        config.addinivalue_line("markers", m)
    config.stash[_NOT_RUN_KEY] = []
    _CONFIG["config"] = config


def tool_available(name: str) -> bool:
    if name.startswith("py:"):
        try:
            return importlib.util.find_spec(name[3:]) is not None
        except (ImportError, ValueError):
            return False
    if shutil.which(name):
        return True
    venv_bin = Path(sys.executable).parent / name
    return venv_bin.is_file() and os.access(venv_bin, os.X_OK)


def _run_live(config) -> bool:
    if config.getoption("--run-live"):
        return True
    from ctf import env
    return env.get_bool("CTF_RUN_LIVE", False)


def strict(config) -> bool:
    """True when a run with anything not run must fail (CTF_STRICT_TESTS=1 or --strict-not-run)."""
    if config.getoption("--strict-not-run", default=False):
        return True
    from ctf import env
    return env.get_bool("CTF_STRICT_TESTS", False)


def record_not_run(item, label: str, reason: str) -> None:
    """Report one part of a test that did not run (the test itself still passes or fails on what
    did run). It is listed in the NOT RUN report as `<nodeid> [<label>]` and counts for strict
    mode. Works under xdist: user_properties travel with the report."""
    for i, (key, value) in enumerate(item.user_properties):
        if key == NOT_RUN_PROPERTY:
            value.append([reason, label])
            return
    item.user_properties.append((NOT_RUN_PROPERTY, [[reason, label]]))


def pytest_runtest_setup(item):
    for mark in item.iter_markers("needs_tool"):
        if not mark.args:
            raise pytest.UsageError(f"{item.nodeid}: needs_tool needs at least one tool name")
        missing = [t for t in mark.args if not tool_available(t)]
        if missing:
            pytest.skip(f"needs_tool: {', '.join(missing)} not available")
    marks = list(item.iter_markers("needs_realdata"))
    if marks:
        from ctf import paths
        root = paths.realdata_root()
        targets = []
        for mark in marks:
            sub = mark.args[0] if mark.args else mark.kwargs.get("subdir")
            targets.append(root / sub if sub else root)
        if not root.is_dir():
            pytest.skip(f"needs_realdata: {root} not present (set CTF_REALDATA)")
        if not any(root.iterdir()):
            pytest.skip(f"needs_realdata: {root} is empty (set CTF_REALDATA)")
        missing = [t for t in targets if not t.is_dir()]
        if missing:
            names = ", ".join(str(t.relative_to(root)) for t in missing)
            pytest.skip(f"needs_realdata: {names} not present under {root} (set CTF_REALDATA)")
    if item.get_closest_marker("needs_loopback") is not None:
        from . import capabilities
        cap = capabilities.loopback()
        if not cap.ok:
            pytest.skip(f"needs_loopback: {cap.reason}")
    if item.get_closest_marker("needs_jit") is not None:
        from . import capabilities
        cap = capabilities.jit()
        if not cap.ok:
            pytest.skip(f"needs_jit: {cap.reason}")
    if item.get_closest_marker("live") is not None and not _run_live(item.config):
        pytest.skip("live: not run by default (pass --run-live)")


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item, call):
    """B-192: in a process that cannot use loopback, a test that failed on a socket denial did not
    run; report it as a needs_loopback skip (NOT RUN, and strict mode fails the run). Only when the
    loopback probe failed: on a host with loopback the failure stands."""
    report = yield
    if report.failed and call.when in ("setup", "call") and call.excinfo is not None:
        from . import capabilities
        if capabilities.is_socket_denial(call.excinfo.value):
            cap = capabilities.loopback()
            if not cap.ok:
                path, lineno, _ = item.reportinfo()
                report.outcome = "skipped"
                report.longrepr = (str(path), (lineno or 0) + 1,
                                   f"needs_loopback: {cap.reason} (auto: the test failed on "
                                   f"{type(call.excinfo.value).__name__}: {call.excinfo.value})")
    return report


# Script-style test modules (carried from Huntress and CSCTF) check with a helper that prints
# "FAIL <label>" and records the failure in a module-level sink instead of raising: FAILED / FAILS /
# FAILURES lists, a FAIL counter, or a RESULTS list of booleans. Pytest saw every such test pass.
# The guard below snapshots those sinks around each test call and fails the test when one grew, so a
# check() failure is a pytest failure. tools/test_audit.py counts a helper that feeds one of these
# sinks as asserting for the same reason; keep the two lists in step.
FAILURE_SINKS = ("FAILED", "FAILS", "FAILURES", "FAIL")
BOOL_SINKS = ("RESULTS",)


def _sink_state(module) -> dict:
    state = {}
    if module is None:
        return state
    g = vars(module)
    for name in FAILURE_SINKS:
        v = g.get(name)
        if isinstance(v, list):
            state[name] = ("list", len(v))
        elif isinstance(v, int) and not isinstance(v, bool):
            state[name] = ("int", v)
    for name in BOOL_SINKS:
        v = g.get(name)
        if isinstance(v, list) and all(isinstance(x, bool) for x in v):
            state[name] = ("bools", len(v))
    return state


def _sink_growth(module, before: dict) -> list[tuple[str, str]]:
    """[(sink, check label)] recorded since `before`."""
    out = []
    g = vars(module)
    for name, (kind, n) in before.items():
        v = g.get(name)
        if kind == "list" and isinstance(v, list) and len(v) > n:
            out += [(name, str(x)[:200]) for x in v[n:]]
        elif kind == "int" and isinstance(v, int) and v > n:
            out.append((name, f"counter rose by {v - n}"))
        elif kind == "bools" and isinstance(v, list):
            bad = sum(1 for x in v[n:] if x is False)
            if bad:
                out.append((name, f"{bad} failed check(s)"))
    return out


# Known failures the guard exposed: tests/known_failures.toml, one table per test node id:
#
#   ["tests/test_x.py::test_y"]
#   reason = "who owns the fix and why it fails"        (required)
#   checks = ["label of a check that fails", ...]       (optional; omitted = any check may fail)
#   strict = false                                      (optional; for an order- or state-dependent failure)
#
# A listed test whose failing checks are all listed is reported xfail ("known-fail: <reason>"), so it
# shows in the NOT RUN report and fails a CTF_STRICT_TESTS=1 run. A check not listed still fails the
# test, and a listed test whose checks all pass fails with "remove the entry" (unless strict = false),
# so the list cannot go stale. Labels are compared with every number replaced by "#" (labels carry
# timings and counts).
KNOWN_FAILURES_FILE = "tests/known_failures.toml"
_KNOWN: dict = {}


def norm_label(label: str) -> str:
    import re
    return re.sub(r"\d+(?:\.\d+)?", "#", " ".join(str(label).split()))[:200]


def known_failures(config) -> dict:
    """{nodeid: (reason, set of normalised labels or None, strict)} from tests/known_failures.toml."""
    if "data" in _KNOWN:
        return _KNOWN["data"]
    import tomllib
    path = Path(str(config.rootpath)) / KNOWN_FAILURES_FILE
    data = {}
    if path.is_file():
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
        for nodeid, entry in raw.items():
            if not isinstance(entry, dict) or not isinstance(entry.get("reason"), str) or not entry["reason"]:
                raise pytest.UsageError(f"{path}: [{nodeid!r}] needs a non-empty reason")
            extra = set(entry) - {"reason", "checks", "strict"}
            if extra:
                raise pytest.UsageError(f"{path}: [{nodeid!r}] unknown key(s) {sorted(extra)}")
            checks = entry.get("checks")
            if checks is not None and (not isinstance(checks, list) or not all(isinstance(c, str) for c in checks)):
                raise pytest.UsageError(f"{path}: [{nodeid!r}] checks must be a list of strings")
            strict_entry = entry.get("strict", True)
            if not isinstance(strict_entry, bool):
                raise pytest.UsageError(f"{path}: [{nodeid!r}] strict must be true or false")
            data[nodeid] = (entry["reason"], None if checks is None else {norm_label(c) for c in checks},
                            strict_entry)
    _KNOWN["data"] = data
    return data


@pytest.hookimpl(wrapper=True)
def pytest_runtest_call(item):
    module = getattr(item, "module", None) if isinstance(item, pytest.Function) else None
    before = _sink_state(module)
    result = yield
    if before:
        grown = _sink_growth(module, before)
        known = known_failures(item.config).get(item.nodeid)
        if grown and known:
            reason, labels, _ = known
            new = [(s, lab) for s, lab in grown if labels is not None and norm_label(lab) not in labels]
            if not new:
                pytest.xfail(f"known-fail: {reason}")
            grown = new
        if grown:
            pytest.fail("check() recorded a failure without raising (module failure list grew):\n  "
                        + "\n  ".join(f"{s}: {lab}" for s, lab in grown), pytrace=False)
        if known and known[2]:
            pytest.fail(f"listed in {KNOWN_FAILURES_FILE} as failing ({known[0]}) but every check passed: "
                        f"remove the entry", pytrace=False)
    return result


def kind_of(reason: str) -> str:
    for k in KINDS:
        if reason.startswith(k + ":") or reason == k:
            return k
    return "skip"


def pytest_runtest_logreport(report):
    store = _CONFIG["config"].stash[_NOT_RUN_KEY]
    for key, value in getattr(report, "user_properties", ()):
        if key == NOT_RUN_PROPERTY and report.when == "call":
            for reason, label in value:
                store.append((f"{report.nodeid} [{label}]", reason))
    if not report.skipped:
        return
    if report.when == "call" and hasattr(report, "wasxfail"):
        w = report.wasxfail
        reason = w if w.startswith("known-fail:") else f"xfail: {w}" if w else "xfail"
    else:
        lr = report.longrepr
        reason = lr[2] if isinstance(lr, tuple) and len(lr) == 3 else str(lr)
        if reason.startswith("Skipped: "):
            reason = reason[len("Skipped: "):]
    store.append((report.nodeid, reason))


@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session, exitstatus):
    config = session.config
    if hasattr(config, "workerinput"):  # xdist worker: the controller decides
        return
    if strict(config) and config.stash.get(_NOT_RUN_KEY, []) and session.exitstatus == 0:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    if hasattr(config, "workerinput"):  # xdist worker: the controller prints the summary
        return
    not_run = config.stash.get(_NOT_RUN_KEY, [])
    if not not_run:
        return
    by_reason: dict[str, list[str]] = defaultdict(list)
    for nodeid, reason in not_run:
        by_reason[reason].append(nodeid)
    kinds = Counter(kind_of(reason) for _, reason in not_run)
    tr = terminalreporter
    is_strict = strict(config)
    head = ", ".join(f"{k} {kinds[k]}" for k in KINDS if kinds[k])
    tr.section(f"NOT RUN: {len(not_run)} test(s) did not run ({head})", sep="=",
               red=is_strict, yellow=not is_strict, bold=True)
    for reason in sorted(by_reason, key=lambda r: (KINDS.index(kind_of(r)), -len(by_reason[r]), r)):
        ids = by_reason[reason]
        tr.write_line(f"{len(ids)} x {reason}")
        for nodeid in sorted(ids):
            tr.write_line(f"    {nodeid}")
    if is_strict:
        tr.write_line(f"CTF_STRICT_TESTS: {len(not_run)} test(s) did not run, so this run fails (exit 1)",
                      red=True, bold=True)
    else:
        tr.write_line("Not run is not passed. Set CTF_STRICT_TESTS=1 to make this run fail.", yellow=True)
