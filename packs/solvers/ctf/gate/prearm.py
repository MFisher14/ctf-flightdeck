"""The pre-arm full gate's preflight (B-153): `ctf gate prearm` = these checks, then `gate run --full`.

The per-lane gate is the builder's quick check (five minutes, ctf/gate/budget.py). Arming is different:
it needs every test file, run index-free, nothing reused, and an environment that can actually run the
suite. The Huntress acceptance runs mixed both and failed for reasons that had nothing to do with the
code -- a worktree with no venv, a sandbox that refused binds, generated files out of date -- an hour
in. The preflight finds those in seconds, before the full gate starts:

    python     the children's interpreter (ctf.pyinterp) exists and imports pytest
    clean      the tree is clean (git status --porcelain, untracked included): a run on a dirty tree
               does not describe HEAD
    baseline   the baseline ledger loads and lists no test file that is gone (ctf/gate/baseline.py)
    loopback   this process can bind 127.0.0.1:0 (the suite's fake services need it; a sandbox that
               refuses it would turn the full gate into a page of ENV rows)
    <name>     each [[prearm]] command of tests/gate.toml, run as <python> <argv...> in the checkout
               (the generated-file checks: requirements_gen --check, engines generate/coverage --check,
               check-event); exit 0 = ok

Every check runs and reports, then any failure refuses the full gate (exit 4): nothing is skipped
silently and a refusal names each failing check with its output tail.
"""
from __future__ import annotations

import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from . import GateError

LAST_PREARM = "last-prearm.json"
EXIT_REFUSED = 4
COMMAND_TIMEOUT = 1800.0      # a generous ceiling for one generated-file check on a loaded host


@dataclass
class Check:
    name: str
    ok: bool
    detail: str

    def line(self) -> str:
        return f"PREFLIGHT {'ok  ' if self.ok else 'FAIL'} {self.name}: {self.detail}"


def _tail(text: str, n: int = 3) -> str:
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    return " / ".join(lines[-n:])[:400]


def check_python(python: str, source: str, root: Path) -> Check:
    try:
        r = subprocess.run([python, "-c", "import pytest; print(pytest.__version__)"], cwd=str(root),
                           capture_output=True, text=True, timeout=300)
    except OSError as e:
        return Check("python", False, f"{python} ({source}) cannot start: {e}")
    except subprocess.TimeoutExpired:
        return Check("python", False, f"{python} ({source}) did not answer in 300s")
    if r.returncode != 0:
        return Check("python", False, f"{python} ({source}) cannot import pytest: {_tail(r.stderr)}")
    return Check("python", True, f"{python} ({source}), pytest {r.stdout.strip()}")


def check_clean(root: Path) -> Check:
    try:
        r = subprocess.run(["git", "-C", str(root), "status", "--porcelain"], capture_output=True, text=True,
                           timeout=300)
    except (OSError, subprocess.TimeoutExpired) as e:
        return Check("clean", False, f"git status failed: {e}")
    if r.returncode != 0:
        return Check("clean", False, f"git status failed: {_tail(r.stderr)}")
    dirty = [ln for ln in r.stdout.splitlines() if ln.strip()]
    if dirty:
        return Check("clean", False, f"{len(dirty)} uncommitted path(s), e.g. {', '.join(d[3:] for d in dirty[:3])}"
                                     f": commit or remove them; a run on a dirty tree does not describe HEAD")
    return Check("clean", True, "no uncommitted or untracked path")


def check_baseline(root: Path, cfg) -> Check:
    from . import baseline
    if not cfg.baseline:
        return Check("baseline", False, "tests/gate.toml names no baseline ledger ('baseline = ...'): a red "
                                        "pre-arm run could not be attributed")
    try:
        led = baseline.load(Path(root) / cfg.baseline)
    except GateError as e:
        return Check("baseline", False, str(e))
    stale = led.stale(root)
    if stale:
        return Check("baseline", False, f"{len(stale)} entr(y/ies) name a test file that is gone: "
                                        f"{', '.join(e.id for e in stale[:3])}; remove them from {cfg.baseline}")
    return Check("baseline", True, f"{cfg.baseline}: {len(led)} known red test(s)")


def check_loopback(bind=None) -> Check:
    from ..testing import loopback
    bind = bind or loopback.bind
    try:
        s = bind("tcp")
    except loopback.LoopbackDenied as e:
        return Check("loopback", False, f"{e}")
    except OSError as e:
        return Check("loopback", False, f"cannot bind {loopback.HOST}:0: {e}")
    try:
        port = s.getsockname()[1]
    finally:
        s.close()
    return Check("loopback", True, f"bound {loopback.HOST}:{port}")


def check_command(name: str, argv, python: str, root: Path, timeout: float = COMMAND_TIMEOUT) -> Check:
    cmd = [python, *argv]
    shown = " ".join(argv)
    try:
        r = subprocess.run(cmd, cwd=str(root), capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL)
    except OSError as e:
        return Check(name, False, f"{shown}: cannot start: {e}")
    except subprocess.TimeoutExpired:
        return Check(name, False, f"{shown}: did not finish in {timeout:.0f}s")
    if r.returncode != 0:
        return Check(name, False, f"{shown}: exit {r.returncode}: {_tail(r.stdout + chr(10) + r.stderr)}")
    return Check(name, True, f"{shown}: exit 0")


def preflight(root: Path, cfg, *, python: str, source: str, bind=None) -> list[Check]:
    """Every preflight check, in order; none is skipped when an earlier one fails."""
    root = Path(root)
    checks = [check_python(python, source, root), check_clean(root), check_baseline(root, cfg),
              check_loopback(bind)]
    for name, argv in cfg.prearm:
        checks.append(check_command(name, argv, python, root))
    return checks


def record(state: Path, doc: dict) -> Path:
    """Write <state>/last-prearm.json (atomically)."""
    from .warm import _atomic_write
    p = Path(state) / LAST_PREARM
    _atomic_write(p, {"when": time.strftime("%Y-%m-%dT%H:%M:%S"), **doc})
    return p


def checks_json(checks) -> list[dict]:
    return [asdict(c) for c in checks]


def summary(result: str, checks, rep=None) -> str:
    bad = [c.name for c in checks if not c.ok]
    s = f"PREARM result={result} preflight={'ok' if not bad else 'fail:' + ','.join(bad)}"
    if rep is not None:
        tot = lambda k: sum(getattr(r, k) for r in rep.rows)  # noqa: E731
        s += (f" gate={'pass' if rep.ok else 'fail'} files={len(rep.rows)} fail={rep.count('FAIL')} "
              f"error={rep.count('ERROR')} timeout={rep.count('TIMEOUT')} env={rep.count('ENV')}")
        if rep.attributed:
            s += f" red_new={tot('red_new')} red_baseline={tot('red_baseline')}"
    return s
