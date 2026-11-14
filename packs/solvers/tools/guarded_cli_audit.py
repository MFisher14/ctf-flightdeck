#!/usr/bin/env python3
"""Audit Python CLIs for guarded ``--help``/no-args/garbage handling.

Every discovered ``solvers/**/*.py`` and ``tools/**/*.py`` file with a ``__main__`` guard is run in
a temporary working directory under three synthetic invocations.  A startup shim blocks Python
network sockets, external subprocesses and ``os.system``; stdout/stderr go to temporary files and
only a bounded tail is read.  The audit flags tracebacks, signals and timeouts.  It never supplies a
real target, token, or challenge file.

Usage: ``.venv/bin/python tools/guarded_cli_audit.py [--path PREFIX ...] [--json]``.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[1]))
    from ctf import env as ctf_env

REPO = Path(__file__).resolve().parent.parent
MAX_CAPTURE = 1 << 20
DEFAULT_TIMEOUT = 3.0
MAX_WORKERS = 12

_SHIM = r'''# Synthetic CLI-audit startup policy: no network and no child processes.
import ipaddress
import os
import socket
import subprocess

def _blocked(*args, **kwargs):
    raise RuntimeError("offline CLI audit blocked external I/O")

_real_getaddrinfo = socket.getaddrinfo
def _literal_getaddrinfo(host, *args, **kwargs):
    # Optional packet libraries resolve numeric defaults while importing.  Let the C library parse
    # only literal addresses/localhost; names that could cause DNS remain blocked, and connect is
    # blocked independently below.
    if host in (None, "", "localhost"):
        return _real_getaddrinfo(host, *args, **kwargs)
    try:
        ipaddress.ip_address(str(host).split("%", 1)[0])
    except ValueError:
        return _blocked(host, *args, **kwargs)
    return _real_getaddrinfo(host, *args, **kwargs)

socket.create_connection = _blocked
socket.getaddrinfo = _literal_getaddrinfo
socket.socket.connect = _blocked
socket.socket.connect_ex = _blocked
socket.socket.bind = _blocked
socket.socket.listen = _blocked
subprocess.Popen = _blocked
subprocess.run = _blocked
subprocess.call = _blocked
subprocess.check_call = _blocked
subprocess.check_output = _blocked
os.system = _blocked
'''


def discover(prefixes=None) -> list[Path]:
    roots = [REPO / "solvers", REPO / "tools"]
    selected = []
    wanted = [str(value).replace("\\", "/").rstrip("/") for value in (prefixes or [])]
    for root in roots:
        for path in root.rglob("*.py"):
            # Unit/self-test scripts are executable test fixtures, not user-facing CLIs.
            if path.name.startswith(("test_", "selftest")):
                continue
            relative = path.relative_to(REPO).as_posix()
            if wanted and not any(relative == prefix or relative.startswith(prefix + "/") for prefix in wanted):
                continue
            try:
                text = path.read_text("utf-8", errors="replace")
            except OSError:
                continue
            if "__main__" in text and "if __name__" in text:
                selected.append(path)
    return sorted(selected)


def _tail(handle) -> str:
    handle.flush()
    size = handle.tell()
    handle.seek(max(0, size - MAX_CAPTURE))
    return handle.read(MAX_CAPTURE).decode("utf-8", "replace")


def _run_case(path: Path, case: str, garbage: Path, shim: Path, timeout: float) -> dict:
    args = {"help": ["--help"], "no_args": [], "garbage": [str(garbage)]}[case]
    env = dict(os.environ)
    old_path = env.get("PYTHONPATH")
    env["PYTHONPATH"] = os.pathsep.join([str(shim), str(REPO)] + ([old_path] if old_path else []))
    env.update({"CTF_OFFLINE_AUDIT": "1", "CTF_TESTING": "1", "CTF_TOKEN": "",
                "CTF_TOKEN": "", "PYTHONDONTWRITEBYTECODE": "1"})
    command = [sys.executable, str(path), *args]
    timed_out = False
    returncode = None
    with tempfile.TemporaryDirectory(prefix="csctf-cli-case-") as work, \
            tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(command, cwd=work, env=env, stdout=stdout, stderr=stderr,
                                       start_new_session=True)
            try:
                returncode = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    process.kill()
                process.wait(timeout=1)
                returncode = process.returncode
        except OSError as exc:
            return {"case": case, "ok": False, "error": f"spawn failed: {exc}"}
        out, err = _tail(stdout), _tail(stderr)
    combined = out + "\n" + err
    traceback = "Traceback (most recent call last)" in combined
    signaled = isinstance(returncode, int) and returncode < 0
    return {"case": case, "ok": not (timed_out or traceback or signaled),
            "returncode": returncode, "timeout": timed_out, "traceback": traceback,
            "stdout_tail": out[-2000:], "stderr_tail": err[-4000:]}


def audit(paths: list[Path], timeout: float = DEFAULT_TIMEOUT) -> dict:
    results = {path.relative_to(REPO).as_posix(): [] for path in paths}
    with tempfile.TemporaryDirectory(prefix="csctf-cli-audit-") as temp:
        temp_path = Path(temp)
        shim = temp_path / "shim"
        shim.mkdir()
        (shim / "sitecustomize.py").write_text(_SHIM, encoding="utf-8")
        garbage = temp_path / "garbage.bin"
        garbage.write_bytes(b"not-a-valid-artifact\x00\xff\n{broken-json")
        jobs = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            for path in paths:
                for case in ("help", "no_args", "garbage"):
                    future = pool.submit(_run_case, path, case, garbage, shim, timeout)
                    jobs.append((path.relative_to(REPO).as_posix(), future))
            for relative, future in jobs:
                try:
                    results[relative].append(future.result())
                except Exception as exc:  # the auditor itself reports, never hides, one worker failure
                    results[relative].append({"case": "internal", "ok": False,
                                              "error": f"{type(exc).__name__}: {exc}"})
    failed = {path: rows for path, rows in results.items() if any(not row.get("ok") for row in rows)}
    return {"files": len(paths), "cases": len(paths) * 3, "failed_files": len(failed),
            "failures": failed, "results": results}


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # pragma: no cover
        raise ValueError(message)


def main(argv=None) -> int:
    if ctf_env.get("CTF_OFFLINE_AUDIT") == "1" and argv is None and not sys.argv[1:]:
        print("usage: guarded_cli_audit.py [--path PREFIX] [--json]", file=sys.stderr)
        return 2
    parser = _Parser(prog="guarded_cli_audit.py")
    parser.add_argument("--path", action="append", default=[], help="repo-relative file/directory prefix")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        if not 0.1 <= args.timeout <= 30:
            raise ValueError("timeout must be between 0.1 and 30 seconds")
        paths = discover(args.path)
        if not paths:
            raise ValueError("no guarded Python CLIs matched")
        report = audit(paths, args.timeout)
        if args.json:
            print(json.dumps(report, sort_keys=True))
        else:
            print(f"audited {report['files']} files / {report['cases']} cases; "
                  f"{report['failed_files']} file(s) failed")
            for path, rows in report["failures"].items():
                for row in rows:
                    if not row.get("ok"):
                        why = "timeout" if row.get("timeout") else "traceback" if row.get("traceback") else row.get("error", "signal")
                        print(f"FAIL {path} [{row.get('case')}]: {why}")
        return 1 if report["failed_files"] else 0
    except (OSError, TypeError, ValueError, OverflowError) as exc:
        print(f"guarded_cli_audit: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
