#!/usr/bin/env python3
"""Per-test comparison of two pytest junit XML files (two runs of tools/suite.py).

    python tools/junit_diff.py OLD.xml NEW.xml [--known-flaky FILE] [--rerun-root CHECKOUT] [--rerun N]
                               [--no-sandbox] [--json OUT.json] [--fail-on-regression]

Each test case is keyed `<classname>::<name>` (a collection error, which has no classname, by its name)
and given one status: passed, skipped, xfailed, failed or error (a key seen several times, as xdist
reports a file's collection error once per worker, keeps its worst status, the first one seen on a
tie; a testcase with both a <skipped> and a <failure>/<error> child is failed/error). It prints both
runs' status counts, then:

  newly_bad  failed/error in NEW, and passed, skipped or absent in OLD
  fixed      failed/error in OLD, passed in NEW
  added / removed   keys only in NEW / only in OLD (a parametrize id that embeds a timestamp shows as one
             of each)

--known-flaky FILE   one junit key per line (# comments allowed): those keys are listed apart as
                     known_flaky_failed, never as newly bad. The file must exist.
--rerun-root DIR     re-run each newly bad test alone, N times (--rerun, default 3), in that checkout,
                     under the suite's network sandbox (tools/suite.sb; --no-sandbox to skip it), and
                     classify it:
                       regression    failed every isolated run
                       passes_alone  passed at least once alone (flaky, load- or order-dependent: judge it)
                       unresolved    its node id could not be rebuilt from the key, or pytest neither
                                     passed nor failed it (not collected, usage error, timeout)
--baseline FILE      the tracked baseline ledger (tests/gate_baseline.toml, B-153): its tests that went bad
                     are listed apart as baseline_failed with the ledger's kind, date and reason, never as
                     newly bad. A missing or malformed ledger is a usage error.
--json OUT           write the whole result as JSON.
--fail-on-regression exit 1 when a newly bad test is left that is not passes_alone (all of them without
                     --rerun-root).

Exit status: 0 (1 only with --fail-on-regression); 2 on a usage error, a missing or unreadable file.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROFILE = HERE / "suite.sb"
BAD = {"failed", "error"}
RANK = {"passed": 0, "skipped": 1, "xfailed": 1, "failed": 3, "error": 3}
RERUN_TIMEOUT = 600


class Usage(Exception):
    """A missing or unreadable input: exit 2 with this message."""


def case_status(tc: ET.Element) -> str:
    """One testcase's status. A <failure> or <error> child wins over a <skipped> one in any order (a
    test skipped in its call can still error in teardown); between failure and error the first wins."""
    st = "passed"
    for ch in tc:
        if ch.tag == "failure":
            return "failed"
        if ch.tag == "error":
            return "error"
        if ch.tag == "skipped" and st == "passed":
            t = f"{ch.get('type') or ''} {ch.get('message') or ''}".lower()
            st = "xfailed" if "xfail" in t else "skipped"
    return st


def load(path) -> dict[str, str]:
    """{junit key: status} of one junit XML file."""
    try:
        root = ET.parse(path).getroot()
    except FileNotFoundError:
        raise Usage(f"no such junit file: {path}")
    except (ET.ParseError, OSError) as e:
        raise Usage(f"cannot read junit file {path}: {e}")
    out: dict[str, str] = {}
    for tc in root.iter("testcase"):
        cls, name = tc.get("classname") or "", tc.get("name") or ""
        key = f"{cls}::{name}" if cls else name
        st = case_status(tc)
        prev = out.get(key)
        # the worst status wins; on a tie (failed vs error, skipped vs xfailed) the first one seen stays
        if prev is None or RANK[st] > RANK[prev]:
            out[key] = st
    return out


def load_known_flaky(path) -> set[str]:
    p = Path(path)
    if not p.is_file():
        raise Usage(f"--known-flaky file not found: {p}")
    return {ln.strip() for ln in p.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.strip().startswith("#")}


def load_baseline(path) -> dict[str, dict]:
    """{junit key: {id, kind, since, reason}} from the tracked baseline ledger (B-153,
    ctf/gate/baseline.py). A missing or malformed ledger is a usage error naming the problem."""
    root = str(HERE.parent)
    if root not in sys.path:
        sys.path.insert(0, root)
    from ctf.gate import GateError, baseline
    try:
        led = baseline.load(Path(path))
    except GateError as e:
        raise Usage(str(e))
    return {baseline.junit_key(i): {"id": i, "kind": e.kind, "since": e.since.isoformat(), "reason": e.reason}
            for i, e in led.entries.items()}


def compare(old: dict[str, str], new: dict[str, str], flaky: set[str] = frozenset(),
            base: dict[str, dict] | None = None) -> dict:
    """Per-test comparison. `flaky` keys and `base` (the baseline ledger, load_baseline) keys that went
    bad are listed apart from newly_bad: `known_flaky_failed` and `baseline_failed` (with the ledger's
    reason and date), so a red run is attributable."""
    base = base or {}
    newly_bad = sorted(k for k, s in new.items() if s in BAD and old.get(k) not in BAD)
    known = [k for k in newly_bad if k in flaky]
    on_base = [dict(key=k, **base[k]) for k in newly_bad if k not in flaky and k in base]
    newly_bad = [k for k in newly_bad if k not in flaky and k not in base]
    fixed = sorted(k for k, s in old.items() if s in BAD and new.get(k) == "passed")
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    return {"counts_old": dict(Counter(old.values())), "counts_new": dict(Counter(new.values())),
            "newly_bad": newly_bad, "known_flaky_failed": known, "baseline_failed": on_base, "fixed": fixed,
            "added_count": len(added), "removed_count": len(removed),
            "added_sample": added[:40], "removed": removed[:200]}


def nodeid(key: str, root) -> str | None:
    """junit key 'a.b.test_x.TestY::test_z[p]' -> 'a/b/test_x.py::TestY::test_z[p]', found under root;
    None when no prefix of the dotted classname is a .py file there."""
    if "::" not in key:
        return None
    cls, name = key.split("::", 1)
    parts = cls.split(".")
    for i in range(len(parts), 0, -1):
        rel = "/".join(parts[:i]) + ".py"
        if (Path(root) / rel).is_file():
            return "::".join([rel, *parts[i:], name])
    return None


def rerun_command(nid: str, sandbox: bool = True, python: str | None = None) -> list[str]:
    cmd = [python or sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--timeout", "300", nid]
    return (["sandbox-exec", "-f", str(PROFILE)] + cmd) if sandbox else cmd


def rerun(nid: str, root, n: int, sandbox: bool = True) -> tuple[int, int, int]:
    """(passes, fails, other) over n isolated runs of one node id."""
    passes = fails = other = 0
    for _ in range(n):
        try:
            rc = subprocess.run(rerun_command(nid, sandbox), cwd=str(root), capture_output=True, text=True,
                                timeout=RERUN_TIMEOUT).returncode
        except subprocess.TimeoutExpired:
            rc = -1           # neither passed nor failed: counted as other, so it can only be unresolved
        if rc == 0:
            passes += 1
        elif rc == 1:
            fails += 1
        else:
            other += 1
    return passes, fails, other


def classify(passes: int, fails: int, n: int) -> str:
    if fails == n:
        return "regression"
    if passes:
        return "passes_alone"
    return "unresolved"


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="tools/junit_diff.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("old", help="the earlier run's junit XML")
    ap.add_argument("new", help="the later run's junit XML")
    ap.add_argument("--known-flaky", help="file of junit keys to report apart (one per line)")
    ap.add_argument("--baseline", help="the tracked baseline ledger (tests/gate_baseline.toml): its tests are "
                                       "reported apart with their reason and date (B-153)")
    ap.add_argument("--rerun-root", help="checkout to re-run each newly bad test in, alone")
    ap.add_argument("--rerun", type=int, default=3, help="isolated runs per newly bad test (default 3)")
    ap.add_argument("--no-sandbox", action="store_true", help="re-run without the sandbox-exec network sandbox")
    ap.add_argument("--json", help="write the result as JSON to this file")
    ap.add_argument("--fail-on-regression", action="store_true",
                    help="exit 1 when a newly bad test is not passes_alone")
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = _parser()
    args = ap.parse_args(argv)
    if args.rerun < 1:
        ap.error("--rerun must be at least 1")
    try:
        old, new = load(args.old), load(args.new)
        flaky = load_known_flaky(args.known_flaky) if args.known_flaky else set()
        base = load_baseline(args.baseline) if args.baseline else {}
        if args.rerun_root and not Path(args.rerun_root).is_dir():
            raise Usage(f"--rerun-root is not a directory: {args.rerun_root}")
    except Usage as e:
        print(f"junit_diff: {e}", file=sys.stderr)
        return 2
    res = {"old": args.old, "new": args.new, **compare(old, new, flaky, base)}
    if args.rerun_root and res["newly_bad"]:
        classes = {}
        for k in res["newly_bad"]:
            nid = nodeid(k, args.rerun_root)
            if nid is None:
                classes[k] = {"class": "unresolved", "nodeid": None}
                continue
            p, f, o = rerun(nid, args.rerun_root, args.rerun, sandbox=not args.no_sandbox)
            classes[k] = {"class": classify(p, f, args.rerun), "nodeid": nid, "passes": p, "fails": f, "other": o}
        res["rerun"] = classes
    if args.json:
        Path(args.json).write_text(json.dumps(res, indent=1), encoding="utf-8")

    print(f"old {res['counts_old']}\nnew {res['counts_new']}")
    print(f"newly_bad {len(res['newly_bad'])}  known_flaky_failed {len(res['known_flaky_failed'])}  "
          f"baseline_failed {len(res['baseline_failed'])}  "
          f"fixed {len(res['fixed'])}  added {res['added_count']}  removed {res['removed_count']}")
    for k in res["newly_bad"][:60]:
        extra = res.get("rerun", {}).get(k)
        print("  NEW BAD", k, json.dumps(extra) if extra else "")
    for k in res["known_flaky_failed"][:60]:
        print("  KNOWN FLAKY", k)
    for b in res["baseline_failed"][:60]:
        print(f"  BASELINE {b['key']}  ({b['kind']} since {b['since']}: {b['reason']})")
    for k in res["fixed"][:60]:
        print("  FIXED", k)
    for k in res["removed"][:60]:
        print("  REMOVED", k)

    if args.fail_on_regression:
        rr = res.get("rerun", {})
        left = [k for k in res["newly_bad"] if rr.get(k, {}).get("class") != "passes_alone"]
        return 1 if left else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
