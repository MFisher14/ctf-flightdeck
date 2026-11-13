"""Shared by tests/real/test_real_<toolkit>.py of group c: find the cache, load one toolkit, check, time.

A real-artifact test prints `SKIP ...` and exits 0 when the cache folder of its toolkit is absent
(tests/real/fetch_c.py fills it); a single absent file skips only its own checks. No network, no
token, no Game Master: the environment is pointed at a dead loopback port before anything is imported,
and $CTF_WORKDIR at an empty temporary folder, so nothing can write into the saved attempts.
Fetched files are data: they are read as bytes and never run or imported."""
import atexit
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
import fetch_c  # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix="test_real_c_"))
atexit.register(shutil.rmtree, TMP, True)
os.environ["CTF_WORKDIR"] = str(TMP / "challenges")
os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
for sub in ("tools", "solvers/common", "solvers/toolkits"):
    sys.path.insert(0, str(REPO / sub))
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
sys.path.append(str(REPO / "tests"))      # last, so tests/ shadows no toolkit module
import sh09_clocks  # noqa: E402

# The web clients refuse hosts outside the event's rules.live_service_scope (B-001c, ctf/scope.py).
# These scripts run as their own processes, so the suite's pinned profile (tests/conftest.py) does not
# reach them: pin a loopback-only profile here for the toy servers the synthetic checks start. When
# a profile is already pinned (this module imported inside the pytest process), that one is kept.
import datetime as _dt  # noqa: E402
from ctf import event as _event, scope as _scope  # noqa: E402
if _scope.pinned() is None:
    _scope.pin(_event.parse({
        "slug": "test-real-c", "name": "tests/real group c loopback scope",
        "dates": {"start": _dt.date(2026, 1, 1), "end": _dt.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": "https://board.realdata-c.test"},
        "flag": {"prefixes": []},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": ["localhost", "127.0.0.0/8", "::1"]},
    }, src="tests/real/realdata_c.py"))

FAILED, SKIPPED, SLOW, NO_CACHE = [], [], [], []
LIMIT = 2.0                             # seconds a toolkit may take on one file under 20 MB


def load(key: str):
    """The toolkit's module the way the registry loads it: by path, under a name of its own
    (modern_crypto, malconfig and web_evidence share a stem with their reader in solvers/common)."""
    import registry
    return registry.load(key)


def start(toolkit: str):
    """(module, cache folder) of one toolkit. With no cache folder a SKIP line is printed and every group
    that asks for a real file is skipped; the groups built in memory still run."""
    root = fetch_c.cache_root() / toolkit
    if not root.is_dir():
        print(f"SKIP test_real_{toolkit}: no cache at {root} (run tests/real/fetch_c.py --toolkit {toolkit}); "
              f"only the checks that need no real file run")
        NO_CACHE.append(toolkit)
    return load(toolkit), root


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or detail == "" else f"  [{str(detail)[:500]}]"))
    if not ok:
        FAILED.append(label)
    return ok


class Skip(Exception):
    pass


def data(root: Path, rel: str) -> bytes:
    """The bytes of one cached file when its sha256 is the manifest's; raises Skip otherwise."""
    p = root / rel
    if not root.is_dir():
        raise Skip("no cache")
    want = {f["dest"]: f.get("sha256") for f in fetch_c.manifest()["files"] if f["toolkit"] == root.name}.get(rel)
    if not p.is_file():
        raise Skip(f"{root.name}/{rel} is not in the cache")
    b = p.read_bytes()
    if want and hashlib.sha256(b).hexdigest() != want:
        raise Skip(f"{root.name}/{rel} differs from the manifest's sha256")
    return b


def section(fn):
    """Run one group of checks; a missing file skips the group, an exception fails it."""
    try:
        fn()
    except Skip as e:
        print(f"SKIP {fn.__name__}: {e}")
        SKIPPED.append(fn.__name__)
    except Exception as e:                  # a crash on a real file is the finding
        import traceback
        check(f"{fn.__name__} ran without an exception", False, f"{type(e).__name__}: {e} | {traceback.format_exc()[-300:]}")


def timed(label, fn, *args, limit=LIMIT, **kw):
    """fn(*args) and a check that its work stayed under the limit, in seconds at the core's top clock.

    Not CPU seconds (SH-09/SH-10): under the suite's sustained load (50-170 on 14 cores) this laptop
    clocks its performance cores down to about half their top speed, so the same parse retires the same
    instructions but costs about twice the CPU seconds it costs on an idle machine, and a CPU-time bound
    set on an idle machine flakes. web_evidence's nginx-JSON solve_set is the case: ~0.5 s of work that
    read 2.5 to 3.8 s of CPU under load against its 2 s limit. The limit is what the toolkit may cost on
    an idle machine, so it is checked as work at the core's top clock (tests/sh09_clocks.work_seconds:
    core cycles over the top clock), which a lower clock does not change. The group-c toolkits are
    single-threaded parsers that start no subprocess, so their cycles are their whole work; one that
    ignores its own budget still trips the limit. Without the work meter fn still runs (the group's
    answer checks still run), and the cost limit alone is a SKIP naming the missing meter (a SKIP fails
    the realdata run), never passed."""
    out, work, no_meter = sh09_clocks.work_seconds_unless_missing(fn, *args, **kw)
    if no_meter:
        print(f"SKIP {label}: cost limit {limit:g} s not checked: no work meter ({no_meter})")
        SKIPPED.append(f"{label} (cost limit: no work meter)")
        return out
    if work > limit:
        SLOW.append((label, round(work, 2)))
    check(f"{label}: {work:.2f} s of work (limit {limit:g} s)", work <= limit)
    return out


def q(qid, text, kind="exact_text", syntax="exact artifact-derived value only", artifact="evidence.zip", **fmt):
    member = artifact.split("->")[-1].strip() if "->" in artifact else None
    return {"id": qid, "qid": qid, "answer_id": qid, "question": text, "artifact": artifact, "member": member,
            "answer_format": {"kind": kind, "syntax": syntax, **fmt}, "normalization": "trim"}


def unsure(value):
    """(key, [(name, value)]) of an unsure answer, or None for anything else."""
    if not (isinstance(value, str) and value.startswith("??")):
        return None
    body = json.loads(value[2:])
    return body["k"], [tuple(o) for o in body["o"]]


def plain(value) -> bool:
    return value is not None and not (isinstance(value, str) and value.startswith("??"))


def offers(value, want) -> bool:
    """An unsure answer one of whose options is `want`, or the plain answer `want`."""
    u = unsure(value)
    return (want in [v for _, v in u[1]]) if u else value == want


def drill(files: dict, questions: list, budget: float = 8.0) -> dict:
    """The end-to-end path of a new lane on one delivery, with no Game Master: the triage map
    (solvers/common/triage.py: what it proves alone, the lane signals) and the toolkit ranking it
    writes into the map. Returns {proven, lanes, rank: [(key, signal, threshold, match)], winner,
    seconds}; `winner` is the first ranked toolkit at or over its threshold that may be a match
    candidate (the generic evidence_core only when no other is), or None."""
    import triage
    t0 = time.perf_counter()
    m = triage.build(questions, files, attempt={}, budget=budget)
    tk = triage.toolkits(questions, {**files, **triage.expand_more(files)}, budget=budget)
    rows = tk.get("rows") or []
    rank = [(r["key"], r["signal"], r["threshold"], r["match"]) for r in rows]
    over = [r for r in rows if r["signal"] >= r["threshold"] and r["match"]]
    specific = [r for r in over if r["key"] != "evidence_core"]
    winner = (specific or over or [{"key": None}])[0]["key"]
    return {"proven": m["proven"], "lanes": m["signals"], "rank": rank, "winner": winner, "error": tk.get("error"),
            "seconds": round(time.perf_counter() - t0, 2)}


def finish(name: str) -> int:
    if SKIPPED:
        print(f"skipped groups: {', '.join(SKIPPED)}")
    if FAILED:
        print(f"{name}: {len(FAILED)} FAILED: {FAILED}")
        return 1
    print(f"{name}: ok")
    return 0
