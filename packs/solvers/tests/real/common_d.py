"""What the real-artifact tests of group d share: where the repository is, how a toolkit is loaded,
how a question in this event's style is written, and the check/finish pair that prints one line
per check. Offline; nothing here reads a token or makes a request."""
import os
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
# Always a fresh scratch folder, whatever the shell has set: the drills write attempts under it, and a
# shell that points CTF_WORKDIR at the real attempts folder must not get them (review, 2026-10-08).
os.environ["CTF_WORKDIR"] = tempfile.mkdtemp(prefix="test_real_d_")
os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"       # nothing here makes a request; this makes sure
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
for p in (REPO / "tools", REPO / "solvers" / "common", Path(__file__).resolve().parent):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))
import run          # noqa: E402
import labels       # noqa: E402
import fetch_d      # noqa: E402

FAILED = []
T0 = time.monotonic()


def toolkit(key: str):
    return run.load_solver(str(REPO / "solvers" / "toolkits" / f"{key}.py"))


def check(name: str, ok, detail=None):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok or detail is None else f"  [{str(detail)[:300]}]"))
    if not ok:
        FAILED.append(name)
    return bool(ok)


def q(qid: str, text: str, kind: str = "exact_text", member: str = "evidence.bin", **fmt) -> dict:
    return {"id": qid, "qid": qid, "answer_id": qid, "question": text, "artifact": f"evidence.zip -> {member}", "member": member,
            "answer_format": {"kind": kind, "syntax": "exact artifact-derived value only", **fmt}}


def opts(v):
    """{name: value} of an unsure answer, None for a plain one or for None."""
    got = labels.parse(v) if isinstance(v, str) else None
    return {n: val for n, val in got["o"]} if got else None


def plain(v):
    """The value when it is a plain answer, else None."""
    return v if v is not None and opts(v) is None else None


def timed(fn, *a, **k):
    t = time.perf_counter()
    r = fn(*a, **k)
    return r, time.perf_counter() - t


def finish(script: str) -> int:
    took = time.monotonic() - T0
    if FAILED:
        print(f"\n{len(FAILED)} FAILED ({script}, {took:.1f} s): " + "; ".join(FAILED))
        return 1
    print(f"ok ({script}, {took:.1f} s)")
    return 0
