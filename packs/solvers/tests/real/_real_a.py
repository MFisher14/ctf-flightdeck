"""What the group-a real-artifact tests share: the cache folder, the skip, the question shape, the checks.

A test of this folder reads files that are not in the repository (the cache `tests/real/fetch_a.py` fills,
`<main checkout>/challenges/_realdata/<kit>/`). When that folder is absent the test prints one SKIP line and
exits 0; a file missing from a folder that is there is a FAIL (the manifest says what belongs in it). Nothing
is written outside a temporary folder, no request is made, no token is read, no file of the cache is run.
"""
import gzip
import json
import os
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
import fetch_a  # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix="test_real_a_"))
os.environ["CTF_WORKDIR"] = str(TMP / "challenges")
os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"       # nothing here makes a request; this makes sure
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
for _p in ("tools", "solvers/common", "solvers/toolkits"):
    sys.path.insert(0, str(REPO / _p))

FAILED = []
SLOW = []
LIMIT = 2.0          # seconds a toolkit may take on one file under 20 MB before it is listed as slow


def folder(kit: str) -> Path:
    """The kit's cache folder; exits 0 with a SKIP line when it is not there."""
    d = fetch_a.cache_root() / kit
    if not d.is_dir() or not any(d.iterdir()):
        print(f"SKIP tests/real: no real files for `{kit}` ({d} is absent); run tests/real/fetch_a.py")
        sys.exit(0)
    return d


def manifest(kit: str) -> list:
    return [e for e in fetch_a.load() if e["kit"] == kit and not e.get("big")]


def load(d: Path, name: str) -> bytes:
    data = (d / name).read_bytes()
    return gzip.decompress(data) if data[:2] == b"\x1f\x8b" and name.endswith(".gz") else data


def check(label, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + label + ("" if ok or not detail else f"   [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(label)
    return ok


def q(qid, text, kind="exact_text", artifact="evidence.bin", **fmt):
    """A question in this event's shape (the runner contract of AGENTS.md)."""
    member = artifact.split("->")[-1].strip() if "->" in artifact else None
    return {"id": qid, "qid": qid, "answer_id": qid, "question": text, "artifact": artifact, "member": member,
            "answer_format": {"kind": kind, "syntax": "exact artifact-derived value only", **fmt}, "normalization": "trim"}


def options(answer):
    """[(method, value)] of an unsure answer, [] of anything else."""
    if isinstance(answer, str) and answer.startswith("??"):
        try:
            return [tuple(x) for x in json.loads(answer[2:])["o"]]
        except (ValueError, KeyError, TypeError):
            return []
    return []


def values(answer):
    return [v for _, v in options(answer)]


def is_plain(answer):
    return answer is not None and not (isinstance(answer, str) and answer.startswith("??"))


def offers(answer, value):
    """The value is the plain answer, or one of an unsure answer's options."""
    return answer == value or value in values(answer)


def timed(label, fn, size=0, limit=LIMIT):
    """Run fn(); a run over the limit on a file under 20 MB is recorded (a NOTE in the kit's page, not a FAIL)."""
    t = time.time()
    out = fn()
    dt = time.time() - t
    if dt > limit and size < 20 << 20:
        SLOW.append((label, round(dt, 2), size))
    return out, dt


def finish(name: str) -> int:
    import shutil
    shutil.rmtree(TMP, ignore_errors=True)
    for label, dt, size in SLOW:
        print(f"NOTE slow: {label} took {dt} s on {size} bytes")
    if FAILED:
        print(f"\n{name}: {len(FAILED)} FAILED")
        for f in FAILED:
            print("  " + f)
        return 1
    print("\nok")
    return 0
