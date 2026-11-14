"""Shared by the group-b real-artifact tests (cloudlogs, cloud_container, edr_persistence, nix_host,
sqlite_artifacts): where the cache is, how a toolkit is loaded, the check/skip printing.

The cache is challenges/_realdata/ of the main checkout (untracked, never committed), filled by
tests/real/fetch_b.py. $CTF_REALDATA names another folder. In a worktree the main checkout's
cache is used, read-only: nothing here writes.
"""
import importlib.util
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
os.environ.setdefault("CTF_PLATFORM_URL", "http://127.0.0.1:9/")     # nothing here makes a request
import tempfile  # noqa: E402
# tools that load judge.py want a scratch folder beside a test URL
os.environ.setdefault("CTF_WORKDIR", tempfile.mkdtemp(prefix="huntress-real-b-"))
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True


def cache_root() -> Path:
    """The corpus root: ctf.paths.realdata_root() ($CTF_REALDATA)."""
    sys.path.insert(0, str(HERE))
    import _corpus
    return _corpus.root()


CACHE = cache_root()
MANIFEST = json.loads((HERE / "manifest_b.json").read_text())


def toolkit(key):
    """solvers/toolkits/<key>.py loaded by path under a name of its own."""
    name = "real_b_" + key
    if name in sys.modules:
        return sys.modules[name]
    for p in (REPO / "solvers" / "toolkits", REPO / "solvers" / "common"):
        if str(p) not in sys.path:
            sys.path.insert(0, str(p))
    spec = importlib.util.spec_from_file_location(name, REPO / "solvers" / "toolkits" / f"{key}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def pinned_token(digest: str, rel: str, pattern: bytes = rb"(?:AKIA|ASIA)[0-9A-Z]{16}"):
    """The one token under CACHE/rel (a file or a folder of plain files) whose SHA-256 is `digest`, or
    None when the corpus holds none. Key-shaped values of the public data sets are pinned this way so
    the commit guard keeps the literals out of the repository; the value is read back from the data."""
    import hashlib
    import re
    p = CACHE / rel
    paths = sorted(x for x in p.rglob("*") if x.is_file()) if p.is_dir() else [p] if p.is_file() else []
    for f in paths:
        for m in set(re.findall(pattern, f.read_bytes())):
            if hashlib.sha256(m).hexdigest() == digest:
                return m.decode()
    return None


def have(*rel) -> bool:
    return all((CACHE / r).exists() for r in rel)


def data(rel) -> bytes:
    return (CACHE / rel).read_bytes()


def files(*rels, strip=None) -> dict:
    """{name: bytes} for files and folders under the cache; names are relative to `strip` (or the
    file's own name)."""
    out = {}
    for rel in rels:
        p = CACHE / rel
        if p.is_dir():
            for f in sorted(x for x in p.rglob("*") if x.is_file()):
                out[str(f.relative_to(CACHE / strip if strip else p))] = f.read_bytes()
        else:
            out[str(p.relative_to(CACHE / strip)) if strip else p.name] = p.read_bytes()
    return out


def plain(a) -> bool:
    return a is not None and not str(a).startswith("??")


def unsure(a) -> bool:
    return isinstance(a, str) and a.startswith("??")


def options(a) -> list:
    return [v for _, v in json.loads(a[2:])["o"]] if unsure(a) else []


def ask(mod, fs, text, fmt=None, qid="q", member=None):
    q = {"qid": qid, "question": text, "answer_id": qid}
    if fmt:
        q["answer_format"] = fmt
    if member:
        q["member"] = member
    return mod.solve_set([q], fs, {}).get(qid)


class Run:
    """One test file's bookkeeping: ok / FAIL / SKIP lines, a slow note, the exit status."""

    def __init__(self, key):
        self.key, self.failed, self.skipped, self.passed, self.slow = key, [], [], 0, []

    def check(self, name, cond, detail=""):
        print(("ok   " if cond else "FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))
        if cond:
            self.passed += 1
        else:
            self.failed.append(name)

    def skip(self, name, why="not in the cache"):
        print(f"SKIP {name}  [{why}]")
        self.skipped.append(name)

    def need(self, name, *rel) -> bool:
        if have(*rel):
            return True
        self.skip(name, "missing " + ", ".join(r for r in rel if not have(r)))
        return False

    def timed(self, name, fn, limit=2.0):
        # Row 170: measure CPU time (process_time), not wall-clock (monotonic), so a loaded machine
        # does not fail this bound. The group-b toolkits are single-threaded parsers, so CPU time
        # tracks their real work; a toolkit that ignores its own budget burns seconds of CPU and
        # still trips `limit`. A toolkit with an internal wall-clock budget cuts its work at that
        # budget, so its CPU stays well under `limit` either way.
        t0 = time.process_time()
        out = fn()
        dt = time.process_time() - t0
        if dt > limit:
            self.slow.append((name, dt))
        self.check(f"{name} within {limit:g} s CPU", dt <= limit, f"{dt:.2f} s CPU")
        return out

    def done(self) -> int:
        if not (CACHE / self.key).is_dir() and not self.passed and not self.failed:
            print(f"SKIP tests/real {self.key}: no cache under {CACHE} (run tests/real/fetch_b.py)")
            return 0
        print(f"{self.key}: {self.passed} ok, {len(self.failed)} failed, {len(self.skipped)} skipped")
        if self.failed:
            print("FAILED: " + "; ".join(self.failed))
            return 1
        print("ok")
        return 0
