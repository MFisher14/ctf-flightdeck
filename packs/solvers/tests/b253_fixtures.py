"""Synthetic fixtures for the B-253 tests: saved attempts, a lane solver with day modules, and two probe
engines (a rendezvous that proves two replays overlap, and one that prints its own niceness). Everything
is written by the test; no real challenge file, no network."""
from __future__ import annotations

import hashlib
import json
import textwrap
from pathlib import Path

import adapt_repo as AR

# A lane solver that loads its day module by question prefix at run time (as binary evidence.py does), so
# only the per-prefix key can tell which day modules a row depends on.
SOLVER = '''\
import hashlib, importlib, os, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def _day(name):
    # A flat `import d30` resolves through sys.modules first; in a shared test process another test may
    # already hold a module of that name from another folder (solvers/binary/d30.py), so drop it first.
    m = sys.modules.get(name)
    if m is not None and Path(getattr(m, "__file__", "") or "").resolve().parent != HERE:
        del sys.modules[name]
    return importlib.import_module(name)


def solve_set(questions, files, ctx):
    out = {}
    blob = b"".join(v for k, v in sorted(files.items()) if isinstance(v, (bytes, bytearray)))
    for q in questions:
        qid = q["qid"]
        if qid.endswith("_pid"):
            out[qid] = str(os.getpid())
            continue
        mod = _day(qid.split("_", 1)[0])
        out[qid] = mod.answer(qid, blob)
        ctx.setdefault("partial", {})[qid] = out[qid]
    return out
'''

DAY = '''\
import hashlib
SALT = {salt!r}


def answer(qid, blob):
    return hashlib.sha256(SALT.encode() + qid.encode() + blob).hexdigest()[:12]
'''

RDV = '''\
# A rendezvous: TOGETHER only when another run of this engine is alive at the same time and has seen this
# one too. A marker left by a run killed at its cap (its pid is dead) is not a peer, so runs one after
# another never meet, however long they wait.
import os, sys, time
from pathlib import Path
d = Path(os.environ["B253_RDV_DIR"])
d.mkdir(parents=True, exist_ok=True)
pid = os.getpid()
(d / f"{pid}.here").write_text(Path(sys.argv[1]).name)


def alive(p):
    try:
        os.kill(p, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


wait = float(os.environ.get("B253_RDV_WAIT", "60"))
end = time.monotonic() + wait
peer = None
while peer is None and time.monotonic() < end:
    for m in d.glob("*.here"):
        other = int(m.name.split(".")[0])
        if other != pid and alive(other):
            peer = other
            break
    else:
        time.sleep(0.05)
seen = False
if peer is not None:
    (d / f"{pid}.saw").write_text(str(peer))
    while time.monotonic() < end and not (d / f"{peer}.saw").exists():   # stay until the peer saw this one
        time.sleep(0.05)
    seen = (d / f"{peer}.saw").exists()
print("TOGETHER" if seen else "ALONE")
print(f"NICE {os.nice(0)}")
'''

RDV_ENGINE = "toolkits.b253_rdv"


def add_rdv_engine(root: Path) -> None:
    AR.write(root, "solvers/toolkits/b253_rdv.py", RDV)
    AR.write(root, "solvers/toolkits/b253_rdv.manifest.toml",
             f'id = "{RDV_ENGINE}"\nlane = "toolkits"\nentry = "cli:python solvers/toolkits/b253_rdv.py"\n'
             'capabilities = ["analysis", "cli"]\ncost_class = "cheap"\n')


def write_lane(root: Path, salts: dict | None = None) -> Path:
    """solvers/lane/solver.py with day modules d07.py and d30.py; returns the solver file."""
    salts = salts or {"d07": "seven", "d30": "thirty"}
    AR.write(root, "solvers/lane/solver.py", SOLVER)
    for day, salt in salts.items():
        AR.write(root, f"solvers/lane/{day}.py", DAY.format(salt=salt))
    return root / "solvers" / "lane" / "solver.py"


def save_attempt(folder: Path, sets: dict, *, expect: dict | None = None) -> Path:
    """A saved attempt: sets = {set number: (delivery name, delivery bytes, [question ids without setN.])}."""
    folder.mkdir(parents=True)
    questions, artifacts = [], []
    for i, (n, (name, data, qids)) in enumerate(sorted(sets.items()), 1):
        d = folder / "artifact" / f"delivery-{i:02d}"
        d.mkdir(parents=True)
        (d / name).write_bytes(data)
        artifacts.append({"filename": name, "sha256": hashlib.sha256(data).hexdigest()})
        for q in qids:
            questions.append({"id": f"set{n}.{q}", "artifact": f"delivery {i} -> {name}", "text": "q"})
    (folder / "attempt.json").write_text(json.dumps({"attempt_id": folder.name, "questions": questions,
                                                     "artifacts": artifacts}), encoding="utf-8")
    if expect is not None:
        (folder / "expect.json").write_text(json.dumps(expect), encoding="utf-8")
    return folder


def day_answer(salt: str, qid: str, blob: bytes) -> str:
    return hashlib.sha256(salt.encode() + qid.encode() + blob).hexdigest()[:12]


def dedent(s: str) -> str:
    return textwrap.dedent(s)
