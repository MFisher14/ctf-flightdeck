"""Exact-hash warm results and batch records.

A test file's warm key is sha256 over:

    the key format version; the test file's repo-relative path
    every input file (Graph.inputs: its closure, its scan inputs, the global inputs, data files under the
      folders it names) as (path, content sha256), a missing one as (path, "-")
    the interpreter (sys.version, sys.executable); the config's env knobs (name=value, unset = "-")
    the extra pytest arguments

A result is stored only when it is green and complete: pytest exit 0 with no plain skip (an xfail, which
is a known failure listed in tests/known_failures.toml, is allowed). A file whose tests skipped depends on
something outside the key (a tool, Docker, a corpus), so it always runs. A red result is never stored: a
rerun of a red file is the point of the gate. A red run also deletes any green result stored under its
key (the same key went red, so the green one is no longer evidence: a flaky test, or an input outside the
key). A file matching the config's `no_warm` globs never reuses, and neither does a file carried as red in
a batch (runner.run_gate `no_reuse`).

State layout under the state dir (ctf.paths.gate_state()):

    checkouts/<id>/hashes.json, deps.json   the content-hash inventory of one checkout (impact.Graph)
    warm/<k[:2]>/<key>.json                  one green result per key
    batches/<batch id>.json                  the batch's full run (when, result, files) and its red files
    runs/<stamp>/                            each run's per-file pytest output
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from .. import env as _env
from . import GateError

KEY_VERSION = "warm-1"
_BATCH_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z")


def checkout_state(state: Path, root: Path) -> Path:
    rid = hashlib.sha256(str(Path(root).resolve()).encode()).hexdigest()[:16]
    return Path(state) / "checkouts" / rid


def warm_key(test: str, inputs: list[tuple[str, str | None]], env_keys, pytest_args=(),
             python: str | None = None) -> str:
    """sha256 over the key format, the test path, every (input path, content sha256) pair, the interpreter,
    the env knobs and the extra pytest arguments. Paths never hold NUL, so NUL-joined fields are unambiguous.
    `python` is the children's interpreter when it is not the running one (B-153, ctf.pyinterp): it enters
    the key then, so a result from one venv is never reused for another."""
    h = hashlib.sha256()
    def put(*parts):
        for p in parts:
            b = str(p).encode("utf-8", "surrogateescape")
            h.update(len(b).to_bytes(8, "big"))
            h.update(b)
    put(KEY_VERSION, test)
    put("files", "\0".join(f"{rel}\0{sha or '-'}" for rel, sha in sorted(inputs)))
    put("python", sys.version, sys.executable)
    if python and os.path.realpath(python) != os.path.realpath(sys.executable):
        put("child-python", python, os.path.realpath(python))
    for k in sorted(env_keys):
        v = _env.get(k)
        put("env", k, "-" if v is None else v)
    for a in pytest_args:
        put("arg", a)
    return h.hexdigest()


def file_key(graph, test: str, pytest_args=(), python: str | None = None) -> str:
    """The warm key of one test file in this checkout (Graph.inputs, hashed by the graph's content cache)."""
    return warm_key(test, [(f, graph.sha(f)) for f in graph.inputs(test)], graph.cfg.env, pytest_args, python)


@dataclass
class WarmResult:
    test: str
    key: str
    seconds: float
    passed: int
    xfailed: int
    ts: float


def _atomic_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, sort_keys=True)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class WarmStore:
    def __init__(self, state: Path):
        self.dir = Path(state) / "warm"

    def _path(self, key: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{64}", key):
            raise ValueError(f"bad warm key {key!r}")
        return self.dir / key[:2] / f"{key}.json"

    def get(self, key: str, test: str) -> WarmResult | None:
        """The green result stored under exactly this key for this test, else None. A record that does
        not parse, or names another test, is not a hit."""
        p = self._path(key)
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            r = WarmResult(**d)
        except (OSError, ValueError, TypeError):
            return None
        return r if r.key == key and r.test == test else None

    def put(self, r: WarmResult) -> None:
        _atomic_write(self._path(r.key), asdict(r))

    def drop(self, key: str) -> bool:
        """Delete the result stored under `key` (that key just ran red). True when one was there."""
        try:
            self._path(key).unlink()
        except FileNotFoundError:
            return False
        return True


def check_batch_id(batch: str) -> str:
    if not _BATCH_ID.match(batch or ""):
        raise GateError(f"bad batch id {batch!r}: letters, digits, '.', '_', '-' (at most 100)")
    return batch


class Batches:
    """Which batches have had their full run, and which test files are red in the batch.

    `red` lists the test files whose last run in the batch was red (FAIL, ERROR or TIMEOUT). The full run
    sets it; every later run of the batch selects those files again and updates it (a file leaves the list
    only when it runs green), so a failure the full run found keeps the batch red until it is fixed,
    whatever the later changes touch."""

    def __init__(self, state: Path):
        self.dir = Path(state) / "batches"

    def _path(self, batch: str) -> Path:
        return self.dir / f"{check_batch_id(batch)}.json"

    def full_run(self, batch: str) -> dict | None:
        p = self._path(batch)
        if not p.exists():
            return None
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise GateError(f"batch record {p} is unreadable ({e}); delete it to rerun the batch's full run") from e
        if not isinstance(d, dict) or "ts" not in d:
            raise GateError(f"batch record {p} is malformed; delete it to rerun the batch's full run")
        red = d.get("red")
        if not isinstance(red, list) or not all(isinstance(t, str) for t in red):
            raise GateError(f"batch record {p} has no list of red files (an older format, or damaged); "
                            f"rerun the batch's full run with --batch {batch} --full")
        return d

    def record_full(self, batch: str, *, result: str, files: int, seconds: float, red) -> None:
        _atomic_write(self._path(batch),
                      {"batch": batch, "ts": time.time(), "result": result, "files": files, "seconds": seconds,
                       "red": sorted(set(red))})

    def update_red(self, batch: str, *, ran, red) -> list:
        """After a later run of the batch: files of `ran` not in `red` went green and leave the list; files
        in `red` join it. Returns the batch's red files now."""
        d = self.full_run(batch)
        if d is None:
            raise GateError(f"batch {batch} has no full run to update")
        d["red"] = sorted((set(d["red"]) - set(ran)) | set(red))
        d["last_ts"] = time.time()
        _atomic_write(self._path(batch), d)
        return d["red"]
