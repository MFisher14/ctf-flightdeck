"""The tracked baseline ledger (B-153): which tests are known red on the baseline, why, and since when.

A build run that finished red told nobody whether the item under test broke something or the tree was
already red there: stale expectations (Lorentz fail=6) and load-dependent tests showed up as fresh
failures, and an hour went into each before someone recognised an old friend. The merge queue kept its
known-flaky list as an untracked text file of junit keys with no reason and no date.

The ledger is a tracked TOML file (tests/gate_baseline.toml; `baseline` in tests/gate.toml):

    version = 1

    [[red]]
    id = "tests/test_x.py::test_y"          a pytest node id (class and parametrize parts allowed)
    kind = "flaky"                          flaky | env | stale | broken (KINDS)
    reason = "fails under the merge queue's load; passes alone"
    since = 2026-11-12                      a TOML date: when it was entered (never in the future)
    owner = "B-123"                         optional: the item that will fix it

It never turns a red green. It makes a red **attributable**: the gate splits every red file's failing
tests into `new` (not in the ledger: this change, or a fresh problem) and `baseline` (listed: known
before this change), shows the ledger's reason and date beside each, and counts both on the GATE line
(`red_new=` / `red_baseline=`). `tools/junit_diff.py --baseline FILE` lists ledger hits apart from the
newly bad tests in the same way, and `ctf gate baseline keys` prints the junit keys for a tool that
still wants the old one-key-per-line form. `ctf gate baseline check` refuses a malformed ledger and an
entry whose test file is gone (stale entries are pruned, not kept).
"""
from __future__ import annotations

import datetime as _dt
import re
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from . import GateError

LEDGER_VERSION = 1
KINDS = ("flaky", "env", "stale", "broken")
_KEYS = {"id", "kind", "reason", "since", "owner"}
_REQUIRED = {"id", "kind", "reason", "since"}
_NODE = re.compile(r"(?P<file>[A-Za-z0-9_./-]+\.py)::(?P<rest>[^\s:][^\n]*)\Z")


@dataclass(frozen=True)
class Entry:
    id: str
    kind: str
    reason: str
    since: _dt.date
    owner: str = ""

    @property
    def file(self) -> str:
        return self.id.split("::", 1)[0]

    def describe(self) -> str:
        return f"{self.kind} since {self.since.isoformat()}: {self.reason}" + (f" (owner {self.owner})"
                                                                                if self.owner else "")


def junit_key(nodeid: str) -> str:
    """The junit `<classname>::<name>` key pytest writes for a node id run from the repo root:
    `tests/test_x.py::TestC::test_y[a]` -> `tests.test_x.TestC::test_y[a]`."""
    m = _NODE.match(nodeid)
    if not m:
        raise GateError(f"not a pytest node id: {nodeid!r} (want path/to/test_x.py::test_name)")
    mod = m["file"][:-3].replace("/", ".")
    parts = m["rest"].split("::")
    name = parts[-1]
    cls = ".".join([mod, *parts[:-1]])
    return f"{cls}::{name}"


class Ledger:
    def __init__(self, path: Path, entries: dict[str, Entry]):
        self.path = Path(path)
        self.entries = entries                                       # {node id: Entry}
        self._by_key = {junit_key(i): e for i, e in entries.items()}

    def __len__(self) -> int:
        return len(self.entries)

    def get(self, nodeid: str) -> Entry | None:
        return self.entries.get(nodeid)

    def by_key(self, key: str) -> Entry | None:
        """The entry for a junit key (`classname::name`)."""
        return self._by_key.get(key)

    def keys(self) -> list[str]:
        return sorted(self._by_key)

    def stale(self, root: Path) -> list[Entry]:
        """Entries whose test file no longer exists under `root`."""
        return [e for e in self.entries.values() if not (Path(root) / e.file).is_file()]


def _date(v, where: str, today: _dt.date) -> _dt.date:
    if isinstance(v, _dt.datetime):
        v = v.date()
    if not isinstance(v, _dt.date):
        raise GateError(f"{where}: 'since' must be a TOML date (2026-11-12), got {v!r}")
    if v > today:
        raise GateError(f"{where}: 'since' {v.isoformat()} is in the future")
    return v


def parse(text: str, path: Path, *, today: _dt.date | None = None) -> Ledger:
    today = today or _dt.date.today()
    try:
        d = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise GateError(f"{path}: not valid TOML: {e}") from e
    unknown = set(d) - {"version", "red"}
    if unknown:
        raise GateError(f"{path}: unknown key(s) {sorted(unknown)}")
    if d.get("version") != LEDGER_VERSION:
        raise GateError(f"{path}: version must be {LEDGER_VERSION}, got {d.get('version')!r}")
    raw = d.get("red", [])
    if not isinstance(raw, list):
        raise GateError(f"{path}: 'red' must be an array of tables ([[red]])")
    entries: dict[str, Entry] = {}
    for i, r in enumerate(raw):
        w = f"{path} [[red]] #{i + 1}"
        if not isinstance(r, dict):
            raise GateError(f"{w}: must be a table")
        missing, extra = _REQUIRED - set(r), set(r) - _KEYS
        if missing or extra:
            raise GateError(f"{w}: " + "; ".join(x for x in (
                f"missing {sorted(missing)}" if missing else "", f"unknown {sorted(extra)}" if extra else "") if x))
        nid = r["id"]
        if not isinstance(nid, str):
            raise GateError(f"{w}: 'id' must be a string")
        junit_key(nid)                                              # validates the node id form
        if nid in entries:
            raise GateError(f"{w}: duplicate id {nid!r}")
        if r["kind"] not in KINDS:
            raise GateError(f"{w}: kind {r['kind']!r} is not one of {', '.join(KINDS)}")
        reason = r["reason"]
        if not isinstance(reason, str) or len(reason.strip()) < 10:
            raise GateError(f"{w}: 'reason' must say what fails and why (at least 10 characters)")
        owner = r.get("owner", "")
        if not isinstance(owner, str):
            raise GateError(f"{w}: 'owner' must be a string")
        entries[nid] = Entry(nid, r["kind"], reason.strip(), _date(r["since"], w, today), owner)
    return Ledger(path, entries)


def load(path: Path, *, today: _dt.date | None = None) -> Ledger:
    """Read and validate the ledger. A missing or malformed file raises GateError naming it."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise GateError(f"baseline ledger not found: {path} (tests/gate.toml names it as 'baseline')") from None
    except (OSError, UnicodeDecodeError) as e:
        raise GateError(f"baseline ledger {path} is unreadable: {e}") from e
    return parse(text, path, today=today)


def for_config(root: Path, cfg) -> Ledger | None:
    """The ledger tests/gate.toml names, or None when the config names none."""
    return load(Path(root) / cfg.baseline) if cfg.baseline else None


def failing_keys(junit: Path) -> list[str]:
    """The junit keys of every failing or erroring testcase in one pytest junit (empty when unreadable)."""
    try:
        root = ET.parse(junit).getroot()
    except (OSError, ET.ParseError):
        return []
    out = []
    for tc in root.iter("testcase"):
        if any(ch.tag in ("failure", "error") for ch in tc):
            cls, name = tc.get("classname") or "", tc.get("name") or ""
            out.append(f"{cls}::{name}" if cls else name)
    return out


@dataclass
class Attribution:
    new: list            # junit keys of failing tests not in the ledger
    baseline: list       # [(junit key, Entry)]

    @property
    def all_baseline(self) -> bool:
        return bool(self.baseline) and not self.new

    def detail(self) -> str:
        parts = []
        if self.baseline:
            parts.append("baseline red: " + "; ".join(f"{k} ({e.describe()})" for k, e in self.baseline[:3])
                         + (f"; +{len(self.baseline) - 3} more" if len(self.baseline) > 3 else ""))
        if self.new:
            parts.append(f"NEW red: {', '.join(self.new[:3])}" + (f" +{len(self.new) - 3} more"
                                                                  if len(self.new) > 3 else ""))
        return " | ".join(parts)


def attribute(keys, ledger: Ledger | None) -> Attribution:
    """Split failing junit keys into new and baseline reds."""
    new, base = [], []
    for k in keys:
        e = ledger.by_key(k) if ledger is not None else None
        if e is None:
            new.append(k)
        else:
            base.append((k, e))
    return Attribution(new=new, baseline=base)


def append_entry(path: Path, nodeid: str, kind: str, reason: str, *, owner: str = "",
                 today: _dt.date | None = None) -> Entry:
    """Add one entry to the ledger file (validated: the result must still load). Refuses a duplicate."""
    today = today or _dt.date.today()
    path = Path(path)
    old = path.read_text(encoding="utf-8") if path.exists() else f"version = {LEDGER_VERSION}\n"
    led = parse(old, path, today=today)
    if nodeid in led.entries:
        raise GateError(f"{nodeid} is already in the ledger ({led.entries[nodeid].describe()})")

    def q(s: str) -> str:
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ") + '"'
    block = (f"\n[[red]]\nid = {q(nodeid)}\nkind = {q(kind)}\nreason = {q(reason)}\nsince = {today.isoformat()}\n"
             + (f"owner = {q(owner)}\n" if owner else ""))
    new_text = old.rstrip("\n") + "\n" + block
    led2 = parse(new_text, path, today=today)                      # refuse anything that would not load
    path.write_text(new_text, encoding="utf-8")
    return led2.entries[nodeid]
