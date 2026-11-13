"""The shipped usage ledger (B-193): every model response of the event's agents, once, priced by model,
tier and the cache TTL the log reports, with the model actually served and one attribution rule for
Claude Code and Codex alike.

    res = ingest(workdir, roots)              # read new session-log lines into <workdir>/usage/
    rows = load(workdir)                      # {response key: row}, de-duplicated
    att = Attributor(workdir)                 # challenge of each response (assign > cwd)
    rep = summarize(rows, prices, att)        # totals, per model+tier, per challenge, per agent
    rec = reconcile(rep, ledger.read(wd))     # usage vs the `spend` the event ledger holds
    ttl = ttl_report(rows, prices)            # B-118: 1h cache writes reused within 5 min, at the 5m rate

Store: <workdir>/usage/responses.jsonl, one JSON line per response (key, harness, agent, parent, kind,
log, model, speed (the tier), ts, cwd, the token counts tools/ledger/pricing.py prices, ttl_assumed, thread,
model_from?, ingested). A response seen again with more output (a Claude response is written as one
line per content block) or from its owning thread (a forked Codex thread replays its parent's
responses) appends a superseding line; load() applies the same rule, so the file replays to the same
rows. <workdir>/usage/ingest-state.json keeps each log's byte offset and parser state, so an ingest
reads only new complete lines; losing it only costs a re-read (the store de-duplicates).

De-duplication is per response: Claude by message.id (the line with the most output wins), Codex by
response_id (the record whose payload thread_id is the rollout's own thread wins, else the first
seen). Pricing is not stored: summarize() prices every row with the current table, so a fixed price
reprices history. Tier: Claude `usage.speed` (fast), Codex the thread's service tier at the time of the
response (`thread_settings_applied`; Astra ultrafast is 6x). Cache writes are priced by their TTL
(ephemeral_5m / ephemeral_1h); a log that gives only the undivided cache_creation_input_tokens is priced
at the 5m rate and the row says ttl_assumed, counted in every report.

Attribution (one rule for both harnesses): a `usage.assign {agent, challenge_id, by}` ledger event for
the agent, else for its parent chain, else the challenge folder its cwd is in (<workdir>/<folder>/ with
a challenge.json naming the id). Anything else is unattributed and listed by agent, with the command
that assigns it. Responses whose cwd is outside every root are never read into the store.

Ledger events written by ingest(): `usage.served {harness, agent, model, kind, first_ts, parent?,
challenge_id?}` once per (harness, agent, model): the model actually served to each agent (a second
model on one agent is a fallback; tools/ledger/fallback.py prices it). By assign(): `usage.assign`.

Log text is data: only the usage, model, id and cwd fields are read.
"""
from __future__ import annotations

import collections
import datetime as _dt
import fcntl
import json
import math
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

from ctf import ledger as _ledger

from . import pricing, scan, sources

STORE_DIR = "usage"
STORE_NAME = "responses.jsonl"
STATE_NAME = "ingest-state.json"
LOCK_NAME = ".ingest.lock"
HARNESSES = ("claude", "codex")
SERVED_EVENT = "usage.served"
ASSIGN_EVENT = "usage.assign"
ROLE_EVENT = "usage.role"           # B-096: an agent's work role (a ctf.stages SPEND_CATEGORIES value)
DEFAULT_ROLE = "unknown"            # B-096: a response whose agent has no recorded role
RECONCILE_SOURCE = "usage:reconcile"
COUNT_FIELDS = {"claude": ("input", "cache_read", "cache_5m", "cache_1h", "output", "web_search"),
                "codex": ("input", "cached", "output")}
_PARENT_DEPTH = 8


class UsageError(RuntimeError):
    """The usage ledger cannot do what was asked (no roots, corrupt store or state)."""


def store_dir(workdir: Path) -> Path:
    return Path(workdir) / STORE_DIR


def store_path(workdir: Path) -> Path:
    return store_dir(workdir) / STORE_NAME


# ------------------------------------------------------------------ per-line readers

class ClaudeRows:
    """Rows from one Claude Code session log. Stateless across lines: every assistant line carries its
    own cwd, model and usage."""

    harness = "claude"

    def __init__(self, ref: sources.LogRef):
        self.ref = ref

    def feed(self, line: str) -> tuple[str, dict] | None:
        if '"usage"' not in line or '"assistant"' not in line:
            return None
        try:
            d = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return None
        if not isinstance(d, dict):
            return None
        got = scan._usage_row_claude(d)
        if not got:
            return None
        mid, row = got
        usage = (d.get("message") or {}).get("usage") or {}
        cc = usage.get("cache_creation") or {}
        split = (cc.get("ephemeral_5m_input_tokens") or 0) + (cc.get("ephemeral_1h_input_tokens") or 0)
        row["ttl_assumed"] = bool((usage.get("cache_creation_input_tokens") or 0) and not split)
        cwd = d.get("cwd")
        row["cwd"] = cwd if isinstance(cwd, str) and cwd else self.ref.cwd
        return mid, row

    def state(self) -> dict:
        return {}

    def restore(self, _st: dict) -> None:
        pass

    def legacy_only(self) -> bool:
        return False


class CodexRows(scan.CodexParser):
    """scan.CodexParser (model by turn, tier by thread setting) plus the cwd (session_meta, then each
    turn_context) and the payload thread_id of each token_usage_record."""

    harness = "codex"

    def __init__(self, ref: sources.LogRef, **st):
        super().__init__(**{k: v for k, v in st.items() if k != "cwd"})
        self.ref = ref
        self.cwd = st.get("cwd") or ref.cwd

    def feed(self, line: str) -> tuple[str, dict] | None:
        head = line[:220]
        if '"session_meta"' in head or '"turn_context"' in head:
            try:
                p = json.loads(line).get("payload") or {}
            except (json.JSONDecodeError, ValueError, AttributeError):
                p = {}
            if isinstance(p, dict) and isinstance(p.get("cwd"), str) and p["cwd"]:
                self.cwd = p["cwd"]
            if '"session_meta"' in head:
                return None
        got = super().feed(line)
        if not got:
            return None
        rid, row = got
        try:
            p = json.loads(line).get("payload") or {}
        except (json.JSONDecodeError, ValueError, AttributeError):
            p = {}
        row["thread"] = p.get("thread_id") if isinstance(p.get("thread_id"), str) else None
        row["cwd"] = self.cwd
        row["ttl_assumed"] = False
        if row.get("model") is None and self.ref.model:
            row["model"] = self.ref.model
            row["model_from"] = "thread_db"
        return rid, row

    def state(self) -> dict:
        return dict(super().state(), cwd=self.cwd)

    def restore(self, st: dict) -> None:
        self.__init__(self.ref, **(st or {}))

    def legacy_only(self) -> bool:
        return bool(self.legacy_lines and not self.records)


def ref_for(path, harness: str) -> sources.LogRef:
    """A LogRef for a log named on the command line (no discovery): a Claude log's agent is its file
    name; a Codex rollout's comes from its session_meta line."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"session log not found: {path}")
    if harness == "claude":
        return sources.claude_ref(path)
    if harness == "codex":
        meta = sources.rollout_meta(path)
        return sources.LogRef(path, "codex", meta.get("id") or path.stem, parent=meta.get("forked_from_id"),
                              kind="fork" if meta.get("forked_from_id") else "main", cwd=meta.get("cwd"))
    raise UsageError(f"unknown harness {harness!r} (one of {', '.join(HARNESSES)})")


def reader_for(ref: sources.LogRef):
    if ref.harness == "claude":
        return ClaudeRows(ref)
    if ref.harness == "codex":
        return CodexRows(ref)
    raise UsageError(f"unknown harness {ref.harness!r} (one of {', '.join(HARNESSES)})")


# ------------------------------------------------------------------ de-duplication

def _owned(row: dict) -> bool:
    return bool(row.get("thread")) and row.get("thread") == row.get("agent")


def better(old: dict, new: dict) -> bool:
    """Whether `new` supersedes `old` for the same response key."""
    if new["harness"] == "claude":
        return new.get("output", 0) > old.get("output", 0)
    return _owned(new) and not _owned(old)


def load(workdir: Path) -> dict[str, dict]:
    """{key: row} from the store, de-duplicated with better(). A partial last line (a writer mid-append)
    is left for the next read; a corrupt complete line raises UsageError."""
    p = store_path(workdir)
    out: dict[str, dict] = {}
    try:
        data = p.read_bytes()
    except FileNotFoundError:
        return out
    end = data.rfind(b"\n")
    for n, raw in enumerate(data[:end + 1].splitlines(), 1):
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as e:
            raise UsageError(f"{p}:{n}: corrupt usage line: {e}") from None
        old = out.get(row.get("key"))
        if old is None or better(old, row):
            out[row["key"]] = row
    return out


# ------------------------------------------------------------------ ingest

@dataclass
class IngestResult:
    logs: int = 0
    new: int = 0                      # responses not in the store before
    superseded: int = 0               # responses replaced by a better line
    outside: int = 0                  # responses whose cwd is outside every root (not stored)
    no_cwd: int = 0                   # responses with no cwd at all (not stored)
    legacy_rollouts: list[str] = field(default_factory=list)   # Codex rollouts with no per-response usage
    served: int = 0                   # usage.served events written
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def discover(roots, harnesses=HARNESSES, *, claude_home=None, codex_home=None) -> tuple[list, list[str]]:
    refs: list[sources.LogRef] = []
    notes: list[str] = []
    for h in harnesses:
        if h == "claude":
            refs += sources.claude_logs(roots, claude_home)
        elif h == "codex":
            got, n = sources.codex_logs(roots, codex_home)
            refs += got
            notes += n
        else:
            raise UsageError(f"unknown harness {h!r} (one of {', '.join(HARNESSES)})")
    return refs, notes


def _load_state(p: Path) -> dict:
    try:
        st = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"files": {}}
    except json.JSONDecodeError as e:
        raise UsageError(f"{p}: corrupt ingest state ({e}); move it aside to re-read every log "
                         "(the store de-duplicates, so nothing is counted twice)") from None
    st.setdefault("files", {})
    return st


def _save_state(p: Path, st: dict) -> None:
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(st, fh)
    os.replace(tmp, p)


def _read_new(ref: sources.LogRef, st: dict):
    """Yield (rid, row) for the new complete lines of one log; updates st['files'][path]."""
    path = Path(ref.path)
    info = path.stat()
    key = str(path.resolve())
    fst = st["files"].get(key)
    if (fst is None or fst.get("harness") != ref.harness or fst.get("ino") != info.st_ino
            or info.st_size < fst.get("offset", 0)):
        fst = {"harness": ref.harness, "ino": info.st_ino, "offset": 0, "parser": {}}
    reader = reader_for(ref)
    reader.restore(fst.get("parser") or {})
    with open(path, "rb") as fh:
        fh.seek(fst["offset"])
        chunk = fh.read()
    end = chunk.rfind(b"\n")
    if end >= 0:
        for raw in chunk[:end + 1].splitlines():
            got = reader.feed(raw.decode("utf-8", errors="replace"))
            if got:
                yield got
        fst["offset"] += end + 1
    fst["parser"] = reader.state()
    st["files"][key] = fst
    if reader.legacy_only():
        fst["legacy_only"] = True
    else:
        fst.pop("legacy_only", None)


def ingest(workdir: Path, roots: Iterable, *, harnesses=HARNESSES, refs: list | None = None,
           claude_home: Path | None = None, codex_home: Path | None = None,
           clock=time.time) -> IngestResult:
    """Read the new usage of every session log of the roots into the store and record the model
    served to each agent. `refs` (explicit logs) replaces discovery; the per-response cwd check
    applies either way. Holds an exclusive lock on the store for the whole ingest."""
    workdir = Path(workdir)
    roots = list(roots)
    if not roots:
        raise UsageError("no roots: ingest reads only the sessions of the event workdir and any --root")
    nroots = sources.normalize_roots(roots)
    res = IngestResult()
    if refs is None:
        refs, res.notes = discover(roots, harnesses, claude_home=claude_home, codex_home=codex_home)
    d = store_dir(workdir)
    d.mkdir(parents=True, exist_ok=True)
    lock = os.open(d / LOCK_NAME, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        best = load(workdir)
        sp = d / STATE_NAME
        st = _load_state(sp)
        lines: list[bytes] = []
        now = clock()
        for ref in refs:
            res.logs += 1
            for rid, row in _read_new(ref, st):
                if not row.get("cwd"):
                    res.no_cwd += 1
                    continue
                if not sources.inside(row["cwd"], nroots):
                    res.outside += 1
                    continue
                row.update(key=f"{ref.harness}:{rid}", agent=ref.agent, parent=ref.parent,
                           kind=ref.kind, log=str(ref.path), ingested=now)
                old = best.get(row["key"])
                if old is not None and not better(old, row):
                    continue
                res.new += old is None
                res.superseded += old is not None
                best[row["key"]] = row
                lines.append((json.dumps(row, separators=(",", ":"), default=str) + "\n").encode())
            if st["files"][str(Path(ref.path).resolve())].get("legacy_only"):
                res.legacy_rollouts.append(str(ref.path))
        if lines:
            fd = os.open(store_path(workdir), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, b"".join(lines))
            finally:
                os.close(fd)
        _save_state(sp, st)
        res.served = record_served(workdir, best)
    finally:
        os.close(lock)
    return res


def record_served(workdir: Path, rows: dict[str, dict]) -> int:
    """One usage.served ledger event per (harness, agent, model) not yet recorded."""
    seen = {(r.get("harness"), r.get("agent"), r.get("model"))
            for r in _ledger.read(workdir) if r.get("event") == SERVED_EVENT}
    first: dict[tuple, dict] = {}
    for row in rows.values():
        k = (row["harness"], row["agent"], row.get("model"))
        if k in seen or row.get("model") is None:
            continue
        cur = first.get(k)
        if cur is None or (row.get("ts") or "") < (cur.get("ts") or ""):
            first[k] = row
    att = Attributor(workdir) if first else None
    n = 0
    for (h, agent, model), row in sorted(first.items(), key=lambda kv: (kv[1].get("ts") or "", kv[0])):
        fields = {"harness": h, "agent": agent, "model": model, "kind": row.get("kind") or "main",
                  "first_ts": row.get("ts")}
        if row.get("parent"):
            fields["parent"] = row["parent"]
        cid, _how, _why = att.of(row)
        if cid:
            fields["challenge_id"] = cid
        _ledger.append(SERVED_EVENT, workdir=workdir, **fields)
        n += 1
    return n


# ------------------------------------------------------------------ attribution

def assign(workdir: Path, agent: str, challenge_id: str, *, by: str, note: str | None = None) -> dict:
    """Record that `agent`'s responses (and its subagents') belong to `challenge_id`."""
    for name, v in (("agent", agent), ("challenge id", challenge_id), ("by", by)):
        if not isinstance(v, str) or not v.strip():
            raise UsageError(f"assign needs a non-empty {name}")
    fields = {"agent": agent, "challenge_id": challenge_id, "by": by}
    if note:
        fields["note"] = note
    return _ledger.append(ASSIGN_EVENT, workdir=workdir, **fields)


def assign_role(workdir: Path, agent: str, role: str, *, by: str, note: str | None = None) -> dict:
    """B-096: record that `agent`'s responses (and its subagents') are `role` work, so summarize(roles=)
    can split verify-role dollars by model (EFFICIENCY-PLAN 3.8). `role` must be one of the spend
    categories (ctf.stages.SPEND_CATEGORIES); an unknown role fails loudly rather than mislabelling."""
    for name, v in (("agent", agent), ("role", role), ("by", by)):
        if not isinstance(v, str) or not v.strip():
            raise UsageError(f"assign-role needs a non-empty {name}")
    from ctf import stages as _stages
    if role not in _stages.SPEND_CATEGORIES:
        raise UsageError(f"unknown role {role!r}; one of: {', '.join(_stages.SPEND_CATEGORIES)}")
    fields = {"agent": agent, "role": role, "by": by}
    if note:
        fields["note"] = note
    return _ledger.append(ROLE_EVENT, workdir=workdir, **fields)


def roles_from_ledger(records: Iterable[dict]) -> dict[str, str]:
    """{agent: role} from the `usage.role` events, latest assignment winning (records are chronological).
    Pass the result as summarize(..., roles=); an empty map means no role split was recorded."""
    out: dict[str, str] = {}
    for r in records:
        if r.get("event") == ROLE_EVENT and r.get("agent") and r.get("role"):
            out[str(r["agent"])] = str(r["role"])
    return out


class Attributor:
    """The one attribution rule: assign (agent, then parent chain) > the challenge folder of the cwd."""

    def __init__(self, workdir: Path, records: Iterable[dict] | None = None,
                 parents: dict[str, str] | None = None):
        self.workdir = Path(workdir)
        self.wd_forms = sources.normalize_roots([self.workdir])
        recs = records if records is not None else _ledger.read(self.workdir)
        self.assigns: dict[str, str] = {}
        for r in recs:
            if r.get("event") == ASSIGN_EVENT and r.get("agent") and r.get("challenge_id"):
                self.assigns[str(r["agent"])] = str(r["challenge_id"])
        self.parents = dict(parents or {})
        self._folders: dict[str, tuple[str | None, str]] = {}

    def learn(self, rows: Iterable[dict]) -> None:
        for r in rows:
            if r.get("parent"):
                self.parents.setdefault(r["agent"], r["parent"])

    def of(self, row: dict) -> tuple[str | None, str | None, str]:
        """(challenge id | None, how: assign | assign:parent | cwd | None, why not when None)."""
        agent = row.get("agent")
        if agent in self.assigns:
            return self.assigns[agent], "assign", ""
        p, depth = row.get("parent") or self.parents.get(agent), 0
        while p and depth < _PARENT_DEPTH:
            if p in self.assigns:
                return self.assigns[p], "assign:parent", ""
            p, depth = self.parents.get(p), depth + 1
        cid, why = self.folder_of(row.get("cwd"))
        return (cid, "cwd", "") if cid else (None, None, why)

    def folder_of(self, cwd: str | None) -> tuple[str | None, str]:
        if not cwd:
            return None, "no cwd"
        for c in sorted(sources._forms(cwd)):
            for wd in self.wd_forms:
                if c == wd:
                    return None, "cwd is the workdir itself, not a challenge folder"
                if c.startswith(wd.rstrip(os.sep) + os.sep):
                    name = c[len(wd.rstrip(os.sep)) + 1:].split(os.sep, 1)[0]
                    return self._folder(name)
        return None, "cwd is outside the event workdir"

    def _folder(self, name: str) -> tuple[str | None, str]:
        if name not in self._folders:
            cj = self.workdir / name / "challenge.json"
            try:
                d = json.loads(cj.read_text(encoding="utf-8"))
            except FileNotFoundError:
                self._folders[name] = (None, f"folder {name} has no challenge.json")
            except (OSError, json.JSONDecodeError, ValueError) as e:
                self._folders[name] = (None, f"folder {name}: unreadable challenge.json ({e})")
            else:
                cid = d.get("id") if isinstance(d, dict) else None
                if cid is None or isinstance(cid, bool) or str(cid).strip() == "":
                    self._folders[name] = (None, f"folder {name}: challenge.json has no id")
                else:
                    self._folders[name] = (str(cid), "")
        return self._folders[name]


# ------------------------------------------------------------------ reports

@dataclass
class Report:
    responses: int = 0
    usd: float = 0.0
    tok: int = 0
    by_model: list = field(default_factory=list)        # {harness, model, tier, responses, tok, usd}
                                                        # (tier: the row's speed; priced rows only)
    by_challenge: dict = field(default_factory=dict)    # cid -> {responses, tok, usd, models}
    unattributed: dict = field(default_factory=dict)    # {responses, tok, usd, agents: [...]}
    agents: list = field(default_factory=list)          # model served per agent
    ttl_assumed: dict = field(default_factory=dict)     # {responses, usd}
    unpriced: list = field(default_factory=list)        # {harness, model, tier, responses, reason}
    by_role: list = field(default_factory=list)         # B-096: {role, responses, tok, usd}; empty when
                                                        # no roles map is given
    by_role_model: list = field(default_factory=list)   # B-096: {role, harness, model, tier, responses,
                                                        # tok, usd}: verify-role cost per model (3.8)

    def to_dict(self) -> dict:
        return asdict(self)


def summarize(rows: dict[str, dict] | Iterable[dict], prices: dict, att: Attributor,
              *, roles: dict[str, str] | None = None) -> Report:
    """Totals per model+tier, per challenge, per agent, and (B-096) per work role and per role+model
    when `roles` (agent id -> role, e.g. from roles_from_ledger) is given. Without it the two by_role
    fields stay empty and the report is unchanged. A priced response whose agent has no role falls
    under DEFAULT_ROLE, so verify-role dollars are never silently merged into another role's total."""
    rows = list(rows.values()) if isinstance(rows, dict) else list(rows)
    att.learn(rows)
    rep = Report()
    models: dict = collections.defaultdict(lambda: {"responses": 0, "tok": 0, "usd": 0.0})
    role_tot: dict = collections.defaultdict(lambda: {"responses": 0, "tok": 0, "usd": 0.0})
    role_models: dict = collections.defaultdict(lambda: {"responses": 0, "tok": 0, "usd": 0.0})
    chal: dict = collections.defaultdict(lambda: {"responses": 0, "tok": 0, "usd": 0.0,
                                                   "models": collections.Counter()})
    agents: dict = {}
    unpriced: dict = {}
    un = {"responses": 0, "tok": 0, "usd": 0.0}
    un_agents: dict = {}
    ttl = {"responses": 0, "usd": 0.0}
    for r in sorted(rows, key=lambda r: (r.get("ts") or "", r["key"])):
        tier = r.get("speed") or "default"
        cid, _how, why = att.of(r)
        a = agents.get((r["harness"], r["agent"]))
        if a is None:
            a = agents[(r["harness"], r["agent"])] = {
                "harness": r["harness"], "agent": r["agent"], "parent": r.get("parent"),
                "kind": r.get("kind") or "main", "responses": 0, "usd": 0.0, "models": collections.Counter(),
                "tiers": collections.Counter(), "challenges": collections.Counter(),
                "first_ts": r.get("ts"), "last_ts": r.get("ts")}
        a["responses"] += 1
        a["models"][r.get("model")] += 1
        a["tiers"][tier] += 1
        a["challenges"][cid or "-"] += 1
        a["last_ts"] = r.get("ts") or a["last_ts"]
        try:
            usd = pricing.cost(r, prices)
        except pricing.PricingError as e:
            k = (r["harness"], r.get("model"), tier)
            u = unpriced.setdefault(k, {"harness": k[0], "model": k[1], "tier": k[2], "responses": 0,
                                        "reason": str(e)})
            u["responses"] += 1
            continue
        tok = pricing.tokens(r)
        a["usd"] += usd
        rep.responses += 1
        rep.usd += usd
        rep.tok += tok
        m = models[(r["harness"], r.get("model"), tier)]
        m["responses"] += 1
        m["tok"] += tok
        m["usd"] += usd
        if roles is not None:
            role = roles.get(r["agent"]) or DEFAULT_ROLE
            rt = role_tot[role]
            rt["responses"] += 1
            rt["tok"] += tok
            rt["usd"] += usd
            rm = role_models[(role, r["harness"], r.get("model"), tier)]
            rm["responses"] += 1
            rm["tok"] += tok
            rm["usd"] += usd
        if r.get("ttl_assumed"):
            ttl["responses"] += 1
            ttl["usd"] += usd
        if cid:
            c = chal[cid]
            c["responses"] += 1
            c["tok"] += tok
            c["usd"] += usd
            c["models"][r.get("model")] += 1
        else:
            un["responses"] += 1
            un["tok"] += tok
            un["usd"] += usd
            ua = un_agents.setdefault((r["harness"], r["agent"]), {
                "harness": r["harness"], "agent": r["agent"], "kind": r.get("kind") or "main",
                "cwd": r.get("cwd"), "why": why, "responses": 0, "usd": 0.0})
            ua["responses"] += 1
            ua["usd"] += usd
    rep.by_model = sorted(({"harness": h, "model": mo, "tier": t, **v} for (h, mo, t), v in models.items()),
                          key=lambda x: -x["usd"])
    rep.by_challenge = {k: dict(v, models=dict(v["models"])) for k, v in sorted(chal.items())}
    rep.unattributed = dict(un, agents=sorted(un_agents.values(), key=lambda x: -x["usd"]))
    for a in agents.values():
        a["served"] = a["models"].most_common(1)[0][0]
        a["models"], a["tiers"], a["challenges"] = dict(a["models"]), dict(a["tiers"]), dict(a["challenges"])
    rep.agents = sorted(agents.values(), key=lambda x: (-x["usd"], x["agent"]))
    rep.ttl_assumed = ttl
    rep.unpriced = sorted(unpriced.values(), key=lambda x: -x["responses"])
    if roles is not None:
        rep.by_role = sorted(({"role": k, **v} for k, v in role_tot.items()), key=lambda x: -x["usd"])
        rep.by_role_model = sorted(
            ({"role": rk, "harness": h, "model": mo, "tier": t, **v}
             for (rk, h, mo, t), v in role_models.items()), key=lambda x: (x["role"], -x["usd"]))
    return rep


@dataclass(frozen=True)
class Reconciled:
    challenge_id: str
    usage_usd: float
    usage_tok: int
    ledger_usd: float
    ledger_tok: int

    @property
    def delta_usd(self) -> float:
        return self.usage_usd - self.ledger_usd

    @property
    def delta_tok(self) -> int:
        return self.usage_tok - self.ledger_tok

    def to_dict(self) -> dict:
        return dict(asdict(self), delta_usd=self.delta_usd, delta_tok=self.delta_tok)


def reconcile(rep: Report, records: Iterable[dict]) -> list[Reconciled]:
    """Usage per challenge against the `spend` the event ledger holds for it (every source: the
    launchers, tools.ledger feed, earlier reconcile top-ups, hand entries)."""
    spent: dict = collections.defaultdict(lambda: [0.0, 0])
    for r in records:
        if r.get("event") == "spend" and r.get("challenge_id"):
            s = spent[str(r["challenge_id"])]
            s[0] += float(r.get("usd") or 0.0)
            s[1] += int(r.get("tok") or 0)
    ids = sorted(set(rep.by_challenge) | set(spent))
    out = []
    for cid in ids:
        u = rep.by_challenge.get(cid, {"usd": 0.0, "tok": 0})
        out.append(Reconciled(cid, u["usd"], u["tok"], spent[cid][0], spent[cid][1]))
    return out


def charge(meter, recon: list[Reconciled], *, min_usd: float = 0.005) -> list[tuple[Reconciled, str]]:
    """Top the event ledger up to the usage ledger: for each challenge whose usage exceeds its ledger
    spend by at least `min_usd`, one add_spend of the difference (source usage:reconcile). Re-running
    charges nothing more. Returns [(row, outcome)] with outcome charged | at_cap (charged, cap reached)."""
    from ctf import budget as _budget
    if not math.isfinite(min_usd) or min_usd <= 0:
        raise UsageError("min_usd must be a positive amount")
    out = []
    for r in recon:
        if r.delta_usd < min_usd:
            continue
        try:
            meter.add_spend(r.challenge_id, round(r.delta_usd, 10), max(0, r.delta_tok), source=RECONCILE_SOURCE)
            out.append((r, "charged"))
        except _budget.BudgetExceeded:
            out.append((r, "at_cap"))
    return out


# ------------------------------------------------------------------ cache TTL (B-118)

TTL_WINDOW_S = 300.0      # a 5-minute cache write lives 5 minutes from its last use
TTL_1H_S = 3600.0         # a 1-hour cache write lives 1 hour from its last use


def _ts_seconds(ts) -> float | None:
    """A log timestamp (ISO 8601, 'Z' or an offset; naive read as UTC) as epoch seconds, else None."""
    if not isinstance(ts, str) or not ts.strip():
        return None
    try:
        d = _dt.datetime.fromisoformat(ts.strip())
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=_dt.timezone.utc)
    return d.timestamp()


@dataclass
class TtlThread:
    harness: str
    agent: str
    kind: str
    parent: str | None
    responses: int = 0          # responses of the thread with a usable timestamp
    writes_1h: int = 0          # priced responses that wrote 1-hour cache
    tok_1h: int = 0
    usd_1h: float = 0.0         # what those responses cost
    hit_5m: int = 0             # 1h writes whose next response came within the window
    tok_hit_5m: int = 0
    saving: float = 0.0         # GROSS: those writes priced at the 5-minute rate instead (no counter-cost)
    late_1h: int = 0            # 1h writes whose next response came after the window
    tok_late_1h: int = 0
    saving_late: float = 0.0    # those writes at the 5-minute rate (their next response pays cost_late)
    last_1h: int = 0            # 1h writes with no next response in the thread
    tok_last_1h: int = 0
    saving_last: float = 0.0    # the last ones at the 5-minute rate (nothing read them again)
    reread_late: int = 0        # responses more than the window but at most 1h after the previous one, in
                                # a thread that had written 1h cache, that read cache: at 5m it had expired
    tok_reread_late: int = 0    # the cache_read tokens of those responses
    cost_late: float = 0.0      # those tokens written again at the 5-minute rate, minus the read they were
    net: float = 0.0            # every 1h write at the 5m rate, minus the re-writes:
                                # saving + saving_late + saving_last - cost_late
    writes_5m: int = 0          # responses that wrote 5-minute cache
    late_5m: int = 0            # 5m writes whose next response came after the window (a cold re-cache)
    tok_late_5m: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TtlReport:
    window_s: float
    threads: list = field(default_factory=list)       # TtlThread, highest net first
    by_kind: dict = field(default_factory=dict)       # kind -> the TtlThread counters summed, + threads
    total: dict = field(default_factory=dict)
    no_ts: dict = field(default_factory=dict)         # {responses, tok_1h}: rows without a usable timestamp
    unpriced: list = field(default_factory=list)      # {model, tier, responses, reason}

    def to_dict(self) -> dict:
        return {"window_s": self.window_s, "threads": [t.to_dict() for t in self.threads],
                "by_kind": self.by_kind, "total": self.total, "no_ts": self.no_ts, "unpriced": self.unpriced}


TTL_SUMS = ("responses", "writes_1h", "tok_1h", "usd_1h", "hit_5m", "tok_hit_5m", "saving", "late_1h",
            "tok_late_1h", "saving_late", "last_1h", "tok_last_1h", "saving_last", "reread_late",
            "tok_reread_late", "cost_late", "net", "writes_5m", "late_5m", "tok_late_5m")


def _as_5m(row: dict) -> dict:
    """The row as if its 1-hour cache writes had been 5-minute writes."""
    return dict(row, cache_5m=(row.get("cache_5m") or 0) + (row.get("cache_1h") or 0), cache_1h=0)


def _reread_as_5m(row: dict) -> dict:
    """The row as if the cache it read had expired: those tokens written again as 5-minute cache."""
    return dict(row, cache_5m=(row.get("cache_5m") or 0) + (row.get("cache_read") or 0), cache_read=0)


def ttl_report(rows: dict[str, dict] | Iterable[dict], prices: dict, *,
               window_s: float = TTL_WINDOW_S) -> TtlReport:
    """B-118 (EFFICIENCY-PLAN 3.12): per Claude thread (one agent's log), what 5-minute writes would have
    cost instead of the 1-hour writes it made.

    Gross: the 1h writes whose next response in that thread came within `window_s`, priced at the
    5-minute rate (`saving`, the plan's hindsight figure): a 5-minute write would still have been warm.
    A 1h write followed after the window (late_1h, saving_late) or by nothing (last_1h, saving_last) is
    also cheaper at 5m. The counter-cost: a response that came more than `window_s` but at most 1 hour
    after the previous one, in a thread that had written 1h cache, read a prefix only the 1h cache kept
    warm; at 5m it would have expired, so its cache_read tokens are priced as 5-minute writes minus the
    read they were (reread_late, cost_late). `net` = saving + saving_late + saving_last - cost_late: the
    whole thread at 5m. 5-minute writes followed after the window are the cold re-caches (late_5m) that
    B-017's no-idle watcher is for. Gaps run from response timestamp to response timestamp. Codex rows
    carry no cache TTL and are not read. A row without a usable timestamp cannot be placed and is counted
    in no_ts, never guessed; a model the table cannot price is listed in unpriced and is in no sum."""
    if isinstance(window_s, bool) or not isinstance(window_s, (int, float)) \
            or not math.isfinite(window_s) or window_s <= 0:
        raise UsageError(f"window must be a positive number of seconds (got {window_s!r})")
    rows = list(rows.values()) if isinstance(rows, dict) else list(rows)
    rep = TtlReport(window_s=float(window_s))
    no_ts = {"responses": 0, "tok_1h": 0}
    unpriced: dict = {}
    threads: dict[str, list] = collections.defaultdict(list)
    for r in rows:
        if r.get("harness") != "claude":
            continue
        t = _ts_seconds(r.get("ts"))
        if t is None:
            no_ts["responses"] += 1
            no_ts["tok_1h"] += r.get("cache_1h") or 0
            continue
        threads[r["agent"]].append((t, r.get("key") or "", r))
    out = []
    for agent, seq in threads.items():
        seq.sort(key=lambda x: (x[0], x[1]))
        first = seq[0][2]
        th = TtlThread("claude", agent, first.get("kind") or "main", first.get("parent"))
        wrote_1h = False            # the thread wrote 1h cache before this response
        for i, (t, _k, r) in enumerate(seq):
            th.responses += 1
            gap = seq[i + 1][0] - t if i + 1 < len(seq) else None
            since = t - seq[i - 1][0] if i else None
            c1, c5, cr = r.get("cache_1h") or 0, r.get("cache_5m") or 0, r.get("cache_read") or 0
            reread = bool(wrote_1h and cr and since is not None and window_s < since <= TTL_1H_S)
            wrote_1h = wrote_1h or bool(c1)
            if c5:
                th.writes_5m += 1
                if gap is not None and gap > window_s:
                    th.late_5m += 1
                    th.tok_late_5m += c5
            if not c1 and not reread:
                continue
            try:
                paid = pricing.cost(r, prices)
                saved = paid - pricing.cost(_as_5m(r), prices) if c1 else 0.0
                rewrite = pricing.cost(_reread_as_5m(r), prices) - paid if reread else 0.0
            except pricing.PricingError as e:
                k = (r.get("model"), r.get("speed") or "standard")
                u = unpriced.setdefault(k, {"model": k[0], "tier": k[1], "responses": 0, "reason": str(e)})
                u["responses"] += 1
                continue
            if reread:
                th.reread_late += 1
                th.tok_reread_late += cr
                th.cost_late += rewrite
            if not c1:
                continue
            th.writes_1h += 1
            th.tok_1h += c1
            th.usd_1h += paid
            if gap is None:
                th.last_1h += 1
                th.tok_last_1h += c1
                th.saving_last += saved
            elif gap <= window_s:
                th.hit_5m += 1
                th.tok_hit_5m += c1
                th.saving += saved
            else:
                th.late_1h += 1
                th.tok_late_1h += c1
                th.saving_late += saved
        th.net = th.saving + th.saving_late + th.saving_last - th.cost_late
        out.append(th)
    rep.threads = sorted(out, key=lambda x: (-x.net, -x.saving, -x.writes_1h, x.agent))
    total: dict = {k: 0 for k in TTL_SUMS}
    kinds: dict = {}
    for th in rep.threads:
        kd = kinds.setdefault(th.kind, {k: 0 for k in TTL_SUMS} | {"threads": 0})
        kd["threads"] += 1
        for k in TTL_SUMS:
            total[k] += getattr(th, k)
            kd[k] += getattr(th, k)
    total["threads"] = len(rep.threads)
    rep.total = total
    rep.by_kind = dict(sorted(kinds.items()))
    rep.no_ts = no_ts
    rep.unpriced = sorted(unpriced.values(), key=lambda x: -x["responses"])
    return rep
