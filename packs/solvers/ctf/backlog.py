"""Backlog as data (B-138): one machine-readable source of truth for the improvements backlog, so the
status of a build is a field, not a word hidden in a Markdown table that gets miscounted by eye.

    from ctf import backlog
    rows = backlog.load(backlog.default_path())        # docs/backlog.jsonl (the master backlog)
    rows, row = backlog.set_status(rows, "B-138", "merged")   # a done status moves the row out of open
    backlog.save(backlog.default_path(), rows)
    print(backlog.render_markdown(rows))               # the Markdown render
    rk = backlog.rank(rows, event.load("csctf"), effort_budget=6)   # reuses buildplan.rank

Why: the backlog was a Markdown table with status in free text. On Oct 9-10 the main thread miscounted
it twice ('player' matched inside done notes; 18 open reported where 21 were open, with 90 built rows
still sitting in the Backlog section). 17 inline Python one-liners plus repeated awk parsed that table.
Here a row is JSON, status is a closed vocabulary, the open count is computed, and a build that is done
moves to the Done section by itself. The hard-tail rows (blocked / deferred) are kept, never dropped.

A row (JSONL, one JSON object per line; blank lines and ``#`` comment lines are ignored):

    id          required, str              the B-id (unique in the file)
    title       required, str
    status      required, one of STATUSES  open | in-progress | partial | blocked | deferred
                                           | built | merged | done | dropped
    decision    free text                  what we decided to do (build / wait / drop / ...)
    impact      free text                  what it buys (qualitative; no dollar figures here)
    cost        free text                  effort / tokens, qualitatively
    risk        free text
    evidence    list[str]                  in-repo pointers (BUILD-PLAN.md line, a build-log path)
    lane        str                        the build lane (buildplan category); needed to rank
    effort      S | M | L | XL or a number required to rank
    priority    P0..P3 or null
    dependencies  list[str]
    automatable yes | partly | no | null
    merged_into str | null

Terminal statuses (built, merged, done, dropped) are the Done section and do not count as open. The
others count as open; blocked and deferred are the hard tail and render in their own group, kept with
their blocker. Same schema serves a per-event backlog under the workdir (event_path(slug))."""
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable

from . import buildplan, ledger, paths
from .event import EventProfile

SCHEMA = 1

# status -> terminal? (terminal rows are "done": they leave the open backlog). Insertion order is the
# render order within a section.
STATUSES: dict[str, bool] = {
    "open": False,
    "in-progress": False,
    "partial": False,
    "blocked": False,       # hard tail: kept with its blocker, still open
    "deferred": False,      # hard tail: not built by design, still open
    "built": True,
    "merged": True,
    "done": True,
    "dropped": True,
}
# The hard tail: open rows that a build runner cannot simply pick up; kept, never dropped.
HARD_TAIL = ("blocked", "deferred")
BACKLOG_NAME = "backlog.jsonl"


class BacklogError(ValueError):
    """A backlog file or row is missing or invalid; the message names it."""


def is_terminal(status: str) -> bool:
    try:
        return STATUSES[status]
    except KeyError:
        raise BacklogError(f"unknown status {status!r}; one of {', '.join(STATUSES)}") from None


# ------------------------------------------------------------------------------------------- rows

@dataclass(frozen=True)
class Row:
    id: str
    title: str = ""
    status: str = "open"
    decision: str = ""
    impact: str = ""
    cost: str = ""
    risk: str = ""
    evidence: tuple[str, ...] = ()
    lane: str = ""
    effort: str = ""
    priority: str | None = None
    dependencies: tuple[str, ...] = ()
    automatable: str | None = None
    merged_into: str | None = None

    @property
    def terminal(self) -> bool:
        return is_terminal(self.status)

    @property
    def hard_tail(self) -> bool:
        return self.status in HARD_TAIL

    def to_dict(self) -> dict:
        return {
            "id": self.id, "title": self.title, "status": self.status, "decision": self.decision,
            "impact": self.impact, "cost": self.cost, "risk": self.risk,
            "evidence": list(self.evidence), "lane": self.lane, "effort": self.effort,
            "priority": self.priority, "dependencies": list(self.dependencies),
            "automatable": self.automatable, "merged_into": self.merged_into,
        }


def _str(v, where: str) -> str:
    if v is None:
        return ""
    if not isinstance(v, str):
        raise BacklogError(f"{where}: expected a string, got {type(v).__name__}")
    return v


def _strlist(v, where: str) -> tuple[str, ...]:
    if v is None:
        return ()
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise BacklogError(f"{where}: expected a list of strings")
    return tuple(v)


def parse_row(rec: object, where: str = "row") -> Row:
    if not isinstance(rec, dict):
        raise BacklogError(f"{where}: expected an object, got {type(rec).__name__}")
    iid = rec.get("id")
    if not isinstance(iid, str) or not iid.strip():
        raise BacklogError(f"{where}.id: required (a non-empty string)")
    where = f"{where} ({iid})"
    status = rec.get("status", "open")
    if status not in STATUSES:
        raise BacklogError(f"{where}.status: unknown status {status!r}; one of {', '.join(STATUSES)}")
    prio = rec.get("priority")
    if prio is not None and prio not in buildplan.PRIORITY_WEIGHT:
        raise BacklogError(f"{where}.priority: expected one of {', '.join(buildplan.PRIORITY_WEIGHT)} "
                           f"or null, got {prio!r}")
    return Row(
        id=iid.strip(), title=_str(rec.get("title"), f"{where}.title"), status=status,
        decision=_str(rec.get("decision"), f"{where}.decision"),
        impact=_str(rec.get("impact"), f"{where}.impact"),
        cost=_str(rec.get("cost"), f"{where}.cost"), risk=_str(rec.get("risk"), f"{where}.risk"),
        evidence=_strlist(rec.get("evidence"), f"{where}.evidence"),
        lane=_str(rec.get("lane"), f"{where}.lane"),
        effort=_str(rec.get("effort"), f"{where}.effort"), priority=prio,
        dependencies=_strlist(rec.get("dependencies"), f"{where}.dependencies"),
        automatable=rec.get("automatable"), merged_into=rec.get("merged_into") or None,
    )


# ------------------------------------------------------------------------------------- load / save

def default_path() -> Path:
    """The committed master backlog: <repo>/docs/backlog.jsonl."""
    return paths.repo_root() / "docs" / BACKLOG_NAME


def event_path(slug: str | None = None) -> Path:
    """The per-event backlog in the workdir (same schema), <workdir>/backlog.jsonl."""
    return paths.workdir(slug) / BACKLOG_NAME


def load(path: str | Path) -> list[Row]:
    p = Path(path)
    if not p.is_file():
        raise BacklogError(f"backlog file not found: {p}")
    rows: list[Row] = []
    seen: set[str] = set()
    for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        try:
            rec = json.loads(s)
        except json.JSONDecodeError as e:
            raise BacklogError(f"{p}:{n}: not JSON: {e}") from None
        row = parse_row(rec, f"{p.name}:{n}")
        if row.id in seen:
            raise BacklogError(f"{p}:{n}: duplicate row id {row.id}")
        seen.add(row.id)
        rows.append(row)
    return rows


def save(path: str | Path, rows: Iterable[Row]) -> Path:
    """Write the rows as JSONL, atomically, open rows first then done rows (both in status order).
    This is where a now-done row 'moves' out of the open section of the file."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(json.dumps(r.to_dict(), ensure_ascii=False) for r in order(rows))
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(body + ("\n" if body else ""), encoding="utf-8")
    os.replace(tmp, p)
    return p


# ----------------------------------------------------------------------------------- queries / sort

def _status_rank(status: str) -> int:
    return list(STATUSES).index(status)


def order(rows: Iterable[Row]) -> list[Row]:
    """Open rows first, then done rows; within each, by the STATUSES order then id. A done row sorts
    after every open row, which is how a status change moves it."""
    return sorted(rows, key=lambda r: (r.terminal, _status_rank(r.status), r.id))


def open_rows(rows: Iterable[Row]) -> list[Row]:
    return [r for r in order(rows) if not r.terminal]


def done_rows(rows: Iterable[Row]) -> list[Row]:
    return [r for r in order(rows) if r.terminal]


def hard_tail(rows: Iterable[Row]) -> list[Row]:
    return [r for r in order(rows) if r.hard_tail]


def counts(rows: Iterable[Row]) -> dict:
    rows = list(rows)
    by_status: dict[str, int] = {s: 0 for s in STATUSES}
    for r in rows:
        by_status[r.status] += 1
    n_open = sum(1 for r in rows if not r.terminal)
    return {
        "total": len(rows),
        "open": n_open,
        "done": len(rows) - n_open,
        "hard_tail": sum(1 for r in rows if r.hard_tail),
        "by_status": by_status,
    }


def get(rows: Iterable[Row], item_id: str) -> Row | None:
    return next((r for r in rows if r.id == item_id), None)


# ----------------------------------------------------------------------------------- status change

def set_status(rows: list[Row], item_id: str, status: str, *, workdir: Path | None = None,
               log: bool = True) -> tuple[list[Row], Row]:
    """Change one row's status and return (new rows list, the updated row). A terminal status moves
    the row to the Done section (via order()/save()). Raises on an unknown id or status."""
    if status not in STATUSES:
        raise BacklogError(f"unknown status {status!r}; one of {', '.join(STATUSES)}")
    idx = next((i for i, r in enumerate(rows) if r.id == item_id), None)
    if idx is None:
        raise BacklogError(f"no backlog row with id {item_id!r}")
    old = rows[idx]
    extra = {}
    if status == "merged" and not old.merged_into:
        extra["merged_into"] = None     # 'merged' means built-and-merged here, not merged-into-another
    new = replace(old, status=status, **extra)
    out = list(rows)
    out[idx] = new
    if log and old.status != status:
        ledger.append("backlog.status", workdir=workdir, item=item_id,
                      **{"from": old.status, "to": status, "terminal": new.terminal})
    return out, new


# ------------------------------------------------------------------------------------------- rank

def to_items(rows: Iterable[Row], *, include_done: bool = False) -> list[buildplan.Item]:
    """Build buildplan Items for ranking. A row with no lane or effort cannot be ranked and raises a
    named error (no silent fallback). Done rows are excluded unless include_done."""
    items = []
    for r in rows:
        if r.terminal and not include_done:
            continue
        if not r.lane:
            raise BacklogError(f"row {r.id}: no lane; cannot rank it (give it a buildplan lane)")
        if not r.effort:
            raise BacklogError(f"row {r.id}: no effort; cannot rank it (S/M/L/XL or a number)")
        items.append(buildplan.parse_item({
            "id": r.id, "title": r.title, "lane": r.lane, "effort": r.effort,
            "priority": r.priority, "dependencies": list(r.dependencies),
            "automatable": r.automatable, "merged_into": r.merged_into,
        }, where=f"backlog row {r.id}"))
    return items


def rank(rows: Iterable[Row], profile: EventProfile, *, effort_budget: float = 0.0,
         board: buildplan.Board | None = None, include_done: bool = False) -> buildplan.Ranking:
    """Rank the open backlog rows by modeled value per effort, reusing buildplan.rank."""
    items = to_items(rows, include_done=include_done)
    return buildplan.rank(items, profile, effort_budget=effort_budget, board=board)


# ------------------------------------------------------------------------------------------ render

# ------------------------------------------------------------------------- sync from the repo tree

# A BUILD-PLAN.md item line, in either form the plan uses:
#   `- `B-xxx` [effort/auto dep:...] Title`              (the per-category lists)
#   `N. **`B-xxx` [effort/auto dep:...] Title** — desc`  (the Phase 0 build-order list)
_PLAN_LINE = re.compile(
    r"^(?:-|\d+\.)?\s*\*{0,2}`(?P<id>B-\d+[a-z]?)`\s*"
    r"\[(?P<effort>XL|S|M|L)/(?P<auto>[A~N?])(?:\s+dep:(?P<dep>[^\]]*))?\]\s*(?P<title>.*?)\s*$")
# A category group header in the plan: `**web (10)**`.
_GROUP = re.compile(r"^\*\*(?P<lane>[a-z0-9][a-z0-9 /+-]*?)\s*\((?P<n>\d+)\)\*\*\s*$")
# The first word of a build log's Status line.
_STATUS_LINE = re.compile(r"^Status:\s*\*{0,2}(?P<word>[A-Za-z-]+)", re.IGNORECASE)
_AUTO = {"A": "yes", "~": "partly", "N": "no", "?": "unknown"}
# A build-log status word -> a backlog status. 'built' is done-but-not-merged; a Merge commit (or a
# log that states 'merged') wins over it.
_LOG_STATUS = {"built": "built", "merged": "merged", "partial": "partial", "blocked": "blocked",
               "deferred": "deferred", "done": "done", "dropped": "dropped"}


def scan_buildplan(text: str, *, default_lane: str = "") -> list[dict]:
    """The item rows in BUILD-PLAN.md text, each {id, title, effort, lane, automatable, dependencies}.
    lane is the nearest preceding `**lane (n)**` group header. An item under a section with no such
    header (the Phase-0 build-order list) gets `default_lane` ('' keeps it empty)."""
    out: list[dict] = []
    lane = ""
    for line in text.splitlines():
        g = _GROUP.match(line.strip())
        if g:
            lane = g.group("lane").strip().lower()
            continue
        if line.startswith("#"):
            lane = ""               # a new section with no group header clears the lane
            continue
        m = _PLAN_LINE.match(line)
        if not m:
            continue
        dep = (m.group("dep") or "").strip()
        deps = [d.strip() for d in re.split(r"[,\s]+", dep) if d.strip() and d.strip() != "—"]
        title = m.group("title")
        if "**" in title:                       # Phase 0 bold form: Title** — long description
            title = title.split("**", 1)[0]
        title = re.sub(r"\s*—\s*_[^_]*_\s*$", "", title).strip()
        out.append({"id": m.group("id"), "title": title, "effort": m.group("effort"),
                    "lane": lane or default_lane, "automatable": _AUTO[m.group("auto")],
                    "dependencies": deps})
    return out


def scan_log_statuses(build_log_dir: Path) -> dict[str, str]:
    """{B-id: backlog status} read from the first `Status:` line of each docs/build-log/<id>.md."""
    out: dict[str, str] = {}
    if not build_log_dir.is_dir():
        return out
    for p in sorted(build_log_dir.glob("B-*.md")):
        iid = p.stem
        for line in p.read_text(encoding="utf-8").splitlines():
            m = _STATUS_LINE.match(line.strip())
            if m:
                word = m.group("word").lower()
                if word in _LOG_STATUS:
                    out[iid] = _LOG_STATUS[word]
                break
    return out


def merged_ids(repo_root: Path) -> set[str]:
    """B-ids that have a `Merge B-xxx:` commit on HEAD (built and merged into the build branch)."""
    try:
        r = subprocess.run(["git", "-C", str(repo_root), "log", "--format=%s"],
                           capture_output=True, text=True, timeout=60, check=True)
    except (OSError, subprocess.SubprocessError):
        return set()
    out: set[str] = set()
    for line in r.stdout.splitlines():
        m = re.match(r"Merge (B-\d+[a-z]?):", line.strip())
        if m:
            out.add(m.group(1))
    return out


def sync(*, repo_root: Path | None = None, existing: Iterable[Row] = (),
         use_git: bool = True, default_lane: str = "ops") -> list[Row]:
    """Build backlog rows from the in-repo sources of truth: BUILD-PLAN.md (id/title/effort/lane/auto/
    deps), the docs/build-log/<id>.md Status lines, and the `Merge B-xxx` commits. Operator-authored
    fields on an existing row (decision, impact, cost, risk, extra evidence, priority) are preserved;
    status is recomputed from the tree. No network, no analysis/, no secrets.

    Phase-0 build-order items sit under a section with no `**lane (n)**` header, so they carry no lane
    of their own. `default_lane` ('ops', a cross-cutting lane) is assigned to them, since they are
    foundation work that serves every event ('do these first, whatever event is next'); without it
    they cannot be ranked. Pass default_lane='' to leave such rows laneless."""
    root = repo_root or paths.repo_root()
    plan = root / "BUILD-PLAN.md"
    if not plan.is_file():
        raise BacklogError(f"BUILD-PLAN.md not found at {plan}")
    prior = {r.id: r for r in existing}
    log_status = scan_log_statuses(root / "docs" / "build-log")
    merged = merged_ids(root) if use_git else set()

    def _subids(iid: str, pool: Iterable[str]) -> list[str]:
        # {iid} plus any lettered sub-item (B-001 -> B-001a) found in pool. An item split into
        # sub-items (B-001a..d) is done when its sub-items are, even with no 'Merge B-001' of its own.
        pat = re.compile(rf"^{re.escape(iid)}[a-z]$")
        return [iid] + [k for k in pool if pat.match(k)]

    rows: list[Row] = []
    for rec in scan_buildplan(plan.read_text(encoding="utf-8"), default_lane=default_lane):
        iid = rec["id"]
        related = set(_subids(iid, set(merged) | set(log_status)))
        if related & merged:
            status = "merged"
        elif iid in log_status:
            status = log_status[iid]
        elif any(log_status.get(k) in STATUSES and is_terminal(log_status[k])
                 for k in related if k in log_status):
            status = "built"
        else:
            status = "open"
        old = prior.get(iid)
        evidence = [f"BUILD-PLAN.md:{iid}"]
        if (root / "docs" / "build-log" / f"{iid}.md").is_file():
            evidence.append(f"docs/build-log/{iid}.md")
        rows.append(Row(
            id=iid, title=rec["title"], status=status,
            decision=old.decision if old else "", impact=old.impact if old else "",
            cost=old.cost if old else "", risk=old.risk if old else "",
            evidence=tuple(evidence), lane=rec["lane"], effort=rec["effort"],
            priority=old.priority if old else None, dependencies=tuple(rec["dependencies"]),
            automatable=rec["automatable"], merged_into=None,
        ))
    return order(rows)


def _cell(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ").strip() or "-"


def _table(rows: list[Row]) -> list[str]:
    out = ["| id | status | effort | title | decision | impact |",
           "|---|---|---|---|---|---|"]
    for r in rows:
        out.append(f"| {r.id} | {r.status} | {r.effort or '-'} | {_cell(r.title)} | "
                   f"{_cell(r.decision)} | {_cell(r.impact)} |")
    return out


def render_markdown(rows: Iterable[Row], *, title: str = "Backlog") -> str:
    rows = list(rows)
    c = counts(rows)
    opens = [r for r in open_rows(rows) if not r.hard_tail]
    tail = hard_tail(rows)
    done = done_rows(rows)
    lines = [f"# {title}", "",
             "_Generated from the backlog data; do not hand-edit. "
             "Change a row with `python -m ctf backlog set-status <id> <status>`._", "",
             f"**{c['open']} open** ({len(opens)} active + {c['hard_tail']} hard tail) · "
             f"{c['done']} done · {c['total']} total.", ""]
    nonzero = [f"{s} {n}" for s, n in c["by_status"].items() if n]
    lines += [f"Status counts: {', '.join(nonzero) if nonzero else 'none'}.", "",
              "## Open", ""]
    lines += _table(opens) if opens else ["_none_"]
    lines += ["", "## Hard tail (kept with the blocker)", ""]
    lines += _table(tail) if tail else ["_none_"]
    lines += ["", "## Done", ""]
    lines += _table(done) if done else ["_none_"]
    lines += [""]
    return "\n".join(lines)
