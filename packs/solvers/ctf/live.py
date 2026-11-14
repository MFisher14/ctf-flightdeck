"""The no-model live status surface: one snapshot of the build, the gates, the running jobs and agents,
armed-versus-HEAD, the board and solves, percent through the plan and ETAs (B-198).

    python -m ctf live [show] [--json]          the compact status, from files and process state only
    python -m ctf live page --out FILE          the same as a self-refreshing HTML page
    python -m ctf live push [--url URL]         send it to the phone (ntfy-style POST), only when it changed
    python -m ctf live loop --every S [--page FILE] [--push]   regenerate and push on change, no model
    python -m ctf live smoke URL [--local FILE] the deployed page answers, is fresh, and is the one we built
    python -m ctf live job --name N -- CMD ...  run CMD as a recorded job (so "is it running?" has an answer)
    python -m ctf live arm [--note TEXT]        record HEAD as the commit armed for the event
    python -m ctf live forget --died            remove the records of runs that died

    from ctf import live
    snap = live.collect(live.default_sources())
    print(live.render_text(snap))

Why. The human polled agents for status and ETA again and again (each answer a full-context model
turn), the board was re-pulled on nearly every check-in, an agent said it was building with nothing
launched, and a hosted dashboard broke in production after local checks passed. Every field here is
read from a file or from process state: nothing asks a model, and nothing contacts the platform.

Sources (all read-only; a missing source is shown with the reason, never as zero):
  build     git: branch, HEAD, its age, uncommitted tracked files
  plan      BUILD-PLAN.md items (`- `B-xxx` [S|M|L|XL/...`) against docs/build-log/<id>.md (a log means
            the item was processed; its `Status:` word is counted). Percent by items and by effort
            (S 1, M 2, L 4, XL 8). Rate: effort units logged in the last 6 h (the add time of each log
            in git), else since the first log. ETA: remaining effort / rate.
  gates     ctf.progress files under <gate state>/progress (`ctf gate run` writes them): running,
            died or finished, done/total, red files, ETA
  jobs      ctf.progress files under <status state>/progress (`ctf live job` writes them)
  workers   git worktrees (name, branch, last commit age), item/* branches not merged into HEAD (the
            merge queue backlog), and the count of running `claude` and `codex` processes (ps, names only)
  event     the event workdir: the watch stream (watcher pid, board count, team solves, poll errors,
            ctf.watch), the ledger (accepted submits, agent launches with no exit and whether their pid
            lives, spend), dispatch claims and their intake states
  armed     <workdir>/status/armed.json (`ctf live arm`): the armed commit against HEAD

The snapshot, the text, the page and the push hold no path, no command line, no flag and no challenge
text: counts, states, names of jobs and branches. Error and note strings (a missing profile, a corrupt
ledger line, a checkout with no .git) often name a file, so `collect` scrubs every string of the
snapshot (`scrub`): the checkout, the workdir and the state folders become `<repo>`, `<workdir>`,
`<gate state>` and `<status state>`, and any other absolute path (one under the home folder included)
keeps only its last part (`<path>/event.toml`). The page carries two meta tags, `ctf-live-digest`
(sha256 of the headline state) and `ctf-live-generated` (epoch), which `smoke` checks on the deployed copy.

Push: an HTTP POST of the short text to $CTF_STATUS_PUSH_URL (or --url), ntfy-style (`Title`,
`Priority` 4 with alerts else 3, `Tags`). The URL is never printed. Sent only when the push key (states,
results, counts of solves and items, alerts; not progress counts or ages) changed since the last
successful push, and not sooner than --min-interval unless the alerts changed. A failed send is an
error and does not update the push state. The push and smoke targets may not be the event platform or
a host in the event's live_service_scope; with no event resolved (--no-event, or none selected) the
target is checked against every event profile under events/, and a profile that does not load stops
the push or smoke with its name.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import html
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import env
from . import progress as _progress

EFFORT_UNITS = {"S": 1, "M": 2, "L": 4, "XL": 8}
PLAN_WINDOW_H = 6.0
STATUS_DIR = "status"
ARMED = "armed.json"
PUSH_STATE = "push.json"
PUSH_ENV = "CTF_STATUS_PUSH_URL"
PROC_NAMES = ("claude", "codex")
META_DIGEST = "ctf-live-digest"
META_GENERATED = "ctf-live-generated"
SNAPSHOT_VERSION = 1

_PLAN_RE = re.compile(r"^- `(B-\d+)` \[(S|M|L|XL)/", re.M)
_STATUS_RE = re.compile(r"Status:\s*\**\s*(built|partial|blocked|deferred)\b", re.I)
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_META_RE = re.compile(r'<meta name="(ctf-live-[a-z]+)" content="([^"]*)">')
# an absolute path: a "/" that does not follow a word character, ".", "~", "/" or "<" (so not "a/b",
# "~/x" or "</b>"), nor a scrub label ("<repo>/x" stays, so scrubbing twice changes nothing), and is not
# the "//" of a URL scheme ("https://h/x"; "file:///x" is still a path), up to whitespace, a quote, a
# bracket, ",", ";" or ":". "x:/abs", "->/abs" and "-/abs" are paths.
_ABS_PATH = r"(?<![\w.~/<]){labels}(?!(?<=:)//(?!/))/[^\s'\"()\[\],;:]+"
PATH_LABEL = "<path>"


class LiveError(RuntimeError):
    """A named reason a live command cannot do what was asked (exit 2)."""


class PushError(RuntimeError):
    """The push target did not take the message (exit 1)."""


# ------------------------------------------------------------------------------------------- sources

def make_git(repo: Path) -> Callable[..., str | None]:
    """git -C repo ARGS -> stdout without the trailing newline, or None when git fails."""
    def git(*args: str) -> str | None:
        try:
            cp = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            return None
        return cp.stdout.rstrip("\n") if cp.returncode == 0 else None
    return git


def ps_names() -> str | None:
    """The executable name of every process (ps -axo comm=), or None when ps cannot run."""
    try:
        cp = subprocess.run(["ps", "-axo", "comm="], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return cp.stdout if cp.returncode == 0 else None


@dataclass
class Sources:
    repo: Path
    git: Callable[..., str | None]
    gate_progress: Path | None = None
    job_progress: Path | None = None
    profile: Any = None                 # ctf.event.EventProfile
    workdir: Path | None = None
    ps: Callable[[], str | None] = ps_names
    alive: Callable[[object], bool] = _progress.pid_alive
    now: float = field(default_factory=time.time)
    notes: dict = field(default_factory=dict)      # section -> why it could not be read


def default_sources(*, event_slug: str | None = None, no_event: bool = False) -> Sources:
    """Sources for this checkout and the current event ($CTF_EVENT, or --event). Each source that does
    not resolve is kept as a note naming why."""
    from . import paths
    repo = paths.repo_root()
    src = Sources(repo=repo, git=make_git(repo))
    try:
        src.gate_progress = paths.gate_state(repo) / _progress.PROGRESS_DIR
    except FileNotFoundError as e:
        src.notes["gates"] = str(e)
    try:
        src.job_progress = paths.status_state(repo) / _progress.PROGRESS_DIR
    except FileNotFoundError as e:
        src.notes["jobs"] = str(e)
    if no_event:
        src.notes["event"] = "not read (--no-event)"
        return src
    from . import event as _event
    try:
        src.profile = _event.load(event_slug) if event_slug else _event.current()
        src.workdir = paths.workdir(src.profile.slug)
    except _event.EventError as e:
        src.notes["event"] = f"no event: {e}"
    return src


# --------------------------------------------------------------------------------------------- build

def build_section(src: Sources) -> dict:
    git = src.git
    head = git("rev-parse", "HEAD")
    if not head:
        return {"error": "not a git checkout (git rev-parse HEAD failed)"}
    ct = git("log", "-1", "--format=%ct")
    porcelain = git("status", "--porcelain", "--untracked-files=no")
    return {"branch": git("rev-parse", "--abbrev-ref", "HEAD"), "head": head,
            "head_age_s": (src.now - int(ct)) if ct and ct.isdigit() else None,
            "dirty": len([ln for ln in porcelain.splitlines() if ln.strip()]) if porcelain is not None else None}


# ---------------------------------------------------------------------------------------------- plan

def plan_items(text: str) -> dict[str, str]:
    """{item id: effort} for every `- `B-xxx` [E/...` line, first occurrence wins."""
    out: dict[str, str] = {}
    for m in _PLAN_RE.finditer(text):
        out.setdefault(m.group(1), m.group(2))
    return out


def log_status(path: Path) -> str:
    """The first `Status:` word of a build log (built, partial, blocked, deferred), else `logged`."""
    m = _STATUS_RE.search(path.read_text(encoding="utf-8", errors="replace"))
    return m.group(1).lower() if m else "logged"


def log_add_times(git: Callable[..., str | None]) -> dict[str, float]:
    """{log stem: epoch of the commit that first added docs/build-log/<stem>.md}."""
    out = git("log", "--diff-filter=A", "--format=@%ct", "--name-only", "--", "docs/build-log")
    times: dict[str, float] = {}
    cur = None
    for line in (out or "").splitlines():
        line = line.strip()
        if line.startswith("@") and line[1:].isdigit():
            cur = float(line[1:])
        elif line.endswith(".md") and cur is not None:
            stem = Path(line).stem
            times[stem] = min(times.get(stem, cur), cur)
    return times


def plan_section(src: Sources, *, window_h: float = PLAN_WINDOW_H) -> dict:
    pf = src.repo / "BUILD-PLAN.md"
    if not pf.is_file():
        return {"error": "no BUILD-PLAN.md in this checkout"}
    items = plan_items(pf.read_text(encoding="utf-8"))
    if not items:
        return {"error": "BUILD-PLAN.md lists no `- `B-xxx` [effort/...` items"}
    logdir = src.repo / "docs" / "build-log"
    logs = {p.stem: p for p in logdir.glob("*.md")} if logdir.is_dir() else {}
    added = log_add_times(src.git)
    done: dict[str, tuple[str, float | None]] = {}
    for iid in items:
        if iid in logs:
            done[iid] = (log_status(logs[iid]), added.get(iid))
            continue
        parts = sorted(k for k in logs if re.fullmatch(re.escape(iid) + r"[a-z]", k))
        if parts:                       # a unit split into parts (B-001a..d): the plan does not list the
                                        # parts, so the unit counts as done once any part is logged
            sts = {log_status(logs[k]) for k in parts}
            ts = [added.get(k) for k in parts]
            done[iid] = (sts.pop() if len(sts) == 1 else "partial",
                         max(ts) if all(t is not None for t in ts) else None)
    units = {i: EFFORT_UNITS[e] for i, e in items.items()}
    total_u = sum(units.values())
    done_u = sum(units[i] for i in done)
    dated = [(ts, units[i]) for i, (_, ts) in done.items() if ts is not None]
    recent = [(ts, u) for ts, u in dated if ts >= src.now - window_h * 3600]
    rate_u, basis = None, "no dated build logs yet"
    if len(recent) >= 2:
        rate_u, basis = sum(u for _, u in recent) / window_h, f"last {window_h:g} h"
    elif len(dated) >= 2:
        span = src.now - min(ts for ts, _ in dated)
        if span > 0:
            rate_u, basis = sum(u for _, u in dated) / (span / 3600), "since the first log"
    remaining = total_u - done_u
    eta = (remaining / rate_u * 3600) if rate_u else None
    return {"items": len(items), "done": len(done), "by_status": dict(Counter(s for s, _ in done.values())),
            "pct": round(100.0 * len(done) / len(items), 1), "effort_pct": round(100.0 * done_u / total_u, 1),
            "rate_units_per_h": round(rate_u, 2) if rate_u else None, "basis": basis,
            "eta_s": round(eta) if eta is not None else (0 if remaining == 0 else None),
            "undated": sum(1 for _, ts in done.values() if ts is None)}


# ---------------------------------------------------------------------------------- progress / jobs

_RUN_FIELDS = ("kind", "label", "state", "total", "done", "ran", "warm", "bad", "bad_items", "jobs", "started",
               "updated", "finished", "result", "eta", "head", "pid", "file", "error")


def runs_section(folder: Path | None, src: Sources) -> list[dict]:
    if folder is None:
        return []
    return [{k: r.get(k) for k in _RUN_FIELDS} for r in _progress.read(folder, alive=src.alive)]


# ------------------------------------------------------------------------------------------- workers

def workers_section(src: Sources) -> dict:
    git = src.git
    out: dict[str, Any] = {}
    wt = git("worktree", "list", "--porcelain")
    if wt is None:
        out["worktrees_error"] = "git worktree list failed"
        trees = []
    else:
        trees, cur = [], {}
        for line in wt.splitlines() + [""]:
            if not line.strip():
                if cur:
                    trees.append(cur)
                cur = {}
            elif line.startswith("worktree "):
                cur["name"] = Path(line[len("worktree "):]).name
            elif line.startswith("HEAD "):
                cur["head"] = line[5:].strip()
            elif line.startswith("branch "):
                cur["branch"] = line[len("branch "):].strip().removeprefix("refs/heads/")
            elif line.strip() == "detached":
                cur["branch"] = "(detached)"
        heads = [t["head"] for t in trees if t.get("head")]
        ages: dict[str, float] = {}
        if heads:
            for line in (git("show", "-s", "--format=%H %ct", *heads) or "").splitlines():
                h, _, ct = line.partition(" ")
                if ct.strip().isdigit():
                    ages[h] = src.now - int(ct)
        for t in trees:
            t["head_age_s"] = ages.get(t.get("head", ""))
    out["worktrees"] = trees
    waiting = git("branch", "--list", "item/*", "--no-merged", "HEAD", "--format=%(refname:short)")
    out["waiting_merge"] = [b for b in (waiting or "").splitlines() if b.strip()] if waiting is not None else None
    names = src.ps()
    if names is None:
        out["procs"] = None
        out["procs_error"] = "ps could not run"
    else:
        c = Counter(Path(n.strip()).name for n in names.splitlines() if n.strip())
        out["procs"] = {n: c.get(n, 0) for n in PROC_NAMES}
    return out


# --------------------------------------------------------------------------------------------- event

def _phase(profile, now: float) -> str | None:
    try:
        from .buildplan import phase_of
        return phase_of(profile, _dt.datetime.fromtimestamp(now, _dt.timezone.utc))
    except Exception:  # noqa: BLE001 - a profile without usable dates has no phase; shown as unknown
        return None


def event_section(src: Sources) -> dict | None:
    prof, wd = src.profile, src.workdir
    if prof is None:
        return None
    out: dict[str, Any] = {"slug": prof.slug, "name": prof.name, "team": prof.platform.team,
                           "platform": prof.platform.kind, "phase": _phase(prof, src.now), "errors": []}
    if wd is None or not Path(wd).is_dir():
        out["errors"].append("the event workdir does not exist yet (nothing has run for this event)")
        return out
    from . import watch as _watch
    # the watch stream: the one poller's view of the board
    out["watcher_pid"] = _watch.poller_pid(wd)
    board = solved_team = None
    erroring = None
    points: dict[str, float] = {}
    last_ts = None
    try:
        evs = _watch.read_events(wd)
        board = _watch.board_ids(wd)
        solved_team = set()
        for ev in evs:
            kind, cid = ev.get("event"), str(ev.get("challenge_id"))
            last_ts = ev.get("ts", last_ts)
            if kind == "team_solved":
                solved_team.add(cid)
            elif kind == "challenge_new" and isinstance(ev.get("points"), (int, float)):
                points[cid] = float(ev["points"])
            elif kind == "points_changed" and isinstance(ev.get("new"), (int, float)):
                points[cid] = float(ev["new"])
            elif kind == "poll_error":
                erroring = erroring or {"since": ev.get("ts"), "status": ev.get("status")}
                erroring["status"] = ev.get("status")
            elif kind in ("poll_ok", "board_open"):
                erroring = None
    except _watch.WatchError as e:
        out["errors"].append(f"watch stream: {e}")
    out["board"] = len(board) if board is not None else None
    out["stream_age_s"] = (src.now - float(last_ts)) if isinstance(last_ts, (int, float)) else None
    out["poll_erroring"] = erroring
    # the ledger: accepted submits, agents, spend
    accepted: set[str] = set()
    agents_running = agents_died = 0
    spend = 0.0
    try:
        from . import ledger as _ledger
        from . import replay as _replay
        recs = list(_ledger.read(wd))
        accepted = {s.challenge_id for s in _replay.stage_events(recs) if s.stage == "accepted" and s.challenge_id}
        open_runs: dict[tuple, list[dict]] = {}
        for r in recs:
            key = (str(r.get("challenge_id")), r.get("harness"))
            if r.get("event") == "agent_launch":
                open_runs.setdefault(key, []).append(r)
            elif r.get("event") == "agent_exit" and open_runs.get(key):
                open_runs[key].pop()
            elif r.get("event") == "spend" and isinstance(r.get("usd"), (int, float)):
                spend += float(r["usd"])
        for runs in open_runs.values():
            for r in runs:
                if src.alive(r.get("pid")):
                    agents_running += 1
                else:
                    agents_died += 1
    except (ValueError, OSError) as e:
        out["errors"].append(f"ledger: {e}")
    solved = accepted | (solved_team or set())
    out.update({"solved": len(solved), "solved_by_us": len(accepted),
                "solved_team_only": len((solved_team or set()) - accepted),
                "points": sum(points.get(c, 0.0) for c in solved) if points else None,
                "agents_running": agents_running, "agents_died": agents_died, "spend_usd": round(spend, 2)})
    # dispatch claims
    cdir = Path(wd) / "dispatch" / "claims"
    intake: Counter = Counter()
    unreadable = 0
    dispatcher_alive = False
    claims = sorted(cdir.glob("*.json")) if cdir.is_dir() else []
    for p in claims:
        try:
            c = json.loads(p.read_text(encoding="utf-8"))
            intake[str(c.get("intake"))] += 1
            dispatcher_alive = dispatcher_alive or src.alive(c.get("dispatcher_pid"))
        except (OSError, ValueError):
            unreadable += 1
    out.update({"claims": len(claims), "intake": dict(intake), "claims_unreadable": unreadable,
                "dispatcher_running": dispatcher_alive})
    return out


# --------------------------------------------------------------------------------------------- armed

def armed_path(workdir: Path) -> Path:
    return Path(workdir) / STATUS_DIR / ARMED


def arm(workdir: Path, git: Callable[..., str | None], *, note: str = "", now: float | None = None) -> dict:
    """Record HEAD as the commit armed for the event (what its long-running processes run)."""
    head = git("rev-parse", "HEAD")
    if not head:
        raise LiveError("cannot arm: this checkout is not a git checkout (git rev-parse HEAD failed)")
    porcelain = git("status", "--porcelain", "--untracked-files=no")
    rec = {"commit": head, "branch": git("rev-parse", "--abbrev-ref", "HEAD"), "ts": time.time() if now is None else now,
           "dirty": len(porcelain.splitlines()) if porcelain else 0, "note": note[:200]}
    p = armed_path(workdir)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f".{p.name}.tmp")
    tmp.write_text(json.dumps(rec, sort_keys=True), encoding="utf-8")
    os.replace(tmp, p)
    return rec


def armed_section(src: Sources, head: str | None) -> dict | None:
    if src.workdir is None:
        return None
    p = armed_path(src.workdir)
    if not p.exists():
        return None
    try:
        rec = json.loads(p.read_text(encoding="utf-8"))
        commit = str(rec["commit"])
    except (OSError, ValueError, KeyError, TypeError) as e:
        return {"state": "unreadable", "error": f"{p.name}: {type(e).__name__}: {e}"}
    out = {"commit": commit, "age_s": src.now - float(rec.get("ts") or src.now), "note": rec.get("note") or "",
           "dirty": rec.get("dirty") or 0}
    if head is None:
        out.update(state="unknown", detail="HEAD unknown")
    elif commit == head:
        out.update(state="at HEAD", ahead=0)
    else:
        n = src.git("rev-list", "--count", f"{commit}..HEAD")
        if n is None or not n.isdigit():
            out.update(state="unknown commit", detail="the armed commit is not in this checkout")
        elif src.git("merge-base", "--is-ancestor", commit, "HEAD") is not None:
            out.update(state="behind HEAD", ahead=int(n))
        else:
            out.update(state="diverged", ahead=int(n))
    return out


# ------------------------------------------------------------------------------------------ scrubbing

def scrub_roots(src: Sources) -> list[tuple[str, str]]:
    """(prefix, label) pairs, longest prefix first: each known folder in its given and resolved form."""
    known = [(src.repo, "<repo>"), (src.workdir, "<workdir>"),
             (src.gate_progress.parent if src.gate_progress else None, "<gate state>"),
             (src.job_progress.parent if src.job_progress else None, "<status state>")]
    out: dict[str, str] = {}
    for p, label in known:
        if p is None:
            continue
        for form in (str(Path(p)), str(Path(p).resolve())):
            if len(form) > 1:
                out.setdefault(form, label)
    return sorted(out.items(), key=lambda kv: len(kv[0]), reverse=True)


def scrub(text: str, roots: list[tuple[str, str]]) -> str:
    """`text` with no absolute path: a known folder becomes its label, any other path its last part."""
    # one pass, so a label just written ("<repo>/x") is never read again as text; a known folder (longest
    # first, whole folder names only: /home/al is not a prefix of /home/alex) wins over a generic path
    labels = [label for _prefix, label in roots]
    known = "|".join(f"(?P<r{i}>{re.escape(prefix)})(?![\\w.-])" for i, (prefix, _l) in enumerate(roots))
    after_label = "".join(f"(?<!{re.escape(lb)})" for lb in sorted({*labels, PATH_LABEL}))
    pat = re.compile((known + "|" if known else "") + _ABS_PATH.format(labels=after_label))

    def one(m: re.Match) -> str:
        for i, label in enumerate(labels):
            if m.group(f"r{i}") is not None:
                return label
        return PATH_LABEL + "/" + (Path(m.group(0)).name or "?")
    return pat.sub(one, text)


def _scrub_tree(obj: Any, roots: list[tuple[str, str]]) -> Any:
    if isinstance(obj, str):
        return scrub(obj, roots)
    if isinstance(obj, dict):
        return {(scrub(k, roots) if isinstance(k, str) else k): _scrub_tree(v, roots) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_scrub_tree(v, roots) for v in obj]
    return obj


# ------------------------------------------------------------------------------------------ snapshot

def _short(h: str | None) -> str:
    return (h or "?")[:7]


def alerts_of(snap: dict) -> list[str]:
    out = []
    head = (snap.get("build") or {}).get("head")
    newest: dict[tuple, dict] = {}
    for r in snap["gates"] + snap["jobs"]:
        if r.get("state") == _progress.UNREADABLE:
            out.append(f"unreadable progress file {r.get('file')}")
            continue
        what = f"{r['kind']} {r.get('label') or ''}".strip()
        if r["state"] == _progress.DIED:
            out.append(f"{what} died at {r.get('done')}/{r['total']}" if r.get("total") is not None
                       else f"{what} died before it finished")
        key = (r["kind"], r.get("label"))
        if key not in newest:
            newest[key] = r
    for (kind, label), r in newest.items():
        if r["state"] != _progress.FINISHED:
            continue
        if kind == "gate" and r.get("result") != "pass":
            out.append(f"last gate {label} {r.get('result')}: {r.get('bad')} red file(s)")
        elif kind == "job" and r.get("result") != "ok":
            out.append(f"job {label} finished {r.get('result')}")
    ev = snap.get("event")
    if ev:
        live = ev.get("phase") == "in-event"
        if live and ev.get("platform") != "manual" and ev.get("watcher_pid") is None and "board" in ev:
            out.append("event is live and no watcher is running (ctf watch run)")
        if ev.get("poll_erroring"):
            out.append(f"board polls failing (status {ev['poll_erroring'].get('status')})")
        if ev.get("agents_died"):
            out.append(f"{ev['agents_died']} agent(s) died without an exit record")
        if ev.get("claims_unreadable"):
            out.append(f"{ev['claims_unreadable']} unreadable claim file(s)")
        for e in ev.get("errors") or []:
            if not e.startswith("the event workdir does not exist"):
                out.append(e)
    arm_ = snap.get("armed")
    if arm_ and arm_.get("state") in ("behind HEAD", "diverged"):
        out.append(f"armed {_short(arm_.get('commit'))} is {arm_['state']} ({arm_.get('ahead')} commit(s) "
                   f"since); re-arm or restart")
    elif arm_ and arm_.get("state") in ("unknown commit", "unreadable"):
        out.append(f"armed: {arm_['state']}")
    for r in snap["gates"] + snap["jobs"]:
        if r.get("state") == _progress.RUNNING and head and r.get("head") and r["head"] != head:
            out.append(f"{r['kind']} {r.get('label') or ''} runs {_short(r['head'])}, HEAD is now {_short(head)}")
    return out


def headline(snap: dict) -> dict:
    """The state the page digest covers: no ages, no ETAs, no timestamps."""
    ev = snap.get("event") or {}
    return {"build": {k: (snap.get("build") or {}).get(k) for k in ("head", "dirty", "branch")},
            "plan": (snap.get("plan") or {}).get("done"),
            "runs": [[r.get("kind"), r.get("label"), r.get("state"), r.get("done"), r.get("total"), r.get("bad"),
                      r.get("result")] for r in snap["gates"] + snap["jobs"]],
            "workers": [len(snap["workers"].get("worktrees") or []), len(snap["workers"].get("waiting_merge") or [])],
            "event": {k: ev.get(k) for k in ("slug", "board", "solved", "claims", "agents_running", "agents_died",
                                              "watcher_pid")},
            "armed": (snap.get("armed") or {}).get("state"), "alerts": snap["alerts"]}


def push_key(snap: dict) -> str:
    """What a push is debounced on: states and results, not progress counts (no push per test file)."""
    h = headline(snap)
    runs = [[k, lab, st, res, bool(bad)] for k, lab, st, _done, _total, bad, res in h["runs"]]
    newest: dict[tuple, list] = {}
    for r in runs:
        if r[2] == _progress.FINISHED:
            newest.setdefault((r[0], r[1]), r)
    h["runs"] = [r for r in runs if r[2] != _progress.FINISHED] + list(newest.values())
    h["build"].pop("dirty", None)
    return hashlib.sha256(json.dumps(h, sort_keys=True).encode()).hexdigest()


def collect(src: Sources) -> dict:
    snap: dict[str, Any] = {"version": SNAPSHOT_VERSION, "generated": src.now, "notes": dict(src.notes)}
    snap["build"] = build_section(src)
    snap["plan"] = plan_section(src)
    snap["gates"] = runs_section(src.gate_progress, src)
    snap["jobs"] = runs_section(src.job_progress, src)
    snap["workers"] = workers_section(src)
    snap["event"] = event_section(src)
    snap["armed"] = armed_section(src, snap["build"].get("head"))
    etas = [{"what": f"{r['kind']} {r.get('label') or ''}".strip(), "eta_s": r["eta"]["eta_s"],
             "basis": r["eta"]["basis"]} for r in snap["gates"] + snap["jobs"] if r.get("state") == _progress.RUNNING]
    if snap["plan"].get("eta_s") is not None:
        etas.append({"what": "plan", "eta_s": snap["plan"]["eta_s"], "basis": snap["plan"]["basis"]})
    snap["etas"] = etas
    snap["alerts"] = alerts_of(snap)
    snap = _scrub_tree(snap, scrub_roots(src))      # nothing path-like reaches the text, page or push
    snap["digest"] = hashlib.sha256(json.dumps(headline(snap), sort_keys=True).encode()).hexdigest()
    return snap


# ----------------------------------------------------------------------------------------- rendering

def dur(s: float | None) -> str:
    if s is None:
        return "?"
    s = max(0.0, float(s))
    if s < 90:
        return f"{s:.0f}s"
    if s < 90 * 60:
        return f"{s / 60:.0f}m"
    if s < 48 * 3600:
        return f"{s / 3600:.1f}h"
    return f"{s / 86400:.1f}d"


def _run_line(r: dict, now: float) -> str:
    if r.get("state") == _progress.UNREADABLE:
        return f"unreadable {r.get('file')}: {r.get('error')}"
    what = f"{r['kind']} {r.get('label') or ''}".strip()
    counted = r.get("total") is not None
    count = f" {r.get('done')}/{r['total']}" if counted else ""
    red = f", {r['bad']} red" if r.get("bad") else ""
    if r["state"] == _progress.RUNNING:
        eta = r.get("eta") or {}
        tail = (f", ETA {dur(eta.get('eta_s'))} ({eta.get('basis')})" if eta.get("eta_s") is not None
                else f", ETA ? ({eta.get('basis')})" if counted else "")
        return f"{what} running{count}{red}, {dur(now - float(r['started']))} in{tail}"
    if r["state"] == _progress.DIED:
        at = f" at{count}" if counted else f" after {dur(float(r['updated']) - float(r['started']))}"
        return f"{what} DIED{at} (pid {r.get('pid')} gone, last update {dur(now - float(r['updated']))} ago)"
    return f"{what} {r.get('result')}{count}{red}, {dur(now - float(r['finished']))} ago"


def _shown_runs(runs: list[dict]) -> list[dict]:
    """Every running, died or unreadable run, and the newest finished run per kind and label."""
    seen, out = set(), []
    for r in runs:
        if r.get("state") != _progress.FINISHED:
            out.append(r)
        elif (r["kind"], r.get("label")) not in seen:
            seen.add((r["kind"], r.get("label")))
            out.append(r)
    return out


def text_lines(snap: dict) -> list[tuple[str, str]]:
    now = snap["generated"]
    rows: list[tuple[str, str]] = []
    b = snap["build"]
    if b.get("error"):
        rows.append(("build", b["error"]))
    else:
        dirty = f", {b['dirty']} uncommitted" if b.get("dirty") else ", clean" if b.get("dirty") == 0 else ""
        rows.append(("build", f"{b.get('branch')} @ {_short(b.get('head'))} ({dur(b.get('head_age_s'))} ago{dirty})"))
    p = snap["plan"]
    if p.get("error"):
        rows.append(("plan", p["error"]))
    else:
        st = ", ".join(f"{k} {v}" for k, v in sorted(p["by_status"].items()))
        rate = f"{p['rate_units_per_h']} effort/h ({p['basis']})" if p.get("rate_units_per_h") else p["basis"]
        rows.append(("plan", f"{p['done']}/{p['items']} items logged ({p['pct']}%; effort {p['effort_pct']}%)"
                             + (f" [{st}]" if st else "") + f"; {rate}; ETA {dur(p.get('eta_s'))}"))
    for name, key in (("gates", "gates"), ("jobs", "jobs")):
        runs = _shown_runs(snap[key])
        if runs:
            for r in runs:
                rows.append((name, _run_line(r, now)))
        elif snap["notes"].get(key):
            rows.append((name, snap["notes"][key]))
        else:
            rows.append((name, "none recorded"))
    w = snap["workers"]
    procs = w.get("procs")
    pr = ", ".join(f"{n} {c}" for n, c in procs.items()) + " processes" if procs is not None else w.get("procs_error")
    wm = w.get("waiting_merge")
    rows.append(("workers", f"{len(w.get('worktrees') or [])} worktrees; "
                            + (f"{len(wm)} item branch(es) not merged into HEAD" if wm is not None else "branches ?")
                            + f"; {pr}"))
    ev = snap.get("event")
    if ev is None:
        rows.append(("event", snap["notes"].get("event", "none")))
    else:
        head = f"{ev['slug']} ({ev.get('phase') or 'phase ?'})"
        if "board" not in ev:
            rows.append(("event", f"{head}: " + "; ".join(ev["errors"])))
        else:
            watcher = f"watcher pid {ev['watcher_pid']}" if ev.get("watcher_pid") else "no watcher"
            stream = f", stream {dur(ev['stream_age_s'])} old" if ev.get("stream_age_s") is not None else ""
            board = ev["board"] if ev["board"] is not None else "not open"
            pts = f", {ev['points']:.0f} pts" if ev.get("points") is not None else ""
            intake = ", ".join(f"{k} {v}" for k, v in sorted(ev["intake"].items()))
            rows.append(("event", f"{head}: {watcher}{stream}; board {board}; solved {ev['solved']} "
                                  f"(by us {ev['solved_by_us']}){pts}; claims {ev['claims']}"
                                  + (f" [{intake}]" if intake else "")
                                  + f"; agents running {ev['agents_running']}, died {ev['agents_died']}"
                                  + f"; spend ${ev['spend_usd']:.2f}"))
    a = snap.get("armed")
    if a:
        extra = f", {a['ahead']} commit(s) since" if a.get("ahead") else ""
        rows.append(("armed", f"{_short(a.get('commit'))} {a.get('state')}{extra} (armed {dur(a.get('age_s'))} ago)"
                     if a.get("state") != "unreadable" else a.get("error", "unreadable")))
    if snap["etas"]:
        rows.append(("ETA", "; ".join(f"{e['what']} {dur(e['eta_s'])}" for e in snap["etas"])))
    for al in snap["alerts"]:
        rows.append(("ALERT", al))
    return rows


def render_text(snap: dict) -> str:
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(snap["generated"]))
    out = [f"live {stamp}  digest {snap['digest'][:12]}"]
    out += [f"{k:<8} {v}" for k, v in text_lines(snap)]
    return "\n".join(out)


_CSS = """
:root{--bg:#f7f7f5;--fg:#1d1d1b;--muted:#6b6b66;--card:#fff;--line:#e2e2dc;--bad:#b42318;--badbg:#fdecea}
@media (prefers-color-scheme: dark){:root{--bg:#141413;--fg:#ecebe6;--muted:#9a9993;--card:#1f1f1d;
--line:#33332f;--bad:#ff8a80;--badbg:#3a1d1a}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 -apple-system,system-ui,sans-serif}
main{max-width:860px;margin:0 auto;padding:16px}
h1{font-size:20px;margin:0 0 4px}.meta{color:var(--muted);font-size:13px;margin-bottom:12px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px}
th,td{text-align:left;vertical-align:top;padding:8px 10px;border-bottom:1px solid var(--line)}
th{width:84px;color:var(--muted);font-weight:600}td{overflow-wrap:anywhere}
tr.alert th,tr.alert td{color:var(--bad);background:var(--badbg)}
"""


def render_html(snap: dict, *, title: str, refresh: int = 30) -> str:
    esc = html.escape
    stamp = time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(snap["generated"]))
    rows = "\n".join(f'<tr class="{"alert" if k == "ALERT" else ""}"><th>{esc(k)}</th><td>{esc(v)}</td></tr>'
                     for k, v in text_lines(snap))
    return (f'<!doctype html>\n<html lang="en"><head><meta charset="utf-8">\n'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f'<meta http-equiv="refresh" content="{int(refresh)}">\n'
            f'<meta name="{META_DIGEST}" content="{esc(snap["digest"])}">\n'
            f'<meta name="{META_GENERATED}" content="{snap["generated"]:.0f}">\n'
            f'<title>{esc(title)}</title><style>{_CSS}</style></head>\n'
            f'<body><main><h1>{esc(title)}</h1>\n'
            f'<div class="meta">generated {esc(stamp)} with no model; refreshes every {int(refresh)} s; '
            f'digest {esc(snap["digest"][:12])}</div>\n<table>\n{rows}\n</table></main></body></html>\n')


def page_title(snap: dict, override: str | None = None) -> str:
    """--title, else the event name and team (the team, not a player name), else the branch."""
    if override:
        return override
    ev = snap.get("event")
    if ev:
        return f"{ev['name']} - {ev['team']}" if ev.get("team") else ev["name"]
    return f"ctf-tools {snap['build'].get('branch') or ''}".strip()


def write_page(snap: dict, out: Path, *, title: str, refresh: int = 30) -> Path:
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(f".{out.name}.{os.getpid()}.tmp")
    tmp.write_text(render_html(snap, title=title, refresh=refresh), encoding="utf-8")
    os.replace(tmp, out)
    return out


# --------------------------------------------------------------------------------- endpoints (push / smoke)

def endpoint_profiles(profile=None) -> list:
    """The profiles a status endpoint is checked against: the event's, or with no event resolved every
    profile under events/ (a status URL must be no event's platform or challenge host). A profile that
    does not load is an error naming it, never skipped."""
    if profile is not None:
        return [profile]
    from . import event as _event
    out = []
    for slug in _event.available():
        try:
            out.append(_event.load(slug))
        except _event.EventError as e:
            raise LiveError(f"cannot check the status endpoint against event {slug!r}: its profile does not "
                            f"load ({e}); fix it or pass --event SLUG") from None
    return out


def check_endpoint(url: str, profile=None) -> str:
    """Refuse a status endpoint that is not http(s), is an event platform, or is a live challenge target
    (of `profile`, or of every event profile when it is None), before any connection. Returns the host
    (the only part of the URL that is ever printed)."""
    from . import scope
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise LiveError("the status endpoint must be an http(s) URL with a host")
    host, _port = scope.split_url(url)
    profiles = endpoint_profiles(profile)
    plat = {h for prof in profiles for h in prof.platform.all_hosts()}
    pu = env.get("CTF_PLATFORM_URL")
    if pu:
        plat.add(scope.split_url(pu if "://" in pu else "https://" + pu)[0])
    if host in plat:
        raise LiveError(f"refused: {host} is the event platform; status never goes to the platform")
    for prof in profiles:
        try:
            scope.check_url(url, profile=prof)
        except scope.OutOfScope:
            continue
        raise LiveError(f"refused: {host} is a live challenge target of event {prof.slug!r} "
                        f"(rules.live_service_scope)")
    return host


def push_url(arg: str | None) -> str:
    url = arg or env.get(PUSH_ENV)
    if not url:
        raise LiveError(f"no push target: set {PUSH_ENV} to an ntfy-style topic URL, or pass --url")
    return url


def _ascii(s: str) -> str:
    return s.encode("ascii", "replace").decode("ascii")


def push(snap: dict, url: str, *, state_dir: Path, title: str, force: bool = False, min_interval: float = 0.0,
         opener: Callable = urllib.request.urlopen, profile=None, now: float | None = None) -> str:
    """Send the status to the phone when it changed. Returns "sent", "unchanged" or "too soon"."""
    host = check_endpoint(url, profile)
    now = time.time() if now is None else now
    sp = Path(state_dir) / PUSH_STATE
    try:
        last = json.loads(sp.read_text(encoding="utf-8")) if sp.exists() else {}
    except (OSError, ValueError):
        last = {}                       # an unreadable push state means "never pushed": send
    key = push_key(snap)
    if not force and last.get("key") == key:
        return "unchanged"
    if not force and last and now - float(last.get("ts") or 0) < min_interval and last.get("alerts") == snap["alerts"]:
        return "too soon"
    body = "\n".join(f"{k}: {v}" for k, v in text_lines(snap) if k in ("ALERT", "ETA", "event", "gates", "jobs", "plan", "armed"))
    head = f"{len(snap['alerts'])} alert(s)" if snap["alerts"] else "ok"
    req = urllib.request.Request(url, data=body.encode("utf-8"), method="POST", headers={
        "Title": _ascii(f"{title}: {head}")[:200], "Priority": "4" if snap["alerts"] else "3",
        "Tags": "warning" if snap["alerts"] else "white_check_mark", "Content-Type": "text/plain; charset=utf-8"})
    try:
        with opener(req, timeout=15) as resp:
            code = getattr(resp, "status", None) or resp.getcode()
    except urllib.error.HTTPError as e:
        raise PushError(f"push to {host} failed: HTTP {e.code}") from None
    except (urllib.error.URLError, OSError) as e:
        raise PushError(f"push to {host} failed: {getattr(e, 'reason', e)}") from None
    if not 200 <= int(code) < 300:
        raise PushError(f"push to {host} failed: HTTP {code}")
    sp.parent.mkdir(parents=True, exist_ok=True)
    sp.write_text(json.dumps({"key": key, "alerts": snap["alerts"], "ts": now}), encoding="utf-8")
    return "sent"


def page_meta(text: str) -> dict[str, str]:
    return {k: v for k, v in _META_RE.findall(text)}


@dataclass
class Check:
    name: str
    ok: bool
    detail: str


def smoke(url: str, *, max_age: float = 600.0, expect_digest: str | None = None, profile=None,
          opener: Callable = urllib.request.urlopen, now: float | None = None) -> list[Check]:
    """Fetch the deployed page and check it: HTTP 200, HTML, our meta tags, fresh, and (given a digest)
    the very page built here. Returns every check; the run passes when all are ok."""
    host = check_endpoint(url, profile)
    checks: list[Check] = []
    req = urllib.request.Request(url, headers={"Cache-Control": "no-cache", "User-Agent": "ctf-live-smoke"})
    try:
        with opener(req, timeout=15) as resp:
            code = getattr(resp, "status", None) or resp.getcode()
            ctype = resp.headers.get("Content-Type", "")
            body = resp.read(2_000_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return [Check("http", False, f"HTTP {e.code} from {host}")]
    except (urllib.error.URLError, OSError) as e:
        return [Check("http", False, f"no answer from {host}: {getattr(e, 'reason', e)}")]
    checks.append(Check("http", int(code) == 200, f"HTTP {code}"))
    checks.append(Check("html", "text/html" in ctype.lower(), f"Content-Type {ctype or '(none)'}"))
    meta = page_meta(body)
    dg, gen = meta.get(META_DIGEST), meta.get(META_GENERATED)
    checks.append(Check("marker", bool(dg and gen),
                        "status meta tags present" if dg and gen else
                        f"no {META_DIGEST}/{META_GENERATED} meta tags: not a ctf live page (or an old deploy)"))
    if gen:
        try:
            age = (time.time() if now is None else now) - float(gen)
            checks.append(Check("fresh", age <= max_age, f"generated {dur(age)} ago (max {dur(max_age)})"))
        except ValueError:
            checks.append(Check("fresh", False, f"bad {META_GENERATED} value"))
    if expect_digest is not None:
        checks.append(Check("digest", dg == expect_digest,
                            f"deployed {(dg or '-')[:12]}, local {expect_digest[:12]}"))
    return checks


# --------------------------------------------------------------------------------------------- jobs

def check_name(name: str) -> str:
    if not _NAME_RE.match(name or ""):
        raise LiveError(f"bad job name {name!r} (letters, digits, . _ -, up to 64)")
    return name


def run_job(name: str, argv: list[str], *, folder: Path, repo: Path) -> int:
    """Run argv as a recorded job: the record says running while it runs, then ok / rc=N / interrupted.
    A record whose process is gone before it finished reads as died."""
    check_name(name)
    if not argv:
        raise LiveError("no command given (ctf live job --name N -- CMD ...)")
    prog = _progress.Progress(folder, "job", total=None, label=name, head=_progress.head_of(repo))
    try:
        proc = subprocess.Popen(argv)
    except OSError as e:
        prog.finish("not started")
        raise LiveError(f"cannot start {Path(argv[0]).name!r}: {type(e).__name__}: {e.strerror or e}") from None
    prog.set(child_pid=proc.pid)
    try:
        rc = proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        prog.finish("interrupted")
        return 130
    prog.finish("ok" if rc == 0 else f"rc={rc}")
    return rc


def forget_died(folders: list[Path], *, alive: Callable[[object], bool] = _progress.pid_alive) -> list[str]:
    """Remove the files of runs that died; returns their names."""
    gone = []
    for f in folders:
        for r in _progress.read(f, alive=alive):
            if r["state"] == _progress.DIED:
                (Path(f) / r["file"]).unlink(missing_ok=True)
                gone.append(r["file"])
    return gone
