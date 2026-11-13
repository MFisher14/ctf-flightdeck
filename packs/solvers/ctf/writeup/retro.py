"""An event or day retro generated from the ledger and the workspace, not re-derived by a model.

    text = retro.render(profile, workdir, since=..., until=..., now=...)
    retro.write(profile, workdir, staging, label, text, force=False)   # <staging>/retro/<label>.md

The tables are facts from the saved evidence (ledger records in the window, challenge folders, and
the main thread's cause and steer claims stated in the window with whether each held, B-259); the
analysis sections (recommendations, open questions) are TODO markers for a person or a drafting
model (B-097). No flag value appears: the timeline shows a whitelisted set of fields only.
"""
from __future__ import annotations

import datetime as _dt
from collections import Counter, defaultdict
from pathlib import Path

from .. import event as _event
from . import common, evidence

ACCEPTED = evidence.ACCEPTED
# Ledger fields the timeline may show. Anything else (flag, flag_sha256, provenance, note, path, ...)
# stays out: provenance and notes are free text that can carry a value.
DETAIL_FIELDS = ("engine", "via", "status", "exit_code", "seconds", "usd", "tok", "reason", "by", "cap_usd",
                 "judged", "guess", "confirmed")
STOP_EVENTS = ("stop", "budget_extend", "budget_resume", "budget_checkpoint")
TIMELINE_MAX = 500


def parse_when(text: str) -> _dt.datetime:
    """ISO-8601 with a UTC offset (or Z), or epoch seconds. A naive time is refused: a guessed zone
    would shift the window by hours."""
    t = text.strip()
    try:
        return _dt.datetime.fromtimestamp(float(t), tz=_dt.timezone.utc)
    except ValueError:
        pass
    try:
        when = _dt.datetime.fromisoformat(t.replace("Z", "+00:00"))
    except ValueError:
        raise common.WriteupError(f"{text!r} is not ISO-8601 or epoch seconds") from None
    if when.tzinfo is None:
        raise common.WriteupError(f"{text!r} has no UTC offset; write e.g. 2026-11-07T08:00:00Z")
    return when.astimezone(_dt.timezone.utc)


def day_window(day: str) -> tuple[_dt.datetime, _dt.datetime]:
    try:
        d = _dt.date.fromisoformat(day)
    except ValueError:
        raise common.WriteupError(f"--day {day!r} is not YYYY-MM-DD") from None
    start = _dt.datetime.combine(d, _dt.time(0), tzinfo=_dt.timezone.utc)
    return start, start + _dt.timedelta(days=1)


def _iso(ts: float | None) -> str:
    if ts is None:
        return "-"
    return _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def _in_window(rec: dict, since: _dt.datetime | None, until: _dt.datetime | None) -> bool:
    ts = rec.get("ts")
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        return False
    if since is not None and ts < since.timestamp():
        return False
    if until is not None and ts >= until.timestamp():
        return False
    return True


def window_label(since, until) -> str:
    if since is None and until is None:
        return "whole event"
    if since is not None and until is not None and until - since == _dt.timedelta(days=1) \
            and since.time() == _dt.time(0):
        return since.date().isoformat()
    return f"{since.isoformat() if since else 'start'} to {until.isoformat() if until else 'now'}"


def _detail(rec: dict) -> str:
    parts = []
    for k in DETAIL_FIELDS:
        if k in rec and rec[k] is not None and rec[k] != "":
            v = rec[k]
            if isinstance(v, float):
                v = f"{v:.4g}"
            parts.append(f"{k}={common.cell(v)}")
    return " ".join(parts) or "-"


def render(profile: _event.EventProfile, workdir: Path, *, since: _dt.datetime | None = None,
           until: _dt.datetime | None = None, now: _dt.datetime | None = None,
           timeline_max: int = TIMELINE_MAX) -> str:
    workdir = Path(workdir)
    if not workdir.is_dir():
        raise common.WriteupError(f"workdir {workdir} does not exist (set CTF_WORKDIR or pass --workdir)")
    now = now or _dt.datetime.now(_dt.timezone.utc)
    all_records = evidence.read_records(workdir)
    evs = evidence.collect(workdir, all_records)
    names = {e.cid: e.name for e in evs}
    recs = sorted((r for r in all_records if _in_window(r, since, until)), key=lambda r: r["ts"])

    by_cid: dict[str, list[dict]] = defaultdict(list)
    for r in recs:
        cid = r.get("challenge_id")
        if cid not in (None, ""):
            by_cid[str(cid)].append(r)

    submits = [r for r in recs if r.get("event") == "platform.submit"]
    accepted = {str(r.get("challenge_id")) for r in submits if r.get("status") in ACCEPTED}
    wrong = sum(1 for r in submits if r.get("status") == "incorrect")
    refused = sum(1 for r in submits if r.get("status") == "not_allowed")
    spends = [r for r in recs if r.get("event") == "spend"]
    usd = sum(float(r.get("usd") or 0) for r in spends)
    tok = sum(int(r.get("tok") or 0) for r in spends)
    runs = [r for r in recs if r.get("event") == "engine.run"]
    # B-097: doc-drafting calls (`ctf writeup assist | review`) are ledgered as writeup.assist, not
    # spend; they are totalled on their own line so the spend line keeps its meaning.
    docs = [r for r in recs if r.get("event") == "writeup.assist"]
    summary = "\n".join([
        f"- Challenge folders in the workspace: {len(evs)} ({sum(1 for e in evs if e.solved)} solved overall).",
        f"- Challenges with activity in this window: {len(by_cid)}.",
        f"- Accepted in this window: {len(accepted)}.",
        f"- Wrong submissions: {wrong}. Sends refused by the rules: {refused}.",
        f"- Engine runs: {len(runs)}.",
        f"- Spend: ${usd:.2f}, {tok:,} tokens.",
    ] + ([f"- Writeup drafting and review (writeup.assist): {len(docs)} call(s), "
          f"${sum(float(r.get('usd') or 0) for r in docs):.2f}, "
          f"{sum(int(r.get('tok') or 0) for r in docs):,} tokens."] if docs else []))

    rows = []
    for cid, rs in by_cid.items():
        first = rs[0]["ts"]
        acc = next((r["ts"] for r in rs if r.get("event") == "platform.submit" and r.get("status") in ACCEPTED), None)
        end = acc if acc is not None else rs[-1]["ts"]
        w = sum(1 for r in rs if r.get("event") == "platform.submit" and r.get("status") == "incorrect")
        sp = sum(float(r.get("usd") or 0) for r in rs if r.get("event") == "spend")
        rows.append((end - first, cid, first, acc, w, sp))
    rows.sort(key=lambda x: (-x[0], x[1]))
    time_table = "\n".join(
        ["| challenge | name | first record | accepted | minutes | wrong | spend |",
         "|---|---|---|---|---:|---:|---:|"]
        + [f"| {common.cell(cid)} | {common.cell(names.get(cid, '?'))} | {_iso(first)} | {_iso(acc)} | "
           f"{dur / 60:.1f} | {w} | ${sp:.2f} |" for dur, cid, first, acc, w, sp in rows]
    ) if rows else "_No per-challenge records in this window._"

    spend_by = Counter()
    tok_by = Counter()
    for r in spends:
        cid = str(r.get("challenge_id", "?"))
        spend_by[cid] += float(r.get("usd") or 0)
        tok_by[cid] += int(r.get("tok") or 0)
    spend_table = "\n".join(
        ["| challenge | name | usd | tokens |", "|---|---|---:|---:|"]
        + [f"| {common.cell(c)} | {common.cell(names.get(c, '?'))} | ${u:.2f} | {tok_by[c]:,} |"
           for c, u in sorted(spend_by.items(), key=lambda kv: (-kv[1], kv[0]))]
        + [f"| **total** | | **${usd:.2f}** | **{tok:,}** |"]
    ) if spends else "_No spend records in this window._"

    eng: dict[str, Counter] = defaultdict(Counter)
    eng_secs: Counter = Counter()
    for r in runs:
        e = str(r.get("engine", "?"))
        eng[e][str(r.get("status") or f"exit {r.get('exit_code', '?')}")] += 1
        eng_secs[e] += float(r.get("seconds") or 0)
    engine_table = "\n".join(
        ["| engine | runs | results | seconds |", "|---|---:|---|---:|"]
        + [f"| `{common.cell(e)}` | {sum(c.values())} | "
           f"{common.cell(', '.join(f'{k} {v}' for k, v in sorted(c.items())))} | {eng_secs[e]:.1f} |"
           for e, c in sorted(eng.items(), key=lambda kv: (-sum(kv[1].values()), kv[0]))]
    ) if runs else "_No engine runs in this window._"

    stop_rows = [r for r in recs if r.get("event") in STOP_EVENTS]
    stops = "\n".join(f"- {_iso(r['ts'])} `{r['event']}` challenge {common.cell(r.get('challenge_id', '?'))}: "
                      f"{_detail(r)}" for r in stop_rows) or "_None in this window._"

    open_evs = [e for e in evs if not e.solved]
    unsolved = "\n".join(f"- {common.cell(e.cid)} {common.cell(e.name)} ({common.cell(e.category)}): "
                         f"{e.status_line}" for e in open_evs) or "_Every challenge folder is solved._"

    shown = recs[:timeline_max]
    timeline = "\n".join(
        ["| time (UTC) | record | challenge | detail |", "|---|---|---|---|"]
        + [f"| {_iso(r['ts'])} | `{common.cell(r.get('event', '?'))}` | {common.cell(r.get('challenge_id', '-'))} | "
           f"{_detail(r)} |" for r in shown]
    ) if recs else "_No ledger records in this window._"
    if len(recs) > len(shown):
        timeline += f"\n\n_{len(recs) - len(shown)} later record(s) not shown (timeline limit {timeline_max})._"

    claims = claims_section(profile, workdir, since=since, until=until)

    values = {
        "claims": claims,
        "event_name": profile.name,
        "window": window_label(since, until),
        "generated": now.strftime("%Y-%m-%d %H:%M:%SZ"),
        "record_count": str(len(recs)),
        "challenge_count": str(len(evs)),
        "summary": summary,
        "time_table": time_table,
        "spend_table": spend_table,
        "engine_table": engine_table,
        "stops": stops,
        "unsolved": unsolved,
        "timeline": timeline,
    }
    return common.render(common.load_template("retro.md.tmpl"), values)


def _masked(profile: _event.EventProfile, text: str) -> str:
    """Claim text is the main thread's free text: a flag in the event format is masked (prefix and
    length only), as the scan previews one."""
    from .. import flagfmt
    from .scan import mask
    out = str(text)
    for hit in sorted(set(flagfmt.for_profile(profile).find_flags(out)), key=len, reverse=True):
        out = out.replace(hit, mask(hit))
    return out


def claims_section(profile: _event.EventProfile, workdir: Path, *, since: _dt.datetime | None = None,
                   until: _dt.datetime | None = None) -> str:
    """Every cause and steer claim the main thread recorded in the window (B-259, ctf.findings), with
    its artifacts, its final status and whether it held. A corrupt findings file is a WriteupError."""
    from .. import findings as _findings
    try:
        cs = _findings.claims(Path(workdir))
    except _findings.FindingsError as e:
        raise common.WriteupError(f"cannot list the claims: {e}") from None
    cs = [c for c in cs if _in_window({"ts": c.get("claimed_ts")}, since, until)]
    if not cs:
        return "_No cause or steer claims recorded in this window._"
    tally = Counter(_findings.held(c) for c in cs)
    head = (f"{len(cs)} claim(s): " + ", ".join(f"{n} {k}" for k, n in
                                                 sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))) + ".")
    rows = ["| claim | stated (UTC) | kind | challenge | claim | evidence | status | held | settled |",
            "|---|---|---|---|---|---|---|---|---|"]
    for c in cs:
        what = _masked(profile, c.get("text") or "")
        if c.get("to"):
            what = f"to {c['to']}: {what}"
        ev = "; ".join(_findings.artifact_label(a) for a in c.get("artifacts") or [])
        settled = "-"
        if c.get("status") != _findings.SUSPECTED:
            settled = f"{_iso(c.get('status_ts'))} by {c.get('status_by')}"
            if c.get("status_reason"):
                settled += f": {_masked(profile, c['status_reason'])}"
            refs = [a for h in c.get("history") or [] for a in h.get("artifacts") or []]
            if refs:
                settled += " (" + "; ".join(_findings.artifact_label(a) for a in refs) + ")"
        rows.append(f"| {common.cell(c.get('id'))} | {_iso(c.get('claimed_ts'))} | {common.cell(c.get('kind'))} | "
                    f"{common.cell(c.get('challenge_id') or '-')} | {common.cell(what)} | {common.cell(ev)} | "
                    f"{common.cell(c.get('status'))} | **{common.cell(_findings.held(c))}** | {common.cell(settled)} |")
    return head + "\n\n" + "\n".join(rows)


def write(profile: _event.EventProfile, staging: Path, label: str, text: str, *, force: bool = False) -> tuple[Path, bool]:
    """Write <staging>/retro/<label>.md. Returns (path, written); a retro edited since the pipeline
    wrote it is kept (written False) unless force."""
    staging = common.guard_dir(staging, "staging folder")
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in label).strip("-.") or "retro"
    rel = f"retro/{safe}.md"
    target = staging / rel
    state = common.State(staging, profile.slug)
    if not state.may_write(target, rel, force):
        return target, False
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    state.record(rel, text)
    state.save()
    return target, True
