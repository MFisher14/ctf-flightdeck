"""Draft one writeup per challenge from the saved evidence into a private staging folder.

    rep = draft.run(profile, workdir, staging)      # DraftReport(written, kept, scripts)

Staging layout (the shape of the 2026 Pink/Spooky staging):

    <staging>/<id>-<slug>/README.md     the draft (templates/writeup/challenge.md.tmpl)
    <staging>/<id>-<slug>/solve/...     solver scripts saved at the top of the challenge folder
    <staging>/STATUS.md                 every challenge: result, wrong count, flag recorded, draft state
    <staging>/writeup-state.json        hashes of what the pipeline wrote (private)

Re-running refreshes drafts from new evidence, but a README or script edited since the pipeline wrote
it is kept (reported as kept) unless force=True. When the event redacts flags, the draft never holds a
flag value: the Flag section says where the value is, and the solve log and copied scripts are
redacted with the known values and the event format.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .. import event as _event
from . import common, evidence, passes as _passes, policy as _policy, scan as _scan

STATUS_NAME = "STATUS.md"


@dataclass
class DraftReport:
    staging: Path
    written: list[str] = field(default_factory=list)
    kept: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    challenges: int = 0


def _quote(text: str) -> str:
    text = common.neutralize(text.strip())
    if not text:
        return "_No description saved._"
    return "\n".join(f"> {line}" if line.strip() else ">" for line in text.splitlines())


def _flag_text(ev: evidence.ChallengeEvidence, pol: _policy.Policy) -> str:
    if not ev.flag:
        return "No flag recorded."
    if pol.redact:
        why = ("this event's rules forbid sharing flags" if pol.sharing_forbidden
               else "the profile redacts flags (writeups.redact_flags)")
        return f"Flag redacted: {why}. The confirmed value is in the workspace `flag.txt`."
    return f"`{ev.flag}`"


def _engines(ev: evidence.ChallengeEvidence) -> str:
    runs = ev.engine_runs()
    if not runs:
        return "_No engine runs on record._"
    lines = []
    for r in runs:
        status = r.get("status") or f"exit {r.get('exit_code', '?')}"
        secs = r.get("seconds")
        took = f", {float(secs):.1f} s" if isinstance(secs, (int, float)) else ""
        lines.append(f"- `{common.cell(r.get('engine', '?'))}` ({common.cell(r.get('via', '?'))}): "
                     f"{common.cell(status)}{took}")
    return "Engine runs on record:\n\n" + "\n".join(lines)


def _dead_ends(ev: evidence.ChallengeEvidence) -> str:
    lines = []
    if ev.wrong:
        lines.append(f"- {ev.wrong} wrong submission(s) on record (values not shown).")
    empty = sorted({str(r.get("engine")) for r in ev.engine_runs() if r.get("status") in ("none", "blocked")})
    if empty:
        lines.append("- Engines that found nothing or could not run: " + ", ".join(f"`{e}`" for e in empty) + ".")
    return "\n".join(lines) or "_Nothing on record._"


def _files(ev: evidence.ChallengeEvidence) -> str:
    if not ev.files:
        return "_No handout files saved._"
    return "\n".join(f"- `{common.cell(n)}` ({size} bytes)" for n, size in ev.files)


def _reproduce(ev: evidence.ChallengeEvidence) -> str:
    if not ev.scripts:
        return "_No solver script saved in the workspace._"
    return "Solver scripts (copied from the workspace):\n\n" + "\n".join(f"- `solve/{p.name}`" for p in ev.scripts)


def render_challenge(ev: evidence.ChallengeEvidence, profile: _event.EventProfile,
                     scanner: _scan.Scanner) -> str:
    pol = scanner.policy
    notes = ev.notes.strip()
    if ev.writeup_md.strip():
        notes = (notes + "\n\n" if notes else "") + "### writeup.md (kept in the workspace)\n\n" + ev.writeup_md.strip()
    if notes and pol.redact:
        notes, _ = scanner.redact(notes)
    values = {
        "name": common.neutralize(ev.name),
        "event_name": profile.name,
        "category": common.neutralize(ev.category),
        "points": "unknown" if ev.points is None else f"{ev.points:g}",
        "description": _quote(ev.description),
        "status": ev.status_line,
        "flag": _flag_text(ev, pol),
        "files": _files(ev),
        "engines": _engines(ev),
        "dead_ends": _dead_ends(ev),
        "reproduce": _reproduce(ev),
        "notes": common.neutralize(notes) if notes else "_No solve log saved._",
    }
    return common.render(common.load_template("challenge.md.tmpl"), values)


def _status_md(profile: _event.EventProfile, evs: list[evidence.ChallengeEvidence], staging: Path) -> str:
    rows = ["| id | challenge | category | points | result | wrong | flag recorded | writeup |",
            "|---|---|---|---:|---|---:|---|---|"]
    for ev in evs:
        readme = staging / ev.folder / "README.md"
        if readme.exists():
            text = readme.read_text(encoding="utf-8", errors="replace")
            todo = len(_scan.TODO_RX.findall(text))
            # B-097: drafted prose that has not had its review pass is not complete.
            unrev = len(_passes.pass_findings(text, publish=True, models=profile.models))
            state = (f"draft ({todo} TODO)" if todo else
                     f"drafted, review pending ({unrev} block(s))" if unrev else "complete")
        else:
            state = "none"
        result = "solved" if ev.solved else ("attempted" if ev.status_line.startswith("Unsolved") else "not attempted")
        rows.append(f"| {common.cell(ev.cid)} | {common.cell(ev.name)} | {common.cell(ev.category)} | "
                    f"{'-' if ev.points is None else f'{ev.points:g}'} | {result} | {ev.wrong} | "
                    f"{'yes' if ev.flag else 'no'} | {state} |")
    solved = sum(1 for e in evs if e.solved)
    return (f"# {profile.name}: writeup status (private: never published)\n\n"
            f"{len(evs)} challenge(s), {solved} solved.\n\n" + "\n".join(rows) + "\n")


def run(profile: _event.EventProfile, workdir: Path, staging: Path, *, only: list[str] | None = None,
        force: bool = False) -> DraftReport:
    staging = common.guard_dir(staging, "staging folder")
    workdir = Path(workdir)
    records = evidence.read_records(workdir) if workdir.is_dir() else []
    evs = evidence.collect(workdir, records)
    if only:
        want = {str(x) for x in only}
        have = {e.cid for e in evs}
        unknown = sorted(want - have)
        if unknown:
            raise common.WriteupError(f"no challenge folder for id(s) {', '.join(unknown)} under {workdir}")
        chosen = [e for e in evs if e.cid in want]
    else:
        chosen = evs
    scanner = _scan.Scanner(profile, known=evidence.known_values(evs, records),
                            known_hashes=evidence.known_hashes(records))
    staging.mkdir(parents=True, exist_ok=True)
    state = common.State(staging, profile.slug)
    rep = DraftReport(staging=staging, challenges=len(chosen))
    for ev in chosen:
        folder = staging / ev.folder
        rel = f"{ev.folder}/README.md"
        text = render_challenge(ev, profile, scanner)
        target = folder / "README.md"
        if not state.may_write(target, rel, force):
            rep.kept.append(rel)
        else:
            folder.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
            state.record(rel, text)
            rep.written.append(rel)
        for src in ev.scripts:
            srel = f"{ev.folder}/solve/{src.name}"
            body = src.read_text(encoding="utf-8", errors="replace")
            if scanner.policy.redact:
                body, _ = scanner.redact(body)
            dst = folder / "solve" / src.name
            if not state.may_write(dst, srel, force):
                rep.kept.append(srel)
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(body, encoding="utf-8")
            state.record(srel, body)
            rep.scripts.append(srel)
    (staging / STATUS_NAME).write_text(_status_md(profile, evs, staging), encoding="utf-8")
    state.save()
    return rep
