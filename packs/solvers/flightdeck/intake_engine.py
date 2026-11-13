"""The whole no-model intake as one flightdeck L1 engine.

flightdeck runs this once per challenge, in a copy of the challenge folder (its last argument),
before the lane's first model call. It runs the pack's intake on that copy: recursive unpack and
flag sweep, every engine whose manifest has an [intake] adapter and whose routes or files match,
then the fastlane decoders; and reports one SolverResult in flightdeck's format (the two share
schema 1) to the file $FLIGHTDECK_L1_RESULT names, else as the last line of stdout.

The challenge is untrusted data: it is read, unpacked and decoded, never run. Nothing here talks
to a platform or the network (the adapter below has no network code, and intake's own engines run
under its network guard). Nothing is submitted: flightdeck decides what happens to a flag.

The event's flag format reaches this engine as $FLIGHTDECK_FLAG_FORMAT (a regular expression).
The pack's engines take a prefix list instead, so the literal prefixes are read out of the
expression (`practice\\{...}` gives `practice`). When it names none, the common prefixes below are
used and the result's notes say so; either way a flag is only reported when the expression
matches it.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

PACK = Path(__file__).resolve().parent.parent
RESULT_ENV = "FLIGHTDECK_L1_RESULT"
FORMAT_ENV = "FLIGHTDECK_FLAG_FORMAT"
SLUG = "flightdeck"
COMMON_PREFIXES = ("flag", "ctf")       # used only when the event's format names no literal prefix
NOTES_MAX = 6000                        # characters of triage kept in the result's notes
CANDIDATES_SHOWN = 6                    # candidate values named in the notes
CHALLENGE_FILE = "challenge.json"
NOT_HANDOUT = {CHALLENGE_FILE, ".flightdeck"}
_PREFIX = re.compile(r"^[A-Za-z0-9_]{1,32}$")
_BUDGET_ENV = "FLIGHTDECK_PACK_ENGINE_BUDGET"   # seconds for all engines on one challenge (default 120)
_COST_ENV = "FLIGHTDECK_PACK_MAX_COST"          # cheap | medium | heavy (default cheap)


def prefixes_of(pattern: str) -> tuple[str, ...]:
    """The literal flag prefixes a flag-format expression names before its opening brace:
    'practice\\{[a-z]+\\}' -> ('practice',); '(?:flag|CTF)\\{.+\\}' -> ('flag', 'CTF');
    '\\w+\\{...' -> (). Only what is certainly literal is taken."""
    head, sep, _ = pattern.partition(r"\{")
    if not sep:
        return ()
    head = head.lstrip("^")
    head = re.sub(r"^\(\?<![^)]*\)", "", head)          # a leading lookbehind (a word boundary)
    head = re.sub(r"^\\b", "", head)
    group = re.fullmatch(r"\((?:\?:)?([^()]*)\)", head)
    parts = group.group(1).split("|") if group else [head]
    out = [p for p in parts if _PREFIX.match(p)]
    return tuple(dict.fromkeys(out)) if len(out) == len(parts) else ()


def profile_toml(prefixes: tuple[str, ...], name: str, scope: tuple[str, ...] = ()) -> str:
    listed = ", ".join(json.dumps(p) for p in prefixes)
    hosts = ", ".join(json.dumps(h) for h in scope)
    return f"""# Written by the flightdeck adapter for one challenge; flightdeck's own event profile rules a run.
slug = "{SLUG}"
name = {json.dumps(name)}
categories = []
sectors = []
dates = {{ start = 2000-01-01, end = 2100-01-01 }}

[platform]
kind = "manual"

[flag]
prefixes = [{listed}]
case = "prefix-insensitive"

[rules]
submit_mode = "manual"
wrong_answer_stop = 3
guess_budget = 0
hints_allowed = false
flag_sharing = "forbidden"
ai_on_platform = "forbidden"
live_service_scope = [{hosts}]
web_state_changing = false

[writeups]
redact_flags = true

[budget]
per_point = 0.5
floor = 25.0
ceiling = 250.0
"""


def read_challenge(folder: Path) -> dict:
    path = folder / CHALLENGE_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        data = {}
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a JSON object")
    return data


def handout_files(folder: Path, listed) -> list[Path]:
    """The handout's files, relative to the folder: challenge.json's `files` when it lists them,
    else every regular file but challenge.json and flightdeck's own folder. Symlinks are left out."""
    if isinstance(listed, list) and listed:
        out = []
        for rel in listed:
            p = folder / str(rel)
            if isinstance(rel, str) and not p.is_symlink() and p.is_file() and folder.resolve() in p.resolve().parents:
                out.append(Path(rel))
        return out
    out = []
    for root, dirs, files in os.walk(folder):
        here = Path(root)
        if here == folder:
            dirs[:] = [d for d in dirs if d not in NOT_HANDOUT]
        dirs[:] = [d for d in dirs if not (here / d).is_symlink()]
        for f in files:
            p = here / f
            if p.is_symlink() or (here == folder and f in NOT_HANDOUT):
                continue
            out.append(p.relative_to(folder))
    return sorted(out)


class FolderAdapter:
    """The one challenge in this folder, as the pack's platform adapter. No network code; every
    platform call but reading the challenge and copying its files is refused."""
    kind = "manual"

    def __init__(self, folder: Path, challenge):
        self.folder, self.challenge = folder, challenge

    def list_challenges(self):
        return [self.challenge]

    def get_challenge(self, challenge_id: str):
        return self.challenge

    def download_files(self, challenge_id: str, dest: Path):
        out = []
        for ref in self.challenge.files:
            target = Path(dest) / ref.name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.folder / ref.name, target, follow_symlinks=False)
            out.append(target)
        return out

    def _refuse(self, *a, **k):
        from ctf.platform.base import NotAllowed
        raise NotAllowed("the flightdeck adapter never touches a platform: flightdeck submits")

    submit = team_solves = scoreboard = _refuse


def run(folder: Path, flag_format: str | None, *, work: Path) -> dict:
    """Intake the challenge in `folder`; the result as a flightdeck SolverResult mapping."""
    data = read_challenge(folder)
    cid = str(data.get("id") or folder.name)
    notes: list[str] = []
    prefixes = prefixes_of(flag_format) if flag_format else ()
    if not prefixes:
        prefixes = COMMON_PREFIXES
        notes.append("the event's flag format names no literal prefix, so the pack looked for "
                     + ", ".join(p + "{...}" for p in prefixes) + " (any case)")
    events = work / "events"
    (events / SLUG).mkdir(parents=True, exist_ok=True)
    (events / SLUG / "event.toml").write_text(profile_toml(prefixes, "flightdeck board"), encoding="utf-8")
    os.environ.update({"CTF_EVENTS_DIR": str(events), "CTF_EVENT": SLUG, "CTF_WORKDIR": str(work / "work"),
                       "CTF_ENGINE_LEDGER": "0"})
    sys.path.insert(0, str(PACK))
    from ctf import event, intake
    from ctf.platform.base import Challenge, FileRef

    profile = event.load(SLUG)
    files = handout_files(folder, data.get("files"))
    urls = data.get("urls") if isinstance(data.get("urls"), list) else []
    challenge = Challenge(
        id=cid, name=str(data.get("name") or cid), category=str(data.get("category") or "misc"),
        points=data.get("points") if isinstance(data.get("points"), int) else None,
        description=str(data.get("description") or ""),
        files=tuple(FileRef(name=f.as_posix(), url="") for f in files),
        connection_info=" ".join(u for u in urls if isinstance(u, str)))
    options = intake.Options(record=False, brief_fetch=False,
                             engine_budget=float(os.environ.get(_BUDGET_ENV) or 120),
                             max_cost=os.environ.get(_COST_ENV) or "cheap")
    report = intake.intake_one(cid, profile, adapter=FolderAdapter(folder, challenge), workdir=work / "work",
                               options=options)
    result = report.result.to_dict()
    result["engine"] = result["challenge_id"] = None        # flightdeck fills these in
    for item in result.get("evidence", []):
        item["path"] = None        # intake's own report, in a folder that goes when this run ends
    if flag_format:
        pattern = re.compile(flag_format)
        kept = [f for f in result["flags"] if pattern.search(f)]
        dropped = len(result["flags"]) - len(kept)
        if dropped:
            notes.append(f"{dropped} value(s) the pack found do not match the event's flag format and were left out")
            result["flags"] = kept
            if not kept and result["status"] in ("solved", "candidate"):
                result["status"], result["evidence"] = "none", []
            elif result["status"] == "solved" and len(kept) != 1:
                result["status"] = "candidate"
    held = ""
    if result["status"] == "candidate":
        # The pack never sends a candidate by itself (its capped auto-submit takes `solved` only), and
        # under auto submit flightdeck would send every flag of a `candidate` result. So candidates
        # go to the lane's model and the player as text, not as flags: the model can prove one.
        shown = result["flags"][:CANDIDATES_SHOWN]
        held = ("candidates, not proven (decoys and guesses are possible): " + ", ".join(shown)
                + (f" and {len(result['flags']) - len(shown)} more" if len(result["flags"]) > len(shown) else ""))
        result["status"], result["flags"], result["evidence"] = "unsure", [], []
    notes.insert(0, held)
    # flightdeck gives a lane's model one line of each engine's notes (its first few hundred
    # characters), and the console and the run log all of it: the summary comes first.
    result["notes"] = "\n".join(filter(None, [notes.pop(0), _summary(report), result.get("notes", ""), *notes, _triage(report)]))[:NOTES_MAX]
    return result


def _summary(report) -> str:
    """One short line for the lane's model: what the handout holds, which engines ran and what
    each said, and which other engines fit. Names come from the challenge: flightdeck fences it."""
    parts = []
    counts = report.counts()
    kinds: dict[str, int] = {}
    for entry in (report.sweep.manifest if report.sweep is not None else []):
        kind = (getattr(entry, "kind", "") or "?").split(",")[0][:40]
        kinds[kind] = kinds.get(kind, 0) + 1
    held = ", ".join(f"{n} {k}" for k, n in sorted(kinds.items(), key=lambda kv: -kv[1])[:5])
    parts.append(f"handout: {counts['files']} file(s), {counts['members']} unpacked member(s)" + (f" ({held})" if held else ""))
    said: dict[str, str] = {}
    for run in report.runs:
        said[run.engine] = run.result_status or run.status
    if said:
        parts.append("engines run: " + ", ".join(f"{e}={s}" for e, s in list(said.items())[:8])
                     + (f" and {len(said) - 8} more" if len(said) > 8 else ""))
    plan = report.plan
    fits = [e for e, _, _ in sorted(getattr(plan, "unadapted", []) or [], key=lambda t: -t[1])][:6] if plan is not None else []
    if fits:
        parts.append("engines that fit but need a person's arguments: " + ", ".join(fits))
    return "; ".join(parts)


def _triage(report) -> str:
    """What intake learned, for the lane's model: files identified, engines run and what each
    said, engines routed here that need arguments. Derived from challenge data: flightdeck fences it."""
    lines = []
    try:
        from ctf.intake import report as _report
        text = _report.triage_md(report)
    except Exception as exc:      # the result stands; the triage is extra
        return f"(no triage: {type(exc).__name__}: {exc})"
    for line in text.splitlines():
        if line.strip():
            lines.append(line.rstrip())
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: intake_engine.py CHALLENGE_DIR", file=sys.stderr)
        return 2
    folder = Path(argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="fd-intake-") as tmp:
        try:
            result = run(folder, os.environ.get(FORMAT_ENV) or None, work=Path(tmp))
        except Exception as exc:
            result = {"schema": 1, "status": "unsure", "notes": f"the pack's intake failed: {type(exc).__name__}: {exc}"}
    text = json.dumps(result)
    target = os.environ.get(RESULT_ENV)
    if target:
        Path(target).write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
