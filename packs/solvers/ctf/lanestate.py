"""Lane-state readers (B-257): one place that reads the harness's per-challenge and per-lane state
files, so agents stop writing inline `cat … | python -c` and heredoc JSON readers for them.

Over the Huntress Oct 26 - Nov 4 cohort agents wrote ~1,554 small inline scripts to read the same
handful of files (attempt/result/start/key.json, verdicts.jsonl, proof-hunt results, conventions and
routes, ladder and answer files) on every day cycle. This module gives each one a named reader with
compact, deterministic output; `ctf/cli/state.py` wraps them as `python -m ctf state <sub>`, the lane
briefs name that command, and B-210's `ctf show` reuses these functions.

Everything here is pure file reading: no network, no model, no challenge binary. A missing file or an
unreadable one fails loudly with a named reason (LaneStateError), never a silent empty result (R-6).

Challenge layout (tools/run.py VARIANT_FILES): one folder per challenge id under a challenges root,
possibly one directory deep (`<root>/day-NN/<id>/`). The Game Master that wrote them is archived, so
the root is always an argument (`--root`, else `$CTF_REAL_CHALLENGES`); callers that already hold the
folder pass it with `--dir`.
"""
from __future__ import annotations

import json
from pathlib import Path

# Per-variant files this module reads, and the alternatives tried in order for a logical name.
# (tools/run.py: VARIANT_FILES / save_outcome / save_attempt.)
VARIANT_FILES: dict[str, tuple[str, ...]] = {
    "attempt": ("attempt.json",),
    "result": ("result.json",),
    "start": ("start.json", "live_start.json"),
    "key": ("key.json",),
    "verdicts": ("verdicts.jsonl",),
    "answers": ("answers.submitted.json", "answers.json", "answers.dry-run.json"),
    "ladder": ("ladder-log.json",),
}
# Proof-hunt output (solvers/web/proof_hunt.py prints {answer_id: proof|None}); a run saves it under
# one of these names next to the attempt. Tried in order.
PROOF_FILES: tuple[str, ...] = ("proofs.json", "proof_hunt.json", "proof-hunt.json", "proof_hunt.jsonl")

# Files whose inline readers B-257 replaces; the brief lint flags these names (plus the logical ones).
STATE_FILE_NAMES: tuple[str, ...] = (
    "attempt.json", "result.json", "start.json", "live_start.json", "key.json",
    "verdicts.jsonl", "answers.json", "answers.submitted.json", "answers.dry-run.json",
    "ladder-log.json", "golden.json", "unsure.json", "conventions.json", "id_conventions.toml",
    "route_table.jsonl", "routes_seen.json",
) + PROOF_FILES

_VALUE_CAP = 120  # a single answer/value line is truncated to this many characters


class LaneStateError(RuntimeError):
    """A lane-state file is missing, ambiguous or unreadable. The message names the file and the fix."""


# ---- locating a challenge folder ---------------------------------------------------------------------

def _is_challenge_dir(d: Path) -> bool:
    """A folder that holds at least one of the per-variant files looks like a challenge folder."""
    for names in VARIANT_FILES.values():
        for n in names:
            if (d / n).exists():
                return True
    return False


def resolve_challenge_dir(cid: str | None, *, root: Path | None = None, direct: Path | None = None) -> Path:
    """The folder holding one challenge's variant files.

    `direct` (from --dir) is used as-is. Otherwise `cid` is located under `root` (--root, else
    $CTF_REAL_CHALLENGES): `<root>/<cid>`, then one directory deep (`<root>/*/<cid>`), matching a
    folder whose name is exactly `cid` or ends in `-<cid>`. Raises LaneStateError when there is no
    root, no match, or more than one match (never guesses)."""
    if direct is not None:
        d = Path(direct).expanduser()
        if not d.is_dir():
            raise LaneStateError(f"--dir: not a directory: {d}")
        return d
    if not cid:
        raise LaneStateError("give a challenge id (and --root, or set $CTF_REAL_CHALLENGES) or --dir")
    if root is None:
        from . import paths as _paths
        try:
            root = _paths.saved_challenges_root()
        except FileNotFoundError as e:          # set to a folder that is not there: name it, do not guess
            raise LaneStateError(f"{e}; fix $CTF_REAL_CHALLENGES, or pass --root DIR or --dir") from e
        if root is None:
            raise LaneStateError(
                "no challenges root: pass --root DIR or set $CTF_REAL_CHALLENGES (or use --dir)")
    root = Path(root).expanduser()
    if not root.is_dir():
        raise LaneStateError(f"--root: not a directory: {root}")
    matches: list[Path] = []
    direct_hit = root / cid
    if direct_hit.is_dir():
        matches.append(direct_hit)
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        for grand in sorted(child.iterdir()):
            if grand.is_dir() and (grand.name == cid or grand.name.endswith("-" + cid)):
                matches.append(grand)
    # de-duplicate while keeping order
    seen: set[str] = set()
    uniq = [m for m in matches if not (str(m) in seen or seen.add(str(m)))]
    if not uniq:
        raise LaneStateError(f"no challenge folder for id {cid!r} under {root}")
    if len(uniq) > 1:
        joined = ", ".join(str(m.relative_to(root)) for m in uniq)
        raise LaneStateError(f"id {cid!r} is ambiguous under {root}: {joined}; pass --dir")
    return uniq[0]


def _pick_file(d: Path, names: tuple[str, ...]) -> Path:
    for n in names:
        p = d / n
        if p.exists():
            return p
    where = names[0] if len(names) == 1 else f"one of {', '.join(names)}"
    raise LaneStateError(f"{where} not found in {d}")


# ---- formatting helpers ------------------------------------------------------------------------------

def _clip(text: str, cap: int = _VALUE_CAP) -> str:
    """One line: control characters shown as spaces, truncated with an ellipsis marker."""
    s = "".join(ch if ch.isprintable() else " " for ch in str(text))
    s = " ".join(s.split())
    return s if len(s) <= cap else s[: cap - 1] + "…"


def _scalar(v) -> str | None:
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "null"
    if isinstance(v, (int, float, str)):
        return _clip(v)
    return None


def _one_value(v) -> str:
    """A value cell: the scalar, a dict's own answer field, or a compact json fallback."""
    s = _scalar(v)
    if s is not None:
        return s
    if isinstance(v, dict):
        for k in ("value", "answer", "text", "flag", "proof"):
            if k in v and _scalar(v[k]) is not None:
                return _scalar(v[k])
        return _clip(json.dumps(v, separators=(",", ":"), sort_keys=True))
    if isinstance(v, list):
        return f"[{len(v)} item{'s' if len(v) != 1 else ''}]"
    return _clip(json.dumps(v, separators=(",", ":"), default=str))


def _summarize(obj, *, first: tuple[str, ...] = ()) -> list[str]:
    """`key: value` lines for a JSON object: `first` keys (when present) in order, then the rest
    sorted. Containers are shown as a count so the output stays compact and fixed."""
    if not isinstance(obj, dict):
        return [_one_value(obj)]
    order = [k for k in first if k in obj] + sorted(k for k in obj if k not in first)
    out = []
    for k in order:
        v = obj[k]
        s = _scalar(v)
        if s is not None:
            out.append(f"{k}: {s}")
        elif isinstance(v, list):
            out.append(f"{k}: [{len(v)} item{'s' if len(v) != 1 else ''}]")
        elif isinstance(v, dict):
            out.append(f"{k}: {{{len(v)} key{'s' if len(v) != 1 else ''}}}")
        else:
            out.append(f"{k}: {_one_value(v)}")
    return out


def _load_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as e:
        raise LaneStateError(f"{p}: could not read JSON ({e})") from None


def _load_jsonl(p: Path) -> list:
    rows = []
    try:
        text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise LaneStateError(f"{p}: could not read ({e})") from None
    for i, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except ValueError as e:
            raise LaneStateError(f"{p}: line {i} is not JSON ({e})") from None
    return rows


def _answer_map_lines(obj, label: str) -> list[str]:
    """`answer_id: value` lines for an {id: value} map (key.json / answers*.json)."""
    if not isinstance(obj, dict):
        raise LaneStateError(f"{label}: expected a JSON object mapping answer ids to values")
    if not obj:
        return [f"{label}: (empty)"]
    lines = [f"{label} ({len(obj)} answer{'s' if len(obj) != 1 else ''}):"]
    for aid in sorted(obj):
        lines.append(f"  {aid} = {_one_value(obj[aid])}")
    return lines


# ---- per-challenge readers ---------------------------------------------------------------------------

def read_attempt(d: Path) -> list[str]:
    p = _pick_file(d, VARIANT_FILES["attempt"])
    obj = _load_json(p)
    lines = [f"attempt {p.name}:"]
    lines += ["  " + ln for ln in _summarize(
        obj, first=("attempt_id", "challenge_id", "id", "kind", "pool", "mode",
                    "started_at", "deadline", "expires_at", "ticket"))]
    return lines


def read_result(d: Path) -> list[str]:
    p = _pick_file(d, VARIANT_FILES["result"])
    obj = _load_json(p)
    lines = [f"result {p.name}:"]
    lines += ["  " + ln for ln in _summarize(
        obj, first=("result", "source", "attempt_id", "submitted", "at"))]
    return lines


def read_start(d: Path) -> list[str]:
    p = _pick_file(d, VARIANT_FILES["start"])
    obj = _load_json(p)
    lines = [f"start {p.name}:"]
    lines += ["  " + ln for ln in _summarize(
        obj, first=("attempt_id", "challenge_id", "id", "kind", "started_at", "deadline"))]
    return lines


def read_key(d: Path) -> list[str]:
    p = _pick_file(d, VARIANT_FILES["key"])
    obj = _load_json(p)
    return _answer_map_lines(obj, "key.json (frozen answers)")


def read_answers(d: Path) -> list[str]:
    p = _pick_file(d, VARIANT_FILES["answers"])
    obj = _load_json(p)
    return _answer_map_lines(obj, p.name)


def read_verdicts(d: Path) -> list[str]:
    p = _pick_file(d, VARIANT_FILES["verdicts"])
    rows = _load_jsonl(p)
    if not rows:
        return [f"verdicts.jsonl: (no entries)"]
    lines = [f"verdicts.jsonl ({len(rows)} submission{'s' if len(rows) != 1 else ''}):"]
    for i, r in enumerate(rows, 1):
        if not isinstance(r, dict):
            lines.append(f"  {i}. {_one_value(r)}")
            continue
        parts = []
        for k in ("kind", "result", "verdict", "http", "left"):
            if k in r and _scalar(r[k]) is not None:
                parts.append(f"{k}={_scalar(r[k])}")
        vals = r.get("values")
        if isinstance(vals, dict) and vals:
            parts.append("values=" + ",".join(f"{a}:{_one_value(v)}" for a, v in sorted(vals.items())))
        lines.append(f"  {i}. " + (" ".join(parts) if parts else _clip(json.dumps(r, sort_keys=True))))
    return lines


def read_ladder(d: Path) -> list[str]:
    p = _pick_file(d, VARIANT_FILES["ladder"])
    obj = _load_json(p)
    lines = [f"ladder-log.json:"]
    if isinstance(obj, list):
        lines[0] = f"ladder-log.json ({len(obj)} step{'s' if len(obj) != 1 else ''}):"
        for i, step in enumerate(obj, 1):
            if isinstance(step, dict):
                lines.append(f"  {i}. " + "; ".join(_summarize(
                    step, first=("op", "answer_id", "value", "result", "at"))))
            else:
                lines.append(f"  {i}. {_one_value(step)}")
    else:
        lines += ["  " + ln for ln in _summarize(obj)]
    return lines


def read_proofs(d: Path, *, direct: Path | None = None) -> list[str]:
    """Proof-hunt results: {answer_id: proof|None}. `direct` overrides the file searched for."""
    if direct is not None:
        p = Path(direct).expanduser()
        if not p.is_file():
            raise LaneStateError(f"--file: not a file: {p}")
    else:
        found = [d / n for n in PROOF_FILES if (d / n).exists()]
        if not found:
            raise LaneStateError(
                f"no proof-hunt results in {d} (looked for {', '.join(PROOF_FILES)}); pass --file")
        p = found[0]
    obj = _load_json(p)
    if not isinstance(obj, dict):
        raise LaneStateError(f"{p}: expected a JSON object {{answer_id: proof|null}}")
    if not obj:
        return [f"{p.name}: (no proofs)"]
    proven = [a for a in obj if obj[a] is not None]
    lines = [f"{p.name} ({len(proven)}/{len(obj)} answered):"]
    for aid in sorted(obj):
        v = obj[aid]
        lines.append(f"  {aid} = {'None' if v is None else _one_value(v)}")
    return lines


# a logical-name -> reader map, so the CLI and `ctf show` dispatch the same way
VARIANT_READERS = {
    "attempt": read_attempt,
    "result": read_result,
    "start": read_start,
    "key": read_key,
    "answers": read_answers,
    "verdicts": read_verdicts,
    "ladder": read_ladder,
}


# ---- lane-level readers (not per challenge) ----------------------------------------------------------

def read_conventions(*, lane: str = "binary", root: Path | None = None,
                     answers_path: Path | None = None, ids_path: Path | None = None) -> list[str]:
    """The lane's answer conventions (solvers/<lane>/conventions.json, field/value -> accepted) and id
    conventions (solvers/<lane>/id_conventions.toml via ctf.idresolve). At least one must exist."""
    if root is None:
        from . import paths as _paths
        root = _paths.repo_root()
    lane_dir = Path(root) / "solvers" / lane
    ans = Path(answers_path) if answers_path is not None else lane_dir / "conventions.json"
    ids = Path(ids_path) if ids_path is not None else lane_dir / "id_conventions.toml"
    lines: list[str] = []
    if ans.is_file():
        obj = _load_json(ans)
        if not isinstance(obj, dict):
            raise LaneStateError(f"{ans}: expected a JSON object of field/value conventions")
        lines.append(f"answer conventions {ans.name} ({len(obj)} entr{'y' if len(obj) == 1 else 'ies'}):")
        for field in sorted(obj):
            entry = obj[field] if isinstance(obj[field], dict) else {}
            accepted = entry.get("accepted")
            rejected = entry.get("rejected") or []
            tail = f" (rejected: {', '.join(map(str, rejected))})" if rejected else ""
            lines.append(f"  {field} -> {_one_value(accepted) if accepted is not None else '?'}{tail}")
    if ids.is_file():
        from . import idresolve as _idresolve
        try:
            cat = _idresolve.load_conventions(ids)
        except _idresolve.ConventionError as e:
            raise LaneStateError(f"{ids}: {e}") from None
        lines.append(f"id conventions {ids.name}: {len(cat.known)} known id(s)"
                     + (f", {len(cat.scopes)} scope(s)" if cat.scopes else ""))
        for k in sorted(cat.known):
            lines.append(f"  {k}")
        for s in cat.scopes:
            lines.append(f"  scope {s.name}: prefix={s.prefix!r} fields="
                         + ",".join(f"{a}->{b}" for a, b in s.fields))
    if not lines:
        raise LaneStateError(
            f"no conventions for lane {lane!r}: neither {ans} nor {ids} exists (pass --answers/--ids)")
    return lines


def read_routes(*, root: Path | None = None, lane: str | None = None,
                category: str | None = None, engine_id: str | None = None) -> list[str]:
    """The triage route table (ctf/engines/route_table.jsonl), optionally filtered. Loud when the
    table is missing (it is generated by `python -m ctf engines generate`)."""
    from .engines import routetable as _rt
    try:
        rows = _rt.load(Path(root) if root is not None else None)
    except _rt.RouteTableError as e:
        raise LaneStateError(str(e)) from None
    sel = []
    for r in rows:
        if lane is not None and lane not in ("", r.id.split(".")[0]):
            # a route has no lane field; the id's first dotted segment is its lane
            if not r.id.startswith(lane + "."):
                continue
        if category is not None and category not in r.category:
            continue
        if engine_id is not None and r.id != engine_id:
            continue
        sel.append(r)
    lines = [f"route_table.jsonl ({len(sel)}/{len(rows)} route{'s' if len(sel) != 1 else ''}):"]
    for r in sorted(sel, key=lambda x: (x.id, -x.priority)):
        cats = ",".join(r.category) or "-"
        files = ",".join(r.files) if r.files else ""
        lines.append(f"  {r.priority:>3} {r.id} [{r.cls}] cat={cats}" + (f" files={files}" if files else ""))
    return lines


def read_qdiff(base_path: Path, timed_path: Path) -> list[str]:
    """Question-contract diff of a timed start against its base (ctf.adapt.qdiff)."""
    from .adapt import qdiff as _qdiff
    base = _load_json(Path(base_path))
    timed = _load_json(Path(timed_path))
    try:
        d = _qdiff.qdiff(base, timed)
    except _qdiff.QDiffError as e:
        raise LaneStateError(str(e)) from None
    return list(d.lines())


# ---- brief lint --------------------------------------------------------------------------------------

import re as _re

# An inline reader is a shell/python one-liner or heredoc that opens one of the state files by name.
_READ_VERBS = _re.compile(
    r"\b(?:cat|less|head|tail|jq|json\.load|json\.loads|read_text|open|loads?\()",
    _re.IGNORECASE)


def lint_brief_text(text: str) -> list[tuple[int, str, str]]:
    """Lines in one brief that tell an agent to hand-parse a lane-state file. Returns
    (line number, the file named, the offending line). A line is flagged when it names a state file
    AND carries a read verb (cat/jq/json.load/open/…), so prose that merely mentions `ctf state`
    is not flagged."""
    hits: list[tuple[int, str, str]] = []
    for n, line in enumerate(text.splitlines(), 1):
        named = next((f for f in STATE_FILE_NAMES if f in line), None)
        if named is None:
            continue
        if "ctf state" in line:            # already points at the command
            continue
        if not _READ_VERBS.search(line):
            continue
        hits.append((n, named, line.strip()))
    return hits


def _iter_brief_files(paths) -> list[Path]:
    exts = {".md", ".markdown", ".txt", ".tmpl"}
    out: list[Path] = []
    for raw in paths:
        p = Path(raw).expanduser()
        if p.is_dir():
            out += sorted(q for q in p.rglob("*") if q.is_file() and q.suffix.lower() in exts)
        elif p.is_file():
            out.append(p)
        else:
            raise LaneStateError(f"brief path not found: {p}")
    return out


def lint_briefs(paths) -> list[tuple[Path, int, str, str]]:
    """Every (file, line, named file, line text) across the brief paths that hand-parses a state file."""
    findings: list[tuple[Path, int, str, str]] = []
    for f in _iter_brief_files(paths):
        try:
            text = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            raise LaneStateError(f"{f}: could not read ({e})") from None
        for n, named, line in lint_brief_text(text):
            findings.append((f, n, named, line))
    return findings
