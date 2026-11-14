"""Per-event agent rules: ONE template renders both CLAUDE.md and AGENTS.md from the event profile.

    from ctf import eventrules
    files = eventrules.render(profile)          # {"CLAUDE.md": text, "AGENTS.md": text}
    eventrules.write(profile, dest_dir)         # writes both, returns the paths
    problems = eventrules.check(profile, dest_dir)   # [] when both files match the profile

Why one template: at Spooky only CLAUDE.md carried the no-AI-on-infrastructure rule, so Codex (which
loads AGENTS.md, not CLAUDE.md) never saw it and reached live challenge hosts. Here both files come
from templates/event/agent-rules.md.tmpl and the same profile; the body below the end-of-header
marker must render byte-identical for both (render() refuses a template where it does not), and
check() re-renders and reports any file that is missing, stale (profile or template changed since it
was generated), edited by hand, or that disagrees with its sibling.

Template syntax (deliberately tiny; anything else is an error):
    {{name}}                         a value from the context (str)
    {{#if name}} .. {{else}} .. {{/if}}   a boolean gate; {{#unless name}} .. {{/unless}} the inverse
    {{!-- ... --}}                   a comment, dropped
A block tag alone on its line takes the whole line with it. An unknown name, a non-boolean gate, an
unbalanced block or a stray "{{" / "}}" raises TemplateError: nothing renders half-filled.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from . import event as _event
from . import flagfmt as _flagfmt
from . import paths

AGENT_FILES = ("CLAUDE.md", "AGENTS.md")
TEMPLATE_REL = Path("templates/event/agent-rules.md.tmpl")
HEADER_END = "<!-- end of header"
_META_RE = re.compile(r"<!-- ctf-event-rules file=(\S+) slug=(\S+) profile=([0-9a-f]+) template=([0-9a-f]+) -->")
DIGEST_LEN = 16


class TemplateError(ValueError):
    """The agent-rules template is malformed or references something the context lacks."""


def template_path() -> Path:
    return paths.repo_root() / TEMPLATE_REL


def _read_template(path: Path | None) -> str:
    path = template_path() if path is None else Path(path)
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise TemplateError(f"agent-rules template not found at {path}") from None


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:DIGEST_LEN]


# ------------------------------------------------------------------------------------------ renderer

_COMMENT_RE = re.compile(r"\{\{!--.*?--\}\}\n?", re.S)
_BLOCK = r"\{\{\s*(?:#if|#unless|else|/if|/unless)\b[^{}]*\}\}"
_ALONE_RE = re.compile(rf"^[ \t]*({_BLOCK})[ \t]*\n", re.M)
_TAG_RE = re.compile(r"\{\{(.*?)\}\}", re.S)
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _parse(src: str) -> list:
    """Template text -> nested nodes: str | ("var", name) | ("if", name, negate, then, else)."""
    root: list = []
    stack: list[tuple[str, str, bool, list, list | None]] = []
    cur = root
    pos = 0

    def literal(text: str) -> None:
        if "{{" in text or "}}" in text:
            raise TemplateError(f"stray brace pair in template text near {text[max(0, text.find('{{')):][:40]!r}")
        if text:
            cur.append(text)

    for m in _TAG_RE.finditer(src):
        literal(src[pos:m.start()])
        pos = m.end()
        inner = m.group(1).strip()
        parts = inner.split()
        if not parts:
            raise TemplateError("empty {{}} tag in template")
        head = parts[0]
        if head in ("#if", "#unless"):
            if len(parts) != 2 or not _NAME_RE.match(parts[1]):
                raise TemplateError(f"bad block tag {{{{{inner}}}}}")
            then: list = []
            stack.append((head, parts[1], head == "#unless", then, None))
            cur = then
        elif head == "else":
            if len(parts) != 1 or not stack or stack[-1][4] is not None or stack[-1][0] != "#if":
                raise TemplateError("{{else}} outside an {{#if}} block (or a second {{else}})")
            kind, name, neg, then, _ = stack.pop()
            other: list = []
            stack.append((kind, name, neg, then, other))
            cur = other
        elif head in ("/if", "/unless"):
            if len(parts) != 1 or not stack or stack[-1][0] != "#" + head[1:]:
                raise TemplateError(f"{{{{{head}}}}} does not close an open {{{{#{head[1:]}}}}}")
            kind, name, neg, then, other = stack.pop()
            cur = stack[-1][4] if stack and stack[-1][4] is not None else (stack[-1][3] if stack else root)
            cur.append(("if", name, neg, then, other or []))
        elif len(parts) == 1 and _NAME_RE.match(head):
            cur.append(("var", head))
        else:
            raise TemplateError(f"unknown template tag {{{{{inner}}}}}")
    literal(src[pos:])
    if stack:
        raise TemplateError(f"unclosed {{{{{stack[-1][0]} {stack[-1][1]}}}}} block")
    return root


def _eval(nodes: list, ctx: dict[str, Any], used: set[str]) -> str:
    out: list[str] = []
    for n in nodes:
        if isinstance(n, str):
            out.append(n)
            continue
        name = n[1]
        if name not in ctx:
            raise TemplateError(f"template uses {name!r}, which the context does not define")
        used.add(name)
        v = ctx[name]
        if n[0] == "var":
            if not isinstance(v, str):
                raise TemplateError(f"{{{{{name}}}}} must be a string, got {type(v).__name__}")
            out.append(v)
        else:
            if not isinstance(v, bool):
                raise TemplateError(f"block gate {name!r} must be a boolean, got {type(v).__name__}")
            _, _, neg, then, other = n
            out.append(_eval(then if (v != neg) else other, ctx, used))
    return "".join(out)


def render_text(template: str, ctx: dict[str, Any]) -> str:
    """Render template text against ctx (str values and bool gates). Strict: see module docstring."""
    src = _COMMENT_RE.sub("", template)
    if "{{!" in src:
        raise TemplateError("unterminated {{!-- comment in template")
    src = _ALONE_RE.sub(r"\1", src)
    return _eval(_parse(src), ctx, set())


# ------------------------------------------------------------------------------------------ context

def profile_digest(profile: _event.EventProfile) -> str:
    """Digest of the profile values the template sees (not the file bytes, not the whole dataclass):
    comment-only edits, and a new profile field the template does not use yet, do not make the
    generated files stale; any change that alters the rendered rules does."""
    ctx = _profile_values(profile)
    return _digest(json.dumps(ctx, sort_keys=True, separators=(",", ":")).encode())


def _money(x: float) -> str:
    return f"{x:g}" if x != int(x) else str(int(x))


def _code_list(items: tuple[str, ...]) -> str:
    return ", ".join(f"`{x}`" for x in items)


_PLATFORM_LABEL = {"ctfd": "CTFd", "gamemaster": "Game Master", "manual": "manual"}


def context(profile: _event.EventProfile, agent_file: str, template_digest: str) -> dict[str, Any]:
    """Everything the template may use: the profile's values plus which file is being rendered."""
    if agent_file not in AGENT_FILES:
        raise ValueError(f"agent_file must be one of {AGENT_FILES}")
    ctx = _profile_values(profile)
    ctx.update({
        "agent_file": agent_file,
        "sibling_file": AGENT_FILES[1 - AGENT_FILES.index(agent_file)],
        "profile_digest": profile_digest(profile),
        "template_digest": template_digest,
    })
    return ctx


def _profile_values(profile: _event.EventProfile) -> dict[str, Any]:
    p, r, f, b = profile.platform, profile.rules, profile.flag, profile.budget
    ff = _flagfmt.for_profile(profile)
    url = p.base_url or ""
    if p.kind == "manual":
        platform_line = ("manual: no platform automation is wired; the player pulls the files and "
                         "submits by hand" + (f" ({url})." if url else "."))
    else:
        platform_line = f"{_PLATFORM_LABEL.get(p.kind, p.kind)} at {url}."
    platform_target = f"the event platform ({url})" if url else "the event platform"
    case_note = {"exact": "case exact",
                 "prefix-insensitive": "the prefix in any case, the body exact",
                 "insensitive": "case-insensitive"}[f.case]
    return {
        "slug": profile.slug,
        "event_name": profile.name,
        "dates": f"{profile.start.isoformat()} to {profile.end.isoformat()}",
        "platform_line": platform_line,
        "platform_target": platform_target,
        "has_team": p.team is not None,
        "team": p.team or "",
        "categories": (", ".join(profile.categories) if profile.categories else
                       "not known yet (set `categories` in the profile, or let `new-event` fetch them "
                       "from the platform)"),
        "sectors": ", ".join(profile.sectors) if profile.sectors else "none listed",
        "ai_platform_forbidden": r.ai_on_platform == "forbidden",
        "scope_empty": not r.live_service_scope,
        "scope_list": _code_list(r.live_service_scope),
        "web_state_changing": r.web_state_changing,
        "flag_known": f.known,
        "flag_examples": ", ".join(f"`{x}{{...}}`" for x in f.prefixes),
        "flag_case_note": case_note,
        "flag_pattern": ff.pattern,
        "has_proof": profile.proof is not None,
        "proof_pattern": profile.proof.pattern if profile.proof else "",
        "submit_auto": r.submit_mode == "auto",
        "submit_confirm": r.submit_mode == "confirm",
        "submit_manual": r.submit_mode == "manual",
        "wrong_answer_stop": str(r.wrong_answer_stop),
        "guess_budget_zero": r.guess_budget == 0,
        "guess_budget": str(r.guess_budget),
        "platform_manual": p.kind == "manual",
        "hints_allowed": r.hints_allowed,
        "flag_sharing_forbidden": r.flag_sharing == "forbidden",
        "budget_per_day": b.per_challenge_day is not None,
        "per_challenge_day": _money(b.per_challenge_day) if b.per_challenge_day is not None else "",
        "per_point": _money(b.per_point),
        "floor": _money(b.floor),
        "ceiling": _money(b.ceiling),
        "budget_overthink": b.overthink_usd is not None,
        "overthink_usd": _money(b.overthink_usd) if b.overthink_usd is not None else "",
        "overthink_max_points": _money(b.overthink_max_points) if b.overthink_max_points is not None else "",
        "overthink_min_solves": str(b.overthink_min_solves) if b.overthink_min_solves is not None else "",
        "redact_flags": profile.writeups.redact_flags,
        "has_public_repo": bool(profile.writeups.public_repo),
        "public_repo": profile.writeups.public_repo or "",
        # B-173 solve policy
        "penalty_line": _penalty_line(r.wrong_penalty),
        "submit_per_minute": str(profile.submit.per_minute),
        "submit_interval": _money(profile.submit.interval_s),
        "submit_per_challenge_interval": _money(profile.submit.per_challenge_interval_s),
        "approved_extras": r.approved_extras,
        "sweep_authorized": profile.sweep.authorized,
        "sweep_max": str(profile.sweep.max_count),
        "sweep_interval": _money(profile.sweep.interval_s),
        "sweep_ttl": _duration(profile.sweep.ttl_s),
        "hint_suggestions": r.hint_suggestions,
        "pointed_allowed": r.pointed_services == "allowed",
        # B-172: the solver contract (one source, ctf/solver_contract.py); in the digest, so a contract
        # change marks every event's agent files stale until they are regenerated
        "solver_contract": _solver_contract_md(),
        # B-199: the repo-reading rules (primer, ctf read / symbols, binary-first, research cache); one
        # source, ctf/primer.py, and in the digest like the solver contract
        "repo_reading_rules": _repo_reading_md(),
        # B-043: the command discipline every brief carries (one source, ctf/briefdiscipline.py); in
        # the digest for the same reason
        "brief_discipline": _brief_discipline_md(),
    }


def _solver_contract_md() -> str:
    from .solver_contract import rules_md
    return rules_md(heading_level=2).rstrip("\n")


def _repo_reading_md() -> str:
    from .primer import rules_md
    return rules_md().rstrip("\n")


def _brief_discipline_md() -> str:
    from .briefdiscipline import rules_md
    return rules_md(heading_level=2).rstrip("\n")


def _penalty_line(points: int | None) -> str:
    if points is None:
        return ("**Penalty: not recorded** in the profile. Treat every wrong answer as costly;\n"
                "  set `rules.wrong_penalty` once the organizers state it.")
    if points == 0:
        return "**Penalty: none.** A wrong answer costs no points, but it still counts toward the stop."
    return f"**Penalty: {points} point(s) per wrong answer.** Every wrong send costs the team."


def _duration(seconds: float) -> str:
    if seconds >= 3600 and seconds % 3600 == 0:
        return f"{int(seconds // 3600)} hour(s)"
    if seconds >= 60 and seconds % 60 == 0:
        return f"{int(seconds // 60)} minute(s)"
    return f"{_money(seconds)} second(s)"


# ------------------------------------------------------------------------------------------ render

def split_header(text: str) -> tuple[str, str]:
    """(header, body) at the end-of-header marker line; the body is what both files share."""
    i = text.find("\n" + HEADER_END)
    if i < 0:
        raise TemplateError("rendered text has no end-of-header marker")
    j = text.find("\n", i + 1)
    j = len(text) if j < 0 else j + 1
    return text[:j], text[j:]


def render(profile: _event.EventProfile, template: Path | None = None) -> dict[str, str]:
    """{"CLAUDE.md": text, "AGENTS.md": text} from the one template. Raises TemplateError when the
    two bodies would differ (a template that put file-specific text below the header)."""
    src = _read_template(template)
    tdig = _digest(src.encode("utf-8"))
    out = {name: render_text(src, context(profile, name, tdig)) for name in AGENT_FILES}
    bodies = {name: split_header(text)[1] for name, text in out.items()}
    if bodies["CLAUDE.md"] != bodies["AGENTS.md"]:
        raise TemplateError("template renders different rules for CLAUDE.md and AGENTS.md below the "
                            "end-of-header marker; only the header may name the file")
    return out


def write(profile: _event.EventProfile, dest: Path, template: Path | None = None) -> list[Path]:
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    written = []
    for name, text in render(profile, template).items():
        path = dest / name
        path.write_text(text, encoding="utf-8")
        written.append(path)
    return written


# ------------------------------------------------------------------------------------------ check

def _first_diff(a: str, b: str) -> str:
    al, bl = a.splitlines(), b.splitlines()
    for i, (x, y) in enumerate(zip(al, bl)):
        if x != y:
            return f"line {i + 1}: expected {x[:70]!r}, found {y[:70]!r}"
    return f"line {min(len(al), len(bl)) + 1}: expected {len(al)} lines, found {len(bl)}"


def check(profile: _event.EventProfile, dest: Path, template: Path | None = None) -> list[str]:
    """Problems with the generated agent files in dest (empty list = all good). Each names the file
    and says whether it is missing, stale (profile or template changed since generation), edited by
    hand, or disagrees with its sibling."""
    dest = Path(dest)
    want = render(profile, template)
    have: dict[str, str] = {}
    problems: list[str] = []
    for name in AGENT_FILES:
        path = dest / name
        if not path.is_file():
            problems.append(f"{path}: missing (run `python -m ctf new-event {profile.slug} --regen`)")
            continue
        text = path.read_text(encoding="utf-8")
        have[name] = text
        if text == want[name]:
            continue
        m = _META_RE.search(text)
        wm = _META_RE.search(want[name])
        assert wm is not None, "template lost its ctf-event-rules metadata line"
        if m is None:
            problems.append(f"{path}: not a generated file (no ctf-event-rules line); regenerate it")
        elif m.group(1) != name or m.group(2) != profile.slug:
            problems.append(f"{path}: generated as {m.group(1)} for event {m.group(2)!r}, "
                            f"not {name} for {profile.slug!r}")
        elif m.group(3) != wm.group(3):
            problems.append(f"{path}: stale: the profile changed since it was generated "
                            f"(profile digest {m.group(3)}, now {wm.group(3)}); "
                            f"run `python -m ctf new-event {profile.slug} --regen`")
        elif m.group(4) != wm.group(4):
            problems.append(f"{path}: stale: the template changed since it was generated "
                            f"(template digest {m.group(4)}, now {wm.group(4)}); "
                            f"run `python -m ctf new-event {profile.slug} --regen`")
        else:
            problems.append(f"{path}: edited by hand; it disagrees with the profile at "
                            f"{_first_diff(want[name], text)}")
    if len(have) == 2:
        try:
            b1, b2 = (split_header(have[n])[1] for n in AGENT_FILES)
        except TemplateError:
            b1, b2 = have["CLAUDE.md"], have["AGENTS.md"]
        if b1 != b2:
            problems.append(f"{dest}: CLAUDE.md and AGENTS.md carry different rules "
                            f"({_first_diff(b1, b2)})")
    return problems
