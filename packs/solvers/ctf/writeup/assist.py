"""Draft the prose of staged writeups and retros on the docs model, then one review pass on the
primary model (B-097). The facts are already in the drafts (ctf.writeup.draft / retro, B-098): only
the `<!-- TODO: ... -->` markers are written here, each from a brief built from a fixed template and
the saved evidence in that file, never from a whole session's context.

    jobs, skipped = assist.plan(profile, staging, kind="draft", scanner=sc, records=ledger_records)
    outcomes = assist.run(profile, staging, workdir, jobs, runner=assist.ClaudeRunner(), scanner=sc)

Routing is by task type only (TASKS, profile [models]; docs/writeup-pipeline.md):

    writeup                 challenge README sections        models.docs      pass pending
    writeup-primary         README of a docs_on_primary      models.primary   pass done by the draft
                            category (exploit-heavy work)
    retro-recommendations   retro rows that change a         models.primary   pass done by the draft
                            solver's behaviour
    retro-questions         retro open questions             models.docs      pass none (private)
    review                  the one pass on pending blocks   models.primary

A model that declines a job is recorded and the job is not re-sent with the same brief, and never
sent to another model: model-shopping was stopped in 2026 and stays stopped. The sections stay TODO
for a person. A decline is the CLI's stop_reason refusal, a <<<DECLINE>>> line, or a reply with no
answer block at all (a refusal in prose). A reply that has answer blocks but does not follow the
format is rejected whole as bad-output (nothing is written) and may be sent again.

The model a block names (`by=`, and `pass=` after a review) is the one the CLI reported, when that
is a valid model id; otherwise the routed model, with model_reported false in the ledger. A review
that ran on a model outside the primary tier (models.primary, models.fallback) leaves the block
pending.

Model output is data: it is neutralized (it cannot open, close or forge a comment marker), redacted
when the event redacts, and wrapped in drafted-text markers (ctf.writeup.passes) whose review state
the publish gate reads. Every call is recorded in the event ledger as `writeup.assist`
{pass_kind, doc, task, model, model_used, model_reported, outcome, usd, tok, sections, brief_sha256}.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from .. import event as _event
from .. import fence as _fence
from .. import fence_launch as _launch
from .. import ledger as _ledger
from . import common, passes, policy as _policy, scan as _scan

TASKS = ("writeup", "writeup-primary", "retro-recommendations", "retro-questions", "review")
LEDGER_EVENT = "writeup.assist"
TODO_MARK_RX = re.compile(r"<!--\s*TODO\b:?[ \t]*(.*?)\s*-->", re.S | re.I)
CATEGORY_RX = re.compile(r"^- Category:[ \t]*(.+?)[ \t]*$", re.M)
REPLY_RX = re.compile(r"^<<<(SECTION|BLOCK)[ \t]+([SD][0-9]{1,3})>>>[ \t]*\n(.*?)^<<<END>>>[ \t]*$",
                      re.M | re.S)
DECLINE_RX = re.compile(r"\A\s*<<<DECLINE>>>")
DATED_RX = re.compile(r"-[0-9]{8}")       # a dated model id: <routed model>-YYYYMMDD
KEEP = "KEEP"
EVIDENCE_MAX = 100_000        # characters of the file itself in one brief
SCRIPT_MAX = 12_000           # characters of one solver script
SCRIPTS_MAX = 30_000          # characters of all scripts together
SKIP_NAMES = frozenset({"STATUS.md", "SOURCE.md", "NEEDS-PLAYER-INPUT.md"})
DRAFT_TEMPLATE = "assist-draft.md.tmpl"
REVIEW_TEMPLATE = "assist-review.md.tmpl"


class AssistError(common.WriteupError):
    """A configuration problem the drafting pass will not guess around (named in the message)."""


class ReplyError(ValueError):
    """The model's reply does not follow the answer format."""


# ------------------------------------------------------------------------------------------ routing

@dataclass(frozen=True)
class Route:
    task: str
    model: str
    pass_: str        # the pass value a block gets when this model wrote it
    why: str


def route(task: str, models: _event.Models) -> Route:
    """The model for a task type. Nothing else picks the model: not the reply, not a decline."""
    primary, docs = models.primary, models.docs
    if task == "writeup":
        return Route(task, docs, primary if docs == primary else passes.PENDING,
                     "writeup prose is drafted on models.docs; it is published, so it gets the review pass")
    if task == "writeup-primary":
        return Route(task, primary, primary, "a models.docs_on_primary category: drafted on models.primary, "
                                             "which is its one pass")
    if task == "retro-recommendations":
        return Route(task, primary, primary, "a retro row that changes a solver's behaviour stays on "
                                             "models.primary")
    if task == "retro-questions":
        return Route(task, docs, primary if docs == primary else passes.NONE,
                     "retro open questions are private and need no review pass")
    if task == "review":
        return Route(task, primary, primary, "the one review pass runs on models.primary")
    raise AssistError(f"unknown assist task {task!r} (one of {', '.join(TASKS)})")


def task_for(rel: str, heading: str, category: str | None, models: _event.Models) -> str:
    """The task type of one TODO slot. In a retro every slot but "Open questions" is a
    retro-recommendations slot and is drafted on models.primary (the retro template has one:
    Recommendations). That is the one primary pass on the rows that change a solver's behaviour,
    taken at drafting time instead of as a docs draft plus a primary review: a review brief carries
    the same evidence as the draft brief, so drafting on the docs model first would add a call and
    save only the recommendation's output tokens (docs/build-log/B-097.md, "Retro cost")."""
    if rel.split("/", 1)[0] == "retro":
        return "retro-questions" if heading.strip().lower().startswith("open questions") \
            else "retro-recommendations"
    wanted = {c.casefold() for c in models.docs_on_primary}
    if category is not None and category.strip().casefold() in wanted:
        return "writeup-primary"
    return "writeup"


# -------------------------------------------------------------------------------------------- slots

@dataclass(frozen=True)
class Slot:
    """One TODO marker: the prose to write under `heading`, as the marker's instruction says."""
    heading: str
    instruction: str
    nth: int            # occurrence of this (heading, instruction) pair in the file
    start: int
    end: int

    @property
    def ident(self) -> tuple[str, str, int]:
        return (self.heading, self.instruction, self.nth)


def _closed_spans(text: str) -> list[tuple[int, int]]:
    """Spans where a TODO marker is not a slot: private blocks (an unclosed opener runs to the end)
    and drafted blocks."""
    spans = [(m.start(), m.end()) for m in _scan.PRIVATE_RX.finditer(text)]
    covered = _scan.PRIVATE_RX.sub(lambda m: " " * len(m.group(0)), text)
    m = _scan.PRIVATE_OPEN_RX.search(covered)
    if m:
        spans.append((m.start(), len(text)))
    found, _ = passes.blocks(text)
    spans += [(b.start, b.end) for b in found]
    return spans


def _headings(text: str) -> list[tuple[int, str]]:
    return [(m.start(), m.group(2).strip()) for m in _scan.HEADING_RX.finditer(text) if len(m.group(1)) >= 2]


def _heading_at(heads: list[tuple[int, str]], offset: int) -> str:
    name = "(top of the file)"
    for pos, h in heads:
        if pos > offset:
            break
        name = h
    return name


def slots(text: str) -> list[Slot]:
    closed = _closed_spans(text)
    heads = _headings(text)
    out: list[Slot] = []
    seen: dict[tuple[str, str], int] = {}
    for m in TODO_MARK_RX.finditer(text):
        if any(a <= m.start() < b for a, b in closed):
            continue
        heading = _heading_at(heads, m.start())
        instruction = " ".join(m.group(1).split()) or "write this section from the evidence"
        n = seen.get((heading, instruction), 0)
        seen[(heading, instruction)] = n + 1
        out.append(Slot(heading, instruction, n, m.start(), m.end()))
    return out


def category_of(text: str) -> str | None:
    closed = _closed_spans(text)
    for m in CATEGORY_RX.finditer(text):
        if not any(a <= m.start() < b for a, b in closed):
            return m.group(1)
    return None


# --------------------------------------------------------------------------------------------- jobs

@dataclass
class Job:
    kind: str                       # "draft" | "review"
    rel: str
    path: Path
    route: Route
    keys: list[str]                 # S1.. (draft) or D1.. (review), in order
    slots: list[Slot] = field(default_factory=list)                     # draft
    blocks: list[tuple[str, str, str, str]] = field(default_factory=list)   # review: (by, task, body, heading)
    brief: str = ""

    @property
    def model(self) -> str:
        return self.route.model

    @property
    def task(self) -> str:
        return self.route.task

    @property
    def brief_sha(self) -> str:
        return common.sha256_text(self.brief)


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    head = limit * 2 // 3
    tail = limit - head
    return f"{text[:head]}\n[... {len(text) - limit} characters cut from the middle ...]\n{text[-tail:]}"


def _scripts(path: Path, staging: Path, scanner: _scan.Scanner) -> str:
    folder = path.parent / "solve"
    if path.name != "README.md" or not folder.is_dir():
        return "_No solver scripts in staging._"
    parts, total = [], 0
    for src in sorted(p for p in folder.rglob("*") if p.is_file() and not p.is_symlink()):
        try:
            body = src.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            parts.append(f"--- {src.relative_to(staging).as_posix()} (binary, not shown) ---")
            continue
        if scanner.policy.redact:
            body, _ = scanner.redact(body)
        body = _clip(body, SCRIPT_MAX)
        if total + len(body) > SCRIPTS_MAX:
            parts.append(f"--- {src.relative_to(staging).as_posix()} (not shown: the brief's script limit) ---")
            continue
        total += len(body)
        parts.append(f"--- {src.relative_to(staging).as_posix()} ---\n{body}")
    return "\n\n".join(parts) or "_No solver scripts in staging._"


def _evidence(text: str, marks: list[tuple[int, int, str]], scanner: _scan.Scanner) -> str:
    """The file with each slot or block replaced by its [[key]] placeholder, redacted when the event
    redacts, clipped to EVIDENCE_MAX."""
    for a, b, key in sorted(marks, reverse=True):
        text = text[:a] + f"[[{key}]]" + text[b:]
    if scanner.policy.redact:
        text, _ = scanner.redact(text)
    return _clip(text, EVIDENCE_MAX)


def _flag_rule(pol: _policy.Policy) -> str:
    if pol.redact:
        why = "this event's rules forbid sharing flags" if pol.sharing_forbidden else "this event redacts flags"
        return (f"Never write a flag value, or any part of one ({why}). Never write a rejected candidate "
                "value either.")
    return "Never write a rejected flag candidate value."


def _audience(rel: str) -> str:
    if rel.split("/", 1)[0] == "retro":
        return "a private retro for the team (never published)"
    return "a public writeup, published after a leak scan and a review pass"


def _draft_brief(profile, rel: str, text: str, chosen: list[tuple[str, Slot]], scanner, staging, path) -> str:
    sections = "\n".join(f"- {k}: under \"{common.cell(s.heading)}\": {s.instruction}" for k, s in chosen)
    fmt = "\n".join(f"<<<SECTION {k}>>>\n(the text for {k})\n<<<END>>>" for k, _ in chosen)
    return common.render(common.load_template(DRAFT_TEMPLATE), {
        "event_name": profile.name, "audience": _audience(rel), "flag_rule": _flag_rule(scanner.policy),
        "sections": sections, "format": fmt, "doc_path": rel,
        "evidence": _evidence(text, [(s.start, s.end, k) for k, s in chosen], scanner),
        "scripts": _scripts(path, staging, scanner),
    })


def _review_brief(profile, rel: str, text: str, chosen: list[tuple[str, passes.Block, str]], scanner,
                  staging, path) -> str:
    listing = "\n\n".join(f"<<<BLOCK {k}>>> (under \"{common.cell(h)}\", drafted by {b.by})\n"
                          f"{b.body(text).strip()}\n<<<END>>>" for k, b, h in chosen)
    fmt = "\n".join(f"<<<BLOCK {k}>>>\n(KEEP, or the corrected text for {k})\n<<<END>>>" for k, _, _ in chosen)
    if scanner.policy.redact:
        listing, _ = scanner.redact(listing)
    return common.render(common.load_template(REVIEW_TEMPLATE), {
        "event_name": profile.name, "audience": _audience(rel), "flag_rule": _flag_rule(scanner.policy),
        "blocks": listing, "format": fmt, "doc_path": rel,
        "evidence": _evidence(text, [(b.start, b.end, k) for k, b, _ in chosen], scanner),
        "scripts": _scripts(path, staging, scanner),
    })


def candidates(staging: Path) -> list[tuple[str, Path]]:
    """Staged markdown files the pass may work on: writeups and retros, not the private records."""
    out = []
    for p in sorted(staging.rglob("*.md")):
        rel = p.relative_to(staging)
        if p.is_symlink() or not p.is_file() or rel.name in SKIP_NAMES \
                or any(part.startswith((".", "_")) for part in rel.parts):
            continue
        out.append((rel.as_posix(), p))
    return out


def _declined_before(records: Iterable[dict], job: Job) -> bool:
    return any(r.get("event") == LEDGER_EVENT and r.get("outcome") == "declined" and r.get("doc") == job.rel
               and r.get("pass_kind") == job.kind and r.get("model") == job.model
               and r.get("brief_sha256") == job.brief_sha for r in records)


def _needs_review(b: passes.Block, models: _event.Models) -> bool:
    """A block the review pass works on: anything the gate blocks except pass=none (private retro
    questions, which a person handles), so a typo or a non-primary pass is reviewed again."""
    return b.pass_.casefold() != passes.NONE and not passes.reviewed(b.pass_, models)


def plan(profile: _event.EventProfile, staging: Path, *, kind: str, scanner: _scan.Scanner,
         records: Iterable[dict] = (), only: list[str] | None = None) -> tuple[list[Job], list[tuple[str, str]]]:
    """The jobs for one pass over staging and the (doc, reason) pairs skipped. kind "draft" writes the
    TODO slots; kind "review" runs the one pass on blocks whose pass is pending."""
    if kind not in ("draft", "review"):
        raise AssistError(f"assist pass kind must be draft or review, got {kind!r}")
    staging = common.guard_dir(staging, "staging folder")
    if not staging.is_dir():
        raise AssistError(f"staging folder {staging} does not exist (run `ctf writeup draft` first)")
    files = candidates(staging)
    if only:
        have = {rel for rel, _ in files}
        unknown = sorted(set(only) - have)
        if unknown:
            raise AssistError(f"not a staged writeup or retro: {', '.join(unknown)} (paths are relative to "
                              f"{staging})")
        files = [(rel, p) for rel, p in files if rel in set(only)]
    records = list(records)
    jobs: list[Job] = []
    skipped: list[tuple[str, str]] = []
    for rel, path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        if kind == "draft":
            groups: dict[str, list[Slot]] = {}
            cat = category_of(text)
            for s in slots(text):
                groups.setdefault(task_for(rel, s.heading, cat, profile.models), []).append(s)
            for task in TASKS:
                if task not in groups:
                    continue
                chosen = [(f"S{i}", s) for i, s in enumerate(groups[task], 1)]
                job = Job("draft", rel, path, route(task, profile.models), [k for k, _ in chosen],
                          slots=[s for _, s in chosen])
                job.brief = _draft_brief(profile, rel, text, chosen, scanner, staging, path)
                jobs.append(job)
        else:
            found, problems = passes.blocks(text)
            if problems:
                skipped.append((rel, f"malformed drafted-text markers ({problems[0][0]}): fix them by hand"))
                continue
            heads = _headings(text)
            pend = [b for b in found if _needs_review(b, profile.models)]
            if not pend:
                continue
            chosen = [(f"D{i}", b, _heading_at(heads, b.start)) for i, b in enumerate(pend, 1)]
            job = Job("review", rel, path, route("review", profile.models), [k for k, _, _ in chosen],
                      blocks=[(b.by, b.task, b.body(text), h) for _, b, h in chosen])
            job.brief = _review_brief(profile, rel, text, chosen, scanner, staging, path)
            jobs.append(job)
    kept = []
    for job in jobs:
        if _declined_before(records, job):
            skipped.append((job.rel, f"{job.task}: declined on {job.model} before with this same brief; not "
                                     "re-sent and never moved to another model: write it by hand"))
        else:
            kept.append(job)
    return kept, skipped


# ------------------------------------------------------------------------------------------- replies

@dataclass
class Reply:
    outcome: str                  # ok | declined | error
    text: str = ""
    model_used: str | None = None
    model_reported: bool = False
    usd: float | None = None
    tok: int | None = None
    detail: str = ""


def _model_used(mu: dict, model: str) -> tuple[str, bool]:
    """(model that ran, reported?) from the CLI's modelUsage. The routed model's own key, or its
    dated form (<model>-YYYYMMDD), is the routed model; otherwise the key with the most output
    tokens. A key that is not a model id (event._MODEL_RE) is not trusted: it would land in a
    marker attribute, so the routed model is named and the ledger says it was not reported."""
    if model in mu or any(isinstance(k, str) and k.startswith(model) and DATED_RX.fullmatch(k[len(model):])
                          for k in mu):
        return model, True
    if not mu:
        return model, False

    def out_tok(k):
        v = mu[k]
        n = v.get("outputTokens", 0) if isinstance(v, dict) else 0
        return n if isinstance(n, (int, float)) and not isinstance(n, bool) else 0
    used = max(sorted(mu, key=str), key=out_tok)
    if not isinstance(used, str) or not _event._MODEL_RE.match(used):
        return model, False
    return used, True


def parse_cli_output(stdout: str, rc: int, model: str) -> Reply:
    """`claude -p --output-format json` -> Reply. Only the result, the stop reason, the model and the
    usage are read; the output is data."""
    d = None
    for cand in (stdout.strip(), *reversed([ln for ln in stdout.splitlines() if ln.strip()])):
        try:
            d = json.loads(cand)
        except ValueError:
            continue
        if isinstance(d, dict):
            break
        d = None
    if d is None:
        return Reply("error", detail=f"claude exited {rc} without a JSON result")
    usage = d.get("usage") if isinstance(d.get("usage"), dict) else {}
    tok = sum(int(v) for k, v in usage.items() if k.endswith("_tokens") and isinstance(v, int)) or None
    usd = d.get("total_cost_usd")
    usd = float(usd) if isinstance(usd, (int, float)) and not isinstance(usd, bool) else None
    mu = d.get("modelUsage") if isinstance(d.get("modelUsage"), dict) else {}
    used, reported = _model_used(mu, model)
    rep = Reply("ok", model_used=used, model_reported=reported, usd=usd, tok=tok)
    stop = str(d.get("stop_reason") or "")
    subtype = str(d.get("subtype") or "")
    if stop == "refusal":
        rep.outcome, rep.detail = "declined", "the model declined (stop_reason refusal)"
        return rep
    if rc != 0 or d.get("is_error") is True or (subtype and subtype != "success"):
        rep.outcome, rep.detail = "error", f"claude exited {rc} ({subtype or 'error'})"
        return rep
    result = d.get("result")
    if not isinstance(result, str):
        rep.outcome, rep.detail = "error", "the JSON result has no text"
        return rep
    rep.text = result
    if DECLINE_RX.match(result):
        rep.outcome, rep.detail = "declined", "the model declined (<<<DECLINE>>>)"
    return rep


def parse_reply(text: str, tag: str, keys: list[str]) -> dict[str, str]:
    """{key: text} from the answer format. Every key exactly once, no other key, none empty."""
    got: dict[str, str] = {}
    for m in REPLY_RX.finditer(text):
        if m.group(1) != tag:
            raise ReplyError(f"answer block <<<{m.group(1)} {m.group(2)}>>> where <<<{tag} ...>>> was asked")
        k = m.group(2)
        if k not in keys:
            raise ReplyError(f"answer for {k}, which was not asked")
        if k in got:
            raise ReplyError(f"two answers for {k}")
        body = m.group(3).strip()
        if not body:
            raise ReplyError(f"empty answer for {k}")
        got[k] = body
    missing = [k for k in keys if k not in got]
    if missing:
        raise ReplyError(f"no answer for {', '.join(missing)}")
    return got


def clean(text: str, scanner: _scan.Scanner) -> str:
    """Model text as it may enter a staged file: no comment markers, redacted when the event redacts."""
    text = common.neutralize(text).strip()
    if scanner.policy.redact:
        text, _ = scanner.redact(text)
    return text


# -------------------------------------------------------------------------------------------- runner

FenceBuilder = Callable[[Path], _fence.Fence]


class ClaudeRunner:
    """Run one brief through `claude -p` on the routed model: the prompt on stdin, no tools
    (`--tools ""`), the filesystem fence's settings (B-219), from an empty scratch folder that is
    removed afterwards. A missing CLI fails at construction, by name."""

    def __init__(self, claude_bin: str = "claude", *, timeout: float = 900.0,
                 fence_builder: FenceBuilder | None = None, which: Callable[[str], str | None] = shutil.which):
        if which(claude_bin) is None:
            raise AssistError(f"claude CLI not found ({claude_bin!r}): install Claude Code or pass --claude-bin")
        self.claude_bin = claude_bin
        self.timeout = timeout
        self.fence_builder = fence_builder or (lambda ws: _fence.build(workspace=ws))

    def argv(self, model: str, settings: Path) -> list[str]:
        return _launch.claude_argv(settings, claude_bin=self.claude_bin,
                                   extra=["-p", "--model", model, "--output-format", "json", "--tools", ""])

    def __call__(self, model: str, prompt: str) -> Reply:
        ws = Path(tempfile.mkdtemp(prefix="ctf-assist-"))
        try:
            settings = _fence.write_claude_settings(self.fence_builder(ws))
            try:
                proc = subprocess.run(self.argv(model, settings), input=prompt, cwd=ws, capture_output=True,
                                      text=True, timeout=self.timeout)
            except subprocess.TimeoutExpired:
                return Reply("error", detail=f"claude timed out after {self.timeout:g} s")
            return parse_cli_output(proc.stdout, proc.returncode, model)
        finally:
            shutil.rmtree(ws, ignore_errors=True)


Runner = Callable[[str, str], Reply]


# ----------------------------------------------------------------------------------------------- run

@dataclass
class Outcome:
    job: Job
    outcome: str          # ok | declined | error | bad-output | changed
    detail: str = ""
    model_used: str | None = None
    usd: float | None = None
    tok: int | None = None

    @property
    def ok(self) -> bool:
        return self.outcome == "ok"


def _pass_for(job: Job, used: str, models: _event.Models) -> str:
    if job.kind == "review":
        return used if passes.reviewed(used, models) else passes.PENDING
    if used == models.primary:
        return models.primary
    return passes.NONE if job.route.pass_ == passes.NONE else passes.PENDING


def _apply_draft(job: Job, answers: dict[str, str], used: str, profile, scanner) -> str | None:
    """Write the answers into the slots. None when a slot is gone (the file changed meanwhile)."""
    text = job.path.read_text(encoding="utf-8", errors="replace")
    now = {s.ident: s for s in slots(text)}
    if any(s.ident not in now for s in job.slots):
        return None
    pass_ = _pass_for(job, used, profile.models)
    for key, s in sorted(zip(job.keys, job.slots), key=lambda ks: now[ks[1].ident].start, reverse=True):
        cur = now[s.ident]
        text = text[:cur.start] + passes.wrap(clean(answers[key], scanner), used, job.task, pass_) + text[cur.end:]
    return text


def _apply_review(job: Job, answers: dict[str, str], used: str, models: _event.Models, scanner) -> str | None:
    text = job.path.read_text(encoding="utf-8", errors="replace")
    found, problems = passes.blocks(text)
    if problems:
        return None
    pend = [b for b in found if _needs_review(b, models)]
    picks = []
    for key, (by, task, body, _h) in zip(job.keys, job.blocks):
        b = next((x for x in pend if x.by == by and x.task == task and x.body(text) == body
                  and x not in [p for _, p in picks]), None)
        if b is None:
            return None
        picks.append((key, b))
    for key, b in sorted(picks, key=lambda kb: kb[1].start, reverse=True):
        ans = answers[key]
        new = b.body(text).strip() if ans.strip() == KEEP else clean(ans, scanner)
        text = text[:b.start] + passes.wrap(new, b.by, b.task, _pass_for(job, used, models)) + text[b.end:]
    return text


def run(profile: _event.EventProfile, staging: Path, workdir: Path, jobs: list[Job], *, runner: Runner,
        scanner: _scan.Scanner) -> list[Outcome]:
    """Run each job once on its routed model, write what came back, record it in the ledger."""
    workdir = Path(workdir)
    if not workdir.is_dir():
        raise AssistError(f"workdir {workdir} does not exist: every model call is recorded in its ledger "
                          "(pass --workdir)")
    common.guard_dir(staging, "staging folder")
    outcomes: list[Outcome] = []
    for job in jobs:
        rep = runner(job.model, job.brief)
        used = rep.model_used or job.model
        out = Outcome(job, rep.outcome, rep.detail, used, rep.usd, rep.tok)
        if rep.outcome == "ok":
            try:
                answers = parse_reply(rep.text, "SECTION" if job.kind == "draft" else "BLOCK", job.keys)
                if job.kind == "draft":
                    new = _apply_draft(job, answers, used, profile, scanner)
                else:
                    new = _apply_review(job, answers, used, profile.models, scanner)
                if new is None:
                    out.outcome, out.detail = "changed", "the file changed while the model ran; run the pass again"
                else:
                    job.path.write_text(new, encoding="utf-8")
            except ReplyError as e:
                if REPLY_RX.search(rep.text) is None:
                    # No answer block at all: a refusal in prose ("I can't help with ..."). It is
                    # recorded as a decline, so the same brief is not sent to the same model again.
                    out.outcome, out.detail = "declined", "the reply has no answer block (a refusal in prose)"
                else:
                    out.outcome, out.detail = "bad-output", f"reply not in the answer format: {e}"
        _ledger.append(LEDGER_EVENT, workdir=workdir, pass_kind=job.kind, doc=job.rel, task=job.task,
                       model=job.model, model_used=used, model_reported=rep.model_reported, outcome=out.outcome,
                       usd=rep.usd, tok=rep.tok, sections=len(job.keys), brief_sha256=job.brief_sha)
        outcomes.append(out)
    return outcomes
