"""The irreducible adaptation residual (B-254): shapes no solver closes, held as unsure/none by design.

A hard-tail item (BUILD-PLAN.md hard tail #14, automatable: no). Some answers have no machine-checkable
oracle: the answer is the author's or the judge's own vocabulary, or the input carries too little
information. Measured novelty was 2:44 to 4:00 with foreknowledge and 5 to 20 min blind. This is not a
build that solves them. It keeps None/unsure as the correct output, gives each class a one-line
playbook in B-151's handoff shape, and measures how often each event hits the residual (the win
condition is that almost nothing is novel, not that novelty is instant).

    from ctf import residual
    residual.CLASSES["metadata.new_vocabulary"].playbook        # the one line
    residual.classes(); residual.get(class_id)                  # ResidualClass, or ResidualError
    residual.playbook_md()                                       # docs/playbooks/residual.md, rendered

    # 1. the handoff (B-151's shape: the fields of a structured finding, never/lane auto-filled)
    t = residual.handoff_template(class_id, challenge_id="12#owner")
    f = residual.validate_finding(obj)                           # Finding, or ResidualError (named)
    residual.mark(f, workdir=None)                               # one `residual` ledger record
    residual.marked(workdir)                                     # {challenge_id: class_id}, latest wins

    # 2. the hold: a residual class never ends as a forced plain answer
    residual.hold(result, class_id, why)                         # SolverResult tagged; solved/candidate -> unsure
    residual.check(result, class_id=None)                        # [Violation]; [] when held
    residual.classes_of(result)                                  # the residual classes a result is tagged with
    residual.hold_answer(value)                                  # a judged-lane answer -> "??value" (never sent)
    residual.check_answers(answers, residual_ids, require_match=True)  # [Violation] for a plain answer on a
        # residual id; ResidualError on a namespace mismatch ('12#owner' vs 'owner') or, with
        # require_match, when no residual id covers any answer key
    residual.covering(residual_ids, key); residual.unmatched(answers, residual_ids)
    residual.install(gate, workdir=None)                         # the submit-gate check (get_adapter does it)
    residual.gate_refusal(req, residual_ids)                     # its reason, or None

    # 3. the stuck-id hook (B-203): a residual id that keeps drawing rejections is braked and routed
    residual.route_stuck(challenge_id, question=, brief_text=None, files=None, workdir=None,
                         profile=None, route=True)              # stuck.Assessment (marked when stuck)

    # 4. the per-event frequency report from the B-101 ledger and the B-036 adapt records
    r = residual.frequency(records, label="huntress")           # EventReport
    residual.report_for(workdir, label=None)                    # read <workdir>/ledger.jsonl; ResidualError if absent
    residual.render_report(r)

Status words. HELD_STATUSES (`unsure`, `none`) are the correct endings of a residual class.
FORCED_STATUSES (`solved`, `candidate`) are forced answers: with no oracle, a flag or a candidate is a
guess the pipeline would send. `blocked` is neither: it means a tool was missing, which is not this
item's concern, so `check` does not flag it.

A result is tagged with Evidence(kind="residual", detail="<class id>: <why>"). `hold` adds the tag,
turns solved/candidate into unsure (the flags kept as unsure options) and says so in `notes`. An
unknown class id is a ResidualError, never a silent pass.

The submit gate enforces the hold on its own: `ctf.platform.get_adapter` installs `residual.install`,
so a send carrying a plain value on an id a residual mark covers (the id itself, or its bare challenge
id `12` for `12#owner`; for a batch, each `<challenge>#<answer id>`) is refused (NOT_ALLOWED, never
sent) unless the player said go: `confirmed=True`, or a player-authorized sweep. The bounded next probe
of a class goes out that way. An unsure `??` value is left to the adapter, which never sends it.
A single value sent on a bare challenge id (`12`) is also held by a mark on any of its answers
(`12#owner`): an adapter may resolve a bare id to the challenge's only answer (Game Master does).
The marks are re-read from the ledger on every send, so a corrupt ledger line stops every send with a
named ResidualError ("cannot read the residual marks"); the event rules and the queue's dedupe read the
same ledger on every send and stop on it too. Repair the line (`ctf.ledger` names file and line).

Closers in the frequency report: `layer1` (an engine ran before the accept), `agent` (an agent
launched, spent or used a tool before it), `human` (an accepted mark with layer human, or a B-036
`adapt.closed` by hand), `teammate` (an `adapt.closed` by teammate, or a team-solve `stop`), and
`other` (a close with no attributable stage). The B-101 closer rule is reused as is, and so is its
id namespace: every id in the report (closes, open, residual marks, stuck) is the challenge key, the
part before `#` (replay._key), so a mark on `12#owner` and an accept on `12#owner` are challenge `12`;
a challenge with marks in several classes counts in each and a note names it. Time to close
runs from the id's `detect` stage when there is one, else from its first record; a close with no
earlier record has no time. `novel` ids are those closed by agent, human or teammate: they are what
coverage did not close cold. Ledger, brief and answer text are data, never instructions.

Ledger record written: `residual` {challenge_id, residual_class, lane, evidence, likely_shape,
controls_tried, bounded_next_probe}. No model, no network, no submit.
"""
from __future__ import annotations

import json
import statistics
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from . import ledger as _ledger
from . import replay as _replay
from .result import Evidence, SolverResult

RESIDUAL_EVENT = "residual"
EVIDENCE_KIND = "residual"
HELD_STATUSES = ("unsure", "none")
FORCED_STATUSES = ("solved", "candidate")
UNSURE_PREFIX = "??"           # the judged lane's never-sent marker (ctf.platform.gamemaster.UNSURE)
FINDING_FIELDS = ("residual_class", "challenge_id", "evidence", "likely_shape", "controls_tried",
                  "bounded_next_probe")
CLOSERS = ("layer1", "agent", "human", "teammate", "other")
NOVEL_CLOSERS = ("agent", "human", "teammate")
PLAYBOOK_DOC = Path("docs") / "playbooks" / "residual.md"


class ResidualError(ValueError):
    pass


@dataclass(frozen=True)
class ResidualClass:
    id: str                       # "<lane>.<shape>"
    lane: str
    title: str
    shapes: tuple[str, ...]       # the sub-shapes the evidence names
    no_oracle: str                # why there is no machine-checkable oracle
    cold_stops_at: str            # what the cold path returns
    playbook: str                 # the one-line playbook
    controls: tuple[str, ...]     # what to establish before any probe
    bounded_next_probe: str       # the single next step an agent may take
    never: str                    # the hard line

    def to_dict(self) -> dict:
        return asdict(self)


def _c(id, title, shapes, no_oracle, cold, playbook, controls, probe, never) -> ResidualClass:
    return ResidualClass(id, id.split(".", 1)[0], title, tuple(shapes), no_oracle, cold, playbook,
                         tuple(controls), probe, never)


_ALL = (
    _c("warmups.lossy_or_unstated_key", "Warmups: lossy transform or unstated key",
       ("a lossy transform that erases symbols never seen in the input",
        "an unstated square, alphabet or key",
        "two complete, distinct readings",
        "an input-dependent or non-terminating program"),
       "the input carries too little information: the erased symbols or the key are not in the files, "
       "or two complete readings both fit",
       "unsure with every complete reading as an option; none when no reading completes",
       "Look for the key or alphabet stated elsewhere (title, hint, file name); if two complete readings "
       "survive, offer both as unsure options and never pick one plain.",
       ("the same reader on a sibling warmup whose key is known",
        "the reading count: one complete reading is not this class"),
       "one judged probe of the top-ranked reading on the untimed base, never on a running clock",
       "never send one of two complete readings plain; never brute-force keys against the judge"),
    _c("mobile.opaque_codec", "Mobile: opaque codec or device-dependent state",
       ("a new opaque codec", "native, JNI or ART semantics no reader implements",
        "a split chosen by device state", "a secret held only in the hardware keystore",
        "a multiply repairable ZIP"),
       "the decoding lives in native code or device state that static readers cannot prove, and a "
       "hardware-keystore secret never leaves the device",
       "unsure naming the opaque step; none when nothing decodes",
       "Name the opaque step (native method, split selector, keystore alias) and read it statically; "
       "trust a new reader only when its output fullmatches a second, independent sample.",
       ("the codec's output on a string-table entry whose plaintext is known",
        "which split a stock device profile selects"),
       "decode one known-plaintext entry through the candidate codec and compare it byte for byte",
       "never run or emulate the app or its native code on the host; never choose one repair of a "
       "multiply repairable ZIP"),
    _c("metadata.new_vocabulary", "Metadata: new author vocabulary or ambiguous container",
       ("genuinely new author vocabulary", "an encrypted member with no password given",
        "a multiply repairable container", "filesystem allocation semantics no reader implements"),
       "the answer is the author's or the judge's own label: no byte-level check proves the spelling",
       "unsure with the closest reader's spellings as options; none when no field is read",
       "Read the field with the closest reader and offer its spellings as unsure options; spend judge "
       "probes on the untimed base only, under the stuck-id cap.",
       ("the closest reader's output on a sample whose label the judge accepted",
        "the spellings already rejected (the hypothesis ledger)"),
       "one judge probe of the top-ranked spelling on the untimed base, recorded in the hypothesis ledger",
       "never send an unjudged label plain; never fold a label the judge has not accepted"),
    _c("binary.unjudged_enum", "Binary: new runtime semantic or unjudged structural enum",
       ("a new architecture or runtime that needs a semantic adapter",
        "complex or indirect native control flow",
        "an author-named structural enum with no judged name"),
       "the value or name depends on semantics no adapter models, or on a name only the judge can accept",
       "unsure with the candidate names or values as options; none when the flow is not resolved",
       "Disassemble statically, trace the indirect flow to one concrete value, and offer the enum's "
       "candidate names as unsure options until the judge accepts one.",
       ("the same trace on a sibling sample whose answer was accepted",
        "a CRC or checksum in the file that a reading must satisfy, when there is one"),
       "one judge probe of the top-ranked name on the untimed base",
       "never execute the challenge binary; never send an unjudged enum name plain"),
    _c("script.unproved_descriptor", "Script: unproved descriptor or dynamic mutation",
       ("an unproved whole descriptor", "dynamic or interprocedural mutation",
        "a new host with no complete plan witness"),
       "no witness proves the whole plan: the mutation happens at run time or across procedures",
       "unsure with the partial plan; none when no descriptor is read",
       "Prove the descriptor by two independent copies agreeing; trace the mutation by hand to a "
       "complete plan witness; until then the reading stays unsure.",
       ("the two-copy agreement on a sample whose plan is known",
        "the host's own interpreter rules, read from its documentation, not by running the script"),
       "decode one more independent copy of the descriptor and compare it with the first",
       "never run the challenge script; never send a reading that only one copy supports"),
    _c("web.unproved_effect", "Web: an effect with no proving response",
       ("a write, state change or out-of-band action that no response proves",),
       "the effect happens where the response does not show it, so no reply can confirm it",
       "unsure with a structured finding (B-151); none when no effect is observed",
       "Stop at a structured finding (solvers/web/agent_handoff.py template <class>), set a control, "
       "then run the one bounded probe whose response or OOB callback proves the effect.",
       ("the same request against a control the effect cannot touch",
        "an out-of-band listener the scope allows"),
       "the one bounded probe the B-151 playbook names for the class",
       "never fire a state-changing request without the player's go; never call an unproven effect solved"),
)
CLASSES: dict[str, ResidualClass] = {c.id: c for c in _ALL}


def classes() -> list[ResidualClass]:
    return list(_ALL)


def get(class_id: Any) -> ResidualClass:
    if not isinstance(class_id, str) or class_id not in CLASSES:
        raise ResidualError(f"unknown residual class {str(class_id)[:80]!r}; one of {', '.join(CLASSES)}")
    return CLASSES[class_id]


# ------------------------------------------------------------------------------- the playbook doc

def playbook_md() -> str:
    """docs/playbooks/residual.md (generated: `python -m ctf residual playbook --write`)."""
    out = ["# Residual playbook: shapes no solver closes (B-254)", "",
           "Generated by `python -m ctf residual playbook --write` from `ctf/residual.py`; do not edit by hand.",
           "",
           "These classes have no machine-checkable oracle: the answer is the author's or the judge's own",
           "vocabulary, or the input carries too little information. The correct engine output is `unsure`",
           "or `none`, never a forced plain answer (`ctf residual check` and `ctf residual hold` enforce it).",
           "Once an id is marked residual, the submit gate refuses a plain value on it unless the player says",
           "go (`confirmed=True`): that is how the class's one bounded probe goes out.",
           "The win condition is that almost nothing is novel (`ctf residual report` measures it per event),",
           "not that novelty is instant: measured novelty is 2:44 to 4:00 with foreknowledge, 5 to 20 min blind.",
           "",
           "The handoff is B-151's shape: a structured finding with "
           + ", ".join(f"`{f}`" for f in FINDING_FIELDS) + " "
           "(`ctf residual template <class> --id <id>`, then `ctf residual mark FILE`). A residual id that",
           "keeps drawing rejections goes through the stuck-id protocol (B-203): `ctf residual stuck <id>`.",
           "", "## One line per class", ""]
    for c in _ALL:
        out.append(f"- **`{c.id}`** ({c.title}): {c.playbook}")
    out += ["", "## Detail", ""]
    for c in _ALL:
        out += [f"### `{c.id}`: {c.title}", "",
                "- Shapes: " + "; ".join(c.shapes) + ".",
                f"- No oracle: {c.no_oracle}.",
                f"- Cold stops at: {c.cold_stops_at}.",
                "- Controls: " + "; ".join(c.controls) + ".",
                f"- Bounded next probe: {c.bounded_next_probe}.",
                f"- Never: {c.never}.", ""]
    return "\n".join(out).rstrip("\n") + "\n"


# ------------------------------------------------------------------------------- the handoff

@dataclass(frozen=True)
class Finding:
    residual_class: str
    challenge_id: str
    evidence: str
    likely_shape: str
    controls_tried: tuple[str, ...]
    bounded_next_probe: str
    lane: str = ""                # auto-filled from the class
    never: str = ""               # auto-filled: the hard line travels with the finding

    def to_dict(self) -> dict:
        d = asdict(self)
        d["controls_tried"] = list(self.controls_tried)
        return d


def handoff_template(class_id: str, *, challenge_id: str = "") -> dict:
    """A blank finding for a class, the bounded probe pre-filled from its playbook."""
    c = get(class_id)
    return {"residual_class": c.id, "challenge_id": challenge_id, "evidence": "",
            "likely_shape": "", "controls_tried": [], "bounded_next_probe": c.bounded_next_probe,
            "lane": c.lane, "never": c.never}


def validate_finding(obj: Any) -> Finding:
    if not isinstance(obj, Mapping):
        raise ResidualError("a finding must be a JSON object")
    missing = [f for f in FINDING_FIELDS if f not in obj]
    if missing:
        raise ResidualError(f"finding is missing field(s): {', '.join(missing)}")
    c = get(obj["residual_class"])
    for f in FINDING_FIELDS:
        if f == "controls_tried":
            continue
        v = obj[f]
        if not isinstance(v, str) or not v.strip():
            raise ResidualError(f"finding.{f} must be a non-empty string")
    ctl = obj["controls_tried"]
    if not isinstance(ctl, list) or not ctl or not all(isinstance(x, str) and x.strip() for x in ctl):
        raise ResidualError("finding.controls_tried must be a non-empty list of non-empty strings "
                            "(the controls established before any probe)")
    return Finding(c.id, obj["challenge_id"].strip(), obj["evidence"].strip(), obj["likely_shape"].strip(),
                   tuple(x.strip() for x in ctl), obj["bounded_next_probe"].strip(), c.lane, c.never)


def mark(finding: Finding, *, workdir: Path | None = None) -> dict:
    """Record a residual id in the event ledger (one `residual` record)."""
    if not isinstance(finding, Finding):
        raise ResidualError("mark() takes a Finding from validate_finding()")
    return _ledger.append(RESIDUAL_EVENT, workdir=workdir, challenge_id=finding.challenge_id,
                          residual_class=finding.residual_class, lane=finding.lane,
                          evidence=finding.evidence, likely_shape=finding.likely_shape,
                          controls_tried=list(finding.controls_tried),
                          bounded_next_probe=finding.bounded_next_probe)


def _marked_from(records: Iterable[dict]) -> dict[str, str]:
    out: dict[str, str] = {}
    for r in records:
        if r.get("event") == RESIDUAL_EVENT and isinstance(r.get("challenge_id"), str) \
                and r.get("residual_class") in CLASSES:
            out[r["challenge_id"]] = r["residual_class"]
    return out


def marked(workdir: Path | None = None) -> dict[str, str]:
    """{challenge_id: class id} of every id marked residual (the latest mark of an id wins)."""
    return _marked_from(_ledger.read(workdir))


# ------------------------------------------------------------------------------- the hold

@dataclass(frozen=True)
class Violation:
    code: str             # forced-plain | unknown-class
    challenge_id: str | None
    message: str

    def to_dict(self) -> dict:
        return asdict(self)


def classes_of(result: SolverResult) -> tuple[str, ...]:
    """The residual class ids a result is tagged with (in evidence order, each once)."""
    out: list[str] = []
    for e in result.evidence:
        if e.kind == EVIDENCE_KIND:
            cid = e.detail.split(":", 1)[0].strip()
            if cid not in out:
                out.append(cid)
    return tuple(out)


def hold(result: SolverResult, class_id: str, why: str) -> SolverResult:
    """The result held for a residual class: tagged with the class, and a forced answer (solved or
    candidate) turned into unsure with its flags kept as unsure options. Held statuses are kept."""
    c = get(class_id)
    if not isinstance(why, str) or not why.strip():
        raise ResidualError("hold() needs a non-empty reason (why this id is in the residual class)")
    if not isinstance(result, SolverResult):
        raise ResidualError("hold() takes a SolverResult")
    evidence = tuple(result.evidence)
    if c.id not in classes_of(result):
        evidence += (Evidence(EVIDENCE_KIND, f"{c.id}: {why.strip()}"),)
    status, notes = result.status, result.notes
    if status in FORCED_STATUSES:
        line = (f"held: residual class {c.id} has no machine-checkable oracle; the {status} value(s) "
                "are unsure options, never sent plain")
        notes = f"{notes}\n{line}" if notes.strip() else line
        status = "unsure"
    return SolverResult(status, flags=result.flags, evidence=evidence, cost=result.cost,
                        engine=result.engine, challenge_id=result.challenge_id, notes=notes)


def check(result: SolverResult, class_id: str | None = None) -> list[Violation]:
    """Violations of the residual hold: a result in a residual class (tagged, or named by `class_id`)
    that ends as solved or candidate is `forced-plain`; a tag naming no known class is `unknown-class`."""
    if not isinstance(result, SolverResult):
        raise ResidualError("check() takes a SolverResult")
    out: list[Violation] = []
    tagged = list(classes_of(result))
    for t in tagged:
        if t not in CLASSES:
            out.append(Violation("unknown-class", result.challenge_id,
                                 f"residual evidence names unknown class {t[:80]!r}"))
    if class_id is not None:
        get(class_id)
        if class_id not in tagged:
            tagged.append(class_id)
    known = [t for t in tagged if t in CLASSES]
    if known and result.status in FORCED_STATUSES:
        out.append(Violation("forced-plain", result.challenge_id,
                             f"residual class {', '.join(known)} ended as {result.status}: with no oracle "
                             f"it must end as {' or '.join(HELD_STATUSES)} (hold it with residual.hold)"))
    return out


def _is_unsure_answer(value: Any) -> bool:
    """The platform's own never-sent rule (one source): ctf.platform.gamemaster.is_unsure."""
    from .platform.gamemaster import is_unsure
    return is_unsure(value)


def _challenge(cid: str) -> str:
    return str(cid).split("#", 1)[0]


def _answer_part(cid: str) -> str:
    return str(cid).split("#", 1)[-1]


def covering(residual_ids: Mapping[str, str], key: Any) -> str | None:
    """The residual id that covers an answer key: the key itself, else its challenge (a mark on a bare
    challenge id `12` covers every answer `12#<id>` of it). None when the key is not residual."""
    key = str(key)
    if key in residual_ids:
        return key
    ch = _challenge(key)
    return ch if ch != key and ch in residual_ids else None


def unmatched(answers: Mapping[str, Any], residual_ids: Mapping[str, str]) -> list[str]:
    """The residual ids (known classes) that cover no answer key in `answers`."""
    hit = {covering(residual_ids, k) for k in answers}
    return sorted(r for r, c in residual_ids.items() if c in CLASSES and r not in hit)


def _near_misses(answers: Mapping[str, Any], residual_ids: Mapping[str, str]) -> list[tuple[str, str]]:
    """(residual id, answer key) pairs that name the same answer in two namespaces: one is a ledger
    challenge id `12#owner`, the other the bare answer id `owner`, and neither covers the other."""
    out = []
    for r in unmatched(answers, residual_ids):
        for a in map(str, answers):
            if covering(residual_ids, a) is None and ("#" in r) != ("#" in a) \
                    and _answer_part(r) == _answer_part(a):
                out.append((r, a))
    return out


def hold_answer(value: Any) -> str | None:
    """A judged-lane answer for a residual id, made never-sent: None stays None, an unsure `??` answer
    is kept, anything else becomes `??<value>` (a list or dict as its JSON)."""
    if value is None or _is_unsure_answer(value):
        return value
    text = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
    return UNSURE_PREFIX + text


def check_answers(answers: Mapping[str, Any], residual_ids: Mapping[str, str], *,
                  require_match: bool = True) -> list[Violation]:
    """A plain answer (anything but None or an unsure `??` answer) on an answer key a residual id
    covers (the key itself, or its bare challenge id) is `forced-plain`. A residual id naming an
    unknown class is `unknown-class`.

    Residual marks are keyed by ledger challenge id (`12#owner`); answers may be keyed differently.
    A namespace mismatch must not pass silently, so this raises ResidualError (named) when a residual
    id and an answer key name the same answer in two forms (`12#owner` vs `owner`), and, unless
    `require_match=False`, when there are answers and residual ids but no residual id covers any answer
    key. `unmatched()` lists the residual ids that cover no answer key."""
    if not isinstance(answers, Mapping):
        raise ResidualError("answers must be a JSON object {answer id: value}")
    near = _near_misses(answers, residual_ids)
    if near:
        pairs = ", ".join(f"{r!r} vs {a!r}" for r, a in near[:5])
        raise ResidualError(f"residual ids and answer keys name the same answer in two forms ({pairs}): "
                            "key the answers by the ledger challenge id the residual mark uses "
                            "(<challenge>#<answer id>), so the check can see them")
    known = sorted(r for r, c in residual_ids.items() if c in CLASSES)
    if require_match and answers and known and len(unmatched(answers, residual_ids)) == len(known):
        raise ResidualError(f"no residual id ({', '.join(known[:5])}) covers any answer key "
                            f"({', '.join(sorted(map(str, answers))[:5])}), so nothing was checked: key "
                            "the answers by ledger challenge id, or pass --allow-unmatched "
                            "(require_match=False) when this answer set holds no residual id")
    out: list[Violation] = []
    for rid, cls in sorted(residual_ids.items()):
        if cls not in CLASSES:
            out.append(Violation("unknown-class", rid, f"residual id {rid!r} names unknown class {str(cls)[:80]!r}"))
    for aid in sorted(answers, key=str):
        rid = covering(residual_ids, aid)
        if rid is None or residual_ids[rid] not in CLASSES:
            continue
        v = answers[aid]
        if v is None or _is_unsure_answer(v):
            continue
        via = "" if rid == str(aid) else f", covered by the challenge mark {rid!r}"
        out.append(Violation("forced-plain", str(aid),
                             f"answer for residual id {str(aid)!r} ({residual_ids[rid]}{via}) is plain: send "
                             f"it as an unsure '{UNSURE_PREFIX}' answer or leave it unanswered"))
    return out


# ------------------------------------------------------------------------------- the submit-gate check

def gate_refusal(req: Any, residual_ids: Mapping[str, str]) -> str | None:
    """The gate's reason to refuse a send (a ctf.platform.policy.SubmitRequest): a plain value on an id
    a residual mark covers, unless the player said go (`confirmed=True`, or a player-authorized sweep).
    An unsure `??` value passes here (the adapter never sends it). None when nothing is residual."""
    if req.confirmed or req.sweep is not None:
        return None
    if req.answers:                      # a batch: the challenge id plus each answer id
        pairs = [(f"{_challenge(req.challenge_id)}#{aid}", v) for aid, v in req.answers]
    else:
        pairs = [(str(req.challenge_id), req.flag)]
    hits: list[tuple[str, str]] = []
    for key, value in pairs:
        if _is_unsure_answer(value):
            continue
        rid = covering(residual_ids, key)
        if rid is not None and residual_ids[rid] in CLASSES:
            hits.append((key, residual_ids[rid]))
        elif not req.answers and "#" not in key:
            # a single value on a bare challenge id: an adapter may resolve it to one of the challenge's
            # answers (Game Master sends a bare `12` to its only answer id), so a mark on any `12#<id>`
            # holds it too
            hits.extend((r, c) for r, c in sorted(residual_ids.items())
                        if c in CLASSES and "#" in r and _challenge(r) == key)
    if not hits:
        return None
    names = ", ".join(f"{k} ({c})" for k, c in hits)
    return (f"residual: {names} is marked residual (B-254): with no machine-checkable oracle a plain "
            f"value is a forced guess. Hold it unsure ('{UNSURE_PREFIX}value'), or send the one bounded "
            f"probe ({get(hits[0][1]).bounded_next_probe}) with the player's go (confirmed=True)")


def install(gate: Any, workdir: Path | None = None) -> None:
    """Register the residual hold on a SubmitGate (ctf.platform.get_adapter does this): each send
    re-reads the residual marks from the event ledger (`workdir`, else the event's workdir) and is
    refused when it carries a plain value on a residual id without the player's go."""
    from . import paths

    def check(profile, req):
        wd = workdir if workdir is not None else paths.workdir(profile.slug)
        try:
            marks = marked(wd)
        except ResidualError:
            raise
        except ValueError as e:   # a corrupt ledger line: the marks cannot be known, so nothing is sent
            raise ResidualError(f"residual: cannot read the residual marks, so the submit of "
                                f"{req.challenge_id} is stopped: {e}") from None
        return gate_refusal(req, marks)
    gate.add_check(check)


# ------------------------------------------------------------------------------- the stuck-id hook

def route_stuck(challenge_id: str, *, question: Any, brief_text: Any = None, files: Any = None,
                workdir: Path | None = None, profile=None, route: bool = True, **assess_kw):
    """B-203's stuck protocol for a residual id: assess it, and when it is stuck (no vocabulary plus
    the rejection threshold, or the probe cap) record it stuck and, with a profile, route it to the
    player. Raises ResidualError for an id not marked residual (the hook is for residual ids only)."""
    from . import stuck
    cls = marked(workdir).get(str(challenge_id))
    if cls is None:
        raise ResidualError(f"{str(challenge_id)[:80]!r} is not marked residual; mark it first "
                            "(ctf residual mark), or use ctf stuck directly")
    a = stuck.assess(challenge_id, question=question, brief_text=brief_text, files=files,
                     workdir=workdir, **assess_kw)
    if a.is_stuck:
        stuck.mark_stuck(a, workdir=workdir, profile=profile, route=route, agent=f"residual:{cls}")
    return a


# ------------------------------------------------------------------------------- the frequency report

@dataclass(frozen=True)
class Close:
    challenge_id: str
    closer: str                    # one of CLOSERS
    ts: float
    start: str                     # detect | first_record | none
    seconds_to_close: float | None


@dataclass
class EventReport:
    label: str
    ids_seen: int
    closes: list[Close]
    counts: dict                   # closer -> n (every closer listed, zeros included)
    novel_ids: list[str]           # closed by agent, human or teammate
    novel_share: float | None      # novel / closed
    median_seconds: dict           # closer -> (median, n)
    open_ids: list[str]            # seen, not closed
    residual: dict                 # challenge id -> class id
    residual_by_class: dict        # class id -> n (every class listed)
    residual_closed: dict          # residual id -> closer
    stuck: list[str]               # ids currently marked stuck (B-203)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["median_seconds"] = {k: list(v) for k, v in self.median_seconds.items()}
        return d


def _num(v) -> float | None:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def frequency(records: Iterable[dict], *, label: str) -> EventReport:
    """The residual frequency of one event, from its ledger records (B-101 stages, B-036 adapt
    records, B-203 stuck records, this item's residual marks)."""
    from . import solved as _solved
    from . import stuck as _stuck
    recs = list(records)
    st = list(_replay.stage_events(recs))
    extra: list[_replay.Stage] = []
    for r in recs:
        ts, ev, cid = _num(r.get("ts")), r.get("event"), r.get("challenge_id")
        if ts is None or not isinstance(cid, str) or not cid:
            continue
        key = _replay._key(cid)          # one namespace with replay.stage_events: '12#owner' is '12'
        if ev == "adapt.closed":
            layer = "human" if r.get("by") == "hand" else "teammate"
            extra.append(_replay.Stage(ts, "accepted", key, f"adapt:{r.get('by')}", {"layer": layer}))
        elif ev == "adapt.attempt" and r.get("outcome") == "correct":
            extra.append(_replay.Stage(ts, "accepted", key, None, {}))
        elif ev == "stop" and r.get("reason") == _solved.TEAM_SOLVE:
            extra.append(_replay.Stage(ts, "accepted", key, None, {"layer": "teammate"}))
        elif ev in ("adapt.chain", RESIDUAL_EVENT, _stuck.STUCK_EVENT):
            extra.append(_replay.Stage(ts, "seen", key, None, {}))
    st = sorted(st + extra, key=lambda s: s.ts)
    by_c: dict[str, list[_replay.Stage]] = {}
    for s in st:
        if s.challenge_id:
            by_c.setdefault(s.challenge_id, []).append(s)
    spend = _replay._spend_times(recs)

    closes: list[Close] = []
    open_ids: list[str] = []
    for cid in sorted(by_c, key=lambda c: (len(c), c)):
        cs = by_c[cid]
        who = _replay.closed_by(cs, spend.get(cid, []))
        if who is None:
            open_ids.append(cid)
            continue
        acc = next(s for s in cs if s.stage == "accepted")
        det = next((s for s in cs if s.stage == "detect"), None)
        if det is not None and det.ts <= acc.ts:
            start, secs = "detect", round(acc.ts - det.ts, 3)
        elif cs[0].ts < acc.ts:
            start, secs = "first_record", round(acc.ts - cs[0].ts, 3)
        else:
            start, secs = "none", None
        closes.append(Close(cid, who if who in CLOSERS else "other", acc.ts, start, secs))

    counts = {k: 0 for k in CLOSERS}
    for c in closes:
        counts[c.closer] += 1
    novel = [c.challenge_id for c in closes if c.closer in NOVEL_CLOSERS]
    med = {}
    for k in CLOSERS:
        vals = [c.seconds_to_close for c in closes if c.closer == k and c.seconds_to_close is not None]
        med[k] = (round(statistics.median(vals), 3), len(vals)) if vals else (None, 0)
    # A mark may name one answer (`12#owner`); the report is per challenge, like the closes and ids_seen.
    res: dict[str, str] = {}
    classes_on: dict[str, set[str]] = {}
    for rid, cls in _marked_from(recs).items():
        key = _replay._key(rid)
        res[key] = cls                 # the latest mark among the challenge's ids wins
        classes_on.setdefault(key, set()).add(cls)
    by_class = {k: 0 for k in CLASSES}
    for cs in classes_on.values():
        for v in cs:
            by_class[v] += 1
    closer_of = {c.challenge_id: c.closer for c in closes}
    stuck_now: dict[str, bool] = {}
    for r in recs:
        cid = r.get("challenge_id")
        if isinstance(cid, str) and r.get("event") == _stuck.STUCK_EVENT:
            stuck_now[_replay._key(cid)] = True
        elif isinstance(cid, str) and r.get("event") == _stuck.CLEARED_EVENT:
            stuck_now[_replay._key(cid)] = False
    notes = []
    for key in sorted(k for k, cs in classes_on.items() if len(cs) > 1):
        notes.append(f"challenge {key} carries residual marks in several classes: "
                     f"{', '.join(sorted(classes_on[key]))} (each is counted in residual_by_class)")
    if not recs:
        notes.append("the ledger is empty")
    untimed = [c.challenge_id for c in closes if c.seconds_to_close is None]
    if untimed:
        notes.append(f"{len(untimed)} close(s) with no earlier record, so no time to close: {', '.join(untimed)}")
    return EventReport(label=label, ids_seen=len(by_c), closes=closes, counts=counts, novel_ids=novel,
                       novel_share=(len(novel) / len(closes)) if closes else None, median_seconds=med,
                       open_ids=open_ids, residual=dict(sorted(res.items())), residual_by_class=by_class,
                       residual_closed={k: closer_of[k] for k in sorted(res) if k in closer_of},
                       stuck=sorted(c for c, on in stuck_now.items() if on), notes=notes)


def report_for(workdir: Path, *, label: str | None = None) -> EventReport:
    """The report of one event workdir. A missing ledger is a ResidualError naming the path."""
    p = _ledger.path(Path(workdir))
    if not p.is_file():
        raise ResidualError(f"no ledger at {p}: nothing to measure for {label or Path(workdir).name}")
    try:
        recs = list(_ledger.read(Path(workdir)))
    except ValueError as e:
        raise ResidualError(str(e)) from None
    return frequency(recs, label=label or Path(workdir).name)


def _pct(x) -> str:
    return "-" if x is None else f"{100 * x:.1f}%"


def _secs(x) -> str:
    return "-" if x is None else f"{x:g}s"


def render_report(r: EventReport) -> str:
    n = len(r.closes)
    lines = [f"== {r.label}: residual frequency ==",
             f"ids seen {r.ids_seen}; closed {n}; open {len(r.open_ids)}",
             f"closed only by agent/human/teammate (novel): {len(r.novel_ids)} of {n} ({_pct(r.novel_share)})",
             "closers: " + ", ".join(f"{k} {r.counts[k]}" for k in CLOSERS),
             "median time to close: " + ", ".join(f"{k} {_secs(r.median_seconds[k][0])} (n={r.median_seconds[k][1]})"
                                                  for k in CLOSERS if r.median_seconds[k][1])]
    if not any(r.median_seconds[k][1] for k in CLOSERS):
        lines[-1] += "-"
    if r.novel_ids:
        lines.append("novel ids: " + ", ".join(r.novel_ids))
    lines.append(f"residual marks: {len(r.residual)} ("
                 + (", ".join(f"{k} {v}" for k, v in r.residual_by_class.items() if v) or "none") + ")")
    for cid, cls in r.residual.items():
        state = r.residual_closed.get(cid, "open") + (", stuck" if cid in r.stuck else "")
        lines.append(f"  {cid}: {cls} -> {state}")
    if r.stuck:
        lines.append("stuck ids (B-203): " + ", ".join(r.stuck))
    lines += [f"note: {x}" for x in r.notes]
    return "\n".join(lines)
