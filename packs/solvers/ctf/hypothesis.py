"""The per-challenge hypothesis ledger, shared across agents and harnesses (B-181).

A challenge is worked by several agents and harnesses at once (and across sessions). Without a shared
record of what has been tried, work repeats: bit-plane and LSB scans on White Noise ran again despite
"do-not-repeat" prompts, a Codex session re-read its own probes at ~158k tokens of context per call,
and PINK+ subagents rebuilt prior layer state from other sessions. White Noise alone took ~48% of the
PINK+ spend (to_build.json B-181). One false-positive brute hit (a wrong "found it") still pulled a
dedicated agent.

This module is the fix: a machine-readable, append-only ledger **per challenge** that agents query
before executing a method, so an attempt already made (and its result) is read, not re-run.

    from ctf import hypothesis as hyp

    # before running a method, ask whether it is already settled:
    s = hyp.should_skip(cid, "zsteg -a")
    if s.skip:
        print(s.reason)          # "already tried (negative) by agent codex-3"
    else:
        ... run it ...
        hyp.record(cid, hypothesis="LSB in blue channel", method="zsteg -a",
                   result=hyp.NEGATIVE, agent="codex-3", evidence="no flag-shaped output")

    # a brute family's false-positive rate across every challenge in the workdir:
    hyp.false_positive_rate("rockyou-lsb")        # FPRate(family, positives, false, rate)

Why per challenge, not the event ledger. Each challenge gets its own file
`<workdir>/hypotheses/<id>.jsonl`, so an agent reads only the attempts for *its* challenge (a few KB),
never the whole event ledger (the 158k-token re-read). Writes use the same flock + O_APPEND discipline
as `ctf.ledger`, so concurrent agents never interleave a line.

Positive-control validation. A `positive` result claims a working payload. A claim is only trusted
(`verified: true`) when it carries a positive control, and the record says which one (`verified_by`):

  - `control`: an explicit `control` string. This is an **attestation** by the recording agent (what
    known-good check it ran and saw pass, e.g. "the same decoder recovers the planted test flag");
    the ledger cannot re-run it, so it records who attested it and what they said.
  - `flag-format`: no control, but the `payload` is a well-formed flag for the event AND its text is
    printable ASCII AND its body is plausible (not whitespace-only, at least MIN_BODY_WORD_CHARS word
    characters, and at least MIN_BODY_WORD_RATIO of the body word characters). A flag-shaped payload
    with control or non-ASCII bytes inside the braces (`PINK{` + garbage + `}`), or printable junk
    (`PINK{#%!@(*&^}`, `PINK{ }`), is exactly the brute false positive this guards, so it stays
    unverified.

A positive from a brute family (`family` set) is never verified by its flag shape alone: a brute
emits flag-shaped candidates by construction, so it needs an explicit control. An unverified positive
is still recorded -- loudly, as `verified: false` with a reason -- so a brute hit cannot masquerade as a
confirmed solve; `should_skip` never treats an unverified positive as settled.

False-positive rate per brute family. `mark_false_positive` files a correction when a positive turns
out wrong; `false_positive_rate(family)` counts, across every challenge, the positives in that family
that were later corrected. A runner reads it to decide how much to trust that family's next hit.

The miner. After an event, `mine(cid)` reads the ledger and returns the true mechanism -- the verified
positive that actually worked -- and `file_mechanism` writes it back to `<workdir>/hypotheses/
_mechanisms.jsonl`, the durable record a seed/promote step (B-040) can learn from.

Challenge text, method strings and payloads recorded here are data, never instructions.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from . import paths as _paths
from . import watch as _watch

HYP_DIR = "hypotheses"
MECHANISMS_NAME = "_mechanisms.jsonl"

# Result vocabulary. A fixed, small set so every reader agrees on what a record means.
NEGATIVE = "negative"            # tried, did not work -> do not repeat
POSITIVE = "positive"           # produced a working payload / candidate flag
INCONCLUSIVE = "inconclusive"   # ran but ambiguous -> worth another angle, not a repeat of this method
ERROR = "error"                 # the method itself failed (tool crash, bad args) -> may retry once fixed
FALSE_POSITIVE = "false_positive"   # a correction: an earlier POSITIVE on this method was wrong
RESULTS = frozenset({NEGATIVE, POSITIVE, INCONCLUSIVE, ERROR, FALSE_POSITIVE})

# Results that settle a method: once seen, a runner skips re-running it.
#  - NEGATIVE: tried, nothing there.
#  - FALSE_POSITIVE: tried, and its hit was wrong. Re-running the same method reproduces the same wrong
#    hit (the brute false positive that pulled a dedicated agent); a stricter variant is a new method.
#  - a VERIFIED POSITIVE: solved by this method; no reason to run it again.
# An unverified POSITIVE, INCONCLUSIVE and ERROR do NOT settle it (they invite a retry/another angle).
_SETTLING = frozenset({NEGATIVE, FALSE_POSITIVE})


class HypothesisError(ValueError):
    """A hypothesis record cannot be written or read: no challenge id, or a result outside RESULTS."""


# --------------------------------------------------------------------------------------- layout

def hyp_dir(workdir: Path | None = None) -> Path:
    return (_paths.workdir() if workdir is None else Path(workdir)) / HYP_DIR


def path(challenge_id: str, workdir: Path | None = None) -> Path:
    """The ledger file for one challenge: `<workdir>/hypotheses/<safe id>.jsonl`."""
    cid = str(challenge_id)
    if not cid.strip():
        raise HypothesisError("challenge id is required (an empty id has no ledger)")
    return hyp_dir(workdir) / f"{_watch.safe_id(cid)}.jsonl"


def mechanisms_path(workdir: Path | None = None) -> Path:
    return hyp_dir(workdir) / MECHANISMS_NAME


# --------------------------------------------------------------------------------------- method keys

_WS = re.compile(r"\s+")


def normalize_method(method: str) -> str:
    """The dedupe key for a method string: lower-cased, whitespace collapsed, stripped. `zsteg  -a`
    and `ZSTEG -a` share a key, so the same probe written two ways is still one method."""
    m = _WS.sub(" ", str(method).strip().lower())
    if not m:
        raise HypothesisError("method is required (an empty method has no key)")
    return m


# ---------------------------------------------------------------------------------- positive control

VERIFIED_BY_CONTROL = "control"          # an explicit control string: the recording agent's attestation
VERIFIED_BY_FLAG = "flag-format"         # a printable, well-formed flag payload (non-brute methods only)


@dataclass(frozen=True)
class Control:
    verified: bool
    reason: str
    by: str | None = None        # VERIFIED_BY_CONTROL | VERIFIED_BY_FLAG when verified, else None


def _printable_ascii(s: str) -> bool:
    return s.isascii() and s.isprintable()


# Body plausibility for a flag-format verification. Event bodies such as pink's `[^{}\n]{1,256}` accept
# any printable junk, so a brute's `PINK{#%!@(*&^}` or `PINK{ }` would otherwise verify by shape. Real
# flag bodies are words, leet, hex or underscores: mostly [A-Za-z0-9_].
MIN_BODY_WORD_CHARS = 3
MIN_BODY_WORD_RATIO = 0.5
_WORD_CHAR = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


def flag_body(flag: str) -> str:
    """The text between the first `{` and the closing `}` of a flag-shaped string (the whole stripped
    string when it has no braces)."""
    t = flag.strip()
    i = t.find("{")
    return t[i + 1:-1] if i >= 0 and t.endswith("}") else t


def body_implausible(flag: str) -> str | None:
    """None when the flag body reads like a flag, else why not: too few word characters (this covers
    an empty or whitespace-only body) or mostly symbols."""
    body = flag_body(flag)
    words = sum(ch in _WORD_CHAR for ch in body)
    if words < MIN_BODY_WORD_CHARS:
        return f"the flag body has {words} word character(s), under {MIN_BODY_WORD_CHARS}"
    if words / len(body) < MIN_BODY_WORD_RATIO:
        return (f"the flag body is mostly symbols ({words}/{len(body)} word characters, under "
                f"{MIN_BODY_WORD_RATIO:.0%})")
    return None


def validate_positive(payload: str | None, control: str | None, *, profile=None,
                      family: str | None = None) -> Control:
    """Whether a POSITIVE carries a positive control.

    Trusted when an explicit `control` is given (an attestation: the known-good check the agent says
    it ran and saw pass; recorded as such, not re-run), or -- for a method outside any brute family --
    when `payload` is a well-formed flag for the event whose text is printable ASCII and whose body is
    plausible (`body_implausible` returns None). A brute-family hit
    (`family` set) needs the explicit control: a brute emits flag-shaped candidates by construction.
    Otherwise unverified, with a named reason -- never silently trusted."""
    if control and str(control).strip():
        return Control(True, f"control (attested): {str(control).strip()}", VERIFIED_BY_CONTROL)
    pl = (payload or "").strip()
    if not pl:
        return Control(False, "no control and no payload to check against the flag format")
    if family is not None and str(family).strip():
        return Control(False, f"brute-family ({str(family).strip()}) hit with no control: a flag-shaped "
                              "payload alone does not verify a brute; give a control (possible false "
                              "positive)")
    from . import flagfmt as _flagfmt
    try:
        ok = _flagfmt.for_profile(profile).is_flag(pl) if profile is not None else _flagfmt.is_flag(pl)
    except Exception as e:  # no resolvable event (EventError) or a bad profile: cannot validate here
        return Control(False, f"no control and the flag format is unavailable to check the payload ({e})")
    if not ok:
        return Control(False, "no control and the payload is not a well-formed flag (possible false positive)")
    if not _printable_ascii(pl):
        return Control(False, "no control and the payload is flag-shaped but holds non-printable or "
                              "non-ASCII characters (brute garbage, possible false positive)")
    why = body_implausible(pl)
    if why is not None:
        return Control(False, f"no control and the payload is flag-shaped but implausible: {why} "
                              "(possible false positive)")
    return Control(True, "payload is a well-formed, printable, plausible flag", VERIFIED_BY_FLAG)


# ------------------------------------------------------------------------------------------ writing

def _append(p: Path, rec: dict) -> None:
    line = (json.dumps(rec, default=str, separators=(",", ":")) + "\n").encode("utf-8")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.write(fd, line)
    finally:
        os.close(fd)


def record(challenge_id: str, *, hypothesis: str, method: str, result: str,
           payload: str | None = None, family: str | None = None, agent: str | None = None,
           evidence: str = "", control: str | None = None,
           workdir: Path | None = None, profile=None) -> dict:
    """Append one attempt to a challenge's ledger and return the written record.

    `result` is one of RESULTS. On POSITIVE the positive control is run and the record carries
    `verified` (and a `verify_reason`); an unverified positive is written, not rejected. `method` is
    stored verbatim and as a normalized `method_key` for dedupe. `agent` names who ran it (default
    "unknown"). Raises HypothesisError on an empty id, empty method, or a result outside RESULTS."""
    cid = str(challenge_id)
    if not cid.strip():
        raise HypothesisError("challenge id is required")
    if result not in RESULTS:
        raise HypothesisError(f"result {result!r} not in {sorted(RESULTS)}")
    key = normalize_method(method)
    rec: dict[str, Any] = {
        "ts": time.time(),
        "challenge_id": cid,
        "hypothesis": str(hypothesis),
        "method": str(method),
        "method_key": key,
        "result": result,
        "payload": None if payload is None else str(payload),
        "family": None if family is None else str(family),
        "agent": str(agent) if agent else "unknown",
        "evidence": str(evidence),
        "control": None if control is None else str(control),
    }
    if result == POSITIVE:
        c = validate_positive(payload, control, profile=profile, family=family)
        rec["verified"] = c.verified
        rec["verified_by"] = c.by
        rec["verify_reason"] = c.reason
    else:
        rec["verified"] = False
    _append(path(cid, workdir), rec)
    return rec


def mark_false_positive(challenge_id: str, method: str, *, agent: str | None = None,
                        evidence: str = "", workdir: Path | None = None) -> dict:
    """File a correction: an earlier POSITIVE on this method was wrong. The correction carries the
    hypothesis and brute family of the latest POSITIVE it corrects (not of whatever record came last,
    e.g. a later negative with no family), so the family's false-positive rate counts it. Raises
    HypothesisError when no positive for that method exists (nothing to correct -- loud, never a
    silent no-op)."""
    key = normalize_method(method)
    positives = [r for r in read(challenge_id, workdir)
                 if r.get("method_key") == key and r.get("result") == POSITIVE]
    if not positives:
        raise HypothesisError(
            f"no positive on method {method!r} for challenge {challenge_id} to mark false")
    corrected = positives[-1]
    return record(challenge_id, hypothesis=corrected.get("hypothesis", ""), method=method,
                  result=FALSE_POSITIVE, family=corrected.get("family"),
                  agent=agent, evidence=evidence, workdir=workdir)


# ------------------------------------------------------------------------------------------ reading

def read(challenge_id: str, workdir: Path | None = None) -> Iterator[dict]:
    """Every attempt recorded for a challenge, in write order. Raises HypothesisError on a corrupt
    line (never a silent skip)."""
    p = path(challenge_id, workdir)
    if not p.exists():
        return
    with open(p, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if line.strip():
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as e:
                    raise HypothesisError(f"{p}:{n}: corrupt hypothesis line: {e}") from None


def entries(challenge_id: str, workdir: Path | None = None) -> list[dict]:
    return list(read(challenge_id, workdir))


def latest_by_method(challenge_id: str, workdir: Path | None = None) -> dict[str, dict]:
    """The last record for each method key (so a FALSE_POSITIVE after a POSITIVE wins, and a later
    retry's result is what stands)."""
    out: dict[str, dict] = {}
    for r in read(challenge_id, workdir):
        k = r.get("method_key")
        if k is not None:
            out[k] = r
    return out


def seen(challenge_id: str, method: str, workdir: Path | None = None) -> dict | None:
    """The latest record for this method on this challenge, or None if the method was never tried."""
    return latest_by_method(challenge_id, workdir).get(normalize_method(method))


def methods_tried(challenge_id: str, workdir: Path | None = None) -> dict[str, str]:
    """{method_key: latest result} -- a compact view of what has been attempted."""
    return {k: r.get("result") for k, r in latest_by_method(challenge_id, workdir).items()}


@dataclass(frozen=True)
class Skip:
    skip: bool
    reason: str
    prior: dict | None


def should_skip(challenge_id: str, method: str, workdir: Path | None = None) -> Skip:
    """Whether a runner should skip executing `method` because it is already settled. A NEGATIVE, a
    FALSE_POSITIVE (its hit was wrong; re-running reproduces it) or a VERIFIED POSITIVE settles it; an
    unverified positive, INCONCLUSIVE, ERROR or never-tried does not.
    This is the query an agent/harness runs before executing a probe."""
    prior = seen(challenge_id, method, workdir)
    if prior is None:
        return Skip(False, "not tried yet", None)
    res = prior.get("result")
    who = prior.get("agent", "unknown")
    if res in _SETTLING:
        return Skip(True, f"already tried ({res}) by {who}", prior)
    if res == POSITIVE and prior.get("verified"):
        how = prior.get("verified_by") or "verified"
        return Skip(True, f"already solved by this method (verified positive, by {how}) by {who}", prior)
    if res == POSITIVE:
        return Skip(False, f"positive by {who} but unverified ({prior.get('verify_reason','')}) -- "
                           "re-run to confirm", prior)
    return Skip(False, f"last result {res} by {who} -- worth another attempt", prior)


# -------------------------------------------------------------------------- false-positive rate

@dataclass(frozen=True)
class FPRate:
    family: str
    positives: int          # distinct (challenge, method) that ever went positive in this family
    false_positives: int    # of those, how many were later corrected
    rate: float | None      # false / positives, or None when the family has no positives yet


def _all_challenge_files(workdir: Path | None = None) -> list[Path]:
    d = hyp_dir(workdir)
    if not d.is_dir():
        return []
    return sorted(p for p in d.glob("*.jsonl") if p.name != MECHANISMS_NAME)


def _read_file(p: Path) -> Iterator[dict]:
    with open(p, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if line.strip():
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as e:
                    raise HypothesisError(f"{p}:{n}: corrupt hypothesis line: {e}") from None


def _family_counts(workdir: Path | None = None) -> dict[str, tuple[set, set]]:
    """{family: (positive_keys, false_keys)} across every challenge, keyed by (file stem, method key)."""
    acc: dict[str, tuple[set, set]] = {}
    for p in _all_challenge_files(workdir):
        for r in _read_file(p):
            fam = r.get("family")
            if not fam:
                continue
            pos, false = acc.setdefault(fam, (set(), set()))
            ident = (p.stem, r.get("method_key"))
            if r.get("result") == POSITIVE:
                pos.add(ident)
            elif r.get("result") == FALSE_POSITIVE:
                false.add(ident)
    return acc


def false_positive_rate(family: str, workdir: Path | None = None) -> FPRate:
    """How often this brute family's positives turned out false, across every challenge in the
    workdir. A family with no positives yet reports rate=None (no data), never 0.0."""
    pos, false = _family_counts(workdir).get(family, (set(), set()))
    confirmed_false = pos & false  # only count a false on a method that actually went positive
    n = len(pos)
    return FPRate(family, n, len(confirmed_false), (len(confirmed_false) / n) if n else None)


def families(workdir: Path | None = None) -> list[FPRate]:
    """The false-positive rate of every brute family seen, worst (highest rate) first."""
    out = [false_positive_rate(fam, workdir) for fam in _family_counts(workdir)]
    return sorted(out, key=lambda r: (-(r.rate if r.rate is not None else -1.0), r.family))


# ----------------------------------------------------------------------------------- the miner

@dataclass(frozen=True)
class Mechanism:
    challenge_id: str
    hypothesis: str
    method: str
    payload: str | None
    family: str | None
    agent: str
    verified_by: str | None = None   # "control" (an attestation) | "flag-format"


def mine(challenge_id: str, workdir: Path | None = None) -> Mechanism | None:
    """The true mechanism for a challenge: the latest VERIFIED positive that is not later corrected.
    A `false_positive` corrects only the positives on its method recorded BEFORE it: a verified
    positive on the same method recorded after the correction (a re-run with a real control) stands.
    None when the ledger holds no verified, uncorrected positive (nothing proven to file back)."""
    standing: list[dict] = []           # verified positives not (yet) corrected, in write order
    for r in read(challenge_id, workdir):
        res = r.get("result")
        if res == FALSE_POSITIVE:
            k = r.get("method_key")
            standing = [p for p in standing if p.get("method_key") != k]
        elif res == POSITIVE and r.get("verified"):
            standing.append(r)
    if not standing:
        return None
    winner = standing[-1]
    return Mechanism(str(challenge_id), winner.get("hypothesis", ""), winner.get("method", ""),
                     winner.get("payload"), winner.get("family"), winner.get("agent", "unknown"),
                     winner.get("verified_by"))


def mine_all(workdir: Path | None = None) -> list[Mechanism]:
    """One mechanism per challenge that has a verified positive, in challenge-file order."""
    out = []
    for p in _all_challenge_files(workdir):
        # the challenge id is on the records, not the (possibly hashed) file name
        recs = list(_read_file(p))
        if not recs:
            continue
        cid = str(recs[0].get("challenge_id"))
        m = mine(cid, workdir)
        if m is not None:
            out.append(m)
    return out


def file_mechanism(mech: Mechanism, workdir: Path | None = None) -> dict:
    """Write a mined mechanism back to `<workdir>/hypotheses/_mechanisms.jsonl`, the durable record a
    seed/promote step learns from. Returns the written record."""
    rec = {
        "ts": time.time(),
        "challenge_id": mech.challenge_id,
        "hypothesis": mech.hypothesis,
        "method": mech.method,
        "payload": mech.payload,
        "family": mech.family,
        "agent": mech.agent,
        "verified_by": mech.verified_by,
    }
    _append(mechanisms_path(workdir), rec)
    return rec


def mechanisms(workdir: Path | None = None) -> list[dict]:
    """Every mechanism filed back so far."""
    p = mechanisms_path(workdir)
    if not p.exists():
        return []
    return list(_read_file(p))
