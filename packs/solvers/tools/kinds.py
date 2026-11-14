#!/usr/bin/env python3
"""Answer-kind conformance: is a plain answer of the kind its question asks for?

  python3 tools/kinds.py <attempt dir> [answers.json]    check a saved attempt's key (or a file) offline

The motivating case: a question that asked kind `integer` was answered `ELF64` -- certainly wrong
before it was sent. Catching that here keeps a mis-kinded answer out of a batch.

    problem(value, answer_format) -> None | str
    withhold(questions, answer_ids, answers) -> (kept, held)

`problem` says why a PLAIN answer cannot be right for the question's `answer_format`, or None.
`withhold` splits {answer id: value} into the answers that may be sent and {answer id: reason}
for those that contradict their kind. A caller never sends a held answer: it is printed as
`FORMAT <answer id>: <reason>` and counted as an open id, so a mis-kinded answer costs one answer
instead of the batch it stood in.

The rule is "certainly wrong", never "probably": a check that withholds a right answer costs a
gap on a clock. So
  - only a kind this file knows is checked, and only against what the contract itself says: the
    kind word, `accepted_values`, and the prose of `syntax` where a rule can be read from it
    without doubt (a digit count, a 0x prefix, a stated letter case). Prose it cannot read is no
    rule;
  - an unknown kind, a missing answer_format, an unsure ('??') value and None all pass;
  - `exact_text` is never checked: any text can be right;
  - CTF_KINDS=off in the environment turns every check off (the player's or an owner's
    escape when a contract moves in a way this file misreads).
tests/test_kinds.py holds it to every key.json and accepted verdict saved on disk: none of them
may be withheld.

A held answer is never sent in a batch; a caller that can prove the value another way releases it
deliberately. The check itself only ever reports, and never guesses.

Standard library only; imports nothing of this repo, reads no file (the command line aside).
"""
import json
import os
import re
import sys

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[1]))
    from ctf import env as ctf_env

UNSURE = "??"            # how labels.pick's wire form starts: never a plain answer, never judged here
OFF = "CTF_KINDS"   # =off (or 0, no, false): no check at all
ATTACK = re.compile(r"TA\d{4}|T\d{4}(?:\.\d{3})?")      # a tactic id (TA0002) is an ATT&CK id too
INTEGER = re.compile(r"[+-]?\d+")
HEX = "0-9a-fA-F"


def enabled() -> bool:
    return ctf_env.get(OFF, "").strip().lower() not in ("off", "0", "no", "false")


def _text(value):
    """The answer as it goes on the wire: a string as it is, anything else as compact JSON
    (tools/run.py's serialization). None for a value that is no answer."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, separators=(",", ":"))
    except (TypeError, ValueError):
        return None


def _hex_class(prose: str) -> str:
    """The character class a syntax text asks of its hex digits: a stated case counts only when
    the text does not also say that case is ignored."""
    low = prose.lower()
    if "case is ignored" in low or "case-insensitive" in low or "case insensitive" in low:
        return HEX
    if "uppercase" in low and "lowercase" not in low:
        return "0-9A-F"
    if "lowercase" in low and "uppercase" not in low:
        return "0-9a-f"
    return HEX


def pattern_of(fmt: dict):
    """A compiled pattern for a `pattern` question, or None when none can be read without doubt.
    A `pattern` or `regex` the contract itself gives wins; else the prose forms seen on Days 1 to 8:
      '<N>-character hexadecimal ...' / 'exact <N> hexadecimal characters ...'
      '<PREFIX> followed by exactly <N> uppercase hexadecimal characters'
      '... hexadecimal with a 0x prefix ...'
    Anything else (a slug, a token with free separators) is not checked."""
    for name in ("pattern", "regex"):
        given = fmt.get(name)
        if isinstance(given, str) and given and len(given) <= 400:
            # Whose regex dialect this is, nobody has seen. A /delimited/flags form, an inline
            # flag group or a named group of another dialect is no rule; what compiles is SEARCHED
            # (problem()), never full-matched: an anchored pattern loses nothing by it, and one
            # written without anchors is not read as stricter than its author meant.
            if re.fullmatch(r"/.*/[a-zA-Z]*", given, re.S) or "(?<" in given.replace("(?<=", "").replace("(?<!", ""):
                return None
            if "[:" in given or "\\p{" in given or "\\h" in given:   # POSIX classes, \p{..}, \h: not Python's dialect
                return None
            try:
                return _Given(re.compile(given))
            except (re.error, RecursionError, OverflowError):
                return None
    prose = fmt.get("syntax")
    if not isinstance(prose, str) or "hexadecimal" not in prose.lower():
        return None
    if _ambiguous(prose):
        return None
    cls = _hex_class(prose)
    m = re.search(r"\b([A-Za-z0-9_.-]{1,12}-) followed by exactly (\d{1,3}) (?:uppercase |lowercase )?hexadecimal characters", prose)
    if m and int(m.group(2)) > 0:
        return re.compile(re.escape(m.group(1)) + f"[{cls}]{{{int(m.group(2))}}}")
    low = prose.lower()
    if re.search(r"\bno 0x prefix\b|\bno prefix\b|\buse no prefix\b|\bwithout (?:a |the )?0x\b", low):
        prefix = ""
    elif re.search(r"\bwith a 0x prefix\b|\b0x[- ]prefixed\b", low):
        prefix = "0x"
    else:
        prefix = None
    m = re.search(r"\b(\d{1,3})[- ]character hexadecimal\b|\bexact(?:ly)? (\d{1,3}) hexadecimal characters\b", low)
    if m:
        n = int(m.group(1) or m.group(2))
        if n <= 0:
            return None
        if prefix == "0x":
            # "N-character hexadecimal with a 0x prefix": whether N counts the prefix is not said,
            # so both readings pass.
            counts = f"{{{n}}}" if n <= 2 else f"(?:[{cls}]{{{n}}}|[{cls}]{{{n - 2}}})"
            return re.compile("0x" + (f"[{cls}]{counts}" if n <= 2 else counts))
        if prefix is None:
            # Nothing is said about a prefix: one is not held against the answer.
            return re.compile(f"(?:0x)?[{cls}]{{{n}}}")
        return re.compile(f"[{cls}]{{{n}}}")
    if prefix == "0x":
        return re.compile(f"0x[{cls}]+")
    return None


SEPARATED = re.compile(r"\b(?:colon|dash|hyphen|dot|period|space|comma|pipe|slash|underscore|semicolon|newline)s?[- ](?:separated|delimited)\b|\bseparated by\b|\bgroups? of\b|\bpairs?\b|\boctets?\b")


def _ambiguous(prose: str) -> bool:
    """A syntax text no single hex rule can be read from: it offers alternatives (' or ', two
    different digit counts) or says the digits are written with separators (a MAC, a GUID)."""
    low = prose.lower()
    if re.search(r"\bor\s+(?:an?\s+|exact(?:ly)?\s+)?\d|\bup to\b|\bat least\b|\bat most\b|\bbetween\b", low) or SEPARATED.search(low):
        return True
    counts = set(re.findall(r"\b(\d{1,3})(?=[- ]character|\s+(?:uppercase |lowercase )?hexadecimal)", low))
    return len(counts) > 1


class _Given:
    """A pattern the contract itself supplied: searched, not full-matched (see pattern_of)."""

    def __init__(self, compiled):
        self.compiled, self.pattern = compiled, compiled.pattern

    def fullmatch(self, text):
        return self.compiled.search(text)


MAX_CHECKED = 4096       # a longer answer is not put through a pattern (no rule is worth a slow match on a clock)


def _none_allowed(text: str, low: str) -> bool:
    """The literal `none` is an answer of its own (AGENTS.md: the container was found and the
    member is absent). It contradicts a kind only when the syntax text is there and never
    mentions it; Days 1 to 8 spell the permission 'use the literal none only when ...'."""
    return text.strip().lower() == "none" and (not low or "none" in low)


def problem(value, fmt):
    """Why `value`, a plain answer, cannot be right for a question whose answer_format is `fmt`;
    None when it can (or when nothing certain can be said)."""
    if not isinstance(fmt, dict) or not enabled():
        return None
    kind = fmt.get("kind")
    text = _text(value)
    if text is None or not isinstance(kind, str) or text.lstrip().startswith(UNSURE):
        return None
    kind = kind.strip().lower()
    prose = fmt.get("syntax") if isinstance(fmt.get("syntax"), str) else ""
    low = prose.lower()
    shown = text if len(text) <= 40 else text[:37] + "..."
    if kind != "enum" and _none_allowed(text, low):      # an enum lists its values: none is right only when listed
        return None
    if kind == "integer":
        # 'base-10 integer ...' on every day so far. A syntax that names another base is not read.
        if prose and "base-10" not in low and re.search(r"hex|octal|binary|base-?\d", low):
            return None
        if not INTEGER.fullmatch(text.strip()):
            return f"kind integer, but {shown!r} is not a base-10 integer"
        return None
    if kind in ("number", "float", "decimal"):
        # No day has asked one, so how it is written (separators, a unit, a percent sign, another
        # base) is not known: only a value with no digit in it at all is certainly no number.
        if not re.search(r"\d", text):
            return f"kind {kind}, but {shown!r} is not a number"
        return None
    # `boolean` is not checked: no day has asked one, and which words the judge takes for a truth
    # value (true/false, yes/no, present/absent, 0/1) is not known.
    if kind == "json":
        if isinstance(value, (list, dict)):
            parsed = value
        else:
            try:
                parsed = json.loads(text)
            except ValueError:
                return f"kind json, but {shown!r} does not parse as JSON"
        both = "array" in low and "object" in low      # 'a JSON object or JSON array': either is right
        if not both and re.search(r"\bjson array\b", low) and not isinstance(parsed, list):
            return f"kind json (an array is asked), but {shown!r} is no JSON array"
        if not both and re.search(r"\bjson object\b", low) and not isinstance(parsed, dict):
            return f"kind json (an object is asked), but {shown!r} is no JSON object"
        return None
    if kind == "enum":
        allowed = fmt.get("accepted_values")
        partial = re.search(r"\bsuch as\b|\bfor example\b|\be\.g\.|\bincluding\b|\bexamples?\b|\bor (?:an)?other\b|\betc\b", low)
        if (isinstance(allowed, list) and allowed and not partial
                and all(isinstance(a, (str, int, float)) for a in allowed)):
            names = {str(a).strip().lower() for a in allowed}
            if text.strip().lower() not in names:
                return f"kind enum, but {shown!r} is not one of {len(allowed)} accepted value(s)"
        return None
    if kind == "mitre_attack_id":
        t = text.strip()
        if not ATTACK.fullmatch(t) and t.lower() != "none":
            return f"kind mitre_attack_id, but {shown!r} is neither T####, T####.### nor TA####"
        return None
    if kind == "ordered_tokens":
        sep = ">" if (not prose or "joined by >" in low) else None
        if sep and (text != text.strip() or any(tok != tok.strip() or not tok for tok in text.split(sep))):
            return f"kind ordered_tokens, but {shown!r} has an empty token or spaces around '>'"
        return None
    if kind == "pattern":
        pattern = pattern_of(fmt)
        if pattern is not None and len(text) <= MAX_CHECKED and not pattern.fullmatch(text):
            return f"kind pattern ({pattern.pattern}), but {shown!r} does not match"
        return None
    return None        # exact_text and every kind this file does not know


def withhold(questions, answer_ids, answers) -> tuple:
    """(kept, held): `answers` ({answer id: value}) without the plain answers that contradict
    their question's kind, and {answer id: reason} for those. questions[] and answer_ids[] are
    aligned by position (tools/run.py: answer_ids_for). Never raises: a question that cannot be
    read holds nothing back."""
    kept, held = dict(answers or {}), {}
    if not enabled():
        return kept, held
    try:
        pairs = list(zip(questions or [], answer_ids or []))
    except TypeError:
        return kept, held
    for q, aid in pairs:
        try:
            if aid not in kept or not isinstance(q, dict):
                continue
            why = problem(kept[aid], q.get("answer_format"))
        except Exception:      # a contract shape nobody has seen: no rule
            continue
        if why:
            held[aid] = why
            del kept[aid]
    return kept, held


def of_attempt(attempt, answers) -> tuple:
    """withhold() for an attempt body, from its questions and answer_ids."""
    if not isinstance(attempt, dict):
        return dict(answers or {}), {}
    qs = attempt.get("questions") or []
    ids = attempt.get("answer_ids") or []
    if len(ids) != len(qs):
        ids = [q.get("id") if isinstance(q, dict) else None for q in qs]
    return withhold(qs, ids, answers)


def format_lines(held: dict, limit: int = 40) -> list:
    """`FORMAT <answer id>: <reason>` for each held answer (the first `limit`)."""
    return [f"FORMAT {aid}: {why}" for aid, why in list(held.items())[:limit]]


def main(argv) -> int:
    if not 1 <= len(argv) <= 2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    from pathlib import Path
    folder = Path(argv[0])
    try:
        attempt = json.loads((folder / "attempt.json").read_text())
        source = Path(argv[1]) if len(argv) == 2 else folder / "key.json"
        answers = json.loads(source.read_text())
    except (OSError, ValueError) as e:
        print(f"kinds.py: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    if isinstance(answers, dict) and isinstance(answers.get("answers"), dict):
        answers = answers["answers"]
    kept, held = of_attempt(attempt, answers if isinstance(answers, dict) else {})
    for line in format_lines(held, limit=10 ** 6):
        print(line)
    print(f"KINDS checked={len(kept) + len(held)} held={len(held)}")
    return 1 if held else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
