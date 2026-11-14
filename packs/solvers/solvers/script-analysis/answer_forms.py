#!/usr/bin/env python3
"""The form an answer format asks, held against a PLAIN answer (built 2026-10-13 for Day 14; the Script
counterpart of Metadata's `FORM <id>` demotion, backlog row 280).

A module answers a judged fact in the spelling the judge took on the days it was judged. When a later day's
`answer_format` certainly asks ANOTHER form of the same fact, that plain answer would be sent and rejected,
and one rejected answer costs the whole batch. `demote(qs, got, skip=...)` is asked once about a whole
delivery (the end of analyze.solve_set; the ids day_patch.py named are skipped, so the patch keeps the last
word) and only ever turns a plain answer into an unsure one. It never withdraws an answer, never makes one
plain, never touches an unsure answer or a None, and demotes nothing at all when the demotion would be broad
(more than MAX_KEYS keys or MAX_IDS ids: one NOTE line).

  enum       the question lists its accepted values and the plain answer is none of them as written, but is
             exactly one of them when letter case (or `-`, `_` and blanks) is left out of the comparison:
             unsure, the LISTED spelling first, the module's own second. One key a transform
             (`script.enum_form/case`, `script.enum_form/separator`), so one base probe settles every id.
  syntax     the syntax text's FIRST clause (up to the first `;`, `:`, `.`, `(` or line end, without the lane's
             house tail `, without quotes or explanatory text ...`) states the form of the asked value itself,
             in one of these shapes and no other (`exact` and `artifact-derived` may stand in front, ` only`
             behind; `converted to lowercase` reads as `in lower case`):
               lowercase <noun> ...  |  [the] <noun> [identifier|id] in lower case      a value with capitals
               uppercase <noun> ...  |  [the] <noun> [identifier|id] in upper case      a value with small letters
               [the] parent technique [id] only ...                                     a value with a sub-technique
               [the] defanged url|link|address|value ... | the url defanged ...         a URL written plainly
                 (followed by its description: `with hxxps and [.]`, `as ..`, `using ..`)
               [the] [file] path with forward slashes [only]                            a value with a backslash
               [a] json string  (kind json)                                             a value that is no JSON text
             where <noun> names the id's own field (technique or attack for `-attack`, campaign for
             `-campaign`, url for `-url`, path for `-path`, ...) or is `value` or `answer`.
             Unsure under `script.form/<field>.<form>`, the fitting form first, the judged form second.

What it does NOT read, on purpose (review of 2026-10-13: eight ordinary syntax texts demoted 7 to 516 right
answers each, and one withdrew 92): a form word anywhere but the first clause (an added sentence, an example,
"use the lowercase literal none", "hexadecimal digests are lowercase", "booleans are lowercase true or false");
a form word about another noun than the id's field; a clause that holds a negation or a condition (not,
n't, never, no, without, unless, except, if, keep, preserve, unchanged, as is, as written, verbatim); and
"no sub-technique" and "without the sub-technique" as negation-worded wordings of the parent-only form. Each of
those leaves the plain answer as it is.

wave13 (finale rehearsal, 2026-10-25). The rehearsal found three wrong-plain shapes this file still missed, each
a correctly-read value asked in a form the solver did not apply, and each now read (the STATED form where it is
rule-derivable, else unsure; never a wrong plain):
  (a) a case form stated AFTER the field noun by a comma, a bare blank or the `-ed` participle
      (`campaign identifier, lowercase`, `value, lowercased`): CASE_BACK no longer demands `in`/`converted to`.
  (b) a count asked spelled as a word (`stage count spelled out`, `number of steps, in words`): the digit value
      is offered as English words FIRST and unsure (COUNT_WORD, _int_to_words); the author's hyphenation and case
      are not knowable, so it is never sent plain.
  (c) the technique NAME asked in place of its ID (`the MITRE ATT&CK technique name`, `the technique name, not
      the ID`): no rule derives the name, so the `T####[.###]` value is demoted to unsure (held out of every
      batch) rather than left plain. A clause that asks the ID and merely excludes the name
      (`technique ID, not the technique name`) is left alone, so its correct ID answer stands
      (_wants_technique_name, CONTRAST).

On the thirteen saved bases and every saved timed variant it changes no answer
(tests/test_day14_script_lookahead.py: forms, forms_saved). One stderr line per changed id: `FORM <id>`.
CTF_SCRIPT_FORMS=off turns it off.

Day 18 look-ahead (2026-10-17, B1; docs/retro/day-18-predictions-script.md, section 5). Staged on the real Day
17 base, 16 of 26 form wordings sent 1,089 plain answers in the old form, because:
  - every exact_text syntax of this lane ends in the house tail `, without quotes or explanatory text unless
    quotes are part of the value`, and the NEGATION guard read its `without` and `unless` as a condition on the
    form. The tail (HOUSE_TAIL, also its shorter forms) is taken off the first clause before anything is read:
    it negates quotes and prose, never the form;
  - ` only` after the stated form, the house adjective `artifact-derived` in front of its noun, `converted to
    lowercase` for `in lower case`, and a defanged url followed by its own description (`with hxxps and [.]`,
    `as hxxps`, `using`) were not in the shapes;
  - MAX_IDS held one field's form of more than 100 ids (105 adapter ids, one key) as "the shared sentence". The
    id limit now holds only when a demotion spans two or more keys; MAX_KEYS is as it was.
It still only demotes. Staged: 1,089 WRONG to 150 (left then, now read by wave13: "campaign identifier,
lowercase", the case form after a comma; still left: the two negation-worded parent-only wordings); every
saved Script base and timed variant of Days 1-17 with a key (55,179 answers) is as it was
(tests/test_day18_script.py)."""
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
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env

try:
    import labels
except Exception:  # noqa: BLE001 - without the ledger nothing can be offered unsure: nothing is changed
    labels = None

CLAUSE_END = re.compile(r"[;:(\n]|\.(?:\s|$)")
# The lane's house tail (B1): every exact_text syntax of Days 1-17 ends in it. It speaks of quotes and prose,
# not of the form, and is taken off the first clause before the negation guard reads it.
HOUSE_TAIL = re.compile(r",?\s*(?:and\s+)?without quotes(?: or explanatory text)?(?: unless quotes are part of the value)?\s*$")
NEGATION = re.compile(r"\b(?:not|never|no|without|unless|except|if|keep\w*|preserv\w*|unchanged|verbatim|as[- ]is|as (?:written|stored|found|given|it appears))\b|n't")
# The breadth of one delivery's demotion. A form asked of one field is one key and that field's ids (the six
# staged cases: 4 to 92 ids, one key each). A form that touches more than this is the shared generic sentence
# stating a form of everything ("uppercase value ..."): 516 ids over 25 keys in the review, more probes than a
# run has. Then nothing is demoted, one NOTE line says so, and a plain batch the judge rejects is split by
# verify.py as it is today.
MAX_KEYS = 6
MAX_IDS = 100
# The nouns that name an id's own field, by the last word of the id. `value` and `answer` name any field.
NOUNS = {"attack": ("technique", "attack", "att&ck technique", "mitre att&ck technique", "mitre technique"),
         "technique": ("technique", "attack", "att&ck technique", "mitre att&ck technique", "mitre technique"),
         "campaign": ("campaign",), "url": ("url", "link", "address"), "path": ("path", "file path"),
         "role": ("role",), "adapter": ("adapter",), "language": ("language",), "profile": ("profile",)}
ANY = ("value", "answer")
END = r"(?:$|,| such as\b| like\b| for example\b| e\.g| only\b)"     # what may follow the stated form in its clause
ADJ = r"(?:artifact[- ]derived )?"          # the house adjective in front of the noun (B1)
CASE_FRONT = r"(?:the |a |an |exact )?" + ADJ + r"(?:all[- ])?{case}[- ]?cased? (?:{nouns})(?: identifier| id| name| value)?" + END
# wave13 (finale rehearsal, 2026-10-25): the case form stated AFTER the field noun is read whether a comma, a
# bare blank, `in`/`converted to`, or the `-ed` participle (`lowercased`) joins it. The old CASE_BACK required
# `in` or `converted to`, so `campaign identifier, lowercase` and `value, lowercased` -- a correctly-read value
# in the wrong case -- went PLAIN and sank the batch. The `case`/`cased` anchor keeps `lower bound`,
# `lower-level`, `role, loader` and the like out; the noun is still the id's OWN field (or `value`/`answer`),
# so a case word about another noun demotes nothing, as before.
CASE_BACK = (r"(?:the |a |an |exact )?" + ADJ + r"(?:{nouns})(?: identifier| id| name| value)?,?\s+"
             r"(?:(?:written |given |spelled )?in |converted to )?(?:all[- ])?{case}[- ]?cased?" + END)
# wave12 (nw-script hardening, 2026-10-24): the id's own form word, found ANYWHERE in the first clause
# (searched, not anchored at the start or the end). The old anchored patterns missed the form after the
# field noun or after an `exact`/`the` lead -- `url indicator, defanged`, `the url indicator, defanged`,
# `exact file_path indicator with forward slashes`, `the file path, using forward slashes`,
# `ATT&CK technique, parent only` -- and sent the judged rendering PLAIN, a wrong plain that sinks the
# batch. Each still fires in syntax_form ONLY when the VALUE itself admits the transformation (a fanged
# http(s) url, a backslash path, a sub-technique id), so a clause that merely names the word demotes
# nothing; a negation or condition in the clause has already stopped it at _asks (`no sub-technique`,
# `without the sub-technique suffix` stay excluded on purpose, as does the comma case form of a campaign).
# The defang word must be bound to the field noun (`defanged url [indicator]`, or `url [indicator], defanged`)
# and be followed by a boundary or its own description, so `defanged address of the relay host only where
# stated` (the form word about ANOTHER noun) and a conditional phrasing demote nothing, as before. Searched,
# not anchored, so an `exact`/`the` lead or an adjective in front (`exact synthetic url indicator, defanged`)
# does not hide it.
DEFANGED = re.compile(r"(?:defanged (?:url|link|address|value)(?: indicator| value| id| identifier| name)?"
                      r"|(?:url|link|address|value)(?: indicator| value| id| identifier| name)?,? +defanged)"
                      r"(?:$|,| only\b| such as\b| like\b| for example\b| e\.g| with\b| as\b| using\b)")
SLASHES = re.compile(r"forward[- ]?slash")
JSON_STRING = re.compile(r"(?:a |one |compact )?json string" + END)
# wave13 (finale rehearsal, 2026-10-25): a count asked "spelled as a word" / "in words" etc. The form word a
# digit value is asked in; COUNT_WORD is the tight phrase that means "render the number as English words", and
# it fires in syntax_form only when the VALUE itself is all digits, so a clause that merely names the word
# demotes nothing. `as it appears`, `as written` etc. are already a NEGATION, so a verbatim phrasing is excluded.
COUNT_WORD = re.compile(r"\b(?:spelled out|spelled as (?:a |an )?word|spelled in words|written out|"
                        r"in words|as (?:a |an )?word|in english(?: words?)?|word form|number word)\b")
# wave13: a `name ... not ... id` / `id ... not ... name` contrast; group 1 is the REQUESTED noun, group 2 the
# excluded one, so `technique ID, not the technique name` asks the ID (group1=id) and `the technique name, not
# the ID` asks the name (group1=name). Used by _wants_technique_name.
CONTRAST = re.compile(r"\b(name|id|identifier)\b[^.;:(]*?\b(?:not|instead of|rather than|in place of)\b"
                      r"[^.;:(]*?\b(name|id|identifier)\b")
TECH_WORD = re.compile(r"\b(?:technique|att&ck|attack|mitre)\b")
WORDS = re.compile(r"lower|upper|parent|defang|forward slash|json string|"
                   r"spelled|in words|as a word|written out|word form|in english|number word")
_ASKS = {}
_ONES = ("zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen "
         "seventeen eighteen nineteen").split()
_TENS = ("", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety")


def _int_to_words(n: int):
    """A non-negative integer up to 999,999 as lowercase English words (`21` -> `twenty-one`), else None. Only
    EVER an unsure option: how the author hyphenates or capitalises a spelled number is not knowable, so the
    word form is offered unsure with the digit behind it, never sent plain."""
    if not isinstance(n, int) or n < 0 or n > 999999:
        return None
    if n < 20:
        return _ONES[n]
    if n < 100:
        return _TENS[n // 10] + ("" if n % 10 == 0 else "-" + _ONES[n % 10])
    if n < 1000:
        return _ONES[n // 100] + " hundred" + ("" if n % 100 == 0 else " " + _int_to_words(n % 100))
    return _int_to_words(n // 1000) + " thousand" + ("" if n % 1000 == 0 else " " + _int_to_words(n % 1000))


def _wants_technique_name(clause: str) -> bool:
    """Whether a first clause asks for the ATT&CK technique NAME rather than its ID (so a `T####[.###]` value we
    read is the WRONG form). True needs the word `name` beside a technique word; a `name/id ... not ... name/id`
    contrast decides which is wanted, and with no contrast a bare `id`/`identifier` in the clause means the ID
    is (or may be) wanted, so nothing is demoted. No rule here can DERIVE the name, so the caller only demotes
    such an answer to unsure; it is never withdrawn and never sent plain in the wrong form."""
    if "name" not in clause or not TECH_WORD.search(clause):
        return False
    m = CONTRAST.search(clause)
    if m:
        return m.group(1) == "name"
    return not re.search(r"\bid(?:entifier)?\b", clause)


def _first_clause(prose: str) -> str:
    low = " ".join(prose.lower().split())
    m = CLAUSE_END.search(low)
    return HOUSE_TAIL.sub("", (low[:m.start()] if m else low).strip()).strip()


def _asks(prose: str) -> bool:
    """Whether a syntax text's first clause holds any word this file reads and no negation. A day has a
    handful of syntax texts and hundreds of questions: each text is looked at once, and one that asks
    nothing costs a dictionary read."""
    got = _ASKS.get(prose)
    if got is None:
        clause = _first_clause(prose)
        # the technique-name request carries its own `not ... id` wording, so it is read past the NEGATION guard
        # (which exists for a form NEGATED, `never in lower case`); _wants_technique_name is tight on its own.
        got = (bool(WORDS.search(clause)) and not NEGATION.search(clause)) or _wants_technique_name(clause)
        if len(_ASKS) < 4096:
            _ASKS[prose] = got
    return got


def _case_asked(clause: str, field: str):
    """`lower`, `upper` or None: the case the first clause states for the id's own field."""
    nouns = "|".join(re.escape(n) for n in sorted(NOUNS.get(field, ()) + ANY, key=len, reverse=True))
    asked = [case for case in ("lower", "upper")
             if re.match(CASE_FRONT.format(case=case, nouns=nouns), clause) or re.match(CASE_BACK.format(case=case, nouns=nouns), clause)]
    if len(asked) != 1 or ("lower" in clause and "upper" in clause):
        return None
    return asked[0]


def enabled() -> bool:
    return ctf_env.get("CTF_SCRIPT_FORMS", "").strip().lower() != "off"


def _field(q) -> str:
    """The last word of the id: the field it asks (`...-file-path` is `path`, `...-upload-url` is `url`)."""
    qid = str(q.get("qid") or q.get("id") or "")
    return re.sub(r"[^a-z0-9]+", "_", qid.rsplit("-", 1)[-1].lower()).strip("_") or "value"


def _squash(text: str) -> str:
    return re.sub(r"[-_\s]+", "", text.lower())


def enum_form(q, value):
    """(key, options) when a plain enum answer is listed only in another spelling, else None."""
    fmt = q.get("answer_format")
    if not isinstance(fmt, dict) or fmt.get("kind") != "enum":
        return None
    allowed = fmt.get("accepted_values")
    if not isinstance(allowed, list) or not allowed or not all(isinstance(a, str) for a in allowed):
        return None
    if value in allowed or value.strip() in [a.strip() for a in allowed]:
        return None
    same_case = [a for a in allowed if a.strip().lower() == value.strip().lower()]
    if len(same_case) == 1:
        return "script.enum_form/case", [("listed", same_case[0]), ("own", value)]
    if same_case:
        return None
    same = [a for a in allowed if _squash(a) == _squash(value)]
    if len(same) == 1:
        return "script.enum_form/separator", [("listed", same[0]), ("own", value)]
    return None


def syntax_form(q, value):
    """(form, options) when the syntax text's first clause certainly asks another form of this value; else None."""
    fmt = q.get("answer_format")
    if not isinstance(fmt, dict):
        return None
    prose = fmt.get("syntax")
    if not isinstance(prose, str) or not prose or not _asks(prose):
        return None
    clause = _first_clause(prose)
    text = value.strip()
    if text.lower() == "none":
        return None                      # the literal none is no value of the field: its form is not asked here
    field = _field(q)
    if fmt.get("kind") == "json" and JSON_STRING.match(clause):
        try:
            json.loads(value)
        except ValueError:
            return "json_string", [("json_string", json.dumps(value)), ("judged", value)]
        return None
    # wave13 (finale rehearsal): a count asked spelled as a word. Rule-derivable to English words, but the
    # author's hyphenation and capitalisation are not knowable, so the word form is offered FIRST and unsure,
    # the digit behind it; never a wrong plain.
    if text.isdigit() and COUNT_WORD.search(clause):
        word = _int_to_words(int(text))
        return "spelled", ([("spelled", word)] if word else []) + [("judged", value)]
    if (field in ("attack", "technique") and all(w in clause for w in ("parent", "only", "technique"))
            and re.fullmatch(r"T\d{4}\.\d{3}", text)):
        return "parent_only", [("parent", text.split(".")[0]), ("judged", value)]
    # wave13 (finale rehearsal): the technique NAME asked in place of its ID. No rule here derives the name, so
    # the T-code we read cannot be shipped plain (it is the wrong form): it is demoted to unsure with only the
    # judged value as its option, so it is held out of every batch (gm.session strips it) and probed, never
    # withdrawn. A clause that asks the ID (`technique ID, not the technique name`) is left alone by
    # _wants_technique_name, so its correct ID answer stands plain.
    if field in ("attack", "technique") and re.fullmatch(r"T\d{4}(?:\.\d{3})?", text) and _wants_technique_name(clause):
        return "technique_name", [("judged", value)]
    if field == "url" and DEFANGED.search(clause) and re.match(r"(?i)https?://\S+$", text) and "[.]" not in text:
        scheme = re.sub(r"(?i)^http(s?)://", lambda m: "hxxp" + m.group(1) + "://", text)
        full = scheme.replace(".", "[.]")
        options = [("hxxp_brackets", full), ("hxxp", scheme), ("brackets", text.replace(".", "[.]"))]
        return "defanged", [(n, v) for n, v in options if v != value] + [("judged", value)]
    if field == "path" and SLASHES.search(clause) and "\\" in value:
        return "forward_slashes", [("forward", value.replace("\\", "/")), ("judged", value)]
    case = _case_asked(clause, field)
    if case == "lower" and value != value.lower():
        return "lower", [("lower", value.lower()), ("judged", value)]
    if case == "upper" and value != value.upper():
        return "upper", [("upper", value.upper()), ("judged", value)]
    return None


def demote(qs, got: dict, say=None, skip=()) -> dict:
    """{qid: unsure value} for the plain answers of `got` whose question asks another form, for ALL the
    questions of one delivery at once (analyze.solve_set calls it once, at the end; `skip` holds the ids the
    day's day_patch.py named, which keeps the last word about them). Never raises, never returns None for an
    id, and returns nothing at all when the demotion would touch more than MAX_KEYS keys or MAX_IDS ids."""
    out, keys, lines = {}, set(), []
    if not enabled() or not isinstance(got, dict):
        return out
    tell = say or (lambda s: print(s, file=sys.stderr))
    for q in qs or []:
        try:
            if skip and q.get("qid") in skip:
                continue
            fmt = q.get("answer_format")
            if type(fmt) is not dict:
                continue
            if fmt.get("kind") != "enum":                      # the common case, decided by one dictionary read
                prose = fmt.get("syntax")
                if type(prose) is not str or not (_ASKS.get(prose) or (prose not in _ASKS and _asks(prose))):
                    continue
            qid = q.get("qid")
            value = got.get(qid)
            if not isinstance(value, str) or not value or value.startswith("??"):
                continue
            found = enum_form(q, value)
            if found is not None:
                key, options = found
                why = "the enum lists it in another spelling"
            else:
                found = syntax_form(q, value)
                if found is None:
                    continue
                form, options = found
                key = f"script.form/{_field(q)}.{form}"
                why = f"the syntax text asks another form ({form})"
            if labels is None or not options:
                continue                                       # nothing can be offered: the answer stands
            new = labels.pick(key, options)
            if not isinstance(new, str) or not new or new == value:
                continue                                       # never withdrawn; or the ledger took this spelling
            out[qid] = new
            keys.add(key)
            lines.append(f"FORM {qid}: {why}; {'unsure under ' + key if new.startswith('??') else 'answered in the form the judge took for ' + key}")
        except Exception as e:  # noqa: BLE001 - a question nobody can read changes nothing
            print(f"[answer_forms] {q.get('qid') if isinstance(q, dict) else q}: {type(e).__name__}: {e}; the answer stands", file=sys.stderr)
    # MAX_IDS holds only across two or more keys (B1): one key is one field's form, however many ids ask it.
    if len(keys) > MAX_KEYS or (len(keys) > 1 and len(out) > MAX_IDS):
        tell(f"NOTE answer_forms: the answer formats of this delivery would turn {len(out)} plain answer(s) unsure under "
             f"{len(keys)} key(s) (limits {MAX_IDS} ids across two or more keys, and {MAX_KEYS} keys): a form asked of "
             f"everything is the shared sentence, not a field's form; nothing is demoted")
        return {}
    for line in lines:
        tell(line)
    return out
