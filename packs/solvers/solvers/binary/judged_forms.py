"""The rewording guard for judged forms (the Day 18 look-ahead, B1): a plain answer whose question asks for
it in a form, or under a rule, the judge never took for its field goes unsure, the judged answer first.

Why. The look-ahead of 2026-10-17 (docs/retro/day-18-predictions-binary.md, section 4) staged 189 Day 18
shapes on the armed solver: no new field, sample or build gave a wrong plain answer, and every one of the 45
wrong plain slots (7 shapes; 42 classified, 3 the same failure on PE sets) came from text the solver does not
read. answer_kinds.reform() (row 291's
backstop) holds a hex, digest or offset answer against the (kind, syntax) pairs its field was judged under;
nothing held a list or a text answer, or a rule written into the question. The seven:

  W23  d01 section_names, syntax "... omit the empty name of the null section"   the leading "" kept
  W26  d04 section_names, syntax "... sorted alphabetically"                     header order
  W27  d17 config_mutex, "... JSON escapes included"                             one backslash, not two
  W28  d17 config_url, "defanged URL ..."                                         https://, dots
  W29  d17 config_campaign, "lowercase campaign identifier"                        BR17-000
  W21  d02 mangled_score_symbol whose rule says SKIP section-definition symbols    .text$_ZNK... on the PE
  W22  d12 hcfg_storage whose rule narrows raw_const_array to a read-only section  raw_const_array (CARRIED)

Two readings, one pass (demote(), called by evidence.solve_set for each prefix right after its answers are
held against their kinds, before day_patch.py's override, which keeps the last word):

  (a) forms. A plain list or text answer whose question's (kind, syntax) pair is not listed for its field in
      judged_syntax.json (answer_kinds.is_judged) and whose syntax text asks one of the forms read below
      (read_forms: omit the empty name, distinct, sorted, descending, reversed, lower case, upper case,
      defanged, JSON-escaped, quoted; each clause with its own negation guard, a case the text leaves free
      read as none) is unsure under binary.list_form/<field>+<tag> or binary.text_form/<field>+<tag> (<tag> is
      answer_kinds.syntax_tag: one key a field and a syntax text), the judged form first (option `judged`),
      then the form the text asks (all of them together first when it asks two). A form that leaves this
      value as it is (a list already sorted, a campaign already in lower case) changes nothing: the answer
      stays plain. Kinds enum and integer are never read
      here (the enum lists its own spellings, kinds.py and reform() hold the rest), nor is a hex, digest or
      integer-like value (reform()'s), nor the literal none, true or false.
  (b) rule texts. hcfg_storage and the d02 symbol fields (RULE: mangled_<m>_symbol, typeinfo_symbol,
      typeinfo_name_symbol, vtable_symbol, a build word in front allowed) state their rule in the question.
      judged_syntax.json's "texts" keeps every judged question text of those fields, normalised (lower case,
      blanks folded, dNN and Day N masked, "in delivery N:" dropped). A plain answer whose question text is
      none of those and states a rule (not the lane's generic sentence "What is the exact ... value for field
      ... in the delivered evidence set?", and one of RULE_WORDS in it) is unsure under
      binary.rule_text/<field>+<shape>+<tag> (<shape> the judged token, or `section_prefixed` / `bare` for a
      symbol; <tag> eight hex digits of the normalised question text and its syntax), the judged answer
      first; then, for hcfg_storage, `raw`, the rule's own catch-all, and for a symbol with a section prefix
      (`.text$...`), the bare name. Only what the enum lists is offered.

Widened by the Day 19 look-ahead (docs/retro/day-19-predictions-binary.md, B1, B6; staged: the 18 WRONG
slots of W35, W38 and W42 are unsure with the judged answer alone, and nothing else on the grid moved):

  (a') an unjudged pair whose syntax is none of the lane's own sentences (generic_pair: a pair judged for any
      field, or its opening cut at a word) is held whether or not a form word is read: W35 "the names of the
      sections that have the SHF_ALLOC flag" (a filter) and W42 "registrable domain only (the last two
      labels)" (a derived part) read no form, or only one that leaves the value as it is. A syntax about a
      number, a hex value or a digest (NUMBER_SYNTAX) is reform()'s and widens nothing.
  (b') "texts" holds every field's judged question texts (text_slot: the rule field, else the field's tail),
      the ones that only ask left out (generic_any: the lane's sentence, `What is <id>?`, under MIN_WORDS
      words). A plain answer, of any kind, of a field the judge has taken under some text, asked under a
      text that is none of them, is unsure under binary.question_text/<field>+<tag>, the judged answer
      alone (W38: "the CRC-32 of its payload bytes exactly as stored in the file (still XOR-encoded)"). A
      field no day judged is not held: its text is its only definition.
  (B6) under an unjudged rule text, the tokens the question's enum lists that the answer does not offer
      follow it as a candidate pick (labels.candidates, row 346; W34: a sixth token, raw_rodata), for an
      answer that is already unsure only, under binary.rule_text/<field>+open+<the pick's own evidence
      shape>+<tag> (elf+no_ref, pe+code_ref: one key a shape), each extra named `listed:<token>`, the
      hypothesis, never the bare value; a plain answer gets no extra token (its key carries the judged token,
      not the container or evidence, so an accepted token would answer every sample of that token: review of
      2026-10-18). Only on an attempt with no deadline (ctx["attempt"]["deadline"]: a base, a
      regular attempt, a practice continuation), where verify.py probes it; with a deadline neither runner
      probes a candidate pick, so the answer is the candidate key's accepted name where the judge took one,
      else the ordinary pick as before (the ladder probes that in its window).

What it costs: every harmless reword of a judged field is one probe on the base (the breadth limit still
holds a reword of everything: Day 3's Time Trial and Mastery changed the syntax of 17 fields against the base,
more than MAX_KEYS keys, so nothing would be held there; Day 17's timed rule texts, 2 or 3 keys, were held by
(b) before this widening too).

It only ever turns a plain answer unsure: it never withdraws one, never makes one plain (an accepted name
for the tagged key, read through labels.pick, is the judge's), and never touches an unsure answer or None.
Under a pair or a text the judge has taken nothing here runs, so no saved question set is touched (every
saved Binary question is in the table: mk_judged_syntax.py builds both parts from the judged attempts).

The breadth limit. When the questions of one set would put more than MAX_KEYS keys or MAX_IDS ids under
the guard (counted from the questions, before any answer: plan()), nothing is demoted and one line says so:
a form asked of everything is the shared sentence, not a field's form (Script's answer_forms.py, row 280).

stderr: `[evidence] FORM <id>: ...` for each demoted answer; `[evidence] NOTE judged_forms: ...` for the
breadth limit. CTF_BINARY_FORMS=off (or CTF_KINDS=off, the kind check's own escape) in front of
the lane command turns it off; the armed opener cannot.

  .venv/bin/python solvers/binary/judged_forms.py 'SYNTAX TEXT'     # the forms a syntax text is read as
"""
import json
import os
import re
import sys
import zlib
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "common"))
import answer_kinds  # noqa: E402
import labels  # noqa: E402

MAX_KEYS = 6            # keys one set may put under the guard (Script's answer_forms.MAX_KEYS)
MAX_IDS = 100           # ids one set may put under the guard
MAX_OPTIONS = 6
FORM_KINDS = ("json", "exact_text", "pattern", "")

# ---- (b) the rule-in-question fields and their judged texts

RULE = re.compile(r"(?:^|_)(hcfg_storage|mangled_[a-z0-9]+_symbol|typeinfo_name_symbol|typeinfo_symbol|vtable_symbol)$")
GENERIC = re.compile(r"what is the exact [a-z0-9 ]+ value for field dnn_[a-z0-9_]+ in the delivered evidence set\?")
TRAILERS = re.compile(r"\s*(?:evidence case: \S+?\.(?=\s|$)|\[assigned-artifact-sha256:[0-9a-f]+\])")
_TABLE = {}


def norm_text(text) -> str:
    """A question text as judged_syntax.json keeps it: lower case, blanks folded, the day's prefix (d17,
    d17--, d17_) as dnn, `day 17` as `day n`, a Mastery's leading `in delivery N:` as `in`, and a timed
    attempt's own trailer (`evidence case: ...`, `[assigned-artifact-sha256:...]`) left out, so a judged rule
    text is still judged when a variant appends one."""
    t = " ".join(str(text or "").lower().split())
    t = re.sub(r"^in delivery \d+:\s*", "in ", t)
    t = re.sub(r"\bd\d{2}(?=--|_|\b)", "dnn", t)
    t = re.sub(r"\bday \d+\b", "day n", t)
    # The Day 21 build: a day's overlay magic (pk19, rs20) where the text names it as one, so the same procedure
    # asked of the next day's magic (rs21) is the text the judge took: `the final rs20 overlay`, `the final
    # rs20 resource overlay`, `pk19 for day n`. Two letters and the two digits only, and only in those places.
    t = OVERLAY_MAGIC.sub("magic", t)
    return TRAILERS.sub("", t).strip()


OVERLAY_MAGIC = re.compile(r"\b[a-z]{2}\d{2}\b(?= (?:resource )?overlay\b| for day n\b)")


RULE_WORDS = re.compile(r"\b(?:submit|rules?|when|whenever|if|traverse|skip\w*|includ\w*|exclud\w*|discard\w*|"
                        r"otherwise|unless|only|first|last|order|prefer\w*|strip\w*|omit\w*|without|bare|prefix\w*|"
                        r"use|report|return|choose|select|pick|must|never|do not|don't)\b")


def is_generic(text) -> bool:
    """Whether a normalised question text states no rule: the lane's generic sentence (an `evidence case:`
    or `[assigned-artifact-sha256:...]` trailer aside), or any text without one word a rule is written with
    (RULE_WORDS: `What is d12_analysis_hcfg_storage?` asks, it does not rule)."""
    text = TRAILERS.sub("", text).strip()
    return bool(GENERIC.fullmatch(text)) or not RULE_WORDS.search(text)


def rule_core(field) -> str:
    """The rule field a question id names (`d15_analysis_stripped_hcfg_storage` -> hcfg_storage), or ''."""
    m = RULE.search(answer_kinds._tail(field))
    return m.group(1) if m else ""


# The Day 19 look-ahead, B1 (b): any field's question text, not only a rule field's. A text that only asks
# (the generic sentence, or `What is d18_analysis_x?`) states no meaning; any other judged text is kept.
SHORT_ASK = re.compile(r"what is (?:the )?(?:value (?:of|for) )?(?:field )?[a-z0-9_.-]+\s*\??")
MIN_WORDS = 4           # a text of fewer words states no meaning of its own ("?", "the value")


def generic_any(text) -> bool:
    """Whether a normalised question text of a field that states no rule only asks: the lane's generic
    sentence, `What is <id>?`, or fewer than MIN_WORDS words, a trailer aside."""
    text = TRAILERS.sub("", text).strip()
    return bool(GENERIC.fullmatch(text) or SHORT_ASK.fullmatch(text) or len(text.split()) < MIN_WORDS)


def text_slot(field) -> str:
    """The key of judged_syntax.json's "texts" a question id's text is kept under: the rule field
    (`hcfg_storage`) for a rule field, else the field's tail (`analysis_config_crc32_hex`)."""
    return rule_core(field) or answer_kinds._tail(field)


def text_kept(field, text) -> bool:
    """Whether a normalised question text is one "texts" keeps (and the guard holds): not empty, and for a
    rule field not is_generic(), for any other field not generic_any()."""
    if not text:
        return False
    return not (is_generic(text) if rule_core(field) else generic_any(text))


def judged_texts() -> dict:
    """{slot: {normalised judged question text}} of judged_syntax.json's "texts"; {} when it cannot be
    read (then no text is known and nothing is demoted: a missing table never demotes)."""
    if "t" not in _TABLE:
        try:
            raw = json.loads((HERE / "judged_syntax.json").read_text()).get("texts") or {}
            _TABLE["t"] = {k: set(v) for k, v in raw.items() if isinstance(v, list)}
        except (OSError, ValueError, TypeError, AttributeError):
            _TABLE["t"] = {}
    return _TABLE["t"]


# The Day 20 look-ahead (backlog row 373, C1): a config member read from the HCFG JSON (every
# analysis_config_* field) and the container's xor_key_hex are not invented, so the "a new field's text is
# its only definition" exemption below does NOT cover them. config_ipv4, config_host_model, config_service and
# the path members have never been judged, so the exemption left a value-changing instruction in the free
# question text (a defanged IPv4, an upper-cased host model) answered plain in the stored form -- a wrong plain
# answer. Now an unjudged config member under a non-generic text is demoted like a judged one (campaign,
# domain, url, mutex): unsure under binary.question_text/config_<name>+<tag>, the judged answer first.
CONFIG_MEMBER = re.compile(r"analysis_config_[a-z0-9_]+|analysis_xor_key_hex")
# B-246 (backlog row 456): a ROLE-prefixed config id (`d21_analysis_plugin_config_domain`, `d27_analysis_gcc_config_
# campaign`, `analysis_plugin_xor_key_hex`) is a config member too: one or two role words between `analysis_` and
# `config_`/`xor_key_hex`. Before, it fullmatched nothing, so a brand-new role id's text was its "only definition"
# and a value-changing text (a defanged IPv4) went plain. Its text slot is its own; a text the judge took for the
# BASE slot (`analysis_config_<name>`) is judged for it too (base_config_slot).
ROLE_CONFIG_MEMBER = re.compile(r"analysis_(?:[a-z0-9]+_){1,2}?(config_[a-z0-9_]+|xor_key_hex)")


def is_config_member(field) -> bool:
    """Whether a field is an HCFG config member (analysis_config_*, or a role-prefixed analysis_<role>_config_*)
    or the container's xor_key_hex (also role-prefixed): a value read from the record, never one the question text
    alone defines (row 373, row 456). Matched on the field's tail from `analysis_`, so another lane's
    `cpp_config_crc32` is not swept in; the judged compact/direct/stripped variants are config members, and their
    judged texts stay judged under their own slot."""
    tail = answer_kinds._tail(field)
    return bool(CONFIG_MEMBER.fullmatch(tail) or ROLE_CONFIG_MEMBER.fullmatch(tail))


def base_config_slot(field) -> str:
    """`analysis_config_<name>` / `analysis_xor_key_hex` for a role-prefixed config id, else ''."""
    tail = answer_kinds._tail(field)
    if CONFIG_MEMBER.fullmatch(tail):
        return ""
    m = ROLE_CONFIG_MEMBER.fullmatch(tail)
    return f"analysis_{m.group(1)}" if m else ""


def text_judged(field, question) -> bool:
    """Whether nothing in the question's text needs holding: the text states nothing (text_kept), the table
    is missing, a field that states no rule was never judged at all (a new field's text is its only
    definition -- but a config member is read from the record, not defined by its text: row 373), or the text
    is one the judge took for the field."""
    text = norm_text(question)
    if not text_kept(field, text):
        return True
    table = judged_texts()
    if not table:
        return True
    if (not rule_core(field) and answer_kinds._tail(field) not in answer_kinds.judged_syntax()
            and not is_config_member(field)):
        return True
    base = base_config_slot(field)
    return text in table.get(text_slot(field), ()) or bool(base and text in table.get(base, ()))


def text_tag(question, fmt) -> str:
    """Eight hex digits that name a question's normalised text and its (kind, syntax)."""
    syntax = fmt.get("syntax") if isinstance(fmt, dict) and isinstance(fmt.get("syntax"), str) else ""
    body = norm_text(question) + "|" + answer_kinds.kind_of(fmt) + "|" + " ".join(syntax.lower().split())
    return f"{zlib.crc32(body.encode()):08x}"


# ---- (a) the forms a syntax text asks

NEGATION = re.compile(r"(?:\bnot\b|\bnever\b|n't\b|\bno longer\b)")
OMIT = re.compile(r"\b(?:omit\w*|exclud\w*|skip\w*|drop\w*|remov\w*|discard\w*|ignor\w*|leav\w* out|without)\b"
                  r"[^;.:]{0,60}?\b(?:empty|blank|null|unnamed|nameless)\b"
                  r"|\bno (?:leading |initial )?(?:empty|blank|null)\b|\bnon-?empty\b"
                  r"|\b(?:empty|blank) (?:names?|strings?|entries) (?:are |is )?(?:omitted|excluded|dropped|removed|"
                  r"skipped|left out)\b")
SORT = re.compile(r"\b(?:sorted|sort|sorting|alphabetical(?:ly)?|lexicographic(?:al(?:ly)?)?|ascending|"
                  r"descending|a-z|z-a)\b")
SORT_BY_TABLE = re.compile(r"\b(?:by|in) (?:section[- ]header|header|table|index|offset|address|file|raw|entry|"
                           r"declared|declaration|appearance|original|load|link)\b|\b(?:index|offset|address)\b|"
                           r"\b(?:section[- ]header(?:[- ]table)?|header(?:[- ]table)?|table|entry|file|load|link|"
                           r"declaration|declared|appearance|raw|original)[- ]order\b")
DESC = re.compile(r"\bdescending\b|\breverse(?:d)? (?:alphabetical|lexicographic)|\bz-a\b")
REVERSE = re.compile(r"\breverse(?:d)? (?:order|header order|table order|section order)\b|\bin reverse\b|"
                     r"\blast[- ]to[- ]first\b")
UNIQUE = re.compile(r"\b(?:unique|distinct|deduplicat\w*|de-duplicat\w*)\b|\b(?:without|no) duplicates?\b")
LOWER = re.compile(r"\blower[\s-]?case(?:d)?\b|\bin small letters\b")
UPPER = re.compile(r"\bupper[\s-]?case(?:d)?\b|\ball[\s-]caps\b|\bcapital letters\b")
CASE_FREE = re.compile(r"\b(?:upper|lower)(?:[\s-]?case)? (?:or|and) (?:upper|lower)|\bcase[- ]insensitive\b|"
                       r"\bany (?:letter )?case\b|\beither case\b|\bcase (?:does not|doesn't) matter\b|\bcase is ignored\b")
DEFANG = re.compile(r"\bdefang(?:ed|ing)?\b|\bhxxps?\b|\[\.\]")
ESCAPED = re.compile(r"\bjson[- ](?:escaped|escaping)\b|\bescape[sd]? (?:included|kept|preserved|intact|as written)\b"
                     r"|\b(?:with|keep\w*|preserv\w*|includ\w*|retain\w*) (?:the |its |any |all |json |backslash )*"
                     r"escapes?\b|\bescaped (?:as|for|in) json\b|\bas (?:it is |they are )?written (?:inside|in) the "
                     r"(?:decoded )?json\b")
QUOTED = re.compile(r"\b(?:in|within|inside|enclosed in|wrapped in|surrounded by|with)\s+(?:double\s+)?"
                    r"(?:quotes|quotation marks)\b|\bdouble[- ]quoted\b|\bas a json string(?: literal)?\b|"
                    r"\bjson string literal\b")


def _clauses(syntax: str) -> list:
    """The syntax text cut where a clause ends (`;`, `:`, `.` before a blank or the end, a new line)."""
    return [c for c in re.split(r";|:|\.(?=\s|$)|\n", syntax.lower()) if c.strip()]


def _positive(pattern, clause: str):
    """The first match of `pattern` in the clause that no negation in the 40 characters before it turns
    around ("do not sort", "never omit"), or None."""
    for m in pattern.finditer(clause):
        if not NEGATION.search(clause[max(0, m.start() - 40):m.start()]):
            return m
    return None


def read_forms(syntax) -> list:
    """The forms a syntax text asks, in a fixed order: omit_empty, unique, sorted or sorted_desc, reversed,
    lower or upper, defanged, escaped, quoted. [] when it asks none of them (the lane's own sentences)."""
    if not isinstance(syntax, str) or not syntax.strip():
        return []
    found = []
    for clause in _clauses(syntax):
        if _positive(OMIT, clause):
            found.append("omit_empty")
        if _positive(UNIQUE, clause):
            found.append("unique")
        sort = _positive(SORT, clause)
        if sort and not SORT_BY_TABLE.search(clause):
            found.append("sorted_desc" if DESC.search(clause) else "sorted")
        elif _positive(REVERSE, clause):
            found.append("reversed")
        lower, upper = _positive(LOWER, clause), _positive(UPPER, clause)
        if CASE_FREE.search(clause):
            pass                        # a case the text leaves free is no form it asks
        elif lower and not upper:
            found.append("lower")
        elif upper and not lower:
            found.append("upper")
        if _positive(DEFANG, clause):
            found.append("defanged")
        if _positive(ESCAPED, clause):
            found.append("escaped")
        if _positive(QUOTED, clause):
            found.append("quoted")
    order = ("omit_empty", "unique", "sorted", "sorted_desc", "reversed", "lower", "upper", "defanged", "escaped",
             "quoted")
    found = [f for f in order if f in found]
    if "lower" in found and "upper" in found:          # two clauses that ask both cases: not read
        found = [f for f in found if f not in ("lower", "upper")]
    return found


def _compact(items) -> str:
    return json.dumps(items, separators=(",", ":"), ensure_ascii=False)


def as_list(value):
    """The list a plain answer is (a list, or the compact JSON text of one), or None."""
    if isinstance(value, list):
        return value
    if isinstance(value, str) and value[:1] == "[":
        try:
            got = json.loads(value)
        except ValueError:
            return None
        return got if isinstance(got, list) else None
    return None


def _list_form(items: list, form: str):
    strings = all(isinstance(x, str) for x in items)
    if form == "omit_empty":
        return [x for x in items if x != ""]
    if form == "unique":
        out = []
        for x in items:
            if x not in out:
                out.append(x)
        return out
    if form in ("sorted", "sorted_desc"):
        if not strings and not all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in items):
            return None
        return sorted(items, reverse=form == "sorted_desc")
    if form == "reversed":
        return list(reversed(items))
    if form in ("lower", "upper"):
        return [x.lower() if form == "lower" else x.upper() for x in items] if strings else None
    return None             # defanged, escaped, quoted: forms of a text, not of a list


def _defangs(value: str) -> list:
    """[(name, value)] of a URL, a domain or an address defanged: scheme and dots, dots only, scheme only."""
    if "." not in value and "://" not in value:
        return []
    scheme = re.sub(r"^(?i:http)(s?)://", lambda m: "hxxp" + m.group(1) + "://", value)
    dots = value.replace(".", "[.]")
    both = re.sub(r"^(?i:http)(s?)://", lambda m: "hxxp" + m.group(1) + "://", dots)
    return [("hxxp_brackets", both), ("brackets", dots), ("hxxp", scheme)]


def _text_forms(value: str, form: str) -> list:
    """[(name, value)] of one form of a text answer (several readings for defanged and escaped)."""
    if form == "lower":
        return [("lower", value.lower())]
    if form == "upper":
        return [("upper", value.upper())]
    if form == "defanged":
        return _defangs(value)
    if form == "escaped":
        return [("escaped", json.dumps(value, ensure_ascii=False)[1:-1]), ("escaped_ascii", json.dumps(value)[1:-1])]
    if form == "quoted":
        return [("quoted", json.dumps(value, ensure_ascii=False))]
    return []


def form_options(value, forms: list) -> list:
    """[(name, value)] of the forms the syntax asks, applied to a plain answer: all of them together first
    (when there are two or more), then each alone. Values equal to the answer are left out."""
    items = as_list(value)
    out = []
    if items is not None:
        applied = [f for f in forms if _list_form(items, f) is not None]
        if len(applied) > 1:
            cur = items
            for f in applied:
                cur = _list_form(cur, f)
            out.append(("+".join(applied), _compact(cur)))
        out += [(f, _compact(_list_form(items, f))) for f in applied]
    elif isinstance(value, str):
        applied = [f for f in forms if _text_forms(value, f)]
        if len(applied) > 1:
            cur = value
            for f in applied:
                cur = _text_forms(cur, f)[0][1]
            out.append(("+".join(applied), cur))
        for f in applied:
            out += _text_forms(value, f)
    return out


TEXT_SKIP = re.compile(r"-?\d+|0x[0-9a-fA-F]+|[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|none|true|false")


def _formable(value) -> bool:
    """Whether a plain answer is one this guard reads forms of: a list, or a text that is no number, hex
    value, digest (reform()'s) or the literal none, true or false."""
    if as_list(value) is not None:
        return True
    return isinstance(value, str) and bool(value) and not TEXT_SKIP.fullmatch(value)


# ---- the plan and the pass

def off() -> bool:
    return any(ctf_env.get(name, "").strip().lower() in ("off", "0", "no", "false")
               for name in ("CTF_BINARY_FORMS", "CTF_KINDS"))


def _qid(q) -> str:
    return q.get("qid") or re.sub(r"^set\d+\.", "", q.get("id") or "")


def _field(qid: str) -> str:
    return qid.split("_", 1)[1] if "_" in qid else qid


# A syntax text about a number, a hex value or a digest: answer_kinds.reform()'s, never a list or text form
# this guard widens over (the Day 2 base's `exact 64-character hexadecimal SHA-256 value; ...`).
NUMBER_SYNTAX = re.compile(r"hexadecimal|\bhex\b|\bsha-?\d+\b|\bmd5\b|\bdigest\b|\bbase-?10\b|\binteger\b|\b0x\b", re.I)


def generic_pair(fmt) -> bool:
    """Whether a question's syntax states nothing of its own: no syntax text, or a (kind, syntax) pair the
    judge took for some field of the lane (the lane's own sentences: `exact artifact-derived value only,
    ...`, `compact valid json array with exact values and order; ...`)."""
    syntax = fmt.get("syntax") if isinstance(fmt.get("syntax"), str) else ""
    if not syntax.strip():
        return True
    kind, text = answer_kinds._norm(fmt.get("kind")), answer_kinds._norm(syntax).rstrip(" .;,")
    for pairs in answer_kinds.judged_syntax().values():
        for k, judged in pairs:
            judged = judged.rstrip(" .;,")
            # the sentence itself, or its opening cut at a word (`exact artifact-derived value only`)
            if k == kind and (judged == text or (judged.startswith(text) and judged[len(text):len(text) + 1] in
                                                 (" ", ",", ";") and len(text.split()) >= MIN_WORDS - 1)):
                return True
    return False


def _deadline(ctx) -> bool:
    """Whether the attempt the set belongs to has a deadline (a timed attempt on a clock). A base, a regular
    attempt and a practice continuation have none; a replay reads the saved attempt's own."""
    attempt = ctx.get("attempt") if isinstance(ctx, dict) else None
    return bool(isinstance(attempt, dict) and attempt.get("deadline"))


def plan(questions, ctx=None) -> dict:
    """{qid: what to hold} for one set's questions: {"forms": [...], "unjudged": True} where (a) applies,
    {"rule": field, "tag": ...} where (b) does for a rule field, {"text": True, "tag": ...} where it does for
    any other field, several where several do; "deadline" says whether the attempt has one (B6). {} with
    one stderr line when the set would put more than MAX_KEYS keys or MAX_IDS ids under the guard (counted
    from the questions alone).

    The breadth limit is held first against everything (the review of 2026-10-18 found that a broad reword of
    the format, architecture and machine texts put about 30 ids under the widened guard; so the widening can
    add holds, and never takes one away). When the set is over it, each held id is judged on its own by the
    fail-safe below (audit #5): a form read or a rule text always stands as the narrow guard made it, and a
    value-changing widened filter/derived hold (its syntax itself unjudged) is kept unsure for a field we
    answer; a genuinely judged id (a judged syntax with only its question text reworded: config_*,
    hcfg_version, ...) and a widened hold of a brand-new field the judge never took (the shared sentence) stand
    plain."""
    if off():
        return {}
    out, keys = {}, set()
    narrow, narrow_keys = {}, set()       # what the guard before the widening holds (a form read, a rule text)
    deadline = _deadline(ctx)
    for q in questions or []:
        try:
            qid = _qid(q)
            field = _field(qid)
            fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
            got, old = {}, {}
            if answer_kinds.kind_of(fmt) in FORM_KINDS and not answer_kinds.is_judged(field, fmt):
                # B1 (a), widened on 2026-10-18: an unjudged pair that is not one of the lane's own sentences
                # is held whether or not a form word is read (W35 "the sections that have the SHF_ALLOC
                # flag", W42 "the last two labels"); under a lane sentence only a form read is held, as before.
                forms = read_forms(fmt.get("syntax"))
                widened = not generic_pair(fmt) and not NUMBER_SYNTAX.search(str(fmt.get("syntax") or ""))
                key = ("form", answer_kinds._tail(field), answer_kinds.syntax_tag(fmt))
                if forms or widened:
                    got["forms"] = forms
                    if widened:
                        got["unjudged"] = True
                    keys.add(key)
                if forms:
                    old["forms"] = forms
                    narrow_keys.add(key)
            if not text_judged(field, q.get("question")):
                got["tag"] = text_tag(q.get("question"), fmt)
                if rule_core(field):
                    got["rule"] = rule_core(field)
                    keys.add(("rule", got["rule"], got["tag"]))
                    old["rule"], old["tag"] = got["rule"], got["tag"]
                    narrow_keys.add(("rule", got["rule"], got["tag"]))
                else:
                    got["text"] = True
                    keys.add(("text", answer_kinds._tail(field), got["tag"]))
            if got:
                got["deadline"] = deadline
                out[qid] = got
            if old:
                old["deadline"] = deadline
                narrow[qid] = old
        except Exception as e:          # a question this cannot read is left as it is
            print(f"[evidence] judged_forms: reading {q.get('id')!r} raised {type(e).__name__}: {e}", file=sys.stderr)
    if len(keys) <= MAX_KEYS and len(out) <= MAX_IDS:
        return out
    # Fail-safe breadth escape (audit #5, refined): over the cap the guard must NEVER let a value-CHANGING hold
    # fall through to a plain answer, yet it must still let a genuinely judged id stand plain. The old
    # `return {}` on a reword-heavy set shipped a defanged / lowercase / sorted / filtered value verbatim PLAIN;
    # a321a811's first narrowing (keep only the pre-widening `narrow` holds -- a form read, a rule text, and for
    # a config member only one that also carries a rule/text) closed the config-id leak but RE-DROPPED the
    # value-changing WIDENED holds the Day 19 widening was built for (W35 "the sections that have the SHF_ALLOC
    # flag", a filter; W42 "registrable domain only", a derived part), because a widened-no-form hold never
    # enters `narrow`. Survivors are now built in two passes:
    #   1. the pre-widening holds, exactly as a321a811 kept them: a form read or a rule text stands as the guard
    #      before the widening made it (the clean `narrow` entry, no `unjudged`/`text` flag). For a config
    #      member only a hold that also carries a rule/text survives -- a bare lowercase/sorted form asked of
    #      every config field at once is the shared sentence (7 `config_* "lowercase value"` keys hold nothing),
    #      and the record value, read under a pinned format, stands plain.
    #   2. the value-changing WIDENED holds a321a811 missed: a hold whose (kind, syntax) pair is itself unjudged
    #      and non-generic and reads NO form word -- the judge's wanted FORMAT/computation is unknown, so the
    #      value may well differ (a filter, a derived part). It is kept UNSURE (the judged value first) for a
    #      field the judge has taken before or a config member -- a field whose plain value we actually ship
    #      (W35, W42) -- but ONLY when a HANDFUL of such fields are widened (at most MAX_KEYS of them). More than
    #      that is the shared sentence being reworded field by field, not a few per-field filters: a cosmetic
    #      mass reword (appending ".", a synonym swap) touches every field at once, so holding them all would
    #      be the breadth limit's own mistake (test_day14 `rewordings_of_the_day_13_base` "every syntax changed"
    #      cosmetically rewords all 53 day-13 fields, and the right answer is to hold NONE). A widened hold on a
    #      BRAND-NEW field the judge never took has no plain value of ours to protect and is dropped too (keeps
    #      t_review_breadth_keeps_narrow's intent).
    # A TEXT-only hold (no form, no widened hold: a judged syntax with only its question prose reworded, the
    # record value in the judge's accepted form -- config_*, hcfg_version, xor_key_hex, ...) is in neither pass,
    # so it stands PLAIN over the cap (a lone such hold is held UNDER the cap; the breadth limit relaxes it).
    # Over-holding only ever costs probes on the untimed base and can never be wrong.
    survivors = {qid: old for qid, old in narrow.items()
                 if not is_config_member(_field(qid))
                 or out.get(qid, {}).get("text") or out.get(qid, {}).get("rule")}
    widened_known = [qid for qid, got in out.items()
                     if qid not in survivors and got.get("unjudged") and not got.get("forms")
                     and (is_config_member(_field(qid))
                          or answer_kinds._tail(_field(qid)) in answer_kinds.judged_syntax())]
    if len(widened_known) <= MAX_KEYS:            # a handful of per-field filters/derived parts (W35/W42): held;
        for qid in widened_known:                 # a mass widened reword of fields we answer is the shared sentence
            survivors[qid] = out[qid]
    if survivors:
        print(f"[evidence] NOTE judged_forms: the question texts of this set would put {len(out)} id(s) under {len(keys)} "
              f"key(s) (limits {MAX_IDS} and {MAX_KEYS}): the genuinely-judged ids (a judged syntax, only the text "
              f"reworded) and the widened holds of brand-new fields are dropped (the shared sentence), and the "
              f"{len(survivors)} id(s) that read a value-changing form, a rule, or a widened filter/derived hold of "
              f"a field we answer are held as before, unsure (fail-safe, audit #5)", file=sys.stderr)
        return survivors
    print(f"[evidence] NOTE judged_forms: the question texts of this set would put {len(out)} id(s) under {len(keys)} "
          f"key(s) (limits {MAX_IDS} and {MAX_KEYS}): a form asked of everything is the shared sentence, not a "
          "field's form; nothing is demoted", file=sys.stderr)
    return {}


SECTION_PREFIXED = re.compile(r"\.[A-Za-z0-9_.]+\$(.+)")


def _rule_options(core: str, value) -> tuple:
    """(shape for the key, [(name, value)]) of a rule field's plain answer: the judged answer first, then
    the readings a changed rule most plausibly asks (hcfg_storage: `raw`, the rule's catch-all; a symbol
    with a COFF section prefix: the bare name)."""
    if core == "hcfg_storage":
        options = [(value, value)]
        if value not in ("raw", "base64"):
            options.append(("raw", "raw"))
        return value, options
    m = SECTION_PREFIXED.fullmatch(value) if isinstance(value, str) else None
    if m:
        return "section_prefixed", [("judged", value), ("bare", m.group(1))]
    return "bare", [("judged", value)]


def _judged_value(value):
    items = as_list(value)
    return _compact(items) if isinstance(value, list) and items is not None else value

LISTED = "listed:"


def listed_tokens(fmt, options) -> list:
    """B6 (the Day 19 look-ahead): [("listed:<token>", token)] of the tokens an enum question lists that
    `options` does not offer, in the question's order. [] for any other kind.

    Each option's name names its hypothesis, "the reworded rule's list calls this evidence shape <token>",
    never the bare value (row 346); it is offered only under a key that carries the evidence shape it was
    read for (_open_rule), so a name the judge accepts for one shape never answers another (review of
    2026-10-18: an ELF `no_ref` and a PE `code_ref` record shared one key, and an accepted `raw_rodata`
    answered a PE build plain)."""
    if answer_kinds.kind_of(fmt) != "enum" or not isinstance(fmt.get("accepted_values"), list):
        return []
    have = {v for _, v in options}
    out = []
    for t in fmt["accepted_values"]:
        if isinstance(t, str) and t and t not in have and t not in {v for _, v in out}:
            out.append((LISTED + t, t))
    return out


def _shape_of(key: str):
    """The evidence shape of an ordinary pick's key, for a key built from it: `binary.hcfg_storage/elf+no_ref`
    is `elf+no_ref`. None for a key with no shape part (nothing then carries the shape: no extra tokens)."""
    tail = key.split("/", 1)[1] if isinstance(key, str) and "/" in key else ""
    tail = tail.split("#", 1)[0]
    return tail if re.fullmatch(r"[a-z0-9_]+(\+[a-z0-9_]+)+", tail or "") else None


def _settled(value) -> bool:
    return value is not None and not labels.is_unsure(value)


def _with_tokens(key: str, kept: list, extra: list, deadline: bool, fallback):
    """B6: the answer of a rule field under an unjudged rule text whose enum lists tokens `kept` does not
    offer. Without a deadline (a base, a regular attempt, a practice continuation) a candidate pick
    (labels.candidates, row 346) of `kept` then `extra`: verify.py probes it on the base, 12 options at most.
    With a deadline neither runner probes a candidate pick, so the answer is the candidate key's accepted
    name when the judge took one (on the base of the day, under the same text), else `fallback()`: the
    ordinary pick, which the ladder probes in its window."""
    full = (kept + extra)[:labels.MAX_OPTIONS]
    if deadline:
        got = labels.candidates(key, full)
        return got if _settled(got) else fallback()
    plain = labels.pick(key, kept[:MAX_OPTIONS]) if kept else None
    if _settled(plain):
        return plain                    # a name the judge took for the ordinary key (in a window)
    return labels.candidates(key, full)


def _say(qid: str, why: str, key: str, new) -> None:
    if new is None:
        print(f"[evidence] FORM {qid}: {why}; every option of {key} was rejected; left unanswered", file=sys.stderr)
    elif labels.is_candidate(new):
        print(f"[evidence] FORM {qid}: {why}; the answer is a candidate pick under {labels.candidate_key(key)}, the "
              "judged answer first, then the tokens the question lists (B6, row 346)", file=sys.stderr)
    elif labels.is_unsure(new):
        print(f"[evidence] FORM {qid}: {why}; the answer is unsure under {key}, the judged form first",
              file=sys.stderr)
    else:
        print(f"[evidence] FORM {qid}: {why}; answered in the form the judge took for {key}", file=sys.stderr)


def _storage_section(qid: str, value: str):
    """field_catalog.storage_section(qid, value), or None when the catalog is not loaded or raises."""
    try:
        cat = sys.modules.get("field_catalog")
        return cat.storage_section(qid, value) if cat is not None else None
    except Exception:
        return None


def _open_rule(qid: str, what: dict, value: str, fmt: dict):
    """B6 for an answer that is already unsure (W34: generic.py's `binary.hcfg_storage/elf+no_ref` offers
    `raw` and `raw_const_array` and the reworded rule adds `raw_rodata`): the tokens the question lists and
    the pick does not offer follow its options as a candidate pick, under an unjudged rule text only. The
    answer as it was when there is no such token, or when the attempt has a deadline and the judge took no
    name for the candidate key."""
    parsed = labels.parse(value)
    if parsed is None or not parsed.key or labels.is_candidate(parsed):
        return value
    kept = [(n, v) for n, v in parsed.options if isinstance(n, str) and isinstance(v, str)]
    extra = listed_tokens(fmt, kept)
    shape = _shape_of(parsed.key)
    if not kept or not extra or shape is None:
        return value
    if what["rule"] == "hcfg_storage":
        # The shape (elf+no_ref) does not say which section holds the record, and a listed token may turn on
        # it (W34: `raw_rodata when literal HCFG begins in a section named exactly .rodata`): the key carries
        # the section, so a token accepted for a .rodata record never answers a .data one plain (review of
        # 2026-10-18). No section known: no extra tokens.
        section = _storage_section(qid, value)
        if section is None:
            return value
        shape += "+sec_" + (re.sub(r"[^a-z0-9]+", "_", section.lower()).strip("_") or "unnamed") if section \
            else "+sec_none"
    key = f"binary.rule_text/{what['rule']}+open+{shape}+{what['tag']}"
    new = _with_tokens(key, kept, extra, what.get("deadline", False), lambda: value)
    if new != value:
        _say(qid, f"the question's rule text was never judged for {what['rule']} and lists "
                  f"{len(extra)} token(s) {parsed.key} does not offer", key, new)
    return new


def demote(qs: list, got: dict, held: dict) -> dict:
    """Apply plan()'s `held` to one prefix's answers: see the module docstring."""
    if not held:
        return got
    for q in qs:
        qid = _qid(q)
        what, value = held.get(qid), got.get(qid)
        if not what or value is None:
            continue
        try:
            fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
            if isinstance(value, str) and labels.is_unsure(value):
                if what.get("rule"):
                    got[qid] = _open_rule(qid, what, value, fmt)
                continue
            field = _field(qid)
            judged = _judged_value(value)
            short = answer_kinds._tail(field).removeprefix("analysis_")
            if what.get("rule"):
                shape, options = _rule_options(what["rule"], judged)
                key = f"binary.rule_text/{what['rule']}+{shape}+{what['tag']}"
                why = f"the question's rule text was never judged for {what['rule']}"
            elif what.get("text"):
                # B1 (b), widened on 2026-10-18: the question text of a field that states no rule (W38: "the
                # CRC-32 of its payload bytes exactly as stored in the file (still XOR-encoded)").
                options = [("judged", judged)]
                key = f"binary.question_text/{short}+{what['tag']}"
                why = f"the question text was never judged for {answer_kinds._tail(field)}"
            else:
                if not _formable(judged):
                    continue            # a hex, digest or number: reform()'s, as before
                options = [("judged", judged)]
                key = f"binary.{'list' if as_list(judged) is not None else 'text'}_form/{short}+{answer_kinds.syntax_tag(fmt)}"
                asks = "+".join(what.get("forms") or ()) or "nothing this guard reads"
                why = f"{answer_kinds._tail(field)} was never judged under this syntax, which asks {asks}"
            if what.get("forms") and _formable(judged):
                options += form_options(judged, what["forms"])
            seen, kept = set(), []
            for name, v in answer_kinds.options_for(options, fmt):
                if isinstance(v, str) and v not in seen and name not in {n for n, _ in kept}:
                    seen.add(v)
                    kept.append((name, v))
            if not kept:
                continue                # nothing of this answer has the form asked: the kind check's, not ours
            if not what.get("rule") and not what.get("text") and not what.get("unjudged") and len(kept) < 2:
                continue                # a lane sentence whose form leaves this answer as it is: it stands
            # No listed tokens beside a PLAIN answer (review of 2026-10-18): its key carries the judged token,
            # not the container or the evidence it was read from, so a token the judge accepted there would
            # answer every other sample of that token plain. The extras are offered only beside an unsure
            # answer whose pick key names its evidence shape (_open_rule).
            new = labels.pick(key, kept[:MAX_OPTIONS])
            if new == value or new == judged:
                continue                # the judge accepted the judged form under this text
            got[qid] = new
            _say(qid, why, key, new)
        except Exception as e:
            print(f"[evidence] FORM {qid}: holding it against its question text raised {type(e).__name__}: {e}; it "
                  "stands as it was", file=sys.stderr)
    return got




if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    print(read_forms(sys.argv[1]))
