"""The kind of answer a question asks for (its answer_format), and holding an answer against it.

Backlog row 106, the solver side. Day 8 asked d08_analysis_elf_class and d08_analysis_machine as
integers; `ELF64` and `x86-64` went out plain under the keys binary.elf_class/64 and
binary.machine/x86-64, names the judge had accepted for the text question, and the first batch was
bisected for them (`64` and `62` were accepted four minutes later). Two rules follow, for every
field and every day:

  1. the kind is part of the label key (binary.elf_class/integer, binary.machine/integer, ...), so a
     name accepted for a text kind never answers an integer question (generic.py, field_catalog.py);
  2. no answer leaves the solver in a form its question does not ask for: conforms() says whether a
     plain value has the form, fit() withholds one that has not and narrows an unsure answer to the
     options that have (generic.py's answers and evidence.py's last pass).

The kinds seen on Days 1 to 8: exact_text, pattern, integer, json, enum (with accepted_values).
Only what a kind states is checked; a kind this module does not know passes everything.

  .venv/bin/python solvers/binary/answer_kinds.py KIND VALUE     # conforms? (a quick look)
"""
import json
import zlib
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
import labels  # noqa: E402

HEX_SYNTAX = re.compile(r"hexadecimal.*\b0x\b|\b0x\b.*hexadecimal", re.I | re.S)
# A syntax that names the prefix in order to forbid it ("without a 0x prefix", "no 0x prefix", "do not
# include 0x", "omit the 0x prefix"): the answer is bare hex digits, and nothing is checked.
NO_PREFIX = re.compile(r"\b(?:no|not|without|omit|omitting|exclude|excluding|drop|strip|never)\b"
                       r"(?:(?!\bwith\b)[^.;,]){0,24}\b0x\b", re.I)
INTEGER = re.compile(r"-?\d+")
HEX_ANSWER = re.compile(r"0x[0-9a-f]+")
ANY_HEX = re.compile(r"(?:0[xX])?[0-9A-Fa-f]+")


def hex_reform(value, fmt):
    """An unsure answer for a plain `0x` + lowercase-digits value whose question asks hexadecimal in
    another form, else None (the value stands as it is).

    The judged form of every hex answer (the XOR key, the CRC-32, an entry point) is the one the
    Days 1 to 8 wording states: lowercase with a 0x prefix. A question that says uppercase, or that
    forbids the prefix, asks the same number in a form no day has judged, and the judged form sent
    plain under it is the Day 8 integer mistake again (row 106). The number is established; its
    spelling is offered under a key per asked form, the asked form first:

      binary.hex_form/bare+<tag>           no prefix:            digits | 0x digits
      binary.hex_form/prefix+upper+<tag>   uppercase:            0xDIGITS | 0XDIGITS | 0xdigits
      binary.hex_form/bare+upper+<tag>     uppercase, no prefix: DIGITS | digits | 0xDIGITS

    <tag> is syntax_tag(fmt): one key a form and a syntax text (the review of 2026-10-13).

    A value with no letter among its digits is spelled the same in upper case and stands plain
    there. Only kind `pattern` with the word hexadecimal in its syntax is read this way."""
    if kind_of(fmt) != "pattern" or not isinstance(fmt.get("syntax"), str) or not isinstance(value, str):
        return None
    syntax = fmt["syntax"].lower()
    if "hexadecimal" not in syntax or not HEX_ANSWER.fullmatch(value):
        return None
    bare = bool(NO_PREFIX.search(syntax))
    upper = "uppercase" in syntax and "lowercase" not in syntax
    digits = value[2:]
    if upper and digits.upper() == digits:
        upper = False
    if bare or upper:
        # (the review of 2026-10-13: the key carries the syntax text's tag, as reform()'s keys do)
        return _hex_pick(value, bare, upper, True, syntax_tag(fmt))
    return None


# ---- the Day 14 look-ahead, proposal 1: a hex, hash or offset answer under a syntax text its field was never
# judged under. hex_reform() reads four wordings; the look-ahead's sweep found a dozen more that ask the same
# number in another form and got the judged form plain (a rejected cumulative batch). Three parts:
#   (a) more wordings are read (a negation with no `0x` token, a stated digit count, an anchored character
#       class, "capital"), and bare uppercase digits are offered where the text names no prefix;
#   (b) a digest asked uppercase is a pick (upper, lower);
#   (c) the backstop: judged_syntax.json lists the (kind, syntax) pairs every field was asked under in the
#       judged attempts of Days 1 to 13. A hex, hash or offset answer under any other pair is unsure, the
#       form read from the text first where one is read, the judged form first where none is.
# Under a listed pair nothing here runs, so no saved question set is touched.
_LAZY = {}
# (set by _compile(); named here so that a reader and a linter find them)
NO_PREFIX_MORE = UPPER_WORD = LOWER_WORD = STATED_COUNT = CLASS_SYNTAX = FORM_WORDS = OFFSET_OTHER_BASE = OFFSET_BASE_TEN = None


def _compile() -> None:
    """The patterns reform() reads a syntax text with, compiled at the first text that is not a judged one
    (the review of 2026-10-13: at import they cost every Binary clock process, which never needs them)."""
    if _LAZY:
        return
    _LAZY.update(
        NO_PREFIX_MORE=re.compile(r"\b(?:no|without|omit\w*|exclud\w*|drop\w*|strip\w*)\s+(?:a\s+|an\s+|any\s+|the\s+|leading\s+)*prefix"
                                    r"|\bunprefixed\b|\bnon-?prefixed\b|\bdigits\s+only\b|\bonly\s+(?:the\s+)?(?:hex(?:adecimal)?\s+)?digits\b"
                                    r"|\bbare\s+hex", re.I),
        UPPER_WORD=re.compile(r"\bupper[\s-]?case\b|\bcapitals?\b|\bcapital\s+letters\b|\ball[\s-]caps\b", re.I),
        LOWER_WORD=re.compile(r"\blower[\s-]?case\b", re.I),
        STATED_COUNT=re.compile(r"\b(\d{1,3}|two|four|eight|sixteen|thirty-two|forty|sixty-four)\b[\s-]*(?:(?:lower[\s-]?case|upper[\s-]?case|"
                                  r"hex(?:adecimal)?|capital)\s+)*(?:digits?|characters?|chars?|nibbles?)\b", re.I),
        CLASS_SYNTAX=re.compile(r"\^?\s*(0[xX])?\[([^\]]+)\]"),
        FORM_WORDS=re.compile(r"hex|digit|character|\bchars?\b|upper|lower|capital|\bcase\b|prefix|\b0x|\[0-9|base-?\d|base64|"
                                r"decimal|octal|binary|suffix|separator|\bsha-?\d*:|encoded|escap", re.I),
        OFFSET_OTHER_BASE=re.compile(r"hex|\b0x|prefix|octal|binary", re.I),
        OFFSET_BASE_TEN=re.compile(r"base-?10|(?<!hexa)decimal", re.I),
    )
    globals().update(_LAZY)


COUNT_WORDS = {"two": 2, "four": 4, "eight": 8, "sixteen": 16, "thirty-two": 32, "forty": 40, "sixty-four": 64}
HASH_ANSWER = re.compile(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}")
# what a syntax text must name before it can ask another form of a number or a digest
_JUDGED = {}


def judged_syntax() -> dict:
    """{field tail: {(kind, syntax)}} of judged_syntax.json beside this file; {} when it cannot be read
    (then nothing is known to be judged and reform() does nothing: a missing table never demotes)."""
    if "t" not in _JUDGED:
        try:
            raw = json.loads((Path(__file__).resolve().parent / "judged_syntax.json").read_text())["fields"]
            _JUDGED["t"] = {k: {tuple(p) for p in v} for k, v in raw.items()}
        except (OSError, ValueError, KeyError, TypeError):
            _JUDGED["t"] = {}
    return _JUDGED["t"]


def _norm(text) -> str:
    return " ".join(str(text or "").lower().split())


def _tail(field: str) -> str:
    return re.sub(r"^d\d\d_", "", re.sub(r"^set\d+\.", "", str(field or ""))).lower()


def is_judged(field: str, fmt) -> bool:
    """Whether the question's (kind, syntax) is one the field was judged under; a field no day asked is
    held against every pair of the table."""
    table = judged_syntax()
    if not table:
        return True
    pair = (_norm(fmt.get("kind")), _norm(fmt.get("syntax")))
    known = table.get(_tail(field))
    return pair in known if known is not None else any(pair in v for v in table.values())


def syntax_tag(fmt) -> str:
    """Eight hex digits that name a question's (kind, syntax): the suffix of every key a form is offered
    under, so a name the judge accepts under one text never answers another text plain."""
    syntax = fmt.get("syntax") if isinstance(fmt, dict) and isinstance(fmt.get("syntax"), str) else ""
    return f"{zlib.crc32(_norm(kind_of(fmt) + '|' + syntax).encode()):08x}"


def _hex_reading(digits: str, value_len: int, syntax: str):
    """(bare, upper, names_prefix) as far as the syntax text states them; bare and upper False where unsaid.
    A text that names 0x without negating it asks for the prefix, whatever else it says ("0x followed by
    lowercase hex digits only": the review of 2026-10-13)."""
    names = bool(re.search(r"\b0x", syntax, re.I))
    negated = bool(NO_PREFIX.search(syntax))
    upper = bool(UPPER_WORD.search(syntax)) and not LOWER_WORD.search(syntax)
    bare = negated
    if not names:
        bare = bare or bool(NO_PREFIX_MORE.search(syntax))
        for m in STATED_COUNT.finditer(syntax):
            n = COUNT_WORDS.get(m.group(1).lower()) or (int(m.group(1)) if m.group(1).isdigit() else 0)
            if n == len(digits) and n != value_len:
                bare = True
    m = CLASS_SYNTAX.search(syntax)
    if m and re.search(r"0-9", m.group(2)):
        bare = bare or (not m.group(1) and not names)
        if "A-F" in m.group(2) and "a-f" not in m.group(2):
            upper = True
    return bare, upper, names and not bare




def reform(field: str, value, fmt):
    """(answer, why) for a plain hex, digest or offset answer whose question's (kind, syntax) the field was
    never judged under: an unsure answer and the reason; (None, '') when the answer stands."""
    if not isinstance(value, str) or labels.is_unsure(value) or not isinstance(fmt, dict):
        return None, ""
    kind, syntax = kind_of(fmt), fmt.get("syntax") if isinstance(fmt.get("syntax"), str) else ""
    if kind not in ("pattern", "exact_text", "integer", ""):
        return None, ""
    tail = _tail(field)
    cls = ("hex" if HEX_ANSWER.fullmatch(value) else "hash" if HASH_ANSWER.fullmatch(value)
           else "offset" if tail.endswith("offset") and INTEGER.fullmatch(value) else None)
    if cls is None or (kind == "integer") != (cls == "offset") or is_judged(field, fmt):
        return None, ""      # a hex number asked as an integer, an offset asked as text: the callers' own rules
    _compile()
    if not FORM_WORDS.search(syntax):
        return None, ""             # no syntax text, or one that says nothing of the form (the lane's exact_text sentence)
    tag = syntax_tag(fmt)
    why = f"{tail} was never judged under this {kind or 'unnamed'} syntax"
    if cls == "hash":
        if (LOWER_WORD.search(syntax) and not UPPER_WORD.search(syntax) and re.search(r"hex", syntax, re.I)
                and not re.search(r"\b0x|prefix|base64|:", syntax, re.I)):
            return None, ""             # another sentence that still says lowercase hexadecimal: the judged form
        if UPPER_WORD.search(syntax) and not LOWER_WORD.search(syntax):
            return labels.pick(f"binary.hash_form/upper+{tag}", [("upper", value.upper()), ("lower", value)]), why
        return labels.pick(f"binary.hash_form/unread+{tag}", [("lower", value), ("upper", value.upper())]), why
    if cls == "offset":
        # The judged integer sentence itself says `base-10` and `separators` (the review of 2026-10-13: a
        # trailing period demoted every hcfg_offset). A decimal offset stands unless the text names another
        # base and does not say base-10 or decimal.
        if not OFFSET_OTHER_BASE.search(syntax) or OFFSET_BASE_TEN.search(syntax):
            return None, ""
        n = int(value)
        return labels.pick(f"binary.int_form/hex+{tag}", [("hex", f"0x{n:x}"), ("decimal", value)]), why
    digits = value[2:]
    read = bool(re.search(r"hex|\[0-9", syntax, re.I))
    bare, upper, names = _hex_reading(digits, len(value), syntax) if read else (False, False, False)
    if upper and digits.upper() == digits:
        if names and not re.search(r"\b0X", syntax):
            return None, ""             # 0x and digits with no letter: the judged spelling is the uppercase one too
        upper = False
    cls_m = CLASS_SYNTAX.search(syntax)
    if not bare and not upper and cls_m and cls_m.group(1) == "0x" and "a-f" in cls_m.group(2):
        return None, ""                 # a pattern that spells the judged form: 0x and a lowercase class
    if not bare and not upper and wants_hex(fmt):
        return None, ""                 # another sentence that still says lowercase with a 0x prefix: the judged form
    if (not bare and not upper and names and LOWER_WORD.search(syntax) and re.search(r"hex", syntax, re.I)
            and not re.search(r"\b(?:no|not|never|without|omit\w*|drop\w*|exclud\w*|strip\w*)\b", syntax, re.I)):
        return None, ""                 # "0x followed by lowercase hex digits only": the judged form in other words
    return _hex_pick(value, bare, upper, names, tag, re.search(r"\b0X", syntax) is not None), why


def _hex_pick(value: str, bare: bool, upper: bool, names: bool, tag: str, big_x: bool = False):
    """The unsure answer of a 0x value for the form read (hex_reform and reform share it): one key a form
    and a syntax text."""
    digits = value[2:]
    if bare and upper:
        return labels.pick(f"binary.hex_form/bare+upper+{tag}", [("bare_upper", digits.upper()), ("bare", digits),
                                                                 ("prefix_upper", "0x" + digits.upper())])
    if bare:
        return labels.pick(f"binary.hex_form/bare+{tag}", [("bare", digits), ("prefix", value)])
    if upper and names:
        return labels.pick(f"binary.hex_form/prefix+upper+{tag}", [("upper_digits", "0x" + digits.upper()),
                                                                   ("upper_all", "0X" + digits.upper()), ("lower", value)])
    if upper:
        return labels.pick(f"binary.hex_form/upper+{tag}", [("upper_digits", "0x" + digits.upper()), ("bare_upper", digits.upper()),
                                                            ("upper_all", "0X" + digits.upper()), ("lower", value)])
    options = [("prefix", value), ("bare", digits)]
    if big_x:
        options.insert(1, ("upper_all", "0X" + digits.upper()))
    if digits.upper() != digits:
        options += [("upper_digits", "0x" + digits.upper()), ("bare_upper", digits.upper())]
    return labels.pick(f"binary.hex_form/unread+{tag}", options)

def kind_of(fmt) -> str:
    """The answer kind an answer_format names (`integer`, `json`, `enum`, `pattern`, `exact_text`),
    lowercase; '' when it names none."""
    kind = fmt.get("kind") if isinstance(fmt, dict) else None
    return kind.strip().lower() if isinstance(kind, str) else ""


def wants_hex(fmt) -> bool:
    """Whether a pattern question's syntax text asks for lowercase hexadecimal with a 0x prefix (the
    wording of every hex question of Days 1 to 8). Any other wording states no form this module
    checks: an answer is never withheld on a reading of a sentence it has not seen. A sentence that
    names the prefix to forbid it ("lowercase hexadecimal without a 0x prefix") asks for the opposite,
    and a bare-hex answer (a SHA-256, a build id) is not withheld under it."""
    return (kind_of(fmt) == "pattern" and isinstance(fmt.get("syntax"), str)
            and bool(HEX_SYNTAX.search(fmt["syntax"])) and "lowercase" in fmt["syntax"].lower()
            and "uppercase" not in fmt["syntax"].lower() and not NO_PREFIX.search(fmt["syntax"]))


# Words that make a hexadecimal pattern more than a number in hex: the Day 12 wordings offer a label
# beside the code ("machine architecture label or its equivalent decimal or hexadecimal code") and a
# digest states its length ("exact 64-character lowercase hexadecimal SHA-256 value").
_NOT_HEX_ONLY = re.compile(r"\b(?:label|labels|name|names|mnemonic|constant|symbolic|token|decimal|integer|or|"
                           r"sha-?\d+|md5|digest|hash|character|characters|digits?-long)\b", re.I)


def hex_form(fmt):
    """(prefix, upper) when a pattern question asks for ONE number written in hexadecimal and nothing
    else, or None. `prefix` is True where the syntax asks for a 0x prefix, False where it forbids one,
    None where it does not say; `upper` is True for uppercase digits. The Day 13 look-ahead, row 4: a
    header fact (the machine) asked this way has one reading, the header's own number in that form,
    and the caller offers it unsure under a key that names the form. A syntax that also allows a
    label, a decimal code or a digest is not read here: the judged answer of such a question stands."""
    if kind_of(fmt) != "pattern" or not isinstance(fmt.get("syntax"), str):
        return None
    syntax = fmt["syntax"]
    if "hexadecimal" not in syntax.lower() or _NOT_HEX_ONLY.search(syntax):
        return None
    prefix = False if NO_PREFIX.search(syntax) else True if re.search(r"\b0x\b", syntax, re.I) else None
    return prefix, "uppercase" in syntax.lower() and "lowercase" not in syntax.lower()


def hex_spellings(method: str, n: int, width: int, form) -> list:
    """[(name, value)] of a number in the hexadecimal form hex_form() read: the shortest spelling
    first, then padded to the field's `width` digits where that differs; with the 0x prefix, without
    it, or both (prefix first) where the question does not say."""
    prefix, upper = form
    out = []
    for name, digits in ((method, f"{n:x}"), (method + "_padded", f"{n:0{width}x}")):
        digits = digits.upper() if upper else digits
        for lead, tag in (("0x", ""), ("", ":bare")):
            if (prefix is False and lead) or (prefix is True and not lead):
                continue
            if (name + tag, lead + digits) not in out and all(v != lead + digits for _, v in out):
                out.append((name + tag, lead + digits))
    return out


def enum_norm(text) -> str:
    """An enum value for comparison with a header's own name: lowercase, `+` as `plus` (PE32+ is not
    PE32), every other separator dropped."""
    return re.sub(r"[^a-z0-9]", "", str(text).lower().replace("+", "plus"))


def enum_listed(fmt, spellings) -> list:
    """The accepted values of an enum question that are one of `spellings` but for letter case and
    separators, in the question's own spelling and order. [] for any other kind or an empty list."""
    if kind_of(fmt) != "enum" or not isinstance(fmt.get("accepted_values"), list):
        return []
    want = {enum_norm(s) for s in spellings}
    return [a for a in fmt["accepted_values"] if isinstance(a, str) and enum_norm(a) in want]


def conforms(value, fmt) -> bool:
    """Whether one plain value has the form the question's answer_format asks for.

      integer   base-10 digits (an int, or a string of digits with an optional minus sign)
      json      a value the runner serializes, or a string that parses as JSON
      enum      one of accepted_values, when the format lists them
      pattern   0x and lowercase hex digits, when the syntax text says lowercase hexadecimal with a 0x
                prefix

    The literal `none` ("the requested field is absent") passes integer and pattern: the day modules
    answer it there, and whether an absence is established is not a question of form."""
    kind = kind_of(fmt)
    if value is None or not kind:
        return True
    text = value if isinstance(value, str) else None
    if kind == "integer":
        if isinstance(value, bool):
            return False
        return isinstance(value, int) or (text is not None and (text == "none" or bool(INTEGER.fullmatch(text))))
    if kind == "json":
        if text is None:
            return True
        try:
            json.loads(text)
            return True
        except ValueError:
            return False
    if kind == "enum":
        accepted = fmt.get("accepted_values")
        if not isinstance(accepted, list) or not accepted:
            return True
        return (text if text is not None else json.dumps(value, separators=(",", ":"))) in [str(a) for a in accepted]
    if wants_hex(fmt):
        return text is not None and (text == "none" or bool(HEX_ANSWER.fullmatch(text)))
    if hex_form(fmt) is not None:
        # The review of 2026-10-12: a question that asks one hexadecimal number and nothing else, in a
        # wording wants_hex() does not read (uppercase, no prefix). A label (`x86-64`, `i386` from a
        # day module that answers before generic.py) is not such a number, in any spelling.
        return text is not None and (text == "none" or bool(ANY_HEX.fullmatch(text)))
    return True


def _loose(text) -> str:
    return re.sub(r"[^a-z0-9]", "", str(text).lower())


def _short(value, limit=60) -> str:
    text = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"), default=str)
    text = "".join(c if c.isprintable() else c.encode("unicode_escape").decode() for c in text)
    return text if len(text) <= limit else text[:limit] + "..."


def options_for(options, fmt) -> list:
    """The (name, value) options whose value has the form the question asks for, order kept."""
    return [(n, v) for n, v in options if v is not None and conforms(v, fmt)]


def fit(value, fmt, field=None):
    """(answer, why it changed or '') for an answer held against the question's kind. With `field` (the
    question's id or its field word) a plain hex, digest or offset answer is first held against the
    syntax texts the field was judged under (reform()).

    A plain answer that conforms is returned as it is. An enum answer that differs from exactly one
    accepted value only in letter case or separators becomes that value: the question's own list makes
    the spelling unambiguous. Any other plain answer of the wrong form is None: sending it would cost
    the batch. An unsure answer keeps only the options whose value conforms; with none left it is
    None. A plain `0x` value under a question that asks uppercase or prefix-free hexadecimal becomes
    the unsure answer of hex_reform()."""
    if value is None or not kind_of(fmt):
        return value, ""
    if labels.is_unsure(value):
        parsed = labels.parse(value)
        if parsed is None or not parsed.key:
            return value, ""
        kept = options_for(parsed.options, fmt)
        if len(kept) == len(parsed.options):
            return value, ""
        if not kept:
            return None, f"no option of {parsed.key} has the form of a {kind_of(fmt)} answer"
        return labels.unsure(parsed.key, kept), f"{len(parsed.options) - len(kept)} option(s) of {parsed.key} dropped"
    if field:
        other, why = reform(field, value, fmt)
        if other is not None and other != value:
            return other, why
    if conforms(value, fmt):
        other = hex_reform(value, fmt)
        if other is not None and other != value:
            return other, f"{value!r} is the judged lowercase 0x form and the question asks hexadecimal in another"
        return value, ""
    if kind_of(fmt) == "enum":
        near = [a for a in fmt.get("accepted_values") or [] if isinstance(a, str) and _loose(a) == _loose(value)]
        if len(near) == 1 and _loose(value):
            return near[0], f"spelled as the question lists it ({near[0]!r})"
        yes_no = bool_as_yes_no(value, fmt)
        if yes_no is not None:
            return yes_no, f"{_short(value)!r} offered as the question's yes/no token (binary.bool_form/yes_no, unsure)"
    return None, f"{_short(value)!r} is not a {kind_of(fmt)} answer"


def bool_as_yes_no(value, fmt):
    """The Day 19 look-ahead, B5: a plain boolean (`true`/`false`, as every has_* reader answers) asked as an
    enum of exactly two tokens that read yes and no (any letter case) is offered as the listed token, unsure
    under the one key binary.bool_form/yes_no (option `yes_no`): no day has judged a yes/no spelling, and
    one accepted name answers every such id plainly from then on. None for anything else."""
    if isinstance(value, bool):
        value = "true" if value else "false"
    if not isinstance(value, str) or value.lower() not in ("true", "false"):
        return None
    accepted = fmt.get("accepted_values") if isinstance(fmt, dict) else None
    if not isinstance(accepted, list) or len(accepted) != 2 or not all(isinstance(a, str) for a in accepted):
        return None
    by = {a.strip().lower(): a for a in accepted}
    if set(by) != {"yes", "no"}:
        return None
    return labels.pick("binary.bool_form/yes_no", [("yes_no", by["yes" if value.lower() == "true" else "no"])])


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    print(conforms(sys.argv[2], {"kind": sys.argv[1], "syntax": "lowercase hexadecimal with a 0x prefix"}))
