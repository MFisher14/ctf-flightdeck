#!/usr/bin/env python3
"""Shape answers read from the text alone, for the three languages whose shapes are judged.

Usage:
  python3 solvers/script-analysis/shapes_text.py <specimen.js|.cmd|.bat|.vbs> [...]

The language modules answer the shape questions (how a routine is written, how the plan
variable is expanded, what wraps the recovery call) from a syntax tree or a walk of the
script. This file answers the same questions by line patterns, with no parser and no
interpreter, so that analyze.py has a second, independent reading of every specimen: it
fills in when a module raises, and it flags a specimen on which the two readings differ.

    shapes(language, text) -> {field: value}
    read(language, text)   -> ({field: value}, the fields answered by the default branch)

  jscript    function-style, invocation-style, property-style
  batch      expansion, control
  vbscript   control, representation, transform (through vbscript.text_scan)

How sure an answer is, in the terms of docs/ops/contracts.md:

  - A shape read from an explicit pattern is plain. A control form goes through
    labels.pick('script.control/<batch|vbs>.<keyword>', [its judged name]); every keyword
    read here has an accepted name in the seed, so the answer is that plain name.
  - A control question on which no pattern matched (the lines between the fragments and the
    echo hold something this file does not know) is the default branch:
    labels.pick('script.control/<lang>.unread_<construct>', the names accepted in the family),
    where <construct> is the command of the line that was not read (`if exist ...` gives
    batch.unread_if_exist). It is unsure, never `direct` by default, and a name the judge
    accepts for one construct answers that construct again and no other. Only a specimen with
    no such line (no join, no echo, no decoder call in VBScript) falls under
    'script.control/<lang>.unknown', which every such specimen shares.
  - Any other field with no pattern is absent from the result.
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _p in (HERE, HERE.parent / "common"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

try:
    import labels  # noqa: E402
except Exception:  # noqa: BLE001 - without labels.py the judged names below are used as they are
    labels = None

# How label keys spell a language (pinned in docs/ops/contracts.md).
KEY_LANG = {"batch": "batch", "vbscript": "vbs", "jscript": "jscript"}

# Batch: what steers execution between the fragments and the echo -> the judge's name.
# All six are accepted names in conventions.json (script.control/batch.<keyword>); the FOR /L
# wrapper around a CALL is not named by the judge, so it reads as the call it wraps.
BAT_CONTROL = {"none": "direct", "goto": "goto_dispatch", "call": "call_subroutine", "for_l": "call_subroutine",
               "if_defined": "if_guard", "errorlevel": "errorlevel_guard"}
# VBScript: text_scan's word for the wrapper -> the seed's keyword.
VBS_KEYWORD = {"direct": "none"}


def control_name(lang: str, keyword: str, name: str):
    """The answer for a control form whose keyword was read from an explicit pattern."""
    if labels is None or not name:
        return name
    try:
        return labels.pick(f"script.control/{KEY_LANG[lang]}.{keyword}", [name])
    except Exception:  # noqa: BLE001
        return name


def control_default(lang: str, construct: str = None):
    """The default branch: no pattern matched, so the name is one of the family's, unsure.

    The key holds the construct that was not read (`batch.unread_if_exist`), so a name the judge
    accepts answers that construct again and no other. One key for every unread form would turn
    the first accepted name into the plain answer for all of them. The `unread_` prefix keeps a
    construct such as `for_l` or `if_defined` apart from the seed key of the form this file does
    read. Only a specimen with no such line (no join, no echo, no decoder call) falls under
    `<lang>.unknown`."""
    if labels is None:
        return None
    try:
        shape = f"unread_{construct}" if construct else "unknown"
        return labels.pick(f"script.control/{KEY_LANG[lang]}.{shape}", labels.family("script.control/"))
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------- JScript

def js_shapes(t: str) -> dict:
    """The three style answers, from the routine that evals the recovered descriptor."""
    m = re.search(r'\beval\s*\(', t)
    if not m:
        return {}
    head = None
    for h in re.finditer(r'(?m)^[ \t]*(?:function\s+(\w+)\s*\(|var\s+(\w+)\s*=\s*function\s*(\w*)\s*\(|'
                         r'(\w+)\s*=\s*function\s*(\w*)\s*\()', t):
        if h.start() < m.start():
            head = h
    out = {}
    if head:
        out['function-style'] = 'declaration' if head.group(1) else \
            ('named_expression' if (head.group(3) or head.group(5)) else 'anonymous_expression')
    line_end = t.find('\n', m.start())
    line = t[m.start():line_end if line_end > 0 else None]
    inv = re.search(r'\+\s*(\w+)\s*(\.\s*(call|apply)|\[\s*["\'](call|apply)["\']\s*\])?\s*\(', line)
    if inv:
        out['invocation-style'] = inv.group(3) or inv.group(4) or 'direct'
    dv = re.search(r'(?:var\s+)?(\w+)\s*=\s*eval\s*\(', t)
    if dv:
        d = re.escape(dv.group(1))
        body = t[m.start():]
        end = re.search(r'(?m)^\};?\s*$|^\}\s*$', body)
        body = body[:end.end()] if end else body
        dot = len(re.findall(r'\b%s\s*\.\s*[A-Za-z_]\w*' % d, body))
        br = len(re.findall(r'\b%s\s*\[\s*["\']' % d, body))
        if dot or br:
            out['property-style'] = 'dot' if not br else 'bracket_literal' if not dot else 'mixed'
    return out


# ---------------------------------------------------------------- Batch

FRAGMENT_RE = re.compile(r'(?i)set\s+"?([A-Za-z_]\w*?)\d+=\S')
# The FOR form of the join, wherever it sits in its line (a gate may stand in front of it).
# [^()]: the list is searched for from every `for` of the line, so a run of unclosed lists must
# be read once, not squared (a hostile 480 KB line took 4 s with [^)]).
FOR_JOIN_RE = re.compile(r'(?i)\bfor\s+%%\w\s+in\s*\([^()]*\)\s*do\s+call\s+set\b')
WORD = 24            # letters of one command word that go into a label key; specimen text is untrusted
IF_WORDS = ("exist", "defined", "errorlevel", "cmdextversion")   # what IF tests: part of the construct


def bat_construct(low: str) -> str:
    """The command of a line bat_wrapper cannot read, for a label key: its first word, and a
    second one only when that is a switch or what an IF tests. NOT is left out.

    `if exist "%~f0" ...` -> if_exist, `if not exist ...` -> if_exist, `pushd "%~dp0"` -> pushd,
    `choice /c yn` -> choice_c, `echo hello` -> echo. '' when the line starts with no word.
    An operand is never taken, even when it reads like a word: it is the specimen's own text,
    it changes with the variant, and the name of the form does not depend on it, so a key that
    held it would not answer the same construct again."""
    words = []
    for raw in low.split():
        word = raw.lstrip('@(/')
        if not re.fullmatch(r'[a-z]{1,%d}' % WORD, word) or len(words) == 2:
            break
        if word == 'not':
            continue
        if words and not (raw.startswith('/') or (words[0] == 'if' and word in IF_WORDS)):
            break
        words.append(word)
    return '_'.join(words)


def bat_wrapper(region: list):
    """The keyword of the control form in the lines between the first fragment and the echo, or
    `?<construct>` (see bat_construct) for the first line that is not one this reader knows, so
    that `none` is read, never assumed.

    Order of precedence is the Batch module's: a CALL to a label (with or without a FOR /L
    around it), an IF DEFINED guard, an IF ERRORLEVEL guard, a GOTO to a dispatch label,
    nothing. A GOTO over a separator block is layout."""
    kinds, i = set(), 0
    while i < len(region):
        low = region[i].lower()
        i += 1
        if not low or low == 'rem' or low.startswith(('rem ', 'rem\t', '::', ':')):
            continue                                    # blank, comment, label
        m = re.match(r'goto\s+:?([^\s&|]+)', low)
        if m:
            label = m.group(1)
            j = next((k for k in range(i, len(region))
                      if region[k].lower().split(' ')[0] == ':' + label), None)
            skipped = ' '.join(region[i:j]).lower() if j is not None else ''
            if 'separator' in label or 'separator' in skipped:
                i = j + 1 if j is not None else i       # the lines it jumps over never run
            else:
                kinds.add('goto')
            continue
        if re.match(r'for\s+/l\s+%%\w\s+in\s*\([^)]*\)\s*do\s+call\s+:\S', low):
            kinds.add('for_l')
        elif re.match(r'call\s+:\S', low):
            kinds.add('call')
        elif re.match(r'if\s+(?:not\s+)?defined\s+\S', low):
            kinds.add('if_defined')
        elif re.match(r'if\s+(?:not\s+)?errorlevel\s+\d', low):
            kinds.add('errorlevel')
        elif re.match(r'(?:call\s+)?set\s', low) or re.match(r'for\s+%%\w\s+in\s*\([^)]*\)\s*do\s+(?:call\s+)?set\s', low) \
                or re.fullmatch(r'ver\s*>\s*nul', low) or re.fullmatch(r'exit\s+/b(?:\s+\d+)?', low):
            pass                                        # assignments, the no-op, a subroutine's return
        else:
            return '?' + bat_construct(low)
    for kind in ('for_l', 'call', 'if_defined', 'errorlevel', 'goto'):
        if kind in kinds:
            return kind
    return 'none'


def bat_shapes(t: str) -> dict:
    """Expansion form of the join and control form around it. When a line in between is not
    read there is no control form; `unread` then names that line's construct for the default
    branch (read() takes it out again)."""
    lines = [ln.strip() for ln in re.split(r'\r?\n', t)]
    frag = [(i, m.group(1)) for i, m in ((i, FRAGMENT_RE.match(ln)) for i, ln in enumerate(lines)) if m]
    names = [n for _, n in frag]
    prefix = max(set(names), key=names.count) if names else None
    out, join = {}, None
    if prefix:
        join = next((ln for ln in lines
                     if re.search(r'(?i)\bset\s+"?\w+=.*[%!]' + re.escape(prefix) + r'(\d|%%)', ln)), None)
    if join:
        # The join is read where it stands: `if exist "%~f0" for %%G in (...) do call set ...` is
        # the FOR form behind a gate, not a plain CALL SET.
        if (re.match(r'(?i)for\s+%%\w\s+in\s*\(', join) or FOR_JOIN_RE.search(join)) and 'call set' in join.lower():
            shape = 'for_indirect'
        elif re.search(r'(?i)\bcall\s+set\b', join):
            shape = 'call_double'
        elif '!' in join:
            shape = 'delayed'
        else:
            shape = 'percent'
        # The judge's names (Day 4 base and five Time Trial variants): a %var% or !var! join
        # and a plain CALL SET are `delayed`; the FOR form is `for_indirect`; either CALL form
        # over fragments with a one-letter name is `call_double`. `percent` is never accepted.
        if shape in ('for_indirect', 'call_double') and len(prefix) == 1:
            out['expansion'] = 'call_double'
        else:
            out['expansion'] = 'for_indirect' if shape == 'for_indirect' else 'delayed'
        var = re.search(r'(?i)\bset\s+"?(\w+)=', join)
        first = next(i for i, n in frag if n == prefix)
        echo = next((i for i in range(first + 1, len(lines))
                     if var and re.match(r'(?i)echo[(.\s]\s*[!%]' + re.escape(var.group(1)) + r'[!%]', lines[i])), None)
        if echo is not None:
            keyword = bat_wrapper(lines[first + 1:echo])
            if keyword in BAT_CONTROL:
                out['control'] = control_name('batch', keyword, BAT_CONTROL[keyword])
            else:
                # A gate written on the join line itself is the construct the name depends on,
                # whatever other line came first (`pushd` three lines up says nothing about it).
                own = bat_wrapper([join])
                unread = (own if own.startswith('?') and own[1:] else keyword)[1:]
                if unread:
                    out['unread'] = unread
    return out


# ---------------------------------------------------------------- VBScript

def vbs_shapes(t: str) -> dict:
    """Wrapper, representation and transform, through vbscript.text_scan (its line reader, not
    its evaluator). The names are the module's own table, so a name learned live reaches both."""
    import vbscript
    seen = vbscript.text_scan(t)
    out = {}
    codec = seen.get("codec") or []
    if codec and codec[0]:
        out["representation"] = codec[0]
    if len(codec) > 1 and codec[1]:
        out["transform"] = codec[1]
    wrapper = seen.get("control")
    if wrapper and vbscript.CONTROL_NAMES.get(wrapper):
        out["control"] = control_name("vbscript", VBS_KEYWORD.get(wrapper, wrapper), vbscript.CONTROL_NAMES[wrapper])
    return out


READERS = {"jscript": js_shapes, "batch": bat_shapes, "vbscript": vbs_shapes}


def read(language: str, text: str):
    """({field: value}, the fields answered by the default branch) for one specimen.

    A default-branch answer was not read from a pattern: it is labels.pick over the family,
    under the key of what was not read. analyze.py needs to know which answers those are: a
    plain one is the name the judge accepted for that very key, not this file's own reading."""
    reader = READERS.get(language)
    if reader is None:
        return {}, set()
    out = dict(reader(text))
    unread = out.pop("unread", None)
    defaulted = set()
    if language in ("batch", "vbscript") and out.get("control") is None:
        default = control_default(language, unread)
        if default is not None:
            out["control"] = default
            defaulted.add("control")
        else:
            out.pop("control", None)
    return out, defaulted


def shapes(language: str, text: str) -> dict:
    """{field: value} for one specimen. A language without a reader gives {}."""
    return read(language, text)[0]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: shapes_text.py <specimen.js|.cmd|.bat|.vbs> [...]   (prints the shapes read from the text)")
    by_ext = {".js": "jscript", ".jse": "jscript", ".cmd": "batch", ".bat": "batch", ".vbs": "vbscript", ".vbe": "vbscript"}
    for arg in sys.argv[1:]:
        lang = by_ext.get(Path(arg).suffix.lower())
        if lang is None:
            print(f"{arg}: no text reader for {Path(arg).suffix or 'a file without an extension'}")
            continue
        try:
            raw = Path(arg).read_bytes()
        except OSError as e:
            print(f"{arg}: cannot be read ({e.strerror or e})")
            continue
        body = raw.decode("utf-16", "replace") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8", "replace")
        print(f"{arg}: " + " | ".join(f"{k}={v}" for k, v in shapes(lang, body).items()))
