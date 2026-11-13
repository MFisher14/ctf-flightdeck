#!/usr/bin/env python3
"""Offline tests of solvers/script-analysis/census.py, the language-blind control-flow census.

  PYTHONDONTWRITEBYTECODE=1 .venv/bin/python solvers/script-analysis/test_census.py

No network and no token. The saved attempts are only read (through gm.CHALLENGES and the
offline loader of tools/run.py); the runtime ledger and the wire state are pointed at one
tempfile.mkdtemp() folder that is removed at the end, so no name learned on a live day can
change a result and nothing is written under challenges/.

What is checked:

  corpus    every saved VBScript and Batch specimen, read as if its language were unknown:
            the (klass, keyword) equals the language module's own control shape or is
            None, never another class; None on at most 20 percent
  ranks     with the ledger masked for that language, the judged name is among the first
            6 options for at least 80 percent of the specimens that got a census
  jscript   the saved JScript specimens (no question judges them): a decoder handed to a
            trampoline is None, never `direct`; every other specimen keeps a reading
  snippets  hand-written python-, sh-, js-, php-, lua-, perl-, ruby-, powershell-,
            autoit- and label-style specimens, one per wrapper, give the expected
            reading; unbalanced, nested-ambiguous, two-site and unknown-keyword specimens
            give None, and so does every wrapper the block stack cannot see (a site in a
            header, a trailing modifier, a short circuit, a callback, a hidden call)
  answer    the labels.pick contract: key spelling, the wrapped transfer's names after the
            first option, None for another question, the seed's name when it is not masked
  hostile   bytes, an empty file and noise never raise
  bounded   specimens built to be slow (blank runs, unpaired quotes, deep nesting,
            thousands of sites or routines) each take under 0.5 s
  speed     the whole corpus in under 0.3 s per 180 specimens

Prints one line per check and `ok` at the end; exits 1 on the first failure.
"""
import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
TMP = Path(tempfile.mkdtemp(prefix="test_census_"))

sys.dont_write_bytecode = True
os.environ["CTF_TESTING"] = "1"
os.environ["CTF_STATE_DIR"] = str(TMP / "state")
os.environ.pop("CTF_PLATFORM_URL", None)       # nothing here talks to a Game Master, real or fake
os.environ.pop("CTF_LEDGER_MASK", None)
for switch in [k for k in os.environ if k == "ONLY" or k.startswith("BATCH_")]:
    os.environ.pop(switch)                     # solver switches would change the module's own reading
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.path.insert(0, str(HERE))
import gm  # noqa: E402  (resolves the saved attempts: $CTF_WORKDIR, else the main checkout's)
import run  # noqa: E402

SAVED = gm.CHALLENGES
os.environ["CTF_WORKDIR"] = str(TMP / "challenges")  # from here on: an empty runtime ledger
import labels  # noqa: E402
import batch  # noqa: E402
import vbscript  # noqa: E402
from vbs_interp import parse as vbs_parse  # noqa: E402
import census  # noqa: E402

# The language module's internal control shape -> the reading the census must give.
EXPECT = {
    "vbscript": {"none": ("direct", "none"), "if": ("guard", "if"), "select": ("multiway", "select"),
                 "do": ("loop", "do"), "while": ("loop", "while"), "for": ("loop", "for"),
                 "on_error": ("guard", "on_error")},
    "batch": {"linear": ("direct", "none"), "goto": ("dispatch", "goto"), "call": ("subroutine", "call"),
              "for_l": ("loop", "for_l"), "if_defined": ("guard", "if_defined"),
              "errorlevel": ("guard", "errorlevel")},
}
LANGUAGE = {".vbs": "vbscript", ".vbe": "vbscript", ".cmd": "batch", ".bat": "batch"}
MASK = {"vbscript": "script.control/vbs.*", "batch": "script.control/batch.*"}
NEED = {"vbscript": 72, "batch": 108}
BUDGET = 0.3 / 180  # seconds per specimen


# ---------------------------------------------------------------------------- the saved corpus
def vbscript_shape(text: str) -> str:
    """The VBScript module's reading, kept as fine as it is made: the innermost block that
    is not a constant-true guard; else the error guard; else that guard itself; else none."""
    prog = vbs_parse(text)
    funcs = {st[1]: st for st in prog if st[0] == "func"}
    _, decode, recover = vbscript.find_routines(funcs)
    body = funcs[recover][3]
    trail = vbscript.trail_to(body, decode)
    real = [k for k, cond in trail if not (k == "if" and cond == ("lit", True))]
    if real:
        return real[-1]
    if vbscript.error_guarded(body, decode):
        return "on_error"
    return "if" if trail else "none"


def batch_shape(text: str) -> str:
    plan_text, sh = batch.recover_plan(text)
    assert plan_text, "the Batch module did not recover a plan"
    return batch.control_of(sh, plan_text)


def attempt_dirs() -> list:
    out = []
    for base in sorted(SAVED.glob("day-*/script-analysis-*")):
        for d in (base, base / "time_trial", base / "mastery"):
            out += [d] + sorted((d / "history").glob("*"))
    return [d for d in out if (d / "attempt.json").exists() and (d / "artifact").is_dir()]


def judged(d: Path):
    """({answer id: name}, grade) from key.json (judge evidence) or golden.json (the solver's
    snapshot, in the judge's vocabulary)."""
    for name in ("key.json", "golden.json"):
        if (d / name).exists():
            data = json.loads((d / name).read_text())
            return data.get("answers") or {}, data.get("grade") or "?"
    return {}, "-"


_corpus = []


def corpus() -> list:
    """Every saved VBScript and Batch specimen: dicts with lang, where, member, text, shape
    (the module's), question (its control-flow question), judged, grade."""
    if _corpus:
        return _corpus
    for d in attempt_dirs():
        with contextlib.redirect_stderr(io.StringIO()):
            attempt, blobs, _ = run.load_offline("offline", str(d))
            sets = run.split_sets(attempt, blobs)
        answers, grade = judged(d)
        for n, questions, files, _ctx in sets:
            for q in questions:
                member = q.get("member") or ""
                lang = LANGUAGE.get(Path(member).suffix.lower())
                if lang is None or not census.is_control_question(q) or member not in files:
                    continue
                text = vbscript.text_of(files[member])
                shape = vbscript_shape(text) if lang == "vbscript" else batch_shape(text)
                _corpus.append({"lang": lang, "where": f"{d.relative_to(SAVED)} set {n}", "member": member,
                                "text": text, "shape": shape, "question": q,
                                "judged": answers.get(q.get("answer_id") or q["id"]), "grade": grade})
    return _corpus


def t_corpus():
    items = corpus()
    counts = Counter(it["lang"] for it in items)
    for lang, need in NEED.items():
        assert counts[lang] >= need, f"{counts[lang]} saved {lang} specimens under {SAVED}, expected at least {need}"
    wrong, none, shapes = [], Counter(), Counter()
    for it in items:
        it["reading"] = got = census.census(it["text"], ".unknown")  # no language is named
        want = EXPECT[it["lang"]][it["shape"]]
        shapes[(it["lang"], it["shape"])] += 1
        if got is None:
            none[it["lang"]] += 1
        elif (got["klass"], got["keyword"]) != want:
            wrong.append(f"{it['where']} {it['member']}: module {it['shape']} -> {want}, census {got}")
    assert not wrong, f"{len(wrong)} wrong reading(s):\n  " + "\n  ".join(wrong)
    for lang in NEED:
        assert set(EXPECT[lang]) == {s for (l, s) in shapes if l == lang}, \
            f"{lang}: the saved specimens do not show every shape of the table"
        assert none[lang] <= 0.2 * counts[lang], f"{lang}: no reading for {none[lang]} of {counts[lang]}"
    return ", ".join(f"{counts[l]} {l}: 0 wrong, {none[l]} None" for l in NEED)


def t_ranks():
    """Mask what the seed knows about the language, then ask where the judged name stands
    among the options the census proposes. A variant with neither key.json nor golden.json (a
    timed attempt that failed before freeze_keys.py could snapshot it, Day 7's two Time Trial
    starts) has no name to rank against: it is counted and left out, never failed."""
    notes = []
    try:
        for lang in NEED:
            os.environ["CTF_LEDGER_MASK"] = MASK[lang]
            ranks, grades, read, unjudged = Counter(), Counter(), 0, 0
            for it in corpus():
                if it["lang"] != lang or it.get("reading") is None:
                    continue
                if it["grade"] == "-":                  # no key.json or golden.json in that attempt folder
                    unjudged += 1
                    continue
                read += 1
                grades[it["grade"]] += 1
                assert it["judged"], f"{it['where']} {it['member']}: no judged or snapshot answer on disk"
                value = census.answer(it["question"], it["text"], Path(it["member"]).suffix)
                parsed = labels.parse(value) if value is not None else None
                names = parsed.names if parsed else ([value] if value is not None else [])
                ranks[names.index(it["judged"]) + 1 if it["judged"] in names else 0] += 1
                assert value is None or parsed is not None, \
                    f"{it['where']} {it['member']}: a masked key answered plain {value!r}"
            top = sum(n for r, n in ranks.items() if 1 <= r <= 6)
            hist = " ".join(f"{'miss' if r == 0 else f'#{r}'}:{n}" for r, n in sorted(ranks.items(), key=lambda x: x[0] or 99))
            print(f"      {lang}: rank of the judged name among the options  {hist}"
                  f"   (answers: {', '.join(f'{n} grade {g}' for g, n in sorted(grades.items()))})")
            assert read and top >= 0.8 * read, f"{lang}: judged name in the first 6 for {top} of {read}"
            notes.append(f"{lang} {top}/{read} in the first 6" + (f" ({unjudged} unjudged left out)" if unjudged else ""))
    finally:
        os.environ.pop("CTF_LEDGER_MASK", None)
    return ", ".join(notes)


def t_speed():
    texts = [it["text"] for it in corpus()]
    best = min(_timed(texts) for _ in range(3))
    limit = BUDGET * len(texts)
    assert best < limit, f"{len(texts)} specimens took {best:.3f} s, limit {limit:.3f} s"
    return f"{len(texts)} specimens in {best * 1000:.0f} ms, limit {limit * 1000:.0f} ms"


def _timed(texts) -> float:
    t = time.perf_counter()
    for text in texts:
        census.census(text, ".unknown")
    return time.perf_counter() - t


# ---------------------------------------------------------------------------- hand-written specimens
PY = '''# inert fixture
MATERIAL_ab12 = "68656c6c6f"
CODEC_ab12 = "hex_compact|identity|"

def load_ab12():
    return bytes.fromhex(MATERIAL_ab12)

def decode_ab12(s):
    return bytes(b ^ 0 for b in s)

def recover_ab12():
    s = load_ab12()
    d = b""
@@
    return d.decode()

def inspect_ab12():
    return recover_ab12()
'''
SH = '''#!/bin/sh
# inert fixture
MATERIAL_ab12="68656c6c6f"
load_ab12() {
  printf '%s' "$MATERIAL_ab12" | xxd -r -p
}
decode_ab12() {
  printf '%s' "$1" | tr 'a-z' 'a-z'
}
recover_ab12() {
  s=$(load_ab12)
@@
  printf '%s' "${d}"
}
inspect_ab12() {
  recover_ab12
}
'''
JS = '''// inert fixture
var material_ab12 = "68656c6c6f";
var load_ab12 = function() {
  var out = [];
  for (var i = 0; i < material_ab12.length; i += 2) { out.push(parseInt(material_ab12.substr(i, 2), 16)); }
  return out;
};
function decode_ab12(s) {
  var d = [];
  for (var i = 0; i < s.length; i++) { d.push(s[i] ^ 0); }
  return d;
}
function recover_ab12() {
  var s = load_ab12();
  var d;
@@
  return String.fromCharCode.apply(null, d);
}
function inspect_ab12() {
  var o = { text: recover_ab12() };
  return o.text;
}
'''
PHP = '''<?php
// inert fixture
$material_ab12 = "68656c6c6f";
function load_ab12() {
    global $material_ab12;
    return hex2bin($material_ab12);
}
function decode_ab12($s) {
    $d = '';
    for ($i = 0; $i < strlen($s); $i++) { $d .= chr(ord($s[$i]) ^ 0); }
    return $d;
}
function recover_ab12() {
    $s = load_ab12();
@@
    return $d;
}
function inspect_ab12() {
    return recover_ab12();
}
'''
LABELS = '''rem inert fixture
goto HUNTRESS_INSPECT
HUNTRESS_INSPECT:
material$ = "68656c6c6f"
@@
print plan$
exit
HUNTRESS_RECOVER:
plan$ = material$
return
'''
BASIC = '''' inert fixture
Const Material_ab12 = "104,101"
Function Load_ab12()
  Load_ab12 = Split(Material_ab12, ",")
End Function
Function Decode_ab12(ByRef s)
  Decode_ab12 = s
End Function
Function Recover_ab12()
  Dim s, d
  s = Load_ab12()
@@
  Recover_ab12 = Join(d, "")
End Function
Function Inspect_ab12()
  Inspect_ab12 = Recover_ab12()
End Function
'''

# (name, template, the wrapper, expected (klass, keyword) or None, expected inner keyword)
SNIPPETS = [
    ("py direct", PY, "    d = decode_ab12(s)", ("direct", "none"), None),
    ("py if", PY, "    if True:\n        d = decode_ab12(s)", ("guard", "if"), None),
    ("py for", PY, "    for _ in range(1):\n        d = decode_ab12(s)", ("loop", "for"), None),
    ("py while", PY, "    p = 0\n    while p < 1:\n        d = decode_ab12(s)\n        p += 1", ("loop", "while"), None),
    ("py try", PY, "    try:\n        d = decode_ab12(s)\n    except ValueError:\n        raise", ("guard", "try"), None),
    ("py match", PY, "    match 1:\n        case 1:\n            d = decode_ab12(s)\n        case _:\n            d = b''",
     ("multiway", "match"), None),
    ("sh direct", SH, '  d=$(decode_ab12 "$s")', ("direct", "none"), None),
    ("sh if", SH, '  if true; then\n    d=$(decode_ab12 "$s")\n  fi', ("guard", "if"), None),
    ("sh while", SH, '  p=0\n  while [ "$p" -lt 1 ]; do\n    d=$(decode_ab12 "$s")\n    p=$((p + 1))\n  done',
     ("loop", "while"), None),
    ("sh for", SH, '  for pass in 1; do\n    d=$(decode_ab12 "$s")\n  done', ("loop", "for"), None),
    ("sh until", SH, '  p=0\n  until [ "$p" -ge 1 ]\n  do\n    d=$(decode_ab12 "$s")\n    p=1\n  done', ("loop", "until"), None),
    ("sh case", SH, '  case 1 in\n    1) d=$(decode_ab12 "$s") ;;\n    *) d="" ;;\n  esac', ("multiway", "case"), None),
    ("js direct", JS, "  d = decode_ab12(s);", ("direct", "none"), None),
    ("js if", JS, "  if (true) {\n    d = decode_ab12(s);\n  }", ("guard", "if"), None),
    ("js for", JS, "  for (var pass = 0; pass < 1; pass++) {\n    d = decode_ab12(s);\n  }", ("loop", "for"), None),
    ("js while", JS, "  var p = 0;\n  while (p < 1) {\n    d = decode_ab12(s);\n    p++;\n  }", ("loop", "while"), None),
    ("js do", JS, "  do {\n    d = decode_ab12(s);\n  } while (false);", ("loop", "do"), None),
    ("js switch", JS, "  switch (1) {\n    case 1:\n      d = decode_ab12(s);\n      break;\n    default:\n      d = [];\n  }",
     ("multiway", "switch"), None),
    ("js try", JS, "  try {\n    d = decode_ab12(s);\n  } catch (e) {\n    throw e;\n  }", ("guard", "try"), None),
    ("js one-line guard", JS, "  if (s.length > 0) d = decode_ab12(s);", ("guard", "if"), None),
    ("php direct", PHP, "    $d = decode_ab12($s);", ("direct", "none"), None),
    ("php if", PHP, "    if (true) {\n        $d = decode_ab12($s);\n    }", ("guard", "if"), None),
    ("php if endif", PHP, "    if (true):\n        $d = decode_ab12($s);\n    endif;", ("guard", "if"), None),
    ("php foreach", PHP, "    foreach (array(1) as $pass) {\n        $d = decode_ab12($s);\n    }", ("loop", "foreach"), None),
    ("php while", PHP, "    $p = 0;\n    while ($p < 1) {\n        $d = decode_ab12($s);\n        $p++;\n    }", ("loop", "while"), None),
    ("php do", PHP, "    do {\n        $d = decode_ab12($s);\n    } while (false);", ("loop", "do"), None),
    ("php switch", PHP, "    switch (1) {\n        case 1:\n            $d = decode_ab12($s);\n            break;\n"
                        "        default:\n            $d = '';\n    }", ("multiway", "switch"), None),
    ("php try", PHP, "    try {\n        $d = decode_ab12($s);\n    } catch (Exception $e) {\n        throw $e;\n    }",
     ("guard", "try"), None),
    ("js decoder fed by a decode helper", JS.replace("load_ab12();", "decodeBase64(load_ab12());")
     + "function decodeBase64(t) {\n  return t;\n}\n",
     "  switch (1) { case 1: d = decode_ab12(s); break; default: d = []; }", ("multiway", "switch"), None),
    ("labels gosub", LABELS, "gosub HUNTRESS_RECOVER", ("subroutine", "gosub"), None),
    ("labels goto", LABELS.replace("HUNTRESS_RECOVER:", "HUNTRESS_DISPATCH:").replace("return\n", "goto HUNTRESS_EMIT\n"),
     "goto HUNTRESS_DISPATCH\nHUNTRESS_EMIT:", ("dispatch", "goto"), None),
    ("labels guarded gosub", LABELS, "if ready = 1 then gosub HUNTRESS_RECOVER", ("guard", "if"), "gosub"),
    ("labels straight", LABELS, "plan$ = material$", ("direct", "none"), None),

    # Doubtful specimens: None, never a reading.
    ("unbalanced: brace never closed", JS, "  if (true) {\n    d = decode_ab12(s);", None, None),
    ("unbalanced: stray brace", JS, "  d = decode_ab12(s);\n  }", None, None),
    ("unbalanced: fi missing", SH, '  if true; then\n    d=$(decode_ab12 "$s")', None, None),
    ("unbalanced: wrong closing word", BASIC, "  Do\n    d = Decode_ab12(s)\n    Exit Do\n  End Select", None, None),
    ("unbalanced: closing word with nothing open", BASIC, "  d = Decode_ab12(s)\n  Wend", None, None),
    ("nested: loop inside try", PY, "    try:\n        for _ in range(1):\n            d = decode_ab12(s)\n"
                                    "    except ValueError:\n        raise", None, None),
    ("nested: switch inside while", JS, "  while (true) {\n    switch (1) {\n      case 1:\n        d = decode_ab12(s);\n"
                                        "    }\n    break;\n  }", None, None),
    ("nested: loop under an error guard", BASIC, "  On Error Resume Next\n  Do\n    d = Decode_ab12(s)\n    Exit Do\n"
                                                 "  Loop\n  On Error GoTo 0", None, None),
    ("two sites that disagree", PY, "    d = decode_ab12(s)\n    while not d:\n        d = decode_ab12(s)", None, None),
    ("unknown keyword: with", PY, "    with lock_ab12:\n        d = decode_ab12(s)", None, None),
    ("unknown keyword: begin", BASIC, "  Begin\n    d = Decode_ab12(s)\n  End", None, None),
    ("labels: jump to a label of unknown purpose", LABELS, "goto HUNTRESS_MYSTERY\nHUNTRESS_MYSTERY:\nplan$ = material$",
     None, None),
    ("no recovery routine at all", "x = 1\nprint x\n", "", None, None),
]
# The same wrappers in a keyword-closed language, as a cross-check of the saved VBScript.
SNIPPETS += [
    ("basic direct", BASIC, "  d = Decode_ab12(s)", ("direct", "none"), None),
    ("basic layout guard around a loop", BASIC, "  If True Then\n    For p = 0 To 0\n      d = Decode_ab12(s)\n    Next\n  End If",
     ("loop", "for"), None),
    ("basic call statement in a loop", BASIC, "  Do\n    Call Decode_ab12(s)\n    Exit Do\n  Loop", ("loop", "do"), "call"),
    ("basic error guard", BASIC, "  On Error Resume Next\n  d = Decode_ab12(s)\n  On Error GoTo 0", ("guard", "on_error"), None),
    ("basic error guard already lifted", BASIC, "  On Error Resume Next\n  On Error GoTo 0\n  d = Decode_ab12(s)",
     ("direct", "none"), None),
    ("keyword inside a string or a comment", BASIC, '  t = "Do While If Then {"  \' Select Case\n  d = Decode_ab12(s)',
     ("direct", "none"), None),
]


# ---------------------------------------------------------------------------- review additions
# Templates in four more syntaxes, and the specimens that were read `direct` (or as the
# wrong block) before the review. `direct` is the costly misreading: all direct specimens
# of a language share one key with one option, so each of these must be None.
LUA = '''-- inert fixture
local material_ab12 = "68656c6c6f"
local function load_ab12()
  local out = {}
  for i = 1, #material_ab12, 2 do
    out[#out + 1] = tonumber(material_ab12:sub(i, i + 1), 16)
  end
  return out
end
local function decode_ab12(s)
  local d = {}
  for i = 1, #s do d[i] = (s[i] + 10) % 256 end
  return d
end
local function recover_ab12()
  local s = load_ab12()
  local d = {}
@@
  return d
end
local function inspect_ab12()
  return recover_ab12()
end
'''
PERL = '''#!/usr/bin/perl
# inert fixture
my $material_ab12 = "68656c6c6f";
sub load_ab12 {
    return map { hex } unpack("(A2)*", $material_ab12);
}
sub decode_ab12 {
    my @d = reverse @_;
    for my $i (0 .. $#d) { $d[$i] = $d[$i] ^ 144; }
    return @d;
}
sub recover_ab12 {
    my @s = load_ab12();
    my @d;
@@
    return join("", map { chr } @d);
}
sub inspect_ab12 {
    return recover_ab12();
}
'''
RUBY = '''# inert fixture
MATERIAL_ab12 = "68656c6c6f"
def load_ab12
  [MATERIAL_ab12].pack("H*").bytes
end
def decode_ab12(s)
  s.reverse
end
def recover_ab12
  s = load_ab12
  d = []
@@
  d.pack("C*")
end
def inspect_ab12
  recover_ab12
end
'''
POSH = '''# inert fixture
$Material_ab12 = "68656c6c6f"
function Load-ab12 {
    return [byte[]]($Material_ab12 -split '(..)' | Where-Object { $_ } | ForEach-Object { [Convert]::ToByte($_, 16) })
}
function Decode-ab12 {
    param([byte[]]$s)
    $d = @()
    foreach ($b in $s) { $d += ($b -bxor 144) }
    return $d
}
function Recover-ab12 {
    $s = Load-ab12
    $d = @()
@@
    return -join ($d | ForEach-Object { [char]$_ })
}
function Inspect-ab12 {
    return Recover-ab12
}
'''
AUTOIT = '''; inert fixture
Func Load_ab12()
    Return 1
EndFunc
Func Decode_ab12($s)
    Return $s
EndFunc
Func Recover_ab12()
    Local $s = Load_ab12()
    Local $d
@@
    Return $d
EndFunc
Func Inspect_ab12()
    Return Recover_ab12()
EndFunc
'''
# A routine header this table does not read (`name(args) {`), next to one it does (`name() {`).
HOTKEY = '''; inert fixture
Load_ab12() {
    return [1]
}
Decode_ab12(s) {
    return s
}
Recover_ab12() {
    s := Load_ab12()
@@
    return d
}
Inspect_ab12() {
    return Recover_ab12()
}
'''
FLAT = '''@echo off
setlocal EnableExtensions EnableDelayedExpansion
if /i "%~1"=="--inspect" goto :HUNTRESS_INSPECT
exit /b 0
:HUNTRESS_INSPECT
set "fragment0=v=1|steps=a"
@@
:HUNTRESS_PLAN
echo x
exit /b 0
'''
FLAT_SUB = '\ngoto :HUNTRESS_EMIT\n:HUNTRESS_RECOVER\nset "cfg=%fragment0%"\nexit /b 0\n:HUNTRESS_EMIT\necho(!cfg!\nexit /b 0'
FLAT_TAIL = '\necho(!cfg!\nexit /b 0'

SNIPPETS += [
    # More syntaxes read by the same tables.
    ("lua for", LUA, "  for pass = 1, 1 do\n    d = decode_ab12(s)\n  end", ("loop", "for"), None),
    ("lua while", LUA, "  while true do\n    d = decode_ab12(s)\n    break\n  end", ("loop", "while"), None),
    ("lua repeat", LUA, "  repeat\n    d = decode_ab12(s)\n  until true", ("loop", "repeat"), None),
    ("lua one-line if", LUA, "  if #s > 0 then d = decode_ab12(s) end", ("guard", "if"), None),
    ("perl unless", PERL, "    unless (!@s) {\n        @d = decode_ab12(@s);\n    }", ("guard", "unless"), None),
    ("perl do until", PERL, "    do {\n        @d = decode_ab12(@s);\n    } until (1);", ("loop", "do"), None),
    ("ruby while", RUBY, "  while d.empty?\n    d = decode_ab12(s)\n  end", ("loop", "while"), None),
    ("powershell foreach", POSH, "    foreach ($pass in 1) {\n        $d = Decode-ab12 $s\n    }", ("loop", "foreach"), None),
    ("powershell switch arm", POSH, "    switch (1) {\n        1 { $d = Decode-ab12 $s }\n        default { $d = @() }\n    }",
     ("multiway", "switch"), None),
    ("powershell catch arm", POSH, "    try {\n        throw 1\n    } catch {\n        $d = Decode-ab12 $s\n    }", ("guard", "try"), None),
    ("autoit do until", AUTOIT, "    Do\n        $d = Decode_ab12($s)\n    Until 1", ("loop", "do"), None),
    ("autoit switch", AUTOIT, "    Switch 1\n        Case 1\n            $d = Decode_ab12($s)\n    EndSwitch", ("multiway", "switch"), None),
    ("js braces inside the loop header", JS, "  for (var k in {a: 1}) {\n    d = decode_ab12(s);\n  }", ("loop", "for"), None),
    ("js first arm in braces", JS, "  switch (1) {\n    default: {\n      d = decode_ab12(s);\n    }\n  }", ("multiway", "switch"), None),
    ("py else arm", PY, "    if not s:\n        d = b''\n    else:\n        d = decode_ab12(s)", ("guard", "if"), None),
    ("flat one-line guarded call", FLAT, "if not defined HUNTRESS_SKIP call :HUNTRESS_RECOVER" + FLAT_SUB,
     ("guard", "if_not_defined"), "call"),

    # The site sits in the header of a block: it is the condition, not the body.
    ("header: while condition", JS, "  while ((d = decode_ab12(s)).length == 0) { break; }", None, None),
    ("header: if condition", JS, "  if ((d = decode_ab12(s)).length == 0) { d = []; }", None, None),
    ("header: do-while tail", JS, "  do { s = s; } while ((d = decode_ab12(s)).length == 0);", None, None),
    ("header: basic if condition", BASIC, "  If UBound(Decode_ab12(s)) >= 0 Then\n    d = s\n  End If", None, None),
    ("header: sh if command", SH, '  if ! d=$(decode_ab12 "$s"); then\n    d=""\n  fi', None, None),

    # Control flow inside the site's own statement.
    ("modifier: perl trailing if", PERL, "    @d = decode_ab12(@s) if @s;", None, None),
    ("modifier: perl trailing for", PERL, "    @d = decode_ab12(@s) for (1);", None, None),
    ("modifier: ruby trailing unless", RUBY, "  d = decode_ab12(s) unless s.empty?", None, None),
    ("modifier: ruby trailing rescue", RUBY, "  d = decode_ab12(s) rescue []", None, None),
    ("modifier: py conditional expression", PY, "    d = decode_ab12(s) if s else b''", None, None),
    ("modifier: py comprehension", PY, "    d = [decode_ab12(s) for _ in range(1)][0]", None, None),
    ("modifier: js ternary", JS, "  d = s.length ? decode_ab12(s) : [];", None, None),
    ("modifier: js short circuit", JS, "  s.length && (d = decode_ab12(s));", None, None),
    ("modifier: sh and-list", SH, '  [ -n "$s" ] && d=$(decode_ab12 "$s")', None, None),
    ("modifier: sh or-list", SH, '  d=$(decode_ab12 "$s") || d=""', None, None),
    ("modifier: lua and-or", LUA, "  d = s and decode_ab12(s) or {}", None, None),
    ("modifier: block inside parentheses", JS, "  [1].forEach(function (p) { d = decode_ab12(s); });", None, None),
    ("modifier: second header on one line", FLAT,
     "if defined HUNTRESS_READY for /l %%Q in (1,1,1) do call :HUNTRESS_RECOVER" + FLAT_SUB, None, None),
    ("modifier: call or exit", FLAT, "call :HUNTRESS_RECOVER || exit /b 1" + FLAT_SUB, None, None),
    ("arm of a guard already closed", JS, "  if (!s.length) d = [];\n  else d = decode_ab12(s);", None, None),

    # The routine handed over as a value.
    ("value: lua pcall", LUA, "  local ok, r = pcall(decode_ab12, s)\n  if ok then d = r end", None, None),
    ("value: js trampoline", JS, "  var invoke = function(block, value) { return block(value); };\n  d = invoke(decode_ab12, s);",
     None, None),
    ("value: js apply trampoline", JS, "  d = invoke.apply(null, [decode_ab12, s]);", None, None),
    ("value: py table", PY, "    d = {1: decode_ab12}[1](s)", None, None),
    ("value: py table on several lines", PY, "    table = {\n        1: decode_ab12,\n    }\n    d = table[1](s)", None, None),
    ("value: powershell script block", POSH, "    $d = & { Decode-ab12 $s }", None, None),

    # A block of a kind the tables do not know.
    ("unknown: perl eval", PERL, "    eval {\n        @d = decode_ab12(@s);\n    };", None, None),
    ("unknown: perl given", PERL, "    given (1) {\n        when (1) { @d = decode_ab12(@s); }\n        default { @d = (); }\n    }",
     None, None),
    ("unknown: ruby times", RUBY, "  1.times { d = decode_ab12(s) }", None, None),
    ("unknown: ruby times do", RUBY, "  1.times do\n    d = decode_ab12(s)\n  end", None, None),
    ("unknown: js callback", JS, "  [1].forEach(function (p) {\n    d = decode_ab12(s);\n  });", None, None),
    ("unknown: powershell pipeline block", POSH, "    1 | ForEach-Object {\n        $d = Decode-ab12 $s\n    }", None, None),
    ("unknown: lua anonymous function", LUA, "  local ok = pcall(function()\n    d = decode_ab12(s)\n  end)", None, None),
    ("unknown: lua scope block", LUA, "  do\n    d = decode_ab12(s)\n  end", None, None),
    ("unknown: py async for", PY, "    async for _ in gen():\n        d = decode_ab12(s)", None, None),
    ("unknown: py condition on two lines", PY, "    if (s and\n            True):\n        d = decode_ab12(s)", None, None),
    ("unknown: py continued condition", PY, "    if s and \\\n       True:\n        d = decode_ab12(s)", None, None),
    ("unknown: js else on its own line", JS, "  if (!s.length)\n    d = [];\n  else\n    d = decode_ab12(s);", None, None),
    ("unknown: sh trap", SH, "  trap 'd=\"\"' ERR\n  d=$(decode_ab12 \"$s\")", None, None),
    ("unknown: powershell trap", POSH, "    trap { $d = @() }\n    $d = Decode-ab12 $s", None, None),
    ("unknown: goto inside the routine", PHP, "    goto run;\n    run:\n    $d = decode_ab12($s);", None, None),
    ("unknown: lua goto inside the routine", LUA, "  goto run\n  ::run::\n  d = decode_ab12(s)", None, None),
    ("an error guard lifted by goto 0 is no jump", BASIC, "  On Error Resume Next\n  On Error GoTo 0\n  d = Decode_ab12(s)",
     ("direct", "none"), None),

    # The recovery routine exists but its call cannot be seen: the next tier (the call of
    # the recover routine, always a plain call) must not be read in its place.
    ("hidden: call in a string", BASIC, '  Execute "d = Decode_ab12(s)"', None, None),
    ("hidden: routine fetched by name", BASIC, '  Set f = GetRef("Decode_ab12")\n  d = f(s)', None, None),
    ("hidden: routine header not read", HOTKEY, "    if (true) {\n        d := Decode_ab12(s)\n    }", None, None),
    ("hidden: routine header not read, plain call", HOTKEY, "    d := Decode_ab12(s)", None, None),

    # A flat path with a wrapper that is neither of the two guards the walk knows.
    ("flat: guard of unknown purpose", FLAT, 'if exist "%~f0" set "cfg=%fragment0%"' + FLAT_TAIL, None, None),
    ("flat: counted loop around the join", FLAT, 'for /l %%Q in (1,1,1) do set "cfg=%fragment0%"' + FLAT_TAIL, None, None),
    ("flat: plain loop joins the fragments", FLAT, 'for %%G in (0) do call set "cfg=%%cfg%%%%fragment%%G%%"' + FLAT_TAIL,
     ("direct", "none"), None),
]


def t_snippets():
    bad, positives = [], 0
    for name, template, wrap, want, inner in SNIPPETS:
        got = census.census(template.replace("@@", wrap), ".unknown")
        seen = (got["klass"], got["keyword"]) if got else None
        seen_inner = got["inner"]["keyword"] if got and got["inner"] else None
        positives += want is not None
        if seen != want or seen_inner != inner:
            bad.append(f"{name}: expected {want} inner {inner}, got {got}")
        assert got is None or got["klass"] in census.KLASSES
    assert not bad, f"{len(bad)} snippet(s) misread:\n  " + "\n  ".join(bad)
    return f"{positives} wrappers read, {len(SNIPPETS) - positives} doubtful specimens None"


# ---------------------------------------------------------------------------- answer()
CONTROL_Q = {"qid": "hta-stager-control", "question": "Identify the exact HTA control-flow form."}


def t_answer():
    do_once = BASIC.replace("@@", "  Do\n    d = Decode_ab12(s)\n    Exit Do\n  Loop")
    # A new language: an unsure answer under the extension's own key, <keyword>_once first.
    value = census.answer(CONTROL_Q, do_once, ".HTA")
    parsed = labels.parse(value)
    assert parsed and parsed.key == "script.control/hta.do" and parsed.names[0] == "do_once", value
    assert parsed.names[-1] == "direct" and len(parsed.names) <= labels.MAX_OPTIONS, value
    # Read from the wording when the id says nothing; another question is not ours to answer.
    assert census.answer({"qid": "q7", "question": "Identify the exact Foo control-flow form."}, do_once, "hta") == value
    for q in ({"qid": "hta-stager-role", "question": "Classify the script."},
              {"qid": "hta-stager-transform", "question": "Name the byte transform."}):
        assert census.answer(q, do_once, ".hta") is None, q
    # No reading, no answer: never a default.
    assert census.answer(CONTROL_Q, "x = 1\n", ".hta") is None
    # The pinned key spelling, and the seed's accepted name once the key is not masked.
    for ext, lang in ((".cmd", "batch"), ("BAT", "batch"), (".vbs", "vbs"), ("vbe", "vbs"), (".js", "jscript"),
                      (".ps1", "powershell"), (".hta", "hta"), ("", "unknown"), (None, "unknown")):
        assert census.language(ext) == lang, (ext, census.language(ext))
    assert census.answer(CONTROL_Q, do_once, ".vbs") == "do_once"
    # A loop around a call: the call's names come right after the loop's first name.
    for_call = {"klass": "loop", "keyword": "for_l", "inner": {"klass": "subroutine", "keyword": "call"}}
    names = census.options(for_call, vocabulary=["direct", "for_once", "goto_dispatch"])
    assert names[:2] == ["for_l_once", "call_subroutine"] and names[-1] == "direct" and "for_once" in names, names
    assert names.count("direct") == 1
    # The same reading under the batch key: the seed's rejections apply, so the first
    # option left is the name the judge accepted on Day 4.
    os.environ["CTF_LEDGER_MASK"] = MASK["batch"]
    try:
        it = next(i for i in corpus() if i["lang"] == "batch" and i["shape"] == "for_l")
        parsed = labels.parse(census.answer(it["question"], it["text"], ".cmd"))
        assert parsed.key == "script.control/batch.for_l" and parsed.names[0] == "call_subroutine", parsed
    finally:
        os.environ.pop("CTF_LEDGER_MASK", None)
    return "keys, options and None"


def t_hostile():
    specimen = BASIC.replace("@@", "  d = Decode_ab12(s)")
    want = {"klass": "direct", "keyword": "none", "inner": None}
    assert census.census(specimen.encode("utf-8"), ".x") == want
    assert census.census(b"\xef\xbb\xbf" + specimen.encode("utf-8"), ".x") == want
    assert census.census(specimen.encode("utf-16"), ".x") == want
    assert census.census(specimen.replace("\n", "\r\n"), None) == want
    with contextlib.redirect_stderr(io.StringIO()) as err:
        for junk in ("", "\n\n", "}}}}{{{{", "end\nend\nend", bytes(range(256)) * 20, "(" * 5000, "{" * 5000,
                     "if " * 5000, '"' * 4001, "'" * 4001, "decode_x\n" * 3000, None, 7):
            assert census.census(junk, ".x") is None, repr(junk)[:40]
    assert "Traceback" not in err.getvalue()
    return "bytes, line endings and noise"


def t_bounded():
    """A specimen built to be slow costs milliseconds, not the timed window. Before the
    review the first of these took 12 s and four others 0.5 to 3.5 s."""
    def basic(wrap):
        return BASIC.replace("@@", wrap)
    plain = "  d = Decode_ab12(s)"
    cases = [
        ("a run of 50,000 blanks in one line", basic(plain + " " * 50000 + "x"), True),
        ("20,000 escaped quotes with no partner", basic("  m = " + '"\\' * 20000 + "\n" + plain), True),
        ("a megabyte of material in one string", basic('  m = "' + "ab" * 500000 + '"\n' + plain), True),
        ("20,000 interpolation openers", basic("  x = " + "${" * 20000 + "\n" + plain), False),
        ("5,000 nested guards", basic("If x Then\n" * 5000 + plain + "\n" + "End If\n" * 5000), False),
        ("3,000 call sites", basic((plain + "\n") * 3000), False),
        ("2,000 recovery routines", "".join(f"Function Decode_{i}(s)\nEnd Function\n" for i in range(2000))
         + "d = Decode_1(s)\n" * 50, False),
        ("2,000 recovery labels", "".join(f":decode_{i}\ncall :decode_{i}\n" for i in range(2000)), False),
    ]
    worst = 0.0
    for name, text, readable in cases:
        t = time.perf_counter()
        with contextlib.redirect_stderr(io.StringIO()):
            got = census.census(text, ".x")
        took = time.perf_counter() - t
        worst = max(worst, took)
        assert took < 0.5, f"{name}: {took:.2f} s"
        want = {"klass": "direct", "keyword": "none", "inner": None} if readable else None
        assert got == want, f"{name}: {got}"
    return f"{len(cases)} hostile specimens, the slowest {worst * 1000:.0f} ms"


def t_jscript():
    """The saved JScript specimens have no control-flow question, so nothing judges their
    readings; they are real output of the same generator, though. One of its forms hands
    the decoder to a trampoline (`invoke(decode_x, s)`, `invoke.apply(null, [decode_x, s])`).
    That is no plain call, so it must not be read `direct`; every other specimen must
    still get a reading.

    Day 8's host fixtures (`host-wsf-jscript-*.js`, `host-hta-jscript-*.js`) come from another
    generator: the plan is a `HUNTRESS_ANALYSIS_V1:` descriptor in a comment and a string
    (shapes_php.py reads it), and there is no recovery routine at all, so nothing is wrapped
    and no control-flow question is asked about them. Their reading must be None, never
    `direct`, and a control-flow question about one would be a new shape this test must see."""
    trampoline = re.compile(r"invoke(?:\.call|\.apply)?\([^)\n]*decode_")
    descriptor = re.compile(r"HUNTRESS_ANALYSIS_V1:[A-Za-z0-9_]+-")
    seen, read, handed, hosts, wrong = 0, Counter(), 0, 0, []
    for d in attempt_dirs():
        with contextlib.redirect_stderr(io.StringIO()):
            attempt, blobs, _ = run.load_offline("offline", str(d))
            sets = run.split_sets(attempt, blobs)
        for n, questions, files, _ctx in sets:
            for member in sorted({q.get("member") or "" for q in questions}):
                if Path(member).suffix.lower() != ".js" or member not in files:
                    continue
                seen += 1
                text = vbscript.text_of(files[member])
                got = census.census(text, ".unknown")
                if descriptor.search(text):
                    hosts += 1
                    asked = [q["qid"] for q in questions
                             if q.get("member") == member and census.is_control_question(q)]
                    if got is not None or asked:
                        wrong.append(f"{d.relative_to(SAVED)} set {n} {member}: descriptor host read as {got}"
                                     + (f", control-flow question {asked[0]}" if asked else ""))
                elif trampoline.search(text):
                    handed += 1
                    if got is not None:
                        wrong.append(f"{d.relative_to(SAVED)} set {n} {member}: trampoline read as {got}")
                elif got is None:
                    wrong.append(f"{d.relative_to(SAVED)} set {n} {member}: no reading")
                else:
                    read[got["keyword"]] += 1
    assert seen >= 144, f"{seen} saved JScript specimens under {SAVED}, expected at least 144"
    assert handed, "no saved JScript specimen uses the trampoline form"
    assert not wrong, f"{len(wrong)} JScript specimen(s):\n  " + "\n  ".join(wrong[:20])
    return f"{seen} specimens: {handed} trampolines None, {hosts} descriptor hosts None, " + ", ".join(f"{n} {k}" for k, n in sorted(read.items()))


def t_cli():
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    r = subprocess.run([sys.executable, str(HERE / "census.py")], capture_output=True, text=True, env=env)
    assert r.returncode == 2 and r.stderr.strip() == "usage: census.py <specimen> [...]", (r.returncode, r.stderr)
    r = subprocess.run([sys.executable, str(HERE / "census.py"), str(TMP / "missing.vbs")],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 2 and len(r.stderr.strip().splitlines()) == 1 and "Traceback" not in r.stderr, r.stderr
    path = TMP / "sample.vbs"
    path.write_text(BASIC.replace("@@", "  Do\n    d = Decode_ab12(s)\n    Exit Do\n  Loop"))
    r = subprocess.run([sys.executable, str(HERE / "census.py"), str(path)], capture_output=True, text=True, env=env)
    assert r.returncode == 0 and "klass=loop keyword=do" in r.stdout and "key=script.control/vbs.do" in r.stdout, r.stdout
    return "usage and one specimen"


def census_bytecode() -> set:
    """The census's bytecode files beside the module. Any tool that imports census.py leaves one,
    so the test compares before and after instead of demanding that none exists."""
    cache = HERE / "__pycache__"
    return {p.name for p in cache.iterdir() if p.name.startswith("census")} if cache.is_dir() else set()


def main():
    before = census_bytecode()
    try:
        for test in (t_corpus, t_ranks, t_jscript, t_snippets, t_answer, t_hostile, t_bounded, t_cli, t_speed):
            note = test()
            print(f"pass  {test.__name__[2:]}" + (f"  ({note})" if note else ""))
        assert census_bytecode() <= before, "the test left bytecode behind"
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    print("ok")


if __name__ == "__main__":
    main()
