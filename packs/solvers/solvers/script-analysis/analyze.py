#!/usr/bin/env python3
"""Script Analysis lane solver: hand each script's questions to the analyzer for its language.

Runner entry point (tools/run.py): solve_set(questions, files, ctx).

The lane is cumulative, so one evidence.zip holds PowerShell, JScript, Batch and
VBScript specimens. Each language lives in its own module next to this file and
exposes:

    def answers(questions, files, ctx) -> dict      # {qid: answer}

where `questions` are only that language's questions and `files` is every file
in the delivery. Set ONLY=vbscript,batch in the environment to run (and submit)
just those modules, which keeps one analyzer's unfinished answers out of
another's submission.

What this file adds around the modules, without editing them:

  A new language.  An extension that is not in LANGUAGE is answered by lang_<ext>.py if a
      racer has written one, else by generic.py: the plan is recovered from the text, so
      role, technique, adapter, campaign, indicators and any field named like a plan key are
      answered on sight, and the shape questions come back None or unsure. The field of an
      id is what is left of it without the words all ids of its specimen share
      (generic.with_fields, applied here to every specimen). A .wsf, .hta or .sct file is read the same
      way; what is still open is then asked of the VBScript or JScript module on the body of
      its <script> block (the one that carries the plan, else the first with a body), and a
      name that module gives for the new container is held as unsure.
  A new component. A .ps1/.js/.bat/.vbs specimen whose ids are not of a component its module
      was built on (known_component) is answered as a new language is, by solve_new. A module's
      answer to a joined-tokens question is put in the question's form (ordered: Batch too).
  A new field word. (Day 13 preparation, 2026-10-12; solve_module.) A module answers what its component
      was judged on (MODULE_FIELDS). A field no day asked of it is unsure with the plan's own value when
      the plan holds a key of that very name (`script.<field>/<ext>.plan_key`), else unanswered
      (unjudged). An id whose field word is an alias of a field (`-technique`) or a field with one more
      word (`-graph-attack`) is asked of the module as that field and sent unsure (generic.renamed,
      generic.reworded); the general path does the same for every other extension.
  A safety net.    A module is called once per specimen, under try/except. If it raised,
      answered nothing, or gave no shape answer at all, what is missing is filled from the
      text path: the plan from plan_codec.py and the shapes from shapes_text.py, neither of
      which parses or runs anything. A single answer the module declined (it ran and answered
      its other questions) is never filled with the text path's own plain reading: a shape
      name becomes an unsure answer under `script.<field>/<lang>.declined.<text reading>`, a
      plan value of a module that declines one on purpose (DECLINES_PLAN: batch.py) stays
      None. A plan value any other module left open is one it failed to evaluate, and is
      filled as before. Each fill prints one stderr line.
  A live fix for a known language.  shapes_<ext>.py (shapes(text, questions) -> {qid: value},
      the file generic.py loads for a new extension) is also asked about a specimen of a
      language that has a module: only the ids that still have no plain answer after the
      module and the text path (a new field, a new kind of specimen, a declined answer, a name
      that is still unsure). Without such a file, or with every answer plain, nothing changes.
  The day's patch.  day_patch.py (patch(member, questions, answers, files) -> {qid: value}), when the
      folder holds one, is asked last about EVERY specimen, whatever answered it (a module, the
      general path, a lang_<ext>.py, shapes_<ext>.py), with the specimen's questions (each with its
      `field`), a copy of its answers so far and the files as the readers saw them. What it returns
      replaces the answer of that id: a plain value, a labels.pick, or None to withdraw one; an id
      it does not name is left as it is, and an id of another specimen is ignored. It is the one
      file that can replace a PLAIN answer of a shipped module, which shapes_<ext>.py cannot (Day
      12, 2026-10-12: the judge re-worded 219 old ids and no hook could reach the 22 wrong plain
      answers; the main thread added this one during the run). One stderr line per replaced
      answer; a patch that raises costs nothing. No such file ships: day_patch_template.py is the
      form to copy, and the day's patch is folded into the modules and deleted after the day.
  The id names the field.  Which field a question asks is read from its answer id (the field word
      generic.with_fields gives it) and its answer format, never from a word of its text: generic's
      asks_role, asks_attack and is_control, batch.field_of, vbscript.kind_of,
      powershell.what_is_asked, census.is_control_question and lang_sh's steps question read the
      text only for an id that names no field (Day 12; tests/test_script_rewording.py re-words every
      saved attempt and holds the plain answers against the keys).
  A cross-check.   The text path is computed for every JScript, Batch and VBScript specimen.
      Where both readings give a plain answer and they differ, one line says so
      ('[analyze] paths disagree on <qid>: module=<a> text=<b>'); the module's value stands.
      One exception (row 115, 2026-10-08): a module's plain value that holds a control or
      non-printable character is a decode that went wrong (Day 8's fuzz: vbscript.py on urlsafe
      base64 with xor answered `C:\\Users\\Public\\HuntrP\\x10..` plain). It is never sent: the
      text path's plain, printable reading stands in its place, else the question is left
      unanswered. This holds for every module, also one without a text path (PowerShell).
  Partial results. Each specimen's answers are copied into ctx['partial'] when the runner
      passed that key, so a timeout still submits what is ready. A module's answers go in
      before the text path of that specimen starts.
  The question's own list. An answer the question's accepted_values do not hold is known to
      be wrong before it is sent: the text path, generic and a wrapped script's module give
      None instead (generic.listed).
  covers(questions).  The contract check before a clock: a problem for every question that
      neither a module nor the generic route can take.
  Encoded scripts. Microsoft Script Encoder blocks (#@~^...^#~@) are decoded only where the
      script host decodes them (screnc.decode_hosted, row 77): the whole of a .vbe or .jse, and
      the body of a <script language="VBScript.Encode|JScript.Encode"> in a .wsf, .hta, .sct or
      .wsc. That file is read as its decoded text by every reader above: the .vbe goes to the
      VBScript module and the .jse to the JScript module through LANGUAGE as a .vbs or .js would,
      with the text path as their net; a new component goes to the general path. A block there
      whose length, checksum or closing mark does not agree is no reading: that specimen's
      questions are all left unanswered (one stderr line), never answered from the encoded
      bytes. Every other file, and every byte outside an Encode element, is read as it is: a
      #@~^ there is inert text (a comment, a string), never decoded and never a bad block.
  Office documents. A .docm, .xlsm, .pptm, .xlsb, .doc, .xls, .ppt (any Office extension) that holds
      VBA modules or Excel 4.0 macro sheets is read as its macro text (officevba.routed, row 93): the
      modules' source, then the macro sheets' cells, under `<member>.bas` (`.xlm` for macro sheets
      alone), which the general path reads as it reads a VBA file. A container that holds macros but
      does not read whole leaves that specimen's questions unanswered (one stderr line); one with no
      macro container, or that is no zip or compound file, is read as before.
  Node packagings. A member of an extension without a module whose bytes are a pkg, nexe, Node
      single-executable, Bun or Deno executable, or a V8 code cache (bytenode .jsc), is read as
      the script it holds (nodepkg.py, row 94; node_view): the general path gets that text under
      the name `<member>.<kind>`, so every label key is the packaging's own. Only when that text
      gives a plan; otherwise the file is read as it is, as before.

  Binary carriers. A member of an extension without a module whose bytes are no text (a shell link, a
      OneNote section, a compiled help file, any container that stores a script as it is or as UTF-16) and
      that gives no plan as it is, is read as the strings it holds (strings_view, 2026-10-08): its runs of
      printable characters, 8-bit and UTF-16LE, one a line, in file order. Only when that text gives a plan;
      otherwise the file is read as before. Nothing is unpacked or run.
  Containers (round 2, 2026-10-08; carriers.py, container_view). Before the strings are tried, a compiled
      help file (.chm), a OneNote section, a shell link, a compiled AutoIt or AutoHotkey script is read by
      its own tables, and the script it holds is handed to the general path as `<member>.<its extension>`,
      whole: its lines are its own, so its plan's last value is as good as a text file's. Only when
      exactly ONE plan is read from what the container holds (two inner files with two plans are no
      reading); otherwise the file is read as before.

CTF_HIDE=vbscript,census (with CTF_TESTING=1) makes those modules look absent: a
rehearsal knob, inert in live play. A missing answer is None, never a default.
"""
import html
import importlib
import importlib.util
import json
import os
import re
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _p in (HERE, HERE.parent / "common"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

try:  # wave3: render_candidates + override_guard wiring (a new file; loaded by path under a unique
    _rsp_spec = importlib.util.spec_from_file_location("script_respell", HERE / "respell.py")
    _respell = importlib.util.module_from_spec(_rsp_spec)   # name, so another lane's respell.py never shadows it
    _rsp_spec.loader.exec_module(_respell)
except Exception:
    _respell = None

def _own(name: str):
    """This folder's own `<name>.py`, whatever else holds that module name.

    solvers/binary has a generic.py too, and both lanes import theirs by its short name. In a
    process that has loaded the Binary solver first (or that has solvers/binary ahead of this
    folder on the import path), `import generic` would hand this file the Binary module, and
    every specimen would then fail on a missing function. So the file beside this one is
    loaded by path; when another lane's module already holds the name, ours gets a private
    name and theirs stays where it is.

    The rule lives in one place, plan_codec.own (SH-05): this delegates, so the two can never drift
    apart and split a module between two sys.modules keys."""
    return _plan_codec_boot().own(name)


def _plan_codec_boot():
    """This folder's plan_codec module, the holder of own(). The loaded one when it is this folder's
    file (a sibling's bare `import plan_codec` usually put it there); else a bootstrap copy is read by
    path, unregistered, only to call its own("plan_codec"), which registers the real one by the rule."""
    path = HERE / "plan_codec.py"
    for key in ("plan_codec", "script_analysis_plan_codec"):
        mod = sys.modules.get(key)
        try:
            if callable(getattr(mod, "own", None)) and Path(getattr(mod, "__file__", "") or "").resolve() == path:
                return mod
        except OSError:
            pass
    spec = importlib.util.spec_from_file_location("script_analysis_plan_codec_boot", path)
    boot = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(boot)
    return boot.own("plan_codec")


generic = _own("generic")
plan_codec = _own("plan_codec")
shapes_text = _own("shapes_text")
screnc = _own("screnc")
try:
    officevba = _own("officevba")   # row 93; without it an Office document is read as it was before
except Exception as _e:  # noqa: BLE001
    print(f"[analyze] officevba.py did not load ({type(_e).__name__}: {_e}); Office documents are read as they are",
          file=sys.stderr)
    officevba = None
nodepkg = _own("nodepkg")
try:
    carriers = _own("carriers")     # round 2 (2026-10-08); without it a binary carrier is read as its strings
except Exception as _e:  # noqa: BLE001
    print(f"[analyze] carriers.py did not load ({type(_e).__name__}: {_e}); binary carriers are read as their strings",
          file=sys.stderr)
    carriers = None
try:
    answer_forms = _own("answer_forms")   # 2026-10-13: a plain answer whose format asks another form goes unsure
except Exception as _e:  # noqa: BLE001
    print(f"[analyze] answer_forms.py did not load ({type(_e).__name__}: {_e}); answers are sent in their judged form",
          file=sys.stderr)
    answer_forms = None
try:
    stage_plan = _own("stage_plan")       # 2026-10-13: the literals of a typed handoff plan, unsure only
except Exception as _e:  # noqa: BLE001
    print(f"[analyze] stage_plan.py did not load ({type(_e).__name__}: {_e}); a handoff plan is not read",
          file=sys.stderr)
    stage_plan = None

try:
    import labels   # noqa: E402
except Exception:   # noqa: BLE001 - generic.py has already said so
    labels = None

LANGUAGE = {".ps1": "powershell", ".js": "jscript", ".jse": "jscript", ".cmd": "batch", ".bat": "batch",
            ".vbs": "vbscript", ".vbe": "vbscript"}

# The languages with a text path, and the technique the judge accepts for their launcher and
# staged chain (the script's own interpreter; the same values as the modules' own tables).
OWN_TECHNIQUE = {"jscript": "T1059.007", "batch": "T1059.003", "vbscript": "T1059.005"}
# Fields the text path reads from the code's shape; every other field comes from the plan.
SHAPE_FIELDS = {"jscript": ("function-style", "invocation-style", "property-style"),
                "batch": ("expansion", "control"),
                "vbscript": ("control", "representation", "transform")}
ALL_SHAPE_FIELDS = {f for fields in SHAPE_FIELDS.values() for f in fields}
# The modules that leave a plan value unanswered ON PURPOSE (batch.py: a value that would hold
# this machine's %VAR%, trailing blanks that give two plans). A plan value another module leaves
# open is one its evaluator failed on, which is what the text path is the net for. That module
# having answered other questions proves nothing: vbscript.py catches its own failures and
# answers the role from the question id even when it recovered no configuration at all.
DECLINES_PLAN = ("batch",)

# Containers that wrap a script of a known language, and the module for a <script language=...>.
WRAPPERS = (".wsf", ".hta", ".sct",
            # Day 9 preparation (2026-10-08): more containers whose script sits in a <script> element. A .wsc is
            # a .sct by another name; the others get the general path's second look at the block alone, and
            # the VBScript or JScript module only when the element names that language.
            ".wsc", ".html", ".htm", ".xhtml", ".svg", ".xsl", ".xslt")
XML_WRAPPERS = (".wsf", ".sct", ".wsc", ".xhtml", ".svg", ".xsl", ".xslt")    # entities outside CDATA are undone
SCRIPT_OPEN = re.compile(r"(?i)<script\b([^<>]*)>")     # [^<>]: a run of unclosed tags is read once, not squared
SCRIPT_CLOSE = re.compile(r"(?i)</script\s*>")
HTML_COMMENT = re.compile(r"(?s)<!--.*?(?:-->|\Z)")     # a markup comment; one left open runs to the end

# Components of the answer ids: the three PowerShell specimens are named by tactic.
POWERSHELL_IDS = ("resource", "collection", "impact")
# The specimens the four modules were built and judged on (Days 1 to 4, every saved variant):
# `<prefix>-<role word>-<field>` with the language's own prefix and one of these nine role words.
# A specimen of a known extension whose ids are anything else (another prefix, another role
# word, `advanced` anywhere) is a new component and goes to solve_new (row 51, 2026-10-07): the
# modules answer what they were built for with plain names, and on a new component those were
# guesses (T1496, benign_utility, a comma-joined step list) that no live fix can override.
KNOWN_PREFIX = {"jscript": "jscript", "batch": "batch", "vbscript": "vbscript"}
KNOWN_ROLE_WORDS = ("benign", "chain", "downloader", "dropper", "impact", "launcher", "relay", "stager", "uploader")
SHOWN = 200          # characters of an answer printed in a stderr line
DECLINED_KEY = 40    # characters of a text reading that go into a `declined.<reading>` label key

_unloadable = set()  # language modules already reported as failing to import


def member_of(q) -> str:
    """The file a question is about: the runner's `member`, else the name after '->' in `artifact`."""
    art = q.get("artifact") or ""
    return q.get("member") or (art.split("->")[-1].strip() if "->" in art else "")


def module_for(q) -> str:
    ext = Path(member_of(q)).suffix.lower()
    return LANGUAGE.get(ext, ext.lstrip(".") or "unknown")


def shown(value) -> str:
    """An answer for a stderr line. Answers hold specimen text: escaped and cut."""
    s = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
    s = s.encode("ascii", "backslashreplace").decode("ascii").replace("\n", "\\n").replace("\r", "\\r")
    return s if len(s) <= SHOWN else s[:SHOWN] + "..."


def plain(value) -> bool:
    return value is not None and not (isinstance(value, str) and value.startswith("??"))


def garbled(value) -> bool:
    """Whether a plain text answer holds a character no answer of this lane ever held: a C0 or C1 control
    character (a tab and a line end too), DEL, the replacement character, a lone surrogate or a
    non-character. Such a value is the trace of a decode that went wrong (row 115)."""
    if not isinstance(value, str) or value.startswith("??"):
        return False
    return any(o < 32 or 127 <= o < 160 or o == 0xFFFD or 0xD800 <= o <= 0xDFFF or o in (0xFFFE, 0xFFFF)
               for o in map(ord, value))


def clean(got) -> dict:
    """A module's result without its empty answers."""
    return {k: v for k, v in (got or {}).items() if v is not None and v != ""} if isinstance(got, dict) else {}


def language_module(name):
    """The module of a known language, or None when it is hidden or does not import (one line)."""
    if not name or name in plan_codec.hidden():
        return None
    try:
        return importlib.import_module(name)
    except Exception as e:  # noqa: BLE001 - a module that cannot load is a language without a module
        if name not in _unloadable:
            _unloadable.add(name)
            print(f"[analyze] module {name} did not load ({type(e).__name__}: {e}); its questions go to generic",
                  file=sys.stderr)
        return None


def generic_module():
    return None if "generic" in plan_codec.hidden() else generic


# ---------------------------------------------------------------- the text path

def text_reading(lang: str, qs: list, text: str, ext: str):
    """({qid: answer}, the qids answered by the default branch) of one known-language specimen,
    from its text alone. The default branch is shapes_text's answer for a form it could not
    read: one of the family's names, under the key of what was not read."""
    got, note = plan_codec.reading(text, ext)
    if note:
        print(f"[analyze] the text path reads {'a shorter' if got else 'no'} plan from this {lang} specimen: {note}",
              file=sys.stderr)
    if note and not got:
        plan = {}
    else:
        plan = plan_codec.flatten(got[0]) if got else plan_codec.plan_of(text, ext)
    try:
        shapes, by_default = shapes_text.read(lang, text)
    except Exception as e:  # noqa: BLE001 - the plan fields below still stand
        print(f"[analyze] text shapes for {lang} raised {type(e).__name__}: {e}", file=sys.stderr)
        shapes, by_default = {}, set()
    out, defaulted = {}, set()
    for q in qs:
        tail = generic.tail_of(q)
        value = shapes.get(tail) if tail in SHAPE_FIELDS[lang] else \
            generic.plan_answer(q, plan, OWN_TECHNIQUE[lang], cut=bool(note and got))
        if lang == "batch" and tail == "expansion":
            value = batch_expansion(q, text, value)
        value = generic.listed(q, value)     # a name the question's own enum does not list is no answer
        if value is not None and value != "":
            out[q["qid"]] = value
            if tail in SHAPE_FIELDS[lang] and tail in by_default:
                defaulted.add(q["qid"])
    return out, defaulted


def batch_expansion(q: dict, text: str, value):
    """The text path's answer to a Batch expansion question, by the answer format the question comes with.

    shapes_text reads the form Days 3 to 11 judged (kind exact_text). Day 12's format (an enum of the four
    forms) asks for the form of the reconstruction statement as it is written, which is batch.py's
    statement_form; batch.expansion_answer holds the rule for both and for a format that is neither. Without
    the Batch module a question that lists its values gets no text-path answer: the old reading is not
    what that format was judged on."""
    mod = language_module("batch")
    if mod is None or not hasattr(mod, "expansion_answer") or not hasattr(mod, "statement_form"):
        return None if generic.accepted_values(q) is not None else value
    try:
        return mod.expansion_answer({"expansion": value, "expansion_statement": mod.statement_form(text)}, q)
    except Exception:  # noqa: BLE001 - a rule that fails gives no answer, never the other format's reading
        return None


def text_answers(lang: str, qs: list, text: str, ext: str) -> dict:
    """The answers of one known-language specimen from its text alone."""
    return text_reading(lang, qs, text, ext)[0]


def stand_in(lang: str, q: dict, name, shape=None):
    """What stands in for a shape name the module declined to give: labels.pick, so an unsure
    answer until the judge has accepted a name for its key, and that name from then on.

    The module saw something the judge has never named (two wrappers at once, an unjudged
    join), so the text path's reading is a candidate, not an answer: it goes first, then the
    names judged for this field of the language. The key holds that reading, so a name the
    judge accepts answers the same reading again. None when there is no such answer (no
    labels.py, a reading that is not a name, a question whose own list excludes them all)."""
    if labels is None or not isinstance(name, str):
        return None
    field = re.sub(r"[^a-z0-9]+", "_", generic.tail_of(q).lower()).strip("_")
    own = shape
    shape = shape or re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")[:DECLINED_KEY]
    if not field or not shape:
        return None
    try:
        family = f"script.{field}/{shapes_text.KEY_LANG[lang]}."
        return generic.listed(q, generic.pick(f"{family}{own}" if own else f"{family}declined.{shape}",
                                              [name] + [n for n in labels.family(family) if n != name]))
    except Exception:  # noqa: BLE001 - nothing to stand in, so no answer
        return None


# ---------------------------------------------------------------- wrapped scripts

def script_blocks(text: str, ext=None) -> list:
    """[(body, module name)] of every <script> block that has a body, in file order.

    A self-closing tag (`<script src="lib.vbs"/>`) and an empty block (an include) have no
    body and are left out. The module is None when the language attribute names neither
    VBScript nor JScript. A .wsf or .sct is XML: outside a CDATA section its script text
    carries entities (&amp; for VBScript's &), which are undone. An .hta is HTML, where script
    text is taken as written.

    A <script> element that opens inside a markup comment (`<!-- <script>..</script> -->`) is no element,
    and no script host runs it (Day 20 gaps: an older pair of descriptor copies kept there was read as the
    specimen's script and answered plain): it is passed over."""
    out, at = [], 0
    comments = None
    while True:
        m = SCRIPT_OPEN.search(text, at)
        if not m:
            return out
        at = m.end()
        if "<!--" in text[:m.start()]:
            if comments is None:
                comments = [(c.start(), c.end()) for c in HTML_COMMENT.finditer(text)]
            if any(a <= m.start() < b for a, b in comments):
                continue
        attrs = m.group(1)
        if attrs.rstrip().endswith("/"):
            continue
        close = SCRIPT_CLOSE.search(text, at)
        if not close:
            return out
        body, at = text[m.end():close.start()], close.end()
        cdata = re.search(r"(?s)<!\[CDATA\[(.*?)\]\]>", body)
        if cdata:
            body = cdata.group(1)
        elif ext in XML_WRAPPERS:
            body = html.unescape(body)
        if not body.strip():
            continue
        lang = re.search(r"""(?i)\blanguage\s*=\s*["']?([\w.]+)""", attrs) or \
            re.search(r"""(?i)\btype\s*=\s*["']?[\w.]+/([\w.]+)""", attrs)
        word = lang.group(1).lower() if lang else ""
        module = "vbscript" if word.startswith(("vbs", "vbscript")) else \
            "jscript" if word.startswith(("jscript", "javascript", "js", "ecmascript")) else None
        out.append((body, module))


def unwrap(text: str, ext=None):
    """(body, module name) of the script a .wsf, .hta or .sct file wraps; (None, None) when it
    has no <script> block with a body.

    A container can hold several blocks (an include, a helper, the specimen). The one that
    carries the plan is the specimen; when none does (or more than one), the first block with
    a body is taken, as the script host itself would start there."""
    blocks = script_blocks(text, ext)
    if not blocks:
        return None, None
    with_plan = []
    for block in blocks[:8]:
        try:
            if plan_codec.reading(block[0], ext)[0]:
                with_plan.append(block)
        except Exception:  # noqa: BLE001 - a block that cannot be read is a block without a plan
            pass
    return with_plan[0] if len(with_plan) == 1 else blocks[0]


def held(q: dict, value, ext: str):
    """A language module's answer about a script inside a new container, as sure as it is.

    Plan values and the judged role and technique tables carry over. A name the module gives
    (a control form, a code-derived representation) was judged for .vbs or .js, not for this
    extension: it is plain only when the question itself lists it, else unsure under the new
    extension's key. The own-interpreter technique is the generic candidate list."""
    name = plan_codec.ext_name(ext)
    tail, text = generic.tail_of(q), q.get("question") or ""
    if generic.asks_attack(q):                   # the id's word; the text only for an id that names no field
        return value if value in generic.ATTACK.values() else generic.pick(generic.own_key(name), generic.techniques(name))
    if tail in ALL_SHAPE_FIELDS:
        if not isinstance(value, str) or labels is None:
            return None
        allowed = generic.accepted_values(q)     # the answer format's own list first, then the names the text lists
        if value in (allowed if allowed is not None else labels.enum_from_question(text)):
            return value
        field = re.sub(r"[^a-z0-9]+", "_", tail.lower()).strip("_")
        shape = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
        return generic.pick(f"script.{field}/{name}.{shape}", [value]) if field and shape else None
    return value


def wrapped_answers(member: str, qs: list, have: dict, data, ext: str, ctx) -> dict:
    """What the body of a wrapper's <script> block adds to the answers generic gave (`have`).

    Open questions are asked of generic on the block alone (only when the whole file gave no
    plan) and then of the block's language module. The module is also asked the shape
    questions generic answered unsure (a census reading, an unlabelled codec): a module that
    has parsed the script names the form better than a language-blind count, so its name goes
    first among that answer's options."""
    whole = plan_codec.text_of(data)
    body, inner = unwrap(whole, ext)
    if not body or not body.strip():
        return {}
    inner_files, got = {member: body.encode("utf-8")}, {}
    todo = [q for q in qs if q["qid"] not in have]
    # generic has read the whole file already. The block alone is worth a second look only when
    # the file gave no plan (markup escapes around the material, a comment that reads as one).
    # (Day 9 preparation: also when the whole file gave a plan without its last field. Markup around a join,
    # `"ab" &amp; "cd"` or `&quot;..&quot;`, makes a piece of what the block alone, its entities undone, reads whole.)
    seen, note = plan_codec.reading(whole, ext)
    gen = generic_module() if todo and (note or not (seen or plan_codec.decode(whole, ext))) else None
    if gen is not None:
        try:
            got = clean(gen.answers(todo, inner_files, ctx))
        except Exception:  # noqa: BLE001
            print(f"[analyze] generic raised on the script block of {member}:\n{traceback.format_exc()}", file=sys.stderr)
    left = [q for q in todo if q["qid"] not in got]
    weak = [q for q in qs if q["qid"] in have and not plain(have[q["qid"]]) and generic.tail_of(q) in ALL_SHAPE_FIELDS]
    mod = language_module(inner) if inner and (left or weak) else None
    if mod is not None:
        try:
            said = clean(mod.answers(left + weak, inner_files, ctx))
        except Exception:  # noqa: BLE001
            said = {}
            print(f"[analyze] {inner} raised on the script block of {member}:\n{traceback.format_exc()}", file=sys.stderr)
        for q in left + weak:
            qid = q["qid"]
            if qid not in said:
                continue
            value = held(q, said[qid], ext)
            if qid in have and not plain(value):
                # generic's unsure answer keeps its key; the module's name leads its options.
                old = labels.parse(have[qid]) if labels is not None else None
                # (Its options as (name, value) pairs: a method-named one, `label` -> the file's own word, must
                # never go out as the name itself.)
                value = generic.pick(old.key, [(said[qid], said[qid])] + [(n, v) for n, v in old.options if v != said[qid]]) \
                    if old is not None and old.key and isinstance(said[qid], str) else None
            value = generic.listed(q, value)
            if value is not None:
                got[qid] = value
    return got


# ---------------------------------------------------------------- one specimen

def unnamed_shape(mod, member: str) -> str:
    """The construct word of a form a module reported as having no judged name: `for` for every plain FOR
    (the key script.control/batch.unread_for, which the text path's unread FOR forms use), else the module's
    own word for it."""
    word = str((getattr(mod, "UNNAMED_KIND", None) or {}).get(member) or "for")
    word = re.sub(r"[^a-z0-9]+", "_", word.lower()).strip("_") or "for"
    return "for" if word in ("for_in", "for") else word


def solve_known(lang: str, mod, member: str, qs: list, files: dict, ctx) -> dict:
    """A specimen of a language with a module: the module, then the text path as net and check."""
    raised = False
    try:
        got = clean(mod.answers(qs, files, ctx))
    except Exception:  # noqa: BLE001 - one specimen's failure must not sink the set
        raised, got = True, {}
        print(f"[analyze] {lang} raised on {member}:\n{traceback.format_exc()}", file=sys.stderr)
    # The module's answers are ready now. The text path below only adds to them, so a time
    # limit that falls inside it must not take them along.
    # Row 115: a garbled plain value is taken out before anything can submit it (the partial table
    # included); below, the text path's printable reading may stand in for it.
    bad = {qid: got.pop(qid) for qid in [k for k, v in got.items() if garbled(v)]}
    keep_partial(ctx, got)

    def dropped():
        for qid, value in bad.items():
            if qid not in got:
                print(f"[analyze] {qid}: {lang} gave a value with a control or non-printable character "
                      f"({shown(value)}); not answered", file=sys.stderr)
        return got
    if lang not in OWN_TECHNIQUE:
        return dropped()
    data = generic.find(files, member)
    if data is None:
        return dropped()
    try:
        text, defaulted = text_reading(lang, qs, plan_codec.text_of(data), Path(member).suffix.lower())
    except Exception:  # noqa: BLE001
        print(f"[analyze] the text path raised on {member}:\n{traceback.format_exc()}", file=sys.stderr)
        return dropped()
    text = {k: v for k, v in text.items() if not garbled(v)}
    answered = set(got)   # what the module itself answered, before any fill
    shape_ids = {q["qid"] for q in qs if generic.tail_of(q) in SHAPE_FIELDS[lang]}
    for q in qs:
        qid = q["qid"]
        a, b = got.get(qid), text.get(qid)
        if qid in bad:
            # The module answered and its value is garbage: that is no declined answer, and the fill
            # rules below (written for a module that said nothing) do not apply. Only the text path's
            # own plain reading may stand, and not a default-branch name.
            if plain(b) and qid not in defaulted:
                got[qid] = b
                print(f"[analyze] {qid}: {lang} gave a value with a control or non-printable character "
                      f"({shown(bad[qid])}); the text path's reading stands", file=sys.stderr)
            continue
        if a is None and b is not None:
            # A module that ran and answered its other questions has declined this one, so the
            # text path's own plain reading is a guess: a shape name is held as unsure, a plan
            # value stays unanswered. Plain fills remain for a raise, for no answer at all, and
            # for a walk that gave no shape, and for a plan value of a module that never declines
            # one (see DECLINES_PLAN). A default-branch answer is not the text path's own
            # reading: it is unsure, or the name the judge accepted for what was not read.
            declined = not raised and bool(answered & shape_ids if qid in shape_ids
                                           else answered and lang in DECLINES_PLAN)
            # Review of 2026-10-12: the module SAID the form around the join has no judged name (batch.UNNAMED:
            # `for %%Q in (1) do <statement>` on one line, where it gave no expansion either, so the walk
            # "gave no shape" and the text path's `goto_dispatch` was filled plain). That is a declined answer
            # whatever else it answered: held unsure under the key its neighbouring forms use.
            unnamed = generic.tail_of(q) in (getattr(mod, "UNNAMED", None) or {}).get(member, ()) and not raised
            if (declined or unnamed) and plain(b) and qid not in defaulted:
                reading = b
                b = stand_in(lang, q, reading, f"unread_{unnamed_shape(mod, member)}" if unnamed else None) \
                    if qid in shape_ids else None
                if b is None:
                    print(f"[analyze] {qid}: {lang} declined it; the text path's plain answer {shown(reading)} is not used",
                          file=sys.stderr)
                    continue
            got[qid] = b
            print(f"[analyze] {qid}: filled from the text path ({lang} {'raised' if raised else 'gave no answer'})"
                  f"{'' if plain(b) else ', unsure'}", file=sys.stderr)
        elif plain(a) and plain(b) and a != b:
            print(f"[analyze] paths disagree on {qid}: module={shown(a)} text={shown(b)}", file=sys.stderr)
    return dropped()


def live_shapes(member: str, qs: list, got: dict, files: dict) -> dict:
    """What shapes_<ext>.py adds on a specimen of a KNOWN language.

    It is asked only the ids that have no plain answer after the module and the text path: a
    new field, a new kind of specimen, an answer the module declined, a name that is still
    unsure. The call is the one generic.py makes for a new extension: shapes(text, questions)
    -> {qid: value}, with this file's text and those questions. A plain answer of the solver
    is never replaced. Without such a file, or with nothing open, nothing changes; a file that
    raises costs its own answers only."""
    left = [q for q in qs if not plain(got.get(q["qid"]))]
    name = plan_codec.ext_name(Path(member or "").suffix)
    fix = plan_codec.optional(f"shapes_{name}") if left and name else None
    data = generic.find(files, member) if fix is not None and hasattr(fix, "shapes") else None
    if data is None:
        return {}
    try:
        found = fix.shapes(plan_codec.text_of(data), left)
    # SystemExit too: a sys.exit() in a live fix must not end the solver. The runner's time limit
    # arrives as another BaseException and passes through.
    except (Exception, SystemExit):  # noqa: BLE001 - a broken live fix costs its own answers only
        print(f"[analyze] shapes_{name} raised on {member}:\n{traceback.format_exc()}", file=sys.stderr)
        return {}
    if not isinstance(found, dict):
        print(f"[analyze] shapes_{name}.shapes returned {type(found).__name__}, not a table, on {member}",
              file=sys.stderr)
        return {}
    out = {}
    for q in left:
        qid = q["qid"]
        given = found.get(qid)
        if given is None or given == "":
            continue
        try:
            json.dumps(given)       # an answer is text or a JSON value: the runner has to serialize it
            value = generic.listed(q, given)
            if value is not None and not plain(value):
                parsed = labels.parse(value) if labels is not None else None
                if parsed is None or not parsed.key or not parsed.options:
                    value = None    # an unsure answer nothing can probe is no answer
        except Exception:  # noqa: BLE001 - a value that cannot be an answer is no answer
            given, value = repr(given), None
        if value is None:
            print(f"[analyze] {qid}: the answer of shapes_{name}.py ({shown(given)}) is not used: it is no JSON "
                  f"value, the question does not list it, or it is an unsure answer without a key or an option",
                  file=sys.stderr)
            continue
        out[qid] = value
        print(f"[analyze] {qid}: answered by shapes_{name}.py{'' if plain(value) else ', unsure'}"
              f"{'' if got.get(qid) is None else ' (in place of the unsure answer of the solver)'}", file=sys.stderr)
    return out


def encoded_view(member: str, files: dict):
    """(files, problem): the delivery as the readers see it when the specimen is a file the
    script host decodes (a .vbe or .jse, or an Encode <script> element of a .wsf, .hta, .sct
    or .wsc: screnc.decode_hosted) and holds Script Encoder blocks there, each replaced by its
    decoded text; the very same `files` otherwise (any other extension, a non-Encode element,
    no block). problem is the reason a block the host would decode does not decode, and then
    no reading of the file is given at all. Only the specimen's own bytes are replaced (every
    key that holds them); the other files of the delivery are left as they are."""
    ext = Path(member or "").suffix.lower()
    if not screnc.hosted(ext):
        return files, None
    data = generic.find(files, member)
    if not isinstance(data, (bytes, bytearray)) or not screnc.has_marker(data):
        return files, None
    text, info = screnc.decode_hosted(plan_codec.text_of(data), ext)
    if text is None:
        return files, info
    if not info:
        return files, None
    raw = text.encode("utf-8")
    view = {k: (raw if v is data else v) for k, v in files.items()}
    view.setdefault(member, raw)
    print(f"[analyze] {member}: {info} Script Encoder block{'' if info == 1 else 's'} decoded (checksum verified)",
          file=sys.stderr)
    return view, None


def office_view(member: str, files: dict):
    """(files, member, problem): an Office document that holds macros as its macro text under a
    `.bas`/`.xlm` name (officevba.routed); the same files and member otherwise. problem is why a
    macro container does not read, and then nothing of it is read.

    A macro text that gives no plan candidate at all (no plan, and no two plans either: a stub
    macro that only reads the document body) while the raw bytes give one plan is not the reading:
    the member is read as its raw bytes, as before row 93, where a plan kept in the body is found
    as it always was. A macro text with no plan and raw bytes with none (a benign macro) stays the
    reading."""
    got = officevba.routed(member, files, generic.find) if officevba is not None else None
    if got is None:
        return files, member, None
    view, virtual, problem = got
    if problem or virtual == member:
        return got
    text, ext = plan_codec.text_of(view[virtual]), Path(virtual).suffix.lower()
    if (plan_codec.decode(text, ext) is None and plan_codec.reading(text, ext)[1] is None
            and plan_codec.optional(f"lang_{plan_codec.ext_name(ext)}") is None     # a racer's module reads its own way
            and plan_codec.decode(plan_codec.text_of(generic.find(files, member)), Path(member).suffix.lower())):
        print(f"[analyze] {member}: its macro text gives no plan; the document is read as its bytes", file=sys.stderr)
        return files, member, None
    return got

def node_view(member: str, qs: list, files: dict):
    """(member, qs, files): a Node packaging (nodepkg.py, row 94: pkg, nexe, a single executable,
    a bytenode .jsc, a Bun or Deno executable) read as the script it holds. The specimen is
    handed to the general path under a name of its own, `<member>.<kind>` (so its label keys are
    `script.<field>/<kind>...`, never another container's), with that script's text as its
    bytes. Only when that text gives a plan; otherwise, and for any file that is not such a
    packaging (every extension with a module, every wrapper and every text file), the three
    come back unchanged and the file is read as before."""
    ext = Path(member or "").suffix.lower()
    if ext in LANGUAGE or ext in WRAPPERS or screnc.hosted(ext):
        return member, qs, files
    data = generic.find(files, member)
    got = nodepkg.view(member, data) if isinstance(data, (bytes, bytearray)) else None
    if got is None:
        return member, qs, files
    kind, text, notes = got
    name = f"{member}.{kind}"
    if not text or not generic.read(name, text)["plan"]:
        print(f"[analyze] {member}: a {kind} packaging ({'; '.join(notes)}) gives no plan; read as it is",
              file=sys.stderr)
        return member, qs, files
    print(f"[analyze] {member}: a {kind} packaging ({'; '.join(notes)}); its script is read as {name}",
          file=sys.stderr)
    view = dict(files)
    view[name] = text.encode("utf-8")
    return name, [dict(q, member=name) for q in qs], view


INNER_EXTS = (".hta", ".htm", ".html", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".ps1", ".bat", ".cmd", ".php", ".py",
              ".sh", ".au3", ".ahk", ".lua", ".rb", ".pl", ".applescript")
INNER_FILES = 256            # inner files of one container that are read for a plan: more, and none is
INNER_BYTES = 256 << 10      # bytes of one inner text that is read for a plan: larger, and none is
INNER_TOTAL = 512 << 10      # bytes of inner text read for a plan in one container (the general path reads
                             # about a megabyte of ordinary text a second): more, and none is
INNER_SECONDS = 1.0          # the time reading them may take on a clock (the sizes above bind first)
STRINGS_MAX = 8 << 20        # bytes of a binary carrier that are searched for strings
STRING_MIN = 8               # characters: shorter runs are noise
BINARY_RAW_MAX = 64 << 10    # bytes of a binary member the general path reads as it is. Review of round 2
                             # (2026-10-08): it reads binary bytes as text at about a second a megabyte, three
                             # times over (2 MB of random bytes: 4.3 s; Apache Tika's 10.8 MB testChm2.chm:
                             # 37 s; with no deadline anywhere in the lane). A larger one is read as its
                             # strings only, which costs 20 ms a megabyte
STRINGS_TEXT_MAX = 512 << 10  # characters of strings text the general path reads: more, and the member is not read
_NARROW = re.compile(rb"[\x20-\x7e\t]{%d,}" % STRING_MIN)
_WIDE = re.compile(rb"(?:[\x20-\x7e\t]\x00){%d,}" % STRING_MIN)


def is_binary(data) -> bool:
    """No text file: a NUL among its first bytes and no UTF-16 byte-order mark."""
    return b"\x00" in bytes(data[:4096]) and bytes(data[:2]) not in (b"\xff\xfe", b"\xfe\xff")


def strings_of(data: bytes) -> str:
    """The runs of printable characters of a binary file, 8-bit and UTF-16LE, one a line, in file order."""
    data = bytes(data[:STRINGS_MAX])
    runs = [(m.start(), m.group(0).decode("latin-1")) for m in _NARROW.finditer(data)]
    runs += [(m.start(), m.group(0).decode("utf-16-le")) for m in _WIDE.finditer(data)]
    return "\n".join(s for _, s in sorted(runs)) + "\n" if runs else ""


def _plan_key(plan: dict) -> tuple:
    return tuple(sorted((str(k), str(v)) for k, v in plan.items()))


def container_view(member: str, qs: list, files: dict, ctx=None):
    """(member, qs, files): a binary carrier (carriers.inner: a .chm, a OneNote section, a shell link, a
    compiled AutoIt or AutoHotkey script, a compiled AppleScript) read as the ONE script it holds, under the
    name `<member>.<that file's extension>` (the container's kind when the inner file has no script
    extension). Only when exactly one plan is read from the inner files: none, or two that differ, leave the
    three as they came, and the file is read as before (as it is, then as its strings). An inner text that
    is itself a strings view (a compiled AppleScript) is named in ctx["strings_views"], as strings_view does.

    "The one plan" is a statement about all the carrier holds (review of round 2, 2026-10-08: five carriers
    with a second, different plan outside what the reader looked at were each answered in full, plain):
      - carriers.inner gives nothing for a container it did not read in full (carriers.Incomplete);
      - an inner file that is no text is read as its strings, and a plan there counts as a plan;
      - an inner file whose own reading is ambiguous (two plans in one file) is no reading;
      - the strings of the whole carrier (what was read before this reader existed: bytes between and behind
        the container's objects) must not hold another plan, nor two.
    Any of them leaves the file to be read as before."""
    ext = Path(member or "").suffix.lower()
    if carriers is None or ext in LANGUAGE or ext in WRAPPERS or screnc.hosted(ext):
        return member, qs, files
    data = generic.find(files, member)
    got = carriers.inner(member, data) if isinstance(data, (bytes, bytearray)) else None
    if got is None:
        return member, qs, files
    kind, inner, notes, loose = got

    def as_before(why):
        print(f"[analyze] {member}: a {kind} container ({'; '.join(notes)}) {why}; read as it is", file=sys.stderr)
        return member, qs, files

    if len(data) > STRINGS_MAX:
        return as_before("is larger than the part whose strings are read")
    inner = [(name, blob) for name, blob in inner if len(blob) >= 24]
    is_text = getattr(carriers, "is_text", lambda name, blob: True)
    texts = []                                   # (inner name, what is read, read as strings)
    for name, blob in inner:
        if loose or is_text(name, blob):
            texts.append((name, blob, loose))
        else:
            runs = strings_of(blob).encode("utf-8")
            if len(runs) >= 24:
                texts.append((name, runs, True))
    if len(texts) > INNER_FILES or any(len(t) > INNER_BYTES for _, t, _ in texts) \
            or sum(len(t) for _, t, _ in texts) > INNER_TOTAL:
        # "Exactly one plan" is a statement about everything the container holds: when not all of it can be
        # read here, nothing is said, and the file is read as before.
        return as_before(f"holds more than is read on a clock ({len(texts)} files, "
                         f"{sum(len(t) for _, t, _ in texts)} bytes)")
    found = {}
    started = time.perf_counter()
    for name, blob, as_strings in texts:
        if time.perf_counter() - started > INNER_SECONDS:
            return as_before(f"took more than {INNER_SECONDS:g} s to read")
        inner_ext = Path(name).suffix.lower()
        virtual = f"{member}{inner_ext if inner_ext in INNER_EXTS else '.' + kind}"
        try:
            info = generic.read(virtual, blob, as_strings)
        except Exception as e:  # noqa: BLE001 - an inner file that does not read may hold what was not seen
            return as_before(f"holds a file that does not read ({type(e).__name__})")
        if info["plan"]:
            found.setdefault(_plan_key(info["plan"]), (virtual, blob, name, as_strings, info["plan"]))
        elif info.get("ambiguous"):
            return as_before(f"holds a file that gives two readings "
                             f"({name.encode('ascii', 'backslashreplace').decode()[:60]})")
    if len(found) != 1:
        return as_before("gives no plan" if not found else f"gives {len(found)} plans that differ")
    virtual, blob, name, as_strings, plan = next(iter(found.values()))
    if as_strings and not loose:
        return as_before("holds its one plan in a file that is no text")
    # 2026-10-13: a compiled AppleScript's text is UTF-16BE, and strings_of reads 8-bit and UTF-16LE runs: a
    # big-endian run read one byte late is the same text without its last character, a "second plan" that is
    # no plan (a real osacompile output was refused for it). Its inner text is already every string of the
    # whole file, read by the reader that knows the byte order (carriers.scpt_strings): that is held here.
    text = bytes(blob).decode("utf-8", "replace") if kind == "scpt" and loose else strings_of(data)
    if len(text) > STRINGS_TEXT_MAX:
        return as_before("holds more strings than are read")
    try:
        outer = generic.read(member, text, True) if text else {"plan": {}}
    except Exception as e:  # noqa: BLE001
        return as_before(f"has strings that do not read ({type(e).__name__})")
    differ = [k for k, v in (outer.get("plan") or {}).items() if str(plan.get(k)) != str(v)]
    if differ or outer.get("ambiguous"):
        return as_before("holds its plan in one file, and its strings hold another"
                         + (f" ({ascii(str(differ[0]))[:40]} differs)" if differ else " (two readings)"))
    print(f"[analyze] {member}: a {kind} container ({'; '.join(notes)}); "
          f"{name.encode('ascii', 'backslashreplace').decode()[:80]} is read as {virtual}", file=sys.stderr)
    view = dict(files)
    view[virtual] = bytes(blob)
    if loose and isinstance(ctx, dict):
        ctx.setdefault("strings_views", set()).add(virtual)
    return virtual, [dict(q, member=virtual) for q in qs], view


def strings_view(member: str, files: dict, ctx=None):
    """`files` with a binary carrier's bytes replaced by the text of its strings (strings_of), when the
    member is no text file (a NUL among its first bytes), gives no plan as it is and gives one as its
    strings; the very same `files` otherwise. The member is named in ctx["strings_views"], so that the
    general path knows this text's line ends are not the file's own (generic.read: loose_lines).

    A binary member over BINARY_RAW_MAX is never read as it is (see there): it is always replaced by its
    strings, plan or none, and by nothing when even those are more than STRINGS_TEXT_MAX."""
    ext = Path(member or "").suffix.lower()
    data = generic.find(files, member)
    if ext in LANGUAGE or not isinstance(data, (bytes, bytearray)) or not is_binary(data):
        return files
    large = len(data) > BINARY_RAW_MAX
    text = strings_of(data)
    if len(text) > STRINGS_TEXT_MAX:
        print(f"[analyze] {member}: a binary file whose strings alone are {len(text)} characters: not read",
              file=sys.stderr)
        text = ""
    as_it_is = None if large else generic.read(member, data)["plan"]
    if as_it_is:
        # The bytes read as text show 8-bit text only. A second plan the strings show (UTF-16 text, as a
        # shell link's arguments are) makes two plans, and two are none: the strings are read, which says so.
        outer = generic.read(member, text, True) if text else {"plan": {}}
        differ = [k for k, v in (outer.get("plan") or {}).items() if str(as_it_is.get(k)) != str(v)]
        if not differ and not outer.get("ambiguous"):
            return files
        if differ:
            print(f"[analyze] {member}: no text file, and its strings hold another plan than its bytes read as "
                  f"text do ({ascii(str(differ[0]))[:40]} differs): not read", file=sys.stderr)
            text = ""
    elif not large and (not text or not generic.read(member, text, True)["plan"]):
        return files
    if isinstance(ctx, dict):
        ctx.setdefault("strings_views", set()).add(member)
    print(f"[analyze] {member}: no text file and {'too large to be read as it is' if large else 'no plan as it is'}; "
          f"read as the strings it holds ({text.count(chr(10))} runs)", file=sys.stderr)
    raw = text.encode("utf-8")
    view = {k: (raw if v is data else v) for k, v in files.items()}
    view[member] = raw
    return view


def keep_partial(ctx, got: dict):
    """Copy answers into ctx['partial'] when the runner passed that key."""
    if isinstance(ctx, dict) and isinstance(ctx.get("partial"), dict):
        ctx["partial"].update(got)


def solve_new(member: str, qs: list, files: dict, ctx) -> dict:
    """A specimen with no language module: lang_<ext>.py if there is one, then generic."""
    ext = Path(member or "").suffix.lower()
    name = plan_codec.ext_name(ext)
    got = {}
    fix = plan_codec.optional(f"lang_{name}") if name and ext not in LANGUAGE else None
    if fix is not None and hasattr(fix, "answers"):
        try:
            got = clean(fix.answers(qs, files, ctx))
        except Exception:  # noqa: BLE001
            print(f"[analyze] lang_{name} raised on {member}:\n{traceback.format_exc()}", file=sys.stderr)
    left = [q for q in qs if q["qid"] not in got]
    gen = generic_module()
    if left and gen is None and fix is None:
        print(f"[analyze] no module for {ext or 'a file without an extension'} ({len(left)} questions of {member})",
              file=sys.stderr)
    if left and gen is not None:
        try:
            filled = clean(gen.answers(left, files, ctx))
        except Exception:  # noqa: BLE001
            filled = {}
            print(f"[analyze] generic raised on {member}:\n{traceback.format_exc()}", file=sys.stderr)
        got.update(filled)
        if fix is not None:
            for qid in filled:
                print(f"[analyze] {qid}: filled by generic (lang_{name} gave no answer)", file=sys.stderr)
    data = generic.find(files, member) if ext in WRAPPERS else None
    if data is not None:
        try:
            got.update(wrapped_answers(member, qs, got, data, ext, ctx))
        except Exception:  # noqa: BLE001
            print(f"[analyze] reading the script block of {member} raised:\n{traceback.format_exc()}", file=sys.stderr)
    return got


def known_component(lang: str, qs: list) -> bool:
    """Whether every id of a known-language specimen is of a component its module was built on
    (KNOWN_PREFIX, KNOWN_ROLE_WORDS; for PowerShell a first word in POWERSHELL_IDS)."""
    for q in qs:
        words = generic.bare_id(q).split("-")
        if "advanced" in words:
            return False
        if lang == "powershell":
            if words[0] not in POWERSHELL_IDS:
                return False
        elif len(words) < 3 or words[0] != KNOWN_PREFIX.get(lang) or words[1] not in KNOWN_ROLE_WORDS:
            return False
    return True


def ordered(lang: str, qs: list, got: dict) -> dict:
    """A module's plain answer to a question that asks for joined tokens (an ordered step list), in the
    form the question states (generic.formatted): the modules give the plan's own comma-joined text. Other
    questions are left as they are. For every language with a module (Day 13 preparation: Batch was left
    out, and `batch-*-steps` came back comma-joined where the answer format asks for `>`): the separator is
    the answer format's, never a language's habit."""
    for q in qs:
        fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
        value = got.get(q["qid"])
        if plain(value) and isinstance(value, str) and (
                fmt.get("kind") == "ordered_tokens" or generic.stated_separator(q)
                or (generic.tail_of(q) == "steps" and generic.STEP_LIST.fullmatch(value))):
            shaped = generic.formatted(q, value)
            if shaped is None:
                got.pop(q["qid"])
            else:
                got[q["qid"]] = shaped
    return got


# The fields each module was built and judged on: every field word of its component in the saved keys of Days
# 1 to 12 (base, Time Trial and Mastery). A module answers an id by its last words, and for a word outside its
# own table it looks the word up in the specimen's plan (batch.field_of: `indicator:<tail>`; the text path
# does the same for JScript and VBScript). So a field no day asked of the component came back plain: Batch
# answered `-next-language` with the literal `none` (its version-1 plan does hold `next_language=none`),
# `-steps` and `-stage-count` with the plan's raw values. The plan's value is a fact; that it is the answer
# to a question nobody has asked is not.
MODULE_FIELDS = {
    "powershell": ("scenario", "attack", "url", "file", "user-agent", "extension", "note", "wallet", "mutex"),
    "jscript": ("role", "attack", "adapter", "campaign", "host", "function-style", "invocation-style", "property-style",
                "url", "path", "next-stage", "extension", "note"),
    "batch": ("role", "attack", "adapter", "campaign", "url", "expansion", "control", "graph", "file-path", "next-stage",
              "host-id", "upload-url", "note-name"),
    "vbscript": ("role", "attack", "adapter", "campaign", "host-id", "representation", "transform", "control", "url",
                 "file-path", "upload-url", "extension", "next-stage"),
}
STEP_LIST = re.compile(r"[a-z][a-z0-9_]*(?:,[a-z][a-z0-9_]*)+")


def plan_key_value(plan: dict, tail: str):
    """The value of the plan key an id's field word names exactly (`next-language` for next_language, `stage-count`
    for stage_count or stageCount), as text; None when the plan holds no such key or no scalar under it."""
    snake = tail.replace("-", "_")
    parts = snake.split("_")
    for key in (snake, parts[0] + "".join(p.title() for p in parts[1:])):
        if key in plan:
            v = plan[key]
            if isinstance(v, (list, tuple)) and v and all(isinstance(x, str) for x in v):
                return ",".join(v)
            return generic.scalar(v)
    return None


def unjudged(lang: str, member: str, qs: list, got: dict, files: dict) -> dict:
    """A module's plain answer to a field no day has asked of its component (MODULE_FIELDS), as sure as it
    is: an unsure answer, `script.<field>/<ext>.plan_key` with the one option `as_read`, when the specimen's
    plan really holds a key of that very name and the text path reads the same value from it; else nothing.
    A step list goes out in the forms generic.step_list gives it for the question's format, under this key.

    One word stays the module's own (judged_word, review of 2026-10-12): the plan's longer name of a judged
    field, when the plan holds a key of exactly that name (`campaign-id` beside `campaign`, whose judged
    answer is the plan's campaign_id; JScript's `file-path` beside `path`). A word that only begins or ends
    like a judged field (`url-host`, `attack-v2`) is a new field: the modules read an id by its ending and
    answered those as `-url` and `-attack`, plain."""
    fields = MODULE_FIELDS.get(lang, ())
    new = [q for q in qs if plain(got.get(q["qid"])) and generic.tail_of(q) not in fields]
    if not new:
        return got
    ext = Path(member or "").suffix.lower()
    plan = {}
    try:
        data = generic.find(files, member)
        text = plan_codec.text_of(data) if data is not None else ""
        seen, note = plan_codec.reading(text, ext)
        if not note:
            plan = plan_codec.flatten(seen[0]) if seen else plan_codec.plan_of(text, ext)
    except Exception:  # noqa: BLE001 - no second reading of the plan: nothing vouches for the value
        plan = {}
    name = plan_codec.ext_name(ext) or "ext"
    for q in new:
        qid, tail = q["qid"], generic.tail_of(q)
        value = got[qid]
        raw = plan_key_value(plan or {}, tail)
        if raw is not None and str(value) == raw and any(generic.near_key(f, tail.replace("-", "_")) for f in fields):
            continue                             # judged_word: the plan's own name of a judged field
        got.pop(qid)
        shaped = generic.formatted(q, generic.listed(q, raw)) if raw is not None else None
        options = []
        if isinstance(value, str) and isinstance(shaped, str):
            if plain(shaped) and value in (raw, shaped):
                options = [("as_read", shaped)]
            elif not plain(shaped):              # a step list in a form no day judged: generic.step_list's options
                parsed = labels.parse(shaped) if labels is not None else None
                options = list(parsed.options) if parsed is not None and parsed.key else []
        field = re.sub(r"[^a-z0-9]+", "_", tail.lower()).strip("_")
        held_ = generic.listed(q, generic.pick(f"script.{field}/{name}.plan_key", options)) if options and field else None
        if held_ is None:
            print(f"[analyze] {qid}: {lang} answered a field no day has asked of it ({shown(value)}); "
                  f"the plan holds no key of that name, or reads otherwise: not answered", file=sys.stderr)
            continue
        got[qid] = held_
        print(f"[analyze] {qid}: a field no day has asked of {lang}; the plan's own value is held unsure", file=sys.stderr)
    return got


def solve_module(lang: str, mod, member: str, qs: list, files: dict, ctx) -> dict:
    """A specimen of a language with a module, with what the modules cannot know about a field word they
    have never seen (Day 13 preparation). The module, the text path and the answer format's separator are
    as before for every id of Days 1 to 12. Around them:

      a renamed field   an id whose field word is an alias of a field, or a field with one more word
                        (generic.renamed), is asked of the module under the field it stands for, and its
                        answer is sent unsure (generic.reworded); the modules read an id by its ending, and
                        `-graph-attack` got the attack answer plain;
      an unjudged field see unjudged()."""
    hows = {q["qid"]: generic.renamed(q) for q in qs}
    hows = {qid: how for qid, how in hows.items() if how is not None}
    if not hows:
        return unjudged(lang, member, qs, ordered(lang, qs, solve_known(lang, mod, member, qs, files, ctx)), files)
    asked, twins, stands = {q["qid"] for q in qs}, [], {}
    for q in qs:
        how = hows.get(q["qid"])
        if how is None:
            continue
        cut = len(generic.tail_of(q)) if how[1] == "new" else len(how[2])
        twin_id = q["qid"][:len(q["qid"]) - cut] + how[0]
        stands[q["qid"]] = twin_id
        if twin_id not in asked and all(t["qid"] != twin_id for t in twins):
            twins.append({**q, "qid": twin_id, "id": twin_id, "field": how[0]})
    # The module is not handed the runner's partial table: a twin's id is no answer id of the attempt.
    quiet_ctx = {k: v for k, v in ctx.items() if k != "partial"} if isinstance(ctx, dict) else ctx
    work = [q for q in qs if q["qid"] not in hows] + twins
    got = unjudged(lang, member, work, ordered(lang, work, solve_known(lang, mod, member, work, files, quiet_ctx)), files)
    name = plan_codec.ext_name(Path(member or "").suffix) or "ext"
    out = {qid: v for qid, v in got.items() if qid in asked}
    for q in qs:
        how = hows.get(q["qid"])
        if how is not None:
            value = generic.reworded(q, how, got.get(stands[q["qid"]]), name)
            if value is not None:
                out[q["qid"]] = value
    return out


def id_forms(member: str, qs: list, got: dict, answer, ctx) -> dict:
    """The ids nothing answered, asked once more in the form the lane knows (generic.normal_ids; Day 13
    preparation, 2026-10-12: a `-v2` behind every id left 835 of 855 unanswered, upper-case ids 779, `_` for
    `-` 575, a `d13-` or `script-` prefix 51).

    Only when the specimen has an unanswered id whose raw form is NOT one the lane knows and whose normal
    form is: lower case, `-` between the words, no `dNN-` / `dayNN-` / lane-word prefix, no `-vN` / `-N`
    suffix. Then the whole specimen is solved again under the normal ids (so the field words compare as on
    a known day), and each id that had no answer takes the one its normal id got, never plain:
    labels.pick('script.id_form/<transform>', [('same_field', value)]), ONE key a transform for the whole
    base, so one probe on the base settles every id of that form. An answer that is unsure already stays
    as it is. An id of a known form is never renamed, and an answer the raw id reached is never replaced."""
    missing = [q for q in qs if got.get(q["qid"]) in (None, "")]
    if not missing:
        return got
    twins = generic.normal_ids(qs, known_words())
    if not twins or not any(q["qid"] in twins for q in missing):
        return got
    work = [dict({k: v for k, v in q.items() if k != "field"}, qid=twins[q["qid"]][0], id=twins[q["qid"]][0])
            if q["qid"] in twins else q for q in qs]
    # The runner's partial table is not handed down: a normal id is no answer id of the attempt.
    quiet = {k: v for k, v in ctx.items() if k != "partial"} if isinstance(ctx, dict) else ctx
    again = answer(generic.with_fields(work), quiet)
    for q in missing:
        if q["qid"] not in twins:
            continue
        twin, transform = twins[q["qid"]]
        value = again.get(twin)
        if value in (None, ""):
            continue
        if plain(value):
            value = generic.pick(f"script.id_form/{transform}", [("same_field", value)])
        if value is not None:
            got[q["qid"]] = value
            print(f"[analyze] {q['qid']}: answered as {twin} ({transform}), unsure", file=sys.stderr)
    return got


_KNOWN_WORDS = []


def known_words() -> set:
    """The first words of the ids the lane knows: the saved components, and those of the newest saved base."""
    if not _KNOWN_WORDS:
        _KNOWN_WORDS.append(set(generic.ID_WORDS) | {w for w in base_components() if w} | set(POWERSHELL_IDS))
    return _KNOWN_WORDS[0]


def _chain(q) -> list:
    """The container chain a question names: `delivery 1: evidence.zip -> stage-1.zip -> x.js` is
    ['evidence.zip', 'stage-1.zip', 'x.js']."""
    parts = [p.strip() for p in str(q.get("artifact") or "").split("->")]
    if parts and parts[0]:
        parts[0] = re.sub(r"^delivery\s+\d+\s*:\s*", "", parts[0])
    return [p for p in parts if p]


def as_expanded(files: dict, ctx) -> bool:
    """Whether `files` is the expansion of the delivery ctx names: tools/run.py's split_sets puts the delivery's
    own bytes under its name, and hands the same bytes over as ctx["delivery"]."""
    if not isinstance(ctx, dict):
        return False
    name, data = ctx.get("delivery_name"), ctx.get("delivery")
    if not isinstance(name, str) or not name or not isinstance(data, (bytes, bytearray)) or not data:
        return False
    held = files.get(name)
    return held is data or (isinstance(held, (bytes, bytearray)) and len(held) == len(data) and held == data)


def same_name_members(specimens: dict, files: dict) -> dict:
    """{member: bytes, or None} for every asked member whose NAME the delivery holds more than once with
    DIFFERENT bytes (built 2026-10-13 for Day 14: a second container with a file of the same name).

    tools/run.py keys a nested member by its immediate container's own name (`stage.zip -> x.js`) and by its
    bare name, first come first kept, and every module here looks a specimen up by the bare name: with two
    files of one name the specimen was answered from whichever the archive listed first (staged: 275 of 913
    answers wrong). Since backlog row 303 run.py ALSO records a full-path key (`evidence.zip -> a.zip ->
    stage.zip -> x.js`) for each copy, but only when a container key is overwritten (two inner archives of one
    name), and marks a
    chain that covers two bodies `<chain> #1`, `<chain> #2`. The question says which one it means: when its
    own container chain is itself a full-path key and that chain is not ambiguous (no `<chain> #N`), the bytes
    are that key's. Failing that, the bytes are those of the one key that ends in the longest tail of the
    question's own container chain (at least a container and the name). When no key does, or the keys that do
    hold different bytes, nothing says which file is asked: None, and the specimen is not answered. A name
    held once, or more than once with the same bytes, is not in the result, and nothing changes for it (every
    delivery saved through Day 13). Never the bare name alone.

    Two more ways to None (the review of 2026-10-13). A path key is `<container> -> <member>` with the
    container's own name only, so two containers of one name write the same key and the later one wins:
      - the bare copy's bytes are under no `->` key at all: a path key was overwritten, and what is left
        under it is not what its name says (two `stage.zip` in two outer archives; a name twice in one zip);
      - the container the chosen key names (compared by its exact name, folder included) is itself held
        more than once with different bytes: the key cannot say which of them its member came from.
    `stage-1.zip` beside `stage-2.zip`, and `a/stage.zip` beside `b/stage.zip`, are different names."""
    tails, exact = {}, {}
    for key in files:
        if not isinstance(key, str):
            continue
        tail = key.rsplit("->", 1)[-1].strip()
        tails.setdefault(tail.rsplit("/", 1)[-1], []).append(key)
        exact.setdefault(tail, []).append(key)

    def differ(keys) -> bool:
        first = files[keys[0]]
        return any(not (files[k] is first or files[k] == first) for k in keys[1:])
    out = {}
    for member, qs in specimens.items():
        keys = tails.get(str(member or "").rsplit("/", 1)[-1])
        if not keys or len(keys) < 2:
            continue
        if not differ(keys):
            continue
        # Backlog row 303: when run.py added the full-path key the question's OWN container chain names, and
        # that chain is not itself ambiguous (no `<chain> #N` sibling), the member's bytes are that key's. A
        # chain of one part is the bare name alone: never answered from it. When the member's questions name
        # chains that resolve to different bodies, or any chain is not an exact unambiguous key, this falls
        # through to the longest-tail logic below (which ends in None for the shapes it cannot tell apart).
        resolved, by_chain = [], True
        for chain in {tuple(_chain(q)) for q in qs}:
            full = " -> ".join(chain)
            if len(chain) < 2 or full not in files or (full + " #1") in files:
                by_chain = False
                break
            body = files[full]
            if not any(body is b or body == b for b in resolved):
                resolved.append(body)
        if by_chain and len(resolved) == 1:
            out[member] = resolved[0]
            continue
        split = {k: [p.strip() for p in k.split("->")] for k in keys}
        bare = [files[k] for k in keys if "->" not in k]
        pathed = [files[k] for k in keys if "->" in k]
        if any(not any(b is p or b == p for p in pathed) for b in bare):
            out[member] = None               # a path key was overwritten: the keys no longer say what they hold
            continue
        chosen = []
        for chain in {tuple(_chain(q)) for q in qs}:
            hit = None
            for i in range(len(chain) - 1):          # the longest tail first; never the bare name alone
                tail = list(chain[i:])
                hit = [k for k, parts in split.items() if parts[-len(tail):] == tail]
                if hit:
                    break
            chosen.append(hit or [])
        bodies, twice_held = [], False
        for hit in chosen:
            for k in hit:
                if not any(files[k] is b or files[k] == b for b in bodies):
                    bodies.append(files[k])
                holder = exact.get(split[k][-2]) if len(split[k]) > 1 else None
                if holder and len(holder) > 1 and differ(holder):
                    twice_held = True        # two containers of this very name: whose member is under the key?
        out[member] = bodies[0] if len(bodies) == 1 and all(chosen) and not twice_held else None
    return out


# 2026-10-13 (Day 14 look-ahead; the review of that day). tools/run.py expands zip and 7z and nothing else,
# so a specimen inside a tar, a tar.gz or a gzip of its own is "not in the delivery". It is looked for HERE,
# in this lane only and only for an asked member that `files` does not hold (teaching run.py's expander the
# two formats put the inner files of every lane's delivery under bare names: a decoy `.gz` beside a Metadata
# file then answered five ids wrong). Bounded: a gzip is read to INNER_GZIP_MAX bytes and must be ONE member
# with nothing behind it (bytes after the first member are a second file or a decoy: refused), a tar gives
# at most INNER_TAR_MEMBERS regular files, INNER_TOTAL_MAX bytes are read in all, three levels deep.
INNER_GZIP_MAX = 64 * 1024 * 1024
INNER_TAR_MEMBERS = 2000
INNER_TOTAL_MAX = 256 * 1024 * 1024
INNER_DEPTH = 3


def _gunzip_one(data: bytes):
    """The bytes of a gzip file that is exactly one member, else None."""
    import zlib
    try:
        d = zlib.decompressobj(wbits=31)
        body = d.decompress(data, INNER_GZIP_MAX + 1)
        if len(body) > INNER_GZIP_MAX or not d.eof or d.unused_data or d.unconsumed_tail:
            return None
    except zlib.error:
        return None
    return body


def inner_members(missing: set, files: dict) -> dict:
    """{member: bytes, or None} for the asked members `files` does not hold and a tar or gzip in it does.
    None when two files of that name with different bytes are found: nothing says which is asked. A member
    found nowhere is not in the result (it stays "not in the delivery")."""
    import io
    import tarfile
    found = {m: [] for m in missing}
    bases = {}
    for m in missing:
        bases.setdefault(str(m).rsplit("/", 1)[-1], []).append(m)
    budget = [INNER_TOTAL_MAX]

    def offer(name: str, body: bytes):
        # The asked name and the member's name must be the SAME (a leading `./` aside): a bare `host-context.js`
        # is not `old/host-context.js` of a backup tar beside the delivery (the review of 2026-10-13: such a
        # file answered three ids right and five wrong where the specimen was simply not delivered), and a
        # folder counts only when the question itself names it.
        while name.startswith("./"):
            name = name[2:]
        for m in bases.get(name.rsplit("/", 1)[-1], ()):
            asked = m[2:] if m.startswith("./") else m
            if asked == name:
                if not any(body is b or body == b for b in found[m]):
                    found[m].append(body)

    def walk(name: str, data: bytes, depth: int):
        if depth > INNER_DEPTH or budget[0] <= 0 or not isinstance(data, (bytes, bytearray)):
            return
        if data[:3] == b"\x1f\x8b\x08":
            body = _gunzip_one(bytes(data))
            if body is None:
                return
            budget[0] -= len(body)
            low = name.lower()
            inner = name[:-4] + ".tar" if low.endswith(".tgz") else name[:name.rfind(".")] if low.endswith((".gz", ".gzip")) else name
            if inner != name:
                offer(inner, body)
            walk(inner, body, depth + 1)
        elif data[257:262] == b"ustar":
            try:
                with tarfile.open(fileobj=io.BytesIO(bytes(data)), mode="r:") as tf:
                    count = 0
                    for info in tf:
                        if not info.isfile():
                            continue
                        count += 1
                        budget[0] -= info.size
                        if count > INNER_TAR_MEMBERS or budget[0] <= 0:
                            return
                        f = tf.extractfile(info)
                        if f is None:
                            continue
                        body = f.read()
                        offer(info.name, body)
                        walk(info.name, body, depth + 1)
            except (tarfile.TarError, OSError, EOFError, ValueError):
                return

    seen = set()
    for key, data in list(files.items()):
        if not isinstance(key, str) or not isinstance(data, (bytes, bytearray)) or id(data) in seen:
            continue
        seen.add(id(data))
        if data[:3] == b"\x1f\x8b\x08" or data[257:262] == b"ustar":
            walk(key.rsplit("->", 1)[-1].strip(), data, 0)
    return {m: (bodies[0] if len(bodies) == 1 else None) for m, bodies in found.items() if bodies}


def solve_set(questions, files, ctx):
    # Perf (2026-10-24): memoize plan_codec.reading for this call, so the second read of a specimen's plan
    # (day23_fold.patch's _plan_of, after the main solve path) is a cache hit; see plan_codec.reading_cache_*.
    # Reference-counted, so the nested solve_set calls day23_fold makes share this cache. No answer changes.
    plan_codec.reading_cache_begin()
    try:
        return _solve_set(questions, files, ctx)
    finally:
        plan_codec.reading_cache_end()


def _solve_set(questions, files, ctx):
    only = {m.strip() for m in os.environ.get("ONLY", "").split(",") if m.strip()}
    specimens = {}
    for q in questions:
        specimens.setdefault(member_of(q), []).append(q)
    out = {}
    try:
        # Only for a delivery as tools/run.py expanded it: ctx names the delivery and `files` holds those very
        # bytes under that name (split_sets, so every runner, the gate's replay and verify.py). There a bare
        # name and its `->` keys were written by one expander, and two that differ are two files. A `files`
        # dict a caller built or edited by hand says nothing of the kind: `{**files, member: new_text}` is how
        # the lane's own tests hand a specimen another text, and it is read by its bare name as ever (the
        # acceptance run of 2026-10-13: 19 checks of test_generic.py were answered None by the guards).
        twice = same_name_members(specimens, files) if as_expanded(files, ctx) else {}
    except Exception:  # noqa: BLE001 - a check that fails changes nothing
        twice = {}
        print(f"[analyze] looking for members of one name raised:\n{traceback.format_exc()}", file=sys.stderr)
    patch_named = set()          # the ids the day's day_patch.py answered or withdrew: never demoted after it
    inner = {}
    try:
        missing = {m for m in specimens if m and generic.find(files, m) is None}
        if missing:
            inner = inner_members(missing, files)
    except Exception:  # noqa: BLE001 - a container that does not read leaves the member "not in the delivery"
        inner = {}
        print(f"[analyze] looking into tar and gzip members raised:\n{traceback.format_exc()}", file=sys.stderr)
    delivery = files
    # Backlog row 163: the smallest members first, so one huge or hostile member is read last and a
    # cut by the runner's clock leaves every other specimen's answers in ctx['partial'].
    for member, qs in sorted(specimens.items(), key=lambda kv: len(files.get(kv[0]) or b"")):
        qs = generic.with_fields(qs)    # all questions of the specimen are known here, and only here
        files = delivery
        if member in inner:
            if inner[member] is None:
                print(f"[analyze] NOTE {member}: found more than once, with different bytes, inside tar or gzip "
                      f"members of the delivery; its {len(qs)} questions are left unanswered", file=sys.stderr)
                continue
            files = dict(delivery)
            files[member] = inner[member]
            print(f"[analyze] NOTE {member}: not a member of the delivery as run.py expands it; read from a tar or "
                  f"gzip member that holds it", file=sys.stderr)
        if member in twice:
            if twice[member] is None:
                print(f"[analyze] NOTE {member}: the delivery holds this name more than once with different bytes "
                      f"and the question's container chain ({' -> '.join(_chain(qs[0])) or 'none'}) names no one of "
                      f"them; its {len(qs)} questions are left unanswered", file=sys.stderr)
                continue
            files = dict(delivery)
            files[member] = twice[member]
            print(f"[analyze] NOTE {member}: the delivery holds this name more than once with different bytes; read "
                  f"from the container chain the question names ({' -> '.join(_chain(qs[0]))})", file=sys.stderr)
        lang = LANGUAGE.get(Path(member).suffix.lower())
        if only and (lang or Path(member).suffix.lower().lstrip(".") or "unknown") not in only:
            continue
        try:
            files_seen, problem = encoded_view(member, files)
        except Exception as e:  # noqa: BLE001 - a decoder that fails is a file that is not read
            files_seen, problem = files, f"{type(e).__name__}: {e}"
        if problem:
            print(f"[analyze] {member}: a Script Encoder block that does not decode ({problem}); "
                  f"its {len(qs)} questions are left unanswered", file=sys.stderr)
            continue
        try:
            files_seen, routed, problem = office_view(member, files_seen)
        except Exception as e:  # noqa: BLE001 - a reader that fails is a document that is not read
            routed, problem = member, f"{type(e).__name__}: {e}"
        if problem:
            print(f"[analyze] {member}: an Office macro container that does not read ({problem}); "
                  f"its {len(qs)} questions are left unanswered", file=sys.stderr)
            continue
        if routed != member:
            member, lang = routed, LANGUAGE.get(Path(routed).suffix.lower())
            qs = [dict(q, member=routed) for q in qs]
        if lang is None:
            try:
                member, qs, files_seen = node_view(member, qs, files_seen)
            except Exception:  # noqa: BLE001 - a reader that fails is a file read as it is
                print(f"[analyze] reading {member} as a Node packaging raised:\n{traceback.format_exc()}", file=sys.stderr)
            try:
                member, qs, files_seen = container_view(member, qs, files_seen, ctx)
            except Exception:  # noqa: BLE001 - a reader that fails is a file read as it is
                print(f"[analyze] reading {member} as a container raised:\n{traceback.format_exc()}", file=sys.stderr)
            try:
                files_seen = strings_view(member, files_seen, ctx)
            except Exception:  # noqa: BLE001 - a reader that fails is a file read as it is
                print(f"[analyze] reading the strings of {member} raised:\n{traceback.format_exc()}", file=sys.stderr)
        def specimen_answers(qs, ctx, member=member, lang=lang, files_seen=files_seen):
            mod = language_module(lang)
            if mod is not None and not known_component(lang, qs):
                print(f"[analyze] {member}: a {lang} specimen of a component its module was not built on; "
                      f"answered by the general path", file=sys.stderr)
                mod = None
            try:
                got = solve_module(lang, mod, member, qs, files_seen, ctx) if mod is not None \
                    else solve_new(member, qs, files_seen, ctx)
            except Exception:  # noqa: BLE001 - belt and braces: the loop itself must survive a specimen
                got = {}
                print(f"[analyze] {member} raised:\n{traceback.format_exc()}", file=sys.stderr)
            if mod is not None:
                keep_partial(ctx, got)      # what the solver has, before a live fix is run
                try:
                    got.update(live_shapes(member, qs, got, files_seen))
                except Exception:  # noqa: BLE001 - whatever goes wrong around a live fix costs the solver nothing
                    print(f"[analyze] asking shapes_<ext>.py about {member} raised:\n{traceback.format_exc()}", file=sys.stderr)
            return got

        got = specimen_answers(qs, ctx)
        try:
            got = id_forms(member, qs, got, specimen_answers, ctx)
        except Exception:  # noqa: BLE001 - the second look costs nothing when it fails
            print(f"[analyze] reading the ids of {member} in their known form raised:\n{traceback.format_exc()}", file=sys.stderr)
        # 2026-10-13 (Day 14 look-ahead). The literals of a typed handoff plan for a specimen nothing else read
        # (stage_plan.py, picks only), BEFORE the day's live fix, so that day_patch.py has the last word.
        try:
            if stage_plan is not None:
                more = stage_plan.answers(member, qs, got, files_seen)
                for qid, value in (more or {}).items():
                    if got.get(qid) is None and isinstance(value, str) and value:
                        got[qid] = value
        except Exception:  # noqa: BLE001
            print(f"[analyze] asking stage_plan.py about {member} raised:\n{traceback.format_exc()}", file=sys.stderr)
        # Build night 2026-10-23: Day 23's live fix folded in (day23_fold.py: LYR-<layers> plan tag, derived
        # token/host/leaf/indicator/style/carrier picks), then the crib-based language ids for the language
        # fields a reader left None or unsure (gdscript_csx_langs.py: unsure picks only). Both before day_patch.py.
        # lang_names_more.py (Day 24 build night, T5): ~50 more language names, unsure picks only, after the first.
        for _fold, _call in (("day23_fold", "patch"), ("gdscript_csx_langs", "overrides"), ("lang_names_more", "overrides")):
            try:
                _mod = plan_codec.optional(_fold)
                # A fold that says so (PATCH_TAKES_CTX) is handed this ctx: day23_fold reads the specimen's plan
                # again and solves a rewritten text, and a member read as a binary carrier's strings
                # (ctx["strings_views"]) must be read so there too (Day 27, review of the variants track).
                _kw = {"ctx": ctx} if getattr(_mod, "PATCH_TAKES_CTX", False) is True else {}
                _res = getattr(_mod, _call)(member, qs, dict(got), files_seen, **_kw) if _mod is not None and hasattr(_mod, _call) else None
                if isinstance(_res, dict):
                    _ask = {q["qid"] for q in qs}
                    for qid, value in _res.items():
                        if qid not in _ask:
                            continue
                        current = got.get(qid)
                        # armed-tree-audit hole (2026-10-24, the script-url fix): a fold is routed through the
                        # SAME override-guard as day_patch below (respell.guard_value -> override_guard.guard),
                        # so a fold VALUE can only change an UNJUDGED answer; it can never replace or withdraw a
                        # judge-accepted one. The guard only ever keeps `current` or hands back the fold's value,
                        # so it introduces no wrong answer, and the #1 batch-style demotion (an unsure candidate
                        # added to an unjudged key) is unaffected (an unjudged `current` is not protected). Only
                        # a str/None value is routed (the shapes the guard reasons about); a non-str value, which
                        # no fold emits, is applied as before so nothing is silently dropped.
                        if _respell is not None and (value is None or isinstance(value, str)):
                            try:
                                value, blocked, gnote = _respell.guard_value(qid, current, value)
                            except Exception:  # noqa: BLE001 - a guard that fails leaves the fold's value as given
                                blocked = False
                            if blocked:
                                print(f"[analyze] {qid}: {_fold}.py override refused: {gnote}", file=sys.stderr)
                                continue
                        if value != current:
                            # No fold is exempted from answer_forms.demote (armed-tree-audit hole #4,
                            # 2026-10-24): day23_fold once added its ids to patch_named here, which skipped
                            # the end-of-delivery form demotion, so a -url id it filled shipped the raw
                            # https:// value PLAIN under a defanged/lowercase/forward-slashes syntax. A fold
                            # is a reader like any other: its plain answers now go through demote (plain ->
                            # unsure only; a judged form still resolves plain via labels.pick). Only
                            # day_patch.py, routed through override_guard, keeps the last word via patch_named.
                            print(f"[analyze] {qid}: {shown(current)} replaced by {_fold}.py ({shown(value)})",
                                  file=sys.stderr)
                            got[qid] = value
            except (Exception, SystemExit):  # noqa: BLE001 - a fold that raises costs the solver nothing
                print(f"[analyze] asking {_fold}.py about {member} raised:\n{traceback.format_exc()}", file=sys.stderr)
        # The day's live fix (added by the main thread on Day 12, 2026-10-12): day_patch.py, when the lane's
        # folder holds one, is asked about every specimen last and may replace or withdraw (None) any of
        # its answers, a module's plain one too: patch(member, questions, answers, files) -> {qid: value}.
        # Only ids of this specimen are taken. Without the file nothing changes (day_patch_template.py).
        try:
            fix = plan_codec.optional("day_patch")       # (Exception, SystemExit): a sys.exit() in the hook, or
            patched = fix.patch(member, qs, dict(got), files_seen) if fix is not None and hasattr(fix, "patch") else None
            if isinstance(patched, dict):
                asked = {q["qid"] for q in qs}
                q_by_id = {q.get("qid"): q for q in qs}
                patch_named.update(qid for qid in patched if qid in asked)
                for qid, value in patched.items():
                    if qid not in asked:
                        continue
                    current = got.get(qid)
                    # wave3 (T4, override-guard): a patch() may not replace or withdraw a judge-accepted
                    # plain answer; a BAD/unjudged/None id, and a family-prior guess, are still fixed.
                    # (T2, render_candidates): a read-but-unjudged unsure value gets its other spellings
                    # offered too (enrich is a no-op for a plain or None value).
                    if _respell is not None:
                        blocked = False
                        try:
                            value, blocked, gnote = _respell.guard_value(qid, current, value)
                        except Exception:
                            blocked = False
                        if blocked:
                            print(f"[analyze] {qid}: {gnote}", file=sys.stderr)
                            continue
                        try:
                            value = _respell.enrich(value, q_by_id.get(qid))
                        except Exception:
                            pass
                    if value != current:
                        print(f"[analyze] {qid}: {shown(current)} replaced by day_patch.py ({shown(value)})",
                              file=sys.stderr)
                        got[qid] = value
        except (Exception, SystemExit):  # noqa: BLE001 - at its import, must not end the set (review of 2026-10-12)
            print(f"[analyze] asking day_patch.py about {member} raised ({sys.exc_info()[0].__name__}); the solver's "
                  f"answers stand:\n{traceback.format_exc()}", file=sys.stderr)
        out.update(got)
        keep_partial(ctx, got)
    # 2026-10-13 (Day 14 look-ahead). A plain answer whose answer format asks another form of it, or lists it
    # in another spelling, goes unsure with the asked form first (answer_forms.py; never withdrawn). Once for
    # the whole delivery, because how broad the demotion is decides whether it is made at all, and never for
    # an id the day's day_patch.py named: the patch has the last word. (ctx["partial"], which a runner
    # submits when its clock cuts the solve, holds the answers as they were until this point.)
    try:
        if answer_forms is not None and out:
            moved = answer_forms.demote(questions, out, skip=patch_named)
            if moved:
                out.update(moved)
                keep_partial(ctx, moved)
    except Exception:  # noqa: BLE001
        print(f"[analyze] asking answer_forms.py about the delivery raised:\n{traceback.format_exc()}", file=sys.stderr)
    return out


# ---------------------------------------------------------------- the contract check

def component(qid: str) -> str:
    """The component of an answer id: its language prefix; the three tactic-named PowerShell
    specimens form `powershell`. A Mastery `setN.` prefix is ignored."""
    first = re.sub(r"^set\d+\.", "", qid or "").split("-", 1)[0]
    return "powershell" if first in POWERSHELL_IDS else first


def base_components() -> set:
    """The components asked on the newest saved base attempt of this lane (today's base)."""
    if labels is None:
        return set()
    try:
        found = sorted(labels.challenges_root().glob("day-*/script-analysis-*/attempt.json"),
                       key=lambda p: p.parent.parent.name)
        attempt = json.loads(found[-1].read_text()) if found else {}
        ids = list(attempt.get("answer_ids") or []) + [q.get("id") for q in attempt.get("questions") or []]
        return {component(i) for i in ids if isinstance(i, str) and i}
    except Exception:  # noqa: BLE001 - an unreadable base proves nothing
        return set()


def covers(questions, files=None) -> list:
    """Problems that should keep a clock from starting: one line per question that neither a
    module nor the generic route can take. An empty list means every question is covered.

    With `files`, the generic route is tested for real: the plan must be recoverable from the
    question's member. Without them (the runner calls this with the questions of a status
    read, before any download) only the ids can speak: the id's component must be one of the
    known languages or one that today's base attempt asked, which is the attempt the gate has
    already replayed with this solver."""
    problems, on_base, sealed, nodes, plans = [], None, {}, {}, {}
    known = {lang for lang in set(LANGUAGE.values()) if language_module(lang) is not None}
    for q in questions or []:
        qid = q.get("qid") or q.get("id") or ""
        member = member_of(q)
        ext = Path(member).suffix.lower()
        lang = LANGUAGE.get(ext)
        seen = files
        if files is not None:
            if member not in sealed:
                try:
                    sealed[member] = encoded_view(member, files)
                except Exception as e:  # noqa: BLE001
                    sealed[member] = (files, f"{type(e).__name__}: {e}")
                if not sealed[member][1]:
                    try:
                        sealed[member] = (*sealed[member], *office_view(member, sealed[member][0]))
                    except Exception as e:  # noqa: BLE001
                        sealed[member] = (*sealed[member], files, member, f"{type(e).__name__}: {e}")
            seen, problem = sealed[member][:2]
            if problem:
                problems.append(f"{qid}: {member} holds a Script Encoder block that does not decode ({problem})")
                continue
            if len(sealed[member]) > 2:
                seen, routed, problem = sealed[member][2:]
                if problem:
                    problems.append(f"{qid}: {member} holds an Office macro container that does not read ({problem})")
                    continue
                if routed != member:
                    member, ext = routed, Path(routed).suffix.lower()
                    lang = LANGUAGE.get(ext)
            if not lang:
                if member not in nodes:
                    try:
                        nodes[member] = node_view(member, [], seen)
                    except Exception:  # noqa: BLE001
                        nodes[member] = (member, [], seen)
                    try:
                        nodes[member] = container_view(nodes[member][0], [], nodes[member][2])
                    except Exception:  # noqa: BLE001
                        pass
                    try:
                        nodes[member] = (*nodes[member][:2], strings_view(nodes[member][0], nodes[member][2]))
                    except Exception:  # noqa: BLE001
                        pass
                member, _, seen = nodes[member]
                ext = Path(member).suffix.lower()
        if lang in known:
            continue
        name = plan_codec.ext_name(ext)
        if not lang and name and plan_codec.optional(f"lang_{name}") is not None:
            continue
        what = f"no module for {ext or 'its file'}"
        if generic_module() is None:
            problems.append(f"{qid}: {what} and generic is not available")
        elif files is not None:
            data = generic.find(seen, member)
            if data is None:
                problems.append(f"{qid}: {what} and {member or 'its file'} is not in the delivery")
            else:
                if member not in plans:      # as the general path reads it: plan_codec, the descriptor, the label
                    try:
                        plans[member] = bool(generic.read(member, data)["plan"])
                    except Exception:  # noqa: BLE001 - a file that cannot be read gives no plan
                        plans[member] = False
                if not plans[member]:
                    problems.append(f"{qid}: {what} and no plan is recovered from {member}")
        else:
            if on_base is None:
                on_base = base_components()
            comp = component(qid)
            if comp not in known and comp not in on_base:
                problems.append(f"{qid}: {what}, and component {comp or '(none)'} is neither a known language "
                                f"nor one today's base asked")
    return problems
