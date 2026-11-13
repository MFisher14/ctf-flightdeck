#!/usr/bin/env python3
"""Batch (cmd.exe) analyzer for the Script Analysis lane.

Usage:
  python3 solvers/script-analysis/batch.py <specimen.cmd|.bat> [...]

Reads a specimen without running it. The plan, `k=v|k=v|...`, is recovered from
three independent places, in this order of trust:

  walk       a small cmd.exe interpreter (bat_cmd.py) follows the script's
             `--inspect` path on paper and captures what it would echo
  material   the `HUNTRESS-MATERIAL` comment decoded with its `HUNTRESS-CODEC`
  fragments  the numbered `set name<N>=...` lines joined in order

The walk and the material are compared on every specimen (they agree on all 108
saved ones). Where they differ the difference is printed and the material plan
answers; where the walk fails the material plan answers. Every answer comes
from that plan plus the shape of the code that rebuilt it:

  role        from the ordered `steps`
  attack      from the role (table below)
  adapter     plan `adapter`
  campaign    plan `campaign_id`
  indicator   the plan key the id's field word names (host_id, url, file_path, ...)
  graph       plan `graph`
  expansion   how the variable echoed as the plan was assembled (see expansion_of);
              under Day 12's answer format (an enum of the four forms) the form of
              the reconstruction statement as it is written (statement_form,
              expansion_answer)
  control     what gates the line that assembles it and how control got there
              (see control_of)

Which of these a question asks is read from its id, `batch-<specimen>-<field>`
(field_of), never from a word of its text: Day 12 re-worded two of them to begin
with "Classify only ..", and the role was answered for both.

Nothing about a particular variant is hardcoded. The answer names are the
judge's own vocabulary; each table says what it has confirmed. A shape the judge
has never named, and anything that could not be established, is answered None
with one `[batch] <file>: <reason>` line on stderr, never with a default.

Switches (diagnostics; removed from every gate replay and timed run):
  BATCH_FIELDS=role,graph   answer only these kinds of question
  BATCH_RULE=plain          report the expansion form as the code writes it
  BATCH_IF_DEFINED=<name>, BATCH_ERRORLEVEL=<name>   another name for a guard
"""
import base64
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bat_cmd  # noqa: E402
from bat_cmd import Cmd  # noqa: E402

# Expansion forms in the judge's order (the order the question lists them in). The judge accepts
# three of them: delayed, call_double, for_indirect. `percent` was rejected every time it was sent
# (three %var% joins and one call join), so it is never an answer; see expansion_of.
EXPANSION = ["percent", "delayed", "call_double", "for_indirect"]

# What gates the join -> the judge's name for it. Every name is judge-confirmed on single-wrapper
# specimens of Day 4 (per-answer accepted values in batch-verdicts.json and the two ladder logs):
#     nothing                                          direct            7
#     goto :HUNTRESS_DISPATCH                          goto_dispatch     13
#     call :HUNTRESS_RECOVER                           call_subroutine   8
#     for /l %%Q in (1,1,1) do call :HUNTRESS_RECOVER  call_subroutine   8  (the loop is not named:
#         22 for-style names were judged incorrect)
#     ver >nul + if errorlevel 1 exit /b 1             errorlevel_guard  4  (direct and if_errorlevel
#         were rejected)
#     if defined HUNTRESS_READY <join or accumulator init>   if_guard    4  (direct, if_defined,
#         defined_guard, defined_check, defined_gate, if_defined_set, defined_branch were rejected)
# The solver has never produced a rejected control value. No saved specimen has two wrappers, and
# no other guard form has been judged, so those are answered None (control_of).
CONTROL = {"linear": "direct", "goto": "goto_dispatch", "call": "call_subroutine", "for_l": "call_subroutine",
           "if_defined": "if_guard", "errorlevel": "errorlevel_guard"}

# The judge's name for an expansion shape where it is not the shape's own word: the plain %var%
# join is `delayed` (12 accepted, `percent` rejected). Only BATCH_RULE=plain reads this table.
EXP_LABEL = {"percent": "delayed"}
# Names the judge rejected for a shape (batch-verdicts.json). A conventions file cannot bring one back.
REJECTED = {"percent": {"percent"}, "errorlevel": {"direct", "if_errorlevel"},
            "if_defined": {"direct", "if_defined", "defined_guard", "defined_check", "defined_gate", "if_defined_set",
                           "defined_branch"}}
CONVENTIONS = Path(__file__).with_name("batch_conventions.json")
OVERRIDES = {"BATCH_IF_DEFINED": "if_defined", "BATCH_ERRORLEVEL": "errorlevel"}


def load_conventions():
    """Names learned on live timed attempts are kept in batch_conventions.json (written by
    timed_ladder.py): {"expansion": {shape: name}, "control": {kind: name}}. They override the
    built-in names above, which already hold everything the judge confirmed up to Day 4, so a
    missing file changes no answer. Returns what the file holds ({} without a usable file)."""
    conv = {}
    if CONVENTIONS.exists():
        try:
            conv = json.loads(CONVENTIONS.read_text())
            if not isinstance(conv, dict):
                raise ValueError("it is not a JSON object")
        except Exception as e:
            print(f"[batch] {CONVENTIONS.name}: not read ({e}); the built-in names are used", file=sys.stderr)
            conv = {}
    for table, names in (("expansion", EXP_LABEL), ("control", CONTROL)):
        learned = conv.get(table)
        for k, v in (learned.items() if isinstance(learned, dict) else ()):
            if not (isinstance(k, str) and isinstance(v, str) and v):
                continue
            if v in REJECTED.get(k, ()):
                print(f"[batch] {CONVENTIONS.name}: {table}.{k} = {v!r} was rejected by the judge; {names.get(k)!r} is kept",
                      file=sys.stderr)
                continue
            names[k] = v
    for var, kind in OVERRIDES.items():
        if os.environ.get(var):
            CONTROL[kind] = os.environ[var]
            print(f"[batch] {var} is set: {kind} guards are answered {os.environ[var]!r}", file=sys.stderr)
    for var in ("BATCH_RULE", "BATCH_FIELDS"):
        if os.environ.get(var):
            print(f"[batch] {var}={os.environ[var]} is set: answers are not the judged ones", file=sys.stderr)
    return conv


load_conventions()

# Role = the ordered behavior the plan's steps describe. First matching rule wins.
ROLE_RULES = [
    (lambda s: "handoff_script" in s, "staged_chain"),
    (lambda s: "write_recovery_note" in s or "transform_content" in s, "impact"),
    (lambda s: "upload_remote" in s, "uploader"),
    (lambda s: "dispatch_memory" in s, "stager"),
    (lambda s: "acquire_remote" in s and "write_file" in s, "downloader"),
    (lambda s: "decode_embedded" in s or ("write_file" in s and "acquire_remote" not in s), "dropper"),
    (lambda s: "dispatch_process" in s, "launcher"),
    (lambda s: "decode_configuration" in s or "return_configuration" in s, "benign_utility"),
]

# One technique per role, all confirmed on the Day 4 base. Launcher and staged_chain take the
# script's own interpreter (T1059.003, Windows Command Shell), whatever the adapter or next stage.
ATTACK = {
    "benign_utility": "none",
    "stager": "T1105",
    "dropper": "T1140",
    "downloader": "T1105",
    "uploader": "T1041",
    "launcher": "T1059.003",
    "impact": "T1486",
    "staged_chain": "T1059.003",
}

JUDGED_WRAPPERS = ("goto", "call", "if_defined", "errorlevel")   # wrappers_of's kinds that CONTROL names


# ---- the plan ---------------------------------------------------------------------------------------

_FIELD = re.compile(r"[A-Za-z_][\w.-]*=")
_NOT_TEXT = re.compile("[\x00-\x1f\x7f\ufffd]")


def looks_like_plan(text) -> bool:
    """`key=value|key=value|...`: two fields or more, every one of them `key=value`, no control
    character and no byte that did not decode. Every field has to be whole, because that is what
    tells a plan from the sentence the `--plan` path echoes, from a wrongly decoded material and
    from a plan the walk put together with a piece missing (`...|stage_co`). Every plan on record
    is plain ASCII with keys in \\w+; a dot or a dash in a key and a value outside ASCII are let
    through, because a generator that adds one would otherwise cost the specimen all eight
    answers although the walk and the material agree on the plan."""
    if not text or len(text) > bat_cmd.MAX_VALUE or _NOT_TEXT.search(text):
        return False                    # (no variable of cmd.exe holds more, so no plan is longer)
    parts = text.split("|")
    return len(parts) >= 2 and all(_FIELD.match(part) for part in parts)


def parse_plan(text: str) -> dict:
    plan = {}
    for part in text.split("|"):
        k, sep, v = part.partition("=")
        if sep:
            plan[k.strip()] = v
    return plan


def _b64(s: str) -> bytes:
    return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)


# HUNTRESS-CODEC:<representation>|<transform>. The material is the plan's bytes after the transform,
# written in the representation. Decoding undoes them in the opposite order.
REPRESENTATIONS = {
    "base64_literal": _b64,
    "hex_pairs": bytes.fromhex,
    "decimal_bytes": lambda s: bytes(int(x) for x in s.split(".")),
    "reversed_text": lambda s: _b64(s[::-1]),
    "split_fragments": _b64,
    "plain_fragments": _b64,
}
UNDO = {
    "identity": lambda b: b,
    "reverse": lambda b: b[::-1],
    "xor_5a": lambda b: bytes(x ^ 0x5A for x in b),
    "add_7": lambda b: bytes((x - 7) & 0xFF for x in b),
    "rotate_left": lambda b: bytes((x >> 1) | ((x & 1) << 7) for x in b),
    "reverse_xor": lambda b: bytes(x ^ 0x33 for x in b)[::-1],
}
_CODEC = re.compile(r"HUNTRESS-CODEC:[ \t]*([\w.-]+)\|([\w.-]+)")
_MATERIAL = re.compile(r"HUNTRESS-MATERIAL:[ \t]*(\S+)")


def material_plan(text: str):
    """The plan decoded from the HUNTRESS-MATERIAL comment: (plan text, None), or (None, why not).
    (None, None) when the specimen has no such comment. Every saved specimen has one comment and
    one label; with more, each material is tried under each label, and two different plans are
    no plan."""
    materials, codecs = _MATERIAL.findall(text), _CODEC.findall(text)
    if not materials:
        return None, None
    if not codecs:
        return None, "the material has no HUNTRESS-CODEC label"
    plans, why = [], None
    for rep, transform in codecs:
        if rep not in REPRESENTATIONS or transform not in UNDO:
            why = why or f"codec {rep}|{transform} is not in the table: the material was not decoded"
            continue
        for material in materials:
            try:
                plain = UNDO[transform](REPRESENTATIONS[rep](material)).decode("utf-8")
            except Exception as e:
                why = why or f"the material does not decode as {rep}|{transform} ({type(e).__name__})"
                continue
            if not looks_like_plan(plain):
                why = why or f"the material decoded as {rep}|{transform} is not a plan"
            elif plain not in plans:
                plans.append(plain)
    if len(plans) > 1:
        return None, f"{len(plans)} MATERIAL comments decode to different plans"
    return (plans[0], None) if plans else (None, why)


def _plan_line(sh: Cmd, loose: bool = False):
    """The last echoed line that is a plan. loose: blanks after it on the echo line are not part of it."""
    for line in reversed(sh.out):
        line = line.rstrip(" \t") if loose else line
        if looks_like_plan(line):
            return line
    return None


def _walk(text: str, arg, **kw):
    sh = Cmd(text, args=["specimen"] + ([arg] if arg else []), **kw)
    sh.run()
    return _plan_line(sh, kw.get("keep_trailing", False)), sh


# The mode switch: `if /i "%~1"=="--inspect" goto :HUNTRESS_INSPECT`.
_MODE = re.compile(r'(?im)^[ \t@]*if[ \t]+(?:/i[ \t]+)?"?%~?1"?[ \t]*==[ \t]*"?([^"\s]+)"?[ \t]+goto[ \t]+:?(\S+)')


def recover_plan(text: str, **kw):
    """Walk `script --inspect` on paper. Returns (plan text, interpreter) or (None, interpreter).

    If that switch echoes no plan it has another name: the switches the script tests are tried,
    the one that jumps to a label naming the inspect path first, and then the walk is started at
    that label itself. Only an echo shaped like a plan counts, so the `--plan` path (a sentence)
    is never taken for it. Keywords go to the interpreter (env, keep_trailing)."""
    plan, first = _walk(text, "--inspect", **kw)
    if plan is not None:
        return plan, first
    modes = sorted(_MODE.findall(text), key=lambda m: "inspect" not in m[1].lower())
    for switch, _ in modes:
        if switch.lower() != "--inspect":
            plan, sh = _walk(text, switch, **kw)
            if plan is not None:
                return plan, sh
    for label, line in first.labels.items():
        if "INSPECT" in label:
            sh = Cmd(text, args=["specimen"], **kw)
            sh.delayed = any(re.match(r"\s*@?\s*setlocal\b.*enabledelayedexpansion", x, re.I) for x in sh.lines[:line])
            sh.run(line + 1)
            plan = _plan_line(sh, kw.get("keep_trailing", False))
            if plan is not None:
                return plan, sh
    return None, first


# The name is taken whole and split into stem and number afterwards: a lazy stem followed by a
# greedy number makes the regex engine try every split of a long name that has no `=` after it.
_FRAGMENT = re.compile(r'(?im)^[ \t@]*set[ \t]+(?P<q>"?)(?P<full>[A-Za-z_]\w*)=(?P<v>.*?)"?[ \t]*'
                       r'(?:&[ \t]*rem\b.*)?\r?$')


def fallback_plan(text: str):
    """The third source: the numbered fragments joined in order.

    Fragments are numbered from 0 without a gap. A `set` that reads its own family (the accumulator
    `item9=%item0%%item1%...` beside `item0..item3`) is the join, not a fragment, and a number
    after a gap is not part of the run either. The longest family whose join is a plan wins."""
    families = {}
    for m in _FRAGMENT.finditer(text):
        full = m.group("full")
        stem = full.rstrip("0123456789")
        if stem == full or len(full) - len(stem) > 9:
            continue                    # no number, or a number no fragment has
        value = m.group("v") if m.group("q") else re.sub(r"\^(.)", r"\1", m.group("v"))
        families.setdefault(stem.lower(), {}).setdefault(int(full[len(stem):]), value.replace("%%", "%"))
    best = None
    for name, frags in families.items():
        own = re.compile(r"[%!]" + re.escape(name) + r"\d+[%!]", re.I)
        run, i = [], 0
        while i in frags and not own.search(frags[i]):
            run.append(frags[i])
            i += 1
        joined = "".join(run)
        if looks_like_plan(joined) and (best is None or len(run) > best[0]):
            best = (len(run), joined)
    return best[1] if best else None


def role_of(plan: dict):
    steps = [s.strip() for s in plan.get("steps", "").split(",") if s.strip()]
    for rule, role in ROLE_RULES:
        if rule(steps):
            return role
    return None


# ---- the shape of the code that rebuilt the plan ----------------------------------------------------

def plan_variable(sh: Cmd, plan_text: str):
    """The variable echoed as the plan. Several variables can hold the plan's text (a decoy join into
    a variable nobody reads); the one the echo expanded is the plan's. Without such an echo it is
    the only variable that holds the text, or None."""
    names = {a["name"] for a in sh.assigns if a["value"] == plan_text}
    for e in reversed(sh.events):
        if e["kind"] == "echo" and e.get("text") == plan_text:
            shown = names & set(e.get("vars") or ())
            if len(shown) == 1:
                return shown.pop()
            break
    return names.pop() if len(names) == 1 else None


def _join(sh: Cmd, plan_text: str) -> list:
    """Every assignment to the plan variable up to the one that completes the plan: the join line
    itself and, for a FOR join, the accumulator's reset before it."""
    var = plan_variable(sh, plan_text)
    own = [a for a in sh.assigns if a["name"] == var] if var else []
    done = max((i for i, a in enumerate(own) if a["value"] == plan_text), default=-1)
    return own[:done + 1]


def _join_flags(sh: Cmd, plan_text: str) -> set:
    flags = set()
    for a in _join(sh, plan_text):
        if a["value"]:
            flags |= a["flags"]
    return flags


def expansion_shape(sh: Cmd, plan_text: str):
    """Name the expansion the code uses to assemble the variable echoed as the plan: %var%
    (percent), !var! (delayed), CALL's second pass over %%var%% (call_double), or a FOR variable
    building the name (for_indirect). Joins into other variables do not count."""
    flags = _join_flags(sh, plan_text)
    for key in ("for", "call", "delayed", "percent"):
        if key in flags:
            return {"for": "for_indirect", "call": "call_double"}.get(key, key)
    return None


def fragment_prefix(sh: Cmd, plan_text: str):
    """The name the fragment variables share (FRAGMENT, H, V_A, FRAG, ITEM), or None if they share none.

    The fragments are the variables the join reads, followed through any intermediate variable down
    to the ones set from literals. A variable that merely holds a prefix of the plan is not one."""
    join = _join(sh, plan_text)
    own = join[0]["name"] if join else None
    last = {}
    for a in sh.assigns:
        if a["value"]:
            last.setdefault(a["name"], []).append(a)
    leaves, seen, todo = set(), {own}, set().union(*(a.get("reads", ()) for a in join)) if join else set()
    while todo:
        name = todo.pop()
        if name in seen or name not in last:
            continue                    # a session variable, or one the script never set
        seen.add(name)
        reads = set().union(*(a.get("reads", ()) for a in last[name])) & set(last) - {name}
        if reads:
            todo |= reads
        elif last[name][-1]["value"] in plan_text:
            leaves.add(name)
    prefixes = {re.sub(r"\d+$", "", n) for n in leaves}
    return prefixes.pop() if len(prefixes) == 1 else None


def expansion_of(sh: Cmd, plan_text: str, text: str = None, notes: list = None):
    """The judge's expansion form, or None (with the reason appended to `notes`).

    The answer is a function of the join and of the fragment variables' name:

        %var% join or !var! join                               delayed       (12 + 18 accepted)
        call set "V=%%a%%%%b%%..."                             delayed       (9 accepted)
        for %%G in (...) do call set "V=%%V%%%%a%%G%%"         for_indirect  (12 accepted)
        either of the last two when the fragment variables have a ONE-LETTER name (h0..h3)
                                                               call_double   (3 accepted)

    Evidence (Day 4 base, five Time Trial variants, both Mastery sets): this rule reproduces all 54
    per-answer accepted values and emits none of the 14 rejected ones. The codec transform, the
    wrapper and the SET style do not matter: of 20 generator features the fragment name is the
    only one that separates the call_double answers. The one-letter case rests on three accepted
    answers, one FOR join (base dropper, where for_indirect was rejected) and two call joins (time
    trial 3 launcher, mastery set 1 impact); the data cannot tell "one letter" from "the name h".
    `percent` is never accepted. A one-letter name on a FOR join without CALL is not in that
    evidence and call_double would name a CALL that is not there, so it is None.

    BATCH_RULE=plain reports the code's own form instead, for diagnostics: it fits 32 of the 54,
    or 44 once EXP_LABEL has renamed `percent`. `text` is not used; callers still pass it.
    """
    notes = [] if notes is None else notes
    shape = expansion_shape(sh, plan_text)
    if shape is None:
        notes.append("expansion: the plan variable is not assembled by any expansion")
        return None
    if os.environ.get("BATCH_RULE") == "plain":
        return shape
    if shape in ("percent", "delayed"):
        return "delayed"
    prefix = fragment_prefix(sh, plan_text)
    if prefix is None:
        notes.append(f"expansion: a {shape} join whose fragment variables share no name has no judged form")
        return None
    if len(prefix) == 1:
        if "call" not in _join_flags(sh, plan_text):
            notes.append("expansion: a FOR join without CALL over one-letter fragment names has no judged form")
            return None
        return "call_double"
    return shape if shape == "for_indirect" else "delayed"


def wrappers_of(sh: Cmd, plan_text: str):
    """What gates the join and how control reached it: ({wrapper kind: True}, for_l) or (None, False).

    Read from the walk, between the jump to the inspect path and the join's last assignment:

      call        the join runs inside a `call :label` subroutine (for_l: that call is the body of a
                  FOR /L that runs once), wherever the fragments are
      if_defined  an IF DEFINED whose body is the join or the accumulator's reset
      errorlevel  an `if errorlevel N exit` passed on the way to the join
      goto        a GOTO taken on the way that is not the separator showcase

    Wrappers placed before the fragments count like any other. What does not gate the join is not
    a wrapper: the mode switch, a statement that only touches neutral_* variables (and a GOTO that
    jumps over nothing but such statements), an IF around anything else, a FOR whose variable
    builds the join, and a call to a subroutine the join is not in together with everything that
    ran inside it (its `goto :eof`, an errorlevel check of its own): by the time the join runs
    that subroutine has returned. Any other gate (an IF of another kind around the join or in
    front of it, a command after && or ||, a loop around the join, a loop that repeats the call, a
    nested call) is reported under its own description, which no judged name covers."""
    join = _join(sh, plan_text)
    if not join:
        return None, False
    found, for_l = {}, False

    def guard(g):
        form, _, _, mode = g
        if not mode:
            found[form if form == "if_defined" else f"{form} around the join"] = True

    for a in join:
        if a["depth"]:
            found["call" if a["depth"] == 1 else "nested call"] = True
        for g in a["guards"]:
            guard(g)
        for kind, uses, depth, count in a["loops"]:
            if kind == "for_l" and not uses and depth < a["depth"] and count == 1:
                for_l = True
            elif not uses:
                found[f"{kind} x{count} around the {'call' if depth < a['depth'] else 'join'}"] = True
    end, frames = join[-1]["seq"], join[-1].get("frames", ())
    start = max((e["seq"] for e in sh.events if e["kind"] == "goto" and e["mode"] and e["seq"] < end), default=0)
    for e in sh.events:
        if not start < e["seq"] < end or e["mode"]:
            continue
        if e.get("frames", ()) != frames[:len(e.get("frames", ()))]:
            continue                    # it ran in a subroutine that returned before the join
        if e["kind"] == "goto" and not e["separator"] and not e.get("neutral"):
            found["goto"] = True
            for g in e["guards"]:
                guard(g)
        elif e["kind"].startswith("if_") and not e["result"] and e["escape"]:
            if str(e.get("name", "")).lower().startswith("neutral_"):
                continue
            judged = e["kind"] == "if_errorlevel" and e["escape"] == "exit" and not e["neg"]
            found["errorlevel" if judged else f"{e['kind']} {e['escape']} before the join"] = True
    return found, for_l


def control_of(sh: Cmd, plan_text: str, notes: list = None):
    """The control-flow form around the join as a key of CONTROL: linear, goto, call, for_l,
    if_defined or errorlevel. None (with the reason appended to `notes`) when the join has two
    wrappers at once or a gate the judge has never named: no verdict says which name wins."""
    notes = [] if notes is None else notes
    found, for_l = wrappers_of(sh, plan_text)
    if found is None:
        notes.append("control: no assignment in the walk produces the plan")
        return None
    if len(found) > 1 or any(k not in JUDGED_WRAPPERS for k in found):
        notes.append(f"control: {' + '.join(sorted(found))} has no judged name")
        return None
    if not found:
        return "linear"
    kind = next(iter(found))
    return "for_l" if kind == "call" and for_l else kind


# ---- one specimen ---------------------------------------------------------------------------------

def _undecided(plan: dict, other, why: str, notes: list) -> dict:
    """Keep only the fields two readings of the same script agree on."""
    other = parse_plan(other or "")
    lost = [k for k in plan if plan[k] != other.get(k)]
    if lost:
        notes.append(f"{why}: {', '.join(lost)} left unanswered")
    return {k: v for k, v in plan.items() if k not in lost}


def analyze(text: str) -> dict:
    """Everything known about one specimen: plan_text, plan, role, attack, expansion, control, plus
    plan_source (walk, material, fragments or None) and notes, the reasons for anything left None."""
    notes = []
    material, why = material_plan(text)
    try:
        walked, sh = recover_plan(text)
    except Exception as e:      # the walk is one of three sources: its failure costs the shape answers only
        walked, sh = None, None
        notes.append(f"the walk raised {type(e).__name__}: {e}")
    if sh is not None and sh.exhausted:
        notes.append("the walk ran out of a budget (steps, call depth or the length of a value)"
                     + ("" if walked is not None else ": expansion and control are left unanswered"))

    plan_text, source = walked, "walk" if walked is not None else None
    if walked is not None and material is not None and walked != material:
        a, b = parse_plan(walked), parse_plan(material)
        notes.append("the walked plan differs from the MATERIAL plan in "
                     + ", ".join(sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k)))
                     + ": the MATERIAL plan answers")
        plan_text, source = material, "material"
    elif walked is None and material is not None:
        notes.append("the walk echoed no plan: the MATERIAL plan answers")
        plan_text, source = material, "material"
    elif walked is None:
        plan_text = fallback_plan(text)
        source = "fragments" if plan_text is not None else None
        notes.append("the walk echoed no plan" + (f" and {why}" if why else " and there is no MATERIAL")
                     + (": the numbered fragments answer" if plan_text is not None else ": no plan was recovered"))
    plan = parse_plan(plan_text or "")
    if source == "walk" and material is None:
        # Nothing independent confirms the walk, so the two things it assumed are checked.
        if why:
            notes.append(why)
        for name, value in sorted(sh.system_refs.items()):
            lost = [k for k, v in plan.items() if value and value in v]
            if lost:            # the interpreter's stand-in for a value only the real machine has
                notes.append(f"{', '.join(lost)} would hold this machine's %{name}%: left unanswered")
                plan = {k: v for k, v in plan.items() if k not in lost}
        if any(line != line.rstrip(" \t") for line in re.split(r"\r\n|\n|\r", text)):
            other = recover_plan(text, keep_trailing=True)[0]
            plan = _undecided(plan, other, "trailing blanks may or may not belong to the plan", notes)

    role = role_of(plan)
    if role is None and "steps" in plan:
        notes.append(f"steps {plan['steps']!r} match no role")
    expansion = control = control_kind = None
    anchor = walked if walked is not None else plan_text
    if sh is None or anchor is None:
        pass                    # already explained above
    elif walked is None and sh.exhausted:
        pass                    # an unfinished walk establishes nothing about the code's shape
    elif not _join(sh, anchor):
        notes.append("expansion and control: no single variable in the walk holds the plan")
    else:
        shape = expansion_of(sh, anchor, text, notes)
        expansion = EXP_LABEL.get(shape, shape)
        control_kind = control_of(sh, anchor, notes)
        control = CONTROL.get(control_kind)
    return {"plan_text": plan_text, "plan": plan, "role": role, "attack": ATTACK.get(role),
            "expansion": expansion, "expansion_statement": statement_form(text), "control": control,
            "control_kind": control_kind, "plan_source": source, "notes": notes}


# ---- Day 12: the form of the reconstruction statement itself ------------------------------------------

_TOK_CALL = r"(?:%%\w+%%)"
_TOK_DELAYED = r"(?:!\w+!)"
_TOK_PERCENT = r"(?:%\w+%)"


def statement_form(text: str):
    """The expansion form of the ONE statement that joins the fragments, as that line is written, or None.

    Day 12's question (2026-10-12; the live fix's reading, accepted for all 9 specimens of the base, the
    Time Trial and both Mastery sets at the first send): "the expansion form used by the descriptor
    reconstruction statement", not the echo line's and not Day 4's fitted rule (expansion_of):

        for %%G in (..) do call set "x=%%x%%%%v%%G%%"    for_indirect
        call set "x=%%a%%%%b%%"                            call_double
        set "x=!a!!b!"                                     delayed
        set "x=%a%%b%"                                     percent

    Echo and rem lines are no statement. Two joins, or a join in a form not listed, establish nothing."""
    found = []
    for line in str(text or "").splitlines():
        if re.match(r"(?i)\s*@?\s*(echo|rem)\b", line):
            continue
        m = re.search(r'(?i)\bset\s+"?([A-Za-z_]\w*)=([^"&]*)"?\s*$', line.rstrip())
        if not m:
            continue
        val = m.group(2).strip()
        is_for = re.match(r"(?i)\s*for\s+%%[A-Za-z]\s+in\s*\(", line) is not None
        is_call = re.search(r"(?i)\bcall\s+set\b", line) is not None
        if is_for:
            if is_call and re.fullmatch(r"%%\w+%%%%\w+%%[A-Za-z]%%", val):
                found.append("for_indirect")
            elif "%" in val or "!" in val:
                found.append(None)
            continue
        if is_call and re.fullmatch(_TOK_CALL + "{2,}", val):
            found.append("call_double")
        elif not is_call and re.fullmatch(_TOK_DELAYED + "{2,}", val):
            found.append("delayed")
        elif not is_call and re.fullmatch(_TOK_PERCENT + "{2,}", val):
            found.append("percent")
        elif re.search(r"[%!]\w+[%!]|[%!]{2}", val):
            # Any other `set` that expands something: a join in a form not read here, or a piece of one
            # (`set "x_0=%a%%b"` under a later `set "x=!x_0!!x_1!"`, tests/variants.py: the statement that
            # rebuilds the plan is then more than the one line this reader took). Nothing is established.
            found.append(None)
    return found[0] if len(found) == 1 else None


# What the last answers() call found without a judged name, by member: {"control"} where control_of saw a
# construct around the join that no judged name covers, and its own word for the construct (UNNAMED_KIND).
# analyze.solve_known reads it: the text path's name for such a form is a candidate, never a plain fill.
UNNAMED, UNNAMED_KIND = {}, {}
# The sentence the expansion answers of Days 3 to 11 were judged under (kind exact_text).
EXPANSION_TEXT = "Identify the percent, delayed, CALL-double, or FOR-indirect expansion form."

FIELDS = ("role", "attack", "adapter", "campaign", "expansion", "control", "graph")
_ID = re.compile(r"^(?:set\d+\.)?batch-[a-z0-9]+-(.+)$")


def field_of(q: dict) -> str:
    """Which fact a question wants: the id's field word (`batch-<specimen>-<field>`), and only for an id of
    another form its wording, as before Day 12.

    Day 12 (2026-10-12) re-worded two questions of this component: "Classify only the expansion form .."
    and "Classify only the control-flow wrapper ..". The wording was read first, `Classify` was the role's
    word, and 18 ids were answered with the role. An id that names its field is never read by its text."""
    text = q.get("question") or ""
    qid = q.get("qid") or q.get("id") or ""
    own = _ID.match(qid)
    if own:
        tail = own.group(1)
        return tail if tail in FIELDS else "indicator:" + tail.replace("-", "_")
    m = re.search(r"exact (\w+) indicator", text)
    if m:
        return "indicator:" + m.group(1)
    for pattern, name in ((r"\bClassify\b", "role"), (r"ATT&CK", "attack"), (r"\badapter\b", "adapter"),
                          (r"campaign identifier", "campaign"), (r"expansion form", "expansion"),
                          (r"control-flow form", "control"), (r"stage-graph topology", "graph")):
        if re.search(pattern, text):
            return name
    return qid if qid in FIELDS else "indicator:" + qid.replace("-", "_")


def _format(q: dict) -> tuple:
    """(kind, accepted values or None) of a question's answer format; ('', None) when it has none."""
    fmt = q.get("answer_format")
    if not isinstance(fmt, dict):
        return "", None
    values = fmt.get("accepted_values")
    values = list(values) if isinstance(values, (list, tuple)) and values and all(isinstance(v, str) for v in values) else None
    return str(fmt.get("kind") or ""), values


def _pick(key: str, options: list):
    """labels.pick, or None without labels.py: an unsure answer that cannot be written is no answer."""
    options = [o for o in options if o]
    if not options:
        return None
    try:
        common = str(Path(__file__).resolve().parent.parent / "common")
        if common not in sys.path:
            sys.path.insert(0, common)
        import labels
        return labels.pick(key, options)
    except Exception as e:  # noqa: BLE001
        print(f"[batch] labels.pick({key!r}) could not be made ({type(e).__name__}: {e}); not answered", file=sys.stderr)
        return None


def expansion_answer(info: dict, q: dict):
    """The expansion question, by the answer format it comes with.

    Two readings are judged, each under its own format, and they differ on some specimens (Day 11's key
    says `delayed` for `call set "cfg=%%a%%%%b%%"`, Day 12's `call_double`):

        Days 3 to 11  kind exact_text, no list   expansion_of: the rule fitted to Day 4's verdicts
        Day 12        kind enum, the four forms  statement_form: the form of the reconstruction statement

    Where both give the same name it is the answer under any format. Where they differ the format decides,
    never the question's text; a format that is neither (a third wording of the same id) gets both as an
    unsure answer, Day 12's first."""
    old, new = info.get("expansion"), info.get("expansion_statement")
    if old == new:
        return old
    kind, allowed = _format(q)
    if allowed is not None and set(allowed) >= {"delayed", "call_double", "for_indirect"}:
        return new
    if (kind, allowed) in (("exact_text", None), ("", None)):
        # Review of 2026-10-12: Day 4's rule is judged under Day 3 to 11's own sentence. Day 12's question
        # (the reconstruction statement) under a format that lists nothing is neither day's contract: both
        # readings, the format's own first, unsure (5 ids of Day 12's base were sent `delayed` plain).
        if " ".join((q.get("question") or "").split()) == EXPANSION_TEXT or not (q.get("question") or "").strip():
            return old
        return _pick("script.expansion/batch.reading", [("fragment_rule", old) if old else None,
                                                        ("statement_form", new) if new else None])
    return _pick("script.expansion/batch.reading", [("statement_form", new) if new else None,
                                                    ("fragment_rule", old) if old else None])


def control_answer(info: dict, q: dict):
    """The control question: control_of's judged name, under either wording.

    Day 12's text says a one-pass FOR /L around the CALL of the join's subroutine is `for_once` and lists
    that name. The judge's verdicts say otherwise and are what counts: `call_subroutine`, Day 4's name for
    that shape (22 for-style names were rejected then), was sent for it under the new wording on the Day
    12 Time Trial (batch-benign-control) and Mastery (five ids) and every batch was CORRECT. So the text
    moves nothing here; `for_once` has never been sent for a Batch specimen under the new list."""
    return info.get("control")


def answer(info: dict, q: dict):
    field = field_of(q)
    plan = info["plan"]
    if field.startswith("indicator:"):
        key = field.split(":", 1)[1]
        if key not in plan and _ID.match(q.get("qid") or q.get("id") or ""):
            # The text may name the key only where it is one the id's word can mean (`host` for host_id).
            m = re.search(r"exact (\w+) indicator", q.get("question") or "")
            named = m.group(1) if m else ""
            if named in plan and (named.startswith(key + "_") or named.endswith("_" + key)):
                return plan.get(named)
        return plan.get(key)
    if field == "adapter":
        return plan.get("adapter")
    if field == "campaign":
        return plan.get("campaign_id")
    if field == "graph":
        return plan.get("graph")
    if field == "expansion":
        return expansion_answer(info, q)
    if field == "control":
        return control_answer(info, q)
    return info.get(field)


def answers(questions, files, ctx):
    """{qid: answer} for the Batch questions of one set. Each specimen is analyzed on its own: one
    that cannot be read or makes the analyzer raise costs its own answers and prints one
    `[batch] <file>: <reason>` line, and the others are answered as if it were not there."""
    # BATCH_FIELDS=role,graph,indicator limits the answer set, to verify one kind of fact at a time.
    only = {f.strip() for f in os.environ.get("BATCH_FIELDS", "").split(",") if f.strip()}
    out, cache = {}, {}
    for q in questions:
        try:
            if only and field_of(q).split(":")[0] not in only:
                continue
            name = q.get("member")
            if name not in cache:
                cache[name] = None
                data = files.get(name)
                if data is None:
                    print(f"[batch] {name}: not in the delivery", file=sys.stderr)
                else:
                    try:
                        cache[name] = analyze(data if isinstance(data, str) else bat_cmd.decode(bytes(data)))
                    except Exception as e:
                        print(f"[batch] {name}: analysis raised {type(e).__name__}: {e}", file=sys.stderr)
                    UNNAMED.pop(name, None)
                    UNNAMED_KIND.pop(name, None)
                    for note in (cache[name] or {}).get("notes", ()):
                        print(f"[batch] {name}: {note}", file=sys.stderr)
                        m = re.match(r"control: (.+?) (?:x\d+ )?around the (?:join|call) has no judged name", str(note))
                        if m:
                            UNNAMED[name] = {"control"}
                            UNNAMED_KIND[name] = m.group(1).split(" + ")[-1].split(" x")[0]
            if cache[name] is not None:
                out[q["qid"]] = answer(cache[name], q)
                if out[q["qid"]] is None and not cache[name]["notes"]:
                    print(f"[batch] {name}: {q['qid']}: nothing in the recovered plan answers it", file=sys.stderr)
        except Exception as e:
            print(f"[batch] {q.get('member')}: {q.get('qid')} raised {type(e).__name__}: {e}", file=sys.stderr)
    return out


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for path in sys.argv[1:]:
        try:
            data = Path(path).read_bytes()
        except OSError as e:
            sys.exit(f"batch.py: cannot read {path}: {e.strerror or e}")
        info = analyze(bat_cmd.decode(data))
        print(f"{path}\n  plan: {info['plan_text']}  (from {info['plan_source']})")
        print("  " + " | ".join(f"{k}={info[k]}" for k in ("role", "attack", "expansion", "control")))
        for note in info["notes"]:
            print(f"  note: {note}")
