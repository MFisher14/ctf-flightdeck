#!/usr/bin/env python3
"""What the Script Analysis lane can answer about a language it has never seen.

Usage:
  python3 solvers/script-analysis/generic.py <specimen> [...]     print the triage block of each file

Runner contract (called from analyze.py for any extension without a module):

    answers(questions, files, ctx) -> {qid: answer}

Nothing here parses or runs the specimen. plan_codec.py recovers the plan from the text, and
the plan answers most of what the lane asks:

  the field        what a question asks for is read from the end of its id: the id without the
                   words all ids of the specimen share (with_fields), so `windows-chain` in
                   `python-current-pyc-launcher-windows-chain`. A specimen with one question
                   keeps the old rule, the third part of the id. The question's TEXT never
                   chooses the field of an id that names one (Day 12, 2026-10-12: names_field,
                   id_asks): role, attack and control are the id's words, `none` is permitted by
                   the answer format or the text (permits_none), and "exact <key> indicator"
                   speaks only for a key the id's word can mean (text_key). A stated `none`
                   that nothing permits is unsure under script.attack/v3.stated_none.
  role             the ordered `steps`, looked up in the table of the eight judged graphs. A
                   steps tuple that is not in the table is a new fact, named on one stderr
                   line, and goes through labels.pick('script.role/<ext>.<step+step>', ...):
                   plain only once the judge has accepted a name under that key of this
                   extension (the four .py lists of Day 5 are in the seed), unsure with the
                   name accepted for the same steps under another extension's key. A step
                   list judged nowhere is offered the names the question itself lists, best
                   first (role_candidates), unsure, while OFFER_UNSEEN_ROLES is on (it is
                   since 2026-10-05, on the player's word); with it off the answer is None.
  attack           the role's technique. A launcher and a staged chain are the script's own
                   interpreter, which is a name per language, so they come back as
                   labels.pick('script.attack/<ext>', the techniques that fit the extension).
                   For a steps tuple outside the table: the techniques of the roles offered
                   for it, under 'script.attack/<ext>.<step+step>', or None. Day 12's keys
                   (stated_v3, GRAPH_SCHEDULE_KEY) make plain what that day's verdicts cover:
                   a version-3 plan's own `attack=` in an extension not yet judged, and
                   build_schedule+register_descriptor. The four keys Day 12's probes spent
                   (script.attack/php, /lua, /mof, /ts) are not asked again (own_key).
  adapter, campaign, graph, "exact <key> indicator", a field named like a plan key
                   the plan's own values. A plan read from what plan_codec grades a piece
                   of its material (sources: a chunk, a line of a wrapped block, a join
                   that goes on) comes without its last field, so that one stays None, and
                   no key that is only near the asked one answers. The grades cover the
                   forms listed there, not every way to split a material.
  representation, transform
                   the in-file codec label (`HUNTRESS-CODEC:` or a `Codec_x = "..."` constant):
                   plain where its words were judged (LABEL_JUDGED: .vbs), else unsure under
                   script.<field>/<ext>.codec_label, the label first (Day 13 preparation: .py,
                   .mjs and .sh answered them plain, where no day asked).
                   Without a label the decode itself is known (hex with
                   colons, a single-byte xor) but not the author's word for it, so the names
                   the VBScript and Batch label tables use for the same decode come back
                   unsure: pick('script.representation/<ext>.<how>', ...) and
                   pick('script.transform/<ext>.<kind>', ...). A constant that names no
                   transform (`Codec_x='decimal_csv|'`) is no label; its word leads the unsure
                   names: pick('script.representation/<ext>.codec_label', ...) (bare_label).
  a new field word an alias of a field (`technique`, `classification`, `stages`) or a field with one
                   more word (`graph-attack`): answered as that field and sent unsure, never plain
                   (renamed, reworded; Day 13 preparation). A word that is only a part of a
                   version-3 plan key (`host` beside host_profile) answers nothing (row 273 b).
  everything else  shapes_<ext>.py if a racer has written one
                   (shapes(text, questions) -> {qid: value}); what it leaves open goes to
                   census.py if it is a control-flow question (census.answer(q, text, ext));
                   else None. Question by question: a shapes file written for one field
                   does not take the census answers of another away.

The tagged descriptor (row 101, 2026-10-08; DESCRIPTOR). A file that carries `HUNTRESS_ANALYSIS_V<n>:<TAG>-..`
or a `descriptor_<id>` literal (Day 8: twelve specimens in .php, .js and .vbs) is read by descriptor.py,
whole or not at all (row 113): its plan is taken when it agrees with every field plan_codec read, a
descriptor that is not ONE whole plan (a cut or decorated payload, a comment and a literal that differ, in
one copy a stage_count that is not the number of steps) answers nothing from any plan, and neither does a
whole one that lacks a plan field the questions ask for. A plan that states its own `role=` or `attack=` (version 3)
is answered from that statement, never from the steps table when the two differ: plain where the judge
has accepted the stated value for that extension and plan version (STATED_JUDGED: Day 8's key took all
twelve, four of which the steps table gets wrong) or where the table gives the same value, else
labels.pick('script.role/<ext>.stated_v<n>', stated first), which the untimed base probes. A plan taken
without its last field because its one copy may be a piece keeps that field, when the tagged comment gave
every field of its version, as an unsure answer: labels.pick('script.<key>/<ext>.one_copy', as read)
(one_copy; Day 12 look-ahead).

A second plan source (LABEL_PLAN, row 37): when plan_codec gives no plan or a cut one, the file's
own `Material_<id>` / `Codec_<id>` pair is decoded by label_plan.py, for every extension. Its plan
is taken only when it agrees with every field plan_codec read (by_label).

Four things keep a doubtful reading from going out as a plain answer. A file that decodes to
two different plans, or that carries two different codec labels, establishes neither (see
plan_codec.reading and label_of): the plan answers are None and the codec names fall back to
the unsure candidates. A plan read from a piece loses its last field, as above. And an answer
that the question's own accepted_values do not list is None (listed()), whoever gave it.

A plain answer given here is final for the specimen: shapes_<ext>.py is asked only what was
left open, so a wrong reading of the general path is replaced only by a lang_<ext>.py.

An answer is plain only where the fact and its name are both established; see
docs/ops/contracts.md. A missing answer is None, never a default.

One triage block per file goes to stderr: the decoded plan, the label, the census result, a
steps tuple or plan key the lane has not seen before, and the ids left unanswered. It is
what the agents read first when a new language appears.
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _p in (HERE, HERE.parent / "common"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import plan_codec  # noqa: E402

try:
    import labels  # noqa: E402
except Exception as _e:  # noqa: BLE001 - without labels.py nothing can be unsure, so those answers stay None
    print(f"[generic] solvers/common/labels.py did not load ({type(_e).__name__}: {_e}); unsure answers are left out",
          file=sys.stderr)
    labels = None

# Ordered behaviour steps -> role: the eight graphs the judge has accepted, in three languages.
ROLE = {
    ("decode_configuration", "return_configuration"): "benign_utility",
    ("acquire_remote", "dispatch_memory"): "stager",
    ("decode_embedded", "write_file"): "dropper",
    ("acquire_remote", "write_file"): "downloader",
    ("locate_local", "dispatch_process"): "launcher",
    ("locate_local", "prepare_transfer", "upload_remote"): "uploader",
    ("enumerate_targets", "transform_content", "write_recovery_note"): "impact",
    ("acquire_remote", "write_file", "dispatch_process", "handoff_script"): "staged_chain",
}
# Role -> primary technique, the same in JScript, Batch and VBScript. The two roles that run
# something take the specimen's own interpreter (OWN_INTERPRETER), whatever binary or next
# stage the plan names: T1218.010 and T1059.001 were judged incorrect for JScript.
ATTACK = {"benign_utility": "none", "stager": "T1105", "dropper": "T1140", "downloader": "T1105",
          "uploader": "T1041", "impact": "T1486"}
OWN_INTERPRETER = ("launcher", "staged_chain")

# Candidate techniques for "the script's own interpreter", best first, by extension. Only
# hta, wsf, sct and py have been asked so far; the others are the extensions a later day may bring.
TECHNIQUES = {
    "hta": ["T1218.005", "T1059.005", "T1059.007"],      # mshta, then the script language inside
    "wsf": ["T1059.005", "T1059.007"],
    "sct": ["T1218.010", "T1059.007"],                   # regsvr32 scriptlet
    "py": ["T1059.006"], "pyw": ["T1059.006"],
    "sh": ["T1059.004"], "bash": ["T1059.004"], "zsh": ["T1059.004"], "ksh": ["T1059.004"],
    "psm1": ["T1059.001"], "psd1": ["T1059.001"],
    "mjs": ["T1059.007"], "cjs": ["T1059.007"], "ts": ["T1059.007"],
    "vba": ["T1059.005"], "bas": ["T1059.005"],
    "xlm": ["T1059.005", "T1059"],                       # row 93: Excel 4.0 macro sheets (no sub-technique of their own)
    "applescript": ["T1059.002"], "scpt": ["T1059.002"],
    "au3": ["T1059.010"], "ahk": ["T1059.010"],
    "lua": ["T1059.011"],
    "node_pkg": ["T1059.007"], "nexe": ["T1059.007"], "node_sea": ["T1059.007"], "bytenode": ["T1059.007"],   # row 94
    "bun": ["T1059.007"], "deno": ["T1059.007"],
    # No sub-technique of their own: the parent, then the shell that starts them.
    "pl": ["T1059", "T1059.004"], "rb": ["T1059", "T1059.004"], "php": ["T1059", "T1059.004"],
    "tcl": ["T1059", "T1059.004"], "awk": ["T1059.004", "T1059"],
    # Row 78 (2026-10-07): the languages rehearsed by tests/next_components.py. A script host of .NET (csi,
    # dotnet-script, dotnet fsi) is also a trusted developer utility, T1127. Swift and the others have no
    # sub-technique of their own: the parent first (osascript's T1059.002 is AppleScript only, never Swift).
    # Every one of them is an unsure option (labels.pick) until the judge accepts a name.
    "csx": ["T1059", "T1127"], "fsx": ["T1059", "T1127"],
    "swift": ["T1059", "T1059.004"], "kts": ["T1059", "T1059.004"], "java": ["T1059", "T1059.004"],
    "dart": ["T1059", "T1059.004"], "jl": ["T1059", "T1059.004"], "exs": ["T1059", "T1059.004"],
    "clj": ["T1059", "T1059.004"], "scm": ["T1059", "T1059.004"], "rkt": ["T1059", "T1059.004"],
    "nim": ["T1059", "T1059.004"], "fish": ["T1059.004", "T1059"],
    # Day 9 preparation (2026-10-08): containers, carriers and infrastructure files a script may arrive in,
    # and more source languages. Candidates only, the technique of the HOST first, then the language inside;
    # every one goes through labels.pick and is unsure until the judge accepts a name for the extension.
    "wsc": ["T1218.010", "T1059.005", "T1059.007"],
    "asp": ["T1505.003", "T1059.005", "T1059.007"], "aspx": ["T1505.003", "T1059", "T1059.001"],
    "ashx": ["T1505.003", "T1059"], "asmx": ["T1505.003", "T1059"],
    "jsp": ["T1505.003", "T1059"], "jspx": ["T1505.003", "T1059"], "cfm": ["T1505.003", "T1059"],
    "csproj": ["T1127.001", "T1059"], "proj": ["T1127.001", "T1059"], "targets": ["T1127.001", "T1059"],
    "xsl": ["T1220", "T1059.007", "T1059.005"], "xslt": ["T1220", "T1059.007", "T1059.005"],
    "html": ["T1059.007", "T1027.006", "T1204.004", "T1204.002"], "htm": ["T1059.007", "T1027.006", "T1204.004", "T1204.002"],
    "svg": ["T1059.007", "T1027.017", "T1027.006"], "xhtml": ["T1059.007", "T1027.006"],
    "chm": ["T1218.001", "T1059.007"], "hhc": ["T1218.001"], "one": ["T1204.002", "T1059.005"],
    "lnk": ["T1204.002", "T1547.009", "T1059.001", "T1059.003"], "url": ["T1204.001", "T1204.002"],
    "reg": ["T1112", "T1547.001"], "inf": ["T1218.011", "T1218.003"], "cpl": ["T1218.002"], "msc": ["T1218.014"],
    "jxa": ["T1059.007", "T1059.002"], "command": ["T1059.004", "T1204.002"], "plist": ["T1543.001", "T1547.011"],
    "dockerfile": ["T1059.004", "T1610", "T1204.003"], "yml": ["T1059.004", "T1059", "T1195.002"],
    "yaml": ["T1059.004", "T1059", "T1195.002"], "makefile": ["T1059.004", "T1059"], "mk": ["T1059.004", "T1059"],
    "service": ["T1543.002", "T1059.004"], "timer": ["T1053.006", "T1543.002"], "crontab": ["T1053.003", "T1059.004"],
    "cron": ["T1053.003", "T1059.004"], "desktop": ["T1547.013", "T1204.002", "T1059.004"],
    "toml": ["T1059", "T1059.004"], "json": ["T1059", "T1059.007"], "json5": ["T1059", "T1059.007"],
    "sql": ["T1059", "T1505.001"], "btm": ["T1059.003"],
    "c": ["T1059", "T1027.004"], "cpp": ["T1059", "T1027.004"], "rs": ["T1059", "T1027.004"], "zig": ["T1059", "T1027.004"],
    "sc": ["T1059", "T1059.004"], "scala": ["T1059", "T1059.004"], "hs": ["T1059", "T1059.004"],
    "ml": ["T1059", "T1059.004"], "raku": ["T1059", "T1059.004"], "cr": ["T1059", "T1059.004"],
    "coffee": ["T1059.007", "T1059"], "groovy": ["T1059", "T1059.004"], "go": ["T1059", "T1059.004"],
    "r": ["T1059", "T1059.004"], "ps1xml": ["T1059.001"], "psc1": ["T1059.001"],
}
# The four languages that have a module. Their extensions reach this file only when the module
# is missing (or hidden in a rehearsal), and their own interpreter is the first candidate.
OWN_TECHNIQUE = {"ps1": "T1059.001", "cmd": "T1059.003", "bat": "T1059.003", "vbs": "T1059.005",
                 "vbe": "T1059.005", "js": "T1059.007", "jse": "T1059.007"}
# Every candidate for an extension follows its own with the rest of this list: the six
# interpreters asked or expected first, the parent technique, then the other sub-techniques.
ANY_INTERPRETER = ["T1059.001", "T1059.003", "T1059.005", "T1059.006", "T1059.007", "T1059.004",
                   "T1059", "T1059.010", "T1059.011", "T1059.002", "T1059.009", "T1059.008"]
MAX_OPTIONS = 12     # labels.MAX_OPTIONS: the options one unsure answer carries

# Whether a step list the judge has named NOWHERE gets role and technique candidates built
# from the question's own list (role_candidates). Those are names of different facts under one
# key, which the unsure-answer contract otherwise does not allow (its options are spellings of
# ONE fact). Switched on by the player on 2026-10-05, on the condition that it never slows a
# solve: the candidates are unsure, so Layer 1 probes them on the untimed base at the end of
# its pass, when every other lane's clocks are done and the lane's agents are already at
# work. Never a plain answer. Read at call time.
OFFER_UNSEEN_ROLES = True

# Whether a file whose plan plan_codec cannot read whole (none, or a cut one) is read a second
# way, by its own codec label (label_plan.reading: `Material_<id>` decoded as `Codec_<id>`
# says, else every reading the plan grammar accepts). Row 37, on the player's word of
# 2026-10-07. The label plan is taken only when it holds every field plan_codec did read, with
# the same value; two different plans answer nothing (by_label). Read at call time.
LABEL_PLAN = True

# Whether a tagged descriptor (descriptor.py) is read at all. Read at call time.
DESCRIPTOR = True

# B-227: whether a plan the readers above left cut, one-copy or unread is asked of blind_reader.py, the
# language-blind container reader (a join in any idiom, a concatenation chain, an escaped string-literal host).
# Its plan is taken only whole, and only when every field already read agrees (by_blind). Read at call time.
BLIND_READER = True
# descriptor.reading_ex's refusal of a SPLIT file whose tagged copy is in a join its table does not hold: the one
# refusal by_blind may settle, and only with a tagged copy and a second copy that agree.
SPLIT_UNREAD = "a SPLIT marker whose tagged copy this reader does not read"
# B-247: whether residuals.py weighs the copies the readers above do not see (the exact HUNTRESS_DESCRIPTOR key,
# wrapped and deep tagged comments, deep untagged literals, computed JavaScript values) and nested base64 hosts.
# A copy that gives another plan withdraws the plan read; an open plan is lifted only whole. Read at call time.
RESIDUALS = True

# The Day 20 build (the Day 19 build's review, left open there): a file with NO SPLIT marker whose real copies are
# in forms nothing reads (template literals, pieces joined after .reverse()) and that keeps an older pair of copies
# in dead text (a /* */ block, a template or multi-line string, a docstring, comment lines). plan_codec reads the
# file's literals wherever they stand, so it read the older pair: 26 of 429 staged ids WRONG plain. Now a plan
# plan_codec read from a file that carries a tagged-looking value with a run of material behind its tag (a quoted
# `<TAG>-` and 16 or more characters of material, or a SPLIT name) is read once more with the dead text blanked;
# when that reading does not give the same plan, the plan stood only in dead text. The verdict is applied only
# AFTER the descriptor reader (fix of the review of ddd83c0): a plan the descriptor settled stands as it settles
# it (the dead plan is still a witness there, so a descriptor plan that differs from it is nothing, as before), and
# only a plan that is still plan_codec's own is dropped. Comment LINES are blanked by the file's own language only
# (_LINE_COMMENTS by extension; an extension not listed has none blanked): a `'` line is code in JavaScript and in
# Python, a `#` line a private field in JavaScript. Nothing else is touched: a material in a heredoc or a
# triple-quoted string of a file without such a value is read as before. Read at call time.
DEAD_TEXT_GUARD = True
_LINE_COMMENTS = {}
for _exts, _lead in (("py pyw sh bash zsh ksh fish ps1 psm1 psd1 rb pl pm r tcl nim cr coffee jl awk ex exs yaml yml "
                      "nu php", "#"),
                     ("js mjs cjs jsx ts tsx mts cts gs jse php java kt kts c h cc cpp hpp cs go rs swift scala dart "
                      "groovy d zig fs", "//"),
                     ("lua sql hs applescript ada elm", "--"),
                     ("au3 ahk ini lisp clj el scm asm reg", ";"),
                     ("vbs vbe vba bas cls frm", "'")):
    for _e in _exts.split():
        _LINE_COMMENTS.setdefault(_e, []).append(re.escape(_lead))
_LINE_COMMENTS = {e: re.compile(r"(?m)^[ \t]*(?:%s)[^\n]*" % "|".join(v)) for e, v in _LINE_COMMENTS.items()}
del _exts, _lead, _e
_HINT_PAYLOAD = 16                                          # material behind a quoted `<TAG>-` that sets the guard off
_MATERIAL_RUN = re.compile(r"[A-Za-z0-9+/=._:-]{16,}")      # what a piece of encoded material looks like
# `name = <opener>material<closer>` at the start of a line: a template literal, a triple-quoted string (a prefix
# letter allowed) or a Lua long bracket whose whole content is material, one run or runs one to a line (no quote,
# bracket, comma or code: a decoy pair of assignments in a string keeps its quotes and stays dead)
_RUNS = r"\s*[A-Za-z0-9+/=._:-]{16,}(?:\s+[A-Za-z0-9+/=._:-]{16,})*\s*"
_ASSIGNED_MATERIAL = re.compile(r"(?m)^[ \t]*(?:(?:const|let|var|local|my|our)[ \t]+)?[$@]?(?P<name>[A-Za-z_][\w]*)"
                                r"[ \t]*:?=[ \t]*(?P<body>[rRbBuU]?(?P<q>`|\"\"\"|''')" + _RUNS + r"(?P=q)"
                                r"|\[(?P<eq>=*)\[" + _RUNS + r"\](?P=eq)\])")
_MARKER_RUN = re.compile(r"HUNTRESS[_-]?ANALYSIS[_-]?V\d+[:_-]?(?:SPLIT|WRAPPED|REVERSED)(?:[:=_-][A-Za-z0-9_]{0,16})?", re.I)

# (extension, plan version) whose own `role=` and `attack=` the judge has accepted as the answers: Day 8,
# 2026-10-08, key.json of the base, the Time Trial and the Mastery (84 specimens, one accepted batch each;
# on four of the twelve the steps table gives another role and technique, which would have been wrong).
# Anywhere else a stated value that differs from the table's is unsure: labels.pick under
# `script.<field>/<ext>.stated_v<n>`, the stated value first.
STATED_JUDGED = {("php", "3"), ("js", "3"), ("vbs", "3")}
# Row 113: the fields Day 8 asked of a descriptor, by the end of the answer id, and the plan key that holds
# each. A descriptor plan that lacks one of those asked is a plan cut between two fields (both copies cut
# alike pass every other check), and then nothing is answered from it.
DESCRIPTOR_FIELDS = {"next-language": "next_language", "stage-profile": "stage_profile", "host-profile": "host_profile",
                     "stage-count": "stage_count", "obfuscation": "obfuscation_profile", "file-path": "file_path",
                     "campaign": "campaign_id", "adapter": "adapter", "steps": "steps", "url": "url"}
ATTACK_ID = re.compile(r"T\d{4}(?:\.\d{3})?")

# Step words -> the techniques they name, offered for a step list no day has judged (unseen),
# while OFFER_UNSEEN_ROLES is on: scheduling a job or registering a descriptor
# (nodejs-persistence: T1053.003 on Day 7), and sending data out.
STEP_TECH = (("schedule", ("T1053.003", "T1053.006", "T1543.002", "T1053")),
             ("register_descriptor", ("T1053.003", "T1053.006", "T1543.002", "T1053")),
             ("transmit", ("T1041", "T1048", "T1567")))

# Row 50 (the player, 2026-10-07): more step words -> the ATT&CK techniques they name, after STEP_TECH
# (so Day 7's judged order stands). Matched as a part of the joined step list; unsure options only.
STEP_WORDS = (("inject", ("T1055",)), ("hollow", ("T1055.012", "T1055")),
              ("run_key", ("T1547.001",)), ("registry_run", ("T1547.001",)), ("startup", ("T1547.001",)),
              ("service", ("T1543.003", "T1543.002")), ("systemd", ("T1543.002",)),
              ("launch_agent", ("T1543.001",)), ("cron", ("T1053.003",)), ("scheduled_task", ("T1053.005",)),
              ("clipboard", ("T1115",)), ("keylog", ("T1056.001",)), ("screenshot", ("T1113",)),
              ("browser_cred", ("T1555.003",)), ("credential", ("T1555", "T1003")),
              ("archive", ("T1560.001", "T1560")), ("compress", ("T1560",)),
              ("exfil", ("T1567", "T1041", "T1048")), ("upload", ("T1041", "T1567")),
              ("wmi", ("T1047",)), ("discover", ("T1082",)), ("profile_host", ("T1082",)),
              ("enumerate", ("T1083",)), ("process_list", ("T1057",)), ("network_config", ("T1016",)),
              ("decode", ("T1140",)), ("deobfuscate", ("T1140",)),
              ("download", ("T1105",)), ("acquire_remote", ("T1105",)),
              ("delete", ("T1070.004",)), ("timestomp", ("T1070.006",)),
              ("mine", ("T1496",)), ("encrypt_files", ("T1486",)))

# Plan keys seen on Days 2 to 5; anything else is printed in the triage block as new.
KNOWN_KEYS = {"v", "language", "role", "verdict", "attack", "host_profile", "obfuscation_profile", "stage_profile",
              "steps", "adapter", "stage_count", "stageCount", "graph", "next_language", "campaign_id",
              "host_id", "url", "file_path", "source_path", "upload_url", "extension", "note_name", "next_stage",
              "registry_path", "target_root", "user_agent", "syntax", "obfuscation", "carrier", "windows_chain",
              "feature", "primitive"}
TRIAGE_WIDTH = 600   # characters of a plan printed in the triage block


def techniques(ext) -> list:
    """The ordered candidates for the own-interpreter technique of an extension: the table's
    (or the language's own) first, then the rest of ANY_INTERPRETER, at most MAX_OPTIONS."""
    ext = plan_codec.ext_name(ext)
    first = list(TECHNIQUES.get(ext) or ([OWN_TECHNIQUE[ext]] if ext in OWN_TECHNIQUE else []))
    return (first + [t for t in ANY_INTERPRETER if t not in first])[:MAX_OPTIONS]


def pick(key, options):
    """labels.pick, or None when labels.py is not there or refuses the key."""
    if labels is None or not options:
        return None
    try:
        return labels.pick(key, options)
    except Exception as e:  # noqa: BLE001 - a bad key must cost one answer, not the set
        print(f"[generic] labels.pick({key!r}) raised {type(e).__name__}: {e}", file=sys.stderr)
        return None


# ---------------------------------------------------------------- reading a question

def bare_id(q: dict) -> str:
    """A question's id without a `setN.` prefix."""
    return re.sub(r"^set\d+\.", "", q.get("qid") or q.get("id") or "")


def fields_of(qs: list) -> dict:
    """{id: field} for the questions of ONE specimen: each id without the leading words all of
    them share (`python-current-pyc-launcher-` in `python-current-pyc-launcher-windows-chain`).
    Empty when there is nothing to compare: one question, or no shared word."""
    parts = [bare_id(q).split("-") for q in qs]
    if len({tuple(p) for p in parts}) < 2:
        return {}
    n = 0
    while all(len(p) > n + 1 for p in parts) and len({p[n] for p in parts}) == 1:
        n += 1
    return {"-".join(p): "-".join(p[n:]) for p in parts} if n else {}


def with_fields(qs: list) -> list:
    """The questions of ONE specimen, each carrying its field as q["field"] (fields_of), on a
    copy. A question that has one already, or that fields_of says nothing about, is passed
    as it is. Called where all questions of the specimen are known (analyze.solve_set, and
    answers() below for a direct call): a later call with fewer of them keeps these fields."""
    if all("field" in q for q in qs):
        return qs
    found = fields_of(qs)
    return [q if "field" in q or bare_id(q) not in found else {**q, "field": found[bare_id(q)]} for q in qs]


# The id forms the lane knows, and the one way back to them (Day 13 preparation, 2026-10-12; used by
# analyze.id_forms, the one place an unanswered id is read a second time). Every saved id of Days 1 to 12
# (83,430) is lower case, `-` between its words, begins with one of these component words and ends in no
# version: none of them is touched.
ID_WORDS = ("resource", "collection", "impact", "jscript", "batch", "vbscript", "python", "bash", "nodejs", "polyglot",
            "host", "powershell")
LANE_WORDS = ("script-analysis", "script_analysis", "scriptanalysis", "scripts", "script", "analysis", "sa")
_ID_PREFIX = re.compile(r"(?:d(?:ay)?[-_]?\d{1,2}|" + "|".join(LANE_WORDS) + r")[-_.:]")
_ID_SUFFIX = re.compile(r"[-_.](?:v\d{1,3}|\d{1,3})$")


def id_known(bare: str, words) -> bool:
    """Whether an id (without `setN.`) is of a form the lane knows."""
    return bare == bare.lower() and bare.split("-", 1)[0] in words and "-" in bare and not _ID_SUFFIX.search(bare)


def normal_id(bare: str, words):
    """(normal id, transform) of an id whose raw form the lane does not know and whose normal form it does;
    None for every other id. The transform names what was done, in a fixed order: `lower`, `prefix` (a
    leading `dNN-`, `dayNN-` or lane word), `version` (a trailing `-vN` or `-N`), `underscore` (`_` between
    the words), joined by `+`."""
    if not bare or id_known(bare, words):
        return None
    done, i = [], bare
    if i != i.lower():
        i, done = i.lower(), done + ["lower"]
    for _ in range(2):                           # `d13-script-..`
        m = _ID_PREFIX.match(i)
        if not m or id_known(i, words):
            break
        i, done = i[m.end():], done + (["prefix"] if "prefix" not in done else [])
    m = _ID_SUFFIX.search(i)
    if m:
        i, done = i[:m.start()], done + ["version"]
    if not id_known(i, words) and "_" in i:
        i, done = i.replace("_", "-"), done + ["underscore"]
    return (i, "+".join(done)) if done and id_known(i, words) else None


def normal_ids(qs: list, words) -> dict:
    """{raw qid: (normal qid, transform)} for the questions of ONE specimen that normal_id renames; {} when a
    normal id would be the id of another question of the specimen (then it is a question of its own)."""
    out, taken = {}, {q.get("qid") for q in qs}
    for q in qs:
        qid = q.get("qid") or ""
        head = re.match(r"set\d+\.", qid)
        got = normal_id(qid[head.end():] if head else qid, words)
        if got is None:
            continue
        twin = (head.group(0) if head else "") + got[0]
        if twin in taken:
            return {}
        taken.add(twin)
        out[qid] = (twin, got[1])
    return out


def tail_of(q: dict) -> str:
    """The field a question asks for: q["field"] when the specimen's questions were compared
    (with_fields), else the third part of an id `<language>-<specimen>-<field>`."""
    field = q.get("field")
    if isinstance(field, str) and field:
        return field
    qid = bare_id(q)
    parts = qid.split("-", 2)
    return parts[2] if len(parts) == 3 else qid


# Which field a question asks is the ID's to say, never a word of its text (Day 12, 2026-10-12: the judge
# re-worded 219 old ids; "Classify only the expansion form .." was taken for a role question, and a rubric
# that spells out "Command and Scripting Interpreter" for Day 7's own-interpreter question: 22 wrong plain
# answers). An id of three or more words, or one whose specimen's ids were compared (with_fields), names
# its field: the text is not asked. Only an id that leaves the field open (`sample`, `one-question`) is
# read by its answer format and then by its wording, as before.

def names_field(q: dict) -> bool:
    """Whether the question's id itself names the field it asks for."""
    field = q.get("field")
    if isinstance(field, str) and field:
        return True
    return len(bare_id(q).split("-", 2)) == 3


def compared(q: dict) -> bool:
    """Whether the question's field word was found by comparing its specimen's ids (with_fields): then every
    word of it is the field's own, and none is a word of the specimen's name."""
    field = q.get("field")
    return isinstance(field, str) and bool(field)


def id_asks(q: dict, field: str):
    """True or False where the id says whether `field` is asked, None where it leaves that open.

    An id whose specimen's ids were compared asks `field` only when its field word IS that word: a tail that
    only ends in it (`graph-attack`, `stated-attack`, `primary-role`) is another field, which no day has
    judged (Day 13 preparation: it was taken for the attack question and given the plan's stated value
    plain; see renamed). An id that was not compared may carry words of its specimen's name in front of
    the field (`current-pyc-launcher-role`, the third part of an id read alone), so there the ending counts."""
    tail = tail_of(q)
    if tail == field:
        return True
    if tail.endswith("-" + field) and not compared(q):
        return True
    return False if names_field(q) else None


# Day 13 preparation (2026-10-12). Two ways an id's field word can be new while the fact behind it is one
# the lane reads, and what is done with each. Neither is ever answered plain: no day has judged the word.
#
#   an alias      the word is another name for a field the lane answers (ALIASES: `technique` for attack,
#                 `classification` for role, `stages` for the step list). The question is answered as that
#                 field's, and the answer goes out unsure under `script.<asked>/<ext>.alias_<field>`, with the
#                 field's own answer as its one option (or the options of that field's unsure answer). A word
#                 that can mean two fields is read by the answer format (`stages` asked as an integer is the
#                 stage count).
#   one more word the field word only ENDS in a field the lane answers (EXTRA_FIELDS) and carries a word in
#                 front (`graph-attack`, `stated-role`, `second-url`). It is a new field. It goes out unsure
#                 under `script.<asked>/<ext>.new_<field>` with the readings the word can mean: for attack and
#                 role what the plan states and what its ordered steps give (the steps' reading first for a
#                 word like `graph`, the statement first for `stated`, else the field's own answer first);
#                 for the others the field's own answer alone. Only for an id whose specimen's ids were
#                 compared (compared), never for a tail that is itself a judged field (KNOWN_TAILS) or that
#                 names a key of the plan (`upload-url` beside upload_url: the plan's own key, as ever).
ALIASES = {
    "technique": ("attack",), "technique-id": ("attack",), "attack-id": ("attack",), "attack-technique": ("attack",),
    "mitre-attack": ("attack",), "mitre-technique": ("attack",), "mitre-id": ("attack",),
    "classification": ("role",), "verdict-class": ("role",), "class": ("role",), "category": ("role",),
    "behavior-class": ("role",), "role-class": ("role",),
    "stages": ("steps", "stage-count"), "stage-list": ("steps",), "step-list": ("steps",), "ordered-steps": ("steps",),
    "behavior-graph": ("steps",), "behavior-steps": ("steps",),
    "stage-total": ("stage-count",), "stages-count": ("stage-count",), "number-of-stages": ("stage-count",),
    # Day 18 look-ahead (B10): four renamed field words that left 52 ids None each on the staged Day 17 base
    "encoding-profile": ("obfuscation",), "url-indicator": ("url",), "next-stage-language": ("next-language",),
    "language-adapter": ("adapter",),
}
ALIAS_WITH_VERDICT = ("classification", "verdict-class", "class", "category")   # the plan's `verdict=` is a reading too
EXTRA_FIELDS = ("attack", "role", "steps", "url", "file-path")
KNOWN_TAILS = ("upload-url", "file-path")          # judged fields that end in a word of EXTRA_FIELDS
GRAPH_WORDS = ("graph", "derived", "steps", "behavior", "behaviour", "observed", "computed")
STATED_WORDS = ("stated", "declared", "plan", "descriptor", "claimed", "labelled", "labeled")


def renamed(q: dict, plan=None):
    """(field, kind, asked word, extra word) for a question whose id's field word is an alias of a field
    (kind `alias`) or a field with one more word in front (kind `new`); None for every other question.
    `plan`, when given, is the specimen's plan: a word that names one of its keys is that key."""
    tail = tail_of(q)
    key = tail.replace("-", "_")
    if isinstance(plan, dict) and key in plan:
        return None
    word = tail if tail in ALIASES else None
    if word is None and not compared(q):
        word = next((a for a in sorted(ALIASES, key=len, reverse=True) if tail.endswith("-" + a)), None)
    if word is not None:
        fields = ALIASES[word]
        field = fields[0]
        fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
        if len(fields) > 1 and (answer_kind(q) == "integer" or re.search(r"\binteger\b", str(fmt.get("syntax") or ""))):
            field = fields[1]
        return field, "alias", word, ""
    if not compared(q) or tail in KNOWN_TAILS:
        return None
    for field in EXTRA_FIELDS:
        if tail.endswith("-" + field):
            return field, "new", tail, tail[:-len(field) - 1]
    return None


def _options(q: dict, name: str, value) -> list:
    """[(name, value)] of one reading as the question can take it: checked against the question's own list
    and put in its answer format; the options of an unsure reading under their own names; [] for none."""
    try:
        value = formatted(q, listed(q, value)) if isinstance(value, str) else None
    except Exception:  # noqa: BLE001 - a reading that cannot be formed is no option
        value = None
    if not isinstance(value, str) or not value:
        return []
    if not value.startswith("??"):
        return [(name, value)]
    parsed = labels.parse(value) if labels is not None else None
    return [(str(n), v) for n, v in parsed.options] if parsed is not None and parsed.key else []


def reworded(q: dict, how: tuple, base, ext: str, plan=None):
    """The unsure answer of a question renamed() names, from `base`, the answer of the field it stands for
    (plain, unsure or None), and for a new attack or role field the plan's own readings. Never plain."""
    field, kind, asked, word = how
    slug = lambda t: re.sub(r"[^a-z0-9_]", "_", str(t).lower()).strip("_") or "field"      # noqa: E731
    own = _options(q, "as_" + slug(field), base)
    plan = plan if isinstance(plan, dict) else {}
    if kind == "alias":
        if asked in ALIAS_WITH_VERDICT and isinstance(plan.get("verdict"), str):
            own += _options(q, "as_verdict", plan["verdict"])
    elif field in ("attack", "role"):
        steps = steps_of(plan)
        said = plan.get(field) if isinstance(plan.get(field), str) else None
        if field == "role":
            seen = ROLE.get(steps)
        else:
            seen, _why = graph_attack(steps)
            if seen == OWN:
                seen = (techniques(ext) or [None])[0]
            if said is not None and said != "none" and not ATTACK_ID.fullmatch(said):
                said = None
        graph, stated_ = _options(q, "graph", seen), _options(q, "stated", said)
        words = set(re.split(r"[^a-z0-9]+", word.lower()))
        if words & set(GRAPH_WORDS):
            own = graph + stated_ + own
        elif words & set(STATED_WORDS):
            own = stated_ + graph + own
        else:
            own = own + stated_ + graph
    seen_values, options = set(), []
    for name, value in own:
        if value in seen_values or any(name == n for n, _ in options):
            continue
        seen_values.add(value)
        options.append((name, value))
    if not options:
        return None
    return pick(f"script.{slug(asked)}/{ext or 'ext'}.{'alias' if kind == 'alias' else 'new'}_{slug(field)}",
                options[:MAX_OPTIONS])


def answer_kind(q: dict) -> str:
    fmt = q.get("answer_format")
    return str(fmt.get("kind") or "") if isinstance(fmt, dict) else ""


def is_control(q: dict) -> bool:
    said = id_asks(q, "control")
    return said if said is not None else bool(re.search(r"control[- ]flow", q.get("question") or "", re.I))


def asks_role(q: dict) -> bool:
    said = id_asks(q, "role")
    return said if said is not None else bool(re.search(r"\bClassify\b", q.get("question") or ""))


def asks_attack(q: dict) -> bool:
    said = id_asks(q, "attack")
    if said is not None:
        return said
    return answer_kind(q) == "mitre_attack_id" or "ATT&CK" in (q.get("question") or "")


def permits_none(q: dict) -> bool:
    """Whether the literal `none` is an answer the question can take: its accepted values list it, its
    answer format's syntax offers it (Day 12: `.. or none for the benign graph`), or its text says `or none`
    (Days 2 to 11, whose one syntax for every technique question says only `use the literal none only when
    the question permits it`: that sentence permits nothing)."""
    allowed = accepted_values(q)
    if allowed is not None:
        return "none" in allowed
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    syntax = re.sub(r"use the literal none only when the question permits it", "", str(fmt.get("syntax") or ""), flags=re.I)
    return bool(re.search(r"\bnone\b", syntax, re.I) or re.search(r"\bor none\b", q.get("question") or "", re.I))


def near_key(tail: str, key: str) -> bool:
    """Whether plan key `key` is the one an id's field word `tail` can mean (`host` for host_id, `url`)."""
    want = str(tail or "").replace("-", "_").lower()
    key = str(key or "").lower()
    return bool(want) and (key == want or key.startswith(want + "_") or key.endswith("_" + want))


def text_key(q: dict, plan: dict):
    """The plan key a question's text names ("exact <key> indicator"), where the text may speak: the id
    leaves the field open, or the named key is one the id's own field word can mean. Else None."""
    named = re.search(r"exact (\w+) indicator", q.get("question") or "")
    if not named or named.group(1) not in plan:
        return None
    return named.group(1) if not names_field(q) or near_key(tail_of(q), named.group(1)) else None


def scalar(v):
    """A plan value as an answer: text as it is, a whole number as its digits, nothing else."""
    if isinstance(v, str):
        return v or None
    if isinstance(v, int) and not isinstance(v, bool):
        return str(v)
    return None


def accepted_values(q: dict):
    """The values a question's own answer format lists (an enum), or None when it lists none."""
    fmt = q.get("answer_format")
    values = fmt.get("accepted_values") if isinstance(fmt, dict) else None
    if isinstance(values, (list, tuple)) and values and all(isinstance(v, str) for v in values):
        return list(values)
    return None


def respelled(allowed: list, value: str):
    """(key, listed value) when the question's own list holds `value` only in another spelling: exactly one
    listed value equal to it with letter case left out (`script.enum_form/case`), else exactly one equal to
    it with `-`, `_`, blanks and case left out (`script.enum_form/separator`); None otherwise. The keys are
    answer_forms.py's, so one base probe settles a module's answer and a plan's alike (B8, below)."""
    if not isinstance(value, str) or not value.strip() or not allowed:
        return None
    low = value.strip().lower()
    same = [a for a in allowed if isinstance(a, str) and a.strip().lower() == low]
    if len(same) == 1:
        return "script.enum_form/case", same[0]
    if same:
        return None
    squash = lambda t: re.sub(r"[-_\s]+", "", str(t).lower())      # noqa: E731
    same = [a for a in allowed if isinstance(a, str) and squash(a) == squash(value)]
    return ("script.enum_form/separator", same[0]) if len(same) == 1 else None


def listed(q: dict, value):
    """`value` as far as the question's own enum allows it.

    A question that lists its accepted values has said what a right answer looks like. A plain
    answer outside the list is known to be wrong before it is sent, and one wrong answer costs
    the whole batch, so it becomes None. An unsure answer keeps the options the list holds
    (None when none is left). A question without a list, and a value that is not text, pass
    through unchanged.

    Day 18 look-ahead (B8, 2026-10-17): a plain answer the list holds only in another spelling (the list
    hyphenated, or in Title Case: `Benign Utility` for benign_utility) is not dropped but offered unsure in
    the LISTED spelling under respelled()'s key, one option. Before, 51 (hyphens) or 96 (Title Case) role ids
    of the staged Day 17 base were None (the plan's stated roles and the general path's), while the modules'
    roles went unsure through answer_forms.py: one probe now settles all of them. Never plain unless the
    judge has accepted that key's name."""
    allowed = accepted_values(q)
    if allowed is None or not isinstance(value, str):
        return value
    if not value.startswith("??"):
        if value in allowed:
            return value
        spelled = respelled(allowed, value)
        return pick(spelled[0], [("listed", spelled[1])]) if spelled else None
    parsed = labels.parse(value) if labels is not None else None
    if parsed is None or not parsed.key:
        return None
    keep = [(n, v) for n, v in parsed.options if v in allowed]
    if len(keep) == len(parsed.options):
        return value
    return labels.unsure(parsed.key, keep) if keep else None


# The separator an answer format's syntax states: `joined by >`, also `separated with >`, `delimited by ->`
# (Day 13 preparation, review of 2026-10-12: only the exact words "joined by" were read, and a syntax that
# says the same another way gave 48 step lists None, or sent them plain and comma-joined under a kind that is
# no token list). What follows the words must be a separator: one to three characters that are no word
# ("separated with the greater-than sign" states none that can be read).
JOINED_BY = re.compile(r"(?:joined|separated|delimited)\s+(?:by|with)\s+(\S+?)(?=\s|$)")
# Day 18 look-ahead (B9): a separator written in quotes, with the spaces it holds: `joined by " > "`. Before, the
# opening quote was read as the separator and the probe could not succeed (82 step lists unsure without the truth).
JOINED_BY_QUOTED = re.compile(r"(?:joined|separated|delimited)\s+(?:by|with)\s+([\"'`])([^\w\"'`\r\n]{1,7})\1")
SEPARATOR = re.compile(r"[^\w\s]{1,3}")
TIGHT = re.compile(r"\bno (?:surrounding )?spaces\b")
KNOWN_KINDS = {"exact_text", "enum", "mitre_attack_id", "integer", "ordered_tokens", "json", "pattern"}
STEP_LIST = re.compile(r"[a-z][a-z0-9_]*(?:(?:,|>|->)[a-z][a-z0-9_]*)+")
# ONE key for the whole lane (not one an extension): the question is the format's, the same sentence on every
# specimen of a delivery, and the options are named by method, so one accepted probe on the base answers
# every step list of every extension (nine extensions carry one on Day 12: nine probes otherwise).
STEPS_KEY = "script.steps/any.separator"


def stated_separator(q: dict):
    """The separator the question's answer format states for joined tokens, or None."""
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    syntax = str(fmt.get("syntax") or "")
    quoted = JOINED_BY_QUOTED.search(syntax) if '"' in syntax or "'" in syntax or "`" in syntax else None
    if quoted and SEPARATOR.fullmatch(quoted.group(2).strip()):
        return quoted.group(2)               # B9: as quoted, its own spaces included
    j = JOINED_BY.search(syntax)
    return j.group(1) if j and SEPARATOR.fullmatch(j.group(1)) else None


def step_list(q: dict, value: str, toks: list):
    """A step list on an id whose field is `steps`, in the form the answer format states.

    Plain in ONE form only, the one every judged step list of the lane has: the syntax states `>` and that
    no spaces surround it. Anything else is not judged and goes out unsure under STEPS_KEY: another
    separator (the stated form first, then `>`), `>` with nothing said about spaces, and no separator at
    all (`>`, ` > `, then the plan's own text), whatever the format's kind is."""
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    sep, tight = stated_separator(q), bool(TIGHT.search(str(fmt.get("syntax") or "")))
    if sep == ">" and tight:
        return ">".join(toks)
    gt, spaced = ("gt", ">".join(toks)), ("gt_spaced", " > ".join(toks))
    if sep == ">":
        options = [gt, spaced]
    elif sep:
        own_spaces = sep != sep.strip()          # B9: a quoted separator that carries its spaces is used as written
        options = [("stated", sep.join(toks))] + ([] if tight or own_spaces else [("stated_spaced", f" {sep} ".join(toks))]) + [gt]
    else:
        options = [gt, spaced, ("as_read", value)]
    return pick(STEPS_KEY, options)


def formatted(q: dict, value):
    """`value` in the form the question's own answer_format states, or None.

    A plan value is the author's raw text; the answer format may ask for another spelling of the
    same fact. A step list on a `steps` id goes through step_list (plain only as `a>b` where the
    syntax says so). Any other token list (`a,b,c`) asked for as tokens `joined by X` is re-joined
    with X: plain when the syntax also says `no surrounding spaces`, else unsure between X and ' X '. An
    integer must be digits. A kind no day has used makes a plain answer unsure (one probe on the
    base) instead of a confident one that can sink the first batch."""
    if not isinstance(value, str) or value.startswith("??"):
        return value
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    kind, syntax = str(fmt.get("kind") or ""), str(fmt.get("syntax") or "")
    sep = stated_separator(q)
    toks = [t.strip() for t in re.split(r"\s*(?:,|>|->|\||;)\s*", value) if t.strip()]
    if tail_of(q) == "steps" and STEP_LIST.fullmatch(value) and not (kind == "json" and "array" in syntax.lower()):
        value = step_list(q, value, toks)
        if not isinstance(value, str) or value.startswith("??"):
            return value
    elif kind == "ordered_tokens" or sep:
        if not sep or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", t) for t in toks):
            return None
        if "no surrounding spaces" in syntax:
            return sep.join(toks)
        if sep != sep.strip():                   # B9: a quoted separator with its own spaces, as written
            return pick(f"script.format/{kind or 'joined'}.{re.sub(r'[^a-z0-9_]', '_', sep.strip())}.quoted",
                        [("as_quoted", sep.join(toks))])
        return pick(f"script.format/{kind or 'joined'}.{re.sub(r'[^a-z0-9_]', '_', sep)}",
                    [("tight", sep.join(toks)), ("spaced", f" {sep} ".join(toks))])
    elif kind == "json" and "array" in syntax.lower() and re.fullmatch(r"[a-z0-9_]+(?:,[a-z0-9_]+)+", value):
        import json as _json
        return pick("script.format/json.tokens", [("array", _json.dumps(value.split(","), separators=(",", ":")))])
    if kind == "integer":
        return value if re.fullmatch(r"\d+", value) else None
    if kind and kind not in KNOWN_KINDS:
        return pick(f"script.format/{re.sub(r'[^a-z0-9_]', '_', kind.lower())}", [("raw", value)])
    return value


def steps_of(plan: dict) -> tuple:
    steps = plan.get("steps")
    return tuple(s.strip() for s in steps.split(",") if s.strip()) if isinstance(steps, str) else ()


# Round 2 of the Day 9 preparation (2026-10-08): a stated role or attack in an extension outside STATED_JUDGED
# cost two base probes (one key per field, `script.<field>/<ext>.stated_v3`). It is plain without them where
# the text proves it, and only for a version-3 plan:
#
#   the language  the plan's own `language=` is one whose stated values the judge accepted on Day 8 (all 84
#                 descriptors: php, javascript, jscript, vbscript) AND the file is one that language is
#                 written in (STATED_HOSTS: a .phtml for php, a .hta, .wsf or .mjs for the script languages).
#                 The same descriptor in such a file states its role as those 84 did. A plan that says php in
#                 a .rb file is not this: its language and its file disagree, and nothing is proven;
#   the name      (STATED_BY_NAME) the specimen is NAMED for the stated role: the role's words stand, in
#                 order, in the member's file name or in the answer id (`polyglot-ruby-persistence-descriptor`
#                 for `persistence_descriptor`), as on the eight `polyglot-php-<role>` specimens of Day 8.
#                 Its attack is plain only when it is also the technique the judge accepted beside that
#                 very role in a Day 8 descriptor (STATED_ATTACK: every one of the 84 is in it).
#
# A name alone proves nothing (`jscript-relay` is a staged_chain, Days 2 to 8, where no plan states a role):
# it counts only as the second witness of what the plan states. Anything else is unsure as before.
STATED_LANGUAGES = {("php", "3"), ("javascript", "3"), ("jscript", "3"), ("vbscript", "3")}
_WSH_HOSTS = ("hta", "htm", "html", "xhtml", "wsf", "wsh", "sct", "wsc", "asp", "svg", "xsl", "xslt")
STATED_HOSTS = {"php": ("php", "phtml", "php3", "php4", "php5", "php7", "php8", "phps", "pht", "phar", "inc"),
                "javascript": ("js", "mjs", "cjs", "jse", "jsx") + _WSH_HOSTS,
                "jscript": ("js", "jse") + _WSH_HOSTS,
                "vbscript": ("vbs", "vbe") + _WSH_HOSTS}
STATED_ATTACK = {"benign_utility": "none", "downloader": "T1105", "dropper": "T1140", "launcher": "T1059",
                 "persistence_descriptor": "T1053", "staged_chain": "T1059", "stager": "T1105", "uploader": "T1041"}
STATED_BY_NAME = True        # read at call time


def named_for(q: dict, role: str) -> bool:
    """Whether the words of `role` stand, in order and side by side, in the member's file name or in the answer id."""
    want = [w for w in str(role).lower().split("_") if w]
    if not want:
        return False
    stem = str(q.get("member") or "").rsplit("/", 1)[-1]
    stem = stem.rsplit(".", 1)[0] if "." in stem else stem
    for text in (stem, bare_id(q)):
        words = [w for w in re.split(r"[^a-z0-9]+", str(text).lower()) if w]
        if any(words[i:i + len(want)] == want for i in range(len(words) - len(want) + 1)):
            return True
    return False


def stated_proven(q: dict, plan: dict, field: str, ext: str = "") -> bool:
    """Whether a plan's own role or attack is proven by the text (see above). `ext` is the file's extension."""
    if str(plan.get("v") or "") != "3":
        return False
    language = str(plan.get("language") or "").strip().lower()
    if (language, "3") in STATED_LANGUAGES and str(ext or "").lower().lstrip(".") in STATED_HOSTS.get(language, ()):
        return True
    role = plan.get("role")
    if not STATED_BY_NAME or not isinstance(role, str) or not named_for(q, role):
        return False
    return field == "role" or STATED_ATTACK.get(role) == plan.get("attack")


def stated(q: dict, plan: dict, field: str, derived, ext=""):
    """The answer of a plan that states its own role or attack (row 101), or None.

    `derived` is what the steps table gives (a plain name or None). The stated value must be one the
    question can take: a role its own list holds (any name when it lists none), a technique id, or
    `none` where the question permits it. It is plain when the judge has accepted the statement for
    this extension and plan version (STATED_JUDGED) or when the table gives the very same value; else
    unsure with the stated value first and the table's plain name behind it. The table's differing
    name is never the plain answer."""
    value = plan.get(field)
    if not isinstance(value, str) or not value:
        return None
    spelled = None
    if field == "role":
        allowed = accepted_values(q)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", value):
            return None
        if allowed is not None and value not in allowed:
            # B8: a list that holds the stated role only in another spelling (hyphens, Title Case)
            spelled = respelled(allowed, value)
            if spelled is None:
                return None
    elif value == "none":
        if not permits_none(q):
            # Nothing of the question says `none` may be sent (Days 8 to 11 said it in the text, Day 12 in
            # the answer format's syntax; a third wording may say it nowhere). A version-3 plan's own `none`
            # is the judged answer of every benign descriptor so far, so it is not dropped but held unsure,
            # one option, one probe: `script.attack/v3.stated_none`. Any other plan: None, as before.
            return pick("script.attack/v3.stated_none", [("stated", "none")]) if str(plan.get("v") or "") == "3" else None
    elif not ATTACK_ID.fullmatch(value):
        return None
    name, version = plan_codec.ext_name(ext) or "plan", str(plan.get("v") or "")
    if (name, version) in STATED_JUDGED or derived == value or stated_proven(q, plan, field, ext):
        # B8: the statement is established; its spelling in the question's list is one probe (respelled)
        return value if spelled is None else pick(spelled[0], [("listed", spelled[1])])
    if spelled is not None:
        return None          # the statement is not established AND its spelling is not: two doubts, as before B8
    options = [("stated", value)]
    if isinstance(derived, str) and derived and not derived.startswith("??"):
        options.append(("steps_table", derived))
    got = pick(f"script.{field}/{name}.stated_v{re.sub(r'[^0-9a-z]', '', version) or '0'}", options)
    if field == "attack" and version == "3" and not (isinstance(got, str) and not got.startswith("??")) \
            and role_stated_holds(q, plan, ext):
        ruled = stated_v3(plan, value)           # this extension's own key is not judged: Day 12's keys may be
        if ruled is not None:
            return ruled
    return got


def role_stated_holds(q: dict, plan: dict, ext: str) -> bool:
    """Whether this plan's own `role=` is established for this specimen: proven by the text (stated_proven:
    the language and its host file, or the specimen named for the role) or judged for the extension
    (`script.role/<ext>.stated_v3` holds an accepted name, not split). Only then do Day 12's verdicts on a
    stated attack (stated_v3) speak for it: they were given on specimens whose stated role was the judged
    one. A plan whose role nothing vouches for keeps its attack unsure under the extension's own key, as
    before Day 12 (tests/next_components.py, d_stated)."""
    if not isinstance(plan.get("role"), str) or not plan.get("role"):
        return False
    if stated_proven(q, plan, "role", ext):
        return True
    if labels is None:
        return False
    try:
        st = labels.state(f"script.role/{plan_codec.ext_name(ext) or 'plan'}.stated_v3")
    except Exception:  # noqa: BLE001 - a ledger that cannot be read vouches for nothing
        return False
    return bool(st.get("accepted")) and not st.get("split")


# The rubric the judge wrote into every `-attack` question on Day 12 (2026-10-12), as a reading of the
# plan's ordered steps: "a terminal handoff_script or dispatch_next_stage makes the staged chain or relay
# the specimen's language-specific Command and Scripting Interpreter sub-technique ..; otherwise
# decode_configuration followed by return_configuration is benign/none, acquire_remote is ingress transfer,
# decode_embedded is deobfuscation/decoding, upload_remote or transmit_remote is exfiltration ..,
# dispatch_process is the language-specific .. sub-technique, build_schedule followed by
# register_descriptor is scheduled-task persistence, and transform_content or transform_copy followed by
# write_recovery_note is encrypted-file impact." It is NOT what decides a plain answer here: the judged
# tables and ledger keys above do, and for a version-3 descriptor the judge kept the plan's own `attack=`
# under this very text (`graph` rejected, `stated` accepted on polyglot-php-uploader-attack). The rubric
# only chooses among the keys Day 12's verdicts were recorded under (stated_v3) and names the one step
# list whose technique was judged for every extension at once (GRAPH_SCHEDULE).
OWN = "own"          # graph_attack's word for "the specimen's own interpreter"
GRAPH_SCHEDULE = ("build_schedule", "register_descriptor")
GRAPH_SCHEDULE_KEY = "script.attack/graph.build_schedule+register_descriptor"
GRAPH_SCHEDULE_OPTIONS = [("prior_cron", "T1053.003"), ("scheduled_task", "T1053.005"), ("parent", "T1053")]
# Where that verdict was given (Day 13 preparation, 2026-10-12): on ONE id, nodejs-persistence-attack, a .mjs
# specimen whose own key (script.attack/mjs.build_schedule+register_descriptor) had held T1053.003 since Day 7.
# So the shared key says nothing new about .mjs, and for another extension it is one language's verdict:
# plain only in the family it was judged in, an unsure answer under the extension's own key elsewhere, with
# the judged technique first.
GRAPH_SCHEDULE_JUDGED = ("mjs", "cjs")


def graph_attack(steps) -> tuple:
    """(value, why) of an ordered step list by Day 12's rubric. value is a technique, `none`, OWN, or None
    where the rubric names no rule (why 'norule'), there are no steps ('noplan'), or it names a family and
    not an id ('schedule')."""
    s = tuple(steps)
    if not s:
        return None, "noplan"
    if s[-1] in ("handoff_script", "dispatch_next_stage"):
        return OWN, "own"
    if s == ("decode_configuration", "return_configuration"):
        return "none", "benign"
    if s[-1] == "dispatch_process" and s[0] in ("profile_host", "acquire_remote") and "write_file" in s:
        return OWN, "own"                        # the multi-stage chain: its interpreter (judged for .py, .sh, .mjs)
    if "acquire_remote" in s:
        return "T1105", "ingress"
    if "decode_embedded" in s:
        return "T1140", "decode"
    if "upload_remote" in s or "transmit_remote" in s:
        return "T1041", "exfil"
    if "dispatch_process" in s:
        return OWN, "own"
    if s == GRAPH_SCHEDULE:
        return None, "schedule"
    if s[-1] == "write_recovery_note" and ("transform_content" in s or "transform_copy" in s):
        return "T1486", "impact"
    return None, "norule"


def stated_v3(plan: dict, value: str):
    """The stated `attack=` of a version-3 descriptor plan where Day 12's verdicts make it plain, else None.

    The keys are the ones the day's live fix probed, for every extension at once (the plan and its
    generator are the same in each): `script.attack/v3.agree` (the rubric's reading of the steps gives the
    stated value: `graph_and_stated` accepted), `script.attack/v3.differ` (it gives another: `graph`
    rejected, `stated` accepted), and `script.attack/v3.<step+step>` where the rubric gives the own
    interpreter or nothing (`stated` accepted for profile_host+decode_configuration+dispatch_language).
    Only a plain result is returned: an unjudged key leaves the answer to the extension's own
    `script.attack/<ext>.stated_v3`, unsure, as before Day 12."""
    steps = steps_of(plan)
    if labels is None or not steps or not all(re.fullmatch(r"[a-z0-9_]+", s) for s in steps):
        return None
    ruled, why = graph_attack(steps)
    if ruled is None or ruled == OWN:
        got = pick(f"script.attack/v3.{'+'.join(steps)}",
                   [("stated", value), ("none", "none"), ("parent", "T1059"), ("ingress", "T1105")])
    elif ruled == value:
        got = pick("script.attack/v3.agree", [("graph_and_stated", value)])
    else:
        got = pick("script.attack/v3.differ", [("graph", ruled), ("stated", value)])
    return got if isinstance(got, str) and got and not got.startswith("??") else None


def plan_answer(q: dict, plan: dict, technique=None, notes=None, cut=False, ext=""):
    """What the plan alone says about a question, or None.

    `technique` answers the attack question of a launcher or a staged chain: a value, or a
    callable that returns one (called only when needed). `notes` collects one line per
    question the plan could have answered two ways. `cut` says the plan came without its
    last field (plan_codec.reading): a key that is only near the asked one may then stand
    where the missing one would have made two, so it answers nothing."""
    text, tail = q.get("question") or "", tail_of(q)
    role = ROLE.get(steps_of(plan))
    if asks_role(q):
        if plan.get("role"):
            return stated(q, plan, "role", role, ext)
        return listed(q, role) if role else None
    if asks_attack(q):
        if plan.get("attack"):
            return stated(q, plan, "attack", None if role in OWN_INTERPRETER else ATTACK.get(role), ext)
        if role in OWN_INTERPRETER:
            return technique() if callable(technique) else technique
        return ATTACK.get(role)
    if tail == "adapter":
        return scalar(plan.get("adapter"))
    if tail == "campaign":
        return scalar(plan.get("campaign_id"))
    # The id's own field word first (Day 12): a text that names another key never moves a question that
    # the id answers. "exact <key> indicator" speaks only for a key the id's word can mean, or for an id
    # that names no field (text_key).
    key = tail.replace("-", "_")
    if key in plan and names_field(q):
        return scalar(plan[key])
    named = text_key(q, plan)
    if named:
        return scalar(plan[named])
    if key in plan:
        return scalar(plan[key])
    # The fields Day 8 asked under another word than the plan's key (`obfuscation` for obfuscation_profile):
    # judged, so they need no neighbour search, and a plan read without its last field answers them too.
    if DESCRIPTOR_FIELDS.get(tail) in plan:
        return scalar(plan[DESCRIPTOR_FIELDS[tail]])
    # `host` asks for host_id and `note` for note_name. Two keys that fit are two facts, so
    # neither is taken.
    # Row 273 (b), 2026-10-12: not on a version-3 descriptor plan. Its fifteen keys are known, the twelve
    # fields asked of it are judged under their own words (DESCRIPTOR_FIELDS and the keys' own names, above),
    # and a word that is only a part of a key (`host` beside host_profile) is a field nobody has asked: None.
    near = [k for k in plan if k.startswith(key + "_") or k.endswith("_" + key)] \
        if key and not cut and str(plan.get("v") or "") != "3" else []
    if len(near) == 1:
        return scalar(plan[near[0]])
    if len(near) > 1 and notes is not None:
        notes.append(f"{q.get('qid')}: plan keys {', '.join(near)} all fit {tail!r}; not answered")
    return None


# ---------------------------------------------------------------- a step list outside the role table

def judged(field: str) -> list:
    """[(extension, steps, name)] for every key `script.<field>/<ext>.<step+step>` that holds an
    accepted name and is not split (seed and ledger), in the order the keys were written."""
    out, prefix = [], f"script.{field}/"
    try:
        table = labels._lane_state("script")     # labels has no public call that lists a lane's keys
    except Exception:  # noqa: BLE001 - no labels.py, or another one: nothing is judged
        return out
    for key, st in table.items():
        ext, dot, shape = key[len(prefix):].partition(".") if key.startswith(prefix) else ("", "", "")
        if dot and shape and st.get("accepted") and not st.get("split") and ext not in ("v3", "graph"):
            out.append((ext, tuple(shape.split("+")), st["accepted"]))      # v3., graph.: Day 12's method keys
    return out


def step_words(steps) -> set:
    return {w for s in steps for w in s.split("_") if w}


def role_candidates(q: dict, steps: tuple, role_q=None) -> list:
    """Role names for a step list the judge has named nowhere, best first, at most MAX_OPTIONS.

    The names are the ones the specimen's role question lists (`role_q`; `q` itself when it is
    that question). First a name that holds a specimen word of the id (`relay` for
    `python-zipapp-relay-role`), then the roles whose judged step lists share two or more step
    words with this one, then the names no judged step list has taken, then the rest."""
    asked = role_q or q
    names = accepted_values(asked) or labels.enum_from_question(asked.get("question") or "") or sorted(set(ROLE.values()))
    words = set(bare_id(q).split("-")[1:])       # the first word is the language
    mine, shared = step_words(steps), {}
    for graph, role in list(ROLE.items()) + [(g, name) for _, g, name in judged("role")]:
        shared[role] = max(shared.get(role, 0), len(mine & step_words(graph)))

    def rank(i):
        name = names[i]
        tier = 0 if words & set(name.split("_")) else 1 if shared.get(name, 0) >= 2 else 2 if name not in shared else 3
        return tier, -shared.get(name, 0), i
    return [names[i] for i in sorted(range(len(names)), key=rank)][:MAX_OPTIONS]


def unseen(q: dict, ext: str, steps: tuple, role_q=None):
    """The role or the technique of a step list that is not in the role table: labels.pick under
    this extension's own key, `script.role/<ext>.<step+step>` or `script.attack/...`. So it is
    unsure until the judge has accepted a name there, and that name, plain, from then on. None
    when nothing is offered.

    Offered first: what the judge has accepted for the same steps under any extension's key.
    A T1059 technique judged for another extension is that extension's interpreter, so this
    extension's own candidates stand in for it. Then, only with OFFER_UNSEEN_ROLES, the names
    of role_candidates, and for the technique those roles' techniques in the same order (the
    own interpreter for a role outside ATTACK). `none` is offered where the question permits it."""
    if labels is None or not all(re.fullmatch(r"[a-z0-9_]+", s) for s in steps):
        return None
    shape = "+".join(steps)

    def accepted(field):
        rows = [(e, name) for e, g, name in judged(field) if g == steps]
        return [name for e, name in rows if e == ext] + [name for e, name in rows if e != ext]

    roles = accepted("role") + (role_candidates(q, steps, role_q) if OFFER_UNSEEN_ROLES else [])
    if asks_role(q):
        return pick(f"script.role/{ext}.{shape}", list(dict.fromkeys(roles))[:MAX_OPTIONS])
    own = techniques(ext)
    if steps == GRAPH_SCHEDULE and ext in GRAPH_SCHEDULE_JUDGED \
            and not any(e == ext and g == steps for e, g, _ in judged("attack")):
        # Day 12: the one step list whose technique was judged under a key of no extension (`prior_cron`,
        # T1053.003, on nodejs-persistence-attack). This extension's own key, once judged, comes first; and
        # only a plain result is taken from the shared key, so an unsure answer stays under the extension's.
        ruled = pick(GRAPH_SCHEDULE_KEY, GRAPH_SCHEDULE_OPTIONS)
        if isinstance(ruled, str) and ruled and not ruled.startswith("??"):
            return ruled
    found = [own[0] if e != ext and name.startswith("T1059") else name for e, g, name in judged("attack") if g == steps]
    if OFFER_UNSEEN_ROLES:                       # what the steps themselves name: candidates too, so under the same switch
        found += [t for word, ts in STEP_TECH if word in "_".join(steps) for t in ts]
    found += [ATTACK.get(role, own[0]) for role in roles]
    if OFFER_UNSEEN_ROLES:                       # row 50: after the role techniques, which led on Day 5 (14 of 14)
        found += [t for word, ts in STEP_WORDS if word in "_".join(steps) for t in ts]
    if any(t == own[0] for t in found):
        found += own[1:]                         # the other interpreters, behind every role's technique
    if not permits_none(q):
        found = [t for t in found if t != "none"]
    found = list(dict.fromkeys(found))
    if own[0] in found and found.index(own[0]) >= MAX_OPTIONS:
        found.remove(own[0])                     # the own interpreter is never cut off by the cap
        found.insert(MAX_OPTIONS - 1, own[0])
    return pick(f"script.attack/{ext}.{shape}", found[:MAX_OPTIONS])


# ---------------------------------------------------------------- names for an unlabelled decode

def representation_names(how: str) -> list:
    """What the known label tables call material that decodes as `how` (plan_codec's word)."""
    base, sep, d = (how or "").rpartition("_")
    delim = plan_codec.DELIMITER_NAMES.get(d) if sep else None
    if how == "base64":
        return ["base64_literal", "base64_chunks", "plain_fragments", "split_fragments"]
    if how == "base64_reversed_text":
        return ["reversed_text"]
    if how == "hex_compact":
        return ["hex_compact", "hex_pairs", "reversed_hex"]
    if how == "plain_fragments":
        return ["plain_fragments", "split_fragments"]
    if how == "hex_array":
        return ["hex_array"]
    if delim and base == "hex":
        return [f"hex_{delim}", "reversed_hex"]
    if delim and base == "decimal":
        return [f"decimal_{delim}", "reversed_decimal", "decimal_bytes"]
    return []


def transform_names(transform: str) -> list:
    """What the known label tables call a transform plan_codec undid as `transform`.

    The same bytes can be labelled two ways (a reversed representation with no transform, or
    a plain one with reverse_bytes), which is why these are candidates and not answers."""
    order, _, tr = (transform or "").rpartition("+")
    rev = bool(order)
    if tr == "identity":
        return ["reverse_bytes", "reverse", "identity"] if rev else ["identity", "reverse_bytes"]
    m = re.fullmatch(r"xor_([0-9a-f]{2})", tr)
    if m:
        return ["reverse_then_xor", "reverse_xor", "single_byte_xor"] if rev else ["single_byte_xor", f"xor_{m.group(1)}"]
    m = re.fullmatch(r"add_(\d+)", tr)
    if m:
        k = int(m.group(1))   # the amount added to read the bytes back
        return ["subtract_modulo_256", "add_modulo_256"] if k < 128 else ["add_modulo_256", f"add_{256 - k}",
                                                                           "subtract_modulo_256"]
    if tr.startswith("repeating_xor_"):
        return ["repeating_key_xor"]
    if tr.startswith("rolling_xor_"):
        return ["rolling_xor"]
    if tr == "bit_ror1":
        return ["rotate_left"]
    return []


# Day 12 look-ahead (S3). The advanced Bash specimens carry a codec constant that names a representation and no
# transform: `Codec_<id>='decimal_csv|'` (a later one may add a key, `'xor_hex|78'`). plan_codec.LABEL_RE wants
# both words, so label_of reads no label there, and a representation question (no day has asked one of them) got
# the decode's names only, the author's own word not among them. The word is in the bytes; that it is the answer
# is not judged, so it is offered first and unsure.
CODEC_CONSTANT = re.compile(r"(?i)\bCodec_\w+\s*(?::=|<-|=)\s*[\"']([^\"'\r\n]*)[\"']")
BARE_LABEL = re.compile(r"([a-z][a-z0-9_]*)\|[0-9A-Za-z_]*")


def bare_label(text: str):
    """The representation word of the file's ONE `Codec_<id>` constant when it reads `<rep>|` or `<rep>|<key>`
    and is no `rep|transform` label (plan_codec's own); None with no such constant or with two that differ."""
    found = {m.group(1).strip() for m in CODEC_CONSTANT.finditer(text)} if "odec_" in text else set()
    if len(found) != 1:
        return None
    label = next(iter(found))
    m = BARE_LABEL.fullmatch(label)
    return m.group(1) if m and not plan_codec.LABEL_RE.fullmatch(label) else None


# ---------------------------------------------------------------- one file

def by_label(info: dict):
    """The plan read by the file's own codec label (label_plan.reading), put in `info` in place
    of a cut plan or of none, when it holds every field plan_codec did read with the same value.
    A label plan that differs from those fields is a second plan: the plan answers nothing. A
    label plan read from a piece of its material comes without its last field (cut), as
    plan_codec's own; then the longer of the two agreeing plans is kept, still cut."""
    lp = plan_codec.optional("label_plan")
    try:
        t, cut = lp.reading(info["text"], info.get("ext")) if lp is not None and hasattr(lp, "reading") else (None, False)
    except Exception as e:  # noqa: BLE001 - the second source's failure leaves the first one as it was
        info["notes"].append(f"label_plan raised {type(e).__name__}: {e}")
        return
    if not t:
        return
    plan, have = plan_codec.flatten(t), info["plan"]
    differ = [k for k in have if k in plan and str(plan[k]) != str(have[k])] + \
             ([k for k in have if k not in plan] if not cut else [])
    if differ:
        info.update(plan={}, plan_text=None, cut=False, ambiguous=True)
        info["notes"].append(f"the codec label's plan differs from plan_codec's on {ascii(str(differ[0]))[:60]}: "
                             f"neither is taken")
        return
    if cut and len(have) >= len(plan):
        return                                   # the label adds nothing to plan_codec's own cut plan
    if info.get("cut") and not cut and (plan_codec.head_of(t, plan_codec.longest(info["text"], info.get("ext")))
                                        or t in plan_codec.continued_plans(info["text"], info.get("ext"))):
        # Day 27 (script residuals): plan_codec read its plan from a piece and saw it go on past the label's
        # material: a longer plan that begins with the label's (a suffix variable `MATERIAL_x_SUFFIX` read as a run),
        # or a rest of that very literal where TAILS or the head rule reads one (another value of its dict, a related
        # name, a function's `return "<rest>"`: plan_codec.continued_plans). The labelled literal is only the head of
        # the plan, and its last value may be cut (`next_stage=st` went out PLAIN, and day23_fold's -indicator with
        # it). It adds nothing whole; plan_codec's cut plan stands. A piece for any other reason (a run of like
        # literals, code glued to it) is settled by the label as before: Day 6 to 9's shell words '..''..'.
        info["notes"].append("the codec label's material is only the head of the plan plan_codec read on from a piece "
                             "(a suffix variable, a dict entry, a rest joined on): the label adds nothing whole")
        return
    info.update(plan=plan, plan_text=t, cut=cut, source="codec label")
    info["notes"].append("plan read by the file's codec label (label_plan)"
                         + (", agreeing with every field plan_codec read" if have else "")
                         + (", from a piece of its material: its last field is left out" if cut else ""))


def by_descriptor(info: dict) -> bool:
    """The plan of the file's tagged descriptor (descriptor.reading_ex), put in `info`. True when the
    descriptor settled the plan one way or the other (the codec label is then not asked).

    A descriptor that is not ONE whole plan leaves no plan at all: what plan_codec read from the same
    file may be the cut copy (row 113). A whole one is taken when plan_codec read nothing, or when it
    holds every field plan_codec read with the same value (a cut reading has dropped its last field
    already); a plan_codec plan that differs is a second plan, and two plans answer nothing. When
    plan_codec itself found two plans, that stands.

    A whole comment beside a literal that is a join (open): the two copies agree only when plan_codec
    read the literal whole and to the very same plan. When it read a piece that agrees, or nothing, the
    comment's plan is taken without its last field, the one value a cut comment would hold cut. A whole
    plan_codec reading that is a shorter plan is a second copy that differs: nothing.

    A descriptor literal alone that this reader does not read (a join, a spelling of another language)
    leaves the plan to plan_codec and the codec label, as before; what they read must still have a
    stage_count equal to its steps, and answers() still wants every asked field (DESCRIPTOR_FIELDS)."""
    mod = plan_codec.optional("descriptor")
    try:
        got = mod.reading_ex(info["text"], info.get("ext")) if mod is not None and hasattr(mod, "reading_ex") else None
    except Exception as e:  # noqa: BLE001 - a reader that fails leaves the file as plan_codec read it
        info["notes"].append(f"descriptor raised {type(e).__name__}: {e}")
        return False
    if got is None:
        return False
    info["descriptor"] = True
    if info.get("ambiguous"):
        return True

    def nothing(note):
        info.update(plan={}, plan_text=None, how=None, transform=None, cut=False, ambiguous=True, source=None)
        info["notes"].append(note)
        return True

    t, have = got["plan"], info["plan"]
    if t is None and got["why"]:
        info["descriptor_why"] = got["why"]      # B-227: by_blind settles one of these (SPLIT_UNREAD)
        return nothing(f"the tagged descriptor is not one whole plan ({got['why']}): no plan is taken")
    if t is None:
        why = (mod.checked(have, True) if hasattr(mod, "lacking") else mod.checked(have)) if have else None
        if why:
            return nothing(f"the descriptor's plan is not whole ({why}): no plan is taken")
        if have and hasattr(mod, "lacking") and mod.lacking(have) and not short_format(info, have, mod):
            # plan_codec's reading of a descriptor literal this reader does not read, with fewer fields than
            # its version holds and no other descriptor of the delivery written so: a cut plan as far as
            # anyone can see. Its last value is the one a cut holds cut.
            if info.get("cut"):
                return True                      # plan_codec left the last field out already
            text_ = info.get("plan_text") or ""
            if "|" not in text_ or len(have) < 2:
                return nothing("the descriptor's plan has fewer fields than its version holds: no plan is taken")
            info.update(plan=dict(list(have.items())[:-1]), plan_text=text_[:text_.rfind("|") + 1], cut=True)
            info["notes"].append(SHORT_NOTE)
            return True
        return False
    plan = plan_codec.flatten(t)
    info["descriptor_keys"] = set(plan)
    short = bool(got.get("short")) and not short_format(info, plan, mod)
    differ = [k for k in have if k not in plan or str(plan[k]) != str(have[k])]
    if differ:
        return nothing(f"the tagged descriptor's plan differs from plan_codec's on {ascii(str(differ[0]))[:60]}: "
                       f"neither is taken")
    rep, _, tr = got["how"].partition("|")
    cut = False
    copies = got.get("copies") or ()
    # Two copies that agree, a comment and a whole literal, are the one thing that says a descriptor's last
    # value was not cut (review of 2026-10-08). ONE copy is whole only as far as this reader can see, so it
    # does not overrule a sign that it is a piece of a longer value:
    #   - in the strings of a binary carrier (analyze.strings_view) a line ends wherever a run of printable
    #     bytes does, and a quote may close a run that a NUL cut;
    #   - the comment's next line reads as more of its payload (descriptor: doubt, a wrapped comment);
    #   - plan_codec itself read this plan from a piece (a wrapped block, a literal that is joined, grown or
    #     used in a join elsewhere) and left its last field out;
    #   - the comment decoded only without what stands behind its payload on the line (descriptor: trimmed,
    #     Day 12 look-ahead): where the payload ends was this reader's choice.
    # Then the plan is taken without its last field, the one value a cut copy holds cut.
    two = "comment" in copies and "literal" in copies
    info["two_copies"] = two
    loose =bool(info.get("loose_lines")) and not two
    #   - (Day 27, fix round of the variants track) a comment SHOWN to go on in its next lines (descriptor:
    #     doubt_proven, its payload with them decodes to a longer plan) beside a literal that agrees with its
    #     first line: both copies are cut alike at the wrap, and their agreement proves nothing (such a pair went
    #     out PLAIN with the cut last value).
    doubt = bool(got.get("doubt")) and (not two or bool(got.get("doubt_proven")))
    piece = bool(have) and bool(info.get("cut")) and not two
    trim = bool(got.get("trimmed")) and not two
    #   - (Day 13 preparation) no tagged comment decoded, and the plan is the one whole literal's, which the
    #     comment only decorates (descriptor: fallback). The literal is one copy with no second witness; a
    #     sign that it is itself a piece (a carrier's strings, plan_codec reading a piece) leaves nothing.
    fb = bool(got.get("fallback"))
    #   - (row 354) the plan is a tagged SPLIT value's, and no bare value equal to its payload is there
    #     (descriptor: split_lone): one copy.
    lone = bool(got.get("split_lone")) and not two
    if fb and (loose or piece):
        return nothing("the tagged comment does not decode and its literal may be a piece of a longer value: "
                       "no plan is taken")
    if got["open"] or loose or doubt or piece or trim or fb or lone:
        if have and not info.get("cut"):
            if set(have) != set(plan):
                return nothing("the descriptor literal gives a shorter plan than its comment: neither is taken")
            if (loose or doubt or trim or fb or lone) and not got["open"]:
                cut = True                       # plan_codec's whole reading is of the same doubtful copy
        else:
            cut = True
        if cut:
            if not loose and ("comment" in copies or fb) and str(plan.get("v")) in getattr(mod, "PLAN_KEYS", ()) \
                    and not mod.lacking(plan):
                info["one_copy"] = list(plan.items())[-1]            # see one_copy()
                # Day 27 (review of the variants track): a comment whose next line reads as more of its payload
                # holds its last value cut, and a name the judge accepted for an unwrapped copy
                # (script.file_path/ahk.one_copy, /escript.one_copy) says nothing about it: its pick is asked under
                # a key of its own (one_copy_wrapped), never answered plain by the other's name. That is so when
                # the wrap is shown (descriptor: doubt_proven, the payload with its next lines decodes to a longer
                # plan) or when only the Day 27 reading sees it (an Erlang `%` wrap, read whole before). A doubt
                # the reading of before Day 27 had and nothing shows (AutoHotkey v1's `#NoEnv` behind a base64
                # comment, which is whole) keeps the key it had, and so does a plan read from the whole literal a
                # wrapped comment only decorates (fallback: decorated() joined every comment line to that literal
                # and saw the comment end there; the value is the literal's, which no wrap cuts).
                info["one_copy_wrapped"] = bool(doubt) and not fb and (bool(got.get("doubt_proven"))
                                                                       or not got.get("doubt_old", False))
            t = t[:t.rfind("|") + 1]
            plan = dict(list(plan.items())[:-1])
            info["notes"].append(("the tagged comment does not decode and only decorates the whole literal, "
                                  "which is read as one copy" if fb
                                  else "the tagged SPLIT value stands alone" if lone and not got["open"]
                                 else "the descriptor literal is a join that was not read whole" if got["open"]
                                  else "the descriptor stands as one copy in a binary carrier's strings" if loose
                                  else "the line after the tagged comment reads as more of its payload" if doubt
                                  else "plan_codec read this plan from a piece of its material" if piece
                                  else "the tagged comment was read without what stands behind its payload")
                                 + ": the descriptor's plan is taken without its last field"
                                 + (" (asked for, that one is unsure: one_copy)" if info.get("one_copy") else ""))
    if short and not cut:
        if "|" not in t or len(plan) < 2:
            return nothing("the descriptor's plan has fewer fields than its version holds: no plan is taken")
        cut, t, plan = True, t[:t.rfind("|") + 1], dict(list(plan.items())[:-1])
        info["notes"].append(SHORT_NOTE)
    if not have or info.get("cut"):
        info.update(how=rep, transform=tr or "identity")
    info.update(plan=plan, plan_text=t, cut=cut, source="descriptor")
    info["descriptor_sig"] = _descriptor_sig(got)
    return True


def by_blind(info: dict) -> bool:
    """B-227: the plan of the file's containers read whole by blind_reader.reading, put in `info` in place of a
    cut plan, a one-copy plan or none. True when it was taken.

    Asked only while the plan is open (none, cut, or one copy of a descriptor) and nothing refused the file,
    except for ONE refusal: a SPLIT file whose tagged copy descriptor.py could not read (SPLIT_UNREAD), which the
    reader settles only with a tagged copy and a second copy of the same plan. Its plan must hold every field
    already read, with the same value; one that differs is a second plan and nothing is taken (as by_label and
    descriptor_whole do)."""
    have = info.get("plan") or {}
    split_refused = bool(info.get("ambiguous")) and str(info.get("descriptor_why") or "").startswith(SPLIT_UNREAD)
    if info.get("ambiguous") and not split_refused:
        return False
    if have and not info.get("cut") and not info.get("one_copy"):
        return False
    # A missing in-tree module fails loudly (the specimen's read raises, naming it); only a module hidden on purpose
    # (the CTF_HIDE rehearsal knob, plan_codec.hidden) is a note.
    blind = plan_codec.optional("blind_reader")
    if blind is None or not hasattr(blind, "reading"):
        if "blind_reader" in plan_codec.hidden():
            info["notes"].append("blind_reader.py is hidden (CTF_HIDE): a plan cut or unread here is left as it is")
            return False
        raise RuntimeError("blind_reader.py (solvers/script-analysis) did not load: the language-blind container "
                           "reader is missing, so a cut or unread plan cannot be weighed")
    missing = getattr(blind, "MissingModule", None)
    try:
        v = blind.reading(info["text"], info.get("ext"))
    except Exception as e:  # noqa: BLE001 - a reader that fails leaves the file as the others read it
        if missing is not None and isinstance(e, missing):
            if getattr(e, "module", None) in plan_codec.hidden():
                info["notes"].append(f"blind_reader: {e} (hidden by CTF_HIDE)")
                return False
            raise
        info["notes"].append(f"blind_reader raised {type(e).__name__}: {e}")
        return False
    if not v.plan_text:
        if v.why and (have or split_refused):
            info["notes"].append(f"blind_reader: {v.why}")
        return False
    if split_refused and not (v.tagged and v.copies >= 2):
        info["notes"].append("blind_reader read the SPLIT file's plan from one copy only: no plan is taken")
        return False
    plan = plan_codec.flatten(v.plan_text)
    differ = next((k for k, x in have.items() if k not in plan or str(plan[k]) != str(x)), None)
    if differ is not None:
        info.update(plan={}, plan_text=None, how=None, transform=None, cut=False, ambiguous=True, source=None)
        info.pop("one_copy", None)
        info["notes"].append(f"the language-blind container reading differs from the other reading on "
                             f"{ascii(str(differ))[:60]}: neither is taken")
        return False
    info.update(plan=plan, plan_text=v.plan_text, how=v.how, transform=v.transform, cut=False, ambiguous=False,
                source="blind_reader", two_copies=v.copies >= 2)
    if info.get("descriptor"):
        info["descriptor_keys"] = set(plan)
    info.pop("one_copy", None)
    info.pop("one_copy_wrapped", None)
    info["notes"].append(f"plan read whole by the language-blind container reader ({v.copies} "
                         f"cop{'y' if v.copies == 1 else 'ies'}; blind_reader)")
    return True


def by_residual(info: dict, name: str = "", hosts: bool = False):
    """B-247: residuals.apply(info) (or, with `hosts`, residuals.multi_host: a script nested in base64 hosts more
    than one level deep). A missing residuals.py or a module it needs fails loudly; only a module hidden on purpose
    (CTF_HIDE) is a note. A bug inside the readers is a note, as in by_blind: the file stays as the others read it."""
    mod = plan_codec.optional("residuals")
    if mod is None or not hasattr(mod, "apply"):
        if "residuals" in plan_codec.hidden():
            info["notes"].append("residuals.py is hidden (CTF_HIDE): the residual copies are not weighed")
            return None
        raise RuntimeError("residuals.py (solvers/script-analysis) did not load: the residual copies (the exact "
                           "HUNTRESS_DESCRIPTOR key, wrapped and deep comments, computed values) cannot be weighed")
    try:
        return mod.multi_host(info, name) if hosts else mod.apply(info)
    except mod.MissingModule as e:
        if e.module in plan_codec.hidden():
            info["notes"].append(f"residuals: {e} (hidden by CTF_HIDE)")
            return None
        raise
    except Exception as e:  # noqa: BLE001 - a reader that fails leaves the file as the others read it
        info["notes"].append(f"residuals raised {type(e).__name__}: {e}")
        return None


def _descriptor_sig(got) -> tuple:
    """What a descriptor reading settled, as by_descriptor reads it: the plan, whether two copies agree (a comment
    and a literal), and without them whether a one-copy sign leaves its last field unproven."""
    if not got:
        return (None,)
    copies = set(got.get("copies") or ())
    two = "comment" in copies and "literal" in copies
    one = not two and any(bool(got.get(k)) for k in ("open", "doubt", "trimmed", "fallback", "split_lone"))
    return got.get("plan"), got.get("why"), two, one


# Round 2 of the Day 9 preparation (2026-10-08). All 84 version-3 descriptors of Day 8 hold the same fifteen
# fields, and a version-3 plan with fewer was read as a cut plan: nothing was answered from it. A later day
# may simply write fewer fields. One file cannot tell the two apart, the delivery can: a plan is of a shorter
# FORMAT when SHORT_SIBLINGS or more other descriptors of the same delivery hold exactly its fields in its
# order and none of them goes on behind them (a plan cut between two fields, or inside a value, holds a
# prefix of what its siblings hold). Then it is read as a whole plan is (the copies and the one-copy rules
# as before), and a question about a field it does not hold stays open by itself. Without that proof the
# plan is taken without its last field, the one value a cut holds cut; before, it answered nothing.
SHORT_SIBLINGS = 2
SHORT_NOTE = ("the descriptor's plan has fewer fields than its version holds and no other descriptor of the "
              "delivery is written so: it is taken without its last field")


def short_format(info: dict, plan: dict, mod) -> bool:
    """Whether a version-3 plan with fewer fields than PLAN_KEYS is the delivery's format (see above).
    True at once for a plan that lacks nothing."""
    if not hasattr(mod, "lacking") or not mod.lacking(plan):
        return True
    siblings = info.get("siblings")
    try:
        others = siblings() if callable(siblings) else ()
    except Exception as e:  # noqa: BLE001 - no census is no proof
        info["notes"].append(f"the delivery's other descriptors could not be read ({type(e).__name__}: {e})")
        others = ()
    mine = tuple(plan)
    same = sum(1 for keys in others if keys == mine)
    longer = any(len(keys) > len(mine) and keys[:len(mine)] == mine for keys in others)
    if same >= SHORT_SIBLINGS and not longer:
        info["short_format"] = True
        info["notes"].append(f"a version {plan.get('v')} plan of {len(mine)} fields, as {same} other descriptors of the "
                             f"delivery are: read as the delivery's format")
        return True
    return False


SIBLING_MAX = 256            # other files of a delivery whose descriptor is read for short_format
SIBLING_BYTES = 1 << 20
_SIBLING_KEYS = {}           # id(bytes of a file) -> (those bytes, its descriptor plan's field names or None)
_SIBLING_KEPT = 4096


def _keys_of(mod, other: str, data) -> tuple:
    """The ordered field names of one file's tagged descriptor plan, or None; read once per file. Review of
    round 2 (2026-10-08): every specimen with a short plan read every other file of the delivery again, so
    a delivery whose format IS shorter (the case this rule is for) cost the square of its size: 160
    specimens 7.0 s where the fifteen-field format takes 0.17 s. The bytes are kept beside the result, so
    an id is never that of another object."""
    hit = _SIBLING_KEYS.get(id(data))
    if hit is not None and hit[0] is data:
        return hit[1]
    try:
        got = mod.reading_ex(plan_codec.text_of(data), Path(other).suffix.lower())
        keys = tuple(plan_codec.flatten(got["plan"])) if got and got.get("plan") else None
    except Exception:  # noqa: BLE001 - a sibling that cannot be read is no sibling
        keys = None
    if len(_SIBLING_KEYS) >= _SIBLING_KEPT:
        _SIBLING_KEYS.clear()
    _SIBLING_KEYS[id(data)] = (data, keys)
    return keys


def sibling_keys(files: dict, name: str):
    """A function that returns the ordered field names of every other file's tagged descriptor plan in the
    delivery (read when a short plan asks, each file once in the process)."""
    cache = []

    def keys():
        if cache:
            return cache[0]
        out = []
        mod = plan_codec.optional("descriptor")
        mine = find(files, name)
        if mod is not None and hasattr(mod, "reading_ex"):
            seen = 0
            for other, data in files.items():
                if "->" in other or data is mine or not isinstance(data, (bytes, bytearray)) or len(data) > SIBLING_BYTES:
                    continue
                if b"HUNTRESS" not in data and b"descriptor_" not in data:
                    continue
                seen += 1
                if seen > SIBLING_MAX:
                    break
                found = _keys_of(mod, other, data)
                if found:
                    out.append(found)
        cache.append(out)
        return out
    return keys


def _dead_hint(text: str, mod) -> bool:
    """Whether the file carries a SPLIT name or a quoted tagged-looking value with a run of material behind its tag
    (descriptor.SPLIT_HINT, narrowed: `"HEX-48656c6c6f"` or `"B64-SGVsbG8="` alone is a banner, not a piece)."""
    for m in mod.SPLIT_HINT.finditer(text) if "-" in text else ():
        if m.group(1) is None:
            return True
        if mod.tag_chain(m.group(1)) is None:
            continue
        run = _MATERIAL_RUN.match(text, m.end(1) + 1)
        if run is not None and run.end() - run.start() >= _HINT_PAYLOAD:
            return True
    return False


def dead_only(info: dict) -> bool:
    """DEAD_TEXT_GUARD: whether the plan plan_codec read stands only in dead text of a file that carries a
    tagged-looking value (see the switch). Changes nothing in `info`; read() applies the verdict after the
    descriptor. Never raises; a check that fails says False (the plan as read)."""
    mod = plan_codec.optional("descriptor")
    text, ext = info["text"], (info.get("ext") or "").lower().lstrip(".")
    try:
        if mod is None or not hasattr(mod, "live_code") or not _dead_hint(text, mod):
            return False
        live = mod.live_code(text, ext)
        lines = _LINE_COMMENTS.get(ext)
        if lines is not None:
            live = lines.sub(lambda m: " " * len(m.group(0)), live)
        for m in _ASSIGNED_MATERIAL.finditer(text):
            # a multi-line string or template literal that holds material and nothing else, assigned
            # on a line of live code, is that value's own text (review of 9793be0: `const material = `<b64>`;`
            # beside a tagged-looking banner lost every answer): it is given back to the live text
            if live[m.start("name"):m.end("name")] == m.group("name"):
                live = live[:m.start("body")] + m.group("body") + live[m.end("body"):]
        if live == text or not any(live[m.start()] == " " and not _MARKER_RUN.fullmatch(m.group(0))
                                   for m in _MATERIAL_RUN.finditer(text)):
            return False                         # no run of material in dead text: the plan cannot stand there
        again, _ = plan_codec.reading(live, info.get("ext"))
        again = again or plan_codec.decode(live, info.get("ext"))
    except Exception as e:  # noqa: BLE001
        info["notes"].append(f"the dead-text check raised {type(e).__name__}: {e}")
        return False
    return not (again and again[0] == info.get("plan_text"))


def _dead_text(text: str, ext: str, mod) -> str:
    """`text` with its LIVE code blanked and its dead text (descriptor.live_code's comment blocks, templates and
    heredocs, plus the file's own comment lines) kept: the complement of dead_only's `live`. A material assigned
    on a line of live code is live, as in dead_only."""
    live = mod.live_code(text, ext)
    lines = _LINE_COMMENTS.get(ext)
    if lines is not None:
        live = lines.sub(lambda m: " " * len(m.group(0)), live)
    for m in _ASSIGNED_MATERIAL.finditer(text):
        if live[m.start("name"):m.end("name")] == m.group("name"):
            live = live[:m.start("body")] + m.group("body") + live[m.end("body"):]
    # text[i] where live differs from it, else a blank; a blank past live's end (the same string as the indexed
    # comprehension of before, read pairwise; perf, Day 27 speed build)
    return "".join(t if c != t else " " for t, c in zip(text, live)) + " " * max(0, len(text) - len(live))


# Day 20 gaps (script group): the descriptor's own copies in dead text. dead_only drops a plan PLAN_CODEC read
# from dead text, but descriptor.reading_ex reads a `descriptor_<id> = ".."` literal and a tagged comment wherever
# they stand: an older pair kept in a /* */ block, a docstring, a template literal or comment lines (`// const
# descriptor_old = ".."`), beside live copies in a form nothing reads (`descriptor_x = unmask("..", 23)`), was
# taken whole and answered plain (staged: 291 WRONG of 1,794 ids in 16 languages, no marker). Now a plan the
# descriptor settled is read once more with the dead text blanked (descriptor.live_code's blocks, templates and
# heredocs, and the file's own comment lines; a line that holds the HUNTRESS_ANALYSIS marker is kept, for the
# tagged comment is a comment by design, as are the material-only strings dead_only gives back). When that reading
# does not settle the same plan in the same way (the same copies) and live code still names a descriptor or holds
# a tagged-looking value, the plan stood on copies in dead text while the live ones say something else or nothing
# readable: no plan is taken. Only a file whose dead text holds a descriptor literal or a quoted tagged value with
# material is read twice; the classic form (a tagged comment line and a live literal) holds neither there.
_DEAD_DESC_COPY = re.compile(r"(?<![A-Za-z0-9])descriptor_\w+[^\r\n]{0,48}?[\"'`][A-Za-z0-9+/=._:-]{16,}"
                             r"|(?<![A-Za-z0-9])descriptor_\w+[ \t]*=[ \t]*[A-Za-z0-9+/=._:-]{16,}"   # Batch's set
                             r"|[\"'`][A-Z][A-Z0-9_+]{0,31}-[A-Za-z0-9+/=._:-]{16,}")
_LIVE_WITNESS = re.compile(r"(?i)descriptor|HUNTRESS[_-]?ANALYSIS[_-]?V\d+[_-]\w"
                           r"|[\"'`][A-Z][A-Z0-9_+]{0,31}-[A-Za-z0-9+/=._:-]{16,}")
_MARK_LINE = re.compile(r"HUNTRESS[_-]ANALYSIS[_-]V\d+[ \t]*[:=][^\r\n]*")
# A live assignment to a descriptor-like name (`descriptor_x = unmask(..)`, `$descriptor_x = ..`, `descriptor_x <- ..`,
# `HUNTRESS_ANALYSIS_V1_x := ..`): a live copy in a form the reader may not read
_LIVE_ASSIGN = re.compile(r"(?i)(?<![\w])[$@]?\w*(?:descriptor|huntress[_-]?analysis|tagged)\w*[ \t]*"
                          r"(?::[ \t]*[A-Za-z][^=\r\n]{0,40})?(?:<-|:?=(?![=>~]))")
# The openers of descriptor.DEAD (a superset: a match only means live_code is asked), for every extension and for
# the ones that have their own
_DEAD_OPENER = re.compile(r"/\*|<!--|<#|--\[=*\[|\"\"\"|'''|(?m:^=[a-z])|(?i:#c(?:s|omments-start)\b)"
                          r"|(?m:@[\"'][ \t]*\r?$)|<<<?[-~]?[ \t]*([\"']?)[A-Z_][A-Z0-9_]*\1(?!\w)")
_DEAD_OPENER_EXT = {e: re.compile(o) for es, o in (
    (("js", "mjs", "cjs", "jsx", "ts", "tsx", "gs", "jse", "go", "coffee"), r"`"), (("coffee",), r"###"),
    (("jl",), r"#="), (("nim",), r"#\["), (("applescript",), r"\(\*"), (("lua",), r"\[=*\[")) for e in es}


# The same openers as plain text, one alternation of literals (searched about four times faster than the regex
# above): what decides whether the regex is asked at all
# The comment lines dead_descriptor reads (only there): _LINE_COMMENTS, and Batch's `REM` and `::` lines and
# VBScript's `Rem` lines (the review of 9e5befc staged an older pair on such lines: 7 WRONG of 39 ids each)
_REM = r"(?i:rem)(?=[ \t]|$)"
_DESC_LINE_COMMENTS = dict(_LINE_COMMENTS)
for _e, _alt in (("bat", _REM + "|::"), ("cmd", _REM + "|::"), ("vbs", _REM + "|'"), ("vbe", _REM + "|'"),
                 ("vba", _REM + "|'"), ("bas", _REM + "|'"), ("cls", _REM + "|'"), ("frm", _REM + "|'")):
    _DESC_LINE_COMMENTS[_e] = re.compile(r"(?m)^[ \t]*@?(?:%s)[^\n]*" % _alt)
del _e, _alt
_DEAD_QUICK = re.compile(r"/\*|<!--|<#|--\[|\"\"\"|'''|<<|@[\"']|\n=|#[cC]")
_DESC_SITES = 16              # `descriptor_` mentions looked at on comment lines


def _has_dead_opener(text: str, ext: str) -> bool:
    """Whether `text` may hold dead text: one search of the openers as literals, then the regex."""
    own = _DEAD_OPENER_EXT.get(ext)
    if own is not None and own.search(text) is not None:
        return True
    if not text.startswith("=") and _DEAD_QUICK.search(text) is None:
        return False
    return _DEAD_OPENER.search(text) is not None


def _desc_on_comment_line(text: str, ext: str) -> bool:
    """Whether a `descriptor_` mention with material behind it stands on a comment line of the file's own
    language that is no tagged comment (at most _DESC_SITES mentions; a file past them counts as one)."""
    lines = _DESC_LINE_COMMENTS.get(ext)
    if lines is None:
        return False
    at, k = 0, 0
    while True:
        i = text.find("descriptor_", at)
        if i < 0:
            return False
        at = i + 11
        k += 1
        if k > _DESC_SITES:
            return True
        start = text.rfind("\n", 0, i) + 1
        m = lines.match(text, start)
        if m is not None and m.end() > i and not _MARK_LINE.search(m.group(0)) and _DEAD_DESC_COPY.search(m.group(0)):
            return True


_BLOCK_ONE_LINE = re.compile(r"[ \t]*(?:/\*+|<!--|<#|\(\*|--\[=*\[|#\[|#=)[ \t]*$")


_LIVE_NAME = re.compile(r"(?i)(?<![\w])[$@%]?\w*(?:descriptor|huntress[_-]?analysis|tagged)\w*")
_ENDS_ASSIGN = re.compile(r"(?:<-|:?=(?![=>~]))[ \t]*(?:\\|_|`)?[ \t]*\r?$", re.M)   # a line that ends `=` (a continuation allowed)


def _live_copy(masked: str) -> bool:
    """Whether live code (tagged comments blanked) holds a descriptor-like copy in a form the reader may not read: a
    descriptor-like name assigned a value (_LIVE_ASSIGN), or one with a run of material behind it on its line
    (`call :unmask descriptor_x 5a1f..`). A name mentioned in prose (`echo "stage written: descriptor_x"`) is none.
    At most _DESC_SITES names are looked at; a file past them counts as holding one."""
    if _LIVE_ASSIGN.search(masked) is not None:
        return True
    for k, m in enumerate(_LIVE_NAME.finditer(masked)):
        if k >= _DESC_SITES:
            return True
        end = masked.find("\n", m.end())
        if _MATERIAL_RUN.search(masked, m.end(), len(masked) if end < 0 else end) is not None:
            return True
        if end >= 0 and _ENDS_ASSIGN.search(masked, m.end(), end) is not None:
            # (Day 20 gaps, residual) the name's line ends in an assignment and its value stands on the next line
            # (`window["descriptor_" + "x"] =\n    unmask("5a1f..", 23);`): material there is a copy too
            nxt = masked.find("\n", end + 1)
            if _MATERIAL_RUN.search(masked, end + 1, len(masked) if nxt < 0 else nxt) is not None:
                return True
    return False


# Dead text descriptor.live_code does not blank, blanked for dead_descriptor only: Perl's and Ruby's data section
# (`__END__` or `__DATA__` on a line of its own, to the end of the file) and a C-family `#if 0` .. `#endif` with no
# other conditional inside (the review of 9e5befc staged an older pair there: 7 WRONG of 39 ids each)
_DATA_END = re.compile(r"(?m)^(?:__END__|__DATA__)[ \t]*\r?$")
_IF0 = re.compile(r"(?m)^[ \t]*#[ \t]*if[ \t]+0[ \t]*(?://[^\n]*|/\*.*?\*/)?\r?\n(?P<body>(?:(?![ \t]*#[ \t]*(?:if|endif|el))[^\n]*\n)*?)"
                  r"[ \t]*#[ \t]*endif\b")
_MORE_DEAD = {**{e: _DATA_END for e in ("pl", "pm", "rb")},
              **{e: _IF0 for e in ("c", "h", "cc", "cpp", "cxx", "hpp", "hh", "m", "mm", "cs")}}


_IF0_QUICK = re.compile(r"#[ \t]*if[ \t]+0")


def _more_dead_in(text: str, ext: str) -> bool:
    """Whether `text` may hold a region of _MORE_DEAD (a literal search first: most files hold none)."""
    rx = _MORE_DEAD.get(ext)
    if rx is None:
        return False
    if rx is _DATA_END:
        return ("__END__" in text or "__DATA__" in text) and rx.search(text) is not None
    return "#" in text and _IF0_QUICK.search(text) is not None


_PP_LINE = re.compile(r"(?m)^[ \t]*#[ \t]*(if|ifdef|ifndef|elif|elifdef|elifndef|else|endif)\b")


def _if0_spans(code: str) -> list:
    """The regions of `#if 0` .. its own `#endif` (or its `#else`/`#elif`, where the live branch starts), nested
    conditionals inside counted (Day 20 gaps, residual: the review's `#if 0` with an `#ifdef` inside was not blanked)."""
    spans = []
    for m in re.finditer(r"(?m)^[ \t]*#[ \t]*if[ \t]+0\b", code):
        if spans and m.start() < spans[-1][1]:
            continue                             # inside a region already taken
        depth = 1
        for d in _PP_LINE.finditer(code, m.end()):
            word = d.group(1)
            if word in ("if", "ifdef", "ifndef"):
                depth += 1
            elif word == "endif":
                depth -= 1
                if depth == 0:
                    spans.append((m.start(), d.end()))
                    break
            elif depth == 1:                     # #else / #elif of the `#if 0` itself: the dead branch ends here
                spans.append((m.start(), d.start()))
                break
        if len(spans) >= _DESC_SITES:
            break
    return spans


def _blank_more(code: str, ext: str) -> str:
    """`code` (live_code's text) with _MORE_DEAD's regions of the extension blanked; line ends are kept."""
    rx = _MORE_DEAD.get(ext)
    if rx is None or not _more_dead_in(code, ext):
        return code
    spans = []
    if rx is _DATA_END:
        m = rx.search(code)
        if m is not None:
            spans.append((m.start(), len(code)))
    else:
        spans = _if0_spans(code)[:_DESC_SITES]
    for a, b in spans:
        code = code[:a] + "".join(c if c in "\r\n" else " " for c in code[a:b]) + code[b:]
    return code


# Day 20 gaps, residual (review of 2310f7d): encoded material in live code that no tagged comment of the file holds,
# a run of hex or of base64 (with a digit, `+` or `/`, so no long identifier) long enough to hold a plan's piece
_ENCODED_RUN = re.compile(r"(?<![A-Za-z0-9+/=])(?:[0-9A-Fa-f]{32,}|[A-Za-z0-9+/]{32,}={0,2})(?![A-Za-z0-9+/=])")
_ENCODED_SITES = 64


def _unread_material(masked: str, text: str, named_only: bool) -> bool:
    """Whether live code (`masked`: tagged comments blanked) holds encoded material that no tagged comment of the file
    holds (neither a piece of a comment's payload nor holding it): a copy in a form the reader does not read
    (`const cfg = unmask("5a1f..", 23)`, `call :unmask 5a1f..`). With `named_only`, only material on the line of a
    descriptor-like name (or on the next line, after a line that ends in an assignment) counts. At most
    _ENCODED_SITES runs are looked at; a file past them counts as holding such material."""
    bodies = [m.group(0) for m in _MARK_LINE.finditer(text)]
    runs = [r.group(0) for b in bodies for r in _MATERIAL_RUN.finditer(b)]
    if named_only:
        spans = []
        for m in _LIVE_NAME.finditer(masked):
            end = masked.find("\n", m.end())
            end = len(masked) if end < 0 else end
            if _ENDS_ASSIGN.search(masked, m.end(), end) is not None and end < len(masked):
                nxt = masked.find("\n", end + 1)
                end = len(masked) if nxt < 0 else nxt
            spans.append((m.end(), end))
            if len(spans) > _DESC_SITES:
                return True
    else:
        spans = [(0, len(masked))]
    k = 0
    for a, b in spans:
        for r in _ENCODED_RUN.finditer(masked, a, b):
            k += 1
            if k > _ENCODED_SITES:
                return True
            v = r.group(0)
            if v.isalpha():
                continue                         # letters only: a word, not material
            if not any(v in body for body in bodies) and not any(x in v for x in runs if len(x) >= 32):
                return True
    return False


def _one_line_block(text: str, a: int, b: int) -> bool:
    """Whether the tagged comment at text[a:b] is a comment block of its own on its one line: only a block opener
    and blanks before it on the line, and the block's closer on the same line (the match runs to the line's end)."""
    start = text.rfind("\n", 0, a) + 1
    if not _BLOCK_ONE_LINE.fullmatch(text, start, a):
        return False
    tail = text[a:b].rstrip()
    return tail.endswith(("*/", "-->", "#>", "*)", "]]", "]#", "=#"))


# The Day 21 look-ahead: a host that holds the WHOLE tagged script (the marker comment and the descriptor literal,
# its two copies) in one multi-line string or heredoc and does nothing else with it in live code (a Jenkins
# `sh '''..'''` step, a Dockerfile `RUN <<'EOF'`, a Python or Kotlin `"""..."""`): the unescaped twin of row 371's
# escaped embedding. dead_descriptor refused it (every copy in dead text, nothing live reads a plan): 33 of 33 ids
# None a host. Taken only when that one dead region gives the plan by its own two agreeing copies, no other dead
# region and nothing outside the region holds a marker or a descriptor, and live code holds no copy in a form
# nothing reads (a descriptor-like name, encoded material, character codes): a decoy pair beside a real copy
# hidden in live code is still refused as before. Read at call time.
EMBEDDED_SCRIPT = True
_CHAR_CODE_RUN = re.compile(r"(?i)fromcharcode|\bchrw?\$?\(|\[char\]|(?:\b\d{2,3}[ \t]*,[ \t]*){15,}\d{2,3}\b")
_QUOTED_PIECE = re.compile(r"[\"'`](?=[A-Za-z0-9+/=._:-]*\d)[A-Za-z0-9+/=._:-]{8,}[\"'`]")   # a piece of material


def _dead_spans(text: str, code: str) -> list:
    """[(start, end)] of the regions live_code blanked: runs of changed characters, blanks between them joined."""
    spans, a, last = [], None, None
    for i, c in enumerate(code):
        if c == text[i]:
            continue
        if a is not None and text[last + 1:i].strip() == "":
            last = i
            continue
        if a is not None:
            spans.append((a, last + 1))
        a = last = i
    if a is not None:
        spans.append((a, last + 1))
    return spans


def _embedded_whole(text: str, ext: str, code: str, mod, settled) -> bool:
    """Whether the plan `settled` is the file's one embedded script's (EMBEDDED_SCRIPT, above). Never raises."""
    try:
        if settled is None or len(code) != len(text):
            return False
        spans = [(a, b) for a, b in _dead_spans(text, code)
                 if "descriptor_" in text[a:b] or _MARK_LINE.search(text, a, b) is not None]
        if len(spans) != 1:
            return False                         # no region, or two that hold copies: which one is the file's?
        a, b = spans[0]
        inner = text[a:b]
        got = mod.reading_ex(inner, ext)
        if not got or got.get("plan") != settled or got.get("why") \
                or not {"comment", "literal"} <= set(got.get("copies") or ()):
            return False                         # the region alone must prove the plan by its two copies
        return _region_alone(text, code, a, b, _payload_len(inner))
    except Exception:  # noqa: BLE001 - a check that fails proves nothing: refuse, as before
        return False


# Since the Day 21 final prep: the guards of the region's outside, widened. The look-ahead's decoy check missed a
# real plan kept in live code as quoted pieces under 8 characters (`def p0 = '5a1f0c'` ...) and as an octal list
# (`[0o154, 0o141, ..]`): an older plan embedded in a heredoc then answered PLAIN (9 plain and 2 WRONG a file).
# Outside the region, any of these refuses: three or more quoted literals of the material alphabet whose joined
# text is 24 characters or more and holds a digit, or such literals totalling half the embedded payload's length
# or more; a list of 16 or more numbers in any base (0o, 0x, 0b, decimal; wrapped across lines too); a run of 8
# or more \xNN or \uNNNN escapes. They only refuse: nothing becomes plain.
_QUOTED_LIT = re.compile(r"\"([A-Za-z0-9+/=._:-]+)\"|'([A-Za-z0-9+/=._:-]+)'|`([A-Za-z0-9+/=._:-]+)`")
_NUM = r"(?:0[oO][0-7]+|0[xX][0-9A-Fa-f]+|0[bB][01]+|\d+)"
_NUM_LIST = re.compile(r"(?<![\w.])" + _NUM + r"(?:\s*,\s*" + _NUM + r"){15,}")
_NUM_SHORT = re.compile(r"(?<![\w.])" + _NUM + r"(?:\s*,\s*" + _NUM + r"){3,}(?![\w.])")
_NUM_ONE = re.compile(_NUM)
_ESC_RUN = re.compile(r"(?:\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|\\u\{[0-9A-Fa-f]{1,6}\}){8,}")
_XMLNS = re.compile(r"""\bxmlns(?::[\w.-]+)?\s*=\s*(?:"[^"\r\n]*"|'[^'\r\n]*')""")   # a namespace name, no data


def _payload_len(region: str) -> int:
    """The length of the longest run of material on the region's tagged comment line (its payload), or 0."""
    return max((len(r.group(0)) for m in _MARK_LINE.finditer(region) for r in _MATERIAL_RUN.finditer(m.group(0))),
               default=0)


def _hidden_copy(rest: str, payload_len: int) -> bool:
    """Whether `rest` (the file outside the embedded region) may hold the plan in a form nothing reads: quoted
    pieces of material (any length), a list of numbers in any base, a run of escapes (see above)."""
    lits = [next(g for g in m.groups() if g is not None) for m in _QUOTED_LIT.finditer(rest)]
    joined = "".join(lits)
    if len(lits) >= 3 and len(joined) >= 24 and re.search(r"\d", joined):
        return True                              # three or more pieces
    if payload_len and len(joined) * 2 >= payload_len:
        return True                              # as much quoted material as half the payload
    if _NUM_LIST.search(rest) is not None or _ESC_RUN.search(rest) is not None:
        return True
    # Since the review of the final prep's review fix: numbers are counted across lists, as quoted pieces are across
    # literals. A plan split into shorter lists (`[15 nums] + [15 nums]`, `def cN = [8 nums]` a line, octal lists of
    # 10) answered 9 plain and 2 WRONG beside an older plan in the heredoc. Every list of 4 or more numbers counts.
    total = sum(len(_NUM_ONE.findall(m.group(0))) for m in _NUM_SHORT.finditer(rest))
    return total >= 16 or bool(payload_len and total * 2 >= payload_len)


def _region_alone(text: str, code: str, a: int, b: int, payload_len: int) -> bool:
    """Whether nothing outside text[a:b] (the one region that holds the tagged script) holds a copy, a witness, a
    marker, or material in a form nothing reads. `code` is the text with its dead parts blanked (same length)."""
    outside = text[:a] + text[b:]
    if "descriptor" in outside.lower() or _MARK_LINE.search(outside) is not None \
            or re.search(r"(?i)HUNTRESS[_-]?ANALYSIS", outside) is not None:
        return False                             # a copy, a witness or a marker beside it
    rest = code[:a] + " " * (b - a) + code[b:]
    rest = _XMLNS.sub(lambda m: " " * len(m.group(0)), rest)
    if _MATERIAL_RUN.search(rest) is not None and _unread_material(rest, text, False):
        return False                             # encoded material in live code that the tagged comment does not hold
    if _CHAR_CODE_RUN.search(rest) is not None or _QUOTED_PIECE.search(rest) is not None:
        return False                             # a copy spelled as character codes, or held in quoted pieces
    if _hidden_copy(rest, payload_len):
        return False                             # short pieces, a number list in any base, escapes (final prep)
    if _unquoted_material(rest, text):
        return False                             # an unquoted value: `set X=<material>`, `def p0=5a1f0c` (review)
    return True


# Since the review of the Day 21 final prep: _ENCODED_RUN's lookbehind keeps a run that follows `=` from matching, and
# _hidden_copy and _QUOTED_PIECE count only quoted pieces, so a real plan written as an UNQUOTED value (`set X=<b64>`,
# `set A=<half>` `set B=<half>`, `set H=<hex|base32|reversed payload>`, `def cfg=<hex>`, `set p0=5a1f0c` ...) beside
# an older plan in the encoded literal or the heredoc was not seen: 9 plain and 2 WRONG a file (campaign, url). Now
# either refuses: a run of 32 or more characters of hex, base64 or base32 (with a digit; base64 with both letter
# cases) that follows anything but the material alphabet and that no tagged comment of the file holds; or three or
# more unquoted assignment values of the material alphabet whose joined text is 24 characters or more and holds a
# digit. They only refuse: nothing becomes plain.
_LOOSE_RUN = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{32,})={0,6}(?![A-Za-z0-9+/=])")
_UNQUOTED_VALUE = re.compile(r"(?im)^[ \t]*(?:(?:set|def|var|let|local|const|export|typeset|declare)[ \t]+"
                             r"(?:-[a-z]+[ \t]+)*)?\$?[A-Za-z_][\w.]*[ \t]*[:]?=[ \t]*([A-Za-z0-9+/=._:-]+)[ \t]*;?[ \t]*\r?$")


def _loose_material(v: str) -> bool:
    """Whether a run of _LOOSE_RUN looks like encoded material: hex, base32 (capitals and 2-7) or base64 with
    both letter cases, holding a digit (a long identifier or a path of letters is none)."""
    if not re.search(r"\d", v):
        return False
    if re.fullmatch(r"[0-9A-Fa-f]+", v) or re.fullmatch(r"[A-Z2-7]+", v):
        return True
    return re.search(r"[a-z]", v) is not None and re.search(r"[A-Z]", v) is not None


def _unquoted_material(rest: str, text: str) -> bool:
    """See above. `rest` is the file outside the region with its dead parts blanked; `text` the whole file, whose
    tagged comments say what material is the plan's own."""
    bodies = [m.group(0) for m in _MARK_LINE.finditer(text)]
    runs = [r.group(0) for b in bodies for r in _MATERIAL_RUN.finditer(b)]
    k = 0
    for r in _LOOSE_RUN.finditer(rest):
        v = r.group(1)
        if not _loose_material(v):
            continue
        k += 1
        if k > _ENCODED_SITES:
            return True
        if not any(v in body for body in bodies) and not any(x in v for x in runs if len(x) >= 32):
            return True
    vals = [m.group(1) for m in _UNQUOTED_VALUE.finditer(rest)]
    joined = "".join(vals)
    return len(vals) >= 3 and len(joined) >= 24 and re.search(r"\d", joined) is not None


# Since the Day 21 final prep: an ENCODED host, one that holds the whole tagged script as one base64 literal a
# shell decodes and runs (`powershell -EncodedCommand <base64 of UTF-16LE>` in a .bat or a scheduled task's XML,
# `echo '<base64>' | base64 -d | sh`, a gzip+base64 `IEX .. FromBase64String('..')` cradle): 99 of 99 ids None.
# One decode layer, asked only of a file that gave no plan: the literal (64+ characters) after -EncodedCommand,
# -enc, -ec or -e in a file that names powershell or pwsh, the FromBase64String argument, or the echo'd text before
# `| base64 -d | sh`; decoded as UTF-16LE when it has a BOM or alternating NULs, else UTF-8, through gzip or raw
# deflate when it is one. Taken only when exactly one such literal decodes to a text with exactly one
# HUNTRESS_ANALYSIS marker, that text, read as its own file with every guard, settles the plan by a tagged comment
# and a descriptor literal that agree, and nothing outside the literal holds a marker, a descriptor or material in
# a form nothing reads (_region_alone, the widened guards included). A file that settled a plan of its own and
# holds such a literal whose script gives ANOTHER plan answers nothing (two plans). Read at call time.
ENCODED_HOST = True
_ENC_B64 = r"([A-Za-z0-9+/]{64,}={0,2})(?![A-Za-z0-9+/=])"
_ENC_FORMS = (     # in this order: a literal one form read is not read again by a later one (`echo -e '..' | ..`)
    ("sh", re.compile(r"(?i)\b(?:echo|printf)[ \t]+(?:-[a-z]+[ \t]+)*(?:[\"']%s(?:\\n)?[\"'][ \t]+)?[\"']?" + _ENC_B64
                      + r"[\"']?[ \t]*\|[ \t]*base64[ \t]+(?:-d|--decode|-D)\b[ \t]*\|[ \t]*(?:ba|da|z|k)?sh\b"), False),
    ("ps1", re.compile(r"(?i)FromBase64String\(\s*[\"']" + _ENC_B64 + r"[\"']\s*\)"), False),
    ("ps1", re.compile(r"(?i)(?<![\w-])[-/](?:encodedcommand|enc|ec|e)[ \t]+[\"']?" + _ENC_B64), True),
)
_ENC_QUICK = re.compile(r"(?i)encodedcommand|[-/]e(?:nc?|c)?\b|frombase64string|base64[ \t]+(?:-d|--decode|-D)")
_PS_NAMED = re.compile(r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b")
_ENC_CANDIDATES = 8           # literals decoded at most
_ENC_MAX = 256 << 10          # bytes a decoded script may hold
_MARK_ANY = re.compile(r"(?i)HUNTRESS[_-]?ANALYSIS")


def _enc_text(lit: str):
    """The script a base64 literal holds (one layer, through gzip or raw deflate), as text; None when it is none."""
    import base64
    import binascii
    import zlib
    if len(lit) % 4:
        return None
    try:
        raw = base64.b64decode(lit, validate=True)
    except (binascii.Error, ValueError):
        return None

    def inflate(data, wbits):
        d = zlib.decompressobj(wbits)
        try:
            out = d.decompress(data, _ENC_MAX + 1)
        except zlib.error:
            return None
        return out if d.eof and not d.unused_data and len(out) <= _ENC_MAX else None

    def as_text(data):
        if not data:
            return None
        if data[:2] == b"\xff\xfe" or (len(data) >= 8 and len(data) % 2 == 0
                                        and data[1::2].count(0) * 10 >= len(data) // 2 * 9):
            body = data[2:] if data[:2] == b"\xff\xfe" else data
            try:
                return body.decode("utf-16-le")
            except UnicodeDecodeError:
                return None
        try:
            return data.decode("utf-8-sig")
        except UnicodeDecodeError:
            return None

    if raw[:2] == b"\x1f\x8b":
        raw = inflate(raw, 16 + 15)
        return as_text(raw) if raw is not None else None
    t = as_text(raw)
    if t is not None and _MARK_ANY.search(t):
        return t
    raw = inflate(raw, -15)
    return as_text(raw) if raw is not None else t


def _encoded_scripts(text: str) -> list:
    """[(ext, start, end, script)]: each distinct base64 literal of an encoded host's forms (see above) that
    decodes to a text holding a HUNTRESS_ANALYSIS marker, and last (None, 0, 0, "") when there were more literals
    than are decoded (_ENC_CANDIDATES). Raises what the readers raise."""
    if _ENC_QUICK.search(text) is None:
        return []
    ps = _PS_NAMED.search(text) is not None
    seen, out = set(), []
    for ext, rx, needs_ps in _ENC_FORMS:
        if needs_ps and not ps:
            continue
        for m in rx.finditer(text):
            span = m.span(1)
            if span in seen:
                continue                         # read by an earlier form
            seen.add(span)
            if len(seen) > _ENC_CANDIDATES:
                return out + [(None, 0, 0, "")]
            script = _enc_text(m.group(1))
            if script is not None and _MARK_ANY.search(script):
                out.append((ext, span[0], span[1], script))
    return out


def encoded_host(info: dict, name: str):
    """ENCODED_HOST (above): for a file that gave no plan, the plan of the one script its base64 literal holds, put
    in `info` (True); with a plan already settled, False when the literal's script agrees or holds none, and the
    string 'differ' when it gives another plan or none can be told. Never raises; a check that fails proves
    nothing (False)."""
    text = info["text"]
    try:
        found = _encoded_scripts(text)
        over = bool(found) and found[-1][0] is None
        found = [f for f in found if f[0] is not None]
        if info.get("plan"):
            # the file settled a plan of its own: every marked script must give that plan or none
            for inner_ext, _a, _b, script in found:
                inner = read(f"{Path(name).stem}.encoded.{inner_ext}", script, _nested=True)
                if not (inner.get("plan") == info["plan"] or (not inner.get("plan") and not inner.get("ambiguous"))):
                    return "differ"
            return False
        if not found:
            return False
        if len(found) != 1 or over:
            info["notes"].append(f"{len(found)} encoded scripts with a HUNTRESS_ANALYSIS marker"
                                 f"{', and more literals than are decoded' if over else ''}: none is read "
                                 f"(encoded host refused, Day 21 final prep)")
            return False
        inner_ext, a, b, script = found[0]
        inner = read(f"{Path(name).stem}.encoded.{inner_ext}", script, _nested=True)
        if len(_MARK_ANY.findall(script)) != 1 or "descriptor_" not in script:
            return False
        if not (inner.get("plan") and inner.get("source") == "descriptor" and inner.get("two_copies")
                and not inner.get("cut") and not inner.get("one_copy") and not inner.get("ambiguous")
                and not inner.get("dead_text")):
            return False                         # the script alone must prove the plan by its two agreeing copies
        if not _region_alone(text, text, a, b, _payload_len(script)):
            return False                         # a copy, a marker or material beside the literal (decoy guards)
        for k in ("plan", "plan_text", "how", "transform", "two_copies", "descriptor", "descriptor_keys",
                  "descriptor_sig"):
            if k in inner:
                info[k] = inner[k]
        info.update(cut=False, ambiguous=False, source="descriptor", route="encoded_host")
        info["notes"].append(f"the plan is the encoded host's one script: a base64 literal ({inner_ext}, "
                             f"{b - a} characters) decodes to the whole tagged script and its two copies agree "
                             f"(encoded host, Day 21 final prep)")
        return True
    except Exception as e:  # noqa: BLE001 - a check that fails proves nothing
        info["notes"].append(f"the encoded-host check raised {type(e).__name__}: {e}")
        return False


def dead_descriptor(info: dict):
    """DEAD_TEXT_GUARD (Day 20 gaps): whether the plan the descriptor settled stands on a copy in dead text while
    live code names another descriptor (see above). Changes nothing in `info`; read() applies the verdict. Never
    raises; a check that fails says False (the plan as settled). The fix round: when the live text (with a tagged
    comment counted only where it is live by design) settles the SAME plan, the verdict is that live text (a str),
    and read() takes the plan as the live copies give it (_settle_live) instead of none."""
    text, ext = info["text"], (info.get("ext") or "").lower().lstrip(".")
    try:
        if "descriptor_" not in text:
            return False                         # the copies descriptor.reading_ex reads in dead text are its literals
        if not _has_dead_opener(text, ext) and not _more_dead_in(text, ext):
            # no comment block, multi-line string or heredoc: only a comment line can be dead, and then one that
            # holds a descriptor literal (cheap: the common specimen pays no live_code)
            if not _desc_on_comment_line(text, ext):
                return False
        elif _DEAD_DESC_COPY.search(text) is None:
            return False
        mod = plan_codec.optional("descriptor")
        if mod is None or not hasattr(mod, "live_code") or not hasattr(mod, "reading_ex"):
            return False
        code = _blank_more(mod.live_code(text, ext), ext)
        live = code
        lines = _DESC_LINE_COMMENTS.get(ext)
        if lines is not None:
            live = lines.sub(lambda m: m.group(0) if _MARK_LINE.search(m.group(0)) else " " * len(m.group(0)), live)
        for m in _ASSIGNED_MATERIAL.finditer(text):
            if live[m.start("name"):m.end("name")] == m.group("name"):
                live = live[:m.start("body")] + m.group("body") + live[m.end("body"):]
        # `strict`: the live text in which a tagged comment inside a comment block counts only when that block is
        # the tagged comment alone, on its one line (`/* HUNTRESS_ANALYSIS_V1:.. */`); a tagged line inside a longer
        # block is part of what the block keeps, an older pair's own comment among them. Only the same-plan rescue
        # below reads it.
        strict = live
        for m in _MARK_LINE.finditer(text):      # the tagged comment, wherever it stands, is read as before
            live = live[:m.start()] + m.group(0) + live[m.end():]
            if code[m.start():m.end()] == m.group(0) or _one_line_block(text, m.start(), m.end()):
                strict = strict[:m.start()] + m.group(0) + strict[m.end():]
        if live == text:
            return False                         # no dead text: nothing to drop
        dead = "".join(c if live[i] != c else " " for i, c in enumerate(text)) if len(live) == len(text) else text
        if _DEAD_DESC_COPY.search(dead) is None:
            return False                         # no descriptor copy in dead text: the plan stands in live code
        live_got = mod.reading_ex(live, info.get("ext"))
        masked = _MARK_LINE.sub(lambda m: " " * len(m.group(0)), live)
        if live_got and live_got.get("plan") is not None and "literal" not in set(live_got.get("copies") or ()) \
                and _live_copy(masked):
            # the fix round: the plan's one live copy is the tagged comment, a descriptor copy stands in dead text
            # and live code holds a copy in a form nothing reads (`call :unmask descriptor_x 5a1f..`): which of the
            # two the comment belongs to the file does not say (the review's REM, `::` and `Rem` shapes)
            return True
        if live_got and live_got.get("plan") is not None \
                and _unread_material(masked, text, "literal" in set(live_got.get("copies") or ())):
            # Day 20 gaps, residual (review of 2310f7d): a descriptor copy stands in dead text and live code holds
            # encoded material no tagged comment holds, in a form nothing reads: with the tagged comment as the
            # plan's one live copy, anywhere in live code (`const cfg = unmask("5a1f..", 23)` beside an older
            # pair: the comment may be that pair's own line); beside a live literal too, on a descriptor-like
            # name's line (`var descriptor_x = unmask(..)` beside `var descriptor_old = ".."`)
            return True
        if _descriptor_sig(live_got) == info.get("descriptor_sig"):
            return False                         # the live text settles the same plan the same way
        settled = (info.get("descriptor_sig") or (None,))[0]
        if settled is None:
            return _LIVE_WITNESS.search(masked) is not None
        # The fix round (review of 9e5befc): the live text settles the SAME plan, only by other copies (a usage note
        # in a docstring repeats the literal; a heredoc writes the stage that holds it). That plan is the live
        # copies' own, and read() takes it as they give it (one copy loses its last field), never none.
        #   - a live descriptor literal that reads the same plan: taken with the tagged comment wherever it stands;
        #   - else the tagged comment alone, counted only where it is live by design (a comment line, or a block of
        #     its own on one line: `strict`), and only while live code assigns no descriptor a value nothing reads
        #     (beside such an assignment, or such a name with material behind it, the comment may be the older
        #     pair's own line: the decoy's comment_tag shape).
        if live_got and live_got.get("plan") == settled and "literal" in set(live_got.get("copies") or ()):
            return live
        strict_got = mod.reading_ex(strict, info.get("ext")) if strict != live else live_got
        if strict_got and strict_got.get("plan") == settled and not _live_copy(masked):
            return strict
        if not (strict_got and strict_got.get("plan")):
            # nothing live reads a plan: every copy the descriptor read, the tagged comment too, stands in dead text
            # (a decoy pair in a long comment block beside live copies in another form), witness or none; except a
            # host that embeds the whole tagged script in ONE multi-line string or heredoc (the Day 21 look-ahead)
            if EMBEDDED_SCRIPT and _embedded_whole(text, ext, code, mod, settled):
                info["notes"].append("the plan is the one embedded script's: a multi-line string or heredoc holds the "
                                     "whole tagged script and its two copies agree (embedded script, Day 21 look-ahead)")
                return False
            return True
        return _LIVE_WITNESS.search(masked) is not None
    except Exception as e:  # noqa: BLE001 - a check that fails proves nothing: answer as settled
        info["notes"].append(f"the dead-text descriptor check raised {type(e).__name__}: {e}")
        return False


def _settle_live(info: dict, live: str) -> bool:
    """The fix round of the Day 20 gaps: `info`'s descriptor plan read once more from `live`, the file with its dead
    text blanked (dead_descriptor), as read() reads a file: plan_codec's reading of that text, then by_descriptor.
    When that settles the same plan, `info` takes the live reading's plan, its cut and its one_copy (a copy in dead
    text no longer proves the last field) and True is said; otherwise `info` is left as it was and False."""
    try:
        ext = info.get("ext")
        got, note = plan_codec.reading(live, ext)
        got = got or (None if note else plan_codec.decode(live, ext))
        alt = dict(info)
        for k in ("one_copy", "one_copy_wrapped", "two_copies", "descriptor_sig", "descriptor", "descriptor_keys"):
            alt.pop(k, None)
        alt.update(text=live, plan_text=got[0] if got else None, how=got[1] if got else None,
                   transform=got[2] if got else None, plan=plan_codec.flatten(got[0]) if got else {},
                   notes=[note] if note else [], ambiguous=bool(note) and not got, cut=bool(note) and bool(got),
                   source="plan_codec" if got else None)
        by_descriptor(alt)
        if not (alt.get("plan") and alt.get("source") == "descriptor" and not alt.get("ambiguous")
                and (alt.get("descriptor_sig") or (None,))[0] == (info.get("descriptor_sig") or (None,))[0]):
            return False
    except Exception as e:  # noqa: BLE001 - a reading that fails settles nothing
        info["notes"].append(f"the live descriptor reading raised {type(e).__name__}: {e}")
        return False
    for k in ("plan", "plan_text", "how", "transform", "cut", "source", "descriptor_sig", "descriptor_keys"):
        info[k] = alt.get(k)
    info["two_copies"] = bool(alt.get("two_copies"))
    info.pop("one_copy", None)
    was_wrapped = bool(info.pop("one_copy_wrapped", None))
    if alt.get("one_copy"):
        info["one_copy"] = alt["one_copy"]
        info["one_copy_wrapped"] = bool(alt.get("one_copy_wrapped")) or was_wrapped   # a wrap either reading saw
    info["notes"].append("a copy of the descriptor stands in dead text and gives the same plan as the live copies: "
                         "the plan is taken as the live copies give it")
    return True


def dead_conflict(info: dict) -> bool:
    """DEAD_TEXT_GUARD / row 372(b): whether a tagged `<TAG>-<payload>` standing only in dead text (a /* */
    block, a template or multi-line string, a comment line) decodes to a plan that CONTRADICTS the plan taken
    (a different value on a field they share). The file then holds two plans and none is answered. The inverse
    of dead_only, which drops a plan plan_codec read FROM dead text; here the taken plan is live (the decoy) and
    the dead text witnesses a different one (the real). Changes nothing in `info`; read() applies the verdict.
    Never raises."""
    mod = plan_codec.optional("descriptor")
    taken = info.get("plan") or {}
    # Two copies of a descriptor that agree (comment and literal) are the strong case: the file's own plan,
    # already proven. Only a weakly supported plan (a lone literal, plan_codec's own reading) can be a decoy
    # whose real twin sits in dead text; running the scan only there also keeps it off the common base specimen.
    if mod is None or not taken or not hasattr(mod, "live_code") or info.get("two_copies"):
        return False
    text, ext = info["text"], (info.get("ext") or "").lower().lstrip(".")
    try:
        if re.search(r"[A-Z][A-Z0-9_+]{0,31}-[A-Za-z0-9+/=]", text) is None:
            return False                         # no tagged-looking value anywhere: nothing to witness
        dead = _dead_text(text, ext, mod)
        seen, n = set(), 0
        for m in mod.TAGGED_VALUE.finditer(dead):
            tag = m.group(1)
            if mod.tag_chain(tag) is None:
                continue
            key = (tag, m.group(2))
            if key in seen:
                continue
            seen.add(key)
            n += 1
            if n > mod.SPLIT_PRESENT_DECODES:
                break
            got = mod.decode(tag, m.group(2))
            if len(got) == 1:
                try:
                    p = plan_codec.flatten(got[0][0])
                except Exception:  # noqa: BLE001
                    continue
                if any(k in taken and str(p[k]) != str(taken[k]) for k in p):
                    return True
    except Exception as e:  # noqa: BLE001 - a check that fails proves nothing: answer as read
        info["notes"].append(f"the dead-text conflict check raised {type(e).__name__}: {e}")
        return False
    return False


# Day 20 gaps (script group): an array of literals changed in place before its join. plan_codec reads the
# literals of a list as they stand (`const parts = ["B64-..", "..", ".."]` and `parts.join("")` read as one piece
# of material), but live code may change the list before it is joined (`parts.splice(1, 1, "..")`,
# `parts[1] = ".."`, `parts.reverse()`, `table.insert(parts, ..)`): the value the code builds is then not the
# text as written, and the plan read from it can be an older one (the Day 19 review's `splice` shape: one
# campaign WRONG plain without the marker, 2 of 429 staged ids with `reverse_call`). A plan plan_codec read
# from a file in which live code changes a list in place is read once more with the literals of that list's
# definition blanked; when that reading does not give the same plan, the plan stood (in part) in a list the
# code changes, and none is taken. A list that only grows by push/append of literals elsewhere has no material
# of its own in its definition (`[]`): blanking it changes nothing and the plan stands.
MUTATED_LIST_GUARD = True
# How a list is changed in place, or reordered at its join, after its NAME: a method that changes it (`.splice(`,
# `.reverse()`, `.insert(`, `.Add(`, ..), an element assigned (`NAME[1] = ..`, `$NAME[] = ..`), an append operator
# (`+=`, `.=`, `<<`), a reversed read (`NAME[::-1]`); and before it, the functions that take it (`table.insert(NAME`,
# `array_splice($NAME`, `splice(@NAME`, `reversed(NAME`, `Array.Reverse(NAME`, `del NAME[`, ..)
_CHANGED_AFTER = (r"[ \t]*(?:\.[ \t]*(?:splice|reverse!?|Reverse|unshift|push|sort!?|Sort|fill|copyWithin|insert|Insert|"
                  r"append|extend|remove|Remove|RemoveAt|pop|shift|prepend|concat!|replace|clear|Clear|Add|AddRange|"
                  r"InsertRange|map!?|reject!?|rotate!?|shuffle!?|set|Set|put|delete_at|SetValue|filter|flatMap|toReversed|"
                  r"toSorted|toSpliced|with)(?!\w)"
                  r"|\[[^\]\r\n]{0,40}\][ \t]*[-+.]?=(?!=)|\[[ \t]*::[ \t]*-1[ \t]*\]|\+=|\.=|<<(?![<A-Za-z_'\"~-]))")
# B-247: an element first on the left of a tuple or destructuring assignment (`p[1], p[2] = p[2], p[1]`,
# `[p[1], p[2]] = [p[2], p[1]]`). Only where a statement starts (_statement_start), so a call's keyword argument
# (`print(p[0], end="")`) is not one.
_SWAP_AT = re.compile(r"\[[^\]\r\n]{0,40}\][ \t]*,[^=\r\n;()]{0,80}(?<![=!<>])=(?![=>])")


def _statement_start(code: str, i: int) -> bool:
    j = i - 1
    while j >= 0 and code[j] in " \t":
        j -= 1
    return j < 0 or code[j] in "\n;{["
_CHANGED_BEFORE = (r"(?:\btable\.(?:insert|remove|sort)|\barray_(?:splice|unshift|push|pop|shift|reverse)|\b(?:splice|"
                   r"unshift|push|pop|shift|reverse|reversed|sorted|rsort|ksort|krsort|usort)|\bArray\.(?:Reverse|Sort|"
                   r"Copy)|\bObject\.assign|\bdel)[ \t]*\(?[ \t]*[$@]?")
# A list that opens on a quoted run of material (one short item before it allowed: `["", "B64-.."]`), and the
# name it is assigned to on its line (`const parts = [`, `my @parts = (`, `parts := []string{`, `$p = @(`, ..)
# B-247: up to four items before the material, of any length (a long human note first was passed over).
_MATERIAL_LIST = re.compile(r"[\[({][ \t\r\n]*(?:[\"'][^\"'\r\n]{0,200}[\"'][ \t]*,[ \t\r\n]*){0,4}"
                            r"[\"'`][A-Za-z0-9+/=._:-]{16,}")
_LIST_HEAD = re.compile(r"(?<![\w.])[$@]?([A-Za-z_]\w{0,63})[ \t]*(?::[^=\r\n]{0,40})?(?<![=!<>])=(?!=)[ \t]*"
                        r"(?:\r?\n[ \t]*)?[^\"'`\r\n=;]{0,24}$")   # the bracket may open on the line after the name
_MUTATE_SITES = 32            # material lists looked at in one file
_MUTATE_SPAN = 65536          # characters of one list's definition that are blanked at most
_QUOTED = re.compile(r'"(?:[^"\\\r\n]|\\.)*"|\'(?:[^\'\\\r\n]|\\.)*\'|`[^`]*`')
_NEXT_GROUP = re.compile(r"[\w \t]*(?=[\[({])")


def _list_span(text: str, s: int):
    """(s, end) of the bracketed list that opens at text[s], with the bracket groups that follow it with only
    words or blanks between (`[]string{..}`); to _MUTATE_SPAN characters when it does not close."""
    depth, i, hi = 0, s, min(len(text), s + _MUTATE_SPAN)
    while i < hi:
        c = text[i]
        if c in "\"'`":
            q = _QUOTED.match(text, i)
            i = q.end() if q else i + 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                nxt = _NEXT_GROUP.match(text, i + 1)
                if nxt is None or nxt.end() >= hi:
                    return s, i + 1
                i = nxt.end()                       # one more bracket group of the same right-hand side
                continue
        i += 1
    return s, hi


_CHANGED_AFTER_AT = re.compile(_CHANGED_AFTER)
_CHANGED_BEFORE_AT = re.compile(_CHANGED_BEFORE + r"$")
_CHANGED_MENTIONS = 64        # mentions of one list's name looked at

# A direct mutation through a simple reference alias is still a mutation of the
# material list (`const p = parts; p.splice(...)`).  Keep this deliberately
# narrower than a language evaluator: only languages whose ordinary list/array
# assignment aliases the same mutable object, only a whole one-line assignment,
# and bounded assignment/alias counts.  This helper is withdrawal-only through
# mutated_list(); it can never make an answer plain.
_ALIAS_EXTS = frozenset({"cjs", "cs", "go", "groovy", "gs", "java", "js", "jsx", "kt", "kts", "lua",
                         "mjs", "py", "pyw", "rb", "ts", "tsx"})
_ALIAS_ASSIGN = re.compile(
    r"(?m)^[ \t]*(?:(?:const|let|var|local|val|final|auto|mutable)[ \t]+)?"
    r"(?P<lhs>[A-Za-z_]\w{0,63})"
    r"(?:[ \t]*:[ \t]*[A-Za-z_][\w.\[\]<>?|, \t]{0,80})?"
    r"[ \t]*(?::=|=(?!=))[ \t]*(?P<rhs>[^;\r\n]+?)[ \t]*;?[ \t]*(?:(?://|#).*)?$"
)
_ALIAS_NAME = re.compile(r"[A-Za-z_]\w{0,63}")
_ALIAS_EVENTS = 64
_ALIASES = 16


def _changed(code: str, name: str) -> bool:
    """Whether `code` changes the list `name` in place or reorders it: each mention of the name (found as a
    literal, at most _CHANGED_MENTIONS) is held against what follows it and what stands before it. A mention past
    the bound counts as a change (a list mentioned that often is no plain list of pieces)."""
    at, n, k = 0, len(name), 0
    while True:
        i = code.find(name, at)
        if i < 0:
            return False
        at = i + n
        prev = code[i - 1] if i else ""
        if prev.isalnum() or prev in "_." or (i + n < len(code) and (code[i + n].isalnum() or code[i + n] == "_")):
            continue                              # a longer name, or a member of something else
        k += 1
        if k > _CHANGED_MENTIONS:
            return True
        if _CHANGED_AFTER_AT.match(code, i + n) or _CHANGED_BEFORE_AT.search(code, max(0, i - 48), i):
            return True
        if _SWAP_AT.match(code, i + n) and _statement_start(code, i):
            return True
        if "=" in code[i + n:i + n + 3] and _reassigned_from_itself(code, i + n, name):
            return True


def _alias_changed(code: str, name: str, ext: str) -> bool:
    """Whether a simple, currently-bound alias of list ``name`` is changed.

    Assignments are consumed in source order.  Rebinding an alias before its
    mutation removes it, while a bounded chain (``p = parts; q = p``) remains
    live.  The original name is always checked by :func:`_changed`; this helper
    only closes the alias path and returns False for value-copy languages.
    """
    if (ext or "").lower().lstrip(".") not in _ALIAS_EXTS or name not in code:
        return False
    events = list(_ALIAS_ASSIGN.finditer(code))
    if not events:
        return False
    aliases, at = {name}, 0
    for index, event in enumerate(events):
        # Check every alias while the bindings in force before this assignment
        # still apply, including a mutation on the assignment's own line.
        piece = code[at:event.end()]
        if any(alias != name and _changed(piece, alias) for alias in aliases):
            return True
        lhs, rhs = event.group("lhs"), event.group("rhs").strip()
        if lhs != name:
            source = rhs if _ALIAS_NAME.fullmatch(rhs) else None
            if source in aliases:
                aliases.add(lhs)
                if len(aliases) > _ALIASES:
                    return True                  # too much alias state: withdraw, never guess
            else:
                aliases.discard(lhs)             # a simple rebind ended this alias
        at = event.end()
        if index + 1 >= _ALIAS_EVENTS and index + 1 < len(events):
            return len(aliases) > 1              # bounded ambiguity is withdrawal-only
    return any(alias != name and _changed(code[at:], alias) for alias in aliases)


_REASSIGN_AT = re.compile(r"[ \t]*(?<![=!<>])=(?![=>~])[^\r\n]{0,400}")


def _reassigned_from_itself(code: str, at: int, name: str) -> bool:
    """Whether the mention of `name` ending at `at` is assigned a value that is built from `name` itself on its line
    (`parts = parts[:1] + [".."] + parts[2:]`): the list the join reads is then not the one written."""
    i, n = at, len(code)
    while i < n and code[i] in " \t":
        i += 1
    if i >= n or code[i] != "=":
        return False                              # the common mention: no assignment follows
    m = _REASSIGN_AT.match(code, at)
    if m is None:
        return False
    return re.search(r"(?<![\w.$@])[$@]?" + re.escape(name) + r"(?!\w)", m.group(0)) is not None


def _material_lists(code: str, text: str, ext: str = "") -> list:
    """The quoted literals holding material (spans in `text`) of the lists assigned in `code` (at most
    _MUTATE_SITES) that `code` changes in place before their join."""
    out, n, seen = [], 0, {}
    for m in _MATERIAL_LIST.finditer(code):
        n += 1
        if n > _MUTATE_SITES:
            break
        line = code.rfind("\n", 0, m.start()) + 1
        if not code[line:m.start()].strip() and line > 0:
            line = code.rfind("\n", 0, line - 1) + 1     # `const parts =` on the line before the bracket
        head = _LIST_HEAD.search(code, max(line, m.start() - 200), m.start())
        if head is None:
            continue
        name = head.group(1)
        if name not in seen:
            seen[name] = _changed(code, name) or _alias_changed(code, name, ext)
        if not seen[name]:
            continue
        a, b = _list_span(code, m.start())
        for q in _QUOTED.finditer(text, a, b):
            if q.end() - q.start() > 2 and _MATERIAL_RUN.search(q.group(0)):
                out.append((q.start() + 1, q.end() - 1))
    return out


def changed_list_spans(text: str, ext: str) -> list:
    """The spans (in `text`) of the quoted material of the lists that live code changes in place before their join
    (_material_lists over descriptor.live_code's text, comment lines blanked); [] when there is none. Raises what
    the readers raise. Also asked by shapes_py.py, which reads a .py file's literals with its own reader."""
    ext = (ext or "").lower().lstrip(".")
    if _MATERIAL_LIST.search(text) is None or not _material_lists(text, text, ext):
        return []                                 # no changed list holds material, even counting dead text
    mod = plan_codec.optional("descriptor")
    live = mod.live_code(text, ext) if mod is not None and hasattr(mod, "live_code") else text
    lines = _LINE_COMMENTS.get(ext)
    if lines is not None:
        live = lines.sub(lambda m: " " * len(m.group(0)), live)
    return _material_lists(live, text, ext)


def mutated_list(info: dict, read_text=None) -> bool:
    """MUTATED_LIST_GUARD: whether the plan plan_codec read (its text `read_text`, by default info's plan_text)
    rests on literals of a list that live code changes in place before its join. Changes nothing in `info`;
    read() applies the verdict. Never raises; a check that fails says False (the plan as read)."""
    if read_text is None:
        read_text = info.get("plan_text")
    text, ext = info["text"], (info.get("ext") or "").lower().lstrip(".")
    try:
        spans = changed_list_spans(text, ext)
        if not spans:
            return False                          # no list live code changes holds material: the plan cannot rest on one
        blanked = list(text)
        for a, b in spans:
            blanked[a:b] = " " * (b - a)
        again_text = "".join(blanked)
        again, _ = plan_codec.reading(again_text, info.get("ext"))
        again = again or plan_codec.decode(again_text, info.get("ext"))
    except Exception as e:  # noqa: BLE001 - a check that fails proves nothing: answer as read
        info["notes"].append(f"the changed-list check raised {type(e).__name__}: {e}")
        return False
    return not (again and again[0] == read_text)


def read(name: str, data, loose_lines: bool = False, siblings=None, _nested: bool = False) -> dict:
    """Everything the text of one file gives: plan, how it decoded, label, census. `loose_lines` says the
    text's line ends are not the file's own (the strings of a binary carrier): see by_descriptor. `siblings`
    is sibling_keys() of the delivery, for a descriptor plan with fewer fields (short_format)."""
    ext = Path(name).suffix.lower()
    text = plan_codec.text_of(data)
    got, note = plan_codec.reading(text, ext)
    got = got or (None if note else plan_codec.decode(text, ext))   # the clear-text fragments, when nothing decodes
    info = {"name": name, "ext": ext, "text": text, "plan_text": got[0] if got else None,
            "how": got[1] if got else None, "transform": got[2] if got else None,
            "plan": plan_codec.flatten(got[0]) if got else {}, "label": plan_codec.label_of(text, ext),
            "census": None, "notes": [note] if note else [], "ambiguous": bool(note) and not got,
            "cut": bool(note) and bool(got), "source": "plan_codec" if got else None, "loose_lines": loose_lines,
            "siblings": siblings}
    dead = bool(DEAD_TEXT_GUARD and got and info["plan"] and dead_only(info))
    read_text = info["plan_text"]                # plan_codec's own reading, before the descriptor may cut it
    tagged = by_descriptor(info) if DESCRIPTOR else False
    # Day 28 review: several functional hosts terminate their encoded plan with
    # host grammar that plan_codec did not know, so it conservatively called the
    # literal a piece and removed its final field.  The optional reader accepts
    # only exact, complete host declarations and a complete plan grammar.  It
    # never repairs an ambiguous/dead/binary reading or a conflicting plan.
    whole = plan_codec.optional("descriptor_whole")
    if whole is not None and hasattr(whole, "reading") and not dead and not loose_lines \
            and not info.get("ambiguous") and (not info.get("plan") or info.get("cut") or info.get("one_copy")):
        try:
            descriptor_mod = plan_codec.optional("descriptor")
            settled = whole.reading(text, ext, descriptor_mod)
        except Exception as e:  # noqa: BLE001 - a supplemental witness that fails proves nothing
            info["notes"].append(f"descriptor_whole raised {type(e).__name__}: {e}")
            settled = None
        if settled:
            whole_text, whole_how, literal_count = settled
            whole_plan = plan_codec.flatten(whole_text)
            conflict_key = next((k for k, v in info.get("plan", {}).items()
                                 if k not in whole_plan or str(whole_plan[k]) != str(v)), None)
            if conflict_key is not None:
                info.update(plan={}, plan_text=None, how=None, transform=None, cut=False,
                            ambiguous=True, source=None)
                info.pop("one_copy", None)
                info["notes"].append("the grammar-bounded descriptor literal differs from the other reading on "
                                     f"{conflict_key}: neither is taken")
            else:
                rep, _, tr = whole_how.partition("|")
                info.update(plan=whole_plan, plan_text=whole_text, how=rep, transform=tr or "identity",
                            cut=False, source="descriptor", descriptor_keys=set(whole_plan))
                info.pop("one_copy", None)
                info.pop("one_copy_wrapped", None)
                # A matching tagged comment plus the bounded literal is two
                # copies.  A bounded literal alone is nevertheless whole; this
                # flag is used only by binary-carrier handling below.
                info["two_copies"] = bool("HUNTRESS_ANALYSIS" in text and literal_count)
                info["notes"].append("the plan literal is complete under its host's declaration grammar "
                                     "(descriptor_whole)")
    # B-227: what is still cut, one copy or unread is asked of the language-blind container reader, which proves a
    # container whole by its structure in any language (a join in any idiom, a concatenation chain, an escaped
    # string-literal host). Before the dead-text checks below, so they weigh its plan as any other.
    if BLIND_READER and not dead and not loose_lines:
        by_blind(info)
    if RESIDUALS and not dead and not loose_lines:
        by_residual(info)
    # asked only of a plan that is still plan_codec's own (a plan the descriptor settled is not read from a list)
    changed = bool(MUTATED_LIST_GUARD and got and info.get("plan") and not dead and info.get("source") == "plan_codec"
                   and mutated_list(info, read_text))
    verdict = DEAD_TEXT_GUARD and info.get("plan") and info.get("source") == "descriptor" and dead_descriptor(info)
    if isinstance(verdict, str) and not _settle_live(info, verdict):
        verdict = True                           # the live copies did not settle the plan after all: none is taken
    if verdict is True:
        # the descriptor's plan stands on a copy in dead text, and live code names a descriptor that says another
        # plan or nothing readable (Day 20 gaps): none is taken
        info.update(plan={}, plan_text=None, how=None, transform=None, cut=False, ambiguous=True, source=None)
        info.pop("one_copy", None)
        info["two_copies"] = False
        info["dead_text"] = True
        info["notes"].append("the descriptor's plan stands on a copy in dead text (a comment block, a comment line or "
                             "a multi-line string), and live code names a descriptor that gives another plan or none: "
                             "no plan is taken")
    conflict = bool(DEAD_TEXT_GUARD and info.get("plan") and dead_conflict(info))
    if changed and info["plan"] and info.get("source") == "plan_codec":
        # the plan plan_codec read rests on a list that live code changes in place before its join (Day 20 gaps):
        # the value the code builds is not the text as written, and none is taken
        info.update(plan={}, plan_text=None, how=None, transform=None, cut=False, ambiguous=True, source=None)
        info.pop("one_copy", None)
        info["dead_text"] = True
        info["notes"].append("the plan rests on the literals of a list that live code changes in place before "
                             "its join (splice, an element assigned, reverse, insert): no plan is taken")
    if (dead and info["plan"] and info.get("source") == "plan_codec") or (conflict and info.get("plan")):
        # the plan plan_codec read stands only in dead text (dead, source still plan_codec's), or a DIFFERENT
        # tagged plan sits in dead text beside the plan taken (conflict, row 372 b): the file holds two plans and
        # none is answered (DEAD_TEXT_GUARD)
        info.update(plan={}, plan_text=None, how=None, transform=None, cut=False, ambiguous=True, source=None)
        info.pop("one_copy", None)
        info["dead_text"] = True
        info["notes"].append("the plan stands only in dead text, or a different tagged plan sits in dead text "
                             "(a comment block, a comment line or a multi-line string) beside it: no plan is taken")
    if ENCODED_HOST and not _nested and not loose_lines and not info.get("ambiguous"):
        if encoded_host(info, name) == "differ":
            info.update(plan={}, plan_text=None, how=None, transform=None, cut=False, ambiguous=True, source=None)
            info.pop("one_copy", None)
            info["two_copies"] = False
            info["notes"].append("the file's plan and the plan of a script its base64 literal holds differ (or that "
                                 "script's own reading is two plans): no plan is taken (encoded host refused, Day 21 "
                                 "final prep)")
    if RESIDUALS and not _nested and not loose_lines and not info.get("plan") and not info.get("ambiguous"):
        by_residual(info, name, hosts=True)
    if info.get("one_copy") and isinstance(data, (bytes, bytearray)) and b"\x00" in data \
            and bytes(data[:2]) not in (b"\xff\xfe", b"\xfe\xff"):
        del info["one_copy"]                     # no text file: a line of it need not end where its text does
    if LABEL_PLAN and not tagged and (info["cut"] or not got and not note):
        by_label(info)
    if loose_lines and info["plan"] and not info.get("cut") and not info.get("two_copies"):
        # The strings of a binary carrier (review of 2026-10-08): a value ends wherever a run of printable
        # bytes does, a junk byte that happens to be printable lengthens it (`..stage` read as `..stageO`
        # behind a length prefix), and a NUL inside a quoted literal cuts it. Whatever read the plan, its
        # last value is not proven; only two copies of a descriptor that agree are (by_descriptor).
        text_ = info.get("plan_text") or ""
        if "|" in text_ and len(info["plan"]) > 1:
            info.update(plan=dict(list(info["plan"].items())[:-1]), plan_text=text_[:text_.rfind("|") + 1], cut=True)
        else:
            info.update(plan={}, plan_text=None, how=None, transform=None, ambiguous=True, source=None)
        info["notes"].append("read from the strings of a binary carrier: the plan is taken without its last field")
    found = plan_codec.labels_in(text)
    if info["label"] is None and len(found) > 1:
        info["notes"].append(f"{len(found)} codec labels that differ ({'; '.join(found[:4])}): none is taken")
    census = plan_codec.optional("census")
    if census is not None and hasattr(census, "census"):
        try:
            info["census"] = census.census(text, ext)
        except Exception as e:  # noqa: BLE001
            info["notes"].append(f"census raised {type(e).__name__}: {e}")
    return info


ADVANCED_SYNTAX = ("recognize_syntax", "reconstruct_intent")    # Day 7: the plan of an advanced-syntax specimen
ADVANCED_JUDGED = ("sh", "bash")     # where its attack was judged to be the own interpreter (script.attack/sh)

# `script.attack/<ext>` is the key of ONE fact: the own-interpreter technique of a specimen whose plan
# states no attack. On Day 12 the armed solver offered that key for every attack question of a descriptor
# specimen (the `interpreter` word test, gone above), and Layer 1 probed four of them on ONE id each, the
# benign one, whose answer is `none`: every T1059.x name is now `rejected` with scope `key` under
# script.attack/php, /lua, /mof (all twelve, so labels.pick gives None there for good) and /ts (four). The
# rows say nothing about a launcher. The ledger is append-only, so those four extensions ask their
# own-interpreter question under a key of their own from here on, and so does any descriptor specimen
# whose plan states no attack (it states one on every day so far): no descriptor specimen's attack is
# read from `script.attack/<ext>` again.
OWN_KEY_SPENT = ("php", "lua", "mof", "ts")


def own_key(ext: str, descriptor: bool = False) -> str:
    """The ledger key of an extension's own-interpreter technique."""
    if descriptor:
        return f"script.attack/{ext}.descriptor_own"
    return f"script.attack/{ext}.own_interpreter" if ext in OWN_KEY_SPENT else f"script.attack/{ext}"


# Where the words of an in-file codec label (`Codec_x = "<representation>|<transform>|<key>"`) were judged as
# the answers: the VBScript component (Days 4 to 12, 360 ids each). In every other extension the label is in
# the bytes and its word is the first candidate, but no representation or transform question was ever asked
# there (Day 13 preparation: .py, .mjs and .sh answered them plain): unsure under
# `script.<field>/<ext>.codec_label`, the method named `label`, so one accepted probe answers every later
# variant with its own label.
LABEL_JUDGED = ("vbs", "vbe")


# 2026-10-13 (Day 14 look-ahead). Field words no day asked whose value is a function of a version-3 plan's
# own step list: the list itself under another word, how many steps it holds, its first and its last step.
# Asked only when nothing else answered the id (answers(): after shapes_<ext>.py and the census), only of a
# version-3 plan that holds `steps`, never for a word
# that is a key of the plan, and never plain: `script.<asked>/<ext>.derived_<what>`, one option.
DERIVED_LIST = ("graph", "ordered-graph", "operation-graph", "step-graph")
DERIVED = {"step-count": "count", "steps-count": "count", "graph-length": "count", "number-of-steps": "count",
           "first-step": "first", "initial-step": "first", "entry-step": "first",
           "last-step": "last", "terminal-step": "last", "final-step": "last"}


def derived(q: dict, info: dict):
    try:
        plan = info.get("plan")
        if not isinstance(plan, dict) or str(plan.get("v")) != "3" or not compared(q):
            return None
        tail = tail_of(q)
        if tail.replace("-", "_") in plan or not isinstance(plan.get("steps"), str):
            return None
        steps = [s for s in steps_of(plan) if s]
        if not steps:
            return None
        ext = plan_codec.ext_name(info["ext"])
        slug = re.sub(r"[^a-z0-9_]", "_", tail.lower()).strip("_") or "field"
        if tail in DERIVED_LIST:
            # the list as the steps field would answer it under this question's format, then the lane's
            # judged form (`a>b`) and the plan's own (`a,b`): one of them is what the word asks
            options, seen = [], set()
            for name, value in (_options(q, "as_steps", answer_field({**q, "field": "steps"}, info))
                                + [("joined_gt", ">".join(steps)), ("as_plan", ",".join(steps))]):
                if value not in seen and all(name != n for n, _ in options):
                    seen.add(value)
                    options.append((name, value))
            return pick(f"script.{slug}/{ext or 'ext'}.derived_steps", options[:MAX_OPTIONS])
        what = DERIVED.get(tail)
        if what is None:
            fd = plan_codec.optional("fields_derived")   # row 492: url / composite / campaign field words
            return fd.derived(q, info) if fd is not None and hasattr(fd, "derived") else None
        value = str(len(steps)) if what == "count" else steps[0] if what == "first" else steps[-1]
        return pick(f"script.{slug}/{ext or 'ext'}.derived_{what}", [("from_steps", value)])
    except Exception:  # noqa: BLE001 - a field nobody can derive is not answered
        return None


def answer(q: dict, info: dict):
    """One question from one file's reading, before the by-name hooks. A question whose field word is an
    alias of a field, or a field with one more word (renamed), is answered as that field and sent unsure."""
    how = renamed(q, info.get("plan"))
    if how is None:
        return answer_field(q, info)
    twin = {**q, "field": how[0]}
    return reworded(q, how, answer_field(twin, info), plan_codec.ext_name(info["ext"]), info.get("plan"))


def answer_field(q: dict, info: dict):
    ext, plan, label = plan_codec.ext_name(info["ext"]), info["plan"], info["label"]
    tail = tail_of(q)
    if tail in ("representation", "transform"):
        i = 0 if tail == "representation" else 1
        if label and len(label) > i and label[i]:
            if ext in LABEL_JUDGED:
                return label[i]
            names = (representation_names(info["how"]) if i == 0 else transform_names(info["transform"])) \
                if info["how"] else []
            return pick(f"script.{tail}/{ext}.codec_label",
                        ([("label", label[i])] + [(n, n) for n in names if n != label[i]])[:MAX_OPTIONS])
        word = bare_label(info["text"]) if i == 0 else None
        if word:
            names = representation_names(info["how"]) if info["how"] else []
            return pick(f"script.representation/{ext}.codec_label",
                        ([("label", word)] + [(n, n) for n in names if n != word])[:MAX_OPTIONS])
        if not info["how"]:
            return None
        if i == 0:
            return pick(f"script.representation/{ext}.{plan_codec.how_slug(info['how'])}",
                        representation_names(info["how"]))
        return pick(f"script.transform/{ext}.{plan_codec.transform_kind(info['transform'])}",
                    transform_names(info["transform"]))
    steps = steps_of(plan)
    own = own_key(ext, bool(info.get("descriptor")))
    says = (asks_role(q) and plan.get("role")) or (asks_attack(q) and plan.get("attack"))
    if asks_attack(q) and steps == ADVANCED_SYNTAX and not says and ext in ADVANCED_JUDGED:
        # Day 7's advanced Bash ("Recover the Bash interpreter ATT&CK technique", re-worded on Day 12): the
        # script's own interpreter, under the extension's own key. Known by the plan's two analysis steps,
        # which every judged id of Days 7 to 12 has, and no longer by the word `interpreter` in the
        # question: Day 12's rubric spells out "Command and Scripting Interpreter" in every attack question.
        # Another extension with those steps is a step list judged nowhere for it: unseen(), unsure.
        return pick(own, techniques(ext))
    if steps and steps not in ROLE and (asks_role(q) or asks_attack(q)) and not says:
        return unseen(q, ext, steps, info.get("role_q"))
    got = plan_answer(q, plan, lambda: pick(own, techniques(ext)), info["notes"],
                      info.get("cut", False), ext)
    if got is None and info.get("one_copy") and not (asks_role(q) or asks_attack(q)):
        return one_copy(q, info["one_copy"], ext, bool(info.get("one_copy_wrapped")))
    return got


def one_copy(q: dict, last: tuple, ext: str, wrapped: bool = False):
    """The question that asks for the last field a descriptor's plan was taken without, answered unsure
    (Day 12 look-ahead, S2), or None when `q` asks for something else.

    by_descriptor drops the last field of a plan it read from ONE copy that something says may be a piece
    (a literal it could not read whole beside the comment, plan_codec grading that literal a piece, the next
    line reading as more of the comment). Where that copy is the tagged comment and it decoded whole to a
    plan with every field of its version (and so with a stage_count equal to its steps), the value is
    there; what is not proven is that it is whole. It goes out as
    labels.pick('script.<key>/<ext>.one_copy', [('as_read', value)]): one option, one probe on the untimed
    base, and plain from then on for that field of that extension. Never for a carrier's strings or a file
    that is no text file (read), and never for a plan with fewer fields than its version, where the last
    value is the one a cut holds cut.

    `wrapped` (Day 27, review of the variants track): the comment's next line reads as more of its payload
    (descriptor: doubt), so its last value is cut more often than not. Its pick goes under a key of its own,
    'script.<key>/<ext>.one_copy_wrapped': the name the judge accepted for an unwrapped copy of that extension
    (as_read under script.file_path/ahk.one_copy and /escript.one_copy) never answers a wrapped one plain."""
    key, value = last
    alone = plan_answer(q, {key: value}, None, None, True, ext)
    if alone is None:
        return None
    alone = formatted(q, listed(q, alone))       # as the question asks it: an option is sent as it stands
    if not isinstance(alone, str) or alone.startswith("??"):
        return None
    shape = "one_copy_wrapped" if wrapped else "one_copy"
    return pick(f"script.{re.sub(r'[^a-z0-9_]', '_', str(key).lower())}/{ext or 'ext'}.{shape}", [("as_read", alone)])


def triage(info: dict, unanswered: list):
    """The stderr block of one file. Specimen text is untrusted: it is printed escaped and cut."""
    def shown(s):
        s = s.encode("ascii", "backslashreplace").decode("ascii").replace("\n", "\\n").replace("\r", "\\r")
        return s if len(s) <= TRIAGE_WIDTH else s[:TRIAGE_WIDTH] + f"... ({len(s)} characters)"

    name, plan = info["name"], info["plan"]
    ext = plan_codec.ext_name(info["ext"]) or "ext"
    lines = [f"[generic] {name}: " + (f"plan decoded as {info['how']} | {info['transform']}"
                                      if info["plan_text"] and info.get("source") not in ("codec label", "descriptor")
                                      else "plan read by its tagged descriptor" if info.get("source") == "descriptor"
                                      else "plan read by its codec label" if info["plan_text"]
                                      else f"NO PLAN RECOVERED (two plans decode, see the note; lang_{ext}.py or "
                                           f"shapes_{ext}.py must choose)" if info.get("ambiguous")
                                      else f"NO PLAN RECOVERED (a crib or a label pattern in hooks_{ext}.py may fix that)")]
    if info["plan_text"]:
        lines.append(f"[generic]   plan: {shown(info['plan_text'])}")
    lines.append(f"[generic]   label: {shown('|'.join(info['label'])) if info['label'] else 'none'}")
    lines.append(f"[generic]   census: {info['census'] if info['census'] is not None else 'none'}")
    steps = steps_of(plan)
    if plan and steps not in ROLE:
        known = ", ".join(f".{e} {n}" for e, g, n in judged("role") if g == steps)
        lines.append(f"[generic]   steps not in the role table: {shown(','.join(steps)) or '(no steps key)'}"
                     + (f" (judged: {known})" if known else ""))
    new = [k for k in plan if k not in KNOWN_KEYS]
    if new:
        lines.append(f"[generic]   new plan keys: {shown(', '.join(map(str, new)))}")
    for note in info["notes"]:
        lines.append(f"[generic]   note: {shown(note)}")
    if unanswered:
        lines.append(f"[generic]   unanswered: {', '.join(unanswered)}")
    print("\n".join(lines), file=sys.stderr)


def find(files: dict, name):
    """The bytes of a question's member, also when the delivery lists it under a folder."""
    if not name:
        return None
    data = files.get(name)
    if data is None:
        base = name.rsplit("/", 1)[-1]
        data = next((v for k, v in files.items() if "->" not in k and k.rsplit("/", 1)[-1] == base), None)
    return data


def answers(questions, files, ctx=None):
    out, by_file = {}, {}
    for q in questions:
        by_file.setdefault(q.get("member") or (q.get("artifact") or "").split("->")[-1].strip(), []).append(q)
    for name, qs in by_file.items():
        data = find(files, name)
        if data is None:
            print(f"[generic] {name or '(no member)'}: not in the delivery, no answer for "
                  f"{', '.join(q['qid'] for q in qs)}", file=sys.stderr)
            continue
        qs = with_fields(qs)
        info = read(name, data, isinstance(ctx, dict) and name in (ctx.get("strings_views") or ()),
                    sibling_keys(files, name))
        info["role_q"] = next((q for q in qs if asks_role(q)), None)     # it lists the role names; see unseen
        if info.get("descriptor") and info["plan"]:
            lacking = sorted({DESCRIPTOR_FIELDS[tail_of(q)] for q in qs if tail_of(q) in DESCRIPTOR_FIELDS}
                             - (info.get("descriptor_keys") or set(info["plan"])))
            if lacking and info.get("short_format"):
                info["notes"].append(f"the delivery's descriptor format has no {', '.join(lacking)}: those questions "
                                     f"stay open")
            elif lacking and info.get("cut"):
                # Two identical copies cut at the same byte do not prove the
                # cut field or any later field, but every complete key=value
                # pair before it is independently present in both copies.  The
                # reader has already removed the cut pair from info["plan"].
                # Keep that proven prefix and let plan_answer leave the absent
                # fields open instead of discarding the whole specimen.
                info["notes"].append(f"the descriptor is cut before {', '.join(lacking)}: complete earlier fields "
                                     "remain established; the cut and later fields stay open")
            elif lacking:
                info["notes"].append(f"the descriptor's plan lacks {', '.join(lacking)}, which the questions ask for: "
                                     f"a cut plan, nothing is answered from it")
                info.update(plan={}, plan_text=None, how=None, transform=None, ambiguous=True, source=None,
                            one_copy=None)
        got = {}
        for q in qs:
            try:
                got[q["qid"]] = answer(q, info)
            except Exception as e:  # noqa: BLE001 - one question must not cost the file
                info["notes"].append(f"{q['qid']} raised {type(e).__name__}: {e}")
        def open_questions():
            return [q for q in qs if got.get(q["qid"]) in (None, "")]

        left = open_questions()
        ext = plan_codec.ext_name(info["ext"])
        shapes = plan_codec.optional(f"shapes_{ext}") if ext and left and not info.get("dead_text") else None
        if ext and left and info.get("dead_text"):
            # review of 9793be0: shapes_py.py reads the plan again from the whole text and answered the dropped
            # plan's role and attack from its steps table (WRONG plain); a plan dropped as dead text is not read
            # again by a shapes file (DEAD_TEXT_GUARD)
            info["notes"].append(f"shapes_{ext}.py not asked: the file's plan stood only in dead text")
        if shapes is not None and hasattr(shapes, "shapes"):
            try:
                found = shapes.shapes(info["text"], left)
                found = found if isinstance(found, dict) else {}
                got.update({q["qid"]: found[q["qid"]] for q in left if found.get(q["qid"]) is not None})
            except Exception as e:  # noqa: BLE001
                info["notes"].append(f"shapes_{ext}.shapes raised {type(e).__name__}: {e}")
        # Question by question: what shapes_<ext>.py did not answer (or all of it, if the file
        # raised) still goes to the census. A racer's file for one field must not take the
        # control answers away, or the base no longer replays to its key.
        left = [q for q in open_questions() if is_control(q)]
        census = plan_codec.optional("census") if left else None
        if census is not None and hasattr(census, "answer"):
            for q in left:
                try:
                    got[q["qid"]] = census.answer(q, info["text"], info["ext"])
                except Exception as e:  # noqa: BLE001
                    info["notes"].append(f"census.answer raised on {q['qid']}: {type(e).__name__}: {e}")
        # 2026-10-13: what is still open after the day's shapes_<ext>.py and the census is asked of derived():
        # a field that is a function of a version-3 plan's own step list, unsure only. Last, so that an
        # agent's file keeps the first word about any id.
        for q in open_questions():
            try:
                got[q["qid"]] = derived(q, info)
            except Exception as e:  # noqa: BLE001
                info["notes"].append(f"{q['qid']} raised {type(e).__name__}: {e}")
        for q in qs:
            value = got.get(q["qid"])
            if value is None or value == "":
                continue
            try:
                kept = formatted(q, listed(q, value))
            except Exception as e:  # noqa: BLE001
                kept = None
                info["notes"].append(f"{q['qid']}: the answer could not be checked against the question's list "
                                     f"({type(e).__name__}: {e}); not answered")
            if kept is None:
                info["notes"].append(f"{q['qid']}: {value if isinstance(value, str) else type(value).__name__} is not "
                                     f"among the values the question lists; not answered")
            got[q["qid"]] = kept
        got = {k: v for k, v in got.items() if v is not None and v != ""}
        out.update(got)
        triage(info, [q["qid"] for q in qs if q["qid"] not in got])
    return out


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: generic.py <specimen> [...]   (prints the triage block of each file)")
    for arg in sys.argv[1:]:
        try:
            raw = Path(arg).read_bytes()
        except OSError as e:
            print(f"{arg}: cannot be read ({e.strerror or e})", file=sys.stderr)
            continue
        seen = read(Path(arg).name, raw)
        triage(seen, [])
        role = ROLE.get(steps_of(seen["plan"]))
        print(f"{arg}: role={role} attack="
              f"{ATTACK.get(role) if role not in OWN_INTERPRETER else techniques(seen['ext'])}"
              f" adapter={seen['plan'].get('adapter')} campaign={seen['plan'].get('campaign_id')}")
