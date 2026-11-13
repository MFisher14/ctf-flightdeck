#!/usr/bin/env python3
"""Binary lane solver: hand each day's questions to the analyzer for that day's sample.

Runner entry point (tools/run.py): solve_set(questions, files, ctx).

The lane is cumulative: one evidence.zip holds a sample per day (d01 ELF, d02
C++, d03 .NET, d04 Go, ...) and question ids are prefixed with the day they
belong to (`d03_analysis_config_domain`). Each day lives in its own module next
to this file, named after the prefix (d01.py, d02.py, ...), and exposes:

    def answers(questions, files, ctx) -> dict      # {qid: answer}

where `questions` are only that prefix's questions and `files` is every file in
the delivery. Set ONLY=d03,d04 in the environment to run (and submit) just
those prefixes.

A prefix is never left without an analyzer. generic.py (headers, hashes and the
HCFG container, no code per sample type) answers it when

  - there is no module for it: a new day's sample, before dNN.py is written;
  - its module cannot be imported (a syntax error in a file written during play);
  - its module raised. One day's failure costs that day's runtime-specific
    fields, not the batch.

What generic.py cannot establish is None, and its triage block on stderr says
what the sample is. A dNN.py dropped next to this file takes over its prefix on
the next run.

Hygiene on what the day modules return. The literal `none` is an answer ("the
requested field is absent"), and d02 and d04 return it as a default for every
config or XOR field whenever they find no container. A default is a guess, so a
module's `none` is kept only where the absence can be checked here:

  - a config member, when hcfg.find decodes a container with a valid CRC-32 in
    one of the prefix's files, that container lacks the member, and some config
    in the delivery has a member of that name (the rule generic.py follows: a
    name no config carries may be a field of the container itself);
  - artifact_sha256_N, where the number of the prefix's files is the fact;
  - d01's recover_code and exported_symbol (SYMBOL_FIELDS, backlog row 323), when the question's syntax
    names the literal none for an absent field and the prefix's one ELF has no SHT_SYMTAB and exports no
    defined function: the field is absent. Day 17 judged recover_code `none` so on the stripped d01 of its
    Time Trial (v014) and Mastery (v006); kinds.py still holds a `none` asked as an integer.
    B-216 generalised the rule: any prefix's symbol-derived field (field_grammar's symbol family:
    `<x>_symbol`, `<x>_symbols`, `recover_code`, `<x>_return_value`), and an absence proven from the
    container's own tables, ELF, PE or thin Mach-O (container_symbols.py).

Any other `none` becomes None, with one stderr line. So does an answer, from
any source, that the runner could not serialize (it would cost the set every
later answer).

Who decides. A day module's None for a field it handles is a decision: it read
the sample and declined (d03.py for a CLI header that leads nowhere, for two
executables that disagree on the machine, for a hash or a config it does not
trust). No plain answer of generic.py replaces such a None. For a field the
module does not handle at all (a new question on an old sample: d04.py knows
`architecture`, not `machine`) generic.py answers what it knows. Which fields a
module handles is taken from, in this order:

  - its own handles(field), if it defines one (d03.py does);
  - LEGACY below, for d01, d02 and d04: they were written before that hook and
    are frozen, so the table says what their code decides on;
  - for any other module, the question ids in the result it returned. An id it
    leaves out is one it does not handle; an id it returns as None is a decision.

Header labels. A format, machine, ELF class, ELF type or byte order is a name
the author chose. The day modules were written before the unsure-answer contract
and answer such a name plainly whether or not the judge has ever accepted it
(d04.py says `macho` and `aarch64`; d01.py passes pyelftools' ET_DYN through).
The Windows builds turned up in a Mastery delivery only, so the next container
or CPU may too, in the one attempt that is never retried. So each header answer
of a day module is held against generic.py's reading of the same sample
(generic.py names a format by d03.py's structural rule and leaves a fact that
the prefix's executables state differently unanswered, so the two do not differ
on a fact):

  - the name has been accepted for that fact: the module's answer stands;
  - no name has ever been accepted for it: the answer becomes an unsure one, the
    module's spelling first, then generic's, and the runner probes it. Not when
    the module's name is one the judge accepted for another fact (`x86-64` where
    generic reads a RISC-V header): the two readings differ on the fact, different
    facts are never options of one key, and the module's answer is kept;
  - a frozen module (LEGACY: d01, d02, d04) gives a name the judge has never
    accepted for any fact of that kind. Those modules read these fields from the
    header and nowhere else, so the name is a spelling of what generic reads. If
    the judge has since accepted a name for that fact (it turned down `macho`
    and took `mach_o`), the accepted name is used: the module would otherwise
    repeat a rejected spelling on every later run, and no hook can replace an
    answer that is not None. If generic reads no fact at all (a machine id no
    table names, which d01.py passes through as a raw number), the answer is
    None. A module written later may mean something else by such a field and is
    left its answer; so is a spelling asked for with a probing switch (D02_PICK,
    D03_FORMAT);
  - the module left a field it handles unanswered: the None stays. The one
    exception is a fact generic reads whose name alone is unjudged (a Mach-O
    container, a RISC-V machine the module has no spelling for): generic's
    unsure answer is used, never a plain one and never a raw machine id. Once
    the judge has accepted a name for that fact, generic's reading is plain, so
    the None stays again and one stderr line says what generic reads: the
    answer then belongs in fields_<prefix>.py;
  - the module does not handle the field: generic's answer is used (plain only
    for a judged name).

What a healthy day module still leaves unanswered is offered to
fields_<prefix>.py, if that file exists (generic.hook_answers). That is the way
in for a field added to an old sample, and the way to answer what a module
declined: the day modules are frozen, the hook is a new file written for the
prefix.

The answer kind (backlog row 106). Every question states the kind of answer it
wants (answer_format: exact_text, pattern, integer, json, enum). generic.py is
handed the format with each field, so a header field asked as an integer is read
as the header's number under a key of its own (binary.elf_class/integer), never
as the name accepted for the text question. As the last step every answer of a
prefix, whoever gave it, is held against its question's kind (answer_kinds.fit):
a plain answer of another form is first asked of generic.py in the form the
question wants and otherwise left unanswered with a `FORMAT <id>` line, and an
unsure answer keeps only the options that have the form.

The rewording guard (the Day 18 look-ahead, B1). A plain list or text answer whose
question's (kind, syntax) its field was never judged under, and whose syntax asks
another form of it (omit the empty name, sorted, lower case, defanged, JSON-escaped,
...), and a plain hcfg_storage or d02 symbol answer whose question states a rule text
the judge never took, become unsure, the judged answer first (judged_forms.py, read
from judged_syntax.json). judged_forms.plan() reads the set's questions before any
prefix is solved, and holds nothing when they would put more than 6 keys or 100 ids
under the guard; demote() runs on each prefix's answers after the kind check and
before day_patch.py, so ctx["partial"] holds the guarded answers and the patch keeps
the last word.

The field catalog (backlog rows 111 and 116). What is still unanswered after the
day module, generic.py and fields_<prefix>.py is offered to field_catalog.py: a
general reader of fields a later day may ask of any sample (language marks, ELF,
PE, Mach-O, WebAssembly, DEX and archive header facts, the embedded dynamic-trace
template). Every answer of it is unsure, and it is never asked a field the day
module decides on.

The override (after Day 12). fields_<prefix>.py is offered only what is still
None, so no file written during play could replace a wrong PLAIN answer of a
shipped dNN.py or of generic.py: the lane would wait for an edit of shipped
code. If a file day_patch.py beside this one defines

    def override(q, answer, files, ctx)

it is asked about EVERY question of every prefix as the last step, with the
answer this module would return. A text it returns replaces that answer (plain,
or a labels.pick value under a binary key), the text `<<withdraw>>`
(PATCH_WITHDRAW) makes it None, and anything else leaves it: also a text that is
only white space, and an unsure value that does not parse or whose key does not
start with `binary.` (one NOTE line each). Each replacement is
one stderr line, `NOTE <id>: <old> replaced by day_patch.py (<new>)`; a patch
that does not load or raises costs nothing. Without that file, or without that
function in it, nothing here changes. day_patch_template.py is the file to copy.

Answers are copied into ctx["partial"] as each prefix finishes, so a solver
stopped by the clock still submits what is ready.

generic.py is loaded from this folder by path, under the name binary_generic:
Script Analysis has a generic.py of its own, and a process that runs both lanes
(the ladder lives in that folder) would otherwise hand one lane the other's.

Rehearsal knob: with CTF_TESTING=1, CTF_HIDE=d04,... treats those
modules as missing, which is how a rehearsal plays a known day as a new one.

covers(questions) is the runner's contract hook: it lists the question ids this
solver has no way to answer, before a clock is started.
"""
import importlib
import importlib.util
import json
import os
import re
import struct
import sys
import traceback
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env

# numpy is loaded here, with the solver, so its ~20 ms are paid before a clock: the Day 20 build's
# permutation search (generic._perm_tables, X07) and needles.py import it inside the solve, and on a delivery
# that loaded nothing else with it (Days 3 to 6) that first import was charged to the timed solve.
try:
    import numpy  # noqa: F401
except ImportError:
    pass

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import binlib
import hcfg
import members
try:  # wave3: render_candidates + override_guard wiring (a new file; loaded by path under a unique
    _rsp_spec = importlib.util.spec_from_file_location("binary_respell", HERE / "respell.py")
    _respell = importlib.util.module_from_spec(_rsp_spec)   # name, so another lane's respell.py never shadows it
    _rsp_spec.loader.exec_module(_respell)
except Exception:
    _respell = None

MODULES = HERE   # where <prefix>.py is looked for (a test points this at a temporary folder)
MODULE_NAME = re.compile(r"[a-z][a-z0-9]*")
# Files of this folder that are not day modules, whatever a question id is prefixed with.
HELPERS = {"evidence", "generic", "facts", "hcfg", "members", "binlib", "answer_kinds", "field_catalog", "static_re",
           "native_behavior",
           "trace_template", "binfmt", "judged_forms", "stated_layout", "pe_resources", "stated_define",
           "stated_collections", "sidecar_records", "hgrf_graph"}
CONFIG_FIELD = re.compile(r"analysis_(?:config_.+|xor_key_hex)")
SHA_FIELD = re.compile(r"artifact_sha256_\d+")
GENERIC = "binary_generic"   # the name generic.py is loaded under when `generic` is not this folder's
STATIC_DAY_ID = re.compile(r"^(?:set\d+\.)?d0*(\d+)(?:_|$)", re.I)
STATIC_ROUTE_DAY = re.compile(r"(?:^|[^a-z0-9])day[-_ ]*0*(\d+)(?:[^0-9]|$)", re.I)
STATIC_SINGLE_MODES = frozenset({"single", "single_solve", "standard", "standard_single_solve"})

# Importing the Day 28 collection reader pulls in the bounded ZIP/PE/ELF parsers.  Keep that cold
# cost off every older prefix whose field cannot possibly use it.  The reader still performs the
# authoritative full-text contract check after this exact, cheap field dispatch.
STATED_COLLECTION_FIELDS = frozenset({
    "structural_artifact_count", "structural_ordered_set_sha256",
    "analysis_cli_runtime", "analysis_has_decoy_branch", "analysis_d_symbol_count",
    "analysis_crystal_symbol_count", "analysis_conditional_branch_opcode_count",
    "analysis_has_gnat_runtime", "analysis_handler_symbols_sha256",
    "analysis_handler_symbol_count", "analysis_packing_key_1_hex",
    "analysis_packing_key_2_hex", "analysis_method_names_sha256",
    "analysis_config_campaign", "analysis_config_domain", "analysis_config_mutex",
    "analysis_config_url",
})
# The fields (question ids without the prefix) that the day modules written before handles() decide on,
# read off their code: d01.analyze's keys, d02.analyze's keys and its config default, d04.analyze's text
# members and the container fields it hands to hcfg.answer. A module's own handles() comes first.
LEGACY = {
    "d01": re.compile(r"artifact_sha256_\d+|analysis_(?:elf_class|machine|elf_type|endianness|section_names|symbols|"
                      r"disassembly|marker|has_symtab|exported_symbol|recover_code|entry_point)"),
    "d02": re.compile(r"artifact_sha256_\d+|analysis_(?:format|xor_key_hex|config_.+)"),
    "d04": re.compile(r"artifact_sha256_\d+|analysis_(?:xor_key_hex|config_.+|architecture|format|goarch|os|"
                      r"go_version|path|module|sample)"),
}


def module_for(q) -> str:
    return q["qid"].split("_", 1)[0].lower()


def hidden() -> set:
    """Modules $CTF_HIDE asks to treat as missing. Honoured only with CTF_TESTING=1."""
    if ctf_env.get("CTF_TESTING") != "1":
        return set()
    return {m.strip().lower() for m in ctf_env.get("CTF_HIDE", "").split(",") if m.strip()}


def load(prefix: str):
    """(module, None) for a prefix with a working day module, else (None, why generic takes it)."""
    if prefix in hidden():
        return None, "its module is hidden by CTF_HIDE"
    if (not MODULE_NAME.fullmatch(prefix) or prefix in HELPERS or prefix.startswith(("fields", "test"))
            or not (Path(MODULES) / f"{prefix}.py").is_file()):
        return None, f"there is no {prefix}.py"
    try:
        mod = importlib.import_module(prefix)
    except (Exception, SystemExit) as e:
        return None, f"{prefix}.py could not be imported ({type(e).__name__}: {e})"
    if not callable(getattr(mod, "answers", None)):
        return None, f"{prefix}.py defines no answers(questions, files, ctx)"
    return mod, None


def _same_file(mod, path: Path) -> bool:
    try:
        return Path(getattr(mod, "__file__", None) or "").resolve() == path
    except (OSError, TypeError, ValueError):
        return False


def _generic():
    """This folder's generic module, or None after one stderr line (then a prefix without a module
    stays unanswered).

    Never `import generic`: by that name Python returns whatever module was imported first, and
    solvers/script-analysis has a generic.py too. A `generic` that is already loaded from this
    folder (the lane's own tests import it that way) is used as it is."""
    path = HERE / "generic.py"
    for name in ("generic", GENERIC):
        mod = sys.modules.get(name)
        if mod is not None and _same_file(mod, path) and callable(getattr(mod, "answers", None)):
            return mod
    try:
        spec = importlib.util.spec_from_file_location(GENERIC, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[GENERIC] = mod
        spec.loader.exec_module(mod)
        return mod
    except (Exception, SystemExit) as e:
        sys.modules.pop(GENERIC, None)
        print(f"[evidence] generic.py could not be imported ({type(e).__name__}: {e})", file=sys.stderr)
        return None


def by_generic(prefix: str, qs: list, files: dict, ctx) -> dict:
    return by_generic_decided(prefix, qs, files, ctx)[0]


def by_generic_decided(prefix: str, qs: list, files: dict, ctx) -> tuple:
    """(generic's answers, the ids it left None ON PURPOSE: generic.decided_ids). The generic path passes the
    second to closing() as `withheld`, as the day-module path passes withheld_ids(), so speed_filled() never
    undoes a never-guess None of generic's (B-216 fix round 2). Generic absent or raising decides nothing."""
    gen = _generic()
    if gen is None:
        return {}, frozenset()
    try:
        got, why = gen.answers_with_reasons(prefix, qs, files, ctx)
        got = dict(got) if isinstance(got, dict) else {}
        return got, gen.decided_ids(got, why if isinstance(why, dict) else {})
    except (Exception, SystemExit):
        print(f"[evidence] generic raised on {prefix}; its {len(qs)} question(s) stay unanswered:\n"
              f"{traceback.format_exc()}", file=sys.stderr)
        return {}, frozenset()


def container_of(prefix: str, files: dict, ctx):
    """The config hcfg.find decodes in one of the prefix's files (a CRC-valid one first), or None."""
    found = None
    try:
        pool = members.day_members(files, ctx or {}, prefix)
        day = re.fullmatch(r"d0*(\d+)", prefix)
        if not pool and day:
            pool = binlib.day_files(files, int(day.group(1)))   # the Day 1-2 naming, dayNN-*
        # Same result as hcfg.find, without its key-by-key search on a file that holds no config.
        find = getattr(_generic(), "find_config", hcfg.find)
        for _, data in pool:
            cfg = find(data)
            if cfg and cfg["crc_ok"]:
                return cfg
            found = found or cfg
    except Exception as e:
        print(f"[evidence] {prefix}: looking for its container raised {type(e).__name__}: {e}", file=sys.stderr)
    return found


def _field(qid: str) -> str:
    return qid.split("_", 1)[-1]


def _formats(qs: list) -> dict:
    """{field: answer_format} of the questions that state one (row 106)."""
    return {_field(q["qid"]): q["answer_format"] for q in qs if isinstance(q.get("answer_format"), dict)}


NONE_SENTENCE = "use the literal none only when the requested field is absent"
# Backlog row 323: d01.py's fields that a symbol table alone gives (the designated function and the constant
# it returns). On a build with no symbol table they are absent, and the judge took the literal none for
# recover_code on the Day 17 Time Trial (d01 v014) and in every set of its Mastery (d01 v006), both stripped.
SYMBOL_FIELDS = {"d01": ("analysis_recover_code", "analysis_exported_symbol")}


def _permits_absent_none(syntax) -> bool:
    """Whether a question's answer-format syntax permits the literal `none` for an absent field. Day 17
    phrased it `use the literal none only when the requested field is absent`; Day 19's d01 reword was
    `unsigned base-10 integer, or the literal token none when the recover_code FUNC symbol is absent`.
    Both name the literal none and tie it to the field (or its symbol) being absent, which is the only
    shape this keeps a module's `none` for; the absence itself is still proven from the bytes below."""
    s = str(syntax or "").lower()
    return NONE_SENTENCE in s or ("literal" in s and "none" in s and "absent" in s)


def symbol_field(prefix: str, qid: str) -> bool:
    """Whether a field is symbol-derived: SYMBOL_FIELDS for its prefix, or (B-216) any id the field grammar
    reads as the symbol family's name, list or value (`<x>_symbol`, `<x>_symbols`, `recover_code`,
    `<x>_return_value`), on any prefix. Presence and count ids are facts, not absences, and are not."""
    if _field(qid) in SYMBOL_FIELDS.get(prefix, ()):
        return True
    try:
        import field_grammar
        fid = field_grammar.parse(qid)
    except Exception as e:
        print(f"[evidence] {qid}: the field grammar raised {type(e).__name__}: {e}", file=sys.stderr)
        return False
    return fid.family == "symbol" and fid.attr in ("name", "list", "value")


def symbols_absent(prefix: str, q: dict, files: dict, ctx) -> bool:
    """Whether a `none` of a symbol-derived field (symbol_field) is the absence the question allows: its
    syntax names the literal none for an absent field, and the prefix's one image (one distinct ELF, PE or
    thin Mach-O body) proves that no symbol table names a function (container_symbols.absent: ELF, no
    SHT_SYMTAB and no defined .dynsym function; PE, no COFF symbol table and no export; Mach-O, no LC_SYMTAB
    entry). Anything else: False. Row 323 proved it for d01's ELF; B-216 keys it on the container."""
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    if not symbol_field(prefix, q["qid"]) or not _permits_absent_none(fmt.get("syntax")):
        return False
    try:
        import container_symbols
        pool = members.day_members(files, ctx or {}, prefix)
        day = re.fullmatch(r"d0*(\d+)", prefix)
        if not pool and day:
            pool = binlib.day_files(files, int(day.group(1)))
        bodies = {bytes(data) for _, data in pool if isinstance(data, (bytes, bytearray))
                  and container_symbols.container_of(bytes(data[:4]))}
        if len(bodies) != 1:
            return False
        proven, _ = container_symbols.absent(next(iter(bodies)))
        return proven
    except Exception as e:
        print(f"[evidence] {q['qid']}: reading the symbol tables raised {type(e).__name__}: {e}", file=sys.stderr)
        return False


def hygiene(prefix: str, qs: list, got: dict, files: dict, ctx) -> dict:
    """Turn a `none` a day module cannot stand behind into None: see the module docstring."""
    proven = ctx.get("proven_none", ()) if isinstance(ctx, dict) else ()
    suspects =[q["qid"] for q in qs if got.get(q["qid"]) == "none" and not SHA_FIELD.fullmatch(_field(q["qid"]))
               and q["qid"] not in proven]
    if not suspects:
        return got
    cfg, names = None, None
    if any(CONFIG_FIELD.fullmatch(_field(qid)) for qid in suspects):
        cfg = container_of(prefix, files, ctx)
    by_id = {q["qid"]: q for q in qs}
    for qid in suspects:
        field = _field(qid)
        name = field[len("analysis_config_"):]
        if symbol_field(prefix, qid) and symbols_absent(prefix, by_id[qid], files, ctx):
            print(f"[evidence] {qid}: {prefix}.py answered the literal none: the image has no symbol table, so the "
                  "field is absent, as its syntax allows (row 323, B-216)", file=sys.stderr)
            continue
        if not CONFIG_FIELD.fullmatch(field):
            why = "only a config member or a file can be absent, and this is neither"
        elif cfg is None:
            why = f"no HCFG container decodes in a file named {prefix}*"
        elif field == "analysis_xor_key_hex" or name == "crc32_hex" or cfg["json"].get(name) is not None:
            why = "the decoded container does carry that field"
        elif name in cfg["json"]:
            why = "that member of the decoded config is JSON null: neither a value nor absent"
        elif not cfg["crc_ok"]:
            why = "the container that lacks the member does not pass its CRC-32"
        else:
            if names is None:
                gen = _generic()
                try:
                    names = set(gen.member_names(files)) if gen is not None else set()
                except Exception as e:
                    names = set()
                    print(f"[evidence] {prefix}: listing the delivery's config members raised {type(e).__name__}: {e}",
                          file=sys.stderr)
            if name in names:
                continue  # a valid container, the member is absent, the name is a member elsewhere: `none`
            why = ("no config in the delivery has a member of that name, so it cannot be told from a field of "
                   "the container itself")
        got[qid] = None
        print(f"[evidence] {qid}: {prefix}.py answered the literal none, but {why}; left unanswered", file=sys.stderr)
    return got


def handles(prefix: str, mod, qid: str, got: dict) -> bool:
    """Whether the day module decides on the field of `qid`, so that a None from it is a decision:
    see "Who decides" in the module docstring. `got` is the result the module returned."""
    field = _field(qid)
    hook = getattr(mod, "handles", None)
    if callable(hook):
        try:
            return bool(hook(field))
        except Exception as e:
            print(f"[evidence] {prefix}: {prefix}.handles({field!r}) raised {type(e).__name__}: {e}; the field is "
                  "taken as handled", file=sys.stderr)
            return True
    if prefix in LEGACY:
        return bool(LEGACY[prefix].fullmatch(field))
    return qid in got


def by_hand(prefix: str) -> str:
    """The name of a hand-probing switch of this prefix's module that is set (D02_PICK, D03_FORMAT), or ''.
    Such a switch makes the module answer a spelling on purpose, and tools/lanes.py removes it from every
    gate replay and timed run."""
    return next((name for name in (f"{prefix.upper()}_PICK", f"{prefix.upper()}_FORMAT") if os.environ.get(name)), "")


def header_labels(prefix: str, qs: list, got: dict, files: dict, ctx, decided=None) -> dict:
    """Hold a day module's header answers against generic's: see "Header labels" in the module docstring.
    `decided` holds the question ids the module handles; without it every one counts as handled."""
    gen = _generic()
    asked = [q["qid"] for q in qs if gen is not None and _field(q["qid"]) in gen.HEADER_FIELDS]
    if not asked:
        return got
    try:
        view = gen.header_answers(prefix, [_field(qid) for qid in asked], files, ctx, _formats(qs))
        switch = by_hand(prefix)
        for qid in asked:
            mine, theirs = got.get(qid), view.get(_field(qid))
            if gen.labels.is_unsure(mine):
                continue   # the module already said how sure it is
            if mine is None:
                if theirs is None:
                    continue
                unsure = gen.labels.is_unsure(theirs)
                if not unsure and (decided is None or qid in decided):
                    print(f"[evidence] {qid}: {prefix}.py left it unanswered, a decision for a field it handles; "
                          f"generic reads {theirs!r} from the header, and a plain answer does not replace the "
                          f"module's None (fields_{prefix}.py can answer it)", file=sys.stderr)
                    continue
                got[qid] = theirs
                print(f"[evidence] {qid}: {prefix}.py left it unanswered; the header gives "
                      f"{'an unsure answer' if unsure else repr(theirs)}", file=sys.stderr)
                continue
            # Whether the judge has ever accepted the module's name for a fact of this kind (elf, pe, pe_cli;
            # x86-64, i386; ...). `raw`: a frozen module's name that it has not (a raw machine id, pyelftools'
            # EM_BPF, a spelling the judge turned down in favour of another). Those modules read these fields
            # from the header and nowhere else, so such a name is not a plain answer. A module written later
            # may mean something else by the field and is trusted with its own answer, and so is the
            # player's probing switch, which asks for exactly that spelling.
            judged = gen.judged(_field(qid), mine)
            raw = prefix in LEGACY and not judged and not switch
            if theirs is None:
                if raw:   # generic has no reading to probe it under, so there is nothing to offer
                    got[qid] = None
                    print(f"[evidence] {qid}: {prefix}.py answers {mine!r}, a name the judge has never accepted, and "
                          f"generic reads no such fact from the header to probe it under; left unanswered "
                          f"(fields_{prefix}.py can answer it)", file=sys.stderr)
            elif not gen.labels.is_unsure(theirs):
                if mine == theirs:
                    continue
                if not raw:
                    print(f"[evidence] {qid}: {prefix}.py answers {mine!r} where generic reads {theirs!r} from the "
                          f"header; {prefix}.py's answer is kept", file=sys.stderr)
                    continue
                # The judge has accepted `theirs` for the fact the prefix's executables state, and the module
                # names the same header under a spelling that was never accepted: the judged name is the answer.
                got[qid] = theirs
                print(f"[evidence] {qid}: {prefix}.py answers {mine!r}, a name the judge has never accepted; "
                      f"{theirs!r} is the accepted name of what generic reads from the header, and it is used",
                      file=sys.stderr)
            else:
                parsed = gen.labels.parse(theirs)
                if parsed is None or not parsed.key or gen.labels.state(parsed.key)["accepted_names"]:
                    continue   # a name was accepted for this fact once (the key is split): leave the module alone
                if judged and not switch:
                    # Accepted for another fact (x86-64 where generic reads a RISC-V header): the two readings
                    # differ on the fact, and different facts are never options of one key.
                    print(f"[evidence] {qid}: {prefix}.py answers {mine!r}, a name accepted for another fact, where "
                          f"generic reads {parsed.key} from the header; {prefix}.py's answer is kept", file=sys.stderr)
                    continue
                if not isinstance(mine, str) or not mine:
                    got[qid] = theirs   # not a name at all: generic's spellings alone
                else:
                    got[qid] = gen.labels.pick(parsed.key, [mine] + [n for n in parsed.names if n != mine])
                print(f"[evidence] {qid}: {prefix}.py answers {mine!r}, but no name has been accepted for "
                      f"{parsed.key}; made an unsure answer", file=sys.stderr)
    except Exception as e:
        print(f"[evidence] {prefix}: checking its header answers raised {type(e).__name__}: {e}; they stand as "
              f"{prefix}.py gave them", file=sys.stderr)
    return got


def unhandled(prefix: str, qs: list, got: dict, files: dict, ctx, decided) -> dict:
    """Let generic answer the questions the day module does not handle (a hash or a container field
    asked of a sample whose module knows neither). The header fields were dealt with by header_labels."""
    gen = _generic()
    if gen is None:
        return got
    try:
        asked = [q["qid"] for q in qs if got.get(q["qid"]) is None and q["qid"] not in decided
                 and gen.knows(_field(q["qid"])) and _field(q["qid"]) not in gen.HEADER_FIELDS]
        view = gen.known_answers(prefix, [_field(qid) for qid in asked], files, ctx, _formats(qs)) if asked else {}
    except (Exception, SystemExit) as e:
        print(f"[evidence] {prefix}: asking generic about the fields {prefix}.py does not handle raised "
              f"{type(e).__name__}: {e}; they stay unanswered", file=sys.stderr)
        return got
    for qid in asked:
        if view.get(_field(qid)) is not None:
            got[qid] = view[_field(qid)]
            print(f"[evidence] {qid}: {prefix}.py does not handle this field; generic answers it", file=sys.stderr)
    return got


def from_hook(prefix: str, qs: list, got: dict, files: dict, ctx) -> dict:
    """Offer the questions a healthy day module left unanswered to fields_<prefix>.py, if it exists."""
    open_qs = [q for q in qs if got.get(q["qid"]) is None]
    if not open_qs:
        return got
    gen = _generic()
    if gen is None:
        return got
    try:
        more = gen.hook_answers(prefix, open_qs, files, ctx)
        more = {q["qid"]: more[q["qid"]] for q in open_qs if isinstance(more, dict) and more.get(q["qid"]) is not None}
    except (Exception, SystemExit):
        print(f"[evidence] {prefix}: asking fields_{prefix}.py raised; its answers are not used:\n"
              f"{traceback.format_exc()}", file=sys.stderr)
        return got
    if more:
        print(f"[evidence] {prefix}: fields_{prefix}.py answers {len(more)} of the {len(open_qs)} question(s) "
              f"{prefix}.py left unanswered ({', '.join(more)})", file=sys.stderr)
        got.update(more)
    return got


def hook_override(prefix: str, qs: list, got: dict, files: dict, ctx) -> dict:
    """Let fields_<prefix>.py's optional override() REPLACE an UNSURE answer with a CRC-verified PLAIN value.
    The Day 31 HGAU fold: generic reads the d31 config WITHOUT CRC verification (it does not recognize the
    HGAU magic) and offers an unsure pick under binary.config_member/uncrc+exact_text; the CRC-valid HGAU
    record read in fields_d31.override() answers those ids plain, deterministically from the member bytes.
    Only an UNSURE current answer is replaced, and only by a PLAIN (non-unsure) string; a judge-accepted
    plain answer and a None answer are never touched, and a prefix whose hook ships no override() is
    unchanged (hook_override_answers returns {}). This is the shipped equivalent of the morning
    day_patch.override(), so the config ids no longer depend on the removed uncrc seed or the ledger."""
    gen = _generic()
    if gen is None:
        return got
    unsure = [q for q in qs if isinstance(got.get(q["qid"]), str) and gen.labels.is_unsure(got[q["qid"]])]
    if not unsure:
        return got
    try:
        more = gen.hook_override_answers(prefix, unsure, files, ctx)
    except (Exception, SystemExit):
        print(f"[evidence] {prefix}: asking fields_{prefix}.py override raised; its answers are not used:\n"
              f"{traceback.format_exc()}", file=sys.stderr)
        return got
    for qid, value in (more or {}).items():
        if (isinstance(value, str) and value and not gen.labels.is_unsure(value)
                and gen.labels.is_unsure(got.get(qid, ""))):
            print(f"[evidence] {qid}: generic's unsure answer ({str(got[qid])[:60]}) replaced by "
                  f"fields_{prefix}.py override (CRC-verified plain: {str(value)[:60]})", file=sys.stderr)
            got[qid] = value
    return got


def key_agrees(prefix: str, qs: list, got: dict, files: dict, ctx) -> dict:
    """A day module's XOR key that differs from the key of the CRC-valid container generic.py reads
    for the prefix is not established and becomes None. d04.py reads a bare XOR-ed JSON object when
    the container's header is not legible as it stands (the whole container under one more XOR
    byte: tests/variants.py's xor_byte) and answers the byte that decodes it, where the container's
    own header, read beneath the layer, states another."""
    qid = next((q["qid"] for q in qs if _field(q["qid"]) == "analysis_xor_key_hex"), None)
    mine = got.get(qid) if qid else None
    gen = _generic()
    if not isinstance(mine, str) or gen is None or gen.labels.is_unsure(mine) or mine == "none":
        return got
    try:
        members = gen.members_of(prefix, files, ctx)
        cfg = gen.pick_sample(members, gen.day_of(prefix))[2] if members else None
        if cfg and cfg.get("crc_ok") and cfg.get("version") is not None and cfg.get("how", "xor") == "xor" \
                and mine != f"0x{cfg['key']:02x}":
            got[qid] = None
            print(f"[evidence] {qid}: {prefix}.py answers {mine}, and the CRC-valid container generic reads for the "
                  f"prefix states key 0x{cfg['key']:02x}: not established, left unanswered", file=sys.stderr)
    except Exception as e:
        print(f"[evidence] {prefix}: holding its XOR key against the container raised {type(e).__name__}: {e}; it "
              "stands as it was", file=sys.stderr)
    return got


_MISSING = object()


def config_members_unsure(prefix: str, qs: list, got: dict, files: dict, ctx) -> dict:
    """A day module that renders a NON-string config member plainly sends a spelling the judge has never
    judged: every config member the judge took (Days 2 to 13) is a non-empty string, and the Day 14
    look-ahead (proposal 2, generic.config_answer) makes any other member type unsure. d03.py and d05.py
    do that themselves; the frozen LEGACY d02.py (`binlib.compact`) and d04.py (`hcfg.answer`) still send
    a list, number, bool, JSON null or empty string as a plain guessed rendering, which sinks the
    all-or-nothing batch.

    Hold a day module's PLAIN config-member answer against the decoded container: when the member of that
    name is present and is not a non-empty string, replace it with generic.config_answer's unsure answer
    (the `binary.config_member/<type>+<kind>` pick, or None). A member that is a non-empty string is left
    exactly as the module gave it, so every saved answer (all non-empty strings) is untouched. The member
    type is read from the bytes, never guessed, so nothing wrong can be introduced."""
    suspects = [q for q in qs if isinstance(got.get(q["qid"]), str) and not got[q["qid"]].startswith("??")
                and _field(q["qid"]).startswith("analysis_config_") and _field(q["qid"]) != "analysis_config_crc32_hex"]
    if not suspects:
        return got
    gen = _generic()
    if gen is None:
        return got
    cfg = container_of(prefix, files, ctx)
    if cfg is None or not isinstance(cfg.get("json"), dict):
        return got
    fmts = _formats(qs)
    for q in suspects:
        qid, field = q["qid"], _field(q["qid"])
        name = field[len("analysis_config_"):]
        member = cfg["json"].get(name, _MISSING)
        if member is _MISSING or (isinstance(member, str) and member != ""):
            continue   # absent (its `none` is hygiene's), or the judged shape (a non-empty string): untouched
        try:
            new, _why = gen.config_answer(field, cfg, lambda: set(), fmt=fmts.get(field))
        except Exception as e:
            print(f"[evidence] {qid}: re-reading the config member against generic raised {type(e).__name__}: {e}; "
                  "the module's answer stands", file=sys.stderr)
            continue
        if new != got[qid]:
            what = type(member).__name__ if member != "" else "empty string"
            print(f"[evidence] {qid}: {prefix}.py rendered a non-string config member ({what}) plainly, but the "
                  f"judge has judged only non-empty-string members; generic's unsure answer is used", file=sys.stderr)
            got[qid] = new
    return got


def config_decoy_guard(prefix: str, qs: list, got: dict, files: dict, ctx) -> dict:
    """Hold a day module's PLAIN config answer against the robust generic reader, and never let a decoy,
    an envelope or a stale CRC make it a wrong plain (the never-wrong bright line).

    The old day modules choose their HCFG container with a selector that is weaker than generic's:
    d02.py and d04.py take the FIRST CRC-valid container in file order (hcfg.find / their own first-CRC
    scan) with no (day, variant) matching, so a CRC-valid decoy of another day placed before the real one
    is read; d03_container.py and d05.py scan only raw and base64, so a real container wrapped in a
    compression envelope (gzip/zlib/xz/lzma/bz2) is not even a candidate and a raw/base64 decoy wins; and
    d03_container.py is not CRC-gated, so a container whose stored CRC-32 does not match its decoded JSON
    still emits config members plain. generic._choose_config peels the envelopes, is CRC-gated, and tells a
    decoy from the sample's own container by the day/variant (fits / _names_day), never by file position
    (d06+ defer config to generic already; this guard also protects a future dNN module written the old
    way). xor_key_hex is already held by key_agrees(); here we hold the config members and crc32_hex.

    For each such id the module answered PLAIN, read the prefix's config with generic.choose_config and
    answer the field with generic.config_answer. When generic's answer differs from the module's plain
    (a decoy or stale-CRC container was read), replace it with generic's answer: the correct plain value
    when generic recovers the real container, an unsure labels.pick, or None when the robust reader cannot
    establish the container. A field generic reads identically is left exactly as the module gave it, so
    every clean saved attempt (where generic reads the same real container) replays byte-identical. It
    RESTRICTS plain only and reads the replacement from the bytes, so nothing wrong can be introduced."""
    suspects = [q for q in qs if isinstance(got.get(q["qid"]), str) and got[q["qid"]]
                and not got[q["qid"]].startswith("??")
                and _field(q["qid"]).startswith("analysis_config_")]
    if not suspects:
        return got
    gen = _generic()
    if gen is None or not callable(getattr(gen, "choose_config", None)):
        return got
    fmts = _formats(qs)
    try:
        pool = gen.members_of(prefix, files, ctx)
        cfg, _at, declined = gen.choose_config(pool, gen.day_of(prefix)) if pool else (None, None, "")
    except Exception as e:
        print(f"[evidence] {prefix}: the robust container read for the decoy guard raised {type(e).__name__}: {e}; "
              "the module's config answers stand", file=sys.stderr)
        return got
    names = {}   # memoised member-name set; computed only if config_answer asks (an absent member)

    def known():
        if "set" not in names:
            try:
                names["set"] = set(gen.member_names(files))
            except Exception:
                names["set"] = set()
        return names["set"]

    for q in suspects:
        qid, field = q["qid"], _field(q["qid"])
        try:
            new, why = gen.config_answer(field, cfg, known, declined or "", fmt=fmts.get(field))
        except Exception as e:
            print(f"[evidence] {qid}: re-reading its config field against the robust reader raised "
                  f"{type(e).__name__}: {e}; the module's answer stands", file=sys.stderr)
            continue
        if new == got[qid]:
            continue   # the robust reader agrees: the clean case, and every saved attempt
        kind = ("an unsure answer" if gen.labels.is_unsure(new) else "nothing" if new is None else repr(new))
        print(f"[evidence] {qid}: {prefix}.py answered {got[qid]!r} plain, but the robust reader (envelope- and "
              f"decoy-resistant, CRC-gated) reads {kind} ({why or 'a different container'}); the module's plain "
              "answer is not established and is replaced (never-wrong guard)", file=sys.stderr)
        got[qid] = new
    return got


def from_catalog(prefix: str, qs: list, got: dict, files: dict, ctx, decided=()) -> dict:
    """Offer what is still unanswered to field_catalog.py (rows 111 and 116), except the fields the day
    module decides on: its None there is a decision, and only a file written for the prefix overrides it."""
    open_qs = [q for q in qs if got.get(q["qid"]) is None and q["qid"] not in decided]
    gen = _generic()
    if not open_qs or gen is None or not callable(getattr(gen, "catalog_answers", None)):
        return got
    try:
        more = gen.catalog_answers(prefix, open_qs, files, ctx)
        more = {q["qid"]: more[q["qid"]] for q in open_qs if isinstance(more, dict) and more.get(q["qid"]) is not None}
    except (Exception, SystemExit):
        print(f"[evidence] {prefix}: asking field_catalog.py raised; its answers are not used:\n"
              f"{traceback.format_exc()}", file=sys.stderr)
        return got
    if more:
        print(f"[evidence] {prefix}: field_catalog.py offers {len(more)} unsure answer(s) for what was left "
              f"unanswered ({', '.join(more)})", file=sys.stderr)
        got.update(more)
    return got


def kind_fit(prefix: str, qs: list, got: dict, files: dict, ctx) -> dict:
    """Hold every answer of the prefix against the kind its question asks for (row 106): see "The answer
    kind" in the module docstring. CTF_KINDS=off, the escape of the runners' own kind check
    (tools/kinds.py), turns this one off too: an agent who has seen a syntax text misread needs one
    switch, not two."""
    if ctf_env.get("CTF_KINDS", "").strip().lower() in ("off", "0", "no", "false"):
        return got
    gen = _generic()
    if gen is None or not callable(getattr(gen, "fit", None)):
        return got
    formats = _formats(qs)
    for q in qs:
        qid = q["qid"]
        fmt = formats.get(_field(qid))
        if got.get(qid) is None or fmt is None:
            continue
        try:
            # The Day 14 look-ahead, proposal 1: a hex, digest or offset answer under a (kind, syntax) its
            # field was never judged under is unsure (answer_kinds.reform, judged_syntax.json).
            reform = getattr(getattr(gen, "answer_kinds", None), "reform", None)
            other, why = reform(_field(qid), got[qid], fmt) if callable(reform) else (None, "")
            if other is not None and other != got[qid]:
                got[qid] = other
                print(f"[evidence] FORMAT {qid}: {why}; the answer is unsure, the form the text asks first",
                      file=sys.stderr)
                continue
            fitted, changed = gen.fit(got[qid], fmt)
            if not changed:
                continue
            if fitted is None and gen.knows(_field(qid)):
                # The same fact in the form the question asks for, when generic.py reads it (an ELF class
                # asked as an integer of a sample whose module answers `ELF64`).
                fitted = gen.known_answers(prefix, [_field(qid)], files, ctx, formats).get(_field(qid))
                if fitted is not None:
                    changed += "; generic.py answers it in the form asked"
            got[qid] = fitted
            print(f"[evidence] FORMAT {qid}: {changed}{'' if fitted is not None else '; left unanswered'}",
                  file=sys.stderr)
        except Exception as e:
            print(f"[evidence] {qid}: holding it against its answer kind raised {type(e).__name__}: {e}; it stands "
                  "as it was", file=sys.stderr)
    return got


def buried_config(prefix: str, qs: list, got: dict, files: dict, ctx) -> dict:
    """Config fields a day module left None while no container stands in the prefix's files as they are:
    the module never saw a config, so its None declines nothing, and generic.py's search beneath the
    files (zip members, zlib, base64, hex, a one-byte XOR; CRC-checked) may answer them. A module that saw
    a container and declined keeps its None. (2026-10-06, tests/variants.py: d02-d05 left every config
    id unanswered when the container was packed.)"""
    open_qs = [q for q in qs if got.get(q["qid"]) is None and CONFIG_FIELD.fullmatch(_field(q["qid"]))]
    if not open_qs or container_of(prefix, files, ctx) is not None:
        return got
    more = {qid: v for qid, v in by_generic(prefix, open_qs, files, ctx).items()
            if isinstance(v, str) and v and not v.startswith("??")}
    if more:
        print(f"[evidence] {prefix}: no container in its files as they are; generic reads one beneath them and "
              f"answers {len(more)} config id(s) {prefix}.py left unanswered", file=sys.stderr)
        got.update(more)
    return got


def role_filled(prefix: str, qs: list, got: dict, files: dict, ctx) -> dict:
    """Answer the dNN_analysis_<build>_<field> ids a prefix delivered as several builds side by side
    carries (row 307), from the one build each id names, through generic.role_answers. Only ids still
    None are filled; a build word that names no file or more than one distinct body stays None, and an
    id that is not a build id is untouched (generic answered it as before). It reads the whole delivery
    (`files`), so it is asked here, where the dispatcher sees it, before fields_<prefix>.py and the
    catalog."""
    gen = _generic()
    if gen is None or not callable(getattr(gen, "role_answers", None)):
        return got
    open_qs = [q for q in qs if got.get(q["qid"]) is None]
    if not open_qs:
        return got
    try:
        more = gen.role_answers(prefix, open_qs, files, ctx)
    except (Exception, SystemExit):
        print(f"[evidence] {prefix}: asking generic.role_answers raised; its answers are not used:\n"
              f"{traceback.format_exc()}", file=sys.stderr)
        return got
    for qid, value in (more or {}).items():
        if value is not None and got.get(qid) is None:
            got[qid] = value
            print(f"[evidence] {qid}: answered from the build its id names (row 307)", file=sys.stderr)
    return got


def stated(prefix: str, qs: list, got: dict, files: dict, ctx) -> dict:
    """The Day 21 look-ahead (L1): what stated_layout.py settles from the wrapper the prefix's own questions
    state ("Find the final <MAGIC> overlay. Read ... u32le at +8 ..."): ids still None of the new structural
    fields as unsure picks, config ids still None from the stated record, and a plain config answer read from
    ANOTHER record than the stated one made unsure (the stated value first). Asked last, before the kind check,
    after the day module, generic, fields_<prefix>.py and the catalog, so it never replaces their answers but in
    that one case. A prefix whose questions state no wrapper costs one regular-expression pass over its texts;
    one that raises costs nothing."""
    try:
        import stated_layout
    except Exception as e:
        print(f"[evidence] stated_layout.py could not be imported ({type(e).__name__}: {e})", file=sys.stderr)
        return got
    try:
        if stated_layout.spec_of(qs) is None:
            return got
        gen = _generic()
        if gen is None:
            return got
        # (only the prefix's own names are handed on: members_of scans every name of the delivery, ~7 ms on a
        # Mastery set of 15,000 names, for what a prefix test of the basename narrows first)
        pre = prefix.lower()
        mine = {n: files[n] for n in files if " -> " not in n and n.rsplit("/", 1)[-1][:len(pre)].lower() == pre}
        more = stated_layout.answers(prefix, qs, got, gen.members_of(prefix, mine or files, ctx), gen)
    except (Exception, SystemExit):
        print(f"[evidence] {prefix}: stated_layout.py raised; its answers are not used:\n{traceback.format_exc()}",
              file=sys.stderr)
        return got
    got.update(more)
    return got


DEFINE_TRIGGER = re.compile(r"entropy|ror-?13|fnv|djb2|sdbm|crc-?32|md5|sha-?1|sha-?256|number of|count|how many|"
                            r"\bat (?:file |byte )?offset\b", re.I)


def defined(prefix: str, qs: list, got: dict, files: dict, ctx) -> dict:
    """The Day 21 build, round 4 (row 422): an id still None of a header field no rule defines, whose question
    states how its value is computed (a count of X in table Y, a named hash of a stated input, the entropy of a
    named section in bits per byte to N decimals, a typed read at a stated offset), gets that value computed from
    the bytes as a ONE-option pick under binary.stated_define/<the definition> (stated_define.py); no stated
    definition, None as before. Asked after stated() and before trailer(). Costs one regular-expression test per
    id still None; one that raises costs nothing."""
    open_qs = [q for q in qs if got.get(q["qid"]) is None and DEFINE_TRIGGER.search(q.get("question") or "")]
    if not open_qs:
        return got
    try:
        import stated_define
        gen = _generic()
        open_qs = [q for q in open_qs if stated_define.asks(_field(q["qid"]), gen)]
        if not open_qs or gen is None:
            return got
        pre = prefix.lower()
        mine = {n: files[n] for n in files if " -> " not in n and n.rsplit("/", 1)[-1][:len(pre)].lower() == pre}
        more = stated_define.answers(prefix, open_qs, got, gen.members_of(prefix, mine or files, ctx), gen)
    except (Exception, SystemExit):
        print(f"[evidence] {prefix}: stated_define.py raised; its answers are not used:\n{traceback.format_exc()}",
              file=sys.stderr)
        return got
    got.update({k: v for k, v in more.items() if got.get(k) is None})
    return got


def stated_collections(prefix: str, qs: list, got: dict, files: dict, ctx) -> dict:
    """Compute fully stated operations over a prefix's member set or named builds.

    ``stated_define`` deliberately selects one executable.  This companion path
    handles contracts that explicitly select every prefix member, a primary
    managed assembly/classfile, or two named family builds. Every operation is
    gated by its complete text. Unlike an ordinary fallback, a matched
    collection rule is authoritative even when generic produced a value from
    one convenient member: if the required member set is incomplete, that
    one-member value is withdrawn; if the collection succeeds, its derived
    value replaces the one-member reading.
    """
    if not any(_field(q["qid"]) in STATED_COLLECTION_FIELDS for q in qs):
        return got
    try:
        import stated_collections as reader
        matched = [q for q in qs if reader.asks(q)]
        gen = _generic()
        if not matched or gen is None:
            return got
        pre = prefix.lower()
        mine = {n: files[n] for n in files if " -> " not in n and
                n.rsplit("/", 1)[-1][:len(pre)].lower() == pre}
        pool = gen.members_of(prefix, mine or files, ctx)
        more = reader.answers(prefix, matched, pool, gen)
    except (Exception, SystemExit):
        print(f"[evidence] {prefix}: stated_collections.py raised; its answers are not used:\n"
              f"{traceback.format_exc()}", file=sys.stderr)
        return got
    for q in matched:
        qid = q["qid"]
        value = more.get(qid)
        if value is None:
            if got.get(qid) is not None:
                print(f"[evidence] {qid}: its stated collection is incomplete; the one-member answer is "
                      "withdrawn", file=sys.stderr)
            got[qid] = None
        else:
            got[qid] = value
    return got


def trailer(prefix: str, qs: list, got: dict, files: dict, ctx) -> dict:
    """The Day 21 build, round 2 (row 397's remainder): an id still None after everything else that asks an
    integer field of the prefix's one verified tagged trailer which no reader knows (generic.trailer_answers)
    gets a labels.candidates pick of the header's integer fields, never a plain answer. Costs nothing when no
    such id is open; one that raises costs nothing."""
    open_qs = [q for q in qs if got.get(q["qid"]) is None]
    gen = _generic()
    if not open_qs or gen is None or not callable(getattr(gen, "trailer_answers", None)):
        return got
    try:
        more = gen.trailer_answers(prefix, open_qs, files, ctx) or {}
    except (Exception, SystemExit):
        print(f"[evidence] {prefix}: generic.trailer_answers raised; its answers are not used:\n"
              f"{traceback.format_exc()}", file=sys.stderr)
        return got
    if more:
        print(f"[evidence] {prefix}: the tagged trailer offers {len(more)} candidate pick(s) for header fields no "
              f"reader knows ({', '.join(more)})", file=sys.stderr)
        got.update({k: v for k, v in more.items() if got.get(k) is None})
    return got


def sidecar(prefix: str, qs: list, got: dict, files: dict, ctx) -> dict:
    """The Day 27 build (group binary-fold d26; row 530's look-ahead): an id still None whose field names a crash or
    stack record and a reading (sidecar_records.asks), whose question states the reading (a JSON path, a list key,
    a selection, a count or a membership predicate), gets that reading of the one record the prefix's members hold,
    as an UNSURE answer (labels.pick / labels.candidates under binary.sidecar_first|count|membership/<shape>), never
    plain before the judge accepts it. The judged Day 26 shape is answered plain by generic (SIDECAR_FIELDS), so
    this is asked only after it, fields_<prefix>.py and the catalog left the id None. Costs one test of the field
    word per id still None; only members that begin with a zip's magic or are named .json are read."""
    gen = _generic()
    if gen is None or not callable(getattr(gen, "_sidecar_module", None)):
        return got
    open_qs = [q for q in qs if got.get(q["qid"]) is None]
    if not open_qs:
        return got
    try:
        mod = gen._sidecar_module()
        open_qs = [q for q in open_qs if mod is not None and mod.asks(q["qid"])]
        pool = gen.members_of(prefix, files, ctx) if open_qs else []
    except (Exception, SystemExit):
        print(f"[evidence] {prefix}: sidecar_records.py raised; its answers are not used:\n{traceback.format_exc()}",
              file=sys.stderr)
        return got
    for q in open_qs:
        try:
            value, why = mod.unsure_answer(q["qid"], q, pool)
        except (Exception, SystemExit):
            print(f"[evidence] {q['qid']}: sidecar_records.py raised; not answered:\n{traceback.format_exc()}",
                  file=sys.stderr)
            continue
        if isinstance(value, str) and not value.strip():
            continue
        if value is not None:
            got[q["qid"]] = value
            print(f"[sidecar] {q['qid']}: the record the question names offers "
                  f"{'an unsure reading' if gen.labels.is_unsure(value) else 'its judged reading ' + repr(value)}",
                  file=sys.stderr)
        else:
            print(f"[sidecar] {q['qid']}: not answered: {why}", file=sys.stderr)
    return got


def patch_facts(prefix: str, qs: list, got: dict, files: dict, ctx) -> dict:
    """KB-3 (the Day 27 build): an id still None after every other reader whose own words AND question text ask a
    fact of the difference between the prefix's two CRC-valid day records (the changed config key, the changed count,
    a side's value, the patch's offset or size) gets an unsure pick of it (generic.patch_diff_answers, patch_diff.py),
    never plain. Asked last, so the stated wrapper, the sidecar, a stated definition and the tagged trailer read their
    ids first (fix round 2 of the review of KB-3). Costs one test of the id's words per id still None; one that raises
    costs nothing."""
    open_qs = [q for q in qs if got.get(q["qid"]) is None]
    gen = _generic()
    if not open_qs or gen is None or not callable(getattr(gen, "patch_diff_answers", None)):
        return got
    try:
        more = gen.patch_diff_answers(prefix, open_qs, files, ctx) or {}
    except (Exception, SystemExit):
        print(f"[evidence] {prefix}: generic.patch_diff_answers raised; its answers are not used:\n"
              f"{traceback.format_exc()}", file=sys.stderr)
        return got
    got.update({k: v for k, v in more.items() if got.get(k) is None})
    return got


def graph_facts(prefix: str, qs: list, got: dict, files: dict, ctx) -> dict:
    """Authoritatively answer strict, question-stated HGRF graph facts.

    The cheap text prefilter keeps the module and its JSON/ZIP dependencies off every
    historical prefix.  An exact HGRF contract is not an HCFG question: withdraw every
    earlier generic/day/patch answer before the strict reader runs.  Thus an HCFG decoy,
    malformed HGRF, import failure, bound, uniqueness or agreement failure stays None
    instead of retaining a plausible but wrong answer from another container family.
    """
    guarded = [q for q in qs if (
        "hgrf" in str(q.get("question") or "").lower()
        or (_field(q["qid"]) == "analysis_config_capsule_format"
            and "basename ends" in str(q.get("question") or "").lower())
    )]
    if not guarded:
        return got
    for q in guarded:
        got[q["qid"]] = None
    try:
        import hgrf_graph
        return hgrf_graph.fill(prefix, guarded, got, files, ctx)
    except (Exception, SystemExit):
        print(f"[evidence] {prefix}: hgrf_graph.py raised; its guarded answers are withdrawn:\n"
              f"{traceback.format_exc()}", file=sys.stderr)
        return got


def closing(prefix: str, qs: list, got: dict, files: dict, ctx, withheld=frozenset()) -> dict:
    """The readers asked last, before the kind check, in this order: stated() (the wrapper the questions state),
    sidecar() (a JSON crash record a question names, the Day 27 build), stated_collections() (a fully stated
    operation over all members or named builds), defined() (a definition over one selected executable, row 422),
    trailer() (a tagged trailer's header fields), patch_facts() (a fact of the patch difference, KB-3),
    speed_filled() (B-216: what is still None, by the id's field family, except the `withheld` ids), then
    authoritative graph_facts() (a strict HGRF property graph)."""
    got = sidecar(prefix, qs, stated(prefix, qs, got, files, ctx), files, ctx)
    got = stated_collections(prefix, qs, got, files, ctx)
    got = trailer(prefix, qs, defined(prefix, qs, got, files, ctx), files, ctx)
    got = patch_facts(prefix, qs, got, files, ctx)
    got = speed_filled(prefix, qs, got, files, ctx, withheld)
    return graph_facts(prefix, qs, got, files, ctx)


def withheld_ids(qs: list, given, decided, got: dict) -> frozenset:
    """The ids of a day module's set that are None on purpose before closing(): those the module answered and a
    guard (hygiene, header_labels, key_agrees, config_members_unsure, config_decoy_guard, ...) then withdrew, and
    those the module decides on and left None (its None is a decision, as from_catalog() holds). speed_filled()
    does not ask about them: a second reader that runs after the guards must not undo what they withdrew."""
    return frozenset(q["qid"] for q in qs if got.get(q["qid"]) is None and (q["qid"] in given or q["qid"] in decided))


def lane_config_hold(prefix: str, files: dict, ctx, extra=()) -> str:
    """Why speed_filled() must leave the config family alone for this prefix, or '' when it may answer it.

    generic.choose_config is the lane's one config selector: it peels the envelopes and text forms the lane knows
    and tells the sample's container from a decoy by its day and variant, and returns None ON PURPOSE when it
    cannot. overlay_records.config sees only the containers it decodes, so beside a container only generic reads it
    can find one 'distinct' record that is the decoy. The speed solver's config is therefore asked only when
    generic finds no CRC-valid container at all in the prefix's files (generic's members, plus `extra`, the files the
    speed solver picked by content): a container generic chose is generic's to answer, and one it declined stays
    unanswered. Without generic (it did not import, or its read raised) the family is held too: no silent
    fallback to the weaker reader."""
    gen = _generic()
    if gen is None or not callable(getattr(gen, "choose_config", None)):
        return "generic.py's config selector is not available to rule out a container it reads"
    try:
        pool = list(gen.members_of(prefix, files, ctx) or [])
        names = {name for name, _ in pool}
        pool += [(name, data) for name, data in extra if name not in names]
        cfg, _at, declined = gen.choose_config(pool, gen.day_of(prefix)) if pool else (None, None, "")
    except (Exception, SystemExit) as e:
        return f"generic's container read raised {type(e).__name__}: {e}"
    if cfg is not None:
        return "generic reads a CRC-valid container in the prefix's files, so its members are generic's to answer"
    if declined:
        return f"generic declined the prefix's containers ({declined})"
    return ""


def speed_filled(prefix: str, qs: list, got: dict, files: dict, ctx, withheld=frozenset()) -> dict:
    """B-216: the ids every reader before left None, asked of speed_solver.py, which answers by the id's family
    (field_grammar.py) only what the bytes prove and the family spells (a file or overlay hash, a section's
    presence or offset, a verified overlay record's member, the literal none for a proven absence the syntax
    permits). An answer already given is never replaced; a raise costs nothing.

    Two holds keep it from undoing a decision made before it (the never-wrong rule): an id in `withheld` (a guard
    withdrew it, or the day module decides on it and left it None: withheld_ids()) is not asked, and the config
    family is answered only when lane_config_hold() says generic's selector finds no container to decide on."""
    open_qs = [q for q in qs if got.get(q["qid"]) is None and q["qid"] not in withheld]
    if not open_qs:
        return got
    try:
        import field_grammar
        import speed_solver
        config_ids = {q["qid"] for q in open_qs if field_grammar.parse(q["qid"]).family == "config"}
        hold = ""
        if config_ids:
            picked = speed_solver.Prefix(prefix, files, ctx).members
            hold = lane_config_hold(prefix, files, ctx, picked)
            if hold:
                print(f"[evidence] {prefix}: speed_solver is not asked about {len(config_ids)} config id(s): {hold}",
                      file=sys.stderr)
                open_qs = [q for q in open_qs if q["qid"] not in config_ids]
        more, why = speed_solver.solve(prefix, open_qs, files, ctx) if open_qs else ({}, {})
    except (Exception, SystemExit):
        print(f"[evidence] {prefix}: speed_solver raised; its answers are not used:\n{traceback.format_exc()}",
              file=sys.stderr)
        return got
    for qid, value in more.items():         # only the open ids were asked, so nothing given is replaced
        if value is not None:
            got[qid] = value
            print(f"[evidence] {qid}: answered by speed_solver (field family) as {str(value)[:60]!r}", file=sys.stderr)
    return got


def generic_path(prefix: str, qs: list, files: dict, ctx) -> dict:
    """A prefix with no day module, or whose module raised: generic, the role reader, then closing() with the ids
    generic decided to leave None held from speed_filled()."""
    got, decided = by_generic_decided(prefix, qs, files, ctx)
    got = role_filled(prefix, qs, got, files, ctx)
    withheld = frozenset(qid for qid in decided if got.get(qid) is None)
    return kind_fit(prefix, qs, closing(prefix, qs, got, files, ctx, withheld), files, ctx)


def solve_prefix(prefix: str, qs: list, files: dict, ctx) -> dict:
    """{qid: answer} for one prefix: its day module, or generic when that is missing or fails."""
    mod, why = load(prefix)
    if mod is None:
        print(f"[evidence] {prefix}: {why}; generic answers its {len(qs)} question(s)", file=sys.stderr)
        return generic_path(prefix, qs, files, ctx)
    try:
        got = mod.answers(qs, files, ctx) or {}
        if not isinstance(got, dict):
            raise TypeError(f"{prefix}.answers returned {type(got).__name__}, not a dict")
        got = dict(got)
        given = {qid for qid, value in got.items() if value is not None}
    except (Exception, SystemExit):
        print(f"[evidence] {prefix} raised; generic answers its {len(qs)} question(s):\n{traceback.format_exc()}",
              file=sys.stderr)
        return generic_path(prefix, qs, files, ctx)
    decided = {q["qid"] for q in qs if handles(prefix, mod, q["qid"], got)}
    got = header_labels(prefix, qs, hygiene(prefix, qs, got, files, ctx), files, ctx, decided)
    got = key_agrees(prefix, qs, got, files, ctx)
    got = config_members_unsure(prefix, qs, got, files, ctx)
    got = config_decoy_guard(prefix, qs, got, files, ctx)
    got = buried_config(prefix, qs, unhandled(prefix, qs, got, files, ctx, decided), files, ctx)
    got = role_filled(prefix, qs, got, files, ctx)
    got = from_catalog(prefix, qs, from_hook(prefix, qs, got, files, ctx), files, ctx, decided)
    withheld = withheld_ids(qs, given, decided, got)
    return kind_fit(prefix, qs, closing(prefix, qs, got, files, ctx, withheld), files, ctx)


def sendable(got: dict) -> dict:
    """Drop an answer the runner could not serialize (bytes, a set, a dict that holds them).
    The runner turns every non-string answer into JSON, and one failure there costs the set
    every answer after it; here it costs that answer alone."""
    for qid, value in got.items():
        if value is None or isinstance(value, str):
            continue
        try:
            json.dumps(value)
        except (TypeError, ValueError) as e:
            got[qid] = None
            print(f"[evidence] {qid}: the answer for it is not JSON ({type(e).__name__}: {e}); left unanswered",
                  file=sys.stderr)
    return got


PATCH = "day_patch.py"            # the live-fix file whose override() is asked last (see the module docstring)
PATCH_WITHDRAW = "<<withdraw>>"   # what override() returns to take an answer back: the answer becomes None


def day_patch():
    """override(q, answer, files, ctx) of day_patch.py in the modules folder, or None. Loaded on each
    call, so a file written during play is heard by the next run; one that does not load is reported
    and ignored."""
    path = Path(MODULES) / PATCH
    if not path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("binary_day_patch", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    except (Exception, SystemExit) as e:
        print(f"[evidence] {PATCH} could not be loaded ({type(e).__name__}: {e}); no answer is overridden", file=sys.stderr)
        return None
    fn = getattr(mod, "override", None)
    return fn if callable(fn) else None


def overridden(override, qs: list, got: dict, files: dict, ctx) -> dict:
    """Ask day_patch.override about every question of one prefix: a text replaces the answer, PATCH_WITHDRAW
    makes it None, anything else leaves it. A raise costs nothing: the answer stands."""
    for q in qs:
        qid = q["qid"]
        value = got.get(qid)
        try:
            new = override(q, value, files, ctx)
        except (Exception, SystemExit) as e:
            print(f"NOTE {qid}: day_patch.override raised {type(e).__name__}: {str(e)[:200]}; the answer stands", file=sys.stderr)
            continue
        if not isinstance(new, str) or not new or new == value:
            continue
        if not new.strip():
            # (the review of 2026-10-12) white space is no answer: sent, it would cost the batch
            print(f"NOTE {qid}: day_patch.override returned a blank text; the answer stands", file=sys.stderr)
            continue
        if new.startswith("??"):
            gen = _generic()
            parsed = gen.labels.parse(new) if gen is not None else None
            if parsed is None or not str(parsed.key or "").startswith("binary."):
                print(f"NOTE {qid}: day_patch.override returned an unsure value that is not under a binary. key "
                      f"({str(new)[:60]}); the answer stands", file=sys.stderr)
                continue
        # wave3 (T4, override-guard): a day_patch override() may not replace or withdraw a
        # judge-accepted plain answer. The guard engages only when `value` is provably the judge's
        # own for its key; a BAD/unjudged/None id is replaced or withdrawn exactly as before.
        if _respell is not None:
            try:
                new, blocked, gnote = _respell.guard_value(qid, value, new, files)
            except Exception:
                blocked = False                      # guard failed: fall back to the shipped behavior
                if new == PATCH_WITHDRAW:
                    new = None
            if blocked:
                print(f"NOTE {qid}: {gnote}", file=sys.stderr)
                continue
            if new == value:
                continue                      # WITHDRAW of an already-None answer, or a no-op
            # wave3 (T2, render_candidates): a day_patch that returns a READ-but-unjudged value as an
            # ordinary unsure pick gets its value's other plausible spellings offered too. enrich()
            # touches only an ordinary unsure pick (never a plain or None value) and never emits plain.
            try:
                new = _respell.enrich(new, q, field=_respell.field_of(qid))
            except Exception:
                pass
        else:
            if new == PATCH_WITHDRAW:
                if value is None:
                    continue
                new = None
        print(f"NOTE {qid}: {str(value)[:100]} replaced by day_patch.py ({str(new)[:100]})", file=sys.stderr)
        got[qid] = new
    return got


_SET_PREFIX = re.compile(r"^set\d+\.")


def folded_storage(qs: list, got: dict, files: dict, ctx) -> dict:
    """The CRC-gated hcfg_storage reader (hcfg_storage.py) as a built-in fallback, asked only about an
    `*_analysis_hcfg_storage` id the day module, generic and the field catalog left None. Its value is a
    judge-accepted plain name, a labels.pick / labels.candidates under a binary. key, or None: the
    reader's own contract, so nothing here can send a guess. Day 23 folded into the shipped solver
    (it had been a day_patch.py live fix); a failure costs nothing."""
    todo = [q for q in qs if got.get(q["qid"]) is None
            and _SET_PREFIX.sub("", q["qid"]).endswith("_analysis_hcfg_storage")]
    if not todo:
        return got
    try:
        import hcfg_storage
    except Exception as e:
        print(f"[evidence] hcfg_storage.py could not be loaded ({type(e).__name__}: {e}); not asked", file=sys.stderr)
        return got
    for q in todo:
        qid = q["qid"]
        try:
            q2 = dict(q, qid=_SET_PREFIX.sub("", qid))
            value = hcfg_storage.answer(q2, files, ctx)
        except (Exception, SystemExit) as e:
            print(f"NOTE {qid}: hcfg_storage.answer raised {type(e).__name__}: {str(e)[:200]}; left as it is", file=sys.stderr)
            continue
        if not isinstance(value, str) or not value.strip():
            continue
        if value.startswith("??"):
            gen = _generic()
            parsed = gen.labels.parse(value) if gen is not None else None
            if parsed is None or not str(parsed.key or "").startswith("binary."):
                continue
        print(f"NOTE {qid}: None answered by hcfg_storage.py ({value[:100]})", file=sys.stderr)
        got[qid] = value
    return got


def structural_enums(qs: list, got: dict, files: dict, ctx, guard=None, held=None) -> dict:
    """KB-6 (the Day 27 build): a format or carrier token the shipped readers do not name, as an unsure pick the
    bytes prove (structural_enums.py). Asked last; adds to an id that is None (or, for hcfg_storage, unsure) and
    never replaces a plain answer; a failure costs nothing.

    The rewording guard (`guard.demote`, with the set's `held`) ran before this module was asked, so it never saw
    these answers; a name the judge has accepted for one of this module's keys answers PLAIN, and a plain answer under
    a question text or rule the judge never took must be held like any other (the review of KB-6: a NEKO module under
    a reworded format text answered neko_bytecode plain, while generic's ELF answer was demoted under the same text).
    So the guard is asked again, about the ids this module set to a PLAIN answer only: an unsure pick is left alone (a
    rule field's unsure answer is the guard's own B6 path, which this module already follows)."""
    try:
        import structural_enums
        before = dict(got)
        got = structural_enums.close(qs, got, files, ctx, _generic())
    except (Exception, SystemExit):
        print(f"[evidence] structural_enums.py raised; its answers are not used:\n{traceback.format_exc()}",
              file=sys.stderr)
        return got
    if guard is not None and held:
        try:
            gen = _generic()
            fresh = []
            for q in qs:
                qid, value = q.get("qid"), got.get(q.get("qid"))
                if (qid in held and value != before.get(qid) and isinstance(value, str)
                        and not (gen is not None and gen.labels.is_unsure(value))):
                    fresh.append(q)
            if fresh:
                got = guard.demote(fresh, got, {q["qid"]: held[q["qid"]] for q in fresh})
        except Exception as e:      # a guard that cannot hold an answer leaves it as it stood
            print(f"[evidence] judged_forms could not hold structural_enums's answer(s) ({type(e).__name__}: {e}); "
                  "they stand as they were", file=sys.stderr)
    return got


def forms_guard(questions, ctx=None):
    """(judged_forms module, its plan for this set) or (None, {}): see "The rewording guard" in the module
    docstring. A guard that does not load costs nothing but its own line."""
    try:
        import judged_forms
        return judged_forms, judged_forms.plan(questions, ctx)
    except Exception as e:
        print(f"[evidence] judged_forms.py could not be used ({type(e).__name__}: {e}); answers are sent in their "
              "judged form", file=sys.stderr)
        return None, {}


def static_reader(questions, files=None, ctx=None):
    """The lone/static Single Solve reader, or None outside its tightly gated contract."""
    # Keep the finale fallback's imports off every historical Binary solve.  This is only a
    # necessary-condition prefilter: static_re.eligible() remains the authoritative gate after
    # import.  In particular covers() has no attempt context, and d01--d29 are absolute opt-outs.
    if not isinstance(ctx, dict) or not isinstance(ctx.get("attempt"), dict):
        return None
    attempt = ctx["attempt"]
    route = " ".join(str(attempt.get(k) or "")
                     for k in ("challenge", "challenge_id", "_challenge_id", "id", "mode")).lower()
    if "time_trial" in route or "time trial" in route or "mastery" in route or attempt.get("deadline") is not None:
        return None
    route_days = [int(value) for value in STATIC_ROUTE_DAY.findall(route)]
    if route_days and any(day not in (30, 31) for day in route_days):
        return None
    days = []
    for q in questions or []:
        qid = (q.get("qid") or q.get("id") or "") if isinstance(q, dict) else str(q or "")
        match = STATIC_DAY_ID.match(str(qid))
        if match:
            days.append(int(match.group(1)))
    if days and any(day not in (30, 31) for day in days):
        return None
    mode = str(attempt.get("mode") or "").strip().lower().replace("-", "_").replace(" ", "_")
    if mode and mode not in STATIC_SINGLE_MODES:
        return None
    if not days and not mode:
        return None
    try:
        import static_re
        return static_re if static_re.eligible(questions, files, ctx) else None
    except (Exception, SystemExit) as e:
        print(f"[evidence] static_re.py could not be used ({type(e).__name__}: {e}); the ordinary Binary readers "
              "continue", file=sys.stderr)
        return None


def static_filled(reader, qs, got, files, ctx):
    """Fill only ids the historical/day reader left None; a static failure moves nothing."""
    if reader is None:
        return got
    todo = [q for q in qs if got.get(q["qid"]) is None]
    if not todo:
        return got
    try:
        more = reader.answers(todo, files, ctx)
    except (Exception, SystemExit):
        print(f"[evidence] static_re.py raised; its answers are not used:\n{traceback.format_exc()}", file=sys.stderr)
        return got
    used = 0
    for q in todo:
        qid = q["qid"]
        if isinstance(more, dict) and more.get(qid) is not None:
            got[qid] = more[qid]
            used += 1
    if used:
        print(f"[evidence] lone/static reader offers {used} bounded answer(s) for ids the day/generic path left "
              "unanswered", file=sys.stderr)
    return got


def solve_set(questions, files, ctx):
    only = {m.strip() for m in os.environ.get("ONLY", "").split(",") if m.strip()}
    override = day_patch()
    groups = {}
    for q in questions:
        groups.setdefault(module_for(q), []).append(q)
    guard, held = forms_guard(questions, ctx)
    static = static_reader(questions, files, ctx)
    # The runner provides ctx["partial"]; one that does not still finds the answers there afterwards.
    partial = ctx.setdefault("partial", {}) if isinstance(ctx, dict) else None
    out = {}
    for name, qs in groups.items():
        if only and name not in only:
            continue
        got = sendable(static_filled(static, qs, solve_prefix(name, qs, files, ctx), files, ctx))
        if held:
            got = guard.demote(qs, got, held)
        got = folded_storage(qs, got, files, ctx)
        got = structural_enums(qs, got, files, ctx, guard, held)
        got = hook_override(name, qs, got, files, ctx)
        if override is not None:
            got = overridden(override, qs, got, files, ctx)
        out.update(got)
        if isinstance(partial, dict):
            partial.update({qid: v for qid, v in got.items() if v is not None})
    return out


def covers(questions) -> list:
    """Problems with a timed id's question contract, one string per question this solver cannot
    answer; an empty list when every id's prefix has a day module or asks only fields generic knows.

    A prefix served by generic that has a fields_<prefix>.py is taken as covered: what that
    file answers is proved by the replay gate, not here. Accepts question dicts or bare ids."""
    gen = _generic()
    static = static_reader(questions)
    problems, loaded = [], {}
    for q in questions or []:
        qid = "?"
        try:
            qid = q if isinstance(q, str) else (q.get("qid") or q.get("id") or "")
            qid = re.sub(r"^set\d+\.", "", qid)
            if static is not None and static.covers_question(q):
                continue
            prefix, _, field = qid.partition("_")
            prefix = prefix.lower()
            if prefix not in loaded:
                loaded[prefix] = load(prefix)
            mod, why = loaded[prefix]
            if mod is not None:
                continue
            if gen is None:
                problems.append(f"{qid}: {why} and generic.py is not importable")
            elif not gen.knows(field) and not gen.catalog_knows(field) and not (
                    MODULE_NAME.fullmatch(prefix) and (Path(gen.HOOKS) / f"fields_{prefix}.py").is_file()):
                problems.append(f"{qid}: {why} and generic.py does not know field {field!r}")
        except Exception as e:
            # A question this hook cannot even read is a problem to report, not a reason to crash the gate.
            problems.append(f"{qid}: could not be checked ({type(e).__name__}: {e})")
    return problems
