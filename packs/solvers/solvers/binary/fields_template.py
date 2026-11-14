"""Template for a new Binary day's fields_dNN.py: runtime facts from facts.py, each as an unsure answer.

Backlog row 52. Copy this file to solvers/binary/fields_dNN.py (dNN: the new sample's id prefix,
d08 on Day 8) when the day asks a runtime field that generic.py leaves None and one of the readers
below states it. Under this name the file is inert: generic.py loads only fields_<prefix>.py for a
prefix the questions carry, and no question id starts with `template_`.

    cp solvers/binary/fields_template.py solvers/binary/fields_d08_dev.py   # edit, check, then copy
    .venv/bin/python solvers/binary/fields_template.py SAMPLE FIELD [...]     # what it would answer

What to edit after copying: RULES only. Each row is (pattern, fact, key, options):

  pattern   a regex searched in the question's field (the id without `dNN_`); the first row that
            matches answers the question. Put the day's exact field name in when it is known.
  fact      the name facts.facts(data) gives the fact (see the facts.py docstring)
  key       the ledger key, binary.<field>/<form>. Keep one key per fact and form: every id that
            shares a key shares the name the judge accepts for it, on this variant and the next.
  options   value -> [(name, value), ...], best first: spellings or formats of ONE fact

Every answer is labels.pick(key, options): no name here has been judged, so the runner probes it on
the untimed base (tools/verify.py) and the ledger keeps the accepted one. Once a name is accepted,
pick returns the plain value for that key. A fact the reader did not find leaves the question
None, never a default. A question whose answer_format says integer gets its decimal option first.

The sample is what generic.py hands the hook: the member with the container, else the first with
a recognised header (a jar, a class, a DEX, a WebAssembly module, a Mach-O).
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
import facts  # noqa: E402
import labels  # noqa: E402

KOTLIN_KIND = {1: "class", 2: "file", 3: "synthetic_class", 4: "multifile_class", 5: "multifile_class_part"}


def _dotted(v):
    """A class name, as the manifest writes it (a.b.C) and as the class file does (a/b/C)."""
    v = str(v)
    return [("dotted", v.replace("/", ".")), ("internal", v.replace(".", "/"))]


def _number(v):
    v = int(v)
    return [("decimal", str(v)), ("hex", f"0x{v:x}")]


def _hex_word(v):
    """A hex word as facts.py writes it (0x + 8 digits), then shorter and decimal."""
    n = int(str(v), 16)
    return [("hex", f"0x{n:08x}"), ("hex_short", f"0x{n:x}"), ("decimal", str(n))]


def _text(v):
    return [("text", str(v))]


def _class_major(v):
    v = int(v)
    release = str(v - 44) if v >= 49 else f"1.{v - 44}"
    return [("decimal", str(v)), ("release", release), ("hex", f"0x{v:x}")]


def _java_release(v):
    return [("release", str(v)), ("java_name", f"java{v}")]


def _version_list(v):
    parts = str(v).split(".")
    return [("dotted", str(v)), ("json", "[" + ",".join(parts) + "]")]


def _kotlin_kind(v):
    v = int(v)
    return ([("name", KOTLIN_KIND[v])] if v in KOTLIN_KIND else []) + [("decimal", str(v))]


def _dex_version(v):
    return [("digits", str(v)), ("decimal", str(int(v)))]


def _filetype(v):
    if isinstance(v, int):
        return [("decimal", str(v)), ("hex", f"0x{v:x}")]
    bare = v[3:].lower() if v.startswith("MH_") else v.lower()
    return [("name", v), ("lower", v.lower()), ("bare", bare)]


RULES = [
    (r"main_?class", "jar_main_class", "binary.jar_main_class/manifest", _dotted),
    (r"kotlin.*kind", "kotlin_kind", "binary.kotlin_kind/metadata", _kotlin_kind),
    (r"kotlin.*(version|mv)", "kotlin_metadata_version", "binary.kotlin_metadata_version/mv", _version_list),
    (r"java_?(release|version)|target_?release", "java_release", "binary.java_release/class", _java_release),
    (r"class.*minor|minor_version", "class_minor", "binary.class_minor/class", _number),
    (r"class.*(major|version)|major_version|bytecode_version", "class_major", "binary.class_major/class",
     _class_major),
    (r"class_?name|this_class", "class_name", "binary.class_name/class", _dotted),
    (r"created_?by", "jar_created_by", "binary.jar_created_by/manifest", _text),
    (r"build_?jdk", "jar_build_jdk", "binary.jar_build_jdk/manifest", _text),
    (r"dex.*version", "dex_version", "binary.dex_version/header", _dex_version),
    (r"wasm.*version|web_?assembly.*version", "wasm_version", "binary.wasm_version/header", _number),
    (r"(macho|mach_o).*file_?type|^analysis_file_?type$", "macho_filetype", "binary.macho_filetype/header",
     _filetype),
    (r"ncmds|load_?command.*count|command_count", "macho_ncmds", "binary.macho_ncmds/header", _number),
    (r"sizeofcmds|size_of_cmds|load_?command.*size", "macho_sizeofcmds", "binary.macho_sizeofcmds/header", _number),
    (r"(macho|mach_o).*flags", "macho_flags", "binary.macho_flags/header", _hex_word),
    (r"cpu_?subtype", "macho_cpusubtype", "binary.macho_cpusubtype/header", _number),
    (r"cpu_?type", "macho_cputype", "binary.macho_cputype/header", _hex_word),
]


def _qid(q):
    return q.get("qid") or q.get("id") or q.get("answer_id")


def answer(field: str, found: dict, fmt=None):
    """labels.pick(...) for one field from the facts found, or None (no rule, or no such fact)."""
    for pattern, fact, key, options in RULES:
        if re.search(pattern, field):
            if found.get(fact) is None:
                return None
            opts = options(found[fact])
            if (fmt or {}).get("kind") == "integer":
                opts = [o for o in opts if o[0] == "decimal"] + [o for o in opts if o[0] != "decimal"]
            return labels.pick(key, opts)
    return None


def fields(sample_name, data, questions):
    """{qid: unsure answer} for the questions generic.py left None that a rule and a found fact answer."""
    found = facts.facts(data)
    out = {}
    for q in questions:
        qid = _qid(q)
        if not isinstance(qid, str):
            continue
        field = qid.split("_", 1)[1] if "_" in qid else qid
        got = answer(field, found, q.get("answer_format") if isinstance(q.get("answer_format"), dict) else None)
        if got is not None:
            out[qid] = got
    return out


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] in ("-h", "--help"):
        sys.exit(__doc__)
    blob = Path(sys.argv[1]).read_bytes()
    found = facts.facts(blob)
    for name in sys.argv[2:]:
        print(f"{name} = {answer(name, found)!r}")
