#!/usr/bin/env python3
"""JSON sidecar records in an archive sample, and the predicates asked over them (backlog rows 530 and 531, the
Day 27 build, group binary-fold d26: the Day 26 live fixes fields_d26.py and d26_cx_dev.py folded).

Day 26's d26 sample was a Groovy-built jar that carried a crash record beside its classfiles,

    crash/trace.json   {"schema": "huntress.synthetic_crash.v1", "kind": "IllegalStateException",
                        "frames": ["stageThree", "stageTwo", "stageOne"]}

and two new ids asked about it that no shipped reader knew (None at Layer 1; the owner's fields_d26.py closed the
base, Time Trial and Mastery, each CORRECT):

    d26_analysis_crash_fault_method          exact_text  "Parse crash/trace.json and submit the exact first string
                                                          in its frames array."                     -> frames[0]
    d26_analysis_crash_frames_match_methods  enum true/false  "true exactly when every string in crash/trace.json
                                                          frames is present in the primary classfile method-name
                                                          set."                                     -> "true"

The lane is cumulative, so every later day asks both again of the d26 sample. Two readers, one module:

judged_answer(field, members, fmt, text) -- PLAIN, asked by generic.answer_field (generic.knows() names both
  fields, SIDECAR_FIELDS), and only in exactly the shape the judge took on Day 26:
    - the field word (the id without dNN_) is one of the two above (JUDGED);
    - the question's text, normalised as judged_forms.norm_text keeps it (case, blanks, the day masked, a
      Mastery's `In delivery N:`), is one judged_syntax.json "texts" holds for that field, and its (kind,
      syntax) is one "fields" holds; the enum lists exactly true and false. A missing table answers nothing;
    - exactly ONE member of the prefix is an archive (a zip at offset 0, ARCHIVE_MAX or less) that holds a
      `trace.json` entry; that entry is the only `trace.json` it holds (no second copy of the name, no
      other path ending in trace.json) and it is named exactly `crash/trace.json`; no other member of the
      prefix is a `trace.json` of its own;
    - the archive is a jar: classfiles and a META-INF/MANIFEST.MF, no AndroidManifest.xml;
    - the entry is strict UTF-8 JSON (no BOM, no NaN, no repeated key) whose top level is an object with a
      `frames` member that is a NON-EMPTY list of non-empty strings.
  crash_fault_method is then frames[0], plain, when it is printable with no white space at either end.
  crash_frames_match_methods reads the manifest's Main-Class (one manifest, a Main-Class with no blank, its
  `<Main/Class>.class` entry exactly once, no multi-release copy of it under META-INF/versions/N/) and parses
  that classfile WHOLE (class_table: every constant-pool tag known, a Long or Double never in the last slot,
  every member name and descriptor a Utf8 constant, every attribute inside the file, the file ending exactly
  where the class attributes end, this_class naming the Main-Class). Every frame must be a bare JVM method
  name (no dot, slash, parenthesis or blank: the form of every judged frame). Then "true" when every frame is
  one of its method names (<init> and <clinit> included: the method table, as binary.methods/class was judged
  on Day 17, `<init>` first in d06_analysis_methods), and "false" only when each frame the Main-Class lacks is a
  method of NO classfile of the jar (all of them parse whole): the primary-class reading and the any-class
  reading then agree. Anything else is None, with the reason.

unsure_answer(field, q, members) -- the look-ahead (row 530), asked by evidence.sidecar() for an id still None
  after everything else (the day module, generic, fields_<prefix>.py and the catalog), so a file written for
  the prefix during play always answers first. A new day may ship the same idea with another member path
  (crash/report.json, trace/stack.json, a json under META-INF), another list key (stack, callstack, backtrace,
  frames), another archive (a jar, an APK, a wasm sample in a zip, the record as a member of its own) or
  another predicate. The question text states the reading: the one JSON path it names, the list key (`its X
  array`, `the "X" list`, `<path> X`), the selection (first, last, an ordinal, `index N` with its base; top,
  innermost, faulting, bottom, outermost are ambiguous and give both ends as candidates), a count (`how many`,
  `number of`), or a membership predicate (every/any/the first string, present in / declared in / member of /
  matches, against the primary class (manifest Main-Class), any classfile of the archive, a DEX's method ids or
  a wasm module's exports). Text that qualifies the reading in a way this reader does not carry out (skip,
  exclude, whose, starts with, after, lowercase, demangle, package, ...: QUALIFIER) reads nothing. The answer
  is NEVER plain before the judge accepts its reading:
    binary.sidecar_first/<shape>             a selected string: labels.pick, option `first`, `last` or
                                             `index:N`; an ambiguous selection is labels.candidates
    binary.sidecar_count/<shape>             a count: labels.pick, option `list_length` (`distinct_length`)
    binary.sidecar_membership/<shape>+<q>    a predicate: labels.candidates, each option named by the SET of
                                             hypotheses that give its value (`main_class_methods+
                                             all_class_methods` when the two agree), so an accepted name
                                             answers a later variant plain only where the same hypotheses agree
  <shape> is `<where>+<path slug>+<list key>+t<tag>`: where the record was found (`jar`, `apk`, `zip`, `+nested`
  when the stated path stands under a folder, `+found` when no path is stated, `member` for a prefix member of
  its own, `+inferred` when the list key was read off the record, `+objects_<k>` for a list of objects), and
  <tag> the text tag of judged_forms (the CRC-32 of the normalised text and its kind and syntax), so a name the
  judge accepts under one text never answers another text plain. No `.` in a shape: labels' family prior never
  reads one.
  OFF in the shipped tree (LOOKAHEAD = False; asks() claims nothing): its review of 2026-10-26 forced a WRONG plain
  in two steps. The judge accepts a pick on a variant where a qualifier the reader did not carry out happens not
  to matter ("the first string ... which is a method of the primary classfile", "is NOT present in", "the
  field-name set"), and the next variant of the same text answers the unqualified reading plain. QUALIFIER is a
  list of banned words and misses such text. It stays off until spec_of rejects every word it did not consume,
  as row 422's stated_define does. judged_answer is not affected.

Cost: both readers run only for ids whose field they handle, and open only members that begin with a zip's
local-file magic (a 67 MB ELF is never parsed for JSON): the jar's central directory once a bytes object
(_ARCH, the last few), a JSON entry of ENTRY_MAX or less, a classfile of ENTRY_MAX or less. Nothing is executed.

  .venv/bin/python solvers/binary/sidecar_records.py SAMPLE.jar [PATH [LIST]]     # what the record holds
"""
import io
import json
import re
import struct
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
if str(HERE.parent / "common") not in sys.path:
    sys.path.insert(0, str(HERE.parent / "common"))
import answer_kinds  # noqa: E402
import facts         # noqa: E402
import labels        # noqa: E402

ZIP_MAGIC = b"PK\x03\x04"
ARCHIVE_MAX = 64 << 20      # an archive member larger than this is not opened
ENTRY_MAX = 1 << 20         # a JSON record, manifest, classfile, DEX or wasm entry larger than this is not read
ENTRIES_MAX = 8192          # an archive of more entries is not read
CLASSES_MAX = 2048          # classfiles read for the any-class reading
JSON_SCAN = 16              # JSON entries read when the text names no path
_KEEP = 8

JUDGED = {"analysis_crash_fault_method": "first", "analysis_crash_frames_match_methods": "membership"}
SIDECAR_FIELDS = tuple(JUDGED)
JUDGED_MEMBER = "crash/trace.json"
JUDGED_LIST = "frames"
JVM_NAME = re.compile(r"<init>|<clinit>|[A-Za-z_$][A-Za-z0-9_$]*")


def _tail(field) -> str:
    """The field word: the id without `setN.`, `dNN_` and `analysis_`."""
    t = answer_kinds._tail(field)
    return t[len("analysis_"):] if t.startswith("analysis_") else t


def _judged_key(field) -> str:
    """The judged field's slot in judged_syntax.json (`analysis_crash_fault_method`), or ''."""
    t = answer_kinds._tail(field)
    return t if t in JUDGED else ""


# ---------------------------------------------------------------------------- archives

_ARCH = []      # [(bytes object, its reading)], the last few: a set asks both fields of one sample


def archive(data):
    """{zf, names (files in central-directory order, repeats kept), kind ('jar', 'apk', 'zip')} of a zip that
    begins at offset 0, or None (not a zip, too large, too many entries, a directory that does not read)."""
    if not isinstance(data, (bytes, bytearray)) or data[:4] != ZIP_MAGIC or len(data) > ARCHIVE_MAX:
        return None
    for held, got in _ARCH:
        if held is data:
            return got
    got = None
    try:
        zf = zipfile.ZipFile(io.BytesIO(bytes(data)))
        infos = zf.infolist()
        if len(infos) <= ENTRIES_MAX:
            names = [i.filename for i in infos if not i.is_dir()]
            kind = "zip"
            if "AndroidManifest.xml" in names and any(re.fullmatch(r"classes\d*\.dex", n) for n in names):
                kind = "apk"
            elif any(n.endswith(".class") for n in names) and "META-INF/MANIFEST.MF" in names \
                    and "AndroidManifest.xml" not in names:
                kind = "jar"
            got = {"zf": zf, "names": names, "infos": {i.filename: i for i in infos if not i.is_dir()},
                   "kind": kind, "json": {}}
    except Exception:
        got = None
    if isinstance(data, bytes):          # only immutable bytes are kept by identity
        _ARCH.append((data, got))
        del _ARCH[:-_KEEP]
    return got


def read_entry(arch, name):
    """The bytes of one entry named exactly once, ENTRY_MAX or less; None otherwise (encrypted, a bad CRC)."""
    if arch is None or arch["names"].count(name) != 1:
        return None
    info = arch["infos"].get(name)
    if info is None or info.file_size > ENTRY_MAX or info.flag_bits & 1:
        return None
    try:
        raw = arch["zf"].read(info)
    except Exception:
        return None
    return raw if len(raw) <= ENTRY_MAX else None


def _no_repeats(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("a key repeated in one object")
    return dict(pairs)


def _no_constant(_text):
    raise ValueError("NaN or Infinity is no JSON value")


def json_object(raw):
    """The JSON object a record's bytes hold, read strictly (UTF-8 with no BOM, no repeated key, no NaN), or
    None."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > ENTRY_MAX:
        return None
    try:
        obj = json.loads(bytes(raw).decode("utf-8"), object_pairs_hook=_no_repeats, parse_constant=_no_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    return obj if isinstance(obj, dict) else None


def _arch_json(arch, name):
    if name not in arch["json"]:
        arch["json"][name] = json_object(read_entry(arch, name))
    return arch["json"][name]


def strings_list(value):
    """A list of non-empty strings as it stands, or None (not a list, empty, a non-string or empty item)."""
    if not isinstance(value, list) or not value:
        return None
    if not all(isinstance(v, str) and v for v in value):
        return None
    return list(value)


# ---------------------------------------------------------------------------- class files, DEX, wasm

CP_SIZES = {3: 4, 4: 4, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}


def _mutf8(raw: bytes):
    """A CONSTANT_Utf8's text (Java's modified UTF-8: NUL as C0 80, supplementary characters as surrogate
    pairs), or None when it is not well formed."""
    raw = raw.replace(b"\xc0\x80", b"\x00")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        return raw.decode("utf-8", "surrogatepass").encode("utf-16", "surrogatepass").decode("utf-16")
    except (UnicodeDecodeError, UnicodeEncodeError):
        return None


def class_table(blob):
    """(this class name, [method names in declared order]) of a class file read WHOLE, or None: every
    constant-pool tag known and inside the file, a Long or Double never in the last slot, every field and
    method name and descriptor a Utf8 constant, every attribute inside the file, and the file ending exactly
    where the class's own attributes end."""
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < 24 or blob[:4] != b"\xca\xfe\xba\xbe":
        return None
    blob = bytes(blob)
    n = len(blob)
    try:
        count = struct.unpack_from(">H", blob, 8)[0]
        if count == 0:
            return None
        utf8, classes, at, i = {}, {}, 10, 1
        while i < count:
            tag = blob[at]
            at += 1
            if tag == 1:
                size = struct.unpack_from(">H", blob, at)[0]
                at += 2
                if at + size > n:
                    return None
                text = _mutf8(blob[at:at + size])
                if text is None:
                    return None
                utf8[i] = text
                at += size
            elif tag in (5, 6):
                at += 8
                i += 1
                if i >= count:
                    return None              # a Long or Double takes two slots; the last slot cannot hold one
            elif tag in CP_SIZES:
                if tag == 7:
                    classes[i] = struct.unpack_from(">H", blob, at)[0]
                at += CP_SIZES[tag]
            else:
                return None
            if at > n:
                return None
            i += 1
        _access, this, _super = struct.unpack_from(">HHH", blob, at)
        at += 6
        at += 2 + 2 * struct.unpack_from(">H", blob, at)[0]          # interfaces

        def members(at):
            count, at, names = struct.unpack_from(">H", blob, at)[0], at + 2, []
            for _ in range(count):
                _acc, name, desc = struct.unpack_from(">HHH", blob, at)
                if name not in utf8 or desc not in utf8:
                    raise ValueError("a member name or descriptor that is no Utf8 constant")
                names.append(utf8[name])
                at += 6
                attrs = struct.unpack_from(">H", blob, at)[0]
                at += 2
                for _ in range(attrs):
                    size = struct.unpack_from(">I", blob, at + 2)[0]
                    at += 6 + size
                    if at > n:
                        raise ValueError("an attribute runs out of the file")
            return names, at

        _, at = members(at)                          # fields
        methods, at = members(at)
        attrs = struct.unpack_from(">H", blob, at)[0]
        at += 2
        for _ in range(attrs):
            size = struct.unpack_from(">I", blob, at + 2)[0]
            at += 6 + size
            if at > n:
                return None
    except (struct.error, IndexError, ValueError):
        return None
    if at != n or this not in classes or classes[this] not in utf8:
        return None
    return utf8[classes[this]], methods


def main_class_entry(arch):
    """(the entry name of the manifest's Main-Class, why None): one META-INF/MANIFEST.MF, a Main-Class with no
    blank in it, and its `<Main/Class>.class` entry exactly once in the archive."""
    raw = read_entry(arch, "META-INF/MANIFEST.MF")
    if raw is None:
        return None, "the archive has no single readable META-INF/MANIFEST.MF"
    try:
        text = raw.decode("utf-8")
        main = facts.manifest(text).get("Main-Class")
    except (UnicodeDecodeError, ValueError):
        return None, "the manifest is not UTF-8"
    section = re.split(r"\r?\n\r?\n|\r\r", text.replace("\r\n", "\n").lstrip("\n"), maxsplit=1)[0]
    heads = [ln for ln in section.split("\n") if ln.lower().startswith("main-class:")]
    if len(heads) != 1 or not heads[0].startswith("Main-Class:"):
        return None, f"the manifest's main section has {len(heads)} Main-Class attribute(s), not one as spelled"
    if not main or re.search(r"\s", main):
        return None, "the manifest names no Main-Class"
    entry = main.replace(".", "/") + ".class"
    if arch["names"].count(entry) != 1:
        return None, f"the Main-Class {main!r} is not one entry of the archive ({entry})"
    versioned = [n for n in arch["names"] if re.fullmatch(r"META-INF/versions/\d+/" + re.escape(entry), n)]
    if versioned:
        return None, (f"the archive also holds a versioned copy of the Main-Class ({versioned[0]}): which classfile "
                      "is primary is not one reading")
    return entry, None


def main_methods(arch):
    """(the method-name set of the manifest's Main-Class classfile parsed whole, why None)."""
    entry, why = main_class_entry(arch)
    if entry is None:
        return None, why
    table = class_table(read_entry(arch, entry))
    if table is None:
        return None, f"the Main-Class classfile {entry} does not parse whole"
    if table[0] != entry[:-len(".class")]:
        return None, f"the Main-Class classfile {entry} names another class ({table[0]})"
    return set(table[1]), None


def all_class_methods(arch):
    """(the method names of every classfile of the archive, each parsed whole, why None)."""
    entries = [n for n in arch["names"] if n.endswith(".class")]
    if not entries:
        return None, "the archive holds no classfile"
    if len(entries) > CLASSES_MAX:
        return None, f"the archive holds {len(entries)} classfiles, over {CLASSES_MAX}"
    out = set()
    for entry in entries:
        table = class_table(read_entry(arch, entry))
        if table is None:
            return None, f"the classfile {entry} does not parse whole"
        out.update(table[1])
    return out, None


def _uleb(data: bytes, at: int):
    value, shift = 0, 0
    for _ in range(5):
        b = data[at]
        at += 1
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, at
        shift += 7
    raise ValueError("a ULEB128 longer than five bytes")


def dex_method_names(data):
    """The names of a DEX file's method ids, or None when its tables do not read inside the file."""
    if not isinstance(data, (bytes, bytearray)) or data[:4] != b"dex\n" or len(data) < 0x70:
        return None
    data = bytes(data)
    try:
        nstr, str_off = struct.unpack_from("<II", data, 0x38)
        nmeth, meth_off = struct.unpack_from("<II", data, 0x58)
        if str_off + 4 * nstr > len(data) or meth_off + 8 * nmeth > len(data) or nmeth > 1 << 20:
            return None
        names = set()
        for k in range(nmeth):
            name_idx = struct.unpack_from("<I", data, meth_off + 8 * k + 4)[0]
            if name_idx >= nstr:
                return None
            at = struct.unpack_from("<I", data, str_off + 4 * name_idx)[0]
            _, at = _uleb(data, at)
            end = data.index(b"\0", at)
            text = _mutf8(data[at:end])
            if text is None:
                return None
            names.add(text)
        return names
    except (struct.error, IndexError, ValueError):
        return None


def wasm_exports(data, funcs_only=False):
    """The export names of a WebAssembly module (its function exports with funcs_only), or None."""
    try:
        import binfmt
        info = binfmt.wasm(bytes(data)) if isinstance(data, (bytes, bytearray)) else None
    except Exception:
        return None
    if not info or info.get("exports") is None:
        return None
    return {name for name, kind in info["exports"] if not funcs_only or kind == "func"}


# ---------------------------------------------------------------------------- the judged reader

def _judged_text(slot: str, text) -> bool:
    """Whether the normalised question text is one judged_syntax.json keeps for the judged field. A missing
    or unreadable table, or one that holds no text of the field, is no."""
    try:
        import judged_forms
        table = judged_forms.judged_texts()
        return judged_forms.norm_text(text) in table.get(slot, ())
    except Exception:
        return False


def _judged_format(slot: str, fmt) -> bool:
    """Whether the question's (kind, syntax) is one the field was judged under (strict: a missing table is
    no), and an enum lists exactly true and false."""
    if not isinstance(fmt, dict):
        return False
    pairs = answer_kinds.judged_syntax().get(slot)
    if not pairs:
        return False
    pair = (answer_kinds._norm(fmt.get("kind")), answer_kinds._norm(fmt.get("syntax")))
    if pair not in pairs:
        return False
    if answer_kinds.kind_of(fmt) == "enum":
        vals = fmt.get("accepted_values")
        return isinstance(vals, list) and len(vals) == 2 and set(vals) == {"true", "false"}
    return True


def _member_base(name: str) -> str:
    """A prefix member's name without its folder and its `dNN--` prefix."""
    base = str(name).rsplit("/", 1)[-1]
    return re.sub(r"^d\d{2}--", "", base, flags=re.I)


def _judged_record(members):
    """(member name, archive, frames, why None) of the one judged crash record among the prefix's members."""
    holders, loose = [], []
    for name, data in members or ():
        arch = archive(data)
        if arch is None:
            if _member_base(name).lower().endswith("trace.json"):
                loose.append(name)
            continue
        hits = [n for n in arch["names"] if n == JUDGED_MEMBER or n.rsplit("/", 1)[-1].lower() == "trace.json"]
        if hits:
            holders.append((name, arch, hits))
    no = (None, None, None)
    if loose:
        return no + (f"the prefix has a trace.json member of its own ({', '.join(loose)})",)
    if not holders:
        return no + ("no archive member of the prefix holds crash/trace.json",)
    if len(holders) > 1:
        return no + (f"{len(holders)} archive members of the prefix hold a trace.json",)
    name, arch, hits = holders[0]
    if hits != [JUDGED_MEMBER]:
        return no + (f"{name} holds {len(hits)} trace.json candidate entries ({', '.join(hits[:4])})",)
    if arch["kind"] != "jar":
        return no + (f"{name} is not a jar (a {arch['kind']}): the judged shape is a jar's crash record",)
    obj = _arch_json(arch, JUDGED_MEMBER)
    if obj is None:
        return no + (f"{JUDGED_MEMBER} in {name} is not one strict JSON object",)
    frames = strings_list(obj.get(JUDGED_LIST))
    if frames is None:
        return no + (f"{JUDGED_MEMBER} {JUDGED_LIST!r} is not a non-empty list of non-empty strings",)
    return name, arch, frames, None


def _plain_text(s) -> bool:
    return isinstance(s, str) and 0 < len(s) <= 512 and s == s.strip() and s.isprintable()


def judged_answer(field, members, fmt=None, text=None, prefix=None):
    """(plain answer, None) for a judged sidecar field asked in exactly the shape the judge took on Day 26,
    else (None, why). `prefix` is the id's day prefix (`d26`) where the caller has it: a text that names
    another day's members (`Use all d25-- members`) is not the judged shape for it. See the module docstring."""
    slot = _judged_key(field)
    reading = JUDGED.get(slot)
    if reading is None:
        return None, f"{field} is not a judged sidecar field"
    if text is None:
        return None, "the question text is not known here, and the judged shape includes the judged text"
    if not _judged_text(slot, text):
        return None, "the question text is not one the judge took for this field (sidecar_records reads it unsure)"
    named = {m.lower() for m in re.findall(r"\b(d\d{2})--", str(text), re.I)}
    if prefix and named and named != {str(prefix).lower()}:
        return None, f"the text names the members of {', '.join(sorted(named))}, not {prefix}'s"
    if not _judged_format(slot, fmt):
        return None, "the answer format is not one the judge took for this field"
    holder, arch, frames, why = _judged_record(members)
    if arch is None:
        return None, why
    if reading == "first":
        if not _plain_text(frames[0]):
            return None, "the first frame has white space at an end or a character that is not printable"
        return frames[0], None
    others = [n for n, d in members if n != holder
              and isinstance(d, (bytes, bytearray)) and d[:4] in (ZIP_MAGIC, b"\xca\xfe\xba\xbe")]
    if others:
        return None, (f"the prefix holds another archive or classfile beside the jar ({', '.join(others[:3])}): which "
                      "classfile is primary is not one reading")
    main, why = main_methods(arch)
    if main is None:
        return None, why
    if not all(JVM_NAME.fullmatch(f) for f in frames):
        return None, "a frame is not a bare JVM method name (the form of every judged frame)"
    if all(f in main for f in frames):
        return "true", None
    every, why = all_class_methods(arch)
    if every is None:
        return None, f"a frame is not a Main-Class method, and the jar's other classes do not read ({why})"
    other = sorted(f for f in frames if f not in main and f in every)
    if other:
        return None, (f"frame(s) {', '.join(other[:3])} are methods of another classfile of the jar, not of the "
                      "Main-Class: the primary-class and the any-class readings differ")
    return "false", None


# ---------------------------------------------------------------------------- the look-ahead reader (unsure)

PATH_RE = re.compile(r"(?<![\w./-])((?:[A-Za-z0-9_.$-]+/)*[A-Za-z0-9_.$-]+\.json)\b", re.I)
LIST_WORDS = ("frames", "stack", "callstack", "call_stack", "backtrace", "stacktrace", "stack_trace", "trace",
              "calls", "callchain", "call_chain")
ELEMENT_KEYS = ("method", "function", "name", "symbol", "frame")
STOP = {"file", "record", "json", "object", "document", "member", "entry", "and", "or", "is", "are", "the", "a",
        "an", "array", "list", "string", "strings", "its", "of", "in", "to", "as", "that", "this", "each", "every",
        "all", "first", "last", "value", "values", "key", "field"}
QUOTE = r"[\"'`“”]?"
KEY = r"([A-Za-z_][A-Za-z0-9_-]*)"
# The phrases the lane's own sentences hold, read as nothing (after judged_forms.norm_text).
BENIGN = re.compile(r"in (?:evidence\.zip|delivery \d+:?)|use all dnn-- members in zip central-directory order|"
                    r"in zip central-directory order|evaluate this public predicate|submit (?:exactly one )?lowercase "
                    r"(?:true or false|token)|submit lowercase|exact case-sensitive|parse|exact(?:ly)?")
QUALIFIER = re.compile(
    r"\b(?:skip\w*|ignor\w*|exclud\w*|except\w*|unless|other than|not counting|whose|starts? with|begins? with|"
    r"ends? with|starting|beginning|ending|prefix\w*|suffix\w*|after|before|deduplicat\w*|revers\w*|"
    r"upper[- ]?case\w*|lower[- ]?case\w*|case[- ]insensitive\w*|normali[sz]\w*|strip\w*|trim\w*|demangl\w*|"
    r"simple name|short name|qualified|package\w*|descriptor\w*|signature\w*|line numbers?|minus|plus|sum|"
    r"concatenat\w*|join\w*|sort\w*|hash\w*|sha-?\d*|md5|crc\w*|length of|characters?|without|only|unique|"
    r"distinct|excluding|non-?empty|containing|contains?|matching|filter\w*|nearest|closest|offset\w*|bytes?)\b")
MEMBERSHIP_VERB = re.compile(r"\b(?:present in|is in|are in|appears? in|declared (?:in|by)|defined (?:in|by)|"
                             r"members? of|belongs? to|found in|contained in|exists? in|matches|match)\b")
ORDINALS = {"second": 1, "third": 2, "fourth": 3, "fifth": 4, "sixth": 5, "seventh": 6, "eighth": 7, "ninth": 8,
            "tenth": 9}


LOOKAHEAD = False   # the look-ahead reader is off: see the module docstring (unsure_answer)


def asks(field) -> bool:
    """Whether the look-ahead reader may read `field` (its word names a crash or stack record and a reading).
    The text decides the rest. Always False while LOOKAHEAD is off."""
    if not LOOKAHEAD:
        return False
    t = _tail(field)
    if answer_kinds._tail(field) in JUDGED:
        return True
    record = re.search(r"(?:^|_)(?:crash|trace|stack|callstack|backtrace|stacktrace|frames?|fault|faulting|"
                       r"exception|panic|sidecar)(?:_|$)", t)
    reading = re.search(r"(?:^|_)(?:method|methods|function|functions|symbol|symbols|frame|frames|count|depth|"
                        r"match|matches|present|declared|defined|first|last|top|bottom|fault)(?:_|$)", t)
    return bool(record and reading)


def _slug(text) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(text or "").lower()).strip("_")[:40] or "none"


def _list_keys(text: str, path):
    """The list keys the text names (`its frames array`, `the "stack" list`, `crash/trace.json frames`)."""
    found = []
    pats = [rf"\bits\s+{QUOTE}{KEY}{QUOTE}\s+(?:array|list)\b",
            rf"[\"'`“]{KEY}[\"'`”]\s+(?:array|list|key|field|property|member)\b",
            rf"\bthe\s+{QUOTE}{KEY}{QUOTE}\s+(?:array|list)\s+(?:of|in)\b"]
    if path:
        p = re.escape(path)
        pats += [rf"{p}(?:'s)?\s+{QUOTE}{KEY}{QUOTE}(?=\s+(?:array|list|is|are|entries|strings|values|items|field|"
                 rf"key|member)\b)"]
    for pat in pats:
        for m in re.finditer(pat, text, re.I):
            word = m.group(1)
            if word.lower() not in STOP and word not in found:
                found.append(word)
    return found


def _selection(low: str, tail: str):
    """[(option name, index)] of the string a text selects and whether the reading is ambiguous, or None."""
    picks = []
    if re.search(r"\b(?:first|initial|leading|1st)\b", low):
        picks.append(("first", [("first", 0)], False))
    if re.search(r"\b(?:last|final|trailing)\b", low):
        picks.append(("last", [("last", -1)], False))
    for word, n in ORDINALS.items():
        if re.search(rf"\b{word}\b", low):
            picks.append((word, [(f"index:{n}", n)], False))
    m = re.search(r"\bindex\s+(\d{1,3})\b", low)
    if m:
        n = int(m.group(1))
        if re.search(r"\b(?:zero|0)[- ]based\b", low):
            picks.append(("index", [(f"index:{n}", n)], False))
        elif re.search(r"\b(?:one|1)[- ]based\b", low):
            if n < 1:
                return None
            picks.append(("index", [(f"index:{n - 1}", n - 1)], False))
        elif n >= 1:
            picks.append(("index", [(f"index:{n}", n), (f"index:{n - 1}", n - 1)], True))
        else:
            picks.append(("index", [(f"index:{n}", n)], False))
    if re.search(r"\b(?:top(?![- ]level)|topmost|innermost|deepest|faulting|crashing|throwing)\b", low):
        picks.append(("top", [("first", 0), ("last", -1)], True))
    if re.search(r"\b(?:bottom|bottommost|outermost)\b", low):
        picks.append(("bottom", [("last", -1), ("first", 0)], True))
    if len(picks) > 1:
        return None
    if picks:
        return picks[0][1], picks[0][2]
    if re.search(r"(?:^|_)first(?:_|$)", tail):
        return [("first", 0)], False
    if re.search(r"(?:^|_)last(?:_|$)", tail):
        return [("last", -1)], False
    if re.search(r"(?:^|_)(?:fault|faulting|top|crash|crashing|throw|throwing)(?:_|$)", tail):
        return [("first", 0), ("last", -1)], True
    return None


TARGETS = (
    ("main_class_methods", r"\bprimary class(?:file)?\b|\bmain[- ]class\b|\bmanifest\b"),
    ("all_class_methods", r"\b(?:any|all|every|some) (?:of the )?class(?:file)?s?\b|\bclassfiles\b|\bthe jar'?s? classes\b"),
    ("dex_method_ids", r"\bdex\b|\bdalvik\b"),
    ("wasm_exports", r"\bexports?\b|\bexported\b"),
)


def spec_of(field, text, fmt):
    """(the reading a question states, why None): {path, list, reading, ...}. See the module docstring."""
    raw = " ".join(str(text or "").split())
    try:
        import judged_forms
        low = judged_forms.norm_text(raw)
    except Exception:
        low = raw.lower()
    kind = answer_kinds.kind_of(fmt)
    tail = _tail(field)
    paths = []
    for m in PATH_RE.finditer(raw):
        if m.group(1) not in paths and not m.group(1).lower().startswith("evidence."):
            paths.append(m.group(1))
    if len(paths) > 1:
        return None, f"the text names {len(paths)} JSON members ({', '.join(paths[:3])})"
    path = paths[0] if paths else None
    lists = _list_keys(raw, path)
    if len(lists) > 1:
        return None, f"the text names {len(lists)} list keys ({', '.join(lists[:3])})"
    list_key = lists[0] if lists else None
    if path is None and not re.search(r"\bjson\b", low):
        return None, "the text names no JSON record"
    if path is None and list_key is None and not re.search(r"\b(?:crash|stack|trace|backtrace|frames?)\b", low):
        return None, "the text names no JSON record and no list"
    rest = BENIGN.sub(" ", low)
    if path:
        rest = rest.replace(path.lower(), " ")
    q = QUALIFIER.search(rest)
    if q:
        return None, f"the text qualifies the reading ({q.group(0)!r}), which this reader does not carry out"
    spec = {"path": path, "list": list_key, "text": raw, "fmt": fmt}
    if kind == "enum" or (kind in ("exact_text", "") and re.search(r"\btrue or false\b", low)):
        if kind == "enum":
            vals = fmt.get("accepted_values") if isinstance(fmt, dict) else None
            if not (isinstance(vals, list) and "true" in vals and "false" in vals):
                return None, "the enum does not list true and false"
        if not MEMBERSHIP_VERB.search(rest) and not re.search(r"(?:^|_)(?:match|matches|in|present|declared)(?:_|$)",
                                                              tail):
            return None, "the text states no membership"
        quants = []
        if re.search(r"\b(?:every|each|all)\b", rest):
            quants.append("all")
        if re.search(r"\b(?:any|some|at least one)\b", rest) and not re.search(r"\bany class", rest):
            quants.append("any")
        if re.search(r"\bfirst\b", rest):
            quants.append("first")
        if len(quants) != 1:
            return None, "the text states no single quantifier (every, any, the first)"
        named = [name for name, pat in TARGETS if re.search(pat, rest)]
        if not named and re.search(r"\bmethods?\b|\bmethod[- ]names?\b", rest):
            named = ["main_class_methods", "all_class_methods", "class_methods", "dex_method_ids"]
        elif "main_class_methods" in named or "all_class_methods" in named:
            named += [h for h in ("main_class_methods", "all_class_methods") if h not in named]
        if not named:
            return None, "the text names no symbol set this reader reads"
        spec.update(reading="membership", quant=quants[0], targets=named)
        return spec, None
    if kind == "integer":
        if re.search(r"\bhow many\b|\bnumber of\b|\bcount\b", rest) or re.search(r"(?:^|_)(?:count|depth)(?:_|$)",
                                                                                   tail):
            spec.update(reading="count")
            return spec, None
        return None, "an integer the text does not state as a count"
    if kind in ("exact_text", "pattern", ""):
        sel = _selection(rest, tail)
        if sel is None:
            return None, "the text selects no single string (first, last, an ordinal, an index)"
        spec.update(reading="select", select=sel[0], ambiguous=sel[1])
        return spec, None
    return None, f"the answer kind {kind!r} is not one this reader answers"


def _values_of(obj, list_key):
    """(the strings, how they were read, why None) of a record's list: the stated key or the one list key
    the record holds; a list of strings as it stands, or of objects that each hold exactly one string under
    one of ELEMENT_KEYS (the same key throughout)."""
    how = []
    if list_key is None:
        keys = [k for k in LIST_WORDS if isinstance(obj.get(k), list)]
        if len(keys) != 1:
            return None, "", "the record holds no single list under a stack word and the text names none"
        list_key = keys[0]
        how.append("inferred")
    if list_key not in obj:
        return None, "", f"the record has no {list_key!r} member at its top level"
    value = obj[list_key]
    got = strings_list(value)
    if got is not None:
        return got, "+".join(how), list_key
    if isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
        keys = {tuple(k for k in ELEMENT_KEYS if isinstance(v.get(k), str) and v.get(k)) for v in value}
        if len(keys) == 1 and len(next(iter(keys))) == 1:
            k = next(iter(keys))[0]
            how.append(f"objects_{_slug(k)}")
            return [v[k] for v in value], "+".join(how), list_key
    return None, "", f"{list_key!r} is not a non-empty list of strings"


def locate(spec, members):
    """(the record {where, holder, entry, arch, values, list, how}, why None) a spec names among the prefix's
    members: exactly one place, or nothing."""
    path, list_key = spec.get("path"), spec.get("list")
    found = []
    for name, data in members or ():
        if not isinstance(data, (bytes, bytearray)):
            continue
        arch = archive(data)
        if arch is not None:
            names = arch["names"]
            if path:
                exact = [n for n in names if n == path]
                nested = [n for n in names if n.endswith("/" + path)]
                if len(exact) > 1 or (not exact and len(nested) > 1):
                    return None, f"{name} holds {path} more than once"
                if exact:
                    found.append((arch["kind"], name, path, arch))
                elif nested:
                    found.append((arch["kind"] + "+nested", name, nested[0], arch))
            else:
                for entry in [n for n in names if n.lower().endswith(".json")][:JSON_SCAN]:
                    obj = _arch_json(arch, entry)
                    if obj is not None and _values_of(obj, list_key)[0] is not None:
                        found.append((arch["kind"] + "+found", name, entry, arch))
            continue
        base = _member_base(name)
        if not base.lower().endswith(".json"):
            continue
        if path is None:
            obj = json_object(data)
            if obj is not None and _values_of(obj, list_key)[0] is not None:
                found.append(("member+found", name, name, None))
        elif base in (path, path.rsplit("/", 1)[-1], path.replace("/", "-"), path.replace("/", "_")):
            found.append(("member", name, name, None))
    if not found:
        return None, f"no member of the prefix holds {path or 'a JSON record with a stack list'}"
    if len(found) > 1:
        return None, f"{len(found)} places hold {path or 'a JSON record with a stack list'}"
    where, holder, entry, arch = found[0]
    obj = _arch_json(arch, entry) if arch is not None else json_object(dict(members)[holder])
    if obj is None:
        return None, f"{entry} is not one strict JSON object"
    values, how, key = _values_of(obj, list_key)
    if values is None:
        return None, key
    return {"where": where, "holder": holder, "entry": entry, "arch": arch, "values": values, "list": key,
            "how": how, "members": members}, None


def _symbol_sets(rec, wanted):
    """{hypothesis: set of names} for the hypotheses among `wanted` that read whole in the record's place."""
    arch, out = rec["arch"], {}
    archives = [arch] if arch is not None else [a for a in (archive(d) for _, d in rec["members"]) if a is not None]
    loose = [d for n, d in rec["members"] if isinstance(d, (bytes, bytearray))]
    if len(archives) == 1:
        a = archives[0]
        if "main_class_methods" in wanted:
            got, _ = main_methods(a)
            if got is not None:
                out["main_class_methods"] = got
        if "all_class_methods" in wanted:
            got, _ = all_class_methods(a)
            if got is not None:
                out["all_class_methods"] = got
        if "dex_method_ids" in wanted:
            dexes = [n for n in a["names"] if re.fullmatch(r"classes\d*\.dex", n)]
            sets = [dex_method_names(read_entry(a, n)) for n in dexes]
            if sets and all(s is not None for s in sets):
                out["dex_method_ids"] = set().union(*sets)
        wasms = [n for n in a["names"] if n.lower().endswith(".wasm")]
        if "wasm_exports" in wanted and len(wasms) == 1:
            blob = read_entry(a, wasms[0])
            for hyp, funcs in (("wasm_exports", False), ("wasm_func_exports", True)):
                got = wasm_exports(blob, funcs) if blob is not None else None
                if got is not None:
                    out[hyp] = got
    classes = [d for d in loose if d[:4] == b"\xca\xfe\xba\xbe"]
    if "class_methods" in wanted and len(classes) == 1:
        table = class_table(classes[0])
        if table is not None:
            out["class_methods"] = set(table[1])
    wasm_members = [d for d in loose if d[:4] == b"\0asm"]
    if "wasm_exports" in wanted and arch is None and len(wasm_members) == 1:
        for hyp, funcs in (("wasm_exports", False), ("wasm_func_exports", True)):
            got = wasm_exports(wasm_members[0], funcs)
            if got is not None:
                out[hyp] = got
    return out


def unsure_answer(field, q, members):
    """(an unsure answer, None) or (None, why) for an id the look-ahead reader may read. Never plain before
    the judge accepts the reading's name for its key (labels.pick / labels.candidates)."""
    text = (q.get("question") or "") if isinstance(q, dict) else ""
    fmt = q.get("answer_format") if isinstance(q, dict) and isinstance(q.get("answer_format"), dict) else {}
    spec, why = spec_of(field, text, fmt)
    if spec is None:
        return None, why
    rec, why = locate(spec, members)
    if rec is None:
        return None, why
    try:
        import judged_forms
        tag = judged_forms.text_tag(text, fmt)
    except Exception:
        return None, "the text tag cannot be computed"
    shape = "+".join(p for p in (rec["where"], _slug(spec.get("path") or rec["entry"]), _slug(rec["list"]),
                                 rec["how"], f"t{tag}") if p)
    values = rec["values"]
    if spec["reading"] == "select":
        options = []
        for name, idx in spec["select"]:
            if -len(values) <= idx < len(values) and _plain_text(values[idx]):
                options.append((name, values[idx]))
        if not options:
            return None, "the selected string is not in the list, or is not a printable text"
        if spec["ambiguous"]:
            return labels.candidates(f"binary.sidecar_first/{shape}", options), None
        return labels.pick(f"binary.sidecar_first/{shape}", options[:1]), None
    if spec["reading"] == "count":
        return labels.pick(f"binary.sidecar_count/{shape}", [("list_length", str(len(values)))]), None
    # membership
    sets = _symbol_sets(rec, spec["targets"] + (["wasm_func_exports"] if "wasm_exports" in spec["targets"] else []))
    if not sets:
        return None, "no symbol set the text names reads whole beside the record"
    quant = spec["quant"]
    groups = {}
    order = [h for h in spec["targets"] + ["wasm_func_exports"] if h in sets]
    for hyp in order:
        names = sets[hyp]
        if quant == "all":
            val = all(v in names for v in values)
        elif quant == "any":
            val = any(v in names for v in values)
        else:
            val = values[0] in names
        groups.setdefault("true" if val else "false", []).append(hyp)
    options = [("+".join(hyps), val) for val, hyps in groups.items()]
    return labels.candidates(f"binary.sidecar_membership/{shape}+{quant}", options), None


def _cli(argv) -> int:
    if not argv:
        print(__doc__)
        return 2
    data = Path(argv[0]).read_bytes()
    arch = archive(data)
    if arch is None:
        print("not a zip at offset 0")
        return 1
    print(f"{arch['kind']}: {len(arch['names'])} entries")
    path = argv[1] if len(argv) > 1 else JUDGED_MEMBER
    obj = _arch_json(arch, path)
    print(f"{path}: {json.dumps(obj)[:400] if obj is not None else None}")
    if obj is not None:
        print("list:", _values_of(obj, argv[2] if len(argv) > 2 else None))
    print("Main-Class methods:", main_methods(arch))
    print("any-class methods:", all_class_methods(arch))
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
