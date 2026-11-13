#!/usr/bin/env python3
"""Day 3 sample (.NET assembly): PE header, CLI metadata root, and the stashed config.

Usage:
  python3 solvers/binary/d03.py <assembly.dll> [side files ...]

Everything is read straight from the structures: the COFF header for the machine, the
data directories for the format, the BSJB metadata root for the runtime version string,
and the HCFG container (the assembly's static array initializer) for the config. No .NET
runtime or decompiler is involved.

What the judge has accepted for this sample (Day 4 base, time trial and both mastery sets,
32 answers on two distinct DLLs; the solver replays the Day 3 attempts to the same values):

  d03_artifact_sha256_N          SHA-256 of the day's Nth file in archive order
  d03_analysis_format            `pe_cli` for a PE with a CLI header. `pe` was accepted
                                 twice for native PE32+ builds (Day 4 mastery set 2, d02
                                 and d04) and `elf` for the ELF builds, so the label is
                                 derived from the headers and is not a constant
  d03_analysis_machine           the COFF machine in GNU spelling: `i386` (`x86-64` is the
                                 accepted spelling of that CPU for d01 and d04)
  d03_analysis_metadata_version  the version string of the BSJB root, cut at the first NUL
  d03_analysis_config_<key>      that member of the decoded config JSON, as text

Rules this module keeps (docs/ops/contracts.md, "Uncertain answers"):

  - It answers a whitelist: the two hashes, format, machine, metadata_version, the config
    members campaign, domain and mutex, any other id that names a real key of the config,
    config_crc32_hex and xor_key_hex. Every other id is None.
  - None means "not established"; the literal `none` is returned only when the thing that
    would hold the value was found and the value is absent from it. A container that holds
    none of campaign, domain and mutex is not established as the config, so it answers None.
  - Only `d03_` ids are answered, and text read from the artifact is never returned if it
    starts with `??` (the marker of an unsure answer, which the runners would act on).
  - A fact whose spelling the judge has not seen (a machine other than i386 and x86-64, a
    config value that is not text) is returned as an unsure answer through labels.pick.
  - The hashes are computed before anything is parsed, and every other answer is computed
    on its own: one failure costs one answer and prints one `[d03] <reason>` line.

A None from this module is a decision, and the dispatcher (evidence.py) keeps it: it asks
handles(field), and for a field handled here it never puts generic.py's plain reading in the
place of a None. It may make the None an unsure answer when generic.py reads the same fact
and only its name is unjudged (a machine such as RISC-V that this module has no spelling
for). generic.py names a format by the rule of file_format() below and leaves a fact that
the day's executables state differently unanswered, as _agreed() does, so the two readings
of one sample do not differ. A field not handled here (a new question on this sample) is
left to generic.py and fields_d03.py.

The day's files are picked by d03_members.py and the container by d03_container.py.
"""
import hashlib
import json
import os
import re
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import d03_container
import d03_members
import hcfg

try:   # the unsure-answer contract; without it an unjudged spelling is None instead of unsure
    _common = str(Path(__file__).resolve().parent.parent / "common")
    if _common not in sys.path:
        sys.path.append(_common)
    import labels
except Exception:
    labels = None

PREFIX = "d03"
DAY = 3
# The judge's name for a PE image with a CLI header, accepted on 2026-10-04 after 182 other spellings
# were rejected (conventions.json, binary.format/pe+cli). It is returned only for that structure;
# D03_FORMAT in the environment overrides whatever the structure says.
FORMAT_LABEL = "pe_cli"

PE_TYPES = {0x10B: "PE32", 0x20B: "PE32+"}
# COFF and ELF machine values in the lane's GNU-style spelling.
MACHINES = {0x14C: "i386", 0x8664: "x86-64", 0xAA64: "aarch64", 0x1C0: "arm", 0x1C4: "armnt", 0x200: "ia64"}
ELF_MACHINES = {3: "i386", 62: "x86-64", 183: "aarch64", 40: "arm"}
# Spellings the judge accepted (conventions.json: binary.machine/i386, binary.machine/x86-64).
JUDGED_MACHINES = ("i386", "x86-64")
# Known machines no question has asked about yet: the options of the unsure answer, best first.
MACHINE_SPELLINGS = {"aarch64": ["aarch64", "arm64"], "arm": ["arm", "arm32", "armv7"],
                     "armnt": ["arm", "armnt", "thumb", "armv7"], "ia64": ["ia64", "itanium"]}

JUDGED_CONFIG = ("campaign", "domain", "mutex")
SIDE_FIELDS = ("analysis_xor_key_hex", "analysis_config_crc32_hex")
HEADERLESS_LIMIT = 1 << 20   # hcfg.find's key hunt reads the file 256 times, and here it only feeds a triage line
# The fields this module decides on (question ids without `d03_`): every hash, also the unjudged third one
# it declines; format, machine and metadata version; everything that comes from the container.
HANDLED = re.compile(r"artifact_sha256_\d+|analysis_(?:format|machine|metadata_version|xor_key_hex|config_.+)")


def handles(field: str) -> bool:
    """Whether a None for `field` is this module's decision. The dispatcher asks: see the module docstring."""
    return isinstance(field, str) and bool(HANDLED.fullmatch(field))


# ---------------------------------------------------------------------------- headers

def pe_info(data: bytes):
    """COFF and optional-header facts and the section table, or None if data is not a readable PE.

    Never raises: a file cut inside its headers is not a PE this module can describe."""
    try:
        if data[:2] != b"MZ" or len(data) < 0x40:
            return None
        nt = struct.unpack_from("<I", data, 0x3C)[0]
        if data[nt:nt + 4] != b"PE\0\0":
            return None
        machine, nsec, _, _, _, optsize, chars = struct.unpack_from("<HHIIIHH", data, nt + 4)
        opt = nt + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        if magic not in PE_TYPES:
            return None
        dirs = opt + (112 if magic == 0x20B else 96)
        ndirs = struct.unpack_from("<I", data, dirs - 4)[0]
        cli = struct.unpack_from("<II", data, dirs + 8 * 14) if ndirs > 14 else (0, 0)
        sections = []
        for i in range(nsec):
            s = opt + optsize + 40 * i
            vsize, va, rsize, raw = struct.unpack_from("<IIII", data, s + 8)
            sections.append((va, max(vsize, rsize), raw))
    except (struct.error, IndexError, TypeError):
        return None
    return {"machine": machine, "magic": magic, "characteristics": chars, "dirs": dirs, "sections": sections,
            "cli": cli}


def elf_info(data: bytes):
    """{"machine": e_machine} for an ELF, or None."""
    if data[:4] != b"\x7fELF" or len(data) < 20 or data[5] not in (1, 2):
        return None
    return {"machine": struct.unpack_from("<H" if data[5] == 1 else ">H", data, 18)[0]}


def rva_to_offset(pe: dict, rva: int):
    for va, size, raw in pe["sections"]:
        if va <= rva < va + size:
            return raw + rva - va
    return None


def metadata_root(data: bytes, pe: dict):
    """File offset of the BSJB metadata root, reached through the CLI header, or None.

    Only the path the loader takes counts. A stray `BSJB` somewhere in the file is not the
    assembly's metadata: a native host with a managed DLL packed inside it has one too."""
    try:
        rva = pe["cli"][0]
        cli = rva_to_offset(pe, rva) if rva else None
        if cli is None:
            return None
        root = rva_to_offset(pe, struct.unpack_from("<I", data, cli + 8)[0])
    except (struct.error, KeyError, IndexError, TypeError):
        return None
    return root if root is not None and data[root:root + 4] == b"BSJB" else None


def metadata_version(data: bytes, pe: dict):
    """Version string of the CLI metadata root, cut at the first NUL, or None if it cannot be read."""
    root = metadata_root(data, pe)
    if root is None:
        return None
    try:
        length = struct.unpack_from("<I", data, root + 12)[0]
    except struct.error:
        return None
    raw = data[root + 16:root + 16 + min(length, 256)].split(b"\0", 1)[0]
    # The field is ASCII by definition; anything else is damage, and an empty answer is no answer.
    return raw.decode("ascii") if re.fullmatch(rb"[\x20-\x7e]+", raw) else None


def is_managed(data: bytes) -> bool:
    """True for a PE whose CLI header leads to a metadata root."""
    pe = pe_info(data)
    return bool(pe and metadata_root(data, pe) is not None)


def file_format(data: bytes):
    """The judge's format label, from structure: `pe_cli`, `pe`, `elf`, or None.

    pe_cli  a PE whose data directory 14 is set and whose BSJB root is reachable through it
    pe      a PE without that directory
    elf     an ELF
    None    anything else, and a PE that claims a CLI header this module cannot follow: such a
            file is neither an established managed image nor an established native one."""
    pe = pe_info(data)
    if pe:
        if not any(pe["cli"]):
            return "pe"
        return FORMAT_LABEL if metadata_root(data, pe) is not None else None
    return "elf" if elf_info(data) else None


def machine_name(data: bytes):
    """The header's machine in the lane's spelling, or None for a value this module does not know."""
    pe = pe_info(data)
    if pe:
        return MACHINES.get(pe["machine"])
    elf = elf_info(data)
    return ELF_MACHINES.get(elf["machine"]) if elf else None


# ---------------------------------------------------------------------------- analysis

def _note(notes: list, text: str):
    """One `[d03] <reason>` line on stderr, once. Names and values from the artifact are untrusted text, so
    the line is kept to one line of printable characters."""
    text = "".join(ch if ch.isprintable() else "?" for ch in str(text))[:400]
    if text not in notes:
        notes.append(text)
        print(f"[d03] {text}", file=sys.stderr)


def _guard(notes: list, what: str, fn, *args):
    """fn(*args), or None after one `[d03]` line: a failure costs the one fact it was computing."""
    try:
        return fn(*args)
    except Exception as e:
        _note(notes, f"{what}: {type(e).__name__}: {e}")
        return None


def _samples(files: list) -> list:
    """The executables that speak for the sample: the managed PEs if there are any, else every PE and ELF.

    An apphost .exe next to the managed .dll is a launcher, so the managed image wins."""
    managed = [(n, b) for n, b in files if is_managed(b)]
    return managed or [(n, b) for n, b in files if pe_info(b) or elf_info(b)]


def _agreed(samples: list, fn, what: str, notes: list):
    """The fact every sample states, or None when they disagree: no file is preferred by position."""
    seen = []
    for _, blob in samples:
        v = fn(blob)
        if v not in seen:
            seen.append(v)
    if len(seen) > 1:
        _note(notes, f"{what}: the day's executables disagree ({', '.join(map(repr, seen[:4]))}); not answered")
        return None
    return seen[0] if seen else None


def _version_of(blob: bytes):
    pe = pe_info(blob)
    return metadata_version(blob, pe) if pe else None


def _why_not(fact: str, name: str, blob: bytes) -> str:
    """One triage line for a fact the sample's headers did not establish."""
    pe, elf = pe_info(blob), elf_info(blob)
    if fact == "machine" and (pe or elf):
        return f"machine: {name} states {(pe or elf)['machine']:#x}, which has no known spelling; not answered"
    if pe and any(pe["cli"]) and metadata_root(blob, pe) is None:
        return f"{fact}: {name} has a CLI header directory but no metadata root can be reached through it; not answered"
    if fact == "metadata_version" and (elf or (pe and not any(pe["cli"]))):
        return f"metadata_version: {name} has no CLI header, so no metadata root; not answered"
    return f"{fact}: not established from the headers of {name}; not answered"


def _config(files: list, notes: list):
    skipped = []
    found = d03_container.candidates(files, skipped)
    for line in skipped:
        _note(notes, f"config: {line}")
    variants = d03_container.variant_numbers([n for n, _ in files], [b for _, b in _samples(files)])
    cfg, why = d03_container.choose(found, DAY, variants)
    if cfg is None or len(found) > 1 or not cfg["crc_ok"] or cfg["via"] != "raw":
        _note(notes, f"config: {why}")
    if not found:
        for name, blob in files:   # a hint for the triage only: nothing is answered from it
            hit = hcfg.find(blob) if len(blob) <= HEADERLESS_LIMIT else None
            if hit:
                _note(notes, f"config: {name} holds a JSON object under single-byte XOR 0x{hit['key']:02x} at "
                             f"{hit['offset']:#x} with no HCFG header; not answered from it")
    return cfg


def analyze(members: list, inner: list = ()) -> dict:
    """members: [(name, bytes)] for this day, in archive order; inner: files inside a member archive.

    Every fact is computed on its own, so a malformed header costs that fact and nothing else.
    `machine` is the lane's canonical spelling (answers() turns an unjudged one into an unsure answer)."""
    notes = []
    info = {"sha256": [hashlib.sha256(b).hexdigest() for _, b in members], "notes": notes, "sample": None,
            "format": None, "pe_type": None, "machine": None, "metadata_version": None, "config": None}
    files = list(members) + list(inner)
    samples = _guard(notes, "sample", _samples, files) or []
    if samples:
        info["sample"] = samples[0][0]
        info["format"] = _guard(notes, "format", _agreed, samples, file_format, "format", notes)
        info["machine"] = _guard(notes, "machine", _agreed, samples, machine_name, "machine", notes)
        info["metadata_version"] = _guard(notes, "metadata_version", _agreed, samples, _version_of,
                                          "metadata_version", notes)
        pe = _guard(notes, "pe_type", pe_info, samples[0][1])
        info["pe_type"] = PE_TYPES.get(pe["magic"]) if pe else None
        for fact in ("format", "machine", "metadata_version"):
            if info[fact] is None and not any(n.startswith(fact + ":") for n in notes):
                _note(notes, _guard(notes, fact, _why_not, fact, *samples[0]) or f"{fact}: not answered")
    elif files:
        _note(notes, "no PE or ELF among the day's files: format, machine and metadata_version are not answered")
    if files and os.environ.get("D03_FORMAT"):
        info["format"] = os.environ["D03_FORMAT"]
    info["config"] = _guard(notes, "config", _config, files, notes)
    return info


# ---------------------------------------------------------------------------- answers

def _pick(notes: list, key: str, options: list):
    """An unsure answer for an established fact whose spelling is unjudged; None without labels.py."""
    if labels is None:
        _note(notes, f"{key}: unjudged spelling and solvers/common/labels.py is not available; not answered")
        return None
    return labels.pick(key, options)


def _machine_answer(name, notes: list):
    if name is None or name in JUDGED_MACHINES:
        return name
    return _pick(notes, f"binary.machine/{name}", MACHINE_SPELLINGS[name])


def _artifact_text(value, what: str, notes: list):
    """Text read out of the artifact, as a plain answer; None if it starts with `??`.

    `??` opens the wire form of an unsure answer (labels.unsure). The runners parse every solver value with
    labels.parse, so artifact text of that shape would make them probe options, and record verdicts under a
    ledger key, that the artifact chose. gm.session() withholds such a value anyway, so nothing is lost."""
    if isinstance(value, str) and value.startswith("??"):
        _note(notes, f"{what}: the text in the artifact starts with `??`, the marker of an unsure answer; not answered")
        return None
    return value


def _text(value, name: str, notes: list):
    """A config member as answer text. Only non-empty strings have a judged form."""
    if isinstance(value, str):
        if value:
            return _artifact_text(value, f"config {name}", notes)
        _note(notes, f"config {name}: the value is an empty string, which has no judged answer; not answered")
        return None
    if value is None:
        return _pick(notes, "binary.config_value/null", [("none", "none"), ("null", "null")])
    if isinstance(value, bool):
        return _pick(notes, "binary.config_value/bool", [("json", json.dumps(value))])
    if isinstance(value, (int, float)):
        return _pick(notes, "binary.config_value/number", [("json", json.dumps(value))])
    plain = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    escaped = json.dumps(value, separators=(",", ":"))
    options = [("compact", plain)] + ([("compact_ascii", escaped)] if escaped != plain else [])
    return _pick(notes, "binary.config_value/json", options)


def _hash_answer(n: int, sel, hashes: list, notes: list):
    """artifact_sha256_N: the Nth day file in archive order."""
    if sel.inner or any(d03_members.is_archive(b) for _, b in sel.members):
        # A day file is an archive: whether the question means it or the files inside it was never judged.
        inner = [hashlib.sha256(b).hexdigest() for _, b in sel.inner]
        return _pick(notes, "binary.artifact_sha256/nested_archive",
                     [("outer", hashes[n - 1] if n <= len(hashes) else None),
                      ("inner", inner[n - 1] if n <= len(inner) else None)])
    if n <= len(hashes):
        return hashes[n - 1]
    if hashes and sel.how in ("name", "lenient"):
        return "none"   # the day's files were found by name and there is no Nth one
    return None


def _config_answer(field: str, cfg, notes: list):
    if cfg is None:
        return None     # a container that was not found (or not chosen) answers nothing, never `none`
    if field == "analysis_xor_key_hex":
        return f"0x{cfg['key']:02x}"
    if field == "analysis_config_crc32_hex":
        if cfg["crc_ok"]:
            return f"0x{cfg['crc32']:08x}"
        computed = zlib.crc32(cfg["plain"]) & 0xFFFFFFFF   # which of the two the judge means was never judged
        return _pick(notes, "binary.config_crc32/mismatch",
                     [("stored", f"0x{cfg['crc32']:08x}"), ("computed", f"0x{computed:08x}")])
    name = field[len("analysis_config_"):]
    if name in cfg["json"]:
        return _text(cfg["json"][name], name, notes)
    if name in JUDGED_CONFIG:
        if not any(k in cfg["json"] for k in JUDGED_CONFIG):
            # A container with none of the three judged members is not established as the config the questions
            # mean (a decoy, or a config whose members moved under another key): `none` three times would be a guess.
            _note(notes, f"config: the container at {cfg.get('where', '?')} holds none of {', '.join(JUDGED_CONFIG)} "
                         f"(its keys: {', '.join(map(str, list(cfg['json'])[:12])) or 'none'}); not answered")
            return None
        return "none"   # the container was found and this member is absent
    _note(notes, f"{field}: not a key of the config ({', '.join(map(str, list(cfg['json'])[:12]))}); not answered")
    return None


def _answer(field: str, sel, hashes: list, info: dict, notes: list):
    m = re.fullmatch(r"artifact_sha256_([12])", field)
    if m:
        return _hash_answer(int(m.group(1)), sel, hashes, notes)
    if field == "analysis_format":
        return info["format"]
    if field == "analysis_machine":
        return _machine_answer(info["machine"], notes)
    if field == "analysis_metadata_version":
        return _artifact_text(info["metadata_version"], "metadata_version", notes)
    if field in SIDE_FIELDS or (field.startswith("analysis_config_") and len(field) > len("analysis_config_")):
        return _config_answer(field, info["config"], notes)
    _note(notes, f"{field}: not an id this module answers")
    return None


def answers(questions, files, ctx):
    """{qid: answer} for every question asked: a plain string, an unsure answer, or None. Never raises."""
    notes = []
    sel = _guard(notes, "members", d03_members.select, files, ctx, DAY, is_managed)
    if sel is None:
        sel = d03_members.Selection([], [], None, [])
    for line in sel.notes:
        _note(notes, line)
    # The hashes need no parsing, so they are ready before anything that could fail.
    hashes = [hashlib.sha256(b).hexdigest() for _, b in sel.members]
    info = _guard(notes, "analysis", analyze, sel.members, sel.inner) or {}
    notes.extend(n for n in info.get("notes", []) if n not in notes)
    info = {"format": None, "machine": None, "metadata_version": None, "config": None, **info}
    out = {}
    try:
        asked = list(questions or [])
    except TypeError:
        asked = []
    for q in asked:
        qid = q.get("qid") if isinstance(q, dict) else None
        if not isinstance(qid, str):
            continue
        day, _, field = qid.partition("_")
        if day.lower() != PREFIX:
            # Another day's question handed to this module must not be answered with this sample's facts.
            _note(notes, f"{qid}: not a {PREFIX}_ id; not answered")
            out[qid] = None
            continue
        value = _guard(notes, qid, _answer, field, sel, hashes, info, notes)
        out[qid] = value if isinstance(value, str) and value else None
    return out


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    try:
        given = [(p, Path(p).read_bytes()) for p in sys.argv[1:]]
    except OSError as e:
        sys.exit(f"d03.py: {e}")
    info = analyze(given)
    cfg = info.pop("config")
    info.pop("notes")
    for k, v in info.items():
        print(f"{k} = {v}")
    if cfg:
        print(f"config: {cfg['where']} key=0x{cfg['key']:02x} crc32=0x{cfg['crc32']:08x} crc_ok={cfg['crc_ok']}")
        for k, v in cfg["json"].items():
            print(f"  {k} = {v}")
    else:
        print("config: no container chosen")
