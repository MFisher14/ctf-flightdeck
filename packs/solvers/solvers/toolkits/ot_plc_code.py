#!/usr/bin/env python3
"""Oracle-gated reader for compiled PLC logic (Siemens MC7, CODESYS): decodes only what a reference pair proves; the table ships empty.

B-160 is a hard-tail item. MC7 and CODESYS encodings are proprietary, and an opcode table written
from memory, a forum post or another tool's source prints confident, wrong STL. So this module
holds no opcode knowledge. It is the gate, and the plumbing around the gate:

* The opcode table (``ot_plc_code_tables.json``). Every entry must cite the reference pair that
  proves it: a compiled sample plus its known source listing, pinned by sha256 in
  ``ot_plc_code_pairs.json`` beside the table. An entry without a citation is refused at load, and
  ``load_table`` holds each citation to that manifest: the shipped table is refused when an entry
  cites a pair the manifest does not pin; a ``--table`` override still loads, and every report
  then says its citations are ``unpinned``. The table ships EMPTY because no such pair exists yet
  (the manifest records the survey).
* A strict table-driven decoder. It reads from offset 0, takes the one entry that matches at each
  position, and stops for good at the first position where none does. It never skips bytes and
  never resynchronises. Every bit of an instruction is either fixed by its entry or printed as an
  operand, and two entries that could match the same bytes are refused.
* The pair check (``check_pair``, ``verify_table``): decode a sample and compare it, statement by
  statement, with its known listing. This is what proves an entry, in the oracle test and by hand.
  A pair an entry cites must match completely. A pinned pair no entry cites yet may be ``unused``
  (pairs are pinned before the entries that read them), but nothing decoded of it may differ.
* A report for one artifact: how much of the logic was read and, where it was not, the named
  reason and the human step. A fully decoded MC7 block is handed to ``plc_logic_depth`` as STL.

With the shipped table every MC7 code block reports ``opaque`` (with its network byte ranges and
hashes from ``ot_s7deep_project``), and every CODESYS application reports ``opaque`` (inventory by
``ot_codesys_native``). That is the honest state, not a fault.

Engine entry (``python -m ctf run toolkits.ot_plc_code <challenge_dir>``): ``solve`` reports on
every MC7 block and CODESYS artifact under the folder and returns a ``SolverResult``: ``blocked``
when compiled logic is there and none of it could be read (the notes name the missing reference
pair), ``unsure`` when some of it was decoded and needs a read, ``none`` when there is none.

The operator tool, run as a script (``.venv/bin/python solvers/toolkits/ot_plc_code.py ...``):

    ot_plc_code.py BLOCK                         report (JSON); exit 0
    ot_plc_code.py BLOCK --listing BLOCK.awl     spot check against a known listing; exit 0 match, 1 not
    ot_plc_code.py --table-status                what the table holds
    ot_plc_code.py --verify-pairs MANIFEST --corpus DIR   prove every table entry on the pinned pairs
    options: --kind auto|mc7|mc7-code|codesys   --table PATH

Offline and static: it never loads a project, runs a PLC runtime or simulator, or contacts a
device. Malformed data (a table, manifest, listing or artifact) and a wrong family, kind or path
argument raise only ``PlcCodeError``; other argument types are the caller's contract.
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import ot_codesys_native
import ot_s7deep_project
import plc_logic_depth

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as _env, event as _event
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import env as _env, event as _event

ENGINE = "toolkits.ot_plc_code"
REPORT = "plc-code-report"
TABLE_SCHEMA = "plc-opcodes-1"
PAIRS_SCHEMA = "plc-pairs-1"
TABLE_PATH = Path(__file__).with_name("ot_plc_code_tables.json")
PAIRS_PATH = Path(__file__).with_name("ot_plc_code_pairs.json")    # where reference pairs are pinned
PAIRS_MANIFEST = "solvers/toolkits/ot_plc_code_pairs.json"          # the same file, as messages name it
FAMILIES = {"mc7": 2}                               # family -> instruction granularity in bytes
KINDS = ("mc7", "mc7-code")                         # a complete online block | bare code bytes
CODESYS_SUFFIXES = (".app", ".application", ".project", ".projectarchive", ".library")
FORMATS = ("dec", "hex", "sdec")
MAX_TABLE = 4 * 1024 * 1024
MAX_MANIFEST = 4 * 1024 * 1024
MAX_ENTRIES = 1024
MAX_INSTRUCTION = 16
MAX_CODE = 1024 * 1024
MAX_LISTING = 4 * 1024 * 1024
MAX_PAIRS = 512
MAX_PREVIEW = 256
MAX_SCAN = 5000                                     # files solve() looks at under a challenge folder
MAX_ARTIFACTS = 64                                  # artifacts solve() reports on
MAX_NOTE = 300                                      # characters of one reason quoted in a result
MC7_MIN = 72                                        # a complete block: 36-byte header + 36-byte footer

_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2})+")
_ID = re.compile(r"[a-z0-9][a-z0-9_.+-]{0,63}")
_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}")
_FILE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,127}")
_PLACEHOLDER = re.compile(r"\{([^{}]*)\}")
_NETWORK = re.compile(r"(?i)(?:NETWORK|NETZWERK)\b")
_TITLE = re.compile(r"(?i)TITLE\b")

MC7_HUMAN_STEPS = (
    "Read the block in a trusted viewer (STEP 7 / TIA Portal, licensed and offline) and work from "
    "that STL; the network byte ranges and hashes in this report say which bytes are which network.",
    "Do not guess opcodes. To extend the table, pin a reference pair (compiled block + known "
    f"listing) in {PAIRS_MANIFEST}, add an entry that cites it, and prove the table with "
    "--verify-pairs MANIFEST --corpus DIR (it checks the citation digests and that the cited pair "
    "exercises every entry; --listing compares one block with one listing and is only a spot check).",
)
CODESYS_HUMAN_STEPS = (
    "Take names, strings and configuration from ot_codesys_native; open the project in the CODESYS "
    "IDE (offline) if the source is needed.",
    f"Decoding the application needs a reference pair (application + known source) in {PAIRS_MANIFEST}; "
    "none exists, so nothing is decoded.",
)


class PlcCodeError(ValueError):
    """A malformed table, pair, listing or artifact, or an input over a limit."""


class PlcConfigError(PlcCodeError):
    """The run is misconfigured (no usable event): a fault of the setup, not of the artifact."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _blob(data, cap: int, label: str) -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise PlcCodeError(f"{label} must be bytes")
    if len(data) > cap:
        raise PlcCodeError(f"{label} is over the {cap}-byte limit")
    return bytes(data)


def _norm(statement: str) -> str:
    """One statement as it is compared: upper case, single spaces."""
    return " ".join(statement.upper().split())


# ---- the opcode table ------------------------------------------------------------------------------

@dataclass(frozen=True)
class Operand:
    name: str
    bit: int        # offset of the field's first bit from the instruction's first bit, MSB first
    width: int
    format: str

    def text(self, word: int, total_bits: int) -> str:
        raw = (word >> (total_bits - self.bit - self.width)) & ((1 << self.width) - 1)
        if self.format == "hex":
            return f"{raw:0{(self.width + 3) // 4}X}"
        if self.format == "sdec" and raw >> (self.width - 1):
            raw -= 1 << self.width
        return str(raw)


@dataclass(frozen=True)
class Entry:
    id: str
    match: bytes
    mask: bytes
    length: int
    stl: str
    operands: tuple
    oracle: tuple   # (pair id, sample sha256, listing sha256)

    def render(self, raw: bytes) -> str:
        word, bits = int.from_bytes(raw, "big"), self.length * 8
        values = {operand.name: operand.text(word, bits) for operand in self.operands}
        return _PLACEHOLDER.sub(lambda found: values[found.group(1)], self.stl)


# What a run knows about a table's oracle citations. Only load_table holds them to the pair manifest.
# No state says an entry was proven on its pair: that is --verify-pairs and
# tests/test_ot_plc_pairs.py, which need the corpus.
GATES = {
    "empty": "the table holds no entry, so nothing is decoded",
    "pinned": f"every entry cites a reference pair pinned in {PAIRS_MANIFEST} (citations checked at "
              "load; the proof on the pair itself is --verify-pairs)",
    "unpinned": f"NOT PROVEN: this table has entries citing a pair that {PAIRS_MANIFEST} does not pin "
                "with those digests; whatever it decodes is unverified",
    "unchecked": "the citations of this table were not checked against the pair manifest in this run",
}


class Table:
    """The validated entries of one family, with the lookup the decoder uses."""

    def __init__(self, family: str, entries, source: str):
        self.family, self.entries, self.source = family, tuple(entries), source
        self.citations = "unchecked" if self.entries else "empty"
        self.word = FAMILIES[family]
        self._by_id = {entry.id: entry for entry in self.entries}
        self._fixed: dict = {}      # first byte -> entries whose first byte is wholly fixed
        self._loose: list = []      # entries with operand bits in the first byte
        for entry in self.entries:
            probe = (len(entry.match), int.from_bytes(entry.mask, "big"),
                     int.from_bytes(entry.match, "big"), entry)
            if entry.mask[0] == 0xFF:
                self._fixed.setdefault(entry.match[0], []).append(probe)
            else:
                self._loose.append(probe)

    def entry(self, entry_id: str) -> Entry:
        return self._by_id[entry_id]

    def find(self, code: bytes, pos: int):
        """The entry matching at pos, or None. At most one can match (ambiguity is refused at load)."""
        for size, mask, match, entry in (*self._fixed.get(code[pos], ()), *self._loose):
            if pos + size <= len(code) and int.from_bytes(code[pos:pos + size], "big") & mask == match:
                return entry
        return None

    def summary(self) -> dict:
        return {"family": self.family, "entries": len(self.entries), "source": self.source,
                "citations": self.citations, "gate": GATES[self.citations]}


def _oracle(raw, bad) -> tuple:
    if not isinstance(raw, dict):
        bad(f"has no oracle citation: every opcode entry must cite the pinned reference pair that "
            f"proves it ({PAIRS_MANIFEST})")
    if set(raw) != {"pair", "sample_sha256", "listing_sha256"}:
        bad("oracle must hold exactly pair, sample_sha256 and listing_sha256")
    pair, sample, listing = raw["pair"], raw["sample_sha256"], raw["listing_sha256"]
    if not isinstance(pair, str) or not _ID.fullmatch(pair):
        bad("oracle.pair must be a reference pair id")
    for key, digest in (("sample_sha256", sample), ("listing_sha256", listing)):
        if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            bad(f"oracle.{key} must be 64 lower-case hex digits")
    return (pair, sample, listing)


def _operands(raw, length: int, fixed: int, bad) -> tuple:
    if not isinstance(raw, list):
        bad("operands must be a list")
    total, covered, out, names = length * 8, 0, [], set()
    for item in raw:
        if not isinstance(item, dict) or set(item) != {"name", "bit", "width", "format"}:
            bad("an operand must hold exactly name, bit, width and format")
        name, bit, width, fmt = item["name"], item["bit"], item["width"], item["format"]
        if not isinstance(name, str) or not _NAME.fullmatch(name) or name in names:
            bad(f"operand name {name!r} is invalid or repeated")
        if not _is_int(bit) or not _is_int(width) or bit < 0 or not 1 <= width <= 32 or bit + width > total:
            bad(f"operand {name!r} does not lie inside the {total}-bit instruction")
        if fmt not in FORMATS:
            bad(f"operand {name!r} has an unknown format {fmt!r}")
        span = ((1 << width) - 1) << (total - bit - width)
        if span & fixed:
            bad(f"operand {name!r} overlaps bits the entry fixes")
        if span & covered:
            bad(f"operand {name!r} overlaps another operand")
        covered |= span
        names.add(name)
        out.append(Operand(name, bit, width, fmt))
    missing = ~(fixed | covered) & ((1 << total) - 1)
    if missing:
        first = total - missing.bit_length()
        bad(f"bit {first} is neither fixed by the mask nor printed as an operand")
    return tuple(out)


def _entry(raw, family: str, index: int, source: str) -> Entry:
    label = raw.get("id") if isinstance(raw, dict) and isinstance(raw.get("id"), str) else f"#{index}"

    def bad(message: str):
        raise PlcCodeError(f"{source}: {family} entry {label}: {message}")

    if not isinstance(raw, dict):
        bad("must be an object")
    unknown = set(raw) - {"id", "match", "mask", "length", "stl", "operands", "oracle", "note"}
    if unknown:
        bad(f"unknown key(s) {sorted(unknown)}")
    for key in ("id", "match", "length", "stl"):
        if key not in raw:
            bad(f"{key} is required")
    oracle = _oracle(raw.get("oracle"), bad)
    if not isinstance(raw["id"], str) or not _ID.fullmatch(raw["id"]):
        bad("id must be lower-case letters, digits and _.+-")
    if not isinstance(raw["match"], str) or not _HEX.fullmatch(raw["match"]):
        bad("match must be whole bytes in hex")
    match = bytes.fromhex(raw["match"])
    mask_text = raw.get("mask", "ff" * len(match))
    if not isinstance(mask_text, str) or not _HEX.fullmatch(mask_text) or len(mask_text) != len(raw["match"]):
        bad("mask must be hex of the same length as match")
    mask = bytes.fromhex(mask_text)
    if not any(mask):
        bad("mask fixes no bit: the entry would match everything")
    if any(value & ~fixed & 0xFF for value, fixed in zip(match, mask)):
        bad("match has bits set outside the mask")
    length = raw["length"]
    if not _is_int(length) or not len(match) <= length <= MAX_INSTRUCTION or length % FAMILIES[family]:
        bad(f"length must be {len(match)}..{MAX_INSTRUCTION} bytes and a multiple of {FAMILIES[family]}")
    stl = raw["stl"]
    if not isinstance(stl, str) or not stl.strip() or len(stl) > 200 or "\n" in stl or "\r" in stl:
        bad("stl must be one non-empty line")
    fixed = int.from_bytes(mask, "big") << (length - len(mask)) * 8
    operands = _operands(raw.get("operands", []), length, fixed, bad)
    placeholders = _PLACEHOLDER.findall(stl)
    if sorted(placeholders) != sorted(operand.name for operand in operands):
        bad("each operand must appear in stl exactly once, and stl may name only operands")
    if set("{}") & set(_PLACEHOLDER.sub("", stl)):
        bad("stl has an unbalanced brace")
    return Entry(raw["id"], match, mask, length, stl, operands, oracle)


def _refuse_ambiguity(entries, source: str) -> None:
    for index, first in enumerate(entries):
        for second in entries[index + 1:]:
            shared = min(len(first.match), len(second.match))
            both = int.from_bytes(first.mask[:shared], "big") & int.from_bytes(second.mask[:shared], "big")
            differ = int.from_bytes(first.match[:shared], "big") ^ int.from_bytes(second.match[:shared], "big")
            if not differ & both:
                raise PlcCodeError(f"{source}: entries {first.id!r} and {second.id!r} can match the same "
                                   f"bytes; a table must be unambiguous")


def parse_table(obj, family: str = "mc7", source: str = "<object>") -> Table:
    """Validate a table object and return the family's Table. Refuses an entry with no oracle."""
    if not isinstance(family, str) or family not in FAMILIES:
        raise PlcCodeError(f"no opcode table family {family!r} (known: {', '.join(sorted(FAMILIES))})")
    if not isinstance(obj, dict) or obj.get("schema") != TABLE_SCHEMA:
        raise PlcCodeError(f"{source}: not a {TABLE_SCHEMA} opcode table")
    unknown = set(obj) - {"schema", "note", "families", "untabled"}
    if unknown:
        raise PlcCodeError(f"{source}: unknown key(s) {sorted(unknown)}")
    families = obj.get("families")
    if not isinstance(families, dict) or not isinstance(families.get(family), dict):
        raise PlcCodeError(f"{source}: the table has no {family!r} family")
    raw_entries = families[family].get("entries")
    if not isinstance(raw_entries, list) or set(families[family]) - {"entries", "note"}:
        raise PlcCodeError(f"{source}: family {family!r} must hold an entries list (and at most a note)")
    if len(raw_entries) > MAX_ENTRIES:
        raise PlcCodeError(f"{source}: family {family!r} has more than {MAX_ENTRIES} entries")
    entries, seen = [], set()
    for index, raw in enumerate(raw_entries):
        entry = _entry(raw, family, index, source)
        if entry.id in seen:
            raise PlcCodeError(f"{source}: {family} entry id {entry.id!r} is used twice")
        seen.add(entry.id)
        entries.append(entry)
    _refuse_ambiguity(entries, source)
    return Table(family, entries, source)


def read_table(family: str = "mc7", path=None) -> Table:
    """Read and validate a family's table from path (default: the shipped table). A missing file
    is an error. The citations are not held to a pair manifest here: load_table does that."""
    path = Path(_local_path(path, "the opcode table path")) if path is not None else TABLE_PATH
    try:
        data = _read_regular(path, MAX_TABLE)
    except PlcCodeError as exc:
        raise PlcCodeError(f"opcode table not readable: {exc}") from exc
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise PlcCodeError(f"{path}: the opcode table is not valid JSON: {exc}") from exc
    return parse_table(obj, family, str(path))


def pairs_manifest_path() -> Path:
    """Where reference pairs are pinned: beside the opcode table, so a run needs nothing under tests/."""
    return PAIRS_PATH


def read_pairs(path) -> list:
    """The pinned pairs of a reference-pair manifest file. Missing or malformed is an error."""
    try:
        data = _read_regular(path, MAX_MANIFEST)
    except PlcCodeError as exc:
        raise PlcCodeError(f"reference-pair manifest not readable: {exc}") from exc
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise PlcCodeError(f"{path}: not valid JSON: {exc}") from exc
    return parse_pairs(obj)


def load_table(family: str = "mc7", path=None, manifest=None) -> Table:
    """The table a report decodes with: read_table, then every citation held to the pair manifest
    (default: this checkout's). The shipped table (path None) is refused when an entry cites a
    pair the manifest does not pin. Any other table still loads, with citations 'unpinned', so
    its reports say that what it decodes is unverified."""
    table = read_table(family, path)
    faults = citation_problems(table, read_pairs(pairs_manifest_path() if manifest is None else manifest))
    if not faults:
        table.citations = "pinned" if table.entries else "empty"
    elif path is None:
        more = f" (and {len(faults) - 1} more)" if len(faults) > 1 else ""
        raise PlcCodeError(f"the shipped opcode table is refused: {faults[0]}{more}")
    else:
        table.citations = "unpinned"
    return table


# ---- the decoder -----------------------------------------------------------------------------------

def decode(code, table: Table, boundaries=()) -> dict:
    """Decode code from offset 0 with table, stopping at the first position no entry matches.

    boundaries are offsets where a network starts. They are a check, not a resync point: an
    instruction that would run across one stops the decode, because then the table or the network
    table is wrong. Nothing after the stop is decoded.
    """
    code = _blob(code, MAX_CODE, "code")
    marks = sorted({mark for mark in boundaries if _is_int(mark)})
    statements, pos, stop = [], 0, None
    while pos < len(code):
        entry = table.find(code, pos)
        if entry is None:
            reason = (f"the {table.family} opcode table is empty: no reference pair exists to prove an "
                      f"entry ({PAIRS_MANIFEST})") if not table.entries else (
                      "no table entry matches the bytes here; decoding stops and never resynchronises")
            stop = {"offset": pos, "reason": reason}
            break
        end = pos + entry.length
        if end > len(code):
            stop = {"offset": pos, "reason": f"entry {entry.id!r} needs {entry.length} bytes, "
                                             f"only {len(code) - pos} remain"}
            break
        nearest = bisect.bisect_right(marks, pos)
        if nearest < len(marks) and marks[nearest] < end:
            stop = {"offset": pos, "reason": f"a network starts at offset {marks[nearest]}, inside the "
                                             f"instruction entry {entry.id!r} decodes at offset {pos}: "
                                             f"the table or the network table is wrong"}
            break
        raw = code[pos:end]
        statements.append({"offset": pos, "size": entry.length, "hex": raw.hex(),
                           "stl": entry.render(raw), "entry": entry.id})
        pos = end
    return {"size": len(code), "decoded_bytes": pos, "complete": pos == len(code),
            "statements": statements, "stop": stop}


# ---- reports ---------------------------------------------------------------------------------------

def _code_report(out: dict, body: bytes, table: Table, offsets, file_offset: int = 0) -> dict:
    """Fill out with the decode of body. Every offset in it counts from the start of the code
    section; code.file_offset says where that section starts in the artifact."""
    starts = list(offsets) if offsets else [0]
    decoded = decode(body, table, boundaries=starts[1:])
    done = decoded["decoded_bytes"]
    networks = []
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(body)
        networks.append({
            "index": index + 1, "offset": start, "size": end - start, "sha256": _sha256(body[start:end]),
            "decoded": done >= end,
            "statements": [item for item in decoded["statements"] if start <= item["offset"] < end]})
    out["network_table"] = bool(offsets)
    out["code"] = {"file_offset": file_offset, "size": len(body), "sha256": _sha256(body),
                   "decoded_bytes": done,
                   "coverage": round(done / len(body), 4) if body else 0.0,
                   "complete": decoded["complete"]}
    out["networks"] = networks
    out["opaque"], out["stl"], out["logic"], out["logic_error"] = None, None, None, None
    if not body:
        out.update(status="no-code", reason="the block's code section is empty", human_steps=[])
        return out
    if decoded["complete"]:
        out["stl"] = "".join("NETWORK\n" + "".join(item["stl"] + "\n" for item in network["statements"])
                             for network in networks)
        try:
            logic = plc_logic_depth.parse_awl(out["stl"])
            out["logic"] = {key: value for key, value in logic.items() if key != "instructions"}
        except plc_logic_depth.ParseError as exc:
            out["logic_error"] = f"plc_logic_depth could not read the listing: {exc}"
        out.update(status="decoded", reason=None, human_steps=[])
        return out
    rest = body[done:]
    out["opaque"] = {"offset": done, "size": len(rest), "sha256": _sha256(rest),
                     "hex": rest[:MAX_PREVIEW].hex(), "hex_truncated": len(rest) > MAX_PREVIEW}
    out.update(status="partial" if done else "opaque",
               reason=f"offset {decoded['stop']['offset']}: {decoded['stop']['reason']}",
               human_steps=list(MC7_HUMAN_STEPS))
    return out


def analyze_mc7(data, table: Table) -> dict:
    """Report on one complete classic MC7 online block (36-byte header .. 36-byte footer)."""
    data = _blob(data, ot_s7deep_project.MAX_ARTIFACT, "MC7 block")
    try:
        block = ot_s7deep_project.parse_mc7_block(data)
    except ot_s7deep_project.S7DeepError as exc:
        raise PlcCodeError(f"not a readable MC7 block: {exc}") from exc
    meta = block["metadata"]
    out = {"format": REPORT, "family": "mc7", "kind": "mc7", "table": table.summary(),
           "block": {"type": meta["block_type"], "number": meta["block_number"],
                     "language": meta["language"], "name": meta["name"], "author": meta["author"],
                     "version": meta["version"], "checksum_valid": block["checksum"]["valid"]}}
    if "code" not in block:
        out.update(status="no-code", network_table=False, code=None, networks=[], opaque=None, stl=None,
                   logic=None, logic_error=None, human_steps=[],
                   reason=f"a {meta['block_type']} block holds data, not code; read its values with "
                          f"ot_s7deep_project")
        return out
    region, table_info = block["code"], block["segment_table"]
    body = data[region["offset"]:region["offset"] + region["size"]]
    # an absent, empty or inconsistent network table leaves the code as one slice
    offsets = table_info["network_offsets"] if table_info.get("network_table_valid") else None
    return _code_report(out, body, table, offsets, region["offset"])


def analyze_mc7_code(code, table: Table) -> dict:
    """Report on bare MC7 code bytes (for example a recovered MC5CODE memo). No network table."""
    code = _blob(code, MAX_CODE, "MC7 code")
    out = {"format": REPORT, "family": "mc7", "kind": "mc7-code", "table": table.summary(), "block": None}
    return _code_report(out, code, table, None)


def analyze_codesys(data, name: str = "<bytes>") -> dict:
    """Report on one CODESYS artifact. Its application code is never decoded: there is no oracle."""
    try:
        inventory = ot_codesys_native.analyze_bytes(data, name=name)
    except ot_codesys_native.CodesysError as exc:
        # The inventory wraps every fault in one fixed message. A configuration fault (an unset or
        # unknown CTF_EVENT, which its flag scan needs) is worth reading and its text is ours, so it
        # is printed. Any other cause is a parser fault whose message can quote the artifact (a ZIP
        # member name is up to 64 KB of untrusted text): only its class is named.
        cause = exc.__cause__
        if isinstance(cause, _event.EventError):
            raise PlcConfigError(f"the CODESYS inventory (ot_codesys_native) failed: {exc} "
                                 f"(cause: {cause})") from exc
        detail = f" (cause: {type(cause).__name__})" if cause is not None else ""
        raise PlcCodeError(f"the CODESYS inventory (ot_codesys_native) failed: {exc}{detail}") from exc
    out = {"format": REPORT, "family": "codesys", "kind": "codesys", "table": None,
           "artifact": {key: inventory[key] for key in ("size", "sha256", "role_hint", "signature", "format")},
           "strings": len(inventory["strings"]), "symbol_candidates": len(inventory["symbol_candidates"])}
    if inventory["format"] in ("opaque", "zip-container"):
        out.update(status="opaque", human_steps=list(CODESYS_HUMAN_STEPS),
                   reason="CODESYS application code is not decoded: no reference pair (application + "
                          f"known source) exists to prove a layout or a table ({PAIRS_MANIFEST})")
    else:
        out.update(status="not-compiled", human_steps=[],
                   reason=f"this is a readable {inventory['format']} artifact, not compiled code: read it "
                          f"with ot_codesys_native")
    return out


# ---- reference pairs: the oracle -------------------------------------------------------------------

def listing_networks(listing) -> list:
    """A known source listing as networks of normalised statements.

    One statement per line; // comments, blank lines and TITLE lines are dropped; a NETWORK line
    starts a network (statements before the first one form a network of their own).
    """
    if isinstance(listing, (bytes, bytearray)):
        listing = _blob(listing, MAX_LISTING, "listing").decode("latin-1")
    if not isinstance(listing, str) or len(listing) > MAX_LISTING:
        raise PlcCodeError("the listing must be text within the size limit")
    networks, current = [], None
    for line in listing.splitlines():
        line = line.split("//", 1)[0].strip().rstrip(";").strip()
        if not line or _TITLE.match(line):
            continue
        if _NETWORK.match(line):
            current = []
            networks.append(current)
            continue
        if current is None:
            current = []
            networks.append(current)
        current.append(_norm(line))
    return networks


def check_pair(table: Table, sample, listing, kind: str = "mc7") -> dict:
    """Decode sample and compare it with its known listing. ok only on a complete, exact match.
    agrees says nothing decoded contradicts the listing: true when ok, and when the decode stopped
    early with every statement before the stop equal to the listing's."""
    if kind not in KINDS:
        raise PlcCodeError(f"unknown pair kind {kind!r} (known: {', '.join(KINDS)})")
    report = analyze_mc7(sample, table) if kind == "mc7" else analyze_mc7_code(sample, table)
    if report["status"] == "no-code":
        raise PlcCodeError(f"the sample holds no code: {report['reason']}")
    want = listing_networks(listing)
    if not any(want):
        raise PlcCodeError("the listing holds no statements")
    got = [[_norm(item["stl"]) for item in network["statements"]] for network in report["networks"]]
    if not report["network_table"]:
        want = [[statement for network in want for statement in network]]
    result = {"ok": False, "agrees": False, "complete": report["code"]["complete"],
              "statements": sum(map(len, got)), "expected_statements": sum(map(len, want)),
              "entries_used": sorted({item["entry"] for network in report["networks"]
                                      for item in network["statements"]}),
              "mismatch": None, "reason": None}
    if len(got) != len(want):
        result["reason"] = f"the sample has {len(got)} network(s), the listing {len(want)}"
        return result
    for number, (decoded, known) in enumerate(zip(got, want), 1):
        for index, statement in enumerate(decoded):
            if index >= len(known) or statement != known[index]:
                result["mismatch"] = {"network": number, "index": index, "got": statement,
                                      "want": known[index] if index < len(known) else None}
                result["reason"] = "a decoded statement differs from the listing"
                return result
    if not result["complete"]:
        result["agrees"] = True
        result["reason"] = f"incomplete: {report['reason']}"
        return result
    for number, (decoded, known) in enumerate(zip(got, want), 1):
        if len(decoded) < len(known):
            result["mismatch"] = {"network": number, "index": len(decoded), "got": None,
                                  "want": known[len(decoded)]}
            result["reason"] = "the listing has a statement the sample does not"
            return result
    result["ok"] = result["agrees"] = True
    return result


def parse_pairs(obj) -> list:
    """Validate a plc-pairs-1 manifest and return its pinned pairs. An unpinned pair is refused."""
    if not isinstance(obj, dict) or obj.get("schema") != PAIRS_SCHEMA:
        raise PlcCodeError(f"not a {PAIRS_SCHEMA} reference-pair manifest")
    rows = obj.get("pairs")
    if not isinstance(rows, list) or len(rows) > MAX_PAIRS:
        raise PlcCodeError(f"pairs must be a list of at most {MAX_PAIRS} rows")
    seen, out = set(), []
    for index, row in enumerate(rows):
        label = row.get("id") if isinstance(row, dict) and isinstance(row.get("id"), str) else f"#{index}"

        def bad(message: str):
            raise PlcCodeError(f"pair {label}: {message}")

        required = {"id", "family", "kind", "sample", "sample_sha256", "listing", "listing_sha256",
                    "source", "licence"}
        if not isinstance(row, dict) or not required <= set(row) or set(row) - required - {"note"}:
            bad(f"must hold exactly {sorted(required)} (and at most a note)")
        if not isinstance(row["id"], str) or not _ID.fullmatch(row["id"]) or row["id"] in seen:
            bad("id is invalid or repeated")
        if not isinstance(row["family"], str) or row["family"] not in FAMILIES or row["kind"] not in KINDS:
            bad(f"family must be one of {sorted(FAMILIES)} and kind one of {list(KINDS)}")
        for key in ("sample", "listing"):
            if not isinstance(row[key], str) or not _FILE.fullmatch(row[key]):
                bad(f"{key} must be a plain file name")
            digest = row[key + "_sha256"]
            if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
                bad(f"{key}_sha256 is not pinned (64 lower-case hex digits): an unpinned pair proves nothing")
        for key in ("source", "licence"):
            if not isinstance(row[key], str) or not row[key].strip():
                bad(f"{key} must say where the pair comes from and under what terms")
        seen.add(row["id"])
        out.append(dict(row))
    return out


def citation_problems(table: Table, pairs: list) -> list:
    """Every table entry must cite a pinned pair of its family, digests included. Returns the faults."""
    pinned = {(row["id"], row["sample_sha256"], row["listing_sha256"]) for row in pairs
              if row["family"] == table.family}
    return [f"{table.family} entry {entry.id!r} cites pair {entry.oracle[0]!r}, which is not pinned with "
            f"those digests in the reference-pair manifest"
            for entry in table.entries if entry.oracle not in pinned]


def load_pairs(pairs: list, root) -> list:
    """Read each pinned pair from root/<id>/ and verify both digests. Missing or changed is an error."""
    root, loaded = Path(_local_path(root, "the corpus folder")), []
    for row in pairs:
        item = {"id": row["id"], "family": row["family"], "kind": row["kind"]}
        for key, cap in (("sample", ot_s7deep_project.MAX_ARTIFACT), ("listing", MAX_LISTING)):
            path = root / row["id"] / row[key]
            try:
                data = _read_regular(path, cap)
            except PlcCodeError as exc:
                raise PlcCodeError(f"pair {row['id']}: {key} not readable: {exc}") from exc
            if _sha256(data) != row[key + "_sha256"]:
                raise PlcCodeError(f"pair {row['id']}: {key} {path.name} does not have the pinned sha256")
            item[key] = data
        loaded.append(item)
    return loaded


def verify_table(table: Table, loaded: list) -> dict:
    """Prove the table on loaded pairs. A pair that an entry cites must match completely, and each
    entry must be used by the pair it cites. A pair no entry cites is pinned ahead of the entries
    that will read it: it is 'unused' while the table does not decode all of it, and it fails only
    when something decoded of it differs from its listing. An entry no matching pair exercises is
    unproven, and with no pair held to a full match nothing is proven, so ok is False."""
    cited_ids = {entry.oracle[0] for entry in table.entries}
    results, proven = {}, set()
    for pair in loaded:
        if pair["family"] != table.family:
            continue
        result = check_pair(table, pair["sample"], pair["listing"], pair["kind"])
        result["unused"] = pair["id"] not in cited_ids and result["agrees"] and not result["ok"]
        results[pair["id"]] = result
        if result["ok"]:
            cited = (pair["id"], _sha256(pair["sample"]), _sha256(pair["listing"]))
            proven.update(entry_id for entry_id in result["entries_used"]
                          if table.entry(entry_id).oracle == cited)
    unproven = sorted(entry.id for entry in table.entries if entry.id not in proven)
    held = [result for result in results.values() if not result["unused"]]
    return {"ok": bool(held) and all(result["ok"] for result in held) and not unproven,
            "family": table.family, "pairs": results, "unproven_entries": unproven,
            "unused_pairs": sorted(name for name, result in results.items() if result["unused"])}


def unproven_reasons(table: Table, pairs: list, corpus) -> list:
    """Why table is not proven; [] when it is. An empty table has nothing to prove. A table with
    entries is proven only when every citation is pinned, the corpus folder holds the pinned pairs
    and verify_table passes on them. An absent corpus is a reason, never a pass: this is what
    keeps a table with entries from being accepted on a machine that cannot check it."""
    if not table.entries:
        return []
    faults = citation_problems(table, pairs)
    if faults:
        return faults
    corpus = Path(_local_path(corpus, "the corpus folder"))
    if not corpus.is_dir():
        return [f"the {table.family} table has entries ({len(table.entries)}) and the reference corpus "
                f"folder {corpus} is absent: nothing proves them"]
    try:
        result = verify_table(table, load_pairs(pairs, corpus))
    except PlcCodeError as exc:
        return [str(exc)]
    if result["ok"]:
        return []
    reasons = [f"pair {pair}: {outcome['reason']}" for pair, outcome in sorted(result["pairs"].items())
               if not outcome["ok"] and not outcome["unused"]]
    reasons += [f"entry {entry_id!r} is not exercised by a matching pair that it cites"
                for entry_id in result["unproven_entries"]]
    return reasons


# ---- files -----------------------------------------------------------------------------------------

def _local_path(path, label: str = "a path"):
    if not isinstance(path, (str, os.PathLike)):
        raise PlcCodeError(f"{label} must be a path string or path object, not {type(path).__name__}")
    return path


def _read_regular(path, cap: int) -> bytes:
    fd = None
    try:
        # O_NONBLOCK: opening a FIFO nobody writes to must reach the regular-file check, not hang
        fd = os.open(_local_path(path), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PlcCodeError(f"{path} is not a regular file")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            data = stream.read(cap + 1)
    except OSError as exc:
        raise PlcCodeError(f"cannot read {path}: {exc.strerror or exc}") from exc
    finally:
        if fd is not None:
            os.close(fd)
    if len(data) > cap:
        raise PlcCodeError(f"{path} is over the {cap}-byte limit")
    return data


def _codesys_name(name: str) -> bool:
    return PurePosixPath(name.replace("\\", "/")).suffix.lower() in CODESYS_SUFFIXES


def looks_like_mc7(head: bytes, size: int) -> bool:
    """Whether a file of size bytes that starts with head can be a complete classic MC7 block: the
    'pp' signature, room for the header and footer, and the header's load-size field (bytes 8..11,
    big endian) equal to the file size. The two signature bytes alone say little: text starts with
    them too."""
    return (head[:2] == b"pp" and size >= MC7_MIN and len(head) >= 12
            and int.from_bytes(head[8:12], "big") == size)


def analyze_file(path, kind: str = "auto", table_path=None, *, table=None) -> dict:
    """Report on one local file. kind auto: an MC7 block by its header (looks_like_mc7), CODESYS
    by suffix; a file with only the 'pp' signature goes to the block parser, which names the fault.
    table: an already loaded Table to decode with, instead of loading table_path."""
    data = _read_regular(path, ot_s7deep_project.MAX_ARTIFACT)
    name = str(path)
    if kind == "auto":
        if looks_like_mc7(data[:12], len(data)):
            kind = "mc7"
        elif _codesys_name(name):
            kind = "codesys"
        elif data[:2] == b"pp":
            kind = "mc7"
        else:
            raise PlcCodeError(f"cannot tell what {name} is: pass --kind mc7, mc7-code or codesys")
    if kind == "codesys":
        return analyze_codesys(data, name=name)
    if kind not in KINDS:
        raise PlcCodeError(f"unknown kind {kind!r}")
    if table is None:
        table = load_table("mc7", table_path)
    return analyze_mc7(data, table) if kind == "mc7" else analyze_mc7_code(data, table)


# ---- the engine entry ------------------------------------------------------------------------------

def _probe(path) -> tuple:
    """(the first twelve bytes, the size) of a regular file; (b"", 0) for anything else. Never
    follows a symlink."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        status = os.fstat(fd)
        return (os.read(fd, 12), status.st_size) if stat.S_ISREG(status.st_mode) else (b"", 0)
    finally:
        os.close(fd)


def find_artifacts(root) -> dict:
    """The files under root that solve() reports on: MC7 blocks by their header (looks_like_mc7),
    CODESYS artifacts by suffix. Walks in name order, does not follow symlinks, opens only regular
    files. Returns {"paths", "looked_at", "unreadable", "signature_only", "truncated"}: truncated
    says a cap ended the walk; signature_only counts the files that start with 'pp' and are not a
    block by their header (they are not artifacts and are not reported on)."""
    out = {"paths": [], "looked_at": 0, "unreadable": 0, "signature_only": 0, "truncated": False}
    for folder, subdirs, names in os.walk(_local_path(root, "the challenge folder")):
        subdirs.sort()
        for name in sorted(names):
            path = Path(folder) / name
            try:
                if not stat.S_ISREG(os.lstat(path).st_mode):
                    continue
                if out["looked_at"] >= MAX_SCAN or len(out["paths"]) >= MAX_ARTIFACTS:
                    out["truncated"] = True
                    return out
                out["looked_at"] += 1
                found = _codesys_name(name)
                if not found:
                    head, size = _probe(path)
                    found = looks_like_mc7(head, size)
                    out["signature_only"] += head[:2] == b"pp" and not found
                if found:
                    out["paths"].append(path)
            except OSError:
                out["unreadable"] += 1
    return out


def _evidence_line(report: dict) -> str:
    if report["family"] == "codesys":
        return f"CODESYS artifact ({report['artifact']['format']}): {report['status']}"
    block, code = report["block"], report["code"]
    line = f"MC7 {block['type']} {block['number']}: {report['status']}"
    if code is not None:
        line += (f"; {code['decoded_bytes']} of {code['size']} code bytes decoded, "
                 f"{len(report['networks'])} network(s), code sha256 {code['sha256']}")
    return line


def solve(challenge_dir, profile=None, **opts):
    """Engine contract entry (docs/CONTRACTS.md sections 6 and 7). Reports on every MC7 block and
    CODESYS artifact under challenge_dir with the shipped table. It never finds a flag:

    blocked  compiled PLC logic is there and none of it could be read; notes name the reason (the
             missing reference pair) and the human step
    unsure   at least one block was decoded, in full or in part: it needs a read (run this file
             on the artifact for the listing); or a file that looks like an artifact failed to parse
             and no artifact is opaque (an opaque one comes first: blocked)
    none    no compiled PLC logic found

    Takes no options. Nothing reported depends on the event; profile only supplies the event name
    the CODESYS inventory needs when CTF_EVENT is unset.
    """
    from ctf.result import Evidence, SolverResult

    def result(status: str, notes: str, evidence=()) -> SolverResult:
        return SolverResult(status=status, evidence=tuple(evidence), engine=ENGINE, notes=notes)

    if opts:
        return result("blocked", f"unknown option(s) {', '.join(sorted(opts))}: this engine takes none")
    if not isinstance(challenge_dir, (str, os.PathLike)) or not Path(challenge_dir).is_dir():
        return result("blocked", "the challenge folder does not exist or is not a folder")
    root = Path(challenge_dir)
    try:
        table = load_table("mc7")
    except PlcCodeError as exc:
        return result("blocked", f"the opcode table cannot be used: {str(exc)[:MAX_NOTE]}")
    found = find_artifacts(root)
    evidence, statuses, reason = [], [], None
    # ot_codesys_native reads the event from CTF_EVENT (its flag scan), never from a profile. When
    # the runner hands over a profile (ctf run ... --event SLUG) and CTF_EVENT is unset, the
    # profile's slug stands in for the length of the scan. Nothing reported here depends on which
    # event it is.
    slug = getattr(profile, "slug", None)
    lend = isinstance(slug, str) and bool(slug) and not _env.get("CTF_EVENT")
    if lend:
        os.environ["CTF_EVENT"] = slug
    try:
        for path in found["paths"]:
            rel = path.relative_to(root).as_posix()
            try:
                report = analyze_file(path, "auto", table=table)
            except PlcConfigError as exc:           # every CODESYS artifact would fail the same way
                return result("blocked", f"the run is misconfigured: {str(exc)[:MAX_NOTE]}")
            except PlcCodeError as exc:
                statuses.append("unparsed")
                evidence.append(Evidence("plc-code", f"not read: {str(exc)[:MAX_NOTE]}", rel))
                continue
            statuses.append(report["status"])
            evidence.append(Evidence("plc-code", _evidence_line(report), rel))
            if reason is None and report["status"] == "opaque":
                reason = f"{report['reason']}. Human step: {report['human_steps'][0]}"
    finally:
        if lend:
            del os.environ["CTF_EVENT"]
    scanned = f"{found['looked_at']} file(s) looked at" + (
        f", the walk stopped at a cap ({MAX_SCAN} files, {MAX_ARTIFACTS} artifacts)" if found["truncated"] else "") + (
        f", {found['unreadable']} could not be opened" if found["unreadable"] else "") + (
        f", {found['signature_only']} not an MC7 block despite the 'pp' signature"
        if found["signature_only"] else "")
    counts = ", ".join(f"{statuses.count(name)} {name}" for name in sorted(set(statuses)))
    if "decoded" in statuses or "partial" in statuses:
        return result("unsure", f"compiled PLC logic was decoded at least in part ({counts}; {scanned}): "
                                f"read the listing with ot_plc_code.py <artifact>", evidence)
    if "opaque" in statuses:
        return result("blocked", f"compiled PLC logic cannot be read ({counts}; {scanned}): {reason}", evidence)
    if "unparsed" in statuses:
        return result("unsure", f"a file that looks like compiled PLC logic could not be parsed ({counts}; "
                                f"{scanned}): the evidence names each fault", evidence)
    return result("none", f"no compiled PLC logic found ({counts or 'no MC7 block or CODESYS artifact'}; "
                          f"{scanned})", evidence)


# ---- command line ----------------------------------------------------------------------------------

def _verify_pairs(manifest_path, corpus, table_path) -> tuple:
    # the citations are held to the manifest named on the command line, so the table is only read here
    pairs, table = read_pairs(manifest_path), read_table("mc7", table_path)
    faults = citation_problems(table, pairs)
    if faults:
        return {"ok": False, "citation_problems": faults}, 1
    if not pairs:
        return {"ok": False, "pairs": {}, "unproven_entries": [],
                "note": "no pinned reference pair in the manifest: nothing was proven"}, 1
    result = verify_table(table, load_pairs(pairs, corpus))
    if not table.entries:
        result["note"] = (f"the table is empty: {len(result['unused_pairs'])} pinned pair(s) read, unused; "
                          f"nothing was proven")
    return result, 0 if result["ok"] else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Oracle-gated reader for compiled PLC logic (MC7, CODESYS). Offline and static.")
    parser.add_argument("artifact", nargs="?", help="an MC7 block, bare MC7 code or a CODESYS artifact")
    parser.add_argument("--kind", choices=("auto", "mc7", "mc7-code", "codesys"), default="auto")
    parser.add_argument("--table", help="opcode table to use instead of the shipped one")
    parser.add_argument("--listing", help="known source listing of the artifact: compare, exit 0 on a match")
    parser.add_argument("--table-status", action="store_true", help="print what the table holds")
    parser.add_argument("--verify-pairs", metavar="MANIFEST", help="prove the table on a pair manifest")
    parser.add_argument("--corpus", help="folder holding <pair id>/<files> for --verify-pairs")
    return parser


def main(argv=None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        code = 0
        if args.table_status:
            result = load_table("mc7", args.table).summary()
        elif args.verify_pairs:
            if not args.corpus:
                raise PlcCodeError("--verify-pairs needs --corpus DIR")
            result, code = _verify_pairs(args.verify_pairs, args.corpus, args.table)
        elif not args.artifact:
            raise PlcCodeError("name an artifact, or use --table-status or --verify-pairs")
        elif args.listing:
            kind = "mc7" if args.kind == "auto" else args.kind
            if kind not in KINDS:
                raise PlcCodeError("--listing compares MC7 only (--kind mc7 or mc7-code)")
            result = check_pair(load_table("mc7", args.table),
                                _read_regular(args.artifact, ot_s7deep_project.MAX_ARTIFACT),
                                _read_regular(args.listing, MAX_LISTING), kind)
            code = 0 if result["ok"] else 1
        else:
            result = analyze_file(args.artifact, args.kind, args.table)
        print(json.dumps(result, indent=2, sort_keys=True))
        return code
    except PlcCodeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
