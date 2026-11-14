#!/usr/bin/env python3
"""Minecraft Java world-folder walker: level.dat, regions, player data, signs, books and item names.

``research_ff_nbt`` parses one NBT stream or one ``.mca`` region and ``ffgame_anvil_semantics`` adds
one region's chunk semantics.  This module is the world-level layer on top of both (B-120): it finds
every world folder under a path, reads each surface a flag can sit on, and reports the text a player
would have to walk the world to read, with where it is.

Surfaces, cheapest first:

* ``level.dat`` (and ``level.dat_old``): world name, version, spawn, seed, the single-player inventory;
* ``playerdata/*.dat`` / ``players/*.dat``: inventories and ender chests (books, named items);
* ``data/*.dat``: scoreboards, command storage, map items (map colours are not rendered);
* every other file in the folder (datapack functions, ``server.properties``, stats, advancements): a
  raw scan for the event flag format;
* every ``.mca`` under ``region/``, ``entities/`` and ``poi/`` of every dimension, nearest the world
  spawn first: each chunk is inflated, and one whose bytes hold a flag lead (``PREFIX{``) or a tag
  that carries text (a sign, a book, a named item or mob, a command block) is parsed and walked, so
  every string is scanned on its own and a sign's four lines, a book's pages and a text component's
  ``extra`` pieces are read as the game shows them, with block coordinates;
* each region file is also scanned whole, so plain text left in slack or in a freed sector is seen;
* a region with data left in unallocated sectors gets the deep pass: ``ffgame_anvil_semantics`` for
  chunk-coordinate anomalies, and the orphaned chunks (a sign that was edited or removed is often
  still there) walked like live ones and marked ``deleted``.

A flag that is contiguous in the stored data is ``direct``; one that only appears once a text component
is flattened is ``component``; one that only appears when a sign's lines or a book's pages are joined is
``joined`` (a candidate, never a solve on its own).

Nothing is executed and nothing outside the given path is opened: ``.mcc`` files are read only when
they sit inside the walked folder, symlinks are not followed, and ``.ctf`` / ``.git`` folders are never
entered.  Bedrock worlds (LevelDB) are named and skipped.  Work is bounded by a CPU-time budget, read
before each file and before each chunk is inflated, and by a cap on what one region's chunks may
inflate to; what was not reached, and what a cap cut, is listed with a count, never dropped silently.

Entry ``solve(challenge_dir, profile) -> SolverResult`` is the intake engine; ``walk()`` returns the
full report and ``main()`` prints it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import time
import zlib
from pathlib import Path
from typing import Any, Callable

import ffgame_anvil_semantics as _anvil
import research_ff_nbt as _nbt

# ctf package import (script runs need the checkout root on sys.path), mirroring the sibling toolkits.
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt
from ctf import event as _event


ENGINE_ID = "toolkits.minecraft_world"

DEFAULT_BUDGET_S = 20.0            # CPU seconds for solve() (intake); the CLI default is larger
CLI_BUDGET_S = 120.0
MAX_WALK_FILES = 50_000
MAX_WORLDS = 16
MAX_AUX_FILE = 8 << 20             # raw flag scan of a non-NBT, non-region file
MAX_NBT_FILE = _nbt.MAX_NBT_INPUT
MAX_REGION_FILE = _nbt.MAX_REGION_INPUT
MAX_NBT_INFLATED = 64 << 20
MAX_CHUNK_INFLATED = 16 << 20
MAX_REGION_INFLATED = _nbt.MAX_REGION_TOTAL_DECOMPRESSED   # all the chunks of one region file together
MAX_RECORDS = 4000
MAX_PARTS = 256
MAX_PART_CHARS = 4096
MAX_FLAGS = 256
MAX_FLAG_SOURCES = 8
MAX_SKIPPED = 200
MAX_ANOMALIES = 200
MAX_JSON_COMPONENT = 1 << 18
MAX_COMPONENT_NODES = 4096
MAX_EVIDENCE = 16

SECTOR = 4096
REGION_SLOTS = 1024
_PRUNE_DIRS = frozenset({".ctf", ".git"})
_REGION_NAME = re.compile(r"r\.(-?\d{1,9})\.(-?\d{1,9})\.mca")
_FORMAT_CODE = re.compile("§[0-9A-FK-ORXa-fk-orx]")
_NBT_SUFFIXES = (".nbt", ".schem", ".schematic", ".litematic")
_MCA_KINDS = ("region", "entities", "poi")
_HOW_RANK = {"direct": 0, "component": 1, "joined": 2}


class MinecraftWorldError(ValueError):
    """A path, option or flag format the walker cannot work with."""


def _fail(message: str) -> MinecraftWorldError:
    return MinecraftWorldError(message)


# --------------------------------------------------------------------------- text components
def strip_formatting(text: str) -> str:
    """Remove legacy section-sign formatting codes, which split a word without showing in game."""
    return _FORMAT_CODE.sub("", text)


def json_component_text(value: Any, cut: list[bool] | None = None) -> str:
    """Plain text of a parsed JSON text component: its text, then ``with`` arguments, then ``extra``.
    At most MAX_COMPONENT_NODES values are read; ``cut`` (a list) gets a True when more were left."""
    out: list[str] = []
    stack: list[Any] = [value]
    steps = 0
    while stack and steps < MAX_COMPONENT_NODES:
        steps += 1
        current = stack.pop()
        if isinstance(current, str):
            out.append(current)
        elif isinstance(current, bool):
            out.append("true" if current else "false")
        elif isinstance(current, (int, float)):
            out.append(str(current))
        elif isinstance(current, list):
            stack.extend(reversed(current))
        elif isinstance(current, dict):
            for key in ("extra", "with"):                 # pushed first, so read last
                child = current.get(key)
                if isinstance(child, list):
                    stack.append(child)
            for key in ("text", "fallback", "translate"):  # the first of these is what is shown
                if key in current and not isinstance(current[key], (dict, list)):
                    stack.append(current[key])
                    break
    if stack and cut is not None:
        cut.append(True)
    return "".join(out)


_NOT_JSON = object()


def _parse_json(raw: str) -> Any:
    """The JSON value a stored string holds (an object, array or string), or ``_NOT_JSON``."""
    stripped = raw.strip()
    if stripped[:1] in ("{", "[", '"') and len(stripped) <= MAX_JSON_COMPONENT:
        try:
            return json.loads(stripped)
        except (ValueError, RecursionError):
            pass
    return _NOT_JSON


def json_strings(value: Any, cut: list[bool] | None = None) -> list[str]:
    """Every string value in a parsed JSON value, up to MAX_COMPONENT_NODES values read; ``cut`` (a
    list) gets a True when more were left unread."""
    out: list[str] = []
    stack: list[Any] = [value]
    steps = 0
    while stack and steps < MAX_COMPONENT_NODES:
        steps += 1
        current = stack.pop()
        if isinstance(current, str):
            out.append(current)
        elif isinstance(current, list):
            stack.extend(reversed(current))
        elif isinstance(current, dict):
            stack.extend(reversed(list(current.values())))
    if stack and cut is not None:
        cut.append(True)
    return out


def component_text(raw: str) -> str:
    """Plain text of a stored text component: its JSON flattened when it is JSON, else the string."""
    parsed = _parse_json(raw)
    return raw if parsed is _NOT_JSON else json_component_text(parsed)


# --------------------------------------------------------------------------- NBT tree helpers
def _fields(node: object) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    if isinstance(node, dict) and node.get("type") == "compound" and isinstance(node.get("value"), list):
        for child in node["value"]:
            if isinstance(child, dict) and isinstance(child.get("name"), str):
                out.setdefault(child["name"], child)
    return out


def _items(node: object) -> list[Any]:
    if isinstance(node, dict) and node.get("type") == "list":
        value = node.get("value")
        if isinstance(value, dict) and isinstance(value.get("items"), list):
            return value["items"]
    return []


def _text(node: object) -> str | None:
    if isinstance(node, dict) and node.get("type") == "string" and isinstance(node.get("value"), str):
        return node["value"]
    return None


def _int(node: object) -> int | None:
    if isinstance(node, dict) and node.get("type") in ("byte", "short", "int", "long"):
        value = node.get("value")
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None


def _node_text(node: object) -> str:
    """Plain text of a text component stored as NBT: a JSON string (to 1.21.4) or a compound/list."""
    out: list[str] = []
    stack: list[Any] = [node]
    steps = 0
    while stack and steps < MAX_COMPONENT_NODES:
        steps += 1
        current = stack.pop()
        if not isinstance(current, dict):
            continue
        kind, value = current.get("type"), current.get("value")
        if kind == "string" and isinstance(value, str):
            out.append(component_text(value))
        elif kind in ("byte", "short", "int", "long", "float", "double"):
            out.append(str(value))
        elif kind == "list":
            stack.extend(reversed(_items(current)))
        elif kind == "compound":
            fields = _fields(current)
            for key in ("extra", "with"):
                if key in fields:
                    stack.append(fields[key])
            for key in ("text", "fallback", "translate"):
                if key in fields:
                    stack.append(fields[key])
                    break
    return "".join(out)


def _position(fields: dict[str, dict[str, Any]]) -> list[int] | None:
    block = [_int(fields.get(axis)) for axis in ("x", "y", "z")]
    if all(value is not None for value in block):
        return block  # type: ignore[return-value]
    pos = _items(fields.get("Pos"))
    if len(pos) == 3:
        coords = []
        for item in pos:
            value = item.get("value") if isinstance(item, dict) else None
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
                return None
            coords.append(math.floor(value))
        return coords
    return None


def _join(path: str, name: str) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]{0,79}", name):
        name = json.dumps(name[:80], ensure_ascii=True)
    return f"{path}.{name}"


# --------------------------------------------------------------------------- the harvest
def _lead_needles(ff: flagfmt.FlagFormat) -> tuple[bool, tuple[bytes, ...]] | None:
    """Literal ``PREFIX{`` byte strings that every flag of this format starts with, or None when the
    format has no known prefix (then every blob goes to the regex)."""
    prefixes = ff.spec.prefixes
    if not prefixes:
        return None
    fold = ff.spec.case != "exact"
    return fold, tuple(((p.lower() if fold else p) + "{").encode("ascii") for p in prefixes)


def _has_lead(blob: bytes, lead: tuple[bool, tuple[bytes, ...]] | None) -> bool:
    if lead is None:
        return True
    fold, needles = lead
    hay = blob.lower() if fold else blob
    return any(needle in hay for needle in needles)


class _Harvest:
    """Flags, text records, skips and anomalies of one walk, all bounded."""

    def __init__(self, ff: flagfmt.FlagFormat) -> None:
        self.ff = ff
        self.lead = _lead_needles(ff)
        self.flags: dict[str, dict[str, Any]] = {}
        self.flags_dropped = 0
        self.records: list[dict[str, Any]] = []
        self.records_dropped = 0
        self.skipped: list[dict[str, str]] = []
        self.skipped_dropped = 0
        self.anomalies: list[dict[str, Any]] = []
        self.anomalies_dropped = 0
        self.stats: dict[str, int] = {}

    def count(self, key: str, amount: int = 1) -> None:
        self.stats[key] = self.stats.get(key, 0) + amount

    def skip(self, what: str, why: str) -> None:
        if len(self.skipped) < MAX_SKIPPED:
            self.skipped.append({"what": what, "why": why})
        else:
            self.skipped_dropped += 1

    def anomaly(self, row: dict[str, Any]) -> None:
        if len(self.anomalies) < MAX_ANOMALIES:
            self.anomalies.append(row)
        else:
            self.anomalies_dropped += 1

    def flag(self, flag: str, how: str, source: dict[str, Any]) -> None:
        entry = self.flags.get(flag)
        if entry is None:
            if len(self.flags) >= MAX_FLAGS:
                self.flags_dropped += 1
                return
            entry = self.flags[flag] = {"flag": flag, "how": how, "sources": []}
        elif _HOW_RANK[how] < _HOW_RANK[entry["how"]]:
            entry["how"] = how
        if len(entry["sources"]) < MAX_FLAG_SOURCES and source not in entry["sources"]:
            entry["sources"].append(source)

    def has_lead(self, blob: bytes) -> bool:
        """Could ``blob`` hold a flag?  A literal search when the prefixes are known, else the regex."""
        if self.lead is None:
            return self.ff.bregex.search(blob) is not None
        return _has_lead(blob, self.lead)

    def scan_bytes(self, blob: bytes, source: dict[str, Any]) -> list[str]:
        """Flags in raw bytes (a file that is not NBT, a chunk that did not parse).  A loose flag body
        can run from a prefix across binary data to the next brace: a hit with a control character in
        it is dropped and counted, never reported."""
        if not self.has_lead(blob):
            return []
        found = []
        for flag in self.ff.find_flags(blob):
            if any(ord(char) < 0x20 or ord(char) == 0x7F for char in flag):
                self.count("byte_hits_dropped_nonprintable")
                continue
            if not flag.isascii():                 # stored strings are UTF-8; the bytes regex reads latin-1
                try:
                    flag = flag.encode("latin-1").decode("utf-8")
                except UnicodeError:
                    pass
            self.flag(flag, "direct", source)
            found.append(flag)
        return found

    def scan_text(self, text: str, how: str, source: dict[str, Any]) -> list[str]:
        found = self.ff.find_flags(text)
        for flag in found:
            self.flag(flag, how, source)
        return found

    def string(self, value: str, source: dict[str, Any]) -> None:
        """One stored string: as stored, then as the game shows it.  A string that is JSON (a text
        component) is scanned one string value at a time, so a hit never runs across JSON syntax."""
        source = {**source, "surface": "string"}
        parsed = _parse_json(value)
        if parsed is _NOT_JSON:
            found = self.scan_text(value, "direct", source)
            shown = strip_formatting(value)
        else:
            found = []
            cut: list[bool] = []
            for leaf in json_strings(parsed, cut):
                found.extend(f for f in self.scan_text(leaf, "direct", source) if f not in found)
            shown = strip_formatting(json_component_text(parsed, cut))
            if cut:                            # too many values to read one by one: the stored text as it is
                self.count("text_components_cut")
                self.skip(f"{source.get('file', '?')} {source.get('path', '?')}",
                          f"text component holds more than {MAX_COMPONENT_NODES} values: past that it was "
                          "searched as stored text, not value by value")
                found.extend(f for f in self.scan_text(value, "direct", source) if f not in found)
        if shown != value:
            found = found + [f for f in self.scan_text(shown, "component", source) if f not in found]
        if found:
            self._keep({**source, "parts": [shown[:MAX_PART_CHARS]],
                        "text": shown[:MAX_PART_CHARS], "flags": found})

    def record(self, surface: str, parts: list[str], source: dict[str, Any],
               extra: dict[str, Any] | None = None) -> None:
        """One readable thing (a sign side, a book, a name): its parts and their join."""
        parts = [strip_formatting(part) for part in parts[:MAX_PARTS]]
        if not any(part.strip() for part in parts):
            return
        source = {**source, "surface": surface}
        found: list[str] = []
        for part in parts:
            found.extend(f for f in self.scan_text(part, "component", source) if f not in found)
        if len(parts) > 1:
            # joined with nothing between the parts, so the previous part's last letter must not hide a
            # flag that starts the next one: the form with no left boundary
            for flag in dict.fromkeys(m.group(0) for m in self.ff.packed_regex.finditer("".join(parts))):
                if flag not in found:
                    self.flag(flag, "joined", source)
                    found.append(flag)
        row = {**source, "parts": [part[:MAX_PART_CHARS] for part in parts],
               "text": "\n".join(part[:MAX_PART_CHARS] for part in parts).strip(), "flags": found}
        if extra:
            row.update(extra)
        self._keep(row)

    def _keep(self, row: dict[str, Any]) -> None:
        if len(self.records) < MAX_RECORDS:
            self.records.append(row)
        else:
            self.records_dropped += 1


_NAME_SURFACES = {
    "CustomName": "custom-name", "custom_name": "custom-name", "minecraft:custom_name": "custom-name",
    "minecraft:item_name": "item-name", "Command": "command", "LastOutput": "command-output",
    "LevelName": "level-name", "DisplayName": "display-name",
}


def _page_text(item: object) -> str:
    fields = _fields(item)
    if "raw" in fields:                       # 1.20.5+: {raw: <component>, filtered: <component>}
        return _node_text(fields["raw"])
    return _node_text(item)


def _emit_records(fields: dict[str, dict[str, Any]], path: str, source: dict[str, Any],
                  ident: str | None, hv: _Harvest) -> None:
    def at(sub: str) -> dict[str, Any]:
        row = {**source, "path": _join(path, sub)}
        if ident:
            row["id"] = ident
        return row

    for side in ("front_text", "back_text"):                       # 1.20+ signs
        side_fields = _fields(fields.get(side))
        if side_fields:
            lines = [_node_text(item) for item in _items(side_fields.get("messages"))]
            hv.record("sign", lines, at(side), {"side": side.split("_", 1)[0]})
    legacy = [_text(fields.get(f"Text{index}")) for index in (1, 2, 3, 4)]
    if any(line is not None for line in legacy):                  # signs to 1.19
        hv.record("sign", [component_text(line or "") for line in legacy], at("Text1"))

    pages = fields.get("pages")
    if isinstance(pages, dict) and pages.get("type") == "list":   # written and writable books
        extra: dict[str, Any] = {}
        title = fields.get("title")
        if title is not None:
            extra["title"] = strip_formatting(_page_text(title))[:MAX_PART_CHARS]
            hv.record("book-title", [extra["title"]], at("title"))
        author = _text(fields.get("author"))
        if author is not None:
            extra["author"] = author[:MAX_PART_CHARS]
        hv.record("book", [_page_text(item) for item in _items(pages)], at("pages"), extra)

    for key, surface in _NAME_SURFACES.items():
        if key in fields:
            hv.record(surface, [_node_text(fields[key])], at(key))
    display = _fields(fields.get("display"))                       # item names and lore to 1.20.4
    if "Name" in display:
        hv.record("item-name", [_node_text(display["Name"])], at("display.Name"))
    for lore, sub in ((display.get("Lore"), "display.Lore"), (fields.get("minecraft:lore"), "minecraft:lore")):
        if lore is not None:
            hv.record("lore", [_node_text(item) for item in _items(lore)], at(sub))
    if ident == "minecraft:text_display" and "text" in fields:
        hv.record("text-display", [_node_text(fields["text"])], at("text"))


def _walk_tree(root: object, hv: _Harvest, *, file: str, where: dict[str, Any]) -> None:
    """Walk one parsed NBT tree: every string is scanned, every readable thing becomes a record."""
    def visit(node: object, path: str, where: dict[str, Any], ident: str | None, depth: int) -> None:
        if not isinstance(node, dict) or depth > _nbt.MAX_DEPTH + 2:
            return
        kind, value = node.get("type"), node.get("value")
        if kind == "string":
            if isinstance(value, str) and value:
                hv.string(value, {"file": file, "where": where, "path": path})
            return
        if kind == "list":
            for index, item in enumerate(_items(node)):
                visit(item, f"{path}[{index}]", where, ident, depth + 1)
            return
        if kind != "compound" or not isinstance(value, list):
            return
        fields = _fields(node)
        position = _position(fields)
        if position is not None:
            where = {**where, "pos": position}
        ident = _text(fields.get("id")) or ident
        _emit_records(fields, path, {"file": file, "where": where}, ident, hv)
        for child in value:                    # every child, duplicates of a name included
            if isinstance(child, dict) and isinstance(child.get("name"), str):
                visit(child, _join(path, child["name"]), where, ident, depth + 1)

    visit(root, "$", dict(where), None, 0)


# --------------------------------------------------------------------------- bytes to trees
def _inflate(payload: bytes, wbits: int, cap: int) -> tuple[bytes | None, str | None]:
    try:
        out = zlib.decompressobj(wbits).decompress(payload, cap + 1)
    except zlib.error as exc:
        return None, f"stream does not inflate ({exc})"
    if len(out) > cap:
        return None, f"inflates past the {cap} byte cap"
    return out, None


def _nbt_blob(raw: bytes) -> tuple[bytes | None, str | None]:
    """The uncompressed NBT bytes of a gzip, zlib or raw NBT file."""
    if raw[:2] == b"\x1f\x8b":
        return _inflate(raw, 16 + zlib.MAX_WBITS, MAX_NBT_INFLATED)
    if len(raw) >= 2 and raw[0] & 0x0F == 8 and ((raw[0] << 8) | raw[1]) % 31 == 0:
        return _inflate(raw, zlib.MAX_WBITS, MAX_NBT_INFLATED)
    return raw, None


def _scan_nbt_file(raw: bytes, hv: _Harvest, *, file: str, surface: str,
                   where: dict[str, Any]) -> dict[str, Any] | None:
    """Scan and walk one NBT file; return its root node, or None (with a named skip)."""
    blob, why = _nbt_blob(raw)
    if blob is None:
        hv.skip(file, f"NBT container: {why}")
        return None
    try:
        parsed = _nbt.parse_nbt(blob, compression="raw")
    except _nbt.ResearchFFNBTError as exc:
        hv.skip(file, f"not Java NBT ({exc}); scanned as raw bytes")
        hv.scan_bytes(blob, {"surface": f"{surface}-bytes", "file": file, "where": where})
        return None
    hv.count("nbt_files_parsed")
    _walk_tree(parsed["root"], hv, file=file, where=where)
    return parsed["root"]


def _tag(name: str) -> bytes:
    raw = name.encode("utf-8")
    return len(raw).to_bytes(2, "big") + raw


# A chunk is parsed only when its inflated bytes hold one of these length-prefixed tag names (or the
# text_display id): the tags that carry text a player reads.
_TEXT_MARKERS = tuple(_tag(name) for name in (
    "front_text", "back_text", "Text1", "Text2", "Text3", "Text4", "pages", "CustomName", "custom_name",
    "minecraft:custom_name", "minecraft:item_name", "minecraft:lore", "display", "Command", "LastOutput",
    "minecraft:text_display"))


def _chunk_blob(raw: bytes, offset: int, count: int) -> tuple[bytes | None, str | None]:
    """The inflated NBT bytes of the chunk a location-table entry points at."""
    start = offset * SECTOR
    if offset < 2 or count < 1 or start + 5 > len(raw):
        return None, "location entry points outside the file"
    length = int.from_bytes(raw[start:start + 4], "big")
    if length < 1 or start + 4 + length > len(raw):
        return None, "declared chunk length runs past the file"
    marker = raw[start + 4]
    if marker & 0x80:
        return None, "chunk is stored in an external .mcc file"
    payload = raw[start + 5:start + 4 + length]
    compression = marker & 0x7F
    if compression == 1:
        return _inflate(payload, 16 + zlib.MAX_WBITS, MAX_CHUNK_INFLATED)
    if compression == 2:
        return _inflate(payload, zlib.MAX_WBITS, MAX_CHUNK_INFLATED)
    if compression == 3:
        return payload, None
    if compression == 4:
        return None, "chunk uses LZ4 compression (id 4), which this reader does not decode"
    return None, f"unknown chunk compression id {compression}"


class _Budget:
    def __init__(self, limit: float | None, clock: Callable[[], float]) -> None:
        self.limit = limit
        self.clock = clock
        self.start = clock()

    def used(self) -> float:
        return self.clock() - self.start

    def spent(self) -> bool:
        return self.limit is not None and self.used() >= self.limit


def _scan_region(raw: bytes, hv: _Harvest, *, file: str, dimension: str, kind: str,
                 coords: tuple[int, int] | None, budget: _Budget) -> bool:
    """Scan one region file's chunks; return True when unallocated sectors hold data (deep pass).

    Inflating is the cost here, so it is what the limits sit in front of: the CPU budget is read
    before each chunk is inflated (a chunk past it is not read at all), sectors that several slots
    point at are read once, and the chunks of one region may inflate to MAX_REGION_INFLATED bytes in
    all (the last one read may run past it by at most MAX_CHUNK_INFLATED).  Each of the three is a
    named skip with a count."""
    hv.scan_bytes(raw, {"surface": f"{kind}-raw", "file": file, "where": {"dimension": dimension}})
    total_sectors = len(raw) // SECTOR
    used = {0, 1}
    first_slot: dict[tuple[int, int], int] = {}
    repeats: list[tuple[int, int]] = []
    inflated = 0
    past_budget = past_cap = 0
    for index in range(REGION_SLOTS):
        location = int.from_bytes(raw[index * 4:index * 4 + 4], "big")
        if not location:
            continue
        offset, count = location >> 8, location & 0xFF
        used.update(range(offset, offset + count))
        hv.count("chunks_present")
        earlier = first_slot.setdefault((offset, count), index)
        if earlier != index:
            repeats.append((index, earlier))
            continue
        if budget.spent():
            past_budget += 1
            continue
        if inflated >= MAX_REGION_INFLATED:
            past_cap += 1
            continue
        where: dict[str, Any] = {"dimension": dimension}
        if coords is not None:
            where["chunk"] = [coords[0] * 32 + (index & 31), coords[1] * 32 + (index >> 5)]
        blob, why = _chunk_blob(raw, offset, count)
        if blob is None:
            hv.count("chunks_undecoded")
            hv.skip(f"{file} slot {index}", why or "chunk not decoded")
            continue
        inflated += len(blob)
        hv.count("chunks_scanned")
        if not hv.has_lead(blob) and not any(marker in blob for marker in _TEXT_MARKERS):
            continue                           # no flag lead and no text tag: nothing to read here
        try:
            parsed = _nbt.parse_nbt(blob, compression="raw")
        except _nbt.ResearchFFNBTError as exc:
            hv.skip(f"{file} slot {index}", f"chunk NBT did not parse ({exc}); scanned as raw bytes")
            hv.scan_bytes(blob, {"surface": f"{kind}-chunk-bytes", "file": file, "where": where})
            continue
        hv.count("chunks_parsed")
        _walk_tree(parsed["root"], hv, file=file, where=where)
    if repeats:
        hv.count("chunks_repeated_location", len(repeats))
        hv.skip(file, f"{len(repeats)} slot(s) point at sectors an earlier slot already uses (slot "
                      f"{repeats[0][0]} repeats slot {repeats[0][1]}): those sectors were read once")
    if past_budget:
        hv.count("chunks_not_reached", past_budget)
        hv.skip(file, f"{past_budget} chunk(s) not read: CPU budget spent")
    if past_cap:
        hv.count("chunks_past_inflation_cap", past_cap)
        hv.skip(file, f"{past_cap} chunk(s) not read: this region's chunks inflate past the "
                      f"{MAX_REGION_INFLATED} byte per-region cap")
    return any(raw[sector * SECTOR:(sector + 1) * SECTOR].strip(b"\x00")
               for sector in range(2, total_sectors) if sector not in used)


def _deep_region(raw: bytes, hv: _Harvest, *, file: str, dimension: str, kind: str,
                 coords: tuple[int, int] | None) -> None:
    """The deep pass on a region with data in unallocated sectors: coordinate anomalies of the live
    chunks (``ffgame_anvil_semantics``) and the orphaned chunks, walked like live ones.  Plain text left
    in slack needs no pass of its own: the whole-file scan in ``_scan_region`` has already read it."""
    hv.count("regions_deep")
    try:
        if coords is None:
            semantic = _anvil.analyze_region(raw)
        else:
            semantic = _anvil.analyze_region(raw, region_x=coords[0], region_z=coords[1])
    except _anvil.FFGameAnvilError as exc:
        hv.skip(file, f"deep pass declined ({exc})")
        return
    orphans = 0
    for chunk in semantic["chunks"]:
        if chunk["source"] == "orphan-sector":
            orphans += 1
        elif kind == "region":
            for issue in chunk["issues"]:
                hv.anomaly({"file": file, "slot": chunk["slot_index"],
                            "chunk": [chunk["x_pos"], chunk["z_pos"]], "issue": issue})
    if not orphans:
        return
    try:
        baseline = _nbt.inspect_region(raw)
    except _nbt.ResearchFFNBTError as exc:
        hv.skip(file, f"orphan chunks not walked ({exc})")
        return
    for orphan in baseline["orphan_chunks"]:
        hv.count("orphan_chunks")
        _walk_tree(orphan["nbt"]["root"], hv, file=file,
                   where={"dimension": dimension, "deleted": True, "sector": orphan["sector_offset"]})


# --------------------------------------------------------------------------- the folder walk
def _read(path: Path, cap: int) -> tuple[bytes | None, str | None]:
    try:
        if path.is_symlink():
            return None, "symlink (not followed)"
        with path.open("rb") as handle:
            data = handle.read(cap + 1)
    except OSError as exc:
        return None, f"could not be read ({exc.strerror or type(exc).__name__})"
    if len(data) > cap:
        return None, f"larger than the {cap} byte cap"
    return data, None


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix() or path.name
    except ValueError:
        return path.name


def _files_under(folder: Path, exclude: frozenset[Path], hv: _Harvest) -> list[Path]:
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(folder, followlinks=False):
        here = Path(dirpath)
        dirnames[:] = sorted(name for name in dirnames
                             if name not in _PRUNE_DIRS and here / name not in exclude)
        for name in sorted(filenames):
            if len(out) >= MAX_WALK_FILES:
                hv.skip(_rel(folder, folder.parent), f"more than {MAX_WALK_FILES} files: the rest not walked")
                return out
            out.append(here / name)
    return out


def _dimension(parts: tuple[str, ...]) -> tuple[str, str]:
    """(dimension, kind) of an ``.mca`` file from its path inside the world folder."""
    kind = parts[-2] if len(parts) >= 2 and parts[-2] in _MCA_KINDS else "region"
    head = parts[:-2] if len(parts) >= 2 else ()
    if not head:
        return "overworld", kind
    if head[0] == "DIM-1":
        return "the_nether", kind
    if head[0] == "DIM1":
        return "the_end", kind
    if head[0] == "dimensions" and len(head) >= 3:
        return f"{head[1]}:{'/'.join(head[2:])}", kind
    return "/".join(head), kind


def _level_summary(root: dict[str, Any] | None) -> dict[str, Any]:
    data = _fields(_fields(root).get("Data"))
    if not data:
        return {}
    summary: dict[str, Any] = {}
    name = _text(data.get("LevelName"))
    if name is not None:
        summary["name"] = name[:256]
    version = _text(_fields(data.get("Version")).get("Name"))
    if version is not None:
        summary["version"] = version[:64]
    for key, out in (("DataVersion", "data_version"), ("GameType", "game_type"),
                     ("RandomSeed", "seed"), ("hardcore", "hardcore"), ("allowCommands", "allow_commands")):
        value = _int(data.get(key))
        if value is not None:
            summary[out] = value
    seed = _int(_fields(data.get("WorldGenSettings")).get("seed"))
    if seed is not None:
        summary["seed"] = seed
    spawn = [_int(data.get(axis)) for axis in ("SpawnX", "SpawnY", "SpawnZ")]
    if all(value is not None for value in spawn):
        summary["spawn"] = spawn
    else:                                                  # newer saves: spawn: {pos: [I; x, y, z]}
        node = _fields(data.get("spawn")).get("pos")
        value = node.get("value") if isinstance(node, dict) and node.get("type") == "int_array" else None
        if isinstance(value, list) and len(value) == 3:
            summary["spawn"] = value
    summary["single_player_inventory"] = "Player" in data
    return summary


def _mca_order(spawn: list[int] | None):
    spawn_x = (spawn[0] >> 9) if spawn else 0              # block -> region coordinate
    spawn_z = (spawn[2] >> 9) if spawn else 0

    def key(item: tuple[Path, str, str, tuple[int, int] | None]):
        path, _dimension_name, kind, coords = item
        distance = max(abs(coords[0] - spawn_x), abs(coords[1] - spawn_z)) if coords else 1 << 30
        return (distance, _MCA_KINDS.index(kind), path.as_posix())
    return key


def _walk_files(files: list[Path], base: Path, root: Path, hv: _Harvest, budget: _Budget,
                deep: bool) -> dict[str, Any]:
    """Walk one world folder's files (or a set of loose files); return the world summary."""
    summary: dict[str, Any] = {"level": {}, "players": [], "dimensions": {}}
    nbt_files: list[tuple[Path, str, dict[str, Any]]] = []
    mca_files: list[tuple[Path, str, str, tuple[int, int] | None]] = []
    aux_files: list[Path] = []
    for path in files:
        parts = path.relative_to(base).parts if path != base else (path.name,)
        name, lower = path.name, path.name.lower()
        if lower.endswith(".mca"):
            dimension, kind = _dimension(parts)
            match = _REGION_NAME.fullmatch(name)
            coords = (int(match.group(1)), int(match.group(2))) if match else None
            mca_files.append((path, dimension, kind, coords))
            counts = summary["dimensions"].setdefault(dimension, {})
            counts[kind] = counts.get(kind, 0) + 1
        elif len(parts) == 1 and name in ("level.dat", "level.dat_old"):
            nbt_files.insert(0 if name == "level.dat" else len(nbt_files), (path, "level", {}))
        elif lower.endswith((".dat", ".dat_old")) and len(parts) >= 2 and parts[-2] in ("playerdata", "players"):
            nbt_files.append((path, "player", {"player": path.stem}))
        elif lower.endswith((".dat", ".dat_old", ".mcc") + _NBT_SUFFIXES):
            nbt_files.append((path, "external-chunk" if lower.endswith(".mcc") else "data", {}))
        else:
            aux_files.append(path)

    not_reached: list[str] = []

    def reach(path: Path) -> bool:
        if budget.spent():
            not_reached.append(_rel(path, root))
            return False
        return True

    for path, surface, where in nbt_files:
        if not reach(path):
            continue
        rel = _rel(path, root)
        raw, why = _read(path, MAX_NBT_FILE)
        if raw is None:
            hv.skip(rel, why or "not read")
            continue
        node = _scan_nbt_file(raw, hv, file=rel, surface=surface, where=where)
        if surface == "level" and path.name == "level.dat":
            summary["level"] = _level_summary(node)
        elif surface == "player" and node is not None:
            player: dict[str, Any] = {"file": rel, "uuid": path.stem}
            position = _position(_fields(node))
            if position is not None:
                player["pos"] = position
            summary["players"].append(player)
        if surface == "data" and path.name.startswith("map_") and node is not None:
            hv.count("map_items")

    for path in aux_files:
        if not reach(path):
            continue
        rel = _rel(path, root)
        raw, why = _read(path, MAX_AUX_FILE)
        if raw is None:
            hv.skip(rel, why or "not read")
            continue
        hv.count("aux_files_scanned")
        hv.scan_bytes(raw, {"surface": "file", "file": rel, "where": {}})

    mca_files.sort(key=_mca_order(summary["level"].get("spawn")))
    residue: list[tuple[Path, str, str, tuple[int, int] | None]] = []
    for item in mca_files:
        path, dimension, kind, coords = item
        if not reach(path):
            continue
        rel = _rel(path, root)
        raw, why = _read(path, MAX_REGION_FILE)
        if raw is None:
            hv.skip(rel, why or "not read")
            continue
        if not raw:
            hv.count("regions_empty")
            continue
        if len(raw) < 2 * SECTOR:
            hv.skip(rel, "shorter than the 8192-byte region header")
            continue
        hv.count("regions_scanned")
        if _scan_region(raw, hv, file=rel, dimension=dimension, kind=kind, coords=coords, budget=budget):
            residue.append(item)

    if residue and not deep:
        hv.skip("deep pass", f"{len(residue)} region(s) hold data in unallocated sectors; deep pass is off")
    elif residue:
        waiting = 0
        for path, dimension, kind, coords in residue:
            if budget.spent():
                waiting += 1
                continue
            raw, why = _read(path, MAX_REGION_FILE)
            if raw is None:
                hv.skip(_rel(path, root), why or "not read")
                continue
            _deep_region(raw, hv, file=_rel(path, root), dimension=dimension, kind=kind, coords=coords)
        if waiting:
            hv.count("regions_deep_not_reached", waiting)
            hv.skip("deep pass", f"{waiting} region(s) with data in unallocated sectors not inspected: "
                                 "CPU budget spent")

    if not_reached:
        hv.count("files_not_reached", len(not_reached))
        shown = ", ".join(not_reached[:5]) + (" ..." if len(not_reached) > 5 else "")
        hv.skip("budget", f"{len(not_reached)} file(s) not reached: CPU budget spent ({shown})")
    return summary


def _signature(world: Path, files: list[Path]) -> str:
    """A digest of every file's path and content: two worlds are the same only when all of it is."""
    digest = hashlib.sha256()
    for path in files:
        inner = hashlib.sha256()
        try:
            if path.is_symlink():
                inner.update(b"symlink")
            else:
                with path.open("rb") as handle:
                    for block in iter(lambda: handle.read(1 << 20), b""):
                        inner.update(block)
        except OSError:
            inner.update(b"unreadable")
        digest.update(f"{path.relative_to(world).as_posix()}:{inner.hexdigest()}\n".encode("utf-8"))
    return digest.hexdigest()


def _find_worlds(root: Path) -> tuple[list[Path], bool]:
    worlds: list[Path] = []
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if name not in _PRUNE_DIRS)
        seen += len(filenames)
        if "level.dat" in filenames and not Path(dirpath, "level.dat").is_symlink():
            worlds.append(Path(dirpath))
        if seen > MAX_WALK_FILES:
            return sorted(worlds), True
    return sorted(worlds), False


def find_worlds(root: str | os.PathLike) -> list[Path]:
    """Every folder at or under ``root`` that holds a ``level.dat`` (``.ctf``/``.git`` never entered)."""
    return _find_worlds(Path(root))[0]


def _looks_nbt(path: Path) -> bool:
    """A loose ``.dat`` is taken only when it starts like NBT: gzip, or a named root compound."""
    try:
        if path.is_symlink():
            return False
        with path.open("rb") as handle:
            head = handle.read(3)
    except OSError:
        return False
    return head[:2] == b"\x1f\x8b" or (len(head) == 3 and head[0] == 0x0A and head[1] == 0)


def walk(path: str | os.PathLike, *, profile=None, budget: float | None = DEFAULT_BUDGET_S,
         deep: bool = True, clock: Callable[[], float] | None = None) -> dict[str, Any]:
    """Walk every Minecraft world (and loose region / NBT file) at or under ``path``.

    ``profile`` is the event whose flag format is harvested (default: the current event); ``budget``
    is CPU seconds (None for no limit) on ``clock`` (default ``time.process_time``).
    """
    root = Path(path)
    if not root.exists():
        raise _fail(f"no such path: {root}")
    if budget is not None and (isinstance(budget, bool) or not isinstance(budget, (int, float))
                               or not math.isfinite(budget) or budget <= 0):
        raise _fail("budget must be a positive number of CPU seconds, or None")
    ff = flagfmt.for_profile(profile) if profile is not None else flagfmt.current()
    hv = _Harvest(ff)
    meter = _Budget(budget, clock or time.process_time)
    worlds: list[dict[str, Any]] = []
    base = root if root.is_dir() else root.parent

    world_dirs, cut = _find_worlds(root) if root.is_dir() else ([], False)
    if cut:
        hv.skip("discovery", f"more than {MAX_WALK_FILES} files under the path: the search for worlds "
                             "stopped early")
    claimed = frozenset(world_dirs)           # every world folder, walked or not: none is "loose files"
    if len(world_dirs) > MAX_WORLDS:
        hv.skip("worlds", f"{len(world_dirs) - MAX_WORLDS} world folder(s) past the first {MAX_WORLDS} "
                          "not walked")
        world_dirs = world_dirs[:MAX_WORLDS]
    signatures: dict[str, str] = {}
    for world in world_dirs:
        files = _files_under(world, claimed - {world}, hv)
        rel = _rel(world, base) if world != base else "."
        if len(world_dirs) > 1:               # an unpacked copy beside the original: walk it once
            signature = _signature(world, files)
            if signature in signatures:
                hv.count("duplicate_worlds")
                hv.skip(rel, f"same world as {signatures[signature]} (every file identical)")
                continue
            signatures[signature] = rel
        summary = _walk_files(files, world, base, hv, meter, deep)
        summary = {"path": rel, "edition": "java", **summary}
        if (world / "db").is_dir() and not summary["level"]:
            summary["edition"] = "bedrock"
            hv.skip(rel, "Bedrock world (LevelDB db/ folder): this reader takes Java worlds only")
        worlds.append(summary)

    if not root.is_dir():
        loose = [root]
    elif root in claimed:
        loose = []
    else:                                   # region and structure files that sit outside any world folder
        loose = [p for p in _files_under(root, claimed, hv)
                 if p.name.lower().endswith((".mca",) + _NBT_SUFFIXES)
                 or (p.name.lower().endswith((".dat", ".dat_old")) and _looks_nbt(p))]
    if loose:
        summary = _walk_files(loose, base, base, hv, meter, deep)
        worlds.append({"path": "(loose files)", "edition": "java", "files": len(loose), **summary})

    hv.records.sort(key=lambda row: (not row["flags"], ))
    return {
        "kind": "minecraft-world",
        "root": root.name,
        "worlds": worlds,
        "flags": list(hv.flags.values()),
        "flags_dropped": hv.flags_dropped,
        "records": hv.records,
        "records_dropped": hv.records_dropped,
        "anomalies": hv.anomalies,
        "anomalies_dropped": hv.anomalies_dropped,
        "skipped": hv.skipped,
        "skipped_dropped": hv.skipped_dropped,
        "stats": dict(sorted(hv.stats.items())),
        "budget": {"limit_s": budget, "used_s": round(meter.used(), 3), "spent": meter.spent()},
        "external_files_accessed": False,
    }


# --------------------------------------------------------------------------- rendering and result
def where_text(where: dict[str, Any] | None) -> str:
    where = where or {}
    bits: list[str] = []
    if where.get("dimension"):
        bits.append(str(where["dimension"]))
    if "pos" in where:
        bits.append("at (%d, %d, %d)" % tuple(where["pos"]))
    elif "chunk" in where:
        bits.append("chunk (%d, %d)" % tuple(where["chunk"]))
    if where.get("player"):
        bits.append(f"player {where['player']}")
    if where.get("deleted"):
        bits.append("orphaned chunk data (deleted or replaced in the world)")
    return ", ".join(bits)


def _dropped_notes(report: dict[str, Any]) -> list[str]:
    """What the caps of one walk left out, said in words (nothing is cut without a count)."""
    notes: list[str] = []
    if report["flags_dropped"]:
        notes.append(f"{report['flags_dropped']} flag hit(s) past the cap of {MAX_FLAGS} distinct flags "
                     "were not kept")
    if report["records_dropped"]:
        notes.append(f"{report['records_dropped']} text record(s) past the cap of {MAX_RECORDS} were not kept")
    if report["anomalies_dropped"]:
        notes.append(f"{report['anomalies_dropped']} chunk anomaly(ies) past the cap of {MAX_ANOMALIES} "
                     "were not kept")
    if report["skipped_dropped"]:
        notes.append(f"{report['skipped_dropped']} skip(s) past the cap of {MAX_SKIPPED} were not listed")
    return notes


def render_text(report: dict[str, Any]) -> str:
    lines: list[str] = []
    for world in report["worlds"]:
        level = world.get("level") or {}
        head = f"world {world['path']} [{world['edition']}]"
        if level.get("name"):
            head += f" name={level['name']!r}"
        if level.get("version"):
            head += f" version={level['version']}"
        if level.get("spawn"):
            head += " spawn=(%d, %d, %d)" % tuple(level["spawn"])
        if "seed" in level:
            head += f" seed={level['seed']}"
        lines.append(head)
        for dimension, counts in sorted(world.get("dimensions", {}).items()):
            lines.append(f"  {dimension}: " + ", ".join(f"{n} {kind} file(s)" for kind, n in sorted(counts.items())))
        for player in world.get("players", []):
            pos = " at (%d, %d, %d)" % tuple(player["pos"]) if "pos" in player else ""
            lines.append(f"  player {player['uuid']}{pos}")
    for entry in report["flags"]:
        source = entry["sources"][0] if entry["sources"] else {}
        lines.append(f"FLAG [{entry['how']}] {entry['flag']}  <- {source.get('surface', '?')} in "
                     f"{source.get('file', '?')} {where_text(source.get('where'))}".rstrip())
    for row in report["records"]:
        if row["surface"] == "string":
            continue
        text = " | ".join(part for part in row["parts"] if part.strip())
        lines.append(f"{row['surface']:<14} {row['file']} {where_text(row.get('where'))}: {text[:400]}")
    for row in report["anomalies"]:
        lines.append(f"anomaly        {row['file']} slot {row['slot']}: {row['issue']}")
    for row in report["skipped"]:
        lines.append(f"skipped        {row['what']}: {row['why']}")
    for note in _dropped_notes(report):
        lines.append(f"dropped        {note}")
    stats = ", ".join(f"{key}={value}" for key, value in report["stats"].items())
    lines.append(f"stats          {stats or 'nothing read'}")
    spent = " (SPENT: rerun with a larger --budget)" if report["budget"]["spent"] else ""
    lines.append(f"budget         {report['budget']['used_s']} of {report['budget']['limit_s']} CPU s{spent}")
    return "\n".join(lines)


_SOLVE_OPTS = frozenset({"budget", "deep", "report"})


def solve(challenge_dir, profile=None, **opts):
    """Intake entry: walk every world in the handout and return what its surfaces give up.

    Options: ``budget`` (CPU seconds, default 20), ``deep`` (default true), ``report`` (a path to write
    the full JSON report to).  One distinct flag that is contiguous in the data is ``solved``; several,
    or one seen only by joining lines or pages, are ``candidate``; readable text with no flag is
    ``unsure`` (the text is the evidence); a handout with no Java world is ``none``.
    """
    from ctf.result import Evidence, SolverResult

    unknown = sorted(set(opts) - _SOLVE_OPTS)
    if unknown:
        raise _fail(f"unknown option(s) {', '.join(unknown)}; known: {', '.join(sorted(_SOLVE_OPTS))}")
    challenge_dir = Path(challenge_dir)
    report = walk(challenge_dir, profile=profile, budget=opts.get("budget", DEFAULT_BUDGET_S),
                  deep=bool(opts.get("deep", True)))
    if opts.get("report"):
        Path(str(opts["report"])).write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    java = [world for world in report["worlds"] if world["edition"] == "java"]
    bedrock = [world for world in report["worlds"] if world["edition"] == "bedrock"]
    notes: list[str] = []
    stats = report["stats"]
    if java:
        notes.append(f"{len(java)} world/file set(s): {stats.get('regions_scanned', 0)} region file(s), "
                     f"{stats.get('chunks_scanned', 0)} chunk(s) scanned, {stats.get('chunks_parsed', 0)} "
                     f"parsed for text, {stats.get('nbt_files_parsed', 0)} NBT file(s)")
    if stats.get("orphan_chunks"):
        notes.append(f"{stats['orphan_chunks']} orphaned chunk(s) recovered from unallocated sectors")
    if stats.get("map_items"):
        notes.append(f"{stats['map_items']} map item(s) in data/: map colours are not rendered here")
    if report["anomalies"]:
        notes.append(f"{len(report['anomalies'])} chunk coordinate anomaly(ies): see the full report")
    notes.extend(_dropped_notes(report))
    for row in report["skipped"][:6]:
        notes.append(f"skipped {row['what']}: {row['why']}")
    more = len(report["skipped"]) - 6
    if more > 0:
        notes.append(f"{more} more skip(s) in the full report")
    if report["budget"]["spent"]:
        notes.append(f"CPU budget of {report['budget']['limit_s']} s spent: rerun with --opt budget=<seconds>")
    notes.append("full report: tools/ctfpy solvers/toolkits/minecraft_world.py <folder> --json")

    evidence: list[Evidence] = []
    for entry in report["flags"]:
        source = entry["sources"][0] if entry["sources"] else {}
        detail = (f"{entry['how']} hit on {source.get('surface', '?')} "
                  f"{where_text(source.get('where'))}".rstrip())
        evidence.append(Evidence(kind="match", detail=detail, path=source.get("file")))
    readable = [row for row in report["records"] if row["surface"] != "string"]
    for row in readable:
        if len(evidence) >= MAX_EVIDENCE:
            break
        if row["flags"]:
            continue
        text = " | ".join(part for part in row["parts"] if part.strip())
        evidence.append(Evidence(kind="text", path=row["file"],
                                 detail=f"{row['surface']} {where_text(row.get('where'))}: {text[:240]}"))

    flags = [entry["flag"] for entry in report["flags"]]
    solid = [entry["flag"] for entry in report["flags"] if entry["how"] != "joined"]
    if len(flags) == 1 and solid:
        status = "solved"
    elif flags:
        status = "candidate"
        notes.insert(0, "several distinct flags, or a flag seen only by joining lines/pages: not auto-returned")
    elif readable:
        status = "unsure"
        notes.insert(0, f"{len(readable)} readable text record(s) (signs, books, names) and no flag-format "
                        "hit: read them")
    elif not java and bedrock:
        return SolverResult(status="blocked", engine=ENGINE_ID,
                            notes="Bedrock world (LevelDB db/ folder): this reader takes Java worlds only; "
                                  "convert it or read the LevelDB with a Bedrock tool")
    else:
        status = "none"
        if not java:
            notes.insert(0, "no Minecraft Java world, region file or NBT structure file in the handout")
    return SolverResult(status=status, flags=tuple(flags), evidence=tuple(evidence), engine=ENGINE_ID,
                        notes="; ".join(notes))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Walk a Minecraft Java world folder: flags, signs, books, "
                                                 "names, deleted chunks")
    parser.add_argument("path", help="a world folder, a folder holding worlds, a .mca region or an NBT file")
    parser.add_argument("--json", action="store_true", help="print the full JSON report")
    parser.add_argument("--compact", action="store_true", help="with --json: one line")
    parser.add_argument("--budget", type=float, default=CLI_BUDGET_S,
                        help=f"CPU seconds (default {CLI_BUDGET_S:g}); 0 for no limit")
    parser.add_argument("--no-deep", action="store_true", help="skip the deep pass on unallocated sectors")
    parser.add_argument("--event", help="event slug whose flag format to harvest (default: the current event)")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        profile = _event.load(args.event) if args.event else None
        report = walk(args.path, profile=profile, budget=args.budget or None, deep=not args.no_deep)
    except (MinecraftWorldError, OSError) as exc:
        print(f"minecraft_world: {exc}", file=sys.stderr)
        return 2
    except _event.EventError as exc:         # no event resolves: say so, never guess a flag format
        print(f"minecraft_world: no flag format ({exc}); set CTF_EVENT or pass --event", file=sys.stderr)
        return 2
    if args.json:
        json.dump(report, sys.stdout, indent=None if args.compact else 2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(render_text(report))
    return 0 if report["flags"] else 1


__all__ = ["MinecraftWorldError", "ENGINE_ID", "DEFAULT_BUDGET_S", "strip_formatting", "json_component_text",
           "component_text", "json_strings", "find_worlds", "walk", "where_text", "render_text", "solve", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
