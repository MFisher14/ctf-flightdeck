#!/usr/bin/env python3
"""Offline Unreal Engine recon: a bounded ``.pak`` reader and unpacker, and a literal-pool harvest.

A ``.pak`` is an UnrealPak container: entry payloads, then an index, then a fixed footer that carries
the magic ``0x5A6F12E1``, the pak version, where the index is, its SHA-1 and (from version 4) whether
the index is AES-encrypted.  This module reads that structure statically (B-120): nothing in the
archive is executed, no file it names is opened, and every size it declares is checked against caps.

What it does:

* finds the footer at the place its version puts it (44, 172, 204 or 205 bytes of footer after the
  magic), or failing that by a scan of the tail, and says which;
* reads the index of pak versions 1-11: the legacy index (1-9: mount point, then a name and an
  ``FPakEntry`` per file) and the path-hash index (10-11: bit-packed encoded entries named through the
  full directory index);
* extracts stored, zlib and gzip entries, harvests the event flag format from each (ASCII and
  UTF-16), and pulls URLs out of the config files (``*.ini``, ``*.json`` ...) a game ships;
* reports an **AES-encrypted index or entry as blocked**, naming the key it needs, unless an AES-256
  key is supplied (UnrealPak's AES-256-ECB; the key is checked against the index SHA-1);
* names every entry it did not extract: Oodle/LZ4/Zstd or custom compression, a delete record, a size
  over the caps, a frozen index;
* **literal pool**: on any file (the archive, a cooked asset, the game executable or module) it finds
  the flag format, URLs and ``/Script/<Module>`` names in ASCII and UTF-16LE, and lists the UTF-16
  literals that sit next to the game's own module name -- the endpoints and keys of a client/server
  protocol usually live there.  It is a heuristic view for a human or model to read, not a decoder.

The layout was written from the UnrealPak format (``FPakInfo`` / ``FPakEntry``) as the open readers
``repak`` and ``u4pak`` describe it; no Unreal code is imported.  IoStore containers (``.utoc`` /
``.ucas``) are not decoded: only the literal-pool harvest runs on them, and each one met is named (a
row in the survey's ``skipped`` and ``iostore`` lists, a note from ``solve``, which is ``blocked`` on
them when nothing else in the handout gave a flag or a lead).  Every cap that cuts the flag harvest
short is said in words (``flag_scan_cuts``), never applied silently.

Entry ``solve(challenge_dir, profile) -> SolverResult`` is the intake engine; ``read_pak`` /
``read_pak_file`` return the full report, ``unpack`` writes the entries to a folder, ``literal_pool``
is the string harvest and ``main()`` is the command line.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import mmap
import os
import re
import struct
import sys
import time
import zlib
from pathlib import Path
from typing import Any, Callable

# ctf package import (script runs need the checkout root on sys.path), mirroring the sibling toolkits.
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt
from ctf import event as _event


ENGINE_ID = "toolkits.unreal_pak"

PAK_MAGIC = 0x5A6F12E1
PAK_MAGIC_LE = struct.pack("<I", PAK_MAGIC)          # the four footer bytes on disk
MAX_VERSION = 11                                      # Fnv64BugFix, the newest index this reader knows

DEFAULT_BUDGET_S = 20.0            # CPU seconds for solve() (intake); the CLI default is larger
CLI_BUDGET_S = 300.0
MAX_PAK_INPUT = 256 << 20          # an in-memory archive
MAX_PAK_FILE = 1 << 36             # a mapped archive file
MAX_FOOTER_SCAN = 4096             # tail bytes scanned for the magic when it is not where it belongs
MAX_ENTRIES = 200_000
MAX_INDEX_BYTES = 64 << 20
MAX_FSTRING_BYTES = 1 << 16
MAX_BLOCKS = 65_535
MAX_EXTRACT_PER_ENTRY = 64 << 20
MAX_EXTRACT_TOTAL = 512 << 20
MAX_FLAGS = 256
MAX_FLAG_SOURCES = 8
MAX_NEEDLE_HITS = 20_000
MAX_URLS = 500
MAX_RUN_CHARS = 2048
MAX_SLOW_SCAN = 64 << 20           # whole-buffer regex scan, used only when the flag prefix is unknown
MAX_MODULE_LITERALS = 300
MAX_GAME_MODULES = 4
MAX_ANCHORS = 4
MAX_CONFIGS = 200
MAX_CONFIG_LINES = 20
MAX_EVIDENCE = 16
MAX_WALK_FILES = 50_000
LITERAL_WINDOW = 64 << 10          # bytes each side of a game-module name read for its literals
AES_BLOCK = 16
AES_KEY_LEN = 32
_FIND_STEP = 32 << 20

_FOOTER_CORE = 44                  # magic, version, index offset, index size, index SHA-1
_PRUNE_DIRS = frozenset({".ctf", ".git"})
_CONFIG_SUFFIXES = (".ini", ".json", ".txt", ".cfg", ".csv", ".xml", ".toml", ".yaml", ".yml", ".html",
                    ".js", ".lua", ".uproject", ".uplugin")
_ASSET_SUFFIXES = (".uasset", ".uexp", ".umap", ".ubulk", ".uptnl", ".locres", ".utoc", ".ucas")
_IOSTORE_SUFFIXES = (".utoc", ".ucas")
IOSTORE_WHY = "IoStore container: not decoded by this reader, literal pool only"
MAX_UNREADABLE_ROWS = 20
_BINARY_SUFFIXES = (".exe", ".dll", ".so", ".dylib")
_BINARY_MAGICS = (b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")

_CONFIG_KEY = re.compile(r"(?i)^\s*[\"']?[\w.\-]*(?:host|server|url|uri|endpoint|addr|port|api|token|secret|"
                         r"passw|flag)[\w.\-]*[\"']?\s*[=:]\s*\S")
_URL = re.compile(r"(?:https?|wss?)://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{3,512}")
_SCRIPT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,63}")
_ENDPOINT = re.compile(r"/([a-z0-9_-]{1,32})(?:/[A-Za-z0-9_.{}:%-]{1,64}){0,8}/?(?:\?[A-Za-z0-9_=&%.-]{0,128})?")
_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){3,}")
_ASCII_RUN = re.compile(rb"[\x20-\x7e]{4,}")
# First path segments that are a file system, not a service route.
_SYSTEM_ROOTS = frozenset({
    "usr", "lib", "lib64", "dev", "proc", "sys", "etc", "tmp", "bin", "sbin", "var", "home", "opt", "run",
    "mnt", "root", "private", "system", "library", "applications", "users", "volumes"})
# Module names the engine itself ships; a /Script/<name> outside this set is taken as the game's own.
_ENGINE_MODULES = frozenset({
    "AIModule", "ActorLayerUtilities", "AnimGraphRuntime", "AnimationCore", "ApplicationCore",
    "AssetRegistry", "AudioExtensions", "AudioMixer", "AudioPlatformConfiguration", "AugmentedReality",
    "BuildPatchServices", "Chaos", "ChaosSolverEngine", "CinematicCamera", "ClothingSystemRuntimeCommon",
    "ClothingSystemRuntimeInterface", "ClothingSystemRuntimeNv", "CommonInput", "CommonUI", "Constraints",
    "Core", "CoreOnline", "CoreUObject", "DataRegistry", "DeveloperSettings", "EngineMessages",
    "EngineSettings", "Engine", "EnhancedInput", "EyeTracker", "FieldSystemEngine", "Foliage",
    "GameplayAbilities", "GameplayCameras", "GameplayTags", "GameplayTasks", "GeometryCollectionEngine",
    "GeometryFramework", "HeadMountedDisplay", "HTTP", "IKRig", "ImageCore", "ImageWriteQueue",
    "InputCore", "InteractiveToolsFramework", "IrisCore", "JsonUtilities", "Landscape", "LevelSequence",
    "LiveLinkInterface", "MRMesh", "MassEntity", "MaterialShaderQualitySettings", "MediaAssets",
    "MediaUtils", "MeshDescription", "ModelViewViewModel", "MoviePlayer", "MovieScene",
    "MovieSceneCapture", "MovieSceneTracks", "NavigationSystem", "NetCore", "Niagara", "NiagaraCore",
    "NiagaraShader", "OnlineSubsystem", "OnlineSubsystemUtils", "Overlay", "PacketHandler", "Paper2D",
    "PhysicsCore", "ProceduralMeshComponent", "PropertyPath", "Renderer", "RigVM", "Serialization",
    "SessionMessages", "SignalProcessing", "Slate", "SlateCore", "SlateRHIRenderer", "StaticMeshDescription",
    "StructUtils", "TimeManagement", "TypedElementFramework", "TypedElementRuntime", "UMG", "UnrealEd",
    "VectorVM", "WebBrowser", "WorldPartitionHLODUtilities"})


class UnrealPakError(ValueError):
    """Malformed, unsupported, or over-limit input."""


def _fail(message: str) -> UnrealPakError:
    return UnrealPakError(message)


def _align16(size: int) -> int:
    return (size + AES_BLOCK - 1) & ~(AES_BLOCK - 1)


# --------------------------------------------------------------------------- AES
def parse_key(text: str) -> bytes:
    """An AES-256 key as 64 hex characters (``0x`` allowed) or as base64 (UE's Crypto.json form)."""
    if not isinstance(text, str) or not text.strip():
        raise _fail("AES key must be a non-empty string")
    value = text.strip()
    hexed = value[2:] if value[:2].lower() == "0x" else value
    if len(hexed) == 2 * AES_KEY_LEN and re.fullmatch(r"[0-9A-Fa-f]+", hexed):
        return bytes.fromhex(hexed)
    try:
        key = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        key = b""
    if len(key) != AES_KEY_LEN:
        raise _fail(f"AES key must be {2 * AES_KEY_LEN} hex characters or base64 of {AES_KEY_LEN} bytes")
    return key


def _aes_decrypt(blob: bytes, key: bytes) -> bytes:
    if len(key) != AES_KEY_LEN:
        raise _fail(f"AES key must be {AES_KEY_LEN} bytes (AES-256)")
    if len(blob) % AES_BLOCK:
        raise _fail("encrypted region is not a multiple of the AES block size")
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ModuleNotFoundError as exc:
        raise _fail("AES backend missing: the 'cryptography' package is needed to use a key") from exc
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()  # UnrealPak: AES-256-ECB
    return decryptor.update(bytes(blob)) + decryptor.finalize()


# --------------------------------------------------------------------------- cursor
class _Cursor:
    __slots__ = ("data", "pos")

    def __init__(self, data, pos: int = 0) -> None:
        self.data = data
        self.pos = pos

    def take(self, count: int, label: str) -> bytes:
        if count < 0 or self.pos < 0 or self.pos + count > len(self.data):
            raise _fail(f"truncated {label}")
        start = self.pos
        self.pos += count
        return bytes(self.data[start:self.pos])

    def u8(self, label: str) -> int:
        return self.take(1, label)[0]

    def u32(self, label: str) -> int:
        return int.from_bytes(self.take(4, label), "little")

    def i32(self, label: str) -> int:
        return int.from_bytes(self.take(4, label), "little", signed=True)

    def u64(self, label: str) -> int:
        return int.from_bytes(self.take(8, label), "little")

    def fstring(self, label: str) -> str:
        """An FString: an int32 length with its NUL (negative: that many UTF-16 units), then the text."""
        length = self.i32(label + " length")
        if length == 0:
            return ""
        if length > 0:
            if length > MAX_FSTRING_BYTES:
                raise _fail(f"{label} exceeds the length cap")
            return self.take(length, label).split(b"\x00", 1)[0].decode("latin-1")
        units = -length
        if units > MAX_FSTRING_BYTES // 2:
            raise _fail(f"{label} exceeds the length cap")
        return self.take(units * 2, label).decode("utf-16-le", "replace").split("\x00", 1)[0]


# --------------------------------------------------------------------------- footer
def _expected_tails(version: int) -> tuple[int, ...]:
    """Bytes from the magic to the end of the file, by pak version."""
    if version <= 7:
        return (44,)
    if version == 8:
        return (172, 204)          # 4.22 wrote four 32-byte compression names, later builds five
    if version == 9:
        return (205,)              # one more byte: the frozen-index flag
    return (204,)


def _footer_at(data, pos: int, *, strict: bool) -> dict[str, Any] | None:
    size = len(data)
    if pos < 0 or pos + _FOOTER_CORE > size or bytes(data[pos:pos + 4]) != PAK_MAGIC_LE:
        return None
    version = int.from_bytes(data[pos + 4:pos + 8], "little")
    index_offset = int.from_bytes(data[pos + 8:pos + 16], "little")
    index_size = int.from_bytes(data[pos + 16:pos + 24], "little")
    if not 1 <= version <= 255 or index_offset + index_size > pos or index_size > MAX_INDEX_BYTES:
        return None
    if strict and size - pos not in _expected_tails(version):
        return None
    after = pos + _FOOTER_CORE
    frozen = False
    if version == 9 and after < size:
        frozen = bool(data[after])
        after += 1
    names: list[str] = []
    if version >= 8:
        for slot in range(min(5, (size - after) // 32)):
            raw = bytes(data[after + 32 * slot:after + 32 * slot + 32])
            names.append(raw.replace(b"\x00", b"").decode("latin-1"))
    encrypted = False
    if version >= 4:
        if pos < 1 or data[pos - 1] > 1:
            return None
        encrypted = data[pos - 1] == 1
    key_guid = bytes(data[pos - 17:pos - 1]).hex() if version >= 7 and pos >= 17 else None
    return {
        "magic_offset": pos, "version": version, "index_offset": index_offset, "index_size": index_size,
        "index_sha1": bytes(data[pos + 24:pos + 44]).hex(), "encrypted_index": encrypted,
        "encryption_key_guid": key_guid, "frozen_index": frozen, "compression_names": names,
        "v8a": version == 8 and len(names) == 4,
        "location": "fixed" if strict else "scanned",
    }


def _find_footer(data) -> dict[str, Any]:
    size = len(data)
    for tail in (44, 172, 204, 205):
        footer = _footer_at(data, size - tail, strict=True)
        if footer is not None:
            return footer
    scan_start = max(0, size - MAX_FOOTER_SCAN)
    tail = bytes(data[scan_start:])
    best = None
    pos = tail.find(PAK_MAGIC_LE)
    while pos >= 0:                      # the last self-consistent magic wins: the footer is at the tail
        footer = _footer_at(data, scan_start + pos, strict=False)
        if footer is not None:
            best = footer
        pos = tail.find(PAK_MAGIC_LE, pos + 1)
    if best is None:
        raise _fail("no UnrealPak footer (magic 0x5A6F12E1 with a consistent index pointer) in the "
                    "archive tail")
    return best


# --------------------------------------------------------------------------- entries
def _compression_name(method: int, version: int, names: list[str]) -> str | None:
    if method == 0:
        return None
    if version < 8:                      # a flag value: 1 zlib, 2 gzip, 4 custom (Oodle in practice)
        return {1: "zlib", 2: "gzip", 4: "custom"}.get(method, f"unknown-method-{method}")
    slot = method - 1                    # from version 8: 1-based slot in the footer's name table
    if slot < len(names) and names[slot]:
        return names[slot].lower()
    return f"unnamed-slot-{method}"


def _read_entry(cursor: _Cursor, footer: dict[str, Any]) -> dict[str, Any]:
    """One ``FPakEntry`` as the index and the start of each entry's data both store it."""
    version = footer["version"]
    offset = cursor.u64("entry offset")
    compressed_size = cursor.u64("entry compressed size")
    uncompressed_size = cursor.u64("entry uncompressed size")
    method = cursor.u8("entry compression") if footer["v8a"] else cursor.u32("entry compression")
    if version <= 1:
        cursor.take(8, "entry timestamp")
    sha1 = cursor.take(20, "entry sha1")
    blocks: list[tuple[int, int]] = []
    flags = 0
    block_size = 0
    if version >= 3:
        if method != 0:
            count = cursor.u32("entry block count")
            if count > MAX_BLOCKS:
                raise _fail("entry compression block count exceeds the cap")
            for _ in range(count):
                start = cursor.u64("entry block start")
                blocks.append((start, cursor.u64("entry block end")))
        flags = cursor.u8("entry flags")
        block_size = cursor.u32("entry block size")
    return {
        "offset": offset, "compressed_size": compressed_size, "uncompressed_size": uncompressed_size,
        "compression": _compression_name(method, version, footer["compression_names"]),
        "sha1": sha1.hex(), "blocks": blocks, "encrypted": bool(flags & 1),
        "deleted": bool(flags & 2) and version >= 6, "block_size": block_size,
    }


def _header_len(compressed: bool, block_count: int) -> int:
    """Size of the ``FPakEntry`` written ahead of an entry's data in a version 10+ archive."""
    return 8 + 8 + 8 + 4 + 20 + ((4 + 16 * block_count) if compressed else 0) + 1 + 4


def _read_encoded(cursor: _Cursor, footer: dict[str, Any]) -> dict[str, Any]:
    """One bit-packed entry of the version 10+ index."""
    bits = cursor.u32("encoded entry flags")
    method = (bits >> 23) & 0x3F
    encrypted = bool(bits & (1 << 22))
    block_count = (bits >> 6) & 0xFFFF
    block_size = bits & 0x3F
    block_size = cursor.u32("encoded block size") if block_size == 0x3F else block_size << 11

    def sized(bit: int, label: str) -> int:
        return cursor.u32(label) if bits & (1 << bit) else cursor.u64(label)

    offset = sized(31, "encoded offset")
    uncompressed_size = sized(30, "encoded uncompressed size")
    compressed_size = uncompressed_size if method == 0 else sized(29, "encoded compressed size")
    base = _header_len(method != 0, block_count)
    blocks: list[tuple[int, int]] = []
    if block_count == 1 and not encrypted:
        blocks.append((base, base + compressed_size))
    elif block_count:
        position = base
        for _ in range(block_count):
            size = cursor.u32("encoded block length")
            blocks.append((position, position + size))
            position += _align16(size) if encrypted else size
    return {
        "offset": offset, "compressed_size": compressed_size, "uncompressed_size": uncompressed_size,
        "compression": _compression_name(method, footer["version"], footer["compression_names"]),
        "sha1": None, "blocks": blocks, "encrypted": encrypted, "deleted": False, "block_size": block_size,
    }


def _region(data, offset: int, size: int, label: str) -> bytes:
    if offset < 0 or size < 0 or size > MAX_INDEX_BYTES or offset + size > len(data):
        raise _fail(f"{label} lies outside the archive or exceeds the index cap")
    return bytes(data[offset:offset + size])


def _parse_index(data, footer: dict[str, Any], index: bytes,
                 aes_key: bytes | None) -> tuple[str, list[dict[str, Any]], list[str]]:
    """(mount point, entries, notes) from the plaintext primary index."""
    cursor = _Cursor(index)
    notes: list[str] = []
    mount_point = cursor.fstring("mount point")
    count = cursor.u32("entry count")
    if count > MAX_ENTRIES:
        raise _fail("index entry count exceeds the cap")
    entries: list[dict[str, Any]] = []
    if footer["version"] < 10:
        for _ in range(count):
            name = cursor.fstring("entry name")
            entry = _read_entry(cursor, footer)
            entry["name"] = name
            entries.append(entry)
        return mount_point, entries, notes

    cursor.take(8, "path hash seed")
    secondary: dict[str, bytes] = {}
    for label in ("path hash index", "full directory index"):
        if cursor.u32(f"{label} flag"):
            offset = cursor.u64(f"{label} offset")
            size = cursor.u64(f"{label} size")
            cursor.take(20, f"{label} sha1")
            blob = _region(data, offset, size, label)
            if footer["encrypted_index"]:
                blob = _aes_decrypt(blob, aes_key or b"")
            secondary[label] = blob
    encoded = cursor.take(cursor.u32("encoded entries size"), "encoded entries")
    plain_count = cursor.u32("non-encoded entry count")
    if plain_count > MAX_ENTRIES:
        raise _fail("non-encoded entry count exceeds the cap")
    plain = [_read_entry(cursor, footer) for _ in range(plain_count)]

    def resolve(name: str, value: int) -> None:
        if value == -(1 << 31):                 # the deleted / pruned sentinel
            notes.append(f"{name}: directory entry is the deleted sentinel")
            return
        if value >= 0:
            try:
                entry = _read_encoded(_Cursor(encoded, value), footer)
            except UnrealPakError as exc:
                notes.append(f"{name}: encoded entry not read ({exc})")
                return
        elif -value - 1 < len(plain):
            entry = dict(plain[-value - 1])
        else:
            notes.append(f"{name}: directory entry points past the non-encoded entries")
            return
        entry["name"] = name
        entries.append(entry)

    if "full directory index" in secondary:
        directory = _Cursor(secondary["full directory index"])
        for _ in range(directory.u32("directory count")):
            folder = directory.fstring("directory name")
            folder = folder[1:] if folder.startswith("/") else folder
            for _ in range(directory.u32("directory file count")):
                if len(entries) >= MAX_ENTRIES:
                    raise _fail("directory index lists more files than the cap")
                name = directory.fstring("file name")
                resolve(folder + name, directory.i32("encoded entry offset"))
    elif "path hash index" in secondary:
        notes.append("no full directory index: entries are named by path hash, not by file name")
        hashes = _Cursor(secondary["path hash index"])
        total = hashes.u32("path hash count")
        if total > MAX_ENTRIES:
            raise _fail("path hash index lists more files than the cap")
        for _ in range(total):
            path_hash = hashes.u64("path hash")
            resolve(f"<path hash {path_hash:#018x}>", hashes.i32("encoded entry offset"))
    else:
        notes.append("the index has neither a full directory index nor a path hash index: no entry "
                     "can be located")
    return mount_point, entries, notes


# --------------------------------------------------------------------------- extraction
BUDGET_SPENT = "skipped: CPU budget spent"
_BLOCK_SLACK = 64                  # stream header and trailer (zlib 6, gzip 18), AES padding (15)


def _stored_bound(size: int) -> int:
    """The most stored bytes a zlib or gzip stream can need for ``size`` bytes of data.

    Deflate grows data it cannot compress by a few bytes per stored block; a quarter on top is far
    above that for any setting, and above the wrapper and AES padding of every block of an entry
    cut into blocks of a few hundred bytes or more.  A block, or the blocks of one entry together,
    that declare more are not that entry's compressed data, and reading them would let the archive
    choose how much this reader allocates and inflates."""
    return size + (size >> 2) + _BLOCK_SLACK


def _inflate_block(chunk: bytes, wbits: int, room: int) -> bytes:
    try:
        return zlib.decompressobj(wbits).decompress(chunk, room + 1)
    except zlib.error as exc:
        raise _fail(f"compression block does not inflate ({exc})") from exc


def _extract(data, footer: dict[str, Any], entry: dict[str, Any], aes_key: bytes | None,
             remaining: list[int], stop: Callable[[], bool] | None = None) -> tuple[bytes | None, str]:
    """``(payload, status)``: the payload is None unless the status is ``ok``.

    The stored bytes read for a compressed entry are bounded by its (capped) uncompressed size, per
    block and in all, never by what a block declares; ``stop()`` is read before each block, so one
    entry with many blocks cannot outrun the CPU budget (status :data:`BUDGET_SPENT`)."""
    usize, csize = entry["uncompressed_size"], entry["compressed_size"]
    method = entry["compression"]
    if entry["deleted"]:
        return None, "skipped: a delete record, not a file"
    if usize > MAX_EXTRACT_PER_ENTRY:
        return None, f"skipped: larger than the {MAX_EXTRACT_PER_ENTRY} byte per-entry cap"
    if usize > remaining[0]:
        return None, "skipped: the total extraction cap is spent"
    if entry["encrypted"] and aes_key is None:
        return None, "blocked: AES-encrypted entry; supply the AES-256 key"
    if method not in (None, "zlib", "gzip"):
        return None, f"unsupported: {method} compression is not decoded by this reader"
    try:
        cursor = _Cursor(data, entry["offset"])
        _read_entry(cursor, footer)             # the entry header repeated ahead of the data
        start = cursor.pos
        if method is None:
            if csize < usize:
                return None, "truncated: stored data is shorter than its declared size"
            # Only the uncompressed size is read (it is the capped one): a stored entry that declares a
            # larger stored size must not make this reader allocate it.
            size = _align16(usize) if entry["encrypted"] else usize
            region = bytes(data[start:start + size])
            if len(region) != size:
                return None, "truncated: stored data is shorter than its declared size"
            if entry["encrypted"]:
                region = _aes_decrypt(region, aes_key or b"")
            payload = region[:usize]
        else:
            if not entry["blocks"]:
                return None, "error: a compressed entry that lists no blocks"
            out = bytearray()
            block_limit = _stored_bound(usize)  # one block holds the whole entry at most
            stored_room = block_limit           # and so do all of them together
            for block_start, block_end in entry["blocks"]:
                if stop is not None and stop():
                    return None, BUDGET_SPENT
                if footer["version"] >= 5:      # block offsets relative to the entry from version 5
                    block_start, block_end = entry["offset"] + block_start, entry["offset"] + block_end
                size = block_end - block_start
                stored = _align16(size) if entry["encrypted"] else size
                if size < 0 or block_start < 0 or block_start + stored > len(data):
                    return None, "truncated: a compression block runs outside the archive"
                if size > block_limit:
                    return None, (f"error: a compression block of {size} stored bytes in an entry of "
                                  f"{usize} bytes: more than its compression can need, not read")
                stored_room -= stored
                if stored_room < 0:
                    return None, (f"error: the compression blocks of an entry of {usize} bytes hold "
                                  "more stored bytes than its compression can need: the rest not read")
                chunk = bytes(data[block_start:block_start + stored])
                if entry["encrypted"]:
                    chunk = _aes_decrypt(chunk, aes_key or b"")[:size]
                out.extend(_inflate_block(chunk, 16 + zlib.MAX_WBITS if method == "gzip" else zlib.MAX_WBITS,
                                          usize - len(out)))
                if len(out) > usize:
                    return None, "error: inflates past the declared uncompressed size"
            if len(out) != usize:
                return None, "error: inflated size differs from the declared uncompressed size"
            payload = bytes(out)
    except UnrealPakError as exc:
        return None, f"error: {exc}"
    remaining[0] -= len(payload)
    return payload, "ok"


# --------------------------------------------------------------------------- literal pool
def _find_all(data, needle: bytes, limit: int, fold: bool = False) -> list[int]:
    """Offsets of ``needle`` in bytes or a mapped file, read in steps (lower-cased when ``fold``).

    Each step reads ``len(needle) - 1`` bytes past its end, so a needle that straddles the edge is
    found by the step it starts in and by no other."""
    out: list[int] = []
    overlap = len(needle) - 1
    for base in range(0, len(data), _FIND_STEP):
        chunk = bytes(data[base:base + _FIND_STEP + overlap])
        if fold:
            chunk = chunk.lower()
        pos = chunk.find(needle)
        while pos >= 0:
            if len(out) >= limit:
                return out
            out.append(base + pos)
            pos = chunk.find(needle, pos + 1)
    return out


def _ascii_run(data, pos: int) -> tuple[int, str]:
    start = pos
    while start > 0 and pos - start < MAX_RUN_CHARS and 0x20 <= data[start - 1] <= 0x7E:
        start -= 1
    end = pos
    while end < len(data) and end - pos < MAX_RUN_CHARS and 0x20 <= data[end] <= 0x7E:
        end += 1
    return start, bytes(data[start:end]).decode("ascii")


def _utf16_run(data, pos: int) -> tuple[int, str]:
    start = pos
    while start >= 2 and pos - start < 2 * MAX_RUN_CHARS and data[start - 1] == 0 \
            and 0x20 <= data[start - 2] <= 0x7E:
        start -= 2
    end = pos
    while end + 1 < len(data) and end - pos < 2 * MAX_RUN_CHARS and data[end + 1] == 0 \
            and 0x20 <= data[end] <= 0x7E:
        end += 2
    return start, bytes(data[start:end]).decode("utf-16-le")


def _utf8_flag(flag: str) -> str:
    if flag.isascii():
        return flag
    try:                                        # the bytes regex reads latin-1; stored text is UTF-8
        return flag.encode("latin-1").decode("utf-8")
    except UnicodeError:
        return flag


def flag_scan(data, ff: flagfmt.FlagFormat) -> tuple[list[dict[str, Any]], list[str]]:
    """Every flag of the format in ``data`` as ASCII and as UTF-16LE: ``([{flag, offset, encoding}],
    cuts)``.  With known prefixes this is a literal search for ``PREFIX{`` and one regex match at each
    hit, so it is cheap on a large binary; with no known prefix the whole buffer goes through the
    regex, up to MAX_SLOW_SCAN bytes.  ``cuts`` says, in words, every way a cap cut the scan short:
    hits past MAX_FLAGS, a lead found MAX_NEEDLE_HITS times, the MAX_SLOW_SCAN window.  It is empty
    when the scan was complete."""
    hits: list[dict[str, Any]] = []
    dropped = [0]
    cuts: list[str] = []

    def add(flag: str, offset: int, encoding: str) -> bool:
        # A loose flag body can run from a prefix across binary data to the next brace: a hit with a
        # control character in it is not a flag, and a real one may start inside it.
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in flag):
            return False
        if len(hits) < MAX_FLAGS:
            hits.append({"flag": flag, "offset": offset, "encoding": encoding})
        else:
            dropped[0] += 1
        return True

    def finish() -> tuple[list[dict[str, Any]], list[str]]:
        if dropped[0]:
            cuts.append(f"{dropped[0]} flag hit(s) past the cap of {MAX_FLAGS} were not kept")
        return hits, cuts

    prefixes = ff.spec.prefixes
    if not prefixes:
        window = bytes(data[:MAX_SLOW_SCAN])
        for match in ff.bregex.finditer(window):
            add(_utf8_flag(match.group().decode("latin-1")), match.start(), "ascii")
        for run in _UTF16_RUN.finditer(window):
            text = run.group().decode("utf-16-le")
            for match in ff.packed_regex.finditer(text):
                add(match.group(), run.start() + 2 * match.start(), "utf-16-le")
        if len(window) < len(data):
            cuts.append(f"no known flag prefix: only the first {MAX_SLOW_SCAN} bytes went through the "
                        "flag regex")
        return finish()

    fold = ff.spec.case != "exact"
    leads = [(prefix.lower() if fold else prefix) + "{" for prefix in prefixes]
    for encoding in ("ascii", "utf-16-le"):
        found = {lead: _find_all(data, lead.encode(encoding), MAX_NEEDLE_HITS, fold) for lead in leads}
        capped = sorted(lead for lead, where in found.items() if len(where) >= MAX_NEEDLE_HITS)
        if capped:
            cuts.append(f"the flag lead {', '.join(capped)} ({encoding}) occurs {MAX_NEEDLE_HITS} times "
                        "or more: later occurrences were not looked at")
        positions = sorted({pos for where in found.values() for pos in where})
        end = -1
        for pos in positions:
            if pos < end:                       # inside the previous flag (CTF{ inside CSCTF{...})
                continue
            if encoding == "ascii":
                match = ff.bregex.match(data, pos)
                if match and add(_utf8_flag(match.group().decode("latin-1")), pos, encoding):
                    end = match.end()
            else:
                _start, text = _utf16_run(data, pos)
                match = ff.packed_regex.match(text, (pos - _start) // 2)
                if match and add(match.group(), pos, encoding):
                    end = pos + 2 * (match.end() - match.start())
    hits.sort(key=lambda hit: hit["offset"])
    return finish()


def flag_hits(data, ff: flagfmt.FlagFormat) -> tuple[list[dict[str, Any]], bool]:
    """:func:`flag_scan` with its cuts as one bool: ``(hits, truncated)``."""
    hits, cuts = flag_scan(data, ff)
    return hits, bool(cuts)


def _urls(data, cuts: list[str]) -> list[dict[str, Any]]:
    """URL literals; what a cap left out is appended to ``cuts`` in words."""
    found: dict[str, dict[str, Any]] = {}
    dropped: set[str] = set()
    for encoding in ("ascii", "utf-16-le"):
        positions = _find_all(data, "://".encode(encoding), MAX_NEEDLE_HITS)
        if len(positions) >= MAX_NEEDLE_HITS:
            cuts.append(f"'://' ({encoding}) occurs {MAX_NEEDLE_HITS} times or more: later URLs were "
                        "not looked at")
        for pos in positions:
            start, text = _ascii_run(data, pos) if encoding == "ascii" else _utf16_run(data, pos)
            for match in _URL.finditer(text):
                url = match.group().rstrip(".,;:)'")
                if url in found:
                    continue
                if len(found) < MAX_URLS:
                    step = 1 if encoding == "ascii" else 2
                    found[url] = {"url": url, "offset": start + step * match.start(), "encoding": encoding}
                else:
                    dropped.add(url)
    if dropped:
        cuts.append(f"{len(dropped)} more URL(s) past the cap of {MAX_URLS} were not kept")
    return sorted(found.values(), key=lambda row: row["offset"])


def _script_modules(data, cuts: list[str]) -> dict[str, dict[str, Any]]:
    modules: dict[str, dict[str, Any]] = {}
    for encoding in ("ascii", "utf-16-le"):
        needle = "/Script/".encode(encoding)
        step = 1 if encoding == "ascii" else 2
        positions = _find_all(data, needle, MAX_NEEDLE_HITS)
        if len(positions) >= MAX_NEEDLE_HITS:
            cuts.append(f"'/Script/' ({encoding}) occurs {MAX_NEEDLE_HITS} times or more: later module "
                        "names were not looked at")
        for pos in positions:
            tail = bytes(data[pos + len(needle):pos + len(needle) + 64 * step])
            if encoding != "ascii":
                tail = tail[:len(tail) & ~1]
            match = _SCRIPT_NAME.match(tail.decode(encoding, "replace"))
            if not match:
                continue
            row = modules.setdefault(match.group(), {"module": match.group(), "count": 0, "anchors": []})
            row["count"] += 1
            if len(row["anchors"]) < MAX_ANCHORS:
                row["anchors"].append({"offset": pos, "encoding": encoding})
    return modules


def _endpoint(text: str) -> bool:
    match = _ENDPOINT.fullmatch(text)
    return bool(match) and match.group(1) not in _SYSTEM_ROOTS


def literal_pool(data, *, profile=None, strings: bool = False) -> dict[str, Any]:
    """Flags, URLs, ``/Script/<Module>`` names and the literals next to the game's own module name.

    ``data`` is bytes or a mapped file.  ``strings`` adds every ASCII and UTF-16LE run (slow, large)."""
    ff = flagfmt.for_profile(profile) if profile is not None else flagfmt.current()
    hits, cuts = flag_scan(data, ff)
    list_cuts: list[str] = []                   # what the caps on the lead lists (not the flags) left out
    urls = _urls(data, list_cuts)
    modules = _script_modules(data, list_cuts)
    game = sorted((row for name, row in modules.items() if name not in _ENGINE_MODULES),
                  key=lambda row: (-row["count"], row["module"]))
    if len(game) > MAX_GAME_MODULES:
        list_cuts.append(f"literals are listed for the first {MAX_GAME_MODULES} of {len(game)} game modules")
    literals: list[dict[str, Any]] = []
    literals_cut = False
    seen: set[str] = set()
    for row in game[:MAX_GAME_MODULES]:
        for anchor in row["anchors"]:
            low = max(0, anchor["offset"] - LITERAL_WINDOW)
            window = bytes(data[low:anchor["offset"] + LITERAL_WINDOW])
            pattern = _ASCII_RUN if anchor["encoding"] == "ascii" else _UTF16_RUN
            near = []
            for match in pattern.finditer(window):
                text = match.group().decode(anchor["encoding"])
                near.append((abs(low + match.start() - anchor["offset"]), low + match.start(), text))
            for _distance, offset, text in sorted(near):
                if text in seen:
                    continue
                if len(literals) >= MAX_MODULE_LITERALS:
                    literals_cut = True
                    break
                seen.add(text)
                literals.append({"module": row["module"], "offset": offset,
                                 "encoding": anchor["encoding"], "text": text[:200]})
    if literals_cut:
        list_cuts.append(f"more than {MAX_MODULE_LITERALS} literals sit next to the game module names: "
                         "the nearest are listed")
    endpoints = sorted({row["text"] for row in literals if _endpoint(row["text"])})
    report: dict[str, Any] = {
        "kind": "ue-literal-pool", "size": len(data), "flags": hits, "flag_scan_truncated": bool(cuts),
        "flag_scan_cuts": cuts, "list_cuts": list_cuts, "urls": urls,
        "script_modules": [{"module": row["module"], "count": row["count"]}
                           for row in sorted(modules.values(), key=lambda row: row["module"])],
        "game_modules": [row["module"] for row in game],
        "module_literals": literals, "endpoints": endpoints,
    }
    if strings:
        report["strings"] = (
            [{"offset": m.start(), "encoding": "ascii", "text": m.group().decode("ascii")}
             for m in _ASCII_RUN.finditer(data)]
            + [{"offset": m.start(), "encoding": "utf-16-le", "text": m.group().decode("utf-16-le")}
               for m in _UTF16_RUN.finditer(data)])
    return report


# --------------------------------------------------------------------------- the archive
def _decode_text(payload: bytes) -> str:
    if payload[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return payload.decode("utf-16", "replace")
    return payload.decode("utf-8", "replace")


def _config(name: str, payload: bytes) -> tuple[dict[str, Any] | None, list[str]]:
    """``(row, cuts)``: the URLs and setting lines of one config entry, and what a cap left out."""
    text = _decode_text(payload)
    urls: list[str] = []
    lines: list[str] = []
    more_lines = 0
    for line in text.splitlines():
        found = [match.group().rstrip(".,;:)'") for match in _URL.finditer(line)]
        urls.extend(url for url in found if url not in urls)
        if found or _CONFIG_KEY.match(line):
            if len(lines) < MAX_CONFIG_LINES:
                lines.append(line.strip()[:300])
            else:
                more_lines += 1
    if not lines:
        return None, []
    cuts: list[str] = []
    if more_lines:
        cuts.append(f"{name}: {more_lines} more URL or setting line(s) past the cap of {MAX_CONFIG_LINES} "
                    "were not kept")
    if len(urls) > MAX_URLS:
        cuts.append(f"{name}: {len(urls) - MAX_URLS} more URL(s) past the cap of {MAX_URLS} were not kept")
    return {"name": name, "urls": urls[:MAX_URLS], "lines": lines}, cuts


def read_pak(data, *, aes_key: bytes | None = None, extract: bool = True, profile=None,
             sink: Callable[[str, bytes], None] | None = None,
             stop: Callable[[], bool] | None = None) -> dict[str, Any]:
    """Read a ``.pak`` held in memory (or mapped): footer, index, entries, flags, config URLs.

    ``aes_key`` is the 32-byte AES-256 key for an encrypted index or entry.  ``sink(name, payload)``
    is called for each extracted entry; ``stop()`` returning True ends extraction early (a CPU budget),
    and the entries it did not reach say so.  A bad archive is an :class:`UnrealPakError`; with no
    ``profile`` and no event that resolves, ``ctf.event.EventError`` (there is then no flag format).
    """
    ff = flagfmt.for_profile(profile) if profile is not None else flagfmt.current()
    try:
        if isinstance(data, (bytes, bytearray, memoryview)):
            if len(data) > MAX_PAK_INPUT:
                raise _fail(f"in-memory archive exceeds {MAX_PAK_INPUT} bytes: use read_pak_file")
            data = bytes(data)
        elif not isinstance(data, mmap.mmap):
            raise _fail("pak input must be bytes-like or a mapped file")
        if aes_key is not None and (not isinstance(aes_key, (bytes, bytearray)) or len(aes_key) != AES_KEY_LEN):
            raise _fail(f"aes_key must be {AES_KEY_LEN} bytes")
        aes_key = bytes(aes_key) if aes_key is not None else None

        footer = _find_footer(data)
        version = footer["version"]
        index_region = bytes(data[footer["index_offset"]:footer["index_offset"] + footer["index_size"]])
        declared = footer["index_sha1"]
        index: bytes | None = index_region
        index_status = "ok"
        if footer["encrypted_index"]:
            if aes_key is None:
                index, index_status = None, ("blocked: AES-encrypted index; supply the AES-256 key to read "
                                             "the file names")
            else:
                try:
                    index = _aes_decrypt(index_region, aes_key)
                except UnrealPakError as exc:
                    index, index_status = None, f"blocked: the index did not decrypt ({exc})"
                else:
                    if hashlib.sha1(index).hexdigest() != declared:
                        index, index_status = None, ("blocked: wrong AES key (the decrypted index does not "
                                                     "match the footer SHA-1)")
                    else:
                        index_status = "ok: index decrypted"
        sha1_match = None if index is None else hashlib.sha1(index).hexdigest() == declared
        if index is not None and version > MAX_VERSION:
            index, index_status = None, (f"blocked: pak version {version} is newer than this reader "
                                         f"(versions 1-{MAX_VERSION})")
        elif index is not None and footer["frozen_index"]:
            index, index_status = None, "blocked: frozen index (version 9), which this reader does not decode"

        mount_point: str | None = None
        entries: list[dict[str, Any]] = []
        notes: list[str] = []
        if index is not None:
            try:
                mount_point, entries, notes = _parse_index(data, footer, index, aes_key)
            except UnrealPakError as exc:
                index_status, entries = f"error: the index did not parse ({exc})", []
            else:
                if sha1_match is False:
                    notes.append("the index does not match the footer SHA-1: it was edited after packing")

        flags: dict[str, dict[str, Any]] = {}
        flags_dropped = [0]
        scan_cut: list[str] = []                # entries whose own flag scan a cap cut short

        def note_flag(flag: str, source: dict[str, Any]) -> None:
            row = flags.get(flag)
            if row is None:
                if len(flags) >= MAX_FLAGS:
                    flags_dropped[0] += 1
                    return
                row = flags[flag] = {"flag": flag, "sources": []}
            if len(row["sources"]) < MAX_FLAG_SOURCES and source not in row["sources"]:
                row["sources"].append(source)

        configs: list[dict[str, Any]] = []
        config_cuts: list[str] = []             # what the caps on the config harvest left out
        configs_unread = 0
        remaining = [MAX_EXTRACT_TOTAL]
        stopped = False
        for entry in entries:
            if not extract:
                entry["extract_status"] = "not extracted (index only)"
            elif stopped or (stop is not None and stop()):
                stopped = True
                entry["extract_status"] = BUDGET_SPENT
            else:
                payload, status = _extract(data, footer, entry, aes_key, remaining, stop)
                entry["extract_status"] = status
                stopped = status == BUDGET_SPENT        # spent part-way through this entry's blocks
                if payload is not None:
                    found, cuts = flag_scan(payload, ff)
                    if cuts:
                        entry["flag_scan_cuts"] = cuts
                        scan_cut.append(f"{entry['name']}: {'; '.join(cuts)}")
                    entry["flags"] = sorted({hit["flag"] for hit in found})
                    for hit in found:
                        note_flag(hit["flag"], {"entry": entry["name"], "offset": hit["offset"],
                                                "encoding": hit["encoding"]})
                    if entry["name"].lower().endswith(_CONFIG_SUFFIXES):
                        if len(configs) < MAX_CONFIGS:
                            config, config_notes = _config(entry["name"], payload)
                            if config is not None:
                                configs.append(config)
                                config_cuts.extend(config_notes)
                        else:
                            configs_unread += 1
                    if sink is not None:
                        sink(entry["name"], payload)
            entry.setdefault("flags", [])
            entry["block_count"] = len(entry.pop("blocks"))

        if stopped or (stop is not None and stop()):
            pool = None
            notes.append("the archive's literal pool was not read: CPU budget spent")
        else:
            pool = literal_pool(data, profile=profile)
            for hit in pool["flags"]:
                note_flag(hit["flag"], {"archive_offset": hit["offset"], "encoding": hit["encoding"]})
        cut_notes: list[str] = []               # every way a cap cut the flag harvest of this archive
        if pool is not None and pool["flag_scan_cuts"]:
            cut_notes.append("flag scan of the archive bytes cut short: " + "; ".join(pool["flag_scan_cuts"]))
        if scan_cut:
            cut_notes.append(f"flag scan cut short in {len(scan_cut)} entry(ies), first {scan_cut[0]}")
        if flags_dropped[0]:
            cut_notes.append(f"{flags_dropped[0]} flag hit(s) past the cap of {MAX_FLAGS} distinct flags "
                             "were not kept")
        notes.extend(cut_notes)
        if configs_unread:
            config_cuts.append(f"{configs_unread} more config file(s) past the cap of {MAX_CONFIGS} were "
                               "not searched for URLs and settings")
        notes.extend(config_cuts)

        statuses: dict[str, int] = {}
        for entry in entries:
            key = entry["extract_status"].split(":", 1)[0]
            statuses[key] = statuses.get(key, 0) + 1
        return {
            "kind": "unreal-pak",
            "version": version,
            "footer_location": footer["location"],
            "magic_offset": footer["magic_offset"],
            "index_offset": footer["index_offset"],
            "index_size": footer["index_size"],
            "index_encrypted": footer["encrypted_index"],
            "encryption_key_guid": footer["encryption_key_guid"],
            "compression_names": footer["compression_names"],
            "index_sha1_declared": declared,
            "index_sha1_match": sha1_match,
            "index_status": index_status,
            "mount_point": mount_point,
            "entry_count": len(entries),
            "entries": entries,
            "extract_statuses": dict(sorted(statuses.items())),
            "notes": notes,
            "configs": configs,
            "config_cuts": config_cuts,
            "literal_pool": pool,
            "flags": list(flags.values()),
            "flags_dropped": flags_dropped[0],
            "flag_scan_truncated": bool(cut_notes),
            "flag_scan_cuts": cut_notes,
            "extraction_cap_remaining": remaining[0],
            "external_files_accessed": False,
        }
    except UnrealPakError:
        raise
    except Exception as exc:  # fail-closed public boundary
        raise _fail(f"pak reader declined the input ({type(exc).__name__})") from None


class _Mapped:
    """A file mapped read-only (any size the OS maps), closed on exit."""

    def __init__(self, path: Path, cap: int) -> None:
        self.path, self.cap = Path(path), cap
        self.handle = None
        self.view: mmap.mmap | None = None

    def __enter__(self) -> mmap.mmap:
        if self.path.is_symlink():
            raise _fail(f"{self.path.name} is a symlink (not followed)")
        self.handle = self.path.open("rb")
        try:
            size = os.fstat(self.handle.fileno()).st_size
            if size == 0:
                raise _fail(f"{self.path.name} is empty")
            if size > self.cap:
                raise _fail(f"{self.path.name} is larger than the {self.cap} byte cap")
            self.view = mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_READ)
        except BaseException:
            self.handle.close()
            raise
        return self.view

    def __exit__(self, *_exc) -> None:
        if self.view is not None:
            try:
                self.view.close()
            except BufferError:            # a live view of the map: it is unmapped when that goes
                pass
        if self.handle is not None:
            self.handle.close()


def read_pak_file(path: str | os.PathLike, **kwargs) -> dict[str, Any]:
    """:func:`read_pak` on a file, mapped rather than read, so a multi-gigabyte archive is fine."""
    try:
        with _Mapped(Path(path), MAX_PAK_FILE) as view:
            return read_pak(view, **kwargs)
    except OSError as exc:
        raise _fail(f"could not read {Path(path).name} ({exc.strerror or type(exc).__name__})") from None


def literal_pool_file(path: str | os.PathLike, **kwargs) -> dict[str, Any]:
    """:func:`literal_pool` on a file, mapped rather than read."""
    try:
        with _Mapped(Path(path), MAX_PAK_FILE) as view:
            return literal_pool(view, **kwargs)
    except OSError as exc:
        raise _fail(f"could not read {Path(path).name} ({exc.strerror or type(exc).__name__})") from None


def _safe_parts(name: str) -> tuple[str, ...] | None:
    parts = tuple(part for part in re.split(r"[\\/]+", name) if part not in ("", "."))
    if not parts or any(part == ".." or ":" in part or "\x00" in part for part in parts):
        return None
    return parts


def unpack(path: str | os.PathLike, dest: str | os.PathLike, *, aes_key: bytes | None = None,
           profile=None) -> dict[str, Any]:
    """Extract a ``.pak`` into ``dest``.  An entry whose name is absolute, has a drive letter or climbs
    with ``..`` is not written; neither is one whose target exists or is a symlink.  Returns the
    :func:`read_pak` report with ``written`` and ``not_written`` lists."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    written: list[str] = []
    refused: list[dict[str, str]] = []

    def sink(name: str, payload: bytes) -> None:
        parts = _safe_parts(name)
        if parts is None:
            refused.append({"name": name, "why": "unsafe entry name (absolute, drive letter or '..')"})
            return
        target = root.joinpath(*parts)
        try:
            # One folder at a time from the destination down, so a symlinked folder on the way is seen
            # before anything is created behind it.
            folder = root
            for part in parts[:-1]:
                folder = folder / part
                if folder.is_symlink():
                    refused.append({"name": name, "why": "target folder leaves the destination (a symlink)"})
                    return
                if folder.exists() and not folder.is_dir():
                    refused.append({"name": name, "why": "a file is in the way of the target folder"})
                    return
                if not folder.exists():
                    folder.mkdir()
            if target.parent.resolve() != target.parent or root not in (target.parent, *target.parent.parents):
                refused.append({"name": name, "why": "target folder leaves the destination (a symlink)"})
                return
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
        except FileExistsError:
            refused.append({"name": name, "why": "target already exists"})
            return
        except OSError as exc:
            refused.append({"name": name, "why": f"not written ({exc.strerror or type(exc).__name__})"})
            return
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
        written.append("/".join(parts))

    report = read_pak_file(path, aes_key=aes_key, profile=profile, sink=sink)
    report["written"] = written
    report["not_written"] = refused
    return report


# --------------------------------------------------------------------------- intake entry
def _candidates(root: Path) -> tuple[list[tuple[Path, str]], bool, list[tuple[Path, str]]]:
    """Unreal files at or under ``root``: [(path, 'pak' | 'asset' | 'binary')], whether the walk was
    cut, and the files that might be executables but could not be opened to see: [(path, why)]."""
    if root.is_file():
        lower = root.name.lower()
        kind = "pak" if lower.endswith(".pak") else "asset" if lower.endswith(_ASSET_SUFFIXES) else "binary"
        return [(root, kind)], False, []
    found: list[tuple[Path, str]] = []
    unreadable: list[tuple[Path, str]] = []
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if name not in _PRUNE_DIRS)
        for name in sorted(filenames):
            seen += 1
            if seen > MAX_WALK_FILES:
                return found, True, unreadable
            path = Path(dirpath, name)
            lower = name.lower()
            if path.is_symlink():
                continue
            if lower.endswith(".pak"):
                found.append((path, "pak"))
            elif lower.endswith(_ASSET_SUFFIXES):
                found.append((path, "asset"))
            elif lower.endswith(_BINARY_SUFFIXES) or "." not in name:
                try:
                    with path.open("rb") as handle:
                        head = handle.read(4)
                except OSError as exc:
                    unreadable.append((path, exc.strerror or type(exc).__name__))
                    continue
                if head.startswith(_BINARY_MAGICS):
                    found.append((path, "binary"))
    order = {"pak": 0, "binary": 1, "asset": 2}
    found.sort(key=lambda item: (order[item[1]], item[0].as_posix()))
    return found, False, unreadable


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


_SOLVE_OPTS = frozenset({"aes_key", "budget", "report"})


def survey(path: str | os.PathLike, *, profile=None, aes_key: bytes | None = None,
           budget: float | None = DEFAULT_BUDGET_S,
           clock: Callable[[], float] | None = None) -> dict[str, Any]:
    """Read every Unreal file at or under ``path``: archives in full, binaries and assets through the
    literal pool.  ``budget`` is CPU seconds (None for no limit) on ``clock`` (``time.process_time``)."""
    root = Path(path)
    if not root.exists():
        raise _fail(f"no such path: {root}")
    if budget is not None and (isinstance(budget, bool) or not isinstance(budget, (int, float))
                               or not math.isfinite(budget) or budget <= 0):
        raise _fail("budget must be a positive number of CPU seconds, or None")
    clock = clock or time.process_time
    start = clock()

    def spent() -> bool:
        return budget is not None and clock() - start >= budget

    base = root if root.is_dir() else root.parent
    files, cut, unreadable = _candidates(root)
    skipped: list[dict[str, str]] = []
    if cut:
        skipped.append({"what": "discovery", "why": f"more than {MAX_WALK_FILES} files: the walk stopped early"})
    for path_, why in unreadable[:MAX_UNREADABLE_ROWS]:
        skipped.append({"what": path_.relative_to(base).as_posix(),
                        "why": f"could not be opened ({why}): not checked for an Unreal executable"})
    if len(unreadable) > MAX_UNREADABLE_ROWS:
        skipped.append({"what": "discovery", "why": f"{len(unreadable) - MAX_UNREADABLE_ROWS} more file(s) "
                                                    "could not be opened and were not checked"})
    archives: list[dict[str, Any]] = []
    pools: list[dict[str, Any]] = []
    iostore: list[str] = []
    pools_read = 0
    digests: dict[str, str] = {}
    not_reached: list[str] = []
    for path_, kind in files:
        rel = path_.relative_to(base).as_posix()
        if spent():
            not_reached.append(rel)
            continue
        try:
            digest = _file_sha256(path_)
        except OSError as exc:
            skipped.append({"what": rel, "why": f"could not be read ({exc.strerror or type(exc).__name__})"})
            continue
        if digest in digests:
            skipped.append({"what": rel, "why": f"same content as {digests[digest]}"})
            continue
        digests[digest] = rel
        try:
            if kind == "pak":
                report = read_pak_file(path_, aes_key=aes_key, profile=profile, stop=spent)
                report["file"] = rel
                archives.append(report)
            else:
                if path_.name.lower().endswith(_IOSTORE_SUFFIXES):
                    iostore.append(rel)        # named when met: the container itself is not decoded
                    skipped.append({"what": rel, "why": IOSTORE_WHY})
                pool = literal_pool_file(path_, profile=profile)
                pools_read += 1
                pool["file"] = rel
                if (pool["flags"] or pool["script_modules"] or pool["flag_scan_cuts"]
                        or (kind == "asset" and pool["urls"])):
                    pools.append(pool)
        except UnrealPakError as exc:
            skipped.append({"what": rel, "why": str(exc)})
    if not_reached:
        shown = ", ".join(not_reached[:5]) + (" ..." if len(not_reached) > 5 else "")
        skipped.append({"what": "budget", "why": f"{len(not_reached)} file(s) not reached: CPU budget "
                                                 f"spent ({shown})"})
    return {"kind": "unreal-survey", "root": root.name, "files": len(files), "archives": archives,
            "literal_pools": pools, "literal_pools_read": pools_read, "iostore": iostore, "skipped": skipped,
            "budget": {"limit_s": budget, "used_s": round(clock() - start, 3), "spent": spent()}}


def solve(challenge_dir, profile=None, **opts):
    """Intake entry: read the handout's ``.pak`` archives and the literal pool of its Unreal binaries.

    Options: ``aes_key`` (``0x`` + 64 hex characters, or base64), ``budget`` (CPU seconds, default 20),
    ``report`` (a path to write the full JSON report to).  One distinct flag is ``solved``, several are
    ``candidate``; an archive that needs a key, or an IoStore container (``.utoc`` / ``.ucas``, not
    decoded here), that gave nothing else is ``blocked`` naming the key or the container; URLs,
    endpoints and module names with no flag are ``unsure`` (they are the evidence); a handout with no
    Unreal file, or whose Unreal files hold nothing, is ``none`` and says which of the two.
    """
    from ctf.result import Evidence, SolverResult

    unknown = sorted(set(opts) - _SOLVE_OPTS)
    if unknown:
        raise _fail(f"unknown option(s) {', '.join(unknown)}; known: {', '.join(sorted(_SOLVE_OPTS))}")
    aes_key = parse_key(str(opts["aes_key"])) if opts.get("aes_key") else None
    report = survey(Path(challenge_dir), profile=profile, aes_key=aes_key,
                    budget=opts.get("budget", DEFAULT_BUDGET_S))
    if opts.get("report"):
        Path(str(opts["report"])).write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    flags: list[str] = []
    evidence: list[Evidence] = []
    notes: list[str] = []
    leads = 0
    unread: list[str] = []
    needs_key = False

    def lead(kind: str, detail: str, path: str) -> None:
        nonlocal leads
        leads += 1
        if len(evidence) < MAX_EVIDENCE:
            evidence.append(Evidence(kind=kind, detail=detail[:300], path=path))

    for archive in report["archives"]:
        rel = archive["file"]
        notes.append(f"{rel}: pak version {archive['version']}, {archive['entry_count']} entries, index "
                     f"{archive['index_status']}; extraction {archive['extract_statuses'] or 'none'}")
        cuts = archive["flag_scan_cuts"] + archive["config_cuts"][:3]
        if archive["literal_pool"] is not None:
            cuts += archive["literal_pool"]["list_cuts"]
        notes.extend(f"{rel}: {note}" for note in [n for n in archive["notes"] if n not in cuts][:3])
        notes.extend(f"{rel}: {note}" for note in cuts)        # a cut harvest is always said
        if archive["index_status"].startswith("blocked"):
            unread.append(f"{rel}: {archive['index_status']}")
            needs_key = needs_key or "AES" in archive["index_status"]
        elif archive["extract_statuses"].get("blocked"):
            unread.append(f"{rel}: {archive['extract_statuses']['blocked']} AES-encrypted entry(ies); "
                          "supply the AES-256 key")
            needs_key = True
        for row in archive["flags"]:
            if row["flag"] not in flags:
                flags.append(row["flag"])
            source = row["sources"][0]
            where = (f"entry {source['entry']} offset {source['offset']}" if "entry" in source
                     else f"archive offset {source['archive_offset']}")
            evidence.insert(0, Evidence(kind="match", detail=f"flag format in {where} ({source['encoding']})",
                                        path=rel))
        for config in archive["configs"]:
            lead("config", f"{config['name']}: " + (", ".join(config["urls"][:4]) or config["lines"][0]), rel)
    for pool in report["literal_pools"]:
        rel = pool["file"]
        for hit in pool["flags"]:
            if hit["flag"] not in flags:
                flags.append(hit["flag"])
            evidence.insert(0, Evidence(kind="match", path=rel, offset=hit["offset"],
                                        detail=f"flag format in the literal pool ({hit['encoding']})"))
        if pool["game_modules"]:
            lead("module", "game module(s): " + ", ".join(pool["game_modules"][:6]), rel)
        if pool["endpoints"]:
            lead("protocol", "endpoint-like literals next to the game module: "
                 + ", ".join(pool["endpoints"][:10]), rel)
        if pool["urls"]:
            lead("url", "URL literal(s): " + ", ".join(row["url"] for row in pool["urls"][:6]), rel)
        notes.extend(f"{rel}: flag scan cut short: {cut}" for cut in pool["flag_scan_cuts"])
        notes.extend(f"{rel}: {cut}" for cut in pool["list_cuts"])
    iostore = report["iostore"]
    if iostore:
        shown = ", ".join(iostore[:4]) + (" ..." if len(iostore) > 4 else "")
        named = (f"IoStore container(s) {shown}: .utoc/.ucas are not decoded by this reader, only their "
                 "literal pool was searched")
        notes.append(named)
        unread.append(named)
    for row in [row for row in report["skipped"] if row["why"] != IOSTORE_WHY][:6]:
        notes.append(f"skipped {row['what']}: {row['why']}")
    if report["budget"]["spent"]:
        notes.append(f"CPU budget of {report['budget']['limit_s']} s spent: rerun with --opt budget=<seconds>")
    notes.append("full report: tools/ctfpy solvers/toolkits/unreal_pak.py <file>")
    evidence = evidence[:MAX_EVIDENCE]

    if len(flags) == 1:
        status = "solved"
    elif flags:
        status = "candidate"
        notes.insert(0, "several distinct flags: not auto-returned")
    elif leads:
        status = "unsure"
        notes.insert(0, "no flag-format hit; the config URLs, module names and literals are the leads")
    elif unread:
        advice = ""
        if needs_key:
            advice += (" For an AES-encrypted pak, recover the AES-256 key from the game executable and "
                       "rerun with --opt aes_key=0x<64 hex> (or the base64 form).")
        if iostore:
            advice += (" For IoStore, unpack the container with a tool that reads .utoc/.ucas and rerun "
                       "on what it writes.")
        return SolverResult(status="blocked", engine=ENGINE_ID, notes=(
            "not readable -- " + "; ".join(unread) + "." + advice + " "
            + "; ".join(note for note in notes if note not in unread)))
    else:
        status = "none"
        if not report["files"]:
            notes.insert(0, "no Unreal archive, asset or module in the handout")
        elif not report["archives"] and not report["literal_pools"]:
            notes.insert(0, f"{report['files']} candidate file(s) (by extension or executable header), "
                            f"{report['literal_pools_read']} read through the literal pool: no archive, "
                            "flag-format hit, URL or game module in them")
    return SolverResult(status=status, flags=tuple(flags), evidence=tuple(evidence), engine=ENGINE_ID,
                        notes="; ".join(notes))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline Unreal .pak reader/unpacker and literal-pool harvest")
    parser.add_argument("path", help="a .pak, a game executable/module or asset, or a folder of them")
    parser.add_argument("--key", help="AES-256 key: 64 hex characters or base64 (an encrypted index/entries)")
    parser.add_argument("--list", action="store_true", help="print one line per archive entry, not JSON")
    parser.add_argument("--extract-to", metavar="DIR", help="write a .pak's entries under DIR")
    parser.add_argument("--literal-pool", action="store_true",
                        help="treat the file as a binary: literal pool only")
    parser.add_argument("--strings", action="store_true", help="with --literal-pool: every string run")
    parser.add_argument("--budget", type=float, default=CLI_BUDGET_S,
                        help=f"CPU seconds for a folder (default {CLI_BUDGET_S:g}); 0 for no limit")
    parser.add_argument("--event", help="event slug whose flag format to harvest (default: the current event)")
    parser.add_argument("--compact", action="store_true")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        profile = _event.load(args.event) if args.event else None
        aes_key = parse_key(args.key) if args.key else None
        target = Path(args.path)
        if target.is_dir():
            report = survey(target, profile=profile, aes_key=aes_key, budget=args.budget or None)
            found = any(a["flags"] for a in report["archives"]) or any(p["flags"] for p in report["literal_pools"])
        elif args.literal_pool or not target.name.lower().endswith(".pak"):
            report = literal_pool_file(target, profile=profile, strings=args.strings)
            if target.name.lower().endswith(_IOSTORE_SUFFIXES):
                report["note"] = IOSTORE_WHY
                print(f"unreal_pak: {target.name}: {IOSTORE_WHY}", file=sys.stderr)
            found = bool(report["flags"])
        elif args.extract_to:
            report = unpack(target, args.extract_to, aes_key=aes_key, profile=profile)
            found = bool(report["flags"])
        else:
            report = read_pak_file(target, aes_key=aes_key, profile=profile)
            found = bool(report["flags"])
    except (UnrealPakError, OSError) as exc:
        print(f"unreal_pak: {exc}", file=sys.stderr)
        return 2
    except _event.EventError as exc:         # no event resolves: say so, never guess a flag format
        print(f"unreal_pak: no flag format ({exc}); set CTF_EVENT or pass --event", file=sys.stderr)
        return 2
    if args.list and report.get("kind") == "unreal-pak":
        print(f"# pak version {report['version']}, index {report['index_status']}, mount "
              f"{report['mount_point']!r}")
        for entry in report["entries"]:
            print(f"{entry['uncompressed_size']:>12} {entry['compression'] or 'stored':<8} "
                  f"{entry['extract_status']:<10.40} {entry['name']}")
        for row in report["flags"]:
            print(f"FLAG {row['flag']}")
    else:
        json.dump(report, sys.stdout, indent=None if args.compact else 2, sort_keys=True)
        sys.stdout.write("\n")
    return 0 if found else 1


__all__ = ["UnrealPakError", "ENGINE_ID", "PAK_MAGIC", "parse_key", "flag_scan", "flag_hits", "literal_pool",
           "literal_pool_file", "read_pak", "read_pak_file", "unpack", "survey", "solve", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
