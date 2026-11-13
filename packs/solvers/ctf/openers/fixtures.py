"""Synthetic day-1 fixtures for the armed Layer-1 openers (B-014).

Each builder writes a *synthetic* input into a destination folder and returns the path the opener
engine is run against. Nothing here is a real challenge file: every fixture is generated from code,
sized to the shape a first-days release used (a base64, rot13 or hex slug blob, a numbered-record
Mastery blob, a PNG, a PowerShell specimen, an ELF, an APK with a puzzle asset), so the regression
gate (`python -m ctf arm`) exercises the real opener with no model and no network. A fixture builder
and the opener's frozen `expect` key are kept in step: if either drifts, arming fails loudly.

Two kinds of builder:
  case     an input the opener must solve; its answer is frozen in openers/layer1.toml
  control  a neutral input of the same file type (no slug, no signal, no puzzle asset, no marker) on
           which no case's key may hold, so a key that the engine prints on anything is caught

    path = fixtures.build("warmups_base64_slug", dest_dir)   # raises FixtureError, never KeyError

Add a builder by registering it in BUILDERS. Keep it deterministic: the opener's answer must not
depend on the clock, the machine or the filesystem (the PNG is stored, not deflated, for that reason).
"""
from __future__ import annotations

import base64
import codecs
import io
import json
import struct
import zipfile
import zlib
from pathlib import Path
from typing import Callable

from . import binary_fixtures as _binary_fixtures
from . import memory_fixtures as _memory_fixtures
from . import mobile_fixtures as _mobile_fixtures
from . import set_fixtures as _set_fixtures

# Synthetic answer slugs (word-word-word-NN), deliberately not real flags or real challenge slugs.
WARMUPS_SLUG = "armed-opener-check-01"
WARMUPS_VARIANT_SLUG = "fresh-variant-check-11"
WARMUPS_MASTERY_SLUG = "mastery-record-check-21"
WARMUPS_ROT13_SLUG = "half-turn-check-02"
WARMUPS_MULTI_SLUG = "multi-record-check-22"
WARMUPS_HEX_SLUG = "hex-appeal-check-03"
WARMUPS_LAYERED_SLUG = "layered-wrap-check-33"

# Synthetic answer codes for the APK puzzle asset (the ANS-<16 hex> shape).
APK_CODE = "ANS-0123456789ABCDEF"
APK_VARIANT_CODE = "ANS-FEDCBA9876543210"


class FixtureError(ValueError):
    """An opener names a fixture builder that does not exist, or a builder could not write it."""


def _write(dest: Path, name: str, data: bytes) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    p = dest / name
    p.write_bytes(data)
    return p


# --------------------------------------------------------------------------- warmups (text blobs)

def _note(slug: str) -> str:
    return (
        "Welcome to the warmup. Decode this message and read its final line.\n"
        "The quick brown fox jumps over the lazy dog near the river bank.\n"
        "The answer slug is on the last line of this note below.\n"
        f"{slug}\n"
    )


def warmups_base64_slug(dest: Path) -> Path:
    """Day-1 base: a base64 text blob whose final non-empty line is the answer slug."""
    return _write(dest, "blob.txt", base64.b64encode(_note(WARMUPS_SLUG).encode()))


def warmups_base64_variant(dest: Path) -> Path:
    """Day-1 Time Trial: the same base64 shape on a fresh variant (a different note and slug)."""
    text = ("Here is a fresh variant of the same warmup for the timed attempt.\n"
            "Read the decoded note and submit the slug on its last line.\n"
            f"{WARMUPS_VARIANT_SLUG}\n")
    return _write(dest, "blob.txt", base64.b64encode(text.encode()))


def warmups_mastery_record(dest: Path) -> Path:
    """Day-1 Mastery: one numbered record `01<TAB><base64>`. A decoder proven only on the bare blob
    reads the `01<TAB>` prefix as part of the payload and returns nothing."""
    payload = base64.b64encode(_note(WARMUPS_MASTERY_SLUG).encode())
    return _write(dest, "member.txt", b"01\t" + payload + b"\n")


def warmups_rot13_slug(dest: Path) -> Path:
    """Day-2 single: a rot13 text blob. rot13 moves letters only, so the slug's digits are read as
    they stand (the digits of the decoded slug are the digits of the blob)."""
    text = ("Half a turn of the alphabet hides this message from a quick look.\n"
            "Turn it back and you will find the answer on the final line.\n"
            f"{WARMUPS_ROT13_SLUG}\n")
    return _write(dest, "blob.txt", codecs.encode(text, "rot13").encode())


def warmups_multi_record(dest: Path) -> Path:
    """Day-2 Mastery: several numbered records, each a fragment of one note in its own encoding
    (base64 and rot13 mixed). The fragments are concatenated in record order, which is not the
    order the lines are written in."""
    frags = [
        ("02", codecs.encode("found on the final line of this note: ", "rot13").encode()),
        ("01", base64.b64encode(b"Join the records in order and the answer is ")),
        ("03", base64.b64encode(f"{WARMUPS_MULTI_SLUG}\n".encode())),
    ]
    return _write(dest, "member.txt", b"".join(n.encode() + b"\t" + p + b"\n" for n, p in frags))


def warmups_hex_slug(dest: Path) -> Path:
    """Day-3 base: a hex text blob whose final decoded line is the slug."""
    return _write(dest, "blob.txt", _note(WARMUPS_HEX_SLUG).encode().hex().encode())


def warmups_layered(dest: Path) -> Path:
    """Day-3 layered: the note in hex, and that hex in base64 (two layers to peel)."""
    return _write(dest, "blob.txt", base64.b64encode(_note(WARMUPS_LAYERED_SLUG).encode().hex().encode()))


def warmups_no_slug(dest: Path) -> Path:
    """Control: a base64 note with no slug on any line. No warmups key may hold on it."""
    text = ("Welcome to the warmup. This note decodes cleanly but carries no answer.\n"
            "The quick brown fox jumps over the lazy dog near the river bank.\n")
    return _write(dest, "blob.txt", base64.b64encode(text.encode()))


# --------------------------------------------------------------------------- metadata (PNG)

def _png(width: int, height: int) -> bytes:
    def chunk(tag: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + tag + body + struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF)

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)     # 8-bit, colour type 2 (RGB)
    raw = b"".join(b"\x00" + b"\xff\x00\x00" * width for _ in range(height))
    idat = zlib.compress(raw, 0)          # level 0: stored blocks, the same bytes on every zlib build
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def metadata_png(dest: Path) -> Path:
    """A minimal valid 2x1 truecolour PNG, byte-for-byte deterministic, so the identity reader's
    format, size and hashes can be frozen."""
    return _write(dest, "evidence.png", _png(2, 1))


def metadata_text(dest: Path) -> Path:
    """Control: a plain text file. It is no image, so no metadata key may hold on it."""
    return _write(dest, "evidence.png", b"just a text note, not an image\n")


# --------------------------------------------------------------------------- script analysis

def _ps_specimen(descriptor: dict, native: list[str]) -> bytes:
    """A PowerShell specimen of the Day-1 shape: `$nativeTypes` names the .NET types it would touch,
    and a JSON descriptor sits base64-encoded under [Convert]::FromBase64String. Benign text, never
    executed: the analyzer reads it statically."""
    blob = base64.b64encode(json.dumps(descriptor).encode()).decode()
    types = ", ".join(f"[{t}]" for t in native)
    return (
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        f"$nativeTypes = @({types})\n"
        f"$descriptor = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{blob}'))\n"
        "$cfg = $descriptor | ConvertFrom-Json\n"
        "Write-Output $cfg.a\n"
    ).encode()


def powershell_resource_hijack(dest: Path) -> Path:
    """Day-1 base: a resource-hijacking specimen (Process + Registry + WebClient + Mutex types, a
    pool URL, a wallet and a mutex in the descriptor), so the analyzer classifies it from real
    signals: scenario, ATT&CK technique and indicators."""
    desc = {"a": "http://pool.invalid.example:3333/job", "b": "wallet_synthetic_0001_armed_check",
            "c": "Global\\ArmedOpenerMiner01"}
    native = ["System.Diagnostics.Process", "Microsoft.Win32.Registry", "System.Net.WebClient",
              "System.Threading.Mutex"]
    return _write(dest, "sample.ps1", _ps_specimen(desc, native))


def powershell_resource_variant(dest: Path) -> Path:
    """Day-1 Time Trial: the same shape on a fresh variant (other indicators, other field names)."""
    desc = {"endpoint": "http://stratum.invalid.example:4444/v2", "wallet": "wallet_synthetic_0002_fresh_variant",
            "lock": "Global\\FreshVariantMiner02"}
    native = ["System.Threading.Mutex", "System.Net.WebClient", "System.Diagnostics.ProcessStartInfo"]
    return _write(dest, "sample.ps1", _ps_specimen(desc, native))


def powershell_neutral(dest: Path) -> Path:
    """Control: a one-line script with no type signal and no descriptor. The analyzer still prints
    its default scenario class here, which is why the script-analysis key must hold more than it."""
    return _write(dest, "sample.ps1", b'Write-Host "hello"\n')


# --------------------------------------------------------------------------- binary (ELF)

def _elf64(*, marker: bytes | None, code: bytes | None, func: str = "recover_code") -> bytes:
    """A minimal, parseable ELF64 x86-64 ET_EXEC. With `code`, a .text section holding it and a .symtab
    with one global FUNC symbol `func` over it; with `marker`, a `.huntress` section holding it. No
    program headers: nothing here can be loaded, and no code runs (the reader parses the bytes)."""
    sections = []      # (name, type, flags, addr, data, link, info, align, entsize)
    if code is not None:
        sections.append((b".text", 1, 0x6, 0x401000, code, 0, 0, 16, 0))           # PROGBITS, AX
    if marker is not None:
        sections.append((b".huntress", 1, 0, 0, marker, 0, 0, 1, 0))
    if code is not None:
        strtab = b"\x00" + func.encode() + b"\x00"
        sym_null = b"\x00" * 24
        # Elf64_Sym: name, info (GLOBAL<<4 | FUNC), other, shndx (.text is section 1), value, size
        sym = struct.pack("<IBBHQQ", 1, (1 << 4) | 2, 0, 1, 0x401000, len(code))
        n = len(sections)
        sections.append((b".symtab", 2, 0, 0, sym_null + sym, n + 2, 1, 8, 24))   # link -> .strtab
        sections.append((b".strtab", 3, 0, 0, strtab, 0, 0, 1, 0))
    shstr = b"\x00"
    offs = []
    for s in sections + [(b".shstrtab",)]:
        offs.append(len(shstr))
        shstr += s[0] + b"\x00"
    sections.append((b".shstrtab", 3, 0, 0, shstr, 0, 0, 1, 0))

    EHSIZE, SHENT = 64, 64
    body = bytearray(b"\x00" * EHSIZE)
    placed = []
    for s in sections:
        align = max(1, s[7])
        body += b"\x00" * ((-len(body)) % align)
        placed.append(len(body))
        body += s[4]
    body += b"\x00" * ((-len(body)) % 8)
    sh_off = len(body)

    def shdr(name, typ, flags, addr, offset, size, link, info, align, entsize) -> bytes:
        return struct.pack("<IIQQQQIIQQ", name, typ, flags, addr, offset, size, link, info, align, entsize)

    body += shdr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    for s, off, name_off in zip(sections, placed, offs):
        _, typ, flags, addr, data, link, info, align, entsize = s
        body += shdr(name_off, typ, flags, addr, off, len(data), link, info, align, entsize)
    shnum = len(sections) + 1
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8                 # ELF64, little-endian, SysV
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2, 0x3E, 1, 0x401000,      # ET_EXEC, EM_X86_64, version, e_entry
        0, sh_off, 0,              # e_phoff, e_shoff, e_flags
        EHSIZE, 0, 0,              # e_ehsize, e_phentsize, e_phnum
        SHENT, shnum, shnum - 1,   # e_shentsize, e_shnum, e_shstrndx (.shstrtab is last)
    )
    body[:EHSIZE] = ehdr
    return bytes(body)


# mov eax, 8100 ; ret  -- the shape of the Day-1 sample's `int recover_code(void) { return 8100; }`
RECOVER_CODE = b"\xb8\xa4\x1f\x00\x00\xc3"


def elf64_orientation(dest: Path) -> Path:
    """Day-1 base: an ELF64 x86-64 with a .huntress marker section and a symbol-table function
    `recover_code` returning a constant, so every field of the Day-1 orientation questions is read."""
    return _write(dest, "day01.elf", _elf64(marker=b"synthetic-day01\x00", code=RECOVER_CODE))


def elf64_bare(dest: Path) -> Path:
    """Control: an ELF64 x86-64 with no marker section, no symbol table and no code. The header
    fields still read, so the binary key must hold the marker, symbol and code fields too."""
    return _write(dest, "day01.elf", _elf64(marker=None, code=None))


# --------------------------------------------------------------------------- mobile (APK)

def _dex(*strings: str) -> bytes:
    """A dex with a real string-id table (count + offset at 0x38, ULEB128 lengths, bodies)."""
    n = len(strings)
    head = bytearray(b"dex\n035\x00" + b"\x00" * (0x70 - 8))
    struct.pack_into("<II", head, 0x38, n, 0x70)
    base = 0x70 + 4 * n
    data = b""
    offs = []
    for s in strings:
        b = s.encode()
        ln = len(b)
        uleb = b""
        while True:
            byte = ln & 0x7F
            ln >>= 7
            uleb += bytes([byte | (0x80 if ln else 0)])
            if not ln:
                break
        offs.append(base + len(data))
        data += uleb + b + b"\x00"
    return bytes(head) + b"".join(struct.pack("<I", o) for o in offs) + data


def _axml(*strings: str) -> bytes:
    """Android binary XML: the RES_XML header and a UTF-16 string pool (enough for is_axml)."""
    count = len(strings)
    offs = []
    data = b""
    for t in strings:
        offs.append(len(data))
        data += struct.pack("<H", len(t)) + t.encode("utf-16-le") + b"\0\0"
    data += b"\0" * (-len(data) % 4)
    hsize = 28
    sstart = hsize + 4 * count
    pool = (struct.pack("<HHIIIIII", 0x0001, hsize, sstart + len(data), count, 0, 0, sstart, 0)
            + b"".join(struct.pack("<I", o) for o in offs) + data)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(pool)) + pool


def _apk(puzzle: dict | None) -> bytes:
    members = {
        "AndroidManifest.xml": _axml("manifest", "package", "com.example.day01"),
        "classes.dex": _dex("DAY-01:exported_trust:marker", "Lcom/example/MainActivity;", "<init>"),
    }
    if puzzle is not None:
        members["assets/huntress_puzzle.json"] = json.dumps(puzzle).encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in members.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 10, 1, 0, 0, 0))      # fixed: deterministic bytes
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, body)
    return buf.getvalue()


def apk_puzzle(dest: Path) -> Path:
    """Day-1 base: an APK (zip: binary manifest, dex) whose puzzle asset carries the answer code under
    the codec the judge accepted on Day 1 (plain), so the puzzle-asset reader answers it plain."""
    doc = {"schema": "huntress.mobile.puzzle.v1", "day": 1, "codec": "plain", "data": APK_CODE}
    return _write(dest, "sample.apk", _apk(doc))


def apk_puzzle_variant(dest: Path) -> Path:
    """Day-1 Time Trial: the same APK shape on a fresh variant (another code)."""
    doc = {"schema": "huntress.mobile.puzzle.v1", "day": 1, "codec": "plain", "data": APK_VARIANT_CODE}
    return _write(dest, "sample.apk", _apk(doc))


def apk_without_puzzle(dest: Path) -> Path:
    """Control: the same APK with no puzzle asset. No mobile key may hold on it."""
    return _write(dest, "sample.apk", _apk(None))


BUILDERS: dict[str, Callable[[Path], Path]] = {
    "warmups_base64_slug": warmups_base64_slug,
    "warmups_base64_variant": warmups_base64_variant,
    "warmups_mastery_record": warmups_mastery_record,
    "warmups_rot13_slug": warmups_rot13_slug,
    "warmups_multi_record": warmups_multi_record,
    "warmups_hex_slug": warmups_hex_slug,
    "warmups_layered": warmups_layered,
    "warmups_no_slug": warmups_no_slug,
    "metadata_png": metadata_png,
    "metadata_text": metadata_text,
    "powershell_resource_hijack": powershell_resource_hijack,
    "powershell_resource_variant": powershell_resource_variant,
    "powershell_neutral": powershell_neutral,
    "elf64_orientation": elf64_orientation,
    "elf64_bare": elf64_bare,
    "apk_puzzle": apk_puzzle,
    "apk_puzzle_variant": apk_puzzle_variant,
    "apk_without_puzzle": apk_without_puzzle,
}
BUILDERS.update(_mobile_fixtures.BUILDERS)   # B-229: the computed-code (analysis) and split-order APK shapes
BUILDERS.update(_set_fixtures.BUILDERS)      # B-042: multi-delivery Mastery attempts (attempt.json + deliveries)
BUILDERS.update(_memory_fixtures.BUILDERS)   # B-136: LiME images with (and without) their kernel's symbol table
BUILDERS.update(_binary_fixtures.BUILDERS)   # B-246: HCFG records under the CRC-gated transform readings


def build(kind: str, dest: Path) -> Path:
    """Write the named fixture into `dest` and return the input path. FixtureError if the kind is
    unknown (no silent fallback) or the builder fails to produce a file."""
    fn = BUILDERS.get(kind)
    if fn is None:
        raise FixtureError(f"no day-1 fixture builder {kind!r}; known: {', '.join(sorted(BUILDERS))}")
    try:
        path = fn(Path(dest))
    except FixtureError:
        raise
    except Exception as e:  # a builder bug must be named, not swallowed
        raise FixtureError(f"fixture {kind!r} failed to build: {type(e).__name__}: {e}") from e
    if not path.is_file():
        raise FixtureError(f"fixture {kind!r} did not write {path}")
    return path
