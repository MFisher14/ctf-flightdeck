#!/usr/bin/env python3
"""Toolkit forensics: STRUCTURE-level breadth for disk/memory/capture forensics (backlog T-b,
docs/retro/day24plus-buildplan-web-toolkits.md; built 2026-10-23). Offline, static, stdlib only.

It is a deliberately NARROW complement to the specialist toolkits, not a competitor:
  - `network` reads pcap/pcapng payloads (DNS, HTTP, TLS, credentials, carved files);
  - `memory` reads Volatility tables and carves process/structure facts;
  - `carve_stego` carves small disk images and ELF cores.
This toolkit answers only the CONTAINER / STRUCTURE facts those do not emphasise, and ONLY for a
format it can validate from a real magic in the bytes:
  - pcap / pcapng: the capture format, its byte order, and the link-layer (datalink) type;
  - memory image: the dump format (Windows crashdump, LiME, ELF core, minidump) and its OS hint;
  - disk image / boot sector: the partition scheme (MBR / GPT), the filesystem (FAT/NTFS/ext),
    and whether the 0x55AA boot signature is present.
It never answers a packet count, a payload, a string's content or anything a payload reader owns:
those stay None here and belong to `network` / `memory` / `carve_stego`. So on a real network or
memory lane the specialist out-answers this toolkit and wins the match.

HARD RULES (AGENTS.md "New categories", "Untrusted content"):
  - RECON / ANALYSIS ONLY. Nothing here mounts, executes or carves beyond a bounded header read;
    the CLI's `--strings` reads at most STRINGS_SCAN bytes and prints them as DATA to report.
  - NEVER-GUESS: every established fact is labels.pick(key, options); everything unproven, and any
    flag, is None. Nothing is ever plain (the format names are author-chosen labels, not judged).
  - Bounded compute: HEADER_SCAN bytes for structure, STRINGS_SCAN bytes for the CLI strings.

Keys: `forensics.<field>/<shape>` (solvers/common/labels.py TOOLKIT_PREFIXES knows `forensics`).
"""
import json
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(1, str(COMMON))
import labels    # noqa: E402
import triage    # noqa: E402

KEY = "forensics"
ARROW = triage.ARROW
HEADER_SCAN = 1 << 20        # bytes read for structure facts (boot sector, superblock, block 1)
STRINGS_SCAN = 1 << 20       # bytes the CLI --strings reads
MAX_FILE = 4 * 1024 * 1024 * 1024

# pcap/pcapng DLT -> a datalink name (a few common ones; the value is an author label, so unsure).
LINKTYPES = {0: "null", 1: "ethernet", 9: "ppp", 101: "raw", 105: "ieee802_11", 108: "loop",
             113: "linux_sll", 127: "ieee802_11_radiotap", 143: "docsis", 147: "user0",
             239: "nflog", 276: "linux_sll2"}


# ---------------------------------------------------------------------------- capture files

def read_capture(data: bytes) -> dict:
    """{format, endian, linktype, linktype_name} for a pcap/pcapng, else None. Header only."""
    if len(data) < 24:
        return None
    magic = data[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):      # classic pcap, big-endian on the wire read
        endian = ">"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif data[:4] == b"\x0a\x0d\x0d\x0a":                       # pcapng Section Header Block
        return _read_pcapng(data)
    else:
        return None
    try:
        linktype = struct.unpack_from(endian + "I", data, 20)[0]
    except struct.error:
        return None
    return {"format": "pcap", "endian": "big" if endian == ">" else "little",
            "linktype": linktype, "linktype_name": LINKTYPES.get(linktype)}


def _read_pcapng(data: bytes) -> dict:
    """pcapng: byte order from the SHB, the first Interface Description Block's linktype."""
    if len(data) < 32:
        return None
    bom = data[8:12]
    if bom == b"\x4d\x3c\x2b\x1a":          # 0x1A2B3C4D stored little-endian
        endian = "<"
    elif bom == b"\x1a\x2b\x3c\x4d":        # stored big-endian
        endian = ">"
    else:
        return None
    out = {"format": "pcapng", "endian": "little" if endian == "<" else "big",
           "linktype": None, "linktype_name": None}
    off, n = 0, min(len(data), HEADER_SCAN)
    try:
        while off + 12 <= n:
            btype, blen = struct.unpack_from(endian + "II", data, off)
            if blen < 12 or off + blen > len(data):
                break
            if btype == 0x00000001:                 # Interface Description Block
                linktype = struct.unpack_from(endian + "H", data, off + 8)[0]
                out["linktype"] = linktype
                out["linktype_name"] = LINKTYPES.get(linktype)
                break
            off += blen
    except struct.error:
        pass
    return out


# ---------------------------------------------------------------------------- memory images

def read_memory(data: bytes) -> dict:
    """{format, os} for a recognised memory dump, else None."""
    head = data[:8]
    if head in (b"PAGEDUMP", b"PAGEDU64"):
        return {"format": "windows_crashdump", "os": "windows"}
    if data[:4] == b"MDMP":
        return {"format": "minidump", "os": "windows"}
    if data[:4] == b"EMiL":                           # LiME header magic (0x4C694D45, little-endian)
        return {"format": "lime", "os": "linux"}
    if data[:4] == b"\x7fELF" and len(data) >= 18:
        try:
            endian = "<" if data[5] == 1 else ">"
            etype = struct.unpack_from(endian + "H", data, 16)[0]
            if etype == 4:                            # ET_CORE
                return {"format": "elf_core", "os": "linux"}
        except struct.error:
            pass
    return None


# ---------------------------------------------------------------------------- disk images / boot sectors

def read_disk(data: bytes) -> dict:
    """{scheme, filesystem, boot_signature} for a disk image or boot sector, else None.
    Validated from real magics only (0x55AA, 'EFI PART', NTFS/FAT OEM, the ext superblock)."""
    if len(data) < 512:
        return None
    boot_sig = data[510:512] == b"\x55\xaa"
    scheme = None
    if len(data) >= 520 and data[512:520] == b"EFI PART":
        scheme = "gpt"
    elif boot_sig:
        # At least one MBR partition entry with a non-zero type byte.
        parts = [data[446 + i * 16: 446 + i * 16 + 16] for i in range(4)]
        if any(p[4] not in (0x00,) for p in parts):
            scheme = "mbr"
    fs = _filesystem(data)
    if scheme is None and fs is None and not boot_sig:
        return None
    return {"scheme": scheme, "filesystem": fs, "boot_signature": boot_sig}


def _filesystem(data: bytes):
    if data[3:11] == b"NTFS    ":
        return "ntfs"
    if data[3:11] == b"EXFAT   ":
        return "exfat"
    if data[82:90] == b"FAT32   ":
        return "fat32"
    if data[54:62] in (b"FAT12   ", b"FAT16   ", b"FAT     "):
        return "fat"
    if len(data) >= 0x440 and data[0x438:0x43A] == b"\x53\xef":   # ext2/3/4 superblock magic 0xEF53
        return "ext"
    if len(data) >= 0x10040 and data[0x10038:0x10040] == b"\x53\xef":  # ext with a boot area ahead
        return "ext"
    return None


# ---------------------------------------------------------------------------- one report per file

def classify(data: bytes) -> dict:
    """{kind, facts} for a file forensics can validate, else None. kind in capture/memory/disk."""
    if not isinstance(data, (bytes, bytearray)) or not data or len(data) > MAX_FILE:
        return None
    data = bytes(data[:HEADER_SCAN]) if len(data) > HEADER_SCAN else bytes(data)
    cap = read_capture(data)
    if cap:
        return {"kind": "capture", "facts": cap}
    mem = read_memory(data)
    if mem:
        return {"kind": "memory", "facts": mem}
    disk = read_disk(data)
    if disk:
        return {"kind": "disk", "facts": disk}
    return None


def reports(files) -> list:
    out = []
    try:
        for name, data in triage.unique_files(files or {}):
            try:
                rep = classify(data)
            except Exception:  # noqa: BLE001 - one unreadable file does not cost the others
                rep = None
            if rep is not None:
                out.append((name, rep))
    except Exception:  # noqa: BLE001
        return []
    return out


# ---------------------------------------------------------------------------- signals

_WORDS = re.compile(
    r"pcap|pcapng|capture|datalink|link[ _-]?type|packet capture|memory (?:image|dump|capture)|"
    r"volatility|crash ?dump|minidump|\blime\b|profile|kdbg|disk image|boot sector|\bmbr\b|\bgpt\b|"
    r"partition|file ?system|\bntfs\b|\bfat(?:12|16|32)?\b|\bext[234]?\b|superblock|sector|forensic", re.I)


def signals(questions, files) -> float:
    """0..1: a validatable capture/memory/disk container in the bytes plus forensic vocabulary.
    0.0 when nothing validates (so it never competes on a 64-byte blob or an e-mail). It answers
    only container/structure facts, so on a real pcap the `network` toolkit out-answers it."""
    try:
        kinds = {r["kind"] for _n, r in reports(files or {})}
    except Exception:  # noqa: BLE001
        kinds = set()
    if not kinds:
        return 0.0
    score = 0.45
    hits = set()
    for q in questions or []:
        f = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
        text = " ".join(str(x or "") for x in (q.get("question"), q.get("answer_id") or q.get("id"),
                                               f.get("syntax")))
        hits |= {m.group().lower() for m in _WORDS.finditer(text)}
    score += min(0.4, 0.1 * len(hits))
    return round(min(1.0, score), 2)


# ---------------------------------------------------------------------------- answers (never-guess)

def _pick(field, shape, value, extra=()):
    if value is None:
        return None
    opts, seen = [], set()
    for v in (value, *extra):
        v = str(v)
        if v and v not in seen:
            seen.add(v)
            opts.append((v, v))
    try:
        return labels.pick(f"{KEY}.{field}/{shape}", opts)
    except ValueError:
        return None


def _file_for(q, reps):
    member = q.get("member") or (str(q.get("artifact") or "").split(ARROW)[-1] if q.get("artifact") else "")
    base = Path(str(member)).name if member else ""
    if base:
        hit = [r for r in reps if Path(r[0]).name == base or r[0].split(ARROW)[-1] == member or r[0] == member]
        if len(hit) == 1:
            return hit[0][1]
        if hit:
            return None
    return reps[0][1] if len(reps) == 1 else None


def _answer_one(q, rep):
    text = str(q.get("question") or "")
    aid = str(q.get("answer_id") or q.get("id") or q.get("qid") or "")
    t = (text + " " + aid).lower()
    kind, facts = rep["kind"], rep["facts"]

    def has(*words):
        return any(re.search(r"(?<![a-z])" + w + r"(?![a-z])", t) for w in words)

    if has("flag"):
        return None
    # H5 fix (docs/retro/new-code-audit-v2.md): these facts VARY across variants/Mastery-sets
    # (ethernet vs linux_sll, windows vs linux, fat32 vs ntfs vs ext, pcap vs pcapng, mbr vs gpt),
    # yet the labels are name==value. Keying them under the KIND shape (`/pcap`, `/memory`, `/disk`)
    # let an accepted name answer a DIFFERENT fact's variant plain. So the key carries the fact
    # itself (as `binary.machine/aarch64` does): an accepted name then only ever answers the variant
    # that shares that fact, and a differing variant stays unsure. `boot_signature` is constant
    # (present/absent) per challenge, so it keeps the `disk` shape (and its yes/no spellings).
    if kind == "capture":
        if has("link[ _-]?type", "datalink", "data link", "layer 2", "l2"):
            name = facts.get("linktype_name")
            return _pick("linktype", name, name) if name else None
        if has("format", "file ?type", "capture format"):
            return _pick("capture_format", facts["format"], facts["format"])
        if has("endian", "endianness", "byte.?order"):
            return _pick("endianness", facts["endian"], facts["endian"])
        return None                               # packet count / payloads belong to `network`
    if kind == "memory":
        if has("os", "operating system", "platform"):
            return _pick("os", facts["os"], facts["os"])
        if has("format", "dump ?type", "image ?type", "file ?type"):
            return _pick("dump_format", facts["format"], facts["format"])
        return None                               # profiles, processes, strings belong to `memory`
    if kind == "disk":
        if has("partition", "scheme", "table") and facts.get("scheme"):
            return _pick("partition_scheme", facts["scheme"], facts["scheme"])
        if has("file ?system", "filesystem", "fs") and facts.get("filesystem"):
            return _pick("filesystem", facts["filesystem"], facts["filesystem"])
        if has("boot signature", "boot sector", "55aa", "0x55aa", "magic"):
            return _pick("boot_signature", "disk", "present" if facts["boot_signature"] else "absent",
                         ["yes" if facts["boot_signature"] else "no"])
        return None
    return None


def solve_set(questions, files, ctx) -> dict:
    reps = reports(files)
    out = {}
    for q in questions or []:
        qid = q.get("qid") or q.get("id") or q.get("answer_id")
        if qid is None:
            continue
        rep = _file_for(q, reps)
        out[qid] = None if rep is None else _answer_one(q, rep)
    return out


# ---------------------------------------------------------------------------- CLI (offline triage)

def main(argv) -> int:
    as_json = "--json" in argv
    want_strings = "--strings" in argv
    paths = [a for a in argv if not a.startswith("--")]
    if not paths:
        print("usage: forensics.py <file>... [--json] [--strings]   (RECON ONLY; container facts, flag None)",
              file=sys.stderr)
        return 2
    out = []
    for p in paths:
        try:
            data = Path(p).read_bytes()
        except OSError as e:
            print(f"forensics.py: {p}: {e}", file=sys.stderr)
            continue
        rep = classify(data)
        row = {"file": p, "kind": rep["kind"] if rep else None, "facts": rep["facts"] if rep else None,
               "bytes": len(data)}
        if want_strings and rep is not None:
            row["strings_sample"] = triage.strings(data[:STRINGS_SCAN])[:40]
        out.append(row)
    if as_json:
        print(json.dumps(out, indent=1))
        return 0
    for row in out:
        if not row["kind"]:
            print(f"- {row['file']}: no capture/memory/disk container recognised ({row['bytes']} bytes)")
            continue
        print(f"# {row['file']}  [{row['kind']}]  " + ", ".join(f"{k}={v}" for k, v in row["facts"].items()))
        for s in row.get("strings_sample", []):
            print(f"    str: {s}")
        print("  container facts only; payloads/processes/strings are `network`/`memory`/`carve_stego`; "
              "the flag is answered None.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
