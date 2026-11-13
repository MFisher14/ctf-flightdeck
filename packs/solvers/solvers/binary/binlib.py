"""Helpers shared by the per-day binary analyzers (d01.py, d02.py, ...)."""
import hashlib
import json
import os
import re


def day_files(files: dict, day: int) -> list:
    """(name, bytes) of one day's samples in archive order: members named dNN-* or dayNN-*."""
    pat = re.compile(rf"^(?:d|day)0*{day}(?!\d)", re.I)
    out, seen = [], set()
    for name, data in files.items():
        if " -> " in name:
            continue
        base = name.rsplit("/", 1)[-1]
        if pat.match(base) and base not in seen:
            seen.add(base)
            out.append((base, data))
    return out


def loose_files(files: dict) -> list:
    """Every archive member once, for analyzers that have to recognise their sample by content."""
    out, seen = [], set()
    for name, data in files.items():
        if " -> " in name or data[:4] == b"PK\x03\x04":
            continue
        if name not in seen:
            seen.add(name)
            out.append((name.rsplit("/", 1)[-1], data))
    return out


def named_day(name):
    """The day a file's basename or a folder of its path is named for (d03 -> 3, day02-x -> 2),
    or None when it is named for no day. Same rule as d03_members.day_of, the lane's convention:
    `d` must be followed by the number and a separator (d03--x, d3.elf; d3d9.dll is nobody's),
    while `day` only needs the number to end (day03-x, day3x)."""
    for part in reversed([p for p in str(name).replace("\\", "/").split("/") if p]):
        m = re.match(r"d0*(\d+)(?![0-9A-Za-z])", part, re.I) or re.match(r"day[-_ ]?0*(\d+)(?!\d)", part, re.I)
        if m:
            return int(m.group(1))
    return None


def prefix_scoped(files: dict, day: int) -> list:
    """loose_files() restricted to members a day MAY own: named for THIS day, or for no day at all.

    A file named for another day's prefix is never returned, so a day module's content-recognition
    fallback can never read another prefix's sample. It is a strict subset of loose_files(), so it
    can only RESTRICT what a fallback answers, never introduce a new answer (the envelope-reprobe
    never-wrong fix: when a day's own member is wrapped so its magic is not at offset 0, the fallback
    finds nothing here and the module returns None/unsure rather than another prefix's config)."""
    out, seen = [], set()
    for name, data in files.items():
        if " -> " in name or data[:4] == b"PK\x03\x04":
            continue
        if named_day(name) not in (day, None):
            continue
        base = name.rsplit("/", 1)[-1]
        if base not in seen:
            seen.add(base)
            out.append((base, data))
    return out


def compact(value) -> str:
    """JSON the way the answer format asks for it: no spaces, original order."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def sha256_field(field: str, samples: list):
    """Answer `artifact_sha256_N`: the SHA-256 of the day's Nth file (1-based, archive order)."""
    m = re.fullmatch(r"artifact_sha256_(\d+)", field)
    if not m:
        return None
    i = int(m.group(1)) - 1
    return hashlib.sha256(samples[i][1]).hexdigest() if 0 <= i < len(samples) else "none"


def pick(env: str, field: str, candidates: list):
    """Choose a naming convention for one field.

    The first candidate is the convention the Game Master accepted. The others
    exist only so a new field's convention can be probed on an untimed Single
    Solve without editing code: e.g. D01_PICK="machine=2,elf_type=1".
    """
    idx = 0
    for part in os.environ.get(env, "").split(","):
        k, _, v = part.partition("=")
        if k.strip() == field and v.strip().isdigit():
            idx = int(v)
    return candidates[idx] if idx < len(candidates) else None
