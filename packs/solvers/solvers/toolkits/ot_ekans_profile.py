#!/usr/bin/env python3
"""Bounded, offline EKANS ransomware evidence matcher; never executes input.

Indicators: Dragos, "EKANS Ransomware and ICS Operations" (2020), Appendix A;
VMware/Carbon Black, "SNAKE Ransomware" (2020-01-27); Trend Micro,
"Ransom.Win32.EKANS.A" (2020-01-10). See SOURCES for primary URLs.

This is a corroborated *profile*, not an infection or actor attribution verdict.
Process-name strings do not prove process termination, and a matching five-letter
rename does not prove randomness or encryption. Decoded strings and separately
observed mutex/process names may be supplied; no malware unpacking is attempted.

Contract: public byte/profile functions return their documented value or raise
EkansError for invalid arguments/resource limits; malformed PE data returns None.
Only regular files are read by the CLI; there is no recursion or network use.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


MAX_ARTIFACT = 8 << 20
MAX_TOTAL = 32 << 20
MAX_ARTIFACTS = 64
MAX_CONTEXT = 1024
MAX_NAME = 4096
MAX_SECTIONS = 96
THRESHOLD = 8

SOURCES = {
    "dragos": "https://www.dragos.com/blog/responding-to-solarwinds-compromise-in-industrial-environments/",
    "dragos_caveats": "https://www.dragos.com/blog/ekans-ransomware-misconceptions-and-misunderstandings",
    "vmware": "https://blogs.vmware.com/security/2020/01/threat-analysis-unit-tau-threat-intelligence-notification-snake-ransomware.html",
    "trendmicro": "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/ransom.win32.ekans.a",
    "pe": "https://learn.microsoft.com/en-us/windows/win32/debug/pe-format",
    "go": "https://go.dev/src/runtime/asm_amd64.s",
}

# Selected ICS/licensing names explicitly listed in Dragos Appendix A. This is
# not the full, later expanded kill-list and does not claim family exclusivity.
ICS_PROCESSES = {
    "ccflic0.exe": "Proficy licensing",
    "ccflic4.exe": "Proficy licensing",
    "hdb.exe": "Honeywell HMIWeb",
    "fnplicensingservice.exe": "FLEXNet licensing",
    "hasplmv.exe": "Sentinel HASP licensing",
    "pralarmmgr.exe": "Proficy",
    "prcalculationmgr.exe": "Proficy historian calculation service",
    "prconfigmgr.exe": "Proficy",
    "prdatabasemgr.exe": "Proficy",
    "premailengine.exe": "Proficy",
    "preventmgr.exe": "Proficy",
    "prftpengine.exe": "Proficy",
    "prgateway.exe": "Proficy gateway",
    "proficyclient.exe": "Proficy client",
    "proficypublisherservice.exe": "Proficy publisher",
    "proficyserver.exe": "Proficy server",
    "proficysts.exe": "Proficy",
    "prprintserver.exe": "Proficy",
    "prproficymgr.exe": "Proficy Plant Applications",
}
_GO_NAMES = (b"runtime.main", b"runtime.morestack", b"runtime.goexit")
_NAME_CHARS = rb"[A-Za-z0-9_.-]"


class EkansError(ValueError):
    """Malformed input or a declared resource bound was exceeded."""


def _bytes(value: object) -> bytes:
    if type(value) not in (bytes, bytearray):
        raise EkansError("artifact must be bytes or bytearray")
    if len(value) > MAX_ARTIFACT:
        raise EkansError("artifact exceeds 8 MiB limit")
    return bytes(value)


def _name(value: object) -> str:
    if type(value) is not str or not 0 < len(value) <= MAX_NAME:
        raise EkansError("names must be nonempty strings of at most 4096 characters")
    if any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise EkansError("control characters or surrogate in name")
    return value


def _names(values: object) -> tuple[str, ...]:
    if type(values) not in (list, tuple) or len(values) > MAX_CONTEXT:
        raise EkansError("context must be a list/tuple of at most 1024 names")
    return tuple(_name(value) for value in values)


def _basename(name: str) -> str:
    return name.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _hit(data: bytes, token: str, *, case_sensitive: bool = False):
    """First bounded token occurrence, preserving byte offset and encoding."""
    flags = 0 if case_sensitive else re.I
    hits = []
    for encoding, stride in (("ascii", 1), ("utf-16-le", 2)):
        encoded = token.encode(encoding)
        boundary = _NAME_CHARS if stride == 1 else _NAME_CHARS + b"\x00"
        pattern = b"(?<!" + boundary + b")" + re.escape(encoded) + b"(?!" + boundary + b")"
        match = re.search(pattern, data, flags)
        if match:
            hits.append((match.start(), encoding))
    return min(hits) if hits else None


def pe_go_evidence(data: object) -> dict | None:
    """PE framing plus >=2 Go runtime symbol strings in declared sections.

    This is weak compiler evidence, not full Go/PE validation or symbol recovery;
    use the existing RE engines for those. Overlay strings never count here.
    """
    raw = _bytes(data)
    if len(raw) < 64 or raw[:2] != b"MZ":
        return None
    pe = int.from_bytes(raw[60:64], "little")
    if pe < 64 or pe + 24 > len(raw) or raw[pe:pe + 4] != b"PE\0\0":
        return None
    machine = int.from_bytes(raw[pe + 4:pe + 6], "little")
    count = int.from_bytes(raw[pe + 6:pe + 8], "little")
    size = int.from_bytes(raw[pe + 20:pe + 22], "little")
    characteristics = int.from_bytes(raw[pe + 22:pe + 24], "little")
    optional = pe + 24
    if not 1 <= count <= MAX_SECTIONS or optional + size > len(raw) or size < 96:
        return None
    magic = int.from_bytes(raw[optional:optional + 2], "little")
    if (machine, magic) not in ((0x14C, 0x10B), (0x8664, 0x20B), (0xAA64, 0x20B)):
        return None
    minimum = 96 if magic == 0x10B else 112
    if size < minimum or not characteristics & 2:
        return None
    directories = int.from_bytes(raw[optional + minimum - 4:optional + minimum], "little")
    if directories > 16 or minimum + directories * 8 > size:
        return None
    table = optional + size
    headers = int.from_bytes(raw[optional + 60:optional + 64], "little")
    if not table + 40 * count <= headers <= len(raw):
        return None
    ranges = []
    symbols = {}
    for index in range(count):
        entry = table + index * 40
        length = int.from_bytes(raw[entry + 16:entry + 20], "little")
        start = int.from_bytes(raw[entry + 20:entry + 24], "little")
        if not length:
            continue
        if start < headers or start + length > len(raw):
            return None
        if any(start < end and begin < start + length for begin, end in ranges):
            return None
        ranges.append((start, start + length))
        section = raw[start:start + length]
        for token in _GO_NAMES:
            hit = _hit(section, token.decode(), case_sensitive=True)
            if hit and hit[1] == "ascii":
                symbols.setdefault(token.decode(), start + hit[0])
    if len(symbols) < 2:
        return None
    return {"machine": machine, "pe_offset": pe, "symbols": symbols}


def analyze(artifacts: object, *, mutexes=(), processes=(), renames=()) -> dict:
    """Correlate {artifact_name: bytes} with explicitly supplied observations.

    Scoring policy (not a statistical probability): identity <=4, ransom note
    <=3, ICS-name set <=3, Go PE <=2, five-letter rename <=1. Match needs score
    >=8, >=3 groups, and identity or note evidence. Repeated names never inflate
    a group. The EKANS footer and mutex share one group to avoid double counting.
    """
    if type(artifacts) is not dict or len(artifacts) > MAX_ARTIFACTS:
        raise EkansError("artifacts must be a dict of at most 64 named byte strings")
    mutexes, processes = _names(mutexes), _names(processes)
    if type(renames) not in (list, tuple) or len(renames) > MAX_CONTEXT:
        raise EkansError("renames must be a list/tuple of at most 1024 pairs")
    checked_renames = []
    for pair in renames:
        if type(pair) not in (list, tuple) or len(pair) != 2:
            raise EkansError("each rename must contain the exact original and new name")
        checked_renames.append((_name(pair[0]), _name(pair[1])))
    checked = []
    total = 0
    for name, data in artifacts.items():
        name, raw = _name(name), _bytes(data)
        total += len(raw)
        if total > MAX_TOTAL:
            raise EkansError("combined artifacts exceed 32 MiB limit")
        checked.append((name, raw))

    evidence = []
    scores = {"identity": 0, "ransom_note": 0, "ics_processes": 0, "go_pe": 0, "renaming": 0}
    found_processes = set()

    def add(group, weight, kind, indicator, artifact, source, offset=None, encoding=None):
        scores[group] = max(scores[group], weight)
        evidence.append({"group": group, "kind": kind, "indicator": indicator,
                         "artifact": artifact, "offset": offset, "encoding": encoding,
                         "source": SOURCES[source]})

    for name, raw in checked:
        if _basename(name) == "fix-your-files.txt":
            add("ransom_note", 3, "supplied_filename", "Fix-Your-Files.txt", name, "vmware")
        for token, group, weight, source, sensitive in (
            ("Global\\EKANS", "identity", 4, "trendmicro", True),
            ("already encrypted!", "identity", 1, "dragos", True),
            ("Fix-Your-Files.txt", "ransom_note", 3, "vmware", False),
            ("bapcocryp@ctemplar.com", "ransom_note", 2, "dragos", False),
        ):
            hit = _hit(raw, token, case_sensitive=sensitive)
            if hit:
                add(group, weight, "artifact_string", token, name, source, *hit)
        if len(raw) >= 5 and raw.endswith(b"EKANS"):
            add("identity", 3, "terminal_bytes", "EKANS", name, "vmware", len(raw) - 5, "ascii")
        for process in ICS_PROCESSES:
            hit = _hit(raw, process)
            if hit:
                found_processes.add(process)
                add("ics_processes", 0, "artifact_string", process, name, "dragos", *hit)
        compiler = pe_go_evidence(raw)
        if compiler:
            add("go_pe", 2, "pe_section_runtime_strings", compiler["symbols"], name,
                "go", compiler["pe_offset"])
    for index, mutex in enumerate(mutexes):
        if mutex in ("EKANS", "Global\\EKANS"):
            add("identity", 4, "supplied_mutex_observation", mutex, f"mutexes[{index}]", "trendmicro")
    for index, process in enumerate(processes):
        base = _basename(process)
        if base in ICS_PROCESSES:
            found_processes.add(base)
            add("ics_processes", 0, "supplied_process_observation", base, f"processes[{index}]", "dragos")
    compatible_renames = []
    for index, (before, after) in enumerate(checked_renames):
        suffix = after[len(before):] if after.startswith(before) else ""
        if re.fullmatch("[A-Za-z]{5}", suffix) and "." in _basename(before):
            compatible_renames.append({"before": before, "after": after, "suffix": suffix})
            add("renaming", 1, "supplied_rename_observation", suffix, f"renames[{index}]", "vmware")
    scores["ics_processes"] = 3 if len(found_processes) >= 2 else int(bool(found_processes))
    score = sum(scores.values())
    matched = score >= THRESHOLD and sum(bool(value) for value in scores.values()) >= 3 \
        and bool(scores["identity"] or scores["ransom_note"])
    return {
        "profile": "EKANS/SNAKE ransomware", "matched": matched, "score": score,
        "threshold": THRESHOLD, "maximum_score": 13, "category_scores": scores,
        "assessment": "corroborated_profile" if matched else "insufficient_corroboration" if evidence else "no_indicators",
        "artifacts": [{"name": name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                      for name, raw in checked],
        "evidence": evidence, "ics_processes": sorted(found_processes), "compatible_renames": compatible_renames,
        "limitations": ["Profile similarity does not prove infection or actor attribution.",
                        "Artifact strings and supplied observations are distinct; neither proves a process was killed.",
                        "The published kill-list overlaps MegaCortex; only a documented ICS subset is matched.",
                        "Five appended letters are compatible with the published rename shape, not proof of randomness.",
                        "Encoded/packed strings are not automatically recovered; absence of evidence is not a clean verdict."],
    }


def analyze_bytes(data: object, *, name="artifact", mutexes=(), processes=(), renames=()) -> dict:
    """Single-artifact convenience API with the same EkansError contract."""
    return analyze({_name(name): _bytes(data)}, mutexes=mutexes, processes=processes, renames=renames)


def _read_file(name):
    try:
        if not stat.S_ISREG(Path(name).stat().st_mode):
            raise EkansError("input must be a regular file")
        with Path(name).open("rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ARTIFACT:
                raise EkansError("input must be a regular file of at most 8 MiB")
            return _bytes(stream.read(MAX_ARTIFACT + 1))
    except (OSError, ValueError) as exc:
        raise EkansError(f"cannot read artifact: {exc}") from None


def main(argv=None) -> int:
    if argv is not None and (type(argv) not in (list, tuple) or any(type(x) is not str for x in argv)):
        print("ot_ekans_profile: argv must be a list/tuple of strings", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", help="local artifact files; no directories or recursion")
    parser.add_argument("--mutex", action="append", default=[], help="explicitly observed mutex name")
    parser.add_argument("--process", action="append", default=[], help="explicitly observed process path/name")
    parser.add_argument("--rename", nargs=2, action="append", default=[], metavar=("BEFORE", "AFTER"))
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if len(args.files) > MAX_ARTIFACTS:
            raise EkansError("at most 64 files are accepted")
        artifacts, total = {}, 0
        for name in args.files:
            raw = _read_file(name)
            total += len(raw) - len(artifacts.get(name, b""))
            if total > MAX_TOTAL:
                raise EkansError("combined artifacts exceed 32 MiB limit")
            artifacts[name] = raw
        result = analyze(artifacts, mutexes=args.mutex,
                         processes=args.process, renames=args.rename)
        print(json.dumps(result, indent=2, ensure_ascii=True))
    except EkansError as exc:
        print(f"ot_ekans_profile: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
