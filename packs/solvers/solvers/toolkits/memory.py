#!/usr/bin/env python3
"""Memory forensics toolkit (`memory`, backlog row 82): dump triage; ELF-core registers and heap record chains.

  .venv/bin/python solvers/toolkits/memory.py <file>...                 triage of the file(s); no request
  .venv/bin/python solvers/toolkits/memory.py <image> --vol windows     run the Volatility 3 plugin set and save
                                  [--where sandbox|venv] [--online]     its tables where solve_set finds them
  .venv/bin/python solvers/toolkits/memory.py --heap-chains <core>...   an ELF core's saved registers and its
                                                                        ranked heap record chains, nothing else
                                                                        (what intake runs on every ELF core)

Offline: no Game Master request, no token. Nothing here runs a heavy tool unless `--vol` (or vol())
is asked for by hand; solve_set never does.

What a memory lane can deliver, and what reads it:
  - tables somebody else's Volatility already printed (pslist, pstree, psscan, cmdline, netscan,
    netstat, malfind, envars, getsids, info, linux.pslist/psaux/bash; text, CSV, JSON, JSONL, the
    Volatility 2 fixed-width form) or a JSON "snapshot" in the event's small-fixture style:
    tables_from_text, tables_from_json, Model.absorb. Columns are recognised by their names.
  - a process image: a Windows minidump (minidump: system info, modules, memory regions and their
    protection, the command line through TEB -> PEB when the memory is in the dump) or an ELF core
    (elf_core: NT_PRPSINFO pid, ppid, name and arguments, NT_FILE mappings, segments with their file
    offsets, and the saved registers of every thread from NT_PRSTATUS).
  - an ELF core's heap (B-067): heap_chains finds the heap segments, scans them for glibc chunks,
    searches a few {next, len, text} record layouts, rebuilds every linked chain and ranks them by
    the saved registers (a chain that starts at the address in the arg0 / return register first) and
    by the event's flag format. It is for the "the flag is a linked list in the core, strings shows
    the pieces out of order, decoys share its tail" handout. build_model keeps the result
    (Model.heap, Model.recovered); the command prints every chain and a RECOVERED line. A carve cut
    by a cap or the deadline says PARTIAL. solve_set does not run it: a flag is not one of its
    answers.
  - a whole-machine image: LiME/AVML (lime_segments), a Windows crash dump (crashdump_header), or
    raw. With no symbols, carve_windows_processes and carve_linux_tasks find process records by
    calibrating the field offsets on the processes every machine has (System is PID 4 and the
    parent of smss.exe; systemd is PID 1, kthreadd PID 2), carve_env reads environment strings
    (COMPUTERNAME, USERNAME, HOSTNAME), carve_banners the Linux banner. Everything carved is
    answered unsure, never plain.
  - Volatility 3 itself, off the clock: vol(image, plugin, where="sandbox"|"venv"), and
    vol_save(image, "windows"|"linux"|"mac") which saves each plugin's JSON under
    <challenges>/_memory/<fingerprint of the image>/ ; build_model reads that folder whenever the
    same image is in the delivery, so a base solved with Volatility replays offline.
  - the Linux symbol table (B-136), with no download: carve_linux_banners reads the kernel's whole
    banner from the image, linux_isfs / match_linux_isf find the ISF whose own banner is that text
    among the ISF files of the delivery and of symbols_folder(), linux_symbol_pack wraps it as the
    `linux.zip` vol(symbols=...) hands the sandbox, and vol_save(image, "linux", symbols="auto") does
    all three before it runs a plugin. A kernel with no local ISF is said so by name; nothing is
    fetched. A candidate table is untrusted data (a handout's own file): the search has a clock
    budget and says where it was cut, a candidate's keys are parsed up to a bound, and one that
    cannot be parsed is no table. A pack is kept per (banner, table file) and found again by its
    banner when the table is gone (saved_linux_pack). solvers/toolkits/vol_triage.py is the opener
    built on these.

The runner contract. solve_set(questions, files, ctx) reads what each question asks from its text
(the process of a PID, a PID, the parent, the command line, a network peer or port, an injected
region, its protection, the user, the host name, the build or kernel version, a time, a count, the
image format) and answers under the never-guess rule (AGENTS.md, "Uncertain answers"):
  - plain only for a fact read from a structured source (a table, a minidump, an ELF core) by a
    selector that matches exactly one consistent value, AND written in a form the question's own
    format leaves no choice about: an integer answer, or a value that is the only rendering the
    answer_format's pattern or option list lets through;
  - labels.pick('memory.<field>/<source>', [(method, value), ...]) for an established fact whose
    spelling or format is not judged (a process name with or without .exe, a time, a hex address),
    and for every carved fact;
  - None for everything else: an ambiguous selector, two values, a question of two families, a
    question this file does not read. Hashes, sizes and counts of named files go to
    solvers/common/triage.py's own rules.
It answers nothing at all (every id None) unless signals(questions, files) says the delivery or its
questions look like memory forensics, so it cannot win tools/lane_match.py on another lane.

signals(questions, files) -> 0..1: how strongly this looks like a memory lane (image magics, image
file names, Volatility tables, question words). Cheap: heads of files only.
"""
import base64
import csv
import datetime as _dt
import hashlib
import io
import json
import os
import re
import struct
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt, scope
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt, scope

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
COMMON = HERE.parent / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(1, str(COMMON))

# the glibc chunk flag bit, from the heap toolkits (one definition; the heap-chain carver reads it)
try:
    from .heap_families import PREV_INUSE as HEAP_PREV_INUSE
except ImportError:     # run as a script or imported as plain `memory`: the repository's direct-import convention
    if str(HERE) not in sys.path:
        sys.path.append(str(HERE))
    from heap_families import PREV_INUSE as HEAP_PREV_INUSE

KEY = "memory"
GATE = 0.25                     # solve_set answers only when signals() reaches this
CARVE_MAX = 16 << 20            # bytes of an image carved inside solve_set (the timed path)
CARVE_MAX_CLI = 512 << 20       # ... and by the command
TEXT_MAX = 4 << 20              # a text or JSON table larger than this is not parsed in solve_set
SENTINEL = "??"
ARROW = " -> "
UTC = _dt.timezone.utc


# ---- unsure answers ---------------------------------------------------------------------------------

def pick(key, options):
    """labels.pick, for a `memory.` key. solvers/common/labels.py knows five lane prefixes; until
    `memory` is one of them (LANE_DIRS), the unsure string is built here in the same wire form, with
    no ledger behind it: nothing is remembered, and tools/verify.py cannot probe the key yet."""
    opts, seen = [], set()
    for item in options or []:
        name, value = item if isinstance(item, (tuple, list)) and len(item) == 2 else (str(item), item)
        if name and value is not None and name not in seen:
            seen.add(name)
            opts.append((str(name), value))
    if not opts:
        return None
    try:
        import labels
        return labels.pick(key, opts)
    except ValueError:              # the lane prefix is not registered
        pass
    except ImportError:
        pass
    return SENTINEL + json.dumps({"k": str(key).lower(), "o": [[n, v] for n, v in opts[:12]]}, separators=(",", ":"))


def _tri():
    import triage
    return triage


# ---- image formats ------------------------------------------------------------------------------------

IMAGE_EXT = (".mem", ".vmem", ".lime", ".dmp", ".mdmp", ".core", ".raw", ".dump", ".avml", ".vmss", ".vmsn", ".hpak", ".crash")
FORMAT_NAMES = {            # the fact -> spellings offered for it (labels: lowercase snake_case, descriptive)
    "lime": ["lime", "lime_dump", "linux_lime"],
    "avml": ["avml", "avml_dump", "lime"],
    "minidump": ["minidump", "windows_minidump", "mdmp"],
    "crashdump64": ["crash_dump", "windows_crash_dump", "crashdump", "pagedu64", "dmp"],
    "crashdump32": ["crash_dump", "windows_crash_dump", "crashdump", "pagedump", "dmp"],
    "elf_core": ["elf_core", "core_dump", "elf", "core"],
    "hibernation": ["hibernation_file", "hiberfil", "hibernation"],
    "vmware_snapshot": ["vmware_snapshot", "vmss", "vmsn"],
}


def image_format(data: bytes) -> str:
    """lime, avml, minidump, crashdump64, crashdump32, elf_core, hibernation, vmware_snapshot, or ''
    (raw or not an image: the bytes do not say)."""
    h = bytes(data[:16])
    if h[:4] == b"EMiL":
        return "lime"
    if h[:4] == b"AVML":
        return "avml"
    if h[:4] == b"MDMP":
        return "minidump"
    if h[:8] == b"PAGEDU64":
        return "crashdump64"
    if h[:8] == b"PAGEDUMP":
        return "crashdump32"
    if h[:4] == b"\x7fELF" and len(data) >= 18:
        end = "<" if data[5] == 1 else ">"
        if struct.unpack_from(end + "H", data, 16)[0] == 4:
            return "elf_core"
    if h[:4].lower() in (b"hibr", b"wake", b"rstr"):
        return "hibernation"
    if h[:4] in (b"\xd2\xbe\xd2\xbe", b"\xd0\xbe\xd2\xbe", b"\xd1\xba\xd1\xba", b"\xd3\xbe\xd2\xbe"):
        return "vmware_snapshot"
    return ""


def lime_segments(data: bytes) -> list:
    """[{start, end, offset, size, version}] of a LiME or AVML image: the physical ranges and where
    each one's bytes begin in the file. An AVML version 2 range is snappy-compressed (size None)."""
    out, pos = [], 0
    while pos + 32 <= len(data) and data[pos:pos + 4] in (b"EMiL", b"AVML"):
        version, start, end = struct.unpack_from("<IQQ", data, pos + 4)
        size = end - start + 1
        if end < start:
            break
        if data[pos:pos + 4] == b"AVML" and version == 2:
            out.append({"start": start, "end": end, "offset": pos + 32, "size": None, "version": version})
            break               # the compressed length is not in the header
        out.append({"start": start, "end": end, "offset": pos + 32, "size": size, "version": version})
        pos += 32 + size
    return out


AVML_CHUNK_MAX = 65536          # decompressed bytes one chunk of the snappy framing holds at most (the format's limit)
AVML_STEP = 16 << 20            # decompressed bytes between two looks at the clock and at the free space
AVML_RESERVE = 1 << 30          # bytes that must stay free on the volume the decompressed copy is written to


def avml_to_lime(data, out, *, deadline=None, clock=time.monotonic, step: int = AVML_STEP, free=None,
                 reserve: int = AVML_RESERVE) -> dict:
    """Write an AVML version 2 image (each range a snappy framed stream) to the seekable file `out`
    as the LiME file `avml-convert` makes of it: per range the 32-byte header with the LiME magic
    and version 1, then the range's bytes. {"status": ran | cut | not run, "reason", "ranges",
    "bytes"}: ranges and bytes are what was written.

    The image is untrusted, so every step is bounded and every stop is named in `reason`:
    - a chunk is decompressed alone (cramjam, pinned in requirements.in), and one that declares more
      than the format's 64 KiB is refused before it is decompressed; checksums are not verified;
    - a range gives at most the bytes its header states; a range that ends early (the file is cut, a
      chunk is damaged, the budget or the disk ran out) is written with a header that states what
      it holds, so the copy is a well-formed LiME file as far as it goes;
    - every `step` bytes the clock is looked at (`deadline`, a `clock()` value) and so is `free()`
      (the bytes free where `out` lives): below `reserve` the copy stops.
    not run: cramjam is not installed (named), or the bytes do not begin with a version 2 header."""
    def answer(status: str, reason: str = "") -> dict:
        return {"status": status, "reason": reason, "ranges": ranges, "bytes": written}
    pos, n, ranges, written, since = 0, len(data), 0, 0, 0
    try:
        import cramjam
    except ImportError:
        return answer("not run", "py:cramjam is not installed (requirements.in pins it): there is no snappy reader")
    while pos < n:
        where = ""
        if n - pos < 32 or bytes(data[pos:pos + 4]) != b"AVML":
            where = f"the bytes at offset 0x{pos:x} are not an AVML range header"
        else:
            version, start, end = struct.unpack_from("<IQQ", data, pos + 4)
            if version != 2 or end < start:
                where = f"the header at offset 0x{pos:x} is not a version 2 range (version {version}, 0x{start:x}..0x{end:x})"
        if where:
            return answer("cut", f"{where}: {n - pos} byte(s) after range {ranges} were not read") if ranges else answer("not run", where)
        size, got, why = end - start + 1, 0, ""
        head_at = out.tell()
        out.write(b"EMiL" + struct.pack("<IQQ", 1, start, end) + bytes(8))
        pos += 32
        while got < size:
            if pos + 4 > n:
                why = "the file ends inside the range"
                break
            word = struct.unpack_from("<I", data, pos)[0]
            kind, body, length = word & 0xff, pos + 4, word >> 8
            if body + length > n:
                why = f"the chunk at offset 0x{pos:x} runs past the end of the file"
                break
            if kind in (0x00, 0x01):                # a compressed or a stored chunk: 4 checksum bytes, then the data
                if length < 4:
                    why = f"the chunk at offset 0x{pos:x} is shorter than its checksum"
                    break
                raw = bytes(data[body + 4:body + length])
                if kind == 0x00:
                    try:
                        if cramjam.snappy.decompress_raw_len(raw) > AVML_CHUNK_MAX:
                            why = f"the chunk at offset 0x{pos:x} declares more than the format's {AVML_CHUNK_MAX} bytes"
                            break
                        raw = bytes(cramjam.snappy.decompress_raw(raw))
                    except (cramjam.DecompressionError, ValueError) as e:
                        why = (f"the chunk at offset 0x{pos:x} is not snappy data "
                               f"({str(e).splitlines()[0][:120] if str(e) else type(e).__name__})")
                        break
                raw = raw[:size - got]
                out.write(raw)
                got, written, since = got + len(raw), written + len(raw), since + len(raw)
            elif kind == 0xff:
                if bytes(data[body:body + length]) != b"sNaPpY":
                    why = f"the stream identifier at offset 0x{pos:x} is not snappy's"
                    break
            elif kind < 0x80:
                why = f"the chunk at offset 0x{pos:x} has the reserved type 0x{kind:02x}"
                break
            pos = body + length                     # 0x80..0xfe: padding and other skippable chunks
            if since >= step:
                since = 0
                if deadline is not None and clock() > deadline:
                    why = "the decompression budget ran out"
                    break
                if free is not None and free() < reserve:
                    why = f"fewer than {reserve} bytes are free where the copy is written"
                    break
        if got < size:
            # the header states what the range holds; a range with nothing in it is not written at all
            out.seek(head_at)
            if got:
                out.write(b"EMiL" + struct.pack("<IQQ", 1, start, start + got - 1) + bytes(8))
                out.seek(0, os.SEEK_END)
                ranges += 1
            else:
                out.truncate()
            return answer("cut", f"range {ranges if got else ranges + 1} (0x{start:x}..0x{end:x}) holds {got} of its {size} bytes: {why}")
        ranges += 1
        pos += 8                                    # the range's trailer: its compressed length, read by nothing here
    return answer("ran")


def _filetime(v):
    """A Windows FILETIME as a UTC datetime, or None when it is not between 1990 and 2100."""
    try:
        if not 0x01B0000000000000 <= v <= 0x0240000000000000:
            return None
        return _dt.datetime(1601, 1, 1) + _dt.timedelta(microseconds=v // 10)
    except (OverflowError, ValueError, TypeError):
        return None


def crashdump_header(data: bytes) -> dict:
    """The DUMP_HEADER fields of a Windows crash dump (PAGEDUMP / PAGEDU64), or {}."""
    fmt = image_format(data)
    try:
        if fmt == "crashdump64":
            major, minor, dtb, pfn, modules, procs, machine, cpus, bugcheck = struct.unpack_from("<IIQQQQIII", data, 8)
            params = struct.unpack_from("<4Q", data, 0x40)
            dump_type = struct.unpack_from("<I", data, 0xF98)[0] if len(data) >= 0xFB0 else None
            when = _filetime(struct.unpack_from("<Q", data, 0xFA8)[0]) if len(data) >= 0xFB0 else None
        elif fmt == "crashdump32":
            major, minor, dtb, pfn, modules, procs, machine, cpus, bugcheck = struct.unpack_from("<IIIIIIIII", data, 8)
            params = struct.unpack_from("<4I", data, 0x2C)
            dump_type = struct.unpack_from("<I", data, 0xF88)[0] if len(data) >= 0xFC8 else None
            when = _filetime(struct.unpack_from("<Q", data, 0xFC0)[0]) if len(data) >= 0xFC8 else None
        else:
            return {}
    except struct.error:
        return {}
    return {"format": fmt, "major_version": major, "build": minor, "directory_table_base": dtb, "pfn_database": pfn,
            "ps_loaded_module_list": modules, "ps_active_process_head": procs, "machine": machine, "processors": cpus,
            "bugcheck_code": bugcheck, "bugcheck_parameters": list(params), "dump_type": dump_type, "system_time": when}


PROTECT = {0x01: "PAGE_NOACCESS", 0x02: "PAGE_READONLY", 0x04: "PAGE_READWRITE", 0x08: "PAGE_WRITECOPY",
           0x10: "PAGE_EXECUTE", 0x20: "PAGE_EXECUTE_READ", 0x40: "PAGE_EXECUTE_READWRITE", 0x80: "PAGE_EXECUTE_WRITECOPY"}
PROT_SHORT = {"PAGE_NOACCESS": "---", "PAGE_READONLY": "r--", "PAGE_READWRITE": "rw-", "PAGE_WRITECOPY": "rw-",
              "PAGE_EXECUTE": "--x", "PAGE_EXECUTE_READ": "r-x", "PAGE_EXECUTE_READWRITE": "rwx", "PAGE_EXECUTE_WRITECOPY": "rwx"}
MD_ARCH = {0: "x86", 5: "arm", 6: "ia64", 9: "amd64", 12: "arm64"}


def _md_string(data, rva):
    try:
        n = struct.unpack_from("<I", data, rva)[0]
        if n > 0x10000 or rva + 4 + n > len(data):
            return None
        return bytes(data[rva + 4:rva + 4 + n]).decode("utf-16-le", "replace")
    except struct.error:
        return None


def minidump(data: bytes) -> dict:
    """A Windows minidump (MDMP), read from its stream directory; {} when it is not one.

    {time, flags, streams: {type: (size, rva)}, system: {arch, processors, major, minor, build,
    csd}, modules: [{base, size, timestamp, path, name}], threads: [{tid, teb}], pid, create_time,
    regions: [{start, size, state, protect, protection, type}] (MemoryInfoList), ranges: [(va, size,
    file offset)] (Memory64List / MemoryList), comment, name, image_path, cmdline}.
    name is the base name of the first module (the process's own image). image_path and cmdline are
    read through TEB -> PEB -> ProcessParameters (x64 only) when the dump holds that memory."""
    if bytes(data[:4]) != b"MDMP" or len(data) < 32:
        return {}
    try:
        _, _, nstreams, dir_rva, _, stamp, flags = struct.unpack_from("<IIIIIIQ", data, 0)
        streams, twice = {}, set()
        for i in range(min(nstreams, 256)):
            typ, size, rva = struct.unpack_from("<III", data, dir_rva + 12 * i)
            if typ and rva + size <= len(data):
                if streams.setdefault(typ, (size, rva)) != (size, rva):
                    twice.add(typ)
        for typ in twice:           # two streams of one type: which one is the process is not known
            del streams[typ]
    except struct.error:
        return {}
    out = {"time": _dt.datetime.fromtimestamp(stamp, UTC).replace(tzinfo=None) if stamp else None, "flags": flags,
           "streams": streams, "system": {}, "modules": [], "threads": [], "pid": None, "create_time": None,
           "regions": [], "ranges": [], "comment": None, "name": None, "image_path": None, "cmdline": None}
    try:
        if 7 in streams:
            rva = streams[7][1]
            arch, _, _, ncpu, _ptype, major, minor, build, _plat, csd = struct.unpack_from("<HHHBBIIIII", data, rva)
            out["system"] = {"arch": MD_ARCH.get(arch, str(arch)), "processors": ncpu, "major": major, "minor": minor,
                             "build": build, "csd": _md_string(data, csd) if csd else None}
        if 4 in streams:
            rva = streams[4][1]
            n = struct.unpack_from("<I", data, rva)[0]
            for i in range(min(n, 4096)):
                base, size, _, ts, name_rva = struct.unpack_from("<QIIII", data, rva + 4 + 108 * i)
                path = _md_string(data, name_rva)
                out["modules"].append({"base": base, "size": size, "timestamp": ts, "path": path,
                                       "name": re.split(r"[\\/]", path)[-1] if path else None})
            if out["modules"] and out["modules"][0]["name"]:
                out["name"] = out["modules"][0]["name"]
        if 3 in streams:
            rva = streams[3][1]
            n = struct.unpack_from("<I", data, rva)[0]
            for i in range(min(n, 4096)):
                tid, _, _, _, teb = struct.unpack_from("<IIIIQ", data, rva + 4 + 48 * i)
                out["threads"].append({"tid": tid, "teb": teb})
        if 15 in streams and streams[15][0] >= 24:
            rva = streams[15][1]
            _, flags1, pid, created = struct.unpack_from("<IIII", data, rva)
            if flags1 & 1:
                out["pid"] = pid
            if flags1 & 2 and created:
                out["create_time"] = _dt.datetime.fromtimestamp(created, UTC).replace(tzinfo=None)
        if 16 in streams:
            rva = streams[16][1]
            hdr, ent, n = struct.unpack_from("<IIQ", data, rva)
            for i in range(min(n, 65536)):
                base, _alloc, _aprot, _, size, state, prot, typ, _ = struct.unpack_from("<QQIIQIIII", data, rva + hdr + ent * i)
                out["regions"].append({"start": base, "size": size, "state": state, "protect": prot,
                                       "protection": PROTECT.get(prot & 0xFF), "type": typ})
        if 9 in streams:
            rva = streams[9][1]
            n, base_rva = struct.unpack_from("<QQ", data, rva)
            pos = base_rva
            for i in range(min(n, 65536)):
                va, size = struct.unpack_from("<QQ", data, rva + 16 + 16 * i)
                out["ranges"].append((va, size, pos))
                pos += size
        elif 5 in streams:
            rva = streams[5][1]
            n = struct.unpack_from("<I", data, rva)[0]
            for i in range(min(n, 65536)):
                va, size, off = struct.unpack_from("<QII", data, rva + 4 + 16 * i)
                out["ranges"].append((va, size, off))
        for typ, wide in ((10, False), (11, True)):
            if typ in streams and out["comment"] is None:
                size, rva = streams[typ]
                raw = bytes(data[rva:rva + min(size, 4096)])
                out["comment"] = (raw.decode("utf-16-le", "replace") if wide else raw.decode("latin-1")).split("\x00")[0]
    except struct.error:
        pass

    def read(va, n):
        for start, size, off in out["ranges"]:
            if start <= va and va + n <= start + size and off + (va - start) + n <= len(data):
                return bytes(data[off + (va - start):off + (va - start) + n])
        return None

    def ustr(va):
        raw = read(va, 16)
        if not raw:
            return None
        length, _, buf = struct.unpack("<HH4xQ", raw)
        body = read(buf, length) if 0 < length <= 0x8000 and length % 2 == 0 else None
        return body.decode("utf-16-le", "replace") if body else None

    if out["system"].get("arch") == "amd64" and out["threads"] and out["ranges"]:
        peb = read(out["threads"][0]["teb"] + 0x60, 8)
        params = read(struct.unpack("<Q", peb)[0] + 0x20, 8) if peb else None
        if params:
            pp = struct.unpack("<Q", params)[0]
            out["image_path"], out["cmdline"] = ustr(pp + 0x60), ustr(pp + 0x70)
    return out


def md_injected(md: dict) -> list:
    """The committed, private, executable-and-writable regions of a minidump: what malfind reports."""
    return [r for r in md.get("regions", []) if r["state"] == 0x1000 and r["type"] == 0x20000 and r["protect"] & 0xC0]


# ELF e_machine -> ordered GPR names of its elf_gregset_t (pr_reg in struct elf_prstatus). These are
# the kernel's core-note register orders, not the DWARF order. An unknown machine is named reg0..regN.
# PRIMARY is the register(s) a reader cross-references first: the SysV arg0 / return register whose
# value is the object the CPU was working on (csctf 9087: the list head sat in rdi and rax).
EM_386, EM_ARM, EM_X86_64, EM_AARCH64 = 3, 40, 62, 183
_GPR_NAMES = {
    EM_X86_64: ("r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx",
                "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base",
                "gs_base", "ds", "es", "fs", "gs"),
    EM_386: ("ebx", "ecx", "edx", "esi", "edi", "ebp", "eax", "ds", "es", "fs", "gs", "orig_eax",
             "eip", "cs", "eflags", "esp", "ss"),
    EM_AARCH64: tuple(f"x{i}" for i in range(31)) + ("sp", "pc", "pstate"),
    EM_ARM: ("r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "fp", "ip", "sp",
             "lr", "pc", "cpsr", "orig_r0"),
}
_GPR_PRIMARY = {EM_X86_64: ("rdi", "rax"), EM_386: ("eax",), EM_AARCH64: ("x0",), EM_ARM: ("r0",)}
# struct elf_prstatus: pr_reg (the elf_gregset_t) begins at this byte offset in the note body. The
# prefix fields (elf_siginfo, pr_cursig, sig masks, pids, four timevals) have the same shapes on every
# architecture of a given word size, so the offset depends only on the ELF class: LP64 112, LP32 72.
_PRSTATUS_PRREG = {True: 112, False: 72}


def _prstatus_regs(body: bytes, machine, e: str, wide: bool) -> dict:
    """pr_reg out of one NT_PRSTATUS note -> {register name: value}. Named per `machine`; an unknown
    machine falls back to reg0..regN. Returns {} when pr_reg does not fit the note body."""
    word = 8 if wide else 4
    base = _PRSTATUS_PRREG[wide]
    avail = (len(body) - base) // word
    if avail <= 0:
        return {}
    names = _GPR_NAMES.get(machine)
    count = len(names) if names else min(avail, 64)     # cap the unnamed fallback to a sane register file
    if names and avail < count:
        return {}                                        # a truncated note of a known machine: trust none of it
    fmt = e + ("Q" if wide else "I")
    out = {}
    for i in range(count):
        name = names[i] if names else f"reg{i}"
        out[name] = struct.unpack_from(fmt, body, base + i * word)[0]
    return out


def elf_core(data: bytes) -> dict:
    """An ELF core file, 64-bit or 32-bit: {pid, ppid, uid, gid, name, args (NT_PRPSINFO), files:
    [{start, end, path}] (NT_FILE), segments: [{vaddr, off, memsz, filesz, flags, perms}] (PT_LOAD),
    registers: [{thread}] (NT_PRSTATUS pr_reg, named per machine), machine, bits}; {} when it is not
    one. `registers` is a list, one dict per thread note, mapping register name -> value; the first is
    the crashing thread. `off` is each loadable segment's file offset, for VA<->file translation."""
    if image_format(data) != "elf_core" or data[4] not in (1, 2):
        return {}
    e = "<" if data[5] == 1 else ">"
    wide = data[4] == 2
    out = {"pid": None, "ppid": None, "uid": None, "gid": None, "name": None, "args": None, "files": [], "segments": [],
           "registers": [], "bits": 64 if wide else 32}
    seen_info = []
    try:
        out["machine"] = struct.unpack_from(e + "H", data, 18)[0]
        if wide:
            phoff = struct.unpack_from(e + "Q", data, 0x20)[0]
            phentsize, phnum = struct.unpack_from(e + "HH", data, 0x36)
        else:
            phoff = struct.unpack_from(e + "I", data, 0x1C)[0]
            phentsize, phnum = struct.unpack_from(e + "HH", data, 0x2A)
        for i in range(min(phnum, 4096)):
            if wide:
                ptype, flags, off, vaddr, _, filesz, memsz, _ = struct.unpack_from(e + "IIQQQQQQ", data, phoff + i * phentsize)
            else:
                ptype, off, vaddr, _, filesz, memsz, flags, _ = struct.unpack_from(e + "IIIIIIII", data, phoff + i * phentsize)
            if ptype == 1:
                out["segments"].append({"vaddr": vaddr, "off": off, "memsz": memsz, "filesz": filesz, "flags": flags,
                                        "perms": ("r" if flags & 4 else "-") + ("w" if flags & 2 else "-") + ("x" if flags & 1 else "-")})
            if ptype != 4:
                continue
            pos, end = off, min(off + filesz, len(data))
            while pos + 12 <= end:
                namesz, descsz, ntype = struct.unpack_from(e + "III", data, pos)
                desc = pos + 12 + ((namesz + 3) & ~3)
                if desc + descsz > end:
                    break
                body = bytes(data[desc:desc + descsz])
                if ntype == 3 and wide and descsz >= 136:   # NT_PRPSINFO, the 64-bit layout
                    seen_info.append(body[:136])
                    out["uid"], out["gid"], out["pid"], out["ppid"] = struct.unpack_from(e + "IIii", body, 16)
                    out["name"] = body[40:56].split(b"\x00")[0].decode("utf-8", "replace")
                    out["args"] = body[56:136].split(b"\x00")[0].decode("utf-8", "replace").rstrip()
                elif ntype == 3 and not wide and descsz in (124, 128):
                    # the 32-bit layout: 16-bit uid and gid in 124 bytes (i386), 32-bit ones in 128 (ARM, MIPS)
                    seen_info.append(body)
                    if descsz == 124:
                        out["uid"], out["gid"], out["pid"], out["ppid"] = struct.unpack_from(e + "HHii", body, 8)
                        at = 28
                    else:
                        out["uid"], out["gid"], out["pid"], out["ppid"] = struct.unpack_from(e + "IIii", body, 8)
                        at = 32
                    out["name"] = body[at:at + 16].split(b"\x00")[0].decode("utf-8", "replace")
                    out["args"] = body[at + 16:at + 96].split(b"\x00")[0].decode("utf-8", "replace").rstrip()
                elif ntype == 0x46494C45 and descsz >= 8 and not wide:      # NT_FILE, 32-bit
                    count, _page = struct.unpack_from(e + "II", body, 0)
                    count = min(count, 65536)
                    names = body[8 + 12 * count:].split(b"\x00")
                    for j in range(count):
                        s, t, _ = struct.unpack_from(e + "III", body, 8 + 12 * j)
                        out["files"].append({"start": s, "end": t, "path": names[j].decode("utf-8", "replace") if j < len(names) else None})
                elif ntype == 0x46494C45 and descsz >= 16:  # NT_FILE
                    count, _page = struct.unpack_from(e + "QQ", body, 0)
                    count = min(count, 65536)
                    names = body[16 + 24 * count:].split(b"\x00")
                    for j in range(count):
                        s, t, _ = struct.unpack_from(e + "QQQ", body, 16 + 24 * j)
                        out["files"].append({"start": s, "end": t, "path": names[j].decode("utf-8", "replace") if j < len(names) else None})
                elif ntype == 1 and bytes(data[pos + 12:pos + 12 + namesz]).rstrip(b"\x00") == b"CORE":
                    # NT_PRSTATUS (type 1 under the name CORE; type 1 under GNU is an ABI tag):
                    # struct elf_prstatus, pr_reg holds the saved GPRs
                    regs = _prstatus_regs(body, out["machine"], e, wide)
                    if regs:
                        out["registers"].append(regs)
                pos = desc + ((descsz + 3) & ~3)
    except (struct.error, OverflowError):
        # struct.error: a header or note that runs past the file. OverflowError: an offset field
        # (e_phoff, 64-bit) too large for struct to index with at all. Either way: what was read
        # so far stands, the rest of the file's headers are not trusted.
        pass
    if len(set(seen_info)) > 1:     # two process records that differ: neither is answered
        out.update(pid=None, ppid=None, uid=None, gid=None, name=None, args=None)
    return out


# ---- heap-chain carver (B-067) ------------------------------------------------------------------------
#
# Carve a linked list of records out of the glibc heap of an ELF core and rank the rebuilt chains by
# the saved registers and the flag format. The node layout {next, len, text} was inferred per
# challenge (csctf 9087); this searches a small set of common record shapes and keeps the one whose
# best chain ranks highest.
#
# What "walk" means here: a SCAN, not an allocator walk. Every 2*word-aligned position of a heap
# region is tried as a chunk header, because a core's regions are not all brk heaps that start on a
# chunk (anonymous maps, thread arenas, the stack), and a walk that steps by size loses everything
# after one corrupt size. A position is kept when its size field passes glibc's size rule (the rule
# solvers/toolkits/heap_primitives.py _chunk_size encodes: a multiple of 2*word, at least 4*word)
# and the chunk fits in the bytes the core holds. PREV_INUSE is the heap toolkits' constant
# (heap_families.PREV_INUSE): the bit is read from the chunk that FOLLOWS a record (reported as
# `inuse` / `freed`, never a filter). A clear bit means the record's chunk had been returned to the
# unsorted, small or large bins when the core was written. A set bit does NOT prove the record was
# live: a tcache or fastbin free, the usual fate of a small record, leaves the bit set.
#
# Memory: a record's text is a slice of the file, so the records of one layout hold at most the
# file's size in text. Chains are different: every chain carries its own copy of its text, and decoy
# heads that share one tail multiply it, so the chain text is capped per chain and per layout
# (HEAP_MAX_CHAIN_TEXT, HEAP_MAX_TEXT) and a cut is named in `partial` like every other bound.

HEAP_SIZE_FLAGS = 0x7                     # the 3 low bits of a glibc chunk size are flags, not size
RECORD_MAX_CHUNK = 0x8000                 # a carved record chunk is short: ignore larger "sizes"
HEAP_MAX_CANDIDATES = 1 << 18             # per core, a cap on the chunk candidates the scan keeps
HEAP_MAX_SCAN = 1 << 24                   # ... on the aligned positions it visits (a huge anon map)
HEAP_MAX_NODES = 20000                    # ... on the records kept under one record shape
HEAP_MAX_WALK = 1 << 21                   # ... on the records visited while rebuilding chains
HEAP_MAX_CHAIN_TEXT = 1 << 20             # ... on the characters of one chain's text
HEAP_MAX_TEXT = 1 << 24                   # ... on the characters of all the chains of one layout
HEAP_SCAN_BLOCK = 1 << 14                 # positions (scan) or chunks (record read) between two looks at the deadline
HEAP_PRINTABLE = frozenset(range(0x20, 0x7F))
REPORT_MAX_CHAINS = 64                    # chains the command prints per core; the rest are counted


def _flag_format() -> tuple:
    """(the active event's FlagFormat, "") following CTF_EVENT, or (None, why) when the event profile
    does not resolve (ctf.event.EventError: no event set, or a profile that does not load). A rebuilt
    chain is then ranked without the format, and heap_chains puts `why` in its warnings. Anything
    that is not an EventError is a bug and is raised."""
    from ctf.event import EventError
    try:
        return flagfmt.current(), ""
    except EventError as exc:
        return None, str(exc)


def _is_chunk_size(csize: int, word: int) -> bool:
    """glibc's rule for a chunk size with its flag bits masked off: a multiple of the malloc
    alignment (2*word), at least the minimum chunk (4*word). The same rule as
    heap_primitives._chunk_size (tests pin the two together)."""
    return csize >= 4 * word and csize % (2 * word) == 0


def _record_shapes(word: int) -> list:
    """The record layouts searched over, for a pointer width `word` (8 LP64, 4 LP32). Each is
    {name, ptr(off,size), len(off,size) | None, text_off}: the node is read out of a chunk's user
    data under exactly one of these."""
    a4 = (4 + word - 1) & ~(word - 1)     # a 4-byte length padded up to the next pointer slot
    return [
        {"name": "next_len", "ptr": (0, word), "len": (word, 4), "text": word + 4},        # {next, len, text}
        {"name": "len_next", "ptr": (a4, word), "len": (0, 4), "text": a4 + word},          # {len, next, text}
        {"name": "next_wlen", "ptr": (0, word), "len": (word, word), "text": 2 * word},     # {next, len(word), text}
        {"name": "wlen_next", "ptr": (word, word), "len": (0, word), "text": 2 * word},      # {len(word), next, text}
        {"name": "next_cstr", "ptr": (0, word), "len": None, "text": word},                 # {next, text\0}
    ]


def _heap_regions(core: dict) -> list:
    """The heap segment(s) of an ELF core: the rw PT_LOAD with no file behind it (brk heap / anon
    mappings), plus any NT_FILE mapping whose path names a heap. Each is {vaddr, off, filesz, memsz,
    perms, source}. Falls back to every rw segment only when nothing else is found (source
    "rw-fallback", which heap_chains reports as a warning), so a core whose every mapping is listed in
    NT_FILE still carves."""
    segs = core.get("segments") or []
    files = [f for f in (core.get("files") or []) if isinstance(f.get("start"), int) and isinstance(f.get("end"), int)]

    def backed(vaddr, end):
        return any(f["start"] < end and vaddr < f["end"] for f in files)

    regions, seen = [], set()

    def add(vaddr, off, filesz, memsz, perms, source):
        if filesz <= 0 or vaddr in seen:
            return
        seen.add(vaddr)
        regions.append({"vaddr": vaddr, "off": off, "filesz": filesz, "memsz": memsz, "perms": perms, "source": source})

    for f in files:                                  # an explicit [heap]/[anon:heap] mapping, when listed
        if "heap" in str(f.get("path") or "").lower():
            for s in segs:
                if s["vaddr"] <= f["start"] < s["vaddr"] + s["filesz"]:
                    start = f["start"]
                    filesz = min(f["end"], s["vaddr"] + s["filesz"]) - start
                    add(start, s["off"] + (start - s["vaddr"]), filesz, filesz, s["perms"], "nt_file:heap")
    for s in segs:                                   # unbacked rw segments: brk heap and anonymous maps
        if s["perms"][0] == "r" and s["perms"][1] == "w" and s["perms"][2] != "x" and not backed(s["vaddr"], s["vaddr"] + s["memsz"]):
            add(s["vaddr"], s["off"], s["filesz"], s["memsz"], s["perms"], "unbacked-rw")
    if not regions:                                  # nothing unbacked: try every rw segment (loud fallback)
        for s in segs:
            if s["perms"][0] == "r" and s["perms"][1] == "w":
                add(s["vaddr"], s["off"], s["filesz"], s["memsz"], s["perms"], "rw-fallback")
    return regions


def _heap_spans(regions: list, size: int) -> list:
    """[(vaddr, file offset, end offset)] of the regions' bytes that are really in the file: a
    truncated core's last region ends where the file does."""
    spans = []
    for r in regions:
        end = min(r["off"] + r["filesz"], size)
        if end > r["off"]:
            spans.append((r["vaddr"], r["off"], end))
    return spans


def _chunk_at(data, span: tuple, pos: int, word: int, fmt: str):
    """The glibc chunk whose header starts at file offset `pos` of one heap span (the caller keeps
    the 2*word header inside the span), or None when the size field there is no chunk size (the size
    rule, the record-size bound, a chunk that runs past the span). {chunk_va, user_va, user_off,
    usable, inuse}: `usable` is the user data an allocated chunk owns (size - one word: it reaches
    into the next chunk's prev_size), cut to the bytes present; `inuse` is the PREV_INUSE bit of the
    chunk that follows, None when that header is not in the span."""
    vaddr, off, end = span
    align = 2 * word
    csize = struct.unpack_from(fmt, data, pos + word)[0] & ~HEAP_SIZE_FLAGS
    if not _is_chunk_size(csize, word) or csize > RECORD_MAX_CHUNK or pos + csize > end:
        return None
    user_off = pos + align
    after = pos + csize
    inuse = None
    if after + align <= end:
        inuse = bool(struct.unpack_from(fmt, data, after + word)[0] & HEAP_PREV_INUSE)
    return {"chunk_va": vaddr + (pos - off), "user_va": vaddr + (user_off - off), "user_off": user_off,
            "usable": min(csize - word, end - user_off), "inuse": inuse}


def _chunk_of(data, spans: list, user_va: int, word: int, fmt: str):
    """The chunk whose user data begins at address `user_va` (a saved register, a record's `next`),
    or None: the address is outside the heap, unaligned, or no chunk header precedes it."""
    align = 2 * word
    if user_va % align:
        return None
    for span in spans:
        vaddr, off, end = span
        if vaddr + align <= user_va < vaddr + (end - off):
            return _chunk_at(data, span, off + (user_va - vaddr) - align, word, fmt)
    return None


def _heap_chunks(data, spans: list, word: int, e: str, *, max_candidates: int = HEAP_MAX_CANDIDATES,
                 max_scan: int = HEAP_MAX_SCAN, deadline=None) -> tuple:
    """Scan every aligned position of the heap spans for chunk headers (_chunk_at). Returns
    ([chunk...], [cut...]): `cut` names each bound that stopped the scan early (the position cap, the
    candidate cap, the deadline), empty when every position was visited."""
    align = 2 * word
    fmt = e + ("Q" if word == 8 else "I")
    pair = e + ("QQ" if word == 8 else "II")          # (prev_size, size): one chunk header
    out, scanned = [], 0
    with memoryview(data) as view:
        for span in spans:
            vaddr, off, end = span
            pos = off + ((align - vaddr % align) % align)       # first position whose chunk VA is aligned
            while pos + align <= end:
                if _late(deadline):
                    return out, ["the scan stopped at its deadline"]
                count = min(HEAP_SCAN_BLOCK, (end - pos) // align, max_scan - scanned)
                if count <= 0:
                    return out, [f"the scan stopped at its cap of {max_scan} positions"]
                for i, (_prev, size) in enumerate(struct.iter_unpack(pair, view[pos:pos + count * align])):
                    if not size:                      # speed only: zero pages are most of a heap
                        continue
                    chunk = _chunk_at(data, span, pos + i * align, word, fmt)
                    if chunk is None:
                        continue
                    if len(out) >= max_candidates:
                        return out, [f"the scan stopped at its cap of {max_candidates} chunk candidates"]
                    out.append(chunk)
                scanned += count
                pos += count * align
    return out, []


def _parse_record(data, chunk: dict, shape: dict, e: str, heap_lo_hi: list):
    """Read one chunk's user data under one record shape. Returns {next, text, len, inuse} or None.
    `next` is accepted only when it is 0 or lands inside a heap region; the text must be printable
    and non-empty. Every field is read inside chunk["usable"], which never passes the file's end."""
    usable, off = chunk["usable"], chunk["user_off"]
    po, ps = shape["ptr"]
    if shape["text"] > usable or po + ps > usable:
        return None
    nxt = struct.unpack_from(e + ("Q" if ps == 8 else "I"), data, off + po)[0]
    if nxt != 0 and not any(lo <= nxt < hi for lo, hi in heap_lo_hi):
        return None
    if shape["len"] is None:
        text = bytes(data[off + shape["text"]: off + usable]).split(b"\x00")[0]
    else:
        lo, ls = shape["len"]
        if lo + ls > usable:
            return None
        ln = struct.unpack_from(e + ("Q" if ls == 8 else "I"), data, off + lo)[0]
        if ln <= 0 or shape["text"] + ln > usable:
            return None
        text = bytes(data[off + shape["text"]: off + shape["text"] + ln])
    if not text or any(b not in HEAP_PRINTABLE for b in text):
        return None
    return {"next": nxt, "text": text.decode("ascii", "replace"), "len": len(text), "inuse": chunk["inuse"]}


def _carve_nodes(data, chunks: list, spans: list, shape: dict, word: int, e: str, reg_vas: list,
                 max_nodes: int, deadline=None) -> tuple:
    """The records of one shape: ({user_va: node}, capped, late). `capped`: max_nodes cut it. `late`:
    the deadline passed with scanned chunks still unread. The records a saved register points at come
    first, each followed by `next` straight through memory (the rule read off csctf 9087: start at
    the object the CPU held and follow next), so neither the scan caps, max_nodes nor the deadline
    can drop the chain the registers name while it fits; then every scanned chunk, in address order,
    with a look at the deadline every HEAP_SCAN_BLOCK chunks."""
    fmt = e + ("Q" if word == 8 else "I")
    heap_lo_hi = [(vaddr, vaddr + (end - off)) for vaddr, off, end in spans]
    nodes, capped, late = {}, False, False
    for va in reg_vas:
        cur = va
        while cur and cur not in nodes:
            chunk = _chunk_of(data, spans, cur, word, fmt)
            node = _parse_record(data, chunk, shape, e, heap_lo_hi) if chunk else None
            if node is None:
                break
            if len(nodes) >= max_nodes:
                capped = True
                break
            nodes[cur] = node
            cur = node["next"]
    for i, chunk in enumerate(chunks):
        if i % HEAP_SCAN_BLOCK == 0 and _late(deadline):
            late = True
            break
        if chunk["user_va"] in nodes:
            continue
        node = _parse_record(data, chunk, shape, e, heap_lo_hi)
        if node is None:
            continue
        if len(nodes) >= max_nodes:
            capped = True
            break
        nodes[chunk["user_va"]] = node
    return nodes, capped, late


def _build_chains(nodes: dict, first=(), max_walk: int = HEAP_MAX_WALK, max_text: int = HEAP_MAX_TEXT,
                  max_chain_text: int = HEAP_MAX_CHAIN_TEXT, deadline=None) -> tuple:
    """Rebuild linked chains from {user_va: node}. Returns ([{"vas": [...], "text": str, "text_cut":
    bool, "loop": bool}], {"unwalked": n, "late": n, "text_cut": n}). A chain starts at every record
    in `first` (the addresses saved registers hold, walked before anything else, whether or not
    another record points there: a decoy that links to the real first record must not hide it), then
    at every record no record points to, then, for a closed loop nothing else reaches, at its lowest
    record. Each start is walked by `next` to 0, to an address that is no record, or to a repeat
    (loop = True).

    Three bounds, each counted in the second value. max_walk bounds the records visited in all: a
    start that would pass it is not emitted cut short (`unwalked`). The deadline is looked at before
    every start that is not a register's: once it has passed, the remaining starts are not walked
    (`late`). The text is bounded because every chain holds its own copy and heads that share a
    tail multiply it: one chain's text stops at max_chain_text characters and the chains' texts
    together at max_text; a chain whose text did not fit whole keeps what fitted and is marked
    (`text_cut`). Register chains come first under all three, so a bound drops decoys before it
    drops the chain the registers name."""
    pointed = {n["next"] for n in nodes.values() if n["next"] in nodes}
    held = list(dict.fromkeys(va for va in first if va in nodes))
    starts = list(dict.fromkeys(held + sorted(va for va in nodes if va not in pointed)))
    chains, visited, steps, text_left = [], set(), 0, max_text
    cut = {"unwalked": 0, "late": 0, "text_cut": 0}

    def text_of(vas):
        nonlocal text_left
        room = min(max_chain_text, text_left)
        parts, size, whole = [], 0, True
        for va in vas:
            piece = nodes[va]["text"]
            if size + len(piece) > room:
                parts.append(piece[:room - size])
                size, whole = room, False
                break
            parts.append(piece)
            size += len(piece)
        text_left -= size
        return "".join(parts), not whole

    def walk(head):
        nonlocal steps
        vas, seen, cur = [], set(), head
        while cur in nodes and cur not in seen:
            if steps >= max_walk:
                cut["unwalked"] += 1
                return
            steps += 1
            seen.add(cur)
            vas.append(cur)
            cur = nodes[cur]["next"]
        visited.update(seen)
        text, text_cut = text_of(vas)
        cut["text_cut"] += text_cut
        chains.append({"vas": vas, "text": text, "text_cut": text_cut, "loop": cur in seen})

    for i, head in enumerate(starts):
        if i >= len(held) and _late(deadline):
            cut["late"] = len(starts) - i
            break
        walk(head)
    if not cut["unwalked"] and not cut["late"]:     # (a spent bound walks nothing more: the counts above say so)
        for va in sorted(nodes):                    # what no start reached is a closed loop: walk it once
            if va in visited:
                continue
            if _late(deadline):
                cut["late"] += 1                    # at least this loop; the loops after it are not counted
                break
            walk(va)
    return chains, cut


def _rank_chains(chains: list, nodes: dict, reg_names: dict, primary: tuple, flag_format) -> list:
    """Score each rebuilt chain and return them best first. Registers: +1000 when the chain's first
    record is the address in a primary register (the SysV arg0 / return register, _GPR_PRIMARY),
    +400 when it is in any other saved register, +100 when a register points at a later record of
    the chain. Flag format: +5000 for a complete flag, +800 for a chain that begins with a flag
    prefix, +50 for one that holds a prefix. Then one point per record (to 64), so length only breaks
    ties between chains the registers and the format do not tell apart. `reg_names` is {address:
    [register names]} over every thread. `freed` counts the chain's records whose chunk had gone back
    to the unsorted, small or large bins (PREV_INUSE clear in the chunk after it); a record freed into
    tcache or a fastbin is not counted, because that free leaves the bit set."""
    cribs = ()
    if flag_format is not None:
        try:
            cribs = flag_format.cribs()
        except LookupError:         # an event whose flag prefix is not known yet: no prefix points
            cribs = ()
    ranked = []
    for c in chains:
        head = c["vas"][0]
        head_regs = reg_names.get(head, [])
        any_regs = sorted({n for va in c["vas"] for n in reg_names.get(va, [])})
        score = 0
        if any(n in primary for n in head_regs):
            score += 1000
        elif head_regs:
            score += 400
        elif any_regs:
            score += 100
        # a text that was cut is never called a complete flag: its end was not read
        is_flag = bool(flag_format is not None and not c["text_cut"] and flag_format.is_flag(c["text"]))
        if is_flag:
            score += 5000
        elif any(c["text"].startswith(crib) for crib in cribs):
            score += 800
        elif cribs and any(crib in c["text"] for crib in cribs):
            score += 50
        score += min(len(c["vas"]), 64)                 # a longer rebuilt chain breaks ties
        ranked.append({"text": c["text"], "head_va": head, "vas": c["vas"], "nodes": len(c["vas"]),
                       "head_regs": head_regs, "regs": any_regs, "is_flag": is_flag, "score": score,
                       "loop": c["loop"], "text_cut": c["text_cut"], "freed": sum(1 for va in c["vas"] if nodes[va]["inuse"] is False)})
    ranked.sort(key=lambda r: (-r["score"], -r["nodes"], r["head_va"]))
    return ranked


def heap_chains(core: dict, data, *, flag_format=None, no_format_why: str = "", max_nodes: int = HEAP_MAX_NODES,
                max_scan: int = HEAP_MAX_SCAN, max_candidates: int = HEAP_MAX_CANDIDATES,
                max_walk: int = HEAP_MAX_WALK, max_text: int = HEAP_MAX_TEXT,
                max_chain_text: int = HEAP_MAX_CHAIN_TEXT, deadline=None) -> dict:
    """Carve glibc heap records out of an ELF core and rebuild and rank their linked chains (B-067).

    `core` is an :func:`elf_core` dict of the same bytes. Returns:
      {heap: [regions], shape: {name, consistent, nodes}|None, nodes: [{va, next, text, len, inuse}],
       chains: [ranked, see _rank_chains], best: the first of chains|None, registers: [threads],
       partial: [the bounds that cut the carve short], warnings: [what a reader must know], note: str}
    The layout search keeps the record shape whose best chain ranks highest; chains are ranked by
    saved-register references and by the flag format. A carve cut by a cap or the deadline
    (monotonic seconds) still returns what it has, with every bound named in `partial`, in `warnings`
    and at the end of `note`: a chain reported next to a partial warning may be a decoy. The caps:
    scanned positions, chunk candidates, records per layout, records walked, and the chain text
    (max_chain_text characters a chain, max_text for all the chains of a layout: memory stays
    bounded when many heads share one tail). The deadline is obeyed by the scan, by each layout's
    read of the scanned chunks and by the chain rebuild; once it has passed only the chains the
    saved registers name are still followed (they need no scan and are short work). With no
    flag_format the ranking uses registers and length only, and a warning says so (with
    `no_format_why`, the reason the caller has no format, when given). No execution, no network:
    bytes in, structure out."""
    out = {"heap": [], "shape": None, "nodes": [], "chains": [], "best": None,
           "registers": core.get("registers") or [], "partial": [], "warnings": [], "note": ""}

    def done(summary):
        if out["partial"]:
            out["warnings"].insert(0, "PARTIAL carve (" + "; ".join(out["partial"])
                                   + "): chains may be missing, cut short or outranked by one not carved")
        out["note"] = "; ".join([summary] + out["warnings"])
        return out

    if not core or not core.get("segments"):
        return done("no PT_LOAD segments: not an ELF core model")
    word = 8 if core.get("bits") == 64 else 4
    e = "<" if data[5:6] == b"\x01" else ">"
    regions = _heap_regions(core)
    out["heap"] = regions
    spans = _heap_spans(regions, len(data))
    if not spans:
        return done("no heap region located (no unbacked rw segment, no [heap] mapping, or none of its bytes in the file)")
    if any(r["source"] == "rw-fallback" for r in regions):
        out["warnings"].append("no unbacked rw segment and no [heap] mapping: every rw segment was carved (rw-fallback)")
    if flag_format is None:
        out["warnings"].append("no flag format" + (f" ({no_format_why})" if no_format_why else "")
                               + ": chains ranked by registers and length only")
    primary = _GPR_PRIMARY.get(core.get("machine"), ())
    reg_names = {}
    for thread in out["registers"]:
        for name, val in thread.items():
            reg_names.setdefault(val, []).append(name)
    reg_vas = sorted(reg_names, key=lambda v: (not any(n in primary for n in reg_names[v]), v))
    chunks, cut = _heap_chunks(data, spans, word, e, max_candidates=max_candidates, max_scan=max_scan,
                               deadline=deadline)
    partial = list(cut)
    best_shape, unread = None, []
    for shape in _record_shapes(word):
        nodes, capped, late = _carve_nodes(data, chunks, spans, shape, word, e, reg_vas, max_nodes, deadline)
        if capped:
            partial.append(f"shape {shape['name']} stopped at its cap of {max_nodes} records")
        if late:
            unread.append(shape["name"])
        if not nodes:
            continue
        consistent = sum(1 for n in nodes.values() if n["next"] == 0 or n["next"] in nodes)
        chains, cut = _build_chains(nodes, reg_vas, max_walk, max_text, max_chain_text, deadline)
        if cut["unwalked"]:
            partial.append(f"shape {shape['name']}: {cut['unwalked']} chain start(s) not walked, the walk budget "
                           f"of {max_walk} records was spent")
        if cut["late"]:
            partial.append(f"shape {shape['name']}: {cut['late']} chain start(s) not walked, the deadline had passed")
        if cut["text_cut"]:
            partial.append(f"shape {shape['name']}: the text of {cut['text_cut']} chain(s) was cut at the text cap "
                           f"({max_chain_text} characters a chain, {max_text} for all chains)")
        ranked = _rank_chains(chains, nodes, reg_names, primary, flag_format)
        best = ranked[0] if ranked else None
        key = (1 if (best and best["is_flag"]) else 0, best["score"] if best else 0, consistent, len(nodes))
        if best_shape is None or key > best_shape["key"]:
            best_shape = {"shape": shape, "key": key, "nodes": nodes, "consistent": consistent, "ranked": ranked, "best": best}
    if unread:
        partial.append("the deadline passed with scanned chunks left unread under shape(s) " + ", ".join(unread))
    out["partial"] = partial
    if best_shape is None:
        return done("no record shape rebuilt a chain" if chunks else "no glibc chunk-shaped records in the heap region")
    nodes = best_shape["nodes"]
    out["shape"] = {"name": best_shape["shape"]["name"], "consistent": best_shape["consistent"], "nodes": len(nodes)}
    out["nodes"] = [{"va": va, "next": n["next"], "text": n["text"], "len": n["len"], "inuse": n["inuse"]}
                    for va, n in sorted(nodes.items())]
    out["chains"] = best_shape["ranked"]
    out["best"] = best_shape["best"]
    if not out["best"]:
        return done(f"records of shape {best_shape['shape']['name']} found, but no chain was rebuilt")
    b = out["best"]
    reg = (", from register " + "/".join(b["head_regs"])) if b["head_regs"] else ""
    return done(f"heap chain ({best_shape['shape']['name']}, {len(nodes)} records): "
                f"{b['text']!r}{reg}{' [flag]' if b['is_flag'] else ''}")


def _core_lines(core: dict, chains) -> list:
    """What the command prints for one ELF core: the process, its saved registers, and (when the
    heap was carved: `chains` is a heap_chains result) the heap regions, the record shape, every
    ranked chain up to REPORT_MAX_CHAINS with the rest counted, and the RECOVERED line."""
    lines = [f"   process {core['name']!r} pid {core['pid']} ppid {core['ppid']} uid {core['uid']} args {core['args']!r}",
             f"   {len(core['segments'])} segments, rwx: " + (", ".join(f"0x{s['vaddr']:x}" for s in core["segments"] if s["perms"] == "rwx") or "none"),
             "   mapped files: " + ", ".join(sorted({str(f['path']) for f in core["files"]})[:12])]
    if core.get("registers"):
        t0 = core["registers"][0]
        keys = [k for k in ("rdi", "rsi", "rdx", "rax", "rip", "rsp", "eax", "ebx", "eip", "esp", "x0", "r0", "pc", "sp") if k in t0]
        lines.append(f"   {len(core['registers'])} thread(s), regs: " + ", ".join(f"{k}=0x{t0[k]:x}" for k in keys[:8]))
    if not chains:
        return lines
    for r in chains["heap"]:
        lines.append(f"   heap region 0x{r['vaddr']:x} filesz 0x{r['filesz']:x} {r['perms']} ({r['source']})")
    if chains["shape"]:
        lines.append(f"   record shape {chains['shape']['name']}: {chains['shape']['nodes']} records, {chains['shape']['consistent']} linked")
    for rank in chains["chains"][:REPORT_MAX_CHAINS]:
        mark = " FLAG" if rank["is_flag"] else ""
        reg = (" <- " + "/".join(rank["head_regs"])) if rank["head_regs"] else ""
        extra = ((f", {rank['freed']} freed" if rank["freed"] else "") + (", loops" if rank["loop"] else "")
                 + (", text cut" if rank["text_cut"] else ""))
        lines.append(f"   chain score {rank['score']} 0x{rank['head_va']:x} ({rank['nodes']} nodes{extra}){reg}{mark}: {rank['text']!r}")
    if len(chains["chains"]) > REPORT_MAX_CHAINS:
        lines.append(f"   {len(chains['chains']) - REPORT_MAX_CHAINS} more chain(s) not printed (the first {REPORT_MAX_CHAINS} by rank are above)")
    for w in chains["warnings"]:
        lines.append(f"   WARNING {w}")
    if chains["best"]:
        lines.append(f"   RECOVERED: {chains['best']['text']!r}" + (" (flag)" if chains["best"]["is_flag"] else "")
                     + (" (PARTIAL carve: read the warning)" if chains["partial"] else ""))
    elif chains["note"]:
        lines.append(f"   heap: {chains['note']}")
    return lines


def heap_report(paths) -> str:
    """`memory.py --heap-chains <core>...`: the ELF-core lines of the command alone (process,
    registers, heap regions, ranked chains, RECOVERED), nothing else of the triage: no hash, no
    process carving. Each file is mapped, not read, and the carve is bounded by the heap caps, so
    intake can run it on every ELF core. ValueError names a file that is not an ELF core."""
    import mmap
    lines = []
    for p in paths:
        with open(p, "rb") as f:
            size = os.fstat(f.fileno()).st_size
            if size < 64:
                raise ValueError(f"{p}: {size} bytes, not an ELF core")
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
                core = elf_core(data)
                if not core:
                    raise ValueError(f"{p}: not an ELF core (no ELF header with e_type ET_CORE)")
                ff, why = _flag_format()
                lines.append(f"== {Path(p).name}: {size} bytes, format elf_core")
                lines += _core_lines(core, heap_chains(core, data, flag_format=ff, no_format_why=why))
    return "\n".join(lines)


# ---- tables: what Volatility (or anything like it) printed ----------------------------------------------

def _norm(h) -> str:
    return re.sub(r"[^a-z0-9]", "", str(h).lower())


PID = ("pid", "processid", "uniqueprocessid", "procid", "owningpid", "ownerpid", "owningprocess")
PPID = ("ppid", "parentpid", "parentprocessid", "inheritedfromuniqueprocessid", "parentid")
NAME = ("imagefilename", "comm", "process", "processname", "image", "imagename", "proc", "task", "owner", "name")
ARGS = ("args", "cmdline", "commandline", "command", "cmd", "arguments", "argv")
# What Volatility prints in a cell it could not read (real windows.cmdline output gives System the
# first): the reader's remark, not the process's command line, name or path.
_NOT_A_VALUE = re.compile(r"Required memory at 0x[0-9a-fA-F]+ is (?:not valid|inaccessible)|\(process exited\?\)$|"
                          r"(?:N/A|n/a|-|None|null|<?unreadable>?|<?unknown>?|Process \d+: Required memory)$")
CREATE = ("createtime", "starttime", "created", "creationtime", "createdat", "startedat", "started", "start")
EXIT = ("exittime", "exited", "exit")
USER = ("user", "username", "account", "accountname")
RADDR = ("foreignaddr", "foreignaddress", "remoteaddr", "remoteaddress", "remoteip", "dstip", "destinationip", "destip",
         "dstaddr", "destinationaddress", "raddr", "peer", "peerip", "peeraddress", "remotehost", "dst", "destination", "remote")
RPORT = ("foreignport", "remoteport", "dstport", "destinationport", "destport", "dport", "rport", "peerport")
LADDR = ("localaddr", "localaddress", "localip", "srcip", "sourceip", "srcaddr", "sourceaddress", "laddr", "src", "source", "local")
LPORT = ("localport", "srcport", "sourceport", "sport", "lport", "port")
PROTO = ("proto", "protocol")
STATE = ("state",)
RSTART = ("startvpn", "vadstart", "regionstart", "startaddress", "baseaddress", "base", "address", "start")
REND = ("endvpn", "vadend", "regionend", "endaddress", "end")
PROT = ("protection", "protect", "perms", "permissions", "prot")
VAR = ("variable", "var", "key", "field")
VALUE = ("value", "val")
SID = ("sid",)
KNOWN = set(PID + PPID + NAME + ARGS + CREATE + EXIT + USER + RADDR + RPORT + LADDR + LPORT + PROTO + STATE + RSTART + REND
            + PROT + VAR + VALUE + SID) | {
    "threads", "handles", "sessionid", "session", "wow64", "offset", "offsetv", "offsetp", "treedepth", "tag", "commitcharge",
    "privatememory", "size", "path", "fileoutput", "hexdump", "disasm", "notes", "block", "loadtime", "tid", "uid", "gid",
    "euid", "egid", "commandtime", "type", "grantedaccess", "handlevalue", "audit", "thds", "hnds", "sess", "filename"}
_NUMERIC = re.compile(r"(?:\*+\s*)?(?:\d+|0x[0-9a-fA-F]+)$")
_NOISE = re.compile(r"Volatility \d|Volatility Foundation|Progress:|PDB scanning|WARNING |INFO |DEBUG ")


def _is_header(cells) -> bool:
    cells = [c.strip() for c in cells]
    if len(cells) < 2 or any(_NUMERIC.match(c) for c in cells if c):
        return False
    known = sum(1 for c in cells if _norm(c) in KNOWN)
    return known >= 2 and known * 2 >= len([c for c in cells if c])


def _split(line: str, mode: str, ncols: int = 0, spans=None) -> list:
    if mode == "tab":
        return line.split("\t")
    if mode == "pipe":
        return [c.strip() for c in line.strip().strip("|").split("|")]
    if mode == "csv":
        try:
            return next(csv.reader([line]))
        except (csv.Error, StopIteration):
            return []
    if spans:
        return [line[a:(b if i < len(spans) - 1 else None)].strip() for i, (a, b) in enumerate(spans)]
    return line.split(None, ncols - 1) if ncols else line.split()


class Table(list):
    """The rows of one text table. ragged: a line under its header was not read as a row (cut short,
    too many cells, a cell that ran over), so the table may be missing a row and is never counted."""
    ragged = False


def tables_from_text(text: str) -> list:
    """[[row, ...], ...]: every table in a text, each row a dict {normalised column name: cell}.
    Tab-separated (Volatility 3), pipe tables (its pretty renderer), CSV, and whitespace columns
    (Volatility 2: a header, a line of dashes, cells cut at the dashes). A line is a header when
    most of its cells are column names this file knows and none is a number."""
    tables, cols, mode, spans, rows = [], None, None, None, None
    lines = text.splitlines()

    def dropped():
        if rows is not None:
            rows.ragged = True
    for i, line in enumerate(lines):
        if not line.strip() or _NOISE.match(line.strip()):
            continue
        for m in ("tab", "pipe", "csv", "space"):
            if (m == "tab" and "\t" not in line) or (m == "pipe" and line.count("|") < 2) or (m == "csv" and "," not in line):
                continue
            cells = _split(line, m)
            if _is_header(cells) and (m != "space" or (len(cells) >= 3 and all(_norm(c) in KNOWN for c in cells))):
                cols, mode, spans, rows = [_norm(c) for c in cells], m, None, Table()
                tables.append(rows)
                nxt = lines[i + 1] if i + 1 < len(lines) else ""
                if m == "space" and re.fullmatch(r"\s*-+(?:\s+-+)+\s*", nxt):
                    spans = [(d.start(), d.end()) for d in re.finditer(r"-+", nxt)]
                    cols = [_norm(c) for c in _split(line, "space", spans=spans)]
                break
        else:
            if cols is None or re.fullmatch(r"[\s|+:=-]+", line):
                continue
            cells = _split(line, mode, len(cols), spans)
            if mode == "tab" and "\t" not in line:
                dropped()
                continue            # a cell that ran over several lines (malfind's hex dump)
            if 2 <= len(cells) <= len(cols) and (mode != "space" or spans or len(cells) == len(cols)):
                row = {c: v.strip() for c, v in zip(cols, cells) if c}
                if "pid" in row and not _NUMERIC.match(row["pid"]):
                    dropped()
                    continue        # what ran over from the row before (a hex dump, a disassembly)
                rows.append(row)
            else:
                dropped()
    return [t for t in tables if t]


def tables_from_json(obj) -> tuple:
    """(tables, info): every list of objects in a JSON value as a table (Volatility's __children are
    flattened), and every scalar that sits directly in an object as info {normalised key: value}.
    A key seen twice with two values is dropped from info."""
    tables, info, clash = [], {}, set()

    def flat(rows, out):
        for r in rows:
            if isinstance(r, dict):
                out.append({_norm(k): v for k, v in r.items() if not isinstance(v, (list, dict))})
                kids = r.get("__children")
                if isinstance(kids, list):
                    flat(kids, out)
                for k, v in r.items():
                    if k != "__children" and isinstance(v, (list, dict)):
                        walk(v)

    def walk(v):
        if isinstance(v, list):
            if v and all(isinstance(x, dict) for x in v):
                out = []
                flat(v, out)
                tables.append(out)
            else:
                for x in v:
                    if isinstance(x, (list, dict)):
                        walk(x)
        elif isinstance(v, dict):
            for k, x in v.items():
                if isinstance(x, (list, dict)):
                    walk(x)
                elif x is not None:
                    k = _norm(k)
                    if k in info and info[k] != x:
                        clash.add(k)
                    info[k] = x

    walk(obj)
    return tables, {k: v for k, v in info.items() if k not in clash}


def _get(row: dict, names):
    for n in names:
        v = row.get(n)
        if v is not None and str(v).strip() not in ("", "-", "N/A", "None", "null"):
            return v
    return None


def _int(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    s = str(v if v is not None else "").strip().lstrip("*").strip()
    if re.fullmatch(r"\d{1,10}", s):
        return int(s)
    if re.fullmatch(r"0x[0-9a-fA-F]{1,16}", s):
        return int(s, 16)
    return None


def _addr(v):
    if isinstance(v, int) and not isinstance(v, bool):
        return v
    s = str(v if v is not None else "").strip()
    if re.fullmatch(r"0x[0-9a-fA-F]{1,16}", s):
        return int(s, 16)
    if re.fullmatch(r"\d{1,20}", s):
        return int(s)
    return None


def when(v):
    """A time cell as a naive UTC datetime, or None. Volatility prints UTC; a value with an offset
    is converted, one without is taken as UTC."""
    if isinstance(v, _dt.datetime):
        return v.astimezone(UTC).replace(tzinfo=None) if v.tzinfo else v
    s = str(v if v is not None else "").strip()
    s = re.sub(r"\s*UTC(?:[+-]0{4})?$", "", s)
    if not re.match(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}", s):
        return None
    try:
        d = _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d.astimezone(UTC).replace(tzinfo=None) if d.tzinfo else d


STRUCTURED = ("table", "minidump", "elfcore")       # sources whose facts are read, not carved


class Model:
    """Everything known about one delivery, whatever it came from.

    procs {pid: {pid, ppid, name, args, create, exit, user, src}}; a field two sources disagree on
    is in `clash` as (pid, field) and is never answered. conns, regions, envars, sids are lists of
    rows; info {normalised name: value}; proc_tables the pid list of each process table as it was
    listed (for a count); images [{name, format, size}]; notes for a reader. history is the shell
    history (linux.bash, mac.bash) as rows {pid, name, time, command, src}; kernel_banners the whole
    Linux banners carved from the images, by count."""

    def __init__(self):
        self.procs, self.clash = {}, set()
        self.conns, self.regions, self.envars, self.sids = [], [], [], []
        self.info, self.info_src, self.proc_tables = {}, {}, []
        self.ragged = False         # a process table lost a row: nothing is counted
        self.images, self.notes, self.env, self.banners = [], [], {}, Counter()
        self.recovered = []         # rebuilt heap/memory chains (B-067): [{source, text, head_va, regs, is_flag, score, partial}]
        self.heap = {}              # ELF core name -> its whole heap_chains result (the command prints from it)
        self.history = []                   # shell history rows (linux.bash, mac.bash): never a process's arguments
        self.kernel_banners = Counter()     # whole Linux banners carved from an image (what names its ISF)

    def add_proc(self, pid, src, **fields):
        if pid is None:
            return
        p = self.procs.setdefault(pid, {"pid": pid, "src": src})
        if p["src"] != src and src in STRUCTURED and p["src"] not in STRUCTURED:
            p["src"] = src
        for k, v in fields.items():
            if v is None or (isinstance(v, str) and not v.strip()):
                continue
            if isinstance(v, str) and _NOT_A_VALUE.match(v.strip()):
                continue                # Volatility's own words for "could not be read", never a value
            v = v.strip() if isinstance(v, str) else v
            old = p.get(k)
            if old is None:
                p[k] = v
            elif old != v:
                if k == "name" and isinstance(old, str) and isinstance(v, str):
                    short, long_ = sorted((old, v), key=len)
                    if len(short) in (14, 15) and long_.startswith(short):   # ImageFileName holds 15 bytes
                        p[k] = long_
                        continue
                self.clash.add((pid, k))

    def set_info(self, key, value, src="table"):
        key = _norm(key)
        if value is None or key == "":
            return
        if key in self.info and self.info[key] != value:
            self.info[key] = None
            return
        if key not in self.info:
            self.info[key], self.info_src[key] = value, src

    def absorb(self, rows: list, src: str = "table") -> str:
        """Take one table in. Returns what it was read as: conn, region, envar, info, sid, history,
        proc or ''."""
        keys = set()
        for r in rows:
            keys.update(k for k, v in r.items() if v is not None)
        has = lambda names: bool(keys & set(names))
        if "banner" in keys and not has(PID):       # banners.Banners: one banner, perhaps found several times
            found = {str(r["banner"]).strip() for r in rows if r.get("banner")}
            if len(found) == 1:
                self.set_info("banner", found.pop(), src)
            return "info"
        if has(RADDR) or (has(("localport", "lport", "port", "srcport")) and has(PROTO)):
            for r in rows:
                self.conns.append({"pid": _int(_get(r, PID)), "name": _get(r, tuple(n for n in NAME if n != "name")),
                                   "laddr": _get(r, LADDR), "lport": _int(_get(r, LPORT)), "raddr": _get(r, RADDR),
                                   "rport": _int(_get(r, RPORT)), "proto": _get(r, PROTO), "state": _get(r, STATE),
                                   "created": _get(r, CREATE), "src": src})
            return "conn"
        if has(PROT) and has(RSTART):
            for r in rows:
                start = _addr(_get(r, RSTART))
                if start is None:
                    continue
                self.regions.append({"pid": _int(_get(r, PID)), "name": _get(r, NAME), "start": start, "start_raw": _get(r, RSTART),
                                     "end": _addr(_get(r, REND)), "prot": str(_get(r, PROT) or "").strip() or None,
                                     "tag": _get(r, ("tag",)), "src": src})
            return "region"
        if has(VAR) and has(VALUE):
            if has(PID):
                for r in rows:
                    var, val = _get(r, VAR), _get(r, VALUE)
                    if var is not None and val is not None:
                        self.envars.append({"pid": _int(_get(r, PID)), "var": str(var), "value": str(val), "src": src})
                return "envar"
            for r in rows:
                var = _get(r, VAR)
                if var is not None:
                    self.set_info(var, _get(r, VALUE), src)
            return "info"
        if has(SID) and has(PID):
            for r in rows:
                self.sids.append({"pid": _int(_get(r, PID)), "sid": _get(r, SID), "name": r.get("name"), "src": src})
            return "sid"
        if "commandtime" in keys and "command" in keys and not has(PPID):
            # linux.bash / mac.bash: what a shell's user typed. A row's Command is a history line, not
            # the command line of the shell that holds it, so it never becomes that process's args
            # (read as a process table, two history lines of one shell were a clash on its args).
            for r in rows:
                command = _get(r, ("command",))
                if command is not None:
                    self.history.append({"pid": _int(_get(r, PID)), "name": _get(r, NAME),
                                         "time": _get(r, ("commandtime",)), "command": str(command), "src": src})
            return "history"
        if has(PID) and (has(PPID) or has(NAME) or has(ARGS)):
            pids = []
            listing = has(PPID)
            for r in rows:
                pid = _int(_get(r, PID))
                if pid is None:
                    self.ragged = self.ragged or listing
                    continue
                pids.append(pid)
                self.add_proc(pid, src, ppid=_int(_get(r, PPID)), name=_get(r, NAME), args=_get(r, ARGS),
                              create=_get(r, CREATE) if listing else None, exit=_get(r, EXIT) if listing else None,
                              user=_get(r, USER))
            if listing:
                self.proc_tables.append(pids)
                self.ragged = self.ragged or bool(getattr(rows, "ragged", False))
            return "proc"
        return ""


def _text(data: bytes):
    if len(data) > TEXT_MAX or b"\x00\x00\x00" in data[:4096]:
        return None
    for enc in ("utf-8-sig", "utf-16"):
        try:
            t = data.decode(enc)
        except (UnicodeDecodeError, UnicodeError):
            continue
        if sum(1 for c in t[:4096] if c.isprintable() or c in "\r\n\t") >= 0.95 * min(len(t), 4096):
            return t
    return None


def read_tables(model: Model, name: str, data: bytes, src: str = "table") -> list:
    """Read one text or JSON file's tables into the model. Returns what each was read as."""
    text = _text(data)
    if text is None:
        return []
    kinds, stripped = [], text.lstrip()
    if stripped[:1] in "{[":
        try:
            docs = [json.loads(stripped)]
        except ValueError:
            docs = []
            for line in stripped.splitlines():
                try:
                    docs.append(json.loads(line))
                except ValueError:
                    docs = []
                    break
            docs = [docs] if docs and all(isinstance(d, dict) for d in docs) else []
        for doc in docs:
            tables, info = tables_from_json(doc)
            for t in tables:
                kinds.append(model.absorb(t, src))
            for k, v in info.items():
                model.set_info(k, v, src)
        if docs:
            return [k for k in kinds if k]
    for t in tables_from_text(text):
        kinds.append(model.absorb(t, src))
    return [k for k in kinds if k]


# ---- carving: no symbols --------------------------------------------------------------------------------

_ENV_VARS = ("COMPUTERNAME", "USERNAME", "USERDOMAIN", "HOSTNAME", "LOGNAME", "USERPROFILE", "USER", "HOME", "OS",
             "PROCESSOR_ARCHITECTURE", "LOGONSERVER", "SESSIONNAME")
_ENV_A = re.compile(rb"(?<![A-Za-z0-9_])(" + "|".join(_ENV_VARS).encode() + rb")=([\x21-\x7e][\x20-\x7e]{0,79})(?=[\x00\r\n])")
_ENV_W = re.compile(rb"(?<![A-Za-z0-9_]\x00)(" + b"|".join(b"".join(bytes((c, 0)) for c in v.encode()) for v in _ENV_VARS)
                    + rb")=\x00((?:[\x21-\x7e]\x00)(?:[\x20-\x7e]\x00){0,79})(?=\x00\x00|\r\x00|\n\x00)")
_BANNER = re.compile(rb"Linux version (\d+\.\d+[\x21-\x7e]{0,60}) \([\x20-\x7e]{3,200}")
_CMD_W = re.compile(rb"(?:\"\x00)?[A-Za-z]\x00:\x00\\\x00(?:[\x20\x21\x23-\x7e]\x00){3,200}\.\x00[eE]\x00[xX]\x00[eE]\x00(?:\"\x00)?"
                    rb"(?:\x20\x00(?:[\x20-\x7e]\x00){1,400})?")


def _finds(data, needle: bytes, limit: int = 100000):
    """Offsets of a literal in the bytes (bytes.find: far faster than a regular expression over an image)."""
    pos, n = data.find(needle), 0
    while pos >= 0 and n < limit:
        yield pos
        n += 1
        pos = data.find(needle, pos + 1)


def _wide(text: str) -> bytes:
    return text.encode("utf-16-le")


def carve_env(data) -> dict:
    """{VARIABLE: Counter(values)} of environment strings found anywhere in the bytes, ASCII and
    UTF-16LE (COMPUTERNAME, USERNAME, USERDOMAIN, HOSTNAME, USER, LOGNAME, HOME, ...)."""
    out = {}
    for var in _ENV_VARS:
        for pos in _finds(data, var.encode() + b"="):
            m = _ENV_A.match(data, pos)
            if m and m.group(1).decode() == var:
                out.setdefault(var, Counter())[m.group(2).decode("latin-1").rstrip()] += 1
        for pos in _finds(data, _wide(var + "=")):
            m = _ENV_W.match(data, pos)
            if m and m.group(1).decode("utf-16-le") == var:
                out.setdefault(var, Counter())[m.group(2).decode("utf-16-le").rstrip()] += 1
    return out


def carve_banners(data) -> Counter:
    """Counter of Linux kernel releases from 'Linux version <release> (' banners."""
    found = (_BANNER.match(data, pos) for pos in _finds(data, b"Linux version "))
    return Counter(m.group(1).decode("latin-1") for m in found if m)


_BANNER_WHOLE = re.compile(rb"Linux version \d+\.\d+[\x20-\x7e]{8,480}")


def banner_key(text) -> str:
    """A Linux banner as it is compared: the text without the NUL and line end a kernel (and
    dwarf2json, in an ISF) leaves after it. Volatility 3 strips the same before it looks one up."""
    if isinstance(text, (bytes, bytearray, memoryview)):
        text = bytes(text).decode("latin-1")
    return str(text).replace("\x00", "").strip()


CARVE_CHUNK = 64 << 20          # bytes of an image searched for banners between two looks at the clock


def shown(text) -> str:
    """A name that comes out of a handout (a file, a folder, a table) as it is printed: every
    character that is not printable (a line break above all, and whatever else str.splitlines breaks
    a line at) is written as its escape. A name is data: it must not be able to start a report line
    of its own, and a reader of the report (intake reads an engine's stdout) must see one line."""
    return "".join(c if c.isprintable() else c.encode("unicode_escape").decode("ascii") for c in str(text))


def carve_linux_banners(data, limit: int = 100000, *, deadline=None, clock=time.monotonic, chunk: int = CARVE_CHUNK,
                        info=None) -> Counter:
    """Counter of whole Linux kernel banners as they stand in the bytes: the printable run from
    'Linux version <release>' on (the builder, the compiler, the build number and date). That whole
    text, not the release alone, names the one Volatility symbol table (ISF) of the kernel: two builds
    of one release have different tables. carve_banners keeps the short release form.
    The bytes are searched `chunk` at a time. With a `deadline` (a `clock()` value) the clock is
    looked at before every chunk and the carve stops past it; info, when a dict is passed, receives
    {"cut": the offset the carve stopped at, or None when it read everything}."""
    needle, out, n, pos, hits = b"Linux version ", Counter(), len(data), 0, 0
    if info is not None:
        info["cut"] = None
    while pos < n and hits < limit:
        if deadline is not None and clock() > deadline:
            if info is not None:
                info["cut"] = pos
            break
        end = min(n, pos + chunk)
        stop = min(n, end + len(needle) - 1)        # a banner that begins in this chunk is this chunk's, wherever it ends
        at = data.find(needle, pos, stop)
        while at >= 0 and hits < limit:
            hits += 1
            m = _BANNER_WHOLE.match(data, at)
            if m:
                out[banner_key(m.group())] += 1
            at = data.find(needle, at + 1, stop)
        pos = end
    return out


def carve_cmdlines(data, limit: int = 200) -> Counter:
    """Counter of UTF-16 strings that read as a Windows command line ('C:\\...\\x.exe args'). For a
    reader: a carved command line is not tied to a PID, and solve_set does not answer from it."""
    out = Counter()
    if data.find(_wide(".exe")) < 0 and data.find(_wide(".EXE")) < 0:
        return out
    for m in _CMD_W.finditer(data):
        out[m.group().decode("utf-16-le", "replace").strip()] += 1
        if len(out) >= limit:
            break
    return out


_WNAME = re.compile(rb"(?<![\x21-\x7e])([\x21-\x7e][\x20-\x7e]{2,14})\x00")


def _kptr(v: int, width: int) -> bool:
    return (v >> 48) == 0xFFFF if width == 8 else v >= 0x80000000


ANCHORS_MAX = 256           # name fields the calibration looks at (an image of nothing but names is not searched)


def _late(deadline) -> bool:
    return deadline is not None and time.monotonic() > deadline


def carve_windows_processes(data, limit: int = 400000, deadline=None) -> dict:
    """EPROCESS records found with no symbols and no profile.

    The layout moves between Windows builds, so the field offsets are calibrated on the image
    itself: ImageFileName is 15 bytes of name; UniqueProcessId sits a fixed distance before it and
    is followed by the two kernel pointers of ActiveProcessLinks; `System` has PID 4. The distance
    at which every `System` name field reads 4 followed by two kernel pointers is the PID offset
    (it must be the only such distance). InheritedFromUniqueProcessId is the one distance at which
    System reads 0, smss.exe reads 4, and the processes' values are PIDs of other carved processes.
    CreateTime is the one distance at which every carved process reads a plausible FILETIME
    (System itself may read 0: Windows XP gives it no create time).

    A name field with a PID before it is not yet a process: a real 512 MB image held 2,300 such
    places and 62 processes. So the object's own structure is calibrated on `System` too and then
    required of every record: the dispatcher header at the object's start (type 3, a size byte,
    two zero bytes: 03 00 1b 00 on Windows XP), found at one distance before every System name
    field, and the pool tag `Pro\xe3` or `Proc` shortly before the object. When either is found the
    image is searched for those marks, not for names (faster, and complete), and what does not
    carry them is dropped. An image with neither (a synthetic one) is read the old way.

    Returns {width, pid_delta, ppid_delta, create_delta, procs: [{pid, ppid, name, create, offset}],
    note}. procs is empty when the calibration is not unique. Terminated processes are found too,
    and a PID may appear twice: the Model marks that PID's fields as clashing."""
    out = {"width": None, "pid_delta": None, "ppid_delta": None, "create_delta": None, "procs": [], "note": ""}
    anchors = [p for p in _finds(data, b"System" + b"\x00" * 9, 4 * ANCHORS_MAX) if p == 0 or not 0x21 <= data[p - 1] <= 0x7E]
    if len(anchors) > ANCHORS_MAX:
        out["note"] = f"more than {ANCHORS_MAX} 'System' name fields: nothing to calibrate on"
        return out
    if not anchors:
        out["note"] = "no 'System' name field: not a Windows image, or nothing to calibrate on"
        return out
    n = len(data)
    found = []
    for width, fmt in ((8, "<QQQ"), (4, "<III")):
        for delta in range(0x40, 0x400, 4):
            ok = 0
            for a in anchors:
                if a - delta < 0:
                    continue
                pid, fl, bl = struct.unpack_from(fmt, data, a - delta)
                if pid == 4 and _kptr(fl, width) and _kptr(bl, width):
                    ok += 1
            if ok:
                found.append((width, delta))
    if len(found) != 1:
        out["note"] = f"the PID offset is not unique ({len(found)} candidates): nothing carved"
        return out
    width, delta = found[0]
    fmt = "<QQQ" if width == 8 else "<III"
    one = "<Q" if width == 8 else "<I"
    out["width"], out["pid_delta"] = width, delta
    good = [a for a in anchors if a - delta >= 0 and struct.unpack_from(fmt, data, a - delta)[0] == 4]
    # the object's own marks, calibrated on System: the header's distance before the name, the pool tag
    heads = []
    for k in range(delta + width, 0x800, width):
        sigs = {bytes(data[a - k:a - k + 4]) for a in good if a - k >= 0}
        if len(sigs) == 1 and all(a - k >= 0 for a in good):
            sig = next(iter(sigs))
            if sig[0] == 3 and sig[1] == 0 and sig[2] and sig[3] == 0:
                heads.append((k, sig))
    head = heads[0] if len(heads) == 1 else None
    tagged = bool(good) and all(max(data.rfind(b"Pro\xe3", max(0, a - 0x1000), a), data.rfind(b"Proc", max(0, a - 0x1000), a)) >= 0 for a in good)
    out["head_delta"], out["pool_tag"] = (head[0] if head else None), tagged
    recs, seen = [], 0

    def take(a, name):
        pid, fl, bl = struct.unpack_from(fmt, data, a - delta)
        if pid == 0 or pid % 4 or pid >= 1 << 26 or not _kptr(fl, width) or not _kptr(bl, width):
            return
        recs.append({"pid": pid, "ppid": None, "name": name, "create": None, "offset": a - delta})

    if head or tagged:
        places = set()
        if head:
            for pos in _finds(data, head[1], 4000000):
                if pos % width == 0:
                    places.add(pos + head[0])
        else:
            dists = {a - max(data.rfind(b"Pro\xe3", max(0, a - 0x1000), a), data.rfind(b"Proc", max(0, a - 0x1000), a)) for a in good}
            for tag in (b"Pro\xe3", b"Proc"):
                for pos in _finds(data, tag, 1000000):
                    places.update(pos + d for d in dists)
        for a in sorted(places):
            seen += 1
            if seen % 2048 == 0 and _late(deadline):
                out["note"] = "no time left: nothing carved"
                return out
            if a - delta < 0 or a + 16 > n:
                continue
            raw = bytes(data[a:a + 16]).split(b"\x00")[0]
            if not 1 <= len(raw) <= 15 or any(not 0x20 <= c <= 0x7E for c in raw):
                continue
            if head and tagged:
                base = a - head[0]
                lo = max(0, base - 0x100)
                if data.rfind(b"Pro\xe3", lo, base) < 0 and data.rfind(b"Proc", lo, base) < 0:
                    continue                # a header-shaped place with no process pool tag before it
            take(a, raw.decode("latin-1"))
    else:
        for m in _WNAME.finditer(data):
            seen += 1
            if seen > limit:
                out["note"] = f"stopped after {limit} name candidates"
                break
            if seen % 2048 == 0 and _late(deadline):
                out["note"] = "no time left: nothing carved"
                return out
            a = m.start(1)
            if a - delta < 0 or a + 16 > n:
                continue
            take(a, m.group(1).decode("latin-1"))
    pids = {r["pid"] for r in recs}
    smss = [r for r in recs if r["name"].lower() == "smss.exe"]
    system = [r for r in recs if r["name"] == "System" and r["pid"] == 4]
    cands = []
    if smss and system:
        others = [r for r in recs if r["pid"] != 4]
        for d in range(4, delta - 3 * width + 1, 4):                # after the PID and its links, before the name
            vals = [struct.unpack_from(one, data, r["offset"] + delta - d)[0] for r in recs]
            by = dict(zip(map(id, recs), vals))
            if any(by[id(r)] != 0 for r in system) or any(by[id(r)] != 4 for r in smss):
                continue
            if any(v % 4 or v >= 1 << 26 for v in vals):
                continue
            if sum(1 for r in others if by[id(r)] in pids) * 2 >= len(others):
                cands.append((d, vals))
    if len(cands) == 1:
        out["ppid_delta"] = cands[0][0]
        for r, v in zip(recs, cands[0][1]):
            r["ppid"] = v
    elif recs:
        out["note"] = (out["note"] + "; " if out["note"] else "") + f"the parent PID offset is not unique ({len(cands)} candidates)"
    times = []
    for d in range(-0x80, 0x400, 4 if width == 4 else 8):     # a 32-bit EPROCESS aligns its LARGE_INTEGERs to 4
        pos0 = [r["offset"] + d for r in recs]
        if not recs or any(p < 0 or p + 8 > n for p in pos0):
            continue
        raw = [struct.unpack_from("<Q", data, p)[0] for p in pos0]
        vals = [_filetime(v) for v in raw]
        # System may have no create time (0 on Windows XP); every other record must read a real one
        if all(v or (r["pid"] == 4 and x == 0) for v, x, r in zip(vals, raw, recs)) and any(vals):
            times.append((d, vals))
    if len(times) > 1:
        # CreateTime sits within a few fields of the PID in every build (0x14 before it on XP, 0x28
        # after it on Windows 10); a second time-shaped field hundreds of bytes on is another one
        times.sort(key=lambda t: abs(t[0]))
        times = times[:1] if abs(times[0][0]) <= 0x60 and abs(times[1][0]) >= 2 * abs(times[0][0]) + 0x40 else times
    if len(times) == 1:
        out["create_delta"] = times[0][0]
        for r, v in zip(recs, times[0][1]):
            r["create"] = v
    out["procs"] = recs
    return out


_LNAME = re.compile(rb"(?<![\x21-\x7e])([\x21-\x7e][\x20-\x7e]{0,14})\x00")


def carve_linux_tasks(data, limit: int = 400000, deadline=None) -> dict:
    """task_struct records of thread-group leaders, with no symbols.

    comm is 16 bytes; pid and tgid are two adjacent 32-bit integers a fixed distance before it. The
    distance at which a `systemd` comm reads (1, 1) and a `kthreadd` comm reads (2, 2) is the PID
    offset, and it must be the only one. Every name field with pid == tgid > 0 at that distance is
    then a process. Parents are pointers and are not read. {pid_delta, procs: [{pid, name,
    offset}], note}; procs is empty when the calibration is not unique."""
    out = {"pid_delta": None, "procs": [], "note": ""}
    field = lambda name: [p for p in _finds(data, name + b"\x00", 4 * ANCHORS_MAX) if p == 0 or not 0x21 <= data[p - 1] <= 0x7E]
    two = field(b"kthreadd")
    one = (field(b"systemd") or field(b"init")) if two else []
    if len(one) > ANCHORS_MAX or len(two) > ANCHORS_MAX:
        out["note"] = f"more than {ANCHORS_MAX} systemd/kthreadd name fields: nothing to calibrate on"
        return out
    if not one or not two:
        out["note"] = "no systemd/init and kthreadd name fields: not a Linux image, or nothing to calibrate on"
        return out
    found = []
    for delta in range(8, 0x1000, 4):
        a = any(p - delta >= 0 and struct.unpack_from("<ii", data, p - delta) == (1, 1) for p in one)
        b = any(p - delta >= 0 and struct.unpack_from("<ii", data, p - delta) == (2, 2) for p in two)
        if a and b:
            found.append(delta)
    if len(found) != 1:
        out["note"] = f"the PID offset is not unique ({len(found)} candidates): nothing carved"
        return out
    delta = out["pid_delta"] = found[0]
    seen = 0
    for m in _LNAME.finditer(data):
        seen += 1
        if seen > limit:
            out["note"] = f"stopped after {limit} name candidates"
            break
        if seen % 2048 == 0 and _late(deadline):
            out["procs"], out["note"] = [], "no time left: nothing carved"
            return out
        a = m.start(1)
        if a - delta < 0:
            continue
        pid, tgid = struct.unpack_from("<ii", data, a - delta)
        if 0 < pid == tgid < 1 << 22:
            out["procs"].append({"pid": pid, "name": m.group(1).decode("latin-1"), "offset": a - delta})
    return out


def carve(model: Model, data, name: str = "", procs: bool = True, deadline=None):
    """Everything the carvers find in one image, into the model, under the source 'carved'. With
    procs=False only the environment strings and the banner (a table already names the processes,
    and a carved record must not be set against a listed one)."""
    for var, values in carve_env(data).items():
        model.env.setdefault(var, Counter()).update(values)
    model.banners.update(carve_banners(data))
    model.kernel_banners.update(carve_linux_banners(data))
    if not procs:
        return None, None
    w = carve_windows_processes(data, deadline=deadline)
    for r in w["procs"]:
        model.add_proc(r["pid"], "carved", ppid=r["ppid"], name=r["name"], create=r["create"])
    if w["procs"]:
        model.notes.append(f"{name}: {len(w['procs'])} EPROCESS records carved (pointer width {w['width']}, PID -0x{w['pid_delta']:x} "
                           f"from the name" + (f", parent -0x{w['ppid_delta']:x}" if w["ppid_delta"] else ", parent not found") + ")")
    elif w["note"] and "not a Windows image" not in w["note"]:
        model.notes.append(f"{name}: {w['note']}")
    lx = {"procs": []}
    if not w["procs"]:
        lx = carve_linux_tasks(data, deadline=deadline)
        for r in lx["procs"]:
            model.add_proc(r["pid"], "carved", name=r["name"])
        if lx["procs"]:
            model.notes.append(f"{name}: {len(lx['procs'])} task_struct records carved (pid -0x{lx['pid_delta']:x} from comm)")
    return w, lx


# ---- Volatility 3, off the clock ----------------------------------------------------------------------

PLUGINS = {
    "windows": ["windows.info", "windows.pslist", "windows.pstree", "windows.psscan", "windows.cmdline", "windows.netscan",
                "windows.netstat", "windows.malfind", "windows.envars", "windows.getsids", "windows.filescan",
                "windows.dlllist", "windows.svcscan", "windows.registry.hivelist", "windows.registry.printkey",
                "windows.hashdump", "windows.lsadump", "windows.cachedump", "windows.cmdscan", "windows.consoles"],
    "linux": ["banners.Banners", "linux.pslist", "linux.pstree", "linux.psaux", "linux.bash", "linux.sockstat", "linux.malfind",
              "linux.envars", "linux.lsmod"],
    "mac": ["banners.Banners", "mac.pslist", "mac.pstree", "mac.psaux", "mac.bash", "mac.netstat", "mac.malfind", "mac.lsmod"],
    "any": ["banners.Banners"],
}

# Plugins that write extracted files need an output directory and are deliberately kept out of
# PLUGINS: vol_save's JSON-only runner cannot recover files created inside its disposable sandbox.
# The plan below makes that distinction explicit and gives the player a bounded, reviewable chain.
PLUGIN_PROFILES = {
    "credentials": ["windows.registry.hivelist", "windows.registry.printkey", "windows.hashdump",
                    "windows.lsadump", "windows.cachedump"],
    "console": ["windows.cmdline", "windows.cmdscan", "windows.consoles"],
    "files": ["windows.filescan", "windows.dumpfiles"],
    "injection": ["windows.malfind"],
}


def volatility_plan(objectives=("credentials", "console", "files", "injection"), *, pids=(),
                    file_offsets=(), max_steps: int = 64) -> list:
    """A static Volatility orchestration plan; it never starts Volatility itself.

    Dump-producing steps are annotated for a player-run sandbox export followed by
    ``chain_carved_blobs``.  PID and file-offset selectors must come from prior plugin rows, never
    from an automatically broadened scan.
    """
    if not isinstance(max_steps, int) or not 1 <= max_steps <= 256:
        raise ValueError("max_steps must be in 1..256")
    wanted = list(objectives)
    if len(wanted) > 16 or any(name not in PLUGIN_PROFILES for name in wanted):
        raise ValueError("unknown or excessive memory objective")
    clean_pids = []
    for pid in list(pids)[:64]:
        value = int(pid)
        if value < 0 or value > 0xFFFFFFFF:
            raise ValueError("PID outside the 32-bit bound")
        clean_pids.append(value)
    clean_offsets = []
    for offset in list(file_offsets)[:128]:
        value = int(offset, 0) if isinstance(offset, str) else int(offset)
        if value < 0 or value.bit_length() > 64:
            raise ValueError("file offset outside the 64-bit bound")
        clean_offsets.append(value)
    steps, seen = [], set()

    def add(plugin, args=(), produces=()):
        key = (plugin, tuple(args))
        if key in seen or len(steps) >= max_steps:
            return
        seen.add(key)
        steps.append({"plugin": plugin, "args": list(args), "produces": list(produces),
                      "offline": True, "chain": "chain_carved_blobs" if produces else None})

    for objective in wanted:
        for plugin in PLUGIN_PROFILES[objective]:
            if plugin == "windows.dumpfiles":
                for offset in clean_offsets:
                    add(plugin, ("--virtaddr", hex(offset), "--dump"), ("dumped-file",))
            elif plugin == "windows.malfind" and clean_pids:
                for pid in clean_pids:
                    add(plugin, ("--pid", str(pid), "--dump"), ("malfind-region",))
            else:
                add(plugin)
    return steps


_CRED_LINE = re.compile(r"(?i)^(?P<user>[^:\r\n]{1,256}):(?P<rid>[0-9a-f]{1,8}):"
                        r"(?P<lm>[0-9a-f]{32}):(?P<nt>[0-9a-f]{32})(?::|$)")
_FLAG_BYTES = flagfmt.BYTES


def parse_credential_rows(text: str) -> list:
    """Parse hashdump-style rows as evidence; hashes are never cracked or submitted."""
    if not isinstance(text, str) or len(text) > TEXT_MAX:
        return []
    out = []
    for line in text.splitlines()[:200000]:
        match = _CRED_LINE.match(line.strip())
        if match:
            out.append({key: value for key, value in match.groupdict().items()})
            if len(out) >= 10000:
                break
    return out


def chain_carved_blobs(blobs, *, max_blobs: int = 256, max_total: int = 64 << 20) -> list:
    """Rank exact strings/file signatures from dumpfiles or malfind exports.

    This is the host-safe bridge into the stego/strings path: it does no execution and returns only
    offsets, exact byte candidates, and recommended offline engines.  Deep recursive carving remains
    an explicit player action through ``carve_stego.py`` in the sandbox workflow.
    """
    if not isinstance(max_blobs, int) or not 1 <= max_blobs <= 4096:
        raise ValueError("max_blobs outside bound")
    rows, total = [], 0
    try:
        items = list(blobs.items()) if isinstance(blobs, dict) else list(blobs)
    except (TypeError, MemoryError) as exc:
        raise ValueError("blobs must be a bounded mapping/sequence") from exc
    if len(items) > max_blobs:
        raise ValueError("blob count exceeds bound")
    magics = ((b"\x89PNG\r\n\x1a\n", "png"), (b"PK\x03\x04", "zip"),
              (b"%PDF-", "pdf"), (b"\x7fELF", "elf"), (b"MZ", "pe"),
              (b"\xff\xd8\xff", "jpeg"), (b"RIFF", "riff"))
    for name, body in items:
        if not isinstance(name, str) or not isinstance(body, (bytes, bytearray, memoryview)):
            continue
        data = bytes(body)
        total += len(data)
        if total > max_total:
            raise ValueError("carved-blob byte budget exceeded")
        for match in _FLAG_BYTES.finditer(data):
            rows.append({"name": name, "kind": "exact-string", "offset": match.start(),
                         "value": match.group().decode("ascii", "replace"), "score": 100,
                         "next": "human review"})
        for magic, kind in magics:
            start = 0
            for _ in range(32):
                offset = data.find(magic, start)
                if offset < 0:
                    break
                rows.append({"name": name, "kind": kind, "offset": offset, "score": 80,
                             "next": "solvers/toolkits/carve_stego.py"})
                start = offset + len(magic)
    return sorted(rows[:4096], key=lambda row: (-row["score"], row["name"], row["offset"]))


def vol_bin() -> Path:
    return Path(sys.executable).parent / "vol"


VOL_SYMBOLS = "https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip"
# The Microsoft symbol server Volatility 3 itself fetches a kernel's PDB from with `--online` (venv only).
MS_SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols/"
_PDB_REF = re.compile(rb"RSDS(.{16})(.{4})((?:nt(?:kr|os)[a-z]{2,6})\.pdb)\x00", re.S | re.I)


def kernel_pdb(data, limit: int = 8) -> list:
    """[(pdb name, GUID as 32 hex digits, age)] of the Windows kernel's debug reference (RSDS) found
    in an image's bytes, most frequent first: what names the one symbol file Volatility needs
    (`ntoskrnl.pdb/<GUID>-<age>.json.xz`). [] for an image with none (not Windows, or paged out)."""
    import uuid
    seen = Counter()
    for m in _PDB_REF.finditer(data):
        seen[(m.group(3).decode("ascii").lower(), uuid.UUID(bytes_le=m.group(1)).hex.upper(), struct.unpack("<I", m.group(2))[0])] += 1
        if len(seen) >= 64:
            break
    return [k for k, _ in seen.most_common(limit)]


def symbols_folder() -> Path:
    return tables_root() / "_symbols"


def fetch_isf(pdb: str, guid: str, age: int, url: str = VOL_SYMBOLS, timeout: float = 120.0) -> tuple:
    """(path or None, note): the one Volatility symbol file for a kernel, as a small `windows.zip`
    pack under <challenges>/_memory/_symbols/<GUID>-<age>/ that vol(..., symbols=path) hands the
    sandbox. It is cut out of Volatility's public symbol pack with three HTTP range requests (the
    pack is 840 MB; the member is about 160 KB): an outside request, so the caller's decision on an
    untimed base and never made by solve_set. A pack already saved is reused with no request.

    Scope (R-13): `url` is a public mirror, so the fetch needs its host in the event profile's
    rules.public_fetch_allow; otherwise ctf.scope.OutOfScope is raised before any request."""
    import urllib.request
    import zipfile
    import zlib
    member = f"windows/{pdb}/{guid}-{age}.json.xz"
    dest = symbols_folder() / f"{guid}-{age}" / "windows.zip"
    if dest.is_file():
        return dest, f"{member}: already saved"
    scope.check_public_fetch(url, purpose=f"memory.fetch_isf (the Volatility symbol file {member})")

    def rng(a, b):
        req = urllib.request.Request(url, headers={"Range": f"bytes={a}-{b}", "User-Agent": "csctf-memory-toolkit"})
        with urllib.request.urlopen(req, timeout=timeout) as h:
            return h.read()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="HEAD", headers={"User-Agent": "csctf-memory-toolkit"}), timeout=timeout) as h:
            size = int(h.headers["Content-Length"])
        tail = rng(max(0, size - 70000), size - 1)
        i = tail.rfind(b"PK\x05\x06")
        if i < 0:
            return None, "the symbol pack's directory was not found"
        _, cdsize, cdoff = struct.unpack_from("<HII", tail, i + 10)
        j = tail.rfind(b"PK\x06\x06")
        if j >= 0 and cdoff == 0xFFFFFFFF:
            _, cdsize, cdoff = struct.unpack_from("<QQQ", tail, j + 32)
        cd = rng(cdoff, cdoff + cdsize - 1)
        pos, hit = 0, None
        while pos + 46 <= len(cd) and cd[pos:pos + 4] == b"PK\x01\x02":
            method = struct.unpack_from("<H", cd, pos + 10)[0]
            csize, usize, nlen, elen, clen = struct.unpack_from("<IIHHH", cd, pos + 20)
            if cd[pos + 46:pos + 46 + nlen].decode("utf-8", "replace").lower() == member.lower():
                hit = (method, csize, usize, struct.unpack_from("<I", cd, pos + 42)[0])
                break
            pos += 46 + nlen + elen + clen
        if hit is None:
            return None, f"{member} is not in the symbol pack (pdbconv.py can make it from Microsoft's PDB: `--where venv --online`)"
        method, csize, usize, lho = hit
        lh = rng(lho, lho + 30 + 1024)
        nlen, elen = struct.unpack_from("<HH", lh, 26)
        body = rng(lho + 30 + nlen + elen, lho + 30 + nlen + elen + csize - 1)
        body = zlib.decompress(body, -15) if method == 8 else body
        if len(body) != usize or body[:6] != b"\xfd7zXZ\x00":
            return None, f"{member}: what came back is not the symbol file"
    except Exception as e:
        return None, f"{member} could not be fetched ({type(e).__name__}: {e})"
    dest.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_STORED) as z:
        z.writestr(member, body)
    return dest, f"{member}: {len(body)} bytes saved"


# ---- the Linux symbol table (ISF), matched locally: no download (B-136) ---------------------------------

ISF_SUFFIXES = (".json", ".json.xz", ".json.gz", ".json.bz2")      # the names Volatility 3 reads as a symbol table
ISF_READ_MAX = 1 << 30          # decompressed bytes of one candidate read while looking for its banner
ISF_FILES_MAX = 256             # candidate files opened under one folder
ISF_WALK_MAX = 20000            # file names looked at under one folder
ISF_DEPTH = 3                   # folder levels walked below it
ISF_KEYS_MAX = 64               # `"linux_banner"` keys of one candidate parsed (a table has one or two)
ISF_SEARCH_BUDGET = 60.0        # seconds linux_symbols_for gives the table search (wall clock: untrusted files)
ISF_CUT = "the table search's budget ran out"      # what every note of a search the clock cut says
_ISF_KEY = b'"linux_banner"'
_ISF_OBJECT = 1 << 16           # the symbol's own JSON object is a few hundred bytes
_ISF_BANNER = re.compile(r"Linux version \d+\.\d+\S*\s.{8,}")


def _isf_open(path: Path):
    name = path.name.lower()
    if name.endswith(".xz"):
        import lzma
        return lzma.open(path, "rb")
    if name.endswith(".gz"):
        import gzip
        return gzip.open(path, "rb")
    if name.endswith(".bz2"):
        import bz2
        return bz2.open(path, "rb")
    return open(path, "rb")


def _isf_symbol_banner(fragment: bytes):
    """The banner of a `"linux_banner": {...}` symbol, given the bytes that follow the key; None
    when what follows is not that object or its constant data is not a kernel banner."""
    m = re.match(rb"\s*:\s*", fragment)
    if not m or fragment[m.end():m.end() + 1] != b"{":
        return None
    try:
        obj, _ = json.JSONDecoder().raw_decode(fragment[m.end():].decode("utf-8", "replace"))
        key = banner_key(base64.b64decode(obj["constant_data"], validate=True))
    except (ValueError, KeyError, TypeError, RecursionError):
        return None             # not that object: a string, other keys, bad base64, or nesting too deep to parse
    return key if _ISF_BANNER.match(key) else None


def isf_banner(path, read_max: int = ISF_READ_MAX, *, deadline=None, clock=time.monotonic, keys_max: int = ISF_KEYS_MAX):
    """The Linux banner an ISF file was made for (the constant data of its `linux_banner` symbol, as
    dwarf2json writes it), or None when the file is not a Linux ISF, cannot be read, or its banner
    symbol does not begin within read_max decompressed bytes. The file is streamed and only that
    one symbol is parsed: a table is tens of MB of JSON.
    A candidate is untrusted (at intake the whole handout is searched), so the read is bounded three
    ways: read_max bytes, keys_max `"linux_banner"` keys parsed (a file with more is no table), and
    `deadline` (a `clock()` value, looked at before every block): past it the answer is None and the
    caller, who holds the same clock, says the search was cut."""
    import lzma
    import zlib
    try:
        with _isf_open(Path(path)) as f:
            buf, total, keys = b"", 0, 0
            while total < read_max:
                if deadline is not None and clock() > deadline:
                    return None
                block = f.read(min(1 << 20, read_max - total))
                if not block:
                    return None
                total += len(block)
                buf += block
                i = buf.find(_ISF_KEY)
                while i >= 0:
                    if keys >= keys_max:
                        return None
                    keys += 1
                    while len(buf) - i < _ISF_OBJECT:       # the whole object, when the key sits at a block's end
                        more = f.read(_ISF_OBJECT)
                        if not more:
                            break
                        total += len(more)
                        buf += more
                    got = _isf_symbol_banner(buf[i + len(_ISF_KEY):i + _ISF_OBJECT])
                    if got:
                        return got
                    i = buf.find(_ISF_KEY, i + 1)
                buf = buf[-(len(_ISF_KEY) - 1):]
    except (OSError, EOFError, ValueError, lzma.LZMAError, zlib.error):
        return None             # unreadable, cut short, or not the compression its name says: no banner read
    return None


def linux_isfs(folders, files_max: int = ISF_FILES_MAX, *, walk_max: int = ISF_WALK_MAX, deadline=None,
               clock=time.monotonic) -> tuple:
    """([(path, banner)], notes): the Linux ISF files under the folders, each with the banner it was
    made for. A folder is walked ISF_DEPTH levels down and at most walk_max names; hidden folders
    (a `.ctf` among them) and links are never entered. Only names Volatility reads as a table
    (ISF_SUFFIXES) are opened, at most files_max per folder. `deadline` (a `clock()` value) bounds the
    whole search: it is looked at before every folder level and every candidate, and inside a
    candidate's read (isf_banner). notes says every folder that is not there, every cut (the budget's
    included, with the candidate it stopped at) and how many candidates hold no Linux banner: nothing
    is left out silently."""
    out, notes, seen = [], [], set()

    def late() -> bool:
        return deadline is not None and clock() > deadline
    spent = False
    for folder in folders:
        folder = Path(folder)
        if spent:
            notes.append(f"{shown(folder)}: not looked at ({ISF_CUT})")
            continue
        if not folder.is_dir():
            notes.append(f"{shown(folder)}: no such folder")
            continue
        looked, opened, blank, cut = 0, 0, [], ""
        for dirpath, dirnames, filenames in os.walk(folder):
            here = Path(dirpath)
            below = len(here.relative_to(folder).parts) < ISF_DEPTH
            dirnames[:] = sorted(d for d in dirnames if below and not d.startswith("."))    # os.walk follows no link
            if late():
                spent, cut = True, f"{ISF_CUT}: {opened} candidate(s) opened, the rest was not looked at"
                break
            for name in sorted(filenames):
                looked += 1
                if looked > walk_max:
                    cut = f"more than {walk_max} files: the rest was not looked at"
                    break
                path = here / name
                if name.startswith(".") or not name.lower().endswith(ISF_SUFFIXES) or path.is_symlink() or not path.is_file():
                    continue
                real = path.resolve()
                if real in seen:
                    continue
                seen.add(real)
                if opened >= files_max:
                    cut = f"more than {files_max} candidate tables: the rest was not opened"
                    break
                if late():
                    spent, cut = True, (f"{ISF_CUT} before {shown(name)}: {opened} candidate(s) opened, "
                                        "the rest was not looked at")
                    break
                opened += 1
                banner = isf_banner(path, deadline=deadline, clock=clock)
                if banner:
                    out.append((path, banner))
                elif late():            # its read was cut by the clock: not known to hold no banner
                    spent, cut = True, (f"{ISF_CUT} while reading {shown(name)}: {opened} candidate(s) "
                                        "opened, the rest was not looked at")
                    break
                else:
                    blank.append(name)
            if cut:
                break
        if cut:
            notes.append(f"{shown(folder)}: {cut}")
        if blank:
            notes.append(f"{shown(folder)}: {len(blank)} candidate file(s) hold no Linux banner "
                         f"({', '.join(shown(name) for name in blank[:4])}" + (", ..." if len(blank) > 4 else "") + ")")
    return out, notes


def match_linux_isf(banners, folders, tables=None, *, deadline=None, clock=time.monotonic) -> tuple:
    """(path or None, banner or None, note): the local ISF made for a kernel whose banner is in
    `banners` (carve_linux_banners' Counter, most frequent first, or any iterable of banner texts).
    A table matches when its banner is the start of a carved one, the test Volatility 3 itself makes
    when it scans an image for the banners of the tables it holds. Of several such tables the one
    with the longest banner is taken (the whole carved banner before any shorter start of it; the
    first in walk order among equals), the rule memory_depth.select_profile has: a table that
    carries only the first words of the banner never wins over the kernel's own. No request is made
    and no table is picked by release alone: two builds of one release differ. With no exact banner the answer
    is None and the note says what was looked at and what is missing (a search the clock cut is
    said first: the table may be among what was not opened). tables: linux_isfs(folders) when the
    caller already holds it (the folders are then only named in the note); deadline, clock: the
    search's budget, as linux_isfs takes it."""
    ordered = [b for b, _ in banners.most_common()] if isinstance(banners, Counter) else list(banners)
    ordered = list(dict.fromkeys(k for k in (banner_key(b) for b in ordered) if k))
    if not ordered:
        return None, None, "no Linux banner was carved from the image: there is no kernel to match a symbol table to"
    folders = [Path(f) for f in folders]
    tables, notes = linux_isfs(folders, deadline=deadline, clock=clock) if tables is None else tables
    notes = sorted(notes, key=lambda n: ISF_CUT not in n)       # a budget cut is never among the notes left out below
    for banner in ordered:
        fits = [(path, made_for) for path, made_for in tables if banner.startswith(made_for)]
        if fits:
            path, made_for = max(fits, key=lambda fit: len(fit[1]))     # max keeps the first of equals: walk order
            how = ("its banner is the image's" if made_for == banner else
                   f"its banner is the first {len(made_for)} of the {len(banner)} characters carved")
            return path, made_for, f"{shown(path.name)} was made for this kernel ({how})"
    releases = sorted({b.split()[2] for _, b in tables if len(b.split()) > 2})
    wanted = ordered[0].split()[2:3]
    near = [shown(p.name) for p, b in tables if b.split()[2:3] == wanted]
    return None, None, (f"no local ISF for {ordered[0][:200]!r}: {len(tables)} Linux table(s) under "
                        + (", ".join(shown(f) for f in folders) or "no folder")
                        + (f" (made for {', '.join(releases[:6])})" if releases else "")
                        + (f"; {', '.join(near[:3])} is for the same release but another build (its banner differs), "
                           "so it is not used" if near else "")
                        + "".join(f"; {n}" for n in notes[:6])
                        + ". Nothing is fetched: make the table offline with dwarf2json from this kernel's debug "
                          "vmlinux and put the .json.xz in one of those folders")


def _banner_hash(banner) -> str:
    return hashlib.sha256(banner_key(banner).encode("utf-8", "replace")).hexdigest()[:16]


ISF_PACK_MAX = 512 << 20        # bytes of a table file that is packed (a real one: a few MiB as .json.xz, under 200 MiB plain)
PACK_TMP_STALE = 3600.0         # seconds after which a pack's temporary file is a killed run's, and is removed


class TableTooLarge(OSError):
    """The matched table is over ISF_PACK_MAX: it is not hashed and not copied into a pack."""


def linux_symbol_pack(isf, banner, info=None) -> Path:
    """The `linux.zip` symbol pack of one ISF, as vol(symbols=...) hands it to the sandbox: the table
    stored as `linux/<its name>` under <challenges>/_memory/_symbols/linux-<sha256 of the banner, 16
    hex>-<sha256 of the table file, 16 hex>/. The folder names the table's own bytes, so a pack is
    reused only for the very table it was made from: a damaged table, or a decoy that carries the
    right banner, is never served again once the right table is at hand. info, when a dict is
    passed, receives {"reused": bool}. The table is copied, never changed.
    The table is hashed and copied whole, outside any budget, so its size is bounded instead: one
    over ISF_PACK_MAX raises TableTooLarge (an OSError) before a byte of it is read. A temporary
    file a killed run left in the pack's folder is removed once it is PACK_TMP_STALE old."""
    import zipfile
    isf = Path(isf)
    size = isf.stat().st_size
    if size > ISF_PACK_MAX:
        raise TableTooLarge(f"{shown(isf.name)} is {size} bytes, over the {ISF_PACK_MAX} a pack takes: "
                            "compress the table (xz) and run this again")
    h = hashlib.sha256()
    with open(isf, "rb") as f:
        for block in iter(lambda: f.read(1 << 22), b""):
            h.update(block)
    dest = symbols_folder() / f"linux-{_banner_hash(banner)}-{h.hexdigest()[:16]}" / "linux.zip"
    if info is not None:
        info["reused"] = dest.is_file()
    if dest.is_file():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    for old in dest.parent.glob(f".{dest.name}.*.tmp"):
        try:
            if time.time() - old.stat().st_mtime > PACK_TMP_STALE:
                old.unlink()
        except OSError:
            pass                # another run's file, gone or not ours to remove: it is not this pack
    tmp = dest.with_name(f".{dest.name}.{os.getpid()}.tmp")
    try:
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_STORED) as z:
            z.write(isf, f"linux/{isf.name}")
        os.replace(tmp, dest)
    finally:
        tmp.unlink(missing_ok=True)
    return dest


def saved_linux_pack(banners) -> tuple:
    """(pack or None, banner or None, note): a `linux.zip` pack linux_symbol_pack saved earlier for a
    kernel whose banner is in `banners` (a Counter, most frequent first, or an iterable), found by the
    banner's hash in the folder's name: no table needs to be at hand any more. The lookup is by the
    exact carved banner (a carved run that goes on after the banner's end names no pack). With
    several packs for one banner (several tables carried it) the newest is used and the note says how
    many there are. Only a readable zip whose members are all under `linux/` is a pack."""
    import zipfile
    ordered = [b for b, _ in banners.most_common()] if isinstance(banners, Counter) else list(banners)
    root = symbols_folder()
    for banner in dict.fromkeys(k for k in (banner_key(b) for b in ordered) if k):
        packs = []
        for pack in sorted(root.glob(f"linux-{_banner_hash(banner)}-*/linux.zip")):
            try:
                with zipfile.ZipFile(pack) as z:
                    names = z.namelist()
            except (OSError, zipfile.BadZipFile):
                continue
            if names and all(n.startswith("linux/") for n in names):
                packs.append((pack.stat().st_mtime_ns, str(pack), pack, names[0].split("/", 1)[1]))
        if packs:
            _mtime, _key, pack, table = max(packs)
            return pack, banner, (f"a pack saved earlier for this kernel holds {shown(table)}"
                                  + (f" ({len(packs)} packs were saved for this banner: the newest is used)" if len(packs) > 1 else ""))
    return None, None, "no pack was saved earlier for this kernel"


def linux_symbols_for(image, folders=None, *, budget: float = ISF_SEARCH_BUDGET, clock=time.monotonic) -> tuple:
    """(pack or None, note): the symbol pack for a Linux image, matched locally from its own banner
    (carve_linux_banners over the whole file, match_linux_isf, linux_symbol_pack). folders defaults to
    the image's own folder (a delivery that ships its ISF) and symbols_folder(). With no table among
    them, a pack saved earlier for the same banner is used (saved_linux_pack). The table search stops
    after `budget` seconds of `clock` and says so. Never a download."""
    import mmap
    image = Path(image)
    if folders is None:
        folders = [image.parent, symbols_folder()]
    if image.stat().st_size == 0:
        return None, f"{image.name} is empty: no banner to match a symbol table to"
    with open(image, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        banners = carve_linux_banners(data)
    path, banner, note = match_linux_isf(banners, folders, deadline=clock() + budget, clock=clock)
    if path is None:
        pack, _banner, saved = saved_linux_pack(banners) if banners else (None, None, "")
        return (pack, saved) if pack is not None else (None, note)
    try:
        return linux_symbol_pack(path, banner), note
    except TableTooLarge as e:
        return None, f"{note}, but no pack was made of it: {e}"


def not_run(note: str) -> bool:
    """True when a vol() note says Volatility never looked at the image (the sandbox is down, the
    program could not be started, `where` is not a place), as against a plugin that ran and failed
    or ran out of time. A caller stops asking for more plugins after the first such note."""
    return note.startswith("sandbox down:") or " could not be run (" in note or note.startswith("where must be ")


def vol(image, plugin: str, args=(), where: str = "sandbox", timeout: float = 600.0, online: bool = False, symbols=None,
        start: bool = True) -> tuple:
    """(rows or None, note): one Volatility 3 plugin over an image file, rendered as JSON.

    symbols: the path of a `windows.zip` (or linux.zip, mac.zip) symbol pack, as fetch_isf() saves
    one. In the sandbox it is copied in beside the image and named as the symbol folder, so the
    Windows plugins work there with no network (checked on a real Windows XP image: pslist in 1.5 s).

    where="sandbox" (the default) runs it in the container of tools/sandbox.py: no network, so only
    plugins that need no symbol download work there (banners.Banners, yarascan, and anything whose
    symbols are already in the image's own pack); the image is copied in for each call. A sandbox
    that is down means not read; this never falls back to a native run by itself. The sandbox caps
    memory at 1g by default, which a heavy plugin on a multi-GB dump can exceed; raise it for the run
    with `CTF_SANDBOX_MEMORY=8g` (and `CTF_SANDBOX_CPUS=N`) — a dump is passive data, so this stays
    full isolation (network none, read-only root). Or use where="venv" for host RAM with no cap.
    where="venv" runs .venv/bin/vol on this machine, with --offline unless online=True (Windows
    plugins fetch the kernel's PDB from the Microsoft symbol server the first time: the caller's
    decision, never made on a clock). Never called by solve_set. That fetch is a public fetch (R-13):
    online=True with where="venv" needs the symbol server's host in the event profile's
    rules.public_fetch_allow, else ctf.scope.OutOfScope is raised before Volatility starts.

    start=False (sandbox only) never starts a container: when none that holds vol is up the note is
    'sandbox down: not started ...' and the image is not read. not_run(note) tells such a note (and
    a Volatility that could not be started) from a plugin that ran and failed."""
    image = Path(image)
    if online and where == "venv":
        scope.check_public_fetch(MS_SYMBOL_SERVER, purpose=f"memory.vol {plugin} --online (Volatility's PDB download)")
    argv = ["-q", "-r", "json"] + ([] if online or where == "sandbox" else ["--offline"])
    try:
        if where == "sandbox":
            sys.path.insert(0, str(ROOT / "tools")) if str(ROOT / "tools") not in sys.path else None
            import sandbox
            more = {} if start else {"start": False}
            try:
                if symbols:
                    # Volatility takes a folder; `{in1}/..` is the call's own drop folder once it has made the path absolute
                    r = sandbox.run("vol", ["-q", "-r", "json", "--offline", "-s", "{in1}/..", "-f", "{in0}", plugin, *args],
                                    inputs=[image, (Path(symbols).name, Path(symbols).read_bytes())], timeout=timeout, **more)
                else:
                    r = sandbox.run("vol", ["-q", "-r", "json", "--offline", "-f", "{in}", plugin, *args], inputs=[image],
                                    timeout=timeout, **more)
            except sandbox.SandboxDown as e:
                return None, f"sandbox down: {e}: the image is not read"
            code, so, se = r.code, r.stdout, r.stderr
        elif where == "venv":
            env = {k: v for k, v in os.environ.items() if k != "CTF_TOKEN"}
            if symbols:
                argv += ["-s", str(Path(symbols).resolve().parent)]
            p = subprocess.run([str(vol_bin()), *argv, "-f", str(image), plugin, *args], capture_output=True, timeout=timeout,
                               env=env, stdin=subprocess.DEVNULL)
            code, so, se = p.returncode, p.stdout, p.stderr
        else:
            return None, f"where must be sandbox or venv, not {where!r}"
    except subprocess.TimeoutExpired:
        return None, f"{plugin} took more than {timeout:g} s"
    except (OSError, ImportError) as e:
        return None, f"{plugin} could not be run ({type(e).__name__}: {e})"
    text = so.decode("utf-8", "replace")
    start = min((i for i in (text.find("["), text.find("{")) if i >= 0), default=-1)
    try:
        rows = json.loads(text[start:]) if start >= 0 else None
    except ValueError:
        rows = None
    if code != 0 or rows is None:
        why = (se.decode("utf-8", "replace").strip().splitlines() or text.strip().splitlines() or [f"exit {code}"])[-1]
        return None, f"{plugin} failed ({why[:200]})"
    return rows, f"{plugin}: {len(rows)} rows"


def fingerprint(data) -> str:
    """The name saved tables are kept under: the image's size and the SHA-256 of ALL its bytes. Two
    captures of one machine share their size and their first megabyte (the low physical memory), so
    a hash of the head would hand a timed variant the tables of the base."""
    return f"{len(data)}-{hashlib.sha256(data).hexdigest()}"


def tables_root() -> Path:
    import labels                       # the event workdir (ctf.paths.workdir()); no fallback folder
    return labels.challenges_root() / "_memory"


NO_SYMBOLS = ("banners.Banners",)       # plugins that need no symbol table (they read the bytes, not the kernel)
VOL_MIN_SLICE = 5.0                     # seconds: a plugin is not started with less than this left before `deadline`


def vol_save(image, family: str = "windows", where: str = "sandbox", online: bool = False, plugins=None, say=print, symbols=None,
             timeout: float = 600.0, deadline=None, clock=time.monotonic, start: bool = True, results=None) -> Path:
    """Run a family's plugins (PLUGINS) over an image and save each one's JSON as
    <challenges>/_memory/<fingerprint>/<plugin>.json, where build_model reads it back whenever a
    delivery holds the same image. Returns the folder. An --online venv run is refused up front
    (ctf.scope.OutOfScope) when the profile does not allow the symbol server (see vol()).

    symbols="auto" (the Linux family, B-136) matches the image's own banner to a local ISF before any
    plugin runs (linux_symbols_for: the image's folder and symbols_folder(); never a download). With
    no match the plugins that need a table are not started and each is said SKIP with the reason; the
    ones in NO_SYMBOLS still run.
    Nothing is retried blind: after the first note that says Volatility never looked at the image
    (not_run: the sandbox is down, the program is missing) the remaining plugins are said SKIP, and a
    1 GB image is not copied in once per plugin to fail the same way.
    deadline (a `clock()` value, default none) bounds the whole run: a plugin gets min(timeout, what
    is left) and one with less than VOL_MIN_SLICE left is said SKIP. start=False never starts a
    sandbox container. results, when a dict is passed, receives {plugin: (rows or None, note)} for
    every plugin, the skipped ones included."""
    image = Path(image)
    if online and where == "venv":
        scope.check_public_fetch(MS_SYMBOL_SERVER, purpose=f"memory.vol_save {family} --online (Volatility's PDB download)")
    h, size = hashlib.sha256(), 0
    with open(image, "rb") as f:
        for block in iter(lambda: f.read(1 << 22), b""):
            h.update(block)
            size += len(block)
    folder = tables_root() / f"{size}-{h.hexdigest()}"
    folder.mkdir(parents=True, exist_ok=True)
    no_table = ""
    if symbols == "auto":
        if family != "linux":
            raise ValueError(f"symbols='auto' matches a Linux ISF by the image's banner; the {family} family has none "
                             "(Windows: --symbols fetch, or a pack path)")
        symbols, note = linux_symbols_for(image)
        say(("OK   " if symbols else "FAIL ") + "symbols: " + note)
        no_table = "" if symbols else "no symbol table (ISF) for this kernel"
    more = {} if start else {"start": False}
    down = ""
    for plugin in plugins or PLUGINS[family]:
        left = timeout if deadline is None else min(timeout, deadline - clock())
        if down:
            skip = down
        elif no_table and plugin not in NO_SYMBOLS:
            skip = no_table
        elif left < VOL_MIN_SLICE:
            skip = f"no time left: {max(left, 0.0):.0f} s of the run's budget"
        else:
            skip = ""
        if skip:
            rows, note = None, f"{plugin} not run ({skip})"
            say("SKIP " + note)
        else:
            rows, note = vol(image, plugin, where=where, online=online, symbols=symbols, timeout=left, **more)
            if rows is None and not_run(note):
                down = note
            say(("OK   " if rows is not None else "FAIL ") + note)
            if rows is not None:
                (folder / f"{plugin}.json").write_text(json.dumps(rows))
        if results is not None:
            results[plugin] = (rows, note)
    return folder


# ---- the model of a delivery -------------------------------------------------------------------------

def _unique(files: dict) -> list:
    seen, out = set(), []
    for key in sorted(files, key=lambda k: (ARROW not in k, k)):
        data = files[key]
        if isinstance(data, (bytes, bytearray, memoryview)) and id(data) not in seen:
            seen.add(id(data))
            out.append((key.split(ARROW)[-1], data))
    return out


def _image_like(name: str, data) -> bool:
    if image_format(data):
        return True
    low = name.lower()
    return low.endswith(IMAGE_EXT) or bool(re.search(r"mem(?:ory)?[-_. ]?(?:dump|image|capture)|memdump|\bram\b", low))


def _heap_into_model(model: Model, name: str, core: dict, data, carve_max: int, deadline) -> None:
    """build_model's heap-chain carve of one ELF core, under the bounds of its other carving: a file
    over carve_max, or one reached after the deadline, is noted and not carved; the scan itself stops
    at the deadline. The whole result goes to model.heap[name], its best chain to model.recovered,
    its note (warnings included) to model.notes. A carve that fails on malformed bytes is a note,
    never an exception: the core's process facts are already in the model and must reach the caller."""
    if len(data) > carve_max:
        model.notes.append(f"{name}: {len(data)} bytes, more than {carve_max}: heap chains not carved here "
                           "(run memory.py --heap-chains on the file)")
        return
    if _late(deadline):
        model.notes.append(f"{name}: no time left to carve heap chains")
        return
    ff, why = _flag_format()
    try:
        chains = heap_chains(core, data, flag_format=ff, no_format_why=why, deadline=deadline)
    except struct.error as exc:
        model.notes.append(f"{name}: heap chain carve failed on malformed bytes (struct.error: {exc})")
        return
    model.heap[name] = chains
    if chains["best"]:
        b = chains["best"]
        model.recovered.append({"source": name, "shape": chains["shape"], "text": b["text"],
                                "head_va": b["head_va"], "regs": b["head_regs"], "is_flag": b["is_flag"],
                                "score": b["score"], "partial": bool(chains["partial"])})
    model.notes.append(f"{name}: {chains['note']}")


def build_model(files: dict, carve_max: int = CARVE_MAX, deadline=None, heap: bool = True) -> Model:
    """The Model of a delivery: its tables, its process images, what was saved for its images by
    vol_save, when no table names a process what the carvers find in images up to carve_max bytes
    (a larger image is noted and not carved: Volatility, off the clock), and the heap chains of its
    ELF cores (heap_chains). carve_max and the deadline bound the heap-chain carve too, and it runs
    last: under a deadline the process carvers, whose facts solve_set answers from, are never
    starved by it. heap=False leaves the heap chains out altogether (solve_set: it reads none of
    them)."""
    model = Model()
    raw, cores = [], []
    for name, data in _unique(files):
        fmt = image_format(data)
        if fmt or _image_like(name, data):
            model.images.append({"name": name, "format": fmt, "size": len(data)})
            saved = tables_root() / fingerprint(data)
            if saved.is_dir():
                for p in sorted(saved.glob("*.json")):
                    try:
                        read_tables(model, p.name, p.read_bytes(), "table")
                    except OSError:
                        pass
                model.notes.append(f"{name}: tables saved by vol_save read from {saved}")
        if fmt == "minidump":
            md = minidump(data)
            if md:
                pid = md["pid"] if md["pid"] is not None else -1
                model.add_proc(pid, "minidump", name=md["name"], args=md["cmdline"], create=md["create_time"])
                for r in md_injected(md):
                    model.regions.append({"pid": pid, "name": md["name"], "start": r["start"], "start_raw": None,
                                          "end": r["start"] + r["size"] - 1, "prot": r["protection"], "tag": None, "src": "minidump"})
                if md["system"].get("build"):
                    model.set_info("buildnumber", md["system"]["build"], "minidump")
                if md["time"]:
                    model.set_info("systemtime", md["time"], "minidump")
        elif fmt == "elf_core":
            core = elf_core(data)
            if core and core["pid"] is not None:
                model.add_proc(core["pid"], "elfcore", ppid=core["ppid"], name=core["name"], args=core["args"])
            if core:
                cores.append((name, core, data))
            raw.append((name, data))
        elif fmt in ("crashdump64", "crashdump32"):
            hdr = crashdump_header(data)
            if hdr:
                model.set_info("buildnumber", hdr["build"], "crashdump")
                if hdr["system_time"]:
                    model.set_info("systemtime", hdr["system_time"], "crashdump")
            raw.append((name, data))
        elif fmt or _image_like(name, data):
            raw.append((name, data))
        elif _text(data) is not None:
            read_tables(model, name, bytes(data))
        elif _tri().identify(bytes(data[:4096]), name) == "data":
            raw.append((name, data))        # bytes of no known kind: perhaps a raw image under another name
    listed = any(p["src"] in STRUCTURED for p in model.procs.values())
    if raw:
        for name, data in raw:
            if len(data) > carve_max:
                model.notes.append(f"{name}: {len(data)} bytes, more than {carve_max}: not carved here (run Volatility off the clock)")
                continue
            if deadline is not None and time.monotonic() > deadline:
                model.notes.append(f"{name}: no time left to carve")
                continue
            carve(model, data, name, procs=not listed, deadline=deadline)
    if heap:
        for name, core, data in cores:
            _heap_into_model(model, name, core, data, carve_max, deadline)
    return model


# ---- signals -----------------------------------------------------------------------------------------

_Q_STRONG = re.compile(r"memory (?:dump|image|capture|sample|forensic|snapshot|acquisition)|\bvolatility\b|\bmalfind\b|\bpslist\b|"
                       r"\bpstree\b|\bpsscan\b|\bnetscan\b|\beprocess\b|\bram (?:dump|image|capture)\b|\bprocess hollowing\b|"
                       r"\binjected (?:code|region|memory|into)\b|\bvad\b|\blime\b|\bminidump\b|\bcrash dump\b|\bcore dump\b", re.I)
_Q_WEAK = re.compile(r"\bpid\b|\bppid\b|\bparent process\b|\bprocess id\b|\bcommand[ -]line\b|\bprocess tree\b|\brunning process", re.I)


def signals(questions, files) -> float:
    """0..1: how strongly a delivery and its questions look like memory forensics. Cheap."""
    score = 0.0
    magic = named = table = False
    for name, data in _unique(files or {}):
        if image_format(data):
            magic = True
        elif _image_like(name, data):
            named = True
        else:
            head = bytes(data[:8192])
            if b"Volatility 3 Framework" in head or b"Volatility Foundation" in head:
                table = True
            elif re.search(rb"(?i)\bPID\b.{0,40}\bPPID\b|ImageFileName|ForeignAddr|Start VPN|\"__children\"|InheritedFromUniqueProcessId", head):
                table = True
    score += 0.6 if magic else 0.0
    score += 0.3 if named else 0.0
    score += 0.5 if table else 0.0
    strong, weak = set(), set()
    for q in questions or []:
        text = " ".join(str(q.get(k) or "") for k in ("question", "answer_id", "id", "artifact")).replace("_", " ").replace("-", " ")
        strong.update(m.group().lower() for m in _Q_STRONG.finditer(text))
        weak.update(m.group().lower() for m in _Q_WEAK.finditer(text))
    score += min(0.5, 0.25 * len(strong)) + min(0.2, 0.1 * len(weak))
    return round(min(1.0, score), 2)


# ---- what a question asks ---------------------------------------------------------------------------

FAMILIES = (
    ("cmdline", r"command[\s-]?line|\bcmdline\b|\barguments?\b|\bargs\b|\bwhat command\b|\bfull command\b"),
    ("parent", r"\bparent\b|\bppid\b|\bchild(?:ren)?\b|\b(?:which|what) process (?:spawned|launched|started|created)\b"),
    ("net", r"\bremote\b|\bforeign\b|\bdestination\b|\bpeer\b|\bc2\b|\bconnect\w*|\blisten\w*|\bports?\b|\bip(?:v4|v6)?\b|"
            r"\bsocket\b|\bnetwork\b|\bbeacon\w*|\bcall(?:s|ed|ing)? (?:out|back|home)\b"),
    ("inject", r"\binject\w*|\bmalfind\b|\brwx\b|\bshellcode\b|\bhollow\w*|\bexecute[_ ]readwrite\b"),
    ("user", r"\busers?(?:name)?\b|\baccount\b|\bsid\b|\bwho (?:ran|launched|started|owns|executed)\b|\blogged[\s-]?(?:in|on)\b"),
    ("host", r"\bhost\s?name\b|\bcomputer\s?name\b|\bmachine name\b|\bname of the (?:host|machine|computer|system)\b"),
    ("os", r"\bkernel (?:version|release|banner)\b|\bos (?:version|build)\b|\bbuild (?:number|lab)\b|\boperating system\b|"
           r"\bwindows (?:version|build)\b|\blinux version\b"),
    ("format", r"\b(?:format|type) of the (?:memory )?(?:image|dump|capture|file)\b|\bdump (?:format|type)\b|\bimage format\b"),
    ("count", r"\bhow many\b|(?<!build )(?<!port )(?<!pid )(?<!id )\bnumber of\b|\bcount of\b"),
    ("time", r"\bwhen\b|\btime(?:stamp)?\b|\bdate\b"),
    ("proc", r"\bpid\b|\bprocess(?:es)?\b|\bimage (?:file )?name\b|\bexecutable\b"),
)
_FAM = [(name, re.compile(rx, re.I)) for name, rx in FAMILIES]
_SEL_PID = re.compile(r"\b(?:pid|process id|process identifier|process with id)\s*(?:of|is|=|:|#)?\s*`?(\d{1,7})\b", re.I)
_SEL_EXE = re.compile(r"(?<![\w.\\/-])([\w$~+-]+(?:\.[\w$~+-]+)*\.(?:exe|dll|scr|com|bat|ps1|sys))(?![\w-])", re.I)
_SEL_PORT = re.compile(r"\bport\s+`?(\d{1,5})\b", re.I)
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
_FILTER = re.compile(r"\b(?:that|which|whose|with|where|named|except|excluding|other than|more|less|than|hidden|terminated|exited|"
                     r"suspicious|malicious|unique|distinct|different|unusual|unsigned|legitimate)\b", re.I)
# A phrase that moves the question to another process than the one it names ("the process spawned by
# PID 4"), and verbs the catch-all `proc` family does not read: such a question is not answered.
_RELATION = re.compile(r"\b(?:spawned|launched|started|created|executed|run|ran|injected|dropped|loaded|downloaded|written|opened|"
                       r"used|killed|terminated) by\b|\bgrand\w+|\bsibling", re.I)
_PROC_VERBS = re.compile(r"\b(?:spawn|launch|start|creat|execut|inject|connect|download|drop|writ|wrote|open|load|kill|terminat|access|"
                         r"read|hid|hollow|migrat|escalat)\w*|\bran\b|\brun\b", re.I)
# Properties this file does not read. A question that names one is about something else than the
# family words in it suggest ("the parent directory of evil.exe", "how many threads does X have").
_UNREAD = re.compile(r"\b(?:directory|folder|registry|dlls?|modules?|handles?|mutex\w*|threads?|services?|drivers?|privileges?|token|"
                     r"integrity|session|window|title|signature|signed|entropy|priority|wow64|architecture|bitness|path|md5|"
                     r"sha-?\d+|hash\w*|size|bytes|time ?zone|uptime|strings?|yara|rule|password|flag)\b", re.I)
_REMOTE = re.compile(r"\bremote\b|\bforeign\b|\bdestination\b|\bpeer\b|\bc2\b|\bconnect\w* to\b|\bbeacon\w*|\bcall\w* (?:out|back|home)\b|"
                     r"\bcommunicat\w* with\b|\boutbound\b|\bexternal\b|\bcommand[ -]and[ -]control\b", re.I)
_COUNTED = re.compile(r"\b(?:how many|number of|count of)\s+((?:\S+\s+){0,3}?)process(?:es)?\b", re.I)
_COUNT_FILL = {"running", "active", "total", "the", "of", "listed", "live", "all", "are", "were"}
_NO_PEER = {"", "0.0.0.0", "::", "*", "-", "127.0.0.1", "::1", "0", "none", "n/a"}


# The words a question may hold and still be answered plain. A plain answer says the question was read
# whole: one word outside this list ("after", "whose", "as", "offset", "second", "not") and the fact is
# offered unsure at best, and a count is not answered at all.
_VOCAB = frozenset("""
what which who whom is was are were be been the a an of in on at to for this these it its there here and or
did does do has have had give provide enter answer state report find identify please using use that
crashed given provided attached analysed analyzed
name named called process processes program executable image binary pid ppid id identifier number numeric
parent child children spawned launched started created how many count total running active listed list
shown show shows showed appear appears present found seen contain contains contained
memory dump dumped image capture captured snapshot sample file evidence artifact system machine host computer
pslist pstree psscan netscan netstat malfind cmdline volatility output table listing
command line full complete arguments argument args with
remote foreign destination peer c2 ip ipv4 ipv6 address port ports connect connects connected connecting
connection connections network socket local listen listens listening protocol outbound external
beacon beacons beaconing communicate communicates communicating
injected injection inject code region memory start starting base protection protections permission permissions rwx
shellcode
user username account sid owner owns owned ran logged
hostname computername build lab kernel version release os operating windows linux banner
when time timestamp date utc created creation started exit exited terminated
acquired taken collected made written
format type decimal integer hex hexadecimal lowercase uppercase value
""".split())
_HINT = re.compile(r"\bas (?:an? )?(?:decimal |whole |plain |single )?(?:integer|number|decimal|hex(?:adecimal)?(?: value| string)?)\b|"
                   r"\bin (?:decimal|hex(?:adecimal)?|utc|lowercase|uppercase)\b", re.I)
_FILE_TOKEN = re.compile(r"(?<![\w.])[\w$~+-]+(?:\.[\w$~+-]+)+(?![\w])")
_KIN = re.compile(r"\bparents?\b|\bppid\b|\bchild(?:ren)?\b", re.I)


def understood(text: str, names=()) -> bool:
    """True when every word of the question is one this file reads: what is left of the text once the
    selector (a PID, a process name, an address, a port), quoted text, file names and a format hint
    ("as an integer") are taken out holds only words of _VOCAB."""
    t = _HINT.sub(" ", text)
    t = _SEL_PID.sub(" ", t)
    t = _SEL_PORT.sub(" port ", t)
    t = re.sub(r"`[^`]{0,80}`|\"[^\"]{0,80}\"|“[^”]{0,80}”", " ", t)
    t = _IPV4.sub(" ", t)
    t = _FILE_TOKEN.sub(" ", t)
    for n in names:
        t = re.sub(r"(?<![\w.-])" + re.escape(n) + r"(?![\w.-])", " ", t, flags=re.I)
    t = re.sub(r"['’]s\b", " ", t)
    return all(w in _VOCAB for w in re.findall(r"[a-z][a-z0-9]*", t.lower()))


def ask(text: str) -> tuple:
    """(family, set of all families matched) for a question text; family is None when the question
    is of no family or of two that this file does not combine."""
    hit = {name for name, rx in _FAM if rx.search(text)}
    core = hit - {"proc"}
    if not core:
        return ("proc" if "proc" in hit else None), hit
    if core == {"time"}:
        return "time", hit
    if "count" in core:
        rest = core - {"count", "time"}
        if len(rest) <= 1 and "time" not in core:
            return "count", hit
        return None, hit
    if "time" in core:
        rest = core - {"time"}
        return ("time" if rest <= {"net"} else None), hit
    return (next(iter(core)) if len(core) == 1 else None), hit


def _fmt(q) -> dict:
    f = q.get("answer_format")
    return f if isinstance(f, dict) else {}


_CANARY = ("Some Value.exe", "some_value", "12345", "10.0.0.1", "0x1f0000", "2024-01-01T00:00:00Z")


def _narrowing(q) -> bool:
    """The question's own format says something: a pattern that refuses at least one ordinary value,
    or a list of options."""
    f = _fmt(q)
    rx = f.get("pattern") or f.get("regex")
    if isinstance(rx, str) and rx.strip():
        try:
            if any(re.fullmatch(rx, c) is None for c in _CANARY):
                return True
        except re.error:
            return False
    return bool(_tri().enum_options(q))


def decide(q, field: str, src: str, options: list, proven: bool):
    """The answer for an established fact with its renderings [(method, value), ...], best first.
    Plain only when the fact is proven (a structured source, one consistent value) and the question's
    own format leaves one rendering: an integer answer, or one survivor of its pattern or options."""
    tri = _tri()
    f = _fmt(q)
    kind = str(f.get("kind") or "")
    if kind in ("mitre_attack_id", "ordered_tokens", "json"):
        return None
    enum = tri.enum_options(q)
    opts, seen = [], set()
    for method, value in options:
        if value is None:
            continue
        value = str(value)
        if value == "" or value in seen or not tri._fits(q, value) or (enum and value not in enum):
            continue
        seen.add(value)
        opts.append((method, value))
    if not opts:
        return None
    if proven and len(opts) == 1:
        v = opts[0][1]
        if (kind == "integer" and re.fullmatch(r"\d+", v)) or _narrowing(q):
            return v
    return pick(f"{KEY}.{field}/{src}", opts)


def name_options(name: str) -> list:
    stem = re.sub(r"\.(?:exe|dll|sys|scr|com)$", "", name, flags=re.I)
    return [("as_listed", name), ("lower", name.lower()), ("no_ext", stem), ("lower_no_ext", stem.lower())]


def time_options(value, syntax: str = "") -> list:
    d = when(value)
    if d is None:
        return [("as_listed", str(value).strip())] if isinstance(value, str) and value.strip() else []
    d = d.replace(microsecond=0)
    opts = [("iso_z", d.strftime("%Y-%m-%dT%H:%M:%SZ")), ("space", d.strftime("%Y-%m-%d %H:%M:%S"))]
    if isinstance(value, str):
        opts.append(("as_listed", value.strip()))
    opts += [("iso_offset", d.strftime("%Y-%m-%dT%H:%M:%S+00:00")), ("space_utc", d.strftime("%Y-%m-%d %H:%M:%S UTC")),
             ("iso", d.strftime("%Y-%m-%dT%H:%M:%S")), ("epoch", str(int(d.replace(tzinfo=UTC).timestamp())))]
    if re.search(r"\bepoch\b|\bunix\b", syntax, re.I):
        opts.sort(key=lambda o: o[0] != "epoch")
    return opts


def zoned(value) -> bool:
    """Does a time say its zone? A datetime read from a structure (UTC by its format) or a cell with
    Z, UTC or an offset. A cell with none is offered as UTC, unsure: the bytes do not say."""
    if isinstance(value, _dt.datetime):
        return True
    return re.search(r"(?:Z|UTC(?:[+-]0{4})?|[+-]\d{2}:?\d{2})\s*$", str(value).strip()) is not None


def addr_options(value: int, raw=None) -> list:
    opts = [("hex_0x", f"0x{value:x}")]
    if isinstance(raw, str) and raw.strip():
        opts.append(("as_listed", raw.strip()))
    return opts + [("hex_0x_16", f"0x{value:016x}"), ("hex", f"{value:x}"), ("hex_0x_upper", f"0x{value:X}"), ("decimal", str(value))]


def prot_options(prot: str) -> list:
    p = prot.strip()
    opts = [("snake", re.sub(r"[^a-z0-9]+", "_", p.lower()).strip("_")), ("as_listed", p)]
    if p.upper() in PROT_SHORT:
        opts.append(("short", PROT_SHORT[p.upper()]))
    return opts


def text_options(value: str) -> list:
    v = str(value).strip()
    return [("as_listed", v), ("lower", v.lower())]


def _one(values):
    """The single distinct value of a list with no gap in it, else None."""
    values = list(values)
    if not values or any(v is None for v in values):
        return None
    distinct = set(values)
    return values[0] if len(distinct) == 1 else None


class _Q:
    """One question against one model: the selector it names and the rows that selector picks."""

    def __init__(self, q, model: Model):
        self.q, self.m = q, model
        self.text = " ".join(str(q.get("question") or "").split())
        self.low = _SEL_PID.sub(" ", self.text).lower()      # the text without "PID 1234": what is asked, not what is given
        self.kind = str(_fmt(q).get("kind") or "")
        self.syntax = str(_fmt(q).get("syntax") or "")
        self.family, self.hit = ask(self.text)
        self.ok = True
        self.sel_pid = [int(v) for v in dict.fromkeys(m.group(1) for m in _SEL_PID.finditer(self.text))]
        self.ips = list(dict.fromkeys(_IPV4.findall(self.text)))
        self.ports = [int(v) for v in dict.fromkeys(_SEL_PORT.findall(self.text))]
        names = {}
        for p in model.procs.values():
            if isinstance(p.get("name"), str):
                names.setdefault(p["name"].lower(), []).append(p["pid"])
        for c in model.conns + model.regions:
            if isinstance(c.get("name"), str) and c.get("pid") is not None:
                names.setdefault(c["name"].lower(), [])
                if c["pid"] not in names[c["name"].lower()]:
                    names[c["name"].lower()].append(c["pid"])
        self.names = names
        named = [m.group(1).lower() for m in _SEL_EXE.finditer(self.text)]
        for n in names:                 # a name with no extension counts only when the text marks it as one
            if n not in named and re.search(r"(?:[`'\"]" + re.escape(n) + r"[`'\"]|\bprocess(?: named| called)? " + re.escape(n)
                                            + r"(?![\w.-])|(?<![\w.-])" + re.escape(n) + r" process\b)", self.text, re.I):
                named.append(n)
        self.sel_names = list(dict.fromkeys(named))
        if any(n not in names for n in self.sel_names) or len(self.sel_names) > 1 or len(self.sel_pid) > 1:
            self.ok = False             # a process this delivery does not list, or two of them

    def selector(self):
        """A pattern for the selector as the text writes it (the name, or "PID 1234"), or None."""
        if self.sel_names:
            return r"[`'\"“‘]?" + re.escape(self.sel_names[0]) + r"[`'\"”’]?"
        m = _SEL_PID.search(self.text)
        return re.escape(m.group(0)) if m else None

    def kin(self, word: str) -> bool:
        """Is the selected process the one whose parent (word 'parent') or whose children ('child')
        are asked for? "the parent of X", "X's parent", "which process spawned X"; "the child of X",
        "X's children", "how many children does X have". Anything else ("X is a child of which
        process", "whose parent is X", "the PPID of the parent of X") is not answered."""
        if len(_KIN.findall(self.text)) > 1:
            return False
        sel = self.selector()
        if sel is None:
            return True                 # one process in the delivery: nothing to point the wrong way
        of = r"\s+(?:of|for)\s+(?:the\s+)?(?:process\s+)?(?:(?:named|called|with)\s+)?(?:the\s+)?"
        if word == "parent":
            rx = (r"\b(?:parent|ppid)\b(?:\s+(?:process id|process name|image name|process|pid|id|name))?" + of + sel
                  + r"|" + sel + r"(?:'s|’s)\s+(?:\w+\s+){0,2}?(?:parent|ppid)\b"
                  + r"|\b(?:which|what) process (?:spawned|launched|started|created)\s+(?:the\s+)?(?:process\s+)?" + sel)
        else:
            rx = (r"\bchild(?:ren)?\b(?:\s+process(?:es)?)?" + of + sel
                  + r"|" + sel + r"(?:'s|’s)\s+(?:\w+\s+){0,2}?child"
                  + r"|\bchild(?:ren)?\b(?:\s+process(?:es)?)?\s+(?:does|did|do|has|have)\s+(?:the\s+)?(?:process\s+)?" + sel
                  + r"\s+(?:have|had|has|spawn|launch|start|create)\b")
        return re.search(rx, self.text, re.I) is not None

    def pids(self):
        """The PIDs the question's selector picks, or None when it names nothing usable."""
        if not self.ok:
            return None
        by_name = set(self.names[self.sel_names[0]]) if self.sel_names else None
        by_pid = set(self.sel_pid) if self.sel_pid else None
        if by_pid is not None and by_name is not None:
            got = by_pid & by_name
        else:
            got = by_pid if by_pid is not None else by_name
        if got is None and len(self.m.procs) == 1:
            return set(self.m.procs)        # a process image: there is one process
        return got or None

    def proc_field(self, pids, field):
        """(value, source) of one field over the selected processes: one consistent value, no clash."""
        rows = [self.m.procs.get(p) for p in pids]
        if not rows or any(r is None for r in rows) or any((p, field) in self.m.clash for p in pids):
            return None, None
        v = _one([r.get(field) for r in rows])
        src = "carved" if any(r["src"] not in STRUCTURED for r in rows) else rows[0]["src"]
        return v, src


def _answer(q, model: Model, files):
    Q = _Q(q, model)
    fam, text, low = Q.family, Q.text, Q.low
    if fam is None or not Q.ok or _RELATION.search(text) or _UNREAD.search(_SEL_EXE.sub(" ", text)):
        return None
    if fam == "proc" and _PROC_VERBS.search(text):
        return None
    pid_word = re.search(r"\bpid\b|\bprocess id\b|\bprocess identifier\b", low) is not None
    wants_pid = Q.kind == "integer" or pid_word
    read = understood(text, Q.sel_names)
    plain_decide = globals()["decide"]

    def decide(q, field, src, options, proven):      # a question not read whole is never answered plain
        return plain_decide(q, field, src, options, proven and read)

    if fam == "format":
        fmts = {i["format"] for i in model.images}
        if len(model.images) != 1 or not fmts or "" in fmts:
            return None
        fmt = next(iter(fmts))
        return decide(q, "format", fmt, [(n, n) for n in FORMAT_NAMES.get(fmt, [])], False)

    if fam == "host":
        cands = [(model.info.get(k), model.info_src.get(k)) for k in ("hostname", "computername", "machinename", "nodename", "host")
                 if model.info.get(k)]
        env = {e["value"] for e in model.envars if e["var"].upper() in ("COMPUTERNAME", "HOSTNAME")}
        if cands or env:
            values = {str(v) for v, _ in cands} | env
            if len(values) != 1:
                return None
            return decide(q, "hostname", "table", text_options(values.pop()), True)
        carved = set(model.env.get("COMPUTERNAME", {})) or set(model.env.get("HOSTNAME", {}))
        return decide(q, "hostname", "carved", text_options(carved.pop()), False) if len(carved) == 1 else None

    if fam == "os":
        if re.search(r"\bbuild\b", low):
            vals = set()
            for k in ("buildnumber", "build", "ntbuildnumber", "osbuild", "osbuildnumber"):
                if model.info.get(k) is not None and re.fullmatch(r"\d{3,6}", str(model.info[k])):
                    vals.add(str(model.info[k]))
            lab = model.info.get("ntbuildlab")
            if isinstance(lab, str) and re.match(r"\d{3,6}\.", lab):
                vals.add(lab.split(".")[0])
            mm = model.info.get("majorminor")
            if isinstance(mm, str) and re.fullmatch(r"\d+\.\d{3,6}", mm):
                vals.add(mm.split(".")[1])
            if len(vals) != 1:
                return None
            if re.search(r"\bbuild lab\b", low):
                return decide(q, "build_lab", "table", [("as_listed", lab)], True) if isinstance(lab, str) else None
            return decide(q, "build", "table", [("number", vals.pop())], True)
        if re.search(r"\bkernel\b|\blinux version\b", low):
            vals = {str(model.info[k]) for k in ("kernelversion", "kernelrelease", "kernel", "release") if model.info.get(k)}
            for k in ("banner", "linuxbanner"):
                m = re.match(r"Linux version (\S+)", str(model.info.get(k) or ""))
                if m:
                    vals.add(m.group(1))
            if len(vals) == 1:
                return decide(q, "kernel", "table", [("release", vals.pop())], True)
            if not vals and len(model.banners) == 1:
                return decide(q, "kernel", "carved", [("release", next(iter(model.banners)))], False)
        return None

    if fam == "count":
        if not read or model.ragged or (_FILTER.search(text) and not (Q.sel_names or Q.sel_pid)):
            return None             # a count of what: only a question read whole says
        rest = Q.hit - {"count", "proc", "time"}
        if not rest:
            m = _COUNTED.search(text)
            if not m or any(w.strip("`'\"").lower() not in _COUNT_FILL | set(Q.sel_names) for w in m.group(1).split()):
                return None         # something else is counted (threads, connections, ...)
            if Q.sel_names and not Q.sel_pid:
                if not model.proc_tables or not _SEL_EXE.search(text):
                    return None     # "how many system processes" is not a count of the process named System
                counts = {sum(1 for p in t if str(model.procs.get(p, {}).get("name") or "").lower() == Q.sel_names[0]) for t in model.proc_tables}
                return decide(q, "count", "table", [("count", str(counts.pop()))], True) if len(counts) == 1 else None
            if Q.sel_pid or not model.proc_tables:
                return None
            sets = {frozenset(t) for t in model.proc_tables}
            if len(sets) != 1 or any(len(t) != len(set(t)) for t in model.proc_tables):
                return None         # pslist and psscan disagree, or a PID is listed twice: which count is the author's
            return decide(q, "count", "table", [("count", str(len(next(iter(sets)))))], True)
        if rest == {"parent"} and re.search(r"\b(?:how many|number of|count of)\s+(?:\w+\s+)?child(?:ren)?\b", low):
            pids = Q.pids()
            if not pids or len(pids) != 1 or not model.proc_tables or any(p["src"] not in STRUCTURED for p in model.procs.values()):
                return None
            if len({frozenset(t) for t in model.proc_tables}) != 1 or not Q.kin("child"):
                return None         # two listings that differ, or the question points the other way
            kids = [p for p in model.procs.values() if p.get("ppid") in pids]
            return decide(q, "count", "table", [("count", str(len(kids)))], True)
        return None

    if fam == "inject":
        regions = model.regions
        pids = Q.pids()
        if Q.sel_names or Q.sel_pid:
            if not pids:
                return None
            regions = [r for r in regions if r["pid"] in pids]
        if not regions:
            return None
        src = _one([r["src"] for r in regions]) or "table"
        if re.search(r"\bprotect\w*|\bpermission", low):
            prot = _one([r["prot"] for r in regions])
            return decide(q, "protection", src, prot_options(prot), True) if prot else None
        asks_proc = re.search(r"\b(?:which|what) process\b|\bpid\b|\bprocess id\b|\bname of the process\b|\bprocess name\b", low) is not None
        if re.search(r"\baddress\b|\bbase\b|\bstart\w*\b|\boffset\b|\bwhere\b|\bvpn\b", low):
            if asks_proc:
                return None
            start = _one([r["start"] for r in regions])
            if start is None:
                return None
            return decide(q, "region_start", src, addr_options(start, _one([r.get("start_raw") for r in regions])), True)
        if Q.sel_names or Q.sel_pid or not asks_proc:
            return None
        owners = {r["pid"] for r in regions}
        if len(owners) != 1 or None in owners:
            return None
        pid = next(iter(owners))
        if pid < 0:
            return None
        if wants_pid:
            return decide(q, "pid", src, [("decimal", str(pid))], True)
        name, psrc = Q.proc_field({pid}, "name")
        name = name or _one([r["name"] for r in regions])
        return decide(q, "process_name", src, name_options(str(name)), True) if name else None

    if fam == "net" or (fam == "time" and "net" in Q.hit):
        conns = model.conns
        if not conns:
            return None
        pids = Q.pids() if (Q.sel_names or Q.sel_pid) else None
        if (Q.sel_names or Q.sel_pid) and not pids:
            return None
        if pids:
            conns = [c for c in conns if c["pid"] in pids or (c["pid"] is None and str(c.get("name") or "").lower() in Q.sel_names)]
        if Q.ips:
            if len(Q.ips) != 1:
                return None
            conns = [c for c in conns if str(c.get("raddr")) == Q.ips[0] or str(c.get("laddr")) == Q.ips[0]]
        if Q.ports:
            if len(Q.ports) != 1:
                return None
            conns = [c for c in conns if Q.ports[0] in (c.get("rport"), c.get("lport"))]
        if not conns:
            return None
        asks_port = re.search(r"\bports?\b", low) is not None and not Q.ports
        local = re.search(r"\blocal\b|\blisten\w*|\bsource\b|\bsrc\b|\bbound\b|\bbind\w*", low) is not None
        outbound = [c for c in conns if str(c.get("raddr") or "").strip().lower() not in _NO_PEER]
        if fam == "time":
            created = _one([c.get("created") for c in (outbound or conns)])
            return decide(q, "conn_time", "table", time_options(created, Q.syntax), zoned(created)) if created else None
        if re.search(r"\bprotocol\b", low):
            proto = _one([c.get("proto") for c in conns])
            return decide(q, "protocol", "table", text_options(proto)[::-1], True) if proto else None
        if (Q.ips or Q.ports) and not asks_port and re.search(r"\b(?:which|what) process\b|\bpid\b|\bprocess id\b|\bname of the process\b|"
                                                             r"\bprocess (?:that|which)\b|\bwhat program\b|\bwhich program\b", low):
            owner = _one([c["pid"] for c in conns])
            if wants_pid:
                return decide(q, "pid", "table", [("decimal", str(owner))], True) if owner is not None else None
            name = _one([c.get("name") for c in conns])
            if owner is not None:
                pname, _ = Q.proc_field({owner}, "name")
                if pname and name and str(pname).lower() != str(name).lower() and not str(pname).lower().startswith(str(name).lower()):
                    return None
                name = pname or name
            return decide(q, "process_name", "table", name_options(str(name)), True) if name else None
        if asks_port:
            if local:
                port = _one([c.get("lport") for c in conns])
                return decide(q, "local_port", "table", [("decimal", str(port))], True) if port else None
            if not _REMOTE.search(text):
                return None         # "which port does X use": local or remote is the author's
            port = _one([c.get("rport") for c in outbound])
            return decide(q, "remote_port", "table", [("decimal", str(port))], True) if port else None
        if Q.ips or local:
            return None
        if not _REMOTE.search(text) or re.search(r"\bdomain\b|\burl\b|\bcountry\b", low):
            return None             # "the IP address of the machine" is not its peer
        peer = _one([str(c["raddr"]).strip() for c in outbound])
        return decide(q, "remote_ip", "table", [("as_listed", peer)], True) if peer else None

    pids = Q.pids()

    if fam == "user":
        if not (Q.sel_names or Q.sel_pid) and len(model.procs) != 1:
            vals = {str(model.info[k]) for k in ("username", "user", "loggedinuser", "loggedonuser", "account") if model.info.get(k)}
            if len(vals) == 1:
                return decide(q, "user", "table", _user_options(vals.pop()), True)
            carved = {v for v in model.env.get("USERNAME", {}) if v.upper() not in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
                      and not v.endswith("$")} or set(model.env.get("USER", {})) or set(model.env.get("LOGNAME", {}))
            if not vals and not model.envars and len(carved) == 1:
                return decide(q, "user", "carved", _user_options(carved.pop()), False)
            return None
        if not pids:
            return None
        if re.search(r"\bsid\b", low):
            sid = _first_sid(model, pids, "sid")
            return decide(q, "sid", "table", [("as_listed", sid)], True) if sid else None
        user, src = Q.proc_field(pids, "user")
        if user:
            return decide(q, "user", src, _user_options(str(user)), src in STRUCTURED)
        envs = [{e["value"] for e in model.envars if e["pid"] == p and e["var"].upper() in ("USERNAME", "USER", "LOGNAME")} for p in pids]
        if envs and all(len(s) == 1 for s in envs) and len(set.union(*envs)) == 1:
            return decide(q, "user", "table", _user_options(next(iter(envs[0]))), True)
        if any(envs):
            return None
        name = _first_sid(model, pids, "name")
        return decide(q, "user", "table", _user_options(name), True) if name else None

    if fam == "cmdline":
        if not pids:
            return None
        args, src = Q.proc_field(pids, "args")
        if not args:
            return None
        args = str(args)
        opts = [("as_listed", args.strip()), ("collapsed", " ".join(args.split()))]
        return decide(q, "cmdline", src, opts, src in STRUCTURED)

    if fam == "parent":
        if not pids:
            return None
        if re.search(r"\bchild", low):
            if len(pids) != 1 or any(p["src"] not in STRUCTURED for p in model.procs.values()) or not Q.kin("child"):
                return None
            kids = [p for p in model.procs.values() if p.get("ppid") in pids]
            if len(kids) != 1 or (kids[0]["pid"], "ppid") in model.clash:
                return None
            if wants_pid:
                return decide(q, "pid", "table", [("decimal", str(kids[0]["pid"]))], True)
            return decide(q, "process_name", "table", name_options(kids[0]["name"]), True) if kids[0].get("name") else None
        ppid, src = Q.proc_field(pids, "ppid")
        if ppid is None or not Q.kin("parent"):
            return None
        if wants_pid or re.search(r"\bppid\b", low):
            return decide(q, "ppid", src, [("decimal", str(ppid))], src in STRUCTURED)
        name, nsrc = Q.proc_field({ppid}, "name")
        if not name:
            return None
        src = "carved" if "carved" in (src, nsrc) else nsrc
        return decide(q, "process_name", src, name_options(str(name)), src in STRUCTURED)

    if fam == "time":
        if Q.sel_names or Q.sel_pid or (len(model.procs) == 1 and re.search(r"\bprocess\b|\bstart|\bcreat|\blaunch", low)):
            if not pids:
                return None
            if not re.search(r"\bstart\w*|\bcreat\w*|\blaunch\w*|\bspawn\w*|\bbeg[ai]n\w*|\bexecut\w*|\brun\b|\bran\b|\bexit\w*|\bterminat\w*|"
                             r"\bend(?:ed)?\b", low):
                return None
            field = "exit" if re.search(r"\bexit\w*|\bterminat\w*|\bend(?:ed)?\b", low) else "create"
            v, src = Q.proc_field(pids, field)
            return decide(q, f"{field}_time", src, time_options(v, Q.syntax), src in STRUCTURED and zoned(v)) if v else None
        if "proc" in Q.hit or not re.search(r"\bcaptur\w*|\bacquir\w*|\btaken\b|\bcollect\w*|\bsystem time\b|\b(?:image|dump|snapshot) "
                                            r"(?:was )?(?:made|created|written)\b", low):
            return None
        v = model.info.get("systemtime") or model.info.get("capturetime") or model.info.get("capturedat") or model.info.get("imagetime")
        return decide(q, "system_time", "table", time_options(v, Q.syntax), zoned(v)) if v else None

    if fam == "proc":
        if not pids:
            return None
        if Q.sel_pid and not Q.sel_names and not re.search(r"\bname\b|\b(?:which|what) process\b|\bexecutable\b|\bimage\b|\bprogram\b|\bbelong", low):
            return None
        if Q.sel_names and not Q.sel_pid:
            if not pid_word or len(pids) != 1:
                return None         # an integer about a named process is not its PID unless the question says so
            src = model.procs[next(iter(pids))]["src"] if next(iter(pids)) in model.procs else "table"
            pid = next(iter(pids))
            return decide(q, "pid", src, [("decimal", str(pid))], src in STRUCTURED) if pid >= 0 else None
        if Q.sel_pid and Q.sel_names:
            return None
        if not Q.sel_pid:
            if len(model.procs) != 1:
                return None
            if pid_word:
                pid = next(iter(pids))
                return decide(q, "pid", model.procs[pid]["src"], [("decimal", str(pid))], True) if pid >= 0 else None
            if Q.kind == "integer":
                return None
        name, src = Q.proc_field(pids, "name")
        return decide(q, "process_name", src, name_options(str(name)), src in STRUCTURED) if name else None
    return None


def _user_options(user: str) -> list:
    u = str(user).strip()
    bare = re.split(r"[\\/]", u)[-1]
    return [("as_listed", u), ("no_domain", bare), ("lower", u.lower()), ("lower_no_domain", bare.lower())]


def _first_sid(model: Model, pids, field):
    """The first getsids row of each selected process (its user; the groups follow), one value."""
    firsts = []
    for p in pids:
        rows = [s for s in model.sids if s["pid"] == p]
        firsts.append(rows[0].get(field) if rows else None)
    v = _one(firsts)
    return str(v).strip() if v is not None and str(v).strip() not in ("", "-") else None


# ---- the runner contract ---------------------------------------------------------------------------

def solve_set(questions, files, ctx) -> dict:
    out = {q.get("qid") or q.get("id"): None for q in questions}
    try:
        if signals(questions, files) < GATE:
            return out
        # heap=False: nothing below reads Model.heap or Model.recovered (a flag is not one of this
        # lane's answers), so the 0.6 s belongs to the tables and the process carvers
        model = build_model(files, deadline=time.monotonic() + 0.6, heap=False)
    except Exception:           # what cannot be read is not answered
        return out
    if isinstance(ctx, dict):
        ctx["partial"] = out
    tri = _tri()
    for q in questions:
        qid = q.get("qid") or q.get("id")
        try:
            got = _answer(q, model, files)
            out[qid] = got if got is not None else tri.answer(q, files, ctx)
        except Exception:
            out[qid] = None
    return out


# ---- the command ------------------------------------------------------------------------------------

def report(paths, carve_max: int = CARVE_MAX_CLI) -> str:
    """The command's triage of the files at `paths` (report_text of their bytes)."""
    files = {}
    for p in paths:
        files[Path(p).name] = Path(p).read_bytes()
    return report_text(files, carve_max)


def report_text(files: dict, carve_max: int = CARVE_MAX_CLI) -> str:
    """The triage text of {name: bytes}: per file its format facts (an ELF core's process, registers
    and ranked heap chains among them), then the model built from all of them."""
    model = build_model(files, carve_max=carve_max)     # first: each core's heap carve is done once, there
    lines = []
    for name, data in files.items():
        fmt = image_format(data)
        lines.append(f"== {name}: {len(data)} bytes, sha256 {hashlib.sha256(data).hexdigest()}, format {fmt or 'not told by the bytes (raw, or a table)'}")
        if fmt in ("lime", "avml"):
            for s in lime_segments(data)[:20]:
                lines.append(f"   range 0x{s['start']:x}-0x{s['end']:x} at file offset {s['offset']} (version {s['version']})")
        elif fmt == "minidump":
            md = minidump(data)
            lines.append(f"   process {md['name']} pid {md['pid']} created {md['create_time']} dumped {md['time']} system {md['system']}")
            lines.append(f"   image path {md['image_path']!r} command line {md['cmdline']!r}")
            lines.append(f"   {len(md['modules'])} modules: " + ", ".join(str(m['name']) for m in md["modules"][:12]))
            for r in md_injected(md)[:20]:
                lines.append(f"   private executable+writable region 0x{r['start']:x} size 0x{r['size']:x} {r['protection']}")
        elif fmt == "elf_core":
            c = elf_core(data)
            if c:
                lines += _core_lines(c, model.heap.get(name))
        elif fmt.startswith("crashdump"):
            h = crashdump_header(data)
            lines.append("   " + ", ".join(f"{k}={(hex(v) if isinstance(v, int) and v > 0xFFFF else v)}" for k, v in h.items() if k != "bugcheck_parameters"))
    lines.append(f"== model: {len(model.procs)} processes, {len(model.conns)} connections, {len(model.regions)} regions, "
                 f"{len(model.envars)} environment rows, {len(model.sids)} sid rows, {len(model.info)} info values; signals {signals([], files)}")
    for n in model.notes:
        lines.append(f"NOTE {n}")
    for rec in model.recovered:
        lines.append(f"recovered(heap chain) from {rec['source']} 0x{rec['head_va']:x}"
                     + (" regs " + "/".join(rec["regs"]) if rec["regs"] else "")
                     + (" FLAG " if rec["is_flag"] else " ") + repr(rec["text"])
                     + (" (PARTIAL carve)" if rec["partial"] else ""))
    for p in sorted(model.procs.values(), key=lambda p: p["pid"])[:400]:
        clash = ",".join(sorted(f for (pid, f) in model.clash if pid == p["pid"]))
        lines.append(f"proc pid={p['pid']} ppid={p.get('ppid')} name={p.get('name')!r} create={p.get('create')} src={p['src']}"
                     + (f" args={p['args']!r}" if p.get("args") else "") + (f" CLASH({clash})" if clash else ""))
    for c in model.conns[:200]:
        lines.append(f"conn pid={c['pid']} {c.get('name')} {c.get('proto')} {c.get('laddr')}:{c.get('lport')} -> {c.get('raddr')}:{c.get('rport')} "
                     f"{c.get('state') or ''} {c.get('created') or ''}".rstrip())
    for r in model.regions[:200]:
        lines.append(f"region pid={r['pid']} {r.get('name')} 0x{r['start']:x} {r.get('prot')} src={r['src']}")
    for k, v in sorted(model.info.items()):
        if v is not None:
            lines.append(f"info {k}={v!r}")
    for var, values in sorted(model.env.items()):
        lines.append(f"env(carved) {var}: " + ", ".join(f"{v!r} x{n}" for v, n in values.most_common(6)))
    for h in model.history[:400]:
        lines.append(f"history pid={h['pid']} {h.get('name') or ''} {h.get('time') or ''} {h['command']!r} src={h['src']}")
    for b, n in model.banners.most_common(4):
        lines.append(f"banner(carved) Linux version {b} x{n}")
    for b, n in model.kernel_banners.most_common(2):
        lines.append(f"banner(carved, whole: what names the kernel's ISF) {b} x{n}")
    for name, data in files.items():
        if _image_like(name, data) and len(data) <= carve_max:
            for c, n in carve_cmdlines(data).most_common(25):
                lines.append(f"cmdline(carved, no PID) x{n} {c}")
    return "\n".join(lines)


def main(argv) -> int:
    if "--plan" in argv:
        try:
            index = argv.index("--plan")
            value = argv[index + 1] if index + 1 < len(argv) and not argv[index + 1].startswith("--") else "credentials,console,files,injection"
            objectives = tuple(part.strip() for part in value.split(",") if part.strip())
            result = volatility_plan(objectives)
            print(json.dumps(result, indent=2 if "--json" in argv else None))
            return 0
        except (TypeError, ValueError, OverflowError) as exc:
            print(f"memory: {exc}", file=sys.stderr)
            return 2
    if "--chain" in argv:
        try:
            index = argv.index("--chain")
            if index + 1 >= len(argv):
                raise ValueError("--chain requires a file or directory")
            root = Path(argv[index + 1])
            paths = sorted(root.rglob("*")) if root.is_dir() else [root]
            files = {}
            for path in paths:
                if not path.is_file():
                    continue
                if len(files) >= 256:
                    raise ValueError("carved-blob file count exceeds 256")
                if path.stat().st_size > 64 << 20:
                    raise ValueError(f"{path} exceeds the carved-blob cap")
                files[str(path)] = path.read_bytes()
            print(json.dumps(chain_carved_blobs(files), indent=2))
            return 0
        except (OSError, TypeError, ValueError, OverflowError) as exc:
            print(f"memory: {exc}", file=sys.stderr)
            return 2
    if "--heap-chains" in argv:
        try:
            cores = [a for a in argv if not a.startswith("--")]
            if not cores:
                raise ValueError("--heap-chains takes one or more ELF core files")
            print(heap_report(cores))
            return 0
        except (OSError, ValueError) as exc:
            print(f"memory: {exc}", file=sys.stderr)
            return 2
    flags = {"--vol": None, "--where": "sandbox", "--symbols": None}
    args, i = [], 0
    while i < len(argv):
        a = argv[i]
        if a in flags:
            if i + 1 >= len(argv):
                args = []
                break
            flags[a] = argv[i + 1]
            i += 2
            continue
        args.append(a)
        i += 1
    online = "--online" in args
    args = [a for a in args if not a.startswith("--")]
    if not args or any(not Path(a).is_file() for a in args) or (flags["--vol"] and flags["--vol"] not in PLUGINS):
        print("usage: memory.py <file>...\n       memory.py <image> --vol windows|linux|mac|any [--where sandbox|venv] [--online] [--symbols fetch|auto|PACK.zip]\n"
              "       memory.py <image> --pdb        the kernel's debug reference, read from the image's bytes\n"
              "       memory.py --heap-chains <core>...   an ELF core's registers and ranked heap record chains only\n"
              "       --symbols auto (linux): the local ISF whose banner is the image's, no download "
              "(vol_triage.py is the opener)", file=sys.stderr)
        return 2
    if "--pdb" in argv:
        import mmap
        with open(args[0], "rb") as f:
            refs = kernel_pdb(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ))
        for pdb, guid, age in refs:
            print(f"{pdb} {guid} {age}   symbol file: windows/{pdb}/{guid}-{age}.json.xz")
        if not refs:
            print("no Windows kernel debug reference in the image")
        return 0
    if flags["--vol"]:
        symbols = flags["--symbols"]
        if symbols == "fetch":
            # one outside request for one symbol file: asked for by name on the command line, never by solve_set
            import mmap
            with open(args[0], "rb") as f:
                refs = kernel_pdb(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ))
            if not refs:
                print("no Windows kernel debug reference in the image: no symbol file to fetch", file=sys.stderr)
                return 1
            try:
                symbols, note = fetch_isf(*refs[0])
            except scope.OutOfScope as e:
                print(f"memory.py: refused: {e}", file=sys.stderr)
                return 2
            print(("OK   " if symbols else "FAIL ") + note)
            if symbols is None:
                return 1
        try:
            folder = vol_save(args[0], flags["--vol"], where=flags["--where"], online=online, symbols=symbols)
        except scope.OutOfScope as e:
            print(f"memory.py: refused: {e}", file=sys.stderr)
            return 2
        except ValueError as e:             # --symbols auto on a family that has no banner-named table
            print(f"memory.py: {e}", file=sys.stderr)
            return 2
        print(f"saved under {folder}")
        return 0
    print(report(args))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
