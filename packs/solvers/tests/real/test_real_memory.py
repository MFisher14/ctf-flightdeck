#!/usr/bin/env python3
"""The memory toolkit on real dumps and real Volatility output (solvers/toolkits/memory.py).

  .venv/bin/python tests/real/test_real_memory.py

Offline. Three parts:

  1. Real Volatility 3 tables, tracked in tests/real/data_a/vol3-xp-laptop/ (always run): the JSON that
     `vol -r json` printed for Volatility's public test image win-xp-laptop-2005-06-25.img, made on
     2026-10-08 in the sandbox (no network) with the kernel's one symbol file, by
     `solvers/toolkits/memory.py <image> --vol windows --symbols fetch`. The toolkit reads them as a
     delivery of tables.
  2. Real minidumps and ELF cores (SKIPped when `challenges/_realdata/memory/` is absent; fetch_a.py fills
     it): rust-minidump's test dumps and pyelftools' test cores. Expected values: a struct reading of the
     minidump streams written out in this file (no library), and pyelftools' own reading of the cores.
  3. The 512 MB image itself (only when it is in the cache: `fetch_a.py --big`): the symbol-free carver
     against the Volatility tables of part 1. Every pslist process must be carved with its parent and its
     create time, and nothing may be carved that psscan does not also find.

Neither Huntress write-up repository holds a memory image, so there is no challenge drill for this toolkit.
CTF_TK_LIVE=1 with the sandbox up and the image and its symbol pack present runs windows.pslist again.
CTF_TK_NET=1 also fetches the symbol pack when it is missing, and only when the event profile's
rules.public_fetch_allow lists the Volatility mirror (downloads.volatilityfoundation.org): this test adds
nothing to the allow-list, and a refusal is a named failed check; without CTF_TK_NET=1 nothing is fetched.
"""
import json
import mmap
import os
import struct
import subprocess
import sys
import time
from datetime import datetime, timedelta

from _real_a import HERE, check, finish, is_plain, manifest, q, timed, values
import fetch_a

import memory as M     # noqa: E402  (_real_a put solvers/toolkits on the path)

def fetch_isf_live():
    """M.fetch_isf under CTF_TK_NET=1, held to the event profile as it stands (ctf.scope): the mirror is
    a public fetch, so it runs only when rules.public_fetch_allow lists it. A refusal is a failed check
    that names the reason (the host and the key to add), never a silent skip; returns (None, note)."""
    from ctf import scope
    try:
        return M.fetch_isf(*KERNEL)
    except scope.OutOfScope as e:
        check("live: the event profile allows the symbol mirror for CTF_TK_NET=1", False, str(e))
        return None, f"symbol pack fetch refused: {e}"


VOL = HERE / "data_a" / "vol3-xp-laptop"
D = fetch_a.cache_root() / "memory"
KERNEL = ("ntoskrnl.pdb", "32962337F0F646388B39535CD8DD70E8", 2)


def ask(files: dict, *questions):
    qs = [q(f"q{i}", t if isinstance(t, str) else t[1], "exact_text" if isinstance(t, str) else t[0], artifact=next(iter(files))) for i, t in enumerate(questions)]
    size = sum(len(v) for v in files.values())
    got, _ = timed("solve_set " + "+".join(files), lambda: M.solve_set(qs, files, {"partial": {}}), size)
    return [got.get(x["id"]) for x in qs]


def minidump_facts(data: bytes) -> dict:
    """PID, create time, build and module count from the stream directory, with struct alone."""
    out = {}
    if data[:4] != b"MDMP":
        return out
    count, rva = struct.unpack_from("<II", data, 8)
    for i in range(count):
        kind, size, at = struct.unpack_from("<III", data, rva + 12 * i)
        if kind == 15 and size >= 24:                   # MiscInfoStream
            flags, pid, created = struct.unpack_from("<III", data, at + 4)
            if flags & 1:
                out["pid"] = pid
            if flags & 2:
                out["created"] = datetime(1970, 1, 1) + timedelta(seconds=created)
        elif kind == 7 and size >= 20:                  # SystemInfoStream
            out["build"] = struct.unpack_from("<I", data, at + 16)[0]
        elif kind == 4:                                 # ModuleListStream
            out["modules"] = struct.unpack_from("<I", data, at)[0]
    return out


def main() -> int:
    # ---- 1. real Volatility tables as a delivery
    tables = {p.name: p.read_bytes() for p in sorted(VOL.glob("*.json"))}
    check("the tracked Volatility tables are there (six plugins of one real image)", len(tables) == 6, sorted(tables))
    pslist = json.loads(tables["windows.pslist.json"])
    psscan = json.loads(tables["windows.psscan.json"])
    check("the tables are what Volatility printed: 47 pslist rows, 67 psscan rows, dd.exe is PID 4012 under cmd.exe 2624",
          len(pslist) == 47 and len(psscan) == 67 and any(r["PID"] == 4012 and r["PPID"] == 2624 and r["ImageFileName"] == "dd.exe" for r in pslist))
    check("signals() takes a delivery of Volatility tables for memory forensics", M.signals([q("a", "What is the PID of lsass.exe?", artifact="windows.pslist.json")], tables) >= 0.5)
    a = ask(tables, "What is the name of the process with PID 4012?", "What is the PID of lsass.exe?", ("integer", "What is the parent PID of dd.exe?"),
            "Which process spawned dd.exe?", "What is the full command line of PID 4012?", "What is the command line of PID 4?",
            ("integer", "How many processes are listed?"), "What is the Windows build number?", "When was dd.exe started?", "What is the PID of svchost.exe?",
            "At what address does the injected region in csrss.exe start?", "When was the memory image captured?")
    check("tables: PID 4012 is dd.exe, lsass.exe is 592 (unsure: a name's and a number's spelling are not judged)", values(a[0])[:1] == ["dd.exe"] and values(a[1]) == ["592"], a[:2])
    check("tables: the parent PID of dd.exe is plain 2624 (kind integer, one consistent value in pslist and psscan)", a[2] == "2624", a[2])
    check("tables: dd.exe was spawned by cmd.exe; its command line is the dd that took the image", values(a[3])[:1] == ["cmd.exe"]
          and values(a[4]) == ["dd if=\\\\.\\PhysicalMemory of=c:\\xp-laptop-2005-06-25.img conv=noerror"], a[3:5])
    check("tables: Volatility's remark for System's unreadable command line ('Required memory at 0x10 is not valid') is not a command line", a[5] is None, a[5])
    check("tables: pslist lists 47 processes and psscan 67, so 'how many processes' has two readings and no answer", a[6] is None, a[6])
    check("tables: build 2600 from windows.info; dd.exe's create time; eleven svchost.exe, so no one PID", values(a[7]) == ["2600"] and "2005-06-25T16:58:46Z" in values(a[8]) and a[9] is None, a[7:10])
    check("tables: the malfind region of csrss.exe and the capture time of windows.info", "0x7f6f0000" in values(a[10]) and "2005-06-25T16:58:47Z" in values(a[11]), a[10:])
    check("tables: nothing but the integer is plain", [is_plain(x) for x in a] == [False, False, True] + [False] * 9, [is_plain(x) for x in a])

    # ---- 2. real minidumps and ELF cores
    if not D.is_dir() or not any(D.iterdir()):
        print(f"SKIP tests/real: no real files for `memory` ({D} is absent); run tests/real/fetch_a.py")
        return finish("test_real_memory")
    names = [e["name"] for e in manifest("memory")]
    check("every dump of the manifest is in the cache", all((D / n).is_file() for n in names), [n for n in names if not (D / n).is_file()])
    for n in names:
        data = (D / n).read_bytes()
        try:
            _, dt = timed(f"report {n}", lambda: M.report([str(D / n)]), len(data))
            fmt = M.image_format(data)
        except Exception as e:            # noqa: BLE001  a crash on a real file is the finding
            check(f"{n}: read and reported", False, f"{type(e).__name__}: {e}")
            continue
        check(f"{n}: named {'minidump' if n.endswith('.dmp') else 'elf_core'} by its bytes and reported", fmt == ("minidump" if n.endswith(".dmp") else "elf_core"), fmt)
    for n in ("rustminidump-test.dmp", "rustminidump-full-dump.dmp", "rustminidump-simple-crashpad.dmp"):
        data = (D / n).read_bytes()
        want, md = minidump_facts(data), M.minidump(data)
        check(f"{n}: PID {want.get('pid')}, build {want.get('build')}, {want.get('modules')} modules, as the stream directory says",
              md["pid"] == want.get("pid") and md["system"].get("build") == want.get("build") and len(md["modules"]) == want.get("modules")
              and (md.get("create_time") == want.get("created") or "created" not in want), (md["pid"], md["system"].get("build"), len(md["modules"]), md.get("create_time")))
    a = ask({"crash.dmp": (D / "rustminidump-test.dmp").read_bytes()}, "What is the name of the process in the dump?", "What is the PID of the process?",
            "When was the process created?", "What is the format of the memory dump?")
    check("test.dmp: test_app.exe, PID 3932, created 2007-02-14 19:13:55 UTC (rust-minidump's own test values), a minidump: all unsure",
          values(a[0])[:1] == ["test_app.exe"] and values(a[1]) == ["3932"] and "2007-02-14T19:13:55Z" in values(a[2]) and values(a[3])[:1] == ["minidump"], a)
    a = ask({"crash.dmp": (D / "rustminidump-linux-mini.dmp").read_bytes()}, "What is the PID of the process?", "What is the name of the process in the dump?")
    check("linux-mini.dmp: a dump with no MiscInfo stream states no PID, and none is answered; its first module is `crash`", a[0] is None and values(a[1]) == ["crash"], a)
    for n in ("rustminidump-invalid-range.dmp", "rustminidump-invalid-record-count.dmp"):
        a = ask({"crash.dmp": (D / n).read_bytes()}, "What is the name of the process in the dump?", "What is the PID of the process?")
        check(f"{n}: a damaged dump answers nothing", a == [None, None], a)
    try:
        from elftools.elf.elffile import ELFFile
    except Exception:            # noqa: BLE001
        ELFFile = None
        print("note pyelftools not importable: the core comparison is skipped")
    for n in [x for x in names if x.endswith(".elf")]:
        if ELFFile is None:
            continue
        with open(D / n, "rb") as f:
            notes = [x for seg in ELFFile(f).iter_segments() if seg.header.p_type == "PT_NOTE" for x in seg.iter_notes()]
        ps = next((x["n_desc"] for x in notes if x["n_type"] == "NT_PRPSINFO"), None)
        core = M.elf_core((D / n).read_bytes())
        if ps is None:
            check(f"{n}: no process record in the core, and none is read", core.get("pid") is None, core.get("pid"))
            continue
        fname = ps["pr_fname"].decode() if isinstance(ps["pr_fname"], bytes) else ps["pr_fname"]
        args = ps["pr_psargs"].decode() if isinstance(ps["pr_psargs"], bytes) else ps["pr_psargs"]
        check(f"{n}: pid {ps['pr_pid']}, ppid {ps['pr_ppid']}, {fname!r} and its arguments, as pyelftools reads NT_PRPSINFO",
              (core["pid"], core["ppid"], core["name"], core["args"]) == (ps["pr_pid"], ps["pr_ppid"], fname.rstrip("\x00"), args.rstrip("\x00 ")), (core["pid"], core["ppid"], core["name"], core["args"]))
    a = ask({"core": (D / "pyelftools-core_linux64.elf").read_bytes()}, "What is the PID of the process?", "What is the parent PID of the process?",
            "What is the command line of the process?", "What is the format of the memory dump?")
    check("core_linux64: 23395, parent 23187, './coredump_self foo bar 42' (the values pyelftools' own test asserts), an ELF core",
          values(a[0]) == ["23395"] and values(a[1]) == ["23187"] and values(a[2]) == ["./coredump_self foo bar 42"] and values(a[3])[:1] == ["elf_core"], a)
    r = subprocess.run([sys.executable, str(M.__file__), str(D / "rustminidump-test.dmp")], capture_output=True, text=True, timeout=120)
    check("cli: the report of test.dmp names the process and its 13 modules", r.returncode == 0 and "test_app.exe pid 3932" in r.stdout and "13 modules" in r.stdout, r.stderr[-300:])

    # ---- 3. the image the tables came from: the carver against Volatility
    img = D / "win-xp-laptop-2005-06-25.img"
    if not img.is_file():
        print("note the 512 MB image is not in the cache (tests/real/fetch_a.py --big): the carver is not compared with Volatility here")
        return finish("test_real_memory")
    with open(img, "rb") as f:
        data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        t = time.time()
        c = M.carve_windows_processes(data)
        dt = time.time() - t
        refs = M.kernel_pdb(data)
    recs = c["procs"]
    check(f"image: the carver calibrates itself on System: 32-bit, PID 0xf0 before the name, parent 0x28, create time 0x14 before the PID, the dispatcher header found ({dt:.1f} s for 512 MB)",
          (c["width"], c["pid_delta"], c["ppid_delta"], c["create_delta"]) == (4, 0xF0, 0x28, -0x14) and c.get("head_delta") and c.get("pool_tag"), {k: v for k, v in c.items() if k != "procs"})
    want = {(r["PID"], r["PPID"], r["ImageFileName"][:15]) for r in pslist}
    got = {(r["pid"], r["ppid"], r["name"]) for r in recs}
    check("image: every one of pslist's 47 processes is carved with its parent PID", want <= got, sorted(want - got)[:5])
    scanned = {(r["PID"], r["ImageFileName"][:15]) for r in psscan}
    extra = sorted({(r["pid"], r["name"]) for r in recs} - scanned)
    check(f"image: nothing is carved that psscan does not find ({len(recs)} records; the carver read 2,300 before it asked for the object's header and pool tag)", not extra and 47 <= len(recs) <= 67, extra[:5])
    made = {r["PID"]: r["CreateTime"] for r in pslist if r["CreateTime"]}
    off = [(r["pid"], str(r["create"]), made[r["pid"]]) for r in recs if r["pid"] in made and (r["pid"], r["name"]) in {(x["PID"], x["ImageFileName"][:15]) for x in pslist}
           and (r["create"] is None or r["create"].strftime("%Y-%m-%dT%H:%M:%S") != made[r["pid"]])]
    live = [r for r in recs if (r["pid"], r["ppid"], r["name"]) in want]
    check("image: the carved create times are Volatility's, to the second", not [x for x in off if not any(y["pid"] == x[0] and y["create"] and y["create"].strftime("%Y-%m-%dT%H:%M:%S") == x[2] for y in live)], off[:4])
    check("image: the kernel's debug reference is read from the bytes (it names the one symbol file Volatility needs)", refs[:1] == [KERNEL], refs[:2])
    if os.environ.get("CTF_TK_LIVE") == "1":
        pack = M.symbols_folder() / f"{KERNEL[1]}-{KERNEL[2]}" / "windows.zip"
        if os.environ.get("CTF_TK_NET") == "1" and not pack.is_file():
            pack, note = fetch_isf_live()
            print(f"note {note}")
        if pack and pack.is_file():
            rows, note = M.vol(img, "windows.pslist", symbols=pack)
            check("live: windows.pslist in the sandbox, offline, with the one symbol file: the 47 rows of the tracked table",
                  rows is not None and sorted((r["PID"], r["PPID"], r["ImageFileName"]) for r in rows) == sorted((r["PID"], r["PPID"], r["ImageFileName"]) for r in pslist), note)
        else:
            print("note no symbol pack saved (CTF_TK_NET=1 fetches it): the live Volatility run is skipped")
    return finish("test_real_memory")


if __name__ == "__main__":
    sys.exit(main())
