#!/usr/bin/env python3
"""Volatility 3 Linux triage opener for a memory image (B-136), engine `toolkits.vol_triage`.

  python -m ctf run toolkits.vol_triage <image>          the no-tool stage (what intake and `ctf arm` run)
  python -m ctf run toolkits.vol_triage <image> --vol    ... then linux.psaux, linux.bash and linux.pslist in the sandbox
        [--symbols DIR]... [--arch x64|x86|arm64] [--plugins a,b] [--where sandbox|venv] [--no-start]
        [--budget S] [--vol-budget S] [--scratch DIR]

The triage half of a Linux memory challenge, with no model. On Peering-Eyes (Spooky 2026) the agent
spent its first hour on exactly this by hand: which kernel, which symbol table, what ran, what the
shell typed, and what strings the image still holds.

The no-tool stage reads the image through mmap and starts nothing, in this order. Each part is
printed (and flushed) as soon as it is found, so a run that is killed has still said what it had:
  - the image format and its LiME ranges (memory.image_format, lime_segments). An AVML version 2
    image is snappy-compressed: it is decompressed chunk by chunk into a temporary LiME copy (what
    `avml-convert` writes; memory.avml_to_lime, cramjam), within UNPACK_SHARE of the budget and
    with a reserve of free disk space, and everything after reads that copy. `image_note` says what
    was decompressed and why it stopped; when nothing could be, the file's bytes are read as they
    stand and the note says that a text the compressor cut in two is then not found;
  - the kernel's whole banner (memory.carve_linux_banners, by CARVE_SHARE of the budget; a cut is
    said), printed at once as `banners(carved)`. An image with no Linux banner is said not to be
    this opener's, and toolkits.memory is named;
  - flags in the event's format, and flag LEADS with no complete flag after them (`prefix{f1rst_`
    and then a NUL or a quote): a constant that is one half of a split flag. Both through
    ctf.flagfmt; with no event the scan is reported not run, with the reason. The scan has
    SCAN_SHARE of the stage's budget and runs before the table search, so nothing a handout's files
    cost can take the flags' time;
  - the ISF: the symbol table whose own banner is the image's, looked for in the image's folder (a
    delivery that ships its table), every --symbols folder and the event's symbol folder
    (memory.symbols_folder()), within what is left of the budget (a search the clock cut is said,
    with where it stopped). Nothing is downloaded; a kernel with no local table is said so with
    what was looked at (memory.match_linux_isf), and a pack saved earlier for the same banner is
    then used (memory.saved_linux_pack). memory_depth.select_profile states the strategy, and a
    matched table is wrapped as the `linux.zip` pack the sandbox takes (memory.linux_symbol_pack).
    `kernel_banner`, its release and architecture are printed here: the banner the table matches
    when one does, else the most frequent one. A table over memory.ISF_PACK_MAX is matched but
    not packed, and `symbol_pack` says so.

--vol adds the Volatility stage (memory.vol_save, where="sandbox": tools/sandbox.py, no network):
the plugins of TRIAGE_PLUGINS with the matched pack, their tables saved where memory.build_model
replays them, then what the tables show: every process with its arguments, the shell history, the
notable processes (an interpreter running a script, a program in a world-writable folder, a kernel
module loaded by hand, the display server) and how often each script's name still stands in the
image. A sandbox that is down, a missing Volatility or a kernel with no table is `not run` with its
reason, never an empty table. Intake's network guard cuts the docker socket, so --vol is a step of
its own, outside the guard; the no-tool stage prints the exact command as `next = ...`, with the
--symbols folders it was given. Text that comes out of the image (a process name, its arguments, a
history line) is printed as a Python literal, and every report line is printed with whatever is
not printable in it escaped (memory.shown): a line break in a file, folder or table name of the
handout cannot start a report line either. The `next` command quotes such a path as `$'...'`.

What stays with a model or a human (the B-136 hard tail), named in the `handoff` lines: pixels held
by the display server (stride detection and BGRX rendering of an X heap or a framebuffer mapping)
and reading what is drawn or written in them.

Output: `key = value` lines, then one SolverResult JSON object as the last line (solved: one flag
carved; candidate: several; unsure: a lead with no complete flag; none; blocked: the image could not
be read). Exit 0 for any result, 2 for a usage error.
"""
from __future__ import annotations

import argparse
import contextlib
import mmap
import re
import shlex
import shutil
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import event as ctf_event, flagfmt
    from ctf.result import Evidence, SolverResult
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import event as ctf_event, flagfmt
    from ctf.result import Evidence, SolverResult

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(1, str(HERE))

import memory          # noqa: E402  (the toolkit this opener is built on)
import memory_depth    # noqa: E402

ENGINE = "toolkits.vol_triage"
TRIAGE_PLUGINS = ("linux.psaux", "linux.bash", "linux.pslist")     # most telling first: a budget cut keeps psaux
HOST_BUDGET = 40.0              # seconds the no-tool scans may take (below intake's 60 s engine budget)
UNPACK_SHARE = 0.2              # of that budget, counted from the start: an AVML version 2 image is decompressed by here,
CARVE_SHARE = 0.3               # the banners are carved by here,
SCAN_SHARE = 0.6                # and the flags are scanned by here; the table search has the rest and what the scan left
VOL_BUDGET = 1500.0             # seconds for the whole Volatility stage
SCAN_CHUNK = 32 << 20           # bytes scanned between two looks at the clock
LEAD_OVERLAP = 512              # a lead that starts in a chunk is matched whole (a prefix is far shorter)
FRAGMENT_MIN = 4                # body bytes after a lead before it is worth a line
FRAGMENT_MAX = 96
LISTED = 60                     # flags, fragments, processes, history rows printed at most (each cut is said)
PIVOT_HITS = 1000               # occurrences of one script name counted at most
PIVOT_NAMES = 8                 # script names searched for at most
OTHER_BANNERS = 3               # carved banners printed beside the kernel's
_FRAGMENT_STOP = frozenset(b"{}\"'`\\")
FORMATS = {"lime": "lime", "avml": "avml", "": "raw", "elf_core": "elf-core", "vmware_snapshot": "vmware"}

_SCRIPT = re.compile(r"(?:^|[/\s])(?:python[\d.]*|perl|ruby|node|php|lua|bash|sh|zsh|dash)\s+(?:-[^\s]+\s+)*"
                     r"([^\s-][^\s]*\.(?:py|pl|rb|js|php|lua|sh))(?:\s|$)")
_WRITABLE = re.compile(r"(?:^|[\s=])(/(?:tmp|dev/shm|var/tmp|run/shm)/[^\s]+)")
_MODULE = re.compile(r"(?:^|[/\s])(?:insmod|modprobe)\s+(?:-[^\s]+\s+)*([^\s-][^\s]*)")
DISPLAY_SERVERS = ("Xorg", "Xwayland", "X", "Xvfb", "Xvnc")


# ---- the no-tool stage ---------------------------------------------------------------------------------

def scan_flags(data, *, clock=time.monotonic, deadline=None, chunk: int = SCAN_CHUNK) -> dict:
    """Flags in the event's format, and flag leads that no complete flag follows, in the bytes.

    {"status": ran | cut | not run, "reason", "scanned", "flags": [{value, offset, count}],
    "fragments": [...]}. A lead (`PREFIX{`, ctf.flagfmt's lead for the active event) followed by a
    complete flag is a flag, when every byte of it is printable: a format with a broad body would
    otherwise run from any lead through NULs and pointers to the next closing brace in reach. A lead
    followed by FRAGMENT_MIN or more printable bytes and then anything but the rest of a flag (a
    NUL, a quote, a line end) is a fragment: a constant that holds one part of a split flag, or a
    cut string. A fragment is never a flag and is never reported as one. A flag is one hit however
    many leads stand inside it (ctf.flagfmt.find_flags counts it the same way).
    The scan looks at the clock every `chunk` bytes and stops at `deadline` with status cut and the
    offset it reached. With no resolvable event, or a profile that states no flag prefix yet, it is
    not run and says why: this file has no flag pattern of its own."""
    try:
        ff = flagfmt.current()
    except ctf_event.EventError as e:
        return {"status": "not run", "reason": f"no event resolves, so there is no flag format to look for "
                                               f"({str(e).splitlines()[0][:160]}): set CTF_EVENT",
                "scanned": 0, "flags": [], "fragments": []}
    if not ff.known:
        return {"status": "not run", "reason": "the event profile states no flag prefix yet", "scanned": 0,
                "flags": [], "fragments": []}
    lead, whole = ff.lead_bregex, ff.bregex
    flags, fragments = {}, {}
    n, pos, done, status, reason = len(data), 0, 0, "ran", ""
    while pos < n:
        if deadline is not None and clock() > deadline:
            status, reason = "cut", f"the scan budget ran out at offset 0x{pos:x} of 0x{n:x}"
            break
        end = min(n, pos + chunk)
        for m in lead.finditer(data, pos, min(n, end + LEAD_OVERLAP)):
            at = m.start()
            if at >= end:
                break                           # the next chunk's
            if at < done:
                # Inside what was already taken: a flag is one hit however many leads stand in it (as
                # find_flags counts it), and a lead cut by this chunk's start is not read again by
                # its tail (the CTF{ of CSCTF{).
                continue
            full = whole.match(data, at)
            if full and _printable(full.group()):
                value, book, body, done = full.group().decode("latin-1"), flags, b"", full.end()
            else:
                # No flag here, or the format's broad body ran through binary bytes to some later brace:
                # that is not a string anyone wrote. The lead may still open a fragment, and a real
                # flag inside the span is still looked for (the scan goes on right after the lead).
                done = m.end()
                body = _fragment(data, m.end())
                if len(body) < FRAGMENT_MIN:
                    continue
                value, book = (m.group() + body).decode("latin-1"), fragments
            hit = book.setdefault(value, {"value": value, "offset": at, "count": 0,
                                          "prefix": m.group()[:-1].decode("latin-1"), "body": body.decode("latin-1")})
            hit["count"] += 1
        pos = end
    return {"status": status, "reason": reason, "scanned": pos if status == "cut" else n,
            "flags": list(flags.values()), "fragments": list(fragments.values())}


def spell(fragment: dict) -> str:
    """A fragment as it is printed: `"prefix" + "{" + "body"`, never the lead written out. Intake reads
    an engine's stdout for the event's flag format when its result names no flag, and this engine's
    last line is a JSON object: a lead written out would be closed by that object's brace and read
    back as a flag that is in no file. Split at the brace, nothing on the line is flag-shaped."""
    return f'"{fragment["prefix"]}" + "{{" + "{fragment["body"]}"'


def _printable(raw: bytes) -> bool:
    """Every byte is printable ASCII (0x20..0x7e): intake's rule for a flag body (decode.body_is_printable).
    In a memory image a format with a broad body matches from any lead to the next closing brace,
    NULs and pointers included; such a span is noise, not a flag."""
    return all(0x20 <= c <= 0x7e for c in raw)


def _fragment(data, pos: int) -> bytes:
    """The printable bytes from pos on, up to a byte that cannot be inside a flag written in source or
    held in a string (a control byte, a space, a brace, a quote, a backslash) or FRAGMENT_MAX."""
    end, stop = pos, min(len(data), pos + FRAGMENT_MAX)
    while end < stop:
        c = data[end]
        if c < 0x21 or c > 0x7e or c in _FRAGMENT_STOP:
            break
        end += 1
    return bytes(data[pos:end])


def symbol_folders(image: Path, extra=()) -> tuple:
    """([(folder, label)], notes): where a Linux ISF is looked for, in order: the image's own folder
    (`delivery`), each --symbols folder, and the event's symbol folder (memory.symbols_folder(), under
    the workdir). With no resolvable workdir the last one is left out and the note says so."""
    out, notes, seen = [], [], set()

    def add(folder, label):
        key = Path(folder).resolve()
        if key not in seen:
            seen.add(key)
            out.append((Path(folder), label))
    add(image.parent, "delivery")
    for folder in extra:
        add(folder, "--symbols")
    try:
        add(memory.symbols_folder(), "symbol folder")
    except ctf_event.EventError as e:
        notes.append(f"the event's symbol folder was not looked at (no workdir: {str(e).splitlines()[0][:120]})")
    return out, notes


def find_table(banners: Counter, folders, arch: str = "", image_format: str = "raw", *, clock=time.monotonic,
               deadline=None) -> dict:
    """The ISF for the carved banners among the folders ([(folder, label)]), and the profile
    memory_depth.select_profile states for it. {"path", "banner", "kernel", "label", "note", "tables",
    "profile", "pack", "pack_note", "reused"}; path None when no local table was made for this kernel
    and no pack was saved for it earlier. kernel: the carved banner the report is about (the one the
    table matches, else the most frequent). deadline (a `clock()` value) bounds the search.
    A handout's files are untrusted: whatever reading one raises becomes the isf note, so the
    banner and the flags found before it are still reported."""
    if not banners:                 # no kernel to match: the tables are not even opened
        _path, _made_for, note = memory.match_linux_isf(banners, [])
        return {"path": None, "banner": None, "kernel": None, "label": "", "note": note, "tables": 0, "profile": None,
                "pack": None, "pack_note": "", "reused": False}
    try:
        tables, notes = memory.linux_isfs([f for f, _ in folders], deadline=deadline, clock=clock)
    except Exception as e:          # noqa: BLE001  (said in the note, never swallowed: see the docstring)
        tables, notes = [], [f"the table search failed ({type(e).__name__}: {str(e).splitlines()[0][:160] if str(e) else 'no message'})"]
    path, made_for, note = memory.match_linux_isf(banners, [f for f, _ in folders], tables=(tables, notes))
    label, pack, pack_note, reused = "", None, "", False
    index = {}
    for table, banner in tables:
        index.setdefault(banner, str(table))
    if path is not None:
        label = next((lab for f, lab in folders if f.resolve() in path.resolve().parents), "")
        info = {}
        try:
            pack = memory.linux_symbol_pack(path, made_for, info)
            reused = bool(info.get("reused"))
        except ctf_event.EventError as e:
            pack_note = f"not written (no workdir: {str(e).splitlines()[0][:120]})"
        except OSError as e:
            pack_note = f"not written ({type(e).__name__}: {e})"
    else:
        try:
            saved, saved_banner, saved_note = memory.saved_linux_pack(banners)
        except ctf_event.EventError:
            saved = None            # no workdir: symbol_folders has said so (isf_note)
        if saved is not None:       # the table is no longer in any folder, the pack made from it is
            path, made_for, label, note, pack, reused = saved, saved_banner, "saved pack", saved_note, saved, True
            index.setdefault(saved_banner, str(saved))
    top = banners.most_common(1)[0][0]
    kernel = next((b for b, _ in banners.most_common() if made_for and b.startswith(made_for)), top)
    meta = {"banner": made_for or top, "image_format": image_format}
    if arch:
        meta["architecture"] = arch
    profile = memory_depth.select_profile("linux", meta, isf_index=index)
    return {"path": path, "banner": made_for, "kernel": kernel, "label": label, "note": note, "tables": len(tables),
            "profile": profile, "pack": pack, "pack_note": pack_note, "reused": reused}


# ---- the Volatility stage ------------------------------------------------------------------------------

def notable(procs) -> list:
    """What stands out in a process list ([{pid, name, args}]), as [{pid, name, kind, detail, script}].
    Four plain rules, each a thing a first read of psaux looks for: an interpreter running a script
    file (`script`), a path in a world-writable folder (`writable-path`), a kernel module loaded by
    hand (`kernel-module`: often the acquisition tool itself), and the display server (`display`: it
    holds the screen's pixels when the page cache no longer holds the files)."""
    out = []
    for p in procs:
        args, name = str(p.get("args") or ""), str(p.get("name") or "")
        m = _SCRIPT.search(args)
        if m:
            out.append({"pid": p["pid"], "name": name, "kind": "script", "detail": args[:200],
                        "script": m.group(1).rsplit("/", 1)[-1]})
        m = _WRITABLE.search(args)
        if m:
            out.append({"pid": p["pid"], "name": name, "kind": "writable-path", "detail": m.group(1)[:200], "script": ""})
        m = _MODULE.search(args)
        if m:
            out.append({"pid": p["pid"], "name": name, "kind": "kernel-module", "detail": m.group(1)[:200], "script": ""})
        program = args.split()[0].rsplit("/", 1)[-1] if args.split() else ""
        if name in DISPLAY_SERVERS or program in DISPLAY_SERVERS:
            out.append({"pid": p["pid"], "name": name, "kind": "display", "detail": args[:200], "script": ""})
    return out


def pivots(data, names) -> list:
    """[{name, count, offsets}]: how often each script name still stands in the image and where it
    first does (a byte search: no symbols needed). Where a script's name is, its source, its tokens
    and its constants often are: the place to point `strings` at. Names under 5 characters are left
    out (they stand everywhere), at most PIVOT_NAMES names are searched for, and a count stops at
    PIVOT_HITS."""
    out = []
    for name in list(dict.fromkeys(n for n in names if len(n) >= 5))[:PIVOT_NAMES]:
        needle, offsets = name.encode("latin-1", "replace"), []
        at = data.find(needle)
        while at >= 0 and len(offsets) < PIVOT_HITS:
            offsets.append(at)
            at = data.find(needle, at + 1)
        out.append({"name": name, "count": len(offsets), "offsets": offsets[:3]})
    return out


def run_volatility(image: Path, pack, *, plugins=TRIAGE_PLUGINS, where: str = "sandbox", start: bool = True,
                   budget: float = VOL_BUDGET, clock=time.monotonic) -> dict:
    """The Volatility stage: the plugins over the image with the matched pack (memory.vol_save, so
    the tables are saved where memory.build_model reads them back), read into a memory.Model.
    {"status": ran | partial | not run, "reason", "plugins": [{plugin, rows, note}], "folder",
    "procs", "history"}. not run: no symbol pack, or the first plugin's note says Volatility never
    looked at the image (the sandbox is down, the program is missing)."""
    blank = {"plugins": [], "folder": None, "procs": [], "history": []}
    if pack is None:
        return {"status": "not run", "reason": "no symbol table (ISF) for this kernel: see isf", **blank}
    results = {}
    try:
        folder = memory.vol_save(image, "linux", where=where, plugins=list(plugins), say=lambda line: None,
                                 symbols=str(pack), deadline=clock() + budget, clock=clock, start=start, results=results)
    except ctf_event.EventError as e:
        return {"status": "not run", "reason": f"no workdir to save the tables in ({str(e).splitlines()[0][:120]})", **blank}
    model, rows_out = memory.Model(), []
    for plugin in plugins:
        rows, note = results.get(plugin, (None, f"{plugin} not run"))
        rows_out.append({"plugin": plugin, "rows": None if rows is None else len(rows), "note": note})
        if rows is not None:
            tables, _info = memory.tables_from_json(rows)
            for table in tables:
                model.absorb(table, "table")
    ran = [r for r in rows_out if r["rows"] is not None]
    if not ran:
        first = rows_out[0]["note"] if rows_out else "no plugin was asked for"
        status = "not run" if rows_out and (memory.not_run(first) or " not run (" in first) else "failed"
        return {"status": status, "reason": first, "plugins": rows_out, "folder": folder, "procs": [], "history": []}
    procs = sorted(model.procs.values(), key=lambda p: p["pid"])
    return {"status": "ran" if len(ran) == len(rows_out) else "partial",
            "reason": "" if len(ran) == len(rows_out) else "; ".join(r["note"] for r in rows_out if r["rows"] is None),
            "plugins": rows_out, "folder": folder, "procs": procs, "history": list(model.history)}


# ---- one image -----------------------------------------------------------------------------------------

def unpack_avml(data, stack, *, clock=time.monotonic, deadline=None, scratch=None) -> tuple:
    """(info, the bytes to read): an AVML version 2 image decompressed into a temporary LiME copy
    (memory.avml_to_lime), mapped for reading. The copy is a nameless temporary file (in `scratch`,
    else the system's temporary folder): it is gone when the stage ends, and a killed run leaves
    nothing behind. info is avml_to_lime's answer plus "where". When nothing was decompressed (no
    snappy reader, no room, a first chunk that is not snappy) the bytes to read are the file's own
    and info says why: nothing is decompressed in silence, and nothing is skipped in silence."""
    where = str(scratch) if scratch else tempfile.gettempdir()
    try:
        out = stack.enter_context(tempfile.TemporaryFile(dir=where))
        info = memory.avml_to_lime(data, out, deadline=deadline, clock=clock, free=lambda: shutil.disk_usage(where).free)
        out.flush()
    except OSError as e:
        return {"status": "not run", "reason": f"the decompressed copy could not be written under {where} "
                                               f"({type(e).__name__}: {e})", "ranges": 0, "bytes": 0, "where": where}, data
    info["where"] = where
    if not info["bytes"]:
        return info, data
    return info, stack.enter_context(mmap.mmap(out.fileno(), 0, access=mmap.ACCESS_READ))


def triage(image, *, symbols=(), arch: str = "", run_vol: bool = False, plugins=TRIAGE_PLUGINS, where: str = "sandbox",
           start: bool = True, budget: float = HOST_BUDGET, vol_budget: float = VOL_BUDGET, clock=time.monotonic,
           say=None, scratch=None) -> dict:
    """Everything the opener finds in one image, as a dict (render() prints it, solver_result() sums
    it up). OSError when the image cannot be opened; ValueError when it is empty.
    say: called with each report line as soon as the part it belongs to is found (main prints and
    flushes it), in the order render() gives them: what a killed run had found is already said.
    budget is the no-tool stage's, counted from the start: an AVML version 2 image is decompressed
    by UNPACK_SHARE of it, the banners are carved by CARVE_SHARE, the flag scan stops at SCAN_SHARE,
    the table search at its end. The flags are scanned first: the table search reads the handout's
    own files, and what those cost must never be taken out of the scan."""
    image = Path(image)
    size = image.stat().st_size
    if size == 0:
        raise ValueError(f"{image.name} is empty")
    began = clock()
    result = {"image": image, "size": size, "run_vol": run_vol, "symbols": [str(folder) for folder in symbols]}

    def found(section, **part) -> None:
        result.update(part)
        if say is not None:
            for line in _one_line(section(result)):
                say(line)
    with contextlib.ExitStack() as stack:
        f = stack.enter_context(open(image, "rb"))
        data = stack.enter_context(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ))
        fmt = memory.image_format(data)
        segments = memory.lime_segments(data) if fmt in ("lime", "avml") else []
        compressed = any(seg["size"] is None for seg in segments)       # AVML version 2: snappy frames, not memory bytes
        found(head_lines, format=fmt, segments=len(segments), compressed=compressed)
        unpacked = None
        if compressed:
            unpacked, data = unpack_avml(data, stack, clock=clock, deadline=began + budget * UNPACK_SHARE, scratch=scratch)
        found(image_lines, unpacked=unpacked)
        carve = {}
        banners = memory.carve_linux_banners(data, deadline=began + budget * CARVE_SHARE, clock=clock, info=carve)
        found(carve_lines, banners=banners, carve_cut=carve["cut"])
        found(flag_lines, flags=scan_flags(data, clock=clock, deadline=began + budget * SCAN_SHARE))
        folders, folder_notes = symbol_folders(image, symbols)
        table = find_table(banners, folders, arch=arch, image_format=FORMATS.get(fmt, "raw"), clock=clock,
                           deadline=began + budget)
        found(table_lines, table=table, folder_notes=folder_notes)
        if run_vol:
            vol = run_volatility(image, table["pack"], plugins=plugins, where=where, start=start, budget=vol_budget, clock=clock)
        else:
            vol = {"status": "not run", "reason": "--vol not given", "plugins": [], "folder": None, "procs": [], "history": []}
        marks = notable(vol["procs"])
        found(vol_lines, vol=vol, notable=marks, pivots=pivots(data, [m["script"] for m in marks if m["script"]]))
        found(tail_lines)
    return result


def _cut(rows, what: str, lines: list, fmt) -> None:
    for row in rows[:LISTED]:
        lines.append(fmt(row))
    if len(rows) > LISTED:
        lines.append(f"{what} = {len(rows) - LISTED} more not listed")


def _one_line(lines) -> list:
    """Every report line with what is not printable in it escaped (memory.shown). The names of the
    handout's files, folders and tables, and the notes that carry them, are data: none of them can
    break a line and start a report line of its own."""
    return [memory.shown(line) for line in lines]


def _shell(path) -> str:
    """A path as one shell word on one line: shlex.quote, and for a path with a character that is
    not printable (a line break in a file name) the `$'...'` form bash and zsh read, so the command
    can still be pasted as printed."""
    text = str(path)
    if text.isprintable():
        return shlex.quote(text)
    return "$'" + "".join("\\" + c if c in "'\\" else c if c.isprintable() else c.encode("unicode_escape").decode("ascii")
                          for c in text) + "'"


def _read_raw(result: dict) -> bool:
    """True when the image is compressed and the stage read its bytes as they stand (nothing was decompressed)."""
    return result["compressed"] and not (result["unpacked"] or {}).get("bytes")


def handoff(result: dict) -> list:
    """What the opener leaves for a model or a human, one line each (the B-136 hard tail and the
    steps this stage could not take)."""
    out, vol, flags = [], result["vol"], result["flags"]
    if flags["fragments"] and not flags["flags"]:
        out.append("a flag lead with no closing brace was carved: the rest of the flag is somewhere else "
                   "(another constant, a file, or pixels on the screen); a fragment is never submitted")
    for mark in result["notable"]:
        if mark["kind"] == "display":
            out.append(f"pixels: {repr(mark['name']) if mark['name'] else 'the display server'} (pid {mark['pid']}) holds the screen. Dump its maps "
                       f"(linux.proc.Maps --pid {mark['pid']} --dump) and look for images by stride; stride detection, "
                       "BGRX rendering and reading what is drawn there are not automated (B-136): a model or a human")
    if vol["status"] in ("not run", "failed") and result["run_vol"]:
        out.append(f"the Volatility stage did not read the image ({vol['reason'][:200]}): fix that and run --vol again; "
                   "until then the carved lines above are all there is")
    return out


# The report, part by part, in the order the stage finds things. Each part reads only what was found
# before it, so triage() can say it at once; render() is the same parts over a finished result.

def head_lines(result: dict) -> list:
    image = result["image"]
    if result["compressed"]:
        return [f"== {image.name}: {result['size']} bytes, format avml version 2 (snappy-compressed ranges)"]
    return [f"== {image.name}: {result['size']} bytes, format {result['format'] or 'raw (the bytes name no wrapper)'}"
            + (f", {result['segments']} range(s)" if result["segments"] else "")]


def image_lines(result: dict) -> list:
    info = result["unpacked"]
    if info is None:
        return []
    if not info["bytes"]:
        return [f"image_note = AVML version 2: not decompressed ({info['reason']}). This stage read the file's bytes as "
                "they stand, so a banner, a flag or a lead the compressor cut in two is not found. Convert the image "
                "(avml-convert <image> <out.lime>) and run this on the result"]
    whole = info["status"] == "ran"
    return [f"image_note = AVML version 2: {'decompressed' if whole else 'decompressed in part'}, {info['ranges']} range(s), "
            f"{info['bytes']} bytes" + ("" if whole else f" ({info['reason']}); what follows is about that part only")
            + ". The offsets below are offsets in the LiME file avml-convert writes of this image, not in the file itself"]


def carve_lines(result: dict) -> list:
    banners, cut = result["banners"], result["carve_cut"]
    late = f"the banner carve's budget ran out at offset 0x{cut:x}: what stands after it was not read" if cut is not None else ""
    if banners:
        top, k = banners.most_common(1)[0]
        return [f"banners(carved) = {len(banners)} distinct, the most frequent: {top} x{k}" + (f" ({late})" if late else "")]
    if late:
        return [f"kernel_banner = none ({late}; run this again with a larger --budget)"]
    if _read_raw(result):
        return ["kernel_banner = none (no 'Linux version' banner stands whole in the compressed bytes: that does not "
                "say the image is not Linux; convert it, see image_note)"]
    if result["unpacked"] and result["unpacked"]["status"] != "ran":
        return ["kernel_banner = none (no 'Linux version' banner in the part that was decompressed: that does not say "
                "the image is not Linux; see image_note)"]
    return ["kernel_banner = none (no 'Linux version' banner in the image: not a Linux kernel's memory, or the "
            "page that holds it is not in the image. This opener reads Linux images only: a Windows image is "
            f"toolkits.memory's, python -m ctf run toolkits.memory {_shell(result['image'])})"]


def flag_lines(result: dict) -> list:
    flags, lines = result["flags"], []
    if flags["status"] == "not run":
        return [f"flag_scan = not run ({flags['reason']})"]
    lines.append(f"flag_scan = {flags['status']} over {flags['scanned']} bytes: {len(flags['flags'])} flag(s), "
                 f"{len(flags['fragments'])} lead(s) with no complete flag"
                 + (f" ({flags['reason']})" if flags["reason"] else ""))
    _cut(flags["flags"], "flag(carved)", lines,
         lambda h: f"flag(carved) = {h['value']} x{h['count']} first at 0x{h['offset']:x}")
    _cut(flags["fragments"], "flag_fragment(carved)", lines,
         lambda h: f"flag_fragment(carved) = {spell(h)} x{h['count']} first at 0x{h['offset']:x} (no complete flag "
                   "follows this lead: one part of a split flag, or a cut string)")
    return lines


def table_lines(result: dict) -> list:
    table, banners, lines = result["table"], result["banners"], []
    kernel, profile = table["kernel"], table["profile"]
    if banners:
        # One kernel through the whole report: the banner the table matches, when one does (the release,
        # the arch and the isf line are then about the same kernel), else the most frequent.
        lines.append(f"kernel_banner = {kernel} x{banners[kernel]}")
        for other, k in [(b, k) for b, k in banners.most_common() if b != kernel][:OTHER_BANNERS]:
            lines.append(f"kernel_banner(other) = {other} x{k}")
        lines.append(f"kernel_release = {kernel.split()[2]}")
    if profile:
        lines.append(f"arch = {profile.architecture}")
    if table["path"] is not None:
        lines.append(f"isf = matched {table['path'].name} [{table['label']}]: {table['note']}")
    else:
        lines.append(f"isf = none ({table['note']})")
    for note in result["folder_notes"]:
        lines.append(f"isf_note = {note}")
    if profile:
        lines.append(f"symbol_strategy = {profile.symbol_strategy}")
        lines.append(f"symbol_hint = {profile.symbol_hint}")
    elif banners:
        lines.append("symbol_strategy = not selected (memory_depth.select_profile took no Linux profile from this banner: "
                     "it needs a three-part release and an architecture; pass --arch x64|x86|arm64 when the banner names none)")
    if table["path"] is not None:
        lines.append(f"symbol_pack = {table['pack'] if table['pack'] else table['pack_note']}"
                     + (" (reused: saved earlier from this very table)" if table["reused"] and table["label"] != "saved pack" else ""))
    return lines


def vol_lines(result: dict) -> list:
    vol, lines = result["vol"], []
    if vol["status"] == "not run":
        lines.append(f"volatility = not run ({vol['reason']})")
    else:
        lines.append(f"volatility = {vol['status']}" + (f" ({vol['reason']})" if vol["reason"] else "")
                     + (f"; tables saved under {vol['folder']}" if vol["folder"] else ""))
    for row in vol["plugins"]:
        lines.append(f"vol {row['plugin']} = " + (f"{row['rows']} rows" if row["rows"] is not None else f"no table ({row['note']})"))
    _cut(vol["procs"], "proc", lines,
         lambda p: f"proc pid={p['pid']} ppid={p.get('ppid')} comm={p.get('name')!r}" + (f" args={p['args']!r}" if p.get("args") else ""))
    _cut(vol["history"], "history", lines,
         lambda h: f"history pid={h['pid']} time={h.get('time') or '?'} command={h['command']!r}")
    for mark in result["notable"]:
        lines.append(f"notable = pid {mark['pid']} {mark['name']!r} [{mark['kind']}] {mark['detail']!r}")
    for pivot in result["pivots"]:
        lines.append(f"pivot(carved) = {pivot['name']!r} stands {pivot['count']}{'+' if pivot['count'] >= PIVOT_HITS else ''} "
                     "time(s) in the image" + (", first at " + ", ".join(f"0x{o:x}" for o in pivot["offsets"]) if pivot["offsets"] else ""))
    return lines


def tail_lines(result: dict) -> list:
    lines = []
    if not result["run_vol"] and result["table"]["pack"] is not None:
        # the command as it can be pasted: the --symbols folders the table may have been found in go with it
        again = "".join(f" --symbols {_shell(folder)}" for folder in result["symbols"])
        lines.append(f"next = python -m ctf run {ENGINE} {_shell(result['image'])}{again} --vol   "
                     "(outside intake's network guard: it cuts the docker socket)")
    for line in handoff(result):
        lines.append(f"handoff = {line}")
    return lines


PARTS = (head_lines, image_lines, carve_lines, flag_lines, table_lines, vol_lines, tail_lines)


def render(result: dict) -> list:
    """The report, as `key = value` lines (the opener's key in openers/layer1.toml is anchored on these):
    the PARTS in order, exactly the lines triage() says through `say` while it works."""
    return _one_line(line for part in PARTS for line in part(result))


def solver_result(result: dict) -> SolverResult:
    flags, table, vol = result["flags"], result["table"], result["vol"]
    found = [h["value"] for h in flags["flags"]]
    name = result["image"].name
    summary = (f"{name}: " + (f"kernel {table['kernel'].split()[2]}" if result["banners"] else "no Linux banner")
               + ("" if not result["compressed"] else "; AVML version 2 (snappy): the carve read compressed bytes" if _read_raw(result)
                  else "; AVML version 2: decompressed" + ("" if result["unpacked"]["status"] == "ran" else " in part"))
               + ("; ISF matched" if table["path"] is not None else "; no local ISF")
               + f"; flag scan {flags['status']}; Volatility {vol['status']}"
               + (f" ({len(vol['procs'])} processes, {len(vol['history'])} history rows)" if vol["status"] in ("ran", "partial") else ""))
    if found:
        at = "the image's bytes" if not result["compressed"] or _read_raw(result) else "the decompressed image (offsets: its LiME copy)"
        evidence = [Evidence("carve", f"{h['value']} stands {h['count']} time(s) in {at}", path=name, offset=h["offset"])
                    for h in flags["flags"][:8]]
        return SolverResult("solved" if len(found) == 1 else "candidate", flags=found[:32], evidence=evidence,
                            engine=ENGINE, notes=summary)
    if flags["fragments"]:
        leads = ", ".join(spell(h) for h in flags["fragments"][:4])
        return SolverResult("unsure", engine=ENGINE,
                            evidence=[Evidence("carve", f"flag lead with no complete flag: {spell(h)}", path=name, offset=h["offset"])
                                      for h in flags["fragments"][:8]],
                            notes=f"{summary}; lead(s) with no complete flag: {leads}. " + " ".join(handoff(result))[:600])
    return SolverResult("none", engine=ENGINE, notes=summary)


# ---- the command ---------------------------------------------------------------------------------------

def _args(argv):
    ap = argparse.ArgumentParser(prog="vol_triage.py", description="Volatility 3 Linux triage opener for a memory image (B-136)")
    ap.add_argument("image", help="the memory image (LiME, AVML or raw)")
    ap.add_argument("--vol", action="store_true", help="run the Volatility stage (linux.psaux, linux.bash, linux.pslist)")
    ap.add_argument("--symbols", action="append", default=[], metavar="DIR", help="another folder to look for the kernel's ISF in")
    ap.add_argument("--arch", default="", choices=("", "x64", "x86", "arm64"), help="the architecture, when the banner does not name it")
    ap.add_argument("--plugins", default=",".join(TRIAGE_PLUGINS), help="the Volatility plugins, in order (comma separated)")
    ap.add_argument("--where", default="sandbox", choices=("sandbox", "venv"), help="where Volatility runs (default: the sandbox)")
    ap.add_argument("--no-start", action="store_true", help="never start a sandbox container: not run when none is up")
    ap.add_argument("--budget", type=float, default=HOST_BUDGET, help="seconds for the no-tool scans")
    ap.add_argument("--vol-budget", type=float, default=VOL_BUDGET, help="seconds for the whole Volatility stage")
    ap.add_argument("--scratch", default=None, metavar="DIR",
                    help="where the temporary decompressed copy of an AVML version 2 image is written (default: the system's temporary folder)")
    return ap.parse_args(argv)


def main(argv) -> int:
    args = _args(argv)                  # argparse exits 2 on a usage error
    plugins = tuple(p.strip() for p in args.plugins.split(",") if p.strip())
    if not plugins or any(not re.fullmatch(r"[A-Za-z0-9_.]+", p) for p in plugins) or args.budget <= 0 or args.vol_budget <= 0:
        print("vol_triage.py: --plugins takes plugin names (linux.psaux,linux.bash); budgets are positive seconds", file=sys.stderr)
        return 2
    image = Path(args.image)
    try:
        # each line is printed and flushed when it is found: a run killed at intake's limit has said what it had
        result = triage(image, symbols=args.symbols, arch=args.arch, run_vol=args.vol, plugins=plugins, where=args.where,
                        start=not args.no_start, budget=args.budget, vol_budget=args.vol_budget, scratch=args.scratch,
                        say=lambda line: print(line, flush=True))
    except (OSError, ValueError) as e:
        why = f"{image.name} could not be read ({type(e).__name__}: {e})"
        print(memory.shown(f"== {image.name}: not read ({why})"))
        print(SolverResult("blocked", engine=ENGINE, notes=why).to_json(), flush=True)
        return 0
    print(solver_result(result).to_json(), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
