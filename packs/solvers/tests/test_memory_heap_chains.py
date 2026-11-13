"""B-067: ELF-core / memory heap-chain carver.

Every core here is synthesised with ``struct`` inside the test (never a core produced by running a
program): an ELF header, program headers, the PRPSINFO / PRSTATUS / NT_FILE notes, and segments. The
heap segment is a run of glibc chunks whose user data are linked records. The standard fixture
carries a real chain that spells a flag, a decoy that splices into the real chain's tail, an isolated
record, three records the carver must reject (a `next` outside the heap, non-printable text, a chunk
over the record-size bound), a file-backed rw .data segment holding a record-shaped decoy, and an
unbacked stack. Saved registers point at the real list head.

Timing: nothing here asserts a wall-clock upper bound. A deadline is tested by passing one that has
already passed, or with an injected step clock (memory._late replaced by a counter that turns "late" at
a chosen look), neither of which depends on machine speed. Memory is measured in characters of chain
text, which is exact, not in resident bytes.
"""

from __future__ import annotations

import functools
import struct
import sys
import time
import types
from pathlib import Path

import pytest

from ctf import event as _event, flagfmt as _flagfmt
from ctf.engines import manifest as _manifest
from ctf.intake import engines as _intake_engines, guard as _intake_guard
import solvers.toolkits.heap_families as heap_families
import solvers.toolkits.heap_primitives as heap_primitives
import solvers.toolkits.memory as memory

REPO = Path(__file__).resolve().parents[1]
FLAG = "CSCTF{heap_chain_carved_ok}"
REAL = ["CSCTF{", "heap_", "chain_", "carved_", "ok}"]   # concatenates to FLAG
DECOY_HEAD = "stand_do"                                   # splices into the real tail ("carved_"...)
DECOY_TEXT = DECOY_HEAD + "carved_ok}"
ISOLATED = "random_"
R, W, X = 4, 2, 1                                          # PT_LOAD p_flags


@pytest.fixture(scope="module")
def ff():
    """The csctf flag format (prefixes CSCTF/chronos/CTF/flag)."""
    return _flagfmt.for_profile(_event.load("csctf"))


@pytest.fixture
def csctf_env(monkeypatch, tmp_path):
    """An active event and an empty workdir, so build_model / report resolve the flag format and the
    saved-tables folder the way a run does."""
    monkeypatch.setenv("CTF_EVENT", "csctf")
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))


# --- synthesis: a glibc heap ---------------------------------------------------------------------------

class Heap:
    """Glibc chunks laid end to end from `base`; each record's user data follows one record shape.
    rec() returns the record's user address (what a `next` pointer or a register holds)."""

    def __init__(self, base: int, word: int = 8, e: str = "<", shape: str = "next_len"):
        self.base, self.word, self.e, self.shape = base, word, e, shape
        self.chunks, self.end, self.links, self.size_fields = [], 0, {}, {}

    def _add(self, csize, prev_inuse, item):
        off = self.end
        self.end += csize
        self.chunks.append((off, csize, heap_families.PREV_INUSE if prev_inuse else 0, item))
        return self.base + off + 2 * self.word

    def rec(self, text, *, csize=None, prev_inuse=True, shape=None, claim_len=None, size_field=None):
        """One record. csize defaults to the smallest chunk whose own bytes hold the payload (it does
        not lean on the next chunk's prev_size word, so it also fits as the last chunk); prev_inuse is
        this chunk's own flag bit (False = the chunk BEFORE it is free); claim_len overrides the
        length field (a record that lies about its length); size_field overrides the header's size
        word (a header no allocator writes) while the chunk still takes csize bytes."""
        shape, w = shape or self.shape, self.word
        fixed = {"next_len": w + 4, "len_next": ((4 + w - 1) & ~(w - 1)) + w, "next_wlen": 2 * w,
                 "wlen_next": 2 * w, "next_cstr": w + 1}[shape]
        if csize is None:
            csize = max(4 * w, -(-(fixed + len(text) + 2 * w) // (2 * w)) * (2 * w))
        va = self._add(csize, prev_inuse, ("rec", shape, text, claim_len))
        if size_field is not None:
            self.size_fields[va] = size_field
        return va

    def raw(self, payload: bytes, csize: int, prev_inuse=True):
        return self._add(csize, prev_inuse, ("raw", payload))

    def chain(self, vas):
        for a, b in zip(vas, vas[1:]):
            self.links[a] = b

    def blob(self, tail: bytes = b"") -> bytes:
        w, e = self.word, self.e
        ptr = e + ("Q" if w == 8 else "I")
        buf = bytearray(self.end)
        for off, csize, flags, _item in self.chunks:
            size = self.size_fields.get(self.base + off + 2 * w, csize | flags)
            struct.pack_into(ptr, buf, off + w, size)                     # size | flags; prev_size stays 0
        for off, csize, _flags, item in self.chunks:
            user = off + 2 * w
            if item[0] == "raw":
                payload = item[1]
            else:
                _, shape, text, claim = item
                nxt = struct.pack(ptr, self.links.get(self.base + user, 0))
                tb = text.encode("latin-1")
                n = len(tb) if claim is None else claim
                if shape == "next_len":
                    payload = nxt + struct.pack(e + "I", n) + tb
                elif shape == "len_next":
                    payload = struct.pack(e + "I", n) + b"\x00" * (((4 + w - 1) & ~(w - 1)) - 4) + nxt + tb
                elif shape == "next_wlen":
                    payload = nxt + struct.pack(ptr, n) + tb
                elif shape == "wlen_next":
                    payload = struct.pack(ptr, n) + nxt + tb
                else:
                    payload = nxt + tb + b"\x00"
            # an allocated chunk owns csize - word bytes: its user data runs into the next prev_size
            assert len(payload) <= min(csize - w, self.end - user), "fixture: payload does not fit its chunk"
            buf[user:user + len(payload)] = payload
        return bytes(buf) + tail


# --- synthesis: an ELF core ----------------------------------------------------------------------------

def _note(e, ntype, body, name=b"CORE"):
    nb = name + b"\x00"
    return (struct.pack(e + "III", len(nb), len(body), ntype) + nb + b"\x00" * (-len(nb) % 4)
            + body + b"\x00" * (-len(body) % 4))


def _prstatus(machine, wide, e, regs):
    word, base = (8, 112) if wide else (4, 72)
    names = memory._GPR_NAMES.get(machine) or tuple(f"reg{i}" for i in range(27))
    assert set(regs) <= set(names), f"fixture: no such register(s) {set(regs) - set(names)}"
    st = bytearray(base + len(names) * word + 2 * word)
    for i, nm in enumerate(names):
        struct.pack_into(e + ("Q" if wide else "I"), st, base + i * word, regs.get(nm, 0))
    return bytes(st)


def _prpsinfo(wide, e, pid):
    if wide:
        pr = bytearray(136)
        struct.pack_into(e + "IIii", pr, 16, 1000, 1000, pid, 1)     # uid, gid, pid, ppid
        pr[40:42], pr[56:59] = b"t\x00", b"/t\x00"                    # pr_fname, pr_psargs
    else:
        pr = bytearray(124)
        struct.pack_into(e + "HHii", pr, 8, 1000, 1000, pid, 1)
        pr[28:30], pr[44:47] = b"t\x00", b"/t\x00"
    return bytes(pr)


def _nt_file(wide, e, entries):
    w = "Q" if wide else "I"
    body = struct.pack(e + w + w, len(entries), 0x1000)
    for start, end, _path in entries:
        body += struct.pack(e + w * 3, start, end, 0)
    return body + b"".join(path.encode() + b"\x00" for _s, _e, path in entries)


def build_core(segments, *, wide=True, machine=memory.EM_X86_64, e="<", regs=None, nt_files=(),
               osabi=0, etype=4, prstatus_name=b"CORE", pid=4242, more_threads=()) -> bytes:
    """An ELF file of e_type `etype` (4 = ET_CORE): one PT_NOTE (PRPSINFO, PRSTATUS, NT_FILE) and one
    PT_LOAD per (vaddr, flags, bytes) in `segments`, laid out in that order. `more_threads` adds one
    PRSTATUS note per register dict after the first thread's; pid=None leaves the PRPSINFO note out
    (a core that names no process)."""
    notes = ((_note(e, 3, _prpsinfo(wide, e, pid)) if pid is not None else b"")
             + _note(e, 1, _prstatus(machine, wide, e, regs or {}), prstatus_name)
             + b"".join(_note(e, 1, _prstatus(machine, wide, e, r)) for r in more_threads)
             + _note(e, 0x46494C45, _nt_file(wide, e, list(nt_files))))
    ehsize, phentsize = (64, 56) if wide else (52, 32)
    phnum = 1 + len(segments)
    notes_off = ehsize + phnum * phentsize
    buf = bytearray(notes_off) + notes
    offs = []
    for _vaddr, _flags, body in segments:
        offs.append(len(buf))
        buf += body
    buf[0:4] = b"\x7fELF"
    buf[4], buf[5], buf[6], buf[7] = (2 if wide else 1), (1 if e == "<" else 2), 1, osabi
    struct.pack_into(e + "HHI", buf, 16, etype, machine, 1)
    if wide:
        struct.pack_into(e + "Q", buf, 0x20, ehsize)                  # e_phoff
        struct.pack_into(e + "HHH", buf, 0x34, ehsize, phentsize, phnum)
    else:
        struct.pack_into(e + "I", buf, 0x1C, ehsize)
        struct.pack_into(e + "HHH", buf, 0x28, ehsize, phentsize, phnum)

    def phdr(i, ptype, flags, off, vaddr, size):
        at = ehsize + i * phentsize
        if wide:
            struct.pack_into(e + "IIQQQQQQ", buf, at, ptype, flags, off, vaddr, 0, size, size, 0x1000)
        else:
            struct.pack_into(e + "IIIIIIII", buf, at, ptype, off, vaddr, 0, size, size, flags, 0x1000)

    phdr(0, 4, 0, notes_off, 0, len(notes))                           # PT_NOTE
    for i, (vaddr, flags, body) in enumerate(segments):
        phdr(1 + i, 1, flags, offs[i], vaddr, len(body))
    return bytes(buf)


def std(*, wide=True, machine=memory.EM_X86_64, e="<", regs="default", nt_extra=(), listed_as=None,
        heap_tail=b"", last=None):
    """The standard fixture. Returns a namespace: core (bytes), head / decoy / iso (record addresses),
    vas (the five real records), heap_base, stack_base, data_base, text_base.

    File order is text, .data, stack, heap, so the heap is the last thing in the file (a truncated
    copy cuts into it). Heap order: the five real records, the decoy head, three records that must be
    rejected, the isolated record (the last chunk). `listed_as` lists the heap in NT_FILE under that
    path; `last` adds one more record after the isolated one."""
    word = 8 if wide else 4
    text_base, data_base, heap_base, stack_base = ((0x400000, 0x601000, 0x555555550000, 0x7ffffffde000) if wide
                                                   else (0x08048000, 0x0804a000, 0x08050000, 0xbffdf000))
    h = Heap(heap_base, word, e)
    vas = [h.rec(t) for t in REAL]
    h.chain(vas)
    decoy = h.rec(DECOY_HEAD)
    h.links[decoy] = vas[3]
    outside = h.rec("outside_")
    h.links[outside] = text_base + 0x10                  # a `next` that leaves the heap
    h.rec("bad\x01text")                                 # non-printable text
    h.rec("oversize", csize=memory.RECORD_MAX_CHUNK + 2 * word)   # a chunk over the record-size bound
    iso = h.rec(ISOLATED)
    extra = h.rec(**last) if last else None
    d = Heap(data_base, word, e)
    d.rec("datadecoy")                                    # record-shaped bytes in the file-backed .data
    heap_bytes = h.blob(heap_tail)
    nt = [(text_base, text_base + 0x1000, "/t"), (data_base, data_base + 0x1000, "/t")] + list(nt_extra)
    if listed_as:
        nt.append((heap_base, heap_base + len(heap_bytes), listed_as))
    if regs == "default":
        regs = ({"rdi": vas[0], "rax": vas[0], "rcx": decoy} if machine == memory.EM_X86_64
                else {"eax": vas[0], "edi": vas[0]} if machine == memory.EM_386 else {})
    elif callable(regs):
        regs = regs(types.SimpleNamespace(head=vas[0], decoy=decoy, iso=iso, vas=vas))
    core = build_core([(text_base, R | X, b"\x7fELF" + b"\x00" * 0x7c),
                       (data_base, R | W, d.blob()),
                       (stack_base, R | W, b"A" * 0x80),
                       (heap_base, R | W, heap_bytes)],
                      wide=wide, machine=machine, e=e, regs=regs, nt_files=nt)
    return types.SimpleNamespace(core=core, head=vas[0], decoy=decoy, iso=iso, vas=vas, extra=extra, heap=h,
                                 heap_base=heap_base, stack_base=stack_base, data_base=data_base,
                                 text_base=text_base, heap_len=len(heap_bytes))


def carve(fx_or_core, **kw):
    core = fx_or_core.core if hasattr(fx_or_core, "core") else fx_or_core
    return memory.heap_chains(memory.elf_core(core), core, **kw)


def dict_core(h: Heap, regs=None, machine=memory.EM_X86_64, tail=b"", lead=b""):
    """(elf_core-shaped dict, bytes) around one heap: the carver's input without a full ELF file.
    `lead` is bytes of the same segment that come before the heap (the segment then starts
    len(lead) below the heap base)."""
    prefix = bytearray(64)
    prefix[0:4] = b"\x7fELF"
    prefix[4], prefix[5] = (2 if h.word == 8 else 1), (1 if h.e == "<" else 2)
    blob = lead + h.blob(tail)
    core = {"bits": 64 if h.word == 8 else 32, "machine": machine, "registers": [regs] if regs else [], "files": [],
            "segments": [{"vaddr": h.base - len(lead), "off": len(prefix), "filesz": len(blob), "memsz": len(blob),
                          "perms": "rw-", "flags": 6}]}
    return core, bytes(prefix) + blob


def texts(out):
    return sorted(c["text"] for c in out["chains"])


# --- elf_core: segment offsets and registers -----------------------------------------------------------

def test_elf_core_adds_segment_offsets_and_registers_lp64():
    fx = std()
    c = memory.elf_core(fx.core)
    assert memory.image_format(fx.core) == "elf_core"
    assert c["bits"] == 64 and c["machine"] == memory.EM_X86_64 and c["pid"] == 4242
    heap_seg = next(s for s in c["segments"] if s["vaddr"] == fx.heap_base)
    assert fx.core[heap_seg["off"]:heap_seg["off"] + heap_seg["filesz"]] == fx.heap.blob()   # off is the file offset
    assert len(c["registers"]) == 1
    t0 = c["registers"][0]
    assert (t0["rdi"], t0["rax"], t0["rcx"]) == (fx.head, fx.head, fx.decoy)
    assert {"rip", "rsp", "rbp"} <= set(t0)


def test_elf_core_registers_lp32():
    fx = std(wide=False, machine=memory.EM_386)
    c = memory.elf_core(fx.core)
    assert c["bits"] == 32 and c["machine"] == memory.EM_386
    t0 = c["registers"][0]
    assert (t0["eax"], t0["edi"]) == (fx.head, fx.head)
    assert "eip" in t0 and "esp" in t0


def test_elf_core_registers_big_endian():
    # an unknown big-endian machine: registers are named by position and read in the file's byte order
    fx = std(e=">", machine=21, regs=lambda v: {"reg3": v.head})
    c = memory.elf_core(fx.core)
    assert c["registers"][0]["reg3"] == fx.head and c["registers"][0]["reg0"] == 0


def test_type_1_note_that_is_not_core_prstatus_is_ignored():
    # note type 1 under the name GNU is an ABI tag, not NT_PRSTATUS: it must not be read as registers
    assert memory.elf_core(std().core)["registers"]
    fx = std()
    other = build_core([(fx.heap_base, R | W, fx.heap.blob())], regs={"rdi": fx.head}, prstatus_name=b"GNU")
    assert memory.elf_core(other)["registers"] == []


def test_prstatus_unknown_machine_falls_back_to_regN():
    body = bytearray(112 + 8 * 4)
    for i in range(4):
        struct.pack_into("<Q", body, 112 + i * 8, 0x1000 + i)
    regs = memory._prstatus_regs(bytes(body), 0x9999, "<", True)
    assert regs == {"reg0": 0x1000, "reg1": 0x1001, "reg2": 0x1002, "reg3": 0x1003}


def test_prstatus_truncated_known_machine_is_rejected():
    assert memory._prstatus_regs(b"\x00" * 200, memory.EM_X86_64, "<", True) == {}


def test_prstatus_unknown_machine_names_every_register_up_to_64():
    # an unknown machine's register file is named by position: all of it, up to 64 registers
    def note(count):
        return bytes(112) + b"".join(struct.pack("<Q", 0x100 + i) for i in range(count))
    ten = memory._prstatus_regs(note(10), 0x9999, "<", True)
    assert ten == {f"reg{i}": 0x100 + i for i in range(10)}
    capped = memory._prstatus_regs(note(70), 0x9999, "<", True)
    assert capped == {f"reg{i}": 0x100 + i for i in range(64)}


def test_register_of_a_later_thread_names_the_head(csctf_env):
    # the crashing thread's registers say nothing; a second thread's rdi holds the real head. Every
    # thread's registers are read and cross-referenced, so the short real list outranks a longer decoy
    h = Heap(0x555555550000)
    h.chain([h.rec(f"d{i}") for i in range(8)])
    real = [h.rec(t) for t in ("t2_", "holds_", "this")]
    h.chain(real)
    core = build_core([(h.base, R | W, h.blob())], regs={"rip": 0x401000}, more_threads=[{"rdi": real[0]}])
    c = memory.elf_core(core)
    assert len(c["registers"]) == 2 and c["registers"][0]["rdi"] == 0 and c["registers"][1]["rdi"] == real[0]
    out = memory.heap_chains(c, core)
    assert (out["best"]["text"], out["best"]["head_regs"]) == ("t2_holds_this", ["rdi"])
    assert "   2 thread(s), regs: rdi=0x0, rsi=0x0, rdx=0x0, rax=0x0, rip=0x401000, rsp=0x0" in \
        memory.report_text({"x.core": core}).splitlines()


@pytest.mark.parametrize("phoff", [1 << 63, (1 << 64) - 1, 1 << 40])
def test_program_header_offset_no_file_holds_is_not_an_exception(phoff, csctf_env, tmp_path, capsys):
    # e_phoff of 2^63 or more made struct raise OverflowError (not struct.error) out of elf_core, and
    # so out of build_model, report_text and the --heap-chains command (found by byte-flip fuzzing)
    fx = std()
    bad = bytearray(fx.core)
    struct.pack_into("<Q", bad, 0x20, phoff)
    bad = bytes(bad)
    c = memory.elf_core(bad)
    assert c["segments"] == [] and c["registers"] == [] and c["pid"] is None and c["bits"] == 64
    model = memory.build_model({"bad.core": bad})
    assert model.recovered == [] and "bad.core: no PT_LOAD segments: not an ELF core model" in model.notes
    assert "   heap: no PT_LOAD segments: not an ELF core model" in memory.report_text({"bad.core": bad}).splitlines()
    path = tmp_path / "bad.core"
    path.write_bytes(bad)
    assert memory.main(["--heap-chains", str(path)]) == 0
    assert "   heap: no PT_LOAD segments: not an ELF core model" in capsys.readouterr().out.splitlines()


# --- heap region location ------------------------------------------------------------------------------

def test_heap_regions_are_the_unbacked_rw_segments_only():
    fx = std()
    regions = memory._heap_regions(memory.elf_core(fx.core))
    # the brk heap and the stack (rw, nothing in NT_FILE); not the r-x text, and not the rw .data
    # segment, which NT_FILE lists as file-backed
    assert {(r["vaddr"], r["source"]) for r in regions} == {(fx.heap_base, "unbacked-rw"), (fx.stack_base, "unbacked-rw")}


def test_file_backed_data_segment_is_not_carved(ff):
    # the .data segment holds a well-formed record ("datadecoy"); it is file-backed, so it is no heap
    out = carve(std(), flag_format=ff)
    assert "datadecoy" not in {n["text"] for n in out["nodes"]}
    assert out["warnings"] == []


def test_nt_file_heap_mapping_is_the_region(ff):
    # the heap is listed in NT_FILE as [heap]: it is then "backed", so only the [heap] rule finds it
    fx = std(listed_as="[heap]")
    out = carve(fx, flag_format=ff)
    assert {(r["vaddr"], r["filesz"], r["source"]) for r in out["heap"]} == {
        (fx.heap_base, fx.heap_len, "nt_file:heap"), (fx.stack_base, 0x80, "unbacked-rw")}
    assert out["best"]["text"] == FLAG


@pytest.mark.parametrize("path", ["[anon:heap]", "[anon:scudo Heap]", "/memfd:heap-arena (deleted)"])
def test_nt_file_mapping_whose_path_names_a_heap_is_the_region(path, ff):
    # not only the literal "[heap]": any listed mapping whose path names a heap, in either case
    fx = std(listed_as=path)
    out = carve(fx, flag_format=ff)
    assert (fx.heap_base, fx.heap_len, "nt_file:heap") in {(r["vaddr"], r["filesz"], r["source"]) for r in out["heap"]}
    assert out["best"]["text"] == FLAG and out["warnings"] == []


def test_unbacked_rwx_segment_is_no_heap_region():
    # an rwx page with nothing in NT_FILE is a JIT or shellcode page, not a heap: record-shaped bytes
    # in it are not carved while there is an rw segment
    h = Heap(0x555555550000)
    h.rec("heap_rec")
    j = Heap(0x7f0000000000)
    j.rec("jit_rec")
    out = carve(build_core([(j.base, R | W | X, j.blob()), (h.base, R | W, h.blob())]))
    assert [(r["vaddr"], r["perms"], r["source"]) for r in out["heap"]] == [(h.base, "rw-", "unbacked-rw")]
    assert texts(out) == ["heap_rec"]
    # with no rw segment at all it is carved by the fallback, which says so
    out = carve(build_core([(j.base, R | W | X, j.blob())]))
    assert [(r["vaddr"], r["source"]) for r in out["heap"]] == [(j.base, "rw-fallback")]
    assert texts(out) == ["jit_rec"] and any("rw-fallback" in w for w in out["warnings"])


def test_nt_file_heap_mapping_inside_a_segment_is_cut_to_the_mapping():
    core = {"segments": [{"vaddr": 0x10000, "off": 0x400, "filesz": 0x3000, "memsz": 0x3000, "perms": "rw-"}],
            "files": [{"start": 0x11000, "end": 0x12000, "path": "[heap]"}]}
    assert memory._heap_regions(core) == [{"vaddr": 0x11000, "off": 0x1400, "filesz": 0x1000, "memsz": 0x1000,
                                           "perms": "rw-", "source": "nt_file:heap"}]


def test_rw_fallback_when_every_rw_segment_is_file_backed(ff):
    # every rw segment is listed in NT_FILE under a name that is no heap: nothing is unbacked, so every
    # rw segment is carved, and the result says it fell back
    fx = std(listed_as="/dev/zero (deleted)", nt_extra=[(0x7ffffffde000, 0x7ffffffde080, "/memfd:stack")])
    out = carve(fx, flag_format=ff)
    assert {r["source"] for r in out["heap"]} == {"rw-fallback"}
    assert {r["vaddr"] for r in out["heap"]} == {fx.data_base, fx.stack_base, fx.heap_base}
    assert out["best"]["text"] == FLAG and out["best"]["is_flag"]
    assert any("rw-fallback" in w for w in out["warnings"]) and "rw-fallback" in out["note"]


def test_no_heap_region_is_named():
    fx = std()
    only_text = build_core([(fx.text_base, R | X, b"\x7fELF" + b"\x00" * 0x7c)], regs={"rdi": fx.head})
    out = carve(only_text)
    assert out["best"] is None and out["heap"] == [] and out["note"].startswith("no heap region located")
    out = memory.heap_chains({}, b"")
    assert out["best"] is None and out["note"].startswith("no PT_LOAD segments: not an ELF core model")
    # a file cut off before its rw segments begin has heap regions in its headers and none in its bytes
    c = memory.elf_core(fx.core)
    cut = fx.core[:min(s["off"] for s in c["segments"] if s["perms"] == "rw-" and s["vaddr"] != fx.data_base)]
    out = carve(cut)
    assert [r["vaddr"] for r in out["heap"]] == [fx.stack_base, fx.heap_base]
    assert out["best"] is None and out["note"].startswith("no heap region located")


def test_register_at_the_first_bytes_of_a_segment_has_no_chunk_header_before_it():
    # a user address needs its 2*word header inside the same segment: bytes that merely precede the
    # segment in the file are another mapping's, however chunk-like they look
    h = Heap(0x555555550000)
    first = h.rec("first")
    core, data = dict_core(h)
    data = bytearray(data)
    struct.pack_into("<QQ", data, 48, 0, 0x31)             # a chunk header's shape, just before the segment
    spans = memory._heap_spans(memory._heap_regions(core), len(data))
    assert memory._chunk_of(bytes(data), spans, h.base, 8, "<Q") is None
    assert memory._chunk_of(bytes(data), spans, first, 8, "<Q")["user_va"] == first


# --- the chunk rule ------------------------------------------------------------------------------------

@pytest.mark.parametrize("bits", [64, 32])
def test_chunk_size_rule_is_the_heap_toolkits_rule(bits):
    # the size rule the carver scans with is heap_primitives._chunk_size, value for value
    def toolkit_accepts(value):
        try:
            heap_primitives._chunk_size(value, bits)
            return True
        except heap_primitives.PrimitiveBuildError:
            return False
    for value in range(0, 0x120):
        assert memory._is_chunk_size(value, bits // 8) == toolkit_accepts(value), hex(value)
    assert memory.HEAP_PREV_INUSE is heap_families.PREV_INUSE


def test_record_using_the_whole_usable_size_is_carved():
    # an allocated chunk owns size - word bytes: its last word is the next chunk's prev_size field
    h = Heap(0x555555550000)
    full = "x" * (0x30 - 8 - 12)                          # next(8) + len(4) + text fills the usable size
    a = h.rec(full, csize=0x30)
    b = h.rec("tail")
    h.links[a] = b
    out = memory.heap_chains(*dict_core(h))
    assert texts(out) == [full + "tail"]


def test_rejected_records_are_not_nodes(ff):
    # of the ten heap chunks only seven are records: a `next` outside the heap, non-printable text
    # and a chunk over RECORD_MAX_CHUNK are each rejected
    fx = std()
    out = carve(fx, flag_format=ff)
    assert sorted(n["text"] for n in out["nodes"]) == sorted(REAL + [DECOY_HEAD, ISOLATED])
    assert out["shape"] == {"name": "next_len", "consistent": 7, "nodes": 7}


def test_a_chunk_at_the_record_size_bound_is_carved():
    h = Heap(0x555555550000)
    h.rec("edge", csize=memory.RECORD_MAX_CHUNK)
    h.rec("after")
    assert texts(memory.heap_chains(*dict_core(h))) == ["after", "edge"]


def test_bad_size_field_before_the_end_of_file_is_skipped(ff):
    # a size that is no multiple of 2*word (0x19 = 0x18 | PREV_INUSE) sixteen bytes before the end
    # of the file: once an uncaught struct.error, now simply not a chunk
    fx = std(heap_tail=struct.pack("<QQQ", 0, 0x19, 0x4141414141414141))
    out = carve(fx, flag_format=ff)
    assert texts(out) == sorted([FLAG, DECOY_TEXT, ISOLATED])
    assert out["partial"] == []


def test_record_under_a_size_no_allocator_writes_is_not_carved():
    # 0x28 is no multiple of 16: a well-formed record behind such a header is not a glibc chunk
    h = Heap(0x555555550000)
    h.rec("odd_", csize=0x30, size_field=0x28 | heap_families.PREV_INUSE)
    h.rec("even")
    assert texts(memory.heap_chains(*dict_core(h))) == ["even"]


def test_last_record_cannot_claim_bytes_past_its_chunk():
    # the last chunk's user data ends where the file does; a length that needs the word after it
    # (the "next prev_size" that is not there) must reject the record, not read a short slice
    h = Heap(0x555555550000)
    h.rec("good")
    h.rec("abcd", csize=0x20, claim_len=12)               # needs user bytes 12..24, the chunk has 16
    assert texts(memory.heap_chains(*dict_core(h))) == ["good"]


@pytest.mark.parametrize("cut", [1, 7, 8, 9, 16, 24, 31])
def test_truncated_core_still_carves_and_keeps_process_facts(cut, ff, csctf_env):
    # the file ends inside the last chunk (the isolated record): no exception anywhere, that record
    # is gone, the flag chain and the process facts are still there
    fx = std()
    short = fx.core[:-cut]
    out = carve(short, flag_format=ff)
    assert texts(out) == sorted([FLAG, DECOY_TEXT])
    assert out["best"]["text"] == FLAG
    model = memory.build_model({"relay.core": short})
    assert model.procs[4242]["src"] == "elfcore"
    assert [r["text"] for r in model.recovered] == [FLAG]
    assert "RECOVERED: " + repr(FLAG) in memory.report_text({"relay.core": short})


def test_scan_starts_at_the_first_aligned_address_of_a_segment():
    # the segment begins 8 bytes below a 16-aligned chunk address: chunk headers sit at aligned
    # ADDRESSES, not at aligned offsets from wherever the segment happens to start
    h = Heap(0x555555550000)
    h.chain([h.rec("off_"), h.rec("by_8")])
    assert texts(memory.heap_chains(*dict_core(h, lead=b"\x00" * 8))) == ["off_by_8"]


def test_register_holding_an_unaligned_address_starts_no_record():
    # record-shaped bytes at an address no chunk can have (8 mod 16): the aligned scan never sees
    # them, and a register that points there must not conjure a record out of them either
    h = Heap(0x555555550000)
    fake = struct.pack("<QQQQI", 0x1111, 0, 0x21, 0, 4) + b"fake"      # junk, then a chunk header and a record
    holder = h.raw(fake, 0x60)
    h.rec("real")
    core, data = dict_core(h, regs={"rdi": holder + 24})
    out = memory.heap_chains(core, data)
    assert sorted(n["text"] for n in out["nodes"]) == ["real"]


def test_record_freed_before_the_dump_is_marked():
    # PREV_INUSE of the chunk after a record says whether the record was still allocated
    h = Heap(0x555555550000)
    a, b = h.rec("live_"), h.rec("freed")
    h.rec("guard", prev_inuse=False)                      # its PREV_INUSE is clear: `b` is free
    h.chain([a, b])
    out = memory.heap_chains(*dict_core(h))
    by_text = {n["text"]: n["inuse"] for n in out["nodes"]}
    assert by_text == {"live_": True, "freed": False, "guard": None}   # the last chunk has no successor
    chain = next(c for c in out["chains"] if c["text"] == "live_freed")
    assert chain["freed"] == 1


@pytest.mark.parametrize("word,e", [(8, "<"), (4, "<"), (8, ">")])
def test_inuse_is_read_only_from_a_whole_header_after_the_record(word, e):
    # the bit is in the size word of the NEXT chunk's header. A file that ends inside that header (any
    # 0 .. 2*word-1 bytes of it) gives None, never a read past the end; a whole header is read
    def last_inuse(tail):
        h = Heap(0x555555550000 if word == 8 else 0x08050000, word, e)
        h.rec("edge")
        out = memory.heap_chains(*dict_core(h, tail=tail))
        assert texts(out) == ["edge"]
        return out["nodes"][0]["inuse"]
    for extra in range(2 * word):
        assert last_inuse(b"\xff" * extra) is None, extra
    ptr = e + ("Q" if word == 8 else "I")
    assert last_inuse(struct.pack(ptr, 0) + struct.pack(ptr, 0x100 | heap_families.PREV_INUSE)) is True
    assert last_inuse(struct.pack(ptr, 0) + struct.pack(ptr, 0x100)) is False


# --- the carve: chains and where they start ------------------------------------------------------------

def test_heap_chains_lp64_recovers_flag_from_register_head(ff):
    fx = std()
    out = carve(fx, flag_format=ff)
    b = out["best"]
    assert (b["text"], b["is_flag"], b["head_va"], b["vas"]) == (FLAG, True, fx.head, fx.vas)
    assert b["head_regs"] == ["rax", "rdi"]
    assert out["partial"] == [] and out["warnings"] == []
    assert out["note"] == f"heap chain (next_len, 7 records): {FLAG!r}, from register rax/rdi [flag]"


def test_heap_chains_lp32_recovers_flag(ff):
    fx = std(wide=False, machine=memory.EM_386)
    out = carve(fx, flag_format=ff)
    b = out["best"]
    assert (b["text"], b["is_flag"], b["head_va"]) == (FLAG, True, fx.head)
    assert set(b["head_regs"]) == {"eax", "edi"}
    assert texts(out) == sorted([FLAG, DECOY_TEXT, ISOLATED])


def test_heap_chains_big_endian(ff):
    fx = std(e=">", machine=21, regs=lambda v: {"reg3": v.head})
    out = carve(fx, flag_format=ff)
    assert out["best"]["text"] == FLAG and out["best"]["head_regs"] == ["reg3"]
    assert texts(out) == sorted([FLAG, DECOY_TEXT, ISOLATED])


def test_exactly_one_chain_per_list_head(ff):
    # three lists: the real one, the decoy that splices into its tail, the isolated record. A record
    # something points to starts no chain of its own.
    out = carve(std(), flag_format=ff)
    assert texts(out) == sorted([FLAG, DECOY_TEXT, ISOLATED])
    assert out["chains"][0]["text"] == FLAG
    decoy = next(c for c in out["chains"] if c["text"] == DECOY_TEXT)
    assert decoy["score"] < out["chains"][0]["score"] and decoy["head_regs"] == ["rcx"]


def test_chain_starts_at_the_record_a_register_holds_even_when_a_decoy_points_to_it(ff):
    # a decoy record links to the real first record, so the real head is no list head any more; the
    # register still names it (the rule read off the handout: follow next from rdi)
    h = Heap(0x555555550000)
    decoy = h.rec("decoy_")
    real = [h.rec(t) for t in ("CSCTF{", "reg_", "head}")]
    h.chain([decoy] + real)
    core, data = dict_core(h, regs={"rdi": real[0], "rax": real[0]})
    for fmt in (ff, None):
        out = memory.heap_chains(core, data, flag_format=fmt)
        assert out["best"]["text"] == "CSCTF{reg_head}"
        assert out["best"]["head_va"] == real[0] and out["best"]["head_regs"] == ["rdi", "rax"]
        whole = next(c for c in out["chains"] if c["head_va"] == decoy)
        assert (whole["text"], whole["head_regs"], whole["regs"]) == ("decoy_CSCTF{reg_head}", [], ["rax", "rdi"])
        assert len(out["chains"]) == 2
    assert memory.heap_chains(core, data, flag_format=ff)["best"]["is_flag"] is True


def test_closed_loop_is_walked_once_and_ends():
    h = Heap(0x555555550000)
    a, b, c = h.rec("A"), h.rec("B"), h.rec("C")
    h.chain([a, b, c, a])                                 # a pure cycle: no record is a list head
    lone = h.rec("lone")
    core, data = dict_core(h)
    out = memory.heap_chains(core, data, max_walk=50)
    loop = next(ch for ch in out["chains"] if ch["loop"])
    assert (loop["text"], loop["vas"]) == ("ABC", [a, b, c])
    assert texts(out) == ["ABC", "lone"] and out["partial"] == []


def test_register_inside_a_closed_loop_ends():
    h = Heap(0x555555550000)
    a, b, c = h.rec("A"), h.rec("B"), h.rec("C")
    h.chain([a, b, c, a])
    out = memory.heap_chains(*dict_core(h, regs={"rdi": b}), max_walk=50)
    assert [(ch["text"], ch["loop"], ch["head_regs"]) for ch in out["chains"]] == [("BCA", True, ["rdi"])]
    assert out["partial"] == []


def test_list_that_runs_into_a_loop_ends_at_the_repeat():
    h = Heap(0x555555550000)
    d, a, b = h.rec("D"), h.rec("A"), h.rec("B")
    h.chain([d, a, b, a])
    out = memory.heap_chains(*dict_core(h), max_walk=50)
    assert [(c["text"], c["loop"]) for c in out["chains"]] == [("DAB", True)]
    assert out["partial"] == []


# --- ranking -------------------------------------------------------------------------------------------

@pytest.mark.parametrize("machine,wide,primary,other", [
    (memory.EM_X86_64, True, "rdi", "rcx"),
    (memory.EM_X86_64, True, "rax", "rbx"),
    (memory.EM_386, False, "eax", "ecx"),
    (memory.EM_AARCH64, True, "x0", "x5"),
    (memory.EM_ARM, False, "r0", "r4"),
])
def test_primary_register_head_beats_a_longer_chain_in_another_register(machine, wide, primary, other):
    # no flag format: only the registers can tell the real list (3 records, its head in the arg0 /
    # return register) from a decoy list twice as long whose head sits in some other register
    h = Heap(0x555555550000 if wide else 0x08050000, 8 if wide else 4)
    decoy = [h.rec(f"d{i}_") for i in range(6)]
    real = [h.rec(t) for t in ("re", "al", "!")]
    h.chain(decoy)
    h.chain(real)
    core, data = dict_core(h, regs={primary: real[0], other: decoy[0]}, machine=machine)
    out = memory.heap_chains(core, data, flag_format=None)
    assert (out["best"]["text"], out["best"]["head_regs"]) == ("real!", [primary])
    assert [c["text"] for c in out["chains"]] == ["real!", "d0_d1_d2_d3_d4_d5_"]
    # and it is the register that decides: swap them and the other list wins
    core, data = dict_core(h, regs={primary: decoy[0], other: real[0]}, machine=machine)
    assert memory.heap_chains(core, data, flag_format=None)["best"]["text"] == "d0_d1_d2_d3_d4_d5_"


def test_register_reference_order_primary_other_midchain_none():
    # four lists of three records. Addresses rise D < C < B < A, so every tie would fall the wrong
    # way: the order below holds only if primary head > other-register head > mid-chain > nothing.
    h = Heap(0x555555550000)
    lists = {}
    for name in "DCBA":
        lists[name] = [h.rec(f"{name}{i}") for i in range(3)]
        h.chain(lists[name])
    core, data = dict_core(h, regs={"rdi": lists["A"][0], "rcx": lists["B"][0], "rbx": lists["C"][1]})
    out = memory.heap_chains(core, data, flag_format=None)
    assert [(c["text"], c["score"]) for c in out["chains"]] == [
        ("A0A1A2", 1003),          # head in the arg0 register
        ("B0B1B2", 403),           # head in another register
        ("C1C2", 402),             # the list as it starts at the record rbx holds
        ("C0C1C2", 103),           # a register points into the list, not at its head
        ("D0D1D2", 3),             # no register
    ]
    assert out["chains"][3]["regs"] == ["rbx"] and out["chains"][3]["head_regs"] == []


def test_flag_format_tiers(ff):
    nodes = {va: {"inuse": True} for va in range(1, 9)}
    chains = [{"vas": [1], "text": "plain", "text_cut": False, "loop": False},
              {"vas": [2], "text": "xx CSCTF{inside} xx", "text_cut": False, "loop": False},      # holds a prefix
              {"vas": [3], "text": "CSCTF{no_closing_brace", "text_cut": False, "loop": False},   # begins with a prefix
              {"vas": [4], "text": "CSCTF{complete}", "text_cut": False, "loop": False}]          # a flag
    ranked = memory._rank_chains(chains, nodes, {}, ("rdi",), ff)
    assert [(r["text"], r["score"], r["is_flag"]) for r in ranked] == [
        ("CSCTF{complete}", 5001, True), ("CSCTF{no_closing_brace", 801, False),
        ("xx CSCTF{inside} xx", 51, False), ("plain", 1, False)]
    # without a format nothing is a flag and nothing gets a format point
    assert {r["score"] for r in memory._rank_chains(chains, nodes, {}, ("rdi",), None)} == {1}
    # length adds one point per record and stops at 64; past that the longer chain still comes first
    long = [{"vas": [1] * 65, "text": "y", "text_cut": False, "loop": False}, {"vas": [2] * 70, "text": "x", "text_cut": False, "loop": False}]
    assert [(r["text"], r["score"]) for r in memory._rank_chains(long, nodes, {}, (), None)] == [("x", 64), ("y", 64)]
    # chains nothing tells apart are listed by address
    same = [{"vas": [5], "text": "p", "text_cut": False, "loop": False}, {"vas": [2], "text": "q", "text_cut": False, "loop": False}]
    assert [r["head_va"] for r in memory._rank_chains(same, nodes, {}, (), None)] == [2, 5]


def test_event_without_a_known_prefix_still_ranks_a_flag_shaped_chain():
    # prefixes = []: any word{...} is a flag, and there is no prefix to give prefix points for
    import datetime
    unknown = _flagfmt.for_profile(_event.parse({
        "slug": "b067-unknown", "name": "unknown flag prefix",
        "dates": {"start": datetime.date(2026, 1, 1), "end": datetime.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": "https://board.b067.test"},
        "flag": {"prefixes": []},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": ["localhost"]},
    }, src="tests/test_memory_heap_chains.py"))
    nodes = {1: {"inuse": True}, 2: {"inuse": True}}
    chains = [{"vas": [1], "text": "CSCTF{no_closing_brace", "text_cut": False, "loop": False},
              {"vas": [2], "text": "anyword{body}", "text_cut": False, "loop": False}]
    ranked = memory._rank_chains(chains, nodes, {}, (), unknown)
    assert [(r["text"], r["score"], r["is_flag"]) for r in ranked] == [
        ("anyword{body}", 5001, True), ("CSCTF{no_closing_brace", 1, False)]


def test_complete_flag_beats_a_register_headed_prefix_lead(ff):
    # the decoy has everything but the closing brace and sits in rdi; a complete flag still wins
    h = Heap(0x555555550000)
    decoy = [h.rec(t) for t in ("CSCTF{", "almost_", "a_flag")]
    real = [h.rec(t) for t in ("CSCTF{", "whole}")]
    h.chain(decoy)
    h.chain(real)
    core, data = dict_core(h, regs={"rdi": decoy[0]})
    out = memory.heap_chains(core, data, flag_format=ff)
    assert [(c["text"], c["score"]) for c in out["chains"]] == [("CSCTF{whole}", 5002), ("CSCTF{almost_a_flag", 1803)]


# --- the layout search ---------------------------------------------------------------------------------

@pytest.mark.parametrize("word,e,shape", [
    (8, "<", "next_len"), (8, "<", "len_next"), (8, "<", "next_wlen"), (8, "<", "next_cstr"),
    (8, ">", "wlen_next"),        # on little-endian bytes {len(word), next} reads the same as {len, pad, next}
    (4, "<", "next_len"), (4, "<", "len_next"), (4, "<", "next_cstr"),
])
def test_layout_search_finds_each_record_shape(word, e, shape, ff):
    h = Heap(0x555555550000 if word == 8 else 0x08050000, word, e, shape)
    vas = [h.rec(t) for t in ("CSCTF{", "shape_", "search}")]
    h.chain(vas)
    out = memory.heap_chains(*dict_core(h), flag_format=ff)
    assert out["shape"]["name"] == shape
    assert texts(out) == ["CSCTF{shape_search}"] and out["best"]["is_flag"]


def test_layout_search_prefers_the_shape_whose_chain_ranks_best(ff):
    # a six-record {next, len, text} list and a three-record {next, text\0} list that spells the flag:
    # the shape with more records must lose to the shape with the flag (or the register-held head)
    h = Heap(0x555555550000)
    h.chain([h.rec(f"d{i}") for i in range(6)])
    vas = [h.rec(t, shape="next_cstr") for t in ("CSCTF{", "by_", "rank}")]
    h.chain(vas)
    out = memory.heap_chains(*dict_core(h), flag_format=ff)
    assert out["shape"]["name"] == "next_cstr" and out["best"]["text"] == "CSCTF{by_rank}"
    out = memory.heap_chains(*dict_core(h, regs={"rdi": vas[0]}), flag_format=None)
    assert out["shape"]["name"] == "next_cstr" and out["best"]["text"] == "CSCTF{by_rank}"
    # with neither signal the shape that links more records is kept
    assert memory.heap_chains(*dict_core(h), flag_format=None)["shape"]["name"] == "next_len"


def test_layout_search_breaks_a_score_tie_by_linked_records_then_by_records():
    # no register, no flag format: {next, len, text} (searched first) and {next, text\0} each rebuild
    # a best chain of two records, so the scores tie. The layout that links more records is kept ...
    h = Heap(0x555555550000)
    h.chain([h.rec("a1"), h.rec("a2")])
    h.chain([h.rec("b1", shape="next_cstr"), h.rec("b2", shape="next_cstr")])
    for i in range(3):
        h.rec(f"c{i}", shape="next_cstr")
    out = memory.heap_chains(*dict_core(h))
    assert out["shape"] == {"name": "next_cstr", "consistent": 5, "nodes": 5} and out["best"]["text"] == "b1b2"
    # ... and with the linked counts tied too (the extra record's `next` points into the heap at no
    # record, so it is a record but not a linked one), the layout with more records
    h = Heap(0x555555550000)
    h.chain([h.rec("a1"), h.rec("a2")])
    h.chain([h.rec("b1", shape="next_cstr"), h.rec("b2", shape="next_cstr")])
    h.links[h.rec("dangling", shape="next_cstr")] = h.base + 8
    out = memory.heap_chains(*dict_core(h))
    assert out["shape"] == {"name": "next_cstr", "consistent": 2, "nodes": 3} and out["best"]["text"] == "b1b2"
    # linked records are compared before records: 3 linked of 3 beats 2 linked of 4
    h = Heap(0x555555550000)
    h.chain([h.rec("a1"), h.rec("a2")])
    for text in ("x1", "x2"):
        h.links[h.rec(text)] = h.base + 8
    h.chain([h.rec("b1", shape="next_cstr"), h.rec("b2", shape="next_cstr")])
    h.rec("c0", shape="next_cstr")
    out = memory.heap_chains(*dict_core(h))
    assert out["shape"] == {"name": "next_cstr", "consistent": 3, "nodes": 3}
    # the tie itself: without the extra records the layout searched first stays
    h = Heap(0x555555550000)
    h.chain([h.rec("a1"), h.rec("a2")])
    h.chain([h.rec("b1", shape="next_cstr"), h.rec("b2", shape="next_cstr")])
    assert memory.heap_chains(*dict_core(h))["shape"]["name"] == "next_len"


# --- bounds: every cut is named, and the register chain survives it -------------------------------------

def _positions_through(fx, index):
    """Aligned positions the scan visits up to and including the chunk header of real record `index`
    of the LP64 standard fixture: the whole stack segment (scanned first, in segment order), then the
    heap from its base."""
    return 0x80 // 16 + (fx.vas[index] - 16 - fx.heap_base) // 16 + 1


def test_scan_cap_leaves_a_partial_chain_and_says_so(ff):
    fx = std(regs={})
    out = carve(fx, flag_format=ff, max_scan=_positions_through(fx, 1))
    assert out["best"]["text"] == "CSCTF{heap_"            # two records in, the rest never visited
    assert out["partial"] == [f"the scan stopped at its cap of {_positions_through(fx, 1)} positions"]
    assert out["warnings"][0].startswith("PARTIAL carve (the scan stopped at its cap")
    assert out["note"].startswith("heap chain (next_len, 2 records): 'CSCTF{heap_'; PARTIAL carve (")


def test_scan_cap_zero_without_registers_finds_nothing_and_says_so(ff):
    out = carve(std(regs={}), flag_format=ff, max_scan=0)
    assert out["best"] is None and out["chains"] == []
    assert out["note"].startswith("no glibc chunk-shaped records in the heap region; PARTIAL carve (")


def test_register_chain_survives_the_scan_cap(ff):
    # nothing is scanned, yet the chain the registers name is followed straight through memory
    fx = std()
    out = carve(fx, flag_format=ff, max_scan=0)
    assert out["best"]["text"] == FLAG and out["best"]["vas"] == fx.vas
    assert out["partial"] == ["the scan stopped at its cap of 0 positions"]
    assert texts(out) == sorted([FLAG, DECOY_TEXT])        # rcx names the decoy head; the lone record is never seen


def test_scan_that_fits_its_cap_is_not_partial(ff):
    fx = std()
    exact = sum(r["filesz"] // 16 for r in carve(fx)["heap"])
    assert carve(fx, flag_format=ff, max_scan=exact)["partial"] == []
    assert carve(fx, flag_format=ff, max_scan=exact - 1)["partial"] != []


def test_candidate_cap_is_named(ff):
    fx = std(regs={})
    out = carve(fx, flag_format=ff, max_candidates=3)
    assert out["partial"] == ["the scan stopped at its cap of 3 chunk candidates"]
    assert out["best"]["text"] == "CSCTF{heap_chain_" and len(out["nodes"]) == 3
    assert carve(fx, flag_format=ff, max_candidates=9)["partial"] == []       # nine candidates in all: none dropped


def test_record_cap_is_named_and_register_chain_comes_first(ff):
    fx = std(regs={})
    out = carve(fx, flag_format=ff, max_nodes=2)
    assert out["best"]["text"] == "CSCTF{heap_"
    assert "shape next_len stopped at its cap of 2 records" in out["partial"]
    assert "PARTIAL carve" in out["note"]
    # the records a register names are taken before the address-order sweep: with room for exactly
    # the five real records the flag is whole, and the cut (two more records exist) is still named
    lifted = std(regs=lambda v: {"rdi": v.head})
    out = carve(lifted, flag_format=ff, max_nodes=5)
    assert out["best"]["text"] == FLAG and len(out["nodes"]) == 5
    assert "shape next_len stopped at its cap of 5 records" in out["partial"]
    assert carve(lifted, flag_format=ff, max_nodes=7)["partial"] == []         # seven records: none dropped
    # a register list longer than the cap is cut and named too, even when the scan adds nothing
    out = carve(lifted, flag_format=ff, max_nodes=3, max_scan=0)
    assert out["best"]["text"] == "CSCTF{heap_chain_"
    assert out["partial"] == ["the scan stopped at its cap of 0 positions",
                              "shape next_len stopped at its cap of 3 records"]


def test_primary_register_list_is_taken_before_another_register_s_list():
    # room for five records, two five-record lists: the one in the arg0 register is kept whole,
    # although the other one sits at lower addresses and in a register too
    h = Heap(0x555555550000)
    other = [h.rec(f"o{i}") for i in range(5)]
    main = [h.rec(f"m{i}") for i in range(5)]
    h.chain(other)
    h.chain(main)
    core, data = dict_core(h, regs={"rcx": other[0], "rdi": main[0]})
    out = memory.heap_chains(core, data, max_nodes=5)
    assert texts(out) == ["m0m1m2m3m4"] and out["partial"] == ["shape next_len stopped at its cap of 5 records"]


def test_walk_budget_is_named_and_register_head_is_walked_first(ff):
    # 40 decoy heads at lower addresses each splice into a 30-record real list whose head is in rdi
    h = Heap(0x555555550000)
    decoys = [h.rec(f"d{i:02d}") for i in range(40)]
    real = [h.rec("CSCTF{")] + [h.rec("a") for _ in range(28)] + [h.rec("}")]
    h.chain(real)
    for d in decoys:
        h.links[d] = real[1]
    flag = "CSCTF{" + "a" * 28 + "}"
    core, data = dict_core(h, regs={"rdi": real[0], "rax": real[0]})
    out = memory.heap_chains(core, data, flag_format=ff)
    assert out["partial"] == [] and len(out["chains"]) == 41 and out["best"]["text"] == flag
    # a budget of 100 records: the register head's list (30) and two decoy lists (30 each) fit, the
    # third does not, and the 37 after it are not started
    out = memory.heap_chains(core, data, flag_format=ff, max_walk=100)
    assert out["best"]["text"] == flag and out["best"]["is_flag"]
    assert len(out["chains"]) == 3
    assert out["partial"] == ["shape next_len: 38 chain start(s) not walked, the walk budget of 100 records was spent"]
    assert "PARTIAL carve" in out["note"]


def test_deadline_stops_the_scan_and_is_named(ff):
    past = time.monotonic() - 1.0                          # already over: independent of machine speed
    out = carve(std(regs={}), flag_format=ff, deadline=past)
    assert out["best"] is None and out["partial"] == ["the scan stopped at its deadline"]
    out = carve(std(), flag_format=ff, deadline=past)       # the register chain needs no scan
    assert out["best"]["text"] == FLAG and out["partial"] == ["the scan stopped at its deadline"]
    assert carve(std(), flag_format=ff, deadline=time.monotonic() + 3600)["partial"] == []


def test_scan_in_blocks_finds_what_one_pass_finds(monkeypatch, ff):
    fx = std(regs={})
    whole = carve(fx, flag_format=ff)
    assert texts(whole) == sorted([FLAG, DECOY_TEXT, ISOLATED])
    for block in (1, 3, 5):
        monkeypatch.setattr(memory, "HEAP_SCAN_BLOCK", block)
        out = carve(fx, flag_format=ff)
        assert (out["nodes"], out["chains"], out["partial"]) == (whole["nodes"], whole["chains"], [])


def _step_clock(monkeypatch, late_from):
    """Replace memory._late with a counter: the look number `late_from` (1-based) and every look after
    it say "late". Returns the list of deadlines it was asked about, one per look."""
    looks = []

    def late(deadline):
        looks.append(deadline)
        return len(looks) >= late_from
    monkeypatch.setattr(memory, "_late", late)
    return looks


def test_scan_looks_at_the_deadline_between_blocks(monkeypatch):
    # "late" from the third look on. One block is two positions here: one 0x20 chunk.
    h = Heap(0x555555550000)
    recs = [h.rec(f"r{i}_") for i in range(4)]
    core, data = dict_core(h)
    spans = memory._heap_spans(memory._heap_regions(core), len(data))
    monkeypatch.setattr(memory, "HEAP_SCAN_BLOCK", 2)
    looks = _step_clock(monkeypatch, 3)
    chunks, cut = memory._heap_chunks(data, spans, 8, "<", deadline=123.0)
    assert [c["user_va"] for c in chunks] == recs[:2] and cut == ["the scan stopped at its deadline"]
    assert looks == [123.0, 123.0, 123.0]


def test_record_read_looks_at_the_deadline_between_blocks(monkeypatch):
    # the read of the scanned chunks under one layout: a look before the first chunk and one every
    # HEAP_SCAN_BLOCK chunks after it; "late" at the second look leaves the chunks after the block unread
    h = Heap(0x555555550000)
    recs = [h.rec(f"r{i}_") for i in range(5)]
    core, data = dict_core(h)
    spans = memory._heap_spans(memory._heap_regions(core), len(data))
    chunks, _ = memory._heap_chunks(data, spans, 8, "<")
    shape = memory._record_shapes(8)[0]
    monkeypatch.setattr(memory, "HEAP_SCAN_BLOCK", 2)
    looks = _step_clock(monkeypatch, 2)
    nodes, capped, late = memory._carve_nodes(data, chunks, spans, shape, 8, "<", [], 100, deadline=5.0)
    assert (sorted(nodes), capped, late) == (recs[:2], False, True) and looks == [5.0, 5.0]
    looks = _step_clock(monkeypatch, 99)
    nodes, capped, late = memory._carve_nodes(data, chunks, spans, shape, 8, "<", [], 100, deadline=5.0)
    assert (sorted(nodes), capped, late) == (recs, False, False) and looks == [5.0, 5.0, 5.0]


def test_after_the_deadline_only_the_register_chain_is_followed(monkeypatch, ff):
    # the standard fixture with the real head in rdi and nothing else in a register. The looks at the
    # deadline, in order: the scan of the stack (1) and of the heap (2); then per layout the read of
    # the scanned chunks (3 for {next, len, text}) and one per chain start no register holds (4: the
    # decoy head, 5: the isolated record); then the read under each of the four other layouts (6-9).
    def run(late_from):
        looks = _step_clock(monkeypatch, late_from)
        out = carve(std(regs=lambda v: {"rdi": v.head}), flag_format=ff, deadline=77.0)
        assert set(looks) == {77.0}
        return out, len(looks)

    out, looks = run(99)                                    # never late: the whole carve
    assert looks == 9 and out["partial"] == [] and texts(out) == sorted([FLAG, DECOY_TEXT, ISOLATED])
    # late once the scan is done: no layout reads a scanned chunk, yet the register's list is followed
    out, looks = run(3)
    assert out["best"]["text"] == FLAG and out["best"]["is_flag"] and len(out["nodes"]) == 5
    assert texts(out) == [FLAG]
    assert out["partial"] == ["the deadline passed with scanned chunks left unread under shape(s) "
                              "next_len, len_next, next_wlen, wlen_next, next_cstr"]
    assert out["warnings"][0].startswith("PARTIAL carve (the deadline passed with scanned chunks left unread")
    # late after the first layout read its chunks: all seven records, but only the register's chain
    out, looks = run(4)
    assert len(out["nodes"]) == 7 and texts(out) == [FLAG]
    assert out["partial"] == ["shape next_len: 2 chain start(s) not walked, the deadline had passed",
                              "the deadline passed with scanned chunks left unread under shape(s) "
                              "len_next, next_wlen, wlen_next, next_cstr"]
    # late before the last start only
    out, looks = run(5)
    assert texts(out) == sorted([FLAG, DECOY_TEXT])
    assert out["partial"][0] == "shape next_len: 1 chain start(s) not walked, the deadline had passed"


def test_closed_loop_is_not_walked_after_the_deadline(monkeypatch):
    # a loop nothing else reaches is the last thing walked; it obeys the deadline too
    nodes = {0x10: {"next": 0x20, "text": "a", "inuse": True}, 0x20: {"next": 0x10, "text": "b", "inuse": True}}
    _step_clock(monkeypatch, 1)
    assert memory._build_chains(nodes, (), deadline=1.0) == ([], {"unwalked": 0, "late": 1, "text_cut": 0})
    _step_clock(monkeypatch, 99)
    chains, cut = memory._build_chains(nodes, (), deadline=1.0)
    assert [(c["text"], c["loop"]) for c in chains] == [("ab", True)] and cut == {"unwalked": 0, "late": 0, "text_cut": 0}
    # a register start is walked whatever the clock says
    _step_clock(monkeypatch, 1)
    chains, cut = memory._build_chains(nodes, (0x20,), deadline=1.0)
    assert [c["text"] for c in chains] == ["ba"] and cut["late"] == 0


# --- bounds: the chain text (memory) --------------------------------------------------------------------

def _shared_tail(heads, tail_records, text_len):
    """`heads` decoy records that all link to the first of `tail_records` records of `text_len`
    characters each: every decoy's chain repeats the whole tail. Returns (heap, tail addresses)."""
    h = Heap(0x555555550000)
    tail = [h.rec(chr(ord("a") + i % 26) * text_len) for i in range(tail_records)]
    h.chain(tail)
    for i in range(heads):
        h.links[h.rec(f"d{i:03d}")] = tail[0]
    return h, tail


def test_one_chain_s_text_is_cut_at_its_cap_and_said():
    h = Heap(0x555555550000)
    h.chain([h.rec(t) for t in ("0123456789", "abcdefghij", "ABCDEFGHIJ")])
    whole = "0123456789abcdefghijABCDEFGHIJ"
    out = memory.heap_chains(*dict_core(h), max_chain_text=30)             # fits exactly: not a cut
    assert (out["best"]["text"], out["best"]["text_cut"], out["partial"]) == (whole, False, [])
    out = memory.heap_chains(*dict_core(h), max_chain_text=29)
    assert (out["best"]["text"], out["best"]["text_cut"], out["best"]["nodes"]) == (whole[:29], True, 3)
    assert out["partial"] == [f"shape next_len: the text of 1 chain(s) was cut at the text cap "
                              f"(29 characters a chain, {memory.HEAP_MAX_TEXT} for all chains)"]
    assert "PARTIAL carve" in out["note"]
    out = memory.heap_chains(*dict_core(h), max_chain_text=12)             # the cut falls inside a record
    assert (out["best"]["text"], out["best"]["text_cut"], out["best"]["nodes"]) == (whole[:12], True, 3)


def test_all_chains_text_is_cut_at_its_cap_and_the_register_chain_comes_first():
    # five decoy heads share a two-record tail; rdi holds the tail's first record. Text, in walk
    # order: the register chain 20 characters, then five decoy chains of 4 + 20 each: 140 in all
    h, tail = _shared_tail(5, 2, 10)
    core, data = dict_core(h, regs={"rdi": tail[0]})
    out = memory.heap_chains(core, data, max_text=140)                    # fits exactly: not a cut
    assert out["partial"] == [] and sum(len(c["text"]) for c in out["chains"]) == 140
    out = memory.heap_chains(core, data, max_text=139)
    assert sum(len(c["text"]) for c in out["chains"]) == 139
    assert [c["text_cut"] for c in sorted(out["chains"], key=lambda c: c["head_va"])] == [False] * 5 + [True]
    assert out["partial"] == [f"shape next_len: the text of 1 chain(s) was cut at the text cap "
                              f"({memory.HEAP_MAX_CHAIN_TEXT} characters a chain, 139 for all chains)"]
    # room for the register chain alone: it is whole, every decoy is there (its records are known)
    # with no text, and the report line says which chains were cut
    out = memory.heap_chains(core, data, max_text=20)
    assert (out["best"]["head_regs"], out["best"]["text"], out["best"]["text_cut"]) == (["rdi"], "a" * 10 + "b" * 10, False)
    decoys = [c for c in out["chains"] if c is not out["best"]]
    assert [(c["text"], c["text_cut"], c["nodes"]) for c in decoys] == [("", True, 3)] * 5
    assert out["partial"] == [f"shape next_len: the text of 5 chain(s) was cut at the text cap "
                              f"({memory.HEAP_MAX_CHAIN_TEXT} characters a chain, 20 for all chains)"]
    lines = memory._core_lines({"name": "t", "pid": 1, "ppid": 0, "uid": 0, "args": "", "segments": [], "files": []}, out)
    assert sum(1 for ln in lines if "(3 nodes, text cut): ''" in ln) == 5
    assert f"   chain score 1002 0x{tail[0]:x} (2 nodes) <- rdi: 'aaaaaaaaaabbbbbbbbbb'" in lines
    assert lines[-1] == "   RECOVERED: 'aaaaaaaaaabbbbbbbbbb' (PARTIAL carve: read the warning)"


def test_cut_text_is_never_called_a_complete_flag(ff):
    # cut after eight characters the text reads as a whole flag; its end was not read, so it is none
    h = Heap(0x555555550000)
    h.chain([h.rec("CSCTF{a}"), h.rec("_and_more")])
    assert ff.is_flag("CSCTF{a}") and not ff.is_flag("CSCTF{a}_and_more")
    out = memory.heap_chains(*dict_core(h), flag_format=ff, max_chain_text=8)
    b = out["best"]
    assert (b["text"], b["text_cut"], b["is_flag"], b["score"]) == ("CSCTF{a}", True, False, 802)
    assert "[flag]" not in out["note"] and "PARTIAL carve" in out["note"]
    out = memory.heap_chains(*dict_core(h), flag_format=ff, max_text=8)    # the same cut by the other cap
    assert (out["best"]["text"], out["best"]["text_cut"], out["best"]["is_flag"]) == ("CSCTF{a}", True, False)
    out = memory.heap_chains(*dict_core(h), flag_format=ff, max_chain_text=17)   # whole: judged as it reads
    assert (out["best"]["text"], out["best"]["text_cut"], out["best"]["is_flag"]) == ("CSCTF{a}_and_more", False, False)


def test_default_caps_bound_the_chain_text_of_heads_that_share_a_tail():
    # the case the caps exist for: 300 decoy heads on one tail of 8 records of 32000 characters. The
    # core is about 0.27 MB; uncapped, its chains held 300 copies of the tail (77 MB of text), and
    # nothing said so. At the defaults the chains hold exactly HEAP_MAX_TEXT characters and the cut is named.
    h, tail = _shared_tail(300, 8, 32000)
    core, data = dict_core(h, regs={"rdi": tail[0]})
    assert len(data) < 300_000
    out = memory.heap_chains(core, data)
    assert len(out["chains"]) == 301 and out["best"]["vas"] == tail and not out["best"]["text_cut"]
    assert len(out["best"]["text"]) == 8 * 32000
    assert sum(len(c["text"]) for c in out["chains"]) == memory.HEAP_MAX_TEXT == 1 << 24
    cut = sum(1 for c in out["chains"] if c["text_cut"])
    whole = 1 + (memory.HEAP_MAX_TEXT - 8 * 32000) // (8 * 32000 + 4)     # the register chain, then 64 decoys
    assert (whole, cut) == (65, 301 - 65)
    assert out["partial"] == [f"shape next_len: the text of {cut} chain(s) was cut at the text cap "
                              f"({1 << 20} characters a chain, {1 << 24} for all chains)"]
    assert out["warnings"][0].startswith("PARTIAL carve (shape next_len: the text of ")


def test_default_cap_bounds_one_long_chain_s_text():
    # one list of 40 records of 32000 characters: 1.28 M characters, cut at the per-chain default
    h = Heap(0x555555550000)
    h.chain([h.rec("z" * 32000) for _ in range(40)])
    out = memory.heap_chains(*dict_core(h))
    assert (len(out["best"]["text"]), out["best"]["text_cut"], out["best"]["nodes"]) == (memory.HEAP_MAX_CHAIN_TEXT, True, 40)
    assert memory.HEAP_MAX_CHAIN_TEXT == 1 << 20 and len(out["partial"]) == 1


# --- bounds: the walk budget at zero, and what is said with no flag format ------------------------------


def test_walk_budget_of_zero_rebuilds_nothing_and_says_so():
    h = Heap(0x555555550000)
    h.chain([h.rec("a"), h.rec("b")])
    out = memory.heap_chains(*dict_core(h), max_walk=0)
    assert out["best"] is None and out["chains"] == [] and len(out["nodes"]) == 2
    assert out["note"].startswith("records of shape next_len found, but no chain was rebuilt; PARTIAL carve (")


def test_no_flag_format_is_said(ff):
    out = carve(std(), flag_format=None)
    assert out["best"]["head_va"] == std().head and out["best"]["is_flag"] is False
    assert out["warnings"] == ["no flag format: chains ranked by registers and length only"]
    out = carve(std(), flag_format=None, no_format_why="CTF_EVENT is not set")
    assert out["warnings"] == ["no flag format (CTF_EVENT is not set): chains ranked by registers and length only"]
    assert out["note"].endswith("; " + out["warnings"][0])
    assert carve(std(), flag_format=ff)["warnings"] == []


# --- wiring: the event's flag format -------------------------------------------------------------------

def test_flag_format_follows_the_event(csctf_env):
    fmt, why = memory._flag_format()
    assert why == "" and fmt.is_flag(FLAG) and not fmt.is_flag("HTB{x}")


def test_flag_format_without_an_event_gives_the_reason(monkeypatch, tmp_path):
    monkeypatch.delenv("CTF_EVENT", raising=False)
    fmt, why = memory._flag_format()
    assert fmt is None and "CTF_EVENT is not set" in why


def test_flag_format_error_that_is_not_an_event_error_is_raised(monkeypatch):
    def boom():
        raise RuntimeError("not an event problem")
    monkeypatch.setattr(memory.flagfmt, "current", boom)
    with pytest.raises(RuntimeError, match="not an event problem"):
        memory._flag_format()


# --- wiring: build_model -------------------------------------------------------------------------------

def test_build_model_records_recovered_chain(csctf_env):
    fx = std()
    model = memory.build_model({"relay.core": fx.core})
    assert model.recovered == [{"source": "relay.core", "shape": {"name": "next_len", "consistent": 7, "nodes": 7},
                                "text": FLAG, "head_va": fx.head, "regs": ["rax", "rdi"], "is_flag": True,
                                "score": 6005, "partial": False}]
    assert f"relay.core: heap chain (next_len, 7 records): {FLAG!r}, from register rax/rdi [flag]" in model.notes
    assert model.heap["relay.core"]["best"]["text"] == FLAG


def test_build_model_without_an_event_ranks_by_registers_and_says_why(monkeypatch, tmp_path):
    monkeypatch.delenv("CTF_EVENT", raising=False)
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    model = memory.build_model({"relay.core": std().core})
    rec = model.recovered[0]
    assert rec["text"] == FLAG and rec["is_flag"] is False and rec["regs"] == ["rax", "rdi"]
    note = next(n for n in model.notes if "heap chain" in n)
    assert "no flag format (CTF_EVENT is not set" in note and "ranked by registers and length only" in note


def test_build_model_does_not_heap_carve_over_carve_max(csctf_env):
    fx = std()
    model = memory.build_model({"relay.core": fx.core}, carve_max=len(fx.core) - 1)
    assert model.recovered == [] and model.heap == {}
    assert any("heap chains not carved here" in n and "--heap-chains" in n for n in model.notes)
    assert model.procs[4242]["src"] == "elfcore"
    assert memory.build_model({"relay.core": fx.core}, carve_max=len(fx.core)).recovered[0]["text"] == FLAG


def test_build_model_does_not_heap_carve_after_the_deadline(csctf_env):
    fx = std()
    model = memory.build_model({"relay.core": fx.core}, deadline=time.monotonic() - 1.0)
    assert model.recovered == [] and model.heap == {}
    assert "relay.core: no time left to carve heap chains" in model.notes
    assert model.procs[4242]["src"] == "elfcore"


def test_build_model_carves_a_core_that_names_no_process(csctf_env):
    # no NT_PRPSINFO: there is no process to add to the model, and the heap is carved all the same
    fx = std()
    core = build_core([(fx.heap_base, R | W, fx.heap.blob())], regs={"rdi": fx.head}, pid=None)
    assert memory.elf_core(core)["pid"] is None
    model = memory.build_model({"anon.core": core})
    assert [r["text"] for r in model.recovered] == [FLAG] and 4242 not in model.procs


def test_build_model_carves_heap_chains_after_the_process_carvers(csctf_env, monkeypatch):
    # under a deadline the heap carve gets what the older carvers leave, not the other way round:
    # their facts are what solve_set answers from
    order = []
    real_carve, real_heap = memory.carve, memory.heap_chains

    def carve_spy(*a, **kw):
        order.append("carve")
        return real_carve(*a, **kw)

    def heap_spy(*a, **kw):
        order.append("heap")
        return real_heap(*a, **kw)
    monkeypatch.setattr(memory, "carve", carve_spy)
    monkeypatch.setattr(memory, "heap_chains", heap_spy)
    model = memory.build_model({"relay.core": std().core}, deadline=time.monotonic() + 3600)
    assert order == ["carve", "heap"] and model.recovered[0]["text"] == FLAG


def test_build_model_without_heap_carves_no_chains(csctf_env):
    model = memory.build_model({"relay.core": std().core}, heap=False)
    assert model.heap == {} and model.recovered == [] and not any("heap" in n for n in model.notes)
    assert model.procs[4242]["src"] == "elfcore"


def test_solve_set_does_not_carve_heap_chains(csctf_env, monkeypatch):
    # solve_set answers from the process facts and reads no heap chain, so none of its 0.6 s goes to
    # the carve (it used to run first and could leave the process carvers no time)
    calls = []
    monkeypatch.setattr(memory, "heap_chains", lambda *a, **kw: calls.append(a) or {})
    text = "What is the PID of the process in the memory dump?"
    out = memory.solve_set([{"qid": "q1", "text": text, "question": text, "answer_format": "integer"}],
                           {"relay.core": std().core}, {})
    assert "4242" in out["q1"]                               # the model was built and read
    assert calls == []


def test_build_model_passes_its_deadline_into_the_scan(csctf_env, monkeypatch):
    seen = {}
    real = memory.heap_chains

    def spy(core, data, **kw):
        seen.update(kw)
        return real(core, data, **kw)
    monkeypatch.setattr(memory, "heap_chains", spy)
    deadline = time.monotonic() + 3600
    memory.build_model({"relay.core": std().core}, deadline=deadline)
    assert seen["deadline"] == deadline


def test_build_model_survives_a_failed_heap_carve(csctf_env, monkeypatch):
    def broken(core, data, **kw):
        raise struct.error("unpack_from requires a buffer of at least 1452 bytes")
    monkeypatch.setattr(memory, "heap_chains", broken)
    model = memory.build_model({"relay.core": std().core})
    assert model.procs[4242]["src"] == "elfcore" and model.recovered == []
    assert any("heap chain carve failed on malformed bytes (struct.error: unpack_from requires" in n for n in model.notes)


def test_partial_carve_reaches_the_model_and_the_report(csctf_env, monkeypatch, tmp_path):
    fx = std(regs={})
    monkeypatch.setattr(memory, "heap_chains",
                        functools.partial(memory.heap_chains, max_scan=_positions_through(fx, 1)))
    model = memory.build_model({"relay.core": fx.core})
    assert model.recovered[0]["text"] == "CSCTF{heap_" and model.recovered[0]["partial"] is True
    assert any("PARTIAL carve (the scan stopped at its cap" in n for n in model.notes)
    text = memory.report_text({"relay.core": fx.core})
    assert "   WARNING PARTIAL carve (the scan stopped at its cap" in text
    assert "   RECOVERED: 'CSCTF{heap_' (PARTIAL carve: read the warning)" in text
    assert "'CSCTF{heap_' (PARTIAL carve)" in text


# --- wiring: the command -------------------------------------------------------------------------------

def test_report_prints_registers_chains_and_recovered_flag(csctf_env, tmp_path):
    fx = std()
    path = tmp_path / "relay.core"
    path.write_bytes(fx.core)
    lines = memory.report([str(path)]).splitlines()
    assert f"   1 thread(s), regs: rdi=0x{fx.head:x}, rsi=0x0, rdx=0x0, rax=0x{fx.head:x}, rip=0x0, rsp=0x0" in lines
    assert f"   heap region 0x{fx.heap_base:x} filesz 0x{fx.heap_len:x} rw- (unbacked-rw)" in lines
    assert "   record shape next_len: 7 records, 7 linked" in lines
    assert f"   chain score 6005 0x{fx.head:x} (5 nodes) <- rax/rdi FLAG: {FLAG!r}" in lines
    assert f"   chain score 403 0x{fx.decoy:x} (3 nodes) <- rcx: {DECOY_TEXT!r}" in lines
    assert f"   chain score 1 0x{fx.iso:x} (1 nodes): {ISOLATED!r}" in lines
    assert f"   RECOVERED: {FLAG!r} (flag)" in lines
    assert f"recovered(heap chain) from relay.core 0x{fx.head:x} regs rax/rdi FLAG {FLAG!r}" in lines
    assert not any("WARNING" in ln or "PARTIAL" in ln for ln in lines)


def test_report_carves_each_core_once(csctf_env, tmp_path, monkeypatch):
    calls = []
    real = memory.heap_chains

    def counting(core, data, **kw):
        calls.append(len(data))
        return real(core, data, **kw)
    monkeypatch.setattr(memory, "heap_chains", counting)
    fx = std()
    path = tmp_path / "relay.core"
    path.write_bytes(fx.core)
    assert f"RECOVERED: {FLAG!r}" in memory.report([str(path)])
    assert calls == [len(fx.core)]


def _many_lists(n):
    h = Heap(0x555555550000)
    head = [h.rec(t) for t in ("CSCTF{", "many}")]
    h.chain(head)
    for i in range(n):
        h.rec(f"lone{i:02d}")
    return build_core([(0x555555550000, R | W, h.blob())], regs={"rdi": head[0]})


def test_report_prints_every_chain_up_to_its_stated_cap(csctf_env, monkeypatch):
    core = _many_lists(11)                                 # 12 chains: more than the 8 once printed
    text = memory.report_text({"x.core": core})
    assert sum(1 for ln in text.splitlines() if ln.startswith("   chain score ")) == 12
    assert all(f"'lone{i:02d}'" in text for i in range(11)) and "more chain(s) not printed" not in text
    monkeypatch.setattr(memory, "REPORT_MAX_CHAINS", 5)
    text = memory.report_text({"x.core": core})
    assert sum(1 for ln in text.splitlines() if ln.startswith("   chain score ")) == 5
    assert "   7 more chain(s) not printed (the first 5 by rank are above)" in text
    assert "   RECOVERED: 'CSCTF{many}' (flag)" in text


def test_report_marks_freed_and_looping_chains(csctf_env):
    h = Heap(0x555555550000)
    a, b = h.rec("L1"), h.rec("L2")
    h.chain([a, b, a])
    gone = h.rec("gone")
    h.rec("end", prev_inuse=False)                         # PREV_INUSE clear: "gone" was freed
    lines = memory.report_text({"x.core": build_core([(0x555555550000, R | W, h.blob())])}).splitlines()
    assert f"   chain score 2 0x{a:x} (2 nodes, loops): 'L1L2'" in lines
    assert f"   chain score 1 0x{gone:x} (1 nodes, 1 freed): 'gone'" in lines


def test_report_says_when_a_heap_holds_no_records(csctf_env):
    text = memory.report_text({"x.core": build_core([(0x555555550000, R | W, bytes(0x100))])})
    assert "   heap: no glibc chunk-shaped records in the heap region" in text.splitlines()
    assert "RECOVERED" not in text and "recovered(heap chain)" not in text


def test_heap_chains_command_prints_the_carve_alone(csctf_env, tmp_path, capsys):
    fx = std()
    path = tmp_path / "snapshot.bin"
    path.write_bytes(fx.core)
    assert memory.main(["--heap-chains", str(path)]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == f"== snapshot.bin: {len(fx.core)} bytes, format elf_core"
    assert "   process 't' pid 4242 ppid 1 uid 1000 args '/t'" in out
    assert f"   RECOVERED: {FLAG!r} (flag)" in out
    assert not any("sha256" in ln or ln.startswith("== model") for ln in out)    # none of the full triage


def test_heap_chains_command_says_why_there_is_no_flag_format(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("CTF_EVENT", raising=False)
    path = tmp_path / "snapshot.bin"
    path.write_bytes(std().core)
    assert memory.main(["--heap-chains", str(path)]) == 0
    out = capsys.readouterr().out.splitlines()
    warning = [ln for ln in out if ln.startswith("   WARNING no flag format")]
    assert len(warning) == 1 and "(CTF_EVENT is not set" in warning[0]
    assert warning[0].endswith(": chains ranked by registers and length only")
    assert f"   RECOVERED: {FLAG!r}" in out                 # the register chain, not called a flag


def test_heap_chains_command_names_a_file_that_is_no_core(csctf_env, tmp_path, capsys):
    fx = std()
    exe = tmp_path / "prog"
    exe.write_bytes(build_core([(fx.heap_base, R | W, fx.heap.blob())], etype=2))    # ET_EXEC, not a core
    assert memory.main(["--heap-chains", str(exe)]) == 2
    assert "not an ELF core" in capsys.readouterr().err
    tiny = tmp_path / "tiny"
    tiny.write_bytes(b"\x7fELF")
    assert memory.main(["--heap-chains", str(tiny)]) == 2
    assert "4 bytes, not an ELF core" in capsys.readouterr().err
    assert memory.main(["--heap-chains"]) == 2
    assert "takes one or more ELF core files" in capsys.readouterr().err


# --- intake: the [intake] table selects cores by content and runs at the default cap --------------------

def _memory_manifest():
    mans = [m for m in _manifest.discover() if m.id == "toolkits.memory"]
    assert len(mans) == 1, "toolkits.memory manifest not discovered"
    return mans


def _intake_folder(tmp_path):
    folder = tmp_path / "files"
    folder.mkdir()
    fx = std()
    (folder / "snapshot.bin").write_bytes(fx.core)                                        # LP64 LE, no core-ish name
    (folder / "old.dump").write_bytes(std(wide=False, machine=memory.EM_386).core)        # LP32 LE
    (folder / "be.img").write_bytes(std(e=">", machine=21, regs={}).core)                 # LP64 BE
    (folder / "gnu.bin").write_bytes(build_core([(fx.heap_base, R | W, fx.heap.blob())], osabi=3))
    (folder / "core.js").write_text("export const core = 1;\n")                           # a name, not a core
    (folder / "core").write_bytes(build_core([(fx.heap_base, R | W, fx.heap.blob())], etype=2))   # ELF, ET_EXEC
    (folder / "notes.core").write_text("not an ELF file\n")
    return folder


def test_intake_selects_elf_cores_by_content_at_the_default_cost_cap(tmp_path):
    folder = _intake_folder(tmp_path)
    guard = types.SimpleNamespace(allows_spawn=False, reason="hook guard")
    plan = _intake_engines.plan(_memory_manifest(), "forensics", "", folder, guard=guard)   # max_cost: the default
    assert sorted(j.files[0].name for j in plan.jobs) == ["be.img", "gnu.bin", "old.dump", "snapshot.bin"]
    assert {j.engine for j in plan.jobs} == {"toolkits.memory"} and plan.skipped == []
    claimed = {name for name, ids in plan.claims.items() if "toolkits.memory" in ids}
    assert claimed == {"be.img", "gnu.bin", "old.dump", "snapshot.bin"}


@pytest.mark.parametrize("wide", [True, False])
@pytest.mark.parametrize("e", ["<", ">"])
@pytest.mark.parametrize("osabi", [0, 3])
def test_intake_selects_a_core_of_every_class_byte_order_and_osabi(wide, e, osabi, tmp_path):
    # one core per folder, so each of the eight content matchers is the only thing that can pick it
    folder = tmp_path / "files"
    folder.mkdir()
    h = Heap(0x555555550000 if wide else 0x08050000, 8 if wide else 4, e)
    h.rec("one")
    machine = {(True, "<"): memory.EM_X86_64, (False, "<"): memory.EM_386, (True, ">"): 21, (False, ">"): 20}[(wide, e)]
    core = build_core([(h.base, R | W, h.blob())], wide=wide, e=e, machine=machine, osabi=osabi)
    assert memory.image_format(core) == "elf_core" and texts(carve(core)) == ["one"]
    (folder / "blob.bin").write_bytes(core)
    (folder / "exec.bin").write_bytes(build_core([(h.base, R | W, h.blob())], wide=wide, e=e, machine=machine,
                                                 osabi=osabi, etype=2))
    guard = types.SimpleNamespace(allows_spawn=False, reason="hook guard")
    plan = _intake_engines.plan(_memory_manifest(), "forensics", "", folder, guard=guard)
    assert [j.files[0].name for j in plan.jobs] == ["blob.bin"] and plan.skipped == []


def test_intake_runs_the_carve_alone_with_a_minute(tmp_path):
    # what makes the manifest's `cheap` class true: intake's argv is the carve alone, never the full
    # triage. The timeout is pinned here because nothing that runs fast can tell 60 s from 1 s: the
    # worst carve measured is under 4 s of CPU (docs/build-log/B-067.md), on a machine whose load
    # stretches that many times over; a short timeout would turn slow machines into "timeout" runs.
    spec = _memory_manifest()[0].intake
    assert spec.timeout == 60 and (spec.run, spec.select) == ("per-file", "files")
    core = tmp_path / "x.core"
    assert _intake_engines.expand_args(spec, (core,), folder=tmp_path, challenge=tmp_path, out=tmp_path) == \
        ["--heap-chains", str(core)]


def test_intake_run_prints_the_flag(tmp_path):
    # the planned job, run the way intake runs it (ctf.engines.runner under the network guard):
    # the manifest's entry and args really reach the carver, and its stdout carries the flag
    folder = _intake_folder(tmp_path)
    guard = _intake_guard.resolve("hook")
    plan = _intake_engines.plan(_memory_manifest(), "forensics", "", folder, guard=guard)
    job = next(j for j in plan.jobs if j.files[0].name == "snapshot.bin")
    challenge = tmp_path / "ch"
    ctx = _intake_engines.Context(challenge_dir=challenge, folder=folder, out_root=challenge / "recon" / "engines",
                                  profile=_event.load("csctf"), guard=guard, root=REPO, python=sys.executable,
                                  challenge_id=None, record=False, workdir=tmp_path / "wd")
    run = _intake_engines.run_job(job, ctx)
    assert (run.status, run.exit_code) == ("ok", 0), (challenge / run.errors).read_text()
    assert run.flags == (FLAG,)
    printed = (challenge / run.output).read_text()
    assert f"RECOVERED: {FLAG!r} (flag)" in printed
    # the carve alone: the full triage would print a sha256 of the file and a `== model` section
    assert printed.splitlines()[0] == f"== snapshot.bin: {len(std().core)} bytes, format elf_core"
    assert "== model" not in printed and "sha256" not in printed
