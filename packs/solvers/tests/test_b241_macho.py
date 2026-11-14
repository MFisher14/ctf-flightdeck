#!/usr/bin/env python3
"""B-241: 64-bit Mach-O images (x86-64, arm64) mapped into the whole-image emulator (macho_image.py).

The fixtures are four small dylibs compiled from ``tests/fixtures/native_image/B241_MACHO.c`` by
``tests/b241_fixture_asm.py --macho``: both architectures, each linked with chained fixups and with the
classic dyld-info opcodes.  The expected values are a Python model of the C source.  Nothing is run on the
host: the code runs inside the bounded emulator.  The engine tests are marked ``needs_tool`` and skip with
a named reason where Unicorn is unavailable; the rebuild test needs macOS and cc and reports NOT RUN
elsewhere.
"""
from __future__ import annotations

import contextlib
import signal
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT / "tests", ROOT / "solvers" / "common"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

import macho_image as mo  # noqa: E402
import native_image as ni  # noqa: E402

FX = ROOT / "tests" / "fixtures" / "native_image"
M64 = (1 << 64) - 1
SEED, FNV = 0x9E3779B97F4A7C15, 0x100000001B3
SBOX = (3, 1, 4, 1, 5, 9, 2, 6)
WORDS = ("alpha", "bravo", "charlie")
VARIANTS = [("x86_64", "chained"), ("x86_64", "classic"), ("arm64", "chained"), ("arm64", "classic"),
            ("x86_64", "exec_chained"), ("arm64", "exec_classic")]       # the last two: PIE executables
NAMES = {"b241_mix", "b241_pid", "b241_round", "b241_seed"}
ARCH = {"x86_64": "x86-64", "arm64": "arm64"}
engine = pytest.mark.needs_tool("py:unicorn", "py:capstone")
INPUTS = (("hello", 3), ("", 0), ("abcdefgh", 9), ("x" * 40, 31))


def fixture(arch, tag):
    suffix = "" if tag.startswith("exec") else ".dylib"
    return (FX / f"b241_macho_{arch}_{tag}{suffix}").read_bytes()


def mload(data, arch=None):
    """native_image.load with the Mach-O opt-in (emulate_symbol passes it; an ELF-only caller does not)."""
    return ni.load(data, arch, macho=True)


def model_mix(text: str, k: int) -> int:
    """b241_mix of B241_MACHO.c."""
    h = SEED
    for byte in text.encode():
        h = ((h ^ byte) * FNV) & M64
    for i in range(k):
        h = ((h ^ SBOX[i & 7]) * FNV) & M64
    return (h + len(WORDS[len(text) % 3])) & M64


def need_engine():
    if not ni.UNICORN_AVAILABLE:
        pytest.skip(f"real Unicorn backend unavailable: {ni._ne.UNICORN_UNAVAILABLE_REASON}")


def universal(*members) -> bytes:
    """A universal (fat) file holding ``members`` [(cputype, cpusubtype, bytes)], as lipo lays one out."""
    head = struct.pack(">II", mo.FAT_MAGIC, len(members))
    at = 0x4000
    body = b""
    for cputype, cpusub, data in members:
        head += struct.pack(">IIIII", cputype, cpusub, at, len(data), 14)
        body += data + bytes(-len(data) % 0x4000)
        at += len(data) + (-len(data) % 0x4000)
    return head + bytes(0x4000 - len(head)) + body


# ------------------------------------------------------------------ what dyld would do, as a plan
@pytest.mark.parametrize("arch,tag", VARIANTS)
def test_the_image_is_read_as_dyld_reads_it(arch, tag):
    img = mload(fixture(arch, tag))
    assert isinstance(img, mo.MachOImage) and img.arch == ARCH[arch] and img.problem is None
    executable = tag.startswith("exec")
    # an executable's __TEXT sits above __PAGEZERO: every address is read relative to the Mach header
    assert img.bias == (0x100000000 if executable else 0)
    exports = img.exports()
    assert set(exports) == NAMES | ({"main", "_mh_execute_header"} if executable else set())
    assert all(exports[name] == img.symbol(name) and 0 < exports[name] < img.hi for name in NAMES)
    assert img.symbol("_b241_mix") == img.symbol("b241_mix") and img.symbol("nope") is None
    assert not img.ambiguous_exports()
    # the linker's __mod_init_func (or __init_offsets) names one initializer: the C constructor
    assert len(img.constructors()) == 1 and img.has_load_code()
    # the segments: the header's first, nothing writable and executable, __PAGEZERO never mapped
    assert img.loads[0][0] == 0 and all(seg[4] & 3 != 3 for seg in img.loads)
    kinds = {}
    for off, kind, payload in img.plan:
        kinds.setdefault(kind, []).append((off, payload))
        seg = img.seg_of(off)
        assert seg is not None and seg[4] & 2 and not seg[4] & 1                # only writable data is fixed up
    libc = {ni.LIBC_FUNCS[payload - 1] for _off, payload in kinds["trap"]}
    assert {"strlen", "malloc", "memcpy", "free", "__stack_chk_fail"} <= libc
    assert len(kinds["canary"]) == 1                                         # ___stack_chk_guard
    assert [payload for _off, payload in kinds["import"]] == ["getpid"]
    # the three b241_words pointers are rebases into the image's own strings
    words = sorted(payload for _off, payload in kinds["rel"])
    texts = [img.data[next(o + p - v for (v, _m, fs, o, _f) in img.loads if v <= p < v + fs):][:8] for p in words]
    assert sum(any(t.startswith(w.encode() + b"\0") for t in texts) for w in WORDS) == 3
    if tag.endswith("classic"):
        assert kinds["poison"]                                               # dyld_stub_binder: never called
    # __DATA_CONST (the GOT) is read-only after the fixups
    assert img.relro is not None
    lo, size = img.relro
    assert all(lo <= off < lo + size for off, _p in kinds["canary"])


def test_container_detection_and_universal_files():
    x86, arm = fixture("x86_64", "chained"), fixture("arm64", "chained")
    assert mo.is_macho(x86) and mo.is_macho(arm) and not mo.is_macho(b"\x7fELF" + bytes(60))
    assert mo.slices(x86) == [(None, 0, len(x86))]
    fat = universal((mo.CPU_X86_64, 3, x86), (mo.CPU_ARM64, 0, arm))
    assert mo.is_macho(fat) and [row[0] for row in mo.slices(fat)] == ["x86-64", "arm64"]
    with pytest.raises(ni.EmulationError, match="name the arch"):
        mload(fat)
    assert mload(fat, "arm64").arch == "arm64" and mload(fat, "x86-64").arch == "x86-64"
    assert mload(fat, "arm64").exports().keys() == mload(arm).exports().keys()
    with pytest.raises(ni.EmulationError, match="holds no arm32 slice"):
        mload(fat, "arm32")
    # one runnable slice beside one this engine does not run (arm64e): no arch needed
    lone = universal((mo.CPU_ARM64, 2, arm), (mo.CPU_X86_64, 3, x86))
    assert [row[0] for row in mo.slices(lone)] == [None, "x86-64"] and mload(lone).arch == "x86-64"
    with pytest.raises(ni.EmulationError, match="outside the file"):
        mo.slices(fat[:0x4000 + 64])
    # a Java class file shares the universal magic: it is refused, not read as slices
    with pytest.raises(ni.EmulationError):
        mload(b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + bytes(64))


def patched(data: bytes, at: int, fmt: str, *values) -> bytes:
    out = bytearray(data)
    struct.pack_into(fmt, out, at, *values)
    return bytes(out)


def find_command(data: bytes, wanted: int) -> int:
    ncmds = struct.unpack_from("<I", data, 16)[0]
    at = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, at)
        if cmd == wanted:
            return at
        at += size
    raise AssertionError(f"load command {wanted:#x} not in the fixture")


def test_what_dyld_would_do_and_the_model_does_not_declines():
    arm = fixture("arm64", "chained")
    assert "arm64e" in mload(patched(arm, 8, "<I", 0x80000002)).problem            # cpusubtype arm64e
    with pytest.raises(ni.EmulationError, match="file type 1 is not loadable"):
        mload(patched(arm, 12, "<I", 1))                                            # MH_OBJECT
    with pytest.raises(ni.EmulationError, match="not an ELF image"):
        mload(patched(arm, 0, "<I", 0xFEEDFACE))                                    # a 32-bit Mach-O: no loader takes it
    with pytest.raises(ni.EmulationError, match="only 64-bit little-endian Mach-O"):
        mo.MachOImage(patched(arm, 0, "<I", 0xFEEDFACE))
    with pytest.raises(ni.EmulationError, match="cputype"):
        mload(patched(arm, 4, "<I", 0x0100000D))
    with pytest.raises(ni.EmulationError):
        mload(arm[:len(arm) - 0x4000])                                              # __LINKEDIT cut off
    # LC_UUID (24 bytes) rewritten as LC_ENCRYPTION_INFO_64 with cryptid 1: an encrypted image
    uuid = find_command(arm, 0x1B)
    encrypted = patched(arm, uuid, "<IIIII", mo.LC_ENCRYPTION_INFO_64, 24, 0, 0, 1)
    assert "encrypted" in mload(encrypted).problem
    assert mload(patched(arm, uuid, "<IIIII", mo.LC_ENCRYPTION_INFO_64, 24, 0, 0, 0)).problem is None
    # a chained pointer format the model does not carry (here: the arm64e format number)
    chained = find_command(arm, mo.LC_DYLD_CHAINED_FIXUPS)
    dataoff = struct.unpack_from("<I", arm, chained + 8)[0]
    starts = dataoff + struct.unpack_from("<I", arm, dataoff + 4)[0]
    seg_count = struct.unpack_from("<I", arm, starts)[0]
    info = next(struct.unpack_from("<I", arm, starts + 4 + 4 * k)[0] for k in range(seg_count)
                if struct.unpack_from("<I", arm, starts + 4 + 4 * k)[0])
    fmt_at = starts + info + 6
    assert struct.unpack_from("<H", arm, fmt_at)[0] in (mo.DYLD_CHAINED_PTR_64, mo.DYLD_CHAINED_PTR_64_OFFSET)
    assert "chained pointer format 1" in mload(patched(arm, fmt_at, "<H", 1)).problem


MH_FLAGS = 24


@pytest.mark.parametrize("arch,tag", [("x86_64", "exec_chained"), ("arm64", "exec_classic")])
def test_a_non_pie_executable_declines(arch, tag):
    data = fixture(arch, tag)
    flags = struct.unpack_from("<I", data, MH_FLAGS)[0]
    assert flags & mo.MH_PIE and mload(data).problem is None
    unpie = patched(data, MH_FLAGS, "<I", flags & ~mo.MH_PIE)
    assert mload(unpie).problem == "a non-PIE Mach-O executable is not modelled"
    # a dylib carries no PIE flag and is position-independent by kind
    dylib = fixture(arch, "chained")
    assert not struct.unpack_from("<I", dylib, MH_FLAGS)[0] & mo.MH_PIE and mload(dylib).problem is None


@engine
def test_emulate_symbol_declines_an_image_with_a_problem():
    need_engine()
    arm = fixture("arm64", "chained")
    with pytest.raises(ni.EmulationError, match="arm64e"):
        ni.emulate_symbol(patched(arm, 8, "<I", 0x80000002), "b241_seed", [])
    exe = fixture("x86_64", "exec_chained")
    flags = struct.unpack_from("<I", exe, MH_FLAGS)[0]
    with pytest.raises(ni.EmulationError, match="non-PIE"):
        ni.emulate_symbol(patched(exe, MH_FLAGS, "<I", flags & ~mo.MH_PIE), "b241_seed", [])


# ------------------------------------------------------------------ only a Mach-O caller gets a Mach-O
def test_load_refuses_a_mach_o_file_without_the_opt_in():
    for data in (fixture("arm64", "chained"), fixture("x86_64", "exec_chained"),
                 universal((mo.CPU_X86_64, 3, fixture("x86_64", "classic")))):
        with pytest.raises(ni.EmulationError, match="a Mach-O .*not an ELF"):
            ni.load(data)
    # the opt-in parses it, and the cached Mach-O image is not handed to a later caller without it
    assert isinstance(mload(fixture("arm64", "chained")), mo.MachOImage)
    with pytest.raises(ni.EmulationError, match="not an ELF"):
        ni.load(fixture("arm64", "chained"))


def test_the_binary_lanes_reader_declines_a_mach_o():
    binary = str(ROOT / "solvers" / "binary")
    if binary not in sys.path:
        sys.path.insert(0, binary)
    import native_behavior as nb
    data = fixture("x86_64", "exec_chained")
    assert isinstance(mload(data), mo.MachOImage)                       # cached: the gate must still hold
    with pytest.raises(nb.Decline, match="not an ELF"):
        nb.discover(data, nb.Contract(argument=1, width=8, endian="little", explicit_address=0x5C0))


# ------------------------------------------------------------------ hostile fixup streams stay bounded
def _uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        low, n = n & 0x7F, n >> 7
        out.append(low | (0x80 if n else 0))
        if not n:
            return bytes(out)


def hostile(stream: bytes, which: str, nsyms: int = 0, data_size: int = 0x1000, extra=()) -> bytes:
    """A dylib of three segments (__TEXT r-x, __DATA rw- of `data_size` zero-fill bytes, __LINKEDIT) whose
    `which` dyld-info stream is `stream`, with `nsyms` external symbols defined besides `_f` (all at 0x100)
    and the external symbols `extra`, (name, address) pairs."""
    symbols = [(b"_f", 0x100)] + [(b"_s%d" % k, 0x100) for k in range(nsyms)] + list(extra)
    names = [name for name, _ in symbols]
    strings = b"\0" + b"".join(name + b"\0" for name in names)
    table, at = b"", 1
    for name, value in symbols:
        table += struct.pack("<IBBHQ", at, 0x0F, 1, 0, value)
        at += len(name) + 1
    linkedit = 0x2000
    stream_at, table_at = linkedit, linkedit + ((len(stream) + 7) & ~7)
    strings_at = table_at + len(table)
    end = strings_at + len(strings)

    def segment(name, vmaddr, vmsize, fileoff, filesize, prot):
        return struct.pack("<II16sQQQQiiII", 0x19, 72, name, vmaddr, vmsize, fileoff, filesize, prot, prot, 0, 0)

    offs = [0] * 10
    offs[{"rebase": 0, "bind": 2}[which]], offs[{"rebase": 1, "bind": 3}[which]] = stream_at, len(stream)
    commands = (segment(b"__TEXT", 0, 0x1000, 0, 0x1000, 5)
                + segment(b"__DATA", 0x1000, data_size, 0x1000, 0, 3)
                + segment(b"__LINKEDIT", 0x1000 + data_size, (end - linkedit + 0xFFF) & ~0xFFF, linkedit,
                          end - linkedit, 1)
                + struct.pack("<II10I", 0x80000022, 48, *offs)
                + struct.pack("<IIIIII", 0x2, 24, table_at, len(names), strings_at, len(strings)))
    out = bytearray(end)
    out[:32] = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, 6, 5, len(commands), 0, 0)
    out[32:32 + len(commands)] = commands
    out[stream_at:stream_at + len(stream)] = stream
    out[table_at:table_at + len(table)] = table
    out[strings_at:strings_at + len(strings)] = strings
    return bytes(out)


class OverBudget(Exception):
    pass


@contextlib.contextmanager
def cpu_bounded(seconds: float):
    """Raise OverBudget in the test once it has spent `seconds` of this process's own CPU time (a hostile
    stream the parser does not bound would otherwise never return). Load on the machine does not count."""
    def fire(_signum, _frame):
        raise OverBudget(f"parsing spent more than {seconds} CPU seconds")

    previous = signal.signal(signal.SIGVTALRM, fire)
    signal.setitimer(signal.ITIMER_VIRTUAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_VIRTUAL, 0)
        signal.signal(signal.SIGVTALRM, previous)


HUGE = _uleb(1 << 62)


def test_a_non_pointer_fixup_repeated_2_to_the_62_declines_at_once():
    text_rebase = bytes([0x12, 0x20]) + _uleb(0) + bytes([0x60]) + HUGE            # type 2 (text), seg 0, x 2**62
    text_bind = bytes([0x52, 0x30, 0x40]) + b"_f\0" + bytes([0x70]) + _uleb(0) + bytes([0xC0]) + HUGE + _uleb(0)
    with cpu_bounded(30):
        assert mo.MachOImage(hostile(text_rebase, "rebase")).problem == "a text rebase is not modelled"
        assert mo.MachOImage(hostile(text_bind, "bind")).problem == "a text bind is not modelled"


def test_a_single_text_fixup_declines_too():
    """One text rebase (REBASE_OPCODE_DO_REBASE_IMM_TIMES 1) or one text bind (BIND_OPCODE_DO_BIND) into
    __DATA is still a fixup the engine does not apply: the image declines, it is not planned as a pointer."""
    text_rebase = bytes([0x12, 0x21]) + _uleb(0x10) + bytes([0x51])                 # type 2, seg 1 + 0x10, x 1
    pointer_rebase = bytes([0x11, 0x21]) + _uleb(0x10) + bytes([0x51])              # the same as a pointer
    text_bind = bytes([0x52, 0x30, 0x40]) + b"_f\0" + bytes([0x71]) + _uleb(0x10) + bytes([0x90])
    pointer_bind = bytes([0x51, 0x30, 0x40]) + b"_f\0" + bytes([0x71]) + _uleb(0x10) + bytes([0x90])
    img = mo.MachOImage(hostile(text_rebase, "rebase"))
    assert img.problem == "a text rebase is not modelled" and img.plan == []
    img = mo.MachOImage(hostile(text_bind, "bind"))
    assert img.problem == "a text bind is not modelled" and img.plan == []
    assert mo.MachOImage(hostile(pointer_rebase, "rebase")).problem is None          # control: one pointer is fine
    img = mo.MachOImage(hostile(pointer_bind, "bind"))
    assert img.problem is None and img.plan == [(0x1010, "sym", 0x100)]


def test_a_self_bind_to_a_name_two_symbols_define_is_poisoned():
    """BIND_SPECIAL_DYLIB_SELF to `_g`: one definition (or two at one address) resolves; two definitions at
    different addresses are ambiguous and the slot is poisoned, never pointed at one of them."""
    bind = bytes([0x30, 0x40]) + b"_g\0" + bytes([0x51, 0x71]) + _uleb(0) + bytes([0x90])
    assert mo.MachOImage(hostile(bind, "bind", extra=[(b"_g", 0x200)])).plan == [(0x1000, "sym", 0x200)]
    same = mo.MachOImage(hostile(bind, "bind", extra=[(b"_g", 0x200), (b"_g", 0x200)]))
    assert same.plan == [(0x1000, "sym", 0x200)]
    two = mo.MachOImage(hostile(bind, "bind", extra=[(b"_g", 0x200), (b"_g", 0x300)]))
    assert two.plan == [(0x1000, "poison", 8)]


def test_a_pointer_fixup_repeated_2_to_the_62_stops_at_the_fixup_cap():
    rebase = bytes([0x11, 0x20]) + _uleb(0) + bytes([0x60]) + HUGE                  # pointer rebases over __TEXT
    with cpu_bounded(20), pytest.raises(ni.EmulationError, match="too many fixups"):
        mo.MachOImage(hostile(rebase, "rebase"))


def test_self_binds_against_a_large_symbol_table_stay_linear():
    """MAX_FIXUPS self binds into a __DATA big enough to take them all, against 50000 symbols: a lookup that
    scanned the symbol table per bind spends about 10**10 steps (minutes of CPU) here; indexed, well under a
    second of CPU, so the 20 s CPU guard has a wide margin at any machine load."""
    bind = bytes([0x30, 0x40]) + b"_f\0" + bytes([0x51, 0x71]) + _uleb(0) + bytes([0xC0]) + HUGE + _uleb(0)
    with cpu_bounded(20), pytest.raises(ni.EmulationError, match="too many fixups"):
        mo.MachOImage(hostile(bind, "bind", nsyms=50000, data_size=0x200000))
    few = bytes([0x30, 0x40]) + b"_f\0" + bytes([0x51, 0x71]) + _uleb(0) + bytes([0xC0]) + _uleb(3) + _uleb(0)
    img = mo.MachOImage(hostile(few, "bind", nsyms=50000, data_size=0x200000))
    assert img.problem is None and img.plan == [(0x1000 + 8 * k, "sym", 0x100) for k in range(3)]


# ------------------------------------------------------------------ running a function of the image
@engine
@pytest.mark.parametrize("arch,tag", VARIANTS)
def test_a_function_runs_to_the_models_value(arch, tag):
    need_engine()
    data = fixture(arch, tag)
    for text, k in INPUTS:
        # strlen, malloc, memcpy and free through the stubs, the rebased word table, a sibling call, the
        # constructor's seed and the stack protector's guard all have to be right for this to match
        assert ni.emulate_symbol(data, "b241_mix", [text.encode() + b"\0", k]) == model_mix(text, k), (text, k)
    assert ni.emulate_symbol(data, "_b241_mix", [b"hello\0", 3], arch=ARCH[arch]) == model_mix("hello", 3)
    with pytest.raises(ni.EmulationError, match="image is"):
        ni.emulate_symbol(data, "b241_mix", [b"hello\0", 3], arch="arm64" if arch == "x86_64" else "x86-64")


@engine
@pytest.mark.parametrize("arch,tag", VARIANTS)
def test_the_initializer_runs_before_the_call_and_an_unmodelled_import_declines(arch, tag):
    need_engine()
    data = fixture(arch, tag)
    assert ni.emulate_symbol(data, "b241_seed", []) == SEED               # the constructor ran first
    assert ni.emulate_symbol(data, "b241_seed", [], init="skip") == 0     # the pristine image: not yet set
    with pytest.raises(ni.EmulationError, match="call to unresolved import getpid"):
        ni.emulate_symbol(data, "b241_pid", [])
    with pytest.raises(ni.EmulationError, match="no function symbol"):
        ni.emulate_symbol(data, "b241_words", [])                          # a data symbol is not a function


@engine
def test_a_universal_file_runs_the_named_slice():
    need_engine()
    fat = universal((mo.CPU_X86_64, 3, fixture("x86_64", "classic")), (mo.CPU_ARM64, 0, fixture("arm64", "chained")))
    for arch in ("x86-64", "arm64"):
        assert ni.emulate_symbol(fat, "b241_mix", [b"abc\0", 5], arch=arch) == model_mix("abc", 5)
    with pytest.raises(ni.EmulationError, match="name the arch"):
        ni.emulate_symbol(fat, "b241_mix", [b"abc\0", 5])


@engine
def test_an_elf_is_still_an_elf():
    """The Mach-O path is chosen by the file's magic alone: the committed ELF fixtures load as before."""
    need_engine()
    img = ni.load((FX / "kb2_jni_x86_64.so").read_bytes())  # ELF: no opt-in needed
    assert isinstance(img, ni.ElfImage) and not mo.is_macho(img.data)


@engine
@pytest.mark.needs_tool("cc")
def test_a_fresh_build_of_the_source_runs_the_same(tmp_path):
    """Rebuild the fixtures with this host's toolchain: a linker that changes how it encodes fixups is
    caught here rather than at an event."""
    need_engine()
    if sys.platform != "darwin":
        pytest.skip("the Mach-O fixtures are linked by the macOS linker; this is not macOS")
    import b241_fixture_asm as builder
    built = builder.build_macho(tmp_path)
    assert [path.name for path in built] == [name for name, _extra in builder.MACHO_BUILDS]
    for path in built:
        data = path.read_bytes()
        assert mload(data).problem is None, path.name
        for text, k in INPUTS[:3]:
            assert ni.emulate_symbol(data, "b241_mix", [text.encode() + b"\0", k]) == model_mix(text, k), path.name
        assert ni.emulate_symbol(data, "b241_seed", [], init="skip") == 0
