"""B-166 fix round 1: ``native_image.emulate_call(output="capture")`` -- output imports as captured sinks.

A decoder that prints its own output (puts / putchar / printf / write, often ``main`` itself) used to
decline at the first call into the import.  With ``output="capture"`` those calls are modelled: what they
print comes back in ``CallResult.stdout`` / ``stderr``, nothing is written anywhere, and every case whose
output the C standard does not fix (an address, a conversion the model does not take, a descriptor other
than 1 or 2, stdio mixed with write(2) on one descriptor, puts's return value) declines.  The default,
``output="decline"``, keeps the old behaviour.

Fixtures: ``dd_print_{x86_64,arm64}`` from tests/decoder_discovery_fixtures.py (our own C, committed).  The
expected text is written here (the flag plaintext and Python's own %-formatting), never read back from the
builder.  ``_Run._format`` is also tested on its own with a small stand-in for the run's memory, so its
rules are pinned without Unicorn.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for _p in (ROOT, ROOT / "solvers" / "common"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import native_image as ni               # noqa: E402  (flat import, the engine sys.path)

FIX = Path(__file__).resolve().parent / "fixtures" / "decoder_discovery"
ARCHES = ("x86_64", "arm64")
PRINT_FLAG = b"CSCTF{pr1nt3d_by_th3_d3c0d3r}"
needs_unicorn = pytest.mark.skipif(not ni.UNICORN_AVAILABLE,
                                   reason="needs_tool: unicorn is guarded off on this host (native_emulate)")


def blob(name: str) -> bytes:
    return (FIX / (name + ".so")).read_bytes()


def run(arch, name, args=(), **kw):
    return ni.emulate_call(blob("dd_print_" + arch), name, list(args), output="capture", **kw)


# ------------------------------------------------------------------ through the emulator
@needs_unicorn
@pytest.mark.parametrize("arch", ARCHES)
def test_a_decoder_that_prints_is_evaluated_and_its_output_captured(arch):
    r = run(arch, "dd_print_flag")
    assert (r.stdout, r.stderr) == (b"flag: " + PRINT_FLAG + b"\n", b"")
    p = run(arch, "dd_putc_flag")
    assert (p.stdout, p.stderr) == (PRINT_FLAG + b"\n", b"")
    assert (p.value, p.value32) == (None, ord("\n"))    # putchar returns the character (an int: high half undefined)
    w = run(arch, "dd_write_flag")
    assert (w.stdout, w.stderr) == (b"", PRINT_FLAG)      # write(2, ...) is standard error, kept apart
    assert w.value == len(PRINT_FLAG)                    # write's ssize_t result is left in the return register
    one = run(arch, "dd_write1")
    assert (one.stdout, one.stderr) == (b"ok\n", b"")    # write(1, ...) alone is standard output


@needs_unicorn
@pytest.mark.parametrize("arch", ARCHES)
def test_the_default_still_declines_a_call_into_an_output_import(arch):
    with pytest.raises(ni.EmulationError, match="call to unresolved import printf"):
        ni.emulate_call(blob("dd_print_" + arch), "dd_print_flag", [])
    with pytest.raises(ni.EmulationError, match="output must be"):
        ni.emulate_call(blob("dd_print_" + arch), "dd_print_flag", [], output="print")


@needs_unicorn
@pytest.mark.parametrize("arch", ARCHES)
def test_printf_formats_every_modelled_conversion_exactly(arch):
    v, w = -42, 123456789012
    want = ("[%5d|%-4x|%04X|%c|%.3s|%d|%d|%06d|%%]\n" % (v, 0xAB, 0xBEEF, "Z", "abcdef", 300 - 256, w, v)).encode()
    r = run(arch, "dd_fmt", [v & 0xFFFFFFFF, w])
    assert r.stdout == want and (r.value, r.value32) == (None, len(want))   # printf: the bytes it wrote, an int
    chk = run(arch, "dd_chk", [10])                      # __printf_chk(flag, format, ...)
    assert (chk.stdout, chk.value32) == (b"chk 10\n", 7)
    # eight variadic integers: on x86-64 three, on AArch64 one, come from the caller's stack
    many = run(arch, "dd_many", [10])
    assert many.stdout == (" ".join(str(10 + i) for i in range(8)) + "|\n").encode()


@needs_unicorn
@pytest.mark.parametrize("arch", ARCHES)
def test_output_the_c_standard_does_not_fix_declines(arch):
    with pytest.raises(ni.EmulationError, match="printf conversion %p is not modelled"):
        run(arch, "dd_fmt_ptr")
    with pytest.raises(ni.EmulationError, match="through stdio and through write"):
        run(arch, "dd_mixed")
    with pytest.raises(ni.EmulationError, match="file descriptor 3"):
        run(arch, "dd_badfd")
    with pytest.raises(ni.EmulationError, match="disagree on what the call wrote"):
        run(arch, "dd_print_addr")                        # the text of an address differs between the layouts
    # puts returns "a non-negative value": the layouts answer differently, so the value is no result,
    # while what it printed is
    r = run(arch, "dd_puts_ret")
    assert (r.stdout, r.value, r.value32) == (b"x\n", None, None)


@needs_unicorn
def test_printed_output_is_bounded(monkeypatch):
    monkeypatch.setattr(ni, "MAX_OUTPUT", len(PRINT_FLAG) + 1)
    assert run("x86_64", "dd_putc_flag").stdout == PRINT_FLAG + b"\n"          # exactly at the bound
    with pytest.raises(ni.EmulationError, match="printed more than"):
        run("x86_64", "dd_print_flag")                                         # "flag: ..." is longer
    monkeypatch.setattr(ni, "MAX_OUTPUT", len(PRINT_FLAG))
    with pytest.raises(ni.EmulationError, match="printed more than"):
        run("x86_64", "dd_putc_flag")                  # one byte at a time: the bound is on the whole output


@needs_unicorn
def test_an_output_buffers_initial_bytes_must_lie_inside_it():
    data = blob("dd_print_x86_64")
    for init in (((6, b"abc"),), ((-1, b"a"),)):
        with pytest.raises(ni.EmulationError, match="initial bytes outside the output buffer"):
            ni.emulate_call(data, "dd_print_flag", [ni.OutBuf(8, init)], output="capture")
    assert ni.OutBuf(8, ((5, b"abc"),)).init == ((5, b"abc"),)


# ------------------------------------------------------------------ the sink models on their own
class _Sinks:
    """A stand-in for one run: the argument registers, the stack, readable memory and the stream table."""
    _emit = ni._Run._emit
    _vararg = ni._Run._vararg
    _sink = ni._Run._sink

    def __init__(self, regs, mem=None, x86=True, stack=None):
        self.x86, self.regs, self.mem, self.stack = x86, dict(regs), dict(mem or {}), dict(stack or {})
        self.sinks = {"stdio": bytearray(), 1: bytearray(), 2: bytearray()}
        self.L = {"puts_ret": None}

    def _args(self, n):
        names = ("rdi", "rsi", "rdx", "rcx", "r8", "r9") if self.x86 else tuple("x%d" % i for i in range(8))
        return [self.regs.get(names[i], 0) for i in range(n)]

    def rr(self, name):
        return self.regs.get(name, 0)

    def read(self, addr, n):
        if addr in self.stack:
            return self.stack[addr][:n]
        return self.mem[addr][:n]


def test_write_takes_the_low_32_bits_of_its_descriptor_and_bounds_its_length():
    run = _Sinks({"rdi": 0xA5A5A5A5_00000001, "rsi": 0x100, "rdx": 3}, {0x100: b"abc"})
    assert run._sink("write") == (3, "ptr") and bytes(run.sinks[1]) == b"abc"
    big = _Sinks({"rdi": 1, "rsi": 0x100, "rdx": ni.MAX_OUTPUT + 1}, {0x100: b"x" * (ni.MAX_OUTPUT + 1)})
    with pytest.raises(ni.EmulationError, match="write of %d bytes" % (ni.MAX_OUTPUT + 1)):
        big._sink("write")


def test_variadic_arguments_past_the_registers_come_from_the_stack_and_are_bounded():
    # x86-64: six registers, then 8-byte slots above the return address the trap still has on the stack
    x86 = _Sinks({"rsi": 0x11, "rsp": 0x1000}, stack={0x1008: b"\x07\x00\x00\x00\xa5\xa5\xa5\xa5",
                                                     0x1010: b"\x08" + bytes(7)})
    assert x86._vararg(1, 8) == 0x11
    high = _Sinks({"rsi": 0xA5A5A5A5_00000002})
    assert high._vararg(1, 4) == 2 and high._vararg(1, 8) == 0xA5A5A5A5_00000002    # an int is its low half
    assert x86._vararg(6, 4) == 7 and x86._vararg(7, 8) == 8
    a64 = _Sinks({"x7": 0x77, "sp": 0x2000}, x86=False, stack={0x2000: b"\x09" + bytes(7)})
    assert a64._vararg(7, 8) == 0x77 and a64._vararg(8, 4) == 9      # AArch64: eight registers, no return address
    with pytest.raises(ni.EmulationError, match="more than 38 arguments"):
        x86._vararg(6 + 32, 4)


def test_the_sink_names_are_the_ones_modelled():
    assert set(ni.SINK_FUNCS) == {"puts", "putchar", "printf", "__printf_chk", "write"}
    with pytest.raises(ni.EmulationError, match="output function fputs is not modelled"):
        _Sinks({})._sink("fputs")


# ------------------------------------------------------------------ the formatter on its own
class _Mem:
    """The two things _Run._format reads: variadic integer arguments and C strings."""

    def __init__(self, args, strings=None):
        self.args, self.strings, self.sizes = list(args), dict(strings or {}), []

    def _vararg(self, k, size):
        self.sizes.append((k, size))
        return self.args[k] & ((1 << (8 * size)) - 1)

    def cstr(self, p, limit):
        return self.strings[p]

    def _strn(self, p, n):
        return self.strings[p][:n]


def fmt(text, args=(), strings=None, first=1):
    mem = _Mem([0] * first + list(args), strings)
    return ni._Run._format(mem, text.encode(), first), mem


@pytest.mark.parametrize("text,args,want", [
    ("plain %% text", (), "plain % text"),
    ("%d|%i|%u", (-5 & 0xFFFFFFFF, 7, -1 & 0xFFFFFFFF), "-5|7|4294967295"),
    ("%x|%X|%lx", (0xBEEF, 0xBEEF, 0x1122334455), "beef|BEEF|1122334455"),
    ("%5d|%-5d|%05d|%-05d", (42, 42, -42 & 0xFFFFFFFF, 42), "   42|42   |-0042|42   "),
    ("%hd|%hhu|%hhd", (0x18000, 0x1FF, 0x80), "-32768|255|-128"),
    ("%lld|%zu|%jd|%td", (-(1 << 40) & ((1 << 64) - 1), 1 << 40, -5 & ((1 << 64) - 1), 1 << 33),
     "-1099511627776|1099511627776|-5|8589934592"),
    ("%c%c|%3c|%-3c|", (0x141, 0x42, 0x43, 0x44), "AB|  C|D  |"),
])
def test_format_integer_and_character_conversions(text, args, want):
    out, _ = fmt(text, args)
    assert out == want.encode()


def test_format_strings_and_their_precision():
    out, _ = fmt("[%s|%.2s|%6s|%-6s|%.0s]", (1, 1, 2, 2, 1), {1: b"hello", 2: b"ab"})
    assert out == b"[hello|he|    ab|ab    |]"


def test_format_reads_only_the_width_a_conversion_takes():
    # an int is read as 4 bytes (a caller may store only those on the stack), a long and a pointer as 8
    _, mem = fmt("%d %c %ld %s %hhd", (1, 2, 3, 9, 4), {9: b"s"})
    assert mem.sizes == [(1, 4), (2, 4), (3, 8), (4, 8), (5, 4)]
    _, chk = fmt("%d", (7,), first=2)                    # __printf_chk: the flag comes first
    assert chk.sizes == [(2, 4)]


@pytest.mark.parametrize("text,match", [
    ("%p", "%p is not modelled"), ("%f", "%f is not modelled"), ("%n", "%n is not modelled"),
    ("%#x", "conversion %# is not modelled"), ("%+d", "conversion %\\+ is not modelled"),
    ("% d", "conversion %  is not modelled"), ("%*d", "conversion %\\* is not modelled"),
    ("%1$d", "conversion %\\$ is not modelled"), ("%.2d", "integer precision"),
    ("%05s", "%s with a flag"), ("%ls", "%s with a flag"), ("%05c", "%c with a flag"), ("%.1c", "%c with a flag"),
    ("%lc", "%c with a flag"), ("abc%", "ends inside a conversion"), ("%l", "ends inside a conversion"),
    ("%99999d", "width or precision too large"), ("%.99999s", "width or precision too large"),
])
def test_format_refuses_what_it_does_not_model(text, match):
    with pytest.raises(ni.EmulationError, match=match):
        fmt(text, (1, 2, 3), {1: b"x"})


def test_format_of_a_null_string_declines():
    with pytest.raises(ni.EmulationError, match="NULL"):
        fmt("%s", (0,))
