"""B-166: ``native_image.emulate_call`` -- a call rebuilt from a call site, in the whole loaded image.

``emulate_call`` is ``emulate_symbol`` with two more argument kinds (``ImagePtr``: the image's own
pointer; ``OutBuf``: an undefined output buffer returned in the object), a structured result (the return
register at 64 and 32 bits, the string at a returned pointer) and ``state="report"`` (the image memory the
call changed, for a decoder that fills a global).

Fixtures: the synthetic images of tests/decoder_discovery_fixtures.py (our own C and assembly, committed
under tests/fixtures/decoder_discovery).  Nothing is run on the host.  Every expected value is an
independent Python model written here.
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
M64 = (1 << 64) - 1

pytestmark = pytest.mark.skipif(not ni.UNICORN_AVAILABLE,
                                reason="needs_tool: unicorn is guarded off on this host (native_emulate)")

FLAG = b"CSCTF{d3c0d3r_b0und_at_th3_c4ll_s1te}"
STATE_FLAG = b"CSCTF{c0nstruct0r_pr3p4red_th3_t4ble}"
STATE_BLOB = b"the quick brown fox jumps over the lazy dog"
LEAD_FLAG = b"CSCTF{th3_l34d_b0und_th3_k3y}"
INOUT_PLAIN = b"caller filled this first"
ARCHES = ("x86_64", "arm64")


def m_enc(plain: bytes, key: int) -> bytes:
    return bytes(p ^ ((key + 7 * i) & 0xFF) for i, p in enumerate(plain))


def m_mix(x: int) -> int:
    x ^= x >> 31
    x = (x * 0x6F2B8A4D93C5E1B7) & M64
    x ^= x >> 27
    x = (x * 0xC3A5F18E7D2B964B) & M64
    return x ^ (x >> 33)


def blob(name: str) -> bytes:
    return (FIX / (name + ".so")).read_bytes()


def find(data: bytes, needle: bytes) -> int:
    """The image vaddr of the one place the file-backed image holds ``needle``."""
    img = ni.load(data)
    hits = []
    for va, _memsz, filesz, off, _flags in img.loads:
        at = img.data.find(needle, off, off + filesz)
        while at >= 0:
            hits.append(va + at - off)
            at = img.data.find(needle, at + 1, off + filesz)
    assert len(hits) == 1, hits
    return hits[0]


def data_symbol(data: bytes, name: str) -> int:
    (value,) = {s.value for s in ni.load(data).dynsyms if s.name == name}
    return value


# ------------------------------------------------------------------ arguments
@pytest.mark.parametrize("arch", ARCHES)
def test_an_image_pointer_and_an_output_buffer_rebuild_the_programs_own_call(arch):
    data = blob("dd_flag_" + arch)
    enc = find(data, m_enc(FLAG, 0x5A))
    out = ni.OutBuf(64)
    assert out.written() == b""                                  # before any call
    ni.emulate_call(data, "dd_xor_decode", [ni.ImagePtr(enc), len(FLAG), 0x5A, out])
    n = len(FLAG) + 1
    assert out.data == FLAG + b"\x00" + bytes(64 - n)            # an undefined byte reads 0
    assert out.defined == b"\x01" * n + bytes(64 - n)
    assert out.written() == FLAG + b"\x00"
    # by image vaddr as well as by (local) symbol name
    again = ni.OutBuf(64)
    ni.emulate_call(data, ni.load(data).symbol("dd_xor_decode"), [ni.ImagePtr(enc), 5, 0x5A, again])
    assert again.written() == FLAG[:5] + b"\x00"


@pytest.mark.parametrize("arch", ARCHES)
def test_the_result_carries_the_return_register_and_a_returned_string(arch):
    data = blob("dd_flag_" + arch)
    r = ni.emulate_call(data, "dd_mix", [0x1337])
    assert (r.value, r.value32, r.cstr, r.changes) == (m_mix(0x1337), m_mix(0x1337) & 0xFFFFFFFF, None, [])
    w = ni.emulate_call(data, "dd_word", [2])
    assert (w.value, w.value32, w.cstr) == (None, None, b"charlie")     # a pointer: the layouts differ
    assert ni.emulate_call(data, "dd_first", []).value32 == ord("o")    # through a relocated pointer
    text = find(data, b"hello, decoder\x00")
    assert ni.emulate_call(data, "dd_len", [ni.ImagePtr(text)]).value == 15      # strlen through the PLT


def test_a_string_returned_on_the_heap_is_read():
    r = ni.emulate_call(blob("dd_inout_x86_64"), "dd_dup", [3])
    assert (r.value, r.value32, r.cstr) == (None, None, b"heap3")
    # ... but a returned string whose text depends on the block's address is no result at all
    with pytest.raises(ni.EmulationError, match="the two runs disagree"):
        ni.emulate_call(blob("dd_inout_x86_64"), "dd_addr", [])


def test_an_undefined_byte_reads_zero_whatever_it_holds():
    assert ni._defined_only(b"\x05\x06\x07", b"\x01\x00\x01") == b"\x05\x00\x07"
    assert ni._defined_only(b"", b"") == b""


def test_an_output_buffer_is_undefined_until_written():
    data = blob("dd_inout_x86_64")
    with pytest.raises(ni.EmulationError, match="undefined"):
        ni.emulate_call(data, "dd_inplace", [ni.OutBuf(32), 24])
    # the same function on a DEFINED in/out buffer decodes it in place
    buf = bytearray(bytes(p ^ 0x42 for p in INOUT_PLAIN))
    ni.emulate_call(data, "dd_inplace", [buf, len(INOUT_PLAIN)])
    assert bytes(buf) == INOUT_PLAIN


def test_one_output_buffer_passed_twice_is_one_buffer():
    data = blob("dd_inout_x86_64")
    both = ni.OutBuf(16)
    assert ni.emulate_call(data, "dd_alias", [both, both]).value32 == ord("x")
    assert both.written() == b"x"
    with pytest.raises(ni.EmulationError, match="undefined"):
        ni.emulate_call(data, "dd_alias", [ni.OutBuf(16), ni.OutBuf(16)])


def test_a_buffer_whose_content_depends_on_an_address_declines():
    data = blob("dd_lead_x86_64")
    enc = find(data, m_enc(LEAD_FLAG, 0x5A))
    with pytest.raises(ni.EmulationError, match="disagree on what the call wrote"):
        # the key is a pointer here: its value differs between the two layouts, and so does the output
        ni.emulate_call(data, "dd_keyed", [ni.ImagePtr(enc), len(LEAD_FLAG), ni.OutBuf(8), ni.OutBuf(64)])
    good = ni.OutBuf(64)
    ni.emulate_call(data, "dd_keyed", [ni.ImagePtr(enc), len(LEAD_FLAG), 0x5A, good])
    assert good.written() == LEAD_FLAG + b"\x00"


def test_a_return_value_that_depends_on_an_address_declines_or_is_none():
    track = blob("dd_track_x86_64")
    with pytest.raises(ni.EmulationError, match="the two runs disagree"):
        ni.emulate_call(track, "tk_arith", [])                   # returns an image address plus a constant
    data = blob("dd_flag_x86_64")
    buf = ni.OutBuf(8)
    r = ni.emulate_call(data, "dd_mix", [buf])                   # mixes the buffer's ADDRESS
    assert (r.value, r.value32, r.cstr) == (None, None, None) and buf.written() == b""


def test_arguments_are_validated():
    data = blob("dd_flag_x86_64")
    for bad, why in ((ni.OutBuf(0), "output buffer of 0 bytes"),
                     (ni.OutBuf(ni.MAX_OUTBUF + 1), "output buffer"),
                     (ni.ImagePtr(0x7000_0000), "not inside a segment"),
                     (True, "must be an int"), ("text", "must be an int"), (1.5, "must be an int")):
        with pytest.raises(ni.EmulationError, match=why):
            ni.emulate_call(data, "dd_mix", [bad])
    assert ni.emulate_call(data, "dd_mix", [ni.OutBuf(ni.MAX_OUTBUF)]).value is None    # the cap itself is fine
    with pytest.raises(ni.EmulationError, match="state must be"):
        ni.emulate_call(data, "dd_mix", [1], state="allow")
    with pytest.raises(ni.EmulationError, match="init must be"):
        ni.emulate_call(data, "dd_mix", [1], init="maybe")
    with pytest.raises(ni.EmulationError, match="no function symbol"):
        ni.emulate_call(data, "dd_missing", [1])
    with pytest.raises(ni.EmulationError, match="not inside an executable segment"):
        ni.emulate_call(data, find(data, m_enc(FLAG, 0x5A)), [1])
    with pytest.raises(ni.EmulationError, match="image is x86-64, not arm64"):
        ni.emulate_call(data, "dd_mix", [1], arch="arm64")
    assert ni.emulate_call(data, "dd_mix", [1], arch="x86-64").value == m_mix(1)


def test_budgets_are_work_bounds():
    data = blob("dd_flag_x86_64")
    with pytest.raises(ni.EmulationError, match="budget"):
        ni.emulate_call(data, "dd_round", [0x10, 3], max_blocks=1)
    with pytest.raises(ni.EmulationError, match="budget"):
        ni.emulate_call(data, "dd_xor_decode", [ni.ImagePtr(find(data, m_enc(FLAG, 0x5A))), len(FLAG), 0x5A,
                                               ni.OutBuf(64)], max_mem=4)


def test_unicorn_guarded_off_is_named(monkeypatch):
    monkeypatch.setattr(ni, "UNICORN_AVAILABLE", False)
    with pytest.raises(ni.EmulationError, match="unicorn engine not available"):
        ni.emulate_call(blob("dd_flag_x86_64"), "dd_mix", [1])


# ------------------------------------------------------------------ the load phase and image state
@pytest.mark.parametrize("arch", ARCHES)
def test_state_check_declines_and_state_report_returns_what_changed(arch):
    data = blob("dd_state_" + arch)
    with pytest.raises(ni.EmulationError, match="state escapes the call"):
        ni.emulate_call(data, "dd_table_flag", [])
    r = ni.emulate_call(data, "dd_table_flag", [], state="report")
    assert r.cstr == STATE_FLAG and r.value is None
    assert [d for _va, d in r.changes] == [STATE_FLAG]           # OUT was zero: its NUL did not change
    (out_va, _d), = r.changes
    seg = ni.load(data).seg_of(out_va)
    assert seg[4] & 2 and out_va >= seg[0] + seg[2]              # in .bss: writable, past the file-backed part


def test_the_constructors_run_first_unless_skipped():
    data = blob("dd_state_x86_64")
    pristine = bytes(((((p + 3 * i) & 0xFF) ^ 0xA7) - 3 * i) & 0xFF for i, p in enumerate(STATE_FLAG))
    assert pristine != STATE_FLAG and pristine[0] and pristine[-1]
    r = ni.emulate_call(data, "dd_table_flag", [], init="skip", state="report")
    # the table as the file holds it (one byte of it decodes to the 0 the buffer already held: the run
    # around it is still one run)
    assert [d for _va, d in r.changes] == [pristine]
    assert ni.emulate_call(data, "dd_table_flag", [], init="auto", state="report").changes[0][1] == STATE_FLAG


@pytest.mark.parametrize("arch", ARCHES)
def test_a_global_decoded_in_place_through_its_own_pointer(arch):
    data = blob("dd_state_" + arch)
    enc = bytes((((p + i) & 0xFF) ^ 0x33) for i, p in enumerate(STATE_BLOB + b"\x00"))
    va = find(data, enc)
    r = ni.emulate_call(data, "dd_unmask", [ni.ImagePtr(va), len(enc), 0x33], state="report")
    assert r.changes == [(va, STATE_BLOB + b"\x00")]
    with pytest.raises(ni.EmulationError, match="state escapes the call"):
        ni.emulate_call(data, "dd_unmask", [ni.ImagePtr(va), len(enc), 0x33])


def test_changed_bytes_close_together_are_one_run_and_far_apart_are_two():
    data = blob("dd_state_x86_64")
    pad = data_symbol(data, "dd_pad")
    r = ni.emulate_call(data, "dd_poke", [], state="report")
    assert r.changes == [(pad, b"\x01" + bytes(7) + b"\x02"), (pad + 100, b"\x03")]


def test_a_change_that_is_undefined_or_differs_between_the_layouts_declines():
    # AArch64: memcpy of eight stack bytes nothing wrote -> the global ends undefined
    with pytest.raises(ni.EmulationError, match="left image memory it changed undefined"):
        ni.emulate_call(blob("dd_state_arm64"), "dd_leak", [], state="report")
    # x86-64: the same source pushes a (poisoned) register first, so the bytes are defined but differ
    with pytest.raises(ni.EmulationError, match="disagree on what the call wrote"):
        ni.emulate_call(blob("dd_state_x86_64"), "dd_leak", [], state="report")


def test_a_write_to_thread_local_storage_declines_even_when_reporting():
    with pytest.raises(ni.EmulationError, match="thread-local storage"):
        ni.emulate_call(blob("dd_track_x86_64"), "tk_tls", [], state="report")
    assert ni.emulate_call(blob("dd_track_x86_64"), "tk_other", [], state="report").value32 == 1


def test_reported_changes_are_bounded(monkeypatch):
    data = blob("dd_state_x86_64")
    monkeypatch.setattr(ni, "MAX_CHANGES", 1)
    with pytest.raises(ni.EmulationError, match="more than 1 runs"):
        ni.emulate_call(data, "dd_poke", [], state="report")
    monkeypatch.setattr(ni, "MAX_CHANGES", 2)
    assert len(ni.emulate_call(data, "dd_poke", [], state="report").changes) == 2
    monkeypatch.setattr(ni, "MAX_CHANGE_BYTES", 8)
    with pytest.raises(ni.EmulationError, match="more than 8 bytes"):
        ni.emulate_call(data, "dd_poke", [], state="report")
    monkeypatch.setattr(ni, "MAX_CHANGE_BYTES", 9)
    assert len(ni.emulate_call(data, "dd_poke", [], state="report").changes) == 2


def test_emulate_symbol_is_unchanged_beside_it():
    data = blob("dd_flag_x86_64")
    assert ni.emulate_symbol(data, "dd_mix", [0x1337]) == m_mix(0x1337)
    with pytest.raises(ni.EmulationError):
        ni.emulate_symbol(data, "dd_mix", [ni.OutBuf(8)])        # the new kinds belong to emulate_call only


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
