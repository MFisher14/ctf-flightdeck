"""B-251: the schema-less FlatBuffers and Cap'n Proto readers (solvers/toolkits/lt_flat_capnp.py).

Independent truth: a FlatBuffers buffer assembled byte by byte from the format's layout rules, the
packed example the Cap'n Proto encoding document prints (08 00 00 00 03 00 02 00 19 00 00 00 aa 01
00 00 packs to 51 08 03 02 31 19 aa 01), and messages written as explicit 64-bit words. The larger
buffers come from the corpus writers (ctf/formats/corpus_longtail.py), which share no code with the
reader.
"""
import struct

import pytest

import lt_flat_capnp as fc
from _lt_common import FormatError, NotThisFormat
from ctf import flagfmt
from ctf.formats.corpus_longtail import capnp_frame, capnp_list_ptr, capnp_struct_ptr, capnp_text, flat_buffer
from lt_mutations import mutations, only_declared_errors

H = bytes.fromhex


# ------------------------------------------------------------------ FlatBuffers

def test_table_reads_a_buffer_assembled_by_hand():
    #  0: root offset 16      4: identifier TEST
    #  8: vtable: size 6, table size 8, field 0 at +4      14: padding
    # 16: table: vtable is 8 bytes back; field 0: the string is 4 bytes on
    # 24: string: length 3, "abc", NUL
    buf = H("10000000" "54455354" "0600" "0800" "0400" "0000" "08000000" "04000000" "03000000" "61626300")
    table, ident, prefixed = fc.root_table(buf)
    assert (table.pos, ident, prefixed) == (16, b"TEST", False)
    assert table.string(0) == b"abc" and table.has(0) and not table.has(1)
    assert table.string(1) is None and table.scalar(1, "<I", 99) == 99
    assert fc.walk_flatbuffer(buf)["root"] == {"field_0": "abc"}


FIELDS = [("u32", 7), ("str", b"hello"), None, ("table", [("str", b"inner"), ("i16", -5)]),
          ("strs", [b"a1", b"b2"]), ("bytes", b"\x01\x02\xff"), ("u8", 5), ("vec", "i32", [1, -2, 3]),
          ("tables", [[("u16", 1)], [("u16", 2), ("str", b"second")]]), ("f64", 2.5)]


def test_table_reads_every_field_kind_of_a_written_buffer():
    table, ident, _ = fc.root_table(flat_buffer(FIELDS, b"DEMO"))
    assert ident == b"DEMO"
    assert table.scalar(0, "<I") == 7 and table.scalar(6, "<B") == 5 and table.scalar(9, "<d") == 2.5
    assert table.string(1) == b"hello" and table.string(5) == b"\x01\x02\xff"
    assert not table.has(2) and table.table(2) is None and table.scalars(2, "<i") == [] and table.tables(2) == []
    inner = table.table(3)
    assert inner.string(0) == b"inner" and inner.scalar(1, "<h") == -5
    assert table.strings(4) == [b"a1", b"b2"]
    assert table.scalars(7, "<i") == [1, -2, 3]
    assert [(t.scalar(0, "<H"), t.string(1)) for t in table.tables(8)] == [(1, None), (2, b"second")]


def test_walk_without_a_schema_finds_text_tables_and_vectors():
    blobs = []
    got = fc.walk_flatbuffer(flat_buffer(FIELDS, b"DEMO"), blobs)
    assert (got["file_identifier"], got["heuristic"], got["size_prefixed"]) == ("DEMO", True, False)
    root = got["root"]
    assert root["field_0"] == 7 and root["field_1"] == "hello" and "field_2" not in root
    assert root["field_3"] == {"field_0": "inner", "field_1": 65531}
    assert root["field_4"] == ["a1", "b2"]
    assert root["field_5"]["bytes"] == "hex:0102ff" and root["field_5"]["length"] == 3 and blobs[0] == b"\x01\x02\xff"
    assert root["field_8"] == [{"field_0": 1}, {"field_0": 2, "field_1": "second"}]
    prefixed = fc.walk_flatbuffer(flat_buffer(FIELDS, size_prefixed=True))
    assert prefixed["size_prefixed"] and prefixed["file_identifier"] is None and prefixed["root"]["field_1"] == "hello"


def test_walk_keeps_a_scalar_whose_value_lands_on_unaligned_bytes():
    # field 0 holds 6. Read as an offset it lands 2 bytes into field 1, where the bytes 03 00 00 00 follow:
    # a "vector of three bytes" at an address no FlatBuffers object can have (they are 4-aligned).
    root = fc.walk_flatbuffer(flat_buffer([("u32", 6), ("u32", 0x00030000), ("u32", 0x41410000), ("str", b"tail")]))["root"]
    assert root == {"field_0": 6, "field_1": 0x00030000, "field_2": 0x41410000, "field_3": "tail"}


def test_flatbuffers_refusals():
    good = bytearray(flat_buffer([("str", b"x" * 40)], b"DEMO"))
    with pytest.raises(FormatError, match="no FlatBuffers root table"):
        fc.root_table(H("ffffff7f") + bytes(28))
    table, _, _ = fc.root_table(bytes(good))
    with pytest.raises(FormatError, match="points outside the buffer"):
        fc.root_table(bytes(good[:table.pos + 8]))[0].string(0)
    with pytest.raises(FormatError, match="string of 40 bytes at 28 runs past the buffer"):
        fc.root_table(bytes(good[:table.pos + 12]))[0].string(0)
    vt = table.pos - struct.unpack_from("<i", good, table.pos)[0]
    struct.pack_into("<H", good, vt + 4, 200)                # field 0 placed outside its table
    with pytest.raises(FormatError, match="field outside its table"):
        fc.root_table(bytes(good))
    long_string = bytearray(flat_buffer([("str", b"abc")]))
    struct.pack_into("<I", long_string, len(long_string) - 8, 5000)
    with pytest.raises(FormatError, match="string of 5000 bytes"):
        fc.root_table(bytes(long_string))[0].string(0)


def test_a_table_with_a_reach_budget_charges_every_read_through_an_offset():
    buf = flat_buffer(FIELDS, b"DEMO")
    reach = fc.Reach(1000)
    table, _, _ = fc.root_table(buf, reach)
    assert reach.left == 1000 - (4 + 2 * len(FIELDS))                # the root's vtable: 4 bytes and a slot per field

    def cost(read):
        before = reach.left
        got = read()
        return got, before - reach.left

    assert cost(lambda: table.scalar(0, "<I")) == (7, 0)                         # an inline scalar is no offset
    assert cost(lambda: table.string(1)) == (b"hello", 5)
    assert cost(lambda: table.scalars(7, "<i")) == ([1, -2, 3], 12)
    assert cost(lambda: table.strings(4)) == ([b"a1", b"b2"], 8 + 2 + 2)        # the offsets, then each string
    inner, spent = cost(lambda: table.table(3))
    assert spent == 4 + 2 * 2                                                    # the inner table's vtable
    assert cost(lambda: inner.string(0)) == (b"inner", 5)                        # a reached table charges the same budget
    rows, spent = cost(lambda: table.tables(8))
    assert spent == 8 + (4 + 2) + (4 + 4) and [t.reach for t in rows] == [reach, reach]
    assert cost(lambda: table.string(1))[1] == 5                                 # a second read is charged again
    # once the budget is spent, a read is a FormatError naming the amplification
    small = fc.Reach(4 + 2 * len(FIELDS) + 4)
    t, _, _ = fc.root_table(buf, small)
    with pytest.raises(FormatError, match="the offsets reach more than 28 bytes .*an amplification"):
        t.string(1)
    exact = fc.Reach(4 + 2 * len(FIELDS) + 5)                         # a budget spent to its last byte is not passed
    assert fc.root_table(buf, exact)[0].string(1) == b"hello" and exact.left == 0
    # without a budget nothing is charged (the schema-less walk keeps its own)
    assert fc.root_table(buf)[0].reach is None and fc.root_table(buf)[0].table(3).reach is None


def fan_out(outer, inner, target: bytes):
    """A buffer whose root field is a vector of `outer` offsets, every one naming the same vector of
    `inner` offsets, every one of which names `target` (appended last, 4-aligned): outer * inner edges
    to one object."""
    out = bytearray(flat_buffer([("vec", "u32", [0] * outer)]))
    table, _, _ = fc.root_table(bytes(out))
    start, _ = table.vector(0)
    second = len(out)
    out += struct.pack("<I", inner) + bytes(4 * inner)
    at = len(out)
    out += target + bytes(-len(target) % 4)
    for k in range(outer):
        struct.pack_into("<I", out, start + 4 * k, second - (start + 4 * k))
    for k in range(inner):
        struct.pack_into("<I", out, second + 4 + 4 * k, at - (second + 4 + 4 * k))
    return bytes(out)


def test_shared_targets_cannot_blow_up_the_walk():
    # 70,000 offsets that all name one vector of 3 offsets to one small table: seven nodes for each of them,
    # bounded by the node budget (a table takes no string or vector bytes). The table (its vtable is 8 bytes
    # after it, one field at +4 holding 7), then that vtable.
    table = struct.pack("<iI", -8, 7) + struct.pack("<HHH", 6, 8, 4) + bytes(2)
    assert fc.walk_flatbuffer(fan_out(3, 3, table))["root"] == {"field_0": [[{"field_0": 7}] * 3] * 3}
    assert len(fc.walk_flatbuffer(fan_out(20_000, 3, table))["root"]["field_0"]) == 20_000       # 140,001 nodes
    with pytest.raises(FormatError, match="more than 200000 nodes"):
        fc.walk_flatbuffer(fan_out(70_000, 3, table))


def test_shared_strings_and_byte_vectors_are_charged_for_every_reference():
    # every offset names one string: each reference would put the text in the tree again
    text = struct.pack("<I", 4000) + b"s" * 4000 + b"\x00"
    with pytest.raises(FormatError, match="reach more string and vector bytes than the buffer could hold"):
        fc.walk_flatbuffer(fan_out(8, 8, text))
    # every offset names one byte vector: 400 references to 17 KiB (the scan used to get a copy for each)
    vector = struct.pack("<I", 17001) + (bytes(range(1, 256)) * 67)[:17001]
    blobs = []
    with pytest.raises(FormatError, match="reach more string and vector bytes than the buffer could hold"):
        fc.walk_flatbuffer(fan_out(20, 20, vector), blobs)
    assert sum(len(b) for b in blobs) == 17001                  # it went to the flag scan once, not once per offset
    # a few references to one vector are a normal buffer: read, and scanned once
    twice = bytearray(flat_buffer([("bytes", b"\x01\x02\xff\xfe" * 3), ("bytes", b"\x09")]))
    table, _, _ = fc.root_table(bytes(twice))
    first = table.vector(0)[0] - 4
    slot = table.pos + table.slots[1]
    struct.pack_into("<I", twice, slot, first - slot)             # field 1 now names field 0's vector
    blobs = []
    root = fc.walk_flatbuffer(bytes(twice), blobs)["root"]
    assert root["field_0"]["length"] == 12 and root["field_1"]["length"] == 12 and blobs == [b"\x01\x02\xff\xfe" * 3]
    assert fc.BYTES_FACTOR == 4


# ------------------------------------------------------------------ Cap'n Proto

def pack(data: bytes) -> bytes:
    """The packed encoding, written simply: no literal runs, zero runs counted."""
    out, words = bytearray(), [data[i:i + 8] for i in range(0, len(data), 8)]
    i = 0
    while i < len(words):
        w = words[i]
        tag = sum(1 << k for k in range(8) if w[k])
        out.append(tag)
        out += bytes(b for b in w if b)
        i += 1
        if tag == 0:
            run = 0
            while i < len(words) and run < 255 and words[i] == bytes(8):
                run, i = run + 1, i + 1
            out.append(run)
        elif tag == 0xFF:
            out.append(0)
    return bytes(out)


def message():
    """A root struct (one data word, two pointers): a Text, and a composite list of two structs."""
    one, two = capnp_text(b"one"), capnp_text(b"two")
    return [capnp_struct_ptr(0, 1, 2),          # 0  root pointer -> word 1
            0x2A,                               # 1  the root's data word
            capnp_list_ptr(1, 2, 12),           # 2  -> word 4: twelve bytes
            capnp_list_ptr(2, 7, 4),            # 3  -> word 6: a composite list of four words
            *capnp_text(b"hello capnp"),        # 4, 5
            capnp_struct_ptr(2, 1, 1),          # 6  the tag: two elements of one data word and one pointer
            1, capnp_list_ptr(2, 2, 4),         # 7, 8   element 0 -> word 11
            2, capnp_list_ptr(1, 2, 4),         # 9, 10  element 1 -> word 12
            *one, *two]                         # 11, 12


TREE = {"data_hex": "2a00000000000000", "pointers": [
    "hello capnp", [{"data_hex": "0100000000000000", "pointers": ["one"]},
                    {"data_hex": "0200000000000000", "pointers": ["two"]}]]}


def test_unpack_matches_the_encoding_documents_example():
    assert fc.unpack(H("5108030231" "19aa01")) == H("0800000003000200" "19000000aa010000")
    assert fc.unpack(H("0002")) == bytes(24)                       # a zero word and two more
    assert fc.unpack(H("ff0102030405060708" "01" "1111111111111111")) == H("0102030405060708" "1111111111111111")
    with pytest.raises(FormatError, match="ends inside a word"):
        fc.unpack(H("5108"))
    with pytest.raises(FormatError, match="ends inside a literal run"):
        fc.unpack(H("ff0102030405060708" "02" "1111111111111111"))


def test_message_tree_plain_and_packed():
    plain = capnp_frame([message()])
    got = fc.read_capnp(plain)
    assert got == {"format": "capnp", "packed": False, "messages": [{"segments": 1, "words": 13, "root": TREE}]}
    packed = fc.read_capnp(pack(plain))
    assert packed["packed"] is True and packed["messages"][0]["root"] == TREE
    two = fc.read_capnp(plain + plain)
    assert [m["root"] for m in two["messages"]] == [TREE, TREE]


def test_far_and_double_far_pointers_cross_segments():
    far = capnp_frame([[2 | 0 << 3 | 1 << 32], [capnp_struct_ptr(0, 1, 0), 0x77]])
    assert fc.read_capnp(far)["messages"][0]["root"] == {"data_hex": "7700000000000000", "pointers": []}
    double = capnp_frame([[2 | 4 | 0 << 3 | 1 << 32],              # double-far -> segment 1, word 0
                          [2 | 1 << 3 | 2 << 32, capnp_struct_ptr(0, 1, 0)],   # far -> segment 2 word 1; the tag
                          [0, 0x99]])
    assert fc.read_capnp(double)["messages"][0]["root"] == {"data_hex": "9900000000000000", "pointers": []}


def test_list_element_sizes():
    words = [capnp_struct_ptr(0, 0, 5),
             capnp_list_ptr(4, 4, 3), capnp_list_ptr(5, 1, 10), capnp_list_ptr(5, 0, 7), capnp_list_ptr(4, 2, 3), 3 | 5 << 32,
             1 | 2 << 32, 3,          # three 32-bit values
             0b1000000101,            # ten bits
             0xFF0201]                # three bytes with no NUL: data, not text
    blobs = []
    root = fc.read_capnp(capnp_frame([words]), blobs)["messages"][0]["root"]
    assert root["pointers"] == [[1, 2, 3], {"bits": [1, 0, 1, 0, 0, 0, 0, 0, 0, 1]}, {"void": 7},
                                {"data": "hex:0102ff", "length": 3}, {"capability": 5}]
    assert blobs == [b"\x01\x02\xff"]


def test_capnp_refusals_and_the_amplification_guard():
    zero_sized = capnp_frame([[capnp_struct_ptr(0, 0, 1), capnp_list_ptr(0, 7, 0), capnp_struct_ptr(1 << 28, 0, 0)]])
    with pytest.raises(FormatError, match="amplification"):
        fc.read_capnp(zero_sized)
    # sixty pointers that all name one struct of a hundred words: few nodes, far more words than the message holds
    shared = [capnp_struct_ptr(0, 0, 1), capnp_list_ptr(0, 6, 60)] + [capnp_struct_ptr(59 - k, 100, 0) for k in range(60)]
    with pytest.raises(FormatError, match="amplification"):
        fc.read_capnp(capnp_frame([shared + list(range(100))]))
    once = [capnp_struct_ptr(0, 0, 1), capnp_list_ptr(0, 6, 2), capnp_struct_ptr(1, 1, 0), capnp_struct_ptr(1, 1, 0), 5, 6]
    assert fc.read_capnp(capnp_frame([once]))["messages"][0]["root"]["pointers"][0] == [
        {"data_hex": "0500000000000000", "pointers": []}, {"data_hex": "0600000000000000", "pointers": []}]
    loop = capnp_frame([[capnp_struct_ptr(-1, 0, 1)]])           # a struct whose only pointer is itself
    with pytest.raises(FormatError, match="nest deeper|amplification"):
        fc.read_capnp(loop)
    with pytest.raises(FormatError, match="runs past it"):
        fc.read_capnp(capnp_frame([[capnp_struct_ptr(0, 9, 0), 1]]))
    with pytest.raises(NotThisFormat):
        fc.read_capnp(capnp_frame([message()]) + b"\x01\x02\x03")
    with pytest.raises(NotThisFormat, match="not a struct pointer"):
        fc.read_capnp(capnp_frame([[capnp_list_ptr(0, 2, 8), 0]]))


@pytest.mark.parametrize("head", [b"\x89PNG\r\n\x1a\n" + bytes(64), b"\x7fELF" + bytes(64), b"PK\x03\x04" + bytes(64),
                                  b"plain text file with words in it\n" * 4, bytes(256), b"TFL3", b"",
                                  H("1c000000" "54464c33") + bytes(64)])
def test_detect_passes_over_other_files(head):
    assert not fc.detect(head, "x.bin")


def test_detect_and_solve(tmp_path):
    flat = flat_buffer(FIELDS, b"DEMO")
    plain = capnp_frame([message()])
    assert fc.detect(flat[:8192]) and fc.detect(plain[:8192]) and fc.detect(pack(plain)[:8192])
    assert fc.solve(tmp_path).status == "none"

    flag = flagfmt.cribs()[0] + "flatbuffer_string}"
    (tmp_path / "state.bin").write_bytes(flat_buffer([("u32", 1), ("table", [("str", flag.encode())])], b"SAVE"))
    r = fc.solve(tmp_path)
    assert (r.status, r.flags) == ("solved", (flag,))

    other = flagfmt.cribs()[0] + "capnp_data_list}"
    raw = b"\xfe\xff" + other.encode() + b"\x01"
    words = [capnp_struct_ptr(0, 0, 1), capnp_list_ptr(0, 2, len(raw)),
             *struct.unpack(f"<{-(-len(raw) // 8)}Q", raw + bytes(-len(raw) % 8))]
    (tmp_path / "msg.capnp").write_bytes(pack(capnp_frame([words])))
    r = fc.solve(tmp_path)
    assert r.status == "candidate" and set(r.flags) == {flag, other}

    # a file whose head passes the cheap test and whose whole is neither format is passed over, with no note
    (tmp_path / "state.bin").unlink()
    (tmp_path / "msg.capnp").write_bytes(capnp_frame([message()]) + b"trailing")
    r = fc.solve(tmp_path)
    assert (r.status, r.notes) == ("none", "no FlatBuffers/Cap'n Proto file in the handout")


# ------------------------------------------------------------------ round 1

def test_the_packed_encoding_unpacks_to_a_stated_limit(monkeypatch):
    run = H("00ff")                                    # a zero word and 255 more: 2048 bytes from two
    assert fc.unpack(run) == bytes(2048) and fc.MAX_UNPACKED_BYTES == 64 << 20
    monkeypatch.setattr(fc, "MAX_UNPACKED_BYTES", 2048)
    assert fc.unpack(run) == bytes(2048)               # exactly the limit
    monkeypatch.setattr(fc, "MAX_UNPACKED_BYTES", 2047)
    with pytest.raises(FormatError, match="the packed data unpacks to more than 2047 bytes"):
        fc.unpack(run)
    with pytest.raises(NotThisFormat, match="packed: the packed data unpacks to more than 2047 bytes"):
        fc.read_capnp(run * 4)
    monkeypatch.undo()
    # the default: 40,000 zero runs (80 KiB) would unpack to 78 MiB, and stop at 64 MiB
    with pytest.raises(FormatError, match="unpacks to more than 67108864 bytes"):
        fc.unpack(run * 40_000)


def test_mutated_buffers_and_messages_raise_only_the_declared_errors():
    flat = flat_buffer(FIELDS, b"DEMO")
    plain = capnp_frame([message()])
    for seed, data in enumerate((flat, plain, pack(plain))):
        read, refused = only_declared_errors(fc.inspect, mutations(data, 2500, seed=251 + seed))
        assert read + refused == 2500 and refused > 100 and read > 100
