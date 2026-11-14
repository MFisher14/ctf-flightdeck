"""B-117: the static SWF reader (solvers/toolkits/swf_parse.py).

Every movie is assembled here from bytes (tests/b117_fixtures.py): no Flash file is read and
nothing is executed. The end-to-end movie follows the 2026 PINK shape (a zlib movie, class-init
arrays, a QR bitmap with its finders left out) without reading it: every class, function and
variable name and every array value below is invented here."""
from __future__ import annotations

import io
import json
import lzma
import random
import struct
import time
import zlib

import pytest

import b117_fixtures as fx
import swf_parse as swf
from ctf import flagfmt

PROFILE = fx.profile()
# Every engine call below gets an explicit budget: the production defaults are wall-clock seconds,
# and this suite runs on a machine loaded far past its cores.
BUDGET = 3600.0
FF = flagfmt.for_profile(PROFILE)
FLAG = "CSCTF{swf_static_read}"
END = fx.swf_tag(0, b"")


def movie(*tags, maker=fx.swf_fws, **kw):
    return maker(fx.swf_body(b"".join(tags) + END, **kw))


def function(name, params, body, registers=None):
    """DefineFunction (or DefineFunction2 when `registers` is given) followed by its body."""
    head = name.encode() + b"\x00" + struct.pack("<H", len(params))
    if registers is None:
        head += b"".join(p.encode() + b"\x00" for p in params)
        return fx.avm1(0x9B, head + struct.pack("<H", len(body))) + body
    head += bytes([registers]) + struct.pack("<H", 0x2A)
    head += b"".join(bytes([i + 1]) + p.encode() + b"\x00" for i, p in enumerate(params))
    return fx.avm1(0x8E, head + struct.pack("<H", len(body))) + body


def member_array(owner, name, values):
    """owner.name = [values] the way a compiler writes it: the elements pushed last-first."""
    return (fx.avm1_push(owner) + fx.avm1(0x1C) + fx.avm1_push(name)
            + fx.avm1_push(*reversed(values), len(values)) + fx.avm1(0x42) + fx.avm1(0x4F))


# ---- header ----------------------------------------------------------------------------------------

def test_three_containers_give_one_body():
    body = fx.swf_body(fx.swf_tag(12, fx.avm1_push(FLAG) + fx.avm1(0x26) + b"\x00") + END)
    for maker, sig, compression, version in ((fx.swf_fws, "FWS", "none", 8), (fx.swf_cws, "CWS", "zlib", 8),
                                             (fx.swf_zws, "ZWS", "lzma", 13)):
        header, got = swf.decompress(maker(body))
        assert got == body
        assert (header["signature"], header["compression"], header["version"]) == (sig, compression, version)
        assert header["file_length"] == len(body) + 8 and header["body_length"] == len(body)
        assert header["trailing"] == 0 and "length_mismatch" not in header
    assert FLAG.encode() not in fx.swf_cws(body) and FLAG.encode() not in fx.swf_zws(body)


@pytest.mark.parametrize("maker", [fx.swf_fws, fx.swf_cws, fx.swf_zws])
def test_bytes_after_the_movie_are_reported(maker):
    body = fx.swf_body(END)
    header, got = swf.decompress(maker(body) + b"PK appended CSCTF{after_the_end}")
    assert got == body and header["trailing"] == 32
    assert header["trailing_bytes"] == b"PK appended CSCTF{after_the_end}"


def test_header_refusals(monkeypatch):
    body = fx.swf_body(END)
    with pytest.raises(swf.SWFError, match="signature"):
        swf.decompress(b"XWS\x08" + struct.pack("<I", 20) + body)
    with pytest.raises(swf.SWFError, match="too short"):
        swf.decompress(b"FWS\x08\x00\x00")
    with pytest.raises(swf.SWFError, match="must be bytes"):
        swf.decompress("FWS")
    with pytest.raises(swf.SWFError, match="does not inflate"):
        swf.decompress(b"CWS\x08" + struct.pack("<I", 100) + b"not a zlib stream at all")
    with pytest.raises(swf.SWFError, match="does not decode"):
        swf.decompress(b"ZWS\x0d" + struct.pack("<I", 100) + b"\x00" * 4 + b"\xff" * 30)
    with pytest.raises(swf.SWFError, match="too short for its LZMA header"):
        swf.decompress(b"ZWS\x0d" + struct.pack("<I", 100) + b"\x00" * 8)
    with pytest.raises(swf.SWFError, match="declared length"):
        swf.decompress(b"FWS\x08" + struct.pack("<I", 7) + body)
    # a header that understates the length cannot hide a bomb: the inflate itself is capped
    monkeypatch.setattr(swf, "MAX_BODY", 256)
    with pytest.raises(swf.SWFError, match="declared length"):
        swf.decompress(fx.swf_cws(b"A" * 4096))
    lying = b"CWS\x08" + struct.pack("<I", 108) + zlib.compress(b"A" * 4096)
    with pytest.raises(swf.SWFError, match="inflates past 256"):
        swf.decompress(lying)
    monkeypatch.setattr(swf, "MAX_BODY", 4096)
    header, got = swf.decompress(lying)
    assert len(got) == 4096 and header["length_mismatch"] == "the header declares 100 body bytes, the file holds 4096"
    short = swf.decompress(b"FWS\x08" + struct.pack("<I", 8 + len(body) + 5) + body)[0]
    assert short["length_mismatch"].startswith(f"the header declares {len(body) + 5} body bytes")


def test_read_rect_is_signed_and_byte_aligned():
    rect, end = swf.read_rect(fx.swf_rect(11000, 8000) + b"tail")
    assert (rect["x_min"], rect["x_max"], rect["y_min"], rect["y_max"]) == (0, 11000, 0, 8000)
    assert (rect["width_px"], rect["height_px"]) == (550.0, 400.0) and end == 9
    # nbits 5, fields -3, 4, -16, 15: 5 + 20 bits -> four bytes
    bits = "00101" + "11101" + "00100" + "10000" + "01111"
    packed = int(bits.ljust(32, "0"), 2).to_bytes(4, "big")
    rect, end = swf.read_rect(b"\xaa" + packed, 1)
    assert (rect["x_min"], rect["x_max"], rect["y_min"], rect["y_max"]) == (-3, 4, -16, 15) and end == 5
    assert swf.read_rect(b"\x00rest")[1] == 1                     # zero-width fields: one byte
    with pytest.raises(swf.SWFError):
        swf.read_rect(fx.swf_rect()[:5])
    with pytest.raises(swf.SWFError):
        swf.read_rect(b"")


# ---- tags ------------------------------------------------------------------------------------------

def test_tag_walk_names_offsets_long_headers_and_sprites():
    inner = fx.swf_tag(12, fx.avm1_push("in the sprite") + b"\x00") + fx.swf_tag(1, b"") + END
    body = fx.swf_body(fx.swf_tag(9, b"\x10\x20\x30") + fx.swf_tag(87, b"\x01\x00" + bytes(4) + b"x" * 100)
                       + fx.swf_tag(1, b"", long=True) + fx.swf_tag(39, struct.pack("<HH", 5, 1) + inner)
                       + fx.swf_tag(777, b"??") + END + fx.swf_tag(9, b"after the end"))
    tags = list(swf.iter_tags(body))
    assert [(code, name, depth) for code, name, _b, _o, depth in tags] == [
        (9, "SetBackgroundColor", 0), (87, "DefineBinaryData", 0), (1, "ShowFrame", 0), (39, "DefineSprite", 0),
        (12, "DoAction", 1), (1, "ShowFrame", 1), (0, "End", 1), (777, "tag777", 0), (0, "End", 0)]
    for _code, _name, data, offset, _depth in tags:
        assert body[offset:offset + len(data)] == data          # offsets are body offsets, nested ones too
    assert len(tags[1][2]) == 106


def test_broken_tag_raises_after_the_good_ones_and_walk_keeps_them(monkeypatch):
    good = fx.swf_tag(9, b"\x00\x00\x00")
    overrun = struct.pack("<H", (12 << 6) | 0x10) + b"\x00\x00"           # claims 16 bytes, has 2
    body = fx.swf_body(good + overrun)
    seen = []
    with pytest.raises(swf.SWFError, match="tag 12 .* length 16 runs past"):
        for tag in swf.iter_tags(body):
            seen.append(tag[1])
    assert seen == ["SetBackgroundColor"]
    tags, error = swf.walk(body)
    assert [t[1] for t in tags] == ["SetBackgroundColor"] and "length 16 runs past" in error
    long_cut = fx.swf_rect() + struct.pack("<HH", 24 * 256, 1) + struct.pack("<H", (12 << 6) | 0x3F) + b"\x01"
    assert "long header" in swf.walk(long_cut)[1]
    assert swf.walk(fx.swf_body(good + END)) == (list(swf.iter_tags(fx.swf_body(good + END))), None)
    monkeypatch.setattr(swf, "MAX_TAGS", 3)
    many = fx.swf_body(good * 2 + fx.swf_tag(39, struct.pack("<HH", 1, 1) + good * 3 + END) + END)
    tags, error = swf.walk(many)
    assert len(tags) == 3 and "more than 3 tags" in error            # nested tags count too


# ---- AVM1 disassembly ------------------------------------------------------------------------------

def test_disassemble_pool_pushes_and_urls():
    code = (fx.avm1_pool("alpha", "beta", FLAG)
            + fx.avm1_push(("const", 2), ("const", 0), ("const", 7), "/r", 42, True, 2.5, None, ("reg", 3), -7)
            + fx.avm1(0x83, b"/secret/next\x00_self\x00") + fx.avm1(0x8C, b"intro\x00") + fx.avm1(0x8B, b"clip\x00")
            + b"\x00" + fx.avm1_push("after the end"))
    dis = swf.disassemble(code)
    assert [a["name"] for a in dis["actions"]] == ["ConstantPool", "Push", "GetURL", "GoToLabel", "SetTarget", "End"]
    assert dis["constant_pool"] == ["alpha", "beta", FLAG]
    assert dis["actions"][1]["args"]["values"] == [FLAG, "alpha", "<constant 7>", "/r", 42, True, 2.5, None,
                                                   {"register": 3}, -7]
    assert dis["actions"][2]["args"] == {"url": "/secret/next", "target": "_self"}
    assert dis["urls"] == ["/secret/next"] and dis["truncated"] is None
    assert dis["strings"] == ["alpha", "beta", FLAG, FLAG, "alpha", "<constant 7>", "/r", "/secret/next", "_self",
                              "intro", "clip"]
    assert "after the end" not in dis["strings"]                    # End ends the block
    wide = swf.disassemble(fx.avm1_pool(*[f"s{i}" for i in range(300)]) + fx.avm1_push(("const", 299)))
    assert wide["actions"][1]["args"]["values"] == ["s299"]          # a 16-bit pool index


def test_push_value_framing():
    def values(payload):
        return swf.disassemble(fx.avm1(0x96, payload))["actions"][0]["args"]["values"]

    assert values(b"\x01" + struct.pack("<f", 1.5)) == [1.5]
    assert values(b"\x03\x05\x00") == ["undefined", False]
    assert values(b"\x07\xff\xff\xff\xff") == [-1]
    assert values(b"\x00abc") == ["abc"]                              # an unterminated string runs to the end
    assert values(b"\x07\x01\x00") == ["<truncated push>"]
    assert values(b"\x06\x00\x00") == ["<truncated push>"]
    assert values(b"\x04") == ["<truncated push>"]
    assert values(b"\x09\x01") == ["<truncated push>"]
    assert values(b"\x07\x05\x00\x00\x00\x0b\x01\x02") == [5, "<push type 11>"]


def test_functions_bodies_branches_with_and_try():
    body = fx.avm1_push("x", 1) + fx.avm1(0x1D) + fx.avm1(0x3E)
    with_body = fx.avm1_push("inside with") + fx.avm1(0x17)
    try_body, catch_body = fx.avm1(0x06), fx.avm1(0x07) + fx.avm1(0x04)
    code = (function("mix", ["step", "salt"], body)
            + function("", ["a"], fx.avm1(0x3E), registers=4)
            + fx.avm1(0x9D, struct.pack("<h", 5)) + fx.avm1(0x99, struct.pack("<h", -3))
            + fx.avm1(0x94, struct.pack("<H", len(with_body))) + with_body
            + fx.avm1(0x8F, b"\x01" + struct.pack("<HHH", len(try_body), len(catch_body), 0) + b"err\x00")
            + try_body + catch_body
            + fx.avm1(0x8F, b"\x04" + struct.pack("<HHH", 0, 0, 0) + b"\x02")
            + fx.avm1(0x9A, b"\x82") + fx.avm1(0x9F, b"\x03\x10\x00") + fx.avm1(0x8A, b"\x05\x00\x02")
            + fx.avm1(0x8D, b"\x01") + fx.avm1(0x81, b"\x09\x00") + fx.avm1(0x87, b"\x02") + fx.avm1(0x9E)
            + bytes([0x7E]) + fx.avm1(0xA5, b"\x01\x02"))
    dis = swf.disassemble(code)
    rows = [(a["name"], a["depth"]) for a in dis["actions"]]
    assert rows == [("DefineFunction", 0), ("Push", 1), ("SetVariable", 1), ("Return", 1),
                    ("DefineFunction2", 0), ("Return", 1), ("If", 0), ("Jump", 0),
                    ("With", 0), ("Push", 1), ("Pop", 1),
                    ("Try", 0), ("Play", 1), ("Stop", 1), ("NextFrame", 1), ("Try", 0),
                    ("GetURL2", 0), ("GotoFrame2", 0), ("WaitForFrame", 0), ("WaitForFrame2", 0), ("GotoFrame", 0),
                    ("StoreRegister", 0), ("Call", 0), ("0x7E", 0), ("0xA5", 0)]
    by = {a["name"]: a for a in dis["actions"]}
    assert dis["actions"][0]["args"] == {"name": "mix", "params": ["step", "salt"], "size": len(body)}
    assert by["DefineFunction2"]["args"] == {"name": "", "params": [{"name": "a", "register": 1}], "registers": 4,
                                             "flags": 0x2A, "size": 1}
    branch = by["If"]
    assert branch["args"] == {"branch": 5} and branch["target"] == branch["offset"] + 5 + 5
    assert by["Jump"]["target"] == by["Jump"]["offset"] + 5 - 3
    assert by["With"]["args"] == {"size": len(with_body)}
    assert dis["actions"][11]["args"] == {"try": 1, "catch": 2, "finally": 0, "catch_name": "err"}
    assert dis["actions"][15]["args"] == {"try": 0, "catch": 0, "finally": 0, "catch_register": 2}
    assert by["GetURL2"]["args"] == {"method": "POST", "load_target": True, "load_variables": False}
    assert by["GotoFrame2"]["args"] == {"play": True, "scene_bias": 16}
    assert by["WaitForFrame"]["args"] == {"frame": 5, "skip": 2} and by["WaitForFrame2"]["args"] == {"skip": 1}
    assert by["GotoFrame"]["args"] == {"frame": 9} and by["StoreRegister"]["args"] == {"register": 2}
    assert by["Call"]["args"] == {} and by["0xA5"]["args"] == {"raw": "0102"}
    assert {"mix", "step", "salt", "a", "err", "x", "inside with"} <= set(dis["strings"])
    # a function body's own constants are found, and End inside a body does not end the block
    assert dis["actions"][2]["offset"] == 32
    assert dis["constants"] == [{"offset": 32, "name": "x", "value": 1, "complete": True}]
    inside = swf.disassemble(function("g", [], b"\x00" + fx.avm1(0x06)) + fx.avm1(0x07))
    assert [a["name"] for a in inside["actions"]] == ["DefineFunction", "End", "Play", "Stop"]


def test_truncated_and_short_records():
    whole = fx.avm1_push("kept")
    cut = swf.disassemble(whole + b"\x96\x10\x00\x00ab")
    assert [a["name"] for a in cut["actions"]] == ["Push"] and cut["truncated"] == len(whole)
    assert swf.disassemble(whole + b"\x96\x10")["truncated"] == len(whole)
    assert swf.disassemble(whole)["truncated"] is None
    # a long action whose payload is shorter than its fields is kept as raw bytes, not guessed at
    for code, payload in ((0x81, b"\x01"), (0x9B, b"f\x00\x02\x00a\x00"), (0x8E, b"f\x00\x01"), (0x8F, b"\x00\x01"),
                          (0x88, b"\x01"), (0x87, b""), (0x9D, b"\x01")):
        action = swf.disassemble(fx.avm1(code, payload))["actions"][0]
        assert action["args"] == ({"raw": payload.hex()} if payload else {}), hex(code)
        assert "target" not in action


# ---- the constant tracker --------------------------------------------------------------------------

def test_array_literals_come_out_whole_and_named():
    seeds = [412, 96, 733, 58, 261]
    grids = [[5, 6, 7], [8, 9, 10]]
    nested = (fx.avm1_push("Kiln") + fx.avm1(0x1C) + fx.avm1_push("rows")
              + fx.avm1_push(10, 9, 8, 3) + fx.avm1(0x42) + fx.avm1_push(7, 6, 5, 3) + fx.avm1(0x42)
              + fx.avm1_push(2) + fx.avm1(0x42) + fx.avm1(0x4F))
    code = (member_array("Kiln", "steps", seeds) + nested
            + fx.avm1_push("plain") + fx.avm1_push("b", "a", 2) + fx.avm1(0x42) + fx.avm1(0x1D)
            + fx.avm1_push("local", 88213) + fx.avm1(0x3C)
            + fx.avm1_push(("reg", 1), "k", 3.5) + fx.avm1(0x4F)
            + fx.avm1_push(2, 1, 2) + fx.avm1(0x42) + fx.avm1(0x87, b"\x05") + fx.avm1(0x17)
            + fx.avm1_push(9, 1) + fx.avm1(0x42) + fx.avm1(0x26))
    consts = swf.disassemble(code)["constants"]
    named = {row["name"]: row["value"] for row in consts}
    assert named["Kiln.steps"] == seeds
    assert named["Kiln.rows"] == grids
    assert named["plain"] == ["a", "b"] and named["local"] == 88213 and named["register1.k"] == 3.5
    assert named["register5"] == [1, 2]
    assert named[None] == [9]                                        # built, then consumed by Trace
    assert all(row["complete"] for row in consts)
    # the inner arrays of Kiln.rows are rows of their own, before the array that holds them
    assert [row["value"] for row in consts if row["name"] is None] == [[8, 9, 10], [5, 6, 7], [9]]
    offsets = [row["offset"] for row in consts]
    assert offsets == sorted(offsets)


def test_objects_urls_calls_and_what_the_tracker_does_not_know():
    code = (fx.avm1_push("cfg") + fx.avm1_push("route", "/vault", "port", 8080, 2) + fx.avm1(0x43) + fx.avm1(0x1D)
            + fx.avm1_push("/next/stage", "_blank") + fx.avm1(0x9A, b"\x40")
            + fx.avm1_push("mixed") + fx.avm1_push("x") + fx.avm1(0x1C) + fx.avm1_push(4, 2) + fx.avm1(0x42)
            + fx.avm1(0x1D)
            + fx.avm1_push("r") + fx.avm1_push(1, 2, 2, "Math") + fx.avm1(0x1C) + fx.avm1_push("max")
            + fx.avm1(0x52) + fx.avm1(0x1D)
            + fx.avm1_push("after_call", 5) + fx.avm1(0x1D)
            + fx.avm1_push(1, 2) + fx.avm1(0x0A) + fx.avm1_push(1) + fx.avm1(0x42)
            + fx.avm1_push("n", 3, 4, 2, "f") + fx.avm1(0x3D) + fx.avm1(0x17) + fx.avm1_push(8) + fx.avm1(0x1D)
            + fx.avm1_push(99) + fx.avm1(0x42))
    dis = swf.disassemble(code)
    named = {row["name"]: row for row in dis["constants"]}
    assert named["cfg"]["value"] == {"port": 8080, "route": "/vault"} and named["cfg"]["complete"] is True
    assert dis["urls"] == ["/next/stage"]
    assert named["mixed"]["value"] == [4, {"ref": "x"}] and named["mixed"]["complete"] is False
    assert "r" not in named                                          # a call's result is not a constant
    assert named["after_call"]["value"] == 5
    assert named["n"]["value"] == 8                                  # the call took its own arguments only
    # Add is not modelled: what it left is unknown, so the array after it is not invented, and a
    # count larger than the stack builds nothing
    assert [row["value"] for row in dis["constants"] if row["name"] is None] == []


def test_function_body_does_not_disturb_the_outer_stack():
    inner = fx.avm1_push("x", 1) + fx.avm1(0x1D) + fx.avm1_push(1, 2, 3)
    code = (fx.avm1_push("obj") + fx.avm1(0x1C) + fx.avm1_push("handler") + function("", [], inner) + fx.avm1(0x4F)
            + fx.avm1_push("k") + function("named", [], inner) + fx.avm1_push(7) + fx.avm1(0x1D))
    named = {row["name"]: row["value"] for row in swf.disassemble(code)["constants"]}
    assert named == {"x": 1, "k": 7}                  # obj.handler is a function: not a constant


def test_listing_shows_constants_depth_branches_and_the_cut():
    code = (member_array("Atlas", "tiles", list(range(100, 140)))
            + function("mix", ["step"], fx.avm1_push(("reg", 1), "s", "x") + fx.avm1(0x3E))
            + fx.avm1(0x9D, struct.pack("<h", 2)) + b"\x96\x09")
    text = swf.listing(swf.disassemble(code), clip=4)
    lines = text.splitlines()
    assert lines[0].endswith("Atlas.tiles = [100, 101, 102, 103, ... (40 values)]") and lines[0].startswith("; ")
    assert any(line.endswith('DefineFunction mix(step) 12 bytes') for line in lines)
    assert any(line.endswith('  Push register1, "s", "x"') for line in lines)      # indented: inside mix
    assert any(" If branch=2 -> " in line for line in lines)
    assert lines[-1].startswith("; the record at ") and "runs past the end" in lines[-1]
    full = swf.listing(swf.disassemble(member_array("A", "b", [1, 2, 3])))
    assert "A.b = [1, 2, 3]" in full and "runs past" not in full


def test_action_blocks_skip_the_sprite_id_and_split_button_conditions():
    init = struct.pack("<H", 7) + fx.avm1_push("class init") + b"\x00"
    first, second = fx.avm1_push("on release") + b"\x00", fx.avm1_push("on key") + b"\x00"
    records = b"\x01\x02\x00\x01\x00\x00\x00"                       # stand-in button records, then the end flag
    conds = struct.pack("<HH", 4 + len(first), 0x0008) + first + struct.pack("<HH", 0, 0x0200) + second
    button = struct.pack("<HBH", 44, 0, 2 + len(records)) + records + conds
    no_actions = struct.pack("<HBH", 45, 0, 0) + records
    body = fx.swf_body(fx.swf_tag(59, init) + fx.swf_tag(34, button) + fx.swf_tag(34, no_actions)
                       + fx.swf_tag(12, fx.avm1_push("frame") + b"\x00") + END)
    tags, _error = swf.walk(body)
    blocks = swf.action_blocks(tags)
    assert [label for label, _o, _c in blocks] == ["DoInitAction sprite 7", "DefineButton2 44 condition 0x0008",
                                                   "DefineButton2 44 condition 0x0200", "DoAction"]
    assert [swf.disassemble(code)["strings"] for _l, _o, code in blocks] == [["class init"], ["on release"],
                                                                             ["on key"], ["frame"]]
    for _label, offset, code in blocks:
        assert body[offset:offset + len(code)] == code


def test_tag_strings():
    body = fx.swf_body(fx.swf_tag(43, b"level_two\x00\x01") + fx.swf_tag(77, b"<rdf>meta</rdf>\x00")
                       + fx.swf_tag(56, struct.pack("<H", 2) + b"\x41\x00hero\x00" + b"\x02\x00door\x00")
                       + fx.swf_tag(76, struct.pack("<H", 1) + b"\x00\x00Main\x00")
                       + fx.swf_tag(87, b"\x03\x00" + bytes(4) + b"\x01\x02key=/admin/panel\x00ab\x00")
                       + fx.swf_tag(56, b"\x05") + END)
    assert swf.tag_strings(swf.walk(body)[0]) == ["level_two", "<rdf>meta</rdf>", "hero", "door", "Main",
                                                  "key=/admin/panel"]


# ---- bitmaps ---------------------------------------------------------------------------------------

PATTERN = [[True, False, True, True, False], [False, False, True, False, True], [True, True, False, False, False]]


def _pixels(image_bytes):
    from PIL import Image
    image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    return image.size, [[image.getpixel((x, y)) == (0, 0, 0) for x in range(image.width)] for y in range(image.height)]


@pytest.mark.needs_tool("py:PIL")
@pytest.mark.parametrize("code,fmt", [(20, 5), (36, 5), (20, 3), (36, 3)])
def test_lossless_bitmaps_are_rebuilt(code, fmt):
    tag = fx.swf_tag(code, fx.lossless_tag_body(9, PATTERN, alpha=code == 36, fmt=fmt))
    images, notes = swf.extract_images(movie(tag))
    assert notes == [] and len(images) == 1
    assert (images[0]["char_id"], images[0]["kind"], images[0]["width"], images[0]["height"]) == (9, "png", 5, 3)
    assert images[0]["tag"] == ("DefineBitsLossless" if code == 20 else "DefineBitsLossless2")
    assert _pixels(images[0]["image"]) == ((5, 3), PATTERN)          # 5 wide: the palette rows are padded


@pytest.mark.needs_tool("py:PIL")
def test_lossless_colours_pix15_and_refusals(monkeypatch):
    from PIL import Image
    raw = bytes((0, 255, 0, 0)) + bytes((0, 0, 128, 255))            # reserved, R, G, B
    images, _ = swf.extract_images(movie(fx.swf_tag(20, struct.pack("<HBHH", 1, 5, 2, 1) + zlib.compress(raw))))
    image = Image.open(io.BytesIO(images[0]["image"]))
    assert [image.getpixel((x, 0)) for x in range(2)] == [(255, 0, 0), (0, 128, 255)]
    argb = bytes((128, 10, 20, 30)) + bytes((255, 1, 2, 3))
    images, _ = swf.extract_images(movie(fx.swf_tag(36, struct.pack("<HBHH", 1, 5, 2, 1) + zlib.compress(argb))))
    image = Image.open(io.BytesIO(images[0]["image"]))
    assert image.mode == "RGBA" and image.getpixel((0, 0)) == (10, 20, 30, 128)
    # PIX15: three 16-bit pixels (red, green, blue at full scale), the row padded to four bytes
    pix15 = struct.pack(">HHH", 31 << 10, 31 << 5, 31) + b"\x00\x00"
    images, _ = swf.extract_images(movie(fx.swf_tag(20, struct.pack("<HBHH", 2, 4, 3, 1) + zlib.compress(pix15))))
    image = Image.open(io.BytesIO(images[0]["image"]))
    assert [image.getpixel((x, 0)) for x in range(3)] == [(255, 0, 0), (0, 255, 0), (0, 0, 255)]

    bad = [fx.swf_tag(20, struct.pack("<HBHH", 3, 9, 2, 2) + zlib.compress(b"x" * 16)),
           fx.swf_tag(20, struct.pack("<HBHH", 4, 5, 2, 2) + b"not zlib"),
           fx.swf_tag(20, struct.pack("<HBHH", 5, 5, 4, 4) + zlib.compress(b"x" * 10)),
           fx.swf_tag(20, struct.pack("<HBHH", 6, 5, 0, 4) + zlib.compress(b"")),
           fx.swf_tag(20, b"\x07\x00\x05"), fx.swf_tag(21, b"\x08\x00")]
    images, notes = swf.extract_images(movie(*bad))
    assert images == []
    assert [note.split(":")[0] for note in notes] == [f"DefineBitsLossless {n}" for n in (3, 4, 5, 6, 7)] + ["DefineBitsJPEG2 8"]
    assert "format 9" in notes[0] and "does not inflate" in notes[1] and "10 bytes, 64 needed" in notes[2]
    assert "empty or over" in notes[3] and "shorter than its header" in notes[4] and "no image data" in notes[5]
    monkeypatch.setattr(swf, "MAX_IMAGE_PIXELS", 14)
    _images, notes = swf.extract_images(movie(fx.swf_tag(20, fx.lossless_tag_body(9, PATTERN))))
    assert "over the 14 pixel cap" in notes[0]


def _jpeg(size=(8, 8), colour=(200, 30, 30)):
    from PIL import Image
    out = io.BytesIO()
    Image.new("RGB", size, colour).save(out, format="JPEG")
    return out.getvalue()


def _split_jpeg(jpeg):
    """(tables, image): a JPEG cut into a tables-only stream and an image stream that refers to it."""
    pos, segments = 2, []
    while jpeg[pos:pos + 2] != b"\xff\xda":
        length = struct.unpack_from(">H", jpeg, pos + 2)[0]
        segments.append(jpeg[pos:pos + 2 + length])
        pos += 2 + length
    tables = b"".join(s for s in segments if s[1] in (0xDB, 0xE0))
    rest = b"".join(s for s in segments if s[1] not in (0xDB, 0xE0))
    return b"\xff\xd8" + tables + b"\xff\xd9", b"\xff\xd8" + rest + jpeg[pos:]


@pytest.mark.needs_tool("py:PIL")
def test_jpeg_tags_are_carved_whole():
    from PIL import Image
    jpeg = _jpeg()
    tables, image = _split_jpeg(jpeg)
    png = fx.matrix_png(PATTERN, scale=1, border=0)
    tags = [fx.swf_tag(21, struct.pack("<H", 1) + jpeg),
            fx.swf_tag(21, struct.pack("<H", 2) + b"\xff\xd9\xff\xd8" + jpeg),               # Flash's stray pair
            fx.swf_tag(21, struct.pack("<H", 3) + tables + image),                           # tables, pair, image
            fx.swf_tag(35, struct.pack("<HI", 4, len(jpeg)) + jpeg + zlib.compress(b"\xff" * 64)),
            fx.swf_tag(90, struct.pack("<HIH", 5, len(jpeg), 0) + jpeg + b"alpha"),
            fx.swf_tag(8, tables), fx.swf_tag(6, struct.pack("<H", 6) + image),
            fx.swf_tag(21, struct.pack("<H", 7) + png)]
    images, notes = swf.extract_images(movie(*tags))
    assert notes == [] and [im["char_id"] for im in images] == [1, 2, 3, 4, 5, 6, 7]
    assert [im["kind"] for im in images] == ["jpeg"] * 6 + ["png"]
    assert [im["tag"] for im in images] == ["DefineBitsJPEG2"] * 3 + ["DefineBitsJPEG3", "DefineBitsJPEG4",
                                                                      "DefineBits", "DefineBitsJPEG2"]
    for im in images[:6]:
        assert im["image"] == jpeg, im["char_id"]
        assert Image.open(io.BytesIO(im["image"])).size == (8, 8)
    assert images[6]["image"] == png


# ---- codes -----------------------------------------------------------------------------------------

def _image(char_id, matrix, scale=3):
    return {"char_id": char_id, "tag": "DefineBitsLossless", "kind": "png",
            "image": fx.matrix_png(matrix, scale=scale, border=2), "width": None, "height": None}


@pytest.mark.needs_tool("py:PIL", "py:qrcode")
def test_find_codes_order_gate_failures_and_deadline():
    grid = _image(1, fx.qr_modules("A", 1))                         # looks like a module matrix
    photo = {**_image(2, [[True] * 30] * 30), "image": _jpeg((64, 64))}
    wide = _image(3, [[True, False] * 40] * 21)                    # two-tone but 80x21: not square
    calls = []

    def camera(data):
        calls.append(("camera", data))
        return [{"format": "ean_13", "text": "5901234123457", "bytes": b""}] if data == photo["image"] else []

    def matrix(data):
        calls.append(("matrix", data))
        return [{"format": "qr_code", "text": "from the matrix", "bytes": b"x"}]

    hits = swf.find_codes([grid, photo, wide], camera=camera, matrix=matrix)
    assert [(h["char_id"], h["codes"][0]["text"]) for h in hits] == [(1, "from the matrix"), (2, "5901234123457")]
    assert [(kind, data == grid["image"]) for kind, data in calls if kind == "matrix"] == [("matrix", True)]
    assert [kind for kind, _d in calls] == ["camera", "matrix", "camera", "camera"]

    def broken(_data):
        raise RuntimeError("decoder fell over")

    skipped = []
    assert swf.find_codes([grid], camera=broken, matrix=matrix, skipped=skipped) == []
    assert skipped == ["codes: DefineBitsLossless 1: decoder failed: RuntimeError: decoder fell over"]
    skipped = []
    assert swf.find_codes([grid, photo], camera=camera, matrix=matrix, deadline=time.monotonic() - 1,
                          skipped=skipped) == []
    assert skipped == ["codes: out of time before DefineBitsLossless 1; 2 bitmap(s) were not read for codes"]


@pytest.mark.needs_tool("py:PIL", "py:qrcode")
def test_module_gate():
    assert swf._looks_like_modules(fx.matrix_png(fx.qr_modules("A", 1), scale=2, border=1)) is True
    assert swf._looks_like_modules(fx.matrix_png([[True, False] * 5] * 10, scale=2, border=0)) is False   # 20 px
    assert swf._looks_like_modules(fx.matrix_png([[True, False] * 15] * 21, scale=1, border=0)) is False  # 30x21
    assert swf._looks_like_modules(b"not an image") is False
    from PIL import Image
    ramp = Image.new("L", (64, 64))
    ramp.putdata([(x * 4) % 256 for _y in range(64) for x in range(64)])
    out = io.BytesIO()
    ramp.save(out, format="PNG")
    assert swf._looks_like_modules(out.getvalue()) is False                      # a gradient is not two-tone


# ---- the whole movie -------------------------------------------------------------------------------

def flashback(flag=FLAG, maker=fx.swf_cws, finders=False, extra=b""):
    """The PINK shape: two class-init blocks with seed and data arrays, a frame action, and a QR
    bitmap drawn without its finder patterns."""
    matrix = fx.qr_modules(flag, 3)
    if not finders:
        matrix = fx.blank_finders(matrix)
    init_a = struct.pack("<H", 1) + member_array("Kiln", "steps", [412, 96, 733, 58, 261]) \
        + member_array("Kiln", "glaze", [88213, 90544, 71009]) + b"\x00"
    init_b = struct.pack("<H", 2) + function("mix", ["step"], fx.avm1_push(("reg", 1), 3301) + fx.avm1(0x0C)
                                             + fx.avm1(0x3E), registers=3) + b"\x00"
    frame = fx.avm1_pool("Atlas", "boot") + fx.avm1_push(0, ("const", 0)) + fx.avm1(0x1C) \
        + fx.avm1_push(("const", 1)) + fx.avm1(0x52) + fx.avm1(0x17) + b"\x00"
    return movie(fx.swf_tag(69, bytes(4)), fx.swf_tag(59, init_a), fx.swf_tag(59, init_b),
                 fx.swf_tag(36, fx.lossless_tag_body(7, matrix, scale=3, alpha=True)),
                 fx.swf_tag(12, frame), fx.swf_tag(1, b""), extra, maker=maker)


@pytest.mark.needs_tool("py:PIL", "py:qrcode")
def test_parse_summary_of_a_whole_movie():
    summary = swf.parse(flashback())
    assert summary["header"]["compression"] == "zlib" and "trailing_bytes" not in summary["header"]
    assert summary["frame_rate"] == 24.0 and summary["frame_count"] == 1
    assert summary["frame_size"]["width_px"] == 550.0
    assert [t["name"] for t in summary["tags"]] == ["FileAttributes", "DoInitAction", "DoInitAction",
                                                    "DefineBitsLossless2", "DoAction", "ShowFrame", "End"]
    assert [b["label"] for b in summary["blocks"]] == ["DoInitAction sprite 1", "DoInitAction sprite 2", "DoAction"]
    named = {row["name"]: (row["value"], row["block"]) for row in summary["constants"]}
    assert named["Kiln.steps"] == ([412, 96, 733, 58, 261], "DoInitAction sprite 1")
    assert named["Kiln.glaze"][0] == [88213, 90544, 71009]
    assert {"Kiln", "steps", "glaze", "mix", "step", "Atlas", "boot"} <= set(summary["strings"])
    assert summary["has_doabc"] is False and summary["error"] is None
    assert swf.parse(movie(fx.swf_tag(82, b"\x01\x00\x00\x00name\x00abc")))["has_doabc"] is True


@pytest.mark.needs_tool("py:PIL", "py:qrcode")
def test_solve_reads_the_finderless_code_and_writes_the_material(tmp_path):
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "flashback.swf").write_bytes(flashback())
    (tmp_path / "files" / "readme.txt").write_text("FWS is not at the start of this file")
    res = swf.solve(tmp_path, PROFILE, seconds=BUDGET)
    assert res.status == "solved" and res.flags == (FLAG,) and res.engine == "toolkits.swf_parse"
    decode = [e for e in res.evidence if e.kind == "decode"]
    assert len(decode) == 1 and decode[0].path == "files/flashback.swf"
    assert decode[0].detail == "flag in qr_code in DefineBitsLossless2 7 (module matrix, repair decode)"
    written = sorted(e.path for e in res.evidence if e.detail == "written")
    assert written == [f"recon/swf_parse/files_flashback.swf.{suffix}" for suffix in
                       ("avm1.txt", "char7.png", "constants.json", "strings.txt")]
    assert "CWS v8 (zlib), 7 tags, 3 AVM1 block(s)" in res.notes and "1 bitmap(s)" in res.notes
    assert "constants: Kiln.steps (5 values), Kiln.glaze (3 values)" in res.notes
    out = tmp_path / "recon" / "swf_parse"
    text = (out / "files_flashback.swf.avm1.txt").read_text()
    assert "== DoInitAction sprite 1 at " in text and "Kiln.steps = [412, 96, 733, 58, 261]" in text
    assert "DefineFunction2 mix(step) " in text and "CallMethod" in text
    constants = json.loads((out / "files_flashback.swf.constants.json").read_text())
    assert [row["name"] for row in constants] == ["Kiln.steps", "Kiln.glaze"] and constants[1]["value"] == [88213, 90544, 71009]
    assert "Atlas" in (out / "files_flashback.swf.strings.txt").read_text().splitlines()
    assert _pixels((out / "files_flashback.swf.char7.png").read_bytes())[0] == (87, 87)
    elsewhere = tmp_path / "elsewhere"
    swf.solve(tmp_path, PROFILE, seconds=BUDGET, out=str(elsewhere))
    assert len(list(elsewhere.iterdir())) == 4
    with pytest.raises(FileNotFoundError):
        swf.solve(tmp_path / "missing", PROFILE, seconds=BUDGET)


@pytest.mark.needs_tool("py:PIL", "py:qrcode", "py:zxingcpp")
def test_camera_decoder_reads_an_intact_code_first(monkeypatch):
    monkeypatch.setattr(swf, "_matrix_codes", lambda data: pytest.fail("the matrix path was not needed"))
    rep = swf.examine({"m.swf": flashback(finders=True)}, FF)
    assert [(flag, kind) for flag, kind, _w in rep.movies[0].flags] == [(FLAG, "decode")]
    assert "module matrix" not in rep.movies[0].flags[0][2]


def test_flags_in_the_body_and_after_the_movie():
    frame = fx.swf_tag(12, fx.avm1_pool("CSCTF{in_the_pool}") + b"\x00")
    for maker in (fx.swf_fws, fx.swf_cws, fx.swf_zws):
        rep = swf.examine({"m.swf": movie(frame, maker=maker)}, FF)
        assert rep.movies[0].flags == [("CSCTF{in_the_pool}", "carve", "the decompressed body")]
        res = swf.result_of(rep)
        assert res.status == "solved" and res.flags == ("CSCTF{in_the_pool}",) and res.evidence[0].kind == "carve"
    appended = movie(fx.swf_tag(1, b""), maker=fx.swf_cws) + b"junk CSCTF{after_the_movie} junk"
    rep = swf.examine({"m.swf": appended}, FF)
    assert rep.movies[0].flags == [("CSCTF{after_the_movie}", "carve", "32 bytes appended after the movie")]
    assert "32 bytes are appended after the movie" in swf.result_of(rep).notes
    both = swf.result_of(swf.examine({"m.swf": movie(frame, maker=fx.swf_cws) + b"CSCTF{after_the_movie}"}, FF))
    assert both.status == "candidate" and both.flags == ("CSCTF{in_the_pool}", "CSCTF{after_the_movie}")


def test_what_is_not_solved_is_said():
    plain = movie(fx.swf_tag(12, fx.avm1(0x83, b"/hidden/route\x00\x00") + b"\x00"), fx.swf_tag(82, b"abc"))
    res = swf.result_of(swf.examine({"plain.swf": plain}, FF))
    assert res.status == "unsure" and res.flags == ()
    assert "URLs: /hidden/route" in res.notes and "AVM2 code (DoABC)" in res.notes
    corrupt = b"CWS\x08" + struct.pack("<I", 100) + b"garbage, not zlib"
    cut = fx.swf_fws(fx.swf_rect() + struct.pack("<HH", 6144, 1) + fx.swf_tag(12, fx.avm1_push("CSCTF{kept}") + b"\x00")
                     + struct.pack("<H", (12 << 6) | 0x20) + b"\x00")
    files = {"a.txt": b"FWS\tis how this text starts", "b.bin": b"FW", "corrupt.swf": corrupt, "cut.swf": cut,
             "old.swf": b"FWS\x00" + bytes(20), "norect.swf": b"FWS\x08" + struct.pack("<I", 9) + b"\xf8"}
    rep = swf.examine(files, FF)
    assert [m.file for m in rep.movies] == ["cut.swf"]
    assert rep.movies[0].flags[0][0] == "CSCTF{kept}"             # what came before the broken tag was read
    # a text that happens to start like a movie is tried and named; no signature or version is not
    assert sorted(note.split(":")[0] for note in rep.skipped) == ["a.txt", "corrupt.swf", "cut.swf", "norect.swf"]
    assert any("tag walk stopped early" in note for note in rep.skipped)
    assert any("norect.swf: not read as a SWF" in note for note in rep.skipped)
    none = swf.result_of(swf.examine({"corrupt.swf": corrupt, "a.txt": b"hello"}, FF))
    assert none.status == "none" and "corrupt.swf: not read as a SWF: CWS body does not inflate" in none.notes
    unread = movie(fx.swf_tag(21, struct.pack("<H", 3) + fx.matrix_png([[True, False] * 3] * 6, scale=1, border=0)))
    seen = swf.result_of(swf.examine({"u.swf": unread}, FF, camera=lambda d: [{"format": "qr_code", "text": "see /door"}]))
    assert seen.status == "unsure" and "qr_code in DefineBitsJPEG2 3 reads 'see /door'" in seen.notes


def test_is_swf():
    assert swf.is_swf(b"FWS\x08" + bytes(4)) and swf.is_swf(b"CWS\x0a" + bytes(4)) and swf.is_swf(b"ZWS\x0d" + bytes(4))
    assert not swf.is_swf(b"FWS\x08" + bytes(3)) and not swf.is_swf(b"FWS\x00" + bytes(4))
    assert not swf.is_swf(b"FWS\x3d" + bytes(4)) and swf.is_swf(b"FWS\x3c" + bytes(4)) and not swf.is_swf(b"GIF89a\x00\x00")


@pytest.mark.needs_tool("py:PIL", "py:qrcode")
def test_cli(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "csctf")
    path = tmp_path / "flashback.swf"
    path.write_bytes(flashback())
    assert swf.main([str(path), "--listing", "--out", str(tmp_path / "out"), "--seconds", "3600"]) == 0
    out = capsys.readouterr().out
    assert "== " in out and "DoInitAction sprite 1 at" in out and "string: 'Atlas'" in out
    assert out.count("written: ") == 4
    result = json.loads(out.strip().splitlines()[-1])
    assert result["status"] == "solved" and result["flags"] == [FLAG]
    assert swf.main([str(path), "--seconds", "3600"]) == 0
    assert "DoInitAction sprite 1 at" not in capsys.readouterr().out
    other = tmp_path / "note.txt"
    other.write_text("not a movie")
    assert swf.main([str(other)]) == 2 and "not a SWF" in capsys.readouterr().err
    assert swf.main([str(tmp_path / "absent.swf")]) == 2 and "no such file" in capsys.readouterr().err


# ---- round 1 of verification: the bounds themselves ------------------------------------------------

class _Spy:
    """A decompressor that records the bound each decompress() call was given and how many bytes
    it handed back: the proof that the inflate is capped where it runs, not checked afterwards."""
    calls = []

    def __init__(self, real, kind):
        self._real, self._kind = real, kind

    def decompress(self, data, max_length=None):
        call = [self._kind, max_length, None]                        # the bound is recorded even if the call raises
        _Spy.calls.append(call)
        out = self._real.decompress(data) if max_length is None else self._real.decompress(data, max_length)
        call[2] = len(out)
        return out

    def __getattr__(self, name):
        return getattr(self._real, name)


@pytest.fixture
def inflates(monkeypatch):
    real_zlib, real_lzma = zlib.decompressobj, lzma.LZMADecompressor
    _Spy.calls = []
    monkeypatch.setattr(swf.zlib, "decompressobj", lambda *a, **k: _Spy(real_zlib(*a, **k), "zlib"))
    monkeypatch.setattr(swf.lzma, "LZMADecompressor", lambda *a, **k: _Spy(real_lzma(*a, **k), "lzma"))
    return _Spy.calls


def test_container_inflate_never_produces_more_than_the_cap(inflates, monkeypatch):
    """A megabyte of zeros behind a header that declares 100 bytes. The refusal alone does not
    show the bound (a check after an unbounded inflate refuses too, a gigabyte later): what the
    decompressor was asked for, and what it gave back, does."""
    monkeypatch.setattr(swf, "MAX_BODY", 256)
    bomb = bytes(1 << 20)
    with pytest.raises(swf.SWFError, match="inflates past 256"):
        swf.decompress(b"CWS\x08" + struct.pack("<I", 108) + zlib.compress(bomb))
    assert inflates == [["zlib", 257, 257]]
    # ZWS: the LZMA header this reader rebuilds carries the declared length (already checked
    # against the cap), so liblzma itself stops there: a stream that holds a megabyte behind a
    # header declaring 100 bytes is refused by the decoder. The same bound is still handed to
    # the call, as the second of the two.
    del inflates[:]
    alone = lzma.compress(bomb, format=lzma.FORMAT_ALONE)
    lying = b"ZWS\x0d" + struct.pack("<I", 108) + struct.pack("<I", len(alone) - 13) + alone[:5] + alone[13:]
    try:
        _header, got = swf.decompress(lying)
    except swf.SWFError as exc:
        assert "does not decode" in str(exc)
    else:
        assert len(got) <= 100                                       # or it stops at the declared length
    assert [call[:2] for call in inflates] == [["lzma", 257]]
    assert all(call[2] is None or call[2] <= 100 for call in inflates)
    # an honest ZWS under the cap is asked for with the same bound and comes back whole
    del inflates[:]
    body = fx.swf_body(END)
    assert swf.decompress(fx.swf_zws(body))[1] == body
    assert inflates == [["lzma", 257, len(body)]]


@pytest.mark.needs_tool("py:PIL")
def test_bitmap_inflate_never_produces_more_than_the_pixels_need(inflates):
    """A 2x2 bitmap (16 bytes of pixels) whose data inflates to a megabyte."""
    tag = fx.swf_tag(20, struct.pack("<HBHH", 1, 5, 2, 2) + zlib.compress(bytes(1 << 20)), long=True)
    images, notes = swf.extract_images(movie(tag))
    assert notes == [] and (images[0]["width"], images[0]["height"]) == (2, 2)
    assert inflates == [["zlib", 16, 16]]
    del inflates[:]
    palette = fx.swf_tag(20, fx.lossless_tag_body(2, PATTERN, fmt=3))
    swf.extract_images(movie(palette))
    assert inflates == [["zlib", 2 * 3 + 8 * 3, 2 * 3 + 8 * 3]]      # 2 colours of 3 bytes, 3 rows padded to 8


def _pops(count):
    return fx.swf_tag(12, b"\x17" * count, long=True)               # `count` one-byte Pop actions


def test_actions_are_capped_over_the_whole_movie_not_a_block(monkeypatch):
    monkeypatch.setattr(swf, "MAX_ACTIONS", 1000)
    data = movie(*[_pops(400) for _ in range(10)])
    summary = swf.parse(data)
    counts = [len(block["disassembly"]["actions"]) for block in summary["blocks"]]
    assert counts == [400, 400, 200]                                 # 1000 in all, not 400 a block for ten blocks
    assert len(summary["cut"]) == 2
    assert summary["cut"][0].startswith("DoAction at 0x") and summary["cut"][0].endswith(
        ": stopped at offset 0xc8 after 200 actions: the cap on a movie's actions")
    assert summary["cut"][1].startswith("7 AVM1 block(s), from DoAction at 0x") and summary["cut"][1].endswith(
        " on, were not disassembled: the cap of 1000 actions a movie was reached")
    assert "; stopped at offset 0xc8 after 200 actions" in swf.listing(summary["blocks"][2]["disassembly"])
    # what the cap left out is still searched as bytes, and the result says what was cut
    flagged = movie(*[_pops(400) for _ in range(4)], fx.swf_tag(12, fx.avm1_push(FLAG) + fx.avm1(0x26)))
    res = swf.result_of(swf.examine({"m.swf": flagged}, FF))
    assert res.status == "solved" and res.flags == (FLAG,)
    assert "m.swf: AVM1: DoAction at 0x" in res.notes and "m.swf: AVM1: 2 AVM1 block(s), from DoAction at 0x" in res.notes
    # under the cap nothing is said
    assert swf.parse(movie(_pops(400), _pops(400)))["cut"] == []


def test_a_kilobyte_file_of_a_million_actions_keeps_the_default_cap():
    """The shape that took 326 MB at intake: about a kilobyte on disk, a million one-byte actions
    once inflated. The production cap is what is tested here, not a patched one."""
    data = fx.swf_cws(fx.swf_body(_pops(600_000) + _pops(400_000) + END))
    assert len(data) < 2500
    summary = swf.parse(data)
    assert sum(len(block["disassembly"]["actions"]) for block in summary["blocks"]) == swf.MAX_ACTIONS == 200_000
    assert len(summary["blocks"]) == 1 and len(summary["cut"]) == 2
    assert "1 AVM1 block(s), from DoAction at " in summary["cut"][1]


def test_action_bytes_and_time_are_capped_and_named(monkeypatch):
    dis = swf.disassemble(b"\x17" * 50, max_bytes=20)
    assert (len(dis["actions"]), dis["consumed"]) == (20, 20)
    assert dis["cut"] == "stopped at offset 0x14: the cap on a movie's action bytes" and dis["truncated"] is None
    # a record that starts under the cap is read whole, never cut in half
    straddling = b"\x17" * 10 + fx.avm1_push("a string that runs well past the cap") + b"\x17" * 5
    dis = swf.disassemble(straddling, max_bytes=20)
    assert [a["name"] for a in dis["actions"]][-1] == "Push" and dis["truncated"] is None
    assert dis["consumed"] == len(straddling) - 5 and dis["strings"] == ["a string that runs well past the cap"]
    whole = swf.disassemble(b"\x17" * 50)
    assert (len(whole["actions"]), whole["cut"], whole["consumed"]) == (50, None, 50)
    assert swf.disassemble(b"\x17" * 50, max_actions=7)["cut"] == \
        "stopped at offset 0x7 after 7 actions: the cap on a movie's actions"
    late = swf.disassemble(b"\x17" * 50, deadline=time.monotonic() - 1)
    assert late["actions"] == [] and late["cut"] == "stopped at offset 0x0 after 0 actions: out of time"

    monkeypatch.setattr(swf, "MAX_CODE", 600)
    summary = swf.parse(movie(_pops(400), _pops(400), _pops(400)))
    assert [len(b["disassembly"]["actions"]) for b in summary["blocks"]] == [400, 200]
    assert summary["cut"][0].endswith(": stopped at offset 0xc8: the cap on a movie's action bytes")
    assert summary["cut"][1].endswith(" on, were not disassembled: the cap of 600 bytes of action code a movie was reached")
    summary = swf.parse(movie(_pops(40), _pops(40)), deadline=time.monotonic() - 1)
    assert summary["blocks"] == [] and len(summary["cut"]) == 1
    assert summary["cut"][0].startswith("2 AVM1 block(s), from DoAction at 0x") and summary["cut"][0].endswith(": out of time")
    # the engine's deadline reaches the disassembly
    rep = swf.examine({"m.swf": movie(_pops(40))}, FF, deadline=time.monotonic() - 1)
    assert rep.movies[0].summary["blocks"] == [] and any("m.swf: AVM1: 1 AVM1 block(s)" in note for note in rep.skipped)


def test_a_literal_keeps_the_name_of_the_first_assignment():
    """b = a = [1, 2, 3]: the literal is assigned twice. It is `a`, the assignment that follows
    it, and is not renamed by each later one."""
    chained = (fx.avm1_push("b") + fx.avm1_push(3, 2, 1, 3) + fx.avm1(0x42)          # "b", L
               + fx.avm1(0x4C) + fx.avm1_push("a") + fx.avm1(0x4D)                   # "b", L, "a", L
               + fx.avm1(0x1D) + fx.avm1(0x1D))                                      # a = L; b = L
    assert [(row["name"], row["value"]) for row in swf.disassemble(chained)["constants"]] == [("a", [1, 2, 3])]
    # the same through a register: stored first, so that is its name, and the member assignment
    # after it does not take the name away
    stored = (fx.avm1_push("obj") + fx.avm1(0x1C) + fx.avm1_push("grid") + fx.avm1_push(8, 7, 2) + fx.avm1(0x42)
              + fx.avm1(0x87, b"\x03") + fx.avm1(0x4F))
    assert [(row["name"], row["value"]) for row in swf.disassemble(stored)["constants"]] == [("register3", [7, 8])]


def test_an_anonymous_function_is_a_value_on_the_stack():
    """obj.f = function () {...}; arr = [1, 2, 3]. The function expression leaves one value for
    SetMember to take. If it left none, SetMember would eat the name pushed below it, and the
    array after it would come out unnamed."""
    inner = fx.avm1_push(1) + fx.avm1(0x17)
    code = (fx.avm1_push("arr")
            + fx.avm1_push("obj") + fx.avm1(0x1C) + fx.avm1_push("f") + function("", [], inner) + fx.avm1(0x4F)
            + fx.avm1_push(3, 2, 1, 3) + fx.avm1(0x42) + fx.avm1(0x1D))
    assert [(row["name"], row["value"]) for row in swf.disassemble(code)["constants"]] == [("arr", [1, 2, 3])]
    # a function statement (it has a name) leaves nothing: the same listing with a named function
    # has one value too few for SetMember, which then takes "arr"
    named = code.replace(function("", [], inner), function("g", [], inner))
    assert [(row["name"], row["value"]) for row in swf.disassemble(named)["constants"]] == [(None, [1, 2, 3])]


@pytest.mark.needs_tool("py:PIL")
def test_pix15_rows_are_unpacked_whole_and_match_a_reference():
    from PIL import Image
    rng = random.Random(15)
    width, height = 5, 3                                             # 10 bytes a row, padded to 12
    values = [[rng.randrange(1 << 16) for _ in range(width)] for _ in range(height)]     # the reserved bit is noise
    raw = b"".join(struct.pack(f">{width}H", *row) + b"\xaa\xbb" for row in values)
    images, notes = swf.extract_images(movie(fx.swf_tag(20, struct.pack("<HBHH", 4, 4, width, height) + zlib.compress(raw))))
    assert notes == []
    image = Image.open(io.BytesIO(images[0]["image"]))
    want = [[tuple(((v >> shift) & 31) * 255 // 31 for shift in (10, 5, 0)) for v in row] for row in values]
    assert image.mode == "RGB" and image.size == (width, height)
    assert [[image.getpixel((x, y)) for x in range(width)] for y in range(height)] == want
    # four megapixels: a per-pixel Python loop took 0.67 s of CPU a megapixel. CPU time, not wall
    # clock, so the bound holds on a loaded machine.
    big_w, big_h = 2000, 2000
    tag = struct.pack("<HBHH", 5, 4, big_w, big_h) + zlib.compress(bytes(rng.randrange(256) for _ in range(64)) * (big_w * big_h * 2 // 64), 1)
    started = time.process_time()
    picture, why = swf._lossless(20, tag)
    spent = time.process_time() - started
    assert why == "" and picture.size == (big_w, big_h) and spent < 1.0, spent


@pytest.mark.needs_tool("py:PIL", "py:qrcode")
def test_missing_code_reader_is_named(monkeypatch):
    import sys
    grid = _image(1, fx.qr_modules("A", 1))
    skipped = []
    swf.find_codes([grid], matrix=lambda data: [], skipped=skipped)
    assert skipped == []                                             # a camera decoder imports here
    monkeypatch.setitem(sys.modules, "zxingcpp", None)
    monkeypatch.setitem(sys.modules, "pyzbar", None)
    note = "codes not read: neither py:zxingcpp nor py:pyzbar is importable"
    swf.find_codes([grid, grid], matrix=lambda data: [], skipped=skipped)
    assert skipped == [note]
    assert swf.find_codes([], skipped=(none := [])) == [] and none == []          # no bitmap, nothing to say
    swf.find_codes([grid], camera=lambda data: [], matrix=lambda data: [], skipped=(own := []))
    assert own == []                                                 # a caller's own reader is not second-guessed
    bitmap = fx.swf_tag(20, fx.lossless_tag_body(7, fx.qr_modules("A", 1), scale=4))
    res = swf.result_of(swf.examine({"m.swf": movie(bitmap)}, FF, matrix=lambda data: []))
    assert note in res.notes


def test_printable_runs_are_found_without_a_byte_loop_and_capped(monkeypatch):
    blob = b"\x00ab\x01abcd\x02 four and more ~\x7f\x80tail"
    assert swf._printable_runs(blob) == ["abcd", " four and more ~", "tail"]
    assert swf._printable_runs(blob, least=5) == [" four and more ~"]
    assert swf._printable_runs(b"") == [] and swf._printable_runs(blob, most=1) == ["abcd"]
    monkeypatch.setattr(swf, "MAX_STRINGS", 3)
    binary = fx.swf_tag(87, struct.pack("<HI", 1, 0) + b"\x00".join(b"run%04d" % n for n in range(50)), long=True)
    assert swf.tag_strings(swf.walk(fx.swf_body(binary + binary + END))[0]) == ["run0000", "run0001", "run0002"]


# ---- round 2 of verification: what a literal costs, not only how many records --------------------

def _doubling(times, name="big"):
    """name = [1, 2], then `times` times PushDuplicate, Push 2, InitArray: each ten bytes of code
    build an array that holds the one before it twice."""
    code = fx.avm1_push(name) + fx.avm1_push(2, 1, 2) + fx.avm1(0x42)
    code += (fx.avm1(0x4C) + fx.avm1_push(2) + fx.avm1(0x42)) * times
    return code + fx.avm1(0x1D)


def _written(value):
    """(values, depth) of a constant as it is written out, counted here and not by the engine: a
    container and each scalar are one value; no recursion, so a deep value cannot fail the count."""
    count, deepest, todo = 0, 0, [(value, 0)]
    while todo:
        item, depth = todo.pop()
        count += 1
        deepest = max(deepest, depth)
        if isinstance(item, list):
            todo += [(part, depth + 1) for part in item]
        elif isinstance(item, dict) and set(item) != {"ref"}:
            todo += [(part, depth + 1) for part in item.values()]
    return count, deepest


def test_a_shared_literal_is_weighed_each_time_it_appears_and_capped(monkeypatch, tmp_path):
    """PushDuplicate puts one list on the stack twice and InitArray then holds it twice, so what
    is written out doubles every ten bytes of code. Counted, not timed: the values the constants
    hold stay under a cap per literal and per movie whatever the code does.

    One test, the patched caps first: were a cap not applied, the small cases fail here before
    the forty doublings below are ever expanded."""
    monkeypatch.setattr(swf, "MAX_LITERAL_NODES", 100)
    monkeypatch.setattr(swf, "MAX_MOVIE_NODES", 10_000)
    dis = swf.disassemble(_doubling(8))
    sizes = [_written(row["value"])[0] for row in dis["constants"]]
    assert sizes == [3, 7, 15, 31, 63, 3, 7, 15]                    # 127 would be next: it is left out
    assert dis["nodes"] == sum(sizes) == 144
    assert dis["constants"][1]["value"] == [[1, 2], [1, 2]] and dis["constants"][1]["complete"] is True
    assert len(dis["left_out"]) == 1 and dis["left_out"][0].endswith(
        " was left out: written out it holds 127 values, over the cap of 100 a literal")
    # what stood on the stack in its place is the unknown, so nothing grows on top of it
    assert dis["constants"][5]["value"] == ["<unknown>", "<unknown>"] and dis["constants"][5]["complete"] is False
    assert (dis["constants"][-1]["name"], dis["constants"][0]["name"]) == ("big", None)
    assert "; the constant at offset " in swf.listing(dis)
    exact = swf.disassemble(_doubling(4))                            # 63 values: under the cap, nothing is said
    assert exact["left_out"] == [] and exact["nodes"] == 3 + 7 + 15 + 31 + 63
    monkeypatch.setattr(swf, "MAX_LITERAL_NODES", 63)                # exactly at the cap is kept
    assert swf.disassemble(_doubling(4))["left_out"] == []
    monkeypatch.setattr(swf, "MAX_LITERAL_NODES", 62)
    assert len(swf.disassemble(_doubling(4))["left_out"]) == 1

    # an object literal and a string are weighed too: a constant-pool index is two bytes of code
    # and can name a string of thousands of characters
    monkeypatch.setattr(swf, "MAX_LITERAL_NODES", 100)
    pooled = fx.avm1_pool("s" * 800) + fx.avm1_push("words") + fx.avm1_push(("const", 0), ("const", 0), 2) \
        + fx.avm1(0x42) + fx.avm1(0x1D)
    dis = swf.disassemble(pooled)
    assert dis["constants"] == [] and "holds 203 values" in dis["left_out"][0]       # 1 + 2 * (1 + 800 // 8)
    short = fx.avm1_pool("s" * 80) + fx.avm1_push("words") + fx.avm1_push(("const", 0), ("const", 0), 2) \
        + fx.avm1(0x42) + fx.avm1(0x1D)
    assert swf.disassemble(short)["nodes"] == 23
    inner = fx.avm1_push(2, 1, 2) + fx.avm1(0x42)
    obj = fx.avm1_push("cfg", "k1") + inner + fx.avm1(0x4C) + fx.avm1_push("k2") + fx.avm1(0x4D) \
        + fx.avm1_push(2) + fx.avm1(0x43) + fx.avm1(0x1D)
    dis = swf.disassemble(obj)
    assert dis["constants"][-1]["value"] == {"k1": [1, 2], "k2": [1, 2]} and dis["nodes"] == 3 + (1 + 2 + 3 + 3)
    # a scalar constant spends the budget as well
    assert swf.disassemble(fx.avm1_push("n", 5) + fx.avm1(0x1D))["nodes"] == 1
    assert swf.disassemble(fx.avm1_push("n", 5) + fx.avm1(0x1D), max_nodes=0)["constants"] == []

    # the cap over a movie is one budget for all its blocks
    monkeypatch.setattr(swf, "MAX_MOVIE_NODES", 200)
    block = fx.swf_tag(12, _doubling(4) + b"\x00")
    summary = swf.parse(movie(block, block))
    assert sum(_written(row["value"])[0] for row in summary["constants"]) == 119 + 56 <= 200
    assert len(summary["cut"]) == 1 and summary["cut"][0].startswith("DoAction at 0x") and summary["cut"][0].endswith(
        " was left out: the cap of 200 values over a movie's constants was reached")
    # every literal left out after the first few is counted, not listed
    monkeypatch.setattr(swf, "MAX_LITERAL_NODES", 2)
    many = swf.disassemble((fx.avm1_push(2, 1, 2) + fx.avm1(0x42) + fx.avm1(0x17)) * 9)
    assert len(many["left_out"]) == swf.MAX_CUT_NOTES + 1 == 5
    assert many["left_out"][-1] == "5 more constant(s) were left out for the same caps"
    monkeypatch.undo()

    # the production caps, forty doublings: 2 ** 42 values if they were written out
    assert swf.MAX_LITERAL_NODES <= 1_000_000 and swf.MAX_MOVIE_NODES <= 4_000_000
    dis = swf.disassemble(_doubling(40))
    sizes = [_written(row["value"])[0] for row in dis["constants"]]
    assert max(sizes) == 2 ** 17 - 1 <= swf.MAX_LITERAL_NODES
    assert dis["nodes"] == sum(sizes) <= swf.MAX_MOVIE_NODES
    assert len(dis["left_out"]) == 2 and all("over the cap of 250000 a literal" in note for note in dis["left_out"])
    # ... and through the engine, from a file of a few hundred bytes: the result names what was
    # left out and the constants file holds what the caps allow, no more
    (tmp_path / "files").mkdir()
    data = fx.swf_cws(fx.swf_body(fx.swf_tag(12, _doubling(80) + fx.avm1_push(FLAG) + fx.avm1(0x26) + b"\x00", long=True) + END))
    assert len(data) < 400
    (tmp_path / "files" / "tiny.swf").write_bytes(data)
    res = swf.solve(tmp_path, PROFILE, seconds=BUDGET)
    assert res.status == "solved" and res.flags == (FLAG,)
    assert "files/tiny.swf: AVM1: DoAction at 0x" in res.notes and "over the cap of 250000 a literal" in res.notes
    assert "the cap of 1000000 values over a movie's constants was reached" in res.notes
    constants = json.loads((tmp_path / "recon" / "swf_parse" / "files_tiny.swf.constants.json").read_text())
    assert sum(_written(row["value"])[0] for row in constants) <= swf.MAX_MOVIE_NODES


def _nested(depth, name="deep"):
    """name = [[[...[7]...]]], `depth` arrays deep."""
    return (fx.avm1_push(name) + fx.avm1_push(7, 1) + fx.avm1(0x42)
            + (fx.avm1_push(1) + fx.avm1(0x42)) * (depth - 1) + fx.avm1(0x1D))


def test_a_deeply_nested_literal_is_cut_at_a_depth_and_named():
    dis = swf.disassemble(_nested(1500))
    depths = [_written(row["value"])[1] for row in dis["constants"]]
    assert max(depths) == swf.MAX_LITERAL_DEPTH == 64
    # 64 arrays are kept, the 65th is left out and the count starts again on the unknown
    assert len(dis["constants"]) == 1500 - 1500 // 65 and depths[:66] == list(range(1, 65)) + [1, 2]
    want = 7
    for _ in range(64):
        want = [want]
    assert dis["constants"][63]["value"] == want and dis["constants"][64]["value"] == ["<unknown>"]
    assert dis["left_out"][0].endswith(" was left out: it nests deeper than 64 arrays")
    assert dis["left_out"][-1] == f"{1500 // 65 - swf.MAX_CUT_NOTES} more constant(s) were left out for the same caps"
    assert swf.disassemble(_nested(64))["left_out"] == [] and len(swf.disassemble(_nested(65))["left_out"]) == 1


def test_a_block_whose_disassembly_fails_costs_that_block_only(monkeypatch):
    """A reader's failure on one stream must not lose the movie's bytes or the movies after it.
    The depth cap is lifted here so that writing the literal out really does fail (5,000 arrays
    deep is past the interpreter's recursion limit): the failure is named, the flag in that
    movie's bytes is still found, and so is the other movie's."""
    deep = movie(fx.swf_tag(12, _nested(5000) + b"\x00", long=True),
                 fx.swf_tag(12, fx.avm1_push("CSCTF{in_the_deep_movie}") + fx.avm1(0x26) + b"\x00"), maker=fx.swf_cws)
    other = movie(fx.swf_tag(12, fx.avm1_push("CSCTF{in_the_other_movie}") + b"\x00"))
    files = {"a_deep.swf": deep, "b_other.swf": other}
    rep = swf.examine(files, FF)                                     # as shipped: the cap holds, nothing fails
    assert [m.flags[0][0] for m in rep.movies] == ["CSCTF{in_the_deep_movie}", "CSCTF{in_the_other_movie}"]
    assert not any("disassembly failed" in note for note in rep.skipped)
    assert any("a_deep.swf: AVM1: DoAction at 0x" in note and "nests deeper than 64 arrays" in note for note in rep.skipped)
    monkeypatch.setattr(swf, "MAX_LITERAL_DEPTH", 10 ** 9)
    rep = swf.examine(files, FF)
    assert [m.file for m in rep.movies] == ["a_deep.swf", "b_other.swf"]
    assert [m.flags[0][0] for m in rep.movies] == ["CSCTF{in_the_deep_movie}", "CSCTF{in_the_other_movie}"]
    failed = [note for note in rep.skipped if "disassembly failed" in note]
    assert len(failed) == 1 and failed[0].startswith("a_deep.swf: AVM1: DoAction at 0x")
    assert "(RecursionError: " in failed[0] and failed[0].endswith("the block is still searched as bytes")
    # the block after the failed one in the same movie was still disassembled
    assert [b["label"] for b in rep.movies[0].summary["blocks"]] == ["DoAction"]
    assert "CSCTF{in_the_deep_movie}" in rep.movies[0].summary["strings"]
    assert swf.result_of(rep).status == "candidate"


def test_listing_clips_long_strings_and_stops_at_a_cap(monkeypatch, tmp_path):
    """A push of constant-pool indices names the same long string two bytes a time: the listing
    shows each clipped, with its length, and the listing of a movie stops at a character cap."""
    long = "L" * 5000
    code = fx.avm1_pool(long, "short") + fx.avm1_push(*[("const", 0)] * 300, ("const", 1)) + fx.avm1(0x17) * 40
    dis = swf.disassemble(code)
    text = swf.listing(dis)
    push = next(line for line in text.splitlines() if " Push " in line)
    assert push.count('"' + "L" * swf.MAX_SHOWN + '... (5000 characters)"') == 300 and push.endswith('"short"')
    assert len(text) < 300 * (swf.MAX_SHOWN + 40) + 5000 + 2000      # not 300 * 5000
    assert long in dis["strings"]                                    # the strings file holds it whole
    assert swf._show("x" * swf.MAX_SHOWN) == json.dumps("x" * swf.MAX_SHOWN)        # at the cap: as it is
    capped = swf.listing(dis, limit=600).splitlines()
    assert capped[-1] == "; the listing stops here: the cap of 600 characters was reached"
    # a line that starts under the cap is written whole, never cut in half; the next one is not started
    assert len(capped) == 3 and capped[0].startswith("000000 ConstantPool") and capped[1] == push
    assert len(swf.listing(dis, limit=len(capped[0])).splitlines()) == 2
    assert "stops here" not in swf.listing(dis, limit=len(text))
    # over a movie: the blocks share one budget, and the result names the blocks not written
    monkeypatch.setattr(swf, "MAX_LISTING", 1500)
    block = fx.swf_tag(12, fx.avm1_push("a string in every block") * 20 + b"\x00", long=True)
    rep = swf.examine({"m.swf": movie(block, block, block, block)}, FF, out_dir=tmp_path)
    written = (tmp_path / "m.swf.avm1.txt").read_text()
    assert written.count("== DoAction at ") == 2 and written.count("the listing stops here") == 1
    assert len(written) < 1500 + 2 * 200
    assert any(note.startswith("m.swf: AVM1: the listing of 2 block(s), from DoAction at 0x") and note.endswith(
        " on, was not written: the cap of 1500 characters a movie's listing was reached") for note in rep.skipped)
    # the notes of a result clip a long constant and a long URL the same way
    noisy = movie(fx.swf_tag(12, fx.avm1_push("k", "v" * 3000) + fx.avm1(0x1D)
                             + fx.avm1(0x83, b"/" + b"u" * 3000 + b"\x00\x00") + b"\x00", long=True))
    notes = swf.result_of(swf.examine({"n.swf": noisy}, FF)).notes
    assert "... (3002 characters)" in notes and "... (3001 characters)" in notes and len(notes) < 1500


@pytest.mark.needs_tool("py:PIL")
def test_bitmaps_stop_at_the_deadline_and_at_a_count_and_are_named(monkeypatch):
    tags = [fx.swf_tag(20, fx.lossless_tag_body(n, PATTERN)) for n in range(1, 6)] \
        + [fx.swf_tag(21, struct.pack("<H", 6) + _jpeg())]
    data = movie(*tags, fx.swf_tag(12, fx.avm1_push(FLAG) + b"\x00"))
    images, notes = swf.extract_images(data, deadline=time.monotonic() - 1)
    assert images == [] and notes == ["6 bitmap(s), from DefineBitsLossless 1 on, were not carved: out of time"]
    assert len(swf.extract_images(data, deadline=time.monotonic() + 3600)[0]) == 6

    class Clock:                                                     # one second a look: no wall clock is read
        now = 1000.0

        def monotonic(self):
            self.now += 1.0
            return self.now - 1.0

    monkeypatch.setattr(swf, "time", Clock())
    images, notes = swf.extract_images(data, deadline=1002.5)        # looks at 1000, 1001, 1002, then 1003
    assert [im["char_id"] for im in images] == [1, 2, 3]
    assert notes == ["3 bitmap(s), from DefineBitsLossless 4 on, were not carved: out of time"]
    monkeypatch.undo()
    monkeypatch.setattr(swf, "MAX_IMAGES", 2)
    images, notes = swf.extract_images(data)
    assert [im["char_id"] for im in images] == [1, 2]
    assert notes == ["4 bitmap(s), from DefineBitsLossless 3 on, were not carved: the cap of 2 bitmaps a movie was reached"]
    monkeypatch.undo()
    # the engine's deadline reaches the bitmaps, and the movie's bytes are searched all the same
    rep = swf.examine({"m.swf": data}, FF, deadline=time.monotonic() - 1)
    assert rep.movies[0].images == [] and rep.movies[0].flags[0][0] == FLAG
    assert "m.swf: 6 bitmap(s), from DefineBitsLossless 1 on, were not carved: out of time" in rep.skipped
