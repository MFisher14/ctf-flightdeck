"""B-076: ctf/fragjoin.py's HTTP header source (header_values, header_fields, part_order) and join over it.

The flag shapes follow the Spooky Cleithrophobia case (three `deflector_partN=<base64>` headers on one
response); every value is built here.
"""
import base64

from ctf import event, flagfmt
from ctf import fragjoin as fj

SPOOKY = flagfmt.for_profile(event.load("spooky"))


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def test_b64_text_reads_strict_base64_of_printable_text_only():
    assert fj.b64_text(b64("Spooky{Be0")) == "Spooky{Be0"
    assert fj.b64_text(b64("Spooky{Be0").rstrip("=")) == "Spooky{Be0"         # missing padding repaired
    assert fj.b64_text(base64.urlsafe_b64encode(b"??>>??>>ab").decode()) == "??>>??>>ab"
    assert fj.b64_text("ZmxhZw") is None                                         # under MIN_B64 characters
    assert fj.b64_text(base64.b64encode(bytes(range(1, 13))).decode()) is None   # control bytes: not text
    assert fj.b64_text("application/json") is None                              # decodes, but to binary
    assert fj.b64_text("keep-alive-123") is None                                 # '-' without '_' is no alphabet here
    assert fj.b64_text("abcde") is None
    assert fj.b64_text("abcdefghi") is None                                      # 9 chars: one left over


def test_part_number_reads_the_number_a_key_or_header_carries():
    assert fj.part_number("X-Bridge-Telemetry:deflector_part1") == 1
    assert fj.part_number("fragment-12") == 12
    assert fj.part_number("X-Chunk.3") == 3
    assert fj.part_number("piece2of5") == 2
    assert fj.part_number("4/7") == 4
    assert fj.part_number("X-Bridge-Telemetry") is None
    assert fj.part_number("partner") is None                                     # no digits after 'part'


def test_header_values_takes_the_whole_value_or_each_key_value_item():
    assert fj.header_values("X-Token", b64("hello world!")) == [("X-Token", b64("hello world!"), "hello world!")]
    got = fj.header_values("X-Bridge", f"status=green; deflector_part1={b64('Spooky{Be0')}, other=plain")
    assert got == [("X-Bridge:deflector_part1", b64("Spooky{Be0"), "Spooky{Be0")]
    assert fj.header_values("Content-Type", "text/plain; charset=utf-8") == []
    assert fj.header_values("Date", "Mon, 06 Nov 2026 10:00:00 GMT") == []


def test_header_fields_put_numbered_parts_in_order_and_leave_the_rest_in_place():
    headers = [("X-Note", b64("first unnumbered")),
               ("X-Warp", "deflector_part3=" + b64("0tty_2266}")),
               ("X-Other", b64("second unnumbered")),
               ("X-Bridge", "deflector_part1=" + b64("Spooky{Be0")),
               ("X-Deflector", "deflector_part2=" + b64("m_Me_Up_Sc"))]
    fields = fj.header_fields(headers)
    assert [f.text for f in fields] == ["first unnumbered", "Spooky{Be0", "second unnumbered", "m_Me_Up_Sc", "0tty_2266}"]
    assert all(f.container == "http:header" for f in fields)
    assert [f.name for f in fields][1] == "X-Bridge:deflector_part1"


def test_part_order_is_stable_for_one_number():
    a = fj.Field("c", "x_part2", "A", 0)
    b = fj.Field("c", "y_part1", "B", 1)
    c = fj.Field("c", "z_part2", "C", 2)
    assert [f.text for f in fj.part_order([a, b, c])] == ["B", "A", "C"]


def test_shuffled_header_parts_join_into_the_flag_only_in_part_order():
    headers = [("X-Warp-Core-Reading", "deflector_part3=" + b64("0tty_2266}")),
               ("X-Bridge-Telemetry", "deflector_part1=" + b64("Spooky{Be0")),
               ("X-Deflector-Status", "deflector_part2=" + b64("m_Me_Up_Sc"))]
    joined = [j.flag for j in fj.join(fj.header_fields(headers), SPOOKY)]
    assert joined[0] == "Spooky{Be0m_Me_Up_Sc0tty_2266}"
    # read in header order, the closing part comes first and nothing joins: the part order is what joins it
    raw = [fj.Field("http:header", n, fj.b64_text(v.split("=", 1)[1]), i) for i, (n, v) in enumerate(headers)]
    assert "Spooky{Be0m_Me_Up_Sc0tty_2266}" not in [j.flag for j in fj.join(raw, SPOOKY)]


def test_fields_of_an_image_are_unchanged_by_the_header_source():
    assert fj.fields(b"GET / HTTP/1.1\r\nX-A: " + b64("Spooky{x}").encode() + b"\r\n\r\n") == []
