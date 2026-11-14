"""Synthetic, offline tests for solvers/web/upload_builder.py."""

import base64
import binascii
import io
import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "web"))

import upload_builder as ub  # noqa: E402


def test_filename_and_ranked_candidate_families_are_bounded():
    names = ub.filename_variants("avatar", ".php", ".jpg")
    assert [x["filename"] for x in names[:3]] == [
        "avatar.php", "avatar.php.jpg", "avatar.jpg.php"
    ]
    rows = ub.generate_candidates(stem="avatar", content=b"MARK", max_candidates=40)
    assert len(rows) <= 40
    assert [x["rank"] for x in rows] == list(range(1, len(rows) + 1))
    assert any("content_type" in x["techniques"] for x in rows)
    assert any("double_allowed_last" in x["techniques"] for x in rows)
    assert any("magic_bytes" in x["techniques"] for x in rows)
    assert any("polyglot" in x["techniques"] for x in rows)
    assert all(x["offline"] for x in rows)


def test_default_is_inert_and_json_payloads_round_trip():
    rows = ub.generate_candidates(max_candidates=20)
    assert all(x["safe_default"] for x in rows)
    assert all(b"<?" not in x["content"] and b"eval(" not in x["content"] for x in rows)
    encoded = ub.json_candidates(rows)
    for raw, printable in zip(rows, encoded):
        assert "content" not in printable
        assert base64.b64decode(printable["content_b64"]) == raw["content"]


def test_magic_prefixes_and_polyglot_carriers():
    marker = b"CTF-INERT-CONTENT"
    for fmt, info in ub.FORMAT_INFO.items():
        shallow = ub.magic_prefixed(fmt, marker)
        poly = ub.build_polyglot(fmt, marker)
        assert shallow.startswith(info["magic"])
        assert poly.startswith(info["magic"])
        assert marker in poly
    assert ub.build_polyglot("gif", marker).endswith(b";")
    assert ub.build_polyglot("jpeg", marker).endswith(b"\xff\xd9")
    assert ub.build_polyglot("pdf", marker).rstrip().endswith(b"%%EOF")


def test_jpeg_container_is_a_decodable_image_when_pillow_is_available():
    image_module = pytest.importorskip("PIL.Image")
    data = ub.build_polyglot("jpeg", b"JPEG-MARKER")
    with image_module.open(io.BytesIO(data)) as image:
        image.load()
        assert image.format == "JPEG"
        assert image.size == (1, 1)
    assert b"JPEG-MARKER" in data


def test_png_is_structurally_valid_and_crcs_match():
    data = ub.build_polyglot("png", b"PNG-MARKER")
    pos = len(ub.FORMAT_INFO["png"]["magic"])
    kinds = []
    while pos < len(data):
        size = struct.unpack(">I", data[pos:pos + 4])[0]
        kind = data[pos + 4:pos + 8]
        payload = data[pos + 8:pos + 8 + size]
        crc = struct.unpack(">I", data[pos + 8 + size:pos + 12 + size])[0]
        assert crc == (binascii.crc32(kind + payload) & 0xFFFFFFFF)
        kinds.append(kind)
        pos += 12 + size
    assert kinds == [b"IHDR", b"tEXt", b"IDAT", b"IEND"]
    assert pos == len(data)


def test_multipart_part_uses_candidate_metadata_only():
    candidate = ub.generate_candidates(content=b"body", max_candidates=1)[0]
    part = ub.multipart_part(candidate, "avatar")
    assert b'name="avatar"' in part
    assert candidate["filename"].encode() in part
    assert candidate["content_type"].encode() in part
    assert part.endswith(b"body")
    with pytest.raises(ValueError):
        ub.multipart_part(candidate, "bad\r\nInjected: yes")
    with pytest.raises(ValueError):
        ub.multipart_part(candidate, "bad\x00field")
    with pytest.raises(ValueError, match="media type"):
        ub.multipart_part({**candidate, "content_type": "image/jpeg\x00evil"})


def test_input_validation_and_cap():
    with pytest.raises(ValueError):
        ub.filename_variants("../avatar", ".php", ".jpg")
    with pytest.raises(ValueError):
        ub.filename_variants('bad"name', ".php", ".jpg")
    with pytest.raises(ValueError):
        ub.generate_candidates(formats=("unknown",))
    with pytest.raises(ValueError):
        ub.generate_candidates(max_candidates=ub.MAX_CANDIDATES + 1)
    with pytest.raises(ValueError):
        ub.build_polyglot("gif", b"x" * (ub.MAX_CONTENT + 1))


def test_jpeg_extension_alias_gets_the_image_mime_type(tmp_path):
    rows = ub.generate_candidates(allowed_ext=".jpeg", formats=("jpeg",), max_candidates=10)
    double = next(row for row in rows if "double_allowed_last" in row["techniques"])
    assert double["filename"].endswith(".php.jpeg")
    assert double["content_type"] == "image/jpeg"

    oversized = tmp_path / "oversized.bin"
    oversized.write_bytes(b"x" * (ub.MAX_CONTENT + 1))
    with pytest.raises(ValueError, match="exceeds"):
        ub._read_payload_file(oversized)


def test_cli_json_is_offline_and_decodable():
    proc = subprocess.run(
        [sys.executable, str(REPO / "solvers" / "web" / "upload_builder.py"),
         "--text", "fixture", "--formats", "gif", "--limit", "4", "--json"],
        check=True, capture_output=True, text=True,
    )
    doc = json.loads(proc.stdout)
    assert doc["offline"] is True and doc["sent"] is False
    assert len(doc["candidates"]) == 4
    assert base64.b64decode(doc["candidates"][0]["content_b64"]) == b"fixture"
