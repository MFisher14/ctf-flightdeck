"""Independent upload/LFI vector locks and deterministic fail-closed probes.

Oracles: RFC 7578 via the stdlib MIME parser; RFC 3986 percent decoding;
PHP's documented filter-wrapper grammar; Pillow/libmagic/pypdf container
parsers; Unicode NFKC and platform path normalizers. No request is sent.
"""
from __future__ import annotations

import base64
from dataclasses import replace
from email import policy
from email.parser import BytesParser
import io
import ntpath
import posixpath
import random
import re
import unicodedata
import urllib.parse

import magic
from PIL import Image
from pypdf import PdfReader
import pytest

import upload_builder as builder
import upload_lfi_catalog as catalog


MARKER = b"CSCTF{offline_upload_vector}"
RNG = random.Random(0x53535246)
PAYLOAD_CASES = [
    b"",
    RNG.randbytes(73),
    b"\xff" * 97,
    MARKER[:9],
    bytes([MARKER[0] ^ 1]) + MARKER[1:],
]
MAGIC_PREFIXES = {
    "gif": b"GIF89a",
    "jpeg": b"\xff\xd8\xff\xe0",
    "png": b"\x89PNG\r\n\x1a\n",
    "pdf": b"%PDF-1.4",
}


def _declared_or_clean(module, call):
    """Require an empty rejection or an exception declared by the engine module."""
    try:
        result = call()
    except Exception as exc:
        assert type(exc).__module__ == module.__name__, (
            f"leaked {type(exc).__module__}.{type(exc).__name__}"
        )
        return None
    assert result is None or result in (b"", "", [], (), {})
    return result


def _mime_part(body: bytes, boundary: str = "CSCTFBOUNDARY"):
    envelope = (
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        "MIME-Version: 1.0\r\n\r\n"
        f"--{boundary}\r\n"
    ).encode() + body + f"\r\n--{boundary}--\r\n".encode()
    message = BytesParser(policy=policy.default).parsebytes(envelope)
    assert message.is_multipart() and len(message.get_payload()) == 1
    return message.get_payload()[0]


def test_filename_catalog_matches_documented_normalization_cases():
    rows = builder.filename_variants("avatar", "php", "jpg")
    assert [(row["technique"], row["filename"]) for row in rows] == [
        ("direct", "avatar.php"),
        ("double_allowed_last", "avatar.php.jpg"),
        ("double_script_last", "avatar.jpg.php"),
        ("mixed_case", "avatar.PHP.jpg"),
        ("trailing_dot", "avatar.php."),
    ]
    # Independent suffix interpretations demonstrate why both double orders
    # are catalogued; this is not an assertion that a server is vulnerable.
    assert posixpath.splitext(rows[1]["filename"])[1] == ".jpg"
    assert posixpath.splitext(rows[2]["filename"])[1] == ".php"


@pytest.mark.parametrize("format_name,mime", [
    ("gif", "image/gif"),
    ("jpeg", "image/jpeg"),
    ("png", "image/png"),
])
def test_raster_polyglots_against_pillow_and_libmagic(format_name, mime):
    blob = builder.build_polyglot(format_name, MARKER)
    with Image.open(io.BytesIO(blob)) as image:
        image.load()
        assert image.size == (1, 1)
        assert image.format == {"gif": "GIF", "jpeg": "JPEG", "png": "PNG"}[format_name]
    assert magic.from_buffer(blob, mime=True) == mime
    assert MARKER in blob


def test_png_binary_payload_has_documented_text_encoding():
    original = b"A\0B\xff"
    blob = builder.build_polyglot("png", original)
    with Image.open(io.BytesIO(blob)) as image:
        carried = image.info["Comment"]
    assert carried.startswith("base64:")
    assert base64.b64decode(carried.removeprefix("base64:")) == original


def test_pdf_polyglot_against_pypdf_and_libmagic():
    blob = builder.build_polyglot("pdf", MARKER)
    reader = PdfReader(io.BytesIO(blob), strict=True)
    assert len(reader.pages) == 1
    assert magic.from_buffer(blob, mime=True) == "application/pdf"
    assert MARKER in blob


@pytest.mark.parametrize("format_name,magic_prefix", [
    *MAGIC_PREFIXES.items(),
])
def test_shallow_magic_vectors_are_prefix_only(format_name, magic_prefix):
    value = builder.magic_prefixed(format_name, MARKER)
    assert value == magic_prefix + MARKER


def test_multipart_part_against_rfc7578_mime_parser():
    candidate = builder.generate_candidates(
        stem="avatar", content=MARKER, formats=("gif",), max_candidates=1
    )[0]
    part = _mime_part(builder.multipart_part(candidate, field="evidence"))
    assert part.get_content_disposition() == "form-data"
    assert part.get_param("name", header="content-disposition") == "evidence"
    assert part.get_filename() == "avatar.php"
    assert part.get_content_type() == "application/octet-stream"
    assert part.get_payload(decode=True) == MARKER


def test_json_candidates_is_an_independent_base64_round_trip():
    rows = builder.generate_candidates(content=MARKER, formats=("png",), max_candidates=8)
    encoded = builder.json_candidates(rows)
    assert [row["rank"] for row in encoded] == list(range(1, len(encoded) + 1))
    assert all("content" not in row for row in encoded)
    assert [base64.b64decode(row["content_b64"], validate=True) for row in encoded] == [
        row["content"] for row in rows
    ]


def test_catalog_multipart_preview_against_rfc7578_mime_parser():
    candidate = catalog.upload_bypass_catalog("probe", "php", "jpg", "MARKER")[0]
    body = catalog.multipart_preview(candidate, field="artifact", boundary="BOUNDARY5").encode()
    headers, payload = body.split(b"\r\n\r\n", 1)
    # multipart_preview produces a whole body, so parse it directly rather
    # than wrapping the already-present boundary delimiter a second time.
    envelope = (
        b"Content-Type: multipart/form-data; boundary=BOUNDARY5\r\n"
        b"MIME-Version: 1.0\r\n\r\n" + body
    )
    message = BytesParser(policy=policy.default).parsebytes(envelope)
    part = message.get_payload()[0]
    assert b'name="artifact"' in headers
    assert part.get_filename() == "probe.php.jpg"
    assert part.get_content_type() == "text/plain"
    assert part.get_payload(decode=True) == b"MARKER"
    assert payload.endswith(b"--BOUNDARY5--\r\n")


def test_upload_catalog_normalization_semantics():
    rows = {row.name: row for row in catalog.upload_bypass_catalog("probe", "php", "jpg", "M")}
    assert posixpath.splitext(rows["double_extension"].filename)[1] == ".jpg"
    assert posixpath.splitext(rows["reverse_double_extension"].filename)[1] == ".php"
    assert unicodedata.normalize("NFKC", rows["fullwidth_dot"].filename) == "probe.php"
    assert urllib.parse.unquote(rows["encoded_dot"].filename) == "probe.php"
    assert urllib.parse.unquote(rows["encoded_trailing_space"].filename) == "probe.php "
    assert all(row.to_dict()["network_requests"] == 0 for row in rows.values())


def test_traversal_decode_layers_and_path_resolution():
    rows = {row.name: row for row in catalog.traversal_catalog("etc/passwd", depth=3)}
    base = "/srv/www/app"
    assert posixpath.normpath(posixpath.join(base, rows["plain"].value)) == "/etc/passwd"
    assert ntpath.normpath(ntpath.join(r"C:\srv\www\app", rows["backslash"].value)) == r"C:\etc\passwd"
    one = urllib.parse.unquote(rows["double_encoded"].value)
    two = urllib.parse.unquote(one)
    assert "%2e%2e%2f" in one.lower()
    assert two == "../../../etc/passwd"
    assert rows["double_encoded"].decode_layers == 2


def test_php_read_wrappers_match_documented_filter_grammar():
    rows = {row.name: row for row in catalog.lfi_wrapper_catalog("var/www/config.php")}
    pattern = re.compile(r"^php://filter/(?:read=)?(?P<filters>[^/]+)/resource=(?P<resource>/.*)$")
    for name in ("php_filter_base64", "php_filter_named_read", "php_filter_chain", "php_rot13_control"):
        match = pattern.fullmatch(rows[name].value)
        assert match, rows[name].value
        assert match.group("resource") == "/var/www/config.php"
    assert rows["php_filter_base64"].value.startswith("php://filter/convert.base64-encode/")
    assert rows["php_filter_chain"].value.split("/resource=", 1)[0].count("|") == 1


def test_lfi_chain_catalog_decodes_exactly_as_claimed():
    rows = {row.name: row for row in catalog.lfi_chain_catalog("etc/passwd", depth=2)}
    encoded = rows["encoded_php_filter_after_traversal"]
    assert encoded.decode_layers == 1
    assert urllib.parse.unquote(encoded.value) == (
        "php://filter/convert.base64-encode/resource=../../etc/passwd"
    )
    double = rows["double_encoded_traversal_in_filter"]
    resource = double.value.split("resource=", 1)[1]
    assert urllib.parse.unquote(urllib.parse.unquote(resource)) == "../../etc/passwd"


def test_surface_analyzer_offsets_and_evidence_against_literal_sources():
    source = "prefix\nallowed_extensions = {'jpg'}\nkind = finfo_file(upload)\ndata = include(user_path)\n"
    rows = catalog.analyze_upload_lfi_surface(source)
    expected = {
        "extension_allowlist": source.index("allowed_extensions"),
        "magic_inspection": source.index("finfo_file"),
        "file_read_sink": source.index("include"),
    }
    assert {row.name: row.offset for row in rows} == expected
    assert all(source[row.offset:row.offset + len(row.evidence)].strip() or row.evidence for row in rows)


@pytest.mark.parametrize("payload", PAYLOAD_CASES)
@pytest.mark.parametrize("format_name", ["gif", "jpeg", "png", "pdf"])
def test_builder_payload_fuzz_returns_cleanly(payload, format_name):
    assert builder.magic_prefixed(format_name, payload).endswith(payload)
    result = builder.build_polyglot(format_name, payload)
    assert isinstance(result, bytes) and result.startswith(MAGIC_PREFIXES[format_name])
    rows = builder.generate_candidates(content=payload, formats=(format_name,), max_candidates=12)
    assert rows and all(isinstance(row["content"], bytes) for row in rows)


def test_builder_oversized_content_requires_declared_error():
    _declared_or_clean(
        builder,
        lambda: builder.build_polyglot("gif", b"X" * (builder.MAX_CONTENT + 1)),
    )


@pytest.mark.parametrize("entrypoint", [
    lambda: builder.magic_prefixed("unknown", b"x"),
    lambda: builder.build_polyglot("unknown", b"x"),
    lambda: builder.generate_candidates(formats=("unknown",)),
])
def test_builder_unknown_format_requires_declared_error(entrypoint):
    _declared_or_clean(builder, entrypoint)


@pytest.mark.parametrize("bad", ["", "../x", "bad\0name", "x" * 129])
def test_builder_filename_fuzz_requires_declared_error(bad):
    _declared_or_clean(builder, lambda: builder.filename_variants(bad, ".php", ".jpg"))


@pytest.mark.parametrize("candidate", [
    {},
    {"filename": "x", "content_type": "text/plain"},
    {"filename": "x\r\nInjected: yes", "content_type": "text/plain", "content": b"x"},
    {"filename": "x", "content_type": "bad", "content": b"x"},
])
def test_builder_multipart_fuzz_requires_declared_error(candidate):
    _declared_or_clean(builder, lambda: builder.multipart_part(candidate))


def test_builder_json_fuzz_requires_declared_error():
    _declared_or_clean(builder, lambda: builder.json_candidates([{"rank": 1}]))


def test_builder_cli_guard_bug():
    assert builder.main(["--not-an-option"]) == 2


@pytest.mark.parametrize("value", [b"", b"\xff" * 32, RNG.randbytes(32), "../secret", "x" * 513])
def test_lfi_target_fuzz_raises_only_declared_error_or_returns(value):
    for parser in (catalog.traversal_catalog, catalog.lfi_wrapper_catalog, catalog.lfi_chain_catalog):
        try:
            result = parser(value)
            assert isinstance(result, tuple)
        except catalog.UploadLFIInputError:
            pass


@pytest.mark.parametrize("arguments", [
    {"basename": ""},
    {"basename": "../escape"},
    {"blocked_extension": "p/hp"},
    {"allowed_extension": "x" * 13},
    {"marker": "bad marker"},
])
def test_upload_catalog_invalid_inputs_raise_only_declared_error(arguments):
    with pytest.raises(catalog.UploadLFIInputError):
        catalog.upload_bypass_catalog(**arguments)


def test_lfi_bytes_target_declared_error_bug():
    with pytest.raises(catalog.UploadLFIInputError):
        catalog.lfi_wrapper_catalog(b"etc/passwd")


@pytest.mark.parametrize("value", [b"", b"\xff" * 128, RNG.randbytes(128), b"include(user"[:7]])
def test_surface_analyzer_binary_fuzz_returns_cleanly(value):
    assert isinstance(catalog.analyze_upload_lfi_surface(value), tuple)


def test_surface_analyzer_oversized_is_declared_error():
    with pytest.raises(catalog.UploadLFIInputError):
        catalog.analyze_upload_lfi_surface(b"X" * (catalog.MAX_TEXT + 1))


def test_rows_as_dicts_declared_error_bug():
    _declared_or_clean(catalog, lambda: catalog.rows_as_dicts([object()]))


def test_catalog_mutated_candidates_reject_with_declared_error():
    seed = catalog.upload_bypass_catalog()[0]
    mutations = [
        replace(seed, filename='x"\r\nInjected: yes'),
        replace(seed, content_type="not-a-media-type"),
        replace(seed, filename="x" * (catalog.MAX_NAME + 1)),
    ]
    for candidate in mutations:
        with pytest.raises(catalog.UploadLFIInputError):
            catalog.multipart_preview(candidate)
