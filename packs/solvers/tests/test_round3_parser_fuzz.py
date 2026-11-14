"""Seeded property-style mutation smoke tests for parser exception boundaries.

Hypothesis is not a repository dependency, so this permanent suite uses deterministic generated and
header-mutated byte strings.  It specifically rejects the exception classes that previously escape
binary parsers (recursion/unicode/overflow/struct/memory) while allowing each API's documented
``ValueError``/repair refusal for an invalid format.
"""
from __future__ import annotations

import csv
import importlib.util
import random
import struct
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
for folder in (REPO / "solvers" / "common", REPO / "solvers" / "toolkits",
               REPO / "solvers" / "warmups", REPO / "solvers" / "web"):
    sys.path.insert(0, str(folder))

import covert_channels  # noqa: E402
import crib_decode  # noqa: E402
import file_repair  # noqa: E402
import osint_leads  # noqa: E402
import timeline  # noqa: E402
import auth_trust  # noqa: E402
import browser_recon  # noqa: E402
import clientside_exploit  # noqa: E402
import deser_gadgets  # noqa: E402
import etag_chain  # noqa: E402
import sqli_helper  # noqa: E402
import ssti_helper  # noqa: E402
import upload_builder  # noqa: E402

_classical_spec = importlib.util.spec_from_file_location(
    "round3_common_classical", REPO / "solvers" / "common" / "classical.py"
)
classical = importlib.util.module_from_spec(_classical_spec)
_classical_spec.loader.exec_module(classical)


RNG = random.Random(0xC5C7F2026)
BAD_ESCAPE = (RecursionError, UnicodeError, OverflowError, struct.error, MemoryError)


def _blobs(count=160):
    headers = (b"", b"\x89PNG\r\n\x1a\n", b"PK\x03\x04", b"%PDF-1.7\n", b"\x1f\x8b", b"BZh9",
               b"pcap", b"{", b"[", b"HTTP/1.1 200 OK\r\n")
    for index in range(count):
        size = RNG.randrange(0, 768)
        body = bytes(RNG.randrange(256) for _ in range(size))
        yield headers[index % len(headers)] + body


def _assert_boundary(call, allowed=(ValueError, TypeError, file_repair.RepairError, csv.Error)):
    try:
        call()
    except BAD_ESCAPE as exc:  # make the dangerous escape class explicit in the failure
        raise AssertionError(f"unsafe parser exception escaped: {type(exc).__name__}: {exc}") from exc
    except allowed:
        pass


def test_classical_and_warmup_decoders_mutation_boundary():
    classical_calls = (
        lambda text, raw: classical.a1z26_decode(text),
        lambda text, raw: classical.spelling_decode(text),
        lambda text, raw: classical.polybius_decode(text),
        lambda text, raw: classical.tap_decode(text),
        lambda text, raw: classical.bacon_decode(text),
        lambda text, raw: classical.ook_to_brainfuck(text),
        lambda text, raw: classical.brainfuck(text, stdin=b"x", steps=500),
        lambda text, raw: classical.cow(text, stdin=b"x", steps=500),
    )
    decoder_names = (
        "d_b62", "d_b36", "d_bigdec", "d_b91", "d_uu", "d_octesc", "d_uesc",
        "d_runlength", "d_revhex", "d_morse2", "d_morsex", "d_nato", "d_urlplus",
        "d_revwords", "d_wordorder", "d_bin7", "d_binlsb", "d_bigbin", "d_bigoct",
        "d_html2", "d_qp2", "d_dump", "d_utf16be", "d_z85", "d_brascii", "d_braille",
        "d_braille8", "d_uesc2", "d_htmlfold", "d_inflate", "d_cssesc", "d_charcodes",
        "d_xescp", "d_xx", "d_yenc", "d_b92", "d_utf7", "d_utf32", "d_datauri",
        "d_unquote", "d_mime", "d_ebcdic", "d_ebcdic500", "d_ebcdic273", "d_nfkc",
        "d_base100", "d_twosym",
    )
    decoders = [getattr(crib_decode, name) for name in decoder_names]
    for raw in _blobs(80):
        text = raw.decode("utf-8", "replace")
        for function in classical_calls:
            _assert_boundary(lambda function=function: function(text, raw))
        for decoder in decoders:
            _assert_boundary(lambda decoder=decoder: decoder(raw))


def test_file_repair_timeline_covert_and_osint_mutation_boundary():
    for raw in _blobs():
        text = raw.decode("utf-8", "replace")
        fmt = file_repair.detect_format(raw)
        if raw:
            _assert_boundary(lambda: file_repair.repair(raw, fmt))
        _assert_boundary(lambda: timeline.parse_bodyfile(text))
        _assert_boundary(lambda: timeline.parse_csv_text(text))
        _assert_boundary(lambda: timeline.parse_json_text(text))
        _assert_boundary(lambda: covert_channels.scan(raw))
        _assert_boundary(lambda: osint_leads.scan_text(text))


def test_web_decoder_and_builder_mutation_boundary():
    for raw in _blobs(120):
        text = raw.decode("utf-8", "replace")[:4096]
        token = text.replace("\x00", "")[:1024]
        calls = (
            lambda: etag_chain.parse_saved_response(raw),
            lambda: sqli_helper.decode_filter_bypasses(text),
            lambda: ssti_helper.detect_response({"body": text, "status": 200, "headers": {}}),
            lambda: auth_trust.inspect_jwt(token),
            lambda: clientside_exploit.analyze(text, text[:512]),
            lambda: deser_gadgets.synthesize(text, "printf CSCTF_FUZZ_MARKER"),
            lambda: browser_recon.analyze(html=text, js=text, headers=[]),
            lambda: upload_builder.build_polyglot(("gif", "jpeg", "png", "pdf")[len(raw) % 4], raw[:1024]),
        )
        for call in calls:
            _assert_boundary(call)

