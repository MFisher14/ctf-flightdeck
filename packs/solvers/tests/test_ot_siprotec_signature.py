"""Synthetic data only; ESET Figure 20 and RFC 768 are independent oracles.

No real malware, packet capture, relay, socket or network access is involved.
The detector's output/constants are never used to construct its test evidence.
"""
import argparse
import json
import random
import struct

import pytest

import ot_siprotec_signature as siprotec


# Transcribed independently from ESET's printed p13/Figure20:
# https://cdn1.esetstatic.com/ESET/INT/Landing/2017/black-hat/WIN32_Industroyer-USLetter-WEB.pdf
# First row has 16 octets, second row has two. This is inert test evidence.
PUBLISHED = bytes.fromhex("11 49 00 00 00 00 00 00 00 00 00 00 00 00 00 00 28 9e")


def supplied_datagram(payload=PUBLISHED, source=12345, destination=50000):
    # RFC 768 header layout, independent of the engine: src,dst,length,checksum.
    return struct.pack("!HHHH", source, destination, 8 + len(payload), 0) + payload


def test_exact_published_payload_is_limited_evidence():
    result = siprotec.detect_payload(PUBLISHED)
    assert len(PUBLISHED) == 18
    assert result["matched"] is True
    assert result["cve"] == "CVE-2015-5374"
    assert result["evidence"] == "documented_payload"
    assert result["destination_port"] is None and result["transport"] is None
    assert result["reference"]["page"] == 13 and result["reference"]["figure"] == 20
    assert "not established" in result["assessment"]


@pytest.mark.parametrize("transport", ["udp", "UDP"])
def test_flow_context_upgrades_only_with_destination_and_udp(transport):
    result = siprotec.detect_payload(PUBLISHED, destination_port=50000, transport=transport)
    assert result["evidence"] == "documented_udp_flow"
    assert result["transport"] == "udp" and result["destination_port"] == 50000
    assert siprotec.detect_payload(PUBLISHED, destination_port=50000)["evidence"] == "documented_payload"
    assert siprotec.detect_payload(PUBLISHED, transport="udp")["evidence"] == "documented_payload"


@pytest.mark.parametrize("port,transport", [(50001, "udp"), (49999, None), (50000, "tcp"), (None, "tcp")])
def test_wrong_known_context_is_not_a_match(port, transport):
    assert siprotec.detect_payload(PUBLISHED, destination_port=port, transport=transport) is None


@pytest.mark.parametrize("position", range(18))
def test_every_published_octet_is_significant(position):
    altered = bytearray(PUBLISHED)
    altered[position] ^= 1
    assert siprotec.detect_payload(altered, destination_port=50000, transport="udp") is None


def test_no_partial_embedded_or_repeated_match():
    for size in range(18):
        assert siprotec.detect_payload(PUBLISHED[:size]) is None
    for data in (b"\x00" + PUBLISHED, PUBLISHED + b"\x00", PUBLISHED * 2, bytes(18)):
        assert siprotec.detect_payload(data) is None


@pytest.mark.parametrize("wrap", [bytes, bytearray, memoryview])
def test_udp_datagram_header_and_byteslike_input(wrap):
    result = siprotec.detect_udp_datagram(wrap(supplied_datagram()))
    assert result["evidence"] == "documented_udp_flow"
    assert result["source_port"] == 12345
    assert result["destination_port"] == 50000
    assert result["udp_length"] == 26 and result["checksum_verified"] is False
    assert siprotec.detect_payload(wrap(PUBLISHED))["matched"] is True


def test_direction_and_length_are_not_inferred_from_source_port():
    assert siprotec.detect_udp_datagram(supplied_datagram(source=50000, destination=12345)) is None
    assert siprotec.detect_udp_datagram(supplied_datagram(payload=bytes(18))) is None
    assert siprotec.detect_udp_datagram(supplied_datagram(payload=b"")) is None


@pytest.mark.parametrize("declared_length", [0, 7, 8, 25, 27, 65535])
def test_udp_length_is_exact(declared_length):
    malformed = struct.pack("!HHHH", 12345, 50000, declared_length, 0) + PUBLISHED
    with pytest.raises(siprotec.SiprotecError):
        siprotec.detect_udp_datagram(malformed)


@pytest.mark.parametrize("data", [None, "text", 123, {}, [], [0, 1]])
@pytest.mark.parametrize("fn", [siprotec.detect_payload, siprotec.detect_udp_datagram])
def test_malformed_types_raise_only_declared_error(fn, data):
    with pytest.raises(siprotec.SiprotecError):
        fn(data)


@pytest.mark.parametrize("options", [
    {"destination_port": -1}, {"destination_port": 65536}, {"destination_port": True},
    {"destination_port": "50000"}, {"destination_port": []}, {"transport": 17},
    {"transport": []}, {"transport": "icmp"}, {"transport": "\ud800"},
])
def test_malformed_context_raises_only_declared_error(options):
    with pytest.raises(siprotec.SiprotecError):
        siprotec.detect_payload(PUBLISHED, **options)


def test_bounds_and_released_buffer():
    assert siprotec.detect_payload(bytes(65527)) is None
    with pytest.raises(siprotec.SiprotecError):
        siprotec.detect_payload(bytes(65528))
    with pytest.raises(siprotec.SiprotecError):
        siprotec.detect_udp_datagram(bytes(65536))
    view = memoryview(PUBLISHED)
    view.release()
    for fn in (siprotec.detect_payload, siprotec.detect_udp_datagram):
        with pytest.raises(siprotec.SiprotecError):
            fn(view)


def test_deterministic_fail_closed_fuzz():
    rng = random.Random(20155374)
    for size in range(256):
        data = rng.randbytes(size)
        assert siprotec.detect_payload(data) is None
        try:
            assert siprotec.detect_udp_datagram(data) is None
        except siprotec.SiprotecError:
            pass
    for size in range(8):
        with pytest.raises(siprotec.SiprotecError):
            siprotec.detect_udp_datagram(bytes(size))


def test_cli_reads_only_supplied_file(tmp_path, capsys):
    path = tmp_path / "inert-payload.bin"
    path.write_bytes(PUBLISHED)
    assert siprotec.main([str(path), "--destination-port", "50000", "--transport", "udp"]) == 0
    assert json.loads(capsys.readouterr().out)["evidence"] == "documented_udp_flow"
    path.write_bytes(supplied_datagram())
    assert siprotec.main([str(path), "--format", "udp"]) == 0
    assert json.loads(capsys.readouterr().out)["udp_length"] == 26
    path.write_bytes(b"no match")
    assert siprotec.main([str(path)]) == 0
    assert json.loads(capsys.readouterr().out) == {"matched": False}


def test_cli_bad_inputs_are_status_codes(tmp_path, capsys):
    path = tmp_path / "bad.bin"
    path.write_bytes(bytes(65536))
    assert siprotec.main([str(path)]) == 2
    assert siprotec.main([str(path), "--format", "udp", "--destination-port", "50000"]) == 2
    assert siprotec.main([str(tmp_path)]) == 2
    assert siprotec.main([str(tmp_path / "absent")]) == 2
    assert siprotec.main(["\ud800"]) == 2
    assert siprotec.main([]) == 2
    assert siprotec.main(["--help"]) == 0
    assert siprotec.main([None]) == 2
    assert siprotec.main("bad") == 2
    capsys.readouterr()


def test_cli_noninteger_systemexit_is_normalized(monkeypatch):
    def invalid_exit(self, args):
        raise SystemExit("bad")
    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", invalid_exit)
    assert siprotec.main([]) == 2
