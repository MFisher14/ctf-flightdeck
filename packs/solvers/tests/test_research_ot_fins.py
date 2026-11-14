"""Reference-layout tests for the static Omron FINS decoder.

The fixtures are hand-authored from Omron W342's FINS command-frame tables and
W421's FINS/TCP header tables.  They are not encoded by the module under test.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

import research_ot_fins as fins


# W342 routing header followed by Memory Area Read (01 01): DM word 100,
# bit 0, one item.  0x82 is the published DM-word memory-area code.
READ_DM100 = bytes.fromhex(
    "80 00 02 00 01 00 00 0a 00 01"
    "01 01 82 00 64 00 00 01"
)

# The response swaps node routing, sets ICF bit 6, repeats 01 01, reports
# end-code 0000, and returns the independently chosen value 0x1234.
READ_DM100_RESPONSE = bytes.fromhex(
    "c0 00 02 00 0a 00 00 01 00 01"
    "01 01 00 00 12 34"
)

# Omron W342 published example: destination node 100, source node 50,
# Memory Area Read of 150 words beginning at DM100.
W342_MEMORY_READ_EXAMPLE = bytes.fromhex(
    "80 00 02 00 64 00 00 32 00 01"
    "01 01 82 00 64 00 00 96"
)


def tcp(command: int, error: int, payload: bytes) -> bytes:
    """Test-only W421 envelope writer, independent of the parser."""
    length = 8 + len(payload)
    return b"FINS" + length.to_bytes(4, "big") + command.to_bytes(4, "big") + error.to_bytes(4, "big") + payload


def test_udp_memory_read_request_from_w342_layout():
    out = fins.parse_udp(READ_DM100)
    assert out["transport"] == "udp"
    assert out["direction"] == "command"
    assert out["header"]["destination"] == {"network": 0, "node": 1, "unit": 0}
    assert out["header"]["source"] == {"network": 0, "node": 10, "unit": 0}
    assert out["header"]["service_id"] == 1
    assert out["command"] == {"code": 0x0101, "code_hex": "0x0101", "name": "memory-area-read"}
    assert out["body"]["memory"] == {
        "area_code": 0x82,
        "area_code_hex": "0x82",
        "area_name": "DM-word",
        "word": 100,
        "bit": 0,
    }
    assert out["body"]["item_count"] == 1


def test_udp_memory_read_response_end_code_and_data():
    out = fins.parse_fins_frame(READ_DM100_RESPONSE)
    assert out["direction"] == "response"
    assert out["header"]["response"] is True
    assert out["body"] == {
        "end_code": 0,
        "end_code_hex": "0x0000",
        "end_code_name": "normal-completion",
        "main_response_code": 0,
        "sub_response_code": 0,
        "ok": True,
        "data_hex": "1234",
        "data_length": 2,
    }


def test_published_w342_memory_read_example_vector():
    out = fins.parse_udp(W342_MEMORY_READ_EXAMPLE)
    assert out["header"]["destination"]["node"] == 100
    assert out["header"]["source"]["node"] == 50
    assert out["body"]["memory"]["word"] == 100
    assert out["body"]["item_count"] == 150


def test_write_multiple_read_run_and_stop_requests():
    prefix = bytes.fromhex("80 00 02 00 01 00 00 0a 00 22")
    write = fins.parse_udp(prefix + bytes.fromhex("01 02 82 00 64 00 00 02 12 34 56 78"))
    assert write["body"]["item_count"] == 2
    assert write["body"]["write_data_hex"] == "12345678"

    multiple = fins.parse_udp(prefix + bytes.fromhex("01 04 82 00 64 00 82 00 65 00"))
    assert multiple["body"]["address_count"] == 2
    assert [entry["word"] for entry in multiple["body"]["addresses"]] == [100, 101]

    run = fins.parse_udp(prefix + bytes.fromhex("04 01 ff ff 02"))
    assert run["body"] == {"program_number": 0xFFFF, "operating_mode": 2}
    stop = fins.parse_udp(prefix + bytes.fromhex("04 02 ff ff"))
    assert stop["body"] == {"program_number": 0xFFFF}


def test_tcp_node_negotiation_layouts_from_w421():
    request = fins.parse_tcp_frame(tcp(0, 0, bytes.fromhex("0000000a")))
    assert request["tcp_command_name"] == "node-address-request"
    assert request["declared_length"] == 12
    assert request["client_node"] == 10

    response = fins.parse_tcp_frame(tcp(1, 0, bytes.fromhex("0000000a 00000001")))
    assert response["tcp_command_name"] == "node-address-response"
    assert response["client_node"] == 10
    assert response["server_node"] == 1


def test_tcp_embedded_frame_and_concatenated_stream():
    envelope = tcp(2, 0, READ_DM100)
    out = fins.parse_tcp_frame(envelope)
    assert out["tcp_command_name"] == "fins-frame"
    assert out["fins"]["body"]["memory"]["word"] == 100
    frames = fins.parse_tcp_stream(tcp(0, 0, bytes.fromhex("0000000a")) + envelope)
    assert [frame["tcp_command"] for frame in frames] == [0, 2]
    assert fins.analyze(envelope)["transport"] == "tcp"
    assert fins.analyze(READ_DM100)["transport"] == "udp"


def test_tcp_error_notification_and_connection_confirmation():
    out = fins.parse_tcp_frame(tcp(3, 0x00000003, b""))
    assert out["ok"] is False
    assert out["tcp_error_hex"] == "0x00000003"
    confirmation = fins.parse_tcp_frame(tcp(6, 0xFFFFFFFF, b""))
    assert confirmation["tcp_command_name"] == "connection-confirmation"
    with pytest.raises(fins.FINSParseError):
        fins.parse_tcp_frame(tcp(3, 0, b"\xaa"))


@pytest.mark.parametrize(
    "value",
    [None, 1, "FINS", [], {}, b"", b"\x80", b"\x80" * 11],
)
def test_udp_public_contract_is_only_declared_exception(value):
    with pytest.raises(fins.FINSParseError):
        fins.parse_udp(value)
    with pytest.raises(fins.FINSParseError):
        fins.parse_fins_frame(value)


@pytest.mark.parametrize(
    "value",
    [
        b"NOPE" + b"\x00" * 12,
        b"FINS" + b"\x00" * 12,
        b"FINS" + bytes.fromhex("00000008 00000009 00000000"),
        b"FINS" + bytes.fromhex("00000009 00000002 00000000 00"),
        b"FINS" + bytes.fromhex("0000000c 00000000 00000000 0001"),
    ],
)
def test_tcp_rejects_bad_magic_lengths_commands_and_payloads(value):
    with pytest.raises(fins.FINSParseError):
        fins.parse_tcp_frame(value)


def test_known_command_shapes_fail_closed():
    prefix = bytes.fromhex("80 00 02 00 01 00 00 0a 00 01")
    for malformed in (
        prefix + bytes.fromhex("01 01 82 00"),
        prefix + bytes.fromhex("01 02 82 00 64 00 00 01"),
        prefix + bytes.fromhex("01 04 82 00 64"),
        prefix + bytes.fromhex("04 01 00 00"),
        prefix + bytes.fromhex("04 02 00"),
    ):
        with pytest.raises(fins.FINSParseError):
            fins.parse_udp(malformed)


def test_deterministic_short_mutations_never_leak_stdlib_exceptions():
    for length in range(33):
        value = bytes(range(length))
        for parser in (fins.parse_udp, fins.parse_tcp_frame, fins.parse_tcp_stream):
            try:
                parser(value)
            except fins.FINSParseError:
                pass


def test_limits_are_enforced(monkeypatch):
    monkeypatch.setattr(fins, "MAX_UDP_FRAME", len(READ_DM100) - 1)
    with pytest.raises(fins.FINSParseError, match="limit"):
        fins.parse_udp(READ_DM100)
    monkeypatch.setattr(fins, "MAX_STREAM_FRAMES", 1)
    one = tcp(0, 0, bytes.fromhex("0000000a"))
    with pytest.raises(fins.FINSParseError, match="frame limit"):
        fins.parse_tcp_stream(one + one)


def test_file_api_and_guarded_cli(tmp_path, capsys):
    artifact = tmp_path / "fins.bin"
    artifact.write_bytes(READ_DM100)
    assert fins.analyze_file(artifact, transport="udp")["command"]["code"] == 0x0101
    assert fins.main([str(artifact), "--transport", "udp"]) == 0
    rendered = json.loads(capsys.readouterr().out)
    assert rendered["body"]["memory"]["area_name"] == "DM-word"
    assert fins.main([]) == 2
    assert fins.main(["--help"]) == 0
    assert fins.main([str(tmp_path / "missing")]) == 2
    with pytest.raises(fins.FINSParseError):
        fins.analyze_file(tmp_path / "missing")


def test_module_is_static_only():
    source = Path(fins.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )
    assert not imports.intersection({"socket", "requests", "httpx", "subprocess", "scapy"})
