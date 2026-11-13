from __future__ import annotations

import hashlib
import hmac
import io
import json
import sqlite3
import struct
import sys
import uuid
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))
import ics_app_depth as app


def ua_string(value):
    if value is None:
        return struct.pack("<i", -1)
    raw = value.encode()
    return struct.pack("<i", len(raw)) + raw


def ua_bytes(value):
    if value is None:
        return struct.pack("<i", -1)
    return struct.pack("<i", len(value)) + value


def nodeid(number):
    return b"\x01\x00" + struct.pack("<H", number)


def request_header(handle=1):
    return (b"\x00\x00" + struct.pack("<qII", 0, handle, 0) + ua_string(None)
            + struct.pack("<I", 1000) + b"\x00\x00\x00")


def opc_chunk(kind, chunk_type, payload):
    return kind.encode() + chunk_type.encode() + struct.pack("<I", 8 + len(payload)) + payload


def test_opcua_nodeids_variants_and_strict_dimensions():
    value, offset = app.parse_opcua_nodeid(b"\x00\x2a")
    assert value == {"namespace": 0, "type": "numeric", "identifier": 42} and offset == 2
    value, offset = app.parse_opcua_nodeid(b"\x03\x02\x00" + ua_string("Pump.Speed"))
    assert value["namespace"] == 2 and value["identifier"] == "Pump.Speed"

    encoded = bytes([0x80 | 6]) + struct.pack("<i", 3) + struct.pack("<iii", 1, -2, 3)
    variant, offset = app.parse_opcua_variant(encoded)
    assert variant["type"] == "Int32" and variant["value"] == [1, -2, 3] and offset == len(encoded)
    matrix = bytes([0xC0 | 7]) + struct.pack("<iIIIIiii", 4, 1, 2, 3, 4, 2, 2, 2)
    parsed, _ = app.parse_opcua_variant(matrix)
    assert parsed["dimensions"] == [2, 2]
    bad = bytes([0xC0 | 7]) + struct.pack("<iIIiI", 2, 1, 2, 1, 3)
    with pytest.raises(app.ParseError, match="dimensions"):
        app.parse_opcua_variant(bad)


def test_opcua_none_policy_chunks_service_reassembly_and_findings():
    policy = "http://opcfoundation.org/UA/SecurityPolicy#None"
    open_service = (nodeid(446) + request_header(7) + struct.pack("<III", 0, 0, 1)
                    + ua_bytes(b"") + struct.pack("<I", 60_000))
    open_payload = (struct.pack("<I", 5) + ua_string(policy) + ua_bytes(None) + ua_bytes(None)
                    + struct.pack("<II", 1, 100) + open_service)
    opn = opc_chunk("OPN", "F", open_payload)

    write_service = (nodeid(673) + request_header(8) + struct.pack("<i", 1)
                     + b"\x01\x02\x2a\x00"  # FourByte NodeId ns=2 id=42
                     + struct.pack("<I", 13) + ua_string(None)
                     + b"\x01" + bytes([6]) + struct.pack("<i", 123))
    msg_payload = struct.pack("<II", 5, 99) + struct.pack("<II", 2, 101) + write_service
    msg = opc_chunk("MSG", "F", msg_payload)
    report = app.analyze_opcua_stream(opn + msg)
    assert report["channel_policies"][5] == policy
    assert [message["service"]["service"] for message in report["messages"]] == [
        "OpenSecureChannelRequest", "WriteRequest"]
    assert report["messages"][1]["service"]["nodes_to_write"][0]["value"]["value"]["value"] == 123
    kinds = {item["kind"] for item in report["findings"]}
    assert {"opcua-security-none", "opcua-message-mode-none", "opcua-write"} <= kinds


def test_opcua_continuation_sequence_gap_secure_opaque_and_bad_lengths():
    policy = "http://opcfoundation.org/UA/SecurityPolicy#None"
    service = nodeid(428) + request_header(1) + b"payload"
    first = opc_chunk("OPN", "F", struct.pack("<I", 1) + ua_string(policy) + ua_bytes(None) + ua_bytes(None)
                      + struct.pack("<II", 1, 1) + nodeid(999))
    c = opc_chunk("MSG", "C", struct.pack("<II", 1, 1) + struct.pack("<II", 4, 9) + service[:5])
    f = opc_chunk("MSG", "F", struct.pack("<II", 1, 1) + struct.pack("<II", 6, 9) + service[5:])
    report = app.analyze_opcua_stream(first + c + f)
    assert any(item["kind"] == "opcua-sequence-gap" for item in report["findings"])
    assert report["messages"][-1]["request_id"] == 9

    secure_policy = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
    secure = opc_chunk("OPN", "F", struct.pack("<I", 2) + ua_string(secure_policy)
                       + ua_bytes(b"certificate") + ua_bytes(b"thumb") + b"ciphertext")
    parsed = app.parse_opcua_chunk(secure)
    assert parsed["payload_decoded"] is False and "protected_payload" in parsed
    with pytest.raises(app.ParseError, match="header"):
        app.parse_opcua_chunk(b"HELF\x09\x00\x00\x00")


def mailbox(mailbox_type, payload):
    return struct.pack("<HHBB", len(payload), 0, 0, mailbox_type) + payload


def ethercat_frame(command, register, payload, *, wkc=1):
    datagram = (bytes([command, 1]) + struct.pack("<HH", 1, register)
                + struct.pack("<HH", len(payload), 0) + payload + struct.pack("<H", wkc))
    return struct.pack("<H", 0x1000 | len(datagram)) + datagram


def test_ethercat_coe_sdo_foe_state_and_wkc_findings():
    coe = struct.pack("<H", 0x2000) + b"\x23" + struct.pack("<H", 0x2000) + b"\x01" + b"\x78\x56\x34\x12"
    report = app.parse_ethercat_frame(ethercat_frame(5, 0x1000, mailbox(3, coe)))
    decoded = report["datagrams"][0]["mailbox"]["coe"]
    assert decoded["index"] == 0x2000 and decoded["subindex"] == 1 and decoded["value"] == "78563412"
    assert {item["kind"] for item in report["findings"]} >= {"ethercat-write", "ethercat-sdo-download"}

    foe = struct.pack("<HI", 2, 0x1234) + b"firmware.bin\0"
    report = app.parse_ethercat_frame(ethercat_frame(5, 0x1000, mailbox(4, foe), wkc=0))
    assert report["datagrams"][0]["mailbox"]["foe"]["filename"] == "firmware.bin"
    assert {"ethercat-foe-write", "ethercat-zero-wkc"} <= {item["kind"] for item in report["findings"]}

    state = app.parse_ethercat_frame(ethercat_frame(5, 0x0120, struct.pack("<H", 8)))
    assert state["datagrams"][0]["al_state"] == "OP"
    assert any(item["kind"] == "ethercat-state-write" for item in state["findings"])
    with pytest.raises(app.ParseError, match="length"):
        app.parse_ethercat_frame(state_to_corrupt := state and ethercat_frame(5, 0x0120, b"\x08\x00")[:-1])


def profinet_block(block_type, payload):
    return struct.pack(">HHBB", block_type, 2 + len(payload), 1, 0) + payload


def dce_request(stub, *, flags=3, call=7, opnum=5):
    body = struct.pack("<IHH", len(stub), 0, opnum) + stub
    header = b"\x05\x00\x00" + bytes([flags]) + b"\x10\x00\x00\x00"
    return header + struct.pack("<HHI", 16 + len(body), 0, call) + body


def test_profinet_dcerpc_record_alarm_blocks_and_fragment_reassembly():
    ar = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff").bytes
    payload = struct.pack(">H", 3) + ar + struct.pack(">IHHH", 0, 1, 2, 0) + struct.pack(">HI", 0xAFF0, 4) + b"DATA"
    block = profinet_block(0x0008, payload)
    report = app.analyze_profinet_rpc(dce_request(block))
    record = report["pdu"]["profinet_blocks"][0]["record"]
    assert record["index"] == 0xAFF0 and record["index_name"] == "I&M0"
    assert {"profinet-record-write", "profinet-rpc-no-integrity"} <= {item["kind"] for item in report["findings"]}

    alarm_payload = struct.pack(">HIHHIIH", 1, 0, 2, 3, 0x1111, 0x2222, 0x8005)
    alarm, end = app.parse_profinet_block(profinet_block(0x0010, alarm_payload))
    assert end == 6 + len(alarm_payload) and alarm["alarm"]["alarm_type_name"] == "Diagnosis"
    assert alarm["alarm"]["channel_diagnosis"] is True

    split = len(block) // 2
    completed = app.reassemble_dcerpc_fragments([
        dce_request(block[:split], flags=1, call=9), dce_request(block[split:], flags=2, call=9)])
    assert completed[0]["fragment_count"] == 2
    assert completed[0]["profinet_blocks"][0]["block_type"] == 0x0008
    with pytest.raises(app.ParseError, match="continuation"):
        app.reassemble_dcerpc_fragments([dce_request(b"x", flags=2)])
    truncated_payload = payload[:-3]
    with pytest.raises(app.ParseError, match="shorter"):
        app.parse_profinet_block(profinet_block(0x0008, truncated_payload))


def test_dnp3_secure_auth_objects_state_and_keyed_mac_verification():
    challenge_value = struct.pack("<IHB", 10, 7, 1) + b"\x00" + b"nonce"
    challenge_blob = b"\x78\x01\x5b\x01" + struct.pack("<H", len(challenge_value)) + challenge_value
    challenge = app.parse_dnp3_sa_free_format(challenge_blob)[0]
    assert challenge["variation_name"] == "Challenge" and challenge["mac_algorithm_name"] == "HMAC-SHA1-96"
    key, protected = b"supplied-test-key", b"exact authenticated bytes"
    mac = hmac.new(key, protected, "sha1").digest()[:12]
    reply = app.parse_dnp3_sa_object(2, struct.pack("<IH", 10, 7) + mac)
    state = app.DNP3SAState()
    state.feed(challenge)
    event = state.feed(reply, key=key, authenticated_data=protected)
    assert event["mac_verification"]["verified"] is True
    assert state.report()["pending_challenges"] == []

    missing = app.DNP3SAState()
    result = missing.feed(reply)
    assert result["mac_verification"]["verified"] is None
    assert "dnp3-sa-reply-without-challenge" in {item["kind"] for item in missing.report()["findings"]}
    short = app.DNP3SAState()
    short.feed(challenge)
    short.feed(app.parse_dnp3_sa_object(2, struct.pack("<IH", 10, 7) + b"short"))
    assert "dnp3-sa-mac-length" in {item["kind"] for item in short.report()["findings"]}
    invalid = app.verify_dnp3_sa_mac(key, 1, protected, b"\0" * 12)
    assert invalid["verified"] is False
    with pytest.raises(ValueError, match="key"):
        app.verify_dnp3_sa_mac(b"", 1, protected, mac)


def test_historian_csv_quality_flatline_gaps_and_alarm_lifecycle():
    csv_data = """timestamp,tag,value,quality,event,user
2026-01-01T00:00:00Z,Pump.Speed,10,Good,Alarm Active,alice
2026-01-01T00:00:01Z,Pump.Speed,10,Bad,,
2026-01-01T00:00:02Z,Pump.Speed,10,Good,,
2026-01-01T00:00:03Z,Pump.Speed,10,Good,,
2026-01-01T00:01:00Z,Pump.Speed,10,Good,Clear,bob
"""
    report = app.analyze_historian_csv(csv_data, name="history.csv")
    assert report["series"]["Pump.Speed"]["samples"] == 5
    assert report["alarms"]["Pump.Speed"]["activations"] == 1
    kinds = {item["kind"] for item in report["findings"]}
    assert {"historian-bad-quality", "historian-flatline", "historian-gap", "alarm-unacknowledged"} <= kinds
    quality_zero = app.analyze_historian_csv("time,tag,value,quality\n1,A,2,0\n")
    assert "historian-bad-quality" not in {item["kind"] for item in quality_zero["findings"]}
    two_bad = app.analyze_historian_csv("time,tag,value,quality\n1,A,2,Bad\n2,A,3,Bad\n")
    assert sum(item["kind"] == "historian-bad-quality" for item in two_bad["findings"]) == 2


def make_sqlite(path):
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE history(timestamp TEXT, tag TEXT, value REAL, quality TEXT)")
    connection.execute("INSERT INTO history VALUES('2026-01-01T00:00:00Z','Pump',1.5,'Good')")
    connection.execute("CREATE TABLE users(username TEXT, password TEXT, startup_script TEXT, token_blob BLOB)")
    connection.execute("INSERT INTO users VALUES('admin','plain-secret','powershell -enc AAA',?)", (b"binary-secret",))
    connection.commit()
    connection.close()


def test_sqlite_read_only_inventory_bytes_and_path(tmp_path):
    database = tmp_path / "historian.sqlite"
    make_sqlite(database)
    by_path = app.analyze_historian_sqlite_path(database)
    assert {table["name"] for table in by_path["tables"]} == {"history", "users"}
    assert next(table for table in by_path["tables"] if table["name"] == "history")["historian_candidate"] is True
    kinds = {item["kind"] for item in by_path["findings"]}
    assert {"hmi-sqlite-literal-secret", "hmi-embedded-script"} <= kinds
    by_bytes = app.analyze_historian_sqlite_bytes(database.read_bytes(), name="copy.sqlite")
    assert by_bytes["table_count"] == 2
    blob_finding = next(item for item in by_path["findings"]
                        if item["kind"] == "hmi-sqlite-literal-secret" and item["column"] == "token_blob")
    assert blob_finding["value"]["sha256"] == hashlib.sha256(b"binary-secret").hexdigest()


def zip_bytes(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, body in entries.items():
            archive.writestr(name, body)
    return stream.getvalue()


def test_hmi_project_zip_embedded_csv_scripts_endpoints_and_path_guard():
    archive = zip_bytes({
        "config/project.xml": b'<Connection endpoint="opc.tcp://10.0.0.5:4840" password="factory-secret"/>',
        "scripts/startup.ps1": b"powershell -File run.ps1",
        "history.csv": b"timestamp,tag,value\n2026-01-01T00:00:00Z,Tank.Level,5\n",
    })
    report = app.analyze_hmi_project(archive, name="hmi.zip")
    assert report["format"] == "hmi-project-zip" and len(report["files"]) == 3
    kinds = {item["kind"] for item in report["findings"]}
    assert {"hmi-project-literal-secret", "hmi-embedded-script"} <= kinds
    assert any(item["analysis"].get("endpoints") == ["opc.tcp://10.0.0.5:4840"]
               for item in report["embedded_analyses"] if "analysis" in item)
    evil = zip_bytes({"../escape.txt": b"x"})
    with pytest.raises(app.ParseError, match="unsafe"):
        app.analyze_hmi_project(evil)


def test_dispatch_bounds_and_malformed_inputs(monkeypatch):
    csv_data = b"time,tag,value\n1,A,2\n"
    assert app.analyze_ics_application(csv_data, kind="csv")["format"] == "historian-csv"
    with pytest.raises(ValueError):
        app.analyze_ics_application(b"x", kind="unknown")
    with pytest.raises(app.ParseError):
        app.parse_ethercat_mailbox(b"\x00")
    with pytest.raises(app.ParseError):
        app.parse_dcerpc_pdu(b"\x05")
    with pytest.raises(app.ParseError):
        app.parse_dnp3_sa_free_format(b"\x78\x01\x5b\x01\xff")
    monkeypatch.setattr(app, "MAX_INPUT", 8)
    with pytest.raises(app.ParseError, match="cap"):
        app.analyze_ics_application(b"A" * 100, kind="opcua")


def test_protocol_parsers_fail_cleanly_on_deterministic_malformed_inputs():
    parsers = [app.parse_opcua_chunk, app.parse_ethercat_frame, app.parse_dcerpc_pdu,
               app.parse_dnp3_sa_free_format]
    for parser_index, parser in enumerate(parsers):
        for length in range(65):
            data = bytes((position * 29 + length * 17 + parser_index * 13) & 0xFF for position in range(length))
            try:
                parser(data)
            except (app.ParseError, ValueError, TypeError):
                pass


def test_dnp3_sa_state_event_bound(monkeypatch):
    state = app.DNP3SAState()
    event = app.parse_dnp3_sa_object(4, b"\x01\x00")
    monkeypatch.setattr(app, "MAX_ITEMS", 1)
    state.feed(event)
    with pytest.raises(app.ParseError, match="cap"):
        state.feed(event)
