"""B-078: the DICOM/SNMP timeline-forensics engine (solvers/toolkits/dicom_snmp_timeline.py) and the
DIMSE reader it adds to healthcare.py.

Every handout is synthetic (tests/b078_fixtures.py builds the PDUs, the BER traps and the capture by
hand from PS3.7/PS3.8 and RFC 3416); no challenge file is read. Nothing here opens a socket or submits.
The expected flag is computed by the fixture with hashlib, independently of the engine."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
for _p in (REPO / "solvers" / "toolkits", REPO / "tests"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import b078_fixtures as fx                    # noqa: E402
import dicom_snmp_timeline as E               # noqa: E402
import healthcare as H                        # noqa: E402

OPENING = "2026-03-01T00:00:00Z"              # the log's first event: what incident chronology ranks first
BOOT = "2026-03-01T00:00:01Z"                 # the one-off boot report, written out of order
FIRST_ANOMALY = "2026-03-01T03:15:00Z"        # the first [ANOMALY] line (the tag the engine must not trust)
LAST_ANOMALY = "2026-03-04T03:15:00Z"


def profile(prefixes=("CSCTF",), stop=3, budget=2):
    return types.SimpleNamespace(flag=types.SimpleNamespace(prefixes=tuple(prefixes)),
                                 rules=types.SimpleNamespace(wrong_answer_stop=stop, guess_budget=budget,
                                                             submit_mode="manual"))


def flag(digest):
    return f"CSCTF{{{digest}}}"


# ============================================================ healthcare.py: the DIMSE reader

def test_parse_dimse_command_reads_the_command_set():
    m = H.parse_dimse_command(fx.command_set(0x0001, 7, fx.STORE_SOP, True))
    assert m["command"] == "C-STORE-RQ" and m["command_field"] == H.C_STORE_RQ == 1
    assert m["message_id"] == 7
    assert m["affected_sop_class_uid"] == fx.STORE_SOP
    assert m["has_dataset"] is True and m["dataset_bytes"] == 0
    echo = H.parse_dimse_command(fx.command_set(0x0030, 3, fx.ECHO_SOP, False))
    assert echo["command"] == "C-ECHO-RQ" and echo["has_dataset"] is False
    rsp = H.parse_dimse_command(fx.command_set(0x8001, 3, fx.STORE_SOP, False))
    assert rsp["command"] == "C-STORE-RSP"
    odd = H.parse_dimse_command(fx.command_set(0x0777, 3, fx.STORE_SOP, False))
    assert odd["command"] == "0x0777"


def test_parse_dimse_command_refuses_what_is_not_a_command_set():
    good = fx.command_set(0x0001, 7, fx.STORE_SOP, True)
    assert H.parse_dimse_command(good[:-1]) is None                      # length overruns
    other_group = struct.pack("<HHI", 0x0008, 0x0100, 2) + b"\x01\x00"
    assert H.parse_dimse_command(other_group) is None                   # element outside group 0000
    no_field = fx._el(0x0110, struct.pack("<H", 1))
    assert H.parse_dimse_command(no_field) is None                      # no CommandField
    wide_field = fx._el(0x0100, struct.pack("<I", 1))
    assert H.parse_dimse_command(wide_field) is None                    # CommandField not 2 bytes
    assert H.parse_dimse_command(good + b"\x00\x00") is None            # trailing bytes that are no element


def test_dicom_pdvs_reads_control_bits_and_refuses_a_bad_body():
    body = fx.pdv(1, True, True, b"CMD!") + fx.pdv(3, False, False, b"data")
    assert H.dicom_pdvs(body) == [(1, True, True, b"CMD!"), (3, False, False, b"data")]
    assert H.dicom_pdvs(body[:-1]) is None                              # items do not tile the body
    bad = struct.pack(">IBB", 6, 1, 0x04) + b"abcd"                     # a reserved control bit set
    assert H.dicom_pdvs(bad) is None
    assert H.dicom_pdvs(b"") is None


def test_dicom_ul_pdus_walks_whole_pdus_and_stops_at_garbage():
    run = fx.associate_rq() + fx.echo_message(1) + bytes.fromhex("050000000004") + b"\x00" * 4
    pdus, consumed = H.dicom_ul_pdus(run + b"GARBAGE!")
    assert [p["name"] for p in pdus] == ["A-ASSOCIATE-RQ", "P-DATA-TF", "A-RELEASE-RQ"]
    assert consumed == len(run)
    # a release with a body length other than 4 is not a PDU: the walk stops before it
    pdus, consumed = H.dicom_ul_pdus(fx.echo_message(1) + bytes.fromhex("050000000005") + b"\x00" * 5)
    assert [p["name"] for p in pdus] == ["P-DATA-TF"]
    # a cut body is not counted
    pdus, consumed = H.dicom_ul_pdus(fx.echo_message(1)[:-1])
    assert pdus == [] and consumed == 0
    # a nonzero reserved byte is not a header
    assert H.dicom_ul_pdus(b"\x04\x01" + fx.echo_message(1)[2:])[0] == []


def test_dimse_messages_counts_c_store_and_their_data_sets():
    run = (fx.associate_rq() + fx.store_message(2, b"\xaa" * 300) + fx.echo_message(9)
           + fx.store_message(3, b"\xbb" * 50) + fx.store_message(4, b"\xcc" * 7))
    got = H.dicom_dimse_messages(run)
    assert got["complete"] is True and got["consumed"] == len(run)
    assert got["pdus"] == {"A-ASSOCIATE-RQ": 1, "P-DATA-TF": 4}
    cmds = [(m["command"], m["message_id"], m["dataset_bytes"]) for m in got["messages"]]
    assert cmds == [("C-STORE-RQ", 2, 300), ("C-ECHO-RQ", 9, 0), ("C-STORE-RQ", 3, 50), ("C-STORE-RQ", 4, 7)]
    assert sum(1 for m in got["messages"] if m["command_field"] == H.C_STORE_RQ) == 3
    assert not H.dicom_dimse_messages(run + b"\x09")["complete"]


def test_dimse_command_split_over_pdus_and_contexts_is_joined():
    cmd = fx.command_set(0x0001, 11, fx.STORE_SOP, True)
    part1, part2 = cmd[:10], cmd[10:]
    run = (fx.pdata(fx.pdv(1, True, False, part1))                      # command, not last
           + fx.pdata(fx.pdv(3, True, True, fx.command_set(0x0030, 5, fx.ECHO_SOP, False)),
                      fx.pdv(1, True, True, part2))                     # context 1 completes here
           + fx.pdata(fx.pdv(1, False, False, b"x" * 40), fx.pdv(3, False, True, b"y" * 4))
           + fx.pdata(fx.pdv(1, False, True, b"z" * 60)))
    got = H.dicom_dimse_messages(run)
    by_id = {m["message_id"]: m for m in got["messages"]}
    assert set(by_id) == {11, 5}
    assert by_id[11]["command"] == "C-STORE-RQ" and by_id[11]["context_id"] == 1
    assert by_id[11]["dataset_bytes"] == 100                            # both fragments on context 1
    assert by_id[5]["dataset_bytes"] == 4                               # context 3's fragment is its own
    # the message offset is that of the PDU that completed the command set (the second PDU)
    assert by_id[11]["offset"] == len(fx.pdata(fx.pdv(1, True, False, part1)))


def test_flow_dimse_reads_each_segment_when_segments_end_on_pdu_boundaries():
    seg = fx.store_message(2, b"\x01" * 20)
    got = H.dicom_flow_dimse([seg, seg, seg, fx.echo_message(1)], stream=seg)  # repeats: a constant-seq capture
    assert got["framing"] == "segment"
    assert [m["command"] for m in got["messages"]] == ["C-STORE-RQ"] * 3 + ["C-ECHO-RQ"]
    assert [m["segment"] for m in got["messages"]] == [0, 1, 2, 3]


def test_flow_dimse_falls_back_to_the_stream_when_a_pdu_spans_segments():
    msg = fx.store_message(2, b"\x01" * 20)
    segs = [msg[:15], msg[15:]]
    got = H.dicom_flow_dimse(segs, stream=msg + fx.echo_message(4))
    assert got["framing"] == "stream"
    assert [m["command"] for m in got["messages"]] == ["C-STORE-RQ", "C-ECHO-RQ"]
    assert all(m["segment"] is None for m in got["messages"])
    assert H.dicom_flow_dimse(segs)["framing"] is None                  # no stream given: nothing read
    assert H.dicom_flow_dimse([b"HTTP/1.1 200 OK\r\n\r\n"], stream=b"HTTP/1.1")["messages"] == []


@pytest.mark.needs_tool("py:scapy")
def test_healthcare_pcap_reports_dimse_per_flow(tmp_path):
    cap = tmp_path / "ward.pcap"
    cap.write_bytes(fx.capture(echo=4, internal_store=2, outside_store=3))
    rep = H.parse_pcap(str(cap))
    dimse = [f for f in rep["findings"] if f.get("kind") == "dicom-dimse"]
    by_flow = {f["flow"]: f for f in dimse}
    outside = [f for flow, f in by_flow.items() if fx.OUTSIDE in flow]
    assert len(outside) == 1
    assert outside[0]["c_store_rq"] == 3 and outside[0]["framing"] == "segment"
    assert outside[0]["message_ids"] == [2, 3, 4]
    assert sum(f["c_store_rq"] for f in dimse) == 5
    assert sum(f["commands"].get("C-ECHO-RQ", 0) for f in dimse) == 4
    assert any("C-STORE-RQ: 3" in line for line in H._render_pcap(rep, False))


# ============================================================ the engine's pieces

def test_is_internal_and_classify():
    assert E.is_internal("10.9.30.45") is True and E.is_internal("192.168.1.1") is True
    assert E.is_internal(fx.OUTSIDE) is False and E.is_internal("8.8.8.8") is False
    assert E.is_internal("core-router") is None
    assert E.classify("x.pcap", fx.capture(echo=1, internal_store=0, outside_store=0, traps=0)) == "capture"
    assert E.classify("d.xml", fx.device_xml().encode()) == "xml"
    assert E.classify("r.csv", fx.records_csv().encode()) == "csv"
    assert E.classify("snmp_trap.log", fx.trap_log().encode()) == "log"
    assert E.classify("x.bin", b"\x00\x01\xff\xfe") == "blob"
    assert E.classify("notes.txt", b"hello there\nno stamps here\n") == "text"


def test_read_xml_fields_and_device_facts():
    fields = E.read_xml_fields(fx.device_xml())
    by_tag = {f["tag"]: f for f in fields}
    assert by_tag["serial_number"]["value"] == fx.SERIAL
    assert by_tag["serial_number"]["path"] == "/dicom_device/identity/serial_number"
    facts = E.device_facts(fields)
    assert list(facts["scp_hosts"]) == [fx.SCP]
    assert facts["max_payload"]["bytes"] == fx.MAX_PAYLOAD
    attr = E.read_xml_fields("<d><unit serial='A-1'/></d>")
    assert attr == [{"path": "/d/unit/@serial", "tag": "serial", "value": "A-1"}]
    with pytest.raises(E.ForensicsError, match="DOCTYPE"):
        E.read_xml_fields('<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x "y">]><d>&x;</d>')
    with pytest.raises(E.ForensicsError, match="well-formed"):
        E.read_xml_fields("<d><e></d>")


def test_parse_log_reads_source_trap_fields_and_marker():
    log = E.parse_log(fx.trap_log(anomaly_days=2), "snmp_trap.log")
    assert log["unparsed"] == 0
    anomalies = [e for e in log["events"] if e["marked"]]
    assert len(anomalies) == 2 and all(e["source"] == fx.OUTSIDE for e in anomalies)
    assert anomalies[0]["trap"] == "SNMP GetBulk"
    assert "ANOMALY: Unusual polling frequency" in anomalies[0]["tags"]
    boot = next(e for e in log["events"] if e["trap"] == "deviceBootReport")
    assert boot["kv"]["DeviceManifestSeed"] == fx.SEED and boot["kv"]["Serial"] == fx.SERIAL
    assert boot["line"] == len(log["events"]) and E._iso(boot["ts"]) == BOOT
    # two lines of one series differ only in their timestamp
    link = [e for e in log["events"] if e["source"] == "10.9.30.1"]
    assert len({e["series"] for e in link}) == 1 and len(link) == 8
    plain = E.parse_log("2026-03-01T00:00:00Z routine poll ok\nnot a stamp\n")
    assert plain["unparsed"] == 1 and plain["events"][0]["marked"] is False


def _events(text):
    return E.parse_log(text, "snmp_trap.log")["events"]


def test_timestamp_candidates_rank_by_chronology_not_the_anomaly_tag():
    ranked = E.timestamp_candidates(_events(fx.trap_log()))
    values = [c["value"] for c in ranked]
    assert values[:4] == [OPENING, BOOT, FIRST_ANOMALY, LAST_ANOMALY]
    assert [c["rank"] for c in ranked] == list(range(1, len(ranked) + 1))
    assert ranked[0]["position"] == "first" and "opening" in ranked[0]["reasons"][0]
    assert any(r.startswith("out-of-order") for r in ranked[1]["reasons"])
    assert any(r.startswith("one-off") for r in ranked[1]["reasons"])
    assert any(r.startswith("outside-source") for r in ranked[2]["reasons"])
    # the middle anomaly repeats are in the set but last
    assert set(values[4:]) == {"2026-03-02T03:15:00Z", "2026-03-03T03:15:00Z"}
    assert all(c["position"] == "middle" for c in ranked[4:])
    # routine repeats (linkDown every 6 h) are not candidates, only the opening one
    assert "2026-03-01T06:00:00Z" not in values


def test_a_marker_never_raises_a_rank():
    unmarked = fx.trap_log(marker="")
    marked = fx.trap_log()
    a = [c["value"] for c in E.timestamp_candidates(_events(marked))]
    b = [c["value"] for c in E.timestamp_candidates(_events(unmarked))]
    assert a[:2] == b[:2] == [OPENING, BOOT]
    # unmarked, the repeated GetBulk lines are no anomaly: only the first (an outside source) is in
    assert FIRST_ANOMALY in b and LAST_ANOMALY not in b
    # a marked line that occurs once, late, still ranks after the opening event
    late = marked + "2026-03-09T10:00:00Z SNMPTRAP v2c from 10.9.30.2: Trap: configChange [ANOMALY: tamper]\n"
    c = E.timestamp_candidates(_events(late))
    assert c[0]["value"] == OPENING
    lone = next(x for x in c if x["value"] == "2026-03-09T10:00:00Z")
    assert lone["position"] == "only" and lone["rank"] > 1


def test_timestamp_candidates_anchor_and_rare_limit():
    events = _events(fx.trap_log(anomaly_days=2))
    anchor = dt.datetime(2026, 3, 1, 4, 0, tzinfo=dt.timezone.utc)
    ranked = E.timestamp_candidates(events, anchor)
    by = {c["value"]: c for c in ranked}
    assert any(r.startswith("before-anchor") for r in by[FIRST_ANOMALY]["reasons"])
    after = next(c for c in ranked if any(r.startswith("after-anchor") for r in c["reasons"]))
    assert after["value"] == "2026-03-01T06:00:00Z"
    assert by[OPENING]["relation"] == "before" and after["relation"] == "after"
    # more one-off lines than MAX_RARE is no signal: none is called one-off
    many = "\n".join(f"2026-03-01T00:{i:02d}:00Z host{i} event kind {i}" for i in range(E.MAX_RARE + 3))
    ranked = E.timestamp_candidates(_events(many))
    assert [c["value"] for c in ranked] == ["2026-03-01T00:00:00Z"]
    assert E.timestamp_candidates([]) == []


def test_a_log_event_at_the_anchor_is_both_before_and_after_it():
    # The first anomalous DICOM operation and a log line share one timestamp: that line is the last
    # event at-or-before the anchor and the first at-or-after it, and it counts as "before".
    events = _events(fx.trap_log(anomaly_days=2))
    anchor = dt.datetime(2026, 3, 1, 3, 15, tzinfo=dt.timezone.utc)          # == FIRST_ANOMALY
    by = {c["value"]: c for c in E.timestamp_candidates(events, anchor)}
    reasons = by[FIRST_ANOMALY]["reasons"]
    assert any(r.startswith("before-anchor") for r in reasons)
    assert any(r.startswith("after-anchor") for r in reasons)
    assert by[FIRST_ANOMALY]["relation"] == "before"
    assert not any(r.startswith("before-anchor") for v, c in by.items() if v != FIRST_ANOMALY
                   for r in c["reasons"])


def _op(dst, size, command="C-STORE-RQ", ts=1):
    return {"command": command, "dst": dst, "dataset_bytes": size, "ts": ts}


def test_anomaly_counts_lists_each_definition_and_ranks_agreement():
    facts = {"scp_hosts": {fx.SCP: "/x"}, "max_payload": {"bytes": 100, "path": "/y"}}
    ops = ([_op(fx.OUTSIDE, 50, ts=5)] * 3 + [_op("10.1.1.1", 500, ts=2)] * 2 + [_op(fx.SCP, 10, ts=1)]
           + [_op(fx.SCP, 10, command="C-ECHO-RQ")] * 4)
    got = E.anomaly_counts(ops, facts)
    defs = {d["name"]: d["count"] for d in got["definitions"]}
    assert defs == {"external": 3, "off-scp": 5, "oversized": 2}
    assert got["total"] == 6
    assert [c["value"] for c in got["candidates"]] == ["3", "5", "2", "6"]
    assert got["candidates"][-1].get("fallback") is True
    assert got["anchor"] == 2
    # two definitions agreeing on one count rank it first
    agree = E.anomaly_counts([_op(fx.OUTSIDE, 500)] * 4 + [_op(fx.SCP, 10)], facts)
    assert agree["candidates"][0]["value"] == "4" and len(agree["candidates"][0]["reasons"]) == 3
    # no device facts: only the outside-address definition
    bare = E.anomaly_counts([_op(fx.OUTSIDE, 1)] * 2 + [_op(fx.SCP, 1)], {})
    assert [d["name"] for d in bare["definitions"]] == ["external"]
    assert [c["value"] for c in bare["candidates"]] == ["2", "3"]
    # the total agrees with a definition: one candidate, both reasons, no catch-all
    all_out = E.anomaly_counts([_op(fx.OUTSIDE, 1)] * 2, {})
    assert len(all_out["candidates"]) == 1 and "fallback" not in all_out["candidates"][0]
    assert len(all_out["candidates"][0]["reasons"]) == 2


def test_a_shared_count_outranks_a_lone_count_found_first():
    # The first definition (external) yields a lone count; two later ones (off-scp, oversized)
    # agree on another. Agreement wins over definition order; the plain total stays last.
    facts = {"scp_hosts": {fx.SCP: "/x"}, "max_payload": {"bytes": 100, "path": "/y"}}
    ops = [_op(fx.OUTSIDE, 10)] + [_op("10.1.1.1", 10)] * 2 + [_op(fx.SCP, 500)] * 3
    got = E.anomaly_counts(ops, facts)
    assert {d["name"]: d["count"] for d in got["definitions"]} == {"external": 1, "off-scp": 3, "oversized": 3}
    assert [c["value"] for c in got["candidates"]] == ["3", "1", "6"]
    assert len(got["candidates"][0]["reasons"]) == 2
    assert got["candidates"][-1].get("fallback") is True


def test_oversized_means_larger_than_the_limit_not_equal_to_it():
    facts = {"scp_hosts": {fx.SCP: "/x"}, "max_payload": {"bytes": 100, "path": "/y"}}
    got = E.anomaly_counts([_op(fx.SCP, 99), _op(fx.SCP, 100), _op(fx.SCP, 101), _op(fx.SCP, 101)], facts)
    defs = {d["name"]: d["count"] for d in got["definitions"]}
    assert defs["oversized"] == 2                                       # 101 twice; 100 (the limit) fits


def test_xor_decode_finds_the_serial_key_and_links_it():
    blob = fx.xor(fx.exfil_plain(), fx.SERIAL.encode())
    keys = [("model", "SynthScan"), ("serial", fx.SERIAL), ("scp", fx.SCP)]
    rows = E.xor_decode(blob, keys, known=[fx.OUTSIDE, fx.SCP])
    assert rows[0]["key"] == fx.SERIAL and rows[0]["decodes"] is True
    assert "ward_exfil_dump" in rows[0]["strings"] and rows[0]["links"] == [fx.OUTSIDE]
    assert all(not r["decodes"] for r in rows[1:])
    assert E.xor_bytes(E.xor_bytes(b"abc", b"k"), b"k") == b"abc"
    with pytest.raises(E.ForensicsError):
        E.xor_bytes(b"abc", b"")
    noise = bytes((i * 151 + 7) % 256 for i in range(64))
    assert not any(r["decodes"] for r in E.xor_decode(noise, keys))


def test_xor_decode_does_not_decode_a_blob_that_is_already_text():
    # Lower-case letters XOR digits land in 0x40-0x5f: the "plaintext" is printable under every key,
    # so only "reads better than the raw blob" keeps an already-printable blob from corroborating
    # a random device string.
    blob = b"plainasciitextwithoutanyspacesornumbersatallinthiswholeblob"
    keys = [("seed", "5150"), ("pin", "7731"), ("code", "0042")]
    rows = E.xor_decode(blob, keys)
    assert len(rows) == 3
    assert all(r["score"] >= E.XOR_TEXT_SCORE for r in rows)          # the score half alone would pass
    assert E.text_score(blob) == 1.0
    assert not any(r["decodes"] for r in rows)


def _ev(xml_fields, log_kv, exfil_best=()):
    return {"xml": [{"name": "files/device.xml", "fields": [{"path": f"/d/{t}", "tag": t, "value": v}
                                                           for t, v in xml_fields]}],
            "logs": [{"name": "files/trap.log", "events": [{"line": n + 1, "kv": kv}
                                                           for n, kv in enumerate(log_kv)]}],
            "exfil_best": list(exfil_best)}


def test_value_candidates_rank_a_value_xml_and_log_agree_on_first():
    # The XML-only decoy comes first in the document and matches as many words; only the
    # cross-file agreement can put the seed the boot report repeats above it.
    ev = _ev([("DeviceManifestSeed", "9999"), ("ManifestSeed", fx.SEED)],
             [{"Status": "ok"}, {"DeviceManifestSeed": fx.SEED}])
    got = E.value_candidates("manifest_seed", ev)
    assert [c["value"] for c in got] == [fx.SEED, "9999"]
    assert "agrees across 2 files" in got[0]["reasons"]
    assert not any("agrees" in r for r in got[1]["reasons"])
    # one file holding the value twice is no agreement: document order stands
    same = _ev([("DeviceManifestSeed", "9999"), ("ManifestSeed", fx.SEED), ("SeedManifest", fx.SEED)], [])
    assert [c["value"] for c in E.value_candidates("manifest_seed", same)] == ["9999", fx.SEED]


def test_value_candidates_rank_the_xor_key_above_a_decoy_serial():
    ev = _ev([("serial", "DECOY-0001"), ("serial_number", fx.SERIAL)], [],
             exfil_best=[{"key": fx.SERIAL, "links": [fx.OUTSIDE], "blob": "files/exfil.bin"}])
    got = E.value_candidates("dicom_serial", ev)
    assert [c["value"] for c in got] == [fx.SERIAL, "DECOY-0001"]
    assert any(r.startswith("XOR key of files/exfil.bin") and fx.OUTSIDE in r for r in got[0]["reasons"])
    no_key = _ev([("serial", "DECOY-0001"), ("serial_number", fx.SERIAL)], [])
    assert [c["value"] for c in E.value_candidates("dicom_serial", no_key)] == ["DECOY-0001", fx.SERIAL]


def test_solve_ranks_the_agreeing_seed_and_the_xor_key_first(tmp_path):
    # End to end: the device XML lists a decoy seed and a decoy serial before the real ones.
    xml = fx.device_xml().replace(
        "<identity>", "<identity>\n    <serial>DECOY-0001</serial>").replace(
        "<calibration>", "<calibration><DeviceManifestSeed>9999</DeviceManifestSeed>")
    root = fx.handout(tmp_path / "ward", files={"dicom_device.xml": xml})
    report = E.analyze(root, profile())
    seeds = [c["value"] for c in report["fields"]["manifest_seed"]["candidates"]]
    serials = [c["value"] for c in report["fields"]["dicom_serial"]["candidates"]]
    assert seeds[:2] == [fx.SEED, "9999"]
    assert serials[:2] == [fx.SERIAL, "DECOY-0001"]
    assert report["candidates"][0]["flag"] == flag(fx.expected_digest(OPENING))


def test_parse_recipe_and_render():
    r = E.parse_recipe(fx.brief())
    assert r["algo"] == "sha256" and r["take"] == 8 and r["upper"] is False
    assert r["fields"] == ["dicom_serial", "snmp_iso_timestamp", "leak_count", "anomaly_count", "manifest_seed"]
    assert r["about"]["leak_count"] == "number of leaked patient records."
    values = {"dicom_serial": "S", "snmp_iso_timestamp": "T", "leak_count": "1", "anomaly_count": "2",
              "manifest_seed": "3"}
    pre, digest = E.render(r, values)
    assert pre == "S:T:1:2:3" and digest == hashlib.sha256(b"S:T:1:2:3").hexdigest()[:8]
    up = E.parse_recipe("flag = md5(\"<a>-<b>\"), first 6 uppercase hex characters")
    assert up["algo"] == "md5" and up["take"] == 6 and up["upper"] is True
    assert E.render(up, {"a": "x", "b": "y"})[1] == hashlib.md5(b"x-y").hexdigest()[:6].upper()
    bare = E.parse_recipe("submit sha1(serial:count)")
    assert bare["fields"] == ["serial", "count"] and bare["template"] == "<serial>:<count>"
    assert bare["take"] is None
    assert E.render(bare, {"serial": "a", "count": "b"})[1] == hashlib.sha1(b"a:b").hexdigest()
    assert E.parse_recipe("sha3_256(\"<a><b>\")")["algo"] == "sha3_256"
    assert E.parse_recipe("no recipe here, just sha256 talk") is None
    with pytest.raises(E.ForensicsError, match="keeps 40"):
        E.parse_recipe('md5("<a>:<b>")[:40]')


def test_field_kind():
    assert E.field_kind("snmp_iso_timestamp") == "time"
    assert E.field_kind("eventTime") == "time"
    assert E.field_kind("leak_count") == "count"
    assert E.field_kind("leaked", "the number of leaked rows") == "count"
    assert E.field_kind("dicom_serial") == "value"


def test_rank_combinations_puts_catch_alls_last_and_dedupes():
    recipe = E.parse_recipe('sha256("<a>:<b>")[:8]')
    fields = {"a": {"candidates": [{"value": "1"}, {"value": "9", "fallback": True}]},
              "b": {"candidates": [{"value": "x"}, {"value": "y"}, {"value": "z"}]}}
    rows, total = E.rank_combinations(recipe, fields, 100)
    assert total == 6
    assert [r["preimage"] for r in rows] == ["1:x", "1:y", "1:z", "9:x", "9:y", "9:z"]
    assert rows[0]["digest"] == hashlib.sha256(b"1:x").hexdigest()[:8]
    assert [r["rank"] for r in rows] == [1, 2, 3, 4, 5, 6]
    # each row names the 1-based rank of the candidate it took from every field
    assert [r["ranks"] for r in rows] == [[1, 1], [1, 2], [1, 3], [2, 1], [2, 2], [2, 3]]
    assert len(E.rank_combinations(recipe, fields, 2)[0]) == 2
    dup = {"a": {"candidates": [{"value": "1"}, {"value": "1"}]}, "b": {"candidates": [{"value": "x"}]}}
    assert E.rank_combinations(recipe, dup, 10)[1] == 1
    empty = {"a": {"candidates": []}, "b": {"candidates": [{"value": "x"}]}}
    assert E.rank_combinations(recipe, empty, 10) == ([], 0)


def test_rank_combinations_caps_the_product(monkeypatch):
    monkeypatch.setattr(E, "MAX_COMBOS", 6)
    recipe = E.parse_recipe('sha256("<a>:<b>")')
    fields = {"a": {"candidates": [{"value": str(i)} for i in range(5)]},
              "b": {"candidates": [{"value": c} for c in "xyz"]}}
    rows, total = E.rank_combinations(recipe, fields, 100)
    assert total == 6                                                    # 5x3 cut to 2x3: longest first
    assert {r["values"]["a"] for r in rows} == {"0", "1"}


def test_flag_prefix_follows_the_brief():
    p = profile(prefixes=("CSCTF", "flag"))
    assert E.flag_prefix(p, "format flag{...}") == "flag"
    assert E.flag_prefix(p, "Flag format: CSCTF{8_hex} (not flag{})") == "CSCTF"
    assert E.flag_prefix(p, "") == "CSCTF"
    assert E.flag_prefix(profile(prefixes=()), "CSCTF{x}") is None
    assert E.flag_prefix(None) is None


# ============================================================ the engine end to end

@pytest.fixture
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("the engine opened a network connection")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def test_solve_ranks_the_chronological_flag_first(tmp_path, no_network):
    root = fx.handout(tmp_path / "ward")
    res = E.solve(root, profile())
    assert res.status == "candidate"
    expected = flag(fx.expected_digest(OPENING))
    assert res.flags[0] == expected
    assert res.flags[1] == flag(fx.expected_digest(BOOT))
    first_anomaly = flag(fx.expected_digest(FIRST_ANOMALY))
    assert first_anomaly in res.flags and res.flags.index(first_anomaly) == 2
    assert res.flags.index(flag(fx.expected_digest(LAST_ANOMALY))) == 3
    # the catch-all counts (every CSV row, every C-STORE) rank behind every evidence-backed combination
    catch_all = flag(fx.expected_digest(OPENING, leak=10, anomaly=7))
    assert res.flags.index(catch_all) > res.flags.index(flag(fx.expected_digest(
        "2026-03-03T03:15:00Z")))
    assert len(res.flags) == len(set(res.flags)) == E.DEFAULT_MAX_CANDIDATES
    out = root / "recon" / "dicom_snmp_timeline"
    assert (out / "candidates.txt").read_text().split() == list(res.flags)
    report = json.loads((out / "report.json").read_text())
    assert report["fields"]["dicom_serial"]["candidates"][0]["value"] == fx.SERIAL
    assert report["fields"]["manifest_seed"]["candidates"][0]["value"] == fx.SEED
    assert [c["value"] for c in report["fields"]["leak_count"]["candidates"]] == ["7", "10"]
    assert [c["value"] for c in report["fields"]["anomaly_count"]["candidates"]] == ["5", "7"]
    assert report["dicom"]["commands"] == {"C-ECHO-RQ": 6, "C-STORE-RQ": 7}
    assert report["snmp"]["capture_messages"] == 3
    assert report["snmp"]["communities"] == {"ward_mgmt_community": 3}
    assert report["exfil"][0]["decodes"][0]["key"] == fx.SERIAL
    assert report["candidates"][0]["preimage"] == f"{fx.SERIAL}:{OPENING}:7:5:{fx.SEED}"
    assert "| " + OPENING in (out / "timeline.md").read_text()
    # the event's rules are quoted, nothing is sent
    assert "Not submitted" in res.notes and "3 wrong answers" in res.notes and "2 logged guesses" in res.notes
    serial_ev = [e for e in res.evidence if e.kind == "decode"]
    assert serial_ev and fx.SERIAL in serial_ev[0].detail


def test_solve_counts_the_same_with_reassemblable_sequence_numbers(tmp_path):
    root = fx.handout(tmp_path / "ward", cap=fx.capture(constant_seq=False))
    res = E.solve(root, profile(), out="none")
    assert res.flags[0] == flag(fx.expected_digest(OPENING))
    assert not (root / "recon").exists()                                 # out=none writes nothing


def test_solve_counts_follow_the_capture(tmp_path):
    root = fx.handout(tmp_path / "ward", cap=fx.capture(outside_store=9, internal_store=1))
    res = E.solve(root, profile(), out="none")
    assert res.flags[0] == flag(fx.expected_digest(OPENING, anomaly=9))


def test_timeline_merges_log_and_capture_in_order(tmp_path):
    root = fx.handout(tmp_path / "ward")
    report = E.analyze(root, profile())
    rows = report["timeline"]
    firsts = [r["first"] for r in rows]
    assert firsts == sorted(firsts)
    stores = [r for r in rows if r["action"] == "C-STORE-RQ" and "(outside)" in r["what"]]
    assert len(stores) == 1 and stores[0]["count"] == 5                  # a run is folded into one row
    assert stores[0]["first"] == "2026-03-01T00:01:50Z" and stores[0]["last"] == "2026-03-01T00:02:50Z"
    assert any(r["action"].startswith("snmp") for r in rows)
    assert any(r["action"] == "deviceBootReport" for r in rows)


def test_solve_without_a_recipe_lists_facts_and_timestamps(tmp_path):
    root = fx.handout(tmp_path / "ward", description="A device leaked records. Find out when.")
    res = E.solve(root, profile(), out="none")
    assert res.status == "unsure" and res.flags == ()
    assert f"chronology: {OPENING}, {BOOT}, {FIRST_ANOMALY}" in res.notes
    # the recipe option supplies what the brief lacks
    res = E.solve(root, profile(), out="none", recipe=fx.RECIPE)
    assert res.status == "candidate" and res.flags[0] == flag(fx.expected_digest(OPENING))


def test_pinned_fields_replace_the_evidence(tmp_path):
    root = fx.handout(tmp_path / "ward")
    res = E.solve(root, profile(), out="none", field_anomaly_count="11|5",
                  **{"field.snmp_iso_timestamp": FIRST_ANOMALY})
    assert res.flags[0] == flag(fx.expected_digest(FIRST_ANOMALY, anomaly=11))
    assert res.flags[1] == flag(fx.expected_digest(FIRST_ANOMALY, anomaly=5))


def test_bad_options_are_blocked_never_ignored(tmp_path):
    root = fx.handout(tmp_path / "ward")
    for opts, why in (({"colour": "red"}, "unknown option"), ({"max_candidates": "lots"}, "max_candidates"),
                      ({"max_candidates": 0}, "max_candidates"), ({"field_nope": "1"}, "not in the recipe"),
                      ({"field_leak_count": "|"}, "pins no value"), ({"recipe": "just words"}, "not a hash recipe"),
                      ({"command": "C-PUSH-RQ"}, "unknown DIMSE command")):
        res = E.solve(root, profile(), out="none", **opts)
        assert res.status == "blocked" and why in res.notes, (opts, res.notes)
    res = E.solve(root, profile(), out="none", max_candidates=3)
    assert len(res.flags) == 3


def test_unbound_field_and_missing_prefix_are_unsure(tmp_path):
    root = fx.handout(tmp_path / "ward")
    res = E.solve(root, profile(), out="none", recipe='sha256("<dicom_serial>:<firmware_hash>")[:8]')
    assert res.status == "unsure" and "firmware_hash" in res.notes and res.flags == ()
    res = E.solve(root, profile(prefixes=()), out="none")
    assert res.status == "unsure" and fx.expected_digest(OPENING) in res.notes
    res = E.solve(root, None, out="none")
    assert res.status == "unsure" and "no event rules" not in res.notes


def test_hostile_xml_is_skipped_by_name(tmp_path):
    bad = '<?xml version="1.0"?><!DOCTYPE d [<!ENTITY e SYSTEM "file:///etc/passwd">]><d>&e;</d>'
    root = fx.handout(tmp_path / "ward", files={"dicom_device.xml": bad})
    report = E.analyze(root, profile())
    assert ["files/dicom_device.xml", "the XML declares a DOCTYPE or an entity; refused (untrusted input)"] \
        in report["skipped"]
    names = [d["name"] for d in report["dicom"]["anomaly"]["definitions"]]
    assert names == ["external"]                                         # no SCP, no payload limit read
    res = E.solve(root, profile(), out="none")
    assert "skipped files/dicom_device.xml" in res.notes


def test_an_empty_handout_is_none(tmp_path):
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "readme.txt").write_text("nothing to see\n")
    res = E.solve(tmp_path, profile(), out="none", description="")
    assert res.status == "none" and res.flags == ()


def test_handout_files_skip_workspace_and_dot_dirs(tmp_path):
    root = fx.handout(tmp_path / "ward")
    (root / "files" / ".ctf").mkdir()
    (root / "files" / ".ctf" / "x.log").write_text("2026-01-01T00:00:00Z secret\n")
    (root / "files" / "copy.pcap").write_bytes((root / "files" / "hospital_network.pcap").read_bytes())
    (root / "files" / "recon").mkdir()
    (root / "files" / "recon" / "r.log").write_text("2026-01-01T00:00:00Z old\n")
    # links in an untrusted handout are not followed: neither to a file nor to a folder outside it
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.log").write_text("2026-01-01T00:00:00Z OUTSIDE-SECRET\n")
    (root / "files" / "linked.log").symlink_to(outside / "private.log")
    (root / "files" / "linked_dir").symlink_to(outside, target_is_directory=True)
    names = [n for n, _ in E.handout_files(root)]
    assert not any(".ctf" in n or "recon" in n for n in names)
    assert not any("linked" in n for n in names)
    assert sum(1 for n in names if n.endswith(".pcap")) == 1            # the second copy is listed once
    E.solve(root, profile())
    assert "OUTSIDE-SECRET" not in (root / "recon" / "dicom_snmp_timeline" / "report.json").read_text()


# ============================================================ wiring: manifest, router, runner

def test_router_sends_a_dicom_exfil_brief_here():
    from ctf.engines import router
    hits = router.route("networking", "A DICOM C-STORE exfil, an SNMP trap log and a device XML")
    assert "toolkits.dicom_snmp_timeline" in [h.manifest.id for h in hits][:3]
    assert "toolkits.dicom_snmp_timeline" not in [h.manifest.id for h in router.route("crypto", "RSA small e")]


def test_ctf_run_prints_the_ranked_result(tmp_path):
    root = fx.handout(tmp_path / "ward")
    env = dict(os.environ, CTF_ENGINE_LEDGER="0")
    proc = subprocess.run([sys.executable, "-m", "ctf", "run", "--no-ledger", "toolkits.dicom_snmp_timeline",
                           str(root), "--opt", "out=none", "--event", "csctf"],
                          cwd=REPO, env=env, capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0, proc.stderr
    got = json.loads(proc.stdout)
    assert got["status"] == "candidate" and got["engine"] == "toolkits.dicom_snmp_timeline"
    assert got["flags"][0] == flag(fx.expected_digest(OPENING))
