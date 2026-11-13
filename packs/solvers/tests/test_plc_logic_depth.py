from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))
import plc_logic_depth as plc


def kinds(report):
    return {item["kind"] for item in report["findings"]}


def test_awl_dataflow_timers_counters_jumps_and_unsafe_findings():
    source = """
NETWORK 1
LOOP: A I 0.0
A EStop_OK
= Q 0.0
TON T 1, T#0S
CTU C 1, 0
NETWORK 2
A M 0.0
= Q 0.0
S Q 0.1
= I 0.1
JU LOOP
A ForceBypass
"""
    report = plc.parse_awl(source)
    assert report["dialect"] == "awl"
    assert report["cross_reference"]["Q0.0"]["role"] == "physical-output"
    assert any(edge["source"] == "EStop_OK" and edge["target"] == "Q0.0" for edge in report["dataflow"])
    found = kinds(report)
    assert {"physical-output-multiple-writers", "timer-nonpositive-preset", "counter-nonpositive-preset",
            "latch-without-reset", "write-to-input", "backward-unconditional-jump",
            "force-bypass-indicator"} <= found
    assert report["timers"][0]["instance"] == "T1" and report["timers"][0]["preset_ms"] == 0
    assert report["counters"][0]["instance"] == "C1" and report["counters"][0]["preset"] == 0


def test_ladder_rungs_latches_interlocks_math_and_cross_reference():
    source = """
RUNG XIC(StartPB) XIC(Safety_OK) OTE(MotorPump);
RUNG XIC(AutoMode) OTL(Q0.1);
RUNG XIC(ResetPB) OTU(Q0.1);
RUNG XIC(StartPB) TON(TimerA, T#5S, 0);
RUNG XIC(CountPB) CTU(CounterA, 10, 0);
RUNG DIV(ProcessValue, 0, Q0.2);
"""
    report = plc.parse_ladder_text(source)
    assert report["dialect"] == "ladder-text"
    assert report["cross_reference"]["StartPB"]["reads"]
    assert any(edge["source"] == "Safety_OK" and edge["target"] == "MotorPump" for edge in report["dataflow"])
    assert report["timers"][0]["preset_ms"] == 5000
    assert report["counters"][0]["preset"] == 10
    assert "constant-divide-by-zero" in kinds(report)
    assert "latch-without-reset" not in kinds(report)
    # A rung beginning with an N-prefixed symbol is not mistaken for the L5K N: marker.
    prefixed = plc.parse_ladder_text("XIC(NOT_READY) OTE(Q0.3);")
    assert "NOT_READY" in prefixed["cross_reference"]


def test_structured_text_assignments_conditions_and_function_blocks():
    source = """
IF Start AND Guard_OK THEN
  MotorPump := Enable;
END_IF;
TON1(IN := Start, PT := T#2S, Q => Done, ET => Elapsed);
Counter1(CU := Pulse, PV := 3, CV => Count);
"""
    report = plc.parse_structured_text(source)
    assert report["dialect"] == "structured-text"
    assert report["cross_reference"]["MotorPump"]["writes"]
    assert any(edge["source"] == "Guard_OK" and edge["target"] == "MotorPump" for edge in report["dataflow"])
    assert report["timers"][0]["instance"] == "TON1" and report["timers"][0]["preset_ms"] == 2000
    assert report["counters"][0]["instance"] == "Counter1" and report["counters"][0]["preset"] == 3


def test_plcopen_xml_connections_coil_storage_and_embedded_st():
    xml = b'''<?xml version="1.0"?>
<project xmlns="http://www.plcopen.org/xml/tc6_0201">
 <pou><body><LD>
  <contact localId="1" variable="Start"/>
  <contact localId="2" variable="Safety_OK"><connectionPointIn><connection refLocalId="1"/></connectionPointIn></contact>
  <coil localId="3" variable="Q0.0"><connectionPointIn><connection refLocalId="2"/></connectionPointIn></coil>
  <coil localId="4" variable="Q0.1" storage="set"><connectionPointIn><connection refLocalId="1"/></connectionPointIn></coil>
 </LD></body></pou>
</project>'''
    report = plc.parse_plcopen_xml(xml)
    assert report["dialect"] == "plcopen-xml"
    assert any(edge["source"] == "Safety_OK" and edge["target"] == "Q0.0" for edge in report["dataflow"])
    assert "latch-without-reset" in kinds(report)
    with pytest.raises(plc.ParseError, match="DTD"):
        plc.parse_plcopen_xml(b'<!DOCTYPE x [<!ENTITY y "z">]><project/>')


def test_plcopen_network_attribution_detects_multiple_physical_writers():
    xml = b'''<project><network><contact localId="1" variable="A"/><coil localId="2" variable="Q0.0">
      <connectionPointIn><connection refLocalId="1"/></connectionPointIn></coil></network>
      <network><contact localId="3" variable="B"/><coil localId="4" variable="Q0.0">
      <connectionPointIn><connection refLocalId="3"/></connectionPointIn></coil></network></project>'''
    report = plc.parse_plcopen_xml(xml)
    finding = next(item for item in report["findings"] if item["kind"] == "physical-output-multiple-writers")
    assert finding["networks"] == [1, 2]


def test_duration_tag_roles_dialect_dispatch_and_malformed_inputs(monkeypatch):
    assert plc.parse_duration_ms("T#1H2M3.5S") == 3_723_500
    assert plc.parse_duration_ms("S5T#250MS") == 250
    assert plc.parse_duration_ms("not-time") is None
    assert plc.tag_role("DB1.DBX0.0") == "data-block"
    assert plc.tag_role("%IX1.2") == "physical-input"
    assert plc.tag_role("QW12") == "physical-output"
    assert plc.detect_dialect("XIC(A) OTE(B);") == "ladder-text"
    assert plc.detect_dialect("Output := Input;") == "structured-text"
    assert plc.parse_plc_logic("Output := Input;")["dialect"] == "structured-text"
    assert plc.parse_plc_logic("A I0.0\n= Q0.0", dialect="stl")["dialect"] == "awl"
    with pytest.raises(plc.ParseError):
        plc.parse_ladder_text("XIC(unclosed")
    with pytest.raises(plc.ParseError):
        plc.parse_structured_text("just unsupported text")
    with pytest.raises(plc.ParseError):
        plc.parse_awl("\n// comments only\n")
    monkeypatch.setattr(plc, "MAX_INPUT", 4)
    with pytest.raises(plc.ParseError, match="cap"):
        plc.parse_plc_logic(b"A" * 20)


def test_cli_json_output(tmp_path):
    artifact = tmp_path / "logic.l5k"
    artifact.write_text("XIC(Start) OTE(Q0.0);")
    proc = subprocess.run([sys.executable, str(ROOT / "solvers/toolkits/plc_logic_depth.py"),
                           str(artifact)], check=True, capture_output=True, text=True)
    report = json.loads(proc.stdout)
    assert report["dialect"] == "ladder-text" and report["instruction_count"] == 2
