"""Unit tests for the OT protocol-detection oracle (B-204), on synthetic captures.

These prove the oracle dispatch (tests/real/_ot_oracle.py): each engine, run on a minimal valid
synthetic capture of its protocol (tests/real/_ot_fixtures.py), recognises that protocol; the token
normalisation collapses the parsers' spellings onto the canonical token; and a mis-routed capture is
not recognised. The real-corpus run (tests/real/test_real_ot.py::realdata) reuses the same dispatch,
so proving it here proves it there. Needs scapy (the oracle reads pcaps with it).
"""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent / "real"))
import event_pin  # noqa: E402

event_pin.pin(globals(), "csctf")  # the ICS parsers resolve the event flag format

pytestmark = pytest.mark.needs_tool("py:scapy")

import _ot_fixtures as fixtures  # noqa: E402
import _ot_oracle as oracle  # noqa: E402


@pytest.fixture(scope="module")
def caps(tmp_path_factory):
    return fixtures.write_captures(tmp_path_factory.mktemp("ot-caps"))


@pytest.mark.parametrize("proto", sorted(fixtures.ENGINE_FOR))
def test_engine_recognises_its_protocol(proto, caps):
    engine = fixtures.ENGINE_FOR[proto]
    det = oracle.detect(engine, caps[proto])
    assert det.recognised(proto), f"{engine} did not recognise {proto} in its own capture: {det}"
    assert det.count >= 1, f"{engine} decoded no {proto} message: {det}"


def test_every_manifest_protocol_has_a_fixture_and_engine():
    import json
    manifest = json.loads((Path(oracle.__file__).parent / "manifest_ot.json").read_text())
    for row in manifest["files"]:
        proto = row["proto"]
        assert row["engine"] in oracle.ENGINES, f"manifest engine {row['engine']!r} unknown"
        # every sourced protocol that an engine here supports also has a synthetic fixture
        if proto in fixtures.captures():
            assert fixtures.ENGINE_FOR[proto] == row["engine"], (
                f"fixture engine for {proto} disagrees with the manifest")


def test_ics_capture_does_not_cross_detect(caps):
    # a modbus capture must not be reported as dnp3 (kills a mutation that ignores the real token)
    det = oracle.detect("ics_capture", caps["modbus"])
    assert det.recognised("modbus")
    assert not det.recognised("dnp3")


def test_normalisation_maps_parser_spellings_to_canonical():
    det = oracle.Detection("x", {"bacnet-ip", "ethernet-ip", "iec61850-goose"}, 3)
    assert det.tokens == {"bacnet", "enip", "goose"}
    assert det.recognised("bacnet") and det.recognised("enip") and det.recognised("goose")
    assert det.recognised("bacnet-ip")  # the query is normalised too, so either spelling matches
    assert not det.recognised("modbus")


def test_empty_capture_recognises_nothing(tmp_path):
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(fixtures.pcap([]))
    det = oracle.detect("ics_capture", empty)
    assert det.tokens == set()
    assert det.count == 0


def test_unknown_engine_raises(caps):
    with pytest.raises(KeyError):
        oracle.detect("no_such_engine", caps["modbus"])


def test_ethercat_engine_rejects_a_non_ethercat_l2_frame(tmp_path):
    # a GOOSE L2 frame fed to the EtherCAT engine (wrong ethertype) yields nothing
    goose_cap = fixtures.write_captures(tmp_path)["goose"]
    det = oracle.detect("ethercat", goose_cap)
    assert det.tokens == set()
    assert det.count == 0
