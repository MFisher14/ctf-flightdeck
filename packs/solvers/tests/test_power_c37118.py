"""Independent C37.118 fixtures: published pyPMU vectors and hand-built frames.

The encoder below is deliberately test-only and uses struct plus the stdlib's
independent CRC implementation, never any engine encoding/checksum function.
Published literals: https://github.com/iicsys/pypmu/blob/master/tests/validate_frames.py
"""
import binascii
import json
import random
import struct

import pytest

import power_c37118 as pmu


PUBLISHED_CFG = bytes.fromhex(
    "aa3101c61e36448527f056071098000f4240000153746174696f6e2041202020202020201e360004000400030001564120"
    "20202020202020202020202020564220202020202020202020202020205643202020202020202020202020202049312020"
    "202020202020202020202020414e414c4f4731202020202020202020414e414c4f4732202020202020202020414e414c4f"
    "4733202020202020202020425245414b4552203120535441545553425245414b4552203220535441545553425245414b45"
    "52203320535441545553425245414b4552203420535441545553425245414b4552203520535441545553425245414b4552"
    "203620535441545553425245414b4552203720535441545553425245414b4552203820535441545553425245414b455220"
    "3920535441545553425245414b4552204120535441545553425245414b4552204220535441545553425245414b45522043"
    "20535441545553425245414b4552204420535441545553425245414b4552204520535441545553425245414b4552204620"
    "535441545553425245414b4552204720535441545553000df847000df847000df8470100b2d00000000101000001020000"
    "010000ffff00000016001ed5d1"
)
PUBLISHED_DATA = bytes.fromhex(
    "aa0100341e3644853600000041b10000392b0000e36ace7ce36a31830444000009c4000042c80000447a0000461c4000"
    "3c12d43f"
)
PUBLISHED_HEADER = bytes.fromhex(
    "aa1100271e36448560300f0bbfd048656c6c6f2049276d20486561646572204672616d652e17cc"
)
PUBLISHED_COMMAND = bytes.fromhex("aa4100121e36448560300f0bbfd00002ce00")


def framed(kind, payload, ident=17, version=2, fraction=250000):
    raw = struct.pack(">BBHHII", 0xAA, kind << 4 | version, len(payload) + 16,
                      ident, 1700000000, fraction) + payload
    return raw + struct.pack(">H", binascii.crc_hqx(raw, 0xFFFF))


def named(value):
    return value.encode("ascii").ljust(16, b" ")


def config(fmt=0, ident=17, blocks=1, kind=3, scale=200000, rate=25):
    payload = struct.pack(">IH", 1000000, blocks)
    for index in range(blocks):
        payload += named(f"Station {index}")
        payload += struct.pack(">HHHHH", index + 1, fmt, 1, 1, 1)
        payload += named("VA") + named("temperature")
        payload += b"".join(named(f"breaker {bit}") for bit in range(16))
        payload += struct.pack(">IIHHHH", scale, 0x01FFFFFD, 0x0001, 0x8003, 1, 4)
    return framed(kind, payload + struct.pack(">h", rate), ident=ident)


def data(fmt=0, ident=17, blocks=1):
    payload = b""
    for _ in range(blocks):
        payload += struct.pack(">H", 0x2C00)
        if fmt & 2:
            payload += struct.pack(">ff", 125.5, -.25)
        elif fmt & 1:
            payload += struct.pack(">Hh", 50000, -2500)
        else:
            payload += struct.pack(">hh", -125, 250)
        payload += struct.pack(">ff", 49.875, -.25) if fmt & 8 else struct.pack(">hh", -125, -25)
        payload += struct.pack(">f", -2.25) if fmt & 4 else struct.pack(">h", -225)
        payload += struct.pack(">H", 0x8002)
    return framed(0, payload, ident=ident)


def recalc(raw):
    return bytes(raw[:-2]) + struct.pack(">H", binascii.crc_hqx(raw[:-2], 0xFFFF))


def test_crc_known_check_and_independent_oracle():
    assert pmu.crc16(b"123456789") == 0x29B1
    for raw in (bytes(range(256)), PUBLISHED_CFG[:-2], PUBLISHED_HEADER[:-2]):
        assert pmu.crc16(raw) == binascii.crc_hqx(raw, 0xFFFF)


def test_published_config_and_data_values():
    cfg = pmu.parse_frame(PUBLISHED_CFG)
    assert cfg["idcode"] == 7734
    assert cfg["time_base"] == 1000000
    assert cfg["data_rate"] == 30
    assert cfg["time_quality_raw"] == 0x56
    assert cfg["leap_pending"] and cfg["leap_delete"] and not cfg["leap_occurred"]
    p = cfg["pmus"][0]
    assert p["station"] == "Station A"
    assert p["phasor_names"] == ["VA", "VB", "VC", "I1"]
    assert p["analog_names"] == ["ANALOG1", "ANALOG2", "ANALOG3"]
    assert p["digital_names"][0][15] == "BREAKER G STATUS"
    assert p["configuration_count"] == 22
    assert p["phasor_units"][0]["scale_factor"] == 915527
    rec = pmu.parse_frame(PUBLISHED_DATA, configuration=PUBLISHED_CFG)
    m = rec["measurements"][0]
    assert m["phasors"][1]["raw"] == [-7318, -12676]
    assert m["phasors"][0]["real"] == pytest.approx(14635 * 9.15527)
    assert m["phasors"][3]["real"] == pytest.approx(1092 * .45776)
    assert m["frequency_hz"] == 62.5
    assert [a["value"] for a in m["analogs"]] == [100, 1000, 10000]
    assert m["digitals"][0]["raw"] == 0x3C12
    assert rec["fractional_seconds"] == .016817


def test_published_header_and_command():
    assert pmu.parse_frame(PUBLISHED_HEADER)["text"] == "Hello I'm Header Frame."
    assert pmu.parse_frame(PUBLISHED_COMMAND)["command_name"] == "start_data"


@pytest.mark.parametrize("fmt", range(16))
def test_all_measurement_formats(fmt):
    cfg = config(fmt)
    parsed_cfg = pmu.parse_frame(cfg)
    assert parsed_cfg["pmus"][0]["analog_units"][0]["user_scale"] == -3
    rec = pmu.parse_frame(data(fmt), configuration=cfg)
    m = rec["measurements"][0]
    value = m["phasors"][0]
    if fmt & 1:
        assert value["magnitude"] == (125.5 if fmt & 2 else 100000)
        assert value["angle_radians"] == -.25
    else:
        assert value["real"] == (125.5 if fmt & 2 else -250)
        assert value["imaginary"] == (-.25 if fmt & 2 else 500)
    assert m["frequency_hz"] == 49.875
    assert m["rocof_hz_per_second"] == -.25
    assert m["analogs"][0]["value"] == (-2.25 if fmt & 4 else -225)
    assert m["digitals"][0]["abnormal_mask"] == 0x8003
    assert m["digitals"][0]["bits"][15] == {"name": "breaker 15", "value": True, "valid": True}
    assert m["synchronization_error"] and m["trigger_detected"] and m["configuration_change"]


def test_stream_configs_multiblock_and_cfg1_does_not_replace_layout():
    stream = (config(15, ident=17, blocks=2) + config(0, ident=18)
              + config(0, ident=17, kind=2) + data(15, ident=17, blocks=2) + data(0, ident=18))
    records = pmu.parse_stream(stream)
    assert len(records) == 5
    assert len(records[3]["measurements"]) == 2
    assert records[3]["measurements"][1]["phasors"][0]["magnitude"] == 125.5
    assert records[4]["measurements"][0]["phasors"][0]["real"] == -250
    assert records[-1]["offset"] + records[-1]["frame_size"] == len(stream)


def test_config_replacement_and_negative_data_rate():
    stream = config(scale=100000, rate=-2) + data() + config(scale=300000) + data()
    records = pmu.parse_stream(stream)
    assert records[0]["frames_per_second"] == .5
    assert records[1]["measurements"][0]["phasors"][0]["real"] == -125
    assert records[3]["measurements"][0]["phasors"][0]["real"] == pytest.approx(-375)


def test_no_config_and_mismatched_config_fail_closed():
    for cfg in (None, config(ident=18), config(kind=2), PUBLISHED_HEADER, {}):
        with pytest.raises(pmu.PowerC37118Error):
            pmu.parse_frame(data(), configuration=cfg)
    with pytest.raises(pmu.PowerC37118Error):
        pmu.parse_stream(config(kind=2) + data())


def test_all_truncations_and_trailing_bytes_rejected():
    for raw in (PUBLISHED_CFG, PUBLISHED_DATA, PUBLISHED_HEADER, PUBLISHED_COMMAND):
        for cut in range(len(raw)):
            with pytest.raises(pmu.PowerC37118Error):
                pmu.parse_frame(raw[:cut], configuration=PUBLISHED_CFG)
        with pytest.raises(pmu.PowerC37118Error):
            pmu.parse_frame(raw + b"\0")
    with pytest.raises(pmu.PowerC37118Error):
        pmu.parse_stream(PUBLISHED_CFG + PUBLISHED_DATA[:-1])


@pytest.mark.parametrize("value", [None, 1, "aa", [], {}, True])
def test_wrong_types_fail_closed(value):
    for fn in (pmu.crc16, pmu.parse_frame, pmu.parse_stream):
        with pytest.raises(pmu.PowerC37118Error):
            fn(value)


def test_released_memoryview_and_binary_buffers():
    view = memoryview(b"hello")
    view.release()
    for fn in (pmu.crc16, pmu.parse_frame, pmu.parse_stream):
        with pytest.raises(pmu.PowerC37118Error):
            fn(view)
    assert pmu.parse_frame(bytearray(PUBLISHED_HEADER))["text"].startswith("Hello")
    assert pmu.parse_frame(memoryview(PUBLISHED_COMMAND))["command"] == 2


@pytest.mark.parametrize("offset,value", [(0, 0), (1, 0x53), (1, 0xB2), (4, 0xFF),
                                          (18, 0), (19, 0), (37, 0xF0)])
def test_header_crc_and_config_malformed(offset, value):
    raw = bytearray(config())
    if offset == 4:
        raw[4:6] = b"\xff\xff"
    elif offset == 18:
        raw[14:18] = b"\0" * 4
    elif offset == 19:
        raw[18:20] = b"\0" * 2
    elif offset == 37:
        raw[38:40] = b"\xff\xff"
    else:
        raw[offset] = value
    with pytest.raises(pmu.PowerC37118Error):
        pmu.parse_frame(recalc(raw))
    raw[-1] ^= 1
    with pytest.raises(pmu.PowerC37118Error):
        pmu.parse_frame(raw)


def test_valid_crc_invalid_body_fields():
    cfg = config()
    # Independently wrapped payloads preserve CRC while breaking the body grammar.
    bad_payloads = [cfg[14:-3], cfg[14:-2] + b"\0", cfg[14:-4] + b"\0\0"]
    for payload in bad_payloads:
        with pytest.raises(pmu.PowerC37118Error):
            pmu.parse_frame(framed(3, payload))
    with pytest.raises(pmu.PowerC37118Error):
        pmu.parse_frame(framed(0, data()[14:-2] + b"\0"), configuration=cfg)
    with pytest.raises(pmu.PowerC37118Error):
        pmu.parse_frame(framed(1, b"\xff"))
    with pytest.raises(pmu.PowerC37118Error):
        pmu.parse_frame(framed(4, b"\0\2extra"))
    assert pmu.parse_frame(framed(4, b"\0\10extra"))["extended_data_hex"] == b"extra".hex()


def test_nan_rejected_and_anomalous_fraction_preserved():
    raw = bytearray(data(15))
    raw[16:20] = struct.pack(">f", float("nan"))
    with pytest.raises(pmu.PowerC37118Error):
        pmu.parse_frame(recalc(raw), configuration=config(15))
    raw = bytearray(data())
    raw[10:14] = struct.pack(">I", 0xFF123456)
    rec = pmu.parse_frame(recalc(raw), configuration=config())
    assert rec["fracsec_raw"] == 0xFF123456
    assert rec["time_quality_raw"] == 255
    assert not rec["fraction_in_range"]


def test_deterministic_noise_never_leaks_stdlib_exceptions():
    rng = random.Random(37118)
    for size in range(0, 150):
        raw = rng.randbytes(size)
        for fn in (pmu.parse_frame, pmu.parse_stream):
            try:
                fn(raw)
            except pmu.PowerC37118Error:
                pass


def test_cli_contract(tmp_path, capsys, monkeypatch):
    assert pmu.main([]) == 2
    assert pmu.main(["--help"]) == 0
    assert pmu.main([str(tmp_path / "missing")]) == 2
    capsys.readouterr()
    path = tmp_path / "header.hex"
    path.write_text(PUBLISHED_HEADER.hex())
    assert pmu.main([str(path), "--hex"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["text"] == "Hello I'm Header Frame."
    config_path = tmp_path / "cfg.bin"
    config_path.write_bytes(config())
    path.write_bytes(data())
    assert pmu.main([str(path), "--config", str(config_path)]) == 0
    assert json.loads(capsys.readouterr().out)[0]["measurements"]
    path.write_text("not hex")
    assert pmu.main([str(path), "--hex"]) == 2
    def exit_text(*args, **kwargs):
        raise SystemExit("failure")
    monkeypatch.setattr(pmu.argparse.ArgumentParser, "parse_args", exit_text)
    assert pmu.main([]) == 2
