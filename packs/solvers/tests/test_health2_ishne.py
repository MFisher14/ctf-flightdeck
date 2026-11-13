"""ISHNE fixtures independently encoded from Badilini's Table 3 / Appendix B.

No fixture uses the engine to construct bytes. ishneholterlib provides a second
independent decoder for sample ordering, patient metadata, CRC, and scaling.
"""
import json
import struct

import pytest
from ishneholterlib import Holter

from health2_ishne import IshneError, main, parse_ishne, read_ishne


def reference_crc(data):
    crc = 65535
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ (0x1021 if crc & 0x8000 else 0)) & 0xffff
    return crc


def repair_crc(data):
    data = bytearray(data)
    end = int.from_bytes(data[22:26], "little", signed=True)
    data[8:10] = reference_crc(data[10:end]).to_bytes(2, "little")
    return bytes(data)


def fixture(*, total_count=False, comments=b"CSCTF{holter_header}\x00"):
    """Append fields in published order; use explicit literals for raw waveform."""
    block = struct.pack("<4ih", len(comments), 8 if total_count else 4, 522, 522 + len(comments), 1)
    block += b"Ada".ljust(40, b"\0") + b"Lovelace".ljust(40, b"\0") + b"P001".ljust(20, b"\0")
    block += struct.pack("<2h", 2, 0)
    block += struct.pack("<12h", 10, 12, 1815, 5, 11, 2026, 5, 11, 2026, 12, 30, 45)
    block += struct.pack("<h", 2)
    block += struct.pack("<12h", 5, 6, *([-9] * 10))
    block += struct.pack("<12h", 1, 1, *([-9] * 10))
    block += struct.pack("<12h", 1000, 2500, *([-9] * 10))
    block += struct.pack("<h", 0) + b"digital".ljust(40, b"\0") + struct.pack("<h", 500)
    block += b"proprietary".ljust(80, b"\0") + b"copyright".ljust(80, b"\0") + bytes(88)
    assert len(block) == 512
    block += comments
    # Four multiplexed frames: (0,100), (-1,-100), (32767,-32768), (7,9).
    return b"ISHNE1.0" + reference_crc(block).to_bytes(2, "little") + block + bytes.fromhex(
        "00006400 ffff9cff ff7f0080 07000900")


def test_independent_reference_and_library(tmp_path, monkeypatch):
    assert reference_crc(b"123456789") == 0x29B1  # CRC-16/IBM-3740 check vector
    raw = fixture()
    decoded = parse_ishne(raw)
    path = tmp_path / "reference.ecg"
    path.write_bytes(raw)
    # NumPy 2.5 removed the old 'a' byte-string alias used by this 2020 oracle.
    # Adapt only that spelling; its format parsing, sampling and scaling stay intact.
    import ishneholterlib
    get_val = ishneholterlib.get_val

    def compat_get_val(filename, ptr, datatype):
        if isinstance(datatype, str) and datatype.startswith("a"):
            datatype = "S" + datatype[1:]
        return get_val(filename, ptr, datatype)

    monkeypatch.setattr(ishneholterlib, "get_val", compat_get_val)
    oracle = Holter(str(path), check_valid=False)
    assert oracle.is_valid(verify_checksum=False)
    # Pass bytes to avoid the oracle's removed ndarray.tostring() convenience API.
    assert oracle.compute_checksum(raw[10:oracle.ecg_block_offset]) == oracle.checksum
    oracle.load_data(convert=False)
    assert decoded["metadata"]["patient_id"] == oracle.id.decode() == "P001"
    assert decoded["metadata"]["first_name"] == oracle.first_name.decode()
    assert decoded["metadata"]["record_date"] == oracle.record_date.isoformat()
    assert decoded["metadata"]["start_time"] == oracle.start_time.isoformat()
    assert decoded["sample_rate_hz"] == oracle.sr == 500
    assert decoded["sample_count_convention"] == "per_lead"
    assert decoded["samples_per_lead"] == 4
    assert decoded["flags"] == ["CSCTF{holter_header}"]
    assert decoded["leads"][0]["samples"] == oracle.lead[0].data.tolist() == [0, -1, 32767, 7]
    assert decoded["leads"][1]["samples"] == oracle.lead[1].data.tolist() == [100, -100, -32768, 9]
    oracle.load_data(convert=True)
    for index, lead in enumerate(decoded["leads"]):
        scaled = [x * lead["resolution_nv"] / 1_000_000 for x in lead["samples"]]
        assert scaled == pytest.approx(oracle.lead[index].data.tolist())


def test_total_samples_convention_and_empty_comment():
    result = parse_ishne(fixture(total_count=True, comments=b""), count_convention="total")
    assert result["sample_count_convention"] == "total"
    assert result["samples_per_lead"] == 4
    assert result["metadata"]["comments"] == ""


@pytest.mark.parametrize("value", [None, "ISHNE1.0", 123, [], {}])
def test_bad_input_type(value):
    with pytest.raises(IshneError):
        parse_ishne(value)


def test_truncation_and_trailing_bytes():
    data = fixture()
    for n in range(len(data)):
        with pytest.raises(IshneError):
            parse_ishne(data[:n])
    with pytest.raises(IshneError):
        parse_ishne(data + b"\0\0")


@pytest.mark.parametrize("offset,fmt,value", [
    (10, "i", -1), (18, "i", 521), (22, "i", 4000), (14, "i", 999),
    (156, "h", 0), (156, "h", 13), (272, "h", 0), (158, "h", 99),
    (182, "h", 6), (206, "h", -1), (162, "h", 0), (150, "h", 24),
    (134, "h", 13),
])
def test_invalid_fields_fail_closed(offset, fmt, value):
    raw = bytearray(fixture())
    struct.pack_into("<" + fmt, raw, offset, value)
    with pytest.raises(IshneError):
        parse_ishne(repair_crc(raw))


def test_bad_checksum():
    raw = bytearray(fixture())
    raw[29] ^= 1
    with pytest.raises(IshneError, match="CRC"):
        parse_ishne(raw)


@pytest.mark.parametrize("limit", [0, -1, None, "2", True, 7])
def test_sample_limits(limit):
    with pytest.raises(IshneError):
        parse_ishne(fixture(), max_samples=limit)


def test_unknown_date_and_byte_buffers():
    raw = bytearray(fixture())
    raw[132:138] = b"\0" * 6
    decoded = parse_ishne(memoryview(repair_crc(raw)))
    assert decoded["metadata"]["birth_date"] is None


def test_reader_error(tmp_path):
    for path in (tmp_path / "missing.ecg", tmp_path, None):
        with pytest.raises(IshneError):
            read_ishne(path)


def test_cli(tmp_path, capsys):
    src = tmp_path / "test.ecg"
    src.write_bytes(fixture())
    csv_path = tmp_path / "data.csv"
    assert main([str(src), "--csv", str(csv_path), "--preview", "2"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["leads"][0]["samples_preview"] == [0, -1]
    assert csv_path.read_text().splitlines()[2] == "1,0.002,-1,-100"
    assert main([str(src), "--csv", str(src)]) == 2
    assert main([str(src), "--csv", str(csv_path)]) == 2
    assert main([str(src), "--preview", "-1"]) == 2
    assert main([str(src), "--preview", "no"]) == 2
    assert main([]) == 2
    assert main(["--help"]) == 0


def test_cli_string_system_exit(monkeypatch):
    import argparse

    def fail(*args, **kwargs):
        raise SystemExit("bad")

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", fail)
    assert main([]) == 2
