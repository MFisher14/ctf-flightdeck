"""Non-circular tests for ``stegodepth_jpegcover``.

The tiny JPEG writer below is an independent reference encoder.  It writes a
baseline grayscale stream with caller-selected quantized coefficients; the
engine under test never supplies encoder output or expected deltas.
"""

from __future__ import annotations

import json
import struct

import pytest

import stegodepth_jpegcover as jc


DC_BITS = [0, 4] + [0] * 14
DC_VALUES = [0, 1, 2, 3]
AC_BITS = [0, 4] + [0] * 14
AC_VALUES = [0x00, 0x01, 0x02, 0x03]


def _codes(counts, values):
    result = {}
    code = 0
    at = 0
    for width, count in enumerate(counts, 1):
        for _ in range(count):
            result[values[at]] = (code, width)
            code += 1
            at += 1
        code <<= 1
    return result


DC_CODES = _codes(DC_BITS, DC_VALUES)
AC_CODES = _codes(AC_BITS, AC_VALUES)


class _Writer:
    def __init__(self):
        self.output = bytearray()
        self.accumulator = 0
        self.count = 0

    def put(self, value, width):
        for shift in range(width - 1, -1, -1):
            self.accumulator = (self.accumulator << 1) | ((value >> shift) & 1)
            self.count += 1
            if self.count == 8:
                self.output.append(self.accumulator)
                if self.accumulator == 0xFF:
                    self.output.append(0)
                self.accumulator = self.count = 0

    def finish(self):
        if self.count:
            padding = 8 - self.count
            self.accumulator = (self.accumulator << padding) | ((1 << padding) - 1)
            self.output.append(self.accumulator)
            if self.accumulator == 0xFF:
                self.output.append(0)
            self.accumulator = self.count = 0


def _category(value):
    return abs(value).bit_length()


def _mantissa(value, width):
    return value if value >= 0 else value + (1 << width) - 1


def _segment(marker, body):
    return bytes((0xFF, marker)) + struct.pack(">H", len(body) + 2) + body


def _block(*ac):
    assert len(ac) <= 63 and all(value != 0 for value in ac)
    return [2, *ac, *([0] * (63 - len(ac)))]


def _jpeg(blocks, width, height, quantizer=1):
    """Encode contiguous nonzero AC prefixes using tiny canonical Huffman tables."""
    assert width % 8 == height % 8 == 0
    assert len(blocks) == (width // 8) * (height // 8)
    assert 1 <= quantizer <= 255
    writer = _Writer()
    previous_dc = 0
    for block in blocks:
        assert len(block) == 64
        difference = block[0] - previous_dc
        previous_dc = block[0]
        size = _category(difference)
        code, length = DC_CODES[size]
        writer.put(code, length)
        if size:
            writer.put(_mantissa(difference, size), size)
        last = max((index for index, value in enumerate(block[1:]) if value), default=-1)
        for index in range(last + 1):
            value = block[index + 1]
            assert value != 0  # this reference table intentionally has no run symbols
            size = _category(value)
            code, length = AC_CODES[size]
            writer.put(code, length)
            writer.put(_mantissa(value, size), size)
        if last < 62:
            code, length = AC_CODES[0]
            writer.put(code, length)
    writer.finish()

    output = bytearray(b"\xff\xd8")
    output += _segment(0xDB, b"\x00" + bytes((quantizer,)) * 64)
    output += _segment(
        0xC0,
        struct.pack(">BHHB", 8, height, width, 1) + bytes((1, 0x11, 0)),
    )
    output += _segment(0xC4, b"\x00" + bytes(DC_BITS) + bytes(DC_VALUES))
    output += _segment(0xC4, b"\x10" + bytes(AC_BITS) + bytes(AC_VALUES))
    output += _segment(0xDA, b"\x01\x01\x00\x00\x3f\x00")
    output += writer.output
    output += b"\xff\xd9"
    return bytes(output)


def _pair():
    cover = [
        _block(2, 3, -2, 4),
        _block(2, -2, -1),
        _block(2, -2, 3),
        _block(2, -2),
    ]
    suspect = [
        _block(3, 2, -2, 4),       # +1 at AC1, -1 at AC2
        _block(2, -2),             # -1 -> 0 shrinkage at AC3
        _block(2, -2, 3, 1),       # 0 -> 1 growth at AC4
        _block(5, -2),             # non-unit +3 at AC1
    ]
    return _jpeg(cover, 32, 8), _jpeg(suspect, 32, 8)


def test_exact_known_cover_delta_report():
    cover, suspect = _pair()
    report = jc.compare(cover, suspect)
    assert report is not None
    assert (report.width, report.height, report.blocks, report.coefficients) == (32, 8, 4, 256)
    assert report.quantization_table_ids == (0,)
    assert report.changed == 5
    assert report.changed_blocks == 4
    assert report.changed_dc == 0
    assert report.changed_ac == 5
    assert report.unit_changes == 4
    assert report.unit_change_fraction == pytest.approx(0.8)
    assert report.shrinkage == 1
    assert report.growth == 1
    assert dict(report.delta_histogram) == {1: 3, -1: 1, 3: 1}
    assert report.delta_histogram_other == 0
    assert report.per_frequency[0] == 0
    assert report.per_frequency[1:5] == (2, 1, 1, 1)
    assert len(report.per_component) == 1
    assert report.per_component[0].changed == 5
    assert report.all_block_ac_energy_quartiles == pytest.approx((4.75, 6.0, 8.0))
    assert report.changed_block_ac_energy_quartiles == pytest.approx((4.75, 6.0, 8.0))
    assert report.changed_to_all_median_energy_ratio == pytest.approx(1.0)
    assert "do not identify" in report.interpretation


def test_identical_pair_is_an_exact_zero_diff():
    cover, _ = _pair()
    report = jc.compare(cover, cover)
    assert report is not None
    assert report.changed == report.changed_blocks == report.unit_changes == 0
    assert report.delta_histogram == ()
    assert report.changed_block_ac_energy_quartiles is None
    assert report.changed_to_all_median_energy_ratio is None


def test_valid_but_incomparable_pairs_raise_only_declared_error():
    cover, suspect = _pair()
    blocks = [_block(2, 3, -2, 4), _block(2, -2, -1),
              _block(2, -2, 3), _block(2, -2)]
    different_table = _jpeg(blocks, 32, 8, quantizer=2)
    with pytest.raises(jc.StegodepthJPEGCoverError, match="quantization"):
        jc.compare(cover, different_table)

    different_shape = _jpeg(blocks[:2], 16, 8)
    with pytest.raises(jc.StegodepthJPEGCoverError, match="geometry"):
        jc.compare(cover, different_shape)
    assert jc.compare(cover, suspect) is not None


def test_malformed_and_resource_guards_fail_closed(monkeypatch):
    cover, _ = _pair()
    assert jc.compare(b"not jpeg", cover) is None
    assert jc.compare(cover[:-3], cover) is None
    with pytest.raises(jc.StegodepthJPEGCoverError):
        jc.compare("not bytes", cover)
    monkeypatch.setattr(jc, "MAX_INPUT_BYTES", 16)
    with pytest.raises(jc.StegodepthJPEGCoverError, match="size"):
        jc.compare(cover, cover)

    class BadBytes(bytes):
        def __len__(self):
            raise RuntimeError("hostile length")

    with pytest.raises(jc.StegodepthJPEGCoverError):
        jc.compare(BadBytes(cover), cover)


def test_guarded_cli(tmp_path, capsys):
    cover, suspect = _pair()
    cover_path = tmp_path / "cover.jpg"
    suspect_path = tmp_path / "suspect.jpg"
    cover_path.write_bytes(cover)
    suspect_path.write_bytes(suspect)

    assert jc.main([str(cover_path), str(suspect_path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["changed"] == 5
    assert "interpretation" in result

    assert jc.main([]) == 2
    capsys.readouterr()
    assert jc.main(["--help"]) == 0
    capsys.readouterr()
    assert jc.main([str(cover_path), str(tmp_path / "missing.jpg")]) == 2
    assert "cannot read" in capsys.readouterr().err
