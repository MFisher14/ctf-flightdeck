"""Independent N7CXI timing vectors for the rf2 SSTV decoder.

The fixtures below synthesize phase-continuous tones directly from the Dayton
mode tables.  They never call an encoder or timing table from the engine.
"""
from __future__ import annotations

import io
import json
import wave

import numpy as np
import pytest

import rf2_sstv_modes as sstv


RATE = 48_000


class ToneWriter:
    def __init__(self, rate=RATE):
        self.rate = rate
        self.phase = 0.0
        self.elapsed_ms = 0.0
        self.samples = 0
        self.parts = []

    def tone(self, frequency, duration_ms):
        target_ms = self.elapsed_ms + duration_ms
        target_samples = int(round(target_ms * self.rate / 1000.0))
        count = target_samples - self.samples
        positions = np.arange(count, dtype=np.float64)
        angles = self.phase + 2.0 * np.pi * frequency * positions / self.rate
        self.parts.append(0.7 * np.sin(angles))
        self.phase = (self.phase + 2.0 * np.pi * frequency * count / self.rate) % (2.0 * np.pi)
        self.elapsed_ms = target_ms
        self.samples = target_samples

    def video(self, value, duration_ms):
        self.tone(1500.0 + float(value) * 800.0 / 255.0, duration_ms)

    def video_pixels(self, values, duration_ms):
        """Emit independently timed, phase-continuous picture elements."""
        pixels = np.asarray(values, dtype=np.uint8).reshape(-1)
        start_ms = self.elapsed_ms
        for index, value in enumerate(pixels):
            target_ms = start_ms + duration_ms * (index + 1) / pixels.size
            target_samples = int(round(target_ms * self.rate / 1000.0))
            count = target_samples - self.samples
            positions = np.arange(count, dtype=np.float64)
            frequency = 1500.0 + float(value) * 800.0 / 255.0
            angles = self.phase + 2.0 * np.pi * frequency * positions / self.rate
            self.parts.append(0.7 * np.sin(angles))
            self.phase = (self.phase + 2.0 * np.pi * frequency * count / self.rate) % (2.0 * np.pi)
            self.samples = target_samples
        self.elapsed_ms = start_ms + duration_ms

    def finish(self):
        return np.concatenate(self.parts)


def header(writer, vis, *, bad_parity=False):
    writer.tone(1900, 300)
    writer.tone(1200, 10)
    writer.tone(1900, 300)
    writer.tone(1200, 30)
    bits = [(vis >> bit) & 1 for bit in range(7)]
    bits.append((sum(bits) & 1) ^ int(bad_parity))
    for bit in bits:
        writer.tone(1100 if bit else 1300, 30)
    writer.tone(1200, 30)


def scottie_fixture(vis, scan_ms, *, red=128, green=64, blue=192):
    writer = ToneWriter()
    header(writer, vis)
    writer.tone(1200, 9)
    writer.tone(1500, 1.5)
    writer.video(green, scan_ms)
    writer.tone(1500, 1.5)
    writer.video(blue, scan_ms)
    writer.tone(1200, 9)
    writer.tone(1500, 1.5)
    writer.video(red, scan_ms)
    return writer.finish(), np.array([red, green, blue], dtype=np.uint8)


def robot36_fixture(y0=80, y1=160, red_y=150, blue_y=110):
    writer = ToneWriter()
    header(writer, 8)
    for line, y, separator, chroma in (
        (0, y0, 1500, red_y), (1, y1, 2300, blue_y),
    ):
        del line
        writer.tone(1200, 9)
        writer.tone(1500, 3)
        writer.video(y, 88)
        writer.tone(separator, 4.5)
        writer.tone(1900, 1.5)
        writer.video(chroma, 44)
    return writer.finish(), (y0, y1, red_y, blue_y)


def robot72_fixture(y=100, red_y=150, blue_y=110):
    writer = ToneWriter()
    header(writer, 12)
    writer.tone(1200, 9)
    writer.tone(1500, 3)
    writer.video(y, 138)
    writer.tone(1500, 4.5)
    writer.tone(1900, 1.5)
    writer.video(red_y, 69)
    writer.tone(2300, 4.5)
    writer.tone(1500, 1.5)
    writer.video(blue_y, 69)
    return writer.finish(), (y, red_y, blue_y)


def scottie_striped_fixture():
    red = np.resize(np.array([32, 64, 96, 128, 160, 192, 224, 48], dtype=np.uint8), 320)
    green = np.roll(red, 3)
    blue = red[::-1].copy()
    writer = ToneWriter()
    header(writer, 60)
    writer.tone(1200, 9)
    writer.tone(1500, 1.5)
    writer.video_pixels(green, 138.240)
    writer.tone(1500, 1.5)
    writer.video_pixels(blue, 138.240)
    writer.tone(1200, 9)
    writer.tone(1500, 1.5)
    writer.video_pixels(red, 138.240)
    return writer.finish(), np.stack((red, green, blue), axis=1)


def robot72_striped_fixture():
    y = np.resize(np.array([48, 80, 112, 144, 176, 208], dtype=np.uint8), 320)
    red_y = np.resize(np.array([96, 128, 160, 128], dtype=np.uint8), 320)
    blue_y = np.resize(np.array([144, 112, 128, 160], dtype=np.uint8), 320)
    writer = ToneWriter()
    header(writer, 12)
    writer.tone(1200, 9)
    writer.tone(1500, 3)
    writer.video_pixels(y, 138)
    writer.tone(1500, 4.5)
    writer.tone(1900, 1.5)
    writer.video_pixels(red_y, 69)
    writer.tone(2300, 4.5)
    writer.tone(1500, 1.5)
    writer.video_pixels(blue_y, 69)
    expected = np.stack([
        reference_yuv(int(luma), int(cr), int(cb))
        for luma, cr, cb in zip(y, red_y, blue_y)
    ])
    return writer.finish(), expected


def pd_fixture(vis, scan_ms, *, y0=80, y1=160, red_y=150, blue_y=110):
    writer = ToneWriter()
    header(writer, vis)
    writer.tone(1200, 20)
    writer.tone(1500, 2.08)
    for value in (y0, red_y, blue_y, y1):
        writer.video(value, scan_ms)
    return writer.finish(), (y0, y1, red_y, blue_y)


def reference_yuv(y, red_y, blue_y):
    red = 0.003906 * (298.082 * (y - 16) + 408.583 * (red_y - 128))
    green = 0.003906 * (298.082 * (y - 16) - 100.291 * (blue_y - 128)
                       - 208.120 * (red_y - 128))
    blue = 0.003906 * (298.082 * (y - 16) + 516.411 * (blue_y - 128))
    return np.clip(np.rint([red, green, blue]), 0, 255).astype(np.uint8)


@pytest.mark.parametrize("vis,name,scan_ms", [
    (60, "Scottie S1", 138.240),
    (56, "Scottie S2", 88.064),
    (76, "Scottie DX", 345.600),
])
def test_scottie_modes_exact_rgb_line(vis, name, scan_ms):
    audio, expected = scottie_fixture(vis, scan_ms)
    frame = sstv.decode_sstv(audio, sample_rate=RATE, max_lines=1)
    assert frame.mode.name == name and frame.mode.vis == vis
    assert frame.pixels.shape == (1, 320, 3)
    np.testing.assert_array_equal(frame.pixels[0], np.tile(expected, (320, 1)))
    assert frame.ppm().startswith(b"P6\n320 1\n255\n")


def test_scottie_nonuniform_pixels_exact_recovery():
    audio, expected = scottie_striped_fixture()
    frame = sstv.decode_sstv(audio, sample_rate=RATE, max_lines=1)
    np.testing.assert_array_equal(frame.pixels[0], expected)


def test_robot36_exact_two_line_yuv_pair():
    audio, (y0, y1, red_y, blue_y) = robot36_fixture()
    frame = sstv.decode_sstv(audio, sample_rate=RATE, max_lines=2)
    assert frame.mode.name == "Robot 36" and frame.pixels.shape == (2, 320, 3)
    np.testing.assert_array_equal(
        frame.pixels[0], np.tile(reference_yuv(y0, red_y, blue_y), (320, 1)))
    np.testing.assert_array_equal(
        frame.pixels[1], np.tile(reference_yuv(y1, red_y, blue_y), (320, 1)))


def test_robot72_exact_yuv_line():
    audio, (y, red_y, blue_y) = robot72_fixture()
    frame = sstv.decode_sstv(audio, sample_rate=RATE, max_lines=1)
    assert frame.mode.name == "Robot 72" and frame.pixels.shape == (1, 320, 3)
    np.testing.assert_array_equal(
        frame.pixels[0], np.tile(reference_yuv(y, red_y, blue_y), (320, 1)))


def test_robot72_nonuniform_yuv_pixels_exact_recovery():
    audio, expected = robot72_striped_fixture()
    frame = sstv.decode_sstv(audio, sample_rate=RATE, max_lines=1)
    np.testing.assert_array_equal(frame.pixels[0], expected)


@pytest.mark.parametrize("vis,name,width,scan_ms", [
    (93, "PD50", 320, 91.520),
    (99, "PD90", 320, 170.240),
    (95, "PD120", 640, 121.600),
])
def test_pd_modes_exact_two_line_yuv_superline(vis, name, width, scan_ms):
    audio, (y0, y1, red_y, blue_y) = pd_fixture(vis, scan_ms)
    frame = sstv.decode_sstv(audio, sample_rate=RATE, max_lines=2)
    assert frame.mode.name == name and frame.pixels.shape == (2, width, 3)
    np.testing.assert_array_equal(
        frame.pixels[0], np.tile(reference_yuv(y0, red_y, blue_y), (width, 1)))
    np.testing.assert_array_equal(
        frame.pixels[1], np.tile(reference_yuv(y1, red_y, blue_y), (width, 1)))


def wav_bytes(samples, rate=RATE):
    pcm = np.clip(np.rint(samples * 32767), -32768, 32767).astype("<i2").tobytes()
    output = io.BytesIO()
    with wave.open(output, "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(rate)
        handle.writeframes(pcm)
    return output.getvalue()


def test_declared_error_contract_for_bad_header_truncation_and_options():
    writer = ToneWriter()
    header(writer, 60, bad_parity=True)
    writer.tone(1200, 9)
    with pytest.raises(sstv.RF2SSTVError):
        sstv.decode_sstv(writer.finish(), sample_rate=RATE)
    valid, _ = scottie_fixture(60, 138.240)
    with pytest.raises(sstv.RF2SSTVError):
        sstv.decode_sstv(valid[:-100], sample_rate=RATE, max_lines=1)
    for source, kwargs in ((np.array([]), {"sample_rate": RATE}),
                           (np.array([np.nan]), {"sample_rate": RATE}),
                           (valid, {"sample_rate": RATE, "max_lines": 0}),
                           (valid, {"sample_rate": RATE,
                                    "max_lines": sstv.MAX_LINES + 1}),
                           (valid, {"sample_rate": RATE, "expected_mode": "PD120"})):
        with pytest.raises(sstv.RF2SSTVError):
            sstv.decode_sstv(source, **kwargs)
    for bad in (None, True, {}, "Martin M1", "x" * 1000):
        with pytest.raises(sstv.RF2SSTVError):
            sstv.mode_spec(bad)


def test_guarded_cli_wav_to_ppm(tmp_path, capsys):
    audio, _ = scottie_fixture(56, 88.064)
    source = tmp_path / "scottie.wav"
    output = tmp_path / "decoded.ppm"
    source.write_bytes(wav_bytes(audio))
    assert sstv.main([str(source), "--mode", "Scottie S2", "--max-lines", "1",
                      "--output", str(output), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report == {"complete": False, "height": 1, "mode": "Scottie S2",
                      "sample_rate": RATE, "vis": 56, "width": 320}
    assert output.read_bytes().startswith(b"P6\n320 1\n255\n")
    assert sstv.main(["--help"]) == 0
    assert sstv.main([]) == 2

