"""Independent RGB vectors from Brainloller and Braincopter specifications.

https://esolangs.org/wiki/Brainloller
https://esolangs.org/wiki/Braincopter
These tests transcribe images; they never execute the contained Brainfuck.
"""
import io
import random
import socket
import subprocess

from PIL import Image
import pytest
import encdepth_image_esolang as engine


def png(rows):
    image = Image.new("RGB", (len(rows[0]), len(rows)))
    image.putdata([pixel for row in rows for pixel in row])
    out = io.BytesIO()
    image.save(out, format="PNG")
    return out.getvalue()


@pytest.fixture(autouse=True)
def offline_only(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("unexpected external execution or network")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)


def test_brainloller_all_commands_and_comment():
    colors = [(255, 0, 0), (128, 0, 0), (0, 255, 0), (0, 128, 0),
              (0, 0, 255), (0, 0, 128), (255, 255, 0), (128, 128, 0), (1, 2, 3)]
    report = engine.transcribe(png([colors]), dialect="brainloller")
    assert report["source"] == "><+-.,[]"
    assert report["source_coordinates"] == [[x, 0] for x in range(8)]
    assert (report["comments"], report["path_pixels"], report["exit"]) == (1, 9, [9, 0])
    assert report["executed"] is False


def test_braincopter_weighted_rgb_residues():
    # 65536*3 + 256*5 = 197888; choose B independently for residues 0..7,10.
    residues = list(range(8)) + [10]
    colors = [(3, 5, (residue - 197888) % 11) for residue in residues]
    report = engine.transcribe(png([colors]), dialect="braincopter")
    assert report["source"] == "><+-.,[]"
    assert report["comments"] == 1


def test_clockwise_and_counterclockwise_geometry():
    white, plus, dot = (255, 255, 255), (0, 255, 0), (0, 0, 255)
    raw = png([[plus, (0, 255, 255), white],
               [white, (0, 128, 128), dot]])
    report = engine.transcribe(raw, dialect="brainloller")
    assert report["source"] == "+."
    assert report["source_coordinates"] == [[0, 0], [2, 1]]
    assert report["turns"] == 2 and report["exit"] == [3, 1]


@pytest.mark.parametrize("field,limit", [("MAX_FILE", 8), ("MAX_PIXELS", 1),
    ("MAX_SOURCE", 1), ("MAX_PATH", 1)])
def test_explicit_small_resource_caps(monkeypatch, field, limit):
    raw = png([[(0, 255, 0)] * 3])
    monkeypatch.setattr(engine, field, limit)
    with pytest.raises(engine.ImageEsolangError):
        engine.transcribe(raw, dialect="brainloller")


def test_deterministic_image_fuzz_and_malformed_arguments():
    valid = png([[(0, 255, 0), (0, 0, 255)]])
    rng = random.Random(899)
    corpus = [b"", b"\xff" * 100, None, "png", valid + b"TRAILER"]
    corpus += [valid[:i] for i in (1, 8, 20, 33, len(valid) - 8)]
    for _ in range(30):
        mutated = bytearray(valid)
        mutated[rng.randrange(len(mutated))] ^= 1 << rng.randrange(8)
        corpus.append(bytes(mutated))
        corpus.append(rng.randbytes(64))
    for raw in corpus:
        try:
            engine.transcribe(raw, dialect="brainloller")
        except engine.ImageEsolangError:
            pass
    for dialect in (None, [], "other"):
        with pytest.raises(engine.ImageEsolangError):
            engine.transcribe(valid, dialect=dialect)
    for color in ((255, 255, 0), (128, 128, 0)):
        with pytest.raises(engine.ImageEsolangError):
            engine.transcribe(png([[color]]), dialect="brainloller")


def test_cli_guards_and_transcription(tmp_path, capsys):
    path = tmp_path / "source.png"
    path.write_bytes(png([[(0, 255, 0), (0, 0, 255)]]))
    assert engine.main([str(path), "--dialect", "brainloller", "--source"]) == 0
    assert capsys.readouterr().out.strip() == "+."
    assert engine.main([]) == 2
    assert engine.main(["--help"]) == 0
