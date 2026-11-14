"""Hand-painted Piet programs using David Morgan-Mar's published command table.

https://dangermouse.net/esoteric/piet.html
No engine palette/table/encoder is used to generate a test program.
"""
import io
import random
import socket
import subprocess

from PIL import Image
import pytest
import piet as engine


def program(value=65, *, numeric=False, scale=1):
    # Light red block has exactly value codels. Transition to red pushes value.
    # Red -> light magenta: hue+5/lightness+2, out(char).
    # Red -> dark magenta: hue+5/lightness+1, out(number).
    # The last colour is a lopsided trap: none of its eight extreme exits can
    # reach the entry at (value+1,0), so the program terminates after printing.
    black = (0, 0, 0)
    final = (192, 0, 192) if numeric else (255, 192, 255)
    width = value + 5
    rows = [[black] * width for _ in range(3)]
    rows[0][:value] = [(255, 192, 192)] * value
    rows[0][value] = (255, 0, 0)
    rows[0][value + 1] = final
    rows[1][value + 1:value + 4] = [final] * 3
    rows[2][value:value + 4] = [final] * 4
    image = Image.new("RGB", (width, 3))
    image.putdata([p for row in rows for p in row])
    if scale != 1:
        image = image.resize((width * scale, 3 * scale), Image.Resampling.NEAREST)
    out = io.BytesIO()
    image.save(out, format="PNG")
    return out.getvalue()


@pytest.fixture(autouse=True)
def offline_only(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("unexpected external execution or network")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)


@pytest.mark.parametrize("value,scale", [(65, 1), (66, 3), (10, 1), (233, 1)])
def test_published_character_transition(value, scale):
    raw = program(value, scale=scale)
    assert engine.run_piet(raw, steps=40) == chr(value).encode("utf-8")
    assert engine.read_slug(raw, steps=40) is None


def test_published_numeric_transition():
    assert engine.run_piet(program(65, numeric=True), steps=40) == b"65"


def test_step_and_output_bounds(monkeypatch):
    assert engine.run_piet(program(), steps=1) is None
    # This two-colour row continually revisits itself; no halt is reachable.
    image = Image.new("RGB", (2, 1))
    image.putdata([(255, 192, 192), (255, 0, 0)])
    out = io.BytesIO()
    image.save(out, format="PNG")
    assert engine.run_piet(out.getvalue(), steps=50) is None
    monkeypatch.setattr(engine, "OUTPUT", 0)
    assert engine.run_piet(program(), steps=40) is None
    monkeypatch.setattr(engine, "TICK", 1)
    assert engine.run_piet(program(), steps=40, deadline=0) is None


def test_seeded_image_fuzz(monkeypatch):
    raw = program()
    rng = random.Random(801)
    corpus = [None, b"", b"\xff" * 300, b"x" * 8192, "wrong type"]
    corpus += [raw[:n] for n in (1, 8, 20, 33, len(raw) - 8)]
    for _ in range(30):
        mutated = bytearray(raw)
        mutated[rng.randrange(len(mutated))] ^= 1 << rng.randrange(8)
        corpus.append(bytes(mutated))
        corpus.append(rng.randbytes(100))
    for candidate in corpus:
        for function in (engine.run_piet, engine.read_slug):
            value = function(candidate, steps=100)
            assert value is None or isinstance(value, (bytes, str))
    # A small Pillow pixel ceiling exercises the decompression-bomb path safely.
    monkeypatch.setattr(Image, "MAX_IMAGE_PIXELS", 10)
    assert engine.run_piet(raw, steps=10) is None


@pytest.mark.parametrize("kwargs", [{"steps": None}, {"steps": "10"}, {"deadline": "x"}])
def test_malformed_limits_fail_closed(monkeypatch, kwargs):
    monkeypatch.setattr(engine, "TICK", 1)
    assert engine.run_piet(program(), **kwargs) is None
