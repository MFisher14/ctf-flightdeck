#!/usr/bin/env python3
"""The reversible-envelope peeler (solvers/common/unwrap.py) and its two wirings.

  .venv/bin/python -m pytest tests/test_envelope_peel.py -q
  .venv/bin/python -I tests/test_envelope_peel.py          # accept.sh runs it as a plain script

The "same challenge, base64-wrapped" class: a whole delivery / member re-encoded as a thin reversible
envelope (base64/base32/base85/hex/url/PEM/data-URI/gzip/zlib/raw-deflate/bz2/xz/byteswap/reversed, and
one 2-level nest), or -- for warmups -- an XOR layer (single-byte, or a repeating key recovered from the
crib) re-fed through the codec battery. This file proves, adversarially:

  * every envelope in the battery is peeled to the exact inner bytes, MAGIC-GATED;
  * a garbage / non-envelope input is NEVER peeled (no false decode) -- the bright line;
  * run.expand reveals the inner container of a wrapped delivery, and leaves an envelope-free delivery
    byte-for-byte unchanged (zero moved answers);
  * crib_decode turns an XOR-envelope warmup (which the shipped chain missed, XOR being a terminal step)
    into a crib-proven solve, while a wrong XOR / random blob stays None.

No network and no token.
"""
import base64
import bz2
import gzip
import io
import lzma
import os
import sys
import tempfile
import zipfile
import zlib
from pathlib import Path

try:
    import pytest
except ImportError:
    class _Skip(Exception):
        pass

    class pytest:  # noqa: N801
        Skipped = _Skip

        @staticmethod
        def skip(reason=""):
            raise _Skip(reason)

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.path.insert(0, str(REPO / "solvers" / "warmups"))
import unwrap  # noqa: E402

INNER = b"PK\x03\x04" + b"a zip body of some length " * 6   # a recognizable (zip-magic) inner artifact
ELF = b"\x7fELF" + os.urandom(400)
CRIB = b"Nice work decoding this warmup! To solve, submit this exact answer to the Game Master: "
PLAIN = CRIB + b"brave-silver-otter-42"


def _raw_deflate(data: bytes) -> bytes:
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def _byteswap16(b: bytes) -> bytes:
    return bytes(bytearray(x for pair in zip(b[1::2], b[0::2]) for x in pair))


def _x1(b, k):
    return bytes(x ^ k for x in b)


def _xk(b, key):
    return bytes(x ^ key[i % len(key)] for i, x in enumerate(b))


def _recovers(wrapped, inner=INNER, **kw):
    return any(bytes(d) == inner for d, _ in unwrap.peel(wrapped, **kw))


# ---------------------------------------------------------------- the battery

def test_battery_single_layer():
    cases = {
        "base64": base64.b64encode(INNER),
        "base64-76col": base64.encodebytes(INNER),
        "base64url": base64.urlsafe_b64encode(INNER).rstrip(b"=") + b"=",
        "base32": base64.b32encode(INNER),
        "base85": base64.b85encode(INNER),
        "ascii85": base64.a85encode(INNER),
        "base16-upper": base64.b16encode(INNER),
        "hex-lower": INNER.hex().encode(),
        "url": b"".join(b"%%%02X" % c for c in INNER),
        "pem": b"-----BEGIN BLOB-----\n" + base64.encodebytes(INNER) + b"-----END BLOB-----\n",
        "data-uri": b"data:application/octet-stream;base64," + base64.b64encode(INNER),
        "gzip": gzip.compress(INNER),
        "zlib": zlib.compress(INNER),
        "raw-deflate": _raw_deflate(INNER),
        "bz2": bz2.compress(INNER),
        "xz": lzma.compress(INNER),
        "reverse": INNER[::-1],
        "byteswap16": _byteswap16(INNER),
    }
    missed = [n for n, w in cases.items() if not _recovers(w)]
    assert not missed, f"these envelopes were not peeled: {missed}"
    return f"{len(cases)} envelope kinds peeled to the exact inner bytes"


def test_two_level_nest():
    assert _recovers(base64.b64encode(gzip.compress(INNER)))
    assert _recovers(gzip.compress(base64.b64encode(INNER)))
    assert _recovers(base64.b64encode(base64.b64encode(INNER)))
    assert _recovers(zlib.compress(INNER).hex().encode())
    return "base64(gzip), gzip(base64), base64(base64), hex(zlib) all reach the inner zip"


def test_elf_endpoint():
    assert any(bytes(d) == ELF for d, _ in unwrap.peel(base64.b64encode(ELF)))
    return "a base64-wrapped ELF is recognized by its magic"


# ---------------------------------------------------------------- the bright line: no false peel

def test_garbage_never_peeled():
    for _ in range(40):
        assert unwrap.peel(os.urandom(4096)) == []
    return "random bytes are never peeled (40 trials)"


def test_non_envelope_bytes_never_peeled():
    # valid base64/hex of RANDOM data decodes cleanly but is not a container -> not peeled
    assert unwrap.peel(base64.b64encode(os.urandom(300))) == []
    assert unwrap.peel(os.urandom(300).hex().encode()) == []
    # a binary member with a stray %XX must not be url-"peeled" (its head magic would survive)
    cls = b"\xca\xfe\xba\xbe" + os.urandom(60) + b"%41%42%43" + os.urandom(60)
    assert cls[:4] in unwrap.MAGICS  # it IS a java-class magic, yet unchanged bytes are not re-peeled
    assert all(bytes(d) != cls for d, _ in unwrap.peel(cls))
    # plain english text is not an envelope
    assert unwrap.peel(b"the quick brown fox jumps over the lazy dog. " * 8) == []
    return "valid-but-non-container decodes, stray-%XX binary, and plain text are all left alone"


def test_recognize_predicate():
    # a caller-supplied clean-parse predicate gates peeling instead of the magic default
    marker = b"SCHEMA::" + b"x" * 40
    wrapped = base64.b64encode(marker)
    hit = unwrap.peel(wrapped, recognize=lambda b: b.startswith(b"SCHEMA::"))
    assert any(bytes(d) == marker for d, _ in hit)
    assert unwrap.peel(wrapped) == []   # not a magic, so the default recognizer declines it
    return "a custom recognizer gates peeling; the default declines a non-magic payload"


# ---------------------------------------------------------------- XOR re-entry (warmups)

def test_xor_reentry_peel():
    cases = {
        "single-byte xor": _x1(PLAIN, 0x5a),
        "repeating-key xor": _xk(PLAIN, b"KEY"),
        "xor-then-base64": base64.b64encode(_x1(PLAIN, 0x33)),
        "base64-then-xor": _x1(base64.b64encode(PLAIN), 0x7f),
        "hex-then-xor": _x1(PLAIN.hex().encode(), 0x41),
    }
    missed = []
    for name, w in cases.items():
        res = unwrap.peel(w, crib=CRIB, try_xor=True, max_nodes=8000)
        if not any(CRIB in d for d, _ in res):
            missed.append(name)
    assert not missed, f"XOR envelopes not re-entered: {missed}"
    return f"{len(cases)} XOR-envelope directions re-fed through the codecs, full crib survives"


def test_xor_wrong_key_no_false_crib():
    # a DIFFERENT plaintext XOR-wrapped must not manufacture our crib; random bytes neither
    other = _x1(b"some entirely different message that is quite long indeed " * 2, 0x5a)
    assert not any(CRIB in d for d, _ in unwrap.peel(other, crib=CRIB, try_xor=True, max_nodes=8000))
    assert not any(CRIB in d for d, _ in unwrap.peel(os.urandom(200), crib=CRIB, try_xor=True, max_nodes=8000))
    return "a wrong XOR key / random blob never reproduces the crib"


def test_crib_decode_solves_xor_envelope():
    import crib_decode as C
    if C.UW is None:
        pytest.skip("unwrap not importable from crib_decode")
    # the genuinely-new class the shipped chain missed: XOR outer, codec inner
    got = C.solve_blob(_x1(base64.b64encode(PLAIN), 0x7f), budget=1.0)
    assert got is not None and got[0] == "brave-silver-otter-42", f"got {got!r}, route {C.LAST.get('route')}"
    assert C.LAST.get("route") == "envelope"
    # a random blob stays None
    assert C.solve_blob(os.urandom(120), budget=1.0) is None
    # a plain (un-wrapped) base64 warmup is still solved by the main path, not the envelope backstop
    got2 = C.solve_blob(base64.b64encode(PLAIN), budget=1.0)
    assert got2 is not None and got2[0] == "brave-silver-otter-42"
    assert C.LAST.get("route") != "envelope", "the envelope backstop must not shadow the main path"
    return "crib_decode solves an XOR envelope (route=envelope), stays None on garbage, main path unshadowed"


# ---------------------------------------------------------------- run.expand wiring

def _expand():
    os.environ.setdefault("CTF_STATE_DIR", tempfile.mkdtemp(prefix="envpeel_state_"))
    os.environ["CTF_QUIET"] = "1"
    os.environ.pop("CTF_PLATFORM_URL", None)
    sys.path.insert(0, str(REPO / "tools"))
    # run.py loads solvers/common/archive_passwords.py and unwrap.py itself at import; the old Game
    # Master client (tools/gm.py) was stripped under CSCTF jeopardy, so no `import gm` here.
    import run  # noqa: E402
    return run


def _zip_delivery():
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_STORED) as z:
        z.writestr("flag.txt", "the answer is here")
    return b.getvalue()


def test_expand_peels_wrapped_delivery():
    run = _expand()
    assert run.unwrap is not None, "run.py did not load solvers/common/unwrap.py"
    z = _zip_delivery()
    for label, wrapped in [("base64", base64.b64encode(z)), ("gzip", gzip.compress(z)),
                           ("hex", z.hex().encode())]:
        out = {}
        run.expand(f"delivery.{label}", wrapped, out)
        assert any(k.endswith("flag.txt") and b"the answer is here" in v for k, v in out.items()), \
            f"{label}-wrapped zip: inner member not revealed; keys={list(out)}"
    return "run.expand reveals the inner member of a base64 / gzip / hex-wrapped zip"


def test_expand_leaves_plain_delivery_unchanged():
    run = _expand()
    z = _zip_delivery()
    out_plain = {}
    run.expand("evidence.zip", z, out_plain)
    # a non-envelope binary blob gets no extra keys
    out_bin = {}
    run.expand("sample.bin", bytes(range(256)) * 20, out_bin)
    assert list(out_bin) == ["sample.bin"], f"a non-envelope binary grew keys: {list(out_bin)}"
    # the plain zip has no [unwrap:...] keys
    assert not any("[unwrap:" in k for k in out_plain), f"a plain zip grew unwrap keys: {list(out_plain)}"
    return "an envelope-free delivery is left byte-for-byte as before (no [unwrap:] keys)"


if __name__ == "__main__":   # tools/accept.sh runs this as a plain script
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in tests:
        try:
            said = fn()
            print(f"ok    {fn.__name__}" + (f": {said}" if said else ""))
        except getattr(pytest, "Skipped", Exception) as e:
            print(f"skip  {fn.__name__}: {e}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {fn.__name__}: {type(e).__name__}: {e}")
    print("FAILED" if failed else "ok")
    sys.exit(1 if failed else 0)
