#!/usr/bin/env python3
"""B-230: the Warmups cumulative decoder pack (crib_decode).

  .venv/bin/python -m pytest tests/test_b230_decoder_pack.py

No network, no token, no challenge binary; every fixture is built synthetically in the test. The
item folds the decoder families into ONE pass of crib_decode's strict search: a warmup blob is tried
against every family at once, behind the built-in readers, under the per-blob budget, the CAP state
cap and the 1 MiB skip that were already present. This file locks:

  * the manual-code families codec_decoders adds that the built-in battery lacked (a 5x5 Polybius
    square, standard A/B Bacon, DTMF/multitap) are now read in the one pass, and are NOT read with the
    fold removed (the non-tautological counterpart);
  * the fold never shadows a reading the built-ins already reach (base64 still reads as `b64`);
  * the 1 MiB skip gates the whole pack (an over-MAX_BLOB blob a family could read is refused first);
  * register_family / unregister_family are the extension point B-250 hooks, and a family registered
    through it is both searched (_strict_steps) and replayable (_step_fn);
  * the spec's own warmup families -- strict baconhex, run-length (count:char), the rail-fence /
    transposition-aware day-walk vouch, and the cumulative per-record day-walk -- sit in the one pass.
"""
import atexit
import base64
import contextlib
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
for _p in (REPO / "solvers" / "common", REPO / "solvers" / "warmups"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

_ROOT = Path(tempfile.mkdtemp(prefix="b230-"))
atexit.register(shutil.rmtree, _ROOT, True)
(_ROOT / "_ledger").mkdir(parents=True)
os.environ["CTF_WORKDIR"] = str(_ROOT)
os.environ["CTF_TESTING"] = "1"
os.environ.setdefault("CTF_EVENT", "huntress")   # the flag-format path (solve_blob) resolves a profile
os.environ.pop("CTF_TOKEN", None)

import crib_decode as C  # noqa: E402

MSG = b"HELLOWORLD"


# --- fixtures for the three manual-code families (independent of the module under test) --------------

def polybius_fixture(text: str) -> bytes:
    square = "ABCDEFGHIKLMNOPQRSTUVWXYZ"   # 5x5, I/J share a cell, no J
    out = []
    for ch in text:
        i = square.index("I" if ch == "J" else ch)
        out.append("%d%d" % (i // 5 + 1, i % 5 + 1))
    return " ".join(out).encode()


def bacon_fixture(text: str) -> bytes:
    bits = "".join(format(ord(c) - 65, "05b") for c in text)   # 26-letter Bacon, A=00000
    return bits.translate(str.maketrans("01", "AB")).encode()


def dtmf_fixture(text: str) -> bytes:
    keys = {"2": "ABC", "3": "DEF", "4": "GHI", "5": "JKL", "6": "MNO",
            "7": "PQRS", "8": "TUV", "9": "WXYZ"}
    inv = {ch: key * (n + 1) for key, group in keys.items() for n, ch in enumerate(group)}
    return " ".join(inv[c] for c in text).encode()


@contextlib.contextmanager
def codec_pack_removed():
    """Run with the codec_decoders family unfolded, then restore it."""
    fam = C._CD_FAMILY
    C.unregister_family(fam)
    try:
        yield
    finally:
        C._CD_FAMILY = C.register_family("codec_decoders", C._CD_ADD_SET, C._cd_steps, C._cd_step_fn)


def strict_read(blob: bytes, want: bytes):
    """The names under which the one-pass strict search reads `blob` to exactly `want`."""
    return [name for name, out in C._strict_steps(blob) if out == want]


# --- the fold -------------------------------------------------------------------------------------

def test_the_pack_is_one_fold_over_the_builtin_battery():
    # B-250 folds its residual readers in through the same hook, after codec_decoders.
    # (a set: codec_pack_removed below re-registers codec_decoders, which moves it behind B-250's family)
    assert C.families()[0] == "built-in"
    assert sorted(C.families()[1:]) == ["codec_decoders", "warmup_residuals"]
    assert set(C._CD_ADD_SET) == {"polybius", "bacon", "dtmf-text"}
    for name in C._CD_ADD_SET:
        assert name in C._STRICT_NAMES, name
        assert name not in C._BUILTIN_STRICT_NAMES, "%s must be new, not a built-in" % name


def test_the_new_manual_codes_are_read_in_the_one_pass():
    assert "polybius" in strict_read(polybius_fixture("HELLOWORLD"), MSG)
    assert "bacon" in strict_read(bacon_fixture("HELLOWORLD"), MSG)
    assert "dtmf-text" in strict_read(dtmf_fixture("HELLOWORLD"), MSG)
    # polybius reads a single value, so it is replayable in a chain (the day walk can carry it).
    fn = C._step_fn("polybius")
    assert fn is not None and fn(polybius_fixture("HELLOWORLD")) == MSG


def test_without_the_fold_the_manual_codes_are_unread():
    # The counterpart that fails if the fold is a no-op: with codec_decoders unfolded, the built-in
    # battery reaches none of the three, so each fixture goes unread.
    with codec_pack_removed():
        assert "codec_decoders" not in C.families()
        assert strict_read(polybius_fixture("HELLOWORLD"), MSG) == []
        assert strict_read(bacon_fixture("HELLOWORLD"), MSG) == []
        assert strict_read(dtmf_fixture("HELLOWORLD"), MSG) == []
    # restored
    assert "codec_decoders" in C.families()
    assert "polybius" in strict_read(polybius_fixture("HELLOWORLD"), MSG)


def test_the_fold_never_shadows_a_builtin_reading():
    # A plain base64 blob keeps the simpler built-in chain name `b64`; the pack yields behind it.
    plain = b"grab the flag{0123456789abcdef0123456789abcdef} now"
    got = C.solve_blob(base64.b64encode(plain), budget=4.0)
    assert got is not None and got[0] == "flag{0123456789abcdef0123456789abcdef}"
    assert got[1] == [["b64"]], got[1]


def test_the_one_mib_skip_gates_the_whole_pack():
    assert C.MAX_BLOB == 1 << 20
    # A polybius blob the pack reads when small ...
    small = polybius_fixture("HELLOWORLD")
    assert "polybius" in strict_read(small, MSG)
    # ... but one byte over the cap is refused before any family (or any reader) runs.
    oversized = b"11 " * (C.MAX_BLOB // 3 + 1)
    assert len(oversized) > C.MAX_BLOB
    assert C.solve_blob(oversized, budget=4.0) is None
    assert "more than is read" in (C.LAST.get("note") or "")


# --- the B-250 extension point --------------------------------------------------------------------

def test_register_family_is_the_extension_point_b250_hooks():
    # A synthetic residual family: a sentinel-tagged repeating-key XOR (a multi-byte key, which the built-in
    # battery never auto-searches), the shape B-250 registers for its own keyed-digit / ITA1 / DTMF-re-entry
    # readers. Nothing else reads the sentinel-prefixed blob.
    sentinel = b"B230\x00"
    key = b"\x11\x22\x33"

    def unxor(body):
        return bytes(x ^ key[i % len(key)] for i, x in enumerate(body))

    def probe_steps(blob):
        if isinstance(blob, (bytes, bytearray)) and bytes(blob[:5]) == sentinel:
            yield "b230probe", unxor(bytes(blob[5:]))

    def probe_step_fn(name):
        if name == "b230probe":
            return lambda blob: unxor(bytes(blob[5:])) if bytes(blob[:5]) == sentinel else None
        return None

    plain = b"here is flag{0123456789abcdef0123456789abcdef} ok"
    blob = sentinel + unxor(plain)   # unxor is its own inverse per position

    assert C.solve_blob(blob, budget=4.0) is None, "precondition: the probe family is not yet folded in"

    fam = C.register_family("b250-probe", {"b230probe"}, probe_steps, probe_step_fn)
    try:
        assert "b250-probe" in C.families()
        assert "b230probe" in C._STRICT_NAMES
        assert C._step_fn("b230probe") is not None
        assert "b230probe" in strict_read(blob, plain)
        got = C.solve_blob(blob, budget=4.0)
        assert got is not None and got[0] == "flag{0123456789abcdef0123456789abcdef}"
        assert "b230probe" in got[1][0]
    finally:
        C.unregister_family(fam)
    assert "b250-probe" not in C.families()
    assert "b230probe" not in C._STRICT_NAMES
    assert C._step_fn("b230probe") is None
    assert C.solve_blob(blob, budget=4.0) is None


def test_register_family_rejects_a_claimed_name():
    # register_family's collision guard: a family claiming a name a built-in reader already owns ('b64') or
    # a name an earlier folded family owns ('polybius', from codec_decoders) is refused loudly, not folded
    # in to be searched-but-never-replayed. Without the guard the colliding family is appended silently.
    assert "b64" in C._STRICT_NAMES          # a built-in strict reader
    assert "polybius" in C._STRICT_NAMES     # owned by the codec_decoders family
    before = list(C.families())
    for label, name in (("b230-clash-builtin", "b64"), ("b230-clash-family", "polybius")):
        with pytest.raises(ValueError) as exc:
            C.register_family(label, {name}, lambda b: iter(()), lambda n: None)
        assert name in str(exc.value)
        assert C.families() == before        # nothing was folded in on the rejected call
    # a non-colliding family still registers (the guard is not a blanket refusal)
    fam = C.register_family("b230-fresh", {"b230freshstep"}, lambda b: iter(()), lambda n: None)
    try:
        assert "b230-fresh" in C.families()
    finally:
        C.unregister_family(fam)
    assert C.families() == before


def test_unregister_reranks_a_chain_as_loose():
    # Kills the _rank.cache_clear() in _refresh_family_names. _rank is lru-cached and reads _STRICT_NAMES at
    # call time, so a chain ranked while a family owns its name caches a 0-loose rank. Once the family is
    # unregistered the same chain must re-rank with that step counted loose -- which only holds because
    # register/unregister clear the _rank cache. Drop the cache_clear and the stale 0-loose rank survives.
    name = "b230rankprobe"
    assert name not in C._STRICT_NAMES
    fam = C.register_family("b230-rank", {name}, lambda b: iter(()), lambda n: None)
    try:
        assert name in C._STRICT_NAMES
        assert C._rank((name,)) == (0, 1)   # the folded name counts as a strict (non-loose) step
    finally:
        C.unregister_family(fam)
    assert name not in C._STRICT_NAMES
    assert C._rank((name,)) == (1, 1)       # once unfolded the same chain's step is loose again


# --- the spec's own warmup families, all in the one pass -------------------------------------------

def _baconhex(data: bytes) -> bytes:
    """Hex nibbles as width-5 a/b groups, a = 0 (the shipped strict baconhex reader's input)."""
    out = []
    for byte in data:
        for nibble in (byte >> 4, byte & 0xF):
            out.append("".join("a" if bit == "0" else "b" for bit in format(nibble, "05b")))
    return "".join(out).encode()


def test_strict_baconhex_is_in_the_one_pass():
    text = b"baconhex_reads!!"   # >= BACONHEX_FLOOR bytes, printable ASCII
    assert len(text) >= C.BACONHEX_FLOOR
    assert "baconhex" in C._STRICT_NAMES
    fn = C._step_fn("baconhex")
    assert fn is not None and fn(_baconhex(text)) == text


def test_run_length_count_char_is_in_the_one_pass():
    assert "runlength" in C._STRICT_NAMES
    blob = b"3:a,1:b,2:c,"   # count:char groups -> "aaabcc"
    fn = C._step_fn("runlength")
    assert fn is not None and fn(blob) == b"aaabcc"


def test_the_day_walk_vouch_accepts_a_rail_fence_transposition():
    # Day 23's residual: the day-walk vouch must accept a transposition record (rail fence), not only a
    # rotation, when the whole sentence is reconstructed.
    assert C._is_transposition(("rail:3.0",)) is True
    assert C._is_transposition(("columnar:2.0.1", "b64")) is True
    assert C._is_transposition(("rot13",)) is False   # a letter cipher is checked by its letters, not shape


def test_the_cumulative_per_record_day_walk_is_present():
    # The per-record, per-day codec search with whole-sentence ranking (Day 4/5) -- the entry points the
    # delivery and the consensus read through, and that B-250's residuals build on.
    for name in ("_day_walk", "_by_days", "_consensus_records", "_walk_slug"):
        assert callable(getattr(C, name)), name


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
