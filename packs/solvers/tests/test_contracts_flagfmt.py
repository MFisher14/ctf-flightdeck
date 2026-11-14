"""B-001 contracts: ctf.flagfmt, the single flag/proof format source, on the shipped profiles."""
from __future__ import annotations

import pytest

from ctf import event, flagfmt

HEX = "0123456789abcdef" * 2


@pytest.fixture(scope="module")
def ff():
    return {s: flagfmt.for_profile(event.load(s)) for s in ("huntress", "csctf", "pink", "spooky")}


def test_huntress_exact_hex_body(ff):
    h = ff["huntress"]
    assert h.is_flag(f"flag{{{HEX}}}")
    assert h.is_flag(f"  flag{{{HEX}}}\n")                       # surrounding whitespace ignored
    assert not h.is_flag(f"FLAG{{{HEX}}}")                       # case exact
    assert not h.is_flag(f"flag{{{HEX[:-1]}}}")                  # 31 hex
    assert not h.is_flag(f"flag{{{HEX.upper()}}}")
    assert h.find_flags(f"x flag{{{HEX}}} y") == [f"flag{{{HEX}}}"]


def test_left_boundary_blocks_embedded_prefixes(ff):
    c = ff["csctf"]
    assert c.find_flags("aCSCTF{x} _CTF{y} 9flag{z}") == []
    assert c.find_flags("(CSCTF{x})") == ["CSCTF{x}"]
    # CSS-like text never matches: the prefix list is literal
    assert c.find_flags("body{color:red} a{b}") == []


def test_prefix_insensitive_matches_and_normalizes(ff):
    c = ff["csctf"]
    hits = c.find_flags("csctf{L33t_Hax} then CTF{other} then Chronos{z}")
    assert hits == ["csctf{L33t_Hax}", "CTF{other}", "Chronos{z}"]
    assert c.normalize(" csctf{L33t_Hax} ") == "CSCTF{L33t_Hax}"
    assert c.normalize("CHRONOS{z}") == "chronos{z}"             # the profile's spelling
    assert c.normalize("CSCTF{Body}") != c.normalize("CSCTF{body}")   # body stays case-exact


def test_longer_prefix_preferred_and_csctf_body_allows_spaces(ff):
    assert ff["csctf"].find_flags("CSCTF{two words}") == ["CSCTF{two words}"]


def test_pink_exact_case(ff):
    p = ff["pink"]
    assert p.find_flags("PINK{a_b!} pink{no}") == ["PINK{a_b!}"]


def test_dedupe_preserves_first_order(ff):
    p = ff["pink"]
    assert p.find_flags("PINK{b} PINK{a} PINK{b}") == ["PINK{b}", "PINK{a}"]


def test_bytes_input(ff):
    h = ff["huntress"]
    # bytes: no left boundary (binary has no word boundaries); text keeps it
    blob = b"\x00\xffjunk" + f"flag{{{HEX}}}".encode() + b"\x00"
    assert h.find_flags(f"junkflag{{{HEX}}}") == []
    assert h.find_flags(blob) == [f"flag{{{HEX}}}"]
    assert h.find_flags(bytearray(blob)) == [f"flag{{{HEX}}}"]
    with pytest.raises(TypeError):
        h.find_flags(123)


def test_normalize_refuses_non_flags(ff):
    with pytest.raises(ValueError):
        ff["pink"].normalize("not a flag")


def test_proof_tokens(ff):
    h = ff["huntress"]
    assert h.find_proofs(f"<p>proof_{HEX}</p>") == [f"proof_{HEX}"]
    assert h.find_proofs(f"xproof_{HEX}") == []                  # left boundary
    assert h.find_proofs(f"proof_{HEX}0") == []                  # right boundary: 33 hex is not a proof
    assert h.find_proofs(f"xxproof_{HEX}\x00".encode()) == [f"proof_{HEX}"]   # bytes: no left boundary
    assert h.find_proofs(f"proof_{HEX}0".encode()) == []         # ... but the right one stays
    assert h.is_proof(f"proof_{HEX}") and not h.is_flag(f"proof_{HEX}")
    with pytest.raises(LookupError, match="no \\[proof\\]"):
        ff["pink"].find_proofs("x")


def test_unknown_format_matches_any_word_prefix():
    spec = event.FlagSpec(prefixes=())
    f = flagfmt.FlagFormat(spec)
    assert not f.known
    assert f.find_flags("got Wh4t{ever} and x") == ["Wh4t{ever}"]


def test_insensitive_case():
    f = flagfmt.FlagFormat(event.FlagSpec(prefixes=("ctf",), body="[a-z]+", case="insensitive"))
    assert f.find_flags("CTF{ABC}") == ["CTF{ABC}"]
    assert f.normalize("CTF{ABC}") == "ctf{abc}"


def test_module_functions_follow_current_event(monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "pink")
    assert flagfmt.find_flags("PINK{x} CSCTF{y}") == ["PINK{x}"]
    assert flagfmt.is_flag("PINK{x}") and not flagfmt.is_flag("CSCTF{y}")
    monkeypatch.setenv("CTF_EVENT", "csctf")
    assert flagfmt.find_flags("PINK{x} CSCTF{y}") == ["CSCTF{y}"]
    assert flagfmt.normalize("csctf{y}") == "CSCTF{y}"
