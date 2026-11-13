"""hash_identify: identify a hash/token string and name its hashcat/john modes."""
from __future__ import annotations

import pytest

import hash_identify as hi


def _names(results):
    return [r["name"] for r in results]


def test_md5():
    r = hi.identify("5d41402abc4b2a76b9719d911017c592")
    assert "MD5" in _names(r) and "NTLM" in _names(r)
    md5 = next(x for x in r if x["name"] == "MD5")
    assert md5["hashcat_mode"] == 0


def test_sha1_sha256_sha512_by_length():
    assert "SHA-1" in _names(hi.identify("a" * 40))
    assert "SHA-256" in _names(hi.identify("a" * 64))
    assert "SHA-512" in _names(hi.identify("a" * 128))
    assert next(x for x in hi.identify("a" * 64) if x["name"] == "SHA-256")["hashcat_mode"] == 1400


def test_bcrypt_structural():
    h = "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"
    r = hi.identify(h)
    top = r[0]
    assert top["name"] == "bcrypt" and top["confidence"] == "high" and top["hashcat_mode"] == 3200


def test_sha512crypt_structural():
    h = "$6$" + "rounds=5000$" + "saltsalt$" + "a" * 86
    r = hi.identify(h)
    assert r[0]["name"] == "sha512crypt" and r[0]["hashcat_mode"] == 1800


def test_jwt():
    tok = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.c2lnbmF0dXJldmFsdWVoZXJl"
    r = hi.identify(tok)
    assert any("JWT" in n for n in _names(r))


def test_netntlmv2_and_ntlm_pair():
    v2 = "admin::WORKGROUP:" + "1" * 48 + ":" + "a" * 48 + ":" + "b" * 16
    assert "NetNTLMv2" in _names(hi.identify(v2))
    pair = "a" * 32 + ":" + "b" * 32
    assert any("NTLM" in n for n in _names(hi.identify(pair)))


def test_unknown_and_fail_closed():
    assert hi.identify("") == []
    assert hi.identify("   ") == []
    assert hi.identify(12345) == []
    r = hi.identify("not-a-hash!@#$%")
    assert r and r[0]["name"] == "unknown"


def test_cli(capsys):
    assert hi.main(["5d41402abc4b2a76b9719d911017c592"]) == 0
    assert "MD5" in capsys.readouterr().out
    rc = hi.main(["a" * 64, "--json"])
    assert rc == 0
    import json
    out = json.loads(capsys.readouterr().out)
    assert any(x["name"] == "SHA-256" for x in out)
    assert hi.main(["--help"]) == 0
