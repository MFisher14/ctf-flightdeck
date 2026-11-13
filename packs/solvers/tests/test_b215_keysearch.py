"""B-215: the resumable key-search harness (solvers/common/keysearch.py, `ctf keysearch`).

Every fixture is built here: a key derived from a planted candidate by a known recipe, then a
ciphertext / tag / digest / zip made with it. The tests check that the space holds exactly the
candidates the spec describes, that each derivation and verifier computes what its reference does,
that a run is resumable chunk for chunk (budget stops, a crash after a chunk, a crash between a hit and
its chunk, a torn ledger line, SIGTERM), and that no plaintext candidate reaches the ledger or stdout.
CTF_WORKDIR points at a temp dir, so no real store or ledger is touched.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import itertools
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

import keysearch as ks
from ctf import paths as ctf_paths

REPO = ctf_paths.repo_root()
SECRET_WORD = "Qwertz"          # the planted atom; must never appear in a ledger line or stdout


@pytest.fixture(autouse=True)
def _workdir(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    yield


def _aes():
    from Crypto.Cipher import AES
    return AES


def _base_spec(verify: dict, *, kdf=("md5", "sha256"), key_len=16, chunk=8, words=("alpha", "qwertz", "beta"),
               case=("as-is", "title"), encodings=("utf8", "utf16le"), salts=None) -> dict:
    spec = {"key_len": key_len, "chunk": chunk, "kdf": list(kdf),
            "bank": [{"name": "words", "values": list(words), "case": list(case), "encodings": list(encodings)},
                     {"name": "sid", "values": ["S-1-5-21-7"]}],
            "template": [{"slots": ["sid", "words"], "seps": ["", ":"]}],
            "verify": verify}
    if key_len is None:
        del spec["key_len"]
    if salts is not None:
        spec["salts"] = list(salts)
    return spec


def _planted(sep=b":", word=SECRET_WORD, enc="utf-16-le") -> bytes:
    return b"S-1-5-21-7" + sep + word.encode(enc)


def _cbc_ct(key: bytes, pt: bytes = b"FLAG{found_it}", iv: bytes = bytes(range(16))) -> bytes:
    AES = _aes()
    pad = 16 - len(pt) % 16
    return iv + AES.new(key, AES.MODE_CBC, iv=iv).encrypt(pt + bytes([pad]) * pad)


def _make(tmp_path, spec, sid="t1", **kw) -> dict:
    return ks.create(sid, spec, base=tmp_path, root=tmp_path / "ks", **kw)


def _run(tmp_path, sid="t1", **kw) -> dict:
    lines = []
    res = ks.run(sid, root=tmp_path / "ks", out=lines.append, warn=lines.append, **kw)
    res["stdout"] = lines
    return res


def _ledger(tmp_path, sid="t1") -> list[dict]:
    return ks.read_progress(tmp_path / "ks" / sid)


def _chunks(records) -> list[int]:
    return [r["chunk"] for r in records if r["event"] == "keysearch.chunk"]


# ---------------------------------------------------------------------------- the space

def test_space_holds_exactly_the_candidates_the_spec_describes(tmp_path):
    key = hashlib.md5(_planted()).digest()
    job = _make(tmp_path, _base_spec({"kind": "hash", "target_hex": key.hex()}, kdf=["md5"]))
    space = ks.Space(job)
    words = []
    for w in ("alpha", "qwertz", "beta"):
        for t in (w, w.title()):
            for enc in ("utf-8", "utf-16-le"):
                words.append(t.encode(enc))
    words = list(dict.fromkeys(words))
    expected = {b"S-1-5-21-7" + sep + w for sep in (b"", b":") for w in words}
    got = [space.candidate(i) for i in range(space.total)]
    assert space.total == len(expected) == job["total"] == 24
    assert sorted(got) == sorted(expected)           # every candidate once: no gap, no repeat


def test_orders_all_adds_every_slot_order_once(tmp_path):
    spec = _base_spec({"kind": "hash", "target_hex": "00" * 16}, kdf=["md5"], words=["ab"], case=["as-is"],
                      encodings=["utf8"])
    spec["template"] = [{"slots": ["sid", "words"], "seps": ["-"], "orders": "all"}]
    space = ks.Space(_make(tmp_path, spec))
    assert sorted(space.candidate(i) for i in range(space.total)) == sorted([b"S-1-5-21-7-ab", b"ab-S-1-5-21-7"])


def test_each_salted_derivation_is_tried_once_per_salt(tmp_path):
    spec = _base_spec({"kind": "hash", "target_hex": "00" * 16}, kdf=["md5", "hmac:sha256"], words=["ab"],
                      case=["as-is"], encodings=["utf8"], salts=["s1", "s2"])
    space = ks.Space(_make(tmp_path, spec))
    # 2 candidates (two separators) x (md5 + hmac with 2 salts)
    assert space.total == 2 * 3
    assert sorted({space.recipe(i)["kdf"] for i in range(space.total)}) == ["hmac:sha256", "md5"]
    assert {space.recipe(i)["salt"] for i in range(space.total)} == {None, 0, 1}


def test_variants_case_encoding_nul_and_latin1_gaps():
    bank = {"name": "b", "values": ["Ab", "Łx"], "hex": ["00ff"], "files": [],
            "case": ["as-is", "upper"], "encodings": ["utf8", "utf16be", "latin1"], "nul": [False, True]}
    out = ks.expand_bank(bank)
    assert b"Ab" in out and b"AB" in out and b"\x00A\x00b" in out and b"Ab\x00" in out
    assert b"\x00A\x00b\x00\x00" in out                 # the NUL is encoded with the text
    assert "Łx".encode("utf-8") in out and "Łx".encode("latin-1", "replace") not in out
    assert b"\x00\xff" in out and b"\x00\xff\x00" not in out   # a hex atom is its exact bytes, no variants
    assert len(out) == len(set(out))


def test_a_wordlist_line_that_is_not_utf8_is_kept_as_its_own_bytes(tmp_path):
    wl = tmp_path / "words.txt"
    wl.write_bytes(b"caf\xe9\nplain\n\n")
    ref = ks._file_ref(wl, None)
    out = ks.expand_bank({"name": "w", "values": [], "hex": [], "files": [ref], "case": ["upper"],
                          "encodings": ["utf16le"], "nul": [False]})
    assert out == [b"caf\xe9", "PLAIN".encode("utf-16-le")]


def test_file_bank_limit_and_sha_pin(tmp_path):
    wl = tmp_path / "words.txt"
    wl.write_text("one\ntwo\nthree\n")
    spec = _base_spec({"kind": "hash", "target_hex": "00" * 16}, kdf=["md5"])
    spec["bank"][0] = {"name": "words", "file": "words.txt", "limit": 2}
    job = _make(tmp_path, spec)
    assert ks.Space(job).banks["words"] == [b"one", b"two"]
    wl.write_text("one\ntwo\nfour\n")                   # the list changed after the job was made
    with pytest.raises(ks.KeySearchError, match="changed since the job was made"):
        _run(tmp_path)


# ---------------------------------------------------------------------------- derivations

@pytest.mark.parametrize("spec, ref", [
    ("md5", lambda x, s: hashlib.md5(x).digest()),
    ("sha256", lambda x, s: hashlib.sha256(x).digest()),
    ("sha256*3", lambda x, s: hashlib.sha256(hashlib.sha256(hashlib.sha256(x).digest()).digest()).digest()),
    ("hmac:sha256", lambda x, s: hmac.new(x, s, "sha256").digest()),
    ("hmac-salt:sha1", lambda x, s: hmac.new(s, x, "sha1").digest()),
    ("pbkdf2:sha256:7", lambda x, s: hashlib.pbkdf2_hmac("sha256", x, s, 7, 16)),
    ("scrypt:16:1:1", lambda x, s: hashlib.scrypt(x, salt=s, n=16, r=1, p=1, dklen=16)),
])
def test_derivations_match_their_reference(spec, ref):
    fn, _ = ks.parse_kdf(spec, 16)
    assert fn(b"candidate", b"pepper")[:16] == ref(b"candidate", b"pepper")[:16]


def test_md4_comes_from_the_hashcrack_lane():
    fn, salted = ks.parse_kdf("md4", None)
    assert not salted
    assert fn(b"abc", b"").hex() == "a448017aaf21d8525fc10ae87aa6729d"       # RFC 1320 vector


def test_raw_needs_the_exact_length_and_pad0_pads():
    raw, _ = ks.parse_kdf("raw", 4)
    pad, _ = ks.parse_kdf("pad0", 4)
    assert raw(b"abcd", b"") == b"abcd" and raw(b"abc", b"") is None
    assert pad(b"ab", b"") == b"ab\x00\x00" and pad(b"abcdef", b"") == b"abcd"


@pytest.mark.parametrize("bad", ["nope", "pbkdf2:sha256:0", "scrypt:15:1:1", "md5*x", "hmac:nohash", "shake_128"])
def test_bad_derivations_are_refused_by_name(bad):
    with pytest.raises(ks.KeySearchError):
        ks.parse_kdf(bad, 16)


def test_a_derivation_shorter_than_the_key_is_refused(tmp_path):
    spec = _base_spec({"kind": "crib", "cipher": "aes-ecb", "crib": "FLAG{abc", "ct_hex": "00" * 16},
                      kdf=["md5"], key_len=32)
    with pytest.raises(ks.KeySearchError, match="md5 gives 16 bytes"):
        _make(tmp_path, spec)


# ---------------------------------------------------------------------------- verifiers find the planted key

def _finds(tmp_path, spec, **run_kw):
    _make(tmp_path, spec)
    res = _run(tmp_path, **run_kw)
    assert res["reason"] == "hit", res
    return res


@pytest.mark.needs_tool("py:Crypto")
def test_crib_aes_cbc_with_the_iv_as_the_first_block_finds_the_pbkdf2_key(tmp_path):
    key = hashlib.pbkdf2_hmac("sha256", _planted(), b"NaCl", 5, 16)
    spec = _base_spec({"kind": "crib", "cipher": "aes-cbc", "crib": "FLAG{", "ct_hex": _cbc_ct(key).hex(),
                       "pkcs7": True},
                      kdf=["md5", "pbkdf2:sha256:5"], salts=["NaCl"])
    res = _finds(tmp_path, spec)
    (hit,) = res["hits"]
    assert hit["recipe"] == {"slots": ["sid", "words"], "sep_len": 1, "kdf": "pbkdf2:sha256:5", "salt": 0}
    cand, k, _ = ks.reveal("t1", hit["index"], root=tmp_path / "ks")
    assert cand == _planted() and k == key


@pytest.mark.needs_tool("py:Crypto")
@pytest.mark.parametrize("cipher", ["aes-ecb", "aes-ctr", "xor", "rc4"])
def test_crib_ciphers(tmp_path, cipher):
    from Crypto.Cipher import AES, ARC4
    key = hashlib.sha256(_planted(sep=b"")).digest()[:16]
    pt = b"junkjunkjunkjunkPK\x03\x04-rest-of-the-file"
    verify = {"kind": "crib", "cipher": cipher, "crib_hex": "504b0304", "offset": 16}
    if cipher == "aes-ecb":
        pt = pt + b"\x00" * (-len(pt) % 16)
        ct = AES.new(key, AES.MODE_ECB).encrypt(pt)
    elif cipher == "aes-ctr":
        ct = AES.new(key, AES.MODE_CTR, nonce=b"\x01" * 8, initial_value=3).encrypt(pt)
        verify.update(nonce_hex="01" * 8, initial=3)
    elif cipher == "xor":
        ct = bytes(c ^ key[i % 16] for i, c in enumerate(pt))
    else:
        ct = ARC4.new(key).encrypt(pt)
    verify["ct_hex"] = ct.hex()
    verify["crib_hex"] = "504b0304" + pt[20:24].hex()      # 8 bytes: exact over this space
    res = _finds(tmp_path, _base_spec(verify, kdf=["md5", "sha256"]))
    assert ks.reveal("t1", res["hits"][0]["index"], root=tmp_path / "ks")[1] == key


@pytest.mark.needs_tool("py:Crypto")
def test_pkcs7_tail_check_rejects_a_key_that_only_matches_the_crib():
    AES = _aes()
    key = b"k" * 16
    good = _cbc_ct(key, pt=b"FLAG{x}" + b"y" * 20)
    v = ks.CribVerifier("aes-cbc", good[16:32], b"FLAG{", 0, good[:16], b"", 0, good[-32:])
    assert v.check(key)
    bad_tail = good[-32:-16] + AES.new(key, AES.MODE_ECB).encrypt(b"\x00" * 16)     # last block: no padding
    v_bad = ks.CribVerifier("aes-cbc", good[16:32], b"FLAG{", 0, good[:16], b"", 0, bad_tail)
    assert not v_bad.check(key)


def test_hash_verifier_finds_ntlm_style_md4_of_utf16(tmp_path):
    target = ks.parse_kdf("md4", None)[0](_planted(), b"")
    spec = _base_spec({"kind": "hash", "target_hex": target.hex()}, kdf=["md5", "md4"])
    res = _finds(tmp_path, spec)
    assert res["hits"][0]["recipe"]["kdf"] == "md4"


def test_hmac_verifier(tmp_path):
    key = hashlib.sha1(_planted(sep=b"")).digest()[:16]
    tag = hmac.new(key, b"license-blob", "sha256").digest()
    spec = _base_spec({"kind": "hmac", "alg": "sha256", "msg_hex": b"license-blob".hex(), "tag_hex": tag.hex()},
                      kdf=["md5", "sha1"])
    res = _finds(tmp_path, spec)
    assert res["hits"][0]["recipe"]["kdf"] == "sha1"


@pytest.mark.needs_tool("py:Crypto")
def test_aes_gcm_verifier(tmp_path):
    AES = _aes()
    key = hashlib.sha256(_planted()).digest()
    c = AES.new(key, AES.MODE_GCM, nonce=b"n" * 12)
    c.update(b"hdr")
    ct, tag = c.encrypt_and_digest(b"secret message")
    spec = _base_spec({"kind": "aes-gcm", "nonce_hex": (b"n" * 12).hex(), "ct_hex": ct.hex(), "tag_hex": tag.hex(),
                       "aad_hex": b"hdr".hex()}, kdf=["sha512", "sha256"], key_len=32)
    res = _finds(tmp_path, spec)
    assert ks.reveal("t1", res["hits"][0]["index"], root=tmp_path / "ks")[1] == key


def test_no_hit_when_the_key_is_not_in_the_space(tmp_path):
    target = hashlib.md5(b"not in any bank").digest()
    _make(tmp_path, _base_spec({"kind": "hash", "target_hex": target.hex()}, kdf=["md5"]))
    res = _run(tmp_path)
    assert res["reason"] == "exhausted" and res["hits"] == []
    assert sorted(_chunks(_ledger(tmp_path))) == list(range(ks.Space(ks.load_job("t1", tmp_path / "ks")[1]).chunks))


# ---------------------------------------------------------------------------- the password lane (B-074)

@pytest.mark.needs_tool("py:pyzipper")
def test_zip_verifier_with_a_harvested_bank_stores_the_password(tmp_path):
    import pyzipper

    import archive_passwords as ap
    pw = "Harvested_Pw_42"
    chal = tmp_path / "chal"
    chal.mkdir()
    z = chal / "locked.zip"
    with pyzipper.AESZipFile(z, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(pw.encode())
        zf.writestr("flag.txt", "FLAG{zip}")
    (chal / "note.txt").write_text(f"remember: {pw}\nand some other words here\n")
    spec = {"kdf": ["raw"], "chunk": 4,
            "bank": [{"name": "h", "harvest": "chal/locked.zip", "siblings": True}],
            "template": [{"slots": ["h"]}],
            "verify": {"kind": "zip", "file": "chal/locked.zip"}}
    _make(tmp_path, spec)
    res = _run(tmp_path)
    assert res["reason"] == "hit"
    assert res["hits"][0]["stored"] is True
    assert pw.encode() in ap.candidates()             # the sweep's archive lane now opens it
    assert ap.read_all(z.read_bytes())[0] == {"flag.txt": b"FLAG{zip}"}


def test_zip_verifier_refuses_a_zip_with_nothing_encrypted(tmp_path):
    import zipfile
    with zipfile.ZipFile(tmp_path / "plain.zip", "w") as zf:
        zf.writestr("a.txt", "x")
    spec = {"kdf": ["raw"], "bank": [{"name": "w", "values": ["a"]}], "template": [{"slots": ["w"]}],
            "verify": {"kind": "zip", "file": "plain.zip"}}
    with pytest.raises(ks.KeySearchError, match="no encrypted member"):
        _make(tmp_path, spec)


def test_store_bank_is_frozen_when_the_job_is_made(tmp_path):
    import archive_passwords as ap
    ap.add("stored_one", source="player")
    spec = {"kdf": ["md5"], "bank": [{"name": "pw", "store": True}], "template": [{"slots": ["pw"]}],
            "verify": {"kind": "hash", "target_hex": "00" * 16}}
    job = _make(tmp_path, spec)
    before = job["total"]
    ap.add("stored_two", source="player")              # the store grows after the job was made
    _, again = ks.load_job("t1", tmp_path / "ks")
    assert ks.Space(again).total == before == 2       # infected + stored_one
    assert b"stored_two" not in ks.Space(again).banks["pw"]


def test_wordlist_bank_reads_ctf_wordlist_and_fails_loudly_when_it_is_unusable(tmp_path, monkeypatch):
    spec = {"kdf": ["md5"], "bank": [{"name": "rock", "wordlist": True, "limit": 3}],
            "template": [{"slots": ["rock"]}], "verify": {"kind": "hash", "target_hex": "00" * 16}}
    monkeypatch.setenv("CTF_WORDLIST", str(tmp_path / "absent.txt"))
    with pytest.raises(ks.KeySearchError, match="CTF_WORDLIST is set to .* not a readable file"):
        _make(tmp_path, spec)
    (tmp_path / "rock.txt").write_text("123456\npassword\niloveyou\nprincess\n")
    monkeypatch.setenv("CTF_WORDLIST", str(tmp_path / "rock.txt"))
    assert ks.Space(_make(tmp_path, spec)).banks["rock"] == [b"123456", b"password", b"iloveyou"]


# ---------------------------------------------------------------------------- exactness

def test_a_weak_verifier_is_refused_unless_allowed(tmp_path):
    spec = _base_spec({"kind": "hash", "target_hex": "ab"}, kdf=["md5", "sha1", "sha256"], key_len=None)
    with pytest.raises(ks.KeySearchError, match="chance hits"):
        _make(tmp_path, spec)                       # 72 candidates x 2^-8 = 0.28 expected false hits
    job = _make(tmp_path, spec, allow_weak=True)
    assert job["allow_weak"] and job["total"] == 72 and job["chance"] == pytest.approx(72 / 256)


def test_chance_hits_counts_the_whole_space():
    assert ks.chance_hits(1 << 20, 40) == pytest.approx(2.0 ** -20)


# ---------------------------------------------------------------------------- resumability

def _slow_space_spec(target_word=None, chunk=4, n_words=40, iters=1):
    """n_words + 1 candidates: the last is target_word (the hit), or a filler when there is no target."""
    words = [f"w{i:03d}" for i in range(n_words)] + [target_word or "w-filler"]
    key = hashlib.pbkdf2_hmac("sha256", (target_word or "zz-in-no-bank").encode(), b"s", iters, 16)
    return {"key_len": 16, "chunk": chunk, "kdf": [f"pbkdf2:sha256:{iters}"], "salts": ["s"],
            "bank": [{"name": "w", "values": words}], "template": [{"slots": ["w"]}],
            "verify": {"kind": "hash", "target_hex": key.hex()}}


def test_budget_stops_resume_without_retesting_a_chunk(tmp_path):
    _make(tmp_path, _slow_space_spec(target_word="w-last"))      # 41 candidates, 11 chunks, hit in the last
    r1 = _run(tmp_path, max_chunks=3)
    r2 = _run(tmp_path, max_chunks=4)
    r3 = _run(tmp_path)
    assert (r1["reason"], r2["reason"], r3["reason"]) == ("max-chunks", "max-chunks", "hit")
    recs = _ledger(tmp_path)
    chunks = _chunks(recs)
    assert chunks[:3] == [0, 1, 2] and chunks[3:7] == [3, 4, 5, 6]
    assert len(chunks) == len(set(chunks))              # no chunk was searched twice
    starts = [r for r in recs if r["event"] == "keysearch.start"]
    assert [s["done_before"] for s in starts] == [0, 3, 7]
    assert any("resume: python -m ctf keysearch run t1" in line for line in r1["stdout"])


def test_cpu_budget_stops_after_the_chunk_that_spent_it(tmp_path):
    _make(tmp_path, _slow_space_spec(iters=2000))
    res = _run(tmp_path, cpu_seconds=1e-12)
    assert res["reason"] == "cpu-budget" and res["chunks"] == 1


def test_a_hit_already_found_is_not_searched_again_and_all_finishes_the_space(tmp_path):
    spec = _slow_space_spec(target_word="w005")
    spec["bank"][0]["values"] = [f"w{i:03d}" for i in range(12)]      # the target is the sixth word
    _make(tmp_path, spec)
    first = _run(tmp_path)
    assert first["reason"] == "hit" and first["hits"][0]["index"] == 5
    assert 1 not in _chunks(_ledger(tmp_path))                # the hit cut chunk 1 short: it is not done
    again = _run(tmp_path)
    assert again["reason"] == "already-hit"
    rest = _run(tmp_path, all_hits=True)
    assert rest["reason"] == "exhausted"
    chunks = _chunks(_ledger(tmp_path))
    assert sorted(chunks) == [0, 1, 2] and len(chunks) == 3
    hits = [r for r in _ledger(tmp_path) if r["event"] == "keysearch.hit"]
    assert [h["index"] for h in hits] == [5]                  # found again in chunk 1, recorded once


def test_two_workers_search_the_same_job(tmp_path):
    _make(tmp_path, _slow_space_spec(target_word="w-hit", n_words=30))
    res = _run(tmp_path, workers=2)
    assert res["reason"] == "hit"
    cand, _, _ = ks.reveal("t1", res["hits"][0]["index"], root=tmp_path / "ks")
    assert cand == b"w-hit"


def test_a_second_runner_is_refused_while_the_lock_is_held(tmp_path):
    _make(tmp_path, _slow_space_spec())
    fd = os.open(tmp_path / "ks" / "t1" / ks.LOCK_NAME, os.O_RDWR | os.O_CREAT)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with pytest.raises(ks.KeySearchError, match="already running"):
            _run(tmp_path)
    finally:
        os.close(fd)
    assert _run(tmp_path)["reason"] == "exhausted"


def test_a_torn_last_ledger_line_is_cut_and_redone(tmp_path):
    _make(tmp_path, _slow_space_spec())
    _run(tmp_path, max_chunks=2)
    p = tmp_path / "ks" / "t1" / ks.PROGRESS_NAME
    with open(p, "ab") as fh:
        fh.write(b'{"ts":1,"event":"keysearch.chunk","fp":"x","chu')      # a crash mid-write
    res = _run(tmp_path)
    assert any("torn last line" in line for line in res["stdout"])
    assert res["reason"] == "exhausted"
    assert p.read_bytes().endswith(b"\n")
    chunks = _chunks(_ledger(tmp_path))
    assert sorted(chunks) == list(range(11)) and len(chunks) == 11


def test_a_corrupt_line_inside_the_ledger_is_an_error(tmp_path):
    _make(tmp_path, _slow_space_spec())
    _run(tmp_path, max_chunks=1)
    p = tmp_path / "ks" / "t1" / ks.PROGRESS_NAME
    p.write_bytes(b"garbage\n" + p.read_bytes())
    with pytest.raises(ks.KeySearchError, match="corrupt ledger line"):
        _run(tmp_path)


def test_an_edited_job_is_refused(tmp_path):
    _make(tmp_path, _slow_space_spec())
    p = tmp_path / "ks" / "t1" / ks.JOB_NAME
    job = json.loads(p.read_text())
    job["chunk"] = 999
    p.write_text(json.dumps(job))
    with pytest.raises(ks.KeySearchError, match="edited after it was made"):
        _run(tmp_path)


def test_new_keeps_an_existing_job_unless_replace_moves_it_aside(tmp_path):
    _make(tmp_path, _slow_space_spec())
    _run(tmp_path, max_chunks=1)
    with pytest.raises(ks.KeySearchError, match="exists"):
        _make(tmp_path, _slow_space_spec())
    _make(tmp_path, _slow_space_spec(n_words=10), replace=True)
    aside = [d for d in (tmp_path / "ks").iterdir() if d.name.startswith("t1.replaced-")]
    assert len(aside) == 1 and (aside[0] / ks.PROGRESS_NAME).exists()
    assert _ledger(tmp_path) == []


_CRASH_CHILD = r'''
import os, signal, sys
sys.path.insert(0, sys.argv[1])
sys.path.insert(0, os.path.join(sys.argv[1], "solvers", "common"))
import keysearch as ks
real = ks.ctf_ledger.append
mode, n = sys.argv[3], int(sys.argv[4])
seen = {"chunk": 0}
def crashing(event, **kw):
    if mode == "before-chunk" and event == "keysearch.chunk":
        os.kill(os.getpid(), signal.SIGKILL)          # the hit is on disk, its chunk record is not
    real(event, **kw)
    if mode == "after-chunks" and event == "keysearch.chunk":
        seen["chunk"] += 1
        if seen["chunk"] == n:
            os.kill(os.getpid(), signal.SIGKILL)
ks.ctf_ledger.append = crashing
ks.run("t1", root=sys.argv[2])
'''


def _crash(tmp_path, mode, n=0):
    script = tmp_path / "crash_child.py"
    script.write_text(_CRASH_CHILD)
    p = subprocess.run([sys.executable, "-I", str(script), str(REPO), str(tmp_path / "ks"), mode, str(n)],
                       capture_output=True, text=True, timeout=300, env={**os.environ})
    assert p.returncode == -signal.SIGKILL, p.stderr


def test_a_crash_after_chunks_resumes_from_the_next_chunk(tmp_path):
    _make(tmp_path, _slow_space_spec(target_word="w-last"))
    _crash(tmp_path, "after-chunks", 4)
    recs = _ledger(tmp_path)
    assert _chunks(recs) == [0, 1, 2, 3] and not any(r["event"] == "keysearch.stop" for r in recs)
    res = _run(tmp_path)
    assert res["reason"] == "hit"
    chunks = _chunks(_ledger(tmp_path))
    assert len(chunks) == len(set(chunks)) and chunks[4] == 4      # resumed at chunk 4, nothing redone


def test_a_crash_between_a_hit_and_its_chunk_keeps_the_hit(tmp_path):
    _make(tmp_path, _slow_space_spec(target_word="w-last", chunk=64))     # one chunk, the hit at its end
    _crash(tmp_path, "before-chunk")
    recs = _ledger(tmp_path)
    assert [r["event"] for r in recs] == ["keysearch.start", "keysearch.hit"]
    res = _run(tmp_path)
    assert res["reason"] == "already-hit"


def test_sigterm_stops_a_cli_run_as_interrupted_and_it_resumes(tmp_path):
    spec = _slow_space_spec(n_words=4000, iters=2000, chunk=8)
    (tmp_path / "spec.json").write_text(json.dumps(spec))
    env = {**os.environ, "CTF_WORKDIR": str(tmp_path / "wd")}
    root = str(tmp_path / "ks")
    assert subprocess.run([sys.executable, "-m", "ctf", "keysearch", "--root", root, "new", "t1",
                           "--spec", str(tmp_path / "spec.json")], cwd=REPO, env=env,
                          capture_output=True, timeout=300).returncode == 0
    proc = subprocess.Popen([sys.executable, "-m", "ctf", "keysearch", "--root", root, "run", "t1"], cwd=REPO,
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        p = tmp_path / "ks" / "t1" / ks.PROGRESS_NAME
        deadline = time.monotonic() + 240               # a lower bound on waiting only: it ends on the first chunk
        while time.monotonic() < deadline and not (p.exists() and b"keysearch.chunk" in p.read_bytes()):
            time.sleep(0.05)
        proc.send_signal(signal.SIGTERM)
        out, err = proc.communicate(timeout=240)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    assert proc.returncode == ks.EXIT_STOPPED, (out, err)
    stop = [r for r in _ledger(tmp_path) if r["event"] == "keysearch.stop"][-1]
    assert stop["reason"] == "interrupted" and stop["done"] >= 1
    assert "resume: python -m ctf keysearch run t1" in out
    done = set(_chunks(_ledger(tmp_path)))
    res = _run(tmp_path, max_chunks=1)
    assert _chunks(_ledger(tmp_path))[-1] not in done            # the resume picks a chunk not yet searched


# ---------------------------------------------------------------------------- nothing secret leaks

@pytest.mark.needs_tool("py:Crypto")
def test_no_plaintext_candidate_or_key_in_the_ledgers_or_stdout(tmp_path, capsys):
    key = hashlib.md5(_planted()).digest()
    spec = _base_spec({"kind": "crib", "cipher": "aes-cbc", "crib": "FLAG{", "ct_hex": _cbc_ct(key).hex()},
                      kdf=["md5"])
    (tmp_path / "spec.json").write_text(json.dumps(spec))
    root = str(tmp_path / "ks")
    assert ks.main(["--root", root, "new", "t1", "--spec", str(tmp_path / "spec.json")]) == 0
    assert ks.main(["--root", root, "run", "t1"]) == ks.EXIT_HIT
    assert ks.main(["--root", root, "status", "t1"]) == 0
    assert ks.main(["--root", root, "show", "t1"]) == 0
    out = capsys.readouterr().out
    texts = [out, (tmp_path / "ks" / "t1" / ks.PROGRESS_NAME).read_text(),
             (tmp_path / "wd" / "ledger.jsonl").read_text()]
    forbidden = [SECRET_WORD, SECRET_WORD.lower(), _planted().hex(), key.hex(),
                 SECRET_WORD.encode("utf-16-le").hex(), json.dumps(_planted().decode("latin-1"))[1:-1]]
    for text in texts:
        for f in forbidden:
            assert f not in text
    assert ks.mask(_planted()) in out
    assert ks.main(["--root", root, "show", "t1", "--reveal"]) == 0
    revealed = capsys.readouterr().out
    assert _planted().hex() in revealed and key.hex() in revealed


def test_event_ledger_gets_the_run_summary(tmp_path):
    _make(tmp_path, _slow_space_spec())
    _run(tmp_path, max_chunks=2)
    events = [json.loads(line) for line in (tmp_path / "wd" / "ledger.jsonl").read_text().splitlines()]
    (stop,) = [e for e in events if e["event"] == "keysearch.stop"]
    assert stop["search"] == "t1" and stop["reason"] == "max-chunks" and stop["done"] == 2 and stop["of"] == 11


# ---------------------------------------------------------------------------- command line

def test_cli_exit_codes(tmp_path, capsys):
    root = str(tmp_path / "ks")
    (tmp_path / "spec.json").write_text(json.dumps(_slow_space_spec()))
    assert ks.main(["--root", root, "run", "missing"]) == ks.EXIT_ERROR
    assert "no search missing" in capsys.readouterr().err
    assert ks.main(["--root", root, "new", "t1", "--spec", str(tmp_path / "spec.json")]) == 0
    assert ks.main(["--root", root, "run", "t1", "--max-chunks", "2"]) == ks.EXIT_STOPPED
    assert ks.main(["--root", root, "run", "t1"]) == ks.EXIT_EXHAUSTED
    assert ks.main(["--root", root, "status", "t1", "--json"]) == 0
    status = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert status["chunks_done"] == status["chunks"] == 11 and status["tested"] == 41 and status["runs"] == 2
    assert ks.main(["--root", root, "list"]) == 0
    assert "t1: 11/11 chunks, 0 hit(s)" in capsys.readouterr().out
    assert ks.main(["--root", root, "show", "t1"]) == ks.EXIT_ERROR        # no hit to show


def test_toml_spec_through_ctf_cli(tmp_path):
    key = hashlib.sha256(b"S-1-5-21-7" + b"qwertz").digest()[:16]
    (tmp_path / "spec.toml").write_text(
        'key_len = 16\nkdf = ["sha256"]\n\n[[bank]]\nname = "sid"\nvalues = ["S-1-5-21-7"]\n\n'
        '[[bank]]\nname = "w"\nvalues = ["qwertz", "other"]\n\n[[template]]\nslots = ["sid", "w"]\n\n'
        f'[verify]\nkind = "hash"\ntarget_hex = "{key.hex()}"\n')
    env = {**os.environ, "CTF_WORKDIR": str(tmp_path / "wd")}
    new = subprocess.run([sys.executable, "-m", "ctf", "keysearch", "new", "t2", "--spec",
                          str(tmp_path / "spec.toml")], cwd=REPO, env=env, capture_output=True, text=True,
                         timeout=300)
    assert new.returncode == 0, new.stderr
    run = subprocess.run([sys.executable, "-m", "ctf", "keysearch", "run", "t2"], cwd=REPO, env=env,
                         capture_output=True, text=True, timeout=300)
    assert run.returncode == ks.EXIT_HIT, run.stderr
    assert (tmp_path / "wd" / "keysearch" / "t2" / ks.JOB_NAME).stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("mutate, message", [
    (lambda s: s.pop("bank"), "no \\[\\[bank\\]\\]"),
    (lambda s: s.pop("template"), "no \\[\\[template\\]\\]"),
    (lambda s: s["template"][0].update(slots=["ghost"]), "name no bank"),
    (lambda s: s["verify"].update(kind="guess"), "verify kind"),
    (lambda s: s.update(extra=1), "unknown key"),
    (lambda s: s["bank"][0].update(encodings=["ebcdic"]), "unknown"),
    (lambda s: s.update(chunk=0), "chunk must be"),
])
def test_bad_specs_are_refused_with_a_reason(tmp_path, mutate, message):
    spec = _slow_space_spec()
    mutate(spec)
    with pytest.raises(ks.KeySearchError, match=message):
        _make(tmp_path, spec)


def test_router_sends_a_derived_key_brief_here():
    from ctf.engines import router
    ids = [hit.manifest.id for hit in router.route("crypto", "the AES key is a PBKDF2 derived key of the SID")]
    assert ids[0] == "common.keysearch"


# ---------------------------------------------------------------------------- verification round 1

def _zipcrypto_zip(name: str, body: bytes, pw: bytes) -> bytes:
    """A one-member stored zip under traditional PKWARE (ZipCrypto) encryption, built byte by byte:
    neither the stdlib nor pyzipper writes ZipCrypto."""
    import struct
    import zlib
    crc = zlib.crc32(body)

    def step(c, b):                                   # the CRC-32 table step ZipCrypto's keys use
        return zlib.crc32(bytes([b]), c ^ 0xFFFFFFFF) ^ 0xFFFFFFFF
    k = [0x12345678, 0x23456789, 0x34567890]

    def update(b):
        k[0] = step(k[0], b)
        k[1] = ((k[1] + (k[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k[2] = step(k[2], k[1] >> 24)
    for b in pw:
        update(b)
    enc = bytearray()
    for b in bytes(range(1, 12)) + bytes([crc >> 24]) + body:     # 11 header bytes, the check byte
        t = (k[2] | 2) & 0xFFFF
        enc.append(b ^ ((t * (t ^ 1)) >> 8) & 0xFF)
        update(b)
    fn = name.encode()
    local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 1, 0, 0, 0, crc, len(enc), len(body), len(fn), 0) + fn
    central = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 1, 0, 0, 0, crc, len(enc), len(body),
                          len(fn), 0, 0, 0, 0, 0, 0) + fn
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local) + len(enc), 0)
    return local + bytes(enc) + central + eocd


def _zipcrypto_spec(tmp_path, pw="Crypto_Pw_7"):
    import zipfile
    data = _zipcrypto_zip("flag.txt", b"FLAG{zipcrypto}", pw.encode())
    (tmp_path / "zc.zip").write_bytes(data)
    with zipfile.ZipFile(tmp_path / "zc.zip") as zf:   # the fixture is a real ZipCrypto zip
        assert zf.read("flag.txt", pwd=pw.encode()) == b"FLAG{zipcrypto}"
        with pytest.raises(RuntimeError, match="password"):
            zf.read("flag.txt", pwd=b"wrong-one")
    return {"kdf": ["raw"], "chunk": 2,
            "bank": [{"name": "w", "values": ["alpha", "beta", pw, "gamma"]}], "template": [{"slots": ["w"]}],
            "verify": {"kind": "zip", "file": "zc.zip"}}


def test_zip_verifier_opens_a_zipcrypto_member_and_stores_the_password(tmp_path):
    import archive_passwords as ap
    job = _make(tmp_path, _zipcrypto_spec(tmp_path))
    assert job["bits"] == 40                          # 8-bit check byte + CRC-32, not the AES 96
    assert ks.build_verifier(job["verify"]).describe() == "zip zipcrypto member (40 bits checked)"
    res = _run(tmp_path)
    assert res["reason"] == "hit" and res["hits"][0]["index"] == 2
    assert res["hits"][0]["stored"] is True
    assert b"Crypto_Pw_7" in ap.candidates()
    v = ks.build_verifier(job["verify"])
    assert v.check(b"Crypto_Pw_7") and not v.check(b"alpha")


def test_a_zip_hit_with_no_store_workdir_says_so_and_is_still_recorded(tmp_path, monkeypatch):
    monkeypatch.delenv("CTF_WORKDIR", raising=False)
    monkeypatch.setenv("CTF_EVENT", "no-such-event-b215")      # the store cannot resolve a workdir
    _make(tmp_path, _zipcrypto_spec(tmp_path))
    res = _run(tmp_path)
    assert res["reason"] == "hit" and res["hits"][0]["stored"] is False
    said = "\n".join(res["stdout"])
    assert "archive-password store: the store has no usable workdir (EventError" in said
    assert "not a storable archive password" not in said        # the password itself was fine
    (hit,) = [r for r in _ledger(tmp_path) if r["event"] == "keysearch.hit"]
    assert hit["index"] == 2 and hit["stored"] is False


def _two_hits_spec():
    """pad0 to 4 bytes: 'abcd1' and 'abcd2' both give the key 'abcd', in chunk 0 (indices 1 and 2)."""
    return {"key_len": 4, "chunk": 4, "kdf": ["pad0"],
            "bank": [{"name": "w", "values": ["x1", "abcd1", "abcd2", "x2", "y1", "y2", "y3", "y4"]}],
            "template": [{"slots": ["w"]}], "verify": {"kind": "hash", "target_hex": b"abcd".hex()}}


@pytest.mark.parametrize("workers", [1, 2])
def test_all_finds_every_hit_in_a_chunk_with_any_worker_count(tmp_path, workers):
    _make(tmp_path, _two_hits_spec())
    res = _run(tmp_path, workers=workers, all_hits=True)
    assert res["reason"] == "exhausted"
    assert sorted(h["index"] for h in res["hits"]) == [1, 2]
    assert sorted(_chunks(_ledger(tmp_path))) == [0, 1]       # chunk 0 searched to its end: done


def test_cpu_budget_stops_a_pool_run(tmp_path):
    _make(tmp_path, _slow_space_spec(iters=2000))
    res = _run(tmp_path, workers=2, cpu_seconds=1e-12)
    assert res["reason"] == "cpu-budget" and res["chunks"] == 1
    assert len(_chunks(_ledger(tmp_path))) == 1


def _huge_space_spec():
    """1e6 one-candidate chunks (three 100-atom slots): far more than any test searches."""
    return {"key_len": 16, "chunk": 1, "kdf": ["md5"],
            "bank": [{"name": n, "values": [f"{n}{i:02d}" for i in range(100)]} for n in ("a", "b", "c")],
            "template": [{"slots": ["a", "b", "c"]}],
            "verify": {"kind": "hash", "target_hex": hashlib.md5(b"in no bank").hexdigest()}}


@pytest.mark.parametrize("workers, kw", [(1, {"max_chunks": 2}), (2, {"cpu_seconds": 1e-12})])
def test_a_run_does_not_hold_the_chunk_list_in_memory(tmp_path, workers, kw):
    import tracemalloc
    job = _make(tmp_path, _huge_space_spec())
    assert job["total"] == 10 ** 6
    tracemalloc.start()
    try:
        res = _run(tmp_path, workers=workers, **kw)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert res["reason"] in ("max-chunks", "cpu-budget") and res["chunks"] >= 1
    # a list of 1e6 chunk numbers (or pool tasks) costs over 30 MB; the lazy run a few hundred kB
    assert peak < 8 * 1024 * 1024, peak
    (start,) = [r for r in _ledger(tmp_path) if r["event"] == "keysearch.start"]
    assert start["todo"] == (2 if "max_chunks" in kw else 10 ** 6)


def test_replace_refuses_a_job_that_is_running(tmp_path):
    _make(tmp_path, _slow_space_spec())
    fd = os.open(tmp_path / "ks" / "t1" / ks.LOCK_NAME, os.O_RDWR | os.O_CREAT)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)                # a runner holds the job
        with pytest.raises(ks.KeySearchError, match="is running now"):
            _make(tmp_path, _slow_space_spec(n_words=10), replace=True)
    finally:
        os.close(fd)
    assert not [d for d in (tmp_path / "ks").iterdir() if d.name.startswith("t1.replaced-")]
    assert ks.load_job("t1", tmp_path / "ks")[1]["total"] == 41      # the running job is untouched


def test_hmac_verifier_with_a_truncated_tag(tmp_path):
    key = hashlib.sha1(_planted(sep=b"")).digest()[:16]
    tag = hmac.new(key, b"license-blob", "sha256").digest()[:16]
    spec = _base_spec({"kind": "hmac", "alg": "sha256", "msg_hex": b"license-blob".hex(), "tag_hex": tag.hex()},
                      kdf=["md5", "sha1"])
    res = _finds(tmp_path, spec)
    assert res["hits"][0]["recipe"]["kdf"] == "sha1"
    v = ks.HmacVerifier("sha256", b"license-blob", tag)
    assert v.bits == 128 and v.check(key) and not v.check(b"k" * 16)


@pytest.mark.needs_tool("py:Crypto")
@pytest.mark.parametrize("last", [0x00, 0x11, 0xFF])
def test_pkcs7_rejects_a_final_byte_outside_1_to_16(last):
    AES = _aes()
    key, iv = b"k" * 16, bytes(16)
    pt = b"FLAG{x}" + b"y" * 9 + b"z" * 15 + bytes([last])          # two blocks, no valid padding
    ct = AES.new(key, AES.MODE_CBC, iv=iv).encrypt(pt)
    v = ks.CribVerifier("aes-cbc", ct, b"FLAG{", 0, iv, b"", 0, ct[-32:])
    assert not v.check(key)
    good = AES.new(key, AES.MODE_CBC, iv=iv).encrypt(pt[:-1] + b"\x01")
    assert ks.CribVerifier("aes-cbc", good, b"FLAG{", 0, iv, b"", 0, good[-32:]).check(key)


@pytest.mark.needs_tool("py:Crypto")
def test_gcm_verifier_says_no_to_a_key_aes_cannot_take():
    AES = _aes()
    key = b"g" * 16
    c = AES.new(key, AES.MODE_GCM, nonce=b"n" * 12)
    ct, tag = c.encrypt_and_digest(b"msg")
    v = ks.GcmVerifier(b"n" * 12, ct, tag, b"")
    assert v.check(key)
    assert v.check(b"g" * 15) is False and v.check(b"") is False     # no ValueError out of AES.new


def test_a_non_utf8_atom_keeps_its_nul_terminated_variant(tmp_path):
    wl = tmp_path / "words.txt"
    wl.write_bytes(b"caf\xe9\n")
    out = ks.expand_bank({"name": "w", "values": [], "hex": [], "files": [ks._file_ref(wl, None)],
                          "case": ["upper"], "encodings": ["utf16le"], "nul": [False, True]})
    assert out == [b"caf\xe9", b"caf\xe9\x00"]


@pytest.mark.parametrize("value, shown", [(b"\xe9abc", "<4 bytes, starts ?>"), ("éa", "<3 bytes, starts ?>"),
                                          (b":x", "<2 bytes, starts ?>"), (b"Zq", "<2 bytes, starts Z>")])
def test_mask_shows_only_an_ascii_alphanumeric_first_character(value, shown):
    assert ks.mask(value) == shown


def test_status_json_lists_the_hits_masked(tmp_path, capsys):
    _make(tmp_path, _slow_space_spec(target_word="w-hit", n_words=5))
    assert ks.main(["--root", str(tmp_path / "ks"), "run", "t1"]) == ks.EXIT_HIT
    capsys.readouterr()
    assert ks.main(["--root", str(tmp_path / "ks"), "status", "t1", "--json"]) == 0
    out = capsys.readouterr().out
    status = json.loads(out.strip().splitlines()[-1])
    (hit,) = status["hits"]
    assert hit["index"] == 5 and hit["masked"] == ks.mask(b"w-hit") and hit["recipe"]["slots"] == ["w"]
    assert "w-hit" not in out


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
