"""B-249: the Mobile lane residuals, each behind the exact ANS fullmatch gate.

  table      codec_more.quadratic_offset_shape (stated or crib-recovered) and piecewise_offset_shape (stated pieces),
             wired into codec_search.solve_doc under the judged `table` name and an unknown one: always an unsure
             candidate under a document-fingerprint key of its own, never the judged `table` / `linear-offset` key
  decoys     lookahead_readers.decoy_places: decoy places listed (`decoys`/`keep`/`every`), then the document's order
  stated     stated_spec: AES-GCM, ChaCha20, XTEA, a keyed columnar transposition, a block reverse, a substitution
             table, a lookup into a stated table, a hash-derived key; and the existing permutation / PBKDF2 depth
  facts      apk_facts: database_name and table_name (a dex string, a SQLite member), unsure, exactly one or None
  dex VM     dex_float TEXT (StringBuilder/String methods) and CROSSDEX (a pure static of another classpath dex, by
             invoke-static or by reflection), each under a capability family of its own (never the judged key)
  look-ahead ctf.lookahead.mobile_specimens: the Thumb JNI and Hermes specimens through the B-174 gate

Every expected code is computed here by an encoder or oracle that does not use the reader under test. Nothing here is
a challenge file; every package is built from code.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import sqlite3
import struct
import sys
import zipfile
from pathlib import Path

import pytest

from ctf import paths
from ctf.openers import mobile_fixtures as F
from ctf.openers.mobile_splits_synth import (ACC_CONSTRUCTOR, ACC_PUBLIC, ACC_STATIC, CLASS, LONG, METHOD, OBJ, SB,
                                             STR, Asm, DexWriter)

REPO = paths.repo_root()
for _d in ("solvers/common", "solvers/mobile-android"):
    if str(REPO / _d) not in sys.path:
        sys.path.insert(0, str(REPO / _d))

import apk_facts as AF  # noqa: E402
import codec_more as CM  # noqa: E402
import codec_search as C  # noqa: E402
import dex_chain_codec as DCC  # noqa: E402
import dex_float as DF  # noqa: E402
import labels  # noqa: E402
import lookahead_readers as L  # noqa: E402
import stated_spec as S  # noqa: E402

PZ = "assets/huntress_puzzle.json"
CODE = "ANS-7C0FFEE1234ABCD9"
M64 = (1 << 64) - 1


@pytest.fixture(autouse=True)
def _private_workdir(tmp_path, monkeypatch):
    """A fresh judge-ledger workdir (the seed's judged names only), the judge ledger on, no mask, no live fix."""
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    for k in ("CTF_JUDGE_LEDGER", "CTF_LEDGER_MASK", "CTF_TESTING"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(C, "_patch", None)
    labels._cache.clear()


def _apk(doc, extra=None):
    return F._apk({}, doc, extra)


def _unsure(out):
    assert labels.is_unsure(out), out
    return labels.parse(out)


# ============================================================================ quadratic and piecewise tables

def quad_data(code, key, a, b):
    return bytes((code.encode()[i] + key + b * i + a * i * i) % 256 for i in range(20)).hex()


def offsets_data(code, offs):
    return bytes((code.encode()[i] + offs[i]) % 256 for i in range(20)).hex()


def test_quadratic_recovered_from_the_crib_reads_the_code_and_the_linear_reader_does_not():
    d = quad_data(CODE, 29, 3, 7)
    assert CM.quadratic_offset_shape({"data": d, "key": 29}) == (CODE, "quadratic-offset:sub-key-recovered")
    assert CM.linear_offset_shape({"data": d, "key": 29}) is None
    assert CM.table_offsets({"data": d, "key": 29}) is None


def test_quadratic_stated_coefficients_are_used_as_stated():
    d = quad_data(CODE, 11, 5, 200)
    assert CM.quadratic_offset_shape({"data": d, "key": 11, "a": 5, "b": 200}) == (CODE,
                                                                                    "quadratic-offset:sub-key-stated")
    assert CM.quadratic_offset_shape({"data": d, "key": 11, "coefficients": [5, 200]}) == (
        CODE, "quadratic-offset:sub-key-stated")
    # stated coefficients that are not the ones used: no code (the crib is not searched past what is stated)
    assert CM.quadratic_offset_shape({"data": d, "key": 11, "a": 6, "b": 200}) is None


def test_quadratic_fails_closed():
    d = quad_data(CODE, 29, 3, 7)
    assert CM.quadratic_offset_shape({"data": d, "key": True}) is None          # a bool is no integer key
    assert CM.quadratic_offset_shape({"data": d, "key": 30}) is None            # the crib's first byte disagrees
    assert CM.quadratic_offset_shape({"data": d[:-2], "key": 29}) is None       # not 20 bytes
    assert CM.quadratic_offset_shape({"data": quad_data("ANS-Z000000000000000", 29, 3, 7), "key": 29}) is None
    # a linear schedule is linear_offset_shape's: the quadratic reader does not claim it
    lin = quad_data(CODE, 29, 0, 7)
    assert CM.quadratic_offset_shape({"data": lin, "key": 29}) is None
    assert CM.linear_offset_shape({"data": lin, "key": 29}) == CODE
    # a = 128 is linear too (128*i*i == 128*i mod 256): still not this shape
    assert CM.quadratic_offset_shape({"data": quad_data(CODE, 29, 128, 7), "key": 29}) is None


def _restart(key, pieces):
    bounds = [p[0] for p in pieces] + [20]
    out = []
    for i in range(20):
        k = max(j for j in range(len(pieces)) if bounds[j] <= i)
        start, step, base = pieces[k]
        out.append(((key if base is None else base) + step * (i - start)) % 256)
    return out


def _continue(key, pieces):
    bounds = [p[0] for p in pieces] + [20]
    out, cur = [], key % 256
    for i in range(20):
        if i:
            k = max(j for j in range(len(pieces)) if bounds[j] <= i)
            cur = (cur + pieces[k][1]) % 256
        out.append(cur)
    return out


def test_piecewise_restart_and_continue_readings():
    pieces = [(0, 7, None), (9, 23, 140)]
    d = offsets_data(CODE, _restart(29, pieces))
    got = CM.piecewise_offset_shape({"data": d, "key": 29, "pieces": [{"start": 0, "step": 7},
                                                                      {"start": 9, "step": 23, "base": 140}]})
    assert got is not None and got[0] == CODE and "restart" in got[1]
    pieces = [(0, 7, None), (12, 51, None)]
    d = offsets_data(CODE, _continue(29, pieces))
    got = CM.piecewise_offset_shape({"data": d, "key": 29, "segments": [[0, 7], [12, 51]]})
    assert got == (CODE, "piecewise-offset:continue")


def test_piecewise_underdetermined_or_malformed_is_none():
    d = offsets_data(CODE, _continue(29, [(0, 7, None), (12, 51, None)]))
    assert CM.piecewise_offset_shape({"data": d, "key": 29, "pieces": [{"start": 0, "step": 7}, {"start": 12}]}) is None
    assert CM.piecewise_offset_shape({"data": d, "key": 29, "pieces": [[1, 7], [12, 51]]}) is None   # not from 0
    assert CM.piecewise_offset_shape({"data": d, "key": 29, "pieces": [[0, 7], [0, 51]]}) is None    # not rising
    assert CM.piecewise_offset_shape({"data": d, "key": 29}) is None                                 # no pieces
    # every piece with the same step is one linear schedule: linear_offset_shape's, not this one
    lin = offsets_data(CODE, _continue(29, [(0, 7, None), (12, 7, None)]))
    assert CM.piecewise_offset_shape({"data": lin, "key": 29, "pieces": [[0, 7], [12, 7]]}) is None


def _absolute(key, pieces):
    bounds = [p[0] for p in pieces] + [20]
    return [(key + pieces[max(j for j in range(len(pieces)) if bounds[j] <= i)][1] * i) % 256 for i in range(20)]


def test_piecewise_absolute_reading():
    """offset = key + step*i with each piece's own step: neither restart nor continue reads it, so the route is
    `absolute` alone, and the code is the one every place of the absolute schedule gives."""
    pieces = [(0, 7, None), (9, 23, None)]
    d = offsets_data(CODE, _absolute(29, pieces))
    raw = bytes.fromhex(d)
    assert CM._apply_offsets(raw, tuple(_restart(29, pieces))) is None
    assert CM._apply_offsets(raw, tuple(_continue(29, pieces))) is None
    assert CM.piecewise_offset_shape({"data": d, "key": 29, "pieces": [[0, 7], [9, 23]]}) == (
        CODE, "piecewise-offset:absolute")


def test_piecewise_boundary_pieces_are_none():
    """Each schedule below reads a code when its malformed piece is ignored; the reader must not ignore it."""
    good = offsets_data(CODE, _continue(29, [(0, 7, None), (9, 51, None)]))
    assert CM.piecewise_offset_shape({"data": good, "key": 29, "pieces": [[0, 7], [9, 51]]}) == (
        CODE, "piecewise-offset:continue")
    # two pieces that start at the same place (an empty piece in the middle): not rising
    assert CM.piecewise_offset_shape({"data": good, "key": 29, "pieces": [[0, 7], [9, 23], [9, 51]]}) is None
    # a piece that starts at place 20 covers nothing of the 20-byte code: not a stated schedule of it
    assert CM.piecewise_offset_shape({"data": good, "key": 29, "pieces": [[0, 7], [9, 51], [20, 3]]}) is None


def test_piecewise_two_readings_with_two_codes_is_none():
    """`continue` and `restart` read the second piece 4 apart: a code whose second-piece characters are 4..9 reads
    (under restart) as another code whose characters are 0..5. Two exact codes: nothing proves which, None."""
    code = "ANS-0123456789456789"
    key, s1, s2 = 29, 7, 11
    base2 = (key + 9 * s1 + s2 + 4) % 256          # the restart offset of piece 2 is the continue offset + 4
    pieces = [{"start": 0, "step": s1}, {"start": 10, "step": s2, "base": base2}]
    d = offsets_data(code, _continue(key, [(0, s1, None), (10, s2, None)]))
    doc = {"data": d, "key": key, "pieces": pieces}
    cont = CM._apply_offsets(bytes.fromhex(d), tuple(_continue(key, [(0, s1, None), (10, s2, None)])))
    rest = CM._apply_offsets(bytes.fromhex(d), tuple(_restart(key, [(0, s1, None), (10, s2, base2)])))
    assert cont == code and rest is not None and rest != code     # both readings are exact codes, and differ
    assert CM.piecewise_offset_shape(doc) is None


def test_table_codec_quadratic_is_an_unsure_candidate_never_the_judged_table_key():
    d = quad_data(CODE, 29, 3, 7)
    out = C.solve_apk(_apk({"schema": F.V1, "day": 30, "codec": "table", "data": d, "key": 29}))
    p = _unsure(out)
    assert p.key.startswith("mobile.codec/quadratic-offset@doc-") and labels.is_candidate(p.key)
    assert p.options == [("quadratic-offset:sub-key-recovered", CODE)]
    # the judged linear table still reads plain under its judged route
    lin = bytes((CODE.encode()[i] + 29 + 7 * i) % 256 for i in range(20)).hex()
    assert C.solve_apk(_apk({"schema": F.V1, "day": 29, "codec": "table", "data": lin, "key": 29})) == CODE


def test_unknown_codec_piecewise_is_an_unsure_candidate():
    pieces = [(0, 7, None), (12, 51, None)]
    d = offsets_data(CODE, _continue(29, pieces))
    out = C.solve_apk(_apk({"schema": F.V1, "day": 31, "codec": "segtable", "data": d, "key": 29,
                            "pieces": [[0, 7], [12, 51]]}))
    p = _unsure(out)
    assert p.key.startswith("mobile.codec/piecewise-offset@doc-") and labels.is_candidate(p.key)
    assert [v for _n, v in p.options] == [CODE]


def test_nonlinear_table_hit_needs_both_shapes_to_agree(monkeypatch):
    monkeypatch.setattr(CM, "quadratic_offset_shape", lambda p: (CODE, "quadratic-offset:sub-key-stated"))
    monkeypatch.setattr(CM, "piecewise_offset_shape", lambda p: ("ANS-0000000000000001", "piecewise-offset:restart"))
    assert C._nonlinear_table_hit({"data": "x"}, "", "") is None
    monkeypatch.setattr(CM, "piecewise_offset_shape", lambda p: (CODE, "piecewise-offset:restart"))
    hit = C._nonlinear_table_hit({"data": "x"}, "", "")
    assert hit.value == CODE and hit.codec.endswith(labels.CANDIDATE_MARK)
    monkeypatch.setattr(CM, "piecewise_offset_shape", lambda p: None)
    monkeypatch.setattr(CM, "quadratic_offset_shape", lambda p: None)
    assert C._nonlinear_table_hit({"data": "x"}, "", "") is None


# ============================================================================ decoy places

def _insert(code, places, ch="q"):
    s = list(code)
    for p in places:
        s.insert(p, ch)
    return "".join(s)


DECOYS = [2, 7, 11, 19, 23]


def test_decoy_places_dropped_zero_and_one_based():
    data = _insert(CODE, DECOYS)
    assert L.decoy_places({"data": data, "decoys": DECOYS}) == [("decoy-places:drop@decoys", CODE)]
    assert L.decoy_places({"data": data, "junk": [p + 1 for p in DECOYS]}) == [("decoy-places:drop@junk", CODE)]


def test_decoy_places_keep_and_every():
    data = _insert(CODE, DECOYS)
    keep = [i for i in range(len(data)) if i not in DECOYS]
    assert L.decoy_places({"data": data, "keep": keep}) == [("decoy-places:keep@keep", CODE)]
    every = "".join(c + "x" for c in CODE)
    assert L.decoy_places({"data": every, "every": 2}) == [("decoy-places:every@every", CODE)]
    first = "".join("x" + c for c in CODE)
    assert L.decoy_places({"data": first, "skip": 2}) == [("decoy-places:every0@skip", CODE)]


def test_decoy_places_then_the_order():
    perm = [7, 3, 19, 0, 12, 5, 16, 1, 9, 14, 2, 18, 6, 11, 4, 17, 8, 13, 10, 15]
    clean = [""] * 20
    for i, src in enumerate(perm):
        clean[src] = CODE[i]
    data = _insert("".join(clean), DECOYS)
    got = L.decoy_places({"data": data, "noise": DECOYS, "order": perm})
    assert got == [("decoy-places:drop@noise+order", CODE)]
    inverse = _insert("".join(CODE[perm[i]] for i in range(20)), DECOYS)       # the order read the other way
    got = L.decoy_places({"data": inverse, "noise": DECOYS, "order": perm})
    assert got == [("decoy-places:drop@noise+order-inverse", CODE)]


def test_decoy_places_fail_closed():
    data = _insert(CODE, DECOYS)
    assert L.decoy_places({"data": data, "decoys": [2, 7, 99]}) == []           # a place past the end
    assert L.decoy_places({"data": data, "decoys": [2, 2, 7]}) == []            # a place twice
    assert L.decoy_places({"data": data}) == []                                 # nothing listed
    assert L.decoy_places({"data": CODE, "decoys": [0]}) == []                  # 20 characters: nothing to drop
    # 0-based removes the hex decoy, 1-based the code's own character: two exact codes, no proof which
    amb = CODE[:10] + "5" + CODE[10:]
    assert CODE[9] != "5"
    assert L.decoy_places({"data": amb, "decoys": [10]}) == []


def test_decoy_places_reach_the_answer_unsure_through_the_solver():
    doc = {"schema": F.V1, "day": 18, "codec": "decoy", "data": _insert(CODE, DECOYS), "decoys": DECOYS}
    p = _unsure(C.solve_apk(_apk(doc)))
    assert p.key == "mobile.codec/lookahead:decoy-places:drop@decoys"
    assert [v for _n, v in p.options] == [CODE]


# ============================================================================ two entries with the document's name (MO1)

def _twins(*bodies):
    import warnings
    out = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")              # zipfile warns of the duplicate name: that is the shape
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            for b in bodies:
                z.writestr(PZ, json.dumps(b).encode())
    return out.getvalue()


def test_two_document_entries_offer_the_earlier_entrys_code_unsure():
    """MO1: the solver reads the LAST entry of the document's name; an earlier entry's exact code is offered, unsure."""
    blob = _twins({"codec": "mystery", "data": list(CODE)}, {"codec": "mystery", "data": "unreadable"})
    p = _unsure(C.solve_apk(blob))
    assert "twin-entry" in p.key and [v for _n, v in p.options] == [CODE]
    other = "ANS-0123456789ABCDE1"
    blob = _twins({"codec": "mystery", "data": list(CODE)}, {"codec": "mystery", "data": list(other)},
                  {"codec": "mystery", "data": "unreadable"})
    p = _unsure(C.solve_apk(blob))
    assert labels.is_candidate(p.key) and {v for _n, v in p.options} == {CODE, other}


# ============================================================================ stated recipes

CB = CODE.encode()


def _read(doc, members=None):
    m = {PZ: json.dumps(doc).encode()}
    m.update(members or {})
    return S.read_package(m)


def _code_of(got):
    return got[0][0] if got[0] else None


def xtea_encrypt(key, data, rounds=32, delta=0x9E3779B9):
    """Independent XTEA encryptor (the published reference, big-endian words)."""
    k = struct.unpack(">4I", key)
    out = b""
    for off in range(0, len(data), 8):
        v0, v1 = struct.unpack(">2I", data[off:off + 8])
        s = 0
        for _ in range(rounds):
            v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3]))) & 0xFFFFFFFF
            s = (s + delta) & 0xFFFFFFFF
            v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3]))) & 0xFFFFFFFF
        out += struct.pack(">2I", v0, v1)
    return out


def test_stated_aes_gcm_with_a_hash_derived_key_and_a_verified_tag():
    from Crypto.Cipher import AES
    key, nonce = hashlib.sha256(b"hunter2").digest(), bytes(range(12))
    ct, tag = AES.new(key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(CB)
    hint = ("Base64-decode the data field, then AES-256-GCM decrypt with key the SHA-256 of 'hunter2' and nonce hex "
            + nonce.hex())
    got = _read({"codec": "vault", "data": base64.b64encode(ct + tag).decode(), "hint": hint})
    assert got[0][:2] == (CODE, "stated:base64>aes-gcm=kdf:sha256")
    assert "hunter2" not in got[0][1] and key.hex() not in got[0][1]       # the route names the origin only
    bad = bytearray(ct + tag)
    bad[-1] ^= 1                                                            # a tag that does not verify
    assert _code_of(_read({"codec": "vault", "data": base64.b64encode(bytes(bad)).decode(), "hint": hint})) is None


def test_stated_chacha20_and_xtea():
    from Crypto.Cipher import ChaCha20
    key, nonce = hashlib.sha256(b"k").digest(), b"\x07" * 8
    ct = ChaCha20.new(key=key, nonce=nonce).encrypt(CB)
    got = _read({"codec": "x", "data": ct.hex(),
                 "hint": "hex-decode the data, then ChaCha20 with the key is the SHA-256 of 'k' and nonce hex "
                         + nonce.hex()})
    assert got[0][:2] == (CODE, "stated:hex>chacha20=kdf:sha256")
    xk = b"0123456789abcdef"
    data = xtea_encrypt(xk, CB + bytes([4]) * 4).hex()
    got = _read({"codec": "x", "data": data, "hint": "hex decode, then XTEA decrypt with key '0123456789abcdef'"})
    assert got[0][:2] == (CODE, "stated:hex>xtea=text")
    # a key of the wrong length is no key: the text is no spec
    assert _code_of(_read({"codec": "x", "data": data, "hint": "hex decode, then XTEA decrypt with key 'short'"})) is None


def col_encode(d, word):
    order = sorted(range(len(word)), key=lambda i: (word[i].upper(), i))
    return bytes(d[i] for c in order for i in range(c, len(d), len(word)))


def test_stated_columnar_transposition_by_keyword_field_and_count():
    enc = col_encode(CB, "ZEBRA").decode()
    assert _code_of(_read({"codec": "x", "data": enc, "hint": "Columnar transposition with keyword 'ZEBRA'"})) == CODE
    got = _read({"codec": "x", "data": enc, "word": "ZEBRA",
                 "hint": "keyed columnar transposition by keyword the word field"})
    assert got[0][:2] == (CODE, "stated:columnar=field:word")
    enc5 = col_encode(CB, "abcde").decode()       # the columns in order: a plain count
    assert _code_of(_read({"codec": "x", "data": enc5, "hint": "columnar transposition with 5 columns"})) == CODE
    assert _code_of(_read({"codec": "x", "data": enc, "hint": "Columnar transposition with keyword 'ZEBRAS'"})) is None


def test_stated_block_reverse_translate_and_lookup():
    blocks = b"".join(CB[i:i + 4][::-1] for i in range(0, 20, 4)).decode()
    assert _read({"codec": "x", "data": blocks, "hint": "reverse each block of 4 bytes"})[0][:2] == (
        CODE, "stated:block-reverse4")
    src, dst = "0123456789ABCDEF", "qwertyuiopzxcvbm"
    enc = CODE[:4] + "".join(dst[src.index(c)] for c in CODE[4:])
    assert _code_of(_read({"codec": "x", "data": enc, "hint": "translate '%s' to '%s'" % (dst, src)})) == CODE
    got = _read({"codec": "x", "data": enc, "subst": dict(zip(dst, src)),
                 "hint": "substitute each character using the subst field"})
    assert got[0][:2] == (CODE, "stated:translate=field:subst")
    alpha = "ANS-0123456789ABCDEFxyz"
    idx = ",".join(str(alpha.index(c)) for c in CODE)
    assert _read({"codec": "x", "data": idx, "alphabet": alpha,
                  "hint": "look up each index in the alphabet field"})[0][:2] == (CODE, "stated:lookup=field:alphabet")
    idx1 = " ".join(str(alpha.index(c) + 1) for c in CODE)
    assert _code_of(_read({"codec": "x", "data": idx1, "hint": "look up each index (1-based) in '%s'" % alpha})) == CODE
    # a substitution with a character twice in its target alphabet is no table
    assert _code_of(_read({"codec": "x", "data": enc, "hint": "translate '%s' to '%s'" % (dst, "00" + src[2:])})) is None


def test_stated_permutation_and_pbkdf2_depth():
    """The recipes the spec calls `depth unverified`: a permutation by a stated order and a PBKDF2-derived AES key."""
    from Crypto.Cipher import AES
    order = (3, 1, 0, 2)
    scr = bytearray(20)
    for base in range(0, 20, 4):
        for i, src in enumerate(order):
            scr[base + src] = CB[base + i]
    assert _code_of(_read({"codec": "x", "data": bytes(scr).decode(), "hint": "permute the bytes by order 3 1 0 2"})) == CODE
    key = hashlib.pbkdf2_hmac("sha256", b"pw", b"salt", 1000, 16)
    pad = CB + bytes([12]) * 12
    ct = AES.new(key, AES.MODE_ECB).encrypt(pad)
    got = _read({"codec": "x", "data": ct.hex(),
                 "hint": "hex-decode the data, then AES-128-ECB decrypt with the key derived by PBKDF2 from "
                         "password 'pw' and salt 'salt' with 1000 iterations"})
    assert got[0][:2] == (CODE, "stated:hex>aes-ecb=kdf:pbkdf2-sha256")


def test_stated_hash_key_first_bytes_of_md5_of_a_field():
    from Crypto.Cipher import AES
    key = hashlib.md5(b"opensesame").digest()[:16]
    ct = AES.new(key, AES.MODE_ECB).encrypt(CB + bytes([12]) * 12)
    got = _read({"codec": "x", "data": ct.hex(), "passphrase": "opensesame",
                 "hint": "hex decode, then AES-128-ECB decrypt with key the first 16 bytes of the MD5 of the "
                         "passphrase field"})
    assert got[0][:2] == (CODE, "stated:hex>aes-ecb=kdf:md5")


def test_stated_hash_key_longer_than_its_digest_is_no_key():
    """`the first 24 bytes of the MD5`: MD5 gives 16, so the stated key does not exist (a cut would silently give the
    16-byte digest, which here is exactly the AES key that decrypts)."""
    from Crypto.Cipher import AES
    key = hashlib.md5(b"opensesame").digest()
    ct = AES.new(key, AES.MODE_ECB).encrypt(CB + bytes([12]) * 12)
    hint = "hex decode, then AES-128-ECB decrypt with key the first %d bytes of the MD5 of 'opensesame'"
    assert _read({"codec": "x", "data": ct.hex(), "hint": hint % 16})[0][:2] == (CODE, "stated:hex>aes-ecb=kdf:md5")
    assert S._hash_key("the key is the first 16 bytes of the MD5 of 'opensesame'", {}) == (key, "kdf:md5")
    assert S._hash_key("the key is the first 24 bytes of the MD5 of 'opensesame'", {}) is None
    assert _code_of(_read({"codec": "x", "data": ct.hex(), "hint": hint % 24})) is None


def test_an_unexecutable_stated_xtea_demotes_a_decoy_data():
    """A stated XTEA whose key is not stated, beside a `data` that base64-decodes to a decoy code: the shape is known,
    the recipe cannot be carried out, so codec_search must not bank the decoy plain."""
    decoy = "ANS-0000000000000001"
    doc = {"codec": "base64", "data": base64.b64encode(base64.b64encode(decoy.encode())).decode(),
           "hint": "base64-decode the data field, then XTEA decrypt it with the device key"}
    reason = S.states_unexecutable_cipher({PZ: json.dumps(doc).encode()})
    assert "xtea" in reason


def test_a_stated_recipe_reaches_the_solver_as_an_unsure_pick():
    xk = b"0123456789abcdef"
    doc = {"schema": F.V1, "day": 32, "codec": "vault", "data": xtea_encrypt(xk, CB + bytes([4]) * 4).hex(),
           "hint": "hex decode, then XTEA decrypt with key '0123456789abcdef'"}
    p = _unsure(C.solve_apk(_apk(doc)))
    assert CODE in [v for _n, v in p.options]


# ============================================================================ database_name / table_name

def _dex_with(*strings):
    d = DexWriter()
    d.cls("Lcom/h/Db;")
    for s in strings:
        d.s(s)
    return d.build()


def _sqlite(*tables):
    con = sqlite3.connect(":memory:")
    for t in tables:
        con.execute("CREATE TABLE %s (id INTEGER, v TEXT)" % t)
    con.execute("CREATE TABLE android_metadata (locale TEXT)")
    blob = con.serialize()
    con.close()
    return blob


def _q(qid):
    return {"id": qid, "qid": qid, "question": "What is the %s?" % qid.replace("_", " ")}


def test_database_and_table_name_from_dex_strings():
    members = {"classes.dex": _dex_with("vault.db", "CREATE TABLE IF NOT EXISTS secrets (k TEXT, v TEXT)")}
    out = AF.solve_questions([_q("database_name"), _q("table_name")], members)
    db, tb = labels.parse(out["database_name"]), labels.parse(out["table_name"])
    assert db.key == "mobile.database_name/apk" and db.options == [("as-written", "vault.db"), ("stem", "vault")]
    assert tb.key == "mobile.table_name/apk" and tb.options == [("as-written", "secrets")]


def test_database_and_table_name_from_a_sqlite_member():
    members = {"classes.dex": _dex_with("onCreate"), "assets/databases/notes.sqlite": _sqlite("entries")}
    out = AF.solve_questions([_q("database_name"), _q("table_name")], members)
    assert labels.parse(out["database_name"]).options[0] == ("as-written", "notes.sqlite")
    assert labels.parse(out["table_name"]).options == [("as-written", "entries")]


def test_framework_create_table_strings_in_the_dex_are_not_the_apps_table():
    """Room and SQLiteOpenHelper put their own CREATE TABLE in the dex beside the app's: the app's table is the one."""
    room = "CREATE TABLE IF NOT EXISTS room_master_table (id INTEGER PRIMARY KEY,identity_hash TEXT)"
    meta = "CREATE TABLE android_metadata (locale TEXT)"
    seq = "CREATE TABLE SQLITE_SEQUENCE (name, seq)"
    members = {"classes.dex": _dex_with(room, meta, seq, "CREATE TABLE IF NOT EXISTS `secrets` (k TEXT, v TEXT)")}
    out = AF.solve_questions([_q("table_name")], members)
    assert labels.parse(out["table_name"]).options == [("as-written", "secrets")]
    only = {"classes.dex": _dex_with(room, meta)}
    assert AF.solve_questions([_q("table_name")], only) == {"table_name": None}


def test_database_and_table_name_fail_closed():
    two = {"classes.dex": _dex_with("a.db", "b.db", "CREATE TABLE x (i INT)", "CREATE TABLE y (i INT)")}
    out = AF.solve_questions([_q("database_name"), _q("table_name")], two)
    assert out == {"database_name": None, "table_name": None}
    broken = {"classes.dex": _dex_with("CREATE TABLE x (i INT)"),
              "assets/x.db": b"SQLite format 3\x00" + b"\xff" * 200}
    assert AF.solve_questions([_q("table_name")], broken) == {"table_name": None}


# ============================================================================ the dex VM: TEXT and CROSSDEX

REL, HELP = "Lcom/p/Release;", "Lcom/p/Helper;"
SEED, MASK = 0x1122334455667788, 0x0F0F0F0F0F0F0F0F


def hex_tail(d, a, ret=True):
    a.op("new-instance", 2, d.t(SB)).op("invoke-direct", d.m(SB, "<init>"), [2])
    a.op("const-string", 3, d.s("ANS-")).op("invoke-virtual", d.m(SB, "append", SB, [STR]), [2, 3])
    a.op("const-string", 3, d.s("0123456789ABCDEF")).op("const/16", 4, 60)
    a.label("hex")
    a.op("ushr-long", 6, 0, 4).op("long-to-int", 8, 6).op("and-int/lit8", 8, 8, 15)
    a.op("invoke-virtual", d.m(STR, "charAt", "C", ["I"]), [3, 8]).op("move-result", 9)
    a.op("invoke-virtual", d.m(SB, "append", SB, ["C"]), [2, 9])
    a.op("add-int/lit8", 4, 4, -4).op("if-gez", 4, "hex")
    if ret:
        finish(d, a)


def finish(d, a):
    a.op("invoke-virtual", d.m(SB, "toString", STR), [2]).op("move-result-object", 2).op("return-object", 2)


def chain(body):
    """A dex whose Release.code() runs `body(d, a)`; the body ends with the code's String returned."""
    d = DexWriter()
    d.cls(REL)
    a = Asm()
    body(d, a)
    d.method(REL, "code", STR, [], a.finish(), regs=12)
    return d.build()


def run(files):
    feats, trace = {}, []
    codes, declines = DCC.analysis_codes_ex(files, _feats=feats, _trace=trace)
    return codes, declines, DF.key_suffix(feats, codes), [t.get("reason") for t in trace if t.get("reason")]


def sb_edit(kind):
    def body(d, a):
        a.op("const-wide", 0, SEED)
        hex_tail(d, a, ret=False)
        if kind == "deleteCharAt":
            a.op("const/4", 3, 4).op("const/16", 4, ord("Z"))
            a.op("invoke-virtual", d.m(SB, "insert", SB, ["I", "C"]), [2, 3, 4])
            a.op("invoke-virtual", d.m(SB, "deleteCharAt", SB, ["I"]), [2, 3])
        elif kind == "deleteCharAt-past-end":
            a.op("const/16", 3, 20).op("invoke-virtual", d.m(SB, "deleteCharAt", SB, ["I"]), [2, 3])
        elif kind == "delete-clamped":
            a.op("const-string", 4, d.s("JUNKJUNK")).op("invoke-virtual", d.m(SB, "append", SB, [STR]), [2, 4])
            a.op("const/16", 3, 20).op("const/16", 4, 999)
            a.op("invoke-virtual", d.m(SB, "delete", SB, ["I", "I"]), [2, 3, 4])
        elif kind == "delete-start-past-length":     # Java clamps end to 20, then start 25 > end throws
            a.op("const/16", 3, 25).op("const/16", 4, 999)
            a.op("invoke-virtual", d.m(SB, "delete", SB, ["I", "I"]), [2, 3, 4])
        elif kind == "delete-start-past-end":
            a.op("const/16", 3, 9).op("const/16", 4, 8)
            a.op("invoke-virtual", d.m(SB, "delete", SB, ["I", "I"]), [2, 3, 4])
        elif kind == "replace":
            a.op("const/4", 3, 0).op("const/4", 4, 4).op("const-string", 5, d.s("XYZ-"))
            a.op("invoke-virtual", d.m(SB, "replace", SB, ["I", "I", STR]), [2, 3, 4, 5])
            a.op("const/4", 4, 4).op("const-string", 5, d.s("ANS-"))
            a.op("invoke-virtual", d.m(SB, "replace", SB, ["I", "I", STR]), [2, 3, 4, 5])
        finish(d, a)
    return chain(body)


BASE = "ANS-%016X" % SEED


@pytest.mark.parametrize("kind", ["deleteCharAt", "delete-clamped", "replace"])
def test_text_stringbuilder_edits_read_the_code_under_their_own_family(kind):
    codes, declines, sfx, why = run({"classes.dex": sb_edit(kind)})
    assert codes == [BASE] and declines == 0 and sfx == "+dex-text", why


@pytest.mark.parametrize("kind", ["deleteCharAt-past-end", "delete-start-past-end", "delete-start-past-length"])
def test_text_an_index_java_rejects_declines(kind):
    codes, declines, _sfx, why = run({"classes.dex": sb_edit(kind)})
    assert codes == [] and declines == 1 and any("Java throws" in w for w in why), why


def test_text_a_supplementary_character_declines():
    """Java holds U+1F600 as two UTF-16 units, the VM as one character: an index or hash over it is not exact."""
    def body(d, a):
        a.op("new-instance", 2, d.t(SB)).op("invoke-direct", d.m(SB, "<init>"), [2])
        # new String(byte[] {F0 9F 98 80}, "UTF-8"): U+1F600, which Java holds as a surrogate pair
        a.op("const/4", 6, 4).op("new-array", 5, 6, d.t("[B"))
        for k, b in enumerate(b"\xf0\x9f\x98\x80"):
            a.op("const/16", 3, b - 256).op("const/4", 6, k)
            a.u += [0x4F | (3 << 8), 5 | (6 << 8)]                 # aput-byte v3, v5, v6 (23x)
        a.op("const-string", 8, d.s("UTF-8")).op("new-instance", 7, d.t(STR))
        a.op("invoke-direct", d.m(STR, "<init>", "V", ["[B", STR]), [7, 5, 8])
        a.op("invoke-virtual", d.m(SB, "append", SB, [STR]), [2, 7])
        for part in ("ANS-", "0123456789ABCDEF"):
            a.op("const-string", 3, d.s(part)).op("invoke-virtual", d.m(SB, "append", SB, [STR]), [2, 3])
        a.op("const/4", 3, 0).op("invoke-virtual", d.m(SB, "deleteCharAt", SB, ["I"]), [2, 3])
        finish(d, a)
    codes, declines, _sfx, why = run({"classes.dex": chain(body)})
    assert codes == [] and declines == 1 and any("supplementary" in w for w in why), why


def java_hash(s):
    h = 0
    for c in s:
        h = (31 * h + ord(c)) & 0xFFFFFFFF
    return h - (1 << 32) if h & 0x80000000 else h


def int_code(v):
    return "ANS-%016X" % (v & M64)


def int_chain(emit):
    """Release.code(): the int `emit` leaves in v3, sign-extended to a long, as 16 hex digits."""
    def body(d, a):
        emit(d, a)
        a.op("int-to-long", 0, 3)
        hex_tail(d, a)
    return chain(body)


def _string_call(name, ret, params, recv, *args):
    def emit(d, a):
        a.op("const-string", 10, d.s(recv))
        regs = [10]
        for i, v in enumerate(args):
            r = 11 if i == 0 else 5
            if isinstance(v, str):
                a.op("const-string", r, d.s(v))
            else:
                a.op("const/16", r, v)
            regs.append(r)
        a.op("invoke-virtual", d.m(STR, name, ret, params), regs).op("move-result", 3)
    return int_chain(emit)


@pytest.mark.parametrize("name,ret,params,recv,args,want", [
    ("hashCode", "I", [], "huntress-mobile", (), java_hash("huntress-mobile")),
    ("equals", "Z", [OBJ], "abc", ("abc",), 1),
    ("equals", "Z", [OBJ], "abc", ("abd",), 0),
    ("startsWith", "Z", [STR], "ANS-1234", ("ANS-",), 1),
    ("startsWith", "Z", [STR, "I"], "xxANS-", ("ANS-", 2), 1),
    ("startsWith", "Z", [STR, "I"], "xxANS-", ("ANS-", 9), 0),
    ("startsWith", "Z", [STR, "I"], "xxANS-", ("ANS-", -4), 0),     # Java: a negative offset is false, never from the end
    ("endsWith", "Z", [STR], "file.dex", (".dex",), 1),
    ("contains", "Z", ["Ljava/lang/CharSequence;"], "a-b-c", ("-b-",), 1),
    ("isEmpty", "Z", [], "", (), 1),
    ("compareTo", "I", [STR], "apple", ("apricot",), ord("p") - ord("r")),
    ("compareTo", "I", [STR], "ab", ("abcd",), -2),
    ("lastIndexOf", "I", [STR], "a.b.c.d", (".",), 5),
    ("lastIndexOf", "I", [STR, "I"], "a.b.c.d", (".", 4), 3),
    ("lastIndexOf", "I", ["I"], "a.b.c.d", (ord("b"),), 2),
])
def test_text_string_methods_match_java(name, ret, params, recv, args, want):
    codes, declines, sfx, why = run({"classes.dex": _string_call(name, ret, params, recv, *args)})
    assert codes == [int_code(want)] and declines == 0 and sfx == "+dex-text", why


def test_text_stringbuilder_index_of_and_substring():
    def body(d, a):
        a.op("new-instance", 2, d.t(SB)).op("const-string", 3, d.s("--ANS-0123456789ABCDEF--"))
        a.op("invoke-direct", d.m(SB, "<init>", "V", [STR]), [2, 3])
        a.op("const-string", 4, d.s("ANS-"))
        a.op("invoke-virtual", d.m(SB, "indexOf", "I", [STR]), [2, 4]).op("move-result", 5)
        a.op("add-int/lit8", 6, 5, 20)
        a.op("invoke-virtual", d.m(SB, "substring", STR, ["I", "I"]), [2, 5, 6]).op("move-result-object", 2)
        a.op("return-object", 2)
    codes, declines, sfx, why = run({"classes.dex": chain(body)})
    assert codes == ["ANS-0123456789ABCDEF"] and declines == 0 and sfx == "+dex-text", why


def helper_dex(*, clinit=False, impure=False, public=True, cls=HELP, inner=None, base=False, method_public=None):
    """classes2.dex's Helper.mix(J)J = x ^ MASK. `inner` "pure" / "impure": mix gets x from Helper.inner(J)J (the
    identity, or one that also reads a static field); `base`: Helper extends an app class Base of the same dex."""
    d = DexWriter()
    if base:
        d.cls("Lcom/p/Base;")
    d.cls(cls, flags=ACC_PUBLIC if public else 0, super_="Lcom/p/Base;" if base else OBJ)
    a = Asm()
    if impure:
        d.static_field(cls, STR, "tag")
        a.op("sget-object", 0, d.f(cls, STR, "tag"))
    if inner:
        b = Asm()
        if inner == "impure":
            d.static_field(cls, STR, "tag")
            b.op("sget-object", 0, d.f(cls, STR, "tag"))
        b.op("move-wide", 0, 2).op("return-wide", 0)
        im = d.method(cls, "inner", "J", ["J"], b.finish(), regs=4, flags=ACC_PUBLIC | ACC_STATIC)
        a.op("invoke-static", im, [2, 3]).op("move-result-wide", 2)
    a.op("const-wide", 0, MASK).op("xor-long/2addr", 0, 2).op("return-wide", 0)
    mpub = public if method_public is None else method_public
    d.method(cls, "mix", "J", ["J"], a.finish(), regs=4, flags=(ACC_PUBLIC if mpub else 0) | ACC_STATIC)
    if clinit:
        c = Asm().op("return-void").finish()
        d.method(cls, "<clinit>", "V", [], c, regs=1, flags=ACC_STATIC | ACC_CONSTRUCTOR)
    return d.build()


def cross_static_dex(cls=HELP):
    def body(d, a):
        a.op("const-wide", 0, SEED).op("invoke-static", d.m(cls, "mix", "J", ["J"]), [0, 1])
        a.op("move-result-wide", 0)
        hex_tail(d, a)
    return chain(body)


WANT = "ANS-%016X" % (SEED ^ MASK)


def test_crossdex_static_of_a_classpath_dex_reads_under_its_own_family():
    codes, declines, sfx, why = run({"classes.dex": cross_static_dex(), "classes2.dex": helper_dex()})
    assert codes == [WANT] and declines == 0 and sfx == "+dex-crossdex", why


@pytest.mark.parametrize("files,why_part", [
    ({"assets/helper.dex": helper_dex()}, "no body in this dex"),              # off the app class loader's path
    ({"classes3.dex": helper_dex()}, "no body in this dex"),                   # classes3 with no classes2: never opened
    ({"classes2.dex": helper_dex(clinit=True)}, "no body in this dex"),        # initializing it runs code
    ({"classes2.dex": helper_dex(impure=True)}, "no body in this dex"),        # a field read in the body
    ({"classes2.dex": helper_dex(inner="impure")}, "no body in this dex"),     # a field read in a callee
    ({"classes2.dex": helper_dex(base=True)}, "no body in this dex"),          # an app superclass to initialize
])
def test_crossdex_static_declines_outside_the_pure_classpath_subset(files, why_part):
    codes, declines, _sfx, why = run(dict({"classes.dex": cross_static_dex()}, **files))
    assert codes == [] and declines == 1 and any(why_part in w for w in why), why


def test_crossdex_static_follows_a_pure_static_callee():
    codes, declines, sfx, why = run({"classes.dex": cross_static_dex(), "classes2.dex": helper_dex(inner="pure")})
    assert codes == [WANT] and declines == 0 and sfx == "+dex-crossdex", why


def test_crossdex_static_declines_a_reference_parameter():
    """mix(String)J of another dex: a reference argument may alias the caller's objects; outside the subset."""
    h = DexWriter()
    h.cls(HELP)
    h.method(HELP, "mix", "J", [STR], Asm().op("const-wide", 0, MASK).op("return-wide", 0).finish(), regs=3)

    def body(d, a):
        a.op("const-string", 4, d.s("seed")).op("invoke-static", d.m(HELP, "mix", "J", [STR]), [4])
        a.op("move-result-wide", 0)
        hex_tail(d, a)
    codes, declines, _sfx, why = run({"classes.dex": chain(body), "classes2.dex": h.build()})
    assert codes == [] and declines == 1 and any("no body in this dex" in w for w in why), why


def test_crossdex_static_declines_a_class_two_dexes_define():
    files = {"classes.dex": cross_static_dex(), "classes2.dex": helper_dex(),
             "classes3.dex": helper_dex(clinit=False, public=False)}
    codes, declines, _sfx, _why = run(files)
    assert codes == [] and declines >= 1


def reflect_dex(accessible=False, name="com.p.Helper"):
    def body(d, a):
        a.op("const-wide", 0, SEED)
        a.op("const-string", 4, d.s(name))
        a.op("invoke-static", d.m(CLASS, "forName", CLASS, [STR]), [4]).op("move-result-object", 4)
        a.op("const/4", 5, 1).op("new-array", 5, 5, d.t("[Ljava/lang/Class;"))
        a.op("sget-object", 6, d.f(LONG, CLASS, "TYPE")).op("const/4", 7, 0).op("aput-object", 6, 5, 7)
        a.op("const-string", 3, d.s("mix"))
        a.op("invoke-virtual", d.m(CLASS, "getDeclaredMethod", METHOD, [STR, "[Ljava/lang/Class;"]), [4, 3, 5])
        a.op("move-result-object", 4)
        if accessible:
            a.op("const/4", 6, 1)
            a.op("invoke-virtual", d.m(METHOD, "setAccessible", "V", ["Z"]), [4, 6])
        a.op("invoke-static", d.m(LONG, "valueOf", LONG, ["J"]), [0, 1]).op("move-result-object", 6)
        a.op("const/4", 5, 1).op("new-array", 5, 5, d.t("[Ljava/lang/Object;")).op("aput-object", 6, 5, 7)
        a.op("const/4", 6, 0)
        a.op("invoke-virtual", d.m(METHOD, "invoke", OBJ, [OBJ, "[Ljava/lang/Object;"]), [4, 6, 5])
        a.op("move-result-object", 4).op("check-cast", 4, d.t(LONG))
        a.op("invoke-virtual", d.m(LONG, "longValue", "J"), [4]).op("move-result-wide", 0)
        hex_tail(d, a)
    return chain(body)


def test_crossdex_reflection_reads_a_public_static_of_another_dex():
    codes, declines, sfx, why = run({"classes.dex": reflect_dex(), "classes2.dex": helper_dex()})
    assert codes == [WANT] and declines == 0 and sfx == "+dex-crossdex+dex-reflect", why


def test_crossdex_reflection_access_check():
    files = {"classes.dex": reflect_dex(), "classes2.dex": helper_dex(public=False)}
    codes, declines, _sfx, why = run(files)
    assert codes == [] and declines == 1 and any("setAccessible" in w for w in why), why
    files["classes.dex"] = reflect_dex(accessible=True)
    codes, declines, sfx, why = run(files)
    assert codes == [WANT] and declines == 0 and "+dex-crossdex" in sfx, why


def test_crossdex_reflection_needs_a_public_class_too():
    """ART's rule has two halves: a public method of a NON-public class of another package is IllegalAccessException
    without setAccessible(true). The class here is com.q.Helper, so no same-package access applies."""
    other = "Lcom/q/Helper;"
    assert run({"classes.dex": reflect_dex(name="com.q.Helper"), "classes2.dex": helper_dex(cls=other)})[0] == [WANT]
    files = {"classes.dex": reflect_dex(name="com.q.Helper"),
             "classes2.dex": helper_dex(cls=other, public=False, method_public=True)}
    codes, declines, _sfx, why = run(files)
    assert codes == [] and declines == 1 and any("setAccessible" in w for w in why), why
    files["classes.dex"] = reflect_dex(accessible=True, name="com.q.Helper")
    codes, declines, sfx, why = run(files)
    assert codes == [WANT] and declines == 0 and "+dex-crossdex" in sfx, why


def reflect_get_method_dex():
    def body(d, a):
        a.op("const-wide", 0, SEED)
        a.op("const-string", 4, d.s("com.p.Helper"))
        a.op("invoke-static", d.m(CLASS, "forName", CLASS, [STR]), [4]).op("move-result-object", 4)
        a.op("const/4", 5, 1).op("new-array", 5, 5, d.t("[Ljava/lang/Class;"))
        a.op("sget-object", 6, d.f(LONG, CLASS, "TYPE")).op("const/4", 7, 0).op("aput-object", 6, 5, 7)
        a.op("const-string", 3, d.s("mix"))
        a.op("invoke-virtual", d.m(CLASS, "getMethod", METHOD, [STR, "[Ljava/lang/Class;"]), [4, 3, 5])
        a.op("move-result-object", 4)
        a.op("invoke-static", d.m(LONG, "valueOf", LONG, ["J"]), [0, 1]).op("move-result-object", 6)
        a.op("const/4", 5, 1).op("new-array", 5, 5, d.t("[Ljava/lang/Object;")).op("aput-object", 6, 5, 7)
        a.op("const/4", 6, 0)
        a.op("invoke-virtual", d.m(METHOD, "invoke", OBJ, [OBJ, "[Ljava/lang/Object;"]), [4, 6, 5])
        a.op("move-result-object", 4).op("check-cast", 4, d.t(LONG))
        a.op("invoke-virtual", d.m(LONG, "longValue", "J"), [4]).op("move-result-wide", 0)
        hex_tail(d, a)
    return chain(body)


def test_crossdex_reflection_get_method_needs_a_public_method():
    codes, declines, sfx, why = run({"classes.dex": reflect_get_method_dex(), "classes2.dex": helper_dex()})
    assert codes == [WANT] and declines == 0 and "+dex-crossdex" in sfx, why
    codes, declines, _sfx, why = run({"classes.dex": reflect_get_method_dex(),
                                      "classes2.dex": helper_dex(public=False)})
    assert codes == [] and declines == 1, why


def test_a_crossdex_code_is_never_plain_under_the_judged_analysis_key():
    files = {"classes.dex": cross_static_dex(), "classes2.dex": helper_dex(),
             PZ: json.dumps({"schema": "huntress.mobile.puzzle.v2", "day": 32, "codec": "analysis"}).encode()}
    q = {"id": "answer", "answer_format": {"kind": "pattern", "syntax": "ANS- followed by 16 hex"}}
    out = C.solve_set([q], files, {})["answer"]
    p = _unsure(out)
    assert p.key.endswith("+dex-crossdex") and [v for _n, v in p.options] == [WANT]


# ============================================================================ the gate reads the compact unsure form

def test_the_gate_reads_the_labels_compact_unsure_encoding():
    from ctf.lookahead import gate as G
    ans = labels.pick("mobile.codec/x", [("route", CODE)])
    assert ans.startswith("??") and '"o"' in ans
    assert G.classify({"id": "answer"}, ans, {"answer": CODE}) == ("unsure", "")
    assert G.classify({"id": "answer"}, ans, {"answer": "ANS-0000000000000000"})[0] == "wrong"


# ============================================================================ look-ahead specimens (B-174 gate)

def test_the_specimen_oracles_and_builders():
    from ctf.lookahead import mobile_specimens as MS
    assert MS.thumb_code() == "ANS-%08X%08X" % (((MS.SEEDS[0] << 3) + 0x5B), ((MS.SEEDS[1] << 3) + 0x5B))
    so = MS.thumb_members()[MS.SO_PATH]
    assert so[:4] == b"\x7fELF" and so[4] == 1 and struct.unpack_from("<H", so, 18)[0] == 40
    import dynamic_members as DM
    assert MS.hermes_code() in DM.hermes_strings(MS.hermes_members()[MS.BUNDLE])


@pytest.mark.needs_tool("py:unicorn")
def test_the_thumb_specimen_decodes_with_capstone_and_reads_through_the_solver():
    from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
    from ctf.lookahead import mobile_specimens as MS
    mn = [i.mnemonic for i in Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(struct.pack("<4H", *MS.THUMB_DERIVE), 0)]
    assert mn[0] == "mov" and mn[-1] == "bx" and len(mn) == 4
    out = C.solve_set([MS.QUESTION], MS.thumb_members(), {})
    assert out == {"answer": MS.thumb_code()}
    assert C.solve_set([MS.QUESTION], MS.thumb_members(gate_fail=True), {}) == {"answer": None}


def _gate(tmp_path, name, guard, **kw):
    from ctf.lookahead import gate as G
    from ctf.lookahead import matrix as M
    from ctf.lookahead import mobile_specimens as MS
    mx = M.load(MS.write(tmp_path / name, **kw))
    return G.evaluate(mx, MS.LANE, G.run_lane(mx, MS.LANE, root=REPO, guard=guard, workdir=tmp_path / (name + "-wd"))
                      ).to_json()


def _gaps(j):
    return [(g["kind"], g["specimen"]) for g in j["gaps"]]


def test_the_hermes_specimen_through_the_gate_under_the_audit_hook(tmp_path):
    from ctf.lookahead import forecast as FC
    from ctf.lookahead import mobile_specimens as MS
    j = _gate(tmp_path, "h", "hook", only=["hermes_bundle"])
    assert j["verdict"] == "green", j["gaps"]
    assert {r["specimen"]: r["status"] for r in j["rows"]} == {"hermes_bundle": "unsure"}
    assert FC.load(tmp_path / "h" / "forecast.toml").lanes[MS.LANE].new == ("answer",)
    j = _gate(tmp_path, "h2", "hook", only=["hermes_bundle"], allow_unsure=False)
    assert j["verdict"] == "red" and _gaps(j) == [("unsure", "hermes_bundle")]
    with pytest.raises(ValueError, match="unknown mobile specimen"):
        MS.write(tmp_path / "bad", only=["arm64_jni"])


def test_under_the_audit_hook_alone_the_thumb_specimen_is_a_gap_never_silently_green(tmp_path):
    """The audit-hook guard refuses ctypes, which the native emulator needs: the Thumb id comes back unanswered and
    the gate is red, naming the specimen (the look-ahead does not pass a shape it could not run)."""
    j = _gate(tmp_path, "t", "hook", only=["thumb_jni"])
    assert j["verdict"] == "red" and _gaps(j) == [("unanswered", "thumb_jni")]


@pytest.mark.needs_tool("py:unicorn")
def test_the_mobile_matrix_under_the_os_sandbox_is_green_and_its_control_turns_it_red(tmp_path):
    from ctf.intake import guard as IG
    try:
        g = IG.resolve("os")
    except IG.GuardError as e:
        pytest.skip(f"OS network sandbox unavailable here, so the Thumb specimen cannot run in the gate: {e}")
    j = _gate(tmp_path, "m", g)
    assert j["verdict"] == "green", j["gaps"]
    assert {r["specimen"]: r["status"] for r in j["rows"]} == {"thumb_jni": "correct", "hermes_bundle": "unsure"}
    j = _gate(tmp_path, "m2", g, controls=True)
    assert j["verdict"] == "red" and _gaps(j) == [("unanswered", "thumb_gate_fail")]
