"""B-060: the no-model AES-GCM nonce-reuse intake adapter (solvers/common/gcm_nonce_intake.py).

Every fixture is built synthetically inside the test: real AES-GCM tags are produced under a chosen key
and a deliberately reused nonce (pycryptodome), the forbidden attack recovers the subkey, and the sealed
blob is opened under it. No real challenge file is used, and no challenge binary is executed.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from ctf import event

import gcm_nonce_intake as gni            # conftest puts solvers/common on sys.path

CSCTF = event.load("csctf")
# The fixtures (and the engine's own decryption) need an AES backend; reported NOT RUN if it is absent.
pytestmark = pytest.mark.needs_tool("py:Crypto")

from Crypto.Cipher import AES            # noqa: E402
from Crypto.Util import Counter          # noqa: E402


# --------------------------------------------------------------------------- fixture helpers

def _gcm(key: bytes, nonce: bytes, pt: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    c = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        c.update(aad)
    return c.encrypt_and_digest(pt)


def _tag_mask(key: bytes, nonce: bytes) -> bytes:
    """S = E_K(J0); for a 12-byte nonce J0 = nonce || 0x00000001."""
    return AES.new(key, AES.MODE_ECB).encrypt(nonce + b"\x00\x00\x00\x01")


def _ctr_seal(key: bytes, pt: bytes) -> bytes:
    return AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=0)).encrypt(pt)


def _dispatches(key: bytes, nonce: bytes, n: int = 3, enc=lambda b: b.hex(), suffix="_hex"):
    """`n` single-block (ciphertext, tag) records under one reused nonce, as JSON-ready dicts."""
    out = []
    for i in range(n):
        ct, tag = _gcm(key, nonce, f"RELAY CHECK {i:04d}".encode().ljust(16, b" "))
        out.append({"ciphertext" + suffix: enc(ct), "tag" + suffix: enc(tag)})
    return out


def _watchword(key, nonce, flag, *, n=3, enc=lambda b: b.hex(), suffix="_hex") -> dict:
    sealed = _ctr_seal(_tag_mask(key, nonce), flag.encode())
    return {
        "link": "SABRELINK",
        "nonce" + suffix: enc(nonce),
        "intercepts": _dispatches(key, nonce, n, enc, suffix),
        "sealed_master_order_ctr" + suffix: enc(sealed),
    }


def _write(challenge_dir: Path, rel: str, obj) -> Path:
    p = challenge_dir / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


FLAG = "CSCTF{synthetic_forbidden_attack_0001}"
KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
NONCE = bytes.fromhex("8f7ce996b767134353fe1145")


# --------------------------------------------------------------------------- field normalisation

def test_split_encoding_strips_the_suffix_and_role_maps_the_base():
    assert gni._split_encoding("ciphertext_hex") == ("ciphertext", "hex")
    assert gni._split_encoding("tag_b64") == ("tag", "b64")
    assert gni._split_encoding("nonce_base64url") == ("nonce", "b64url")
    assert gni._split_encoding("associated_data_base32") == ("associated_data", "b32")
    assert gni._split_encoding("plaintext") == ("plaintext", None)
    assert gni._role("ciphertext") == "ct" and gni._role("tag") == "tag"
    assert gni._role("aad") == "aad" and gni._role("nonce") == "nonce"
    assert gni._role("sealed_master_order_ctr") is None


def test_decode_honours_each_encoding():
    assert gni._decode("48656c6c6f", "hex") == b"Hello"
    assert gni._decode(base64.b64encode(b"Hello").decode(), "b64") == b"Hello"
    assert gni._decode(base64.urlsafe_b64encode(b"\xfa\xfb\xfc").decode().rstrip("="), "b64url") == b"\xfa\xfb\xfc"
    assert gni._decode("zzzz", "hex") is None          # a declared hex that is not hex is rejected
    assert gni._decode(123, "hex") is None


# --------------------------------------------------------------------------- end to end

def test_recovers_unique_subkey_and_opens_the_ctr_seal(tmp_path):
    """The 9061 shape: 3 reused-nonce dispatches + a CTR seal keyed by E_K(J0); solve returns the flag."""
    _write(tmp_path, "files/intercepts.json", _watchword(KEY, NONCE, FLAG))
    res = gni.solve(tmp_path, CSCTF)
    assert res.status == "solved"
    assert res.flags == (FLAG,)
    assert res.evidence and res.evidence[0].path == "files/intercepts.json"
    assert "aes-ctr" in res.evidence[0].detail


def test_records_and_seal_given_in_base64_also_recover(tmp_path):
    """The *_b64 field names a real export may use are normalised just like *_hex (kills a hex-only path)."""
    obj = _watchword(KEY, NONCE, FLAG, enc=lambda b: base64.b64encode(b).decode(), suffix="_b64")
    _write(tmp_path, "files/export.json", obj)
    res = gni.solve(tmp_path, CSCTF)
    assert res.status == "solved" and res.flags == (FLAG,)


def test_two_pairs_are_ambiguous_and_never_decrypt(tmp_path):
    """With only two pairs every GF(2^128) root is self-consistent, so no unique H is accepted and the
    sealed blob is not opened (a wrong H would otherwise emit a garbage 'flag')."""
    _write(tmp_path, "files/intercepts.json", _watchword(KEY, NONCE, FLAG, n=2))
    res = gni.solve(tmp_path, CSCTF)
    assert res.status == "none"
    assert res.flags == ()


def test_unique_subkey_but_no_flag_body_is_unsure_not_solved(tmp_path):
    """The subkey recovers, but the sealed text is not in the event flag format: flagfmt gates it, so the
    engine reports unsure (with H/S in the notes), never a false solved."""
    not_a_flag = "attack at dawn, hold the line"
    obj = _watchword(KEY, NONCE, FLAG, n=3)
    obj["sealed_master_order_ctr_hex"] = _ctr_seal(_tag_mask(KEY, NONCE), not_a_flag.encode()).hex()
    _write(tmp_path, "files/intercepts.json", obj)
    res = gni.solve(tmp_path, CSCTF)
    assert res.status == "unsure"
    assert res.flags == ()
    assert f"{int.from_bytes(_tag_mask(KEY, NONCE), 'big'):032x}" in res.notes      # S is offered to the human


def test_no_gcm_material_is_none(tmp_path):
    _write(tmp_path, "files/config.json", {"name": "x", "value_hex": "deadbeef"})
    res = gni.solve(tmp_path, CSCTF)
    assert res.status == "none"
    assert "no AES-GCM nonce-reuse material" in res.notes


def test_a_twelve_byte_tag_is_not_taken_as_an_observation(tmp_path):
    """A short 'tag' is not a GCM auth tag; without a 16-byte tag there is no observation to recover from."""
    bad = {"intercepts": [{"ciphertext_hex": ("aa" * 16), "tag_hex": ("bb" * 12)} for _ in range(3)]}
    _write(tmp_path, "files/x.json", bad)
    res = gni.solve(tmp_path, CSCTF)
    assert res.status == "none"
    assert "no AES-GCM nonce-reuse material" in res.notes      # tags rejected -> no observation at all


def test_material_in_an_unpacked_member_recovers_and_recon_is_skipped(tmp_path):
    """Intake writes the sweep's members under unpacked/; its own reports live under recon/ and are not
    challenge data. Material only under recon/ must be ignored; material under unpacked/ must be found."""
    _write(tmp_path, "unpacked/watchword.zip.unpacked/watchword/intercepts.json", _watchword(KEY, NONCE, FLAG))
    _write(tmp_path, "recon/engines/decoy.json", _watchword(KEY, NONCE, "CSCTF{decoy_from_recon}"))
    res = gni.solve(tmp_path, CSCTF)
    assert res.status == "solved" and res.flags == (FLAG,)


def test_nonce_grouping_recovers_the_single_reused_nonce_group(tmp_path):
    """Three dispatches share nonce A (recoverable) and two share nonce B. The engine groups by nonce, so
    the A group recovers; lumping all five would fail verification and recover nothing."""
    nonce_a, nonce_b = NONCE, bytes.fromhex("111111111111111111111111")
    obj = {
        "intercepts": (
            [dict(d, nonce_hex=nonce_a.hex()) for d in _dispatches(KEY, nonce_a, 3)]
            + [dict(d, nonce_hex=nonce_b.hex()) for d in _dispatches(KEY, nonce_b, 2)]
        ),
        "sealed_master_order_ctr_hex": _ctr_seal(_tag_mask(KEY, nonce_a), FLAG.encode()).hex(),
    }
    _write(tmp_path, "files/mixed.json", obj)
    res = gni.solve(tmp_path, CSCTF)
    assert res.status == "solved" and res.flags == (FLAG,)


def test_two_nonces_without_a_group_of_three_recover_nothing(tmp_path):
    nonce_a, nonce_b = NONCE, bytes.fromhex("222222222222222222222222")
    obj = {"intercepts": (
        [dict(d, nonce_hex=nonce_a.hex()) for d in _dispatches(KEY, nonce_a, 2)]
        + [dict(d, nonce_hex=nonce_b.hex()) for d in _dispatches(KEY, nonce_b, 2)]
    )}
    _write(tmp_path, "files/mixed.json", obj)
    res = gni.solve(tmp_path, CSCTF)
    assert res.status == "none"


def test_missing_aes_backend_blocks_with_a_named_reason(tmp_path, monkeypatch):
    """When a unique subkey is found but the AES backend is absent, the seal cannot be opened: the engine
    blocks and names the missing tool rather than silently reporting none."""
    _write(tmp_path, "files/intercepts.json", _watchword(KEY, NONCE, FLAG))

    def _no_backend(key, blob, nonce):
        raise ImportError("No module named 'Crypto'")

    monkeypatch.setattr(gni, "_trial_decrypts", _no_backend)
    res = gni.solve(tmp_path, CSCTF)
    assert res.status == "blocked"
    assert "pycryptodome" in res.notes and "py:Crypto" in res.notes


# --------------------------------------------------------------------------- round-1 verification fixes

def _subkey(key: bytes) -> bytes:
    """H = E_K(0^128), the GHASH subkey."""
    return AES.new(key, AES.MODE_ECB).encrypt(b"\x00" * 16)


def _intercepts_only(key=KEY, nonce=NONCE, n=3) -> dict:
    return {"nonce_hex": nonce.hex(), "intercepts": _dispatches(key, nonce, n)}


def test_undeclared_hex_with_leading_zeros_is_read_as_hex():
    """Only a literal 0x prefix is stripped before the parity check; lstrip('0xX') used to eat leading
    zeros and read an odd-zero hex value as base64."""
    assert gni._decode("0abc", None) == b"\x0a\xbc"
    assert gni._decode("000abc", None) == b"\x00\x0a\xbc"
    assert gni._decode("0x0abc", None) == b"\x0a\xbc"


def test_a_seal_in_a_json_sorted_before_the_intercepts_is_tried(tmp_path):
    """Blobs from every document are trialled once the subkey is recovered, not only those read after it."""
    _write(tmp_path, "files/a_sealed.json",
           {"sealed_order_hex": _ctr_seal(_tag_mask(KEY, NONCE), FLAG.encode()).hex()})
    _write(tmp_path, "files/b_intercepts.json", _intercepts_only())
    res = gni.solve(tmp_path, CSCTF)
    assert res.status == "solved" and res.flags == (FLAG,)
    assert res.evidence[0].path == "files/a_sealed.json"
    assert "files/b_intercepts.json" in res.notes          # the subkey's source is still named


def test_a_non_unique_subkey_is_declined(tmp_path, monkeypatch):
    """Two candidates (even when the first one is the true subkey) are not a unique H: nothing is opened."""
    _write(tmp_path, "files/intercepts.json", _watchword(KEY, NONCE, FLAG))
    true_hs = (int.from_bytes(_subkey(KEY), "big"), int.from_bytes(_tag_mask(KEY, NONCE), "big"))
    monkeypatch.setattr(gni._depth, "gcm_recover_subkey", lambda triples: [true_hs, (1, 2)])
    res = gni.solve(tmp_path, CSCTF)
    assert res.status == "none" and res.flags == ()
    monkeypatch.setattr(gni._depth, "gcm_recover_subkey", lambda triples: [true_hs])
    assert gni.solve(tmp_path, CSCTF).status == "solved"    # the same handout opens with a unique H


def test_a_seal_keyed_by_h_opens_and_is_labelled_h(tmp_path):
    obj = _intercepts_only()
    obj["sealed_hex"] = _ctr_seal(_subkey(KEY), FLAG.encode()).hex()
    _write(tmp_path, "files/intercepts.json", obj)
    res = gni.solve(tmp_path, CSCTF)
    assert res.status == "solved" and res.flags == (FLAG,)
    assert "H=E_K(0^128)" in res.evidence[0].detail
    assert "E_K(J0)" not in res.evidence[0].detail


@pytest.mark.parametrize("mode", ["aes-ecb", "aes-cbc"])
def test_block_mode_seals_under_s_open(tmp_path, mode):
    from Crypto.Util.Padding import pad

    s = _tag_mask(KEY, NONCE)
    cipher = AES.new(s, AES.MODE_ECB) if mode == "aes-ecb" else AES.new(s, AES.MODE_CBC, iv=b"\x00" * 16)
    obj = _intercepts_only()
    obj["sealed_hex"] = cipher.encrypt(pad(FLAG.encode(), 16)).hex()
    _write(tmp_path, "files/intercepts.json", obj)
    res = gni.solve(tmp_path, CSCTF)
    assert res.status == "solved" and res.flags == (FLAG,)
    assert res.evidence[0].detail.startswith(mode + " ")
    assert "S=E_K(J0)" in res.evidence[0].detail


@pytest.mark.parametrize("nonce_at", ["top", "sibling"])
def test_gcm_keystream_seal_under_the_recovered_nonce_opens(tmp_path, nonce_at):
    """A seal made as AES-GCM under S with the reused nonce. In the 'sibling' layout the records carry no
    nonce in scope, so the engine must take the nonce the document names elsewhere."""
    sealed = AES.new(_tag_mask(KEY, NONCE), AES.MODE_GCM, nonce=NONCE).encrypt(FLAG.encode())
    if nonce_at == "top":
        obj = _intercepts_only()
    else:
        obj = {"intercepts": _dispatches(KEY, NONCE, 3), "meta": {"nonce_hex": NONCE.hex()}}
    obj["sealed_hex"] = sealed.hex()
    _write(tmp_path, "files/intercepts.json", obj)
    res = gni.solve(tmp_path, CSCTF)
    assert res.status == "solved" and res.flags == (FLAG,)
    assert res.evidence[0].detail.startswith("aes-gcm-keystream ")


def test_a_sealed_binary_member_is_tried(tmp_path):
    _write(tmp_path, "files/intercepts.json", _intercepts_only())
    (tmp_path / "unpacked" / "h.zip.unpacked").mkdir(parents=True)
    (tmp_path / "unpacked" / "h.zip.unpacked" / "sealed.bin").write_bytes(
        _ctr_seal(_tag_mask(KEY, NONCE), FLAG.encode()))
    res = gni.solve(tmp_path, CSCTF)
    assert res.status == "solved" and res.flags == (FLAG,)
    assert res.evidence[0].path == "unpacked/h.zip.unpacked/sealed.bin"


def test_a_hex_text_member_is_decoded_and_tried(tmp_path):
    _write(tmp_path, "files/intercepts.json", _intercepts_only())
    (tmp_path / "files" / "sealed.txt").write_text(
        _ctr_seal(_tag_mask(KEY, NONCE), FLAG.encode()).hex() + "\n", encoding="ascii")
    res = gni.solve(tmp_path, CSCTF)
    assert res.status == "solved" and res.flags == (FLAG,)
    assert res.evidence[0].path == "files/sealed.txt"


def test_a_tagless_ciphertext_field_is_a_leftover_blob(tmp_path):
    obj = _intercepts_only()
    obj["sealed"] = {"ciphertext_hex": _ctr_seal(_tag_mask(KEY, NONCE), FLAG.encode()).hex()}
    _write(tmp_path, "files/intercepts.json", obj)
    res = gni.solve(tmp_path, CSCTF)
    assert res.status == "solved" and res.flags == (FLAG,)
    assert "ciphertext_hex" in res.evidence[0].detail


def test_metadata_names_are_skipped_only_at_the_root(tmp_path):
    """A handout member called challenge.json under unpacked/ is challenge data; the root one is intake's."""
    _write(tmp_path, "challenge.json", _watchword(KEY, NONCE, FLAG))
    assert gni.solve(tmp_path, CSCTF).status == "none"
    _write(tmp_path, "unpacked/h.zip.unpacked/challenge.json", _watchword(KEY, NONCE, FLAG))
    res = gni.solve(tmp_path, CSCTF)
    assert res.status == "solved" and res.flags == (FLAG,)
    assert res.evidence[0].path == "unpacked/h.zip.unpacked/challenge.json"


@pytest.mark.parametrize("rel", [".ctf/intercepts.json", "files/.git/intercepts.json",
                                 "files/.env.json", "unpacked/.ctf/x/intercepts.json"])
def test_the_sweep_credential_fence_holds(tmp_path, rel):
    """Nothing in a .ctf/ or .git/ folder or named .env* is read (ctf.sweep's fence)."""
    _write(tmp_path, rel, _watchword(KEY, NONCE, FLAG))
    res = gni.solve(tmp_path, CSCTF)
    assert res.status == "none"
    assert "no AES-GCM nonce-reuse material" in res.notes


def test_a_seal_inside_a_credentials_folder_is_not_read(tmp_path):
    _write(tmp_path, "files/intercepts.json", _intercepts_only())
    (tmp_path / "files" / ".ctf").mkdir()
    (tmp_path / "files" / ".ctf" / "sealed.bin").write_bytes(
        _ctr_seal(_tag_mask(KEY, NONCE), FLAG.encode()))
    res = gni.solve(tmp_path, CSCTF)
    assert res.status == "unsure" and res.flags == ()


# --------------------------------------------------------------------------- the manifest wiring

def test_manifest_declares_the_challenge_mode_intake_adapter():
    from ctf import paths
    from ctf.engines import manifest as M

    ms = {m.id: m for m in M.discover(paths.repo_root())}
    m = ms["common.gcm_nonce_intake"]
    assert m.entry.kind == "function" and m.entry.function == "solve"
    assert m.intake is not None
    assert m.intake.run == "challenge" and m.intake.select == "files"
    assert "ext:.json" in m.intake.match
    assert m.status == "active" and m.routes          # routed, so triage can also surface it


# --------------------------------------------------------------------------- round-2 verification fixes

def test_a_symlinked_member_outside_the_challenge_folder_is_not_read(tmp_path):
    """A link in files/ to a sealed blob outside the challenge folder is never followed (read fence): the
    subkey still recovers from the real intercepts, but the outside seal is not opened."""
    challenge = tmp_path / "challenge"
    _write(challenge, "files/intercepts.json", _intercepts_only())
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "sealed.bin").write_bytes(_ctr_seal(_tag_mask(KEY, NONCE), FLAG.encode()))
    (challenge / "files" / "sealed.bin").symlink_to(outside / "sealed.bin")
    res = gni.solve(challenge, CSCTF)
    assert res.status == "unsure" and res.flags == ()
    # Control: the same seal as a regular file inside the folder opens, so the link alone kept it out.
    (challenge / "files" / "sealed.bin").unlink()
    (challenge / "files" / "sealed.bin").write_bytes((outside / "sealed.bin").read_bytes())
    assert gni.solve(challenge, CSCTF).flags == (FLAG,)


def test_a_symlinked_json_outside_the_challenge_folder_is_not_read(tmp_path):
    """A linked JSON handout (intercepts and seal together) outside the folder recovers nothing."""
    challenge = tmp_path / "challenge"
    (challenge / "files").mkdir(parents=True)
    _write(tmp_path, "outside/intercepts.json", _watchword(KEY, NONCE, FLAG))
    (challenge / "files" / "intercepts.json").symlink_to(tmp_path / "outside" / "intercepts.json")
    res = gni.solve(challenge, CSCTF)
    assert res.status == "none" and res.flags == ()


def test_a_symlinked_directory_outside_the_challenge_folder_is_not_entered(tmp_path):
    challenge = tmp_path / "challenge"
    _write(challenge, "files/intercepts.json", _intercepts_only())
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "sealed.bin").write_bytes(_ctr_seal(_tag_mask(KEY, NONCE), FLAG.encode()))
    (challenge / "files" / "linked").symlink_to(outside, target_is_directory=True)
    res = gni.solve(challenge, CSCTF)
    assert res.status == "unsure" and res.flags == ()


def test_a_single_unverified_candidate_is_rejected_by_the_recheck(tmp_path):
    """gcm_recover_subkey returning ONE (H, S) whose tags do not reproduce is not accepted: the engine's own
    re-check rejects it. The seal is keyed by that wrong S, so accepting it would emit the flag."""
    wrong_h, wrong_s = 0x0123456789ABCDEF0123456789ABCDEF, 0xFEDCBA9876543210FEDCBA9876543210
    obj = _intercepts_only()
    obj["sealed_hex"] = _ctr_seal(wrong_s.to_bytes(16, "big"), FLAG.encode()).hex()
    _write(tmp_path, "files/intercepts.json", obj)
    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setattr(gni._depth, "gcm_recover_subkey", lambda triples: [(wrong_h, wrong_s)])
        res = gni.solve(tmp_path, CSCTF)
    finally:
        monkeypatch.undo()
    assert res.status == "none" and res.flags == ()


def test_manifest_declares_the_aes_backend_it_needs():
    """Intake's planner skips the engine up front (named reason) when pycryptodome is absent."""
    from ctf import paths
    from ctf.engines import manifest as M
    from ctf.intake import engines as IE

    m = {m.id: m for m in M.discover(paths.repo_root())}["common.gcm_nonce_intake"]
    assert "py:Crypto" in m.needs_tools
    assert IE.tool_missing(m.needs_tools) == []          # installed here, so intake does run it


def test_a_recon_folder_below_the_root_is_read(tmp_path):
    """Only intake's own recon/ at the challenge root is skipped; a handout's nested recon/ is data."""
    _write(tmp_path, "files/recon/intercepts.json", _watchword(KEY, NONCE, FLAG))
    res = gni.solve(tmp_path, CSCTF)
    assert res.status == "solved" and res.flags == (FLAG,)


@pytest.mark.parametrize("name", [".ctf", ".git"])
def test_a_file_named_like_a_credentials_folder_is_not_read(tmp_path, name):
    """The sweep's fence covers a path part named .ctf/.git, the file's own name included."""
    _write(tmp_path, "files/intercepts.json", _intercepts_only())
    (tmp_path / "files" / name).write_bytes(_ctr_seal(_tag_mask(KEY, NONCE), FLAG.encode()))
    res = gni.solve(tmp_path, CSCTF)
    assert res.status == "unsure" and res.flags == ()
