"""B-086: Android unlock-crypto chain solver (solvers/mobile-android/apk_unlock_crypto.py).

Every APK fixture is built synthetically in-test (rule 4): a real EC-signed X.509 cert in a v2/v3 APK
Signing Block or a v1 META-INF PKCS#7 block, R.string values in a hand-encoded resources.arsc,
string constants in a hand-encoded dex, receiver actions in a hand-encoded binary AndroidManifest,
and an AES-GCM/CBC ciphertext the engine must derive the key for and open.  No challenge binary is
executed.  Budgets that matter are explicit; the CPU time budget is driven by an injected step clock
(rule 16), never by wall time.
"""
import base64
import datetime
import hashlib
import hmac
import io
import json
import os
import struct
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "solvers" / "mobile-android"))
sys.path.insert(0, str(ROOT / "solvers" / "common"))

from ctf import event, flagfmt  # noqa: E402
import apk_unlock_crypto as U  # noqa: E402

CSCTF = event.load("csctf")
FF = flagfmt.for_profile(CSCTF)
FLAG = "CSCTF{v4ultk33p3r_unl0ck3d}"
PASSCODE = "CARD-7731"
PIN = "4972"
TEMPLATE = "KJSC-%s-RECOVERY"
ACTION = "org.csctf.vault.action.UNLOCK"


# --------------------------------------------------------------------------- fixture builders

def _ec_cert():
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "VaultKeeper")])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2026, 1, 1))
            .not_valid_after(datetime.datetime(2030, 1, 1))
            .sign(key, hashes.SHA256()))


def _ec_cert_der() -> bytes:
    from cryptography.hazmat.primitives import serialization
    return _ec_cert().public_bytes(serialization.Encoding.DER)


def _v1_rsa_block(cert) -> bytes:
    """A META-INF/CERT.RSA-shaped PKCS#7 (certs-only) carrying the signer cert."""
    from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
    return pkcs7.serialize_certificates([cert], Encoding.DER)


def _lp(b: bytes) -> bytes:
    return struct.pack("<I", len(b)) + b


def _v2_signing_block(cert_der: bytes, scheme_id: int = U._V2_SCHEME_ID) -> bytes:
    """A minimal but structurally valid APK Signing Block carrying one signer leaf cert under
    `scheme_id` (v2 or v3).  Only the certificate must parse; digests/signatures/public-key are
    filler (the engine reads the cert, it does not verify the signature)."""
    certs_seq = _lp(cert_der)                       # sequence: one length-prefixed cert
    digests_seq = _lp(b"\x01\x00\x00\x00dgst")      # sequence: one filler digest
    signed_data = _lp(digests_seq) + _lp(certs_seq) + _lp(b"attrs")
    signer = _lp(signed_data) + _lp(b"signatures") + _lp(b"publickey")
    signers_seq = _lp(signer)
    value = _lp(signers_seq)
    pair = struct.pack("<Q", 4 + len(value)) + struct.pack("<I", scheme_id) + value
    size = len(pair) + 8 + 16                        # trailing size (8) + magic (16)
    return struct.pack("<Q", size) + pair + struct.pack("<Q", size) + U._APK_SIG_MAGIC


def _dex(*strings: str) -> bytes:
    """A dex with a real string_ids table (count+offset at 0x38), ULEB128 lengths, MUTF-8 bodies."""
    n = len(strings)
    head = bytearray(b"dex\n035\x00" + b"\x00" * (0x70 - 8))
    struct.pack_into("<II", head, 0x38, n, 0x70)
    data, offs, base = b"", [], 0x70 + 4 * n
    for s in strings:
        b = s.encode()
        ln, uleb = len(b), b""
        while True:
            byte = ln & 0x7F
            ln >>= 7
            uleb += bytes([byte | (0x80 if ln else 0)])
            if not ln:
                break
        offs.append(base + len(data))
        data += uleb + b + b"\x00"
    return bytes(head) + b"".join(struct.pack("<I", o) for o in offs) + data


def _string_pool(strings):
    offsets, content = [], b""
    for value in strings:
        encoded = value.encode("utf-8")
        assert len(encoded) < 128
        offsets.append(len(content))
        content += bytes([len(value), len(encoded)]) + encoded + b"\0"
    content += b"\0" * (-len(content) % 4)
    start = 28 + 4 * len(strings)
    return (struct.pack("<HH6I", 1, 28, start + len(content), len(strings), 0, 256, start, 0)
            + b"".join(struct.pack("<I", v) for v in offsets) + content)


def _arsc(entries) -> bytes:
    """A resources.arsc with string resources [(entry name, value), ...] in one 'string' type."""
    n = len(entries)
    pool = _string_pool([v for _k, v in entries])
    types, keys = _string_pool(["string"]), _string_pool([k for k, _v in entries])
    spec = struct.pack("<HHIBBHI", 0x202, 16, 16 + 4 * n, 1, 0, 0, n) + b"\0" * (4 * n)
    config = struct.pack("<I", 64) + bytes(60)
    offsets = b"".join(struct.pack("<I", 16 * i) for i in range(n))
    body = b"".join(struct.pack("<HHIHBBI", 8, 0, i, 8, 0, 3, i) for i in range(n))  # Res_value string -> pool[i]
    start = 84 + 4 * n
    table = struct.pack("<HHIBBHII", 0x201, 84, start + len(body), 1, 0, 0, n, start) + config + offsets + body
    content = types + keys + spec + table
    package = (struct.pack("<HHII", 0x200, 288, 288 + len(content), 0x7f)
               + "org.csctf.fixture".encode("utf-16le").ljust(256, b"\0")
               + struct.pack("<5I", 288, 1, 288 + len(types), n, 0) + content)
    return struct.pack("<HHII", 2, 12, 12 + len(pool) + len(package), 1) + pool + package


def _arsc_string(entry_name: str, value: str) -> bytes:
    return _arsc([(entry_name, value)])


def _axml_manifest(package: str, receiver: str, actions) -> bytes:
    """A binary AndroidManifest.xml: manifest > application > receiver > intent-filter > action*."""
    strings = ["manifest", "package", package, "application", "receiver", "name", receiver,
               "intent-filter", "action"] + list(actions)
    idx = {s: i for i, s in enumerate(strings)}

    def start(tag, attrs=()):
        body = struct.pack("<iIHHHHHH", -1, idx[tag], 20, 20, len(attrs), 0, 0, 0)
        for an, av in attrs:
            body += struct.pack("<iiIHBBI", -1, idx[an], idx[av], 8, 0, 3, idx[av])
        return struct.pack("<HHIIi", 0x0102, 16, 16 + len(body), 1, -1) + body

    def end(tag):
        return struct.pack("<HHIIi", 0x0103, 16, 24, 1, -1) + struct.pack("<iI", -1, idx[tag])

    chunks = (_string_pool(strings) + start("manifest", [("package", package)]) + start("application")
              + start("receiver", [("name", receiver)]) + start("intent-filter"))
    for a in actions:
        chunks += start("action", [("name", a)]) + end("action")
    chunks += end("intent-filter") + end("receiver") + end("application") + end("manifest")
    return struct.pack("<HHI", 3, 8, 8 + len(chunks)) + chunks


def _zip(members: dict) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
        for name, body in members.items():
            z.writestr(name, body)
    return out.getvalue()


def _splice_signing_block(apk: bytes, block: bytes) -> bytes:
    """Insert the APK Signing Block just before the central directory and fix the EOCD offset."""
    eocd = apk.rfind(b"PK\x05\x06")
    cd_off = struct.unpack_from("<I", apk, eocd + 16)[0]
    new = bytearray(apk[:cd_off] + block + apk[cd_off:])
    struct.pack_into("<I", new, eocd + len(block) + 16, cd_off + len(block))
    return bytes(new)


def _gcm_blob(key: bytes, plaintext: bytes, nonce: bytes = b"ABCDEFGHIJKL") -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)        # nonce || ct || tag


def _gcm_blob_tag_first(key: bytes, plaintext: bytes, nonce: bytes = b"ABCDEFGHIJKL") -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    ct_tag = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ct_tag[-16:] + ct_tag[:-16]                          # nonce || tag || ct


def _cbc_blob(key: bytes, plaintext: bytes, iv: bytes = b"0123456789abcdef") -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    pad = 16 - (len(plaintext) % 16)
    data = plaintext + bytes([pad]) * pad
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv + enc.update(data) + enc.finalize()


def _recovery_token(der: bytes) -> str:
    return "KJSC-" + hashlib.sha256(der).hexdigest()[:8].upper() + "-RECOVERY"


def _vk_key(der: bytes, pin: str = PIN, passcode: str = PASSCODE) -> bytes:
    """VaultKeeper's KDF seed: SHA256(recovery_token || PIN || passcode)."""
    return hashlib.sha256(_recovery_token(der).encode() + pin.encode() + passcode.encode()).digest()


def _write_apk(tmp_path, apk: bytes, name="VaultKeeper.apk"):
    d = tmp_path / "chal"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(apk)
    return d


def _vaultkeeper_apk(tmp_path, mode="gcm", with_hmac_gate=True, with_signing_block=True):
    """A full VaultKeeper-class APK; returns (challenge_dir, cert_der). key = SHA256(token||PIN||passcode)."""
    der = _ec_cert_der()
    key = _vk_key(der)  # AES-256
    blob = _gcm_blob(key, FLAG.encode()) if mode == "gcm" else _cbc_blob(key, FLAG.encode())
    ct_b64 = base64.b64encode(blob).decode()

    dex_strings = [TEMPLATE, "unlock_ciphertext", ct_b64]
    if with_hmac_gate:
        target = hmac.new(PASSCODE.encode(), PIN.encode(), hashlib.sha256).digest()[:4].hex()
        dex_strings.append(target)
    members = {"classes.dex": _dex(*dex_strings),
               "resources.arsc": _arsc_string("passcode", PASSCODE)}
    apk = _zip(members)
    if with_signing_block:
        apk = _splice_signing_block(apk, _v2_signing_block(der))
    return _write_apk(tmp_path, apk), der


def _signed_apk(tmp_path, members, der, name="c.apk"):
    return _write_apk(tmp_path, _splice_signing_block(_zip(members), _v2_signing_block(der)), name)


def _note_int(notes: str, label: str) -> int:
    """The integer before `label` in the first package's notes (e.g. 'cipher trials')."""
    head = notes.split(label, 1)[0]
    return int(head.rsplit(",", 1)[1].split()[0])


# --------------------------------------------------------------------------- cert extraction

def test_v2_signing_block_cert_extraction_roundtrip(tmp_path):
    """The v2 APK Signing Block parser recovers exactly the leaf cert DER that was embedded."""
    der = _ec_cert_der()
    apk = _splice_signing_block(_zip({"classes.dex": _dex("x")}), _v2_signing_block(der))
    # the inserted block must leave the zip readable, and v1 (no META-INF) must be absent
    with zipfile.ZipFile(io.BytesIO(apk)) as z:
        members = {i.filename: z.read(i) for i in z.infolist()}
    assert U._v1_cert_der(members) is None
    assert U._v2_cert_der(apk) == der
    assert U._cert_der(members, apk) == der


def test_v3_signing_block_cert_is_read():
    """A v3-only signing block (scheme id 0xf05368c0) yields the leaf cert too; an unknown scheme
    id does not."""
    der = _ec_cert_der()
    base = _zip({"classes.dex": _dex("x")})
    assert U._v2_cert_der(_splice_signing_block(base, _v2_signing_block(der, U._V3_SCHEME_ID))) == der
    assert U._v2_cert_der(_splice_signing_block(base, _v2_signing_block(der, 0x12345678))) is None


def test_v2_parser_rejects_corrupt_block(tmp_path):
    """A tampered signing block yields no cert, not a wrong one (no silent fallback to garbage)."""
    der = _ec_cert_der()
    apk = _splice_signing_block(_zip({"classes.dex": _dex("x")}), _v2_signing_block(der))
    broken = bytearray(apk)
    idx = broken.find(U._APK_SIG_MAGIC)
    broken[idx + 4] ^= 0xFF  # corrupt the magic
    assert U._v2_cert_der(bytes(broken)) is None


def test_v2_parser_rejects_mismatched_block_sizes():
    """The Signing Block's leading size must equal its trailing size: a block whose header size was
    tampered with (magic intact) yields no cert."""
    der = _ec_cert_der()
    block = bytearray(_v2_signing_block(der))
    struct.pack_into("<Q", block, 0, struct.unpack_from("<Q", block, 0)[0] + 8)   # header size != footer size
    apk = _splice_signing_block(_zip({"classes.dex": _dex("x")}), bytes(block))
    assert U._APK_SIG_MAGIC in apk
    assert U._v2_cert_der(apk) is None
    good = _splice_signing_block(_zip({"classes.dex": _dex("x")}), _v2_signing_block(der))
    assert U._v2_cert_der(good) == der                                            # the untampered twin reads


def test_v1_meta_inf_cert_unlocks(tmp_path):
    """v1-signed APK (META-INF/CERT.RSA, no signing block): the cert DER comes from the PKCS#7 block
    and drives the recovery token end to end."""
    from cryptography.hazmat.primitives import serialization
    cert = _ec_cert()
    der = cert.public_bytes(serialization.Encoding.DER)
    members = {"classes.dex": _dex(TEMPLATE, base64.b64encode(_gcm_blob(_vk_key(der), FLAG.encode())).decode()),
               "resources.arsc": _arsc_string("passcode", PASSCODE),
               "META-INF/CERT.RSA": _v1_rsa_block(cert)}
    apk = _zip(members)
    assert U._v2_cert_der(apk) is None
    assert U._cert_der(members, apk) == der
    res = U.solve(_write_apk(tmp_path, apk), CSCTF, challenge_id="9070")
    assert res.status == "solved", res.notes
    assert res.flags == (FLAG,)


# --------------------------------------------------------------------------- atoms and blobs

def test_arsc_string_value_is_read(tmp_path):
    """R.string constants come through apk_resources.arsc_values into the key-atom set."""
    members = {"resources.arsc": _arsc_string("passcode", PASSCODE)}
    assert PASSCODE in U._string_constants(members)


def test_candidate_blob_picks_base64_string():
    """A base64 R.string that decodes to a cipher-sized blob is surfaced as a candidate; a short
    non-base64 token is not."""
    blob = bytes(range(32))
    strings = [base64.b64encode(blob).decode(), "hello", PASSCODE]
    cands = U._candidate_blobs({}, strings)
    assert any(data == blob for _, data in cands)
    assert all(data != b"hello" for _, data in cands)


def test_candidate_blob_picks_base64url_string():
    """A base64url constant (with '-'/'_', unpadded) is decoded as a candidate too."""
    for i in range(256):
        blob = bytes([i]) + bytes(range(250, 256)) * 6
        enc = base64.urlsafe_b64encode(blob).decode().rstrip("=")
        if ("-" in enc or "_" in enc) and len(enc) % 4:
            break
    assert not U._B64.match(enc)
    cands = U._candidate_blobs({}, [enc])
    assert [data for _, data in cands] == [blob]
    assert cands[0][0].startswith("b64url:")


def test_candidate_blobs_skip_media_and_elf_keep_raw_asset():
    """Raw binary members are candidates (smallest first), but PNG/ELF/dex magics and text are not."""
    vault = bytes((i * 37 + 11) % 256 for i in range(48))
    members = {"assets/vault.bin": vault,
               "assets/big.bin": bytes((i * 91 + 3) % 256 for i in range(4000)),
               "res/drawable/icon.dat": b"\x89PNG\r\n\x1a\n" + bytes(200),
               "lib/arm64-v8a/libx.bin": b"\x7fELF" + bytes(200),
               "assets/readme.txt": b"plain text that is not a blob at all, really" * 2}
    cands = U._candidate_blobs(members, [])
    assert [label for label, _ in cands] == ["file:assets/vault.bin", "file:assets/big.bin"]


def test_candidate_blobs_scan_every_string_ranked():
    """The ciphertext is found behind hundreds of constants, and a random-looking base64 string
    ranks ahead of an identifier that merely parses as base64."""
    ident = "androidxAppcompatWidgetToolbarActionMenu"   # 40 chars, parses as base64, no digits
    real = base64.b64encode(bytes(range(7, 55))).decode()
    strings = ["filler%04d" % i for i in range(5000)] + [ident, real]
    cands = U._candidate_blobs({}, strings)
    assert cands[0][1] == bytes(range(7, 55))
    assert len(cands) == 2


def test_actions_read_from_binary_manifest():
    members = {"AndroidManifest.xml": _axml_manifest("org.csctf.vault", ".UnlockReceiver", [ACTION, "x.y.Z"])}
    assert U._actions(members) == [ACTION, "x.y.Z"]


def test_rank_atoms_puts_hint_named_rstring_first():
    """R.string values named like key material, then key-shaped codes, before words, sentences and
    identifiers; dex descriptors and signatures never become atoms."""
    arsc = [("app_name", "Vault Keeper"), ("abc_action_bar_up", "Navigate up"), ("passcode", PASSCODE)]
    dex = ["Landroid/app/Activity;", "(Ljava/lang/String;)V", "onCreate", "ISO-8859-1", "<init>"]
    got = U._rank_atoms(arsc, ["Handover-9911"], dex)
    assert got[0] == PASSCODE
    assert got.index("Handover-9911") < got.index("ISO-8859-1") < got.index("Navigate up") < got.index("onCreate")
    assert "Landroid/app/Activity;" not in got and "(Ljava/lang/String;)V" not in got and "<init>" not in got


def test_recipe_cap_spreads_across_families():
    """With 78 cert tokens and 40 strings the token x string family alone exceeds the cap; ranking
    still keeps the best of every family (string||PIN, action||PIN, token||action||PIN) in the cut."""
    tokens = ["T%02d" % i for i in range(78)]
    strings = ["S%02d" % i for i in range(40)]
    acts = ["A%02d" % i for i in range(16)]
    recipes, total = U._recipes(tokens, strings, acts)
    assert len(recipes) == U.MAX_RECIPES < total
    assert ((), ()) == recipes[0]
    assert (("S25",), ()) in recipes and ((), ("S00",)) in recipes
    assert (("A15",), ()) in recipes
    assert (("T00", "A00"), ()) in recipes and (("A00",), ("T00",)) in recipes
    assert (("T00",), ("S00",)) in recipes
    assert (("T77",), ("S39",)) not in recipes          # the cut drops the lowest-ranked pairs


def test_loose_atoms_read_text_files_not_symlinks_or_hidden(tmp_path):
    d = tmp_path / "chal"
    (d / ".ctf").mkdir(parents=True)
    (d / "handover_card.txt").write_text("VaultKeeper handover\nHandover code: CARD-7731\n")
    (d / ".ctf" / "secret.txt").write_text("hidden-code: HIDDEN-0001\n")
    outside = tmp_path / "outside.txt"
    outside.write_text("Code: OUTSIDE-4242\n")
    os.symlink(outside, d / "link.txt")
    (d / "badge.txt").write_text("staff badge\nPIN-CARD:BADGE-5150\n")   # label:value with no space
    got = U._loose_atoms(d)
    assert "CARD-7731" in got and "BADGE-5150" in got
    assert not any("HIDDEN" in a or "OUTSIDE" in a for a in got)


# --------------------------------------------------------------------------- end-to-end chains

def test_full_gcm_unlock_chain(tmp_path):
    """End to end: derive key = SHA256(recovery_token || 4-digit PIN || passcode) from the cert +
    R.string + dex constants, brute the PIN, and open the AES-GCM blob on tag verify."""
    d, der = _vaultkeeper_apk(tmp_path, mode="gcm")
    res = U.solve(d, CSCTF, challenge_id="9070")
    assert res.status == "solved", res.notes
    assert FLAG in res.flags
    assert res.evidence and res.evidence[0].kind == "decrypt"
    assert "aes-gcm" in res.evidence[0].detail
    assert "PIN=%s" % PIN in res.evidence[0].detail
    assert res.evidence[0].path == "VaultKeeper.apk"


def test_hmac_prefix_gate_shrinks_the_pin_search(tmp_path):
    """With the stated HMAC-SHA256 prefix, the correct PIN is tried first, so the cipher search costs
    far fewer trials than the full 10,000-PIN brute would; the gate's own HMACs are counted in the
    total trials (the budget covers them)."""
    d_gated, _ = _vaultkeeper_apk(tmp_path / "a", mode="gcm", with_hmac_gate=True)
    res_gated = U.solve(d_gated, CSCTF, challenge_id="9070")
    assert res_gated.status == "solved", res_gated.notes
    gated_cipher = _note_int(res_gated.notes, "cipher trials")
    gate_hmacs = _note_int(res_gated.notes, "gate HMACs")
    assert "HMAC-gated first" in res_gated.notes

    d_plain, _ = _vaultkeeper_apk(tmp_path / "b", mode="gcm", with_hmac_gate=False)
    res_plain = U.solve(d_plain, CSCTF, challenge_id="9070")
    assert res_plain.status == "solved"
    plain_cipher = _note_int(res_plain.notes, "cipher trials")
    assert _note_int(res_plain.notes, "gate HMACs") == 0

    assert gated_cipher * 10 < plain_cipher, (gated_cipher, plain_cipher)
    assert gate_hmacs > 0
    total = int(res_gated.notes.rsplit(",", 1)[1].split()[0])
    assert total == gate_hmacs + gated_cipher


def test_hmac_gate_cost_is_one_hmac_per_key_and_pin():
    """Each HMAC is computed once and checked against every target: 30 targets cost what 1 does."""
    pins = U._pin_strings(100)
    want = hmac.new(b"k1", b"0042", hashlib.sha256).digest()[:4].hex()
    m1 = U._Meter(10 ** 9, 0, 0)
    assert U._hmac_gated_pins([want], ["k1", "k2"], pins, m1) == ["0042"]
    m30 = U._Meter(10 ** 9, 0, 0)
    decoys = ["%08x" % (0xA0000000 + i) for i in range(29)]
    assert U._hmac_gated_pins(decoys + [want], ["k1", "k2"], pins, m30) == ["0042"]
    assert m1.trials == m30.trials == 2 * 100


def test_full_cbc_unlock_chain(tmp_path):
    """AES-CBC path: accepted on valid PKCS#7 padding plus a flag in the event format."""
    d, _ = _vaultkeeper_apk(tmp_path, mode="cbc")
    res = U.solve(d, CSCTF, challenge_id="9070")
    assert res.status == "solved", res.notes
    assert FLAG in res.flags
    assert "aes-cbc" in res.evidence[0].detail


def test_aes128_key_from_truncated_digest(tmp_path):
    """key = SHA256(...)[:16] (AES-128) is tried, not only the full 32-byte digest."""
    der = _ec_cert_der()
    blob = _gcm_blob(_vk_key(der)[:16], FLAG.encode())
    d = _signed_apk(tmp_path, {"classes.dex": _dex(TEMPLATE, base64.b64encode(blob).decode()),
                               "resources.arsc": _arsc_string("passcode", PASSCODE)}, der)
    res = U.solve(d, CSCTF)
    assert res.status == "solved", res.notes
    assert "AES-128" in res.evidence[0].detail


def test_gcm_nonce_tag_ct_layout(tmp_path):
    """A nonce || tag || ct blob (tag before the ciphertext) opens on tag verify."""
    der = _ec_cert_der()
    blob = _gcm_blob_tag_first(_vk_key(der), FLAG.encode())
    d = _signed_apk(tmp_path, {"classes.dex": _dex(TEMPLATE, base64.b64encode(blob).decode()),
                               "resources.arsc": _arsc_string("passcode", PASSCODE)}, der)
    res = U.solve(d, CSCTF)
    assert res.status == "solved", res.notes
    assert res.flags == (FLAG,)


def test_broadcast_action_preimage_in_key(tmp_path):
    """key = SHA256(action || PIN || recovery_token): the receiver's intent-filter action, read from
    the binary manifest, is a KDF input."""
    der = _ec_cert_der()
    key = hashlib.sha256(ACTION.encode() + PIN.encode() + _recovery_token(der).encode()).digest()
    members = {"AndroidManifest.xml": _axml_manifest("org.csctf.vault", ".UnlockReceiver", [ACTION]),
               "classes.dex": _dex(TEMPLATE, base64.b64encode(_gcm_blob(key, FLAG.encode())).decode())}
    res = U.solve(_signed_apk(tmp_path, members, der), CSCTF)
    assert res.status == "solved", res.notes
    assert ACTION in res.evidence[0].detail


def test_raw_binary_asset_ciphertext(tmp_path):
    """The ciphertext shipped as a raw asset file (no base64 string anywhere) is found and opened."""
    der = _ec_cert_der()
    members = {"classes.dex": _dex(TEMPLATE, "assets/vault.bin"),
               "resources.arsc": _arsc_string("passcode", PASSCODE),
               "assets/vault.bin": _gcm_blob(_vk_key(der), FLAG.encode())}
    res = U.solve(_signed_apk(tmp_path, members, der), CSCTF)
    assert res.status == "solved", res.notes
    assert "file:assets/vault.bin" in res.evidence[0].detail


def test_pin_space_includes_9999(tmp_path):
    """The default 4-digit space is 0000..9999 inclusive: the last PIN is reached."""
    der = _ec_cert_der()
    blob = _gcm_blob(_vk_key(der, pin="9999"), FLAG.encode())
    d = _signed_apk(tmp_path, {"classes.dex": _dex(TEMPLATE, base64.b64encode(blob).decode()),
                               "resources.arsc": _arsc_string("passcode", PASSCODE)}, der)
    res = U.solve(d, CSCTF)
    assert res.status == "solved", res.notes
    assert "PIN=9999" in res.evidence[0].detail


def test_passcode_from_handover_card_next_to_apk(tmp_path):
    """The passcode is not in the APK at all, only on a handover card text file beside it."""
    der = _ec_cert_der()
    blob = _gcm_blob(_vk_key(der), FLAG.encode())
    d = _signed_apk(tmp_path, {"classes.dex": _dex(TEMPLATE, base64.b64encode(blob).decode())}, der)
    (d / "handover_card.txt").write_text("VaultKeeper staff handover\nHandover code: %s\n" % PASSCODE)
    res = U.solve(d, CSCTF)
    assert res.status == "solved", res.notes
    assert PASSCODE in res.evidence[0].detail


def test_realistic_string_tables(tmp_path):
    """Hundreds of sorted dex constants and an appcompat-sized arsc ahead of the template and the
    ciphertext: the blob is still found and the atoms ranked, within the default budgets."""
    der = _ec_cert_der()
    blob = _gcm_blob(_vk_key(der), FLAG.encode())
    dex = ["Landroidx/appcompat/widget/W%03d;" % i for i in range(120)]
    dex += ["onMethod%sName" % chr(97 + i % 26) for i in range(60)]
    dex += ["v1.%d.%d" % (i, i * 7 % 10) for i in range(40)]
    dex += ["Unable to start activity number %d" % i for i in range(40)]
    dex += ["androidxAppcompatWidgetToolbarActionMenu", "(Ljava/lang/String;)V", "<init>", "ISO-8859-1"]
    dex += [TEMPLATE, base64.b64encode(blob).decode()]
    dex = sorted(dict.fromkeys(dex))
    arsc = [("abc_string_%03d" % i, ("Navigate up %d" % i) if i % 3 else "ID-%03d" % i) for i in range(250)]
    arsc += [("abc_count_%d" % i, "%d selected of many") for i in range(3)]
    arsc.append(("passcode", PASSCODE))
    d = _signed_apk(tmp_path, {"classes.dex": _dex(*dex), "resources.arsc": _arsc(arsc)}, der)
    res = U.solve(d, CSCTF, challenge_id="9070")
    assert res.status == "solved", res.notes
    assert res.flags == (FLAG,)


def test_not_routed_through_ans_gate(tmp_path):
    """The flag is matched against the event (CSCTF) format, not the ANS- code gate: an ANS- value in
    the plaintext is ignored, and the CSCTF flag is what is returned."""
    der = _ec_cert_der()
    plaintext = b"ANS-0123456789ABCDEF " + FLAG.encode()  # both an ANS code and a CSCTF flag present
    blob = _gcm_blob(_vk_key(der), plaintext)
    members = {"classes.dex": _dex(TEMPLATE, base64.b64encode(blob).decode()),
               "resources.arsc": _arsc_string("passcode", PASSCODE)}
    res = U.solve(_signed_apk(tmp_path, members, der), CSCTF, challenge_id="9070")
    assert res.status == "solved"
    assert res.flags[0] == FLAG
    assert not res.flags[0].startswith("ANS-")


# --------------------------------------------------------------------------- honest endings

def test_wrong_pin_space_finds_nothing(tmp_path):
    """Honest 'none' when the PIN is outside the searched space and the space was covered: no false
    positive, and the notes say the whole bounded space was searched."""
    d, _ = _vaultkeeper_apk(tmp_path, mode="gcm", with_hmac_gate=False)
    res = U.solve(d, CSCTF, challenge_id="9070", pins=100)  # 4972 is out of 0000..0099
    assert res.status == "none"
    assert not res.flags
    assert "searched the whole bounded space" in res.notes


def test_trial_budget_exhaustion_is_reported(tmp_path):
    """A search cut by the trial budget is 'unsure' and names the budget, never a plain 'none'."""
    d, _ = _vaultkeeper_apk(tmp_path, mode="gcm", with_hmac_gate=False)
    res = U.solve(d, CSCTF, budget=2000)
    assert res.status == "unsure", res.notes
    assert not res.flags
    assert "search incomplete" in res.notes and "trial budget 2000 exhausted after 2000 trials" in res.notes


def test_hmac_gate_counts_against_budget(tmp_path):
    """The HMAC pre-gate spends the trial budget: a budget smaller than the gate stops in the gate
    (unsure) instead of running it for free and then solving."""
    d, _ = _vaultkeeper_apk(tmp_path, mode="gcm", with_hmac_gate=True)
    res = U.solve(d, CSCTF, budget=5000)
    assert res.status == "unsure", res.notes
    assert _note_int(res.notes, "gate HMACs") == 5000
    assert _note_int(res.notes, "cipher trials") == 0


def test_cpu_time_budget_exhaustion_is_reported(tmp_path, monkeypatch):
    """The CPU time budget (driven here by an injected step clock, not wall time) stops the search
    and is named in an 'unsure' result."""
    ticks = iter(range(10 ** 9))
    monkeypatch.setattr(U, "_cpu", lambda: float(next(ticks)))   # every clock read advances 1 s
    d, _ = _vaultkeeper_apk(tmp_path, mode="gcm", with_hmac_gate=False)
    res = U.solve(d, CSCTF, time_budget=3)
    assert res.status == "unsure", res.notes
    assert "CPU time budget 3s exhausted" in res.notes
    assert _note_int(res.notes, "cipher trials") <= 5 * U.CLOCK_EVERY


def test_wall_clock_budget_exhaustion_is_reported(tmp_path, monkeypatch):
    """The wall-clock budget (an injected step clock: every read advances 1 s, CPU clock frozen) stops
    the search and is named in an 'unsure' result.  The [intake] runner kills on *wall* time, so this
    deadline -- not the CPU cap -- is what lets the engine print its own 'unsure' first."""
    ticks = iter(range(10 ** 9))
    monkeypatch.setattr(U, "_wall", lambda: float(next(ticks)))
    monkeypatch.setattr(U, "_cpu", lambda: 0.0)                     # no CPU time passes at all
    d, _ = _vaultkeeper_apk(tmp_path, mode="gcm", with_hmac_gate=False)
    res = U.solve(d, CSCTF, wall_budget=3)
    assert res.status == "unsure", res.notes
    assert "wall-clock budget 3s exhausted" in res.notes
    assert _note_int(res.notes, "cipher trials") <= 5 * U.CLOCK_EVERY


def test_default_budgets_against_the_intake_timeout():
    """Two clocks: the [intake] timeout is wall clock (proc.wait), DEFAULT_TIME_BUDGET is CPU time.
    Under load CPU seconds lag wall seconds, so the CPU cap alone cannot end a run before intake
    kills it; the default *wall* budget must sit below the intake timeout with room left for start-up
    and the result line, and the CPU cap must not exceed it."""
    import tomllib
    man = tomllib.loads((ROOT / "solvers" / "mobile-android" / "apk_unlock_crypto.manifest.toml").read_text())
    timeout = man["intake"]["timeout"]
    assert 0 < U.DEFAULT_WALL_BUDGET <= timeout - 30
    assert 0 < U.DEFAULT_TIME_BUDGET <= U.DEFAULT_WALL_BUDGET
    _n, _b, _t, wall = U._options({})
    assert wall == U.DEFAULT_WALL_BUDGET


def test_class_file_member_is_not_a_blob():
    """A Java class file (CAFEBABE, e.g. Kotlin's DebugProbesKt.bin) is never a ciphertext candidate,
    so a plain Kotlin APK does not start a full brute on it."""
    probe = b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + bytes((i * 53 + 7) % 256 for i in range(400))
    vault = bytes((i * 37 + 11) % 256 for i in range(48))
    cands = U._candidate_blobs({"DebugProbesKt.bin": probe, "assets/vault.bin": vault}, [])
    assert [label for label, _ in cands] == ["file:assets/vault.bin"]


def test_recipe_cap_is_named_and_unsure(tmp_path, monkeypatch):
    """A recipe list cut by MAX_RECIPES says so in the notes, and the ending is 'unsure' (only the
    capped space was searched), never 'none' with "searched the whole bounded space"."""
    monkeypatch.setattr(U, "MAX_RECIPES", 3)
    d, _ = _vaultkeeper_apk(tmp_path, mode="gcm", with_hmac_gate=False)
    res = U.solve(d, CSCTF, pins=10)
    assert res.status == "unsure", res.notes
    assert "3 recipe(s) (capped at 3 of " in res.notes
    assert "searched the capped space only" in res.notes and "MAX_RECIPES=3" in res.notes
    assert "searched the whole bounded space" not in res.notes


def test_uncapped_covered_search_is_none(tmp_path):
    """The same search with the recipe list not cut (and the PIN outside the space) is a plain 'none'."""
    d, _ = _vaultkeeper_apk(tmp_path, mode="gcm", with_hmac_gate=False)
    res = U.solve(d, CSCTF, pins=10)
    assert "capped at" not in res.notes
    assert res.status == "none", res.notes


@pytest.mark.parametrize("opt,val", [("pins", "abc"), ("budget", "x"), ("time_budget", "y"), ("pins", "0"),
                                     ("time_budget", "-1"), ("wall_budget", "z"), ("wall_budget", "-2")])
def test_malformed_option_blocks_naming_it(tmp_path, opt, val):
    d, _ = _vaultkeeper_apk(tmp_path, mode="gcm", with_hmac_gate=False)
    res = U.solve(d, CSCTF, **{opt: val})
    assert res.status == "blocked"
    assert opt in res.notes


def test_no_package_is_none(tmp_path):
    d = tmp_path / "empty"
    d.mkdir()
    (d / "notes.txt").write_text("nothing here")
    res = U.solve(d, CSCTF)
    assert res.status == "none"
    assert "no APK" in res.notes


def test_symlinked_apk_is_not_followed(tmp_path):
    """An APK reachable only through a symlink (file or directory) in the challenge dir is not read."""
    d_real, _ = _vaultkeeper_apk(tmp_path / "real", mode="gcm")
    d = tmp_path / "chal2"
    d.mkdir()
    os.symlink(d_real / "VaultKeeper.apk", d / "VaultKeeper.apk")
    os.symlink(d_real, d / "subdir")
    res = U.solve(d, CSCTF)
    assert res.status == "none"
    assert "no APK" in res.notes


def test_named_symlink_file_is_not_read(tmp_path):
    """Even an explicitly named file is skipped when it is a symlink (the lane never follows one)."""
    d_real, _ = _vaultkeeper_apk(tmp_path / "real", mode="gcm")
    link = tmp_path / "link.apk"
    os.symlink(d_real / "VaultKeeper.apk", link)
    assert U._packages(tmp_path, [link]) == []
    assert [pkg[0] for pkg in U._packages(tmp_path, [d_real / "VaultKeeper.apk"])] == ["VaultKeeper.apk"]


def test_missing_cryptography_blocks_loudly(tmp_path, monkeypatch):
    """A missing cryptography dependency is a loud 'blocked' naming it, never a silent skip."""
    def boom():
        raise U.CryptoMissing("cryptography is required for the AES unlock chain; pip install cryptography")
    monkeypatch.setattr(U, "_require_crypto", boom)
    d = tmp_path / "chal"
    d.mkdir()
    (d / "x.apk").write_bytes(_zip({"classes.dex": _dex("x")}))
    res = U.solve(d, CSCTF)
    assert res.status == "blocked"
    assert "cryptography" in res.notes


def test_main_with_one_apk_reads_only_that_file(tmp_path, capsys):
    """Given one APK path, the CLI reads that file only -- not a solvable sibling in the same folder."""
    d, _ = _vaultkeeper_apk(tmp_path, mode="gcm")
    other = d / "other.apk"
    other.write_bytes(_zip({"classes.dex": _dex("nothing")}))
    assert U.main([str(other), "--event", "csctf"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "none" and "VaultKeeper" not in out["notes"] and "other.apk" in out["notes"]
    assert U.main([str(d / "VaultKeeper.apk"), "--event", "csctf"]) == 0
    assert FLAG in json.loads(capsys.readouterr().out)["flags"]


# --------------------------------------------------------------------------- split bundles and many packages

def _vaultkeeper_bytes(tmp_path, **kw) -> bytes:
    d, _ = _vaultkeeper_apk(tmp_path / "src", **kw)
    return (d / "VaultKeeper.apk").read_bytes()


def test_xapk_inner_apk_is_opened(tmp_path):
    """An .xapk (a zip of the APK plus manifest.json and an icon) is opened: the inner APK is searched
    as a package of its own and the flag recovered -- not a 'none' over the outer zip's members."""
    inner = _vaultkeeper_bytes(tmp_path, mode="gcm")
    xapk = _zip({"manifest.json": b'{"package_name": "org.csctf.vault"}', "icon.png": b"\x89PNG\r\n\x1a\n" + bytes(64),
                 "org.csctf.vault.apk": inner})
    d = _write_apk(tmp_path, xapk, name="VaultKeeper.xapk")
    res = U.solve(d, CSCTF, challenge_id="9070")
    assert res.status == "solved", res.notes
    assert res.flags == (FLAG,)
    assert res.evidence[0].path == "VaultKeeper.xapk!org.csctf.vault.apk"


def test_apks_split_bundle_base_and_config_splits(tmp_path):
    """An .apks bundle: base.apk holds the chain, a config split holds nothing; both are searched and
    the base solves.  The outer zip has no other members, so it is not a package of its own."""
    inner = _vaultkeeper_bytes(tmp_path, mode="cbc")
    split = _zip({"resources.arsc": _arsc_string("x", "y")})
    apks = _zip({"splits/base-master.apk": inner, "splits/base-arm64_v8a.apk": split})
    pkgs = U._packages(tmp_path, [_write_apk(tmp_path, apks, name="v.apks") / "v.apks"])
    assert [p[0] for p in pkgs] == ["v.apks!splits/base-arm64_v8a.apk", "v.apks!splits/base-master.apk"]
    res = U.solve(tmp_path / "chal", CSCTF)
    assert res.status == "solved", res.notes
    assert res.evidence[0].path == "v.apks!splits/base-master.apk"


def test_nested_apk_larger_than_member_cap_is_still_read(tmp_path, monkeypatch):
    """A nested APK (or a dex) over MAX_MEMBER_BYTES is structural and still read; any other oversized
    member is skipped and named in the notes, never dropped silently."""
    inner = _vaultkeeper_bytes(tmp_path, mode="gcm")
    monkeypatch.setattr(U, "MAX_MEMBER_BYTES", 256)
    assert len(inner) > 256
    xapk = _zip({"org.csctf.vault.apk": inner, "assets/huge.obb": bytes(1000)})
    d = _write_apk(tmp_path, xapk, name="v.xapk")
    res = U.solve(d, CSCTF)
    assert res.status == "solved", res.notes
    assert "1 member(s) not read (assets/huge.obb)" in res.notes


def test_blobless_decoy_package_does_not_end_the_search(tmp_path):
    """A package with no ciphertext candidate sorted before the real one is passed over, not the end
    of the multi-package search."""
    inner = _vaultkeeper_bytes(tmp_path, mode="gcm")
    d = _write_apk(tmp_path, _zip({"classes.dex": _dex("hello", "world")}), name="A_decoy.apk")
    (d / "VaultKeeper.apk").write_bytes(inner)
    res = U.solve(d, CSCTF)
    assert res.status == "solved", res.notes
    assert "A_decoy.apk: no ciphertext candidate" in res.notes
    assert res.evidence[0].path == "VaultKeeper.apk"


def test_no_blob_anywhere_says_nothing_to_decrypt(tmp_path):
    """No candidate in any package: 'none' that says there was nothing to decrypt (not a claim that a
    key space was searched)."""
    d = _write_apk(tmp_path, _zip({"classes.dex": _dex("hello")}), name="a.apk")
    res = U.solve(d, CSCTF)
    assert res.status == "none"
    assert "no ciphertext candidate in any of 1 package(s)" in res.notes
    assert "searched the whole bounded space" not in res.notes


# --------------------------------------------------------------------------- a KDF method run in the dex VM

sys.path.insert(0, str(ROOT / "tests"))
from day24_mobile_computed_specimens import Asm, DexBuilder  # noqa: E402

MD, SBT, STR = "Ljava/security/MessageDigest;", "Ljava/lang/StringBuilder;", "Ljava/lang/String;"
KDF_CLS = "Lorg/csctf/vault/Kdf;"


def _emit_sha256_of(a, d, src, dst):
    """dst = MessageDigest.getInstance("SHA-256").digest(src.getBytes()); uses v0..v2 as scratch."""
    a.const_string(0, d.s("SHA-256"))
    a.invoke(0x71, d.m(MD, "getInstance", "LL"), [0])
    a.move_result_object(1)
    a.invoke(0x6e, d.m(STR, "getBytes", "L"), [src])
    a.move_result_object(2)
    a.invoke(0x6e, d.m(MD, "digest", "LL"), [1, 2])
    a.move_result_object(dst)


def _emit_concat(a, d, parts, dst):
    """dst = new StringBuilder().append(p0)...toString(); a part is a register, ('lit', text) or
    ('int', reg).  Uses v3 (builder) and v4 (literal) as scratch."""
    a.new_instance(3, d.t(SBT))
    a.invoke(0x70, d.m(SBT, "<init>", "V"), [3])
    for part in parts:
        if isinstance(part, tuple) and part[0] == "lit":
            a.const_string(4, d.s(part[1]))
            a.invoke(0x6e, d.m(SBT, "append", "LL"), [3, 4])
        elif isinstance(part, tuple) and part[0] == "int":
            a.invoke(0x6e, d.m(SBT, "append", "LI"), [3, part[1]])
        else:
            a.invoke(0x6e, d.m(SBT, "append", "LL"), [3, part])
        a.move_result_object(3)
    a.invoke(0x6e, d.m(SBT, "toString", "L"), [3])
    a.move_result_object(dst)


def _kdf_dex(strings, kind):
    """A classes.dex with a static KDF the enumerated recipes cannot express, plus `strings`.

    kind "int":     byte[] deriveKey(String token, int pin, String passcode)
                    = SHA256(token + ":" + pin + passcode)         (one method, the PIN an int)
    kind "helper":  byte[] unlock(String passcode, String pin, String token)
                    = sha(passcode + "/" + pin + "/" + token)      (calls a static sha(String))
    kind "decline": byte[] deriveKey(String a, String pin) = SHA256(SystemProperties.get(a) + pin):
                    a call the VM does not model."""
    d = DexBuilder()
    for t in strings:
        d.s(t)
    methods = []
    if kind == "int":                                  # ins v6, v7, v8 (regs 9)
        a = Asm()
        _emit_concat(a, d, [6, ("lit", ":"), ("int", 7), 8], 5)
        _emit_sha256_of(a, d, 5, 0)
        a.return_object(0)
        methods.append((d.m(KDF_CLS, "deriveKey", "LLIL"), a.finish(), 9, 2, 3))
    elif kind == "helper":
        h = Asm()                                      # sha(String): ins v5 (regs 6)
        _emit_sha256_of(h, d, 5, 0)
        h.return_object(0)
        sha = d.m(KDF_CLS, "sha", "LL")
        a = Asm()                                      # unlock(String, String, String): ins v6..v8
        _emit_concat(a, d, [6, ("lit", "/"), 7, ("lit", "/"), 8], 5)
        a.invoke(0x71, sha, [5])
        a.move_result_object(0)
        a.return_object(0)
        methods += [(sha, h.finish(), 6, 2, 1), (d.m(KDF_CLS, "unlock", "LLLL"), a.finish(), 9, 2, 3)]
    else:
        a = Asm()                                      # ins v6, v7 (regs 8)
        a.invoke(0x71, d.m("Landroid/os/SystemProperties;", "get", "LL"), [6])
        a.move_result_object(5)
        _emit_concat(a, d, [5, 7], 5)
        _emit_sha256_of(a, d, 5, 0)
        a.return_object(0)
        methods.append((d.m(KDF_CLS, "deriveKey", "LLL"), a.finish(), 8, 2, 2))
    d.add_class(methods)
    return d.build()


def test_kdf_method_with_int_pin_is_evaluated_in_the_dex_vm(tmp_path):
    """SHA256(token + ":" + pin-as-int + passcode) is outside every enumerated recipe (a separator, and
    PIN 0815 rendered as "815"); the static deriveKey is found and run in the dex VM with the
    recovery token, the PIN as an int and the passcode, and its byte[] opens the blob."""
    der = _ec_cert_der()
    pin = "0815"
    key = hashlib.sha256((_recovery_token(der) + ":" + str(int(pin)) + PASSCODE).encode()).digest()
    dex = _kdf_dex([TEMPLATE, base64.b64encode(_gcm_blob(key, FLAG.encode())).decode()], "int")
    members = {"classes.dex": dex, "resources.arsc": _arsc_string("passcode", PASSCODE)}
    kdfs, note = U._kdf_methods(members)
    assert note == "" and [(k[0], k[4]) for k in kdfs] == [(KDF_CLS + "->deriveKey", "LIL")]
    res = U.solve(_signed_apk(tmp_path, members, der), CSCTF)
    assert res.status == "solved", res.notes
    assert res.flags == (FLAG,)
    ev = res.evidence[0].detail
    assert "evaluated in the dex VM" in ev and KDF_CLS + "->deriveKey" in ev and "PIN=0815" in ev
    assert _note_int(res.notes, "dex VM trials") > 0


def test_kdf_wrapper_calling_a_digest_helper_is_found(tmp_path):
    """A static unlock(passcode, pin, token) that joins with '/' and calls a static sha(String) is
    found one call away from MessageDigest.digest and evaluated; the 1-parameter helper is offered
    too but cannot reproduce the key."""
    der = _ec_cert_der()
    key = hashlib.sha256((PASSCODE + "/" + PIN + "/" + _recovery_token(der)).encode()).digest()
    dex = _kdf_dex([TEMPLATE, base64.b64encode(_cbc_blob(key, FLAG.encode())).decode()], "helper")
    members = {"classes.dex": dex, "resources.arsc": _arsc_string("passcode", PASSCODE)}
    names = [k[0] for k in U._kdf_methods(members)[0]]
    assert KDF_CLS + "->unlock" in names and KDF_CLS + "->sha" in names
    res = U.solve(_signed_apk(tmp_path, members, der), CSCTF)
    assert res.status == "solved", res.notes
    assert "aes-cbc" in res.evidence[0].detail and KDF_CLS + "->unlock" in res.evidence[0].detail


def test_kdf_method_the_vm_declines_is_named_and_recipes_still_run(tmp_path):
    """A KDF that calls something the VM does not model is dropped with its reason in the notes, and
    the enumerated recipes still solve the standard VaultKeeper composition."""
    der = _ec_cert_der()
    blob = _gcm_blob(_vk_key(der), FLAG.encode())
    dex = _kdf_dex([TEMPLATE, base64.b64encode(blob).decode()], "decline")
    members = {"classes.dex": dex, "resources.arsc": _arsc_string("passcode", PASSCODE)}
    res = U.solve(_signed_apk(tmp_path, members, der), CSCTF)
    assert res.status == "solved", res.notes
    assert KDF_CLS + "->deriveKey declined by the dex VM" in res.notes
    assert "evaluated in the dex VM" not in res.evidence[0].detail


def test_instance_kdf_method_is_not_offered():
    """Only static methods are run: an instance method (ins_size counts `this`) with the same shorty
    is not offered, since the VM would bind the arguments one register off."""
    d = DexBuilder()
    a = Asm()
    _emit_concat(a, d, [6, 7, 8], 5)
    _emit_sha256_of(a, d, 5, 0)
    a.return_object(0)
    d.add_class([(d.m(KDF_CLS, "deriveKey", "LLL"), a.finish(), 9, 2, 3)])   # 2 params + this = ins 3
    assert U._kdf_methods({"classes.dex": d.build()}) == ([], "")


def test_dex_vm_import_failure_is_named(monkeypatch):
    """When the dex VM cannot be imported the notes say the KDF methods were not evaluated, and why."""
    def boom():
        raise ImportError("no dex_chain_codec")
    monkeypatch.setattr(U, "_load_vm", boom)
    kdfs, note = U._kdf_methods({"classes.dex": _kdf_dex([TEMPLATE], "int")})
    assert kdfs == [] and "dex VM unavailable (ImportError: no dex_chain_codec)" in note


def test_invoked_skips_payloads():
    """The invoke scan walks instruction widths and skips a fill-array payload whose data happens to
    look like an invoke of method 7."""
    import dex_chain_codec as dcc
    insns = [0x0071, 3, 0,                      # invoke-static {} meth@3
             0x0300, 1, 4, 0, 0x0071, 7,        # fill-array-data payload: 4 one-byte elements (2 units)
             0x0000, 0x000e]                    # nop, return-void
    assert U._invoked(insns, dcc._W) == {3}
