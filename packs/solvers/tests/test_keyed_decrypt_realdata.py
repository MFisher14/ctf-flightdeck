"""Real-sample checks for the B-161 decrypt-with-key helpers.

Each format needs a real sample with its known key before the helper is
trusted.  Samples live OUTSIDE the repo, under the real-data corpus
(``$CTF_REALDATA``, ``ctf.paths.realdata_root()``)::

    keyed_decrypt/ebics/<case>/case.toml
    keyed_decrypt/knx/<case>/case.toml
    keyed_decrypt/ios_backup/<case>/case.toml

When a folder is absent the test reports as NOT RUN (needs_realdata); a present
folder with no case is a failure, never a pass.  ``case.toml`` keys (paths are
relative to the case folder; ``expect_sha256`` is of the decrypted bytes):

ebics       documents = ["init.xml", "transfer1.xml"]
            private_key = "key.pem"  | transaction_key_hex = "..."
            key_password_file = "pw.txt" (optional)
            expect_sha256 = "..." and/or expect_contains = "text"
knx         mode = "keyring" | "data-secure" | "wrapper"
            keyring = "x.knxkeys", password_file = "pw.txt"     (keyring, or key source)
            frames_hex = "frames.hex" (one hex frame per line)  (data-secure, wrapper)
            key_hex = "..."           (instead of a keyring)
            expect_plain_hex = ["...", ...]  (plain APDU / inner frame per frame)
            expect_group_keys = {"1/2/3" = "hex"}               (keyring)
ios_backup  backup = "backup-folder", password_file = "pw.txt" | passcode_key_hex = "..."
            expect_files = [{relative_path = "...", sha256 = "..."}]
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from ctf import paths

import ff2_ios_backup_decrypt as IOS
import sec_bank_ebics_decrypt as EBICS
import sec_bas_knx_secure as KNX


def _cases(fmt: str) -> list[tuple[Path, dict]]:
    folder = paths.realdata_root() / "keyed_decrypt" / fmt
    cases = sorted(path.parent for path in folder.glob("*/case.toml"))
    assert cases, f"{folder} exists but holds no <case>/case.toml"
    return [(case, tomllib.loads((case / "case.toml").read_text(encoding="utf-8"))) for case in cases]


def _hash(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


@pytest.mark.needs_realdata("keyed_decrypt/ebics")
def test_real_ebics_samples():
    for case, spec in _cases("ebics"):
        documents = [(case / name).read_bytes() for name in spec["documents"]]
        password = None
        if "key_password_file" in spec:
            password = (case / spec["key_password_file"]).read_bytes().rstrip(b"\r\n")
        result = EBICS.decrypt_envelopes(
            documents,
            private_key=(case / spec["private_key"]).read_bytes() if "private_key" in spec else None,
            key_password=password,
            transaction_key=bytes.fromhex(spec["transaction_key_hex"]) if "transaction_key_hex" in spec else None,
        )
        plain = result["order_plaintext"]
        assert "expect_sha256" in spec or "expect_contains" in spec, f"{case}: case.toml states no expectation"
        if "expect_sha256" in spec:
            assert _hash(plain) == spec["expect_sha256"], case
        if "expect_contains" in spec:
            assert spec["expect_contains"].encode() in plain, case


@pytest.mark.needs_realdata("keyed_decrypt/knx")
def test_real_knx_samples():
    for case, spec in _cases("knx"):
        keyring = None
        if "keyring" in spec:
            password = (case / spec["password_file"]).read_text(encoding="utf-8").rstrip("\r\n")
            keyring = KNX.load_keyring((case / spec["keyring"]).read_bytes(), password)
        mode = spec["mode"]
        if mode == "keyring":
            assert keyring is not None, f"{case}: keyring mode needs keyring"
            for address, key in spec["expect_group_keys"].items():
                assert keyring["group_keys"][address] == key.lower(), case
            continue
        lines = (case / spec["frames_hex"]).read_text(encoding="ascii").splitlines()
        frames = [bytes.fromhex("".join(line.split("#", 1)[0].split())) for line in lines
                  if line.split("#", 1)[0].strip()]
        expected = spec["expect_plain_hex"]
        assert len(expected) == len(frames), f"{case}: one expect_plain_hex per frame"
        for frame, want in zip(frames, expected):
            if mode == "data-secure":
                keys = spec.get("key_hex") or KNX.keyring_keys(keyring)
                assert KNX.decrypt_data_secure(frame, keys)["plain_apdu_hex"] == want.lower(), case
            elif mode == "wrapper":
                key = spec.get("key_hex") or keyring["backbone"]["key"]
                assert KNX.decrypt_secure_wrapper(frame, key)["inner_hex"] == want.lower(), case
            else:
                pytest.fail(f"{case}: unknown mode {mode!r}")


@pytest.mark.needs_realdata("keyed_decrypt/ios_backup")
def test_real_ios_backup_samples(tmp_path):
    for index, (case, spec) in enumerate(_cases("ios_backup")):
        password = None
        if "password_file" in spec:
            password = (case / spec["password_file"]).read_bytes().rstrip(b"\r\n")
        passcode_key = bytes.fromhex(spec["passcode_key_hex"]) if "passcode_key_hex" in spec else None
        report = IOS.decrypt_backup(case / spec["backup"], tmp_path / str(index), password=password,
                                    passcode_key=passcode_key)
        by_path = {row["relative_path"]: row for row in report["files"]}
        assert spec["expect_files"], f"{case}: case.toml states no expected files"
        for want in spec["expect_files"]:
            assert by_path[want["relative_path"]]["sha256"] == want["sha256"], case
