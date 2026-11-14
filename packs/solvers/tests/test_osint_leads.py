#!/usr/bin/env python3
"""Tests for solvers/toolkits/osint_leads.py -- the offline OSINT lead miner.

Every fixture is SYNTHETIC and built in-test (no files on disk, no network). The miner must find and
correctly classify the lead kinds the audit flagged as missing (CVE, VIN, IBAN, license-plate, API
keys, onion v3, crypto wallets) alongside the breadth it reuses from osint.py, validate what is
validatable (VIN ISO-3779 check digit, IBAN mod-97), attach offline lookup plans and a maps link /
decoded JWT note, and never raise on binary/garbage input.

  .venv/bin/python tests/test_osint_leads.py          # standalone
  .venv/bin/python -m pytest tests/test_osint_leads.py # under pytest
"""
import base64
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
sys.path.insert(0, str(REPO / "solvers" / "common"))

import osint_leads as L  # noqa: E402

# --------------------------------------------------------------------------- synthetic fixtures

# A valid VIN (ISO-3779 check digit at position 9 is self-consistent) and an invalid one.
VIN_OK = "1HGCM82633A004352"
VIN_BAD = "1HGCM82633A004353"          # check digit flipped -> must NOT be classified `vin`
# IBANs: GB82WEST... passes mod-97; the zero-check variant fails.
IBAN_OK = "GB82WEST12345698765432"
IBAN_BAD = "GB00WEST12345698765432"
# A base58check-valid BTC address (osint verifies the checksum) and an ETH address.
BTC = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
ETH = "0x52908400098527886E0F7030069857D2E4169EE7"
# A Tor v3 onion (56-char base32 label).
ONION_V3 = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"
# Secret shapes.
AWS = "AKIAIOSFODNN7EXAMPLE"  # secret-scan: allow
GOOGLE = "AIza" + "SyA1234567890abcdefghijklmnopqrstuv"   # AIza + 35 chars


def make_jwt():
    h = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps({"iss": "acme", "sub": "42", "role": "admin"}).encode()).rstrip(b"=").decode()
    return f"{h}.{p}.c2lnbmF0dXJl"


BLOB = (
    "Incident notes:\n"
    "Exploited CVE-2021-44228 (Log4Shell) and also cve-2014-0160.\n"
    f"Ransom wallet {BTC}, backup {ETH}.\n"
    "Contact handler@example.ru or @nightfall_ops; phone +40721234567.\n"
    f"Hidden service {ONION_V3}.\n"
    f"Stolen vehicle VIN {VIN_OK}; wire to {IBAN_OK}.\n"
    f"Leaked creds: {AWS} / {GOOGLE} / token {make_jwt()}.\n"
    "Last seen at 44.4268, 26.1025 and 40 deg 44' 54.3\" N 73 deg 59' 08.4\" W.\n"
    "MD5 d41d8cd98f00b204e9800998ecf8427e of the dropper.\n"
)


def _by_kind(rows):
    d = {}
    for r in rows:
        d.setdefault(r["kind"], []).append(r["value"])
    return d


# --------------------------------------------------------------------------- tests

def test_core_lead_kinds_found():
    rows = L.mine(text=BLOB)
    d = _by_kind(rows)
    assert "CVE-2021-44228" in d.get("cve", [])
    assert "CVE-2014-0160" in d.get("cve", [])
    assert VIN_OK in d.get("vin", [])
    assert IBAN_OK in d.get("iban", [])
    assert AWS in d.get("aws_key", [])
    assert GOOGLE in d.get("google_api_key", [])
    assert any(j.startswith("eyJ") for j in d.get("jwt", []))
    # reused from osint.py (not re-implemented here)
    assert BTC in d.get("crypto_address", [])
    assert ETH in d.get("crypto_address", [])
    assert "handler@example.ru" in d.get("email", [])
    assert "d41d8cd98f00b204e9800998ecf8427e" in d.get("md5", [])


def test_vin_check_digit_distinguishes_valid():
    assert L._vin_check_ok(VIN_OK) is True
    assert L._vin_check_ok(VIN_BAD) is False
    d = _by_kind(L.mine(text=f"vin {VIN_BAD} here"))
    assert VIN_BAD not in d.get("vin", [])          # bad check digit -> never plain `vin`
    assert VIN_BAD in d.get("vin_candidate", [])    # kept as a candidate instead


def test_iban_mod97():
    assert L._iban_ok(IBAN_OK) is True
    assert L._iban_ok(IBAN_BAD) is False
    d = _by_kind(L.mine(text=f"pay {IBAN_BAD}"))
    assert IBAN_BAD not in d.get("iban", [])
    assert IBAN_BAD in d.get("iban_candidate", [])


def test_onion_v3_reclassified():
    d = _by_kind(L.mine(text=f"svc {ONION_V3} online"))
    assert ONION_V3 in d.get("onion_v3", [])
    assert "onion_address" not in d               # reclassified away from osint's generic kind


def test_gps_coordinate_maps_link():
    rows = L.mine(text="rendezvous 44.4268, 26.1025")
    gps = [r for r in rows if r["kind"] == "gps_coordinate"]
    assert gps, "decimal pair should yield a gps_coordinate lead"
    assert gps[0]["note"].startswith("maps: https://www.google.com/maps?q=")
    # a DMS pair in one string is paired and normalized to decimal + a maps link
    link = L.maps_link("40 deg 44' 54.3\" N 73 deg 59' 08.4\" W")
    assert link and "maps?q=40.748" in link and "-73.985" in link


def test_jwt_decoded_offline_note():
    tok = make_jwt()
    rows = L.mine(text=f"auth {tok}")
    jrow = next(r for r in rows if r["kind"] == "jwt")
    assert "decoded" in jrow["note"]
    assert '"role": "admin"' in jrow["note"] or "'role': 'admin'" in jrow["note"]
    claims = L.jwt_claims(tok)
    assert claims["payload"]["iss"] == "acme"


def test_every_lead_has_a_lookup_plan():
    for r in L.mine(text=BLOB):
        assert isinstance(r.get("lookup"), str) and len(r["lookup"]) > 20


def test_ranking_prioritises_specific_leads():
    rows = L.mine(text=BLOB)
    kinds = [r["kind"] for r in rows]
    # a GPS coordinate / secret ranks above a bare hash
    assert kinds.index("gps_coordinate") < kinds.index("md5")
    assert kinds.index("aws_key") < kinds.index("md5")


def test_scan_dir_and_files(tmp_path=None):
    import tempfile
    tmp = Path(tempfile.mkdtemp())
    try:
        (tmp / "a.txt").write_text(f"CVE-2019-0708 and wallet {BTC}")
        (tmp / "b.log").write_text(f"VIN {VIN_OK}")
        rows = L.mine(paths=[str(tmp)])
        d = _by_kind(rows)
        assert "CVE-2019-0708" in d.get("cve", [])
        assert VIN_OK in d.get("vin", [])
        # sources name the files the lead came from
        vin_row = next(r for r in rows if r["kind"] == "vin")
        assert any("b.log" in s for s in vin_row["sources"])
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_never_raises_on_garbage():
    garbage = {"a.bin": os.urandom(4096), "b": bytes(range(256)) * 8, "c.pdf": b"%PDF-1.7 ("}
    leadmap = L.scan_files(garbage)
    assert isinstance(leadmap, dict)
    rows = L.rank(leadmap)
    assert isinstance(rows, list)
    # empty input is clean, too
    assert L.mine(text="") == []


def test_json_and_text_render_run():
    rows = L.mine(text=BLOB)
    txt = L.render_text(rows)
    assert "OSINT leads" in txt and "lookup:" in txt
    blob = json.dumps(rows, default=str)       # must be JSON-serialisable
    assert "cve" in blob


_TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]

if __name__ == "__main__":
    failed = []
    for fn in _TESTS:
        try:
            fn()
            print(f"ok   {fn.__name__}")
        except Exception as e:  # noqa: BLE001
            failed.append(fn.__name__)
            print(f"FAIL {fn.__name__}: {e}")
    if failed:
        print(f"\n{len(failed)} FAILED: " + "; ".join(failed))
        sys.exit(1)
    print(f"\nall {len(_TESTS)} osint_leads tests passed")
