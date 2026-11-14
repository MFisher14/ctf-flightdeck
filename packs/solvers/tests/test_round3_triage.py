"""Round-3 engines are routed and web/offensive nudges remain category-scoped."""
from __future__ import annotations

from ctf import triage


def test_round3_category_engine_membership():
    expected = {
        "crypto": {"solvers/common/crypto_depth.py", "solvers/common/lattice_tools.py",
                   "solvers/common/ecc_weak.py", "solvers/toolkits/prng_recovery.py",
                   "solvers/toolkits/blockchain.py"},
        "pwn": {"solvers/toolkits/pwn_shellcode.py", "solvers/toolkits/pwn_fsop.py"},
        "web": {"solvers/web/deser_gadgets.py", "solvers/web/clientside_exploit.py",
                "solvers/web/authflow_exploit.py"},
        "forensics": {"solvers/toolkits/disk_images.py", "solvers/toolkits/video_stego.py"},
        "stego": {"solvers/toolkits/video_stego.py", "solvers/toolkits/qr_matrix.py"},
        "mobile": {"solvers/mobile-android/mobile_depth.py"},
        "ml": {"solvers/toolkits/ml_security.py"},
        "reverse": {"solvers/toolkits/reverse_depth.py"},
        "networking": {"solvers/toolkits/network_ics_depth.py"},
        "ics": {"solvers/toolkits/network_ics_depth.py", "solvers/toolkits/hardware_depth.py"},
        "opsec": {"solvers/toolkits/cloud_security.py"},
        "programming": {"solvers/warmups/esolang_tail.py", "solvers/toolkits/qr_matrix.py"},
        "misc": {"solvers/warmups/esolang_tail.py", "solvers/toolkits/qr_matrix.py",
                 "solvers/toolkits/prng_recovery.py", "solvers/toolkits/blockchain.py"},
    }
    for category, paths in expected.items():
        assert paths <= set(triage.CATEGORY_ENGINES[category])


def test_cloud_category_alias_routes_to_opsec_engine():
    report = triage.suggest("cloud")
    assert report["category"] == "opsec"
    assert "solvers/toolkits/cloud_security.py" in report["engines"]


def test_round3_keyword_nudges_front_the_specific_engine():
    cases = (
        ("crypto", "invalid curve weak subgroup MOV pairing transfer", "solvers/common/ecc_weak.py"),
        ("crypto", "ChaCha Poly1305 nonce reuse and GHASH", "solvers/common/crypto_depth.py"),
        ("pwn", "FSOP house of apple wide_data", "solvers/toolkits/pwn_fsop.py"),
        ("forensics", "recover deleted inode from QCOW2 ext4", "solvers/toolkits/disk_images.py"),
        ("mobile", "Flutter app with exported deep link", "solvers/mobile-android/mobile_depth.py"),
        ("ml", "malicious pickle inside a GGUF model card", "solvers/toolkits/ml_security.py"),
        ("ics", "SPI flash capture and JTAG boundary scan", "solvers/toolkits/hardware_depth.py"),
        ("reverse", "opaque predicate control flow flattening", "solvers/toolkits/reverse_depth.py"),
        ("opsec", "IAM policy and Kubernetes RBAC", "solvers/toolkits/cloud_security.py"),
        ("misc", "A FRACTRAN esolang program", "solvers/warmups/esolang_tail.py"),
    )
    for category, description, expected in cases:
        assert triage.suggest(category, description)["engines"][0] == expected


def test_web_payload_nudges_are_web_only_and_ecc_has_a_cli():
    description = "OAuth redirect_uri, SAML XSW, prototype pollution, deserialization and cloud metadata"
    web = triage.suggest("web", description)["engines"]
    assert web[0] == "solvers/toolkits/cloud_security.py"  # last matching web-only nudge
    assert "solvers/web/authflow_exploit.py" in web
    assert "solvers/web/clientside_exploit.py" in web
    assert "solvers/web/deser_gadgets.py" in web

    forensic = triage.suggest("forensics", description)["engines"]
    assert "solvers/web/authflow_exploit.py" not in forensic
    assert "solvers/web/clientside_exploit.py" not in forensic
    assert "solvers/web/deser_gadgets.py" not in forensic
    assert "solvers/toolkits/cloud_security.py" not in forensic

    assert "solvers/common/ecc_weak.py" not in triage.IMPORT_ONLY

