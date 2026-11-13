from __future__ import annotations

from ctf import triage


def test_round2_engines_are_wired_to_their_lanes():
    expected = {
        "crypto": {"solvers/common/crypto_oracles.py", "solvers/common/crypto_malleability.py",
                   "solvers/common/lattice_tools.py"},
        "web": {"solvers/web/ssrf_chains.py", "solvers/web/http_desync.py"},
        "pwn": {"solvers/toolkits/pwn_seccomp.py", "solvers/toolkits/pwn_exploit.py"},
        "forensics": {"solvers/toolkits/timeline.py", "solvers/toolkits/file_repair.py"},
        "stego": {"solvers/toolkits/file_repair.py"},
        "osint": {"solvers/toolkits/osint_pivot.py"},
        "programming": {"solvers/toolkits/pow_solver.py"},
        "misc": {"solvers/toolkits/jail_escape.py", "solvers/toolkits/pow_solver.py"},
    }
    for category, engines in expected.items():
        assert engines <= set(triage.CATEGORY_ENGINES[category])


def test_round2_keyword_nudges_are_specific():
    cases = (
        ("crypto", "CBC padding oracle", "solvers/common/crypto_oracles.py"),
        ("crypto", "CBC bitflip token malleability", "solvers/common/crypto_malleability.py"),
        ("crypto", "Merkle-Hellman subset sum lattice", "solvers/common/lattice_tools.py"),
        ("pwn", "seccomp sock_filter blocks execve", "solvers/toolkits/pwn_seccomp.py"),
        ("programming", "proof of work with leading zero bits", "solvers/toolkits/pow_solver.py"),
        ("misc", "Python pyjail with no builtins", "solvers/toolkits/jail_escape.py"),
        ("forensics", "build a bodyfile supertimeline", "solvers/toolkits/timeline.py"),
        ("forensics", "repair PNG with corrupt CRC", "solvers/toolkits/file_repair.py"),
        ("stego", "seeded LSB pixel permutation", "solvers/toolkits/carve_stego.py"),
        ("web", "SSRF gopher:// FastCGI", "solvers/web/ssrf_chains.py"),
        ("web", "CL.TE request smuggling", "solvers/web/http_desync.py"),
    )
    for category, description, first in cases:
        assert triage.suggest(category, description)["engines"][0] == first


def test_new_web_payload_nudges_stay_behind_web_guard():
    engines = triage.suggest("forensics", "SSRF request smuggling cache poisoning FastCGI")["engines"]
    assert "solvers/web/ssrf_chains.py" not in engines
    assert "solvers/web/http_desync.py" not in engines

