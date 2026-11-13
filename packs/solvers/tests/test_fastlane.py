"""Tests for ctf.fastlane -- the in-process wave fast lane (sanity flags, encoding chains, OSINT
candidates, and never guessing).

Run:  .venv/bin/python -m pytest tests/test_fastlane.py   (or `python tests/test_fastlane.py`)

All inputs are SYNTHETIC and all lookups are OFFLINE: network fetches are exercised only through an
injected `fetch` that returns canned bodies, so the test never touches the wire.

B-001d: this was a module-level script that pytest never collected (tests/conftest.py collect_ignore);
its 16 checks are now pytest tests with plain asserts, so a failure fails the suite.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from ctf import config as _config          # noqa: E402
from ctf import fastlane                    # noqa: E402

FLAG = "CSCTF{f4st_L4ne_g0_g0_g0}"
BLOB = base64.b64encode(FLAG.encode())


@pytest.fixture(scope="module")
def cfg():
    return _config.load()


@pytest.fixture
def mkfiles(tmp_path):
    def make(**named: bytes) -> Path:
        d = tmp_path / f"files{len(list(tmp_path.iterdir()))}"
        d.mkdir()
        for name, data in named.items():
            (d / name).write_bytes(data if isinstance(data, bytes) else data.encode())
        return d
    return make


def test_inline_flag_in_description_is_high_confidence_sanity(cfg, mkfiles):
    d = {"name": "Sanity Check", "category": "sanity",
         "description": f"Welcome! Read the rules. Here is a freebie: {FLAG}"}
    r = fastlane.try_solve(d, mkfiles(), cfg=cfg, online=False)
    assert r is not None and r["flag"] == FLAG, r
    assert r["klass"] == "sanity" and r["confidence"] == "high", r


RULES_DESC = {"name": "Read The Rules", "category": "sanity",
              "description": "To prove you read the rules, submit the flag hidden on the rules page."}


def test_flag_fetched_from_rules_page_with_its_source(cfg, mkfiles):
    rules_url = cfg.base_url + "/rules"
    html = f"<html><body><h1>Rules</h1><p>Be fair. The sanity flag is {FLAG} enjoy.</p></body></html>"
    r = fastlane.try_solve(RULES_DESC, mkfiles(), cfg=cfg, online=True,
                           fetch=lambda url: html if url == rules_url else None)
    assert r is not None and r["flag"] == FLAG, r
    assert r["klass"] == "sanity" and rules_url in (r.get("source") or ""), r


def test_offline_sanity_gives_an_instruction_not_a_guess(cfg, mkfiles):
    r = fastlane.try_solve(RULES_DESC, mkfiles(), cfg=cfg, online=False)
    assert r is not None and r["flag"] is None and r.get("instruction"), r


def test_base64_file_decodes_to_the_flag(cfg, mkfiles):
    d = {"name": "Decode Me", "category": "crypto", "description": "Peel the layers."}
    r = fastlane.try_solve(d, mkfiles(**{"message.txt": BLOB}), cfg=cfg, online=False)
    assert r is not None and r["flag"] == FLAG, r
    assert r["klass"] == "encoding" and r["confidence"] == "high", r


def test_base64_blob_in_the_description_decodes(cfg, mkfiles):
    d = {"name": "Inline Blob", "category": "crypto", "description": f"Here you go: {BLOB.decode()}"}
    r = fastlane.try_solve(d, mkfiles(), cfg=cfg, online=False)
    assert r is not None and r["flag"] == FLAG, r


def test_double_base64_chain_resolves(cfg, mkfiles):
    d = {"name": "Deep", "category": "crypto", "description": ""}
    r = fastlane.try_solve(d, mkfiles(**{"deep.txt": base64.b64encode(BLOB)}), cfg=cfg, online=False)
    assert r is not None and r["flag"] == FLAG, r


def test_wayback_first_capture_is_a_candidate_for_a_human(cfg, mkfiles):
    body = json.dumps([["timestamp", "original"], ["20071015123456", "http://example.com/"]])
    d = {"name": "Time Machine", "category": "osint",
         "description": "When was http://example.com/ first archived on the Wayback Machine?"}
    r = fastlane.try_solve(d, mkfiles(), cfg=cfg, online=True,
                           fetch=lambda url: body if "web.archive.org/cdx" in url else None)
    assert r is not None and r["flag"] is None and r["candidate"] == "2007-10-15", r
    assert r["klass"] == "osint:wayback" and r["confidence"] == "medium", r


def test_nvd_score_is_a_candidate_not_a_submit_value(cfg, mkfiles):
    body = json.dumps({"vulnerabilities": [{"cve": {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}}]})
    d = {"name": "VulnDB", "category": "osint", "description": "What is the CVSS v3.1 base score of CVE-2021-44228?"}
    r = fastlane.try_solve(d, mkfiles(), cfg=cfg, online=True,
                           fetch=lambda url: body if "services.nvd.nist.gov" in url else None)
    assert r is not None and r["flag"] is None and r["candidate"] == "9.8", r


def test_mitre_technique_gives_the_authoritative_source(cfg, mkfiles):
    d = {"name": "Technique", "category": "osint", "description": "Which MITRE ATT&CK technique is T1059.003?"}
    r = fastlane.try_solve(d, mkfiles(), cfg=cfg, online=False)
    assert r is not None and r["flag"] is None, r
    assert "T1059.003" in (r.get("instruction") or "") and "attack.mitre.org" in (r.get("source") or ""), r


def test_unrelated_pwn_challenge_is_not_guessed(cfg, mkfiles):
    d = {"name": "Mystery Pwn", "category": "pwn", "description": "nc chall.example 1337 -- pop a shell and read /flag."}
    assert fastlane.try_solve(d, mkfiles(), cfg=cfg, online=False) is None


def test_plain_prose_file_is_not_guessed(cfg, mkfiles):
    files = mkfiles(**{"readme.txt": b"Just some ordinary notes, nothing encoded here at all today."})
    d = {"name": "Notes", "category": "misc", "description": "Have a look."}
    assert fastlane.try_solve(d, files, cfg=cfg, online=False) is None


def test_cli_report_returns_0_on_a_solved_encoding_challenge(tmp_path, capsys):
    ws = tmp_path / "ws"
    (ws / "files").mkdir(parents=True)
    (ws / "files" / "blob.txt").write_bytes(BLOB)
    (ws / "challenge.json").write_text(json.dumps({"id": 1, "name": "CLI Decode", "category": "crypto",
                                                   "description": ""}), encoding="utf-8")
    assert fastlane.report(ws, online=False) == 0
    assert FLAG in capsys.readouterr().out


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
