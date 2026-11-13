"""B-114: the `ctf scan-index` command (ctf/cli/scan_index.py).

The command is run against the loopback provider fakes (tests/scan_index_fakes.py): keys come from the
process environment (dummy values), the workdir from $CTF_WORKDIR, the scope from a pinned test
profile. What is proved here: a captured certificate or icon file reaches every provider in the form
that provider indexes, the report keeps "no hit" and "not asked" apart, the exit codes, the quota
view, and that no key is ever printed. No test contacts a real provider, so none is marked `live`.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import ssl
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import scan_index_fakes as fk
from ctf import cli as ctf_cli
from ctf import favicon, ledger, scope
from ctf import scan_index as si
from ctf.cli import scan_index as cli

SERIAL = 0x6FDBE5407014B76F971F
ICON = b"\x00\x00\x01\x00" + bytes(range(256)) * 3


@pytest.fixture
def rig(monkeypatch, tmp_path):
    """Loopback fakes, dummy keys in the environment, a pinned profile that allows the fakes and a
    scratch workdir. Returns a function that starts the fakes (optionally with other handlers)."""
    made = []
    before = scope.pinned()
    work = tmp_path / "work"
    monkeypatch.setenv("CTF_WORKDIR", str(work))
    for name, value in fk.ENV.items():
        monkeypatch.setenv(name, value)
    # an operator shell's budget or org settings must not reach the tests
    for name in ("CTF_SCAN_INDEX_BUDGET", "CTF_SCAN_INDEX_CENSYS_ORG",
                 *(f"CTF_SCAN_INDEX_BUDGET_{p.upper()}" for p in si.PROVIDERS)):
        monkeypatch.delenv(name, raising=False)
    scope.pin(fk.profile())

    def _start(overrides=None):
        ix = fk.Indexes(overrides)
        made.append(ix)
        monkeypatch.setattr(cli, "_ENDPOINTS", ix.endpoints)
        ix.work = work
        return ix
    yield _start
    for ix in made:
        ix.close()
    scope.unpin() if before is None else scope.pin(before)


def _run(*argv: str) -> int:
    p = argparse.ArgumentParser()
    cli.add_arguments(p)
    return cli.run(p.parse_args(list(argv)))


def _no_key(text: str) -> bool:
    return not any(key in text for key in fk.KEYS.values())


def _leaf_der() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "origin.synthetic.test")])
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(SERIAL).not_valid_before(now).not_valid_after(now + dt.timedelta(days=30))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


def _fofa_q(fake) -> str:
    return base64.b64decode(fake.requests[-1].query["qbase64"][0]).decode("utf-8")


def test_command_is_discovered_as_scan_index():
    found = {name: (mod, err) for name, mod, err in ctf_cli.discover()}
    assert found["scan-index"] == (cli, None)
    assert isinstance(cli.HELP, str) and "B-114" in cli.HELP


@pytest.mark.parametrize("pem", [False, True])
def test_a_certificate_file_reaches_every_provider_in_the_form_it_indexes(rig, tmp_path, capsys, pem):
    ix = rig()
    der = _leaf_der()
    path = tmp_path / ("leaf-cert.pem" if pem else "leaf-cert.der")
    path.write_bytes(ssl.DER_cert_to_PEM_cert(der).encode() if pem else der)
    rc = _run("cert", "--cert-file", str(path))
    out, err = capsys.readouterr()
    assert rc == 0 and err == ""
    sha256, sha1 = hashlib.sha256(der).hexdigest(), hashlib.sha1(der).hexdigest()
    assert ix["shodan"].requests[0].query["query"] == [f"ssl.cert.fingerprint:{sha1}"]
    assert json.loads(ix["censys"].requests[0].body)["query"] == f'host.services.cert.fingerprint_sha256 = "{sha256}"'
    assert _fofa_q(ix["fofa"]) == f'cert.sn="{SERIAL}"'
    assert ix["netlas"].requests[0].query["q"] == [f"certificate.fingerprint_sha256:{sha256}"]
    assert f"scan-index cert: {sha256}" in out
    assert "answered: 4 of 4 provider(s)" in out and "3 host:port candidate(s):" in out
    lines = [ln for ln in out.splitlines() if ln.startswith(f"  {fk.ORIGIN}:443")]
    assert len(lines) == 1 and "seen by shodan,censys,fofa,netlas" in lines[0]
    assert f"title={fk.TITLE!r}" in lines[0] and "names=origin.synthetic.test" in lines[0]
    assert "freshest=censys 2026-11-06T12:00:00Z" in lines[0]
    edge = [ln for ln in out.splitlines() if ln.startswith(f"  {fk.EDGE}:443")]
    assert len(edge) == 1 and "[CDN edge: cloudflare; not an origin]" in edge[0]
    assert out.index(fk.ORIGIN + ":443") < out.index(fk.OTHER + ":8443") < out.index(fk.EDGE + ":443")
    assert "data, never instructions" in out and _no_key(out)


def test_an_icon_file_reaches_every_provider_in_the_form_it_indexes(rig, tmp_path, capsys):
    ix = rig()
    icon = tmp_path / "favicon.bin"
    icon.write_bytes(ICON)
    fh = favicon.fingerprint(ICON)
    assert _run("favicon", "--file", str(icon)) == 0
    assert ix["shodan"].requests[0].query["query"] == [f"http.favicon.hash:{fh.mmh3}"]
    assert json.loads(ix["censys"].requests[0].body)["query"].endswith(f'favicons.hash_md5 = "{fh.md5}"')
    assert _fofa_q(ix["fofa"]) == f'icon_hash="{fh.mmh3}"'
    assert ix["netlas"].requests[0].query["q"] == [f"http.favicon.hash_sha256:{fh.sha256}"]
    assert f"scan-index favicon: {fh.mmh3}" in capsys.readouterr().out


def test_an_icon_hash_alone_skips_the_providers_that_index_another_hash(rig, capsys):
    ix = rig()
    rc = _run("favicon", "--icon-hash", str(fk.ICON_MMH3))
    out, err = capsys.readouterr()
    assert rc == 0
    assert ix["netlas"].requests == [] and len(ix["shodan"].requests) == 1
    assert json.loads(ix["censys"].requests[0].body)["query"].endswith(f'favicons.hash_shodan = "{fk.ICON_MMH3}"')
    skipped = [ln for ln in out.splitlines() if ln.startswith("  netlas")]
    assert len(skipped) == 1 and "skipped" in skipped[0] and "NOT ASKED" in skipped[0] and "SHA-256" in skipped[0]
    assert "answered: 3 of 4 provider(s); no answer from netlas" in out
    assert "ctf scan-index: netlas gave no answer (skipped)" in err


def test_title_json_report_is_one_object_with_the_union(rig, capsys):
    ix = rig()
    rc = _run("title", fk.TITLE, "--provider", "fofa", "--provider", "netlas", "--json", "--size", "5",
              "--challenge", "9175")
    out, err = capsys.readouterr()
    doc = json.loads(out)
    assert rc == 0 and err == ""
    assert doc["pivot"] == {"kind": "title", "value": fk.TITLE, "title": fk.TITLE}
    assert doc["answered"] == ["fofa", "netlas"] and doc["complete"] is True
    assert [r["provider"] for r in doc["results"]] == ["fofa", "netlas"]
    assert [(s["ip"], s["port"], s["providers"], s["cdn"]) for s in doc["services"]] == [
        (fk.ORIGIN, 443, ["fofa", "netlas"], None), (fk.OTHER, 8443, ["fofa"], None),
        (fk.EDGE, 443, ["fofa"], "cloudflare")]
    assert "public_ports" not in doc and "non_public" not in doc["services"][0]
    assert ix["shodan"].requests == [] and ix["censys"].requests == []
    assert ix["fofa"].requests[0].query["size"] == ["5"] and _fofa_q(ix["fofa"]) == f'title="{fk.TITLE}"'
    rows = [r for r in ledger.read(ix.work) if r["event"] == si.EVENT]
    assert [r["challenge"] for r in rows] == ["9175", "9175"] and rows[0]["value"] == fk.TITLE
    assert _no_key(out)


def test_host_report_marks_the_non_public_ports_and_shows_what_the_scanners_archived(rig, capsys):
    rig()
    rc = _run("host", fk.ORIGIN)
    out, err = capsys.readouterr()
    assert rc == 0 and err == ""
    assert f"ports of {fk.ORIGIN} across 5 index(es); public port(s): 80, 443" in out
    line = {p: next(ln for ln in out.splitlines() if f"{fk.ORIGIN}:{p} " in ln) for p in (22, 443, 8080)}
    assert line[8080].startswith("  NON-PUBLIC ") and line[22].startswith("  NON-PUBLIC ")
    assert line[443].startswith("  public     ")
    assert "seen by censys,fofa,netlas,internetdb" in line[8080] and "NOT listed by shodan" in line[8080]
    assert "title='Synthetic Internal Ops'" in line[8080] and "NOT listed by" not in line[443]
    assert f"      uuid (recovery token): {fk.PANEL_UUID}   [from the body censys archived]" in out
    assert "not an answer" in out and "Do not guess paths or scan ports" in out


def test_host_public_port_option_and_json_flags(rig, capsys):
    rig()
    assert _run("host", fk.ORIGIN, "--public-port", "8080", "--public-port", "22", "--json") == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["public_ports"] == [8080, 22]
    assert {s["port"]: s["non_public"] for s in doc["services"]} == {22: False, 443: True, 8080: False}
    panel = next(s for s in doc["services"] if s["port"] == 8080)
    assert panel["missing_from"] == ["shodan"] and panel["freshest"] == "censys"
    assert panel["findings"] == [{"provider": "censys", "kind": "uuid", "value": fk.PANEL_UUID,
                                  "label": "recovery token"}]


def test_a_missing_key_is_reported_and_the_rest_still_answer(rig, monkeypatch, capsys):
    ix = rig()
    monkeypatch.delenv("CTF_SCAN_INDEX_SHODAN_KEY")
    rc = _run("title", fk.TITLE)
    out, err = capsys.readouterr()
    assert rc == 0 and ix["shodan"].requests == []
    assert "no_key     NOT ASKED: CTF_SCAN_INDEX_SHODAN_KEY is not set" in out
    assert "ctf scan-index: shodan gave no answer (no_key): CTF_SCAN_INDEX_SHODAN_KEY is not set" in err
    assert "answered: 3 of 4 provider(s); no answer from shodan" in out


def test_no_provider_answering_exits_3_and_names_every_reason(rig, monkeypatch, capsys):
    ix = rig()
    for name in fk.ENV:
        monkeypatch.delenv(name)
    rc = _run("cert", "--sha256", fk.CERT_SHA256, "--sha1", fk.CERT_SHA1, "--serial", fk.CERT_SERIAL)
    out, err = capsys.readouterr()
    assert rc == cli.NO_ANSWER_EXIT == 3 and ix.total_requests() == 0
    for name in fk.ENV:
        assert f"{name} is not set" in err
    assert "answered: 0 of 4 provider(s)" in out and "candidate" not in out and "no indexed host" not in out


def test_a_provider_failure_is_asked_not_answered_and_exits_3_when_alone(rig, capsys):
    ix = rig({"netlas": lambda rec: (429, {"detail": "daily limit"})})
    rc = _run("title", fk.TITLE, "--provider", "netlas")
    out, err = capsys.readouterr()
    assert rc == 3 and len(ix["netlas"].requests) == 1
    assert "  netlas     quota      asked: HTTP 429: daily limit" in out
    assert "netlas gave no answer (quota)" in err


def test_zero_rows_is_an_answer_that_says_an_index_is_not_proof(rig, capsys):
    rig({"netlas": lambda rec: (200, {"items": []})})
    rc = _run("title", "Nothing Has This Title", "--provider", "netlas")
    out, err = capsys.readouterr()
    assert rc == 0 and err == ""
    assert "ok         0 row(s)" in out and "no indexed host:port matched" in out and "not proof" in out


def test_scope_refusal_exits_4_and_sends_nothing(rig, capsys):
    ix = rig()
    scope.pin(fk.profile(public=()))
    rc = _run("host", fk.ORIGIN)
    out, err = capsys.readouterr()
    assert rc == cli.REFUSED_EXIT == 4 and ix.total_requests() == 0
    assert err.count("gave no answer (refused)") == 5 and "rules.public_fetch_allow" in err
    assert out.count("refused    NOT ASKED") == 5
    # an unknown --event is a bad argument, not a lookup
    scope.unpin()
    assert _run("--event", "no-such-event-b114", "host", fk.ORIGIN) == cli.ERROR_EXIT
    assert "no-such-event-b114" in capsys.readouterr().err


def test_exit_4_needs_every_askable_provider_refused_not_just_one(rig, monkeypatch, capsys):
    ix = rig()
    # Shodan points at a loopback address the profile does not list: refused before any byte. Netlas
    # is in scope but has no key. One refusal among other failures is "no answer" (3), not scope (4).
    monkeypatch.setattr(cli, "_ENDPOINTS", {**ix.endpoints, "shodan": "http://127.0.0.2:9"})
    monkeypatch.delenv("CTF_SCAN_INDEX_NETLAS_KEY")
    rc = _run("title", fk.TITLE, "--provider", "shodan", "--provider", "netlas")
    out, err = capsys.readouterr()
    assert "shodan gave no answer (refused)" in err and "127.0.0.2" in err
    assert "netlas gave no answer (no_key)" in err
    assert rc == cli.NO_ANSWER_EXIT == 3 and ix.total_requests() == 0
    # the same refusal beside a provider that cannot take the pivot (skipped, so not askable) is a
    # scope refusal: every provider that could have been asked was refused
    monkeypatch.setenv("CTF_SCAN_INDEX_NETLAS_KEY", fk.KEYS["netlas"])
    rc = _run("favicon", "--icon-hash", str(fk.ICON_MMH3), "--provider", "shodan", "--provider", "netlas")
    out, err = capsys.readouterr()
    assert "netlas gave no answer (skipped)" in err and rc == cli.REFUSED_EXIT == 4
    assert ix.total_requests() == 0


def test_no_event_profile_is_a_refusal(rig, monkeypatch, capsys):
    ix = rig()
    scope.unpin()
    monkeypatch.setenv("CTF_EVENT", "no-such-event-b114")
    assert _run("title", fk.TITLE) == cli.REFUSED_EXIT
    assert "profile did not load" in capsys.readouterr().err and ix.total_requests() == 0


@pytest.mark.parametrize("argv,word", [
    (["cert"], "needs a SHA-256"),
    (["cert", "--sha256", "abcd"], "64 hex"),
    (["favicon"], "needs the mmh3"),
    (["favicon", "--icon-hash", "not-a-number"], "signed 32-bit"),
    (["host", "origin.synthetic.test"], "one IP address"),
    (["title", "x" * 201], "at most 200"),
    (["title", "ok", "--size", "0"], "size"),
    (["title", "ok", "--budget", "-1"], "int >= 0"),
])
def test_bad_arguments_exit_2_and_send_nothing(rig, capsys, argv, word):
    ix = rig()
    assert _run(*argv) == cli.ERROR_EXIT == 2
    assert word in capsys.readouterr().err and ix.total_requests() == 0


def test_file_arguments_are_checked(rig, tmp_path, capsys):
    ix = rig()
    junk = tmp_path / "junk.der"
    junk.write_bytes(b"\x30\x03not a certificate")
    assert _run("cert", "--cert-file", str(junk)) == 2
    assert "could not be read as an X.509 certificate" in capsys.readouterr().err
    assert _run("cert", "--cert-file", str(tmp_path / "absent.der")) == 2
    assert _run("cert", "--cert-file", str(junk), "--sha256", fk.CERT_SHA256) == 2
    assert "not both" in capsys.readouterr().err
    icon = tmp_path / "favicon.bin"
    icon.write_bytes(ICON)
    assert _run("favicon", "--file", str(icon), "--icon-hash", "5") == 2
    assert "not both" in capsys.readouterr().err
    assert _run("favicon", "--file", str(tmp_path / "absent.ico")) == 2
    assert ix.total_requests() == 0
    with pytest.raises(SystemExit):                          # the provider list is closed at the parser too
        _run("title", "x", "--provider", "zoomeye")


def test_budget_refresh_and_cache_lines(rig, capsys):
    ix = rig()
    assert _run("title", fk.TITLE, "--provider", "netlas") == 0
    assert "[HTTP 200]" in capsys.readouterr().out
    assert _run("title", fk.TITLE, "--provider", "netlas") == 0          # served from the workdir cache
    assert "[cached 20" in capsys.readouterr().out and len(ix["netlas"].requests) == 1
    assert _run("title", fk.TITLE, "--provider", "netlas", "--refresh") == 0
    assert len(ix["netlas"].requests) == 2
    capsys.readouterr()
    assert _run("title", "Another Title", "--provider", "netlas", "--budget", "2") == 3
    out, err = capsys.readouterr()
    assert "budget     NOT ASKED: 2 of 2 budgeted netlas requests" in out and len(ix["netlas"].requests) == 2


def test_quota_view_shows_keys_present_and_requests_used_never_a_key(rig, monkeypatch, capsys):
    ix = rig({"fofa": lambda rec: (200, {"error": True, "errmsg": "[820031] insufficient points"})})
    monkeypatch.delenv("CTF_SCAN_INDEX_NETLAS_KEY")
    monkeypatch.setenv("CTF_SCAN_INDEX_BUDGET_FOFA", "4")
    _run("title", fk.TITLE)
    capsys.readouterr()
    assert _run("quota") == 0
    out = capsys.readouterr().out
    line = {ln.split()[0]: ln for ln in out.splitlines()[1:]}
    assert "used 1/25 (left 24)" in line["shodan"] and "CTF_SCAN_INDEX_SHODAN_KEY set" in line["shodan"]
    assert "last ok 20" in line["shodan"]
    assert "used 1/4 (left 3)" in line["fofa"] and "last quota" in line["fofa"] and "provider quota hit 20" in line["fofa"]
    assert "used 0/25 (left 25)" in line["netlas"] and "CTF_SCAN_INDEX_NETLAS_KEY NOT SET" in line["netlas"]
    assert "never asked" in line["netlas"] and "no key needed" in line["internetdb"]
    assert str(ix.work) in out.splitlines()[0] and _no_key(out)
    assert _run("quota", "--json", "--budget", "10") == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["fofa"]["used"] == 1 and doc["fofa"]["budget"] == 10 and doc["fofa"]["left"] == 9
    assert doc["netlas"] == {"provider": "netlas", "used": 0, "budget": 10, "left": 10, "last_status": None,
                             "last_ts": None, "quota_hit_ts": None, "key_env": "CTF_SCAN_INDEX_NETLAS_KEY",
                             "key_set": False}
    assert doc["shodan"]["key_set"] is True and doc["internetdb"]["key_env"] is None
    assert doc["internetdb"]["key_set"] is True


def test_a_key_is_never_printed_even_when_a_provider_echoes_it(rig, capsys):
    key = fk.KEYS["shodan"]
    rig({"shodan": lambda rec: (403, {"error": f"key {key} lacks access to {rec.raw_path}"})})
    rc = _run("title", fk.TITLE, "--provider", "shodan")
    out, err = capsys.readouterr()
    assert rc == 3 and "<redacted>" in err and key not in out and key not in err
    assert _run("title", fk.TITLE, "--provider", "shodan", "--json") == 3
    out, err = capsys.readouterr()
    assert key not in out and key not in err and json.loads(out)["results"][0]["status"] == "auth"


def test_the_command_runs_through_ctf_main(rig, capsys):
    rig()
    assert ctf_cli.main(["scan-index", "title", fk.TITLE, "--provider", "censys"]) == 0
    assert "answered: 1 of 1 provider(s)" in capsys.readouterr().out


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
