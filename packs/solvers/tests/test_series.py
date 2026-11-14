"""B-090: series-chaining. A follow-up task reuses the certificate / favicon a sibling task saved.

Every fixture is synthetic: two (or more) sibling workspaces built in tmp_path in the `ctf pull` /
`ctf intake` layout (`<id>-<slug>/challenge.json`, `evidence/`), with a self-signed certificate
generated here and a made-up ICO. The expected values are computed independently of ctf.series
(cryptography's own `cert.fingerprint`, hashlib, ctf.favicon), so a wrong field, form or source
fails the test.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ctf import event, favicon, hypothesis, series  # noqa: E402

from cryptography.hazmat.primitives import hashes  # noqa: E402

import series_chain  # noqa: E402  the engine, flat-imported from solvers/toolkits

sys.path.insert(0, str(Path(__file__).resolve().parent))
from series_fixtures import (BRIEF_1, BRIEF_FP, BRIEF_MD5, ICON, colon_upper, der, make_cert, pem,  # noqa: E402
                             profile, workspace)

REPO = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------- names and briefs

@pytest.mark.parametrize("name,key,rest", [
    ("Onion Deanon 1: Read the Certificate", "onion deanon 1", "Read the Certificate"),
    ("Onion Deanon 2: Hash the Favicon Again", "onion deanon 2", "Hash the Favicon Again"),
    ("Harbor Lab - Part 2", "harbor lab", "Part 2"),
    ("Harbor Lab — The Gate", "harbor lab", "The Gate"),
    ("Ghost Ship | Logbook", "ghost ship", "Logbook"),
    ("Harbor Lab Part 3", "harbor lab", "Part 3"),
    ("Harbor Lab (2/3)", "harbor lab", "(2/3)"),
])
def test_series_key_is_the_shared_prefix(name, key, rest):
    assert series.split_name(name) == (key, rest)


@pytest.mark.parametrize("name", ["Web: SQL Login", "Warmup: Hello", "OSINT: Where", "Task 2 - Read it",
                                  "Part 1: The start", "Plain Name", "AB: tiny"])
def test_category_generic_and_bare_part_prefixes_are_not_series(name):
    assert series.series_key(name) is None


def test_continuation_wording_is_read_through_markup():
    assert series.continuation_marker(BRIEF_FP) == "continuation of the same lab"
    assert series.continuation_marker("<i>See the <b>first</b> task</i> for details") == "see the first task"
    assert series.continuation_marker(BRIEF_1) is None
    assert series.continuation_marker("a continuation of the story is not a lab") is None


def test_brief_flag_prefix():
    assert series.brief_prefix(BRIEF_FP) == "CSCTF"
    assert series.brief_prefix("flag FORMAT: <code>pink{...}</code>") == "pink"
    assert series.brief_prefix("no format here") is None


# ---------------------------------------------------------------- wording -> field and form

def test_fingerprint_wording_maps_to_one_certificate_sha256_with_colons_upper():
    reqs = series.requests("Onion Deanon 1: Fingerprint the Certificate", BRIEF_FP)
    assert [(r.kind, r.field) for r in reqs] == [("certificate", "sha256")]
    assert reqs[0].form.colon is True and reqs[0].form.case == "upper"


def test_favicon_md5_wording_maps_to_the_favicon_md5_only():
    reqs = series.requests("Onion Deanon 2: Hash the Favicon Again", BRIEF_MD5)
    assert [(r.kind, r.field) for r in reqs] == [("favicon", "md5")]
    assert reqs[0].form.colon is None and reqs[0].form.case is None


def test_the_title_object_wins_over_one_the_brief_mentions_in_passing():
    brief = BRIEF_MD5.replace("Get the favicon's MD5 hash.",
                              "The certificate did not help. Get the MD5 hash of the favicon.")
    reqs = series.requests("Lab 9: Hash the Favicon", brief)
    assert [(r.kind, r.field) for r in reqs] == [("favicon", "md5")]


@pytest.mark.parametrize("text,expected", [
    ("Get the certificate's serial number. Answer: decimal.", [("certificate", "serial")]),
    ("Give the favicon hash the way Shodan indexes it.", [("favicon", "mmh3")]),
    ("What is the certificate fingerprint?", [("certificate", "sha256"), ("certificate", "sha1")]),
    ("What is the favicon's hash?", [("favicon", "mmh3"), ("favicon", "md5")]),
    ("Give the SPKI pin.", [("certificate", "spki_sha256")]),
    ("Who is the certificate issuer?", [("certificate", "issuer_cn")]),
    ("Name the subject of the email.", []),            # 'subject' without a certificate binds nothing
    ("What is the SHA-256 of the dump?", []),          # a digest of something this module does not hold
])
def test_wording_to_field(text, expected):
    assert [(r.kind, r.field) for r in series.requests("Lab 9: Task", text)] == expected


def test_stated_forms_filter_the_grid():
    fields = {"sha256": "ab" * 32, "serial": "0A1B", "serial_int": "2587",
              "mmh3": "-5", "mmh3_unsigned": str(2 ** 32 - 5), "md5": "cd" * 16}

    def F(kind, field, brief):
        return [v for _, v in series.forms(series.Request(kind, field, series.answer_form(brief), ""), fields)]

    assert F("certificate", "sha256", "Answer: uppercase hexadecimal with colons") == [":".join(["AB"] * 32)]
    assert F("certificate", "sha256", "Answer: lowercase, without colons") == ["ab" * 32]
    assert F("certificate", "sha256", "Answer: the fingerprint")[0] == ":".join(["AB"] * 32)
    assert F("favicon", "md5", "Answer: the MD5 hash, hexadecimal") == ["cd" * 16, "CD" * 16]
    assert F("certificate", "serial", "Answer: the serial as a decimal integer") == ["2587"]
    assert F("certificate", "serial", "Answer: the serial") == ["0A1B", "0a1b", "2587"]
    assert F("favicon", "mmh3", "Answer: the unsigned mmh3") == [str(2 ** 32 - 5)]
    assert F("favicon", "mmh3", "Answer: the hash") == ["-5", str(2 ** 32 - 5)]


# ---------------------------------------------------------------- the chain, end to end

def test_follow_up_fingerprint_is_computed_from_the_siblings_saved_certificate(tmp_path):
    cert = make_cert(0x6FDBE5407014B76F971FAFC7E888BD66FEC5D2FD)
    workspace(tmp_path, 9166, "Onion Deanon 1: Read the Certificate", BRIEF_1,
              {"evidence/leaf-cert.pem": pem(cert), "notes.md": b"# solve notes\n"})
    target = workspace(tmp_path, 9167, "Onion Deanon 1: Fingerprint the Certificate", BRIEF_FP)
    rep = series.chain(target, profile=profile())
    want = "CSCTF{" + colon_upper(cert.fingerprint(hashes.SHA256())) + "}"
    assert rep.status == "candidate"
    assert rep.flags == [want]                              # one stated form -> exactly one flag
    c = rep.candidates[0]
    assert (c.kind, c.field, c.sibling) == ("certificate", "sha256", "9166-onion-deanon-1-read-the-certificate")
    assert c.source == "9166-onion-deanon-1-read-the-certificate/evidence/leaf-cert.pem"
    assert c.source_sha256 == hashlib.sha256(pem(cert)).hexdigest()
    assert rep.siblings == [{"dir": "9166-onion-deanon-1-read-the-certificate", "id": "9166",
                             "name": "Onion Deanon 1: Read the Certificate", "marker": None}]


def test_follow_up_favicon_md5_is_computed_from_the_siblings_saved_icon(tmp_path):
    workspace(tmp_path, 9170, "Onion Deanon 2: Read the Favicon", BRIEF_1.replace("certificate", "favicon"),
              {"evidence/favicon.bin": ICON, "evidence/favicon.json": b'{"md5": "not this"}'})
    target = workspace(tmp_path, 9171, "Onion Deanon 2: Hash the Favicon Again", BRIEF_MD5)
    rep = series.chain(target, profile=profile())
    md5 = hashlib.md5(ICON).hexdigest()
    assert rep.status == "candidate"
    assert rep.flags == [f"CSCTF{{{md5}}}", f"CSCTF{{{md5.upper()}}}"]     # lower first: hex unstated
    assert {c.source for c in rep.candidates} == {"9170-onion-deanon-2-read-the-favicon/evidence/favicon.bin"}
    art = rep.artifacts[0]
    fh = favicon.fingerprint(ICON)
    assert art.fields["mmh3"] == str(fh.mmh3) and art.fields["image_type"] == "ico"


def test_a_task_of_another_series_is_never_used(tmp_path):
    mine, other = make_cert(1111), make_cert(2222)
    workspace(tmp_path, 9166, "Onion Deanon 1: Read the Certificate", BRIEF_1, {"evidence/leaf-cert.pem": pem(mine)})
    workspace(tmp_path, 9175, "Onion Deanon 2: Read the Certificate", BRIEF_1, {"evidence/leaf-cert.pem": pem(other)})
    workspace(tmp_path, 9180, "Cloudflare Deanon: Read", BRIEF_1, {"evidence/cert.der": der(other)})
    target = workspace(tmp_path, 9167, "Onion Deanon 1: Fingerprint the Certificate", BRIEF_FP)
    rep = series.chain(target, profile=profile())
    assert [s["id"] for s in rep.siblings] == ["9166"]
    assert rep.flags == ["CSCTF{" + colon_upper(mine.fingerprint(hashes.SHA256())) + "}"]


def test_first_task_evidence_ranks_before_a_later_siblings(tmp_path):
    first, later = make_cert(1), make_cert(2)
    workspace(tmp_path, 9169, "Lab Q: Find the Back Office", BRIEF_FP.replace("Fingerprint", "Find"),
              {"evidence/origin-cert.pem": pem(later)})
    workspace(tmp_path, 9166, "Lab Q: Read the Certificate", BRIEF_1, {"evidence/leaf-cert.pem": pem(first)})
    target = workspace(tmp_path, 9167, "Lab Q: Fingerprint the Certificate", BRIEF_FP)
    rep = series.chain(target, profile=profile())
    assert [s["id"] for s in rep.siblings] == ["9166", "9169"]       # the briefing task first
    assert rep.flags[0] == "CSCTF{" + colon_upper(first.fingerprint(hashes.SHA256())) + "}"
    assert len(rep.flags) == 2


def test_a_der_file_and_the_leaf_of_a_chain_are_read(tmp_path):
    leaf, ca = make_cert(77), make_cert(78, cn="ca")
    workspace(tmp_path, 1, "Lab Z: One", BRIEF_1, {"recon/engines/x/leaf.crt": der(leaf),
                                                   "files/chain.pem": pem(leaf) + pem(ca)})
    target = workspace(tmp_path, 2, "Lab Z: Serial Again", BRIEF_FP.replace(
        "Get the certificate's SHA-256 fingerprint", "Get the certificate serial").replace(
        "the SHA-256 fingerprint, uppercase hexadecimal with colons (e.g. `AA:BB:...`)", "the serial in decimal"))
    rep = series.chain(target, profile=profile())
    assert rep.flags == ["CSCTF{77}"]                      # the same leaf twice is one artifact, the CA never
    assert len([a for a in rep.artifacts if a.kind == "certificate"]) == 1


def test_a_saved_error_page_named_favicon_is_rejected_not_hashed(tmp_path):
    page = b"<!DOCTYPE html><html><body>404 Not Found</body></html>"
    workspace(tmp_path, 9170, "Onion Deanon 2: Read the Favicon", BRIEF_1, {"evidence/favicon.ico": page})
    target = workspace(tmp_path, 9171, "Onion Deanon 2: Hash the Favicon Again", BRIEF_MD5)
    rep = series.chain(target, profile=profile())
    assert rep.status == "no-evidence" and rep.candidates == []
    assert hashlib.md5(page).hexdigest() not in json.dumps(rep.to_dict())
    assert rep.rejected and "HTML page" in rep.rejected[0].reason
    assert "favicon" in rep.reason and "9170-onion-deanon-2-read-the-favicon" in rep.reason


def test_links_and_secret_folders_in_a_sibling_are_never_read(tmp_path):
    outside, secret = make_cert(5), make_cert(6)
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "elsewhere" / "leaf.pem").write_bytes(pem(outside))
    root = tmp_path / "wd"
    root.mkdir()
    sib = workspace(root, 9166, "Onion Deanon 1: Read the Certificate", BRIEF_1, {".ctf/leaf.pem": pem(secret)})
    (sib / "evidence").mkdir()
    os.symlink(tmp_path / "elsewhere" / "leaf.pem", sib / "evidence" / "leaf-cert.pem")
    os.symlink(tmp_path / "elsewhere", sib / "recon")
    target = workspace(root, 9167, "Onion Deanon 1: Fingerprint the Certificate", BRIEF_FP)
    rep = series.chain(target, profile=profile())
    assert rep.status == "no-evidence" and rep.artifacts == []
    blob = json.dumps(rep.to_dict())
    for c in (outside, secret):
        assert c.fingerprint(hashes.SHA256()).hex() not in blob.lower().replace(":", "")


def test_a_symlinked_sibling_folder_is_neither_a_sibling_nor_a_source(tmp_path):
    # The workdir holds `<id>-<slug>` as a link to a folder outside it that looks like a sibling.
    cert = make_cert(0x5150)
    outside = workspace(tmp_path / "outside", 9166, "Onion Deanon 1: Read the Certificate", BRIEF_1,
                        {"evidence/leaf-cert.pem": pem(cert)})
    root = tmp_path / "wd"
    root.mkdir()
    os.symlink(outside, root / outside.name)
    target = workspace(root, 9167, "Onion Deanon 1: Fingerprint the Certificate", BRIEF_FP)
    assert [t.cid for t in series.workspace_tasks(root)[0]] == ["9167"]
    rep = series.chain(target, profile=profile())
    assert rep.status == "no-sibling" and rep.siblings == [] and rep.candidates == []
    assert cert.fingerprint(hashes.SHA256()).hex() not in json.dumps(rep.to_dict()).lower().replace(":", "")


def test_a_linked_challenge_json_is_not_followed(tmp_path):
    cert = make_cert(0x5151)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "challenge.json").write_text(json.dumps(
        {"id": 9166, "name": "Onion Deanon 1: Read the Certificate", "description": BRIEF_1}))
    root = tmp_path / "wd"
    sib = root / "9166-onion-deanon-1-read-the-certificate"
    (sib / "evidence").mkdir(parents=True)
    (sib / "evidence" / "leaf-cert.pem").write_bytes(pem(cert))
    os.symlink(elsewhere / "challenge.json", sib / "challenge.json")
    with pytest.raises(series.SeriesError, match="challenge.json"):
        series.load_task(sib)
    target = workspace(root, 9167, "Onion Deanon 1: Fingerprint the Certificate", BRIEF_FP)
    rep = series.chain(target, profile=profile())
    assert rep.siblings == [] and rep.candidates == [] and rep.status == "no-sibling"
    assert any("workdir folder not read" in n and sib.name in n for n in rep.notes)    # named, not dropped


def test_an_html_page_holding_an_svg_saved_as_favicon_is_rejected_and_a_real_svg_is_read(tmp_path):
    page = b"<html><head><title>x</title></head><body><svg xmlns='http://www.w3.org/2000/svg'></svg></body></html>"
    assert series.icon_type(page) is None
    workspace(tmp_path, 9170, "Onion Deanon 2: Read the Favicon", BRIEF_1, {"evidence/favicon.ico": page})
    target = workspace(tmp_path, 9171, "Onion Deanon 2: Hash the Favicon Again", BRIEF_MD5)
    rep = series.chain(target, profile=profile())
    assert rep.status == "no-evidence" and rep.candidates == []
    assert rep.rejected and "HTML page" in rep.rejected[0].reason
    # Positive control: a real SVG icon is read and hashed.
    svg = b"<?xml version='1.0'?>\n<svg xmlns='http://www.w3.org/2000/svg' width='16' height='16'/>\n"
    ok = tmp_path / "ok"
    workspace(ok, 9170, "Onion Deanon 2: Read the Favicon", BRIEF_1, {"evidence/favicon.svg": svg})
    t2 = workspace(ok, 9171, "Onion Deanon 2: Hash the Favicon Again", BRIEF_MD5)
    r2 = series.chain(t2, profile=profile())
    assert r2.flags[0] == f"CSCTF{{{hashlib.md5(svg).hexdigest()}}}"
    assert r2.artifacts[0].fields["image_type"] == "svg"


def test_an_empty_favicon_is_rejected_with_the_reason(tmp_path):
    workspace(tmp_path, 9170, "Onion Deanon 2: Read the Favicon", BRIEF_1, {"evidence/favicon.ico": b""})
    target = workspace(tmp_path, 9171, "Onion Deanon 2: Hash the Favicon Again", BRIEF_MD5)
    rep = series.chain(target, profile=profile())
    assert rep.status == "no-evidence" and rep.candidates == []
    assert [(r.path, r.reason) for r in rep.rejected] == [
        ("9170-onion-deanon-2-read-the-favicon/evidence/favicon.ico", "empty file: not a favicon")]
    assert "empty file" in rep.reason


def test_a_certificate_saved_below_the_depth_cap_is_not_read(tmp_path):
    cert = make_cert(0x7777)
    deep = "/".join(f"d{i}" for i in range(series.MAX_DEPTH + 1))        # one folder too deep
    edge = "/".join(f"d{i}" for i in range(series.MAX_DEPTH))            # the deepest folder walked
    workspace(tmp_path / "a", 1, "Lab D: One", BRIEF_1, {f"{deep}/leaf.pem": pem(cert)})
    t1 = workspace(tmp_path / "a", 2, "Lab D: Fingerprint the Certificate", BRIEF_FP)
    assert series.chain(t1, profile=profile()).status == "no-evidence"
    workspace(tmp_path / "b", 1, "Lab D: One", BRIEF_1, {f"{edge}/leaf.pem": pem(cert)})
    t2 = workspace(tmp_path / "b", 2, "Lab D: Fingerprint the Certificate", BRIEF_FP)
    assert series.chain(t2, profile=profile()).flags == ["CSCTF{" + colon_upper(cert.fingerprint(hashes.SHA256())) + "}"]


def _unknown_key_cert_der(serial: int) -> bytes:
    # A synthetic certificate whose public-key algorithm OID is one `cryptography` does not know
    # (id-ecPublicKey 1.2.840.10045.2.1 rewritten to .2.9): it parses, but public_key() fails.
    d = der(make_cert(serial))
    ec_oid = bytes.fromhex("06072a8648ce3d0201")
    assert d.count(ec_oid) == 1
    return d.replace(ec_oid, bytes.fromhex("06072a8648ce3d0209"))


def test_an_spki_pin_that_cannot_be_computed_is_named_not_reported_missing(tmp_path):
    d = _unknown_key_cert_der(0x4242)
    workspace(tmp_path, 1, "Lab S: One", BRIEF_1, {"evidence/leaf.der": d})
    target = workspace(tmp_path, 2, "Lab S: Pin the Key", "*Continuation of the same lab.* Give the SPKI pin. "
                                                         "Flag format: `CSCTF{<answer>}`")
    rep = series.chain(target, profile=profile())
    assert rep.status == "no-evidence" and rep.candidates == []
    assert "SPKI pin not computed" in rep.reason and "1-lab-s-one/evidence/leaf.der" in rep.reason
    assert "no sibling" not in rep.reason
    assert any("SPKI pin not computed" in n for n in rep.notes)
    # The other fields of the same certificate still stand.
    assert rep.artifacts[0].fields["sha256"] == hashlib.sha256(d).hexdigest()


def test_a_missing_cryptography_package_is_named_not_reported_as_a_bad_certificate(tmp_path, monkeypatch):
    workspace(tmp_path, 1, "Lab C: One", BRIEF_1, {"evidence/leaf-cert.pem": pem(make_cert(3))})
    target = workspace(tmp_path, 2, "Lab C: Fingerprint the Certificate", BRIEF_FP)
    monkeypatch.setitem(sys.modules, "cryptography", None)        # `import cryptography` now fails
    assert "not installed" in series.cryptography_missing()
    rep = series.chain(target, profile=profile())
    assert rep.status == "no-evidence"
    assert [r.reason for r in rep.rejected] == [f"a certificate, not read: {series.cryptography_missing()}"]
    assert "did not parse" not in rep.reason and "`cryptography` package is not installed" in rep.reason
    monkeypatch.undo()
    assert series.cryptography_missing() is None


def test_a_continuation_with_no_sibling_says_what_is_missing(tmp_path):
    target = workspace(tmp_path, 9167, "Onion Deanon 1: Fingerprint the Certificate", BRIEF_FP)
    rep = series.chain(target, profile=profile())
    assert rep.status == "no-sibling"
    assert "'onion deanon 1'" in rep.reason and "continuation of the same lab" in rep.reason
    assert rep.candidates == []


def test_a_continuation_whose_name_has_no_series_part_is_named(tmp_path):
    target = workspace(tmp_path, 5, "Fingerprint", BRIEF_FP)
    rep = series.chain(target)
    assert rep.status == "no-sibling" and "no series part" in rep.reason


def test_a_task_outside_any_series_is_unlinked(tmp_path):
    workspace(tmp_path, 1, "Lonely", BRIEF_1, {"evidence/leaf-cert.pem": pem(make_cert(3))})
    target = workspace(tmp_path, 2, "Another One", "Get the certificate's SHA-256 fingerprint.")
    rep = series.chain(target)
    assert rep.status == "unlinked" and rep.candidates == []


def test_unmapped_wording_lists_what_the_siblings_hold(tmp_path):
    workspace(tmp_path, 1, "Lab Y: One", BRIEF_1, {"evidence/leaf-cert.pem": pem(make_cert(3))})
    target = workspace(tmp_path, 2, "Lab Y: Two", "*Continuation of the same lab.* Find the admin's email.")
    rep = series.chain(target)
    assert rep.status == "unmapped" and "certificate" in rep.reason


def test_the_event_format_wraps_when_the_brief_states_none(tmp_path):
    cert = make_cert(9)
    workspace(tmp_path, 1, "Lab X: One", BRIEF_1, {"evidence/leaf-cert.pem": pem(cert)})
    brief = BRIEF_FP.replace("Flag format: `CSCTF{<answer>}`", "")
    target = workspace(tmp_path, 2, "Lab X: Fingerprint the Certificate", brief)
    fp = colon_upper(cert.fingerprint(hashes.SHA256()))
    assert series.chain(target, profile=profile(["PINK"])).flags == [f"PINK{{{fp}}}"]
    bare = series.chain(target, profile=profile([]))
    assert bare.status == "unsure-format" and bare.flags == []
    assert [c.answer for c in bare.candidates] == [fp]
    assert "no flag format" in bare.reason


def test_a_brief_prefix_the_event_rejects_gives_no_flag(tmp_path):
    workspace(tmp_path, 1, "Lab X: One", BRIEF_1, {"evidence/leaf-cert.pem": pem(make_cert(9))})
    target = workspace(tmp_path, 2, "Lab X: Fingerprint the Certificate",
                       BRIEF_FP.replace("CSCTF{", "OTHER{"))
    rep = series.chain(target, profile=profile(["CSCTF"]))
    assert rep.flags == [] and rep.status == "unsure-format"
    assert any("not a well-formed flag" in n for n in rep.notes)


def test_a_pem_block_pasted_into_a_text_file_is_found(tmp_path):
    # e.g. `openssl s_client -showcerts` output saved as a log: the file name says nothing about certs.
    cert = make_cert(31337)
    log = b"CONNECTED(00000003)\n---\nServer certificate\n" + pem(cert) + b"subject=CN = lab\n"
    workspace(tmp_path, 1, "Lab X: One", BRIEF_1, {"evidence/s_client.log": log})
    target = workspace(tmp_path, 2, "Lab X: Fingerprint the Certificate", BRIEF_FP)
    rep = series.chain(target, profile=profile())
    assert rep.flags == ["CSCTF{" + colon_upper(cert.fingerprint(hashes.SHA256())) + "}"]
    assert rep.candidates[0].source == "1-lab-x-one/evidence/s_client.log"


def test_index_groups_every_series_first_task_first(tmp_path):
    workspace(tmp_path, 12, "Lab A: Two", BRIEF_FP)
    workspace(tmp_path, 11, "Lab A: One", BRIEF_1)
    workspace(tmp_path, 20, "Lab B: One", BRIEF_1)
    workspace(tmp_path, 30, "Solo", BRIEF_1)
    (tmp_path / "hypotheses").mkdir()
    g = series.index(tmp_path)
    assert list(g) == ["lab a"]
    assert [t.cid for t in g["lab a"]] == ["11", "12"]


def test_a_folder_without_challenge_json_is_an_error(tmp_path):
    with pytest.raises(series.SeriesError, match="challenge.json"):
        series.chain(tmp_path / "nothing")


# ---------------------------------------------------------------- outputs and the ledger

def test_reuse_is_recorded_in_the_hypothesis_ledger_once(tmp_path):
    cert = make_cert(42)
    workspace(tmp_path, 9166, "Onion Deanon 1: Read the Certificate", BRIEF_1, {"evidence/leaf-cert.pem": pem(cert)})
    target = workspace(tmp_path, 9167, "Onion Deanon 1: Fingerprint the Certificate", BRIEF_FP)
    prof = profile()
    rep = series.chain(target, profile=prof)
    written = series.record_reuse(rep, profile=prof)
    assert len(written) == 1
    recs = hypothesis.entries("9167", workdir=tmp_path)
    assert len(recs) == 1
    r = recs[0]
    assert r["method"] == "series-chain certificate.sha256 from 9166-onion-deanon-1-read-the-certificate"
    assert r["payload"] == rep.flags[0] and r["result"] == hypothesis.POSITIVE and r["verified"] is True
    assert "9166-onion-deanon-1-read-the-certificate/evidence/leaf-cert.pem" in r["evidence"]
    assert hashlib.sha256(pem(cert)).hexdigest() in r["evidence"]
    assert "not submitted" in r["evidence"] and r["agent"] == "series-chain"
    assert series.record_reuse(series.chain(target, profile=prof), profile=prof) == []    # re-run: nothing new
    assert len(hypothesis.entries("9167", workdir=tmp_path)) == 1


def test_a_guessed_form_is_recorded_inconclusive_and_does_not_settle_the_method(tmp_path):
    # The MD5 brief states no case: two forms remain, so the first is a guess, not a solve.
    workspace(tmp_path, 9170, "Onion Deanon 2: Read the Favicon", BRIEF_1, {"evidence/favicon.bin": ICON})
    target = workspace(tmp_path, 9171, "Onion Deanon 2: Hash the Favicon Again", BRIEF_MD5)
    prof = profile()
    rep = series.chain(target, profile=prof)
    assert len(rep.flags) == 2
    [r] = series.record_reuse(rep, profile=prof)
    assert r["result"] == hypothesis.INCONCLUSIVE and r["payload"] == rep.flags[0]
    assert rep.flags[1] in r["evidence"] and "not settled" in r["evidence"]
    assert hypothesis.should_skip("9171", r["method"], workdir=tmp_path).skip is False


def test_a_stated_form_flag_is_a_verified_positive_that_settles_the_method(tmp_path):
    workspace(tmp_path, 9166, "Onion Deanon 1: Read the Certificate", BRIEF_1,
              {"evidence/leaf-cert.pem": pem(make_cert(43))})
    target = workspace(tmp_path, 9167, "Onion Deanon 1: Fingerprint the Certificate", BRIEF_FP)
    prof = profile()
    [r] = series.record_reuse(series.chain(target, profile=prof), profile=prof)
    assert r["result"] == hypothesis.POSITIVE and r["verified"] is True
    assert hypothesis.should_skip("9167", r["method"], workdir=tmp_path).skip is True


def test_nothing_is_recorded_without_a_candidate(tmp_path):
    target = workspace(tmp_path, 9167, "Onion Deanon 1: Fingerprint the Certificate", BRIEF_FP)
    assert series.record_reuse(series.chain(target)) == []
    assert not (tmp_path / "hypotheses").exists()


def test_answers_without_a_format_are_recorded_inconclusive(tmp_path):
    workspace(tmp_path, 1, "Lab X: One", BRIEF_1, {"evidence/leaf-cert.pem": pem(make_cert(9))})
    target = workspace(tmp_path, 2, "Lab X: Fingerprint the Certificate",
                       BRIEF_FP.replace("Flag format: `CSCTF{<answer>}`", ""))
    rep = series.chain(target, profile=profile([]))
    [r] = series.record_reuse(rep, profile=profile([]))
    assert r["result"] == hypothesis.INCONCLUSIVE and r["payload"] == rep.candidates[0].answer


# ---------------------------------------------------------------- the engine

def test_engine_returns_candidates_writes_the_report_and_records(tmp_path):
    workspace(tmp_path, 9170, "Onion Deanon 2: Read the Favicon", BRIEF_1, {"evidence/favicon.bin": ICON})
    target = workspace(tmp_path, 9171, "Onion Deanon 2: Hash the Favicon Again", BRIEF_MD5)
    res = series_chain.solve(target, profile())
    md5 = hashlib.md5(ICON).hexdigest()
    assert res.status == "candidate"                         # never "solved": nothing is submitted
    assert res.flags[0] == f"CSCTF{{{md5}}}"
    assert res.evidence[0].path == "9170-onion-deanon-2-read-the-favicon/evidence/favicon.bin"
    doc = json.loads((target / "recon" / "series.json").read_text())
    assert doc["status"] == "candidate" and doc["submitted"] is False and doc["flags"][0] == res.flags[0]
    assert f"CSCTF{{{md5}}}" in (target / "recon" / "series.md").read_text()
    assert hypothesis.entries("9171", workdir=tmp_path)[0]["payload"] == res.flags[0]


def test_engine_report_of_its_own_is_not_reused_as_evidence(tmp_path):
    # A sibling's own recon/series.json quotes hashes; it must never become a source.
    workspace(tmp_path, 1, "Lab X: One", BRIEF_1,
              {"recon/series.json": pem(make_cert(9)), "recon/series.md": pem(make_cert(10))})
    target = workspace(tmp_path, 2, "Lab X: Fingerprint the Certificate", BRIEF_FP)
    assert series.chain(target, profile=profile()).status == "no-evidence"


def test_engine_is_unsure_with_no_sibling_and_none_outside_a_series(tmp_path):
    t1 = workspace(tmp_path, 9167, "Onion Deanon 1: Fingerprint the Certificate", BRIEF_FP)
    r1 = series_chain.solve(t1, profile(), ledger="false")
    assert r1.status == "unsure" and "no-sibling" in r1.notes and r1.flags == ()
    t2 = workspace(tmp_path, 5, "Solo", "Find the thing.")
    assert series_chain.solve(t2, profile()).status == "none"
    assert series_chain.solve(tmp_path / "missing", profile()).status == "blocked"


def test_manifest_routes_continuation_briefs_to_the_engine_at_intake():
    from ctf.engines import manifest, router
    m = {x.id: x for x in manifest.discover(REPO)}["toolkits.series_chain"]
    assert m.intake.select == "route" and m.intake.run == "challenge" and m.cost_class == "cheap"
    ids = [h.manifest.id for h in router.route("osint", series.plain_text(BRIEF_FP))]
    assert "toolkits.series_chain" in ids
    assert "toolkits.series_chain" in [h.manifest.id for h in router.route("forensics", BRIEF_MD5.lower())]
    assert "toolkits.series_chain" not in [h.manifest.id for h in router.route("osint", "find the gps location")]


class _Adapter:
    kind = "fake"

    def __init__(self, ch):
        self.ch = ch

    def get_challenge(self, cid):
        return self.ch

    def list_challenges(self):
        return [self.ch]

    def download_files(self, cid, dest):
        return []

    def submit(self, cid, flag):
        raise AssertionError("intake never submits")

    def team_solves(self):
        return []


def test_intake_of_a_follow_up_reuses_the_sibling_with_no_model(tmp_path):
    from ctf import intake as I
    from ctf.platform.base import Challenge
    prof = event.load("csctf")
    wd = tmp_path / "wd"
    cert = make_cert(0xABCDEF)
    workspace(wd, 9166, "Onion Deanon 1: Read the Certificate", BRIEF_1, {"evidence/leaf-cert.pem": pem(cert)})
    ch = Challenge(id="9167", name="Onion Deanon 1: Fingerprint the Certificate", category="osint",
                   points=120, description=BRIEF_FP, files=())
    rep = I.intake_one("9167", prof, adapter=_Adapter(ch), workdir=wd,
                       options=I.Options(net_guard="hook", record=False))
    runs = [r for r in rep.runs if r.engine == "toolkits.series_chain"]
    want = "CSCTF{" + colon_upper(cert.fingerprint(hashes.SHA256())) + "}"
    assert runs and runs[0].status == "ok" and runs[0].result_status == "candidate", runs
    assert runs[0].flags == (want,)
    # Intake lists it in recon/flags.txt (found, never submitted: the adapter's submit raises).
    assert want in (rep.dir / "recon" / "flags.txt").read_text()
    # Intake's roll-up keeps it a candidate (the engine's own status), so the capped auto-submit
    # (`ctf intake --submit`, which takes `solved` only) never sends it.
    from ctf.intake import autosubmit
    assert rep.status == "candidate" and rep.result.flags == (want,)
    assert json.loads((rep.dir / "recon" / "intake.json").read_text())["status"] == "candidate"
    assert autosubmit.eligible(rep.status, rep.result.flags, prof)[0] is None
    assert json.loads((rep.dir / "recon" / "series.json").read_text())["flags"] == [want]
    assert hypothesis.entries("9167", workdir=wd)[0]["payload"] == want
