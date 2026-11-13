"""B-220: metadata_forensics.msi_identity, the MSI / MSIX identity engine (solvers/metadata-forensics/msi_identity.py).

It reads the Property table and summary of every Windows Installer database (and the Identity of every
MSIX/AppX package) in a challenge's handout through the Metadata lane's reader pack (readers_msi.py), and
gives each identity fact with its answer forms, a GUID read as text in its STORED form first (Day 13:
`{DD1A80D5-...}` uppercase in braces, the form the judge took). Every installer here is built byte by byte
by tests/msi_build.py; expected values are the ones it was built with.
"""
import importlib.util
import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

from ctf import event
from ctf.engines import manifest as _manifest
from ctf.engines import router
from ctf.intake import engines as E
from ctf.intake import guard as G
from ctf.result import SolverResult

from msi_build import MANIFEST, PRODUCT, PROPERTIES, UPGRADE, bundle_of, cfb, installer, package

import msi_identity as MI

REPO = Path(__file__).resolve().parents[1]
CSCTF = event.load("csctf")
HUNTRESS = event.load("huntress")


@pytest.fixture(autouse=True)
def _workdir(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))


def _challenge(tmp_path, files):
    ch = tmp_path / "challenge"
    (ch / "files").mkdir(parents=True)
    for name, body in files.items():
        p = ch / "files" / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body)
    return ch


def _details(r):
    return [e.detail for e in r.evidence]


def _fact(r, prop):
    """The evidence line of one identity fact: (value given first, its form name, the other values)."""
    hits = [d for d in _details(r) if f": {prop} = " in d]
    assert len(hits) == 1, (prop, _details(r))
    value, _, rest = hits[0].split(f": {prop} = ", 1)[1].partition("  [")
    form, _, more = rest.rstrip("]").partition("; also ")
    return value, form, more.split(", ") if more else []


# ------------------------------------------------------------------ the result

def test_an_installer_gives_its_identity_with_the_stored_guid_first(tmp_path):
    r = MI.solve(_challenge(tmp_path, {"installer-001.msi": installer()}), HUNTRESS)
    assert r.status == "unsure" and not r.flags, r
    value, form, more = _fact(r, "msi.product_code_guid")
    assert (value, form) == (PRODUCT, "braces_upper")
    assert len(more) == 5 and PRODUCT[1:-1].lower() in more and PRODUCT not in more
    value, form, more = _fact(r, "msi.upgrade_code_guid")
    assert (value, form) == (UPGRADE, "braces_upper")
    assert UPGRADE[1:-1].lower() in more and UPGRADE.lower() in more        # the other spellings follow
    assert _fact(r, "msi.product_version")[0] == "2.7.1"
    assert _fact(r, "msi.manufacturer")[0] == "Scratch Labs"
    assert _fact(r, "msi.product_name")[0] == "Scratch Product"
    assert _fact(r, "msi.product_language")[0] == "1033"
    assert all(e.path == "files/installer-001.msi" and e.kind == "msi-identity" for e in r.evidence)
    SolverResult.from_json(r.to_json())                                       # a valid result, round trip


@pytest.mark.parametrize("stored, form", [(PRODUCT.lower(), "braces_lower"), (PRODUCT[1:-1], "hyphen_upper"),
                                          (PRODUCT[1:-1].replace("-", "").lower(), "compact_lower")])
def test_a_guid_stored_in_another_form_is_given_as_stored_first(tmp_path, stored, form):
    r = MI.solve(_challenge(tmp_path, {"setup.msi": installer(product=stored)}), HUNTRESS)
    value, got_form, more = _fact(r, "msi.product_code_guid")
    assert (value, got_form) == (stored, form)
    assert PRODUCT in more                                                   # the judged form is still offered


def test_an_installer_inside_a_zip_is_read_one_level_down(tmp_path):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("installer-002.msi", installer())
        z.writestr("readme.txt", "nothing here")
    r = MI.solve(_challenge(tmp_path, {"evidence.zip": out.getvalue()}), HUNTRESS)
    assert r.status == "unsure"
    hit = [d for d in _details(r) if "msi.product_code_guid" in d]
    assert hit and hit[0].startswith("files/evidence.zip -> installer-002.msi: "), hit


def test_an_msix_package_gives_its_identity(tmp_path):
    r = MI.solve(_challenge(tmp_path, {"notes-001.msix": package()}), HUNTRESS)
    assert r.status == "unsure"
    assert _fact(r, "msix.identity_name")[0] == "Scratch.Notes"
    assert _fact(r, "msix.identity_version")[0] == "3.2.1.0"
    assert _fact(r, "msix.processor_architecture")[0] == "x64"
    assert all(e.kind == "msix-identity" for e in r.evidence)


def test_a_flag_in_a_property_row_is_a_candidate(tmp_path):
    rows = PROPERTIES + [("ARPCOMMENTS", "see CSCTF{msi_property_rows_are_data}")]
    r = MI.solve(_challenge(tmp_path, {"installer-001.msi": installer(properties=rows)}), CSCTF)
    assert r.status == "candidate" and r.flags == ("CSCTF{msi_property_rows_are_data}",), r
    assert any(e.kind == "match" for e in r.evidence)


def test_no_installer_is_none_and_recon_is_not_read(tmp_path):
    ch = _challenge(tmp_path, {"notes.txt": b"just text", "picture.png": b"\x89PNG\r\n\x1a\n" + b"\x00" * 40})
    (ch / "recon").mkdir()
    (ch / "recon" / "copy.msi").write_bytes(installer())      # an engine's own output folder is not the handout
    r = MI.solve(ch, HUNTRESS)
    assert r.status == "none" and not r.evidence, r


def test_a_compound_file_that_is_no_installer_is_not_read_as_one(tmp_path):
    r = MI.solve(_challenge(tmp_path, {"report.doc": cfb([("WordDocument", b"x" * 600)], clsid=b"\x00" * 16)}), HUNTRESS)
    assert r.status == "none", r


def test_a_fact_the_bytes_do_not_settle_is_named_never_guessed(tmp_path):
    r = MI.solve(_challenge(tmp_path, {"installer-001.msi": installer(damage="two-rows")}), HUNTRESS)
    assert not [d for d in _details(r) if "msi.product_code_guid" in d], _details(r)
    assert "msi.product_code_guid not established" in r.notes, r.notes


def test_without_olefile_an_installer_is_blocked_by_name(tmp_path, monkeypatch):
    real = importlib.util.find_spec
    monkeypatch.setattr(MI.importlib.util, "find_spec", lambda name, *a: None if name == "olefile" else real(name, *a))
    r = MI.solve(_challenge(tmp_path, {"installer-001.msi": installer()}), HUNTRESS)
    assert r.status == "blocked" and "olefile" in r.notes and not r.flags, r
    # an MSIX package needs no olefile
    assert MI.solve(_challenge(tmp_path / "x", {"n.msix": package()}), HUNTRESS).status == "unsure"


def test_the_cli_prints_the_facts(tmp_path, capsys):
    f = tmp_path / "installer-001.msi"
    f.write_bytes(installer())
    other = tmp_path / "notes.txt"
    other.write_text("plain")
    assert MI.main([str(f), str(other)]) == 0
    out = capsys.readouterr().out
    assert f"msi.product_code_guid = {PRODUCT}  [braces_upper; also " in out
    assert "notes.txt: neither a Windows Installer database nor an MSIX/AppX package" in out
    assert MI.main(["--help"]) == 2


def test_a_flag_in_an_msix_identity_is_a_candidate(tmp_path):
    flag = "CSCTF{msix_identity_is_data}"
    m = MANIFEST.replace('<Identity Name="Scratch.Notes"', f'<Identity Name="{flag}"')
    assert m != MANIFEST
    r = MI.solve(_challenge(tmp_path, {"notes-001.msix": package(manifests=(m,))}), CSCTF)
    assert r.status == "candidate" and r.flags == (flag,), r
    assert [e.detail for e in r.evidence if e.kind == "match"] == [
        "files/notes-001.msix: flag-format text in an identity field or Property value"]


def test_a_flag_read_twice_is_given_once(tmp_path):
    """ProductName is both an identity fact and a Property row: the flag is one flag, one match line."""
    flag = "CSCTF{one_flag_two_readings}"
    rows = [(n, flag if n == "ProductName" else v) for n, v in PROPERTIES]
    r = MI.solve(_challenge(tmp_path, {"installer-001.msi": installer(properties=rows)}), CSCTF)
    assert _fact(r, "msi.product_name")[0] == flag
    assert r.status == "candidate" and r.flags == (flag,), r
    assert len([e for e in r.evidence if e.kind == "match"]) == 1, _details(r)


def test_a_bundle_is_read_once_not_also_unpacked_as_a_zip(tmp_path):
    r = MI.solve(_challenge(tmp_path, {"b.msixbundle": bundle_of({"x64.appx": package()})}), HUNTRESS)
    assert r.status == "unsure", r
    assert _fact(r, "msix.identity_version")[0] == "2026.1013.1.0"            # the bundle's own Identity
    labels = {d.split(": ", 1)[0] for d in _details(r)}
    assert labels == {"files/b.msixbundle"}, _details(r)                    # no "b.msixbundle -> x64.appx" line


@pytest.mark.parametrize("cut", ["third", "600", "header"])
def test_a_cut_installer_is_named_never_dropped(tmp_path, cut):
    """A truncated installer keeps the compound-file magic and its .msi name: intake chose it, so the
    engine says it could not read it and why, never "no installer in the handout"."""
    whole = installer()
    data = {"third": whole[: len(whole) // 3], "600": whole[:600], "header": whole[:8]}[cut]
    r = MI.solve(_challenge(tmp_path, {"installer-001.msi": data}), HUNTRESS)
    assert r.status == "unsure" and not r.flags, r
    assert [e.kind for e in r.evidence] == ["unreadable"], r
    assert r.evidence[0].detail.startswith("files/installer-001.msi: compound file not readable ("), r.evidence
    assert "files/installer-001.msi: not read as an installer or package (compound file not readable (" in r.notes
    assert "no Windows Installer database" not in r.notes


def test_a_cut_installer_beside_a_good_one_is_still_named(tmp_path):
    whole = installer()
    r = MI.solve(_challenge(tmp_path, {"a.msi": whole, "b.msi": whole[:600]}), HUNTRESS)
    assert r.status == "unsure"
    assert _fact(r, "msi.product_code_guid")[0] == PRODUCT
    assert "files/b.msi: not read as an installer or package (compound file not readable (" in r.notes, r.notes


def _plain_zip():
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("readme.txt", "no manifest")
    return out.getvalue()


@pytest.mark.parametrize("name, body, why", [
    ("setup.msi", lambda: b"this is not an installer at all", "named as an installer or package, but neither"),
    ("app.msix", _plain_zip, "a zip, but no readable AppxManifest.xml"),
    ("setup.msi", lambda: cfb([("WordDocument", b"x" * 600)], clsid=b"\x00" * 16),
     "a compound file, but no Windows Installer tables in it"),
])
def test_a_file_named_as_an_installer_that_is_none_is_named(tmp_path, name, body, why):
    r = MI.solve(_challenge(tmp_path, {name: body()}), HUNTRESS)
    assert r.status == "unsure" and [e.kind for e in r.evidence] == ["unreadable"], r
    assert why in r.evidence[0].detail and why in r.notes, r


def test_the_cli_says_why_a_cut_installer_was_not_read(tmp_path, capsys):
    f = tmp_path / "installer-001.msi"
    f.write_bytes(installer()[:600])
    assert MI.main([str(f)]) == 0
    assert "that could be read (compound file not readable (" in capsys.readouterr().out


def test_a_symlink_in_the_handout_is_not_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "real.msi").write_bytes(installer())
    ch = _challenge(tmp_path, {"notes.txt": b"plain"})
    (ch / "files" / "link.msi").symlink_to(outside / "real.msi")
    (ch / "files" / "linkdir").symlink_to(outside, target_is_directory=True)
    r = MI.solve(ch, HUNTRESS)
    assert r.status == "none" and not r.evidence, r


def test_a_recon_folder_inside_the_handout_is_read(tmp_path):
    """Only the challenge's own recon/ (the engines' output) is skipped; files/recon/ is handout."""
    r = MI.solve(_challenge(tmp_path, {"recon/setup.msi": installer()}), HUNTRESS)
    assert r.status == "unsure"
    assert _fact(r, "msi.product_code_guid")[0] == PRODUCT


def test_past_max_files_the_rest_is_named_not_read(tmp_path):
    """The first MAX_FILES files (in sorted order) are read, the next is not, and the note says so."""
    n = MI.MAX_FILES
    files = {f"a{i:03d}.txt": b"plain" for i in range(n - 1)}
    files["b-last-read.msix"] = package()
    files["c-over.msi"] = installer()
    r = MI.solve(_challenge(tmp_path, files), HUNTRESS)
    assert r.status == "unsure", r
    assert {d.split(": ", 1)[0] for d in _details(r)} == {"files/b-last-read.msix"}, _details(r)
    assert f"1 more file(s) not read (over MAX_FILES={n})" in r.notes, r.notes


def _zip(members, method=zipfile.ZIP_STORED):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", method) as z:
        for name, body in members.items():
            z.writestr(name, body)
    return out.getvalue()


def _encrypted(data: bytes) -> bytes:
    """The zip `data` with the encryption bit set on every member, in the local and the central headers
    (zipfile writes no encrypted zip; reading such a member without a password raises)."""
    b = bytearray(data)
    for sig, at in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        i = b.find(sig)
        while i != -1:
            b[i + at] |= 1
            i = b.find(sig, i + 4)
    return bytes(b)


def test_an_unreadable_installer_inside_a_zip_is_named_by_its_member_name(tmp_path):
    """A zip member named setup.msi that holds no installer is judged by its own name, not the zip's."""
    r = MI.solve(_challenge(tmp_path, {"x.zip": _zip({"setup.msi": b"plain text, not an installer"})}), HUNTRESS)
    assert r.status == "unsure" and [e.kind for e in r.evidence] == ["unreadable"], r
    assert r.evidence[0].detail == ("files/x.zip -> setup.msi: named as an installer or package, but neither "
                                    "a compound file nor a zip"), r.evidence
    assert r.evidence[0].path == "files/x.zip"


def test_unreadable_installers_in_a_zip_are_each_named(tmp_path):
    whole = installer()
    r = MI.solve(_challenge(tmp_path, {"handout.zip": _zip({"setup.msi": b"plain", "cut.msi": whole[:600]})}), HUNTRESS)
    assert r.status == "unsure", r
    got = sorted(d.split(": ", 1)[0] for d in _details(r))
    assert got == ["files/handout.zip -> cut.msi", "files/handout.zip -> setup.msi"], _details(r)


def test_an_installer_over_max_bytes_is_named_not_dropped(tmp_path, monkeypatch):
    monkeypatch.setattr(MI, "MAX_BYTES", 1000)
    whole = installer()
    assert len(whole) > 1000
    r = MI.solve(_challenge(tmp_path, {"big.msi": whole, "big.bin": b"x" * 2000}), HUNTRESS)
    assert r.status == "unsure" and [e.kind for e in r.evidence] == ["unreadable"], r
    assert r.evidence[0].detail == f"files/big.msi: {len(whole)} bytes, over MAX_BYTES=1000, not read"
    assert "files/big.bin: 2000 bytes, over MAX_BYTES=1000, not read" in r.notes, r.notes
    assert "no Windows Installer database" not in r.notes


def test_a_large_file_that_is_no_installer_is_none_but_named_in_the_notes(tmp_path, monkeypatch):
    monkeypatch.setattr(MI, "MAX_BYTES", 10)
    r = MI.solve(_challenge(tmp_path, {"disk.img": b"y" * 50}), HUNTRESS)
    assert r.status == "none" and not r.evidence, r
    assert "files/disk.img: 50 bytes, over MAX_BYTES=10, not read" in r.notes, r.notes


def test_an_installer_member_over_max_bytes_is_named(tmp_path, monkeypatch):
    whole = installer()
    data = _zip({"setup.msi": whole}, zipfile.ZIP_DEFLATED)
    monkeypatch.setattr(MI, "MAX_BYTES", len(data) + 10)       # the zip is read, its member is too big
    assert len(whole) > MI.MAX_BYTES
    r = MI.solve(_challenge(tmp_path, {"h.zip": data}), HUNTRESS)
    assert r.status == "unsure" and [e.kind for e in r.evidence] == ["unreadable"], r
    assert r.evidence[0].detail == f"files/h.zip -> setup.msi: {len(whole)} bytes, over MAX_BYTES={MI.MAX_BYTES}, not read"


def test_an_encrypted_installer_member_is_named_and_the_others_are_read(tmp_path):
    good = _zip({"a-good.msi": installer()})
    locked = _encrypted(_zip({"b-locked.msi": installer()}))
    r = MI.solve(_challenge(tmp_path, {"good.zip": good, "locked.zip": locked}), HUNTRESS)
    assert r.status == "unsure", r
    assert _fact(r, "msi.product_code_guid")[0] == PRODUCT
    bad = [e.detail for e in r.evidence if e.kind == "unreadable"]
    assert len(bad) == 1 and bad[0].startswith("files/locked.zip -> b-locked.msi: zip member not read (RuntimeError: "), bad
    assert "encrypted" in bad[0]


def test_one_encrypted_member_does_not_hide_the_next(tmp_path):
    """Members are read one by one: an encrypted one is named, and the installer after it is still read."""
    data = bytearray(_zip({"a.msi": b"locked bytes", "b.msi": installer()}))
    data[6] |= 1                                                   # the first local header
    data[data.find(b"PK\x01\x02") + 8] |= 1                        # and its central header
    r = MI.solve(_challenge(tmp_path, {"h.zip": bytes(data)}), HUNTRESS)
    assert _fact(r, "msi.product_code_guid")[0] == PRODUCT
    assert [e.detail.split(": ", 1)[0] for e in r.evidence if e.kind == "unreadable"] == ["files/h.zip -> a.msi"]


def test_a_cut_zip_that_names_an_installer_is_named_never_dropped(tmp_path):
    data = _zip({"readme.txt": b"r" * 300, "setup.msi": installer()})   # the installer is the second member
    cut = data[: len(data) // 2]                                   # no central directory left
    r = MI.solve(_challenge(tmp_path, {"h.zip": cut}), HUNTRESS)
    assert r.status == "unsure" and [e.kind for e in r.evidence] == ["unreadable"], r
    assert r.evidence[0].detail.startswith("files/h.zip -> setup.msi: the zip could not be opened (BadZipFile: "), r.evidence
    assert "no Windows Installer database" not in r.notes


def test_a_broken_zip_with_no_installer_name_is_none_and_named_in_the_notes(tmp_path):
    cut = _zip({"readme.txt": b"r" * 400})[:200]
    r = MI.solve(_challenge(tmp_path, {"h.zip": cut}), HUNTRESS)
    assert r.status == "none" and not r.evidence, r
    assert "files/h.zip: the zip could not be opened (BadZipFile: " in r.notes, r.notes
    assert "no installer or package name in its headers" in r.notes


def test_past_max_members_the_rest_is_named(tmp_path, monkeypatch):
    monkeypatch.setattr(MI, "MAX_MEMBERS", 1)
    r = MI.solve(_challenge(tmp_path, {"h.zip": _zip({"a.msi": installer(), "b.msi": installer()})}), HUNTRESS)
    assert {d.split(": ", 1)[0] for d in _details(r)} == {"files/h.zip -> a.msi"}, _details(r)
    assert "files/h.zip: 1 more installer/package member(s) not read (over MAX_MEMBERS=1)" in r.notes, r.notes


# ------------------------------------------------------------------ manifest, routing and intake

def _mine():
    return [m for m in _manifest.discover() if m.id == MI.ENGINE]


def test_the_manifest_is_a_cheap_contract_engine_that_intake_runs_on_an_installer():
    m = _manifest.load(REPO / "solvers" / "metadata-forensics" / "msi_identity.manifest.toml")
    assert m.id == MI.ENGINE and m.entry.kind == "function" and m.entry.function == "solve"
    assert m.cost_class == "cheap" and m.status == "active" and "py:olefile" in m.needs_tools
    assert m.intake.select == "files" and m.intake.run == "challenge" and not m.intake.spawns
    assert "ext:.msi" in m.intake.match and "ext:.msix" in m.intake.match


def test_the_router_sends_an_installer_handout_here(tmp_path):
    ch = _challenge(tmp_path, {"installer-001.msi": installer()})
    hits = [h.manifest.id for h in router.route("forensics", "", ch / "files")]
    assert MI.ENGINE in hits
    assert MI.ENGINE in [h.manifest.id for h in router.route("misc", "find the ProductCode of the installer")]
    plain = _challenge(tmp_path / "p", {"notes.txt": b"hello"})
    assert MI.ENGINE not in [h.manifest.id for h in router.route("forensics", "", plain / "files")]


def test_intake_plans_it_for_an_installer_and_not_for_other_files(tmp_path):
    hook = G.Guard("hook", (), "test: audit hook only")
    ch = _challenge(tmp_path, {"installer-001.msi": installer()})
    plan = E.plan(_mine(), "forensics", "", ch / "files", guard=hook)
    assert [j.engine for j in plan.jobs] == [MI.ENGINE] and plan.jobs[0].files == ()
    other = _challenge(tmp_path / "o", {"notes.txt": b"hello"})
    assert not E.plan(_mine(), "forensics", "", other / "files", guard=hook).jobs


def test_intake_runs_it_under_the_audit_hook_guard(tmp_path):
    """The real intake run: a child process under the Python audit hook (no network, no program started),
    on an installer whose cabinet is LZX (which only an external tool could unpack; this engine never asks)."""
    hook = G.Guard("hook", (), "test: audit hook only")
    ch = _challenge(tmp_path, {"installer-001.msi": installer(method=3)})     # an LZX cabinet it must not unpack
    plan = E.plan(_mine(), "forensics", "", ch / "files", guard=hook)
    ctx = E.Context(challenge_dir=ch, folder=ch / "files", out_root=ch / "recon" / "engines", profile=HUNTRESS,
                    guard=hook, root=REPO, python=sys.executable, challenge_id="b220", record=False,
                    workdir=tmp_path / "work")
    run = E.run_job(plan.jobs[0], ctx, timeout=60)
    out = (ch / run.output).read_text()
    assert run.status == "ok" and run.result_status == "unsure", (run, (ch / run.errors).read_text()[-800:])
    result = json.loads([ln for ln in out.splitlines() if ln.strip()][-1])
    assert any(f"msi.product_code_guid = {PRODUCT}  [braces_upper" in e["detail"] for e in result["evidence"]), result
