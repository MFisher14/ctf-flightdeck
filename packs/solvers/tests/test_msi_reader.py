"""B-220: the MSI installer-table reader of the Metadata lane (solvers/metadata-forensics/readers_msi.py).

Huntress Day 13 asked msi.product_code_guid (the Value of the Property table's ProductCode row) and the
lane had no reader of MSI tables: Layer 1 stopped on UNKNOWN PROPERTY, an agent wrote a live patch that
decoded _StringPool, _StringData and the Property table, and four GUID spellings were rejected before the
stored one (`braces_upper`) was accepted. These tests hold the shipped reader to that day:

  * the pack is loaded by the lane and registered (msi.*, msix.*), nothing in it confirmed in code;
  * every Property row and the installer tables read back what a synthetic installer was built with
    (2- and 3-byte string ids, codepage 1252, long strings in both published pool layouts);
  * what is not whole is no answer (named NOT ESTABLISHED), never a guess;
  * a GUID read as text offers its stored form first (row 284): plain only under the judged key and only
    where the stored text is the judged form; any other stored form is unsure under a key of its own,
    stored text first, then the judged form;
  * the facts page lists msi.* for an installer with no namespace asked (so a Layer-1 UNKNOWN PROPERTY
    shows the table facts);
  * the embedded cabinet (stored, MSZIP, LZX via 7zz/bsdtar, Quantum via the pack's own decoder) and
    MSIX/AppX identity, as the archived Huntress test held them.

Carried from the archived Huntress test tests/test_day13_metadata_msi.py (see docs/migration/ARCHIVED.md)
as pytest functions; the builders are tests/msi_build.py. The saved Day 13 installers are read only through
ctf.paths.saved_challenges_root() ($CTF_REAL_CHALLENGES); unset, those tests are reported not run.
"""
import contextlib
import hashlib
import io
import json
import os
import random
import re
import struct
import time
import tracemalloc
import zipfile
from pathlib import Path

import pytest

from ctf import paths

import msi_fixtures                                 # loads properties_strict and the pack, loudly
from msi_build import (BUNDLE, COMPONENT, MANIFEST, MS_STORE, MS_WINDOWS, PAYLOAD, PRODUCT, PROPERTIES, UPGRADE,
                       Db, KEY, bundle_of, cabinet, cfb, installer, msi_stream, package, quantum_encode,
                       with_raw_string, with_summary)

import labels

M = msi_fixtures.M
MSI = msi_fixtures.MSI
PACK = msi_fixtures.PACK
LANE = Path(M.__file__).resolve().parent
JUDGED_KEY = "metadata.format/msi.product_code_guid"
GUID = {"kind": "pattern", "syntax": "canonical GUID text in 8-4-4-4-12 hexadecimal form, including hyphens"}
TXT = {"kind": "exact_text", "syntax": "exact ordered artifact-derived text requested by the question"}
FIVE = ["hyphen_lower", "hyphen_upper", "compact_lower", "compact_upper", "braces_upper"]   # the binary order
DAY13 = "day-13/metadata-forensics-day-13-product-placement"
HAVE_7ZZ = MSI._sevenzip() is not None
HAVE_BSDTAR = any(os.access(t, os.X_OK) for t in MSI.BSDTAR)


@pytest.fixture(autouse=True)
def _seed_only(tmp_path, monkeypatch):
    """Each test reads the tracked seed alone: a fresh, empty event workdir (no runtime ledger of a played
    day), and no live day patch (the registry is under test, not a fix)."""
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    monkeypatch.setenv("CTF_JUDGE_LEDGER", "on")
    monkeypatch.setattr(M, "_day_patch", lambda: None)
    yield


# ------------------------------------------------------------------ asking the lane

def ask(prop, data, fmt=None, fname="installer-001.msi", item="d13-msi-001-"):
    """One question in Day 13's wording about one delivered file: (answer, stderr text)."""
    qid = item + prop.replace(".", "-").replace("_", "-")
    q = {"qid": qid, "answer_id": qid, "question": f"Determine {prop} for {fname}.", "artifact": f"evidence.zip -> {fname}",
         "member": fname, "answer_format": fmt or (GUID if prop.endswith("guid") else TXT)}
    files = {f"evidence.zip -> {fname}": data, fname: data, "evidence.zip": b"PK\x05\x06" + b"\x00" * 18}
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        out = M.solve_set([q], files, {"set": 1, "delivery_name": "evidence.zip", "delivery": files["evidence.zip"]})
    return out[qid], err.getvalue()


def options(answer):
    parsed = labels.parse(answer) if isinstance(answer, str) else None
    return [tuple(o) for o in parsed.options] if parsed else []


def key_of(answer):
    parsed = labels.parse(answer) if isinstance(answer, str) else None
    return parsed.key if parsed else None


def plain(answer):
    return answer is not None and labels.parse(answer) is None


def first(answer):
    return options(answer)[0][1] if options(answer) else None


def value(answer):
    """The answer's value: itself when plain, its first option when unsure."""
    return answer if plain(answer) else first(answer)


def no_value(answer):
    return answer is None or [v for _, v in options(answer)] == ["none"]


def unknown(fn):
    try:
        fn()
    except M.Unknown:
        return True
    return False


def pack_names(prefix="msi."):
    return sorted({p.name for p in M.REG.values()
                   if getattr(p.fn, "__module__", "") == "metadata_" + PACK[:-3] and p.name.startswith(prefix)})


# ------------------------------------------------------------------ [1] the pack in the lane

def test_the_pack_is_loaded_and_registered_beside_the_others():
    mine = [p for p in M.REG.values() if getattr(p.fn, "__module__", "") == "metadata_" + PACK[:-3]]
    assert PACK in M.MORE_LOADED and set(M.MORE_LOADED) == set(M.MORE_FILES), M.MORE_LOADED
    assert len(mine) > 300, len(mine)


def test_nothing_in_the_pack_is_confirmed_and_every_reader_is_tie_free():
    mine = [p for p in M.REG.values() if getattr(p.fn, "__module__", "") == "metadata_" + PACK[:-3]]
    assert not [p.name for p in mine if p.confirmed]
    assert all(p.fn in M.TIE_FREE for p in mine)


def test_no_two_readers_of_msi_or_msix_share_their_words():
    by = {}
    for k, p in M.REG.items():
        if k.partition("_")[0] in ("msi", "msix"):
            by.setdefault(M.words(k), {}).setdefault(p.fn, []).append(p.name)
    clash = [sorted(sum(fns.values(), [])) for fns in by.values() if len(fns) > 1]
    assert not clash, clash[:4]


def test_the_judged_name_keeps_the_ledger_key_and_the_seed_holds_braces_upper():
    p = M.lookup("msi.product_code_guid")
    assert p is not None and p.key == JUDGED_KEY and p.fmt == "uuid" and not p.confirmed, p and p.key
    seed = json.loads((LANE / "conventions.json").read_text()).get(JUDGED_KEY, {})
    assert seed.get("accepted") == "braces_upper" and not seed.get("split"), seed
    assert "msix" in M.NAMESPACES and M.NS_ALIAS.get("appx") == "msix"


# ------------------------------------------------------------------ [3] the tables of a built installer

def test_every_reader_reads_the_value_the_installer_was_built_with():
    d = installer()
    props = dict(PROPERTIES)
    md5 = hashlib.md5(PAYLOAD).hexdigest()
    want = {
        "msi.product_code_guid": PRODUCT, "msi.product_code": PRODUCT, "msi.upgrade_code_guid": UPGRADE, "msi.upgrade_code": UPGRADE,
        "msi.product_version": "2.7.1", "msi.product_language": "1033", "msi.product_name": "Scratch Product",
        "msi.manufacturer": "Scratch Labs", "msi.all_users": "1", "msi.allusers": "1", "msi.arp_contact": props["ARPCONTACT"],
        "msi.property_arpcontact": props["ARPCONTACT"], "msi.property_product_version": "2.7.1",
        "msi.property_names": ",".join(n for n, _ in PROPERTIES), "msi.property_count": "8", "msi.property_row_count": "8",
        "msi.component_guid": COMPONENT, "msi.component_id": COMPONENT, "msi.component_names": "MarkerComponent",
        "msi.component_count": "1", "msi.component_directory": "INSTALLFOLDER", "msi.component_attributes": "256",
        "msi.component_key_path": "MarkerFile", "msi.file_names": "evidence.txt", "msi.file_name": "evidence.txt",
        "msi.file_count": "1", "msi.file_file_size": "24", "msi.file_sizes": "24", "msi.file_keys": "File0",
        "msi.file_sequence": "1", "msi.media_disk_id": "1", "msi.media_last_sequence": "1", "msi.cabinet_names": "#artifact.cab",
        "msi.media_cabinet": "#artifact.cab", "msi.feature_names": "Complete", "msi.feature_title": "Scratch Product",
        "msi.feature_level": "1", "msi.feature_attributes": "0", "msi.directory_names": "INSTALLFOLDER,ProgramFiles64Folder,TARGETDIR",
        "msi.directory_count": "3", "msi.file_hash_md5": md5, "msi.msi_file_hash_row_count": "1", "msi.binary_row_count": "0",
        "msi.declared_table_count": "9",
        "msi.component_column_names": "Component,ComponentId,Directory_,Attributes,Condition,KeyPath", "msi.file_column_count": "8",
        "msi.string_pool_codepage": "0", "msi.string_id_width": "2",
        "msi.cabinet_file_names": "File0", "msi.cabinet_file_count": "1", "msi.cabinet_file_sizes": "24", "msi.cabinet_file_size": "24",
        "msi.cabinet_file_md5": md5, "msi.cabinet_file_sha256": hashlib.sha256(PAYLOAD).hexdigest(),
        "msi.cabinet_file_sha1": hashlib.sha1(PAYLOAD).hexdigest(), "msi.cabinet_compression": "mszip",
        "msi.cabinet_sha256": hashlib.sha256(cabinet([("File0", PAYLOAD)])).hexdigest(),
        "msi.cabinet_size_bytes": str(len(cabinet([("File0", PAYLOAD)]))), "msi.has_embedded_cabinet": "true",
        "installer.upgrade_code_guid": UPGRADE, "windows_installer.product_code_guid": PRODUCT,
    }
    got = {n: ask(n, d)[0] for n in want}
    bad = {n: (got[n], v) for n, v in want.items() if value(got[n]) != v}
    assert not bad, bad


def test_the_judged_guid_is_plain_and_closes_without_a_live_patch():
    """The Day 13 row: Layer 1 answers msi.product_code_guid from the Property table, plain (the seed's
    braces_upper is the stored form), and says nothing about an UNKNOWN PROPERTY."""
    got, err = ask("msi.product_code_guid", installer(), GUID)
    assert got == PRODUCT and plain(got), (got, err[-300:])
    assert "UNKNOWN PROPERTY" not in err and "NOT ESTABLISHED" not in err, err[-300:]


def test_the_cabinet_name_is_offered_as_stored_then_without_its_hash():
    assert [v for _, v in options(ask("msi.cabinet_names", installer())[0])] == ["#artifact.cab", "artifact.cab"]


def test_a_stored_cabinet_is_read_too():
    stored = installer(method=0)
    assert first(ask("msi.cabinet_file_md5", stored)[0]) == hashlib.md5(PAYLOAD).hexdigest()
    assert first(ask("msi.cabinet_compression", stored)[0]) == "none"


def test_two_files_give_a_list_and_no_single_name_or_member_digest():
    two = installer(files=2)
    assert first(ask("msi.file_names", two)[0]) == "evidence.txt,second.bin"
    assert ask("msi.file_name", two)[0] is None
    assert first(ask("msi.cabinet_file_names", two)[0]) == "File0,File1"
    assert ask("msi.cabinet_file_md5", two)[0] is None
    assert first(ask("msi.file_count", two)[0]) == "2"


def test_three_byte_string_ids_read_the_same_rows():
    wide = installer(wide=True)
    assert ask("msi.product_code_guid", wide)[0] == PRODUCT
    assert first(ask("msi.string_id_width", wide)[0]) == "3"
    assert first(ask("msi.component_guid", wide)[0]) == COMPONENT


def test_codepage_1252_decodes_a_value_beyond_ascii_and_codepage_0_does_not():
    accent = [(n, "Café Labs" if n == "Manufacturer" else v) for n, v in PROPERTIES]
    assert first(ask("msi.property_manufacturer", installer(properties=accent, codepage=1252))[0]) == "Café Labs"
    assert ask("msi.property_manufacturer", cfb(with_raw_string(accent)))[0] is None


def test_the_table_reader_directly():
    """MSI._table: (column names, rows in stored order) of a table; None for a table _Tables does not name."""
    d = installer()
    names, rows = MSI._table(d, "Property")
    assert list(names) == ["Property", "Value"]
    assert [tuple(r) for r in rows] == PROPERTIES
    assert MSI._table(d, "Registry") is None
    assert MSI._table(b"%PDF-1.7\n" + b"x" * 600, "Property") is None


# ------------------------------------------------------------------ [4] never plain, never a guess

def test_only_the_judged_name_is_ever_plain_and_most_names_read_a_value():
    d = installer()
    mine = pack_names()
    answers = {n: ask(n, d)[0] for n in mine}
    sure = [n for n, a in answers.items() if n != "msi.product_code_guid" and plain(a)]
    assert not sure, sure[:6]
    answered = sum(1 for a in answers.values() if not no_value(a))
    assert answered > 100, answered


@pytest.mark.parametrize("damage", ["pool-sum", "table-rows", "string-id", "two-rows", "long-string"])
def test_a_database_that_is_not_whole_is_no_answer(damage):
    got, err = ask("msi.product_code_guid", installer(damage=damage))
    assert got is None and "NOT ESTABLISHED" in err, (got, err[-300:])


def test_two_streams_of_one_name_is_no_answer():
    got, err = ask("msi.product_code_guid", installer(twice="Property"))
    assert got is None and "NOT ESTABLISHED" in err, (got, err[-300:])


def test_a_product_code_that_is_no_guid_or_absent_is_no_answer():
    assert ask("msi.product_code_guid", installer(product="not-a-guid"))[0] is None
    assert no_value(ask("msi.product_code_guid", installer(product=None))[0])


def test_a_file_that_is_no_installer_is_no_answer():
    assert no_value(ask("msi.product_code_guid", b"%PDF-1.7\n" + b"x" * 600)[0])
    assert no_value(ask("msi.property_count", b"MZ" + b"\x00" * 600)[0])
    assert no_value(ask("msi.product_code_guid", cfb([("WordDocument", b"x" * 600)], clsid=b"\x00" * 16))[0])


def test_declared_table_without_columns_and_an_absent_table():
    d = installer()
    assert ask("msi.error_row_count", d)[0] is None
    got = ask("msi.registry_row_count", d)[0]
    assert no_value(got) and first(got) != "0"


def test_a_name_the_pack_does_not_know_is_not_answered_by_a_look_alike():
    d = installer()
    assert ask("msi.product_code_checksum", d)[0] is None
    assert ask("msi.product_signature", d)[0] is None


# ------------------------------------------------------------------ [5] row 284: the stored form first

def test_a_guid_read_from_binary_keeps_its_five_forms_in_order():
    names = [n for n, _ in M.FORMATS["uuid"][1]("dd1a80d502504f4db28913096d633c61")]
    assert names == FIVE
    got = ask("msi.root_clsid", installer())[0]
    assert [n for n, _ in options(got)] == FIVE
    assert first(got) == "000c1084-0000-0000-c000-000000000046"


HY = PRODUCT[1:-1]
STORED_FORMS = {"braces_upper": PRODUCT, "braces_lower": PRODUCT.lower(), "hyphen_upper": HY, "hyphen_lower": HY.lower(),
                "compact_upper": HY.replace("-", ""), "compact_lower": HY.replace("-", "").lower(),
                "as_stored": "{dd1a80d5-0250-4F4D-b289-13096D633C61}"}


def _upgrade_form(form):
    up = UPGRADE[1:-1]
    return {"braces_upper": UPGRADE, "braces_lower": UPGRADE.lower(), "hyphen_upper": up, "hyphen_lower": up.lower(),
            "compact_upper": up.replace("-", ""), "compact_lower": up.replace("-", "").lower(),
            "as_stored": "{5f63b105-6C37-46fb-B671-2af6c4f4cd67}"}[form]


@pytest.mark.parametrize("form", sorted(STORED_FORMS))
def test_an_unjudged_guid_key_offers_the_stored_text_first(form):
    text = _upgrade_form(form)
    rows = [(n, text if n == "UpgradeCode" else v) for n, v in PROPERTIES]
    got = options(ask("msi.upgrade_code_guid", installer(properties=rows))[0])
    assert got[:1] == [(form, text)], got[:2]
    assert len({v for _, v in got}) == len(got), got
    assert {n for n, _ in got} >= set(FIVE), got


def test_the_judged_key_stored_uppercase_in_braces_is_plain():
    assert ask("msi.product_code_guid", installer())[0] == PRODUCT


@pytest.mark.parametrize("form", sorted(f for f in STORED_FORMS if f != "braces_upper"))
def test_the_judged_key_in_another_stored_form_is_unsure_under_its_own_key(form):
    text = STORED_FORMS[form]
    got, err = ask("msi.product_code_guid", installer(product=text))
    assert key_of(got) == f"{JUDGED_KEY}+stored_{form}", key_of(got)
    assert options(got)[:2] == [(form, text), ("braces_upper", PRODUCT)], options(got)[:3]
    assert "FORM " in err, err[-300:]


def test_the_judged_key_is_plain_once_the_judge_accepted_the_stored_form():
    lower = installer(product=PRODUCT.lower())
    labels.learn(f"{JUDGED_KEY}+stored_braces_lower", "braces_lower", "accepted", attempt_id="test", answer_ids=["x"])
    assert ask("msi.product_code_guid", lower)[0] == PRODUCT.lower()
    assert ask("msi.product_code_guid", installer())[0] == PRODUCT


def test_the_judged_key_gives_the_judged_form_when_that_is_what_the_judge_took():
    lower = installer(product=PRODUCT.lower())
    labels.learn(f"{JUDGED_KEY}+stored_braces_lower", "braces_upper", "accepted", attempt_id="test", answer_ids=["x"])
    assert ask("msi.product_code_guid", lower)[0] == PRODUCT


@pytest.mark.parametrize("text", ["{DD1A80D5}", "DD1A80D5-0250-4F4D-B289-13096D633C61}", "{DD1A80D502504F4DB28913096D633C61}", ""])
def test_a_text_that_is_no_guid_is_not_a_stored_guid(text):
    with pytest.raises(TypeError):
        M.FORMATS["uuid"][1](M.Stored(text))


# ------------------------------------------------------------------ [6] and [10]: MSIX / AppX identity

def test_an_msix_manifest_identity_is_read_none_plain():
    d = package()
    want = {"msix.identity_name": "Scratch.Notes", "msix.package_name": "Scratch.Notes",
            "msix.identity_publisher": "CN=Scratch Labs, O=Scratch, C=US", "msix.publisher": "CN=Scratch Labs, O=Scratch, C=US",
            "msix.identity_version": "3.2.1.0", "msix.version": "3.2.1.0", "msix.processor_architecture": "x64",
            "msix.display_name": "Scratch Notes", "msix.publisher_display_name": "Scratch Labs",
            "msix.capabilities": "internetClient,documentsLibrary", "msix.capability_count": "2", "msix.application_id": "App",
            "msix.application_executable": "Notes.exe", "msix.target_device_family_name": "Windows.Desktop",
            "msix.min_version": "10.0.17763.0", "msix.has_signature": "true", "msix.has_block_map": "true",
            "appx.identity_name": "Scratch.Notes"}
    got = {n: ask(n, d, fname="notes-001.msix", item="d14-msix-001-")[0] for n in want}
    bad = {n: (got[n], v) for n, v in want.items() if first(got[n]) != v}
    assert not bad, bad
    assert not [n for n in got if plain(got[n])]


def test_msix_unsigned_duplicate_doctype_and_not_a_package():
    assert first(ask("msix.has_signature", package(signed=False), fname="notes-001.msix")[0]) == "false"
    two = package((MANIFEST, MANIFEST.replace("Scratch.Notes", "Other")))
    assert ask("msix.identity_name", two, fname="notes-001.msix")[0] is None
    doctype = package((MANIFEST.replace("<Package", "<!DOCTYPE Package>\n<Package", 1),))
    assert ask("msix.identity_name", doctype, fname="n.msix")[0] is None
    assert no_value(ask("msix.identity_name", package(()), fname="notes-001.msix")[0])


def test_publisher_id_and_package_full_name_as_windows_writes_them():
    assert MSI.publisher_id(MS_STORE) == "8wekyb3d8bbwe"
    assert MSI.publisher_id(MS_WINDOWS) == "cw5n1h2txyewy"
    calc = MANIFEST.replace('Name="Scratch.Notes" Publisher="CN=Scratch Labs, O=Scratch, C=US" Version="3.2.1.0"',
                            f'Name="Microsoft.WindowsCalculator" Publisher="{MS_STORE}" Version="10.1906.55.0"')
    got = ask("msix.package_full_name", package((calc,)), fname="calc-001.msix", item="d14-msix-001-")[0]
    assert first(got) == "Microsoft.WindowsCalculator_10.1906.55.0_x64__8wekyb3d8bbwe" and not plain(got), got
    assert first(ask("msix.package_family_name", package((calc,)), fname="calc-001.msix")[0]) == "Microsoft.WindowsCalculator_8wekyb3d8bbwe"


def _inner():
    arm = MANIFEST.replace('ProcessorArchitecture="x64"', 'ProcessorArchitecture="arm64"')
    res = MANIFEST.replace('ProcessorArchitecture="x64"', 'ResourceId="scale-140"')
    return {"Notes_x64.msix": package(), "Notes_arm64.msix": package((arm,)), "Notes_scale-140.msix": package((res,))}


def test_a_bundle_identity_package_list_and_inner_identities():
    inner = _inner()
    d = bundle_of(inner)
    pid = MSI.publisher_id("CN=Scratch Labs, O=Scratch, C=US")
    want = {"msix.bundle_identity_name": "Scratch.Notes", "msix.bundle_version": "2026.1013.1.0",
            "msix.bundle_publisher": "CN=Scratch Labs, O=Scratch, C=US", "msix.identity_version": "2026.1013.1.0",
            "msix.identity_name": "Scratch.Notes", "msix.is_bundle": "true", "msix.bundle_package_count": "3",
            "msix.bundle_package_file_names": "Notes_x64.msix,Notes_arm64.msix,Notes_scale-140.msix",
            "msix.bundle_package_types": "application,application,resource", "msix.bundle_package_architectures": "x64,arm64",
            "msix.bundle_package_names": "Scratch.Notes,Scratch.Notes,Scratch.Notes",
            "msix.bundle_package_identity_architectures": "x64,arm64,neutral",
            "msix.bundle_package_full_names": f"Scratch.Notes_3.2.1.0_x64__{pid},Scratch.Notes_3.2.1.0_arm64__{pid},"
                                              f"Scratch.Notes_3.2.1.0_neutral_scale-140_{pid}",
            "msix.publisher_id": pid, "msixbundle.bundle_identity_name": "Scratch.Notes"}
    got = {n: ask(n, d, fname="notes-001.msixbundle", item="d14-msix-001-")[0] for n in want}
    bad = {n: (got[n], v) for n, v in want.items() if first(got[n]) != v}
    assert not bad, bad
    assert not [n for n in got if plain(got[n])]
    assert ask("msix.bundle_application_package_full_name", d, fname="notes-001.msixbundle")[0] is None
    one_app = bundle_of(inner, BUNDLE.replace('Type="application" Version="3.2.1.0" Architecture="arm64"',
                                              'Type="resource" Version="3.2.1.0" Architecture="arm64"'))
    assert (first(ask("msix.bundle_application_package_full_name", one_app, fname="notes-001.msixbundle")[0])
            == f"Scratch.Notes_3.2.1.0_x64__{pid}")
    missing = bundle_of({k: v for k, v in inner.items() if "arm64" not in k})
    assert first(ask("msix.bundle_package_file_names", missing, fname="notes-001.msixbundle")[0]) == want["msix.bundle_package_file_names"]
    assert ask("msix.bundle_package_full_names", missing, fname="notes-001.msixbundle")[0] is None
    assert first(ask("msix.is_bundle", package(), fname="notes-001.msix")[0]) == "false"
    assert no_value(ask("msix.bundle_identity_name", package(), fname="notes-001.msix")[0])
    assert no_value(ask("msix.package_full_name", d, fname="notes-001.msixbundle")[0])


def test_a_bundle_whose_inner_packages_state_too_much_is_not_unpacked():
    big = b"\x00" * (40 << 20)                        # three inner "packages" of 40 MiB each, deflated to a few KiB
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for name in ("Notes_x64.msix", "Notes_arm64.msix", "Notes_scale-140.msix"):
            z.writestr(name, big)
        z.writestr("AppxMetadata/AppxBundleManifest.xml", BUNDLE)
    d = out.getvalue()
    del big, out
    kw = {"fname": "notes-001.msixbundle", "item": "d14-msix-001-"}
    tracemalloc.start()
    try:
        own = ask("msix.identity_name", d, **kw)[0]
        names = ask("msix.bundle_package_file_names", d, **kw)[0]
        inner, err = ask("msix.bundle_package_full_names", d, **kw)
        more = ask("msix.bundle_package_names", d, **kw)[0]
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert first(own) == "Scratch.Notes"
    assert first(names) == "Notes_x64.msix,Notes_arm64.msix,Notes_scale-140.msix"
    assert inner is None and more is None and "NOT ESTABLISHED" in err
    assert peak < 8 << 20, f"peak {peak >> 20} MiB: an inner package was unpacked"


def test_deflated_and_stored_inner_packages_of_ordinary_size_are_read():
    pid = MSI.publisher_id("CN=Scratch Labs, O=Scratch, C=US")
    want = f"Scratch.Notes_3.2.1.0_x64__{pid},Scratch.Notes_3.2.1.0_arm64__{pid},Scratch.Notes_3.2.1.0_neutral_scale-140_{pid}"
    inner = _inner()
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for name, body in inner.items():
            z.writestr(name, body)
        z.writestr("AppxMetadata/AppxBundleManifest.xml", BUNDLE)
    assert first(ask("msix.bundle_package_full_names", out.getvalue(), fname="notes-001.msixbundle")[0]) == want
    heavy = io.BytesIO()                              # a stored inner package with 32 MiB beside its manifest
    with zipfile.ZipFile(heavy, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("payload.bin", b"\x00" * (32 << 20))
        z.writestr("AppxManifest.xml", MANIFEST)
    stored = bundle_of({**inner, "Notes_x64.msix": heavy.getvalue()})
    tracemalloc.start()
    try:
        got = ask("msix.bundle_package_full_names", stored, fname="notes-001.msixbundle")[0]
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert first(got) == want
    assert peak < 8 << 20, f"peak {peak >> 20} MiB: more than the manifest was unpacked"


# ------------------------------------------------------------------ [7] the live-fix template names real helpers

def test_the_day_patch_template_names_only_helpers_that_exist():
    import importlib.util
    path = LANE / "day_patch_template.py"
    doc = path.read_text().split('"""', 2)[1]
    spec = importlib.util.spec_from_file_location("day_patch_template_under_test", path)
    T = importlib.util.module_from_spec(spec)
    with contextlib.redirect_stderr(io.StringIO()):
        spec.loader.exec_module(T)
    listed = sorted(set(re.findall(r"\b(M|RF|RM|MSI)\.([A-Za-z_]\w*)", doc)))
    missing = [f"{mod}.{name}" for mod, name in listed if not hasattr(getattr(T, mod, None), name)]
    assert len(listed) >= 18 and not missing, missing
    assert T.MSI is not None and T.MSI.__name__ == MSI.__name__
    assert T.ALIAS == {} and T.NEW == {}
    line = re.search(r'(?m)^\s+"msi\.arp_contact_text": \((lambda n, d: .+), "text"\),$', doc)
    assert line, "the template's worked NEW line for an MSI property is gone"
    fn = eval(line.group(1), {"MSI": T.MSI, "M": T.M})   # the docstring's own worked example, our own text
    assert fn("installer-001.msi", installer()) == dict(PROPERTIES)["ARPCONTACT"]


# ------------------------------------------------------------------ [8] the cabinet

def test_a_cabinet_of_a_set_reads_the_whole_member_and_not_the_one_that_continues():
    two = [("File0", PAYLOAD), ("File1", b"second member, other bytes\n" * 40)]
    part = cabinet(two[:1] + [("File1", b"")], 1, continues={1: 0xFFFE}, extra_block=(b"CK\x01\x02\x03", 0))
    part = part.replace(struct.pack("<IIH", 0, len(PAYLOAD), 0xFFFE), struct.pack("<IIH", len(two[1][1]), len(PAYLOAD), 0xFFFE))
    parsed = MSI._cab_parse(part)
    assert parsed["to_next"] and not parsed["from_prev"]
    assert MSI._cab_member(part, parsed, parsed["files"][0]) == PAYLOAD
    assert unknown(lambda: MSI._cab_member(part, parsed, parsed["files"][1]))
    d = installer(cab=part)
    assert first(ask("msi.cabinet_file_names", d)[0]) == "File0,File1"
    assert first(ask("msi.cabinet_file_sizes", d)[0]) == f"24,{len(two[1][1])}"
    assert ask("msi.cabinet_file_md5_list", d)[0] is None
    assert first(ask("msi.cabinet_is_multi_part", d)[0]) == "true"
    prev = cabinet(two, 1, continues={0: 0xFFFD})
    parsed = MSI._cab_parse(prev)
    assert parsed["from_prev"] and all(unknown(lambda f=f: MSI._cab_member(prev, parsed, f)) for f in parsed["files"])
    whole = installer(cab=cabinet(two, 1))
    assert first(ask("msi.cabinet_file_sha256_list", whole)[0]) == ",".join(hashlib.sha256(b).hexdigest() for _, b in two)
    assert first(ask("msi.cabinet_is_multi_part", whole)[0]) == "false"


def test_a_changed_byte_in_an_mszip_folder_is_no_answer():
    mszip = bytearray(cabinet([("File0", PAYLOAD)], 1))
    mszip[-3] ^= 0x01
    assert ask("msi.cabinet_file_md5", installer(cab=bytes(mszip)))[0] is None


def test_a_quantum_folder_that_does_not_unpack_is_no_answer_but_its_names_are_read():
    d = installer(method="bad-quantum")
    assert ask("msi.cabinet_file_md5", d)[0] is None
    assert first(ask("msi.cabinet_compression", d)[0]) == "quantum"
    assert first(ask("msi.cabinet_file_names", d)[0]) == "File0"


def test_without_7zz_or_bsdtar_an_lzx_folder_is_no_answer(monkeypatch):
    monkeypatch.setattr(MSI, "SEVENZIP", ("/nonexistent/7zz",))
    monkeypatch.setattr(MSI, "BSDTAR", ("/nonexistent/bsdtar",))
    monkeypatch.setenv("PATH", "/nonexistent")
    got, err = ask("msi.cabinet_file_md5", installer(method=3, product=UPGRADE))
    assert got is None and "NOT ESTABLISHED" in err, (got, err[-300:])
    # the tables do not need a tool: the Property rows still read
    assert ask("msi.product_code_guid", installer(method=3, properties=PROPERTIES + [("NoTool", "1")]))[0] == PRODUCT


@pytest.mark.needs_tool("7zz")
def test_7zz_and_the_mszip_unpacker_agree_and_7zz_unpacks_a_built_lzx_folder():
    two = [("File0", PAYLOAD), ("File1", b"second member, other bytes\n" * 40)]
    plain_cab = cabinet(two, 1)
    parsed = MSI._cab_parse(plain_cab)
    assert MSI._cab_7z(plain_cab, parsed, 0) == MSI._cab_folder(plain_cab, parsed, 0) == two[0][1] + two[1][1]
    lzx_cab = cabinet(two, 3)
    parsed = MSI._cab_parse(lzx_cab)
    assert parsed["folders"][0][2] == 3 and MSI._cab_folder(lzx_cab, parsed, 0) == two[0][1] + two[1][1]
    d = installer(method=3)
    md5 = hashlib.md5(PAYLOAD).hexdigest()
    got = ask("msi.cabinet_file_md5", d)[0]
    assert first(got) == md5 == first(ask("msi.file_hash_md5", d)[0]) and not plain(got)
    assert first(ask("msi.cabinet_file_sha256", d)[0]) == hashlib.sha256(PAYLOAD).hexdigest()
    assert first(ask("msi.cabinet_compression", d)[0]) == "lzx"
    d = installer(cab=cabinet(two, 3))
    assert first(ask("msi.cabinet_file_sha1_list", d)[0]) == ",".join(hashlib.sha1(b).hexdigest() for _, b in two)


@pytest.mark.needs_tool("7zz")
def test_an_lzx_folder_with_a_changed_byte_is_not_unpacked():
    broken = bytearray(cabinet([("File0", PAYLOAD)], 3))
    broken[-20] ^= 0xFF
    parsed = MSI._cab_parse(bytes(broken))
    assert unknown(lambda: MSI._cab_folder(bytes(broken), parsed, 0))
    assert ask("msi.cabinet_file_md5", installer(cab=bytes(broken)))[0] is None


@pytest.mark.needs_tool("7zz", "bsdtar")
def test_an_lzx_folder_is_unpacked_by_7zz_and_bsdtar_and_they_agree():
    d = installer(method=3, properties=PROPERTIES + [("TwoTools", "1")])
    ask("msi.cabinet_file_md5", d)
    assert MSI._cab(d)[2]["decoders"].get(0) == ["7zz", "bsdtar"], MSI._cab(d)[2]["decoders"]


# ------------------------------------------------------------------ [12] a hanging tool costs a bounded time

def _hanging_tool(tmp_path):
    stand_in = tmp_path / "hanging-7zz"
    stand_in.write_text("#!/bin/sh\n# a tool that never answers; the sleep is a child, as a tool's helper would be\nsleep 30\necho done\n")
    stand_in.chmod(0o755)
    return str(stand_in)


def _refusing_tool(tmp_path):
    stand_in = tmp_path / "refusing-7zz"
    stand_in.write_text("#!/bin/sh\n# a tool that refuses every folder at once\nexit 3\n")
    stand_in.chmod(0o755)
    return str(stand_in)


class _Launched(list):
    """The programs started, in order. `procs` are their Popen objects, in the same order; each has
    `waits`, the timeouts its communicate() was called with, in order, and `group`, the process group
    it was in when it started (None where it had ended before that could be read)."""

    def __init__(self):
        super().__init__()
        self.procs = []

    def forget(self):
        del self[:]
        del self.procs[:]


def _launches(monkeypatch):
    """The programs started from here on, in order. subprocess.Popen itself is counted and every launch
    still runs, so what the reader's budget and its once-per-folder rule allow is held by a count, which
    no load changes, and not by a time. For the same reason the time a tool is GIVEN is read off the
    timeout its communicate() is called with (exact at any load), not off how long the wait then took."""
    import subprocess
    started = _Launched()

    class Counted(subprocess.Popen):
        def __init__(self, args, *a, **kw):
            self.waits = []
            started.append(args[0])
            started.procs.append(self)
            super().__init__(args, *a, **kw)
            try:
                self.group = os.getpgid(self.pid)
            except OSError:
                self.group = None

        def communicate(self, input=None, timeout=None):
            self.waits.append(timeout)
            return super().communicate(input, timeout)

    monkeypatch.setattr(subprocess, "Popen", Counted)
    return started


def _assert_killed_with_its_group(proc):
    """A hanging stand-in the reader gave up on was killed, and what it started (its `sleep 30`) with it.
    The 10 s here are wall-clock by nature and are not a margin around the cut: a killed process is
    reaped at once, one that was not killed sleeps on for 30 s, so 10 s tells them apart at any load.
    Where the check fails, the stand-in is ended here so that it does not outlive the test."""
    import signal
    import subprocess

    def end_it():
        with contextlib.suppress(OSError):
            proc.kill()
        if proc.group == proc.pid:
            with contextlib.suppress(OSError):
                os.killpg(proc.pid, signal.SIGKILL)

    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        end_it()
        pytest.fail(f"the hanging tool (pid {proc.pid}) was not killed when it was cut")
    assert proc.returncode == -signal.SIGKILL, proc.returncode
    # The tool must have led a process group of its own (a session of its own), or a kill of "its group"
    # reaches nothing it started. Its pid then names that group, and the group is gone once the orphaned
    # `sleep` has been killed too and collected by init.
    assert proc.group == proc.pid, f"the tool was started in its caller's process group ({proc.group})"
    deadline = time.monotonic() + 10
    while True:
        try:
            os.killpg(proc.pid, 0)
        except ProcessLookupError:
            return
        if time.monotonic() > deadline:
            end_it()
            pytest.fail(f"what the hanging tool started (process group {proc.pid}) outlived the cut")
        time.sleep(0.02)


def _refusals(cab_bytes, parsed, indexes):
    """What _cab_folder says of each folder: every one must be Unknown."""
    said = []
    for i in indexes:
        with pytest.raises(M.Unknown) as refusal:
            MSI._cab_folder(cab_bytes, parsed, i)
        said.append(str(refusal.value))
    return said


def test_the_tool_limits_as_shipped():
    assert MSI.SEVENZIP_SECONDS == 0.5 and MSI.SEVENZIP_BUDGET == 0.6
    assert MSI.CAB_REQUIRE_TWO is False and MSI.CAB_REFUSAL_VETOES == (2, 3)


def test_a_hanging_tool_never_runs_for_the_facts_page_and_is_cut_and_not_rerun(tmp_path, monkeypatch):
    hang = _hanging_tool(tmp_path)
    monkeypatch.setattr(MSI, "SEVENZIP", (hang,))
    monkeypatch.setattr(MSI, "BSDTAR", (hang,))
    monkeypatch.setattr(MSI, "_sevenzip", lambda: hang)
    launched = _launches(monkeypatch)
    d = installer(method=3, product=COMPONENT)
    got, err = ask("msi.product_fingerprint", d)
    assert got is None and "UNKNOWN PROPERTY" in err, err[-300:]
    assert "msi.cabinet_file_names = File0" in err and "msi.cabinet_file_md5" not in err, err[-600:]
    c = MSI._cab(d)
    assert c[2]["spent"] == 0.0 and not c[2]["failed"], c[2]
    assert launched == [], f"a tool was started for the facts page: {launched}"
    # The cut is a real wall-clock timeout of an external process (the shipped SEVENZIP_SECONDS = 0.5 s
    # per-tool cap, SEVENZIP_BUDGET = 0.6 s for the cabinet). Under full-suite load (50-170 on 14 cores)
    # the communicate() deadline and the SIGKILL/tmpdir cleanup slip past the budget by scheduling slop,
    # so the TIMES below are NOT tight margins around the budget (rule 16): the lower bound proves the
    # tools ran and the upper bound proves both were cut well before their 30 s hang, with room to hold
    # at load. That the budget itself is applied is held by the launch counts, which no load changes.
    started = time.perf_counter()
    got = ask("msi.cabinet_file_md5", d)[0]
    took = time.perf_counter() - started
    assert got is None
    assert 0.3 < c[2]["spent"] < 15, c[2]["spent"]
    assert took < 15, f"{took:.2f} s: the hanging tools were not cut well before their 30 s hang"
    # 7zz is always started and waits out its 0.5 s; bsdtar is started only where at least 0.05 s of the
    # 0.6 s are then left, which load decides: one launch or two, never more.
    assert launched in ([hang], [hang, hang]), launched
    # What each tool was GIVEN, exactly (the timeout of its wait, which no load moves): 7zz its whole
    # per-run cap; bsdtar, where it was started, only what 7zz left of the cabinet's 0.6 s, which is at
    # least the 0.05 s floor and at most 0.6 - 0.5.
    assert launched.procs[0].waits[0] == MSI.SEVENZIP_SECONDS, launched.procs[0].waits
    for second in launched.procs[1:]:
        assert 0.05 <= second.waits[0] <= MSI.SEVENZIP_BUDGET - MSI.SEVENZIP_SECONDS + 1e-9, second.waits
    for proc in launched.procs:
        _assert_killed_with_its_group(proc)
    # Not rerun: the failure is cached, so no new subprocess runs. Neither the launch count nor "spent"
    # (which grows only while a tool runs) may change over three more asks. Accounting, not wall-clock.
    spent_after_cut, launched_after_cut = c[2]["spent"], list(launched)
    again = [ask(n, d)[0] for n in ("msi.cabinet_file_md5", "msi.cabinet_file_sha256", "msi.cabinet_file_sha1_list")]
    assert again == [None, None, None] and 0 in c[2]["failed"]
    assert launched == launched_after_cut, "the folder was sent to the tool again"
    assert c[2]["spent"] == spent_after_cut, "the folder was sent to the tool again"

    # Four folders of one cabinet share the cabinet's ONE budget: the first folder's tools use it up and
    # the other three are told so without a tool being started. Unbudgeted, the four folders would start
    # eight tools (and cost eight cuts); the count holds that at any load, where a time bound could not.
    one = cabinet([("File0", PAYLOAD)], 3)
    parsed = MSI._cab_parse(one)
    parsed["folders"] = parsed["folders"] * 4
    launched.forget()
    first_folder = _refusals(one, parsed, [0])[0]
    spent_on_the_first, launched_for_the_first = parsed["spent"], list(launched)
    assert launched_for_the_first in ([hang], [hang, hang]), launched
    assert first_folder.startswith("7zz did not unpack the folder within 0.5 s; "), first_folder   # the per-run cap
    assert spent_on_the_first > MSI.SEVENZIP_SECONDS, spent_on_the_first      # 7zz was waited for, for all of its cap
    budget_spent = f"the {MSI.SEVENZIP_BUDGET:g} s this cabinet has for unpacking are spent"
    assert _refusals(one, parsed, [1, 2, 3]) == [f"{budget_spent}; {budget_spent}"] * 3
    assert launched == launched_for_the_first, f"a tool was started after the cabinet's budget was spent: {launched}"
    assert parsed["spent"] == spent_on_the_first
    # wall-clock by nature, as above: the first folder's cuts came well before a 30 s hang
    assert parsed["spent"] < 15, parsed["spent"]
    for proc in launched.procs:
        _assert_killed_with_its_group(proc)


def test_a_tool_is_given_what_is_left_of_the_cabinet_budget_and_nothing_under_the_floor(tmp_path, monkeypatch):
    """A tool is waited for only as long as the cabinet's budget still has, not for its per-run cap. The
    time already spent is SET here on a fresh parse, not measured, so what is left is known exactly and
    the timeout the tool is given is held to it with no margin, at any load. (In the test above, whether
    bsdtar is started at all after the hanging 7zz is for load to decide.)"""
    hang = _hanging_tool(tmp_path)
    monkeypatch.setattr(MSI, "SEVENZIP", (hang,))
    monkeypatch.setattr(MSI, "BSDTAR", (hang,))
    monkeypatch.setattr(MSI, "_sevenzip", lambda: hang)
    launched = _launches(monkeypatch)
    one = cabinet([("File0", PAYLOAD)], 3)
    budget_spent = f"the {MSI.SEVENZIP_BUDGET:g} s this cabinet has for unpacking are spent"

    # 0.08 s are left: 7zz gets those 0.08 s (not its 0.5 s) and is cut, and bsdtar after it gets nothing
    parsed = MSI._cab_parse(one)
    parsed["spent"] = already = MSI.SEVENZIP_BUDGET - 0.08
    left = MSI.SEVENZIP_BUDGET - already
    assert left == pytest.approx(0.08) and 0.05 < left < MSI.SEVENZIP_SECONDS
    assert _refusals(one, parsed, [0]) == [f"7zz did not unpack the folder within 0.08 s; {budget_spent}"]
    assert launched == [hang], launched
    assert launched.procs[0].waits[0] == left, launched.procs[0].waits
    assert parsed["spent"] >= already + left, (parsed["spent"], already)   # the wait was charged to the cabinet
    _assert_killed_with_its_group(launched.procs[0])

    # the floor: with less than 0.05 s of the budget left (0.03 s here) no tool is started at all
    parsed = MSI._cab_parse(one)
    parsed["spent"] = already = MSI.SEVENZIP_BUDGET - 0.03
    launched.forget()
    assert _refusals(one, parsed, [0]) == [f"{budget_spent}; {budget_spent}"]
    assert launched == [], f"a tool was started on less than the 0.05 s floor: {launched}"
    assert parsed["spent"] == already


def test_a_folder_the_tools_refused_is_not_sent_to_them_again_while_budget_remains(tmp_path, monkeypatch):
    """The once-per-folder rule on its own. In the hanging case the spent budget also stops a second
    launch, so there the rule is not seen; here the tools refuse at once and the budget is far from spent."""
    refuse = _refusing_tool(tmp_path)
    monkeypatch.setattr(MSI, "SEVENZIP", (refuse,))
    monkeypatch.setattr(MSI, "BSDTAR", (refuse,))
    monkeypatch.setattr(MSI, "_sevenzip", lambda: refuse)
    # An explicit budget instead of the shipped one (rule 16): however slowly the two stand-ins start and
    # exit under load, time is left for more runs afterwards, so only the rule can keep a tool from starting.
    monkeypatch.setattr(MSI, "SEVENZIP_SECONDS", 20.0)
    monkeypatch.setattr(MSI, "SEVENZIP_BUDGET", 1000.0)
    launched = _launches(monkeypatch)
    one = cabinet([("File0", PAYLOAD)], 3)
    parsed = MSI._cab_parse(one)
    said = _refusals(one, parsed, [0])[0]
    assert said == ("7zz did not unpack the folder to its stated size; "
                    "bsdtar did not unpack the folder to its stated size"), said
    assert launched == [refuse, refuse] and parsed["failed"] == {0: said}
    assert MSI.SEVENZIP_BUDGET - parsed["spent"] > 2 * MSI.SEVENZIP_SECONDS, "no budget left: this case shows nothing"
    spent = parsed["spent"]
    assert _refusals(one, parsed, [0, 0, 0]) == [said] * 3
    assert launched == [refuse, refuse], f"a refused folder was sent to a tool again: {launched}"
    assert parsed["spent"] == spent

    # the same through the lane: four questions about one installer's cabinet start the two tools once
    launched.forget()
    d = installer(method=3, properties=PROPERTIES + [("RefusingTool", "1")])
    names = ("msi.cabinet_file_md5", "msi.cabinet_file_sha256", "msi.cabinet_file_sha1_list", "msi.cabinet_file_md5")
    assert [ask(n, d)[0] for n in names] == [None] * 4
    c = MSI._cab(d)[2]
    assert MSI.SEVENZIP_BUDGET - c["spent"] > 2 * MSI.SEVENZIP_SECONDS and 0 in c["failed"], c
    assert launched == [refuse, refuse], f"a refused folder was sent to a tool again: {launched}"


@pytest.mark.needs_tool("bsdtar")
def test_a_hanging_7zz_and_a_working_bsdtar_give_the_digest_by_bsdtar(tmp_path, monkeypatch):
    hang = _hanging_tool(tmp_path)
    monkeypatch.setattr(MSI, "SEVENZIP", (hang,))
    monkeypatch.setattr(MSI, "_sevenzip", lambda: hang)
    # 7zz is cut by a real wall-clock timeout (the per-tool cap), and only then does bsdtar run, on what
    # is left of the cabinet's budget. At the shipped caps bsdtar would get min(0.5, 0.6 - 0.5) = 0.1 s,
    # too tight to spawn and unpack under full-suite load (50-170 on 14 cores) - that is what made this
    # flaky. So the engine gets an explicit budget instead of the shipped default (rule 16): 10 s a run
    # and 30 s a cabinet, which leaves bsdtar a 10 s window for its few-millisecond unpack. The hanging
    # 7zz alone keeps the shipped 0.5 s cap (the real _cab_7z, called under that cap), so the test does
    # not idle for the whole window. These are wall-clock seconds by nature.
    shipped_cap = MSI.SEVENZIP_SECONDS
    monkeypatch.setattr(MSI, "SEVENZIP_SECONDS", 10.0)
    monkeypatch.setattr(MSI, "SEVENZIP_BUDGET", 30.0)
    real_7z = MSI._cab_7z

    def seven_zip_under_the_shipped_cap(*a):
        with monkeypatch.context() as m:
            m.setattr(MSI, "SEVENZIP_SECONDS", shipped_cap)
            return real_7z(*a)

    monkeypatch.setattr(MSI, "_cab_7z", seven_zip_under_the_shipped_cap)
    launched = _launches(monkeypatch)
    d = installer(method=3, product=UPGRADE.lower())
    got = ask("msi.cabinet_file_md5", d)[0]
    assert first(got) == hashlib.md5(PAYLOAD).hexdigest()
    c = MSI._cab(d)[2]
    assert c["decoders"][0] == ["bsdtar"]
    bsdtar = next(t for t in MSI.BSDTAR if os.access(t, os.X_OK))
    assert launched == [hang, bsdtar], launched            # each tool once: the hanging one is not tried again
    # what each was given, exactly: the hanging 7zz the shipped cap, bsdtar this test's 10 s window
    hanging, working = launched.procs
    assert hanging.waits[0] == shipped_cap and working.waits == [10.0], (hanging.waits, working.waits)
    _assert_killed_with_its_group(hanging)                 # cut means killed, with the `sleep` it started
    assert working.returncode == 0
    # the hanging 7zz was waited for (all of its cap) and cut well before its 30 s hang: wall-clock, so
    # a lower bound and an upper one that holds at load
    assert shipped_cap < c["spent"] < 15, c["spent"]
    assert first(ask("msi.cabinet_file_sha256", d)[0]) == hashlib.sha256(PAYLOAD).hexdigest()
    assert launched == [hang, bsdtar], launched            # the unpacked folder is kept: no tool for the second digest


# ------------------------------------------------------------------ [9] long strings

@pytest.mark.parametrize("layout", [{"long": "refs_first"}, {"long": "high_first"},
                                    {"long": "high_first", "long_own_id": True}, {"long": "refs_first", "long_own_id": True}])
def test_a_string_of_64_kib_or_more_in_each_published_pool_layout(layout):
    long = "L" * 70000
    d = installer(properties=[("ARPCOMMENTS", long)] + PROPERTIES, **layout)
    assert ask("msi.product_code_guid", d)[0] == PRODUCT
    assert first(ask("msi.arp_comments", d)[0]) == long
    assert first(ask("msi.property_count", d)[0]) == "9"
    assert first(ask("msi.component_guid", d)[0]) == COMPONENT


def test_long_strings_with_data_that_does_not_sum_is_no_answer():
    rows = [("ARPCOMMENTS", "L" * 70000)] + PROPERTIES
    got, err = ask("msi.product_code_guid", installer(properties=rows, damage="pool-sum"))
    assert got is None and "NOT ESTABLISHED" in err
    db = MSI._db(installer(properties=rows))
    assert db["strings"].count(b"L" * 70000) == 1
    assert len(MSI._pool_readings(struct.pack("<HH", 0, 0) + struct.pack("<HH", 3, 1), b"abc")) == 1


# ------------------------------------------------------------------ [11] the facts page

def test_the_facts_page_of_an_installer_lists_its_msi_facts():
    rows = M.facts("installer-001.msi", installer())
    assert f"msi.product_code_guid = {PRODUCT}" in rows and "msi.property_count = 8" in rows, [r for r in rows if r.startswith("msi.")][:5]
    assert any(r.startswith("ole.") for r in rows)
    rows = M.facts("notes-001.msix", package())
    assert "msix.identity_name = Scratch.Notes" in rows and any(r.startswith("zip.") for r in rows)
    rows = M.facts("report.doc", cfb([("WordDocument", b"x" * 600)], clsid=b"\x00" * 16))
    assert not [r for r in rows if r.startswith("msi.")] and any(r.startswith("ole.") for r in rows)


# ------------------------------------------------------------------ [14] the package code

def test_a_revision_number_that_is_one_guid_offers_the_stored_form_first():
    code = "{99BE1D60-AB14-4859-85FA-9E465A88729D}"
    got = options(ask("msi.package_code", with_summary(code))[0])
    assert got[:1] == [("braces_upper", code)] and {n for n, _ in got} >= set(FIVE), got[:2]


@pytest.mark.parametrize("text", ["{99BE1D60-AB14-4859-85FA-9E465A88729D}{11111111-2222-3333-4444-555555555555}",
                                  "{99BE1D60-AB14-4859-85FA-9E465A88729D};1.0", "revision 7"])
@pytest.mark.parametrize("name", ["msi.package_code", "msi.package_code_guid"])
def test_a_revision_number_that_is_not_one_guid_is_the_text_unsure(text, name):
    assert options(ask(name, with_summary(text))[0]) == [("raw", text)]


def test_the_revision_number_is_the_text_either_way():
    both = "{99BE1D60-AB14-4859-85FA-9E465A88729D}{11111111-2222-3333-4444-555555555555}"
    assert first(ask("msi.revision_number", with_summary(both))[0]) == both


# ------------------------------------------------------------------ [15] the decoder chain

def _sample():
    rnd = random.Random(13)
    words = [bytes(rnd.randrange(97, 123) for _ in range(rnd.randrange(2, 9))) for _ in range(300)]
    text = b" ".join(rnd.choice(words) for _ in range(30000))
    return text[:60000] + bytes(rnd.randrange(256) for _ in range(9000)) + b"ABCD" * 5000 + b"\x00" * 3000 + text[900:20900]


@pytest.mark.parametrize("bits", [10, 18, 21])
def test_the_quantum_decoder_gives_back_a_folder_of_several_frames(bits):
    sample = _sample()
    blocks = quantum_encode(sample, bits)
    assert len(blocks) > 3 and sum(len(p) for p, _ in blocks) < len(sample) * 0.6
    assert MSI._quantum(blocks, bits) == sample


def test_the_quantum_decoder_refuses_what_the_format_does_not_allow():
    sample = _sample()
    blocks = quantum_encode(sample, 21)
    crossing = quantum_encode(sample, 18, cross=True)
    assert crossing != quantum_encode(sample, 18) and unknown(lambda: MSI._quantum(crossing, 18))
    zeros = quantum_encode(b"\x00" * 100000, 18)
    assert MSI._quantum(zeros, 18) == b"\x00" * 100000 and sum(len(p) for p, _ in zeros) < 64
    assert unknown(lambda: MSI._quantum(blocks, 9))
    assert unknown(lambda: MSI._quantum([(blocks[0][0][:40], blocks[0][1])], 21))
    assert unknown(lambda: MSI._quantum(blocks, 21, time.monotonic() - 1))


def test_an_installer_with_a_quantum_cabinet_is_read_by_the_decoder_here():
    d = installer(method=2)
    got = ask("msi.cabinet_file_md5", d)[0]
    used = MSI._cab(d)[2]["decoders"].get(0)
    assert first(got) == hashlib.md5(PAYLOAD).hexdigest() == first(ask("msi.file_hash_md5", d)[0]) and not plain(got)
    assert first(ask("msi.cabinet_file_sha256", d)[0]) == hashlib.sha256(PAYLOAD).hexdigest()
    assert first(ask("msi.cabinet_compression", d)[0]) == "quantum"
    assert used and "the decoder here" in used, used


def _fresh(n):
    """An LZX-cabinet installer no earlier check has asked about (what a folder gave is remembered per file)."""
    return installer(method=3, properties=PROPERTIES + [("ChainCase", str(n))])


def _refuse(*a):
    raise M.Unknown("this one does not unpack it")


def _away(*a):
    raise MSI.Unavailable("this one is not installed")


@pytest.mark.parametrize("decoders, require_two, method, want", [
    (((("one", lambda *a: PAYLOAD), ("other", lambda *a: PAYLOAD[::-1]))), False, 3, None),     # disagree
    (((("one", _refuse), ("other", lambda *a: PAYLOAD))), False, 3, None),                      # LZX refusal vetoes
    (((("one", _refuse), ("other", lambda *a: PAYLOAD))), False, 2, None),                      # Quantum refusal vetoes
    (((("one", _away), ("other", lambda *a: PAYLOAD))), False, 3, "md5"),                       # one absent: other stands
    (((("one", _away), ("other", lambda *a: PAYLOAD))), True, 3, None),                         # ...unless two required
    (((("one", lambda *a: PAYLOAD), ("other", lambda *a: PAYLOAD))), True, 3, "md5"),           # two that agree
])
def test_the_decoder_chain_rules(decoders, require_two, method, want, monkeypatch, request):
    monkeypatch.setattr(MSI, "CAB_DECODERS", {method: decoders})
    monkeypatch.setattr(MSI, "CAB_REQUIRE_TWO", require_two)
    tag = request.node.name                         # a file no other case has asked about
    d = installer(method=method, properties=PROPERTIES + [("ChainCase", tag)])
    got = ask("msi.cabinet_file_md5", d)[0]
    if want is None:
        assert got is None, got
    else:
        assert first(got) == hashlib.md5(PAYLOAD).hexdigest(), got


def test_a_member_name_that_does_not_decode_costs_the_names_only():
    named = installer(cab=cabinet([(b"caf\xe9.txt", PAYLOAD)], 1))
    assert ask("msi.cabinet_file_names", named)[0] is None
    assert ask("msi.cabinet_file_name", named)[0] is None
    assert first(ask("msi.cabinet_file_sizes", named)[0]) == "24"
    assert first(ask("msi.cabinet_file_md5", named)[0]) == hashlib.md5(PAYLOAD).hexdigest()


# ------------------------------------------------------------------ [2] the saved Day 13 installers (not run without them)

def _saved(day_folder, token):
    """{member name: (bytes, key.json's answer, answer id)} of one saved day's attempts."""
    out = {}
    for sub in ("", "time_trial", "mastery"):
        folder = day_folder / sub
        if not (folder / "key.json").is_file():
            continue
        key = json.loads((folder / "key.json").read_text())
        key = key.get("answers", key) if isinstance(key, dict) else {}
        for z in sorted((folder / "artifact").glob("*.zip")):
            with zipfile.ZipFile(z) as zf:
                members = {}
                for name in zf.namelist():
                    body = zf.read(name)
                    if name.endswith(".zip"):
                        with zipfile.ZipFile(io.BytesIO(body)) as inner:
                            members.update({m: inner.read(m) for m in inner.namelist()})
                    else:
                        members[name] = body
            for name, body in members.items():
                number = name.rsplit("-", 1)[-1].split(".")[0]
                answers = [(k, v) for k, v in key.items() if f"-{token}-{number}-" in k and isinstance(v, str)]
                if len(answers) == 1:
                    aid = answers[0][0].split(".", 1)[-1] if answers[0][0].startswith("set") else answers[0][0]
                    out[name] = (body, answers[0][1], aid)
    return out


def _day13():
    root = paths.saved_challenges_root()
    if root is None:
        pytest.skip("not run: CTF_REAL_CHALLENGES is not set (the saved Huntress Day 13 installers)")
    real = _saved(root / DAY13, "msi")
    if not real:
        pytest.skip(f"not run: no saved Day 13 installers under {root / DAY13}")
    return real


def test_the_saved_day13_installers_answer_their_key_plain_from_the_seed_alone():
    real = _day13()
    bad, hashes = [], []
    for name, (body, want, aid) in real.items():
        got, _ = ask("msi.product_code_guid", body, GUID, fname=name, item=aid[:len("d13-msi-001-")])
        if got != want or not plain(got):
            bad.append((name, got, want))
        md5, member = first(ask("msi.file_hash_md5", body, fname=name)[0]), first(ask("msi.cabinet_file_md5", body, fname=name)[0])
        if not md5 or md5 != member:
            hashes.append((name, md5, member))
    assert len(real) == 4 and not bad, bad
    assert not hashes, hashes


def test_the_saved_day13_question_is_covered():
    root = paths.saved_challenges_root()
    _day13()
    q = json.loads((root / DAY13 / "attempt.json").read_text())
    questions = [{**x, "answer_id": a} for x, a in zip(q["questions"], q["answer_ids"])]
    assert M.covers(questions) == [], M.covers(questions)


def test_builder_round_trip_stream_names():
    """The stream-name coder the builders use is the inverse of the reader's (else every table test is moot)."""
    RF = MSI.RF
    for name, table in (("Property", True), ("_StringPool", True), ("artifact.cab", False), ("MsiFileHash", True)):
        assert RF.msi_name(msi_stream(name, table)) == (name, table)
    db = Db()
    db.table("Property", [("Property", KEY), ("Value", 0x0F00)], [("A", "b")])
    assert len(db.streams()) == 5
