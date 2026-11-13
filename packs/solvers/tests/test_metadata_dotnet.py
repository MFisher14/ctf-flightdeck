"""B-222: the Metadata lane's CLR/.NET reader pack, solvers/metadata-forensics/readers_dotnet.py.

Huntress Day 12 (Managed Expectations) asked dotnet.mvid_guid, the Module table's Mvid. The shipped
reader then parsed the file as a plain PE only, so a standby agent wrote a day patch. The reader that
patch became is armed in properties_strict (MORE_FILES); its Huntress test was archived at the import
(it read saved day data). This file is that test mined into pytest, plus what B-222 adds: the debug
directory's Repro / PdbChecksum / embedded-PDB entries, the namespaces, a .NET single-file bundle read
through its application assembly (B-054 takes it out), the speed solver pointed at this reader, and the
dotnet entry of the format catalog.

Every assembly is built byte by byte by ctf.formats.corpus.clr_image (narrow and wide heap indexes, a
strong-name key, a culture, managed resources, debug entries); expected values are read independently
with dnfile (pinned in requirements.in: a missing one is an error, never a skip) or are the values the
builder wrote. The judge ledger is a scratch one under tmp_path (empty), so the only judged evidence is
the tracked seed (solvers/metadata-forensics/conventions.json: dotnet_mvid_guid accepted `raw`).
The saved Day 12 files are read only when $CTF_REAL_CHALLENGES names the saved Huntress challenges;
unset, those two tests report not run.
"""
import contextlib
import hashlib
import io
import json
import logging
import struct
import uuid
import zipfile
import zlib

import dnfile          # pinned in requirements.in: the independent reading
import pytest

import ctf.formats as F
from ctf import paths
from ctf.formats import corpus as C
from ctf.formats import matrix as X

LANE = X.lane_module()
import labels  # noqa: E402  (solvers/common, on sys.path once the lane is loaded)

logging.getLogger("dnfile").setLevel(logging.CRITICAL)   # its notes on a heap's padding are not this test's
RD = LANE.MORE_MODULES["readers_dotnet.py"]
PACK = "readers_dotnet.py"
JUDGED_KEY = "metadata.format/dotnet_mvid_guid"
GUID = {"kind": "pattern", "syntax": "canonical GUID text in 8-4-4-4-12 hexadecimal form, including hyphens"}
TXT = {"kind": "exact_text", "syntax": "exact ordered artifact-derived text requested by the question"}
DAY12 = "day-12/metadata-forensics-day-12-managed-expectations"
WANT = C.CLR_MVID
PUBLIC_KEY = bytes.fromhex("0024000004800000940000000602000000240000525341310004000001000100") + bytes(range(128))
build = C.clr_image


@pytest.fixture(autouse=True)
def _lane(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))   # the runtime ledger: empty, never a played day's
    monkeypatch.delenv("CTF_JUDGE_LEDGER", raising=False)       # on: the tracked seed is read
    monkeypatch.setattr(LANE, "_day_patch", lambda: None)       # the registry is under test, not a live fix
    monkeypatch.setattr(LANE, "_unknown", lambda *a, **k: None)  # no facts page on stderr


def ask(prop, data, fmt=None, fname="managed-001.dll", item="d12-dotnet-001-"):
    """One question in Day 12's wording about one delivered file: (answer, stderr text)."""
    qid = item + prop.replace(".", "-").replace("_", "-")
    q = {"qid": qid, "answer_id": qid, "question": f"Determine {prop} for {fname}.", "artifact": f"evidence.zip -> {fname}",
         "member": fname, "answer_format": fmt or TXT}
    files = {f"evidence.zip -> {fname}": data, fname: data, "evidence.zip": b"PK\x05\x06" + b"\x00" * 18}
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        out = LANE.solve_set([q], files, {"set": 1, "delivery_name": "evidence.zip", "delivery": files["evidence.zip"]})
    return out[qid], err.getvalue()


def options(answer):
    parsed = labels.parse(answer) if isinstance(answer, str) else None
    return [tuple(o) for o in parsed.options] if parsed else []


def plain(answer):
    return answer is not None and labels.parse(answer) is None


def first(answer):
    return options(answer)[0][1] if options(answer) else None


def no_value(answer):
    return answer is None or [v for _, v in options(answer)] == ["none"]


def read(prop, data):
    """The registered reader's own value (no answer formatting): what the lane's extractor returns."""
    return LANE.lookup(LANE.canon(prop)).fn(prop, data)


# ------------------------------------------------------------------ the independent reading (dnfile)

def expected(data: bytes) -> dict:
    """{property: the value its first option must hold, or None for 'no value'} read with dnfile."""
    pe = dnfile.dnPE(data=data)
    n, mt = pe.net, pe.net.mdtables
    s = n.struct
    md = n.metadata.struct
    out = {
        "dotnet.is_managed": "true", "dotnet.clr_header_size": str(s.cb),
        "dotnet.clr_header_major_runtime_version": str(s.MajorRuntimeVersion),
        "dotnet.cor20_minor_runtime_version": str(s.MinorRuntimeVersion),
        "dotnet.clr_header_runtime_version": f"{s.MajorRuntimeVersion}.{s.MinorRuntimeVersion}",
        "dotnet.clr_header_flags": hex(s.Flags), "dotnet.corflags": hex(s.Flags), "dotnet.il_only": str(bool(s.Flags & 1)).lower(),
        "dotnet.clr_header_32bit_required": str(bool(s.Flags & 2)).lower(), "dotnet.strong_name_signed": str(bool(s.Flags & 8)).lower(),
        "dotnet.is_strongnamesigned": str(bool(s.Flags & 8)).lower(), "dotnet.32bit_preferred": str(bool(s.Flags & 0x20000)).lower(),
        "dotnet.entry_point_token": f"0x{s.EntryPointTokenOrRva:08x}", "dotnet.metadata_rva": hex(s.MetaDataRva),
        "dotnet.metadata_size": str(s.MetaDataSize), "dotnet.metadata_version": md.Version.rstrip(b"\x00").decode(),
        "dotnet.runtime_version": md.Version.rstrip(b"\x00").decode(), "dotnet.metadata_root_version": f"{md.MajorVersion}.{md.MinorVersion}",
        "dotnet.stream_count": str(md.NumberOfStreams),
        "dotnet.metadata_stream_names": ",".join(x.struct.Name.decode() for x in n.metadata.streams_list),
        "dotnet.guid_heap_count": str(n.guids.sizeof() // 16), "dotnet.strings_heap_size": str(n.strings.sizeof()),
        "dotnet.blob_stream_size_bytes": str(n.blobs.sizeof()),
        "dotnet.tables_stream_version": f"{mt.header.MajorVersion}.{mt.header.MinorVersion}",
        "dotnet.heap_sizes": hex(mt.header.HeapOffsetSizes), "dotnet.tables_valid_mask": hex(mt.header.MaskValid),
        "dotnet.table_count": str(len(mt.tables_list)), "dotnet.table_names": ",".join(t.name for t in mt.tables_list),
    }
    for t in mt.tables_list:
        out[f"dotnet.{t.name.lower()}_count"] = str(t.num_rows)
        out[f"dotnet.{RD.snake(t.name)}_table_row_count"] = str(t.num_rows)
    for absent in ("Field", "Event", "GenericParam"):
        if not getattr(mt, absent, None) or not getattr(mt, absent).num_rows:
            out[f"dotnet.{absent.lower()}_count"] = "0"
    out["dotnet.method_count"] = str(mt.MethodDef.num_rows if mt.MethodDef else 0)
    out["dotnet.number_of_type_refs"] = str(mt.TypeRef.num_rows if mt.TypeRef else 0)
    out["dotnet.typeref_count"] = out["dotnet.number_of_type_refs"]
    module = mt.Module.rows[0]
    g = uuid.UUID(str(module.Mvid))
    out.update({"dotnet.mvid": str(g), "dotnet.module_version_id": str(g), "dotnet.mvid_bytes_hex": g.bytes_le.hex(),
                "dotnet.module_name": module.Name.value})

    def rows(name):
        return getattr(mt, name).rows if getattr(mt, name, None) else []
    a = mt.Assembly.rows[0]
    key = a.PublicKey.value if a.PublicKey else b""
    out.update({"dotnet.assembly_name": a.Name.value,
                "dotnet.assembly_version": f"{a.MajorVersion}.{a.MinorVersion}.{a.BuildNumber}.{a.RevisionNumber}",
                "dotnet.assembly_major_version": str(a.MajorVersion), "dotnet.assembly_revision_number": str(a.RevisionNumber),
                "dotnet.assembly_culture": a.Culture.value or "neutral", "dotnet.assembly_public_key_length": str(len(key)),
                "dotnet.assembly_public_key": key.hex() or None, "dotnet.assembly_has_public_key": str(bool(key)).lower(),
                "dotnet.assembly_public_key_token": hashlib.sha1(key).digest()[-8:][::-1].hex() if key else None,
                "dotnet.assembly_hash_algorithm": {0x8004: "SHA1"}[a.struct.HashAlgId], "dotnet.assembly_flags": hex(a.struct.Flags)})
    refs = rows("AssemblyRef")
    vers = [f"{r.MajorVersion}.{r.MinorVersion}.{r.BuildNumber}.{r.RevisionNumber}" for r in refs]
    typedefs = rows("TypeDef")
    out.update({"dotnet.assembly_ref_names": ",".join(r.Name.value for r in refs) or None,
                "dotnet.assembly_ref_versions": ",".join(vers) or None,
                "dotnet.referenced_assemblies": ",".join(r.Name.value for r in refs) or None,
                "dotnet.assembly_ref_public_key_tokens": ",".join(r.PublicKey.value.hex() for r in refs) or None,
                "dotnet.first_assembly_ref_name": refs[0].Name.value if refs else None,
                "dotnet.last_assembly_ref_version": vers[-1] if refs else None,
                "dotnet.typedef_names": ",".join(r.TypeName.value for r in typedefs),
                "dotnet.typeref_full_names": ",".join(".".join(p for p in (r.TypeNamespace.value, r.TypeName.value) if p)
                                                      for r in rows("TypeRef")) or None,
                "dotnet.methoddef_names": ",".join(r.Name.value for r in rows("MethodDef")),
                "dotnet.memberref_names": ",".join(r.Name.value for r in rows("MemberRef")) or None})
    spaces = list(dict.fromkeys(r.TypeNamespace.value for r in typedefs if r.TypeNamespace.value))
    out["dotnet.namespaces"] = ",".join(spaces) or None
    out["dotnet.namespace_count"] = str(len(spaces))
    out["dotnet.typeref_namespaces"] = ",".join(dict.fromkeys(r.TypeNamespace.value for r in rows("TypeRef") if r.TypeNamespace.value)) or None
    res = rows("ManifestResource")
    out["dotnet.manifest_resource_names"] = ",".join(r.Name.value for r in res) or None
    out["dotnet.managed_resource_count"] = str(len(res))
    token = s.EntryPointTokenOrRva
    out["dotnet.entry_point_method_name"] = rows("MethodDef")[(token & 0xFFFFFF) - 1].Name.value if token >> 24 == 6 else None
    attrs = {}
    for r in rows("CustomAttribute"):
        if r.Parent.table is not None and r.Parent.table.name == "Assembly":
            owner, blob = r.Type.row.Class.row, r.Value.value
            text = None
            if r.Type.row.Signature.value == C.CLR_CTOR_STRING and blob[:2] == b"\x01\x00" and blob[2] != 0xFF:
                size = blob[2]   # every string of these files is shorter than 128 bytes
                text = blob[3:3 + size].decode()
            attrs.setdefault(owner.TypeName.value, []).append(text)
    names = {"AssemblyTitleAttribute": ("dotnet.assembly_title", "dotnet.title"),
             "AssemblyCompanyAttribute": ("dotnet.assembly_company", "dotnet.company_name"),
             "AssemblyProductAttribute": ("dotnet.assembly_product",), "AssemblyCopyrightAttribute": ("dotnet.assembly_copyright",),
             "AssemblyFileVersionAttribute": ("dotnet.assembly_file_version", "dotnet.file_version_attribute"),
             "AssemblyInformationalVersionAttribute": ("dotnet.assembly_informational_version", "dotnet.informational_version"),
             "TargetFrameworkAttribute": ("dotnet.target_framework", "dotnet.target_framework_attribute", "dotnet.assembly_target_framework"),
             "GuidAttribute": ("dotnet.guid_attribute", "dotnet.assembly_guid_attribute"),
             "AssemblyDescriptionAttribute": ("dotnet.assembly_description",), "AssemblyTrademarkAttribute": ("dotnet.assembly_trademark",),
             "AssemblyConfigurationAttribute": ("dotnet.assembly_configuration",)}
    for kind, props in names.items():
        for p in props:
            out[p] = attrs[kind][0] if len(attrs.get(kind, ())) == 1 else None
    out["dotnet.assembly_attribute_count"] = str(sum(len(v) for v in attrs.values()))
    return out


def fixtures():
    cv = ("9d2f3a10-77aa-4c21-8e01-aabbccddeeff", 3, r"C:\build\obj\Fixture.pdb")
    return {
        "narrow": build(),
        "wide strings and blobs": build(wide=5, name="Wide.Fixture", version=(10, 0, 65535, 7)),
        "wide guid, strong name, culture": build(wide=2, public_key=PUBLIC_KEY, culture="en-US", flags=0x9,
                                                 refs=(("System.Runtime", (8, 0, 0, 0), C.MS_TOKEN),
                                                       ("System.Console", (8, 0, 0, 1), C.MS_TOKEN))),
        "resources, codeview, display name": build(resources=("Fixture.Properties.Resources.resources", "logo.png"),
                                                   debug=((2, C.clr_codeview(*cv)),), display_name=".NET Framework 4.8",
                                                   entry=0x06000002, flags=0x20003, version_string="v2.0.50727"),
        "no attributes, no user strings": build(attrs=(), user_strings=(), entry=0),
        "namespaces and type references": build(types=(("A.B", "One"), ("", "Global"), ("A.B", "Two"), ("A.C", "Three")),
                                                typerefs=(("System", "Object"), ("System.IO", "File"))),
    }


@pytest.mark.parametrize("label", sorted(fixtures()))
def test_every_forecast_property_is_unsure_and_holds_what_dnfile_reads(label):
    data = fixtures()[label]
    bad = {}
    for prop, value in expected(data).items():
        answer, said = ask(prop, data)
        got = first(answer)
        if plain(answer) or (value is None and not no_value(answer)) or (value is not None and got != value):
            bad[prop] = (value, got if got is not None else answer, said[-200:])
    assert not bad, dict(list(bad.items())[:4])


def test_the_dnfile_cross_check_fails_on_a_wrong_value():
    """The comparison above is not vacuous: a value dnfile reads differently is caught."""
    data = build()
    want = expected(data)
    assert want["dotnet.assembly_name"] == "Corpus.Fixture" and want["dotnet.mvid"] == WANT
    answer, _ = ask("dotnet.assembly_name", build(name="Other.Name"))
    assert first(answer) != want["dotnet.assembly_name"]


# ------------------------------------------------------------------ the pack is armed

def test_the_pack_is_armed_beside_the_others_and_registered_over_nothing():
    mine = [p for p in LANE.REG.values() if getattr(p.fn, "__module__", "") == "metadata_" + PACK[:-3]]
    assert PACK in LANE.MORE_FILES and PACK in LANE.MORE_LOADED and len(mine) > 100
    assert not [p.name for p in mine if p.confirmed]                   # first-seen names stay unsure
    assert all(p.fn in LANE.TIE_FREE for p in mine)
    assert not [n for n in LANE.MORE_CLASHES if n.startswith(("dotnet", "pe."))]
    assert "dotnet" in LANE.NAMESPACES
    judged = LANE.lookup("dotnet.mvid_guid")
    assert judged.key == JUDGED_KEY and not judged.confirmed           # plain only through the seed or the ledger


def test_no_two_readers_of_dotnet_share_their_words():
    by = {}
    for k, p in LANE.REG.items():
        if k.startswith("dotnet_"):
            by.setdefault(LANE.words(k)[1], {}).setdefault(p.fn, []).append(p.name)
    clash = [sorted(sum(fns.values(), [])) for fns in by.values() if len(fns) > 1]
    assert not clash, clash[:4]


def test_a_missing_b054_engine_at_read_time_is_raised_not_an_unknown(monkeypatch, tmp_path):
    data = bundle_of([("App.dll", 1, build(name="App"))])
    monkeypatch.setattr(RD, "INTAKE", tmp_path / "missing" / "decompile_intake.py")
    monkeypatch.setattr(RD, "_INTAKE", [])
    RD._bundled.cache_clear()
    try:
        with pytest.raises(ModuleNotFoundError):
            read("dotnet.is_single_file_bundle", data)
        with pytest.raises(ModuleNotFoundError):
            read("dotnet.mvid", data)
        answer, said = ask("dotnet.mvid", data)        # the set goes on; the question is unanswered and the cause named
        assert answer is None and "ModuleNotFoundError" in said, (answer, said)
    finally:
        RD._bundled.cache_clear()


# ------------------------------------------------------------------ the builder's own values

def test_the_codeview_record_and_the_mvid_are_two_guids_under_two_names():
    cv = build(resources=("a.resources",), debug=((2, C.clr_codeview("9d2f3a10-77aa-4c21-8e01-aabbccddeeff", 3, r"C:\b\F.pdb")),),
               display_name=".NET Framework 4.8", entry=0x06000002, flags=0x20003, version_string="v2.0.50727")
    got = {p: first(ask(p, cv)[0]) for p in ("dotnet.pdb_path", "dotnet.codeview_guid", "dotnet.pdb_age", "dotnet.mvid",
                                             "dotnet.target_framework_display_name", "dotnet.metadata_version",
                                             "dotnet.entry_point_method", "dotnet.clr_header_flag_names", "dotnet.codeview_present")}
    assert got == {"dotnet.pdb_path": r"C:\b\F.pdb", "dotnet.codeview_guid": "9d2f3a10-77aa-4c21-8e01-aabbccddeeff",
                   "dotnet.pdb_age": "3", "dotnet.mvid": WANT, "dotnet.target_framework_display_name": ".NET Framework 4.8",
                   "dotnet.metadata_version": "v2.0.50727", "dotnet.entry_point_method": "Helper",
                   "dotnet.clr_header_flag_names": "COMIMAGE_FLAGS_ILONLY,COMIMAGE_FLAGS_32BITREQUIRED,COMIMAGE_FLAGS_32BITPREFERRED",
                   "dotnet.codeview_present": "true"}
    assert [v for _, v in options(ask("dotnet.metadata_version", cv)[0])] == ["v2.0.50727", "2.0.50727"]
    narrow = build()
    assert no_value(ask("dotnet.pdb_guid", narrow)[0]) and no_value(ask("dotnet.pdb_path", narrow)[0])
    assert first(ask("dotnet.codeview_present", narrow)[0]) == "false" and first(ask("dotnet.mvid", narrow)[0]) == WANT


def test_a_strong_name_token_and_a_culture():
    strong = build(wide=2, public_key=PUBLIC_KEY, culture="en-US", flags=0x9)
    token = hashlib.sha1(PUBLIC_KEY).digest()[-8:][::-1].hex()
    assert first(ask("dotnet.public_key_token", strong)[0]) == token
    assert first(ask("dotnet.assembly_culture", strong)[0]) == "en-US"
    assert RD._token(bytes.fromhex("00000000000000000400000000000000")) == "b77a5c561934e089"   # the ECMA key
    assert [v for _, v in options(ask("dotnet.assembly_culture", build())[0])] == ["neutral", "none"]


# ------------------------------------------------------------------ the judged name (Day 12)

def _q():
    return {"answer_id": "d12-dotnet-001-dotnet-mvid-guid", "question": "Determine dotnet.mvid_guid for managed-001.dll.",
            "answer_format": GUID}


def test_the_judged_name_is_plain_from_the_seed_with_no_live_patch():
    """The coverage rows' missing capability: a no-model first pass answers dotnet.mvid_guid plain."""
    assert "raw" in labels.state(JUDGED_KEY)["accepted_names"]        # the tracked seed holds Day 12's verdict
    answer, said = ask("dotnet.mvid_guid", build(), GUID)
    assert answer == WANT and plain(answer), (answer, said)
    assert LANE.covers([_q()]) == []
    assert "UNKNOWN PROPERTY" not in said and "day_patch" not in said
    other = "00112233-4455-6677-8899-aabbccddeeff"
    assert ask("dotnet.mvid_guid", build(mvid=other, wide=7), GUID)[0] == other   # the next file, every index wide


def test_without_the_judge_the_judged_name_is_unsure_with_its_one_form(monkeypatch):
    monkeypatch.setenv("CTF_JUDGE_LEDGER", "off")
    answer, said = ask("dotnet.mvid_guid", build(), GUID)
    parsed = labels.parse(answer)
    assert parsed is not None and parsed.key == JUDGED_KEY and [tuple(o) for o in parsed.options] == [("raw", WANT)], (answer, said)
    assert len(LANE.covers([_q()])) == 1


def test_a_judged_value_asked_in_another_form_is_demoted_not_sent_plain():
    """Row 280: the judged form is lowercase; a syntax text asking uppercase is not answered plain."""
    upper = {"kind": "pattern", "syntax": "GUID in uppercase 8-4-4-4-12 hexadecimal form"}
    answer, _ = ask("dotnet.mvid_guid", build(), upper)
    assert not plain(answer) and first(answer) == WANT.upper() and WANT in [v for _, v in options(answer)]


def test_its_other_spellings_stay_unsure_under_keys_of_their_own():
    data = build()
    spellings = {p: ask(p, data, GUID)[0] for p in ("dotnet.mvid", "dotnet.module_version_id", "pe.dotnet_mvid_guid", "pe.mvid",
                                                     "clr.mvid_guid", "dotnet.mvid_hex")}
    assert all(a is not None and not plain(a) and labels.parse(a).key != JUDGED_KEY for a in spellings.values()), spellings
    assert first(spellings["dotnet.mvid"]) == WANT and first(spellings["pe.mvid"]) == WANT and first(spellings["clr.mvid_guid"]) == WANT
    assert first(spellings["dotnet.mvid_hex"]) == uuid.UUID(WANT).bytes_le.hex()   # the heap's bytes as stored


FORECAST = ("dotnet.metadata_version", "dotnet.clr_header_flags", "dotnet.il_only", "dotnet.entry_point_token", "dotnet.module_name",
            "dotnet.assembly_name", "dotnet.assembly_version", "dotnet.assembly_culture", "dotnet.assembly_hash_algorithm",
            "dotnet.typedef_count", "dotnet.type_ref_count", "dotnet.methoddef_count", "dotnet.member_ref_count", "dotnet.assemblyref_count",
            "dotnet.assembly_ref_names", "dotnet.assembly_ref_versions", "dotnet.stream_names", "dotnet.stream_count",
            "dotnet.guid_heap_count", "dotnet.target_framework", "dotnet.assembly_title", "dotnet.assembly_company",
            "dotnet.assembly_product", "dotnet.assembly_copyright", "dotnet.assembly_file_version",
            "dotnet.assembly_informational_version", "dotnet.guid_attribute", "dotnet.user_string_count",
            "dotnet.manifest_resource_names", "dotnet.pdb_path", "dotnet.codeview_guid", "dotnet.codeview_age",
            "dotnet.public_key_token", "dotnet.assembly_public_key", "dotnet.mvid", "dotnet.is_managed",
            "dotnet.namespaces", "dotnet.typeref_namespaces", "dotnet.is_deterministic", "dotnet.repro_hash", "dotnet.debug_types",
            "dotnet.pdb_checksum", "dotnet.pdb_checksum_algorithm")


def _rich():
    return build(public_key=PUBLIC_KEY, resources=("a.resources",), typerefs=(("System", "Object"),),
                 debug=((2, C.clr_codeview(str(uuid.UUID(int=5)), 1, "a.pdb")), (16, C.clr_repro(b"\x07" * 32)),
                        (19, b"SHA256\x00" + b"\x09" * 32)))


def test_no_forecast_name_is_plain_even_with_the_judged_row_on_hand():
    data = _rich()
    answers = {p: ask(p, data)[0] for p in FORECAST}
    assert all(a is not None and not plain(a) for a in answers.values()), {p: a for p, a in answers.items() if a is None or plain(a)}
    assert {p: labels.parse(a).key for p, a in answers.items()} == {p: "metadata.format/" + p for p in FORECAST}
    again = {p: first(ask(p.replace("dotnet.", "pe.dotnet_", 1), data)[0]) for p in FORECAST if p != "dotnet.is_managed"}
    assert {p: v for p, v in again.items() if v != first(answers[p])} == {}
    assert first(ask("pe.clr_header_flags", data)[0]) == "0x1" and first(ask("net.assembly_name", data)[0]) == "Corpus.Fixture"
    assert first(ask("clr.metadata_version", data)[0]) == "v4.0.30319"
    assert first(ask("pe.is_dotnet", data, item="d09-pe-001-")[0]) == "true"   # the PE names registered before keep their readers
    assert first(ask("pe.pdb_age", data, item="d09-pe-001-")[0]) == "1"


# ------------------------------------------------------------------ what is not certain is no answer

def test_two_attributes_of_one_type_establish_nothing():
    twice = C.CLR_STRING_ATTRS + (("System.Reflection", "AssemblyTitleAttribute", "Another title"),)
    assert ask("dotnet.assembly_title", build(attrs=twice))[0] is None
    assert first(ask("dotnet.assembly_company", build(attrs=twice))[0]) == "Synthetic Corpus Ltd"


def test_a_constructor_that_does_not_take_one_string_is_not_read():
    assert ask("dotnet.assembly_title", build(ctor_sig=b"\x20\x02\x01\x0e\x0e"))[0] is None


def test_a_native_entry_point_is_no_token_and_no_method():
    assert ask("dotnet.entry_point_token", build(flags=0x11))[0] is None
    assert ask("dotnet.entry_point_method", build(flags=0x11))[0] is None
    assert first(ask("dotnet.entry_point_token", build(entry=0))[0]) == "0x00000000"
    assert no_value(ask("dotnet.entry_point_method", build(entry=0))[0])


def test_two_guid_streams_give_no_mvid():
    two = build(streams_twice=True)
    assert ask("dotnet.mvid_guid", two, GUID)[0] is None and ask("dotnet.mvid", two)[0] is None
    assert ask("dotnet.guid_heap_count", two)[0] is None and first(ask("dotnet.stream_count", two)[0]) == "6"


def test_a_file_cut_inside_its_metadata_establishes_nothing():
    cut = build()[:0x200 + 72 + 40]
    assert ask("dotnet.mvid_guid", cut, GUID)[0] is None
    assert ask("dotnet.assembly_name", cut)[0] is None and ask("dotnet.typedef_count", cut)[0] is None


def test_a_pe_with_no_clr_header_and_a_file_that_is_no_pe():
    native = build(clr=False)
    assert first(ask("dotnet.is_managed", native)[0]) == "false"
    assert no_value(ask("dotnet.typedef_count", native)[0]) and first(ask("dotnet.typedef_count", native)[0]) != "0"
    assert no_value(ask("dotnet.mvid_guid", native, GUID)[0]) and no_value(ask("dotnet.assembly_name", native)[0])
    assert no_value(ask("dotnet.is_deterministic", build(clr=False, debug=((16, b""),)))[0])   # a native PE's Repro is not dotnet's
    assert no_value(ask("dotnet.mvid_guid", b"%PDF-1.7\n" + b"x" * 600, GUID)[0])
    assert no_value(ask("dotnet.assembly_name", b"\x7fELF" + b"\x00" * 600)[0])


def test_a_name_the_pack_does_not_know_is_not_answered_by_a_look_alike():
    assert ask("dotnet.assembly_signature_hash", build())[0] is None and ask("dotnet.type_count", build())[0] is None


# ------------------------------------------------------------------ B-222: the debug directory's other entries

def test_a_deterministic_build_has_a_repro_entry_and_its_hash():
    digest = bytes(range(32))
    data = build(debug=((2, C.clr_codeview(str(uuid.UUID(int=3)), 1, "x.pdb")), (16, C.clr_repro(digest)), (17, b"MPDB" + b"\x00" * 12),
                        (19, b"SHA256\x00" + b"\xab" * 32)))
    assert read("dotnet.is_deterministic", data) is True and read("dotnet.has_repro_entry", data) is True
    assert read("dotnet.repro_hash", data) == digest.hex()
    assert read("dotnet.debug_types", data) == ["CODEVIEW", "REPRO", "EMBEDDED_PORTABLE_PDB", "PDBCHECKSUM"]
    assert read("dotnet.debug_entry_count", data) == 4
    assert read("dotnet.has_embedded_pdb", data) is True
    assert read("dotnet.pdb_checksum_algorithm", data) == "SHA256" and read("dotnet.pdb_checksum", data) == "ab" * 32
    assert first(ask("dotnet.repro_hash", data)[0]) == digest.hex()


def test_a_repro_entry_with_no_data_is_deterministic_with_no_hash():
    data = build(debug=((16, C.clr_repro()),))
    assert read("dotnet.is_deterministic", data) is True and read("dotnet.repro_hash", data) is None
    assert read("dotnet.has_embedded_pdb", data) is False and read("dotnet.pdb_checksum", data) is None


def test_a_build_with_no_repro_entry_is_not_deterministic():
    assert read("dotnet.is_deterministic", build(debug=((2, C.clr_codeview(str(uuid.UUID(int=3)), 1, "x.pdb")),))) is False
    assert read("dotnet.is_deterministic", build()) is False and read("dotnet.debug_types", build()) is None
    assert read("dotnet.debug_entry_count", build()) == 0


@pytest.mark.parametrize("debug, prop", [
    (((16, C.clr_repro(b"\x01" * 8)), (16, C.clr_repro(b"\x02" * 8))), "dotnet.repro_hash"),   # two Repro entries
    (((16, struct.pack("<I", 40) + b"\x01" * 8),), "dotnet.repro_hash"),                       # a length past its data
    (((16, struct.pack("<I", 0)),), "dotnet.repro_hash"),                                      # a length of nothing
    (((19, b"\x00" + b"\x01" * 32),), "dotnet.pdb_checksum_algorithm"),                        # no algorithm name
    (((19, b"SHA256\x00"),), "dotnet.pdb_checksum"),                                           # no checksum
    (((99, b""),), "dotnet.debug_types"),                                                      # a type nobody names
])
def test_a_debug_entry_that_does_not_settle_its_fact_is_unknown(debug, prop):
    with pytest.raises(LANE.Unknown):
        read(prop, build(debug=debug))
    assert ask(prop, build(debug=debug))[0] is None


def test_a_debug_directory_that_is_not_whole_entries_is_unknown():
    data = bytearray(build(debug=((16, b""),)))
    x = RD.RM._pex(bytes(data))
    opt = x["at"] + 24
    struct.pack_into("<I", data, opt + 96 + 6 * 8 + 4, 30)        # the debug directory's size: 30, not 28
    with pytest.raises(LANE.Unknown, match="whole number of entries"):
        read("dotnet.is_deterministic", bytes(data))


def _debug_entry_at(data: bytes, i: int) -> int:
    """The file offset of the debug directory's i-th 28-byte entry."""
    x = RD.RM._pex(data)
    rva, size = x["dirs"][6]
    return RD._off(x, data, rva, size) + 28 * i


def test_a_debug_entry_whose_data_runs_past_the_file_is_unknown_not_a_cut_value():
    good = build(debug=((19, b"SHA256\x00" + b"\xab" * 32),))
    assert read("dotnet.pdb_checksum", good) == "ab" * 32
    data = bytearray(good)
    at = _debug_entry_at(good, 0)
    _typ, sz, _rva, ptr = struct.unpack_from("<IIII", data, at + 12)
    assert ptr + sz <= len(data)
    struct.pack_into("<I", data, at + 16, len(data) - ptr + 1)     # SizeOfData: one byte past the end of the file
    for prop in ("dotnet.pdb_checksum", "dotnet.pdb_checksum_algorithm", "dotnet.debug_types"):
        with pytest.raises(LANE.Unknown, match="runs past the file"):
            read(prop, bytes(data))
    assert ask("dotnet.pdb_checksum", bytes(data))[0] is None


def test_a_debug_directory_of_more_entries_than_are_read_is_unknown():
    data = bytearray(build(debug=((16, b""),)))
    x = RD.RM._pex(bytes(data))
    opt = x["at"] + 24
    struct.pack_into("<I", data, opt + 96 + 6 * 8 + 4, (RD.DEBUG_ENTRIES + 1) * 28)
    with pytest.raises(LANE.Unknown, match="more debug entries than are read"):
        read("dotnet.debug_entry_count", bytes(data))
    struct.pack_into("<I", data, opt + 96 + 6 * 8 + 4, 28)        # the same file with its one entry: read
    assert read("dotnet.debug_entry_count", bytes(data)) == 1


# ------------------------------------------------------------------ B-222: namespaces

def test_namespaces_are_distinct_in_table_order_and_the_global_one_is_left_out():
    data = build(types=(("A.B", "One"), ("", "Global"), ("A.B", "Two"), ("A.C", "Three")),
                 typerefs=(("System", "Object"), ("System.IO", "File"), ("System", "Console")), attrs=())
    assert read("dotnet.namespaces", data) == ["A.B", "A.C"]
    assert read("dotnet.namespace_count", data) == 2
    assert read("dotnet.typeref_namespaces", data) == ["System", "System.IO"]
    assert first(ask("dotnet.typedef_namespaces", data)[0]) == "A.B,A.C"


def test_an_assembly_whose_types_are_all_global_has_no_namespace():
    data = build(types=(("", "Program"),), attrs=())
    assert read("dotnet.namespaces", data) is None and read("dotnet.namespace_count", data) == 0
    assert read("dotnet.typeref_namespaces", data) is None


# ------------------------------------------------------------------ B-222: a single-file bundle (B-054 takes the assembly out)

def _bwstr(s: str) -> bytes:
    b = s.encode()
    n, out = len(b), bytearray()
    while True:
        x, n = n & 0x7F, n >> 7
        out.append(x | 0x80 if n else x)
        if not n:
            return bytes(out) + b


def bundle_of(members, *, major=6, apphost=None, deflate=(), sizes=None, broken=()):
    """A .NET single-file bundle: an apphost (a native PE by default) with `members` [(path, type, body)]
    appended (1 assembly, 3 deps.json, 4 runtimeconfig.json), those named in `deflate` stored raw-deflated
    (.NET 6+), then the signature with the header offset before it, then the manifest. `sizes` {path: n}
    writes n as a member's manifest size instead of its length; a deflated member named in `broken` is
    stored as bytes that are no deflate stream (0xFF: block type 3, which zlib refuses)."""
    sig = RD._intake()._runtime_facts().BUNDLE_SIG
    blob = bytearray(apphost if apphost is not None else build(clr=False, mvid=str(uuid.UUID(int=9))))
    placed = []
    for path, kind, body in members:
        stored = body
        if path in deflate:
            z = zlib.compressobj(9, zlib.DEFLATED, -15)
            stored = z.compress(body) + z.flush()
            if path in broken:
                stored = b"\xff" * len(stored)
        size = (sizes or {}).get(path, len(body))
        placed.append((path, kind, len(blob), size, len(stored) if path in deflate else 0))
        blob += stored
    at = len(blob)
    blob += b"\x00" * 8 + sig
    header = len(blob)
    man = struct.pack("<IIi", major, 0, len(placed)) + _bwstr("bundle-id-b222") + (b"\x00" * 40 if major >= 2 else b"")
    for path, kind, offset, size, packed in placed:
        man += struct.pack("<qq", offset, size) + (struct.pack("<q", packed) if major >= 6 else b"") + bytes([kind]) + _bwstr(path)
    blob += man
    struct.pack_into("<q", blob, at, header)
    return bytes(blob)


APP_MVID = "a1b2c3d4-0000-4000-8000-0000000000aa"
LIB_MVID = "b1b2c3d4-0000-4000-8000-0000000000bb"


def _app_bundle(**kw):
    app, lib = build(name="App", mvid=APP_MVID), build(name="Helpers", mvid=LIB_MVID)
    return bundle_of([("Helpers.dll", 1, lib), ("App.dll", 1, app), ("App.deps.json", 3, b'{"runtimeTarget":{}}'),
                      ("App.runtimeconfig.json", 4, b"{}"), ("System.Private.CoreLib.dll", 1, build(name="System.Private.CoreLib"))], **kw)


def test_a_bundle_is_read_through_the_assembly_its_deps_json_names():
    data = _app_bundle()
    assert RD._clr(data) == ()                                         # the apphost itself is a native PE
    answer, said = ask("dotnet.mvid_guid", data, GUID, fname="App.exe")
    assert answer == APP_MVID and plain(answer), (answer, said)        # the seed's verdict holds for the bundled assembly
    assert first(ask("dotnet.assembly_name", data, fname="App.exe")[0]) == "App"
    assert read("dotnet.is_managed", data) is True
    assert read("dotnet.bundle_entry_assembly", data) == "App.dll"
    assert read("dotnet.is_single_file_bundle", data) is True
    assert read("dotnet.bundle_version", data) == "6.0" and read("dotnet.bundle_id", data) == "bundle-id-b222"
    assert read("dotnet.bundle_file_count", data) == 5
    assert read("dotnet.bundle_file_names", data)[:2] == ["Helpers.dll", "App.dll"]


def test_a_deflated_application_assembly_is_inflated_by_b054():
    data = _app_bundle(deflate=("App.dll",))
    assert build(name="App", mvid=APP_MVID) not in data               # the assembly is only in the bundle deflated
    assert read("dotnet.mvid_guid", data) == APP_MVID
    assert first(ask("dotnet.assembly_name", data, fname="App.exe")[0]) == "App"


def test_a_bundle_on_an_elf_apphost_is_read_too():
    data = _app_bundle(apphost=b"\x7fELF\x02\x01\x01" + b"\x00" * 249)
    assert read("dotnet.mvid_guid", data) == APP_MVID and read("dotnet.is_single_file_bundle", data) is True


def test_a_bundle_without_deps_json_is_read_through_its_one_application_assembly():
    data = bundle_of([("Tool.dll", 1, build(name="Tool", mvid=APP_MVID)), ("Microsoft.Extensions.Logging.dll", 1, build(name="M")),
                      ("Tool.resources.dll", 1, build(name="Tool.resources"))])
    assert read("dotnet.mvid_guid", data) == APP_MVID and read("dotnet.bundle_entry_assembly", data) == "Tool.dll"


@pytest.mark.parametrize("members, why", [
    ([("A.dll", 1, build(name="A")), ("B.dll", 1, build(name="B"))], "2 application assemblies"),
    ([("A.dll", 1, build(name="A")), ("Gone.deps.json", 3, b"{}")], "names Gone.dll"),
    ([("A.dll", 1, build(name="A")), ("A.deps.json", 3, b"{}"), ("B.runtimeconfig.json", 4, b"{}")], "two applications"),
    ([("A.dll", 1, build(name="A", clr=False)), ("A.deps.json", 3, b"{}")], "no CLR header"),
])
def test_a_bundle_whose_application_assembly_is_not_settled_is_no_answer(members, why):
    data = bundle_of(members)
    with pytest.raises(LANE.Unknown, match=why):
        read("dotnet.mvid", data)
    assert ask("dotnet.mvid_guid", data, GUID, fname="App.exe")[0] is None


@pytest.mark.parametrize("extra", [100, -100])
def test_a_deflated_assembly_whose_inflated_length_is_not_its_manifest_size_is_no_answer(extra):
    # B-054's dotnet_bundle keeps only entries that lie inside the file, so the one way a member comes out
    # short or long is a deflated one that inflates to another length than the manifest says: it is not
    # the file the bundler stored, and reading it anyway would answer from bytes the manifest disowns.
    app = build(name="App", mvid=APP_MVID)
    data = _app_bundle(deflate=("App.dll",), sizes={"App.dll": len(app) + extra})
    assert dict(RD._intake().bundle_members(data))["App.dll"] == app       # B-054 hands out the whole assembly
    with pytest.raises(LANE.Unknown, match="not taken out of it whole"):
        read("dotnet.mvid_guid", data)
    assert ask("dotnet.mvid_guid", data, GUID, fname="App.exe")[0] is None


def test_a_deflated_assembly_b054_cannot_inflate_is_not_read_from_its_raw_slice():
    # The manifest's own slice stands in only for a member stored as it is: a deflated one's slice is
    # compressed bytes (here followed by the next members), never the assembly.
    data = _app_bundle(deflate=("App.dll",), broken=("App.dll",))
    assert "App.dll" not in dict(RD._intake().bundle_members(data))      # zlib refuses it: B-054 withholds it
    info = RD._bundle(data)
    entry = next(f for f in info["files"] if f["path"] == "App.dll")
    assert entry["compressed"] and entry["offset"] + entry["size"] <= len(data)   # the raw slice is whole-length
    with pytest.raises(LANE.Unknown, match="not taken out of it whole"):
        read("dotnet.mvid_guid", data)


def test_a_managed_pe_is_read_as_itself_and_is_no_bundle():
    data = build()
    assert read("dotnet.is_single_file_bundle", data) is False and read("dotnet.bundle_entry_assembly", data) is None
    assert read("dotnet.is_single_file_bundle", build(clr=False)) is False
    assert read("dotnet.is_single_file_bundle", b"%PDF-1.7\n" + b"x" * 600) is None
    # A managed PE that carries a bundle-looking tail is still read as itself, not as the tail's assembly.
    tail = bundle_of([("App.dll", 1, build(name="App", mvid=APP_MVID)), ("App.deps.json", 3, b"{}")], apphost=data)
    assert read("dotnet.mvid_guid", tail) == WANT


def test_an_executable_with_no_bundle_and_no_clr_header_is_unmanaged():
    assert read("dotnet.is_managed", build(clr=False)) is False and read("dotnet.mvid", build(clr=False)) is None


# ------------------------------------------------------------------ the speed solver reads through this pack

def test_the_speed_solver_reads_the_mvid_through_the_lane_reader():
    from speedrun.solvers import metadata_d12
    assert metadata_d12.dotnet_mvid("a.dll", build(mvid=LIB_MVID, wide=7)) == LIB_MVID
    assert metadata_d12.dotnet_mvid("App.exe", _app_bundle(deflate=("App.dll",))) == APP_MVID   # only the lane's reader reads bundles
    assert metadata_d12.dotnet_mvid("a.dll", build(streams_twice=True)) is None
    assert metadata_d12.dotnet_mvid("a.dll", build(clr=False)) is None
    assert RD.read_mvid(build()) == WANT


def test_read_mvid_refuses_before_the_lane_registers_it(monkeypatch):
    monkeypatch.setattr(RD, "M", None)
    with pytest.raises(RuntimeError, match="not registered"):
        RD.read_mvid(build())


# ------------------------------------------------------------------ the format catalog's dotnet entry

def test_the_catalog_has_a_dotnet_format_identified_from_the_bytes():
    cat = F.load()
    fmt = next(f for f in cat if f.id == "dotnet")
    assert fmt.namespaces == ("dotnet",) and "dotnet_assembly" in fmt.samples
    assert [(m.format, m.sure) for m in F.identify("App.dll", build(), cat)] == [("dotnet", True)]
    assert [(m.format, m.sure) for m in F.identify("native.dll", build(clr=False), cat)] == [("dotnet", False)]
    assert F.identify("blob.bin", build(clr=False), cat) == []
    broken = bytearray(build())
    broken[broken.find(b"BSJB")] = ord("X")                            # the CLR header points at no metadata root
    assert F.identify("blob.bin", bytes(broken), cat) == []
    assert F.identify("cut.bin", build()[:0x180], cat) == []
    short = bytearray(build())
    x = RD.RM._pex(bytes(short))
    struct.pack_into("<I", short, x["at"] + 24 + 96 + 14 * 8 + 4, 8)   # a CLR directory shorter than the 72-byte header
    assert F.identify("blob.bin", bytes(short), cat) == []
    few = bytearray(build())
    assert struct.unpack_from("<I", few, x["at"] + 24 + 92)[0] >= 15
    struct.pack_into("<I", few, x["at"] + 24 + 92, 14)                 # NumberOfRvaAndSizes 14: entry 14 is not a directory
    assert F.identify("blob.bin", bytes(few), cat) == []


# ------------------------------------------------------------------ the saved Day 12 files (not run without them)

def _day12():
    root = paths.saved_challenges_root()
    if root is None:
        pytest.skip("not run: CTF_REAL_CHALLENGES is not set (the saved Huntress Day 12 assemblies)")
    out = {}
    for sub in ("", "time_trial", "mastery"):
        folder = root / DAY12 / sub
        if not (folder / "key.json").is_file():
            continue
        key = json.loads((folder / "key.json").read_text())
        key = key.get("answers", key) if isinstance(key, dict) else {}
        for z in sorted((folder / "artifact").glob("*.zip")):
            members = {}
            with zipfile.ZipFile(z) as zf:
                for name in zf.namelist():
                    body = zf.read(name)
                    if name.endswith(".zip"):
                        with zipfile.ZipFile(io.BytesIO(body)) as inner:
                            members.update({m: inner.read(m) for m in inner.namelist()})
                    else:
                        members[name] = body
            for name, body in members.items():
                number = name.rsplit("-", 1)[-1].split(".")[0]
                answers = [v for k, v in key.items() if f"-dotnet-{number}-" in k and isinstance(v, str)]
                if len(answers) == 1:
                    out[name] = (body, answers[0])
    if not out:
        pytest.skip(f"not run: no saved Day 12 assemblies under {root / DAY12}")
    return out


def test_the_saved_day12_files_answer_their_key_plain_from_the_seed_alone():
    real = _day12()
    assert len(real) == 4, sorted(real)            # base, time trial and the two mastery sets
    bad = {name: (want, ask("dotnet.mvid_guid", body, GUID, fname=name)[0]) for name, (body, want) in real.items()}
    assert {name: v for name, v in bad.items() if v[0] != v[1] or not plain(v[1])} == {}


def test_the_saved_day12_files_agree_with_dnfile():
    real = _day12()
    for name, (body, _) in real.items():
        want = expected(body)
        got = {p: first(ask(p, body, fname=name)[0]) for p in ("dotnet.mvid", "dotnet.assembly_name", "dotnet.module_name",
                                                               "dotnet.metadata_version", "dotnet.typedef_count")}
        assert got == {p: want[p] for p in got}, name
