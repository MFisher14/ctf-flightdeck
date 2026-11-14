"""The schema-bundle engine (solvers/toolkits/schema_bundle.py, B-159): bundle resolution, the
per-family record, EXI / ASN.1 / bit-dictionary decoding against a bundle, the contract entry and
the CLI.

Every schema in these tests is synthetic and written here or in tests/_schema_bundle_fixtures.py;
expected bytes are laid out by hand (bit strings for EXI and UPER, TLVs for BER, an LSB-first packer
for the bit dictionaries). The tests at the end run against the operator's real bundle and are
reported as not run when it does not hold the family.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "solvers" / "toolkits"))
import schema_bundle as sb  # noqa: E402

from _schema_bundle_fixtures import (  # noqa: E402
    HANDSHAKE, HANDSHAKE_REQ, HANDSHAKE_RES, HEADER, KITCHEN, ROOT_MSG, kitchen_stream, octets, pack, text, uint, xsd)
from ctf import env as ctf_env  # noqa: E402
from ctf import event, paths  # noqa: E402

NEEDS_PYCRATE = pytest.mark.needs_tool("py:pycrate_asn1c", "py:pycrate_asn1rt")
FLAG = "CSCTF{exi_fields_decoded}"


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    root = tmp_path / "bundle"
    root.mkdir()
    monkeypatch.setenv("CTF_ASSET_SCHEMAS", str(root))
    return root


def add_exi_family(root: Path, name: str = "iso15118-2") -> Path:
    folder = root / name
    folder.mkdir()
    (folder / "V2G_CI_AppProtocol.xsd").write_text(xsd(HANDSHAKE, "urn:t:hs", "unqualified"))
    (folder / "V2G_CI_MsgDef.xsd").write_text(xsd(KITCHEN))
    return folder


def v2gtp(payload: bytes, kind: int = 0x8001) -> bytes:
    return b"\x01\xfe" + kind.to_bytes(2, "big") + len(payload).to_bytes(4, "big") + payload


def kitchen_note(note: str | None, ident: bytes = b"\x01") -> bytes:
    """<Msg seq="1"><Id>ident</Id>[<Note>note</Note>]<Head/></Msg> against KITCHEN."""
    head = [HEADER, ROOT_MSG, "01", uint(1), "0", "0", octets(ident), "0"]
    if note is None:
        head += ["010"]                      # SE(Head)=2 of Note, Alpha, Head, Zeta
    else:
        head += ["000", "0", text(note), "0", "01"]   # SE(Note); then SE(Head)=1 of Alpha, Head, Zeta
    return pack(*head, "0", "01")            # HeadType EE; no Item: EE=1


# ---- the per-family record ------------------------------------------------------------------------

def test_every_family_records_source_and_redistribution_and_the_doc_agrees():
    doc = (paths.repo_root() / "docs" / "toolkits" / "schema_bundle.md").read_text()
    rows = {}
    for line in doc.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 6 and cells[0].startswith("`") and cells[0].endswith("`"):
            rows[cells[0].strip("`")] = cells[3:]
    assert set(rows) == {f.id for f in sb.FAMILIES}
    for fam in sb.FAMILIES:
        assert fam.source and fam.licence, fam.id
        assert fam.obtainable in ("free", "paid", "restricted", "none")
        assert fam.redistributable in ("yes", "no", "unclear", "n/a")
        assert rows[fam.id] == [fam.obtainable, fam.redistributable, fam.decoder], fam.id
    # nothing is vendored: no schema file of any family is tracked beside the engine
    toolkit = paths.repo_root() / "solvers" / "toolkits"
    assert not [p for p in toolkit.iterdir() if p.suffix.lower() in (".xsd", ".asn", ".asn1")]
    assert sb.family("vmf-k").obtainable == "restricted" and sb.family("etsi-its-r2").redistributable == "yes"
    assert {f.decoder for f in sb.FAMILIES} <= {"built", "built-unverified", "blocked", "none"}
    assert all(f.note for f in sb.FAMILIES if f.decoder != "built")      # a decoder short of built says why
    with pytest.raises(sb.SchemaBundleError, match="unknown schema family"):
        sb.family("iso15118-3")


# ---- the bundle ----------------------------------------------------------------------------------

def test_bundle_root_resolves_through_the_asset_and_names_what_is_missing(tmp_path, monkeypatch):
    monkeypatch.delenv("CTF_ASSET_SCHEMAS", raising=False)
    monkeypatch.setenv("CTF_TOOLBOX_DIR", str(tmp_path / "tb"))
    with pytest.raises(sb.BundleMissing) as err:
        sb.bundle_root()
    assert str(tmp_path / "tb" / "schemas") in str(err.value) and "schema_bundle.md" in str(err.value)
    (tmp_path / "tb" / "schemas").mkdir(parents=True)
    assert sb.bundle_root() == tmp_path / "tb" / "schemas"            # the candidate under the toolbox
    mine = tmp_path / "mine"
    mine.mkdir()
    monkeypatch.setenv("CTF_ASSET_SCHEMAS", str(mine))
    assert sb.bundle_root() == mine                                    # the override wins
    monkeypatch.setenv("CTF_ASSET_SCHEMAS", str(tmp_path / "gone"))
    with pytest.raises(sb.BundleMissing, match="CTF_ASSET_SCHEMAS is set"):   # never falls through to the candidate
        sb.bundle_root()


def test_status_reports_each_family(bundle, monkeypatch):
    add_exi_family(bundle)
    (bundle / "din70121").mkdir()
    (bundle / "din70121" / "V2G_CI_MsgDef.xsd").write_text(xsd(KITCHEN))
    (bundle / "mms").mkdir()
    out = sb.status()
    by = {r["id"]: r for r in out["families"]}
    assert out["bundle"] == str(bundle) and out["bundle_error"] is None
    assert by["iso15118-2"]["state"] == "present"
    assert by["iso15118-2"]["files"] == ["V2G_CI_AppProtocol.xsd", "V2G_CI_MsgDef.xsd"]
    assert by["din70121"]["state"] == "incomplete" and "V2G_CI_AppProtocol.xsd" in by["din70121"]["detail"]
    assert by["mms"]["state"] == "incomplete" and by["etsi-its-r2"]["state"] == "missing"
    assert by["pnio"]["state"] == "not-loadable" and by["pnio"]["decoder"] == "none"
    assert by["vmf-k"]["source"] == sb.family("vmf-k").source
    monkeypatch.setenv("CTF_ASSET_SCHEMAS", str(bundle / "absent"))
    out = sb.status()
    assert out["bundle"] is None and "CTF_ASSET_SCHEMAS" in out["bundle_error"]
    assert {r["state"] for r in out["families"]} == {"no-bundle", "not-loadable"}


# ---- EXI -----------------------------------------------------------------------------------------

def test_decode_exi_picks_the_one_document_that_decodes(bundle):
    add_exi_family(bundle)
    out = sb.decode_exi(bytes.fromhex(HANDSHAKE_REQ), "iso15118-2")
    assert (out["family"], out["document"], out["schema"]) == ("iso15118-2", "app-protocol", "iso15118-2/app-protocol")
    assert {"path": "supportedAppProtocolReq/AppProtocol/ProtocolNamespace",
            "value": "urn:din:70121:2012:MsgDef"} in out["fields"]
    assert out["tree"]["name"] == "supportedAppProtocolReq"
    out = sb.decode_exi(kitchen_stream(), "iso15118-2")
    assert out["document"] == "message" and {"path": "Msg/Alpha/Delta", "value": -5} in out["fields"]
    with pytest.raises(sb.DecodeFailed, match="message: Exi"):       # named document, wrong stream
        sb.decode_exi(bytes.fromhex(HANDSHAKE_REQ), "iso15118-2", "message")
    with pytest.raises(sb.DecodeFailed, match="decodes under no document"):
        sb.decode_exi(b"\x80\xff\xff\xff\xff", "iso15118-2")
    with pytest.raises(sb.SchemaBundleError, match="no document 'body'"):
        sb.decode_exi(kitchen_stream(), "iso15118-2", "body")
    with pytest.raises(sb.SchemaBundleError, match="not an EXI family"):
        sb.decode_exi(kitchen_stream(), "mms")


def test_a_stream_that_decodes_under_several_documents_is_refused_not_guessed(bundle):
    folder = add_exi_family(bundle)
    (folder / "V2G_CI_AppProtocol.xsd").write_text(xsd(KITCHEN))       # both documents accept the stream
    with pytest.raises(sb.DecodeFailed, match=r"decodes under several documents \(app-protocol, message\); name one"):
        sb.decode_exi(kitchen_stream(), "iso15118-2")
    assert sb.decode_exi(kitchen_stream(), "iso15118-2", "message")["document"] == "message"   # naming one works


def test_a_missing_family_or_file_is_named_with_its_source(bundle):
    with pytest.raises(sb.SchemaMissing) as err:
        sb.decode_exi(kitchen_stream(), "iso15118-2")
    assert err.value.family == "iso15118-2" and err.value.path == bundle / "iso15118-2"
    assert "standards.iso.org" in str(err.value) and "redistributable: no" in str(err.value)
    folder = add_exi_family(bundle)
    (folder / "V2G_CI_MsgDef.xsd").unlink()
    with pytest.raises(sb.SchemaMissing) as err:
        sb.decode_exi(kitchen_stream(), "iso15118-2", "message")
    assert err.value.path == folder / "V2G_CI_MsgDef.xsd"
    # one document present, the stream belongs to the absent one: the failure names both facts
    with pytest.raises(sb.DecodeFailed, match="not tried: .*V2G_CI_MsgDef.xsd"):
        sb.decode_exi(kitchen_stream(), "iso15118-2")
    (folder / "V2G_CI_MsgDef.xsd").write_text(
        xsd('<xs:import namespace="urn:o" schemaLocation="V2G_CI_MsgBody.xsd"/>' + KITCHEN))
    with pytest.raises(sb.SchemaMissing) as err:                       # an import the bundle lacks
        sb.decode_exi(kitchen_stream(), "iso15118-2", "message")
    assert err.value.path.name == "V2G_CI_MsgBody.xsd"


def test_v2gtp_frames_are_split_and_each_exi_frame_decoded(bundle):
    add_exi_family(bundle)
    data = v2gtp(bytes.fromhex(HANDSHAKE_REQ)) + v2gtp(b"\x10\x00", 0x9000) + v2gtp(kitchen_stream())
    rows = sb.decode_v2gtp(data, "iso15118-2")
    assert [r["offset"] for r in rows] == [0, 8 + 34, 8 + 34 + 8 + 2]
    assert rows[0]["decoded"]["document"] == "app-protocol" and rows[2]["decoded"]["document"] == "message"
    assert "decoded" not in rows[1] and "0x9000" in rows[1]["skipped"]
    with pytest.raises(sb.DecodeFailed, match="no V2GTP header"):
        sb.split_v2gtp(b"\x01\xfd\x80\x01\x00\x00\x00\x00")
    with pytest.raises(sb.DecodeFailed, match="declares 9 payload bytes"):
        sb.split_v2gtp(b"\x01\xfe\x80\x01\x00\x00\x00\x09abc")


def test_v2gtp_split_agrees_with_the_carried_single_frame_parser():
    """split_v2gtp keeps its own multi-frame splitter (sec_evcharge_v2g.parse_v2gtp takes exactly one
    frame); on every frame of a known type the two must read the same type and payload."""
    import sec_evcharge_v2g
    data = v2gtp(bytes.fromhex(HANDSHAKE_REQ)) + v2gtp(kitchen_note("x"), 0x8002) + v2gtp(b"\x80\x40", 0x8004)
    rows = sb.split_v2gtp(data)
    assert len(rows) == 3
    for row in rows:
        frame = data[row["offset"]:row["offset"] + 8 + len(row["payload"])]
        carried = sec_evcharge_v2g.parse_v2gtp(frame)
        assert carried["payload_type"] == f"0x{row['payload_type']:04x}"
        assert carried["payload_hex"] == row["payload"].hex()
    assert [r["payload_type"] for r in rows] == [0x8001, 0x8002, 0x8004]


def test_decode_exi_against_a_named_xsd(tmp_path):
    path = tmp_path / "challenge.xsd"
    path.write_text(xsd(KITCHEN))
    out = sb.decode_exi_xsd(kitchen_note("hello"), [path])
    assert out["schema"] == "challenge.xsd" and {"path": "Msg/Note", "value": "hello"} in out["fields"]
    with pytest.raises(sb.DecodeFailed, match="ExiDecodeError"):
        sb.decode_exi_xsd(kitchen_note("hello") + b"\xff", [path])
    with pytest.raises(sb.SchemaBundleError, match="missing"):
        sb.decode_exi_xsd(kitchen_note("hello"), [tmp_path / "absent.xsd"])


# ---- ASN.1 ---------------------------------------------------------------------------------------

CDD = """
ETSI-ITS-CDD { itu-t (0) identified-organization (4) test (99) cdd (2) major-version-4 (4) minor-version-1 (1) }
DEFINITIONS AUTOMATIC TAGS ::= BEGIN
ItsPduHeader ::= SEQUENCE { protocolVersion INTEGER (0..255), messageId INTEGER (0..255),
                            stationId INTEGER (0..4294967295) }
Speed ::= INTEGER (0..16383)
END
"""
CAM = """
CAM-PDU-Descriptions { itu-t (0) identified-organization (4) test (99) cam (1) major-version-2 (2) minor-version-1 (1) }
DEFINITIONS AUTOMATIC TAGS ::= BEGIN
IMPORTS ItsPduHeader, Speed FROM ETSI-ITS-CDD
  { itu-t (0) identified-organization (4) test (99) cdd (2) major-version-4 (4) minor-version-1 (1) } WITH SUCCESSORS;
CAM ::= SEQUENCE { header ItsPduHeader, speed Speed, kind CHOICE { none NULL, tag OCTET STRING (SIZE (4)) } }
END
"""
DENM = """
DENM-PDU-Descriptions { itu-t (0) identified-organization (4) test (99) denm (3) major-version-2 (2) minor-version-1 (1) }
DEFINITIONS AUTOMATIC TAGS ::= BEGIN
IMPORTS ItsPduHeader FROM ETSI-ITS-CDD
  { itu-t (0) identified-organization (4) test (99) cdd (2) major-version-4 (4) minor-version-1 (1) } WITH SUCCESSORS;
DENM ::= SEQUENCE { header ItsPduHeader,
                    denm SEQUENCE { cause ENUMERATED { roadworks (0), accident (1), weather (2) },
                                    note IA5String (SIZE (1..32)) OPTIONAL } }
END
"""
MMS = """
MMS-Test { iso standard 9506 part (2) test (99) }
DEFINITIONS ::= BEGIN
MMSpdu ::= CHOICE { confirmed-RequestPDU [0] IMPLICIT Confirmed-RequestPDU, reject [4] IMPLICIT NULL }
Confirmed-RequestPDU ::= SEQUENCE { invokeID INTEGER, name VisibleString }
END
"""


BROKEN = """
CAM-PDU-Descriptions { itu-t (0) identified-organization (4) test (99) cam (1) }
DEFINITIONS AUTOMATIC TAGS ::= BEGIN
IMPORTS Thing FROM Absent-Mod { itu-t (0) identified-organization (4) test (99) absent (8) };
CAM ::= SEQUENCE { thing Thing }
END
"""


def header_bits(message_id: int, station: int) -> str:
    return "00000010" + f"{message_id:08b}" + f"{station:032b}"      # three constrained INTEGERs, no preamble


def cam_bytes(tag: bytes = b"flag") -> bytes:
    # speed 100 in 14 bits; CHOICE index 1 of 2 in 1 bit; a fixed-size OCTET STRING has no length
    return pack(header_bits(2, 1234), f"{100:014b}", "1", "".join(f"{b:08b}" for b in tag))


def denm_bytes(note: str) -> bytes:
    # inner SEQUENCE: 1 preamble bit (note present); ENUMERATED of 3 in 2 bits; length-1 in 5 bits; 7-bit IA5
    return pack(header_bits(1, 7), "1", "10", f"{len(note) - 1:05b}", "".join(f"{ord(c):07b}" for c in note))


def add_its_family(root: Path) -> Path:
    folder = root / "etsi-its-r2"
    folder.mkdir()
    (folder / "ETSI-ITS-CDD.asn").write_text(CDD)
    (folder / "CAM-PDU-Descriptions.asn").write_text(CAM)
    (folder / "DENM-PDU-Descriptions.asn").write_text(DENM)
    return folder


@NEEDS_PYCRATE
def test_cam_and_denm_decode_against_the_bundle_modules(bundle):
    add_its_family(bundle)
    out = sb.decode_asn1(cam_bytes(), "etsi-its-r2", "cam")
    assert (out["module"], out["pdu"], out["codec"], out["family"]) == ("CAM-PDU-Descriptions", "CAM", "uper", "etsi-its-r2")
    assert out["value"] == {"header": {"protocolVersion": 2, "messageId": 2, "stationId": 1234},
                            "speed": 100, "kind": {"tag": {"hex": b"flag".hex()}}}
    assert {"path": "kind/tag", "value": {"hex": "666c6167"}} in out["fields"] and out["canonical"] is True
    out = sb.decode_asn1(denm_bytes("ice"), "etsi-its-r2", "DENM")       # the family name is case-blind
    assert out["value"]["denm"] == {"cause": "weather", "note": "ice"}


@NEEDS_PYCRATE
def test_asn1_wrong_bytes_types_and_families_are_refused(bundle):
    with pytest.raises(sb.SchemaMissing) as err:
        sb.decode_asn1(cam_bytes(), "etsi-its-r2", "cam")
    assert err.value.path == bundle / "etsi-its-r2" and "forge.etsi.org" in str(err.value)
    folder = add_its_family(bundle)
    with pytest.raises(sb.DecodeFailed, match="follow the CAM PDU"):
        sb.decode_asn1(cam_bytes() + b"\x00\x00", "etsi-its-r2", "cam")
    with pytest.raises(sb.DecodeFailed):                               # a DENM is not a CAM
        sb.decode_asn1(denm_bytes("black ice on the bridge"), "etsi-its-r2", "cam")
    with pytest.raises(sb.SchemaBundleError, match="has no PDU 'Speed'"):
        sb.decode_asn1(cam_bytes(), "etsi-its-r2", "Speed")            # a bare Type needs a codec
    with pytest.raises(sb.SchemaBundleError, match="no ASN.1 type 'Nope'"):
        sb.decode_asn1(cam_bytes(), "etsi-its-r2", "Nope", codec="uper")
    with pytest.raises(sb.SchemaBundleError, match="codec must be"):
        sb.decode_asn1(cam_bytes(), "etsi-its-r2", "CAM", codec="xer")
    with pytest.raises(sb.SchemaBundleError, match="not an ASN.1 family"):
        sb.decode_asn1(cam_bytes(), "iso15118-2", "cam")
    for path in folder.iterdir():
        path.unlink()
    with pytest.raises(sb.SchemaMissing, match="holds no .asn file"):
        sb.decode_asn1(cam_bytes(), "etsi-its-r2", "cam")


@NEEDS_PYCRATE
def test_a_type_of_the_family_decodes_with_an_explicit_codec(bundle):
    add_its_family(bundle)
    out = sb.decode_asn1(pack(header_bits(2, 99)), "etsi-its-r2", "ETSI-ITS-CDD.ItsPduHeader", codec="uper")
    assert out["value"] == {"protocolVersion": 2, "messageId": 2, "stationId": 99} and out["module"] == "ETSI-ITS-CDD"


@NEEDS_PYCRATE
def test_mms_ber_pdu_decodes_and_trailing_bytes_are_refused(bundle):
    (bundle / "mms").mkdir()
    (bundle / "mms" / "mms.asn").write_text(MMS)
    pdu = bytes.fromhex("a008" "020105" "1a03616263")      # [0] { INTEGER 5, VisibleString "abc" }
    out = sb.decode_asn1(pdu, "mms", "mmspdu")
    assert out["value"] == {"confirmed-RequestPDU": {"invokeID": 5, "name": "abc"}} and out["codec"] == "ber"
    assert out["fields"] == [{"path": "confirmed-RequestPDU/invokeID", "value": 5},
                             {"path": "confirmed-RequestPDU/name", "value": "abc"}]
    with pytest.raises(sb.DecodeFailed):
        sb.decode_asn1(pdu + b"\x30\x00", "mms", "mmspdu")
    with pytest.raises(sb.DecodeFailed):
        sb.decode_asn1(bytes.fromhex("a108020105"), "mms", "mmspdu")   # an alternative the CHOICE lacks


PLAIN = """
Plain-Test { iso standard 9506 part (2) test (98) }
DEFINITIONS AUTOMATIC TAGS ::= BEGIN
Pair ::= SEQUENCE { n INTEGER, s OCTET STRING }
One ::= SEQUENCE { n INTEGER }
END
"""


@NEEDS_PYCRATE
def test_canonical_codecs_refuse_bytes_that_do_not_re_encode_to_themselves(tmp_path):
    """pycrate parses each of these, so only the re-encode check stands between them and a decode."""
    mod = tmp_path / "plain.asn"
    mod.write_text(PLAIN)
    good = bytes.fromhex("3006" "800105" "810161")          # Pair { n 5, s 'a' } in DER: [0] 5, [1] 'a'
    out = sb.decode_asn1_files(good, [mod], "Pair", "der")
    assert out["value"] == {"n": 5, "s": {"hex": "61"}} and out["canonical"] is True
    assert sb.decode_asn1_files(bytes.fromhex("0105"), [mod], "One", "uper")["canonical"] is True
    for data, pdu, codec in [
            (bytes.fromhex("308106" "800105" "810161"), "Pair", "der"),   # a long-form length (legal BER, not DER)
            (bytes.fromhex("3007" "80020005" "810161"), "Pair", "der"),   # an INTEGER with a leading zero octet
            (good, "One", "der"),                                         # a Pair read as One: the wrong type
            (bytes.fromhex("020005"), "One", "uper"),                     # 5 in two octets, not one
            (bytes.fromhex("020005"), "One", "oer")]:
        with pytest.raises(sb.DecodeFailed, match="do not re-encode to themselves"):
            sb.decode_asn1_files(data, [mod], pdu, codec)
    # BER has no canonical form: the long-form length decodes there, and canonical is not claimed
    out = sb.decode_asn1_files(bytes.fromhex("308106" "800105" "810161"), [mod], "Pair", "ber")
    assert out["value"] == {"n": 5, "s": {"hex": "61"}} and out["canonical"] is None


@NEEDS_PYCRATE
def test_named_module_files_ambiguity_and_compile_errors(tmp_path):
    a, b, c = tmp_path / "a.asn", tmp_path / "b.asn", tmp_path / "c.asn"
    a.write_text(CDD)
    b.write_text(CAM)
    c.write_text(CDD.replace("ETSI-ITS-CDD", "Other-CDD"))
    out = sb.decode_asn1_files(cam_bytes(b"abcd"), [a, b], "CAM-PDU-Descriptions.CAM", "uper")
    assert out["value"]["kind"] == {"tag": {"hex": "61626364"}} and out["schema"] == "a.asn, b.asn"
    with pytest.raises(sb.SchemaBundleError, match="several modules .*write Module.Type"):
        sb.decode_asn1_files(pack(header_bits(2, 1)), [a, c], "ItsPduHeader", "uper")
    bad = tmp_path / "bad.asn"
    bad.write_text("this is not ASN.1")
    with pytest.raises(sb.SchemaUnusable, match="no ASN.1 module found in bad.asn"):
        sb.decode_asn1_files(b"\x00", [bad], "X", "uper")
    bad.write_text(BROKEN)
    with pytest.raises(sb.SchemaUnusable, match="pycrate could not compile bad.asn: .*Absent-Mod"):
        sb.decode_asn1_files(b"\x00", [bad], "CAM", "uper")
    with pytest.raises(sb.SchemaBundleError, match="absent.asn is missing"):
        sb.compile_asn1([tmp_path / "absent.asn"])
    with pytest.raises(sb.SchemaBundleError, match="no ASN.1 module file"):
        sb.compile_asn1([])


def test_missing_pycrate_is_a_named_failure(bundle, monkeypatch):
    add_its_family(bundle)
    monkeypatch.setitem(sys.modules, "pycrate_asn1c.asnproc", None)   # the import now fails
    with pytest.raises(sb.ToolMissing, match="pycrate"):
        sb.decode_asn1(cam_bytes(), "etsi-its-r2", "cam")


# ---- bit dictionaries ----------------------------------------------------------------------------

DICTIONARY = {
    "message": "K99.9", "edition": "synthetic",
    "fields": [
        {"name": "Originator", "bits": 24},
        {"name": "Speed", "bits": 11, "presence": True, "codes": {"2047": "no statement"}},
        {"name": "Remark", "type": "text7", "max_chars": 5, "presence": True},
        {"name": "Waypoint", "presence": True, "repeat": 3, "fields": [
            {"name": "Latitude", "bits": 25}, {"name": "Longitude", "bits": 26}]},
        {"name": "Tag", "bits": 4, "repeat": 2},
    ],
}


def lsb(*fields: tuple[int, int]) -> bytes:
    """Pack (value, width) fields: octets in order, least significant bit first."""
    bits = [(value >> i) & 1 for value, width in fields for i in range(width)]
    out = bytearray((len(bits) + 7) // 8)
    for index, bit in enumerate(bits):
        out[index // 8] |= bit << (index % 8)
    return bytes(out)


FULL = [(0xABCDEF, 24), (1, 1), (2047, 11), (1, 1), (ord("H"), 7), (ord("I"), 7), (0x7F, 7),
        (1, 1), (1, 1), (1, 25), (2, 26), (0, 1), (3, 25), (4, 26), (1, 1), (5, 4), (0, 1), (9, 4)]


def add_vmf(root: Path, spec: dict = DICTIONARY) -> Path:
    (root / "vmf-k").mkdir(exist_ok=True)
    path = root / "vmf-k" / "K99.9.json"
    path.write_text(json.dumps(spec))
    return path


def test_bit_dictionary_presence_recurrence_text_and_codes(bundle):
    add_vmf(bundle)
    out = sb.decode_bits(lsb(*FULL), "vmf-k", "K99.9")
    assert out["values"] == {"Originator": 0xABCDEF, "Speed": 2047, "Remark": "HI",
                             "Waypoint": [{"Latitude": 1, "Longitude": 2}, {"Latitude": 3, "Longitude": 4}],
                             "Tag": [5, 9]}
    assert (out["family"], out["schema"], out["message"]) == ("vmf-k", "vmf-k/K99.9.json", "K99.9")
    rows = {r["path"]: r for r in out["fields"] if "indicator" not in r}
    assert rows["Speed"] == {"path": "Speed", "bit_offset": 25, "width_bits": 11, "value": 2047,
                             "meaning": "no statement"}
    assert rows["Remark"]["width_bits"] == 21 and rows["Waypoint[1]/Longitude"]["value"] == 4
    assert [r["indicator"] for r in out["fields"] if "indicator" in r] == [
        "FPI", "FPI", "GPI", "GRI", "GRI", "FRI", "FRI"]
    assert out["bits_consumed"] == sum(w for _v, w in FULL) and out["padding_bits"] == (-out["bits_consumed"]) % 8
    absent = sb.decode_bits(lsb((1, 24), (0, 1), (0, 1), (0, 1), (0, 1), (7, 4)), "vmf-k", "K99.9")
    assert absent["values"] == {"Originator": 1, "Tag": [7]}
    # a text field that fills max_chars has no terminator: the next field starts right after
    full = sb.decode_bits(lsb((1, 24), (0, 1), (1, 1), *[(ord(c), 7) for c in "HELLO"], (0, 1), (0, 1), (3, 4)),
                          "vmf-k", "K99.9")
    assert full["values"] == {"Originator": 1, "Remark": "HELLO", "Tag": [3]}


def test_bit_order_is_the_carried_vmf_readers(bundle):
    import sec_tdl_link22
    add_vmf(bundle)
    body = lsb(*FULL)
    reader = sec_tdl_link22._LsbReader(body)
    carried = [reader.take(24, "a")[0], reader.take(1, "b")[0], reader.take(11, "c")[0]]
    out = sb.decode_bits(body, "vmf-k", "K99.9")
    assert carried == [out["values"]["Originator"], 1, out["values"]["Speed"]] == [0xABCDEF, 1, 2047]
    msb = dict(DICTIONARY, bit_order="msb0", fields=[{"name": "a", "bits": 4}, {"name": "b", "bits": 12}])
    assert sb.bits_codec.decode(b"\xab\xcd", msb)["values"] == {"a": 0xA, "b": 0xBCD}


def test_bit_decode_failures_are_named(bundle):
    with pytest.raises(sb.SchemaMissing) as err:
        sb.decode_bits(lsb(*FULL), "vmf-k", "K99.9")
    assert "MIL-STD-6017" in str(err.value)
    path = add_vmf(bundle)
    with pytest.raises(sb.SchemaMissing) as err:
        sb.decode_bits(lsb(*FULL), "vmf-k", "K05.1")
    assert err.value.path == path.with_name("K05.1.json")
    with pytest.raises(sb.SchemaBundleError, match="plain file stem"):
        sb.decode_bits(lsb(*FULL), "vmf-k", "../K99.9")
    with pytest.raises(sb.DecodeFailed, match="ends inside Waypoint"):
        sb.decode_bits(lsb(*FULL)[:9], "vmf-k", "K99.9")
    with pytest.raises(sb.DecodeFailed, match="not zero fill"):
        sb.decode_bits(lsb(*FULL) + b"\x01", "vmf-k", "K99.9")
    # FULL is 173 bits: 3 bits of the last octet are fill, and one of them set is refused too
    assert sum(w for _v, w in FULL) == 173
    body = bytearray(lsb(*FULL))
    body[-1] |= 1 << (174 % 8)
    with pytest.raises(sb.DecodeFailed, match="3 bit\\(s\\) follow the last field and are not zero fill"):
        sb.decode_bits(bytes(body), "vmf-k", "K99.9")
    with pytest.raises(sb.DecodeFailed, match="recurs more than the dictionary's 2"):
        sb.decode_bits(lsb((1, 24), (0, 1), (0, 1), (0, 1), (1, 1), (5, 4), (1, 1), (6, 4), (0, 1), (7, 4)),
                       "vmf-k", "K99.9")
    assert sb.decode_bits(lsb(*FULL) + b"\xff", "vmf-k", "K99.9",
                          bit_length=sum(w for _v, w in FULL))["values"]["Tag"] == [5, 9]
    with pytest.raises(sb.SchemaBundleError, match="not a bit-dictionary family"):
        sb.decode_bits(lsb(*FULL), "mms", "K99.9")


@pytest.mark.parametrize("change, message", [
    ({"extra": 1}, "unknown key"),
    ({"message": ""}, "message must be"),
    ({"bit_order": "middle"}, "bit_order"),
    ({"fields": []}, "non-empty list"),
    ({"fields": [{"name": "a", "bits": 0}]}, "bits must be"),
    ({"fields": [{"name": "a", "bits": 4, "width": 4}]}, "unknown key"),
    ({"fields": [{"name": "a", "type": "text7"}]}, "max_chars"),
    ({"fields": [{"name": "a", "type": "float", "bits": 4}]}, "type must be"),
    ({"fields": [{"name": "a", "bits": 4, "repeat": 0}]}, "repeat must be"),
    ({"fields": [{"name": "a", "bits": 4, "presence": 1}]}, "presence must be"),
    ({"fields": [{"name": "g", "bits": 4, "fields": [{"name": "a", "bits": 1}]}]}, "a group cannot also set"),
    ({"fields": [{"name": "a", "bits": 4, "codes": {"x": "y"}}]}, "codes must map"),
], ids=lambda v: v if isinstance(v, str) else None)
def test_a_bad_dictionary_is_refused_by_name(bundle, change, message):
    add_vmf(bundle, dict(DICTIONARY, **change))
    with pytest.raises(sb.SchemaBundleError, match=message):
        sb.decode_bits(lsb(*FULL), "vmf-k", "K99.9")


def test_a_dictionary_that_is_not_json_is_refused(bundle):
    add_vmf(bundle).write_text("{not json")
    with pytest.raises(sb.SchemaBundleError, match="is not JSON"):
        sb.decode_bits(lsb(*FULL), "vmf-k", "K99.9")


def test_bit_dictionary_structure_and_input_limits(bundle):
    codec = sb.bits_codec
    deep: dict = {"name": "leaf", "bits": 1}
    for level in range(codec.MAX_DEPTH + 2):
        deep = {"name": f"g{level}", "fields": [deep]}
    for spec, message in [({"message": "M", "fields": [deep]}, "nest deeper"),
                          ({"message": "M", "fields": ["x"]}, "must be an object"),
                          ({"message": "M", "fields": [{"bits": 3}]}, "name must be"),
                          ({"message": "M", "fields": [{"name": "t", "type": "text7", "max_chars": 3, "bits": 7}]},
                           "not bits or codes"),
                          ({"message": "M", "fields": [{"name": "a", "bits": 4, "max_chars": 3}]}, "belongs to a text7"),
                          (["not", "an", "object"], "must be a JSON object")]:
        with pytest.raises(codec.BitDictionaryError, match=message):
            codec.check_dictionary(spec)
    with pytest.raises(codec.BitDictionaryError, match="more than"):
        codec.check_dictionary({"message": "M", "fields": [{"name": f"f{i}", "bits": 1}
                                                           for i in range(codec.MAX_FIELDS + 1)]})
    with pytest.raises(codec.BitDictionaryError, match="is missing"):
        codec.load_dictionary(bundle / "absent.json")
    one = {"message": "M", "fields": [{"name": "a", "bits": 3}]}
    for data, kw, message in [(b"", {}, "input must hold"), ("07", {}, "input must be bytes"),
                              (b"\x07", {"bit_length": 9}, "bit_length is outside"),
                              (b"\x07", {"bit_length": 0}, "bit_length is outside"),
                              (b"\x07", {"bit_length": 2}, "ends inside a")]:
        with pytest.raises(codec.BitDecodeError, match=message):
            codec.decode(data, one, **kw)
    assert codec.decode(b"\x0f", one, allow_trailing=True)["values"] == {"a": 7}     # the set 4th bit is let through
    with pytest.raises(codec.BitDecodeError, match="5 bit\\(s\\) follow"):            # but not by default
        codec.decode(b"\x0f", one)
    assert codec.decode(b"\x07", one)["padding_bits"] == 5                           # zero fill is fine
    assert codec.decode(bytearray(b"\x05"), one, bit_length=3)["padding_bits"] == 0


# ---- the contract entry --------------------------------------------------------------------------

@pytest.fixture
def profile():
    return event.load("csctf")


def challenge(tmp_path: Path, **files: bytes) -> Path:
    folder = tmp_path / "chal"
    folder.mkdir()
    for name, data in files.items():
        (folder / name).write_bytes(data)
    return folder


def test_solve_finds_a_flag_in_a_decoded_string_field(bundle, tmp_path, profile):
    add_exi_family(bundle)
    folder = challenge(tmp_path, **{"session.bin": v2gtp(bytes.fromhex(HANDSHAKE_REQ)) + v2gtp(kitchen_note(FLAG)),
                                    "readme.txt": b"an EV charging capture"})
    r = sb.solve(folder, profile, challenge_id="7")
    assert (r.status, list(r.flags), r.engine, r.challenge_id) == ("solved", [FLAG], "toolkits.schema_bundle", "7")
    assert [e.path for e in r.evidence] == ["session.bin", "session.bin"]
    assert "iso15118-2/message" in r.evidence[1].detail and FLAG in r.evidence[1].detail


def test_solve_reads_hex_text_and_a_flag_inside_a_binary_field(bundle, tmp_path, profile):
    add_exi_family(bundle, "din70121")       # only DIN is in the bundle: the ISO families are skipped by name
    folder = challenge(tmp_path, **{"body.hex": kitchen_note(None, FLAG.encode()).hex().encode() + b"\n"})
    r = sb.solve(folder, profile)
    assert (r.status, list(r.flags)) == ("solved", [FLAG])
    assert r.evidence[0].detail.startswith("din70121/message: ")
    assert r.notes == ""            # the families tried before DIN blocked nothing: the payload decoded


def test_solve_keeps_the_blocked_reasons_of_other_payloads_beside_a_decode(bundle, tmp_path, profile):
    add_exi_family(bundle)          # no etsi-its-r2 family: the ITS PDU cannot be tried (no pycrate needed)
    folder = challenge(tmp_path, **{"session.bin": v2gtp(kitchen_note(FLAG)), "cam.uper": cam_bytes()})
    r = sb.solve(folder, profile)
    assert (r.status, list(r.flags)) == ("solved", [FLAG])
    assert "cam.uper could not be tried" in r.notes and "etsi-its-r2" in r.notes and "forge.etsi.org" in r.notes
    assert "heuristic for cam.uper" in r.notes and "session.bin" not in r.notes
    (folder / "session.bin").write_bytes(v2gtp(kitchen_note("no flag here")))
    r = sb.solve(folder, profile)
    assert r.status == "unsure" and "none holds a flag-format value" in r.notes
    assert "cam.uper could not be tried" in r.notes and "etsi-its-r2" in r.notes


def test_solve_is_unsure_when_fields_decode_without_a_flag_and_none_without_payloads(bundle, tmp_path, profile):
    add_exi_family(bundle)
    folder = challenge(tmp_path, **{"a.bin": v2gtp(kitchen_note("nothing here"))})
    r = sb.solve(folder, profile)
    assert r.status == "unsure" and not r.flags and "Msg/Note" in r.evidence[0].detail
    (folder / "a.bin").write_bytes(b"plain text, not a frame")
    r = sb.solve(folder, profile)
    assert r.status == "none" and "no V2GTP frame" in r.notes
    (folder / "a.bin").write_bytes(v2gtp(b"\x80\xff\xff\xff"))            # a frame no document decodes
    r = sb.solve(folder, profile, family="iso15118-2")
    assert r.status == "none" and "decodes under no document" in r.notes


def test_solve_is_blocked_by_name_when_the_bundle_or_the_family_is_missing(bundle, tmp_path, profile, monkeypatch):
    folder = challenge(tmp_path, **{"a.bin": v2gtp(kitchen_note(FLAG))})
    r = sb.solve(folder, profile)                                          # the bundle is empty
    assert r.status == "blocked" and not r.flags
    assert "iso15118-2" in r.notes and "standards.iso.org" in r.notes and "din70121" in r.notes
    assert "heuristic" not in r.notes                                      # a V2GTP frame is no guess
    r = sb.solve(folder, profile, family="mms")
    assert r.status == "blocked" and "not an EXI family" in r.notes
    r = sb.solve(folder, profile, family="iso15118-9")
    assert r.status == "blocked" and "unknown schema family" in r.notes
    monkeypatch.setenv("CTF_ASSET_SCHEMAS", str(tmp_path / "gone"))
    r = sb.solve(folder, profile)
    assert r.status == "blocked" and "CTF_ASSET_SCHEMAS" in r.notes and "heuristic" not in r.notes
    # a file that only starts with 0x80 is a guess, and the note says so for that file alone
    (folder / "blob.dat").write_bytes(b"\x80" + bytes(range(40)))
    r = sb.solve(folder, profile)
    assert r.status == "blocked" and "CTF_ASSET_SCHEMAS" in r.notes
    assert "payload detection was heuristic for blob.dat:" in r.notes and "a.bin" not in r.notes
    monkeypatch.setenv("CTF_ASSET_SCHEMAS", str(bundle))
    (folder / "a.bin").unlink()
    r = sb.solve(folder, profile)                                          # bundle there, family missing
    assert r.status == "blocked" and "heuristic for blob.dat" in r.notes and "iso15118-2" in r.notes


@NEEDS_PYCRATE
def test_solve_decodes_an_its_release2_pdu(bundle, tmp_path, profile):
    add_its_family(bundle)
    folder = challenge(tmp_path, **{"denm.uper": denm_bytes(FLAG), "cam.uper": cam_bytes()})
    r = sb.solve(folder, profile)
    assert (r.status, list(r.flags)) == ("solved", [FLAG])
    assert sorted(e.path for e in r.evidence) == ["cam.uper", "denm.uper"]


@NEEDS_PYCRATE
def test_solve_is_blocked_when_the_bundle_modules_do_not_compile(bundle, tmp_path, profile):
    (bundle / "etsi-its-r2").mkdir()
    (bundle / "etsi-its-r2" / "CAM-PDU-Descriptions.asn").write_text(BROKEN)
    folder = challenge(tmp_path, **{"cam.uper": cam_bytes()})
    r = sb.solve(folder, profile)
    assert r.status == "blocked" and not r.evidence
    assert "etsi-its-r2" in r.notes and "pycrate could not compile" in r.notes and "Absent-Mod" in r.notes
    with pytest.raises(sb.SchemaUnusable, match="schema family 'etsi-its-r2'.*Blocked on the compiler"):
        sb.decode_asn1(cam_bytes(), "etsi-its-r2", "cam")


def test_solve_is_blocked_when_a_bundle_xsd_does_not_load(bundle, tmp_path, profile):
    folder = add_exi_family(bundle)
    (folder / "V2G_CI_MsgDef.xsd").write_text("<not-a-schema/>")
    r = sb.solve(challenge(tmp_path, **{"a.bin": v2gtp(kitchen_note(FLAG))}), profile, family="iso15118-2")
    assert r.status == "blocked" and "V2G_CI_MsgDef.xsd" in r.notes and "not xs:schema" in r.notes


def test_solve_skips_hidden_oversized_and_linked_files(bundle, tmp_path, profile):
    add_exi_family(bundle)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(v2gtp(kitchen_note(FLAG)))
    folder = challenge(tmp_path, **{".hidden.bin": v2gtp(kitchen_note(FLAG)),
                                    "big.bin": v2gtp(kitchen_note(FLAG)) + b"\x00" * sb.MAX_INPUT})
    (folder / ".cache").mkdir()
    (folder / ".cache" / "frame.bin").write_bytes(v2gtp(kitchen_note(FLAG)))
    (folder / "link.bin").symlink_to(outside)
    assert sb.solve(folder, profile).status == "none"
    (folder / "sub").mkdir()
    (folder / "sub" / "cookie.exi").write_bytes(b"$EXI" + kitchen_note(FLAG))       # a sub-folder, an EXI cookie
    r = sb.solve(folder, profile)
    assert (r.status, list(r.flags), [e.path for e in r.evidence]) == ("solved", [FLAG], ["sub/cookie.exi"])


def test_iso15118_20_payload_types_are_exi_and_inputs_are_bounded(bundle):
    add_exi_family(bundle)
    rows = sb.decode_v2gtp(v2gtp(kitchen_note("x"), 0x8002) + v2gtp(kitchen_note("y"), 0x8006) + v2gtp(b"\x00", 0x8007),
                           "iso15118-2", "message")
    assert ["decoded" in r for r in rows] == [True, True, False]
    for bad, message in [(b"", "input must hold"), ("8040", "input must be bytes"),
                         (b"\x80" * (sb.MAX_INPUT + 1), "input must hold")]:
        with pytest.raises(sb.DecodeFailed, match=message):
            sb.decode_exi(bad, "iso15118-2", "message")
    assert sb.status(bundle)["bundle"] == str(bundle)                              # an explicit root needs no asset


# ---- CLI and the runner --------------------------------------------------------------------------

def test_cli_status_exi_bits_and_named_exit(bundle, tmp_path, capsys):
    add_exi_family(bundle)
    add_vmf(bundle)
    assert sb.main(["status"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert {r["id"]: r["state"] for r in out["families"]}["iso15118-2"] == "present"
    frame = tmp_path / "frame.hex"
    frame.write_text(v2gtp(kitchen_note("cli")).hex())
    assert sb.main(["exi", str(frame), "--family", "iso15118-2"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["decoded"]["document"] == "message"
    body = tmp_path / "body.exi"
    body.write_bytes(kitchen_note("cli"))
    xsd_path = tmp_path / "k.xsd"
    xsd_path.write_text(xsd(KITCHEN))
    assert sb.main(["exi", str(body), "--xsd", str(xsd_path)]) == 0
    assert {"path": "Msg/Note", "value": "cli"} in json.loads(capsys.readouterr().out)["fields"]
    raw = tmp_path / "k.bin"
    raw.write_bytes(lsb(*FULL))
    assert sb.main(["bits", str(raw), "--message", "K99.9"]) == 0
    assert json.loads(capsys.readouterr().out)["values"]["Remark"] == "HI"
    assert sb.main(["exi", str(body), "--family", "iso15118-20"]) == 2
    err = capsys.readouterr().err
    assert "SchemaMissing" in err and "iso15118-20" in err
    assert sb.main(["exi", str(tmp_path / "nope.bin"), "--family", "iso15118-2"]) == 2


def test_cli_refuses_a_decode_without_a_schema_choice(tmp_path, capsys):
    body = tmp_path / "body.exi"
    body.write_bytes(kitchen_note("cli"))
    for argv in (["exi", str(body)], ["asn1", str(body), "--pdu", "CAM"],
                 ["asn1", str(body), "--asn", str(body), "--pdu", "CAM"]):
        with pytest.raises(SystemExit) as err:
            sb.main(argv)
        assert err.value.code == 2
    assert "needs --family or --xsd" in capsys.readouterr().err


@NEEDS_PYCRATE
def test_cli_asn1_with_named_modules(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))         # the modules are not under it
    a, b, pdu = tmp_path / "cdd.asn", tmp_path / "cam.asn", tmp_path / "cam.uper"
    a.write_text(CDD)
    b.write_text(CAM)
    pdu.write_bytes(cam_bytes())
    assert sb.main(["asn1", str(pdu), "--asn", str(a), str(b), "--pdu", "CAM", "--codec", "uper"]) == 0
    got = capsys.readouterr()
    assert json.loads(got.out)["value"]["speed"] == 100
    assert "pass only modules you trust" in got.err                    # the warning of every --asn run


def test_cli_refuses_an_asn_module_from_the_challenge_folders(tmp_path, capsys, monkeypatch):
    """No pycrate needed: the refusal comes before any compile."""
    work, corpus = tmp_path / "work", tmp_path / "corpus"
    (work / "chal").mkdir(parents=True)
    corpus.mkdir()
    monkeypatch.setenv("CTF_WORKDIR", str(work))
    monkeypatch.setenv("CTF_REALDATA", str(corpus))
    saved, rehearsal = tmp_path / "saved", tmp_path / "rehearsal"
    (saved / "day-01").mkdir(parents=True)
    rehearsal.mkdir()
    monkeypatch.setenv("CTF_REAL_CHALLENGES", str(saved))
    monkeypatch.setenv("CTF_REHEARSAL_CORPUS", str(rehearsal))
    pdu = tmp_path / "cam.uper"
    pdu.write_bytes(cam_bytes())
    for folder, label in [(work / "chal", "the work folder"), (corpus, "the real-data corpus"),
                          (saved / "day-01", "the saved challenges"), (rehearsal, "the rehearsal corpus")]:
        mod = folder / "given.asn"
        mod.write_text(CAM)
        assert sb.main(["asn1", str(pdu), "--asn", str(mod), "--pdu", "CAM", "--codec", "uper"]) == 2
        err = capsys.readouterr().err
        assert f"lies under {label}" in err and "challenge-supplied" in err and "given.asn" in err
    (tmp_path / "ok").mkdir()
    assert sb._refuse_challenge_asn([str(tmp_path / "ok" / "mine.asn")]) is None     # outside: allowed


def test_cli_asn_guard_covers_the_default_work_base_when_ctf_workdir_is_unset(tmp_path, capsys, monkeypatch):
    """With no $CTF_WORKDIR, every event's folder under ~/ctf-work holds challenge files, not only the
    current event's: a module under another event's folder is refused by the work base."""
    home = tmp_path / "home"
    other = home / "ctf-work" / "another-event" / "chal"
    other.mkdir(parents=True)
    for name in ("CTF_WORKDIR", *ctf_env.legacy_names("CTF_WORKDIR"),   # the old spellings, via ctf.env
                 "CTF_REAL_CHALLENGES", "CTF_REHEARSAL_CORPUS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("CTF_EVENT", "csctf")                           # current work folder: ~/ctf-work/csctf
    monkeypatch.setenv("CTF_REALDATA", str(tmp_path / "corpus"))
    mod = other / "given.asn"
    mod.write_text(CAM)
    pdu = tmp_path / "cam.uper"
    pdu.write_bytes(cam_bytes())
    assert sb.main(["asn1", str(pdu), "--asn", str(mod), "--pdu", "CAM", "--codec", "uper"]) == 2
    err = capsys.readouterr().err
    assert "lies under the work base" in err and str((home / "ctf-work").resolve()) in err
    (home / "mine").mkdir()
    assert sb._refuse_challenge_asn([str(home / "mine" / "ok.asn")]) is None   # beside ctf-work: allowed


@pytest.mark.parametrize("var", ["CTF_REAL_CHALLENGES", "CTF_REHEARSAL_CORPUS"])
def test_cli_asn_guard_fails_loudly_on_a_corpus_variable_that_names_no_folder(tmp_path, capsys, monkeypatch, var):
    """A typo in a corpus variable is a named failure, never read as 'nothing lies there'."""
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    monkeypatch.setenv("CTF_REALDATA", str(tmp_path / "corpus"))
    for name in ("CTF_REAL_CHALLENGES", "CTF_REHEARSAL_CORPUS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(var, str(tmp_path / "typo"))
    (tmp_path / "ok").mkdir()
    mod = tmp_path / "ok" / "mine.asn"
    mod.write_text(CAM)
    pdu = tmp_path / "cam.uper"
    pdu.write_bytes(cam_bytes())
    assert sb.main(["asn1", str(pdu), "--asn", str(mod), "--pdu", "CAM", "--codec", "uper"]) == 2
    err = capsys.readouterr().err
    assert "--asn guard cannot check" in err and var in err and "typo" in err
    assert "pass only modules you trust" not in err                    # stopped before any compile


def test_ctf_run_reaches_the_engine_through_its_manifest(bundle, tmp_path):
    add_exi_family(bundle)
    folder = challenge(tmp_path, **{"session.bin": v2gtp(kitchen_note(FLAG))})
    env = dict(os.environ, CTF_ASSET_SCHEMAS=str(bundle), CTF_EVENT="csctf")
    done = subprocess.run([sys.executable, "-m", "ctf", "run", "--no-ledger", "toolkits.schema_bundle", str(folder)],
                          cwd=paths.repo_root(), env=env, capture_output=True, text=True, timeout=600)
    assert done.returncode == 0, done.stderr[-800:]
    result = json.loads([line for line in done.stdout.splitlines() if line.strip()][-1])
    assert result["status"] == "solved" and result["flags"] == [FLAG] and result["engine"] == "toolkits.schema_bundle"


# ---- the operator's real bundle (not run without it) -------------------------------------------

def real_family(name: str) -> Path:
    try:
        root = sb.bundle_root()
    except sb.BundleMissing as exc:
        pytest.skip(f"not run: the schema bundle is not on this machine ({exc})")
    folder = root / name
    if not folder.is_dir():
        pytest.skip(f"not run: the schema bundle at {root} holds no {name} family")
    return root


def test_real_iso15118_2_handshake_and_session_setup():
    """The public handshake vector, and a SessionSetupReq laid out from the ISO 15118-2 grammar: the
    V2G_Message root is event code 76 of 7 bits (the 80 98 every ISO 15118-2 message starts with),
    SessionSetupReq is body code 29 of 6 bits (the 11 D0 after an 8-byte zero session id)."""
    root = real_family("iso15118-2")
    out = sb.decode_exi(bytes.fromhex(HANDSHAKE_REQ), "iso15118-2", "app-protocol", root)
    assert {"path": "supportedAppProtocolReq/AppProtocol/ProtocolNamespace",
            "value": "urn:din:70121:2012:MsgDef"} in out["fields"]
    assert sb.decode_exi(bytes.fromhex(HANDSHAKE_RES), "iso15118-2", None, root)["document"] == "app-protocol"
    mac = bytes.fromhex("010203040506")
    stream = pack(HEADER, "1001100",                     # V2G_Message
                  "0", "0", "0", octets(bytes(8)), "0",  # SE(Header); SE(SessionID); CH; 8 zero bytes; EE
                  "10",                                  # Header: Notification 0, Signature 1, EE 2
                  "0", "011101",                         # SE(Body); SessionSetupReq = 29 of 36
                  "0", "0", octets(mac), "0",            # SE(EVCCID); CH; the MAC; EE
                  "0", "0", "0")                         # EE SessionSetupReq, Body, V2G_Message
    assert stream[:3] == bytes.fromhex("809802") and stream[11:13] == bytes.fromhex("11d0")
    out = sb.decode_exi(stream, "iso15118-2", None, root)
    assert out["document"] == "message" and out["root"]["event_code"] == 76 and out["root"]["event_code_bits"] == 7
    got = {r["path"]: r["value"] for r in out["fields"]}
    assert got == {"V2G_Message/Header/SessionID": {"hex": "00" * 8},
                   "V2G_Message/Body/SessionSetupReq/EVCCID": {"hex": mac.hex()}}


def test_real_din70121_message_schema_loads_with_its_root_code():
    """DIN 70121 messages start 80 9A: V2G_Message is event code 77 of 7 bits."""
    root = real_family("din70121")
    schema = sb.exi_schema("din70121", "message", root)
    names = [d.qname[1] for d in schema.global_elements]
    assert names.index("V2G_Message") == 77 and len(names).bit_length() == 7


def test_real_iso15118_20_schemas_load():
    root = real_family("iso15118-20")
    for document, _file in sb.family("iso15118-20").documents:
        assert sb.exi_schema("iso15118-20", document, root).global_elements


@NEEDS_PYCRATE
@pytest.mark.xfail(strict=True, reason="pycrate 0.8.1 does not compile the real ETSI release2 CDD module (seen "
                                       "2026-11-12; docs/toolkits/schema_bundle.md): needs another ASN.1 compiler")
def test_real_etsi_release2_modules_compile_and_hold_cam_and_denm():
    root = real_family("etsi-its-r2")
    module = sb.compile_asn1(sb._asn_files(sb.family("etsi-its-r2"), root / "etsi-its-r2"))
    assert sb._find_pdu(module, "CAM")[0] == "CAM-PDU-Descriptions"
    assert sb._find_pdu(module, "DENM")[0] == "DENM-PDU-Descriptions"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
