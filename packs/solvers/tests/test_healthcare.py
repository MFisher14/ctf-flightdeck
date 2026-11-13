#!/usr/bin/env python3
"""solvers/toolkits/healthcare.py: the DICOM / HL7 v2 / FHIR offline reader.

Offline, no network, no token. Every fixture below is SYNTHETIC and SPEC-DERIVED: the DICOM byte
streams are built here by hand from the Part-10 grammar (preamble + DICM, Explicit-VR-LE File Meta,
and a data set in each of Implicit VR LE / Explicit VR LE / Explicit VR BE / Deflated), the HL7 and
FHIR messages are written out as text, and the capture is assembled with scapy. The parser is then
asserted to read the known field values back. Where scapy ships a dissector (the DICOM upper-layer
protocol in scapy.contrib.dicom) the AE titles are cross-checked against it. No real PHI, no real flag.

  CTF_WORKDIR=/tmp/ctfws .venv/bin/python tests/test_healthcare.py

Coverage:
  dicom      Explicit VR LE, Implicit VR LE, Explicit VR BE, Deflated Explicit VR LE; key tags named
             (PatientName/ID, Modality, StudyDescription); PixelData presence+length (native and
             encapsulated); SQ recursion; private (odd group) / overlay (60xx) / free-text tags; a
             flag hidden in a comment, a private tag and a nested sequence is highlighted; a bare
             data set with no preamble still parses
  hl7        MSH field-separator / encoding-char handling (MSH-1/MSH-2 special case), fields ->
             repetitions -> components -> subcomponents, MLLP (0x0B..0x1C0x0D) framing stripped
  fhir       JSON resource + Bundle (entries walked), XML resource (value attributes scanned)
  pcap       scapy reassembles TCP flows (incl. out-of-order segments); DICOM A-ASSOCIATE AE titles
             (cross-checked vs scapy.contrib.dicom) + presentation/transfer syntaxes, HL7-over-MLLP,
             FHIR in an HTTP body are all dissected and their flags surfaced
  adversarial random / empty / non-MSH / truncated DICOM never crash; raw flag scan still fires
  cli        the command prints the decode with the flag highlighted and emits valid --json
"""
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import paths
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[1]))
    from ctf import paths

REPO = Path(__file__).resolve().parent.parent
os.environ.setdefault("CTF_WORKDIR", tempfile.mkdtemp(prefix="test_healthcare_"))
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.dont_write_bytecode = True

import healthcare as H                                        # noqa: E402

PY = sys.executable
FAILED = []


def check(label, cond, detail=None):
    if cond:
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}" + (f"   [{detail}]" if detail is not None else ""))
        FAILED.append(label)


# ----------------------------------------------------------------- DICOM byte-stream builders (spec)

_LONG = H._VR_LONG


def _el(g, e, vr, val, little=True):
    """One Explicit-VR data element."""
    end = "<" if little else ">"
    hdr = struct.pack(end + "HH", g, e) + vr.encode()
    if vr in _LONG:
        hdr += b"\x00\x00" + struct.pack(end + "I", len(val))
    else:
        hdr += struct.pack(end + "H", len(val))
    return hdr + val


def _eli(g, e, val, little=True):
    """One Implicit-VR data element (tag + 4-byte length + value)."""
    end = "<" if little else ">"
    return struct.pack(end + "HH", g, e) + struct.pack(end + "I", len(val)) + val


def _pad_ui(s):
    b = s.encode()
    return b + (b"\x00" if len(b) % 2 else b"")


def _pad_sp(s):
    b = s.encode()
    return b + (b" " if len(b) % 2 else b"")


def _part10(ts_uid, dataset, deflate=False):
    """A Part-10 file: 128-byte preamble + DICM + Explicit-VR-LE File Meta (with a correct group
    length) + the data set, optionally raw-deflated for the Deflated Explicit VR LE transfer syntax."""
    meta_tail = _el(0x0002, 0x0010, "UI", _pad_ui(ts_uid))
    meta_tail += _el(0x0002, 0x0002, "UI", _pad_ui("1.2.840.10008.5.1.4.1.1.2"))
    gl = _el(0x0002, 0x0000, "UL", struct.pack("<I", len(meta_tail)))
    body = dataset
    if deflate:
        import zlib
        co = zlib.compressobj(9, zlib.DEFLATED, -15)
        body = co.compress(dataset) + co.flush()
    return b"\x00" * 128 + b"DICM" + gl + meta_tail + body


# ----------------------------------------------------------------- DICOM tests

def test_dicom_explicit_le():
    ds = b"".join([
        _el(0x0008, 0x0060, "CS", _pad_sp("CT")),
        _el(0x0010, 0x0010, "PN", _pad_sp("DOE^JANE^Q")),
        _el(0x0010, 0x0020, "LO", _pad_sp("PID00042")),
        _el(0x0008, 0x1030, "LO", _pad_sp("Chest CT")),
        _el(0x0020, 0x4000, "LT", _pad_sp("note csctf{explicit_le_comment}")),
        _el(0x0009, 0x0010, "LO", _pad_sp("csctf{private_block}")),       # odd group -> private
        _el(0x6000, 0x0022, "LO", _pad_sp("csctf{overlay_desc}")),        # 60xx -> overlay
        _el(0x7FE0, 0x0010, "OW", b"\xAB\xCD" * 8),                       # native pixel data (16 B)
    ])
    r = H.parse_dicom(_part10("1.2.840.10008.1.2.1", ds))
    vals = {x["keyword"]: x["value"] for x in r["elements"] if x["keyword"]}
    check("explicit-LE: transfer syntax read", r["transfer_syntax"] == "1.2.840.10008.1.2.1", r["transfer_syntax"])
    check("explicit-LE: encoding flags", r["explicit_vr"] is True and r["little_endian"] is True)
    check("explicit-LE: Modality=CT", vals.get("Modality") == "CT", vals.get("Modality"))
    check("explicit-LE: PatientName kept with ^ components", vals.get("PatientName") == "DOE^JANE^Q",
          vals.get("PatientName"))
    check("explicit-LE: PatientID=PID00042", vals.get("PatientID") == "PID00042", vals.get("PatientID"))
    check("explicit-LE: StudyDescription", vals.get("StudyDescription") == "Chest CT")
    check("explicit-LE: PixelData present, 16 bytes, native",
          r["pixel_data"] and r["pixel_data"]["length"] == 16 and not r["pixel_data"]["encapsulated"],
          r["pixel_data"])
    priv = [x for x in r["elements"] if x.get("private")]
    overlay = [x for x in r["elements"] if x.get("overlay")]
    check("explicit-LE: private tag flagged", any(x["tag"] == "(0009,0010)" for x in priv), priv)
    check("explicit-LE: overlay tag flagged", any(x["tag"] == "(6000,0022)" for x in overlay), overlay)
    want = {"csctf{explicit_le_comment}", "csctf{private_block}", "csctf{overlay_desc}"}
    check("explicit-LE: flags from comment + private + overlay", want <= set(r["flags"]), r["flags"])


def test_dicom_implicit_le():
    ds = b"".join([
        _eli(0x0008, 0x0060, _pad_sp("MR")),
        _eli(0x0010, 0x0010, _pad_sp("ROE^RICHARD")),
        _eli(0x0020, 0x4000, _pad_sp("csctf{implicit_vr_flag}")),
    ])
    r = H.parse_dicom(_part10("1.2.840.10008.1.2", ds))
    vals = {x["keyword"]: x["value"] for x in r["elements"] if x["keyword"]}
    check("implicit-LE: encoding flags", r["explicit_vr"] is False and r["little_endian"] is True)
    check("implicit-LE: Modality=MR (VR from dictionary)", vals.get("Modality") == "MR", vals.get("Modality"))
    check("implicit-LE: PatientName", vals.get("PatientName") == "ROE^RICHARD")
    check("implicit-LE: flag in comment", "csctf{implicit_vr_flag}" in r["flags"], r["flags"])


def test_dicom_explicit_be():
    ds = b"".join([
        _el(0x0008, 0x0060, "CS", _pad_sp("US"), little=False),
        _el(0x0010, 0x0010, "PN", _pad_sp("BIG^ENDIAN"), little=False),
        _el(0x0028, 0x0010, "US", struct.pack(">H", 512), little=False),     # Rows=512
        _el(0x0020, 0x4000, "LT", _pad_sp("csctf{big_endian_flag}"), little=False),
    ])
    r = H.parse_dicom(_part10("1.2.840.10008.1.2.2", ds))
    vals = {x["keyword"]: x["value"] for x in r["elements"] if x["keyword"]}
    check("explicit-BE: encoding flags", r["explicit_vr"] is True and r["little_endian"] is False,
          (r["explicit_vr"], r["little_endian"]))
    check("explicit-BE: Modality=US", vals.get("Modality") == "US", vals.get("Modality"))
    check("explicit-BE: Rows=512 (big-endian US)", vals.get("Rows") == "512", vals.get("Rows"))
    check("explicit-BE: flag", "csctf{big_endian_flag}" in r["flags"], r["flags"])


def test_dicom_deflated():
    ds = b"".join([
        _el(0x0008, 0x0060, "CS", _pad_sp("CT")),
        _el(0x0020, 0x4000, "LT", _pad_sp("csctf{deflated_flag}")),
    ])
    r = H.parse_dicom(_part10("1.2.840.10008.1.2.1.99", ds, deflate=True))
    vals = {x["keyword"]: x["value"] for x in r["elements"] if x["keyword"]}
    check("deflated: inflated + Modality=CT", vals.get("Modality") == "CT", vals.get("Modality"))
    check("deflated: flag recovered after inflate", "csctf{deflated_flag}" in r["flags"], r["flags"])


def test_dicom_sequence_and_encapsulated():
    # Defined-length SQ (0008,1115) holding one item with a nested comment carrying a flag.
    inner = _el(0x0020, 0x4000, "LT", _pad_sp("csctf{nested_in_sequence}"))
    item = struct.pack("<HH", 0xFFFE, 0xE000) + struct.pack("<I", len(inner)) + inner
    sq = _el(0x0008, 0x1115, "SQ", item)
    # Encapsulated PixelData: undefined length, basic offset table item + one fragment item.
    bot = struct.pack("<HH", 0xFFFE, 0xE000) + struct.pack("<I", 0)
    frag_data = b"\xDE\xAD\xBE\xEF" * 4
    frag = struct.pack("<HH", 0xFFFE, 0xE000) + struct.pack("<I", len(frag_data)) + frag_data
    seq_end = struct.pack("<HH", 0xFFFE, 0xE0DD) + struct.pack("<I", 0)
    pixel = struct.pack("<HH", 0x7FE0, 0x0010) + b"OB" + b"\x00\x00" + struct.pack("<I", 0xFFFFFFFF) \
        + bot + frag + seq_end
    ds = _el(0x0008, 0x0060, "CS", _pad_sp("CT")) + sq + pixel
    r = H.parse_dicom(_part10("1.2.840.10008.1.2.1", ds))
    sqs = [x for x in r["elements"] if x.get("vr") == "SQ"]
    check("sequence: SQ element parsed with one item", sqs and len(sqs[0]["items"]) == 1, sqs)
    check("sequence: flag found inside nested item", "csctf{nested_in_sequence}" in r["flags"], r["flags"])
    check("encapsulated: PixelData marked encapsulated",
          r["pixel_data"] and r["pixel_data"]["encapsulated"] and r["pixel_data"]["length"] == 16,
          r["pixel_data"])


def test_dicom_bare_dataset():
    bare = _eli(0x0008, 0x0060, _pad_sp("CT")) + _eli(0x0020, 0x4000, _pad_sp("csctf{bare_dataset}"))
    r = H.analyze(bare, "bare.raw")
    vals = {x["keyword"]: x["value"] for x in r.get("elements", []) if x["keyword"]}
    check("bare: no preamble still parses as a data set", r["kind"] == "dicom" and vals.get("Modality") == "CT",
          r.get("kind"))
    check("bare: flag found", "csctf{bare_dataset}" in r.get("flags", []), r.get("flags"))


def test_dicom_flag_in_preamble_and_trailer():
    """A flag stuffed into the 128-byte preamble (a classic hiding spot that carries no elements) or
    appended after the data set must still surface -- the whole file is raw-scanned as a safety net."""
    ds = _el(0x0008, 0x0060, "CS", _pad_sp("CT"))
    meta = _el(0x0002, 0x0010, "UI", _pad_ui("1.2.840.10008.1.2.1")) \
        + _el(0x0002, 0x0002, "UI", _pad_ui("1.2.840.10008.5.1.4.1.1.2"))
    gl = _el(0x0002, 0x0000, "UL", struct.pack("<I", len(meta)))
    blob = b"csctf{preamble_hideout}".ljust(128, b"\x00") + b"DICM" + gl + meta + ds
    r = H.parse_dicom(blob)
    check("dicom: flag hidden in the 128-byte preamble recovered", "csctf{preamble_hideout}" in r["flags"],
          r["flags"])
    check("dicom: preamble_nonzero flagged", r["preamble_nonzero"] is True)
    r2 = H.parse_dicom(_part10("1.2.840.10008.1.2.1", ds) + b"\n; trailer csctf{dcm_trailer} ;\n")
    check("dicom: flag in trailing bytes after the data set recovered", "csctf{dcm_trailer}" in r2["flags"],
          r2["flags"])


def test_dicom_explicit_be_long_vr():
    """Explicit VR Big Endian with a 4-byte-length VR (OB): VR, then 2 reserved bytes, then a
    BIG-ENDIAN 4-byte length. Exercises the reserved+4-byte-length header path in the retired
    big-endian syntax and that parsing resumes correctly on the next element."""
    payload = b"raw bytes with csctf{be_ob_longvr} inside\x00"
    ds = _el(0x0008, 0x0060, "CS", _pad_sp("CT"), little=False) \
        + _el(0x0009, 0x0010, "OB", payload, little=False) \
        + _el(0x0020, 0x4000, "LT", _pad_sp("csctf{be_text}"), little=False)
    r = H.parse_dicom(_part10("1.2.840.10008.1.2.2", ds))
    ob = [x for x in r["elements"] if x["tag"] == "(0009,0010)"]
    check("explicit-BE long-VR: OB length read (big-endian 4-byte length)",
          ob and ob[0]["length"] == len(payload), ob)
    check("explicit-BE long-VR: element after the OB long-VR still parses",
          any(x["tag"] == "(0020,4000)" for x in r["elements"]), [x["tag"] for x in r["elements"]])
    check("explicit-BE long-VR: flags from OB raw bytes and the trailing LT",
          {"csctf{be_ob_longvr}", "csctf{be_text}"} <= set(r["flags"]), r["flags"])


def test_dicom_undefined_length_sequences():
    """Undefined-length (delimited) SQ in BOTH implicit and explicit VR, plus the element that follows
    the sequence delimiter -- the parser must resume cleanly after (FFFE,E0DD)."""
    def undef_item(inner):
        return (struct.pack("<HH", 0xFFFE, 0xE000) + struct.pack("<I", 0xFFFFFFFF) + inner
                + struct.pack("<HH", 0xFFFE, 0xE00D) + struct.pack("<I", 0))
    # Explicit VR LE: undefined-length SQ, two items, then a trailing element.
    sq_region = undef_item(_el(0x0020, 0x4000, "LT", _pad_sp("csctf{undef_sq_item0}"))) \
        + undef_item(_el(0x0020, 0x4000, "LT", _pad_sp("csctf{undef_sq_item1}"))) \
        + struct.pack("<HH", 0xFFFE, 0xE0DD) + struct.pack("<I", 0)
    sq = struct.pack("<HH", 0x0008, 0x1115) + b"SQ\x00\x00" + struct.pack("<I", 0xFFFFFFFF) + sq_region
    ds = _el(0x0008, 0x0060, "CS", _pad_sp("CT")) + sq + _el(0x0020, 0x0013, "IS", _pad_sp("7"))
    r = H.parse_dicom(_part10("1.2.840.10008.1.2.1", ds))
    sqs = [x for x in r["elements"] if x.get("vr") == "SQ"]
    vals = {x["keyword"]: x["value"] for x in r["elements"] if x["keyword"]}
    check("undef-SQ explicit: two items walked", sqs and len(sqs[0]["items"]) == 2,
          sqs and len(sqs[0]["items"]))
    check("undef-SQ explicit: both nested flags found",
          {"csctf{undef_sq_item0}", "csctf{undef_sq_item1}"} <= set(r["flags"]), r["flags"])
    check("undef-SQ explicit: element after (FFFE,E0DD) still parsed", vals.get("InstanceNumber") == "7",
          vals.get("InstanceNumber"))
    # Implicit VR LE: SQ VR is absent from both bytes and dictionary -> detected by undefined length
    # plus item structure.
    inner = _eli(0x0020, 0x4000, _pad_sp("csctf{implicit_undef_sq}"))
    item = (struct.pack("<HH", 0xFFFE, 0xE000) + struct.pack("<I", 0xFFFFFFFF) + inner
            + struct.pack("<HH", 0xFFFE, 0xE00D) + struct.pack("<I", 0))
    sq_i = struct.pack("<HH", 0x0008, 0x1140) + struct.pack("<I", 0xFFFFFFFF) + item \
        + struct.pack("<HH", 0xFFFE, 0xE0DD) + struct.pack("<I", 0)
    ds2 = _eli(0x0008, 0x0060, _pad_sp("CT")) + sq_i + _eli(0x0020, 0x0013, _pad_sp("9"))
    r2 = H.parse_dicom(_part10("1.2.840.10008.1.2", ds2))
    sqs2 = [x for x in r2["elements"] if x.get("vr") == "SQ"]
    vals2 = {x["keyword"]: x["value"] for x in r2["elements"] if x["keyword"]}
    check("undef-SQ implicit: sequence detected + item walked", sqs2 and len(sqs2[0]["items"]) == 1, sqs2)
    check("undef-SQ implicit: nested flag found", "csctf{implicit_undef_sq}" in r2["flags"], r2["flags"])
    check("undef-SQ implicit: element after the sequence parsed", vals2.get("InstanceNumber") == "9",
          vals2.get("InstanceNumber"))


def test_dicom_deflated_zlib_wrapped():
    """Spec deflate is raw (RFC1951); an artifact deflated WITH a zlib header (RFC1950, e.g. a plain
    zlib.compress a CTF author might reach for) must still inflate via the fallback."""
    import zlib as _z
    ds = _el(0x0008, 0x0060, "CS", _pad_sp("CT")) + _el(0x0020, 0x4000, "LT", _pad_sp("csctf{zlib_wrapped}"))
    meta = _el(0x0002, 0x0010, "UI", _pad_ui("1.2.840.10008.1.2.1.99")) \
        + _el(0x0002, 0x0002, "UI", _pad_ui("1.2.840.10008.5.1.4.1.1.2"))
    gl = _el(0x0002, 0x0000, "UL", struct.pack("<I", len(meta)))
    blob = b"\x00" * 128 + b"DICM" + gl + meta + _z.compress(ds)       # zlib-wrapped, not raw
    r = H.parse_dicom(blob)
    vals = {x["keyword"]: x["value"] for x in r["elements"] if x["keyword"]}
    check("deflated-zlib: flag recovered via zlib-wrapped fallback", "csctf{zlib_wrapped}" in r["flags"],
          r["flags"])
    check("deflated-zlib: data set decoded (Modality=CT)", vals.get("Modality") == "CT", vals.get("Modality"))


# ----------------------------------------------------------------- HL7 tests

HL7_MSG = (
    "MSH|^~\\&|SendingApp|SendingFac|RecvApp|RecvFac|20260607120000||ADT^A01|MSG0001|P|2.5\r"
    "PID|1||PID00042^^^HOSP^MR||DOE^JANE^Q||19800101|F|||123 MAIN ST^^CITY^ST^00000\r"
    "NTE|1||clinician note: csctf{hl7_note_flag}\r"
    "OBX|1|ST|GLU^Glucose^L||99|mg/dL|70-110|N\r"
)


def test_hl7():
    r = H.parse_hl7(HL7_MSG.encode())
    seg_ids = [s["id"] for s in r["segments"]]
    msh = r["segments"][0]["fields"]
    pid = r["segments"][1]["fields"]
    check("hl7: segments in order", seg_ids == ["MSH", "PID", "NTE", "OBX"], seg_ids)
    check("hl7: MSH-1 is the field separator", msh.get("1") == "|", msh.get("1"))
    check("hl7: MSH-2 is the encoding chars", msh.get("2") == "^~\\&", msh.get("2"))
    check("hl7: MSH-3 shifted correctly past the separator", msh.get("3") == "SendingApp", msh.get("3"))
    check("hl7: message type ADT^A01", r["message_type"] == "ADT^A01", r["message_type"])
    check("hl7: PID-5 split into components", pid.get("5") == ["DOE", "JANE", "Q"], pid.get("5"))
    check("hl7: PID-3 keeps empty components", pid.get("3") == ["PID00042", "", "", "HOSP", "MR"], pid.get("3"))
    check("hl7: flag in NTE", "csctf{hl7_note_flag}" in r["flags"], r["flags"])


def test_hl7_mllp():
    framed = b"\x0b" + HL7_MSG.encode() + b"\x1c\x0d"
    r = H.parse_hl7(framed)
    check("hl7-mllp: framing stripped, message type read", r["message_type"] == "ADT^A01", r["message_type"])
    check("hl7-mllp: flag recovered", "csctf{hl7_note_flag}" in r["flags"], r["flags"])


def test_hl7_rejects_non_msh():
    try:
        H.parse_hl7(b"PID|1|no MSH here")
        check("hl7: a non-MSH message is rejected", False, "no exception")
    except ValueError:
        check("hl7: a non-MSH message is rejected", True)


def test_hl7_short_encoding_chars():
    """MSH-2 shorter than four characters must be read only up to the next field separator, not a
    fixed 4-byte slice that would swallow the separator and the start of MSH-3 and so corrupt the
    derived escape / subcomponent delimiters."""
    msg = "MSH|^~|LAB|HOSP|EMR|HOSP|20260101||ORU^R01|1|P|2.5\rNTE|1||csctf{short_enc}\r"
    r = H.parse_hl7(msg.encode())
    check("hl7-shortenc: MSH-2 read as exactly '^~' (to next field sep)", r["encoding_chars"] == "^~",
          r["encoding_chars"])
    check("hl7-shortenc: MSH-3 not corrupted (=LAB)", r["segments"][0]["fields"].get("3") == "LAB",
          r["segments"][0]["fields"].get("3"))
    check("hl7-shortenc: message type ORU^R01", r["message_type"] == "ORU^R01", r["message_type"])
    check("hl7-shortenc: flag still found", "csctf{short_enc}" in r["flags"], r["flags"])


def test_hl7_custom_separators():
    """Non-default delimiters declared in MSH-1/MSH-2 must be used throughout, and message_type must
    be reconstructed with the message's OWN component separator (not a hardcoded '^')."""
    msg = "MSH#@~\\&#LAB#HOSP#EMR#HOSP#20260101##ORU@R01#MSG#P#2.5\rNTE#1##csctf{custom_delim}\r"
    r = H.parse_hl7(msg.encode())
    check("hl7-custom: field separator '#'", r["field_sep"] == "#", r["field_sep"])
    check("hl7-custom: component separator read as '@'", r["encoding_chars"][:1] == "@", r["encoding_chars"])
    check("hl7-custom: MSH-3 parsed with the custom field sep (=LAB)",
          r["segments"][0]["fields"].get("3") == "LAB", r["segments"][0]["fields"].get("3"))
    check("hl7-custom: message_type uses the message's own comp sep (ORU@R01)",
          r["message_type"] == "ORU@R01", r["message_type"])
    check("hl7-custom: flag in the custom-delimited NTE", "csctf{custom_delim}" in r["flags"], r["flags"])


# ----------------------------------------------------------------- FHIR tests

PATIENT = {
    "resourceType": "Patient", "id": "pat1",
    "identifier": [{"system": "urn:mrn", "value": "PID00042"}],
    "name": [{"family": "Doe", "given": ["Jane", "Q"], "text": "Jane Q Doe"}],
    "gender": "female", "birthDate": "1980-01-01",
    "text": {"status": "generated", "div": "<div>clinical note csctf{fhir_narrative_flag}</div>"},
}


def test_fhir_json():
    r = H.parse_fhir(json.dumps(PATIENT).encode())
    ke = r["resources"][0]["key_elements"]
    check("fhir-json: resourceType=Patient", r["resourceType"] == "Patient", r["resourceType"])
    check("fhir-json: name key element", ke.get("name") == "Jane Q Doe", ke)
    check("fhir-json: identifier key element", ke.get("identifier") == "PID00042", ke)
    check("fhir-json: flag found in narrative", "csctf{fhir_narrative_flag}" in r["flags"], r["flags"])


def test_fhir_bundle():
    bundle = {"resourceType": "Bundle", "type": "collection", "entry": [
        {"resource": PATIENT},
        {"resource": {"resourceType": "Observation", "status": "final",
                      "code": {"text": "Glucose"}, "valueString": "result csctf{fhir_observation_flag}"}},
    ]}
    r = H.parse_fhir(json.dumps(bundle).encode())
    rts = [x["resourceType"] for x in r["resources"]]
    check("fhir-bundle: entries walked", rts == ["Patient", "Observation"], rts)
    check("fhir-bundle: flags from both entries",
          {"csctf{fhir_narrative_flag}", "csctf{fhir_observation_flag}"} <= set(r["flags"]), r["flags"])


def test_fhir_xml():
    xml = ('<Patient xmlns="http://hl7.org/fhir"><id value="pat1"/>'
           '<name><family value="Doe"/><given value="Jane"/>'
           '<text value="note csctf{fhir_xml_flag}"/></name></Patient>')
    r = H.parse_fhir(xml.encode())
    check("fhir-xml: resourceType from root tag (namespace stripped)", r["resourceType"] == "Patient",
          r["resourceType"])
    check("fhir-xml: flag found in a value attribute", "csctf{fhir_xml_flag}" in r["flags"], r["flags"])


# ----------------------------------------------------------------- DICOM upper-layer (pcap) tests

def _ul_item(itype, val):
    return struct.pack(">BBH", itype, 0, len(val)) + val


def _build_associate_rq(called, calling, app_uid, abstract_uid, ts_uid):
    """A spec-derived A-ASSOCIATE-RQ PDU: fixed fields + application + presentation context items."""
    appc = _ul_item(0x10, app_uid.encode())
    pc_body = struct.pack(">BBBB", 1, 0, 0, 0) + _ul_item(0x30, abstract_uid.encode()) \
        + _ul_item(0x40, ts_uid.encode())
    presc = _ul_item(0x20, pc_body)
    fixed = struct.pack(">H", 1) + b"\x00\x00" + called.encode().ljust(16) + calling.encode().ljust(16) \
        + b"\x00" * 32
    body = fixed + appc + presc
    return struct.pack(">BBI", 1, 0, len(body)) + body


def test_dicom_ul_variable_items():
    pdu = _build_associate_rq("ARCHIVE", "SCANNER", "1.2.840.10008.3.1.1.1",
                              "1.2.840.10008.5.1.4.1.1.2", "1.2.840.10008.1.2.1")
    m = H._dicom_ul_ae_titles(pdu)
    check("dicom-UL: PDU recognised as A-ASSOCIATE-RQ", m and m["pdu"] == "A-ASSOCIATE-RQ", m)
    check("dicom-UL: called AE title", m and m["called_ae_title"] == "ARCHIVE", m and m["called_ae_title"])
    check("dicom-UL: calling AE title", m and m["calling_ae_title"] == "SCANNER", m and m["calling_ae_title"])
    check("dicom-UL: application context UID", m and m["application_context"] == "1.2.840.10008.3.1.1.1", m)
    check("dicom-UL: abstract syntax UID", m and m["abstract_syntaxes"] == ["1.2.840.10008.5.1.4.1.1.2"], m)
    check("dicom-UL: transfer syntax UID", m and m["transfer_syntaxes"] == ["1.2.840.10008.1.2.1"], m)


def test_dicom_ul_crosscheck_scapy():
    """Cross-check the AE-title parse against scapy.contrib.dicom's own dissector (spec source of truth)."""
    try:
        from scapy.contrib.dicom import DICOM, A_ASSOCIATE_RQ
    except Exception as ex:                                    # scapy absent -> skip, do not fail
        check("dicom-UL: scapy cross-check (skipped, scapy unavailable)", True, str(ex)[:60])
        return
    called = b"PACSARCHIVE     "
    calling = b"CTSCANNER       "
    raw = bytes(DICOM() / A_ASSOCIATE_RQ(called_ae_title=called, calling_ae_title=calling))
    scapy_view = DICOM(raw).payload
    mine = H._dicom_ul_ae_titles(raw)
    check("dicom-UL xcheck: called AE matches scapy",
          mine and mine["called_ae_title"] == scapy_view.called_ae_title.decode().strip(),
          mine and mine["called_ae_title"])
    check("dicom-UL xcheck: calling AE matches scapy",
          mine and mine["calling_ae_title"] == scapy_view.calling_ae_title.decode().strip(),
          mine and mine["calling_ae_title"])


# ----------------------------------------------------------------- pcap end-to-end (scapy)

def _write_pcap(path, flows):
    """flows: list of (src, dst, sport, dport, payload-or-list-of-(seq,bytes)). Uses explicit MACs so
    scapy does not try to resolve any, which keeps the test output clean."""
    from scapy.all import Ether, IP, TCP, Raw, wrpcap, conf
    conf.verb = 0
    pkts = []
    for src, dst, sport, dport, payload in flows:
        segs = payload if isinstance(payload, list) else [(1, payload)]
        for seq, data in segs:
            pkts.append(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                        / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=seq) / Raw(data))
    wrpcap(str(path), pkts)


def test_pcap_end_to_end():
    try:
        import scapy.all  # noqa: F401
    except Exception as ex:
        check("pcap: end-to-end (skipped, scapy unavailable)", True, str(ex)[:60])
        return
    tmp = Path(tempfile.mkdtemp(prefix="hc_pcap_"))
    rq = _build_associate_rq("ARCHIVE", "SCANNER", "1.2.840.10008.3.1.1.1",
                             "1.2.840.10008.5.1.4.1.1.2", "1.2.840.10008.1.2.1")
    hl7 = b"MSH|^~\\&|LAB|HOSP|EMR|HOSP|20260607||ORU^R01|9|P|2.5\rNTE|1||csctf{pcap_hl7_flag}\r"
    mllp = b"\x0b" + hl7 + b"\x1c\x0d"
    fhir = json.dumps({"resourceType": "Patient", "id": "x",
                       "name": [{"text": "flag csctf{pcap_fhir_flag}"}]}).encode()
    http = (b"POST /fhir/Patient HTTP/1.1\r\nHost: ehr\r\nContent-Type: application/fhir+json\r\n"
            b"Content-Length: %d\r\n\r\n" % len(fhir)) + fhir

    pcap = tmp / "health.pcap"
    _write_pcap(pcap, [
        ("10.0.0.1", "10.0.0.2", 4000, 104, rq),              # DICOM association
        ("10.0.0.3", "10.0.0.4", 5000, 2575, mllp),           # HL7 over MLLP
        ("10.0.0.5", "10.0.0.6", 6000, 8080, http),           # FHIR over HTTP
    ])
    rep = H.parse_pcap(pcap)
    kinds = [(f.get("kind") or f.get("pdu")) for f in rep["findings"]]
    check("pcap: three flows reassembled", rep["flows"] == 3, rep["flows"])
    check("pcap: DICOM association dissected", "A-ASSOCIATE-RQ" in kinds, kinds)
    check("pcap: HL7 dissected", "hl7" in kinds, kinds)
    check("pcap: FHIR dissected", "fhir" in kinds, kinds)
    check("pcap: flags from HL7 + FHIR surfaced",
          {"csctf{pcap_hl7_flag}", "csctf{pcap_fhir_flag}"} <= set(rep["flags"]), rep["flags"])

    # Out-of-order TCP reassembly: split the MLLP frame into two segments, written reversed.
    seg1, seg2 = mllp[:24], mllp[24:]
    pcap2 = tmp / "split.pcap"
    _write_pcap(pcap2, [
        ("10.1.0.1", "10.1.0.2", 7000, 2575, [(1000 + len(seg1), seg2), (1000, seg1)]),
    ])
    rep2 = H.parse_pcap(pcap2)
    check("pcap: out-of-order segments reassembled by seq", "csctf{pcap_hl7_flag}" in rep2["flags"], rep2["flags"])


# ----------------------------------------------------------------- adversarial + CLI

def test_adversarial():
    import os as _os
    r = H.analyze(_os.urandom(400), "rand.bin")
    check("adversarial: random bytes do not crash", isinstance(r, dict) and "flags" in r, r.get("kind"))
    r2 = H.analyze(b"", "empty")
    check("adversarial: empty input handled", isinstance(r2, dict))
    r3 = H.analyze(b"loose text csctf{raw_scan_flag} end", "note.txt")
    check("adversarial: raw flag scan on unstructured text", "csctf{raw_scan_flag}" in r3["flags"], r3["flags"])
    trunc = b"\x00" * 128 + b"DICM" + _el(0x0002, 0x0000, "UL", struct.pack("<I", 200)) + b"\x02\x00\x10\x00UI"
    r4 = H.analyze(trunc, "trunc.dcm")
    check("adversarial: truncated DICOM does not crash", r4["kind"] == "dicom", r4.get("kind"))


def test_cli():
    tmp = Path(tempfile.mkdtemp(prefix="hc_cli_"))
    ds = _el(0x0008, 0x0060, "CS", _pad_sp("CT")) + _el(0x0010, 0x0010, "PN", _pad_sp("DOE^JANE")) \
        + _el(0x0020, 0x4000, "LT", _pad_sp("csctf{cli_flag}")) + _el(0x7FE0, 0x0010, "OW", b"\x00" * 32)
    dcm = tmp / "study.dcm"
    dcm.write_bytes(_part10("1.2.840.10008.1.2.1", ds))
    mod = str(REPO / "solvers" / "toolkits" / "healthcare.py")
    env = dict(os.environ, CTF_WORKDIR=str(paths.workdir()))

    r = subprocess.run([PY, mod, str(dcm)], capture_output=True, text=True, timeout=60, env=env)
    check("cli: human output names the flag and the kind",
          r.returncode == 0 and "csctf{cli_flag}" in r.stdout and "[dicom]" in r.stdout,
          (r.stdout + r.stderr)[-300:])
    check("cli: Modality decoded in human output", "Modality" in r.stdout and "CT" in r.stdout)

    rj = subprocess.run([PY, mod, str(dcm), "--json"], capture_output=True, text=True, timeout=60, env=env)
    ok_json = False
    try:
        out = json.loads(rj.stdout)
        ok_json = out[0]["kind"] == "dicom" and "csctf{cli_flag}" in out[0]["flags"]
    except Exception:
        ok_json = False
    check("cli: --json is valid and carries the flag", rj.returncode == 0 and ok_json, rj.stdout[-200:])

    other = tmp / "x.bin"
    other.write_bytes(b"nothing medical here\n")
    r2 = subprocess.run([PY, mod, str(other)], capture_output=True, text=True, timeout=60, env=env)
    check("cli: unknown artifact handled cleanly", r2.returncode == 0 and "[unknown]" in r2.stdout,
          r2.stdout[-200:])


def main():
    print("DICOM:")
    test_dicom_explicit_le()
    test_dicom_implicit_le()
    test_dicom_explicit_be()
    test_dicom_deflated()
    test_dicom_sequence_and_encapsulated()
    test_dicom_bare_dataset()
    test_dicom_flag_in_preamble_and_trailer()
    test_dicom_explicit_be_long_vr()
    test_dicom_undefined_length_sequences()
    test_dicom_deflated_zlib_wrapped()
    print("HL7:")
    test_hl7()
    test_hl7_mllp()
    test_hl7_rejects_non_msh()
    test_hl7_short_encoding_chars()
    test_hl7_custom_separators()
    print("FHIR:")
    test_fhir_json()
    test_fhir_bundle()
    test_fhir_xml()
    print("DICOM upper-layer / pcap:")
    test_dicom_ul_variable_items()
    test_dicom_ul_crosscheck_scapy()
    test_pcap_end_to_end()
    print("adversarial / CLI:")
    test_adversarial()
    test_cli()
    if FAILED:
        print(f"\n{len(FAILED)} FAILED: " + "; ".join(FAILED))
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
