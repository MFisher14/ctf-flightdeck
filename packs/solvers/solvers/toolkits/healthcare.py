#!/usr/bin/env python3
"""Toolkit healthcare: an OFFLINE, STATIC reader for medical-data formats that show up in the
critical-infrastructure / healthcare lane of a jeopardy CTF -- DICOM imaging files, HL7 v2 messages
and FHIR resources. The bytes are walked as a grammar and the structure and values are read out;
NOTHING is ever instantiated, imaged, rendered or executed (the repo's never-execute discipline).
In jeopardy the decoded content IS where the flag hides, so every decoded text value -- and the raw
bytes of binary/private/overlay/comment elements where an author would stuff a flag -- is scanned for
the CSCTF flag format and any hit is highlighted prominently.

Formats read:
  DICOM   DICOM Part-10 file: 128-byte preamble + 'DICM', the File Meta group (0002, always Explicit
          VR Little-Endian) whose (0002,0010) TransferSyntaxUID selects the encoding of the main data
          set -- Implicit VR LE, Explicit VR LE, Explicit VR BE, or Deflated Explicit VR LE. Data
          elements are decoded with their VR; key tags (PatientName/ID, Modality, StudyDescription,
          ...) are named, and ALL text tags, private tags (odd group), overlays (group 60xx) and
          free-text/comment tags are surfaced because a flag can hide in any of them. Sequences (SQ)
          are walked recursively. PixelData (7FE0,0010) is NOT rendered -- only its presence/length
          is noted (native or encapsulated). A bare data set (no preamble/DICM) is parsed too.
  HL7v2   HL7 version 2.x pipe-delimited message: MSH plus segments, split into fields / repetitions /
          components / subcomponents using the delimiters declared in MSH-1/MSH-2. MLLP framing
          (0x0B ... 0x1C 0x0D) is stripped if present.
  FHIR    HL7 FHIR resource as JSON or XML: resourceType plus key elements, Bundle entries walked;
          every string value / XML value-attribute is surfaced and flag-scanned.

Inputs (CLI): BOTH a raw artifact file (.dcm / an HL7 .hl7|.txt / a FHIR .json|.xml) AND a
.pcap/.pcapng are accepted. For a capture, scapy reassembles TCP flows and the relevant payloads are
pulled out and dissected: HL7-over-MLLP, FHIR in HTTP bodies, embedded DICOM Part-10 files, and the
DICOM upper-layer protocol (A-ASSOCIATE AE titles / presentation contexts, and the DIMSE commands
carried in P-DATA-TF fragments, with a C-STORE-RQ count per flow). scapy is optional -- without it the file parsers still work and the pcap path degrades to
a clear message.

  .venv/bin/python solvers/toolkits/healthcare.py <file>... [--kind dicom|hl7|fhir|pcap] [--json]

Scope: this is an offline parser of a provided artifact. It never touches the network, never submits,
and never executes anything. A recovered flag is PRINTED for the player to submit by hand through
ctf.submit.guarded_submit.
"""
import bisect
import json
import re
import struct
import sys
import zlib
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

try:                                                    # xml is stdlib; keep the import defensive
    import xml.etree.ElementTree as ET
except Exception:                                       # pragma: no cover - xml always present
    ET = None

# Event flag detection: the active event's flag format (ctf.flagfmt).
# A hit in a decoded artifact is highlighted and PRINTED for the player; nothing here auto-submits.
FLAG_RE = flagfmt.TEXT

MAX_FILE = 64 * 1024 * 1024
_PREVIEW = 120                                           # cap on a rendered value preview (chars)


def find_flags(data):
    """Every event-format flag string in a body (bytes or str), as a de-duplicated list in order.
    Bytes are binary fields and packed records, so they are scanned without a word boundary before
    the flag (flagfmt.PACKED_TEXT, R-16); text keeps the boundary."""
    if isinstance(data, (bytes, bytearray)):
        text, rx = bytes(data).decode("utf-8", "replace"), flagfmt.PACKED_TEXT
    else:
        text, rx = str(data or ""), FLAG_RE
    out, seen = [], set()
    for m in rx.findall(text):
        if m not in seen:
            seen.add(m)
            out.append(m)
    return out


# ======================================================================== DICOM Part-10 / data set

# Transfer-syntax UID -> (explicit_vr, little_endian, deflated). Unknown/compressed syntaxes still use
# Explicit VR Little Endian for the data set (only the PixelData is encapsulated), so that is the
# default for any 1.2.840.10008.1.2.4.* / .5 we do not special-case.
_TS = {
    "1.2.840.10008.1.2":        (False, True,  False),   # Implicit VR Little Endian
    "1.2.840.10008.1.2.1":      (True,  True,  False),   # Explicit VR Little Endian
    "1.2.840.10008.1.2.1.99":   (True,  True,  True),    # Deflated Explicit VR Little Endian
    "1.2.840.10008.1.2.2":      (True,  False, False),   # Explicit VR Big Endian (retired)
}

# Explicit-VR value representations that carry 2 reserved bytes + a 4-byte length (the rest use u16).
_VR_LONG = {"OB", "OD", "OF", "OL", "OV", "OW", "SQ", "UC", "UN", "UR", "UT", "SV", "UV"}
# VRs whose value is text we decode and flag-scan as a string.
_VR_TEXT = {"AE", "AS", "CS", "DA", "DS", "DT", "IS", "LO", "LT", "PN", "SH", "ST", "TM",
            "UC", "UI", "UR", "UT"}
# Free-text VRs where an author is most likely to park a flag.
_VR_FREETEXT = {"LT", "ST", "UT"}

# A small (group,element) -> (VR, keyword) dictionary: enough to decode Implicit VR and to NAME the
# tags a solver cares about. Unlisted tags are still parsed (VR sniffed) and flag-scanned.
_DICT = {
    (0x0002, 0x0000): ("UL", "FileMetaInformationGroupLength"),
    (0x0002, 0x0001): ("OB", "FileMetaInformationVersion"),
    (0x0002, 0x0002): ("UI", "MediaStorageSOPClassUID"),
    (0x0002, 0x0003): ("UI", "MediaStorageSOPInstanceUID"),
    (0x0002, 0x0010): ("UI", "TransferSyntaxUID"),
    (0x0002, 0x0012): ("UI", "ImplementationClassUID"),
    (0x0002, 0x0013): ("SH", "ImplementationVersionName"),
    (0x0002, 0x0016): ("AE", "SourceApplicationEntityTitle"),
    (0x0008, 0x0005): ("CS", "SpecificCharacterSet"),
    (0x0008, 0x0008): ("CS", "ImageType"),
    (0x0008, 0x0016): ("UI", "SOPClassUID"),
    (0x0008, 0x0018): ("UI", "SOPInstanceUID"),
    (0x0008, 0x0020): ("DA", "StudyDate"),
    (0x0008, 0x0030): ("TM", "StudyTime"),
    (0x0008, 0x0050): ("SH", "AccessionNumber"),
    (0x0008, 0x0060): ("CS", "Modality"),
    (0x0008, 0x0070): ("LO", "Manufacturer"),
    (0x0008, 0x0080): ("LO", "InstitutionName"),
    (0x0008, 0x0090): ("PN", "ReferringPhysicianName"),
    (0x0008, 0x1030): ("LO", "StudyDescription"),
    (0x0008, 0x103E): ("LO", "SeriesDescription"),
    (0x0008, 0x1090): ("LO", "ManufacturerModelName"),
    (0x0008, 0x2111): ("ST", "DerivationDescription"),
    (0x0008, 0x4000): ("LT", "IdentifyingComments"),
    (0x0010, 0x0010): ("PN", "PatientName"),
    (0x0010, 0x0020): ("LO", "PatientID"),
    (0x0010, 0x0021): ("LO", "IssuerOfPatientID"),
    (0x0010, 0x0030): ("DA", "PatientBirthDate"),
    (0x0010, 0x0040): ("CS", "PatientSex"),
    (0x0010, 0x1000): ("LO", "OtherPatientIDs"),
    (0x0010, 0x1010): ("AS", "PatientAge"),
    (0x0010, 0x2180): ("SH", "Occupation"),
    (0x0010, 0x21B0): ("LT", "AdditionalPatientHistory"),
    (0x0010, 0x4000): ("LT", "PatientComments"),
    (0x0018, 0x0015): ("CS", "BodyPartExamined"),
    (0x0020, 0x000D): ("UI", "StudyInstanceUID"),
    (0x0020, 0x000E): ("UI", "SeriesInstanceUID"),
    (0x0020, 0x0010): ("SH", "StudyID"),
    (0x0020, 0x0011): ("IS", "SeriesNumber"),
    (0x0020, 0x0013): ("IS", "InstanceNumber"),
    (0x0020, 0x4000): ("LT", "ImageComments"),
    (0x0028, 0x0010): ("US", "Rows"),
    (0x0028, 0x0011): ("US", "Columns"),
    (0x0028, 0x0100): ("US", "BitsAllocated"),
    (0x0028, 0x0101): ("US", "BitsStored"),
    (0x0032, 0x4000): ("LT", "StudyComments"),
    (0x0038, 0x4000): ("LT", "VisitComments"),
    (0x0040, 0x0254): ("LO", "PerformedProcedureStepDescription"),
    (0x7FE0, 0x0010): ("OW", "PixelData"),
}

# UIDs worth naming in the readout (transfer syntaxes + a couple of SOP classes).
_UID_NAMES = {
    "1.2.840.10008.1.2":        "Implicit VR Little Endian",
    "1.2.840.10008.1.2.1":      "Explicit VR Little Endian",
    "1.2.840.10008.1.2.1.99":   "Deflated Explicit VR Little Endian",
    "1.2.840.10008.1.2.2":      "Explicit VR Big Endian",
    "1.2.840.10008.1.2.4.50":   "JPEG Baseline",
    "1.2.840.10008.1.2.4.70":   "JPEG Lossless",
    "1.2.840.10008.1.2.4.90":   "JPEG 2000 Lossless",
    "1.2.840.10008.1.2.4.91":   "JPEG 2000",
    "1.2.840.10008.1.2.5":      "RLE Lossless",
    "1.2.840.10008.5.1.4.1.1.2":    "CT Image Storage",
    "1.2.840.10008.5.1.4.1.1.4":    "MR Image Storage",
    "1.2.840.10008.5.1.4.1.1.1":    "CR Image Storage",
    "1.2.840.10008.5.1.4.1.1.7":    "Secondary Capture Image Storage",
    "1.2.840.10008.1.1":            "Verification SOP Class",
}

_ITEM = 0xFFFE
_ITEM_BEGIN, _ITEM_END, _SEQ_END = 0xE000, 0xE00D, 0xE0DD
_UNDEF = 0xFFFFFFFF


class DicomError(ValueError):
    """Bytes that are not a DICOM file / data set, or are not well-formed enough to read."""


def _u16(b, o, little):
    return struct.unpack_from("<H" if little else ">H", b, o)[0]


def _u32(b, o, little):
    return struct.unpack_from("<I" if little else ">I", b, o)[0]


def _tag_str(g, e):
    return f"({g:04X},{e:04X})"


def _vr_sniff(value):
    """Guess, for an Implicit-VR element with no dictionary entry, whether the value reads as text."""
    if not value:
        return "UN"
    sample = value[:64].rstrip(b"\x00 ")
    if sample and all(0x20 <= c < 0x7F or c in (0x09, 0x0A, 0x0D) for c in sample):
        return "LO"
    return "UN"


def _decode_text(value, vr):
    """Render a text-VR value: trailing NUL/space padding stripped, kept as a readable string."""
    s = bytes(value).decode("latin-1")
    # DICOM pads with NUL (UI) or SPACE (most) to an even length; strip trailing pad only.
    return s.rstrip("\x00 ")


def _render_value(vr, value, little):
    """A short human-readable rendering of one element value (never the full pixel data)."""
    try:
        if vr in _VR_TEXT:
            txt = _decode_text(value, vr)
            return txt if len(txt) <= _PREVIEW else txt[:_PREVIEW] + f"...(+{len(txt) - _PREVIEW})"
        if vr in ("US", "SS") and len(value) >= 2:
            fmt = ("<" if little else ">") + ("H" if vr == "US" else "h") * (len(value) // 2)
            nums = struct.unpack(fmt, value[: 2 * (len(value) // 2)])
            return "\\".join(str(n) for n in nums[:16])
        if vr in ("UL", "SL") and len(value) >= 4:
            fmt = ("<" if little else ">") + ("I" if vr == "UL" else "i") * (len(value) // 4)
            nums = struct.unpack(fmt, value[: 4 * (len(value) // 4)])
            return "\\".join(str(n) for n in nums[:16])
        if vr == "FL" and len(value) >= 4:
            n = struct.unpack(("<" if little else ">") + "f", value[:4])[0]
            return f"{n:g}"
        if vr == "FD" and len(value) >= 8:
            n = struct.unpack(("<" if little else ">") + "d", value[:8])[0]
            return f"{n:g}"
        if vr == "AT" and len(value) >= 4:
            g, e = _u16(value, 0, little), _u16(value, 2, little)
            return _tag_str(g, e)
    except Exception:
        pass
    # binary / unknown: a short hex preview
    head = bytes(value[:16]).hex()
    return f"<{vr} {len(value)} bytes{': ' + head if head else ''}>"


def _parse_dataset(data, start, end, explicit, little, depth, sink):
    """Walk a DICOM data set in data[start:end]; append elements to sink['elements'] and route every
    decoded text / raw value through the flag scanner. Returns the offset reached (<= end)."""
    o = start
    elements = sink["elements"]
    while o + 8 <= end:
        g = _u16(data, o, little)
        e = _u16(data, o + 2, little)
        o += 4
        # Item / delimiter tags (FFFE,...) end a sequence or item; hand control back to the caller.
        if g == _ITEM:
            if o + 4 <= end:
                o += 4                                   # consume the (always 32-bit) length
            return o
        if explicit:
            if o + 2 > end:
                break
            vr = data[o:o + 2].decode("latin-1", "replace")
            o += 2
            if vr in _VR_LONG:
                if o + 6 > end:
                    break
                length = _u32(data, o + 2, little)       # 2 reserved bytes then 4-byte length
                o += 6
            else:
                if o + 2 > end:
                    break
                length = _u16(data, o, little)
                o += 2
        else:
            vr = _DICT.get((g, e), (None, None))[0] or ""
            if o + 4 > end:
                break
            length = _u32(data, o, little)
            o += 4

        vr_known, keyword = _DICT.get((g, e), (None, None))
        if not vr:
            vr = vr_known or ""

        is_seq = (vr == "SQ") or (not explicit and length == _UNDEF and vr in ("", "UN"))
        if is_seq:
            seq = {"tag": _tag_str(g, e), "keyword": keyword or "", "vr": "SQ", "items": []}
            o = _parse_sequence(data, o, end if length == _UNDEF else min(end, o + length),
                                 length == _UNDEF, explicit, little, depth, sink, seq)
            elements.append(seq)
            continue

        if length == _UNDEF:
            # Undefined length outside SQ == encapsulated PixelData: fragments until (FFFE,E0DD).
            frag_total, p = 0, o
            while p + 8 <= end:
                ig, ie = _u16(data, p, little), _u16(data, p + 2, little)
                ilen = _u32(data, p + 4, little)
                p += 8
                if ig == _ITEM and ie == _SEQ_END:
                    break
                if ig == _ITEM and ie == _ITEM_BEGIN:
                    if ilen == _UNDEF or p + ilen > end:
                        break
                    sink["flags"].extend(find_flags(data[p:p + ilen]))
                    frag_total += ilen
                    p += ilen
                else:
                    break
            elements.append({"tag": _tag_str(g, e), "keyword": keyword or "", "vr": vr or "OB",
                             "length": frag_total, "encapsulated": True,
                             "value": f"<encapsulated, {frag_total} bytes in fragments>",
                             "pixel_data": (g, e) == (0x7FE0, 0x0010)})
            o = p
            continue

        if o + length > end:
            length = max(0, end - o)                     # truncated: read what remains, do not guess past
        value = data[o:o + length]
        o += length

        if not vr:
            vr = _vr_sniff(value)
        rendered = _render_value(vr, value, little)
        # Flag scan: decoded text AND raw bytes (a flag can hide in OB/UN/private/overlay/comment).
        sink["flags"].extend(find_flags(rendered))
        sink["flags"].extend(find_flags(value))

        private = bool(g & 1) and g not in (0xFFFE,)
        overlay = 0x6000 <= g <= 0x60FF and not (g & 1)
        freetext = vr in _VR_FREETEXT or (keyword and ("Comment" in keyword or "Description" in keyword))
        elements.append({
            "tag": _tag_str(g, e), "keyword": keyword or "", "vr": vr, "length": length,
            "value": rendered, "private": private, "overlay": overlay, "freetext": bool(freetext),
            "pixel_data": (g, e) == (0x7FE0, 0x0010),
        })
    return min(o, end)


def _parse_sequence(data, start, end, undefined, explicit, little, depth, sink, seq):
    """Walk SQ items; each item is a nested data set. Bounded by depth to avoid pathological nesting."""
    o = start
    if depth <= 0:
        return end
    while o + 8 <= end:
        g = _u16(data, o, little)
        e = _u16(data, o + 2, little)
        length = _u32(data, o + 4, little)
        o += 8
        if g == _ITEM and e == _SEQ_END:                 # sequence delimitation item
            return o
        if g != _ITEM or e != _ITEM_BEGIN:
            return o - 8                                 # not an item: hand back to caller
        item_end = end if length == _UNDEF else min(end, o + length)
        child = {"elements": [], "flags": sink["flags"]}
        reached = _parse_dataset(data, o, item_end, explicit, little, depth - 1, child)
        seq["items"].append(child["elements"])
        o = item_end if length != _UNDEF else reached
    return o


def parse_dicom(data):
    """Parse a DICOM Part-10 file (preamble + DICM) or a bare data set. Returns a report dict."""
    if len(data) > MAX_FILE:
        raise DicomError("file too large")
    report = {"kind": "dicom", "part10": False, "preamble_nonzero": False, "meta": [],
              "transfer_syntax": None, "transfer_syntax_name": None, "explicit_vr": None,
              "little_endian": None, "elements": [], "flags": [], "pixel_data": None, "notes": []}

    body_off = 0
    if len(data) >= 132 and data[128:132] == b"DICM":
        report["part10"] = True
        report["preamble_nonzero"] = any(data[:128])
        # File Meta group 0002 is ALWAYS Explicit VR Little Endian. Parse just that group; its
        # (0002,0000) group length (when present) fixes the exact start of the main data set.
        report["meta"], body_off = _parse_meta(data, 132, report["flags"])
        for el in report["meta"]:
            if el["tag"] == "(0002,0010)":
                report["transfer_syntax"] = str(el["value"]).rstrip("\x00 ")
    else:
        # No Part-10 wrapper: treat the whole thing as a bare data set. Guess the encoding.
        report["notes"].append("no 128-byte preamble + 'DICM' magic; parsing as a bare data set")
        body_off = 0

    ts = report["transfer_syntax"]
    if ts and ts in _TS:
        explicit, little, deflated = _TS[ts]
    elif ts:
        explicit, little, deflated = True, True, False    # compressed syntax: data set is Explicit VR LE
        report["notes"].append(f"transfer syntax {ts} not special-cased; data set read as Explicit VR LE")
    else:
        explicit, little, deflated = _guess_encoding(data, body_off)
        if report["part10"]:
            report["notes"].append("file meta had no TransferSyntaxUID; data-set encoding guessed")
    report["transfer_syntax_name"] = _UID_NAMES.get(ts or "")
    report["explicit_vr"], report["little_endian"] = explicit, little

    body = data[body_off:]
    if deflated:
        try:
            body = zlib.decompress(body, -15)            # spec: raw DEFLATE (RFC 1951), no zlib header
            report["notes"].append("deflated data set inflated")
        except Exception:
            try:                                         # tolerate a zlib-wrapped stream (RFC 1950)
                body = zlib.decompress(body)
                report["notes"].append("deflated data set inflated (zlib-wrapped, non-spec header)")
            except Exception:
                report["notes"].append("deflate transfer syntax but data set did not inflate; read raw")

    body_sink = {"elements": report["elements"], "flags": report["flags"]}
    try:
        _parse_dataset(body, 0, len(body), explicit, little, 32, body_sink)
    except Exception as ex:                               # noqa: BLE001 - never crash on a bad element
        report["notes"].append(f"data-set walk stopped: {ex}")

    for el in report["elements"]:
        if el.get("pixel_data"):
            report["pixel_data"] = {"length": el.get("length"), "vr": el.get("vr"),
                                    "encapsulated": bool(el.get("encapsulated"))}
    # Safety net: a flag can hide in bytes the structural walk never visits -- the 128-byte preamble
    # (a classic hiding spot), the gap an over-stated (0002,0000) group length skips, element padding,
    # or trailing data after the last element. Raw-scan the whole original file (and the inflated data
    # set, for a deflated transfer syntax) so no flag in the artifact is missed. The structural decode
    # above still shows which named element each value lives in.
    report["flags"].extend(find_flags(data))
    if deflated:
        report["flags"].extend(find_flags(body))
    # de-dup flags, keep order
    report["flags"] = _dedup(report["flags"])
    if not report["part10"] and not report["elements"]:
        raise DicomError("no DICM magic and no element parsed")
    return report


def _read_explicit_le(data, o, n):
    """Read one Explicit-VR-Little-Endian element header+value at o. Returns (g, e, vr, value, next_o)
    or None if it does not fit. Used only for the File Meta group, which is always this encoding."""
    if o + 8 > n:
        return None
    g, e = _u16(data, o, True), _u16(data, o + 2, True)
    vr = data[o + 4:o + 6].decode("latin-1", "replace")
    if vr in _VR_LONG:
        if o + 12 > n:
            return None
        length, vstart = _u32(data, o + 8, True), o + 12
    else:
        length, vstart = _u16(data, o + 6, True), o + 8
    if vstart + length > n:
        return None
    return g, e, vr, data[vstart:vstart + length], vstart + length


def _parse_meta(data, start, flag_sink):
    """Parse ONLY the File Meta group 0002 (always Explicit VR LE). The (0002,0000) group length, when
    present, is authoritative for where the main data set begins; otherwise the body starts at the
    first element whose group is not 0002. Returns (elements, body_offset)."""
    elements, o, n = [], start, len(data)
    body_off = None
    while o + 8 <= n:
        el = _read_explicit_le(data, o, n)
        if el is None:
            break
        g, e, vr, value, nxt = el
        if g != 0x0002 and body_off is None:
            body_off = o
            break
        rendered = _render_value(vr, value, True)
        flag_sink.extend(find_flags(rendered))
        flag_sink.extend(find_flags(value))
        kw = _DICT.get((g, e), (None, None))[1]
        elements.append({"tag": _tag_str(g, e), "keyword": kw or "", "vr": vr, "length": len(value),
                         "value": rendered, "private": False, "overlay": False, "freetext": False,
                         "pixel_data": False})
        if (g, e) == (0x0002, 0x0000):
            try:
                body_off = nxt + int(rendered.split("\\")[0])   # group length counts bytes after itself
            except Exception:
                body_off = None
        o = nxt
        if body_off is not None and o >= body_off:
            break
    return elements, (body_off if body_off is not None else o)


def _guess_encoding(data, off):
    """Best-effort: is the bare data set at off Explicit or Implicit, little or big endian?"""
    if off + 8 > len(data):
        return True, True, False
    # Explicit VR LE: bytes 4,5 of the first element are two uppercase letters (a VR).
    vr = data[off + 4:off + 6]
    if len(vr) == 2 and vr.isalpha() and vr.upper() == vr:
        return True, True, False
    # Big-endian group for a tiny group number would put the zero byte first.
    g_le = _u16(data, off, True)
    g_be = _u16(data, off, False)
    if g_be in (0x0008, 0x0002) and g_le not in (0x0008, 0x0002):
        return False, False, False
    return False, True, False                            # default: Implicit VR Little Endian


def _dedup(seq):
    out, seen = [], set()
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# ======================================================================== HL7 v2 (pipe-delimited)

def strip_mllp(data):
    """Remove MLLP framing (0x0B <msg> 0x1C 0x0D) if present; return the inner message bytes."""
    if not data:
        return data
    if data[:1] == b"\x0b":
        end = data.find(b"\x1c")
        if end >= 0:
            return data[1:end]
        return data[1:]
    return data


def parse_hl7(data):
    """Parse an HL7 v2 message (bytes or str). Returns a report dict with structured segments."""
    if isinstance(data, (bytes, bytearray)):
        data = strip_mllp(bytes(data))
        text = data.decode("latin-1")
    else:
        text = str(data)
    # Segments are CR-separated in the wire format; tolerate LF / CRLF too.
    raw_segs = [s for s in re.split(r"\r\n|\r|\n", text) if s.strip()]
    if not raw_segs or not raw_segs[0].startswith("MSH"):
        raise ValueError("not an HL7 v2 message (no MSH segment at the start)")

    msh = raw_segs[0]
    field_sep = msh[3] if len(msh) > 3 else "|"
    # MSH-2 encoding characters: the run between MSH-1 (the field separator) and the next field
    # separator. Read up to that delimiter rather than assuming exactly four characters, so a short
    # or non-standard MSH-2 (e.g. "^~") is not over-sliced into the field separator and MSH-3, which
    # would corrupt the derived escape / subcomponent delimiters.
    _enc_end = msh.find(field_sep, 4)
    enc = (msh[4:_enc_end] if _enc_end != -1 else msh[4:8]) or "^~\\&"
    comp_sep = enc[0] if len(enc) > 0 else "^"
    rep_sep = enc[1] if len(enc) > 1 else "~"
    esc = enc[2] if len(enc) > 2 else "\\"
    sub_sep = enc[3] if len(enc) > 3 else "&"

    report = {"kind": "hl7", "field_sep": field_sep, "encoding_chars": enc,
              "message_type": None, "segments": [], "flags": []}

    def split_field(val):
        """A field -> repetitions -> components -> subcomponents (only when a separator is present)."""
        reps = val.split(rep_sep) if rep_sep in val else [val]
        out = []
        for rep in reps:
            if comp_sep in rep:
                comps = [c.split(sub_sep) if sub_sep in c else c for c in rep.split(comp_sep)]
                out.append(comps)
            else:
                out.append(rep)
        return out[0] if len(out) == 1 else out

    for seg in raw_segs:
        parts = seg.split(field_sep)
        seg_id = parts[0]
        fields = {}
        if seg_id == "MSH":
            # In MSH the field separator itself is MSH-1 and the encoding chars are MSH-2, so the
            # remaining pieces are shifted by one relative to a normal segment.
            fields["1"] = field_sep
            fields["2"] = enc
            for i, val in enumerate(parts[2:], start=3):
                fields[str(i)] = split_field(val) if val != "" else ""
        else:
            for i, val in enumerate(parts[1:], start=1):
                fields[str(i)] = split_field(val) if val != "" else ""
        report["segments"].append({"id": seg_id, "fields": fields, "raw": seg})
        report["flags"].extend(find_flags(seg))

    msh_fields = report["segments"][0]["fields"]
    mt = msh_fields.get("9")
    report["message_type"] = _flatten_hl7(mt, comp_sep, sub_sep)
    report["flags"] = _dedup(report["flags"])
    return report


def _flatten_hl7(v, comp="^", sub="&"):
    """Re-serialise one parsed HL7 field value to a readable string using the message's own component
    and subcomponent separators (not a hardcoded '^'/'&'), so a custom-delimiter message round-trips."""
    if v is None or v == "":
        return None
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        parts = []
        for x in v:
            if isinstance(x, list):                      # a component split into subcomponents
                parts.append(sub.join(str(y) for y in x))
            else:
                parts.append(_flatten_hl7(x, comp, sub) or "")
        return comp.join(parts)
    return str(v)


# ======================================================================== FHIR (JSON / XML)

def parse_fhir(data):
    """Parse a FHIR resource as JSON or XML. Returns a report dict (resourceType + key elements)."""
    if isinstance(data, (bytes, bytearray)):
        head = bytes(data).lstrip()[:1]
        text = bytes(data).decode("utf-8", "replace")
    else:
        text = str(data)
        head = text.lstrip()[:1].encode()

    if head == b"<":
        return _parse_fhir_xml(text)
    return _parse_fhir_json(text)


def _parse_fhir_json(text):
    try:
        obj = json.loads(text)
    except Exception as ex:
        raise ValueError(f"not valid JSON: {ex}")
    if not isinstance(obj, dict) or "resourceType" not in obj:
        raise ValueError("JSON has no 'resourceType' (not a FHIR resource)")
    report = {"kind": "fhir", "format": "json", "resourceType": obj.get("resourceType"),
              "resources": [], "key_elements": {}, "strings": [], "flags": []}
    strings = []
    _walk_json(obj, strings)
    report["strings"] = strings
    report["flags"] = _dedup([f for s in strings for f in find_flags(s)])
    report["key_elements"] = _fhir_key_elements(obj)
    if obj.get("resourceType") == "Bundle":
        for entry in obj.get("entry", []) or []:
            res = entry.get("resource") if isinstance(entry, dict) else None
            if isinstance(res, dict) and "resourceType" in res:
                report["resources"].append({"resourceType": res["resourceType"],
                                            "key_elements": _fhir_key_elements(res)})
    else:
        report["resources"].append({"resourceType": obj.get("resourceType"),
                                    "key_elements": report["key_elements"]})
    return report


def _walk_json(node, out):
    if isinstance(node, dict):
        for v in node.values():
            _walk_json(v, out)
    elif isinstance(node, list):
        for v in node:
            _walk_json(v, out)
    elif isinstance(node, str):
        out.append(node)
    elif isinstance(node, (int, float, bool)):
        out.append(str(node))


def _fhir_key_elements(res):
    """Pull a handful of commonly flag-bearing elements from a resource for the summary line."""
    ke = {}
    rt = res.get("resourceType")
    if rt == "Patient":
        names = res.get("name") or []
        if names and isinstance(names, list) and isinstance(names[0], dict):
            n = names[0]
            given = " ".join(n.get("given", []) or [])
            ke["name"] = (n.get("text") or f"{given} {n.get('family', '')}").strip()
        ke["id"] = res.get("id")
        ids = res.get("identifier") or []
        if ids and isinstance(ids[0], dict):
            ke["identifier"] = ids[0].get("value")
    elif rt == "Observation":
        code = res.get("code", {})
        if isinstance(code, dict):
            ke["code"] = code.get("text") or _first_coding_display(code)
        if "valueString" in res:
            ke["value"] = res["valueString"]
        elif isinstance(res.get("valueQuantity"), dict):
            vq = res["valueQuantity"]
            ke["value"] = f"{vq.get('value')} {vq.get('unit', '')}".strip()
    elif rt in ("DiagnosticReport", "DocumentReference"):
        ke["id"] = res.get("id")
        if isinstance(res.get("conclusion"), str):
            ke["conclusion"] = res["conclusion"]
    for k in ("id", "status", "text"):
        if k in res and k not in ke and not isinstance(res[k], (dict, list)):
            ke[k] = res[k]
    if isinstance(res.get("text"), dict):
        div = res["text"].get("div")
        if isinstance(div, str):
            ke["narrative"] = re.sub(r"<[^>]+>", " ", div).strip()[:_PREVIEW]
    return {k: v for k, v in ke.items() if v not in (None, "")}


def _first_coding_display(code):
    for c in code.get("coding", []) or []:
        if isinstance(c, dict) and c.get("display"):
            return c["display"]
    return None


def _parse_fhir_xml(text):
    if ET is None:
        raise ValueError("xml parser unavailable")
    try:
        root = ET.fromstring(text)
    except Exception as ex:
        raise ValueError(f"not valid XML: {ex}")
    rt = root.tag.split("}")[-1]                          # strip the {http://hl7.org/fhir} namespace
    report = {"kind": "fhir", "format": "xml", "resourceType": rt,
              "resources": [{"resourceType": rt, "key_elements": {}}],
              "key_elements": {}, "strings": [], "flags": []}
    strings = []
    for el in root.iter():
        # FHIR XML carries data in a `value` attribute; also scan text and every attribute value.
        for av in el.attrib.values():
            strings.append(av)
        if el.text and el.text.strip():
            strings.append(el.text.strip())
    report["strings"] = strings
    report["flags"] = _dedup([f for s in strings for f in find_flags(s)])
    return report


# ======================================================================== pcap / pcapng (optional)

def _have_scapy():
    try:
        import scapy.all  # noqa: F401
        return True
    except Exception:
        return False


def _reassemble_tcp(path, segments=None):
    """Return {flow_key: bytes} for each TCP flow in the capture, ordered by sequence number.
    UDP payloads are grouped too (HL7 can ride UDP). scapy only; caller checks availability.
    `segments`, when a dict is passed, is filled with {flow_key: [payload, ...]} in capture order
    (every TCP segment, repeated sequence numbers included) for readers that frame per segment."""
    from scapy.all import PcapReader, TCP, UDP                 # noqa: E402
    try:
        from scapy.layers.inet import IP
    except Exception:
        IP = None
    try:
        from scapy.layers.inet6 import IPv6
    except Exception:
        IPv6 = None

    tcp_segs = {}                                             # flow -> list[(seq, bytes)]
    udp_blobs = {}                                            # flow -> bytes
    with PcapReader(str(path)) as pr:
        for pkt in pr:
            ipl = pkt.getlayer(IP) if IP else None
            if ipl is None and IPv6:
                ipl = pkt.getlayer(IPv6)
            if ipl is None:
                continue
            src = getattr(ipl, "src", "?")
            dst = getattr(ipl, "dst", "?")
            t = pkt.getlayer(TCP)
            if t is not None:
                # Take the whole TCP payload as bytes whether scapy left it Raw or auto-dissected a
                # higher layer (e.g. a DICOM PDU bound to port 104); bytes() re-serialises it exactly.
                payload = bytes(t.payload)
                if not payload:
                    continue
                key = (src, dst, int(t.sport), int(t.dport))
                tcp_segs.setdefault(key, []).append((int(t.seq), payload))
                if segments is not None:
                    segments.setdefault(key, []).append(payload)
                continue
            u = pkt.getlayer(UDP)
            if u is not None:
                payload = bytes(u.payload)
                if not payload:
                    continue
                key = (src, dst, int(u.sport), int(u.dport))
                udp_blobs[key] = udp_blobs.get(key, b"") + payload

    flows = {}
    for key, segs in tcp_segs.items():
        segs.sort(key=lambda s: s[0])
        seen, buf = set(), bytearray()
        for seq, data in segs:
            if seq in seen:
                continue
            seen.add(seq)
            buf += data
        flows[key] = bytes(buf)
    flows.update(udp_blobs)
    return flows


def _dicom_ul_ae_titles(flow):
    """If a flow begins with a DICOM upper-layer A-ASSOCIATE-RQ/AC PDU, pull the AE titles and the
    UIDs out of the variable items. Pure byte-offset parse (no scapy needed)."""
    if len(flow) < 74 or flow[0] not in (1, 2):             # 1=A-ASSOCIATE-RQ, 2=AC; header+fixed = 74
        return None
    if flow[1] != 0 or struct.unpack_from(">H", flow, 6)[0] != 1:   # reserved byte, protocol_version
        return None
    pdu_len = struct.unpack_from(">I", flow, 2)[0]
    if pdu_len < 68 or pdu_len > len(flow):                  # the RQ/AC PDU fits within the flow
        return None
    body = flow[6:6 + pdu_len]
    if len(body) < 68:
        return None
    called = body[4:20].decode("latin-1", "replace").strip()
    calling = body[20:36].decode("latin-1", "replace").strip()
    out = {"pdu": "A-ASSOCIATE-RQ" if flow[0] == 1 else "A-ASSOCIATE-AC",
           "called_ae_title": called, "calling_ae_title": calling,
           "application_context": None, "abstract_syntaxes": [], "transfer_syntaxes": []}
    # Variable items start at body[68]: type(1) reserved(1) length(2) value.
    o = 68
    while o + 4 <= len(body):
        itype = body[o]
        ilen = struct.unpack_from(">H", body, o + 2)[0]
        val = body[o + 4:o + 4 + ilen]
        if itype == 0x10:
            out["application_context"] = val.decode("latin-1", "replace").strip()
        elif itype in (0x20, 0x21):                          # presentation context RQ/AC: has sub-items
            _dicom_pres_context(val, out)
        o += 4 + ilen
    return out


def _dicom_pres_context(val, out):
    # Presentation-context sub-items: skip the 4-byte header, then type/len/value sub-items.
    o = 4
    while o + 4 <= len(val):
        stype = val[o]
        slen = struct.unpack_from(">H", val, o + 2)[0]
        sval = val[o + 4:o + 4 + slen].decode("latin-1", "replace").strip()
        if stype == 0x30:
            out["abstract_syntaxes"].append(sval)
        elif stype == 0x40:
            out["transfer_syntaxes"].append(sval)
        o += 4 + slen


# ---- DICOM upper layer: P-DATA-TF fragments and DIMSE command sets (B-078) ------------------------------
# PS3.8 section 9.3: every PDU is type(1) reserved(1) length(4, big-endian) + body. A P-DATA-TF body is
# a run of presentation-data-value items: item-length(4, big-endian) context-id(1) message-control(1)
# fragment. Message control bit 0 says command (1) or data set (0), bit 1 marks the last fragment.
# PS3.7: a command set is group 0000 in Implicit VR Little Endian whatever the negotiated transfer
# syntax; (0000,0100) CommandField names the DIMSE service (0x0001 is C-STORE-RQ).

DICOM_PDU_TYPES = {1: "A-ASSOCIATE-RQ", 2: "A-ASSOCIATE-AC", 3: "A-ASSOCIATE-RJ", 4: "P-DATA-TF",
                   5: "A-RELEASE-RQ", 6: "A-RELEASE-RP", 7: "A-ABORT"}
DIMSE_COMMANDS = {
    0x0001: "C-STORE-RQ", 0x8001: "C-STORE-RSP", 0x0010: "C-GET-RQ", 0x8010: "C-GET-RSP",
    0x0020: "C-FIND-RQ", 0x8020: "C-FIND-RSP", 0x0021: "C-MOVE-RQ", 0x8021: "C-MOVE-RSP",
    0x0030: "C-ECHO-RQ", 0x8030: "C-ECHO-RSP", 0x0FFF: "C-CANCEL-RQ",
    0x0100: "N-EVENT-REPORT-RQ", 0x8100: "N-EVENT-REPORT-RSP", 0x0110: "N-GET-RQ", 0x8110: "N-GET-RSP",
    0x0120: "N-SET-RQ", 0x8120: "N-SET-RSP", 0x0130: "N-ACTION-RQ", 0x8130: "N-ACTION-RSP",
    0x0140: "N-CREATE-RQ", 0x8140: "N-CREATE-RSP", 0x0150: "N-DELETE-RQ", 0x8150: "N-DELETE-RSP",
}
C_STORE_RQ = 0x0001
_NO_DATASET = 0x0101                                       # (0000,0800) CommandDataSetType: no data set
_FIXED_PDU_LEN = {3: 4, 5: 4, 6: 4, 7: 4}                  # RJ, RELEASE-RQ/RP and ABORT bodies are 4 bytes
MAX_DICOM_PDUS = 200_000


def dicom_ul_pdus(data, max_pdus=MAX_DICOM_PDUS):
    """Walk whole DICOM upper-layer PDUs from offset 0 of `data`.

    Returns (pdus, consumed): pdus is [{"type", "name", "offset", "length"}] (length is the body's),
    consumed the offset after the last whole PDU. The walk stops, without raising, at the first
    position that is not a PDU header (type 1..7, reserved byte 0, a body length the type allows) or
    at a PDU whose body is cut."""
    pdus, o, n = [], 0, len(data)
    while o + 6 <= n and len(pdus) < max_pdus:
        ptype = data[o]
        if ptype not in DICOM_PDU_TYPES or data[o + 1] != 0:
            break
        length = struct.unpack_from(">I", data, o + 2)[0]
        fixed = _FIXED_PDU_LEN.get(ptype)
        if (fixed is not None and length != fixed) or (ptype in (1, 2) and length < 68) \
                or (ptype == 4 and length < 6) or o + 6 + length > n:
            break
        pdus.append({"type": ptype, "name": DICOM_PDU_TYPES[ptype], "offset": o, "length": length})
        o += 6 + length
    return pdus, o


def dicom_pdvs(body):
    """The presentation-data-value items of one P-DATA-TF body:
    [(context_id, is_command, is_last, fragment)], or None when the item lengths do not tile the body
    exactly or a reserved message-control bit is set (then it is not a P-DATA-TF body)."""
    out, o, n = [], 0, len(body)
    while o < n:
        if o + 6 > n:
            return None
        ilen = struct.unpack_from(">I", body, o)[0]
        if ilen < 2 or o + 4 + ilen > n:
            return None
        mch = body[o + 5]
        if mch & 0xFC:
            return None
        out.append((body[o + 4], bool(mch & 1), bool(mch & 2), bytes(body[o + 6:o + 4 + ilen])))
        o += 4 + ilen
    return out or None


def parse_dimse_command(cmd):
    """A DIMSE command set (group 0000, Implicit VR Little Endian) as a dict, or None when the bytes
    are not one: an element outside group 0000, a length that overruns, or no 2-byte CommandField."""
    o, n, el = 0, len(cmd), {}
    while o + 8 <= n:
        group, elem, length = struct.unpack_from("<HHI", cmd, o)
        if group != 0 or o + 8 + length > n:
            return None
        el[elem] = bytes(cmd[o + 8:o + 8 + length])
        o += 8 + length
    if o != n or len(el.get(0x0100, b"")) != 2:
        return None

    def us(e):
        v = el.get(e)
        return struct.unpack("<H", v)[0] if v is not None and len(v) == 2 else None

    def ui(e):
        v = el.get(e)
        return v.rstrip(b"\x00 ").decode("latin-1") if v else None

    field, dstype = us(0x0100), us(0x0800)
    return {"command_field": field, "command": DIMSE_COMMANDS.get(field, f"0x{field:04x}"),
            "message_id": us(0x0110), "message_id_responded_to": us(0x0120), "status": us(0x0900),
            "affected_sop_class_uid": ui(0x0002), "affected_sop_instance_uid": ui(0x1000),
            "has_dataset": dstype is not None and dstype != _NO_DATASET, "dataset_bytes": 0}


def dicom_dimse_messages(data):
    """The DIMSE messages in a byte run that starts on a PDU boundary (a flow, or one segment).

    Returns {"pdus": {name: count}, "messages": [...], "consumed": int, "complete": bool}. A message
    is parse_dimse_command()'s dict plus "offset" (of the PDU that completed its command set),
    "context_id" and "dataset_bytes" (the data-set fragments that followed it on the same
    presentation context). Command fragments split over several PDVs or PDUs are joined before they
    are parsed. `complete` is True when every byte was a whole PDU; bytes after `consumed` were not
    read."""
    pdus, _ = dicom_ul_pdus(data)
    counts, messages, cmd_buf, current = {}, [], {}, {}
    end = 0
    for pdu in pdus:
        if pdu["type"] == 4:
            pdvs = dicom_pdvs(data[pdu["offset"] + 6:pdu["offset"] + 6 + pdu["length"]])
            if pdvs is None:
                break                                     # not P-DATA after all: stop before it
            for ctx, is_command, is_last, frag in pdvs:
                if is_command:
                    cmd_buf[ctx] = cmd_buf.get(ctx, b"") + frag
                    if is_last:
                        msg = parse_dimse_command(cmd_buf.pop(ctx))
                        current[ctx] = msg
                        if msg is not None:
                            msg["offset"] = pdu["offset"]
                            msg["context_id"] = ctx
                            messages.append(msg)
                elif current.get(ctx) is not None:
                    current[ctx]["dataset_bytes"] += len(frag)
        counts[pdu["name"]] = counts.get(pdu["name"], 0) + 1
        end = pdu["offset"] + 6 + pdu["length"]
    return {"pdus": counts, "messages": messages, "consumed": end, "complete": end == len(data) and end > 0}


def dicom_flow_dimse(segments, stream=None):
    """The DIMSE messages of one direction of a TCP flow.

    `segments` are its payloads in capture order. When every segment ends on a PDU boundary (one PDU
    run per packet: the shape of a generated capture, where sequence numbers are often constant or
    repeat, so a reassembly that drops repeated sequence numbers would lose messages), the segments
    are read in capture order and each message carries "segment", the index of the segment its
    command set completed in. Otherwise `stream` (the reassembled flow) is read and "segment" is
    None. Returns {"framing": "segment" | "stream" | None, "messages", "pdus"}; framing None means
    the flow carries no DIMSE message."""
    segments = [bytes(seg) for seg in segments if seg]
    bounds, total = [], 0
    for seg in segments:
        total += len(seg)
        bounds.append(total)
    if segments:
        joined = b"".join(segments)
        pdus, consumed = dicom_ul_pdus(joined)
        ends = {p["offset"] + 6 + p["length"] for p in pdus}
        if consumed == len(joined) and all(b in ends for b in bounds):
            got = dicom_dimse_messages(joined)
            if got["complete"]:
                for m in got["messages"]:
                    m["segment"] = bisect.bisect_right(bounds, m["offset"])
                framing = "segment" if got["messages"] else None
                return {"framing": framing, "messages": got["messages"], "pdus": got["pdus"]}
    if stream:
        got = dicom_dimse_messages(stream)
        for m in got["messages"]:
            m["segment"] = None
        if got["messages"]:
            return {"framing": "stream", "messages": got["messages"], "pdus": got["pdus"]}
    return {"framing": None, "messages": [], "pdus": {}}


def parse_pcap(path):
    """Read a capture, reassemble TCP flows, and dissect healthcare payloads from them."""
    if not _have_scapy():
        return {"kind": "pcap", "error": "scapy not installed; cannot read the capture", "findings": [],
                "flags": []}
    report = {"kind": "pcap", "flows": 0, "findings": [], "flags": []}
    segments = {}
    try:
        flows = _reassemble_tcp(path, segments)
    except Exception as ex:                                   # noqa: BLE001
        return {"kind": "pcap", "error": f"capture read failed: {ex}", "findings": [], "flags": []}
    report["flows"] = len(flows)
    for key, data in flows.items():
        tag = f"{key[0]}:{key[2]} -> {key[1]}:{key[3]}"
        report["flags"].extend(find_flags(data))             # catch a flag even if no parser matches

        ul = _dicom_ul_ae_titles(data)
        if ul:
            ul["flow"] = tag
            report["findings"].append(ul)

        # DIMSE services carried in P-DATA-TF on this flow (B-078): which commands, how many, and
        # the C-STORE-RQ count (a store sent somewhere it should not go is the usual exfil shape).
        dimse = dicom_flow_dimse(segments.get(key, ()), data)
        if dimse["messages"]:
            by_cmd = {}
            for m in dimse["messages"]:
                by_cmd[m["command"]] = by_cmd.get(m["command"], 0) + 1
            report["findings"].append({
                "kind": "dicom-dimse", "flow": tag, "framing": dimse["framing"], "commands": by_cmd,
                "c_store_rq": sum(1 for m in dimse["messages"] if m["command_field"] == C_STORE_RQ),
                "message_ids": [m["message_id"] for m in dimse["messages"]][:64]})

        # Embedded DICOM Part-10 file (DICM at offset 128 of some region).
        idx = data.find(b"DICM")
        if idx >= 128:
            try:
                rep = parse_dicom(data[idx - 128:])
                rep["flow"] = tag
                report["findings"].append(rep)
                report["flags"].extend(rep["flags"])
            except Exception:
                pass

        # HL7 (MLLP-framed or a bare MSH| run).
        for m in re.finditer(rb"\x0b(.*?)\x1c", data, re.S):
            _try_hl7(m.group(1), tag, report)
        if b"\x0b" not in data:
            for m in re.finditer(rb"MSH\|.*?(?=(?:\r?\nMSH\||\Z))", data, re.S):
                _try_hl7(m.group(0), tag, report)

        # FHIR inside an HTTP body (after the blank line) or a bare JSON/XML resource.
        for body in _http_bodies(data):
            if b"resourceType" in body or b"hl7.org/fhir" in body:
                try:
                    rep = parse_fhir(body)
                    rep["flow"] = tag
                    report["findings"].append(rep)
                    report["flags"].extend(rep["flags"])
                except Exception:
                    pass

    report["flags"] = _dedup(report["flags"])
    return report


def _try_hl7(blob, tag, report):
    try:
        rep = parse_hl7(blob)
        rep["flow"] = tag
        report["findings"].append(rep)
        report["flags"].extend(rep["flags"])
    except Exception:
        pass


def _http_bodies(data):
    """Yield the body of each HTTP request/response in a flow (bytes after the header block)."""
    out = []
    for m in re.finditer(rb"(?:HTTP/\d\.\d|POST|PUT|GET|PATCH)[^\r\n]*\r\n", data):
        start = m.start()
        sep = data.find(b"\r\n\r\n", start)
        if sep >= 0:
            out.append(data[sep + 4:])
    if not out and data.lstrip()[:1] in (b"{", b"<"):
        out.append(data)
    return out


# ======================================================================== dispatch + rendering

def sniff_kind(data):
    """Guess the artifact kind from its bytes."""
    if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") \
            or data[:4] == b"\x0a\x0d\x0d\x0a":
        return "pcap"
    if len(data) >= 132 and data[128:132] == b"DICM":
        return "dicom"
    stripped = strip_mllp(data) if isinstance(data, (bytes, bytearray)) else data.encode()
    if stripped[:4] == b"MSH|" or data[:1] == b"\x0b":
        return "hl7"
    head = bytes(data).lstrip()[:1]
    if head == b"{" and b"resourceType" in bytes(data)[:4096]:
        return "fhir"
    if head == b"<" and (b"hl7.org/fhir" in bytes(data)[:4096] or b"resourceType" in bytes(data)[:4096]):
        return "fhir"
    # Bare DICOM data set?
    if len(data) >= 8:
        g = struct.unpack_from("<H", data, 0)[0]
        if g in (0x0002, 0x0008):
            return "dicom"
    return "unknown"


def analyze(data, name="<data>", kind=None, path=None):
    """Produce a report dict for one artifact. `kind` forces a parser; else it is sniffed."""
    kind = kind or sniff_kind(data)
    try:
        if kind == "pcap":
            rep = parse_pcap(path) if path else {"kind": "pcap",
                                                 "error": "pcap needs a file path", "findings": [], "flags": []}
        elif kind == "dicom":
            rep = parse_dicom(data)
        elif kind == "hl7":
            rep = parse_hl7(data)
        elif kind == "fhir":
            rep = parse_fhir(data)
        else:
            rep = {"kind": "unknown", "flags": find_flags(data),
                   "note": "no DICOM/HL7/FHIR/pcap signature recognised; raw flag scan only"}
    except Exception as ex:                                   # noqa: BLE001
        rep = {"kind": kind, "error": str(ex), "flags": find_flags(data)}
    rep["file"] = name
    rep.setdefault("flags", [])
    return rep


# ---- human-readable rendering ----------------------------------------------------------------------

def _c(s, code, tty):
    return f"\x1b[{code}m{s}\x1b[0m" if tty else s


def _render(rep, tty):
    out = []
    name = rep.get("file", "<data>")
    kind = rep.get("kind", "?")
    out.append(_c(f"# {name}  [{kind}]", "1", tty))
    if rep.get("error"):
        out.append(f"  error: {rep['error']}")

    flags = rep.get("flags") or []
    if flags:
        out.append(_c(">>> FLAG FORMAT HIT" + ("S" if len(flags) > 1 else ""), "1;93", tty))
        for f in flags:
            out.append("    " + _c(f, "7;92", tty))

    if kind == "dicom":
        out += _render_dicom(rep, tty)
    elif kind == "hl7":
        out += _render_hl7(rep, tty)
    elif kind == "fhir":
        out += _render_fhir(rep, tty)
    elif kind == "pcap":
        out += _render_pcap(rep, tty)
    elif kind == "unknown":
        out.append("  " + (rep.get("note") or "no structure"))
    for n in rep.get("notes", []) or []:
        out.append(_c(f"  note: {n}", "2", tty))
    return "\n".join(out)


def _render_dicom(rep, tty):
    out = []
    ts = rep.get("transfer_syntax")
    tsn = rep.get("transfer_syntax_name")
    enc = ("Explicit" if rep.get("explicit_vr") else "Implicit") + " VR, " + \
          ("Little" if rep.get("little_endian") else "Big") + " Endian"
    out.append(f"  Part-10: {rep.get('part10')}   transfer syntax: {ts or '?'}"
               + (f" ({tsn})" if tsn else "") + f"   data set: {enc}")
    if rep.get("pixel_data"):
        pd = rep["pixel_data"]
        out.append(f"  PixelData (7FE0,0010): present, {pd.get('length')} bytes, VR {pd.get('vr')}"
                   + (", encapsulated" if pd.get("encapsulated") else ", native"))
    else:
        out.append("  PixelData: none")
    meta = rep.get("meta") or []
    if meta:
        out.append(_c("  -- File Meta (0002) --", "36", tty))
        for el in meta:
            out.append("    " + _fmt_el(el, tty))
    out.append(_c("  -- Data Set --", "36", tty))
    for el in rep.get("elements", []):
        out += _fmt_el_tree(el, tty, indent="    ")
    return out


def _fmt_el_tree(el, tty, indent):
    lines = [indent + _fmt_el(el, tty)]
    if el.get("vr") == "SQ":
        for i, item in enumerate(el.get("items", [])):
            lines.append(indent + f"  Item {i}:")
            for child in item:
                lines += _fmt_el_tree(child, tty, indent + "    ")
    return lines


def _fmt_el(el, tty):
    tag = el["tag"]
    kw = el.get("keyword") or ""
    vr = el.get("vr") or "??"
    val = el.get("value", "")
    marks = []
    if el.get("private"):
        marks.append(_c("PRIVATE", "35", tty))
    if el.get("overlay"):
        marks.append(_c("OVERLAY", "35", tty))
    if el.get("freetext"):
        marks.append(_c("free-text", "33", tty))
    mk = ("  " + " ".join(marks)) if marks else ""
    name = _c(kw, "32", tty) if kw else _c("(unknown)", "2", tty)
    if vr == "SQ":
        return f"{tag} {name} SQ ({len(el.get('items', []))} item(s)){mk}"
    return f"{tag} {name} {vr}: {val}{mk}"


def _render_hl7(rep, tty):
    out = [f"  message type: {rep.get('message_type')}   field sep '{rep.get('field_sep')}'"
           f"   encoding '{rep.get('encoding_chars')}'   segments: {len(rep.get('segments', []))}"]
    for seg in rep.get("segments", []):
        out.append(_c(f"  {seg['id']}", "36", tty))
        for idx, val in seg["fields"].items():
            flat = _hl7_field_str(val)
            if flat != "":
                out.append(f"    {seg['id']}-{idx}: {flat}")
    return out


def _hl7_field_str(val):
    if isinstance(val, str):
        return val
    if isinstance(val, list):
        parts = []
        for comp in val:
            if isinstance(comp, list):
                parts.append("&".join(str(x) for x in comp))
            else:
                parts.append(str(comp))
        return "^".join(parts)
    return str(val)


def _render_fhir(rep, tty):
    out = [f"  resourceType: {rep.get('resourceType')}   format: {rep.get('format')}"]
    for res in rep.get("resources", []):
        ke = res.get("key_elements") or {}
        kestr = "  ".join(f"{k}={v}" for k, v in ke.items())
        out.append(_c(f"  - {res.get('resourceType')}", "36", tty) + (f"   {kestr}" if kestr else ""))
    strings = rep.get("strings") or []
    if strings:
        out.append(_c(f"  ({len(strings)} string values scanned for flags)", "2", tty))
    return out


def _render_pcap(rep, tty):
    out = []
    if rep.get("error"):
        return out
    out.append(f"  flows: {rep.get('flows')}   findings: {len(rep.get('findings', []))}")
    for fnd in rep.get("findings", []):
        k = fnd.get("kind") or fnd.get("pdu")
        flow = fnd.get("flow", "")
        if fnd.get("pdu"):
            out.append(_c(f"  [{fnd['pdu']}] {flow}", "36", tty))
            out.append(f"    called AE: {fnd.get('called_ae_title')!r}  "
                       f"calling AE: {fnd.get('calling_ae_title')!r}")
            if fnd.get("abstract_syntaxes"):
                out.append(f"    abstract syntaxes: {', '.join(fnd['abstract_syntaxes'])}")
            if fnd.get("transfer_syntaxes"):
                out.append(f"    transfer syntaxes: {', '.join(fnd['transfer_syntaxes'])}")
        elif k == "dicom-dimse":
            out.append(_c(f"  [DIMSE] {flow}", "36", tty))
            out.append("    commands: " + ", ".join(f"{n} x{c}" for n, c in sorted(fnd["commands"].items()))
                       + f"   C-STORE-RQ: {fnd['c_store_rq']}   (framing: {fnd['framing']})")
        else:
            out.append(_c(f"  [{k}] {flow}", "36", tty))
            sub = _render(dict(fnd, file=""), tty).split("\n")
            out += ["  " + ln for ln in sub[1:]]
    return out


# ======================================================================== CLI

def report(path, kind=None):
    """Convenience: analyze one file path and return its report dict."""
    data = Path(path).read_bytes()
    return analyze(data, name=str(path), kind=kind, path=path)


def reports(files, kind=None):
    """Analyze a mapping {name: bytes} or an iterable of paths; return a list of report dicts."""
    out = []
    if isinstance(files, dict):
        for name, data in files.items():
            out.append(analyze(data if isinstance(data, (bytes, bytearray)) else Path(data).read_bytes(),
                               name=str(name), kind=kind))
    else:
        for p in files:
            try:
                out.append(report(p, kind=kind))
            except OSError as e:
                out.append({"file": str(p), "kind": "error", "error": str(e), "flags": []})
    return out


def _json_default(o):
    if isinstance(o, (bytes, bytearray)):
        return o.hex()
    return str(o)


def main(argv):
    as_json = "--json" in argv
    kind = None
    args = []
    it = iter(argv)
    for a in it:
        if a == "--json":
            continue
        if a == "--kind":
            kind = next(it, None)
            continue
        if a.startswith("--kind="):
            kind = a.split("=", 1)[1]
            continue
        args.append(a)
    if not args:
        print("usage: healthcare.py <file>... [--kind dicom|hl7|fhir|pcap] [--json]\n"
              "  reads DICOM (.dcm), HL7 v2, FHIR (json/xml) artifacts and .pcap/.pcapng captures;\n"
              "  highlights any CSCTF flag-format text found in the decoded content.", file=sys.stderr)
        return 2

    results = []
    for p in args:
        try:
            data = Path(p).read_bytes()
        except OSError as e:
            print(f"healthcare.py: {p}: {e}", file=sys.stderr)
            results.append({"file": p, "kind": "error", "error": str(e), "flags": []})
            continue
        results.append(analyze(data, name=p, kind=kind, path=p))

    if as_json:
        print(json.dumps(results, indent=1, default=_json_default))
        return 0

    tty = sys.stdout.isatty()
    any_flag = False
    for rep in results:
        print(_render(rep, tty))
        print()
        if rep.get("flags"):
            any_flag = True
    if any_flag:
        allf = _dedup([f for r in results for f in (r.get("flags") or [])])
        print(_c(f"FLAGS RECOVERED ({len(allf)}): " + "  ".join(allf), "1;93", tty))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
