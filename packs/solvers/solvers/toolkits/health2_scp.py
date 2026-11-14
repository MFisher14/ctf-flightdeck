#!/usr/bin/env python3
"""Offline SCP-ECG v1/v2 reader for the uncompressed 16-bit rhythm profile.

Checks record/section CRCs, pointer tables and lengths, exposes patient TLVs,
and decodes section 6 raw/first-difference/second-difference samples. Huffman,
bimodal decimation, reference-beat subtraction, and v3 data are rejected, never
silently treated as raw samples. This is a forensic reader, not a conformance
validator or a clinical tool. Unknown patient TLVs remain available as hex.

CLI: python health2_scp.py recording.scp [--samples]
Reference: https://devel.support.cardio.ai/api/formats/scp/
"""

import argparse
import binascii
import json
import struct
import sys
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_FILE = 64 * 1024 * 1024
MAX_SAMPLES = 2_000_000
_TEXT_TAGS = {0, 1, 2, 3, 13, 16, 17, 18, 19, 20, 21, 22, 23, 30, 31, 35}
_TAG_NAMES = {0: "LastName", 1: "FirstName", 2: "PatientID", 3: "SecondLastName",
              13: "Diagnosis", 14: "AcquiringDevice", 15: "AnalyzingDevice",
              16: "AcquiringInstitution", 17: "AnalyzingInstitution", 18: "AcquiringDepartment",
              19: "AnalyzingDepartment", 20: "ReferringPhysician", 21: "ConfirmingPhysician",
              22: "Technician", 23: "Room", 25: "AcquisitionDate", 26: "AcquisitionTime",
              30: "FreeText", 31: "ECGSequenceNumber", 35: "MedicalHistory"}


class ScpError(ValueError):
    """Malformed, unsupported, oversized, or unreadable SCP-ECG input."""


def _patient_tlvs(payload):
    result, offset = [], 0
    while offset + 3 <= len(payload):
        tag, length = struct.unpack_from("<BH", payload, offset)
        offset += 3
        if tag == 255:
            if length or payload[offset:] not in (b"", b"\0"):
                raise ScpError("bad patient-section terminator or padding")
            return result
        if offset + length > len(payload):
            raise ScpError("truncated patient TLV")
        value = payload[offset:offset + length]
        item = {"tag": tag, "name": _TAG_NAMES.get(tag, "Unknown"), "hex": value.hex()}
        if tag in _TEXT_TAGS:
            item["text"] = value.rstrip(b"\0").decode("latin-1")
        result.append(item)
        if len(result) > 4096:
            raise ScpError("too many patient TLVs")
        offset += length
    raise ScpError("missing patient-section terminator")


def parse_scp(data, *, max_samples=MAX_SAMPLES):
    """Return section inventory, patient TLVs and decoded per-lead samples.

    All malformed-input failures become ScpError. ``start_sample`` is one-based;
    scale raw counts by ``resolution_nv`` for nanovolts. No data is executed.
    """
    try:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise ScpError("input must be bytes")
        if not isinstance(max_samples, int) or isinstance(max_samples, bool) or max_samples < 1:
            raise ScpError("max_samples must be a positive integer")
        if not 142 <= len(data) <= MAX_FILE:
            raise ScpError("invalid file size")
        data = bytes(data)
        crc, length = struct.unpack_from("<HI", data)
        if length != len(data) or binascii.crc_hqx(data[2:], 65535) != crc:
            raise ScpError("record length or CRC mismatch")
        offset, sections = 6, {}
        while offset < len(data):
            if offset + 16 > len(data):
                raise ScpError("truncated section header")
            check, sid, size, version, protocol, reserved = struct.unpack_from("<HHIBB6s", data, offset)
            if sid in sections or size < 16 or size % 2 or offset + size > len(data):
                raise ScpError("duplicate section or invalid section length")
            if not 10 <= protocol < 30:
                raise ScpError("only SCP-ECG v1/v2 profiles are supported")
            if reserved != (b"SCPECG" if sid == 0 else b"\0" * 6):
                raise ScpError("invalid section signature or reserved bytes")
            if binascii.crc_hqx(data[offset + 2:offset + size], 65535) != check:
                raise ScpError(f"section {sid} CRC mismatch")
            sections[sid] = {"offset": offset, "length": size, "version": version,
                             "protocol": protocol, "payload": data[offset + 16:offset + size]}
            if len(sections) > 1024:
                raise ScpError("too many sections")
            offset += size
        if not {0, 1, 3, 6} <= sections.keys() or sections[0]["offset"] != 6:
            raise ScpError("required sections 0, 1, 3, 6 missing or misplaced")
        pointers = sections[0]["payload"]
        if len(pointers) < 120 or len(pointers) % 10:
            raise ScpError("invalid pointer table length")
        entries = list(struct.iter_unpack("<HII", pointers))
        ids = [sid for sid, _, _ in entries]
        if ids != sorted(set(ids)) or not set(range(12)) <= set(ids):
            raise ScpError("pointer table must inventory sections 0..11 in order")
        for sid, size, index in entries:
            section = sections.get(sid)
            if section is None:
                if size or index:
                    raise ScpError("pointer references an absent section")
            elif size != section["length"] or index != section["offset"] + 1:
                raise ScpError("section pointer disagrees with section boundary")
        if not sections.keys() <= set(ids):
            raise ScpError("unlisted section")
        if 2 in sections:
            raise ScpError("Huffman table sections are unsupported")
        lead_data = sections[3]["payload"]
        nleads, flags = struct.unpack_from("<BB", lead_data)
        if not 1 <= nleads <= 64 or flags & 3:
            raise ScpError("unsupported lead count, reference-beat subtraction or reserved flags")
        expected = 2 + 9 * nleads
        if len(lead_data) != expected + expected % 2 or lead_data[expected:] not in (b"", b"\0"):
            raise ScpError("invalid lead definition length/padding")
        descriptors = list(struct.iter_unpack("<IIB", lead_data[2:expected]))
        if any(start < 1 or end < start for start, end, _ in descriptors):
            raise ScpError("invalid lead sample range")
        if sum(end - start + 1 for start, end, _ in descriptors) > max_samples:
            raise ScpError("sample allocation limit exceeded")
        rhythm = sections[6]["payload"]
        avm, interval, difference, bimodal = struct.unpack_from("<HHBB", rhythm)
        if avm == 0 or interval == 0 or difference not in (0, 1, 2) or bimodal:
            raise ScpError("invalid scale/interval or unsupported rhythm encoding")
        lengths = struct.unpack_from("<" + "H" * nleads, rhythm, 6)
        offset = 6 + 2 * nleads
        leads = []
        for (start, end, lead_id), size in zip(descriptors, lengths):
            count = end - start + 1
            if size != 2 * count or offset + size > len(rhythm):
                raise ScpError("rhythm length disagrees with lead sample range")
            samples = [x[0] for x in struct.iter_unpack("<h", rhythm[offset:offset + size])]
            for i in range(difference, count):
                if difference == 1:
                    samples[i] += samples[i - 1]
                elif difference == 2:
                    samples[i] += 2 * samples[i - 1] - samples[i - 2]
                if not -32768 <= samples[i] <= 32767:
                    raise ScpError("reconstructed sample exceeds signed 16-bit range")
            leads.append({"lead_id": lead_id, "start_sample": start, "end_sample": end,
                          "samples": samples})
            offset += size
        if offset != len(rhythm):
            raise ScpError("unexpected trailing rhythm bytes")
        return {"format": "SCP-ECG v1/v2 raw16", "resolution_nv": avm,
                "sample_interval_us": interval, "sample_rate_hz": 1_000_000 / interval,
                "difference_order": difference, "leads": leads,
                "patient_fields": _patient_tlvs(sections[1]["payload"]),
                "sections": [{"id": sid, **{k: v for k, v in section.items() if k != "payload"}}
                             for sid, section in sections.items()],
                # binary sections and packed tag fields: no word boundary before a flag (R-16)
                "flags": list(dict.fromkeys(flagfmt.PACKED_TEXT.findall(data.decode("latin-1"))))}
    except ScpError:
        raise
    except Exception as exc:
        raise ScpError(f"invalid SCP-ECG data: {exc}") from None


def read_scp(path, *, max_samples=MAX_SAMPLES):
    try:
        with Path(path).open("rb") as source:
            return parse_scp(source.read(MAX_FILE + 1), max_samples=max_samples)
    except ScpError:
        raise
    except Exception as exc:
        raise ScpError(f"cannot read SCP-ECG: {exc}") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file")
    parser.add_argument("--samples", action="store_true", help="include all decoded samples in JSON")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        result = read_scp(args.file)
        if not args.samples:
            for lead in result["leads"]:
                samples = lead.pop("samples")
                lead.update(samples_preview=samples[:16], minimum_raw=min(samples), maximum_raw=max(samples))
        print(json.dumps(result, indent=2))
        return 0
    except Exception as exc:
        print(f"SCP-ECG error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
