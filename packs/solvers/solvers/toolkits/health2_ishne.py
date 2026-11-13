#!/usr/bin/env python3
"""Strict offline ISHNE 1.0 Holter ECG reader (Badilini et al., 1998).

Reads the complete 512-byte fixed header, variable comments, header CRC-CCITT,
and multiplexed little-endian signed samples. No clinical interpretation is
performed. The published sample-count convention is per lead; the common
total-samples convention requires an explicit option to avoid accepting a
truncated recording. The -32768 value is preserved, not assumed missing.

CLI: python health2_ishne.py recording.ecg [--csv samples.csv] [--preview 16]
Source: https://www.ampsmedical.com/uploads/2017-12-7/The_ISHNE_Format.pdf
"""

import argparse
import binascii
import csv
import datetime
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
LEAD_NAMES = ("unknown", "bipolar", "X", "Y", "Z", "I", "II", "III",
              "aVR", "aVL", "aVF", "V1", "V2", "V3", "V4", "V5", "V6",
              "ES", "AS", "AI")


class IshneError(ValueError):
    """Malformed, unsupported, oversized, or unreadable ISHNE input."""


def _date(raw):
    if any(x in (0, -9) for x in raw):
        return None
    return datetime.date(raw[2], raw[1], raw[0]).isoformat()


def parse_ishne(data, *, max_samples=MAX_SAMPLES, count_convention="per_lead"):
    """Return metadata and per-lead raw samples; failures raise only IshneError.

    max_samples caps the total number of scalar samples allocated, not frames.
    The returned lead's ``resolution_nv`` scales raw counts into nanovolts.
    """
    try:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise IshneError("input must be bytes")
        if not isinstance(max_samples, int) or isinstance(max_samples, bool) or max_samples < 1:
            raise IshneError("max_samples must be a positive integer")
        if count_convention not in ("per_lead", "total"):
            raise IshneError("count_convention must be per_lead or total")
        if not 522 <= len(data) <= MAX_FILE:
            raise IshneError("file must contain 522 bytes through 64 MiB")
        data = bytes(data)
        if data[:8] != b"ISHNE1.0":
            raise IshneError("missing ISHNE1.0 signature")
        var_size, declared_samples, var_offset, ecg_offset = struct.unpack_from("<4i", data, 10)
        if var_size < 0 or var_offset != 522 or ecg_offset != 522 + var_size:
            raise IshneError("inconsistent header offsets or variable block size")
        if ecg_offset > len(data):
            raise IshneError("truncated variable header")
        stored_crc = struct.unpack_from("<H", data, 8)[0]
        if binascii.crc_hqx(data[10:ecg_offset], 0xFFFF) != stored_crc:
            raise IshneError("header CRC-CCITT mismatch")
        nleads = struct.unpack_from("<h", data, 156)[0]
        rate = struct.unpack_from("<h", data, 272)[0]
        if not 1 <= nleads <= 12 or rate <= 0 or declared_samples <= 0:
            raise IshneError("invalid lead count, sampling rate, or sample count")
        scalar_count, remainder = divmod(len(data) - ecg_offset, 2)
        if remainder or scalar_count % nleads:
            raise IshneError("truncated multiplexed sample frame")
        expected_samples = declared_samples * nleads if count_convention == "per_lead" else declared_samples
        if scalar_count != expected_samples:
            raise IshneError("declared sample count disagrees with file size")
        if scalar_count > max_samples:
            raise IshneError("sample allocation limit exceeded")
        specs = struct.unpack_from("<12h", data, 158)
        quality = struct.unpack_from("<12h", data, 182)
        resolution = struct.unpack_from("<12h", data, 206)
        if any(x < 0 or x >= len(LEAD_NAMES) for x in specs[:nleads]):
            raise IshneError("unsupported lead code")
        if any(x not in range(6) for x in quality[:nleads]) or any(x <= 0 for x in resolution[:nleads]):
            raise IshneError("invalid lead quality or amplitude resolution")
        if any(x != -9 for values in (specs, quality, resolution) for x in values[nleads:]):
            raise IshneError("unused lead descriptors must be -9")
        metadata = {}
        for name, offset, size in (("first_name", 28, 40), ("last_name", 68, 40),
                                   ("patient_id", 108, 20), ("recorder", 232, 40),
                                   ("proprietary", 274, 80), ("copyright", 354, 80),
                                   ("reserved", 434, 88)):
            metadata[name] = data[offset:offset + size].rstrip(b"\x00").decode("latin-1")
        for name, offset in (("file_version", 26), ("sex", 128), ("race", 130), ("pacemaker", 230)):
            metadata[name] = struct.unpack_from("<h", data, offset)[0]
        for name, offset in (("birth_date", 132), ("record_date", 138), ("file_date", 144)):
            raw = struct.unpack_from("<3h", data, offset)
            metadata[name] = _date(raw)
            metadata[name + "_raw"] = list(raw)
        time = struct.unpack_from("<3h", data, 150)
        metadata["start_time"] = None if -9 in time else datetime.time(*time).isoformat()
        metadata["comments"] = data[522:ecg_offset].decode("latin-1")
        leads = [{"code": specs[i], "name": LEAD_NAMES[specs[i]], "quality": quality[i],
                  "resolution_nv": resolution[i], "samples": []} for i in range(nleads)]
        for index, (value,) in enumerate(struct.iter_unpack("<h", data[ecg_offset:])):
            leads[index % nleads]["samples"].append(value)
        frames = scalar_count // nleads
        return {"format": "ISHNE1.0", "metadata": metadata, "header_crc": stored_crc,
                "sample_rate_hz": rate, "samples_per_lead": frames,
                "duration_seconds": frames / rate, "sample_count_convention": count_convention,
                "declared_samples": declared_samples, "leads": leads,
                # fixed-width header fields sit back to back: no word boundary before a flag (R-16)
                "flags": list(dict.fromkeys(flagfmt.PACKED_TEXT.findall(data[10:ecg_offset].decode("latin-1"))))}
    except IshneError:
        raise
    except Exception as exc:
        raise IshneError(f"invalid ISHNE data: {exc}") from None


def read_ishne(path, *, max_samples=MAX_SAMPLES, count_convention="per_lead"):
    """Read a bounded local file; never access network resources."""
    try:
        with Path(path).open("rb") as source:
            data = source.read(MAX_FILE + 1)
        return parse_ishne(data, max_samples=max_samples, count_convention=count_convention)
    except IshneError:
        raise
    except Exception as exc:
        raise IshneError(f"cannot read ISHNE file: {exc}") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file")
    parser.add_argument("--csv", help="write sample_index,time_seconds and each lead in raw counts")
    parser.add_argument("--preview", type=int, default=16, help="samples per lead shown in JSON (0..1000)")
    parser.add_argument("--count-convention", choices=("per_lead", "total"), default="per_lead",
                        help="header sample-count interpretation; published standard is per_lead")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if not 0 <= args.preview <= 1000:
            raise IshneError("preview must be between 0 and 1000")
        result = read_ishne(args.file, count_convention=args.count_convention)
        if args.csv:
            if Path(args.csv).resolve() == Path(args.file).resolve():
                raise IshneError("CSV output must differ from input")
            with Path(args.csv).open("x", newline="") as destination:
                writer = csv.writer(destination)
                writer.writerow(["sample_index", "time_seconds"] +
                                [f"lead_{i}_{x['name']}_raw" for i, x in enumerate(result["leads"])])
                for i in range(result["samples_per_lead"]):
                    writer.writerow([i, i / result["sample_rate_hz"]] +
                                    [x["samples"][i] for x in result["leads"]])
        for lead in result["leads"]:
            samples = lead.pop("samples")
            lead["minimum_raw"] = min(samples)
            lead["maximum_raw"] = max(samples)
            lead["samples_preview"] = samples[:args.preview]
        print(json.dumps(result, indent=2))
        return 0
    except Exception as exc:
        print(f"ISHNE error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
