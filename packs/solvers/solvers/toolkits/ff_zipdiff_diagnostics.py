#!/usr/bin/env python3
"""Bounded ZIP metadata differential diagnostics; never decompresses or extracts.

analyze_zip(bytes, **limits) returns JSON-compatible evidence for supported EOCD
views, or raises ZipDiffError. A finding is evidence about bytes, not a claim that
a particular extractor is exploitable. CRCs validate Unicode names/descriptors
only; member contents and compressed-stream integrity are deliberately unverified.
ZIP64 single-volume metadata is supported; multi-volume archives are reported,
not reconstructed. No network, file writes, password handling or payload execution.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
import zlib


class ZipDiffError(ValueError):
    """Malformed/unsupported ZIP structure or an exceeded analysis limit."""


class _LimitError(ZipDiffError):
    pass


_EOCD = b"PK\x05\x06"
_ZIP64 = b"PK\x06\x06"
_LOCATOR = b"PK\x06\x07"
_CENTRAL = b"PK\x01\x02"
_LOCAL = b"PK\x03\x04"
_DESCRIPTOR = b"PK\x07\x08"
MAX_INPUT = 32 << 20


class _Budget:
    def __init__(self, entries, findings, metadata):
        self.entries = entries
        self.findings = findings
        self.metadata = metadata

    def charge(self, kind, count=1):
        remaining = getattr(self, kind) - count
        if remaining < 0:
            raise _LimitError(f"{kind} analysis limit exceeded")
        setattr(self, kind, remaining)


def _unpack(fmt, data, at, end=None):
    size = struct.calcsize(fmt)
    if at < 0 or at + size > (len(data) if end is None else min(end, len(data))):
        raise ZipDiffError(f"truncated structure at offset {at}")
    return struct.unpack_from(fmt, data, at)


def _finding(out, budget, code, offset, **evidence):
    budget.charge("findings")
    out.append({"code": code, "offset": offset, **evidence})


def _extras(data, start):
    out, p = [], 0
    while p < len(data):
        tag, size = _unpack("<HH", data, p)
        if p + 4 + size > len(data):
            raise ZipDiffError(f"truncated extra field at offset {start + p}")
        out.append((tag, data[p + 4:p + 4 + size], start + p))
        p += 4 + size
    return out


def _zip64_values(extra, fields):
    """Only sentinel fields consume ZIP64 values, in the APPNOTE order."""
    needed = [(key, width) for key, value, width in fields
              if value == (1 << (width * 8)) - 1]
    result = {key: value for key, value, _ in fields}
    if not needed:
        return result
    blocks = [body for tag, body, _ in extra if tag == 1]
    if len(blocks) != 1:
        raise ZipDiffError("missing or duplicate required ZIP64 extra")
    p = 0
    for key, width in needed:
        # Ordinary fields are 32/16 bits; ZIP64 expands sizes/offsets to 64,
        # and the disk number to 32 bits.
        fmt = "<I" if key == "disk" else "<Q"
        result[key] = _unpack(fmt, blocks[0], p)[0]
        p += struct.calcsize(fmt)
    return result


def _path_reasons(name):
    reasons = []
    if not name:
        reasons.append("empty name")
    if "\x00" in name:
        reasons.append("NUL truncation ambiguity")
    normalized = name.replace("\\", "/")
    if normalized.startswith("/"):
        reasons.append("absolute or UNC path")
    if re.match(r"^[A-Za-z]:", normalized):
        reasons.append("Windows drive path")
    depth = 0
    for part in normalized.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if depth == 0:
                reasons.append("parent traversal escapes root")
                break
            depth -= 1
        else:
            depth += 1
    return reasons


def _name_info(raw, flags, extra, at, findings, budget, source):
    encoding = "utf-8" if flags & 0x800 else "cp437"
    try:
        name = raw.decode(encoding)
    except UnicodeError:
        name = None
        _finding(findings, budget, "invalid_utf8_name", at, source=source,
                 raw_hex=raw.hex())
    names = [] if name is None else [(encoding, name)]
    unicode_fields = []
    for tag, body, offset in extra:
        if tag != 0x7075:
            continue
        entry = {"offset": offset, "valid": False}
        if len(body) < 5:
            entry["reason"] = "short Unicode path extra"
        else:
            entry["version"] = body[0]
            entry["name_crc32"] = _unpack("<I", body, 1)[0]
            entry["actual_name_crc32"] = zlib.crc32(raw)
            if body[0] != 1:
                entry["reason"] = "unsupported Unicode path version"
            elif entry["name_crc32"] != entry["actual_name_crc32"]:
                entry["reason"] = "Unicode path CRC mismatch"
            else:
                try:
                    entry["name"] = body[5:].decode("utf-8")
                    entry["valid"] = True
                except UnicodeError:
                    entry["reason"] = "invalid Unicode path UTF-8"
        unicode_fields.append(entry)
        if entry["valid"]:
            names.append(("unicode_extra", entry["name"]))
            if name is not None and name != entry["name"]:
                _finding(findings, budget, "unicode_name_conflict", offset,
                         source=source, encoding=encoding, header_name=name,
                         unicode_name=entry["name"])
        else:
            _finding(findings, budget, "invalid_unicode_extra", offset,
                     source=source, reason=entry["reason"])
    if len(unicode_fields) > 1:
        _finding(findings, budget, "multiple_unicode_extras", at, source=source,
                 count=len(unicode_fields))
    for interpretation, candidate in names:
        reasons = _path_reasons(candidate)
        if reasons:
            _finding(findings, budget, "unsafe_path", at, source=source,
                     interpretation=interpretation, name=candidate, reasons=reasons)
    return {"raw_hex": raw.hex(), "encoding": encoding, "name": name,
            "unicode_paths": unicode_fields}


def _directory(data, start, size, count, budget):
    end = start + size
    if start < 0 or end > len(data) or count > size // 46:
        raise ZipDiffError("central-directory bounds or count is invalid")
    entries, p = [], start
    for index in range(count):
        budget.charge("entries")
        if data[p:p + 4] != _CENTRAL:
            raise ZipDiffError(f"missing central header at offset {p}")
        fields = _unpack("<6H3I5H2I", data, p + 4, end)
        made, need, flags, method, time, date, crc, csize, usize, n, x, c, disk, ia, ea, lho = fields
        stop = p + 46 + n + x + c
        if stop > end:
            raise ZipDiffError(f"central header exceeds directory at offset {p}")
        budget.charge("metadata", stop - p)
        raw = data[p + 46:p + 46 + n]
        extra = _extras(data[p + 46 + n:p + 46 + n + x], p + 46 + n)
        expanded = _zip64_values(extra, [("uncompressed_size", usize, 4),
            ("compressed_size", csize, 4), ("local_offset", lho, 4), ("disk", disk, 2)])
        entries.append({"index": index, "offset": p, "end": stop,
                        "made_by": made, "version_needed": need, "flags": flags,
                        "method": method, "time": time, "date": date, "crc32": crc,
                        "external_attributes": ea, "_raw": raw, "_extra": extra,
                        "zip64": any(tag == 1 for tag, _, _ in extra), **expanded})
        p = stop
    # The APPNOTE allows one digital signature at the end of the directory.
    if p < end and data[p:p + 4] == b"PK\x05\x05":
        length = _unpack("<H", data, p + 4, end)[0]
        p += 6 + length
    if p != end:
        raise ZipDiffError("central-directory size/count does not match records")
    return entries


def _end_record(data, at):
    disk, cd_disk, on_disk, count, size, start, comment = _unpack("<4H2IH", data, at + 4)
    end = at + 22 + comment
    if end > len(data):
        raise ZipDiffError("truncated EOCD comment")
    meta = {"eocd_offset": at, "eocd_end": end, "trailing_bytes": len(data) - end,
            "disk": disk, "central_disk": cd_disk, "entries_on_disk": on_disk,
            "entry_count": count, "central_size": size, "central_offset": start,
            "zip64": False, "anchor": at}
    sentinels = (disk == 0xFFFF or cd_disk == 0xFFFF or on_disk == 0xFFFF or
                 count == 0xFFFF or size == 0xFFFFFFFF or start == 0xFFFFFFFF)
    locator = at >= 20 and data[at - 20:at - 16] == _LOCATOR
    if not locator:
        if sentinels:
            raise ZipDiffError("ZIP64 sentinel without a ZIP64 locator")
        return meta
    loc_disk, loc_offset, disks = _unpack("<IQI", data, at - 16, at)
    # Try the declared position and an adjacent ZIP64 record. The latter allows
    # a prepended SFX prefix; variable-size extensions remain strictly bounded.
    positions = set()
    if data[loc_offset:loc_offset + 4] == _ZIP64:
        positions.add(loc_offset)
    p = max(0, at - 20 - (1 << 20))
    while True:
        p = data.find(_ZIP64, p, at - 20)
        if p < 0:
            break
        positions.add(p)
        if len(positions) > 128:
            raise _LimitError("ZIP64 end-record candidate limit exceeded")
        p += 4
    valid = []
    for p in positions:
        try:
            record_size = _unpack("<Q", data, p + 4, at - 20)[0]
            if record_size < 44 or p + 12 + record_size != at - 20:
                continue
            made, need, zdisk, zcd_disk, zon_disk, zcount, zsize, zstart = _unpack("<2H2I4Q", data, p + 12, at - 20)
            if p < loc_offset:
                continue
            valid.append((p, zdisk, zcd_disk, zon_disk, zcount, zsize, zstart))
        except ZipDiffError:
            continue
    if len(valid) != 1:
        raise ZipDiffError("missing or ambiguous ZIP64 end record")
    p, zdisk, zcd_disk, zon_disk, zcount, zsize, zstart = valid[0]
    meta.update(zip64=True, anchor=p, zip64_offset=p, zip64_locator_offset=at - 20,
                zip64_declared_offset=loc_offset, locator_disk=loc_disk, disk_count=disks,
                disk=zdisk, central_disk=zcd_disk, entries_on_disk=zon_disk,
                entry_count=zcount, central_size=zsize, central_offset=zstart)
    # Non-sentinel legacy fields must agree with the ZIP64 values.
    legacy = [(disk, 0xFFFF, zdisk), (cd_disk, 0xFFFF, zcd_disk),
              (on_disk, 0xFFFF, zon_disk), (count, 0xFFFF, zcount),
              (size, 0xFFFFFFFF, zsize), (start, 0xFFFFFFFF, zstart)]
    meta["legacy_conflicts"] = [[a, b] for a, sentinel, b in legacy if a != sentinel and a != b]
    return meta


def _descriptor(data, at, end, central, zip64):
    fmt = "<IQQ" if zip64 else "<III"
    matches, observations = [], []
    for signed in (False, True):
        if signed and data[at:at + 4] != _DESCRIPTOR:
            continue
        begin = at + (4 if signed else 0)
        stop = begin + struct.calcsize(fmt)
        if stop > end:
            continue
        crc, compressed, uncompressed = _unpack(fmt, data, begin, end)
        item = {"offset": at, "end": stop, "signed": signed, "zip64": zip64,
                "crc32": crc, "compressed_size": compressed,
                "uncompressed_size": uncompressed}
        observations.append(item)
        if (crc, compressed, uncompressed) == (central["crc32"], central["compressed_size"], central["uncompressed_size"]):
            matches.append(item)
    return {"status": "valid" if len(matches) == 1 else "ambiguous" if matches else "invalid",
            "matches": matches, "observations": observations}


def _local(data, entry, base, cd_start, findings, budget):
    at = base + entry["local_offset"]
    if entry["disk"]:
        _finding(findings, budget, "member_on_other_disk", entry["offset"],
                 entry=entry["index"], disk=entry["disk"])
        return None
    if at < 0 or at + 30 > cd_start or data[at:at + 4] != _LOCAL:
        raise ZipDiffError(f"missing or out-of-bounds local header at offset {at}")
    need, flags, method, time, date, crc, csize, usize, n, x = _unpack("<5H3I2H", data, at + 4, cd_start)
    body = at + 30 + n + x
    if body > cd_start:
        raise ZipDiffError("local header extends into central directory")
    budget.charge("metadata", body - at)
    raw = data[at + 30:at + 30 + n]
    extra = _extras(data[at + 30 + n:body], at + 30 + n)
    sizes = _zip64_values(extra, [("uncompressed_size", usize, 4), ("compressed_size", csize, 4)])
    local = {"offset": at, "data_offset": body, "version_needed": need,
             "flags": flags, "method": method, "time": time, "date": date,
             "crc32": crc, **sizes,
             "name": _name_info(raw, flags, extra, at + 30, findings, budget, "local")}
    for field in ("version_needed", "flags", "method", "time", "date", "crc32",
                  "compressed_size", "uncompressed_size"):
        value = local[field]
        # With bit 3, zero local CRC/sizes are ordinary placeholders.
        if field in ("crc32", "compressed_size", "uncompressed_size") and flags & 8 and value == 0:
            continue
        if value != entry[field]:
            _finding(findings, budget, "header_mismatch", at, entry=entry["index"],
                     field=field, central=entry[field], local=value)
    if raw != entry["_raw"]:
        _finding(findings, budget, "header_mismatch", at, entry=entry["index"],
                 field="name_bytes", central=entry["_raw"].hex(), local=raw.hex())
    stop = body + entry["compressed_size"]
    local["central_data_span"] = [body, stop]
    local["local_data_span"] = None if flags & 8 and sizes["compressed_size"] == 0 else [body, body + sizes["compressed_size"]]
    span_end = stop
    if stop > cd_start:
        _finding(findings, budget, "data_out_of_bounds", body, entry=entry["index"],
                 declared_end=stop, central_start=cd_start, interpretation="central")
    elif (entry["flags"] | flags) & 8:
        desc = _descriptor(data, stop, cd_start, entry,
                           entry["zip64"] or any(tag == 1 for tag, _, _ in extra))
        local["descriptor"] = desc
        if desc["status"] != "valid":
            _finding(findings, budget, "descriptor_" + desc["status"], stop,
                     entry=entry["index"], observations=desc["observations"])
        if desc["matches"]:
            span_end = max(item["end"] for item in desc["matches"])
    if local["local_data_span"] and local["local_data_span"][1] > cd_start:
        _finding(findings, budget, "data_out_of_bounds", body, entry=entry["index"],
                 declared_end=local["local_data_span"][1], central_start=cd_start,
                 interpretation="local")
    local["record_span"] = [at, span_end]
    return local


def _overlaps(entries, findings, budget):
    by_offset, spans, local_spans = {}, [], []
    for entry in entries:
        local = entry.get("local")
        if not local:
            continue
        start, end = local["record_span"]
        if start in by_offset:
            _finding(findings, budget, "local_header_alias", start,
                     entries=[by_offset[start], entry["index"]])
        else:
            by_offset[start] = entry["index"]
        spans.append((start, end, entry["index"]))
        if local["local_data_span"]:
            local_spans.append((start, local["local_data_span"][1], entry["index"]))
    # One witness per entry is sufficient to establish overlap, with O(n log n)
    # work even when thousands of entries reference exactly the same bytes.
    furthest_end, witness = -1, None
    for start, end, index in sorted(spans):
        if start < furthest_end:
            _finding(findings, budget, "record_overlap", start,
                     entries=[witness, index], overlap=[start, min(end, furthest_end)])
        if end > furthest_end:
            furthest_end, witness = end, index
    furthest_end, witness = -1, None
    for start, end, index in sorted(local_spans):
        if start < furthest_end:
            _finding(findings, budget, "local_size_overlap", start,
                     entries=[witness, index], overlap=[start, min(end, furthest_end)])
        if end > furthest_end:
            furthest_end, witness = end, index


def _analyze(data, max_input_bytes, max_entries, max_candidates, max_findings,
             max_metadata_bytes, max_declared_output, max_ratio):
    limits = (max_input_bytes, max_entries, max_candidates, max_findings,
              max_metadata_bytes, max_declared_output, max_ratio)
    if any(type(value) is not int or value <= 0 for value in limits):
        raise ZipDiffError("limits must be positive integers")
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ZipDiffError("input must be bytes-like")
    if (data.nbytes if isinstance(data, memoryview) else len(data)) > max_input_bytes:
        raise _LimitError("input byte limit exceeded")
    data = bytes(data)
    budget = _Budget(max_entries, max_findings, max_metadata_bytes)
    output = {"format": "zip", "input_bytes": len(data), "payloads_verified": False,
              "views": [], "rejected_eocd": [], "findings": []}
    p, signatures = 0, 0
    while True:
        at = data.find(_EOCD, p)
        if at < 0:
            break
        p = at + 4
        signatures += 1
        if signatures > max_candidates:
            raise _LimitError("EOCD candidate limit exceeded")
        try:
            meta = _end_record(data, at)
            multi = (meta["disk"] != 0 or meta["central_disk"] != 0 or
                     meta["entries_on_disk"] != meta["entry_count"] or
                     meta.get("locator_disk", 0) != 0 or meta.get("disk_count", 1) != 1)
            if multi:
                _finding(output["findings"], budget, "multidisk_unsupported", at,
                         disk=meta["disk"], central_disk=meta["central_disk"],
                         entries_on_disk=meta["entries_on_disk"], entry_count=meta["entry_count"],
                         locator_disk=meta.get("locator_disk"), disk_count=meta.get("disk_count"))
                output["rejected_eocd"].append({"offset": at, "reason": "multidisk metadata; directory not reconstructed", "metadata": meta})
                continue
            bases = [0]
            inferred = meta["anchor"] - meta["central_size"] - meta["central_offset"]
            if meta["zip64"]:
                bases = [meta["zip64_offset"] - meta["zip64_declared_offset"]]
            elif inferred > 0 and meta["entry_count"]:
                bases.append(inferred)
            reasons, found = [], False
            for base in bases:
                start = base + meta["central_offset"]
                try:
                    if start + meta["central_size"] > meta["anchor"]:
                        raise ZipDiffError("central directory overlaps end records")
                    if meta["zip64"] and base + meta["zip64_declared_offset"] != meta["zip64_offset"]:
                        raise ZipDiffError("ZIP64 locator and directory base disagree")
                    entries = _directory(data, start, meta["central_size"], meta["entry_count"], budget)
                except _LimitError:
                    raise
                except ZipDiffError as exc:
                    reasons.append(str(exc))
                    continue
                found = True
                findings = []
                view = {**meta, "archive_base": base, "central_span": [start, start + meta["central_size"]],
                        "entries": entries, "findings": findings}
                if base:
                    _finding(findings, budget, "rebased_offsets", at, archive_base=base)
                if meta["trailing_bytes"]:
                    _finding(findings, budget, "trailing_bytes", meta["eocd_end"], count=meta["trailing_bytes"])
                if start + meta["central_size"] < meta["anchor"]:
                    _finding(findings, budget, "directory_end_gap", start + meta["central_size"], end=meta["anchor"])
                if meta.get("legacy_conflicts"):
                    _finding(findings, budget, "zip64_legacy_conflict", at, pairs=meta["legacy_conflicts"])
                total = 0
                names = {}
                for entry in entries:
                    entry["name"] = _name_info(entry["_raw"], entry["flags"], entry["_extra"], entry["offset"] + 46, findings, budget, "central")
                    raw = entry["_raw"]
                    if raw in names:
                        _finding(findings, budget, "duplicate_central_name", entry["offset"], entries=[names[raw], entry["index"]], raw_hex=raw.hex())
                    else:
                        names[raw] = entry["index"]
                    total += entry["uncompressed_size"]
                    if entry["uncompressed_size"] > max_ratio * max(1, entry["compressed_size"]):
                        _finding(findings, budget, "declared_ratio_limit", entry["offset"], entry=entry["index"], compressed_size=entry["compressed_size"], uncompressed_size=entry["uncompressed_size"], limit=max_ratio)
                    if entry["made_by"] >> 8 == 3 and (entry["external_attributes"] >> 16) & 0xF000 == 0xA000:
                        _finding(findings, budget, "symlink_member", entry["offset"], entry=entry["index"], target_verified=False)
                    try:
                        entry["local"] = _local(data, entry, base, start, findings, budget)
                    except _LimitError:
                        raise
                    except ZipDiffError as exc:
                        entry["local"] = None
                        _finding(findings, budget, "invalid_local_header", base + entry["local_offset"], entry=entry["index"], reason=str(exc))
                    del entry["_raw"], entry["_extra"]
                view["declared_uncompressed_total"] = total
                if total > max_declared_output:
                    _finding(findings, budget, "declared_output_limit", at, declared_total=total, limit=max_declared_output)
                _overlaps(entries, findings, budget)
                output["views"].append(view)
            if not found:
                raise ZipDiffError("; ".join(reasons))
        except _LimitError:
            raise
        except ZipDiffError as exc:
            output["rejected_eocd"].append({"offset": at, "reason": str(exc)})
    # A complete empty EOCD can occur inside an ordinary member. Keep the
    # parseable candidate, but qualify its provenance before claiming multiple
    # archive endings. This does not assume that its bytes are malicious.
    for view in output["views"]:
        containers = []
        for parent in output["views"]:
            if parent["eocd_offset"] == view["eocd_offset"]:
                continue
            for entry in parent["entries"]:
                local = entry["local"]
                if local:
                    start, end = local["central_data_span"]
                    if start <= view["eocd_offset"] and view["eocd_end"] <= end <= parent["central_span"][0]:
                        containers.append({"eocd_offset": parent["eocd_offset"], "entry": entry["index"]})
        view["contained_in_payload"] = containers
        if containers:
            _finding(view["findings"], budget, "payload_contained_eocd", view["eocd_offset"], containers=containers)
    independent = [view for view in output["views"] if not view["contained_in_payload"]]
    offsets = sorted({view["eocd_offset"] for view in independent})
    if len(offsets) > 1:
        _finding(output["findings"], budget, "multiple_eocd", offsets[0], eocd_offsets=offsets)
    terminal = [view for view in independent if view["eocd_end"] == len(data)]
    if len(terminal) > 1:
        _finding(output["findings"], budget, "ambiguous_terminal_views", terminal[0]["eocd_offset"],
                 views=[{"eocd_offset": v["eocd_offset"], "archive_base": v["archive_base"]} for v in terminal])
    if not output["views"] and not output["findings"]:
        raise ZipDiffError("no supported ZIP directory: " + "; ".join(item["reason"] for item in output["rejected_eocd"]))
    return output


def analyze_zip(data, *, max_input_bytes=MAX_INPUT, max_entries=4096,
                max_candidates=128, max_findings=4096, max_metadata_bytes=8 << 20,
                max_declared_output=256 << 20, max_ratio=200):
    """Inspect ZIP metadata; all failures use ZipDiffError (including limits).

    Entries/metadata/findings budgets are cumulative over attempted directory
    views. Output/ratio limits concern declared sizes only, never measured output.
    Unsupported or damaged EOCD candidates are retained with rejection reasons.
    """
    try:
        return _analyze(data, max_input_bytes, max_entries, max_candidates, max_findings,
                        max_metadata_bytes, max_declared_output, max_ratio)
    except ZipDiffError:
        raise
    except Exception as exc:
        raise ZipDiffError(f"invalid ZIP input: {type(exc).__name__}: {exc}") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", help="ZIP file to inspect without extraction")
    parser.add_argument("--max-input", type=int, default=MAX_INPUT, help="input byte cap")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if args.max_input <= 0 or args.max_input > MAX_INPUT:
            raise ZipDiffError(f"--max-input must be between 1 and {MAX_INPUT}")
        with open(args.archive, "rb") as stream:
            data = stream.read(args.max_input + 1)
        report = analyze_zip(data, max_input_bytes=args.max_input)
        print(json.dumps(report, indent=2, ensure_ascii=True))
        return 0
    except (OSError, ZipDiffError, ValueError, TypeError) as exc:
        print(f"zipdiff: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
