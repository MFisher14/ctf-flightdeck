#!/usr/bin/env python3
"""Bounded, static BlackEnergy configuration and historical IOC inspection.

Reads *already decoded* BE2 bkernel XML and the five length-prefixed X.509
Name records pictured in F-Secure's 2014 BlackEnergy & Quedagh, image 14.
The latter are NOT X.509 certificates: each DWORD length precedes one DER
SEQUENCE/SET/SEQUENCE containing OID 1.1..1.5 and a PrintableString value.
No executable, macro, command, URL, or decoded plugin is ever executed.

BlackEnergyError is the only exception raised for invalid public API inputs.
An unrecognized format returns None; extract_configs returns an empty list.
IOC scores indicate corroborating historical artifacts, not attribution or
proof that BlackEnergy caused a power outage. Timeline dates are source
reporting periods, never timestamps inferred from the supplied bytes.

Sources:
https://blog-assets.f-secure.com/wp-content/uploads/2019/10/15163408/BlackEnergy_Quedagh.pdf
https://www.welivesecurity.com/2016/01/03/blackenergy-sshbeardoor-details-2015-attacks-ukrainian-news-media-electric-industry/
https://malware.lu/articles/2013/02/11/analysis-of-the-sample-blackenergy.html
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET


MAX_ARTIFACT = 8 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_CONFIG = 64 * 1024
MAX_ARTIFACTS = 32
MAX_CANDIDATES = 128
MAX_CONFIGS = 32
MAX_XML_NODES = 512
MAX_XML_DEPTH = 12
MAX_FIELD = 4096
FIELD_NAMES = {1: "servers", 2: "plugins", 3: "cmds", 4: "build_id", 5: "sleepfreq"}
ESET_SOURCE = "https://www.welivesecurity.com/2016/01/03/blackenergy-sshbeardoor-details-2015-attacks-ukrainian-news-media-electric-industry/"
FSECURE_SOURCE = "https://blog-assets.f-secure.com/wp-content/uploads/2019/10/15163408/BlackEnergy_Quedagh.pdf"
BUILD_IDS = ("2015en", "khm10", "khelm", "2015telsmi", "2015ts", "2015stb", "kiev_o",
             "brd2015", "11131526kbp", "02260517ee", "03150618aaa", "11131526trk")
C2_IPS = ("5.149.254.114", "5.9.32.230", "31.210.111.154", "88.198.25.92", "146.0.74.7", "188.40.8.72")
KILLDISK_SHA1 = ("16f44fac7e8bc94eccd7ad9692e6665ef540eec4", "8ad6f88c5813c2b4cd7abab1d6c056d95d6ac569",
                "6d6ba221da5b1ae1e910bbeaa07bd44aff26a7c0", "f3e41eb94c4d72a98cd743bbb02d248f510ad925")


class BlackEnergyError(ValueError):
    """Invalid, ambiguous, unsupported, or over-budget input."""


def _bytes(data: object, maximum: int) -> bytes:
    if type(data) not in (bytes, bytearray, memoryview):
        raise BlackEnergyError("input must be bytes")
    try:
        size = data.nbytes if type(data) is memoryview else len(data)
        if size > maximum:
            raise BlackEnergyError("input exceeds byte limit")
        return bytes(data)
    except (ValueError, TypeError, BufferError, MemoryError) as exc:
        raise BlackEnergyError("invalid byte buffer") from exc


def _text(value: str | None, *, empty: bool = False) -> str:
    value = value or ""
    if len(value) > MAX_FIELD or (not empty and not value) or any(ord(c) < 32 for c in value):
        raise BlackEnergyError("invalid configuration string")
    return value


def _url(value: str) -> str:
    value = _text(value)
    if any(character.isspace() for character in value):
        raise BlackEnergyError("whitespace in server address")
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.hostname is None:
            raise BlackEnergyError("expected an HTTP(S) server address")
        parsed.port  # Validate an explicit port without resolving or connecting.
    except ValueError as exc:
        raise BlackEnergyError("invalid server address") from exc
    return value


def _interval(value: str) -> int:
    if not re.fullmatch(r"[0-9]{1,10}", value):
        raise BlackEnergyError("invalid sleepfreq")
    result = int(value)
    if result > 0xFFFFFFFF:
        raise BlackEnergyError("sleepfreq exceeds DWORD range")
    return result


def decode_be2_xml(data: object) -> dict | None:
    """Decode one bkernel XML document, retaining unexecuted plugin/command XML.

    The bkernel/servers/server/type+addr/build_id/sleepfreq layout is published
    in F-Secure image 13 and Malware.lu's independent 2013 analysis. XML with
    another root is not classified as a BlackEnergy config.
    """
    raw = _bytes(data, MAX_CONFIG)
    if not raw.lstrip().startswith((b"<", b"\xef\xbb\xbf<")):
        return None
    if b"\x00" in raw or re.search(rb"<!\s*(?:DOCTYPE|ENTITY)\b", raw, re.I):
        raise BlackEnergyError("DTD, entities, and NUL-containing XML are unsupported")
    try:
        root = ET.fromstring(raw)
    except (ET.ParseError, UnicodeError, LookupError, ValueError) as exc:
        raise BlackEnergyError("malformed XML") from exc
    if root.tag != "bkernel":
        return None
    pending, count = [(root, 1)], 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > MAX_XML_NODES or depth > MAX_XML_DEPTH:
            raise BlackEnergyError("XML structure exceeds limits")
        pending.extend((child, depth + 1) for child in node)
    fields = {}
    for node in root:
        if node.tag in fields:
            raise BlackEnergyError("duplicate top-level configuration field")
        fields[node.tag] = node
    if not {"servers", "build_id", "sleepfreq"} <= fields.keys():
        raise BlackEnergyError("incomplete bkernel config")
    servers = []
    for server in fields["servers"]:
        if server.tag != "server" or len(server) != 2 or {child.tag for child in server} != {"type", "addr"}:
            raise BlackEnergyError("unsupported server structure")
        kind, addr = server.find("type"), server.find("addr")
        if len(kind) or len(addr) or kind.text not in ("http", "https"):
            raise BlackEnergyError("invalid server type")
        address = _url(addr.text or "")
        if urlsplit(address).scheme != kind.text:
            raise BlackEnergyError("server type/address mismatch")
        servers.append({"type": kind.text, "addr": address})
    if not servers or len(servers) > 32:
        raise BlackEnergyError("invalid server count")
    for scalar in ("build_id", "sleepfreq", "http_key"):
        if scalar in fields and len(fields[scalar]):
            raise BlackEnergyError("nested scalar field")
    result = {"format": "be2-xml", "servers": servers,
              "build_id": _text(fields["build_id"].text),
              "sleepfreq": _interval(fields["sleepfreq"].text or ""),
              "plugins_xml": ET.tostring(fields["plugins"], encoding="unicode") if "plugins" in fields else None,
              "cmds_xml": ET.tostring(fields["cmds"], encoding="unicode") if "cmds" in fields else None}
    if "http_key" in fields:
        result["http_key"] = _text(fields["http_key"].text)
    return result


def _tlv(raw: bytes, start: int, end: int, expected: int) -> tuple[int, int, int]:
    if start + 2 > end or raw[start] != expected:
        raise BlackEnergyError("unexpected or truncated DER tag")
    first = raw[start + 1]
    pos = start + 2
    if first < 128:
        length = first
    else:
        width = first & 127
        if not 1 <= width <= 3 or pos + width > end or raw[pos] == 0:
            raise BlackEnergyError("invalid DER length")
        length = int.from_bytes(raw[pos:pos + width], "big")
        pos += width
        if length < 128:
            raise BlackEnergyError("non-minimal DER length")
    stop = pos + length
    if stop > end:
        raise BlackEnergyError("truncated DER value")
    return pos, stop, stop


def _name_record(record: bytes) -> tuple[int, str]:
    start, end, following = _tlv(record, 0, len(record), 0x30)
    if following != len(record):
        raise BlackEnergyError("trailing data in X.509 Name")
    for tag in (0x31, 0x30):
        child_start, child_end, following = _tlv(record, start, end, tag)
        if following != end:
            raise BlackEnergyError("multiple RDNs/attributes are unsupported")
        start, end = child_start, child_end
    oid_start, oid_end, following = _tlv(record, start, end, 0x06)
    if oid_end - oid_start != 1 or not 0x29 <= record[oid_start] <= 0x2D:
        raise BlackEnergyError("unknown BlackEnergy field OID")
    value_start, value_end, following = _tlv(record, following, end, 0x13)
    if following != end:
        raise BlackEnergyError("trailing attribute data")
    try:
        value = record[value_start:value_end].decode("ascii")
    except UnicodeError as exc:
        raise BlackEnergyError("non-ASCII PrintableString") from exc
    if re.fullmatch(r"[A-Za-z0-9 '()+,\-./:=?]*", value) is None:
        raise BlackEnergyError("invalid ASN.1 PrintableString character")
    return record[oid_start] - 0x28, _text(value, empty=True)


def _be3_at(raw: bytes, offset: int) -> tuple[dict, int]:
    start, fields = offset, {}
    for _ in range(5):
        if offset + 4 > len(raw):
            raise BlackEnergyError("truncated X.509 record length")
        size = int.from_bytes(raw[offset:offset + 4], "little")
        offset += 4
        if not 11 <= size <= MAX_CONFIG or offset + size > len(raw) or offset + size - start > MAX_CONFIG:
            raise BlackEnergyError("invalid X.509 record size")
        number, value = _name_record(raw[offset:offset + size])
        if number in fields:
            raise BlackEnergyError("duplicate BlackEnergy field OID")
        fields[number] = value
        offset += size
    return {"format": "be3-asn1", "servers": [{"type": urlsplit(_url(fields[1])).scheme, "addr": fields[1]}],
            "plugins": fields[2], "cmds": fields[3], "build_id": _text(fields[4]),
            "sleepfreq": _interval(fields[5]), "field_oids": {FIELD_NAMES[i]: f"1.{i}" for i in fields},
            "raw_fields": {FIELD_NAMES[i]: value for i, value in fields.items()}}, offset


def decode_be3_asn1(data: object) -> dict | None:
    """Read the five DWORD-length + DER Name records in F-Secure image 14.

    Only the documented single-attribute PrintableString form is accepted.
    Complete input consumption is mandatory; encrypted/wrapped data is not
    guessed or executed. Missing/duplicate fields cannot become partial facts.
    """
    raw = _bytes(data, MAX_CONFIG)
    if len(raw) < 5 or raw[4] != 0x30:
        return None
    result, end = _be3_at(raw, 0)
    if end != len(raw):
        raise BlackEnergyError("trailing bytes after complete configuration")
    return result


def extract_configs(data: object) -> list[dict]:
    """Carve complete plaintext configs with byte offsets; bounded candidate scan."""
    raw = _bytes(data, MAX_ARTIFACT)
    output, attempts = [], 0
    # Count even unfinished opening tags. Searching across a full unterminated
    # tag for every repeated prefix would otherwise make this scan quadratic.
    for match in re.finditer(rb"<bkernel\b", raw):
        attempts += 1
        if attempts > MAX_CANDIDATES:
            raise BlackEnergyError("too many configuration candidates")
        start = match.start()
        end = raw.find(b"</bkernel>", match.end(), min(len(raw), start + MAX_CONFIG))
        if end < 0:
            continue
        end += len(b"</bkernel>")
        try:
            config = decode_be2_xml(raw[start:end])
        except BlackEnergyError:
            continue
        if config is not None:
            output.append({"offset": start, "length": end - start, **config})
    # The DWORD prefix bounds the scan. Each candidate must then validate all
    # five DER Names and five unique known OIDs; a bare certificate never fits.
    cursor = 0
    while True:
        position = raw.find(b"\x00\x00\x30", cursor)
        if position < 0:
            break
        cursor = position + 1
        start = position - 2
        if start < 0:
            continue
        attempts += 1
        if attempts > MAX_CANDIDATES:
            raise BlackEnergyError("too many configuration candidates")
        try:
            config, end = _be3_at(raw, start)
        except BlackEnergyError:
            continue
        output.append({"offset": start, "length": end - start, **config})
        cursor = end
    if len(output) > MAX_CONFIGS:
        raise BlackEnergyError("too many configurations")
    return sorted(output, key=lambda item: item["offset"])


def _hit(raw: bytes, token: str) -> int | None:
    encoded = token.encode("ascii")
    found = re.search(rb"(?<![A-Za-z0-9_.])" + re.escape(encoded) + rb"(?![A-Za-z0-9_.])", raw, re.I)
    if found:
        return found.start()
    # Process inventories and Windows strings may be UTF-16LE.
    wide = encoded.decode("ascii").encode("utf-16-le")
    found = re.search(rb"(?<![A-Za-z0-9_.]\x00)" + re.escape(wide) + rb"(?![A-Za-z0-9_.]\x00)", raw, re.I)
    return found.start() if found else None


def match_profile(artifacts: object) -> dict:
    """Score independent historical indicator categories over named raw artifacts.

    ``artifacts`` is a plain ``dict[str, bytes]``. Repeated indicators cannot
    inflate a category. A match needs 50 points and two categories; names alone
    never suffice. A known digest in text is explicitly a *reported* IOC, not
    a claim that the supplied artifact has that digest.
    """
    if type(artifacts) is not dict or len(artifacts) > MAX_ARTIFACTS:
        raise BlackEnergyError("expected a bounded artifact dictionary")
    checked, total = {}, 0
    for name, data in artifacts.items():
        if type(name) is not str or not name or len(name) > 1024 or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in name):
            raise BlackEnergyError("invalid artifact name")
        checked[name] = _bytes(data, MAX_ARTIFACT)
        total += len(checked[name])
        if total > MAX_TOTAL:
            raise BlackEnergyError("artifact set exceeds byte limit")
    evidence, categories, configs = [], {}, []

    def add(name, category, value, offset, weight, phase):
        evidence.append({"artifact": name, "category": category, "value": value, "offset": offset,
                         "phase": phase, "source": FSECURE_SOURCE if category == "configuration" else ESET_SOURCE})
        categories[category] = max(categories.get(category, 0), weight)

    for name, raw in checked.items():
        for config in extract_configs(raw):
            configs.append({"artifact": name, **config})
            add(name, "configuration", config["format"], config["offset"], 25, "configuration")
        for value in BUILD_IDS:
            at = _hit(raw, value)
            if at is not None:
                add(name, "campaign_build", value, at, 25, "2015 campaign")
        for value in C2_IPS:
            at = _hit(raw, value)
            if at is not None:
                add(name, "historical_c2", value, at, 25, "2015 campaign")
        processes = [(value, _hit(raw, value)) for value in ("komut.exe", "sec_service.exe")]
        present = [(value, at) for value, at in processes if at is not None]
        for value, at in present:
            add(name, "killdisk_processes", value, at, 30 if len(present) == 2 else 10, "destruction")
        for digest in KILLDISK_SHA1:
            at = _hit(raw, digest)
            if at is not None:
                add(name, "reported_killdisk_sha1", digest, at, 25, "destruction")
        if hashlib.sha1(raw).hexdigest() in KILLDISK_SHA1:
            add(name, "verified_killdisk_sha1", hashlib.sha1(raw).hexdigest(), 0, 100, "destruction")
        if _hit(raw, "passDs5Bu9Te7") is not None and _hit(raw, "dropbear.exe") is not None:
            add(name, "sshbeardoor", "dropbear.exe + published backdoor password", _hit(raw, "dropbear.exe"), 30, "fallback access")
        if raw.startswith((b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", b"PK\x03\x04")) and (
                _hit(raw, "Workbook_Open") is not None or _hit(raw, "AutoOpen") is not None):
            add(name, "office_macro_context", "Office magic and auto-run macro string", 0, 10, "delivery")
    periods = {"delivery": "reported 2015", "configuration": "published 2014-09 / 2016-01-03",
               "2015 campaign": "observed 2015", "destruction": "reported 2015-11 and late 2015",
               "fallback access": "published 2016-01-03"}
    timeline = [{"phase": phase, "reported_period": period,
                 "evidence_indexes": [i for i, item in enumerate(evidence) if item["phase"] == phase]}
                for phase, period in periods.items() if any(item["phase"] == phase for item in evidence)]
    score = min(100, sum(categories.values()))
    return {"profile": "BlackEnergy / associated KillDisk and SSHBearDoor historical indicators",
            "score": score, "matched": score >= 50 and len(categories) >= 2,
            "category_scores": categories, "evidence": evidence, "configs": configs,
            "timeline": timeline, "timeline_kind": "source chronology, not artifact timestamps",
            "assessment": "corroborated historical indicators" if score >= 50 and len(categories) >= 2 else "insufficient corroboration"}


def _read(path: str, maximum: int = MAX_ARTIFACT) -> bytes:
    try:
        metadata = Path(path).stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise BlackEnergyError("expected a bounded regular file")
        # O_NONBLOCK prevents a raced-in FIFO from blocking between stat/open;
        # fstat verifies the object actually opened before any read.
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
                raise BlackEnergyError("expected a bounded regular file")
            return _bytes(handle.read(maximum + 1), maximum)
    except (OSError, ValueError) as exc:
        raise BlackEnergyError(f"cannot read artifact: {path}") from exc


def main(argv: list[str] | None = None) -> int:
    if argv is not None and (type(argv) not in (list, tuple) or any(type(arg) is not str for arg in argv)):
        return 2
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("config", "profile"))
    parser.add_argument("files", nargs="+")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if len(args.files) > MAX_ARTIFACTS:
            raise BlackEnergyError("too many files")
        artifacts, total = {}, 0
        for name in args.files:
            if name in artifacts:
                continue
            data = _read(name, min(MAX_ARTIFACT, MAX_TOTAL - total))
            total += len(data)
            if total > MAX_TOTAL:
                raise BlackEnergyError("artifact set exceeds byte limit")
            artifacts[name] = data
        result = match_profile(artifacts) if args.mode == "profile" else {
            name: extract_configs(data) for name, data in artifacts.items()}
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 0
    except BlackEnergyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
