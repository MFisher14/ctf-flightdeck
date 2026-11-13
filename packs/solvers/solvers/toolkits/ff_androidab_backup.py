"""Strict, bounded, offline Android adb-backup header and tar inventory.

No member is extracted, no link is followed, and encrypted payloads are never
decrypted. Public parsers raise only AndroidBackupError on malformed input.
The supported tar subset is regular files, directories, safe links, and POSIX
PAX metadata; sparse files and other special member types are rejected.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, fields
from functools import wraps
import hashlib
import json
import re
import sys
import zlib


MAGIC = b"ANDROID BACKUP\n"


class AndroidBackupError(ValueError):
    """Malformed, unsupported, unsafe, or over-limit Android backup."""


@dataclass(frozen=True)
class Limits:
    max_input: int = 64 * 1024 * 1024
    max_output: int = 128 * 1024 * 1024
    max_member: int = 32 * 1024 * 1024
    max_total: int = 128 * 1024 * 1024
    max_members: int = 10000
    max_links: int = 1000
    max_ratio: int = 200
    max_path: int = 4096
    max_pax: int = 32768
    max_metadata: int = 8 * 1024 * 1024

    def __post_init__(self):
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or not 1 <= value <= 1024 * 1024 * 1024:
                raise AndroidBackupError(f"invalid limit: {field.name}")
        if self.max_members > 100000 or self.max_links > 100000:
            raise AndroidBackupError("member/link count limit exceeds hard ceiling")
        if self.max_path > 65536 or self.max_pax > 1024 * 1024:
            raise AndroidBackupError("metadata limit exceeds hard ceiling")


def _contract(function):
    @wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except AndroidBackupError:
            raise
        except Exception as exc:
            raise AndroidBackupError(f"invalid input to {function.__name__}") from exc
    return checked


def _limits(value):
    if value is None:
        return Limits()
    if type(value) is not Limits:
        raise AndroidBackupError("limits must be Limits")
    return value


def _bytes(data, maximum):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise AndroidBackupError("input must be bytes-like")
    length = data.nbytes if isinstance(data, memoryview) else len(data)
    if length > maximum:
        raise AndroidBackupError("input size limit exceeded")
    return bytes(data)


def detect_backup(data) -> bool:
    """Recognize only the literal magic; recognition does not validate a backup."""
    try:
        return isinstance(data, (bytes, bytearray, memoryview)) and bytes(data[:len(MAGIC)]) == MAGIC
    except Exception:
        return False


def _decimal(raw, label, maximum):
    if not raw or len(raw) > 10 or not raw.isascii() or not raw.isdigit():
        raise AndroidBackupError(f"invalid {label}")
    value = int(raw)
    if value > maximum:
        raise AndroidBackupError(f"{label} exceeds format limit")
    return value


@_contract
def parse_header(data, *, limits=None) -> dict:
    """Validate the LF-delimited .ab header, returning metadata and data_offset."""
    limits = _limits(limits)
    data = _bytes(data, limits.max_input)
    if not data.startswith(MAGIC):
        raise AndroidBackupError("missing ANDROID BACKUP magic")
    offset = len(MAGIC)

    def line(label):
        nonlocal offset
        end = data.find(b"\n", offset, min(len(data), offset + 8193))
        if end < 0 or end > 16384:
            raise AndroidBackupError(f"truncated or overlong {label}")
        result = data[offset:end]
        offset = end + 1
        if not result or any(c < 32 or c > 126 for c in result):
            raise AndroidBackupError(f"invalid ASCII {label}")
        return result

    version_raw = line("version")
    version = _decimal(version_raw, "version", 5)
    if version_raw not in (b"1", b"2", b"3", b"4", b"5"):
        raise AndroidBackupError("unsupported backup version")
    compressed = line("compression")
    if compressed not in (b"0", b"1"):
        raise AndroidBackupError("compression must be 0 or 1")
    algorithm = line("encryption")
    if algorithm not in (b"none", b"AES-256"):
        raise AndroidBackupError("unsupported encryption algorithm")
    result = {"format": "android-backup", "version": version,
              "compressed": compressed == b"1", "encryption": algorithm.decode("ascii")}
    if algorithm == b"AES-256":
        def hexline(label, expected):
            raw = line(label)
            if len(raw) != expected * 2 or re.fullmatch(b"[0-9A-Fa-f]+", raw) is None:
                raise AndroidBackupError(f"invalid {label} hex or length")
            return raw.decode("ascii").lower()

        user_salt = hexline("user salt", 64)
        checksum_salt = hexline("checksum salt", 64)
        rounds = _decimal(line("KDF rounds"), "KDF rounds", 2147483647)
        if rounds == 0:
            raise AndroidBackupError("KDF rounds must be positive")
        user_iv = hexline("user IV", 16)
        key_blob = hexline("encrypted key blob", 96)
        result["crypto"] = {
            "cipher": "AES-256-CBC", "padding": "PKCS5/PKCS7",
            "kdf": "PBKDF2-HMAC-SHA1", "kdf_rounds": rounds,
            "version_1_legacy_pbkdf2_fallback": version == 1,
            "user_salt_hex": user_salt, "checksum_salt_hex": checksum_salt,
            "user_iv_hex": user_iv, "encrypted_key_blob_hex": key_blob,
            "encrypted_key_blob_bytes": 96,
        }
    result["data_offset"] = offset
    return result


def _path(value, limits, *, base=(), allow_parent=False):
    if not value or len(value.encode("utf-8")) > limits.max_path:
        raise AndroidBackupError("empty or overlong member/link path")
    if value.startswith("/") or "\\" in value or ":" in value:
        raise AndroidBackupError("absolute, Windows, or ambiguous member/link path")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise AndroidBackupError("control character in member/link path")
    parts = list(base)
    appended = False
    for part in value.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not allow_parent or appended or not parts:
                raise AndroidBackupError("member/link path escapes archive root")
            parts.pop()
        else:
            if part.endswith((".", " ")):
                raise AndroidBackupError("ambiguous trailing dot/space in path")
            parts.append(part)
            appended = True
        if len(parts) > 128:
            raise AndroidBackupError("member/link path depth limit exceeded")
    if not parts:
        raise AndroidBackupError("member/link path resolves to archive root")
    return "/".join(parts)


def _text(field):
    head, separator, tail = field.partition(b"\0")
    if separator and any(tail):
        raise AndroidBackupError("nonzero bytes after tar string terminator")
    return head.decode("utf-8")


def _octal(field, label):
    raw = field.strip(b"\0 ")
    if not raw:
        return 0
    if any(c < 48 or c > 55 for c in raw):
        raise AndroidBackupError(f"invalid octal tar {label}; base-256 unsupported")
    return int(raw, 8)


def _pax(body):
    result = {}
    offset = 0
    while offset < len(body):
        end = body.find(b" ", offset, min(len(body), offset + 12))
        if end < 0:
            raise AndroidBackupError("invalid PAX record length")
        size = _decimal(body[offset:end], "PAX record length", len(body))
        stop = offset + size
        if stop <= end + 2 or stop > len(body) or body[stop - 1:stop] != b"\n":
            raise AndroidBackupError("truncated PAX record")
        key, equals, value = body[end + 1:stop - 1].partition(b"=")
        if not key or not equals:
            raise AndroidBackupError("invalid PAX key/value")
        key = key.decode("utf-8")
        value = value.decode("utf-8")
        if key in result or len(result) >= 128 or "\0" in value:
            raise AndroidBackupError("duplicate or excessive PAX metadata")
        if key.startswith("GNU.sparse") or key in ("SCHILY.filetype", "SCHILY.realsize"):
            raise AndroidBackupError("sparse/special PAX metadata unsupported")
        result[key] = value
        offset = stop
    return result


@_contract
def inventory_tar(data, *, limits=None) -> dict:
    """Inventory a complete tar, validating checksums, paths, links, and limits.

    POSIX local/global PAX path, linkpath, and size overrides are honored before
    bounds and path checks. All header records count toward max_members. No
    data is written; returned hashes refer to stored regular-file bytes only.
    """
    limits = _limits(limits)
    data = _bytes(data, limits.max_output)
    if len(data) < 1024 or len(data) % 512:
        raise AndroidBackupError("tar must contain complete 512-byte blocks and EOF")
    members, paths, link_paths = [], {}, {}
    offset = total = records = emitted_metadata_bytes = 0
    global_pax, pending_pax = {}, {}
    pending = False
    ended = False
    while offset < len(data):
        block = data[offset:offset + 512]
        if block == bytes(512):
            if pending or data[offset + 512:offset + 1024] != bytes(512):
                raise AndroidBackupError("tar missing second EOF block or dangling PAX")
            if any(data[offset:]):
                raise AndroidBackupError("nonzero trailing data after tar EOF")
            ended = True
            break
        records += 1
        if records > limits.max_members:
            raise AndroidBackupError("tar member/header count limit exceeded")
        expected = _octal(block[148:156], "checksum")
        if expected != sum(block[:148]) + 256 + sum(block[156:]):
            raise AndroidBackupError(f"tar checksum mismatch at offset {offset}")
        magic = block[257:265]
        if magic not in (b"ustar\x0000", b"ustar  \x00", bytes(8)):
            raise AndroidBackupError("unsupported tar magic/version")
        name = _text(block[:100])
        prefix = _text(block[345:500]) if magic == b"ustar\x0000" else ""
        if prefix:
            name = prefix + "/" + name
        size = _octal(block[124:136], "size")
        mode = _octal(block[100:108], "mode")
        mtime = _octal(block[136:148], "mtime")
        kind = block[156:157]
        body_offset = offset + 512
        if kind in (b"x", b"g"):
            if size > limits.max_pax:
                raise AndroidBackupError("PAX metadata size limit exceeded")
            stop = body_offset + ((size + 511) // 512) * 512
            if stop > len(data) or any(data[body_offset + size:stop]):
                raise AndroidBackupError("truncated PAX body or nonzero padding")
            metadata = _pax(data[body_offset:body_offset + size])
            if kind == b"g":
                if pending:
                    raise AndroidBackupError("global PAX interrupts local PAX header")
                for key, value in metadata.items():
                    if value:
                        global_pax[key] = value
                    else:
                        global_pax.pop(key, None)
                if len(global_pax) > 128:
                    raise AndroidBackupError("excessive global PAX metadata")
                if len(json.dumps(global_pax, ensure_ascii=True)) > limits.max_pax:
                    raise AndroidBackupError("accumulated global PAX metadata limit exceeded")
            else:
                if pending:
                    raise AndroidBackupError("consecutive local PAX headers are ambiguous")
                pending_pax, pending = metadata, True
            offset = stop
            continue
        metadata = dict(global_pax)
        for key, value in pending_pax.items():
            if value:
                metadata[key] = value
            else:
                metadata.pop(key, None)
        pending_pax, pending = {}, False
        name = metadata.get("path", name)
        if "size" in metadata:
            size = _decimal(metadata["size"].encode("ascii"), "PAX size", 1073741824)
        if size > limits.max_member:
            raise AndroidBackupError("tar member size limit exceeded")
        total += size
        if total > limits.max_total:
            raise AndroidBackupError("tar cumulative member size limit exceeded")
        stop = body_offset + ((size + 511) // 512) * 512
        if stop > len(data) or any(data[body_offset + size:stop]):
            raise AndroidBackupError("truncated tar member or nonzero padding")
        normalized = _path(name, limits)
        if normalized in paths:
            raise AndroidBackupError("duplicate normalized tar member path")
        kinds = {b"\0": "file", b"0": "file", b"5": "directory",
                 b"1": "hardlink", b"2": "symlink"}
        if kind not in kinds:
            raise AndroidBackupError("unsupported special/sparse/GNU tar member")
        member = {"name": name, "path": normalized, "type": kinds[kind],
                  "size": size, "mode": mode, "mtime": mtime,
                  "header_offset": offset, "data_offset": body_offset}
        if metadata:
            member["pax"] = metadata
        if kind in (b"1", b"2", b"5") and size:
            raise AndroidBackupError("directory/link has nonzero payload size")
        if kind in (b"1", b"2"):
            if len(link_paths) >= limits.max_links:
                raise AndroidBackupError("tar link count limit exceeded")
            target = metadata.get("linkpath", _text(block[157:257]))
            base = tuple(normalized.split("/")[:-1]) if kind == b"2" else ()
            resolved = _path(target, limits, base=base, allow_parent=kind == b"2")
            member.update({"link_target": target, "resolved_target": resolved})
            link_paths[normalized] = resolved
        elif kind in (b"\0", b"0"):
            if metadata.get("linkpath") or _text(block[157:257]):
                raise AndroidBackupError("regular file has a link target")
            member["sha256"] = hashlib.sha256(memoryview(data)[body_offset:body_offset + size]).hexdigest()
        elif metadata.get("linkpath") or _text(block[157:257]):
            raise AndroidBackupError("directory has a link target")
        emitted_metadata_bytes += len(json.dumps(member, ensure_ascii=True))
        if emitted_metadata_bytes > limits.max_metadata:
            raise AndroidBackupError("cumulative inventory metadata limit exceeded")
        paths[normalized] = member
        members.append(member)
        offset = stop
    if not ended:
        raise AndroidBackupError("tar has no two-block EOF")
    for path, member in paths.items():
        parts = path.split("/")
        for end in range(1, len(parts)):
            parent = paths.get("/".join(parts[:end]))
            if parent is not None and parent["type"] != "directory":
                raise AndroidBackupError("tar member is nested beneath a non-directory/link")
        if member["type"] in ("symlink", "hardlink"):
            target = member["resolved_target"]
            target_parts = target.split("/")
            if any("/".join(target_parts[:end]) in link_paths
                   for end in range(1, len(target_parts) + 1)):
                raise AndroidBackupError("link chains or cycles are not supported")
            if member["type"] == "hardlink" and (
                target not in paths or paths[target]["type"] != "file"
            ):
                raise AndroidBackupError("hardlink target must be an inventoried regular file")
    return {"members": members, "member_count": len(members), "header_count": records,
            "total_member_bytes": total, "tar_bytes": len(data), "eof_offset": offset}


def _inflate(payload, limits):
    if not payload:
        raise AndroidBackupError("missing zlib payload")
    budget = min(limits.max_output, len(payload) * limits.max_ratio)
    inflater = zlib.decompressobj()
    result = inflater.decompress(payload, budget + 1)
    if len(result) > budget or inflater.unconsumed_tail:
        raise AndroidBackupError("decompression output/ratio limit exceeded")
    if not inflater.eof:
        raise AndroidBackupError("truncated zlib stream")
    if inflater.unused_data:
        raise AndroidBackupError("trailing/concatenated data after zlib stream")
    return result


@_contract
def parse_backup(data, *, limits=None) -> dict:
    """Parse .ab metadata and inventory unencrypted tar; encrypted bodies stay opaque."""
    limits = _limits(limits)
    data = _bytes(data, limits.max_input)
    header = parse_header(data, limits=limits)
    payload = data[header["data_offset"]:]
    result = {"header": header, "payload_bytes": len(payload), "status": "inventoried"}
    if header["encryption"] != "none":
        if not payload or len(payload) % 16:
            raise AndroidBackupError("missing or non-block-aligned encrypted payload")
        result.update({"status": "encrypted_metadata_only", "inventory": None})
        return result
    tar = _inflate(payload, limits) if header["compressed"] else payload
    result["inventory"] = inventory_tar(tar, limits=limits)
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backup", help="local .ab file; no extraction or password processing")
    parser.add_argument("--max-input", type=int, default=Limits.max_input)
    parser.add_argument("--max-output", type=int, default=Limits.max_output)
    parser.add_argument("--max-member", type=int, default=Limits.max_member)
    parser.add_argument("--max-total", type=int, default=Limits.max_total)
    parser.add_argument("--max-members", type=int, default=Limits.max_members)
    parser.add_argument("--max-ratio", type=int, default=Limits.max_ratio)
    parser.add_argument("--max-metadata", type=int, default=Limits.max_metadata)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        limits = Limits(max_input=args.max_input, max_output=args.max_output,
                        max_member=args.max_member, max_total=args.max_total,
                        max_members=args.max_members, max_ratio=args.max_ratio,
                        max_metadata=args.max_metadata)
        with open(args.backup, "rb") as stream:
            data = stream.read(limits.max_input + 1)
        print(json.dumps(parse_backup(data, limits=limits), indent=2, sort_keys=True))
        return 0
    except (AndroidBackupError, OSError, ValueError, TypeError) as exc:
        print(f"ff_androidab_backup: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
