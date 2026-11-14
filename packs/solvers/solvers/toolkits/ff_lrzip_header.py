#!/usr/bin/env python3
"""Bounded, offline LRZIP magic-header inventory; never decompresses any data.

Reads the 24-byte LRZI header (format versions 0.2--0.7) and, for 0.7
encryption mode 3, its 32-byte CryptoDesc.  Header validity does not establish
archive completeness or authenticity.  Compression types are stored in stream
block headers, not in LRZI; LZMA properties are only a hint, not a backend ID.

Layout references: ckolivas/lrzip v0.631 lrzip.c:write_magic/get_magic and
doc/magic.header.txt; 0.7 snapshot 3a849ef9529593b5993331fcc43fbe1167338c43
of the same files.  Legacy format documentation says size ends at byte 14;
the reference code actually copies eight bytes at offset 6 (through byte 13).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path


HEADER_SIZE = 24
MAX_HEADER_SIZE = 56


class LRZIPError(ValueError):
    """Malformed, unsupported, or inaccessible LRZIP header."""


def parse_header(data: bytes, offset: int = 0) -> dict:
    """Inspect at most 56 bytes at *offset*, or raise only LRZIPError.

    Only bytes inputs are accepted.  Trailing archive bytes are never examined,
    allocated according to declared sizes, hashed, or passed to a decoder.
    A zero size means unspecified (possibly empty); encryption uses it as salt.
    """
    if not isinstance(data, bytes):
        raise LRZIPError("input must be bytes")
    if type(offset) is not int or offset < 0 or offset > len(data):
        raise LRZIPError("offset must be within input")
    if len(data) - offset < HEADER_SIZE:
        raise LRZIPError("truncated 24-byte LRZI header")
    header = data[offset:offset + HEADER_SIZE]
    if header[:4] != b"LRZI":
        raise LRZIPError("not an LRZI header")
    major, minor = header[4], header[5]
    if major != 0 or not 2 <= minor <= 7:
        raise LRZIPError(f"unsupported LRZIP format version {major}.{minor}")
    hash_flag, encryption = header[21], header[22]
    if hash_flag not in (0, 1) or (minor < 5 and hash_flag):
        raise LRZIPError("unsupported checksum flag for format version")
    permitted_encryption = (0,) if minor < 6 else (0, 1) if minor == 6 else (0, 1, 3)
    if encryption not in permitted_encryption:
        raise LRZIPError("unsupported encryption mode for format version")
    streaming = last_block = None
    if minor == 7:
        streaming, last_block = header[14], header[23]
        if streaming not in (0, 1) or last_block not in (0, 1):
            raise LRZIPError("invalid streaming flags")
        if not streaming and not last_block:
            raise LRZIPError("neither streaming nor final block is set")
        if header[15]:
            raise LRZIPError("nonzero reserved byte 15")

    properties = header[16:21]
    lzma = None
    if properties[0]:
        prop = properties[0]
        if prop >= 225:
            raise LRZIPError("invalid LZMA properties byte")
        dictionary = int.from_bytes(properties[1:], "little")
        lzma = {"lc": prop % 9, "lp": (prop // 9) % 5, "pb": prop // 45,
                "dictionary_size": dictionary,
                "decoder_dictionary_size": max(dictionary, 4096)}

    raw_size = None
    salt = None
    loops = None
    crypto_desc = None
    extent = HEADER_SIZE
    if encryption:
        salt = header[6:14].hex()
        if encryption == 1:
            shift, multiplier = header[6], header[7]
            if shift > 40 or multiplier == 0:
                raise LRZIPError("invalid legacy encryption loop parameters")
            loops = multiplier << shift
        else:
            extent = MAX_HEADER_SIZE
            if len(data) - offset < extent:
                raise LRZIPError("truncated 32-byte CryptoDesc")
            desc = data[offset + HEADER_SIZE:offset + extent]
            if desc[0] != 1 or desc[1] != 16:
                raise LRZIPError("unsupported CryptoDesc suite or salt length")
            iterations = int.from_bytes(desc[2:6], "little")
            if not 1 <= iterations <= 5_000_000:
                raise LRZIPError("invalid PBKDF2 iteration count")
            if any(desc[6:8]) or any(desc[24:32]):
                raise LRZIPError("nonzero CryptoDesc reserved bytes")
            if desc[8:16] != header[6:14]:
                raise LRZIPError("CryptoDesc salt prefix disagrees with LRZI")
            crypto_desc = {"offset": offset + HEADER_SIZE, "size": 32,
                           "suite_id": 1, "kdf": "PBKDF2-HMAC-SHA512",
                           "iterations": iterations, "salt_hex": desc[8:24].hex()}
    elif minor < 4:
        raw_size = (int.from_bytes(header[6:10], "big")
                    | (int.from_bytes(header[10:14], "big") << 32))
    else:
        raw_size = int.from_bytes(header[6:14], "little")
    if raw_size is not None and raw_size >= (1 << 63):
        raise LRZIPError("size exceeds reference implementation's signed 64-bit range")

    encryption_names = {0: "none", 1: "AES-128-CBC / SHA-512 KDF",
                        3: "AES-256-GCM / PBKDF2-HMAC-SHA512"}
    return {
        "format": "lrzip", "version": f"{major}.{minor}",
        "major_version": major, "minor_version": minor,
        "header_offset": offset, "header_size": extent,
        "data_offset": offset + extent,
        "header_sha256": hashlib.sha256(data[offset:offset + extent]).hexdigest(),
        "size_encoding": "salt" if encryption else
            "two-big-endian-u32-low-first" if minor < 4 else "little-endian-u64",
        "raw_uncompressed_size": raw_size,
        "declared_uncompressed_size": raw_size if raw_size else None,
        "size_status": "encrypted" if encryption else "unspecified" if not raw_size else "declared",
        "compressed_size": None,
        "compression_backend": None,
        "compression_backend_reason": "per-stream block types are outside the LRZI header",
        "lzma_properties_hex": properties.hex(), "lzma_properties": lzma,
        "lzma_properties_used_by_reference": bool(properties[0]),
        "checksum_flag": hash_flag, "appended_md5_declared": bool(hash_flag),
        "checksum_verified": False,
        "encrypted": bool(encryption), "encryption_mode": encryption,
        "encryption": encryption_names[encryption], "salt_prefix_hex": salt,
        "legacy_kdf_loops": loops, "crypto_descriptor": crypto_desc,
        "streaming": bool(streaming) if streaming is not None else None,
        "first_block_is_last": bool(last_block) if last_block is not None else None,
        "reserved_bytes_hex": header[15:16].hex() if minor == 7 else
            bytes((header[14], header[15], header[23])).hex(),
        "validation_scope": "header_only", "payload_examined": False,
    }


def main(argv: list[str] | None = None) -> int:
    """Print JSON metadata; return 0, or 2 for malformed input/CLI errors."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="LRZIP archive or a saved LRZI header")
    parser.add_argument("--offset", type=int, default=0, help="embedded header byte offset")
    try:
        args = parser.parse_args(argv)
        try:
            if args.offset < 0:
                raise LRZIPError("offset must be nonnegative")
            with Path(args.input).open("rb") as source:
                file_size = os.fstat(source.fileno()).st_size
                if args.offset > file_size:
                    raise LRZIPError("offset exceeds file size")
                source.seek(args.offset)
                data = source.read(MAX_HEADER_SIZE)
            result = parse_header(data)
            result["header_offset"] += args.offset
            result["data_offset"] += args.offset
            if result["crypto_descriptor"] is not None:
                result["crypto_descriptor"]["offset"] += args.offset
            result["source_file_size"] = file_size
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        except (LRZIPError, OSError, ValueError, OverflowError) as exc:
            parser.error(str(exc))
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
