#!/usr/bin/env python3
"""Strict offline firmware-container identification, validation, and carving.

Supported artifacts are SquashFS, JFFS2, UBI, CramFS, U-Boot legacy uImage/FIT,
Intel HEX, and Motorola S-record.  Parsing is read-only and bounded; the module neither
mounts nor executes firmware and does not invoke external unpackers.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import struct
import zlib
from pathlib import Path


MAX_INPUT = 256 << 20
MAX_IMAGE_SPAN = 128 << 20
MAX_RECORDS = 1_000_000
MAX_CARVES = 512


class FirmwareError(ValueError):
    pass


def _check_blob(data: bytes) -> None:
    if not isinstance(data, bytes) or len(data) > MAX_INPUT:
        raise FirmwareError("firmware input must be bounded bytes")


def _check_text(text: str, label: str) -> None:
    if not isinstance(text, str):
        raise FirmwareError(f"{label} input must be text")
    try:
        size = len(text.encode("utf-8"))
    except UnicodeError as exc:
        raise FirmwareError(f"{label} contains invalid Unicode") from exc
    if size > MAX_INPUT:
        raise FirmwareError(f"{label} text exceeds cap")


def _segments(memory: dict[int, int]) -> list[dict]:
    if not memory:
        return []
    addresses = sorted(memory)
    out, start, previous = [], addresses[0], addresses[0]
    payload = bytearray([memory[start]])
    for address in addresses[1:]:
        if address == previous + 1:
            payload.append(memory[address])
        else:
            out.append({"address": start, "data": bytes(payload)})
            start, payload = address, bytearray([memory[address]])
        previous = address
    out.append({"address": start, "data": bytes(payload)})
    return out


_SQUASH_COMP = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}


def parse_squashfs(data: bytes) -> dict:
    _check_blob(data)
    if len(data) < 96 or data[:4] not in (b"hsqs", b"sqsh"):
        raise FirmwareError("not a SquashFS superblock")
    endian = "<" if data[:4] == b"hsqs" else ">"
    fields = struct.unpack_from(endian + "IIIIIHHHHHHQQQQQQQQ", data)
    (magic, inode_count, mkfs_time, block_size, fragments, compression, block_log, flags,
     id_count, major, minor, root_inode, bytes_used, id_table, xattr_table, inode_table,
     directory_table, fragment_table, export_table) = fields
    if (major != 4 or not 4096 <= block_size <= (1 << 20)
            or block_size & (block_size - 1) or block_log != block_size.bit_length() - 1):
        raise FirmwareError("implausible SquashFS geometry")
    if bytes_used < 96 or bytes_used > len(data):
        raise FirmwareError("SquashFS bytes_used exceeds supplied artifact")
    offsets = {"id": id_table, "xattr": xattr_table, "inode": inode_table,
               "directory": directory_table, "fragment": fragment_table, "export": export_table}
    valid_offsets = {name: value for name, value in offsets.items()
                     if value != 0xFFFFFFFFFFFFFFFF}
    if any(value >= bytes_used for value in valid_offsets.values()):
        raise FirmwareError("SquashFS table points beyond bytes_used")
    return {"kind": "squashfs", "endian": "little" if endian == "<" else "big",
            "version": f"{major}.{minor}", "inode_count": inode_count,
            "mkfs_time": mkfs_time, "block_size": block_size, "block_log": block_log,
            "fragment_count": fragments, "compression_id": compression,
            "compression": _SQUASH_COMP.get(compression, f"unknown-{compression}"),
            "flags": flags, "id_count": id_count, "root_inode_ref": root_inode,
            "bytes_used": bytes_used, "table_offsets": offsets, "extent": bytes_used,
            "complete": True}


def _jffs2_crc(data: bytes) -> int:
    return (zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF


_JFFS_TYPES = {0xE001: "dirent", 0xE002: "inode", 0x2003: "cleanmarker",
                0x2004: "padding", 0x2006: "summary", 0xE008: "xattr",
                0xE009: "xref"}


def parse_jffs2(data: bytes) -> dict:
    _check_blob(data)
    if len(data) < 12:
        raise FirmwareError("JFFS2 input is too short")
    if data[:2] == b"\x85\x19":
        endian = "<"
    elif data[:2] == b"\x19\x85":
        endian = ">"
    else:
        raise FirmwareError("not a JFFS2 node stream")
    nodes, pos, invalid_headers = [], 0, 0
    while pos + 12 <= len(data) and len(nodes) < MAX_RECORDS:
        if data[pos:pos + 4] == b"\xff\xff\xff\xff":
            pos += 4
            continue
        magic, node_type, total, supplied_crc = struct.unpack_from(endian + "HHII", data, pos)
        if magic != 0x1985:
            break
        if total < 12 or total > len(data) - pos:
            raise FirmwareError("JFFS2 node length exceeds artifact")
        header_ok = _jffs2_crc(data[pos:pos + 8]) == supplied_crc
        if not header_ok:
            invalid_headers += 1
        kind = _JFFS_TYPES.get(node_type, f"0x{node_type:04x}")
        row = {"offset": pos, "node_type": node_type, "kind": kind,
               "length": total, "header_crc_ok": header_ok}
        if kind == "dirent" and total >= 40:
            pino, version, ino, mctime = struct.unpack_from(endian + "IIII", data, pos + 12)
            name_size, dtype = struct.unpack_from("BB", data, pos + 28)
            node_crc, name_crc = struct.unpack_from(endian + "II", data, pos + 32)
            if 40 + name_size <= total:
                name = data[pos + 40:pos + 40 + name_size]
                row.update(parent_inode=pino, version=version, inode=ino, mctime=mctime,
                           entry_type=dtype, name=name.decode("utf-8", "replace"),
                           node_crc_ok=_jffs2_crc(data[pos:pos + 32]) == node_crc,
                           name_crc_ok=_jffs2_crc(name) == name_crc)
        elif kind == "inode" and total >= 68:
            ino, version, mode = struct.unpack_from(endian + "III", data, pos + 12)
            file_size = struct.unpack_from(endian + "I", data, pos + 28)[0]
            file_offset, compressed_size, data_size = struct.unpack_from(endian + "III", data, pos + 44)
            compression = data[pos + 56]
            data_crc, node_crc = struct.unpack_from(endian + "II", data, pos + 60)
            payload = data[pos + 68:pos + 68 + compressed_size]
            row.update(inode=ino, version=version, mode=mode, file_size=file_size,
                       file_offset=file_offset, compressed_size=compressed_size,
                       data_size=data_size, compression=compression,
                       node_crc_ok=_jffs2_crc(data[pos:pos + 60]) == node_crc,
                       data_crc_ok=(len(payload) == compressed_size and
                                    _jffs2_crc(payload) == data_crc))
        nodes.append(row)
        pos += (total + 3) & ~3
    if not nodes:
        raise FirmwareError("no complete JFFS2 nodes")
    return {"kind": "jffs2", "endian": "little" if endian == "<" else "big",
            "nodes": nodes, "node_count": len(nodes), "invalid_header_crcs": invalid_headers,
            "extent": pos, "complete": pos <= len(data)}


def _ubi_crc(data: bytes) -> int:
    return (zlib.crc32(data) ^ 0xFFFFFFFF) & 0xFFFFFFFF


def parse_ubi_ec_header(data: bytes, offset: int = 0) -> dict:
    _check_blob(data)
    if not isinstance(offset, int) or offset < 0 or offset + 64 > len(data) or data[offset:offset + 4] != b"UBI#":
        raise FirmwareError("not a complete UBI erase-counter header")
    version = data[offset + 4]
    erase_count = struct.unpack_from(">Q", data, offset + 8)[0]
    vid_offset, data_offset, image_seq = struct.unpack_from(">III", data, offset + 16)
    supplied = struct.unpack_from(">I", data, offset + 60)[0]
    if version not in (1,) or not 64 <= vid_offset < data_offset or data_offset > (16 << 20):
        raise FirmwareError("implausible UBI header geometry")
    return {"offset": offset, "version": version, "erase_count": erase_count,
            "vid_header_offset": vid_offset, "data_offset": data_offset,
            "image_sequence": image_seq, "header_crc": supplied,
            "header_crc_ok": _ubi_crc(data[offset:offset + 60]) == supplied}


def parse_ubi_vid_header(data: bytes, offset: int) -> dict:
    _check_blob(data)
    if not isinstance(offset, int) or offset < 0 or offset + 64 > len(data) or data[offset:offset + 4] != b"UBI!":
        raise FirmwareError("not a complete UBI volume-identifier header")
    version, volume_type, copy_flag, compatibility = struct.unpack_from("BBBB", data, offset + 4)
    volume_id, logical_number = struct.unpack_from(">II", data, offset + 8)
    data_size, used_ebs, data_pad, data_crc = struct.unpack_from(">IIII", data, offset + 20)
    sequence = struct.unpack_from(">Q", data, offset + 40)[0]
    supplied = struct.unpack_from(">I", data, offset + 60)[0]
    return {"version": version, "volume_type": volume_type, "copy_flag": copy_flag,
            "compatibility": compatibility, "volume_id": volume_id,
            "logical_eraseblock": logical_number, "data_size": data_size,
            "used_eraseblocks": used_ebs, "data_padding": data_pad, "data_crc": data_crc,
            "sequence": sequence, "header_crc": supplied,
            "header_crc_ok": _ubi_crc(data[offset:offset + 60]) == supplied}


def parse_ubi(data: bytes) -> dict:
    _check_blob(data)
    first = parse_ubi_ec_header(data, 0)
    positions, cursor = [], 0
    while len(positions) < MAX_CARVES:
        found = data.find(b"UBI#", cursor)
        if found < 0:
            break
        positions.append(found)
        cursor = found + 4
    # Ignore magic-like payload bytes before deriving geometry: only complete, plausible EC
    # headers may participate in the eraseblock stride.
    valid_positions = []
    for position in positions:
        try:
            parse_ubi_ec_header(data, position)
            valid_positions.append(position)
        except FirmwareError:
            pass
    positive = [b - a for a, b in zip(valid_positions, valid_positions[1:]) if b > a]
    eraseblock = 0
    if positive:
        eraseblock = positive[0]
        for distance in positive[1:]:
            eraseblock = math.gcd(eraseblock, distance)
        if eraseblock < first["data_offset"]:
            eraseblock = positive[0]
    headers = []
    for position in valid_positions:
        try:
            ec = parse_ubi_ec_header(data, position)
            vid_at = position + ec["vid_header_offset"]
            ec["vid"] = parse_ubi_vid_header(data, vid_at) if data[vid_at:vid_at + 4] == b"UBI!" else None
            headers.append(ec)
        except FirmwareError:
            continue
    if not headers:
        raise FirmwareError("no valid UBI headers")
    extent = len(data) if not eraseblock else min(len(data), valid_positions[-1] + eraseblock)
    return {"kind": "ubi", "eraseblock_size": eraseblock or None, "peb_count": len(headers),
            "headers": headers, "extent": extent, "complete": bool(eraseblock)}


CRAMFS_MAGIC = 0x28CD3D45


def parse_cramfs(data: bytes) -> dict:
    _check_blob(data)
    if len(data) < 76:
        raise FirmwareError("CramFS superblock is truncated")
    little = struct.unpack_from("<I", data)[0] == CRAMFS_MAGIC
    big = struct.unpack_from(">I", data)[0] == CRAMFS_MAGIC
    if not (little or big):
        raise FirmwareError("not CramFS")
    endian = "<" if little else ">"
    size, flags, future = struct.unpack_from(endian + "III", data, 4)
    if size < 92 or size > len(data):
        raise FirmwareError("CramFS size exceeds artifact")
    signature = data[16:32].rstrip(b"\x00")
    if not signature.startswith(b"Compressed ROMFS"):
        raise FirmwareError("CramFS signature missing")
    checksum, edition, blocks, files = struct.unpack_from(endian + "IIII", data, 32)
    name = data[48:64].split(b"\x00", 1)[0].decode("utf-8", "replace")
    supplied = bytearray(data[:size])
    supplied[32:36] = b"\x00" * 4
    calculated = zlib.crc32(supplied) & 0xFFFFFFFF
    return {"kind": "cramfs", "endian": "little" if little else "big", "size": size,
            "flags": flags, "future": future, "edition": edition, "block_count": blocks,
            "file_count": files, "name": name, "checksum": checksum,
            "checksum_ok": calculated == checksum, "extent": size, "complete": True}


# U-Boot include/image.h IH_OS_* / IH_ARCH_* enums (canonical, long-stable).
_UBOOT_OS = {0: "invalid", 1: "openbsd", 2: "netbsd", 3: "freebsd", 4: "4_4bsd", 5: "linux",
             6: "svr4", 7: "esix", 8: "solaris", 9: "irix", 10: "sco", 11: "dell",
             12: "ncr", 13: "lynxos", 14: "vxworks", 15: "psos", 16: "qnx", 17: "u-boot",
             18: "rtems", 19: "artos", 20: "unity", 21: "integrity", 22: "ose", 23: "plan9",
             24: "openrtos", 25: "arm-trusted-firmware", 26: "tee", 27: "opensbi",
             28: "efi", 29: "elf"}
_UBOOT_ARCH = {0: "invalid", 1: "alpha", 2: "arm", 3: "x86", 4: "ia64", 5: "mips", 6: "mips64", 7: "ppc",
               8: "s390", 9: "sh", 10: "sparc", 11: "sparc64", 12: "m68k", 13: "nios",
               14: "microblaze", 15: "nios2", 16: "blackfin", 17: "avr32", 18: "st200",
               19: "sandbox", 20: "nds32", 21: "openrisc", 22: "arm64", 23: "arc",
               24: "x86_64", 25: "xtensa", 26: "riscv"}
_UBOOT_TYPE = {1: "standalone", 2: "kernel", 3: "ramdisk", 4: "multi", 5: "firmware",
               6: "script", 7: "filesystem", 8: "flatdt", 14: "kernel-noload"}
_UBOOT_COMP = {0: "none", 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo", 5: "lz4", 6: "zstd"}


def parse_uimage(data: bytes) -> dict:
    _check_blob(data)
    if len(data) < 64 or data[:4] != b"'\x05\x19V":
        raise FirmwareError("not a legacy U-Boot uImage")
    (magic, header_crc, timestamp, size, load, entry, data_crc,
     os_id, arch_id, image_type, compression, name_raw) = struct.unpack_from(">7I4B32s", data)
    if size > MAX_IMAGE_SPAN or 64 + size > len(data):
        raise FirmwareError("uImage payload is truncated or exceeds cap")
    header = bytearray(data[:64])
    header[4:8] = b"\x00" * 4
    payload = data[64:64 + size]
    return {"kind": "uimage", "timestamp": timestamp, "payload_size": size,
            "load_address": load, "entry_address": entry, "os_id": os_id,
            "os": _UBOOT_OS.get(os_id, f"unknown-{os_id}"), "arch_id": arch_id,
            "arch": _UBOOT_ARCH.get(arch_id, f"unknown-{arch_id}"), "type_id": image_type,
            "type": _UBOOT_TYPE.get(image_type, f"unknown-{image_type}"),
            "compression_id": compression,
            "compression": _UBOOT_COMP.get(compression, f"unknown-{compression}"),
            "name": name_raw.split(b"\x00", 1)[0].decode("utf-8", "replace"),
            "header_crc": header_crc, "header_crc_ok": zlib.crc32(header) & 0xFFFFFFFF == header_crc,
            "data_crc": data_crc, "data_crc_ok": zlib.crc32(payload) & 0xFFFFFFFF == data_crc,
            "payload": payload, "extent": 64 + size, "complete": True}


FDT_MAGIC = 0xD00DFEED
FDT_BEGIN_NODE, FDT_END_NODE, FDT_PROP, FDT_NOP, FDT_END = 1, 2, 3, 4, 9


def _c_string(data: bytes, offset: int, limit: int) -> tuple[str, int]:
    end = data.find(b"\x00", offset, limit)
    if end < 0:
        raise FirmwareError("unterminated FDT string")
    return data[offset:end].decode("utf-8", "replace"), (end + 4) & ~3


def parse_fit(data: bytes) -> dict:
    _check_blob(data)
    if len(data) < 40 or struct.unpack_from(">I", data)[0] != FDT_MAGIC:
        raise FirmwareError("not an FDT/FIT image")
    (magic, total, struct_off, strings_off, reserve_off, version, last_version,
     boot_cpuid, strings_size, struct_size) = struct.unpack_from(">10I", data)
    if total < 40 or total > len(data) or struct_off + struct_size > total or strings_off + strings_size > total:
        raise FirmwareError("FIT offsets exceed artifact")
    strings = data[strings_off:strings_off + strings_size]
    pos, end, stack, nodes = struct_off, struct_off + struct_size, [], {}
    saw_end = False
    while pos + 4 <= end and len(nodes) < MAX_RECORDS:
        token = struct.unpack_from(">I", data, pos)[0]
        pos += 4
        if token == FDT_BEGIN_NODE:
            name, pos = _c_string(data, pos, end)
            stack.append(name)
            path = "/" + "/".join(part for part in stack if part)
            nodes.setdefault(path, {})
        elif token == FDT_END_NODE:
            if not stack:
                raise FirmwareError("unbalanced FIT node")
            stack.pop()
        elif token == FDT_PROP:
            if pos + 8 > end or not stack:
                raise FirmwareError("truncated FIT property")
            length, name_offset = struct.unpack_from(">II", data, pos)
            pos += 8
            if pos + length > end or name_offset >= len(strings):
                raise FirmwareError("FIT property points out of bounds")
            name_end = strings.find(b"\x00", name_offset)
            if name_end < 0:
                raise FirmwareError("FIT property name is unterminated")
            name = strings[name_offset:name_end].decode("utf-8", "replace")
            value = data[pos:pos + length]
            pos = (pos + length + 3) & ~3
            path = "/" + "/".join(part for part in stack if part)
            nodes[path][name] = value
        elif token == FDT_NOP:
            continue
        elif token == FDT_END:
            saw_end = True
            break
        else:
            raise FirmwareError(f"unknown FIT token {token}")
    if not saw_end or stack:
        raise FirmwareError("FIT structure is missing its end token or has unclosed nodes")
    if "/images" not in nodes and not any(path.startswith("/images/") for path in nodes):
        raise FirmwareError("FDT has no FIT /images node")
    images = []
    for path, props in sorted(nodes.items()):
        if path.count("/") != 2 or not path.startswith("/images/"):
            continue
        row = {"name": path.rsplit("/", 1)[1]}
        for key in ("description", "type", "arch", "os", "compression"):
            if key in props:
                row[key] = props[key].split(b"\x00", 1)[0].decode("utf-8", "replace")
        for key in ("load", "entry", "data-size", "data-offset", "data-position"):
            if key in props and len(props[key]) in (4, 8):
                row[key.replace("-", "_")] = int.from_bytes(props[key], "big")
        if "data" in props:
            row["embedded_data_size"] = len(props["data"])
            payload = props["data"]
        else:
            payload = None
            size = row.get("data_size")
            if isinstance(size, int) and "data_position" in row:
                start = row["data_position"]
                if 0 <= start <= len(data) and start + size <= len(data):
                    payload = data[start:start + size]
                    row["external_data_span"] = [start, start + size]
            elif isinstance(size, int) and "data_offset" in row:
                start = ((total + 3) & ~3) + row["data_offset"]
                if 0 <= start <= len(data) and start + size <= len(data):
                    payload = data[start:start + size]
                    row["external_data_span"] = [start, start + size]
        hashes = []
        for hash_path, hash_props in sorted(nodes.items()):
            if not hash_path.startswith(path + "/") or hash_path.count("/") != 3:
                continue
            algorithm = hash_props.get("algo", b"").split(b"\x00", 1)[0].decode("ascii", "replace")
            expected = hash_props.get("value")
            actual = None
            if payload is not None and algorithm in {"sha1", "sha256", "sha384", "sha512", "md5"}:
                actual = hashlib.new(algorithm, payload).digest()
            elif payload is not None and algorithm == "crc32":
                actual = struct.pack(">I", zlib.crc32(payload) & 0xFFFFFFFF)
            hashes.append({"node": hash_path.rsplit("/", 1)[1], "algorithm": algorithm,
                           "expected": expected, "calculated": actual,
                           "valid": actual == expected if actual is not None and expected is not None else None})
        if hashes:
            row["hashes"] = hashes
        images.append(row)
    return {"kind": "fit", "fdt_version": version, "last_compatible_version": last_version,
            "boot_cpuid": boot_cpuid, "images": images,
            "configurations": sorted(path.rsplit("/", 1)[1] for path in nodes
                                     if path.count("/") == 2 and path.startswith("/configurations/")),
            "node_count": len(nodes), "extent": total, "complete": True}


def _write_memory(memory: dict[int, int], address: int, payload: bytes) -> None:
    if address < 0 or address + len(payload) > (1 << 64):
        raise FirmwareError("record address overflow")
    for offset, byte in enumerate(payload):
        old = memory.get(address + offset)
        if old is not None and old != byte:
            raise FirmwareError(f"conflicting data at address 0x{address + offset:x}")
        memory[address + offset] = byte
    if memory and max(memory) - min(memory) > MAX_IMAGE_SPAN:
        raise FirmwareError("sparse firmware image span exceeds cap")


def parse_intel_hex(text: str) -> dict:
    _check_text(text, "Intel HEX")
    memory, upper, mode, entry, eof, records = {}, 0, "linear", None, False, 0
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        if eof:
            raise FirmwareError("non-empty Intel HEX record follows EOF")
        if not line.startswith(":") or len(line) % 2 == 0:
            raise FirmwareError(f"malformed Intel HEX line {line_number}")
        try:
            record = bytes.fromhex(line[1:])
        except ValueError as exc:
            raise FirmwareError(f"non-hex Intel HEX line {line_number}") from exc
        records += 1
        if records > MAX_RECORDS or len(record) < 5 or record[0] + 5 != len(record) or sum(record) & 0xFF:
            raise FirmwareError(f"invalid Intel HEX length/checksum at line {line_number}")
        count, address, kind = record[0], int.from_bytes(record[1:3], "big"), record[3]
        payload = record[4:-1]
        if kind == 0:
            _write_memory(memory, upper + address, payload)
        elif kind == 1:
            if count or address:
                raise FirmwareError("invalid Intel HEX EOF record")
            eof = True
        elif kind == 2:
            if count != 2 or address:
                raise FirmwareError("invalid Intel HEX segment record")
            upper, mode = int.from_bytes(payload, "big") << 4, "segment"
        elif kind == 3:
            if count != 4 or address:
                raise FirmwareError("invalid Intel HEX start-segment record")
            entry = (int.from_bytes(payload[:2], "big") << 4) + int.from_bytes(payload[2:], "big")
        elif kind == 4:
            if count != 2 or address:
                raise FirmwareError("invalid Intel HEX linear record")
            upper, mode = int.from_bytes(payload, "big") << 16, "linear"
        elif kind == 5:
            if count != 4 or address:
                raise FirmwareError("invalid Intel HEX start-linear record")
            entry = int.from_bytes(payload, "big")
        else:
            raise FirmwareError(f"unsupported Intel HEX record type {kind}")
    if not eof or not records:
        raise FirmwareError("Intel HEX EOF record missing")
    return {"kind": "intel-hex", "record_count": records, "address_mode": mode,
            "entry_address": entry, "segments": _segments(memory), "byte_count": len(memory),
            "base_address": min(memory) if memory else None,
            "end_address": max(memory) + 1 if memory else None, "complete": True}


def parse_srec(text: str) -> dict:
    _check_text(text, "S-record")
    address_sizes = {0: 2, 1: 2, 2: 3, 3: 4, 5: 2, 6: 3, 7: 4, 8: 3, 9: 2}
    memory, headers, declared_count, entry, records, data_records, terminated = {}, [], None, None, 0, 0, False
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        if terminated:
            raise FirmwareError("S-record follows termination record")
        if len(line) < 4 or line[0] != "S" or line[1] not in "0123456789":
            raise FirmwareError(f"malformed S-record line {line_number}")
        kind = int(line[1])
        if kind not in address_sizes:
            raise FirmwareError(f"unsupported S-record type S{kind}")
        try:
            body = bytes.fromhex(line[2:])
        except ValueError as exc:
            raise FirmwareError(f"non-hex S-record line {line_number}") from exc
        records += 1
        if records > MAX_RECORDS or len(body) < 2 or body[0] + 1 != len(body) or sum(body) & 0xFF != 0xFF:
            raise FirmwareError(f"invalid S-record length/checksum at line {line_number}")
        addr_size = address_sizes[kind]
        if body[0] < addr_size + 1:
            raise FirmwareError("S-record count cannot contain its address/checksum")
        address = int.from_bytes(body[1:1 + addr_size], "big")
        payload = body[1 + addr_size:-1]
        if kind == 0:
            headers.append(payload.decode("latin1"))
        elif kind in (1, 2, 3):
            _write_memory(memory, address, payload)
            data_records += 1
        elif kind in (5, 6):
            if payload:
                raise FirmwareError("S-record count record contains payload")
            declared_count = address
        elif kind in (7, 8, 9):
            if payload:
                raise FirmwareError("S-record termination contains payload")
            entry, terminated = address, True
    if not terminated or not records:
        raise FirmwareError("S-record termination missing")
    return {"kind": "srec", "record_count": records, "data_record_count": data_records,
            "declared_data_records": declared_count,
            "count_matches": declared_count is None or declared_count == data_records,
            "headers": headers, "entry_address": entry, "segments": _segments(memory),
            "byte_count": len(memory), "base_address": min(memory) if memory else None,
            "end_address": max(memory) + 1 if memory else None, "complete": True}


_MAGICS = ((b"hsqs", "squashfs", parse_squashfs), (b"sqsh", "squashfs", parse_squashfs),
           (b"\x85\x19", "jffs2", parse_jffs2), (b"\x19\x85", "jffs2", parse_jffs2),
           (b"UBI#", "ubi", parse_ubi), (b"E=\xcd(", "cramfs", parse_cramfs),
           (b"(\xcd=E", "cramfs", parse_cramfs), (b"'\x05\x19V", "uimage", parse_uimage),
           (b"\xd0\r\xfe\xed", "fit", parse_fit))


def carve_firmware(data: bytes) -> list[dict]:
    """Find and validate embedded firmware containers; false magic hits are omitted."""
    _check_blob(data)
    rows, seen, covered = [], set(), {}
    for magic, kind, parser in _MAGICS:
        cursor = 0
        while len(rows) < MAX_CARVES:
            offset = data.find(magic, cursor)
            if offset < 0:
                break
            cursor = offset + 1
            if (offset, kind) in seen:
                continue
            seen.add((offset, kind))
            if any(start <= offset < end for start, end in covered.get(kind, [])):
                continue
            try:
                report = parser(data[offset:])
            except (FirmwareError, struct.error, OverflowError):
                continue
            rows.append({"offset": offset, "kind": kind, "extent": report.get("extent"),
                         "report": report})
            extent = report.get("extent")
            if isinstance(extent, int) and extent > 0:
                covered.setdefault(kind, []).append((offset, offset + extent))
    stripped = data.lstrip()
    if stripped.startswith(b":"):
        try:
            rows.append({"offset": len(data) - len(stripped), "kind": "intel-hex", "extent": len(stripped),
                         "report": parse_intel_hex(stripped.decode("ascii"))})
        except (FirmwareError, UnicodeError):
            pass
    if stripped.startswith(b"S"):
        try:
            rows.append({"offset": len(data) - len(stripped), "kind": "srec", "extent": len(stripped),
                         "report": parse_srec(stripped.decode("ascii"))})
        except (FirmwareError, UnicodeError):
            pass
    rows.sort(key=lambda row: (row["offset"], row["kind"]))
    return rows[:MAX_CARVES]


def _jsonable(value):
    if isinstance(value, bytes):
        return value.hex()
    raise TypeError(type(value).__name__)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="offline firmware container validator/carver")
    parser.add_argument("input")
    parser.add_argument("--format", choices=("auto", "ihex", "srec"), default="auto")
    try:
        args = parser.parse_args(argv)
        try:
            data = Path(args.input).read_bytes()
            if args.format == "ihex":
                result = parse_intel_hex(data.decode("ascii"))
            elif args.format == "srec":
                result = parse_srec(data.decode("ascii"))
            else:
                result = carve_firmware(data)
            print(json.dumps(result, indent=2, default=_jsonable, sort_keys=True))
            return 0
        except (OSError, UnicodeError, FirmwareError) as exc:
            parser.error(str(exc))
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
