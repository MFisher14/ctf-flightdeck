#!/usr/bin/env python3
"""Strict, offline mobile/RF depth helpers for saved challenge artifacts.

This module never opens a radio, device, debugger, or network connection.  Results are evidence
and human-review candidates.  In particular, a corrected pager codeword and a sliced FSK bitstream
are *not* promoted to verified plaintext without an enclosing checksum/protocol validation.
"""
from __future__ import annotations

import argparse
import json
import math
import statistics
import struct
import sys
import zipfile
from io import BytesIO
from pathlib import Path

MAX_INPUT = 256 << 20
MAX_COMMANDS = 4096
MAX_IMAGES = 200000
MAX_MEMBERS = 200000
MAX_MEMBER_UNCOMPRESSED = 128 << 20
MAX_UF2_BLOCKS = 65536
MAX_IMAGE_SPAN = 64 << 20
MAX_CODEWORDS = 4096
MAX_SAMPLES = 2_000_000


class ArtifactError(ValueError):
    """A bounded parser declined malformed, unsupported, or ambiguous input."""


def _cstring(data: bytes, start: int, end: int) -> str:
    if not (0 <= start < end <= len(data)):
        raise ArtifactError("string offset is outside its containing structure")
    stop = data.find(b"\0", start, end)
    if stop < 0:
        raise ArtifactError("unterminated string")
    return data[start:stop].decode("utf-8", "replace")


_CPU = {7: "x86", 12: "arm", 0x01000007: "x86_64", 0x0100000C: "arm64"}
_DYLIB_COMMANDS = {0x0C, 0x0D, 0x18, 0x80000018, 0x20, 0x8000001F, 0x80000023}


def parse_macho(data: bytes) -> dict:
    """Parse bounded Mach-O headers/load commands and report security/runtime evidence.

    Supports thin 32/64-bit files and FAT/FAT64 containers.  It intentionally does not claim that
    a referenced dylib was loaded at runtime or that a code signature is cryptographically valid.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ArtifactError("Mach-O input must be bytes")
    if len(data) > MAX_INPUT:
        raise ArtifactError("Mach-O exceeds 256 MiB cap")
    if len(data) < 4:
        raise ArtifactError("truncated Mach-O")
    raw = data[:4]
    if raw in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf", b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca"):
        endian = ">" if raw[:1] == b"\xca" else "<"
        fat64 = raw in (b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")
        if len(data) < 8:
            raise ArtifactError("truncated FAT header")
        count = struct.unpack_from(endian + "I", data, 4)[0]
        if count == 0 or count > 128:
            raise ArtifactError("invalid FAT slice count")
        size = 32 if fat64 else 20
        if 8 + count * size > len(data):
            raise ArtifactError("truncated FAT architecture table")
        slices = []
        ranges = []
        for i in range(count):
            off = 8 + i * size
            if fat64:
                cpu, sub, pos, length, align, _ = struct.unpack_from(endian + "IIQQII", data, off)
            else:
                cpu, sub, pos, length, align = struct.unpack_from(endian + "IIIII", data, off)
            if align > 63 or pos < 8 + count * size or pos > len(data) or length > len(data) - pos:
                raise ArtifactError("FAT slice range/align is invalid")
            if any(pos < b and a < pos + length for a, b in ranges):
                raise ArtifactError("overlapping FAT slices")
            ranges.append((pos, pos + length))
            if data[pos:pos + 4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf", b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca"):
                raise ArtifactError("FAT slice must be a thin Mach-O")
            child = parse_macho(data[pos:pos + length])
            slices.append({"index": i, "cpu_type": cpu, "cpu": _CPU.get(cpu, f"cpu-{cpu}"),
                           "cpu_subtype": sub, "offset": pos, "size": length, "macho": child})
        return {"format": "fat64" if fat64 else "fat", "slices": slices,
                "verified_structure": True, "candidate_only": True}

    magics = {
        b"\xce\xfa\xed\xfe": ("<", False), b"\xcf\xfa\xed\xfe": ("<", True),
        b"\xfe\xed\xfa\xce": (">", False), b"\xfe\xed\xfa\xcf": (">", True),
    }
    if raw not in magics:
        raise ArtifactError("not a supported Mach-O magic")
    endian, is64 = magics[raw]
    hsize = 32 if is64 else 28
    if len(data) < hsize:
        raise ArtifactError("truncated Mach-O header")
    values = struct.unpack_from(endian + ("IIIIIIII" if is64 else "IIIIIII"), data, 0)
    _, cpu, subtype, filetype, ncmds, sizeofcmds, flags, *rest = values
    if ncmds > MAX_COMMANDS or sizeofcmds > len(data) - hsize:
        raise ArtifactError("invalid Mach-O command bounds")
    command_end = hsize + sizeofcmds
    pos = hsize
    dylibs, uuids, segments, commands = [], [], [], []
    encryption = None
    code_signature = None
    entryoff = None
    for index in range(ncmds):
        if pos + 8 > command_end:
            raise ArtifactError("truncated Mach-O load command")
        cmd, cmdsize = struct.unpack_from(endian + "II", data, pos)
        if cmdsize < 8 or cmdsize % 4 or cmdsize > command_end - pos:
            raise ArtifactError("invalid Mach-O load-command size")
        row = {"index": index, "command": cmd, "size": cmdsize}
        if cmd in _DYLIB_COMMANDS:
            if cmdsize < 24:
                raise ArtifactError("truncated dylib command")
            nameoff = struct.unpack_from(endian + "I", data, pos + 8)[0]
            if nameoff < 24 or nameoff >= cmdsize:
                raise ArtifactError("invalid dylib name offset")
            name = _cstring(data, pos + nameoff, pos + cmdsize)
            dylibs.append(name)
            row["dylib"] = name
        elif cmd == 0x1B:
            if cmdsize != 24:
                raise ArtifactError("invalid LC_UUID size")
            value = data[pos + 8:pos + 24].hex()
            uuids.append(value)
            row["uuid"] = value
        elif cmd == 0x1D:
            if cmdsize < 16:
                raise ArtifactError("truncated LC_CODE_SIGNATURE")
            off, size = struct.unpack_from(endian + "II", data, pos + 8)
            if off > len(data) or size > len(data) - off:
                raise ArtifactError("code-signature range is outside file")
            code_signature = {"offset": off, "size": size, "present": bool(size),
                              "cryptographically_verified": False}
        elif cmd in (0x21, 0x2C):
            need = 24 if cmd == 0x2C else 20
            if cmdsize < need:
                raise ArtifactError("truncated encryption command")
            cryptoff, cryptsize, cryptid = struct.unpack_from(endian + "III", data, pos + 8)
            if cryptoff > len(data) or cryptsize > len(data) - cryptoff:
                raise ArtifactError("encrypted range is outside file")
            encryption = {"offset": cryptoff, "size": cryptsize, "cryptid": cryptid,
                          "encrypted_on_disk": cryptid != 0}
        elif cmd == 0x80000028:
            if cmdsize < 24:
                raise ArtifactError("truncated LC_MAIN")
            entryoff = struct.unpack_from(endian + "Q", data, pos + 8)[0]
            if entryoff >= len(data):
                raise ArtifactError("LC_MAIN entry offset is outside file")
        elif cmd in (0x1, 0x19):
            need = 72 if cmd == 0x19 else 56
            if cmdsize < need:
                raise ArtifactError("truncated segment command")
            name = data[pos + 8:pos + 24].split(b"\0", 1)[0].decode("ascii", "replace")
            segments.append(name)
            row["segment"] = name
        commands.append(row)
        pos += cmdsize
    if pos != command_end:
        raise ArtifactError("load-command sizes do not equal sizeofcmds")
    frida = [name for name in dylibs if any(token in name.lower()
             for token in ("fridagadget", "frida-gadget", "frida_agent", "frida-agent"))]
    return {"format": "macho64" if is64 else "macho32", "byte_order": "little" if endian == "<" else "big",
            "cpu_type": cpu, "cpu": _CPU.get(cpu, f"cpu-{cpu}"), "cpu_subtype": subtype,
            "file_type": filetype, "flags": flags, "commands": commands, "dylibs": dylibs,
            "uuids": uuids, "segments": segments, "entry_offset": entryoff,
            "code_signature": code_signature, "encryption": encryption,
            "frida_gadget_evidence": frida, "instrumentation_active_verified": False,
            "verified_structure": True, "candidate_only": True}


def parse_dyld_cache(data: bytes) -> dict:
    """Inventory the bounded mapping/image tables in classic dyld shared-cache headers."""
    if not isinstance(data, (bytes, bytearray)):
        raise ArtifactError("dyld input must be bytes")
    if len(data) > MAX_INPUT or len(data) < 32 or not data[:16].startswith((b"dyld_v0", b"dyld_v1")):
        raise ArtifactError("not a bounded dyld shared cache")
    mapping_off, mapping_count, image_off, image_count = struct.unpack_from("<IIII", data, 16)
    if mapping_count > 4096 or image_count > MAX_IMAGES:
        raise ArtifactError("dyld table count exceeds cap")
    if mapping_off > len(data) or mapping_count * 32 > len(data) - mapping_off:
        raise ArtifactError("dyld mapping table is truncated")
    if image_off > len(data) or image_count * 32 > len(data) - image_off:
        raise ArtifactError("dyld image table is truncated")
    mappings = []
    for i in range(mapping_count):
        address, size, fileoff, maxprot, initprot = struct.unpack_from("<QQQII", data, mapping_off + 32 * i)
        if fileoff > len(data) or size > len(data) - fileoff:
            raise ArtifactError("dyld mapping range is outside cache")
        mappings.append({"address": address, "size": size, "file_offset": fileoff,
                         "max_protection": maxprot, "initial_protection": initprot})
    images = []
    for i in range(image_count):
        address, modtime, inode, pathoff, _ = struct.unpack_from("<QQQII", data, image_off + 32 * i)
        if pathoff >= len(data):
            raise ArtifactError("dyld image path offset is outside cache")
        path = _cstring(data, pathoff, len(data))
        images.append({"address": address, "mod_time": modtime, "inode": inode, "path": path})
    frida = [x["path"] for x in images if "fridagadget" in x["path"].lower() or "frida-gadget" in x["path"].lower()]
    return {"magic": data[:16].rstrip(b"\0").decode("ascii", "replace"), "mappings": mappings,
            "images": images, "frida_gadget_evidence": frida,
            "instrumentation_active_verified": False, "verified_structure": True,
            "candidate_only": True, "layout": "classic-header"}


def inspect_mobile_bundle(data: bytes) -> dict:
    """Inventory exact Xamarin/IL2CPP/Flutter/Frida artifacts in an APK/IPA/ZIP."""
    if not isinstance(data, (bytes, bytearray)):
        raise ArtifactError("bundle input must be bytes")
    if len(data) > MAX_INPUT:
        raise ArtifactError("bundle exceeds 256 MiB cap")
    try:
        with zipfile.ZipFile(BytesIO(data)) as zf:
            infos = zf.infolist()
    except (zipfile.BadZipFile, OSError, MemoryError, NotImplementedError) as exc:
        raise ArtifactError("not a readable ZIP mobile bundle") from exc
    if len(infos) > MAX_MEMBERS:
        raise ArtifactError("bundle member count exceeds cap")
    names = []
    for info in infos:
        if info.file_size > MAX_MEMBER_UNCOMPRESSED or info.compress_size > MAX_INPUT:
            raise ArtifactError("bundle member exceeds extraction cap")
        if info.filename.startswith("/") or ".." in Path(info.filename).parts or "\0" in info.filename:
            raise ArtifactError("unsafe bundle member name")
        names.append(info.filename)
    low = {name.lower(): name for name in names}
    def matches(pred): return sorted(name for name in names if pred(name.lower()))
    dotnet = matches(lambda n: n.endswith(".dll") or "assemblies.blob" in n or "libmonodroid.so" in n
                     or "mono.framework" in n or "xamarin." in n or "microsoft.ios" in n)
    ilmeta = matches(lambda n: n.endswith("global-metadata.dat"))
    ilbin = matches(lambda n: n.endswith("libil2cpp.so") or n.endswith("gameassembly.dll")
                    or n.endswith("unityframework") or n.endswith("unityframework.dylib"))
    flutter_bin = matches(lambda n: n.endswith("libapp.so") or n.endswith("app.framework/app"))
    flutter_runtime = matches(lambda n: n.endswith("libflutter.so") or n.endswith("flutter.framework/flutter"))
    snapshots = matches(lambda n: n.endswith("vm_snapshot_data") or n.endswith("isolate_snapshot_data"))
    assets = matches(lambda n: "/flutter_assets/" in "/" + n or n.startswith("flutter_assets/"))
    frida = matches(lambda n: any(t in n for t in ("fridagadget", "frida-gadget", "frida_agent", "frida-agent")))
    xamarin_markers = dotnet and any("mono" in n.lower() or "assembl" in n.lower() or "xamarin" in n.lower()
                                     or "microsoft.ios" in n.lower() for n in dotnet)
    return {"member_count": len(names), "xamarin_dotnet": dotnet, "unity_metadata": ilmeta,
            "unity_native": ilbin, "flutter_aot": flutter_bin, "flutter_runtime": flutter_runtime,
            "flutter_snapshots": snapshots, "flutter_assets": assets, "frida_gadget_evidence": frida,
            "runtime_pairs": {"xamarin_or_maui": bool(xamarin_markers),
                              "unity_il2cpp": bool(ilmeta and ilbin),
                              "flutter_aot": bool(flutter_bin and (flutter_runtime or snapshots or assets))},
            "runtime_executed_verified": False, "candidate_only": True}


UF2_MAGIC0, UF2_MAGIC1, UF2_END = 0x0A324655, 0x9E5D5157, 0x0AB16F30


def parse_uf2(data: bytes) -> dict:
    """Validate UF2 blocks and reconstruct only complete, conflict-free flash images."""
    if not data or len(data) > MAX_INPUT or len(data) % 512:
        raise ArtifactError("UF2 must be a bounded non-empty multiple of 512 bytes")
    blocks, by_number, ranges = [], {}, []
    declared = None
    family = None
    for offset in range(0, len(data), 512):
        block = data[offset:offset + 512]
        m0, m1, flags, address, size, number, total, family_or_size = struct.unpack_from("<IIIIIIII", block)
        end = struct.unpack_from("<I", block, 508)[0]
        if (m0, m1, end) != (UF2_MAGIC0, UF2_MAGIC1, UF2_END) or size > 476:
            raise ArtifactError("invalid UF2 magic or payload size")
        if total == 0 or total > MAX_UF2_BLOCKS or number >= total:
            raise ArtifactError("invalid UF2 block numbering")
        if declared is None: declared = total
        if declared != total: raise ArtifactError("inconsistent UF2 block count")
        fam = family_or_size if flags & 0x2000 else None
        if family is None: family = fam
        if fam is not None and family != fam: raise ArtifactError("inconsistent UF2 family ID")
        payload = block[32:32 + size]
        item = {"file_offset": offset, "flags": flags, "target_address": address,
                "payload_size": size, "block_number": number, "block_count": total,
                "family_id": fam, "payload": payload}
        if number in by_number:
            if by_number[number] != item:
                raise ArtifactError("conflicting duplicate UF2 block")
            raise ArtifactError("duplicate UF2 block")
        by_number[number] = item
        if not flags & 0x1:
            if address + size > 0x1_0000_0000:
                raise ArtifactError("UF2 target range wraps")
            if any(address < b and a < address + size for a, b in ranges):
                raise ArtifactError("overlapping UF2 target ranges")
            ranges.append((address, address + size))
        blocks.append(item)
    complete = declared == len(by_number) and set(by_number) == set(range(declared or 0))
    flash = [x for x in blocks if not x["flags"] & 0x1 and x["payload_size"]]
    base = min((x["target_address"] for x in flash), default=None)
    top = max((x["target_address"] + x["payload_size"] for x in flash), default=None)
    image = None
    gaps = []
    if complete and base is not None and top is not None:
        if top - base > MAX_IMAGE_SPAN:
            raise ArtifactError("UF2 image span exceeds 64 MiB cap")
        cursor = base
        for start, end in sorted(ranges):
            if start > cursor:
                gaps.append((cursor, start))
            cursor = max(cursor, end)
        if cursor < top:
            gaps.append((cursor, top))
        # UF2 describes writes, not an erased-flash snapshot.  Bytes between non-contiguous
        # target ranges retain their previous device contents; inventing 0xff there emitted a
        # plausible but unverified reconstructed file.  Only materialise a dense image when every
        # byte in its span is present in a validated block.
        if not gaps:
            buf = bytearray(top - base)
            for item in flash:
                start = item["target_address"] - base
                buf[start:start + item["payload_size"]] = item["payload"]
            image = bytes(buf)
    return {"blocks": blocks, "declared_blocks": declared, "complete": complete,
            "base_address": base, "end_address": top, "gaps": gaps, "image": image,
            "reconstruction_verified": bool(complete and image is not None),
            "candidate_only": not bool(complete and image is not None)}


POCSAG_SYNC, POCSAG_IDLE, POCSAG_GENERATOR = 0x7CD215D8, 0x7A89C197, 0x769


def _pocsag_syndrome(word: int) -> int:
    value = (word >> 1) & 0x7FFFFFFF
    for bit in range(30, 9, -1):
        if value & (1 << bit):
            value ^= POCSAG_GENERATOR << (bit - 10)
    return value & 0x3FF


def _pocsag_valid(word: int) -> bool:
    return _pocsag_syndrome(word) == 0 and word.bit_count() % 2 == 0


def correct_pocsag_codeword(word: int, *, max_errors: int = 2) -> dict:
    """BCH/parity check a 32-bit POCSAG word; corrections remain review candidates."""
    if not isinstance(word, int) or isinstance(word, bool) or not 0 <= word <= 0xFFFFFFFF:
        raise ArtifactError("POCSAG codeword must be uint32")
    if max_errors not in (0, 1, 2):
        raise ArtifactError("POCSAG correction cap is two bits")
    # The synchronization word is not a BCH information codeword.  Accept only the exact marker;
    # never run it through the data-codeword corrector and accidentally turn it into payload.
    if word == POCSAG_SYNC:
        return {"input": word, "word": word, "corrected_bits": [], "bch_parity_valid": None,
                "payload_verified": True, "candidate_only": False, "protocol_marker": "sync"}
    if _pocsag_valid(word):
        return {"input": word, "word": word, "corrected_bits": [], "bch_parity_valid": True,
                "payload_verified": True, "candidate_only": False}
    candidates = []
    if max_errors >= 1:
        for a in range(32):
            value = word ^ (1 << a)
            if _pocsag_valid(value): candidates.append((value, [a]))
    if not candidates and max_errors >= 2:
        for a in range(32):
            for b in range(a + 1, 32):
                value = word ^ (1 << a) ^ (1 << b)
                if _pocsag_valid(value): candidates.append((value, [a, b]))
    unique = {(v, tuple(bits)) for v, bits in candidates}
    if len(unique) != 1:
        return {"input": word, "word": None, "corrected_bits": None, "bch_parity_valid": False,
                "payload_verified": False, "candidate_only": True,
                "reason": "uncorrectable or ambiguous BCH neighborhood"}
    value, bits = next(iter(unique))
    return {"input": word, "word": value, "corrected_bits": list(bits), "bch_parity_valid": True,
            "payload_verified": False, "candidate_only": True,
            "reason": "BCH correction is plausible but has no enclosing integrity check"}


def decode_pocsag_words(words: list[int]) -> dict:
    """Decode already-demodulated words; raw message fields are exact, text remains candidate-only."""
    if not isinstance(words, (list, tuple)):
        raise ArtifactError("POCSAG words must be a list")
    if len(words) > MAX_CODEWORDS:
        raise ArtifactError("POCSAG word count exceeds cap")
    corrected = [correct_pocsag_codeword(x) for x in words]
    decoded = []
    batch_position = 0
    for index, item in enumerate(corrected):
        word = item["word"]
        if word is None:
            # An undecodable word still occupied a transmitted batch slot.  Skipping the slot
            # shifted every later address into the wrong POCSAG frame and therefore emitted a
            # wrong capcode.  Preserve the hole and advance the framing clock.
            decoded.append({"index": index, "kind": "uncorrectable", "verified": False})
            batch_position = (batch_position + 1) % 16
            continue
        if word == POCSAG_SYNC:
            batch_position = 0
            decoded.append({"index": index, "kind": "sync", "verified": item["payload_verified"]})
            continue
        if word == POCSAG_IDLE:
            decoded.append({"index": index, "kind": "sync" if word == POCSAG_SYNC else "idle",
                            "verified": item["payload_verified"]})
        elif word & 0x80000000:
            decoded.append({"index": index, "kind": "message", "bits20": (word >> 11) & 0xFFFFF,
                            "verified": item["payload_verified"], "text_interpretation_verified": False})
        else:
            frame = (batch_position % 16) // 2
            decoded.append({"index": index, "kind": "address",
                            "capcode": (((word >> 13) & 0x3FFFF) << 3) | frame,
                            "function": (word >> 11) & 3, "verified": item["payload_verified"]})
        batch_position = (batch_position + 1) % 16
    return {"codewords": corrected, "fields": decoded,
            "all_payloads_verified": all(x["payload_verified"] for x in corrected),
            "candidate_only": not all(x["payload_verified"] for x in corrected)}


def slice_fsk_discriminator(samples, samples_per_symbol: int) -> dict:
    """Hard-slice a saved FM-discriminator trace and return both unresolved polarities."""
    if not isinstance(samples_per_symbol, int) or isinstance(samples_per_symbol, bool):
        raise ArtifactError("samples_per_symbol must be an int")
    try:
        vals = [float(x) for x in samples]
    except (TypeError, ValueError, OverflowError) as exc:
        raise ArtifactError("discriminator samples must be finite numbers") from exc
    if not vals or len(vals) > MAX_SAMPLES or not 1 <= samples_per_symbol <= 65536:
        raise ArtifactError("invalid bounded discriminator trace")
    if any(not math.isfinite(x) for x in vals):
        raise ArtifactError("non-finite discriminator sample")
    best = None
    for phase in range(min(samples_per_symbol, len(vals))):
        means = [sum(vals[i:i + samples_per_symbol]) / len(vals[i:i + samples_per_symbol])
                 for i in range(phase, len(vals), samples_per_symbol)
                 if len(vals[i:i + samples_per_symbol]) == samples_per_symbol]
        if not means: continue
        score = sum(abs(x) for x in means) / len(means)
        if best is None or score > best[0]: best = (score, phase, means)
    if best is None:
        raise ArtifactError("trace contains no complete symbol")
    score, phase, means = best
    bits = [1 if x >= 0 else 0 for x in means]
    noise = statistics.fmean(abs(x) for x in vals) or 1.0
    return {"phase": phase, "samples_per_symbol": samples_per_symbol,
            "polarity_candidates": [bits, [1 - x for x in bits]],
            "separation_score": score / noise, "payload_verified": False, "candidate_only": True}


def analyze_glitch_trace(samples, *, z_threshold: float = 8.0, max_width: int = 32) -> dict:
    """Locate robust-MAD outlier runs in a saved voltage/clock trace without assigning cause."""
    try:
        vals = [float(x) for x in samples]
    except (TypeError, ValueError, OverflowError) as exc:
        raise ArtifactError("trace samples must be finite numbers") from exc
    if not vals or len(vals) > MAX_SAMPLES or not 1 <= max_width <= 65536 or not 1 <= z_threshold <= 1000:
        raise ArtifactError("invalid bounded glitch trace parameters")
    if any(not math.isfinite(x) for x in vals):
        raise ArtifactError("non-finite trace sample")
    median = statistics.median(vals)
    mad = statistics.median(abs(x - median) for x in vals)
    scale = 1.4826 * mad
    if scale == 0:
        nonzero = [abs(x - median) for x in vals if x != median]
        scale = min(nonzero) / z_threshold if nonzero else 1.0
    mask = [abs(x - median) / scale >= z_threshold for x in vals]
    events, i = [], 0
    while i < len(vals):
        if not mask[i]: i += 1; continue
        j = i + 1
        while j < len(vals) and mask[j]: j += 1
        if j - i <= max_width:
            peak = max(range(i, j), key=lambda k: abs(vals[k] - median))
            events.append({"start": i, "end": j, "width": j - i, "peak_index": peak,
                           "peak_value": vals[peak], "robust_z": abs(vals[peak] - median) / scale})
        i = j
    return {"median": median, "mad": mad, "events": events,
            "fault_or_glitch_cause_verified": False, "candidate_only": True}


def _jsonable(value):
    if isinstance(value, bytes): return {"hex": value.hex(), "length": len(value)}
    if isinstance(value, dict): return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)): return [_jsonable(v) for v in value]
    return value


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Offline saved-artifact mobile/RF depth parser")
    ap.add_argument("mode", choices=("macho", "dyld", "bundle", "uf2", "pocsag", "fsk", "glitch"))
    ap.add_argument("input", help="artifact file; pocsag/fsk/glitch use bounded JSON arrays")
    ap.add_argument("--samples-per-symbol", type=int, default=1)
    try:
        ns = ap.parse_args(argv)
        path = Path(ns.input)
        if path.stat().st_size > MAX_INPUT: raise ArtifactError("input exceeds 256 MiB cap")
        if ns.mode in ("pocsag", "fsk", "glitch"):
            value = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(value, list): raise ArtifactError("JSON input must be an array")
            if ns.mode == "pocsag": result = decode_pocsag_words(value)
            elif ns.mode == "fsk": result = slice_fsk_discriminator(value, ns.samples_per_symbol)
            else: result = analyze_glitch_trace(value)
        else:
            data = path.read_bytes()
            result = {"macho": parse_macho, "dyld": parse_dyld_cache,
                      "bundle": inspect_mobile_bundle, "uf2": parse_uf2}[ns.mode](data)
        print(json.dumps(_jsonable(result), indent=2, sort_keys=True))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (ArtifactError, OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError,
            struct.error, zipfile.BadZipFile, MemoryError, RecursionError) as exc:
        print(f"mobile-rf-depth: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
