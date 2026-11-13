#!/usr/bin/env python3
"""Bounded, offline PSD/PSB section, resource, layer and embedded-data inventory.

Extends the header-only PSD metadata in readers_more.py without rendering pixels.
Adobe specification: https://www.adobe.com/devnet-apps/photoshop/fileformatashtml/
Unknown descriptors and compressed pixels remain opaque. Offsets are file-relative.
Public parsing/extraction APIs raise only PSDInventoryError on rejected inputs.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

MAX_BYTES = 256 * 1024 * 1024
MAX_RECORDS = 8192
MAX_LAYERS = 4096
MAX_STRING_UNITS = 32768
MAX_SCANLINES = 1_000_000

# PSB lengths widened by Adobe, plus later keys implemented by psd-tools.
_BIG_KEYS = {b"LMsk", b"Lr16", b"Lr32", b"Layr", b"Mt16", b"Mt32", b"Mtrn",
             b"Alph", b"FMsk", b"lnk2", b"lnk3", b"lnkE", b"FEid", b"FXid",
             b"FELS", b"PxSD", b"pths", b"extd", b"extn", b"cinf", b"artd"}
_RESOURCE_NAMES = {1005: "resolution", 1006: "alpha_names", 1008: "caption",
                   1028: "IPTC", 1033: "thumbnail_v4", 1036: "thumbnail_v5",
                   1039: "ICC_profile", 1045: "unicode_alpha_names",
                   1058: "EXIF_1", 1059: "EXIF_3", 1060: "XMP",
                   1086: "auto_save_path", 1087: "auto_save_format"}
_BLENDS = {"norm": "normal", "pass": "pass_through", "mul ": "multiply",
           "scrn": "screen", "over": "overlay", "diss": "dissolve",
           "dark": "darken", "lite": "lighten", "diff": "difference"}


class PSDInventoryError(Exception):
    """Invalid, unsupported, inaccessible or over-budget PSD/PSB input."""


class _Reader:
    def __init__(self, data: bytes, start: int = 0, end: int | None = None):
        self.data, self.pos = data, start
        self.end = len(data) if end is None else end

    @property
    def left(self):
        return self.end - self.pos

    def take(self, size):
        if size < 0 or size > self.left:
            raise PSDInventoryError(f"extent at {self.pos} exceeds its containing section")
        at = self.pos
        self.pos += size
        return self.data[at:self.pos]

    def skip(self, size):
        if size < 0 or size > self.left:
            raise PSDInventoryError(f"extent at {self.pos} exceeds its containing section")
        self.pos += size

    def uint(self, size):
        return int.from_bytes(self.take(size), "big")

    def sint(self, size):
        return int.from_bytes(self.take(size), "big", signed=True)

    def sub(self, size):
        at = self.pos
        self.skip(size)
        return _Reader(self.data, at, self.pos)

    def pascal(self, alignment):
        count = self.uint(1)
        raw = self.take(count)
        padding = self.take(-(count + 1) % alignment)
        return raw.decode("mac_roman"), raw.hex(), padding

    def unicode(self):
        count = self.uint(4)
        if count > MAX_STRING_UNITS:
            raise PSDInventoryError("Unicode string exceeds code-unit cap")
        try:
            return self.take(count * 2).decode("utf-16-be").rstrip("\0")
        except UnicodeError as exc:
            raise PSDInventoryError("invalid UTF-16 string") from exc


class _Inventory:
    def __init__(self, data):
        self.data = data
        self.records = 0
        self.layer_total = 0
        self.result = {"sections": [], "resources": [], "layers": [], "layer_sets": [],
                       "additional_info": [], "thumbnails": [], "embedded_objects": [],
                       "slack": []}

    def budget(self):
        self.records += 1
        if self.records > MAX_RECORDS:
            raise PSDInventoryError("record count exceeds cap")

    def slack(self, reader, scope):
        if reader.left:
            self.result["slack"].append({"scope": scope, "offset": reader.pos,
                                         "length": reader.left,
                                         "preview_hex": reader.data[reader.pos:min(reader.end, reader.pos + 32)].hex()})
            reader.pos = reader.end

    def padding(self, reader, size, scope):
        body = reader.sub(size)
        if any(body.data[body.pos:body.end]):
            self.slack(body, scope)

    def section(self, reader, name, width):
        length_offset = reader.pos
        length = reader.uint(width)
        body = reader.sub(length)
        self.result["sections"].append({"name": name, "length_offset": length_offset,
                                        "offset": body.pos, "length": length, "end": body.end})
        return body

    def thumbnail(self, body, index):
        fmt, width, height, row_bytes, total, compressed = (body.uint(4) for _ in range(6))
        bits, planes = body.uint(2), body.uint(2)
        if (fmt not in (0, 1) or not width or not height or bits != 24 or planes != 1 or
                row_bytes != ((width * bits + 31) // 32) * 4 or total != row_bytes * height):
            raise PSDInventoryError("invalid thumbnail header")
        size = compressed if fmt == 1 else total
        offset = body.pos
        body.skip(size)
        self.result["thumbnails"].append({"resource_index": index, "format": "jpeg" if fmt else "raw_rgb",
                                          "width": width, "height": height, "row_bytes": row_bytes,
                                          "offset": offset, "length": size,
                                          "channel_order": "BGR" if self.result["resources"][index]["id"] == 1033 else "RGB"})
        self.slack(body, f"resource[{index}].thumbnail")

    def resources(self, reader):
        while reader.left and reader.data[reader.pos:reader.pos + 4] == b"8BIM":
            self.budget()
            start = reader.pos
            reader.take(4)
            resource_id = reader.uint(2)
            name, name_hex, padding = reader.pascal(2)
            if any(padding):
                self.slack(_Reader(reader.data, reader.pos - len(padding), reader.pos), "resource.name_padding")
            size = reader.uint(4)
            body = reader.sub(size)
            index = len(self.result["resources"])
            self.result["resources"].append({"id": resource_id, "kind": _RESOURCE_NAMES.get(resource_id, "unknown"),
                                             "name": name, "name_hex": name_hex, "record_offset": start,
                                             "offset": body.pos, "length": size})
            self.padding(reader, size % 2, f"resource[{index}].data_padding")
            if resource_id in (1033, 1036):
                self.thumbnail(body, index)
        self.slack(reader, "image_resources")

    def linked(self, reader, key, scope):
        while reader.left >= 8:
            self.budget()
            start = reader.pos
            size = reader.uint(8)
            body = reader.sub(size)
            kind = body.take(4).decode("latin-1")
            version = body.uint(4)
            if kind not in ("liFD", "liFE", "liFA") or not 1 <= version <= 8:
                raise PSDInventoryError("unsupported linked-layer record")
            uid, _, _ = body.pascal(1)
            filename = body.unicode()
            filetype, creator = body.take(4).decode("latin-1"), body.take(4).decode("latin-1")
            data_size, has_descriptor = body.uint(8), body.uint(1)
            if has_descriptor not in (0, 1):
                raise PSDInventoryError("invalid linked-layer descriptor flag")
            item = {"key": key, "scope": scope, "record_offset": start, "record_length": size + 8,
                    "kind": kind, "version": version, "uuid": uid, "filename": filename,
                    "filetype": filetype, "creator": creator, "declared_data_length": data_size,
                    "status": "opaque_descriptor" if has_descriptor or kind == "liFE" else "metadata_only"}
            if not has_descriptor and kind == "liFD":
                item.update(offset=body.pos, length=data_size, status="embedded")
                body.skip(data_size)
                if version >= 5:
                    item["child_id"] = body.unicode()
                if version >= 6:
                    body.skip(8)  # Asset modification time: inventory only.
                if version >= 7:
                    body.skip(1)
                if version >= 8:
                    item["trailing_descriptor"] = {"offset": body.pos, "length": body.left}
                    body.pos = body.end
            elif not has_descriptor and kind == "liFA":
                body.skip(8)
            if item["status"] == "opaque_descriptor":
                item["opaque"] = {"offset": body.pos, "length": body.left}
                body.pos = body.end
            self.result["embedded_objects"].append(item)
            self.slack(body, f"{scope}.{key}.linked_record")
            self.padding(reader, -size % 4, f"{scope}.{key}.record_padding")
        self.slack(reader, f"{scope}.{key}")

    def tagged(self, reader, scope, alignment, allow_layers=False):
        out = []
        while reader.left and reader.data[reader.pos:reader.pos + 4] in (b"8BIM", b"8B64"):
            self.budget()
            start = reader.pos
            signature, key_raw = reader.take(4), reader.take(4)
            key = key_raw.decode("latin-1")
            width = 8 if self.version == 2 and key_raw in _BIG_KEYS else 4
            size = reader.uint(width)
            body = reader.sub(size)
            item = {"key": key, "signature": signature.decode("ascii"), "record_offset": start,
                    "offset": body.pos, "length": size, "length_width": width}
            self.padding(reader, -size % alignment, f"{scope}.{key}.padding")
            if key_raw == b"luni":
                item["name"] = body.unicode()
                self.slack(body, f"{scope}.luni")
            elif key_raw == b"lyid":
                item["layer_id"] = body.uint(4)
                self.slack(body, f"{scope}.lyid")
            elif key_raw in (b"lsct", b"lsdk"):
                item["divider_type"] = body.uint(4)
            elif key_raw in (b"lnkD", b"lnk2", b"lnk3", b"lnkE"):
                self.linked(body, key, scope)
            elif allow_layers and key_raw in (b"Layr", b"Lr16", b"Lr32"):
                self.layer_info(body, key)
            elif key_raw in (b"SoLd", b"SoLE", b"PlLd", b"plLd"):
                item["kind"] = "placed_object_descriptor"
            out.append(item)
        self.slack(reader, scope)
        return out

    def layer_info(self, reader, source):
        signed_count = reader.sint(2)
        count = abs(signed_count)
        self.layer_total += count
        if self.layer_total > MAX_LAYERS:
            raise PSDInventoryError("layer count exceeds cap")
        layer_set = {"source": source, "count": count, "merged_transparency": signed_count < 0,
                     "layers": []}
        self.result["layer_sets"].append(layer_set)
        for index in range(count):
            self.budget()
            start = reader.pos
            bounds = [reader.sint(4) for _ in range(4)]
            if bounds[2] < bounds[0] or bounds[3] < bounds[1]:
                raise PSDInventoryError("inverted layer rectangle")
            channel_count = reader.uint(2)
            if channel_count > 56:
                raise PSDInventoryError("layer channel count exceeds cap")
            channels = [{"id": reader.sint(2), "length": reader.uint(self.length_width)}
                        for _ in range(channel_count)]
            if reader.take(4) != b"8BIM":
                raise PSDInventoryError("invalid layer blend signature")
            blend = reader.take(4).decode("latin-1")
            opacity, clipping, flags, filler = (reader.uint(1) for _ in range(4))
            if clipping not in (0, 1) or filler:
                raise PSDInventoryError("invalid layer clipping/filler")
            extra = reader.sub(reader.uint(4))
            mask = extra.sub(extra.uint(4))
            mask_info = {"offset": mask.pos, "length": mask.left}
            if mask.left:
                mask_info.update(bounds=[mask.sint(4) for _ in range(4)],
                                 default_color=mask.uint(1), flags=mask.uint(1))
            ranges = extra.sub(extra.uint(4))
            pascal, name_hex, padding = extra.pascal(4)
            if any(padding):
                self.slack(_Reader(extra.data, extra.pos - len(padding), extra.pos), f"{source}.layer[{index}].name_padding")
            tags = self.tagged(extra, f"{source}.layer[{index}].extra", 1)
            unicode_names = [tag["name"] for tag in tags if tag["key"] == "luni"]
            item = {"index": index, "record_offset": start, "bounds": bounds,
                    "channels": channels, "pascal_name": pascal, "pascal_name_hex": name_hex,
                    "unicode_name": unicode_names[-1] if unicode_names else None,
                    "name": unicode_names[-1] if unicode_names else pascal,
                    "visible": not bool(flags & 2), "opacity": opacity, "flags": flags,
                    "transparency_protected": bool(flags & 1), "clipping": clipping,
                    "blend_mode": blend, "blend_name": _BLENDS.get(blend, "unknown"),
                    "mask": mask_info, "blending_ranges": {"offset": ranges.pos, "length": ranges.left},
                    "additional_info": tags}
            layer_set["layers"].append(item)
        for layer in layer_set["layers"]:
            for channel in layer["channels"]:
                body = reader.sub(channel["length"])
                channel["offset"] = body.pos
                channel["compression"] = body.uint(2)
                if channel["compression"] > 3:
                    raise PSDInventoryError("invalid layer channel compression")
        self.slack(reader, f"{source}.layer_info")

    def composite(self, reader, header):
        start = reader.pos
        compression = reader.uint(2)
        if compression > 3:
            raise PSDInventoryError("invalid composite compression")
        image = {"offset": start, "compression": compression, "length": reader.end - start}
        if compression == 0:
            expected = ((header["width"] * header["depth"] + 7) // 8) * header["height"] * header["channels"]
            reader.skip(expected)
            image["length"] = expected + 2
            image["extent_verified"] = True
            self.slack(reader, "composite.trailing")
        elif compression == 1:
            count = header["height"] * header["channels"]
            if count > MAX_SCANLINES:
                raise PSDInventoryError("RLE scanline table exceeds cap")
            rows = reader.sub(count * self.length_width // 2)
            total = sum(rows.uint(self.length_width // 2) for _ in range(count))
            reader.skip(total)
            image["length"] = reader.pos - start
            image["extent_verified"] = True
            self.slack(reader, "composite.trailing")
        else:
            image["extent_verified"] = False
            image["status"] = "opaque_zip_pixels"
        self.result["composite"] = image

    def run(self):
        reader = _Reader(self.data)
        if reader.take(4) != b"8BPS":
            raise PSDInventoryError("not a PSD/PSB signature")
        self.version = reader.uint(2)
        if self.version not in (1, 2) or reader.take(6) != b"\0" * 6:
            raise PSDInventoryError("unsupported PSD version or reserved header bytes")
        self.length_width = 4 if self.version == 1 else 8
        channels, height, width, depth, mode = (reader.uint(n) for n in (2, 4, 4, 2, 2))
        maximum = 30000 if self.version == 1 else 300000
        if not (1 <= channels <= 56 and 1 <= height <= maximum and 1 <= width <= maximum and
                depth in (1, 8, 16, 32) and mode in (0, 1, 2, 3, 4, 7, 8, 9)):
            raise PSDInventoryError("invalid PSD/PSB header dimensions or mode")
        header = {"version": self.version, "channels": channels, "height": height,
                  "width": width, "depth": depth, "color_mode": mode}
        self.result.update(format="PSD" if self.version == 1 else "PSB", header=header)
        self.result["sections"].append({"name": "file_header", "offset": 0, "length": 26, "end": 26})
        self.section(reader, "color_mode", 4)
        self.resources(self.section(reader, "image_resources", 4))
        layers = self.section(reader, "layer_and_mask", self.length_width)
        if layers.left:
            layer_info = layers.sub(layers.uint(self.length_width))
            if layer_info.left:
                self.layer_info(layer_info, "primary")
            # Some writers omit the empty global-mask field before tagged blocks.
            if layers.left >= 4 and layers.data[layers.pos:layers.pos + 4] not in (b"8BIM", b"8B64"):
                mask = layers.sub(layers.uint(4))
                self.result["global_mask"] = {"offset": mask.pos, "length": mask.left}
            self.result["additional_info"] = self.tagged(layers, "global", 4, allow_layers=True)
        chosen = next((item for item in self.result["layer_sets"] if item["source"] == {16: "Lr16", 32: "Lr32"}.get(depth)), None)
        if chosen is None:
            chosen = next((item for item in self.result["layer_sets"] if item["source"] == "primary"), None)
        self.result["layers"] = chosen["layers"] if chosen else []
        self.result["layer_count"] = len(self.result["layers"])
        self.composite(reader, header)
        composite = self.result["composite"]
        self.result["sections"].append({"name": "composite", "offset": composite["offset"],
                                        "length": composite["length"],
                                        "end": composite["offset"] + composite["length"]})
        return self.result


def inventory(data: bytes) -> dict:
    """Inventory bounded PSD/PSB bytes; raise PSDInventoryError on invalid input.

    Unknown records are inventoried by their declared extents, never executed.
    Trailing unparsed section bytes are labelled slack, not guessed as records.
    """
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        raise PSDInventoryError("input must be bytes within the 256 MiB cap")
    try:
        return _Inventory(data).run()
    except PSDInventoryError:
        raise
    except (ValueError, TypeError, IndexError, KeyError, OverflowError, RecursionError, MemoryError) as exc:
        raise PSDInventoryError(f"invalid PSD/PSB structure: {type(exc).__name__}") from exc


def _read_file(path):
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(MAX_BYTES + 1)
    except (OSError, ValueError, TypeError, OverflowError) as exc:
        raise PSDInventoryError("cannot read input file") from exc
    if len(data) > MAX_BYTES:
        raise PSDInventoryError("input exceeds 256 MiB cap")
    return data


def inventory_file(path) -> dict:
    """Read a bounded local file and inventory it; no network or rendering."""
    return inventory(_read_file(path))


def extract_payload(data: bytes, kind: str, index: int = 0) -> bytes:
    """Return one validated resource/thumbnail/embedded payload by inventory index."""
    if kind not in ("resource", "thumbnail", "embedded") or type(index) is not int or index < 0:
        raise PSDInventoryError("invalid extraction kind or index")
    report = inventory(data)
    items = report[{"resource": "resources", "thumbnail": "thumbnails", "embedded": "embedded_objects"}[kind]]
    if index >= len(items) or "offset" not in items[index]:
        raise PSDInventoryError("payload index unavailable or object has an opaque descriptor")
    item = items[index]
    return data[item["offset"]:item["offset"] + item["length"]]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="local PSD/PSB file")
    parser.add_argument("--extract", choices=("resource", "thumbnail", "embedded"))
    parser.add_argument("--index", type=int, default=0)
    parser.add_argument("--output", help="explicit destination for extracted bytes")
    try:
        args = parser.parse_args(argv)
        if bool(args.extract) != bool(args.output):
            raise PSDInventoryError("--extract and --output must be supplied together")
        data = _read_file(args.input)
        if args.extract:
            payload = extract_payload(data, args.extract, args.index)
            try:
                Path(args.output).write_bytes(payload)
            except (OSError, ValueError, TypeError) as exc:
                raise PSDInventoryError("cannot write extraction destination") from exc
            print(json.dumps({"kind": args.extract, "index": args.index, "length": len(payload)}))
        else:
            print(json.dumps(inventory(data), ensure_ascii=True, indent=2))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except PSDInventoryError as exc:
        print(f"ff_psd_inventory: {exc}", file=sys.stderr)
        return 2
    except (OSError, TypeError, ValueError, OverflowError) as exc:
        print(f"ff_psd_inventory: invalid CLI argument or output ({type(exc).__name__})", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
