"""Strict, offline document-forensics candidates over supplied bytes.

This module is intentionally a composition layer.  The repository's mature ``maldoc`` reader
understands PDF, OOXML, CFB/OLE, RTF, VBA, and XLM semantics; ``pdf_revisions`` validates PDF
xref history; and ``script-analysis/officevba.py`` supplies an independent fail-closed Office
container reader.  Here those engines are cross-checked, package/object relationships are made
explicit, and only integrity-gated payloads/findings are returned.

Nothing is rendered or executed.  There are no subprocesses, temporary files, passwords,
network requests, or implicit artifact discovery.  Every decoder consumes caller-supplied bytes
and returns ``None`` when its complete structural check does not hold.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import logging
import posixpath
import re
import struct
import sys
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Mapping
from xml.etree import ElementTree as ET

try:  # tests place solvers/toolkits directly on sys.path
    import maldoc as _maldoc
    import pdf_revisions as _pdf_revisions
except ImportError:  # package-style import
    from . import maldoc as _maldoc
    from . import pdf_revisions as _pdf_revisions


MAX_DOCUMENT = 64 * 1024 * 1024
MAX_MEMBER = 32 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED = 256 * 1024 * 1024
MAX_RATIO = 200
MAX_MEMBERS = 10_000
MAX_XML = 16 * 1024 * 1024
MAX_OBJECTS = 50_000
MAX_FINDINGS = 20_000
MAX_EMBEDDED = 2_000
MAX_MACROS = 512
MAX_MACRO_SOURCE = 8 * 1024 * 1024
MAX_RTF_DEPTH = 4_096


def _load_officevba():
    name = "_r5e_strict_officevba"
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).resolve().parent.parent / "script-analysis" / "officevba.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError("officevba reader unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_officevba = _load_officevba()


@dataclass(frozen=True)
class EmbeddedObject:
    name: str
    source: str
    media_type: str
    data: bytes
    sha256: str


@dataclass(frozen=True)
class Finding:
    kind: str
    value: str
    source: str


@dataclass(frozen=True)
class MacroArtifact:
    name: str
    language: str
    source: str
    decoded: tuple[str, ...]
    commands: tuple[str, ...]
    autoexec: tuple[str, ...]
    techniques: tuple[str, ...]


@dataclass(frozen=True)
class PdfRevision:
    index: int
    end_offset: int
    object_numbers: tuple[int, ...]


@dataclass(frozen=True)
class PdfReport:
    version: str
    revisions: tuple[PdfRevision, ...]
    object_count: int
    reference_edges: tuple[tuple[str, str], ...]
    findings: tuple[Finding, ...]
    embedded: tuple[EmbeddedObject, ...]
    cross_checks: tuple[str, ...]


@dataclass(frozen=True)
class Relationship:
    source_part: str
    rel_id: str
    rel_type: str
    target: str
    external: bool


@dataclass(frozen=True)
class OfficeReport:
    family: str
    main_part: str
    members: tuple[str, ...]
    relationships: tuple[Relationship, ...]
    macros: tuple[MacroArtifact, ...]
    findings: tuple[Finding, ...]
    embedded: tuple[EmbeddedObject, ...]
    cross_checks: tuple[str, ...]


@dataclass(frozen=True)
class OleStream:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class OleReport:
    streams: tuple[OleStream, ...]
    macros: tuple[MacroArtifact, ...]
    findings: tuple[Finding, ...]
    embedded: tuple[EmbeddedObject, ...]
    cross_checks: tuple[str, ...]


@dataclass(frozen=True)
class RtfReport:
    object_count: int
    classes: tuple[str, ...]
    findings: tuple[Finding, ...]
    embedded: tuple[EmbeddedObject, ...]


def _blob(data: object) -> bytes | None:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    raw = bytes(data)
    return raw if 0 < len(raw) <= MAX_DOCUMENT else None


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _media(data: bytes) -> str:
    if data.startswith(_maldoc.OLE_MAGIC):
        return "application/x-ole-storage"
    if data.startswith(b"PK\x03\x04"):
        return "application/zip"
    if b"%PDF-" in data[:1024]:
        return "application/pdf"
    if data.startswith(b"{\\rt"):
        return "application/rtf"
    if data.startswith(b"MZ"):
        return "application/x-dosexec"
    return "application/octet-stream"


def _embedded(name: str, source: str, data: bytes, media_type: str | None = None) -> EmbeddedObject:
    safe = str(name).replace("\x00", "")[:1024] or "embedded"
    return EmbeddedObject(safe, source[:2048], media_type or _media(data), bytes(data), _sha(data))


def _uniq(items):
    return tuple(dict.fromkeys(items))


def _xml(raw: bytes) -> ET.Element | None:
    if not raw or len(raw) > MAX_XML or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        return None
    try:
        return ET.fromstring(raw)
    except (ET.ParseError, ValueError):
        return None


def _local(tag: object) -> str:
    return str(tag).rsplit("}", 1)[-1]


# ---- macro candidates -----------------------------------------------------------------------------

_VBA_SHAPE = re.compile(
    r"(?im)^\s*(?:attribute\s+vb_name\s*=|(?:public\s+|private\s+|friend\s+|static\s+)*"
    r"(?:sub|function|property)\s+[A-Za-z_]\w*|(?:dim|const|set|let)\s+[A-Za-z_]\w*)"
)
_VBA_AUTO = re.compile(
    r"(?im)^\s*(?:public\s+|private\s+|friend\s+|static\s+)*(?:sub|function)\s+"
    r"(auto(?:open|close|exec|exit|new)|document_(?:open|close|new)|"
    r"workbook_(?:open|activate|beforeclose|close)|worksheet_activate)\b"
)
_XLM_AUTO = re.compile(r"(?i)\bauto_?(?:open|close)\b")


def decode_macro_source(source: str, *, name: str = "macro", language: str = "vba") -> MacroArtifact | None:
    """Statically deobfuscate checked VBA or XLM source text."""

    if not isinstance(source, str) or not source or len(source.encode("utf-8", "replace")) > MAX_MACRO_SOURCE \
            or "\x00" in source or not isinstance(name, str):
        return None
    lang = language.lower() if isinstance(language, str) else ""
    if lang == "vba":
        if not _VBA_SHAPE.search(source):
            return None
        autoexec = _uniq(match.group(1) for match in _VBA_AUTO.finditer(source))
        xlm = False
    elif lang == "xlm":
        lines = [line.strip() for line in source.splitlines() if line.strip()]
        if not lines or any(not (line.startswith("=") or re.match(r"^[A-Za-z]{1,3}\d+\s*=", line)) for line in lines):
            return None
        autoexec = _uniq(match.group(0) for match in _XLM_AUTO.finditer(source))
        xlm = True
    else:
        return None
    try:
        result = _maldoc.deobfuscate(source, xlm=xlm)
    except Exception:
        return None
    if not isinstance(result, Mapping) or result.get("truncated") is True:
        return None
    decoded = _uniq(str(value) for value in result.get("decoded", ()) if isinstance(value, str) and value)
    commands = _uniq(str(value) for value in result.get("commands", ()) if isinstance(value, str) and value)
    techniques = _uniq(str(value) for value in result.get("techniques", ()) if isinstance(value, str) and value)
    return MacroArtifact(name[:1024], lang, source, decoded, commands, autoexec, techniques)


# ---- PDF ------------------------------------------------------------------------------------------

def _pdf_refs(value: object, refs: set[tuple[int, int]], depth: int = 0) -> bool:
    if depth > 64:
        return False
    if isinstance(value, _maldoc.PdfRef):
        refs.add((int(value[0]), int(value[1])))
        return True
    if isinstance(value, Mapping):
        return all(_pdf_refs(item, refs, depth + 1) for item in value.values())
    if isinstance(value, (list, tuple)):
        return all(_pdf_refs(item, refs, depth + 1) for item in value)
    return True


def _pdf_string(value: object, parsed: Mapping) -> str | None:
    if isinstance(value, _maldoc.PdfRef):
        stream = _maldoc.pdf_stream(parsed, int(value[0]), int(value[1]))
        if stream is not None:
            body, complete = stream
            if not complete:
                return None
            value = body
        else:
            value = parsed["resolve"](value)
    if isinstance(value, bytes):
        return _maldoc._pdf_str(value)
    if isinstance(value, (str, _maldoc.PdfName)):
        return str(value)
    return None


def decode_pdf(data: bytes) -> PdfReport | None:
    """Return a PDF object/action/revision report only for a fully resolving xref chain."""

    raw = _blob(data)
    if raw is None or raw[:1024].find(b"%PDF-") < 0 or not raw.rstrip(b"\x00\t\r\n \x1a").endswith(b"%%EOF"):
        return None
    if not _pdf_revisions.chain_resolves(raw):
        return None
    revisions = _pdf_revisions.revisions(raw)
    if not revisions or len(revisions) > 256 or any(not item.get("valid") for item in revisions):
        return None
    try:
        parsed = _maldoc.pdf(raw)
    except Exception:
        return None
    objects = parsed.get("objects")
    if not isinstance(objects, Mapping) or not objects or len(objects) > MAX_OBJECTS or parsed.get("incomplete") \
            or parsed.get("encrypted"):
        return None
    refs_by_object: dict[tuple[int, int], set[tuple[int, int]]] = {}
    all_refs: set[tuple[int, int]] = set()
    for key, pair in objects.items():
        if not (isinstance(key, tuple) and len(key) == 2 and isinstance(pair, tuple) and len(pair) == 2):
            return None
        refs: set[tuple[int, int]] = set()
        if not _pdf_refs(pair[0], refs):
            return None
        refs_by_object[(int(key[0]), int(key[1]))] = refs
        all_refs.update(refs)
    trailer_refs: set[tuple[int, int]] = set()
    if not _pdf_refs(parsed.get("trailer", {}), trailer_refs):
        return None
    all_refs.update(trailer_refs)
    for ref in all_refs:
        # A PDF indirect reference names an exact object generation.  Object-stream members are
        # generation zero and are already materialized under that exact key by maldoc.pdf().
        if ref not in objects:
            return None
    edges = tuple(sorted(
        (f"{src[0]} {src[1]}", f"{dst[0]} {dst[1]}")
        for src, targets in refs_by_object.items() for dst in targets
    ))

    findings: list[Finding] = []
    embedded: list[EmbeddedObject] = []
    file_names: dict[tuple[int, int], str] = {}
    for key, (value, _stream) in objects.items():
        if not isinstance(value, Mapping):
            continue
        ef = parsed["resolve"](value.get("EF"))
        if isinstance(ef, Mapping):
            name = _pdf_string(value.get("UF"), parsed) or _pdf_string(value.get("F"), parsed) or "embedded"
            for ref in ef.values():
                if isinstance(ref, _maldoc.PdfRef):
                    file_names[(int(ref[0]), int(ref[1]))] = name
        action = str(parsed["resolve"](value.get("S")) or "")
        source = f"object {key[0]} {key[1]}"
        if "JS" in value:
            text = _pdf_string(value["JS"], parsed)
            if text:
                findings.append(Finding("javascript", text[:MAX_MACRO_SOURCE], source))
        if "URI" in value:
            text = _pdf_string(value["URI"], parsed)
            if text:
                findings.append(Finding("uri", text[:8192], source))
        if action in {"Launch", "GoToR", "GoToE", "SubmitForm", "ImportData"}:
            target = _pdf_string(value.get("F"), parsed)
            findings.append(Finding("action", action + ((":" + target) if target else ""), source))
        if "AA" in value:
            findings.append(Finding("additional_action", "present", source))
    for key, (value, stream) in objects.items():
        if not isinstance(value, Mapping) or value.get("Type") != "EmbeddedFile":
            continue
        if stream is None:
            return None
        decoded = _maldoc.pdf_stream(parsed, int(key[0]), int(key[1]))
        if decoded is None or not decoded[1]:
            return None
        name = file_names.get((int(key[0]), int(key[1])), f"embedded-{key[0]}")
        embedded.append(_embedded(name, f"object {key[0]} {key[1]}", decoded[0]))
        if len(embedded) > MAX_EMBEDDED:
            return None
    if len(findings) > MAX_FINDINGS:
        return None

    checks = ["maldoc", "pdf_revisions"]
    try:
        import pypdf
        logging.getLogger("pypdf").setLevel(logging.ERROR)
        reader = pypdf.PdfReader(io.BytesIO(raw), strict=True)
        expected_pages = parsed.get("pages_count")
        if isinstance(expected_pages, int) and expected_pages != len(reader.pages):
            return None
        checks.append("pypdf")
    except ImportError:
        pass
    except Exception:
        return None
    revs = tuple(PdfRevision(
        int(item["index"]), int(item["end_offset"]),
        tuple(sorted(int(number) for number in item.get("objects", {}))),
    ) for item in revisions)
    return PdfReport(
        str(parsed.get("version") or ""), revs, len(objects), edges,
        tuple(findings), tuple(embedded), tuple(checks),
    )


# ---- OOXML ----------------------------------------------------------------------------------------

_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
_CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"


def _safe_member(name: str) -> str | None:
    if not name or "\x00" in name or "\\" in name or name.startswith("/"):
        return None
    parts = PurePosixPath(name).parts
    if any(part in ("", ".", "..") for part in parts) or (parts and ":" in parts[0]):
        return None
    normalized = posixpath.normpath(name)
    return normalized if normalized == name.rstrip("/") else None


def _rels_source(name: str) -> str | None:
    if name == "_rels/.rels":
        return ""
    match = re.fullmatch(r"(.*/)?_rels/([^/]+)\.rels", name)
    if not match:
        return None
    return (match.group(1) or "") + match.group(2)


def _resolve_target(source: str, target: str) -> str | None:
    clean = target.split("#", 1)[0].replace("\\", "/")
    if not clean or "\x00" in clean:
        return None
    if clean.startswith("/"):
        resolved = posixpath.normpath(clean.lstrip("/"))
    else:
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(source), clean))
    return None if resolved == ".." or resolved.startswith("../") or resolved.startswith("/") else resolved


def _zip_package(data: bytes):
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = archive.infolist()
    except (zipfile.BadZipFile, OSError, ValueError, EOFError):
        return None
    if not infos or len(infos) > MAX_MEMBERS:
        archive.close()
        return None
    names: dict[str, zipfile.ZipInfo] = {}
    total = 0
    for info in infos:
        safe = _safe_member(info.filename)
        if safe is None:
            archive.close()
            return None
        if info.is_dir():
            continue
        if safe.casefold() in names or info.flag_bits & 1 or info.file_size > MAX_MEMBER \
                or info.file_size > MAX_RATIO * max(info.compress_size, 1):
            archive.close()
            return None
        total += info.file_size
        if total > MAX_TOTAL_UNCOMPRESSED:
            archive.close()
            return None
        names[safe.casefold()] = info
    try:
        if archive.testzip() is not None:
            archive.close()
            return None
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError, EOFError, zlib.error):
        archive.close()
        return None
    return archive, names


def decode_ooxml(data: bytes) -> OfficeReport | None:
    """Return a relationship-closed OOXML package report with checked embedded objects/macros."""

    raw = _blob(data)
    if raw is None or not raw.startswith(b"PK\x03\x04"):
        return None
    opened = _zip_package(raw)
    if opened is None:
        return None
    archive, by_lower = opened
    try:
        if "[content_types].xml" not in by_lower or "_rels/.rels" not in by_lower:
            return None

        def read(name: str) -> bytes | None:
            info = by_lower.get(name.casefold())
            if info is None:
                return None
            try:
                body = archive.read(info)
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError, EOFError, zlib.error):
                return None
            return body if len(body) == info.file_size else None

        ct_raw = read("[Content_Types].xml")
        ct_root = _xml(ct_raw or b"")
        if ct_root is None or ct_root.tag != f"{{{_CT_NS}}}Types":
            return None
        defaults: dict[str, str] = {}
        overrides: dict[str, str] = {}
        for child in ct_root:
            if child.tag == f"{{{_CT_NS}}}Default":
                ext, ctype = child.get("Extension"), child.get("ContentType")
                if ext and ctype:
                    key = ext.lower()
                    if key in defaults:
                        return None
                    defaults[key] = ctype
                else:
                    return None
            elif child.tag == f"{{{_CT_NS}}}Override":
                part, ctype = child.get("PartName"), child.get("ContentType")
                if part and ctype:
                    normalized = _resolve_target("", part)
                    if normalized is None or normalized.casefold() not in by_lower:
                        return None
                    key = normalized.casefold()
                    if key in overrides:
                        return None
                    overrides[key] = ctype
                else:
                    return None
            else:
                return None

        relationships: list[Relationship] = []
        root_office: list[Relationship] = []
        seen_rel_ids: set[tuple[str, str]] = set()
        for lower, info in sorted(by_lower.items()):
            source = _rels_source(info.filename)
            if source is None:
                continue
            if source and source.casefold() not in by_lower:
                return None
            rel_root = _xml(read(info.filename) or b"")
            if rel_root is None or rel_root.tag != f"{{{_REL_NS}}}Relationships":
                return None
            for node in rel_root:
                if node.tag != f"{{{_REL_NS}}}Relationship":
                    return None
                rid, rtype, target = node.get("Id"), node.get("Type"), node.get("Target")
                if not rid or not rtype or not target or (source, rid) in seen_rel_ids:
                    return None
                seen_rel_ids.add((source, rid))
                mode = (node.get("TargetMode") or "").strip().lower()
                if mode not in ("", "internal", "external"):
                    return None
                external = mode == "external"
                if external:
                    if "\x00" in target or len(target) > 8192:
                        return None
                    resolved = target
                else:
                    resolved = _resolve_target(source, target)
                    if resolved is None or resolved.casefold() not in by_lower:
                        return None
                relation = Relationship(source, rid, rtype.rsplit("/", 1)[-1], resolved, external)
                relationships.append(relation)
                if len(relationships) > MAX_FINDINGS:
                    return None
                if source == "" and rtype.endswith("/officeDocument") and not external:
                    root_office.append(relation)
        if len(root_office) != 1:
            return None
        main_part = root_office[0].target
        main_type = overrides.get(main_part.casefold())
        if main_type is None:
            ext = main_part.rsplit(".", 1)[-1].lower() if "." in main_part else ""
            main_type = defaults.get(ext)
        if not main_type:
            return None
        low_type = main_type.lower()
        family = (
            "word" if "wordprocessingml" in low_type or "ms-word" in low_type else
            "excel" if "spreadsheetml" in low_type or "ms-excel" in low_type else
            "powerpoint" if "presentationml" in low_type or "ms-powerpoint" in low_type else ""
        )
        if not family:
            return None
        # Every ordinary package part must be typed by either an exact Override or its extension's
        # Default.  The package manifest and relationship parts are OPC infrastructure.
        for info in by_lower.values():
            low = info.filename.casefold()
            if low == "[content_types].xml" or low.endswith(".rels"):
                continue
            extension = low.rsplit(".", 1)[-1] if "." in low.rsplit("/", 1)[-1] else ""
            if low not in overrides and (not extension or extension not in defaults):
                return None
        # A corrupt document body or macro sheet must not be hidden behind a valid ZIP central
        # directory.  Every XML package part is parsed wholly with DTD/entity rejection.
        for info in by_lower.values():
            if info.filename.lower().endswith((".xml", ".rels")):
                body = read(info.filename)
                if body is None or _xml(body) is None:
                    return None
        try:
            parsed = _maldoc.ooxml(raw)
        except Exception:
            return None
        members = tuple(sorted(info.filename for info in by_lower.values()))
        if set(parsed.get("members", ())) != set(members):
            return None

        findings: list[Finding] = []
        for relation in relationships:
            if relation.external:
                findings.append(Finding("external_relationship", relation.target, relation.source_part or "package"))
        for dde in parsed.get("dde", ()):
            findings.append(Finding("dde", str(dde), main_part))

        embedded: list[EmbeddedObject] = []
        for name in members:
            low = name.lower()
            if not re.search(r"(?:^|/)(?:embeddings|activex)/", low) or low.endswith((".xml", ".rels")):
                continue
            body = read(name)
            if body is None:
                return None
            ctype = overrides.get(low) or defaults.get(low.rsplit(".", 1)[-1] if "." in low else "")
            embedded.append(_embedded(name.rsplit("/", 1)[-1], name, body, ctype))
            if len(embedded) > MAX_EMBEDDED:
                return None

        macros: list[MacroArtifact] = []
        for index, formula in enumerate(parsed.get("macro_formulas", ()), 1):
            candidate = decode_macro_source(str(formula), name=f"xlm-{index}", language="xlm")
            if candidate is None:
                return None
            macros.append(candidate)
            if len(macros) > MAX_MACROS:
                return None
        for part, body in parsed.get("vba", ()):
            report = decode_ole(body)
            if report is None:
                return None
            macros.extend(report.macros)
            if len(macros) > MAX_MACROS:
                return None
        checks = ["zipfile", "maldoc"]
        if macros or parsed.get("vba") or parsed.get("macro_formulas"):
            try:
                strict = _officevba.macro_text(
                    {"word": "document.docm", "excel": "document.xlsm", "powerpoint": "document.pptm"}[family],
                    raw, _officevba.Clock(seconds=5.0),
                )
            except _officevba.Bad:
                return None
            if strict is None:
                return None
            checks.append("officevba")
        if len(findings) > MAX_FINDINGS:
            return None
        return OfficeReport(
            family, main_part, members, tuple(relationships), tuple(macros), tuple(findings),
            tuple(embedded), tuple(checks),
        )
    finally:
        archive.close()


# ---- CFB/OLE --------------------------------------------------------------------------------------

def _strict_cfb_streams(data: bytes):
    try:
        strict = _officevba.CFB(data, _officevba.Clock(seconds=5.0))
    except Exception:
        return None
    streams: list[tuple[str, bytes]] = []
    reachable = {0}

    def walk(storage: int, prefix: str, depth: int) -> bool:
        if depth > 128:
            return False
        try:
            children = strict.children(storage)
        except Exception:
            return False
        for index in children.values():
            if index in reachable:
                return False
            reachable.add(index)
            entry = strict.entries[index]
            path = prefix + entry["name"]
            if entry["type"] == 1:
                if not walk(index, path + "/", depth + 1):
                    return False
            elif entry["type"] == 2:
                try:
                    streams.append((path, strict.stream(index)))
                except Exception:
                    return False
            else:
                return False
        return True

    if not walk(0, "", 0):
        return None
    active = {index for index, entry in enumerate(strict.entries) if entry["type"] in (1, 2, 5)}
    if active != reachable:
        return None
    return strict, streams


def decode_ole(data: bytes) -> OleReport | None:
    """Return a complete CFB stream inventory, checked payloads, and static macro candidates."""

    raw = _blob(data)
    if raw is None or not raw.startswith(_maldoc.OLE_MAGIC):
        return None
    checked = _strict_cfb_streams(raw)
    if checked is None:
        return None
    _strict, streams = checked
    try:
        broad = _maldoc.CFB(raw)
    except Exception:
        return None
    if not broad.intact() or broad.directory_entries() != len(broad.entries):
        return None
    broad_names = {entry["path"].casefold() for entry in broad.entries if entry["type"] == "stream"}
    strict_names = {name.casefold() for name, _body in streams}
    if broad_names != strict_names:
        return None
    checks = ["officevba", "maldoc"]
    try:
        import olefile
        compound = olefile.OleFileIO(io.BytesIO(raw))
        try:
            names = {"/".join(parts).casefold() for parts in compound.listdir(streams=True, storages=False)}
            if names != strict_names:
                return None
        finally:
            compound.close()
        checks.append("olefile")
    except ImportError:
        pass
    except Exception:
        return None

    inventory = tuple(OleStream(name, len(body), _sha(body)) for name, body in streams)
    embedded: list[EmbeddedObject] = []
    findings: list[Finding] = []
    for name, body in streams:
        tail = name.rsplit("/", 1)[-1].casefold()
        if tail == "\x01ole10native":
            parsed = _maldoc.ole10native(body)
            if parsed is None or not parsed.get("data"):
                return None
            embedded.append(_embedded(parsed["filename"], name, parsed["data"]))
            if parsed.get("source_path"):
                findings.append(Finding("package_source_path", str(parsed["source_path"]), name))
            if parsed.get("temp_path"):
                findings.append(Finding("package_temp_path", str(parsed["temp_path"]), name))
        elif tail in {"package", "contents", "\x01ole"} and (
            body.startswith((_maldoc.OLE_MAGIC, b"PK\x03\x04", b"MZ"))
        ):
            embedded.append(_embedded(name, name, body))
        elif tail == "equation native":
            # The stream identifies an Equation Editor object, not exploitation.  A CVE claim
            # requires parsing and proving the vulnerable record shape, which this layer does not
            # currently do.
            findings.append(Finding("equation_stream", "present", name))
    if len(embedded) > MAX_EMBEDDED:
        return None

    macros: list[MacroArtifact] = []
    try:
        strict_macro = _officevba.macro_text("document.doc", raw, _officevba.Clock(seconds=5.0))
    except _officevba.Bad:
        return None
    try:
        project = _maldoc.vba_project(broad)
    except Exception:
        return None
    broad_modules = project.get("modules") or []
    if not isinstance(broad_modules, list) or len(broad_modules) > MAX_MACROS:
        return None
    if broad_modules and strict_macro is None:
        return None
    strict_normalized = strict_macro[0].replace("\r\n", "\n") if strict_macro is not None else ""
    for module in broad_modules:
        source = module.get("source")
        if source is None:
            return None
        if source.replace("\r\n", "\n").rstrip("\n") not in strict_normalized:
            return None
        candidate = decode_macro_source(source, name=str(module.get("name") or module.get("stream") or "module"), language="vba")
        if candidate is None:
            return None
        macros.append(candidate)
        if len(macros) > MAX_MACROS:
            return None
    if strict_macro is not None:
        strict_text, extension = strict_macro
        if not macros:
            candidate = decode_macro_source(
                strict_text, name="office-macros", language="xlm" if extension == ".xlm" else "vba"
            )
            if candidate is None:
                return None
            macros.append(candidate)
            if len(macros) > MAX_MACROS:
                return None
        checks.append("officevba-macro")
    if len(findings) > MAX_FINDINGS:
        return None
    return OleReport(inventory, tuple(macros), tuple(findings), tuple(embedded), tuple(checks))


# ---- RTF ------------------------------------------------------------------------------------------

_RTF_CONTROL = re.compile(rb"\\([A-Za-z]+)(-?\d+)? ?")


def _rtf_balanced(data: bytes) -> bool:
    if not data.startswith(b"{\\rt"):
        return False
    depth, index = 0, 0
    while index < len(data):
        byte = data[index]
        if byte == 0x7B:
            depth += 1
            if depth > MAX_RTF_DEPTH:
                return False
            index += 1
        elif byte == 0x7D:
            depth -= 1
            if depth < 0:
                return False
            index += 1
        elif byte == 0x5C:
            if data[index + 1:index + 2] in (b"{", b"}", b"\\"):
                index += 2
                continue
            match = _RTF_CONTROL.match(data, index)
            if match:
                index = match.end()
                if match.group(1).lower() == b"bin":
                    if match.group(2) is None:
                        return False
                    count = int(match.group(2))
                    if count < 0 or index + count > len(data):
                        return False
                    index += count
                continue
            index += 2
        else:
            index += 1
    return depth == 0 and data.rstrip(b"\x00\t\r\n \x1a").endswith(b"}")


def _strict_objdata(data: bytes, start: int) -> bytes | None:
    out = bytearray()
    depth, index, nibble = 0, start, None
    while index < len(data):
        byte = data[index]
        if byte == 0x7B:
            depth += 1
            index += 1
            continue
        if byte == 0x7D:
            depth -= 1
            index += 1
            if depth < 0:
                return bytes(out) if nibble is None and out else None
            continue
        if byte == 0x5C:
            match = _RTF_CONTROL.match(data, index)
            if match:
                index = match.end()
                if match.group(1).lower() == b"bin":
                    if match.group(2) is None or nibble is not None:
                        return None
                    count = int(match.group(2))
                    if count < 0 or index + count > len(data):
                        return None
                    out.extend(data[index:index + count])
                    index += count
                    continue
                # Ignoring any other control word could silently drop bytes from the object.
                return None
            # Control symbols and RTF hex escapes have byte semantics; this decoder deliberately
            # rejects them rather than returning a payload with those bytes skipped.
            return None
        if byte in b" \t\r\n":
            index += 1
            continue
        value = byte - 48 if 48 <= byte <= 57 else byte - 87 if 97 <= byte <= 102 else byte - 55 if 65 <= byte <= 70 else None
        if value is None:
            return None
        if nibble is None:
            nibble = value
        else:
            out.append((nibble << 4) | value)
            nibble = None
        if len(out) > MAX_MEMBER:
            return None
        index += 1
    return None


def decode_rtf(data: bytes) -> RtfReport | None:
    """Return RTF OLE/object candidates only after full brace/control/objdata validation."""

    raw = _blob(data)
    if raw is None or not _rtf_balanced(raw):
        return None
    markers = []
    for match in re.finditer(rb"\\objdata\b ?", raw):
        markers.append(match)
        if len(markers) > MAX_EMBEDDED:
            return None
    decoded = [_strict_objdata(raw, match.end()) for match in markers]
    if any(body is None for body in decoded):
        return None
    try:
        parsed = _maldoc.rtf_objects(raw)
    except Exception:
        return None
    if len(parsed) != len(decoded):
        return None
    findings: list[Finding] = []
    embedded: list[EmbeddedObject] = []
    classes: list[str] = []
    for index, (record, objdata) in enumerate(zip(parsed, decoded), 1):
        if record.get("raw_size") != len(objdata):
            return None
        declared_raw = record.get("declared_class")
        declared = str(declared_raw).split("{", 1)[0].strip() if declared_raw else None
        actual = record.get("class_name")
        if actual:
            classes.append(str(actual))
        if declared:
            findings.append(Finding("declared_class", str(declared), f"object {index}"))
        if actual and declared and str(actual).casefold() != str(declared).casefold():
            findings.append(Finding("class_mismatch", f"{declared} != {actual}", f"object {index}"))
        if record.get("updates"):
            findings.append(Finding("objupdate", "present", f"object {index}"))
        payload = record.get("payload")
        if isinstance(payload, bytes) and payload:
            name = str(record.get("filename") or f"object-{index}")
            embedded.append(_embedded(name, f"rtf object {index}", payload))
    if len(findings) > MAX_FINDINGS:
        return None
    return RtfReport(len(parsed), tuple(classes), tuple(findings), tuple(embedded))


__all__ = [
    "EmbeddedObject", "Finding", "MacroArtifact", "PdfRevision", "PdfReport", "Relationship",
    "OfficeReport", "OleStream", "OleReport", "RtfReport", "decode_macro_source", "decode_pdf",
    "decode_ooxml", "decode_ole", "decode_rtf",
]
