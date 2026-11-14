#!/usr/bin/env python3
"""Bounded offline profiler for embedded Frida Gadget and Objection artifacts.

This module inspects caller-supplied bytes only.  It never starts Frida, imports a
mobile package, executes JavaScript, opens a socket, extracts an archive, or invokes
another program.  It complements the repository's native-marker detectors and hook
generator by answering a different question: *what static instrumentation artifacts
are present, and what would a valid Gadget configuration do?*

The public entry points are ``parse_gadget_config()``, ``profile_script()``,
``inspect_files()``, and ``inspect_archive()``.  Malformed or oversized input raises
only :class:`Mobile2InstrumentationError`.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import lzma
import math
import re
import struct
import sys
import zipfile
import zlib
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


class Mobile2InstrumentationError(ValueError):
    """A supplied instrumentation artifact is malformed or outside parser limits."""


MAX_INPUT = 256 << 20
MAX_ARCHIVE_MEMBERS = 32_768
MAX_ARCHIVE_EXPANDED = 512 << 20
MAX_MEMBER = 8 << 20
MAX_SCANNED_TOTAL = 48 << 20
MAX_CONFIG = 2 << 20
MAX_SCRIPT = 4 << 20
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 20_000
MAX_JSON_STRING = 1 << 16
MAX_HITS = 32

_GADGET_LIBRARIES = {
    "fridagadget.dylib": "ios-frida-gadget",
    "libgadget.so": "android-frida-gadget",
    # Objection uses this name by default, but the name alone does not prove
    # Objection performed the patch.
    "libfrida-gadget.so": "android-frida-gadget-objection-default-name",
}
_GADGET_CONFIGS = {
    "fridagadget.config": "ios-gadget-config",
    "libgadget.config.so": "android-gadget-config",
    "libfrida-gadget.config.so": "android-gadget-config-objection-default-name",
}
_GADGET_SCRIPTS = {
    "libfrida-gadget.script.so": "android-embedded-script-objection-default-name",
}
_TEXT_SUFFIXES = (".js", ".smali", ".java", ".kt", ".xml", ".json", ".config", ".txt")

_SCRIPT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("java-perform", re.compile(r"\bJava\.perform\s*\(")),
    ("java-use", re.compile(r"\bJava\.use\s*\(")),
    ("java-implementation", re.compile(r"\.implementation\s*=")),
    ("interceptor-attach", re.compile(r"\bInterceptor\.attach\s*\(")),
    ("interceptor-replace", re.compile(r"\bInterceptor\.replace\s*\(")),
    ("module-lookup", re.compile(r"\b(?:Process\.getModuleByName|Module\.get(?:Global)?ExportByName)\s*\(")),
    ("objc-classes", re.compile(r"\bObjC\.classes\b")),
    ("objc-implement", re.compile(r"\bObjC\.implement\s*\(")),
    ("rpc-exports", re.compile(r"\brpc\.exports\b")),
    ("frida-send", re.compile(r"\bsend\s*\(")),
)


def _fail(message: str, exc: BaseException | None = None) -> Mobile2InstrumentationError:
    error = Mobile2InstrumentationError(message)
    if exc is not None:
        error.__cause__ = exc
    return error


def _bounded_bytes(data: object, *, limit: int, label: str) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise Mobile2InstrumentationError(f"{label} must be bytes")
    try:
        raw = bytes(data)
    except (ValueError, TypeError, BufferError, MemoryError, OverflowError) as exc:
        raise _fail(f"{label} cannot be converted to bounded bytes", exc)
    if len(raw) > limit:
        raise Mobile2InstrumentationError(f"{label} exceeds {limit}-byte cap")
    return raw


def _json_budget(value: Any, *, depth: int = 0, budget: list[int] | None = None) -> None:
    if budget is None:
        budget = [MAX_JSON_NODES]
    if depth > MAX_JSON_DEPTH:
        raise Mobile2InstrumentationError("Gadget JSON nesting exceeds cap")
    budget[0] -= 1
    if budget[0] < 0:
        raise Mobile2InstrumentationError("Gadget JSON node count exceeds cap")
    if isinstance(value, str):
        if len(value) > MAX_JSON_STRING:
            raise Mobile2InstrumentationError("Gadget JSON string exceeds cap")
    elif isinstance(value, list):
        for child in value:
            _json_budget(child, depth=depth + 1, budget=budget)
    elif isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > 256:
                raise Mobile2InstrumentationError("Gadget JSON key is invalid or oversized")
            _json_budget(child, depth=depth + 1, budget=budget)
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise Mobile2InstrumentationError("Gadget JSON contains an unsupported value")
    elif isinstance(value, float) and not math.isfinite(value):
        raise Mobile2InstrumentationError("Gadget JSON contains a non-finite number")


def _string(mapping: Mapping[str, Any], key: str, *, default: str | None = None,
            required: bool = False, maximum: int = 4096) -> str | None:
    value = mapping.get(key, default)
    if value is None and not required:
        return None
    if not isinstance(value, str) or (required and not value) or len(value) > maximum:
        raise Mobile2InstrumentationError(f"Gadget {key!r} must be a bounded string")
    return value


def _enum(mapping: Mapping[str, Any], key: str, allowed: set[str], default: str) -> str:
    value = mapping.get(key, default)
    if not isinstance(value, str) or value not in allowed:
        choices = ", ".join(sorted(allowed))
        raise Mobile2InstrumentationError(f"Gadget {key!r} must be one of: {choices}")
    return value


def _port(mapping: Mapping[str, Any], default: int) -> int:
    value = mapping.get("port", default)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65_535:
        raise Mobile2InstrumentationError("Gadget 'port' must be an integer from 1 to 65535")
    return value


def _unknown(mapping: Mapping[str, Any], known: set[str]) -> list[str]:
    return sorted(key for key in mapping if key not in known)


def parse_gadget_config(data: bytes) -> dict[str, Any]:
    """Parse and validate Frida Gadget JSON, returning effective offline semantics.

    Authentication tokens and certificate contents are deliberately not reproduced;
    the report records only whether each is configured.
    """
    raw = _bounded_bytes(data, limit=MAX_CONFIG, label="Gadget config")

    def object_from_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, child in pairs:
            if key in result:
                raise Mobile2InstrumentationError(f"Gadget JSON repeats key {key!r}")
            result[key] = child
        return result

    def reject_constant(token: str) -> None:
        raise Mobile2InstrumentationError(f"Gadget JSON contains invalid number {token}")

    try:
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=object_from_pairs, parse_constant=reject_constant)
    except Mobile2InstrumentationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, OverflowError,
            RecursionError, MemoryError) as exc:
        raise _fail("Gadget config is not bounded UTF-8 JSON", exc)
    if not isinstance(value, dict):
        raise Mobile2InstrumentationError("Gadget config root must be an object")
    _json_budget(value)

    teardown = _enum(value, "teardown", {"minimal", "full"}, "minimal")
    runtime = _enum(value, "runtime", {"default", "qjs", "v8"}, "default")
    code_signing = _enum(value, "code_signing", {"optional", "required"}, "optional")
    defaulted = [key for key in ("teardown", "runtime", "code_signing") if key not in value]
    root_unknown = _unknown(value, {"interaction", "teardown", "runtime", "code_signing"})

    supplied = "interaction" in value
    interaction = value.get("interaction", {"type": "listen"})
    if not isinstance(interaction, dict):
        raise Mobile2InstrumentationError("Gadget 'interaction' must be an object")
    if supplied and "type" not in interaction:
        raise Mobile2InstrumentationError("Gadget interaction object is missing 'type'")
    kind = interaction.get("type", "listen")
    if not isinstance(kind, str) or kind not in {"listen", "connect", "script", "script-directory"}:
        raise Mobile2InstrumentationError("unsupported Gadget interaction type")

    effective: dict[str, Any] = {"type": kind}
    behavior: dict[str, Any]
    if kind == "listen":
        known = {"type", "address", "port", "certificate", "token", "on_port_conflict",
                 "on_load", "origin", "asset_root"}
        address = _string(interaction, "address", default="127.0.0.1", required=True, maximum=1024)
        port = _port(interaction, 27042)
        conflict = _enum(interaction, "on_port_conflict", {"fail", "pick-next"}, "fail")
        on_load = _enum(interaction, "on_load", {"resume", "wait"}, "wait")
        certificate = _string(interaction, "certificate", maximum=MAX_JSON_STRING)
        token = _string(interaction, "token", maximum=MAX_JSON_STRING)
        origin = _string(interaction, "origin", maximum=4096)
        asset_root = _string(interaction, "asset_root", maximum=4096)
        defaulted.extend(f"interaction.{key}" for key in (
            "address", "port", "on_port_conflict", "on_load") if key not in interaction)
        effective.update({"address": address, "port": port, "on_port_conflict": conflict,
                          "on_load": on_load, "tls_configured": certificate is not None,
                          "authentication_configured": token is not None,
                          "origin_restricted": origin is not None,
                          "serves_asset_root": asset_root is not None})
        exposure = "loopback" if address in {"127.0.0.1", "::1", "localhost"} else "non-loopback-or-named"
        behavior = {"network": "listen", "endpoint": f"{address}:{port}",
                    "exposure": exposure, "blocks_on_load": on_load == "wait",
                    "runtime_activation": "unverified"}
    elif kind == "connect":
        known = {"type", "address", "port", "certificate", "token", "acl"}
        address = _string(interaction, "address", default="127.0.0.1", required=True, maximum=1024)
        port = _port(interaction, 27052)
        certificate = _string(interaction, "certificate", maximum=MAX_JSON_STRING)
        token = _string(interaction, "token", maximum=MAX_JSON_STRING)
        acl = interaction.get("acl", [])
        if (not isinstance(acl, list) or len(acl) > 256
                or any(not isinstance(item, str) or not item or len(item) > 1024 for item in acl)):
            raise Mobile2InstrumentationError("Gadget 'acl' must be a bounded string array")
        defaulted.extend(f"interaction.{key}" for key in ("address", "port") if key not in interaction)
        effective.update({"address": address, "port": port,
                          "tls_configured": certificate is not None,
                          "authentication_configured": token is not None,
                          "acl": list(acl)})
        behavior = {"network": "outbound-connect", "endpoint": f"{address}:{port}",
                    "destination_role": "frida-portal cluster interface",
                    "runtime_activation": "unverified"}
    elif kind == "script":
        known = {"type", "path", "parameters", "on_change"}
        path = _string(interaction, "path", required=True)
        on_change = _enum(interaction, "on_change", {"ignore", "reload"}, "ignore")
        parameters = interaction.get("parameters", {})
        if not isinstance(parameters, dict):
            raise Mobile2InstrumentationError("Gadget script parameters must be an object")
        defaulted.extend(f"interaction.{key}" for key in ("parameters", "on_change") if key not in interaction)
        effective.update({"path": path, "parameters": parameters, "on_change": on_change})
        behavior = {"network": "none-by-interaction", "loads_script": path,
                    "reloads_on_change": on_change == "reload", "runs_before_entrypoint": True,
                    "runtime_activation": "unverified"}
    else:
        known = {"type", "path", "on_change"}
        path = _string(interaction, "path", required=True)
        on_change = _enum(interaction, "on_change", {"ignore", "rescan"}, "ignore")
        if "on_change" not in interaction:
            defaulted.append("interaction.on_change")
        effective.update({"path": path, "on_change": on_change})
        behavior = {"network": "none-by-interaction", "loads_script_directory": path,
                    "rescans_on_change": on_change == "rescan",
                    "runtime_activation": "unverified"}
    effective["unknown_keys"] = _unknown(interaction, known)
    return {
        "valid": True,
        "default_interaction_used": not supplied,
        "defaults_used": bool(defaulted),
        "defaulted_fields": sorted(defaulted),
        "teardown": teardown,
        "runtime": runtime,
        "code_signing": code_signing,
        "interceptor_api_configured_available": code_signing != "required",
        "recognized_schema_complete": not root_unknown and not effective["unknown_keys"],
        "unknown_root_keys": root_unknown,
        "interaction": effective,
        "behavior": behavior,
    }


def profile_script(data: bytes, *, path: str | None = None) -> dict[str, Any]:
    """Inventory static Frida-JavaScript API fingerprints without running source."""
    if path is not None and (not isinstance(path, str) or len(path) > 16_384):
        raise Mobile2InstrumentationError("script path must be a bounded string")
    raw = _bounded_bytes(data, limit=MAX_SCRIPT, label="instrumentation script")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _fail("instrumentation script is not UTF-8 text", exc)
    hits = []
    for name, pattern in _SCRIPT_PATTERNS:
        positions, count = [], 0
        for match in pattern.finditer(text):
            count += 1
            if len(positions) < MAX_HITS:
                positions.append(match.start())
        if count:
            hits.append({"api": name, "count": count, "offsets": positions,
                         "offsets_truncated": count > MAX_HITS})
    apis = {item["api"] for item in hits}
    platform = []
    if apis & {"java-perform", "java-use", "java-implementation"}:
        platform.append("android-java")
    if apis & {"objc-classes", "objc-implement"}:
        platform.append("apple-objc")
    if apis & {"interceptor-attach", "interceptor-replace", "module-lookup"}:
        platform.append("native")
    likely = len(apis) >= 2 and bool(apis & {
        "java-perform", "java-use", "java-implementation", "interceptor-attach",
        "interceptor-replace", "module-lookup", "objc-classes", "objc-implement", "rpc-exports",
    })
    return {"path": path, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "utf8": True, "fingerprints": hits, "likely_frida_script": likely,
            "platform_hints": platform, "runtime_activation": "unverified"}


def _safe_name(name: object) -> str:
    if not isinstance(name, str) or not name or "\x00" in name:
        raise Mobile2InstrumentationError("archive/member path is invalid")
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise Mobile2InstrumentationError("absolute archive/member path is not allowed")
    parts = tuple(part for part in path.parts if part not in ("", "."))
    if not parts or ".." in parts:
        raise Mobile2InstrumentationError("traversal archive/member path is not allowed")
    result = "/".join(parts)
    if len(result) > 16_384:
        raise Mobile2InstrumentationError("archive/member path exceeds cap")
    return result


def _role(path: str) -> tuple[str, str] | None:
    base = path.rsplit("/", 1)[-1].lower()
    if base in _GADGET_LIBRARIES:
        return "library", _GADGET_LIBRARIES[base]
    if base in _GADGET_CONFIGS:
        return "config", _GADGET_CONFIGS[base]
    if base in _GADGET_SCRIPTS:
        return "script", _GADGET_SCRIPTS[base]
    if base == "objection.jks":
        return "objection", "objection-signing-keystore"
    if base == "network_security_config.xml":
        return "objection-weak", "network-security-config"
    return None


def _is_scannable(path: str, role: tuple[str, str] | None) -> bool:
    lower = path.lower()
    return role is not None or lower.endswith(_TEXT_SUFFIXES) or lower.endswith("classes.dex")


def _add_evidence(items: list[dict[str, Any]], seen: set[tuple[str, str]],
                  kind: str, value: str, weight: int, *, path: str | None = None) -> None:
    key = (kind, value if path is None else f"{path}\0{value}")
    if key in seen:
        return
    seen.add(key)
    item: dict[str, Any] = {"kind": kind, "value": value, "weight": weight}
    if path is not None:
        item["path"] = path
    items.append(item)


def _profile_entries(entries: Mapping[str, bytes | None], *, container_name: str | None) -> dict[str, Any]:
    if container_name is not None and (not isinstance(container_name, str) or len(container_name) > 16_384):
        raise Mobile2InstrumentationError("container name must be a bounded string")
    paths = sorted(entries)
    evidence: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    libraries, configs, scripts, objection = [], [], [], []
    text_entries: list[tuple[str, bytes]] = []

    container_base = (container_name or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
    if container_base.endswith((".objection.apk", ".aligned.objection.apk")) or container_base.endswith(".apktemp"):
        _add_evidence(evidence, seen, "objection-output-name", container_base, 35)

    for path in paths:
        body = entries[path]
        role = _role(path)
        if role is not None:
            category, detail = role
            if category == "library":
                libraries.append({"path": path, "role": detail})
                _add_evidence(evidence, seen, "gadget-library-path", detail, 40, path=path)
            elif category == "config":
                item: dict[str, Any] = {"path": path, "role": detail}
                if body is None:
                    item["error"] = "content not scanned"
                else:
                    try:
                        item["report"] = parse_gadget_config(body)
                        _add_evidence(evidence, seen, "valid-gadget-config", detail, 30, path=path)
                    except Mobile2InstrumentationError as exc:
                        item["error"] = str(exc)
                        _add_evidence(evidence, seen, "gadget-config-name", detail, 8, path=path)
                configs.append(item)
            elif category == "script":
                item = {"path": path, "role": detail}
                if body is None:
                    item["error"] = "content not scanned"
                else:
                    try:
                        item["report"] = profile_script(body, path=path)
                        weight = 30 if item["report"]["likely_frida_script"] else 8
                        _add_evidence(evidence, seen, "embedded-script", detail, weight, path=path)
                    except Mobile2InstrumentationError as exc:
                        item["error"] = str(exc)
                scripts.append(item)
            elif category == "objection":
                objection.append({"path": path, "role": detail})
                _add_evidence(evidence, seen, "objection-artifact", detail, 35, path=path)
            else:
                objection.append({"path": path, "role": detail, "strength": "weak"})
                _add_evidence(evidence, seen, "weak-patch-artifact", detail, 3, path=path)
        if body is not None and _is_scannable(path, role):
            text_entries.append((path, body))

    # Generic .js files are not evidence by name; their API combinations are.
    known_script_paths = {item["path"] for item in scripts}
    for path, body in text_entries:
        if path in known_script_paths or not path.lower().endswith(".js"):
            continue
        try:
            report = profile_script(body, path=path)
        except Mobile2InstrumentationError:
            continue
        if report["likely_frida_script"]:
            scripts.append({"path": path, "role": "frida-api-script", "report": report})
            _add_evidence(evidence, seen, "frida-js-api-combination", "multiple Frida APIs", 28, path=path)

    load_paths = []
    for path, body in text_entries:
        lower = body.lower()
        if b"objection patchapk" in lower or b"objection patchipa" in lower:
            _add_evidence(evidence, seen, "objection-command-string", "Objection patch command", 24,
                          path=path)
        if b"frida-gadget" not in lower and b"libfrida-gadget" not in lower:
            continue
        if (b"loadlibrary" in lower or b"system;->loadlibrary" in lower
                or b"system.loadlibrary" in lower):
            load_paths.append(path)
            _add_evidence(evidence, seen, "gadget-load-library", "Frida Gadget loadLibrary reference", 22,
                          path=path)

    correlations = []
    if libraries and configs:
        correlations.append({"kind": "library-plus-config", "libraries": [x["path"] for x in libraries],
                             "configs": [x["path"] for x in configs]})
        _add_evidence(evidence, seen, "correlation", "Gadget library and config coexist", 20)
    valid_scripts = [item for item in scripts if isinstance(item.get("report"), dict)]
    if libraries and valid_scripts:
        correlations.append({"kind": "library-plus-script", "libraries": [x["path"] for x in libraries],
                             "scripts": [x["path"] for x in valid_scripts]})
        _add_evidence(evidence, seen, "correlation", "Gadget library and Frida script coexist", 18)
    if libraries and load_paths:
        correlations.append({"kind": "library-plus-load-reference", "load_references": load_paths})
        _add_evidence(evidence, seen, "correlation", "Gadget library and load reference coexist", 15)
    objection_strong = any(item.get("role") == "objection-signing-keystore" for item in objection)
    if libraries and (objection_strong or container_base.endswith((".objection.apk", ".aligned.objection.apk"))):
        correlations.append({"kind": "objection-patch-correlation"})
        _add_evidence(evidence, seen, "correlation", "Objection artifact and Gadget library coexist", 18)

    behavior = []
    for item in configs:
        report = item.get("report")
        if isinstance(report, dict):
            behavior.append({"path": item["path"], **report["behavior"]})
    score = min(100, sum(int(item["weight"]) for item in evidence))
    confidence = "high" if score >= 70 else "medium" if score >= 40 else "low" if score else "none"
    evidence.sort(key=lambda item: (-item["weight"], item["kind"], item.get("path", "")))
    return {
        "format": "frida-objection-static-profile-v1",
        "container_name": container_name,
        "member_count": len(paths),
        "libraries": libraries,
        "configs": configs,
        "scripts": scripts,
        "objection_artifacts": objection,
        "correlations": correlations,
        "behavior": behavior,
        "score": score,
        "confidence": confidence,
        "evidence": evidence,
        "runtime_activation": "unverified; static artifacts do not prove the Gadget was loaded",
    }


def inspect_files(files: Mapping[str, bytes], *, container_name: str | None = None) -> dict[str, Any]:
    """Profile a caller-supplied path-to-bytes mapping without executing contents."""
    if not isinstance(files, Mapping):
        raise Mobile2InstrumentationError("files must be a path-to-bytes mapping")
    entries: dict[str, bytes | None] = {}
    total = 0
    try:
        if len(files) > MAX_ARCHIVE_MEMBERS:
            raise Mobile2InstrumentationError("file count exceeds cap")
        for original, value in files.items():
            path = _safe_name(original)
            if path in entries:
                raise Mobile2InstrumentationError("duplicate normalized file path")
            body = _bounded_bytes(value, limit=MAX_MEMBER, label=f"member {path}")
            total += len(body)
            if total > MAX_SCANNED_TOTAL:
                raise Mobile2InstrumentationError("supplied scanned content exceeds cap")
            entries[path] = body
        return _profile_entries(entries, container_name=container_name)
    except Mobile2InstrumentationError:
        raise
    except (MemoryError, RecursionError, UnicodeError, ValueError, TypeError, OverflowError,
            KeyError, IndexError, AttributeError, BufferError) as exc:
        raise _fail("could not profile supplied instrumentation files", exc)


def inspect_archive(data: bytes, *, container_name: str | None = None) -> dict[str, Any]:
    """Profile a ZIP/APK/IPA in memory; members are never written or executed."""
    raw = _bounded_bytes(data, limit=MAX_INPUT, label="archive")
    entries: dict[str, bytes | None] = {}
    scanned = 0
    expanded = 0
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_MEMBERS:
                raise Mobile2InstrumentationError("archive member count exceeds cap")
            for info in infos:
                if info.is_dir():
                    continue
                path = _safe_name(info.filename)
                if path in entries:
                    raise Mobile2InstrumentationError("archive has duplicate normalized paths")
                if info.file_size < 0 or info.compress_size < 0:
                    raise Mobile2InstrumentationError("archive member has invalid size")
                expanded += info.file_size
                if expanded > MAX_ARCHIVE_EXPANDED:
                    raise Mobile2InstrumentationError("archive expanded size exceeds cap")
                role = _role(path)
                should_read = _is_scannable(path, role) and info.file_size <= MAX_MEMBER
                body: bytes | None = None
                if should_read:
                    if scanned + info.file_size > MAX_SCANNED_TOTAL:
                        raise Mobile2InstrumentationError("archive scanned-content cap exceeded")
                    with archive.open(info) as handle:
                        body = handle.read(info.file_size + 1)
                    if len(body) != info.file_size:
                        raise Mobile2InstrumentationError("archive member size mismatch")
                    scanned += len(body)
                entries[path] = body
        return _profile_entries(entries, container_name=container_name)
    except Mobile2InstrumentationError:
        raise
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, EOFError, RuntimeError,
            NotImplementedError, UnicodeError, ValueError, TypeError, OverflowError,
            MemoryError, RecursionError, struct.error, zlib.error, lzma.LZMAError,
            KeyError, IndexError, AttributeError, BufferError) as exc:
        raise _fail("archive is not a bounded readable ZIP", exc)


def _read_file(path: str | Path, limit: int = MAX_INPUT) -> bytes:
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(limit + 1)
    except (OSError, ValueError, TypeError, OverflowError) as exc:
        raise _fail("could not read artifact", exc)
    if len(data) > limit:
        raise Mobile2InstrumentationError("artifact exceeds file-size cap")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", help="Gadget config, Frida script, APK/IPA, or ZIP")
    parser.add_argument("--kind", choices=("auto", "config", "script", "archive"), default="auto")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        data = _read_file(args.artifact)
        kind = args.kind
        if kind == "auto":
            lower = Path(args.artifact).name.lower()
            if data.startswith(b"PK"):
                kind = "archive"
            elif lower in _GADGET_CONFIGS or lower.endswith("gadget.config"):
                kind = "config"
            else:
                kind = "script"
        if kind == "archive":
            report = inspect_archive(data, container_name=Path(args.artifact).name)
        elif kind == "config":
            report = parse_gadget_config(data)
        else:
            report = profile_script(data, path=Path(args.artifact).name)
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True))
        return 0
    except Mobile2InstrumentationError as exc:
        print(f"{parser.prog}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
