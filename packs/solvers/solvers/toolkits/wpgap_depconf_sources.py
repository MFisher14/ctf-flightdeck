#!/usr/bin/env python3
"""Offline package index/source-precedence and dependency-confusion audit.

Only caller-supplied configuration is parsed.  The module never resolves a
package, contacts a registry, reads ambient configuration/environment state,
executes a build file, or invokes a package manager.
"""
from __future__ import annotations

import argparse
import configparser
import json
import re
import sys
import tomllib
import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from functools import wraps
from pathlib import Path
from typing import Any, Callable, TypeVar
from urllib.parse import urlsplit, urlunsplit


MAX_FILES = 64
MAX_FILE = 4 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
MAX_PATH = 4096
MAX_LINE = 64 * 1024
MAX_LINES = 200_000
MAX_PACKAGES = 20_000
MAX_SOURCES = 4096
MAX_XML_NODES = 100_000
MAX_XML_DEPTH = 64
MAX_WORK = 1_000_000

ECOSYSTEMS = ("pip", "uv", "npm", "nuget", "maven", "gradle")
_PUBLIC_HOSTS = {
    "pypi.org",
    "registry.npmjs.org",
    "api.nuget.org",
    "www.nuget.org",
    "nuget.org",
    "repo.maven.apache.org",
    "repo1.maven.org",
    "dl.google.com",
    "plugins.gradle.org",
}
_SECRET = re.compile(r"(?i)(?:token|password|passwd|secret|api[_-]?key|credential|signature)")
_VARIABLE = re.compile(r"\$\{[^}]+}|\$[A-Za-z_]\w*|%[A-Za-z_]\w*%")
_PY_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")


class DepConfError(ValueError):
    """Supplied evidence is malformed, ambiguous, unsupported, or over a cap."""


_F = TypeVar("_F", bound=Callable[..., Any])


def _guard(function: _F) -> _F:
    @wraps(function)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        try:
            return function(*args, **kwargs)
        except DepConfError:
            raise
        except Exception:
            raise DepConfError("malformed dependency source configuration") from None
    return wrapped  # type: ignore[return-value]


def _normalize_python(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _normalize_name(ecosystem: str, name: str) -> str:
    value = name.strip()
    if not value or len(value) > 512 or "\x00" in value:
        raise DepConfError("invalid internal package name")
    if ecosystem in {"pip", "uv"}:
        if not _PY_NAME.fullmatch(value):
            raise DepConfError("invalid Python project name")
        return _normalize_python(value)
    if ecosystem in {"npm", "nuget"}:
        return value.lower()
    if ecosystem in {"maven", "gradle"}:
        pieces = value.split(":")
        if len(pieces) != 2 or not all(pieces) or any(len(piece) > 256 for piece in pieces):
            raise DepConfError("Maven/Gradle internal names must be group:artifact")
        return value
    raise DepConfError("unsupported ecosystem")


def _host(value: Any) -> str:
    if not isinstance(value, str):
        raise DepConfError("host classification must be text")
    result = value.strip().lower().rstrip(".")
    if not result or len(result) > 253 or any(ch in result for ch in "/:@?#\x00"):
        raise DepConfError("invalid classified host")
    return result


def _roles(internal_hosts: Sequence[str], public_hosts: Sequence[str]) -> tuple[set[str], set[str]]:
    if (isinstance(internal_hosts, (str, bytes)) or isinstance(public_hosts, (str, bytes))
            or not isinstance(internal_hosts, Sequence) or not isinstance(public_hosts, Sequence)):
        raise DepConfError("host classifications must be sequences")
    if len(internal_hosts) + len(public_hosts) > MAX_SOURCES:
        raise DepConfError("host classification count exceeds cap")
    internal = {_host(value) for value in internal_hosts}
    public = _PUBLIC_HOSTS | {_host(value) for value in public_hosts}
    if internal & public:
        raise DepConfError("a host cannot be both internal and public")
    return internal, public


def _source(identifier: str, raw: str, internal: set[str], public: set[str], **extra: Any) -> dict[str, Any]:
    if not isinstance(raw, str) or not raw.strip() or len(raw) > MAX_PATH:
        raise DepConfError("invalid package source URL")
    value = raw.strip()
    if _VARIABLE.search(value):
        return {"id": identifier, "url": "<unresolved-variable>", "host": "", "role": "unresolved", **extra}
    if value.startswith(("file:", "/", "./", "../")) or re.match(r"^[A-Za-z]:[\\/]", value):
        return {"id": identifier, "url": "<local-path>", "host": "", "role": "local", **extra}
    parts = urlsplit(value)
    if not parts.scheme or not parts.hostname:
        return {"id": identifier, "url": "<unresolved-source>", "host": "", "role": "unresolved", **extra}
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https", "git+http", "git+https", "ssh", "git+ssh"}:
        return {"id": identifier, "url": "<unsupported-scheme>", "host": "", "role": "unresolved", **extra}
    try:
        port = parts.port
    except ValueError:
        raise DepConfError("invalid package source port") from None
    hostname = parts.hostname.lower().rstrip(".")
    netloc = hostname
    if ":" in hostname and not hostname.startswith("["):
        netloc = f"[{hostname}]"
    if port is not None:
        netloc += f":{port}"
    # Only the origin is needed for precedence.  Removing the entire path also
    # prevents opaque path-carried credentials from reaching reports.
    clean = urlunsplit((scheme, netloc, "", "", ""))
    role = "internal" if hostname in internal else "public" if hostname in public else "unknown"
    return {"id": identifier, "url": clean, "host": hostname, "role": role, **extra}


def _input_files(files: Mapping[str, bytes | str]) -> dict[str, str]:
    if not isinstance(files, Mapping):
        raise DepConfError("files must be a mapping")
    if len(files) > MAX_FILES:
        raise DepConfError("file count exceeds cap")
    output: dict[str, str] = {}
    total = 0
    processed = 0
    for name, value in files.items():
        processed += 1
        if processed > MAX_FILES:
            raise DepConfError("file count exceeds cap")
        if not isinstance(name, str) or not name or len(name) > MAX_PATH or "\x00" in name:
            raise DepConfError("invalid supplied filename")
        if not isinstance(value, (bytes, str)):
            raise DepConfError("file values must be bytes or text")
        if isinstance(value, bytes):
            if len(value) > MAX_FILE:
                raise DepConfError("file exceeds size cap")
            try:
                text = value.decode("utf-8-sig")
            except UnicodeDecodeError:
                raise DepConfError("configuration is not UTF-8 text") from None
            size = len(value)
        else:
            try:
                encoded = value.encode("utf-8")
            except UnicodeError:
                raise DepConfError("configuration cannot be encoded") from None
            if len(encoded) > MAX_FILE:
                raise DepConfError("file exceeds size cap")
            text, size = value.lstrip("\ufeff"), len(encoded)
        total += size
        if total > MAX_TOTAL:
            raise DepConfError("aggregate input exceeds cap")
        lines = text.splitlines()
        if len(lines) > MAX_LINES or any(len(line) > MAX_LINE for line in lines):
            raise DepConfError("configuration line limit exceeded")
        normalized_name = name.replace("\\", "/")
        if normalized_name in output:
            raise DepConfError("duplicate normalized filenames are ambiguous")
        output[normalized_name] = text
    return dict(sorted(output.items()))


def _internal_names(value: Mapping[str, Sequence[str]] | None) -> dict[str, list[str]]:
    if value is None:
        return {ecosystem: [] for ecosystem in ECOSYSTEMS}
    if not isinstance(value, Mapping):
        raise DepConfError("internal_names must be a mapping")
    unknown = set(value) - set(ECOSYSTEMS)
    if unknown:
        raise DepConfError("unsupported ecosystem in internal_names")
    output = {ecosystem: [] for ecosystem in ECOSYSTEMS}
    processed = 0
    for ecosystem, names in value.items():
        if isinstance(names, (str, bytes)) or not isinstance(names, Sequence):
            raise DepConfError("internal package names must be sequences")
        for name in names:
            processed += 1
            if processed > MAX_PACKAGES:
                raise DepConfError("package count exceeds cap")
            if not isinstance(name, str):
                raise DepConfError("internal package name must be text")
            normalized = _normalize_name(ecosystem, name)
            if normalized not in output[ecosystem]:
                output[ecosystem].append(normalized)
    for names in output.values():
        names.sort()
    return output


def _record(ecosystem: str, name: str, outcome: str, reason: str,
            sources: Sequence[dict[str, Any]] = (), **extra: Any) -> dict[str, Any]:
    item = {
        "ecosystem": ecosystem,
        "name": name,
        "outcome": outcome,
        "reason": reason,
        "sources": list(sources),
    }
    item.update({key: value for key, value in extra.items() if value not in (None, [], {}, "")})
    return item


def _pool_outcome(ecosystem: str, name: str, sources: Sequence[dict[str, Any]], *,
                  order_matters: bool, dynamic: bool = False) -> dict[str, Any]:
    roles = [source["role"] for source in sources]
    if not sources or "unresolved" in roles:
        return _record(ecosystem, name, "indeterminate",
                       "source configuration is missing or contains an unresolved value", sources)
    if dynamic and "public" in roles and any(role != "public" for role in roles):
        return _record(ecosystem, name, "dynamic-version-race",
                       "dynamic version metadata may be combined across public and non-public sources", sources)
    if order_matters:
        first = roles[0]
        if first == "public":
            outcome = "public-first" if len(sources) > 1 else "public-routed"
            return _record(ecosystem, name, outcome, "a known-public source is the first eligible source", sources)
        if first == "internal":
            if "public" in roles[1:]:
                return _record(ecosystem, name, "public-fallback",
                               "the public source remains eligible if the internal source has no usable artifact", sources)
            if "unknown" in roles[1:]:
                return _record(ecosystem, name, "indeterminate",
                               "an unclassified fallback source remains eligible", sources)
            return _record(ecosystem, name, "protected", "only caller-classified internal/local sources are eligible", sources)
        if first == "local" and all(role in {"local", "internal"} for role in roles):
            return _record(ecosystem, name, "protected", "only local/internal sources are eligible", sources)
        return _record(ecosystem, name, "indeterminate", "the highest-priority source is unclassified", sources)
    if "public" in roles and any(role != "public" for role in roles):
        return _record(ecosystem, name, "shadowable",
                       "the resolver considers a known-public source in the same candidate set", sources)
    if roles and all(role == "public" for role in roles):
        return _record(ecosystem, name, "public-routed", "the internal name is routed only to known-public sources", sources)
    if roles and all(role in {"internal", "local"} for role in roles):
        return _record(ecosystem, name, "protected", "known-public sources are not eligible", sources)
    return _record(ecosystem, name, "indeterminate", "source trust is not classified", sources)


def _single(files: Mapping[str, str], predicate: Callable[[str], bool], label: str) -> tuple[str, str] | None:
    hits = [(name, text) for name, text in files.items() if predicate(name.lower())]
    if len(hits) > 1:
        raise DepConfError(f"multiple {label} files have ambiguous precedence")
    return hits[0] if hits else None


def _bool(value: str) -> bool:
    lowered = value.strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise DepConfError("invalid boolean configuration value")


def _requirement_name(line: str) -> tuple[str | None, str | None, bool, bool, bool]:
    """Return name, direct source, exact pin, hash presence, and marker presence."""
    clean = re.sub(r"\s+--hash(?:=|\s+)\S+", "", line).strip()
    hashed = "--hash=" in line or bool(re.search(r"\s--hash\s+", line))
    conditional = bool(re.search(r"\s;\s*[^;]+$", clean))
    match = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^]]+])?\s*@\s*(\S+)", clean)
    if match:
        return _normalize_python(match.group(1)), match.group(2), False, hashed, conditional
    match = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^]]+])?\s*(.*)$", clean)
    if not match:
        return None, None, False, hashed, conditional
    name, spec = _normalize_python(match.group(1)), match.group(2)
    return name, None, bool(re.search(r"(?:===|==)\s*[^,;\s]+", spec)), hashed, conditional


def _pip(files: Mapping[str, str], names: Sequence[str], internal: set[str], public: set[str]) -> tuple[list[dict], list[dict]]:
    conf_hit = _single(files, lambda n: n.rsplit("/", 1)[-1] in {"pip.conf", "pip.ini"}, "pip config")
    effective: dict[str, str] = {}
    if conf_hit:
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        try:
            parser.read_string(conf_hit[1])
        except configparser.Error:
            raise DepConfError("malformed pip configuration") from None
        sections: dict[str, dict[str, str]] = {}
        for section in parser.sections():
            values: dict[str, str] = {}
            for key, value in parser.items(section):
                values[key.lower().replace("_", "-")] = value
            sections[section.lower()] = values
        effective.update(sections.get("global", {}))
        effective.update(sections.get("install", {}))
    index_url = effective.get("index-url", "https://pypi.org/simple")
    extras = effective.get("extra-index-url", "").split()
    find_links = effective.get("find-links", "").split()
    no_index = _bool(effective["no-index"]) if "no-index" in effective else False
    require_hashes = _bool(effective["require-hashes"]) if "require-hashes" in effective else False
    requirements: dict[str, dict[str, Any]] = {}
    clues: list[dict] = []
    unresolved_include = False
    requirement_files = [
        (filename, text) for filename, text in files.items()
        if (base := filename.lower().rsplit("/", 1)[-1]).startswith("requirements")
        and base.endswith((".txt", ".in"))
    ]
    if len(requirement_files) > 1:
        raise DepConfError("multiple root requirements files have ambiguous independent option scope")
    for filename, text in requirement_files:
        logical: list[str] = []
        pending = ""
        for raw in text.splitlines():
            stripped = raw.strip()
            if stripped.endswith("\\"):
                pending += stripped[:-1] + " "
                continue
            logical.append((pending + stripped).strip())
            pending = ""
        if pending:
            raise DepConfError("truncated pip requirement continuation")
        for line in logical:
            if not line or line.startswith("#"):
                continue
            option = line.split(None, 1)
            key = option[0].split("=", 1)[0]
            inline = option[0].split("=", 1)[1] if "=" in option[0] else (option[1] if len(option) == 2 else "")
            if key in {"-i", "--index-url"}:
                if not inline:
                    raise DepConfError("pip index option lacks a value")
                index_url = inline
                continue
            if key == "--extra-index-url":
                if not inline:
                    raise DepConfError("pip extra index option lacks a value")
                extras.append(inline)
                continue
            if key in {"-f", "--find-links"}:
                if not inline:
                    raise DepConfError("pip find-links option lacks a value")
                find_links.append(inline)
                continue
            if key == "--no-index":
                no_index = True
                continue
            if key == "--require-hashes":
                require_hashes = True
                continue
            if key in {"-r", "--requirement", "-c", "--constraint"}:
                clues.append({"ecosystem": "pip", "kind": "included-file-not-followed", "file": filename})
                unresolved_include = True
                continue
            name, direct, exact, hashed, conditional = _requirement_name(line)
            if name:
                if name in requirements or conditional:
                    requirements[name] = {"ambiguous": True}
                else:
                    requirements[name] = {"direct": direct, "exact": exact, "hash": hashed}
                if direct and re.search(r"(?:git\+|github\.com)", direct, re.I) and not re.search(r"@[0-9a-fA-F]{40}(?:$|[#&])", direct):
                    clues.append({"ecosystem": "pip", "kind": "repo-namespace-coupled", "package": name,
                                  "reason": "mutable repository reference; external validation required"})
    if 1 + len(extras) + len(find_links) > MAX_SOURCES:
        raise DepConfError("pip source count exceeds cap")
    index_sources = [_source("index-url", index_url, internal, public)]
    index_sources += [_source(f"extra-index-url[{index}]", url, internal, public)
                      for index, url in enumerate(extras)]
    link_sources = [_source(f"find-links[{index}]", url, internal, public)
                    for index, url in enumerate(find_links)]
    configured_sources = index_sources + link_sources
    if len(names) * max(1, len(configured_sources)) > MAX_WORK:
        raise DepConfError("pip analysis work exceeds cap")
    output = []
    for name in names:
        req = requirements.get(name, {})
        if req.get("ambiguous"):
            output.append(_record("pip", name, "indeterminate",
                                  "duplicate or environment-marked requirements have multiple possible source routes"))
            continue
        if unresolved_include:
            output.append(_record("pip", name, "indeterminate",
                                  "an included requirement/constraint file was not supplied with an explicit evaluation graph"))
            continue
        direct = req.get("direct")
        if direct:
            source = _source("direct", direct, internal, public)
            outcome = "protected" if source["role"] in {"internal", "local"} else "public-routed" if source["role"] == "public" else "indeterminate"
            output.append(_record("pip", name, outcome, "direct requirements bypass index candidate selection", [source], source_pinned=True))
            continue
        if no_index:
            if link_sources:
                item = _pool_outcome("pip", name, link_sources, order_matters=False)
                item["reason"] += "; --no-index disables indexes but not configured find-links locations"
                output.append(item)
            else:
                output.append(_record("pip", name, "unmapped-failure",
                                      "--no-index leaves no supplied location for this non-direct requirement", []))
            continue
        item = _pool_outcome("pip", name, configured_sources, order_matters=False)
        if require_hashes and req.get("hash") and req.get("exact"):
            item["mitigations"] = ["complete local hash for this exact supplied requirement"]
        elif req.get("exact"):
            item["limitations"] = ["an exact version is not a source pin"]
        output.append(item)
    return output, clues


def _toml(text: str, label: str) -> dict[str, Any]:
    try:
        value = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError):
        raise DepConfError(f"malformed {label} TOML") from None
    if not isinstance(value, dict):
        raise DepConfError(f"{label} TOML must be a table")
    return value


def _uv(files: Mapping[str, str], names: Sequence[str], internal: set[str], public: set[str]) -> list[dict]:
    py_hit = _single(files, lambda n: n.rsplit("/", 1)[-1] == "pyproject.toml", "pyproject")
    uv_hit = _single(files, lambda n: n.rsplit("/", 1)[-1] == "uv.toml", "uv config")
    py = _toml(py_hit[1], "pyproject") if py_hit else {}
    uv_doc = _toml(uv_hit[1], "uv") if uv_hit else {}
    tool = py.get("tool", {}) if isinstance(py.get("tool", {}), dict) else {}
    py_cfg = tool.get("uv", {}) if isinstance(tool.get("uv", {}), dict) else {}
    config = uv_doc if uv_hit else py_cfg
    if not isinstance(config, dict):
        raise DepConfError("uv configuration must be a table")
    indexes_raw = config.get("index", [])
    if isinstance(indexes_raw, dict):
        indexes_raw = [indexes_raw]
    if not isinstance(indexes_raw, list):
        raise DepConfError("uv index must be an array of tables")
    indexes: list[dict[str, Any]] = []
    seen: set[str] = set()
    has_default = False
    default_count = 0
    for position, entry in enumerate(indexes_raw):
        if not isinstance(entry, dict) or not isinstance(entry.get("url"), str):
            raise DepConfError("uv index entry lacks a literal URL")
        configured_name = entry.get("name")
        if configured_name is not None and not isinstance(configured_name, str):
            raise DepConfError("uv index name must be literal text")
        index_name = configured_name or f"<unnamed-index-{position}>"
        if index_name in seen:
            raise DepConfError("duplicate uv index name")
        seen.add(index_name)
        default = entry.get("default", False)
        explicit = entry.get("explicit", False)
        if not isinstance(default, bool) or not isinstance(explicit, bool):
            raise DepConfError("uv index flags must be booleans")
        has_default |= default
        default_count += int(default)
        indexes.append(_source(index_name, entry["url"], internal, public,
                               explicit=explicit, default=default, position=position))
    pip_cfg = config.get("pip", {}) if isinstance(config.get("pip", {}), dict) else {}
    pip_mode_settings = any(key in pip_cfg for key in (
        "index-url", "extra-index-url", "index-strategy", "no-index", "find-links"
    ))
    legacy_default = config.get("default-index", config.get("index-url"))
    legacy_extra = config.get("extra-index-url", [])
    if isinstance(legacy_extra, str):
        legacy_extra = legacy_extra.split()
    if legacy_extra and not isinstance(legacy_extra, list):
        raise DepConfError("uv extra-index-url must be text or an array")
    for position, url in enumerate(legacy_extra or []):
        if not isinstance(url, str):
            raise DepConfError("uv extra index must be text")
        indexes.append(_source(f"legacy-extra[{position}]", url, internal, public,
                               explicit=False, default=False, position=len(indexes)))
    if isinstance(legacy_default, str):
        indexes.append(_source("legacy-default", legacy_default, internal, public,
                               explicit=False, default=True, position=len(indexes)))
        has_default = True
        default_count += 1
    if not has_default:
        indexes.append(_source("pypi", "https://pypi.org/simple", internal, public,
                               explicit=False, default=True, implicit=True, position=len(indexes)))
        default_count += 1
    if len(indexes) > MAX_SOURCES:
        raise DepConfError("uv source count exceeds cap")
    if default_count > 1:
        raise DepConfError("multiple uv default indexes are ambiguous")
    indexes.sort(key=lambda item: (bool(item.get("default")), int(item.get("position", 0))))
    find_links_raw = config.get("find-links", [])
    if isinstance(find_links_raw, str):
        find_links_raw = [find_links_raw]
    if not isinstance(find_links_raw, list):
        raise DepConfError("uv find-links must be text or an array")
    link_sources: list[dict[str, Any]] = []
    for position, entry in enumerate(find_links_raw):
        if isinstance(entry, dict):
            entry = entry.get("url")
        if not isinstance(entry, str):
            raise DepConfError("uv find-links entry must contain a literal URL/path")
        link_sources.append(_source(f"find-links[{position}]", entry, internal, public))
    if len(indexes) + len(link_sources) > MAX_SOURCES:
        raise DepConfError("uv source count exceeds cap")
    if len(names) * max(1, len(indexes) + len(link_sources)) > MAX_WORK:
        raise DepConfError("uv analysis work exceeds cap")
    strategy = config.get("index-strategy", "first-index")
    if strategy not in {"first-index", "unsafe-first-match", "unsafe-best-match"}:
        raise DepConfError("unsupported uv index strategy")
    no_index = config.get("no-index", False)
    if not isinstance(no_index, bool):
        raise DepConfError("uv no-index must be boolean")
    sources_table = config.get("sources", {})
    if not isinstance(sources_table, dict):
        raise DepConfError("uv sources must be a table")
    normalized_sources = {_normalize_python(str(key)): value for key, value in sources_table.items()}
    no_sources = config.get("no-sources", False)
    if not isinstance(no_sources, bool):
        raise DepConfError("uv no-sources must be boolean")
    no_source_packages = config.get("no-sources-package", [])
    if isinstance(no_source_packages, str):
        no_source_packages = [no_source_packages]
    if not isinstance(no_source_packages, list) or not all(isinstance(value, str) for value in no_source_packages):
        raise DepConfError("uv no-sources-package must be an array of names")
    disabled_bindings = {_normalize_python(value) for value in no_source_packages}
    output = []
    for name in names:
        binding = None if no_sources or name in disabled_bindings else normalized_sources.get(name)
        if binding is not None:
            if isinstance(binding, list):
                output.append(_record("uv", name, "indeterminate", "conditional/multiple uv source bindings are not selected offline",
                                      mode="uv-project"))
                continue
            if not isinstance(binding, dict) or any(key in binding for key in ("marker", "extra", "group")):
                output.append(_record("uv", name, "indeterminate", "uv source binding is missing or conditional",
                                      mode="uv-project"))
                continue
            direct_keys = [key for key in ("path", "url", "git", "workspace") if key in binding]
            if direct_keys:
                if len(direct_keys) != 1 or "index" in binding:
                    output.append(_record("uv", name, "indeterminate", "uv source binding has multiple direct source kinds",
                                          mode="uv-project"))
                    continue
                key = direct_keys[0]
                value = binding[key]
                if key == "path" and isinstance(value, str):
                    source = {"id": key, "url": "<local-path>", "host": "", "role": "local"}
                elif key == "workspace" and value is True:
                    source = {"id": key, "url": "<local-path>", "host": "", "role": "local"}
                elif isinstance(value, str):
                    source = _source(key, value, internal, public)
                else:
                    output.append(_record("uv", name, "indeterminate", "uv direct source is not a literal value",
                                          mode="uv-project"))
                    continue
                outcome = ("protected" if source["role"] in {"internal", "local"}
                           else "public-routed" if source["role"] == "public" else "indeterminate")
                output.append(_record("uv", name, outcome, "uv direct source binding bypasses index selection",
                                      [source], source_pinned=True, mode="uv-project"))
                continue
            if not isinstance(binding.get("index"), str):
                output.append(_record("uv", name, "indeterminate", "uv source binding lacks a supported literal source",
                                      mode="uv-project"))
                continue
            if no_index:
                output.append(_record("uv", name, "unmapped-failure",
                                      "uv no-index disables the named registry index binding", mode="uv-project"))
                continue
            hits = [source for source in indexes if source["id"] == binding["index"]]
            if len(hits) != 1:
                output.append(_record("uv", name, "indeterminate", "uv source binding names a missing index",
                                      mode="uv-project"))
                continue
            source = hits[0]
            outcome = "protected" if source["role"] in {"internal", "local"} else "public-routed" if source["role"] == "public" else "indeterminate"
            output.append(_record("uv", name, outcome, "uv source binding restricts this package to one named index",
                                  [source], source_pinned=True, mode="uv-project"))
            continue
        if no_index:
            if link_sources:
                item = _pool_outcome("uv", name, link_sources, order_matters=False)
                item["reason"] += "; uv no-index disables registry indexes but not find-links locations"
            else:
                item = _record("uv", name, "unmapped-failure",
                               "uv no-index leaves no supplied direct or find-links source")
            item["mode"] = "uv-project"
            output.append(item)
            continue
        eligible = [source for source in indexes if not source.get("explicit")]
        if link_sources:
            item = _pool_outcome("uv", name, eligible + link_sources, order_matters=False)
            item["reason"] += "; flat find-links locations are additional candidates"
        elif strategy == "unsafe-best-match":
            item = _pool_outcome("uv", name, eligible, order_matters=False)
        else:
            item = _pool_outcome("uv", name, eligible, order_matters=True)
            if item["outcome"] == "public-fallback" and strategy == "first-index":
                item["outcome"] = "protected-if-present"
                item["reason"] = "first-index ignores higher public versions if the earlier internal index contains the name"
        item["strategy"] = strategy
        item["mode"] = "uv-project"
        output.append(item)
    if pip_mode_settings:
        limitation = "[tool.uv.pip] source settings describe a separate uv pip resolver mode"
        exposed = {"public-routed", "public-first", "public-fallback", "shadowable", "dynamic-version-race"}
        for item in output:
            if limitation not in item.setdefault("limitations", []):
                item["limitations"].append(limitation)
            if item["outcome"] not in exposed:
                item["outcome"] = "indeterminate"
                item["reason"] = "project and uv pip source policies are both supplied but only one resolver mode can be evaluated per result"
    return output


def _json(text: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        raise DepConfError(f"malformed {label} JSON") from None
    if not isinstance(value, dict):
        raise DepConfError(f"{label} JSON must be an object")
    return value


def _npmrc(files: Mapping[str, str]) -> dict[str, str]:
    hit = _single(files, lambda n: n.rsplit("/", 1)[-1] == ".npmrc", "npm config")
    if not hit:
        return {}
    values: dict[str, str] = {}
    for raw in hit[1].splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if "=" not in line:
            raise DepConfError("malformed npm configuration line")
        key, value = (part.strip() for part in line.split("=", 1))
        lowered = key.lower()
        if not key or not value:
            raise DepConfError("malformed npm configuration assignment")
        if _SECRET.search(lowered) or lowered.startswith("//") or any(
            marker in lowered for marker in ("_auth", "cafile", "certfile", "keyfile")
        ):
            continue
        if (lowered in {"registry", "package-lock", "replace-registry-host"}
                or re.fullmatch(r"@[a-z0-9._-]+:registry", lowered)):
            values[lowered] = value.strip('"\'')
    return values


def _npm_alias(spec: Any) -> str | None:
    if not isinstance(spec, str) or not spec.startswith("npm:"):
        return None
    target = spec[4:]
    if target.startswith("@"):
        match = re.match(r"(@[^/@\s]+/[^@\s]+)(?:@.*)?$", target)
    else:
        match = re.match(r"([^@/\s]+)(?:@.*)?$", target)
    return match.group(1).lower() if match else None


def _npm_lock_entries(lock: Mapping[str, Any]) -> dict[str, list[Mapping[str, Any]]]:
    output: dict[str, list[Mapping[str, Any]]] = {}
    entry_count = 0
    packages = lock.get("packages")
    if isinstance(packages, dict):
        for key, value in packages.items():
            if not isinstance(key, str) or not isinstance(value, dict):
                continue
            lowered = key.lower()
            if lowered.startswith("node_modules/"):
                package_name = lowered.rsplit("/node_modules/", 1)[-1]
                if package_name.startswith("node_modules/"):
                    package_name = package_name[len("node_modules/"):]
                output.setdefault(package_name, []).append(value)
                entry_count += 1
    dependencies = lock.get("dependencies")
    if isinstance(dependencies, dict):
        for key, value in dependencies.items():
            if isinstance(key, str) and isinstance(value, dict):
                output.setdefault(key.lower(), []).append(value)
                entry_count += 1
    if len(output) > MAX_PACKAGES or entry_count > MAX_PACKAGES:
        raise DepConfError("npm lock package count exceeds cap")
    return output


def _npm_root_specs(lock: Mapping[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    packages = lock.get("packages")
    root = packages.get("") if isinstance(packages, dict) else None
    if isinstance(root, dict):
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            values = root.get(section, {})
            if isinstance(values, dict):
                output.update({str(key).lower(): value for key, value in values.items()})
    return output


def _npm(files: Mapping[str, str], names: Sequence[str], internal: set[str], public: set[str]) -> tuple[list[dict], list[dict]]:
    config = _npmrc(files)
    registry = config.get("registry", "https://registry.npmjs.org/")
    package_hit = _single(files, lambda n: n.rsplit("/", 1)[-1] == "package.json", "package manifest")
    package = _json(package_hit[1], "package manifest") if package_hit else {}
    shrink = _single(files, lambda n: n.rsplit("/", 1)[-1] == "npm-shrinkwrap.json", "npm shrinkwrap")
    package_lock = _single(files, lambda n: n.rsplit("/", 1)[-1] == "package-lock.json", "npm lock")
    use_lock = _bool(config["package-lock"]) if "package-lock" in config else True
    lock_disabled_for_install = not use_lock and shrink is None and package_lock is not None
    # npm ci still consumes package-lock.json when package-lock=false, so retain
    # it as an alternate command-mode route instead of discarding the evidence.
    lock_hit = shrink or package_lock
    lock = _json(lock_hit[1], "npm lock") if lock_hit else {}
    lock_entries = _npm_lock_entries(lock)
    lock_root_spec_sets = [_npm_root_specs(lock)] if lock_hit else []
    alternate_lock_entries: dict[str, list[Mapping[str, Any]]] = {}
    if shrink is not None and package_lock is not None:
        alternate_lock = _json(package_lock[1], "npm package lock")
        alternate_lock_entries = _npm_lock_entries(alternate_lock)
        lock_root_spec_sets.append(_npm_root_specs(alternate_lock))
    replace_registry_host = config.get("replace-registry-host", "npmjs").lower()
    if replace_registry_host not in {"npmjs", "never", "always"}:
        replace_registry_host = "unresolved"
    specs: dict[str, Any] = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        entries = package.get(section, {})
        if entries is None:
            continue
        if not isinstance(entries, dict):
            raise DepConfError(f"npm {section} must be an object")
        for key, value in entries.items():
            if isinstance(key, str):
                specs[key.lower()] = value
                if len(specs) > MAX_PACKAGES:
                    raise DepConfError("npm manifest package count exceeds cap")
    output: list[dict] = []
    clues: list[dict] = []
    for original in names:
        target = _npm_alias(specs.get(original)) or original
        spec = specs.get(original)
        scope = target.split("/", 1)[0].lower() if target.startswith("@") and "/" in target else ""
        route = config.get(f"{scope}:registry", registry) if scope else registry
        direct_spec = isinstance(spec, str) and (
            spec.startswith(("file:", "link:", "workspace:", "./", "../", "/", "git+", "git://"))
            or bool(re.match(r"https?://", spec, re.I))
            or bool(re.match(r"^[^/@\s]+/[^/\s]+(?:#.*)?$", spec))
        )
        if direct_spec:
            repository_reference = bool(re.match(
                r"(?:git\+|git://|https?://.*(?:github|gitlab|bitbucket)|^[^/@\s]+/[^/\s]+(?:#.*)?$)",
                spec, re.I,
            ))
            if repository_reference and not re.search(r"(?:#|/)[0-9a-fA-F]{40}$", spec):
                clues.append({"ecosystem": "npm", "kind": "repo-namespace-coupled", "package": original,
                              "reason": "mutable repository dependency; external validation required"})
            if spec.startswith(("file:", "link:", "workspace:", "./", "../", "/")):
                direct_source = {"id": "direct", "url": "<local-path>", "host": "", "role": "local"}
            elif re.match(r"^[^/@\s]+/[^/\s]+(?:#.*)?$", spec):
                direct_source = {"id": "direct", "url": "<repository-shorthand>", "host": "github.com", "role": "unknown"}
            else:
                direct_source = _source("direct", spec, internal, public)
            outcome = ("protected" if direct_source["role"] in {"internal", "local"}
                       else "public-routed" if direct_source["role"] == "public" else "indeterminate")
            output.append(_record("npm", original, outcome,
                                  "the supplied dependency is a direct source and bypasses npm registry routing",
                                  [direct_source], source_pinned=True))
            continue
        entries = list(lock_entries.get(original, []))
        if target != original:
            entries.extend(lock_entries.get(target, []))
        alternate_entries = list(alternate_lock_entries.get(original, []))
        if target != original:
            alternate_entries.extend(alternate_lock_entries.get(target, []))
        entries.extend(alternate_entries)
        if entries:
            if original in specs and any(
                original in root_specs and specs[original] != root_specs[original]
                for root_specs in lock_root_spec_sets
            ):
                output.append(_record("npm", original, "indeterminate",
                                      "package.json and the active lock disagree on the root dependency spec",
                                      locked=True, alias_target=target if target != original else None))
                continue
            locked_sources: list[dict[str, Any]] = []
            integrity_complete = True
            for position, lock_entry in enumerate(entries):
                integrity = lock_entry.get("integrity")
                integrity_complete &= bool(isinstance(integrity, str) and integrity)
                if lock_entry.get("link") is True:
                    locked_sources.append({"id": f"lock-link[{position}]", "url": "<local-path>",
                                           "host": "", "role": "local"})
                    continue
                resolved = lock_entry.get("resolved")
                if isinstance(resolved, str) and resolved and _VARIABLE.search(resolved):
                    locked = {"id": f"lock-resolved[{position}]", "url": "<unresolved-variable>",
                              "host": "", "role": "unresolved"}
                elif isinstance(resolved, str) and resolved:
                    locked = _source(f"lock-resolved[{position}]", resolved, internal, public)
                    registry_tarball = resolved.lower().startswith(("http://", "https://"))
                    replace_lock_host = registry_tarball and (
                        replace_registry_host == "always"
                        or (replace_registry_host == "npmjs" and locked["host"] == "registry.npmjs.org")
                    )
                    if replace_lock_host:
                        locked = _source(f"effective-registry[{position}]", route, internal, public,
                                         lock_default_registry_magic=True)
                    elif replace_registry_host == "unresolved":
                        locked = {"id": f"lock-resolved[{position}]", "url": "<unresolved-registry-replacement>",
                                  "host": "", "role": "unresolved"}
                elif resolved is None or resolved == "":
                    locked_version = lock_entry.get("version")
                    if isinstance(locked_version, str) and locked_version.startswith(
                        ("http://", "https://", "git+", "git://", "ssh://", "file:", "./", "../", "/")
                    ):
                        if _VARIABLE.search(locked_version):
                            locked = {"id": f"lock-version[{position}]", "url": "<unresolved-variable>",
                                      "host": "", "role": "unresolved"}
                        elif locked_version.startswith(("file:", "./", "../", "/")):
                            locked = {"id": f"lock-version[{position}]", "url": "<local-path>",
                                      "host": "", "role": "local"}
                        else:
                            locked = _source(f"lock-version[{position}]", locked_version, internal, public)
                    else:
                        locked = _source(f"effective-registry[{position}]", route, internal, public,
                                         lock_origin_omitted=True)
                else:
                    locked = {"id": f"lock-resolved[{position}]", "url": "<invalid-lock-origin>",
                              "host": "", "role": "unresolved"}
                locked_sources.append(locked)
            if lock_disabled_for_install:
                locked_sources.append(_source("npm-install-route", route, internal, public,
                                              package_lock_disabled=True))
            shrinkwrap_version_split = shrink is not None
            if shrinkwrap_version_split and (package_lock is None or not alternate_entries or not use_lock):
                locked_sources.append(_source("npm12-route", route, internal, public,
                                              shrinkwrap_ignored=True))
            roles = {source["role"] for source in locked_sources}
            if roles <= {"internal", "local"}:
                outcome = "protected"
            elif roles == {"public"}:
                outcome = "public-routed"
            elif "unresolved" in roles or "unknown" in roles:
                outcome = "indeterminate"
            else:
                outcome = "version-dependent" if shrinkwrap_version_split else (
                    "mode-dependent" if lock_disabled_for_install else "shadowable"
                )
            reason = "the active npm lock records the artifact origin for each installed location"
            if lock_disabled_for_install:
                reason = "npm install ignores the lock while npm ci still consumes it; the command modes have different routes"
            if shrinkwrap_version_split:
                reason = "npm <=11 gives shrinkwrap precedence while npm 12 ignores it; possible version routes are combined"
            item = _record("npm", original, outcome,
                           reason,
                           locked_sources, alias_target=target if target != original else None,
                           locked=True, lock_origins=sorted(roles), integrity=integrity_complete)
            if "internal" in roles:
                item["limitations"] = ["an internal registry may proxy public upstreams"]
            if shrinkwrap_version_split:
                item.setdefault("limitations", []).append("npm-shrinkwrap.json behavior changes in npm 12")
            output.append(item)
            continue
        source = _source(f"scope:{scope}" if scope else "registry", route, internal, public)
        if source["role"] == "public":
            outcome, reason = "public-routed", "npm routes this name to one known-public registry"
        elif source["role"] in {"internal", "local"}:
            outcome = "protected" if scope else "proxy-policy-unknown"
            reason = ("the npm scope is mapped to one internal registry with no client-side public fallback"
                      if scope else "the client uses one internal default registry, but its upstream proxy policy is unknown")
        else:
            outcome, reason = "indeterminate", "the single npm registry route is not trust-classified"
        if target != original:
            reason = f"npm alias target {target} is evaluated: {reason}"
        item = _record("npm", original, outcome, reason, [source],
                       alias_target=target if target != original else None)
        if source["role"] == "internal":
            item["limitations"] = ["server-side proxy/upstream policy is not present in npm client configuration"]
        output.append(item)
    return output, clues


class _BoundedTree:
    def __init__(self) -> None:
        self.builder = ET.TreeBuilder()
        self.depth = 0
        self.nodes = 0

    def start(self, tag: str, attributes: dict[str, str]) -> Any:
        self.depth += 1
        self.nodes += 1
        if self.depth > MAX_XML_DEPTH or self.nodes > MAX_XML_NODES:
            raise DepConfError("XML structure exceeds cap")
        return self.builder.start(tag, attributes)

    def end(self, tag: str) -> Any:
        value = self.builder.end(tag)
        self.depth -= 1
        return value

    def data(self, data: str) -> None:
        self.builder.data(data)

    def close(self) -> ET.Element:
        if self.depth:
            raise DepConfError("malformed XML nesting")
        return self.builder.close()

    def doctype(self, name: str, public_id: str | None, system_id: str | None) -> None:
        raise DepConfError("DTD/entity declarations are forbidden")


def _xml(text: str, label: str) -> ET.Element:
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)", text, re.I):
        raise DepConfError("DTD/entity declarations are forbidden")
    target = _BoundedTree()
    try:
        parser = ET.XMLParser(target=target)
        parser.feed(text)
        return parser.close()
    except DepConfError:
        raise
    except (ET.ParseError, RecursionError):
        raise DepConfError(f"malformed {label} XML") from None


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _children(element: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in list(element) if _local(child.tag) == name]


def _first(element: ET.Element, name: str) -> ET.Element | None:
    matches = _children(element, name)
    if len(matches) > 1:
        raise DepConfError(f"duplicate XML element: {name}")
    return matches[0] if matches else None


def _text(element: ET.Element | None, default: str = "") -> str:
    return default if element is None or element.text is None else element.text.strip()


def _nuget_pattern(pattern: str, package: str) -> tuple[int, int] | None:
    value = pattern.strip().lower()
    package_id = package.lower()
    if not value or value.count("*") > 1 or ("*" in value and not value.endswith("*")):
        raise DepConfError("unsupported NuGet source mapping pattern")
    if value == "*":
        return (0, 0)
    if value.endswith("*"):
        prefix = value[:-1]
        return (1, len(prefix)) if package_id.startswith(prefix) else None
    return (2, len(value)) if package_id == value else None


def _nuget(files: Mapping[str, str], names: Sequence[str], internal: set[str], public: set[str]) -> list[dict]:
    hit = _single(files, lambda n: n.rsplit("/", 1)[-1] in {"nuget.config", "nuget.config.xml"}, "NuGet config")
    if not hit:
        return [_record("nuget", name, "indeterminate",
                        "no supplied NuGet.Config establishes enabled sources or inherited configuration")
                for name in names]
    root = _xml(hit[1], "NuGet config")
    if _local(root.tag) != "configuration":
        raise DepConfError("NuGet config root must be configuration")
    package_sources = _first(root, "packageSources")
    clear_sources = False
    raw_sources: list[tuple[str, str]] = []
    if package_sources is not None:
        for child in list(package_sources):
            tag = _local(child.tag)
            if tag == "clear":
                clear_sources = True
                raw_sources.clear()
            elif tag == "add":
                key, value = child.get("key"), child.get("value")
                if not key or not value:
                    raise DepConfError("NuGet package source lacks key/value")
                raw_sources = [(old_key, old_value) for old_key, old_value in raw_sources
                               if old_key.lower() != key.lower()]
                raw_sources.append((key, value))
                if len(raw_sources) > MAX_SOURCES:
                    raise DepConfError("NuGet source count exceeds cap")
    disabled: set[str] = set()
    disabled_section = _first(root, "disabledPackageSources")
    if disabled_section is not None:
        for child in list(disabled_section):
            tag = _local(child.tag)
            if tag == "clear":
                disabled.clear()
            elif tag == "add":
                key, value = child.get("key"), child.get("value")
                if not key or value is None:
                    raise DepConfError("NuGet disabled source lacks key/value")
                if _bool(value):
                    disabled.add(key.lower())
                else:
                    disabled.discard(key.lower())
    sources = [_source(key, value, internal, public, enabled=key.lower() not in disabled)
               for key, value in raw_sources if key.lower() not in disabled]
    if len(sources) > MAX_SOURCES:
        raise DepConfError("source count exceeds cap")
    mapping_section = _first(root, "packageSourceMapping")
    mappings: dict[str, list[str]] = {}
    mapping_present = mapping_section is not None
    clear_mappings = False
    pattern_count = 0
    if mapping_section is not None:
        for child in list(mapping_section):
            tag = _local(child.tag)
            if tag == "clear":
                clear_mappings = True
                mappings.clear()
                continue
            if tag != "packageSource":
                continue
            key = child.get("key")
            if not key:
                raise DepConfError("NuGet source mapping lacks a key")
            patterns: list[str] = []
            for package in list(child):
                if _local(package.tag) != "package":
                    continue
                pattern = package.get("pattern")
                if not pattern:
                    raise DepConfError("NuGet source mapping lacks a pattern")
                _nuget_pattern(pattern, "__validation_only__")
                patterns.append(pattern)
                pattern_count += 1
                if pattern_count > MAX_SOURCES:
                    raise DepConfError("NuGet mapping count exceeds cap")
            mappings[key.lower()] = patterns
    source_by_key = {source["id"].lower(): source for source in sources}
    inherited_unknown = not clear_sources or (mapping_present and not clear_mappings)
    if len(names) * max(1, pattern_count if mapping_present else len(sources)) > MAX_WORK:
        raise DepConfError("NuGet analysis work exceeds cap")
    output: list[dict] = []
    for name in names:
        if not mapping_present:
            candidates = list(sources)
            if inherited_unknown:
                candidates.append({"id": "inherited", "url": "<not-supplied>", "host": "",
                                   "role": "unresolved"})
            item = _pool_outcome("nuget", name, candidates, order_matters=False)
            item["mapping"] = False
            output.append(item)
            continue
        matches: list[tuple[tuple[int, int], dict[str, Any] | None, str]] = []
        for key, patterns in mappings.items():
            scores = [score for pattern in patterns if (score := _nuget_pattern(pattern, name)) is not None]
            if not scores:
                continue
            source = source_by_key.get(key)
            matches.append((max(scores), source, key))
        if not matches:
            item = _record("nuget", name, "unmapped-failure",
                           "Package Source Mapping is active but no pattern matches this package", mapping=True)
            if inherited_unknown:
                item["limitations"] = ["higher-level NuGet mappings were not supplied"]
                item["outcome"] = "indeterminate"
                item["reason"] = "no local mapping matches, but inherited mapping state was not cleared"
            item["assumptions"] = ["Package Source Mapping requires NuGet 6.0 / .NET SDK 6.0.100 or newer"]
            output.append(item)
            continue
        best = max(score for score, _source_item, _key in matches)
        best_matches = [(source, key) for score, source, key in matches if score == best]
        eligible = [source for source, _key in best_matches if source is not None]
        dead = sorted(key for source, key in best_matches if source is None)
        if not eligible:
            item = _record("nuget", name, "unmapped-failure",
                           "the highest-specificity mapping references only disabled or missing sources",
                           mapping=True, dead_mapping_sources=dead)
            if inherited_unknown:
                item["limitations"] = ["higher-level NuGet mappings were not supplied"]
                item["outcome"] = "indeterminate"
                item["reason"] = "local matching sources are disabled/missing, but inherited mapping state was not cleared"
            item["assumptions"] = ["Package Source Mapping requires NuGet 6.0 / .NET SDK 6.0.100 or newer"]
            output.append(item)
            continue
        item = _pool_outcome("nuget", name, eligible, order_matters=False)
        item["mapping"] = True
        item["mapping_specificity"] = {2: "exact", 1: "prefix", 0: "wildcard"}[best[0]]
        item["assumptions"] = ["Package Source Mapping requires NuGet 6.0 / .NET SDK 6.0.100 or newer"]
        if dead:
            item["dead_mapping_sources"] = dead
        if inherited_unknown:
            item.setdefault("limitations", []).append("higher-level NuGet sources/mappings were not cleared or supplied")
            if item["outcome"] == "protected":
                item["outcome"] = "indeterminate"
                item["reason"] = "the local mapping is internal-only, but inherited mapping state was not cleared"
        output.append(item)
    return output


def _maven_bool(element: ET.Element | None, default: bool) -> bool:
    value = _text(_first(element, "enabled") if element is not None else None)
    return default if not value else _bool(value)


def _maven_repository(element: ET.Element, internal: set[str], public: set[str], origin: str) -> dict[str, Any]:
    identifier = _text(_first(element, "id"))
    url = _text(_first(element, "url"))
    if not identifier or not url:
        raise DepConfError("Maven repository lacks literal id/url")
    releases = _maven_bool(_first(element, "releases"), True)
    snapshots = _maven_bool(_first(element, "snapshots"), True)
    return _source(identifier, url, internal, public, origin=origin,
                   releases=releases, snapshots=snapshots)


def _maven_repositories(container: ET.Element, internal: set[str], public: set[str], origin: str) -> list[dict[str, Any]]:
    section = _first(container, "repositories")
    if section is None:
        return []
    return [_maven_repository(child, internal, public, origin)
            for child in list(section) if _local(child.tag) == "repository"]


def _maven_active_settings(root: ET.Element, internal: set[str], public: set[str]) -> tuple[list[dict[str, Any]], bool]:
    active_section = _first(root, "activeProfiles")
    active_elements = list(active_section) if active_section is not None else []
    active = {_text(child) for child in active_elements if _local(child.tag) == "activeProfile"}
    profiles = _first(root, "profiles")
    output: list[dict[str, Any]] = []
    unresolved_activation = False
    if profiles is None:
        return output, False
    profile_elements = [profile for profile in list(profiles) if _local(profile.tag) == "profile"]
    candidates: list[ET.Element] = []
    for profile in profile_elements:
        profile_id = _text(_first(profile, "id"))
        activation = _first(profile, "activation")
        by_default = _text(_first(activation, "activeByDefault") if activation is not None else None).lower() == "true"
        complex_activation = activation is not None and any(
            _local(child.tag) != "activeByDefault" for child in list(activation)
        )
        if profile_id in active or by_default:
            candidates.append(profile)
        elif complex_activation and _first(profile, "repositories") is not None:
            unresolved_activation = True
    # Maven's effective settings gives later-declared active profiles higher
    # precedence when repository IDs collide.
    for profile in reversed(candidates):
        output.extend(_maven_repositories(profile, internal, public, "settings-profile"))
    return output, unresolved_activation


def _maven_properties(root: ET.Element) -> dict[str, str]:
    values: dict[str, str] = {}
    properties = _first(root, "properties")
    if properties is not None:
        for child in list(properties):
            if child.text is not None:
                values[_local(child.tag)] = child.text.strip()
    group = _text(_first(root, "groupId"))
    artifact = _text(_first(root, "artifactId"))
    version = _text(_first(root, "version"))
    parent = _first(root, "parent")
    values.update({key: value for key, value in {
        "project.groupId": group or _text(_first(parent, "groupId") if parent is not None else None),
        "project.artifactId": artifact,
        "project.version": version or _text(_first(parent, "version") if parent is not None else None),
    }.items() if value})
    return values


def _maven_resolve(value: str, properties: Mapping[str, str]) -> str | None:
    current = value
    for _ in range(16):
        matches = re.findall(r"\$\{([^}]+)}", current)
        if not matches:
            return current
        if any(key.startswith("env.") or key not in properties for key in matches):
            return None
        updated = current
        for key in matches:
            updated = updated.replace("${" + key + "}", properties[key])
        if updated == current:
            return None
        current = updated
    return None


def _maven_versions(root: ET.Element, properties: Mapping[str, str]) -> dict[str, str | None]:
    output: dict[str, str | None] = {}
    sections: list[ET.Element] = []
    management = _first(root, "dependencyManagement")
    if management is not None:
        managed_dependencies = _first(management, "dependencies")
        if managed_dependencies is not None:
            sections.append(managed_dependencies)
    direct_dependencies = _first(root, "dependencies")
    if direct_dependencies is not None:
        sections.append(direct_dependencies)
    for section in sections:
        for element in list(section):
            if _local(element.tag) != "dependency":
                continue
            group = _text(_first(element, "groupId"))
            artifact = _text(_first(element, "artifactId"))
            version = _text(_first(element, "version"))
            if group and artifact and version:
                output[f"{group}:{artifact}"] = _maven_resolve(version, properties)
    return output


def _external_repo(source: Mapping[str, Any], http_only: bool = False) -> bool:
    url = str(source.get("url", ""))
    parts = urlsplit(url) if not url.startswith("<") else None
    if parts is None or not parts.hostname:
        return False
    host = parts.hostname.lower()
    if host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local"):
        return False
    return (parts.scheme == "http") if http_only else parts.scheme in {"http", "https"}


def _mirror_pattern_matches(pattern: str, source: Mapping[str, Any]) -> bool:
    tokens = pattern.split(",")
    if any(token != token.strip() or not token for token in tokens):
        raise DepConfError("malformed Maven mirrorOf expression")
    identifier = str(source["id"])
    included = False
    for token in tokens:
        if token.startswith("!"):
            if token[1:] == identifier:
                return False
            continue
        if token == identifier or token == "*":
            included = True
        elif token == "external:*" and _external_repo(source):
            included = True
        elif token == "external:http:*" and _external_repo(source, http_only=True):
            included = True
    return included


def _maven_mirrors(root: ET.Element | None, internal: set[str], public: set[str]) -> list[dict[str, Any]]:
    if root is None:
        return []
    section = _first(root, "mirrors")
    if section is None:
        return []
    output: list[dict[str, Any]] = []
    for element in list(section):
        if _local(element.tag) != "mirror":
            continue
        identifier = _text(_first(element, "id"))
        url = _text(_first(element, "url"))
        pattern = _text(_first(element, "mirrorOf"))
        if not identifier or not url or not pattern:
            raise DepConfError("Maven mirror lacks id/url/mirrorOf")
        output.append(_source(identifier, url, internal, public, mirror_of=pattern))
        if len(output) > MAX_SOURCES:
            raise DepConfError("Maven mirror count exceeds cap")
    return output


def _apply_mirror(source: dict[str, Any], mirrors: Sequence[dict[str, Any]]) -> dict[str, Any]:
    exact = [mirror for mirror in mirrors if mirror["mirror_of"] == source["id"]]
    candidates = exact or [mirror for mirror in mirrors if _mirror_pattern_matches(mirror["mirror_of"], source)]
    if not candidates:
        return source
    mirror = dict(candidates[0])
    mirror.update({"mirrors": source["id"], "original_role": source["role"],
                   "releases": source["releases"], "snapshots": source["snapshots"]})
    return mirror


def _maven(files: Mapping[str, str], names: Sequence[str], internal: set[str], public: set[str]) -> tuple[list[dict], list[dict]]:
    pom_hit = _single(files, lambda n: n.rsplit("/", 1)[-1] == "pom.xml", "Maven POM")
    settings_hit = _single(files, lambda n: n.rsplit("/", 1)[-1] == "settings.xml", "Maven settings")
    pom = _xml(pom_hit[1], "Maven POM") if pom_hit else None
    settings = _xml(settings_hit[1], "Maven settings") if settings_hit else None
    if pom is not None and _local(pom.tag) != "project":
        raise DepConfError("Maven POM root must be project")
    if settings is not None and _local(settings.tag) != "settings":
        raise DepConfError("Maven settings root must be settings")
    repositories: list[dict[str, Any]] = []
    unresolved_activation = False
    unresolved_parent = pom is not None and _first(pom, "parent") is not None
    if settings is not None:
        setting_repos, unresolved_activation = _maven_active_settings(settings, internal, public)
        repositories.extend(setting_repos)
    if pom is not None:
        repositories.extend(_maven_repositories(pom, internal, public, "pom"))
        profiles = _first(pom, "profiles")
        if profiles is not None and any(
            _first(profile, "repositories") is not None
            for profile in list(profiles) if _local(profile.tag) == "profile"
        ):
            unresolved_activation = True
    # Settings definitions take precedence when repository IDs collide.
    deduplicated: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for source in repositories:
        if source["id"] not in seen_ids:
            deduplicated.append(source)
            seen_ids.add(source["id"])
            if len(deduplicated) > MAX_SOURCES:
                raise DepConfError("Maven repository count exceeds cap")
    if "central" not in seen_ids:
        deduplicated.append(_source("central", "https://repo.maven.apache.org/maven2", internal, public,
                                    origin="super-pom", releases=True, snapshots=False))
    mirrors = _maven_mirrors(settings, internal, public)
    if len(names) * max(1, len(deduplicated)) * max(1, len(mirrors)) > MAX_WORK:
        raise DepConfError("Maven analysis work exceeds cap")
    properties = _maven_properties(pom) if pom is not None else {}
    versions = _maven_versions(pom, properties) if pom is not None else {}
    clues: list[dict] = []
    if any(source.get("host") == "jitpack.io" for source in deduplicated):
        for name in names:
            if name.startswith("com.github."):
                clues.append({"ecosystem": "maven", "kind": "repo-namespace-coupled", "package": name,
                              "reason": "JitPack coordinates are repository-namespace coupled; external validation required"})
    output: list[dict] = []
    for name in names:
        version = versions.get(name)
        version_declared = name in versions
        unresolved_version = version_declared and version is None
        snapshot = bool(version and version.upper().endswith("-SNAPSHOT"))
        dynamic = bool(version and (re.search(r"[\[(].*[,].*[\])]", version) or version.upper() in {"LATEST", "RELEASE"}))
        eligible = [source for source in deduplicated
                    if ((source["snapshots"] if snapshot else source["releases"])
                        if version is not None else (source["releases"] or source["snapshots"]))]
        mirrored = [_apply_mirror(source, mirrors) for source in eligible]
        item = _pool_outcome("maven", name, mirrored, order_matters=True, dynamic=dynamic)
        item["version"] = version or "<not-supplied>"
        if unresolved_version:
            item["outcome"] = "indeterminate"
            item["reason"] = "the dependency version contains an unresolved Maven property"
        elif not version_declared:
            item["outcome"] = "indeterminate"
            item["reason"] = "no literal or locally managed dependency version was supplied; release/snapshot eligibility is unknown"
        opaque_internal_mirror = any(
            source.get("mirrors") and source.get("role") == "internal" and source.get("original_role") != "internal"
            for source in mirrored
        )
        if opaque_internal_mirror and item["outcome"] in {"protected", "protected-if-present"}:
            item["outcome"] = "proxy-policy-unknown"
            item["reason"] = "an internal mirror replaces external repositories, but its upstream policy is opaque"
        if unresolved_activation and item["outcome"] == "protected":
            item["outcome"] = "indeterminate"
            item["reason"] = "a supplied Maven profile can add repositories but its effective activation is not statically known"
        if unresolved_parent and item["outcome"] == "protected":
            item["outcome"] = "indeterminate"
            item["reason"] = "the supplied POM has an unresolved parent that may contribute repositories"
        limitations = item.setdefault("limitations", [])
        if settings is None:
            limitations.append("user/global Maven settings and mirrors were not supplied")
        if unresolved_activation:
            limitations.append("a settings/POM profile can add repositories but effective activation is not fully supplied")
        if unresolved_parent:
            limitations.append("the parent POM and its inherited repositories were not supplied")
        if not limitations:
            item.pop("limitations")
        output.append(item)
    return output, clues


def _config_inventory(files: Mapping[str, str]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for filename in files:
        base = filename.lower().rsplit("/", 1)[-1]
        ecosystems: list[str] = []
        if base in {"pip.conf", "pip.ini"} or (base.startswith("requirements") and base.endswith((".txt", ".in"))):
            ecosystems.append("pip")
        if base in {"pyproject.toml", "uv.toml"}:
            ecosystems.append("uv")
        if base in {".npmrc", "package.json", "package-lock.json", "npm-shrinkwrap.json"}:
            ecosystems.append("npm")
        if base in {"nuget.config", "nuget.config.xml"}:
            ecosystems.append("nuget")
        if base in {"pom.xml", "settings.xml"}:
            ecosystems.append("maven")
        if ecosystems:
            output.append({"file": filename, "ecosystems": ecosystems})
    return output


@_guard
def audit_configs(files: Mapping[str, bytes | str], *,
                  internal_names: Mapping[str, Sequence[str]] | None = None,
                  internal_hosts: Sequence[str] = (),
                  public_hosts: Sequence[str] = ()) -> dict[str, Any]:
    """Evaluate only supplied package-manager configuration and ownership hints.

    Unknown hosts and unavailable package/version state remain indeterminate.  The
    function performs no discovery and no registry, filesystem, or environment IO.
    """
    supplied = _input_files(files)
    names = _internal_names(internal_names)
    internal, public = _roles(internal_hosts, public_hosts)
    packages: list[dict[str, Any]] = []
    clues: list[dict[str, Any]] = []
    if names["pip"]:
        pip_packages, pip_clues = _pip(supplied, names["pip"], internal, public)
        packages.extend(pip_packages)
        clues.extend(pip_clues)
    if names["uv"]:
        packages.extend(_uv(supplied, names["uv"], internal, public))
    if names["npm"]:
        npm_packages, npm_clues = _npm(supplied, names["npm"], internal, public)
        packages.extend(npm_packages)
        clues.extend(npm_clues)
    if names["nuget"]:
        packages.extend(_nuget(supplied, names["nuget"], internal, public))
    if names["maven"]:
        maven_packages, maven_clues = _maven(supplied, names["maven"], internal, public)
        packages.extend(maven_packages)
        clues.extend(maven_clues)
    if names["gradle"]:
        packages.extend(_record("gradle", name, "indeterminate",
                                "Gradle executable build scripts are intentionally not evaluated by this configuration-only engine")
                        for name in names["gradle"])
    if len(packages) > MAX_PACKAGES or sum(len(item.get("sources", [])) for item in packages) > MAX_SOURCES * MAX_FILES:
        raise DepConfError("analysis output exceeds cap")
    order = {ecosystem: index for index, ecosystem in enumerate(ECOSYSTEMS)}
    packages.sort(key=lambda item: (order[item["ecosystem"]], item["name"], item["outcome"], item["reason"]))
    clues.sort(key=lambda item: (item.get("ecosystem", ""), item.get("package", ""), item.get("kind", "")))
    return {
        "kind": "dependency-source-precedence-audit",
        "offline": True,
        "network_requests": 0,
        "packages": packages,
        "clues": clues,
        "configs": _config_inventory(supplied),
        "limitations": [
            "package/version availability and registry-manager upstream policy are not observable offline",
            "command-line, environment, user, machine, parent, and imported configuration not supplied here may override these results",
            "repository namespace ownership or claimability requires external validation",
            "Gradle build logic is researched in the gap report but intentionally not executed or interpreted by this quick-win engine",
        ],
    }


@_guard
def audit_paths(paths: Sequence[str | Path], *,
                internal_names: Mapping[str, Sequence[str]] | None = None,
                internal_hosts: Sequence[str] = (),
                public_hosts: Sequence[str] = ()) -> dict[str, Any]:
    """Read an explicit bounded list of local files and pass it to audit_configs."""
    if isinstance(paths, (str, bytes)) or not isinstance(paths, Sequence):
        raise DepConfError("paths must be a sequence")
    if not paths or len(paths) > MAX_FILES:
        raise DepConfError("provide between one and the maximum number of files")
    files: dict[str, bytes] = {}
    for raw in paths:
        if not isinstance(raw, (str, Path)):
            raise DepConfError("path must be text or Path")
        path = Path(raw)
        if len(str(path)) > MAX_PATH or not path.is_file():
            raise DepConfError("supplied path is not a regular file")
        key = path.name
        if key in files:
            raise DepConfError("duplicate configuration basenames are ambiguous")
        with path.open("rb") as handle:
            value = handle.read(MAX_FILE + 1)
        if len(value) > MAX_FILE:
            raise DepConfError("file exceeds size cap")
        files[key] = value
    return audit_configs(files, internal_names=internal_names,
                         internal_hosts=internal_hosts, public_hosts=public_hosts)


def _arguments(values: Sequence[str]) -> dict[str, list[str]]:
    output = {ecosystem: [] for ecosystem in ECOSYSTEMS}
    for value in values:
        if ":" not in value:
            raise DepConfError("--internal must be ECOSYSTEM:NAME")
        ecosystem, name = value.split(":", 1)
        if ecosystem not in output or not name:
            raise DepConfError("--internal names an unsupported ecosystem")
        output[ecosystem].append(name)
    return output


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Offline package source-precedence auditor")
    parser.add_argument("files", nargs="+", help="explicit config/manifest/lock files")
    parser.add_argument("--internal", action="append", default=[], metavar="ECOSYSTEM:NAME",
                        help="internal-intended package (repeatable)")
    parser.add_argument("--internal-host", action="append", default=[], help="caller-classified internal hostname")
    parser.add_argument("--public-host", action="append", default=[], help="additional known-public hostname")
    parser.add_argument("--pretty", action="store_true", help="pretty-print deterministic JSON")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        try:
            args = _parser().parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2
        report = audit_paths(args.files, internal_names=_arguments(args.internal),
                             internal_hosts=args.internal_host, public_hosts=args.public_host)
        print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
        return 0
    except DepConfError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
