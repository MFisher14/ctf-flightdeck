#!/usr/bin/env python3
"""Offline deserialization-CVE precondition mapper.

This analyzer consumes a bounded JSON evidence document supplied by the player
and evaluates vendor-documented version, configuration, sink, and classpath
gates. It never contacts a target, scans a classpath, imports target code,
deserializes an object, or executes a gadget.

Evidence schema (fields are optional; missing facts remain ``unknown``)::

    {
      "products": [{"name": "Apache Tomcat", "version": "10.1.34"}],
      "dependencies": [{"name": "org.apache.commons:commons-collections4",
                         "version": "4.0"}],
      "config": {"tomcat.default_servlet_writes": true},
      "classes": ["org.apache.commons.collections4.functors.InvokerTransformer"],
      "symbols": ["torch.load"]
    }

CLI::

    ./.venv/bin/python solvers/web/webdeser2_preconditions.py analyze evidence.json
    ./.venv/bin/python solvers/web/webdeser2_preconditions.py catalog

Only assessments whose every mandatory gate is proven true appear in the
top-level ``satisfied`` list. ``not_satisfied`` means supplied evidence proves
at least one gate false; it is not a claim that the deployment is generally
safe from deserialization flaws.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence


MAX_JSON_BYTES = 1024 * 1024
MAX_JSON_NODES = 4096
MAX_JSON_DEPTH = 8
MAX_FACTS = 512
MAX_COMPONENTS = 128
MAX_TEXT = 256


class WebDeser2Error(ValueError):
    """Supplied evidence is malformed, ambiguous, or exceeds a safety cap."""


@dataclass(frozen=True)
class _Version:
    numbers: tuple[int, int, int, int]
    stage: int
    stage_number: int

    def key(self) -> tuple[tuple[int, int, int, int], int, int]:
        return self.numbers, self.stage, self.stage_number


@dataclass(frozen=True)
class _Evidence:
    components: dict[str, tuple[str, str]]
    dependencies: dict[str, tuple[str, str]]
    config: dict[str, bool]
    classes: frozenset[str]
    symbols: frozenset[str]
    present: frozenset[str]


_CONFIG_KEYS = frozenset(
    {
        "activemq.openwire_network_access",
        "tomcat.default_servlet_writes",
        "tomcat.partial_put",
        "tomcat.file_session_persistence_default",
        "pytorch.weights_only",
        "pytorch.untrusted_checkpoint",
        "pytorch.legacy_tar",
        "dotnet.unsafe_binaryformatter_enabled",
        "dotnet.untrusted_input_reaches_deserialize",
        "log4j.message_lookups_enabled",
        "log4j.untrusted_message_data",
        "log4j.jndi_endpoint_reachable",
    }
)

_TOMCAT_GADGET_CLASSES = frozenset(
    {
        "org.apache.commons.collections.functors.InvokerTransformer",
        "org.apache.commons.collections4.functors.InvokerTransformer",
        "org.apache.commons.beanutils.BeanComparator",
        "com.sun.syndication.feed.impl.ObjectBean",
        "com.rometools.rome.feed.impl.ObjectBean",
        "org.codehaus.groovy.runtime.ConvertedClosure",
    }
)

_LOG4J_LOCAL_ENHANCERS = frozenset(
    {
        "org.apache.naming.factory.BeanFactory",
        "javax.el.ELProcessor",
        "org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
    }
)


_RULES: tuple[dict[str, Any], ...] = (
    {
        "id": "CVE-2023-46604",
        "profile": "activemq-classic-spring-string-constructor",
        "kind": "cve",
        "title": "ActiveMQ Java OpenWire arbitrary class instantiation",
        "aliases": (
            "apache activemq",
            "apache activemq classic",
            "activemq",
            "activemq classic",
            "apache activemq legacy openwire module",
            "activemq legacy openwire module",
            "org.apache.activemq:activemq-client",
            "org.apache.activemq:activemq-openwire-legacy",
        ),
        "affected": (
            "Classic <5.15.16; >=5.16.0,<5.16.7; >=5.17.0,<5.17.6; "
            ">=5.18.0,<5.18.3 (legacy OpenWire module lower bound: 5.8.0)"
        ),
        "config": (("activemq.openwire_network_access", True),),
        "classes_any": ("org.springframework.context.support.ClassPathXmlApplicationContext",),
        "sources": (
            "https://activemq.apache.org/news/cve-2023-46604",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-46604",
        ),
        "note": (
            "This is Apache's documented known Spring String-constructor exploitation profile; "
            "an affected OpenWire marshaller without this class is still upgrade-worthy."
        ),
    },
    {
        "id": "CVE-2025-24813",
        "profile": "tomcat-partial-put-session-deserialization-rce",
        "kind": "cve",
        "title": "Tomcat partial PUT to file-backed session deserialization",
        "aliases": (
            "apache tomcat",
            "tomcat",
            "org.apache.tomcat.embed:tomcat-embed-core",
            "org.apache.tomcat:tomcat-catalina",
        ),
        "affected": (
            "8.5.0..8.5.100 (EOL, no fixed 8.5 release); 9.0.0-M1..<9.0.99; "
            "10.1.0-M1..<10.1.35; 11.0.0-M1..<11.0.3"
        ),
        "config": (
            ("tomcat.default_servlet_writes", True),
            ("tomcat.partial_put", True),
            ("tomcat.file_session_persistence_default", True),
        ),
        "classes_any": tuple(sorted(_TOMCAT_GADGET_CLASSES)),
        "sources": (
            "https://lists.apache.org/thread/j5fkjv2k477os90nczf2v9l61fb0kkgq",
            "https://tomcat.apache.org/security-9.html",
            "https://tomcat.apache.org/security-10.html",
            "https://tomcat.apache.org/security-11.html",
        ),
        "note": (
            "Apache states that every listed configuration condition and a deserialization-capable "
            "library are required for the RCE path. A recognized class is a precondition lead, not "
            "proof that a complete gadget chain executes."
        ),
    },
    {
        "id": "CVE-2025-32434",
        "profile": "pytorch-weights-only-legacy-tar",
        "kind": "cve",
        "title": "PyTorch weights_only legacy-tar restricted-unpickler bypass",
        "aliases": ("pytorch", "torch"),
        "affected": "<=2.5.1 (patched in 2.6.0)",
        "config": (
            ("pytorch.weights_only", True),
            ("pytorch.untrusted_checkpoint", True),
            ("pytorch.legacy_tar", True),
        ),
        "symbols_any": ("torch.load",),
        "sources": (
            "https://github.com/pytorch/pytorch/security/advisories/GHSA-53q9-r3pm-6pq6",
            "https://github.com/pytorch/pytorch/commit/8d4b8a920a2172523deb95bf20e8e52d50649c04",
        ),
        "note": (
            "weights_only=False is unsafe by design but is not this CVE profile; the documented "
            "bypass requires the weights-only path and legacy tar serialization."
        ),
    },
    {
        "id": "DOTNET-9-BINARYFORMATTER-COMPAT",
        "profile": "dotnet9-unsafe-binaryformatter-restored",
        "kind": "platform-control",
        "title": ".NET 9+ unsafe compatibility package restores BinaryFormatter",
        "aliases": (".net", "dotnet", "microsoft.netcore.app"),
        "affected": ">=9.0 (in-box implementation otherwise always throws)",
        "config": (
            ("dotnet.unsafe_binaryformatter_enabled", True),
            ("dotnet.untrusted_input_reaches_deserialize", True),
        ),
        "dependencies_any": ("system.runtime.serialization.formatters",),
        "classes_any": ("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter",),
        "symbols_any": ("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Deserialize",),
        "sources": (
            "https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-migration-guide/",
            "https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-migration-guide/compatibility-package",
        ),
        "note": (
            "This is a platform-control state, not a CVE. On .NET 9+ the old switch alone cannot "
            "restore BinaryFormatter; the unsupported package and unsafe switch are both required."
        ),
    },
    {
        "id": "CVE-2021-44228",
        "profile": "log4j-core-message-jndi-lookup",
        "kind": "cve",
        "title": "Log4j Core attacker-controlled message JNDI lookup",
        "aliases": ("log4j-core", "org.apache.logging.log4j:log4j-core"),
        "affected": "[2.0-beta9,2.3.1) U [2.4,2.12.2) U [2.13.0,2.15.0)",
        "config": (
            ("log4j.message_lookups_enabled", True),
            ("log4j.untrusted_message_data", True),
            ("log4j.jndi_endpoint_reachable", True),
        ),
        "classes_all": (
            "org.apache.logging.log4j.core.lookup.JndiLookup",
            "org.apache.logging.log4j.core.net.JndiManager",
        ),
        "sources": ("https://logging.apache.org/security.html#CVE-2021-44228",),
        "note": (
            "log4j-api alone is not affected. Local JNDI object-factory gadget classes are optional "
            "enhancers, not mandatory gates for Apache's base LDAP code-loading CVE description."
        ),
    },
)


def _duplicate_reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WebDeser2Error(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _strict_object(value: Any) -> dict[str, Any]:
    try:
        if isinstance(value, Mapping):
            raw = json.dumps(dict(value), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        elif isinstance(value, str):
            raw = value.encode("utf-8", "strict")
        elif isinstance(value, (bytes, bytearray, memoryview)):
            raw = bytes(value)
        else:
            raise WebDeser2Error("evidence must be a JSON object, text, or bytes")
    except WebDeser2Error:
        raise
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError) as exc:
        raise WebDeser2Error("evidence is not bounded JSON") from exc
    if not raw or len(raw) > MAX_JSON_BYTES:
        raise WebDeser2Error(f"evidence is empty or exceeds {MAX_JSON_BYTES} bytes")
    try:
        parsed = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_duplicate_reject,
            parse_constant=lambda item: (_ for _ in ()).throw(
                WebDeser2Error(f"non-standard JSON number {item}")
            ),
        )
    except WebDeser2Error:
        raise
    except (UnicodeError, ValueError, OverflowError, RecursionError) as exc:
        raise WebDeser2Error("invalid evidence JSON") from exc
    if not isinstance(parsed, dict):
        raise WebDeser2Error("evidence must be a JSON object")
    stack: list[tuple[Any, int]] = [(parsed, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise WebDeser2Error("evidence exceeds JSON tree bounds")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif item is None or isinstance(item, (bool, int, float, str)):
            continue
        else:
            raise WebDeser2Error("evidence contains a non-JSON value")
    return parsed


def _bounded_text(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise WebDeser2Error(f"{label} must be text")
    text = value.strip()
    if not text or len(text) > MAX_TEXT or "\x00" in text:
        raise WebDeser2Error(f"{label} is empty or exceeds its text cap")
    try:
        text.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise WebDeser2Error(f"{label} is not valid Unicode text") from exc
    return text


_VERSION_RE = re.compile(
    r"^[vV]?(?P<base>[0-9]+(?:\.[0-9]+){0,3})(?:[-.]?(?P<tag>alpha|beta|m|rc)(?P<num>[0-9]+))?$",
    re.IGNORECASE,
)
_STAGES = {"alpha": 0, "beta": 1, "m": 2, "rc": 3}


def _parse_version(value: str) -> _Version:
    if not isinstance(value, str) or len(value) > 64:
        raise WebDeser2Error("version must be bounded text")
    match = _VERSION_RE.fullmatch(value.strip())
    if not match:
        raise WebDeser2Error(f"unsupported version syntax {value!r}")
    try:
        numbers = tuple(int(part) for part in match.group("base").split("."))
        stage_number = int(match.group("num") or 0)
    except (ValueError, OverflowError) as exc:
        raise WebDeser2Error(f"invalid version {value!r}") from exc
    if any(part > 1_000_000_000 for part in numbers) or stage_number > 1_000_000_000:
        raise WebDeser2Error("version component exceeds its cap")
    padded = numbers + (0,) * (4 - len(numbers))
    tag = match.group("tag")
    return _Version(padded, _STAGES[tag.casefold()] if tag else 4, stage_number)


def _name(value: Any, label: str) -> tuple[str, str]:
    display = _bounded_text(value, label)
    return display.casefold(), display


def _component_rows(value: Any, label: str) -> dict[str, tuple[str, str]]:
    if not isinstance(value, list) or len(value) > MAX_COMPONENTS:
        raise WebDeser2Error(f"{label} must be a list of at most {MAX_COMPONENTS} records")
    result: dict[str, tuple[str, str]] = {}
    for index, row in enumerate(value):
        if not isinstance(row, dict) or set(row) != {"name", "version"}:
            raise WebDeser2Error(f"{label}[{index}] must contain exactly name and version")
        normalized, display = _name(row["name"], f"{label}[{index}].name")
        version = _bounded_text(row["version"], f"{label}[{index}].version")
        _parse_version(version)
        if normalized in result:
            raise WebDeser2Error(f"duplicate {label} name {display!r}")
        result[normalized] = (display, version)
    return result


def _text_set(value: Any, label: str) -> frozenset[str]:
    if not isinstance(value, list) or len(value) > MAX_FACTS:
        raise WebDeser2Error(f"{label} must be a list of at most {MAX_FACTS} strings")
    result: set[str] = set()
    for index, item in enumerate(value):
        text = _bounded_text(item, f"{label}[{index}]")
        if text in result:
            raise WebDeser2Error(f"duplicate {label} fact {text!r}")
        result.add(text)
    return frozenset(result)


def _normalize(value: Any) -> _Evidence:
    obj = _strict_object(value)
    allowed = {"products", "dependencies", "config", "classes", "symbols"}
    unknown = sorted(set(obj) - allowed)
    if unknown:
        raise WebDeser2Error(f"unknown evidence fields: {', '.join(unknown)}")
    products = _component_rows(obj["products"], "products") if "products" in obj else {}
    dependencies = (
        _component_rows(obj["dependencies"], "dependencies") if "dependencies" in obj else {}
    )
    config: dict[str, bool] = {}
    if "config" in obj:
        raw_config = obj["config"]
        if not isinstance(raw_config, dict) or len(raw_config) > MAX_FACTS:
            raise WebDeser2Error(f"config must be an object of at most {MAX_FACTS} booleans")
        for raw_key, raw_value in raw_config.items():
            key = _bounded_text(raw_key, "config key")
            if key not in _CONFIG_KEYS:
                raise WebDeser2Error(f"unknown config fact {key!r}")
            if not isinstance(raw_value, bool):
                raise WebDeser2Error(f"config fact {key!r} must be boolean")
            config[key] = raw_value
    classes = _text_set(obj["classes"], "classes") if "classes" in obj else frozenset()
    symbols = _text_set(obj["symbols"], "symbols") if "symbols" in obj else frozenset()
    return _Evidence(products, dependencies, config, classes, symbols, frozenset(obj))


def _cmp(left: _Version, right: str) -> int:
    lkey, rkey = left.key(), _parse_version(right).key()
    return (lkey > rkey) - (lkey < rkey)


def _affected(rule_id: str, version: _Version, component: str = "") -> bool:
    if rule_id == "CVE-2023-46604":
        # The CNA/NVD range for the separately named legacy OpenWire module
        # begins at 5.8.0.  Classic itself is listed as affected below
        # 5.15.16 without that lower bound.
        before_51516 = _cmp(version, "5.15.16") < 0
        if component.casefold() in {
            "apache activemq legacy openwire module",
            "activemq legacy openwire module",
            "org.apache.activemq:activemq-openwire-legacy",
        }:
            before_51516 = _cmp(version, "5.8.0") >= 0 and before_51516
        return (
            before_51516
            or (_cmp(version, "5.16.0") >= 0 and _cmp(version, "5.16.7") < 0)
            or (_cmp(version, "5.17.0") >= 0 and _cmp(version, "5.17.6") < 0)
            or (_cmp(version, "5.18.0") >= 0 and _cmp(version, "5.18.3") < 0)
        )
    if rule_id == "CVE-2025-24813":
        return (
            (_cmp(version, "8.5.0") >= 0 and _cmp(version, "8.5.100") <= 0)
            or (_cmp(version, "9.0.0-M1") >= 0 and _cmp(version, "9.0.99") < 0)
            or (_cmp(version, "10.1.0-M1") >= 0 and _cmp(version, "10.1.35") < 0)
            or (_cmp(version, "11.0.0-M1") >= 0 and _cmp(version, "11.0.3") < 0)
        )
    if rule_id == "CVE-2025-32434":
        return _cmp(version, "2.5.1") <= 0
    if rule_id == "DOTNET-9-BINARYFORMATTER-COMPAT":
        return _cmp(version, "9.0") >= 0
    if rule_id == "CVE-2021-44228":
        return (
            (_cmp(version, "2.0-beta9") >= 0 and _cmp(version, "2.3.1") < 0)
            or (_cmp(version, "2.4") >= 0 and _cmp(version, "2.12.2") < 0)
            or (_cmp(version, "2.13.0") >= 0 and _cmp(version, "2.15.0") < 0)
        )
    raise WebDeser2Error(f"unknown catalog rule {rule_id!r}")


def _version_fact(evidence: _Evidence, aliases: Sequence[str]) -> tuple[str, str] | None:
    wanted = {alias.casefold() for alias in aliases}
    found: list[tuple[str, str]] = []
    for table in (evidence.components, evidence.dependencies):
        found.extend(value for key, value in table.items() if key in wanted)
    if not found:
        return None
    versions = {version for _, version in found}
    if len(versions) != 1:
        rendered = ", ".join(f"{name}={version}" for name, version in found)
        raise WebDeser2Error(f"conflicting component versions: {rendered}")
    return found[0]


def _gate(kind: str, name: str, state: str, expected: Any, observed: Any, rationale: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "name": name,
        "state": state,
        "expected": expected,
        "observed": observed,
        "rationale": rationale,
    }


def _any_exact_gate(
    evidence: _Evidence,
    *,
    field: str,
    expected: Sequence[str],
    kind: str,
    name: str,
) -> dict[str, Any]:
    if field not in evidence.present:
        return _gate(kind, name, "unknown", list(expected), None, f"{field} evidence was not supplied")
    if field == "classes":
        matches = sorted(evidence.classes & set(expected))
    elif field == "symbols":
        matches = sorted(evidence.symbols & set(expected))
    elif field == "dependencies":
        normalized_expected = {item.casefold() for item in expected}
        matches = sorted(
            evidence.dependencies[item][0] for item in set(evidence.dependencies) & normalized_expected
        )
    else:
        raise WebDeser2Error(f"unknown exact-match gate field {field!r}")
    return _gate(
        kind,
        name,
        "satisfied" if matches else "not_satisfied",
        list(expected),
        matches,
        "exact match required; substrings and inferred transitive dependencies are not accepted",
    )


def _all_exact_class_gate(evidence: _Evidence, expected: Sequence[str]) -> dict[str, Any]:
    if "classes" not in evidence.present:
        return _gate(
            "class",
            "classes_all",
            "unknown",
            list(expected),
            None,
            "classes evidence was not supplied",
        )
    matched = sorted(evidence.classes & set(expected))
    missing = sorted(set(expected) - evidence.classes)
    return _gate(
        "class",
        "classes_all",
        "satisfied" if not missing else "not_satisfied",
        list(expected),
        {"matched": matched, "missing": missing},
        "every exact class is required; substrings and inferred transitive classes are not accepted",
    )


def _assess(rule: Mapping[str, Any], evidence: _Evidence) -> dict[str, Any]:
    gates: list[dict[str, Any]] = []
    version_fact = _version_fact(evidence, rule["aliases"])
    if version_fact is None:
        gates.append(
            _gate(
                "version",
                "affected_version",
                "unknown",
                rule["affected"],
                None,
                "no exact product or dependency alias with a version was supplied",
            )
        )
    else:
        product, raw_version = version_fact
        in_range = _affected(str(rule["id"]), _parse_version(raw_version), product)
        gates.append(
            _gate(
                "version",
                "affected_version",
                "satisfied" if in_range else "not_satisfied",
                rule["affected"],
                {"name": product, "version": raw_version},
                "version compared only against the vendor-published range",
            )
        )
    for key, expected in rule.get("config", ()):
        if key not in evidence.config:
            state, observed = "unknown", None
        else:
            observed = evidence.config[key]
            state = "satisfied" if observed is expected else "not_satisfied"
        gates.append(
            _gate(
                "configuration",
                key,
                state,
                expected,
                observed,
                "effective deployment state must be supplied explicitly",
            )
        )
    for field, kind, key in (
        ("dependencies", "dependency", "dependencies_any"),
        ("classes", "class", "classes_any"),
        ("symbols", "sink", "symbols_any"),
    ):
        expected_items = rule.get(key)
        if expected_items:
            gates.append(
                _any_exact_gate(
                    evidence, field=field, expected=expected_items, kind=kind, name=key
                )
            )
    if rule.get("classes_all"):
        gates.append(_all_exact_class_gate(evidence, rule["classes_all"]))
    states = {gate["state"] for gate in gates}
    status = (
        "not_satisfied"
        if "not_satisfied" in states
        else "insufficient_evidence"
        if "unknown" in states
        else "preconditions_satisfied"
    )
    result: dict[str, Any] = {
        "id": rule["id"],
        "profile": rule["profile"],
        "kind": rule["kind"],
        "title": rule["title"],
        "status": status,
        "gates": gates,
        "sources": list(rule["sources"]),
        "note": rule["note"],
    }
    if rule["id"] == "CVE-2021-44228" and "classes" in evidence.present:
        result["optional_local_gadget_enhancers"] = sorted(evidence.classes & _LOG4J_LOCAL_ENHANCERS)
    return result


def precondition_catalog() -> tuple[dict[str, Any], ...]:
    """Return fixed, provenance-tagged rule metadata without mutable internals."""

    rows: list[dict[str, Any]] = []
    for rule in _RULES:
        rows.append(
            {
                "id": rule["id"],
                "profile": rule["profile"],
                "kind": rule["kind"],
                "title": rule["title"],
                "component_aliases": list(rule["aliases"]),
                "affected": rule["affected"],
                "configuration_gates": [key for key, _ in rule.get("config", ())],
                "dependency_gates": list(rule.get("dependencies_any", ())),
                "class_gates": list(rule.get("classes_any", ())) + list(rule.get("classes_all", ())),
                "class_gate_mode": "all" if rule.get("classes_all") else "any",
                "sink_gates": list(rule.get("symbols_any", ())),
                "sources": list(rule["sources"]),
                "note": rule["note"],
            }
        )
    return tuple(rows)


def analyze_evidence(evidence: Any) -> dict[str, Any]:
    """Evaluate supplied facts and expose only :class:`WebDeser2Error` on bad input."""

    try:
        normalized = _normalize(evidence)
        assessments = [_assess(rule, normalized) for rule in _RULES]
        satisfied = [
            {"id": row["id"], "profile": row["profile"], "kind": row["kind"]}
            for row in assessments
            if row["status"] == "preconditions_satisfied"
        ]
        return {
            "assessments": assessments,
            "satisfied": satisfied,
            "summary": {
                "preconditions_satisfied": len(satisfied),
                "not_satisfied": sum(row["status"] == "not_satisfied" for row in assessments),
                "insufficient_evidence": sum(
                    row["status"] == "insufficient_evidence" for row in assessments
                ),
            },
            "offline": True,
            "deserialized": False,
            "executed": False,
            "network_requests": 0,
        }
    except WebDeser2Error:
        raise
    except Exception as exc:
        raise WebDeser2Error("malformed deserialization precondition evidence") from exc


def _read_bounded(path: str) -> bytes:
    try:
        value = Path(path)
        if not value.is_file() or value.stat().st_size > MAX_JSON_BYTES:
            raise WebDeser2Error(f"evidence file is absent or exceeds {MAX_JSON_BYTES} bytes")
        with value.open("rb") as handle:
            raw = handle.read(MAX_JSON_BYTES + 1)
    except WebDeser2Error:
        raise
    except OSError as exc:
        raise WebDeser2Error("cannot read evidence file") from exc
    if len(raw) > MAX_JSON_BYTES:
        raise WebDeser2Error(f"evidence file exceeds {MAX_JSON_BYTES} bytes")
    return raw


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="evaluate one local JSON evidence file")
    analyze.add_argument("evidence")
    sub.add_parser("catalog", help="print rule metadata and authoritative sources")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        if argv is not None and not all(isinstance(item, str) for item in argv):
            raise WebDeser2Error("argv elements must be text")
        try:
            args = _parser().parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2
        if args.command == "catalog":
            result: Any = {
                "catalog": precondition_catalog(),
                "offline": True,
                "deserialized": False,
                "executed": False,
                "network_requests": 0,
            }
        else:
            result = analyze_evidence(_read_bounded(args.evidence))
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
        return 0
    except WebDeser2Error as exc:
        print(f"webdeser2_preconditions: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
