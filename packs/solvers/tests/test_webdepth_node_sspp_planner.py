"""Published-semantics tests for the offline Node server-side PP planner."""

from __future__ import annotations

import ast
import json
from pathlib import Path
import urllib.parse

import pytest

import webdepth_node_sspp_planner as sspp


def _report(**overrides):
    facts = {
        "node_version": "20.11.1",
        "source_paths": ["__proto__"],
        "proven_source": True,
        "sink_api": "fork",
        "call_shape": "options_omitted",
        "options_inherit": True,
        "platform": "linux",
        "blockers": [],
        "marker": "REFERENCE_MARKER",
        "reviewed_module_path": "/tmp/reviewed-marker.cjs",
    }
    facts.update(overrides)
    return sspp.analyze_node_sspp(**facts)


def _gadget(report, plan_id, path="__proto__"):
    return next(
        row for row in report["gadgets"]
        if row["plan_id"] == plan_id and row["source_path"] == path
    )


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        # Node's CLI documentation marks --import as added in v18.18.0 and
        # v19.0.0.  This table is an independent boundary matrix, not output
        # produced by the engine under test.
        ("17.9.1", False),
        ("18.17.1", False),
        ("18.18.0-rc.1", False),
        ("18.18.0", True),
        ("18.18.1", True),
        ("19.0.0", True),
        ("v20.0.0", True),
        ("22.13.1", True),
    ],
)
def test_node_import_published_version_boundary(version, expected):
    assert sspp.node_import_supported(version) is expected
    report = _report(node_version=version)
    assert report["facts"]["node_import_supported"] is expected
    candidate = _gadget(report, "node_options_import_data")
    assert (candidate["readiness"] == "ready_for_marker_review") is expected
    if not expected:
        assert any("18.18.0" in reason for reason in candidate["unmet"])


def test_ready_fork_plans_encode_documented_properties_and_marker_only_values():
    report = _report()
    assert report["summary"]["ready_count"] == 3
    assert report["offline"] and not report["sent"] and not report["executed"]

    direct = _gadget(report, "fork_execargv_eval")
    direct_doc = json.loads(direct["value"])
    assert direct_doc == {
        "__proto__": {"execArgv": ['--eval=console.log("REFERENCE_MARKER")']}
    }

    required = _gadget(report, "node_options_require")
    assert json.loads(required["value"])["__proto__"]["NODE_OPTIONS"] == (
        "--require=/tmp/reviewed-marker.cjs"
    )

    imported = _gadget(report, "node_options_import_data")
    option = json.loads(imported["value"])["__proto__"]["NODE_OPTIONS"]
    assert option.startswith("--import=data:text/javascript,")
    module_source = urllib.parse.unquote(option.split(",", 1)[1])
    assert module_source == 'console.log("REFERENCE_MARKER")'
    assert all(
        row["benign_marker_only"]
        and row["candidate_only"]
        and row["network_requests"] == 0
        and not row["executed"]
        for row in report["gadgets"]
    )


def test_version_alone_never_makes_a_gadget_ready():
    report = _report(
        source_paths=[],
        proven_source=False,
        sink_api="none",
        call_shape="unknown",
        options_inherit=False,
        reviewed_module_path=None,
    )
    assert report["facts"]["node_import_supported"] is True
    assert report["summary"]["ready_count"] == 0
    assert "version alone is insufficient" in report["summary"]["claim"]
    for row in report["gadgets"]:
        assert row["readiness"] == "blocked"
        assert any("source" in reason for reason in row["unmet"])
        assert any("inherited options" in reason for reason in row["unmet"])


def test_inert_source_encodings_and_benign_express_detectors_are_structural():
    report = _report(
        source_paths=["constructor.prototype", "__proto__"],
        proven_source=False,
    )
    # The engine canonicalizes caller order and emits query+JSON marker forms.
    assert report["facts"]["source_paths"] == ["__proto__", "constructor.prototype"]
    assert len(report["source_encodings"]) == 4
    assert len(report["detectors"]) == 6

    query = next(row for row in report["source_encodings"] if row["id"] == "__proto__:query_marker")
    parsed = urllib.parse.parse_qs(query["value"], strict_parsing=True)
    assert parsed == {"__proto__[webdepth_sspp_marker]": ["REFERENCE_MARKER"]}
    ctor = next(row for row in report["source_encodings"] if row["id"] == "constructor.prototype:json_marker")
    assert json.loads(ctor["value"]) == {
        "constructor": {"prototype": {"webdepth_sspp_marker": "REFERENCE_MARKER"}}
    }
    assert all(row["inert"] and row["network_requests"] == 0 for row in report["source_encodings"])

    proto_detectors = {
        row["property"]: json.loads(row["value"])["__proto__"][row["property"]]
        for row in report["detectors"]
        if row["source_path"] == "__proto__"
    }
    assert proto_detectors == {
        "status": 555,
        "json spaces": 2,
        "content-type": "application/json; charset=utf-7",
    }
    assert all(row["benign"] and row["negative_control"] for row in report["detectors"])


def test_disable_proto_blocks_only_proto_path_not_constructor_path():
    report = _report(
        source_paths=["__proto__", "constructor.prototype"],
        blockers=["disable-proto"],
    )
    assert report["facts"]["effective_source_paths"] == ["constructor.prototype"]
    assert {row["source_path"] for row in report["source_encodings"]} == {
        "constructor.prototype"
    }
    assert _gadget(report, "fork_execargv_eval", "__proto__")["readiness"] == "blocked"
    assert _gadget(report, "fork_execargv_eval", "constructor.prototype")["readiness"] == (
        "ready_for_marker_review"
    )


@pytest.mark.parametrize(
    ("sink", "shape", "import_ready"),
    [
        ("fork", "plain_options", True),
        ("cluster", "cluster_options", True),
        ("spawn", "node_binary_options", True),
        ("execfile", "node_binary_options", True),
        ("spawn", "plain_options", False),
        ("worker", "worker_options", False),
        ("cluster", "plain_options", False),
    ],
)
def test_node_options_requires_a_fresh_node_child_call_shape(sink, shape, import_ready):
    report = _report(sink_api=sink, call_shape=shape)
    imported = _gadget(report, "node_options_import_data")
    assert (imported["readiness"] == "ready_for_marker_review") is import_ready
    direct = _gadget(report, "fork_execargv_eval")
    assert (direct["readiness"] == "ready_for_marker_review") is (
        sink == "fork" and shape in {"plain_options", "options_omitted"}
    )


@pytest.mark.parametrize(
    "blocker",
    [
        "freeze-object-prototype",
        "own-properties-only",
        "null-prototype-options",
        "child-process-disabled",
        "unmodeled-mitigation",
    ],
)
def test_mitigation_blockers_override_optimistic_facts(blocker):
    report = _report(blockers=[blocker])
    assert report["summary"]["ready_count"] == 0
    assert all(row["readiness"] == "blocked" for row in report["gadgets"])


def test_gadget_specific_mitigations_do_not_overclaim_other_gadgets():
    execargv = _report(blockers=["strip-execargv"])
    assert _gadget(execargv, "fork_execargv_eval")["readiness"] == "blocked"
    assert _gadget(execargv, "node_options_import_data")["readiness"] == "ready_for_marker_review"

    node_options = _report(blockers=["strip-node-options"])
    assert _gadget(node_options, "fork_execargv_eval")["readiness"] == "ready_for_marker_review"
    assert _gadget(node_options, "node_options_require")["readiness"] == "blocked"
    assert _gadget(node_options, "node_options_import_data")["readiness"] == "blocked"


def test_require_plan_stays_blocked_until_reviewed_module_path_is_explicit():
    report = _report(reviewed_module_path=None)
    assert _gadget(report, "fork_execargv_eval")["readiness"] == "ready_for_marker_review"
    assert _gadget(report, "node_options_import_data")["readiness"] == "ready_for_marker_review"
    required = _gadget(report, "node_options_require")
    assert required["readiness"] == "blocked"
    assert any("reviewed local marker module" in reason for reason in required["unmet"])
    assert "REVIEWED_LOCAL_MARKER_MODULE.cjs" in required["value"]


class _ExplodingIterable:
    def __iter__(self):
        raise KeyError("must be normalized")


@pytest.mark.parametrize(
    "changes",
    [
        {"node_version": 20},
        {"node_version": "18.18"},
        {"node_version": "018.18.0"},
        {"node_version": "18.18.0-01"},
        {"source_paths": "__proto__"},
        {"source_paths": ["prototype"]},
        {"source_paths": _ExplodingIterable()},
        {"proven_source": 1},
        {"sink_api": "system"},
        {"call_shape": "magic_options"},
        {"options_inherit": "yes"},
        {"platform": "solaris"},
        {"blockers": "disable-proto"},
        {"blockers": ["unknown-mitigation"]},
        {"marker": 'x");process.exit()//'},
        {"reviewed_module_path": "relative/module.cjs"},
        {"platform": "windows", "reviewed_module_path": r"C:\Temp\has space.cjs"},
    ],
)
def test_all_malformed_public_inputs_raise_only_declared_error(changes):
    with pytest.raises(sspp.NodeSSPPError):
        _report(**changes)


def test_public_version_helper_uses_declared_error_only():
    for value in (None, {}, "", "19", "v19.0", "19.0.0.0"):
        with pytest.raises(sspp.NodeSSPPError):
            sspp.node_import_supported(value)


def test_input_iteration_is_bounded_and_reports_are_deterministic():
    first = _report()
    second = _report()
    assert first == second
    with pytest.raises(sspp.NodeSSPPError, match="exceeds"):
        _report(blockers=("disable-proto" for _ in range(sspp.MAX_ITERABLE_ITEMS + 1)))


def test_guarded_argparse_cli_returns_codes_and_json(capsys):
    assert sspp.main(["--does-not-exist"]) == 2
    assert "usage:" in capsys.readouterr().err
    assert sspp.main(["--help"]) == 0
    assert "offline server-side Node" in capsys.readouterr().out

    args = [
        "--node-version", "18.18.0",
        "--source-path", "constructor.prototype",
        "--proven-source",
        "--sink", "fork",
        "--call-shape", "plain_options",
        "--options-inherit",
        "--platform", "linux",
        "--reviewed-module-path", "/tmp/reviewed.cjs",
        "--json",
    ]
    assert sspp.main(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["facts"]["node_import_supported"] is True
    assert report["summary"]["ready_count"] == 3
    assert report["network_requests"] == 0


def test_module_has_no_network_process_dynamic_execution_or_file_runtime():
    path = Path(sspp.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    forbidden_imports = {
        "asyncio", "http", "httpx", "os", "requests", "socket", "subprocess",
        "urllib", "webbrowser",
    }
    imports: set[str] = set()
    direct_calls: set[str] = set()
    attribute_calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                direct_calls.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                attribute_calls.add(node.func.attr)
    assert not imports.intersection(forbidden_imports)
    assert not direct_calls.intersection({"eval", "exec", "compile", "open", "__import__"})
    assert not attribute_calls.intersection({"connect", "request", "urlopen", "Popen", "system"})

