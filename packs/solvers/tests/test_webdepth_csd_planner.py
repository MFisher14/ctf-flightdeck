"""Published-semantics tests for the offline browser CL.0/CSD planner."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

import webdepth_csd_planner as csd


def _supported_facts():
    return {name: True for name in csd.FACT_NAMES}


def test_browser_artifact_is_cors_simple_post_and_lengths_reference_h1_bytes():
    plan = csd.build_csd_plan(
        "https://control.example:8443",
        "/submit?mode=preview",
        marker_path="/__marker__",
        followup_path="/__next__",
        marker="WD_CSD_01",
        facts=_supported_facts(),
    )
    assert plan.readiness == "preconditions_supported"
    assert plan.vulnerability_claimed is False and plan.network_requests == 0

    # Fetch/CORS defines POST + text/plain as a safelisted request shape.  Host,
    # Content-Length, and Connection are browser-controlled forbidden headers;
    # the actual headers object contains only Content-Type.
    assert 'method: "POST", mode: "no-cors", credentials: "include"' in plan.browser_artifact
    header_line = next(line for line in plan.browser_artifact.splitlines() if "headers:" in line)
    assert '"Content-Type": "text/plain;charset=UTF-8"' in header_line
    assert all(name not in header_line for name in ("Host", "Content-Length", "Connection"))

    declared = int(
        next(line for line in plan.first_request_reference.split("\r\n")
             if line.startswith("Content-Length: ")).split(": ", 1)[1]
    )
    assert declared == len(plan.smuggled_body.encode("ascii"))
    assert plan.smuggled_body == (
        "GET /__marker__ HTTP/1.1\r\n"
        "Host: control.example:8443\r\n"
        "X-WebDepth-CSD: WD_CSD_01\r\n"
        "Connection: keep-alive\r\n\r\n"
    )
    assert plan.followup_request_reference.startswith("GET /__next__ HTTP/1.1\r\n")


def test_readiness_requires_http1_reuse_not_merely_an_early_response():
    facts = _supported_facts()
    facts["http1_reuse_observed"] = None
    readiness, requirements, blockers, unknown = csd.assess_csd_facts(facts)
    assert readiness == "unverified" and not blockers
    assert len(unknown) == 1 and "same HTTP/1.1 connection" in unknown[0]
    assert next(row for row in requirements if row.name == "early_response_observed").state == "satisfied"

    facts["http1_reuse_observed"] = True
    facts["h2_unavailable"] = False
    plan = csd.build_csd_plan("https://a.example", "/early", facts=facts)
    assert plan.readiness == "blocked"
    assert any("HTTP/1.1 rather than" in blocker for blocker in plan.blockers)
    assert "early response" in plan.false_positive_warning.lower()


def test_default_plan_is_explicitly_unverified_and_uses_reserved_inert_paths():
    plan = csd.build_csd_plan("http://127.0.0.1:8080", "/redirect")
    assert plan.readiness == "unverified"
    assert len(plan.unverified) == len(csd.FACT_NAMES)
    assert plan.marker_path == "/__webdepth_csd_marker__"
    assert "candidate only" not in plan.browser_artifact.lower()  # metadata, not an executable claim
    assert plan.candidate_only and plan.offline


@pytest.mark.parametrize(
    ("args", "kwargs"),
    [
        (("ftp://host.example", "/x"), {}),
        (("https://host.example/path", "/x"), {}),
        (("https://host.example", "relative"), {}),
        (("https://host.example", "/x\r\nInjected: 1"), {}),
        (("https://host.example", "/x"), {"marker": "bad marker"}),
        (("https://host.example", "/x"), {"facts": {"unknown": True}}),
        (("https://host.example", "/x"), {"facts": {"h2_unavailable": "yes"}}),
        ((123, "/x"), {}),
    ],
)
def test_public_builder_fails_only_with_declared_error(args, kwargs):
    with pytest.raises(csd.WebDepthCSDError):
        csd.build_csd_plan(*args, **kwargs)


def test_guarded_cli(capsys):
    assert csd.main(["--help"]) == 0
    capsys.readouterr()
    assert csd.main([]) == 2
    assert "Traceback" not in capsys.readouterr().err
    argv = ["https://target.example", "/early", "--json"]
    for name in csd.FACT_NAMES:
        argv.extend(("--" + name.replace("_", "-"), "yes"))
    assert csd.main(argv) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["readiness"] == "preconditions_supported"
    assert result["network_requests"] == 0


def test_module_has_no_transport_browser_or_execution_surface():
    path = Path(csd.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports = set()
    calls = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                calls.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                calls.add(node.func.attr)
    assert not imports.intersection({"socket", "requests", "httpx", "selenium", "playwright", "subprocess"})
    assert not calls.intersection({"connect", "send", "sendall", "urlopen", "request", "eval", "exec", "compile"})
