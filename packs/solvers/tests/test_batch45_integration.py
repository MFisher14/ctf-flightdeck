"""Batch-45 integration fixes.

B-151: `web.agent_handoff` landed with no `[[routes]]`, which the route lint rejects for an engine
that is not retired (tests/test_engines_lint.py). It now has one keyword route in the web category:
a brief that names a class the registry marks agent-only or agent-browser-only lists the handoff
playbook, after every cold engine. These tests fail if the route goes away, starts fronting a cold
engine, fires on a brief that names no such class, or names a class the registry does not hand to
the agent.

B-137: docs/CONTRACTS.md section 23 named the gate runner's red-status tuple as `runner.BAD`, which
the doc checker resolves to `ctf.engines.runner` (section 6). The doc now writes the full name, so
the reference is checked against the module that defines it.

Offline: no network, no challenge files.
"""
import json

from ctf import paths, triage
from ctf.engines import manifest

import test_contracts_doc as CD  # conftest puts tests/ on sys.path

HANDOFF = "solvers/web/agent_handoff.py"


def _routes(category, description):
    return triage.suggest(category, description)["routes"]


def test_agent_only_web_brief_lists_the_handoff_after_the_cold_engines():
    rs = _routes("web", "HTTP request smuggling between the front proxy and the backend")
    engines = [r["engine"] for r in rs]
    assert HANDOFF in engines
    assert engines[0] == "solvers/web/http_desync.py"          # the cold engine still fronts the brief
    assert engines[-1] == HANDOFF                              # the handoff comes after every cold engine
    hit = rs[-1]
    assert hit["id"] == "web.agent_handoff" and "request smuggling" in hit["reason"]
    assert all(r["priority"] > hit["priority"] for r in rs[:-1])


def test_handoff_is_not_suggested_without_an_agent_only_class_or_outside_web():
    assert HANDOFF not in [r["engine"] for r in _routes("web", "a plain login page with a cookie")]
    assert HANDOFF not in [r["engine"] for r in _routes("pwn", "a race condition in the allocator")]


def test_every_route_keyword_names_a_class_the_registry_hands_to_the_agent():
    """Each keyword maps to a registry class whose status is agent-only or agent-browser-only, and
    every such class has a keyword: the route cannot drift from the registry."""
    root = paths.repo_root()
    m = manifest.load(root / "solvers/web/agent_handoff.manifest.toml")
    assert m.status == "active" and len(m.routes) == 1
    route = m.routes[0]
    assert tuple(route.category) == ("web",) and not route.files
    reg = json.loads((root / "solvers/web/class_registry.json").read_text(encoding="utf-8"))["classes"]
    agent = {k for k, v in reg.items() if v["status"].split("/")[-1] in ("agent-only", "agent-browser-only")}
    keyword_class = {
        "request smuggling": "request_smuggling", "cache poisoning": "cache_poisoning",
        "race condition": "race", "business logic": "business_logic", "method override": "method_override",
        "reflected xss": "reflected_xss", "dom xss": "dom_xss", "dom-based xss": "dom_xss",
    }
    assert set(route.keywords) == set(keyword_class)
    assert set(keyword_class.values()) == agent


def test_section_23_names_the_gate_runner_bad_tuple_by_its_full_name():
    from ctf.gate import runner as gate_runner
    sec = CD.sections(CD.DOC.read_text(encoding="utf-8"))[23]
    refs = CD.references(sec, CD.doc_aliases(23, sec))
    assert refs.get("ctf.gate.runner.BAD") is True             # checked, and it exists
    assert "runner.BAD" not in refs                            # the short name means ctf.engines.runner
    assert "ENV" not in gate_runner.BAD                        # what the sentence claims
