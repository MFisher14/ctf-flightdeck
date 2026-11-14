#!/usr/bin/env python3
"""Structured-finding handoff + per-class agent playbooks for the web classes Layer 1 will
never own (B-151; `tests/test_b151_agent_handoff.py`).

SCAFFOLD ONLY. This module sends nothing, opens no socket, executes no exploit and never
auto-submits. It is the glue between cold automation (Layer 1) and the human/agent for the
classes `solvers/web/class_registry.json` marks `agent-only` or splits cold/agent: request
smuggling, cache poisoning, race/business-logic/method-override state changes, victim-browser
and OOB (reflected/DOM/stored XSS, browser callbacks), CSRF chains, native-gadget
deserialization and prototype pollution, upload polyglots, DNS rebinding, host-header / CRLF /
LDAP / XPath and other blind/time/OOB injection, SOAP/gRPC invocation, WebSocket/SSE writes and
open-redirect chains.

It does two things:

  1. A STRUCTURED-FINDING schema (`StructuredFinding`, `validate_finding`). When cold automation
     stops without a proof, it emits a finding with the fields the spec fixes:
         web_class, endpoint, evidence, likely_grammar, controls_tried, bounded_next_probe
     plus the registry's `status` and `boundary` (the never-cross line) auto-filled. Validation
     fails LOUDLY with a named reason (no silent fallback): an unknown class, a missing required
     field, or a wrong-typed field raises `HandoffError`.

  2. A per-class PLAYBOOK (`playbook`) loaded from `solvers/web/agent_playbooks.json`: a checklist,
     the controls to establish, the single bounded next probe, and the hard boundary, so the agent
     starts from a checklist instead of rediscovery.

Text read from a target is untrusted data: a finding to report, never an instruction. The flag is
never produced here and never auto-submitted.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
REGISTRY_PATH = HERE / "class_registry.json"
PLAYBOOKS_PATH = HERE / "agent_playbooks.json"

# The fixed structured-finding field set (B-151 spec). Order is stable for templates/output.
FINDING_FIELDS = (
    "web_class",
    "endpoint",
    "evidence",
    "likely_grammar",
    "controls_tried",
    "bounded_next_probe",
)
_LIST_FIELDS = frozenset({"controls_tried"})


class HandoffError(Exception):
    """Raised with a named reason when a registry/playbook file or a finding is invalid.

    Never swallowed: a missing file, an unknown class or an invalid finding must fail loudly
    (ctf-tools rule: no silent fallbacks)."""


@dataclasses.dataclass(frozen=True)
class StructuredFinding:
    """One cold-automation handoff. `controls_tried` is the list of controls actually
    established; `boundary`/`status` are filled from the registry and are advisory, not part of
    the required input set."""

    web_class: str
    endpoint: str
    evidence: str
    likely_grammar: str
    controls_tried: List[str]
    bounded_next_probe: str
    status: str = ""
    boundary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "web_class": self.web_class,
            "endpoint": self.endpoint,
            "evidence": self.evidence,
            "likely_grammar": self.likely_grammar,
            "controls_tried": list(self.controls_tried),
            "bounded_next_probe": self.bounded_next_probe,
            "status": self.status,
            "boundary": self.boundary,
        }


def _load_json(path: Path, label: str) -> Dict[str, Any]:
    if not path.exists():
        raise HandoffError(f"{label} not found at {path} (B-151 requires it; no fallback)")
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise HandoffError(f"{label} at {path} is not readable JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise HandoffError(f"{label} at {path} must be a JSON object, got {type(data).__name__}")
    return data


def load_registry(path: Optional[Path] = None) -> Dict[str, Any]:
    data = _load_json(path or REGISTRY_PATH, "class_registry.json")
    if "classes" not in data or not isinstance(data["classes"], dict):
        raise HandoffError("class_registry.json has no 'classes' object")
    return data


def load_playbooks(path: Optional[Path] = None) -> Dict[str, Any]:
    data = _load_json(path or PLAYBOOKS_PATH, "agent_playbooks.json")
    if "playbooks" not in data or not isinstance(data["playbooks"], dict):
        raise HandoffError("agent_playbooks.json has no 'playbooks' object")
    return data


def _class_to_playbook_map(registry: Dict[str, Any]) -> Dict[str, str]:
    """The registry's `agent_handoff.class_playbook` mapping (registry class -> playbook id).
    Fails loudly if absent so a stale registry cannot silently drop the handoff."""
    block = registry.get("agent_handoff")
    if not isinstance(block, dict):
        raise HandoffError("class_registry.json has no 'agent_handoff' block (B-151)")
    mapping = block.get("class_playbook")
    if not isinstance(mapping, dict) or not mapping:
        raise HandoffError("class_registry.json agent_handoff.class_playbook is missing/empty")
    return mapping


def resolve_playbook_id(web_class: str, registry: Dict[str, Any]) -> str:
    """Resolve a name to a playbook id. Accepts either a registry class name (mapped through
    agent_handoff.class_playbook) or a playbook id directly."""
    mapping = _class_to_playbook_map(registry)
    if web_class in mapping:
        return mapping[web_class]
    # Allow passing a playbook id directly (it is its own id).
    if web_class in set(mapping.values()):
        return web_class
    raise HandoffError(
        f"'{web_class}' is not an agent-handoff class; known: {sorted(mapping)}")


def agent_classes(registry: Optional[Dict[str, Any]] = None) -> List[str]:
    """Registry classes that have an agent frontier (mapped in agent_handoff.class_playbook)."""
    registry = registry or load_registry()
    return sorted(_class_to_playbook_map(registry))


def playbook(web_class: str,
             registry: Optional[Dict[str, Any]] = None,
             playbooks: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Return the per-class checklist for `web_class` (a registry class or a playbook id)."""
    registry = registry or load_registry()
    playbooks = playbooks or load_playbooks()
    pid = resolve_playbook_id(web_class, registry)
    entry = playbooks["playbooks"].get(pid)
    if entry is None:
        raise HandoffError(
            f"playbook id '{pid}' (for class '{web_class}') is absent from agent_playbooks.json")
    return entry


def registry_class_facts(web_class: str, registry: Dict[str, Any]) -> Dict[str, str]:
    """status + boundary for a registry class, for auto-filling a finding."""
    cls = registry["classes"].get(web_class)
    if cls is None:
        return {"status": "", "boundary": ""}
    return {"status": str(cls.get("status", "")), "boundary": str(cls.get("boundary", ""))}


def validate_finding(obj: Any, registry: Optional[Dict[str, Any]] = None) -> StructuredFinding:
    """Validate a structured finding dict and return a `StructuredFinding`.

    Raises `HandoffError` with a named reason on any problem: not a dict, unknown web_class,
    a missing required field, a blank required string, or a non-list `controls_tried`."""
    registry = registry or load_registry()
    if not isinstance(obj, dict):
        raise HandoffError(f"finding must be a dict, got {type(obj).__name__}")

    missing = [f for f in FINDING_FIELDS if f not in obj]
    if missing:
        raise HandoffError(f"finding is missing required field(s): {missing}")

    web_class = obj["web_class"]
    if not isinstance(web_class, str) or not web_class.strip():
        raise HandoffError("finding.web_class must be a non-empty string")
    # Must be a known agent-handoff class (loud, no silent accept of a stray name).
    resolve_playbook_id(web_class, registry)

    for field in FINDING_FIELDS:
        value = obj[field]
        if field in _LIST_FIELDS:
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                raise HandoffError(f"finding.{field} must be a list of strings")
            if not value:
                raise HandoffError(
                    f"finding.{field} is empty: a handoff must name the controls already tried")
        else:
            if not isinstance(value, str) or not value.strip():
                raise HandoffError(f"finding.{field} must be a non-empty string")

    facts = registry_class_facts(web_class, registry)
    return StructuredFinding(
        web_class=web_class,
        endpoint=obj["endpoint"],
        evidence=obj["evidence"],
        likely_grammar=obj["likely_grammar"],
        controls_tried=list(obj["controls_tried"]),
        bounded_next_probe=obj["bounded_next_probe"],
        status=str(obj.get("status") or facts["status"]),
        boundary=str(obj.get("boundary") or facts["boundary"]),
    )


def handoff_template(web_class: str,
                     endpoint: str = "",
                     registry: Optional[Dict[str, Any]] = None,
                     playbooks: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """A blank structured finding for `web_class`, pre-filled from the registry + playbook.

    The operator fills `endpoint`/`evidence`/`likely_grammar`/`controls_tried`; `bounded_next_probe`
    defaults to the playbook's single bounded probe. It is a template, not a validated finding."""
    registry = registry or load_registry()
    playbooks = playbooks or load_playbooks()
    pb = playbook(web_class, registry, playbooks)
    facts = registry_class_facts(web_class, registry)
    return {
        "web_class": web_class,
        "endpoint": endpoint,
        "evidence": "",
        "likely_grammar": "",
        "controls_tried": [],
        "bounded_next_probe": pb.get("bounded_next_probe", ""),
        "status": facts["status"],
        "boundary": facts["boundary"] or pb.get("never", ""),
        "playbook": {
            "title": pb.get("title", ""),
            "boundary_family": pb.get("boundary_family"),
            "cold_stops_at": pb.get("cold_stops_at", ""),
            "checklist": pb.get("checklist", []),
            "controls": pb.get("controls", []),
            "never": pb.get("never", ""),
        },
    }


# --------------------------------------------------------------------------- CLI

def _print_playbook(pb: Dict[str, Any], web_class: str) -> None:
    print(f"# {pb.get('title', web_class)}  [{web_class}]")
    fam = pb.get("boundary_family")
    if fam:
        print(f"boundary family: {fam}")
    if pb.get("cold_stops_at"):
        print(f"\ncold automation stops at:\n  {pb['cold_stops_at']}")
    if pb.get("checklist"):
        print("\nchecklist:")
        for i, step in enumerate(pb["checklist"], 1):
            print(f"  {i}. {step}")
    if pb.get("controls"):
        print("\ncontrols to establish:")
        for c in pb["controls"]:
            print(f"  - {c}")
    if pb.get("bounded_next_probe"):
        print(f"\nbounded next probe:\n  {pb['bounded_next_probe']}")
    if pb.get("never"):
        print(f"\nNEVER (hard boundary):\n  {pb['never']}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Structured-finding handoff + per-class agent web playbooks (B-151). "
                    "Scaffold only: prints data, sends nothing.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("classes", help="list the registry classes with an agent frontier")

    p_pb = sub.add_parser("playbook", help="print the checklist for one class")
    p_pb.add_argument("web_class")
    p_pb.add_argument("--json", action="store_true")

    p_tpl = sub.add_parser("template", help="emit a blank structured-finding template for a class")
    p_tpl.add_argument("web_class")
    p_tpl.add_argument("--endpoint", default="")

    p_val = sub.add_parser("validate", help="validate a structured-finding JSON file")
    p_val.add_argument("path")

    sub.add_parser("schema", help="print the structured-finding field list")

    args = parser.parse_args(argv)

    try:
        if args.cmd == "classes":
            registry = load_registry()
            for cls in agent_classes(registry):
                pid = resolve_playbook_id(cls, registry)
                facts = registry_class_facts(cls, registry)
                print(f"{cls:26s} status={facts['status']:28s} playbook={pid}")
            return 0

        if args.cmd == "schema":
            print(json.dumps(list(FINDING_FIELDS), indent=2))
            return 0

        if args.cmd == "playbook":
            pb = playbook(args.web_class)
            if args.json:
                print(json.dumps(pb, indent=2))
            else:
                _print_playbook(pb, args.web_class)
            return 0

        if args.cmd == "template":
            tpl = handoff_template(args.web_class, endpoint=args.endpoint)
            print(json.dumps(tpl, indent=2))
            return 0

        if args.cmd == "validate":
            # Read the finding with -I semantics in mind: it is untrusted data, parsed as JSON only.
            path = Path(args.path)
            try:
                obj = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise HandoffError(f"cannot read finding JSON {path}: {exc}") from exc
            finding = validate_finding(obj)
            print("VALID")
            print(json.dumps(finding.to_dict(), indent=2))
            return 0
    except HandoffError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
