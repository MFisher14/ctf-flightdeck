#!/usr/bin/env python3
"""B-151: structured-finding handoff + per-class agent web playbooks.

Fully offline: no network, no target, no external tool. Exercises the schema validator (it must
fail loudly on bad findings), the playbook completeness invariant (every agent-frontier registry
class has a playbook), the never-auto-execute boundary on every playbook, the handoff template,
and the CLI. Each assertion fails when the behaviour is wrong.
"""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
MODFILE = REPO / "solvers" / "web" / "agent_handoff.py"
REGFILE = REPO / "solvers" / "web" / "class_registry.json"
PBFILE = REPO / "solvers" / "web" / "agent_playbooks.json"


def _load_module():
    spec = importlib.util.spec_from_file_location("b151_agent_handoff", MODFILE)
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so dataclasses can resolve the module namespace (KW_ONLY check).
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


H = _load_module()


def _valid_finding(web_class="request_smuggling"):
    return {
        "web_class": web_class,
        "endpoint": "POST https://target.example/api/convert",
        "evidence": "front-end Cloudfront, back-end gunicorn; CL and TE both honoured in a saved exchange",
        "likely_grammar": "CL.TE desync",
        "controls_tried": ["clean baseline on same socket shape", "single-connection negative control"],
        "bounded_next_probe": "one raw-socket CL.TE differential with a correlated benign marker",
    }


# --------------------------------------------------------------------- schema

def test_valid_finding_round_trips_and_autofills_boundary():
    f = H.validate_finding(_valid_finding())
    assert f.web_class == "request_smuggling"
    # boundary + status are auto-filled from the registry (the never-cross line travels with it).
    assert f.boundary and "spray" in f.boundary.lower()
    assert "agent" in f.status
    d = f.to_dict()
    for field in H.FINDING_FIELDS:
        assert field in d


def test_missing_required_field_fails_loudly():
    for field in H.FINDING_FIELDS:
        bad = _valid_finding()
        del bad[field]
        with pytest.raises(H.HandoffError) as exc:
            H.validate_finding(bad)
        assert field in str(exc.value)


def test_unknown_class_rejected():
    bad = _valid_finding(web_class="not_a_real_class")
    with pytest.raises(H.HandoffError):
        H.validate_finding(bad)


def test_controls_tried_must_be_nonempty_list():
    bad = _valid_finding()
    bad["controls_tried"] = []
    with pytest.raises(H.HandoffError):
        H.validate_finding(bad)
    bad["controls_tried"] = "clean baseline"  # a string, not a list
    with pytest.raises(H.HandoffError):
        H.validate_finding(bad)


def test_blank_required_string_rejected():
    bad = _valid_finding()
    bad["endpoint"] = "   "
    with pytest.raises(H.HandoffError):
        H.validate_finding(bad)


def test_non_dict_finding_rejected():
    with pytest.raises(H.HandoffError):
        H.validate_finding(["not", "a", "dict"])


# ----------------------------------------------------------------- completeness

def test_every_agent_status_class_has_a_playbook():
    reg = json.loads(REGFILE.read_text())
    pbs = json.loads(PBFILE.read_text())["playbooks"]
    mapping = reg["agent_handoff"]["class_playbook"]
    agent_status = [k for k, v in reg["classes"].items() if "agent" in v.get("status", "")]
    assert agent_status, "expected some agent-status classes in the registry"
    for cls in agent_status:
        assert cls in mapping, f"agent-status class {cls} missing from class_playbook"
        assert mapping[cls] in pbs, f"{cls} maps to unknown playbook {mapping[cls]}"


def test_every_mapping_target_is_a_real_playbook_and_class():
    reg = json.loads(REGFILE.read_text())
    pbs = json.loads(PBFILE.read_text())["playbooks"]
    mapping = reg["agent_handoff"]["class_playbook"]
    for cls, pid in mapping.items():
        assert cls in reg["classes"], f"{cls} is mapped but not a registry class"
        assert pid in pbs, f"{cls} -> {pid} has no playbook"


def test_finding_fields_consistent_between_registry_and_module():
    reg = json.loads(REGFILE.read_text())
    assert tuple(reg["agent_handoff"]["finding_fields"]) == H.FINDING_FIELDS
    pbs = json.loads(PBFILE.read_text())
    assert tuple(pbs["schema_fields"]) == H.FINDING_FIELDS


def test_the_named_item_classes_are_covered():
    # The B-151 spec names these families explicitly; each must resolve to a playbook.
    reg = H.load_registry()
    for cls in ["request_smuggling", "cache_poisoning", "csrf", "deser", "proto",
                "reset_rebind", "ldap_xpath_injection", "reflected_xss", "dom_xss",
                "business_logic", "race", "host_header", "crlf_response_split",
                "soap_wsdl", "grpc_web", "method_override", "upload_template"]:
        pb = H.playbook(cls, reg)
        assert pb.get("checklist"), f"{cls} playbook has no checklist"


# ------------------------------------------------------------- playbook shape

def test_every_playbook_has_a_checklist_probe_and_hard_boundary():
    pbs = json.loads(PBFILE.read_text())["playbooks"]
    assert pbs, "no playbooks"
    for pid, pb in pbs.items():
        assert pb.get("checklist") and all(isinstance(s, str) for s in pb["checklist"]), pid
        assert pb.get("bounded_next_probe", "").strip(), f"{pid} has no bounded next probe"
        # The never-auto-execute line is mandatory: this is scaffold, not exploitation.
        assert pb.get("never", "").strip(), f"{pid} has no 'never' boundary"
        assert pb.get("controls"), f"{pid} has no controls"


def test_playbooks_do_not_auto_execute():
    # The module is a scaffold: it must not import sockets/requests or run subprocesses.
    src = MODFILE.read_text()
    for banned in ["import socket", "import requests", "urllib.request.urlopen", "httpx"]:
        assert banned not in src, f"agent_handoff.py must not {banned!r}"


# ------------------------------------------------------------------ template

def test_handoff_template_prefills_probe_from_playbook():
    tpl = H.handoff_template("cache_poisoning", endpoint="GET https://t.example/profile")
    assert tpl["web_class"] == "cache_poisoning"
    assert tpl["endpoint"] == "GET https://t.example/profile"
    assert tpl["evidence"] == "" and tpl["controls_tried"] == []
    assert tpl["bounded_next_probe"]  # defaulted from the playbook
    assert tpl["playbook"]["checklist"]
    assert tpl["boundary"]


def test_resolve_accepts_class_or_playbook_id_and_rejects_stray():
    reg = H.load_registry()
    assert H.resolve_playbook_id("ssrf", reg) == "dns_rebinding"   # class name -> id
    assert H.resolve_playbook_id("dns_rebinding", reg) == "dns_rebinding"  # id -> itself
    with pytest.raises(H.HandoffError):
        H.resolve_playbook_id("totally_unknown", reg)


# -------------------------------------------------------------- loud failures

def test_missing_playbook_file_fails_loudly(tmp_path):
    with pytest.raises(H.HandoffError):
        H.load_playbooks(tmp_path / "nope.json")


def test_registry_without_agent_handoff_block_fails_loudly(tmp_path):
    p = tmp_path / "reg.json"
    p.write_text(json.dumps({"classes": {"x": {"status": "cold"}}}))
    reg = H.load_registry(p)
    with pytest.raises(H.HandoffError):
        H.agent_classes(reg)


# ------------------------------------------------------------------------ CLI

def _run_cli(*args):
    return subprocess.run([sys.executable, "-I", str(MODFILE), *args],
                          capture_output=True, text=True)


def test_cli_classes_lists_mappings():
    r = _run_cli("classes")
    assert r.returncode == 0, r.stderr
    assert "request_smuggling" in r.stdout and "playbook=" in r.stdout


def test_cli_playbook_prints_boundary():
    r = _run_cli("playbook", "race")
    assert r.returncode == 0, r.stderr
    assert "NEVER" in r.stdout and "irreversible" in r.stdout.lower()


def test_cli_template_is_valid_json_with_fields():
    r = _run_cli("template", "deser", "--endpoint", "POST /api")
    assert r.returncode == 0, r.stderr
    obj = json.loads(r.stdout)
    for field in H.FINDING_FIELDS:
        assert field in obj


def test_cli_validate_accepts_good_and_rejects_bad(tmp_path):
    good = tmp_path / "good.json"
    good.write_text(json.dumps(_valid_finding()))
    r = _run_cli("validate", str(good))
    assert r.returncode == 0, r.stderr
    assert "VALID" in r.stdout

    bad = tmp_path / "bad.json"
    bad_obj = _valid_finding()
    del bad_obj["evidence"]
    bad.write_text(json.dumps(bad_obj))
    r2 = _run_cli("validate", str(bad))
    assert r2.returncode == 2
    assert "evidence" in r2.stderr


def test_cli_schema_prints_field_list():
    r = _run_cli("schema")
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == list(H.FINDING_FIELDS)
