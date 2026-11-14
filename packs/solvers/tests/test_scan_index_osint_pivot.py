"""B-114: an IP lead's OSINT pivot plan names the keyed scan-index host union.

`solvers/toolkits/osint_pivot.py` builds offline plans; for a public IP it now carries one step that
runs `python -m ctf scan-index host <ip>` (the port union across Shodan, Censys, FOFA, Netlas and
InternetDB). No request is made: the plan is only constructed.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

TOOLKITS = Path(__file__).resolve().parents[1] / "solvers/toolkits"
sys.path.insert(0, str(TOOLKITS))
import osint_pivot as op  # noqa: E402


def _scan(rows):
    return [r for r in rows if r["provider"] == "scan index"]


@pytest.mark.parametrize("kind,value,canonical", [
    ("ip", "8.8.4.4", "8.8.4.4"),
    ("ipv6", "[2606:4700:4700:0000:0000:0000:0000:1111]", "2606:4700:4700::1111"),
])
def test_a_public_ip_plan_names_the_scan_index_host_union(kind, value, canonical):
    rows = op.plan_lead(kind, value)
    (step,) = _scan(rows)
    assert step["query"] == f"python -m ctf scan-index host {canonical}" and step["url"] is None
    assert "CTF_SCAN_INDEX_" in step["note"] and "public_fetch_allow" in step["note"]
    # ranked after the registration record and before the routing lookup
    assert [r["provider"] for r in rows] == ["IANA RDAP", "scan index", "RIPEstat"]


@pytest.mark.parametrize("value", ["10.1.2.3", "127.0.0.1", "203.0.113.5", "2001:db8::1"])
def test_a_private_or_documentation_address_gets_no_scan_index_step(value):
    # the scan indexes only see the public internet; a reserved address would spend quota on nothing
    rows = op.plan_lead("ip", value)
    assert _scan(rows) == [] and [r["provider"] for r in rows] == ["IANA RDAP", "RIPEstat"]


def test_the_rendered_plan_shows_the_command():
    text = op.render(op.build_plan([{"kind": "ip", "value": "8.8.4.4"}]))
    assert "scan index: union the indexed ports" in text
    assert "python -m ctf scan-index host 8.8.4.4" in text


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
