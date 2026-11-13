from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse


TOOLKITS = Path(__file__).resolve().parents[1] / "solvers/toolkits"
sys.path.insert(0, str(TOOLKITS))
import osint_pivot as O  # noqa: E402


def test_username_matrix_is_ranked_and_encoded():
    rows = O.plan_lead("username", "alice.dev")
    assert rows[0]["provider"] == "GitHub"
    assert rows[0]["url"].endswith("/alice.dev")
    assert all(rows[i]["rank"] >= rows[i + 1]["rank"] for i in range(len(rows) - 1))


def test_email_builds_gravatar_without_network_and_domain_pivot():
    rows = O.plan_lead("email", "Alice@Example.COM")
    gravatar = rows[0]
    assert gravatar["provider"] == "Gravatar"
    assert len(gravatar["query"]) == 32
    assert "Alice@" not in gravatar["url"]
    assert any(row["provider"] == "Have I Been Pwned" for row in rows)
    assert any(row["provider"] == "domain plan" and row["query"] == "example.com" for row in rows)


def test_domain_queries_are_narrow_and_url_encoded():
    rows = O.plan_lead("domain", "Example.COM.")
    crt = next(row for row in rows if row["provider"] == "crt.sh")
    assert parse_qs(urlparse(crt["url"]).query)["q"] == ["%.example.com"]
    cdx = next(row for row in rows if row["provider"] == "Wayback CDX")
    assert "*.example.com/*" in parse_qs(urlparse(cdx["url"]).query)["url"]
    dns = next(row for row in rows if row["provider"] == "DNS")
    assert "dig +short MX example.com" in dns["query"]


def test_secret_is_redacted_and_never_put_in_url():
    secret = "AKIA1234567890EXAMPLE"
    plans = O.build_plan([{"kind": "aws_key", "value": secret}])
    assert plans[0]["value"] == "<redacted>"
    blob = O.render(plans)
    assert secret not in blob
    assert plans[0]["pivots"][0]["url"] is None


def test_invalid_leads_and_cli_fail_closed(capsys):
    try:
        O.plan_lead("domain", "https://example.com/path")
    except ValueError:
        pass
    else:
        raise AssertionError("URL accepted as a bare domain")
    assert O.main([]) == 2
    assert "osint_pivot:" in capsys.readouterr().err

