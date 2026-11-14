"""Routing checks for the offline web exploitation helpers."""

from ctf import triage


WEB_HELPERS = {
    "solvers/web/ssti_helper.py",
    "solvers/web/sqli_helper.py",
    "solvers/web/auth_trust.py",
    "solvers/web/object_refs.py",
    "solvers/web/upload_builder.py",
    "solvers/web/etag_chain.py",
}


def test_all_offline_helpers_are_in_the_web_lane():
    assert WEB_HELPERS <= set(triage.CATEGORY_ENGINES["web"])


def test_web_keywords_prioritize_the_matching_helper():
    cases = {
        "Jinja SSTI in a template": "solvers/web/ssti_helper.py",
        "NFKC SQL injection": "solvers/web/sqli_helper.py",
        "JWT alg:none role cookie": "solvers/web/auth_trust.py",
        "md5(id) IDOR": "solvers/web/object_refs.py",
        "file upload double extension": "solvers/web/upload_builder.py",
        "ETag If-None-Match chain": "solvers/web/etag_chain.py",
    }
    for description, expected in cases.items():
        assert triage.suggest("web", description)["engines"][0] == expected


def test_web_nudges_do_not_change_other_category_routing():
    suggestions = triage.suggest("forensics", "JWT IDOR file upload ETag SSTI SQL injection")
    assert WEB_HELPERS.isdisjoint(suggestions["engines"])
