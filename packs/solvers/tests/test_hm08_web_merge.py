#!/usr/bin/env python3
"""Asserting regression for the hm-08 hand-merge (B-001).

Covers the four web solvers whose merge restored Huntress capability on top of
the CSCTF base:

  * forge_event / graphql_read / post_chain / post_exploit label vocabulary:
    the union keeps the CSCTF words (secret/success) AND restores the Huntress
    words (proof/evidence/objective/submission) the sed had dropped.
  * graphql_read field selection: SCALAR_RANK/OBJECT_RANK lead with the recovery
    nouns again while still carrying CSCTF's `flag`; the wire-wrapper set and the
    key regex regained `proof`/`objective`.
  * post_chain SSTI payoff variable: the engine now asks the confirmed template
    for BOTH `config` (CSCTF) and `objective` (Huntress), so either event's
    template yields its scalar.

Every check is a real `assert`; each fails if the merge is reverted to one side.
These are unit assertions on the merged modules plus one end-to-end SSTI solve.
No network, no challenge binaries: the fake target is built in-process here.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import urllib.parse
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "web"))
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import forge_event as forge  # noqa: E402
import graphql_read as graphql  # noqa: E402
import post_chain as post  # noqa: E402
import post_exploit as pe  # noqa: E402


# --------------------------------------------------------------------------- #
#  Label vocabulary: union of Huntress + CSCTF words (merge outcome)
# --------------------------------------------------------------------------- #

# Restored Huntress words -- a CSCTF base alone would NOT match these.
_HUNTRESS_WORDS = ("proof", "evidence", "objective", "submission")
# Kept CSCTF words -- a pure Huntress base would NOT match all of these.
_CSCTF_WORDS = ("secret", "success")


def _key_matches(rx, word):
    return bool(rx.search(f"x_{word}_y"))


def test_forge_event_label_union_restored_and_kept():
    for w in _HUNTRESS_WORDS:
        assert _key_matches(forge.LABEL_KEY, w), f"forge.LABEL_KEY lost Huntress word {w!r}"
    # secret is a key word; success is a text word in forge's vocab.
    assert _key_matches(forge.LABEL_KEY, "secret")
    assert forge.LABELLED_TEXT.search('objective: "abc123"'), "forge.LABELLED_TEXT lost 'objective'"
    assert forge.LABELLED_TEXT.search('success = done-value'), "forge.LABELLED_TEXT lost CSCTF 'success'"


def test_post_chain_label_union_restored_and_kept():
    for w in _HUNTRESS_WORDS:
        assert _key_matches(post.LABEL_KEY, w), f"post.LABEL_KEY lost Huntress word {w!r}"
    for w in _CSCTF_WORDS:
        assert _key_matches(post.LABEL_KEY, w), f"post.LABEL_KEY lost CSCTF word {w!r}"
    assert post.LABELLED_TEXT.search('objective: "deadbeef"')
    assert post.LABELLED_TEXT.search('success: "deadbeef"')


def test_post_exploit_label_union_restored_and_kept():
    for w in _HUNTRESS_WORDS:
        assert _key_matches(pe.LABEL_KEY, w), f"pe.LABEL_KEY lost Huntress word {w!r}"
    assert _key_matches(pe.LABEL_KEY, "secret")
    # SUCCESS_LABEL_KEY is the widened success-channel vocab (adds token).
    for w in _HUNTRESS_WORDS + ("token",) + _CSCTF_WORDS:
        assert _key_matches(pe.SUCCESS_LABEL_KEY, w), f"pe.SUCCESS_LABEL_KEY lost {w!r}"


# --------------------------------------------------------------------------- #
#  graphql_read field selection restored (reader logic, not naming)
# --------------------------------------------------------------------------- #

def test_graphql_strong_label_and_wrappers_restored():
    for w in _HUNTRESS_WORDS:
        assert graphql.STRONG_LABEL.search(f"a_{w}_b"), f"graphql.STRONG_LABEL lost {w!r}"
    assert graphql.STRONG_LABEL.search("a_success_b"), "graphql.STRONG_LABEL lost CSCTF 'success'"
    assert "proof" in graphql._WIRE_WRAPPER_WORDS
    assert "objective" in graphql._WIRE_WRAPPER_WORDS


def test_graphql_rank_leads_with_recovery_nouns_but_keeps_flag():
    sr = graphql.SCALAR_RANK
    orr = graphql.OBJECT_RANK
    for w in ("proof", "evidence", "objective"):
        assert w in sr, f"SCALAR_RANK lost {w!r}"
    # Recovery nouns must outrank 'flag' again (the CSCTF reorder led with flag).
    assert sr.index("proof") < sr.index("flag"), sr
    assert sr.index("evidence") < sr.index("flag"), sr
    # CSCTF's flag must still be present (master must also serve flag{} events).
    assert "flag" in sr and "flag" in orr, (sr, orr)
    for w in ("evidence", "proof", "objective"):
        assert w in orr, f"OBJECT_RANK lost {w!r}"
    assert orr.index("evidence") < orr.index("flag"), orr


# --------------------------------------------------------------------------- #
#  post_chain SSTI payoff: tries BOTH 'config' and 'objective'
# --------------------------------------------------------------------------- #

def test_ssti_payoff_vars_are_both():
    assert post.SSTI_PAYOFF_VARS == ("config", "objective"), post.SSTI_PAYOFF_VARS


def _ssti_response(status, body, path):
    if not isinstance(body, (bytes, bytearray)):
        body = str(body).encode()
    ct = "application/json" if bytes(body).lstrip()[:1] in (b"{", b"[") else "text/html; charset=utf-8"
    return {"status": status, "body": bytes(body),
            "response_headers": {"Content-Type": ct},
            "final_url": "http://fake.local" + path}


# Delimiters for the curly syntax the engine confirms first.
def _curly(value):
    return "{{" + value + "}}"


class _SSTIServer:
    """A confirmed Jinja (curly, Spring Boot) template that exposes its scalar
    under exactly ONE variable name. Mirrors the saved Template-Temper contract:
    arithmetic evaluates for any expression (the confirm control), but the payoff
    renders only when the engine asks for `payoff_var`. The answer is a CSCTF
    flag so a successful solve RETURNS it.
    """

    def __init__(self, payoff_var, answer):
        self.payoff_var = payoff_var
        self.answer = answer
        self.base = "http://fake.local/"
        self.timeout = 8.0
        self.feature = "/process-hm08"
        self.field = "template"          # default field -> omitted from clues, as in the saved contract
        self.log = []

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        self.log.append({"method": method, "path": path, "data": data})
        path = path.split("?")[0]
        if method == "GET" and path == "/":
            return _ssti_response(200, "<title>Message Mill · Spring Boot</title>", path)
        if method == "GET" and path == "/api/clues":
            return _ssti_response(200, json.dumps({
                "current_role": "analyst",
                "framework": "Spring Boot",
                "feature_route": self.feature,
            }), path)
        if method == "GET" and path == self.feature:
            return _ssti_response(200, "<article><h1>Rendered message</h1><pre></pre></article>", path)
        if method == "POST" and path == self.feature:
            values = dict(urllib.parse.parse_qsl(data or "", keep_blank_values=True))
            value = str(values.get(self.field, ""))
            if value == _curly("7213*4567"):
                rendered = str(7213 * 4567)             # arithmetic confirm control
            elif value == _curly(self.payoff_var):
                rendered = self.answer                   # the payoff scalar
            else:
                rendered = value                         # any other var: echo only
            return _ssti_response(200, f"<article><h1>Rendered message</h1><pre>{rendered}</pre></article>", path)
        return _ssti_response(404, '{"error":"not_found"}', path)


def _solve_ssti(payoff_var, answer=None):
    answer = answer or f"flag{{ssti_{payoff_var}_payoff}}"
    server = _SSTIServer(payoff_var, answer)
    target = {"answer_id": "t1", "url": "http://fake.local/",
              "question": "Recover the flag from the template engine."}
    ctx = {"client": server, "prompt": "The template engine evaluates every expression you submit."}
    got = post.solve(target, ctx)
    return got, answer, server


def test_ssti_recovers_huntress_objective_scalar(monkeypatch):
    # A target whose template answers ONLY to `objective` (Huntress form). CSCTF
    # base (asks `config` only) cannot reach this payoff; the merge can. The answer
    # is a CSCTF-format flag, so the run is under the csctf profile (flag payoffs).
    monkeypatch.setenv("CTF_EVENT", "csctf")
    got, answer, server = _solve_ssti("objective")
    assert got == answer, (got, answer)
    assert all(row["method"] in {"GET", "POST"} for row in server.log), server.log


def test_ssti_recovers_csctf_config_scalar(monkeypatch):
    # The CSCTF form must still work after restoring the Huntress candidate.
    monkeypatch.setenv("CTF_EVENT", "csctf")
    got, answer, server = _solve_ssti("config")
    assert got == answer, (got, answer)


# R-06: under the Huntress profile the template's scalar is a proof_<32 hex> token and the
# engine returns it as the proof (the profile's [proof]); a flag-format scalar is not the answer.
_HUNTRESS_PROOF = "proof_0123456789ab4def8abc0123456789ab"


def _posted_vars(server):
    return [urllib.parse.unquote_plus(str(row["data"] or "")) for row in server.log if row["method"] == "POST"]


def test_ssti_returns_huntress_proof_and_asks_objective_first(monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "huntress")
    got, answer, server = _solve_ssti("objective", _HUNTRESS_PROOF)
    assert got == _HUNTRESS_PROOF, (got, server.log)
    # A proof event's template reads `objective`: no POST is spent asking for `config`.
    assert not any("{{config}}" in body for body in _posted_vars(server)), _posted_vars(server)


def test_ssti_huntress_config_template_still_reached(monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "huntress")
    got, _answer, server = _solve_ssti("config", _HUNTRESS_PROOF)
    assert got == _HUNTRESS_PROOF, (got, server.log)


def test_ssti_flag_scalar_is_not_a_huntress_proof(monkeypatch):
    # Under the Huntress profile a flag-shaped scalar is another token family: never returned.
    monkeypatch.setenv("CTF_EVENT", "huntress")
    got, _answer, _server = _solve_ssti("objective", "flag{" + "ab" * 16 + "}")
    assert got is None


def test_ssti_payoff_var_order_follows_the_profile(monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "huntress")
    assert post.ssti_payoff_vars() == ("objective", "config")
    monkeypatch.setenv("CTF_EVENT", "csctf")
    assert post.ssti_payoff_vars() == ("config", "objective")


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
