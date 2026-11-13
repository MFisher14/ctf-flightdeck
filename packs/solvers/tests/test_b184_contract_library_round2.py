"""B-184 round 2: route-trust floors, clue field cues, forge-plan escalation, shared name mutation.

Each test drives the real ``contract_library`` offline (pure functions, no socket)
and pins one behaviour the round-2 verification found missing or unpinned:

* the fatal floor catches compounds (``wipedb``, ``shutdownnow``, ``dropall``),
  camelCase (``dropTables``, ``doNukeIt``), NFKC-folded spellings and the fatal
  words the shared guard lacks (``poweroff``, ``nuke``, ``format`` + object);
* a route named in a negated clue sentence is not trusted even when the
  explicit advertised list carries it, wherever the route sits in the sentence;
* a guarded route needs an exact path+query match;
* clue field extraction prefers the labels after the cue;
* the forge plan never comes back silently empty;
* the label->wire mutation reuses ``forge_event.name_variants``.
"""
from __future__ import annotations

import sys

import pytest

from ctf import paths

ROOT = paths.repo_root()
WEB = ROOT / "solvers" / "web"
for _p in (str(WEB), str(ROOT / "solvers" / "toolkits")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import contract_library as cl  # noqa: E402 -- the engine under test
import forge_event  # noqa: E402 -- the live engine whose mutation is reused

BASE = "http://target.local/"


def _trust_advertised(route, clue=None):
    """route_trust with the route both in the list and named in an inviting clue."""
    return cl.route_trust(route, BASE, advertised=[route],
                          clue=clue if clue is not None else f"Use the advertised endpoint {route} now.")


# --------------------------------------------------------------------------- fatal floor

@pytest.mark.parametrize("route", [
    "/admin/wipedb",        # wipe + object compound
    "/admin/shutdownnow",   # shutdown + modifier compound
    "/admin/dropall",       # drop + modifier compound
    "/admin/killall",       # kill (not an unambiguous compound) + modifier
    "/admin/flushcache",    # flush + object compound
    "/admin/drop_all",      # separator form (already caught in round 1)
])
def test_fatal_floor_catches_compound_words(route):
    v = _trust_advertised(route)
    assert not v.trusted, f"{route} advertised must never be trusted: {v}"
    assert v.guarded
    assert "catastrophic" in v.reason


@pytest.mark.parametrize("route", [
    "/admin/dropTables",    # shared-guard fatal word inside camelCase
    "/admin/doNukeIt",      # extra fatal word inside camelCase (no compound match without the split)
])
def test_fatal_floor_splits_camel_case(route):
    v = _trust_advertised(route)
    assert not v.trusted, f"{route} advertised must never be trusted: {v}"
    assert "catastrophic" in v.reason


@pytest.mark.parametrize("route", [
    "/admin/poweroff", "/admin/nuke-all", "/admin/nukeEverything",
    "/admin/nukeserver", "/admin/forcepoweroff",   # unseparated compounds
    "/admin/format-disk", "/admin/formatdb", "/admin/format/all",
])
def test_fatal_words_missing_from_the_shared_set_are_still_fatal(route):
    # the shared guard does not know poweroff/nuke/format, so without the extra
    # check these would pass as "same-origin non-destructive" and be trusted.
    v = _trust_advertised(route)
    assert not v.trusted, f"{route}: {v}"
    assert "catastrophic" in v.reason


def test_fatal_floor_folds_compatibility_spellings():
    # fullwidth letters NFKC-fold to ASCII downstream; the floor must see that
    # (it checks every canonical_route_layers layer, which includes the fold).
    assert cl._route_has_fatal_word("/admin/ｎｕｋｅ")      # fullwidth "nuke"
    assert cl._route_has_fatal_word("/admin/ｗｉｐｅdb")    # fullwidth "wipe" + db


def test_plain_format_route_is_not_fatal_and_waivable_guarded_words_stay_waivable():
    # "format" alone is an ordinary route word (a date formatter), not a disk wipe.
    v = cl.route_trust("/api/format", BASE)
    assert v.trusted and not v.guarded
    # ordinary guarded words stay waivable by an advertisement (the item's exception).
    for route in ("/admin/reset-all", "/admin/delete-session", "/admin/reset-token"):
        v = _trust_advertised(route)
        assert v.trusted and v.guarded, f"{route}: {v}"


# --------------------------------------------------------------------------- negation

@pytest.mark.parametrize("clue", [
    "Do not call /admin/delete-all.",
    "/admin/delete-all must never be called.",
    "Whatever happens, /admin/delete-all is not for you!",
])
def test_negated_route_is_not_trusted_even_when_listed(clue):
    v = cl.route_trust("/admin/delete-all", BASE, advertised=["/admin/delete-all"], clue=clue)
    assert not v.trusted, f"{clue!r}: {v}"
    assert "negated" in v.reason


def test_negation_is_scoped_to_its_own_sentence():
    clue = "Never touch /admin/delete-all. Use /admin/reset-token to start over."
    good = cl.route_trust("/admin/reset-token", BASE, advertised=[], clue=clue)
    bad = cl.route_trust("/admin/delete-all", BASE, advertised=["/admin/delete-all"], clue=clue)
    assert good.trusted and good.guarded
    assert not bad.trusted


def test_route_at_the_end_of_a_sentence_is_advertised():
    # the trailing full stop is punctuation, not part of the path.
    v = cl.route_trust("/admin/delete-note", BASE, advertised=[], clue="Clean up with /admin/delete-note.")
    assert v.trusted and v.guarded


def test_route_plan_drops_a_listed_route_the_clue_forbids():
    m = cl.load_matrix()
    ev = dict(m.fixtures["route_trust_guarded"])
    ev["clue"] = ("Use the advertised endpoint /admin/reset-token to rotate your token. "
                  "/admin/delete-all must never be called.")
    ev["advertised_routes"] = ["/admin/reset-token", "/admin/delete-all"]
    decision = cl.route(ev, m)
    assert decision["chosen"]["id"] == "route_trust_guarded"
    urls = [r["url"] for r in decision["plan"]["routes"]]
    assert urls == ["/admin/reset-token"], urls
    verdicts = {t["url"]: t["trusted"] for t in decision["route_trust"]}
    assert verdicts == {"/admin/reset-token": True, "/admin/delete-all": False}


# --------------------------------------------------------------------------- exact path+query

def test_guarded_route_needs_an_exact_query_match():
    v = cl.route_trust("/admin/reset?all=1", BASE, advertised=["/admin/reset"],
                       clue="Use /admin/reset to start over.")
    assert not v.trusted, v
    assert v.guarded


def test_guarded_route_with_the_advertised_query_is_trusted():
    listed = cl.route_trust("/admin/reset?all=1", BASE, advertised=["/admin/reset?all=1"])
    in_clue = cl.route_trust("/admin/reset?all=1", BASE, advertised=[],
                             clue="Use /admin/reset?all=1 to start over.")
    assert listed.trusted and in_clue.trusted


# --------------------------------------------------------------------------- clue field cue

def test_field_extraction_prefers_labels_after_the_cue():
    clue = "Forge a Transfer for Alice via the Bank form: it shows Amount, Recipient and Memo"
    assert set(cl._fields_from_clue(clue)) == {"Amount", "Recipient", "Memo"}


def test_field_extraction_without_a_cue_scans_the_whole_clue():
    assert set(cl._fields_from_clue("Send Amount and Recipient to the bank")) == {"Amount", "Recipient"}


# --------------------------------------------------------------------------- forge plan escalation

def test_forge_plan_without_labels_escalates_with_a_reason():
    m = cl.load_matrix()
    ev = {"category": "web", "clue": "the form has fields event and owner", "method": "POST",
          "responses": [], "advertised_routes": [], "base_url": BASE}
    decision = cl.route(ev, m)
    assert decision["chosen"]["id"] == "post_event_forge"
    plan = decision["plan"]
    assert plan["action"] == "escalate-agent", plan
    assert "no field labels" in plan["reason"]
    assert "candidates" not in plan


def test_forge_plan_with_only_noise_labels_escalates_with_a_reason():
    m = cl.load_matrix()
    ev = {"category": "web", "clue": "forge the event for the owner", "method": "POST",
          "responses": [], "advertised_routes": [], "base_url": BASE,
          "fields": {"Signature": "x", "Token": "y"}}
    plan = cl.route(ev, m)["plan"]
    assert plan["action"] == "escalate-agent", plan
    assert "noise" in plan["reason"]


# --------------------------------------------------------------------------- shared name mutation

def test_wire_name_variants_reuse_the_forge_event_mutation():
    vs = cl.wire_name_variants("Desired Role")
    # forge_event strips the "desired_" prefix and adds its semantic synonyms;
    # none of these come from the planner's own mechanical spellings.
    for name in forge_event.name_variants("Desired Role"):
        assert name in vs, f"{name} from forge_event.name_variants missing: {vs}"
    assert "role" in vs and "access_role" in vs
    # the exact display spelling still leads (the planner's addition).
    assert vs[0] == "Desired Role"


def test_wire_name_variants_rank_shared_mutation_before_local_extras():
    vs = cl.wire_name_variants("Owner")
    # "scope" comes from forge_event's table; "owner_id" only from the local extras.
    assert vs.index("owner") < vs.index("scope") < vs.index("owner_id")
    assert len(vs) == len(set(vs))
