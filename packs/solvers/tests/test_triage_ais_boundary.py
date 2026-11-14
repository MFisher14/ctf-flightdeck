"""B-091: the AIS triage word-boundary fix (solvers/toolkits/transport.manifest.toml).

The transport engine's keyword nudge matched the bare substring "ais", so an OSINT challenge whose
text merely contained the letters a-i-s -- "Globex Artisanal Mayonnaise Co." in the ParsnipLocker
onion card, or "aisle", "praise" -- was mis-routed to the vehicle/marine transport engine. The keyword
is narrowed to the whole word " ais "; these tests pin that boundary from the generated route table
(ctf.triage.suggest, the real routing path), so a regression in the manifest or the table fails here.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ctf import triage

TRANSPORT = "solvers/toolkits/transport.py"

# The genuine ransom-note text from the onion-deanon card: it names "Mayonnaise", nothing marine.
RANSOM_NOTE = ("Hello, Globex Artisanal Mayonnaise Co. Your network has been parsnipped. "
               "Pay 0.8 XMR or we publish on our blog.")


def _engines(category, description):
    return set(triage.suggest(category, description)["engines"])


def test_mayonnaise_does_not_route_the_transport_engine():
    # OSINT category: the transport engine has no bare-category route here, so it would only appear via
    # the keyword nudge. "Mayonnaise" must no longer trigger it.
    assert TRANSPORT not in _engines("osint", RANSOM_NOTE)


def test_other_ais_substrings_do_not_route_transport():
    for text in ("walk down the aisle", "sing his praises", "a mayonnaise jar"):
        assert TRANSPORT not in _engines("osint", text), text


def test_real_ais_still_routes_transport():
    # A genuine marine AIS challenge (the word AIS, space-delimited) must still reach the engine.
    routes = {r["id"]: r for r in triage.suggest("misc", "decode the ais broadcast from the vessel")["routes"]}
    assert "toolkits.transport" in routes
    assert "ais" in routes["toolkits.transport"]["reason"]


def test_ais_at_capital_still_matches_lowercased():
    # Routing lower-cases the description, so "AIS" in the text matches the " ais " keyword too.
    assert TRANSPORT in _engines("misc", "The AIS feed is attached.")


def test_ais_at_text_boundaries_and_punctuation_still_match():
    # The whole-word keyword is boundary-safe: AIS at the very start or end of the description, or
    # followed by punctuation, must still route. These use the "osint" category, where transport has
    # no category route, so it can only appear via the keyword nudge -- isolating the keyword match
    # from the unconditional "misc"/"networking" category routes. The plain space-padded substring
    # " ais " would miss every one of these (no space before a leading token, after a trailing one,
    # or before "." / ",").
    for text in ("AIS broadcast captured", "please decode the broadcast AIS",
                 "the feed is AIS.", "payload type: AIS, decode it"):
        assert TRANSPORT in _engines("osint", text), text


def test_ais_inside_words_still_rejected_at_boundaries():
    # The boundary fix must not re-open the false positives: AIS as a letter run inside a word stays out.
    for text in ("Globex Artisanal Mayonnaise Co.", "aisle seat", "faiss index tricks", "praise the sun"):
        assert TRANSPORT not in _engines("osint", text), text
