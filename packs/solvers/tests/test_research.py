"""B-199: the shared research cache (ctf.research) and `ctf research`.

No network anywhere: entries are pre-filled by the tests, as an agent's `put` would. Time is an
injected clock, so claim expiry needs no sleeping. Each test fails when the behaviour is wrong: two
spellings of one question that do not share a key (or two questions that do), a secret that reaches
the shared store, a claim two agents both win, an expired claim that still blocks, a silent overwrite.
"""
from __future__ import annotations

import argparse
import threading

import pytest

from ctf import research
from ctf.cli import research as cli_research


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    monkeypatch.delenv("CTF_EVENT", raising=False)
    monkeypatch.delenv("CTF_AGENT", raising=False)


class Clock:
    def __init__(self, t: float = 1_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


# --------------------------------------------------------------------------- keys

@pytest.mark.parametrize("a,b", [
    ("The RFC 4648 base32 alphabet", "rfc 4648: base32 alphabet?"),
    ("What is the PNG  IHDR chunk layout?", "png ihdr chunk layout"),
    ("ＲＦＣ 4648", "rfc 4648"),                                         # NFKC full-width
    ("https://www.rfc-editor.org/rfc/rfc4648/", "http://rfc-editor.org/rfc/rfc4648"),
    ("https://example.com:443/a//b?z=1&a=2#sec", "https://example.com/a/b?a=2&z=1"),
    ("https://example.com/x?utm_source=t&fbclid=1&q=1", "https://EXAMPLE.com/x?q=1"),
    ("www.example.com/doc", "https://example.com/doc"),
])
def test_same_question_same_key(a, b):
    assert research.normalize(a) == research.normalize(b)


@pytest.mark.parametrize("a,b", [
    ("rfc 4648 base32", "rfc 4648 base64"),
    ("https://example.com/a?q=1", "https://example.com/a?q=2"),
    ("https://example.com:8443/a", "https://example.com/a"),
    ("https://example.com/a", "https://example.org/a"),
    ("c++ name mangling", "c name mangling"),
    ("convert hex to base64", "convert base64 to hex"),          # direction matters: word order kept
    ("base32 alphabet rfc 4648", "rfc 4648 base32 alphabet"),
])
def test_different_questions_different_keys(a, b):
    assert research.normalize(a) != research.normalize(b)


def test_key_shapes():
    assert research.normalize("The RFC 4648 base32 alphabet") == "q:rfc 4648 base32 alphabet"
    assert research.normalize("https://www.Example.com/A/?b=2&a=1#x") == "url:example.com/A?a=1&b=2"


@pytest.mark.parametrize("url,what", [
    ("https://user:pw@example.com/doc", "credentials"),
    ("https://example.com/doc?api_key=abc", "api_key"),
    ("https://example.com/doc?access_token=abc", "access_token"),
    ("https://example.com/doc?X-Amz-Signature=abc", "X-Amz-Signature"),
    ("https://example.com/doc?session=abc", "session"),
])
def test_secret_bearing_urls_are_refused(url, what):
    with pytest.raises(research.ResearchError, match=what):
        research.normalize(url)


def test_harmless_params_that_look_like_secret_words_pass():
    assert research.normalize("https://example.com/s?author=x&keyword=y") == \
        "url:example.com/s?author=x&keyword=y"


@pytest.mark.parametrize("bad", ["", "   ", "the of and", "!!! ???", "https:///nohost"])
def test_empty_or_unusable_keys_are_refused(bad):
    with pytest.raises(research.ResearchError):
        research.normalize(bad)


# --------------------------------------------------------------------------- the store

def test_put_then_get_from_another_cache_instance(tmp_path):
    clock = Clock()
    a = research.Cache(tmp_path / "r", clock=clock)
    a.put("RFC 4648 base32 alphabet", "A-Z then 2-7; pad with =", sources=["https://rfc-editor.org/rfc/rfc4648"],
          agent="alice")
    got = research.Cache(tmp_path / "r").get("the RFC 4648 base32 alphabet?")
    assert got is not None
    assert (got.answer, got.agent, got.at, got.sources) == ("A-Z then 2-7; pad with =", "alice", clock.t,
                                                            ["https://rfc-editor.org/rfc/rfc4648"])
    assert research.Cache(tmp_path / "r").get("rfc 4648 base64") is None


def test_put_refuses_overwrite_unless_replace(tmp_path):
    c = research.Cache(tmp_path / "r")
    c.put("q one", "first", agent="alice")
    with pytest.raises(research.ResearchError, match="already answered by alice"):
        c.put("Q one?", "second", agent="bob")
    assert c.get("q one").answer == "first"
    c.put("Q one?", "second", agent="bob", replace=True)
    assert c.get("q one").answer == "second" and c.get("q one").agent == "bob"


def test_put_refuses_empty_oversized_and_secret_sources(tmp_path):
    c = research.Cache(tmp_path / "r")
    with pytest.raises(research.ResearchError, match="empty answer"):
        c.put("q", "  ", agent="a")
    with pytest.raises(research.ResearchError, match="over"):
        c.put("q", "x" * (research.MAX_ANSWER_BYTES + 1), agent="a")
    with pytest.raises(research.ResearchError, match="token"):
        c.put("q", "fine", sources=["https://example.com/?token=abc"], agent="a")
    assert c.get("q") is None
    c.put("q", "x" * research.MAX_ANSWER_BYTES, agent="a")         # exactly at the limit is stored


def test_a_corrupt_entry_is_named_not_treated_as_a_miss(tmp_path):
    c = research.Cache(tmp_path / "r")
    c.put("q", "answer", agent="a")
    (p,) = (tmp_path / "r").glob("*.json")
    p.write_text("{not json")
    with pytest.raises(research.ResearchError, match="unreadable"):
        c.get("q")


def test_entries_lists_newest_first(tmp_path):
    clock = Clock()
    c = research.Cache(tmp_path / "r", clock=clock)
    c.put("first question", "1", agent="a")
    clock.t += 10
    c.put("second question", "2", agent="b")
    assert [e.answer for e in c.entries()] == ["2", "1"]
    assert research.Cache(tmp_path / "none").entries() == []


# --------------------------------------------------------------------------- claims

def test_claim_is_exclusive_until_it_expires(tmp_path):
    clock = Clock()
    c = research.Cache(tmp_path / "r", clock=clock)
    c.claim("png ihdr", agent="alice")
    with pytest.raises(research.ClaimHeld) as e:
        c.claim("PNG IHDR", agent="bob")
    assert e.value.claim.agent == "alice"
    clock.t += research.CLAIM_TTL - 1
    with pytest.raises(research.ClaimHeld):
        c.claim("png ihdr", agent="bob")
    clock.t += 2                                                   # past the TTL: stale, taken over
    assert c.claim("png ihdr", agent="bob").agent == "bob"
    assert c.holder("png ihdr").agent == "bob"


def test_ttl_boundary_and_a_dead_agents_claim_stops_blocking(tmp_path):
    clock = Clock()
    c = research.Cache(tmp_path / "r", clock=clock)
    c.claim("rfc 9110", agent="alice")                             # alice then dies without put/release
    clock.t += research.CLAIM_TTL                                  # exactly at the TTL: stale
    assert c.holder("rfc 9110") is None
    got = c.lookup("rfc 9110", agent="bob", claim=True)
    assert got.status == "claimed" and got.claim.agent == "bob"
    assert c.holder("rfc 9110").agent == "bob"


def test_claim_exactly_at_the_ttl_is_taken_over(tmp_path):
    clock = Clock()
    c = research.Cache(tmp_path / "r", clock=clock)
    c.claim("q", agent="alice")
    clock.t += research.CLAIM_TTL
    assert c.claim("q", agent="bob").agent == "bob"


def test_own_claim_refreshes_and_release_only_drops_your_own(tmp_path):
    clock = Clock()
    c = research.Cache(tmp_path / "r", clock=clock)
    c.claim("q", agent="alice")
    clock.t += research.CLAIM_TTL - 5
    c.claim("q", agent="alice")                                    # refresh
    clock.t += 10
    assert c.holder("q").agent == "alice"                          # would be stale without the refresh
    assert c.release("q", agent="bob") is False
    assert c.holder("q").agent == "alice"
    assert c.release("q", agent="alice") is True
    assert c.holder("q") is None


def test_put_releases_the_claim(tmp_path):
    c = research.Cache(tmp_path / "r")
    c.claim("q", agent="alice")
    c.put("q", "found", agent="alice")
    assert c.holder("q") is None and not list((tmp_path / "r").glob("*.claim"))


def test_concurrent_claims_have_exactly_one_winner(tmp_path):
    c = research.Cache(tmp_path / "r")
    barrier = threading.Barrier(8)
    won, held = [], []

    def go(i):
        barrier.wait()
        try:
            won.append(c.claim("rfc 9110", agent=f"agent{i}").agent)
        except research.ClaimHeld as e:
            held.append(e.claim.agent)

    threads = [threading.Thread(target=go, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(won) == 1 and len(held) == 7
    assert set(held) == set(won)


def test_stale_takeover_has_one_winner_when_a_rival_acts_between_read_and_write(tmp_path):
    """Round-2 finding: bob and carol both see alice's stale claim. Bob's read of the claim is hooked
    so carol's whole take-over runs (in another thread) between bob's read and bob's write. Exactly
    one of them may come out holding the claim; the other gets ClaimHeld naming the winner."""
    clock = Clock()
    root = tmp_path / "r"
    research.Cache(root, clock=clock).claim("q", agent="alice")
    clock.t += research.CLAIM_TTL + 1                              # alice died: her claim is stale
    bob, carol = research.Cache(root, clock=clock), research.Cache(root, clock=clock)
    outcome = {}

    def carol_claims():
        try:
            outcome["carol"] = carol.claim("q", agent="carol").agent
        except research.ClaimHeld as e:
            outcome["carol"] = ("held", e.claim.agent)

    real_read = research.Cache._read_claim
    rival = threading.Thread(target=carol_claims)

    def bob_read(self, p, key):
        got = real_read(self, p, key)
        if self is bob and not rival.is_alive() and "carol" not in outcome:
            rival.start()
            # a lower bound only (rule 16): give carol time to finish if nothing stops her. With the
            # per-key lock she cannot finish until bob is done, so this wait simply times out.
            rival.join(timeout=2.0)
        return got

    research.Cache._read_claim = bob_read
    try:
        try:
            outcome["bob"] = bob.claim("q", agent="bob").agent
        except research.ClaimHeld as e:
            outcome["bob"] = ("held", e.claim.agent)
    finally:
        research.Cache._read_claim = real_read
    rival.join()
    winners = [who for who, got in outcome.items() if got == who]
    assert len(winners) == 1, outcome
    (loser,) = {"bob", "carol"} - set(winners)
    assert outcome[loser] == ("held", winners[0])
    assert research.Cache(root, clock=clock).holder("q").agent == winners[0]


def test_concurrent_stale_takeovers_have_exactly_one_winner(tmp_path):
    clock = Clock()
    c = research.Cache(tmp_path / "r", clock=clock)
    c.claim("rfc 9110", agent="dead")
    clock.t += research.CLAIM_TTL + 1
    barrier = threading.Barrier(8)
    won, held = [], []

    def go(i):
        barrier.wait()
        try:
            won.append(c.claim("rfc 9110", agent=f"agent{i}").agent)
        except research.ClaimHeld as e:
            held.append(e.claim.agent)

    threads = [threading.Thread(target=go, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(won) == 1 and len(held) == 7
    assert set(held) == set(won) and "dead" not in held


def test_release_with_no_claim_is_false_and_creates_nothing(tmp_path):
    c = research.Cache(tmp_path / "r")
    assert c.release("q", agent="alice") is False
    assert not (tmp_path / "r").exists()


def test_lookup_statuses(tmp_path):
    clock = Clock()
    c = research.Cache(tmp_path / "r", clock=clock)
    assert c.lookup("q", agent="alice").status == "miss"
    assert c.holder("q") is None                                   # a plain miss claims nothing
    got = c.lookup("q", agent="alice", claim=True)
    assert got.status == "claimed" and got.claim.agent == "alice"
    assert c.lookup("q", agent="bob", claim=True).status == "held"
    assert c.lookup("q", agent="alice", claim=True).status == "claimed"   # your own claim is not "held"
    c.put("q", "answer", agent="alice")
    hit = c.lookup("q", agent="bob", claim=True)
    assert hit.status == "hit" and hit.entry.answer == "answer"


def test_a_corrupt_claim_expires_instead_of_blocking_forever(tmp_path):
    clock = Clock()
    c = research.Cache(tmp_path / "r", clock=clock)
    c.claim("q", agent="alice")
    (p,) = (tmp_path / "r").glob("*.claim")
    p.write_text("garbage")
    import os
    os.utime(p, (clock.t, clock.t))
    assert c.holder("q").agent == "(unreadable claim)"
    clock.t += research.CLAIM_TTL + 1
    assert c.claim("q", agent="bob").agent == "bob"


# --------------------------------------------------------------------------- the command

def _args(*argv):
    p = argparse.ArgumentParser()
    cli_research.add_arguments(p)
    return p.parse_args(list(argv))


def test_cli_get_claim_put_get_flow(tmp_path, capsys):
    d = str(tmp_path / "r")
    assert cli_research.run(_args("--dir", d, "--agent", "alice", "get", "rfc 4648 base32", "--claim")) == 1
    assert "you (alice) now hold the claim" in capsys.readouterr().err
    assert cli_research.run(_args("--dir", d, "--agent", "bob", "get", "RFC 4648, base32", "--claim")) == 3
    assert "alice is looking this up now" in capsys.readouterr().err
    assert cli_research.run(_args("--dir", d, "--agent", "alice", "put", "rfc 4648 base32",
                                  "--answer", "A-Z2-7", "--source", "https://rfc-editor.org/rfc/rfc4648")) == 0
    capsys.readouterr()
    assert cli_research.run(_args("--dir", d, "--agent", "bob", "get", "RFC 4648, base32?")) == 0
    out = capsys.readouterr().out
    assert "answered by alice" in out and "asked: rfc 4648 base32" in out and "A-Z2-7" in out and "source: https://rfc-editor.org/rfc/rfc4648" in out
    assert cli_research.run(_args("--dir", d, "--agent", "bob", "put", "rfc 4648 base32", "--answer", "x")) == 2
    assert "already answered" in capsys.readouterr().err


def test_cli_hit_shows_the_stored_question(tmp_path, capsys):
    d = str(tmp_path / "r")
    assert cli_research.run(_args("--dir", d, "--agent", "a", "put", "How does PNG IHDR work?",
                                  "--answer", "13 bytes")) == 0
    capsys.readouterr()
    assert cli_research.run(_args("--dir", d, "get", "png ihdr work")) == 0
    assert "asked: How does PNG IHDR work?" in capsys.readouterr().out.splitlines()[1]


def test_cli_uses_the_event_workdir_by_default_and_ctf_agent(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CTF_AGENT", "worker-7")
    assert cli_research.run(_args("put", "some question", "--answer", "an answer")) == 0
    assert (tmp_path / "wd" / "research").is_dir()
    assert research.Cache(tmp_path / "wd" / "research").get("Some question").agent == "worker-7"


def test_cli_without_an_event_or_workdir_fails_loudly(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("CTF_WORKDIR")
    from ctf import event
    monkeypatch.setattr(event, "available", lambda root=None: ["a", "b"])
    assert cli_research.run(_args("get", "q")) == 2
    assert "no research store" in capsys.readouterr().err


def test_cli_refuses_secret_urls_and_answer_file(tmp_path, capsys):
    d = str(tmp_path / "r")
    assert cli_research.run(_args("--dir", d, "get", "https://x.com/?api_key=1")) == 2
    assert "secret-looking" in capsys.readouterr().err
    f = tmp_path / "ans.md"
    f.write_text("from a file")
    assert cli_research.run(_args("--dir", d, "put", "q", "--answer-file", str(f))) == 0
    assert research.Cache(tmp_path / "r").get("q").answer == "from a file"
    assert cli_research.run(_args("--dir", d, "put", "q2", "--answer-file", str(tmp_path / "missing"))) == 2


def test_cli_claim_release_list_and_key(tmp_path, capsys):
    d = str(tmp_path / "r")
    assert cli_research.run(_args("--dir", d, "--agent", "a", "claim", "q")) == 0
    assert cli_research.run(_args("--dir", d, "--agent", "b", "claim", "q")) == 3
    assert cli_research.run(_args("--dir", d, "--agent", "b", "release", "q")) == 1
    assert cli_research.run(_args("--dir", d, "--agent", "a", "release", "q")) == 0
    assert cli_research.run(_args("--dir", d, "--agent", "b", "claim", "q")) == 0
    capsys.readouterr()
    assert cli_research.run(_args("--dir", d, "list")) == 0
    assert "(no answers stored)" in capsys.readouterr().out
    assert cli_research.run(_args("key", "The PNG chunk")) == 0
    assert capsys.readouterr().out.strip() == "q:png chunk"
