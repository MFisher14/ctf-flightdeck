"""B-209: the manual-mode cockpit: drop-zone watcher, needs checklist, submission queue.

Runs against the shipped spooky profile (manual) and synthetic manual profiles; every file is a few
bytes written here. Nothing contacts a platform: a socket tripwire guards the end-to-end test.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
import tomllib

import pytest

from ctf import event, ledger, paths
from ctf.cockpit import Cockpit, CockpitError, Refused, board, make_id
from ctf.platform import get_adapter
from ctf.platform.rules import EventRules

OLD = time.time() - 3600


def _profile(**rules):
    data = tomllib.loads((paths.event_dir("spooky") / "event.toml").read_text())
    data["slug"] = "manualtest"
    data["rules"].update(rules)
    return event.parse(data, src="<test>")


@pytest.fixture
def work(tmp_path, monkeypatch):
    w = tmp_path / "work"
    monkeypatch.setenv("CTF_WORKDIR", str(w))
    monkeypatch.setenv("CTF_EVENT", "spooky")
    return w


@pytest.fixture
def ck(work):
    return Cockpit(event.load("spooky"), settle=0)


def drop(path, data=b"data", age=True):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if age:
        os.utime(path, (OLD, OLD))
    return path


def records(work, kind):
    return [r for r in ledger.read(work) if r["event"] == kind]


# ----------------------------------------------------------------------------- manual only
def test_refuses_an_event_that_is_not_manual(work):
    with pytest.raises(CockpitError, match="not manual"):
        Cockpit(event.load("csctf"))
    assert not (work / "inbox").exists()


def test_ai_forbidden_on_a_ctfd_platform_counts_as_manual(work):
    data = tomllib.loads((paths.event_dir("csctf") / "event.toml").read_text())
    data["rules"].update(submit_mode="manual", ai_on_platform="forbidden")
    data["sweep"]["mode"] = "forbidden"         # B-173: a manual event cannot authorize sweeps
    ck = Cockpit(event.parse(data, src="<test>"), settle=0)
    assert ck.drop_dir == work / "drop" and ck.inbox.is_dir()


def test_state_of_another_event_is_refused(work):
    Cockpit(_profile(), settle=0).add("Ghost")
    with pytest.raises(CockpitError, match="belongs to event 'manualtest'"):
        Cockpit(event.load("spooky")).needs()


# ----------------------------------------------------------------------------- drop zone
def test_inbox_folder_named_like_the_challenge_is_filed_where_the_adapter_reads(ck, work):
    cid = ck.add("Peering Eyes", category="Forensics", points=300)
    assert cid == "Peering-Eyes"
    drop(work / "inbox" / "peering eyes" / "box.lime", b"EMiL" + b"\x00" * 60)
    drop(work / "inbox" / "peering eyes" / "sub" / "symbols.json.xz", b"\xfd7zXZ\x00")
    rep = ck.sweep()
    assert sorted(f["rel"] for f in rep.filed) == ["box.lime", "sub/symbols.json.xz"]
    assert (work / "drop" / cid / "files" / "box.lime").read_bytes().startswith(b"EMiL")
    assert not (work / "inbox" / "peering eyes").exists()          # moved, not copied
    ch = get_adapter(event.load("spooky")).get_challenge(cid)
    assert (ch.name, ch.category, ch.points) == ("Peering Eyes", "Forensics", 300)
    assert sorted(f.name for f in ch.files) == ["files/box.lime", "files/sub/symbols.json.xz"]
    filed = records(work, "cockpit.filed")
    assert {r["file"] for r in filed} == {"box.lime", "sub/symbols.json.xz"}
    assert all(len(r["sha256"]) == 64 and r["challenge_id"] == cid for r in filed)


def test_inbox_folder_for_an_unknown_challenge_creates_it(ck, work):
    drop(work / "inbox" / "Heads will Roll!" / "a.png", b"\x89PNG....")
    rep = ck.sweep()
    assert rep.created == ["Heads-will-Roll"]
    assert (work / "drop" / "Heads-will-Roll" / "files" / "a.png").exists()
    assert ck.meta("Heads-will-Roll")["name"] == "Heads will Roll!"


def test_mirrored_layout_is_not_nested(ck, work):
    ck.add("Ghost")
    drop(work / "inbox" / "Ghost" / "files" / "g.bin")
    ck.sweep()
    assert (work / "drop" / "Ghost" / "files" / "g.bin").exists()
    assert not (work / "drop" / "Ghost" / "files" / "files").exists()


def test_loose_inbox_file_routing(ck, work):
    ck.add("Ghost")
    ck.add("Witch")
    drop(work / "inbox" / "Witch__spell.txt", b"abra")
    drop(work / "inbox" / "mystery.bin")
    drop(work / "inbox" / "nobody__x.bin")                 # prefix of no challenge: not created
    rep = ck.sweep()
    assert [(f["challenge"], f["rel"]) for f in rep.filed] == [("Witch", "spell.txt")]
    assert sorted(os.path.basename(u["src"]) for u in rep.unfiled) == ["mystery.bin", "nobody__x.bin"]
    assert (work / "inbox" / "mystery.bin").exists()
    assert ck.challenge_ids() == ["Ghost", "Witch"]
    ck.focus("ghost")
    rep = ck.sweep()
    assert sorted((f["challenge"], f["rel"]) for f in rep.filed) == [("Ghost", "mystery.bin"),
                                                                       ("Ghost", "nobody__x.bin")]
    assert all("focus" in f["how"] for f in rep.filed)


def test_need_expectation_routes_a_loose_file_and_closes_itself(ck, work):
    ck.add("Peering Eyes")
    ck.add("Other")
    ck.focus("Other")                                       # the expectation beats the focus
    n = ck.add_need("Peering-Eyes", "the 1 GB capture from the Drive link", kind="capture",
                    expect="*.lime")
    assert n["status"] == "open"
    drop(work / "inbox" / "memdump.LIME", b"EMiL" + b"\x00" * 30)
    rep = ck.sweep()
    assert [(f["challenge"], f["rel"]) for f in rep.filed] == [("Peering-Eyes", "memdump.LIME")]
    assert all(x.id != n["id"] for x in ck.needs())
    assert records(work, "cockpit.need_done")[-1]["need"] == n["id"]


def test_need_whose_file_is_already_there_is_done_at_once(ck, work):
    ck.add("Ghost")
    drop(work / "inbox" / "Ghost" / "a.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    ck.sweep()
    assert ck.add_need("Ghost", "the capture", expect="*.pcap")["status"] == "done"


def test_misplaced_drops_are_normalised(ck, work):
    ck.add("Ghost")
    drop(work / "drop" / "Ghost" / "loose.bin")                     # next to challenge.toml
    drop(work / "drop" / "Ghost" / "extra" / "deep.bin")
    drop(work / "drop" / "Ghost__atroot.bin")                       # at the drop root
    rep = ck.sweep()
    assert sorted(f["rel"] for f in rep.filed) == ["atroot.bin", "extra/deep.bin", "loose.bin"]
    assert sorted(p.name for p in (work / "drop" / "Ghost").iterdir()) == ["files"]
    assert not (work / "drop" / "Ghost__atroot.bin").exists()


def test_partial_and_fresh_downloads_wait(work):
    now = [time.time()]
    ck = Cockpit(event.load("spooky"), settle=5, clock=lambda: now[0])
    ck.add("Ghost")
    drop(work / "inbox" / "Ghost__a.zip.crdownload")
    drop(work / "inbox" / "Ghost__fresh.bin", age=False)
    drop(work / "inbox" / "Ghost" / "x.bin")
    drop(work / "inbox" / "Ghost" / "y.part")                        # the folder waits as a whole
    rep = ck.sweep()
    assert rep.filed == []
    assert sorted((os.path.basename(w["src"]), w["reason"]) for w in rep.waiting) == [
        ("Ghost__a.zip.crdownload", "partial download"), ("Ghost__fresh.bin", "still being written"),
        ("y.part", "partial download")]
    now[0] += 10
    os.rename(work / "inbox" / "Ghost" / "y.part", work / "inbox" / "Ghost" / "y.bin")
    rep = ck.sweep()
    assert sorted(f["rel"] for f in rep.filed) == ["fresh.bin", "x.bin", "y.bin"]


def test_watch_mode_files_only_what_looked_the_same_twice(ck, work):
    ck.track_growth = True
    ck.add("Ghost")
    p = drop(work / "inbox" / "Ghost__grow.bin", b"a")
    assert ck.sweep().filed == []
    p.write_bytes(b"ab")
    os.utime(p, (OLD + 1, OLD + 1))                                   # changed between passes
    assert ck.sweep().filed == []
    assert [f["rel"] for f in ck.sweep().filed] == ["grow.bin"]


def test_duplicates_conflicts_and_replace(ck, work):
    ck.add("Ghost")
    drop(work / "inbox" / "Ghost__a.bin", b"one")
    ck.sweep()
    drop(work / "inbox" / "Ghost__a.bin", b"one")
    rep = ck.sweep()
    assert len(rep.duplicates) == 1 and not (work / "inbox" / "Ghost__a.bin").exists()
    drop(work / "inbox" / "Ghost__a.bin", b"two")
    rep = ck.sweep()
    assert len(rep.conflicts) == 1 and (work / "inbox" / "Ghost__a.bin").read_bytes() == b"two"
    assert (work / "drop" / "Ghost" / "files" / "a.bin").read_bytes() == b"one"
    rep = ck.file("Ghost__a.bin", "Ghost", as_name="a.bin", replace=True)
    assert [f["rel"] for f in rep.filed] == ["a.bin"]
    assert (work / "drop" / "Ghost" / "files" / "a.bin").read_bytes() == b"two"


def test_a_redownload_replaces_a_bad_download(ck, work):
    ck.add("Ghost")
    drop(work / "inbox" / "Ghost__chal.zip", b"<!DOCTYPE html><html>scan warning")
    ck.sweep()
    assert any(n.id == "Ghost:disguised_html:chal.zip" and n.kind == "redownload" for n in ck.needs())
    drop(work / "inbox" / "Ghost__chal.zip", b"PK\x03\x04" + b"\x00" * 30)
    rep = ck.sweep()
    assert [f["rel"] for f in rep.filed] == ["chal.zip"] and "bad download" in rep.filed[0]["how"]
    assert (work / "drop" / "Ghost" / "files" / "chal.zip").read_bytes().startswith(b"PK")
    assert not any(n.kind == "redownload" for n in ck.needs())


def test_symlinks_are_never_moved_or_followed(ck, work, tmp_path):
    ck.add("Ghost")
    secret = drop(tmp_path / "outside.txt", b"keep me here")
    (work / "inbox").mkdir(exist_ok=True)
    os.symlink(secret, work / "inbox" / "Ghost__link.txt")
    drop(work / "inbox" / "Ghost" / "ok.bin")
    os.symlink(secret, work / "inbox" / "Ghost" / "inner.txt")
    os.symlink(secret, work / "drop" / "Ghost__rootlink.txt")
    os.symlink(secret, work / "drop" / "Ghost" / "folderlink.txt")
    rep = ck.sweep()
    assert sorted(os.path.basename(r["src"]) for r in rep.refused) == [
        "Ghost__link.txt", "Ghost__rootlink.txt", "folderlink.txt", "inner.txt"]
    assert [f["rel"] for f in rep.filed] == ["ok.bin"]
    assert secret.read_bytes() == b"keep me here"
    files = work / "drop" / "Ghost" / "files"
    assert sorted(p.name for p in files.iterdir()) == ["ok.bin"]
    assert (work / "drop" / "Ghost__rootlink.txt").is_symlink()


def test_one_bad_drop_does_not_stop_the_sweep(ck, work):
    ck.add("Ghost-1")
    assert ck.add("Ghost_1") == "Ghost-1"               # the same name ignoring punctuation
    (work / "drop" / "Ghost_1" / "files").mkdir(parents=True)   # a second folder made by hand
    ck.add("Witch")
    drop(work / "inbox" / "Ghost 1" / "a.bin")
    drop(work / "inbox" / "Witch" / "b.bin")
    rep = ck.sweep()
    assert [f["rel"] for f in rep.filed] == ["b.bin"]
    assert len(rep.refused) == 1 and "several challenges" in rep.refused[0]["reason"]
    assert (work / "inbox" / "Ghost 1" / "a.bin").exists()


def test_dropped_description_becomes_the_challenge_description(ck, work):
    drop(work / "inbox" / "Ghost" / "description.txt", b"Find the ghost in the pcap.\n")
    drop(work / "inbox" / "Ghost" / "a.png", b"\x89PNG")
    rep = ck.sweep()
    assert rep.described == ["Ghost"] and [f["rel"] for f in rep.filed] == ["a.png"]
    assert get_adapter(event.load("spooky")).get_challenge("Ghost").description == \
        "Find the ghost in the pcap."
    # The description promises a pcap and none is here: that is a need now.
    assert any(n.id == "Ghost:capture_missing" for n in ck.needs())


def test_a_dropped_description_that_differs_is_filed_not_deleted(ck, work):
    ck.add("Ghost", description="the description the player pasted")
    drop(work / "inbox" / "Ghost" / "description.txt", b"a different text\n")
    rep = ck.sweep()
    assert rep.described == [] and [f["rel"] for f in rep.filed] == ["description.txt"]
    assert (work / "drop" / "Ghost" / "files" / "description.txt").read_bytes() == b"a different text\n"
    assert ck.meta("Ghost")["description"] == "the description the player pasted"
    # The same text again is consumed: nothing new to keep.
    drop(work / "inbox" / "Witch" / "description.txt", b"brew\n")
    ck.sweep()
    drop(work / "inbox" / "Witch" / "description.txt", b"brew\n")
    rep = ck.sweep()
    assert rep.filed == [] and not (work / "inbox" / "Witch").exists()
    assert not (work / "drop" / "Witch" / "files" / "description.txt").exists()


def test_an_expected_file_several_challenges_await_is_left_unfiled(ck, work):
    ck.add("Peering Eyes")
    ck.add("Memory Lane")
    ck.add_need("Peering-Eyes", "the capture", kind="capture", expect="*.lime")
    ck.add_need("Memory-Lane", "the capture", kind="capture", expect="*.lime")
    drop(work / "inbox" / "memdump.lime", b"EMiL" + b"\x00" * 30)
    rep = ck.sweep()
    assert rep.filed == []
    [u] = rep.unfiled
    assert u["src"].endswith("memdump.lime") and "several challenges" in u["reason"]
    assert "Memory-Lane" in u["reason"] and "Peering-Eyes" in u["reason"]
    assert (work / "inbox" / "memdump.lime").exists()


def test_a_closed_need_added_again_is_a_new_open_need(ck):
    ck.add("Ghost")
    a = ck.add_need("Ghost", "start the instance", kind="instance")
    ck.done(a["id"])
    b = ck.add_need("Ghost", "start the instance", kind="instance")
    assert b["id"] != a["id"] and b["status"] == "open"
    assert [n.id for n in ck.needs() if n.kind == "instance"] == [b["id"]]


def test_a_fresh_description_in_a_challenge_folder_waits(work):
    now = [time.time()]
    ck = Cockpit(event.load("spooky"), settle=5, clock=lambda: now[0])
    ck.add("Ghost")
    p = drop(work / "drop" / "Ghost" / "description.txt", b"half a descr", age=False)
    rep = ck.sweep()
    assert rep.described == [] and [os.path.basename(w["src"]) for w in rep.waiting] == ["description.txt"]
    assert p.exists() and "description" not in ck.meta("Ghost")
    p.write_bytes(b"half a description, now whole")
    now[0] += 10
    rep = ck.sweep()
    assert rep.described == ["Ghost"] and ck.meta("Ghost")["description"] == "half a description, now whole"


def test_empty_unknown_folder_is_left_alone(ck, work):
    (work / "inbox" / "New Folder").mkdir(parents=True)
    rep = ck.sweep()
    assert ck.challenge_ids() == [] and (work / "inbox" / "New Folder").is_dir()
    assert "empty folder" in rep.unfiled[0]["reason"]


# ----------------------------------------------------------------------------- needs
def test_needs_are_complete_and_ordered_most_blocking_first(ck, work):
    ck.add("Ghost", description="a memory dump")
    ck.add("Witch")
    ck.add("Bat", description="just a web page")
    drop(work / "inbox" / "Ghost" / "symbols.json.xz", b"\xfd7zXZ\x00")
    drop(work / "inbox" / "Bat" / "x.txt", b"hello")
    ck.sweep()
    got = [(n.id, n.kind) for n in ck.needs()]
    assert got == [("Witch:files", "files"),
                   ("Ghost:helper_without_capture:symbols.json.xz", "capture"),
                   ("Witch:description", "description")]


def test_needs_resolve_as_the_drop_completes(ck, work):
    ck.add("Ghost")
    assert {n.id for n in ck.needs()} == {"Ghost:files", "Ghost:description"}
    drop(work / "inbox" / "Ghost" / "a.bin")
    ck.describe("Ghost", "boo")
    ck.sweep()
    assert ck.needs() == []


def test_done_dismisses_computed_needs_and_closes_added_ones(ck, work):
    ck.add("Web One", description="a site")
    assert [n.id for n in ck.needs()] == ["Web-One:files"]
    assert ck.done("Web-One:files") == "Web-One:files dismissed"
    assert ck.needs() == []
    assert ck.board()["challenges"][0]["state"] == "ready"
    n = ck.add_need("Web-One", "start the instance and paste host:port", kind="instance")
    assert [x.id for x in ck.needs()] == [n["id"]]
    ck.done(n["id"], note="host given")
    assert ck.needs() == []
    with pytest.raises(CockpitError, match="already done"):
        ck.done(n["id"])
    with pytest.raises(CockpitError, match="no open need"):
        ck.done("Web-One:nonsense")


def test_a_challenge_added_with_no_files_never_asks_for_them(ck):
    ck.add("OSINT Map", description="find the cemetery", no_files=True)
    ck.add("Other", description="d")
    assert [n.id for n in ck.needs()] == ["Other:files"]


def test_add_need_validates(ck):
    ck.add("Ghost")
    with pytest.raises(CockpitError, match="no challenge"):
        ck.add_need("Nope", "x")
    with pytest.raises(CockpitError, match="need kind"):
        ck.add_need("Ghost", "x", kind="pizza")
    a = ck.add_need("Ghost", "same text")
    assert ck.add_need("Ghost", "same text")["id"] == a["id"]


def test_board_always_says_how_many_are_open():
    from ctf.cockpit.core import Need
    needs = [Need(f"c{i}:files", f"c{i}", "files", "get it", "auto", float(i)) for i in range(7)]
    lines = board.needs_lines(needs, 3)
    assert lines[0].startswith("NEEDS  7 open across 7 challenge(s); next 3")
    assert len(lines) == 4 and "[c2:files]" in lines[3]
    assert len(board.needs_lines(needs, None)) == 8
    assert "7 open" in board.needs_lines(needs, 10)[0] and "next" not in board.needs_lines(needs, 10)[0]


# ----------------------------------------------------------------------------- queue
def test_enqueue_checks_like_the_submit_gate(ck):
    ck.add("Ghost")
    with pytest.raises(Refused, match="provenance"):
        ck.enqueue("Ghost", "spooky{a}", provenance=" ")
    with pytest.raises(Refused, match="flag format"):
        ck.enqueue("Ghost", "POSTO_DECIO", provenance="map")
    q = ck.enqueue("Ghost", "POSTO_DECIO", provenance="map", nonstandard=True)
    assert q["status"] == "pending"
    ck.enqueue("Ghost", "spooky{a}", provenance="xor")
    with pytest.raises(Refused, match="already holds"):
        ck.enqueue("Ghost", "SPOOKY{a}", provenance="xor again")   # prefix-insensitive dedupe
    with pytest.raises(CockpitError, match="no challenge"):
        ck.enqueue("Nope", "spooky{a}", provenance="x")
    assert [x["flag"] for x in ck.queue()] == ["POSTO_DECIO", "spooky{a}"]


def test_a_rejected_value_cannot_be_queued_again(ck):
    ck.add("Ghost")
    q = ck.enqueue("Ghost", "spooky{a}", provenance="xor")
    ck.verdict(q["id"], False, by="max", interactive=True)
    with pytest.raises(Refused, match="rejected"):
        ck.enqueue("Ghost", "spooky{a}", provenance="xor")


def test_wrong_answer_stop_from_player_verdicts(work):
    ck = Cockpit(_profile(wrong_answer_stop=2), settle=0)
    ck.add("Ghost")
    for i in range(2):
        q = ck.enqueue("Ghost", f"spooky{{w{i}}}", provenance="try")
        out = ck.verdict(q["id"], False, by="max", interactive=True)
    assert out["stop"] and out["wrong"] == 2
    with pytest.raises(Refused, match="wrong_answer_stop"):
        ck.enqueue("Ghost", "spooky{w2}", provenance="try")
    # B-006: confirmed=True alone does not pass the stop; the player's counted approval is needed too.
    with pytest.raises(Refused, match="no unused player approval"):
        ck.enqueue("Ghost", "spooky{w2}", provenance="player said go", confirmed=True)
    EventRules(ck.profile).grant("Ghost", "max: try the w2 variant")
    q = ck.enqueue("Ghost", "spooky{w2}", provenance="player said go", confirmed=True)
    assert q["confirmed"]
    # The gate's own rules see the same count: one memory of submissions.
    assert EventRules(ck.profile).wrong_count("Ghost") == 2


def test_guess_budget(work):
    ck = Cockpit(_profile(guess_budget=1), settle=0)
    ck.add("Ghost")
    q = ck.enqueue("Ghost", "spooky{g1}", provenance="variant", guess=True)
    ck.verdict(q["id"], False, by="max", interactive=True)
    with pytest.raises(Refused, match="guess_budget"):
        ck.enqueue("Ghost", "spooky{g2}", provenance="variant", guess=True)
    ck.enqueue("Ghost", "spooky{reasoned}", provenance="derived")         # a reasoned value passes


def test_spooky_has_no_guess_budget(ck):
    ck.add("Ghost")
    with pytest.raises(Refused, match="guess_budget"):
        ck.enqueue("Ghost", "spooky{g}", provenance="variant", guess=True)


def test_accepted_verdict_writes_solved_and_records(ck, work):
    ck.add("Ghost")
    a = ck.enqueue("Ghost", "spooky{right}", provenance="stego lsb")
    b = ck.enqueue("Ghost", "spooky{other}", provenance="alt")
    n = ck.add_need("Ghost", "anything else")
    assert not (work / "drop" / "Ghost" / "SOLVED").exists()           # queueing never marks solved
    out = ck.verdict(a["id"], True, by="max", interactive=True)
    assert out["status"] == "accepted"
    assert (work / "drop" / "Ghost" / "SOLVED").read_text().splitlines()[0] == "max"
    [solve] = get_adapter(event.load("spooky")).team_solves()
    assert (solve.challenge_id, solve.solver) == ("Ghost", "max")
    assert {q["id"]: q["status"] for q in ck.queue(all_items=True)} == {a["id"]: "accepted",
                                                                       b["id"]: "superseded"}
    assert ck.needs() == [] and all(x.id != n["id"] for x in ck.needs())
    [rec] = records(work, "platform.submit")
    assert (rec["status"], rec["judged"], rec["challenge_id"]) == ("correct", True, "Ghost")
    assert "flag" not in rec and len(rec["flag_sha256"]) == 64           # spooky: flag_sharing forbidden
    assert all("flag" not in r for r in records(work, "cockpit.enqueue"))
    with pytest.raises(Refused, match="already solved"):
        ck.enqueue("Ghost", "spooky{late}", provenance="x")
    with pytest.raises(Refused, match="not pending"):
        ck.verdict(b["id"], True, by="max", interactive=True)


def test_flag_sharing_allowed_keeps_the_value(work):
    ck = Cockpit(_profile(flag_sharing="allowed"), settle=0)
    ck.add("Ghost")
    q = ck.enqueue("Ghost", "spooky{v}", provenance="x")
    ck.verdict(q["id"], False, by="max", interactive=True)
    [rec] = records(work, "platform.submit")
    assert rec["flag"] == "spooky{v}" and rec["status"] == "incorrect"


def test_a_verdict_without_a_terminal_needs_the_players_words(ck, work):
    ck.add("Ghost")
    q = ck.enqueue("Ghost", "spooky{x}", provenance="x")
    with pytest.raises(Refused, match="player"):
        ck.verdict(q["id"], True, by="agent", interactive=False)
    assert not (work / "drop" / "Ghost" / "SOLVED").exists()
    assert records(work, "platform.submit") == [] and ck.queue()[0]["status"] == "pending"
    out = ck.verdict(q["id"], True, by="agent", interactive=False, relayed="accepted!! nice")
    assert out["status"] == "accepted"
    assert records(work, "cockpit.verdict")[0]["relayed"] == "accepted!! nice"


def test_withdraw(ck):
    ck.add("Ghost")
    q = ck.enqueue("Ghost", "spooky{x}", provenance="x")
    assert ck.withdraw(q["id"], "decoy")["status"] == "withdrawn"
    assert ck.queue() == [] and ck.next_item() is None
    ck.enqueue("Ghost", "spooky{x}", provenance="x")                    # withdrawn is not a dedupe hit


def test_values_queued_before_the_stop_are_held_not_served(work):
    ck = Cockpit(_profile(wrong_answer_stop=2), settle=0)
    ck.add("Ghost")
    a, b, c = (ck.enqueue("Ghost", f"spooky{{v{i}}}", provenance="try") for i in range(3))
    ck.verdict(a["id"], False, by="max", interactive=True)
    assert ck.next_item()["id"] == b["id"]
    out = ck.verdict(b["id"], False, by="max", interactive=True)
    assert out["stop"] and out["held"] == [c["id"]]
    assert ck.next_item() is None                                       # #3 is never served
    [held] = ck.queue()
    assert held["id"] == c["id"] and "wrong_answer_stop" in held["held"]
    with pytest.raises(Refused, match="held"):
        ck.verdict(c["id"], False, by="max", interactive=True)
    assert EventRules(ck.profile).wrong_count("Ghost") == 2             # nothing recorded for #3
    assert ck.queue()[0]["status"] == "pending"
    with pytest.raises(Refused, match="player"):
        ck.confirm(c["id"], by="agent", interactive=False)
    assert ck.next_item() is None
    # B-006: the confirm alone leaves it held until the player records a counted approval.
    assert "no unused player approval" in ck.confirm(c["id"], by="max", interactive=True)["held"]
    assert records(work, "cockpit.confirm")[0]["item"] == c["id"]
    assert ck.next_item() is None
    with pytest.raises(Refused, match="submit-queue approve Ghost"):
        ck.verdict(c["id"], False, by="max", interactive=True)
    EventRules(ck.profile).grant("Ghost", "max: send v2")
    assert ck.queue()[0]["held"] is None
    assert ck.next_item()["id"] == c["id"]
    assert ck.verdict(c["id"], False, by="max", interactive=True)["wrong"] == 3


def test_queued_guesses_count_against_the_budget(work):
    ck = Cockpit(_profile(guess_budget=1), settle=0)
    ck.add("Ghost")
    g1 = ck.enqueue("Ghost", "spooky{g1}", provenance="variant", guess=True)
    with pytest.raises(Refused, match="1 queued"):
        ck.enqueue("Ghost", "spooky{g2}", provenance="variant", guess=True)
    ck.enqueue("Ghost", "spooky{reasoned}", provenance="derived")         # a reasoned value passes
    ck.withdraw(g1["id"])
    ck.enqueue("Ghost", "spooky{g2}", provenance="variant", guess=True)


def test_a_guess_spent_elsewhere_holds_the_queued_one(work):
    from ctf.platform import SubmitResult, SubmitStatus
    from ctf.platform.policy import SubmitRequest
    ck = Cockpit(_profile(guess_budget=1), settle=0)
    ck.add("Ghost")
    g = ck.enqueue("Ghost", "spooky{g1}", provenance="variant", guess=True)
    assert ck.next_item()["id"] == g["id"]
    # A judged guess recorded by the gate on another path (the same ledger) spends the budget.
    EventRules(ck.profile).record(ck.profile, SubmitRequest("Ghost", "spooky{other}", "v", False, False, True),
                                  SubmitResult(SubmitStatus.INCORRECT, "x", sent=True))
    assert ck.next_item() is None and "guess_budget" in ck.queue()[0]["held"]
    assert ck.confirm(g["id"], by="max", interactive=True)["held"]      # a yes does not lift a budget
    assert ck.next_item() is None
    with pytest.raises(Refused, match="withdraw"):
        ck.verdict(g["id"], True, by="max", interactive=True)
    assert not (work / "drop" / "Ghost" / "SOLVED").exists()


def test_a_solved_marker_that_cannot_be_written_records_nothing(ck, work, tmp_path, monkeypatch):
    ck.add("Ghost")
    q = ck.enqueue("Ghost", "spooky{right}", provenance="x")
    elsewhere = tmp_path / "elsewhere"
    os.symlink(elsewhere, work / "drop" / "Ghost" / "SOLVED")
    with pytest.raises(CockpitError, match="symlink"):
        ck.verdict(q["id"], True, by="max", interactive=True)
    assert records(work, "platform.submit") == [] and not elsewhere.exists()
    assert ck.queue()[0]["status"] == "pending"
    os.unlink(work / "drop" / "Ghost" / "SOLVED")

    def broken(*a, **k):
        raise OSError("disk full")
    with monkeypatch.context() as m:                                   # (undo() would drop the env too)
        m.setattr(EventRules, "record", broken)
        with pytest.raises(OSError, match="disk full"):
            ck.verdict(q["id"], True, by="max", interactive=True)
    assert not (work / "drop" / "Ghost" / "SOLVED").exists()          # no record, no marker
    assert ck.queue()[0]["status"] == "pending"
    ck.verdict(q["id"], True, by="max", interactive=True)
    assert len(records(work, "platform.submit")) == 1


@pytest.mark.parametrize("as_name", ["../../x.bin", "../x.bin", "/abs/x.bin", "sub/../../x.bin",
                                     ".hidden", ""])
def test_file_as_must_stay_under_files(ck, work, as_name):
    ck.add("Ghost")
    src = drop(work / "inbox" / "a.bin", b"payload")
    with pytest.raises(CockpitError, match="plain name"):
        ck.file("a.bin", "Ghost", as_name=as_name)
    assert src.read_bytes() == b"payload"
    assert list((work / "drop" / "Ghost" / "files").iterdir()) == []
    assert not (work / "drop" / "x.bin").exists() and not (work / "x.bin").exists()


def test_file_never_lands_through_a_symlinked_folder(ck, work, tmp_path):
    ck.add("Ghost")
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(outside, work / "drop" / "Ghost" / "files" / "sub")
    src = drop(work / "inbox" / "a.bin", b"payload")
    with pytest.raises(CockpitError, match="outside"):
        ck.file("a.bin", "Ghost", as_name="sub/a.bin")
    assert list(outside.iterdir()) == [] and src.exists()
    assert [f["rel"] for f in ck.file("a.bin", "Ghost", as_name="deep/a.bin").filed] == ["deep/a.bin"]


def test_concurrent_writers_lose_nothing(work):
    Cockpit(event.load("spooky"), settle=0).add("Ghost")
    errors = []

    def worker(tag):
        c = Cockpit(event.load("spooky"), settle=0)                    # its own lock descriptor
        try:
            for i in range(15):
                c.enqueue("Ghost", f"spooky{{{tag}{i}}}", provenance="t")
        except Exception as e:                                         # surfaced below
            errors.append(e)

    ts = [threading.Thread(target=worker, args=(t,)) for t in "abc"]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert errors == []
    items = Cockpit(event.load("spooky")).queue()
    assert len(items) == 45 and len({q["id"] for q in items}) == 45


def test_state_file_is_private(ck, work):
    ck.add("Ghost")
    ck.enqueue("Ghost", "spooky{x}", provenance="x")
    assert (work / "cockpit" / "state.json").stat().st_mode & 0o077 == 0


def test_make_id():
    assert make_id("Cyberphobia: Formatting Nightmare") == "Cyberphobia-Formatting-Nightmare"
    assert make_id("J*b Application") == "J-b-Application"
    with pytest.raises(CockpitError):
        make_id("***")


def test_challenge_toml_round_trips_odd_text(ck, work):
    text = 'Quote " back\\slash\nnew line\ttab \x7f del, ünïcode 👻'
    ck.add("Ghost", description=text, points=100, category="Misc")
    assert get_adapter(event.load("spooky")).get_challenge("Ghost").description == text


# ----------------------------------------------------------------------------- end to end, CLI
def test_cycle_never_touches_the_network(ck, work, monkeypatch):
    def trip(*a, **k):
        raise AssertionError("the cockpit opened a socket")
    for name in ("socket", "create_connection", "getaddrinfo"):
        monkeypatch.setattr(socket, name, trip)
    ck.add("Ghost")
    drop(work / "inbox" / "Ghost" / "a.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    ck.sweep()
    q = ck.enqueue("Ghost", "spooky{net}", provenance="tcp stream 3")
    ck.verdict(q["id"], True, by="max", interactive=True)
    assert board.render(ck.board(), batch=3)


def _cli(work, *args, env_extra=None, stdin=None):
    env = dict(os.environ, CTF_WORKDIR=str(work), CTF_EVENT="spooky", **(env_extra or {}))
    return subprocess.run([sys.executable, "-m", "ctf", "cockpit", *args], cwd=paths.repo_root(),
                          env=env, capture_output=True, text=True, input=stdin, timeout=120)


def test_cli_cycle(work, tmp_path):
    assert _cli(work, "add", "Peering Eyes", "Hashphobia", "--category", "Forensics").returncode == 0
    drop(work / "inbox" / "Peering Eyes" / "symbols.json.xz", b"\xfd7zXZ\x00")
    r = _cli(work, "--settle", "0", "watch", "--once")
    assert r.returncode == 0, r.stderr
    assert "FILED  Peering-Eyes/files/symbols.json.xz" in r.stdout
    assert "NEEDS  4 open across 2 challenge(s); next 3" in r.stdout
    r = _cli(work, "needs", "--json")
    assert {n["id"] for n in json.loads(r.stdout)} == {
        "Hashphobia:files", "Hashphobia:description", "Peering-Eyes:description",
        "Peering-Eyes:helper_without_capture:symbols.json.xz"}
    assert _cli(work, "describe", "Hashphobia", "-", stdin="Tweet and check reviews").returncode == 0
    r = _cli(work, "enqueue", "Hashphobia", "notaflag", "--provenance", "x")
    assert r.returncode == 4 and "refused" in r.stderr
    r = _cli(work, "enqueue", "Hashphobia", "spooky{tweet}", "--provenance", "acrostic")
    assert r.returncode == 0 and "queued #" in r.stdout
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "pbcopy").write_text(f"#!/bin/sh\ncat > '{tmp_path / 'clip'}'\n")
    (fake / "pbcopy").chmod(0o755)
    r = _cli(work, "next", "--copy", env_extra={"PATH": f"{fake}:{os.environ['PATH']}"})
    assert r.returncode == 0 and "spooky{tweet}" in r.stdout
    assert (tmp_path / "clip").read_text() == "spooky{tweet}"
    qid = json.loads(_cli(work, "queue", "--json").stdout)[0]["id"]
    r = _cli(work, "accepted", str(qid))                    # no terminal and no --relayed
    assert r.returncode == 4 and not (work / "drop" / "Hashphobia" / "SOLVED").exists()
    r = _cli(work, "accepted", str(qid), "--relayed", "accepted", "--by", "max")
    assert r.returncode == 0 and (work / "drop" / "Hashphobia" / "SOLVED").read_text().startswith("max\n")
    r = _cli(work, "status", "--json")
    states = {c["id"]: c["state"] for c in json.loads(r.stdout)["challenges"]}
    assert states == {"Hashphobia": "solved", "Peering-Eyes": "needs"}


def test_cli_holds_and_confirms_past_the_stop(work):
    _cli(work, "add", "Ghost", "--no-files")
    for i in range(4):                                     # spooky: wrong_answer_stop = 3
        assert _cli(work, "enqueue", "Ghost", f"spooky{{c{i}}}", "--provenance", "x").returncode == 0
    ids = [q["id"] for q in json.loads(_cli(work, "queue", "--json").stdout)]
    for qid in ids[:2]:
        assert _cli(work, "rejected", str(qid), "--relayed", "nope").returncode == 0
    r = _cli(work, "rejected", str(ids[2]), "--relayed", "nope")
    assert r.returncode == 0 and "wrong_answer_stop" in r.stdout and f"#{ids[3]}" in r.stdout
    r = _cli(work, "next")
    assert r.returncode == 0 and "1 held" in r.stdout and "spooky{c3}" not in r.stdout
    r = _cli(work, "accepted", str(ids[3]), "--relayed", "yes")
    assert r.returncode == 4 and "held" in r.stderr
    assert not (work / "drop" / "Ghost" / "SOLVED").exists()
    assert _cli(work, "confirm", str(ids[3])).returncode == 4          # no terminal, no --relayed
    r = _cli(work, "confirm", str(ids[3]), "--relayed", "go on, send it")
    assert r.returncode == 4 and "still held" in r.stdout and "no unused player approval" in r.stdout
    env = dict(os.environ, CTF_WORKDIR=str(work), CTF_EVENT="spooky")    # B-006: the player's approval
    a = subprocess.run([sys.executable, "-m", "ctf", "submit-queue", "approve", "Ghost", "--reason",
                        "max: send c3"], cwd=paths.repo_root(), env=env, capture_output=True, text=True,
                       timeout=120)
    assert a.returncode == 0, a.stderr
    r = _cli(work, "confirm", str(ids[3]), "--relayed", "go on, send it")
    assert r.returncode == 0 and "next` serves it" in r.stdout
    assert "spooky{c3}" in _cli(work, "next").stdout


def test_cli_copy_without_pbcopy_fails_loudly(work, tmp_path):
    _cli(work, "add", "Ghost", "--no-files")
    _cli(work, "enqueue", "Ghost", "spooky{c}", "--provenance", "x")
    empty = tmp_path / "nobin"
    empty.mkdir()
    r = _cli(work, "next", "--copy", env_extra={"PATH": str(empty)})
    assert r.returncode == 2 and "pbcopy" in r.stderr


def test_cli_refuses_a_non_manual_event(work):
    r = _cli(work, "--event", "csctf", "status")
    assert r.returncode == 2 and "not manual" in r.stderr
