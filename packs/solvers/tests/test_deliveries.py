"""B-042: which delivery serves which set (ctf/deliveries.py) and the `ctf deliveries` command.

Every attempt here is written by the test: questions with `setN.` ids, deliveries that share a file name
and member names (the Huntress Mastery shapes), and the cases the old runner answered from a neighbour's
delivery. No real challenge file, no network."""
from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from ctf import deliveries as D
from ctf import paths


def q(n, qid="answer", artifact="", **extra):
    out = {"id": f"set{n}.{qid}" if n else qid, "question": "?", "artifact": artifact}
    out.update(extra)
    return out


def zipped(members, password=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, body in members:
            z.writestr(zipfile.ZipInfo(name, date_time=(2026, 10, 1, 0, 0, 0)), body)
    return buf.getvalue()


def save(folder: Path, deliveries, questions, *, sha=True, name_files=True) -> Path:
    art = folder / "artifact"
    for i, (name, data) in enumerate(deliveries):
        d = art if len(deliveries) == 1 else art / f"delivery-{i + 1:02d}"
        d.mkdir(parents=True, exist_ok=True)
        (d / name).write_bytes(data)
    arts = [{"filename": name if name_files else None,
             **({"sha256": hashlib.sha256(data).hexdigest()} if sha else {})} for name, data in deliveries]
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "attempt.json").write_text(json.dumps({"questions": questions, "artifacts": arts}))
    return folder


# --------------------------------------------------------------------------- reading a question

def test_set_of_reads_the_id_prefix_then_the_set_field():
    assert D.set_of({"id": "set12.message"}) == 12
    assert D.set_of({"id": "set3.x", "set": 9}) == 3, "the id's prefix wins over the field"
    assert D.set_of({"id": "message", "set": 4}) == 4
    assert D.set_of({"id": "message"}) == 0
    assert D.set_of({"id": "message", "set": True}) == 0, "a boolean is not a set number"
    assert D.set_of({"id": "message", "set": "4"}) == 0, "nor is a string"
    assert D.set_of({"id": "reset1.x"}) == 0, "setN. must lead the id"


def test_a_delivery_is_named_only_at_the_start_of_the_artifact_text():
    assert D.named_delivery({"artifact": "delivery 2: evidence.zip -> x.ps1"}) == 2
    assert D.named_delivery({"artifact": "  delivery 10 : blob.txt"}) == 10
    assert D.named_delivery({"artifact": "evidence-01.zip -> delivery 2: notes.txt"}) is None
    assert D.named_delivery({"artifact": "delivery 2 notes.txt"}) is None, "no colon: a file name, not a delivery"
    assert D.named_delivery({}) is None


def test_chain_drops_the_delivery_head():
    assert D.chain({"artifact": "delivery 1: evidence.zip -> stage.zip -> x.js"}) == ["evidence.zip", "stage.zip", "x.js"]
    assert D.chain({"artifact": "blob-02.txt"}) == ["blob-02.txt"]
    assert D.chain({}) == []


# --------------------------------------------------------------------------- the rules

def test_one_set_sees_every_delivery():
    for count in (0, 1, 3):
        c = D.choose(0, [q(0)], [0], count)
        assert (c.rule, c.index, c.member, c.mapped) == (D.ALL, None, None, True)
    assert D.choose(1, [q(1)], [1], 2).rule == D.ALL
    # one numbered set whose questions all name one of several deliveries reads that one
    c = D.choose(1, [q(1, artifact="delivery 2: b.zip"), q(1, "b", "delivery 2: b.zip -> x")], [1], 3)
    assert (c.rule, c.index) == (D.NAMED, 1)
    assert D.choose(0, [q(0, artifact="delivery 2: b.zip")], [0], 3).rule == D.ALL, "an unnumbered set: all of them"


def test_named_is_the_questions_own_word_even_against_set_order():
    sets = [1, 2, 3]
    # set 1's questions name delivery 3: position would say delivery 1
    c = D.choose(1, [q(1, artifact="delivery 3: blob.txt"), q(1, "b", "delivery 3: blob.txt")], sets, 3)
    assert (c.rule, c.index, c.reason) == (D.NAMED, 2, "")
    # a question that names none does not break the set's one name
    c = D.choose(2, [q(2, artifact="delivery 1: blob.txt"), q(2, "b", "")], sets, 3)
    assert (c.rule, c.index) == (D.NAMED, 0)


def test_questions_naming_two_deliveries_leave_the_set_unmapped():
    c = D.choose(2, [q(2, artifact="delivery 1: a.zip"), q(2, "b", "delivery 2: a.zip")], [1, 2], 2)
    assert not c.mapped and c.rule == D.UNMAPPED and c.index is None
    assert "deliveries 1, 2" in c.reason


def test_a_named_delivery_the_attempt_does_not_have_is_unmapped():
    c = D.choose(3, [q(3, artifact="delivery 3: blob.txt")], [1, 2, 3], 2)
    assert c.rule == D.UNMAPPED and "delivery 3" in c.reason and "has 2" in c.reason
    c = D.choose(1, [q(1, artifact="delivery 0: blob.txt")], [1, 2], 2)
    assert c.rule == D.UNMAPPED, "deliveries are numbered from 1"
    # one bundle, and the set names delivery 2: never the bundle's numbered member instead
    c = D.choose(2, [q(2, artifact="delivery 2: blob.txt")], [1, 2], 1, ["blob-01.txt", "blob-02.txt"])
    assert c.rule == D.UNMAPPED


def test_position_pairs_set_n_with_delivery_n_only_when_they_pair_one_to_one():
    for n in (1, 2, 3):
        c = D.choose(n, [q(n, artifact="evidence-0%d.zip -> a.ps1" % n)], [1, 2, 3], 3)
        assert (c.rule, c.index) == (D.POSITION, n - 1)
    # three sets and two deliveries: the old runner gave set 3 the last delivery (set 2's)
    for n in (1, 2, 3):
        c = D.choose(n, [q(n)], [1, 2, 3], 2)
        assert c.rule == D.UNMAPPED and "do not pair one to one with 2 deliveries" in c.reason
    # sets 2 and 3 of three deliveries, and sets 2 and 3 of two: neither is 1..count
    assert D.choose(2, [q(2)], [2, 3], 3).rule == D.UNMAPPED
    assert D.choose(3, [q(3)], [2, 3], 2).rule == D.UNMAPPED
    # questions with no set number beside numbered sets belong to no delivery
    assert D.choose(0, [q(0)], [0, 1, 2], 3).rule == D.UNMAPPED
    assert D.choose(1, [q(1)], [0, 1, 2], 3).rule == D.UNMAPPED


def test_a_multi_set_attempt_with_no_delivery_is_unmapped():
    c = D.choose(1, [q(1)], [1, 2], 0)
    assert c.rule == D.UNMAPPED and c.reason == "the attempt has no delivery"


def test_member_is_the_bundles_one_member_numbered_for_the_set():
    members = ["blob-12.txt", "blob-02.txt", "blob-20.txt", "blob-2.bak.txt", "notes.txt", "blob-01.txt"]
    c = D.choose(2, [q(2, artifact="blob-02.txt")], [1, 2], 1, members)
    assert (c.rule, c.index, c.member) == (D.MEMBER, 0, "blob-02.txt"), "12 and 20 are not 2"
    assert D.choose(1, [q(1)], [1, 2], 1, members).member == "blob-01.txt"
    assert D.choose(12, [q(12)], [1, 2, 12], 1, members).member == "blob-12.txt"
    # unpadded and folder members
    assert D.choose(2, [q(2)], [1, 2], 1, ["sets/evidence-1.zip", "sets/evidence-2.zip"]).member == "sets/evidence-2.zip"


def test_two_members_numbered_for_a_set_need_the_questions_to_name_one():
    members = ["evidence-01.zip", "notes-01.txt", "evidence-02.zip"]
    c = D.choose(1, [q(1, artifact="evidence-01.zip -> a.txt"), q(1, "b", "evidence-01.zip -> b.txt")], [1, 2], 1, members)
    assert (c.rule, c.member) == (D.MEMBER, "evidence-01.zip")
    c = D.choose(1, [q(1, artifact="delivery 1: notes-01.txt")], [1, 2], 1, members)
    assert c.member == "notes-01.txt", "the head of the chain, after the delivery"
    c = D.choose(1, [q(1, artifact="a.txt")], [1, 2], 1, members)
    assert c.rule == D.UNMAPPED and "2 members of the bundle are numbered 1" in c.reason
    c = D.choose(1, [q(1, artifact="evidence-01.zip -> a"), q(1, "b", "notes-01.txt")], [1, 2], 1, members)
    assert c.rule == D.UNMAPPED, "the questions name both"


def test_a_bundle_with_no_numbered_member_is_read_whole_only_on_the_questions_word():
    members = ["alpha.ps1", "beta.ps1"]
    named = [q(2, artifact="delivery 1: bundle.zip -> beta.ps1"), q(2, "b", "delivery 1: bundle.zip -> beta.ps1")]
    c = D.choose(2, named, [1, 2], 1, members)
    assert (c.rule, c.index, c.member) == (D.NAMED, 0, None)
    # the old runner handed the whole bundle to a set whose questions said nothing of the kind
    c = D.choose(2, [q(2, artifact="beta.ps1")], [1, 2], 1, members)
    assert c.rule == D.UNMAPPED and "no member of the bundle is numbered 2" in c.reason
    c = D.choose(2, [named[0], q(2, "b", "beta.ps1")], [1, 2], 1, members)
    assert c.rule == D.UNMAPPED, "one question that does not name the delivery leaves it unproven"


def test_the_bundle_case_refuses_to_guess_without_the_member_names():
    with pytest.raises(D.DeliveryError, match="member names"):
        D.choose(1, [q(1)], [1, 2], 1)


def test_plan_covers_every_set_in_set_order_and_labels_them():
    attempt = {"questions": [q(2, artifact="delivery 2: evidence.zip -> a.ps1"), q(1, artifact="delivery 1: evidence.zip"),
                             q(2, "b", "delivery 2: evidence.zip")],
               "artifacts": [{"filename": "evidence.zip"}, {"filename": "evidence.zip"}]}
    plan = D.plan(attempt)
    assert [(c.set, c.rule, c.index) for c in plan] == [(1, D.NAMED, 0), (2, D.NAMED, 1)]
    names = ["evidence.zip", "evidence.zip"]
    assert [c.label(names) for c in plan] == ["delivery 1: evidence.zip", "delivery 2: evidence.zip"]
    assert plan[1].to_dict() == {"set": 2, "rule": "named", "delivery": 2, "member": None, "reason": ""}
    bundle = D.plan({"questions": [q(1), q(2), q(3)], "artifacts": [{"filename": "b.zip"}]}, members=["x-1.txt", "x-2.txt"])
    assert [c.label(["b.zip"]) for c in bundle][:2] == ["delivery 1: b.zip -> x-1.txt", "delivery 1: b.zip -> x-2.txt"]
    assert bundle[2].label(["b.zip"]).startswith("UNMAPPED: no member of the bundle is numbered 3")
    assert D.plan({"questions": [q(0)], "artifacts": []})[0].label([]) == "every delivery"


# --------------------------------------------------------------------------- a saved attempt

def test_read_attempt_reads_same_named_deliveries_from_their_numbered_folders(tmp_path):
    save(tmp_path / "m", [("blob.txt", b"one"), ("blob.txt", b"two"), ("blob.txt", b"three")], [q(1), q(2), q(3)])
    for where in (tmp_path / "m", tmp_path / "m" / "attempt.json"):
        s = D.read_attempt(where)
        assert s.names == ("blob.txt",) * 3 and s.blobs == (b"one", b"two", b"three") and s.folder == tmp_path / "m"
    assert D.is_attempt(tmp_path / "m" / "attempt.json") and not D.is_attempt(tmp_path / "m")
    assert not D.is_attempt(tmp_path / "m" / "artifact" / "delivery-01" / "blob.txt")


def test_read_attempt_reads_one_delivery_and_an_unnamed_one(tmp_path):
    save(tmp_path / "a", [("evidence.zip", b"zipbytes")], [q(0)])
    assert D.read_attempt(tmp_path / "a").blobs == (b"zipbytes",)
    save(tmp_path / "b", [("whatever.bin", b"x"), ("other.bin", b"y")], [q(1), q(2)], name_files=False)
    s = D.read_attempt(tmp_path / "b")
    assert s.names == ("whatever.bin", "other.bin") and s.blobs == (b"x", b"y")
    # an active base attempt lists its one delivery at the top level
    (tmp_path / "c" / "artifact").mkdir(parents=True)
    (tmp_path / "c" / "artifact" / "blob.txt").write_bytes(b"top")
    (tmp_path / "c" / "attempt.json").write_text(json.dumps(
        {"questions": [q(0)], "download": "x", "sha256": hashlib.sha256(b"top").hexdigest()}))
    assert D.read_attempt(tmp_path / "c").blobs == (b"top",)


def test_read_attempt_takes_a_sha256_stated_in_uppercase(tmp_path):
    """A hex digest is the same digest in either case: an attempt that states it in uppercase reads,
    and an uppercase digest of other bytes is still refused."""
    f = save(tmp_path / "m", [("blob.txt", b"one"), ("blob.txt", b"two")], [q(1), q(2)])
    body = json.loads((f / "attempt.json").read_text())
    for art in body["artifacts"]:
        art["sha256"] = art["sha256"].upper()
        assert art["sha256"] != art["sha256"].lower()     # the digest really has letters to change
    (f / "attempt.json").write_text(json.dumps(body))
    assert D.read_attempt(f).blobs == (b"one", b"two")
    body["artifacts"][1]["sha256"] = hashlib.sha256(b"other").hexdigest().upper()
    (f / "attempt.json").write_text(json.dumps(body))
    with pytest.raises(D.DeliveryError, match="delivery 2 of 2: .* has sha256"):
        D.read_attempt(f)


@pytest.mark.parametrize("breakage, needle", [
    ("no_body", "no attempt.json"),
    ("not_json", "not readable JSON"),
    ("not_attempt", "not an attempt"),
    ("missing", "delivery 2 of 2 is not saved"),
    ("changed", "has sha256"),
    ("bad_hash", "is not 64 hex"),
    ("escape", "is not a plain file name"),
    ("two_unnamed", "holds 2 files, not one"),
    ("symlink", "is not saved"),
])
def test_read_attempt_fails_loudly(tmp_path, breakage, needle):
    f = save(tmp_path / "m", [("blob.txt", b"one"), ("blob.txt", b"two")], [q(1), q(2)])
    body = json.loads((f / "attempt.json").read_text())
    second = f / "artifact" / "delivery-02" / "blob.txt"
    if breakage == "no_body":
        (f / "attempt.json").unlink()
    elif breakage == "not_json":
        (f / "attempt.json").write_text("{nope")
    elif breakage == "not_attempt":
        (f / "attempt.json").write_text(json.dumps({"artifacts": []}))
    elif breakage == "missing":
        second.unlink()
    elif breakage == "changed":
        second.write_bytes(b"tampered")
    elif breakage == "bad_hash":
        body["artifacts"][1]["sha256"] = "abc123"
        (f / "attempt.json").write_text(json.dumps(body))
    elif breakage == "escape":
        body["artifacts"][1]["filename"] = "../delivery-01/blob.txt"
        (f / "attempt.json").write_text(json.dumps(body))
    elif breakage == "two_unnamed":
        body["artifacts"][1]["filename"] = None
        (f / "attempt.json").write_text(json.dumps(body))
        (second.parent / "extra.txt").write_bytes(b"x")
    elif breakage == "symlink":
        second.unlink()
        second.symlink_to(f / "artifact" / "delivery-01" / "blob.txt")
    with pytest.raises(D.DeliveryError, match=needle):
        D.read_attempt(f)


def test_set_inputs_give_each_set_its_own_bytes(tmp_path):
    # one delivery per set, the same file name and the same bytes length: only the pairing tells them apart
    save(tmp_path / "n", [("blob.txt", b"AAAA"), ("blob.txt", b"BBBB")],
         [q(1, artifact="delivery 2: blob.txt"), q(2, artifact="delivery 1: blob.txt")])
    got = D.set_inputs(D.read_attempt(tmp_path / "n"))
    assert [(i.choice.set, i.label, i.name, i.data) for i in got] == [
        (1, "delivery 2: blob.txt", "blob.txt", b"BBBB"), (2, "delivery 1: blob.txt", "blob.txt", b"AAAA")]


def test_set_inputs_take_a_bundles_members_by_number_not_by_archive_order(tmp_path):
    bundle = zipped([("sub/blob-02.txt", b"second"), ("readme.txt", b"hello"), ("sub/blob-01.txt", b"first")])
    save(tmp_path / "b", [("bundle.zip", bundle)], [q(1), q(2), q(3)])
    got = D.set_inputs(D.read_attempt(tmp_path / "b"))
    assert [(i.choice.rule, i.name, i.data) for i in got[:2]] == [("member", "blob-01.txt", b"first"),
                                                                 ("member", "blob-02.txt", b"second")]
    assert got[0].label == "delivery 1: bundle.zip -> sub/blob-01.txt"
    assert (got[2].choice.rule, got[2].name, got[2].data) == ("unmapped", None, None)
    assert got[2].label.startswith("UNMAPPED: no member of the bundle is numbered 3")


def test_set_inputs_of_a_one_set_attempt(tmp_path):
    save(tmp_path / "one", [("blob.txt", b"only")], [q(0)])
    (one,) = D.set_inputs(D.read_attempt(tmp_path / "one"))
    assert (one.choice.rule, one.label, one.data) == ("all", "delivery 1: blob.txt", b"only")
    save(tmp_path / "two", [("a.bin", b"a"), ("b.bin", b"b")], [q(0)])
    (both,) = D.set_inputs(D.read_attempt(tmp_path / "two"))
    assert (both.choice.rule, both.label, both.data) == ("all", "every delivery", None)


def test_bundle_members_lists_one_level_through_the_runners_expander():
    inner = zipped([("deep.txt", b"deep")])
    got = D.bundle_members("b.zip", zipped([("evidence-01.zip", inner), ("blob-02.txt", b"two")]))
    assert got == {"evidence-01.zip": inner, "blob-02.txt": b"two"}, "members of members are not top-level"
    assert D.bundle_members("blob.txt", b"not an archive") == {}


@pytest.mark.needs_tool("py:pyzipper")
def test_bundle_members_opens_an_aes_bundle_with_the_stock_password():
    import pyzipper
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_STORED, encryption=pyzipper.WZ_AES) as z:
        z.setpassword(b"infected")
        z.writestr("blob-01.txt", b"first")
        z.writestr("blob-02.txt", b"second")
    assert D.bundle_members("mastery.zip", buf.getvalue()) == {"blob-01.txt": b"first", "blob-02.txt": b"second"}


# --------------------------------------------------------------------------- the command

def run_cli(tmp_path, *args):
    e = dict(os.environ, CTF_WORKDIR=str(tmp_path), CTF_EVENT="huntress")
    return subprocess.run([sys.executable, "-m", "ctf", "deliveries", *args], cwd=paths.repo_root(), env=e,
                          stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)


def test_cli_prints_the_pairing_and_exits_0(tmp_path):
    f = save(tmp_path / "m", [("evidence.zip", b"one!"), ("evidence.zip", b"two")],
             [q(1, artifact="delivery 1: evidence.zip"), q(1, "b", "delivery 1: evidence.zip"),
              q(2, artifact="delivery 2: evidence.zip")])
    r = run_cli(tmp_path, str(f))
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.splitlines() == ["set 1 <- delivery 1: evidence.zip [named]  2 question(s), 4 bytes",
                                     "set 2 <- delivery 2: evidence.zip [named]  1 question(s), 3 bytes",
                                     "2 of 2 set(s) paired with their own delivery"]


def test_cli_exits_1_on_an_unmapped_set_and_2_on_an_unreadable_attempt(tmp_path):
    f = save(tmp_path / "m", [("a.bin", b"a"), ("b.bin", b"b")], [q(1), q(2), q(3)])
    r = run_cli(tmp_path, str(f / "attempt.json"), "--json")
    assert r.returncode == 1, r.stdout + r.stderr
    rep = json.loads(r.stdout)
    assert rep["ok"] is False and rep["deliveries"] == ["a.bin", "b.bin"]
    assert [(s["set"], s["rule"], s["delivery"], s["bytes"]) for s in rep["sets"]] == [(n, "unmapped", None, None)
                                                                                      for n in (1, 2, 3)]
    r = run_cli(tmp_path, str(f))
    assert r.returncode == 1 and "FAIL CLOSED: set(s) 1, 2, 3 have none" in r.stdout
    (f / "artifact" / "delivery-02" / "b.bin").unlink()
    r = run_cli(tmp_path, str(f))
    assert r.returncode == 2 and r.stdout == "" and "delivery 2 of 2 is not saved" in r.stderr
