"""B-070: the handout-git step (ctf/handoutgit.py) in the sweep, and what repo_supply_chain.py gained for it.

The two coverage rows it serves, rebuilt synthetically (a git directory written byte by byte, no git program):
  * Spooky Demented Memories: a deleted file, a hidden dotfile whose hex decodes, a note left in .git/,
    each holding one numbered fragment of the flag;
  * CSCTF Polyglot Requiem: a commit cut loose that only ORIG_HEAD still names, and an icon with a zip
    behind its IEND.
Nothing is executed, no git program runs, nothing touches the network.
"""
import base64
import json
import os
import subprocess

import pytest

import archive_expand
import b070_fixtures as fx
import repo_supply_chain as rsc
from ctf import event, flagfmt, handoutgit, sweep
from ctf.engines import router

CSCTF = event.load("csctf")
SPOOKY = event.load("spooky")
REPORT = handoutgit.REPORT
REAL_CANDIDATES = archive_expand.pw.candidates


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    monkeypatch.setattr(archive_expand.pw, "candidates", lambda: [b"infected"])


def chains(rep) -> list:
    return [" -> ".join(e.chain) for e in rep.manifest]


def member(rep, ch, chain: str) -> bytes:
    e = next(e for e in rep.manifest if " -> ".join(e.chain) == chain)
    return (ch / e.path).read_bytes()


# ---------------------------------------------------------------- fixtures

RETRO = b"int main(void) { return 0; }\n// miss the days when people cared ...spooky{the_g00d_ (1)\n"
FOG61 = b"the_l0st_@nd (2)".hex().encode() + b"\n"
SPACE = b"61, the year the memories cuts through the fog... th3_void} (3)\n"


def demented():
    """({work tree path: bytes}, GitDir, commit ids) of a Demented-Memories-shaped repository."""
    g = fx.GitDir()
    fog = {f"fog{i}.fog": b"%032x\n" % ((i * 0x9E3779B97F4A7C15F39CC0605CEDC834) % (1 << 128)) for i in range(1, 8)}
    fog[".fog61.fog"] = FOG61
    readme = {"README.md": b"memories\n"}
    c1 = g.commit(readme, "Initial commit", when=1730000000)
    c2 = g.commit({**readme, "retrospective.c": RETRO}, "a flash to the past", [c1], 1730000100)
    c3 = g.commit({**readme, "retrospective.c": RETRO, **fog}, "the weight of the fog", [c2], 1730000200)
    c4 = g.commit({**readme, **fog}, "MEMORY WIPE INITIALIZATION", [c3], 1730000300)
    g.branch("main", c4)
    g.t["errored_space.txt"] = SPACE
    return {**readme, **fog}, g, (c1, c2, c3, c4)


def demented_zip() -> tuple[bytes, tuple]:
    work, g, ids = demented()
    files = {f"forgotten-playground/{p}": d for p, d in work.items()}
    files.update(g.files("forgotten-playground/.git/"))
    return fx.zip_bytes(files), ids


CUT_FLAG = b"CSCTF{cut_loose_but_still_in_the_object_store}"
ICON = fx.png(text={"Provenance": "ground-station-7"})
ICON_ZIP = fx.zip_bytes({"cache/telemetry_cache.db": b"SQLite format 3\x00" + b"row: sealed asset key material " * 6})


def requiem():
    """A Polyglot-Requiem-shaped repository: a commit only ORIG_HEAD names, one nothing names, a dangling
    blob, and an icon in the work tree with a zip behind it."""
    g = fx.GitDir()
    base = {"README.md": b"flight telemetry sdk\n", "src/sdk.py": b"print('ok')\n",
            "assets/telemetry_icon.png": ICON + ICON_ZIP}
    c1 = g.commit(base, "initial import", when=1730000000)
    c2 = g.commit({**base, "CHANGELOG": b"0.2\n"}, "release 0.2", [c1], 1730000100)
    cut = g.commit({**base, "CHANGELOG": b"0.2\n", "build/sign.sh": b"#!/bin/sh\n# sealed: " + CUT_FLAG + b"\n"},
                   "sign the dashboard asset", [c2], 1730000222)
    lost = g.commit({**base, "notes/todo.txt": b"rotate the signing key before release\n"}, "wip", [c1], 1730000300)
    g.branch("main", c2)
    g.t["ORIG_HEAD"] = cut.encode() + b"\n"
    dangling = g.blob(b"a blob no tree holds\n")
    work = {**base, "CHANGELOG": b"0.2\n"}
    return work, g, {"c1": c1, "c2": c2, "cut": cut, "lost": lost, "dangling": dangling}


def requiem_zip():
    work, g, ids = requiem()
    files = {f"flight-telemetry-sdk/{p}": d for p, d in work.items()}
    files.update(g.files("flight-telemetry-sdk/.git/"))
    return fx.zip_bytes(files), ids


# ---------------------------------------------------------------- repo_supply_chain.py additions

def test_a_clean_git_directory_has_no_nonstandard_file():
    work, g, _ = requiem()
    g.t.update({"COMMIT_EDITMSG": b"release 0.2\n", "packed-refs": b"# pack-refs with: peeled fully-peeled sorted \n",
                "objects/pack/pack-" + "ab" * 20 + ".idx": b"\xfftOc", "objects/info/packs": b"\n",
                "info/attributes": b"", "FETCH_HEAD": b"", "index": b"DIRC", "logs/refs/remotes/origin/main": b"",
                "refs/remotes/origin/HEAD": b"ref: refs/remotes/origin/main\n", "rr-cache/x/preimage": b"x",
                "modules/sub/HEAD": b"ref: refs/heads/main\n", "hooks/pre-push.sample": b"#!/bin/sh\n"})
    assert rsc.GitRepo(g.t).nonstandard() == []


@pytest.mark.parametrize("path,data,why", [
    ("errored_space.txt", b"61, the year", "not a file git writes"),
    ("objects/note.txt", b"hidden among the objects", "under objects/ but not an object"),
    ("objects/ab/cdef", b"short name", "under objects/ but not an object"),
    ("objects/pack/readme.md", b"x", "under objects/ but not an object"),
    ("refs/heads/secret", b"CSCTF{in_a_ref_file}\n", "a ref file that holds no object id"),
    ("logs/refs/heads/x", b"this is no reflog line\n", "a reflog file with lines that are no reflog entries"),
    ("hooks/post-checkout", b"#!/bin/sh\ncurl evil\n", "a hook that is not a sample"),
    ("info/notes", b"x", "not a file git writes"),
    ("description", b"the key is under the mat\n", "the description file was edited"),
    ("secrets/vault.bin", b"\x00\x01", "not a file git writes"),
])
def test_each_kind_of_nonstandard_file_is_listed_with_its_reason(path, data, why):
    _work, g, _ = requiem()
    g.t[path] = data
    assert [(r["path"], r["size"]) for r in rsc.GitRepo(g.t).nonstandard()] == [(path, len(data))]
    assert why in rsc.GitRepo(g.t).nonstandard()[0]["why"]


def test_nonstandard_is_sorted_and_shown_by_describe_and_report():
    work, g, _ = requiem()
    g.t["zz_note.txt"] = b"last"
    g.t["a_note.txt"] = b"first"
    files = {f"sdk/{p}": d for p, d in work.items()}
    files.update(g.files("sdk/.git/"))
    d = rsc.describe(files)
    assert [r["path"] for r in d["histories"][0]["nonstandard_files"]] == ["a_note.txt", "zz_note.txt"]
    text = rsc.report(d)
    assert "NOT GIT'S OWN FILE a_note.txt (5 bytes): not a file git writes" in text


def test_find_git_records_where_each_repository_sits():
    work, g, _ = requiem()
    entries = [("h.zip", f"sdk/.git/{p}", d) for p, d in g.t.items()] + [("h.zip", "sdk/README.md", b"x")]
    entries += [("", "backup/objects.pack", g.pack())]
    repos = rsc.find_git(entries)
    assert sorted((r.container, r.root) for r in repos) == [("", "backup/objects.pack"), ("h.zip", "sdk/.git/")]
    lone = next(r for r in repos if r.root.endswith(".pack"))
    assert len(lone.objects) == len(g.raw) and lone.nonstandard() == []      # the pack fixture reads whole


# ---------------------------------------------------------------- Demented Memories, through the sweep

def test_demented_memories_fragments_are_recovered_and_joined_as_candidates(tmp_path, monkeypatch):
    monkeypatch.delenv("CTF_EVENT", raising=False)       # the step uses the profile it is given, never the active event
    with pytest.raises(event.EventError):
        flagfmt.current()
    data, ids = demented_zip()
    for piece in (b"spooky{the_g00d_", b"th3_void}"):
        assert piece not in data                         # deflated in the zip: a raw search sees no fragment
    ch = fx.pulled(tmp_path, {"forgotten-playground.zip": data}, description="help me recover my fragmented past")
    rep = sweep.sweep(ch, SPOOKY)
    # candidates, never `solved`: the join the platform took first, then the pieces as written
    assert rep.result.status == "candidate"
    assert rep.result.flags == ("spooky{the_g00d_the_l0st_@nd_th3_void}", "spooky{the_g00d_the_l0st_@ndth3_void}")
    assert rep.flags == {}
    base = "forgotten-playground.zip -> forgotten-playground/.git"
    wipe = ids[3][:7]
    got = [c for c in chains(rep) if c.startswith(base + " -> ")]
    assert got == [f"{base} -> deleted/{wipe}/retrospective.c", f"{base} -> nonstandard/errored_space.txt",
                   f"{base} -> {REPORT}"]
    assert member(rep, ch, f"{base} -> deleted/{wipe}/retrospective.c") == RETRO
    assert member(rep, ch, f"{base} -> nonstandard/errored_space.txt") == SPACE
    # members land beside the repository in `.git.unpacked/`, which `ctf read` allows (never inside `.git/`)
    e = next(e for e in rep.manifest if e.chain[-1] == REPORT)
    assert e.path == f"unpacked/forgotten-playground.zip.unpacked/forgotten-playground/.git.unpacked/{REPORT}"
    assert not any(part in sweep.SECRET_DIRS for part in e.path.split("/"))
    j = rep.joins[0][0]
    assert [p.name for p in j.parts[:3]] == [f"(1) deleted/{wipe}/retrospective.c", "(2) .fog61.fog (hex-decoded)",
                                             "(3) git directory file errored_space.txt"]
    assert rep._locations()[rep.joins[0][1]] == [f"{base} -> {REPORT}"]
    assert any(ev.kind == "join" and "numbered:(2) .fog61.fog (hex-decoded)" in ev.detail for ev in rep.result.evidence)


def test_the_git_summary_lists_what_the_spec_asks_for(tmp_path):
    data, ids = demented_zip()
    ch = fx.pulled(tmp_path, {"forgotten-playground.zip": data})
    rep = sweep.sweep(ch, SPOOKY)
    git = json.loads((ch / "unpacked" / sweep.REPORT).read_text())["git"]
    assert len(git) == 1
    g = git[0]
    assert g["label"] == "forgotten-playground.zip -> forgotten-playground/.git" and g["commits"] == 4
    assert g["complete"] is True and g["problems"] == []
    assert g["deleted_files"] == [{"commit": ids[3], "path": "retrospective.c",
                                   "member": f"deleted/{ids[3][:7]}/retrospective.c"}]
    assert [(r["path"], r["member"]) for r in g["nonstandard_files"]] == [("errored_space.txt", "nonstandard/errored_space.txt")]
    assert g["hidden_dotfiles"] == [{"path": ".fog61.fog", "where": "work tree", "size": len(FOG61)}]
    # of the eight 32-hex fog values, only the one that reads as text is a decoded string
    assert g["decoded"] == [{"where": ".fog61.fog", "encoding": "hex", "offset": 0, "token": FOG61.strip().decode(),
                             "text": "the_l0st_@nd (2)"}]
    assert [(f["index"], f["text"]) for f in g["fragments"]] == [
        (1, "// miss the days when people cared ...spooky{the_g00d_"), (2, "the_l0st_@nd"),
        (3, "61, the year the memories cuts through the fog... th3_void}")]
    assert g["candidates"] == list(rep.result.flags) and g["would_run"] == []
    note = next(n for n in rep.notes if n.startswith("git handout forgotten-playground.zip"))
    assert "4 commit(s)" in note and "1 deleted file(s)" in note and "1 file(s) in the git directory git did not write" in note
    assert "2 assembled candidate(s)" in note and "no git program was run" in note


def test_the_report_names_everything_but_never_holds_an_assembled_candidate(tmp_path):
    data, ids = demented_zip()
    ch = fx.pulled(tmp_path, {"forgotten-playground.zip": data})
    rep = sweep.sweep(ch, SPOOKY)
    text = member(rep, ch, f"forgotten-playground.zip -> forgotten-playground/.git -> {REPORT}").decode()
    for want in (f"commit {ids[3]}", "MEMORY WIPE INITIALIZATION", "deleted  retrospective.c",
                 f"retrospective.c  deleted by commit {ids[3][:12]}  -> deleted/{ids[3][:7]}/retrospective.c",
                 "errored_space.txt (64 bytes): not a file git writes  -> nonstandard/errored_space.txt",
                 ".fog61.fog (33 bytes, work tree)", "the_l0st_@nd (2)", "(3) in git directory file errored_space.txt:",
                 "1730000300 (2024-10-27 03:38:20 UTC, zone +0000)", "No git program was"):
        assert want in text, want
    # the flag sweep reads this member too: an assembled value in it would be reported as a plain, solved flag
    assert SPOOKY and not flagfmt.for_profile(SPOOKY).find_flags(text)
    for flag in rep.result.flags:
        assert flag not in text


@pytest.mark.needs_tool("7zz")
def test_the_same_repository_in_a_7z_as_the_real_handout_was(tmp_path):
    import shutil
    work, g, ids = demented()
    src = tmp_path / "build" / "forgotten-playground"
    fx.write_tree(src, {**work, **g.files(".git/")})
    arc = tmp_path / "build" / "forgotten-playground.7z"
    subprocess.run([shutil.which("7zz"), "a", str(arc), str(src)], check=True, capture_output=True, timeout=120)
    ch = fx.pulled(tmp_path, {"forgotten-playground.7z": arc.read_bytes()})
    rep = sweep.sweep(ch, SPOOKY)
    assert rep.result.status == "candidate"
    assert rep.result.flags == ("spooky{the_g00d_the_l0st_@nd_th3_void}", "spooky{the_g00d_the_l0st_@ndth3_void}")
    base = "forgotten-playground.7z -> forgotten-playground/.git"
    assert f"{base} -> deleted/{ids[3][:7]}/retrospective.c" in chains(rep)
    assert f"{base} -> nonstandard/errored_space.txt" in chains(rep)
    assert rep.to_dict()["git"][0]["hidden_dotfiles"] == [{"path": ".fog61.fog", "where": "work tree", "size": len(FOG61)}]


# ---------------------------------------------------------------- Polyglot Requiem, through the sweep

def test_polyglot_requiem_cut_commit_and_icon_zip_are_both_opened(tmp_path, monkeypatch):
    monkeypatch.delenv("CTF_EVENT", raising=False)
    data, ids = requiem_zip()
    assert CUT_FLAG not in data
    ch = fx.pulled(tmp_path, {"polyglot-requiem.zip": data},
                   description="A review turned up altered build history and an odd dashboard asset.")
    rep = sweep.sweep(ch, CSCTF)
    base = "polyglot-requiem.zip -> flight-telemetry-sdk/.git"
    cut, lost = ids["cut"], ids["lost"]
    assert rep.result.status == "solved" and rep.result.flags == (CUT_FLAG.decode(),)
    hit = rep.flags[CUT_FLAG.decode()][0]
    assert rep._locations()[hit.sha256] == [f"{base} -> reflog-only/{cut[:7]}/build/sign.sh"]
    got = [c for c in chains(rep) if c.startswith(base + " -> ")]
    assert got == [f"{base} -> reflog-only/{cut[:7]}/build/sign.sh", f"{base} -> unreachable/{lost[:7]}/notes/todo.txt",
                   f"{base} -> dangling/blob-{ids['dangling'][:12]}", f"{base} -> {REPORT}"]
    assert not any(" -> history/" in c for c in chains(rep))      # what the work tree holds is not exported twice
    g = rep.to_dict()["git"][0]
    assert g["pseudo_heads"] == {"ORIG_HEAD": [cut]}
    assert g["commits_no_ref_reaches"] == [
        {"id": cut, "reached_from": "reflog", "time": 1730000222, "subject": "sign the dashboard asset"},
        {"id": lost, "reached_from": "unreachable", "time": 1730000300, "subject": "wip"}]
    assert {"id": ids["dangling"], "type": "blob", "reached_from": "unreachable", "dangling": True} in g["not_reached_by_a_ref"]
    assert {"id": cut, "type": "commit", "reached_from": "reflog", "dangling": False} in g["not_reached_by_a_ref"]
    text = member(rep, ch, f"{base} -> {REPORT}").decode()
    assert f"ORIG_HEAD: {cut}" in text
    assert f"commit {cut}   [ONLY THE REFLOG OR A PSEUDO-HEAD REACHES IT]" in text
    assert f"commit {lost}   [NO REF REACHES IT]" in text and f"commit {ids['c2']}\n" in text
    assert "1730000222 (2024-10-27 03:37:02 UTC" in text           # the epoch the unseal needed
    # the icon's zip went back through the walk
    icon = f"polyglot-requiem.zip -> flight-telemetry-sdk/assets/telemetry_icon.png -> carved@0x{len(ICON):x}.zip"
    assert icon in chains(rep) and icon + " -> cache/telemetry_cache.db" in chains(rep)
    assert member(rep, ch, icon + " -> cache/telemetry_cache.db").startswith(b"SQLite format 3\x00")


def test_a_git_handout_routes_to_repo_supply_chain_first_whatever_the_category(tmp_path):
    data, _ = requiem_zip()
    ch = fx.pulled(tmp_path, {"polyglot-requiem.zip": data}, category="Forensics")
    rep = sweep.sweep(ch, CSCTF)
    assert rep.triage["engines"][0] == "solvers/toolkits/repo_supply_chain.py"
    hits = router.route("forensics", "", ch / "unpacked")
    assert hits[0].manifest.id == "toolkits.repo_supply_chain" and hits[0].priority == 65
    # a handout with no repository in it does not get the engine in forensics
    plain = fx.pulled(tmp_path, {"notes.zip": fx.zip_bytes({"a.txt": b"PACKING list\n", "HEAD": b"shoulders\n"})}, cid=5)
    rep2 = sweep.sweep(plain, CSCTF)
    assert "solvers/toolkits/repo_supply_chain.py" not in rep2.triage["engines"] and rep2.to_dict()["git"] == []


def test_no_git_program_and_no_hook_runs_and_what_would_run_is_reported(tmp_path, monkeypatch):
    work, g, ids = requiem()
    g.t["config"] += b"\tfsmonitor = ./pwn.sh\n[alias]\n\tst = !sh -c 'id > /tmp/owned'\n"
    marker = tmp_path / "hook-ran"
    g.t["hooks/post-checkout"] = f"#!/bin/sh\ntouch {marker}\n".encode()
    files = {f"sdk/{p}": d for p, d in work.items()}
    files.update(g.files("sdk/.git/"))
    started = []
    real = subprocess.Popen.__init__

    def spy(self, args, *a, **kw):
        started.append(args)
        return real(self, args, *a, **kw)
    monkeypatch.setattr(subprocess.Popen, "__init__", spy)
    ch = fx.pulled(tmp_path, {"h.zip": fx.zip_bytes(files)})
    rep = sweep.sweep(ch, CSCTF)
    assert started == []                                   # a zip handout: nothing at all is started
    assert not marker.exists()
    g0 = rep.to_dict()["git"][0]
    assert g0["would_run"] == ["config fsmonitor = ./pwn.sh", "config alias = !sh -c 'id > /tmp/owned'",
                               "hooks/post-checkout"]
    assert any("a real git would run 3 thing(s)" in n and "never run git in the scratch copy" in n for n in rep.notes)
    text = member(rep, ch, f"h.zip -> sdk/.git -> {REPORT}").decode()
    assert "WOULD RUN under a real git: hooks/post-checkout" in text
    assert [r["path"] for r in g0["nonstandard_files"]] == ["hooks/post-checkout"]
    # the hook is exported as data: readable, and never executable
    e = next(e for e in rep.manifest if e.chain[-1] == "nonstandard/hooks/post-checkout")
    assert not os.access(ch / e.path, os.X_OK)


# ---------------------------------------------------------------- what is exported, and what it is fed to

def test_a_polyglot_image_deleted_from_history_is_exported_carved_and_searched(tmp_path):
    flag = b"CSCTF{icon_deleted_then_carved}"
    icon = fx.png() + fx.zip_bytes({"flag.txt": flag * 3})
    g = fx.GitDir()
    c1 = g.commit({"README.md": b"x\n", "assets/icon.png": icon}, "add icon", when=1)
    c2 = g.commit({"README.md": b"x\n"}, "drop icon", [c1], 2)
    g.branch("main", c2)
    files = {"repo/README.md": b"x\n", **g.files("repo/.git/")}
    data = fx.zip_bytes(files)
    assert flag not in data
    rep = sweep.sweep(fx.pulled(tmp_path, {"h.zip": data}), CSCTF)
    assert rep.result.flags == (flag.decode(),)
    assert (f"h.zip -> repo/.git -> deleted/{c2[:7]}/assets/icon.png -> carved@0x{len(fx.png()):x}.zip -> flag.txt"
            in chains(rep))


def test_an_archive_deleted_from_history_is_opened_by_the_walk(tmp_path):
    flag = b"CSCTF{backup_zip_removed_in_the_next_commit}"
    g = fx.GitDir()
    c1 = g.commit({"backup.zip": fx.zip_bytes({"db/creds.txt": flag + b"\n" + b"pad " * 30})}, "oops", when=1)
    c2 = g.commit({"README.md": b"clean\n"}, "remove backup", [c1], 2)
    g.branch("main", c2)
    data = fx.zip_bytes({"repo/README.md": b"clean\n", **g.files("repo/.git/")})
    assert flag not in data
    rep = sweep.sweep(fx.pulled(tmp_path, {"h.zip": data}), CSCTF)
    assert rep.result.flags == (flag.decode(),)
    assert f"h.zip -> repo/.git -> deleted/{c2[:7]}/backup.zip -> db/creds.txt" in chains(rep)


NESTED_FLAG = b"CSCTF{a_repo_in_a_zip_deleted_from_a_repo}"


def nested_handout() -> tuple[bytes, str, str]:
    """(handout zip, outer deleting commit, inner deleting commit): a repository whose history holds a
    deleted zip of a second repository, whose own history holds a deleted file with the flag."""
    inner = fx.GitDir()
    i1 = inner.commit({"secret.txt": NESTED_FLAG + b"\n"}, "keep it", when=1)
    i2 = inner.commit({"README.md": b"nothing here\n"}, "scrub", [i1], 2)
    inner.branch("main", i2)
    inner_zip = fx.zip_bytes({"inner/README.md": b"nothing here\n", **inner.files("inner/.git/")})
    outer = fx.GitDir()
    o1 = outer.commit({"backup.zip": inner_zip}, "backup", when=3)
    o2 = outer.commit({"README.md": b"clean\n"}, "remove backup", [o1], 4)
    outer.branch("main", o2)
    return fx.zip_bytes({"repo/README.md": b"clean\n", **outer.files("repo/.git/")}), o2, i2


def test_a_repository_inside_an_archive_the_step_exported_is_read_too(tmp_path):
    # Verification finding (round 1): the step ran once, so a repository inside its own exports was
    # unpacked but its history never read.
    data, o2, i2 = nested_handout()
    assert NESTED_FLAG not in data
    rep = sweep.sweep(fx.pulled(tmp_path, {"h.zip": data}), CSCTF)
    assert rep.result.flags == (NESTED_FLAG.decode(),)
    inner = f"h.zip -> repo/.git -> deleted/{o2[:7]}/backup.zip -> inner/.git"
    assert f"{inner} -> deleted/{i2[:7]}/secret.txt" in chains(rep)
    assert [g["label"] for g in rep.to_dict()["git"]] == ["h.zip -> repo/.git", inner]
    assert sum(1 for c in chains(rep) if c.endswith(f" -> {REPORT}")) == 2


def test_nested_repositories_stop_at_the_pass_limit_and_say_so(tmp_path, monkeypatch):
    data, o2, _i2 = nested_handout()
    monkeypatch.setattr(handoutgit, "MAX_DEPTH", 1)
    rep = sweep.sweep(fx.pulled(tmp_path, {"h.zip": data}), CSCTF)
    assert [g["label"] for g in rep.to_dict()["git"]] == ["h.zip -> repo/.git"]
    assert rep.result.flags == ()
    held = f"h.zip -> repo/.git -> deleted/{o2[:7]}/backup.zip"
    assert any(n.startswith(f"git handout: {held!r} and 0 more place(s)") and "limit of 1 passes" in n
               for n in rep.notes)
    monkeypatch.setattr(handoutgit, "MAX_DEPTH", 2)
    rep = sweep.sweep(fx.pulled(tmp_path, {"h.zip": data}, cid=2), CSCTF)
    assert rep.result.flags == (NESTED_FLAG.decode(),)
    assert not any("passes)" in n for n in rep.notes)


def test_a_loose_git_is_read_once_when_a_later_pass_reads_a_repository_inside_it(tmp_path):
    inner = fx.GitDir()
    i1 = inner.commit({"secret.txt": NESTED_FLAG + b"\n"}, "keep it", when=1)
    i2 = inner.commit({"README.md": b"x\n"}, "scrub", [i1], 2)
    inner.branch("main", i2)
    outer = fx.GitDir()
    o1 = outer.commit({"b.zip": fx.zip_bytes(inner.files("inner/.git/"))}, "backup", when=3)
    o2 = outer.commit({"README.md": b"x\n"}, "remove", [o1], 4)
    outer.branch("main", o2)
    rep = sweep.sweep(fx.pulled(tmp_path, {"README.md": b"x\n", **outer.files(".git/")}), CSCTF)
    assert [g["label"] for g in rep.to_dict()["git"]] == [".git", f".git -> deleted/{o2[:7]}/b.zip -> inner/.git"]
    assert rep.result.flags == (NESTED_FLAG.decode(),)


def test_max_repos_counts_the_repositories_of_every_pass(tmp_path, monkeypatch):
    data, o2, _i2 = nested_handout()
    monkeypatch.setattr(handoutgit, "MAX_REPOS", 1)
    rep = sweep.sweep(fx.pulled(tmp_path, {"h.zip": data}), CSCTF)
    assert [g["label"] for g in rep.to_dict()["git"]] == ["h.zip -> repo/.git"]
    inner = f"h.zip -> repo/.git -> deleted/{o2[:7]}/backup.zip -> inner/.git"
    assert f"git handout {inner}: not read, 1 repositories were read already" in rep.notes


def test_an_older_version_of_a_file_and_a_staged_file_are_exported(tmp_path):
    old = b"password = CSCTF{edited_out_in_the_next_commit}\n"
    g = fx.GitDir()
    c1 = g.commit({"app.cfg": old}, "config", when=1)
    c2 = g.commit({"app.cfg": b"password = <redacted>\n"}, "scrub", [c1], 2)
    g.branch("main", c2)
    g.index({"app.cfg": b"password = <redacted>\n", "staged/never_committed.txt": b"staged only: token-4471\n"})
    data = fx.zip_bytes({"repo/app.cfg": b"password = <redacted>\n", **g.files("repo/.git/")})
    rep = sweep.sweep(fx.pulled(tmp_path, {"h.zip": data}), CSCTF)
    assert rep.result.flags == ("CSCTF{edited_out_in_the_next_commit}",)
    got = [c for c in chains(rep) if c.startswith("h.zip -> repo/.git -> ")]
    assert got == ["h.zip -> repo/.git -> index-only/staged/never_committed.txt",
                   f"h.zip -> repo/.git -> history/{c1[:7]}/app.cfg", f"h.zip -> repo/.git -> {REPORT}"]


def test_a_git_directory_with_no_work_tree_gives_up_the_files_of_head(tmp_path):
    flag = b"CSCTF{only_in_the_objects}"
    g = fx.GitDir()
    c1 = g.commit({"src/main.py": b"print(1)\n", "secret.txt": flag + b"\n"}, "all there is", when=1)
    g.branch("main", c1)
    data = fx.zip_bytes(g.files("dump/.git/"))
    assert flag not in data
    rep = sweep.sweep(fx.pulled(tmp_path, {"dump.zip": data}), CSCTF)
    assert rep.result.flags == (flag.decode(),)
    assert sorted(c for c in chains(rep) if " -> history/" in c) == [
        f"dump.zip -> dump/.git -> history/{c1[:7]}/secret.txt", f"dump.zip -> dump/.git -> history/{c1[:7]}/src/main.py"]


def test_a_lone_packfile_is_a_repository_too(tmp_path):
    flag = b"CSCTF{in_a_bare_pack}"
    g = fx.GitDir()
    g.commit({"vault/key.txt": flag + b"\n"}, "packed", when=7)
    pack = g.pack()
    assert flag not in pack
    rep = sweep.sweep(fx.pulled(tmp_path, {"evidence.zip": fx.zip_bytes({"backup/objects.pack": pack})}), CSCTF)
    assert rep.result.flags == (flag.decode(),)
    assert any(c.startswith("evidence.zip -> backup/objects.pack -> ") and c.endswith("/vault/key.txt") for c in chains(rep))


def test_a_base64_commit_message_is_a_decoded_string_and_the_flag_in_it_is_found(tmp_path):
    flag = "CSCTF{said_in_a_commit_message}"
    g = fx.GitDir()
    c1 = g.commit({"a.txt": b"a\n"}, "first", when=1)
    c2 = g.commit({"a.txt": b"b\n"}, "note to self: " + base64.b64encode(b"the vault code is 4471-ALPHA").decode(), [c1], 2)
    c3 = g.commit({"a.txt": b"c\n"}, f"oops {flag}", [c2], 3)
    g.branch("main", c3)
    data = fx.zip_bytes({"repo/a.txt": b"c\n", **g.files("repo/.git/")})
    rep = sweep.sweep(fx.pulled(tmp_path, {"h.zip": data}), CSCTF)
    assert rep.result.flags == (flag,)                       # a commit message is deflated: only the report shows it
    assert rep._locations()[rep.flags[flag][0].sha256] == [f"h.zip -> repo/.git -> {REPORT}"]
    dec = rep.to_dict()["git"][0]["decoded"]
    assert [(d["where"], d["encoding"], d["text"]) for d in dec] == [
        (f"commit {c2[:7]} message", "base64", "the vault code is 4471-ALPHA")]


def _real_git(cwd, *args):
    """Run the real git on a repository this test creates (a fixture, never a handout), with no user or
    system configuration, no hooks path and a fixed identity and clock."""
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(cwd), "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "Ada", "GIT_AUTHOR_EMAIL": "ada@example.test",
           "GIT_COMMITTER_NAME": "Ada", "GIT_COMMITTER_EMAIL": "ada@example.test",
           "GIT_AUTHOR_DATE": "1730000000 +0000", "GIT_COMMITTER_DATE": "1730000000 +0000", "LC_ALL": "C"}
    done = subprocess.run(["git", "-c", "init.defaultBranch=main", "-c", "gc.auto=0", "-c", "commit.gpgsign=false",
                           *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


@pytest.mark.needs_tool("git")
def test_a_repository_written_by_the_real_git_reads_whole_with_no_false_nonstandard_file(tmp_path):
    """The byte-built fixtures above could share a misreading with the reader. This one is written by git
    itself: packed objects with deltas, packed-refs, a real index, a real reflog, a real ORIG_HEAD."""
    repo = tmp_path / "build" / "sdk"
    repo.mkdir(parents=True)
    _real_git(repo, "init", "-q")
    body = "".join(f"line {i} of the telemetry module\n" for i in range(200))
    (repo / "telemetry.py").write_text(body)
    (repo / "notes.txt").write_text("rotate the key: CSCTF{deleted_by_a_real_git_commit}\n")
    _real_git(repo, "add", "-A")
    _real_git(repo, "commit", "-q", "-m", "import")
    (repo / "telemetry.py").write_text(body.replace("line 100 ", "line one hundred "))
    _real_git(repo, "rm", "-q", "notes.txt")
    _real_git(repo, "commit", "-q", "-am", "scrub notes")
    (repo / "telemetry.py").write_text(body + "sealed = 'cut-loose-marker-7731'\n")
    _real_git(repo, "commit", "-q", "-am", "sign the asset")
    cut = _real_git(repo, "rev-parse", "HEAD")
    _real_git(repo, "reset", "-q", "--hard", "HEAD~1")              # ORIG_HEAD + a reflog-only commit
    scrub = _real_git(repo, "rev-parse", "HEAD")
    _real_git(repo, "gc", "-q")                                     # a pack with deltas, packed-refs
    assert list((repo / ".git" / "objects" / "pack").glob("*.pack"))
    files = {p.relative_to(repo.parent).as_posix(): p.read_bytes() for p in sorted(repo.rglob("*")) if p.is_file()}
    data = fx.zip_bytes(files)
    assert b"deleted_by_a_real_git_commit" not in data
    ch = fx.pulled(tmp_path, {"sdk.zip": data})
    rep = sweep.sweep(ch, CSCTF)
    g = rep.to_dict()["git"][0]
    assert g["complete"] is True and g["problems"] == [] and g["commits"] == 3
    assert g["nonstandard_files"] == []                              # nothing git wrote is called foreign
    assert g["head"] == {"ref": "refs/heads/main", "id": scrub} and g["pseudo_heads"] == {"ORIG_HEAD": [cut]}
    assert [(c["id"], c["reached_from"], c["subject"]) for c in g["commits_no_ref_reaches"]] == [
        (cut, "reflog", "sign the asset")]
    assert g["deleted_files"] == [{"commit": scrub, "path": "notes.txt", "member": f"deleted/{scrub[:7]}/notes.txt"}]
    assert rep.result.flags == ("CSCTF{deleted_by_a_real_git_commit}",)
    base = "sdk.zip -> sdk/.git"
    assert member(rep, ch, f"{base} -> deleted/{scrub[:7]}/notes.txt") == b"rotate the key: CSCTF{deleted_by_a_real_git_commit}\n"
    assert member(rep, ch, f"{base} -> reflog-only/{cut[:7]}/telemetry.py").endswith(b"sealed = 'cut-loose-marker-7731'\n")
    assert rep.triage["engines"][0] == "solvers/toolkits/repo_supply_chain.py"


# ---------------------------------------------------------------- which .git is read

def loose_layout(root, flag: bytes):
    """repo/ with a work tree and a .git whose history holds `flag` in a deleted file."""
    g = fx.GitDir()
    c1 = g.commit({"README.md": b"x\n", "old/secret.txt": flag + b"\n"}, "add", when=1)
    c2 = g.commit({"README.md": b"x\n"}, "remove", [c1], 2)
    g.branch("main", c2)
    fx.write_tree(root, {"repo/README.md": b"x\n", **g.files("repo/.git/")})
    return c2


def test_a_loose_git_folder_in_a_pulled_files_folder_is_read_by_the_step_only(tmp_path):
    flag = b"CSCTF{loose_git_in_files}"
    ch = fx.pulled(tmp_path, {})
    c2 = loose_layout(ch / "files", flag)
    (ch / "files" / "repo" / ".git" / "leak.txt").write_bytes(b"CSCTF{raw_git_file_seen_only_through_the_step}")
    rep = sweep.sweep(ch, CSCTF)
    assert rep.target.kind == "pulled"
    assert set(rep.result.flags) == {flag.decode(), "CSCTF{raw_git_file_seen_only_through_the_step}"}
    got = chains(rep)
    assert got == ["repo/README.md", f"repo/.git -> deleted/{c2[:7]}/old/secret.txt",
                   "repo/.git -> nonstandard/leak.txt", f"repo/.git -> {REPORT}"]
    # the raw git files are neither swept as originals nor copied: only what the step derives is written
    assert not (ch / "unpacked" / "repo" / ".git").exists()
    assert (ch / "unpacked" / "repo" / ".git.unpacked" / "deleted" / c2[:7] / "old" / "secret.txt").read_bytes() == flag + b"\n"
    assert any("left out of the flag sweep 'repo/.git'" in n and "handout-git step" in n for n in rep.notes)
    assert not any("credentials" in n for n in rep.notes)


def test_files_that_hold_nothing_but_a_git_folder_still_sweep(tmp_path):
    flag = b"CSCTF{only_a_dot_git}"
    g = fx.GitDir()
    c1 = g.commit({"flag.txt": flag + b"\n"}, "only commit", when=1)
    g.branch("main", c1)
    ch = fx.pulled(tmp_path, g.files(".git/"))
    rep = sweep.sweep(ch, CSCTF)
    assert rep.result.flags == (flag.decode(),)
    assert chains(rep) == [f".git -> history/{c1[:7]}/flag.txt", f".git -> {REPORT}"]


@pytest.mark.parametrize("kind", ["folder", "drop"])
def test_a_git_folder_outside_a_pulled_files_folder_is_never_read(tmp_path, kind):
    flag = b"CSCTF{the_operators_own_repository}"
    src = tmp_path / "wd" / "manual"
    loose_layout(src, flag)
    (src / "note.txt").write_bytes(b"nothing here\n")
    if kind == "drop":
        (src / "challenge.toml").write_text('description = "x"\ncategory = "forensics"\n')
    rep = sweep.sweep(src, CSCTF)
    assert rep.target.kind == kind
    assert rep.result.flags == () and rep.to_dict()["git"] == []
    assert chains(rep) == ["note.txt", "repo/README.md"]
    assert any("'repo/.git'" in n and "credentials" in n and "from its archive" in n for n in rep.notes)
    assert handoutgit.loose(rep.target, []) == []


def test_a_git_folder_at_or_above_the_challenge_folder_is_never_read(tmp_path):
    flag = b"CSCTF{workdir_repository_history}"
    ch = fx.pulled(tmp_path, {"note.txt": b"hello\n"})
    loose_layout(ch.parent, flag)                 # <workdir>/repo/.git: above the challenge
    g = fx.GitDir()
    c1 = g.commit({"x.txt": flag + b"\n"}, "c", when=1)
    g.branch("main", c1)
    fx.write_tree(ch, g.files(".git/"))           # <challenge>/.git: at the challenge folder, beside files/
    rep = sweep.sweep(ch, CSCTF)
    assert rep.result.flags == () and rep.to_dict()["git"] == [] and chains(rep) == ["note.txt"]


def test_links_and_credential_folders_inside_a_loose_git_are_not_followed(tmp_path):
    ch = fx.pulled(tmp_path, {})
    loose_layout(ch / "files", b"CSCTF{fine}")
    gitdir = ch / "files" / "repo" / ".git"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "host-secret.txt").write_bytes(b"CSCTF{host_file_behind_a_link}")
    (gitdir / "linked-file.txt").symlink_to(outside / "host-secret.txt")
    (gitdir / "linked-dir").symlink_to(outside, target_is_directory=True)
    (gitdir / ".ctf").mkdir()
    (gitdir / ".ctf" / "token").write_bytes(b"CSCTF{platform_token}")
    notes = []
    rows = handoutgit.loose(sweep.resolve_target(ch), notes)
    names = [rel for rel, _ in rows]
    assert "repo/.git/HEAD" in names and names == sorted(names)
    assert not any("linked" in n or ".ctf" in n for n in names)
    assert any("'repo/.git/linked-dir'" in n and "symbolic link" in n for n in notes)
    assert any("'repo/.git/.ctf'" in n and "credentials folder" in n for n in notes)
    rep = sweep.sweep(ch, CSCTF)
    assert rep.result.flags == ("CSCTF{fine}",)
    # a .git that is itself a link is not a handout repository
    ch2 = fx.pulled(tmp_path, {"a.txt": b"a"}, cid=77)
    (ch2 / "files" / ".git").symlink_to(gitdir, target_is_directory=True)
    assert handoutgit.loose(sweep.resolve_target(ch2), []) == []
    assert sweep.sweep(ch2, CSCTF).to_dict()["git"] == []


def test_loose_git_reading_is_bounded(tmp_path, monkeypatch):
    ch = fx.pulled(tmp_path, {})
    loose_layout(ch / "files", b"CSCTF{x}")
    (ch / "files" / "repo" / ".git" / "big.bin").write_bytes(b"B" * 500)
    t = sweep.resolve_target(ch)
    monkeypatch.setattr(handoutgit, "MAX_GIT_FILE", 499)
    notes = []
    rows = handoutgit.loose(t, notes)
    assert "repo/.git/big.bin" not in [r for r, _ in rows] and "repo/.git/HEAD" in [r for r, _ in rows]
    assert any("'repo/.git/big.bin'" in n and "over the limit of 499" in n for n in notes)
    monkeypatch.setattr(handoutgit, "MAX_GIT_FILES", 3)
    notes = []
    assert len(handoutgit.loose(t, notes)) == 3
    assert sum("the budget for loose .git folders" in n for n in notes) == 1
    monkeypatch.setattr(handoutgit, "MAX_GIT_FILES", 40000)
    monkeypatch.setattr(handoutgit, "MAX_GIT_BYTES", 200)
    notes = []
    assert sum(len(d) for _, d in handoutgit.loose(t, notes)) <= 200
    assert any("read incomplete" in n for n in notes)


# ---------------------------------------------------------------- limits and hostile bytes

def many_versions(n: int):
    """(GitDir, the commit that deletes log.txt, [the commits that wrote version 0..n-1 of it])."""
    g = fx.GitDir()
    ids, parents = [], []
    for i in range(n):
        ids.append(g.commit({"log.txt": b"version %d\n" % i, "keep.txt": b"k\n"}, f"v{i}", parents, when=100 + i))
        parents = [ids[-1]]
    gone = g.commit({"keep.txt": b"k\n"}, "delete the log", parents, when=100 + n)
    g.branch("main", gone)
    return g, gone, ids


def test_exports_are_capped_the_deleted_file_first_then_history_newest_first(tmp_path, monkeypatch):
    g, gone, ids = many_versions(5)
    data = fx.zip_bytes({"repo/keep.txt": b"k\n", **g.files("repo/.git/")})
    ch = fx.pulled(tmp_path, {"h.zip": data})
    rep = sweep.sweep(ch, CSCTF)
    got = [c.split(" -> ")[-1] for c in chains(rep) if c.startswith("h.zip -> repo/.git -> ")]
    # the last version is the deleted file; the four before it are history, newest first; nothing twice
    assert got == [f"deleted/{gone[:7]}/log.txt"] + [f"history/{c[:7]}/log.txt" for c in reversed(ids[:4])] + [REPORT]
    assert member(rep, ch, f"h.zip -> repo/.git -> deleted/{gone[:7]}/log.txt") == b"version 4\n"
    assert member(rep, ch, f"h.zip -> repo/.git -> history/{ids[1][:7]}/log.txt") == b"version 1\n"
    monkeypatch.setattr(handoutgit, "MAX_EXPORTS", 2)
    rep = sweep.sweep(ch, CSCTF)
    got = [c.split(" -> ")[-1] for c in chains(rep) if c.startswith("h.zip -> repo/.git -> ")]
    assert got == [f"deleted/{gone[:7]}/log.txt", f"history/{ids[3][:7]}/log.txt", REPORT]
    assert any("3 older file version(s) not exported (limit 2 per repository)" in n for n in rep.notes)
    assert rep.to_dict()["git"][0]["exported"] == 2


def test_nonstandard_files_past_the_cap_are_listed_but_not_exported(tmp_path, monkeypatch):
    g, _gone, _ids = many_versions(1)
    g.t["a_note.txt"] = b"first note\n"
    g.t["b_note.txt"] = b"second note\n"
    monkeypatch.setattr(handoutgit, "MAX_NONSTANDARD", 1)
    data = fx.zip_bytes({"repo/keep.txt": b"k\n", **g.files("repo/.git/")})
    rep = sweep.sweep(fx.pulled(tmp_path, {"h.zip": data}), CSCTF)
    assert [c for c in chains(rep) if "nonstandard/" in c] == ["h.zip -> repo/.git -> nonstandard/a_note.txt"]
    rows = rep.to_dict()["git"][0]["nonstandard_files"]
    assert [(r["path"], r.get("member")) for r in rows] == [("a_note.txt", "nonstandard/a_note.txt"), ("b_note.txt", None)]
    assert any("1 more file(s) git did not write are listed" in n for n in rep.notes)


def test_a_dotfile_only_history_holds_is_listed_with_its_commit(tmp_path):
    g = fx.GitDir()
    c1 = g.commit({"app.py": b"x\n", ".env.production": b"API_KEY=k-123\n", "conf/.hidden/x": b"y\n"}, "oops", when=1)
    c2 = g.commit({"app.py": b"x\n"}, "scrub", [c1], 2)
    g.branch("main", c2)
    data = fx.zip_bytes({"repo/app.py": b"x\n", "repo/.editorconfig": b"root = true\n", **g.files("repo/.git/")})
    rep = sweep.sweep(fx.pulled(tmp_path, {"h.zip": data}), CSCTF)
    assert rep.to_dict()["git"][0]["hidden_dotfiles"] == [
        {"path": ".editorconfig", "where": "work tree", "size": 12},
        {"path": ".env.production", "where": f"commit {c1[:7]}", "size": 14},
        {"path": "conf/.hidden/x", "where": f"commit {c1[:7]}", "size": 2}]


def test_decoding_skips_binary_files_and_is_capped(tmp_path, monkeypatch):
    token = base64.b64encode(b"a readable secret sentence").decode()
    stray = b"mostly readable text with one \x01 stray byte inside it".hex().encode()
    work = {"repo/a.txt": f"one {token}\n".encode(), "repo/b.bin": b"\x00\x01" + token.encode(),
            "repo/c.txt": b"two " + b"second readable sentence!".hex().encode() + b"\n", "repo/d.txt": stray + b"\n"}
    # the decoder itself offers the stray-byte token at this threshold: the step is what leaves it out
    assert sweep._embedded().find_blobs(stray, min_printable=0.95, flag_re=flagfmt.for_profile(CSCTF).bregex)
    g = fx.GitDir()
    g.branch("main", g.commit({p[5:]: d for p, d in work.items()}, "all", when=1))
    data = fx.zip_bytes({**work, **g.files("repo/.git/")})
    ch = fx.pulled(tmp_path, {"h.zip": data})
    dec = sweep.sweep(ch, CSCTF).to_dict()["git"][0]["decoded"]
    assert [(d["where"], d["encoding"], d["offset"], d["text"]) for d in dec] == [
        ("a.txt", "base64", 4, "a readable secret sentence"), ("c.txt", "hex", 4, "second readable sentence!")]
    monkeypatch.setattr(handoutgit, "MAX_DECODED", 1)
    assert len(sweep.sweep(ch, CSCTF).to_dict()["git"][0]["decoded"]) == 1
    monkeypatch.setattr(handoutgit, "MAX_TEXTS", 1)
    rep = sweep.sweep(ch, CSCTF)
    assert any("text(s) not searched for encoded strings or numbered fragments (limit 1)" in n for n in rep.notes)


@pytest.mark.needs_tool("py:pyzipper")
def test_the_harvest_resweep_reads_each_repository_once(tmp_path, monkeypatch):
    import io
    import pyzipper
    monkeypatch.setattr(archive_expand.pw, "candidates", REAL_CANDIDATES)        # the store the harvest fills
    bio = io.BytesIO()
    with pyzipper.AESZipFile(bio, "w", encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(b"Octopus2024")
        zf.writestr("flag.txt", b"CSCTF{locked_until_the_note_was_read}")
    data, _ = demented_zip()
    ch = fx.pulled(tmp_path, {"forgotten-playground.zip": data, "secret.zip": bio.getvalue(),
                              "note.txt": b"The curator left a note: the archive password is Octopus2024.\n"})
    rep = sweep.sweep(ch, CSCTF)
    assert any("harvested" in n and "re-swept" in n for n in rep.notes)          # the unpack ran twice
    assert rep.result.flags == ("CSCTF{locked_until_the_note_was_read}",)
    assert len(rep.to_dict()["git"]) == 1
    assert sum(1 for c in chains(rep) if c.endswith(f" -> {REPORT}")) == 1


def test_a_repository_over_the_byte_or_object_limit_is_a_note(tmp_path, monkeypatch):
    g, _gone, _ids = many_versions(3)
    data = fx.zip_bytes({"repo/keep.txt": b"k\n", **g.files("repo/.git/")})
    monkeypatch.setattr(handoutgit, "MAX_GIT_BYTES", 64)
    rep = sweep.sweep(fx.pulled(tmp_path, {"h.zip": data}), CSCTF)
    assert rep.to_dict()["git"] == [] and not any(".git -> " in c for c in chains(rep))
    assert any("bytes of git objects is over the limit of 64" in n and "by hand" in n for n in rep.notes)
    monkeypatch.setattr(handoutgit, "MAX_GIT_BYTES", 256 << 20)
    monkeypatch.setattr(handoutgit, "MAX_OBJECTS", 5)
    rep = sweep.sweep(fx.pulled(tmp_path, {"h.zip": data}, cid=2), CSCTF)
    assert rep.to_dict()["git"] == []
    assert any("objects is over the pull-time limit of 5" in n for n in rep.notes)


def test_only_max_repos_repositories_are_read(tmp_path, monkeypatch):
    files = {}
    for name in ("a", "b", "c"):
        g = fx.GitDir()
        g.branch("main", g.commit({"f.txt": name.encode()}, name, when=1))
        files.update(g.files(f"{name}/.git/"))
    monkeypatch.setattr(handoutgit, "MAX_REPOS", 2)
    rep = sweep.sweep(fx.pulled(tmp_path, {"h.zip": fx.zip_bytes(files)}), CSCTF)
    assert [g["label"] for g in rep.to_dict()["git"]] == ["h.zip -> a/.git", "h.zip -> b/.git"]
    assert any(n == "git handout h.zip -> c/.git: not read, 2 repositories were read already" for n in rep.notes)


def test_git_members_count_against_the_walk_budget(tmp_path):
    g, gone, _ids = many_versions(4)
    data = fx.zip_bytes({"repo/keep.txt": b"k\n", **g.files("repo/.git/")})
    ch = fx.pulled(tmp_path, {"h.zip": data})
    probe = archive_expand.Walk()
    whole = sweep.sweep(ch, CSCTF, walk=probe)
    mine = [c for c in chains(whole) if c.startswith("h.zip -> repo/.git -> ")]
    assert len(mine) == 5                                 # deleted + 3 history + the report
    # room for the zip's own members and two of the step's: the third is refused and the walk is full
    rep = sweep.sweep(ch, CSCTF, walk=archive_expand.Walk(max_members=probe.count - 3))
    got = [c for c in chains(rep) if c.startswith("h.zip -> repo/.git -> ")]
    assert got == mine[:2]
    assert any("the walk's budget" in n and "is spent" in n for n in rep.notes)
    assert rep.to_dict()["git"][0]["report"] is None and rep.to_dict()["git"][0]["exported"] == 2


def test_a_damaged_object_is_a_problem_in_the_summary_not_a_crash(tmp_path):
    flag = b"CSCTF{the_rest_still_reads}"
    g = fx.GitDir()
    c1 = g.commit({"a.txt": b"a\n", "gone.txt": flag + b"\n"}, "one", when=1)
    c2 = g.commit({"a.txt": b"a\n"}, "two", [c1], 2)
    g.branch("main", c2)
    g.t["objects/de/" + "ad" * 19] = b"this is not zlib"
    data = fx.zip_bytes({"repo/a.txt": b"a\n", **g.files("repo/.git/")})
    rep = sweep.sweep(fx.pulled(tmp_path, {"h.zip": data}), CSCTF)
    assert rep.result.flags == (flag.decode(),)
    g0 = rep.to_dict()["git"][0]
    assert g0["complete"] is False and any("loose object de" + "ad" * 19 in p for p in g0["problems"])
    assert "PROBLEM: loose object de" in member(rep, fx_dir(rep), f"h.zip -> repo/.git -> {REPORT}").decode()


def fx_dir(rep):
    return rep.target.root


def test_a_reader_that_raises_is_a_note_and_the_sweep_still_reports(tmp_path, monkeypatch):
    data, _ = requiem_zip()
    mod = handoutgit._rsc()

    def boom(entries):
        raise RuntimeError("hostile repository")
    monkeypatch.setattr(mod, "find_git", boom)
    rep = sweep.sweep(fx.pulled(tmp_path, {"h.zip": data}), CSCTF)
    assert rep.result.status == "none" and rep.to_dict()["git"] == []
    assert any(n == "git handout in h.zip: the repository does not read (RuntimeError: hostile repository)"
               for n in rep.notes)
    # the rest of the sweep is whole: the icon's zip was still carved
    assert any("carved@0x" in c for c in chains(rep))


def test_a_failure_inside_one_repository_does_not_lose_the_next(tmp_path, monkeypatch):
    files = {}
    for name, body in (("a", b"CSCTF{from_repository_a}"), ("b", b"CSCTF{from_repository_b}")):
        g = fx.GitDir()
        g.branch("main", g.commit({"f.txt": body}, name, when=1))
        files.update(g.files(f"{name}/.git/"))
    real = handoutgit.Step._read

    def flaky(self, rsc_mod, repo, container, walk, notes):
        if repo.label.endswith("a/.git"):
            raise ValueError("broken tree")
        return real(self, rsc_mod, repo, container, walk, notes)
    monkeypatch.setattr(handoutgit.Step, "_read", flaky)
    rep = sweep.sweep(fx.pulled(tmp_path, {"h.zip": fx.zip_bytes(files)}), CSCTF)
    assert rep.result.flags == ("CSCTF{from_repository_b}",)
    assert any(n == "git handout h.zip -> a/.git: reading it failed, nothing exported (ValueError: broken tree)"
               for n in rep.notes)


def test_a_candidate_quoted_in_the_brief_is_excluded_like_any_other(tmp_path):
    data, _ = demented_zip()
    ch = fx.pulled(tmp_path, {"forgotten-playground.zip": data},
                   description="example: spooky{the_g00d_the_l0st_@ndth3_void}")
    rep = sweep.sweep(ch, SPOOKY)
    assert rep.result.flags == ("spooky{the_g00d_the_l0st_@nd_th3_void}",)
    assert "brief" in rep.excluded["spooky{the_g00d_the_l0st_@ndth3_void}"]
