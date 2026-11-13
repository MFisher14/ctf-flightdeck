"""B-013: the pull-time corpus sweep (ctf/sweep.py), its CLI (`ctf sweep`) and the `ctf pull` hook.

The three coverage rows it closes, rebuilt synthetically:
  * CSCTF 9076 Last Buffer: a handout zip whose vim swap file holds a base64 flag at an offset;
  * Spooky The Phantom Login: a zip of logs whose web log carries a URL-encoded base64 parameter;
  * Spooky Tormented Tanny: a bare dropped PNG whose flag is split over tEXt, XMP and eXIf.
Every fixture is built in the test; nothing is executed, nothing touches the network.
"""
import base64
import hashlib
import io
import json
import os
import stat
import urllib.parse
import zipfile
from pathlib import Path

import pytest

import archive_expand
from ctf import event, flagfmt, sweep
from ctf.cli import _pullsweep
from ctf.packs import PackMissing

import test_fragjoin as frag


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    monkeypatch.setattr(archive_expand.pw, "candidates", lambda: [b"infected"])


def zip_bytes(entries, compression=zipfile.ZIP_DEFLATED):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", compression=compression) as z:
        for e in entries:
            z.writestr(*e)
    return bio.getvalue()


def pulled(tmp_path, files: dict, description="", cid=9076, category="Forensics") -> Path:
    ch = tmp_path / "wd" / f"{cid}-x"
    (ch / "files").mkdir(parents=True)
    (ch / "challenge.json").write_text(json.dumps({"id": cid, "name": "x", "category": category,
                                                   "description": description}))
    for name, data in files.items():
        (ch / "files" / name).write_bytes(data)
    return ch


def tree_digest(folder: Path) -> dict:
    return {p.relative_to(folder).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(folder.rglob("*")) if p.is_file()}


def swap_file(flag: bytes) -> bytes:
    """A vim-swap-shaped blob: header, binary noise, then the base64 of the flag glued in."""
    noise = bytes((i * 37 + 11) % 256 for i in range(3000))
    return b"b0VIM 9.0\x00" + noise + b"\x00\x00" + base64.b64encode(flag) + b"\x00" + noise[:200]


CSCTF = event.load("csctf")
SPOOKY = event.load("spooky")


# ---------------------------------------------------------------- 9076 Last Buffer

def test_last_buffer_base64_in_a_zipped_swap_file_is_found_in_a_scratch_copy(tmp_path):
    flag = b"CSCTF{last_buffer_survives_the_crash}"
    ch = pulled(tmp_path, {"handout.zip": zip_bytes([("home/user/.notes.txt.swp", swap_file(flag)),
                                                     ("timeline.txt", b"pid 4242 pts/3")])},
                description="Recover what was left in the buffer. Flag format: CSCTF{...}")
    before = tree_digest(ch / "files")
    rep = sweep.sweep(ch, CSCTF)
    assert rep.result.status == "solved"
    assert rep.result.flags == ("CSCTF{last_buffer_survives_the_crash}",)
    ev = rep.result.evidence[0]
    assert ev.path == "unpacked/handout.zip.unpacked/home/user/.notes.txt.swp"
    swp = (ch / ev.path).read_bytes()
    assert swp[ev.offset:].startswith(base64.b64encode(flag))      # the offset points at the token
    assert "home/user/.notes.txt.swp" in ev.detail
    # Never in place: the originals are byte-for-byte unchanged and nothing was added beside them.
    assert tree_digest(ch / "files") == before
    assert (ch / "unpacked" / "handout.zip").read_bytes() == (ch / "files" / "handout.zip").read_bytes()


def test_manifest_has_sha256_of_every_original_and_member_and_triage(tmp_path):
    member = b"just text"
    ch = pulled(tmp_path, {"a.zip": zip_bytes([("dir/m.txt", member)]), "loose.bin": b"\x7fELF" + b"\x00" * 60})
    rep = sweep.sweep(ch, CSCTF)
    report = json.loads((ch / "unpacked" / sweep.REPORT).read_text())
    rows = {r["chain"]: r for r in report["manifest"]}
    assert rows["a.zip -> dir/m.txt"]["sha256"] == hashlib.sha256(member).hexdigest()
    assert rows["a.zip -> dir/m.txt"]["path"] == "unpacked/a.zip.unpacked/dir/m.txt"
    assert rows["a.zip"]["original"] is True and rows["a.zip -> dir/m.txt"]["original"] is False
    assert rows["loose.bin"]["kind"].startswith("elf")
    listed = dict(report["triage"]["files"])
    assert "a.zip.unpacked/dir/m.txt" in listed and "loose.bin" in listed
    assert not any(name.startswith(".sweep") or name == ".lock" for name in listed)
    assert report["result"]["status"] == rep.result.status == "none"


def test_flag_quoted_in_the_brief_is_excluded_as_template_text(tmp_path):
    ch = pulled(tmp_path, {"readme.txt": b"submit like CSCTF{example_of_the_format}"},
                description="Flags look like CSCTF{example_of_the_format}.")
    rep = sweep.sweep(ch, CSCTF)
    assert rep.result.status == "none"
    assert "CSCTF{example_of_the_format}" in rep.excluded
    assert "brief" in rep.excluded["CSCTF{example_of_the_format}"]


def test_placeholder_bodies_are_excluded_but_real_ones_kept(tmp_path):
    ch = pulled(tmp_path, {"a.txt": b"CSCTF{...} CSCTF{xxx} CSCTF{real_value_1}"})
    rep = sweep.sweep(ch, CSCTF)
    assert rep.result.flags == ("CSCTF{real_value_1}",)
    assert set(rep.excluded) == {"CSCTF{...}", "CSCTF{xxx}"}


def test_the_innermost_member_is_the_witness_not_the_stored_archive_around_it(tmp_path):
    raw = zip_bytes([("deep/note.txt", b"x CSCTF{stored_member} y")], compression=zipfile.ZIP_STORED)
    assert b"CSCTF{stored_member}" in raw                  # the archive's own bytes show it too
    ch = pulled(tmp_path, {"a.zip": raw})
    rep = sweep.sweep(ch, CSCTF)
    assert rep.result.evidence[0].path == "unpacked/a.zip.unpacked/deep/note.txt"
    assert rep.result.evidence[0].offset == 2


def test_two_distinct_flags_are_candidates_not_solved(tmp_path):
    ch = pulled(tmp_path, {"a.txt": b"CSCTF{decoy_one}", "b.txt": base64.b64encode(b"CSCTF{maybe_real}")})
    rep = sweep.sweep(ch, CSCTF)
    assert rep.result.status == "candidate"
    assert set(rep.result.flags) == {"CSCTF{decoy_one}", "CSCTF{maybe_real}"}


# ---------------------------------------------------------------- The Phantom Login

def test_phantom_login_url_encoded_base64_parameter_in_a_web_log(tmp_path):
    flag = b"spooky{???_phantom_login_???}"            # '?' makes the base64 full of '/', so %2F splits it
    token = base64.b64encode(flag).decode()
    assert "/" in token
    param = urllib.parse.quote(token, safe="")
    log = "\n".join([f'10.0.0.{i} - - [06/Nov/2026] "GET /index.html HTTP/1.1" 200' for i in range(50)]
                    + [f'10.9.9.9 - - [06/Nov/2026] "GET /archives/export?note={param} HTTP/1.1" 200'])
    csv = "EventID,Account,Detail\n" + "\n".join(f"4625,evelyn.graves,An account failed to log on" for _ in range(9))
    ch = pulled(tmp_path, {"phantom.zip": zip_bytes([("security.csv", csv), ("access.log", log)])}, cid=3)
    rep = sweep.sweep(ch, SPOOKY)
    assert rep.result.flags == ("spooky{???_phantom_login_???}",)
    methods = [h.method for h in rep.flags["spooky{???_phantom_login_???}"]]
    assert any(m.startswith("url+decode:base64") for m in methods)
    # Without the URL layer the raw text gives nothing: the token is cut at every %2F.
    raw = log.encode()
    assert not any(h.method.startswith("decode") for h in sweep.scan(raw, "x", flagfmt.for_profile(SPOOKY),
                                                                     sweep._embedded())
                   if h.flag.startswith("spooky"))


# ---------------------------------------------------------------- Tormented Tanny (manual mode, bare file)

def test_tormented_tanny_bare_png_split_metadata_is_a_candidate(tmp_path):
    drop = tmp_path / "dropped"
    drop.mkdir()
    png = drop / "tanny.png"
    png.write_bytes(frag.tanny_png())
    rep = sweep.sweep(png, SPOOKY)
    assert rep.result.status == "candidate"
    assert rep.result.flags[0] == "spooky{split_across_three_containers}"
    assert rep.result.evidence[0].kind == "join"
    # A bare file's scratch copy is under the workdir, never beside the file.
    assert sweep._inside(rep.target.out, tmp_path / "wd" / "sweep")
    assert sorted(p.name for p in drop.iterdir()) == ["tanny.png"]
    assert "tanny.png" in dict(rep.triage["files"])


def test_drop_folder_reads_its_brief_and_skips_its_own_files(tmp_path):
    drop = tmp_path / "wd" / "drop" / "c1"
    drop.mkdir(parents=True)
    (drop / "challenge.toml").write_text('name = "c1"\ncategory = "misc"\ndescription = "format spooky{fake_one}"\n')
    (drop / "SOLVED").write_text("someone\n")
    (drop / "note.txt").write_bytes(b"spooky{fake_one} and spooky{" + b"real}")
    rep = sweep.sweep(drop, SPOOKY)
    assert rep.target.kind == "drop" and rep.target.challenge_id == "c1"
    chains = {e.chain[0] for e in rep.manifest}
    assert chains == {"note.txt"}
    assert rep.result.flags == ("spooky{real}",)
    assert "spooky{fake_one}" in rep.excluded


# ---------------------------------------------------------------- the other encodings

def test_utf16_nested_and_misaligned_encodings(tmp_path):
    ff = flagfmt.for_profile(CSCTF)
    ed = sweep._embedded()
    u16 = b"\xff\xfe" + "noise CSCTF{wide_chars} end".encode("utf-16-le")
    methods = {h.method for h in sweep.scan(u16, "d", ff, ed) if h.flag == "CSCTF{wide_chars}"}
    assert "utf16le" in methods and not any(m == "plain" or m.startswith("decode") for m in methods)
    nested = base64.b64encode(b"CSCTF{hex_inside_b64}".hex().encode())
    assert any(h.method == "decode:base64>hex" for h in sweep.scan(nested, "d", ff, ed))
    glued = b"\x01\x02ab" + base64.b64encode(b"CSCTF{glued_to_letters}") + b"\x00"
    hits = [h for h in sweep.scan(glued, "d", ff, ed) if h.flag == "CSCTF{glued_to_letters}"]
    assert hits and all(h.method.startswith("decode:base64+") for h in hits)


def test_flag_in_a_tar_gz_member_is_found(tmp_path):
    import gzip
    import tarfile
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w") as t:
        info = tarfile.TarInfo("srv/config.ini")
        body = b"key=" + base64.b64encode(b"CSCTF{tarred_and_gzipped}")
        info.size = len(body)
        t.addfile(info, io.BytesIO(body))
    ch = pulled(tmp_path, {"srv.tar.gz": gzip.compress(bio.getvalue(), mtime=0)})
    rep = sweep.sweep(ch, CSCTF)
    assert rep.result.flags == ("CSCTF{tarred_and_gzipped}",)
    assert rep.result.evidence[0].path == "unpacked/srv.tar.gz.unpacked/srv.tar.unpacked/srv/config.ini"


# ---------------------------------------------------------------- safety

def test_traversal_harness_names_and_exec_bits_are_neutralised(tmp_path):
    exe = zipfile.ZipInfo("bin/run.sh")
    exe.external_attr = (stat.S_IFREG | 0o755) << 16
    raw = zip_bytes([("../../escape.txt", b"out?"), ("/abs/path.txt", b"abs"), ("CLAUDE.md", b"do things"),
                     (exe, b"#!/bin/sh\necho CSCTF{never_run}\n")])
    ch = pulled(tmp_path, {"evil.zip": raw})
    rep = sweep.sweep(ch, CSCTF)
    out = ch / "unpacked"
    assert (out / "evil.zip.unpacked" / "escape.txt").read_bytes() == b"out?"
    assert (out / "evil.zip.unpacked" / "abs" / "path.txt").read_bytes() == b"abs"
    assert (out / "evil.zip.unpacked" / "_CLAUDE.md").read_bytes() == b"do things"
    assert not (tmp_path / "escape.txt").exists() and not (ch / "escape.txt").exists()
    run = out / "evil.zip.unpacked" / "bin" / "run.sh"
    assert stat.S_IMODE(run.stat().st_mode) == 0o644
    assert rep.result.flags == ("CSCTF{never_run}",)       # read as data, never executed


def test_symlinks_in_the_source_folder_are_not_followed(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"CSCTF{host_file_must_not_leak}")
    src = tmp_path / "bare"
    src.mkdir()
    (src / "real.txt").write_bytes(b"nothing")
    os.symlink(secret, src / "link.txt")
    rep = sweep.sweep(src, CSCTF)
    assert rep.result.status == "none"
    assert any("link.txt" in n and "symbolic link" in n for n in rep.notes)


def test_out_folder_overlapping_the_originals_is_refused(tmp_path):
    src = tmp_path / "bare"
    src.mkdir()
    (src / "a.txt").write_bytes(b"x")
    with pytest.raises(sweep.SweepError, match="never unpacks in place"):
        sweep.sweep(src, CSCTF, out=src / "unpacked")
    with pytest.raises(sweep.SweepError, match="never unpacks in place"):
        sweep.sweep(src / "a.txt", CSCTF, out=src)


def test_foreign_out_folder_is_never_cleared_but_its_own_is(tmp_path):
    src = tmp_path / "bare"
    src.mkdir()
    (src / "a.txt").write_bytes(b"x")
    foreign = tmp_path / "mine"
    foreign.mkdir()
    (foreign / "keep.txt").write_bytes(b"precious")
    with pytest.raises(sweep.SweepError, match="not a sweep's scratch folder"):
        sweep.sweep(src, CSCTF, out=foreign)
    assert (foreign / "keep.txt").read_bytes() == b"precious"
    own = tmp_path / "scratch"
    sweep.sweep(src, CSCTF, out=own)
    (own / "stale.txt").write_bytes(b"left over")
    sweep.sweep(src, CSCTF, out=own)
    assert not (own / "stale.txt").exists() and (own / "a.txt").read_bytes() == b"x"


def test_unpack_budget_notes_reach_the_report(tmp_path):
    ch = pulled(tmp_path, {"many.zip": zip_bytes([(f"m{i}.txt", b"x") for i in range(12)])})
    rep = sweep.sweep(ch, CSCTF, walk=archive_expand.Walk(max_members=4))
    assert sum(not e.original for e in rep.manifest) == 4
    assert any("budget" in n for n in rep.notes)


def test_missing_pack_fails_loudly(tmp_path, monkeypatch):
    src = tmp_path / "bare"
    src.mkdir()
    (src / "a.txt").write_bytes(b"x")
    monkeypatch.setattr(sweep._paths, "repo_root", lambda: tmp_path / "no-repo")
    monkeypatch.delitem(__import__("sys").modules, "ctf_embedded_decode", raising=False)
    with pytest.raises(PackMissing, match="embedded_decode"):
        sweep.sweep(src, CSCTF)


def test_empty_target_and_missing_target_are_errors(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(sweep.NothingToSweep, match="no file to sweep"):
        sweep.sweep(empty, CSCTF)
    links = tmp_path / "links"
    links.mkdir()
    os.symlink(tmp_path / "nope", links / "l.txt")
    with pytest.raises(sweep.SweepError, match="every file was left out.*symbolic link") as ei:
        sweep.sweep(links, CSCTF)
    assert not isinstance(ei.value, sweep.NothingToSweep)
    with pytest.raises(sweep.SweepError, match="not there"):
        sweep.sweep(tmp_path / "nope", CSCTF)


# ---------------------------------------------------------------- CLI and the pull hook

def test_cli_sweep_json_and_error_exit(tmp_path, capsys):
    from ctf.cli import main
    f = tmp_path / "bare.txt"
    f.write_bytes(base64.b64encode(b"spooky{from_the_cli}"))
    assert main(["sweep", str(f), "--event", "spooky", "--json"]) == 0
    res = json.loads(capsys.readouterr().out)
    assert res["status"] == "solved" and res["flags"] == ["spooky{from_the_cli}"]
    assert main(["sweep", str(tmp_path / "missing"), "--event", "spooky"]) == 2
    assert "SweepError" in capsys.readouterr().err
    assert main(["sweep", str(f), "--event", "spooky", "--max-depth", "-1"]) == 2


def test_cli_brief_option_excludes(tmp_path, capsys):
    from ctf.cli import main
    f = tmp_path / "bare.txt"
    f.write_bytes(b"spooky{in_brief}")
    assert main(["sweep", str(f), "--event", "spooky", "--brief", "like spooky{in_brief}"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("sweep: none") and "excluded spooky{in_brief}" in out


class _FakeCTFd:
    """Stands in for the CTFd client in `ctf pull`: one challenge, one handout, no network."""

    def __init__(self, files):
        self.files = files

    def challenge(self, cid):
        return {"id": cid, "name": "Last Buffer", "category": "Forensics", "description": "a crash", "value": 120}

    def download_files(self, cid, dest):
        for name, data in self.files.items():
            (Path(dest) / name).write_bytes(data)


def test_pull_runs_the_sweep_and_notes_it(tmp_path, monkeypatch, capsys):
    from ctf import cli, workspace
    flag = b"CSCTF{pulled_then_swept}"

    def for_challenge(detail, cfg=None):
        d = tmp_path / "wd" / f"{detail['id']}-x"
        (d / "files").mkdir(parents=True, exist_ok=True)
        (d / "challenge.json").write_text(json.dumps(detail))
        return workspace.Challenge(cid=int(detail["id"]), name=detail["name"], category=detail["category"], dir=d)

    monkeypatch.setattr(cli._ws, "for_challenge", for_challenge)
    ch = cli._pull_one(_FakeCTFd({"handout.zip": zip_bytes([("b.swp", swap_file(flag))])}), 9076)
    out = capsys.readouterr().out
    assert "sweep: solved" in out and "CSCTF{pulled_then_swept}" in out
    notes = ch.notes_path.read_text()
    assert "## sweep" in notes and "CSCTF{pulled_then_swept}" in notes
    assert (ch.dir / "unpacked" / "handout.zip.unpacked" / "b.swp").is_file()


def _hook_challenge(tmp_path, name, detail='{"id": 1}'):
    from ctf import workspace
    d = tmp_path / "wd" / name
    (d / "files").mkdir(parents=True)
    (d / "challenge.json").write_text(detail)
    return workspace.Challenge(cid=1, name="e", category="misc", dir=d)


def test_pull_hook_says_no_handout_plainly_not_failed(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "csctf")
    ch = _hook_challenge(tmp_path, "1-web")             # a web/instance challenge: files/ is empty
    assert _pullsweep.after_pull(ch) == 0
    cap = capsys.readouterr()
    assert "sweep: nothing to sweep (no handout files)" in cap.out
    assert "FAILED" not in cap.out + cap.err
    notes = ch.notes_path.read_text()
    assert "nothing to sweep" in notes and "FAILED" not in notes


def test_pull_hook_reports_a_failed_sweep_by_name(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "csctf")
    bad = _hook_challenge(tmp_path, "2-bad", detail="{not json")
    assert _pullsweep.after_pull(bad) == 1
    assert "sweep: FAILED (SweepError:" in capsys.readouterr().err
    assert "sweep: FAILED" in bad.notes_path.read_text()
    # files that are there but all left out are a failure with the reason, not "no handout"
    only_secret = _hook_challenge(tmp_path, "3-secret")
    (only_secret.dir / "files" / ".ctf").mkdir()
    (only_secret.dir / "files" / ".ctf" / "token").write_bytes(b"K=v")
    assert _pullsweep.after_pull(only_secret) == 1
    err = capsys.readouterr().err
    assert "sweep: FAILED (SweepError: no file to sweep" in err and "may hold credentials" in err


# ---------------------------------------------------------------- verification round 1

def test_cli_event_option_holds_with_ctf_event_unset(tmp_path, capsys, monkeypatch):
    from ctf.cli import main
    monkeypatch.delenv("CTF_EVENT", raising=False)
    assert len(event.available()) > 1
    with pytest.raises(event.EventError):                 # no active event: only --event names one
        flagfmt.current()
    f = tmp_path / "a.txt"
    f.write_bytes(b"token=" + base64.b64encode(b"spooky{event_option_holds}") + b"\n")
    assert main(["sweep", str(f), "--event", "spooky", "--json"]) == 0
    res = json.loads(capsys.readouterr().out)
    assert res["status"] == "solved" and res["flags"] == ["spooky{event_option_holds}"]


def test_find_blobs_uses_the_given_flag_pattern_and_opt_in_alignments(monkeypatch):
    monkeypatch.delenv("CTF_EVENT", raising=False)
    ed = sweep._embedded()
    text = "x " + base64.b64encode(b"CSCTF{given_pattern_ok}").decode() + " y"
    hit = [b for b in ed.find_blobs(text, min_printable=0.0, flag_re=flagfmt.for_profile(CSCTF).bregex)
           if b["decoded"] == b"CSCTF{given_pattern_ok}"]
    assert hit and hit[0]["flag"] is True
    other = [b for b in ed.find_blobs(text, min_printable=0.0, flag_re=flagfmt.for_profile(SPOOKY).bregex)
             if b["decoded"] == b"CSCTF{given_pattern_ok}"]
    assert other and other[0]["flag"] is False            # the pattern passed in decides, not a default
    glued = "ab" + base64.b64encode(b"CSCTF{glued_alignment}").decode()
    rx = flagfmt.for_profile(CSCTF).bregex
    plain = ed.find_blobs(glued, min_printable=0.0, flag_re=rx)
    assert not any(b"CSCTF{glued_alignment}" in b["decoded"] for b in plain)
    wide = ed.find_blobs(glued, min_printable=0.0, flag_re=rx, alignments=True)
    got = [b for b in wide if b["decoded"] == b"CSCTF{glued_alignment}"]
    assert got and got[0]["encoding"] == "base64+2" and got[0]["offset"] == 2 and got[0]["flag"]


def test_utf16le_at_an_odd_offset_without_bom():
    ff = flagfmt.for_profile(CSCTF)
    data = b"\x01" + "noise CSCTF{odd_offset_wide} end".encode("utf-16-le")
    hits = [h for h in sweep.scan(data, "d", ff, sweep._embedded()) if h.flag == "CSCTF{odd_offset_wide}"]
    assert any(h.method == "utf16le" and h.offset == 1 + 2 * len("noise ") for h in hits)


def test_token_straddling_a_window_boundary_is_found(monkeypatch):
    monkeypatch.setattr(sweep, "WINDOW", 4096)
    monkeypatch.setattr(sweep, "OVERLAP", 256)
    token = base64.b64encode(b"CSCTF{straddles_the_window}")
    at = 4096 - 20                                        # the token runs over the 4096 boundary
    data = b"." * at + token + b" " + b"." * 6000
    hits = [h for h in sweep.scan(data, "d", flagfmt.for_profile(CSCTF), sweep._embedded())
            if h.flag == "CSCTF{straddles_the_window}"]
    assert any(h.method == "decode:base64" and h.offset == at for h in hits)


def test_oversized_tar_member_is_never_read(tmp_path, monkeypatch):
    import tarfile
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w") as t:
        for name, body in (("big.bin", b"B" * 500), ("small.txt", b"CSCTF{small_member}")):
            info = tarfile.TarInfo(name)
            info.size = len(body)
            t.addfile(info, io.BytesIO(body))
    src = tmp_path / "bare"
    src.mkdir()
    (src / "a.tar").write_bytes(bio.getvalue())
    read = []
    real = tarfile.TarFile.extractfile

    def spy(self, member):
        read.append(member.name if hasattr(member, "name") else member)
        return real(self, member)
    monkeypatch.setattr(tarfile.TarFile, "extractfile", spy)
    rep = sweep.sweep(src, CSCTF, walk=archive_expand.Walk(max_member=100))
    assert read == ["small.txt"]                           # the declared size decides; big.bin never opened
    assert any("big.bin" in n and "member limit" in n for n in rep.notes)
    assert rep.result.flags == ("CSCTF{small_member}",)


def test_secret_bearing_paths_are_never_read(tmp_path):
    src = tmp_path / "bare"
    for rel in (".ctf/token", ".git/config", ".env", ".env.local", "sub/.ctf/cookie"):
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_bytes(b"CSCTF{leak_" + rel.replace("/", "_").replace(".", "d").encode() + b"}")
    (src / "a.txt").write_bytes(b"CSCTF{fine}")
    rep = sweep.sweep(src, CSCTF)
    assert rep.result.flags == ("CSCTF{fine}",)
    assert [e.chain for e in rep.manifest] == [("a.txt",)]
    for rel in (".ctf", ".git", ".env", ".env.local", "sub/.ctf"):
        assert any(repr(rel) in n and "credentials" in n for n in rep.notes), rel
    assert not any(b"leak" in p.read_bytes() for p in rep.target.out.rglob("*") if p.is_file())
    with pytest.raises(sweep.SweepError, match="credentials store"):
        sweep.sweep(src / ".ctf", CSCTF)
    with pytest.raises(sweep.SweepError, match="credentials store"):
        sweep.sweep(src / ".env", CSCTF)


# ---------------------------------------------------------------- verification round 2

@pytest.mark.parametrize("prefix", ["a", "ab", "abc"])
@pytest.mark.parametrize("tail", ["", "x"])
def test_misaligned_base64_every_glue_length_and_a_trailing_char(monkeypatch, prefix, tail):
    monkeypatch.delenv("CTF_EVENT", raising=False)
    ed = sweep._embedded()
    flag = b"CSCTF{glue_every_widths}"                      # 24 bytes: 32 base64 chars, no '='
    assert len(flag) % 3 == 0
    text = prefix + base64.b64encode(flag).decode() + tail  # one run: glue + token (+ one stray char)
    rx = flagfmt.for_profile(CSCTF).bregex
    assert not any(flag in b["decoded"] for b in ed.find_blobs(text, min_printable=0.0, flag_re=rx))
    got = [b for b in ed.find_blobs(text, min_printable=0.0, flag_re=rx, alignments=True)
           if b["decoded"] == flag]
    assert got, (prefix, tail)
    assert got[0]["encoding"] == f"base64+{len(prefix)}" and got[0]["offset"] == len(prefix) and got[0]["flag"]


def test_a_git_folder_target_is_refused_like_a_ctf_one(tmp_path):
    g = tmp_path / "repo" / ".git"
    (g / "objects").mkdir(parents=True)
    (g / "config").write_bytes(b"CSCTF{git_config_leak}")
    (g / "objects" / "x").write_bytes(b"CSCTF{git_object_leak}")
    with pytest.raises(sweep.SweepError, match=r"credentials store \(.*\.git/"):
        sweep.sweep(g, CSCTF)
    with pytest.raises(sweep.SweepError, match="credentials store"):
        sweep.sweep(g / "objects", CSCTF)
    with pytest.raises(sweep.SweepError, match="credentials store"):
        sweep.sweep(g / "config", CSCTF)
    assert not (tmp_path / "wd" / "sweep").exists()          # refused before any scratch copy


def test_a_pulled_handouts_env_file_is_read_but_its_ctf_folder_is_not(tmp_path):
    d = tmp_path / "wd" / "7-webapp"
    (d / "files" / ".ctf").mkdir(parents=True)
    (d / "challenge.json").write_text('{"id": 7, "category": "web"}')
    (d / "files" / ".env").write_bytes(b"SECRET_KEY=x\nFLAG=CSCTF{handout_dotenv}\n")
    (d / "files" / ".ctf" / "token").write_bytes(b"CSCTF{never_this}")
    rep = sweep.sweep(d, CSCTF)
    assert rep.target.kind == "pulled"
    assert rep.result.flags == ("CSCTF{handout_dotenv}",)
    assert [e.chain for e in rep.manifest] == [(".env",)]
    assert any("'.ctf'" in n and "credentials" in n for n in rep.notes)
    # the same .env in a folder that is not a pulled challenge stays unread
    loose = tmp_path / "loose"
    loose.mkdir()
    (loose / ".env").write_bytes(b"FLAG=CSCTF{handout_dotenv}\n")
    (loose / "a.txt").write_bytes(b"nothing")
    rep2 = sweep.sweep(loose, CSCTF)
    assert rep2.result.flags == () and any("'.env'" in n and "credentials" in n for n in rep2.notes)


def test_sources_have_a_total_byte_budget(tmp_path, monkeypatch):
    monkeypatch.setattr(sweep, "MAX_SOURCE_TOTAL", 100)
    src = tmp_path / "bare"
    src.mkdir()
    (src / "a.txt").write_bytes(b"a" * 60)
    (src / "b.txt").write_bytes(b"CSCTF{over_budget}".ljust(60, b" "))
    (src / "c.txt").write_bytes(b"CSCTF{fits}".ljust(30, b" "))
    rep = sweep.sweep(src, CSCTF)
    assert [e.chain for e in rep.manifest] == [("a.txt",), ("c.txt",)]
    assert any("'b.txt'" in n and "total budget of 100" in n for n in rep.notes)
    assert rep.result.flags == ("CSCTF{fits}",)
