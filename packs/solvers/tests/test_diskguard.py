"""B-176 disk side: disk-budget preflight, the copier that rejects symlinks, post-acceptance eviction of
large artifacts, Spotlight exclusion, and their `ctf governor` subcommands. All trees are synthetic; big
files are sparse (truncate), so nothing here fills the disk."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from ctf import diskguard as dg
from ctf import ledger
from ctf.cli import governor as cli

MiB, GiB = dg.MiB, dg.GiB


def usage(free):
    return lambda p: SimpleNamespace(free=free, total=free * 4, used=0)


def big(path: Path, size: int) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        fh.truncate(size)
    return path


# ------------------------------------------------------------------------------------------ preflight

def test_preflight_boundary_is_inclusive(tmp_path):
    v = dg.disk_preflight(tmp_path, 6 * GiB, 4 * GiB, usage=usage(10 * GiB))
    assert v.ok and v.free_bytes == 10 * GiB
    v = dg.disk_preflight(tmp_path, 6 * GiB + 1, 4 * GiB, usage=usage(10 * GiB))
    assert not v.ok and "floor 4.00 GiB" in v.reason


def test_preflight_measures_nearest_existing_ancestor(tmp_path):
    seen = []
    dg.disk_preflight(tmp_path / "a" / "b", 1, 0, usage=lambda p: seen.append(p) or SimpleNamespace(free=9))
    assert seen == [tmp_path]


def test_preflight_real_volume(tmp_path):
    assert dg.disk_preflight(tmp_path, 1, 0).ok
    assert not dg.disk_preflight(tmp_path, 1 << 62, 0).ok


def test_preflight_rejects_negative():
    with pytest.raises(dg.DiskGuardError):
        dg.disk_preflight(".", -1, 0)


@pytest.mark.parametrize("text,n", [("123", 123), ("500M", 500 * MiB), ("2G", 2 * GiB), ("1.5GiB", int(1.5 * GiB)),
                                    ("4k", 4096), ("1T", 1024 * GiB)])
def test_parse_size(text, n):
    assert dg.parse_size(text) == n


def test_parse_size_bad():
    with pytest.raises(dg.DiskGuardError):
        dg.parse_size("lots")


# ------------------------------------------------------------------------------------------ copier

def tree(root: Path) -> Path:
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_text("alpha")
    (root / "sub" / "b.bin").write_bytes(b"\x00\x01" * 10)
    return root


def test_copytree_copies_regular_files(tmp_path):
    src = tree(tmp_path / "src")
    n = dg.safe_copytree(src, tmp_path / "dst")
    assert n == 25
    assert (tmp_path / "dst" / "a.txt").read_text() == "alpha"
    assert (tmp_path / "dst" / "sub" / "b.bin").read_bytes() == b"\x00\x01" * 10


def test_copytree_rejects_the_huntress_self_referential_symlink_before_writing(tmp_path):
    src = tree(tmp_path / "challenges")
    os.symlink("..", src / "sub" / "challenges")          # challenges/sub/challenges -> challenges
    with pytest.raises(dg.SymlinkRejected, match="symlink"):
        dg.safe_copytree(src, tmp_path / "dst")
    assert not (tmp_path / "dst").exists()


def test_copytree_rejects_a_file_symlink(tmp_path):
    src = tree(tmp_path / "src")
    os.symlink(src / "a.txt", src / "link.txt")
    with pytest.raises(dg.SymlinkRejected):
        dg.safe_copytree(src, tmp_path / "dst")
    assert not (tmp_path / "dst").exists()


def test_copytree_rejects_a_fifo(tmp_path):
    src = tree(tmp_path / "src")
    os.mkfifo(src / "pipe")
    with pytest.raises(dg.SymlinkRejected, match="not a regular file"):
        dg.safe_copytree(src, tmp_path / "dst")


def test_copytree_rejects_a_symlinked_source(tmp_path):
    src = tree(tmp_path / "src")
    os.symlink(src, tmp_path / "alias")
    with pytest.raises(dg.SymlinkRejected):
        dg.safe_copytree(tmp_path / "alias", tmp_path / "dst")


def test_copytree_refuses_over_the_disk_budget_before_writing(tmp_path):
    src = tree(tmp_path / "src")
    with pytest.raises(dg.DiskBudgetError, match="refused"):
        dg.safe_copytree(src, tmp_path / "dst", min_free_bytes=100, usage=usage(110))
    assert not (tmp_path / "dst").exists()
    dg.safe_copytree(src, tmp_path / "dst", min_free_bytes=100, usage=usage(125))   # exactly fits


def test_copytree_refuses_existing_destination_and_copy_into_itself(tmp_path):
    src = tree(tmp_path / "src")
    (tmp_path / "dst").mkdir()
    with pytest.raises(dg.DiskGuardError, match="exists"):
        dg.safe_copytree(src, tmp_path / "dst")
    with pytest.raises(dg.DiskGuardError, match="recurse"):
        dg.safe_copytree(src, src / "sub" / "copy")


def test_scan_tree_counts(tmp_path):
    assert dg.scan_tree(tree(tmp_path / "s")) == (2, 25)


# ------------------------------------------------------------------------------------------ eviction

def workdir(tmp_path):
    wd = tmp_path / "work"
    solved = wd / "7-peering-eyes"
    big(solved / "files" / "capture.pcapng", 60 * MiB)
    big(solved / "files" / "small.bin", 1 * MiB)
    big(solved / "solve.py", 60 * MiB)                    # a script: kept whatever its size
    big(solved / "writeup" / "figure.png", 60 * MiB)      # under writeup/: kept
    (solved / "flag.txt").write_text("FLAG{x}\n")
    os.symlink(solved / "files" / "capture.pcapng", solved / "files" / "link.pcapng")
    team = wd / "9-model-knows"
    big(team / "files" / "model.bin", 80 * MiB)
    open_ = wd / "12-unsolved"
    big(open_ / "files" / "disk.img", 500 * MiB)
    big(wd / "dispatch" / "huge.bin", 500 * MiB)          # not a challenge folder
    return wd


def test_eviction_plan_lists_only_large_non_writeup_files_of_accepted_challenges(tmp_path):
    wd = workdir(tmp_path)
    plan = dg.eviction_plan(wd, min_bytes=50 * MiB, solved={"9"})
    got = sorted((f.challenge, Path(f.path).name, f.why_accepted) for f in plan.files)
    assert got == [("7-peering-eyes", "capture.pcapng", "flag.txt"), ("9-model-knows", "model.bin", "team solve")]
    assert plan.kept == 2 and plan.bytes == 140 * MiB
    assert plan.challenges == ("7-peering-eyes", "9-model-knows")


def test_eviction_plan_reads_team_solves_from_the_ledger(tmp_path):
    wd = workdir(tmp_path)
    ledger.append("stop", workdir=wd, reason="team_solve", challenge_id="9")
    plan = dg.eviction_plan(wd, min_bytes=50 * MiB)
    assert "9-model-knows" in plan.challenges and "12-unsolved" not in plan.challenges


def test_eviction_plan_threshold(tmp_path):
    wd = workdir(tmp_path)
    plan = dg.eviction_plan(wd, min_bytes=1 * MiB, solved=set())
    assert sorted(Path(f.path).name for f in plan.files) == ["capture.pcapng", "small.bin"]
    with pytest.raises(dg.DiskGuardError):
        dg.eviction_plan(wd, min_bytes=0, solved=set())


def test_apply_eviction_deletes_records_and_keeps_the_rest(tmp_path):
    wd = workdir(tmp_path)
    plan = dg.eviction_plan(wd, min_bytes=50 * MiB, solved={"9"})
    res = dg.apply_eviction(plan, wd)
    assert sorted(r["action"] for r in res) == ["evicted", "evicted"]
    assert not (wd / "7-peering-eyes" / "files" / "capture.pcapng").exists()
    assert not (wd / "9-model-knows" / "files" / "model.bin").exists()
    for keep in ("solve.py", "writeup/figure.png", "flag.txt", "files/small.bin"):
        assert (wd / "7-peering-eyes" / keep).exists()
    assert (wd / "12-unsolved" / "files" / "disk.img").exists()
    assert (wd / "dispatch" / "huge.bin").exists()
    rec = json.loads((wd / "7-peering-eyes" / "evicted.json").read_text())
    assert rec[0]["path"] == "files/capture.pcapng" and rec[0]["size"] == 60 * MiB
    evs = [r for r in ledger.read(wd) if r["event"] == "governor.evict"]
    assert len(evs) == 2 and {e["action"] for e in evs} == {"evicted"}


def test_apply_eviction_skips_a_file_changed_since_the_plan(tmp_path):
    wd = workdir(tmp_path)
    plan = dg.eviction_plan(wd, min_bytes=50 * MiB, solved=set())
    target = wd / "7-peering-eyes" / "files" / "capture.pcapng"
    target.unlink()
    big(target, 70 * MiB)                                  # replaced: new inode and size
    res = dg.apply_eviction(plan, wd, ledger=False)
    assert res[0]["action"] == "skipped" and "changed" in res[0]["reason"]
    assert target.exists()


def test_apply_eviction_skips_a_file_swapped_for_a_symlink(tmp_path):
    wd = workdir(tmp_path)
    plan = dg.eviction_plan(wd, min_bytes=50 * MiB, solved=set())
    target = wd / "7-peering-eyes" / "files" / "capture.pcapng"
    outside = big(tmp_path / "precious.bin", 60 * MiB)
    target.unlink()
    os.symlink(outside, target)
    res = dg.apply_eviction(plan, wd, ledger=False)
    assert res[0]["action"] == "skipped" and outside.exists()


# ------------------------------------------------------------------------------------------ spotlight

def test_spotlight_status_and_exclusion(tmp_path):
    wt = tmp_path / "worktrees" / "wt1"
    wt.mkdir(parents=True)
    assert dg.spotlight_status(wt).excluded is False
    st = dg.exclude_from_spotlight(tmp_path / "worktrees")
    assert (tmp_path / "worktrees" / dg.NEVER_INDEX).is_file()
    assert dg.spotlight_status(wt) == st and st.how == "marker" and st.excluded
    ni = tmp_path / "trees.noindex" / "wt2"
    ni.mkdir(parents=True)
    assert dg.spotlight_status(ni).how == "noindex-folder"


def test_exclude_from_spotlight_needs_a_folder(tmp_path):
    with pytest.raises(dg.DiskGuardError):
        dg.exclude_from_spotlight(tmp_path / "missing")


# ------------------------------------------------------------------------------------------ CLI

def parse(*argv):
    ap = argparse.ArgumentParser()
    cli.add_arguments(ap)
    return ap.parse_args(list(argv))


def test_cli_evict_dry_run_then_apply(tmp_path, capsys):
    wd = workdir(tmp_path)
    (wd / "9-model-knows" / "flag.txt").write_text("x")
    assert cli.run(parse("evict", "--workdir", str(wd), "--json")) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["applied"] is False and len(out["files"]) == 2
    assert (wd / "9-model-knows" / "files" / "model.bin").exists()
    assert cli.run(parse("evict", "--workdir", str(wd), "--apply")) == 0
    assert not (wd / "9-model-knows" / "files" / "model.bin").exists()
    assert "evicted" in capsys.readouterr().out


def test_cli_evict_min_mb_from_env(tmp_path, monkeypatch, capsys):
    wd = workdir(tmp_path)
    monkeypatch.setenv("CTF_GOVERNOR_EVICT_MIN_MB", "100")
    assert cli.run(parse("evict", "--workdir", str(wd), "--json")) == 0
    assert json.loads(capsys.readouterr().out)["files"] == []
    monkeypatch.setenv("CTF_GOVERNOR_EVICT_MIN_MB", "many")
    assert cli.run(parse("evict", "--workdir", str(wd))) == 2


def test_cli_disk_and_copy(tmp_path, capsys):
    assert cli.run(parse("disk", "--need", "1", "--path", str(tmp_path), "--min-free", "0")) == 0
    assert cli.run(parse("disk", "--need", "4096T", "--path", str(tmp_path), "--min-free", "0")) == 1
    src = tree(tmp_path / "src")
    os.symlink("..", src / "loop")
    assert cli.run(parse("copy", str(src), str(tmp_path / "dst"), "--min-free", "0")) == 1
    assert "symlink" in capsys.readouterr().err
    (src / "loop").unlink()
    assert cli.run(parse("copy", str(src), str(tmp_path / "dst"), "--min-free", "0")) == 0


def test_cli_spotlight(tmp_path):
    assert cli.run(parse("spotlight", str(tmp_path))) == 1
    assert cli.run(parse("spotlight", str(tmp_path), "--apply")) == 0
    assert cli.run(parse("spotlight", str(tmp_path))) == 0


def test_apply_eviction_skips_a_file_already_gone_and_appends_records(tmp_path):
    wd = workdir(tmp_path)
    (wd / "7-peering-eyes" / "evicted.json").write_text(json.dumps([{"path": "earlier.bin"}]))
    plan = dg.eviction_plan(wd, min_bytes=50 * MiB, solved={"9"})
    (wd / "9-model-knows" / "files" / "model.bin").unlink()
    res = {r["challenge"]: r for r in dg.apply_eviction(plan, wd, ledger=False)}
    assert res["9-model-knows"]["action"] == "skipped" and "gone" in res["9-model-knows"]["reason"]
    assert res["7-peering-eyes"]["action"] == "evicted"
    rec = json.loads((wd / "7-peering-eyes" / "evicted.json").read_text())
    assert [r["path"] for r in rec] == ["earlier.bin", "files/capture.pcapng"]
    assert not (wd / "9-model-knows" / "evicted.json").exists()


# ----------------------------------------- verification round 1: the eviction guards, each with a test

def test_eviction_plan_skips_a_symlinked_challenge_folder(tmp_path):
    wd = workdir(tmp_path)
    outside = tmp_path / "outside"
    big(outside / "precious.bin", 60 * MiB)
    (outside / "flag.txt").write_text("FLAG{x}\n")
    os.symlink(outside, wd / "20-linked")
    plan = dg.eviction_plan(wd, min_bytes=50 * MiB, solved={"20"})
    assert "20-linked" not in plan.challenges
    assert all(Path(f.path).name != "precious.bin" for f in plan.files)
    dg.apply_eviction(plan, wd, ledger=False)
    assert (outside / "precious.bin").exists()


def test_eviction_plan_ignores_a_symlinked_flag_txt(tmp_path):
    wd = workdir(tmp_path)
    real_flag = tmp_path / "elsewhere" / "flag.txt"
    real_flag.parent.mkdir()
    real_flag.write_text("FLAG{y}\n")
    chal = wd / "21-fake-flag"
    big(chal / "files" / "dump.bin", 60 * MiB)
    os.symlink(real_flag, chal / "flag.txt")
    plan = dg.eviction_plan(wd, min_bytes=50 * MiB, solved=set())
    assert "21-fake-flag" not in plan.challenges
    assert all(f.challenge != "21-fake-flag" for f in plan.files)


def test_apply_eviction_skips_when_a_parent_folder_is_swapped_for_a_symlink_out(tmp_path):
    wd = workdir(tmp_path)
    plan = dg.eviction_plan(wd, min_bytes=50 * MiB, solved=set())
    files = wd / "7-peering-eyes" / "files"
    moved = tmp_path / "outside-files"
    os.rename(files, moved)                                # same inode, size and mtime for capture.pcapng
    os.symlink(moved, files)
    res = dg.apply_eviction(plan, wd, ledger=False)
    assert res[0]["action"] == "skipped" and "no longer inside" in res[0]["reason"]
    assert (moved / "capture.pcapng").exists()


def test_apply_eviction_skips_a_same_size_in_place_rewrite(tmp_path):
    wd = workdir(tmp_path)
    plan = dg.eviction_plan(wd, min_bytes=50 * MiB, solved=set())
    target = wd / "7-peering-eyes" / "files" / "capture.pcapng"
    before = os.stat(target)
    with open(target, "r+b") as fh:                        # rewritten in place: same inode, same size
        fh.write(b"new capture")
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns + 5_000_000_000))
    after = os.stat(target)
    assert (after.st_ino, after.st_size) == (before.st_ino, before.st_size)
    res = dg.apply_eviction(plan, wd, ledger=False)
    assert res[0]["action"] == "skipped" and "changed" in res[0]["reason"]
    assert target.exists()
