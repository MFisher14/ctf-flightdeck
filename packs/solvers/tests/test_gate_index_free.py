"""B-137: a FULL run lists the tree without reading the git index, so what is staged -- a deletion, an
add, a `git rm --cached` -- cannot change which files it runs. On Oct 9 an "unstaged deletion" was one
of five false reds; a full run must see exactly the files on disk, not the index's idea of them."""
from __future__ import annotations

import argparse

import pytest

from ctf.cli import gate
from ctf.gate import config
from ctf.gate.impact import Graph, list_files, list_files_fs
from gate_repo import git, make_repo, write

FILES = {
    "lib/val.txt": "7\n",
    "tests/test_a.py": "def test_a():\n    assert True\n",
    "tests/test_b.py": "def test_b():\n    assert True\n",
}


@pytest.fixture
def repo(tmp_path):
    return make_repo(tmp_path / "repo", FILES)


def test_fs_listing_ignores_gitignored_and_matches_the_index_on_a_clean_tree(repo):
    write(repo, {".gitignore": "build/\n*.pyc\n", "build/junk.txt": "x\n", "tests/test_a.pyc": "x\n"})
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "ignore")
    fs = set(list_files_fs(repo))
    assert "tests/test_a.py" in fs and "tests/test_b.py" in fs
    assert "build/junk.txt" not in fs and "tests/test_a.pyc" not in fs     # gitignored, dropped
    assert fs == set(list_files(repo))                                     # same answer on a clean tree


def test_fs_listing_is_invariant_under_a_staged_deletion(repo):
    before = set(list_files_fs(repo))
    git(repo, "rm", "--cached", "-q", "tests/test_b.py")   # removed from the index, still on disk
    assert set(list_files_fs(repo)) == before             # the index change does not move the listing
    # the index-based listing, by contrast, now reports it as untracked-but-present (still there), while
    # a staged *content* change would not perturb either -- the point is the FS listing never consults
    # staging at all.


def test_fs_listing_drops_a_file_deleted_from_disk_even_if_still_in_the_index(repo):
    (repo / "tests" / "test_b.py").unlink()               # unstaged deletion: gone from disk, still in index
    fs = set(list_files_fs(repo))
    assert "tests/test_b.py" not in fs and "tests/test_a.py" in fs


def _graph(repo, state, *, use_index):
    return Graph(repo, config.load(repo, repo / "gate.toml"), state / "co", use_index=use_index)


def test_full_run_graph_sees_a_new_on_disk_test_without_an_index_add(repo, tmp_path):
    write(repo, {"tests/test_c.py": "def test_c():\n    assert True\n"})     # on disk, never `git add`ed
    g = _graph(repo, tmp_path / "s", use_index=False)
    assert "tests/test_c.py" in g.tests


def _cli(repo, state, *argv):
    p = argparse.ArgumentParser()
    gate.add_arguments(p)
    args = p.parse_args(["--root", str(repo), "--config", str(repo / "gate.toml"),
                         "--state", str(state)] + list(argv))
    return gate.run(args)


def _planned(capsys):
    out = capsys.readouterr().out
    return {ln.split()[1] for ln in out.splitlines() if ln.startswith(("RUN ", "WARM"))}


def test_list_files_full_and_index_diverge_on_a_tracked_but_gitignored_file(repo):
    """The point of use_index=False is that a full run does NOT consult the index. The one scenario
    where the index-based and filesystem listings MUST differ is a file that is tracked in the index
    AND matched by a .gitignore rule: `git ls-files --cached` keeps it (a tracked file overrides the
    ignore rule), while the filesystem walk drops it (it is ignored, judged with check-ignore
    --no-index). The staged-deletion / rm --cached scenarios above leave both listings identical -- a
    rm --cached file is re-listed as untracked and still on disk -- so they cannot catch a swap of the
    use_index branch. This case does: under `if use_index:` (the swapped branch) list_files(use_index=
    True) would return the filesystem listing and drop the file, and list_files(use_index=False) would
    read the index and keep it, so each assertion below flips and fails."""
    write(repo, {".gitignore": "secret.txt\n", "secret.txt": "x\n"})
    git(repo, "add", ".gitignore")
    git(repo, "add", "-f", "secret.txt")                    # force-track a file the ignore rule covers
    git(repo, "commit", "-q", "-m", "tracked-but-ignored")
    index = set(list_files(repo, use_index=True))
    full = set(list_files(repo, use_index=False))
    assert "secret.txt" in index                            # the index lists a tracked file even when ignored
    assert "secret.txt" not in full                         # the filesystem walk drops anything ignored
    assert index - full == {"secret.txt"}                   # that file is the sole difference


def test_full_plan_drops_a_tracked_but_gitignored_test_file_the_index_keeps(repo, tmp_path, capsys):
    """End to end through `ctf gate plan --full`: a test file that is tracked but matched by a .gitignore
    rule is absent from the full plan, because the full run lists the tree off the filesystem and never
    reads the index -- while an index-based listing (an impact run's view) still carries it. Swapping the
    use_index branch would pull the ignored file into the full plan, so this fails on the swapped code
    too (the companion to the unit test above, through the headline CLI path)."""
    write(repo, {".gitignore": "tests/test_hidden.py\n",
                 "tests/test_hidden.py": "def test_hidden():\n    assert True\n"})
    git(repo, "add", ".gitignore")
    git(repo, "add", "-f", "tests/test_hidden.py")          # force-track an ignored test file
    git(repo, "commit", "-q", "-m", "ignored test file")
    _cli(repo, tmp_path / "s", "plan", "--full")
    assert "tests/test_hidden.py" not in _planned(capsys)   # the full plan lists the FS, not the index
    assert "tests/test_hidden.py" in set(list_files(repo, use_index=True))   # the index still carries it


def test_cli_full_plan_is_the_same_with_or_without_a_staged_deletion(repo, tmp_path, capsys):
    _cli(repo, tmp_path / "s1", "plan", "--full")
    clean = _planned(capsys)
    assert clean == {"tests/test_a.py", "tests/test_b.py"}
    git(repo, "rm", "--cached", "-q", "tests/test_b.py")        # stage a deletion
    git(repo, "add", "lib/val.txt")                            # and stage an unrelated change
    _cli(repo, tmp_path / "s2", "plan", "--full")
    assert _planned(capsys) == clean                           # staging did not change the full selection
