"""R-05: no file in the repo hardcodes a home folder or a source-repo path.

The tree check fails on any tracked (or untracked, not ignored) file holding /Users/<name>/ or a
home-relative 2026 source-repo path (~/2026-ctf-<event>), outside docs/migration/ and the listed
allowances (ctf/paths.py's documented realdata default; CLAUDE.md / AGENTS.md naming the read-only
source repos). Code and tests resolve the workdir and corpora through ctf.paths instead:
realdata_root() ($CTF_REALDATA) for the real-data corpus, saved_challenges_root() ($CTF_REAL_CHALLENGES)
for the saved past-event attempts. The scanner itself (ctf/testing/home_paths.py) is tested here on
synthetic text and a synthetic git repository; every home path below is made up.
"""
from __future__ import annotations

import importlib.util
import re
import subprocess
from pathlib import Path

import pytest

from ctf import env, paths
from ctf.testing import home_paths as hp

REPO = paths.repo_root()


# ---- the tree --------------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def tree_hits():
    return hp.scan_repo(REPO)


@pytest.mark.needs_tool("git")
def test_tree_has_no_hardcoded_home_or_source_paths(tree_hits):
    bad = hp.violations(tree_hits)
    assert not bad, ("hardcoded home / source-repo paths (resolve them through ctf.paths and ctf.env):\n  "
                     + "\n  ".join(str(h) for h in bad))


@pytest.mark.needs_tool("git")
def test_every_allowance_still_matches(tree_hits):
    stale = hp.stale_allowances(tree_hits)
    assert not stale, f"stale allowances (remove them from ctf/testing/home_paths.py): {stale}"


@pytest.mark.needs_tool("git")
def test_tree_scan_sees_the_allowed_default(tree_hits):
    # The scan really read ctf/paths.py (not an empty file list): its documented default is a hit.
    allowed = [h for h in tree_hits if h.allowance is not None]
    assert any(h.path == "ctf/paths.py" and h.kind == "source" for h in allowed), allowed


def test_playbooks_run_from_the_master_checkout():
    books = sorted((REPO / "docs" / "playbooks").glob("*.md"))
    assert len(books) >= 10, books
    for b in books:
        text = b.read_text(encoding="utf-8")
        # no fixed workdir and no interpreter from another checkout: the master's own venv, relative
        assert "CTF_WORKDIR=/" not in text, f"{b.name} pins CTF_WORKDIR to a fixed folder"
        for line in text.splitlines():
            for tok in line.replace("`", " ").replace("=", " ").split():
                if tok.endswith("/.venv/bin/python"):
                    assert tok == ".venv/bin/python" or tok.startswith("$PWD"), (b.name, line)


# ---- the scanner on synthetic text ----------------------------------------------------------------

def kinds(text, path="x/y.py", allowances=()):
    return [(h.kind, h.match, h.allowance is not None) for h in hp.scan_text(path, text, allowances)]


@pytest.mark.parametrize("text,expected", [
    ("p = '/Users/bob/projects/x'", [("home", "/Users/bob", False)]),
    ('HOME=/Users/alice\n', [("home", "/Users/alice", False)]),
    ("cd /Users/alice.smith/work", [("home", "/Users/alice.smith", False)]),
    ("see ~/2026-ctf-pink/tools/a.py", [("source", "~/2026-ctf-", False)]),
    ("cp $HOME/2026-ctf-csctf/x .", [("source", "$HOME/2026-ctf-", False)]),
    ("cp ${HOME}/2026-ctf-csctf/x .", [("source", "${HOME}/2026-ctf-", False)]),
    ("cd /Users/bob/2026-ctf-huntress", [("home", "/Users/bob", False)]),
    ("a ~/2026-ctf-a b ~/2026-ctf-b", [("source", "~/2026-ctf-", False)] * 2),
    # a name followed by a separator or prose punctuation is still a home folder
    ("PYTHONPATH=/Users/bob:/usr/lib", [("home", "/Users/bob", False)]),
    ("(see /Users/bob)", [("home", "/Users/bob", False)]),
    ("[/Users/bob, 1]", [("home", "/Users/bob", False)]),
    ("cd /Users/bob; ls", [("home", "/Users/bob", False)]),
    ("x = ['/Users/bob']", [("home", "/Users/bob", False)]),
    ("{/Users/bob}", [("home", "/Users/bob", False)]),
    ("folded onto /Users/x) and /var", [("home", "/Users/x", False)]),
    ("/System/Volumes/Data/Users/eve/x", [("home", "/Users/eve", False)]),
    # the Python spelling of a home-relative source repo
    ('SRC = Path.home() / "2026-ctf-csctf"', [("source", 'Path.home() / "2026-ctf-', False)]),
    ("SRC = HOME/'2026-ctf-pink'", [("source", "HOME/'2026-ctf-", False)]),
])
def test_scanner_finds(text, expected):
    assert kinds(text) == expected


@pytest.mark.parametrize("text", [
    "drop = '/Users/Shared/.cache/loader'",           # the macOS shared folder, not a home
    "file_path=C:/Users/Public/x.txt",                # the Windows public folder
    "a home is /Users/<name>/ in prose",              # a placeholder
    "firmlink /System/Volumes/Data/Users/...`",       # a placeholder
    "C:/Users/Public, /Users/Shared;",                # system folders before punctuation
    "SOURCE_NAMES = {'pink': '2026-ctf-pink'}",       # a folder name, not a home path
    "MY_HOME / '2026-ctf-x'",                         # HOME only as a whole word
    "startswith('/Users/')",                          # no name
    "/Users/$USER/x",                                 # not a literal name
    "from the 2026-ctf-huntress repo",                # a repo name, not a path
    "~/ctf-work/csctf and ~/Downloads/x",             # other home paths are not this check's business
])
def test_scanner_allows(text):
    assert kinds(text) == []


def test_line_numbers_and_text():
    hits = hp.scan_text("a.md", "ok\nok\nuse /Users/bob/x here\n")
    assert [(h.path, h.line, h.text) for h in hits] == [("a.md", 3, "use /Users/bob/x here")]
    assert "a.md:3" in str(hits[0]) and "home" in str(hits[0])


def test_allowance_covers_only_its_exact_text_in_its_file():
    allow = (hp.Allowance("ctf/p.py", "~/2026-ctf-x/data", "test"),)
    text = 'D = "~/2026-ctf-x/data"   # also ~/2026-ctf-y\n'
    got = kinds(text, "ctf/p.py", allow)
    assert got == [("source", "~/2026-ctf-", True), ("source", "~/2026-ctf-", False)]
    # the same text in another file is not allowed
    assert kinds(text, "ctf/q.py", allow) == [("source", "~/2026-ctf-", False)] * 2
    # a hit on another line of the allowed file is not allowed
    assert kinds('ok\nx = "~/2026-ctf-x/other"\n', "ctf/p.py", allow) == [("source", "~/2026-ctf-", False)]


def test_stale_allowance_detected():
    used = hp.Allowance("a", "~/2026-ctf-a", "used")
    unused = hp.Allowance("b", "~/2026-ctf-b", "unused")
    hits = hp.scan_text("a", "~/2026-ctf-a\n", (used, unused))
    assert hp.violations(hits) == []
    assert hp.stale_allowances(hits, (used, unused)) == [unused]


def test_default_allowances_are_exactly_the_documented_ones():
    assert {(a.path, a.text) for a in hp.ALLOWANCES} == {
        ("ctf/paths.py", "~/2026-ctf-huntress/challenges/_realdata"),
        ("tests/test_contracts_env_paths.py", 'Path.home() / "2026-ctf-huntress/challenges/_realdata"'),
        ("CLAUDE.md", "`~/2026-ctf-*`"),
        ("AGENTS.md", "`~/2026-ctf-*`"),
    }
    assert all(a.reason for a in hp.ALLOWANCES)


@pytest.mark.parametrize("path,exempt", [
    ("docs/migration/IMPORT-REPORT.md", True),
    ("docs/migration/sub/x.json", True),
    ("docs/migrations.md", False),
    ("docs/build-log/R-05.md", False),
    ("ctf/testing/home_paths.py", True),
    ("tests/test_no_home_paths.py", True),
    ("tests/test_other.py", False),
    ("ctf/paths.py", False),
])
def test_exempt(path, exempt):
    assert hp.exempt(path) is exempt


# ---- the scanner on a synthetic git repository ----------------------------------------------------

def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


@pytest.fixture
def fake_repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    (root / ".gitignore").write_text("ignored.txt\n")
    (root / "ctf").mkdir()
    (root / "ctf" / "tracked.py").write_text("ROOT = '/Users/bob/2026-ctf-huntress/challenges'\n")
    (root / "notes.md").write_text("from ~/2026-ctf-pink/tools\n")                      # untracked, not ignored
    (root / "ignored.txt").write_text("/Users/bob/x\n")                                   # ignored
    (root / "docs" / "migration").mkdir(parents=True)
    (root / "docs" / "migration" / "REPORT.md").write_text("copied from ~/2026-ctf-csctf/x\n")
    (root / "blob.bin").write_bytes(b"\x00\x01\xff/Users/carol/lib/x.dylib\x00\x02")    # binary
    (root / "link").symlink_to("/Users/dave/secret")                                      # never followed
    (root / "clean.py").write_text("print('fine')\n")
    _git(root, "add", ".gitignore", "ctf/tracked.py", "docs/migration/REPORT.md", "blob.bin", "link", "clean.py")
    return root


@pytest.mark.needs_tool("git")
def test_scan_repo_on_synthetic_repo(fake_repo):
    hits = hp.scan_repo(fake_repo, allowances=())
    found = sorted((h.path, h.kind, h.match) for h in hits)
    assert found == [
        ("blob.bin", "home", "/Users/carol"),
        ("ctf/tracked.py", "home", "/Users/bob"),
        ("link", "home", "/Users/dave"),
        ("notes.md", "source", "~/2026-ctf-"),
    ]


@pytest.mark.needs_tool("git")
def test_repo_files_lists_tracked_and_untracked_not_ignored(fake_repo):
    files = hp.repo_files(fake_repo)
    assert "ctf/tracked.py" in files and "notes.md" in files and "link" in files
    assert "ignored.txt" not in files


@pytest.mark.needs_tool("git")
def test_deleted_tracked_file_is_skipped(fake_repo):
    (fake_repo / "ctf" / "tracked.py").unlink()
    assert "ctf/tracked.py" in hp.repo_files(fake_repo)
    assert all(h.path != "ctf/tracked.py" for h in hp.scan_repo(fake_repo, allowances=()))


@pytest.mark.needs_tool("git")
def test_repo_files_fails_loudly_outside_git(tmp_path):
    with pytest.raises(RuntimeError, match="git ls-files failed"):
        hp.repo_files(tmp_path)


@pytest.mark.needs_tool("git")
@pytest.mark.parametrize("var", ["GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE"])
def test_repo_files_ignores_inherited_git_env(fake_repo, tmp_path, monkeypatch, var):
    """A hook's GIT_DIR / GIT_INDEX_FILE / GIT_WORK_TREE must not point the scan at another repository."""
    other = tmp_path / "other"
    other.mkdir()
    _git(other, "init", "-q")
    (other / "foreign.txt").write_text("x\n")
    # deleted from the work tree: only fake_repo's own index still lists it (--others cannot)
    (fake_repo / "ctf" / "tracked.py").unlink()
    expected = hp.repo_files(fake_repo)
    assert "ctf/tracked.py" in expected and "notes.md" in expected
    monkeypatch.setenv(var, str({"GIT_DIR": other / ".git", "GIT_INDEX_FILE": other / ".git" / "index",
                                 "GIT_WORK_TREE": other}[var]))
    assert hp.repo_files(fake_repo) == expected


@pytest.mark.needs_tool("git")
def test_cli_exit_codes(fake_repo, monkeypatch, capsys):
    monkeypatch.setattr(paths, "repo_root", lambda: fake_repo)
    monkeypatch.setattr(hp, "ALLOWANCES", ())
    assert hp.main([]) == 1
    out = capsys.readouterr()
    assert "ctf/tracked.py:1: home path" in out.out and "4 hardcoded" in out.err
    for rel in ("ctf/tracked.py", "notes.md", "blob.bin", "link"):
        (fake_repo / rel).unlink()
    assert hp.main([]) == 0
    assert "no hardcoded home or source-repo paths" in capsys.readouterr().out


@pytest.mark.needs_tool("git")
def test_cli_reports_stale_allowance(fake_repo, monkeypatch, capsys):
    for rel in ("ctf/tracked.py", "notes.md", "blob.bin", "link"):
        (fake_repo / rel).unlink()
    monkeypatch.setattr(paths, "repo_root", lambda: fake_repo)
    monkeypatch.setattr(hp, "ALLOWANCES", (hp.Allowance("clean.py", "~/2026-ctf-z", "gone"),))
    assert hp.main([]) == 1
    assert "stale allowance: clean.py" in capsys.readouterr().out


# ---- ctf.paths.saved_challenges_root ---------------------------------------------------------------

def test_saved_challenges_root_unset_is_none(monkeypatch):
    for name in ("CTF_REAL_CHALLENGES", *env.legacy_names("CTF_REAL_CHALLENGES")):
        monkeypatch.delenv(name, raising=False)
    assert paths.saved_challenges_root() is None


def test_saved_challenges_root_set(monkeypatch, tmp_path):
    d = tmp_path / "challenges"
    d.mkdir()
    monkeypatch.setenv("CTF_REAL_CHALLENGES", str(d))
    assert paths.saved_challenges_root() == d.resolve()


def test_saved_challenges_root_set_but_missing_fails_loudly(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_REAL_CHALLENGES", str(tmp_path / "nope"))
    with pytest.raises(FileNotFoundError, match="CTF_REAL_CHALLENGES"):
        paths.saved_challenges_root()


def test_saved_challenges_root_never_derived_from_realdata(monkeypatch, tmp_path):
    (tmp_path / "_realdata").mkdir()
    (tmp_path / "day-01").mkdir()
    monkeypatch.setenv("CTF_REALDATA", str(tmp_path / "_realdata"))
    for name in ("CTF_REAL_CHALLENGES", *env.legacy_names("CTF_REAL_CHALLENGES")):
        monkeypatch.delenv(name, raising=False)
    assert paths.saved_challenges_root() is None


def test_carried_scripts_use_the_resolver():
    """The carried check scripts with a saved-attempts section resolve it through ctf.paths only."""
    scripts = ["tests/test_day28_warmups.py", "tests/test_warmups_esolang_sweep.py",
               "tests/test_wave122_esolang3.py", "tests/test_wave15_esolang2.py",
               "tests/test_wave4_esolang.py", "solvers/script-analysis/test_wavec2_deflate.py",
               "tests/test_day24_binary_config_guard.py", "tests/test_day27_record_select_binary.py",
               "tests/test_day27_split_fold_mobile.py", "tests/test_day27_native_image_mobile.py"]
    for rel in scripts:
        text = (REPO / rel).read_text(encoding="utf-8")
        assert "paths.saved_challenges_root()" in text, rel
        assert not DIRECT_READ.search(text), rel
        assert "realdata_root().parent" not in text, rel


# Reading the variable straight from the environment skips ctf.env's legacy names and the loud
# set-but-missing error, so a typo would read as "no saved attempts".
DIRECT_READ = re.compile(r"""(?:environ(?:\.get)?\s*[\[(]|getenv\s*\()\s*["']CTF_REAL_CHALLENGES["']""")


@pytest.mark.parametrize("text,direct", [
    ('Path(os.environ["CTF_REAL_CHALLENGES"])', True),
    ("os.environ.get('CTF_REAL_CHALLENGES')", True),
    ('os.getenv("CTF_REAL_CHALLENGES")', True),
    ('monkeypatch.setenv("CTF_REAL_CHALLENGES", str(d))', False),
    ('env["CTF_REAL_CHALLENGES"] = str(saved)', False),
])
def test_direct_read_pattern(text, direct):
    assert bool(DIRECT_READ.search(text)) is direct


@pytest.mark.needs_tool("git")
def test_no_code_reads_saved_challenges_from_the_environment():
    offenders = []
    for rel in hp.repo_files(REPO):
        if rel.endswith(".py") and rel != "tests/test_no_home_paths.py":
            text = hp.read_for_scan(REPO, rel)
            if text and DIRECT_READ.search(text):
                offenders.append(rel)
    assert not offenders, f"read CTF_REAL_CHALLENGES through ctf.paths.saved_challenges_root(): {offenders}"


# ---- tools/migrate/import_master.py: the source repos' parent folder is a flag ---------------------

def _import_master():
    spec = importlib.util.spec_from_file_location("import_master_r05", REPO / "tools/migrate/import_master.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_import_master_source_roots(tmp_path):
    im = _import_master()
    assert im.source_roots(tmp_path) == {e: tmp_path / f"2026-ctf-{e}" for e in ("csctf", "huntress", "pink", "spooky")}
    assert im.SOURCES == im.source_roots(Path.home())     # the documented default


def test_import_master_sources_dir_flag(tmp_path, capsys):
    im = _import_master()
    with pytest.raises(SystemExit) as e:
        im.main(["--dry-run", "--sources-dir", str(tmp_path)])
    assert e.value.code == 2
    assert f"source csctf missing at {tmp_path / '2026-ctf-csctf'}" in capsys.readouterr().err
    assert im.SOURCES["pink"] == tmp_path / "2026-ctf-pink"
