"""R-14: one install source for the Python dependencies.

requirements.in is the file people edit; requirements.txt is generated from it with every pin
(tools/requirements_gen.py) and is the only thing setup.sh installs; the lock never contradicts a pin.
The real tree is checked first, then each rule of the generator and of the setup.sh reader is pinned on
synthetic text, so a regression in either fails here rather than at the next setup.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import requirements_gen as rg

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "requirements_gen.py"


def _pins(path: Path) -> dict:
    return {p.key: p.version for p in rg.parse_pins(path.read_text(), path.name)}


# ------------------------------------------------------------------------------------------- the real tree
def test_setup_installs_exactly_requirements_txt_once():
    installs = rg.setup_installs((ROOT / "setup.sh").read_text())
    assert [f for i in installs for f in i.files] == ["requirements.txt"]
    assert [s for i in installs for s in i.specs] == [], "setup.sh installs a package outside the lock-step file"
    assert rg.setup_problems((ROOT / "setup.sh").read_text()) == []


def test_what_setup_installs_pins_exactly_requirements_in():
    """Every pin in requirements.in, at its version, and nothing else, is in what setup.sh installs."""
    want = _pins(ROOT / "requirements.in")
    for inst in rg.setup_installs((ROOT / "setup.sh").read_text()):
        for rel in inst.files:
            assert _pins(ROOT / rel) == want, f"setup.sh installs {rel}, whose pins differ from requirements.in"


@pytest.mark.parametrize("dist,ver", [("capstone", "5.0.9"), ("cryptography", "50.0.2"),
                                      ("pycryptodomex", "3.23.0"), ("unicorn", "2.1.4")])
def test_the_r14_pins_reach_setup(dist, ver):
    """The four pins Phase 0 found missing from what setup.sh installed."""
    files = [f for i in rg.setup_installs((ROOT / "setup.sh").read_text()) for f in i.files]
    assert files
    for rel in files:
        assert _pins(ROOT / rel).get(dist) == ver, f"{rel} lacks {dist}=={ver}"


def test_generated_file_is_current():
    assert (ROOT / "requirements.txt").read_text() == rg.render((ROOT / "requirements.in").read_text()), \
        "requirements.txt is stale: run .venv/bin/python tools/requirements_gen.py"


def test_lock_never_contradicts_a_pin():
    locked = rg.read_lock((ROOT / "requirements.lock.txt").read_text())
    clash = {p.name: (p.version, locked[p.key]) for p in rg.parse_pins((ROOT / "requirements.in").read_text())
             if p.key in locked and locked[p.key] != p.version}
    assert clash == {}


def test_check_passes_on_this_tree():
    r = subprocess.run([sys.executable, "-I", str(TOOL), "--check"], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert r.stderr == ""


# -------------------------------------------------------------------------------- requirements.in, strictly
GOOD_IN = """\
# header comment, dropped
# --- section one ---
alpha==1.0
Beta_Pkg==2.3.post1  # trailing comment
# a note, dropped

# --- section two ---
gamma.ns==0.1
"""


def test_parse_pins_reads_every_pin_with_line_numbers():
    pins = rg.parse_pins(GOOD_IN)
    assert [(p.name, p.version, p.lineno) for p in pins] == [
        ("alpha", "1.0", 3), ("Beta_Pkg", "2.3.post1", 4), ("gamma.ns", "0.1", 8)]
    assert [p.key for p in pins] == ["alpha", "beta-pkg", "gamma-ns"]


@pytest.mark.parametrize("line", [
    "alpha>=1.0", "alpha", "alpha~=1.0", "alpha==1.*", "alpha[extra]==1.0", "-r other.txt",
    "--index-url https://example.invalid/simple", "alpha @ https://example.invalid/a.whl", "./local/pkg",
    "alpha==1.0; sys_platform == 'darwin'", "-e .", "alpha==1.0 --hash=sha256:00",
])
def test_parse_pins_rejects_anything_but_an_exact_pin(line):
    with pytest.raises(rg.RequirementsError, match=r"requirements\.in:2: .* not an exact pin"):
        rg.parse_pins("ok==1\n" + line + "\n")


@pytest.mark.parametrize("second", ["alpha==1.0", "Alpha==1.0", "alpha==2.0", "ALPHA==1.0"])
def test_parse_pins_rejects_a_package_pinned_twice(second):
    """Even at the same version: the import kept protobuf/lz4/zstandard twice in requirements.txt."""
    with pytest.raises(rg.RequirementsError, match=r":3: .* pinned twice .*line 1"):
        rg.parse_pins("alpha==1.0\nother==1\n" + second + "\n")


def test_parse_pins_duplicate_check_uses_normalized_names():
    with pytest.raises(rg.RequirementsError, match="pinned twice"):
        rg.parse_pins("dissect.ntfs==3.16\ndissect-ntfs==3.16\n")
    assert len(rg.parse_pins("alpha==1\nalpha-two==1\nalph==1\n")) == 3


def test_canon_folds_case_and_separators():
    assert rg.canon("Dissect.NTFS") == rg.canon("dissect-ntfs") == rg.canon("dissect__ntfs") == "dissect-ntfs"


def test_render_keeps_every_pin_and_section_titles_only():
    out = rg.render(GOOD_IN)
    assert out.startswith(rg.HEADER)
    body = out[len(rg.HEADER):].splitlines()
    assert body == ["", "# --- section one ---", "alpha==1.0", "Beta_Pkg==2.3.post1",
                    "", "# --- section two ---", "gamma.ns==0.1"]
    assert {p.key: p.version for p in rg.parse_pins(out)} == {p.key: p.version for p in rg.parse_pins(GOOD_IN)}


def test_render_refuses_an_invalid_source():
    with pytest.raises(rg.RequirementsError):
        rg.render("alpha>=1\n")


def test_read_lock_ignores_non_pins():
    assert rg.read_lock("# c\n-e .\nalpha==1.0\nBeta.X==2  # c\nfoo>=1\n") == {"alpha": "1.0", "beta-x": "2"}


# ----------------------------------------------------------------------------------- what setup.sh installs
SETUP_OK = """\
#!/usr/bin/env bash
set -euo pipefail
# uv pip install -r requirements.in   (a comment: not a command)
uv venv -p 3.12 .venv
uv pip install -p .venv/bin/python -r requirements.txt
.venv/bin/python -m playwright install chromium || true
brew install ghidra jadx || true
echo "don't pip install here" >&2
"""


def test_setup_reader_finds_the_install_and_ignores_comments_and_other_installers():
    insts = rg.setup_installs(SETUP_OK)
    assert len(insts) == 1
    i = insts[0]
    assert (i.lineno, i.files, i.specs, i.constraints, i.guarded) == (5, ["requirements.txt"], [], [], False)
    assert rg.setup_problems(SETUP_OK) == []


@pytest.mark.parametrize("line,files,specs,constraints", [
    ("uv pip install -p .venv/bin/python flask-unsign opencv-python || true", [], ["flask-unsign", "opencv-python"], []),
    ("pip install --requirement=requirements.in", ["requirements.in"], [], []),
    ("pip3 install -rreqs.txt -c requirements.lock.txt", ["reqs.txt"], [], ["requirements.lock.txt"]),
    (".venv/bin/python -m pip install --index-url https://x.invalid/simple requests==1", [], ["requests==1"], []),
    ("uv pip install --python .venv/bin/python -e .", [], ["-e ."], []),
    ("cd x && uv pip install -p py --constraint=c.txt -r a.txt", ["a.txt"], [], ["c.txt"]),
])
def test_setup_reader_parses_install_arguments(line, files, specs, constraints):
    (i,) = rg.setup_installs(line + "\n")
    assert (i.files, i.specs, i.constraints) == (files, specs, constraints)


def test_setup_reader_joins_continuations_and_reports_the_first_line():
    text = "echo hi\nuv pip install \\\n  -p .venv/bin/python \\\n  -r requirements.txt \\\n  extra==1\n"
    (i,) = rg.setup_installs(text)
    assert (i.lineno, i.files, i.specs) == (2, ["requirements.txt"], ["extra==1"])


@pytest.mark.parametrize("script,needle", [
    ("uv pip install -p py -r requirements.txt\nuv pip install -p py flask-unsign opencv-python || true\n",
     "'opencv-python' outside requirements.txt"),
    ("uv pip install -p py -r requirements.in\n", "installs -r requirements.in"),
    ("uv pip install -p py -r requirements.txt || true\n", "followed by `||`"),
    ("uv pip install -p py -r requirements.txt -c requirements.lock.txt\n", "constraint file requirements.lock.txt"),
    ("uv pip install -p py -r requirements.txt\nuv pip install -p py -r requirements.txt\n", "2 times"),
    ("uv venv .venv\n", "no pip install command"),
    ("uv pip install -p py -r requirements.lock.txt\n", "requirements.txt 0 times"),
])
def test_setup_problems_name_each_way_out_of_the_one_source(script, needle):
    problems = rg.setup_problems(script)
    assert any(needle in p for p in problems), problems


@pytest.mark.parametrize("line,files,constraints,others", [
    ("uv pip install -p py --requirements requirements.lock.txt -r requirements.txt",
     ["requirements.lock.txt", "requirements.txt"], [], []),
    ("uv pip install -p py --requirements=requirements.lock.txt -r requirements.txt",
     ["requirements.lock.txt", "requirements.txt"], [], []),
    ("uv pip install -p py --constraints c.txt -r requirements.txt", ["requirements.txt"], ["c.txt"], []),
    ("uv pip install -p py --constraints=c.txt -r requirements.txt", ["requirements.txt"], ["c.txt"], []),
    ("uv pip install -p py --overrides o.txt -r requirements.txt", ["requirements.txt"], [], ["--overrides o.txt"]),
    ("uv pip install -p py --overrides=o.txt -r requirements.txt", ["requirements.txt"], [], ["--overrides o.txt"]),
    ("uv pip install -p py --override o.txt -r requirements.txt", ["requirements.txt"], [], ["--override o.txt"]),
    ("uv pip install -p py --excludes x.txt -r requirements.txt", ["requirements.txt"], [], ["--excludes x.txt"]),
    ("uv pip install -p py --group dev -r requirements.txt", ["requirements.txt"], [], ["--group dev"]),
])
def test_setup_reader_knows_uv_plural_and_other_source_options(line, files, constraints, others):
    """uv spells -r/-c as --requirements/--constraints; --overrides/--excludes/--group also pick packages."""
    (i,) = rg.setup_installs(line + "\n")
    assert (i.kind, i.files, i.constraints, i.others, i.specs) == ("install", files, constraints, others, [])


@pytest.mark.parametrize("line,needle", [
    ("uv pip install -p py --requirements=requirements.lock.txt -r requirements.txt",
     "installs -r requirements.lock.txt"),
    ("uv pip install -p py --requirements requirements.lock.txt -r requirements.txt",
     "installs -r requirements.lock.txt"),
    ("uv pip install -p py --constraints c.txt -r requirements.txt", "constraint file c.txt"),
    ("uv pip install -p py --constraints=c.txt -r requirements.txt", "constraint file c.txt"),
    ("uv pip install -p py --overrides o.txt -r requirements.txt", "uses --overrides o.txt, another install source"),
    ("uv pip install -p py --overrides=o.txt -r requirements.txt", "uses --overrides o.txt, another install source"),
    ("uv pip install -p py --group dev -r requirements.txt", "uses --group dev, another install source"),
])
def test_setup_problems_catch_uv_plural_and_override_sources(line, needle):
    problems = rg.setup_problems(line + "\n")
    assert any(needle in p for p in problems), problems


@pytest.mark.parametrize("line,kind,files", [
    ("uv pip sync -p .venv/bin/python requirements.lock.txt", "sync", ["requirements.lock.txt"]),
    ("uv pip sync --python=.venv/bin/python a.txt b.txt", "sync", ["a.txt", "b.txt"]),
    ("pip-sync requirements.lock.txt --python-executable .venv/bin/python", "sync", ["requirements.lock.txt"]),
    ("venv/bin/pip-sync r.txt", "sync", ["r.txt"]),
])
def test_setup_reader_treats_pip_sync_arguments_as_install_files(line, kind, files):
    (i,) = rg.setup_installs(line + "\n")
    assert (i.kind, i.files, i.specs) == (kind, files, [])


def test_setup_problems_catch_a_pip_sync_beside_the_install():
    script = SETUP_OK + "uv pip sync -p .venv/bin/python requirements.lock.txt\n"
    problems = rg.setup_problems(script)
    assert problems == ["setup.sh:9: syncs the venv to requirements.lock.txt; the one install source is "
                        "requirements.txt"], problems


def test_a_lone_sync_of_requirements_txt_is_the_one_source():
    assert rg.setup_problems("uv pip sync -p .venv/bin/python requirements.txt\n") == []
    assert any("2 times" in p for p in rg.setup_problems(
        "uv pip sync -p py requirements.txt\nuv pip install -p py -r requirements.txt\n"))


@pytest.mark.parametrize("line,files,specs,guarded", [
    ("uv pip install -p py -r requirements.txt||true", ["requirements.txt"], [], True),
    ("uv pip install -p py -r requirements.txt;echo done", ["requirements.txt"], [], False),
    ("(uv pip install -p py -r requirements.txt)", ["requirements.txt"], [], False),
    ("true&&uv pip install -p py extra==1|cat", [], ["extra==1"], False),
])
def test_setup_reader_splits_unspaced_shell_operators(line, files, specs, guarded):
    """`x||true` is one shell word only to a naive split; the reader must cut it at the operator."""
    (i,) = rg.setup_installs(line + "\n")
    assert (i.files, i.specs, i.guarded) == (files, specs, guarded)


@pytest.mark.parametrize("script,needle", [
    ("uv pip install -p py -r requirements.txt||true\n", "followed by `||`"),
    ("uv pip install -p py -r requirements.txt;uv pip install -p py extra==1\n", "'extra==1' outside requirements.txt"),
])
def test_setup_problems_see_through_unspaced_operators(script, needle):
    problems = rg.setup_problems(script)
    assert any(needle in p for p in problems), problems


@pytest.mark.parametrize("arg", ["-e ./x", "--editable ./x", "--editable=./x", "-e./x"])
def test_setup_reader_sees_every_spelling_of_an_editable_install(arg):
    """`-e`/`--editable`, spaced, with `=` and attached, are all a second install source."""
    (i,) = rg.setup_installs(f"uv pip install -p py -r requirements.txt {arg}\n")
    assert (i.files, i.specs, i.others) == (["requirements.txt"], ["-e ./x"], [])
    problems = rg.setup_problems(f"uv pip install -p py -r requirements.txt {arg}\n")
    assert problems == ["setup.sh:1: installs '-e ./x' outside requirements.txt; pin it in requirements.in "
                        "instead"], problems


def test_setup_reader_editable_with_no_target_fails_loudly():
    with pytest.raises(rg.RequirementsError, match=r"setup\.sh:1: --editable with no file"):
        rg.setup_installs("uv pip install -p py -r requirements.txt --editable\n")


@pytest.mark.parametrize("script,word,lineno", [
    ("UV_CONSTRAINT=requirements.lock.txt uv pip install -p py -r requirements.txt\n",
     "UV_CONSTRAINT=requirements.lock.txt", 1),
    ("PIP_CONSTRAINT=x.txt pip install -r requirements.txt\n", "PIP_CONSTRAINT=x.txt", 1),
    ("A=1 UV_OVERRIDE=o.txt uv pip install -p py -r requirements.txt\n", "UV_OVERRIDE=o.txt", 1),
    ("env PIP_REQUIREMENT=r.txt pip install -r requirements.txt\n", "PIP_REQUIREMENT=r.txt", 1),
    ("export PIP_EDITABLE=.\nuv pip install -p py -r requirements.txt\n", "PIP_EDITABLE=.", 1),
    ("export -n X=1 UV_CONSTRAINT=c.txt\nuv pip install -p py -r requirements.txt\n", "UV_CONSTRAINT=c.txt", 1),
    ("echo hi\nUV_CONSTRAINT=c.txt\nuv pip install -p py -r requirements.txt\n", "UV_CONSTRAINT=c.txt", 2),
    ("uv pip install -p py -r requirements.txt && declare -x PIP_CONSTRAINT=c.txt\n", "PIP_CONSTRAINT=c.txt", 1),
])
def test_setup_problems_catch_install_source_environment_variables(script, word, lineno):
    """A constraint or requirement file passed through the environment is a second install source."""
    assert rg.setup_env_sources(script) == [(lineno, word)]
    problems = rg.setup_problems(script)
    assert problems == [f"setup.sh:{lineno}: sets {word}, another install source; requirements.txt is the "
                        "one install source"], problems


@pytest.mark.parametrize("script", [
    "UV_BUILD_CONSTRAINT=b.txt uv pip install -p py -r requirements.txt\n",  # build envs only, like -b
    "PIP_NO_CACHE_DIR=1 uv pip install -p py -r requirements.txt\n",
    "echo UV_CONSTRAINT=c.txt\nuv pip install -p py -r requirements.txt\n",  # an argument, not an assignment
    "export PATH=$PATH:x\nuv pip install -p py -r requirements.txt\n",
])
def test_setup_env_scan_leaves_other_variables_and_arguments_alone(script):
    assert rg.setup_env_sources(script) == []
    assert rg.setup_problems(script) == []


@pytest.mark.parametrize("line", ['"$PIP" install foo', "$UV sync r.txt", '"${PIP}" install -r requirements.txt'])
def test_setup_problems_reject_an_installer_named_by_a_variable(line):
    script = "uv pip install -p py -r requirements.txt\n" + line + "\n"
    (hit,) = rg.setup_opaque_installs(script)
    assert hit[0] == 2
    problems = rg.setup_problems(script)
    assert len(problems) == 1 and problems[0].startswith("setup.sh:2: runs ") \
        and "installer named by a variable" in problems[0], problems


def test_opaque_installer_scan_skips_pip_reached_through_a_variable_path():
    """`"$VENV/bin/pip" install` is pip by name; the normal reader handles it, not the opaque scan."""
    script = '"$VENV/bin/pip" install -r requirements.txt\necho "$X" installed\n'
    assert rg.setup_opaque_installs(script) == []
    assert rg.setup_problems(script) == []


def test_setup_reader_fails_loudly_on_unparseable_shell():
    with pytest.raises(rg.RequirementsError, match=r"setup\.sh:2: cannot parse"):
        rg.setup_installs("echo ok\necho 'unterminated\n")


# --------------------------------------------------------------------------------- check / main on a temp tree
def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "requirements.in").write_text(GOOD_IN)
    (root / "requirements.txt").write_text(rg.render(GOOD_IN))
    (root / "requirements.lock.txt").write_text("alpha==1.0\nbeta-pkg==2.3.post1\nunrelated==9\n")
    (root / "setup.sh").write_text(SETUP_OK)
    return root


def _run(*args) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", str(TOOL), *args], capture_output=True, text=True, timeout=60)


def test_check_is_clean_on_a_consistent_tree(tmp_path):
    assert rg.check(_tree(tmp_path)) == []


def test_check_names_a_stale_pin(tmp_path):
    root = _tree(tmp_path)
    (root / "requirements.in").write_text(GOOD_IN.replace("alpha==1.0", "alpha==1.1"))
    (root / "requirements.lock.txt").write_text("")
    (problem,) = rg.check(root)
    assert "requirements.txt is stale" in problem and "alpha: 1.0 -> 1.1" in problem


def test_check_names_a_pin_missing_from_the_generated_file(tmp_path):
    root = _tree(tmp_path)
    (root / "requirements.in").write_text(GOOD_IN + "capstone==5.0.9\n")
    (problem,) = rg.check(root)
    assert "capstone: None -> 5.0.9" in problem


def test_check_flags_a_hand_edit_that_keeps_the_pins(tmp_path):
    root = _tree(tmp_path)
    (root / "requirements.txt").write_text(rg.render(GOOD_IN) + "# hand note\n")
    (problem,) = rg.check(root)
    assert "pins agree, text differs" in problem


def test_check_flags_a_lock_that_contradicts_a_pin(tmp_path):
    root = _tree(tmp_path)
    (root / "requirements.lock.txt").write_text("alpha==0.9\n")
    assert rg.check(root) == ["requirements.lock.txt pins alpha==0.9, requirements.in pins ==1.0"]


def test_check_flags_setup_installing_outside_the_source(tmp_path):
    root = _tree(tmp_path)
    (root / "setup.sh").write_text(SETUP_OK + "uv pip install -p .venv/bin/python opencv-python || true\n")
    (problem,) = rg.check(root)
    assert "setup.sh:9: installs 'opencv-python' outside requirements.txt" in problem


@pytest.mark.parametrize("missing", ["requirements.in", "requirements.txt", "requirements.lock.txt", "setup.sh"])
def test_check_names_a_missing_file(tmp_path, missing):
    root = _tree(tmp_path)
    (root / missing).unlink()
    problems = rg.check(root)
    assert any(missing in p and "missing" in p for p in problems), problems


def test_main_writes_then_check_passes_then_fails_when_stale(tmp_path):
    root = _tree(tmp_path)
    (root / "requirements.txt").unlink()
    w = _run("--root", str(root))
    assert w.returncode == 0 and "3 pins" in w.stdout, w.stderr
    assert (root / "requirements.txt").read_text() == rg.render(GOOD_IN)
    assert _run("--root", str(root), "--check").returncode == 0
    (root / "requirements.in").write_text(GOOD_IN + "delta==4\n")
    c = _run("--root", str(root), "--check")
    assert c.returncode == 1 and "FAIL requirements.txt is stale" in c.stderr and "delta" in c.stderr


def test_main_refuses_an_invalid_source_and_writes_nothing(tmp_path):
    root = _tree(tmp_path)
    before = (root / "requirements.txt").read_text()
    (root / "requirements.in").write_text("alpha>=1\n")
    r = _run("--root", str(root))
    assert r.returncode == 2 and "not an exact pin" in r.stderr
    assert (root / "requirements.txt").read_text() == before
    assert _run("--root", str(root), "--check").returncode == 2


def test_setup_sh_runs_the_check_before_installing():
    """setup.sh refuses a stale requirements.txt: the --check runs, unguarded, before the install."""
    lines = [ln.strip() for ln in (ROOT / "setup.sh").read_text().splitlines()]
    chk = next(n for n, ln in enumerate(lines) if "tools/requirements_gen.py --check" in ln and not ln.startswith("#"))
    inst = next(n for n, ln in enumerate(lines) if "-r requirements.txt" in ln and not ln.startswith("#"))
    assert chk < inst
    assert "||" not in lines[chk] and "&&" not in lines[chk]
    assert "set -euo pipefail" in lines


def _import_master(monkeypatch, tmp_path):
    spec = importlib.util.spec_from_file_location("import_master_r14", ROOT / "tools/migrate/import_master.py")
    im = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(im)
    repo, src = tmp_path / "master", tmp_path / "csctf"
    repo.mkdir()
    src.mkdir()
    (src / "requirements.txt").write_text("# CSCTF 2026 solver dependencies\nalpha==1.0\nalpha==1.0\nbeta==2\n")
    monkeypatch.setattr(im, "REPO", repo)
    monkeypatch.setitem(im.SOURCES, "csctf", src)
    return im, repo


def test_import_rerun_keeps_the_master_requirements_in(monkeypatch, tmp_path):
    """Re-running the import must not put the CSCTF-era requirements.in (old header, no B-240 pins) back."""
    im, repo = _import_master(monkeypatch, tmp_path)
    mine = "# master-owned (R-14)\ncapstone==5.0.9\n"
    (repo / "requirements.in").write_text(mine)
    assert im.requirements_in(dry=False) == ["alpha==1.0"]
    assert (repo / "requirements.in").read_text() == mine


def test_import_first_run_still_writes_requirements_in(monkeypatch, tmp_path):
    im, repo = _import_master(monkeypatch, tmp_path)
    assert im.requirements_in(dry=False) == ["alpha==1.0"]
    pins = rg.parse_pins((repo / "requirements.in").read_text())
    assert [(p.name, p.version) for p in pins][:2] == [("alpha", "1.0"), ("beta", "2")]
    assert ("unicorn", "2.1.4") in [(p.name, p.version) for p in pins]


@pytest.mark.needs_tool("bash")
def test_setup_sh_is_valid_bash():
    r = subprocess.run(["bash", "-n", str(ROOT / "setup.sh")], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
