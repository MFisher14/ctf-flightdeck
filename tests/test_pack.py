"""Solver packs: pack.toml, fetching with git from a local repository made here, the setup
command, and the config's [l1] table. No network: every git address is a file:// one."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ctf_flightdeck import pack as packs
from ctf_flightdeck.config import load_config
from ctf_flightdeck.l1.manifest import ManifestError, discover
from ctf_flightdeck.pack_cli import app

from l1_kit import cli_engine

runner = CliRunner()
LADDER = '[api]\nbase_url = "http://127.0.0.1:11434/v1"\nkey_env = ""\n\n[models]\nladder = ["local-model"]\n\n[lanes]\nruntime = "host"\n'


def invoke(*args, **kw):
    return runner.invoke(app, [str(a) for a in args], prog_name="flightdeck pack", **kw)


def git(folder: Path, *args: str) -> str:
    done = subprocess.run(["git", "-C", str(folder), "-c", "user.name=t", "-c", "user.email=t@example.test", *args],
                          capture_output=True, text=True, check=True)
    return done.stdout


def make_pack(folder: Path, *, toml: str | None = 'name = "demo-pack"\nversion = "1.2.0"\n', setup: str | None = None) -> Path:
    cli_engine(folder, "e", "echo t{from_the_pack}\n")
    if toml is not None:
        (folder / "pack.toml").write_text(toml)
    if setup is not None:
        script = folder / "setup.sh"
        script.write_text("#!/bin/sh\n" + setup)
        script.chmod(0o755)
    return folder


def make_repo(folder: Path, **kw) -> str:
    make_pack(folder, **kw)
    git(folder, "init", "-q", "-b", "main")
    git(folder, "add", "-A")
    git(folder, "commit", "-q", "-m", "a pack")
    return folder.as_uri()


@pytest.fixture
def config(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    path = tmp_path / "config.toml"
    path.write_text(LADDER)
    return path


# ---------------------------------------------------------------- pack.toml


def test_a_pack_toml_names_the_pack_its_setup_command_and_its_image(tmp_path):
    root = make_pack(tmp_path / "p", setup="true\n", toml=(
        'name = "demo-pack"\nversion = "1.2.0"\ndescription = "Demo."\n[setup]\ncommand = "./setup.sh --fast"\n'
        '[image]\ntag = "demo-pack:1"\ndockerfile = "docker/Dockerfile"\n'))
    (root / "docker").mkdir()
    (root / "docker" / "Dockerfile").write_text("FROM scratch\n")
    info = packs.read(root)
    assert (info.name, info.version, info.description) == ("demo-pack", "1.2.0", "Demo.")
    assert info.setup == (str(root.resolve() / "setup.sh"), "--fast")
    assert info.image == packs.Image("demo-pack:1", root.resolve() / "docker" / "Dockerfile", root.resolve() / "docker")
    assert packs.image_command(info, "lane:9", docker="docker") == [
        "docker", "build", "--tag", "demo-pack:1", "--file", str(root.resolve() / "docker" / "Dockerfile"),
        "--build-arg", "LANE_IMAGE=lane:9", str(root.resolve() / "docker")]


def test_a_pack_without_a_pack_toml_is_named_after_its_folder_and_needs_nothing(tmp_path):
    info = packs.read(make_pack(tmp_path / "plain", toml=None))
    assert (info.name, info.setup, info.image) == ("plain", (), None)


@pytest.mark.parametrize(("toml", "message"), [
    ('version = "1"\n', "name is required"),
    ('name = "Bad Name"\n', "name is required"),
    ('name = "p"\nsetpu = 1\n', "setpu is not a key flightdeck knows"),
    ('name = "p"\n[setup]\ncommand = "../outside.sh"\n', "leaves the pack"),
    ('name = "p"\n[setup]\ncommand = "/bin/sh -c id"\n', "must be a path inside the pack"),
    ('name = "p"\n[setup]\ncommand = "./missing.sh"\n', "is not a file of the pack"),
    ('name = "p"\n[setup]\ncommand = "./setup.sh"\nshell = true\n', "setup.shell is not a key"),
    ('name = "p"\n[image]\ntag = "latest image"\ndockerfile = "Dockerfile"\n', "image.tag must be a docker image name with a tag"),
    ('name = "p"\n[image]\ntag = "p:1"\ndockerfile = "nope/Dockerfile"\n', "is not a file of the pack"),
    ('name = "p"\nengines = "../elsewhere"\n', "engines"),
    ('name = [broken\n', "not valid TOML"),
])
def test_a_bad_pack_toml_is_an_error_that_says_what_is_wrong(tmp_path, toml, message):
    root = make_pack(tmp_path / "p", toml=toml)
    with pytest.raises(packs.PackError, match=message):
        packs.read(root)


def test_a_setup_command_that_is_a_symlink_out_of_the_pack_is_refused(tmp_path):
    root = make_pack(tmp_path / "p", toml='name = "p"\n[setup]\ncommand = "./setup.sh"\n')
    outside = tmp_path / "outside.sh"
    outside.write_text("#!/bin/sh\n")
    (root / "setup.sh").symlink_to(outside)
    with pytest.raises(packs.PackError, match="leaves the pack"):
        packs.read(root)


def test_engines_names_the_folder_searched_for_manifests_and_the_rest_is_not_searched(tmp_path):
    root = tmp_path / "p"
    cli_engine(root / "fd", "e", "echo hi\n")
    (root / "other").mkdir()
    (root / "other" / "tool.manifest.toml").write_text('lane = "another tool\'s file"\n')  # not a flightdeck manifest
    with pytest.raises(ManifestError, match="unknown key"):
        discover(root)
    (root / "pack.toml").write_text('name = "p"\nengines = "fd"\n')
    assert [m.id for m in discover(root)] == ["e"]
    (root / "pack.toml").write_text('name = "p"\nengines = "nowhere"\n')
    with pytest.raises(ManifestError, match="is not a folder of the pack"):
        discover(root)


# ---------------------------------------------------------------- fetching


def test_fetch_clones_a_pack_into_the_packs_folder_and_a_second_fetch_updates_it(tmp_path, config):
    source = make_repo(tmp_path / "origin")
    root, how = packs.fetch(source)
    assert root == tmp_path / "data" / "ctf-flightdeck" / "packs" / "origin" and how == "fetched"
    assert packs.read(root).version == "1.2.0"
    (tmp_path / "origin" / "pack.toml").write_text('name = "demo-pack"\nversion = "1.3.0"\n')
    git(tmp_path / "origin", "commit", "-q", "-am", "newer")
    assert packs.fetch(source) == (root, "updated")
    assert packs.read(root).version == "1.3.0"


def test_fetch_takes_one_folder_of_a_repository_and_a_branch(tmp_path, config):
    repo = tmp_path / "mono"
    make_pack(repo / "packs" / "solvers")
    (repo / "big").mkdir()
    (repo / "big" / "other.txt").write_text("not the pack\n")
    git(repo, "init", "-q", "-b", "main")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "one")
    git(repo, "tag", "v9.9.9")
    root, how = packs.fetch(repo.as_uri(), ref="v9.9.9", name="mine", subdir="packs/solvers")
    clone = tmp_path / "data" / "ctf-flightdeck" / "packs" / "mine"
    assert root == clone / "packs" / "solvers" and how == "fetched" and packs.read(root).name == "demo-pack"
    assert not (clone / "big").exists()  # only the pack's folder is checked out
    with pytest.raises(packs.PackError, match="has no folder"):
        packs.fetch(repo.as_uri(), name="other", subdir="packs/missing")


@pytest.mark.parametrize(("source", "kw", "message"), [
    ("not a url", {}, "is not a git address"),
    ("--upload-pack=touch /tmp/x", {}, "is not a git address"),
    ("ext::sh -c id", {}, "is not a git address"),
    ("https://example.test/p.git", {"ref": "--orphan"}, "is not a branch or tag"),
    ("https://example.test/p.git", {"name": "../up"}, "--name"),
    ("https://example.test/p.git", {"subdir": "../.."}, "--subdir"),
])
def test_fetch_refuses_an_address_a_ref_a_name_or_a_folder_that_could_be_an_option_or_leave(tmp_path, config, source, kw, message):
    with pytest.raises(packs.PackError, match=message):
        packs.fetch(source, **kw)
    assert not (tmp_path / "data").exists()


def test_a_failed_clone_leaves_no_folder_and_names_gits_reason(tmp_path, config):
    with pytest.raises(packs.PackError, match="git could not clone the pack"):
        packs.fetch((tmp_path / "no-such-repo").as_uri())
    assert not (tmp_path / "data" / "ctf-flightdeck" / "packs" / "no-such-repo").exists()


def test_a_folder_that_is_another_packs_clone_is_not_overwritten(tmp_path, config):
    first = make_repo(tmp_path / "a" / "pack")
    second = make_repo(tmp_path / "b" / "pack")
    packs.fetch(first)
    with pytest.raises(packs.PackError, match="is a clone of"):
        packs.fetch(second)


# ---------------------------------------------------------------- the config


def test_set_l1_fills_the_example_table_and_keeps_every_other_line():
    before = "[lanes]\nruntime = \"host\"\n\n[l1]\n# Your solvers.\n# pack = \"~/ctf/solvers\"        # no pack\nconcurrency = 4\n\n[notify]\n# quiet\n"
    after = packs.set_l1(before, Path("/packs/p"), "p:1")
    assert after == ("[lanes]\nruntime = \"host\"\n\n[l1]\n# Your solvers.\n# pack = \"~/ctf/solvers\"        # no pack\n"
                     "pack = \"/packs/p\"\nconcurrency = 4\nimage = \"p:1\"\n\n[notify]\n# quiet\n")
    again = packs.set_l1(after, Path("/packs/q"), None)  # another pack, with no image: the image line is commented out
    assert 'pack = "/packs/q"\n' in again and '\n# image = "p:1"\n' in again and '\npack = "/packs/p"' not in again
    assert packs.set_l1("[api]\nx = 1", Path("/p"), None) == '[api]\nx = 1\n\n[l1]\npack = "/p"\n'


def test_write_config_puts_the_file_back_when_it_does_not_load_with_the_pack(tmp_path):
    path = tmp_path / "config.toml"
    broken = LADDER + "[l1]\nconcurrency = 0\n"
    path.write_text(broken)
    with pytest.raises(packs.PackError, match="put back as it was"):
        packs.write_config(path, tmp_path / "p", None)
    assert path.read_text() == broken
    with pytest.raises(packs.PackError, match="flightdeck init"):
        packs.write_config(tmp_path / "missing.toml", tmp_path / "p", None)


# ---------------------------------------------------------------- flightdeck pack install


def test_install_fetches_runs_the_setup_it_was_allowed_to_and_writes_the_config(tmp_path, config):
    source = make_repo(tmp_path / "origin", setup="echo ready > set-up.txt\n",
                       toml='name = "demo-pack"\n[setup]\ncommand = "./setup.sh"\n')
    result = invoke("install", source, "--yes", "--config", config)
    root = tmp_path / "data" / "ctf-flightdeck" / "packs" / "origin"
    assert result.exit_code == 0, result.output
    assert (root / "set-up.txt").read_text() == "ready\n"  # run in the pack's folder
    loaded = load_config(config)
    assert loaded.l1.pack == root and loaded.l1.image is None
    assert "engines: 1" in result.output and "setup command runs on this machine, as you" in result.output


def test_install_never_runs_a_setup_command_it_was_not_allowed_to(tmp_path, config):
    source = make_repo(tmp_path / "origin", setup="echo ran > set-up.txt\n",
                       toml='name = "demo-pack"\n[setup]\ncommand = "./setup.sh"\n')
    root = tmp_path / "data" / "ctf-flightdeck" / "packs" / "origin"
    refused = invoke("install", source, "--config", config)  # no terminal to ask at, and no --yes
    assert refused.exit_code == 2 and "no terminal to ask at" in refused.output
    assert not (root / "set-up.txt").exists() and load_config(config).l1.pack is None
    skipped = invoke("install", source, "--no-setup", "--config", config)
    assert skipped.exit_code == 0 and not (root / "set-up.txt").exists()
    assert load_config(config).l1.pack == root


def test_a_failing_setup_command_stops_the_install_and_leaves_the_config(tmp_path, config):
    source = make_repo(tmp_path / "origin", setup="exit 7\n", toml='name = "demo-pack"\n[setup]\ncommand = "./setup.sh"\n')
    result = invoke("install", source, "--yes", "--config", config)
    assert result.exit_code == 7 and "setup command failed (exit 7)" in result.output
    assert load_config(config).l1.pack is None


def test_install_uses_a_local_folder_where_it_is(tmp_path, config):
    root = make_pack(tmp_path / "mine")
    result = invoke("install", root, "--config", config)
    assert result.exit_code == 0 and "used where it is" in result.output
    assert load_config(config).l1.pack == root.resolve()
    assert not (tmp_path / "data").exists()


def test_install_refuses_a_folder_with_no_engines_and_a_missing_config(tmp_path, config):
    empty = tmp_path / "empty"
    empty.mkdir()
    result = invoke("install", empty, "--config", config)
    assert result.exit_code == 2 and "has no engines" in result.output and load_config(config).l1.pack is None
    missing = invoke("install", make_pack(tmp_path / "mine"), "--config", tmp_path / "nope.toml")
    assert missing.exit_code == 2 and "flightdeck init" in missing.output


def test_no_config_prints_the_lines_and_changes_nothing(tmp_path, config):
    root = make_pack(tmp_path / "mine")
    result = invoke("install", root, "--no-config")
    assert result.exit_code == 0 and f'[l1]\npack = "{root.resolve()}"' in result.output
    assert config.read_text() == LADDER


def test_a_pack_tomls_text_is_shown_made_safe(tmp_path, config):
    root = make_pack(tmp_path / "mine", toml='name = "p"\ndescription = "nice \\u001b[31mred\\u001b[0m pack"\n')
    result = invoke("info", root)
    assert result.exit_code == 0 and "\x1b" not in result.output and "nice" in result.output


def test_the_default_pack_is_this_checkouts_own(tmp_path, config):
    own = packs.own_pack()
    if own is None:
        pytest.skip("not run: this flightdeck is not a source checkout with packs/solvers beside it")
    assert (own / "pack.toml").is_file() and packs.read(own).name == "flightdeck-solvers"
    assert [m.id for m in discover(own)] == ["solvers.intake"]
    assert packs.default_ref().startswith("v")


# ---------------------------------------------------------------- the pack as a toolkit for lanes


def test_a_packs_lane_note_names_the_packs_folder_and_is_cut_and_cleaned(tmp_path):
    root = make_pack(tmp_path / "p", toml='name = "p"\n[lanes]\nnote = "LANE.md"\n')
    (root / "LANE.md").write_text("Solvers are at {pack}.\x1b[31m Run {pack}/go.\n")
    info = packs.read(root)
    assert packs.lane_note(info) == f"Solvers are at {root.resolve()}. Run {root.resolve()}/go." or "\x1b" not in packs.lane_note(info)
    assert "\x1b" not in packs.lane_note(info) and packs.lane_note(info, "/seen/here").startswith("Solvers are at /seen/here.")
    (root / "LANE.md").write_text("x" * 10000)
    assert len(packs.lane_note(packs.read(root))) == packs.MAX_NOTE
    (root / "LANE.md").write_text("  \n")
    with pytest.raises(packs.PackError, match="is empty"):
        packs.lane_note(packs.read(root))
    with pytest.raises(packs.PackError, match="is no toolkit for lanes"):
        packs.lane_note(packs.read(make_pack(tmp_path / "plain")))


def test_install_turns_lane_tools_on_only_for_a_pack_that_says_how(tmp_path, config):
    plain = make_pack(tmp_path / "plain")
    assert invoke("install", plain, "--config", config).exit_code == 0 and load_config(config).l1.lane_tools is False
    refused = invoke("install", plain, "--lane-tools", "--config", config)
    assert refused.exit_code == 2 and "does not say how a lane calls it" in refused.output
    noted = make_pack(tmp_path / "noted", toml='name = "noted"\n[lanes]\nnote = "LANE.md"\n')
    (noted / "LANE.md").write_text("Call {pack}/tool.\n")
    assert invoke("install", noted, "--config", config).exit_code == 0 and load_config(config).l1.lane_tools is True
    assert invoke("install", noted, "--no-lane-tools", "--config", config).exit_code == 0
    assert load_config(config).l1.lane_tools is False and "# lane_tools = true" in config.read_text()
