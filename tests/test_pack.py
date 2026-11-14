"""Solver packs: pack.toml, fetching with git from a local repository made here, the setup
command, and the config's [l1] table. No network: every git address is a file:// one."""

from __future__ import annotations

import os
import re
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


def test_pack_info_reads_the_config_it_is_given_and_its_help_says_read_not_write(tmp_path, config):
    """`pack info` writes nothing, so its --config is the file it reads the pack's place from.
    `install` and `image` do write the config, and their help keeps saying so."""
    def shown(command: str) -> str:
        output = runner.invoke(app, [command, "--help"], prog_name="flightdeck pack", terminal_width=200).output
        return " ".join(re.sub(r"[│╭╮╰╯─]", " ", output).split())

    info = shown("info")
    assert "--config <file> The config file that names the pack when PACK is left out (default: your config). Only read: info writes nothing." in info
    assert "write the pack into" not in info
    for command in ("install", "image"):
        assert "--config <file> The config file to write the pack into (default: your config)." in shown(command), command

    root = make_pack(tmp_path / "mine")
    other = tmp_path / "other.toml"
    other.write_text(LADDER + f'\n[l1]\npack = "{root}"\n')
    result = invoke("info", "--config", other)
    assert result.exit_code == 0 and f"pack: demo-pack 1.2.0 at {root.resolve()}" in result.output.splitlines()
    assert other.read_text() == LADDER + f'\n[l1]\npack = "{root}"\n' and config.read_text() == LADDER
    none = invoke("info", "--config", config)  # the config it was given names no pack: it says so, and still writes nothing
    assert none.exit_code == 2 and "your config names no pack ([l1] pack)" in none.output and config.read_text() == LADDER


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


# ---------------------------------------------------------------- the programs a pack's engines call (tools)

STAND_IN_DOCKER = r"""#!/bin/sh
# A stand-in docker for the pack-tools lookups: never the real docker, and no container.
# `image inspect` and `run` know the images named in images.txt beside it; `run ... --entrypoint
# bash IMAGE -c SCRIPT ARGS` runs SCRIPT with this machine's bash on the "image's" PATH: the
# folder image-bin beside it, and a relative entry that must never be searched.
here="${0%/*}"  # no dirname: PATH holds this folder alone
for a in "$@"; do printf '%s\037' "$a" >> "$here/calls.log"; done
printf '\036' >> "$here/calls.log"
case "$1" in
  version) echo 99.0.0-fake; exit 0 ;;
  image) [ "$2" = inspect ] && /usr/bin/grep -qx -- "$3" "$here/images.txt" && exit 0; exit 1 ;;
  run)
    [ -f "$here/run.fail" ] && { /bin/cat "$here/run.fail" >&2; exit 125; }
    image=""; prev=""
    for a in "$@"; do if [ "$prev" = bash ]; then image="$a"; break; fi; prev="$a"; done
    /usr/bin/grep -qx -- "$image" "$here/images.txt" || { echo "Unable to find image '$image' locally" >&2; exit 125; }
    while [ "$1" != "-c" ]; do shift; done
    shift
    cd "$here/work" && PATH="$here/image-bin:relative-bin:" exec /bin/bash -c "$@" ;;
esac
echo "stand-in docker: unexpected call: $*" >&2
exit 64
"""


def program(folder: Path, name: str) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    exe = folder / name
    exe.write_text("#!/bin/sh\nexit 0\n")
    exe.chmod(0o755)
    return exe


def stand_in_docker(tmp_path: Path, monkeypatch, *, images: tuple[str, ...] = (), has: tuple[str, ...] = (),
                    path: str | None = None) -> Path:
    """STAND_IN_DOCKER as the only docker on PATH (with `path` after it), knowing `images`,
    each holding the programs `has`. A program of the same name in the folder a relative PATH
    entry names (work/relative-bin, and the working folder itself) must not count as found.
    Returns its folder: calls.log there lists every call."""
    folder = tmp_path / "stand-in-docker"
    folder.mkdir()
    (folder / "docker").write_text(STAND_IN_DOCKER)
    (folder / "docker").chmod(0o755)
    (folder / "images.txt").write_text("".join(f"{image}\n" for image in images))
    (folder / "image-bin").mkdir()
    for name in has:
        program(folder / "image-bin", name)
    program(folder / "work" / "relative-bin", "planted")
    program(folder / "work", "planted")
    monkeypatch.setenv("PATH", str(folder) + (f"{os.pathsep}{path}" if path else ""))
    return folder


def docker_calls(folder: Path) -> list[list[str]]:
    log = folder / "calls.log"
    if not log.exists():
        return []
    return [call.split("\x1f")[:-1] for call in log.read_text().split("\x1e")[:-1]]


def test_a_pack_toml_lists_the_programs_its_engines_call(tmp_path):
    root = make_pack(tmp_path / "p", toml='name = "p"\ntools = ["tshark", "7zz", "mdb-export", "g++", "zip2john", "7z2john.pl"]\n')
    assert packs.read(root).tools == ("tshark", "7zz", "mdb-export", "g++", "zip2john", "7z2john.pl")
    assert packs.read(make_pack(tmp_path / "none", toml='name = "p"\n')).tools == ()
    assert packs.read(make_pack(tmp_path / "plain", toml=None)).tools == ()


@pytest.mark.parametrize(("toml", "message"), [
    ('tools = "tshark"\n', "tools must be a list of at most 200 program names"),
    ('tools = [1]\n', r"tools\[0\] \(int\) must be a program's name"),
    ('tools = ["ok", "/usr/bin/tshark"]\n', r"tools\[1\] \(/usr/bin/tshark\) must be a program's name as it is typed .*, not a path"),
    ('tools = ["../x"]\n', r"tools\[0\]"),
    ('tools = ["--rm"]\n', r"tools\[0\]"),
    ('tools = ["a b"]\n', r"tools\[0\]"),
    ('tools = ["x;id"]\n', r"tools\[0\]"),
    ('tools = [""]\n', r"tools\[0\]"),
    ('tools = ["' + "a" * 65 + '"]\n', r"tools\[0\]"),
    ('tools = ["bad\\u001b[31m"]\n', r"tools\[0\] \(bad\^\[\[31m\)"),
    ('tools = ["tshark", "upx", "tshark"]\n', "tools lists tshark twice"),
    ("tools = [" + ", ".join(f'"t{i}"' for i in range(201)) + "]\n", "at most 200"),
])
def test_a_bad_tools_list_is_refused_saying_which_entry(tmp_path, toml, message):
    root = make_pack(tmp_path / "p", toml='name = "p"\n' + toml)
    with pytest.raises(packs.PackError, match=message):
        packs.read(root)


def test_tools_missing_on_this_machine_are_looked_up_in_paths_absolute_folders_only(tmp_path, monkeypatch):
    program(tmp_path / "bin", "tshark")
    program(tmp_path / "bin2", "upx")
    program(tmp_path / "here", "planted")  # in the working folder: a relative PATH entry must not find it
    (tmp_path / "bin" / "notes").write_text("not a program\n")  # there, but not executable
    monkeypatch.chdir(tmp_path / "here")
    path = os.pathsep.join(["", ".", str(tmp_path / "bin"), "relative", str(tmp_path / "bin2")])
    assert packs.missing_on_host(["tshark", "binwalk", "upx", "planted", "notes"], path) == ["binwalk", "planted", "notes"]
    assert packs.missing_on_host(["tshark"], "") == ["tshark"]
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))
    assert packs.missing_on_host(["tshark", "upx"]) == ["upx"]  # by default this process's PATH
    assert packs.missing_on_host([]) == []


def test_tools_missing_in_an_image_are_asked_of_one_throwaway_container_with_no_network(tmp_path, monkeypatch):
    docker = stand_in_docker(tmp_path, monkeypatch, images=("demo-pack:1",), has=("tshark", "upx"))
    assert packs.missing_in_image("demo-pack:1", ["tshark", "binwalk", "upx", "planted"]) == ["binwalk", "planted"]
    (call,) = docker_calls(docker)
    assert call[:10] == ["run", "--rm", "--pull", "never", "--network", "none", "--entrypoint", "bash", "demo-pack:1", "-c"]
    assert call[11:] == ["flightdeck-pack", "tshark", "binwalk", "upx", "planted"]  # one container for every name
    assert "-v" not in call and "--mount" not in call  # nothing of this machine goes in


def test_an_image_that_cannot_be_asked_is_an_error_never_a_list_of_missing_tools(tmp_path, monkeypatch):
    docker = stand_in_docker(tmp_path, monkeypatch, images=("demo-pack:1",), has=("tshark",))
    with pytest.raises(packs.PackError, match=r"the image gone:1 did not say which programs it has \(it needs bash\): "
                                              "Unable to find image 'gone:1' locally"):
        packs.missing_in_image("gone:1", ["tshark"])
    (docker / "run.fail").write_text('exec: "bash": executable file not found in $PATH\n')
    with pytest.raises(packs.PackError, match="executable file not found"):
        packs.missing_in_image("demo-pack:1", ["tshark"])
    with pytest.raises(packs.PackError, match="--privileged is not a program's name"):
        packs.missing_in_image("demo-pack:1", ["--privileged"])
    before = len(docker_calls(docker))
    assert packs.missing_in_image("demo-pack:1", []) == [] and len(docker_calls(docker)) == before  # nothing to ask
    monkeypatch.setenv("PATH", str(tmp_path / "no-docker-here"))
    with pytest.raises(packs.PackError, match="docker is not on PATH, so the image demo-pack:1 cannot be asked"):
        packs.missing_in_image("demo-pack:1", ["tshark"])


def tools_pack(tmp_path: Path, *, image: bool) -> Path:
    toml = 'name = "demo-pack"\ntools = ["tshark", "binwalk", "upx"]\n'
    if image:
        toml += '[image]\ntag = "demo-pack:1"\ndockerfile = "Dockerfile"\n'
    root = make_pack(tmp_path / "p", toml=toml)
    (root / "Dockerfile").write_text("FROM scratch\n")
    return root


def test_pack_info_lists_the_tools_and_which_are_missing_on_this_machine(tmp_path, config, monkeypatch):
    root = tools_pack(tmp_path, image=False)
    program(tmp_path / "bin", "tshark")
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))
    lines = invoke("info", root).output.splitlines()
    assert "tools: 3 programs its engines call: tshark binwalk upx" in lines
    assert "  on this machine: missing binwalk upx" in lines
    assert not [line for line in lines if "in the image" in line]  # no image of its own to look in
    for name in ("binwalk", "upx"):
        program(tmp_path / "bin", name)
    assert "  on this machine: all on PATH" in invoke("info", root).output.splitlines()
    plain = invoke("info", make_pack(tmp_path / "plain", toml='name = "plain"\n')).output.splitlines()
    assert "tools: none listed (its pack.toml has no `tools`)" in plain


def test_pack_info_looks_in_the_packs_image_when_it_is_built_and_says_so_when_it_is_not(tmp_path, config, monkeypatch):
    root = tools_pack(tmp_path, image=True)
    docker = stand_in_docker(tmp_path, monkeypatch, images=(), has=("tshark", "binwalk"))
    lines = invoke("info", root).output.splitlines()
    assert "  on this machine: missing tshark binwalk upx" in lines
    assert "  in the image demo-pack:1: not looked up, since it is not built" in lines
    assert not [call for call in docker_calls(docker) if call[0] == "run"]  # an absent image is never run, or pulled
    (docker / "images.txt").write_text("demo-pack:1\n")
    lines = invoke("info", root).output.splitlines()
    assert "image: demo-pack:1 (built)" in lines and "  in the image demo-pack:1: missing upx" in lines
    program(docker / "image-bin", "upx")
    assert "  in the image demo-pack:1: all there" in invoke("info", root).output.splitlines()
    (docker / "run.fail").write_text("Cannot connect to the Docker daemon\n")
    said = invoke("info", root)
    assert said.exit_code == 0 and "  in the image demo-pack:1: not looked up: the image demo-pack:1 did not say which programs it has" in said.output


def test_flightdecks_own_pack_lists_tools_its_engines_name(tmp_path):
    own = packs.own_pack()
    if own is None:
        pytest.skip("not run: this flightdeck is not a source checkout with packs/solvers beside it")
    tools = packs.read(own).tools
    assert {"tshark", "binwalk", "exiftool", "7zz"} <= set(tools) and list(tools) == sorted(tools)
    assert not {"docker", "claude", "python3"} & set(tools)  # what flightdeck itself brings or checks is not the pack's to list


# ---------------------------------------------------------------------- a copy installed from a clone


class _Recorded:
    def __init__(self, text):
        self.text = text

    def read_text(self, name):
        assert name == "direct_url.json"
        return self.text


@pytest.mark.parametrize(("record", "found"), [
    ('{{"url": "file://{folder}", "dir_info": {{}}}}', True),
    ('{{"url": "file://{folder}", "dir_info": {{"editable": true}}}}', True),
    ('{{"url": "file://{folder}/gone", "dir_info": {{}}}}', False),  # the clone was moved or removed
    ('{{"url": "file://{folder}/x.whl", "archive_info": {{}}}}', False),  # an archive, not a folder
    ('{{"url": "https://example.org/{folder}", "dir_info": {{}}}}', False),
    ("not json", False),
    (None, False),  # an install from PyPI records nothing
])
def test_the_folder_a_copy_was_installed_from_is_read_from_the_installers_record(tmp_path, monkeypatch, record, found):
    from importlib import metadata

    text = None if record is None else record.format(folder=tmp_path.as_posix().lstrip("/") if "https" in record else tmp_path.as_posix())
    monkeypatch.setattr(metadata, "distribution", lambda name: _Recorded(text))
    assert packs.installed_from() == (tmp_path if found else None)


def test_a_copy_installed_from_a_clone_uses_that_clones_pack(tmp_path, monkeypatch):
    clone, site = tmp_path / "clone", tmp_path / "site" / "lib" / "ctf_flightdeck"
    (clone / "packs" / "solvers").mkdir(parents=True)
    (clone / "packs" / "solvers" / "pack.toml").write_text('name = "p"\n')
    site.mkdir(parents=True)
    monkeypatch.setattr(packs, "__file__", str(site / "pack.py"))  # this code runs from site-packages: no pack beside it
    monkeypatch.setattr(packs, "installed_from", lambda: None)
    assert packs.own_pack() is None
    monkeypatch.setattr(packs, "installed_from", lambda: clone)
    assert packs.own_pack() == clone / "packs" / "solvers"
