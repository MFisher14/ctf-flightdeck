"""B-142: the binary toolbox (tools/toolbox.toml, ctf/toolbox.py, `ctf toolbox`, doctor check `toolbox`).

Every probe here runs a stub written by the test (a shell or Python script in tmp_path); no install
ever runs (apply is driven through an injected runner or stub programs carrying the stub marker), and
the one test that reads the real host is marked needs_tool so it reports as not run without it.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from ctf import doctor, paths
from ctf import toolbox as tb
from ctf.engines import capabilities

ROOT = paths.repo_root()
PIN = "a" * 40
OTHER = "b" * 40
SYS_PATH = "/usr/bin:/bin"


# ------------------------------------------------------------------------------- helpers

def exe(path: Path, body: str, *, stub: bool = False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n" + ("# ctf-toolbox-stub\n" if stub else "") + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def tool(name="tbx-alpha", **kw) -> tb.Tool:
    base = dict(name=name, kind="binary", role="core", install_method="brew", install_target=name,
                bins=(name,), version_args=("--version",))
    base.update(kw)
    return tb.Tool(**base)


def env_with(bindir: Path, **extra) -> dict:
    e = {"PATH": f"{bindir}:{SYS_PATH}"}
    e.update(extra)
    return e


def write_manifest(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body))
    return path


def clone(dest: Path, head: str, script: str = "print('tool 1.4.2')\n") -> Path:
    (dest / ".git").mkdir(parents=True, exist_ok=True)
    (dest / ".git" / "HEAD").write_text(head + "\n")
    (dest / "tool.py").write_text(script)
    return dest


# ------------------------------------------------------------------------------- the real manifest

def test_real_manifest_names_every_past_needed_tool_with_its_runtime_needs():
    tools = {t.name: t for t in tb.load()}
    wanted = {"sops", "age", "rclone", "git-crypt", "ccrypt", "websocat", "keepassxc-cli", "veracrypt",
              "firefox_decrypt"}
    assert wanted <= set(tools)
    assert all(tools[n].role == "core" for n in wanted)
    assert tools["sage"].role == "optional"
    assert tools["firefox_decrypt"].kind == "clone" and tools["firefox_decrypt"].needs == ("nss",)
    assert tools["veracrypt"].needs == ("macfuse",)
    assert "age-keygen" in tools["age"].extra_bins
    assert "--disable-version-check" in tools["sops"].version_args     # sops --version phones home without it
    # sudo installers with a system extension / reboot are gated behind --system; nothing else is
    assert {n for n, t in tools.items() if t.system} == {"macfuse", "veracrypt"}
    for t in tools.values():
        if t.playbook:
            assert (ROOT / t.playbook).is_file(), f"{t.name}: playbook {t.playbook} missing"


@pytest.mark.needs_tool("websocat")
def test_real_host_probe_reads_the_websocat_version():
    st, = tb.verify(tb.load(), only=["websocat"])
    assert st.state == "ok" and st.version and st.version[0].isdigit(), st.line()


def test_committed_brewfile_is_the_render_of_the_manifest():
    assert (ROOT / "Brewfile").read_text() == tb.render_brewfile(tb.load())


def test_committed_capabilities_lists_every_toolbox_tool():
    text = (ROOT / "docs" / "CAPABILITIES.md").read_text()
    sec = text.split("\n## Binary toolbox\n", 1)
    assert len(sec) == 2, "docs/CAPABILITIES.md has no Binary toolbox section"
    for t in tb.load():
        assert f"| `{t.name}` | {t.role} |" in sec[1], t.name
    assert "[forensics](playbooks/forensics.md)" in sec[1]      # links resolve from docs/


def test_setup_sh_installs_the_toolbox_from_the_manifest_and_no_unpinned_clone():
    s = (ROOT / "setup.sh").read_text()
    assert "-m ctf toolbox install --apply" in s
    assert "firefox_decrypt ~/tools" not in s and "unode/firefox_decrypt" not in s
    runs = [ln for ln in s.splitlines() if ln.lstrip().startswith(".venv/bin/python -m ctf toolbox install")]
    assert runs and not any("--system" in ln for ln in runs)      # setup.sh never runs a system install
    assert "need Homebrew" in s                                     # documented: the brew steps need brew


# ------------------------------------------------------------------------------- parse / validate

GOOD = """\
[[tool]]
name = "a"
kind = "binary"
role = "core"
bins = ["a"]
install = { brew = "a" }
"""


@pytest.mark.parametrize("extra, msg", [
    ('colour = "red"\n', "unknown key"),
    ('', None),
])
def test_unknown_keys_are_refused(tmp_path, extra, msg):
    p = write_manifest(tmp_path / "t.toml", GOOD + extra)
    if msg is None:
        assert [t.name for t in tb.load(p)] == ["a"]
    else:
        with pytest.raises(tb.ToolboxError, match=msg):
            tb.load(p)


@pytest.mark.parametrize("body, msg", [
    (GOOD.replace('kind = "binary"', 'kind = "pkg"'), "kind 'pkg'"),
    (GOOD.replace('role = "core"', 'role = "nice"'), "role 'nice'"),
    (GOOD.replace('install = { brew = "a" }', 'install = { brew = "a", cask = "a" }'), "install must be"),
    (GOOD.replace('install = { brew = "a" }', 'install = { pip = "a" }'), "install must be"),
    (GOOD.replace('bins = ["a"]\n', ''), "a binary needs bins"),
    (GOOD.replace('install = { brew = "a" }', 'install = { git = "u" }'), "not installed by git"),
    (GOOD + 'app_paths = ["Apps/x"]\n', "must be absolute"),
    (GOOD + "version_re = 'v\\\\d+'\n", "needs a group"),
    (GOOD + "version_re = '(['\n", "does not compile"),
    (GOOD + 'min_version = "new"\n', "not a dotted number"),
    (GOOD + 'needs = ["ghost"]\n', "unknown tool"),
    (GOOD + GOOD, "duplicate tool name"),
    ('[[tool]]\nname = "c"\nkind = "clone"\nrole = "core"\ndest = "c"\nentry = "c.py"\n'
     'install = { git = "u" }\n', "a clone needs rev"),
    ('[[tool]]\nname = "c"\nkind = "clone"\nrole = "core"\ndest = "c"\nentry = "c.py"\nrev = "abc"\n'
     'install = { git = "u" }\n', "full 40-hex"),
    ('[[tool]]\nname = "c"\nkind = "clone"\nrole = "core"\ndest = "../c"\nentry = "c.py"\n'
     f'rev = "{PIN}"\ninstall = {{ git = "u" }}\n', "dest must be a folder name"),
    ('[[tool]]\nname = "f"\nkind = "file"\nrole = "core"\ninstall = { brew = "f" }\n', "a file needs candidates"),
    ('[[tool]]\nname = "f"\nkind = "file"\nrole = "core"\ncandidates = ["/x"]\nenv_dir = "X"\n'
     'install = { brew = "f" }\n', "env_dir and file_name go together"),
    ('[[tool]]\nname = "f"\nkind = "file"\nrole = "core"\ncandidates = ["/x"]\nversion_args = ["-v"]\n'
     'install = { brew = "f" }\n', "no version probe"),
    ('', "no \\[\\[tool\\]\\] entries"),
    (GOOD + 'system = "yes"\n', "system must be true or false"),
    (GOOD.replace('install = { brew = "a" }', 'install = { manual = "by hand" }') + "system = true\n",
     "not a system step"),
])
def test_bad_manifests_fail_loudly_naming_the_problem(tmp_path, body, msg):
    p = write_manifest(tmp_path / "t.toml", body)
    with pytest.raises(tb.ToolboxError, match=msg):
        tb.load(p)


def test_needs_cycle_and_core_needing_optional_are_refused(tmp_path):
    cyc = (GOOD + 'needs = ["b"]\n' + GOOD.replace('"a"', '"b"') + 'needs = ["a"]\n')
    with pytest.raises(tb.ToolboxError, match="cycle"):
        tb.load(write_manifest(tmp_path / "c.toml", cyc))
    opt = GOOD + 'needs = ["b"]\n' + GOOD.replace('"a"', '"b"').replace('"core"', '"optional"')
    with pytest.raises(tb.ToolboxError, match="core tool a needs an optional one"):
        tb.load(write_manifest(tmp_path / "o.toml", opt))


def test_missing_manifest_and_bad_toml_are_named(tmp_path):
    with pytest.raises(tb.ToolboxError, match="not found"):
        tb.load(tmp_path / "none.toml")
    with pytest.raises(tb.ToolboxError, match="not valid TOML"):
        tb.load(write_manifest(tmp_path / "b.toml", "[[tool]\n"))


# ------------------------------------------------------------------------------- versions

@pytest.mark.parametrize("found, minimum, ok", [
    ("1.1.3", "1.1.2", True), ("1.1.2", "1.1.2", True), ("1.1.1", "1.1.2", False),
    ("1.10", "1.9", True), ("1.11", "1.11.0", True), ("2", "1.99.99", True), ("1.0", None, True),
    ("1.0rc", "1.0", False),
])
def test_version_ok_compares_dotted_numbers(found, minimum, ok):
    assert tb.version_ok(found, minimum) is ok


# ------------------------------------------------------------------------------- verify: binaries

def test_binary_found_on_path_reports_version_and_path(tmp_path):
    b = exe(tmp_path / "bin" / "tbx-alpha", 'echo "tbx-alpha 2.3.4 (build)"\n')
    st, = tb.verify([tool(version_re=r"tbx-alpha (\d+\.\d+\.\d+)")], environ=env_with(tmp_path / "bin"))
    assert (st.state, st.version, st.path) == ("ok", "2.3.4", str(b))


def test_binary_probe_gets_its_version_args(tmp_path):
    exe(tmp_path / "bin" / "tbx-alpha", '[ "$1 $2" = "--text --version" ] && echo "V 1.2" || exit 9\n')
    st, = tb.verify([tool(version_args=("--text", "--version"))], environ=env_with(tmp_path / "bin"))
    assert st.state == "ok" and st.version == "1.2", st.line()


def test_missing_binary_names_where_it_looked_and_the_install(tmp_path):
    st, = tb.verify([tool(install_method="cask", install_target="alpha-app",
                          app_paths=(str(tmp_path / "App" / "alpha"),))],
                    environ=env_with(tmp_path / "bin"))
    assert st.state == "missing" and "tbx-alpha" in st.detail and str(tmp_path / "App" / "alpha") in st.detail
    assert st.fix == "brew install --cask alpha-app"


def test_app_path_fallback_needs_an_executable(tmp_path):
    app = tmp_path / "App" / "alpha"
    app.parent.mkdir()
    app.write_text("#!/bin/sh\necho alpha 3.0.1\n")
    t = tool(app_paths=(str(app),))
    st, = tb.verify([t], environ=env_with(tmp_path / "bin"))
    assert st.state == "missing"                      # not executable: not a tool
    app.chmod(app.stat().st_mode | stat.S_IXUSR)
    st, = tb.verify([t], environ=env_with(tmp_path / "bin"))
    assert (st.state, st.path, st.version) == ("ok", str(app), "3.0.1")


def test_path_wins_over_the_app_path(tmp_path):
    b = exe(tmp_path / "bin" / "tbx-alpha", "echo 1.0.0\n")
    app = exe(tmp_path / "App" / "alpha", "echo 9.0.0\n")
    st, = tb.verify([tool(app_paths=(str(app),))], environ=env_with(tmp_path / "bin"))
    assert st.path == str(b) and st.version == "1.0.0"


@pytest.mark.parametrize("body, why", [
    ("echo boom >&2; exit 3\n", "exited 3: boom"),
    ("echo no digits here\n", "no version in the probe output"),
])
def test_a_probe_that_fails_is_broken_not_ok(tmp_path, body, why):
    exe(tmp_path / "bin" / "tbx-alpha", body)
    st, = tb.verify([tool()], environ=env_with(tmp_path / "bin"))
    assert st.state == "broken" and why in st.detail and st.fix.startswith("reinstall: brew install")


def test_a_probe_that_hangs_is_broken(tmp_path):
    exe(tmp_path / "bin" / "tbx-alpha", "echo 1.0\n")

    def hang(argv, **kw):
        raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
    st, = tb.verify([tool()], environ=env_with(tmp_path / "bin"), run=hang)
    assert st.state == "broken" and "timed out" in st.detail


def test_probe_runs_without_stdin_and_with_a_timeout(tmp_path):
    exe(tmp_path / "bin" / "tbx-alpha", "echo 1.0\n")
    seen = {}

    def rec(argv, **kw):
        seen.update(kw, argv=argv)
        return subprocess.CompletedProcess(argv, 0, "x 1.0\n", "")
    tb.verify([tool()], environ=env_with(tmp_path / "bin"), run=rec)
    assert seen["stdin"] is subprocess.DEVNULL and seen["timeout"] == tb.PROBE_TIMEOUT
    assert seen["argv"] == [str(tmp_path / "bin" / "tbx-alpha"), "--version"]


def test_below_min_version_is_old_with_an_upgrade_fix(tmp_path):
    exe(tmp_path / "bin" / "tbx-alpha", "echo 1.1.1\n")
    st, = tb.verify([tool(min_version="1.1.2")], environ=env_with(tmp_path / "bin"))
    assert st.state == "old" and st.version == "1.1.1" and "1.1.2" in st.detail
    assert st.fix.startswith("upgrade:")


def test_extra_bins_must_exist_on_path_or_beside_the_tool(tmp_path):
    exe(tmp_path / "bin" / "tbx-alpha", "echo 1.0\n")
    t = tool(extra_bins=("tbx-alpha-keygen",))
    st, = tb.verify([t], environ=env_with(tmp_path / "bin"))
    assert st.state == "missing" and "tbx-alpha-keygen" in st.detail
    exe(tmp_path / "bin" / "tbx-alpha-keygen", "echo 1.0\n")
    st, = tb.verify([t], environ=env_with(tmp_path / "bin"))
    assert st.state == "ok"


def test_extra_bins_of_an_app_path_tool_are_found_in_its_folder(tmp_path):
    """An app-bundle tool (found by app_paths, not PATH) ships its helpers beside it, off PATH."""
    app = exe(tmp_path / "App" / "MacOS" / "alpha", "echo alpha 2.0.0\n")
    t = tool(app_paths=(str(app),), extra_bins=("alpha-helper",))
    e = env_with(tmp_path / "bin")
    st, = tb.verify([t], environ=e)
    assert st.state == "missing" and "alpha-helper" in st.detail and st.path == str(app)
    exe(tmp_path / "App" / "MacOS" / "alpha-helper", "exit 0\n")      # beside the app, not on PATH
    st, = tb.verify([t], environ=e)
    assert (st.state, st.path, st.version) == ("ok", str(app), "2.0.0"), st.line()


def test_status_line_carries_the_fix_on_its_own_line():
    s = tb.Status("a", "core", "missing", detail="no a on PATH", fix="brew install a")
    assert s.line() == "MISSING a (core): no a on PATH\n        fix: brew install a"
    assert "fix:" not in tb.Status("a", "core", "ok", path="/x/a").line()


def test_a_binary_without_version_args_is_presence_only(tmp_path):
    exe(tmp_path / "bin" / "tbx-alpha", "exit 1\n")
    st, = tb.verify([tool(version_args=())], environ=env_with(tmp_path / "bin"))
    assert st.state == "ok" and st.version is None


# ------------------------------------------------------------------------------- verify: files, needs

def ftool(name, cands, **kw) -> tb.Tool:
    return tb.Tool(name=name, kind="file", role="core", install_method="brew", install_target=name,
                   candidates=tuple(str(c) for c in cands), **kw)


def test_file_tool_finds_a_candidate_or_names_all_it_tried(tmp_path):
    a, b = tmp_path / "a" / "lib.dylib", tmp_path / "b" / "lib.dylib"
    t = ftool("libx", [a, b])
    st, = tb.verify([t], environ={"PATH": SYS_PATH})
    assert st.state == "missing" and str(a) in st.detail and str(b) in st.detail
    b.parent.mkdir()
    b.write_bytes(b"\0")
    st, = tb.verify([t], environ={"PATH": SYS_PATH})
    assert (st.state, st.path) == ("ok", str(b))


def test_file_tool_tries_its_env_dir_first(tmp_path):
    (tmp_path / "custom").mkdir()
    (tmp_path / "custom" / "libnss3.dylib").write_bytes(b"\0")
    (tmp_path / "brew").mkdir()
    (tmp_path / "brew" / "libnss3.dylib").write_bytes(b"\0")
    t = ftool("nss", [tmp_path / "brew" / "libnss3.dylib"], env_dir="NSS_LIB_PATH", file_name="libnss3.dylib")
    st, = tb.verify([t], environ={"PATH": SYS_PATH, "NSS_LIB_PATH": str(tmp_path / "custom")})
    assert st.state == "ok" and st.path == str(tmp_path / "custom" / "libnss3.dylib")
    st, = tb.verify([t], environ={"PATH": SYS_PATH})
    assert st.path == str(tmp_path / "brew" / "libnss3.dylib")


def test_a_tool_whose_need_is_missing_is_needs_with_the_needs_fix(tmp_path):
    exe(tmp_path / "bin" / "tbx-alpha", "echo 1.0\n")
    lib = ftool("libx", [tmp_path / "lib" / "libx.dylib"])
    report = tb.verify([tool(needs=("libx",)), lib], environ=env_with(tmp_path / "bin"))
    assert [s.name for s in report] == ["libx", "tbx-alpha"]          # needs first
    by = {s.name: s for s in report}
    assert by["libx"].state == "missing"
    assert by["tbx-alpha"].state == "needs" and "libx (missing)" in by["tbx-alpha"].detail
    assert by["tbx-alpha"].fix == "brew install libx" and by["tbx-alpha"].version == "1.0"
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "libx.dylib").write_bytes(b"\0")
    assert all(s.ok for s in tb.verify([tool(needs=("libx",)), lib], environ=env_with(tmp_path / "bin")))


def test_only_selects_a_tool_with_its_needs_and_refuses_unknown_names(tmp_path):
    tools = [tool(needs=("libx",)), ftool("libx", [tmp_path / "x"]), tool("tbx-beta")]
    assert [s.name for s in tb.verify(tools, only=["tbx-alpha"], environ={"PATH": SYS_PATH})] == \
        ["libx", "tbx-alpha"]
    with pytest.raises(tb.ToolboxError, match="unknown toolbox tool.*ghost"):
        tb.verify(tools, only=["ghost"])


def test_problems_split_core_and_optional():
    rep = [tb.Status("a", "core", "ok"), tb.Status("b", "core", "missing"),
           tb.Status("c", "optional", "missing")]
    assert [s.name for s in tb.problems(rep)] == ["b", "c"]
    assert [s.name for s in tb.problems(rep, core_only=True)] == ["b"]
    with pytest.raises(ValueError):
        tb.Status("x", "core", "green")


# ------------------------------------------------------------------------------- verify: clones

def ctool(**kw) -> tb.Tool:
    base = dict(name="fxd", kind="clone", role="core", install_method="git", install_target="https://example.invalid/fxd",
                dest="fxd", entry="tool.py", rev=PIN, version_args=("--version",))
    base.update(kw)
    return tb.Tool(**base)


def test_clone_at_the_pin_runs_with_this_python_isolated_from_its_folder(tmp_path):
    d = clone(tmp_path / "tools" / "fxd", PIN,
              "import os, sys\nprint('fxd 1.1.3', os.getcwd(), sys.flags.isolated)\n")
    st, = tb.verify([ctool()], environ={"PATH": SYS_PATH, "CTF_TOOLBOX_DIR": str(tmp_path / "tools")})
    assert (st.state, st.version, st.path) == ("ok", "1.1.3", str(d / "tool.py"))
    seen = {}

    def rec(argv, **kw):
        seen.update(kw, argv=argv)
        return subprocess.CompletedProcess(argv, 0, "1.1.3\n", "")
    tb.verify([ctool()], environ={"PATH": SYS_PATH, "CTF_TOOLBOX_DIR": str(tmp_path / "tools")},
              run=rec, python="/py")
    assert seen["argv"] == ["/py", "-I", str(d / "tool.py"), "--version"] and seen["cwd"] == str(d)


@pytest.mark.parametrize("layout", ["loose", "packed"])
def test_clone_head_through_a_branch_ref_is_read_without_git(tmp_path, layout):
    d = clone(tmp_path / "t" / "fxd", "ref: refs/heads/main")
    if layout == "loose":
        (d / ".git" / "refs" / "heads").mkdir(parents=True)
        (d / ".git" / "refs" / "heads" / "main").write_text(PIN + "\n")
    else:
        (d / ".git" / "packed-refs").write_text(f"# pack-refs with: peeled\n{OTHER} refs/heads/dev\n"
                                                f"{PIN} refs/heads/main\n")
    st, = tb.verify([ctool()], environ={"PATH": SYS_PATH, "CTF_TOOLBOX_DIR": str(tmp_path / "t")})
    assert st.state == "ok", st.line()


def test_clone_at_another_commit_is_drift_naming_both(tmp_path):
    clone(tmp_path / "t" / "fxd", OTHER)
    st, = tb.verify([ctool()], environ={"PATH": SYS_PATH, "CTF_TOOLBOX_DIR": str(tmp_path / "t")})
    assert st.state == "drift" and OTHER in st.detail and PIN in st.detail and st.version == "1.4.2"


def test_clone_without_its_script_is_missing_and_a_broken_one_is_broken(tmp_path):
    e = {"PATH": SYS_PATH, "CTF_TOOLBOX_DIR": str(tmp_path / "t")}
    st, = tb.verify([ctool()], environ=e)
    assert st.state == "missing" and "tool.py" in st.detail
    clone(tmp_path / "t" / "fxd", PIN, "raise SystemExit(4)\n")
    st, = tb.verify([ctool()], environ=e)
    assert st.state == "broken" and "exited 4" in st.detail


def test_toolbox_dir_reads_ctf_toolbox_dir(tmp_path):
    assert paths.toolbox_dir({"CTF_TOOLBOX_DIR": str(tmp_path)}) == tmp_path.resolve()
    assert paths.toolbox_dir({}) == paths.DEFAULT_TOOLBOX_DIR.expanduser().resolve()


# ------------------------------------------------------------------------------- plan

def test_plan_installs_missing_upgrades_old_and_broken_and_skips_ok(tmp_path):
    tools = [tool("a"), tool("b"), tool("c", install_method="cask", install_target="c-app", note="approve it"),
             tool("d"), tool("e", install_method="manual", install_target="do it by hand"), tool("f")]
    rep = [tb.Status("a", "core", "missing"), tb.Status("b", "core", "old"),
           tb.Status("c", "core", "missing"), tb.Status("d", "core", "ok"), tb.Status("e", "optional", "missing"),
           tb.Status("f", "core", "broken")]
    steps = tb.plan_install(tools, rep)
    assert [(s.tool, s.argv) for s in steps] == [
        ("a", ("brew", "install", "a")), ("b", ("brew", "upgrade", "b")),
        ("c", ("brew", "install", "--cask", "c-app")), ("e", None), ("f", ("brew", "upgrade", "f"))]
    assert steps[2].note == "approve it" and "MANUAL: do it by hand" in steps[3].line()


def test_plan_puts_needs_first_and_skips_a_needs_state(tmp_path):
    tools = [tool("app", needs=("lib",)), tool("lib")]
    steps = tb.plan_install(tools, [tb.Status("app", "core", "missing"), tb.Status("lib", "core", "missing")])
    assert [s.tool for s in steps] == ["lib", "app"] and steps[1].after == ("lib",)
    steps = tb.plan_install(tools, [tb.Status("app", "core", "needs"), tb.Status("lib", "core", "missing")])
    assert [s.tool for s in steps] == ["lib"]


def test_plan_clones_at_the_pin_and_moves_a_drifted_clone(tmp_path):
    e = {"CTF_TOOLBOX_DIR": str(tmp_path / "t")}
    dest = str((tmp_path / "t" / "fxd").resolve())
    steps = tb.plan_install([ctool()], [tb.Status("fxd", "core", "missing")], environ=e)
    assert [s.argv for s in steps] == [
        ("git", "init", "-q", dest),
        ("git", "-C", dest, "fetch", "-q", "--depth", "1", "https://example.invalid/fxd", PIN),
        ("git", "-C", dest, "checkout", "-q", "--detach", PIN)]
    clone(tmp_path / "t" / "fxd", OTHER)
    steps = tb.plan_install([ctool()], [tb.Status("fxd", "core", "drift")], environ=e)
    assert [s.argv[3] for s in steps] == ["fetch", "checkout"]


def test_plan_marks_a_system_tool_and_its_line_says_so(tmp_path):
    tools = [tool("fuse", install_method="cask", install_target="fuse-app", system=True),
             tool("vc", install_method="cask", install_target="vc-app", needs=("fuse",)), tool("plain")]
    rep = [tb.Status(n, "core", "missing") for n in ("fuse", "vc", "plain")]
    steps = tb.plan_install(tools, rep)
    assert [(s.tool, s.system) for s in steps] == [("fuse", True), ("vc", False), ("plain", False)]
    assert "[SYSTEM: runs only with --system]" in steps[0].line()
    assert "SYSTEM" not in steps[1].line() and "SYSTEM" not in steps[2].line()


def test_plan_never_clones_over_a_folder_that_is_not_the_tool(tmp_path):
    (tmp_path / "t" / "fxd").mkdir(parents=True)
    steps = tb.plan_install([ctool()], [tb.Status("fxd", "core", "missing")],
                            environ={"CTF_TOOLBOX_DIR": str(tmp_path / "t")})
    assert len(steps) == 1 and steps[0].argv is None and "move it aside" in steps[0].note


# ------------------------------------------------------------------------------- apply

class Recorder:
    def __init__(self, fail=()):
        self.calls, self.fail = [], set(fail)

    def __call__(self, argv, **kw):
        self.calls.append(tuple(argv))
        rc = 1 if tuple(argv) in self.fail else 0
        return subprocess.CompletedProcess(argv, rc, "", "boom" if rc else "")


def stub_progs(tmp_path, *names, stub=True) -> dict:
    for n in names:
        exe(tmp_path / "pbin" / n, "exit 0\n", stub=stub)
    return {"PATH": f"{tmp_path / 'pbin'}:{SYS_PATH}", "CTF_TESTING": "1"}


def test_apply_refuses_a_real_program_under_ctf_testing(tmp_path):
    e = stub_progs(tmp_path, "brew", stub=False)
    rec = Recorder()
    with pytest.raises(tb.ToolboxError, match="brew is not a test stub"):
        tb.apply([tb.Step("a", ("brew", "install", "a"))], environ=e, run=rec)
    assert rec.calls == []


def test_apply_skips_and_names_an_absent_program_and_runs_the_rest(tmp_path):
    """No Homebrew: the brew steps are skipped by name, the git steps still run, and a tool that needs
    one that was not installed is skipped with the reason (never run half-provisioned)."""
    e = stub_progs(tmp_path, "git")                       # git is a stub; brew is absent
    steps = [tb.Step("lib", ("brew", "install", "lib")),
             tb.Step("clone", ("git", "init", "/c")),
             tb.Step("clone", ("git", "-C", "/c", "fetch")),
             tb.Step("app", ("git", "init", "/a"), after=("lib",))]
    rec = Recorder()
    res = tb.apply(steps, environ=e, run=rec)
    assert rec.calls == [("git", "init", "/c"), ("git", "-C", "/c", "fetch")]
    assert [(r.step.tool, r.returncode, r.skipped, r.reason) for r in res] == [
        ("lib", None, True, "absent"), ("clone", 0, False, ""), ("clone", 0, False, ""),
        ("app", None, True, "blocked")]
    assert "brew not found on PATH" in res[0].output and "https://brew.sh" in res[0].output
    assert "lib: brew not found on PATH" in res[3].output


def test_apply_runs_a_system_step_only_when_allowed(tmp_path):
    e = stub_progs(tmp_path, "brew")
    steps = [tb.Step("fuse", ("brew", "install", "--cask", "fuse"), system=True),
             tb.Step("vc", ("brew", "install", "--cask", "vc"), after=("fuse",)),
             tb.Step("plain", ("brew", "install", "plain"))]
    rec = Recorder()
    res = tb.apply(steps, environ=e, run=rec)
    assert rec.calls == [("brew", "install", "plain")]
    assert [(r.step.tool, r.reason) for r in res] == [("fuse", "system"), ("vc", "blocked"), ("plain", "")]
    assert "--system" in res[0].output and "fuse:" in res[1].output
    rec = Recorder()
    res = tb.apply(steps, environ=e, run=rec, allow_system=True)
    assert rec.calls == [("brew", "install", "--cask", "fuse"), ("brew", "install", "--cask", "vc"),
                         ("brew", "install", "plain")]
    assert not any(r.skipped for r in res)


def test_apply_runs_in_order_never_runs_manual_and_skips_after_a_failure(tmp_path):
    e = stub_progs(tmp_path, "brew", "git")
    steps = [tb.Step("lib", ("brew", "install", "lib")),
             tb.Step("app", ("git", "init", "/x"), after=("lib",)),
             tb.Step("app", ("git", "-C", "/x", "fetch"), after=("lib",)),
             tb.Step("man", None, "by hand"),
             tb.Step("other", ("brew", "install", "other")),
             tb.Step("other", ("brew", "install", "other-2"))]
    rec = Recorder(fail={("brew", "install", "lib"), ("brew", "install", "other")})
    res = tb.apply(steps, environ=e, run=rec)
    assert rec.calls == [("brew", "install", "lib"), ("brew", "install", "other")]
    assert [(r.step.tool, r.returncode, r.skipped) for r in res] == [
        ("lib", 1, False), ("app", None, True), ("app", None, True), ("man", None, True),
        ("other", 1, False), ("other", None, True)]
    assert "lib" in res[1].output and res[3].output.startswith("manual step")
    assert [r.reason for r in res] == ["", "blocked", "blocked", "manual", "", "blocked"]


def test_apply_runs_every_step_when_nothing_fails(tmp_path):
    e = stub_progs(tmp_path, "brew")
    rec = Recorder()
    tb.apply([tb.Step("a", ("brew", "install", "a")), tb.Step("b", ("brew", "install", "b"), after=("a",))],
             environ=e, run=rec)
    assert rec.calls == [("brew", "install", "a"), ("brew", "install", "b")]


def test_stub_marker_past_the_window_is_not_a_stub(tmp_path):
    p = tmp_path / "pbin" / "brew"
    p.parent.mkdir()
    p.write_text("#!/bin/sh\n" + "#" * (tb.STUB_MARKER_WINDOW + 10) + "\n# ctf-toolbox-stub\n")
    p.chmod(0o755)
    with pytest.raises(tb.ToolboxError, match="not a test stub"):
        tb.apply([tb.Step("a", ("brew", "install", "a"))],
                 environ={"PATH": str(p.parent), "CTF_TESTING": "1"}, run=Recorder())


# ------------------------------------------------------------------------------- render

def test_brewfile_lists_formulae_then_casks_and_names_the_rest():
    tools = [tool("a"), tool("c", install_method="cask", install_target="c-app"), tool("b"),
             ctool(), tool("m", install_method="manual", install_target="by hand")]
    text = tb.render_brewfile(tools)
    lines = [ln for ln in text.splitlines() if not ln.startswith("#")]
    assert lines == ['brew "a"', 'brew "b"', 'cask "c-app"']
    assert f"#   fxd: git clone https://example.invalid/fxd at {PIN}" in text and "#   m: by hand" in text
    text = tb.render_brewfile([tool("fuse", install_method="cask", install_target="fuse-app", system=True)])
    assert 'cask "fuse-app"  # system: ' in text and "--system" in text


def test_capabilities_render_ends_with_the_toolbox_section():
    text = capabilities.render()
    assert text.endswith(capabilities._toolbox_section(ROOT)) and "\n## Binary toolbox\n" in text


def test_capabilities_section_without_a_manifest_says_why(tmp_path):
    assert "No toolbox manifest: gone" in tb.capabilities_section(None, missing_reason="gone")
    assert "No toolbox manifest" in capabilities._toolbox_section(tmp_path)
    write_manifest(tmp_path / "tools" / "toolbox.toml", GOOD + 'provides = "alpha | beta"\n')
    sec = capabilities._toolbox_section(tmp_path)
    assert "| `a` | core | alpha \\| beta |" in sec and "brew `a`" in sec


# ------------------------------------------------------------------------------- doctor

def doctor_root(tmp_path, body) -> Path:
    write_manifest(tmp_path / "root" / "tools" / "toolbox.toml", body)
    return tmp_path / "root"


TWO = """\
[[tool]]
name = "tbx-alpha"
kind = "binary"
role = "core"
bins = ["tbx-alpha"]
version_args = ["--version"]
install = { brew = "tbx-alpha" }

[[tool]]
name = "tbx-opt"
kind = "binary"
role = "optional"
bins = ["tbx-opt"]
install = { manual = "by hand" }
"""


def test_doctor_toolbox_ok_warn_and_fail(tmp_path):
    root = doctor_root(tmp_path, TWO)
    e = env_with(tmp_path / "bin")
    c = doctor.check_toolbox(e, root=root)
    assert c.status == "warn" and "tbx-alpha missing" in c.detail and "toolbox install" in c.fix
    exe(tmp_path / "bin" / "tbx-alpha", "echo 1.0\n")
    c = doctor.check_toolbox(e, root=root)
    assert c.status == "ok" and "1/2 ok" in c.detail and "optional: tbx-opt missing" in c.detail
    bad = doctor_root(tmp_path / "bad", "[[tool]]\nname = 1\n")
    c = doctor.check_toolbox(e, root=bad)
    assert c.status == "fail" and "toolbox manifest" in c.detail


def toolbox_check(cs) -> doctor.Check:
    c, = [c for c in cs if c.name == "toolbox"]
    return c


def test_run_checks_can_skip_the_toolbox_and_says_so(tmp_path, monkeypatch):
    from test_preflight_doctor import profile
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))         # the allowance check reads the workdir
    c = toolbox_check(doctor.run_checks(profile(), codex=False, toolbox=False))
    assert c.status == "skip" and "unverified" in c.detail


def test_run_checks_gives_the_toolbox_its_run(tmp_path, monkeypatch):
    """A caller that injects `run` keeps host programs out of the toolbox probes too."""
    from test_preflight_doctor import profile
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "w"))
    root = doctor_root(tmp_path, TWO)
    flag = tmp_path / "ran-for-real"
    exe(tmp_path / "bin" / "tbx-alpha", f'touch "{flag}"\necho 1.0\n')
    calls = []

    def rec(argv, **kw):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "tbx 3.2.1\n", "")
    cs = doctor.run_checks(profile(), codex=False, environ=env_with(tmp_path / "bin"), root=root, run=rec)
    assert calls == [[str(tmp_path / "bin" / "tbx-alpha"), "--version"]] and not flag.exists()
    c = toolbox_check(cs)
    assert c.status == "ok", c.line()


def test_ctf_doctor_host_tools_leave_the_toolbox_tools_to_the_toolbox_check(monkeypatch, capsys, tmp_path):
    """Each toolbox tool is checked once: by the `toolbox` check, not again in the carried host-tools list."""
    import shutil
    import subprocess as sp
    from ctf import cli, config

    class Done:
        returncode, stdout, stderr = 1, "", ""
    monkeypatch.setattr(sp, "run", lambda *a, **k: Done())
    monkeypatch.setattr(shutil, "which", lambda t, **k: None)
    monkeypatch.setattr(doctor, "check_toolbox", lambda *a, **k: doctor.Check("toolbox", "ok", "stubbed"))
    monkeypatch.setattr(config, "load", lambda: config.Config(base_url="https://demo.example", token=None,
                                                              team_id=None, workdir=tmp_path / "w"))
    monkeypatch.setenv("CTF_EVENT", "pink")
    cli.main(["doctor", "--no-codex"])
    out = capsys.readouterr().out
    host = out[out.index("host tools:"):out.index("host extras")]
    assert "] ghidraRun" in host                                  # the carried list is still there
    for t in tb.load():
        assert f"] {t.name} " not in host, t.name
    assert "`toolbox` check" in host


# ------------------------------------------------------------------------------- CLI

def run_ctf(*args, env):
    return subprocess.run([sys.executable, "-m", "ctf", "toolbox", *args], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=120)


def cli_env(tmp_path, **extra) -> dict:
    e = {k: v for k, v in os.environ.items() if k in ("HOME", "TMPDIR", "LANG")}
    e.update(PATH=f"{tmp_path / 'bin'}:{tmp_path / 'pbin'}:{SYS_PATH}", CTF_TESTING="1",
             CTF_TOOLBOX_DIR=str(tmp_path / "tools"), CTF_WORKDIR=str(tmp_path / "work"), CTF_EVENT="csctf")
    e.update(extra)
    return e


def test_cli_verify_exit_codes_and_json(tmp_path):
    m = write_manifest(tmp_path / "t.toml", TWO)
    e = cli_env(tmp_path)
    r = run_ctf("--manifest", str(m), "verify", env=e)
    assert r.returncode == 1 and "TOOLBOX PROBLEMS: tbx-alpha" in r.stdout, r.stdout + r.stderr
    assert "\n          fix: brew install tbx-alpha\n" in r.stdout, r.stdout     # the operator's next step
    exe(tmp_path / "bin" / "tbx-alpha", "echo tbx 4.5.6\n")
    r = run_ctf("--manifest", str(m), "verify", "--json", env=e)
    assert r.returncode == 0, r.stdout + r.stderr            # the optional tool is missing: still a pass
    doc = json.loads(r.stdout)
    assert doc["passed"] and {t["name"]: t["state"] for t in doc["tools"]} == {"tbx-alpha": "ok",
                                                                               "tbx-opt": "missing"}
    r = run_ctf("--manifest", str(m), "verify", "--only", "ghost", env=e)
    assert r.returncode == 2 and "unknown toolbox tool" in r.stderr


def test_cli_install_is_a_dry_run_by_default(tmp_path):
    m = write_manifest(tmp_path / "t.toml", TWO)
    log = tmp_path / "brew.log"
    exe(tmp_path / "pbin" / "brew", f'echo "$@" >> "{log}"\n', stub=True)
    r = run_ctf("--manifest", str(m), "install", env=cli_env(tmp_path))
    assert r.returncode == 1 and "DRY RUN" in r.stdout and "brew install tbx-alpha" in r.stdout
    assert "MANUAL: by hand" in r.stdout and not log.exists()


def test_cli_install_apply_runs_stubs_then_verifies_again(tmp_path):
    m = write_manifest(tmp_path / "t.toml", TWO)
    log = tmp_path / "brew.log"
    # the stub "installs" by writing the tool the re-verify then finds
    exe(tmp_path / "pbin" / "brew",
        f'echo "$@" >> "{log}"\nprintf \'#!/bin/sh\\necho 7.0.1\\n\' > "{tmp_path / "bin"}/$2"\n'
        f'chmod +x "{tmp_path / "bin"}/$2"\n', stub=True)
    (tmp_path / "bin").mkdir()
    r = run_ctf("--manifest", str(m), "install", "--apply", "--json", env=cli_env(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    doc = json.loads(r.stdout)
    assert log.read_text().split("\n")[0] == "install tbx-alpha"
    assert {t["name"]: t["state"] for t in doc["after"]}["tbx-alpha"] == "ok"
    assert [x["skipped"] for x in doc["results"]] == [False, True]      # the manual step never ran


def test_cli_install_apply_refuses_a_real_brew_under_testing(tmp_path):
    m = write_manifest(tmp_path / "t.toml", TWO)
    log = tmp_path / "brew.log"
    exe(tmp_path / "pbin" / "brew", f'echo "$@" >> "{log}"\n', stub=False)
    r = run_ctf("--manifest", str(m), "install", "--apply", env=cli_env(tmp_path))
    assert r.returncode == 2 and "not a test stub" in r.stderr and not log.exists()


SYS = """\
[[tool]]
name = "tbx-fuse"
kind = "binary"
role = "core"
bins = ["tbx-fuse"]
install = { cask = "tbx-fuse" }
system = true

[[tool]]
name = "tbx-plain"
kind = "binary"
role = "core"
bins = ["tbx-plain"]
install = { brew = "tbx-plain" }
"""


def installing_brew(tmp_path, log):
    """A stub brew that "installs" by writing the last argument as a tool the re-verify finds."""
    (tmp_path / "bin").mkdir(exist_ok=True)
    exe(tmp_path / "pbin" / "brew",
        f'echo "$@" >> "{log}"\nfor a; do last="$a"; done\n'
        f'printf \'#!/bin/sh\\necho 1.0\\n\' > "{tmp_path / "bin"}/$last"\nchmod +x "{tmp_path / "bin"}/$last"\n',
        stub=True)


def test_cli_install_apply_runs_a_system_step_only_with_system(tmp_path):
    m = write_manifest(tmp_path / "t.toml", SYS)
    log = tmp_path / "brew.log"
    installing_brew(tmp_path, log)
    e = cli_env(tmp_path)
    r = run_ctf("--manifest", str(m), "install", env=e)
    assert r.returncode == 1 and "[SYSTEM: runs only with --system]" in r.stdout and not log.exists()
    r = run_ctf("--manifest", str(m), "install", "--system", env=e)
    assert r.returncode == 2 and "only means something with --apply" in r.stderr and not log.exists()
    r = run_ctf("--manifest", str(m), "install", "--apply", env=e)
    assert r.returncode == 1, r.stdout + r.stderr
    assert log.read_text().splitlines() == ["install tbx-plain"]            # the system cask never ran
    assert "system step(s) not run: tbx-fuse" in r.stderr and "STILL TO DO: tbx-fuse (missing)" in r.stdout
    r = run_ctf("--manifest", str(m), "install", "--apply", "--system", "--json", env=e)
    assert r.returncode == 0, r.stdout + r.stderr
    assert log.read_text().splitlines() == ["install tbx-plain", "install --cask tbx-fuse"]
    assert json.loads(r.stdout)["passed"]


def test_cli_install_apply_without_brew_runs_the_git_steps_and_names_brew(tmp_path):
    m = write_manifest(tmp_path / "t.toml", TWO + textwrap.dedent(f"""\

        [[tool]]
        name = "fxd"
        kind = "clone"
        role = "core"
        dest = "fxd"
        entry = "tool.py"
        rev = "{PIN}"
        install = {{ git = "https://example.invalid/fxd" }}
        """))
    log = tmp_path / "git.log"
    exe(tmp_path / "pbin" / "git", f'echo "$@" >> "{log}"\n', stub=True)        # no brew anywhere
    r = run_ctf("--manifest", str(m), "install", "--apply", "--json", env=cli_env(tmp_path))
    assert r.returncode == 2, r.stdout + r.stderr
    assert "brew not found on PATH" in r.stderr
    assert [ln.split()[0] for ln in log.read_text().splitlines()] == ["init", "-C", "-C"]
    by = {x["tool"]: x["reason"] for x in json.loads(r.stdout)["results"]}
    assert by == {"tbx-alpha": "absent", "tbx-opt": "manual", "fxd": ""}


def test_cli_brewfile_prints_and_checks_the_committed_file(tmp_path):
    e = cli_env(tmp_path)
    r = run_ctf("brewfile", env=e)
    assert r.returncode == 0 and r.stdout == tb.render_brewfile(tb.load())
    r = run_ctf("brewfile", "--check", env=e)
    assert r.returncode == 0 and "is current" in r.stdout
    r = run_ctf("--manifest", str(write_manifest(tmp_path / "t.toml", TWO)), "brewfile", "--check", env=e)
    assert r.returncode == 2 and "drop --manifest" in r.stderr


def test_cli_brewfile_check_fails_when_stale_or_missing_and_write_fixes_it(tmp_path, monkeypatch, capsys):
    import argparse
    from ctf.cli import toolbox as cmd
    target = tmp_path / "Brewfile"
    monkeypatch.setattr(tb, "brewfile_path", lambda root=None: target)

    def go(*argv):
        p = argparse.ArgumentParser()
        cmd.add_arguments(p)
        return cmd.run(p.parse_args(list(argv)))
    assert go("brewfile", "--check") == 1 and "missing" in capsys.readouterr().err
    target.write_text("brew \"old\"\n")
    assert go("brewfile", "--check") == 1 and "stale" in capsys.readouterr().err
    assert go("brewfile", "--write") == 0
    assert target.read_text() == tb.render_brewfile(tb.load())
    assert go("brewfile", "--check") == 0
