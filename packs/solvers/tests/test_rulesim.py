"""B-190: the brief rules simulation (ctf/rulesim.py). Every brief here is synthetic text, every
fence is built under tmp_path (its own fake home), and nothing a brief names is ever run."""
from __future__ import annotations

import os
import textwrap
from pathlib import Path

import pytest

from ctf import fence, rulesim
from ctf.rulesim import Action


@pytest.fixture
def tree(tmp_path):
    home = tmp_path / "home"
    repo = home / "ctf-tools"
    ws = home / "ctf-work" / "demo"
    drop = home / "Downloads" / "demo"
    for d in (repo, ws, drop):
        d.mkdir(parents=True)
    f = fence.build(repo=repo, workspace=ws, home=home, drop=drop, user_dir=None)
    return f


def claude(f, mode="default", settings=None):
    return rulesim.ClaudeRules.from_settings(settings if settings is not None else f.claude_settings(),
                                             cwd=f.workspace, home=f.home, mode=mode)


def codex(f, tmp_roots=()):
    return rulesim.CodexRules.from_fence(f, tmp_roots=tmp_roots)


def one(rules, kind, text, via="", cwd=""):
    return rules.decide(Action(kind, text, 1, via=via, cwd=cwd))


# ------------------------------------------------------------------------------- extraction

def test_shell_block_lines_are_commands_with_continuations_prompts_and_comments():
    acts = rulesim.extract(textwrap.dedent("""\
        Intro.
        ```bash
        # a comment
        $ python3 -I solve.py \\
            --input a.bin
        ls

        ```
        """))
    cmds = [(a.text, a.line) for a in acts if a.kind == "command"]
    assert cmds == [("python3 -I solve.py      --input a.bin", 4), ("ls", 6)]


def test_console_and_untagged_blocks_count_only_prompt_lines():
    acts = rulesim.extract(textwrap.dedent("""\
        ```console
        $ cat notes.txt
        some output line
        ```
        ```
        plain text, not a command
        $ ls -la
        ```
        ```python
        import os
        ```
        """))
    assert [a.text for a in acts if a.kind == "command"] == ["cat notes.txt", "ls -la"]


def test_inline_spans_commands_paths_and_bare_files_on_write_lines():
    acts = rulesim.extract(textwrap.dedent("""\
        Run `python3 -m ctf sweep 12` first.
        Write the flag to `flag.txt` and save notes in `~/ctf-work/demo/notes.md`.
        Read `/opt/wordlists/a.txt` and `config.toml` and see `https://x.example/a/b`; pass `--fast`.
        """))
    got = [(a.kind, a.text, a.line) for a in acts if not a.via]
    assert got == [("command", "python3 -m ctf sweep 12", 1), ("write", "flag.txt", 2),
                   ("write", "~/ctf-work/demo/notes.md", 2), ("read", "/opt/wordlists/a.txt", 3)]


def test_command_paths_redirects_tee_cp_cd_and_scripts():
    a = Action("command", "cd sub && FOO=1 ./run.sh in/a.bin > out/r.txt 2>&1 | tee -a log/x.txt", 3)
    got = [(p.kind, p.text, p.cwd) for p in rulesim.command_paths(a)]
    assert ("write", "out/r.txt", "sub") in got and ("write", "log/x.txt", "sub") in got
    assert ("read", "in/a.bin", "sub") in got and ("read", "./run.sh", "sub") in got
    assert not any(p[1] == "1" for p in got)                          # 2>&1 is not a file
    cp = [(p.kind, p.text) for p in rulesim.command_paths(Action("command", "cp ~/a/b.txt /opt/c", 1))]
    assert cp == [("write", "/opt/c"), ("read", "~/a/b.txt")]
    assert all(p.line == 3 and p.via == a.text for p in rulesim.command_paths(a))


def test_segments_split_on_shell_operators():
    assert rulesim.segment_texts("a x && b ; c || d | e & f") == ["a x", "b", "c", "d", "e", "f"]
    assert rulesim.segments("make 2> build.log") == [["make", ">", "build.log"]]   # the fd digit goes


def test_extract_refuses_a_dump():
    with pytest.raises(rulesim.RulesError, match="larger than"):
        rulesim.extract("x" * (rulesim.MAX_BRIEF_BYTES + 1))


def test_find_briefs_file_folder_and_missing(tmp_path):
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "a" / "codex_brief-x.md").write_text("x")
    (tmp_path / "a" / "b" / "brief.md").write_text("x")
    (tmp_path / "a" / "notes.md").write_text("x")
    assert [p.name for p in rulesim.find_briefs(tmp_path / "a")] == ["brief.md", "codex_brief-x.md"]
    assert rulesim.find_briefs(tmp_path / "a" / "notes.md") == [tmp_path / "a" / "notes.md"]
    with pytest.raises(FileNotFoundError, match="not found"):
        rulesim.find_briefs(tmp_path / "nope")


# ------------------------------------------------------------------------------- Bash rules

@pytest.mark.parametrize("spec,seg,want", [
    ("log show *", "log show --last 1h", True), ("log show *", "log show", True),
    ("log show *", "logger show", False), ("log show", "log show", True), ("log show", "log show x", False),
    ("npm run test:*", "npm run test --x", True), ("npm run test:*", "npm run tester", False),
    ("git * main", "git push origin main", True), ("git * main", "git push origin dev", False),
    (None, "anything at all", True),
])
def test_bash_rule_matching(spec, seg, want):
    assert rulesim.bash_rule_matches(spec, seg) is want


def settings(allow=(), deny=(), ask=(), sandbox=True, auto=None, **perms):
    sb = {"enabled": sandbox, "filesystem": {"allowWrite": [], "denyWrite": [], "denyRead": []}}
    if auto is not None:
        sb["autoAllowBashIfSandboxed"] = auto
    return {"permissions": {"allow": list(allow), "deny": list(deny), "ask": list(ask), **perms}, "sandbox": sb}


def test_claude_bash_deny_beats_ask_beats_allow_on_any_sub_command(tree):
    s = settings(allow=["Bash(cat *)", "Bash(rm *)"], deny=["Bash(rm *)"], ask=["Bash(curl *)"], sandbox=False)
    r = claude(tree, settings=s)
    assert one(r, "command", "cat a && rm b").verdict == "deny"
    assert one(r, "command", "cat a | curl x").verdict == "prompt"
    assert one(r, "command", "cat a").verdict == "allow"
    assert one(r, "command", "cat a; ls").verdict == "prompt"      # ls has no allow rule, no sandbox


def test_claude_sandbox_auto_allow_and_modes(tree):
    assert one(claude(tree, settings=settings()), "command", "ls").verdict == "allow"
    assert one(claude(tree, settings=settings(auto=False)), "command", "ls").verdict == "prompt"
    assert one(claude(tree, settings=settings(sandbox=False), mode="dontAsk"), "command", "ls").verdict == "deny"
    assert one(claude(tree, settings=settings(), mode="plan"), "command", "ls").verdict == "deny"
    with pytest.raises(rulesim.RulesError, match="bypassPermissions"):
        claude(tree, mode="bypassPermissions")
    with pytest.raises(rulesim.RulesError, match="unknown Claude permission mode"):
        claude(tree, mode="yolo")
    with pytest.raises(rulesim.RulesError, match="permissions.allow"):
        claude(tree, settings={"permissions": {"allow": "Bash(*)"}})


def test_fence_deny_commands_are_denied_for_both_harnesses(tree):
    for r in (claude(tree), codex(tree)):
        assert one(r, "command", "cd x && log show --last 1h").verdict == "deny", r.label
        assert one(r, "command", "tmutil listlocalsnapshots /").verdict == "deny", r.label
        assert one(r, "command", "python3 -I solve.py").verdict == "allow", r.label


# ------------------------------------------------------------------------------- file tools

def test_claude_file_tool_writes_depend_on_mode_and_rules(tree):
    ws = tree.workspace
    assert one(claude(tree), "write", "flag.txt").verdict == "prompt"          # default asks every edit
    assert one(claude(tree, mode="acceptEdits"), "write", "flag.txt").verdict == "allow"
    assert one(claude(tree, mode="acceptEdits"), "write", str(tree.repo / "x.py")).verdict == "allow"
    assert one(claude(tree, mode="acceptEdits"), "write", "/opt/x").verdict == "prompt"   # outside
    assert one(claude(tree, mode="acceptEdits"), "write", str(tree.repo / "analysis" / "x")).verdict == "deny"
    assert one(claude(tree, mode="acceptEdits"), "write", str(ws / "c" / ".ctf" / "t")).verdict == "deny"
    s = settings(allow=[f"Edit(/{ws}/**)"])
    assert one(claude(tree, settings=s), "write", "notes/a.md").verdict == "allow"


def test_claude_file_tool_reads(tree):
    r = claude(tree)
    assert one(r, "read", "a.bin").verdict == "allow"
    assert one(r, "read", str(tree.drop / "chal.zip")).verdict == "allow"      # exempt drop folder
    d = one(r, "read", "~/.codex/config.toml")
    assert d.verdict == "deny" and "deny rule Read(" in d.reason
    assert one(r, "read", "/opt/wordlists/a.txt").verdict == "deny"            # blockReadsOutside...
    s = tree.claude_settings()
    s["permissions"] = dict(s["permissions"], blockReadsOutsideWorkingDirectories=False, deny=[])
    assert one(claude(tree, settings=s), "read", "/opt/wordlists/a.txt").verdict == "prompt"


def test_claude_sandboxed_bash_paths(tree):
    r = claude(tree)
    cmd = "x"
    assert one(r, "write", "out.txt", via=cmd).verdict == "allow"
    assert one(r, "write", str(tree.repo / "notes.md"), via=cmd).verdict == "allow"
    assert one(r, "write", str(tree.repo / "analysis" / "a"), via=cmd).verdict == "deny"   # denyWrite
    assert one(r, "write", "/opt/x", via=cmd).verdict == "deny"
    assert one(r, "read", "~/Downloads/other/a", via=cmd).verdict == "deny"
    assert one(r, "read", str(tree.drop / "a"), via=cmd).verdict == "allow"   # allowRead re-opens it
    assert one(r, "read", str(tree.workspace / "1" / ".ctf" / "token"), via=cmd).verdict == "deny"
    assert one(r, "read", "/usr/share/dict/words", via=cmd).verdict == "allow"


def test_cd_moves_the_cwd_of_later_relative_paths(tree):
    r = claude(tree)
    d = one(r, "read", "config.toml", via="cd ~/.codex && cat config.toml", cwd="~/.codex")
    assert d.verdict == "deny" and ".codex" in d.reason


def test_tmp_spellings_are_one_path(tree):
    s = settings(allow=["Edit(//tmp/work/**)"])
    s["sandbox"]["filesystem"]["allowWrite"] = ["/tmp/work"]
    r = claude(tree, settings=s)
    assert one(r, "write", "/private/tmp/work/a", via="x").verdict == "allow"
    assert one(r, "write", "/private/tmp/other/a", via="x").verdict == "deny"
    assert one(r, "write", "/private/tmp/work/a").verdict == "allow"           # the Edit rule's spelling
    assert one(r, "write", "/private/tmp/other/a").verdict == "prompt"


def test_a_less_specific_allow_read_does_not_reopen_a_deny(tmp_path):
    home = tmp_path / "home"
    repo, ws = home / "ctf-tools", home / "ctf-work" / "demo"
    for d in (repo, ws):
        d.mkdir(parents=True)
    f = fence.build(repo=repo, workspace=ws, home=home, user_dir=None, strict_home=True, toolchain=())
    r = claude(f)
    assert one(r, "read", str(repo / "solvers" / "a.py"), via="x").verdict == "allow"   # allowRead beats $HOME
    assert one(r, "read", str(repo / "analysis" / "a"), via="x").verdict == "deny"      # deeper deny wins
    assert one(r, "read", str(home / "other" / "a"), via="x").verdict == "deny"


# ------------------------------------------------------------------------------- Codex

def test_codex_most_specific_entry_wins(tree):
    r = codex(tree)
    assert one(r, "read", str(tree.drop / "a")).verdict == "allow"
    assert one(r, "read", "~/Downloads/other/a").verdict == "deny"
    assert one(r, "write", str(tree.repo / "x.py")).verdict == "allow"
    assert one(r, "write", str(tree.repo / "analysis" / "x")).verdict == "deny"
    assert one(r, "read", str(tree.workspace / "c" / ".ctf" / "t")).verdict == "deny"
    assert one(r, "write", str(tree.drop / "a")).verdict == "deny"            # read-only root
    assert one(r, "write", "/opt/x").verdict == "deny"
    assert one(r, "read", "/opt/x").verdict == "allow"                        # :workspace reads


def test_codex_temp_roots_are_writable(tree, tmp_path):
    t = tmp_path / "scratch"
    t.mkdir()
    assert one(codex(tree, tmp_roots=[t]), "write", str(t / "a")).verdict == "allow"
    assert one(codex(tree, tmp_roots=[]), "write", str(t / "a")).verdict == "deny"


# ------------------------------------------------------------------------------- end to end

def test_simulate_and_blocking_background_vs_interactive(tree):
    brief = textwrap.dedent("""\
        Save the flag to `flag.txt`.
        ```bash
        python3 -I ~/ctf-tools/solvers/x.py a.bin > out.txt
        ```
        """)
    rows = rulesim.simulate(rulesim.extract(brief), [claude(tree), codex(tree)])
    bad_bg = rulesim.blocking(rows, background=True)
    assert [(d.harness, d.action.text) for d in bad_bg] == [("claude (default)", "flag.txt")]
    assert rulesim.blocking(rows, background=False) == []
    rows = rulesim.simulate(rulesim.extract(brief), [claude(tree, mode="acceptEdits"), codex(tree)])
    assert rulesim.blocking(rows) == []


# ------------------------------------------------------------------------------- B-190 round 1 fixes

def test_auto_mode_denies_still_deny_and_prompts_go_to_the_classifier(tree):
    r = claude(tree, mode="auto")
    assert r.label == "claude (auto)"
    d = one(r, "write", "flag.txt")                                     # in the workspace: no prompt
    assert d.verdict == "allow" and "(auto)" in d.reason
    d = one(r, "write", "/opt/x")                                       # outside: classifier, not prompt
    assert d.verdict == "classifier" and "approximate" in d.reason
    assert one(r, "write", str(tree.repo / "analysis" / "x")).verdict == "deny"     # Edit deny rule
    assert one(r, "read", "~/.codex/config.toml").verdict == "deny"
    assert one(r, "command", "log show --last 1h").verdict == "deny"                # Bash deny rule
    s = settings(allow=["Bash(cat *)"], ask=["Bash(curl *)"], sandbox=False)
    u = claude(tree, mode="auto", settings=s)
    assert one(u, "command", "cat a").verdict == "allow"
    assert one(u, "command", "curl x").verdict == "classifier"
    assert one(u, "command", "ls").verdict == "classifier"
    rows = rulesim.simulate([Action("write", "/opt/x", 1)], [r])
    assert rulesim.blocking(rows, background=True) == []                # never a blocking prompt


def test_the_launch_mode_is_the_mode_the_launchers_pass():
    import argparse
    import re as _re
    from ctf import paths
    from ctf.cli import preflight
    sh = (paths.repo_root() / "tools" / "pink_launch.sh").read_text(encoding="utf-8")
    m = _re.search(r'^PERMISSION_MODE="\$\{PERMISSION_MODE:-([A-Za-z]+)\}"', sh, _re.M)
    assert m, "tools/pink_launch.sh no longer sets a PERMISSION_MODE default"
    assert m.group(1) == rulesim.LAUNCH_PERMISSION_MODE
    doc = (paths.repo_root() / "docs" / "fence.md").read_text(encoding="utf-8")
    assert f"--permission-mode {rulesim.LAUNCH_PERMISSION_MODE}" in doc
    assert rulesim.LAUNCH_PERMISSION_MODE in rulesim.CLAUDE_MODES
    p = argparse.ArgumentParser()
    preflight.add_arguments(p)
    assert p.parse_args([]).permission_mode == rulesim.LAUNCH_PERMISSION_MODE
    assert p.parse_args(["--permission-mode", "auto"]).permission_mode == "auto"


def test_claude_sandbox_cwd_is_a_write_root_on_its_own(tree):
    r = claude(tree, settings=settings())                   # sandbox on, allowWrite empty
    d = one(r, "write", "out.txt", via="x")
    assert d.verdict == "allow" and "write root" in d.reason
    assert one(r, "write", str(tree.workspace / "c" / "a.bin"), via="x").verdict == "allow"
    assert one(r, "write", str(tree.repo / "x.py"), via="x").verdict == "deny"     # not in allowWrite now


def test_allow_read_at_the_same_path_reopens_a_plain_deny_but_not_a_glob(tree):
    s = settings()
    data = str(tree.home / "data")
    s["sandbox"]["filesystem"].update(denyRead=[data, "/**/.secret"], allowRead=[data, "/**/.secret"])
    r = claude(tree, settings=s)
    d = one(r, "read", str(tree.home / "data" / "a"), via="x")
    assert d.verdict == "allow" and "allowRead" in d.reason          # emitted after the deny: it wins
    assert one(r, "read", str(tree.home / "x" / ".secret" / "a"), via="x").verdict == "deny"   # glob re-emitted


def test_codex_read_only_entry_inside_a_write_root_refuses_writes(tree, tmp_path):
    ws = tree.workspace
    t = tmp_path / "scratch"
    t.mkdir()
    r = rulesim.CodexRules(fsmap={str(ws / "ro"): "read", str(t / "ro"): "read"}, cwd=ws, home=tree.home,
                           tmp_roots=(t,))
    d = one(r, "write", str(ws / "ro" / "x"))
    assert d.verdict == "deny" and "read-only" in d.reason
    assert one(r, "write", str(t / "ro" / "x")).verdict == "deny"
    assert one(r, "write", str(ws / "rw" / "x")).verdict == "allow"
    assert one(r, "read", str(ws / "ro" / "x")).verdict == "allow"


def test_launcher_briefs_are_the_launcher_locations_only(tmp_path):
    wd = tmp_path / "work"
    (wd / "1-web" / "files" / "deep").mkdir(parents=True)
    (wd / "1-web" / "codex_brief.md").write_text("x")
    (wd / "1-web" / "codex_brief-r1.md").write_text("x")
    (wd / "1-web" / "files" / "evil_brief.md").write_text("x")          # challenge-supplied: data
    (wd / "1-web" / "files" / "deep" / "codex_brief.md").write_text("x")
    (wd / "1-web" / "notes_brief.md").write_text("x")
    (wd / "codex_brief.md").write_text("x")                              # not in a challenge folder
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "elsewhere" / "codex_brief.md").write_text("x")
    (wd / "2-link").symlink_to(tmp_path / "elsewhere")
    (wd / "1-web" / "codex_brief-link.md").symlink_to(tmp_path / "elsewhere" / "codex_brief.md")
    got = rulesim.launcher_briefs(wd)
    assert got == [wd / "1-web" / "codex_brief-r1.md", wd / "1-web" / "codex_brief.md"]
    with pytest.raises(FileNotFoundError, match="event workdir not found"):
        rulesim.launcher_briefs(tmp_path / "nope")


def test_read_brief_checks_the_size_before_reading(tmp_path):
    big = tmp_path / "codex_brief.md"
    with open(big, "wb") as fh:
        fh.truncate(rulesim.MAX_BRIEF_BYTES + 1)                       # sparse: nothing written
    with pytest.raises(rulesim.RulesError, match=f"is {rulesim.MAX_BRIEF_BYTES + 1} bytes.*not read"):
        rulesim.read_brief(big)                                       # refused on its size, before reading
    ok = tmp_path / "ok_brief.md"
    ok.write_bytes(b"```bash\nls\n```\n\xff")
    assert rulesim.read_brief(ok).startswith("```bash\nls")


def test_read_brief_reads_at_most_the_limit_when_the_file_grew(tmp_path, monkeypatch):
    big = tmp_path / "codex_brief.md"
    with open(big, "wb") as fh:
        fh.truncate(rulesim.MAX_BRIEF_BYTES + 1)
    small = os.stat_result((0o100644, 0, 0, 1, 0, 0, 10, 0, 0, 0))    # what the stat saw: 10 bytes
    monkeypatch.setattr(rulesim.Path, "stat", lambda self, **k: small)
    with pytest.raises(rulesim.RulesError, match="grew past"):
        rulesim.read_brief(big)
