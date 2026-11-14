"""An event's VPN file: kept for its owner only, the command that connects it, and whether
it looks connected. No test connects anything: every command is built, never run, and a
command a test did not answer itself fails the test (no_real_commands)."""

from __future__ import annotations

import hashlib
import json
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest
import typer
from typer.testing import CliRunner

from ctf_flightdeck import cli, vpn, vpn_cli
from ctf_flightdeck.leftovers import state_folder

WG = "[Interface]\nPrivateKey = c3ludGhldGljLW5vdC1hLWtleQ==\nAddress = 10.13.37.5/32, fd00::5/128\n[Peer]\nEndpoint = vpn.example.org:51820\n"
# the same file with a line wg-quick would run as root (line 4), an escape sequence in it
WG_ROOT = WG.replace("[Peer]", "PostUp = touch /tmp/synthetic \x1b[2K\n[Peer]")
OVPN = "client\nremote vpn.example.org 1194\n"
which = lambda tool: f"/opt/bin/{tool}"  # noqa: E731
nothing = lambda tool: None  # noqa: E731


@pytest.fixture(autouse=True)
def no_real_commands(monkeypatch):
    """No test here runs a command (sudo, ps, a package manager): one that reaches
    subprocess.run without a runner of its own fails."""
    def refuse(argv, **kw):
        raise AssertionError(f"a test ran a real command: {argv}")

    monkeypatch.setattr(subprocess, "run", refuse)


def kept(tmp_path, name="team.conf", text=WG, folder="event"):
    source = tmp_path / name
    source.write_text(text)
    return vpn.keep(tmp_path / folder, source)


def found_in(folder, name="vpn.conf", text=WG_ROOT):
    """A VPN file that is merely in a folder: nobody added it through flightdeck."""
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text(text)
    return vpn.find(folder)


def ps(commands):
    """A runner that answers `ps -p PID -o command=` from {pid: command line} (exit 1 for a
    pid it does not know, as ps does) and notes every command it was asked to run."""
    def run(argv, **kw):
        run.ran.append(list(argv))
        if argv[0] != "ps":
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        line = commands.get(int(argv[argv.index("-p") + 1]))
        return SimpleNamespace(returncode=0 if line else 1, stdout=f"{line}\n" if line else "", stderr="")

    run.ran = []
    return run


def started_as(found):
    """The command line of the OpenVPN that `flightdeck vpn up` starts for `found`."""
    return " ".join(vpn.up_command(found, which)[1:])


def terminal(monkeypatch, answer=None):
    """A player at a terminal who answers every yes/no question with `answer` (None: presses
    Enter, taking the default). Returns the (question, default) pairs asked."""
    asked = []

    def confirm(question, default=False, **kw):
        asked.append((question, default))
        return default if answer is None else answer

    monkeypatch.setattr(typer, "confirm", confirm)
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: True))
    return asked


def runner(monkeypatch, commands=None):
    run = ps(commands or {})
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(vpn.shutil, "which", which)
    return run


def test_a_vpn_file_is_kept_in_the_events_folder_for_its_owner_only(tmp_path):
    found = kept(tmp_path)
    assert found.file == tmp_path / "event" / "vpn.conf" and found.kind == "wireguard"
    assert stat.S_IMODE(found.file.stat().st_mode) == 0o600 and found.file.read_text() == WG
    assert vpn.find(tmp_path / "event") == found and (tmp_path / "team.conf").exists()
    other = kept(tmp_path, "team.ovpn", "client\nremote vpn.example.org 1194\n")  # a new file replaces the old
    assert other.kind == "openvpn" and vpn.find(tmp_path / "event") == other and not found.file.exists()


def test_a_file_that_is_no_vpn_file_is_refused(tmp_path):
    (tmp_path / "notes.txt").write_text("x")
    with pytest.raises(vpn.VPNError, match="WireGuard .conf or an OpenVPN .ovpn"):
        vpn.keep(tmp_path / "event", tmp_path / "notes.txt")
    assert vpn.find(tmp_path / "event") is None
    (tmp_path / "team.conf").write_bytes(b"[Interface]\nPost\0Up = id\n")  # bash would read that as PostUp
    with pytest.raises(vpn.VPNError, match="NUL byte"):
        vpn.keep(tmp_path / "event", tmp_path / "team.conf")
    assert vpn.find(tmp_path / "event") is None


# ---- only a file the player added is connected


def test_a_kept_file_is_noted_as_added_by_its_path_and_hash_and_a_change_unverifies_it(tmp_path):
    found = kept(tmp_path)
    note = state_folder() / "vpn.json"
    assert json.loads(note.read_text()) == {str(found.file.resolve()): hashlib.sha256(WG.encode()).hexdigest()}
    assert stat.S_IMODE(note.stat().st_mode) == 0o600
    assert vpn.added(found) is True
    found.file.write_text(WG_ROOT)  # changed since it was added (something appended a PostUp)
    assert vpn.added(found) is False
    assert "unverified" in vpn.unverified(found) and f"flightdeck vpn add {found.folder} {found.file}" in vpn.unverified(found)
    again = vpn.keep(found.folder, found.file)  # the player read it and adds it again, from where it is
    assert again == found and vpn.added(found) is True and found.file.read_text() == WG_ROOT
    merely_there = found_in(tmp_path / "board", text=WG)  # the same bytes, in a folder nobody added them to
    assert vpn.added(merely_there) is False


def test_a_note_that_cannot_be_read_verifies_nothing_and_one_that_cannot_be_written_is_said(tmp_path, monkeypatch):
    found = kept(tmp_path)
    (state_folder() / "vpn.json").write_text("not json")
    assert vpn.added(found) is False
    (tmp_path / "blocked").write_text("a file where the state folder's parent would be")
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "blocked"))
    with pytest.raises(vpn.VPNError, match="could not note that you added it .* stays unverified"):
        kept(tmp_path)
    assert vpn.added(found) is False


@pytest.mark.parametrize("change", ["never added", "changed since"])
def test_vpn_up_runs_nothing_for_a_file_that_is_unverified_even_with_yes(tmp_path, monkeypatch, change):
    if change == "never added":
        found = found_in(tmp_path / "event", text=WG)
    else:
        found = kept(tmp_path)
        found.file.write_text(WG_ROOT)
    run = runner(monkeypatch)
    monkeypatch.setattr(vpn, "connected", lambda *a, **k: False)
    result = CliRunner().invoke(cli.app, ["vpn", "up", str(found.folder), "--yes"])
    assert result.exit_code == 2 and run.ran == []
    assert "unverified" in result.output and f"flightdeck vpn add {found.folder} {found.file}" in result.output


def test_play_never_offers_to_connect_a_vpn_file_it_merely_found(tmp_path, monkeypatch, capsys):
    asked = terminal(monkeypatch)  # the player presses Enter at whatever is asked
    run = runner(monkeypatch)
    monkeypatch.setattr(vpn, "connected", lambda *a, **k: False)
    board = found_in(tmp_path / "board").folder  # a board somebody shared, with a vpn.conf in it
    assert cli._vpn_ready(board, ask=True) is True
    said = capsys.readouterr().err
    assert asked == [] and run.ran == []
    assert "unverified" in said and "flightdeck vpn add" in said and "was not connected" in said
    assert "touch /tmp/synthetic" not in said  # nothing of a file nobody added is shown
    added = kept(tmp_path)  # the same question for a file the player added: offered, Enter connects
    monkeypatch.setattr(vpn, "connected", lambda *a, **k: bool(run.ran))  # up once its command has run
    assert cli._vpn_ready(added.folder, ask=True) is True
    assert asked == [("Run it?", True)] and run.ran == [["sudo", "/opt/bin/wg-quick", "up", str(added.file)]]


def test_play_says_a_found_vpn_file_is_unverified_and_goes_on(tmp_path, monkeypatch):
    from ctf_flightdeck import run as runs

    runner(monkeypatch)
    found_in(tmp_path / "board")
    monkeypatch.setattr(runs, "prepare_run", lambda options: (_ for _ in ()).throw(runs.RunError("stopped by the test")))
    result = CliRunner().invoke(cli.app, ["play", str(tmp_path / "board")])
    assert "unverified" in result.output and "flightdeck vpn add" in result.output and "stopped by the test" in result.output


# ---- what the file would run as root


@pytest.mark.parametrize(("text", "lines", "down"), [
    (WG, [], []),
    ("[Interface]\nPreUp = a\nPostUp = b\nPreDown = c\nPostDown = d\n", [2, 3, 4, 5], [4, 5]),
    ("[Interface]\n  postup=b\n\tPOSTDOWN\t= d\r\nPostUp\x0b= e\n", [2, 3, 4], [3]),  # any case, any spacing, as wg-quick reads keys
    ("[Interface]\n# PostUp = b\nAddress = 10.0.0.2/32 # PostUp = b\nPostUpper = x\n", [], []),  # a comment, and another key
    ("[Interface]\nPostUp # = b\n", [2], []),  # wg-quick cuts the comment first: the key is still PostUp
    ("\ufeff[Interface]\nDNS = 10.0.0.1\nPostUp = b", [3], []),  # no newline at the end
])
def test_the_wireguard_lines_that_run_a_program_as_root_are_listed(text, lines, down):
    assert [line.number for line in vpn.root_programs("wireguard", text.encode())] == lines
    assert [line.number for line in vpn.root_programs("wireguard", text.encode(), down=True)] == down


@pytest.mark.parametrize("line", [
    "up /etc/openvpn/up.sh", "down x", "route-up x", "route-pre-down x", "ipchange x", "tls-verify x", "auth-user-pass-verify x via-env",
    "client-connect x", "client-disconnect x", "learn-address x", "tls-crypt-v2-verify x", "plugin /tmp/synthetic.so", "pkcs11-providers /tmp/x.so",
    "engine /tmp/x.so", "iproute /tmp/ip", "config /tmp/more.ovpn", "setenv LD_PRELOAD /tmp/x.so",
    "script-security 2", "script-security 3", "script-security 2 execve", "script-security",
    "  --up x", "\tup\tx", '"up" x', "'up' x", "u\\p x", "UP x", "setenv opt up x", "setenv opt setenv opt plugin x", "<plugin>",
    "up x\r",
])
def test_the_openvpn_directives_that_run_a_program_as_root_are_listed(line):
    found = vpn.root_programs("openvpn", f"client\n{line}\nremote vpn.example.org 1194\n".encode())
    assert [(entry.number, entry.text) for entry in found] == [(2, line.rstrip("\r"))]
    assert vpn.root_programs("openvpn", f"{line}\n".encode(), down=True) == []  # an OpenVPN is stopped by signal: the file is not read
    marked = vpn.root_programs("openvpn", b"\xef\xbb\xbf" + f"{line}\nnobind\n".encode())  # OpenVPN skips a byte order mark
    assert [entry.number for entry in marked] == [1]


@pytest.mark.parametrize("line", [
    "client", "remote vpn.example.org 1194", "script-security 1", "script-security 0", "# up x", "; up x", "#up x", "upper x", "dev tun",
    "setenv opt block-outside-dns", "setenv-safe NAME value", "remote-cert-tls server", "</plugin>", "<ca>", "verb 3 # up x", "auth-user-pass",
])
def test_an_openvpn_line_that_runs_nothing_is_not_listed(line):
    assert vpn.root_programs("openvpn", f"{line}\nnobind\n".encode()) == []


def test_an_openvpn_line_too_long_to_be_read_as_one_is_listed_with_the_reason():
    padded = "# " + "a" * 300 + " up /tmp/x"  # OpenVPN reads 255 bytes of it as a comment and the rest as a line of its own
    (found,) = vpn.root_programs("openvpn", f"client\n{padded}\n".encode())
    assert (found.number, found.text) == (2, padded) and "longer than OpenVPN reads" in found.note
    assert vpn.root_programs("openvpn", ("# " + "a" * 250 + "\n").encode()) == []


def test_a_line_is_shown_as_written_with_what_a_terminal_would_act_on_escaped():
    assert vpn.shown("PostUp = echo 'ok' \x1b[2K\rPostUp = x\u202e\t\x07") == "PostUp = echo 'ok' \\x1b[2K\\rPostUp = x\\u202e\\t\\x07"
    assert vpn.shown("up /usr/local/bin/école.sh") == "up /usr/local/bin/école.sh"


def test_vpn_up_shows_the_lines_that_run_as_root_and_asks_with_no_as_the_default_whatever_yes_says(tmp_path, monkeypatch, capsys):
    found = kept(tmp_path, text=WG_ROOT)
    run = runner(monkeypatch)
    monkeypatch.setattr(vpn, "connected", lambda *a, **k: False)
    asked = terminal(monkeypatch)  # Enter: the default
    assert vpn_cli.connect(found, yes=True) == 1
    said = capsys.readouterr().out
    assert run.ran == [] and [default for _, default in asked] == [False] and "root" in asked[0][0]
    assert "  line 4: PostUp = touch /tmp/synthetic \\x1b[2K" in said and "\x1b" not in said
    assert "sudo /opt/bin/wg-quick up" in said and "not connected" in said
    assert "c3ludGhldGlj" not in said  # the private key's line runs nothing: it is not shown
    terminal(monkeypatch, answer=True)  # the player read the line and says yes
    monkeypatch.setattr(vpn, "connected", lambda *a, **k: None)
    assert vpn_cli.connect(found, yes=False) == 0
    assert run.ran == [["sudo", "/opt/bin/wg-quick", "up", str(found.file)]]


@pytest.mark.parametrize(("name", "text", "shown"), [
    ("team.conf", WG_ROOT, ["line 4: PostUp = touch /tmp/synthetic"]),
    ("team.ovpn", "client\nscript-security 2\nup /tmp/synthetic-up.sh\n", ["line 2: script-security 2", "line 3: up /tmp/synthetic-up.sh"]),
])
def test_with_no_terminal_a_file_that_runs_programs_as_root_is_refused_even_with_yes(tmp_path, monkeypatch, name, text, shown):
    found = kept(tmp_path, name, text)
    run = runner(monkeypatch)
    monkeypatch.setattr(vpn, "connected", lambda *a, **k: False)
    result = CliRunner().invoke(cli.app, ["vpn", "up", str(found.folder), "--yes"])
    assert result.exit_code == 2 and run.ran == []
    assert "refused" in result.output and "runs programs as root" in result.output and "no terminal to ask at" in result.output
    assert all(line in result.output for line in shown)
    monkeypatch.setattr(vpn.shutil, "which", lambda tool: "/opt/bin/brew" if tool == "brew" else None)  # the file's tool is missing
    monkeypatch.setattr(vpn.sys, "platform", "darwin")
    result = CliRunner().invoke(cli.app, ["vpn", "up", str(found.folder), "--yes"])
    assert result.exit_code == 2 and "refused" in result.output and run.ran == []  # nothing is installed for a file that is refused


def test_vpn_add_shows_the_lines_that_would_run_as_root(tmp_path, monkeypatch):
    runner(monkeypatch)
    (tmp_path / "team.conf").write_text(WG_ROOT)
    result = CliRunner().invoke(cli.app, ["vpn", "add", str(tmp_path / "event"), str(tmp_path / "team.conf")])
    assert result.exit_code == 0, result.output
    assert "line 4: PostUp = touch /tmp/synthetic \\x1b[2K" in result.output and "ask before anything runs" in result.output
    (tmp_path / "plain.conf").write_text(WG)
    result = CliRunner().invoke(cli.app, ["vpn", "add", str(tmp_path / "event"), str(tmp_path / "plain.conf")])
    assert result.exit_code == 0 and "as root" not in result.output


def test_vpn_down_checks_a_wireguard_file_as_up_does(tmp_path, monkeypatch):
    plain = kept(tmp_path)
    run = runner(monkeypatch)
    result = CliRunner().invoke(cli.app, ["vpn", "down", str(plain.folder)])
    assert result.exit_code == 0 and run.ran == [["sudo", "/opt/bin/wg-quick", "down", str(plain.file)]]
    run.ran.clear()
    plain.file.write_text(WG.replace("[Peer]", "PostDown = touch /tmp/synthetic\n[Peer]"))  # changed since it was added
    result = CliRunner().invoke(cli.app, ["vpn", "down", str(plain.folder)])
    assert result.exit_code == 2 and run.ran == [] and "unverified" in result.output
    hooked = kept(tmp_path, text=WG.replace("[Peer]", "PostUp = touch /tmp/up\nPostDown = touch /tmp/synthetic\n[Peer]"))
    result = CliRunner().invoke(cli.app, ["vpn", "down", str(hooked.folder)])  # added, but wg-quick down runs its PostDown as root
    assert result.exit_code == 2 and run.ran == [] and "refused" in result.output
    assert "line 5: PostDown = touch /tmp/synthetic" in result.output and "touch /tmp/up" not in result.output


# ---- the commands


def test_the_command_that_connects_names_the_tool_the_file_and_sudo_and_a_missing_tool_says_how_to_get_it(tmp_path):
    wg = kept(tmp_path)
    assert vpn.up_command(wg, which) == ["sudo", "/opt/bin/wg-quick", "up", str(wg.file)]
    assert vpn.down_command(wg, which) == ["sudo", "/opt/bin/wg-quick", "down", str(wg.file)]
    with pytest.raises(vpn.VPNError, match="wg-quick is not on this machine: .*wireguard-tools"):
        vpn.up_command(wg, nothing)
    ovpn = kept(tmp_path, "team.ovpn", "client\n")
    argv = vpn.up_command(ovpn, which)
    assert argv[:4] == ["sudo", "/opt/bin/openvpn", "--config", str(ovpn.file)] and "--daemon" in argv
    assert argv[argv.index("--writepid") + 1] == str(ovpn.folder / "vpn.pid")
    with pytest.raises(vpn.VPNError, match="no OpenVPN that flightdeck started"):
        vpn.down_command(ovpn, which)
    (ovpn.folder / "vpn.pid").write_text("4242\n")
    assert vpn.down_command(ovpn, which, run=ps({4242: started_as(ovpn)})) == ["sudo", "kill", "4242"]


def test_a_vpn_named_by_a_relative_path_is_handed_to_its_tool_by_its_full_path(tmp_path, monkeypatch):
    found = kept(tmp_path)
    monkeypatch.chdir(found.folder)
    for target in (found.folder.parent / "event" / ".." / "event", tmp_path / "event" / "vpn.conf"):
        assert vpn.named(target) == found
    assert vpn.named(type(tmp_path)("vpn.conf")) == found  # `wg-quick up vpn.conf` would read /etc/wireguard instead
    assert vpn.find(type(tmp_path)(".")) == found


@pytest.mark.parametrize("name", ["vpn.pid", "vpn.log"])
def test_openvpn_is_not_started_to_write_through_a_link_as_root(tmp_path, name):
    ovpn = kept(tmp_path, "team.ovpn", OVPN)
    (tmp_path / "elsewhere").write_text("another file\n")
    (ovpn.folder / name).symlink_to(tmp_path / "elsewhere")
    with pytest.raises(vpn.VPNError, match=f"{name} is a link or a folder.*as root"):
        vpn.up_command(ovpn, which)


@pytest.mark.parametrize(("listing", "state"), [
    ("utun4: flags=8051\n\tinet 10.13.37.5 --> 10.13.37.5 netmask 0xffffffff\n", True),
    ("en0: flags=8863\n\tinet 10.13.37.50 netmask 0xffffff00\n", False),  # another address that only starts the same
    ("", None),  # this machine's interfaces could not be listed
])
def test_wireguard_is_connected_when_an_interface_has_the_files_address(tmp_path, listing, state):
    run = lambda argv, **kw: SimpleNamespace(returncode=0 if listing else 1, stdout=listing)  # noqa: E731
    assert vpn.connected(kept(tmp_path), run=run, which=which) is state


# ---- the OpenVPN flightdeck started: its pid file is checked before it is believed


def test_openvpn_is_connected_while_the_process_flightdeck_started_runs(tmp_path):
    ovpn = kept(tmp_path, "team.ovpn", OVPN, folder="my event")  # a folder with a space in its name
    assert vpn.connected(ovpn, run=ps({})) is None  # started another way, or not at all: it cannot be told
    (ovpn.folder / "vpn.pid").write_text("4242\n")
    run = ps({4242: started_as(ovpn)})
    assert vpn.connected(ovpn, run=run) is True and vpn.started(ovpn, run=run) == (4242, "")
    assert run.ran[0] == ["ps", "-ww", "-p", "4242", "-o", "command="]
    assert (ovpn.folder / "vpn.pid").exists()


@pytest.mark.parametrize(("noted", "commands", "why"), [
    ("4242", {}, "is not running"),  # after a reboot, or OpenVPN stopped
    ("4242", {4242: "/usr/sbin/sshd -D"}, "is not an OpenVPN that flightdeck started"),  # the number went to another process
    ("4242", {4242: "/opt/bin/openvpn --config /etc/openvpn/other.ovpn --daemon --writepid /run/o.pid --log /var/log/o.log"},
     "is not an OpenVPN that flightdeck started"),  # an OpenVPN, of another file
    ("4242", {4242: "/bin/sh -c openvpn"}, "is not an OpenVPN that flightdeck started"),
    ("1", {1: "/sbin/init"}, "does not hold a process number"),
    ("-4242", {}, "does not hold a process number"),  # kill would read that as a process group
    ("4242 1", {}, "does not hold a process number"),
    ("²", {}, "does not hold a process number"),  # a digit to str.isdigit, not a number
    ("", {}, "does not hold a process number"),
])
def test_a_stale_or_foreign_pid_is_not_connected_is_removed_and_is_never_killed(tmp_path, noted, commands, why):
    ovpn = kept(tmp_path, "team.ovpn", OVPN)
    note = ovpn.folder / "vpn.pid"
    note.write_text(noted)
    run = ps(commands)
    assert vpn.connected(ovpn, run=run) is False and not note.exists()
    assert vpn.connected(ovpn, run=run) is None  # the stale note is gone: nothing is noted now
    note.write_text(noted)
    with pytest.raises(vpn.VPNError, match=f"{why}.*stale note was removed. Nothing was stopped"):
        vpn.down_command(ovpn, which, run=run)
    assert not note.exists() and all(argv[0] == "ps" for argv in run.ran)


def test_a_process_ps_cannot_name_is_neither_believed_nor_killed_and_the_reason_is_said(tmp_path):
    ovpn = kept(tmp_path, "team.ovpn", OVPN)
    (ovpn.folder / "vpn.pid").write_text("4242")

    def no_ps(argv, **kw):
        raise FileNotFoundError(2, "No such file or directory", "ps")

    for run in (no_ps, lambda argv, **kw: SimpleNamespace(returncode=2, stdout="", stderr="ps: bad usage")):
        with pytest.raises(vpn.VPNError, match="cannot tell what process 4242 is: `ps -ww -p 4242 -o command=`"):
            vpn.connected(ovpn, run=run)
        with pytest.raises(vpn.VPNError, match="cannot tell what process 4242 is"):
            vpn.down_command(ovpn, which, run=run)
    assert (ovpn.folder / "vpn.pid").read_text() == "4242"  # not known to be stale: left as it was


def test_vpn_down_kills_only_the_openvpn_flightdeck_started(tmp_path, monkeypatch):
    ovpn = kept(tmp_path, "team.ovpn", OVPN)
    note = ovpn.folder / "vpn.pid"
    note.write_text("4242\n")
    run = runner(monkeypatch, {4242: "/usr/libexec/synthetic-daemon --serve"})  # the pid is another program's now
    result = CliRunner().invoke(cli.app, ["vpn", "down", str(ovpn.folder)])
    assert result.exit_code == 2 and "Nothing was stopped" in result.output and not note.exists()
    assert [argv for argv in run.ran if argv[0] != "ps"] == []
    result = CliRunner().invoke(cli.app, ["vpn", "status", str(ovpn.folder)])
    assert "cannot tell whether it is connected" in result.output
    note.write_text("4242\n")
    run = runner(monkeypatch, {4242: started_as(ovpn)})
    result = CliRunner().invoke(cli.app, ["vpn", "status", str(ovpn.folder)])
    assert result.exit_code == 0 and "looks connected" in result.output
    result = CliRunner().invoke(cli.app, ["vpn", "down", str(ovpn.folder)])
    assert result.exit_code == 0 and "disconnected" in result.output
    assert [argv for argv in run.ran if argv[0] != "ps"] == [["sudo", "kill", "4242"]]
    assert not note.exists()  # OpenVPN leaves its pid file: flightdeck clears it, so the next status is not misled


def test_the_status_never_shows_what_the_file_holds(tmp_path, monkeypatch):
    found = kept(tmp_path)
    monkeypatch.setattr(vpn, "connected", lambda *a, **k: False)
    result = CliRunner().invoke(cli.app, ["vpn", "status", str(tmp_path / "event")])
    assert result.exit_code == 1 and "is NOT connected" in result.output and f"flightdeck vpn up {found.folder}" in result.output
    assert "c3ludGhldGlj" not in result.output and "10.13.37.5" not in result.output


def test_vpn_up_shows_the_command_and_runs_nothing_without_a_yes(tmp_path, monkeypatch):
    kept(tmp_path)
    monkeypatch.setattr(vpn, "connected", lambda *a, **k: False)
    monkeypatch.setattr(vpn.shutil, "which", which)
    ran = []
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: ran.append(argv) or SimpleNamespace(returncode=0))
    result = CliRunner().invoke(cli.app, ["vpn", "up", str(tmp_path / "event")])  # no terminal to ask at
    assert result.exit_code == 2 and "sudo /opt/bin/wg-quick up" in result.output and ran == []
    result = CliRunner().invoke(cli.app, ["vpn", "up", str(tmp_path / "event"), "--yes"])
    assert ran == [["sudo", "/opt/bin/wg-quick", "up", str(tmp_path / "event" / "vpn.conf")]]


def test_vpn_commands_on_a_folder_with_no_vpn_file_say_how_to_add_one(tmp_path):
    result = CliRunner().invoke(cli.app, ["vpn", "status", str(tmp_path)])
    assert result.exit_code == 2 and "flightdeck vpn add" in result.output


def test_play_says_an_events_vpn_is_down_before_the_run_starts(tmp_path, monkeypatch):
    from ctf_flightdeck import run as runs
    from ctf_flightdeck import start

    start.write(tmp_path / "event", start.EventAnswers(name="One", platform="manual"))
    kept(tmp_path)
    monkeypatch.setattr(vpn, "connected", lambda *a, **k: False)
    monkeypatch.setattr(runs, "prepare_run", lambda options: (_ for _ in ()).throw(runs.RunError("stopped by the test")))
    result = CliRunner().invoke(cli.app, ["play", str(tmp_path / "event")])
    assert "is NOT connected" in result.output and "cannot reach this event's live targets" in result.output
    assert "stopped by the test" in result.output  # nobody to ask: said, and the run goes on to start


@pytest.mark.parametrize(("platform", "have", "argv"), [
    ("darwin", {"brew"}, ["brew", "install", "wireguard-tools"]),
    ("darwin", set(), None),
    ("linux", {"apt-get", "dnf"}, ["sudo", "apt-get", "install", "-y", "wireguard-tools"]),
    ("linux", {"pacman"}, ["sudo", "pacman", "-S", "--noconfirm", "wireguard-tools"]),
])
def test_the_install_command_is_this_machines_package_managers(tmp_path, platform, have, argv):
    assert vpn.install_command(kept(tmp_path), platform, lambda tool: tool if tool in have else None) == argv


def test_a_missing_vpn_tool_is_installed_on_a_yes_before_connecting_and_never_without_one(tmp_path, monkeypatch):
    ovpn = kept(tmp_path, "team.ovpn", "client\n")
    have = {"brew"}
    monkeypatch.setattr(vpn.shutil, "which", lambda tool: f"/opt/bin/{tool}" if tool in have else None)
    monkeypatch.setattr(vpn.sys, "platform", "darwin")
    monkeypatch.setattr(vpn, "install_command", lambda found: ["brew", "install", "openvpn"])
    monkeypatch.setattr(vpn, "connected", lambda *a, **k: None)
    ran = []

    def run(argv, **kw):
        ran.append(argv)
        if argv[0] == "brew":
            have.add("openvpn")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", run)
    result = CliRunner().invoke(cli.app, ["vpn", "up", str(ovpn.folder)])  # nobody to ask
    assert result.exit_code == 2 and "brew install openvpn" in result.output and ran == []
    result = CliRunner().invoke(cli.app, ["vpn", "up", str(ovpn.folder), "--yes"])
    assert result.exit_code == 0, result.output
    assert ran[0] == ["brew", "install", "openvpn"] and ran[1][:2] == ["sudo", "/opt/bin/openvpn"]
    assert "installed openvpn" in result.output


def test_with_no_package_manager_the_missing_tool_is_named_and_nothing_runs(tmp_path, monkeypatch):
    found = kept(tmp_path)
    monkeypatch.setattr(vpn.shutil, "which", lambda tool: None)
    monkeypatch.setattr(vpn, "connected", lambda *a, **k: False)
    result = CliRunner().invoke(cli.app, ["vpn", "up", str(found.folder), "--yes"])
    assert result.exit_code == 2 and "wg-quick is not on this machine" in result.output and "no package" in result.output
