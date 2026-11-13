"""An event's VPN file: kept for its owner only, the command that connects it, and whether
it looks connected. No test connects anything: every command is built, never run."""

from __future__ import annotations

import stat
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from ctf_flightdeck import cli, vpn

WG = "[Interface]\nPrivateKey = c3ludGhldGljLW5vdC1hLWtleQ==\nAddress = 10.13.37.5/32, fd00::5/128\n[Peer]\nEndpoint = vpn.example.org:51820\n"
which = lambda tool: f"/opt/bin/{tool}"  # noqa: E731
nothing = lambda tool: None  # noqa: E731


def kept(tmp_path, name="team.conf", text=WG):
    source = tmp_path / name
    source.write_text(text)
    return vpn.keep(tmp_path / "event", source)


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
    assert vpn.down_command(ovpn, which) == ["sudo", "kill", "4242"]


@pytest.mark.parametrize(("listing", "state"), [
    ("utun4: flags=8051\n\tinet 10.13.37.5 --> 10.13.37.5 netmask 0xffffffff\n", True),
    ("en0: flags=8863\n\tinet 10.13.37.50 netmask 0xffffff00\n", False),  # another address that only starts the same
    ("", None),  # this machine's interfaces could not be listed
])
def test_wireguard_is_connected_when_an_interface_has_the_files_address(tmp_path, listing, state):
    run = lambda argv, **kw: SimpleNamespace(returncode=0 if listing else 1, stdout=listing)  # noqa: E731
    assert vpn.connected(kept(tmp_path), run=run, which=which) is state


def test_openvpn_is_connected_while_the_process_flightdeck_started_lives(tmp_path):
    ovpn = kept(tmp_path, "team.ovpn", "client\n")
    assert vpn.connected(ovpn) is None  # started another way, or not at all: it cannot be told
    (ovpn.folder / "vpn.pid").write_text("4242")
    assert vpn.connected(ovpn, alive=lambda pid: pid == 4242) is True
    assert vpn.connected(ovpn, alive=lambda pid: False) is False


def test_the_status_never_shows_what_the_file_holds(tmp_path, monkeypatch):
    found = kept(tmp_path)
    monkeypatch.setattr(vpn, "connected", lambda *a, **k: False)
    result = CliRunner().invoke(cli.app, ["vpn", "status", str(tmp_path / "event")])
    assert result.exit_code == 1 and "is NOT connected" in result.output and f"flightdeck vpn up {found.folder}" in result.output
    assert "c3ludGhldGlj" not in result.output and "10.13.37.5" not in result.output


def test_vpn_up_shows_the_command_and_runs_nothing_without_a_yes(tmp_path, monkeypatch):
    import subprocess

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
