"""B-005: code-enforced manual mode (Spooky-type events): no automated platform call, a drop folder."""
from __future__ import annotations

import socket

import pytest

from ctf import env, event
from ctf.platform import (NotAllowed, NotSupported, PlatformError, SubmitStatus, adapter_kind,
                          get_adapter, supports_instances)
from ctf.platform import ctfd, manual
from ctf.platform.base import PlatformAdapter


@pytest.fixture
def drop(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    d = tmp_path / "work" / "drop"
    (d / "haunted-pdf" / "sub").mkdir(parents=True)
    (d / "haunted-pdf" / "haunted.pdf").write_bytes(b"%PDF-1.7 boo")
    (d / "haunted-pdf" / "sub" / "extra.txt").write_text("extra")
    (d / "haunted-pdf" / "challenge.toml").write_text(
        'name = "Haunted PDF"\ncategory = "Forensics"\npoints = 300\n'
        'description = "Something lives in the PDF."\ntags = ["pdf"]\n')
    (d / "web-1").mkdir()
    (d / "web-1" / "SOLVED").write_text("max\n")
    (d / ".hidden").mkdir()
    return d


@pytest.fixture
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("manual mode opened a socket")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def test_spooky_selects_manual(drop):
    gate = get_adapter(event.load("spooky"))
    assert gate.kind == "manual" and isinstance(gate._adapter, manual.ManualAdapter)
    assert isinstance(gate._adapter, PlatformAdapter)


def test_gate_never_sends_and_raw_submit_raises(drop):
    gate = get_adapter(event.load("spooky"))
    res = gate.submit("haunted-pdf", "spooky{boo}", provenance="pdf stream 4", confirmed=True)
    assert res.status is SubmitStatus.NOT_ALLOWED and not res.sent and "manual" in res.message
    with pytest.raises(NotAllowed, match="manual"):
        gate._adapter.submit("haunted-pdf", "spooky{boo}")


@pytest.mark.parametrize("name", ["start_instance", "stop_instance", "instance_status"])
def test_instance_calls_raise_not_allowed(drop, name):
    gate = get_adapter(event.load("spooky"))
    assert not supports_instances(gate._adapter)
    with pytest.raises(NotAllowed, match="manual"):
        getattr(gate, name)("haunted-pdf")


def test_scoreboard_not_allowed(drop):
    with pytest.raises(NotAllowed):
        get_adapter(event.load("spooky")).scoreboard()


def test_reads_come_from_the_drop_folder_with_no_network(drop, no_network, tmp_path):
    gate = get_adapter(event.load("spooky"))
    chs = {c.id: c for c in gate.list_challenges()}
    assert set(chs) == {"haunted-pdf", "web-1"}
    h = chs["haunted-pdf"]
    assert (h.name, h.category, h.points, h.tags) == ("Haunted PDF", "Forensics", 300, ("pdf",))
    assert sorted(f.name for f in h.files) == ["haunted.pdf", "sub/extra.txt"]
    assert chs["web-1"].solved_by_team and chs["web-1"].name == "web-1"
    out = gate.download_files("haunted-pdf", tmp_path / "chal")
    assert sorted(p.relative_to(tmp_path / "chal").as_posix() for p in out) == ["haunted.pdf", "sub/extra.txt"]
    assert (tmp_path / "chal" / "haunted.pdf").read_bytes() == b"%PDF-1.7 boo"
    assert not (tmp_path / "chal" / "challenge.toml").exists()
    [solve] = gate.team_solves()
    assert (solve.challenge_id, solve.solver) == ("web-1", "max")


def test_missing_drop_folder_names_the_path(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "empty"))
    gate = get_adapter(event.load("spooky"))
    with pytest.raises(PlatformError, match=str(tmp_path / "empty" / "drop")):
        gate.list_challenges()


def test_missing_challenge_and_bad_ids(drop):
    a = manual.make_adapter(event.load("spooky"))
    with pytest.raises(PlatformError, match="no drop folder for challenge 'ghost'"):
        a.get_challenge("ghost")
    for bad in ("../etc", ".hidden", "a/b", ""):
        with pytest.raises(PlatformError, match="not a usable"):
            a.download_files(bad, drop.parent / "x")


def test_bad_metadata_is_an_error(drop):
    (drop / "web-1" / "challenge.toml").write_text('name = "W"\nflag = "spooky{x}"\n')
    a = manual.make_adapter(event.load("spooky"))
    with pytest.raises(PlatformError, match="unknown key 'flag'"):
        a.get_challenge("web-1")
    (drop / "web-1" / "challenge.toml").write_text('points = "many"\n')
    with pytest.raises(PlatformError, match="points must be a int"):
        a.get_challenge("web-1")


def test_symlinks_are_refused(drop, tmp_path):
    secret = tmp_path / "outside.txt"
    secret.write_text("not for the drop folder")
    (drop / "haunted-pdf" / "link.txt").symlink_to(secret)
    a = manual.make_adapter(event.load("spooky"))
    with pytest.raises(PlatformError, match="symlink"):
        a.download_files("haunted-pdf", tmp_path / "chal")


def test_dest_inside_drop_folder_is_refused(drop):
    a = manual.make_adapter(event.load("spooky"))
    with pytest.raises(PlatformError, match="inside the drop folder"):
        a.download_files("haunted-pdf", drop / "haunted-pdf" / "out")


def _profile_with(tmp_path, slug, old, new):
    src = event.load(slug).path.read_text()
    for o, n in zip(old, new):
        assert o in src
        src = src.replace(o, n)
    (tmp_path / slug).mkdir()
    (tmp_path / slug / "event.toml").write_text(src)
    return event.load(slug, root=tmp_path)


def test_ai_forbidden_on_a_ctfd_event_selects_manual(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    prof = _profile_with(tmp_path, "pink", ['submit_mode = "auto"', 'ai_on_platform = "allowed"'],
                         ['submit_mode = "manual"', 'ai_on_platform = "forbidden"'])
    assert prof.platform.kind == "ctfd" and adapter_kind(prof) == "manual"
    gate = get_adapter(prof)
    assert gate.kind == "manual"
    with pytest.raises(NotAllowed):
        ctfd.make_adapter(prof)       # defence in depth: the CTFd adapter itself refuses


def test_manual_submit_mode_on_ctfd_keeps_reads_but_never_submits(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    monkeypatch.setenv("CTF_TOKEN", "tok")
    for name in ("CTF_PLATFORM_URL", *env.legacy_names("CTF_PLATFORM_URL")):
        monkeypatch.delenv(name, raising=False)
    prof = _profile_with(tmp_path, "pink", ['submit_mode = "auto"'], ['submit_mode = "manual"'])
    gate = get_adapter(prof)
    assert gate.kind == "ctfd"
    res = gate.submit("1", "PINK{x}", provenance="p", confirmed=True)
    assert res.status is SubmitStatus.NOT_ALLOWED and "manual" in res.message and not res.sent


def test_not_allowed_is_a_not_supported():
    assert issubclass(NotAllowed, NotSupported)
