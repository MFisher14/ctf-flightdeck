"""B-074: archive_passwords.add_many() and the `tools/password.py harvest` subcommand.

The store is the on-disk <workdir>/_passwords.json; CTF_WORKDIR is pointed at a temp dir so the test
writes nothing into a real store. Values are never printed by the CLI -- only masks and counts.
"""
import io
import zipfile

import pytest

import archive_passwords as ap
import password as pwcli


@pytest.fixture(autouse=True)
def _isolated_store(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    yield


def test_add_many_returns_only_the_new_values():
    new = ap.add_many(["alpha", "beta", "infected", "alpha"], source="harvest")
    assert new == ["alpha", "beta"]              # infected and the duplicate add nothing
    stored = set(ap.candidates())
    assert b"alpha" in stored and b"beta" in stored


def test_add_many_skips_unusable_values_without_raising():
    new = ap.add_many(["ok", "line\nbreak", "x" * 999, ""], source="harvest")
    assert new == ["ok"]                         # the newline, the overlong, and the empty are skipped


def test_harvest_command_stores_candidates_from_a_file_and_siblings(tmp_path, capsys):
    folder = tmp_path / "chal"
    folder.mkdir()
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        z.writestr("a.txt", "hi")
    (folder / "secret.zip").write_bytes(bio.getvalue() + b"\nOVERLAY_Pw_7\n")
    (folder / "note.txt").write_text("archive password: NOTE_Pw_8\n")
    rc = pwcli.main(["harvest", str(folder / "secret.zip")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "HARVEST secret.zip" in out
    stored = {c.decode() for c in ap.candidates()}
    assert "OVERLAY_Pw_7" in stored
    assert "NOTE_Pw_8" in stored
    # the raw value is never printed
    assert "OVERLAY_Pw_7" not in out and "NOTE_Pw_8" not in out


def test_harvest_command_no_siblings_flag(tmp_path, capsys):
    folder = tmp_path / "chal"
    folder.mkdir()
    (folder / "target.bin").write_bytes(b"\x00OWN_Pw_9\x00")
    (folder / "note.txt").write_text("SIBLING_Pw_X\n")
    assert pwcli.main(["harvest", str(folder / "target.bin"), "--no-siblings"]) == 0
    capsys.readouterr()
    stored = {c.decode() for c in ap.candidates()}
    assert "OWN_Pw_9" in stored
    assert "SIBLING_Pw_X" not in stored


def test_harvest_command_missing_file_errors():
    assert pwcli.main(["harvest", "/no/such/file.bin"]) == 2
