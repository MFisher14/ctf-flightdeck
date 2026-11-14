"""The player's keys file: keys kept outside the repository, readable by the owner only, never shown."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ctf_flightdeck.config import ConfigError, api_key, load_config
from ctf_flightdeck import keys as keyfile
from ctf_flightdeck.keys import KeysError, environment, load_keys, source
from ctf_flightdeck.setup import Answers, doctor, report, write_config

SECRET = "value-that-must-never-show-5150"


@pytest.fixture
def keys(tmp_path, monkeypatch):
    path = tmp_path / "keys.env"
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(path))
    monkeypatch.delenv("FLIGHTDECK_TEST_KEY", raising=False)

    def write(text: str, mode: int = 0o600) -> Path:
        path.write_text(text)
        path.chmod(mode)
        return path

    return write


def test_the_keys_file_reads_names_comments_export_and_quotes(keys):
    path = keys(f'# my keys\n\nexport FLIGHTDECK_TEST_KEY="{SECRET}"\nOTHER = \'two words\'\nPLAIN=x=y\n')
    assert load_keys(path) == {"FLIGHTDECK_TEST_KEY": SECRET, "OTHER": "two words", "PLAIN": "x=y"}


def test_no_keys_file_is_no_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(tmp_path / "absent.env"))
    assert load_keys() == {}


def test_a_keys_file_others_can_read_is_refused_naming_the_fix(keys):
    path = keys(f"FLIGHTDECK_TEST_KEY={SECRET}\n", mode=0o644)
    with pytest.raises(KeysError, match=f"other users can read it; keep it to yourself with: chmod 600 {path}"):
        load_keys(path)


def test_a_bad_line_is_named_by_number_never_by_its_text(keys):
    path = keys(f"FLIGHTDECK_TEST_KEY={SECRET}\n{SECRET}\n")
    with pytest.raises(KeysError) as caught:
        load_keys(path)
    assert "line 2 is not NAME=value" in str(caught.value) and SECRET not in str(caught.value)


def test_the_environment_wins_over_the_file(keys):
    keys("FLIGHTDECK_TEST_KEY=from-the-file\n")
    assert environment({"PATH": "/bin"})["FLIGHTDECK_TEST_KEY"] == "from-the-file"
    assert environment({"FLIGHTDECK_TEST_KEY": "from-the-shell"})["FLIGHTDECK_TEST_KEY"] == "from-the-shell"
    assert source("FLIGHTDECK_TEST_KEY", {}) == "keys file"
    assert source("FLIGHTDECK_TEST_KEY", {"FLIGHTDECK_TEST_KEY": "x"}) == "environment"


def test_the_api_key_comes_from_the_keys_file_and_doctor_says_where_without_showing_it(keys, tmp_path):
    keys(f"FLIGHTDECK_TEST_KEY={SECRET}\n")
    cfg = write_config(Answers("https://openrouter.ai/api/v1", "FLIGHTDECK_TEST_KEY", ("a/b",), "host"), tmp_path / "c.toml")
    assert api_key(load_config(cfg)) == SECRET
    checks = doctor(cfg, environ={"FLIGHTDECK_KEYS": os.environ["FLIGHTDECK_KEYS"]})
    found = {c.name: c for c in checks}["api key"]
    assert found.ok and found.detail == "FLIGHTDECK_TEST_KEY is set (in your keys file)"
    assert SECRET not in report(checks)[0]


def test_a_missing_key_says_to_put_it_in_the_keys_file(keys, tmp_path):
    keys("SOMETHING_ELSE=x\n")
    cfg = write_config(Answers("https://openrouter.ai/api/v1", "FLIGHTDECK_TEST_KEY", ("a/b",), "host"), tmp_path / "c.toml")
    with pytest.raises(ConfigError, match="put FLIGHTDECK_TEST_KEY=<your key> in .*keys.env \\(chmod 600\\), or export it"):
        api_key(load_config(cfg))


# ---------------------------------------------------------------------- saving a key


def kept(tmp_path, text: str = "# mine\nOPENROUTER_API_KEY=real\n") -> Path:
    path = tmp_path / "keys.env"
    path.write_text(text)
    path.chmod(0o600)
    return path


@pytest.mark.parametrize("separator", ["\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029", "\n", "\r"])
def test_a_value_with_any_line_break_in_it_is_refused_so_it_cannot_set_another_key(tmp_path, separator):
    """Every character the file is split into lines at (str.splitlines), not only a newline:
    what follows one would be read as a line of its own."""
    path = kept(tmp_path)
    before = path.read_bytes()
    with pytest.raises(KeysError) as caught:
        keyfile.save("CTFD_TOKEN_X", f"{SECRET}{separator}OPENROUTER_API_KEY=evil", path=path)
    assert "line break" in str(caught.value) and f"U+{ord(separator):04X}" in str(caught.value)
    assert "evil" not in str(caught.value) and SECRET not in str(caught.value)
    assert path.read_bytes() == before and load_keys(path) == {"OPENROUTER_API_KEY": "real"}


@pytest.mark.parametrize(("hidden", "said"), [("\x00", "control character"), ("\t", "control character"), ("\x1b", "control character"),
                                              ("\x7f", "control character"), ("\u200b", "invisible character"), ("\u202e", "invisible character"),
                                              ("\ud800", "invisible character")])
def test_a_value_with_a_control_or_invisible_character_is_refused_naming_the_kind_never_the_value(tmp_path, hidden, said):
    path = kept(tmp_path)
    before = path.read_bytes()
    with pytest.raises(KeysError) as caught:
        keyfile.save("CTFD_TOKEN_X", f"{SECRET}{hidden}tail", path=path)
    assert said in str(caught.value) and f"U+{ord(hidden):04X}" in str(caught.value)
    assert SECRET not in str(caught.value) and "tail" not in str(caught.value)
    assert path.read_bytes() == before
    assert sorted(entry.name for entry in tmp_path.iterdir()) == ["keys.env"]  # refused before the lock or a file is made


def test_what_a_value_cannot_be_is_said_before_a_save_in_the_same_words():
    assert keyfile.value_problem(SECRET) is None and keyfile.value_problem(f"  {SECRET}\n") is None  # the ends are trimmed
    assert keyfile.value_problem("   ") == "is empty"
    assert keyfile.value_problem(f'"{SECRET}"') == "is in quotes: give it without them"
    assert keyfile.value_problem("a\u2028b").startswith("has a line break in it (U+2028)")


def test_a_save_that_fails_leaves_the_keys_that_were_there_and_no_file_behind(tmp_path, monkeypatch):
    """The file is never emptied to be written again: a write that cannot finish (a full disk
    here) loses no key."""
    path = kept(tmp_path)
    before = path.read_bytes()

    def full(*args, **kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(keyfile.os, "fsync", full)
    with pytest.raises(KeysError, match="cannot write it \\(No space left on device\\)") as caught:
        keyfile.save("CTFD_TOKEN_X", SECRET, path=path)
    assert SECRET not in str(caught.value)
    assert path.read_bytes() == before
    assert sorted(entry.name for entry in tmp_path.iterdir()) == ["keys.env", "keys.env.lock"]


def test_a_save_puts_a_whole_new_file_in_place_so_a_reader_never_sees_half_of_one(tmp_path):
    path = kept(tmp_path)
    with open(path, encoding="utf-8") as reader:  # a run reading the keys while a save happens
        keyfile.save("CTFD_TOKEN_X", SECRET, path=path)
        assert reader.read() == "# mine\nOPENROUTER_API_KEY=real\n"  # the file it opened: whole, as it was
    assert path.read_text() == f"# mine\nOPENROUTER_API_KEY=real\nCTFD_TOKEN_X={SECRET}\n"
    assert path.stat().st_mode & 0o777 == 0o600


def test_a_save_waits_for_the_lock_and_says_so_when_another_save_holds_it(tmp_path):
    import fcntl

    path = kept(tmp_path)
    before = path.read_bytes()
    holder = os.open(tmp_path / "keys.env.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(holder, fcntl.LOCK_EX)  # another flightdeck in the middle of its save
        with pytest.raises(KeysError, match="another flightdeck is writing it") as caught:
            keyfile.save("CTFD_TOKEN_X", SECRET, path=path, wait=0.2)
        assert SECRET not in str(caught.value) and path.read_bytes() == before
    finally:
        os.close(holder)
    keyfile.save("CTFD_TOKEN_X", SECRET, path=path, wait=0.2)  # the lock went with its holder
    assert load_keys(path) == {"OPENROUTER_API_KEY": "real", "CTFD_TOKEN_X": SECRET}


def test_saves_at_the_same_time_each_keep_what_the_others_added(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    path = kept(tmp_path)
    names = [f"CTFD_TOKEN_{n}" for n in range(24)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda name: keyfile.save(name, f"value-of-{name}", path=path), names))
    assert load_keys(path) == {"OPENROUTER_API_KEY": "real", **{name: f"value-of-{name}" for name in names}}


def test_a_keys_file_that_is_a_link_stays_a_link_and_what_it_points_at_gets_the_key(tmp_path):
    real = tmp_path / "dotfiles" / "keys.env"
    real.parent.mkdir()
    real.write_text("OTHER=one\n")
    real.chmod(0o600)
    link = tmp_path / "config" / "keys.env"
    link.parent.mkdir()
    link.symlink_to(real)
    assert keyfile.save("CTFD_TOKEN_X", SECRET, path=link) == link
    assert link.is_symlink() and load_keys(real) == {"OTHER": "one", "CTFD_TOKEN_X": SECRET}
    assert real.stat().st_mode & 0o777 == 0o600
