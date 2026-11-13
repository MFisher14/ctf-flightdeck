"""B-001 contracts: ctf.env (CTF_* canonical, legacy names warn) and ctf.paths (one resolver)."""
from __future__ import annotations

import warnings
from pathlib import Path

import pytest

from ctf import env, paths


def test_canonical_name_wins_without_warning():
    e = {"CTF_REALDATA": "/new", "HUNTRESS_REALDATA": "/old"}
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert env.get("CTF_REALDATA", environ=e) == "/new"


def test_prefix_legacy_name_is_read_and_warns():
    with pytest.warns(DeprecationWarning, match="HUNTRESS_REALDATA is deprecated; set CTF_REALDATA"):
        assert env.get("CTF_REALDATA", environ={"HUNTRESS_REALDATA": "/old"}) == "/old"
    with pytest.warns(DeprecationWarning, match="CSCTF_DOCKER"):
        assert env.get("CTF_DOCKER", environ={"CSCTF_DOCKER": "x"}) == "x"


def test_explicit_renames_cover_names_that_changed_more_than_the_prefix():
    with pytest.warns(DeprecationWarning, match="HUNTRESS_GM_URL"):
        assert env.get("CTF_PLATFORM_URL", environ={"HUNTRESS_GM_URL": "https://gm.example"}) == "https://gm.example"
    with pytest.warns(DeprecationWarning, match="CSCTF_URL"):
        assert env.get("CTF_PLATFORM_URL", environ={"CSCTF_URL": "https://c.example"}) == "https://c.example"
    # explicit rename is tried before the generic prefix swap
    assert env.legacy_names("CTF_TOKEN")[:2] == ("CSCTF_TOKEN", "HUNTRESS_GM_TOKEN")


def test_empty_counts_as_unset_and_default_applies():
    assert env.get("CTF_X_UNSET", "d", environ={"CTF_X_UNSET": ""}) == "d"


def test_non_canonical_lookup_is_refused():
    with pytest.raises(ValueError, match="canonical"):
        env.get("HUNTRESS_REALDATA", environ={})


def test_bool_int_and_require_fail_loudly():
    assert env.get_bool("CTF_T", environ={"CTF_T": "yes"}) is True
    assert env.get_bool("CTF_T", environ={"CTF_T": "0"}) is False
    with pytest.raises(env.EnvError, match="not a boolean"):
        env.get_bool("CTF_T", environ={"CTF_T": "maybe"})
    assert env.get_int("CTF_N", environ={"CTF_N": " 7 "}) == 7
    with pytest.raises(env.EnvError, match="not an integer"):
        env.get_int("CTF_N", environ={"CTF_N": "seven"})
    with pytest.raises(env.EnvError, match="CTF_EVENT is not set"):
        env.require("CTF_EVENT", environ={})


# ------------------------------------------------------------------ paths

def test_repo_root_and_event_dir():
    root = paths.repo_root()
    assert (root / "ctf" / "paths.py").is_file()
    assert paths.event_dir("csctf") == root / "events" / "csctf"
    for bad in ("", "../x", ".hidden", "a/b"):
        with pytest.raises(ValueError):
            paths.event_dir(bad)


def test_workdir_env_override_wins(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "w"))
    assert paths.workdir() == (tmp_path / "w").resolve()
    assert not (tmp_path / "w").exists()          # resolving never creates
    assert paths.ensure_workdir().is_dir()


def test_workdir_default_is_per_event_and_outside_repo(monkeypatch):
    monkeypatch.delenv("CTF_WORKDIR", raising=False)
    monkeypatch.delenv("HUNTRESS_WORKDIR", raising=False)
    monkeypatch.delenv("CSCTF_WORKDIR", raising=False)
    w = paths.workdir("csctf")
    assert w == (Path.home() / "ctf-work" / "csctf").resolve()
    assert paths.repo_root() not in w.parents


def test_workdir_without_override_or_event_fails_loudly(monkeypatch):
    from ctf import event
    for v in ("CTF_WORKDIR", "HUNTRESS_WORKDIR", "CSCTF_WORKDIR", "CTF_EVENT", "HUNTRESS_EVENT", "CSCTF_EVENT"):
        monkeypatch.delenv(v, raising=False)
    # four profiles ship under events/, so "the only profile" is ambiguous
    with pytest.raises(event.EventError, match="set CTF_EVENT"):
        paths.workdir()
    monkeypatch.setenv("CTF_EVENT", "pink")
    assert paths.workdir().name == "pink"


def test_realdata_root_env_and_legacy(monkeypatch, tmp_path):
    monkeypatch.delenv("CTF_REALDATA", raising=False)
    monkeypatch.delenv("HUNTRESS_REALDATA", raising=False)
    assert paths.realdata_root() == (Path.home() / "2026-ctf-huntress/challenges/_realdata").resolve()
    monkeypatch.setenv("HUNTRESS_REALDATA", str(tmp_path))
    with pytest.warns(DeprecationWarning):
        assert paths.realdata_root() == tmp_path.resolve()
    monkeypatch.setenv("CTF_REALDATA", str(tmp_path / "missing"))
    with pytest.raises(FileNotFoundError, match="CTF_REALDATA"):
        paths.require_realdata()
