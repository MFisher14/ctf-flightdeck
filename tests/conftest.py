"""Shared test setup.

Textual reads a few environment variables that would make headless runs press keys or
take screenshots on their own; clear them so tests only see what they do themselves.
"""

from __future__ import annotations

import os

for _name in list(os.environ):
    if _name.startswith(("TEXTUAL_PRESS", "TEXTUAL_SCREENSHOT")):
        del os.environ[_name]
os.environ["_TYPER_FORCE_DISABLE_TERMINAL"] = "1"  # plain CLI output in CliRunner


import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def no_real_keys_file(tmp_path_factory, monkeypatch):
    """No test reads the player's real keys file: FLIGHTDECK_KEYS points at a file that does
    not exist, unless a test sets its own."""
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(tmp_path_factory.mktemp("keys") / "absent-keys.env"))


@pytest.fixture(autouse=True)
def own_state_folder(tmp_path_factory, monkeypatch):
    """Each test has a state folder of its own (XDG_STATE_HOME), never the player's: what a
    run notes there, and the containers a sweep may remove (leftovers.py), are the test's
    only. Commands a test starts get it through the environment they inherit."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path_factory.mktemp("state")))
