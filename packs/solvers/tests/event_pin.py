"""Run a whole test module under one event profile (docs/CONTRACTS.md: a test that needs another event
sets CTF_EVENT with monkeypatch).

    import event_pin
    event_pin.pin(globals(), "huntress")

Under pytest this defines an autouse fixture in the calling module that sets CTF_EVENT for each of its
tests (unittest.TestCase methods included) and restores it after, so the rest of the suite keeps its
default event. Run as a script (`python tests/test_x.py`), it sets CTF_EVENT for the process. The slug
must name a shipped profile: an unknown one fails at pin time, not as a confusing format mismatch later.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

try:
    from ctf import event
except ModuleNotFoundError:                 # `python tests/x.py`: the checkout root is not on sys.path
    sys.path.append(str(Path(__file__).resolve().parents[1]))
    from ctf import event


def pin(module_globals: dict, slug: str) -> None:
    event.load(slug)                        # EventError now if the profile does not exist

    @pytest.fixture(autouse=True)
    def _event_pin(monkeypatch):
        monkeypatch.setenv("CTF_EVENT", slug)
        yield

    module_globals["_event_pin"] = _event_pin
    module_globals["PINNED_EVENT"] = slug
    if module_globals.get("__name__") == "__main__":
        os.environ["CTF_EVENT"] = slug
        _pin_suite_scope()


def _pin_suite_scope() -> None:
    """A script run gets the suite's test-only scope profile, as under pytest: the pinned event's own
    rules.live_service_scope (*.huntress.example) would refuse the loopback fakes the tests start."""
    from ctf import scope
    if scope.pinned() is not None:
        return
    import importlib.util
    spec = importlib.util.spec_from_file_location("_tests_conftest_scope", Path(__file__).with_name("conftest.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)              # tests/conftest.py pins SUITE_SCOPE_PROFILE on import
    if scope.pinned() is None:
        raise RuntimeError("tests/conftest.py no longer pins the suite scope profile; event_pin needs it")
