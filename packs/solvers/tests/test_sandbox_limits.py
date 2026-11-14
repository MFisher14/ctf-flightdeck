"""The detonation sandbox's resource limits are env-overridable, validated, and identity-affecting.

Defaults (cpus 2 / memory 1g / pids 128) are the safety cap for detonating an untrusted sample. A big
PASSIVE-data job (multi-GB memory dump / disk image via Volatility/TSK — parses structures, runs no
untrusted code) needs more, so CTF_SANDBOX_MEMORY / _CPUS / _PIDS raise the cap. A raised limit must
flow into run_args() -> spec() so a container with different limits is a different identity (stale ones
get replaced, not silently reused), and a malformed value must never reach `docker run`.
"""
from __future__ import annotations

import importlib
import sys

import pytest


@pytest.fixture(autouse=True)
def _no_stale_sandbox():
    # these tests reimport `sandbox` under mutated env; drop the cached module after each so any
    # later test in the session re-imports it fresh (with the real, unmutated environment).
    yield
    sys.modules.pop("sandbox", None)


def _load(monkeypatch, **env):
    for k in ("CTF_SANDBOX_MEMORY", "CTF_SANDBOX_CPUS", "CTF_SANDBOX_PIDS"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    sys.modules.pop("sandbox", None)
    return importlib.import_module("sandbox")


def test_defaults_are_the_safety_cap(monkeypatch):
    s = _load(monkeypatch)
    assert s.LIMITS["memory"] == "1g"
    assert s.LIMITS["cpus"] == "2"
    assert s.LIMITS["pids"] == 128


def test_overrides_apply_and_reach_run_args(monkeypatch):
    s = _load(monkeypatch, CTF_SANDBOX_MEMORY="8g", CTF_SANDBOX_CPUS="6", CTF_SANDBOX_PIDS="512")
    assert s.LIMITS["memory"] == "8g"
    assert s.LIMITS["cpus"] == "6"
    assert s.LIMITS["pids"] == 512
    args = s.run_args()
    assert "8g" in args                       # --memory
    assert args[args.index("--memory-swap") + 1] == "8g"   # swap tracks memory (no extra swap)
    assert "6" in args                         # --cpus
    assert "512" in args                       # --pids-limit


def test_limits_change_container_identity(monkeypatch):
    # spec() hashes run_args, so a different memory cap -> a different container spec (not a silent reuse)
    default_spec = _load(monkeypatch).spec()
    raised_spec = _load(monkeypatch, CTF_SANDBOX_MEMORY="8g").spec()
    assert default_spec != raised_spec


def test_malformed_values_fall_back_to_safe_defaults(monkeypatch):
    # a bad/injection value must never reach docker run — the safe default stands
    s = _load(monkeypatch, CTF_SANDBOX_MEMORY="lots", CTF_SANDBOX_CPUS="; rm -rf /",
              CTF_SANDBOX_PIDS="many")
    assert s.LIMITS["memory"] == "1g"
    assert s.LIMITS["cpus"] == "2"
    assert s.LIMITS["pids"] == 128


def test_memory_unit_forms_accepted(monkeypatch):
    for val in ("4096m", "2g", "512m", "4G"):
        s = _load(monkeypatch, CTF_SANDBOX_MEMORY=val)
        assert s.LIMITS["memory"] == val, val
