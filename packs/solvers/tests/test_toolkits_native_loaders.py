#!/usr/bin/env python3
"""B-241: the optional loaders (Qiling, unidbg) are detected and fail with a named reason, never installed."""
from __future__ import annotations

import json
import subprocess
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from solvers.toolkits import native_loaders as NL  # noqa: E402


def absent(name):
    return None


def present(name):
    return types.SimpleNamespace(origin=f"/site/{name}/__init__.py")


def no_java(name):
    return None


def test_qiling_reasons_are_named_one_by_one(tmp_path):
    got = NL.status("qiling", environ={}, find_spec=absent)
    assert not got.available and "not installed in this interpreter" in got.reason and got.detail == ""
    assert "never done by build work" in got.reason                     # the install is a human step
    got = NL.status("qiling", environ={}, find_spec=present)
    assert not got.available and "CTF_QILING_ROOTFS is not set" in got.reason
    got = NL.status("qiling", environ={"CTF_QILING_ROOTFS": str(tmp_path / "missing")}, find_spec=present)
    assert not got.available and "does not exist" in got.reason
    got = NL.status("qiling", environ={"CTF_QILING_ROOTFS": str(tmp_path)}, find_spec=present)
    assert got == NL.LoaderStatus("qiling", True, "", "/site/qiling/__init__.py")

    def broken(name):
        raise ImportError("no parent package")
    got = NL.status("qiling", environ={"CTF_QILING_ROOTFS": str(tmp_path)}, find_spec=broken)
    assert not got.available and "cannot be located" in got.reason


def test_unidbg_reasons_are_named_one_by_one(tmp_path):
    jar = tmp_path / "unidbg.jar"
    got = NL.status("unidbg", environ={}, which=no_java)
    assert not got.available and "CTF_UNIDBG_JAR is not set" in got.reason
    got = NL.status("unidbg", environ={"CTF_UNIDBG_JAR": str(jar)}, which=no_java)
    assert not got.available and "does not exist" in got.reason
    jar.write_bytes(b"PK\x03\x04")
    got = NL.status("unidbg", environ={"CTF_UNIDBG_JAR": str(jar)}, which=no_java)
    assert not got.available and "java is not on PATH" in got.reason
    got = NL.status("unidbg", environ={"CTF_UNIDBG_JAR": str(jar)}, which=lambda name: "/usr/bin/" + name)
    assert got == NL.LoaderStatus("unidbg", True, "", str(jar))
    # a folder is not a jar
    got = NL.status("unidbg", environ={"CTF_UNIDBG_JAR": str(tmp_path)}, which=lambda name: "/usr/bin/java")
    assert not got.available


def test_require_raises_with_the_loader_and_the_reason():
    with pytest.raises(NL.LoaderUnavailable) as error:
        NL.require("qiling", environ={}, find_spec=absent)
    assert error.value.name == "qiling" and "not installed" in error.value.reason
    assert "optional loader qiling is unavailable" in str(error.value)
    assert NL.require("qiling", environ={"CTF_QILING_ROOTFS": str(ROOT)}, find_spec=present).available
    with pytest.raises(ValueError, match="unknown optional loader"):
        NL.status("frida")


def test_report_lists_every_loader_and_is_json(tmp_path):
    found = NL.report(environ={}, find_spec=absent, which=no_java)
    assert set(found) == set(NL.LOADERS) == {"qiling", "unidbg"}
    assert all(row["available"] is False and row["reason"] for row in found.values())
    json.dumps(found)


def test_detection_never_imports_the_loader(monkeypatch):
    """Importing Qiling would import Unicorn outside the guarded capability check: the probe may not."""
    calls = []

    def find_spec(name):
        calls.append(name)
        return present(name)

    before = set(sys.modules)
    NL.status("qiling", environ={"CTF_QILING_ROOTFS": str(ROOT)}, find_spec=find_spec)
    assert calls == ["qiling"]
    assert "qiling" not in set(sys.modules) - before


def test_this_checkout_reports_real_state_and_the_cli_exit_code_follows_it(tmp_path):
    """The repo installs neither loader: with no settings the CLI exits 1 and names both reasons."""
    script = ROOT / "solvers" / "toolkits" / "native_loaders.py"
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}
    done = subprocess.run([sys.executable, "-B", str(script)], capture_output=True, text=True, env=env,
                          cwd=str(tmp_path))
    found = json.loads(done.stdout)
    assert set(found) == {"qiling", "unidbg"}
    assert found["unidbg"]["available"] is False and "CTF_UNIDBG_JAR is not set" in found["unidbg"]["reason"]
    assert done.returncode == (0 if any(row["available"] for row in found.values()) else 1)
    if not found["qiling"]["available"]:
        assert found["qiling"]["reason"]
