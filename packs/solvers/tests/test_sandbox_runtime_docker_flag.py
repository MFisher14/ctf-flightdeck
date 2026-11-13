"""Integration fix (batch 902, B-196 x B-242): the real side of tools/sandbox.py `_runtime_docker`.

The suite runs with CTF_TESTING=1, so before this test the runtime path's docker lookup only ever ran on
its test-double side (a stub that carries RUNTIME_STUB_MARKER is required). B-196's fake-branch audit asks
for a test that reaches the branch with the flag off. With the flag off, `_runtime_docker` returns the
docker CLI that `docker()` names, whatever its contents; with the flag on, the same file is refused.
Nothing is run: the "docker" here is a file this test writes and never executes.
"""
from __future__ import annotations

import pytest

import sandbox      # tools/ (root conftest sys.path)


def _not_a_stub(tmp_path):
    path = tmp_path / "docker"
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(0o755)
    return path


def test_runtime_docker_without_the_flag_returns_the_real_cli(tmp_path, monkeypatch):
    path = _not_a_stub(tmp_path)
    monkeypatch.setenv("CTF_DOCKER", str(path))
    monkeypatch.delenv("CTF_TESTING", raising=False)
    assert sandbox._runtime_docker() == str(path)


def test_runtime_docker_under_the_flag_refuses_a_file_that_is_not_a_stub(tmp_path, monkeypatch):
    path = _not_a_stub(tmp_path)
    monkeypatch.setenv("CTF_DOCKER", str(path))
    monkeypatch.setenv("CTF_TESTING", "1")
    with pytest.raises(sandbox.SandboxDown, match="not a test stub"):
        sandbox._runtime_docker()


def test_runtime_docker_under_the_flag_accepts_a_marked_stub(tmp_path, monkeypatch):
    path = tmp_path / "docker"
    path.write_bytes(b"#!/bin/sh\n# " + sandbox.RUNTIME_STUB_MARKER + b"\nexit 0\n")
    path.chmod(0o755)
    monkeypatch.setenv("CTF_DOCKER", str(path))
    monkeypatch.setenv("CTF_TESTING", "1")
    assert sandbox._runtime_docker() == str(path)
