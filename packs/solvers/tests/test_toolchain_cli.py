"""B-188: `python -m ctf toolchain ...` end to end (subprocesses), and the doctor's assets/images checks.

Docker is the stub of toolchain_stubs.py on PATH; a real docker is refused (exit 2) under CTF_TESTING.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ctf import doctor, paths
from ctf.toolchain import images
from toolchain_stubs import calls, checkout, docker_stub, set_state, write

KIT = """\
[[image]]
name = "kit"
tag = "ctf-kit:1"
dockerfile = "docker/kit/Dockerfile"
context = "docker/kit"
py = ["capstone"]
smoke = [["kit-check"]]
"""
BAD = KIT.replace('name = "kit"', 'name = "bad"').replace("ctf-kit:1", "ctf-bad:1").replace("docker/kit", "docker/bad")
ASSETS = """\
[[asset]]
name = "wl"
kind = "file"
candidates = ["{path}"]
export = ["CTF_ASSET_WL", "WL"]
install = "put it there"
"""


def ctf(*args, env=None, cwd=None):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run([sys.executable, "-m", "ctf", "toolchain", *args], cwd=cwd or paths.repo_root(),
                          env=e, capture_output=True, text=True, timeout=120)


def kit_root(tmp_path, manifest=KIT, assets_path=None):
    files = {"docker/kit/Dockerfile": "FROM python:3.12\nCOPY toolchain-requirements.txt /t/\n",
             "docker/bad/Dockerfile": "FROM python\nRUN pip install requests || true\n"}
    root = checkout(tmp_path, manifest, files)
    (root / "tools" / "assets.toml").write_text(ASSETS.format(path=assets_path or tmp_path / "wl.txt"))
    return root


def test_lint_exit_codes(tmp_path):
    r = ctf("lint")
    assert r.returncode == 0 and "LINT OK" in r.stdout and "unlocked toolkit" in r.stdout, r.stdout + r.stderr
    root = kit_root(tmp_path, KIT + "\n" + BAD)
    r = ctf("--root", str(root), "lint")
    assert r.returncode == 1 and "FAIL bad:" in r.stdout and "from-unpinned" in r.stdout
    r = ctf("--root", str(root), "lint", "--json")
    doc = json.loads(r.stdout)
    assert r.returncode == 1 and not doc["passed"]
    assert {f["rule"] for f in doc["findings"] if f["fatal"]} == {"from-unpinned", "pip-unpinned", "swallowed-failure"}
    unpinned = BAD + 'pinned = false\nunpinned_reason = "carried"\n'
    r = ctf("--root", str(kit_root(tmp_path / "u", KIT + "\n" + unpinned)), "lint")
    assert r.returncode == 0 and "note bad:" in r.stdout and "unpinned bad: carried" in r.stdout
    (root / "tools" / "images.toml").write_text("[[image]\n")
    r = ctf("--root", str(root), "lint")
    assert r.returncode == 2 and "not valid TOML" in r.stderr


def test_status_and_build_through_a_stub_docker(tmp_path):
    root = kit_root(tmp_path)
    env = docker_stub(tmp_path, {"images": {}})
    env["PATH"] = env["PATH"] + os.pathsep + os.environ.get("PATH", "")
    r = ctf("--root", str(root), "status", env=env)
    assert r.returncode == 1 and "MISSING" in r.stdout and "IMAGES PROBLEMS: kit" in r.stdout
    r = ctf("--root", str(root), "build", env=env)
    assert r.returncode == 1 and "DRY RUN" in r.stdout and "docker build -t ctf-kit:1" in r.stdout
    assert not [c for c in calls(env) if c["argv"][0] == "build"]       # a dry run builds nothing
    r = ctf("--root", str(root), "build", "--apply", env=env)
    assert r.returncode == 0 and "BUILT  kit" in r.stdout, r.stdout + r.stderr
    built, = [c for c in calls(env) if c["argv"][0] == "build"]
    label = next(a for a in built["argv"] if a.startswith(images.LABEL + "="))
    set_state(env, {"images": {"ctf-kit:1": {images.LABEL: label.split("=", 1)[1]}}})
    r = ctf("--root", str(root), "status", "--json", env=env)
    assert r.returncode == 0 and json.loads(r.stdout)["images"][0]["state"] == "ok"
    r = ctf("--root", str(root), "build", env=env)
    assert r.returncode == 0 and "fresh" in r.stdout                   # never rebuilt while unchanged
    set_state(env, {"images": {}, "build_rc": 9})
    r = ctf("--root", str(root), "build", "--apply", env=env)
    assert r.returncode == 1 and "FAILED kit: exit 9" in r.stdout


def test_build_apply_refuses_a_pinned_image_that_fails_lint(tmp_path):
    root = kit_root(tmp_path, KIT + "\n" + BAD)
    env = docker_stub(tmp_path, {"images": {}})
    env["PATH"] = env["PATH"] + os.pathsep + os.environ.get("PATH", "")
    r = ctf("--root", str(root), "build", "--apply", env=env)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "refused bad (ctf-bad:1)" in r.stdout and "lint finding(s)" in r.stdout and "BUILT  kit" in r.stdout
    built = [c for c in calls(env) if c["argv"][0] == "build"]
    assert [c["argv"][c["argv"].index("-t") + 1] for c in built] == ["ctf-kit:1"]   # bad was never built


def test_a_real_docker_is_refused_under_testing(tmp_path):
    root = kit_root(tmp_path)
    env = docker_stub(tmp_path, {"images": {}}, marker=False)
    for cmd in (["status"], ["build"], ["smoke", "kit"]):
        r = ctf("--root", str(root), *cmd, env=env)
        assert r.returncode == 2 and "not a test stub" in r.stderr, cmd
    assert calls(env) == []


def test_smoke_exit_codes(tmp_path):
    root = kit_root(tmp_path)
    env = docker_stub(tmp_path, {"run_fail": "kit-check"})
    r = ctf("--root", str(root), "smoke", "kit", env=env)
    assert r.returncode == 1 and "FAIL kit: kit-check (exit 3)" in r.stdout
    set_state(env, {})
    r = ctf("--root", str(root), "smoke", "kit", env=env)
    assert r.returncode == 0 and "SMOKE OK" in r.stdout
    r = ctf("--root", str(root), "smoke", "nope", env=env)
    assert r.returncode == 2 and "unknown image" in r.stderr


def test_assets_and_env(tmp_path):
    wl = tmp_path / "dir with space" / "w'l.txt"
    root = kit_root(tmp_path, assets_path=wl)
    r = ctf("--root", str(root), "assets")
    assert r.returncode == 1 and "MISSING  wl" in r.stdout and "fix: put it there" in r.stdout
    write(wl, "words\n")
    r = ctf("--root", str(root), "assets", "--json")
    doc = json.loads(r.stdout)
    assert r.returncode == 0 and doc["exports"] == {"CTF_ASSET_WL": str(wl), "WL": str(wl)}
    r = ctf("--root", str(root), "env", env={"CTF_WORKDIR": str(tmp_path / "wd")})
    assert r.returncode == 0
    sh = subprocess.run(["sh", "-c", r.stdout + 'printf "%s|%s|%s" "$WL" "$CTF_PYTHON" "${PATH%%:*}"'],
                        capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
    assert sh.stdout == f"{wl}|{sys.executable}|{Path(sys.executable).parent}", sh.stderr
    r = ctf("--root", str(root), "env", "--write", env={"CTF_WORKDIR": str(tmp_path / "wd")})
    written = (tmp_path / "wd" / "toolchain" / "env.sh").read_text()
    assert r.returncode == 0 and r.stdout in written and written.startswith("# written by")


def test_versions_exit_codes(tmp_path):
    chal = tmp_path / "chal"
    chal.mkdir()
    (chal / "README").write_text("Solved with SageMath version 10.5, nothing newer.\n")
    r = ctf("versions", str(chal))
    assert r.returncode == 0 and "OK        sage: ctf-sage:10.5" in r.stdout, r.stdout + r.stderr
    assert "--network none" in r.stdout and "ctf-sage:10.5 sage <script>" in r.stdout
    (chal / "README").write_text("Solved with SageMath version 9.1.\n")
    r = ctf("versions", str(chal), "--json")
    doc = json.loads(r.stdout)
    assert r.returncode == 1 and doc["picks"][0]["status"] == "missing"
    r = ctf("versions", str(tmp_path / "nope"))
    assert r.returncode == 2 and "not a folder" in r.stderr


def test_wheels_exit_codes(tmp_path):
    root = kit_root(tmp_path)
    (root / "requirements.txt").write_text("capstone==5.0.9\n")
    wh = tmp_path / "wh"
    r = ctf("--root", str(root), "wheels", "--dir", str(wh))
    assert r.returncode == 2 and "is not there" in r.stderr
    wh.mkdir()
    r = ctf("--root", str(root), "wheels", "--dir", str(wh))
    assert r.returncode == 1 and "MISSING capstone==5.0.9" in r.stdout
    (wh / "capstone-5.0.9-py3-none-any.whl").write_text("")
    r = ctf("--root", str(root), "wheels", "--dir", str(wh))
    assert r.returncode == 0 and "WHEELS OK" in r.stdout
    r = ctf("--root", str(root), "wheels", "--dir", str(wh), "--plan")
    assert r.returncode == 0 and "--offline" in r.stdout and "pip download" in r.stdout


# ----------------------------------------------------------------------------------------- doctor

def test_doctor_assets_check(tmp_path):
    wl = tmp_path / "wl.txt"
    root = kit_root(tmp_path, assets_path=wl)
    c = doctor.check_assets({}, root=root)
    assert c.status == "warn" and "wl missing" in c.detail and "wl: put it there" in c.fix
    wl.write_text("x")
    c = doctor.check_assets({}, root=root)
    assert c.status == "ok" and "1/1 ok" in c.detail and "toolchain env" in c.detail
    (root / "tools" / "assets.toml").write_text("nope = 1\n")
    assert doctor.check_assets({}, root=root).status == "fail"


def test_doctor_images_check(tmp_path):
    root = kit_root(tmp_path)
    env = docker_stub(tmp_path, {"images": {}})
    c = doctor.check_images(env, root=root)
    assert c.status == "warn" and "core: kit missing" in c.detail
    im, = images.load(root / "tools" / "images.toml")
    set_state(env, {"images": {"ctf-kit:1": {images.LABEL: images.content_hash(im, root)}}})
    assert doctor.check_images(env, root=root).status == "ok"
    c = doctor.check_images({"PATH": str(tmp_path / "none")}, root=root)
    assert c.status == "warn" and "docker is not on PATH" in c.detail
    real = docker_stub(tmp_path / "r", {"images": {}}, marker=False)
    c = doctor.check_images(real, root=root)
    assert c.status == "skip" and "not a test stub" in c.detail
    bad = kit_root(tmp_path / "b", KIT + "\n" + BAD)
    c = doctor.check_images(env, root=bad)
    assert c.status == "fail" and "from-unpinned" in c.detail
    (bad / "tools" / "images.toml").write_text("")
    assert doctor.check_images(env, root=bad).status == "fail"


def test_run_checks_skips_assets_and_images_with_the_toolbox(tmp_path, monkeypatch):
    from test_preflight_doctor import profile
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    cs = {c.name: c for c in doctor.run_checks(profile(), codex=False, toolbox=False)}
    assert cs["assets"].status == "skip" and cs["images"].status == "skip"
