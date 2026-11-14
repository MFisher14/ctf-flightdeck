"""B-242: the ctf-runtime-* images as tools/images.toml and docker/runtime/ declare them.

Static checks only (the manifest, the Dockerfiles' text, the build plan): no docker, no build, no
network. They hold the three things tools/sandbox.py runtime_run relies on: every base image is
pinned by digest, the build stamps the label runtime_run compares, and the images are built by
`ctf toolchain build` (managed), never by hand.
"""
from __future__ import annotations

import importlib
import re
import shlex
import sys

import pytest

from ctf import paths
from ctf.toolchain import images

ROOT = paths.repo_root()
RUNTIME = [im for im in images.load() if im.name.startswith("runtime-")]
IDS = [im.name for im in RUNTIME]
_DIGEST = re.compile(r"^[a-z0-9./-]+:[A-Za-z0-9_][A-Za-z0-9_.-]*@sha256:[0-9a-f]{64}$")


def test_there_is_one_image_per_runtime_and_version():
    assert IDS == ["runtime-wasm", "runtime-jvm", "runtime-dotnet", "runtime-lua",
                   "runtime-node-20", "runtime-node-22", "runtime-node-24",
                   "runtime-python-3.8", "runtime-python-3.9", "runtime-python-3.10", "runtime-python-3.11",
                   "runtime-python-3.12", "runtime-python-3.13", "runtime-python-3.14"]
    assert len({im.tag for im in RUNTIME}) == len(RUNTIME)
    assert all(im.tag.startswith("ctf-runtime-") for im in RUNTIME)


def test_runtime_images_lint_clean():
    assert [f.render() for f in images.lint(RUNTIME)] == []


@pytest.mark.parametrize("im", RUNTIME, ids=IDS)
def test_the_image_is_optional_managed_pinned_and_shares_the_runtime_context(im):
    assert (im.role, im.managed, im.pinned, im.context) == ("optional", True, True, "docker/runtime")
    assert im.dockerfile.startswith("docker/runtime/") and im.dockerfile.endswith("/Dockerfile")
    assert im.downloads == ()


@pytest.mark.parametrize("im", RUNTIME, ids=IDS)
def test_every_base_image_is_an_exact_tag_and_its_digest(im):
    text = (ROOT / im.dockerfile).read_text(encoding="utf-8")
    args = im.build_args()
    stages, refs = set(), []
    for ins in images.parse_dockerfile(text):
        if ins.op != "FROM":
            continue
        toks = ins.text.split()
        ref = re.sub(r"\$\{([A-Z_]+)\}", lambda m: args.get(m.group(1), m.group(0)), toks[0])
        if len(toks) >= 3 and toks[1].upper() == "AS":
            stages.add(toks[2])
        if ref not in stages:
            refs.append(ref)
    assert refs, "the Dockerfile has a FROM"
    for ref in refs:
        assert _DIGEST.match(ref), f"{im.name}: FROM {ref} is not tag@sha256:<digest>"
        assert ":latest@" not in ref


@pytest.mark.parametrize("im", RUNTIME, ids=IDS)
def test_the_build_stamps_the_label_runtime_run_checks(im):
    (step,) = images.plan_build([im])
    assert step.action == "build", step.reason
    want = images.content_hash(im)
    assert f"{images.LABEL}={want}" in step.argv
    assert step.argv[:4] == ("docker", "build", "-t", im.tag) and step.argv[-1] == "docker/runtime"
    for name, value in im.build_args().items():
        assert f"{name}={value}" in step.argv


SELFTEST = {"wasm": "selftest.wasm", "python": "selftest.pyc", "lua": "selftest.lua", "jvm": "Selftest.class",
            "dotnet": "Selftest.dll", "node": "selftest.js"}


def plans():
    import runtime_trace
    return runtime_trace.load_plans()


def expected_smoke(name: str) -> str:
    """The smoke script the image must carry: the self-test fixture packed as runtime_run's request
    tar, fed to the entry script on stdin, under the plan's own argv for every variant the image
    serves (all five VMs of the Lua image)."""
    P = plans()
    pairs = [(r, v) for (r, v), image in P.IMAGES.items() if image == name]
    assert pairs, name
    head = ["rm -rf /tmp/req", "mkdir -p /tmp/req/dep", f"cp /opt/selftest/{SELFTEST[pairs[0][0]]} /tmp/req/artifact.bin",
            "tar -C /tmp/req -cf /tmp/req.tar artifact.bin dep"]
    runs = []
    for r, v in pairs:
        plan = P.build_plan(r, v)
        runs.append(f"{P.ENTRY} {plan.container_seconds} {shlex.join(plan.argv)} < /tmp/req.tar | grep -q ctf-selftest-ok")
    return " && ".join(head + runs)


@pytest.mark.parametrize("im", RUNTIME, ids=IDS)
def test_the_smoke_check_runs_the_self_test_through_the_entry_script_under_the_plans_argv(im):
    assert len(im.smoke) == 1 and im.smoke[0][:2] == ("sh", "-c")
    assert im.smoke[0][2] == expected_smoke(im.name)


def test_the_lua_smoke_runs_every_vm_the_image_serves():
    lua = next(im for im in RUNTIME if im.name == "runtime-lua")
    script = lua.smoke[0][2]
    for vm in ("lua5.1", "lua5.2", "lua5.3", "lua5.4", "luajit"):
        assert f"ctf-runtime-entry 35 {vm} /opt/runner/trace_runner.lua --artifact /work/artifact.bin" in script


def test_apt_packages_come_from_the_dated_snapshot_of_the_base_image():
    apt = [im for im in RUNTIME if "apt-get" in (ROOT / im.dockerfile).read_text(encoding="utf-8")]
    assert [im.name for im in apt] == ["runtime-lua"]
    text = (ROOT / apt[0].dockerfile).read_text(encoding="utf-8")
    base = re.search(r"^FROM debian:bookworm-(\d{8})-slim@", text, re.M)
    assert base, "apt packages are only pinned on a dated Debian base"
    stamp = f"{base.group(1)}T000000Z"
    uris = re.findall(r"URIs: (\S+)'", text)
    assert uris == [f"http://snapshot.debian.org/archive/debian/{stamp}",
                    f"http://snapshot.debian.org/archive/debian-security/{stamp}"]
    assert "> /etc/apt/sources.list.d/debian.sources" in text and "rm -f /etc/apt/sources.list " in text
    assert "deb.debian.org" not in "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert text.index("debian.sources") < text.index("apt-get -o Acquire::Check-Valid-Until=false update")
    assert text.count("apt-get install") == 1 and text.count("apt-get") == 2


def test_images_built_from_one_dockerfile_differ_only_by_their_base_image():
    by_file = {}
    for im in RUNTIME:
        by_file.setdefault(im.dockerfile, []).append(im)
    shared = {f: ims for f, ims in by_file.items() if len(ims) > 1}
    assert sorted(shared) == ["docker/runtime/node/Dockerfile", "docker/runtime/python/Dockerfile"]
    for ims in shared.values():
        refs = [dict(im.args) for im in ims]
        assert all(len(r) == 1 for r in refs)
        values = [next(iter(r.values())) for r in refs]
        assert len(set(values)) == len(values)
        assert len({images.content_hash(im) for im in ims}) == len(ims)


def test_the_wasm_image_takes_wasmtime_at_the_masters_pin():
    wasm = next(im for im in RUNTIME if im.name == "runtime-wasm")
    assert wasm.py == ("wasmtime",)
    staged = images.staged_files(wasm)[images.STAGED_REQUIREMENTS]
    pin = images.requirement_pins()["wasmtime"]
    assert f"wasmtime=={pin[1]}" in staged


def test_sandbox_py_uses_the_toolchains_label_and_stub_marker():
    sandbox = importlib.import_module("sandbox")
    try:
        assert sandbox.RUNTIME_LABEL == images.LABEL
        assert sandbox.RUNTIME_STUB_MARKER == images.STUB_MARKER.encode()
        assert sandbox.RUNTIME_MAX_SECONDS == 305 and sandbox.RUNTIME_MAX_INPUT == 96 << 20
        assert sandbox.RUNTIME_ENTRY == "/usr/local/bin/ctf-runtime-entry"
    finally:
        sys.modules.pop("sandbox", None)
