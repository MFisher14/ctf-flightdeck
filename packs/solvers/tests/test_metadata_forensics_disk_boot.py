"""B-131: the engine metadata_forensics.disk_boot, `ctf disk-boot`, and the boot image's manifest entry.

No image is built, pulled or booted: disk images are synthetic structures, docker is a stub on PATH
that logs its calls, and QMP is the stub of tests/qmp_stub.py.
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

import disk_boot as engine
from ctf import diskboot, event, paths
from ctf.cli import disk_boot as cli_mod
from ctf.engines import manifest, router
from ctf.toolchain import images
from qmp_stub import StubQMP, docker_calls, docker_stub, ppm

ESP = bytes.fromhex("28732ac11ff8d211ba4b00a0c93ec93b")


def gpt_image() -> bytes:
    b = bytearray(1 << 16)
    b[446 + 4] = 0xEE
    b[510:512] = b"\x55\xaa"
    b[512:520] = b"EFI PART"
    struct.pack_into("<Q", b, 512 + 72, 2)
    struct.pack_into("<II", b, 512 + 80, 128, 128)
    b[1024:1040] = ESP
    return bytes(b)


def fat_data() -> bytes:
    b = bytearray(1 << 16)
    b[0:3] = b"\xeb\x3c\x90"
    b[0x36:0x3B] = b"FAT16"
    b[510:512] = b"\x55\xaa"
    return bytes(b)


def handout(tmp_path, files=None, name="19-pink-os") -> Path:
    d = tmp_path / name
    for rel, data in (files or {"files/uefi_disk.img": gpt_image(), "files/data.img": fat_data()}).items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return d


PROFILE = event.load("pink")


# ------------------------------------------------------------------------------------------- engine

def test_engine_plans_the_boot_and_boots_nothing(tmp_path, monkeypatch):
    env = docker_stub(tmp_path, {"images": {}})
    monkeypatch.setenv("PATH", env["PATH"])
    monkeypatch.setenv("STUB_STATE", env["STUB_STATE"])
    monkeypatch.setenv("STUB_LOG", env["STUB_LOG"])
    d = handout(tmp_path)
    res = engine.solve(d, PROFILE)
    assert docker_calls(env) == []                             # planning never calls docker
    assert res.status == "unsure" and res.flags == () and res.engine == "metadata_forensics.disk_boot"
    assert [(e.kind, e.path) for e in res.evidence] == [("disk-image", "files/uefi_disk.img"),
                                                       ("disk-image", "files/data.img"),
                                                       ("boot-plan", "recon/boot/plan.json")]
    assert "gpt" in res.evidence[0].detail and "uefi" in res.evidence[0].detail and "boot" in res.evidence[0].detail
    assert "python -m ctf disk-boot start" in res.notes and "operator" in res.notes
    assert "no observe run yet" in res.notes and "client-replay harvest" in res.notes
    plan = diskboot.BootPlan.from_dict(json.loads((d / "recon/boot/plan.json").read_text()))
    assert plan == diskboot.plan(d) and plan.firmware == "uefi"
    assert not (d / "recon/boot" / diskboot.SESSION_FILE).exists()


def test_engine_without_an_image_is_none_and_writes_nothing(tmp_path):
    d = handout(tmp_path, {"files/readme.txt": b"hello " * 200})
    res = engine.solve(d, PROFILE)
    assert res.status == "none" and res.evidence == () and not (d / "recon").exists()


def test_engine_blocks_with_the_reason_when_no_plan_can_be_made(tmp_path):
    d = handout(tmp_path, {"files/a,b.img": gpt_image()})
    res = engine.solve(d, PROFILE)
    assert res.status == "blocked" and "cannot be passed to QEMU safely" in res.notes
    assert [e.kind for e in res.evidence] == ["disk-image"]
    bad = engine.solve(handout(tmp_path, name="other"), PROFILE, firmware="coreboot")
    assert bad.status == "blocked" and "firmware must be" in bad.notes


def test_engine_options_reach_the_plan(tmp_path):
    d = handout(tmp_path)
    engine.solve(d, PROFILE, firmware="bios", memory_mb=512, machine="pc", drive_if="virtio")
    plan = json.loads((d / "recon/boot/plan.json").read_text())
    assert plan["firmware"] == "bios" and not any("pflash" in a for a in plan["qemu_argv"])
    assert "file=/img/files/uefi_disk.img,format=raw,media=disk,if=virtio,index=0" in plan["qemu_argv"]
    assert "pc,accel=tcg" in plan["qemu_argv"] and "512" in plan["qemu_argv"]


def test_engine_reports_screens_that_wait_for_a_vision_read(tmp_path):
    d = handout(tmp_path)
    out = d / "recon" / "boot"
    frames = [ppm(4, 4, lambda x, y: (1, 1, 1)), ppm(4, 4, lambda x, y: (2, 2, 2) if x == 0 and y == 0 else (1, 1, 1))]
    with StubQMP(frames=frames) as stub:
        with diskboot.QMP.connect(stub.spec) as qmp:
            diskboot.observe(qmp, [{"burst": {"name": "wall", "count": 2, "interval": 0}}], out)
    res = engine.solve(d, PROFILE)
    screens = next(e for e in res.evidence if e.kind == "screens")
    assert "2 screenshot(s) and 2 crop(s)" in screens.detail and screens.path == "recon/boot/vision-handoff.json"
    assert res.status == "unsure" and "vision hand-off" in res.notes and "never completed" in res.notes
    assert [e.path for e in res.evidence if e.kind == "disk-image"] == ["files/uefi_disk.img", "files/data.img"]


# ----------------------------------------------------------------------------- manifest and routing

def test_the_engine_is_routed_by_file_and_runs_at_intake(tmp_path):
    m = next(x for x in manifest.discover() if x.id == "metadata_forensics.disk_boot")
    assert m.entry_raw == "solvers.metadata-forensics.disk_boot:solve" and m.needs_tools == ()
    assert (m.intake.run, m.intake.select) == ("challenge", "files")
    assert {"ext:.img", "ext:.iso", "ext:.qcow2"} <= set(m.intake.match)
    d = handout(tmp_path)
    ids = [h.manifest.id for h in router.route("Steganography", "", d / "files")]
    assert "metadata_forensics.disk_boot" in ids and "web.client_replay" in ids
    assert ids.index("metadata_forensics.disk_boot") < ids.index("web.client_replay")   # plan first, then harvest
    words = [h.manifest.id for h in router.route("misc", "can you boot the image and see what it shows?")]
    assert "metadata_forensics.disk_boot" in words


# ------------------------------------------------------------------------------------- image entry

def boot_image():
    return next(i for i in images.load() if i.name == diskboot.IMAGE_NAME)


def test_the_boot_image_is_listed_pinned_and_lint_clean():
    im = boot_image()
    assert (im.tag, im.context, im.managed, im.pinned, im.role) == (
        "ctf-qemu-boot:1", "docker/qemu-boot", True, True, "optional")
    assert [f for f in images.lint([im])] == []
    assert ("ctf-boot-envcheck",) in im.smoke


def test_the_dockerfile_matches_what_the_harness_names():
    root = paths.repo_root()
    text = (root / "docker/qemu-boot/Dockerfile").read_text()
    ops = [(i.op, i.text) for i in images.parse_dockerfile(text)]
    assert not any(op == "EXPOSE" for op, _ in ops)            # QMP is a Unix socket: no port
    users = [t for op, t in ops if op == "USER"]
    assert users and users[-1] not in ("root", "0")
    run = " ".join(t for op, t in ops if op == "RUN")
    for pkg in ("qemu-system-x86", "ovmf", "socat"):
        assert pkg in run
    assert diskboot.OVMF_CODE in run and diskboot.OVMF_VARS in run
    check = (root / "docker/qemu-boot/envcheck.sh").read_text()
    assert diskboot.OVMF_CODE in check and diskboot.OVMF_VARS in check
    plan_cmd = {"qemu-system-x86_64", "socat"}
    assert all(b in check for b in plan_cmd)
    assert os.path.dirname(diskboot.QMP_SOCKET) in run          # the socket's folder exists in the image


# ---------------------------------------------------------------------------------------------- CLI

def cli(*argv) -> int:
    p = argparse.ArgumentParser()
    cli_mod.add_arguments(p)
    return cli_mod.run(p.parse_args(list(argv)))


def test_cli_plan_writes_the_plan_and_names_the_operator_step(tmp_path, capsys):
    d = handout(tmp_path)
    assert cli("plan", str(d)) == 0
    out = capsys.readouterr().out
    assert "image  files/uefi_disk.img: raw, table gpt, firmware uefi, boot" in out
    assert "ctf disk-boot start" in out and "(the operator)" in out
    plan = json.loads((d / "recon/boot/plan.json").read_text())
    assert plan["container"] == diskboot.container_name(d)
    script = tmp_path / "script.json"
    script.write_text(json.dumps([{"wait": 3}, {"shot": "desk"}]))
    assert cli("plan", str(d), "--script", str(script), "--firmware", "bios", "--json") == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["script"] == [{"wait": 3}, {"shot": "desk"}] and printed["firmware"] == "bios"


def test_cli_plan_errors_are_named(tmp_path, capsys):
    empty = handout(tmp_path, {"files/a.txt": b"x" * 600})
    assert cli("plan", str(empty)) == 2 and "no disk image found" in capsys.readouterr().err
    d = handout(tmp_path, name="two")
    bad = tmp_path / "bad.json"
    bad.write_text("[{\"explode\": 1}]")
    assert cli("plan", str(d), "--script", str(bad)) == 2 and "unknown action" in capsys.readouterr().err
    bad.write_text("not json")
    assert cli("plan", str(d), "--script", str(bad)) == 2 and "not a readable JSON observe script" in capsys.readouterr().err


def test_cli_start_is_refused_without_a_person_and_calls_no_docker(tmp_path, capsys, monkeypatch):
    im = boot_image()
    env = docker_stub(tmp_path, {"images": {im.tag: {images.LABEL: images.content_hash(im)}}})
    for k in ("PATH", "STUB_STATE", "STUB_LOG"):
        monkeypatch.setenv(k, env[k])
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    d = handout(tmp_path)
    assert cli("start", str(d), "--reason", "look at it") == 2          # no plan yet
    assert "run `python -m ctf disk-boot plan` first" in capsys.readouterr().err
    assert cli("plan", str(d)) == 0
    capsys.readouterr()
    assert cli("start", str(d), "--reason", "look at it") == 3          # pytest's stdin is not a terminal
    err = capsys.readouterr().err
    assert "operator's decision" in err and "no flag bypasses this" in err
    assert docker_calls(env) == [] and not (d / "recon/boot" / diskboot.SESSION_FILE).exists()
    assert not (tmp_path / "work" / "ledger.jsonl").exists()             # nothing was approved, nothing recorded


def test_cli_start_refuses_an_edited_plan_before_anyone_is_asked(tmp_path, capsys, monkeypatch):
    """An edited plan.json fails with exit 2 (the plan check), not 3 (no person at the terminal):
    the check runs before the approval prompt, so nobody is shown a command that would be refused."""
    im = boot_image()
    env = docker_stub(tmp_path, {"images": {im.tag: {images.LABEL: images.content_hash(im)}}})
    for k in ("PATH", "STUB_STATE", "STUB_LOG"):
        monkeypatch.setenv(k, env[k])
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    d = handout(tmp_path)
    assert cli("plan", str(d)) == 0
    pj = d / "recon/boot/plan.json"
    plan = json.loads(pj.read_text())
    i = plan["start_argv"].index("-d") + 1
    plan["start_argv"][i:i] = ["--privileged", "-v", "/:/host"]
    pj.write_text(json.dumps(plan))
    capsys.readouterr()
    assert cli("start", str(d), "--reason", "look at it") == 2
    assert "differs from what this harness writes for this folder (start_argv)" in capsys.readouterr().err
    other = handout(tmp_path, name="other")                   # a plan copied from another folder
    assert cli("plan", str(d)) == 0
    (other / "recon/boot").mkdir(parents=True)
    (other / "recon/boot/plan.json").write_text(pj.read_text())
    capsys.readouterr()
    assert cli("start", str(other), "--reason", "look at it") == 2
    assert "is a plan for" in capsys.readouterr().err
    assert docker_calls(env) == []


def test_cli_observe_and_quit_need_a_session(tmp_path, capsys):
    d = handout(tmp_path)
    assert cli("plan", str(d)) == 0
    capsys.readouterr()
    assert cli("observe", str(d)) == 2
    assert "the operator starts the boot first" in capsys.readouterr().err
    assert cli("quit", str(d)) == 2
    assert "no boot session" in capsys.readouterr().err


def test_cli_observe_drives_a_vm_given_by_hand(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "pink")
    d = handout(tmp_path)
    script = tmp_path / "s.json"
    script.write_text(json.dumps([{"key": "ret"}, {"shot": "desk"}]))
    with StubQMP(frames=[ppm(6, 4, lambda x, y: (x, y, 0))]) as stub:
        assert cli("observe", str(d), "--qmp", stub.spec, "--script", str(script), "--json") == 0
        assert stub.executed() == ["qmp_capabilities", "send-key", "screendump"]
    got = json.loads(capsys.readouterr().out)
    assert [s["file"] for s in got["shots"]] == ["shots/0001-desk.png"]
    out = d / "recon" / "boot"
    assert (out / "shots/0001-desk.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    assert json.loads((out / diskboot.HANDOFF_FILE).read_text())["flag_prefixes"] == ["PINK"]
    assert cli("observe", str(d), "--qmp", "tcp:192.0.2.7:4444") == 2
    assert "loopback only" in capsys.readouterr().err


def test_cli_observe_and_quit_use_the_recorded_session(tmp_path, capsys, monkeypatch):
    from qmp_stub import stdio_log, stdio_state
    im = boot_image()
    frame = ppm(6, 4, lambda x, y: (x, y, 9))
    env = docker_stub(tmp_path, {"images": {im.tag: {images.LABEL: images.content_hash(im)}},
                                 "qmp_state": stdio_state(tmp_path, [frame])})
    for k in ("PATH", "STUB_STATE", "STUB_LOG"):
        monkeypatch.setenv(k, env[k])
    monkeypatch.setenv("CTF_EVENT", "pink")
    d = handout(tmp_path)
    script = tmp_path / "s.json"
    script.write_text(json.dumps([{"shot": "desk"}]))
    assert cli("plan", str(d), "--script", str(script)) == 0
    plan = diskboot.BootPlan.from_dict(json.loads((d / "recon/boot/plan.json").read_text()))
    approval = diskboot.approve_interactive(plan, "test", stdin=_Tty(), stdout=_Tty(), prompt=lambda q: d.name)
    session = diskboot.start(plan, approval, environ=env)      # the operator's step, done here by the library
    session["guest_out"] = plan.out_dir                         # the stub writes on this host, not in a container
    (d / "recon/boot" / diskboot.SESSION_FILE).write_text(json.dumps(session))
    capsys.readouterr()
    assert cli("observe", str(d)) == 0                          # the plan's script, over `docker exec`
    out = capsys.readouterr().out
    assert "1 screenshot(s)" in out and "vision hand-off" in out
    assert (d / "recon/boot/shots/0001-desk.png").is_file()
    assert cli("quit", str(d)) == 0 and plan.container in capsys.readouterr().out
    assert [m["execute"] for m in stdio_log(tmp_path)] == ["qmp_capabilities", "screendump", "qmp_capabilities", "quit"]
    assert not (d / "recon/boot" / diskboot.SESSION_FILE).exists()
    assert [c[0] for c in docker_calls(env)] == ["image", "run", "exec", "exec"]


class _Tty:
    def isatty(self):
        return True


def test_cli_is_discovered_by_python_m_ctf(tmp_path):
    d = handout(tmp_path)
    r = subprocess.run([sys.executable, "-m", "ctf", "disk-boot", "plan", str(d), "--json"],
                       cwd=paths.repo_root(), capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stdout + r.stderr
    plan = json.loads(r.stdout)
    assert plan["image_tag"] == "ctf-qemu-boot:1" and [i["path"] for i in plan["images"]] == [
        "files/uefi_disk.img", "files/data.img"]
