"""B-131: the disk-image boot harness (ctf/diskboot.py).

Nothing here boots anything: there is no QEMU, no VM and no real docker. Disk images are synthetic
structures built in the test (a partition table and zeros), QMP is the stub of tests/qmp_stub.py on
a Unix socket, a loopback port or a command's stdio, and docker is a stub script on PATH.
"""
from __future__ import annotations

import dataclasses
import json
import os
import shlex
import socket
import struct
import subprocess
import threading
import time
import zlib
from pathlib import Path

import pytest

from ctf import diskboot, event, ledger
from ctf.toolchain import images
from qmp_stub import StubQMP, docker_calls, docker_stub, ppm, stdio_log, stdio_state

ESP = bytes.fromhex("28732ac11ff8d211ba4b00a0c93ec93b")
LINUX = bytes.fromhex("af3dc60f838472478e793d69d8477de4")


# ------------------------------------------------------------------------------- synthetic images

def gpt_image(guid=ESP, sector=512) -> bytes:
    b = bytearray(1 << 20)
    b[446 + 4] = 0xEE                                   # protective MBR
    b[510:512] = b"\x55\xaa"
    b[sector:sector + 8] = b"EFI PART"
    struct.pack_into("<Q", b, sector + 72, 2)           # partition entries at LBA 2
    struct.pack_into("<II", b, sector + 80, 128, 128)   # 128 entries of 128 bytes
    b[2 * sector + 128: 2 * sector + 144] = guid        # the second entry
    return bytes(b)


def mbr_image(types=(0x83,), active=True, code=True) -> bytes:
    b = bytearray(1 << 16)
    if code:
        b[0:3] = b"\xeb\x63\x90"
    for i, t in enumerate(types):
        b[446 + 16 * i] = 0x80 if active and i == 0 else 0x00
        b[446 + 16 * i + 4] = t
        struct.pack_into("<II", b, 446 + 16 * i + 8, 2048 * (i + 1), 2048)
    b[510:512] = b"\x55\xaa"
    return bytes(b)


def fat_volume(efi=True) -> bytes:
    b = bytearray(1 << 16)
    b[0:3] = b"\xeb\x3c\x90"
    b[0x36:0x3B] = b"FAT16"
    b[510:512] = b"\x55\xaa"
    if efi:
        b[0x2600:0x260C] = b"EFI        \x10"         # a directory entry named EFI
    return bytes(b)


def iso_image(platforms=(0x00,), catalog=True) -> bytes:
    b = bytearray(0xA000 + 2048)
    b[0x8000] = 1
    b[0x8001:0x8006] = b"CD001"
    if catalog:
        b[0x8800] = 0
        b[0x8801:0x8806] = b"CD001"
        b[0x8807:0x881E] = b"EL TORITO SPECIFICATION"
        struct.pack_into("<I", b, 0x8847, 20)           # the boot catalog's sector
        cat = 20 * 2048
        b[cat], b[cat + 1] = 1, platforms[0]            # validation entry
        for n, p in enumerate(platforms[1:]):
            b[cat + 64 + 32 * n], b[cat + 65 + 32 * n] = 0x91, p
    return bytes(b)


def challenge(tmp_path, files: dict) -> Path:
    d = tmp_path / "19-boot-me"
    for rel, data in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return d


def ident(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return diskboot.identify(p)


# ----------------------------------------------------------------------------------- identification

def test_gpt_with_an_efi_system_partition_is_a_uefi_boot_disk(tmp_path):
    i = ident(tmp_path, "a.img", gpt_image())
    assert (i.format, i.table, i.firmware, i.role) == ("raw", "gpt", "uefi", "boot")
    assert i.size == 1 << 20 and "EFI System Partition" in i.why


def test_gpt_without_an_efi_system_partition_is_not_called_uefi(tmp_path):
    i = ident(tmp_path, "a.img", gpt_image(guid=LINUX))
    assert (i.table, i.firmware, i.role) == ("gpt", "bios", "boot")


def test_gpt_header_on_a_4k_sector_disk_is_found(tmp_path):
    b = bytearray(gpt_image(sector=4096))
    i = ident(tmp_path, "a.img", bytes(b))
    assert (i.table, i.firmware) == ("gpt", "uefi") and "4096" in i.why


def test_mbr_roles_and_firmware(tmp_path):
    bios = ident(tmp_path, "b.img", mbr_image())
    assert (bios.table, bios.firmware, bios.role) == ("mbr", "bios", "boot") and "0x83" in bios.why
    uefi = ident(tmp_path, "u.img", mbr_image(types=(0xEF, 0x83)))
    assert (uefi.table, uefi.firmware, uefi.role) == ("mbr", "uefi", "boot")
    data = ident(tmp_path, "d.img", mbr_image(active=False, code=False))
    assert (data.table, data.role, data.firmware) == ("mbr", "data", "unknown")


def test_a_bare_fat_volume_boots_only_with_an_efi_directory(tmp_path):
    boot = ident(tmp_path, "uefi_disk.img", fat_volume(efi=True))
    assert (boot.table, boot.firmware, boot.role) == ("none", "uefi", "boot")
    data = ident(tmp_path, "data.img", fat_volume(efi=False))
    assert (data.table, data.role) == ("none", "data")


def test_container_formats_and_iso(tmp_path):
    q = ident(tmp_path, "x.bin", b"QFI\xfb" + bytes(4096))
    assert (q.format, q.role) == ("qcow2", "boot")
    v = ident(tmp_path, "y.bin", b"KDMV" + bytes(4096))
    assert v.format == "vmdk"
    bios_iso = ident(tmp_path, "b.iso", iso_image(platforms=(0x00,)))
    assert (bios_iso.format, bios_iso.firmware, bios_iso.role) == ("iso", "bios", "boot")
    uefi_iso = ident(tmp_path, "u.iso", iso_image(platforms=(0x00, 0xEF)))
    assert (uefi_iso.firmware, uefi_iso.role) == ("uefi", "boot")
    plain = ident(tmp_path, "p.iso", iso_image(catalog=False))
    assert (plain.format, plain.role) == ("iso", "data") and "no El Torito" in plain.why


def test_other_container_and_volume_signatures(tmp_path):
    vhdx = ident(tmp_path, "a.bin", b"vhdxfile" + bytes(4096))
    vdi = ident(tmp_path, "b.bin", bytes(0x40) + b"\x7f\x10\xda\xbe" + bytes(4096))
    dyn_vhd = ident(tmp_path, "c.bin", b"conectix" + bytes(4096))
    fixed_vhd = ident(tmp_path, "d.bin", bytes(4096) + b"conectix" + bytes(504))
    assert [i.format for i in (vhdx, vdi, dyn_vhd, fixed_vhd)] == ["vhdx", "vdi", "vpc", "vpc"]
    ext = bytearray(4096)
    ext[1080:1082] = b"\x53\xef"
    e = ident(tmp_path, "e.bin", bytes(ext))
    assert (e.format, e.table, e.role) == ("raw", "none", "data") and "ext2/3/4" in e.why
    odd = bytearray(4096)
    odd[446] = 0x7F                                          # not a partition status byte
    odd[510:512] = b"\x55\xaa"
    o = ident(tmp_path, "f.bin", bytes(odd))
    assert (o.table, o.role, o.firmware) == ("unknown", "boot", "bios")


def test_more_images_than_the_cap_are_named_not_dropped_silently(tmp_path, monkeypatch):
    monkeypatch.setattr(diskboot, "MAX_IMAGES", 2)
    d = challenge(tmp_path, {f"d{i}.img": gpt_image() for i in range(3)})
    p = diskboot.plan(d)
    assert [i["path"] for i in p.images] == ["d0.img", "d1.img"]
    assert any("3 images found" in n and "d2.img left out" in n for n in p.notes)
    assert not any("d2.img" in a for a in p.qemu_argv)


def test_what_is_not_an_image(tmp_path):
    assert ident(tmp_path, "notes.txt", b"just some notes\n" * 100) is None
    assert ident(tmp_path, "tiny.img", b"\x55\xaa") is None                    # below one sector
    assert ident(tmp_path, "pic.png", b"\x89PNG\r\n\x1a\n" + bytes(2048)) is None
    raw = ident(tmp_path, "blob.img", bytes(range(256)) * 16)                   # named like an image, no structure
    assert (raw.table, raw.role) == ("unknown", "data")
    assert ident(tmp_path, "blob.dat", bytes(range(256)) * 16) is None


def test_find_images_orders_boot_first_and_skips_private_and_own_folders(tmp_path):
    d = challenge(tmp_path, {
        "files/data.img": fat_volume(efi=False),
        "files/uefi_disk.img": gpt_image(),
        "files/readme.txt": b"boot me",
        ".ctf/secret.img": gpt_image(),
        "recon/boot/old.img": gpt_image(),
    })
    os.symlink(d / "files" / "uefi_disk.img", d / "files" / "link.img")
    got = diskboot.find_images(d)
    assert [i.path for i in got] == ["files/uefi_disk.img", "files/data.img"]
    assert [i.role for i in got] == ["boot", "data"]
    with pytest.raises(diskboot.BootError, match="not a challenge folder"):
        diskboot.find_images(d / "nope")


# --------------------------------------------------------------------------------------------- plan

def pink_like(tmp_path) -> Path:
    return challenge(tmp_path, {"files/uefi_disk.img": gpt_image(), "files/data.img": fat_volume(efi=False)})


def value_after(argv, flag):
    return [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == flag]


def test_plan_is_networkless_read_only_and_boots_the_uefi_disk_first(tmp_path):
    d = pink_like(tmp_path)
    p = diskboot.plan(d)
    tag = next(im.tag for im in images.load() if im.name == "qemu-boot")
    assert p.image_tag == tag == "ctf-qemu-boot:1" and p.firmware == "uefi"
    s = p.start_argv
    assert s[:2] == ["docker", "run"] and "-d" in s
    assert value_after(s, "--network") == ["none"]
    assert "--pull=never" in s and value_after(s, "--cap-drop") == ["ALL"] and "--read-only" in s
    assert value_after(s, "--security-opt") == ["no-new-privileges"]
    assert not any(a in ("-p", "--publish", "-P", "--privileged") or a.startswith("--publish") for a in s)
    mounts = value_after(s, "-v")
    assert f"{d.resolve()}:/img:ro" in mounts and f"{d.resolve() / 'recon' / 'boot'}:/out" in mounts
    assert len(mounts) == 2
    # the image tag separates docker's options from QEMU's command line
    q = s[s.index(tag) + 1:]
    assert q == p.qemu_argv and q[0] == "qemu-system-x86_64"
    assert value_after(q, "-nic") == ["none"] and "-snapshot" in q
    assert not any(a.startswith(("-netdev", "-net")) for a in q)
    drives = value_after(q, "-drive")
    assert drives[0] == f"if=pflash,format=raw,readonly=on,file={diskboot.OVMF_CODE}"
    assert drives[2:] == ["file=/img/files/uefi_disk.img,format=raw,media=disk,if=ide,index=0",
                          "file=/img/files/data.img,format=raw,media=disk,if=ide,index=1"]
    assert value_after(q, "-qmp") == [f"unix:{diskboot.QMP_SOCKET},server=on,wait=off"]
    assert p.qmp_argv == ["docker", "exec", "-i", p.container, "socat", "-", f"UNIX-CONNECT:{diskboot.QMP_SOCKET}"]
    assert p.container == diskboot.container_name(d) and p.container.startswith("ctf-boot-")
    assert value_after(s, "--name") == [p.container]
    assert not (d / "recon").exists()                       # plan() writes nothing
    assert diskboot.BootPlan.from_dict(json.loads(json.dumps(p.to_dict()))) == p


def test_plan_bios_iso_and_options(tmp_path):
    d = challenge(tmp_path, {"cd.iso": iso_image(platforms=(0x00,))})
    p = diskboot.plan(d, memory_mb=512, cpus=1, machine="pc")
    assert p.firmware == "bios" and not any("pflash" in a for a in p.qemu_argv)
    assert "file=/img/cd.iso,format=raw,media=cdrom,readonly=on,if=ide,index=0" in p.qemu_argv
    assert value_after(p.qemu_argv, "-m") == ["512"] and value_after(p.qemu_argv, "-machine") == ["pc,accel=tcg"]
    assert value_after(p.start_argv, "--memory") == ["1536m"]
    forced = diskboot.plan(d, firmware="uefi")
    assert forced.firmware == "uefi" and any("pflash" in a for a in forced.qemu_argv)


def test_plan_says_when_no_image_has_a_boot_structure(tmp_path):
    d = challenge(tmp_path, {"data.img": fat_volume(efi=False)})
    p = diskboot.plan(d)
    assert any("no image has a recognised boot structure" in n and "data.img" in n for n in p.notes)
    assert any("firmware not recognised" in n for n in p.notes) and p.firmware == "uefi"


@pytest.mark.parametrize("kwargs, needle", [
    ({"firmware": "coreboot"}, "firmware must be"),
    ({"machine": "microvm"}, "machine must be"),
    ({"drive_if": "floppy"}, "drive_if must be"),
    ({"memory_mb": 8}, "memory_mb must be"),
    ({"cpus": True}, "cpus must be"),
    ({"script": [{"reboot": 1}]}, "unknown action"),
])
def test_plan_refuses_unusable_options(tmp_path, kwargs, needle):
    with pytest.raises(diskboot.BootError, match=needle):
        diskboot.plan(pink_like(tmp_path), **kwargs)


def test_plan_refuses_no_image_and_unsafe_names(tmp_path):
    with pytest.raises(diskboot.BootError, match="no disk image found"):
        diskboot.plan(challenge(tmp_path, {"a.txt": b"x" * 1024}))
    d = challenge(tmp_path, {"files/evil,readonly=off.img": gpt_image()})
    with pytest.raises(diskboot.BootError, match="cannot be passed to QEMU safely"):
        diskboot.plan(d)


# ------------------------------------------------------------------------------------ operator gate

class Tty:
    def __init__(self, tty=True):
        self._tty = tty

    def isatty(self):
        return self._tty


def approve(p, typed=None, reason="first look at the desktop", tty=True):
    name = Path(p.challenge_dir).name
    return diskboot.approve_interactive(p, reason, stdin=Tty(tty), stdout=Tty(tty),
                                        prompt=lambda _q: name if typed is None else typed)


def test_approval_needs_a_person_at_a_terminal_who_types_the_folder_name(tmp_path):
    d = pink_like(tmp_path)
    p = diskboot.plan(d)
    asked = []
    with pytest.raises(PermissionError, match="interactive terminal"):
        diskboot.approve_interactive(p, "why", stdin=Tty(False), stdout=Tty(True),
                                     prompt=lambda q: asked.append(q) or d.name)
    with pytest.raises(PermissionError, match="interactive terminal"):
        diskboot.approve_interactive(p, "why", stdin=Tty(True), stdout=Tty(False),
                                     prompt=lambda q: asked.append(q) or d.name)
    assert asked == []                                        # nobody is asked when nobody is there
    with pytest.raises(PermissionError, match="did not match"):
        approve(p, typed="yes")
    with pytest.raises(PermissionError, match="needs a reason"):
        approve(p, reason="  ")
    with pytest.raises(PermissionError, match="for a boot plan"):
        diskboot.approve_interactive(d, "why", stdin=Tty(True), stdout=Tty(True), prompt=lambda q: d.name)
    diskboot.approve_interactive(p, "why", stdin=Tty(True), stdout=Tty(True),
                                 prompt=lambda q: asked.append(q) or d.name)
    assert shlex.join(p.start_argv) in asked[0]               # the person sees the exact command
    a = approve(p)
    assert a.challenge_dir == str(d.resolve()) and a.reason == "first look at the desktop" and a.by
    assert a.argv == tuple(p.start_argv)


def built_state(extra=None):
    im = next(i for i in images.load() if i.name == "qemu-boot")
    return {"images": {im.tag: {images.LABEL: images.content_hash(im)}}, **(extra or {})}


def test_start_runs_the_plan_once_and_records_who_approved(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    d = pink_like(tmp_path)
    plan = diskboot.plan(d)
    env = docker_stub(tmp_path, built_state())
    prof = event.load("pink")
    session = diskboot.start(plan, approve(plan), profile=prof, environ=env, clock=lambda: 1234.5)
    calls = docker_calls(env)
    assert [c[:2] for c in calls] == [["image", "inspect"], ["run", "--rm"]]
    assert calls[1] == plan.start_argv[1:]                    # exactly the plan, nothing added
    saved = json.loads((Path(plan.out_dir) / diskboot.SESSION_FILE).read_text())
    assert saved == session and saved["container"] == plan.container and saved["started"] == 1234.5
    assert saved["qmp_argv"] == plan.qmp_argv and saved["reason"] == "first look at the desktop"
    rec, = [r for r in ledger.read(tmp_path / "work") if r["event"] == diskboot.START_EVENT]
    assert rec["event_slug"] == "pink" and rec["container"] == plan.container
    assert rec["approved_by"] == session["approved_by"] and rec["challenge_dir"] == "19-boot-me"
    # a second start is refused before docker is called again
    with pytest.raises(diskboot.BootError, match="already started"):
        diskboot.start(plan, approve(plan), profile=prof, environ=env)
    assert len(docker_calls(env)) == 2


def test_start_refuses_without_an_approval_for_this_challenge(tmp_path):
    d = pink_like(tmp_path)
    plan = diskboot.plan(d)
    env = docker_stub(tmp_path, built_state())
    with pytest.raises(diskboot.BootError, match="needs an Approval"):
        diskboot.start(plan, {"by": "me", "reason": "x"}, environ=env)
    other = challenge(tmp_path / "other", {"x.img": gpt_image()})
    with pytest.raises(diskboot.BootError, match="approval is for"):
        diskboot.start(plan, approve(diskboot.plan(other)), environ=env)
    assert docker_calls(env) == [] and not (Path(plan.out_dir) / diskboot.SESSION_FILE).exists()


def test_start_names_the_build_step_when_the_image_is_missing(tmp_path):
    d = pink_like(tmp_path)
    plan = diskboot.plan(d)
    env = docker_stub(tmp_path, {"images": {}})
    with pytest.raises(diskboot.BootError, match=r"ctf-qemu-boot:1 is missing.*toolchain build --apply --only qemu-boot"):
        diskboot.start(plan, approve(plan), environ=env)
    assert [c[0] for c in docker_calls(env)] == ["image"]      # inspected, never run, never built or pulled
    assert not (Path(plan.out_dir) / diskboot.SESSION_FILE).exists()


def test_start_refuses_a_plan_that_is_not_the_networkless_run(tmp_path):
    d = pink_like(tmp_path)
    env = docker_stub(tmp_path, built_state())
    plan = diskboot.plan(d)
    i = plan.start_argv.index("--network")
    plan.start_argv[i + 1] = "host"
    with pytest.raises(diskboot.BootError, match="not this harness's networkless"):
        diskboot.start(plan, approve(plan), environ=env)
    plan = diskboot.plan(d)
    plan.start_argv[0:2] = ["docker", "build"]
    with pytest.raises(diskboot.BootError, match="not this harness's networkless"):
        diskboot.start(plan, approve(plan), environ=env)
    assert docker_calls(env) == []


def test_a_hand_built_or_edited_approval_is_refused(tmp_path):
    d = pink_like(tmp_path)
    plan = diskboot.plan(d)
    env = docker_stub(tmp_path, built_state())
    forged = diskboot.Approval(str(d.resolve()), "me", "no person asked", tuple(plan.start_argv))
    with pytest.raises(diskboot.BootError, match="needs an Approval from approve_interactive"):
        diskboot.start(plan, forged, environ=env)
    real = approve(plan)
    for changed in (dataclasses.replace(real, reason="something else"),
                    dataclasses.replace(real, argv=tuple(plan.start_argv) + ("--privileged",))):
        with pytest.raises(diskboot.BootError, match="needs an Approval from approve_interactive"):
            diskboot.start(plan, changed, environ=env)
        object.__setattr__(changed, "_seal", real._seal)      # the seal copied over: it covers every field
        with pytest.raises(diskboot.BootError, match="needs an Approval from approve_interactive"):
            diskboot.start(plan, changed, environ=env)
    assert docker_calls(env) == []
    diskboot.start(plan, real, environ=env)                   # the sealed one, unchanged, is taken
    assert [c[0] for c in docker_calls(env)] == ["image", "run"]


def _tamper_insert_after(argv, flag, *extra):
    i = argv.index(flag) + 1
    argv[i:i] = list(extra)


TAMPERS = {
    "privileged": lambda p: _tamper_insert_after(p.start_argv, "-d", "--privileged", "--cap-add", "ALL"),
    "host-mount": lambda p: _tamper_insert_after(p.start_argv, "-d", "-v", "/:/host"),
    "qemu-network": lambda p: [a.__setitem__(a.index("-nic") + 1, "user") for a in (p.start_argv, p.qemu_argv)],
    "no-snapshot": lambda p: [a.remove("-snapshot") for a in (p.start_argv, p.qemu_argv)],
    "writable-images": lambda p: p.start_argv.__setitem__(
        p.start_argv.index(f"{p.challenge_dir}:{diskboot.GUEST_IMG}:ro"), f"{p.challenge_dir}:{diskboot.GUEST_IMG}"),
}


@pytest.mark.parametrize("how", sorted(TAMPERS))
def test_an_edited_plan_is_refused_even_when_its_command_was_approved(tmp_path, how):
    """plan.json is a file anyone can edit. The person may approve what they are shown, but start()
    runs only what this harness writes for the folder: an edit that keeps `docker run`, the tag and
    `--network none` is still refused, and docker is never run."""
    d = pink_like(tmp_path)
    env = docker_stub(tmp_path, built_state())
    plan = diskboot.BootPlan.from_dict(json.loads(json.dumps(diskboot.plan(d).to_dict())))
    TAMPERS[how](plan)
    assert value_after(plan.start_argv, "--network") == ["none"]       # the old check alone would pass it
    with pytest.raises(diskboot.BootError, match="differs from what this harness writes"):
        diskboot.start(plan, approve(plan), environ=env)
    assert docker_calls(env) == [] and not (Path(plan.out_dir) / diskboot.SESSION_FILE).exists()


def test_an_approval_is_for_the_command_it_showed(tmp_path):
    d = pink_like(tmp_path)
    env = docker_stub(tmp_path, built_state())
    shown = diskboot.plan(d)
    other = diskboot.plan(d, memory_mb=1024)                  # an honest plan, but not the one approved
    with pytest.raises(diskboot.BootError, match="approval was given for a different command"):
        diskboot.start(other, approve(shown), environ=env)
    assert docker_calls(env) == []


def test_a_plan_without_its_options_or_for_a_changed_folder_is_refused(tmp_path):
    d = pink_like(tmp_path)
    env = docker_stub(tmp_path, built_state())
    old = diskboot.BootPlan.from_dict({k: v for k, v in diskboot.plan(d).to_dict().items() if k != "options"})
    with pytest.raises(diskboot.BootError, match="does not record the options"):
        diskboot.start(old, approve(old), environ=env)
    plan = diskboot.plan(d)
    (d / "files" / "extra.img").write_bytes(gpt_image())     # an image added after the plan was made
    with pytest.raises(diskboot.BootError, match=r"differs from what this harness writes.*images"):
        diskboot.start(plan, approve(plan), environ=env)
    assert diskboot.check_plan(diskboot.plan(d), None) is None
    assert docker_calls(env) == []


def test_start_reports_a_failed_docker_run_and_keeps_no_session(tmp_path):
    d = pink_like(tmp_path)
    plan = diskboot.plan(d)
    env = docker_stub(tmp_path, built_state({"run_rc": 125}))
    with pytest.raises(diskboot.BootError, match="docker run exited 125"):
        diskboot.start(plan, approve(plan), environ=env)
    assert not (Path(plan.out_dir) / diskboot.SESSION_FILE).exists()


def test_the_ledger_records_the_outcome_of_the_run_not_the_intent(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    prof = event.load("pink")
    d = pink_like(tmp_path)
    plan = diskboot.plan(d)
    failing = docker_stub(tmp_path / "a", built_state({"run_rc": 125}))
    with pytest.raises(diskboot.BootError, match="docker run exited 125"):
        diskboot.start(plan, approve(plan), profile=prof, environ=failing)
    rec, = [r for r in ledger.read(tmp_path / "work") if r["event"] == diskboot.START_EVENT]
    assert rec["outcome"] == "failed" and "docker run exited 125" in rec["detail"]
    working = docker_stub(tmp_path / "b", built_state())
    diskboot.start(plan, approve(plan), profile=prof, environ=working)
    recs = [r for r in ledger.read(tmp_path / "work") if r["event"] == diskboot.START_EVENT]
    assert [r["outcome"] for r in recs] == ["failed", "started"] and "detail" not in recs[1]

    def hangs(argv, **kw):
        if argv[1] == "run":
            raise subprocess.TimeoutExpired(argv, 120)
        return subprocess.run(argv, **kw)

    (Path(plan.out_dir) / diskboot.SESSION_FILE).unlink()
    with pytest.raises(diskboot.BootError, match="may exist"):
        diskboot.start(plan, approve(plan), profile=prof, environ=working, run=hangs)
    last = [r for r in ledger.read(tmp_path / "work") if r["event"] == diskboot.START_EVENT][-1]
    assert last["outcome"] == "unknown" and plan.container in last["detail"]

    def cannot_exec(argv, **kw):                               # docker present but fails to exec
        if argv[1] == "run":
            raise FileNotFoundError(2, "No such file or directory", argv[0])
        return subprocess.run(argv, **kw)

    with pytest.raises(diskboot.BootError, match="did not start the boot container"):
        diskboot.start(plan, approve(plan), profile=prof, environ=working, run=cannot_exec)
    last = [r for r in ledger.read(tmp_path / "work") if r["event"] == diskboot.START_EVENT][-1]
    assert last["outcome"] == "failed"                         # an exec failure created nothing
    assert "FileNotFoundError" in last["detail"] and "No such file or directory" in last["detail"]
    assert not (Path(plan.out_dir) / diskboot.SESSION_FILE).exists()


def test_a_real_docker_is_refused_under_testing(tmp_path):
    d = pink_like(tmp_path)
    plan = diskboot.plan(d)
    env = docker_stub(tmp_path, built_state(), marker=False)
    with pytest.raises(diskboot.BootError, match="not a test stub"):
        diskboot.start(plan, approve(plan), environ=env)
    assert docker_calls(env) == []                             # the unmarked docker was never executed
    with pytest.raises(diskboot.BootError, match="not a test stub"):
        diskboot.connect_session({"qmp_argv": plan.qmp_argv}, environ=env)
    assert docker_calls(env) == []


def test_start_without_docker_names_it_and_prepares_the_snapshot_folder_only_when_it_runs(tmp_path):
    d = pink_like(tmp_path)
    plan = diskboot.plan(d)
    empty = tmp_path / "emptybin"
    empty.mkdir()
    with pytest.raises(diskboot.BootError, match="docker is not on PATH"):
        diskboot.start(plan, approve(plan), environ={"PATH": str(empty), "CTF_TESTING": "1"})
    assert not Path(plan.out_dir).exists()
    env = docker_stub(tmp_path, built_state())
    diskboot.start(plan, approve(plan), environ=env)
    assert (Path(plan.out_dir) / ".snapshot").is_dir()        # where the plan points QEMU's TMPDIR
    assert f"TMPDIR={diskboot.GUEST_OUT}/.snapshot" in plan.start_argv


def test_load_session_says_who_starts_the_boot(tmp_path):
    with pytest.raises(diskboot.BootError, match="the operator starts the boot first"):
        diskboot.load_session(tmp_path)
    (tmp_path / diskboot.SESSION_FILE).write_text("{}")
    with pytest.raises(diskboot.BootError, match="no qmp_argv"):
        diskboot.load_session(tmp_path)


def test_a_rewritten_session_transport_is_refused_and_never_run(tmp_path):
    """session.json is a file anyone can edit, and its qmp_argv is run: only the exact `docker exec
    -i <ctf-boot-...> socat` transport the plan writes is accepted."""
    d = pink_like(tmp_path)
    plan = diskboot.plan(d)
    env = docker_stub(tmp_path, built_state())
    out = Path(plan.out_dir)
    out.mkdir(parents=True)
    canary = tmp_path / "ran"
    bad = {
        "a shell": ["sh", "-c", f"touch {canary}"],
        "another docker verb": ["docker", "run", "--rm", plan.container, "socat", "-", "x"],
        "an extra argument": plan.qmp_argv + ["-v"],
        "another socket": plan.qmp_argv[:6] + ["UNIX-CONNECT:/tmp/other.sock"],
        "not a boot container": ["docker", "exec", "-i", "postgres", "socat", "-",
                                 f"UNIX-CONNECT:{diskboot.QMP_SOCKET}"],
    }
    for what, argv in bad.items():
        session = {"container": plan.container, "qmp_argv": argv}
        (out / diskboot.SESSION_FILE).write_text(json.dumps(session))
        with pytest.raises(diskboot.BootError, match="not this harness's"):
            diskboot.load_session(out)
        with pytest.raises(diskboot.BootError, match="not this harness's"):
            diskboot.connect_session(session, environ=env)
        with pytest.raises(diskboot.BootError, match="not this harness's"):
            diskboot.end_session(out, environ=env)
    # the right shape for another challenge's container is refused for this challenge
    elsewhere = diskboot.container_name(tmp_path / "elsewhere")
    session = {"container": elsewhere, "qmp_argv": diskboot.plan(d).qmp_argv[:3] + [elsewhere]
               + plan.qmp_argv[4:]}
    (out / diskboot.SESSION_FILE).write_text(json.dumps(session))
    assert diskboot.load_session(out)["container"] == elsewhere           # well-formed on its own
    with pytest.raises(diskboot.BootError, match=f"not {plan.container!r}"):
        diskboot.load_session(out, d)
    with pytest.raises(diskboot.BootError, match="names container"):
        diskboot.connect_session({"container": plan.container, "qmp_argv": session["qmp_argv"]}, environ=env)
    assert docker_calls(env) == [] and not canary.exists()


# ---------------------------------------------------------------------------------------------- QMP

@pytest.mark.parametrize("transport", ["unix", "tcp"])
def test_qmp_negotiates_before_any_command(transport):
    with StubQMP(transport=transport) as stub:
        with diskboot.QMP.connect(stub.spec) as qmp:
            assert qmp.greeting["version"]["qemu"]["major"] == 9
            assert qmp.status() == {"status": "running", "running": True}
        assert stub.executed() == ["qmp_capabilities", "query-status"]


def test_qmp_tcp_is_loopback_only_and_specs_are_checked():
    with pytest.raises(diskboot.QMPError, match="loopback only"):
        diskboot.QMP.connect("tcp:10.0.0.5:4444")
    with pytest.raises(diskboot.QMPError, match="loopback only"):
        diskboot.QMP.connect_tcp("qemu.example.org", 4444)
    for bad in ("tcp:127.0.0.1", "unix:", "ssh:host", "4444"):
        with pytest.raises(diskboot.QMPError):
            diskboot.QMP.connect(bad)
    with pytest.raises(diskboot.QMPError, match="cannot connect"):
        diskboot.QMP.connect("unix:/nonexistent/q.sock")


def test_qmp_error_replies_carry_class_and_description():
    with StubQMP(errors={"screendump": {"class": "GenericError", "desc": "no such display"}}) as stub:
        with diskboot.QMP.connect(stub.spec) as qmp:
            with pytest.raises(diskboot.QMPError, match="screendump: no such display") as ei:
                qmp.screendump("/out/x.ppm")
            assert ei.value.cls == "GenericError"
            assert qmp.status()["running"] is True              # the session survives an error reply


def test_qmp_events_are_kept_apart_from_replies(tmp_path):
    ev = {"event": "RESET", "timestamp": {"seconds": 1, "microseconds": 2}, "data": {"guest": True}}
    frame = ppm(4, 2, lambda x, y: (x, y, 0))
    with StubQMP(frames=[frame], events=[ev]) as stub:
        with diskboot.QMP.connect(stub.spec) as qmp:
            assert qmp.execute("screendump", filename=str(tmp_path / "s" / "a.ppm")) == {}
            assert qmp.events == [ev]
    assert (tmp_path / "s" / "a.ppm").read_bytes() == frame


def test_qmp_gives_up_on_a_silent_vm():
    # This is about real elapsed time: a hung QEMU must not hang the driver. Only a lower bound is asserted.
    with StubQMP(mute=["query-status"]) as stub:
        with diskboot.QMP.connect(stub.spec, timeout=0.4) as qmp:
            t0 = time.monotonic()
            with pytest.raises(diskboot.QMPError, match="no reply to query-status within 0.4 s"):
                qmp.status()
            assert time.monotonic() - t0 >= 0.4


def test_qmp_reports_a_closed_connection():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def accept_and_close():
        c, _ = srv.accept()
        c.close()

    t = threading.Thread(target=accept_and_close, daemon=True)
    t.start()
    try:
        with pytest.raises(diskboot.QMPError, match="closed while waiting for the QMP greeting"):
            diskboot.QMP.connect(f"tcp:127.0.0.1:{srv.getsockname()[1]}")
    finally:
        t.join(timeout=5)
        srv.close()


def test_qmp_refuses_an_endpoint_that_is_not_qmp():
    with StubQMP(greeting=False, mute=["qmp_capabilities"]) as stub:
        with pytest.raises(diskboot.QMPError, match="no reply to the QMP greeting"):
            diskboot.QMP.connect(stub.spec, timeout=0.3)


@pytest.mark.parametrize("banner, needle", [
    (b"SSH-2.0-OpenSSH_9.6\r\n", "not a QMP message while waiting for the QMP greeting"),
    (b'{"hello": "world"}\n', "expected the QMP greeting"),
    (b"[1, 2, 3]\n", "not a QMP message"),
])
def test_qmp_names_a_service_that_speaks_something_else(banner, needle):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def serve():
        c, _ = srv.accept()
        c.sendall(banner)
        c.recv(1024)
        c.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        with pytest.raises(diskboot.QMPError, match=needle):
            diskboot.QMP.connect(f"tcp:127.0.0.1:{srv.getsockname()[1]}", timeout=5)
    finally:
        srv.close()
        t.join(timeout=5)


def test_keys_text_and_mouse_on_the_wire():
    with StubQMP() as stub:
        with diskboot.QMP.connect(stub.spec) as qmp:
            qmp.send_key("ctrl-alt-f2")
            qmp.send_key("ret", hold_ms=250)
            qmp.type_text("Hi!\n")
            qmp.mouse_rel(-5, 7)
            qmp.click("right")
            with pytest.raises(diskboot.BootError, match="unknown key.*hyper"):
                qmp.send_key("ctrl-hyper")
            with pytest.raises(diskboot.BootError, match="unknown mouse button"):
                qmp.click("thumb")
        sent = [c for c in stub.commands if c["execute"] != "qmp_capabilities"]

    def chord(*keys):
        return {"keys": [{"type": "qcode", "data": k} for k in keys]}

    assert [c["execute"] for c in sent] == ["send-key"] * 6 + ["input-send-event"] * 3
    assert sent[0]["arguments"] == chord("ctrl", "alt", "f2")
    assert sent[1]["arguments"] == {**chord("ret"), "hold-time": 250}
    assert [c["arguments"] for c in sent[2:6]] == [chord("shift", "h"), chord("i"), chord("shift", "1"), chord("ret")]
    assert sent[6]["arguments"] == {"events": [{"type": "rel", "data": {"axis": "x", "value": -5}},
                                               {"type": "rel", "data": {"axis": "y", "value": 7}}]}
    assert [c["arguments"]["events"][0]["data"] for c in sent[7:]] == [{"down": True, "button": "right"},
                                                                     {"down": False, "button": "right"}]


def test_text_that_a_us_layout_cannot_type_is_named():
    assert diskboot.text_chords("a_B {x}|~") == ["a", "shift-minus", "shift-b", "spc", "shift-bracket_left", "x",
                                                 "shift-bracket_right", "shift-backslash", "shift-grave_accent"]
    with pytest.raises(diskboot.BootError, match="cannot type 'ü'"):
        diskboot.text_chords("grüß")
    assert diskboot.parse_chord("Meta_L-D") == ["meta_l", "d"]
    with pytest.raises(diskboot.BootError, match="empty key"):
        diskboot.parse_chord("ctrl--")


def test_qmp_over_a_command_transport(tmp_path):
    import sys
    frame = ppm(3, 3, lambda x, y: (9, 9, 9))
    state = stdio_state(tmp_path, [frame])
    argv = [sys.executable, "-I", str(Path(__file__).with_name("qmp_stub.py")), "--stdio", state]
    with diskboot.QMP.connect(argv) as qmp:
        qmp.screendump(str(tmp_path / "shot.ppm"))
        qmp.quit()
    assert (tmp_path / "shot.ppm").read_bytes() == frame
    assert [m["execute"] for m in stdio_log(tmp_path)] == ["qmp_capabilities", "screendump", "quit"]
    with pytest.raises(diskboot.QMPError, match="cannot start the QMP transport"):
        diskboot.QMP.connect([str(tmp_path / "no-such-binary")])


# ------------------------------------------------------------------------------------------- frames

def png_pixels(data: bytes):
    """Decode an 8-bit RGB PNG with filter 0 rows (what write_png emits), checking every CRC."""
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    at, chunks = 8, []
    while at < len(data):
        n, kind = struct.unpack(">I4s", data[at:at + 8])
        body = data[at + 8: at + 8 + n]
        crc, = struct.unpack(">I", data[at + 8 + n: at + 12 + n])
        assert crc == zlib.crc32(kind + body) & 0xFFFFFFFF
        chunks.append((kind, body))
        at += 12 + n
    assert [k for k, _ in chunks] == [b"IHDR", b"IDAT", b"IEND"]
    w, h, depth, colour, comp, filt, lace = struct.unpack(">IIBBBBB", chunks[0][1])
    assert (depth, colour, comp, filt, lace) == (8, 2, 0, 0, 0)
    raw = zlib.decompress(chunks[1][1])
    stride = w * 3 + 1
    assert len(raw) == stride * h and all(raw[y * stride] == 0 for y in range(h))
    return w, h, b"".join(raw[y * stride + 1:(y + 1) * stride] for y in range(h))


def test_ppm_to_png_keeps_every_pixel():
    data = ppm(7, 5, lambda x, y: (x * 30, y * 50, (x + y) % 256))
    f = diskboot.read_ppm(data)
    assert (f.width, f.height) == (7, 5) and f.pixels[:3] == bytes((0, 0, 0)) and f.pixels[-3:] == bytes((180, 200, 10))
    assert png_pixels(diskboot.write_png(f)) == (7, 5, f.pixels)
    with_comment = b"P6\n# made by qemu\n7 5\n255\n" + f.pixels
    assert diskboot.read_ppm(with_comment) == f


@pytest.mark.parametrize("bad, needle", [
    (b"P5\n2 2\n255\n" + bytes(4), "not a binary PPM"),
    (b"P6\n2 2\n65535\n" + bytes(24), "unsupported PPM"),
    (b"P6\n2 2\n255\n" + bytes(11), "truncated PPM screenshot: 11 of 12"),
    (b"", "not a binary PPM"),
])
def test_bad_screenshots_are_named(bad, needle):
    with pytest.raises(diskboot.BootError, match=needle):
        diskboot.read_ppm(bad)


def frame_with(w, h, changes):
    px = {(x, y): (10, 20, 30) for x in range(w) for y in range(h)}
    px.update(changes)
    return diskboot.read_ppm(ppm(w, h, lambda x, y: px[(x, y)]))


def test_changed_box_is_exact_at_every_edge():
    base = frame_with(16, 9, {})
    assert diskboot.changed_box(base, base) is None
    assert diskboot.changed_box(base, frame_with(16, 9, {(0, 0): (10, 20, 31)})) == (0, 0, 1, 1)
    assert diskboot.changed_box(base, frame_with(16, 9, {(15, 8): (11, 20, 30)})) == (15, 8, 16, 9)
    two = frame_with(16, 9, {(3, 2): (0, 0, 0), (11, 6): (10, 21, 30)})
    assert diskboot.changed_box(base, two) == (3, 2, 12, 7)
    assert diskboot.changed_box(base, frame_with(8, 4, {})) == (0, 0, 8, 4)        # another size: the whole screen


def test_crop_takes_exactly_the_box_and_clips_to_the_frame():
    f = diskboot.read_ppm(ppm(6, 4, lambda x, y: (x, y, 7)))
    c = diskboot.crop(f, (2, 1, 5, 3))
    assert (c.width, c.height) == (3, 2)
    assert c.pixels == bytes((2, 1, 7, 3, 1, 7, 4, 1, 7, 2, 2, 7, 3, 2, 7, 4, 2, 7))
    clipped = diskboot.crop(f, (-8, -8, 2, 2))
    assert (clipped.width, clipped.height) == (2, 2) and clipped.pixels[:3] == bytes((0, 0, 7))
    with pytest.raises(diskboot.BootError, match="empty crop box"):
        diskboot.crop(f, (5, 1, 5, 3))


# ------------------------------------------------------------------------------------------ observe

@pytest.mark.parametrize("script, needle", [
    ({"shot": "a"}, "JSON list of steps"),
    ([{"shot": "a", "wait": 1}], "step 0: a step is an object with exactly one action"),
    ([{"wait": 1}, {"reboot": True}], "step 1: unknown action 'reboot'"),
    ([{"shot": "../../etc/x"}], "step 0: a shot name"),
    ([{"burst": {"name": "b", "count": 0}}], "step 0: burst count"),
    ([{"burst": {"name": "b", "count": 2, "every": 1}}], "step 0: burst takes"),
    ([{"wait": 3000}, {"wait": 3000}], "step 1: the script waits more than"),
    ([{"key": "ctrl-banana"}], "step 0: unknown key"),
    ([{"type": "héllo"}], "step 0: cannot type"),
    ([{"mouse": [1]}], r"step 0: mouse takes \[x, y\]"),
    ([{"click": "double"}], "step 0: click takes"),
    ([{"wait": -1}], "step 0: wait must be"),
    ([{"burst": {"name": "b", "count": 2.5}}], "step 0: burst count must be a whole number"),
    ([{"burst": {"name": "b", "count": 601}}], "step 0: burst count"),
    ([{"burst": {"name": "b", "count": 600, "interval": 600}}], "step 0: the script waits more than"),
    ([{"key": ["ctrl", "c"]}], "step 0: key takes a chord string"),
    ([{"mouse_rel": [0, 99999]}], "step 0: mouse_rel must be"),
    ([{"wait": 0}] * 501, "at most 500 steps"),
])
def test_a_bad_script_is_refused_whole(script, needle):
    with pytest.raises(diskboot.BootError, match=needle):
        diskboot.validate_script(script)


def test_nothing_reaches_the_vm_when_a_later_step_is_bad(tmp_path):
    with StubQMP(frames=[ppm(2, 2, lambda x, y: (1, 1, 1))]) as stub:
        with diskboot.QMP.connect(stub.spec) as qmp:
            with pytest.raises(diskboot.BootError, match="step 2: unknown action"):
                diskboot.observe(qmp, [{"key": "ret"}, {"shot": "a"}, {"format_disk": True}], tmp_path / "out")
        assert stub.executed() == ["qmp_capabilities"]
    assert not (tmp_path / "out" / "shots").exists()


W, H = 64, 48
BOX = (40, 10, 52, 22)


def desktop(glyph=None):
    """A desktop: a gradient, with one solid 'glyph' colour in BOX (or the plain gradient)."""
    def px(x, y):
        if glyph is not None and BOX[0] <= x < BOX[2] and BOX[1] <= y < BOX[3]:
            return glyph
        return (x * 3, y * 5, 99)
    return ppm(W, H, px)


def test_observe_runs_the_script_and_hands_the_screens_to_vision(tmp_path):
    a, b, c, d = desktop((255, 0, 0)), desktop((0, 255, 0)), desktop((0, 0, 255)), desktop((255, 255, 0))
    frames = [desktop(), a, a, b, c, c, d]                     # one shot, then a burst with two repeats
    script = [{"wait": 5}, {"shot": "desk"}, {"key": "ctrl-alt-f2"}, {"type": "ab"}, {"mouse": [10, 20]},
              {"click": "left"}, {"burst": {"name": "wall", "count": 6, "interval": 2}}]
    out = tmp_path / "out"
    guest = tmp_path / "guest"                                  # the same folder under the name the VM uses
    out.mkdir()
    guest.symlink_to(out)
    slept = []
    with StubQMP(frames=frames) as stub:
        with diskboot.QMP.connect(stub.spec) as qmp:
            obs = diskboot.observe(qmp, script, out, guest_out=str(guest), sleep=slept.append,
                                   flag_prefixes=["PINK"])
        wire = [c for c in stub.commands if c["execute"] != "qmp_capabilities"]

    assert slept == [5.0, 2.0, 2.0, 2.0, 2.0, 2.0]             # time is the injected sleep, nothing else
    assert [c["execute"] for c in wire] == (["screendump", "send-key", "send-key", "send-key"]
                                            + ["input-send-event"] * 4 + ["screendump"] * 6)
    assert wire[0]["arguments"]["filename"] == f"{guest}/shots/0001-desk.ppm"
    assert wire[4]["arguments"]["events"][0]["data"] == {"axis": "x", "value": -16383}    # park, then move
    assert [e["data"]["value"] for e in wire[5]["arguments"]["events"]] == [10, 20]

    assert [s.file for s in obs.shots] == ["shots/0001-desk.png", "shots/0002-wall.png", "shots/0003-wall.png",
                                           "shots/0004-wall.png", "shots/0005-wall.png"]
    assert obs.duplicates_dropped == 2 and [s.step for s in obs.shots] == [1, 6, 6, 6, 6]
    assert all((s.width, s.height) == (W, H) for s in obs.shots)
    assert png_pixels((out / "shots/0003-wall.png").read_bytes()) == (W, H, diskboot.read_ppm(b).pixels)
    assert sorted(p.name for p in (out / "shots").iterdir()) == [Path(s.file).name for s in obs.shots]   # no PPM left

    assert obs.animated == [{"step": 6, "name": "wall", "box": list(BOX), "cropped": True}]
    assert obs.crops == ["crops/0002-wall.png", "crops/0003-wall.png", "crops/0004-wall.png", "crops/0005-wall.png"]
    cw, ch, cpx = png_pixels((out / obs.crops[1]).read_bytes())
    pad = diskboot.CROP_PAD
    assert (cw, ch) == (BOX[2] - BOX[0] + 2 * pad, BOX[3] - BOX[1] + 2 * pad)
    centre = (ch // 2 * cw + cw // 2) * 3
    assert cpx[centre:centre + 3] == bytes((0, 255, 0))        # the glyph of the second distinct frame

    handoff = json.loads((out / diskboot.HANDOFF_FILE).read_text())
    assert handoff["needs"] == "vision" and handoff["flag_prefixes"] == ["PINK"]
    assert [s["file"] for s in handoff["shots"]] == [s.file for s in obs.shots]
    assert handoff["crops"] == obs.crops and handoff["animated"] == obs.animated
    assert "Do not complete" in handoff["ask"] and obs.handoff == diskboot.HANDOFF_FILE


def test_a_burst_that_repaints_the_whole_screen_is_not_cropped(tmp_path):
    f1 = ppm(8, 8, lambda x, y: (0, 0, 0))
    f2 = ppm(8, 8, lambda x, y: (255, 255, 255))
    with StubQMP(frames=[f1, f2]) as stub:
        with diskboot.QMP.connect(stub.spec) as qmp:
            obs = diskboot.observe(qmp, [{"burst": {"name": "b", "count": 2, "interval": 0}}], tmp_path,
                                   sleep=lambda s: pytest.fail("a zero interval must not sleep"))
    assert obs.animated == [{"step": 0, "name": "b", "box": [0, 0, 8, 8], "cropped": False}]
    assert obs.crops == [] and not (tmp_path / "crops").exists() and len(obs.shots) == 2


def test_a_still_screen_has_no_animated_region_and_repeated_shots_are_kept(tmp_path):
    f = ppm(8, 8, lambda x, y: (5, 5, 5))
    with StubQMP(frames=[f]) as stub:
        with diskboot.QMP.connect(stub.spec) as qmp:
            obs = diskboot.observe(qmp, [{"shot": "one"}, {"shot": "two"},
                                         {"burst": {"name": "b", "count": 3, "interval": 0}}], tmp_path)
    # explicit shots are never dropped; a burst frame equal to the last kept frame is
    assert [s.name for s in obs.shots] == ["one", "two"] and obs.duplicates_dropped == 3
    assert obs.animated == [] and obs.crops == []


def test_validate_script_returns_the_steps_it_will_run():
    got = diskboot.validate_script([{"burst": {"count": 3}}, {"mouse": (5, 6.9)}, {"wait": 1.5}])
    assert got == [{"burst": {"name": "burst", "count": 3, "interval": 1.0}}, {"mouse": [5, 6]}, {"wait": 1.5}]
    assert diskboot.validate_script(diskboot.DEFAULT_SCRIPT)[0] == {"wait": 60}


def test_a_relative_mouse_step_is_sent_as_given(tmp_path):
    with StubQMP() as stub:
        with diskboot.QMP.connect(stub.spec) as qmp:
            obs = diskboot.observe(qmp, [{"mouse_rel": [3, -4]}, {"click": "middle"}], tmp_path)
        sent = [c["arguments"]["events"] for c in stub.commands if c["execute"] == "input-send-event"]
    assert [e["data"]["value"] for e in sent[0]] == [3, -4] and len(sent) == 3
    assert sent[1][0]["data"] == {"down": True, "button": "middle"}
    assert obs.shots == [] and json.loads((tmp_path / diskboot.HANDOFF_FILE).read_text())["shots"] == []


def test_observe_names_a_folder_the_vm_does_not_share(tmp_path):
    elsewhere = tmp_path / "elsewhere"
    with StubQMP(frames=[ppm(2, 2, lambda x, y: (1, 2, 3))]) as stub:
        with diskboot.QMP.connect(stub.spec) as qmp:
            with pytest.raises(diskboot.BootError, match="is not readable.*the folder the VM sees as"):
                diskboot.observe(qmp, [{"shot": "a"}], tmp_path / "out", guest_out=str(elsewhere))


def test_shot_numbers_continue_across_runs(tmp_path):
    f = ppm(2, 2, lambda x, y: (1, 2, 3))
    for expect in ("shots/0001-a.png", "shots/0002-a.png"):
        with StubQMP(frames=[f]) as stub:
            with diskboot.QMP.connect(stub.spec) as qmp:
                obs = diskboot.observe(qmp, [{"shot": "a"}], tmp_path)
        assert [s.file for s in obs.shots] == [expect]
    assert len(list((tmp_path / "shots").glob("*.png"))) == 2


# ------------------------------------------------------------------------------------------ session

def test_a_session_is_driven_and_ended_through_docker_exec(tmp_path):
    d = pink_like(tmp_path)
    plan = diskboot.plan(d)
    frame = desktop((1, 2, 3))
    env = docker_stub(tmp_path, built_state({"qmp_state": stdio_state(tmp_path, [frame])}))
    diskboot.start(plan, approve(plan), environ=env)
    out = Path(plan.out_dir)
    session = diskboot.load_session(out)
    with diskboot.connect_session(session, environ=env) as qmp:
        obs = diskboot.observe(qmp, [{"shot": "desk"}], out)    # this host's folder: the stub writes where told
    assert [s.file for s in obs.shots] == ["shots/0001-desk.png"]
    assert docker_calls(env)[-1] == plan.qmp_argv[1:]
    ended = diskboot.end_session(out, environ=env)
    assert ended["container"] == plan.container
    assert stdio_log(tmp_path)[-1]["execute"] == "quit"
    assert not (out / diskboot.SESSION_FILE).exists() and (out / "session-ended.json").exists()
    # only run / inspect / exec were ever asked of docker: nothing is stopped, killed or removed
    assert {c[0] for c in docker_calls(env)} == {"image", "run", "exec"}


def test_ending_a_session_whose_vm_is_gone_stops_nothing_and_keeps_the_record(tmp_path):
    d = pink_like(tmp_path)
    plan = diskboot.plan(d)
    env = docker_stub(tmp_path, built_state())                 # `exec` exits at once: no QMP behind it
    diskboot.start(plan, approve(plan), environ=env)
    out = Path(plan.out_dir)
    with pytest.raises(diskboot.BootError, match="was NOT stopped.*" + plan.container):
        diskboot.end_session(out, environ=env, timeout=5)
    assert (out / diskboot.SESSION_FILE).exists()
    assert {c[0] for c in docker_calls(env)} == {"image", "run", "exec"}
