"""Disk-image boot harness (B-131): plan a networkless QEMU/OVMF boot, drive it over QMP, and hand
the screens to a vision read.

Some challenges are a bootable disk set: the answer is what the booted system shows. At PINK+
"PINK OS" the first half of the flag was drawn on the desktop wallpaper one glyph at a time, and
nothing in the master could boot the image or look at it. This module is the reusable half:

    from ctf import diskboot
    infos = diskboot.find_images(challenge_dir)          # static: what each image is, which one boots
    plan = diskboot.plan(challenge_dir, infos)           # the docker/QEMU command lines; runs nothing
    session = diskboot.start(plan, approval)             # the OPERATOR's step: boots the image
    with diskboot.QMP.connect(spec) as qmp:              # "unix:PATH" | "tcp:127.0.0.1:PORT" | argv
        obs = diskboot.observe(qmp, script, out_dir)     # keys, mouse, screenshots
    obs.shots; obs.animated; obs.crops; obs.handoff      # PNG files and the vision hand-off

Booting a challenge disk image runs challenge code. So:

- Nothing here boots anything by itself. `plan()` only writes command lines. `start()` needs an
  `Approval`, which `approve_interactive()` issues only to a person at an interactive terminal who
  is shown the exact `docker run` command and types the challenge folder's name; no flag stands in
  for it. The approval is sealed to that command (a hand-built or edited `Approval` is refused) and
  `start()` re-plans from the folder and refuses a plan whose commands differ from what this
  harness writes, so an edited plan.json cannot add mounts, privileges or a network. The Python API
  is not a security boundary (code in this process can reach the module's privates); the boundary
  is the person at the terminal, which the CLI (`python -m ctf disk-boot start`) always asks. Build
  work and tests never call a real docker: under CTF_TESTING only a stub docker runs
  (ctf.toolchain.images.docker_path).
- The boot is networkless twice over: the container runs with `--network none` and QEMU with
  `-nic none`. A shipped client's network path is replayed from outside by ctf.clientreplay, under
  the event's scope guard, never by letting the guest reach the network.
- The images are mounted read-only and QEMU runs with `-snapshot`: the handout is never written.
- The image is `ctf-qemu-boot:1` (docker/qemu-boot/, listed in tools/images.toml). `start()` refuses
  with the build command when it is not built; it never builds or pulls.

QMP. `QMP` speaks the QEMU Machine Protocol over a Unix socket, a loopback TCP port (any other host
is refused) or the stdio of a command (the plan uses `docker exec -i <container> socat -
UNIX-CONNECT:/run/boot/qmp.sock`, which works with `--network none` and on macOS, where a socket in
a bind mount does not). Every reply has a deadline; that deadline is real elapsed time by nature (a
hung QEMU must not hang the driver).

Observe script: a JSON list of steps, validated as a whole before the first one runs.

    {"wait": 45}                                  seconds
    {"shot": "desktop"}                           one screenshot
    {"burst": {"name": "wall", "count": 30, "interval": 1.0}}   screenshots over time (animations)
    {"key": "ctrl-alt-f2"}                        one key chord, QEMU qcodes joined by "-"
    {"type": "startx\n"}                          text on a US layout (anything else: "key")
    {"mouse": [640, 400]}                         park the pointer top-left, then move there (PS/2,
                                                  relative: exact only when the guest moves it 1:1)
    {"mouse_rel": [10, -4]}                       a relative move
    {"click": "left"}                             left | middle | right

Screens. QEMU writes PPM; each one is converted to PNG here (stdlib only) and the PPM removed.
Within a burst a frame identical to the last kept one is dropped. When the frames of a run differ in
a region smaller than CROP_MAX_SHARE of the screen (a glyph box, a ticker), that region is cropped
out of every distinct frame into `crops/`, so the reader sees each state large. Reading what is
drawn is vision: `vision-handoff.json` lists the files and the question, and this module stops there.
"""
from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import re
import select
import shlex
import socket
import struct
import subprocess
import time
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from . import ledger, paths
from .event import EventProfile

IMAGE_NAME = "qemu-boot"                       # its entry in tools/images.toml
CONTAINER_PREFIX = "ctf-boot-"
GUEST_IMG = "/img"                              # the challenge folder, read-only, inside the container
GUEST_OUT = "/out"                              # the out folder inside the container
QMP_SOCKET = "/run/boot/qmp.sock"
OVMF_CODE = "/opt/ctf-boot/OVMF_CODE.fd"       # docker/qemu-boot/Dockerfile puts them there
OVMF_VARS = "/opt/ctf-boot/OVMF_VARS.fd"
SESSION_FILE = "session.json"
PLAN_FILE = "plan.json"
HANDOFF_FILE = "vision-handoff.json"
START_EVENT = "diskboot.start"                 # ledger record of an operator-approved boot

HEAD_BYTES = 4 * 1024 * 1024
MAX_IMAGES = 8
MIN_IMAGE_BYTES = 512
RAW_EXT = (".img", ".raw", ".dd")
SKIP_PARTS = frozenset({".ctf", ".git"})
OWN_OUTPUT = ("recon/boot", "recon/client")

QMP_TIMEOUT = 30.0                             # seconds for one QMP reply (real time: see the docstring)
MAX_STEPS = 500
MAX_WAIT_TOTAL = 3600.0
MAX_BURST = 600
CROP_MAX_SHARE = 0.6
CROP_PAD = 8
MAX_FRAME_BYTES = 64 * 1024 * 1024

DEFAULT_SCRIPT: tuple[dict, ...] = (
    {"wait": 60},
    {"shot": "boot"},
    {"burst": {"name": "watch", "count": 24, "interval": 2.5}},
)

_ESP_GUID = bytes.fromhex("28732ac11ff8d211ba4b00a0c93ec93b")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,40}$")

# QEMU qcodes this driver sends. `type` maps US-layout characters onto them.
QCODES = frozenset(
    list("abcdefghijklmnopqrstuvwxyz0123456789")
    + [f"f{i}" for i in range(1, 13)]
    + ["shift", "shift_r", "alt", "alt_r", "ctrl", "ctrl_r", "meta_l", "meta_r", "menu", "esc", "tab",
       "ret", "spc", "backspace", "delete", "insert", "home", "end", "pgup", "pgdn", "up", "down", "left",
       "right", "caps_lock", "num_lock", "scroll_lock", "print", "sysrq", "pause", "minus", "equal",
       "bracket_left", "bracket_right", "backslash", "semicolon", "apostrophe", "grave_accent", "comma",
       "dot", "slash", "less", "kp_enter", "kp_add", "kp_subtract", "kp_multiply", "kp_divide",
       "kp_decimal"] + [f"kp_{i}" for i in range(10)])
_PLAIN = {" ": "spc", "\n": "ret", "\t": "tab", "-": "minus", "=": "equal", "[": "bracket_left",
          "]": "bracket_right", "\\": "backslash", ";": "semicolon", "'": "apostrophe", "`": "grave_accent",
          ",": "comma", ".": "dot", "/": "slash"}
_SHIFTED = {"!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6", "&": "7", "*": "8", "(": "9",
            ")": "0", "_": "minus", "+": "equal", "{": "bracket_left", "}": "bracket_right",
            "|": "backslash", ":": "semicolon", '"': "apostrophe", "~": "grave_accent", "<": "comma",
            ">": "dot", "?": "slash"}
BUTTONS = ("left", "middle", "right")


class BootError(RuntimeError):
    """The harness cannot do what was asked; the message names what is missing or wrong."""


class QMPError(BootError):
    """QEMU answered a command with an error, or did not answer."""

    def __init__(self, message: str, cls: str = ""):
        super().__init__(message)
        self.cls = cls


# ------------------------------------------------------------------------------------ identification

@dataclass(frozen=True)
class ImageInfo:
    path: str                 # relative to the challenge folder
    format: str               # raw | qcow2 | vmdk | vhdx | vdi | vpc | iso (QEMU's driver; iso is raw + cdrom)
    table: str                # gpt | mbr | none | iso9660 | unknown | - (a container format: not looked into)
    firmware: str             # uefi | bios | unknown
    role: str                 # boot | data
    size: int
    why: str                  # one line: what was recognised


def _fs_boot_sector(sec: bytes) -> str | None:
    if sec[0x36:0x3B] in (b"FAT12", b"FAT16") or sec[0x52:0x57] == b"FAT32":
        return "fat"
    if sec[3:11] == b"NTFS    ":
        return "ntfs"
    if sec[3:11] == b"EXFAT   ":
        return "exfat"
    return None


def _gpt_has_esp(head: bytes, at: int) -> bool | None:
    """Whether the GPT whose header is at `at` lists an EFI System Partition; None when unreadable."""
    hdr = head[at:at + 92]
    if len(hdr) < 92:
        return None
    lba, count, size = struct.unpack_from("<Q", hdr, 72)[0], *struct.unpack_from("<II", hdr, 80)
    sector = at                                    # the header sits at LBA 1, so its offset is the sector size
    start = lba * sector
    if size < 128 or count > 1024 or start + count * size > len(head):
        return None
    return any(head[start + i * size: start + i * size + 16] == _ESP_GUID for i in range(count))


def _iso_uefi(fh, head: bytes) -> bool | None:
    """Whether an ISO's El Torito boot catalog has a UEFI entry; None when it has no catalog."""
    if head[0x8800:0x8801] != b"\x00" or head[0x8807:0x881E] != b"EL TORITO SPECIFICATION":
        return None
    sector = struct.unpack_from("<I", head, 0x8847)[0]
    try:
        fh.seek(sector * 2048)
        cat = fh.read(2048)
    except (OSError, OverflowError):
        return None
    if len(cat) < 64 or cat[0] != 1:
        return None
    if cat[1] == 0xEF:
        return True
    return any(cat[i] in (0x90, 0x91) and cat[i + 1] == 0xEF for i in range(32, len(cat) - 1, 32))


def identify(path: str | Path, rel: str | None = None) -> ImageInfo | None:
    """What a file is as a disk image, from its structure (read as data, never mounted or run), or
    None when it is not one. A `.img`/`.raw`/`.dd` file with no recognised structure is still listed
    (table "unknown", role data), since a raw volume need not have a signature."""
    p = Path(path)
    name = rel if rel is not None else p.name
    try:
        size = p.stat().st_size
        if size < MIN_IMAGE_BYTES:
            return None
        with open(p, "rb") as fh:
            head = fh.read(HEAD_BYTES)
            tail = b""
            if size >= 512:
                fh.seek(size - 512)
                tail = fh.read(512)
            iso_uefi = _iso_uefi(fh, head) if head[0x8001:0x8006] == b"CD001" else None
    except OSError:
        return None

    def info(fmt, table, firmware, role, why):
        return ImageInfo(name, fmt, table, firmware, role, size, why)

    if head[:4] == b"QFI\xfb":
        return info("qcow2", "-", "unknown", "boot", "qcow2 header (QFI\\xfb); the guest disk inside is not read")
    if head[:4] == b"KDMV" or head[:21] == b"# Disk DescriptorFile":
        return info("vmdk", "-", "unknown", "boot", "VMDK extent or descriptor; the guest disk inside is not read")
    if head[:8] == b"vhdxfile":
        return info("vhdx", "-", "unknown", "boot", "VHDX file identifier; the guest disk inside is not read")
    if head[0x40:0x44] == b"\x7f\x10\xda\xbe":
        return info("vdi", "-", "unknown", "boot", "VirtualBox VDI signature; the guest disk inside is not read")
    if head[:8] == b"conectix":
        return info("vpc", "-", "unknown", "boot", "dynamic VHD (conectix header); the guest disk inside is not read")
    if head[0x8001:0x8006] == b"CD001":
        if iso_uefi is None:
            return info("iso", "iso9660", "unknown", "data", "ISO 9660 volume with no El Torito boot catalog")
        return info("iso", "iso9660", "uefi" if iso_uefi else "bios", "boot",
                    "ISO 9660 with an El Torito boot catalog" + (" that has a UEFI entry" if iso_uefi else ""))
    boot_sig = head[510:512] == b"\x55\xaa"
    for at in (512, 4096):
        if head[at:at + 8] == b"EFI PART":
            esp = _gpt_has_esp(head, at)
            fw = "uefi" if esp or esp is None else "bios"
            what = {True: "with an EFI System Partition", False: "with no EFI System Partition",
                    None: "(partition entries not readable from the head)"}[esp]
            return info("raw", "gpt", fw, "boot", f"GPT header at offset {at} {what}")
    fs = _fs_boot_sector(head[:512]) if boot_sig else None
    if fs is not None:
        efi_dir = b"EFI        \x10" in head
        if efi_dir:
            return info("raw", "none", "uefi", "boot",
                        f"{fs.upper()} volume with no partition table and an EFI directory entry near its start")
        return info("raw", "none", "unknown", "data", f"{fs.upper()} volume with no partition table")
    if boot_sig:
        entries = [head[446 + 16 * i: 462 + 16 * i] for i in range(4)]
        sane = all(e[0] in (0x00, 0x80) for e in entries) and any(e[4] for e in entries)
        if sane:
            types = [e[4] for e in entries if e[4]]
            if 0xEF in types:
                return info("raw", "mbr", "uefi", "boot", "MBR with an EFI System partition (type 0xEF)")
            active = any(e[0] == 0x80 for e in entries)
            code = any(head[:440].strip(b"\x00"))
            role = "boot" if active or code else "data"
            return info("raw", "mbr", "bios" if role == "boot" else "unknown", role,
                        "MBR partition table (types " + ", ".join(f"0x{t:02X}" for t in types) + ")"
                        + ("" if role == "boot" else ", no boot code and no active partition"))
        return info("raw", "unknown", "bios", "boot", "boot signature 55AA with no readable partition table")
    if head[1080:1082] == b"\x53\xef":
        return info("raw", "none", "unknown", "data", "ext2/3/4 volume with no partition table")
    if tail[:8] == b"conectix":
        return info("vpc", "-", "unknown", "boot", "fixed VHD (conectix footer); the guest disk inside is not read")
    if name.lower().endswith(RAW_EXT):
        return info("raw", "unknown", "unknown", "data",
                    "named like a raw image; no partition table or filesystem signature recognised")
    return None


def find_images(challenge_dir: str | Path) -> list[ImageInfo]:
    """Every disk image under the challenge folder, bootable ones first, then by path. Paths under
    `.ctf`, `.git` and this harness's own output are never opened; symbolic links are not followed."""
    root = Path(challenge_dir)
    if not root.is_dir():
        raise BootError(f"{root}: not a challenge folder")
    out: list[ImageInfo] = []
    for f in sorted(root.rglob("*")):
        rel = f.relative_to(root)
        r = rel.as_posix()
        if SKIP_PARTS & set(rel.parts) or any(r == o or r.startswith(o + "/") for o in OWN_OUTPUT):
            continue
        if f.is_symlink() or not f.is_file():
            continue
        got = identify(f, r)
        if got is not None:
            out.append(got)
    out.sort(key=lambda i: (i.role != "boot", i.path))
    return out


# ---------------------------------------------------------------------------------------------- plan

@dataclass
class BootPlan:
    challenge_dir: str
    out_dir: str
    image: str                        # tools/images.toml name
    image_tag: str
    container: str
    firmware: str                     # uefi | bios
    images: list[dict]
    qemu_argv: list[str]
    start_argv: list[str]             # `docker run -d ...`: the operator's step (diskboot.start)
    qmp_argv: list[str]               # the QMP transport: `docker exec -i <container> socat ...`
    guest_out: str = GUEST_OUT
    script: list[dict] = field(default_factory=lambda: [dict(s) for s in DEFAULT_SCRIPT])
    notes: list[str] = field(default_factory=list)
    options: dict = field(default_factory=dict)  # plan()'s arguments: start() re-plans with them to check

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "BootPlan":
        try:
            return cls(**dict(d))
        except TypeError as e:
            raise BootError(f"not a boot plan: {e}") from None


_CONTAINER_RE = re.compile(r"^" + re.escape(CONTAINER_PREFIX) + r"[0-9a-f]{12}$")


def container_name(challenge_dir: str | Path) -> str:
    digest = hashlib.sha256(str(Path(challenge_dir).resolve()).encode("utf-8")).hexdigest()[:12]
    return f"{CONTAINER_PREFIX}{digest}"


def _toolchain_image(root: Path | None = None):
    from .toolchain import images
    try:
        found = [im for im in images.load(images.manifest_path(root)) if im.name == IMAGE_NAME]
    except images.ImagesError as e:
        raise BootError(f"the image manifest did not load: {e}") from e
    if not found:
        raise BootError(f"tools/images.toml has no image named {IMAGE_NAME!r}: the boot harness has no image to run")
    return found[0]


def plan(challenge_dir: str | Path, infos: Sequence[ImageInfo] | None = None, *, out_dir: str | Path | None = None,
         firmware: str = "auto", memory_mb: int = 2048, cpus: int = 2, machine: str = "q35",
         drive_if: str = "ide", script: Sequence[Mapping[str, Any]] | None = None,
         root: Path | None = None) -> BootPlan:
    """The command lines that would boot the challenge's disk images, networkless and read-only.
    Runs nothing and writes nothing. BootError when there is no image, or an option is unusable."""
    cdir = Path(challenge_dir).resolve()
    infos = list(find_images(cdir) if infos is None else infos)
    if not infos:
        raise BootError(f"{cdir}: no disk image found (GPT/MBR/boot-sector raw, qcow2, vmdk, vhdx, vdi, vhd, iso)")
    if firmware not in ("auto", "uefi", "bios"):
        raise BootError(f"firmware must be auto, uefi or bios, got {firmware!r}")
    if machine not in ("q35", "pc"):
        raise BootError(f"machine must be q35 or pc, got {machine!r}")
    if drive_if not in ("ide", "virtio", "scsi"):
        raise BootError(f"drive_if must be ide, virtio or scsi, got {drive_if!r}")
    for name, v, lo, hi in (("memory_mb", memory_mb, 64, 16384), ("cpus", cpus, 1, 8)):
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            raise BootError(f"{name} must be an integer from {lo} to {hi}, got {v!r}")
    steps = validate_script(DEFAULT_SCRIPT if script is None else script)
    requested_fw = firmware
    notes: list[str] = []
    if len(infos) > MAX_IMAGES:
        notes.append(f"{len(infos)} images found; only the first {MAX_IMAGES} are attached: "
                     + ", ".join(i.path for i in infos[MAX_IMAGES:]) + " left out")
        infos = infos[:MAX_IMAGES]
    for i in infos:
        if any(ch in i.path for ch in ",\n\r\x00") or i.path.startswith("/") or ".." in Path(i.path).parts:
            raise BootError(f"image path {i.path!r} cannot be passed to QEMU safely (a comma, a line break "
                            "or a path that leaves the folder): copy the image to a plain name first")
    if not any(i.role == "boot" for i in infos):
        notes.append(f"no image has a recognised boot structure; {infos[0].path} is tried as the boot disk")
    boot = infos[0]
    if firmware == "auto":
        firmware = boot.firmware if boot.firmware in ("uefi", "bios") else "uefi"
        if boot.firmware == "unknown":
            notes.append(f"{boot.path}: firmware not recognised from its structure; UEFI is tried first "
                         "(re-plan with firmware=bios when it does not come up)")
    out = Path(out_dir).resolve() if out_dir is not None else cdir / "recon" / "boot"
    image = _toolchain_image(root)
    name = container_name(cdir)

    qemu = ["qemu-system-x86_64", "-machine", f"{machine},accel=tcg", "-cpu", "max", "-m", str(memory_mb),
            "-smp", str(cpus), "-nodefaults", "-vga", "std", "-display", "none", "-nic", "none",
            "-snapshot", "-no-reboot", "-rtc", "base=utc"]
    if firmware == "uefi":
        qemu += ["-drive", f"if=pflash,format=raw,readonly=on,file={OVMF_CODE}",
                 "-drive", f"if=pflash,format=raw,file={OVMF_VARS}"]
    if drive_if == "scsi":
        qemu += ["-device", "virtio-scsi-pci,id=scsi0"]
    for n, i in enumerate(infos):
        guest = f"{GUEST_IMG}/{i.path}"
        if i.format == "iso":
            qemu += ["-drive", f"file={guest},format=raw,media=cdrom,readonly=on,if=ide,index={n}"]
        else:
            qemu += ["-drive", f"file={guest},format={i.format},media=disk,if={drive_if},index={n}"]
    qemu += ["-qmp", f"unix:{QMP_SOCKET},server=on,wait=off"]

    from .toolchain import images as _images
    base = _images.run_argv(image, [])              # the house flags: no network, never a pull, no capabilities
    start = base[:-1] + ["-d", "--name", name, "--read-only", "--tmpfs", "/run/boot:rw,nosuid,nodev,mode=1777",
                         "--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777",
                         "--memory", f"{memory_mb + 1024}m", "--cpus", str(cpus), "--pids-limit", "256",
                         "-e", f"TMPDIR={GUEST_OUT}/.snapshot",
                         "-v", f"{cdir}:{GUEST_IMG}:ro", "-v", f"{out}:{GUEST_OUT}"] + [base[-1]] + qemu
    notes.append("booting runs challenge code: `start` is the operator's step (python -m ctf disk-boot start)")
    notes.append("the guest has no network (docker --network none, qemu -nic none); replay a shipped "
                 "client's requests with python -m ctf client-replay instead")
    options = {"firmware": requested_fw, "memory_mb": memory_mb, "cpus": cpus, "machine": machine,
               "drive_if": drive_if}
    return BootPlan(challenge_dir=str(cdir), out_dir=str(out), image=image.name, image_tag=image.tag,
                    container=name, firmware=firmware, images=[asdict(i) for i in infos], qemu_argv=qemu,
                    start_argv=start, qmp_argv=_qmp_argv(name), script=steps, notes=notes, options=options)


def _qmp_argv(container: str) -> list[str]:
    """The one QMP transport this harness runs: socat inside the boot container, over `docker exec`."""
    return ["docker", "exec", "-i", container, "socat", "-", f"UNIX-CONNECT:{QMP_SOCKET}"]


# ------------------------------------------------------------------------------------- operator gate

@dataclass(frozen=True)
class Approval:
    """A person's go-ahead to boot one challenge's images with one exact `docker run` command.
    Issued by approve_interactive() only: it carries a seal over its fields that start() checks, so
    an Approval built by hand, or copied with a field changed (dataclasses.replace), is refused. This
    keeps callers honest; it is not a security boundary against code in the same process."""
    challenge_dir: str
    by: str
    reason: str
    argv: tuple = ()
    _seal: str = field(default="", init=False, repr=False, compare=False)


_SEAL_KEY = os.urandom(32)                     # per process: an approval never outlives its process


def _seal_of(a: Approval) -> str:
    body = json.dumps([a.challenge_dir, a.by, a.reason, list(a.argv)], separators=(",", ":"))
    return hmac.new(_SEAL_KEY, body.encode("utf-8"), hashlib.sha256).hexdigest()


def _sealed(a: Any) -> bool:
    return isinstance(a, Approval) and bool(a._seal) and hmac.compare_digest(a._seal, _seal_of(a))


def approve_interactive(plan_: BootPlan, reason: str, *, stdin=None, stdout=None,
                        prompt: Callable[[str], str] = input) -> Approval:
    """Show the person at the terminal the exact `docker run` command of the plan and ask them to
    confirm the boot by typing the challenge folder's name. PermissionError when there is no
    interactive terminal (an agent, a pipe, a script) or the typed name does not match; nothing
    stands in for the person. The Approval is sealed to that command."""
    import sys
    if not isinstance(plan_, BootPlan):
        raise PermissionError("an approval is given for a boot plan (diskboot.plan()), so that the person "
                              "sees the command they approve")
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    cdir = Path(plan_.challenge_dir).resolve()
    if not reason or not reason.strip():
        raise PermissionError("a boot needs a reason (why this image is booted; it goes into the ledger)")
    if stdin is None or not stdin.isatty() or not stdout.isatty():
        raise PermissionError("booting a challenge disk image runs challenge code: `ctf disk-boot start` is the "
                              "operator's decision. Run it yourself in an interactive terminal "
                              "(no flag bypasses this)")
    command = shlex.join(plan_.start_argv)
    typed = prompt(f"Booting runs the challenge's code in a networkless container. This exact command "
                   f"will run:\n\n  {command}\n\nRead it, then type the challenge folder name ({cdir.name}) "
                   f"to boot it: ").strip()
    if typed != cdir.name:
        raise PermissionError(f"confirmation did not match {cdir.name!r}; nothing was started")
    approval = Approval(str(cdir), getpass.getuser() or "human", reason.strip(), tuple(plan_.start_argv))
    object.__setattr__(approval, "_seal", _seal_of(approval))
    return approval


PLAN_OPTIONS = frozenset({"firmware", "memory_mb", "cpus", "machine", "drive_if"})


def check_plan(plan_: BootPlan, root: Path | None) -> None:
    """BootError unless `plan_` is exactly what plan() writes for its folder and options now: an
    edited plan.json (a mount, a privilege, a network, a QEMU option added or dropped) is refused."""
    opts = plan_.options if isinstance(plan_.options, dict) else {}
    unknown = set(opts) - PLAN_OPTIONS
    if not opts or unknown:
        raise BootError("the plan does not record the options it was made with"
                        + (f" (unknown: {', '.join(sorted(unknown))})" if unknown else "")
                        + ": re-plan with `python -m ctf disk-boot plan`")
    try:
        fresh = plan(plan_.challenge_dir, out_dir=plan_.out_dir, script=plan_.script, root=root, **opts)
    except (BootError, TypeError) as e:
        raise BootError(f"the plan cannot be made again from its folder ({e}): re-plan with "
                        "`python -m ctf disk-boot plan`") from e
    mine, theirs = fresh.to_dict(), plan_.to_dict()
    differ = [k for k in mine if mine[k] != theirs.get(k)]
    if differ:
        raise BootError("the plan differs from what this harness writes for this folder ("
                        + ", ".join(differ) + "): it was edited, or the folder changed since. Nothing was "
                        "started; re-plan with `python -m ctf disk-boot plan`")


def start(plan_: BootPlan, approval: Approval, *, profile: EventProfile | None = None,
          environ: Mapping[str, str] | None = None, run: Callable[..., Any] = subprocess.run,
          clock: Callable[[], float] = time.time, root: Path | None = None) -> dict:
    """Boot the plan's images in the QEMU container (the operator's step). Checks the approval is a
    sealed one for this challenge and this exact command, that the plan is what plan() writes for
    the folder now, that the image is built here (never builds or pulls), and that no session is
    already recorded; then runs the plan's `docker run -d`, records the session in the out folder
    and, with a profile, a `diskboot.start` ledger record with the run's outcome (started, failed,
    or unknown when docker did not return). BootError names whatever is missing."""
    from .toolchain import images
    if not _sealed(approval):
        raise BootError("start() needs an Approval from approve_interactive(): the operator boots, not the caller")
    if Path(approval.challenge_dir).resolve() != Path(plan_.challenge_dir).resolve():
        raise BootError(f"the approval is for {approval.challenge_dir}, not {plan_.challenge_dir}")
    e = dict(os.environ if environ is None else environ)
    out = Path(plan_.out_dir)
    session_path = out / SESSION_FILE
    if session_path.exists():
        raise BootError(f"{session_path} exists: a boot of this challenge was already started "
                        f"(container {plan_.container}); end it with `python -m ctf disk-boot quit` first")
    image = _toolchain_image(root)
    if image.tag != plan_.image_tag or plan_.start_argv[:2] != ["docker", "run"] \
            or plan_.start_argv.count(image.tag) != 1 or "none" != _after(plan_.start_argv, "--network"):
        raise BootError("the plan's start command is not this harness's networkless `docker run` of "
                        f"{image.tag}: re-plan with `python -m ctf disk-boot plan`")
    check_plan(plan_, root)
    if tuple(plan_.start_argv) != tuple(approval.argv):
        raise BootError("the approval was given for a different command than this plan's; nothing was "
                        "started: approve the plan that is to run")
    try:
        docker = images.docker_path(e)
        if docker is None:
            raise BootError("docker is not on PATH: the boot harness runs QEMU in the "
                            f"{image.tag} container (install Docker Desktop)")
        st = images.status([image], root=root, environ=e, run=run)[0]
    except images.ImagesError as ex:
        raise BootError(str(ex)) from ex
    if st.state != "ok":
        raise BootError(f"image {image.tag} is {st.state} ({st.detail}); a human builds it: {st.fix}")
    (out / ".snapshot").mkdir(parents=True, exist_ok=True)
    failure, outcome = "", "started"
    try:
        p = run([docker, *plan_.start_argv[1:]], capture_output=True, text=True, env=e, timeout=120,
                stdin=subprocess.DEVNULL)
        if p.returncode != 0:
            outcome = "failed"
            failure = f"docker run exited {p.returncode}: {((p.stdout or '') + (p.stderr or '')).strip()[:400]}"
    except subprocess.TimeoutExpired as ex:
        outcome = "unknown"                    # a `docker run -d` that did not return may have created it
        failure = (f"docker run did not return ({ex}); container {plan_.container} may exist: the operator "
                   "checks for it by that exact name")
    except OSError as ex:
        outcome = "failed"
        failure = f"docker run did not start the boot container: {type(ex).__name__}: {ex}"
    if profile is not None:
        rec: dict[str, Any] = {"challenge_dir": Path(plan_.challenge_dir).name, "container": plan_.container,
                               "image": image.tag, "approved_by": approval.by, "reason": approval.reason,
                               "outcome": outcome}
        if failure:
            rec["detail"] = failure
        ledger.append(START_EVENT, workdir=paths.workdir(profile.slug), event_slug=profile.slug, **rec)
    if failure:
        raise BootError(failure)
    session = {"container": plan_.container, "image": image.tag, "started": clock(),
               "approved_by": approval.by, "reason": approval.reason, "qmp_argv": list(plan_.qmp_argv),
               "guest_out": plan_.guest_out}
    session_path.write_text(json.dumps(session, indent=2) + "\n", encoding="utf-8")
    return session


def _after(argv: Sequence[str], flag: str) -> str | None:
    for i, a in enumerate(argv[:-1]):
        if a == flag:
            return argv[i + 1]
    return None


def _check_qmp_argv(argv: Any, container: Any = None, where: str = "the session record") -> list[str]:
    """The session's QMP transport, only if it is the one plan() writes (`docker exec -i
    <ctf-boot-...> socat - UNIX-CONNECT:<socket>`), for `container` when that is given. The record is
    a file anyone can edit, and its argv is run: any other command is refused, never run."""
    if not (isinstance(argv, list) and len(argv) == 7 and all(isinstance(x, str) for x in argv)
            and _CONTAINER_RE.match(argv[3]) and argv == _qmp_argv(argv[3])):
        raise BootError(f"{where}: its qmp_argv is not this harness's `docker exec -i {CONTAINER_PREFIX}... "
                        f"socat` transport, so it is not run: {argv!r}")
    if container is not None and argv[3] != container:
        raise BootError(f"{where}: its qmp_argv names container {argv[3]!r}, not {container!r}; it is not run")
    return list(argv)


def load_session(out_dir: str | Path, challenge_dir: str | Path | None = None) -> dict:
    """The session `start()` recorded in the out folder. BootError when there is none: nothing was
    booted by the operator, so there is nothing to drive; or when its QMP transport is not the one
    this harness writes (for `challenge_dir`'s container, when given)."""
    p = Path(out_dir) / SESSION_FILE
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise BootError(f"no boot session in {Path(out_dir)}: the operator starts the boot first "
                        "(`python -m ctf disk-boot start <challenge_dir> --reason ...`), or pass --qmp for a "
                        "QEMU started by hand") from None
    except (OSError, ValueError) as e:
        raise BootError(f"{p}: unreadable session record ({type(e).__name__}: {e})") from e
    argv = data.get("qmp_argv") if isinstance(data, dict) else None
    if not (isinstance(argv, list) and argv and all(isinstance(a, str) for a in argv)):
        raise BootError(f"{p}: the session record has no qmp_argv")
    _check_qmp_argv(argv, data.get("container"), where=str(p))
    if challenge_dir is not None:
        _check_qmp_argv(argv, container_name(challenge_dir), where=str(p))
    return data


def connect_session(session: Mapping[str, Any], *, environ: Mapping[str, str] | None = None,
                    timeout: float = QMP_TIMEOUT) -> "QMP":
    """The QMP client of a recorded session, over its transport command, which must be the `docker
    exec ... socat` one plan() writes (anything else is refused, never run). The docker on PATH runs
    through the toolchain's guard (under CTF_TESTING only a stub docker runs)."""
    from .toolchain import images
    argv = _check_qmp_argv(session.get("qmp_argv"), session.get("container"))
    e = dict(os.environ if environ is None else environ)
    try:
        docker = images.docker_path(e)
    except images.ImagesError as ex:
        raise BootError(str(ex)) from ex
    if docker is None:
        raise BootError("docker is not on PATH: the session's QMP transport is `docker exec`")
    argv[0] = docker
    return QMP.connect_command(argv, timeout=timeout, environ=e)


def end_session(out_dir: str | Path, *, environ: Mapping[str, str] | None = None,
                timeout: float = QMP_TIMEOUT, challenge_dir: str | Path | None = None) -> dict:
    """Ask the session's QEMU to exit over QMP (its container, started with --rm, goes with it) and
    retire the session record (renamed to session-ended.json). No docker stop, kill or rm is run: a
    VM that no longer answers QMP is the operator's to remove, by its exact name."""
    out = Path(out_dir)
    session = load_session(out, challenge_dir)
    try:
        with connect_session(session, environ=environ, timeout=timeout) as qmp:
            qmp.quit()
    except QMPError as e:
        raise BootError(f"the VM did not take `quit` over QMP ({e}); it was NOT stopped. If container "
                        f"{session.get('container')} is still running, the operator removes it by that exact "
                        f"name; then delete {out / SESSION_FILE}") from e
    os.replace(out / SESSION_FILE, out / "session-ended.json")
    return session


# ----------------------------------------------------------------------------------------------- QMP

class QMP:
    """A QEMU Machine Protocol client over two file descriptors (one socket, or a command's pipes)."""

    def __init__(self, rfd: int, wfd: int, *, timeout: float = QMP_TIMEOUT, closer: Callable[[], None] | None = None,
                 where: str = "qmp"):
        self._rfd, self._wfd = rfd, wfd
        self.timeout = float(timeout)
        self._closer = closer
        self._buf = b""
        self.where = where
        self.events: list[dict] = []
        self.greeting: dict | None = None
        self._id = 0

    # -- transports
    @classmethod
    def connect_unix(cls, path: str | Path, *, timeout: float = QMP_TIMEOUT) -> "QMP":
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.settimeout(timeout)
            s.connect(str(path))
            s.settimeout(None)
        except OSError as e:
            s.close()
            raise QMPError(f"cannot connect to the QMP socket {path}: {e}") from e
        return cls(s.fileno(), s.fileno(), timeout=timeout, closer=s.close, where=f"unix:{path}")._open(s)

    @classmethod
    def connect_tcp(cls, host: str, port: int, *, timeout: float = QMP_TIMEOUT) -> "QMP":
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise QMPError(f"QMP over TCP is loopback only (127.0.0.1, ::1, localhost), not {host!r}: a QMP port "
                           "is full control of the VM")
        try:
            s = socket.create_connection((host, int(port)), timeout=timeout)
            s.settimeout(None)
        except (OSError, ValueError) as e:
            raise QMPError(f"cannot connect to QMP at {host}:{port}: {e}") from e
        return cls(s.fileno(), s.fileno(), timeout=timeout, closer=s.close, where=f"tcp:{host}:{port}")._open(s)

    @classmethod
    def connect_command(cls, argv: Sequence[str], *, timeout: float = QMP_TIMEOUT,
                        environ: Mapping[str, str] | None = None) -> "QMP":
        """QMP over the stdin/stdout of a command (the plan's `docker exec -i ... socat`)."""
        if not argv:
            raise QMPError("no QMP transport command")
        try:
            proc = subprocess.Popen(list(argv), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, env=None if environ is None else dict(environ))
        except OSError as e:
            raise QMPError(f"cannot start the QMP transport {argv[0]!r}: {e}") from e

        def closer():
            for fh in (proc.stdin, proc.stdout):
                try:
                    fh.close()
                except OSError:
                    pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

        return cls(proc.stdout.fileno(), proc.stdin.fileno(), timeout=timeout, closer=closer,
                   where="command " + " ".join(argv[:3]))._open(proc)

    @classmethod
    def connect(cls, spec: str | Sequence[str], *, timeout: float = QMP_TIMEOUT,
                environ: Mapping[str, str] | None = None) -> "QMP":
        """`unix:PATH`, `tcp:HOST:PORT` (loopback only), or an argv list for a command transport."""
        if not isinstance(spec, str):
            return cls.connect_command(list(spec), timeout=timeout, environ=environ)
        if spec.startswith("unix:") and len(spec) > 5:
            return cls.connect_unix(spec[5:], timeout=timeout)
        if spec.startswith("tcp:"):
            host, sep, port = spec[4:].rpartition(":")
            if not sep or not port.isdigit():
                raise QMPError(f"{spec!r}: write tcp:127.0.0.1:PORT")
            return cls.connect_tcp(host.strip("[]"), int(port), timeout=timeout)
        raise QMPError(f"{spec!r} is not a QMP address: write unix:PATH or tcp:127.0.0.1:PORT")

    def _open(self, obj: Any) -> "QMP":
        self._held = obj                 # keeps the socket / process alive as long as the client
        try:
            return self.handshake()
        except BaseException:
            self.close()
            raise

    def __enter__(self) -> "QMP":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        closer, self._closer = self._closer, None
        if closer is not None:
            closer()

    # -- wire
    def _read_message(self, what: str) -> dict:
        deadline = time.monotonic() + self.timeout      # real time on purpose: a hung QEMU must not hang us
        while b"\n" not in self._buf:
            left = deadline - time.monotonic()
            if left <= 0:
                raise QMPError(f"{self.where}: no reply to {what} within {self.timeout:g} s")
            ready, _, _ = select.select([self._rfd], [], [], left)
            if not ready:
                continue
            try:
                chunk = os.read(self._rfd, 65536)
            except OSError as e:
                raise QMPError(f"{self.where}: read failed while waiting for {what}: {e}") from e
            if not chunk:
                raise QMPError(f"{self.where}: the connection closed while waiting for {what}")
            self._buf += chunk
            if len(self._buf) > 16 * 1024 * 1024:
                raise QMPError(f"{self.where}: a reply to {what} exceeds 16 MiB")
        line, _, self._buf = self._buf.partition(b"\n")
        try:
            msg = json.loads(line)
        except ValueError:
            raise QMPError(f"{self.where}: not a QMP message while waiting for {what}: {line[:120]!r}") from None
        if not isinstance(msg, dict):
            raise QMPError(f"{self.where}: not a QMP message while waiting for {what}: {line[:120]!r}")
        return msg

    def _write(self, obj: dict) -> None:
        data = json.dumps(obj, separators=(",", ":")).encode("utf-8") + b"\n"
        try:
            while data:
                n = os.write(self._wfd, data)
                data = data[n:]
        except OSError as e:
            raise QMPError(f"{self.where}: write failed: {e}") from e

    def handshake(self) -> "QMP":
        msg = self._read_message("the QMP greeting")
        if "QMP" not in msg:
            raise QMPError(f"{self.where}: expected the QMP greeting, got {json.dumps(msg)[:160]}")
        self.greeting = msg["QMP"]
        self.execute("qmp_capabilities")
        return self

    def execute(self, command: str, **arguments: Any) -> Any:
        """Run one QMP command and return its `return` value. Events that arrive meanwhile are kept
        in `.events`. QMPError carries QEMU's error class and description."""
        self._id += 1
        msg: dict[str, Any] = {"execute": command, "id": self._id}
        if arguments:
            msg["arguments"] = arguments
        self._write(msg)
        while True:
            reply = self._read_message(command)
            if "event" in reply:
                self.events.append(reply)
                continue
            if reply.get("id") not in (None, self._id):
                continue                                    # a late reply to an earlier command
            if "error" in reply:
                err = reply["error"] if isinstance(reply["error"], dict) else {}
                raise QMPError(f"{command}: {err.get('desc', reply['error'])}", cls=str(err.get("class", "")))
            if "return" in reply:
                return reply["return"]
            raise QMPError(f"{self.where}: unexpected reply to {command}: {json.dumps(reply)[:160]}")

    # -- commands
    def status(self) -> dict:
        return self.execute("query-status")

    def screendump(self, guest_path: str) -> None:
        self.execute("screendump", filename=guest_path)

    def send_key(self, chord: str, hold_ms: int | None = None) -> None:
        keys = [{"type": "qcode", "data": k} for k in parse_chord(chord)]
        if hold_ms is None:
            self.execute("send-key", keys=keys)
        else:
            self.execute("send-key", **{"keys": keys, "hold-time": int(hold_ms)})

    def type_text(self, text: str) -> None:
        for chord in text_chords(text):
            self.send_key(chord)

    def mouse_rel(self, dx: int, dy: int) -> None:
        self.execute("input-send-event", events=[
            {"type": "rel", "data": {"axis": "x", "value": int(dx)}},
            {"type": "rel", "data": {"axis": "y", "value": int(dy)}}])

    def click(self, button: str = "left") -> None:
        if button not in BUTTONS:
            raise BootError(f"unknown mouse button {button!r} (one of {', '.join(BUTTONS)})")
        for down in (True, False):
            self.execute("input-send-event", events=[{"type": "btn", "data": {"down": down, "button": button}}])

    def quit(self) -> None:
        """Ask QEMU to exit (the container, started with --rm, goes with it)."""
        self.execute("quit")


def parse_chord(chord: str) -> list[str]:
    """`ctrl-alt-f2` -> ["ctrl", "alt", "f2"]. BootError names a key that is not a known qcode."""
    keys = [k for k in str(chord).strip().lower().split("-")]
    if not keys or any(not k for k in keys):
        raise BootError(f"empty key in chord {chord!r} (join qcodes with '-': ctrl-alt-f2; the minus key is 'minus')")
    bad = [k for k in keys if k not in QCODES]
    if bad:
        raise BootError(f"unknown key(s) {', '.join(bad)} in chord {chord!r} (QEMU qcodes, e.g. ret, spc, esc, "
                        "meta_l, f1, kp_enter)")
    return keys


def text_chords(text: str) -> list[str]:
    """The key chords that type `text` on a US layout. BootError names the first character that
    layout cannot type (send such a key with a `key` step, by qcode)."""
    out = []
    for ch in text:
        if ch.isascii() and (ch.islower() or ch.isdigit()):
            out.append(ch)
        elif ch.isascii() and ch.isupper():
            out.append(f"shift-{ch.lower()}")
        elif ch in _PLAIN:
            out.append(_PLAIN[ch])
        elif ch in _SHIFTED:
            out.append(f"shift-{_SHIFTED[ch]}")
        else:
            raise BootError(f"cannot type {ch!r} on a US layout: send it as a `key` step by qcode")
    return out


# -------------------------------------------------------------------------------------------- frames

@dataclass(frozen=True)
class Frame:
    width: int
    height: int
    pixels: bytes              # RGB, 3 bytes a pixel, rows top to bottom

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.pixels).hexdigest()


def read_ppm(data: bytes) -> Frame:
    """A binary PPM (P6, 8 bits a channel) as QEMU's screendump writes it. BootError otherwise."""
    m = re.match(rb"P6(?:\s+|#[^\n]*\n)+(\d{1,5})(?:\s+|#[^\n]*\n)+(\d{1,5})(?:\s+|#[^\n]*\n)+(\d{1,5})\s", data)
    if not m:
        raise BootError("not a binary PPM (P6) screenshot")
    w, h, maxval = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if maxval != 255 or w < 1 or h < 1 or w * h * 3 > MAX_FRAME_BYTES:
        raise BootError(f"unsupported PPM screenshot ({w}x{h}, maxval {maxval})")
    pixels = data[m.end(): m.end() + w * h * 3]
    if len(pixels) != w * h * 3:
        raise BootError(f"truncated PPM screenshot: {len(pixels)} of {w * h * 3} pixel bytes")
    return Frame(w, h, pixels)


def write_png(frame: Frame) -> bytes:
    """The frame as an RGB PNG (stdlib only)."""
    stride = frame.width * 3
    raw = b"".join(b"\x00" + frame.pixels[y * stride:(y + 1) * stride] for y in range(frame.height))

    def chunk(kind: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", frame.width, frame.height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))


def changed_box(a: Frame, b: Frame) -> tuple[int, int, int, int] | None:
    """(x0, y0, x1, y1), half-open, around every pixel that differs between two frames; None when
    they are identical; the whole screen when their sizes differ."""
    if (a.width, a.height) != (b.width, b.height):
        return (0, 0, b.width, b.height)
    if a.pixels == b.pixels:
        return None
    stride = a.width * 3
    x0, x1, y0, y1 = a.width, -1, -1, -1
    for y in range(a.height):
        ra, rb = a.pixels[y * stride:(y + 1) * stride], b.pixels[y * stride:(y + 1) * stride]
        if ra == rb:
            continue
        if y0 < 0:
            y0 = y
        y1 = y
        x = int.from_bytes(ra, "big") ^ int.from_bytes(rb, "big")
        first = (stride * 8 - x.bit_length()) // 24
        last = (stride * 8 - (x & -x).bit_length()) // 24
        x0, x1 = min(x0, first), max(x1, last)
    return (x0, y0, x1 + 1, y1 + 1)


def crop(frame: Frame, box: tuple[int, int, int, int]) -> Frame:
    x0, y0, x1, y1 = box
    x0, y0, x1, y1 = max(0, x0), max(0, y0), min(frame.width, x1), min(frame.height, y1)
    if x1 <= x0 or y1 <= y0:
        raise BootError(f"empty crop box {box} of a {frame.width}x{frame.height} frame")
    stride = frame.width * 3
    rows = [frame.pixels[y * stride + x0 * 3: y * stride + x1 * 3] for y in range(y0, y1)]
    return Frame(x1 - x0, y1 - y0, b"".join(rows))


# ------------------------------------------------------------------------------------------- observe

def validate_script(script: Sequence[Mapping[str, Any]]) -> list[dict]:
    """The script as a list of checked steps. BootError names the first bad step and why; nothing is
    sent to a VM before the whole script passes."""
    if isinstance(script, (str, bytes, Mapping)) or not isinstance(script, Sequence):
        raise BootError("an observe script is a JSON list of steps")
    if len(script) > MAX_STEPS:
        raise BootError(f"an observe script has at most {MAX_STEPS} steps, got {len(script)}")
    out: list[dict] = []
    waited = 0.0

    def num(v, what, lo, hi):
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:
            raise BootError(f"step {n}: {what} must be a number from {lo:g} to {hi:g}, got {v!r}")
        return v

    def pair(v, what, lo, hi):
        if not (isinstance(v, (list, tuple)) and len(v) == 2):
            raise BootError(f"step {n}: {what} takes [x, y], got {v!r}")
        return [int(num(v[0], what, lo, hi)), int(num(v[1], what, lo, hi))]

    for n, step in enumerate(script):
        if not isinstance(step, Mapping) or len(step) != 1:
            raise BootError(f"step {n}: a step is an object with exactly one action, got {step!r}")
        (action, arg), = step.items()
        if action == "wait":
            waited += num(arg, "wait", 0, MAX_WAIT_TOTAL)
        elif action == "shot":
            if not isinstance(arg, str) or not _NAME.match(arg):
                raise BootError(f"step {n}: a shot name is 1-41 of [A-Za-z0-9_.-], got {arg!r}")
        elif action == "burst":
            if not isinstance(arg, Mapping) or set(arg) - {"name", "count", "interval"} or "count" not in arg:
                raise BootError(f"step {n}: burst takes {{name, count, interval}}, got {arg!r}")
            name = arg.get("name", "burst")
            if not isinstance(name, str) or not _NAME.match(name):
                raise BootError(f"step {n}: a burst name is 1-41 of [A-Za-z0-9_.-], got {name!r}")
            count = num(arg["count"], "burst count", 1, MAX_BURST)
            if count != int(count):
                raise BootError(f"step {n}: burst count must be a whole number, got {count!r}")
            interval = num(arg.get("interval", 1.0), "burst interval", 0, 600)
            waited += interval * (int(count) - 1)
            arg = {"name": name, "count": int(count), "interval": float(interval)}
        elif action == "key":
            if not isinstance(arg, str):
                raise BootError(f"step {n}: key takes a chord string such as 'ctrl-alt-f2', got {arg!r}")
            try:
                parse_chord(arg)
            except BootError as e:
                raise BootError(f"step {n}: {e}") from None
        elif action == "type":
            if not isinstance(arg, str) or not arg:
                raise BootError(f"step {n}: type takes a non-empty string, got {arg!r}")
            try:
                text_chords(arg)
            except BootError as e:
                raise BootError(f"step {n}: {e}") from None
        elif action == "mouse":
            arg = pair(arg, "mouse", 0, 16383)
        elif action == "mouse_rel":
            arg = pair(arg, "mouse_rel", -16383, 16383)
        elif action == "click":
            if arg not in BUTTONS:
                raise BootError(f"step {n}: click takes one of {', '.join(BUTTONS)}, got {arg!r}")
        else:
            raise BootError(f"step {n}: unknown action {action!r} (wait, shot, burst, key, type, mouse, "
                            "mouse_rel, click)")
        if waited > MAX_WAIT_TOTAL:
            raise BootError(f"step {n}: the script waits more than {MAX_WAIT_TOTAL:g} s in all")
        out.append({action: arg})
    return out


@dataclass
class Shot:
    file: str                  # relative to the out folder
    name: str
    step: int
    width: int
    height: int
    sha256: str                # of the pixels


@dataclass
class Observation:
    out_dir: str
    shots: list[Shot] = field(default_factory=list)
    duplicates_dropped: int = 0
    animated: list[dict] = field(default_factory=list)    # per burst that changed: {step, name, box, cropped}
    crops: list[str] = field(default_factory=list)
    handoff: str = ""                                      # the vision hand-off file
    events: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


VISION_ASK = ("Read every piece of text and every glyph drawn on these screens, in order. A flag or a part "
              "of one may be drawn (a wallpaper, a banner, one character at a time across frames). Report "
              "what is drawn literally, character by character; where a character is unclear, say so. Do "
              "not complete or correct a partial flag: a missing part is found, not guessed.")


def observe(qmp: QMP, script: Sequence[Mapping[str, Any]], out_dir: str | Path, *, guest_out: str | None = None,
            sleep: Callable[[float], None] = time.sleep, flag_prefixes: Sequence[str] = ()) -> Observation:
    """Run the script against a booted VM: wait, press keys, move the mouse, take screenshots.
    `out_dir` is where this process reads the screenshots; `guest_out` is the same folder as QEMU
    names it (the container's /out; default: out_dir itself, for a QEMU on this host). Writes
    shots/*.png, crops/*.png and vision-handoff.json into out_dir and returns what it wrote."""
    steps = validate_script(script)
    out = Path(out_dir)
    shots_dir = out / "shots"
    shots_dir.mkdir(parents=True, exist_ok=True)
    guest = str(out) if guest_out is None else guest_out.rstrip("/")
    obs = Observation(out_dir=str(out))
    frames: list[tuple[Shot, Frame]] = []
    seq = [len(list(shots_dir.glob("*.png")))]

    def shot(name: str, step_no: int, dedupe: bool) -> None:
        seq[0] += 1
        stem = f"{seq[0]:04d}-{name}"
        raw = f"{stem}.ppm"
        qmp.screendump(f"{guest}/shots/{raw}")
        host = shots_dir / raw
        try:
            data = host.read_bytes()
        except OSError as e:
            raise BootError(f"QEMU reported the screenshot written but {host} is not readable ({e}): is "
                            f"{out} the folder the VM sees as {guest}?") from e
        frame = read_ppm(data)
        host.unlink()
        if dedupe and frames and frames[-1][1].pixels == frame.pixels:
            obs.duplicates_dropped += 1
            seq[0] -= 1
            return
        (shots_dir / f"{stem}.png").write_bytes(write_png(frame))
        s = Shot(f"shots/{stem}.png", name, step_no, frame.width, frame.height, frame.sha256)
        obs.shots.append(s)
        frames.append((s, frame))

    for n, step in enumerate(steps):
        (action, arg), = step.items()
        if action == "wait":
            sleep(float(arg))
        elif action == "shot":
            shot(arg, n, dedupe=False)
        elif action == "burst":
            for i in range(arg["count"]):
                if i and arg["interval"] > 0:
                    sleep(arg["interval"])
                shot(arg["name"], n, dedupe=True)
        elif action == "key":
            qmp.send_key(arg)
        elif action == "type":
            qmp.type_text(arg)
        elif action == "mouse":
            qmp.mouse_rel(-16383, -16383)
            qmp.mouse_rel(arg[0], arg[1])
        elif action == "mouse_rel":
            qmp.mouse_rel(arg[0], arg[1])
        elif action == "click":
            qmp.click(arg)

    # The region that changes inside each burst (an animation), cropped out of its distinct frames.
    for n, step in enumerate(steps):
        if "burst" not in step:
            continue
        run = [(s, f) for s, f in frames if s.step == n]
        box = None
        for (_, a), (_, b) in zip(run, run[1:]):
            got = changed_box(a, b)
            if got is None or (a.width, a.height) != (b.width, b.height):
                continue
            box = got if box is None else (min(box[0], got[0]), min(box[1], got[1]),
                                           max(box[2], got[2]), max(box[3], got[3]))
        if box is None:
            continue
        w, h = run[-1][1].width, run[-1][1].height
        small = (box[2] - box[0]) * (box[3] - box[1]) <= CROP_MAX_SHARE * w * h
        obs.animated.append({"step": n, "name": step["burst"]["name"], "box": list(box), "cropped": small})
        if not small:
            continue
        padded = (box[0] - CROP_PAD, box[1] - CROP_PAD, box[2] + CROP_PAD, box[3] + CROP_PAD)
        (out / "crops").mkdir(parents=True, exist_ok=True)
        seen: set[str] = set()
        for s, f in run:
            if (f.width, f.height) != (w, h):
                continue
            c = crop(f, padded)
            if c.sha256 in seen:
                continue
            seen.add(c.sha256)
            rel = f"crops/{Path(s.file).stem}.png"
            (out / rel).write_bytes(write_png(c))
            obs.crops.append(rel)
    obs.events = list(qmp.events)
    handoff = {"needs": "vision", "ask": VISION_ASK, "flag_prefixes": list(flag_prefixes),
               "shots": [asdict(s) for s in obs.shots], "duplicates_dropped": obs.duplicates_dropped,
               "animated": list(obs.animated), "crops": list(obs.crops)}
    (out / HANDOFF_FILE).write_text(json.dumps(handoff, indent=2) + "\n", encoding="utf-8")
    obs.handoff = HANDOFF_FILE
    return obs


__all__ = ["Approval", "BootError", "BootPlan", "Frame", "ImageInfo", "Observation", "QMP", "QMPError",
           "Shot", "approve_interactive", "changed_box", "connect_session", "container_name", "crop",
           "check_plan", "end_session", "find_images", "identify", "load_session", "observe", "parse_chord", "plan",
           "read_ppm", "start", "text_chords", "validate_script", "write_png"]
