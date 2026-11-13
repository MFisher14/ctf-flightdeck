"""An event's VPN: the file the organizers hand out, connected on this machine.

Many events put their live targets behind a VPN and give each team a WireGuard (.conf) or
OpenVPN (.ovpn) file. flightdeck keeps a copy of it in the event's folder (vpn.conf or
vpn.ovpn, readable by its owner only: it holds a private key and is never shown or logged),
connects it with the tool the file is for, and says whether it looks connected.

    WireGuard   sudo wg-quick up FILE            (wireguard-tools)
    OpenVPN     sudo openvpn --config FILE --daemon --writepid FOLDER/vpn.pid --log FOLDER/vpn.log

Both need root, so the command is shown and run through sudo in the player's terminal, which
asks for their password itself; flightdeck never sees it. The VPN is this machine's: lanes on
the host runtime use it as any program does, and Docker Desktop sends a container's traffic
out through this machine's routes, the VPN's among them.

Nothing here reads the file beyond the address line of a WireGuard [Interface] (to tell
whether it is up); nothing prints any of it.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

KINDS = {".conf": "wireguard", ".ovpn": "openvpn"}
NAMES = ("vpn.conf", "vpn.ovpn")
PID_FILE, LOG_FILE = "vpn.pid", "vpn.log"
MAX_BYTES = 256 * 1024
_ADDRESS = re.compile(r"^\s*Address\s*=\s*(.+)$", re.IGNORECASE | re.MULTILINE)


class VPNError(Exception):
    """The VPN file cannot be used, or its tool is missing; the message says what to do."""


@dataclass(frozen=True)
class VPN:
    file: Path
    kind: str  # "wireguard" | "openvpn"

    @property
    def folder(self) -> Path:
        return self.file.parent

    @property
    def tool(self) -> str:
        return "wg-quick" if self.kind == "wireguard" else "openvpn"


def kind_of(path: Path) -> str:
    kind = KINDS.get(path.suffix.lower())
    if kind is None:
        raise VPNError(f"{path.name}: a VPN file is a WireGuard .conf or an OpenVPN .ovpn (the event's site says which it gives)")
    return kind


def find(folder: Path) -> VPN | None:
    """The VPN file kept in an event's folder, or None."""
    for name in NAMES:
        path = folder / name
        if path.is_file():
            return VPN(path, kind_of(path))
    return None


def named(target: Path) -> VPN:
    """`target` as a VPN: an event's folder that keeps one, or a VPN file itself."""
    if target.is_dir():
        vpn = find(target)
        if vpn is None:
            raise VPNError(f"{target} keeps no VPN file: `flightdeck vpn add {target} FILE` copies the event's .conf or .ovpn in")
        return vpn
    if not target.is_file():
        raise VPNError(f"{target}: no such file or folder")
    return VPN(target, kind_of(target))


def keep(folder: Path, source: Path) -> VPN:
    """Copy the event's VPN file into its folder as vpn.conf or vpn.ovpn, for its owner only,
    replacing one kept before. The source is left where it is."""
    kind = kind_of(source)
    try:
        if not source.is_file():
            raise VPNError(f"{source}: no such file")
        if source.stat().st_size > MAX_BYTES:
            raise VPNError(f"{source.name} is over {MAX_BYTES // 1024} KB: that is not a VPN file")
        data = source.read_bytes()
        folder.mkdir(parents=True, exist_ok=True)
        for name in NAMES:
            (folder / name).unlink(missing_ok=True)
        target = folder / ("vpn.conf" if kind == "wireguard" else "vpn.ovpn")
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        os.chmod(target, 0o600)
    except OSError as exc:
        raise VPNError(f"cannot keep the VPN file in {folder}: {exc.strerror or type(exc).__name__}") from None
    return VPN(target, kind)


def install_hint(vpn: VPN, platform: str = sys.platform) -> str:
    package = "wireguard-tools" if vpn.kind == "wireguard" else "openvpn"
    how = f"brew install {package}" if platform == "darwin" else f"sudo apt install {package}"
    return f"{vpn.tool} is not on this machine: {how}"


def up_command(vpn: VPN, which: Callable[[str], str | None] | None = None) -> list[str]:
    """What connects the VPN. VPNError when its tool is missing."""
    tool = (which or shutil.which)(vpn.tool)
    if tool is None:
        raise VPNError(install_hint(vpn))
    if vpn.kind == "wireguard":
        return ["sudo", tool, "up", str(vpn.file)]
    return ["sudo", tool, "--config", str(vpn.file), "--daemon", "--writepid", str(vpn.folder / PID_FILE),
            "--log", str(vpn.folder / LOG_FILE)]


def down_command(vpn: VPN, which: Callable[[str], str | None] | None = None) -> list[str]:
    """What disconnects it. VPNError when there is nothing of flightdeck's to stop."""
    if vpn.kind == "wireguard":
        tool = (which or shutil.which)(vpn.tool)
        if tool is None:
            raise VPNError(install_hint(vpn))
        return ["sudo", tool, "down", str(vpn.file)]
    pid = _pid(vpn)
    if pid is None:
        raise VPNError(f"no OpenVPN that flightdeck started is noted in {vpn.folder / PID_FILE}")
    return ["sudo", "kill", str(pid)]


def _pid(vpn: VPN) -> int | None:
    try:
        text = (vpn.folder / PID_FILE).read_text().strip()
    except OSError:
        return None
    return int(text) if text.isdigit() and int(text) > 1 else None


def addresses(vpn: VPN) -> tuple[str, ...]:
    """The addresses a WireGuard file gives this machine (its [Interface] Address), without
    their prefix lengths; () for OpenVPN, whose server assigns one."""
    if vpn.kind != "wireguard":
        return ()
    try:
        text = vpn.file.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise VPNError(f"cannot read {vpn.file.name}: {exc.strerror}") from None
    found = []
    for line in _ADDRESS.findall(text):
        found += [part.strip().split("/")[0] for part in line.split(",") if part.strip()]
    return tuple(found)


def _interfaces(run=subprocess.run, which=shutil.which) -> str:
    """This machine's interface addresses, as its own tool prints them ("" when none can)."""
    for argv in (["ip", "-o", "addr"], ["ifconfig"]):
        if which(argv[0]) is None:
            continue
        try:
            done = run(argv, capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            continue
        if done.returncode == 0:
            return done.stdout
    return ""


def connected(vpn: VPN, *, run=subprocess.run, which=shutil.which, alive: Callable[[int], bool] | None = None) -> bool | None:
    """Whether the VPN looks connected: True, False, or None when this cannot be told.
    WireGuard: an interface of this machine has the file's address. OpenVPN: the process
    flightdeck started (vpn.pid) is alive; one started another way cannot be told."""
    if vpn.kind == "wireguard":
        wanted = addresses(vpn)
        listing = _interfaces(run, which)
        if not wanted or not listing:
            return None
        return any(re.search(rf"(?<![\w.:]){re.escape(address)}(?![\w.:])", listing) for address in wanted)
    pid = _pid(vpn)
    if pid is None:
        return None
    return (alive or _alive)(pid)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # root's process: it is there
    return True


def status_line(vpn: VPN, state: bool | None) -> str:
    what = "WireGuard" if vpn.kind == "wireguard" else "OpenVPN"
    if state is True:
        return f"vpn: {what} ({vpn.file.name}) looks connected"
    if state is False:
        return f"vpn: {what} ({vpn.file.name}) is NOT connected: `flightdeck vpn up {vpn.folder}` connects it"
    return (f"vpn: {what} ({vpn.file.name}): flightdeck cannot tell whether it is connected; "
            f"`flightdeck vpn up {vpn.folder}` connects it if it is not")


def reachable(urls: Sequence[str], *, timeout: float = 3.0) -> list[str]:
    """The addresses among `urls` (origins and tcp:// services) that a TCP connection from
    this machine does not reach, each with the reason. A lane's reach is its own (the fence);
    this is the player's machine asking whether the target is there at all."""
    import socket
    from urllib.parse import urlsplit

    failed = []
    for url in urls:
        parts = urlsplit(url)
        port = parts.port or {"http": 80, "https": 443}.get(parts.scheme)
        if not parts.hostname or not port:
            continue
        try:
            with socket.create_connection((parts.hostname, port), timeout=timeout):
                pass
        except OSError as exc:
            failed.append(f"{parts.hostname}:{port} ({exc.strerror or type(exc).__name__})")
    return failed
