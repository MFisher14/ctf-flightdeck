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

A VPN file is a program for root: wg-quick runs its PreUp/PostUp/PreDown/PostDown lines in a
root shell, and OpenVPN runs its scripts and loads its plugins as root. So three things hold
before anything is run through sudo:

  - Only a file the player added is connected. keep() (`flightdeck vpn add`, and the VPN
    answer of `flightdeck start` and of the home form) notes the kept file's resolved path
    and SHA-256 in flightdeck's state folder (vpn.json). A vpn.conf or vpn.ovpn that is
    merely in a folder (a board somebody shared), or one changed since it was added, is
    unverified: added() is False, and nothing connects it.
  - root_programs() lists every line of the file that runs a program, or loads code, as
    root. The caller shows them as written (shown(): control characters escaped) and asks
    with no as the default; with nobody to ask it refuses.
  - `vpn down` stops only the OpenVPN flightdeck started: started() checks with ps that
    vpn.pid names a running openvpn whose command line is the one up_command() gave for this
    file. Any other note is stale: it is removed, and the process is never signalled.

What is read of the file: all of it, for the hash and those lines; the address line of a
WireGuard [Interface], to tell whether it is up. Nothing else of it is printed (the private
key never is).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from .leftovers import state_folder

KINDS = {".conf": "wireguard", ".ovpn": "openvpn"}
NAMES = ("vpn.conf", "vpn.ovpn")
PID_FILE, LOG_FILE = "vpn.pid", "vpn.log"
NOTE = "vpn.json"  # in flightdeck's state folder: the VPN files the player added, {resolved path: SHA-256}
MAX_BYTES = 256 * 1024
_ADDRESS = re.compile(r"^\s*Address\s*=\s*(.+)$", re.IGNORECASE | re.MULTILINE)

# wg-quick runs these [Interface] lines in a root shell: all four belong to a connection (the
# Down ones run when it is disconnected), and `wg-quick down` runs the last two.
_WG_HOOKS = ("preup", "postup", "predown", "postdown")
_WG_DOWN_HOOKS = ("predown", "postdown")
# OpenVPN directives that run a program as root, or load code into the root process: scripts,
# shared objects (a plugin, a PKCS#11 provider, an OpenSSL engine or provider), the program
# used in place of `ip`, another config file (it can hold any of these), and the environment
# of every program OpenVPN starts (setenv: LD_PRELOAD and its kin). `script-security` of 2 or
# more is what lets scripts run at all, so it is listed too (_ovpn_runs).
_OVPN_PROGRAMS = frozenset({
    "up", "down", "route-up", "route-pre-down", "ipchange", "tls-verify", "auth-user-pass-verify", "client-connect",
    "client-disconnect", "client-crresponse", "learn-address", "tls-crypt-v2-verify",
    "plugin", "pkcs11-providers", "engine", "providers", "iproute", "config", "setenv",
})
_OVPN_LINE = 254  # OpenVPN reads a config line into a 256-byte buffer: a longer line is not read as one line
# the command line of the OpenVPN that up_command() starts, as ps prints it
_STARTED = re.compile(r"(?P<tool>.+?) --config (?P<config>.+) --daemon --writepid (?P<pid>.+) --log (?P<log>.+)", re.DOTALL)


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
    """The VPN file in a folder (vpn.conf or vpn.ovpn), or None. Being there does not make it
    one the player added: added() says that. Its path is absolute, so the tool it is handed
    to, as root, reads this file and no other."""
    for name in NAMES:
        path = Path(os.path.abspath(folder / name))
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
    return VPN(Path(os.path.abspath(target)), kind_of(target))


def keep(folder: Path, source: Path) -> VPN:
    """Copy the event's VPN file into its folder as vpn.conf or vpn.ovpn, for its owner only,
    replacing one kept before, and note it as one the player added (added()). The source is
    left where it is. Only what the player does calls this: a file is never kept, and so
    never noted, because it was found somewhere."""
    kind = kind_of(source)
    folder = Path(os.path.abspath(folder))
    if not source.is_file():
        raise VPNError(f"{source}: no such file")
    data = _bytes(source)
    try:
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
    _note_added(target, data)
    return VPN(target, kind)


def _bytes(path: Path) -> bytes:
    """A VPN file's bytes. VPNError when it cannot be read, or is not the text file its tool
    reads: too big, or with a NUL byte (bash drops one and OpenVPN stops at one, so a line
    could read differently to wg-quick or OpenVPN than it does here)."""
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_BYTES + 1)
    except OSError as exc:
        raise VPNError(f"cannot read {path}: {exc.strerror or type(exc).__name__}") from None
    if len(data) > MAX_BYTES:
        raise VPNError(f"{path.name} is over {MAX_BYTES // 1024} KB: that is not a VPN file")
    if b"\0" in data:
        raise VPNError(f"{path.name} holds a NUL byte: a VPN file is plain text, and flightdeck does not connect one that is not")
    return data


def read(vpn: VPN) -> bytes:
    """The file's bytes, read once: what added() and root_programs() are then asked about is
    the same text. VPNError when it is not a text file of a VPN file's size."""
    return _bytes(vpn.file)


# ---- the files the player added


def _note() -> Path:
    return state_folder() / NOTE


def _noted() -> dict[str, str]:
    """{resolved path: SHA-256} of the files added. A note that is missing or cannot be read
    notes nothing: every file is then unverified, which is the safe reading of it."""
    try:
        data = json.loads(_note().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {path: digest for path, digest in data.items() if isinstance(path, str) and isinstance(digest, str)}


def _note_added(file: Path, data: bytes) -> None:
    """Note that the player added `file` with these bytes. VPNError when the note cannot be
    written: the file is kept, and stays unverified."""
    try:
        path = _note()
        noted = {known: digest for known, digest in _noted().items() if os.path.isfile(known)}  # a file that is gone is forgotten
        noted[str(file.resolve())] = hashlib.sha256(data).hexdigest()
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(noted, indent=1, sort_keys=True) + "\n")
        os.replace(temp, path)
    except (OSError, RuntimeError) as exc:
        why = getattr(exc, "strerror", None) or str(exc) or type(exc).__name__
        raise VPNError(f"{file} is kept, but flightdeck could not note that you added it ({why}), so it stays unverified "
                       f"and will not be connected: fix that, then `flightdeck vpn add` it again") from None


def added(vpn: VPN, data: bytes | None = None) -> bool:
    """Whether this file is one the player added through flightdeck and has not changed since:
    its resolved path is noted with the SHA-256 of what it holds now (`data`, or the file
    read here). VPNError when the file cannot be read."""
    data = read(vpn) if data is None else data
    try:
        key = str(vpn.file.resolve())
    except (OSError, RuntimeError):
        return False
    return _noted().get(key) == hashlib.sha256(data).hexdigest()


def unverified(vpn: VPN) -> str:
    """What to say of a file that added() refuses."""
    folder = vpn.folder if vpn.file.name in NAMES else "FOLDER"
    return (f"vpn: {vpn.file} is unverified: it was not added with flightdeck, or it has changed since it was. A VPN file can run "
            f"programs as root, so flightdeck connects only one you added: read it, then `flightdeck vpn add {folder} {vpn.file}`")


# ---- what the file would run as root


@dataclass(frozen=True)
class RootLine:
    number: int  # the line in the file, from 1
    text: str  # the line as written
    note: str = ""  # why it is listed, when it is not for a directive


def root_programs(kind: str, data: bytes, *, down: bool = False) -> list[RootLine]:
    """Every line of a VPN file that runs a program, or loads code, as root when the file is
    connected (`down`: when it is disconnected, which for WireGuard reads the file again).
    Lines are told apart as the tool does it (a line ends at a newline only), and a line is
    listed in doubt: a harmless line shown is a question asked; one missed is root's."""
    text = data.decode("utf-8", errors="replace").removeprefix("\ufeff")  # OpenVPN skips a byte order mark
    found = []
    for number, line in enumerate(text.split("\n"), start=1):
        if kind == "wireguard":
            # wg-quick: what follows a # is a comment; the key is what stands before the first =, trimmed, in any case
            key = line.split("#", 1)[0].split("=", 1)[0].strip().lower()
            if key in (_WG_DOWN_HOOKS if down else _WG_HOOKS):
                found.append(RootLine(number, line.rstrip("\r")))
        elif not down:  # an OpenVPN is stopped by signal: its file is not read again
            if len(line.encode("utf-8")) > _OVPN_LINE:
                found.append(RootLine(number, line.rstrip("\r"), "longer than OpenVPN reads as one line, so it may hide a directive"))
            elif _ovpn_runs(_ovpn_words(line)):
                found.append(RootLine(number, line.rstrip("\r")))
    return found


def _ovpn_words(line: str) -> list[str]:
    """A config line's words as OpenVPN's parser splits them: on whitespace, "double" and
    'single' quotes, a backslash taking the next character as it is (not within single
    quotes), and a ; or # where a word would start beginning a comment."""
    words: list[str] = []
    word: list[str] = []
    state, backslash = "", False  # state: "" between words, "bare" in one, or the quote a word is in
    for ch in line:
        if ch == "\\" and not backslash and state != "'":
            backslash = True
            continue
        done = False
        if state == "":
            if not ch.isspace():
                if ch in ";#":
                    break
                if ch in "\"'" and not backslash:
                    state = ch
                else:
                    word.append(ch)
                    state = "bare"
        elif state == "bare":
            if ch.isspace() and not backslash:
                done = True
            else:
                word.append(ch)
        elif ch == state and (state == "'" or not backslash):
            done = True
        else:
            word.append(ch)
        if done:
            words.append("".join(word))
            word, state = [], ""
        backslash = False
    if state:
        words.append("".join(word))  # a quote left open: OpenVPN refuses the line; here it is read as far as it goes
    return words


def _ovpn_runs(words: list[str]) -> bool:
    """Whether a config line's words are a directive that runs a program, or loads code, as
    root. A directive may be written --name, <name> (an inline block), or `setenv opt name`
    (applied when this OpenVPN knows it)."""
    while len(words) > 2 and words[0].removeprefix("--").lower() == "setenv" and words[1] == "opt":
        words = words[2:]
    if not words:
        return False
    name = words[0].lower()
    if name.startswith("<") and name.endswith(">") and len(words) == 1:
        name = name[1:-1]
    name = name.removeprefix("--")
    if name == "script-security":  # 0 and 1 run no script; anything else is read as letting scripts run
        return not (len(words) > 1 and words[1] in ("0", "1"))
    return name in _OVPN_PROGRAMS


def shown(text: str) -> str:
    """`text` for a terminal: as written, with every character that is not printable (control
    characters, and the ones that hide or reorder text) as its escape."""
    return "".join(ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii") for ch in text)


def install_hint(vpn: VPN, platform: str = sys.platform) -> str:
    package = "wireguard-tools" if vpn.kind == "wireguard" else "openvpn"
    how = f"brew install {package}" if platform == "darwin" else f"sudo apt install {package}"
    return f"{vpn.tool} is not on this machine: {how}"


def install_command(vpn: VPN, platform: str = sys.platform, which: Callable[[str], str | None] | None = None) -> list[str] | None:
    """What installs the VPN's tool with this machine's package manager (Homebrew on macOS;
    apt, dnf or pacman on Linux), or None when none of them is here."""
    which = which or shutil.which
    package = "wireguard-tools" if vpn.kind == "wireguard" else "openvpn"
    if platform == "darwin":
        return ["brew", "install", package] if which("brew") else None
    for manager, argv in (("apt-get", ["sudo", "apt-get", "install", "-y", package]), ("dnf", ["sudo", "dnf", "install", "-y", package]),
                          ("pacman", ["sudo", "pacman", "-S", "--noconfirm", package])):
        if which(manager):
            return argv
    return None


def has_tool(vpn: VPN, which: Callable[[str], str | None] | None = None) -> bool:
    return (which or shutil.which)(vpn.tool) is not None


def up_command(vpn: VPN, which: Callable[[str], str | None] | None = None) -> list[str]:
    """What connects the VPN. VPNError when its tool is missing."""
    tool = (which or shutil.which)(vpn.tool)
    if tool is None:
        raise VPNError(install_hint(vpn))
    if vpn.kind == "wireguard":
        return ["sudo", tool, "up", str(vpn.file)]
    for path in (vpn.folder / PID_FILE, vpn.folder / LOG_FILE):  # root's OpenVPN writes both: never through a link
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise VPNError(f"{path} is a link or a folder, and OpenVPN would write through it as root: remove it, then connect again")
    return ["sudo", tool, "--config", str(vpn.file), "--daemon", "--writepid", str(vpn.folder / PID_FILE),
            "--log", str(vpn.folder / LOG_FILE)]


def down_command(vpn: VPN, which: Callable[[str], str | None] | None = None, *, run=None) -> list[str]:
    """What disconnects it. VPNError when there is nothing of flightdeck's to stop: an OpenVPN
    is stopped only when started() finds the one flightdeck started for this file."""
    if vpn.kind == "wireguard":
        tool = (which or shutil.which)(vpn.tool)
        if tool is None:
            raise VPNError(install_hint(vpn))
        return ["sudo", tool, "down", str(vpn.file)]
    pid, stale = started(vpn, run=run)
    if pid is None:
        raise VPNError(f"{stale}. Nothing was stopped" if stale else f"no OpenVPN that flightdeck started is noted in {vpn.folder / PID_FILE}")
    return ["sudo", "kill", str(pid)]


def started(vpn: VPN, *, run=None) -> tuple[int | None, str]:
    """The OpenVPN flightdeck started for this file: (its pid, "") while it runs. (None, "")
    when none is noted (no vpn.pid). (None, why) when the note is stale: it holds no process
    number, or names a process that is gone, or one that is not an openvpn started with this
    file by up_command() (ps says what it is). A stale note is removed here and its process
    is left alone. VPNError when ps cannot say what the process is."""
    note = vpn.folder / PID_FILE
    try:
        with note.open("rb") as handle:
            text = handle.read(64).decode("ascii", errors="replace").strip()
    except FileNotFoundError:
        return None, ""
    except OSError as exc:
        raise VPNError(f"cannot read {note}: {exc.strerror or type(exc).__name__}") from None
    if not re.fullmatch(r"[0-9]{1,10}", text) or int(text) <= 1:
        return None, _forget(note, f"{note} does not hold a process number")
    pid = int(text)
    command = _command_of(pid, run)
    if not command:
        return None, _forget(note, f"process {pid}, noted in {note}, is not running")
    match = _STARTED.fullmatch(command)
    if not (match and Path(match["tool"]).name == "openvpn" and _same_file(match["config"], vpn.file)):
        return None, _forget(note, f"process {pid}, noted in {note}, is not an OpenVPN that flightdeck started with {vpn.file.name}")
    return pid, ""


def forget_started(vpn: VPN) -> None:
    """Drop the note of the OpenVPN flightdeck started (after it was stopped)."""
    (vpn.folder / PID_FILE).unlink(missing_ok=True)


def _forget(note: Path, why: str) -> str:
    try:
        note.unlink(missing_ok=True)
    except OSError as exc:
        return f"{why} (the stale note could not be removed: {exc.strerror or type(exc).__name__})"
    return f"{why}: the stale note was removed"


def _command_of(pid: int, run=None) -> str:
    """The command line of process `pid` as ps prints it; "" when there is no such process.
    VPNError when ps cannot be run, or fails some other way."""
    argv = ["ps", "-ww", "-p", str(pid), "-o", "command="]
    try:
        done = (run or subprocess.run)(argv, capture_output=True, text=True, errors="replace", timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        raise VPNError(f"cannot tell what process {pid} is: `{' '.join(argv)}` did not run ({type(exc).__name__})") from None
    if done.returncode == 1:  # ps: no process was selected
        return ""
    if done.returncode != 0:
        raise VPNError(f"cannot tell what process {pid} is: `{' '.join(argv)}` failed (exit {done.returncode})")
    return (done.stdout or "").strip()


def _same_file(named: str, file: Path) -> bool:
    try:
        return Path(named).resolve() == file.resolve()
    except (OSError, RuntimeError):
        return False


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


def connected(vpn: VPN, *, run=None, which=shutil.which) -> bool | None:
    """Whether the VPN looks connected: True, False, or None when this cannot be told.
    WireGuard: an interface of this machine has the file's address. OpenVPN: the process
    flightdeck started for this file runs (started()); a stale note of one is not connected
    (and is removed); one started another way cannot be told."""
    run = run or subprocess.run
    if vpn.kind == "wireguard":
        wanted = addresses(vpn)
        listing = _interfaces(run, which)
        if not wanted or not listing:
            return None
        return any(re.search(rf"(?<![\w.:]){re.escape(address)}(?![\w.:])", listing) for address in wanted)
    pid, stale = started(vpn, run=run)
    if pid is not None:
        return True
    return False if stale else None


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
