"""What a run leaves running when flightdeck itself is killed, and the backstop that finds and
removes it.

Quitting, a hang-up and SIGTERM stop every lane and remove what it started. SIGKILL and a
power loss leave flightdeck no handler to run, so lane containers, L1 engines and
coding-agent CLIs can outlive it. A run therefore marks what it starts:

- every container it starts (a lane's, an L1 engine's; a coding-agent docker lane runs in
  its lane's container) carries labels (labels()): flightdeck.run, the run folder's name,
  and the flightdeck that started it: this machine (a hash of the machine's id, never the
  id itself), the user id, the process id, the process's start time, and the folder it
  keeps its notes in (state_folder(), as a hash), so that two flightdeck setups, or two
  test suites, on one machine never remove each other's containers. The network a fenced
  lane gets and the proxy containers on it (agent/egress.py) carry the same labels;
- its run folder holds processes.json (ProcessRecord): the same flightdeck, whether the run
  used Docker, and every process group the run started on this machine that may still be
  running (host lanes' commands, L1 engines on the host, coding-agent CLIs on the host),
  each with the processes seen in it and their start times, its leader first. The file is
  written atomically (a new file, synced, then renamed over the old one) whenever a group
  comes or goes or what runs in it changes, and removed when the run ends cleanly;
- while that record is there, a note in the state folder's open-runs/ names the run folder,
  so the run is found wherever its folder is: `play --run-dir` puts it outside the
  config's runs folder, and a later doctor or play may be given another one.

A run's flightdeck is gone when no live process has its pid, or the one that has it
started at another time (the pid was reused). sweep() finds what such runs left (the run
folders in the runs folder it is given, and those the notes name), and with clean=True
removes it:

- their containers, and then their Docker networks: only those with all of flightdeck's
  labels, of this machine, this user and this state folder;
- their process groups: each only when a process recorded in it is still in it (the same
  pid with the same start time) and works in a folder under that run's folder. A process
  group's number is not given out again while any process of the group lives, so the group
  is then still the one the run started. A group whose recorded processes run on but no
  longer work under the run's folder is left alone, and the sweep says so. A group whose
  recorded processes have all ended is gone: its number may be another program's group
  by now, so it is never signalled (if processes that work in the run's folder are in a
  group of that number, the sweep names them). No process flightdeck did not record is
  ever signalled.

`play` and `practice` sweep at their start and say what they removed; `flightdeck doctor`
reports, and removes with --clean. What a sweep leaves alone (Swept.alone) says why, and
what to do about it when the player can.

Start times and working folders come from /proc on Linux and from the kernel (sysctl and
proc_pidinfo) on macOS. Elsewhere nothing can be checked, so nothing is removed, and the
sweep says why. A run's folder is compared with a working folder as the kernel names both
(_kernel_path()): on macOS in the case and Unicode form stored on disk, whatever spelling
the config or --run-dir used.

Everything read back here (a record, a note, a container's labels, a run folder's name) may
have been written by something else running as the player, a host lane included: it is
parsed strictly and shown only through untrusted().
"""

from __future__ import annotations

import contextlib
import ctypes
import ctypes.util
import errno
import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path

from .text import untrusted

RECORD = "processes.json"
SCHEMA = 1
LABEL_RUN = "flightdeck.run"
LABEL_HOST = "flightdeck.host"
LABEL_UID = "flightdeck.uid"
LABEL_PID = "flightdeck.pid"
LABEL_STARTED = "flightdeck.started"
LABEL_STATE = "flightdeck.state"
LABELS = (LABEL_RUN, LABEL_HOST, LABEL_UID, LABEL_PID, LABEL_STARTED, LABEL_STATE)
STATE_ENV = "XDG_STATE_HOME"
OPEN_RUNS = "open-runs"  # in the state folder: a note per run whose record is still in its run folder
MAX_PROCESSES = 16  # processes recorded per group: one of them still there is enough to know the group
RECORD_MAX = 1024 * 1024  # a record bigger than this is not read
NOTE_MAX = 16 * 1024  # a note bigger than this is not read
DOCKER_TIMEOUT = 60.0  # seconds for one docker call
SHOWN_PIDS = 5  # pids named in a line about processes left alone
_CONTAINER_ID = re.compile(r"[0-9a-f]{12,64}")
_RUNNING, _GONE, _UNKNOWN = "running", "gone", "unknown"
NOT_SHUT_DOWN = "did not shut down (its flightdeck was killed, or the machine stopped)"


class Unsupported(Exception):
    """This system gives flightdeck no way to read a process's start time or folder."""


# ---------------------------------------------------------------- processes on this machine


@dataclass(frozen=True)
class Proc:
    """A live process: its pid, its process group, and when it started (a token that is equal
    for the same process only: two processes never share one, even with the same pid)."""

    pid: int
    pgid: int
    started: str


def supported() -> str | None:
    """None when this system lets flightdeck read processes' start times and groups, else why
    not. It reads its own process and checks what it read against what it knows."""
    try:
        me = process(os.getpid())
    except Unsupported as exc:
        return str(exc)
    if me is None or me.pgid != os.getpgrp():
        return "flightdeck cannot read its own process's start time and group here"
    return None


def process(pid: int) -> Proc | None:
    """The live process with this pid (a zombie has exited: it is not live), or None.
    Unsupported when this system cannot say."""
    if not _whole(pid) or pid <= 0:
        return None
    if sys.platform == "darwin":
        return next((p for p in _darwin_procs(_KERN_PROC_PID, pid) if p.pid == pid), None)
    if sys.platform.startswith("linux"):
        return _linux_proc(pid, _boot_id())
    raise Unsupported(f"flightdeck reads process start times on Linux and macOS only, not on {sys.platform}")


def processes_in(pgids: Iterable[int]) -> dict[int, list[Proc]]:
    """{group: its live processes, its leader first} for each of these process groups (an
    empty list for a group with none). On Linux one pass over /proc answers for all of them.
    Unsupported when this system cannot say."""
    found: dict[int, list[Proc]] = {pgid: [] for pgid in pgids if _whole(pgid) and pgid > 0}
    if not found:
        return found
    if sys.platform == "darwin":
        for pgid in found:
            found[pgid] = [p for p in _darwin_procs(_KERN_PROC_PGRP, pgid) if p.pgid == pgid]
    elif sys.platform.startswith("linux"):
        for proc in _linux_all(_boot_id()):
            if proc.pgid in found:
                found[proc.pgid].append(proc)
    else:
        raise Unsupported(f"flightdeck lists process groups on Linux and macOS only, not on {sys.platform}")
    return {pgid: sorted(procs, key=lambda p: (p.pid != pgid, p.pid)) for pgid, procs in found.items()}


def group(pgid: int) -> list[Proc]:
    """The live processes in a process group, its leader first."""
    return processes_in([pgid]).get(pgid, [])


def working_folder(pid: int) -> str | None:
    """The folder a process works in, as the kernel has it (no symlinks), or None when it
    cannot be read (the process is gone, or is not this user's)."""
    if sys.platform == "darwin":
        return _darwin_cwd(pid)
    if sys.platform.startswith("linux"):
        try:
            return os.readlink(f"{_PROC}/{pid}/cwd")
        except OSError:
            return None
    return None


def _kernel_path(path: str | Path) -> str:
    """A folder's path as the kernel names it, the way working_folder() has a process's: no
    symlinks, and on macOS in the case and Unicode form stored on disk (the kernel's name
    for the open folder, F_GETPATH), where the config may spell ~/CTF/runs as ~/ctf/runs.
    Its real path when the folder cannot be opened (it has gone: nothing works in it)."""
    real = os.path.realpath(path)
    if sys.platform != "darwin":
        return real
    try:
        fd = os.open(real, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return real
    try:
        named = fcntl.fcntl(fd, fcntl.F_GETPATH, bytes(_MAXPATHLEN))
    except OSError:
        return real
    finally:
        os.close(fd)
    return os.fsdecode(named.split(b"\0", 1)[0]) or real


@cache
def host_id() -> str:
    """This machine, as a hash of its id (never the id itself): containers and records of
    another machine (a shared Docker daemon, a shared folder) are never touched."""
    raw: bytes | None = None
    if sys.platform == "darwin":
        uuid = ctypes.create_string_buffer(16)
        wait = (ctypes.c_long * 2)(0, 0)
        with contextlib.suppress(OSError, AttributeError):
            if _libc().gethostuuid(uuid, wait) == 0:
                raw = uuid.raw
    else:
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                raw = Path(path).read_bytes().strip() or None
            except OSError:
                continue
            if raw:
                break
    if not raw:  # no machine id to be had: the host name is the next best name for this machine
        raw = b"hostname:" + socket.gethostname().encode("utf-8", "replace")
    return hashlib.sha256(b"ctf-flightdeck host\0" + raw).hexdigest()[:16]


def state_folder() -> Path:
    """The folder flightdeck keeps notes of its own in: $XDG_STATE_HOME/ctf-flightdeck when
    that is an absolute path (the XDG rule: anything else is ignored), else
    ~/.local/state/ctf-flightdeck. OSError when there is no home folder to put it in."""
    base = os.environ.get(STATE_ENV, "")
    if os.path.isabs(base):
        return Path(base) / "ctf-flightdeck"
    try:
        home = Path.home()
    except RuntimeError:
        home = Path()
    if not home.is_absolute():
        raise OSError(errno.ENOENT, f"there is no home folder for flightdeck's notes; set {STATE_ENV} to a folder")
    return home / ".local" / "state" / "ctf-flightdeck"


def open_runs() -> Path:
    """The folder of notes naming the run folders whose record is still there (OSError as
    state_folder())."""
    return state_folder() / OPEN_RUNS


def state_id() -> str:
    """The state folder as a hash (never its path): the label that tells this setup's
    containers from those of a flightdeck that keeps its notes elsewhere. OSError as
    state_folder()."""
    folder = os.path.realpath(state_folder())
    return hashlib.sha256(b"ctf-flightdeck state\0" + os.fsencode(folder)).hexdigest()[:16]


# Linux: /proc/<pid>/stat, whose fields after the command's name are: state, ppid, pgrp, ...,
# starttime (clock ticks after boot) at index 19. The boot's id makes a start time unique
# across reboots.

_PROC = "/proc"


@cache
def _boot_id() -> str:
    try:
        boot = Path(_PROC, "sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        boot = ""
    if not boot:
        raise Unsupported("this Linux has no /proc/sys/kernel/random/boot_id, so process start times cannot be compared")
    return boot


def _linux_stat(pid: int) -> tuple[str, int, str] | None:
    """(state, process group, start time in ticks after boot) of a process, or None."""
    try:
        with open(f"{_PROC}/{pid}/stat", "rb") as handle:
            data = handle.read()
    except OSError:
        return None
    end = data.rfind(b")")  # the command's name is in parentheses and may hold anything
    fields = data[end + 2:].split() if end >= 0 else []
    if len(fields) < 20 or not fields[2].lstrip(b"-").isdigit() or not fields[19].isdigit():
        return None
    return fields[0].decode("ascii", "replace"), int(fields[2]), fields[19].decode("ascii")


def _linux_proc(pid: int, boot: str) -> Proc | None:
    info = _linux_stat(pid)
    if info is None or info[0] in ("Z", "X", "x"):  # a zombie, or dead
        return None
    return Proc(pid, info[1], f"linux:{boot}:{info[2]}")


def _linux_all(boot: str) -> list[Proc]:
    try:
        names = os.listdir(_PROC)
    except OSError as exc:
        raise Unsupported(f"{_PROC} cannot be listed ({exc.strerror or exc})") from None
    found = []
    for name in names:
        if name.isdigit():
            proc = _linux_proc(int(name), boot)
            if proc is not None:
                found.append(proc)
    return found


# macOS: sysctl(CTL_KERN, KERN_PROC, KERN_PROC_PID or KERN_PROC_PGRP, n) gives struct
# kinfo_proc records (648 bytes each on 64-bit macOS): in its extern_proc, p_starttime (a
# timeval: seconds, microseconds) at offset 0, p_stat at 36 (5 is a zombie) and p_pid at 40;
# in its eproc (from offset 296), e_pgid at 268. proc_pidinfo(PROC_PIDVNODEPATHINFO) gives a
# struct proc_vnodepathinfo (2352 bytes) whose working folder's path starts at offset 152.

_CTL_KERN, _KERN_PROC, _KERN_PROC_PID, _KERN_PROC_PGRP = 1, 14, 1, 2
_KINFO = 648
_P_STARTTIME, _P_STAT, _P_PID, _E_PGID = 0, 36, 40, 296 + 268
_SZOMB = 5
_VNODEPATHINFO, _VNODEPATHINFO_SIZE, _CDIR_PATH, _MAXPATHLEN = 9, 2352, 152, 1024


@cache
def _libc() -> ctypes.CDLL:
    return ctypes.CDLL(ctypes.util.find_library("c") or "/usr/lib/libc.dylib", use_errno=True)


@cache
def _libproc() -> ctypes.CDLL:
    return ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib", use_errno=True)


def _darwin_kinfo(what: int, arg: int) -> list[bytes]:
    try:
        libc = _libc()
    except OSError as exc:
        raise Unsupported(f"the C library cannot be loaded ({exc})") from None
    mib = (ctypes.c_int * 4)(_CTL_KERN, _KERN_PROC, what, arg)
    for _ in range(4):
        size = ctypes.c_size_t(0)
        if libc.sysctl(mib, 4, None, ctypes.byref(size), None, ctypes.c_size_t(0)) != 0:
            raise Unsupported(f"sysctl kern.proc failed ({os.strerror(ctypes.get_errno())})")
        if size.value == 0:
            return []
        size = ctypes.c_size_t(size.value + 16 * _KINFO)  # room for processes started meanwhile
        buffer = ctypes.create_string_buffer(size.value)
        if libc.sysctl(mib, 4, buffer, ctypes.byref(size), None, ctypes.c_size_t(0)) == 0:
            if size.value % _KINFO:
                raise Unsupported("this macOS lays out its process records in a way flightdeck does not know")
            raw = buffer.raw[:size.value]
            return [raw[i:i + _KINFO] for i in range(0, len(raw), _KINFO)]
        if ctypes.get_errno() != errno.ENOMEM:
            raise Unsupported(f"sysctl kern.proc failed ({os.strerror(ctypes.get_errno())})")
    raise Unsupported("sysctl kern.proc kept growing")


def _darwin_procs(what: int, arg: int) -> list[Proc]:
    found = []
    for record in _darwin_kinfo(what, arg):
        seconds, micros = struct.unpack_from("=qi", record, _P_STARTTIME)
        (pid,) = struct.unpack_from("=i", record, _P_PID)
        (pgid,) = struct.unpack_from("=i", record, _E_PGID)
        if record[_P_STAT] != _SZOMB and pid > 0:
            found.append(Proc(pid, pgid, f"darwin:{seconds}.{micros:06d}"))
    return found


def _darwin_cwd(pid: int) -> str | None:
    try:
        libproc = _libproc()
    except OSError:
        return None
    buffer = ctypes.create_string_buffer(_VNODEPATHINFO_SIZE)
    size = libproc.proc_pidinfo(pid, _VNODEPATHINFO, ctypes.c_uint64(0), buffer, _VNODEPATHINFO_SIZE)
    if size != _VNODEPATHINFO_SIZE:
        return None
    path = buffer.raw[_CDIR_PATH:_CDIR_PATH + _MAXPATHLEN].split(b"\0", 1)[0]
    return os.fsdecode(path) if path else None


# ---------------------------------------------------------------- the flightdeck a run belongs to


@dataclass(frozen=True)
class Owner:
    """The flightdeck that started a run: this machine, the user, its pid and when it started
    ("" when this system cannot tell)."""

    host: str
    uid: int
    pid: int
    started: str

    @classmethod
    def this(cls) -> Owner:
        return _this(os.getpid())

    def here(self) -> bool:
        """Whether it ran on this machine as this user: only then is it this sweep's to judge."""
        me = Owner.this()
        return self.host == me.host and self.uid == me.uid

    def state(self) -> str:
        """"running", "gone" (no live process has its pid, or that process started at another
        time), or "unknown" (this system or the record cannot tell)."""
        if not self.started:
            return _UNKNOWN
        try:
            now = process(self.pid)
        except Unsupported:
            return _UNKNOWN
        return _RUNNING if now is not None and now.started == self.started else _GONE

    def as_json(self) -> dict:
        return {"host": self.host, "uid": self.uid, "pid": self.pid, "started": self.started}


@cache
def _this(pid: int) -> Owner:
    try:
        me = process(pid)
    except Unsupported:
        me = None
    return Owner(host_id(), os.getuid(), pid, me.started if me is not None else "")


def labels(run: str, owner: Owner | None = None) -> dict[str, str]:
    """The labels every container of the run carries: the run folder's name, its owner, and
    the state folder its owner keeps its notes in (state_id()). OSError as state_folder()."""
    owner = owner or Owner.this()
    return {
        LABEL_RUN: run,
        LABEL_HOST: owner.host,
        LABEL_UID: str(owner.uid),
        LABEL_PID: str(owner.pid),
        LABEL_STARTED: owner.started,
        LABEL_STATE: state_id(),
    }


# ---------------------------------------------------------------- the run's record


def _write_atomically(path: Path, data: bytes) -> None:
    """Write `data` to a new file next to `path`, sync it, and rename it over `path`: a reader
    sees the old content or the new, never a part of one."""
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


class ProcessRecord:
    """processes.json in a run folder: the run's flightdeck, whether the run used Docker, and
    the process groups it started on this machine that may still be running (see the module
    docstring). add() when a group starts, refresh() to note the processes in groups that
    are still there, drop() when they are gone or killed, finish() when the run ends.

    Writing the file never raises: the first failure is kept in `problem` for the run to
    report, since a run whose record cannot be written still runs (only the backstop is
    lost). start() writes it the first time, then the run's note in open_runs() (`note`),
    and raises OSError naming the file it could not write (its filename) when it cannot
    write either: then neither is left."""

    def __init__(self, run_dir: Path, *, docker: bool, owner: Owner | None = None) -> None:
        self.run_dir = Path(run_dir)
        self.path = self.run_dir / RECORD
        self.docker = docker
        self.owner = owner or Owner.this()
        self.note: Path | None = None  # the run's note in open_runs(), once start() has written it
        self.problem: str | None = None
        self._groups: dict[int, dict] = {}
        self._lock = threading.Lock()

    @classmethod
    def start(cls, run_dir: Path, *, docker: bool, owner: Owner | None = None) -> ProcessRecord:
        record = cls(run_dir, docker=docker, owner=owner)
        with record._lock:
            try:
                record._write()
            except OSError as exc:
                raise OSError(exc.errno, exc.strerror or str(exc), str(record.path)) from None
            try:  # the record first: a note always names a folder whose record is there, or was
                record.note = _note(record.run_dir)
            except OSError:
                with contextlib.suppress(OSError):
                    record.path.unlink()
                raise
        return record

    def groups(self) -> dict[int, list[list]]:
        """{process group: [[pid, start time], ...]} as recorded now."""
        with self._lock:
            return {pgid: [list(p) for p in entry["processes"]] for pgid, entry in self._groups.items()}

    def add(self, pgid: int, folder: Path, what: str) -> None:
        """A process group just started in `folder` (its leader's pid is `pgid`)."""
        try:
            leader = process(pgid)
        except Unsupported:
            return  # nothing could tell it apart later: sweep() says so
        processes = [[leader.pid, leader.started]] if leader is not None else _seen(pgid)
        if not processes:  # it has ended already, and left nothing in its group
            return
        with self._lock:
            self._groups[pgid] = {"what": what, "folder": str(folder), "processes": processes}
            self._save()

    def refresh(self, pgids: Iterable[int]) -> None:
        """Note the processes now in these groups (one that started in the background and
        outlived the command that started it, say); a group with none left goes."""
        with self._lock:
            wanted = [pgid for pgid in pgids if pgid in self._groups]
        if not wanted:
            return
        try:
            current = {pgid: [[p.pid, p.started] for p in procs[:MAX_PROCESSES]]
                       for pgid, procs in processes_in(wanted).items()}
        except Unsupported:
            return
        with self._lock:
            changed = False
            for pgid, processes in current.items():
                entry = self._groups.get(pgid)
                if entry is None:
                    continue
                if not processes:
                    del self._groups[pgid]
                    changed = True
                elif processes != entry["processes"]:
                    entry["processes"] = processes
                    changed = True
            if changed:
                self._save()

    def drop(self, pgids: Iterable[int]) -> None:
        """These groups are gone, or were just killed."""
        with self._lock:
            gone = [pgid for pgid in pgids if pgid in self._groups]
            for pgid in gone:
                del self._groups[pgid]
            if gone:
                self._save()

    def finish(self) -> None:
        """The run ended cleanly: the record goes, then its note, unless a group is still in
        it (then the next sweep, once this flightdeck has exited, deals with it)."""
        with self._lock:
            if self._groups:
                self._save()
                return
            try:
                self.path.unlink(missing_ok=True)
            except OSError as exc:
                self._failed(exc)
                return
            if self.note is not None:
                with contextlib.suppress(OSError):  # one left naming a folder with no record: the next sweep removes it
                    self.note.unlink(missing_ok=True)

    def _save(self) -> None:
        try:
            self._write()
        except OSError as exc:
            self._failed(exc)

    def _failed(self, exc: OSError) -> None:
        if self.problem is None:
            self.problem = (
                f"could not keep {self.path} current ({exc.strerror or exc}): if flightdeck is killed, what this run "
                "left running on this machine will not be found by the next start"
            )

    def _write(self) -> None:
        data = {
            "flightdeck": SCHEMA,
            "run": self.run_dir.name,
            "owner": self.owner.as_json(),
            "docker": self.docker,
            "groups": [{"pgid": pgid, **entry} for pgid, entry in sorted(self._groups.items())],
        }
        _write_atomically(self.path, (json.dumps(data, indent=1) + "\n").encode("utf-8"))


def _seen(pgid: int) -> list[list]:
    """[[pid, start time], ...] of the live processes in a group, its leader first."""
    try:
        return [[p.pid, p.started] for p in group(pgid)[:MAX_PROCESSES]]
    except Unsupported:
        return []


def _note(run_dir: Path) -> Path:
    """Write the note in open_runs() that names this run folder (its real path); the note's
    path. OSError naming the file or folder that could not be written (its filename; none
    when there is no state folder at all)."""
    folder = open_runs()
    try:
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise OSError(exc.errno, exc.strerror or str(exc), str(folder)) from None
    stem = re.sub(r"[^A-Za-z0-9_-]", "_", run_dir.name)[:64] or "run"
    path = folder / f"{stem}-{secrets.token_hex(6)}.json"
    data = {"flightdeck": SCHEMA, "folder": os.path.realpath(run_dir)}
    try:
        _write_atomically(path, (json.dumps(data) + "\n").encode("utf-8"))
    except OSError as exc:
        raise OSError(exc.errno, exc.strerror or str(exc), str(path)) from None
    return path


def _notes() -> tuple[list[tuple[Path, Path]], list[str]]:
    """[(a note in open_runs(), the run folder it names)], and a line for each note (or the
    folder of notes) that cannot be read: such a note is kept, and named."""
    why = "runs whose folder is not in the runs folder looked at cannot be found"
    try:
        folder = open_runs()
        entries = sorted(os.scandir(folder), key=lambda e: e.name)
    except FileNotFoundError:
        return [], []  # no run has noted itself yet
    except OSError as exc:
        return [], [f"{why}: {_show(str(exc.strerror or exc))}" + (f" ({_show(exc.filename)})" if exc.filename else "")]
    found: list[tuple[Path, Path]] = []
    problems: list[str] = []
    for entry in entries:
        if entry.name.startswith("."):  # a note being written, or one whose writer was killed: never a whole note
            continue
        named, problem = _read_note(entry)
        if named is None:
            problems.append(f"a note in {_show(str(folder))} cannot be read ({_show(problem)}), so the run it names cannot "
                            f"be found; remove {_show(entry.path)}")
        else:
            found.append((Path(entry.path), named))
    return found, problems


def _read_note(entry: os.DirEntry) -> tuple[Path | None, str]:
    """(the run folder a note names, "") or (None, why it cannot be read). Strict, as
    read_record()."""
    try:
        if not entry.is_file(follow_symlinks=False) or entry.stat(follow_symlinks=False).st_size > NOTE_MAX:
            return None, "it is not a file, or is too big"
        data = json.loads(Path(entry.path).read_bytes().decode("utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        return None, f"{type(exc).__name__}: {exc}"
    folder = data.get("folder") if isinstance(data, dict) and data.get("flightdeck") == SCHEMA else None
    if not (isinstance(folder, str) and os.path.isabs(folder) and "\0" not in folder):
        return None, "it is not a note this flightdeck wrote"
    return Path(folder), ""


@dataclass(frozen=True)
class _Group:
    pgid: int
    what: str
    folder: str
    processes: tuple[tuple[int, str], ...]


@dataclass(frozen=True)
class _Record:
    owner: Owner
    docker: bool
    groups: tuple[_Group, ...]


def read_record(path: Path) -> tuple[_Record | None, str]:
    """(the record, "") or (None, why it cannot be read). Strict: anything else in the file
    is a reason, never a guess."""
    try:
        if path.is_symlink() or path.stat().st_size > RECORD_MAX:
            return None, "it is a symlink or too big"
        data = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        return None, f"{type(exc).__name__}: {exc}"
    problem = "it is not a record this flightdeck wrote"
    if not (isinstance(data, dict) and data.get("flightdeck") == SCHEMA and isinstance(data.get("docker"), bool)
            and isinstance(data.get("owner"), dict) and isinstance(data.get("groups"), list)):
        return None, problem
    owner = _owner(data["owner"].get("host"), data["owner"].get("uid"), data["owner"].get("pid"), data["owner"].get("started"))
    if owner is None:
        return None, problem
    groups = []
    for entry in data["groups"]:
        if not isinstance(entry, dict):
            return None, problem
        pgid, what, folder, processes = entry.get("pgid"), entry.get("what"), entry.get("folder"), entry.get("processes")
        if not (_whole(pgid) and pgid > 1 and isinstance(what, str) and isinstance(folder, str) and isinstance(processes, list)):
            return None, problem
        pairs = []
        for item in processes:
            if not (isinstance(item, list) and len(item) == 2 and _whole(item[0]) and item[0] > 1 and isinstance(item[1], str)
                    and item[1]):
                return None, problem
            pairs.append((item[0], item[1]))
        groups.append(_Group(pgid, what, folder, tuple(pairs)))
    return _Record(owner, data["docker"], tuple(groups)), ""


def _whole(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _owner(host: object, uid: object, pid: object, started: object) -> Owner | None:
    if isinstance(uid, str) and uid.isdigit():
        uid = int(uid)
    if isinstance(pid, str) and pid.isdigit():
        pid = int(pid)
    if not (isinstance(host, str) and host and _whole(uid) and uid >= 0 and _whole(pid) and pid > 0 and isinstance(started, str)):
        return None
    return Owner(host, uid, pid, started)


# ---------------------------------------------------------------- the sweep


@dataclass(frozen=True)
class Swept:
    """What a sweep did and found, as lines for the player."""

    done: tuple[str, ...] = ()  # what it removed: a line per run
    found: tuple[str, ...] = ()  # what is still there that a sweep with clean removes (none after one)
    alone: tuple[str, ...] = ()  # what it leaves alone, could not remove or could not check, each with why: clean does not change it

    @property
    def lines(self) -> tuple[str, ...]:
        return self.done + self.found + self.alone


@dataclass
class _Run:
    """A run folder with a record, as a sweep found it."""

    record: Path  # its processes.json
    name: str  # how lines name it: its folder's name, or its folder's path when that is not in the runs folder looked at
    notes: list[Path] = field(default_factory=list)  # the notes in open_runs() that name its folder


@dataclass
class _Leftovers:
    """What one run whose flightdeck is gone left."""

    run: str
    containers: list[tuple[str, str]] = field(default_factory=list)  # (id, name)
    networks: list[tuple[str, str]] = field(default_factory=list)  # (id, name): a fenced lane's (agent/egress.py)
    groups: list[tuple[_Group, str]] = field(default_factory=list)  # (group, the run folder, as the kernel names it)
    alone: list[str] = field(default_factory=list)  # left alone, each with why
    record: Path | None = None
    notes: list[Path] = field(default_factory=list)  # they go with the record
    keep: bool = False  # its record stays: its containers could not be looked for


def sweep(runs: Path | None, *, docker: bool | None, clean: bool) -> Swept:
    """Find what runs whose flightdeck is gone left, in the run folders under `runs` and
    those the notes in open_runs() name, and (with `docker`) in Docker, and with `clean`
    remove it (see the module docstring). docker: True looks for containers, False does
    not, None only when such a run's record says it used Docker. Never raises for what it
    finds: every problem is a line."""
    reason = supported()
    if reason is not None:
        return Swept(alone=(f"what an earlier run left running cannot be checked here: {reason}",))
    found_runs, stale, alone = _runs_with_records(runs)
    gone: list[tuple[_Run, _Record]] = []
    for run in found_runs:
        record, problem = read_record(run.record)
        if record is None:
            alone.append(f"run {_show(run.name)}: its {RECORD} cannot be read ({_show(problem)}), so what it left cannot be "
                         f"checked; remove {_show(str(run.record))} once no flightdeck runs from that folder")
            continue
        if not record.owner.here():
            continue  # another machine's or another user's run
        state = record.owner.state()
        if state == _UNKNOWN:
            alone.append(f"run {_show(run.name)}: whether its flightdeck still runs cannot be told (its record has no start "
                         "time), so what it left was not touched")
        elif state == _GONE:
            gone.append((run, record))
    if clean:
        for note in stale:  # its run ended, or its folder is gone: nothing is left to find from it
            with contextlib.suppress(OSError):
                note.unlink()
    try:  # every group of every such run, in one look at this machine's processes
        live = processes_in(item.pgid for _, record in gone for item in record.groups)
    except Unsupported as exc:
        return Swept(alone=(*alone, f"what an earlier run left running cannot be checked here: {exc}"))
    found: dict[str, _Leftovers] = {}
    named: dict[tuple[str, Owner], str] = {}  # (a gone run's folder name, its flightdeck): its entry, for its containers
    look = docker is True
    for run, record in gone:
        entry = found.setdefault(run.name, _Leftovers(run.name))
        entry.record = run.record
        entry.notes += run.notes
        named[(run.record.parent.name, record.owner)] = run.name
        folder = _kernel_path(run.record.parent)
        for item in record.groups:
            verdict = _judge(item, folder, live.get(item.pgid, []))
            if verdict == "":
                entry.groups.append((item, folder))
            elif verdict != _GONE:
                entry.alone.append(f"{_describe(item, folder)} was left alone: {verdict}")
        if record.docker:
            if docker is False:
                entry.keep = True
                entry.alone.append("it ran lanes in Docker, which is not available now, so its containers were not looked for")
            else:
                look = True
    if look:
        mine, boxes, problem = "", [], ""
        nets: list[tuple[str, str, dict[str, str]]] = []
        try:
            mine = state_id()
        except OSError as exc:  # no state folder: whose containers are this setup's cannot be told
            problem = (f"the containers of runs that did not shut down were not looked for: "
                       f"{_show(str(exc.strerror or exc))}")
        else:
            boxes, problem = _containers()
            if not problem:
                nets, problem = _networks()
            if problem:
                boxes, nets = [], []  # one look that failed: nothing of Docker's is touched, and the next sweep looks again
                problem = (f"the containers of runs that did not shut down could not be looked for ({problem}); once Docker "
                           "runs, `flightdeck doctor --clean` removes them")
        if problem:
            alone.append(problem)
            for entry in found.values():
                if entry.record is not None and _says_docker(entry.record):
                    entry.keep = True
        for kind, things in (("container", boxes), ("network", nets)):
            for thing_id, name, thing_labels in things:
                owner = _owner(thing_labels.get(LABEL_HOST), thing_labels.get(LABEL_UID), thing_labels.get(LABEL_PID),
                               thing_labels.get(LABEL_STARTED))
                if owner is None or not owner.here() or thing_labels.get(LABEL_STATE) != mine:
                    continue  # not all of flightdeck's labels, or another machine's, user's or setup's (state folder's)
                state = owner.state()
                if state == _RUNNING:
                    continue
                run_name = named.get((thing_labels[LABEL_RUN], owner), thing_labels[LABEL_RUN])
                entry = found.setdefault(run_name, _Leftovers(run_name))
                if state == _UNKNOWN:
                    entry.alone.append(f"its {kind} {_show(name)} was left alone: its labels do not say when its "
                                       "flightdeck started")
                    continue
                (entry.containers if kind == "container" else entry.networks).append((thing_id, name))
    done_lines: list[str] = []
    found_lines: list[str] = []
    for run_name in sorted(found):
        entry = found[run_name]
        if clean:
            done, failed = _remove(entry)
            if done:
                done_lines.append(f"run {_show(run_name)} {NOT_SHUT_DOWN}; removed what it left running: {'; '.join(done)}")
        else:
            failed, items = [], _items(entry)
            if items:
                found_lines.append(f"run {_show(run_name)} {NOT_SHUT_DOWN} and left running: {'; '.join(items)}")
        alone += [f"run {_show(run_name)}: {text}" for text in [*failed, *entry.alone]]
        if clean and entry.record is not None and not (entry.keep or failed or entry.alone):  # else the next sweep looks again
            with contextlib.suppress(OSError):
                entry.record.unlink()
                for note in entry.notes:
                    note.unlink(missing_ok=True)
    return Swept(tuple(done_lines), tuple(found_lines), tuple(alone))


def _runs_with_records(runs: Path | None) -> tuple[list[_Run], list[Path], list[str]]:
    """The run folders with a record: those in `runs`, in name order, then those elsewhere
    that the notes in open_runs() name (each folder once, by its identity, whatever path
    led to it); the notes whose folder has no record (its run ended, or the folder is
    gone); and lines for what could not be read."""
    found: dict[tuple[int, int], _Run] = {}
    for folder in _run_folders(runs):
        key = _folder_id(folder)
        if key is not None and key not in found:
            found[key] = _Run(folder / RECORD, folder.name)
    notes, problems = _notes()
    stale: list[Path] = []
    for note, folder in notes:
        key = _folder_id(folder) if os.path.isfile(folder / RECORD) else None
        if key is None:
            stale.append(note)
            continue
        found.setdefault(key, _Run(folder / RECORD, str(folder))).notes.append(note)
    return list(found.values()), stale, problems


def _run_folders(runs: Path | None) -> list[Path]:
    """runs/<run folder> for each run folder that has a record."""
    if runs is None:
        return []
    try:
        folders = sorted(os.scandir(runs), key=lambda e: e.name)
    except OSError:
        return []
    return [Path(f.path) for f in folders if f.is_dir(follow_symlinks=False) and os.path.isfile(os.path.join(f.path, RECORD))]


def _folder_id(folder: Path) -> tuple[int, int] | None:
    """A folder's identity (device, inode), the same whatever path names it; None when it is
    not a folder (a symlink is not one)."""
    try:
        info = os.lstat(folder)
    except OSError:
        return None
    return (info.st_dev, info.st_ino) if stat.S_ISDIR(info.st_mode) else None


def _says_docker(path: Path) -> bool:
    record, _ = read_record(path)
    return record is not None and record.docker


def _judge(item: _Group, folder: str, live: list[Proc]) -> str:
    """"" when the group is still the run's (stop it), _GONE when nothing the run recorded in
    it is left, else why it is left alone. `live`: the processes in that group now."""
    if item.pgid == os.getpgrp():
        return "it is the process group of the flightdeck that is sweeping"
    if not live:
        return _GONE
    recorded = set(item.processes)
    known = [p for p in live if (p.pid, p.started) in recorded]
    if not known:  # the number may be another program's group now: never signalled
        strays = [p.pid for p in live if _under(working_folder(p.pid), folder)]
        if not strays:
            return _GONE
        return (f"none of the processes flightdeck recorded in it is left, and processes it did not record that work "
                f"in the run's folder are in a group of that number now ({_pids(strays)})")
    if not any(_under(working_folder(p.pid), folder) for p in known):
        return (f"the processes flightdeck recorded in it ({_pids([p.pid for p in known])}) run on, but no longer work in "
                f"a folder under the run's folder; if it is a leftover, stop it yourself (kill -KILL -- -{item.pgid})")
    return ""


def _pids(pids: list[int]) -> str:
    shown = ", ".join(str(pid) for pid in pids[:SHOWN_PIDS])
    return f"pid {shown}" + (f" and {len(pids) - SHOWN_PIDS} more" if len(pids) > SHOWN_PIDS else "")


def _under(path: str | None, folder: str) -> bool:
    """Whether `path` is `folder` or in it (both as the kernel names them: no symlinks)."""
    if not path:
        return False
    path, folder = os.path.normpath(path), os.path.normpath(folder)
    return path == folder or path.startswith(folder.rstrip(os.sep) + os.sep)


def _describe(item: _Group, folder: str) -> str:
    where = item.folder
    if os.path.isabs(where):
        real = _kernel_path(where)
        if _under(real, folder):
            where = os.path.relpath(real, folder)
    return f"process group {item.pgid} ({_show(item.what)} in {_show(where)})"


def _items(entry: _Leftovers) -> list[str]:
    return ([f"its container {_show(name)}" for _, name in entry.containers]
            + [f"its network {_show(name)}" for _, name in entry.networks]
            + [f"its {_describe(item, folder)}" for item, folder in entry.groups])


def _remove(entry: _Leftovers) -> tuple[list[str], list[str]]:
    """(what was removed or stopped, what could not be, with why)."""
    done: list[str] = []
    failed: list[str] = []
    for box_id, name in entry.containers:
        problem = _remove_container(box_id)
        if problem:
            failed.append(f"its container {_show(name)} could not be removed: {problem}")
        else:
            done.append(f"its container {_show(name)}")
    for net_id, name in entry.networks:  # after the containers: docker removes no network a container is on
        problem = _remove_network(net_id)
        if problem:
            failed.append(f"its network {_show(name)} could not be removed: {problem}")
        else:
            done.append(f"its network {_show(name)}")
    for item, folder in entry.groups:
        try:
            live = group(item.pgid)
        except Unsupported as exc:
            entry.alone.append(f"{_describe(item, folder)} was left alone: {exc}")
            continue
        verdict = _judge(item, folder, live)  # checked again right before: it may have ended since
        if verdict == _GONE:
            continue
        if verdict:
            entry.alone.append(f"{_describe(item, folder)} was left alone: {verdict}")
            continue
        try:
            os.killpg(item.pgid, signal.SIGKILL)
        except ProcessLookupError:
            continue
        except OSError as exc:
            failed.append(f"its {_describe(item, folder)} could not be stopped: {exc.strerror or exc}")
            continue
        done.append(f"its {_describe(item, folder)}")
    return done, failed


# ---------------------------------------------------------------- containers

_FORMAT = "\t".join(["{{.ID}}", "{{.Names}}", *(f'{{{{.Label "{name}"}}}}' for name in LABELS)])
_NETWORK_FORMAT = _FORMAT.replace("{{.Names}}", "{{.Name}}")


def _docker(*args: str) -> tuple[int, str]:
    docker = shutil.which("docker")
    if docker is None:
        raise OSError(errno.ENOENT, "docker not found on PATH")
    try:
        done = subprocess.run([docker, *args], stdin=subprocess.DEVNULL, capture_output=True, timeout=DOCKER_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise OSError(errno.ETIMEDOUT, f"docker {args[0]} did not finish within {DOCKER_TIMEOUT:g} s") from None
    return done.returncode, (done.stdout + done.stderr).decode("utf-8", "replace")


def _containers() -> tuple[list[tuple[str, str, dict[str, str]]], str]:
    """([(id, name, flightdeck's labels)] of every container with the run label, running or
    not), or ([], why they could not be listed)."""
    return _listed("ps", "-a", "--no-trunc", "--filter", f"label={LABEL_RUN}", "--format", _FORMAT)


def _networks() -> tuple[list[tuple[str, str, dict[str, str]]], str]:
    """([(id, name, flightdeck's labels)] of every Docker network with the run label: a fenced
    lane's, agent/egress.py), or ([], why they could not be listed)."""
    return _listed("network", "ls", "--no-trunc", "--filter", f"label={LABEL_RUN}", "--format", _NETWORK_FORMAT)


def _listed(*args: str) -> tuple[list[tuple[str, str, dict[str, str]]], str]:
    try:
        code, out = _docker(*args)
    except OSError as exc:
        return [], _show(str(exc.strerror or exc))
    if code != 0:
        first = next((line.strip() for line in out.splitlines() if line.strip()), f"docker {args[0]} exited {code}")
        return [], _show(first)[:300]
    boxes = []
    for line in out.splitlines():
        fields = line.split("\t")
        if len(fields) != 2 + len(LABELS) or not _CONTAINER_ID.fullmatch(fields[0]) or not fields[2]:
            continue  # not a line this format makes: never a container to touch
        boxes.append((fields[0], fields[1], dict(zip(LABELS, fields[2:]))))
    return boxes, ""


def _remove_container(box_id: str) -> str:
    """"" when the container is gone or going (removed now, already, or by docker itself),
    else why not."""
    try:
        code, out = _docker("rm", "-f", box_id)
    except OSError as exc:
        return _show(str(exc.strerror or exc))
    if code == 0 or "No such container" in out or "already in progress" in out:
        return ""
    first = next((line.strip() for line in out.splitlines() if line.strip()), f"docker rm exited {code}")
    return _show(first)[:300]


def _remove_network(net_id: str) -> str:
    """"" when the network is gone (removed now, or already), else why not."""
    try:
        code, out = _docker("network", "rm", net_id)
    except OSError as exc:
        return _show(str(exc.strerror or exc))
    if code == 0 or "No such network" in out or "not found" in out:
        return ""
    first = next((line.strip() for line in out.splitlines() if line.strip()), f"docker network rm exited {code}")
    return _show(first)[:300]


def _show(text: str) -> str:
    return untrusted(text, one_line=True)
