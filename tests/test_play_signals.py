"""`flightdeck play` when its terminal goes away or it gets SIGTERM: every lane stops and every
workspace closes, as when the player quits, and the run log gets its run-end line.

Each play test starts the real command in a session of its own on a pty, the way a terminal
window runs it (flightdeck is the session leader: closing the pty's master side is closing the
window, and the system sends it SIGHUP). Lanes ask the fake model server on 127.0.0.1, which
answers with one quiet shell command that would run for minutes. The docker test runs only when
docker answers and debian:bookworm-slim is already on this machine (tests never pull, and use
no other image); otherwise it reports as not run. Whatever a test starts is removed at the end,
even when it fails.

The console's terminal driver is tested on its own too: once its output thread has died on a
dead terminal, no write may wait for it (Textual's queue holds 30 writes; the 31st would block
the console's event loop, and with it the stopping of every lane).
"""

from __future__ import annotations

import asyncio
import errno
import fcntl
import io
import json
import os
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import threading
import time
from pathlib import Path

import pytest
from textual.drivers._writer_thread import MAX_QUEUED_WRITES, WriterThread

from ctf_flightdeck.agent.workspace import docker_unavailable
from ctf_flightdeck.console.app import FlightdeckApp
from ctf_flightdeck.console.terminal import TerminalDriver
from ctf_flightdeck.mock import scenarios
from ctf_flightdeck.mock.world import FakeWorld

from fake_model import FakeModelServer, tool_call_reply
from l1_kit import docker_not_run

IMAGE = "debian:bookworm-slim"
QUIET = "echo $$ > lane-pid.txt; sleep 240"  # the lane's command: prints nothing for minutes
# Makes the pty this session's controlling terminal, then becomes flightdeck (same process).
LAUNCH = (
    "import fcntl, os, sys, termios\n"
    "fcntl.ioctl(0, termios.TIOCSCTTY, 0)\n"
    "os.execv(sys.executable, [sys.executable, '-m', 'ctf_flightdeck', *sys.argv[1:]])\n"
)


class Terminal:
    """A pty with one program on it, as in a terminal window; its output is read and kept."""

    def __init__(self, argv: list[str], env: dict[str, str], cwd: Path, *, launch: str = LAUNCH) -> None:
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 46, 160, 0, 0))
        self.master: int | None = master
        self.seen = bytearray()
        self._stop = threading.Event()
        try:
            self.proc = subprocess.Popen(
                [sys.executable, "-c", launch, *argv], stdin=slave, stdout=slave, stderr=slave,
                env=env, cwd=cwd, start_new_session=True,
            )
        finally:
            os.close(slave)
        self._reader = threading.Thread(target=self._read, name="test-terminal", daemon=True)
        self._reader.start()

    def _read(self) -> None:
        while not self._stop.is_set():
            ready, _, _ = select.select([self.master], [], [], 0.05)
            if not ready:
                continue
            try:
                chunk = os.read(self.master, 65536)
            except OSError:
                return
            if not chunk:
                return
            self.seen.extend(chunk)

    def hang_up(self) -> None:
        """Close the window: the master side goes away."""
        self._stop.set()
        self._reader.join()
        if self.master is not None:
            os.close(self.master)
            self.master = None

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        self.hang_up()

    def text(self) -> str:
        return self.seen.decode("utf-8", "replace")


def env_for(tmp_path: Path, **extra: str) -> dict[str, str]:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "FLIGHTDECK_KEYS": str(tmp_path / "no-keys.env"),  # never the player's keys file
        "TERM": "xterm-256color",
        "LANG": "en_US.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        **extra,
    }


def make_board(tmp_path: Path) -> Path:
    root = tmp_path / "board"
    folder = root / "note"
    folder.mkdir(parents=True)
    (folder / "note.txt").write_text("nothing here\n")
    (folder / "challenge.json").write_text(json.dumps({"name": "Note", "category": "misc", "points": 50}))
    (root / "board.json").write_text(json.dumps({"event": "Signals", "flag_format": r"t\{[a-z0-9_]+\}"}))
    return root


def make_config(tmp_path: Path, base_url: str, runtime: str = "host") -> Path:
    path = tmp_path / "config.toml"
    path.write_text(
        f'[api]\nbase_url = "{base_url}"\nkey_env = ""\n'
        '[models]\nladder = ["fake/small", "fake/big"]\n'
        f'[lanes]\nmax_lanes = 1\nruntime = "{runtime}"\nimage = "{IMAGE}"\n'
        f'[run]\ndir = "{tmp_path / "runs"}"\n'
    )
    return path


def wait_for(cond, what: str, term: Terminal, timeout: float = 60.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = cond()
        if value:
            return value
        if term.proc.poll() is not None:
            break
        time.sleep(0.1)
    raise AssertionError(f"{what}: not seen (flightdeck exit {term.proc.poll()}); the terminal showed:\n{term.text()[-3000:]}")


def lane_pid_file(tmp_path: Path) -> Path | None:
    found = sorted((tmp_path / "runs").glob("*/**/lane-pid.txt"))
    return found[0] if found and found[0].read_text().strip() else None


def group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def gone(check, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not check():
            return True
        time.sleep(0.1)
    return False


def run_end(tmp_path: Path) -> list[str]:
    (log,) = (tmp_path / "runs").glob("*/events.jsonl")
    return [json.loads(line)["kind"] for line in log.read_text().splitlines() if line.strip()]


def stop(term: Terminal, how: str) -> int:
    """Send the signal (or close the window); the signal flightdeck gets."""
    if how == "hangup":
        term.hang_up()
        return signal.SIGHUP
    os.kill(term.proc.pid, signal.SIGTERM)
    return signal.SIGTERM


@pytest.mark.parametrize("how", ["sigterm", "hangup"])
def test_a_sigterm_or_closing_the_terminal_stops_a_host_lane_and_ends_the_run_log(tmp_path, how):
    with FakeModelServer([tool_call_reply("shell", {"command": QUIET, "timeout_seconds": 300})]) as server:
        cfg = make_config(tmp_path, server.base_url)
        term = Terminal(["play", str(make_board(tmp_path)), "--config", str(cfg)], env_for(tmp_path), tmp_path)
        pgid = None
        try:
            pid_file = wait_for(lambda: lane_pid_file(tmp_path), "the lane's command", term)
            pgid = int(pid_file.read_text())  # the command's shell leads its own process group
            assert group_alive(pgid)
            sig = stop(term, how)
            status = term.proc.wait(timeout=60)
            assert status == 128 + sig, f"flightdeck ended with {status}; the terminal showed:\n{term.text()[-3000:]}"
            assert gone(lambda: group_alive(pgid)), "the lane's command outlived flightdeck"
            assert run_end(tmp_path)[-1] == "run-end"
        finally:
            term.close()
            if pgid is not None and group_alive(pgid):
                os.killpg(pgid, signal.SIGKILL)


def _docker_missing() -> str | None:
    reason = docker_unavailable()
    if reason:
        return reason
    found = subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, check=False)
    return None if found.returncode == 0 else f"{IMAGE} is not on this machine (tests never pull)"


def container_exists(name: str) -> bool:
    return subprocess.run(["docker", "container", "inspect", name], capture_output=True, check=False).returncode == 0


@pytest.mark.parametrize("how", ["sigterm", "hangup"])
def test_a_sigterm_or_closing_the_terminal_removes_a_docker_lanes_container(tmp_path, how):
    missing = _docker_missing()
    if missing:
        docker_not_run(f"not run: needs docker and {IMAGE}: {missing}")
    with FakeModelServer([tool_call_reply("shell", {"command": QUIET, "timeout_seconds": 300})]) as server:
        cfg = make_config(tmp_path, server.base_url, runtime="docker")
        term = Terminal(["play", str(make_board(tmp_path)), "--config", str(cfg)], env_for(tmp_path), tmp_path)
        name = None
        try:
            wait_for(lambda: lane_pid_file(tmp_path), "the lane's command in its container", term, timeout=120)
            (run_dir,) = (tmp_path / "runs").iterdir()
            name = f"flightdeck-{run_dir.name}-l01"
            assert container_exists(name)
            sig = stop(term, how)
            status = term.proc.wait(timeout=90)
            assert status == 128 + sig, f"flightdeck ended with {status}; the terminal showed:\n{term.text()[-3000:]}"
            assert not container_exists(name), "the lane's container outlived flightdeck"
            assert run_end(tmp_path)[-1] == "run-end"
        finally:
            term.close()
            if name is not None and container_exists(name):
                subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)


FAKE_CLI = Path(__file__).resolve().parent / "fake_agent_cli.py"


def test_closing_the_terminal_ends_a_coding_agent_cli_frozen_while_its_flag_waits(tmp_path):
    """The lane found a flag and waits for the player, so its CLI is stopped (SIGSTOP): it must
    not stay stopped forever once flightdeck is gone."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script, record = tmp_path / "script.json", tmp_path / "record.jsonl"
    script.write_text(json.dumps({"turns": [{"calls": [{"text": "found it: t{probe_flag}"}], "result": "found it: t{probe_flag}"}]}))
    fake_env = {"FAKE_AGENT_SCRIPT": str(script), "FAKE_AGENT_RECORD": str(record), "FAKE_AGENT_STATE": str(tmp_path / "state.json")}
    wrapper = bin_dir / "claude"
    wrapper.write_text(
        f"#!{sys.executable} -I\nimport os, sys\nos.environ.update({fake_env!r})\n"
        f"os.execv(sys.executable, [sys.executable, '-I', {str(FAKE_CLI)!r}, 'claude', *sys.argv[1:]])\n"
    )
    wrapper.chmod(0o755)
    cfg = make_config(tmp_path, "http://127.0.0.1:9/v1")  # never asked: lanes are the CLI
    env = env_for(tmp_path, PATH=f"{bin_dir}:/usr/bin:/bin", ANTHROPIC_API_KEY="dummy-credential-for-the-fake-cli")
    term = Terminal(["play", str(make_board(tmp_path)), "--config", str(cfg), "--host", "--agent", "claude"], env, tmp_path)
    cli = None
    try:
        def frozen_cli() -> int | None:
            starts = [json.loads(line) for line in record.read_text().splitlines()] if record.exists() else []
            pids = [r["pid"] for r in starts if r.get("rec") == "start"]
            if not pids:
                return None
            state = subprocess.run(["ps", "-o", "stat=", "-p", str(pids[0])], capture_output=True, text=True).stdout.strip()
            return pids[0] if state.startswith("T") else None

        cli = wait_for(frozen_cli, "the CLI frozen while its flag waits", term)
        sig = stop(term, "hangup")
        status = term.proc.wait(timeout=60)
        assert status == 128 + sig, f"flightdeck ended with {status}; the terminal showed:\n{term.text()[-3000:]}"
        assert gone(lambda: _alive(cli)), "the frozen CLI outlived flightdeck"
        assert run_end(tmp_path)[-1] == "run-end"
    finally:
        term.close()
        if cli is not None and _alive(cli):
            os.kill(cli, signal.SIGKILL)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    return bool(state) and not state.startswith("Z")


# ---------------------------------------------------------------------- the terminal driver


class GoneTerminal(io.TextIOBase):
    """Stands for a terminal that hung up: every write fails with EIO. With `hold`, a write
    first waits for it (a slow terminal, until it goes)."""

    def __init__(self, hold: threading.Event | None = None) -> None:
        self.hold = hold
        self.started = threading.Event()

    def write(self, text: str) -> int:
        self.started.set()
        if self.hold is not None:
            self.hold.wait()
        raise OSError(errno.EIO, "Input/output error")

    def flush(self) -> None:
        pass


@pytest.fixture
def driver_on(request):
    """A TerminalDriver whose output thread writes to `terminal`, made on a running loop (as
    Textual makes it). Its constructor sets SIGTSTP and SIGCONT handlers: put back afterwards."""
    saved = {sig: signal.getsignal(sig) for sig in (signal.SIGTSTP, signal.SIGCONT)}

    def make(terminal: io.TextIOBase) -> TerminalDriver:
        async def build() -> TerminalDriver:
            return TerminalDriver(None, mouse=False)  # the app is not needed to write

        driver = asyncio.run(build())
        driver._writer_thread = WriterThread(terminal)
        driver._writer_thread.start()
        return driver

    yield make
    for sig, handler in saved.items():
        signal.signal(sig, handler)


# The output thread dying of EIO is what these tests set up, so pytest's report of it is expected.
output_dies = pytest.mark.filterwarnings("ignore:Exception in thread textual-output:pytest.PytestUnhandledThreadExceptionWarning")


def in_thread(work) -> threading.Event:
    """Run `work` on a thread of its own; the event is set when it returns (never, if it hangs)."""
    done = threading.Event()

    def run() -> None:
        work()
        done.set()

    threading.Thread(target=run, daemon=True).start()
    return done


@output_dies
def test_once_the_output_thread_has_died_writes_and_close_return_at_once(driver_on):
    driver = driver_on(GoneTerminal())
    driver.write("frame 0")  # the terminal is gone: the output thread dies on it
    driver._writer_thread.join(5)
    assert not driver._writer_thread.is_alive()

    def draw() -> None:
        for n in range(1, 3 * MAX_QUEUED_WRITES):
            driver.write(f"frame {n}")
        driver.close()

    assert in_thread(draw).wait(5), "a write waited on the dead output thread"


@output_dies
def test_a_write_waiting_for_room_gives_up_when_the_output_thread_dies(driver_on):
    """A slow terminal fills the queue (a write then waits, as Textual's does); the terminal
    then goes, and the output thread dies with its queue full: the waiting write returns."""
    hold = threading.Event()
    terminal = GoneTerminal(hold)
    driver = driver_on(terminal)
    try:
        driver.write("frame 0")
        assert terminal.started.wait(5)  # the thread took it and is stuck writing it
        for n in range(1, MAX_QUEUED_WRITES + 1):
            driver.write(f"frame {n}")  # the queue is full now
        waiting = in_thread(lambda: driver.write("one too many"))
        assert not waiting.wait(0.6)  # it waits for room while the terminal is only slow
        hold.set()  # the terminal goes: the thread's write fails and the thread dies
        assert waiting.wait(5), "the write still waits on the dead output thread's full queue"
        assert in_thread(driver.close).wait(5), "close waited on the dead output thread"
    finally:
        hold.set()


def test_the_console_on_a_terminal_uses_the_driver_that_never_waits_on_a_dead_terminal(monkeypatch):
    monkeypatch.delenv("TEXTUAL_DRIVER", raising=False)
    world = FakeWorld(scenarios.get("sstv"))
    assert FlightdeckApp(world.deck).driver_class is TerminalDriver


# A console whose terminal hangs up and that hears of it late, the way a job hears it from its
# shell: by then its output thread has died. It keeps drawing (a status line 50 times a
# second), and its run takes a while to stop and draws all the way: far more than 30 writes.
LATE_APP = r"""
import asyncio, sys, time
from pathlib import Path
from ctf_flightdeck.console.app import FlightdeckApp
from ctf_flightdeck.mock import scenarios
from ctf_flightdeck.mock.world import FakeWorld

out = Path(sys.argv[1])


class Busy(FlightdeckApp):
    def on_mount(self):
        super().on_mount()
        self.set_interval(0.02, self.busy)

    def busy(self):
        self.say(f"busy {time.monotonic():.3f}")
        if not self._driver._writer_thread.is_alive() and not (out / "output-dead").exists():
            (out / "output-dead").write_text("")


async def stop_the_run():
    (out / "stopping").write_text("")
    for n in range(100):
        app.say(f"stopping {n}")
        await asyncio.sleep(0.02)
    (out / "stopped").write_text("")


app = Busy(FakeWorld(scenarios.get("sstv")).deck, refresh_seconds=0.05,
           on_start=lambda: (out / "up").write_text(""), on_exit=stop_the_run)
app.run()
(out / "exited").write_text(app.stopped_by.name if app.stopped_by else "-")
"""

# The session leader stands for the player's shell: it outlives the hang-up and passes nothing
# on; the console is its child, in the foreground, and hears SIGHUP only when the test sends it.
LATE_LAUNCH = (
    "import fcntl, os, signal, sys, termios\n"
    "fcntl.ioctl(0, termios.TIOCSCTTY, 0)\n"
    "signal.signal(signal.SIGHUP, signal.SIG_IGN)\n"
    "pid = os.fork()\n"
    "if pid == 0:\n"
    "    signal.signal(signal.SIGHUP, signal.SIG_DFL)\n"
    "    os.execv(sys.executable, [sys.executable, *sys.argv[1:]])\n"
    "open(os.environ['CONSOLE_PID'], 'w').write(str(pid))\n"
    "_, status = os.waitpid(pid, 0)\n"
    "os._exit(os.waitstatus_to_exitcode(status) % 256)\n"
)


def test_a_console_that_hears_of_the_hang_up_after_its_output_died_still_stops_the_run(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    app_file = tmp_path / "late_app.py"
    app_file.write_text(LATE_APP)
    pid_file = tmp_path / "console.pid"
    term = Terminal([str(app_file), str(out)], env_for(tmp_path, CONSOLE_PID=str(pid_file)), tmp_path, launch=LATE_LAUNCH)
    pid = None
    try:
        wait_for(lambda: (out / "up").exists() and pid_file.exists() and pid_file.read_text(), "the console", term, timeout=30)
        pid = int(pid_file.read_text())
        term.hang_up()
        deadline = time.monotonic() + 10
        while not (out / "output-dead").exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert (out / "output-dead").exists(), "the console's output thread did not die on the dead terminal"
        time.sleep(1.0)  # it keeps drawing meanwhile: more than 30 writes after its output died
        os.kill(pid, signal.SIGHUP)  # as its shell would pass it on, late
        status = term.proc.wait(timeout=30)
        assert (out / "stopped").exists(), "the run was not stopped"
        assert (out / "exited").read_text() == "SIGHUP" and status == 0
    finally:
        if pid is not None and _alive(pid):
            os.kill(pid, signal.SIGKILL)
        term.close()
