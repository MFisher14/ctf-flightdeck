"""Sessions: long-lived processes a lane's model talks to across turns (P82).

The shell tool starts a fresh bash for each call, so a debugger, an interpreter or a
connection to the challenge's instance lasts one call. A session lasts until the lane closes
it: session_start starts a command in the lane's workspace (agent/workspace.py's
open_session: bash in the workspace on the host, a `docker exec -i` of its own in the lane's
container), session_send writes to its input and reads what it wrote, and session_close kills
it and everything it started.

The process gets pipes, not a terminal, so a program that asks whether it has one acts as if
it were scripted: it may show no prompt, or hold its output in a buffer (python3 does both
unless started as python3 -u -i). That is what keeps its output plain text: no echo of what was sent, no
escape sequences of a line editor. A session started with `terminal` (P87) runs on a pty
instead (agent/terminal.py: no controlling terminal, TERM=dumb, no echo), and its escapes and
carriage returns are taken out as it is read, before it is stored, so what is stored is plain
text either way.

Limits, so that a lane cannot leave its processes running or fill memory: at most
MAX_SESSIONS open at once; a session nobody sent to or read for IDLE_SECONDS is closed (and
the lane hears why when it next names it); at most BUFFER_BYTES of output waits between
reads, the oldest dropped first and the drop counted; and a read waits at most MAX_WAIT
seconds. Every session is closed when the lane ends and when the player takes it over
(agent/driver.py), and the workspace's own close kills what is left (a host process group, a
docker client; the container's removal ends the rest).

Everything a session writes is the challenge's, as any tool output is: the Toolbox takes the
run's secrets out of it before anything cuts it and fences it like the shell's output. A few
bytes at the end of a read that could be the start of a secret wait for the next read (or the
process's end), so a secret written across two reads is still found whole. The read says how
many it held; a read that sees no more output after them releases them (a prompt that ends
without a newline, say), and a read that matched `until` shows the match whole. What such a
read showed that could start a secret is scrubbed again with the next read's output, so the
rest of the secret is still found; and the oldest bytes dropped from a full buffer never end
partway into a secret.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass

from .terminal import TerminalText
from .workspace import SessionProcess

MAX_SESSIONS = 3
IDLE_SECONDS = 600.0  # unused this long, a session is closed
BUFFER_BYTES = 1024 * 1024  # output kept between reads; older bytes are dropped first
INPUT_BYTES = 64 * 1024  # the most one send writes
DEFAULT_WAIT = 2.0
MAX_WAIT = 60.0
QUIET = 0.5  # seconds without output, after some came, that end a read with no `until`
SEND_TIMEOUT = 10.0  # seconds a write may wait for a process that is not reading its input
END_WAIT = 2.0  # seconds a read that saw the output end waits for the process's exit status
HEAD_BYTES = 256  # the most the workspace's first line (SessionProcess.marker) may take


class SessionMistake(Exception):
    """Something the model asked of a session that cannot be done: an unknown name, too many
    open, a process that no longer reads. It becomes the tool's error result."""


@dataclass(frozen=True)
class Read:
    """What one read of a session gave."""

    output: bytes
    dropped: int  # bytes dropped before this read because more than BUFFER_BYTES waited
    why: str  # how the read ended: "matched", "quiet", "waited", "ended"
    waited: float  # seconds the read waited
    exit_code: int | None = None  # why == "ended": the process's status, None when it is not known
    held: int = 0  # bytes at the end held back for the next read: they may start a secret
    carried: bytes = b""  # the end of the last read's output that may start a secret: scrubbed with this one, not shown again


class Session:
    """One long-lived process and the output it has written that nobody has read yet."""

    def __init__(self, name: str, command: str, process: SessionProcess, *, cap: int = BUFFER_BYTES,
                 unfinished: Callable[[bytes], int] | None = None, terminal: bool = False) -> None:
        self.name = name
        self.command = command
        self.process = process
        self.terminal = terminal  # it runs on a pty (agent/terminal.py): its escapes come out before it is stored
        self._text = TerminalText() if terminal else None
        self.cap = cap
        self.unfinished = unfinished  # bytes at the end of a read that may start a secret: held for the next
        self.pid: int | None = None  # where it runs, when the workspace says (process.marker)
        self.buffer = bytearray()
        self.dropped = 0
        self.eof = False
        self.busy = False  # a send or a read is under way: the idle timer waits
        self.held = 0  # bytes at the buffer's start the last read held back (unfinished): not news to the next
        self.added = 0  # bytes ever stored (dropped ones too): with _mark, what came after the last send
        self._mark = 0  # `added` when the last send began: what came before it is no reply to it
        self.carry = b""  # the end of what was shown that could start a secret: scrubbed again with what follows
        self._head: bytearray | None = bytearray() if process.marker else None
        self._changed = asyncio.Event()
        self._last = 0.0  # loop time of the last output
        self._reader = asyncio.ensure_future(self._read_all())

    @property
    def ended(self) -> bool:
        return self.eof and self.process.proc.returncode is not None

    async def _read_all(self) -> None:
        stream = self.process.proc.stdout
        assert stream is not None
        try:
            while chunk := await stream.read(64 * 1024):
                if self._head is not None:
                    chunk = self._take_head(chunk)
                self._add(self._plain(chunk))
        except (OSError, ValueError):
            pass  # the pipe broke: the same as its end
        finally:
            if self._head:  # the first line never came whole: it is output (docker's own error, say)
                self._add(self._plain(bytes(self._head)))
            self._head = None
            if self._text is not None:
                self._add(self._text.flush())
            self.eof = True
            self._changed.set()

    def _take_head(self, chunk: bytes) -> bytes:
        """The workspace's first line off the output, its pid kept; b"" until that line is whole."""
        assert self._head is not None
        self._head += chunk
        if b"\n" not in self._head and len(self._head) < HEAD_BYTES:
            return b""
        line, newline, rest = bytes(self._head).partition(b"\n")
        self._head = None
        marker = self.process.marker.encode()
        number = line[len(marker):].strip()
        if newline and line.startswith(marker) and number.isdigit():
            self.pid = int(number)
            return rest
        return line + newline + rest

    def _plain(self, chunk: bytes) -> bytes:
        """`chunk` as it is stored: a terminal session's with its escapes taken out."""
        return chunk if self._text is None else self._text.feed(chunk)

    def _add(self, data: bytes) -> None:
        if not data:
            return
        self.buffer += data
        self.added += len(data)
        over = len(self.buffer) - self.cap
        if over > 0 and self.unfinished is not None:
            # a secret the cut would split is kept whole, so that the scrubber finds it: the
            # buffer may then pass the cap by less than a secret's length
            over -= self.unfinished(bytes(self.buffer[:over]))
        if over > 0:
            del self.buffer[:over]
            self.dropped += over
            self.held = max(0, self.held - over)
        self._last = asyncio.get_running_loop().time()
        self._changed.set()

    async def send(self, data: bytes) -> None:
        """Write `data` to the process's input. SessionMistake when it no longer reads it."""
        stdin = self.process.proc.stdin
        if stdin is None or self.process.proc.returncode is not None or stdin.is_closing():
            raise SessionMistake(f"session {self.name} has ended; read what it wrote with session_send and no input")
        self._mark = self.added  # what it wrote before this is no reply to it: it ends no read
        try:
            stdin.write(data)
            await asyncio.wait_for(stdin.drain(), SEND_TIMEOUT)
        except (BrokenPipeError, ConnectionResetError):
            raise SessionMistake(f"session {self.name} no longer reads its input (it closed it, or ended)") from None
        except TimeoutError:
            raise SessionMistake(f"session {self.name} took none of the input for {SEND_TIMEOUT:g} s: it is not reading it; "
                                 "read its output, or close it") from None

    async def read(self, wait: float, until: bytes | None = None) -> Read:
        """What the process wrote, after waiting at most `wait` seconds: until `until` is in the
        output, until it has been quiet for QUIET seconds after writing something (with no
        `until`), or until its output ends. Only output written since the last send ends the
        read: what came before it is shown too, but a reply is waited for. `carried` in the
        result is the end of the last read's output that could start a secret: the caller
        scrubs it with this output, so a secret cut between two reads is still found."""
        loop = asyncio.get_running_loop()
        begun = loop.time()
        end = begun + wait
        why = "waited"
        found = -1
        while True:
            now = loop.time()
            since = self.added - self._mark  # bytes written since the last send
            news = min(since, len(self.buffer) - self.held) > 0  # what is held back is no reason to stop
            if until is not None:
                found = self.buffer.find(until, max(0, len(self.buffer) - since - len(until) + 1))
                if found >= 0:
                    why = "matched"
                    break
            if self.eof:
                why = "ended"
                break
            if now >= end:
                break
            if until is None and news and now - self._last >= QUIET:
                why = "quiet"
                break
            timeout = end - now
            if until is None and news:
                timeout = min(timeout, QUIET - (now - self._last))
            self._changed.clear()
            try:
                await asyncio.wait_for(self._changed.wait(), max(timeout, 0.01))
            except TimeoutError:
                pass
        code = None
        if why == "ended":
            try:
                code = await asyncio.wait_for(self.process.proc.wait(), END_WAIT)
            except TimeoutError:
                code = None
        keep = 0
        if why != "ended" and self.unfinished is not None and len(self.buffer) > self.held:
            # held back only while output is still coming: a tail the last read held, with nothing
            # after it since (a prompt with no newline, say), is released, so nothing waits for good
            keep = self.unfinished(bytes(self.buffer))
            if why == "matched" and until is not None:  # what matched is shown whole
                keep = min(keep, len(self.buffer) - found - len(until))
        output = bytes(self.buffer[: len(self.buffer) - keep])
        del self.buffer[: len(output)]
        self.held = len(self.buffer)
        dropped, self.dropped = self.dropped, 0
        carried = self.carry
        if output:
            self.carry = self.tail(carried + output)
        return Read(output, dropped, why, loop.time() - begun, code, held=self.held, carried=carried if output else b"")

    def tail(self, shown: bytes) -> bytes:
        """The end of `shown` that could start a secret: what a released hold or a matched
        `until` showed of one. The next output is scrubbed together with it."""
        if self.unfinished is None or not shown:
            return b""
        size = self.unfinished(shown)
        return shown[len(shown) - size:] if size else b""

    async def stop(self) -> None:
        """Kill the process and everything it started; never raises."""
        try:
            await self.process.stop(self.pid)
        except Exception:
            pass  # the workspace's close kills what is left
        try:
            await asyncio.wait_for(self._reader, END_WAIT)
        except (TimeoutError, Exception):
            self._reader.cancel()


class Sessions:
    """A lane's sessions: started, found by name, closed, and closed when unused.

    `open` starts a process (a workspace's open_session). Names are s1, s2, ... and never
    reused in a lane, so a name the model kept from an earlier turn means that session or
    none: one that is gone answers why (`gone`)."""

    def __init__(self, open: Callable, *, limit: int = MAX_SESSIONS, idle: float = IDLE_SECONDS,
                 cap: int = BUFFER_BYTES, unfinished: Callable[[bytes], int] | None = None) -> None:
        if limit < 1 or idle <= 0 or cap < 1:
            raise ValueError(f"need limit >= 1, idle > 0 and cap >= 1, got {limit}, {idle} and {cap}")
        self._open = open
        self.limit = limit
        self.idle = idle
        self.cap = cap
        self.unfinished = unfinished
        self.open: dict[str, Session] = {}
        self.gone: dict[str, str] = {}  # name -> why it is gone
        self._count = 0
        self._timers: dict[str, asyncio.TimerHandle] = {}
        self._closing: set[asyncio.Task] = set()

    async def start(self, command: str, *, terminal: bool = False) -> Session:
        """A new session running `command`; with `terminal`, on a pty (the workspace's
        open_session(command, terminal=True))."""
        if len(self.open) >= self.limit:
            listed = ", ".join(f"{s.name} ({'ended' if s.eof else 'running'}: {_short(s.command)})" for s in self.open.values())
            raise SessionMistake(f"{self.limit} sessions are open already ({listed}); close one with session_close first")
        process = await (self._open(command, terminal=True) if terminal else self._open(command))
        self._count += 1
        session = Session(f"s{self._count}", command, process, cap=self.cap, unfinished=self.unfinished, terminal=terminal)
        self.open[session.name] = session
        self.touch(session)
        return session

    def get(self, name: str) -> Session:
        session = self.open.get(name)
        if session is not None:
            return session
        if name in self.gone:
            raise SessionMistake(f"session {name} is gone: {self.gone[name]}")
        listed = ", ".join(self.open) or "none"
        raise SessionMistake(f"no session named {_short(name)}; open now: {listed}")

    def touch(self, session: Session) -> None:
        """The session was used now: its idle time starts again."""
        timer = self._timers.pop(session.name, None)
        if timer is not None:
            timer.cancel()
        self._timers[session.name] = asyncio.get_running_loop().call_later(self.idle, self._expire, session.name)

    def _expire(self, name: str) -> None:
        session = self.open.get(name)
        if session is None:
            return
        if session.busy:  # a read is under way: idle is counted from its end
            self.touch(session)
            return
        task = asyncio.ensure_future(self.close(name, f"it was closed after {self.idle:g} s unused"))
        self._closing.add(task)
        task.add_done_callback(self._closing.discard)

    async def close(self, name: str, why: str) -> Session | None:
        """Close the session `name` (the process and everything it started) and remember why;
        the session, or None when none is open by that name."""
        session = self.open.pop(name, None)
        if session is None:
            return None
        timer = self._timers.pop(name, None)
        if timer is not None:
            timer.cancel()
        self.gone[name] = why
        await session.stop()
        return session

    def ended(self, session: Session, code: int | None) -> None:
        """A read saw the session's end: it is no longer open."""
        status = "it ended" + (f" (exit {code})" if code is not None else "")
        self.open.pop(session.name, None)
        timer = self._timers.pop(session.name, None)
        if timer is not None:
            timer.cancel()
        self.gone[session.name] = status
        task = asyncio.ensure_future(session.stop())  # collects the reader and the process
        self._closing.add(task)
        task.add_done_callback(self._closing.discard)

    async def close_all(self, why: str) -> list[str]:
        """Close every open session; the names of those that were open."""
        names = list(self.open)
        for name in names:
            await self.close(name, why)
        if self._closing:
            await asyncio.gather(*self._closing, return_exceptions=True)
        return names


def _short(text: str, limit: int = 60) -> str:
    line = " ".join(text.split())
    return line if len(line) <= limit else line[: limit - 1] + "…"
