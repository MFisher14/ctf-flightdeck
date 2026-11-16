"""A terminal for a session that asks for one (P87): the relay that gives a program a pty, and
the filter that turns what the pty writes back into plain text.

Some programs act differently when their input is not a terminal: python3 shows no prompt
and holds its output, a program that reads a password from the terminal will not start, a
challenge's menu buffers its lines. session_start with `terminal: true` runs the command
under RELAY, a short Python program that opens a pty, starts the command with the pty's
side as its standard input, output and error, and copies between its own pipes and the pty.
Everything around it stays as it is for any session (agent/sessions.py): the same pipes to
flightdeck, the same caps, the same kill.

Four choices shape it:

- **No controlling terminal.** The command does not start a session of its own (no setsid),
  so it stays in the relay's process group, which on the host is the group flightdeck kills
  and in a container is the tree under the pid the workspace's first line names. The price:
  a key such as ctrl+c sends no signal, and a program that opens /dev/tty finds none. A
  stuck session is closed, not interrupted.
- **TERM=dumb and no echo.** The command's TERM is `dumb`, so a line editor and a colour
  library mostly leave their escapes out, and the pty does not echo what was sent. A line
  editor may still write the line again itself.
- **Escapes stripped here, in flightdeck.** TerminalText takes control sequences (CSI, OSC
  and the other ESC forms), carriage returns and bells out of the stream before anything
  stores it, on the host side, so the relay (which in a container runs on the lane's own
  python3, which the lane can change) is trusted with nothing: whatever it writes is
  filtered all the same. The filter keeps its state between chunks, so a sequence split
  across two reads is still taken out whole; an escape that never ends gives its bytes back
  (without the ESC) after ESCAPE_LIMIT, so it cannot hide what follows it.

- **Bytes as sent.** The pty's line discipline would edit what is sent before the program
  reads it: ctrl+? and ctrl+h erase, ctrl+u and ctrl+w kill, ctrl+v quotes, ctrl+s stops the
  stream, ctrl+c and ctrl+z become signals, and a carriage return becomes a newline. A
  payload sent this way would reach the program changed, with no word of it, so the relay
  turns all of that off (ICRNL, INLCR, IGNCR, IXON, IXOFF, ISTRIP, ISIG, IEXTEN, and the
  erase, kill and extra end-of-line characters disabled). What is left is canonical mode:
  input goes to the program a line at a time, a line ends only at a newline, and ctrl+d
  (END_OF_FILE) still ends the input, which is how the end of the relay's own input reaches
  the program. So a send to a terminal session refuses ctrl+d rather than let it be taken.

A terminal takes a line at a time and a pty's line has a limit (MAX_CANON: 1024 bytes on
macOS, 4096 on Linux), so a send to a terminal session refuses a line over TERMINAL_LINE
bytes rather than letting the terminal cut it.
"""

from __future__ import annotations

TERM = "dumb"
ROWS, COLUMNS = 500, 200  # the pty's size: tall, so a pager that reads it rarely stops
TERMINAL_LINE = 1000  # bytes in one line sent to a terminal session, its newline included
ESCAPE_LIMIT = 4096  # bytes an unfinished escape may take before they are given back
END_OF_FILE = b"\x04"  # ctrl+d, the one byte the terminal still takes for itself (VEOF)

# The relay: argv[1:] is the program and its arguments. It exits with the program's status
# (128 + the signal when a signal ended it) once the pty's other side is closed by everything
# that had it, as a pipe's end would be. The end of its own input becomes the terminal's
# end-of-file (ctrl+d), sent once.
RELAY = r"""
import errno, fcntl, os, select, struct, sys, termios
master, slave = os.openpty()
mode = termios.tcgetattr(slave)
mode[0] &= ~(termios.ICRNL | termios.INLCR | termios.IGNCR | termios.IXON | termios.IXOFF | termios.ISTRIP)
mode[3] &= ~(termios.ECHO | termios.ECHONL | termios.ISIG | termios.IEXTEN)
off = os.fpathconf(slave, "PC_VDISABLE").to_bytes(1, "big")
for key in (termios.VERASE, termios.VKILL, termios.VEOL, termios.VEOL2):
    mode[6][key] = off
termios.tcsetattr(slave, termios.TCSANOW, mode)
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", %(rows)d, %(columns)d, 0, 0))
pid = os.fork()
if pid == 0:
    os.close(master)
    for fd in (0, 1, 2):
        os.dup2(slave, fd)
    if slave > 2:
        os.close(slave)
    os.environ["TERM"] = %(term)r
    try:
        os.execvp(sys.argv[1], sys.argv[1:])
    except OSError as exc:
        os.write(2, ("flightdeck: cannot start %%s: %%s\n" %% (sys.argv[1], exc.strerror)).encode())
    os._exit(127)
os.close(slave)
os.set_blocking(master, False)
pending = bytearray()
reading = True
while True:
    want = [master] + ([0] if reading and not pending else [])
    ready, writable, _ = select.select(want, [master] if pending else [], [])
    if 0 in ready:
        data = os.read(0, 65536)
        if data:
            pending += data
        else:
            reading = False
            pending += b"\x04"
    if master in writable and pending:
        try:
            del pending[: os.write(master, pending)]
        except BlockingIOError:
            pass
        except OSError:
            pending.clear()
    if master in ready:
        try:
            data = os.read(master, 65536)
        except BlockingIOError:
            continue
        except OSError as exc:
            if exc.errno != errno.EIO:
                raise
            data = b""
        if not data:
            break
        view = memoryview(data)
        while view:
            view = view[os.write(1, view):]
_, status = os.waitpid(pid, 0)
code = os.waitstatus_to_exitcode(status)
sys.exit(128 - code if code < 0 else code)
""" % {"rows": ROWS, "columns": COLUMNS, "term": TERM}

_ESC = 0x1B
_STRINGS = frozenset(b"]P_^X")  # OSC, DCS, APC, PM, SOS: a string that ends with BEL or ESC \
_DROPPED = frozenset(b"\r\x07")


class TerminalText:
    """A filter from what a pty writes to plain text, fed in chunks: feed(chunk) returns what
    of it is text, holding back the start of an escape sequence the chunk ends in."""

    def __init__(self) -> None:
        self._held = bytearray()  # an escape sequence begun and not ended

    def feed(self, data: bytes) -> bytes:
        out = bytearray()
        stream = bytes(self._held) + data
        self._held.clear()
        i, n = 0, len(stream)
        while i < n:
            byte = stream[i]
            if byte != _ESC:
                if byte not in _DROPPED:
                    out.append(byte)
                i += 1
                continue
            end = _escape_end(stream, i)
            if end is None:  # the sequence goes past this chunk
                if n - i > ESCAPE_LIMIT:
                    i += 1  # no sequence is that long: the ESC goes and the bytes after it are text
                    continue
                self._held += stream[i:]
                break
            i = end
        return bytes(out)

    def flush(self) -> bytes:
        """What is held when the stream ends: an unfinished escape's bytes, without the ESC."""
        held, self._held = bytes(self._held[1:]), bytearray()
        return bytes(b for b in held if b not in _DROPPED)


def _escape_end(data: bytes, start: int) -> int | None:
    """The index just past the escape sequence at `start` (an ESC), or None when it does not end
    within `data`. ECMA-48's forms: CSI (ESC [, parameters and intermediates, a final byte), a
    control string (ESC ] and its kind, up to BEL or ESC \\), and ESC with intermediates and
    a final byte (ESC ( B, ESC =, ESC 7, ...)."""
    n = len(data)
    i = start + 1
    if i >= n:
        return None
    kind = data[i]
    if kind == ord("["):
        i += 1
        while i < n and 0x30 <= data[i] <= 0x3F:
            i += 1
        while i < n and 0x20 <= data[i] <= 0x2F:
            i += 1
        if i >= n:
            return None
        return i + 1 if 0x40 <= data[i] <= 0x7E else i  # a malformed one ends before the byte that broke it
    if kind in _STRINGS:
        i += 1
        while i < n:
            if data[i] == 0x07:
                return i + 1
            if data[i] == _ESC:
                if i + 1 >= n:
                    return None
                if data[i + 1] == ord("\\"):
                    return i + 2
            i += 1
        return None
    while i < n and 0x20 <= data[i] <= 0x2F:
        i += 1
    if i >= n:
        return None
    return i + 1 if 0x30 <= data[i] <= 0x7E else i
