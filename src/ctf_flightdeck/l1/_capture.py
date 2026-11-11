"""flightdeck's output capture for an L1 engine. Never imported; the runner runs it as

    <flightdeck's python> -I _capture.py <head> <tail> <stderr> [--lc-ctype=<value>] -- <command ...>

in the engine's workspace, as the workspace's command. It starts <command> (the engine)
with stdout and stderr on pipes of its own; stdin, the working directory and the
environment are the engine's as given. So whatever the engine and its children print
reaches flightdeck only through here, and this keeps, counting every byte:

- the first <head> bytes of stdout, and the last <tail> bytes of what came after them;
- the last <stderr> bytes of stderr.

Nothing goes to disk, so an engine that prints without end fills no disk, and an engine is
never stopped for printing: what is not kept is read and dropped. When both pipes have
closed and the engine has exited, it writes one record on its own stdout, the workspace's
pipe, which no process it started holds:

    {"capture": 1, "status": S, "stdout": N, "head": H, "tail": T, "stderr": M, "stderr_kept": E}
    then, after that line's newline, H + T + E bytes: the head, the tail, the end of stderr

and exits with S, the engine's status: its exit code, or 128 + n when signal n ended it, as
a shell says it. A command it cannot start at all: status 127, the reason as its stderr.

Python starts with LC_CTYPE set to a UTF-8 locale when the locale is C (PEP 538), and passes
it on to the processes it starts, where it changes how tools treat bytes (macOS's tr refuses
binary input). So the runner says what LC_CTYPE was, --lc-ctype=<value> or nothing when it
was not set, and the engine gets exactly that.

Python 3.8 syntax, standard library only.
"""

import json
import os
import subprocess
import sys
import threading

CHUNK = 65536


class Keep:
    """The first `head` and the last `tail` bytes of a stream, and how many there were."""

    def __init__(self, head, tail):
        self.head_size = head
        self.tail_size = tail
        self.head = bytearray()
        self.tail = bytearray()
        self.total = 0

    def add(self, data):
        self.total += len(data)
        room = self.head_size - len(self.head)
        if room > 0:
            self.head += data[:room]
            data = data[room:]
        if data and self.tail_size:
            self.tail += data
            if len(self.tail) > 2 * self.tail_size + CHUNK:  # trimmed now and then: each byte moves O(1) times
                del self.tail[: len(self.tail) - self.tail_size]

    def kept_tail(self):
        return bytes(self.tail[-self.tail_size:]) if self.tail_size else b""

    def pump(self, pipe):
        fd = pipe.fileno()
        while True:
            chunk = os.read(fd, CHUNK)
            if not chunk:
                break
            self.add(chunk)


def main(argv):
    try:
        split = argv.index("--")
        head, tail, err = (int(word) for word in argv[1:4])
        options = argv[4:split]
        command = argv[split + 1:]
        if head < 0 or tail < 0 or err < 0 or not command or any(not o.startswith("--lc-ctype=") for o in options):
            raise ValueError
    except ValueError:
        sys.stderr.write("usage: _capture.py <head> <tail> <stderr> [--lc-ctype=<value>] -- <command ...>\n")
        return 2
    env = dict(os.environ)
    env.pop("LC_CTYPE", None)
    for option in options:
        env["LC_CTYPE"] = option[len("--lc-ctype="):]
    out = Keep(head, tail)
    errors = Keep(0, err)
    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    except OSError as exc:
        errors.add(("flightdeck: cannot start %s: %s\n" % (command[0], exc.strerror or exc)).encode("utf-8", "backslashreplace"))
        return report(127, out, errors)
    reader = threading.Thread(target=out.pump, args=(proc.stdout,))
    reader.daemon = True
    reader.start()
    errors.pump(proc.stderr)
    reader.join()
    proc.stdout.close()
    proc.stderr.close()
    code = proc.wait()
    return report(code if code >= 0 else 128 - code, out, errors)


def report(status, out, errors):
    head = bytes(out.head)
    tail = out.kept_tail()
    err = errors.kept_tail()
    record = {
        "capture": 1, "status": status, "stdout": out.total, "head": len(head), "tail": len(tail),
        "stderr": errors.total, "stderr_kept": len(err),
    }
    stream = sys.stdout.buffer
    stream.write(json.dumps(record).encode("ascii") + b"\n" + head + tail + err)
    stream.flush()
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv))
