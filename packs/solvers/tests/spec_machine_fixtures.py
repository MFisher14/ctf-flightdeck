"""Shared fixtures for the spec_machine tests (B-057): a synthetic 16-bit machine, an independent
reference interpreter for it, a random program generator and a loopback audit service.

Everything is built here: no challenge file is read. `TALLY` is the declarative spec under test;
`reference()` is a separate tree-walking interpreter written against the same prose rules, so a
differential run fails when the engine's semantics drift. Helper module, not collected (no test_ prefix).
"""
from __future__ import annotations

import copy
import random
import socket
import threading

FLAG = "CSCTF{sp3c_m4ch1n3_r0unds}"
M = 0xFFFF

# The "tally" machine: 8 registers of 16 bits, wrap everywhere, structured blocks closed by `done`.
TALLY = {
    "name": "tally",
    "word_bits": 16,
    "registers": {"count": 8, "prefix": "r"},
    "quirks": {"div_zero": 65535, "mod_zero": "dividend", "shift_mask": 15, "input_eof": 65535},
    "syntax": {"end": "done", "comment": ["#"]},
    "ops": {
        "put": {"args": ["d:reg", "v:imm"], "do": "d = v"},
        "cpy": {"args": ["d:reg", "x:reg"], "do": "d = x"},
        "add": {"args": ["d:reg", "x:reg", "y:reg"], "do": "d = x + y"},
        "sub": {"args": ["d:reg", "x:reg", "y:reg"], "do": "d = x - y"},
        "mul": {"args": ["d:reg", "x:reg", "y:reg"], "do": "d = x * y"},
        "div": {"args": ["d:reg", "x:reg", "y:reg"], "do": "d = x // y"},
        "rem": {"args": ["d:reg", "x:reg", "y:reg"], "do": "d = x % y"},
        "and": {"args": ["d:reg", "x:reg", "y:reg"], "do": "d = x & y"},
        "orr": {"args": ["d:reg", "x:reg", "y:reg"], "do": "d = x | y"},
        "xor": {"args": ["d:reg", "x:reg", "y:reg"], "do": "d = x ^ y"},
        "lsh": {"args": ["d:reg", "x:reg", "y:reg"], "do": "d = x << y"},
        "rsh": {"args": ["d:reg", "x:reg", "y:reg"], "do": "d = x >> y"},
        "inv": {"args": ["d:reg", "x:reg"], "do": "d = ~x"},
        "get": {"args": ["d:reg"], "do": "d = input()"},
        "say": {"args": ["x:reg"], "do": "output(x)"},
    },
    "blocks": {
        "times": {"kind": "repeat", "args": ["n:imm"], "count": "n"},
        "whenz": {"kind": "if", "args": ["x:reg"], "cond": "x == 0"},
        "whennz": {"kind": "if", "args": ["x:reg"], "cond": "x != 0"},
    },
    "framing": {"program_start": "PROGRAM", "program_end": ".", "input_prefix": "INPUT",
                "output_prefix": "OUTPUT", "prompt": "OUTPUT>"},
    "examples": [
        {"name": "wrap", "program": "get r1\nget r2\nadd r0 r1 r2\nsay r0\n", "input": [65535, 2], "output": "1"},
        {"name": "zero rules", "program": "put r1 9\ndiv r2 r1 r3\nrem r4 r1 r3\nsay r2\nsay r4\n",
         "output": "65535 9"},
    ],
}


def tally(**changes) -> dict:
    """A deep copy of TALLY with top-level keys replaced (a dict value is merged one level down)."""
    d = copy.deepcopy(TALLY)
    for key, value in changes.items():
        if isinstance(value, dict) and isinstance(d.get(key), dict):
            d[key].update(value)
        else:
            d[key] = value
    return d


def reference(program: str, tape) -> str:
    """The tally machine, written independently of the engine: a tree walk over nested blocks."""
    rows = [ln.split("#")[0].split() for ln in program.splitlines()]
    rows = [r for r in rows if r]
    pos = 0

    def block():
        nonlocal pos
        body = []
        while pos < len(rows):
            row = rows[pos]
            pos += 1
            if row[0] == "done":
                return body
            if row[0] in ("times", "whenz", "whennz"):
                body.append((row[0], row[1], block()))
            else:
                body.append(tuple(row))
        return body

    tree = block()
    regs = [0] * 8
    out: list[int] = []
    cursor = [0]

    def r(tok):
        return int(tok[1:])

    def walk(body):
        for ins in body:
            op = ins[0]
            if op == "times":
                for _ in range(int(ins[1])):
                    walk(ins[2])
            elif op == "whenz":
                if regs[r(ins[1])] == 0:
                    walk(ins[2])
            elif op == "whennz":
                if regs[r(ins[1])] != 0:
                    walk(ins[2])
            elif op == "put":
                regs[r(ins[1])] = int(ins[2]) % 65536
            elif op == "cpy":
                regs[r(ins[1])] = regs[r(ins[2])]
            elif op == "inv":
                regs[r(ins[1])] = 65535 - regs[r(ins[2])]
            elif op == "get":
                if cursor[0] < len(tape):
                    regs[r(ins[1])] = tape[cursor[0]] % 65536
                    cursor[0] += 1
                else:
                    regs[r(ins[1])] = 65535
            elif op == "say":
                out.append(regs[r(ins[1])])
            else:
                y, z = regs[r(ins[2])], regs[r(ins[3])]
                if op == "add":
                    v = y + z
                elif op == "sub":
                    v = y - z
                elif op == "mul":
                    v = y * z
                elif op == "div":
                    v = 65535 if z == 0 else y // z
                elif op == "rem":
                    v = y if z == 0 else y % z
                elif op == "and":
                    v = y & z
                elif op == "orr":
                    v = y | z
                elif op == "xor":
                    v = y ^ z
                elif op == "lsh":
                    v = y * (2 ** (z % 16))
                elif op == "rsh":
                    v = y // (2 ** (z % 16))
                else:
                    raise AssertionError(f"reference: unknown op {op}")
                regs[r(ins[1])] = v % 65536
    walk(tree)
    return " ".join(str(v) for v in out)


_THREE = ("add", "sub", "mul", "div", "rem", "and", "orr", "xor", "lsh", "rsh")


def random_program(rng: random.Random, depth: int = 0) -> list[str]:
    """Random tally source lines: every op, nested blocks, immediates past both ends of a word."""
    lines = []
    for _ in range(rng.randint(2, 7)):
        reg = lambda: f"r{rng.randrange(8)}"                     # noqa: E731
        roll = rng.random()
        if depth < 3 and roll < 0.22:
            head = rng.choice([f"times {rng.randrange(0, 4)}", f"whenz {reg()}", f"whennz {reg()}"])
            lines += [head] + ["  " + ln for ln in random_program(rng, depth + 1)] + ["done"]
        elif roll < 0.40:
            lines.append(f"put {reg()} {rng.choice([0, 1, 2, 15, 16, 17, 255, 65535, 65536, 70001, -1, -40000, rng.randrange(65536)])}")
        elif roll < 0.48:
            lines.append(f"get {reg()}")
        elif roll < 0.58:
            lines.append(f"say {reg()}")
        elif roll < 0.63:
            lines.append(f"{rng.choice(['cpy', 'inv'])} {reg()} {reg()}")
        else:
            lines.append(f"{rng.choice(_THREE)} {reg()} {reg()} {reg()}")
    return lines


def random_round(rng: random.Random) -> tuple[str, list[int]]:
    """A program that always prints something, and a tape for it."""
    body = random_program(rng) + [f"say r{rng.randrange(8)}", "say r0"]
    tape = [rng.choice([0, 1, 7, 65535, rng.randrange(65536)]) for _ in range(rng.randrange(0, 5))]
    return "\n".join(body), tape


def round_text(k: int, total: int, program: str, tape) -> str:
    return (f"=== round {k}/{total} ===\nPROGRAM\n{program}\n.\n"
            f"INPUT {' '.join(map(str, tape))}\nOUTPUT> ")


class AuditService:
    """A loopback service: `rounds` is a list of (program, tape, expected answer). It sends each
    round, reads one answer line, and closes with WRONG on the first mismatch; after the last round
    it sends the flag. `split_at` sends each round in two writes with a pause between them."""

    def __init__(self, rounds, flag: str = FLAG, banner: str = "tally audit v1\n", split_at: int | None = None,
                 pause: float = 0.0):
        self.rounds, self.flag, self.banner = rounds, flag, banner
        self.split_at, self.pause = split_at, pause
        self.answers: list[str] = []
        self.accepted = 0
        self.error: str | None = None
        self.done = threading.Event()
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(1)
        self.host, self.port = self.srv.getsockname()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            self.srv.settimeout(30.0)
            conn, _ = self.srv.accept()
            self.accepted += 1
            conn.settimeout(30.0)
            with conn:
                conn.sendall(self.banner.encode())
                buf = b""
                for k, (program, tape, expected) in enumerate(self.rounds, 1):
                    data = round_text(k, len(self.rounds), program, tape).encode()
                    if self.split_at is not None:
                        conn.sendall(data[:self.split_at])
                        self.done.wait(self.pause)          # never set here: a plain pause
                        conn.sendall(data[self.split_at:])
                    else:
                        conn.sendall(data)
                    while b"\n" not in buf:
                        chunk = conn.recv(65536)
                        if not chunk:
                            return
                        buf += chunk
                    line, buf = buf.split(b"\n", 1)
                    self.answers.append(line.decode("utf-8", "replace"))
                    if self.answers[-1].strip() != expected.strip():
                        conn.sendall(b"WRONG. session closed.\n")
                        return
                conn.sendall(f"all correct. {self.flag}\n".encode())
        except Exception as e:  # noqa: BLE001 - surfaced through .error
            self.error = f"{type(e).__name__}: {e}"
        finally:
            self.srv.close()
            self.done.set()

    def join(self) -> "AuditService":
        self.thread.join(timeout=60.0)
        return self

    def close(self) -> None:
        """For a test where no client ever connects: stop the accept."""
        try:
            self.srv.close()
        except OSError:
            pass
