"""B-110: custom-cipher auto-inverter with SMT fallback (solvers/toolkits/cipher_invert.py).

Every cipher here is synthetic source written for this test (no challenge file, no challenge
constants).  The ground truth of a cipher is CPython running that test-authored source; the engine
itself never runs it -- it parses it and evaluates it in its closed interpreter.  "It inverts X" is
always a round trip: encrypt a secret with the real source, give the engine the source and the
output, require the secret back, and require the method (algebraic / smt / blackbox) the case is
about, so a broken rule or a skipped stage fails the test.

No test bounds wall-clock time: budgets are passed explicitly and are either huge (the work must
finish) or driven by an injected step clock / a step count.
"""
from __future__ import annotations

import ast
import gzip
import io
import itertools
import json
import random
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import _cipher_vm as cvm               # noqa: E402  (flat import, the engine sys.path)
import cipher_invert as ci             # noqa: E402
from ctf import event                  # noqa: E402
from ctf.engines import manifest as _manifest   # noqa: E402
from ctf.result import SolverResult    # noqa: E402

CSCTF = event.load("csctf")
BIG = 3600.0                           # a budget no test should reach: the work has to finish


def native(src, name, *args):
    """Ground truth: CPython running the test's own synthetic source."""
    ns: dict = {}
    exec(compile(src, "<synthetic>", "exec"), ns)   # noqa: S102 - test-authored source, not a handout
    return ns[name](*args)


def rec(src, **kw):
    kw.setdefault("budget_s", BIG)
    return ci.recover(src, **kw)


def only(rep):
    assert len(rep.recovered) == 1, (rep.recovered, rep.notes)
    return rep.recovered[0]


# A block scrambler of the 9142 shape with its own constants: an LCG-shuffled S-box, LCG round keys,
# add-mod-256 on even rounds and xor on odd ones, a 64-bit rotation per round, PKCS#7-style padding.
SPN = '''
M = (1 << 64) - 1
def lcg(s):
    while True:
        s = (s * 0x41C64E6D + 0x3039) & 0xFFFFFFFF
        yield s
g = lcg(0x0BADF00D)
box = list(range(256))
for i in range(255, 0, -1):
    j = next(g) % (i + 1)
    box[i], box[j] = box[j], box[i]
g = lcg(0x5EED1234)
ROUNDS = 6
RK = [[next(g) & 0xFF for _ in range(8)] for _ in range(ROUNDS)]
rot = lambda r: (5 * r + 3) % 63 + 1
def enc_block(b):
    s = list(b)
    for r in range(ROUNDS):
        s = [(s[i] + RK[r][i]) & 255 if r % 2 == 0 else s[i] ^ RK[r][i] for i in range(8)]
        s = [box[c] for c in s]
        x = int.from_bytes(bytes(s), 'big')
        k = rot(r) & 63
        x = ((x << k) | (x >> (64 - k))) & M
        s = list(x.to_bytes(8, 'big'))
    return bytes(s)
def seal(msg):
    pad = 8 - len(msg) % 8
    msg = msg + bytes([pad]) * pad
    return b''.join(enc_block(msg[i:i + 8]) for i in range(0, len(msg), 8))
'''


# ============================================================ the interpreter is faithful and closed

CIPHERS = {
    "spn": (SPN, "seal", b"synthetic passphrase 01"),
    "stream": ('''
import hashlib
KEY = hashlib.sha256(b"k3y").digest()
def enc(data):
    prev = 0x5A
    out = bytearray()
    for i, b in enumerate(data):
        c = ((b ^ prev) + KEY[i % 32]) & 0xFF
        out.append(c)
        prev = c
    return bytes(out)
''', "enc", b"chained \x00\xff bytes"),
    "words": ('''
import struct
def enc(data):
    a, b = struct.unpack('<II', data)
    for r in range(8):
        a = (a + (((b << 4) ^ (b >> 5)) + b ^ (0x9E3779B9 * r & 0xFFFFFFFF))) & 0xFFFFFFFF
        b = (b + (((a << 4) ^ (a >> 5)) + a ^ (0x01234567 * r & 0xFFFFFFFF))) & 0xFFFFFFFF
    return struct.pack('<II', a, b)
''', "enc", b"feistel!"),
    "klass": ('''
class Scrambler:
    def __init__(self, key):
        self.key = key
        self.perm = list(range(8))
        for i in range(8):
            j = (key[i] + i) % 8
            self.perm[i], self.perm[j] = self.perm[j], self.perm[i]
    def encrypt(self, block):
        out = [0] * 8
        for i in range(8):
            out[self.perm[i]] = (block[i] * 7 + self.key[i]) & 0xFF
        return out
box = Scrambler(b"abcdefgh")
def encrypt(block):
    return box.encrypt(block)
''', "encrypt", b"8bytes!!"),
    "text": ('''
def enc(s):
    return ''.join(chr((ord(c) * 5 + i * 3 + 7) % 128) for i, c in enumerate(s))
''', "enc", "hello, world {x}"),
    "seeded": ('''
import random
random.seed(1337)
SBOX = list(range(256))
random.shuffle(SBOX)
def enc(data):
    r = random.Random(42)
    ks = [r.randint(0, 255) for _ in data]
    return bytes(SBOX[b] ^ k for b, k in zip(data, ks))
''', "enc", b"seeded random stream"),
    "misc": ('''
from functools import reduce
def enc(data):
    total = reduce(lambda a, b: a ^ b, data, 0)
    out = []
    i = 0
    while i < len(data):
        q, r = divmod(data[i] + 3 * i, 16)
        out.append((r << 4 | q % 16) ^ (total if i else 0))
        i += 1
    try:
        out.append([1, 2][len(data)])
    except IndexError:
        out.append(0x7F)
    finally:
        out.reverse()
    return tuple(out), {k: v for k, v in zip("ab", out)}
''', "enc", b"reduce and divmod"),
}


# Not a cipher: one function per language feature the interpreter models, checked against CPython.
FEATURES = '''
K = 5
COUNT = 0
class Box:
    K = 7
    SIZE = 3
    def __init__(self, seed, *rest, scale=2):
        self.seed, self.rest, self.scale = seed, rest, scale
    def get(self):
        return K + self.seed            # the module's K: a class body is not a closure
    @staticmethod
    def twice(v):
        return v * 2
def variadic(a, *rest, key=1, **extra):
    return [a, rest, key, sorted(extra.items())]
def counter():
    global COUNT
    COUNT += 1
    return COUNT
def outer(n):
    total = 0
    def inner(k):
        nonlocal total
        total += k
        return total
    return [inner(i) for i in range(n)], total
def fib():
    a, b = 0, 1
    while True:
        yield a
        a, b = b, a + b
def run(data):
    out = []
    box = Box(3, 4, 5, scale=9)
    out.append([box.get(), box.rest, box.scale, Box.twice(4), Box.SIZE, Box.K])
    out.append(variadic(1, 2, 3, key=4, z=5, y=6))
    out.append(variadic(1))
    out.append([counter(), counter(), COUNT])
    out.append(outer(4))
    g = fib()
    out.append([next(g) for _ in range(8)])
    for i, b in enumerate(data):
        if i > 0 and b % 2 == 0 or b == 0:
            out.append(("even", i))
        elif not (i < 2 or b > 100) and 0 < i <= 5:
            out.append(("mid", i))
        else:
            continue
        if len(out) > 14:
            break
    else:
        out.append("no break")
    n = 0
    while n < 3:
        n += 1
    else:
        out.append(("while-else", n))
    first, *middle, last = data
    out.append((first, middle[:2], last, data[::-1][:3], data[1:-1:2]))
    table = {k: v for k, v in zip("abc", range(3))}
    table["d"] = table.get("z", 9)
    table["a"] += 10
    out.append(sorted(table.items()))
    out.append([k for k in table if table[k] > 1])
    words = "the Quick  brown fox".split()
    out.append(["-".join(w.upper() for w in words), words[1].lower().startswith("q"), "fox" in words])
    out.append(f"{len(data):03d}|{data[:2].hex()}|{words[0]!r}|{3.5:.1f}")
    grid = [[r * c for c in range(3)] for r in range(3)]
    grid[1][2] ^= 0xFF
    out.append(grid)
    out.append((lambda a, b=2: a ** b)(7))
    try:
        out.append(int("x"))
    except (KeyError, ValueError) as exc:
        out.append("caught")
    finally:
        out.append("finally")
    out.append([x is None for x in (None, 0)])
    out.append((y := len(data)) + y)
    out.append([min(data), max(data), sum(data), sorted(data)[:3], any(b > 250 for b in data)])
    return out
'''


def test_interpreter_models_the_language_features_ciphers_use():
    vm = ci.Cipher(FEATURES).fresh()
    assert vm.skipped == []
    data = bytes([7, 0, 12, 200, 33, 4, 250, 9])
    assert vm.root.vars["run"](data) == native(FEATURES, "run", data)


@pytest.mark.parametrize("name", sorted(CIPHERS))
def test_interpreter_gives_what_cpython_gives(name):
    src, fn, secret = CIPHERS[name]
    vm = ci.Cipher(src).fresh()
    assert vm.skipped == []
    got = vm.root.vars[fn](secret)
    assert got == native(src, fn, secret)


@pytest.mark.parametrize("name", ["spn", "stream", "words", "seeded"])
def test_symbolic_trace_evaluates_to_the_concrete_result(name):
    src, fn, secret = CIPHERS[name]
    _syms, x = ci.make_input("bytes", len(secret))
    out = ci.Cipher(src).fresh().root.vars[fn](x)
    assert isinstance(out, cvm.SymBytes) and not out.concrete()
    vals = cvm.evaluate(list(out.items), dict(enumerate(secret)))
    assert bytes(vals) == native(src, fn, secret)


def test_the_source_cannot_reach_files_processes_or_the_host_interpreter(tmp_path):
    canary = tmp_path / "canary.txt"
    marker = tmp_path / "marker.txt"
    marker.write_text("present")
    src = f'''
import os, subprocess
a = os.system("touch {canary}")
b = subprocess.run(["touch", "{canary}"])
c = open("{marker}").read()
d = __import__("os")
e = ().__class__.__bases__
f = eval("1+1")
g = exec("x = 1")
h = globals()
i = getattr(int, "__subclasses__")
with open("{canary}", "w") as fh:
    fh.write("written")
j = open("{canary}", "w").write("written")
k = (lambda: 0).__globals__
class A:
    def __init__(self):
        self.v = 1
inst = A()
l = inst.__init__
m = inst.__dict__
ok = 41 + 1
'''
    vm = ci.Cipher(src).fresh()
    assert not canary.exists()                       # nothing ran, nothing was written
    g = vm.root.vars
    assert g["ok"] == 42                             # the rest of the module still evaluated
    for name in "abcdefghiklm":
        assert isinstance(g[name], cvm.Poison), name
    assert vm.written == ["written", "written"]      # a write is kept as a candidate output only
    reasons = " | ".join(vm.skipped)
    assert "reads the file" in reasons and "'os'" in reasons and "'eval'" in reasons
    assert "__class__" in reasons and "__globals__" in reasons


def test_module_level_infinite_loop_hits_the_step_budget():
    vm = cvm.VM(max_steps=5000)
    with pytest.raises(cvm.BudgetExceeded, match="step budget of 5000"):
        vm.run_module(ast.parse("while True:\n    pass\n"))
    assert vm.steps == 5001                          # it stopped at the budget, not somewhere later


def test_a_runaway_function_fails_its_own_hypothesis_not_the_run():
    src = '''
def enc(data):
    n = 0
    while True:
        n += 1
    return data
def seal(data):
    return bytes(b ^ 0x21 for b in data)
'''
    rep = rec(src, target=bytes(b ^ 0x21 for b in b"still solved"), max_steps=20000)
    r = only(rep)
    assert r.func == "seal" and r.values == [b"still solved"]
    assert any("enc on" in n and "step budget" in n for n in rep.notes)
    # the runaway function is given up per input type, not retried at every length
    assert not rep.incomplete and rep.attempts <= 4


def test_huge_concrete_values_are_refused_not_computed():
    vm = ci.Cipher("a = 1 << (1 << 40)\nb = 7 ** (10 ** 9)\nc = [0] * (10 ** 12)\n"
                   "d = list(range(10 ** 12))\ne = bytes(10 ** 12)\nok = 1\n").fresh()
    assert vm.root.vars["ok"] == 1
    assert all(isinstance(vm.root.vars[n], cvm.Poison) for n in "abcde")
    assert len(vm.skipped) == 5


# Each line hands an iterable to something CPython consumes in C.  The sizes are small enough that
# CPython finishes them in a moment (so the test stays cheap without the fix it guards), but every one
# is far past a budget of 5000 steps: the interpreter has to stop at the budget, which is what keeps
# `max(range(10 ** 11))` in a handout from running unbounded.
C_LEVEL_CONSUMERS = [
    "s = sum(range(10 ** 6))",
    "s = sum(range(10 ** 6), 7)",
    "s = max(range(10 ** 6))",
    "s = min(range(10 ** 6))",
    "s = any(itertools.repeat(0, 10 ** 6))",
    "s = all(itertools.repeat(1, 10 ** 6))",
    "s = math.prod(itertools.repeat(1, 10 ** 6))",
    "d = dict.fromkeys(range(10 ** 6))",
    "d = dict(zip(range(10 ** 6), range(10 ** 6)))",
    "l = list(itertools.repeat(0, 10 ** 6))",
    "l = tuple(itertools.repeat(0, 10 ** 6))",
    "l = sorted(itertools.repeat(0, 10 ** 6))",
    "l = set(itertools.repeat(0, 10 ** 6))",
    "b = bytes(itertools.repeat(0, 10 ** 6))",
    "j = ''.join(itertools.repeat('a', 10 ** 6))",
    "j = b''.join(itertools.repeat(b'a', 10 ** 6))",
    "j = str.join('', itertools.repeat('a', 10 ** 6))",
    "r = functools.reduce(operator.add, range(10 ** 6))",
    "p = itertools.product(range(10 ** 6))",
    "p = itertools.product(range(2), range(10 ** 6))",   # every iterable is pulled, not just the first
    "p = itertools.permutations(range(10 ** 6), 1)",
    "p = itertools.combinations(range(10 ** 6), 1)",
    "t = 5 in itertools.repeat(0, 10 ** 6)",
    "a, *rest = range(10 ** 6)",
    "l = [*range(10 ** 6)]",
    "m = max(*range(10 ** 6))",
    # iterator builders that skip or copy inside CPython: the charge sits on their source
    "x = next(filter(None, itertools.repeat(0, 10 ** 6)), 1)",
    "x = next(itertools.islice(range(10 ** 6), 10 ** 6 - 1, None))",
    "x = next(itertools.chain(filter(None, itertools.repeat(0, 10 ** 6)), [1]))",
    # whitelisted methods that pull an iterable argument in C
    "l = []\nl.extend(itertools.repeat(0, 10 ** 6))",
    "s = set()\ns.update(itertools.repeat(0, 10 ** 6))",
    "s = {1}.union(itertools.repeat(0, 10 ** 6))",
    "s = {1}.issubset(itertools.repeat(0, 10 ** 6))",
    "d = {}\nd.update(zip(range(10 ** 6), range(10 ** 6)))",
    "b = bytearray()\nb.extend(itertools.repeat(0, 10 ** 6))",
]


@pytest.mark.parametrize("line", C_LEVEL_CONSUMERS)
def test_c_level_consumers_are_charged_to_the_step_budget(line):
    vm = cvm.VM(max_steps=5000)
    src = "import itertools, math, functools, operator\n" + line + "\n"
    with pytest.raises(cvm.BudgetExceeded, match="step budget of 5000"):
        vm.run_module(ast.parse(src))
    assert vm.steps == 5001


def test_c_level_consumers_still_give_what_cpython_gives():
    src = ("import itertools, math, functools, operator\n"
           "a = sum(range(10), 7)\nb = max([3, 9, 2])\nc = min(4, 1, 8)\nd = min([5, 6], key=lambda v: -v)\n"
           "e = any(x > 8 for x in range(10))\nf = all([])\ng = math.prod([2, 3, 4])\n"
           "h = math.prod([2, 3], start=5)\ni = dict.fromkeys('ab', 0)\nj = dict([(1, 2)], z=3)\n"
           "k = list(itertools.product('ab', repeat=2))\nl = list(itertools.permutations([1, 2, 3], 2))\n"
           "m = list(itertools.combinations('abc', 2))\nn = 3 in iter([1, 3])\no = 4 in iter([1, 3])\n"
           "p = functools.reduce(operator.xor, [1, 2, 4])\nq = ''.join(map(str, range(3)))\n"
           "r = 2 not in itertools.repeat(2, 3)\ns = sum([[1], [2]], [])\n"
           "t = list(filter(None, [0, 3, 0, 4]))\nu = list(map(operator.add, [1, 2, 3], [10, 20]))\n"
           "v = list(zip('abc', range(5)))\nw = list(enumerate('xy', 3))\n"
           "x = list(itertools.islice(itertools.count(5), 2, 8, 2))\n"
           "y = list(itertools.islice(itertools.cycle('ab'), 5))\n"
           "z = list(itertools.accumulate([1, 2, 3], operator.mul, initial=2))\n"
           "A = list(itertools.zip_longest('ab', 'c', fillvalue='-'))\n"
           "B = list(itertools.chain('ab', [1], (2,)))\nC = list(itertools.product('ab', [1, 2]))\n"
           "D = [1]\nD.extend(D)\nE = {1}\nE.update([2], {3})\nF = {1: 2}\nF.update({3: 4}, z=5)\n"
           "G = {1: 2}\nG.update([(5, 6)])\nH = {1, 2}.union([3], (4,))\nI = {1}.issubset(iter([1, 2]))\n"
           "J = bytearray(b'a')\nJ.extend(J)\nJ.extend(iter([66]))\nJ = bytes(J)\n"
           "K = list(zip('ab', 'cd', strict=True))\nL = list(itertools.islice('abcdef', 4))\n")
    vm = cvm.VM().run_module(ast.parse(src))
    assert vm.skipped == []
    ns: dict = {}
    exec(compile(src, "<synthetic>", "exec"), ns)   # noqa: S102 - test-authored source
    for name in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL":
        assert vm.root.vars[name] == ns[name], name


# Lazy builders that pass elements on one for one (map, zip, enumerate, accumulate, ...) are drained
# by a charged consumer anyway; what is checked is that each pull from their *sources* is charged too,
# so a builder that skips (filter, islice) or copies (cycle, product) in C cannot run uncharged.
# (line, pulls from the sources on top of the 1000 the outer list() is charged)
SOURCE_PULLS = [
    ("l = list(map(operator.neg, range(1000)))", 1000),
    ("l = list(map(operator.add, range(1000), range(1000)))", 2000),
    ("l = list(zip(range(1000), range(1000)))", 2000),
    ("l = list(enumerate(range(1000)))", 1000),
    ("l = list(filter(None, range(1001)))", 1001),
    ("l = list(itertools.islice(range(3000), 2000, None))", 3000),
    ("l = list(itertools.chain(range(500), range(500)))", 1000),
    ("l = list(itertools.islice(itertools.cycle(range(1000)), 1000))", 2000),
    ("l = list(itertools.accumulate(range(1000)))", 1000),
    ("l = list(itertools.zip_longest(range(1000), range(1000)))", 2000),
    ("l = list(itertools.product(range(2), range(500)))", 502),
]


def _steps(line):
    vm = cvm.VM().run_module(ast.parse("import itertools, operator\n" + line + "\n"))
    assert vm.skipped == [], vm.skipped
    assert len(vm.root.vars["l"]) == 1000
    return vm.steps


@pytest.mark.parametrize("line,pulls", SOURCE_PULLS)
def test_every_pull_from_an_iterator_builders_source_is_charged(line, pulls):
    extra = _steps(line) - _steps("l = list(range(1000))")
    # a few more steps go to evaluating the builder's own call expression; never fewer than the pulls
    assert pulls <= extra < pulls + 40, extra


# These never end inside CPython without the charge (an infinite source behind a builder that skips),
# so they run in a child interpreter under a CPU-time limit: a regression is killed and reported as a
# failure instead of hanging the suite.  The limit is CPU seconds, so machine load does not move it.
INFINITE_SOURCES = [
    "x = next(filter(None, itertools.repeat(0)))",
    "x = next(itertools.islice(itertools.count(), 10 ** 12, None))",
    "x = list(itertools.islice(filter(None, itertools.repeat(0)), 1))",
    "x = next(itertools.chain(filter(None, itertools.repeat(0))))",
    "x = next(map(None, filter(None, itertools.repeat(0))), 0)",
    "x = next(zip(filter(None, itertools.repeat(0))), 0)",
    "x = next(enumerate(filter(None, itertools.repeat(0))), 0)",
    "s = set()\ns.update(filter(None, itertools.repeat(0)))",
]

_CHILD = r"""
import ast, resource, sys
resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
sys.path.insert(0, sys.argv[1])
import _cipher_vm as cvm
for line in sys.argv[2:]:
    vm = cvm.VM(max_steps=5000)
    try:
        vm.run_module(ast.parse("import itertools\n" + line + "\n"))
        print("FINISHED", vm.steps, flush=True)
    except cvm.BudgetExceeded as exc:
        print("BUDGET", vm.steps, exc, flush=True)
"""


def test_an_infinite_source_behind_a_lazy_builder_stops_at_the_step_budget():
    # the wall-clock timeout is only a last resort against a wedged child; the CPU limit is the guard
    proc = subprocess.run([sys.executable, "-I", "-c", _CHILD, str(REPO / "solvers" / "toolkits"),
                           *INFINITE_SOURCES], capture_output=True, text=True, timeout=1800)
    lines = proc.stdout.splitlines()
    assert proc.returncode == 0, (proc.returncode, lines, proc.stderr[-2000:])
    assert lines == ["BUDGET 5001 step budget of 5000 used up"] * len(INFINITE_SOURCES)


def test_a_builder_over_something_that_is_not_iterable_still_fails_where_cpython_does():
    vm = cvm.VM().run_module(ast.parse("a = zip(1)\nb = filter(None, 2)\nc = enumerate(3)\nok = 1\n"))
    assert vm.root.vars["ok"] == 1
    assert len(vm.skipped) == 3 and all("'int' object is not iterable" in r for r in vm.skipped), \
        vm.skipped


def test_sizes_past_the_limit_are_refused_before_they_are_allocated():
    seq = cvm.MAX_SEQ
    src = (f"a = (7).to_bytes({seq + 1}, 'big')\nb = 'a'.ljust({seq + 1})\nc = 'a'.rjust({seq + 1})\n"
           f"d = 'a'.center({seq + 1})\ne = '1'.zfill({seq + 1})\nf = b'a'.ljust({seq + 1})\n"
           f"g = bytearray(b'a').zfill({seq + 1})\nh = ('a' * 1000).replace('a', 'a' * 5000)\n"
           f"i = ('a' * 1000).translate({{97: 'a' * 5000}})\nj = f'{{1:>{{{seq + 1}}}}}'\n"
           f"k = '%*d' % ({seq + 1}, 1)\nl = '%.{seq + 1}f' % 1.0\nm = b'%{seq + 1}d' % 1\n"
           f"n = (7).to_bytes(length={seq + 1}, byteorder='big')\n"
           f"o = ('x' * 300000 + 'a' * 1000).replace('a', 'a' * 4000)\n"   # the unmatched text counts
           # at the limit, or a literal digit run that is not a width: all allowed
           f"A = len((7).to_bytes({seq}, 'big'))\nB = len('a'.ljust({seq}))\n"
           f"C = len(('a' * 1000).replace('a', 'a' * 4000))\nD = 'x{seq + 1}_%d' % 5\n"
           f"E = '%%{seq + 1}d' % ()\nF = f'{{255:08x}}'\nG = ('a' * 9).replace('a', 'bb', 2)\n"
           f"H = len(('ab' * 4000).replace('ab', 'c' * 1000))\n"
           f"I = len(('a' * 1000).replace('a', 'a' * 5000, 1))\nJ = len(('a' * 1024).replace('a', 'a' * 4096))\n"
           f"K = len(('a' * 1024).translate({{97: 'a' * 4096}}))\n")
    vm = cvm.VM().run_module(ast.parse(src))
    g = vm.root.vars
    assert [n for n in "abcdefghijklmno" if not isinstance(g[n], cvm.Poison)] == []
    assert len(vm.skipped) == 15 and all("size limit" in r for r in vm.skipped), vm.skipped
    assert (g["A"], g["B"], g["C"]) == (seq, seq, 4_000_000)
    assert g["D"] == f"x{seq + 1}_5" and g["E"] == f"%{seq + 1}d" and g["F"] == "000000ff"
    assert g["G"] == "bbbbaaaaaaa" and g["H"] == 4_000_000
    assert (g["I"], g["J"], g["K"]) == (5999, seq, seq)      # a count is honoured; exactly the limit is fine
    x = cvm.Sym("in", (0,), (0, 0))
    with pytest.raises(cvm.Unsupported, match="size limit"):
        x.to_bytes(seq + 1)
    assert len(x.to_bytes(3)) == 3


def test_random_draws_past_the_size_limits_are_refused_before_they_are_drawn():
    # one past each limit (small enough that CPython would just draw it), and each limit itself allowed
    seq, bits = cvm.MAX_SEQ, cvm.MAX_CONCRETE_BITS
    vm = ci.Cipher(f"import random\nrandom.seed(1)\na = random.randbytes({seq + 1})\n"
                   f"b = random.choices([1, 2], k={seq + 1})\nc = random.sample(range(10 ** 13), {seq + 1})\n"
                   f"d = random.getrandbits({bits + 1})\nok = random.randbytes(4)\n"
                   f"e = len(random.randbytes({seq}))\nf = random.getrandbits({bits}).bit_length() <= {bits}\n"
                   ).fresh()
    assert all(isinstance(vm.root.vars[n], cvm.Poison) for n in "abcd")
    assert [r.split(": ", 1)[1].split("(")[0] for r in vm.skipped] == \
        ["random.randbytes", "random.choices", "random.sample", "random.getrandbits"]
    assert vm.root.vars["ok"] == random.Random(1).randbytes(4)   # the stream is not advanced by a refusal
    assert vm.root.vars["e"] == seq and vm.root.vars["f"] is True


def test_unseeded_random_is_refused_and_seeded_random_is_the_real_stream():
    vm = ci.Cipher("import random\nk = random.randint(0, 255)\n").fresh()
    assert isinstance(vm.root.vars["k"], cvm.Poison)
    assert "without a seed" in vm.skipped[0]
    vm = ci.Cipher("import random\nrandom.seed(99)\nk = [random.getrandbits(32) for _ in range(4)]\n"
                   "p = list(range(20))\nrandom.shuffle(p)\n").fresh()
    r = random.Random(99)
    want_k = [r.getrandbits(32) for _ in range(4)]
    want_p = list(range(20))
    r.shuffle(want_p)
    assert vm.root.vars["k"] == want_k and vm.root.vars["p"] == want_p


def test_a_branch_on_the_secret_cannot_be_traced_and_says_so():
    vm = ci.Cipher("def f(d):\n    if d[0] > 5:\n        return 1\n    return 0\n").fresh()
    _syms, x = ci.make_input("bytes", 2)
    with pytest.raises(cvm.Unsupported, match="branch or truth test depends on the secret"):
        vm.root.vars["f"](x)


@pytest.mark.parametrize("body", [
    "return {1: 2}.get(d[0], 0)",                    # a hash lookup would compare identities
    "return d[0] in {1: 2}",
    "return d[0] in {1, 2}",
    "return {d[0]: 1}",
    "t = {}\n    t[d[0]] = 1\n    return t",
    "return set(d)",
])
def test_a_secret_used_as_a_dict_key_or_set_member_is_refused(body):
    vm = ci.Cipher(f"def f(d):\n    {body}\n").fresh()
    _syms, x = ci.make_input("bytes", 2)
    with pytest.raises(cvm.Unsupported, match="dict key|dict or set|set member|index or key"):
        vm.root.vars["f"](x)
    assert vm.root.vars["f"](b"\x01\x02") is not None     # the same code is fine on concrete bytes


def test_a_hash_of_the_secret_is_refused_by_name():
    vm = ci.Cipher("import hashlib\ndef f(d):\n    return hashlib.sha256(d).digest()\n").fresh()
    _syms, x = ci.make_input("bytes", 4)
    with pytest.raises(cvm.Unsupported, match="hash of secret-dependent data"):
        vm.root.vars["f"](x)


# ============================================================ symbolic integers keep Python's meaning

def _sel(c, a, b):
    return cvm.ite(c, a, b)


def _tab(table, i):
    return cvm.lookup(table, i) if isinstance(i, cvm.Sym) else table[i]


EXPRS = [
    lambda x, y: (x + y) & 0xFF,
    lambda x, y: (x - y) & 0xFFFF,
    lambda x, y: (x - 200) % 26,                       # Python's % of a negative value
    lambda x, y: (-x) % 256,
    lambda x, y: (~x) & 0xFF,
    lambda x, y: ((x << 3) | (x >> 5)) & 0xFF,
    lambda x, y: (x * 37 + y * 11) % 251,
    lambda x, y: (x * y) & 0xFFFF,
    lambda x, y: (x ^ y) // 7,
    lambda x, y: (x + 300) // 16 + (x & 15),
    lambda x, y: _sel(x > y, x - y, y - x),
    lambda x, y: _sel(x & 1, x ^ 0x55, (x + 3) & 0xFF),
    lambda x, y: (x | 0x100) - (y & 0x0F),
    lambda x, y: ((x - y) ^ 0x33) & 0x7F,              # xor of a possibly negative value, then masked
    lambda x, y: (x % 1) + (x // 1) + (x & -1),
    lambda x, y: (x - 300) * (y - 100),                # a product of two possibly negative values
    lambda x, y: ((x - y) ^ 0x33) % 256,               # a power-of-two modulus is a mask, any range
]


@pytest.mark.parametrize("i", range(len(EXPRS)))
def test_symbolic_arithmetic_equals_python_integer_arithmetic(i):
    f = EXPRS[i]
    sx, sy = cvm.Sym("in", (0,), (0, 255)), cvm.Sym("in", (1,), (0, 255))
    node = f(sx, sy)
    rng = random.Random(1000 + i)
    samples = [(0, 0), (255, 255), (0, 255), (255, 0), (200, 199), (1, 2)] + \
              [(rng.randrange(256), rng.randrange(256)) for _ in range(60)]
    for x, y in samples:
        want = f(x, y)
        assert cvm.evaluate([node], {0: x, 1: y}) == [want], (x, y)
        if isinstance(node, cvm.Sym) and node.rng is not None:
            assert node.rng[0] <= want <= node.rng[1]          # the range bound really bounds


def test_what_the_dag_cannot_express_is_refused_by_name():
    x = cvm.Sym("in", (0,), (0, 255))
    with pytest.raises(cvm.Unsupported, match="shift count"):
        1 << x
    with pytest.raises(cvm.Unsupported, match="may be negative"):
        (x - 1) >> 1
    with pytest.raises(cvm.Unsupported, match="modulus or divisor depends on the secret"):
        x % x
    with pytest.raises(cvm.Unsupported, match="outside its table"):
        cvm.lookup([1, 2, 3], x)
    with pytest.raises(cvm.Unsupported, match="may be negative"):
        cvm.mkbytes([x - 1])
    # a byte that may exceed 255 keeps its low 8 bits (CPython would raise for such an input)
    wide = cvm.mkbytes([x + 1])
    assert cvm.evaluate(wide.items, {0: 7}) == [8] and cvm.evaluate(wide.items, {0: 255}) == [0]
    with pytest.raises(cvm.Unsupported, match="may not fit"):
        (x * 300).to_bytes(1, "big")
    assert (x < 256) is True and (x > 255) is False and (x == 300) is False   # decided by the range


# ============================================================ known-bits propagation: every rule sound

TABLE = [(i * 167 + 13) % 256 for i in range(256)]                 # a permutation of 0..255
LOSSY = [(i * i + 7) % 64 for i in range(256)]                     # many indices share a value


def _random_steps(rng, n_inputs, n_ops):
    steps = []
    for k in range(n_ops):
        pool = n_inputs + k
        steps.append((rng.choice(["xor", "add", "sub", "mulc", "andc", "or", "and", "shl", "shr",
                                  "rot", "box", "lossy", "mod", "div", "ite", "cmp", "neg",
                                  "modneg", "cmpneg", "inv"]),
                      rng.randrange(pool), rng.randrange(pool), rng.randrange(pool),
                      rng.randrange(1, 1 << 16), rng.randrange(1, 15)))
    return steps


def _apply(steps, vals):
    """The same arithmetic on Syms and on ints (every value is kept inside 16 bits)."""
    vals = list(vals)
    for op, i, j, k, c, s in steps:
        a, b, d = vals[i], vals[j], vals[k]
        if op == "xor":
            v = a ^ b
        elif op == "add":
            v = (a + b) & 0xFFFF
        elif op == "sub":
            v = (a - b) & 0xFFFF
        elif op == "mulc":
            v = (a * c) & 0xFFFF
        elif op == "andc":
            v = a & c
        elif op == "and":
            v = a & b
        elif op == "or":
            v = a | b
        elif op == "shl":
            v = (a << s) & 0xFFFF
        elif op == "shr":
            v = a >> s
        elif op == "rot":
            v = ((a << s) | (a >> (16 - s))) & 0xFFFF
        elif op == "box":
            v = _tab(TABLE, a & 0xFF) | (a & 0xFF00)
        elif op == "lossy":
            v = _tab(LOSSY, a & 0xFF)
        elif op == "mod":
            v = (a & 0xFFF) % (c % 250 + 3)
        elif op == "div":
            v = (a & 0xFFF) // (c % 250 + 3)
        elif op == "ite":
            v = _sel(a & 1, b, d)
        elif op == "cmp":
            v = _sel(a < b, d, a ^ 1)
        elif op == "modneg":                         # % of a value that may be negative
            v = ((a & 0xFF) - (c & 0x1FF)) % (s + 11)
        elif op == "cmpneg":                         # a comparison between possibly negative values
            v = _sel((a & 0xFF) - 100 < (b & 0x3F) - s, d, a)
        elif op == "inv":
            v = (~a) & 0xFFFF
        else:
            v = (-a) & 0xFFFF
        vals.append(v)
    return vals


def _case(seed):
    """A random program whose last values depend on the input (a draw whose last three values all
    fold to constants is drawn again, so every seed is a real case)."""
    rng = random.Random(seed)
    while True:
        n_in = rng.randrange(1, 4)
        steps = _random_steps(rng, n_in, rng.randrange(4, 22))
        inputs = [rng.randrange(1 << 16) for _ in range(n_in)]
        syms = [cvm.Sym("in", (i,), (0, 0xFFFF)) for i in range(n_in)]
        svals, ivals = _apply(steps, syms), _apply(steps, inputs)
        outs = [(s, v) for s, v in zip(svals[-3:], ivals[-3:]) if isinstance(s, cvm.Sym)]
        if outs:
            return inputs, svals, ivals, outs


@pytest.mark.parametrize("seed", range(120))
def test_propagation_only_ever_learns_true_bits(seed):
    inputs, svals, ivals, outs = _case(seed)
    assert cvm.evaluate(svals, dict(enumerate(inputs))) == ivals    # the trace means what Python means
    net = ci.Net(outs)
    net.propagate()                                  # the true output can never be a contradiction
    truth = cvm.evaluate(net.order, dict(enumerate(inputs)))
    learned = 0
    for n, tv in zip(net.order, truth):
        w = net.W[n.uid]
        assert net.K[n.uid] >> w == 0
        assert (tv & ((1 << w) - 1)) & net.K[n.uid] == net.V[n.uid], (n.op, n.uid)
        learned += bin(net.K[n.uid]).count("1")
    assert learned >= sum(net.W[a.uid] for a, _ in outs) // 3       # and it does learn something
    for i, v in net.solved().items():
        assert v == inputs[i]


@pytest.mark.needs_tool("py:z3")
@pytest.mark.parametrize("seed", range(40))
def test_z3_lowering_agrees_with_the_trace(seed):
    import z3
    inputs, _svals, _ivals, outs = _case(seed)
    net = ci.Net(outs)                               # NOT propagated: z3 has to carry the meaning
    vs = {i: z3.BitVec(f"x{i}", 16) for i in net.inputs}
    pin = [vs[i] == inputs[i] for i in vs]
    s = z3.Solver()
    s.add(net.constraints(z3, vs) + pin)
    assert s.check() == z3.sat                       # the real input satisfies the lowered network
    a, v = outs[-1]
    wrong = ci.Net(outs[:-1] + [(a, v ^ 1)])
    s = z3.Solver()
    s.add(wrong.constraints(z3, {i: vs[i] for i in wrong.inputs})
          + [vs[i] == inputs[i] for i in wrong.inputs])
    assert s.check() == z3.unsat                     # and no other output value does


def test_propagation_reports_a_contradiction_for_an_impossible_target():
    x = cvm.Sym("in", (0,), (0, 255))
    net = ci.Net([((x | 1) & 0xFF, 0x40)])           # bit 0 of the output is always 1
    with pytest.raises(ci._Conflict):
        net.propagate()
    net = ci.Net([(cvm.lookup(LOSSY, x), 63 if 63 not in LOSSY else 64)])
    with pytest.raises(ci._Conflict):
        net.propagate()
    with pytest.raises(ci._Conflict):
        ci.Net([((x * 6) & 0xFF, 0x05)]).propagate()             # 6x is never odd
    with pytest.raises(ci._Conflict):
        ci.Net([(x & 0x0F, 0x1F)]).propagate()                   # wider than the value can be
    idx = x % 200
    with pytest.raises(ci._Conflict):                            # no x has x % 200 == 250
        ci.Net([(idx, 250)]).propagate()
    # a table index pinned outside the table is a contradiction, not an IndexError
    hit = cvm.lookup(list(range(200)), idx)
    net = ci.Net([(hit, 5)])
    net.K[idx.uid], net.V[idx.uid] = 0xFF, 250
    with pytest.raises(ci._Conflict):
        net._step(hit)


def test_a_carry_is_known_where_two_of_its_inputs_agree():
    # (x & 0x0F) + 0x30: the low four bits of the constant are zero and the carry in is zero, so no
    # carry leaves them whatever x is, and the top bits of the sum are 0b11 before x is known
    x, k = cvm.Sym("in", (0,), (0, 255)), cvm.Sym("in", (1,), (0, 3))
    s = (x & 0x0F) + 0x30
    net = ci.Net([((s >> 4) ^ k, 2)])
    net.propagate()
    assert net.solved() == {1: 2 ^ 3}                # k follows; x stays open
    assert net.K[s.uid] == 0x30 and net.V[s.uid] == 0x30


# ============================================================ algebraic inversion, primitive by primitive

ALGEBRAIC = {
    # name: (source, function, secret, input type, size)
    "xorshift-mixer": ('''
M = (1 << 64) - 1
def mix(x):
    x ^= x >> 29
    x = (x * 0xBF58476D1CE4E5B9) & M
    x ^= x >> 32
    x = (x + 0x1234567) & M
    x ^= (x << 17) & M
    return x
''', "mix", 0x0123456789ABCDEF, "int", 64),
    "add-with-carries": ("def f(x):\n    return (x + (x << 3) + (x << 7)) & 0xFFFFFFFF\n",
                         "f", 0xC0FFEE11, "int", 32),
    "even-multiplier-on-7-bits": ("def f(x):\n    return (x * 6) & 0xFF\n", "f", 0x5B, "int", 7),
    "subtract-negate-invert": ("def f(d):\n    return [(b - 200) & 0xFF for b in d] + "
                               "[(-b) % 256 for b in d] + [(~b) & 0xFF for b in d]\n",
                               "f", b"\x00\x7f\x80\xff", "bytes", 4),
    "mod-by-enumeration": ("def f(d):\n    return [(b + 100) % 257 for b in d]\n",
                           "f", b"\x00\x05\x9c\x9d\xff", "bytes", 5),
    # 99 sits at indices 3 and 12, which share no bit: only the index bit known from the second
    # output (bit 0) tells them apart
    "table-pruned-by-known-index-bits": (
        "T = [0, 1, 2, 99, 4, 5, 6, 7, 8, 9, 10, 11, 99, 13, 14, 15]\n"
        "def f(d):\n    return [T[b & 15] for b in d] + [b & 1 for b in d] + [b >> 4 for b in d]\n",
        "f", b"\x53\x5c", "bytes", 2),
    "lossy-table-unique-preimage": ("T = [i // 3 for i in range(256)]\nT[77] = 250\n"
                                    "def f(d):\n    return [T[b] for b in d]\n", "f", b"M", "bytes", 1),
    "select-fixed-by-another-output": (
        "def f(d):\n    return [b & 1 for b in d] + "
        "[(b ^ 0x55) if b & 1 else (b + 3) & 0xFF for b in d]\n", "f", b"\x10\x11\xfe\xff", "bytes", 4),
    "compare-fixed-by-another-output": (
        "def f(d):\n    return [b & 0xF0 for b in d] + "
        "[(b ^ 0x55) if (b & 0xF0) > 0x70 else (b + 3) & 0xFF for b in d]\n",
        "f", b"\x10\x7f\x80\xff", "bytes", 4),
    "rotate-and-pack": ('''
def f(d):
    x = int.from_bytes(d, 'little')
    x = ((x << 11) | (x >> 21)) & 0xFFFFFFFF
    x = x * 256 + 0x7E
    return x.to_bytes(5, 'big')
''', "f", b"\x01\x02\xfe\xff", "bytes", 4),
    "two-tables-of-one-size": (
        "A = [(i * 7 + 3) % 16 for i in range(16)]\nB = [(i * 11 + 5) % 16 for i in range(16)]\n"
        "def f(d):\n    return [A[b & 15] << 4 | B[b >> 4] for b in d]\n",
        "f", b"\x00\x1f\xa5\xff", "bytes", 4),
    "cbc-chained-sbox": ('''
S = [(i * 91 + 17) % 256 for i in range(256)]
def f(d):
    prev, out = 0xA7, []
    for b in d:
        prev = S[b ^ prev]
        out.append(prev)
    return bytes(out)
''', "f", b"chained through S", "bytes", 17),
}


@pytest.mark.parametrize("name", sorted(ALGEBRAIC))
def test_algebraic_inverse_needs_no_solver(name):
    src, fn, secret, kind, size = ALGEBRAIC[name]
    out = native(src, fn, secret)
    rep = rec(src, target=out if not isinstance(out, list) else [out], func=fn, kind=kind,
              length=size, use_smt=False, use_blackbox=False)
    r = only(rep)
    assert r.method == "algebraic" and r.unique and r.values == [secret]
    assert (r.func, r.kind, r.length) == (fn, kind, size)


def test_the_block_scrambler_is_inverted_end_to_end_with_everything_discovered():
    secret = b"open-the-synthetic-vault-0123456789abcdef"            # 41 bytes -> 48 sealed
    sealed = native(SPN, "seal", secret)
    assert len(sealed) == 48
    rep = rec(SPN + f"\nSEALED = bytes.fromhex('{sealed.hex()}')\n", use_smt=False, use_blackbox=False)
    r = only(rep)
    assert r.values == [secret] and r.method == "algebraic" and r.unique
    assert r.func == "seal" and r.target == "variable SEALED" and (r.kind, r.length) == ("bytes", 41)
    assert r.primitives["s-box"] >= 6 * 5 * 8 and r.primitives["xor"] and r.primitives["add"]
    # the other padded lengths were tried and proved impossible, not guessed
    assert any("outside what the function can produce" in n for n in rep.notes)


def test_a_wrong_target_has_no_preimage_and_nothing_is_reported():
    sealed = bytearray(native(SPN, "seal", b"twelve bytes"))
    sealed[-1] ^= 0x01                               # the padding of the last block no longer decodes
    rep = rec(SPN, target=bytes(sealed), func="seal")
    assert rep.recovered == [] and not rep.promising and not rep.incomplete   # refuted, not open
    assert any("outside what the function can produce" in n for n in rep.notes)


def test_a_recovered_input_is_rerun_forward_before_it_is_reported(monkeypatch):
    src = "def f(d):\n    return bytes(b ^ 0x21 for b in d)\n"
    monkeypatch.setattr(ci.Net, "solved", lambda self: {i: 0x41 for i in self.inputs})
    rep = rec(src, target=native(src, "f", b"secret"), func="f", kind="bytes", length=6)
    assert rep.recovered == []                       # a wrong solution never leaves the engine
    assert any("does not reproduce the target" in n for n in rep.notes)


def test_each_forward_run_starts_from_a_fresh_module_state():
    # the keystream comes from module state that every call advances: tracing, then verifying, must
    # both start from the module's initial state or the verification would see another stream
    src = '''
import random
random.seed(7)
def enc(d):
    return bytes(b ^ random.randint(0, 255) for b in d)
'''
    r = random.Random(7)
    want = bytes(b ^ r.randint(0, 255) for b in b"stateful stream")
    got = only(rec(src, target=want, func="enc", kind="bytes"))
    assert got.values == [b"stateful stream"] and got.method == "algebraic"


def test_input_positions_that_do_not_matter_are_said_so():
    src = "def f(d):\n    return bytes(b ^ 3 for b in d[:3])\n"
    r = only(rec(src, target=bytes(b ^ 3 for b in b"abc"), func="f", kind="bytes", length=5))
    assert r.values == [b"abc\x00\x00"] and not r.unique
    assert "2 input position(s) do not affect the output" in r.caveat


# ============================================================ a checker states its own target

def test_a_checker_function_is_inverted_from_its_own_comparison():
    secret = b"the checker names its target"
    sealed = native(SPN, "seal", secret)
    src = SPN + f"\nSEALED = bytes.fromhex('{sealed.hex()}')\n" \
                "def check(guess):\n    return seal(guess) == SEALED\n"
    r = only(rec(src, use_smt=False, use_blackbox=False))
    assert r.func == "check" and r.target == "the function's own comparison"
    assert r.values == [secret] and r.method == "algebraic" and r.unique
    assert native(src, "check", secret) is True


@pytest.mark.parametrize("body, secret", [
    ("return len(s) == 6 and [ord(c) ^ 5 for c in s] == [100, 103, 102, 97, 96, 99]", "abcdef"),
    ("return ''.join(chr(ord(c) + 1) for c in s) == 'bcdefg'", "abcdef"),
    ("return tuple(b ^ k for b, k in zip(s, s[1:] + s[:1])) == (3, 1, 7, 1, 3, 7)", None),
    ("return bytes(b ^ 0x10 for b in s) + b'!' == b'qrstuv!'", b"abcdef"),
])
def test_checkers_over_lists_text_tuples_and_bytes(body, secret):
    src = f"def check(s):\n    {body}\n"
    kind = "str" if isinstance(secret, str) else "bytes"
    rep = rec(src, target=ci.TRUTH, kind=kind, length=6, use_blackbox=False, use_smt=False)
    if secret is None:               # s[i] ^ s[i+1] fixes the input only up to one free byte
        assert rep.recovered == [] and rep.promising
        return
    r = only(rep)
    assert r.values == [secret] and r.method == "algebraic" and r.unique
    assert native(src, "check", secret) is True


def test_sequence_equality_on_secret_data():
    x, y = cvm.Sym("in", (0,), (0, 255)), cvm.Sym("in", (1,), (0, 255))
    sb = cvm.SymBytes([x, 7, y])
    assert cvm.sequence_equal(sb, b"ab") is False                    # lengths differ
    assert cvm.sequence_equal(cvm.SymBytes([x, y]), b"abc") is False   # ... whatever the prefix is
    assert cvm.sequence_equal(sb, b"a\x08c") is False                # a constant position differs
    assert cvm.sequence_equal(sb, [1, 7, 3]) is False                # bytes are never equal to a list
    assert cvm.sequence_equal(cvm.SymBytes([x]), cvm.SymBytes([x])) is True
    chk = cvm.sequence_equal(sb, b"a\x07c")
    assert isinstance(chk, cvm.Check) and chk.pairs == [(x, 0x61), (y, 0x63)]
    both = cvm.sequence_equal([x, 5], [y, 5])
    assert cvm.evaluate([both.pairs[0][0]], {0: 9, 1: 9}) == [both.pairs[0][1]] == [0]
    with pytest.raises(cvm.Unsupported, match="comparison of secret-dependent data"):
        bool(chk)
    vm = ci.Cipher("def f(d):\n    if bytes(b ^ 1 for b in d) == b'ab':\n        return 1\n    return 0\n"
                   "def g(d):\n    return bytes(b ^ 1 for b in d) != b'ab'\n").fresh()
    _syms, sym = ci.make_input("bytes", 2)
    with pytest.raises(cvm.Unsupported, match="comparison of secret-dependent data"):
        vm.root.vars["f"](sym)
    with pytest.raises(cvm.Unsupported, match="inequality test on secret-dependent data"):
        vm.root.vars["g"](sym)
    assert vm.root.vars["g"](b"`c") is False and vm.root.vars["f"](b"xx") == 0   # concrete: plain Python


def test_verify_needs_every_output_position_to_match():
    src = "def f(d):\n    return bytes(b ^ 1 for b in d)\n"
    cipher = ci.Cipher(src)
    fwd = ci.find_forwards(cipher.fresh())[0]
    def t(v):
        return ci.Target("test", v)
    assert ci.verify(cipher, fwd, b"abc", t(b"`cb")) is True
    # x reproduces some positions of the target but not all: that is not a preimage
    assert ci.verify(cipher, fwd, b"abc", t(b"`cX")) is False
    assert ci.verify(cipher, fwd, b"abc", t(b"Xcb")) is False
    assert ci.verify(cipher, fwd, b"abc", t(b"`Xb")) is False


def test_a_checker_result_is_verified_by_the_checker_saying_true():
    src = "def check(s):\n    return bytes(b ^ 0x10 for b in s) == b'qrstuv'\n"
    cipher = ci.Cipher(src)
    fwd = ci.find_forwards(cipher.fresh())[0]
    assert ci.verify(cipher, fwd, b"abcdef", ci.TRUTH) is True
    assert ci.verify(cipher, fwd, b"abcdeX", ci.TRUTH) is False      # a concrete False is not a match
    assert ci.verify(cipher, fwd, b"abc", ci.TRUTH) is False
    assert ci.pairs_for("true", ci.TRUTH) is None and ci.pairs_for(1, ci.TRUTH) is None


def test_a_checker_that_is_false_for_every_input_has_no_preimage():
    src = "def check(s):\n    return bytes(b | 1 for b in s) == b'\\x40\\x41'\n"
    rep = rec(src, target=ci.TRUTH, kind="bytes", length=2, use_blackbox=False)
    assert rep.recovered == [] and not rep.promising
    assert any("outside what the function can produce" in n for n in rep.notes)


# ============================================================ the SMT fallback

KLIMOV = "def mix(x):\n    return (x + ((x * x) | 5)) & 0xFFFFFFFF\n"       # a bijection propagation cannot undo
XTIME = "def f(d):\n    return bytes((((b << 1) ^ 0x1B) & 0xFF) if b & 0x80 else (b << 1) for b in d)\n"


@pytest.mark.needs_tool("py:z3")
def test_smt_fallback_inverts_what_propagation_cannot_and_proves_it_unique():
    want = native(KLIMOV, "mix", 0xDEADBEEF)
    r = only(rec(KLIMOV, target=want, kind="int", length=32))
    assert r.method == "smt" and r.unique and r.values == [0xDEADBEEF]
    r = only(rec(XTIME, target=native(XTIME, "f", b"\x00\x7f\x80\xc3\xff"), kind="bytes"))
    assert r.method == "smt" and r.unique and r.values == [b"\x00\x7f\x80\xc3\xff"]


def test_without_the_smt_fallback_the_same_cipher_is_left_unsolved_and_named():
    rep = rec(KLIMOV, target=native(KLIMOV, "mix", 0xDEADBEEF), kind="int", length=32,
              use_smt=False)
    assert rep.recovered == [] and rep.promising
    assert any("not determined by propagation" in n for n in rep.notes)


@pytest.mark.needs_tool("py:z3")
def test_several_preimages_are_all_reported_and_none_called_unique():
    src = "def f(d):\n    return bytes(b | 1 for b in d)\n"
    r = only(rec(src, target=b"\x41\x43", kind="bytes", length=2))
    assert r.method == "smt" and not r.unique
    assert sorted(r.values) == [b"\x40\x42", b"\x40\x43", b"\x41\x42", b"\x41\x43"]
    assert "4 inputs give the target" in r.caveat


@pytest.mark.needs_tool("py:z3")
def test_an_underconstrained_cipher_is_retried_over_printable_ascii_and_says_so():
    src = "def f(d):\n    return bytes((b & 0x7F) ^ 0x15 for b in d)\n"   # 2**6 preimages over all bytes
    r = only(rec(src, target=native(src, "f", b"sixchr"), kind="bytes", length=6))
    assert r.values == [b"sixchr"] and r.method == "smt" and not r.unique
    assert "unique only among printable-ASCII inputs" in r.caveat


@pytest.mark.needs_tool("py:z3")
def test_a_given_charset_constrains_the_solver():
    src = "def f(d):\n    return bytes(b & 0xDF for b in d)\n"      # folds case: 2 preimages per letter
    r = only(rec(src, target=b"KEY", kind="bytes", length=3, charset="lower"))
    assert r.values == [b"key"] and not r.unique and "given character set" in r.caveat


@pytest.mark.needs_tool("py:z3")
def test_z3_proving_there_is_no_input_is_reported_as_no_preimage():
    src = "def f(x):\n    return (x * x) & 0xFF\n"                  # squares mod 256 are never 3
    rep = rec(src, target=3, kind="int", length=8, use_blackbox=False)
    assert rep.recovered == []
    assert any("z3 proved no input" in n for n in rep.notes)


@pytest.mark.needs_tool("py:z3")
def test_z3_proving_no_input_within_a_given_charset_is_no_preimage():
    # XTIME is a bijection propagation cannot undo, so only z3 decides it: the target's preimage is
    # b"xyz", outside the charset the caller gave, so z3 proves there is none and that is final
    rep = rec(XTIME, target=native(XTIME, "f", b"xyz"), kind="bytes", length=3, charset="abc",
              use_blackbox=False)
    assert rep.recovered == [] and not rep.promising and not rep.incomplete
    assert any("z3 proved no input" in n and "within the character set" in n for n in rep.notes)
    r = only(rec(XTIME, target=native(XTIME, "f", b"cab"), kind="bytes", length=3, charset="abc",
                 use_blackbox=False))
    assert r.values == [b"cab"] and r.method == "smt"


def test_a_missing_z3_blocks_the_fallback_by_name(monkeypatch, tmp_path):
    def no_z3():
        raise RuntimeError("symbolic.py needs z3 (pip install z3-solver)")

    monkeypatch.setattr(ci, "_symbolic", no_z3)
    rep = rec(KLIMOV, target=native(KLIMOV, "mix", 77), kind="int", length=32)
    assert rep.recovered == [] and "needs z3" in rep.blocked
    chal = _chal(tmp_path, {"mix.py": KLIMOV})
    res = ci.solve(chal, CSCTF, target=f"int:{native(KLIMOV, 'mix', 0xDEADBEEF)}", input="int",
                   length=32, budget_s=BIG)
    assert res.status == "blocked" and "z3" in res.notes
    # the algebraic pass does not need z3 at all
    src = "def f(d):\n    return bytes(b ^ 9 for b in d)\n"
    assert only(rec(src, target=bytes(b ^ 9 for b in b"plain"))).values == [b"plain"]


# ============================================================ the black-box search

CAESAR = '''
def enc(s):
    out = []
    for i, c in enumerate(s):
        if c.isalpha():
            base = ord('a') if c.islower() else ord('A')
            out.append(chr((ord(c) - base + 3 + i) % 26 + base))
        else:
            out.append(c)
    return ''.join(out)
'''


def test_a_cipher_that_branches_on_the_secret_is_recovered_position_by_position():
    secret = "Dawn at 6!"
    r = only(rec(CAESAR, target="str:" + native(CAESAR, "enc", secret),
                 charset="Dawnt 6!abcXYZ05", use_smt=False))
    assert r.method == "blackbox" and r.values == [secret] and r.kind == "str"
    assert not r.unique and "given character set" in r.caveat


def test_the_black_box_search_follows_measured_dependence_not_position_order():
    # output position k depends on input positions k.. (a suffix chain) and the order is reversed
    src = '''
def enc(d):
    acc, out = 0, []
    for b in reversed(d):
        acc = (acc + b) % 251 if b % 2 else (acc ^ b)
        out.append(acc)
    return out
'''
    secret = b"abcab"
    r = only(rec(src, target=[native(src, "enc", secret)], kind="bytes", length=5, charset="abc",
                 use_smt=False))
    assert r.method == "blackbox" and r.values == [secret]


def test_with_the_black_box_search_off_the_branching_cipher_is_unsolved_and_named():
    rep = rec(CAESAR, target="str:" + native(CAESAR, "enc", "Dawn"), kind="str", length=4,
              use_blackbox=False)
    assert rep.recovered == [] and rep.promising     # it runs and its output fits: left open, named
    assert any("cannot trace" in n and "isalpha" in n for n in rep.notes)


def test_black_box_sweeps_lengths_when_the_output_is_longer_than_the_input():
    src = '''
def enc(d):
    out = [0x7E]
    for b in d:
        if b % 2:
            out.append((b + 1) % 256)
        else:
            out.append(b ^ 0x20)
    return bytes(out)
'''
    r = only(rec(src, target=native(src, "enc", b"abca"), kind="bytes", charset="abc", use_smt=False))
    assert r.method == "blackbox" and r.values == [b"abca"] and r.length == 4


def test_black_box_leaves_positions_the_output_ignores_and_says_so():
    src = '''
def enc(d):
    out = []
    for b in d[:3]:
        if b % 2:
            out.append((b * 3) % 256)
        else:
            out.append(b ^ 0x20)
    return bytes(out)
'''
    r = only(rec(src, target=native(src, "enc", b"bcd"), kind="bytes", length=5, charset="abcd",
                 use_smt=False))
    assert r.method == "blackbox" and r.values == [b"bcdaa"] and not r.unique
    assert "2 input position(s) do not affect the output and were left as 'a'" in r.caveat


def test_what_the_black_box_search_finds_is_rerun_in_a_fresh_interpreter(monkeypatch):
    monkeypatch.setattr(ci, "verify", lambda *a, **k: False)
    rep = rec(CAESAR, target="str:" + native(CAESAR, "enc", "Dawn"), kind="str", length=4,
              charset="Dawnxyz", use_smt=False)
    assert rep.recovered == []
    assert any("black-box search found no input that verifies" in n for n in rep.notes)


def test_black_box_gives_up_on_a_cipher_with_no_positional_structure():
    src = '''
def enc(d):
    t = sum(d) % 256
    return bytes((b + t) % 256 if t % 2 else (b ^ t) for b in d)
'''
    rep = rec(src, target=native(src, "enc", b"abcd"), kind="bytes", length=4, charset="abcd",
              use_smt=False)
    assert rep.recovered == [] and rep.promising
    assert any("black-box search" in n for n in rep.notes)


# ============================================================ finding the function, the key and the target

def test_other_parameters_are_bound_from_module_variables_of_the_same_name():
    src = '''
KEY = b"module key"
def encrypt(msg, key):
    return bytes((m + key[i % len(key)]) & 0xFF for i, m in enumerate(msg))
'''
    want = native(src, "encrypt", b"bound from KEY", b"module key")
    r = only(rec(src, target=want))
    assert r.values == [b"bound from KEY"] and r.func == "encrypt"


def test_a_method_of_a_module_level_instance_is_a_forward_function():
    src, fn, secret = CIPHERS["klass"]
    out = native(src, fn, secret)
    src_no_wrapper = src[:src.index("def encrypt(block)")]
    r = only(rec(src_no_wrapper, target=[out]))
    assert r.func == "box.encrypt" and r.values == [secret]


def test_helpers_rank_below_the_top_level_cipher_function():
    vm = ci.Cipher(SPN).fresh()
    labels = [f.label for f in ci.find_forwards(vm)]
    assert labels[0] == "seal" and "enc_block" in labels and "lcg" not in labels
    assert [f.label for f in ci.find_forwards(vm, func="enc_block")] == ["enc_block"]
    vm = ci.Cipher("def _mix(d):\n    return d\ndef mix(d):\n    return d\n"
                   "def check(d):\n    return d\ndef decode(d):\n    return d\n").fresh()
    # a cipher-like name first (ties keep source order), a private helper lower, a decoder last
    assert [f.label for f in ci.find_forwards(vm)] == ["mix", "check", "_mix", "decode"]


def test_a_conversion_helper_that_returns_the_target_unchanged_is_not_an_inversion(tmp_path):
    helpers = ("def as_bytes(x):\n    return bytes(x)\n"
               "def tidy(s):\n    return s.strip()\n"
               "def ident(n):\n    return n\n")
    rep = rec(helpers, target=b"printable target")
    assert rep.recovered == [] and not rep.promising
    assert any("returns this target unchanged" in n for n in rep.notes)
    assert rec(helpers, target="str:some text").recovered == []
    assert rec(helpers, target=123456789012345).recovered == []
    # ... and it does not hide the cipher that follows it
    src = helpers + "def stage2(d):\n    return bytes(b ^ 0x2A for b in d)\n"
    r = only(rec(src, target=bytes(b ^ 0x2A for b in b"CSCTF{past_the_helpers}")))
    assert r.func == "stage2" and r.values == [b"CSCTF{past_the_helpers}"]
    chal = _chal(tmp_path, {"util.py": helpers, "data.txt": "deadbeefcafebabe00112233"})
    assert ci.solve(chal, CSCTF, budget_s=BIG).status == "none"


def test_a_yes_no_predicate_that_cannot_be_traced_is_not_searched_or_left_open(tmp_path):
    # true for many inputs, branches on the secret: the black-box search has one bit to follow
    src = ("def is_ok(s):\n    for c in s:\n        if c < 32 or c > 126:\n            return False\n"
           "    return True\n")
    rep = rec(src, target=ci.TRUTH, kind="bytes", length=6)
    assert rep.recovered == [] and not rep.promising and not rep.incomplete
    chal = _chal(tmp_path, {"p.py": src, "out.bin": b"0123456789"})
    assert ci.solve(chal, CSCTF, budget_s=BIG).status == "none"


def test_black_box_does_not_report_an_output_the_input_never_changes():
    src = "def enc(d):\n    if d[0] > 100:\n        return b'fixed'\n    return b'fixed'\n"
    rep = rec(src, target=b"fixed", kind="bytes", length=5, charset="abc", use_smt=False)
    assert rep.recovered == [] and not rep.promising
    assert any("does not change with the input" in n for n in rep.notes)


def test_hex_text_output_is_matched_against_hex_and_bytes_targets():
    src = "def enc(d):\n    return bytes(b ^ 0x5C for b in d).hex()\n"
    out = native(src, "enc", b"hex text")
    for target in (out, "str:" + out, bytes.fromhex(out)):
        assert only(rec(src, target=target)).values == [b"hex text"]


def test_base64_output_and_text_input():
    src = ("import base64\ndef enc(s):\n"
           "    return base64.b64encode(bytes((ord(c) + 1) & 0xFF for c in s)).decode()\n")
    out = native(src, "enc", "text in, b64 out")
    r = only(rec(src, target="str:" + out))
    assert r.values == ["text in, b64 out"] and r.kind == "str"


def test_module_mode_takes_the_unavailable_variable_as_the_secret():
    src = '''
flag = open("flag.txt").read().strip()
enc = []
for i, c in enumerate(flag):
    enc.append((ord(c) ^ (i * 7 + 3)) & 0xff)
print(enc)
'''
    secret = "CSCTF{module_mode}"
    printed = str([(ord(c) ^ (i * 7 + 3)) & 0xFF for i, c in enumerate(secret)])
    r = only(rec(src, side_texts=[("file output.txt", printed + "\n")]))
    assert r.func == "module:flag" and r.values == [secret] and r.target == "file output.txt (list)"


def test_module_mode_reads_imports_file_writes_and_fstrings():
    src = '''
from secret import FLAG
ct = bytes((b * 3 + 1) & 0xFF for b in FLAG)
with open("ct.bin", "wb") as f:
    f.write(ct)
'''
    want = bytes((b * 3 + 1) & 0xFF for b in b"written out")
    r = only(rec(src, side_blobs=[("file ct.bin", want)]))
    assert r.func == "module:FLAG" and r.values == [b"written out"]
    src = 'import os\nsecret = os.environ["S"].encode()\nprint(f"ct = {bytes(b ^ 7 for b in secret).hex()}")\n'
    r = only(rec(src, target=bytes(b ^ 7 for b in b"formatted")))
    assert r.func == "module:secret" and r.values == [b"formatted"]
    # naming the input and an output variable explicitly
    src = "PLAIN = b'REDACTED'\nresult = [p + 1 for p in PLAIN]\n"
    r = only(rec(src, target=[[c + 1 for c in b"named"]], input_name="PLAIN", output_name="result"))
    assert r.func == "module:PLAIN" and r.values == [b"named"]


def test_targets_are_found_and_ranked():
    vm = ci.Cipher(SPN + "\nSEALED = b'0123456789abcdef'\n").fresh()
    ts = ci.find_targets(vm, ci.Cipher(SPN + "\nSEALED = b'0123456789abcdef'\n"),
                         side_texts=[("file out.txt", "ct: deadbeef00112233\nnums [1, 2, 3, 4]\n"
                                                      "b64 QUJDREVGR0hJSktM 12345678901234\n")])
    labels = [t.label for t in ts]
    assert ts[0].value == bytes.fromhex("deadbeef00112233")          # a handout file ranks first
    found = {(t.label, repr(t.value)) for t in ts}
    assert ("file out.txt (hex integer)", repr(0xDEADBEEF00112233)) in found
    assert ("file out.txt (list)", repr([1, 2, 3, 4])) in found
    assert ("file out.txt (base64)", repr(b"ABCDEFGHIJKL")) in found
    assert ("file out.txt (integer)", repr(12345678901234)) in found
    assert not any(t.label == "file out.txt (text)" for t in ts)     # three lines are not one value
    assert [t.label for t in ci.text_targets("deadbeef00112233", "f")] == ["f (hex)", "f (hex integer)"]
    assert ci.text_targets("Khoor, Zruog", "f")[-1] == ci.Target("f (text)", "Khoor, Zruog")
    assert labels.index("variable SEALED") < labels.index("variable box")   # SEALED before the S-box


def test_parse_target_forms():
    assert ci.parse_target("hex:0aff").value == b"\x0a\xff"
    assert ci.parse_target("0AFF").value == b"\x0a\xff"
    assert ci.parse_target("b64:QUJD").value == b"ABC"
    assert ci.parse_target("int:0x10").value == 16
    assert ci.parse_target("str:0aff").value == "0aff"
    assert ci.parse_target("list:[1, 2]").value == [1, 2]
    assert ci.parse_target("not hex").value == "not hex"
    assert ci.parse_target(b"raw").value == b"raw" and ci.parse_target(5).value == 5
    for bad in ("hex:zz", "b64:!!", "int:x", "list:[1, 'a']", None, True, [1, "a"]):
        with pytest.raises(ci.InvertError):
            ci.parse_target(bad)


def test_candidate_lengths_and_charsets():
    ls = ci.candidate_lengths(48)
    assert ls[:3] == [48, 47, 46] and 32 in ls and 24 in ls and 16 in ls and 12 in ls and 6 in ls
    assert ls.index(32) < ls.index(24) and len(ls) == len(set(ls)) <= ci.MAX_LENGTHS
    assert ci.candidate_lengths(2) == [2, 1]
    assert ci.parse_charset("lower") == tuple(range(97, 123))
    assert ci.parse_charset("ba") == (97, 98) and ci.parse_charset((48, 50)) == (48, 49, 50)
    assert ci.parse_charset(None) is None
    with pytest.raises(ci.InvertError):
        ci.parse_charset("")


def test_bad_arguments_are_refused_by_name():
    with pytest.raises(ci.InvertError, match="input type"):
        rec("x = 1\n", kind="float")
    with pytest.raises(ci.InvertError, match="budget_s"):
        ci.recover("x = 1\n", budget_s=-1)
    with pytest.raises(ci.InvertError, match="length"):
        rec("x = 1\n", length=0)
    with pytest.raises(ci.InvertError, match="not parseable Python"):
        rec("def (:\n")
    with pytest.raises(ci.InvertError, match="larger than"):
        rec("#" * (ci.MAX_SOURCE_BYTES + 1))


def test_no_function_and_no_target_are_named():
    rep = rec("x = 1\n", target=b"abcdefgh")
    assert rep.recovered == [] and any("no forward function found" in n for n in rep.notes)
    rep = rec("def f(d):\n    return d\n")
    assert rep.recovered == [] and any("no target found" in n for n in rep.notes)


def test_the_time_budget_stops_the_sweep_on_an_injected_clock():
    ticks = itertools.count()
    rep = ci.recover(SPN, target=native(SPN, "seal", b"never reached"), budget_s=40,
                     clock=lambda: next(ticks))      # every look at the clock costs one second
    assert rep.recovered == [] and rep.incomplete
    assert any("time budget" in n for n in rep.notes)
    # a cipher too small to reach the interpreter's own clock check is still stopped between tries
    ticks = itertools.count()
    tiny = "def f(d):\n    return bytes(b ^ 1 for b in d) + b'!'\n"
    rep = ci.recover(tiny, target=b"no preimage: wrong tail", func="f", kind="bytes", budget_s=6,
                     clock=lambda: next(ticks))
    assert rep.incomplete and 1 <= rep.attempts <= 6
    assert any("time budget of 6 s used up" in n for n in rep.notes)


# ============================================================ the engine entry

def _chal(tmp_path, files, sub="files"):
    chal = tmp_path / "chal"
    for rel, data in files.items():
        p = chal / sub / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return chal


def test_solve_reports_a_flag_recovered_from_source_and_output_file(tmp_path):
    flag = b"CSCTF{sealed_by_a_synthetic_spn}"
    chal = _chal(tmp_path, {"scrambler.py": SPN, "sealed.txt": native(SPN, "seal", flag).hex() + "\n"})
    res = ci.solve(chal, CSCTF, budget_s=BIG)
    assert isinstance(res, SolverResult)
    assert res.status == "solved" and res.flags == (flag.decode(),)
    ev = res.evidence[0]
    assert ev.kind == "recovered-input" and ev.path == "files/scrambler.py"
    assert "algebraic" in ev.detail and "proved the only preimage" in ev.detail and "s-box" in ev.detail


def test_solve_is_unsure_with_the_passphrase_when_it_is_not_a_flag(tmp_path):
    secret = b"speak-this-to-the-vault"
    chal = _chal(tmp_path, {"scrambler.py": SPN, "sealed.bin": native(SPN, "seal", secret)})
    res = ci.solve(chal, CSCTF, budget_s=BIG)
    assert res.status == "unsure" and res.flags == ()
    assert repr(secret) in res.notes and "not itself a flag" in res.notes
    assert any(repr(secret) in e.detail for e in res.evidence)


@pytest.mark.needs_tool("py:z3")
def test_solve_reports_a_flag_that_is_not_proved_unique_as_a_candidate(tmp_path):
    src = "def f(d):\n    return bytes((b & 0x7F) ^ 0x15 for b in d)\n"
    chal = _chal(tmp_path, {"c.py": src, "out.bin": native(src, "f", b"CSCTF{seven_bits}")})
    res = ci.solve(chal, CSCTF, budget_s=BIG)
    assert res.status == "candidate" and res.flags == ("CSCTF{seven_bits}",)


def test_solve_finds_the_source_in_unpacked_and_skips_recon(tmp_path):
    secret = b"CSCTF{inside_the_archive}"
    chal = _chal(tmp_path, {"inner/scrambler.py": SPN,
                            "inner/sealed.txt": native(SPN, "seal", secret).hex()}, sub="unpacked")
    (chal / "recon").mkdir()
    (chal / "recon" / "bait.py").write_text("def f(d):\n    return d\n")
    (chal / "recon" / "bait.txt").write_text(secret.hex())
    res = ci.solve(chal, CSCTF, budget_s=BIG)
    assert res.status == "solved" and res.flags == (secret.decode(),)
    assert res.evidence[0].path == "unpacked/inner/scrambler.py"
    # a source that exists only under recon/ (an engine's own output) is not a handout source
    only_recon = tmp_path / "r"
    (only_recon / "recon" / "engines").mkdir(parents=True)
    (only_recon / "recon" / "engines" / "c.py").write_text("def f(d):\n    return bytes(d)\n")
    (only_recon / "recon" / "out.bin").write_bytes(b"CSCTF{from_recon}")
    (only_recon / "files").mkdir()
    (only_recon / "files" / "readme.txt").write_text("nothing")
    res = ci.solve(only_recon, CSCTF, budget_s=BIG)
    assert res.status == "none" and "no Python source" in res.notes


def test_the_same_file_in_files_and_unpacked_is_read_once(tmp_path):
    chal = _chal(tmp_path, {"a.py": SPN, "out.txt": "00112233"})
    _chal(tmp_path, {"copy/a.py": SPN, "copy/out.txt": "00112233", "other.py": "x = 1\n"},
          sub="unpacked")
    (chal / ".ctf").mkdir()
    (chal / ".ctf" / "session.py").write_text("x = 2\n")
    sources, others, over = ci._handout(chal)
    assert [str(f.relative_to(chal)) for f, _ in sources] == ["files/a.py", "unpacked/other.py"]
    assert [str(f.relative_to(chal)) for f, _ in others] == ["files/out.txt"] and over == 0


def test_solve_is_none_without_python_source_or_without_a_fit(tmp_path):
    chal = _chal(tmp_path, {"readme.txt": "no source here"})
    res = ci.solve(chal, CSCTF, budget_s=BIG)
    assert res.status == "none" and "no Python source" in res.notes
    app = ("import flask\napp = flask.Flask(__name__)\n\n@app.route('/')\ndef index():\n"
           "    return 'hi'\n\ndef helper(name):\n    return 'hello ' + name\n")
    chal2 = _chal(tmp_path / "b", {"app.py": app, "notes.txt": "deadbeefcafebabe0011"})
    res = ci.solve(chal2, CSCTF, budget_s=BIG)
    assert res.status == "none" and res.flags == ()


def test_solve_is_unsure_naming_why_when_a_fit_was_not_inverted(tmp_path):
    src = "import hashlib\ndef enc(d):\n    return hashlib.sha256(d).digest()\n"
    chal = _chal(tmp_path, {"h.py": src, "out.bin": native(src, "enc", b"x")})
    res = ci.solve(chal, CSCTF, input="bytes", length=3, charset="xyz", budget_s=BIG)
    assert res.status == "unsure" and res.flags == ()
    assert "hash of secret-dependent data" in res.notes


def test_a_binary_preimage_from_a_wrong_pairing_does_not_end_the_sweep(tmp_path):
    # scramble() ranks first by name and inverts the target to bytes that are not text; the sweep
    # goes on, finds the printable preimage under the real function, and lists that one first
    src = ("def scramble(d):\n    return bytes(b ^ 0x80 for b in d)\n"
           "def stage(d):\n    return bytes((b + 1) & 0xFF for b in d)\n")
    flag = b"CSCTF{printable_wins}"
    target = bytes((b + 1) & 0xFF for b in flag)
    rep = rec(src, target=target)
    assert [r.func for r in rep.recovered] == ["stage", "scramble"]
    assert rep.recovered[0].values == [flag]
    assert rep.recovered[1].values == [bytes(b ^ 0x80 for b in target)]
    res = ci.solve(_chal(tmp_path, {"two.py": src, "out.bin": target}), CSCTF, budget_s=BIG)
    assert res.status == "solved" and res.flags == (flag.decode(),)
    assert len(res.evidence) == 2
    # MAX_RESULTS bounds how many are kept when nothing is printable
    many = "".join(f"def f{i}(d):\n    return bytes(b ^ {0x80 + i} for b in d)\n" for i in range(7))
    rep = rec(many, target=b"\x01\x02\x03\x04")
    assert len(rep.recovered) == ci.MAX_RESULTS


def test_solve_stops_at_the_first_source_that_recovers(tmp_path):
    # two checkers, each naming its own target: sources are tried in path order, and the first that
    # recovers an input ends the sweep -- the second source's flag is never reported
    def checker(key, flag):
        enc = bytes(b ^ key for b in flag)
        return f"def check(s):\n    return bytes(b ^ {key} for b in s) == {enc!r}\n"
    chal = _chal(tmp_path, {"a.py": checker(1, b"CSCTF{first_source}"),
                            "b.py": checker(2, b"CSCTF{second_source}")})
    res = ci.solve(chal, CSCTF, budget_s=BIG)
    assert res.status == "solved" and res.flags == ("CSCTF{first_source}",)
    assert [e.path for e in res.evidence] == ["files/a.py"]
    assert "b.py" not in res.notes


def test_solve_passes_its_options_through(tmp_path):
    src = ("def a(d):\n    return bytes(b ^ 1 for b in d)\n"
           "def b(d):\n    return bytes(x ^ 2 for x in d)\n")
    chal = _chal(tmp_path, {"two.py": src})
    target = "hex:" + bytes(x ^ 2 for x in b"CSCTF{picked_b}").hex()
    res = ci.solve(chal, CSCTF, target=target, func="b", budget_s=BIG)
    assert res.status == "solved" and res.flags == ("CSCTF{picked_b}",)
    res = ci.solve(chal, CSCTF, target=target, func="a", budget_s=BIG)
    assert res.flags == ()                           # a() gives another, non-flag input


def test_solve_takes_a_named_source_outside_the_handout(tmp_path):
    src = "def enc(d):\n    return bytes(b ^ 0x33 for b in d)\n"
    chal = _chal(tmp_path, {"out.bin": bytes(b ^ 0x33 for b in b"CSCTF{named_source}")})
    assert ci.solve(chal, CSCTF, budget_s=BIG).status == "none"          # no source in the handout
    (chal / "recon" / "recovered").mkdir(parents=True)
    (chal / "recon" / "recovered" / "cipher.py").write_text(src)
    res = ci.solve(chal, CSCTF, source="recon/recovered/cipher.py", budget_s=BIG)
    assert res.status == "solved" and res.flags == ("CSCTF{named_source}",)
    assert res.evidence[0].path == "recon/recovered/cipher.py"
    elsewhere = tmp_path / "elsewhere.py"
    elsewhere.write_text(src)
    res = ci.solve(chal, CSCTF, source=str(elsewhere), budget_s=BIG)
    assert res.status == "solved" and res.evidence[0].path is None
    assert "elsewhere.py: enc(" in res.evidence[0].detail
    res = ci.solve(chal, CSCTF, source="missing.py", budget_s=BIG)
    assert res.status == "blocked" and "missing.py" in res.notes and "cannot be read" in res.notes
    (chal / "recon" / "huge.py").write_text("#" * (ci.MAX_SOURCE_BYTES + 1))
    res = ci.solve(chal, CSCTF, source="recon/huge.py", budget_s=BIG)
    assert res.status == "blocked" and "too large" in res.notes
    # the named source replaces the handout's own: this handout source would give another input
    (chal / "files" / "decoy.py").write_text("def enc(d):\n    return bytes(b ^ 0x32 for b in d)\n")
    assert ci.solve(chal, CSCTF, budget_s=BIG).flags == ()
    res = ci.solve(chal, CSCTF, source="recon/recovered/cipher.py", budget_s=BIG)
    assert res.flags == ("CSCTF{named_source}",) and len(res.evidence) == 1


def test_one_unrelated_source_cannot_use_the_whole_budget(tmp_path, monkeypatch):
    chal = _chal(tmp_path, {"a_first.py": "x = 1\n", "b_second.py": "y = 2\n", "c_third.py": "z = 3\n"})
    seen = []

    def fake_recover(blob, *, budget_s, **_kw):
        seen.append(budget_s)
        return ci.Report()

    monkeypatch.setattr(ci, "recover", fake_recover)
    ci.solve(chal, CSCTF, budget_s=90, clock=lambda: 0.0)        # a clock that never advances
    assert seen == [30.0, 45.0, 90.0]                # a third, then half, then all of what is left


@pytest.mark.parametrize("rel", ["ctf/result.py", "ctf/flagfmt.py", "tools/requirements_gen.py",
                                 "solvers/toolkits/symbolic.py"])
def test_ordinary_python_is_survived_and_nothing_is_made_up(rel):
    # this repo's own modules as data: no cipher, no target worth the name.  The step clock makes
    # the budget a number of clock reads, so the run is bounded whatever the machine is doing.
    ticks = itertools.count()
    rep = ci.recover((REPO / rel).read_bytes(), budget_s=400, max_steps=20000,
                     side_texts=[("file out.txt", "deadbeefcafebabe00112233\n")],
                     clock=lambda: next(ticks))
    assert isinstance(rep, ci.Report) and rep.recovered == []


def test_solve_with_no_budget_left_says_so(tmp_path):
    chal = _chal(tmp_path, {"scrambler.py": SPN, "sealed.bin": native(SPN, "seal", b"x" * 9)})
    res = ci.solve(chal, CSCTF, budget_s=0)
    assert res.status == "unsure" and "time budget" in res.notes and res.flags == ()


# ============================================================ wiring: manifest, router, runner, intake

def test_manifest_is_valid_routed_and_adapted_for_intake():
    m = _manifest.load(REPO / "solvers" / "toolkits" / "cipher_invert.manifest.toml")
    assert m.id == "toolkits.cipher_invert" and m.cost_class == "cheap" and m.status == "active"
    assert m.entry.target_file(REPO).name == "cipher_invert.py"
    assert m.intake.select == "route" and m.intake.run == "challenge" and not m.intake.spawns
    table = (REPO / "ctf" / "engines" / "route_table.jsonl").read_text()
    assert '"toolkits.cipher_invert"' in table


def test_router_sends_a_python_cipher_handout_here(tmp_path):
    from ctf.engines import router
    (tmp_path / "scrambler.py").write_text(SPN)
    ids = [h.manifest.id for h in router.route("misc", "recover the passphrase", tmp_path)]
    assert "toolkits.cipher_invert" in ids
    ids = [h.manifest.id for h in router.route("crypto", "a home-built block cipher")]
    assert "toolkits.cipher_invert" in ids
    (tmp_path / "scrambler.py").unlink()
    (tmp_path / "data.bin").write_bytes(b"\x00" * 8)
    assert "toolkits.cipher_invert" not in [h.manifest.id for h in
                                            router.route("misc", "recover the passphrase", tmp_path)]
    assert "toolkits.cipher_invert" not in [h.manifest.id for h in router.route("web", "a login page")]


def test_ctf_run_prints_the_result_under_the_engine_boot(tmp_path):
    from ctf.engines import runner
    flag = "CSCTF{through_the_runner}"
    chal = _chal(tmp_path, {"c.py": "def enc(d):\n    return bytes((b + 9) & 0xFF for b in d)\n",
                            "out.txt": bytes((b + 9) & 0xFF for b in flag.encode()).hex()})
    cmd = runner.command("toolkits.cipher_invert",
                         [str(chal), "--event", "csctf", "--opt", "budget_s=3600"], record=False)
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO, check=False)
    assert proc.returncode == 0, proc.stderr
    res = SolverResult.from_json(proc.stdout.strip().splitlines()[-1])
    assert res.status == "solved" and res.flags == (flag,) and res.engine == "toolkits.cipher_invert"


class _Adapter:
    kind = "fake"

    def __init__(self, ch, files):
        self.ch, self.files = ch, files

    def get_challenge(self, cid):
        return self.ch

    def list_challenges(self):
        return [self.ch]

    def download_files(self, cid, dest):
        out = []
        for rel, data in self.files.items():
            p = Path(dest) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
            out.append(p)
        return out

    def submit(self, cid, flag):
        raise AssertionError("intake never submits")

    def team_solves(self):
        return []


def _targz(members):
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz, \
            tarfile.open(fileobj=gz, mode="w") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_intake_inverts_a_cipher_shipped_in_an_archive_with_no_model(tmp_path):
    from ctf import intake as I
    from ctf.platform.base import Challenge, FileRef
    flag = "CSCTF{intake_ran_it_backward}"
    small = SPN.replace("ROUNDS = 6", "ROUNDS = 2")
    handout = _targz({"vault/scrambler.py": small.encode(),
                      "vault/sealed.txt": native(small, "seal", flag.encode()).hex().encode()})
    ch = Challenge(id="42", name="vault", category="Misc", points=200,
                   description="a home-built block scrambler; nothing runs it backward",
                   files=(FileRef("vault.tar.gz"),))
    rep = I.intake_one("42", CSCTF, adapter=_Adapter(ch, {"vault.tar.gz": handout}),
                       workdir=tmp_path / "wd", options=I.Options(net_guard="hook", record=False))
    runs = [r for r in rep.runs if r.engine == "toolkits.cipher_invert"]
    assert runs and runs[0].status == "ok" and runs[0].result_status == "solved"
    assert flag in rep.result.flags
    saved = json.loads((rep.dir / "recon" / "intake.json").read_text())
    assert any(r["engine"] == "toolkits.cipher_invert" for r in saved["engines_run"])


def test_cli_prints_the_recovered_input(tmp_path, capsys):
    p = tmp_path / "c.py"
    p.write_text("def enc(d):\n    return bytes(b ^ 0x10 for b in d)\n")
    assert ci.main([str(p), "--target", "hex:" + bytes(b ^ 0x10 for b in b"by hand").hex(),
                    "--budget-s", "3600"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["recovered"][0]["values"] == [repr(b"by hand")]
    assert out["recovered"][0]["method"] == "algebraic" and out["recovered"][0]["unique"] is True


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
