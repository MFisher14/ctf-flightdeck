"""Shipped scratch scaffolds: repro, probe, adversarial and bench runs, and the complex-racer day file (B-258).

The same throwaway harnesses were rewritten day after day (adv*.py, probe*.py, repro.py, dbg.py,
harness.py, runtests.py, h.py, prof.py, bench.py). They are shipped here once, tested, and handed out
by one generator:

    python -m ctf scaffold list
    python -m ctf scaffold repro  DIR [--target FILE.py:FUNC] [--name N] [--force]
    python -m ctf scaffold probe  DIR ...        python -m ctf scaffold adv DIR ...
    python -m ctf scaffold bench  DIR ...
    python -m ctf scaffold racer  --day N [--role cx] [--lane-dir DIR] [--force]

A generated scaffold is a short fill-in file (what to call, on what): the logic lives in this module,
which the file imports from the checkout that wrote it. What each run does:

  repro  call the target on every case; PASS / FAIL (with a per-key diff) / ERROR (with the last
         frames) / OUT (no expectation); `--expect FILE` checks an expectations file
         (ctf.expectations), `--save FILE` writes one from these outputs (the test-pin codemod reads
         it), `--pdb` opens the debugger on the first error. Exit 1 on any FAIL or ERROR.
  probe  per file: size, sha256, the format its magic names, entropy; `--find` every offset of a
         hex/text needle, `--at OFF --len N` a hexdump, `--strings MIN [--grep RE]`; the file's own
         probes (fn(name, data) -> value) each on one line, a raise shown, never fatal.
  adv    derive variants of one case's subject (bytes, text, a {name: bytes} delivery or a JSON
         object) by seeded mutations and classify each output against the base output per key:
         same, declined (None or absent), changed, raised. A changed answer fails unless the
         file's oracle accepts it: a variant must answer as the base did or decline, never answer
         something else with confidence. Exit 1 on a raise or an unaccepted change.
  bench  CPU time (time.process_time) of each case over --repeat runs, min/median/max, wall time
         beside it for information only; `--cpu-budget S` fails a case whose median CPU exceeds
         it; `--profile` prints cProfile's top functions by cumulative time.
  racer  copy solvers/binary/racer_template.py to <lane>/dNN_<role>_dev.py with PREFIX set: the
         complex-racer candidate a lane's promotion step turns into dNN.py. Never the final name.
"""
from __future__ import annotations

import argparse
import cProfile
import hashlib
import io
import math
import pstats
import random
import re
import statistics
import sys
import time
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from . import expectations as X
from . import paths as _paths

TEMPLATES = Path(__file__).resolve().parent / "scaffold_templates"
KINDS = {
    "repro": "call a target on cases, diff against expectations, save expectations (repro.py, runtests.py, dbg.py)",
    "probe": "per-file facts, needle offsets, hexdumps, strings and custom probes (probe*.py, h.py)",
    "adv": "seeded adversarial variants of one case, classified against the base output (adv*.py)",
    "bench": "CPU-time benchmark and cProfile of a target over cases (bench.py, prof.py)",
    "racer": "the complex-racer day candidate solvers/binary/dNN_<role>_dev.py (from racer_template.py)",
}
RACER_TEMPLATE = "racer_template.py"
RACER_PREFIX_LINE = re.compile(r'^PREFIX = "template"$', re.M)
ROLE = re.compile(r"[a-z][a-z0-9]{0,15}")


class ScaffoldError(ValueError):
    """A scaffold that cannot be written or run, with the reason."""


case = X.case


def _say(out, text: str) -> None:
    print(text, file=out)


def _short(v, cap: int = 100) -> str:
    text = repr(v)
    return text if len(text) <= cap else text[: cap - 3] + "..."


# ============================================================================================== repro

def _expect_from(doc: dict) -> dict:
    return {cid: rec for cid, rec in X.validate(doc)["cases"].items()}


def repro(target: Callable, cases: Iterable, *, only: str | None = None, expect_doc: dict | None = None,
          out=None, pdb: bool = False, frames: int = 3) -> tuple[int, dict]:
    """(exit code, the expectations document of these outputs). See the module docstring."""
    out = out or sys.stdout
    sel = re.compile(only) if only else None
    saved = _expect_from(expect_doc) if expect_doc is not None else {}
    counts = {"PASS": 0, "FAIL": 0, "ERROR": 0, "OUT": 0}
    doc_cases = {}
    for c in cases:
        if not isinstance(c, X.Case):
            raise ScaffoldError(f"not a case: {c!r} (build cases with S.case(id, *args, expect=..., **kw))")
        if sel and not sel.search(c.id):
            continue
        if c.id in doc_cases:
            raise ScaffoldError(f"case id {c.id!r} appears twice")
        try:
            got = c.call(target)
        except Exception as e:  # noqa: BLE001 - reported per case
            counts["ERROR"] += 1
            doc_cases[c.id] = {"error": f"{type(e).__name__}: {e}"}
            _say(out, f"ERROR {c.id}: {type(e).__name__}: {e}")
            for line in traceback.format_exception(type(e), e, e.__traceback__)[-(frames + 1):-1]:
                _say(out, "      " + line.rstrip().replace("\n", "\n      "))
            if pdb:
                import pdb as _pdb
                _pdb.post_mortem(e.__traceback__)
            continue
        norm = X.normalize(got, f"case {c.id!r}")
        doc_cases[c.id] = {"output": norm}
        if c.id in saved:
            want = saved[c.id]
            if "error" in want:
                diffs = [X.Diff(c.id, "", want, {"output": norm})]
            else:
                diffs = X.diff_values(want["output"], norm, "", c.id)
        elif c.expect is not X.MISSING:
            diffs = X.diff_values(X.normalize(c.expect, f"case {c.id!r} expect"), norm, "", c.id)
        else:
            counts["OUT"] += 1
            _say(out, f"OUT   {c.id}: {_short(got)}")
            continue
        if diffs:
            counts["FAIL"] += 1
            _say(out, f"FAIL  {c.id}: {len(diffs)} difference(s)")
            for d in diffs:
                _say(out, f"      {d}")
        else:
            counts["PASS"] += 1
            _say(out, f"PASS  {c.id}")
    if not doc_cases:
        raise ScaffoldError("no case ran" + (f" (--only {only!r} matched none)" if only else ""))
    _say(out, "repro: " + " ".join(f"{k.lower()}={v}" for k, v in counts.items()))
    code = 1 if counts["FAIL"] or counts["ERROR"] else 0
    return code, {"schema": X.SCHEMA, "target": getattr(target, "__qualname__", ""), "cases": doc_cases}


def repro_main(target, cases, argv=None) -> int:
    ap = argparse.ArgumentParser(description="repro: call the target on each case and compare")
    ap.add_argument("--only", help="regex on case ids")
    ap.add_argument("--expect", type=Path, help="an expectations file to check against (ctf.expectations)")
    ap.add_argument("--save", type=Path, help="write these outputs as an expectations file")
    ap.add_argument("--pdb", action="store_true", help="post-mortem debugger on the first error")
    a = ap.parse_args(argv)
    try:
        target = X.load_target(target) if isinstance(target, str) else target
        expect_doc = X.load(a.expect) if a.expect else None
        code, doc = repro(target, cases() if callable(cases) else cases, only=a.only, expect_doc=expect_doc,
                          pdb=a.pdb)
        if a.save:
            X.write(a.save, doc)
            print(f"repro: saved {len(doc['cases'])} case(s) to {a.save}")
    except (ScaffoldError, X.ExpectationError) as e:
        print(f"repro: {e}", file=sys.stderr)
        return 2
    return code


# ============================================================================================== probe

MAGIC = [
    (b"\x7fELF", "elf"), (b"MZ", "pe/dos"), (b"\xcf\xfa\xed\xfe", "mach-o64"), (b"\xce\xfa\xed\xfe", "mach-o32"),
    (b"\xfe\xed\xfa\xcf", "mach-o64-be"), (b"\xca\xfe\xba\xbe", "java-class/mach-o-fat"), (b"dex\n", "dex"),
    (b"\x00asm", "wasm"), (b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip-empty"), (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"), (b"\xfd7zXZ\x00", "xz"), (b"7z\xbc\xaf\x27\x1c", "7z"), (b"Rar!\x1a\x07", "rar"),
    (b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpeg"), (b"GIF8", "gif"), (b"%PDF-", "pdf"),
    (b"SQLite format 3\x00", "sqlite"), (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2"), (b"{", "json?"),
]


def sniff(data: bytes) -> str:
    for magic, name in MAGIC:
        if data.startswith(magic):
            return name
    return "unknown"


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 for empty data)."""
    if not data:
        return 0.0
    n = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def needle(text: str) -> bytes:
    """`hex:4142` or `0x4142` as bytes, anything else as its UTF-8 text."""
    t = text.strip()
    for p in ("hex:", "0x"):
        if t.lower().startswith(p):
            body = t[len(p):].replace(" ", "")
            try:
                return bytes.fromhex(body)
            except ValueError:
                raise ScaffoldError(f"needle {text!r}: not hex") from None
    return text.encode("utf-8")


def find_all(data: bytes, pat: bytes, cap: int = 50) -> list[int]:
    if not pat:
        raise ScaffoldError("an empty needle")
    out, at = [], data.find(pat)
    while at >= 0 and len(out) < cap:
        out.append(at)
        at = data.find(pat, at + 1)
    return out


def hexdump(data: bytes, at: int = 0, length: int = 256, width: int = 16) -> list[str]:
    if at < 0:
        at = max(0, len(data) + at)
    chunk = data[at: at + length]
    lines = []
    for i in range(0, len(chunk), width):
        row = chunk[i: i + width]
        hx = " ".join(f"{b:02x}" for b in row)
        tx = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{at + i:08x}  {hx:<{width * 3 - 1}}  {tx}")
    return lines


def strings(data: bytes, minimum: int = 4) -> list[tuple[int, str]]:
    return [(m.start(), m.group().decode("ascii"))
            for m in re.finditer(rb"[\x20-\x7e]{%d,}" % max(1, minimum), data)]


def probe(paths: Iterable, probes: Iterable = (), *, find: Iterable[str] = (), at: int | None = None,
          length: int = 128, min_strings: int | None = None, grep: str | None = None, out=None) -> int:
    """Print facts for each file; exit 2 when a file is missing (named), else 0."""
    out = out or sys.stdout
    pats = [(f, needle(f)) for f in find]
    rx = re.compile(grep) if grep else None
    paths = [Path(p) for p in paths]
    missing = [str(p) for p in paths if not p.is_file()]
    if missing:
        raise ScaffoldError("no such file: " + ", ".join(missing))
    if not paths:
        raise ScaffoldError("no file to probe")
    for p in paths:
        data = p.read_bytes()
        _say(out, f"== {p}")
        _say(out, f"  size     {len(data)}")
        _say(out, f"  sha256   {hashlib.sha256(data).hexdigest()}")
        _say(out, f"  format   {sniff(data)}")
        _say(out, f"  entropy  {entropy(data):.3f}")
        for text, pat in pats:
            hits = find_all(data, pat)
            _say(out, f"  find {text!r}: {', '.join(hex(h) for h in hits) or 'none'}")
        if at is not None:
            for line in hexdump(data, at, length):
                _say(out, "  " + line)
        if min_strings is not None:
            found = [(o, s) for o, s in strings(data, min_strings) if rx is None or rx.search(s)]
            _say(out, f"  strings  {len(found)}")
            for o, s in found[:40]:
                _say(out, f"    {o:#08x} {_short(s, 90)}")
        for fn in probes:
            name = getattr(fn, "__name__", repr(fn))
            try:
                _say(out, f"  {name}: {_short(fn(p.name, data), 200)}")
            except Exception as e:  # noqa: BLE001 - a probe's raise is a fact about the file
                _say(out, f"  {name}: raised {type(e).__name__}: {e}")
    return 0


def probe_main(probes=(), argv=None) -> int:
    ap = argparse.ArgumentParser(description="probe: facts about files")
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--find", action="append", default=[], help="needle: text, or hex:.. / 0x..")
    ap.add_argument("--at", type=lambda s: int(s, 0), help="hexdump offset (negative: from the end)")
    ap.add_argument("--len", dest="length", type=lambda s: int(s, 0), default=128)
    ap.add_argument("--strings", dest="min_strings", type=int, help="list printable runs of at least N")
    ap.add_argument("--grep", help="regex the listed strings must match")
    a = ap.parse_args(argv)
    try:
        return probe(a.files, probes, find=a.find, at=a.at, length=a.length, min_strings=a.min_strings,
                     grep=a.grep)
    except ScaffoldError as e:
        print(f"probe: {e}", file=sys.stderr)
        return 2


# ======================================================================================== adversarial

def _bytes_variants(data: bytes, rng: random.Random, flips: int) -> list[tuple[str, bytes]]:
    n = len(data)
    out = [("empty", b""), ("append-junk", data + bytes(rng.randrange(256) for _ in range(64))),
           ("prepend-junk", bytes(rng.randrange(256) for _ in range(64)) + data)]
    if n:
        out += [("truncate-half", data[: n // 2]), ("truncate-1", data[:-1]),
                ("duplicate-tail", data + data[n // 2:]), ("duplicate-whole", data + data)]
        w = min(32, n)
        z = rng.randrange(n - w + 1)
        out.append((f"zero@{z:#x}+{w}", data[:z] + bytes(w) + data[z + w:]))
        for off in sorted(rng.sample(range(n), min(flips, n))):
            bit = rng.randrange(8)
            b = bytearray(data)
            b[off] ^= 1 << bit
            out.append((f"bitflip@{off:#x}.{bit}", bytes(b)))
    return out


def _text_variants(text: str, rng: random.Random) -> list[tuple[str, str]]:
    out = [("upper", text.upper()), ("lower", text.lower()), ("pad-space", f"  {text}  "),
           ("crlf", text.replace("\n", "\r\n")), ("empty", ""), ("duplicate", text + "\n" + text)]
    if text:
        out.append(("truncate-half", text[: len(text) // 2]))
    return [(k, v) for k, v in out if v != text]


def _json_variants(obj: dict, rng: random.Random) -> list[tuple[str, dict]]:
    out = []
    for k in sorted(obj):
        out.append((f"drop:{k}", {kk: v for kk, v in obj.items() if kk != k}))
    out.append(("reorder", dict(reversed(list(obj.items())))))
    out.append(("decoy-key", {**obj, "__decoy__": "decoy"}))
    return out


def _delivery_variants(files: dict, rng: random.Random, flips: int) -> list[tuple[str, dict]]:
    out = []
    names = sorted(files)
    for n in names:
        rest = {k: v for k, v in files.items() if k != n}
        out.append((f"drop:{n}", rest))
        stem, dot, ext = n.rpartition(".")
        decoy = f"{stem}.decoy.{ext}" if dot else f"{n}.decoy"
        out.append((f"decoy-copy:{n}", {**files, decoy: files[n]}))
        out.append((f"rename:{n}", {**rest, "renamed_" + n.rsplit("/", 1)[-1]: files[n]}))
        for label, data in _bytes_variants(bytes(files[n]), rng, flips):
            out.append((f"{n}:{label}", {**files, n: data}))
    return out


def variants(subject, *, seed: int = 0, flips: int = 8) -> list[tuple[str, Any]]:
    """[(label, mutated subject)] for bytes, str, a {name: bytes} delivery, or a JSON-like dict."""
    rng = random.Random(seed)
    if isinstance(subject, (bytes, bytearray)):
        return _bytes_variants(bytes(subject), rng, flips)
    if isinstance(subject, str):
        return _text_variants(subject, rng)
    if isinstance(subject, dict) and subject and all(isinstance(v, (bytes, bytearray)) for v in subject.values()):
        return _delivery_variants(subject, rng, flips)
    if isinstance(subject, dict):
        return _json_variants(subject, rng)
    raise ScaffoldError(f"no mutators for a {type(subject).__name__} subject (bytes, str, or a dict)")


@dataclass
class Verdict:
    label: str
    kind: str              # same, declined, changed, accepted, raised
    detail: str = ""


def _eq(a, b) -> bool:
    """Equal as answers: through the expectations' JSON form, so 1 and True differ; values that have
    no JSON form are compared with ==."""
    try:
        return X._same(X.normalize(a), X.normalize(b))
    except X.ExpectationError:
        return a == b


def classify(base, got) -> tuple[str, list[str]]:
    """same / declined / changed for one variant's output against the base output. For dict outputs
    (an answer per id) each key is held separately: a key that kept its value is same, a key that went
    None or absent is declined, any other value is changed. The worst kind wins."""
    if isinstance(base, dict) and isinstance(got, dict):
        changed, declined = [], []
        for k in sorted(set(base) | set(got)):
            b, g = base.get(k), got.get(k)
            if _eq(b, g):
                continue
            if g is None:
                declined.append(k)
            else:
                changed.append(f"{k}: {_short(b, 40)} -> {_short(g, 40)}")
        if changed:
            return "changed", changed
        return ("declined", declined) if declined else ("same", [])
    if _eq(base, got):
        return "same", []
    if got is None or got == {} or got == []:
        return "declined", []
    return "changed", [f"{_short(base, 40)} -> {_short(got, 40)}"]


def adversarial(target: Callable, seed_case, *, subject: int | str = 0, oracle: Callable | None = None,
                seed: int = 0, flips: int = 8, limit: int | None = None, only: str | None = None,
                allow_raise: bool = False, out=None) -> tuple[int, list[Verdict]]:
    """Run every variant of the seed case's subject argument (an index into args or a kwarg name).
    `oracle(label, variant_case, base_output, output) -> bool` accepts a changed answer (the mutation
    changed the truth); without one every change fails. Exit 1 on a raise (unless allow_raise) or an
    unaccepted change; ScaffoldError when the base case itself raises."""
    out = out or sys.stdout
    if not isinstance(seed_case, X.Case):
        raise ScaffoldError("the seed is a case: S.case(id, *args, **kw)")
    try:
        base = seed_case.call(target)
    except Exception as e:  # noqa: BLE001
        raise ScaffoldError(f"the base case raises ({type(e).__name__}: {e}): fix it before mutating") from None
    if isinstance(subject, int):
        if not 0 <= subject < len(seed_case.args):
            raise ScaffoldError(f"subject index {subject} is not an argument of the seed case")
        subj = seed_case.args[subject]
    else:
        if subject not in seed_case.kwargs:
            raise ScaffoldError(f"subject {subject!r} is not a keyword argument of the seed case")
        subj = seed_case.kwargs[subject]
    sel = re.compile(only) if only else None
    todo = [(lab, v) for lab, v in variants(subj, seed=seed, flips=flips) if not sel or sel.search(lab)]
    if limit is not None:
        todo = todo[:limit]
    if not todo:
        raise ScaffoldError("no variant to run")
    _say(out, f"base   {_short(base)}")
    verdicts = []
    for label, mutated in todo:
        if isinstance(subject, int):
            args = list(seed_case.args)
            args[subject] = mutated
            vc = X.Case(f"{seed_case.id}~{label}", tuple(args), dict(seed_case.kwargs))
        else:
            vc = X.Case(f"{seed_case.id}~{label}", seed_case.args, {**seed_case.kwargs, subject: mutated})
        try:
            got = vc.call(target)
        except Exception as e:  # noqa: BLE001 - the finding
            verdicts.append(Verdict(label, "raised", f"{type(e).__name__}: {e}"))
            continue
        kind, detail = classify(base, got)
        if kind == "changed" and oracle is not None and oracle(label, vc, base, got):
            kind = "accepted"
        verdicts.append(Verdict(label, kind, "; ".join(detail)))
    for v in verdicts:
        _say(out, f"{v.kind:<9} {v.label}" + (f"  {v.detail}" if v.detail else ""))
    tally = {k: sum(1 for v in verdicts if v.kind == k) for k in ("same", "declined", "accepted", "changed", "raised")}
    _say(out, "adv: " + " ".join(f"{k}={n}" for k, n in tally.items()))
    bad = tally["changed"] + (0 if allow_raise else tally["raised"])
    return (1 if bad else 0), verdicts


def adversarial_main(target, seed_case, *, subject=0, oracle=None, argv=None) -> int:
    ap = argparse.ArgumentParser(description="adv: seeded adversarial variants of one case")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--flips", type=int, default=8, help="bit flips per byte subject")
    ap.add_argument("--max", dest="limit", type=int)
    ap.add_argument("--only", help="regex on variant labels")
    ap.add_argument("--allow-raise", action="store_true")
    a = ap.parse_args(argv)
    try:
        target = X.load_target(target) if isinstance(target, str) else target
        code, _ = adversarial(target, seed_case() if callable(seed_case) else seed_case, subject=subject,
                              oracle=oracle, seed=a.seed, flips=a.flips, limit=a.limit, only=a.only,
                              allow_raise=a.allow_raise)
    except (ScaffoldError, X.ExpectationError) as e:
        print(f"adv: {e}", file=sys.stderr)
        return 2
    return code


# ============================================================================================== bench

@dataclass
class Timing:
    case: str
    cpu: list
    wall: list

    @property
    def median_cpu(self) -> float:
        return statistics.median(self.cpu)


def bench(target: Callable, cases: Iterable, *, repeat: int = 3, cpu_budget: float | None = None,
          profile: bool = False, top: int = 15, only: str | None = None, out=None,
          clock: Callable[[], float] = time.process_time,
          wall: Callable[[], float] = time.perf_counter) -> tuple[int, list[Timing]]:
    """Time each case `repeat` times in CPU seconds (`clock`, injectable). Exit 1 when a case's median
    CPU time is over `cpu_budget` or the case raises."""
    out = out or sys.stdout
    if repeat < 1:
        raise ScaffoldError("--repeat must be at least 1")
    sel = re.compile(only) if only else None
    rows, failed = [], 0
    prof = cProfile.Profile() if profile else None
    for c in cases:
        if not isinstance(c, X.Case):
            raise ScaffoldError(f"not a case: {c!r}")
        if sel and not sel.search(c.id):
            continue
        t = Timing(c.id, [], [])
        try:
            for i in range(repeat):
                c0, w0 = clock(), wall()
                if prof is not None and i == 0:
                    prof.enable()
                try:
                    c.call(target)
                finally:
                    if prof is not None and i == 0:
                        prof.disable()
                t.cpu.append(clock() - c0)
                t.wall.append(wall() - w0)
        except Exception as e:  # noqa: BLE001
            failed += 1
            _say(out, f"ERROR {c.id}: {type(e).__name__}: {e}")
            continue
        over = cpu_budget is not None and t.median_cpu > cpu_budget
        failed += over
        rows.append(t)
        _say(out, f"{'OVER ' if over else ''}{c.id}: cpu min {min(t.cpu):.4f} median {t.median_cpu:.4f} "
                  f"max {max(t.cpu):.4f} s; wall median {statistics.median(t.wall):.4f} s (load-dependent)")
    if not rows and not failed:
        raise ScaffoldError("no case ran" + (f" (--only {only!r} matched none)" if only else ""))
    if prof is not None:
        buf = io.StringIO()
        pstats.Stats(prof, stream=buf).sort_stats("cumulative").print_stats(top)
        _say(out, buf.getvalue().rstrip())
    return (1 if failed else 0), rows


def bench_main(target, cases, argv=None) -> int:
    ap = argparse.ArgumentParser(description="bench: CPU time and profile of a target over cases")
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--cpu-budget", type=float, help="fail a case whose median CPU seconds exceed this")
    ap.add_argument("--profile", action="store_true")
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--only", help="regex on case ids")
    a = ap.parse_args(argv)
    try:
        target = X.load_target(target) if isinstance(target, str) else target
        code, _ = bench(target, cases() if callable(cases) else cases, repeat=a.repeat, cpu_budget=a.cpu_budget,
                        profile=a.profile, top=a.top, only=a.only)
    except (ScaffoldError, X.ExpectationError) as e:
        print(f"bench: {e}", file=sys.stderr)
        return 2
    return code


# ========================================================================================== generator

def render(kind: str, *, target: str = "", name: str = "", repo: Path | None = None) -> str:
    """The text of a repro/probe/adv/bench scaffold (racer: see racer_text)."""
    if kind not in KINDS or kind == "racer":
        raise ScaffoldError(f"unknown scaffold {kind!r} (one of: {', '.join(k for k in KINDS if k != 'racer')})")
    src = TEMPLATES / f"{kind}.py.tmpl"
    if not src.is_file():
        raise ScaffoldError(f"the {kind} template is missing: {src}")
    if target and target.count(":") != 1:
        raise ScaffoldError(f"--target {target!r}: expected FILE.py:FUNCTION or package.module:FUNCTION")
    text = src.read_text(encoding="utf-8")
    repo = Path(repo) if repo is not None else _paths.repo_root()
    subs = {"@@REPO@@": str(repo), "@@TARGET@@": target or "path/to/module.py:function",
            "@@NAME@@": name or kind}
    for k, v in subs.items():
        text = text.replace(k, v.replace("\\", "\\\\").replace('"', '\\"'))
    left = re.findall(r"@@[A-Z]+@@", text)
    if left:
        raise ScaffoldError(f"the {kind} template has unfilled markers: {', '.join(sorted(set(left)))}")
    return text


def write_scaffold(kind: str, dest: str | Path, *, target: str = "", name: str = "", force: bool = False,
                   repo: Path | None = None) -> Path:
    """Write a scaffold. `dest` is a folder (the file is <name or kind>.py in it) or a .py path."""
    dest = Path(dest)
    path = dest if dest.suffix == ".py" else dest / f"{name or kind}.py"
    if path.exists() and not force:
        raise ScaffoldError(f"{path} exists (--force to overwrite)")
    text = render(kind, target=target, name=name or path.stem, repo=repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def racer_text(day: int, template: Path | None = None) -> str:
    """racer_template.py with PREFIX set to dNN."""
    if not isinstance(day, int) or isinstance(day, bool) or not 1 <= day <= 999:
        raise ScaffoldError(f"--day {day!r}: a day number from 1 to 999")
    src = Path(template) if template is not None else _paths.repo_root() / "solvers" / "binary" / RACER_TEMPLATE
    if not src.is_file():
        raise ScaffoldError(f"the racer template is missing: {src}")
    text = src.read_text(encoding="utf-8")
    prefix = f"d{day:02d}"
    new, n = RACER_PREFIX_LINE.subn(f'PREFIX = "{prefix}"', text)
    if n != 1:
        raise ScaffoldError(f"{src}: expected exactly one line `PREFIX = \"template\"`, found {n}")
    return new


def write_racer(day: int, *, role: str = "cx", lane_dir: str | Path | None = None, force: bool = False,
                template: Path | None = None) -> Path:
    """Write <lane_dir>/dNN_<role>_dev.py from the racer template. The final name dNN.py is never
    written here: a candidate is promoted by the lane's promotion step after a replay."""
    if not isinstance(role, str) or not ROLE.fullmatch(role):
        raise ScaffoldError(f"--role {role!r}: lowercase letters and digits, starting with a letter")
    lane = Path(lane_dir) if lane_dir is not None else _paths.repo_root() / "solvers" / "binary"
    if not lane.is_dir():
        raise ScaffoldError(f"no lane folder {lane}")
    text = racer_text(day, template)
    path = lane / f"d{day:02d}_{role}_dev.py"
    if path.exists() and not force:
        raise ScaffoldError(f"{path} exists (--force to overwrite)")
    path.write_text(text, encoding="utf-8")
    return path
