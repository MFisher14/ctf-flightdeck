"""Check that pytest collects the same test ids every time (SH-07).

pytest-xdist has every worker collect the suite on its own and aborts the run with "Different tests
were collected between gwN and gwM" when two workers' ordered id lists differ. A test id differs
between workers when it is built at collection from something that varies per process: most often
the wall clock (a parametrize value of gzip.compress() or zipfile.writestr() output embeds the time,
and bytes params become ids), sometimes set or dict-of-set iteration order (str hashes are seeded
per process). Each such abort cost the merge queue a full rerun.

This module collects the given tests twice, each time in a fresh `pytest --collect-only` child, and
compares the two ordered id lists. Between the two collections it moves the clock and changes the
hash seed, so an id that only drifts when workers start a second (or a day) apart drifts here every
time:

    run A   wall clock as is,                          PYTHONHASHSEED=1
    run B   wall clock + SHIFT (400 days 1h 1m 1s),    PYTHONHASHSEED=2, started GAP seconds after A

The clock move is this module loaded as a pytest plugin (`-p ctf.testing.collect_ids`) with
CTF_COLLECT_CLOCK_SHIFT set: at import, before any conftest or test module, it shifts time.time,
time.time_ns, the no-argument forms of time.localtime / gmtime / ctime / asctime / strftime, and
datetime.datetime.now / utcnow / today and datetime.date.today. Clocks read below Python (a file's
mtime, a child process) are not shifted; the GAP sleep makes those differ by a second at least.

    .venv/bin/python -m ctf.testing.collect_ids tests/test_a.py tests/test_b.py
    .venv/bin/python -m ctf.testing.collect_ids tests            # the whole tree

Exit 0: identical ids. Exit 1: the ids differ; a unified diff is printed. Exit 2: a collection did
not produce an id list (pytest failed to start, the plugin did not load), pytest reported an internal
or usage error (a target that does not exist), or nothing was collected; the reason is printed.
Collection errors are compared too: a module that errors in one run only is a difference. Each run's
errors are recorded sorted by node id, so the same broken modules reported in a different order are
not a difference.
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

SHIFT_ENV = "CTF_COLLECT_CLOCK_SHIFT"
OUT_ENV = "CTF_COLLECT_IDS_OUT"
DEFAULT_SHIFT = 400 * 86400 + 3661          # crosses a year, a day, an hour, a minute and a second
DEFAULT_GAP = 1.1                            # seconds between the two children: unshifted clocks move too
HASH_SEEDS = ("1", "2")
PLUGIN = "ctf.testing.collect_ids"


# ============================================================================================ the clock shift
def install_clock_shift(seconds: float) -> None:
    """Move every Python-level wall clock forward by `seconds` for the rest of this process."""
    import datetime as _dt
    import time as _time

    real_time, real_time_ns = _time.time, _time.time_ns
    real_localtime, real_gmtime = _time.localtime, _time.gmtime
    real_ctime, real_asctime, real_strftime = _time.ctime, _time.asctime, _time.strftime
    shift_ns = int(seconds * 1_000_000_000)

    def shifted_time():
        return real_time() + seconds

    def shifted_time_ns():
        return real_time_ns() + shift_ns

    def shifted_localtime(secs=None):
        return real_localtime(shifted_time() if secs is None else secs)

    def shifted_gmtime(secs=None):
        return real_gmtime(shifted_time() if secs is None else secs)

    def shifted_ctime(secs=None):
        return real_ctime(shifted_time() if secs is None else secs)

    def shifted_asctime(t=None):
        return real_asctime(shifted_localtime() if t is None else t)

    def shifted_strftime(fmt, t=None):
        return real_strftime(fmt, shifted_localtime() if t is None else t)

    _time.time, _time.time_ns = shifted_time, shifted_time_ns
    _time.localtime, _time.gmtime, _time.ctime = shifted_localtime, shifted_gmtime, shifted_ctime
    _time.asctime, _time.strftime = shifted_asctime, shifted_strftime

    delta = _dt.timedelta(seconds=seconds)
    base_datetime, base_date = _dt.datetime, _dt.date

    class _StandIn(type):
        # isinstance(x, datetime.datetime) stays true for the values C code and earlier imports make;
        # a class derived from a stand-in later checks as usual
        def __instancecheck__(cls, obj):
            base = cls.__dict__.get("_ctf_shifted_base")
            return isinstance(obj, base) if base else super().__instancecheck__(obj)

        def __subclasscheck__(cls, sub):
            base = cls.__dict__.get("_ctf_shifted_base")
            return issubclass(sub, base) if base else super().__subclasscheck__(sub)

    def _as(cls, d):
        return cls(d.year, d.month, d.day, d.hour, d.minute, d.second, d.microsecond, d.tzinfo, fold=d.fold)

    class datetime(base_datetime, metaclass=_StandIn):  # noqa: N801 - stands in for datetime.datetime
        @classmethod
        def now(cls, tz=None):
            return _as(cls, base_datetime.now(tz) + delta)

        @classmethod
        def utcnow(cls):
            return _as(cls, base_datetime.now(_dt.timezone.utc).replace(tzinfo=None) + delta)

        @classmethod
        def today(cls):
            return cls.now()

    class date(base_date, metaclass=_StandIn):  # noqa: N801 - stands in for datetime.date
        @classmethod
        def today(cls):
            d = base_date.fromtimestamp(shifted_time())
            return cls(d.year, d.month, d.day)

    datetime._ctf_shifted_base, date._ctf_shifted_base = base_datetime, base_date
    datetime.__module__ = date.__module__ = "datetime"
    datetime.__qualname__, date.__qualname__ = "datetime", "date"
    _dt.datetime, _dt.date = datetime, date


_shift = os.environ.get(SHIFT_ENV)
if _shift:
    install_clock_shift(float(_shift))


# ================================================================================== the pytest plugin hooks
_ERRORS: list[str] = []


def pytest_collectreport(report):
    if report.failed:
        _ERRORS.append(report.nodeid)


def pytest_collection_finish(session):
    out = os.environ.get(OUT_ENV)
    if out:
        Path(out).write_text(json.dumps({"ids": [item.nodeid for item in session.items],
                                         "errors": sorted(_ERRORS)}))


# =========================================================================================== the comparison
class CollectFailed(RuntimeError):
    """A collection child produced no id list, or an empty one."""


@dataclass
class Collection:
    ids: list[str]
    errors: list[str]
    output: str = field(repr=False, default="")


def collect(targets, *, cwd, shift: float, hash_seed: str, pytest_args=(), python=sys.executable,
            env=None, timeout=900) -> Collection:
    """One `pytest --collect-only` child over `targets`, with the clock moved by `shift` seconds.

    `env` is the child's environment (default: this process's); the hash seed, the id-list path and
    the shift are set on top of it, and a parent pytest run's PYTEST_CURRENT_TEST / PYTEST_XDIST_*
    are dropped."""
    with tempfile.TemporaryDirectory(prefix="collect-ids-") as tmp:
        out = Path(tmp) / "ids.json"
        env = {k: v for k, v in (os.environ if env is None else env).items()
               if k != "PYTEST_CURRENT_TEST" and not k.startswith("PYTEST_XDIST_")}
        env.update(PYTHONHASHSEED=hash_seed, **{OUT_ENV: str(out)})
        env.pop(SHIFT_ENV, None)
        if shift:
            env[SHIFT_ENV] = repr(float(shift))
        cmd = [python, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", "-p", "no:xdist",
               "-p", "no:randomly", "-p", PLUGIN, *pytest_args, *map(str, targets)]
        proc = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
        text = proc.stdout + proc.stderr
        if not out.exists():
            raise CollectFailed(f"pytest exited {proc.returncode} without writing an id list "
                                f"(the {PLUGIN} plugin did not run):\n{text[-3000:]}")
        data = json.loads(out.read_text())
    if proc.returncode in (3, 4):
        raise CollectFailed(f"pytest exited {proc.returncode} (an internal or usage error):\n{text[-3000:]}")
    if not data["ids"] and not data["errors"]:
        raise CollectFailed(f"pytest collected no tests from {' '.join(map(str, targets))}:\n{text[-3000:]}")
    return Collection(data["ids"], data["errors"], text)


@dataclass
class Comparison:
    a: Collection
    b: Collection

    @property
    def stable(self) -> bool:
        return self.a.ids == self.b.ids and self.a.errors == self.b.errors

    def diff(self) -> str:
        lines = list(difflib.unified_diff(self.a.ids, self.b.ids, "run A ids", "run B ids (clock moved)",
                                          lineterm="", n=1))
        lines += difflib.unified_diff(self.a.errors, self.b.errors, "run A collection errors",
                                      "run B collection errors", lineterm="", n=0)
        return "\n".join(lines)


def compare(targets, *, cwd=".", shift: float = DEFAULT_SHIFT, gap: float = DEFAULT_GAP, pytest_args=(),
            python=sys.executable, env=None, timeout=900) -> Comparison:
    """Collect `targets` twice (run A as is, run B `gap` seconds later with the clock `shift` seconds
    ahead and another hash seed) and return both id lists."""
    kw = dict(cwd=cwd, pytest_args=pytest_args, python=python, env=env, timeout=timeout)
    a = collect(targets, shift=0, hash_seed=HASH_SEEDS[0], **kw)
    if gap > 0:
        time.sleep(gap)
    b = collect(targets, shift=shift, hash_seed=HASH_SEEDS[1], **kw)
    return Comparison(a, b)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m ctf.testing.collect_ids", description=__doc__.split("\n\n")[0])
    ap.add_argument("targets", nargs="+", help="test files or folders, as given to pytest")
    ap.add_argument("--shift", type=float, default=DEFAULT_SHIFT, help="seconds the clock moves for run B")
    ap.add_argument("--gap", type=float, default=DEFAULT_GAP, help="seconds between the two collections")
    ap.add_argument("--pytest-arg", action="append", default=[], help="extra pytest argument (repeatable)")
    args = ap.parse_args(argv)
    try:
        cmp = compare(args.targets, shift=args.shift, gap=args.gap, pytest_args=args.pytest_arg)
    except CollectFailed as exc:
        print(f"collect_ids: {exc}", file=sys.stderr)
        return 2
    if cmp.stable:
        print(f"collect_ids: stable: {len(cmp.a.ids)} ids, {len(cmp.a.errors)} collection errors, identical "
              f"across a {args.shift:g} s clock move and a hash-seed change")
        return 0
    print(cmp.diff())
    print(f"collect_ids: DIVERGED: run A {len(cmp.a.ids)} ids, run B {len(cmp.b.ids)} ids; an id built at "
          "collection from the clock, a hash order or another per-process value. Build such values at test "
          "time, or pass explicit ids=.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
