"""A saved multi-set attempt as one opener or lane-gate input (B-042).

An opener engine reads one file. A Mastery is several sets, each with a delivery of its own, so a
case whose input is a saved attempt (`attempt.json`, written by `ctf.openers.set_fixtures` or saved by
a runner) is run as the Mastery is played: `ctf.deliveries` pairs every set with its own delivery,
and the engine runs once per set on that delivery's bytes. `openers.run_input` calls this for an
input named attempt.json and hands every other input to `run_engine` unchanged.

    code, out, err, seconds = run(attempt_json, run_dir, run_one)
    # run_one(input_file, cwd) -> an EngineRun (code, out, err, seconds, cut): one guarded engine run

The combined stdout is what a case's `expect` strings are checked against:

    set2 <- delivery 2: blob.txt [named]                       one line per set: its delivery and the rule
    set2> delivery 2: blob.txt: second-set-delivery-42 [b64]   the engine's own lines, each under `set2> `

In the engine's lines the path of the file it was given is replaced by the delivery's label, so a
key can name the set, the delivery and the answer in one string and holds only when that set printed
that answer from that delivery. A set with no proven delivery prints `set3 <- UNMAPPED: <reason>`,
the engine is not run for it, and the run's exit code is UNMAPPED_EXIT.

Exit code: None when a set's run was killed at its timeout (the sets after it are not run), else the
first non-zero engine exit, else UNMAPPED_EXIT when a set had no delivery, else 0. An attempt that
cannot be read is exit UNREADABLE_EXIT with the reason on stderr and no engine run. Each set's run
has the caller's whole timeout; `seconds` is the sum.

The pairing runs here, in the caller's process (the `ctf arm` / lane-gate parent): for a one-bundle
attempt with several sets `ctf.deliveries.set_inputs` expands the bundle one level deep with the
runner's expander (tools/archive_expand.py, 7-Zip for a 7z member), not inside the guarded engine
process. Only each set's engine run is guarded (docs/CONTRACTS.md section 53).
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from .. import deliveries as _deliveries

UNREADABLE_EXIT = 2          # the attempt or one of its deliveries could not be read
UNMAPPED_EXIT = 3            # a set has no proven delivery


def _prefixed(n: int, text: str) -> list[str]:
    return [f"set{n}> {line}" for line in text.splitlines()]


def _safe(name: str | None) -> str:
    base = Path(name or "").name
    return base if base not in ("", ".", "..") else "delivery.bin"


def run(attempt_path: Path, run_dir: Path, run_one: Callable) -> tuple[int | None, str, str, float]:
    """Run `run_one` once per set of the saved attempt, on the set's own delivery: (code, out, err,
    seconds) as described above. `run_dir` must not exist; each set's input is written under it."""
    try:
        inputs = _deliveries.set_inputs(_deliveries.read_attempt(attempt_path))
        if not inputs:
            raise _deliveries.DeliveryError(f"{attempt_path}: the attempt asks no question")
        if any(i.choice.mapped and i.data is None for i in inputs):
            raise _deliveries.DeliveryError(f"{attempt_path}: one set over no delivery or several: an opener "
                                            "engine reads one file, so there is no per-set input")
    except _deliveries.DeliveryError as e:
        return UNREADABLE_EXIT, "", f"sets: {e}\n", 0.0
    except Exception as e:    # the expander on a bundle it cannot open: the case fails with the reason
        return UNREADABLE_EXIT, "", f"sets: {attempt_path}: {type(e).__name__}: {e}\n", 0.0
    run_dir = Path(run_dir)
    run_dir.mkdir()
    out, err, seconds, failed, unmapped = [], [], 0.0, 0, False
    for item in inputs:
        n = item.choice.set
        if not item.choice.mapped:
            out.append(f"set{n} <- {item.label}")
            unmapped = True
            continue
        out.append(f"set{n} <- {item.label} [{item.choice.rule}]")
        path = run_dir / f"set-{n:02d}-in" / _safe(item.name)
        path.parent.mkdir()
        path.write_bytes(item.data)
        r = run_one(path, run_dir / f"set-{n:02d}")
        seconds += r.seconds
        out += _prefixed(n, r.out.replace(str(path), item.label))
        err += _prefixed(n, r.err.replace(str(path), item.label))
        if r.code is None:
            return None, "\n".join(out) + "\n", "\n".join(err) + ("\n" if err else ""), seconds
        failed = failed or r.code
    code = failed or (UNMAPPED_EXIT if unmapped else 0)
    return code, "\n".join(out) + "\n", "\n".join(err) + ("\n" if err else ""), seconds
