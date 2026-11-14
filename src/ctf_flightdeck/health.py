"""`flightdeck doctor`'s checks for the home screen's Settings and health (console/health.py),
run in a child process that the screen can kill.

The checks are the ones doctor runs (setup.doctor), and some of them wait: `docker version`
can take 20 s when the daemon hangs, and the pack's tools are asked of a container. The home
screen must never wait for them and must leave nothing running when the player leaves it, so
the checks run in a process of their own, in a process group of its own: closing the screen
cancels the task that waits for it, and the whole group is killed, docker with it. A thread
could not be stopped that way. The child prints the checks as JSON on its standard output,
and nothing else; it never prints a key (doctor never returns one).

    python -P -m ctf_flightdeck.health COLUMNS LINES

COLUMNS and LINES are the size of the player's terminal, which the child cannot ask (its
output is a pipe): the terminal check measures the console at that size. 0 0: no terminal
check. `-P` keeps the folder the player is in off the child's import path.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
from dataclasses import asdict

from .setup import Check

CHECKS_TIMEOUT = 120.0  # seconds: past this the checks are stopped and the screen says so
FIELDS = ("name", "ok", "detail", "fix", "essential")


class HealthError(Exception):
    """The checks could not be run or read: what happened, in words for the player."""


def child_command(columns: int, lines: int) -> list[str]:
    return [sys.executable, "-P", "-m", "ctf_flightdeck.health", str(columns), str(lines)]


async def run_checks(columns: int, lines: int, *, timeout: float = CHECKS_TIMEOUT) -> list[Check]:
    """doctor's checks, as the child process ran them; HealthError when it could not.
    Cancelled, the child and everything it started are killed at once."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *child_command(columns, lines),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,  # a group of its own, so the whole of it can be killed
        )
    except OSError as exc:
        raise HealthError(f"the checks could not be started: {exc.strerror or exc}") from None
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError:
        raise HealthError(f"the checks took longer than {timeout:g} s and were stopped: `flightdeck doctor` in a "
                          "terminal shows which one waits") from None
    finally:
        if proc.returncode is None:  # timed out, or cancelled: never leave it running
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            try:  # collected, so no zombie stays
                await asyncio.wait_for(proc.wait(), 2.0)
            except TimeoutError:
                pass
    if proc.returncode != 0:
        lines_said = [line.strip() for line in err.decode("utf-8", "replace").splitlines() if line.strip()]
        said = f" ({lines_said[-1]})" if lines_said else ""
        raise HealthError(f"the checks stopped with status {proc.returncode}{said}: `flightdeck doctor` in a terminal "
                          "says more")
    return parse(out)


def parse(out: bytes) -> list[Check]:
    """The child's output as checks; HealthError when it is not what the child writes."""
    try:
        items = json.loads(out.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HealthError("the checks answered with something that is not their list: `flightdeck doctor` in a "
                          "terminal shows them") from None
    if not isinstance(items, list) or not all(isinstance(item, dict) and set(item) == set(FIELDS) for item in items):
        raise HealthError("the checks answered with something that is not their list: `flightdeck doctor` in a "
                          "terminal shows them")
    checks = []
    for item in items:
        if not (all(isinstance(item[k], str) for k in ("name", "detail", "fix"))
                and all(isinstance(item[k], bool) for k in ("ok", "essential"))):
            raise HealthError("the checks answered with a check that is not one: `flightdeck doctor` in a terminal "
                              "shows them")
        checks.append(Check(**{k: item[k] for k in FIELDS}))
    return checks


def main(argv: list[str]) -> int:
    from .setup import doctor

    if len(argv) != 2 or not all(arg.isdigit() for arg in argv):
        sys.stderr.write("usage: python -P -m ctf_flightdeck.health COLUMNS LINES\n")
        return 64
    checks = doctor(terminal=(int(argv[0]), int(argv[1])))
    sys.stdout.write(json.dumps([asdict(check) for check in checks]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
