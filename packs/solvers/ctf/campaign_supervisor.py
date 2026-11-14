"""The detached supervisor of one campaign agent launch (B-178). Started only by
ctf.campaign.Campaign.launch()/relaunch(), in its own session so it outlives the shell or harness
session that started it:

    python -m ctf.campaign_supervisor --workdir W --agent ID --launch N --lock-fd FD [--detach]

With --detach it forks once more and prints the detached pid, so it is never the launcher's child
(no zombie, and nothing ties it to the launcher's session).

It inherits the agent's lock (agents/<id>.lock, flock held on FD) and hands the same descriptor to the
agent, so the lock is held while either lives: a reboot, a crash or a kill releases it and the next
reconcile() marks the agent lost. It runs the recorded command with the recorded stdin, forwards
TERM/INT/HUP to it, and on exit records done (rc 0) or failed and closes the agent's scratch pass.
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
from pathlib import Path

from . import campaign as _campaign
from . import scratch as _scratch


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ctf.campaign_supervisor")
    p.add_argument("--workdir", required=True)
    p.add_argument("--agent", required=True)
    p.add_argument("--launch", type=int, required=True)
    p.add_argument("--lock-fd", type=int, required=True)
    p.add_argument("--detach", action="store_true",
                   help="fork away (new session, reparented to init), print the detached pid and return")
    a = p.parse_args(argv)
    camp = _campaign.Campaign(Path(a.workdir))
    st = camp.load()
    rec = st["agents"].get(a.agent)
    if rec is None or rec.get("launches") != a.launch or rec.get("status") != "running":
        print(f"campaign_supervisor: agent {a.agent} launch {a.launch} is not the current running launch",
              file=sys.stderr)
        return 3
    camp.event = st.get("event")
    if a.detach:
        _detach(rec["log"])
    env = dict(os.environ)
    env.update(camp.child_env(rec))
    stdin = open(rec["stdin_file"], "rb") if rec.get("stdin_file") else subprocess.DEVNULL
    try:
        with open(rec["log"], "ab") as log:
            log.write(f"\n=== campaign agent {a.agent} launch {a.launch}: {rec['argv']}\n".encode())
            log.flush()
            try:
                child = subprocess.Popen(rec["argv"], cwd=rec["cwd"], env=env, stdin=stdin, stdout=log,
                                         stderr=subprocess.STDOUT, pass_fds=(a.lock_fd,))
            except OSError as e:
                _close_scratch(rec, "failed", f"could not start: {e}", camp)
                camp.finish(a.agent, "failed", note=f"could not start: {e}", launch=a.launch)
                return 1

            def forward(signum, _frame):
                try:
                    child.send_signal(signum)
                except ProcessLookupError:
                    pass

            for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
                signal.signal(sig, forward)
            camp.set_pid(a.agent, a.launch, child.pid)
            rc = child.wait()
            log.write(f"=== exit {rc}\n".encode())
    finally:
        if stdin is not subprocess.DEVNULL:
            stdin.close()
    status = "done" if rc == 0 else "failed"
    # the pass is closed before the agent is marked finished, so "done" means its scratch is recorded
    _close_scratch(rec, "closed" if rc == 0 else "failed", f"agent {a.agent} exit {rc}", camp)
    camp.finish(a.agent, status, rc=rc, note=f"exit {rc}", launch=a.launch)
    return 0


def _detach(log_path: str) -> None:
    """Fork: the parent prints the child's pid on stdout and exits; the child starts a new session
    and sends its stdout/stderr to the agent log, so the launcher's pipe closes."""
    sys.stdout.flush()
    pid = os.fork()
    if pid > 0:
        os.write(1, f"{pid}\n".encode())
        os._exit(0)
    os.setsid()
    fd = os.open(log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    os.dup2(fd, 1)
    os.dup2(fd, 2)
    os.close(fd)


def _close_scratch(rec: dict, status: str, note: str, camp: _campaign.Campaign) -> None:
    if rec.get("scratch"):
        try:
            _scratch.close_pass(Path(rec["scratch"]), status, note=note, now=camp.now())
        except _scratch.ScratchError as e:
            print(f"campaign_supervisor: scratch pass not closed: {e}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
