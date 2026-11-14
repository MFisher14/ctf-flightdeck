#!/usr/bin/env python3
"""Owned subprocess groups for bounded tools.

Every process started here is a new POSIX session leader, so its pid is also
its process-group and session id.  A timeout can therefore stop the tool and
all of its ordinary descendants without matching command lines or touching an
unrelated process.  The leader is deliberately left unreaped until TERM/KILL
escalation is complete: while that pid is still owned by the caller, neither
its pid nor its process-group id can be reused.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time


TERM_GRACE = 0.25
POST_STOP_DRAIN = 1.0


class OwnedProcess:
    """A ``Popen`` whose pid names a session/process group owned by us."""

    def __init__(self, popen: subprocess.Popen):
        self.popen = popen
        self.pid = popen.pid
        self.pgid = popen.pid
        self.sid = popen.pid

    def _same_leader(self) -> bool:
        """True only while our unreaped child still anchors its original group."""
        if self.popen.returncode is not None:
            return False
        try:
            return os.getpgid(self.pid) == self.pgid and os.getsid(self.pid) == self.sid
        except (OSError, ProcessLookupError):
            return False

    def _critical(self, reason: str) -> None:
        """Put an ownership failure on the opener's captured stderr."""
        print(
            f"CRITICAL owned-process cleanup pid={self.pid} pgid={self.pgid}: {reason}",
            file=sys.stderr,
            flush=True,
        )

    @staticmethod
    def _error(exc: OSError) -> str:
        """Stable signal-error detail without argv, output, or other secrets."""
        suffix = f" errno={exc.errno}" if exc.errno is not None else ""
        return f"{type(exc).__name__}{suffix}"

    def stop(self, grace: float = TERM_GRACE) -> bool:
        """TERM then KILL the exact owned group, without ever targeting a reused pgid.

        The caller must reap ``popen`` only after this returns.  False means the
        session identity could not be proved; in that fail-closed case only the
        still-owned direct child is killed, never a process group inferred from
        stale state.
        """
        if self.popen.returncode is not None:
            # Popen has already reaped the leader.  Its numeric pid/pgid may
            # now be reused, and this handle cannot prove whether descendants
            # remain in the old group.  Never turn stale ownership into a
            # broad signal.
            self._critical(
                f"leader was already reaped (returncode={self.popen.returncode}); "
                "descendant state is unverifiable; refused killpg"
            )
            return False
        if not self._same_leader():
            detail = "leader session/process-group identity is unverifiable; refused killpg"
            try:
                self.popen.kill()
            except OSError as exc:
                detail += f"; direct-child SIGKILL also failed ({self._error(exc)})"
            self._critical(detail)
            return False
        try:
            os.killpg(self.pgid, signal.SIGTERM)
        except ProcessLookupError:
            return True
        except OSError as exc:
            detail = f"group SIGTERM failed ({self._error(exc)}); descendant cleanup is incomplete"
            try:
                self.popen.kill()
            except OSError as direct:
                detail += f"; direct-child SIGKILL also failed ({self._error(direct)})"
            self._critical(detail)
            return False

        # Do not poll/wait here: reaping the leader would give up the identity
        # guarantee before the stubborn members receive SIGKILL.
        end = time.monotonic() + max(0.0, grace)
        while True:
            left = end - time.monotonic()
            if left <= 0:
                break
            time.sleep(min(0.02, left))
        # Darwin stops resolving getpgid(leader) once TERM has made the
        # leader a zombie.  It is nevertheless still our unreaped child, so
        # its pid/pgid cannot be reused.  Do not re-query it here; the proof
        # made before TERM remains valid until the caller reaps ``popen``.
        if self.popen.returncode is None:
            try:
                os.killpg(self.pgid, signal.SIGKILL)
            except ProcessLookupError:
                return True
            except OSError as exc:
                self._critical(
                    f"group SIGKILL failed ({self._error(exc)}); descendant cleanup is incomplete"
                )
                return False
        return True

    def communicate_after_stop(self, timeout: float | None = None):
        """Drain/reap after ``stop`` for at most ``timeout`` seconds.

        A descendant may retain stdout after ownership or signaling failed.
        Returning partial output is safer than turning the opener's wall cap
        into another unbounded wait.
        """
        timeout = POST_STOP_DRAIN if timeout is None else timeout
        try:
            stdout, stderr = self.popen.communicate(timeout=max(0.0, timeout))
            return stdout, stderr, True
        except subprocess.TimeoutExpired as exc:
            self._critical(
                f"post-stop output drain/reap exceeded {timeout:.2f}s; returning boundedly with partial output"
            )
            return exc.output, exc.stderr, False
        except Exception as exc:  # cleanup must not replace the caller's original failure
            self._critical(f"post-stop output drain/reap failed ({type(exc).__name__}); returning boundedly")
            return None, None, False

    def wait_after_stop(self, timeout: float | None = None) -> bool:
        """Reap a stopped leader within a fixed wall, with a visible failure."""
        timeout = POST_STOP_DRAIN if timeout is None else timeout
        try:
            self.popen.wait(timeout=max(0.0, timeout))
            return True
        except subprocess.TimeoutExpired:
            self._critical(f"post-stop leader reap exceeded {timeout:.2f}s; returning boundedly")
            return False
        except Exception as exc:  # cleanup must stay bounded and observable
            self._critical(f"post-stop leader reap failed ({type(exc).__name__}); returning boundedly")
            return False


def spawn(args, **kwargs) -> OwnedProcess:
    """Start ``args`` as a session leader and return its owned-group handle."""
    if "start_new_session" in kwargs and not kwargs["start_new_session"]:
        raise ValueError("an owned process must start a new session")
    kwargs["start_new_session"] = True
    return OwnedProcess(subprocess.Popen(args, **kwargs))


def run(args, *, timeout=None, input=None, **kwargs) -> subprocess.CompletedProcess:
    """The subset of ``subprocess.run`` used by the opener, with tree cleanup.

    TimeoutExpired carries the output collected within the bounded post-stop
    drain.  On any other exception the isolated child tree is stopped before
    the exception is allowed to unwind.
    """
    capture_output = kwargs.pop("capture_output", False)
    if capture_output:
        if kwargs.get("stdout") is not None or kwargs.get("stderr") is not None:
            raise ValueError("stdout and stderr arguments may not be used with capture_output")
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    if input is not None:
        if kwargs.get("stdin") is not None:
            raise ValueError("stdin and input arguments may not both be used")
        kwargs["stdin"] = subprocess.PIPE
    owned = spawn(args, **kwargs)
    proc = owned.popen
    try:
        stdout, stderr = proc.communicate(input=input, timeout=timeout)
    except subprocess.TimeoutExpired:
        owned.stop()
        stdout, stderr, _ = owned.communicate_after_stop()
        raise subprocess.TimeoutExpired(args, timeout, output=stdout, stderr=stderr)
    except BaseException:
        owned.stop()
        owned.communicate_after_stop()
        raise
    return subprocess.CompletedProcess(args, proc.returncode, stdout, stderr)
