"""Fake `cysignals.alarm` for the B-157 tests: alarm(seconds) raises AlarmInterrupt, a
KeyboardInterrupt, in the main thread when the time is up (what cysignals does inside Sage). Both
calls are written to FAKE_SAGE_LOG so a test can see the limit that was set and that it was cleared."""
import json
import os
import signal

if os.environ.get("FAKE_SAGE_MODE") == "noalarm":            # a Sage whose cysignals has no alarm
    raise ImportError("fake cysignals: alarm is not available in this mode")


class AlarmInterrupt(KeyboardInterrupt):
    pass


def _log(entry):
    path = os.environ.get("FAKE_SAGE_LOG")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")


def _raise(signum, frame):
    raise AlarmInterrupt()


def alarm(seconds):
    _log({"call": "alarm", "seconds": seconds})
    signal.signal(signal.SIGALRM, _raise)
    signal.setitimer(signal.ITIMER_REAL, float(seconds))


def cancel_alarm():
    _log({"call": "cancel_alarm"})
    signal.setitimer(signal.ITIMER_REAL, 0)
