#!/usr/bin/env python3
"""Tell the player something happened: a macOS notification and a log line.

  python3 tools/alert.py <info|warn|critical> [--lane LANE] <message ...>

  info      a macOS notification                      (a solver is done)
  warn      a notification                            (a rate-limit pause, a solver stopped)
  critical  a notification titled CRITICAL            (something that needs the player now)

No alert makes a sound (the player's preference: notification center is plenty). CTF_SOUND=1
brings the sounds back: the Glass sound with a warn, and for a critical alert the message spoken
and Sosumi three times.

Every alert is also printed to stderr and appended, with its time, as one line to
<CHALLENGES>/_logs/ALERTS.log, which is what a watching session relays. CTF_QUIET=1 keeps the
print and the log and makes no notification and no sound.

An alert must never be the thing that breaks: each channel runs on its own with a 5 second
limit, and whatever fails is skipped. Anything that looks like a bearer credential is removed
from the message before it goes anywhere.
"""
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env, paths as ctf_paths
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[1]))
    from ctf import env as ctf_env, paths as ctf_paths

LEVELS = ("info", "warn", "critical")
CHANNEL_TIMEOUT = 5   # seconds one notification, spoken line or sound may take
TITLE = "CSCTF"
SOSUMI = "/System/Library/Sounds/Sosumi.aiff"
NOTIFY = ("on run argv", "display notification (item 1 of argv) with title (item 2 of argv)", "end run")
NOTIFY_WITH_SOUND = (NOTIFY[0], NOTIFY[1] + ' sound name "Glass"', NOTIFY[2])


def audible() -> bool:
    """Whether an alert may make a sound: only with CTF_SOUND=1 (see the top of this file)."""
    return ctf_env.get("CTF_SOUND") == "1"


def scrub(text) -> str:
    """One line of text with any bearer credential (the word and the value after it, on the same
    line or the next) taken out, and with it the value of $CTF_TOKEN wherever it stands.
    The token file is not read for this."""
    text = re.sub(r"(?i)\bbearer\b[\s:=]*[^\s\"',;]*", "<credential removed>", str(text))
    token = ctf_env.get("CTF_TOKEN", "").strip()
    if len(token) >= 8:
        text = text.replace(token, "<credential removed>")
    return " ".join(text.split())


def log_path() -> Path:
    """<CHALLENGES>/_logs/ALERTS.log, resolved when the alert fires (tests and rehearsals move the
    folder): the event workdir, ctf.paths.workdir()."""
    return ctf_paths.workdir() / "_logs" / "ALERTS.log"


def _channel(command) -> bool:
    """Run one channel. True when it finished cleanly inside the limit."""
    try:
        done = subprocess.run(command, timeout=CHANNEL_TIMEOUT, stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return done.returncode == 0
    except Exception:
        return False


def _notify(title, message, sound) -> bool:
    script = NOTIFY_WITH_SOUND if sound else NOTIFY
    command = ["/usr/bin/osascript"]
    for line in script:
        command += ["-e", line]
    # The text travels as arguments, never as script source. '--' ends the options: without it a
    # message that starts with '-' is read as one, and the notification is not shown.
    return _channel(command + ["--", message, title])


def _deliver(name, title, message) -> dict:
    """Run the channels of one level, one after the other. Returns {channel: worked}."""
    loud = audible()
    if name == "info":
        return {"notification": _notify(title, message, sound=False)}
    if name == "critical":
        worked = {"notification": _notify(f"{title} (CRITICAL)", message, sound=False)}
        if loud:
            worked["say"] = _channel(["/usr/bin/say", "--", message])
            worked["sosumi"] = all([_channel(["/usr/bin/afplay", SOSUMI]) for _ in range(3)])
        return worked
    return {"notification": _notify(title, message, sound=loud)}


def alert(level, message, lane=None, wait=True) -> dict:
    """Raise one alert. Returns {level, line, logged, channels: {name: worked}}; it never raises.
    An unknown level is delivered as a warn, under the name it was given.

    The print and the log line are always written before this returns. With CTF_SOUND=1 a
    critical alert then takes about ten seconds to speak and ring. A caller with a clock to catch passes wait=False:
    the channels are handed to a separate process and the result says {'detached': started}."""
    channels, logged, line = {}, False, ""
    try:
        name = str(level).lower()
        message = scrub(message)
        where = scrub(lane) if lane else "-"
        line = f"{datetime.now().astimezone().isoformat(timespec='seconds')} {name.upper()} [{where}] {message}"
        try:
            print(f"ALERT {name.upper()} [{where}] {message}", file=sys.stderr, flush=True)
        except Exception:
            pass
        try:
            path = log_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            logged = True
        except (Exception, SystemExit):   # whatever goes wrong resolving the path only leaves the alert unlogged
            pass
        if ctf_env.get("CTF_QUIET") != "1":
            title = f"{TITLE}: {where}" if lane else TITLE
            if wait:
                channels = _deliver(name, title, message)
            else:
                try:   # a session of its own, so it outlives a caller that exits
                    subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--deliver", name, title, message],
                                     start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
                    channels = {"detached": True}
                except Exception:
                    channels = {"detached": False}
        return {"level": name, "line": line, "logged": logged, "channels": channels}
    except Exception:
        return {"level": str(level), "line": line, "logged": logged, "channels": channels}


def main():
    args, lane = sys.argv[1:], None
    if len(args) == 4 and args[0] == "--deliver":   # the detached half of alert(..., wait=False): channels only
        if ctf_env.get("CTF_QUIET") != "1":
            _deliver(args[1], scrub(args[2]), scrub(args[3]))
        return
    if "--lane" in args:
        i = args.index("--lane")
        if i + 1 >= len(args):
            args = []
        else:
            lane = args[i + 1]
            del args[i:i + 2]
    if len(args) < 2 or args[0] not in LEVELS:
        print("usage: alert.py <info|warn|critical> [--lane LANE] <message ...>", file=sys.stderr)
        sys.exit(2)
    alert(args[0], " ".join(args[1:]), lane)


if __name__ == "__main__":
    main()
