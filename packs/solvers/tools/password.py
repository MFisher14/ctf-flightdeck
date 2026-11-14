#!/usr/bin/env python3
"""Archive passwords: add the one the player gives, list them, check which one opens a file.

  python3 tools/password.py add VALUE [--source player]
  python3 tools/password.py list
  python3 tools/password.py check FILE
  python3 tools/password.py harvest FILE [--no-siblings]

Evidence zips have always opened with `infected`. Every reader of an encrypted delivery (tools/run.py
via run.expand, tools/unpack.py) tries `infected` first and then every password in
<challenges>/_passwords.json, newest first, and reads that file on every decrypt: a password added
here is used by the next decrypt of a process that is already running, with no restart. Nothing else
is ever tried: no password is generated or guessed. (solvers/common/archive_passwords.py is the reader.)

  add VALUE      Store VALUE (quote it for the shell: `tools/password.py add 'the value'`). --source
                 says where it came from (player by default). A value that is `infected` or already
                 stored changes nothing. The value is never printed: every line shows its length and
                 first character only.
  list           The stored passwords, masked, newest first, with when and where from.
  check FILE     Which candidate opens FILE (a zip, or a 7z with 7-Zip installed), masked.
  harvest FILE   Read candidate passwords out of FILE's own bytes (appended overlay, readable strings)
                 and, unless --no-siblings, the small text files beside it, and store the new ones
                 (source `harvest`). The next decrypt of any running process tries them. Values are
                 never printed; only the count of new candidates and their masks are shown.

When no candidate opens a delivery, the run that met it raises one critical alert
`ARCHIVE PASSWORD NEEDED <lane> <file>`, writes <challenges>/_logs/password_needed.json
{lane, challenge, file, at, candidates} and ends without a verdict. After `add`, run it again.

Exit status:
  0  add: stored (or already known); list: listed; check: a candidate opens the file, or it is not encrypted
  1  check: no candidate opens the file
  2  usage error, an unusable value, or a file that cannot be read
  3  the store could not be written

No token is read.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "solvers" / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))
import archive_passwords as pw  # noqa: E402

NEEDED_FILE = "password_needed.json"
SEVENZ_MAGIC = b"7z\xbc\xaf\x27\x1c"


def _alert_words(text) -> str:
    """Letters, digits and single spaces: what goes into the alert's text."""
    return " ".join(re.sub(r"[^A-Za-z0-9]+", " ", str(text or "")).split())


def needed_path() -> Path:
    return pw.challenges_root() / "_logs" / NEEDED_FILE


def needed(lane, challenge, file, wait=False) -> str:
    """No candidate opens `file` of `challenge`: raise ONE critical alert, write
    _logs/password_needed.json, and return the reason line the lane stops with,
    'archive password needed: <file>'. The same lane, challenge, file and number of candidates
    as the file already records is not alerted again (a lane's second step on the same archive);
    a password added since that still does not fit is. It never raises."""
    reason = f"archive password needed: {Path(str(file)).name}"
    try:
        count = len(pw.candidates())
        row = {"lane": lane, "challenge": challenge, "file": Path(str(file)).name,
               "at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "candidates": count}
        path = needed_path()
        try:
            old = json.loads(path.read_text())
        except (OSError, ValueError):
            old = None
        again = isinstance(old, dict) and all(old.get(k) == row[k] for k in ("lane", "challenge", "file", "candidates"))
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".password_needed.", dir=str(path.parent))
        with os.fdopen(fd, "w") as f:
            json.dump(row, f, indent=2)
        os.replace(tmp, path)
        if not again:
            if str(HERE) not in sys.path:
                sys.path.insert(0, str(HERE))
            import alert
            alert.alert("critical", f"ARCHIVE PASSWORD NEEDED {_alert_words(lane)} {_alert_words(row['file'])}",
                        lane=lane, wait=wait)
    except Exception:          # the reason still reaches the lane; only the alert or the file is lost
        pass
    return reason


# ---------------------------------------------------------------------------- check

def _check_7z(data: bytes):
    """(opened, the candidate) for a 7z archive, with 7-Zip; (None, None) when 7-Zip is missing."""
    exe = shutil.which("7zz") or shutil.which("7z")
    if not exe:
        return None, None
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "archive.7z"
        src.write_bytes(data)
        for pwd in pw.candidates():
            done = subprocess.run([exe, "t", "-y", "-p" + pwd.decode("utf-8", "replace"), str(src)],
                                  capture_output=True, timeout=60)
            if done.returncode == 0:
                return True, pwd
    return False, None


def check(path: str) -> int:
    try:
        data = Path(path).read_bytes()
    except OSError as e:
        print(f"password.py: {path}: {e.strerror or e}", file=sys.stderr)
        return 2
    if data[:6] == SEVENZ_MAGIC:
        opened, pwd = _check_7z(data)
        if opened is None:
            print("password.py: 7-Zip is not installed, so a 7z archive cannot be checked", file=sys.stderr)
            return 2
        print(f"CHECK {Path(path).name}: " + (f"opens with {pw.mask(pwd)}" if opened else "no candidate opens it"))
        return 0 if opened else 1
    try:
        op = pw.Opener(data)
    except Exception as e:
        print(f"password.py: {path} is not a zip this can read ({type(e).__name__})", file=sys.stderr)
        return 2
    infos = [i for i in op.zf.infolist() if not i.is_dir()]
    locked = [i for i in infos if pw.encrypted(i)]
    if not locked:
        print(f"CHECK {Path(path).name}: not encrypted ({len(infos)} member(s))")
        return 0
    for info in locked:
        op.read(info)
    good = op.password_for()
    if op.locked or good is None:
        print(f"CHECK {Path(path).name}: no candidate opens {len(op.locked) or len(locked)} of {len(locked)} encrypted "
              f"member(s) ({len(pw.candidates())} candidate(s) tried)")
        return 1
    print(f"CHECK {Path(path).name}: opens with {pw.mask(good)} ({len(locked)} encrypted member(s))")
    return 0


def harvest_cmd(path: str, include_siblings: bool = True) -> int:
    """Harvest candidate passwords from `path` (and, by default, its siblings) and add the new ones to
    the store. Exit 0 on a clean read (even when nothing was new), 2 when the file cannot be read,
    3 when the store could not be written."""
    if not os.path.exists(path):
        print(f"password.py: {path}: no such file", file=sys.stderr)
        return 2
    if str(COMMON) not in sys.path:
        sys.path.insert(0, str(COMMON))
    import harvest as hv
    cands = hv.harvest(path, include_siblings=include_siblings)
    try:
        new = pw.add_many(cands, source="harvest")
    except OSError:
        print(f"password.py: the store {pw.store_path()} could not be written", file=sys.stderr)
        return 3
    print(f"HARVEST {Path(path).name}: {len(cands)} candidate(s) read, {len(new)} new")
    for value in new:
        print(f"  added {pw.mask(value)}")
    return 0


def listing() -> int:
    rows = list(enumerate(pw.stored()))
    rows.sort(key=lambda p: (str(p[1].get("added") or ""), p[0]), reverse=True)
    print(f"{pw.mask(pw.DEFAULT.decode())}  built in")
    for _, row in rows:
        print(f"{pw.mask(row['value'])}  added {row.get('added') or '?'}  source {row.get('source') or '?'}")
    print(f"PASSWORDS candidates={len(pw.candidates())} file={pw.store_path()}")
    return 0


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    usage = ("usage: password.py add VALUE|- [--source player] | list | check FILE | "
             "harvest FILE [--no-siblings]   (- reads the value from stdin)")
    if not args or args[0] in ("-h", "--help"):
        print(__doc__ if args else usage, file=sys.stdout if args else sys.stderr)
        return 0 if args else 2
    cmd, rest = args[0], args[1:]
    if cmd == "list" and not rest:
        return listing()
    if cmd == "check" and len(rest) == 1:
        return check(rest[0])
    if cmd == "harvest" and rest:
        include_siblings = True
        if "--no-siblings" in rest:
            include_siblings = False
            rest = [r for r in rest if r != "--no-siblings"]
        if len(rest) != 1:
            print(usage, file=sys.stderr)
            return 2
        return harvest_cmd(rest[0], include_siblings=include_siblings)
    if cmd == "add" and rest:
        source = "player"
        if "--source" in rest:
            i = rest.index("--source")
            if i + 1 >= len(rest):
                print(usage, file=sys.stderr)
                return 2
            source = rest[i + 1]
            del rest[i:i + 2]
        if len(rest) != 1:
            print(usage + "  (quote a value that has spaces)", file=sys.stderr)
            return 2
        if rest[0] == "-":     # read the value from stdin, so it stays out of the process list and shell history
            rest[0] = sys.stdin.readline().rstrip("\r\n")
        try:
            new = pw.add(rest[0], source=source)
        except ValueError as e:
            print(f"password.py: {e}", file=sys.stderr)
            return 2
        except OSError as e:
            print(f"password.py: the store {pw.store_path()} could not be written ({type(e).__name__})", file=sys.stderr)
            return 3
        print(f"ADDED {pw.mask(rest[0])} source={source}" if new else f"KNOWN {pw.mask(rest[0])}: nothing changed")
        return 0
    print(usage, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
