"""Command line for the CSCTF solver backbone.

    .venv/bin/python -m ctf me                     check the token / show who we are
    .venv/bin/python -m ctf list [--category C]    list visible challenges (solved ones marked)
    .venv/bin/python -m ctf pull <id|all>          download challenge(s) into the workspace + triage + sweep
    .venv/bin/python -m ctf triage <id>            re-run triage on an already-pulled challenge
    .venv/bin/python -m ctf submit <id> <flag>     submit one flag on sight through the gate and the
                                                   team's submit queue (B-006; see submit-queue)
    .venv/bin/python -m ctf status                 our scoreboard line + solved/open counts
    .venv/bin/python -m ctf check <id>             has the team already solved it?
    .venv/bin/python -m ctf wait [--grow-from N|now] [--not-before T]
                                                   block until a wave opens (first or later wave)

Nothing here loops over candidate flags, scans, or touches other teams' instances.

Manual mode is code-enforced (R-02): every built-in command that reaches the platform builds its
client through ctf.client, which refuses (ctf/platform/legacy.py) before any session or socket exists
when the event (CTF_EVENT, else the only profile) is manual or forbids automation on its platform;
submit also refuses submit_mode manual. A refusal prints "ctf <cmd>: refused: <reason>" and exits
REFUSED_EXIT (4). `submit` goes through ctf.platform.get_adapter (the submit gate and queue), not
ctf.client; a gate refusal (wrong-answer stop, dedupe, format) also exits 4. Exit codes: 0 ok, 1 command-specific failure, 2 error, 3 challenges not open yet,
4 refused by the event's rules.

New subcommands do NOT go in this file. Each is its own module ctf/cli/<name>.py (underscores
become dashes on the command line), discovered at startup, exposing:

    HELP = "one line for --help"
    def add_arguments(parser: argparse.ArgumentParser) -> None
    def run(args: argparse.Namespace) -> int

Modules whose name starts with "_" are not commands. A command module that fails to import is
still listed (marked BROKEN) and exits 2 with the import error when run; the other commands keep
working. A discovered name that collides with a built-in command below is an error. The built-in
commands here are the carried CSCTF CLI; unit B-001a moves them out into their own modules.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .. import client as _client
from .. import config as _config
from .. import paths as _paths
from .. import triage as _triage
from .. import workspace as _ws
from ..platform import NotSupported
from . import _pullsweep

REFUSED_EXIT = 4   # the event's rules forbid the call (manual mode); nothing reached the platform


def _ctfd() -> _client.CTFd:
    return _client.connect()


def cmd_me(args) -> int:
    c = _ctfd()
    c.cfg.require_auth()
    me = c.me()
    print(f"user: {me.get('name')} (id {me.get('id')})  team_id={me.get('team_id')}")
    t = c.team()
    if t:
        print(f"team: {t.get('name')} (id {t.get('id')})  score={t.get('score')}  place={t.get('place')}")
    return 0


def cmd_list(args) -> int:
    c = _ctfd()
    c.cfg.require_auth()
    chs = c.challenges()
    solved = c.team_solved_ids()
    cats: dict[str, list] = {}
    for ch in chs:
        cats.setdefault(ch.get("category", "?"), []).append(ch)
    for cat in sorted(cats):
        if args.category and _triage.canonical_category(cat) != _triage.canonical_category(args.category):
            continue
        print(f"\n== {cat} ==")
        for ch in sorted(cats[cat], key=lambda x: x.get("value", 0)):
            mark = "x" if (ch["id"] in solved or ch.get("solved_by_me")) else " "
            print(f"  [{mark}] {ch['id']:>4}  {ch.get('value','?'):>4}  {ch.get('name')}")
    return 0


def _pull_one(c: _client.CTFd, cid: int) -> _ws.Challenge:
    from .. import stages as _stages                     # B-101: the wave replay times the intake
    _stages.try_mark("intake_start", str(cid))
    try:
        ch = _pull_one_inner(c, cid)
    except BaseException:
        _stages.try_mark("intake_done", str(cid), ok=False)
        raise
    _stages.try_mark("intake_done", str(cid), ok=True)
    return ch


def _pull_one_inner(c: _client.CTFd, cid: int) -> _ws.Challenge:
    detail = c.challenge(cid)
    ch = _ws.for_challenge(detail)
    c.download_files(cid, ch.files_dir)
    s = _triage.suggest(ch.category, detail.get("description", ""), ch.files_dir)
    ch.note("\n## triage\n\n```\n" + _triage.render(s) + "\n```")
    print(f"pulled {cid} -> {ch.dir}")
    print(_triage.render(s))
    _pullsweep.after_pull(ch)       # B-013: unpack + flag sweep into <challenge>/unpacked/
    return ch


def cmd_pull(args) -> int:
    c = _ctfd()
    c.cfg.require_auth()
    if args.target == "all":
        solved = c.team_solved_ids()
        for ch in c.challenges():
            if ch["id"] in solved:
                continue
            try:
                _pull_one(c, ch["id"])
            except _client.CTFdError as e:
                print(f"  skip {ch['id']}: {e}", file=sys.stderr)
    else:
        _pull_one(c, int(args.target))
    return 0


def cmd_triage(args) -> int:
    c = _ctfd()
    detail = c.challenge(int(args.id))
    ch = _ws.for_challenge(detail)
    print(_triage.render(_triage.suggest(ch.category, detail.get("description", ""), ch.files_dir)))
    return 0


def cmd_submit(args) -> int:
    # B-006: one POST through the gate and the team's queue (no challenge or solves read first).
    from . import submit_queue as _sq
    return _sq.submit_one(args.id, args.flag, note=args.note or "manual cli submit",
                          confirmed=args.confirm, allow_nonstandard=args.nonstandard, guess=args.guess,
                          source=args.source, local_checks=args.passed)


def _add_plausibility_args(p) -> None:
    # B-154: the plausibility check's inputs (ctf/flagcheck.py), as `ctf flag check` takes them
    from .. import flagcheck as _fc
    p.add_argument("--source", choices=sorted(_fc.SOURCES),
                   help="how the value was found: a static shortcut (strings, grep, intake...) draws a "
                        "decoy warning, a case-losing cipher (enigma, morse...) case guidance")
    p.add_argument("--passed", action="append", default=[], metavar="CHECK",
                   help="a local check the value passed, e.g. pkcs7, hmac (repeatable; named in a decoy "
                        "warning)")


def cmd_status(args) -> int:
    c = _ctfd()
    c.cfg.require_auth()
    chs = c.challenges()
    solved = c.team_solved_ids()
    print(f"challenges visible: {len(chs)}  solved: {len(solved & {x['id'] for x in chs})}")
    t = c.team()
    if t:
        print(f"team {t.get('name')}: score={t.get('score')} place={t.get('place')}")
    return 0


def cmd_check(args) -> int:
    c = _ctfd()
    c.cfg.require_auth()
    solved = c.team_solved_ids()
    print("solved" if int(args.id) in solved else "not solved")
    return 0


def cmd_doctor(args) -> int:
    """Race-morning readiness check: auth, Docker + images, host tools, engines, workspace."""
    import importlib
    import shutil
    import subprocess
    ok = True

    GRN, RED, YEL, RST = "\033[32m", "\033[31m", "\033[33m", "\033[0m"

    def line(good, label, detail=""):
        """Required check: green OK / red XX, and a miss fails the wave."""
        nonlocal ok
        ok = ok and good
        tag = f"{GRN}OK {RST}" if good else f"{RED}XX {RST}"
        print(f"  [{tag}] {label}{(' — ' + detail) if detail else ''}")

    def opt(good, label, detail=""):
        """Optional check: green OK / yellow -- ; a miss is reported but never fails the wave."""
        tag = f"{GRN}OK {RST}" if good else f"{YEL}-- {RST}"
        print(f"  [{tag}] {label}{(' — ' + detail) if detail else ''}")

    cfg = _config.load()
    print("auth:")
    line(bool(cfg.token or cfg.cookie), "token/cookie present",
         "token" if cfg.token else ("cookie" if cfg.cookie else "MISSING: put it in .ctf/token"))
    if cfg.token or cfg.cookie:
        try:
            me = _client.connect(cfg).me()
            line(True, "API auth works", f"user {me.get('name')} / team {me.get('team_id')}")
        except Exception as e:
            line(False, "API auth works", str(e)[:70])

    print("docker (detonation + pwn):")
    have_docker = shutil.which("docker") is not None
    daemon = have_docker and subprocess.run(["docker", "info"], capture_output=True).returncode == 0
    if have_docker and not daemon and getattr(args, "start_docker", False):
        import time
        print("  launching Docker Desktop (open -g -a Docker)...")
        subprocess.run(["open", "-g", "-a", "Docker"], capture_output=True)
        for _ in range(60):  # up to ~120s for the daemon to come up
            time.sleep(2)
            if subprocess.run(["docker", "info"], capture_output=True).returncode == 0:
                daemon = True
                break
    from .. import sandboxinfo as _sbx
    _sb = _sbx.detect()
    if not daemon and _sb.sandboxed:      # B-190: inside a sandbox this is not a host fact
        opt(False, "docker daemon up [sandbox-only]", f"not reachable from here ({_sb.summary()}); "
            "re-run `ctf doctor` on the host to confirm")
    else:
        line(daemon, "docker daemon up", "" if daemon else "start Docker Desktop (or pass --start-docker)")
    if daemon:
        imgs = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                              capture_output=True, text=True).stdout
        for img in ("csctf-sandbox:2", "csctf-pwn:1", "csctf-pwn-multiarch:1"):
            line(img in imgs, f"image {img}", "" if img in imgs else "run ./setup.sh")

    print("host tools:")
    for t in ("ghidraRun", "radare2", "jadx", "sqlmap", "hashcat", "john", "ffuf", "exiftool"):
        line(shutil.which(t) is not None, t, "" if shutil.which(t) else "missing (./setup.sh)")
    # sops, age, rclone, git-crypt, ccrypt, keepassxc-cli, websocat (and veracrypt, firefox_decrypt):
    # one list, tools/toolbox.toml, checked once by the `toolbox` preflight check below (B-142).
    print("  (key-leak/decrypt tools: the `toolbox` check below; `ctf toolbox verify` alone)")

    print("host extras (optional — a miss won't block the wave):")
    import os
    # cracking helpers exposed by setup.sh (bkcrack not in homebrew-core; john helpers
    # live in the Cellar and are symlinked onto PATH by setup.sh).
    # flask-unsign and other python console-scripts install into the venv's bin, which may not be on
    # $PATH; check there too so the doctor doesn't cry wolf on a tool that's actually usable.
    venv_bin = os.path.join(os.path.dirname(sys.executable), "")
    def _which2(t):
        return shutil.which(t) or next((p for p in (venv_bin + t,) if os.path.exists(p)), None)
    for t in ("bkcrack", "zip2john", "unshadow", "mdb-tables", "flask-unsign"):
        w = _which2(t)
        opt(w is not None, t, w or "missing (./setup.sh)")
    # rockyou wordlist: setup.sh's path first, then common system fallbacks.
    rock = next((p for p in (os.path.expanduser("~/tools/wordlists/rockyou.txt"),
                             "/usr/share/wordlists/rockyou.txt",
                             "/opt/homebrew/share/wordlists/rockyou.txt")
                 if os.path.exists(p)), None)
    opt(rock is not None, "rockyou.txt wordlist", rock or "missing (./setup.sh)")
    # opencv (image/forensics CV) import — big optional wheel, so non-fatal.
    try:
        importlib.import_module("cv2")
        opt(True, "import cv2 (opencv)")
    except Exception as e:
        opt(False, "import cv2 (opencv)", str(e)[:55])

    print("engines (import sample):")
    REPO = _paths.repo_root()
    for d in ("solvers/common", "solvers/toolkits", "solvers/warmups"):
        p = str(REPO / d)
        if p not in sys.path:
            sys.path.insert(0, p)
    for m in ("modern_crypto", "network", "carve_stego", "ics_scada", "healthcare",
              "financial", "transport", "telecom", "pwn_exploit", "crib_decode"):
        try:
            importlib.import_module(m)
            line(True, f"import {m}")
        except Exception as e:
            line(False, f"import {m}", str(e)[:60])

    print("workspace:")
    try:
        _ws.root(cfg)
        line(True, "workdir writable", str(cfg.workdir))
    except Exception as e:
        line(False, "workdir writable", str(e)[:60])

    print("preflight (B-039: ctf/doctor.py; `ctf preflight` runs these alone):")
    from .. import doctor as _doctor
    from .. import event as _event
    try:
        prof = _event.current()
    except _event.EventError as e:
        line(False, "event profile", str(e))
    else:
        for c in _doctor.run_checks(prof, codex=not getattr(args, "no_codex", False), sandbox=_sb):
            # B-190: only a blocking check's fail is an XX; advisory and sandbox-only results are --
            tag = " [sandbox-only]" if c.sandbox_only else (" [advisory]" if c.level == "advisory" else "")
            (line if c.blocking or c.status == "ok" else opt)(c.status == "ok", c.name + tag, c.detail[:160])

    print("\n" + ("ALL GREEN — ready for the wave." if ok else "SOME CHECKS FAILED — see XX above."))
    return 0 if ok else 1


def _parse_when(text: str) -> float:
    """`--not-before` value -> epoch seconds. Accepts epoch seconds or ISO-8601 WITH a UTC offset.

    A naive timestamp is refused: wave times are announced in a local zone and a silent guess
    would shift the start by hours."""
    import datetime as _dt
    t = text.strip()
    try:
        return float(t)
    except ValueError:
        pass
    try:
        when = _dt.datetime.fromisoformat(t.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"--not-before {text!r}: not epoch seconds or ISO-8601") from None
    if when.tzinfo is None:
        raise ValueError(f"--not-before {text!r} has no UTC offset; write e.g. 2026-11-07T08:00-05:00")
    return when.timestamp()


def _parse_grow_from(text: str):
    """`--grow-from` value -> int baseline, or "now" (baseline = count at the first successful poll)."""
    if text == "now":
        return "now"
    try:
        n = int(text)
    except ValueError:
        raise ValueError(f"--grow-from {text!r}: an integer challenge count or 'now'") from None
    if n < 0:
        raise ValueError(f"--grow-from {text!r}: must be >= 0")
    return n


def wait_for_open(list_challenges, *, interval: float, timeout: float, grow_from=None,
                  not_before: float | None = None, clock=None, sleep=None, log=None) -> tuple[int, str]:
    """Poll `list_challenges()` until a wave is open. Returns (exit code, message).

    First wave (no `grow_from`): open = the challenge list stops answering 403 (403 -> 200).
    Later wave (`grow_from=N` or "now"): open = more than N challenges are visible. The board already
    answers 200 then, so a 403 -> 200 check would fire at once on the old wave.
    `not_before` (epoch seconds): no poll is sent before that time; the timeout counts from then.
    Exit codes: 0 open, 1 timeout, 2 an error other than the pre-open 403."""
    import time as _time
    clock = clock or _time.time
    sleep = sleep or _time.sleep
    log = log or (lambda m: print(m, file=sys.stderr))
    if interval <= 0:
        return 2, f"--interval must be > 0, got {interval}"

    if not_before is not None:
        gap = not_before - clock()
        if gap > 0:
            log(f"not polling before the wave start: sleeping {int(gap)}s")
        while clock() < not_before:
            sleep(min(interval * 8, max(not_before - clock(), 0.0)) or interval)

    started = clock()
    baseline = grow_from
    last_seen = None
    next_note = 120.0
    while True:
        try:
            n = len(list_challenges())
        except _client.CTFdError as e:
            if "403" not in str(e):
                return 2, f"CTFd error (not the pre-open 403): {e}"
            n = None
        if n is not None:
            if baseline is None:
                return 0, f"OPEN — {n} challenges visible."
            if baseline == "now":
                baseline = n
                log(f"baseline: {n} challenges visible; waiting for more")
            elif n > baseline:
                return 0, f"OPEN — {n} challenges visible ({n - baseline} new since baseline {baseline})."
            if n != last_seen:
                last_seen = n
                if n < baseline:
                    log(f"  {n} visible, below the baseline {baseline}; still waiting")
        elapsed = clock() - started
        if elapsed >= timeout:
            what = (f"still {last_seen if last_seen is not None else 'no'} challenges visible, "
                    f"need more than {baseline}" if baseline is not None and baseline != "now"
                    else "challenges still not open")
            return 1, f"timed out after {int(elapsed)}s — {what}."
        sleep(interval)
        if clock() - started >= next_note:
            log(f"  still waiting after {int(clock() - started)}s...")
            next_note += 120.0


def cmd_wait(args) -> int:
    """Block until a wave opens, then exit 0.

    First wave: polls /challenges until it's visible (403 -> 200). Later wave: `--grow-from N` (or
    `now`) waits for the visible challenge count to exceed N, and `--not-before T` holds every poll
    until the announced start. Exit 0 = open (prints the challenge count), 1 = timeout, 2 = auth/other
    error. Polling our own account's challenge list at a modest interval is not scanning/flooding."""
    try:
        grow_from = _parse_grow_from(args.grow_from) if args.grow_from is not None else None
        not_before = _parse_when(args.not_before) if args.not_before is not None else None
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2
    # `wave` is a B-101 flag; direct callers (e.g. tests driving cmd_wait) may omit it, so read it
    # defensively rather than assume the argparse default is always present.
    wave = getattr(args, "wave", None)
    if wave is not None and _wave_label_taken(wave):
        print(f"ctf wait: wave {wave!r} is already in the ledger; pick another --wave label "
              "(see `ctf ledger waves`)", file=sys.stderr)
        return 2
    c = _ctfd()
    c.cfg.require_auth()
    mode = ("first wave (403 -> 200)" if grow_from is None
            else f"later wave (count > {grow_from})")
    print(f"waiting for the wave to open: {mode}, poll every {args.interval}s, timeout {args.timeout}s...",
          file=sys.stderr)
    # B-017: while `ctf watch run` polls this event's board, wait on its stream instead of the platform.
    from .. import event as _event
    from .. import watch as _watch
    note = lambda m: print(f"ctf wait: {m}", file=sys.stderr)  # noqa: E731
    if not_before is not None:      # B-140: the announced start is a release window for every lane
        from ..platform import wire as _wire
        try:
            _wire.mark_releases(_paths.workdir(), [not_before])
        except (_event.EventError, _wire.WireError) as e:
            note(f"--not-before not recorded as a release anchor ({e}); `ctf wire mark-release` does it")
    try:
        source = _watch.board_reader(_paths.workdir(), c.challenges, _client.CTFdError, note)
    except _event.EventError as e:
        note(f"no event workdir ({e}): cannot share a ctf watch stream; polling the board directly")
        source = c.challenges

    # B-101: capture the ids the last poll saw, so a successful wait records one detect per challenge.
    # `source` yields challenge dicts when polling the board directly, or bare ids from the watch stream.
    listed: list = []

    def listing():
        chs = source()
        ids = []
        for ch in chs:
            cid = ch.get("id") if isinstance(ch, dict) else ch
            if cid is not None:
                ids.append(cid)
        listed[:] = ids
        return chs

    code, msg = wait_for_open(listing, interval=args.interval, timeout=args.timeout,
                              grow_from=grow_from, not_before=not_before)
    print(msg, file=sys.stdout if code == 0 else sys.stderr)
    if code == 0:   # B-101: wave_open + one detect per new challenge, for `ctf ledger replay`
        _record_wave(listed, label=wave, announced=not_before)
    return code


def _wave_label_taken(label: str) -> bool:
    """Whether `label` already names a wave in the ledger. A ledger that cannot be resolved or read is
    not a clash here: it is warned about now, the wait goes on, and _record_wave reports again why the
    wave is not recorded once the board opens."""
    from .. import stages as _stages
    try:
        return label in _stages.wave_labels()
    except (OSError, ValueError) as e:          # EventError is a ValueError
        print(f"ctf wait: warning: cannot read the ledger to check wave label {label!r}: {e}; "
              "waiting anyway, but the wave will not be recorded unless the ledger is fixed",
              file=sys.stderr)
        return False


def _record_wave(ids, *, label, announced) -> None:
    from .. import stages as _stages
    from ..event import EventError
    try:
        _stages.record_wave(ids, label=label, announced=announced)
    except (EventError, OSError) as e:          # no workdir resolves, or the write failed
        print(f"ctf wait: wave not recorded in the ledger: {e} (set CTF_WORKDIR or CTF_EVENT)",
              file=sys.stderr)
    except ValueError as e:                     # StageError (a label clash, a bad id) or a corrupt line
        print(f"ctf wait: wave not recorded in the ledger: {e}", file=sys.stderr)


class CLIError(RuntimeError):
    pass


_COMMAND_API = ("HELP", "add_arguments", "run")


def discover(search_path=None, package: str | None = None):
    """[(command name, module | None, error | None)] for every ctf/cli/<name>.py, sorted by name.
    `search_path`/`package` default to this package (tests point them at a scratch package)."""
    import importlib
    import pkgutil
    search_path = __path__ if search_path is None else search_path
    package = __name__ if package is None else package
    out = []
    for info in sorted(pkgutil.iter_modules(search_path), key=lambda i: i.name):
        if info.name.startswith("_") or info.ispkg:
            continue
        name = info.name.replace("_", "-")
        try:
            mod = importlib.import_module(f"{package}.{info.name}")
        except Exception as e:  # reported as BROKEN, never hidden
            out.append((name, None, f"{type(e).__name__}: {e}"))
            continue
        missing = [a for a in _COMMAND_API if not hasattr(mod, a)]
        if missing:
            out.append((name, None, f"ctf/cli/{info.name}.py lacks {', '.join(missing)}"))
            continue
        out.append((name, mod, None))
    return out


def _broken(name: str, err: str):
    def fn(args) -> int:
        print(f"ctf {name}: this command is broken: {err}", file=sys.stderr)
        return 2
    return fn


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="ctf", description="CTF master solver")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("me").set_defaults(fn=cmd_me)
    pl = sub.add_parser("list"); pl.add_argument("--category"); pl.set_defaults(fn=cmd_list)
    pp = sub.add_parser("pull"); pp.add_argument("target"); pp.set_defaults(fn=cmd_pull)
    pt = sub.add_parser("triage"); pt.add_argument("id"); pt.set_defaults(fn=cmd_triage)
    ps = sub.add_parser("submit"); ps.add_argument("id"); ps.add_argument("flag"); ps.add_argument("--note")
    ps.add_argument("--confirm", action="store_true",
                    help="the player confirmed this send (confirm mode; past the wrong-answer stop it "
                         "also needs a recorded approval: submit-queue approve)")
    ps.add_argument("--nonstandard", action="store_true",
                    help="an answer in a shape the brief defines (coordinates, a name), not the flag format")
    ps.add_argument("--guess", action="store_true",
                    help="an unreasoned variant of an earlier value: counted against rules.guess_budget "
                         "and logged with its note (B-173; `ctf policy guesses`)")
    _add_plausibility_args(ps)
    ps.set_defaults(fn=cmd_submit)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    pc = sub.add_parser("check"); pc.add_argument("id"); pc.set_defaults(fn=cmd_check)
    pdoc = sub.add_parser("doctor"); pdoc.add_argument("--start-docker", action="store_true",
        help="launch Docker Desktop and wait for the daemon if it's not up")
    pdoc.add_argument("--no-codex", action="store_true", help="skip the Codex model check and smoke call")
    pdoc.set_defaults(fn=cmd_doctor)
    pw = sub.add_parser("wait"); pw.add_argument("--interval", type=int, default=15)
    pw.add_argument("--timeout", type=int, default=3600)
    pw.add_argument("--grow-from", dest="grow_from", metavar="N|now",
                    help="later wave: open when more than N challenges are visible ('now' = current count)")
    pw.add_argument("--not-before", dest="not_before", metavar="T",
                    help="no poll before T (epoch seconds or ISO-8601 with offset); timeout counts from T")
    pw.add_argument("--wave", metavar="LABEL",
                    help="label for the wave recorded in the ledger (default W<n>; see `ctf ledger replay`)")
    pw.set_defaults(fn=cmd_wait)
    for name, mod, err in discover():
        if name in sub.choices:
            raise CLIError(f"ctf/cli/{name.replace('-', '_')}.py collides with the built-in command {name!r}")
        if err is not None:
            sp = sub.add_parser(name, help=f"BROKEN: {err}")
            sp.set_defaults(fn=_broken(name, err))
            continue
        sp = sub.add_parser(name, help=mod.HELP, description=mod.HELP)
        mod.add_arguments(sp)
        sp.set_defaults(fn=mod.run)
    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except NotSupported as e:
        print(f"ctf {args.cmd}: refused: {e}", file=sys.stderr)
        return REFUSED_EXIT
    except _client.CTFdError as e:
        msg = str(e)
        if "403" in msg and "/challenges" in msg:
            print("Challenges aren't visible yet — CTFd gates them until the competition/wave opens "
                  "(see the event profile for wave times). Auth is working (try `ctf me`); re-run at the "
                  "wave, or use `ctf wait`.", file=sys.stderr)
            return 3
        print(f"CTFd error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
