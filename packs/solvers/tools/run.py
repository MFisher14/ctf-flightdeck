#!/usr/bin/env python3
"""One-process attempt runner: start -> download -> solve -> submit.

Usage:
  python3 tools/run.py <challenge-id> <solver.py> [--dry-run | --offline [DIR]] [--retry | --practice]
                       [--no-submit] [--no-save] [--solve-timeout SECONDS] [--quiet]

  --dry-run    Read the attempt with op=status instead of starting it, run the
               solver, and print the answers. Never starts a clock and never
               submits. Works on solved attempts, so use it to regression-test
               a solver against earlier variants.
  --offline    Replay the attempt saved under challenges/ (or under DIR) without
               any Game Master call: attempt.json plus artifact/. This is how
               to fix a solver against a timed variant after its clock ran out.
  --retry      Renew an expired timed attempt (next variant) before solving.
  --practice   A timed id whose fresh timed variants are used up: instead of a retry, post
               the untimed continuation the contract names: a retry without run_for_time (a
               dual-pool route) and {"op":"practice"} (a legacy route), the one that fits the
               route first, each once. No timer, no Hall of Fame time; it can still complete
               the mode. A retry that is refused because no fresh variant remains turns into
               this by itself. Needs a ticket like any timed start; the run says `NOTE
               practice attempt on a timed id` and result.json `practice`.
  --rejoin     (backlog row 250; only tools/open_day.py passes it, under "start": "regular") The
               attempt of this timed id on disk is a regular attempt of ours that is still open:
               it has no deadline, and a rejected batch left it open. No retry is posted: the
               plain start returns it (`NOTE rejoin: the start returned our open attempt`); when
               the start returns no attempt, ONE retry is sent in its place. Needs a ticket.
  --start-only (W-5, Day 19 build; only tools/open_day.py passes it, on its forced path for a lane
               with no delivery and a live target; the solver argument is then '-') Inside
               judge.clock(), ONE plain start (no run_for_time, no ladder, no fall-back to the flag
               body), saved as start.json and live_start.json in the id's folder; then the run ends:
               nothing is downloaded, solved or submitted, so the clock lock is held for the start
               alone. Refused with no request unless CTF_RFT_SUPPORTED=1. `RUN result=started_live`
               for a start that returned an attempt; the answers go by hand through
               tools/verify.py <id> --answers FILE.
  --no-submit  Start and solve, but do not submit.
  --no-save    With --dry-run or --offline: write no file at all.
  --solve-timeout SECONDS
               Stop the solver after this long and report what it has so far.
  --quiet      Do not print every answer.

Timed windows have been as short as 5 seconds, so everything between start and
submit happens here on one keep-alive pool, and the solver is imported before
the clock starts. The attempt and its deliveries are written to disk as soon as
they are downloaded (a few milliseconds), so an attempt that fails or expires
still leaves its variant behind. On a timed attempt the solver is stopped
shortly before the deadline and whatever is already answered is submitted.

The Game Master rate-limits bursts (HTTP 429 `rate_limited`, shared by every
agent on the token). A rate-limited request was not processed, so the runner
pauses briefly and sends it again, and it will not start a clock while the
limiter is still answering 429. A timed run that begins while the wire governor
(tools/judge.py) already holds a rate-limit pause waits for the pause to end
before its first request (see wait_out_pause), instead of reading into it.

A Time Trial or Mastery id is started only with a ticket from
`tools/preflight.py --gate <id>` and runs inside judge.clock(), so there is one
clock at a time on this machine. Without a ticket nothing is requested. Solver
switches (ONLY, BATCH_*, ...) are taken out of the environment of a timed run.

No status read before a timed start (package PR1, the player's decision of
2026-10-11; the switch `preread` of tools/switches.py, `none` in force without
the file). The start is the run's first request: judge.clock() still waits out a
rate-limit pause the governor knows, a start answered 429 starts no clock (`RUN
result=rate_limited`, as a refused warm-up read ended), the start body follows
the id's op=list row (start_order), and the id's questions are checked against
what the lane's solver covers (tools/lanes.py: contract) on the start response's
own question list, before any download is asked for. That check no longer holds
a clock: its problems are printed as `CONTRACT <problem>` lines with one line
that says the check ran after the start, and the run goes on to download, solve
and submit what the solver answers. With `"preread": "status"` in
challenges/_opener.json the warm-up status read comes back as it was up to the
tag armed at 19:44 that evening: the check runs on the read's questions, and a
mismatch starts no clock (`RUN result=contract_mismatch`, exit 3). A Mastery
under connect=early keeps that read under either value (see preread()).

Whatever happens, the run ends with the same summary: answers, GUESS lines,
NOTE/ERROR/CHECK lines, the mode and timing lines, where things were saved, the
result, and one machine-readable last line:

  RUN result=<word> remaining=<n|-> unsure=<n> missing=<n> infra=<true|false>

result is the judge's word (CORRECT, accepted, incorrect), another word the Game
Master answered with, or one of not_submitted, no_submit, dry_run, offline,
no_attempt, no_ticket, clock_busy, contract_mismatch, no_solver (the solver file
could not be loaded; nothing was requested), unauthorized (the Game Master
refused the token, at whatever step: tell the player). unsure counts the answers
that were withheld, missing the questions with no answer at all. infra is true
when a live run ended without a verdict for a reason that is not the solver's (a
rate limit, a failed download or submit, an expired or unstartable attempt).

Deliveries are fetched through gm.fetch_delivery: op=artifact as always, and when that route
answers a 4xx or 5xx the attempt's own link and the contract's download op, each once (the
download ladder; `NOTE download ladder: ...`). A plain answer the kind check holds is printed as
`FORMAT <id>: <reason>`; when such answers are all that is missing, `NOTE kind check only: ...`.

Every submission and what came back is appended to verdicts.jsonl, and CORRECT
freezes key.json (written once, never replaced). A live run that could not
submit leaves a result.json marker ({"result": "not_submitted", "source":
"tools/run.py"}) so the failure shows on disk; if the submit request itself
failed, op=status is read once and the server's own result is saved instead when
it has one. Only a run that submitted writes answers.json and
answers.submitted.json. Any other run writes answers.dry-run.json, and a dry run
of an attempt that has a result.json or key.json leaves its attempt.json alone.

The exit status is 3 when no clock was started for want of a ticket or because of
a contract mismatch (which ends a run only with preread=status), and otherwise
non-zero only when there was no attempt to solve, the solver could not be loaded,
or the runner itself failed; read the result from the RUN line or result.json.

Solver contract (variant-proof: derive every answer from the bytes):

  def solve_set(questions, files, ctx) -> dict      # {qid: answer}

  questions  the questions for ONE set. q["qid"] is the id without its "setN."
             prefix; q["member"] is the file named after "->" in q["artifact"].
             q["answer_id"] is the id the answer is submitted under (see below).
  files      {name: bytes}: the delivery under its filename plus every archive
             member under its own name (nested archives expanded, also
             addressable as "outer -> inner"). Encrypted members are tried
             with "infected", then the passwords in <challenges>/_passwords.json
             (tools/password.py); an archive none of them opens ends a live run
             without a verdict, "archive password needed: <file>".
  ctx        {"set": N, "delivery_name": str, "delivery": bytes, "attempt": dict,
              "partial": {}, "delivery_id": str, "delivery_state": {}}. Fill ctx["partial"] ({qid: answer}) as each part
             finishes: when the time budget stops the solver, what is in there
             is used as if it had been returned. Every set of one multi-set
             delivery shares the same delivery_state object and has "siblings":
             {set number: delivery bytes} for all of its sets (backlog row 109).

Answers that are None, missing or empty are left out of the submission. So is
an unsure answer (a value from labels.pick, which starts with "??"; see
docs/ops/contracts.md): it is printed as `GUESS <answer id>: <key> <names>`,
saved to unsure.json, never sent and not counted as answered.

One exception since backlog row 299 (2026-10-13), on a timed id only: once the
confident batch is accepted (or when the solver gave no confident answer at
all), nothing is held by the kind check, and the clock has at least 10 s left
or the attempt has no deadline, each unsure key is probed as the ladder and
tools/verify.py probe one, by tools/grade.py's probe(): the options of the key
on ONE of its ids, one per request, in order; the accepted name goes to the
labels ledger and to the key's other ids as one batch. At most 6 option probes
a run, 0.4 s apart, each in verdicts.jsonl before the next. A probe that is not
judged (a 429, a dropped connection) ends the probing. What is still unsure
afterwards is a GUESS line as before, and a NOTE says what was tried or why
nothing was. An answer of None is never probed. The gates are unchanged: the
Mastery gate of a run.py lane still refuses a failed variant that replays
unsure, because the window is not known before the start.

So is a plain answer whose kind contradicts its question's answer_format (backlog
row 106; tools/kinds.py: an integer question answered `ELF64`, JSON that does not
parse, a pattern that cannot match). It is certainly wrong and would only sink the
batch it stands in: it is printed as `FORMAT <answer id>: <reason>`, never sent,
and counted with the missing ids. tools/kinds.py's off switch (kinds.OFF=off) turns the check off.

A timed id that the Game Master plays as a regular attempt (backlog row 108: the
start or the result says run_for_time false or hall_of_fame_eligible false) gets
the line `NOTE regular attempt on a timed id: <id> (...)`, and result.json
carries the pool fields and "regular_attempt": true. It scores; it posts nothing
to the fastest-times board. tools/open_day.py turns the NOTE into a warn alert.

A solver may define covers(questions) -> list of problems. When the lane's
contract is 'hook' it is asked with the questions in the shape solve_set gets
them: on the start response's questions (preread=none), or before the clock
starts (preread=status).

The Game Master judges answer_ids[], and questions[] is aligned with it by
position. The two ids normally match. When they do not (Metadata timed
variants), the answer returned for q["qid"] is submitted under q["answer_id"],
and the file named in the question may not be the one that was delivered.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from types import SimpleNamespace

import requests

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[1]))
    from ctf import env as ctf_env
from ctf import deliveries as _deliveries   # noqa: E402  B-042: which delivery is a set's own

sys.path.insert(0, str(Path(__file__).resolve().parent))
# The attempt runner below is the Huntress platform adapter's (B-001 hm-17): it needs the Game Master
# client (tools/gm.py) and the lane policy (tools/lanes.py), which master does not carry. They are
# imported when present so `import run` (split_sets, load_offline, the re-exported expander) works
# without them; main() refuses loudly when either is missing (RUNNER_MISSING), and the timed-window
# constants below are None then rather than a guessed value. Its environment names stay the
# Huntress ones (CTF_RFT_SUPPORTED, CTF_TIMING_FILE, CTF_OWN_ATTEMPT,
# CTF_PROBE413_MARK, ...) because the Huntress opener (open_day.py) sets exactly those.
RUNNER_MISSING = []
try:
    import gm
except ImportError as _e:
    gm = None
    RUNNER_MISSING.append(f"tools/gm.py (the Game Master client): {_e}")
try:
    import lanes
except ImportError as _e:
    lanes = None
    RUNNER_MISSING.append(f"tools/lanes.py (lane policy and timed-window budget): {_e}")


# The delivery expander lives in tools/archive_expand.py (B-001 hm-17: the library half of this
# runner, importable without the platform client); every name is re-exported here so run.expand,
# run.Keys, run.pw, run.unwrap, run.SEVENZ_MAGIC and run._collision_keys keep working.
import archive_expand  # noqa: E402
from archive_expand import (  # noqa: E402,F401
    SEVENZ_MAGIC, Keys, _collision_keys, _load_passwords, _load_unwrap, _OnlyInfected, _peel_envelopes,
    expand, expand_7z, pw, pyzipper, unwrap)

judge = getattr(gm, "judge", None)   # None without the GM client: nothing is recorded, no clock starts

# The rest of the attempt runner's Huntress modules, imported inside the functions that use them (every one
# of those functions also needs gm or lanes). The merge plan archived them with the Game Master client
# (infra-tools-ctf-claude.merge.json), so main() names each one that is missing before it requests
# anything, instead of a runner that starts and then quietly skips its gate row, probes and proposer
# (B-001b). tools/import_gate.py allows these imports in this file only.
RUNNER_MODULES = {
    "grade": "tools/grade.py (bank-and-probe for batch judges)",
    "preflight": "tools/preflight.py (the clock gate and replay)",
    "proposer_gate": "tools/proposer_gate.py (the proposer gate)",
    "proposer_wire": "tools/proposer_wire.py (the proposer wiring)",
}
for _name, _what in RUNNER_MODULES.items():
    if importlib.util.find_spec(_name) is None:
        RUNNER_MISSING.append(f"{_what}: not in this tree")

# tools/switches.py (the player's switches in challenges/_opener.json) was archived by the merge plan: "Pattern:
# replaced by event profile keys" (B-001b removed the import that could never load). Until a profile key
# replaces a switch, every switch is off, which is what the runner did without the file.


def switch_on(name: str) -> bool:
    """Always False: the Huntress switch file is not read in master (see above)."""
    return False


def regular_mode() -> bool:
    """Always False: the "start": "regular" switch (backlog row 250) lived in the archived switch file."""
    return False


def preread(cid: str) -> bool:
    """True when this timed id's op=status is read before its start; False when the start is the
    run's first request (package PR1, the player's decision of 2026-10-11: the read was ten of the
    63 requests of a clean release minute, and about 0.2 s before every clock).

    The player's switch preread (tools/switches.py): none, in force without the file, sends no
    read; "preread": "status" in challenges/_opener.json gives it back at the next clock, with
    everything it did up to the tag armed at 19:44 that evening. One clock keeps its read under
    none: a Mastery with connect=early on, because preopen() counts the deliveries from that read's
    questions and warms the connection it used (the switch is defined on the read: tools/switches.py).
    A switch file that cannot be read is no file: none."""
    return switch_on("preread") or (str(cid).endswith("/mastery") and switch_on("connect"))


try:   # answer-kind conformance (backlog row 106); without the module nothing is held back
    import kinds
except Exception:
    kinds = None


def kind_check(attempt, answers: dict) -> tuple:
    """(answers that may be sent, {answer id: why it was held back}). A plain answer whose kind
    contradicts its question's answer_format (an integer question answered `ELF64`) is certainly
    wrong and would only cost the batch it stands in. Never raises; nothing is held when
    tools/kinds.py is not there."""
    if kinds is None:
        return dict(answers), {}
    try:
        return kinds.of_attempt(attempt, answers)
    except Exception:
        return dict(answers), {}


# ---- which pool a timed attempt came from (backlog row 108) --------------------------------------
#
# Day 8: a dual-pool route answers a timed id with a REGULAR attempt unless the start carried
# run_for_time:true. It scores, but it posts nothing to the fastest-times board, and nothing
# noticed (Warmups: run_for_time false, hall_of_fame_eligible false, deadline null).

POOL_FIELDS = ("run_for_time", "hall_of_fame_eligible", "variant_fresh")
HELD_ONLY = "kind check only"      # the NOTE of a batch that is complete but for answers the kind check holds (row 144)
REGULAR_NOTE = "regular attempt on a timed id"      # the NOTE tools/open_day.py reads


def pool_of(body) -> dict:
    """The pool fields a start, retry or result body carries, as they came (absent ones left out)."""
    if not isinstance(body, dict):
        return {}
    return {name: body[name] for name in POOL_FIELDS if isinstance(body.get(name), bool)}


def regular_attempt(cid: str, *bodies):
    """Why the attempt of a timed id is a regular one (not a timed Hall of Fame run), or None. Only
    an explicit false says so: a body without the fields (a legacy route) says nothing. A later
    body (the result) wins over an earlier one (the start)."""
    if not gm.is_timed(cid):
        return None
    seen = {}
    for body in bodies:
        seen.update(pool_of(body))
    said = [f"{name}={str(seen[name]).lower()}" for name in ("run_for_time", "hall_of_fame_eligible") if seen.get(name) is False]
    return ", ".join(said) or None


def regular_note(cid: str, *bodies):
    """The NOTE line (without its NOTE prefix) for a regular attempt on a timed id, or None."""
    why = regular_attempt(cid, *bodies)
    if not why:
        return None
    return (f"{REGULAR_NOTE}: {cid} ({why}); it scores, but posts nothing to the fastest-times board "
            f"(the start body lacked run_for_time:true, or the route ignores it)")


def pool_record(cid: str, result, *bodies):
    """Lay the pool fields of the start body under a result that lacks them, and mark a regular
    attempt, so result.json says which pool was played. Returns the result (a copy when changed)."""
    if not isinstance(result, dict) or not gm.is_timed(cid):
        return result
    seen = {}
    for body in bodies:
        seen.update(pool_of(body))
    add = {name: value for name, value in seen.items() if name not in result}
    if regular_attempt(cid, *bodies, result):
        add["regular_attempt"] = True
    return {**result, **add} if add else result

# The solve budget of a timed window lives in tools/lanes.py (run_budget), shared with the gate (row 99).
# None without lanes.py: main() refuses before any of these is read (no guessed budget).
SUBMIT_MARGIN = lanes.RUN_SUBMIT_MARGIN if lanes else None   # seconds of a timed window kept back for the submit round trip
MIN_SOLVE_BUDGET = lanes.RUN_MIN_BUDGET if lanes else None   # a timed solver gets at least this long ...
MIN_SOLVE_LEFT = lanes.RUN_MIN_LEFT if lanes else None       # ... but only while this much of the window remains
RESUMED_AFTER = 1.0      # server Date this far past started_at: the attempt was already running
DOWNLOAD_WORKERS = 6     # parallel downloads (the wire discipline's limit)
VERDICTS = ("accepted", "CORRECT", "incorrect")   # anything else the Game Master answers is not a verdict
# What belongs to one variant and moves to history/<attempt id>/ with it.
VARIANT_FILES = ("attempt.json", "artifact", "answers.json", "answers.submitted.json", "answers.dry-run.json",
                 "result.json", "verdicts.jsonl", "gaps.json", "key.json", "golden.json", "must_not.json",
                 "unsure.json", "ladder-log.json", "solver.stderr.txt")
BULKY = ("guidance", "questions", "artifacts", "prompt", "download", "downloads")
RATE_LIMIT_WAITS = (0.4, 0.8, 1.2)        # pauses before re-sending a request answered with 429 rate_limited
WARMUP_WAITS = (0.5, 1.0, 2.0, 2.0)       # the same, before any clock is running
PAUSE_TICKET_SPARE = 10.0                 # seconds of its ticket's life a wait for a rate-limit pause leaves over
PAUSE_PUSH_MAX = 5.0                      # seconds past the pause first seen that the same wait may go on, if it is pushed out


def wait_out_pause(cid: str, who: str = "run.py") -> float:
    """Before the warm-up status read of a timed id on a live run: while the wire governor
    (tools/judge.py) says a rate-limit pause is in force, wait for its end. Returns the seconds
    waited, 0.0 when there was no pause.

    The status read of a timed id is not held back by the governor, so without this it goes
    out into the pause: the Game Master answers 429, which pushes the pause out for every tool
    on the token, and after five such reads the run ends `rate_limited` with no clock started.
    judge.clock() would wait for the same pause before the start anyway, so the wait costs the
    run nothing; it only comes before the read instead of after it.

    The wait is bounded three times. By the pause as it stood at the first look, plus
    PAUSE_PUSH_MAX: the caller that set this run's time limit (tools/open_day.py: allowance)
    added the pause it saw when it launched the run and what judge.clock() may wait, and
    nothing else. A pause that is pushed far out while this waits is therefore not waited
    for: the read goes out as it always has, and either it is answered 429 (`rate_limited`,
    no clock) or judge.clock() sits the rest out inside the time the caller allowed for it.
    Waiting here for every push could move the start past that limit, and the caller would
    kill the run inside its window. By judge.LOCKOUT_MAX, the longest pause the governor
    sets. And by the ticket: judge.clock() needs it to be younger than TICKET_TTL when the
    read is done, so the wait leaves PAUSE_TICKET_SPARE seconds of its life over; a ticket
    with less than that left is not waited on at all. One line on stderr says what is being
    waited for, before the wait. A governor that cannot be read shows no pause."""
    if judge is None:
        return 0.0
    began, told = time.monotonic(), False
    try:
        row = judge.ticket(cid)
        age = time.time() - float(row["at"]) if row else float(judge.TICKET_TTL)
        first = float(judge.blocked_for())
        cap = min(first + PAUSE_PUSH_MAX, float(judge.LOCKOUT_MAX), float(judge.TICKET_TTL) - age - PAUSE_TICKET_SPARE)
        wait = min(first, cap)
        while wait > 0:
            if not told:
                told = True
                with contextlib.suppress(Exception):   # a stderr that cannot be written to must not cancel the wait
                    print(f"{who}: a rate-limit pause is in force for another {wait:.0f} s; waiting for its end before "
                          f"the status read of {cid}", file=sys.stderr, flush=True)
            time.sleep(wait + 0.01)
            wait = min(float(judge.blocked_for()), cap - (time.monotonic() - began))
    except Exception:   # the wait is a courtesy to the wire: it must never be why a run does not play
        pass
    return time.monotonic() - began if told else 0.0


# ---- a 429 inside an attempt with no deadline (backlog row 250, start=regular) ---------------------
#
# A regular attempt on a timed id has no deadline, so a refused request costs it nothing but time: the
# request was not processed, and the attempt is still open when the pause ends. Under start=regular the
# runners therefore do not give a refused download or submit up after 2.4 s (run.py) or 0.9 s (the
# ladder): they wait for the end of the pause the wire governor noted for that very 429 and send the
# request again. No quick re-send goes into the pause first (no request sent again inside a refused
# minute was ever answered, and under wire=minute a second 429 within 120 s doubles the pause). The
# waits of one process together take at most UNTIMED_PATIENCE seconds, so a tool never hangs: what is
# still refused then ends the run as it always did (rate_limited, infra=true), and the opener, which
# gives a timed step that much longer under this value, rejoins the open attempt afterwards.
UNTIMED_PATIENCE = 150.0                  # seconds one process waits in all for rate-limit pauses inside such an attempt
UNTIMED_PAUSE_PAD = 0.25                  # a pause is waited out to this long past its end
UNTIMED_PAUSE_BLIND = 5.0                 # the wait when the governor noted no pause for the 429 (judge.MINUTE_PAUSE_MIN)
_PATIENCE = {"left": UNTIMED_PATIENCE}
_PATIENCE_LOCK = threading.Lock()         # a Mastery's deliveries are fetched in parallel


def untimed_patient(cid, clock=None) -> bool:
    """True when a refused request of this id is to be waited out: start=regular is in force, the id is
    a timed one, and the attempt in hand has no deadline (`clock` is None or has nothing left to
    count: a regular attempt, or practice)."""
    try:
        return bool(cid) and gm.is_timed(cid) and (clock is None or clock.left() is None) and regular_mode()
    except Exception:
        return False


def wait_untimed_pause(what: str = "request", notes=None) -> float:
    """Sleep to the end of the rate-limit pause in force (the governor's own record; UNTIMED_PAUSE_BLIND
    when it has none) and return the seconds waited; 0.0 when this process has used its
    UNTIMED_PATIENCE, and then the caller gives the request up as before. Never raises."""
    try:
        pause = float(judge.blocked_for()) if judge is not None else 0.0
    except Exception:
        pause = 0.0
    want = (pause if pause > 0 else UNTIMED_PAUSE_BLIND) + UNTIMED_PAUSE_PAD
    with _PATIENCE_LOCK:
        if _PATIENCE["left"] < min(want, 1.0):
            return 0.0
        wait = min(want, _PATIENCE["left"])
        _PATIENCE["left"] -= wait
    if notes is not None:
        with contextlib.suppress(Exception):
            notes.append(f"{what} was rate limited on an attempt with no deadline; waited {wait:.1f}s for the pause to end "
                         f"and sent it again (start=regular)")
    time.sleep(wait)
    return wait


def rate_limited(resp) -> bool:
    if resp.status_code == 429:
        return True
    try:
        return (resp.headers.get("content-type", "").startswith("application/json")
                and resp.json().get("error") == "rate_limited")
    except Exception:
        return False


def patient(send, notes: list, what: str, clock=None, waits=RATE_LIMIT_WAITS, cid=None):
    """send() a request; while the answer is a rate limit (so nothing was processed), pause and send it again.
    With `cid` of a timed id whose attempt has no deadline, under start=regular (untimed_patient), the
    pause is the governor's own, waited out to its end, for UNTIMED_PATIENCE seconds in all."""
    resp = send()
    if cid is not None and untimed_patient(cid, clock):
        while rate_limited(resp) and wait_untimed_pause(what, notes):
            resp = send()
        return resp
    for wait in waits:
        if not rate_limited(resp):
            break
        left = clock.left() if clock else None
        if left is not None and left < wait + 0.3:
            break  # no time left on the attempt to wait it out
        time.sleep(wait)
        notes.append(f"{what} was rate limited; sent again after {wait}s")
        resp = send()
    return resp


def load_solver(path: str):
    p = Path(path).resolve()
    sys.path.insert(0, str(p.parent))
    spec = importlib.util.spec_from_file_location("solver_under_run", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if not hasattr(mod, "solve_set"):
        sys.exit(f"{path} does not define solve_set(questions, files, ctx)")
    return mod


def answer_ids_for(attempt: dict) -> list:
    """The id each question must be answered under, in question order.

    questions[] is aligned one-for-one with answer_ids[], and answer_ids[] is
    what the Game Master judges. The two usually match, but a question can carry
    another id (seen on Metadata timed variants, where the question text even
    names a file from a different variant), so the position decides.
    """
    qs, ids = attempt.get("questions") or [], attempt.get("answer_ids") or []
    return list(ids) if len(ids) == len(qs) else [q["id"] for q in qs]


def shaped(q: dict, aid) -> tuple:
    """(set number, the question as a solver sees it): qid is the id without its "setN." prefix,
    member the file named after "->" in the artifact text, answer_id the id it is answered under."""
    m = re.match(r"set(\d+)\.(.+)$", q["id"])
    n, qid = (int(m.group(1)), m.group(2)) if m else (0, q["id"])
    if not m and isinstance(q.get("set"), int):
        n = q["set"]
    art = q.get("artifact") or ""
    member = art.split("->")[-1].strip() if "->" in art else None
    return n, {**q, "qid": qid, "member": member, "answer_id": aid}


def _fatal_locks(keys, groups: dict) -> tuple:
    """(blocking, noted) archive names from keys.found. Blocking: a delivery no member of which
    could be read, or a locked archive that is, or holds, a member a question names (its answers
    would be guesses). Every other locked archive (a decoy zip inside the bundle, an APK entry with
    only the encryption flag set) is noted, and the solver runs on everything that was read: the
    behaviour before backlog row 75."""
    named = {Path(str(q.get("member"))).name.lower()
             for qs in groups.values() for q in qs if q.get("member")}
    blocking, noted = [], []
    for name in keys.locked:
        f = keys.found.get(name) or {"depth": 0, "members": [], "read_any": False}
        hit = Path(str(name)).name.lower() in named or any(Path(str(m)).name.lower() in named for m in f["members"])
        (blocking if hit or (f["depth"] == 0 and not f["read_any"]) else noted).append(name)
    return blocking, noted


def set_rule(n: int):
    """The name rule by which a one-bundle delivery's member serves set `n` (evidence-02.zip, blob-2.txt)."""
    return re.compile(rf"(?<!\d)0*{n}(?=\.[A-Za-z0-9]+$)")


# `siblings` itself holds references to bytes already resident in the set contexts and is always present: solver
# semantics must not change at a payload-size threshold. This limit applies only to copying that map through the
# optional multiprocessing pool. A larger delivery stays on the serial path, where the one shared map is free.
SIBLINGS_MAX = 1024 * 1024


def split_sets(attempt: dict, blobs: list, locked: list = None, notes: list = None) -> list:
    """Pair each set of questions with the delivery it is about: [(set_no, questions, files, ctx)].
    `locked`, when given, receives the name of every archive no known password opens that stops the
    run (a delivery nothing could be read from, or one holding a member a question names); `notes`,
    when given, gets one line for each other such archive, which the solver simply does without.

    Which delivery is a set's own is ctf.deliveries.choose (B-042, docs/CONTRACTS.md section 53). A set
    with no proven delivery gets no files, delivery b"", ctx["delivery_unmapped"] (the reason) and one
    line in `notes` (on stderr when no list is given); solve_all does not hand it to the solver."""
    keys = Keys(attempt)
    names = [a.get("filename") or f"delivery-{i}" for i, a in enumerate(attempt.get("artifacts") or [])]
    groups = {}
    for q, aid in zip(attempt.get("questions") or [], answer_ids_for(attempt)):
        n, question = shaped(q, aid)
        groups.setdefault(n, []).append(question)
    order = sorted(groups)
    out = []
    top = None    # a one-bundle Mastery's bundle, expanded once for all its sets (backlog row 25)
    picked = {}   # that bundle's Choice per set
    for n in order:
        qs, files = groups[n], {}
        # B-042: which delivery is the set's own is ctf.deliveries.choose's one rule (the questions' own
        # `delivery K:`, one delivery per set in set order, a bundle's numbered member). A set it cannot
        # prove a delivery for gets none: it used to read the nearest one (the last delivery, or the whole
        # bundle), which answers a set from a neighbour's file under the same member names.
        if len(blobs) == 1 and len(order) > 1:
            # One bundle holding a numbered member per set (blob-01.txt, evidence-02.zip).
            if top is None:
                # Every set used to expand the whole bundle again: same bytes, same Keys, so the
                # same result each time. Done once it saves about 0.12 s per extra set on Script.
                # Row 225: the bundle is read one level deep for the members that serve a set (each
                # is expanded below, once, as its set's delivery; walking into it here as well
                # decrypted every AES member twice). A member no set takes is walked into as before,
                # so every archive the bundle holds still meets the same Keys.
                top = {}
                rules = [set_rule(k) for k in order]
                serves = (lambda m: " -> " not in m and any(r.search(f"{names[0]} -> {m}") for r in rules))
                expand(names[0], blobs[0], top, keys=keys, _skip=serves)
                members = [k.split(" -> ", 1)[1] for k in top
                           if k.startswith(names[0] + " -> ") and " -> " not in k.split(" -> ", 1)[1]]
                picked = {k: _deliveries.choose(k, groups[k], order, 1, members) for k in order}
                chosen = {c.member for c in picked.values() if c.member is not None}
                for k in [k for k in top if k.startswith(names[0] + " -> ")]:
                    m = k.split(" -> ", 1)[1]
                    if " -> " not in m and serves(m) and m not in chosen:
                        expand(m, top[k], top, 1, keys, _rows=[], _chain=(names[0], m))
            choice = picked[n]
        else:
            choice = _deliveries.choose(n, qs, order, len(blobs))
        ctx = {"set": n, "attempt": attempt}
        if choice.rule == _deliveries.ALL:
            # One set: it sees every delivery.
            for name, data in zip(names, blobs):
                expand(name, data, files, keys=keys)
            dname, dbytes = (names[0], blobs[0]) if blobs else (None, b"")
        elif choice.member is not None:
            dname, dbytes = choice.member, top[f"{names[0]} -> {choice.member}"]
            expand(dname, dbytes, files, keys=keys)
        elif choice.index is not None:
            dname, dbytes = names[choice.index], blobs[choice.index]
            expand(dname, dbytes, files, keys=keys)
        else:
            dname, dbytes = None, b""
            ctx["delivery_unmapped"] = choice.reason
            line = (f"set {n}: no delivery is proven to be its own ({choice.reason}); it gets no files and "
                    f"its {len(qs)} question(s) are left unanswered")
            if notes is not None:
                notes.append(line)
            else:
                print(f"NOTE {line}", file=sys.stderr)
        ctx.update(delivery_name=dname, delivery=dbytes)
        out.append((n, qs, files, ctx))
    # Backlog row 109: the sets of a multi-set attempt also see each other's deliveries, as
    # ctx["siblings"] = {set number: bytes}, one dict shared by all of them. A solver may read it to decide
    # what one set cannot (a letter cipher's key over a slug-only record). The state object and identity are also
    # shared, so solvers can cache one delivery-wide result rather than repeat it in every set. These are references,
    # not copies. Every caller goes through here, so a replay sees the same context as the live run.
    if len(out) > 1:
        total = sum(len(c["delivery"] or b"") for _, _, _, c in out)
        state = {}
        identity = str(attempt.get("attempt_id") or attempt.get("id") or "")
        if not identity:
            identity = hashlib.sha256("\n".join(
                f"{n}:{c.get('delivery_name')}:{len(c.get('delivery') or b'')}" for n, _, _, c in out
            ).encode()).hexdigest()
        for _, _, _, c in out:
            c["delivery_id"] = identity
            c["delivery_state"] = state
            c["siblings_total_bytes"] = total
            c["siblings_limit_bytes"] = SIBLINGS_MAX
        siblings = {n: c["delivery"] for n, _, _, c in out if c["delivery"]}
        for _, _, _, c in out:
            c["siblings"] = siblings
    blocking, noted = _fatal_locks(keys, groups)
    if locked is not None:
        locked.extend(blocking)
    if notes is not None:
        for name in noted:
            f = keys.found.get(name) or {}
            what = ", ".join(Path(str(m)).name for m in (f.get("members") or [])[:3]) or "its members"
            notes.append(f"no known archive password opens {Path(str(name)).name} ({what}); no question names it, "
                         f"so the solver runs on the rest (tools/password.py add '<value>' if it matters)")
    return out


def normalize(attempt: dict) -> dict:
    """Give every attempt an artifacts[] list.

    An active base or Time Trial attempt reports its one delivery as top-level
    `download` and `sha256`; only Mastery and already-solved attempts carry
    artifacts[]. The filename is filled in from the download's headers.
    """
    if not attempt.get("artifacts") and attempt.get("questions") and (attempt.get("sha256") or attempt.get("download")):
        attempt["artifacts"] = [{"filename": None, "sha256": attempt.get("sha256"), "download": attempt.get("download")}]
    return attempt


def time_limit(clock, slack: float):
    """Timeout for one request: 30 s, or on a timed attempt what the clock has left plus `slack`
    (at least half a second, so a request is never sent with no time to be answered)."""
    left = clock.left() if clock else None
    return 30 if left is None else max(0.5, min(30.0, left + slack))


DOWNLOAD_NOTES = []      # what gm.fetch_delivery's download ladder said in this process (drained into the run's NOTE lines)


def download_notes() -> list:
    """The download ladder's lines so far, each once."""
    out = []
    while DOWNLOAD_NOTES:
        line = DOWNLOAD_NOTES.pop(0)
        if line not in out:
            out.append(line)
    return out


_TIMING_ENV = "CTF_TIMING_FILE"   # row 293: tools/open_day.py names its _open/timing.jsonl for the tools it starts


def timing_row(event, at=None, **row):
    """Backlog row 544, step 1: one measurement row in the opener's _open/timing.jsonl (`delivery_in`: a
    Mastery delivery's bytes have arrived and passed their sha256 check), only when tools/open_day.py
    started this run and named the file in CTF_TIMING_FILE. A run by hand writes nothing. Nothing here
    can raise, and a row that cannot be written is not written (verify.py.timing_row's contract). It is
    called from the download threads, so each row is one atomic append."""
    try:
        path = ctf_env.get(_TIMING_ENV)
        if not path or Path(path).name != "timing.jsonl" or not Path(path).parent.is_dir():
            return
        now = time.time() if at is None else float(at)
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now)) + time.strftime("%z", time.localtime(now))
        line = json.dumps({"at": round(now, 3), "time": stamp[:-2] + ":" + stamp[-2:], "event": event,
                           "tool": "run.py", **row}, ensure_ascii=False, default=str)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _fetch_one(s, cid: str, arts: list, i: int, clock=None) -> bytes:
    last, tries, waits = "no response", 0, iter(RATE_LIMIT_WAITS)
    want = arts[i].get("sha256")
    checked = []         # (response, is it the delivery): the sha256 of a large delivery is taken once

    def is_delivery(r) -> bool:
        for seen, verdict in checked:
            if seen is r:
                return verdict
        is_json = r.headers.get("content-type", "").startswith("application/json")
        verdict = r.status_code == 200 and (hashlib.sha256(r.content).hexdigest() == want if want else not is_json)
        checked.append((r, verdict))
        return verdict

    fetch = getattr(gm, "fetch_delivery", None)
    while tries < 2:
        try:
            if fetch is None:     # an older gm.py beside this file
                r = s.get(gm.GM, params={"op": "artifact", "challenge": cid, "delivery": i}, timeout=time_limit(clock, -1.0))
            else:
                # op=artifact as always; when that route answers a 4xx or 5xx, the attempt's own link and the
                # contract's download op, each once (gm.py: the download ladder), all inside the clock's time.
                r = fetch(s, cid, i, {"artifacts": arts}, timeout=lambda: time_limit(clock, -1.0), ok=is_delivery,
                          notes=DOWNLOAD_NOTES)
        except Exception as e:  # a dropped connection gets the second try
            last, tries = f"{type(e).__name__}: {e}", tries + 1
            continue
        if rate_limited(r):  # not a real try: pause and ask again
            if untimed_patient(cid, clock):      # row 250: no deadline, so the pause is waited out
                last = "http 429 rate_limited"
                if wait_untimed_pause(f"delivery {i}", DOWNLOAD_NOTES):
                    continue
                break
            last, wait = "http 429 rate_limited", next(waits, None)
            if wait is None:
                break
            time.sleep(wait)
            continue
        tries += 1
        if is_delivery(r):
            if not arts[i].get("filename"):
                m = re.search(r'filename="?([^";]+)"?', r.headers.get("content-disposition", ""))
                arts[i]["filename"] = Path(m.group(1)).name if m else f"delivery-{i + 1:02d}.bin"
            timing_row("delivery_in", id=cid, delivery=i, bytes=len(r.content))   # row 544 step 1: the arrival
            return r.content
        last = f"http {r.status_code}, sha256 mismatch or error: {r.content[:120]!r}"
    raise RuntimeError(f"delivery {i}: {last}")


PREOPEN_WAIT = 0.5       # connect=early: seconds the extra connections may take, all together (a TLS
                         # handshake takes about 0.1 s; this is the most the switch can hold a start back)


def deliveries_named(body) -> int:
    """How many deliveries a question contract names ('delivery 3: name.apk -> member'); 0 for none."""
    named = set()
    for q in (body.get("questions") if isinstance(body, dict) else None) or []:
        m = re.match(r"\s*delivery (\d+)\b", str(q.get("artifact") or "")) if isinstance(q, dict) else None
        if m:
            named.add(int(m.group(1)))
    return len(named)


def preopen(s, cid: str, body, notes: list) -> int:
    """connect=early (backlog row 27): before a multi-delivery Mastery is started, open the extra
    keep-alive connections its parallel downloads will need, so that no download pays a TLS
    handshake inside the window. Called after the live status read (the last 429 check before a
    clock, which stays) and before the start. Only connections are opened: no request is sent, so
    the rate limit is not touched. It uses urllib3's private pool API (_new_conn, _put_conn) on the
    pool the status read used; when that pool cannot be found, holds no connection yet, or anything
    fails, nothing is opened and the run goes on as before. Returns the number opened."""
    if not (str(cid).endswith("/mastery") and switch_on("connect")):
        return 0
    extra = min(deliveries_named(body), DOWNLOAD_WORKERS) - 1
    if extra <= 0:
        return 0
    t0 = time.perf_counter()
    try:
        req = requests.Request("GET", gm.GM).prepare()
        env = s.merge_environment_settings(req.url, {}, None, None, None)
        adapter = s.get_adapter(req.url)
        if hasattr(adapter, "get_connection_with_tls_context"):
            pool = adapter.get_connection_with_tls_context(req, env.get("verify"), env.get("proxies"), env.get("cert"))
        else:
            pool = adapter.get_connection(req.url, env.get("proxies"))
        if not getattr(pool, "num_connections", 0):
            notes.append("connect=early: the status read's connection pool was not found; nothing was pre-opened")
            return 0

        lock, opened, late = threading.Lock(), [], []

        def one():
            # A daemon thread each: one that hangs is left behind, never waited for at exit. A
            # connection that comes after PREOPEN_WAIT is closed, not given to the pool.
            try:
                conn = pool._new_conn()
                conn.timeout = PREOPEN_WAIT
                conn.connect()
            except Exception:
                return
            with lock:
                kept = not late
                if kept:
                    opened.append(conn)
            if not kept:
                with contextlib.suppress(Exception):
                    conn.close()
        threads = [threading.Thread(target=one, daemon=True, name="preopen") for _ in range(extra)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(max(0.0, PREOPEN_WAIT - (time.perf_counter() - t0)))
        with lock:
            late.append(None)          # from here on a connection is late
            ready = list(opened)
        # The pool's queue starts full of None placeholders (one per slot), so _put_conn alone would
        # find it full and close what it was given. Each new connection takes a placeholder's slot;
        # the connections go on top (the queue is LIFO), so the downloads take them first.
        # urllib3 sets each request's own timeouts when it takes a connection.
        held = []
        with contextlib.suppress(Exception):
            while True:
                held.append(pool.pool.get_nowait())
        spare = sum(1 for c in held if c is None)
        fits, extra_conns = ready[:spare], ready[spare:]
        for conn in extra_conns:
            with contextlib.suppress(Exception):
                conn.close()
        dropped = len(fits)
        for c in held:
            if c is None and dropped:
                dropped -= 1
                continue
            if c is None:
                pool.pool.put_nowait(None)
        for c in held:
            if c is not None:
                pool.pool.put_nowait(c)
        for conn in fits:
            pool.pool.put_nowait(conn)
        opened = fits
        notes.append(f"connect=early: {len(opened)} of {extra} extra connection(s) opened before the start "
                     f"in {time.perf_counter() - t0:.2f}s")
        return len(opened)
    except Exception as e:
        notes.append(f"connect=early: nothing was pre-opened ({type(e).__name__}: {str(e)[:120]})")
        return 0


def fetch_all(s, cid: str, arts: list, clock=None) -> list:
    """Download every delivery in parallel; raises if any of them fails."""
    if not arts:
        return []
    with ThreadPoolExecutor(max_workers=min(DOWNLOAD_WORKERS, len(arts))) as ex:
        return list(ex.map(lambda i: _fetch_one(s, cid, arts, i, clock), range(len(arts))))


def fetch_each(s, cid: str, arts: list, clock=None, on_ready=None):
    """Like fetch_all, but a failed delivery becomes None plus an error line, so the rest still get solved.

    Backlog row 544, step 2: when `on_ready` is given, it is called `on_ready(i, blob)` from the download
    thread the moment delivery i's bytes have arrived and passed their sha256 check, so a caller can start
    solving that delivery while the rest download. A failed delivery never calls on_ready (its None plus
    error line stand), so the failure semantics are unchanged, and the return value is the same (every
    blob in order, the error lines)."""
    def one(i):
        try:
            blob = _fetch_one(s, cid, arts, i, clock)
            if on_ready is not None:
                try:
                    on_ready(i, blob)
                except Exception:   # noqa: BLE001 - the hand-off never undoes the download; that delivery falls to serial
                    pass
            return blob, None
        except Exception as e:
            return None, f"download failed, {e}"
    if not arts:
        return [], []
    with ThreadPoolExecutor(max_workers=min(DOWNLOAD_WORKERS, len(arts))) as ex:
        pairs = list(ex.map(one, range(len(arts))))
    return [b for b, _ in pairs], [e for _, e in pairs if e]


# ---- solve-on-download for independent run.py sets (Day 31, backlog row 598) --------------------

STREAM_SOLVE_LANES = frozenset(("mobile-android", "metadata-forensics"))


def stream_solve_eligible(cid, attempt, st, solver=None, solve_cap=None) -> bool:
    """Whether this attempt can solve each delivery before the download barrier.

    Mobile and Metadata never consult ``ctx['siblings']``; Warmups does, so it deliberately stays on the barrier
    path.  A real deadline keeps the main-thread watchdog path too.  Single-set and one-bundle attempts gain nothing
    and retain the exact old path.
    """
    try:
        lane = lanes.canonical(lanes.lane_of(cid)) or lanes.lane_of(cid)
    except Exception:
        return False
    arts = attempt.get("artifacts") or []
    groups = {shaped(q, aid)[0] for q, aid in zip(attempt.get("questions") or [], answer_ids_for(attempt))}
    deadline = bool(getattr(st, "clock", None) and st.clock.window is not None)
    try:
        bounded = float(solve_cap) > 0 and float(solve_cap) < float("inf")
    except (TypeError, ValueError, OverflowError):
        bounded = False
    return lane in STREAM_SOLVE_LANES and bool(getattr(solver, "INDEPENDENT_DELIVERIES", False)) \
        and len(arts) > 1 and len(groups) > 1 and not deadline \
        and bool(getattr(st, "timed", False)) and bounded \
        and getattr(st, "pool", None) is None


class StreamSolve:
    """One solver thread fed by sha256-checked deliveries while the other downloads continue.

    Download workers only enqueue bytes.  This thread alone calls the solver, preserving module-global ordering.
    The main thread joins it at the download barrier, builds the authoritative full set contexts, and serially
    falls back for any set the early path did not finish.  No submission can leave before that barrier.
    """
    STOP = object()

    def __init__(self, solver, attempt, count, solve_cap):
        self.solver, self.attempt, self.count = solver, attempt, count
        self.solve_cap = max(0.01, float(solve_cap))
        self.q = queue.Queue()
        self.answers, self.done, self.sets = {}, set(), {}
        self.expected = len({shaped(q, aid)[0]
                             for q, aid in zip(attempt.get("questions") or [], answer_ids_for(attempt))})
        self.fallback = []
        self.expand_s = self.solve_s = 0.0
        self.aborted = None
        self._active_since = None
        self._state_lock = threading.Lock()
        self._stop_sent = False
        self.started_ns = time.time_ns()
        self.thread_ids = set()       # test/diagnostic fact: exactly one thread may call solve_set
        self.thread = threading.Thread(target=self._work, name="run-stream-solver", daemon=True)
        self.thread.start()

    def ready(self, i, blob):
        self.q.put((i, blob))

    def _work(self):
        while True:
            item = self.q.get()
            if item is self.STOP:
                return
            with self._state_lock:
                if self.aborted:
                    return
            i, blob = item
            partial = [b""] * self.count
            partial[i] = blob
            locked, split_notes = [], []
            t0 = time.perf_counter()
            try:
                sets = [row for row in split_sets(self.attempt, partial, locked, split_notes)
                        if row[3].get("delivery")]
            except BaseException as e:  # a main-thread BaseException would stop the run, never fall back
                if not isinstance(e, Exception):
                    with self._state_lock:
                        self.aborted = (self.aborted or
                                        f"solve-on-download worker stopped in split ({type(e).__name__})")
                    return
                # The authoritative barrier path will try an ordinary split failure normally.
                self.fallback.append(f"delivery {i + 1}: split raised {type(e).__name__}: {str(e)[:120]}")
                continue
            self.expand_s += time.perf_counter() - t0
            if locked or split_notes or not sets:
                why = "locked archive" if locked else split_notes[0] if split_notes else "no independent set"
                self.fallback.append(f"delivery {i + 1}: {why}")
                continue
            errors, finished = [], []
            self.thread_ids.add(threading.get_ident())
            t1 = time.perf_counter()
            with self._state_lock:
                if self.aborted or self.solve_s >= self.solve_cap:
                    self.aborted = self.aborted or (
                        f"solve-on-download exceeded its {self.solve_cap:.2f}s aggregate solve cap")
                    return
                self._active_since = t1
            try:
                got, cut = solve_all(self.solver, sets, None, errors, finished)
            except BaseException as e:
                with self._state_lock:
                    self.solve_s += time.perf_counter() - t1
                    self._active_since = None
                    self.aborted = (self.aborted or
                                    f"solve-on-download worker stopped in solver ({type(e).__name__})")
                return
            with self._state_lock:
                self.solve_s += time.perf_counter() - t1
                self._active_since = None
                if self.aborted or self.solve_s > self.solve_cap:
                    self.aborted = self.aborted or (
                        f"solve-on-download exceeded its {self.solve_cap:.2f}s aggregate solve cap")
                    return
            if cut or errors:
                why = errors[0].splitlines()[0] if errors else "solver was cut"
                self.fallback.append(f"delivery {i + 1}: {why}")
                continue
            with self._state_lock:
                if self.aborted:
                    return
                self.answers.update(got)
                self.done.update(finished)
                for row in sets:
                    if row[0] in finished:
                        self.sets[row[0]] = row

    def close(self, wait_cap=None):
        """Finish the worker within its aggregate cap; return False on a fail-stop abort.

        Python cannot safely kill a thread.  On expiry the daemon is therefore abandoned and the caller must end
        the attempt without a serial fallback or submission.  The worker checks ``aborted`` before publishing any
        late answer, and the process exit discards it.
        """
        if not self._stop_sent:
            self._stop_sent = True
            self.q.put(self.STOP)
        cap = self.solve_cap if wait_cap is None else max(0.0, float(wait_cap))
        wait_end = time.perf_counter() + cap
        while self.thread.is_alive():
            now = time.perf_counter()
            with self._state_lock:
                active = self._active_since
                spent = self.solve_s + (max(0.0, now - active) if active is not None else 0.0)
                abort = self.aborted
            left = min(wait_end - now, self.solve_cap - spent)
            if abort or left <= 0:
                with self._state_lock:
                    self.aborted = self.aborted or (
                        f"solve-on-download exceeded its {self.solve_cap:.2f}s aggregate solve cap")
                return False
            self.thread.join(min(0.05, left))
        with self._state_lock:
            return self.aborted is None

    def complete_sets(self):
        """The already-expanded authoritative set list when every independent set finished cleanly."""
        if self.aborted:
            return None
        return [self.sets[n] for n in sorted(self.sets)] if not self.fallback and len(self.sets) == self.expected else None

    def finish(self, sets, budget, errors, notes):
        """Merge early answers and solve every unfinished set through the unchanged serial fallback."""
        if self.aborted:
            raise RuntimeError(self.aborted)
        answers, done = dict(self.answers), list(self.done)
        remaining = [row for row in sets if row[0] not in self.done]
        t0 = time.perf_counter()
        tail_budget = None if budget is None else max(0.0, budget - self.solve_s)
        if remaining and tail_budget is not None and tail_budget <= 0:
            errors.append(f"solver stopped after its {budget:.2f}s time budget with {len(answers)} answer(s) ready")
            more, cut = {}, True
        else:
            more, cut = solve_all(self.solver, remaining, tail_budget, errors, done) if remaining else ({}, False)
        tail_s = time.perf_counter() - t0
        answers.update(more)
        if self.fallback:
            notes.append("solve-on-download: " + "; ".join(self.fallback[:4]) + "; serial fallback used")
        notes.append(f"solve-on-download: {len(self.done)} of {len(sets)} set(s) finished before the barrier "
                     f"on one solver thread; post-barrier fallback {len(remaining)} set(s)")
        return answers, cut, done, self.expand_s, self.solve_s + tail_s


def _ts(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def seconds_left(attempt: dict):
    """Seconds to the deadline by the local wall clock (the runner itself uses Clock, which does not trust it)."""
    try:
        return (_ts(attempt["deadline"]) - datetime.now(timezone.utc)).total_seconds()
    except Exception:
        return None


class Clock:
    """Seconds left on a timed attempt, measured without trusting the local wall clock.

    The window is deadline - started_at, both server times. For an attempt this
    request started, it began no earlier than the moment the request left. For
    an attempt that was already running (start resumes it), the server's Date
    header says how far in it is; that header is whole seconds, so one second is
    given away. ``known_resumed`` is reserved for an attempt whose exact id an
    earlier start of ours recorded.  It bypasses only the one-second resume
    heuristic; remaining time still comes from Date and gives that second away.
    """

    def __init__(self, attempt: dict, resp, t_sent: float, t_resp: float, known_resumed: bool = False):
        self.base = self.window = None
        self.resumed = False
        try:
            started, deadline = _ts(attempt["started_at"]), _ts(attempt["deadline"])
        except Exception as e:
            if known_resumed:
                # An exact earlier start says this is a running timed attempt.  Missing/malformed bounds must not
                # turn it into an untimed attempt with unlimited solve/submission time.
                raise RuntimeError("known resumed attempt has no readable started_at/deadline; refusing to estimate "
                                   "its clock") from e
            return  # untimed
        self.window = (deadline - started).total_seconds()
        self.base, self.t = self.window, t_sent
        try:
            server_now = parsedate_to_datetime(resp.headers["Date"])
            if known_resumed or (server_now - started).total_seconds() >= RESUMED_AFTER:
                self.resumed = True
                self.base, self.t = (deadline - server_now).total_seconds() - 1.0, t_resp
        except Exception as e:
            if known_resumed:
                # Its age is established, but without the server's clock there is no safe remaining-time estimate.
                # Raising ends the runner before a delivery or answer request; treating it as fresh would grant the
                # full window to an already-running attempt.
                raise RuntimeError("known resumed attempt has no readable server Date; refusing to estimate its clock") from e

    def left(self):
        return None if self.base is None else self.base - (time.perf_counter() - self.t)


OWN_ATTEMPT = "CTF_OWN_ATTEMPT"     # tools/open_day.py: the row 413 probe's timed attempt, which is ours
OWN_REJOIN_LINE = "start rejoined our own attempt (row 413 probe)"


def known_own_rejoin(attempt, env=None) -> bool:
    """True only when the response is the exact timed attempt our row-413 probe started.

    The Date header has one-second precision.  A real rejoin can therefore look
    0.999 s old and miss Clock's ordinary RESUMED_AFTER test.  The opener passes
    this id from its recorded probe response; an absent or different id keeps the
    ordinary teammate/fresh-start classifier byte-for-byte.
    """
    env = os.environ if env is None else env
    own = str(env.get(OWN_ATTEMPT) or "").strip()
    aid = (attempt or {}).get("attempt_id") if isinstance(attempt, dict) else None
    return bool(own and isinstance(aid, str) and aid == own)


def resumed_note(attempt, left, env=None) -> str:
    """The NOTE (without its 'NOTE ' prefix) for a start that resumed an attempt already running.

    The Day 21 final prep: when the opener's row 413 probe was dealt a TIMED Mastery attempt, the Mastery runner's
    plain start rejoins it 1 to 2 s later, which the Clock reads as resumed. The opener then names that attempt in
    CTF_OWN_ATTEMPT, and a resumed attempt with that very id says OWN_REJOIN_LINE, which matches no teammate
    sign of tools/open_day.py or tools/preflight.py. Every other resume says the old line, word for word."""
    aid = (attempt or {}).get("attempt_id") if isinstance(attempt, dict) else None
    if known_own_rejoin(attempt, env):
        return f"{OWN_REJOIN_LINE}: attempt {aid[:8]}, {left:+.2f}s to its deadline"
    return f"start resumed an attempt that was already running ({left:+.2f}s to its deadline)"


class SolverTimeout(BaseException):
    """The solver's time budget ran out. A BaseException, so a solver's own `except Exception` cannot swallow it."""


class Watchdog:
    """Raise SolverTimeout in the main thread once `seconds` have passed (no-op when seconds is None)."""

    def __init__(self, seconds):
        self.seconds, self.armed, self.installed = seconds, False, False

    def _fire(self, signum, frame):
        if self.armed:
            raise SolverTimeout()

    def __enter__(self):
        if (self.seconds is not None and hasattr(signal, "setitimer")
                and threading.current_thread() is threading.main_thread()):
            self.previous = signal.signal(signal.SIGALRM, self._fire)
            self.armed = self.installed = True
            # Repeats, so a solver that swallows the first one with a bare `except:` is interrupted again.
            signal.setitimer(signal.ITIMER_REAL, max(self.seconds, 0.01), 0.25)
        return self

    def __exit__(self, *exc):
        self.armed = False
        if self.installed:
            signal.setitimer(signal.ITIMER_REAL, 0)
            # Not back to the default action: a stray late alarm would then kill the process.
            signal.signal(signal.SIGALRM, self.previous if callable(self.previous) else signal.SIG_IGN)
        return False


def solve_all(solver, sets: list, budget, errors: list, done: list = None):
    """Run the solver over every set. Returns (answers keyed by answer id, timed_out).
    `done`, when given, receives the number of every set the solver returned from (row 256: the sets
    a second pass need not solve again).

    Each set gets a fresh ctx["partial"] = {}. A solver fills it ({qid: answer}) as its parts
    finish, and when the time budget stops it in the middle of a set, what that set has in
    there is taken as if it had been returned. An unsure answer comes back as it is, also from
    partial: telling it from a plain one is the caller's job (split_unsure)."""
    answers, timed_out = {}, False
    flying = None   # (questions, ctx) of the set being solved
    dog = Watchdog(budget)

    def take(qs, got, fill_only=False):
        for q in qs:
            v = got.get(q["qid"])
            if isinstance(v, str) and not v.strip():
                v = None   # an empty answer is no answer: sent, it could only cost the batch
            if v is not None and not (fill_only and q["answer_id"] in answers):
                answers[q["answer_id"]] = v if isinstance(v, str) else json.dumps(v, separators=(",", ":"))

    try:
        with dog:
            for n, qs, files, ctx in sets:
                if not ctx["delivery"]:
                    errors.append(_deliveries.unsolved_line(n, ctx))     # B-042: names split_sets' reason
                    continue
                ctx["partial"] = {}
                flying = (qs, ctx)
                try:
                    take(qs, solver.solve_set(qs, files, ctx) or {})
                    if done is not None:
                        done.append(n)
                except SystemExit as e:
                    errors.append(f"set {n}: solver called sys.exit({e.code!r})")
                except Exception:
                    errors.append(f"set {n}: solver raised\n{traceback.format_exc()}")
                flying = None
    except SolverTimeout:
        dog.armed = False
        timed_out = True
        if flying is not None:
            qs, ctx = flying
            try:
                take(qs, ctx["partial"] if isinstance(ctx.get("partial"), dict) else {}, fill_only=True)
            except Exception:   # a partial that is no {qid: answer} mapping gives nothing
                errors.append(f"set {ctx.get('set')}: its partial answers could not be read\n{traceback.format_exc()}")
        errors.append(f"solver stopped after its {budget:.2f}s time budget with {len(answers)} answer(s) ready")
    return answers, timed_out


# ---- warmups=pool (backlog row 28): the sets of a Warmups Mastery in forked workers -------------

POOL_WORKERS = 4          # forked workers; the Mac has 10 performance cores
POOL_WAIT = 1.5           # seconds the pool may take for all of its sets, at most half the solve budget
POOL_POLL = 0.005         # seconds between looks at the pool's results and workers
_POOL_SOLVER = None       # the solver the workers inherit through fork


def _pool_task(qs, files, ctx):
    """One set in a worker: ('ok', answers) or ('error', text). Never raises."""
    ctx = dict(ctx)
    ctx["partial"] = {}
    try:
        return "ok", dict(_POOL_SOLVER.solve_set(qs, files, ctx) or {})
    except SystemExit as e:
        return "error", f"solver called sys.exit({e.code!r})"
    except BaseException:
        return "error", "solver raised\n" + traceback.format_exc()


class SolvePool:
    """Workers forked at the top of main(), before any request, thread or TLS session exists (on
    macOS a process forked after those can crash in the child). solve() hands them the sets and
    takes back what they answer; anything that goes wrong (a worker that dies, a pool that does
    not answer within POOL_WAIT, an answer that cannot be read) only sends those sets to the serial
    path, solve_all(), with what is left of the budget. The submit never depends on the pool."""

    def __init__(self, solver, workers=POOL_WORKERS):
        global _POOL_SOLVER
        import multiprocessing
        _POOL_SOLVER = solver
        self.pool = multiprocessing.get_context("fork").Pool(processes=workers)
        self.pids = sorted(p.pid for p in self.pool._pool)

    @classmethod
    def maybe(cls, cid: str, solver, notes: list):
        """A pool for a Warmups Mastery when the switch warmups=pool is on; else None."""
        if not (str(cid).endswith("/mastery") and lanes.canonical(lanes.lane_of(cid)) == "warmups" and switch_on("warmups")):
            return None
        if threading.active_count() > 1:
            notes.append("warmups=pool: a thread was already running, so no worker was forked; "
                         "the sets are solved one by one")
            return None
        try:
            return cls(solver)
        except Exception as e:
            notes.append(f"warmups=pool: the workers could not be forked ({type(e).__name__}: {e}); "
                         "the sets are solved one by one")
            return None

    def healthy(self) -> bool:
        try:
            procs = list(self.pool._pool)
            return sorted(p.pid for p in procs) == self.pids and all(p.exitcode is None for p in procs)
        except Exception:
            return False

    def solve(self, solver, sets: list, budget, errors: list, notes: list):
        """(answers keyed by answer id, timed_out), as solve_all returns them."""
        # A siblings map contains only references in the parent, but multiprocessing would pickle the complete
        # delivery once per task. More importantly, omitting it would change what a consensus-dependent solver can
        # prove. Keep the full information and use the ordinary serial path instead; the pool is only an optional
        # speed optimization and may never change answers.
        sibling_bytes = max((int(ctx.get("siblings_total_bytes") or 0) for _, _, _, ctx in sets), default=0)
        if sibling_bytes > SIBLINGS_MAX:
            notes.append(f"warmups=pool: {sibling_bytes} sibling bytes exceed the {SIBLINGS_MAX}-byte worker "
                         "serialization limit; all sets are solved one by one with complete sibling context")
            self.close()
            return solve_all(solver, sets, budget, errors)
        t0 = time.perf_counter()
        answers, rest, pending = {}, [], []
        for item in sets:
            n, qs, files, ctx = item
            if not ctx["delivery"]:
                rest.append(item)          # solve_all says why it is not solved
                continue
            try:
                job_ctx = {k: v for k, v in ctx.items() if k != "partial"}
                pending.append((item, self.pool.apply_async(_pool_task, (qs, files, job_ctx))))
            except Exception:
                rest.append(item)
        wait = POOL_WAIT if budget is None else min(POOL_WAIT, budget / 2.0)
        broken = None
        while pending and broken is None:
            if all(r.ready() for _, r in pending):
                break
            if not self.healthy():
                broken = "a worker died"
            elif time.perf_counter() - t0 > wait:
                broken = f"the workers took more than {wait:.2f}s"
            else:
                time.sleep(POOL_POLL)
        for item, r in pending:
            n, qs, files, ctx = item
            got = None
            if r.ready():
                try:
                    got = r.get(0)
                except Exception:
                    got = None
            if isinstance(got, tuple) and len(got) == 2 and got[0] == "error":
                errors.append(f"set {n}: {got[1]}")       # what the serial path would say of it
                continue
            if not (isinstance(got, tuple) and len(got) == 2 and got[0] == "ok" and isinstance(got[1], dict)):
                rest.append(item)
                continue
            for q in qs:
                v = got[1].get(q["qid"])
                if isinstance(v, str) and not v.strip():
                    v = None   # an empty answer is no answer (as in solve_all)
                if v is not None:
                    answers[q["answer_id"]] = v if isinstance(v, str) else json.dumps(v, separators=(",", ":"))
        timed_out = False
        if broken:
            notes.append(f"warmups=pool: {broken}; {len(rest)} set(s) solved one by one instead")
            self.close()
        done = len(sets) - len(rest)
        if rest:
            left = None if budget is None else max(0.05, budget - (time.perf_counter() - t0))
            more, timed_out = solve_all(solver, sorted(rest, key=lambda x: x[0]), left, errors)
            answers.update(more)
        notes.append(f"warmups=pool: {done} of {len(sets)} set(s) solved by the pool; "
                     f"{time.perf_counter() - t0:.3f}s in all")
        return answers, timed_out

    def close(self):
        with contextlib.suppress(Exception):
            self.pool.terminate()


def split_unsure(answers: dict) -> tuple:
    """(plain, unsure): the answers that may be sent, and the ones the solver is unsure of.
    gm.is_unsure decides, so a "??" value inside a serialized list or object counts as well."""
    plain, unsure = {}, {}
    for aid, value in answers.items():
        (unsure if gm.is_unsure(value) else plain)[aid] = value
    return plain, unsure


def guess_line(aid: str, value) -> str:
    """`GUESS <answer id>: <key> <names>` for an unsure answer: its labels key and the names it
    offers, best first. A value that names no key reads `? -`: there is nothing to probe.

    The value is read back with the labels module the solver itself loaded, when it loaded one.
    This file imports none: which copy of solvers/common a solver uses is the solver's choice,
    and an import here would make it for every solver that comes after."""
    key, names = "", []
    text = value.lstrip() if isinstance(value, str) else ""
    labels = sys.modules.get("labels")
    try:
        if callable(getattr(labels, "parse", None)):
            parsed = labels.parse(text)
            if parsed is not None:
                key, names = parsed.key, list(parsed.names)
        elif text.startswith(gm.UNSURE):
            # The wire form itself (docs/ops/contracts.md): "??" + {"k": key, "o": [[name, value], ...]}.
            body = json.loads(text[len(gm.UNSURE):])
            key, names = body["k"], [o[0] for o in body["o"] if isinstance(o, list) and len(o) == 2 and isinstance(o[0], str)]
            if len(names) != len(body["o"]):
                key = ""   # an option that is no [name, value] pair: as labels.parse reads it, nothing to probe
    except Exception:
        key = ""
    if not isinstance(key, str) or not key:
        return f"GUESS {aid}: ? -"
    return f"GUESS {aid}: {key} {' '.join(str(name) for name in names) or '-'}"


def solve_budget(left, cap, asked):
    """Seconds the solver may run. Untimed: --solve-timeout, if given. On a clock: what is left
    after SUBMIT_MARGIN (not under MIN_SOLVE_BUDGET while MIN_SOLVE_LEFT remains), at most the
    lane's solve_cap, and at most --solve-timeout. The rule itself is lanes.run_budget, which
    tools/preflight.py --gate applies to a Mastery replay before the clock (backlog row 99)."""
    return lanes.run_budget(left, cap, asked)


def contract_problems(solver, cid: str, status_body) -> list:
    """Why a timed id's questions are not ones the lane's solver covers: a list of lines, empty
    when they are covered or there is nothing to check (no questions in the body, a lane whose
    contract is 'none', a lane that is not registered).

    status_body is the answer to op=status, which starts no clock. What it is checked against
    is the lane's contract in tools/lanes.py:
      same_ids  every question id, with its "setN." prefix removed, is an answer id of the base
                attempt saved on disk (the attempt the gate replayed with this solver);
      hook      the solver's own covers(questions), when it defines one, with the questions in
                the shape solve_set gets them."""
    body = status_body if isinstance(status_body, dict) else {}
    raw = [q for q in body.get("questions") or [] if isinstance(q, dict) and isinstance(q.get("id"), str)]
    if not raw:
        return []
    ids = body.get("answer_ids") or []
    ids = ids if len(ids) == len(raw) else [q["id"] for q in raw]
    questions = [shaped(q, aid)[1] for q, aid in zip(raw, ids)]
    entry = lanes.policy(lanes.lane_of(cid))
    contract = entry["contract"] if entry else "none"
    if contract == "same_ids":
        base = lanes.base_of(cid)
        try:
            known = set(answer_ids_for(json.loads((attempt_dir(base) / "attempt.json").read_text())))
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            known = set()
        if not known:
            return [f"no saved attempt of the base {base} to compare the question ids with"]
        return [f"{q['id']}: not an answer id of the base attempt ({base})" for q in questions if q["qid"] not in known]
    if contract == "hook" and callable(getattr(solver, "covers", None)):
        try:
            problems = solver.covers(questions)
        except Exception as e:
            return [f"the solver's covers() raised {type(e).__name__}: {str(e)[:200]}"]
        if isinstance(problems, str):
            problems = [problems]
        return [str(p) for p in problems or []]
    return []


def clock_cost(status_body) -> int:
    """Requests the attempt needs from the shared bucket once its clock runs: at most one
    download per set, plus retry, start, submit and one to spare. With no questions to count
    the sets from, judge.CLOCK_COST."""
    body = status_body if isinstance(status_body, dict) else {}
    questions = [q for q in body.get("questions") or [] if isinstance(q, dict)]
    if not questions:
        return judge.CLOCK_COST
    sets = {m.group(1) for m in (re.match(r"set(\d+)\.", str(q.get("id"))) for q in questions) if m}
    return max(len(sets), 1) + 4


# ---- no status read before a timed start (package PR1, switch preread; see preread()) -------------

LATE_CHECK = "the check ran after the start"     # in the one line that follows the CONTRACT lines of such a run


def cost_unread(cid: str) -> int:
    """The requests judge.clock() is asked to wait for when no status read told the sets: a Time
    Trial is one set, so what clock_cost() gives a one-set question list (5, as with the read); a
    Mastery's sets are not known before its start, so judge.CLOCK_COST, which is what clock_cost()
    gives a status body without questions."""
    return clock_cost({"questions": [{"id": "-"}]}) if str(cid).endswith("/time_trial") else judge.CLOCK_COST


def late_contract(solver, cid: str, attempt) -> list:
    """preread=none: contract_problems() on the START response's own question list, asked once the
    attempt is in hand and before any download is requested. The check sees what the status read
    showed it, the questions and nothing else (not answer_ids: the 409 body has none), so its
    lines are today's lines. It never holds or ends the attempt: the clock is already running, and
    what a solver does with a question it does not cover is the solver's (None or an unsure answer,
    which is never sent). A check that cannot be made is one problem line, as before."""
    questions = attempt.get("questions") if isinstance(attempt, dict) else None
    if not isinstance(questions, list) or not questions:
        return []
    try:
        return list(contract_problems(solver, cid, {"questions": questions}) or [])
    except Exception as e:
        return [f"the contract check failed ({type(e).__name__}: {e})"]


def late_contract_lines(cid: str, problems: list, limit: int = 40) -> list:
    """What a run prints for the problems late_contract() found: the `CONTRACT <problem>` lines as
    they have always been, then one line that says the check ran after the start. Empty for none."""
    if not problems:
        return []
    return [f"CONTRACT {p}" for p in problems[:limit]] + [
        f"contract mismatch: {len(problems)} problem(s) with the questions of {cid}; {LATE_CHECK} (preread=none), so the "
        f"clock was already running: the attempt is played on, and only what the solver answers plainly is sent"]


def format_problems(attempt, answers: dict, unsure=(), held=None) -> list:
    """One line per answer id that has no plain answer or whose answer contradicts the question's
    answer_format (tools/kinds.py: an enum value outside accepted_values, an integer that is no
    base-10 number, JSON that does not parse, a pattern that does not match). An id in `unsure`
    has an answer that was withheld, and its line says so; an id in `held` ({answer id: reason})
    had a plain answer of the wrong kind that was held back (backlog row 106)."""
    questions = attempt["questions"] if isinstance(attempt, dict) else attempt
    ids = answer_ids_for(attempt) if isinstance(attempt, dict) else [q["id"] for q in questions]
    held = held or {}
    bad = []
    for q, aid in zip(questions, ids):
        a = answers.get(aid)
        fmt = q.get("answer_format") or {}
        if a is None and aid in held:
            bad.append(f"{aid}: wrong kind, not sent ({held[aid]})")
        elif a is None and aid in unsure:
            bad.append(f"{aid}: unsure, not sent")
        elif a is None or a == "":
            bad.append(f"{aid}: no answer")
        elif fmt.get("kind") == "enum" and fmt.get("accepted_values") and a not in fmt["accepted_values"]:
            bad.append(f"{aid}: {a!r} not in {fmt['accepted_values']}")
        else:
            why = None
            if kinds is not None:
                with contextlib.suppress(Exception):
                    why = kinds.problem(a, fmt)
            if why:
                bad.append(f"{aid}: {why}")
    return bad


def attempt_dir(cid: str) -> Path:
    """Where gm.challenge_dir files an attempt, without creating anything or calling the API."""
    m = re.search(r"-day-(\d+)", cid)
    return gm.CHALLENGES / (f"day-{int(m.group(1)):02d}" if m else "unsorted") / cid


def history_name(attempt_id) -> str:
    """The folder under history/ for an attempt id. An id is a UUID and is its own name; one
    that is not (it came from a response, so it is untrusted) is made a single path part, so a
    variant can only ever move to a folder inside history/."""
    name = re.sub(r"[^\w.-]", "_", str(attempt_id)).strip(".")
    return name or "unnamed"


def save_attempt(cid: str, attempt: dict, blobs: list, d: Path = None) -> Path:
    """Write attempt.json and the deliveries. A different attempt already on disk moves to history/ first."""
    d = d or gm.challenge_dir(cid)
    d.mkdir(parents=True, exist_ok=True)
    old, prev = d / "attempt.json", None
    if old.exists():
        try:
            prev = json.loads(old.read_text()).get("attempt_id")
        except Exception:
            prev = None
        if prev and attempt.get("attempt_id") and prev != attempt["attempt_id"]:
            # A retry moved to a new variant: keep the earlier one for regression tests. Its verdicts,
            # its frozen key and the rest of VARIANT_FILES go with it, or the new variant would
            # inherit them.
            hist = d / "history" / history_name(prev)
            hist.mkdir(parents=True, exist_ok=True)
            for name in VARIANT_FILES:
                if not (d / name).exists():
                    continue
                to, n = hist / name, 1
                while to.exists():   # this variant has been in history before: nothing there is replaced
                    to, n = hist / f"{name}.{n}", n + 1
                shutil.move(str(d / name), str(to))
    (d / "attempt.json").write_text(json.dumps(attempt, indent=2))
    arts = attempt.get("artifacts") or []
    for i, data in enumerate(blobs):
        if not data:
            continue
        path = gm.artifact_path(d / "artifact", arts, i)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return d


def save_outcome(d: Path, answers: dict, result, submitted: bool, unsure=None) -> list:
    """Write the answers and the result.

    A run that submitted writes answers.json and answers.submitted.json: what
    the judge was sent. A run that did not submit (a dry run, a replay,
    --no-submit, a failed attempt) writes only answers.dry-run.json, so it can
    never replace the record of a judged attempt. `unsure` is a live run's
    withheld answers, {answer id: unsure value}: written to unsure.json when
    there are any, and an unsure.json left by an earlier run of the attempt is
    brought up to date. None leaves that file alone.
    """
    text = json.dumps(answers, indent=2)
    written = ["answers.json", "answers.submitted.json"] if submitted else ["answers.dry-run.json"]
    for name in written:
        (d / name).write_text(text)
    if unsure is not None and (unsure or (d / "unsure.json").exists()):
        (d / "unsure.json").write_text(json.dumps(unsure, indent=2))
        written.append("unsure.json")
    if result is not None:
        (d / "result.json").write_text(json.dumps(result, indent=2))
        written.append("result.json")
    return written


def save(cid: str, attempt: dict, blobs: list, answers: dict, result):
    """One-step save, kept for callers of the earlier API."""
    d = save_attempt(cid, attempt, blobs)
    save_outcome(d, answers, result, submitted=result is not None)
    return d


def load_offline(cid: str, where):
    """Read a saved attempt back: (attempt, blobs, directory). No network."""
    d = Path(where) if isinstance(where, str) else attempt_dir(cid)
    if not (d / "attempt.json").exists():
        sys.exit(f"--offline: no attempt.json under {d}")
    attempt = normalize(json.loads((d / "attempt.json").read_text()))
    # Game Master attempt bodies do not carry their challenge id.  Solvers that must distinguish a
    # standard one-off route from an older route need that stable routing fact on replays too.  Add it
    # only to the in-memory copy: attempt.json remains the exact saved response.
    local_cid = str(cid or "").strip()
    if not local_cid:
        for candidate in (d, *d.parents):
            if re.fullmatch(r"day-\d+", candidate.parent.name, re.I):
                local_cid = candidate.name
                break
    if local_cid:
        attempt["_challenge_id"] = local_cid
    arts, blobs = attempt.get("artifacts") or [], []
    for i in range(len(arts)):
        p = gm.artifact_path(d / "artifact", arts, i) if arts[i].get("filename") else None
        if p is None or not p.exists():
            # A response saved by `gm.py start` names no file: take the only one in the folder.
            folder = d / "artifact" if len(arts) == 1 else d / "artifact" / f"delivery-{i + 1:02d}"
            found = [x for x in sorted(folder.glob("*")) if x.is_file()] if folder.exists() else []
            p = found[0] if len(found) == 1 else None
        if p is None:
            sys.exit(f"--offline: delivery {i + 1} of {len(arts)} is not saved under {d / 'artifact'}")
        data = p.read_bytes()
        want = arts[i].get("sha256")
        if want and hashlib.sha256(data).hexdigest() != want:
            sys.exit(f"--offline: {p} does not match the sha256 in attempt.json")
        arts[i]["filename"] = arts[i].get("filename") or p.name
        blobs.append(data)
    return attempt, blobs, d


def body_of(resp) -> dict:
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {"error": "unexpected JSON", "body": data}
    except Exception:
        return {"error": f"http {resp.status_code}: response is not JSON", "body": resp.text[:300]}


def brief(data: dict, limit: int = 4000) -> str:
    return json.dumps({k: v for k, v in data.items() if k not in BULKY}, indent=2)[:limit]


SEEN_BODIES = []   # status and attempt bodies of this run, for note_contract() once the run is over (row 95)


def remember(body):
    """Keep a Game Master body for note_contract(). Costs nothing on the clock: a reference only."""
    if isinstance(body, dict) and body.get("guidance"):
        SEEN_BODIES.append(body)


def note_contract(cid: str):
    """After the run (its last line is printed, the clock is over): hand the guidance text of the
    bodies this run received to tools/contract.py, which diffs it against the last copy and
    raises GM CONTRACT CHANGED on a difference. No request; whatever fails is skipped."""
    if not SEEN_BODIES:
        return
    try:
        import contract
        for body in SEEN_BODIES[:4]:
            contract.note_guidance(body, cid, source=Path(sys.argv[0]).name)
    except Exception:
        pass
    SEEN_BODIES.clear()


def unknown_word(resp, op: str, st):
    """A start or retry answered with a word no tool knows: one NOTE for tools/open_day.py, which
    stops the lane at once with that word instead of trying again for a minute (row 95)."""
    word = gm.unknown_start_word(resp)
    walk = getattr(gm, "LAST_LADDER", None) or {}
    if not word and walk.get("op") == op and walk.get("sent") and walk.get("worked") is None \
            and getattr(gm, "refusal_word", lambda r: None)(resp):
        # Row 97: the start-body ladder sent every body the contract allows and each was refused
        # (by words the tools know: the route refuses run_for_time, a bare 400): stop at once as well.
        word = "start_ladder_exhausted"
    if word:
        st.unknown_start = word
        st.notes.append(f"{gm.UNKNOWN_START} {word} (http {resp.status_code}, {op}); the Game Master's contract "
                        f"may have changed: tools/contract.py show")


PRACTICE_NOTE = getattr(gm, "PRACTICE_NOTE", "practice attempt on a timed id")     # the NOTE tools/open_day.py reads
# Backlog row 256: a second solve pass inside a long window. The first pass keeps the lane's solve_cap (the
# number the gate holds a replay against, unchanged); when it was cut and the window still has
# SECOND_PASS_LEFT seconds or more, the sets it did not finish are solved again, from scratch, with at most
# SECOND_PASS_SHARE of what is left, and never past the submit margin. A 6 to 7 s window never has the time,
# so it is played as before; a hung solver holds at most half of what is left of a long one.
SECOND_PASS_LEFT = 10.0
SECOND_PASS_SHARE = 0.5
SECOND_PASS_MAX = 6.0     # seconds at most, whatever is left: tools/open_day.py gives a timed run.py step T_TIMED (25 s) in
                          # all, and a clock that runs on holds every other lane's untimed submits (review of f1f5f8c)


def fold_cut_lines(cut_lines: list) -> tuple[list, list]:
    """(errors, notes) of a first pass that was cut and that the second pass finished (row 256): a
    set that had no delivery (not downloaded, or B-042's unmapped set) stays an error, as no second
    pass can give it one; every other cut line becomes a `first pass:` NOTE."""
    kept = [line for line in cut_lines if _deliveries.is_unsolved_line(line)]
    noted = [f"first pass: {line.splitlines()[0]}" for line in cut_lines if not _deliveries.is_unsolved_line(line)]
    return kept, noted


def second_pass(solver, sets: list, answers: dict, done: list, st) -> bool:
    """Row 256: solve again the sets the first pass did not finish, when the attempt has a deadline and
    at least SECOND_PASS_LEFT seconds remain. A set the second pass finishes takes ITS answers whole (a
    cut set's partial answers can be the plain ones a full solve would have demoted); a set it cuts again
    keeps the first pass's answers and only adds ids they lacked. Returns True when the second pass
    finished every set it took (the run is then no longer cut). Never raises."""
    try:
        if not (st.clock and st.clock.window is not None):
            return False
        left = st.clock.left()
        if left is None or left < SECOND_PASS_LEFT:
            return False
        rest = [x for x in sets if x[0] not in set(done) and x[3].get("delivery")]
        if not rest:
            return False
        budget = max(0.05, min(left * SECOND_PASS_SHARE, left - lanes.RUN_SUBMIT_MARGIN, SECOND_PASS_MAX))
        errors, again = [], []
        t0 = time.perf_counter()
        more, cut = solve_all(solver, rest, budget, errors, again)
        for n, qs, _, _ in rest:
            ids = [q["answer_id"] for q in qs]
            if n in again:
                for aid in ids:
                    answers.pop(aid, None)
                answers.update({aid: more[aid] for aid in ids if aid in more})
            else:
                for aid in ids:
                    if aid in more and aid not in answers:
                        answers[aid] = more[aid]
        st.notes.append(f"second pass (row 256): {len(again)} of {len(rest)} set(s) the first pass did not finish "
                        f"solved again in {time.perf_counter() - t0:.2f}s of a {budget:.2f}s budget ({left:.1f}s were left)")
        finished = not cut and {n for n, _, _, _ in rest} <= set(again)
        if not finished:
            st.errors.extend(errors)
        return finished
    except Exception as e:  # noqa: BLE001 - never the submit's undoing: the first pass's answers stand
        st.notes.append(f"second pass (row 256) failed ({type(e).__name__}: {str(e)[:160]}); the first pass's answers stand")
        return False


UNTIMED_SOLVE_CAP = 45.0     # seconds a solver may run on a timed id's attempt that has no deadline (practice, a
                             # regular attempt): the run still holds the clock lock, so it is never unbounded


def practice_why(cid: str, attempt, asked: bool = False):
    """Why the attempt of a timed id is a practice attempt (no timer, no Hall of Fame time, the last
    artifact), or None: it says `practice` true, it came from this run's own op=practice, or it has
    no deadline while the Game Master says no fresh variant remains (what a retry dealt on
    2026-10-07)."""
    if not gm.is_timed(cid) or not isinstance(attempt, dict) or not attempt.get("questions"):
        return None
    if attempt.get("practice") is True:
        return "the Game Master says practice"
    if asked:
        return "dealt by op=practice"
    left = getattr(gm, "fresh_left", lambda *b: None)(attempt)
    if attempt.get("deadline") is None and (left == 0 or attempt.get("variant_fresh") is False):
        return "no deadline and no fresh variant" + (f" (unique_attempts_remaining {left})" if left is not None else "")
    return None


def practice_note(cid: str, why: str) -> str:
    return (f"{PRACTICE_NOTE}: {cid} ({why}); no fresh timed variant remains, so this attempt has no timer and no "
            f"Hall of Fame time; it can still complete the mode")


def continuation_bodies(cid: str, refused=None) -> list:
    """[(label, body)]: what to post, in order and each once, to go on with a timed id for which no
    fresh timed variant remains. The contract names two ways (tools/gm.py: "no fresh variant, and
    practice"): a dual-pool route is continued by a retry WITHOUT run_for_time (regular untimed
    play), a legacy route by op=practice. The way that fits the route goes first, the other after
    it. A route is dual-pool when its attempts carry `run_for_time`: read off the retry that was
    just refused (`refused`: the body templates the start ladder sent), else off the attempt saved
    on disk. A plain retry that was refused a moment ago is not sent again."""
    plain = ("retry without run_for_time", gm.start_body(cid, "retry", run_for_time=False))
    practice = ("practice", gm.practice_body(cid))
    if refused:
        dual = any("run_for_time" in t for t in refused if isinstance(t, dict))
        if any(isinstance(t, dict) and "run_for_time" not in t for t in refused):
            return [practice]                 # the plain retry is what was refused
    else:
        dual = False
        with contextlib.suppress(Exception):
            saved = json.loads((attempt_dir(cid) / "attempt.json").read_text())
            dual = isinstance(saved.get("run_for_time"), bool)
    return [plain, practice] if dual else [practice, plain]


RFT_SUPPORTED = "CTF_RFT_SUPPORTED"   # set by tools/open_day.py: 1 when the id's list row says run_for_time_supported true,
                                           # 0 when the row was listed live and does not say so; no such name when no row is known


def start_order(st) -> dict:
    """What start_attempt() asks of gm.post_start() about the order of a timed id's bodies (row 199):
    the pre-clock status body of this run as the hint, and the plain bodies first once run_for_time
    was answered timed_intent_not_available. `st` is this file's state or the ladder's job, which
    has a status_body only when its own status read set one: hence getattr. Before a retry that
    body is the attempt that ended, and the guidance read is the attempt's own text. The player's
    switch start=ladder asks for neither, and for a body that a hint remembered in routes.json
    earlier today to be left out: run_for_time first and the ladder in its own order, as on Days 8
    to 11.

    The list row's own signal (package T2 part c, Day 12; the event's lesson of 2026-10-11: a route
    whose op=list entry says "run_for_time_supported": true gives a regular untimed attempt on a
    plain start). tools/open_day.py's timed_run() sets CTF_RFT_SUPPORTED=1 for the tool of
    such an id, and then no hint is passed and a row a hint wrote is left out: run_for_time goes
    first whatever the guidance text says. A route that refuses it all the same gets the plain
    bodies next, as before.

    The other half of that signal (package PR1, 2026-10-11): a run that read no status before its
    start (preread=none) has no hint, and timed_run() sets CTF_RFT_SUPPORTED=0 for an id
    whose row was listed live and does not carry the flag. Then the body without run_for_time
    goes first (plain_first: the same body the guidance hint chooses), the default and the ladder
    behind it. With a status body in hand (preread=status) the 0 changes nothing: the hint decides,
    as before. Any other value, or no such name (no row is known: a --lane resume that fell back
    on day.json), changes nothing either: without a status body that is run_for_time first and
    the plain body after a refusal.

    The player's switch start=regular (backlog row 250) asks gm.post_start() for `regular`: the body
    without run_for_time first for a start and for a retry, the flag body next. It is read here, once
    per start, from the file as it stands."""
    if switch_on("start"):
        return {"ignore_hinted": True}
    told = ctf_env.get(RFT_SUPPORTED)
    if regular_mode() and not (told == "0" and getattr(st, "status_body", None) is None):
        # Row 250, start=regular: never opt in first, whatever the row, the guidance or routes.json say.
        # The one case left to the line below is a row this run listed live WITHOUT the flag and no status
        # body in hand: there the plain body goes first already, and everything stays as it is without
        # the value, to the cause routes.json keeps.
        return {"regular": True, "plain_after_refusal": True}
    if told == "1":
        return {"plain_after_refusal": True, "ignore_hinted": True}
    hint = getattr(st, "status_body", None)
    if hint is None and told == "0":
        return {"plain_first": True, "plain_after_refusal": True}
    return {"hint": hint, "plain_after_refusal": True}


CONTINUATION_REFUSED = "continuation_refused"     # row 252: the word of the at-once stop when no continuation body returned an attempt
REJOIN_NOTE = "rejoin:"                           # row 250: the runners' NOTE lines of a --rejoin
_REJOIN_NO_RETRY = ("CORRECT", "already_solved", "rate_limited", "unauthorized", "base_not_solved", "unknown_challenge",
                    "artifact_unavailable")


def retry_spent(cid: str, resp) -> bool:
    """Row 253: True when a retry's answer is no attempt, names no other matter (not a 401, a 429 or a
    5xx; not attempt_active, base_not_solved and the other words of gm._NOT_NO_FRESH), and the attempt
    on disk says unique_attempts_remaining 0. The Game Master may word a refused retry differently from
    the one form seen (rotation_exhausted); with the route's own count at 0 there is no fresh variant
    to retry into either way, so the continuation follows in the same process. Never raises."""
    try:
        code = int(resp.status_code)
        if code in (401, 429) or code >= 500:
            return False
        body = body_of(resp)
        if body.get("questions"):
            return False
        word = body.get("error") or body.get("result")
        if isinstance(word, str) and word in getattr(gm, "_NOT_NO_FRESH", ()):
            return False
        saved = json.loads((attempt_dir(cid) / "attempt.json").read_text())
        left = saved.get("unique_attempts_remaining")
        return left == 0 and not isinstance(left, bool)
    except Exception:
        return False


def continuation_refused(resp, answers: list, st):
    """Row 252: the continuation step ran and no body returned an attempt. When every answer was a
    refusal of the body (a 4xx other than 401 and 429, and not attempt_active: an attempt that is
    still live is no refusal of the continuation, and a rate limit refuses nothing), the Game Master
    will not let this mode go on, and asking again every 2 s for a minute only spends the request
    count all lanes share (the lock-out other teams reported on Day 11 Binary): the unknown-word NOTE
    is printed with the word CONTINUATION_REFUSED, and tools/open_day.py stops the lane at once,
    critical, when the start that follows returns no attempt either. Otherwise as before: a word no
    tool knows on the last answer is said, and anything else is tried again by the opener."""
    refused = bool(answers) and all(400 <= int(code) < 500 and int(code) not in (401, 429) and not limited
                                    and word != "attempt_active" for _, code, word, limited in answers)
    if not refused:
        return unknown_word(resp, "practice", st)
    said = ", ".join(f"{label}: http {code} {word or '-'}" for label, code, word, _ in answers)
    if not getattr(st, "unknown_start", None):       # a word no tool knows on the retry itself stays the run's word
        st.unknown_start = CONTINUATION_REFUSED
    st.notes.append(f"{gm.UNKNOWN_START} {CONTINUATION_REFUSED} (http {resp.status_code}, practice); the untimed "
                    f"continuation was refused by every body ({said}): this mode cannot go on from here")


def rejoined(s, cid: str, st, attempt, resp, sent: dict, order: dict) -> tuple:
    """Row 250, --rejoin: what the plain start returned for an attempt of ours that the opener holds to be
    still open (a regular attempt: no deadline, a rejected batch leaves it open). No retry was posted.
    Returns (attempt, response) to play. When the start returned an attempt it is played, and one NOTE
    says whether it is the one on disk. When it returned none (and not CORRECT, a rate limit or
    another matter a retry cannot help), ONE retry is posted in its place, with the same body order,
    and what that returns is played."""
    try:
        on_disk = json.loads((attempt_dir(cid) / "attempt.json").read_text()).get("attempt_id")
    except Exception:
        on_disk = None
    body = attempt if isinstance(attempt, dict) else {}
    if body.get("questions"):
        now = body.get("attempt_id")
        if on_disk and now and now != on_disk:
            st.notes.append(f"{REJOIN_NOTE} the start returned ANOTHER attempt ({str(now)[:8]}) than the one on disk "
                            f"({str(on_disk)[:8]}); it is played as a new start")
        else:
            st.notes.append(f"{REJOIN_NOTE} the start returned our open attempt ({str(now)[:8]}); no retry was posted")
        return attempt, resp
    word = word_of(body)
    code = resp.status_code
    if code in (401, 429) or code >= 500 or word in _REJOIN_NO_RETRY:
        st.notes.append(f"{REJOIN_NOTE} the start returned no attempt (http {code} {word or '-'}); no retry is sent for that")
        return attempt, resp
    st.notes.append(f"{REJOIN_NOTE} the start returned no attempt (http {code} {word or '-'}); ONE retry is sent in its place")
    again = gm.check(patient(lambda: gm.post_start(s, cid, "retry", notes=st.notes, sent=sent, **order), st.notes, "retry"))
    r = body_of(again)
    st.notes.append(f"retry answered http {again.status_code}: " + json.dumps({k: v for k, v in r.items() if k not in BULKY})[:300])
    if r.get("questions"):
        st.start_http = again.status_code
        return r, again
    unknown_word(again, "retry", st)
    return attempt, resp


def start_attempt(s, cid: str, retry: bool, st):
    """POST retry and/or start (the body is gm.start_body: run_for_time on a timed id, with the
    fallback to the old body for a route that refuses it; row 199: the plain body first when this
    run's own status read says the route takes no timed intent, start_order()). Returns (attempt, Clock).

    No fresh timed variant (the event guide and the contract of 2026-10-08; tools/gm.py). With
    st.practice set (--practice: the opener read a count of 0 off the last attempt), or when the
    retry is REFUSED because no fresh variant remains (gm.no_fresh_variant), the untimed
    continuation is posted in its place, in this process and on the same ticket: a retry without
    run_for_time and {"op":"practice"}, in the order that fits the route (continuation_bodies),
    each once, until one returns an attempt. That attempt has no timer; it is played like any
    other and said plainly in a NOTE (PRACTICE_NOTE, or row 108's REGULAR_NOTE for a regular
    attempt on a fresh variant). A retry that simply returns the same artifact again is an attempt
    like any other and is played.

    Rows 252 and 253 (2026-10-12): the continuation also follows a retry that returned no attempt
    while the attempt on disk counts no unique attempt left (retry_spent), and a continuation that
    every body refused is said with the word continuation_refused (continuation_refused()).

    Row 250: with st.rejoin (--rejoin: the opener holds our attempt on disk to be still open, under
    start=regular) no retry and no continuation is posted; the start rejoins the attempt, with one
    fall-back to the retry when it returns none (rejoined())."""
    sent = {"t": time.perf_counter()}
    attempt = resp = None
    order = start_order(st)      # read once: a 429 sends patient() back into post_start with the same order
    practice = bool(getattr(st, "practice", False)) and gm.is_timed(cid)
    asked, refused = False, None
    rejoin = bool(getattr(st, "rejoin", False)) and gm.is_timed(cid)
    if rejoin:
        retry = practice = False     # row 250: no retry at an attempt of ours that is still open; the start rejoins it
    if retry and practice:
        retry = False            # no fresh variant is left to retry into: practice below, then the plain start
    mine = None                  # the id of our attempt on disk as it stands before any request of this run
    with contextlib.suppress(Exception):
        mine = json.loads((attempt_dir(cid) / "attempt.json").read_text()).get("attempt_id")
    if retry:
        # sent: the start-body ladder (row 97) may send several bodies; the clock runs from the one that answered
        resp = gm.check(patient(lambda: gm.post_start(s, cid, "retry", notes=st.notes, sent=sent, **order),
                                st.notes, "retry"))
        r = body_of(resp)
        # The attempt-id rule (the review of 2026-10-12): an answer that names an attempt other than ours on disk
        # is the Game Master holding a teammate's. It is no "no fresh variant" of ours, nothing is posted at it,
        # and its line stays the teammate sign it was; an answer that names OUR attempt says so on the line.
        foreign = getattr(gm, "foreign_attempt", lambda b, o: False)(r, mine)
        st.notes.append(f"retry answered http {resp.status_code}: " + json.dumps({k: v for k, v in r.items() if k not in BULKY})[:300]
                        + (getattr(gm, "OURS_MARK", "") if r.get("attempt_id") and not r.get("questions") and not foreign else ""))
        if foreign and not r.get("questions"):
            st.notes.append(f"the retry's answer names attempt {str(r.get('attempt_id'))[:8]}, not ours on disk "
                            f"({str(mine)[:8] if mine else 'none'}): a teammate's? No continuation is posted at it")
        if normalize(r).get("artifacts") and r.get("questions"):
            attempt = r
        elif foreign:
            unknown_word(resp, "retry", st)   # as before rows 253 and 254: the start below reconnects, and the line is a sign
        elif (getattr(gm, "no_fresh_variant", lambda r_, loose=False: False)(resp, loose=True)
              or getattr(gm, "no_fresh_word", lambda r_, o=None: False)(resp, mine)):     # row 253: also in a 2xx body, or beside OUR attempt id
            practice = True
            refused = list((getattr(gm, "LAST_LADDER", None) or {}).get("sent") or [{"run_for_time": True}])
            st.notes.append("the retry was refused because no fresh variant remains; the untimed continuation is sent "
                            "in its place")
        elif retry_spent(cid, resp):
            # Row 253: the retry returned no attempt under a word that names no other matter, and the attempt
            # on disk says the route has no unique attempt left: the continuation by the count on disk.
            practice = True
            refused = list((getattr(gm, "LAST_LADDER", None) or {}).get("sent") or [{"run_for_time": True}])
            # A word no tool knows is still said, with the ladder's walk, as before row 253: when the continuation is
            # refused too, the opener's stop names it and reads the contract (review of 2026-10-12).
            unknown_word(resp, "retry", st)
            st.notes.append("the retry returned no attempt and the attempt on disk says unique_attempts_remaining 0; "
                            "the untimed continuation is sent in its place")
        else:
            unknown_word(resp, "retry", st)   # the start below is still sent: it reconnects to a live attempt
    if attempt is None and practice:
        answers = []             # row 252: (label, http status, word) of every continuation body that returned no attempt
        for label, body in continuation_bodies(cid, refused):
            def ask(body=body):
                sent["t"] = time.perf_counter()
                return s.post(gm.GM, json=body, timeout=30)
            resp = gm.check(patient(ask, st.notes, label))
            r = body_of(resp)
            st.notes.append(f"{label} answered http {resp.status_code}: "
                            + json.dumps({k: v for k, v in r.items() if k not in BULKY})[:300])
            if normalize(r).get("artifacts") and r.get("questions"):
                attempt, asked = r, label == "practice"
                break
            answers.append((label, resp.status_code, word_of(r), rate_limited(resp)))
        else:
            continuation_refused(resp, answers, st)   # the start below is still sent: it reconnects to a live attempt
        retry = True             # for the start below: its request is not what began the attempt's window
    if attempt is None:
        def start():
            if not retry:
                sent["t"] = time.perf_counter()  # the window cannot have begun before the request that started it
            # post_start moves sent["t"] to each body of the start-body ladder as it leaves (row 97)
            return gm.post_start(s, cid, "start", notes=st.notes, sent=None if retry else sent, **order)
        resp = gm.check(patient(start, st.notes, "start"))
        attempt = body_of(resp)
        st.start_http = resp.status_code
        unknown_word(resp, "start", st)     # nothing for an attempt, a known word, a 429 or a 5xx
        if rejoin:
            attempt, resp = rejoined(s, cid, st, attempt, resp, sent, order)
    remember(attempt)
    with contextlib.suppress(Exception):     # which pool the attempt came from; never the start's undoing
        why = practice_why(cid, attempt, asked)
        if why:
            st.practice_played = why
            st.notes.append(practice_note(cid, why))
        else:
            note = regular_note(cid, attempt)      # row 108
            if note:
                st.notes.append(note)
    return attempt, Clock(attempt, resp, sent["t"], time.perf_counter(),
                          known_resumed=known_own_rejoin(attempt))


def word_of(body) -> str:
    """What a response says, as one token for the RUN line: its result, else its error."""
    if isinstance(body, dict):
        for field in ("result", "error"):
            value = body.get(field)
            if isinstance(value, (str, int)) and not isinstance(value, bool) and str(value):
                return re.sub(r"[^\w.:+-]+", "_", str(value))[:60]
    return ""


def record(st, cid: str, values: dict, result, http=None, kind="bank"):
    """Append one submission and what came back to the attempt's verdicts.jsonl. It never
    raises: the request has been sent, and a ledger that cannot be written must not cost the run."""
    if judge is None:
        return
    try:
        judge.record(st.dir or attempt_dir(cid), values, result, left=st.clock.left() if st.clock else None,
                     http=http, kind=kind, attempt_id=(st.attempt or {}).get("attempt_id"))
    except Exception as e:
        st.notes.append(f"verdicts.jsonl was not written ({type(e).__name__}: {e})")


def freeze(st, cid: str):
    """The attempt is CORRECT: write key.json from its verdict ledger. An existing key stays."""
    if judge is None:
        return
    d = st.dir or attempt_dir(cid)
    try:
        had = (d / "key.json").exists()
        if judge.freeze_key(d, st.attempt) is None and not had:
            st.notes.append("CORRECT, but key.json was not written: the recorded verdicts do not cover every answer id")
    except Exception as e:
        st.notes.append(f"key.json was not written ({type(e).__name__}: {e})")


def status_after_failed_submit(s, cid: str, st, error) -> bool:
    """The submit request failed, so it is not known whether the judge saw it. Read op=status
    once and, when the server has a result for this attempt, keep that as result.json in place
    of the not_submitted marker. True when it had one.

    CORRECT for this very attempt is also taken as the verdict on what was sent: the attempt
    was open when this run got it from start, the failed request was this run's one submission,
    and the judge banks a batch only when all of it is right. The row is recorded with kind
    'status', so the ledger shows where it came from. Any other result says nothing about these
    answers, and is recorded against no answer."""
    try:
        resp = gm.check(s.get(gm.GM, params={"op": "status", "challenge": cid}, timeout=time_limit(st.clock, 2.0)))
        body = body_of(resp)
    except Exception:
        return False
    said, ours, theirs = body.get("result"), st.attempt.get("attempt_id"), body.get("attempt_id")
    if not isinstance(said, str) or not said or (ours and theirs and ours != theirs):
        return False
    word = word_of(body)
    st.left_after = st.clock.left() if st.clock else None
    st.result = {"result": said[:60], "attempt_id": ours, "source": "op=status after the submit request failed",
                 "submit_error": f"{type(error).__name__}: {error}"[:300]}
    if isinstance(body.get("remaining"), (int, list)) and not isinstance(body.get("remaining"), bool):
        st.result["remaining"] = body["remaining"]
    mine = said == "CORRECT" and bool(ours) and ours == theirs
    record(st, cid, st.answers if mine else {}, said[:60], http=resp.status_code, kind="status")
    if mine:
        st.submitted = True
        freeze(st, cid)
    st.errors.append(f"the submit request failed ({type(error).__name__}: {error}); op=status says {word}")
    return True


# Row 223 (b) (Day 20 build): the Time Trial variant's replay, warmed for the Mastery gate. The Mastery gate
# replays the base (cached since row 223 (a)) and the Time Trial variant just closed (0.28 to 0.37 s with its
# expand on Script, Day 17; row 337). The runner's first submit is its idle time: the solve is done and the
# judge's answer is on its way (Day 17 Script: 1.77 s). So PREWARM_AFTER s after that submit is handed to the
# wire, a thread starts `tools/preflight.py --prewarm <lane> --dir <time_trial folder> --pid <this process>`,
# but only while the one clock running on this machine is this process's own for this id
# (judge.only_own_clock): beside another lane's clock it starts nothing (conflict C7 of the Day 19 build). The
# warm-up replays the variant into a PENDING row of gate_replays.json that the Mastery gate takes only once it
# reproduces key.json (row 357's rule), under the same check (preflight.prewarm_timed). Its output goes to
# <CHALLENGES>/_logs/timed-prewarm-<lane>.log (prewarm-<lane>.log is verify.py's base warm-up, which the release
# pass never starts). CTF_PREWARM=off turns it off. Nothing here can raise or wait.
PREWARM_ENV = "CTF_PREWARM"
PREWARM_AFTER = 0.05     # seconds after the first submit is handed to the wire: the request has left by then


# The Day 21 local speed build (gate reuse): the solve this run already made, offered to the next gate as a PENDING
# row of gate_replays.json (tools/preflight.py, pending_from_solve, which says when a row is written and when the
# gate takes it). tools/verify.py offers the base, this runner and the ladder the Time Trial, each from a thread
# started as its first submit is handed to the wire (PREWARM_AFTER later: the request has left), and each joins
# it before the process ends (join_gate_row), so the gate that follows finds the row. Nothing here raises; a
# row not written costs only the replay the gate made before. CTF_GATE_REUSE=off turns it off.
GATE_ROW = {"thread": None, "result": None}
GATE_ROW_JOIN = 5.0      # seconds a tool waits for its row at its end, at most


def gate_offer(cid: str, folder, solver_path, attempt: dict, blobs: list, answers: dict, solved_from_ns: int,
               expand: float, solve: float, source: str):
    """What offer_gate_row hands preflight.pending_from_solve, or None when this solve is not offered (not a
    base or a Time Trial, the switch off). The answers are copied (one shallow dict copy, microseconds), so what
    the run learns after the solve never reaches the row; the attempt and the bytes are kept by reference."""
    if ctf_env.get("CTF_GATE_REUSE") == "off" or ctf_env.get("CTF_GATE_CACHE") == "off":
        return None
    try:
        if lanes.mode_of(cid) not in ("base", "time_trial") or folder is None:
            return None
    except Exception:
        return None
    return {"cid": cid, "folder": folder, "solver_path": solver_path, "attempt": attempt, "blobs": list(blobs or []),
            "answers": dict(answers or {}), "solved_from_ns": solved_from_ns, "expand": expand, "solve": solve,
            "source": source}


def offer_gate_row(offer):
    """Start the thread that writes the offer (gate_offer) as a pending row, once per process. Never raises."""
    if not offer or GATE_ROW["thread"] is not None:
        return

    def go():
        try:
            time.sleep(PREWARM_AFTER)
            import preflight
            GATE_ROW["result"] = preflight.pending_from_solve(**offer)
        except Exception as e:
            GATE_ROW["result"] = (False, f"{type(e).__name__}: {str(e)[:160]}")
    try:
        t = threading.Thread(target=go, name="gate-row", daemon=True)
        GATE_ROW["thread"] = t
        t.start()
    except Exception:
        GATE_ROW["thread"] = None


def join_gate_row(timeout: float = GATE_ROW_JOIN):
    """Wait (at most `timeout` s) for this process's gate row; its (written, why), or None when none was offered."""
    t = GATE_ROW.get("thread")
    if t is None:
        return None
    with contextlib.suppress(Exception):
        t.join(timeout)
    return GATE_ROW.get("result")


def start_timed_prewarm(cid: str, folder):
    """Row 223 (b): start the Time Trial variant's warm replay (see above) on a thread of its own. Only for a
    `<base>/time_trial` id with its folder on disk and a lane the registry knows; never for a Mastery or a base."""
    try:
        if (ctf_env.get(PREWARM_ENV) == "off" or judge is None or folder is None
                or lanes.mode_of(cid) != "time_trial" or not (Path(folder) / "attempt.json").is_file()):
            return
        lane = lanes.lane_of(cid)
        if not lane or lanes.policy(lane) is None:
            return
    except Exception:
        return
    pid = os.getpid()

    def go():
        try:
            time.sleep(PREWARM_AFTER)
            done = join_gate_row(2.0)
            if done and done[0]:
                return          # the run's own solve is the Mastery gate's row already (gate reuse): no replay
            if not judge.only_own_clock(pid, cid):
                return          # the clock is over (the verdict is in) or another one runs: the gate replays it
            logs = gm.CHALLENGES / "_logs"
            logs.mkdir(parents=True, exist_ok=True)
            with open(logs / f"timed-prewarm-{lane}.log", "a", encoding="utf-8") as out:
                out.write(f"=== {time.strftime('%Y-%m-%dT%H:%M:%S')} preflight.py --prewarm {lane} --dir {folder} "
                          f"(the Time Trial variant, row 223 (b))\n")
                out.flush()
                subprocess.Popen([sys.executable, str(Path(__file__).resolve().parent / "preflight.py"), "--prewarm", lane,
                                  "--dir", str(folder), "--pid", str(pid)], stdin=subprocess.DEVNULL, stdout=out,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        except Exception:
            pass
    try:
        threading.Thread(target=go, name="prewarm-tt", daemon=True).start()
    except Exception:
        pass


PROBE413_MARK_ENV = "CTF_PROBE413_MARK"   # row 413's probe (Day 21 build): named by tools/open_day.py to the
                                               # Warmups Time Trial's runner alone, in its full pass


def probe413_mark():
    """Row 413's probe: write the time this submit leaves into the file CTF_PROBE413_MARK names, once
    (created exclusively, so only the run's first submit marks). The opener's probe thread sends its one plain
    Mastery start 0.30 s after this time. Without the name nothing is done; it never raises and never waits."""
    path = ctf_env.get(PROBE413_MARK_ENV)
    if not path:
        return
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except OSError:
        return
    try:
        os.write(fd, f"{time.time():.4f}\n".encode())
    except OSError:
        pass
    finally:
        os.close(fd)


def submit(s, cid: str, st):
    """The run's one submission: every plain answer in a single request. Each response is on
    disk in verdicts.jsonl before anything else happens, and CORRECT freezes the key."""
    offer_gate_row(getattr(st, "gate_offer", None))         # gate reuse (Day 21 local speed): after the request has left
    start_timed_prewarm(cid, getattr(st, "dir", None))      # row 223 (b): its thread waits until the request has left

    def send():
        probe413_mark()     # row 413: the time this submit leaves (a no-op unless the opener named the file)
        resp = s.post(gm.GM, json={"challenge": cid, "answers": st.answers}, timeout=time_limit(st.clock, 2.0))
        record(st, cid, st.answers, body_of(resp), http=resp.status_code)
        return resp

    try:
        resp = patient(send, st.notes, "submit", clock=st.clock, cid=cid)
    except Exception as e:
        st.infra = True
        record(st, cid, st.answers, f"no response ({type(e).__name__})")
        if not status_after_failed_submit(s, cid, st, e):
            raise
        return
    st.left_after = st.clock.left() if st.clock else None
    # A request that was still rate limited after the re-sends was not processed: nothing was submitted.
    st.result, st.submitted = body_of(gm.check(resp)), not rate_limited(resp)
    if getattr(st, "prior", None):
        st.prior.saw(st.answers, st.result.get("result"), st.left_after)    # row 415: in memory, no file
    if st.result.get("result") == "CORRECT":
        freeze(st, cid)
    elif st.result.get("result") not in VERDICTS:
        st.infra = True   # a rate limit, a 5xx, an expired attempt: nothing was judged


# ---- row 415: the family prior's answers, into the labels ledger once the judge accepted them --------------

def prior_watch(answers: dict):
    """labels.PriorWatch over the solver's answers, or None (no labels module loaded, an older one, or nothing the
    family prior answered). The module is the one the solver imported (sys.modules), as guess_line reads it."""
    try:
        make = getattr(sys.modules.get("labels"), "PriorWatch", None)
        watch = make(answers) if make is not None else None
        return watch if watch else None
    except Exception:
        return None


def prior_flush(st):
    """Row 415: after the run's last request, one `accepted` ledger row per key the prior answered and the judge
    accepted, and one NOTE. Never raises; nothing is sent."""
    watch = getattr(st, "prior", None)
    if not watch:
        return
    try:
        said = type(watch).note(watch.flush((st.attempt or {}).get("attempt_id")))
        if said:
            st.notes.append(said)
    except Exception:
        pass


# ---- row 412: a solver's warm(), on a thread before the timed start --------------------------------------

def start_warm(solver, st, when: str = "before the start"):
    """Row 412: when the lane solver module defines a callable warm() (crib_decode.py's: the day chains it would
    otherwise prove inside the window), call it once on a daemon thread, so its CPU work overlaps the start
    request in flight (Day 20 Warmups: 0.23 s of proofs against 0.65 s of network wait). Nothing waits for it:
    not the start, not the solve, not the submit (the solver tolerates a warm() still running). An exception
    in it is swallowed with one NOTE. A solver without warm() is untouched. Once a process."""
    if getattr(st, "warm_started", None) is not None:
        return
    fn = getattr(solver, "warm", None)
    if not callable(fn):
        st.warm_started = False
        return
    st.warm_started = when

    def go():
        try:
            fn()
        except BaseException as e:  # noqa: BLE001 - a warm-up is never the run's undoing
            st.notes.append(f"the solver's warm() raised {type(e).__name__}: {str(e)[:160]}; the solve goes on "
                            f"without it (row 412)")
    try:
        threading.Thread(target=go, name="solver-warm", daemon=True).start()
        st.notes.append(f"the solver's warm() was started on a thread {when} (row 412)")
    except Exception as e:  # a thread that cannot start: no warm-up, as before the row
        st.notes.append(f"the solver's warm() was not started ({type(e).__name__}: {e}) (row 412)")


# Backlog row 299 (2026-10-13). Until then an unsure answer was never sent by this runner: the rule was made
# for 6 s windows. Day 13's windows were 50 to 200 s, a regular attempt has no deadline, and the legacy routes
# gave one attempt per mode, so a variant that asks a fact whose name is not judged lost the mode for good.
PROBE_MAX = 6            # option probes of one run at most
PROBE_FLOOR = 10.0       # no probe request with less than this many seconds on the clock (no deadline: no floor)
PROBE_GAP = 0.4          # seconds between this run's submits while it probes: the gap of untimed submissions, which
                         # the wire does not keep inside a clock (the ladder keeps it only without a deadline)


def probe_gap(deadline: bool) -> float:
    """Backlog row 302: the gap between this run's submits while it probes. A probing clock holds every other
    lane's untimed submit for its whole length, so it keeps no more gap than the ladder does: none inside a
    window with a deadline (the ladder sends there back to back; requests inside a clock are only counted), and
    without a deadline the token's own gap of untimed submissions (judge's MINUTE_GAP plus its pad under
    wire=minute, else PROBE_GAP), never more than PROBE_GAP."""
    if deadline:
        return 0.0
    try:
        if judge is not None and judge.minute_mode():
            return min(PROBE_GAP, judge.MINUTE_GAP + judge.GAP_PAD)
    except Exception:
        pass
    return PROBE_GAP


def proposer_gate_check(cid: str, st):
    """The proposer gate (tools/proposer_gate.py): a clock its ticket opened for a regular attempt with no deadline
    whose start returned a timed one (a deadline, a window, run_for_time true) sends nothing unsure: st.no_unsure says
    why, may_probe() and proposer_start() read it, one critical alert is raised and the lane falls back to today's
    rules (the marker beside the base). A ticket of the ordinary gate changes nothing. Never raises."""
    try:
        if not st.timed or not isinstance(st.ticket, dict) or not st.ticket.get("proposer_gate"):
            return
        import proposer_gate
        why = proposer_gate.runner_fallback(cid, st.ticket, st.attempt, attempt_dir(lanes.base_of(cid)))
        if why:
            st.no_unsure = why
            st.notes.append(f"PROPOSER GATE FALLBACK {cid}: {why}")
        else:
            st.notes.append(f"proposer gate: a regular attempt with no deadline, as the gate expected; the proposer "
                            f"probes the {st.ticket.get('proposer_gate')} id(s) the replay leaves open")
    except Exception as e:
        st.no_unsure = f"the proposer gate's start check failed ({type(e).__name__})"
        st.notes.append(f"PROPOSER GATE FALLBACK {cid}: {st.no_unsure}")


def may_probe(cid: str, st) -> str:
    """Why this run sends nothing for its unsure answers, or '' when it may probe them (row 299):
    a timed id, nothing the kind check holds, the confident batch accepted (or no confident answer
    at all), and at least PROBE_FLOOR seconds on the clock or no deadline."""
    if not st.unsure:
        return "nothing is unsure"
    if getattr(st, "no_unsure", ""):
        return f"the proposer gate fell back: {st.no_unsure}"
    if not gm.is_timed(cid):
        return "an untimed base is probed by tools/verify.py"
    if getattr(st, "misformat", None):
        return "the kind check holds an answer, so the attempt cannot close"
    if getattr(st, "bisected_in_window", False):
        return "the confident batch was rejected and bisected inside the window (it ends short of CORRECT as before)"
    if st.timed_out or st.infra:
        return "the run is not clean (the solver was cut, or a request was not judged)"
    if st.answers:
        word = (st.result or {}).get("result") if isinstance(st.result, dict) else None
        if not st.submitted or word != "accepted":
            return f"the confident batch was not accepted ({word or 'not judged'})"
    left = st.clock.left() if st.clock else None
    if left is not None and left < PROBE_FLOOR:
        return f"{left:.1f} s left, under the {PROBE_FLOOR:g} s a probe needs"
    return ""


def probe_unsure(s, cid: str, st, group=None, max_total=None, max_per_key=None):
    """Row 299: probe each unsure key the way the ladder and verify.py do, with the one grading
    algorithm (tools/grade.py probe): the options of a key on ONE id, one per request, in order;
    the accepted name goes to the labels ledger and to the key's other ids as one batch. At most
    PROBE_MAX option probes, none with less than PROBE_FLOOR seconds left, PROBE_GAP apart. Every
    request is in verdicts.jsonl before the next one. A response that is no verdict ends the
    probing (grade's rule), and what is still unsure stays a GUESS line, as before. A `None` is
    never probed: it is not in st.unsure. Returns grade's Probe, or None when nothing was probed.

    The adaptability build: `group` ({answer id: unsure string}) probes the proposer's candidate keys instead of
    st.unsure (propose_open checks its own conditions first), with its own budget (max_total, max_per_key)."""
    if group is None:
        why = may_probe(cid, st)
        if why:
            if st.unsure and gm.is_timed(cid):
                st.notes.append(f"unsure answers were not probed: {why} (row 299)")
            return None
    import grade                    # here, not at the top: it imports labels, and which copy of solvers/common
    labels = grade.labels           # a solver uses is the solver's choice (see guess_line)
    d = st.dir or attempt_dir(cid)
    attempt_id = (st.attempt or {}).get("attempt_id")
    # Every option's value as it goes on the wire (tools/verify.py _text: a string as it is, anything else as
    # compact JSON), before grade sees it: the request, the name looked up for the ledger, the rejected pairs
    # of verdicts.jsonl and the answer kept in st.answers are then one text, and key.json and the gate's
    # replay agree for an option that is a number or a list.
    def wire_text(value):
        return value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
    unsure, parsed = {}, {}
    for aid, v in (st.unsure if group is None else group).items():
        u = labels.parse(v) if isinstance(v, str) else None
        if u is not None and u.key:
            v = gm.UNSURE + json.dumps({"k": u.key, "o": [[n, wire_text(x)] for n, x in u.options]}, separators=(",", ":"))
            u = labels.parse(v)
        unsure[aid], parsed[aid] = v, u
    rejected = set()
    try:
        rejected = set(judge.ledger(d, attempt_id=attempt_id)[1]) if judge is not None else set()
    except Exception:
        rejected = set()
    left = st.clock.left if st.clock else None
    # Row 346: a candidate pick (labels.candidates: different candidate values under one key) is probed only on
    # an attempt with no deadline (a regular attempt, practice). Inside a deadline it stays a GUESS line.
    deadline = bool((st.clock and st.clock.window is not None) or (st.attempt or {}).get("deadline"))
    gap = probe_gap(deadline)       # row 302
    seen = {"at": time.perf_counter() if st.submitted else None, "good": None, "last": None, "unjudged": None}
    sent_before = bool(st.submitted)

    def send(values):
        aid = next(iter(values))
        u = parsed.get(aid)
        name = next((n for n, v in (u.options if u else ()) if v == values[aid]), None)
        if seen["at"] is not None:
            wait = gap - (time.perf_counter() - seen["at"])
            if wait > 0:
                time.sleep(wait)
        seen["at"] = time.perf_counter()
        http, body = None, {}
        try:
            resp = s.post(gm.GM, json={"challenge": cid, "answers": dict(values)}, timeout=time_limit(st.clock, 2.0))
            http, body = resp.status_code, body_of(resp)
            word = body.get("result") if isinstance(body.get("result"), str) else None
            if rate_limited(resp):
                word = "rate_limited"
            elif word not in VERDICTS:
                word = word_of(body) or f"http {http}"
                word = f"http {http}" if word in VERDICTS else word      # a verdict word in the wrong field is none
        except gm.NothingToSend:
            resp, word = None, "nothing_to_send"
        except Exception as e:      # a dropped connection, a timeout: not judged, and the probing ends
            resp, word = None, type(e).__name__
        after = left() if left else None
        try:
            if judge is not None:
                judge.record(d, dict(values), word, remaining=body.get("remaining") if word in ("accepted", "CORRECT") else None,
                             left=after, http=http, kind="probe" if len(values) == 1 else "bank",
                             key=u.key if u else None, name=name, attempt_id=attempt_id)
        except Exception as e:      # the request went out: its verdict stands whether or not it was written down
            st.notes.append(f"verdicts.jsonl was not written ({type(e).__name__}: {e})")
        if resp is not None and (http == 401 or body.get("error") == "unauthorized"):
            gm.check(resp)          # as the run's one submission does: the token was rejected, the run ends
        raw = {k: v for k, v in body.items() if k not in BULKY}
        if word in VERDICTS:
            seen["last"] = raw
            if word != "incorrect":
                seen["good"] = raw
            st.left_after = after
        else:
            seen["unjudged"] = (word, raw)
        return grade.verdict(word, body.get("remaining") if word in ("accepted", "CORRECT") else None, raw)

    def on_learn(key, name, verdict, scope="key", ids=()):
        labels.learn(key, name, verdict, scope=scope, answer_ids=list(ids), left=left() if left else None,
                     attempt_id=attempt_id)

    out = grade.probe(send, unsure, left=left, floor=PROBE_FLOOR, max_total=PROBE_MAX if max_total is None else max_total,
                      max_per_key=labels.MAX_OPTIONS if max_per_key is None else max_per_key, skip=frozenset(rejected),
                      on_learn=on_learn, order=answer_ids_for(st.attempt), candidates=not deadline)
    if out.requests and seen["last"] is None and not sent_before:
        # Nothing confident was sent and no probe was judged (a 429, a dropped connection): this run
        # submitted nothing. It ends as a run whose one submission was not judged ends: infra, with the
        # word that came back, so the opener's handling of a rate limit applies and no judged failure is
        # counted against the variant.
        word, raw = seen["unjudged"] or ("not judged", {})
        st.infra = True
        if st.result is None:
            st.result = raw if isinstance(raw, dict) and raw else {"error": word}
        st.errors.append(f"nothing was judged: the first probe of an unsure answer came back {word} "
                         f"({'http 429, ' if word == 'rate_limited' else ''}not processed); nothing was submitted")
    elif out.requests:
        st.submitted = True
        if seen["good"] is not None:
            st.result = seen["good"]
        elif st.result is None and seen["last"] is not None:
            st.result = seen["last"]        # nothing confident was sent and every probe was rejected: a judged failure
    for aid, value in out.banked.items():
        st.answers[aid] = wire_text(value)
        st.unsure.pop(aid, None)
    for key, name in out.learned.items():
        if group is None:
            st.notes.append(f"probed {key}: the judge accepted {name!r} (row 299; recorded in the labels ledger)")
    for key, row in ({} if group is not None else out.open).items():
        if deadline and grade.is_candidate(key):
            st.notes.append(grade.candidate_note(key))
            continue
        st.notes.append(f"probed {key or '(an unsure value that cannot be read)'}: still open for {len(row['ids'])} id(s), "
                        f"tried {row.get('tried') or []}, left {row.get('left') or []}"
                        + (f", not read by the judge {row['invalid']} (row 329)" if row.get("invalid") else ""))
    if out.stopped:
        st.notes.append(f"the probing ended early: {out.stopped}")
    if isinstance(st.result, dict) and st.result.get("result") == "CORRECT":
        freeze(st, cid)
    return out


def judged_on_disk(d: Path, attempt: dict) -> bool:
    """True when the folder holds a judged attempt (it has a result.json or a key.json) and
    `attempt` is not a later variant of it. A dry run leaves the attempt.json of such an attempt
    alone: the status body that would replace it is not the start response the judge answered."""
    if not ((d / "result.json").exists() or (d / "key.json").exists()):
        return False
    try:
        prev = json.loads((d / "attempt.json").read_text()).get("attempt_id")
    except Exception:
        prev = None
    return not (prev and attempt.get("attempt_id") and prev != attempt["attempt_id"])


def confident_rejected_nodeadline(st) -> bool:
    """T1 (adaptable-solver-upgrade-plan; backlog row 483). True when the run's one confident batch (more
    than one id) came back `incorrect` on a timed attempt with NO deadline. Day 23's cumulative Metadata
    Time Trial lost 4 h 55 m here: a 28-id batch with ONE wrong id was rejected whole and tools/run.py had
    no bisection, so it re-sent the identical batch every resume. Then, and only then, the batch is bisected
    exactly as tools/verify.py bisects an untimed base. With a deadline a single submit stands, as before."""
    return (no_deadline(st) and getattr(st, "submitted", False) and len(st.answers) > 1
            and isinstance(st.result, dict) and st.result.get("result") == "incorrect")


BISECT_WINDOW_MAX = 20     # Day 26 (oracle-audit row E): requests inside a window, the first rejected batch included


def confident_rejected_in_window(st, cid: str = "") -> bool:
    """Retro failure #6 (Day 23, ~40 wasted resends). True when the run's one confident batch (more than one id)
    came back `incorrect` on a TIME TRIAL attempt WITH a deadline and the clock still has the submit margin plus the
    grade.MIN_LEFT an `incorrect` needs to be believed. The batch is then bisected inside the window exactly as the
    ladder and verify.py bisect, with the clock as the floor and BISECT_WINDOW_MAX as the request budget.

    A MASTERY is excluded (Day-26 fix round, reconciling R9/R21/R22). A Mastery is all-or-nothing: banking the
    confirmed ids never closes the expiring attempt (it needs every id), the banked ids do not carry to the
    retry's fresh variant, and the isolated wrong id cannot be probed (bisect sets `bisected_in_window`, which
    closes probing). So the in-window bisect gives a Mastery no closing benefit. Its only lasting effect would be
    the single-id rejections it records of the solver's own values, and because the Mastery retry gate (row 39's
    automatic retry, row 105's forced retry) replays the FAILED variant -- the same bytes, so the solver produces
    the same values -- a bisected Mastery failure would always read `replay repeats a rejected value` and so would
    permanently block those documented retry flows. Excluding Masteries is a pure restriction (it only makes the
    bisect run less; it never banks a wrong answer and never loses a clock) that keeps the all-or-nothing Mastery
    retry semantics exactly as before. The Time Trial path (where the bisect banks confirmed ids on the attempt)
    is unchanged."""
    if str(cid).endswith("/mastery"):
        return False
    if no_deadline(st) or not getattr(st, "timed", False) or not (st.clock and st.clock.window is not None):
        return False
    if not (getattr(st, "submitted", False) and len(st.answers) > 1
            and isinstance(st.result, dict) and st.result.get("result") == "incorrect"):
        return False
    try:
        import grade
        left = st.clock.left()
        return left is not None and left >= SUBMIT_MARGIN + grade.MIN_LEFT
    except Exception:
        return False


def bisect_confident(s, cid: str, st, in_window: bool = False):
    """Reuse tools/grade.py's splitter (the one tools/verify.py runs on a base) to bank the right ids of a
    rejected NO-DEADLINE confident batch and name the wrong one(s), inside the attempt. Returns the set of
    isolated BAD ids, which solve_and_submit then hands to the proposer/probe path like any open id.

    Never-wrong: it runs only when the attempt has no deadline (row 346: candidate sweeps are fine), banks
    only the plain values the solver already computed (never a new guess), begins with the split because the
    whole batch's rejection is already known (`rejected_whole`), so no (id, value) goes on the wire twice,
    and every sub-batch's verdict is in verdicts.jsonl before the next. CORRECT still freezes key.json."""
    import grade
    lane = lanes.lane_of(cid)
    attempt_id = (st.attempt or {}).get("attempt_id")
    d = st.dir or attempt_dir(cid)
    answers = dict(st.answers)
    sent = {"n": 1}         # in_window: the rejected whole batch was request 1 of BISECT_WINDOW_MAX
    pace_as_untimed = bool(gm.is_timed(cid) and no_deadline(st))

    def send(values, priority="normal"):
        http, body = None, {}
        if in_window:
            if sent["n"] >= BISECT_WINDOW_MAX:      # the window's request budget: not a verdict, the split ends
                return grade.verdict("budget", raw="window request budget")
            sent["n"] += 1
        try:
            # A regular/practice attempt has no deadline even though its route
            # name ends in /time_trial or /mastery.  Tell GateSession only for
            # these split requests so grade's low tier protects the token from
            # an unpaced bisection storm.  The initial batch and every real
            # window retain their existing timed classification and speed.
            pacing = {"priority": priority, "_untimed_attempt": True} if pace_as_untimed else {}
            resp = s.post(gm.GM, json={"challenge": cid, "answers": dict(values)},
                          timeout=time_limit(st.clock, 2.0), **pacing)
            http, body = resp.status_code, body_of(resp)
            word = body.get("result") if isinstance(body.get("result"), str) else None
            if rate_limited(resp):
                word = "rate_limited"
            elif word not in VERDICTS:
                word = word_of(body) or f"http {http}"
                word = f"http {http}" if word in VERDICTS else word
        except Exception as e:      # a dropped connection, a timeout: not judged, the split ends
            resp, word = None, type(e).__name__
        after = st.clock.left() if st.clock else None
        try:
            if judge is not None:
                judge.record(d, dict(values), word,
                             remaining=body.get("remaining") if word in ("accepted", "CORRECT") else None,
                             left=after, http=http, kind="bank" if len(values) != 1 else "probe", attempt_id=attempt_id)
        except Exception as e:
            st.notes.append(f"verdicts.jsonl was not written ({type(e).__name__}: {e})")
        if resp is not None and (http == 401 or body.get("error") == "unauthorized"):
            gm.check(resp)          # the token was rejected: the run ends as the one submission does
        st.left_after = after
        return grade.verdict(word, body.get("remaining") if word in ("accepted", "CORRECT") else None,
                             {k: v for k, v in body.items() if k not in BULKY})

    b = grade.bank(send, answers, split=(lambda aid: lanes.family_of(lane, aid)) if lane else None,
                   left=(st.clock.left if in_window else None), floor=SUBMIT_MARGIN, rejected_whole=True)
    banked, bad = set(b.banked), set(b.bad)
    where = ("inside the window (Day 26, retro failure #6)" if in_window
             else "on a no-deadline attempt")
    st.notes.append(f"BISECT {cid}: the confident batch of {len(answers)} was rejected whole {where}; "
                    f"split it (row 483): banked {len(banked)}, wrong {sorted(bad)}, {b.requests} request(s)"
                    + (f"; stopped: {b.stopped}" if in_window and getattr(b, "stopped", None) else ""))
    if in_window:
        st.bisected_in_window = True
    if b.last is not None and b.last.result == "CORRECT":
        st.result = dict(b.last.raw) if isinstance(b.last.raw, dict) and b.last.raw else {"result": "CORRECT"}
        freeze(st, cid)
        return set()
    # The right ids are banked; the wrong one(s) stay open for the proposer and the lane's agent. st.answers
    # becomes the accepted subset, so may_probe and propose_open treat the bad and unsure ids as this run's
    # remaining work on the no-deadline attempt.
    st.answers = {aid: answers[aid] for aid in answers if aid in banked}
    if banked:
        st.submitted = True
        st.result = {"result": "accepted", "remaining": len(answers) - len(banked)}
    return bad


def solve_and_submit(a, cid: str, solver, st, t: dict, live: bool, s):
    """Solve the attempt in st.attempt from st.blobs and, on a live run, submit the plain answers."""
    renamed = [(q["id"], aid) for q, aid in zip(st.attempt["questions"], answer_ids_for(st.attempt)) if q["id"] != aid]
    if renamed:
        st.notes.append(f"{len(renamed)} question id(s) differ from answer_ids; answers go under answer_ids by position, "
                        f"e.g. question {renamed[0][0]!r} -> answer id {renamed[0][1]!r}. The question's file name may "
                        f"belong to another variant: trust the delivered files and q['answer_id'].")

    left = st.clock.left() if st.clock else None
    if left is not None and st.clock.resumed:
        st.notes.append(resumed_note(st.attempt, left))
    budget = solve_budget(left, (st.lane or {}).get("solve_cap"), a.solve_timeout)
    if budget is None and live and getattr(st, "timed", False):
        # A timed id's attempt without a deadline (practice, a regular attempt): UNTIMED_SOLVE_CAP. Row 250 held
        # it to the lane's solve cap under start=regular; Day 16 retro: a 78-set Warmups Mastery that needed
        # 3.2 s was cut at 3 s on every rejoin, the same last 10 sets each time, so a rejoin could never close
        # it (+4 min to the day's last mark). The clock lock is per lane (chains=parallel), so a longer solve
        # holds only its own lane, which has nothing else to do while its Mastery is open.
        budget = UNTIMED_SOLVE_CAP
    locked = []
    streamed = getattr(st, "streamed", None)
    solved_from_ns = streamed.started_ns if streamed is not None else time.time_ns()
    p0 = time.perf_counter()     # the gate reuse row's times (Day 21 local speed)
    # The wire response deliberately stays unmodified on disk, while the solver receives the route
    # id that this process already knows.  Offline load_offline() supplies the same transient field.
    solve_attempt = dict(st.attempt)
    if cid:
        solve_attempt["_challenge_id"] = cid
    sets = streamed.complete_sets() if streamed is not None else None
    if sets is None:
        sets = split_sets(solve_attempt, [b or b"" for b in st.blobs], locked, st.notes)
    p1 = time.perf_counter()
    expand_elapsed = p1 - p0
    if locked:
        # No known password opens a delivery: nothing the solver could say from it is worth a
        # submission (on a clock it would only be a guess). The run ends without a verdict.
        why = password_needed(cid, locked, alert=live)
        st.errors.insert(0, why)
        st.infra = st.infra or live
        t["solve"] = t["submit"] = time.perf_counter()
        return
    pool = getattr(st, "pool", None)
    if pool is not None:
        try:
            answers, st.timed_out = pool.solve(solver, sets, budget, st.errors, st.notes)
        except Exception:
            # Never the submit's undoing: the whole attempt again, one set after another.
            st.notes.append("warmups=pool: the pool failed (" + traceback.format_exc().strip().splitlines()[-1][:160]
                            + "); every set solved one by one instead")
            pool.close()
            left = st.clock.left() if st.clock else None
            budget = solve_budget(left, (st.lane or {}).get("solve_cap"), a.solve_timeout)
            answers, st.timed_out = solve_all(solver, sets, budget, st.errors)
    else:
        done, mark = [], len(st.errors)
        solve_started = time.perf_counter()
        if streamed is not None:
            answers, st.timed_out, done, early_expand, solve_elapsed = streamed.finish(
                sets, budget, st.errors, st.notes)
            expand_elapsed += early_expand
        else:
            answers, st.timed_out = solve_all(solver, sets, budget, st.errors, done)
            solve_elapsed = time.perf_counter() - solve_started
        if live and not st.timed_out and len(st.errors) == mark:
            # The Day 21 local speed build: a clean first pass is offered to the Mastery gate as it stands (a pass
            # that was cut, or that a second pass finished, is not).
            st.gate_offer = gate_offer(cid, st.dir, a.solver, st.attempt, st.blobs, answers, solved_from_ns,
                                       expand_elapsed, solve_elapsed, "tools/run.py")
        if st.timed_out and live and second_pass(solver, sets, answers, done, st):
            # Every set the first pass cut was finished by the second (row 256): the run is clean, and its
            # cut lines are NOTEs, not errors.
            kept, noted = fold_cut_lines(st.errors[mark:])
            del st.errors[mark:]
            st.errors += kept
            st.notes += noted
            st.timed_out = False
    st.prior = prior_watch(answers) if live else None    # row 415: the ids the family prior answered plain
    st.answers, st.unsure = split_unsure(answers)   # an unsure answer is never sent
    # Nor is a plain answer of the wrong kind (row 106): certainly wrong, it would sink the batch.
    st.answers, st.misformat = kind_check(st.attempt, st.answers)
    t["solve"] = time.perf_counter()
    prop = proposer_start(a, cid, st, sets) if live and not a.no_submit else None     # the adaptability build

    if live and not a.no_submit:
        confident = bool(st.answers)
        bad_prop = None
        if confident:
            submit(s, cid, st)
            in_window = (not confident_rejected_nodeadline(st)) and confident_rejected_in_window(st, cid)
            if confident_rejected_nodeadline(st) or in_window:
                # T1 (row 483): one wrong id sank a correct no-deadline batch. Bank the right ids and isolate
                # the wrong one(s), then let the proposer offer candidates for them on this no-deadline attempt.
                try:
                    bad = bisect_confident(s, cid, st, in_window=in_window)
                except Exception as e:
                    bad = set()
                    st.notes.append(f"the rejected confident batch was not bisected ({type(e).__name__}: "
                                    f"{str(e)[:160]}); it stands rejected as before")
                if bad and not (isinstance(st.result, dict) and st.result.get("result") == "CORRECT"):
                    bad_prop = proposer_start(a, cid, st, sets, open_ids=list(bad))
        probed = None
        if st.unsure:
            # Row 299: after the confident batch is accepted (or when there is none), a timed attempt with
            # the time for it has its unsure keys probed. Whatever goes wrong here leaves the run where
            # it was before the row: the unsure answers are GUESS lines and nothing more is sent.
            try:
                probed = probe_unsure(s, cid, st)
            except Exception as e:
                st.notes.append(f"the unsure answers were not probed ({type(e).__name__}: {str(e)[:160]}); nothing more "
                                f"was sent for them")
        for p in (prop, bad_prop):      # bad_prop (T1) covers the bisection's isolated wrong id(s)
            if p is not None:
                try:
                    got = propose_open(s, cid, st, p, probed)
                    if got is not None and got.requests and probed is None:
                        probed = got
                except Exception as e:
                    st.notes.append(f"the proposer's candidates were not probed ({type(e).__name__}: {str(e)[:160]})")
                finally:
                    p.kill()
        if confident:
            pass
        elif st.misformat and not st.unsure and not (probed and probed.requests):
            st.errors.append(f"nothing was submitted: every answer the solver gave ({len(st.misformat)}) is of the wrong "
                             f"kind for its question")
        elif probed is not None and probed.requests:
            pass                    # the probes were this run's submissions
        elif st.unsure:
            st.errors.append(f"nothing was submitted: the solver is unsure of every answer it gave ({len(st.unsure)})")
        elif not st.misformat:
            st.errors.append("nothing was submitted: the solver produced no answers")
    t["submit"] = time.perf_counter()
    prior_flush(st)                 # row 415: after the run's last request, outside its timing


PROPOSED_MAX = 12        # the adaptability build: option probes of the proposer's candidates in one run
PROPOSED_PER_ID = 3      # and on one id


def no_deadline(st) -> bool:
    """A timed id's attempt in hand that has NO deadline (a regular attempt under start=regular, practice)."""
    return bool(getattr(st, "timed", False)) and not (st.clock and st.clock.window is not None) \
        and not (st.attempt or {}).get("deadline")


def proposer_start(a, cid: str, st, sets, open_ids=None):
    """The adaptability build: once the solver is back, on a timed attempt with NO deadline only, tools/propose.py
    (the enumerator) for the ids the solver left None, unsure or held, a process of its own beside the submit. With
    a deadline it never starts and nothing is computed. None when off or nothing is open.

    `open_ids` names the ids to enumerate; without it, the ids the solver left open (None, held). T1 (row 483)
    passes the wrong id(s) a no-deadline bisection isolated, so the proposer offers candidates for them too."""
    try:
        if not no_deadline(st) or not gm.is_timed(cid) or st.dir is None or getattr(st, "no_unsure", ""):
            return None
        import proposer_wire as pw
        lane = lanes.lane_of(cid)
        if not pw.prefix_of(lane) or pw.off():
            return None
        order = answer_ids_for(st.attempt)
        if open_ids is None:
            open_ids = [aid for aid in order if aid not in st.answers or aid in (st.misformat or {})]
        if not open_ids:
            return None
        shipped = {}
        labels = sys.modules.get("labels")
        for aid in open_ids:
            u = labels.parse(st.unsure[aid]) if labels is not None and aid in st.unsure else None
            shipped[aid] = ({"kind": "unsure", "key": u.key, "options": [list(o) for o in u.options]} if u is not None
                            else {"kind": "none"})
        ids = Path(st.dir) / ".proposer_ids.json"
        if not pw.write_ids(ids, open_ids, shipped, {}, lane):
            return None
        multi = len(sets) > 1
        # forked on a thread of its own a moment later: never between the solver and the submit
        proc = pw.Later(delay=0.05, d=st.dir, ids_path=ids, deadline_s=pw.DEADLINE_MASTERY if multi else pw.DEADLINE_BASE,
                        sets=multi).start()
        proc.lane, proc.open_ids = lane, open_ids
        return proc
    except Exception as e:
        st.notes.append(f"the proposer was not started ({type(e).__name__}: {e})")
        return None


def propose_open(s, cid: str, st, prop, probed):
    """Probe the proposer's candidates for the ids still open, after the solver's own unsure keys (probe_unsure),
    under may_probe's conditions: the confident batch accepted (or none), nothing held, the run clean, no deadline.
    PROPOSED_MAX option probes a run, PROPOSED_PER_ID an id, probe_gap apart, every request in verdicts.jsonl first."""
    if st.timed_out or st.infra or getattr(st, "misformat", None) or not no_deadline(st) or getattr(st, "no_unsure", ""):
        return None
    if st.answers and not (st.submitted and isinstance(st.result, dict) and st.result.get("result") in ("accepted", "CORRECT")):
        return None
    if isinstance(st.result, dict) and st.result.get("result") == "CORRECT":
        return None
    import proposer_wire as pw
    import grade
    exhausted = set()
    if probed is not None:
        for row in probed.open.values():
            if not row.get("left"):
                exhausted.update(row.get("ids") or [])
    targets = [aid for aid in prop.open_ids if aid not in st.answers and (aid not in st.unsure or aid in exhausted)]
    if not targets:
        return None
    started = prop.get()
    props = started.collect() if started is not None else {}
    rejected = set()
    try:
        rejected = set(judge.ledger(st.dir, attempt_id=(st.attempt or {}).get("attempt_id"))[1]) if judge is not None else set()
    except Exception:
        rejected = set()
    group = pw.unsure_for(grade.labels, props, targets, prop.lane, (st.attempt or {}).get("attempt_id"),
                          rejected=rejected, per_id=PROPOSED_PER_ID)
    if not group:
        st.notes.append(f"proposer: no candidate for the {len(targets)} open id(s)")
        return None
    wired = {aid: grade.labels.unsure(u.key, u.options) for aid, u in group.items()}
    out = probe_unsure(s, cid, st, group=wired, max_total=PROPOSED_MAX, max_per_key=PROPOSED_PER_ID)
    if out is None:
        return None
    for aid, u in group.items():
        if aid in out.banked:
            value = out.banked[aid]
            rank = next((i + 1 for i, (n, v) in enumerate(u.options) if v == value), "?")
            name = next((n for n, v in u.options if v == value), "?")
            st.notes.append(f"PROPOSED-ACCEPTED {aid} {name} rank {rank} ({pw.provenance(props, aid, value)[:200]})")
        else:
            row = out.open.get(u.key) or {}
            st.notes.append(f"PROPOSED-OPEN {aid} tried {len(row.get('tried') or [])}")
    return out


def password_needed(cid: str, locked: list, alert: bool = True) -> str:
    """The reason line for an archive no known password opens: 'archive password needed: <file>
    (...)'. With alert, tools/password.py raises the one critical alert ARCHIVE PASSWORD NEEDED and
    writes <challenges>/_logs/password_needed.json first."""
    file = Path(str(locked[0])).name
    reason = f"archive password needed: {file}"
    if alert:
        try:
            import password
            reason = password.needed(lanes.lane_of(cid) or cid, cid, file)
        except Exception:
            pass
    more = f"; also {', '.join(Path(str(n)).name for n in locked[1:4])}" if len(locked) > 1 else ""
    return (f"{reason} ({len(pw.candidates())} known password(s) tried{more}); "
            f"add it with tools/password.py add '<value>' and run the lane again")


WIRE_HOLD_ENV = "CTF_WIRE_HOLD"     # 'off' disables the wave17 early regular-attempt save; anything else leaves it on


def wire_hold_on() -> bool:
    """The wave17 wire-hold fix is on unless CTF_WIRE_HOLD is set to 'off'."""
    return ctf_env.get(WIRE_HOLD_ENV, "").strip().lower() != "off"


def save_early_regular(a, cid: str, st, live: bool):
    """Wave17 wire-hold fix. Write a REGULAR (deadline null) timed attempt's attempt.json now, right
    after the start response and BEFORE the download, so a sibling lane's untimed bank is not held
    behind this clock while it downloads: judge.holder_regular reads the holder's attempt.json to
    prove a clock has no deadline (row 400), and until the runner has saved it the sibling bank is
    held fail-safe. The download can take seconds (a 33 MB Binary delivery), which is exactly the span
    row 400 could not exempt (Day 24: Script's base bank held 2.888 s behind Mobile/Metadata's clocks).

    Strict/fail-safe:
    - A genuine timed clock (deadline set) writes NOTHING here, so it is held as before (byte-identical).
    - Only fires inside a held clock on a live run (not a base, dry run, --no-save or offline replay),
      so the gate's regression (`--offline`/`--replay`) never reaches it and no saved answer moves.
    - The authoritative save after the download rewrites the SAME attempt.json (with the download's
      filenames and the deliveries), so the final on-disk state is byte-identical to today.
    - Any error is swallowed: the normal save after the download still runs.
    - CTF_WIRE_HOLD=off restores exactly today's behavior (no early save)."""
    if not (live and getattr(st, "timed", False) and st.clock and not a.dry_run and not a.no_save and not a.offline):
        return
    if (st.attempt or {}).get("deadline") is not None:
        return                               # a genuine timed clock: holder_regular holds it as before
    if not wire_hold_on():
        return
    try:
        save_attempt(cid, st.attempt, [])    # attempt.json only (no blobs yet); history move, if any, happens here
        st.notes.append("wire-hold: the regular attempt (deadline null) was saved before the download, "
                        "so a sibling lane's untimed bank is not held behind this clock (row 400, wave17)")
    except Exception:
        pass                                 # fail-safe: the authoritative save after the download still runs


def attempt_in_hand(a, cid: str, solver, st, t: dict, live: bool, s):
    """st.attempt is a start or status response: download its deliveries, save it, solve, submit."""
    normalize(st.attempt)
    t["start"] = time.perf_counter()
    if not st.attempt.get("artifacts") or not st.attempt.get("questions"):
        # Nothing to solve. Already CORRECT is no failure; anything else on a live run is the
        # Game Master's answer to the start, not the solver's doing.
        st.infra = st.infra or (live and st.attempt.get("result") != "CORRECT")
        return
    save_early_regular(a, cid, st, live)     # wave17: a regular attempt's attempt.json before the download
    stream = None
    stream_left = st.clock.left() if st.clock else None
    stream_cap = solve_budget(stream_left, (st.lane or {}).get("solve_cap"), a.solve_timeout)
    if stream_cap is None and live and getattr(st, "timed", False):
        stream_cap = UNTIMED_SOLVE_CAP
    if stream_solve_eligible(cid, st.attempt, st, solver, stream_cap):
        solve_attempt = dict(st.attempt)
        if cid:
            solve_attempt["_challenge_id"] = cid
        stream = StreamSolve(solver, solve_attempt, len(st.attempt["artifacts"]), stream_cap)
    try:
        st.blobs, failed = fetch_each(s, cid, st.attempt["artifacts"], st.clock,
                                      on_ready=stream.ready if stream is not None else None)
    except BaseException:
        if stream is not None:
            stream.close(wait_cap=0.0)
        raise
    st.notes += download_notes()
    st.errors += failed
    st.infra = st.infra or (live and bool(failed))
    t["download"] = time.perf_counter()
    if not a.no_save:
        # On disk before the solver runs: an attempt that fails or expires still leaves its variant behind.
        try:
            if a.dry_run and judged_on_disk(attempt_dir(cid), st.attempt):
                st.dir = attempt_dir(cid)
            else:
                st.dir, st.saved_attempt = save_attempt(cid, st.attempt, st.blobs), True
        except Exception:
            st.errors.append("could not save the attempt\n" + traceback.format_exc())
    if stream is not None:
        # The sha-checked download barrier and authoritative save stay in their original order.  Only now wait for
        # any solver tail; this wait is charged to solve time, and submit still cannot precede it.
        if not stream.close():
            st.errors.append(stream.aborted or "solve-on-download worker did not stop within its solve cap")
            st.notes.append("solve-on-download fail-stop: no serial fallback and no answer submission were attempted")
            st.infra = st.infra or live
            t["solve"] = t["submit"] = time.perf_counter()
            return
        st.streamed = stream
    solve_and_submit(a, cid, solver, st, t, live, s)


def play(a, cid: str, solver, st, t: dict, live: bool):
    if a.offline:
        st.attempt, st.blobs, st.dir = load_offline(cid, a.offline)
        t["warm"] = t["start"] = t["download"] = time.perf_counter()
        return solve_and_submit(a, cid, solver, st, t, live, None)

    s = gm.session()
    if st.timed and not preread(cid):
        return play_unread(a, cid, solver, st, t, s)     # package PR1: the start is the first request
    if st.timed:
        # No read into a rate-limit pause that is known to be in force: it would only be answered 429.
        waited = wait_out_pause(cid)
        if waited:
            st.notes.append(f"a rate-limit pause was in force: waited {waited:.1f}s for its end before the status read")
            t["t0"] = time.perf_counter()   # the timing line measures the run, not the pause
    # Warm the connection and read the public contract; this never starts a clock.
    pre = gm.check(patient(lambda: s.get(gm.GM, params={"op": "status", "challenge": cid}, timeout=30),
                           st.notes, "status", waits=WARMUP_WAITS))
    t["warm"] = time.perf_counter()
    if a.dry_run or rate_limited(pre):
        st.attempt = body_of(pre)
        if not a.dry_run:
            # Do not start a clock into an active rate limit: the downloads would fail inside the window.
            st.infra = True
            st.notes.append("still rate limited after waiting; the attempt was NOT started")
        return attempt_in_hand(a, cid, solver, st, t, live, s)

    guard, refusals = contextlib.nullcontext(), ()
    if st.timed:
        body = body_of(pre)
        remember(body)          # the 409 start_required body's guidance, for note_contract() after the run
        st.status_body = body   # and for the start: the hint of gm.post_start() (row 199)
        if body.get("questions"):
            try:
                st.contract = contract_problems(solver, cid, body)
            except Exception as e:   # a check that cannot be made is not a pass
                st.contract = [f"the contract check failed ({type(e).__name__}: {e})"]
            if st.contract:
                return   # no start: the clock would run on questions the solver does not cover
        else:
            st.notes.append("the status read carried no questions, so the question contract was not checked")
        guard, refusals = judge.clock(cid, clock_cost(body)), (judge.NoTicket, judge.ClockBusy)
    try:
        # One clock at a time: a timed id is started, downloaded, solved and submitted inside
        # judge.clock(), which spends the ticket and waits for a rate-limit pause to end.
        with guard as ticket:
            st.ticket = ticket if isinstance(ticket, dict) else None
            if st.timed:
                preopen(s, cid, body_of(pre), st.notes)
                start_warm(solver, st)          # row 412: the solver's warm() overlaps the start in flight
            st.attempt, st.clock = start_attempt(s, cid, a.retry, st)
            proposer_gate_check(cid, st)        # the proposer gate: a timed clock after all sends nothing unsure
            attempt_in_hand(a, cid, solver, st, t, live, s)
    except refusals as e:
        st.refused = ("no_ticket" if isinstance(e, judge.NoTicket) else "clock_busy", str(e))


def play_unread(a, cid: str, solver, st, t: dict, s):
    """A live timed id with no op=status read before its start (preread=none, package PR1).

    What the read was for is done so. No clock into a pause: judge.clock() waits out a rate-limit
    pause the governor knows, as it always has, and a start that is itself answered 429 (after
    patient()'s re-sends) was not processed, so no clock runs: the run ends `rate_limited` with
    infra=true, which tools/open_day.py counts as no start and tries again after the pause. The
    start body: start_order(), from the id's list row. The contract check: late_contract(), on the
    start response's questions, before the first download; it changes nothing the run does. The
    contract watch: start_attempt() keeps the start response for note_contract().

    One thing the read did is not done another way: it opened the connection. Here the start is this
    process's first request, so that request's set-up (DNS, TCP, TLS) rides on the start, and Clock,
    which counts the window from the moment the start request leaves, believes that much less of
    it is left. The read took 0.22 to 0.41 s in all on Days 9 to 11, which moves no solve budget;
    with the VPN up a first request took 4 to 5.6 s, which a 6 s window does not survive: no clock
    with the VPN up unless "preread": "status" is in the file (docs/ops/runbook.md, section 11)."""
    t["warm"] = time.perf_counter()
    try:
        with judge.clock(cid, cost_unread(cid)) as ticket:
            st.ticket = ticket if isinstance(ticket, dict) else None
            start_warm(solver, st)              # row 412: the solver's warm() overlaps the start in flight
            st.attempt, st.clock = start_attempt(s, cid, a.retry, st)
            proposer_gate_check(cid, st)        # the proposer gate: a timed clock after all sends nothing unsure
            refused = start_limited_note(st.attempt, st.start_http)
            if refused:
                st.notes.append(refused)
            st.contract_late = late_contract(solver, cid, st.attempt)
            attempt_in_hand(a, cid, solver, st, t, True, s)
    except (judge.NoTicket, judge.ClockBusy) as e:
        st.refused = ("no_ticket" if isinstance(e, judge.NoTicket) else "clock_busy", str(e))


def start_limited_note(attempt, http=None):
    """preread=none: the NOTE of a start that was answered with a rate limit (HTTP 429, or a body
    that says rate_limited) and returned no attempt, or None. It carries the words tools/open_day.py
    reads for a run that posted no start ('the attempt was NOT started'), as the note of a refused
    warm-up read does."""
    body = attempt if isinstance(attempt, dict) else {}
    if body.get("questions") or not (http == 429 or body.get("error") == "rate_limited"):
        return None
    return ("the start was answered with a rate limit, and so was every re-send; the attempt was NOT started "
            "(a rate-limited request is not processed)")


# ---- W-5 (Day 19 build): the start of a live target's timed mode, and nothing else -----------------

LIVE_START_FILE = "start.json"          # the start body, as tools/verify.py's web B1 saves a live base's (LIVE_FILE)
LIVE_MARK_FILE = "live_start.json"      # what says this start.json is a forced live start of ours (verify.py reads it)
LIVE_START_SOURCE = "tools/run.py --start-only"
LIVE_VARIANT_FILES = (LIVE_START_FILE, LIVE_MARK_FILE, "verdicts.jsonl", "result.json", "gaps.json")
LIVE_STARTED = "started_live"           # the RUN line's word for a start that returned an attempt
LIVE_FOREIGN = "teammate_attempt"       # the RUN line's word for a start that resumed an attempt not ours
LIVE_FOREIGN_FILE = "start.teammate.json"   # such a body is kept for the player, never as start.json
LIVE_SOLVED = "already_solved"          # the RUN line's word for a start answered CORRECT or already_solved
RESUMED_LINE = "start resumed an attempt that was already running"   # the normal runner's NOTE: a TEAMMATE_SIGNS line
# Row 368: the plain start AND the plain retry after it (the Day 19 Gap B fix) were both refused in a way that
# means the route will not take a fresh plain regular start RIGHT NOW: the target is still preparing (200 with a
# provisioning status), a dual-pool route is not set up for a plain start/retry yet (503 mode_configuration_invalid),
# or it wants a start first (409 start_required). This is NOT a timed-only route refusing a plain start
# (timed_intent_required, a bare 400: "the start is the player's", which keeps its own word) and NOT a start we
# just made: nothing is counted and nothing is saved. The forced-start path (tools/open_day.py) reads this one
# RUN word, caps the forced re-issues per mode, and hands the lane to its agent instead of re-issuing on a timer.
LIVE_NOT_STARTABLE = "not_startable"    # the RUN line's word for a route that is not plain-startable right now
NOT_STARTABLE_WORDS = frozenset({"mode_configuration_invalid", "preparing", "start_required"})
PROVISIONING_STATES = frozenset({"preparing", "provisioning", "pending"})


def not_startable(word: str, status: int, body) -> bool:
    """Row 368: True when a refused plain start/retry means the route is not plain-startable right now (above),
    told from the error word or the http status only, never a new request. A timed-only route's refusal of a
    plain start (timed_intent_required, a bare 400) and a 409 unlock refusal (timed_mode_locked) are NOT this."""
    if word in NOT_STARTABLE_WORDS:
        return True
    if status == 503:          # the observed mode_configuration_invalid (Day 19)
        return True
    if status == 200 and isinstance(body, dict):
        state = str(body.get("status") or body.get("state") or "").lower()
        return state in PROVISIONING_STATES
    return False


def live_known_ids(d: Path) -> set:
    """Attempt ids of our own live starts in the timed id's folder: start.json and live_start.json, and the
    same two files of every variant moved to history/. Files only."""
    ids = set()
    folders = [d] + (sorted((d / "history").glob("*")) if (d / "history").is_dir() else [])
    for folder in folders:
        for name in (LIVE_START_FILE, LIVE_MARK_FILE):
            with contextlib.suppress(Exception):
                aid = json.loads((folder / name).read_text()).get("attempt_id")
                if isinstance(aid, str) and aid:
                    ids.add(aid)
    return ids


def live_resumed(attempt: dict, resp):
    """Whether a start's answer is an attempt that was already running, told from the attempt's started_at
    against the server's Date header MINUS how long this very request took (resp.elapsed). The server sets
    started_at for a freshly created attempt sometime between receiving our POST and sending the reply, so a
    fresh attempt's started_at trails the Date by up to the request's own round trip; a slow answer (Day 19:
    the web starts took 3-11 s) must not read as "already running". An attempt a teammate (or our own earlier
    start) opened trails the Date by that round trip PLUS RESUMED_AFTER or more.
    (True|False, seconds late) or (None, why) when the answer does not say."""
    try:
        started = _ts(attempt["started_at"])
    except Exception:
        return None, "the start answer has no readable started_at"
    try:
        server_now = parsedate_to_datetime(resp.headers["Date"])
    except Exception:
        return None, "the start answer has no readable Date header"
    try:
        late = (server_now - started).total_seconds()
    except Exception:
        return None, "started_at and the Date header could not be compared"
    dur = 0.0
    with contextlib.suppress(Exception):
        dur = max(0.0, resp.elapsed.total_seconds())
    return (late - dur) >= RESUMED_AFTER, late


def _has_download(body) -> bool:
    return isinstance(body, dict) and bool(body.get("artifacts") or body.get("downloads") or body.get("download"))


def save_live_start(cid: str, body: dict) -> Path:
    """Write the start body as start.json and the marker live_start.json in the timed id's folder.
    Never attempt.json: that file names a playable variant to every tool (the gates replay it). A
    start.json of another attempt moves to history/<its id>/ first, with its verdicts, as a retry's
    variant does."""
    d = attempt_dir(cid)
    d.mkdir(parents=True, exist_ok=True)
    prev = None
    with contextlib.suppress(Exception):
        prev = json.loads((d / LIVE_START_FILE).read_text()).get("attempt_id")
    if prev and body.get("attempt_id") and prev != body["attempt_id"]:
        hist = d / "history" / history_name(prev)
        hist.mkdir(parents=True, exist_ok=True)
        for name in LIVE_VARIANT_FILES:
            if (d / name).exists():
                to, n = hist / name, 1
                while to.exists():
                    to, n = hist / f"{name}.{n}", n + 1
                shutil.move(str(d / name), str(to))
    for name, data in ((LIVE_START_FILE, body),
                       (LIVE_MARK_FILE, {"source": LIVE_START_SOURCE, "challenge": cid, "attempt_id": body.get("attempt_id"),
                                         "saved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                         "deadline": body.get("deadline"), "run_for_time": body.get("run_for_time"),
                                         "hall_of_fame_eligible": body.get("hall_of_fame_eligible"),
                                         "has_delivery": _has_download(body)})):
        tmp = d / f".{name}.{os.getpid()}.tmp"
        tmp.write_text(json.dumps(data, indent=2))
        os.replace(tmp, d / name)
    return d


def start_only(cid: str) -> int:
    """--start-only (W-5, the player's yes of 2026-10-18; only tools/open_day.py passes it, on its forced
    path for a lane with no delivery and a live target). Inside judge.clock(), which spends the forced
    ticket and holds the clock lock (the lane's own under chains=parallel, row 358), ONE start is posted:
    the plain body {"challenge": <id>}, never run_for_time, so that on a route whose list row says
    run_for_time_supported true the attempt is a regular one with no deadline. No ladder, no fall-back to
    the flag body: a refused plain start is said and nothing else is sent. The answer is saved as
    start.json (+ live_start.json) and the run ends at once: nothing is downloaded, solved or submitted,
    and the clock lock is let go within the second. The answers are an agent's, by hand, through
    tools/verify.py <id> --answers FILE. Refused with no request unless CTF_RFT_SUPPORTED=1 (the
    opener says so only for an id whose list row carries the flag)."""
    notes = []

    def end(word, infra=False, code=0, missing=0):
        for line in notes:
            print(f"NOTE {line}")
        print(run_line(word, missing=missing, infra=infra))
        return code

    if ctf_env.get(RFT_SUPPORTED) != "1":
        print(f"live start refused: the list row of {cid} is not known to say run_for_time_supported true "
              f"({RFT_SUPPORTED}={ctf_env.get(RFT_SUPPORTED, 'unset')}); a plain start there may be the timed clock "
              f"itself, which is the player's. Nothing was requested")
        return end("refused", code=3)
    try:
        with judge.clock(cid, 1):
            s = gm.session()
            body = gm.start_body(cid, "start", run_for_time=False)
            resp = gm.check(patient(lambda: s.post(gm.GM, json=body, timeout=30), notes, "start"))
            attempt = body_of(resp)
            status = resp.status_code
            if rate_limited(resp):
                notes.append("the start was answered with a rate limit, and so was every re-send; the attempt was NOT "
                             "started (a rate-limited request is not processed)")
                return end("rate_limited", infra=True)
            if (not (isinstance(attempt, dict) and isinstance(attempt.get("attempt_id"), str) and attempt["attempt_id"])
                    and (word_of(attempt) or f"http_{status}") not in ("CORRECT", "already_solved", "preparing")):
                # Day 19: a Mastery's plain start answered 503 mode_configuration_invalid. op=openapi: "new
                # dual-pool routes use start or retry without run_for_time for regular play", so the plain
                # retry (still no run_for_time: never a timed clock) is sent once before giving up.
                refused = word_of(attempt) or f"http_{status}"
                rbody = gm.start_body(cid, "retry", run_for_time=False)
                rresp = gm.check(patient(lambda: s.post(gm.GM, json=rbody, timeout=30), notes, "retry"))
                notes.append(f"the plain start was refused (http {status}: {refused}); sent the plain retry "
                             f"(no run_for_time): http {rresp.status_code}: {word_of(body_of(rresp)) or '-'}")
                if not rate_limited(rresp):
                    resp, attempt, status = rresp, body_of(rresp), rresp.status_code
            if not (isinstance(attempt, dict) and isinstance(attempt.get("attempt_id"), str) and attempt["attempt_id"]
                    and isinstance(attempt.get("questions"), list) and attempt["questions"]):
                word = word_of(attempt) or f"http_{status}"
                if word in ("CORRECT", "already_solved"):
                    # The opener had just found the mode not CORRECT (the list call and our files): someone
                    # else closed it. `already_solved` is a TEAMMATE_SIGNS word; the line keeps it.
                    notes.append(f"the start answered {word}: the mode is already_solved, and not by us (the opener "
                                 f"found it open); a teammate's hand? nothing was started")
                    return end(LIVE_SOLVED)
                if not_startable(word, status, attempt):
                    # Row 368: the plain start and the plain retry both say the route is not plain-startable right
                    # now (the target is preparing, or a dual-pool route is not set up for a plain start/retry yet).
                    # The start WITH run_for_time is still not sent here (it would be a timed clock, the player's).
                    # tools/open_day.py reads this RUN word, caps the forced re-issues and hands the lane to its agent.
                    notes.append(f"the route is not plain-startable right now (http {status}: {word}): the target is "
                                 f"preparing, or this dual-pool route is not set up for a plain start/retry yet. The "
                                 f"start WITH run_for_time is not sent here (it would be a timed clock, the player's). "
                                 f"Nothing was started: the forced-start path caps the re-issues and hands the lane to "
                                 f"its agent (row 368). " + json.dumps({k: v for k, v in attempt.items() if k not in BULKY})[:200])
                    return end(LIVE_NOT_STARTABLE)
                notes.append(f"the plain start was refused (http {status}: {word}); the attempt was NOT started. The "
                             f"start WITH run_for_time is not sent here: it would be a timed clock, which is the player's. "
                             + json.dumps({k: v for k, v in attempt.items() if k not in BULKY})[:300])
                return end(word)
            resumed, late = live_resumed(attempt, resp)
            if resumed and attempt["attempt_id"] not in live_known_ids(attempt_dir(cid)):
                # The normal runner's Clock says the same line (a TEAMMATE_SIGNS line). The body is kept for the
                # player as start.teammate.json, never as start.json: nothing of ours answers it.
                d = attempt_dir(cid)
                with contextlib.suppress(Exception):
                    d.mkdir(parents=True, exist_ok=True)
                    tmp = d / f".{LIVE_FOREIGN_FILE}.{os.getpid()}.tmp"
                    tmp.write_text(json.dumps(attempt, indent=2))
                    os.replace(tmp, d / LIVE_FOREIGN_FILE)
                took = ""
                with contextlib.suppress(Exception):
                    took = f", this start took {resp.elapsed.total_seconds():.1f} s"
                notes.append(f"{RESUMED_LINE} (attempt {str(attempt['attempt_id'])[:8]}, started {late:.1f} s before "
                             f"the server's Date{took}, deadline {attempt.get('deadline')}): more than the request's own "
                             f"round trip, not a start of ours, and no attempt of ours on disk has that id; a teammate's? "
                             f"It is NOT saved as start.json (kept as {d / LIVE_FOREIGN_FILE}); who answers it is the "
                             f"player's question")
                return end(LIVE_FOREIGN)
            if resumed:
                notes.append(f"{RESUMED_LINE.replace('start resumed', 'start rejoined')}: attempt "
                             f"{str(attempt['attempt_id'])[:8]} is our own earlier live start (on disk)")
            elif resumed is None:
                notes.append(f"whether the start resumed a running attempt could not be told: {late}")
            save_live_start(cid, attempt)
    except (judge.NoTicket, judge.ClockBusy) as e:
        print(f"no ticket: {e}" if isinstance(e, judge.NoTicket) else f"clock busy: {e}")
        return end("no_ticket" if isinstance(e, judge.NoTicket) else "clock_busy", code=3)
    deadline = attempt.get("deadline")
    left = None
    with contextlib.suppress(Exception):
        left = (_ts(deadline) - datetime.now(timezone.utc)).total_seconds() if deadline else None
    print(f"LIVE START {cid}: attempt {str(attempt['attempt_id'])[:8]}, "
          + (f"DEADLINE {deadline} ({left:.0f} s left)" if left is not None else
             f"deadline {deadline}" if deadline else "no deadline")
          + f", run_for_time={attempt.get('run_for_time')}, hall_of_fame_eligible={attempt.get('hall_of_fame_eligible')}, "
          f"{len(attempt['questions'])} question(s); saved as {attempt_dir(cid) / LIVE_START_FILE}. Nothing is downloaded, "
          f"solved or submitted here: tools/verify.py {cid} --answers FILE")
    if _has_download(attempt):
        notes.append("the attempt carries a delivery; this path downloads nothing (tools/gm.py artifact reads it)")
    return end(LIVE_STARTED, missing=len(attempt["questions"]))


def run_line(result: str, remaining="-", unsure: int = 0, missing: int = 0, infra: bool = False) -> str:
    """The machine-readable last line of every run (pinned in docs/ops/contracts.md)."""
    return f"RUN result={result} remaining={remaining} unsure={unsure} missing={missing} infra={'true' if infra else 'false'}"


def remaining_of(result) -> str:
    """The judge's count of answer ids still open, for the RUN line: a number, or '-' when the
    response gave none. CORRECT leaves nothing open."""
    if not isinstance(result, dict):
        return "-"
    rem = result.get("remaining")
    if isinstance(rem, (list, dict)):
        return str(len(rem))
    if isinstance(rem, int) and not isinstance(rem, bool):
        return str(rem)
    return "0" if result.get("result") == "CORRECT" else "-"


def report(a, cid: str, st, t: dict, live: bool) -> int:
    """Print the summary and write the outcome files. Returns the exit status."""
    att = st.attempt or {}
    has_attempt = bool(att.get("questions") and att.get("artifacts"))
    last = t["t0"]
    for k in ("warm", "start", "download", "solve", "submit"):
        last = t.setdefault(k, last)
    timed = bool(st.clock and st.clock.window is not None)

    result = st.result
    if has_attempt and live and not a.no_submit and result is None:
        # No Game Master response to record: leave a marker so the failure is visible on disk.
        why = (st.errors[0].splitlines()[0] if st.errors else "not submitted")
        result = {"result": "not_submitted", "error": why, "source": "tools/run.py", "attempt_id": att.get("attempt_id")}
    correct = bool(result and result.get("result") == "CORRECT")
    if live:
        with contextlib.suppress(Exception):
            # Row 108: result.json says which pool was played, and a regular attempt that only the
            # result reveals (the start body carried no pool field) still gets its NOTE.
            result = pool_record(cid, result, att)
            played = getattr(st, "practice_played", None)
            if played and isinstance(result, dict):
                result = {**result, "practice": True}
                result.pop("regular_attempt", None)
            late = None if played else regular_note(cid, att, result)
            if late and not any(str(n).startswith(REGULAR_NOTE) for n in st.notes):
                st.notes.append(late)

    written = []
    if has_attempt and st.dir is not None and not a.no_save:
        try:
            written = save_outcome(st.dir, st.answers, result, st.submitted, st.unsure if live else None)
        except Exception:
            st.errors.append("could not save the outcome\n" + traceback.format_exc())

    if not a.quiet:
        for k, v in st.answers.items():
            print(f"  {k} = {v}")
    for k, v in st.unsure.items():
        print(guess_line(k, v))
    misformat = getattr(st, "misformat", None) or {}
    for k, why in list(misformat.items())[:40]:
        print(f"FORMAT {k}: {why}")
    if misformat and has_attempt:
        # Row 144: the kind check is a veto. When the held answers are all that keeps the batch from
        # being complete, that is said in one line the opener carries into the lane's reason.
        open_ids = [aid for aid in answer_ids_for(att) if aid not in st.answers]
        if all(aid in misformat for aid in open_ids):
            st.notes.append(f"{HELD_ONLY}: {len(misformat)} answer(s) held by the kind check are all that is missing "
                            f"({', '.join(list(misformat)[:3])}); check them offline with tools/kinds.py <attempt dir> "
                            f"answers.dry-run.json")
    for n in st.notes:
        print("NOTE", n)
    for e in st.errors:
        print("ERROR", e)
    for line in late_contract_lines(cid, getattr(st, "contract_late", None) or []):
        print(line)     # preread=none: the check ran on the start response; the run went on and ends as usual below

    if st.contract or st.refused:
        # No clock was started. Exit 3 tells the caller that nothing was played and why.
        if st.contract:
            for p in st.contract[:40]:
                print("CONTRACT", p)
            word = "contract_mismatch"
            print(f"contract mismatch: {len(st.contract)} problem(s) with the questions of {cid}; the clock was NOT started")
        else:
            word, why = st.refused
            print(f"no ticket: run tools/preflight.py --gate {cid}" if word == "no_ticket"
                  else f"clock busy: {why}; nothing was started. Run tools/preflight.py --gate {cid} again")
        print("timing: warm={:.2f}s start={:.2f}s".format(t["warm"] - t["t0"], t["start"] - t["warm"]))
        print(run_line(word))
        return 3

    if not has_attempt:
        if att:
            print(json.dumps({k: v for k, v in att.items() if k != "guidance"}, indent=2)[:3000])
        hint = "see the response above"
        err = str(att.get("error") or "")
        if err == "rate_limited":
            hint = "the Game Master is rate limiting this token and nothing was started; wait a little and run again"
        elif a.dry_run and err == "start_required":
            hint = "this challenge has not been started; a dry run never starts it"
        elif "expire" in err.lower():
            hint = "the attempt has expired: rerun with --retry to move to the next variant"
        elif live and not a.retry and att:
            hint = "if this means the last attempt expired, rerun with --retry to move to the next variant"
        print(f"no attempt to solve: {hint}")
        print("timing: warm={:.2f}s start={:.2f}s".format(t["warm"] - t["t0"], t["start"] - t["warm"]))
        print(run_line(st.word or word_of(att) or "no_attempt", infra=bool(live and st.infra)))
        return 1

    problems = format_problems(att, st.answers, st.unsure, misformat)
    for p in problems[:40]:
        print("CHECK", p)
    got = sum(1 for b in st.blobs if b)
    print(f"mode={att.get('mode')} attempt={att.get('attempt_id')} deliveries={got}"
          f"{'' if got == len(st.blobs) else f' of {len(st.blobs)}'} "
          f"questions={len(att['questions'])} answered={len(st.answers)} format_problems={len(problems)}")
    tail = ""
    if timed and live:
        after = st.left_after if st.left_after is not None else st.clock.left()
        tail = f" | {after:+.2f}s to deadline after submit" if st.submitted else f" | {after:+.2f}s to deadline now, not submitted"
        tail += f" (window {st.clock.window:g}s)"
    print("timing: warm={:.2f}s start={:.2f}s download={:.2f}s solve={:.2f}s submit={:.2f}s | start->submit={:.2f}s{}".format(
        t["warm"] - t["t0"], t["start"] - t["warm"], t["download"] - t["start"], t["solve"] - t["download"],
        t["submit"] - t["solve"], t["submit"] - t["warm"], tail))
    if a.no_save:
        print("--no-save: nothing was written")
    elif st.dir is not None:
        print(f"saved: {st.dir}")
        if written:
            print(f"files: {', '.join((['attempt.json', 'artifact/'] if st.saved_attempt else []) + written)}")
    if st.result is not None:
        print("RESULT:", brief(st.result))
    elif a.dry_run:
        print("dry run: nothing started, nothing submitted")
    elif a.offline:
        print("offline replay: no Game Master call was made")
    elif a.no_submit:
        print("--no-submit: the attempt was started but nothing was submitted")

    if live and timed and not correct and not a.no_submit:
        print(f"NEXT: this variant is on disk. Fix the solver against it with `tools/run.py {cid} {a.solver} --offline`, "
              f"then rerun with --retry (a new variant) once the deadline has passed.")

    word = st.word or word_of(result) or ("dry_run" if a.dry_run else "offline" if a.offline else "no_submit" if a.no_submit
                                          else "not_submitted")
    answered = set(st.answers) | set(st.unsure)
    missing = sum(1 for aid in answer_ids_for(att) if aid not in answered)
    # infra: the run ended without a verdict, and not because of what the solver returned.
    infra = bool(live and not a.no_submit and st.infra and word not in VERDICTS)
    print(run_line(word, remaining_of(result), len(st.unsure), missing, infra))
    return 1 if st.fatal else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("challenge")
    ap.add_argument("solver")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--offline", nargs="?", const=True, default=None, metavar="DIR")
    ap.add_argument("--retry", action="store_true")
    ap.add_argument("--practice", action="store_true",
                    help="a timed id with no fresh variant left: post op=practice (the last artifact, no timer) "
                         "instead of a retry; needs a ticket like any timed start")
    ap.add_argument("--rejoin", action="store_true",
                    help="a timed id whose attempt on disk is ours and still open (a regular attempt, start=regular): "
                         "no retry is posted, the plain start returns the attempt; needs a ticket like any timed start")
    ap.add_argument("--start-only", action="store_true",
                    help="W-5: a live target's timed id (no delivery): post the plain start inside the clock, save it as "
                         "start.json and end; nothing is downloaded, solved or submitted. Only tools/open_day.py passes it, "
                         "on its forced path, and the solver argument is then '-'")
    ap.add_argument("--no-submit", action="store_true")
    ap.add_argument("--no-save", action="store_true")
    ap.add_argument("--solve-timeout", type=float, default=None, metavar="SECONDS")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()
    if RUNNER_MISSING:
        sys.exit("run.py: refused: the attempt runner is the Huntress platform adapter's and needs "
                 + "; ".join(RUNNER_MISSING) + ". Nothing was requested. (The expander is tools/archive_expand.py.)")
    if a.dry_run and a.offline:
        ap.error("--dry-run and --offline are different sources for the attempt: pick one")
    cid = a.challenge
    live = not (a.dry_run or a.offline)
    if a.no_save and live:
        ap.error("--no-save goes with --dry-run or --offline: a live run always saves its variant and its verdicts")

    st = SimpleNamespace(attempt=None, blobs=[], answers={}, unsure={}, errors=[], notes=[], result=None, dir=None,
                         clock=None, submitted=False, timed_out=False, left_after=None, start_http=None, fatal=False,
                         timed=live and gm.is_timed(cid), lane=None, contract=[], refused=None, infra=False,
                         saved_attempt=False, word=None, pool=None, misformat={}, practice=False, practice_played=None,
                         status_body=None, contract_late=[], ticket=None, no_unsure="", streamed=None)
    if a.practice and not (live and gm.is_timed(cid)):
        ap.error("--practice is for a live Time Trial or Mastery id")
    if a.rejoin and (not (live and gm.is_timed(cid)) or a.practice or a.retry):
        ap.error("--rejoin is for a live Time Trial or Mastery id, without --retry or --practice")
    st.practice = bool(a.practice)
    st.rejoin = bool(a.rejoin)
    if a.start_only and (not (live and gm.is_timed(cid)) or a.practice or a.retry or a.rejoin or a.no_submit):
        ap.error("--start-only is for a live Time Trial or Mastery id, alone (no --retry, --practice, --rejoin or --no-submit)")
    if st.timed:
        # A clock needs a ticket. Without one the run ends here: no request, no token read, no solver import.
        if judge is None or judge.ticket(cid) is None:
            print(f"no ticket: run tools/preflight.py --gate {cid}"
                  + ("" if judge is not None else " (tools/judge.py did not load, so no ticket can be read: fix that first)"))
            print(run_line("no_ticket"))
            sys.exit(3)
        # Switches that change what a solver answers are for experiments; none follows a run onto a clock.
        removed = lanes.clean_env()[1]
        for name in removed:
            os.environ.pop(name, None)
        if removed:
            st.notes.append(f"removed from the environment for this timed run: {', '.join(removed)}")
    if a.start_only:
        # W-5: no solver is loaded (a live target has none), nothing but the one start is sent.
        try:
            code = start_only(cid)
        except SystemExit as e:     # gm.check stops on `unauthorized`, gm.session on a missing token
            if e.code in (0, None):
                raise
            print(f"STOPPED {e.code}")
            print(run_line("unauthorized" if str(e.code).startswith("unauthorized") else "stopped"))
            code = 1
        sys.exit(code)
    try:
        st.lane = lanes.policy(lanes.lane_of(cid))   # read now: no file is opened for it on the clock
    except Exception as e:
        st.notes.append(f"the lane table could not be read ({type(e).__name__}: {e}); no solve cap applies")

    try:
        solver = load_solver(a.solver)  # imported before any clock starts
    except (Exception, SystemExit) as e:
        # Nothing was requested and no ticket was spent. The run still ends with its last line, so
        # a caller that reads only that line learns that the solver is the problem.
        if isinstance(e, SystemExit) and isinstance(e.code, str):
            print(e.code)   # load_solver's own line: the file defines no solve_set
        elif isinstance(e, OSError) and not Path(a.solver).is_file():
            print(f"no solver: {a.solver} is not a file")
        else:
            print("ERROR the solver could not be loaded\n" + traceback.format_exc())
        print(run_line("no_solver"))
        sys.exit(1)
    # warmups=pool (backlog row 28, off by default): the workers are forked here, before any request.
    st.pool = SolvePool.maybe(cid, solver, st.notes)
    if st.timed and switch_on("spawn"):
        # Row 412 under spawn=warm: this process was waiting with its imports done, so its start is near; the
        # warm-up begins at once (after the pool's fork above: warmups=pool forks no worker beside a thread).
        start_warm(solver, st, "at process start (spawn=warm)")
    t = {"t0": time.perf_counter()}
    try:
        play(a, cid, solver, st, t, live)
    except KeyboardInterrupt:
        st.fatal, st.infra = True, False
        st.errors.append("interrupted")
    except SystemExit as e:  # gm.check stops on `unauthorized`; --offline stops on a missing file
        if e.code not in (0, None):
            st.fatal, st.infra = True, False
            st.errors.append(f"stopped: {e.code}")
            if str(e.code).startswith("unauthorized"):
                st.word = "unauthorized"   # the one failure only the player can fix: the last line says so
    except BaseException:
        st.fatal, st.infra = True, True
        st.errors.append("runner failed\n" + traceback.format_exc())
    finally:
        if st.pool is not None:
            st.pool.close()
    code = report(a, cid, st, t, live)
    join_gate_row()             # gate reuse: the row is on disk before the gate that follows this run reads it
    if live:
        note_contract(cid)      # after the last line: the clock is over, and it costs the run nothing
    sys.exit(code)


if __name__ == "__main__":
    main()
