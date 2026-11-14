#!/usr/bin/env python3
"""Play a timed attempt of a cumulative lane: one batch, groups when it is rejected, names learned live.

Usage:
  python3 solvers/script-analysis/timed_ladder.py <challenge-id> [--solver PATH] [--retry] [--dry]

  --solver PATH  the lane solver (default: analyze.py beside this file). With another solver,
                 for example solvers/binary/evidence.py, the Batch and VBScript modules are not
                 imported and their legacy name tables are not used.
  --retry        renew an expired attempt (next variant) first
  --dry          read the attempt with op=status, compute the groups, submit nothing, write nothing

A Time Trial or Mastery is started only with a ticket (tools/preflight.py --gate <id> writes
it). Without one this prints `no ticket: ...` and exits 3 before any request.

No op=status read before the start (package PR1, the player's decision of 2026-10-11; the switch
`preread` of tools/switches.py, read through tools/run.py: preread). The start is the first
request; the lane's contract check runs on the start response's own questions before any download,
prints its `CONTRACT <problem>` lines with one line that says the check ran after the start, and
the attempt is played on. `"preread": "status"` in challenges/_opener.json gives the read back:
the check then runs before the clock, and a mismatch starts none (`contract_mismatch`, exit 3).

Why not simply one submission: the judge banks a batch only when every answer in it is right
and otherwise answers a bare `incorrect`. Some answers are names the challenge author chose,
and a name the base never showed cannot be known before the clock runs. So inside one window:

  1. One batch of every plain answer. On a clean variant that is the only request (the wire
     behaviour of tools/run.py). Unsure answers ("??", see docs/ops/contracts.md), legacy
     sentinels and missing answers are held out; an unsure answer is never sent as text.
  2. If that batch is rejected, the answers are worked in groups:
       CORE            the components of the lane's frozen list (tools/lanes.py), minus
       VC, BC, BE      the VBScript control, Batch control and Batch expansion answers
       <prefix>/plan   for any other component: role, attack, adapter, campaign, graph,
                       artifact_sha256_*, analysis_config_*, crc and xor fields, and every
                       field asked fewer than nine times per set
       <prefix>/<field>  each other field of that component
     A group of one field (VC, BC, BE, <prefix>/<field>) is cut into label classes: its ids
     that share one answer. The wrong part is found with one request for each cut (send one
     half; accepted, the wrong answer is in the other half, which is then not sent). The rest
     is banked as one batch. A wrong label class is offered the other names accepted for its
     family (labels.family, and the legacy vocabulary of the four known languages), the whole
     class per request; if none fits, its ids are sent one by one (a class of more than three
     is halved by grade.bank) and each rejected id is offered those names alone. A wrong CORE
     or plan group goes through grade.bank, which halves it down to the ids that are wrong;
     such an id is then offered its family's names.
  3. Legacy sentinels (a name blanked in batch_conventions.json) and unsure answers are probed
     through grade.probe: the options of a key on ONE id, one per request, and the accepted
     name applied to the key's other ids. Accepted and rejected names go to the labels ledger
     (labels.learn); the legacy ones also to batch_conventions.json, which batch.py loads, so
     the next attempt (a new variant) starts from what this one learned.

What keeps a bad minute from costing the attempt:
  - Nothing is sent with less than 1.0 s on the clock. Every request has a timeout of
    min(3 s, time left). A 429, a 5xx or a dropped connection is not a verdict: the request
    is sent again, at most twice, and what it carried stays pending (it is sent once more at
    the end). Only CORRECT ends the run early. Four things stop the sending without one: a
    rate limit that outlasts its re-sends (the bucket is empty, and more requests only take
    from the next clock), two requests in a row that stay unjudged, a response that says the
    attempt takes no more answers (expired, not started, HTTP 401, 403, 404, 409 or 410), and
    `already_solved`, after which op=status is read once, because the CORRECT may have been
    lost on its way back. When the status read says CORRECT for this very attempt, the answers
    of the batch whose response was lost are recorded (see Ladder.settle_lost), so key.json is
    written and the Mastery gate can read the Time Trial as closed.
  - A rejection is recorded only for a single id answered `incorrect` with at least 0.3 s left.
    At most 12 family names are offered for rejected plain answers in one run.
  - The solver runs under a time budget of min(time left - 2.5 s, 2.0 s x the larger of the
    attempt's deliveries and its sets: lanes.ladder_budget); when it runs out, what the solver put into ctx['partial'] is submitted.
  - A plain answer whose kind contradicts its question's answer_format (backlog row 106,
    tools/kinds.py: `ELF64` where an integer is asked) is held out of every batch, printed as
    `FORMAT <id>: <reason>` and filed in gaps.json with the missing ids.
  - binary=pool (backlog row 121; the player's switch in challenges/_opener.json, off by
    default): for a Binary Mastery, six workers are forked before any request; each delivery
    is read from disk, expanded and solved by a worker of its own, and a delivery whose worker
    died, failed, raised or was not back within half the solve budget (at most 4 s) is solved
    here, serially, with what is left. See SetPool.
  - script=pool (backlog row 336, built 2026-10-17 for Day 18; the player's switch, off by default):
    the same pool for a Script Analysis Mastery, by SET. Its one delivery is a zip of numbered
    inner zips (evidence-01.zip ...); each worker reads the saved delivery, takes only its own
    set's inner zip by run.split_sets's name rule, expands and solves that set. Used only where the
    delivery has exactly one unencrypted member per set and nothing else; a set whose worker died,
    failed, raised, was late or met a locked archive is solved here, serially. See SetPool.
  - The prefix pool (the Day 21 local speed build, under binary=pool): for a Binary Time Trial four
    workers are forked before any request, each solves one share of the one delivery's prefixes, and
    a share not given back cleanly is solved here, serially. See tools/prefix_pool.py and pool_prefixes().
  - --practice (the event guide of 2026-10-08): no fresh variant remains, so op=practice is posted
    in place of the retry (tools/run.py: start_attempt; a retry refused for that reason turns into
    it by itself). The attempt has no deadline, so nothing here is cut by a clock, but the solver
    is still bounded (the run holds the clock lock). One NOTE, `practice attempt on a timed id`,
    and result.json carries "practice": true.
  - A delivery is downloaded through tools/gm.py's download ladder (run.fetch_each); when another
    way than op=artifact returned it, one NOTE `download ladder: ...` says so.
  - A timed id the Game Master plays as a regular attempt (backlog row 108) is one NOTE,
    `regular attempt on a timed id: ...`, and result.json carries run_for_time,
    hall_of_fame_eligible and "regular_attempt": true.
  - The attempt and its deliveries are on disk before the solver runs. Every response is in
    verdicts.jsonl before the next request. ladder-log.json, result.json (the last response),
    gaps.json and solver.stderr.txt are written whatever happens; key.json on CORRECT. After a
    retry these files of the earlier variant are in history/<its attempt id>/, beside its
    attempt.json, which is where tools/preflight.py looks for a variant's verdicts.
  - Solver switches (ONLY, BATCH_*, D02_PICK, ...) are removed from the environment, with a NOTE.

The last line of stdout is
  LADDER result=<r> remaining=<n> banked=<n> probes=<n> rejected=<n> learned=<n> infra=<true|false>
result is CORRECT, accepted (something was banked), incorrect (judged, nothing banked), or the
word that stopped the run (no_ticket, contract_mismatch, rate_limited, expired, ...). infra is
true only when an attempt was tried, nothing was judged, and a request or a download failed; a
solver that gave nothing to send is infra=false. Exit 0 CORRECT, 2 otherwise, 3 for no ticket
or a contract mismatch.
"""
import argparse
import contextlib
import io
import json
import os
import re
import shutil
import signal
import sys
import threading
import time
import traceback
from collections import Counter, namedtuple
from pathlib import Path
from types import SimpleNamespace

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env
from ctf import deliveries as ctf_deliveries   # B-042: one wording for a set with no delivery

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
for _p in (HERE.parent / "common", ROOT / "tools", HERE):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
import requests

# This is the Huntress Game Master timed runner (merge plan: take_huntress, "stays with the Huntress stack").
# Its platform modules were archived with the Game Master client (infra-tools-ctf-claude.merge.json; the
# Huntress adapter is B-005), so without them the import stops here naming every one (B-001b), not at the
# first bare "No module named 'gm'". tools/import_gate.py allows these imports in this file only.
import importlib.util  # noqa: E402
_HUNTRESS_RUNNER = ("gm", "judge", "lanes", "grade", "prefix_pool")
_missing = [m for m in _HUNTRESS_RUNNER if importlib.util.find_spec(m) is None]
if _missing:
    raise ImportError("timed_ladder.py is the Huntress Game Master runner and needs "
                      + ", ".join(f"tools/{m}.py" for m in _missing)
                      + ", archived by the master merge plan (the Huntress platform adapter is B-005)",
                      name=_missing[0])

import gm
import run
import judge
import lanes
import grade
import labels
import prefix_pool

MARGIN = 1.0             # nothing is sent with less than this many seconds on the clock
MIN_LEFT = judge.MIN_LEFT  # an `incorrect` with less than this left is not a rejection
RESENDS = 2              # times a request that was not judged (429, 5xx, dropped) is sent again
STRIKES = 2              # requests in a row that stay unjudged before the run stops
# The solve budget lives in tools/lanes.py (ladder_budget), shared with the gate (backlog row 99).
SOLVE_HOLDBACK = lanes.LADDER_HOLDBACK   # seconds of the window kept for submitting
SOLVE_CAP = lanes.LADDER_CAP             # the longest a solver runs inside a window, per delivery or set
POST_TIMEOUT = 3.0
# Row 527 (Day 26: a ~1.07 MB Mastery body hit the flat 3 s read timeout and recovered only through already_solved
# -> op=status): a body of 1 MiB or more gets POST_TIMEOUT + 1 s per MiB, at most POST_TIMEOUT_CAP, so a dropped
# connection still recovers fast. A smaller body keeps POST_TIMEOUT exactly. Inside a window the read is still
# capped at the time left (Ladder._send).
POST_TIMEOUT_CAP = 8.0
POST_TIMEOUT_MIB = 1 << 20


def post_timeout(size) -> float:
    """The read timeout of a submit whose body is `size` bytes (no deadline), row 527."""
    if not isinstance(size, (int, float)) or size < POST_TIMEOUT_MIB:
        return POST_TIMEOUT
    return min(POST_TIMEOUT_CAP, POST_TIMEOUT + size / POST_TIMEOUT_MIB)
PROBES = 40              # option probes of one run (grade.probe's max_total)
RELEARN_LEFT = 10.0      # row 579: enough clock to solve an affected set and submit its new plain answers
# An attempt with no deadline (practice once no fresh variant remains, a regular attempt on a timed id): no
# clock bounds the run, and tools/judge.py only counts a timed id's requests. Unbounded, a rejected batch of
# 357 answers with twenty wrong ids is bisected in about 170 requests at 5 a second, into a limit of about
# 120 a calendar minute that every lane shares (Day 8's first 429 came at the 66th). So such a run sends at
# most UNTIMED_REQUESTS, at least UNTIMED_GAP apart; what it banked stays banked, and the next start goes on.
# Row 250 (start=regular, where an attempt with no deadline is the ordinary case): both numbers stand. A request
# answered 429 on such an attempt is waited out and is not one of the 40 (Ladder.send); a run that does use 40
# leaves the attempt open with what it banked, and the opener's next step is a rejoin behind the retry gate,
# asked with --same-artifact, so the same answers are never bisected a second time.
UNTIMED_REQUESTS = 40
UNTIMED_GAP = 0.4
NAME_OFFERS = 12         # family names offered, in one run, for plain answers the judge rejected
ONE_BY_ONE = 3           # a wrong label class of at most this many ids is sent id by id, a larger one halved
JUDGED = ("accepted", "CORRECT", "incorrect")
GOOD = ("accepted", "CORRECT")
# A response that says the attempt itself takes no more answers (it expired, it was never started,
# the token is refused): no other batch can fare better, so the run stops at the first one.
OVER_HTTP = (401, 403, 404, 409, 410)
OVER_WORD = re.compile(r"expire|start_required|unauthori[sz]ed|unknown_challenge", re.I)
# What the ladder leaves in an attempt folder besides the attempt itself; it follows a retried
# variant into history/<attempt id>/ (see shelve).
SHELVED = ("verdicts.jsonl", "gaps.json", "key.json", "ladder-log.json", "solver.stderr.txt")
# Backlog row 341: the guidance text of every Mastery since Day 17 says 'If the encoded JSON would exceed
# 512 KiB, split it into chunks of at most 500 answers and at most 512 KiB each; each request counts as one
# submission'. Day 17's Script Mastery body was 349,820 B (66.7 %), growing 16 to 22 KB a day. A body at or
# below BODY_LIMIT goes as it always did; a larger one is sent as chunks (Ladder.send). BODY_WARN raises one
# warn alert after the run, so the day the chunks first go is seen coming.
# Since the Day 21 build (wire-chunk): the guidance of 2026-10-20 says 'one request may carry up to 4 MiB of
# JSON, enough for every answer of the largest Mastery. Split only above 4 MiB, into chunks of at most 4 MiB
# each' and names no answer count (challenges/day-20/wire-proposal.md). BODY_LIMIT keeps 256 KiB of margin
# under 4 MiB; a chunk has no answer cap (CHUNK_ANSWERS None). Day 20's Script Mastery body was 419,227 B.
BODY_LIMIT = 4 * 1024 * 1024 - 256 * 1024
CHUNK_ANSWERS = None
BODY_WARN = 3 * 1024 * 1024 + 512 * 1024

# ---- the legacy name tables of the four known languages (batch_conventions.json is their store) ----
# Candidate names for a shape whose name is blanked there, most plausible first.
CANDIDATES = {
    # Every specimen echoes the plan with !var!, so a %var% join may simply be reported as delayed.
    "@percent": ["delayed", "immediate", "for_indirect", "call_double", "percent_immediate", "percent_expansion",
                 "plain", "normal", "standard", "eager", "static", "parse_time"],
    "@errorlevel": ["errorlevel_guard", "errorlevel_check", "errorlevel_gate", "errorlevel_exit", "errorlevel_branch",
                    "errorlevel_test", "errorlevel", "if_errorlevel_exit", "guard", "early_exit", "exit_guard",
                    "if_exit", "guarded", "if_guard"],
    "@if_defined": ["direct", "if_defined", "defined_guard", "defined_check", "defined_gate", "if_defined_set",
                    "defined_branch", "if_guard", "guarded", "conditional", "if_ready", "ready_guard"],
    # VBScript wrappers the base never contained. Batch's guards turned out to be errorlevel_guard and
    # if_guard, and VBScript's confirmed loops are do_once and while_once, so those patterns go first.
    "@von_error": ["error_guard", "on_error_guard", "on_error", "err_guard", "on_error_resume_next", "resume_next",
                   "error_trap", "on_error_resume", "error_handler", "on_error_once", "guard", "try_once"],
    "@vif": ["if_guard", "if_true", "if_then", "if_once", "guard", "if_block", "conditional", "direct", "if_else"],
    "@vfor": ["for_once", "for_next", "for_loop", "for_single", "loop_once", "for_each"],
}
KIND = {"@percent": ("expansion", "percent"), "@errorlevel": ("control", "errorlevel"), "@if_defined": ("control", "if_defined"),
        "@von_error": ("vbscript_control", "on_error"), "@vif": ("vbscript_control", "if"), "@vfor": ("vbscript_control", "for")}
# The same six shapes under their pinned labels keys: what is learned for a sentinel is also a
# row of the labels ledger, so labels.family and the text path see it.
LEGACY_KEY = {"@percent": "script.expansion/batch.percent", "@errorlevel": "script.control/batch.errorlevel",
              "@if_defined": "script.control/batch.if_defined", "@von_error": "script.control/vbs.on_error",
              "@vif": "script.control/vbs.if", "@vfor": "script.control/vbs.for"}
# The names the judge has accepted in each legacy group; an answer of the group that is rejected
# is offered the others.
VOCAB = {"BE": ["delayed", "for_indirect", "call_double"],
         "BC": ["direct", "goto_dispatch", "call_subroutine", "errorlevel_guard", "if_guard"],
         "VC": ["direct", "select_case", "do_once", "while_once", "for_once", "error_guard"]}
LEGACY_GROUPS = ("VC", "BC", "BE")
SHAPE_PREFIX = {"vbscript": "vbs"}    # component -> the language part of its labels keys (script.control/vbs.do)

# Fields of a new component that come from its recovered plan or its headers; they share one group.
PLAN_FIELDS = ("role", "attack", "adapter", "campaign", "graph")
PLAN_PREFIXES = ("artifact_sha256", "analysis_config")
FIELD_PER_SET = 9        # a field asked fewer times than this per set has no group of its own

Unit = namedtuple("Unit", "label kind answers group name")
Unit.__doc__ = """One part of the plain answers on the fallback path.

label    how its requests are named in the log
kind     'group' (CORE or a <prefix>/plan group: several fields, halved by grade.bank) or
         'class' (the ids of one single-field group that share one answer)
answers  {answer id: value}
group    the group it belongs to
name     the shared answer of a class, None for a group"""


def group_of(qid: str) -> str:
    """The legacy group of a known-language question id (without its 'setN.' prefix)."""
    if re.fullmatch(r"batch-.*-expansion", qid):
        return "BE"
    if re.fullmatch(r"batch-.*-control", qid):
        return "BC"
    if re.fullmatch(r"vbscript-.*-control", qid):
        return "VC"
    return "CORE"


def is_plan_field(field: str, per_set: int) -> bool:
    f = str(field).lower()
    return (f in PLAN_FIELDS or f.startswith(PLAN_PREFIXES) or "crc" in f or "xor" in f or per_set < FIELD_PER_SET)


def plan_groups(lane, frozen, rows) -> dict:
    """{answer id: group label} for the rows [(answer id, question id without 'setN.', set number)].

    Components in `frozen` form CORE, minus the legacy VC, BC and BE groups. Any other component
    gets '<prefix>/plan' and one '<prefix>/<field>' for each field asked at least nine times per set."""
    per_set = Counter()
    for _, qid, n in rows:
        per_set[(n,) + tuple(lanes.family_of(lane, qid))] += 1
    most = {}
    for (n, comp, field), count in per_set.items():
        most[(comp, field)] = max(most.get((comp, field), 0), count)
    out = {}
    for aid, qid, _ in rows:
        legacy = group_of(qid)
        comp, field = lanes.family_of(lane, qid)
        first = re.split(r"[-_]", qid, maxsplit=1)[0]
        if legacy != "CORE":
            out[aid] = legacy
        elif comp in frozen or first in frozen:
            out[aid] = "CORE"
        else:
            out[aid] = f"{comp}/plan" if is_plan_field(field, most[(comp, field)]) else f"{comp}/{field}"
    return out


def ordered_groups(group_of_id: dict, plain: dict) -> dict:
    """{group label: {answer id: value}} with CORE, VC, BC, BE first (as on Day 4) and every other
    group in question order."""
    groups = {g: {} for g in ("CORE",) + LEGACY_GROUPS}
    for aid, value in plain.items():
        groups.setdefault(group_of_id[aid], {})[aid] = value
    return groups


def shown(value, cut=28) -> str:
    """An answer for a log label: one line, ASCII, cut."""
    s = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
    s = s.encode("ascii", "backslashreplace").decode("ascii").replace("\n", "\\n").replace("\r", "\\r")
    return s if len(s) <= cut else s[:cut] + "..."


def units_of(groups: dict) -> list:
    """The fallback units, in the order they are cut: label classes first, plan groups, CORE last."""
    classes, wholes = [], []
    for label, answers in groups.items():
        if not answers:
            continue
        if label == "CORE" or label.endswith("/plan"):
            wholes.append(Unit(label, "group", dict(answers), label, None))
            continue
        by = {}
        for aid, value in answers.items():
            by.setdefault(value, {})[aid] = value
        classes += [Unit(f"{label}={shown(value)}", "class", part, label, value) for value, part in by.items()]
    return classes + sorted(wholes, key=lambda u: u.label == "CORE")


def union(units) -> dict:
    out = {}
    for u in units:
        out.update(u.answers)
    return out


def batch_key(values):
    """What Ladder.refused keeps for one batch: its (id, value) pairs as a frozenset. None for a
    batch that cannot be kept that way (a value that is not hashable; the plain answers are text,
    so this is not expected): such a batch is never known as refused, and it is sent as before.
    Keeping a verdict must never be what ends a run on the clock."""
    try:
        return frozenset(values.items())
    except TypeError:
        return None


def cut_label(units) -> str:
    n = sum(len(u.answers) for u in units)
    if len(units) == 1:
        return f"{units[0].label}[{n}]"
    names = [u.label for u in units]
    return f"cut[{n}]: " + ", ".join(names[:4]) + (f" (+{len(names) - 4})" if len(names) > 4 else "")


def word_of(value) -> str:
    """A result as one token for the LADDER line."""
    s = re.sub(r"\s+", "_", str(value if value not in (None, "") else "none").strip())
    return re.sub(r"[^\w.:+-]", "", s)[:48] or "none"


def ladder_line(result, remaining="-", banked=0, probes=0, rejected=0, learned=0, infra=False) -> str:
    return (f"LADDER result={word_of(result)} remaining={remaining} banked={banked} probes={probes} "
            f"rejected={rejected} learned={learned} infra={'true' if infra else 'false'}")


def contract_problems(solver, cid, body) -> list:
    """Why this timed id's questions are not ones the solver was proven on (empty: start).

    tools/run.py owns this check (run.contract_problems); the copy here is used only with a
    run.py that does not have it yet. Lane contract 'same_ids': every question id, 'setN.'
    removed, must be an answer id of the saved base attempt. 'hook': the solver's own
    covers(questions)."""
    if hasattr(run, "contract_problems"):
        return list(run.contract_problems(solver, cid, body) or [])
    entry = lanes.policy(lanes.lane_of(cid)) or {}
    questions = [q for q in body.get("questions") or [] if isinstance(q, dict)]
    mode = entry.get("contract", "none")
    if mode == "same_ids":
        saved = run.attempt_dir(lanes.base_of(cid)) / "attempt.json"
        try:
            base = json.loads(saved.read_text())
        except (OSError, ValueError):
            return [f"the base attempt is not saved ({saved}), so the question ids cannot be checked"]
        have = set(run.answer_ids_for(base)) | {q.get("id") for q in base.get("questions") or [] if isinstance(q, dict)}
        new = [q.get("id") for q in questions if re.sub(r"^set\d+\.", "", str(q.get("id"))) not in have]
        return [f"{qid}: not an answer id of the saved base" for qid in new]
    if mode == "hook" and hasattr(solver, "covers"):
        return [str(p) for p in (solver.covers(questions) or [])]
    return []


class Ladder:
    """One attempt's submissions: what was sent, what the judge said, and what is still open."""

    def __init__(self, cid, lane, session, attempt, clock, folder, t0, conv=None):
        self.cid, self.lane, self.s, self.attempt, self.clock, self.dir, self.t0 = cid, lane, session, attempt, clock, folder, t0
        self.attempt_id = attempt.get("attempt_id")
        self.order = run.answer_ids_for(attempt)
        self.question = dict(zip(self.order, attempt.get("questions") or []))
        self.conv, self.conv_changed = conv, False
        self.log = []
        self.banked, self.bad = {}, {}       # accepted answers; solver answers rejected alone
        self.rejected = set()                # every (id, value) answered incorrect alone
        self.refused = set()                 # every batch (frozenset of its items) answered incorrect in time
        self.surprises, self.learned, self.open_keys, self.plan = {}, {}, {}, {}
        self.requests = self.probes = self.judged = self.strikes = self.offers = 0
        self.remaining = None
        self.correct = False
        self.stopped = None                  # why no further request is sent (None: none yet)
        self.last = None                     # the last response, as result.json keeps it
        self.unjudged = []                   # what came back instead of a verdict
        self.invalid = 0                     # requests the judge would not read (row 329: http 400 invalid_answers)
        self.notes = []                      # NOTE lines of the submitting (row 346), printed by main
        self.lost = False                    # a response may have been lost on its way back
        self.record_failed = False
        self.chunked = False                 # row 341: a body over BODY_LIMIT was sent in chunks
        self.biggest = 0                     # the largest submit body measured, in bytes
        self.prior = None                    # row 415: labels.PriorWatch of the solver's answers (play() sets it)

    def has_deadline(self) -> bool:
        """True when the attempt has a deadline: the clock reads one, or the attempt body names one.
        Row 346: a candidate pick is probed inside a timed attempt only when this is False (a regular
        attempt, or practice: deadline null)."""
        return self.clock is not None or bool(self.attempt.get("deadline"))

    # -- the clock --

    def left(self):
        return self.clock.left() if self.clock is not None else None

    def open(self) -> bool:
        """True while another request may be sent."""
        if self.correct or self.stopped:
            return False
        t = self.left()
        if t is None and self.requests >= UNTIMED_REQUESTS:
            # No deadline (practice, a regular attempt on a timed id): no clock ends the bisecting and
            # probing, and the wire only counts a timed id's requests. The run's own budget does.
            self.stopped = (f"{UNTIMED_REQUESTS} requests sent on an attempt with no deadline: the rest is left to the next "
                            f"start (the rate limit is shared by every lane)")
            return False
        return t is None or t >= MARGIN

    # -- one request --

    def body_size(self, values) -> int:
        """The bytes of the submit body as requests encodes it (json.dumps with its default separators)."""
        try:
            return len(json.dumps({"challenge": self.cid, "answers": values}, allow_nan=False).encode("utf-8"))
        except (TypeError, ValueError):
            return 0

    def chunks(self, values) -> list:
        """`values` cut, in order, into chunks of at most BODY_LIMIT bytes (and CHUNK_ANSWERS answers, when set) each."""
        head = self.body_size({})
        out, part, size = [], {}, head
        for aid, value in values.items():
            try:                                                     # '"id": value' and its ", " separator
                one = len(json.dumps(aid).encode("utf-8")) + len(json.dumps(value, allow_nan=False).encode("utf-8")) + 4
            except (TypeError, ValueError):
                one = BODY_LIMIT                                     # not encodable: a chunk of its own
            if part and ((CHUNK_ANSWERS and len(part) >= CHUNK_ANSWERS) or size + one > BODY_LIMIT):
                out.append(part)
                part, size = {}, head
            part[aid] = value
            size += one
        if part:
            out.append(part)
        return out

    def send(self, label, values, kind="bank", key=None, name=None):
        """Row 341: _send() with the guidance's size rule. A body at or below BODY_LIMIT is one request,
        exactly as before. A larger one goes as chunks (self.chunks), in order: an accepted chunk banks,
        the last one returns CORRECT, and the first chunk that is not accepted ends the batch with its
        verdict, which is the batch's too (a rejected chunk holds a wrong answer, so the batch does; a
        chunk not judged leaves the rest unsettled). Once a run has sent chunks, an answer it has
        banked is not sent again: the halves grade.bank and narrow() cut from a rejected batch would
        otherwise carry the chunks already accepted. Before that nothing is left out, as before."""
        values = dict(values)
        if self.chunked and kind == "bank":
            # a probe is never filtered: an 'accepted' made up here would read as the judge accepting a name
            values = self.unbanked(values)
            if not values:
                return grade.verdict("CORRECT" if self.correct else "accepted", self.remaining)
        size = self.body_size(values)
        self.biggest = max(self.biggest, size)
        if size <= BODY_LIMIT:
            return self._send(label, values, kind=kind, key=key, name=name)
        parts = self.chunks(values)
        if not self.chunked:
            self.chunked = True
            self.notes.append(f"submit body of {len(values)} answers is {size} B, over the {BODY_LIMIT} B the guidance "
                              f"allows: sent as {len(parts)} chunks of at most {BODY_LIMIT} B (row 341)")
        v = grade.verdict("accepted", self.remaining)
        for i, part in enumerate(parts, 1):
            if i > 1 and not self.open():
                return grade.verdict(self.stopped or "time", self.remaining)
            v = self._send(f"{label}#{i}/{len(parts)}", part, kind=kind, key=key, name=name)
            if v.result == "CORRECT":
                return v
            if v.result not in GOOD:
                t = self.left()
                if v.judged and (t is None or t >= MIN_LEFT):
                    k = batch_key(part)
                    if k is not None:
                        self.refused.add(k)
                return v
        return v

    def unbanked(self, values) -> dict:
        """`values` less the answers this run has banked with the same value (row 341, once chunks were sent)."""
        return {aid: v for aid, v in values.items() if aid not in self.banked or self.banked[aid] != v}

    def size_alert(self):
        """One warn alert when a submit body of this run passed BODY_WARN (row 341). Never raises."""
        if self.biggest <= BODY_WARN:
            return
        try:
            import alert
            how = "sent in chunks" if self.chunked else "sent whole"
            alert.alert("warn", f"SUBMIT BODY LARGE {self.cid}: {self.biggest} B of the {BODY_LIMIT} B a request may "
                                f"hold ({how}; row 341)", lane=self.lane, wait=False)
        except Exception:  # noqa: BLE001 - an alert is never the run's undoing
            pass

    def _send(self, label, values, kind="bank", key=None, name=None):
        """POST one submission and return its grade.Verdict. A request that was not judged for a
        passing reason (429, 5xx, a dropped connection) is sent again, at most RESENDS times while
        the clock allows. Every response is recorded (judge.record) before the next request."""
        values = dict(values)
        word = remaining = http = after = None
        if not self.requests and not getattr(self, "_warmed", False):
            # Row 223 (b): the Time Trial variant's warm replay for the Mastery gate, started by a thread
            # tools/run.py owns once this first request has left, and only while this clock is the one running.
            self._warmed = True
            with contextlib.suppress(Exception):
                getattr(run, "offer_gate_row", lambda *_: None)(getattr(self, "gate_offer", None))   # gate reuse
            with contextlib.suppress(Exception):
                getattr(run, "start_timed_prewarm", lambda *_: None)(self.cid, self.dir)
        again = -1
        read_for = post_timeout(self.body_size(values))      # row 527: scaled with the body, once per submission
        while again < RESENDS:
            again += 1
            t = self.left()
            if again and t is not None and t < MARGIN:
                break
            http, body, passing = None, None, False
            if t is None and self.requests:
                # No deadline: nothing is gained by haste, and the wire does not pace a timed id. The
                # gap of untimed submissions is kept here (0.4 s; AGENTS.md, "rate-limits").
                wait = UNTIMED_GAP - (time.perf_counter() - getattr(self, "_sent_at", 0.0))
                if wait > 0:
                    time.sleep(wait)
            self._sent_at = time.perf_counter()
            try:
                resp = self.s.post(gm.GM, json={"challenge": self.cid, "answers": values},
                                   timeout=read_for if t is None else max(0.3, min(read_for, t)))
                http, body = resp.status_code, run.body_of(resp)
                word = body.get("result") or body.get("error") or f"http {http}"
                word = word if isinstance(word, str) else json.dumps(word)[:80]
                passing = http == 429 or http >= 500 or word == "rate_limited"
            except gm.NothingToSend:
                word = "nothing_to_send"
            except Exception as e:  # noqa: BLE001 - a dropped connection or a timeout is not a verdict
                word, passing, self.lost = type(e).__name__, True, True
            self.lost = self.lost or word == "already_solved"
            self.requests += 1
            if kind == "probe":
                self.probes += 1
            after = self.left()
            remaining = body.get("remaining") if isinstance(body, dict) and word in GOOD else None
            try:
                judge.record(self.dir, values, word, remaining=remaining, left=after, http=http, kind=kind,
                             key=key, name=name, attempt_id=self.attempt_id)
            except Exception as e:  # noqa: BLE001 - the verdict stands whether or not it could be written down
                if not self.record_failed:
                    self.record_failed = True
                    print(f"NOTE verdicts.jsonl could not be written ({type(e).__name__}: {e})", file=sys.stderr)
            row = {"label": label, "n": len(values), "result": word, "remaining": remaining,
                   "at": round(time.perf_counter() - self.t0, 2), "left": None if after is None else round(after, 2)}
            if again:
                row["resend"] = again
            self.log.append(row)
            self.last = {k: v for k, v in body.items() if k not in run.BULKY} if isinstance(body, dict) else {"error": word}
            if word in JUDGED:
                break
            if word == grade.INVALID and kind == "probe":
                break                        # row 329: refused unread, the same every time; see below
            self.unjudged.append(word)
            if not passing:
                break
            if (http == 429 or word == "rate_limited") and t is None and getattr(run, "untimed_patient", None) \
                    and run.untimed_patient(self.cid, None):
                # Row 250 (start=regular): the attempt has no deadline and the request was not processed. The
                # pause the governor noted for this 429 is waited out to its end and the request is sent
                # again, for run.UNTIMED_PATIENCE seconds in all in this process; it is neither one of the
                # RESENDS nor one of the UNTIMED_REQUESTS (a refused request took nothing from the attempt).
                said = []
                if run.wait_untimed_pause(f"submit {label}", said):
                    for line in said:
                        print("NOTE", line, flush=True)
                    row["waited_out"] = True
                    self.requests -= 1
                    if kind == "probe":
                        self.probes -= 1
                    self.unjudged.pop()
                    again -= 1
                    continue
            if http == 429 and again < RESENDS:
                time.sleep(0.3 * (again + 1))
        if word in JUDGED:
            self.judged += 1
            self.strikes = 0
            if word in GOOD:
                self.banked.update(values)
                for aid in values:
                    self.bad.pop(aid, None)
                if self.prior:
                    self.prior.saw(values, word, after)     # row 415: in memory; the ledger row comes after the run
                self.correct = word == "CORRECT"
                self.remaining = 0 if self.correct else (remaining if isinstance(remaining, int) else self.remaining)
            elif len(values) == 1 and (after is None or after >= MIN_LEFT):
                (aid, value), = values.items()
                self.rejected.add((aid, value))
                if kind != "probe":
                    self.bad[aid] = value
        elif word == grade.INVALID and kind == "probe":
            # Row 329 (a probe only: a plain batch refused unread is unjudged, as before): the judge would not read this request's answers (Day 17: a probe's list sent as a JSON
            # array). No verdict, nothing banked, and nothing wrong with the wire or the attempt: no strike,
            # not one of the unjudged requests (they mark a run as infra and send the plain answers again).
            # grade.probe goes on with the next option.
            self.invalid += 1
        else:
            self.strikes += 1
            if word == "already_solved":
                # Observed on the real judge: a solved attempt takes no further submission. Here it
                # means an earlier answer of CORRECT was lost on its way back, or a teammate closed
                # the attempt (see confirm and settle_lost).
                self.stopped = "already_solved"
            elif http in OVER_HTTP or OVER_WORD.search(str(word)):
                # The attempt is over for every batch alike: one more request would only be one
                # more taken from the bucket the next clock needs.
                self.stopped = f"the attempt takes no more answers ({word})"
            elif http == 429 or word == "rate_limited":
                # Still limited after the re-sends: the bucket is empty, and more requests only
                # take from the next clock.
                self.stopped = "rate limited (429) on every send of one request"
            elif self.strikes >= STRIKES:
                self.stopped = f"not judged {STRIKES} times in a row ({word})"
        return grade.verdict(word, remaining)

    def ask(self, label, values, **how):
        """Send one batch. True: accepted. False: incorrect, with time enough left to believe it.
        None: not sent or not judged; whatever it carried is still unsettled."""
        if not values or not self.open():
            return None
        v = self.send(label, values, **how)
        if v.result in GOOD:
            return True
        if not v.judged:
            return None
        t = self.left()
        if t is None or t >= MIN_LEFT:
            key = batch_key(values)
            if key is not None:
                self.refused.add(key)                # work() and narrow() do not send this batch a second time
            return False
        return None

    def is_refused(self, values) -> bool:
        """True when the judge has answered this very batch `incorrect` in this run, in time."""
        key = batch_key(values)
        if key is not None and key in self.refused:
            return True
        if self.chunked:                             # a rejected chunk is keyed as sent: without what was banked
            key = batch_key(self.unbanked(values))
            return key is not None and key in self.refused
        return False

    # -- the plain answers --

    def family(self, aid):
        return lanes.family_of(self.lane, aid)

    def names_for(self, aid, sent) -> tuple:
        """(labels key prefix, the other names the judge has accepted in this answer's family).
        Only names: an answer is never offered a value the judge has not accepted somewhere in the
        family, and a question that lists its values is offered listed ones only."""
        comp, field = self.family(aid)
        short = labels.LANE_ALIASES.get(self.lane, self.lane)
        prefix = f"{short}." + re.sub(r"[^a-z0-9]+", "_", str(field).lower()).strip("_") + "/"

        def family(part):
            try:
                return labels.family(part)
            except Exception:  # noqa: BLE001 - a lane labels.py does not know has no family
                return []

        # The component's own names (script.control/vbs.*) and the legacy vocabulary of its group.
        # Only a component with neither (a new language) is offered the names of the whole field.
        names = family(prefix + SHAPE_PREFIX.get(comp, str(comp)) + ".")
        names += [n for n in VOCAB.get(group_of(re.sub(r"^set\d+\.", "", aid)), []) if n not in names]
        names = names or family(prefix)
        listed = ((self.question.get(aid) or {}).get("answer_format") or {}).get("accepted_values")
        names = [n for n in names if n != sent and (not listed or n in listed) and (aid, n) not in self.rejected]
        return prefix, names[:labels.MAX_OPTIONS]

    def offer(self, label, values, key, name):
        """Offer a family name for a plain answer that was rejected: self.ask, within the run's
        budget of NAME_OFFERS such requests (None once it is spent)."""
        if self.offers >= NAME_OFFERS:
            return None
        self.offers += 1
        return self.ask(label, values, kind="probe", key=key, name=name)

    def bank(self, unit, rejected=False):
        """grade.bank on one group: its first request is the group itself, and a rejected group is
        halved down to the ids that are wrong. `rejected`: the judge has already said this very
        group holds a wrong answer (it was sent whole, or everything else was accepted), so that
        first request is answered from what is known instead of being sent.

        A group of one id is the exception: an id is called wrong only on a verdict of its own.
        When it is known wrong only because everything else was accepted, it has never been sent
        alone, so it is sent now; otherwise it would be named nowhere (not in `bad`, not in
        gaps.json) and never be offered its family's names."""
        alone = next(iter(unit.answers)) if len(unit.answers) == 1 else None
        known = {"use": rejected and (alone is None or alone in self.bad)}

        def send(values):
            if known["use"]:
                known["use"] = False
                if values == unit.answers:
                    return grade.verdict("incorrect")
            return self.send(f"{unit.label}[{len(values)}]", values)

        out = grade.bank(send, unit.answers, split=self.family, left=self.left, floor=MARGIN)
        if out.stopped and not self.stopped and out.stopped.startswith("time"):
            self.stopped = out.stopped
        return out

    def narrow(self, units):
        """`units` (two or more) hold a wrong answer between them. One request for each cut: the
        first half is sent; accepted, the wrong answer is in the second half, which is not sent.
        Returns (the unit left, the units set aside unsent, sent), or (None, [], False) when a cut
        was not judged. `sent` is True when the unit left was itself sent and rejected.

        A cut the judge has already answered `incorrect` in this run is answered from that
        verdict and not sent again: the `pending` pass cuts the same units the same way, so after
        ALL and one or more cuts were rejected and a later cut was not judged, it would otherwise
        spend one request of the window on each of those cuts before it reaches the open one."""
        aside, sent = [], False
        while len(units) > 1:
            mid = len(units) // 2
            first, second = units[:mid], units[mid:]
            values = union(first)
            r = False if self.is_refused(values) else self.ask(cut_label(first), values)
            if r is None:
                return None, [], False
            if r:
                units, sent = second, False
            else:
                aside, units, sent = second + aside, first, True
        return units[0], aside, sent

    def work(self, units, label="ALL"):
        """Bank the plain answers: one batch of everything, and the fallback when it is rejected.

        A batch the judge has already answered `incorrect` in this run is not sent a second time:
        the `pending` pass after a cut that was not judged would otherwise open with the very
        batch ALL was rejected for. It goes straight to narrowing instead, and narrow() answers
        the cuts whose verdict is known in the same way. (The halving inside bank() keeps no
        such memory: grade.bank sends through self.send.)"""
        todo, known_bad = list(units), False
        while todo and self.open():
            known_bad = known_bad or self.is_refused(union(todo))
            if not known_bad:
                if len(todo) == 1 and todo[0].kind == "group":
                    self.bank(todo[0])               # its first request is the batch
                    return
                r = self.ask(label, union(todo))
                if r is None or r:
                    return
            sent = len(todo) == 1                    # one unit: it is the batch that was just rejected
            unit, aside = todo[0], []
            if not sent:
                unit, aside, sent = self.narrow(todo)
                if unit is None:
                    return
            if unit.kind == "group":
                # Rejected itself, or everything else was accepted or set aside: the wrong answer is in it.
                self.bank(unit, rejected=True)
                todo, known_bad = aside, False
            else:
                todo, known_bad = self.fix_class(unit, aside, sent)
            label = "rest"

    def fix_class(self, unit, aside, sent):
        """A label class that holds a wrong answer. The units set aside are banked first, as one
        batch; then the class is offered its family's other names, one per request. Returns
        (units still to work, whether they are known to hold a wrong answer)."""
        ids = list(unit.answers)
        rest = union(aside)
        known_bad = False
        if rest:
            r = self.ask("rest", rest)
            if r is None:
                return [], False
            if r:
                aside = []
            else:
                known_bad = True                     # a second wrong answer, in what was set aside
        key, names = self.names_for(ids[0], unit.name)
        won = None
        for name in names:
            r = self.offer(f"{unit.label}?{name}", {aid: name for aid in ids}, key, name)
            if r is None:
                break
            if r:
                won = name
                break
        if won is not None or (len(ids) == 1 and names):
            for aid in ids:
                self.surprises[aid] = {"sent": unit.answers[aid], "accepted": won}
        if won is None and self.open():
            # No one name fits the whole class, so which of its ids are wrong: a rejection must
            # rest on a verdict of its own. A small class is sent id by id; a larger one is halved.
            if len(ids) > ONE_BY_ONE:
                self.bank(unit, rejected=True)
            elif not (len(ids) == 1 and sent):
                for aid in ids:
                    if aid not in self.banked and aid not in self.bad and self.ask(f"{unit.group}/{aid}", {aid: unit.answers[aid]}) is None:
                        break
            self.retry([aid for aid in ids if aid in self.bad])
        return aside, known_bad

    def retry(self, ids):
        """An id whose answer was rejected alone is offered the other names of its family, alone.
        A name that fits one id goes first for the next."""
        first = []
        for aid in ids:
            if aid in self.banked or aid in self.surprises or not self.open():
                continue
            sent = self.bad.get(aid)
            key, names = self.names_for(aid, sent)
            names = [n for n in first if n in names] + [n for n in names if n not in first]
            hit = None
            for name in names:
                r = self.offer(f"{aid}?{name}", {aid: name}, key, name)
                if r is None:
                    return
                if r:
                    hit, first = name, [name] + [n for n in first if n != name]
                    break
            if names:
                self.surprises[aid] = {"sent": sent, "accepted": hit}

    # -- names the judge has not given yet --

    def on_learn(self, key, name, verdict, scope="key", ids=()):
        """grade.probe's hook: one verdict on a name. A legacy sentinel goes to batch_conventions.json
        and, under its pinned key, to the labels ledger; any other key to the labels ledger."""
        if key in KIND:
            table, field = KIND[key]
            if scope == "key" and verdict == "accepted":
                self.conv[table][field] = name
                self.conv_changed = True
            elif scope == "key" and verdict == "rejected":
                seen = self.conv["rejected"].setdefault(key, [])
                if name not in seen:
                    seen.append(name)
                    self.conv_changed = True
        if scope == "key" and verdict == "accepted":
            self.learned[key] = name
        labels.learn(LEGACY_KEY.get(key, key), name, verdict, scope=scope, answer_ids=list(ids), left=self.left(),
                     attempt_id=self.attempt_id)

    def probe(self, held, skip=()):
        """grade.probe over the held-out answers ({answer id: unsure string or labels.Unsure}).

        Every option's value is taken as the text that goes on the wire (row 329: a list as compact
        JSON, as sort_answers sends a plain list), so the request, the name looked up for its
        verdict row and the rejected pairs of verdicts.jsonl are one text. Row 346: a candidate key
        (labels.candidates) is probed only when the attempt has no deadline; inside a deadline it
        stays unsent and one NOTE per key says why."""
        parsed = {}
        for aid, v in held.items():
            u = v if isinstance(v, labels.Unsure) else labels.parse(v)
            if u is not None and u.key:
                u = labels.Unsure(u.key, [(n, grade.wire_text(x)) for n, x in u.options])
            parsed[aid] = u
        wired = {aid: (u if u is not None and u.key else held[aid]) for aid, u in parsed.items()}

        def send(values):
            aid = next(iter(values))
            u = parsed.get(aid)
            name = next((n for n, v in (u.options if u else ()) if v == values[aid]), None)
            key = u.key if u else None
            if len(values) == 1:
                return self.send(f"{key}?{name}", values, kind="probe", key=LEGACY_KEY.get(key, key), name=name)
            return self.send(f"{key}={name} (other {len(values)} ids)", values, key=LEGACY_KEY.get(key, key), name=name)

        deadline = self.has_deadline()
        out = grade.probe(send, wired, left=self.left, floor=MARGIN, skip=frozenset(skip) | frozenset(self.rejected),
                          on_learn=self.on_learn, order=self.order, max_total=PROBES if self.open() else 0,
                          candidates=not deadline)
        if deadline:
            for key in out.open:
                if grade.is_candidate(key):
                    self.notes.append(grade.candidate_note(key))
        self.open_keys = out.open
        if out.stopped and not self.stopped and out.stopped.startswith("time"):
            self.stopped = out.stopped
        return out

    def probe_proposed(self, group, max_total, max_per_key):
        """The adaptability build: grade.probe over the proposer's candidate keys ({answer id: labels.Unsure}),
        on an attempt with NO deadline only, with a budget of its own. Unlike probe() it leaves open_keys alone:
        a proposed key that stays open is the proposer's (gaps.json's `proposed`), not the solver's."""
        def send(values):
            aid = next(iter(values))
            u = group.get(aid)
            name = next((n for n, v in (u.options if u else ()) if v == values[aid]), None)
            key = u.key if u else None
            return self.send(f"{key}?{name}", values, kind="probe", key=key, name=name)

        if self.has_deadline() or not self.open():
            return None
        return grade.probe(send, group, left=self.left, floor=MARGIN, skip=frozenset(self.rejected),
                           on_learn=self.on_learn, order=self.order, max_total=max_total, max_per_key=max_per_key,
                           candidates=True)

    # -- the outcome --

    def confirm(self):
        """After a response may have been lost (a dropped connection, or `already_solved` to a
        batch sent again), read op=status once: the server knows whether the attempt is CORRECT."""
        http = None
        try:
            resp = self.s.get(gm.GM, params={"op": "status", "challenge": self.cid}, timeout=5)
            http, body = resp.status_code, run.body_of(resp)
        except Exception as e:  # noqa: BLE001 - then the answer stays what the responses said
            body = {"error": type(e).__name__}
        self.requests += 1
        word = body.get("result") or body.get("error")
        self.log.append({"label": "status", "result": word if isinstance(word, str) else None,
                         "at": round(time.perf_counter() - self.t0, 2)})
        if word == "CORRECT":
            self.correct, self.remaining = True, 0
            self.last = {k: v for k, v in body.items() if k not in run.BULKY + ("answer_ids",)}
            if body.get("attempt_id") == self.attempt_id:    # the server names this very attempt
                self.settle_lost(http)

    def settle_lost(self, http=None):
        """The server says the attempt is CORRECT, and the answer that said so never arrived.

        The judge banks an answer only from a batch it accepts, and every batch whose verdict
        did arrive is in the ledger. So an id the ledger does not show as accepted was banked
        from a request that came back without a verdict; when every such request carried the
        same value for it, that value is the accepted one. If that holds for every open id, the
        values are recorded as one row (kind `status`, result CORRECT), which lets
        judge.freeze_key write key.json: without it the Mastery gate reads this Time Trial as
        not closed. If an id went out under two different values in such requests, or a row
        could not be written, nothing is recorded and no key is written.

        A request answered `already_solved` is not such a request: that answer proves the attempt
        was closed before the request arrived, so the request banked nothing. When a teammate
        closes the attempt first (team play shares one attempt), our own batch comes back that
        way, and its answers were never judged: they must not become the key."""
        if not self.attempt_id or self.record_failed:
            return
        sent = {}
        for row in judge.verdicts(self.dir):
            values = row.get("values")
            if (row.get("attempt_id") != self.attempt_id or row.get("result") in JUDGED or not isinstance(values, dict)
                    or row.get("result") in ("already_solved", grade.INVALID)):
                continue                     # invalid_answers (row 329) was refused unread: it banked nothing
            for aid, value in values.items():
                if value not in sent.setdefault(aid, []):
                    sent[aid].append(value)
        todo = [aid for aid in self.order if aid not in self.banked]
        unclear = [aid for aid in todo if len(sent.get(aid, [])) != 1 or gm.is_unsure(sent[aid][0])]
        if not todo:
            return
        if unclear:
            print(f"NOTE CORRECT by op=status, but {len(unclear)} answer(s) cannot be told from the requests that came back "
                  f"without a verdict (first: {unclear[0]}); key.json is not written", file=sys.stderr)
            return
        inferred = {aid: sent[aid][0] for aid in todo}
        try:
            judge.record(self.dir, inferred, "CORRECT", remaining=0, left=self.left(), http=http, kind="status",
                         attempt_id=self.attempt_id)
        except Exception as e:  # noqa: BLE001 - then there is no key, and the server's CORRECT still stands
            print(f"NOTE verdicts.jsonl could not be written ({type(e).__name__}: {e}); key.json is not written", file=sys.stderr)
            return
        self.banked.update(inferred)
        if self.prior:
            self.prior.saw(inferred, "CORRECT", self.left())   # row 415: the lost batch was accepted after all
        self.log.append({"label": "status: the answers of the lost batch", "n": len(inferred), "result": "CORRECT",
                         "at": round(time.perf_counter() - self.t0, 2)})

    def open_count(self) -> int:
        """Answer ids still open: the judge's own count when it gave one."""
        return self.remaining if self.remaining is not None else len(self.order) - len(self.banked)

    def result(self) -> str:
        if self.correct:
            return "CORRECT"
        if not self.judged and self.unjudged:
            return self.unjudged[-1]
        if not self.judged and not self.banked:
            return "not_submitted"
        return "accepted" if self.banked else "incorrect"

    def infra(self) -> bool:
        """True when the attempt was played and the judge gave no verdict on anything: nothing
        judged in this run, and nothing banked by an earlier run on the same attempt."""
        return not self.correct and not self.judged and not self.banked


def scrub_switches() -> list:
    """Remove the solver switches (and, against the real Game Master, the rehearsal knobs) from
    this process's environment. Returns the names that were set."""
    removed = lanes.clean_env()[1]
    for name in removed:
        os.environ.pop(name, None)
    return removed


def legacy_setup():
    """Import the Batch and VBScript modules and read the legacy conventions file. Returns
    (batch module, conventions). A name the file holds for a VBScript wrapper replaces the
    module's own. A shape the file lists with an empty value (null or "") is one whose name is
    not known: its answers become a sentinel, are held out of every batch and are probed. A
    shape the file does not list is answered by the module's own, judge-confirmed name."""
    import batch
    import vbscript
    conv = batch.load_conventions() or {}
    for table in ("expansion", "control", "rejected", "vbscript_control"):
        if not isinstance(conv.get(table), dict):
            conv[table] = {}

    def blank(table, key):
        return key in conv[table] and not conv[table][key]

    if blank("expansion", "percent"):
        batch.EXP_LABEL["percent"] = "@percent"
    for kind in ("errorlevel", "if_defined"):
        if blank("control", kind):
            batch.CONTROL[kind] = "@" + kind
    for key in ("on_error", "if", "for"):
        value = conv["vbscript_control"].get(key)
        if isinstance(value, str) and value:
            vbscript.CONTROL_NAMES[key] = value
        elif blank("vbscript_control", key):
            vbscript.CONTROL_NAMES[key] = "@v" + key
    return batch, conv


def write_conventions(path: Path, conv: dict):
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(conv, indent=2) + "\n")
    os.replace(tmp, path)


def shelve(folder: Path, attempt: dict):
    """Before a new variant is saved: move what the ladder wrote for the variant already in
    `folder` to history/<its attempt id>/, where run.save_attempt puts that variant's
    attempt.json and artifact.

    tools/preflight.py reads each variant's verdicts from the variant's own folder, so a failed
    variant whose verdicts.jsonl stayed behind would look as if the judge had rejected nothing,
    and the retry gate would pass a solver that repeats a rejected answer. run.save_attempt is
    to move these files itself (plan B1, item 9); a file it has already moved is not here any
    more, and one already in history/ is left alone, so the two do not collide."""
    try:
        prev = json.loads((folder / "attempt.json").read_text()).get("attempt_id")
    except (OSError, ValueError, AttributeError):
        return
    new = attempt.get("attempt_id")
    if not (isinstance(prev, str) and prev and new and prev != new):
        return
    if Path(prev).name != prev or prev in (".", ".."):
        return      # an attempt id is one folder name; anything else is not used as a path
    hist = folder / "history" / prev
    for name in SHELVED:
        if (folder / name).exists() and not (hist / name).exists():
            hist.mkdir(parents=True, exist_ok=True)
            shutil.move(str(folder / name), str(hist / name))


def question_rows(attempt) -> list:
    """[(answer id, question id without its set prefix, set number)] in the order run.split_sets
    hands the sets out (by set number, then question order), without expanding any delivery."""
    groups = {}
    for q, aid in zip(attempt.get("questions") or [], run.answer_ids_for(attempt)):
        n, shaped = run.shaped(q, aid)
        groups.setdefault(n, []).append((shaped["answer_id"], shaped["qid"], n))
    return [row for n in sorted(groups) for row in groups[n]]


# ---- binary=pool (backlog row 121): a Binary Mastery's deliveries in forked workers --------------
#
# Day 8: the Binary Mastery's five 67 MB deliveries took 3.3 s to expand and solve one after
# another inside a 27 s window. With the switch on (off by default; challenges/_opener.json
# {"binary": "pool"}), main() forks POOL_WORKERS processes before any request, thread or TLS
# session exists (a process forked after those can crash in the child on macOS: row 28's rule).
# Each waits on a pipe. After the download the attempt is on disk, and each worker is told one
# delivery: it reads that file, expands it with run.split_sets exactly as the serial path does,
# solves the sets it serves under a time budget of its own and sends the answers back. A worker
# that dies, fails or is not back within its share of the budget costs nothing but that share:
# its sets are then solved here, serially, with what is left. The submit never depends on the pool.

POOL_WORKERS = 6          # forked workers (the floor); sized up to the lane's delivery/set trajectory by pool_workers_for()
POOL_WORKERS_MAX = 12     # the most workers forked; each holds one expanded ~34 MB delivery for a fraction of a second
POOL_WORKER_HEADROOM = 2  # workers above the most deliveries/sets seen, so the next day's one-more delivery still runs in one round
POOL_SHARE = 0.5          # of the solve budget the workers may use before the serial path takes over
POOL_WAIT_MAX = 4.0       # seconds the parent waits for its workers on an attempt WITH a deadline
POOL_UNTIMED_WAIT_MAX = 20.0  # ... and without one (a regular/practice/expired-replay attempt): the slow serial
                          # parent fallback is for a stuck worker, not for deliveries that simply need a second round
                          # (prefix_pool's UNTIMED_WAIT_MAX; before this, the 4 s cap dumped a Day-24 Mastery's last
                          # deliveries to the serial parent at ~3.6 s each, 11.2 s in all against 3.9 s pooled)
POOL_MARGIN = 0.1         # a worker stops its solver this long before the parent stops waiting
POOL_LANES = ("binary-reverse-engineering",)
# script=pool (backlog row 336, built 2026-10-17): a Script Analysis Mastery's SETS in the same forked workers.
# Day 17: one delivery of five numbered inner zips (635 AES members), split 0.84 s and five solves 1.38 s, all
# serial, 2.22 s in all. Each worker expands only its own set's inner zip and solves that set (about 0.45 s), so
# the five run side by side. Off unless challenges/_opener.json holds {"script": "pool"}.
SET_POOL_LANES = ("script-analysis",)


def set_pool_workers() -> int:
    """script=pool (backlog row 541): how many workers to fork for a Script Analysis Mastery, sized to the set
    count. The one delivery of the newest saved Script Mastery is a zip of numbered inner evidence-NN.zip, one a
    set; its count is read from that zip's central directory (zipfile.namelist, no extraction, never a JSON parse)
    before the fork, and the pool is forked min(POOL_WORKERS_MAX, count + POOL_WORKER_HEADROOM) so a Mastery with
    few sets does not over-fork and one with many is not left to a second round (Day 27: 11 sets solved in two
    rounds on 6 workers; now one round on 12). A cheap read of the directory only; any trouble, or no saved
    Mastery, falls back to POOL_WORKERS (6). Nothing about the answers changes: _dispatch feeds the sets to the
    workers and a set no worker returns is solved by the serial path, byte-identical either way."""
    try:
        import zipfile
        base = Path(gm.CHALLENGES)
        newest, newest_day = None, -1
        for lane_name in SET_POOL_LANES:
            for z in base.glob(f"day-*/{lane_name}-*/mastery/artifact/*.zip"):
                m = re.search(r"day-(\d+)", str(z))
                day = int(m.group(1)) if m else -1
                if day >= newest_day:
                    newest, newest_day = z, day
        if newest is None:
            return POOL_WORKERS
        with zipfile.ZipFile(newest) as zf:
            count = sum(1 for n in zf.namelist() if re.search(r"evidence-?0*\d+\.zip$", n, re.I))
        if count < 1:
            return POOL_WORKERS
        return min(POOL_WORKERS_MAX, count + POOL_WORKER_HEADROOM)
    except Exception:  # noqa: BLE001 - any trouble: the floor
        return POOL_WORKERS


def pool_workers_for(lane: str, unit: str) -> int:
    """How many workers to fork, sized to the lane's Mastery trajectory. The pool is forked before the
    delivery is known (macOS fork safety: no thread may exist yet), so the count is read from saved Masteries.
    For the delivery pool (binary): a Binary Mastery's delivery count has grown by about one a day (Day 22 six,
    23 seven, 24 eight, 25 nine), and six workers left the last two or three deliveries of each to the slow
    serial parent. The count is the most delivery sub-folders any saved Mastery of the lane has, plus headroom
    for the next day, clamped to [POOL_WORKERS, POOL_WORKERS_MAX]. For the set pool (script, row 541): the inner
    evidence-NN.zip of the newest saved Script Mastery, via set_pool_workers(). A cheap filesystem scan (about
    1 ms), never a JSON parse, so it does not sit on the release critical path; any trouble falls back to
    POOL_WORKERS."""
    if unit == "set":
        return set_pool_workers()
    if unit != "delivery":
        return POOL_WORKERS
    most = 0
    try:
        for lane_name in POOL_LANES:
            base = Path(gm.CHALLENGES)
            for art in base.glob(f"day-*/{lane_name}-*/mastery/artifact"):
                try:
                    n = sum(1 for e in os.scandir(art) if e.is_dir())
                except OSError:
                    continue
                most = max(most, n)
    except Exception:  # noqa: BLE001 - any trouble: the floor
        return POOL_WORKERS
    return max(POOL_WORKERS, min(POOL_WORKERS_MAX, most + POOL_WORKER_HEADROOM))


# The set pool below (_pool_wait, SetPool, solve, solve_cap) has a tested master copy in ctf/adapt/setpool.py
# (B-036), free of the Game Master modules this file needs. That copy is the source of truth: fix it there.
# When the Huntress adapter (B-005) restores this runner, import SetPool and solve from ctf.adapt.setpool
# and drop this copy; the clock runner (B-252/B-003) imports ctf.adapt.setpool, not this file.
def _pool_wait(budget, deadline: bool) -> float:
    """Seconds the parent waits for its workers: the solve budget's share, capped at POOL_WAIT_MAX with a
    deadline and POOL_UNTIMED_WAIT_MAX without one (prefix_pool.wait_for)."""
    cap = POOL_WAIT_MAX if deadline else POOL_UNTIMED_WAIT_MAX
    return cap if budget is None else max(0.2, min(budget * POOL_SHARE, cap))


def _pool_solve(solver, attempt, paths, index, budget) -> dict:
    """One delivery in a worker: its file from disk, expanded and split as run.split_sets does with
    every other delivery empty, then solve() over the sets that got it. Never raises."""
    try:
        blobs = [b""] * len(paths)
        blobs[index] = Path(paths[index]).read_bytes()
        locked, notes, errors = [], [], []
        sets = [s for s in run.split_sets(attempt, blobs, locked, notes) if s[3]["delivery"]]
        raw, timed_out, said = solve(solver, [] if locked else sets, budget, errors)
        return {"index": index, "sets": [s[0] for s in sets], "raw": raw, "errors": errors, "said": said,
                "locked": [str(x) for x in locked], "notes": notes, "timed_out": timed_out}
    except BaseException:  # noqa: BLE001 - the parent solves this delivery itself
        return {"index": index, "failed": traceback.format_exc().strip().splitlines()[-1][:200]}


def set_member_rule(n: int):
    """run.split_sets's rule for the member of a one-bundle delivery that serves set `n`."""
    return re.compile(rf"(?<!\d)0*{n}(?=\.[A-Za-z0-9]+$)")


def set_members(attempt: dict, blob: bytes):
    """{set number: the bundle's member name} when the one delivery can be split by set in a worker exactly as
    run.split_sets splits it, else None: two or more sets, the delivery a zip whose every member is unencrypted
    and serves exactly one set by the name rule (each set exactly one member, no other member, no name twice).
    Anything else (a locked or extra member, a delivery named per set) is the serial path's."""
    try:
        groups = {}
        for q, aid in zip(attempt.get("questions") or [], run.answer_ids_for(attempt)):
            n, _ = run.shaped(q, aid)
            groups.setdefault(n, 0)
        order = sorted(groups)
        if len(order) < 2 or 0 in order or not blob or blob[:4] != b"PK\x03\x04":
            return None
        names = [a.get("filename") or f"delivery-{i}" for i, a in enumerate(attempt.get("artifacts") or [])]
        if len(names) != 1:
            return None
        import zipfile
        infos = [i for i in zipfile.ZipFile(io.BytesIO(blob)).infolist() if not i.is_dir()]
        if len(infos) != len(order) or len({i.filename for i in infos}) != len(infos) \
                or any(i.flag_bits & 1 or i.compress_type == 99 or " -> " in i.filename for i in infos):
            return None
        out = {}
        for n in order:
            rule = set_member_rule(n)
            hits = [i.filename for i in infos if rule.search(f"{names[0]} -> {i.filename}")]
            if len(hits) != 1:
                return None
            out[n] = hits[0]
        return out if len(set(out.values())) == len(out) else None
    except Exception:  # noqa: BLE001 - anything unexpected is the serial path's
        return None


def _pool_solve_set(solver, attempt, path, n, members, budget) -> dict:
    """One set of a one-bundle Mastery in a worker (script=pool): its own inner zip read from the saved
    delivery, expanded as run.split_sets expands it (a fresh run.Keys), the set's ctx as split_sets builds it
    (siblings included where it adds them), then solve() over that one set. Never raises."""
    try:
        import zipfile
        blob = Path(path).read_bytes()
        bundle = zipfile.ZipFile(io.BytesIO(blob))
        groups = {}
        for q, aid in zip(attempt.get("questions") or [], run.answer_ids_for(attempt)):
            k, question = run.shaped(q, aid)
            groups.setdefault(k, []).append(question)
        bodies = {k: bundle.read(name) for k, name in members.items()}
        keys = run.Keys(attempt)
        files = {}
        run.expand(members[n], bodies[n], files, keys=keys)
        ctx = {"set": n, "delivery_name": members[n], "delivery": bodies[n], "attempt": attempt}
        if len(members) > 1 and sum(len(b) for b in bodies.values()) <= run.SIBLINGS_MAX:
            ctx["siblings"] = dict(bodies)
        if keys.locked:
            return {"set": n, "locked": [str(x) for x in keys.locked], "raw": {}, "errors": [], "said": ""}
        errors = []
        raw, timed_out, said = solve(solver, [(n, groups[n], files, ctx)], budget, errors)
        return {"set": n, "raw": raw, "errors": errors, "said": said, "locked": [], "timed_out": timed_out}
    except BaseException:  # noqa: BLE001 - the parent solves this set itself
        return {"set": n, "failed": traceback.format_exc().strip().splitlines()[-1][:200]}


def _pool_worker(conn, solver, parent):
    """A worker's whole life: wait for (attempt, paths, index, budget), answer, wait again. It ends
    on None, on a closed pipe, and when the process that forked it is gone."""
    with contextlib.suppress(Exception):
        # Nothing a solver prints here may reach the ladder's pinned output, and a worker must never
        # hold the pipe its parent's output goes to (tools/open_day.py reads that pipe to its end).
        sys.stdout = io.StringIO()
        null = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null, 1)
        os.dup2(null, 2)
        os.close(null)
    try:
        while True:
            if not conn.poll(1.0):
                if os.getppid() != parent:
                    return
                continue
            task = conn.recv()
            if task is None:
                return
            if isinstance(task, tuple) and task and task[0] == "set":
                conn.send(_pool_solve_set(solver, *task[1:]))
            else:
                conn.send(_pool_solve(solver, *task))
    except (EOFError, OSError, KeyboardInterrupt):
        return
    finally:
        os._exit(0)                     # no atexit handler and no buffer of the parent's is run or flushed here


class SetPool:
    """The forked workers of binary=pool (one task a delivery) and script=pool (one task a set). maybe() gives
    None unless the lane's switch is on, the id is a Mastery of a POOL_LANES or SET_POOL_LANES lane and no
    thread is running yet."""

    unit, word = "delivery", "binary"

    def __init__(self, solver, workers=POOL_WORKERS):
        import multiprocessing
        ctx = multiprocessing.get_context("fork")
        for stream in (sys.stdout, sys.stderr):
            with contextlib.suppress(Exception):
                stream.flush()          # nothing buffered is inherited, so nothing is printed twice
        self.workers, parent = [], os.getpid()
        for _ in range(workers):
            ours, theirs = ctx.Pipe()
            proc = ctx.Process(target=_pool_worker, args=(theirs, solver, parent), daemon=True)
            proc.start()
            theirs.close()
            self.workers.append((proc, ours))

    @classmethod
    def maybe(cls, cid, lane, legacy, solver, notes):
        unit, word = ("delivery", "binary") if lane in POOL_LANES else ("set", "script") if lane in SET_POOL_LANES else (None, None)
        # analyze.py runs `legacy` (the Batch and VBScript tables legacy_setup() set): main() sets them up
        # before it forks, so every worker holds the same tables as the serial path. binary=pool keeps its rule.
        if (legacy and unit != "set") or unit is None or not str(cid).endswith("/mastery") or not run.switch_on(word):
            return None
        if threading.active_count() > 1:
            notes.append(f"{word}=pool: a thread was already running, so no worker was forked; the sets are solved one by one")
            return None
        try:
            pool = cls(solver, workers=pool_workers_for(lane, unit))
        except Exception as e:  # noqa: BLE001
            notes.append(f"{word}=pool: the workers could not be forked ({type(e).__name__}: {e}); "
                         "the sets are solved one by one")
            return None
        pool.unit, pool.word = unit, word
        return pool

    def _dispatch(self, items, build_task, result_key, wait):
        """Queue `items` to the forked workers with at most ONE in-flight task per worker, handing a
        worker its next item only once it has answered the last. So a slow item never waits behind a
        fast one in a worker's pipe (backlog row 485: with `k % len(workers)` two items went down one
        pipe and the second sat out the first, and a Mastery with more sets than workers lost them),
        every worker stays busy, and a worker's pipe never fills behind a task it is still solving.
        Returns {item: msg} for the items a worker answered within `wait` seconds of the start; an item
        whose worker died, that could not be sent, or that did not answer in time is simply absent, so
        the caller solves it serially and no item is ever lost. `result_key` is the field each worker
        echoes its item under ("set" or "index")."""
        from multiprocessing import connection
        t0 = time.perf_counter()
        results = {}
        pending = list(items)
        by_conn = {id(c): (p, c) for p, c in self.workers}
        idle = list(self.workers)            # (proc, conn) pairs free to take an item
        inflight = {}                        # id(conn) -> (item, conn) currently being solved

        def feed():
            while pending and idle:
                proc, conn = idle.pop()
                item = pending.pop(0)
                try:
                    conn.send(build_task(item))
                    inflight[id(conn)] = (item, conn)
                except Exception:            # noqa: BLE001 - that item falls to the serial path
                    pass

        feed()
        while inflight:
            left = t0 + wait - time.perf_counter()
            if left <= 0:
                break
            for conn in connection.wait([c for _, c in inflight.values()], timeout=min(left, 0.05)):
                item, _ = inflight.pop(id(conn), (None, None))
                try:
                    msg = conn.recv()
                except (EOFError, OSError):
                    continue                 # the worker is gone: its item falls to the serial path
                if isinstance(msg, dict) and msg.get(result_key) == item:
                    results[item] = msg
                if self._usable(conn):       # the worker is free again: give it the next pending item
                    idle.append(by_conn[id(conn)])
            feed()
        return results

    def solve_sets(self, solver, attempt, path, blob, members, budget, errors, notes, deadline=True):
        """script=pool: (raw answers by answer id, timed out, the solvers' stderr, locked archives), as the
        serial path's split_sets and solve() give them. Each set goes to a worker of its own; a set whose
        worker failed, raised, ran out of time, met a locked archive or was not back within its share is
        solved here, serially, after run.split_sets (and with any locked archive, every set is: the serial
        path is the one that decides a STOP)."""
        t0 = time.perf_counter()
        order = sorted(members)
        wait = _pool_wait(budget, deadline)
        results = self._dispatch(order, lambda n: ("set", attempt, path, n, members, max(0.05, wait - POOL_MARGIN)),
                                 "set", wait)
        raw, said, done, locked_seen = {}, "", [], False
        for n in order:
            msg = results.get(n)
            if msg is None:
                continue
            if msg.get("locked"):
                locked_seen = True
                notes.append(f"script=pool: set {n} holds an archive no known password opens; every set is solved here")
                continue
            if "failed" in msg or not isinstance(msg.get("raw"), dict):
                notes.append(f"script=pool: the worker of set {n} failed ({msg.get('failed', 'no answers')})")
                continue
            if msg.get("errors") or msg.get("timed_out"):
                why = str((msg.get("errors") or ["its time budget ran out"])[0]).splitlines()[0][:120]
                notes.append(f"script=pool: the worker of set {n} did not finish cleanly ({why})")
                continue
            raw.update(msg["raw"])
            said += msg.get("said") or ""
            done.append(n)
        if locked_seen:
            raw, said, done = {}, "", []
        rest = [n for n in order if n not in done]
        took = time.perf_counter() - t0
        locked, timed_out = [], False
        if rest:
            self.close()                # a worker still at work must not go on beside the serial path
            sets = [st for st in run.split_sets(attempt, [blob], locked, notes) if st[0] in rest]
            left = None if budget is None else max(0.05, budget - (time.perf_counter() - t0))
            more, timed_out, said2 = solve(solver, [] if locked else sets, left, errors)
            raw.update(more)
            said += said2
        notes.append(f"script=pool: {len(done)} of {len(order)} sets solved by workers in {took:.2f}s"
                     + (f"; set {', '.join(str(n) for n in rest)} solved here instead "
                        f"({time.perf_counter() - t0:.2f}s in all)" if rest else ""))
        return raw, timed_out, said, locked

    def solve(self, solver, attempt, paths, blobs, budget, errors, notes, deadline=True):
        """(raw answers by answer id, timed out, the solvers' stderr, locked archives), as the
        serial path's split_sets and solve() give them."""
        t0 = time.perf_counter()
        n = len(paths)
        wait = _pool_wait(budget, deadline)
        results = self._dispatch(range(n), lambda i: (attempt, paths, i, max(0.05, wait - POOL_MARGIN)), "index", wait)
        raw, said, locked, timed_out, done = {}, "", [], False, []
        for i in sorted(results):
            msg = results[i]
            if "failed" in msg or not isinstance(msg.get("raw"), dict):
                notes.append(f"binary=pool: the worker of delivery {i + 1} failed ({msg.get('failed', 'no answers')})")
                continue
            raw.update(msg["raw"])          # what it has is kept: the serial path can only add to it
            said += msg.get("said") or ""
            locked.extend(msg.get("locked") or [])
            for note in msg.get("notes") or []:
                if note not in notes:
                    notes.append(note)
            if (msg.get("errors") or msg.get("timed_out")) and not msg.get("locked"):
                # A solver that raised or ran out of time in the worker may do neither here (trouble
                # that is the fork's, a worker short of its share): the delivery is solved again.
                why = str((msg.get("errors") or ["its time budget ran out"])[0]).splitlines()[0][:120]
                notes.append(f"binary=pool: the worker of delivery {i + 1} did not finish cleanly ({why})")
                continue
            done.append(i)
        rest = [i for i in range(n) if i not in done]
        took = time.perf_counter() - t0
        if rest:
            self.close()                # a worker still at work must not go on beside the serial path
            only = [blobs[i] if i in rest else b"" for i in range(n)]
            more_locked = []
            sets = [s for s in run.split_sets(attempt, only, more_locked, notes) if s[3]["delivery"]]
            locked.extend(more_locked)
            left = None if budget is None else max(0.05, budget - (time.perf_counter() - t0))
            more, late, said2 = solve(solver, [] if more_locked else sets, left, errors)
            raw.update(more)
            said += said2
            timed_out = timed_out or late
        notes.append(f"binary=pool: {len(done)} of {n} deliveries solved by workers in {took:.2f}s"
                     + (f"; delivery {', '.join(str(i + 1) for i in rest)} solved here instead "
                        f"({time.perf_counter() - t0:.2f}s in all)" if rest else ""))
        return raw, timed_out, said, locked

    def solve_stream(self, solver, attempt, paths, writer, run_download, budget, errors, notes, deadline=True):
        """binary=pool with download/solve overlap (backlog row 544): each delivery is handed to a free worker
        the moment its bytes are on disk, so solving runs beside the remaining downloads. Keeps binary=pool's
        per-delivery worker model and fetch_each's failure semantics.

        `run_download(on_ready)` runs the parallel download and calls `on_ready(i, blob)` for each delivery that
        lands (after its sha256 check); it returns (blobs, failed) when every delivery is done. `writer(i, blob)`
        puts the bytes on disk at paths[i]. `paths` is every delivery's final path, computed up front; a worker
        reads only its own index, so a path whose delivery has not landed yet is never touched.

        Returns (raw, timed_out, said, locked, blobs, failed). The answers are what the barrier solve() gives,
        byte for byte: each worker runs the same solver on the same bytes under the same per-delivery budget, and
        the solve budget still runs for `wait` seconds from the moment the last download is in (the barrier
        point), exactly as the barrier path measures it; only the wall-clock schedule differs. A worker that
        died, failed, raised, met a locked archive or was not back by then, and a delivery that never
        downloaded, fall to the serial path here, as in solve()."""
        import queue as _queue
        from multiprocessing import connection
        n = len(paths)
        wait = _pool_wait(budget, deadline)
        ready_q = _queue.Queue()
        done_dl = threading.Event()
        box = {}

        def on_ready(i, blob):
            # In a download thread: put the delivery on disk, then hand its index to the driver below.
            try:
                writer(i, blob)
                ready_q.put(i)
            except Exception:   # noqa: BLE001 - that delivery simply falls to the serial path
                pass

        def drive_download():
            try:
                box["result"] = run_download(on_ready)
            except BaseException:   # noqa: BLE001
                box["error"] = traceback.format_exc()
                box["result"] = ([b""] * n, [])
            finally:
                done_dl.set()

        t0 = time.perf_counter()
        dl = threading.Thread(target=drive_download, name="pool-download", daemon=True)
        dl.start()

        results = {}
        idle = list(self.workers)
        inflight = {}                        # id(conn) -> (index, conn)
        by_conn = {id(c): (p, c) for p, c in self.workers}
        barrier = [None]                     # perf_counter when every download is in; the solve budget runs from here

        def feed():
            while idle:
                try:
                    i = ready_q.get_nowait()
                except _queue.Empty:
                    break
                proc, conn = idle.pop()
                try:
                    conn.send((attempt, paths, i, max(0.05, wait - POOL_MARGIN)))
                    inflight[id(conn)] = (i, conn)
                except Exception:            # noqa: BLE001 - that delivery falls to the serial path
                    pass

        try:
            while True:
                feed()
                if done_dl.is_set() and barrier[0] is None:
                    barrier[0] = time.perf_counter()
                if not inflight:
                    if done_dl.is_set() and ready_q.empty():
                        break
                    time.sleep(0.005)        # a download still in flight, or every worker busy with none free
                    continue
                if barrier[0] is None:
                    to = 0.02                # the download is still running: poll, do not cut the solve budget yet
                else:
                    left = barrier[0] + wait - time.perf_counter()
                    if left <= 0:
                        break                # out of the solve budget: the rest go to the serial path
                    to = min(left, 0.05)
                for conn in connection.wait([c for _, c in inflight.values()], timeout=to):
                    i, _ = inflight.pop(id(conn), (None, None))
                    try:
                        msg = conn.recv()
                    except (EOFError, OSError):
                        continue              # the worker is gone: its delivery falls to the serial path
                    if isinstance(msg, dict) and msg.get("index") == i:
                        results[i] = msg
                    if self._usable(conn):
                        idle.append(by_conn[id(conn)])
        except Exception:                    # noqa: BLE001 - never the submit's undoing; join and solve the rest serially
            notes.append("binary=pool: the overlap driver failed (" + traceback.format_exc().strip().splitlines()[-1][:160]
                         + "); the deliveries left are solved one by one")
        dl.join()
        blobs, failed = box.get("result", ([b""] * n, []))
        if box.get("error"):
            notes.append("binary=pool: the download thread failed (" + box["error"].strip().splitlines()[-1][:160] + ")")
        ref = barrier[0] if barrier[0] is not None else t0

        # From here the result handling is solve()'s, so the answers are the barrier path's, byte for byte.
        raw, said, locked, timed_out, done = {}, "", [], False, []
        for i in sorted(results):
            msg = results[i]
            if "failed" in msg or not isinstance(msg.get("raw"), dict):
                notes.append(f"binary=pool: the worker of delivery {i + 1} failed ({msg.get('failed', 'no answers')})")
                continue
            raw.update(msg["raw"])
            said += msg.get("said") or ""
            locked.extend(msg.get("locked") or [])
            for note in msg.get("notes") or []:
                if note not in notes:
                    notes.append(note)
            if (msg.get("errors") or msg.get("timed_out")) and not msg.get("locked"):
                why = str((msg.get("errors") or ["its time budget ran out"])[0]).splitlines()[0][:120]
                notes.append(f"binary=pool: the worker of delivery {i + 1} did not finish cleanly ({why})")
                continue
            done.append(i)
        rest = [i for i in range(n) if i not in done]
        if rest:
            self.close()                     # a worker still at work must not go on beside the serial path
            only = [blobs[i] if i in rest else b"" for i in range(n)]
            more_locked = []
            sets = [s for s in run.split_sets(attempt, only, more_locked, notes) if s[3]["delivery"]]
            locked.extend(more_locked)
            left = None if budget is None else max(0.05, budget - (time.perf_counter() - ref))
            more, late, said2 = solve(solver, [] if more_locked else sets, left, errors)
            raw.update(more)
            said += said2
            timed_out = timed_out or late
        took = time.perf_counter() - ref
        notes.append(f"binary=pool: {len(done)} of {n} deliveries solved by workers in {took:.2f}s"
                     " (overlapped with the download, row 544)"
                     + (f"; delivery {', '.join(str(i + 1) for i in rest)} solved here instead "
                        f"({time.perf_counter() - ref:.2f}s in all)" if rest else ""))
        return raw, timed_out, said, locked, blobs, failed

    def _usable(self, conn) -> bool:
        """True while the worker behind `conn` lives or has an answer waiting in the pipe."""
        try:
            return any(proc.is_alive() for proc, c in self.workers if c is conn) or conn.poll(0)
        except Exception:  # noqa: BLE001
            return False

    def close(self):
        for proc, conn in self.workers:
            with contextlib.suppress(Exception):
                conn.close()
            with contextlib.suppress(Exception):
                if proc.is_alive():
                    proc.terminate()
        for proc, _ in self.workers:
            with contextlib.suppress(Exception):
                proc.join(0.2)
                if proc.is_alive():
                    proc.kill()
                    proc.join()
                proc.close()
        self.workers = []


def stream_pool_on() -> bool:
    """Backlog row 544: overlap a Binary Mastery's download with the binary=pool solve, on by default.
    CTF_POOL_STREAM=off is the way back (the barrier path)."""
    return ctf_env.get("CTF_POOL_STREAM", "").lower() != "off"


def run_binary_stream(job, cid, attempt, clock, timed):
    """Backlog row 544: download a Binary Mastery's deliveries and solve each in a forked worker as it lands,
    so the solve overlaps the remaining downloads. Returns (blobs, failed, pooled, folder); `pooled` is
    (raw, timed_out, said, locked) when the pool ran, else None (the caller solves serially from `blobs`).
    Keeps binary=pool's per-delivery worker model and fetch_each's failure semantics, and never raises for a
    recoverable fault."""
    arts = attempt["artifacts"]
    n = len(arts)
    folder = run.attempt_dir(cid)
    # The history move and attempt.json come BEFORE any new delivery is written: run.save_attempt moves the
    # old variant's 'artifact' folder to history/ on a retry, so the new deliveries must not be on disk yet.
    try:
        shelve(folder, attempt)
    except Exception as e:  # noqa: BLE001 - the rows carry their attempt id, so the run goes on
        job.notes.append(f"the earlier variant's verdict files were not moved to history/ ({type(e).__name__}: {e})")
    try:
        folder = run.save_attempt(cid, attempt, [])
    except Exception:  # noqa: BLE001
        job.errors.append("could not save the attempt\n" + traceback.format_exc())
    art_dir = folder / "artifact"
    paths = [str(gm.artifact_path(art_dir, arts, i)) for i in range(n)]

    def writer(i, blob):
        p = Path(paths[i])
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(blob)

    def run_download(on_ready):
        return run.fetch_each(job.s, cid, arts, clock if timed else None, on_ready=on_ready)

    nsets = len({x for _, _, x in question_rows(attempt)}) or 1
    left = clock.left() if timed else None
    budget = lanes.ladder_budget(left, n, nsets)
    if budget is None:
        budget = max(getattr(run, "UNTIMED_SOLVE_CAP", 20.0), lanes.LADDER_CAP * max(n, nsets))
    pooled = None
    try:
        raw, timed_out, said, locked, blobs, failed = job.pool.solve_stream(
            job.solver, attempt, paths, writer, run_download, budget, job.errors, job.notes,
            deadline=timed or bool(attempt.get("deadline")))
        pooled = (raw, timed_out, said, locked)
    except Exception:  # noqa: BLE001 - never the submit's undoing; the download already ran inside solve_stream
        job.notes.append("binary=pool: the overlapped pool failed (" + traceback.format_exc().strip().splitlines()[-1][:160]
                         + "); every set solved one by one instead")
        with contextlib.suppress(Exception):
            job.pool.close()
        # solve_stream only raises before run_download started (a programming fault): fetch the deliveries
        # the plain way so the caller's serial path has the bytes on disk.
        try:
            blobs, failed = run.fetch_each(job.s, cid, arts, clock if timed else None)
            for i, data in enumerate(blobs):
                if data:
                    writer(i, data)
        except Exception:  # noqa: BLE001
            blobs, failed = [b""] * n, ["download failed in the stream fallback"]
    job.notes += getattr(run, "download_notes", list)()
    job.errors += failed
    return blobs, failed, pooled, folder


def pool_prefixes(job, attempt, path, blobs, cap, timed):
    """A Binary Time Trial through the prefix pool: (raw answers by answer id, timed out, the solver's stderr,
    locked archives), as the serial path's split_sets and solve() give them, or None for the serial path
    (tools/prefix_pool.py says when)."""
    t0 = time.perf_counter()
    pooled = job.pool.solve(job.solver, attempt, path, cap, timed, job.notes, size=len(blobs[0]))
    if pooled is None:
        return None
    for line in pooled.unread:
        if line not in job.notes:
            job.notes.append(line)
    raw = {}
    for _, q in pooled.rows:
        value = pooled.got.get(q["qid"])
        if value is not None and not is_blank(value):
            raw[q["answer_id"]] = value
    said, timed_out, locked = pooled.said, False, []
    if pooled.rest:
        more_notes = []
        sets = run.split_sets(attempt, [b or b"" for b in blobs], locked, more_notes)
        if locked:
            return {}, False, "", locked     # the caller's STOP: nothing is solved or sent
        left = max(0.05, cap - (time.perf_counter() - t0))
        with prefix_pool.only(pooled.rest):
            more, timed_out, said2 = solve(job.solver, sets, left, job.errors)
        raw.update(more)
        said += said2
    job.notes.append(prefix_pool.rest_note(pooled, t0))
    return raw, timed_out, said, locked


def solve_cap(deliveries: int, sets: int) -> float:
    """The longest a solver may run inside a window, before the window itself is looked at: the
    ladder's cap for each delivery or each set, whichever is more (the rule is lanes.ladder_budget)."""
    return lanes.LADDER_CAP * max(1, int(deliveries or 1), int(sets or 1))


def solve(solver, sets, budget, errors):
    """Run the solver over every set under one time budget. Returns ({answer id: raw value},
    timed out, the solver's stderr). When the budget runs out (or the solver raises) the answers
    it had put into ctx['partial'] for the set in flight are taken.

    Backlog row 163: each set runs under a watchdog of its own, which keeps back half of a fair share
    (budget / sets / 2) for every set still to come. One set that cannot be read in time (a hostile or
    huge member) loses only its own unanswered ids; the sets after it are still solved."""
    raw, timed_out, said = {}, False, io.StringIO()
    end = None if budget is None else time.perf_counter() + budget
    keep = 0.0 if budget is None else budget / max(1, len(sets)) / 2

    def take(qs, got):
        for q in qs:
            value = (got or {}).get(q["qid"])
            if value is not None and not is_blank(value):
                raw[q["answer_id"]] = value

    with contextlib.redirect_stderr(said):
        for i, (n, qs, files, ctx) in enumerate(sets):
            if not ctx["delivery"]:
                errors.append(ctf_deliveries.unsolved_line(n, ctx))     # B-042: names split_sets' reason
                continue
            limit = None
            if end is not None:
                left = end - time.perf_counter()
                if left <= 0.01:
                    timed_out = True
                    errors.append(f"set {n}: the time budget was spent before it, so it was not solved")
                    continue
                later = len(sets) - i - 1
                limit = max(min(left, keep), left - keep * later)
            ctx["partial"] = {}
            dog = run.Watchdog(limit)
            try:
                with dog:
                    got = solver.solve_set(qs, files, ctx) or {}
            except run.SolverTimeout:
                timed_out = True
                got = dict(ctx.get("partial") or {})
                errors.append(f"set {n}: solver stopped after its {limit:.2f}s share with {len(got)} answer(s) ready")
            except SystemExit as e:
                errors.append(f"set {n}: solver called sys.exit({e.code!r}); its partial answers are used")
                got = dict(ctx.get("partial") or {})
            except Exception:  # noqa: BLE001 - one set's failure must not cost the others
                errors.append(f"set {n}: solver raised; its partial answers are used\n{traceback.format_exc()}")
                got = dict(ctx.get("partial") or {})
            finally:
                # The watchdog's timer repeats: make sure it is off even if its own exit was interrupted.
                dog.armed = False
                with contextlib.suppress(Exception):
                    signal.setitimer(signal.ITIMER_REAL, 0)
            take(qs, got)
    if timed_out:
        errors.append(f"solver stopped after its {budget:.2f}s time budget with {len(raw)} answer(s) ready")
    return raw, timed_out, said.getvalue()


def is_blank(value) -> bool:
    """True for a string that is empty once stripped. It is no answer (tools/run.py's rule):
    sent, it could only cost the batch it is in."""
    return isinstance(value, str) and not value.strip()


def sort_answers(raw, order, legacy):
    """Split the solver's answers into (plain, sentinels, unsure, missing): plain values are
    serialized as tools/run.py does; a legacy sentinel and an unsure answer are held out, and a
    blank string is missing."""
    plain, sentinels, unsure, missing = {}, {k: [] for k in CANDIDATES}, {}, []
    for aid in order:
        value = raw.get(aid)
        if value is None or is_blank(value):
            missing.append(aid)
        elif legacy and isinstance(value, str) and value in sentinels:
            sentinels[value].append(aid)
        elif gm.is_unsure(value):
            unsure[aid] = value
        else:
            text = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
            if gm.is_unsure(text):
                unsure[aid] = value
            else:
                plain[aid] = text
    return plain, sentinels, unsure, missing


def parse_args(argv):
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            print(f"usage: timed_ladder.py <challenge-id> [--solver PATH] [--retry] [--dry]   ({message})", file=sys.stderr)
            sys.exit(2)

    if any(arg in ("-h", "--help") for arg in argv):
        print(__doc__)
        sys.exit(0)
    ap = Parser(add_help=False)
    ap.add_argument("challenge")
    ap.add_argument("--solver", default=None)
    ap.add_argument("--retry", action="store_true")
    ap.add_argument("--practice", action="store_true")      # no fresh variant is left: op=practice instead of a retry
    ap.add_argument("--rejoin", action="store_true")        # row 250: our attempt on disk is still open (a regular attempt):
                                                            # no retry, the plain start returns it (tools/run.py: rejoined)
    ap.add_argument("--dry", action="store_true")
    return ap.parse_args(argv)


def find_solver(arg):
    """(path, legacy): the solver file, and whether it is the Script Analysis dispatcher beside
    this file (the only solver the legacy name tables apply to). None when there is no such file."""
    default = HERE / "analyze.py"
    if not arg:
        return default, True
    path = Path(arg).expanduser()
    if not path.is_file() and not path.is_absolute() and (ROOT / path).is_file():
        path = ROOT / path
    if not path.is_file():
        return None, False
    path = path.resolve()
    return path, path == default.resolve()


def main(argv=None) -> int:
    a = parse_args(sys.argv[1:] if argv is None else argv)
    for stream in (sys.stdout, sys.stderr):
        # Under launchd the locale is C: a character it cannot encode must not cost the LADDER line.
        with contextlib.suppress(Exception):
            stream.reconfigure(errors="backslashreplace")
    cid = a.challenge
    solver_path, legacy = find_solver(a.solver)
    if solver_path is None:
        print(f"timed_ladder.py: no solver at {a.solver}", file=sys.stderr)
        return 2
    if not a.dry and not gm.is_timed(cid):
        print(f"timed_ladder.py plays Time Trial and Mastery ids; a base is submitted with tools/verify.py ({cid})",
              file=sys.stderr)
        print(ladder_line("not_timed"))
        return 2
    if not a.dry and judge.ticket(cid) is None:
        print(f"no ticket: run tools/preflight.py --gate {cid}")
        print(ladder_line("no_ticket"))
        return 3

    # Before the solver is imported: batch.py reads its switches when it loads.
    for name in scrub_switches():
        print(f"NOTE {name} was set; removed for this run (a solver switch never follows a process onto a clock)")
    # A lane played under an alias (tools/lanes.py, row 81) is grouped, probed and ledgered as its lane.
    job = SimpleNamespace(cid=cid, lane=lanes.canonical(lanes.lane_of(cid)) or lanes.lane_of(cid), dry=a.dry, retry=a.retry, legacy=legacy, conv=None,
                          batch=None, notes=[], errors=[], start_http=None,
                          practice=bool(getattr(a, "practice", False)) and not a.dry, practice_played=None,
                          rejoin=bool(getattr(a, "rejoin", False)) and not a.dry and not a.retry
                          and not getattr(a, "practice", False))
    job.frozen = list((lanes.policy(job.lane) or {}).get("frozen") or [])
    job.solver_path, job.legacy_same = solver_path, not legacy
    try:
        if legacy:
            import batch
            import vbscript
            tables = lambda: (dict(batch.EXP_LABEL), dict(batch.CONTROL), dict(vbscript.CONTROL_NAMES))
            before = tables()
            job.batch, job.conv = legacy_setup()
            # Gate reuse (Day 21 local speed): the legacy tables changed nothing, so this solve answers as a replay
            # (run.load_solver, no legacy_setup) would; otherwise the Time Trial is not offered to the gate.
            job.legacy_same = tables() == before
            import analyze as solver
        else:
            solver = run.load_solver(str(solver_path))
    except SystemExit as e:     # run.load_solver: the file has no solve_set
        print(f"timed_ladder.py: {e.code}", file=sys.stderr)
        return 2
    job.solver = solver
    # binary=pool (backlog row 121, off by default): the workers are forked here, before any request.
    job.pool = None if a.dry else SetPool.maybe(cid, job.lane, legacy, solver, job.notes)
    if job.pool is None and not a.dry and not legacy and str(cid).endswith("/time_trial"):
        # The Day 21 local speed build: a Binary Time Trial's prefixes in forked workers (tools/prefix_pool.py).
        job.pool = prefix_pool.PrefixPool.maybe(job.lane, solver, job.notes)
    try:
        return _play_guarded(a, cid, job, solver)
    finally:
        if job.pool is not None:
            job.pool.close()
        with contextlib.suppress(Exception):
            run.join_gate_row()     # gate reuse: the row is on disk before the gate that follows reads it


def _play_guarded(a, cid, job, solver) -> int:
    """main() from the session on: the status read, the clock, play(). Its own function so that
    main() can close the worker pool whichever way this ends."""
    try:
        job.s = gm.session()
        if not a.dry and hasattr(run, "preread") and not run.preread(cid):
            return _play_unread(a, cid, job, solver)     # package PR1: the start is the first request
        if not a.dry:
            # No read into a rate-limit pause that is known to be in force: it would only be answered 429.
            waited = run.wait_out_pause(cid, "timed_ladder.py")
            if waited:
                job.notes.append(f"a rate-limit pause was in force: waited {waited:.1f}s for its end before the status read")
        # Warm the connection and read the public contract; this never starts a clock.
        pre = gm.check(run.patient(lambda: job.s.get(gm.GM, params={"op": "status", "challenge": cid}, timeout=30),
                                   job.notes, "status", waits=run.WARMUP_WAITS))
        status = run.body_of(pre)
        if hasattr(run, "remember"):    # row 95: its guidance is noted by tools/contract.py after the run
            run.remember(status)
        job.status_body = status        # row 199: run.start_attempt hands it to gm.post_start as the hint
        if a.dry:
            return play(job, status, None, time.perf_counter(), 0.0)
        if run.rate_limited(pre):
            print("NOTE still rate limited after waiting; the attempt was NOT started (the ticket is untouched)")
            print(ladder_line("rate_limited", infra=True))
            return 2
        sets = 1
        questions = status.get("questions")
        if isinstance(questions, list) and questions:
            problems = contract_problems(solver, cid, status)
            if problems:
                for p in problems[:20]:
                    print(f"CONTRACT {p}")
                print(f"contract mismatch: {len(problems)} problem(s) with the questions of {cid}; the clock was NOT started")
                print(ladder_line("contract_mismatch"))
                return 3
            sets = len({m.group(1) for q in questions if isinstance(q, dict)
                        for m in [re.match(r"set(\d+)\.", str(q.get("id")))] if m}) or 1
        else:
            print("NOTE the status read carries no questions; the contract was not checked")
        with judge.clock(cid, sets + 4) as ticket:
            job.ticket = ticket if isinstance(ticket, dict) else None
            if hasattr(run, "preopen"):      # connect=early (backlog row 27); off by default
                run.preopen(job.s, cid, status, job.notes)
            sent = time.perf_counter()
            attempt, clock = run.start_attempt(job.s, cid, a.retry, job)
            t0 = time.perf_counter()
            return play(job, attempt, clock, t0, t0 - sent)
    except judge.NoTicket as e:
        print(f"no ticket: {e}")
        print(ladder_line("no_ticket"))
        return 3
    except judge.ClockBusy as e:
        print(f"NOTE {e}; the attempt was NOT started")
        print(ladder_line("clock_busy", infra=True))
        return 2
    except SystemExit as e:     # gm.check stops on `unauthorized`
        text = str(e.code)
        print(f"stopped: {text}", file=sys.stderr)
        print(ladder_line("unauthorized" if "unauthorized" in text else "stopped", infra=True))
        return 2
    except requests.RequestException as e:   # the status read or the start itself did not get through
        print(f"stopped: {type(e).__name__} before the attempt was played", file=sys.stderr)
        print(ladder_line(type(e).__name__, infra=True))
        return 2
    except Exception:  # noqa: BLE001 - a fault of the ladder itself: the pinned line still says so
        traceback.print_exc()
        print(ladder_line("ladder_error"))
        return 2


def _play_unread(a, cid, job, solver) -> int:
    """A live timed id with no op=status read before its start (preread=none, package PR1 of
    2026-10-11; tools/run.py: preread, play_unread). Called inside _play_guarded's try, so every
    refusal and failure ends as it does there. judge.clock() waits out a rate-limit pause the
    governor knows; a start answered 429 returns no attempt, and play() ends `rate_limited` with
    infra=true and no clock. The contract check runs on the start response's own questions before
    any download: its problems are printed as the CONTRACT lines they have always been, with one
    line that says the check ran after the start, and the attempt is played on."""
    with judge.clock(cid, run.cost_unread(cid)) as ticket:
        job.ticket = ticket if isinstance(ticket, dict) else None
        sent = time.perf_counter()
        attempt, clock = run.start_attempt(job.s, cid, a.retry, job)
        t0 = time.perf_counter()
        refused = run.start_limited_note(attempt, job.start_http)
        if refused:
            job.notes.append(refused)
        for line in run.late_contract_lines(cid, run.late_contract(solver, cid, attempt)):
            print(line)
        return play(job, attempt, clock, t0, t0 - sent)


def play(job, attempt, clock, t0, start_took) -> int:
    """Everything after the start response: download, save, solve, submit, write the files."""
    cid, dry = job.cid, job.dry
    run.normalize(attempt)
    if not attempt.get("artifacts") or not attempt.get("questions"):
        word = attempt.get("result") or attempt.get("error") or "not_started"
        if word == "CORRECT" and not dry:
            print(f"NOTE {cid} is already solved; nothing was started")
            print(ladder_line("CORRECT", remaining=0))
            return 0
        for n in job.notes:
            print("NOTE", n)
        print(run.brief(attempt, 1500))
        print("no attempt to play (see the response above)" + ("" if job.retry or dry else "; an expired attempt needs --retry"))
        if not dry:
            print(ladder_line(word, infra=True))
        return 2

    timed = clock is not None and clock.window is not None
    no_unsure = proposer_gate_check(job, cid, attempt) if not dry else ""
    if timed and clock.resumed:
        job.notes.append(f"start resumed an attempt that was already running ({clock.left():+.2f}s to its deadline)")
    # With the clock: a delivery that stalls is given up at the deadline (tools/run.py: time_limit),
    # not after two 30 s timeouts, so the variant is still saved and the LADDER line still printed.
    pool = getattr(job, "pool", None)
    streamed, pooled = False, None
    folder = run.attempt_dir(cid)
    if (pool is not None and getattr(pool, "unit", "delivery") == "delivery" and not dry
            and len(attempt.get("artifacts") or []) >= 2 and stream_pool_on()):
        # binary=pool, backlog row 544: download and solve each delivery as it lands, overlapping the solve
        # with the remaining downloads. run_binary_stream does the history move and attempt.json up front and
        # writes every delivery to disk, so the save block below is skipped for this path.
        blobs, failed, pooled, folder = run_binary_stream(job, cid, attempt, clock, timed)
        streamed = True
    else:
        blobs, failed = run.fetch_each(job.s, cid, attempt["artifacts"], clock if timed else None)
        job.notes += getattr(run, "download_notes", list)()      # the download ladder's lines (tools/gm.py), if it ran
        job.errors += failed
    t_dl = time.perf_counter()
    if not dry and not streamed:
        # On disk before the solver runs: an attempt that fails or expires still leaves its variant behind.
        try:
            shelve(folder, attempt)
        except Exception as e:  # noqa: BLE001 - the rows carry their attempt id, so the run goes on
            job.notes.append(f"the earlier variant's verdict files were not moved to history/ ({type(e).__name__}: {e})")
        try:
            folder = run.save_attempt(cid, attempt, blobs)
        except Exception:  # noqa: BLE001
            job.errors.append("could not save the attempt\n" + traceback.format_exc())

    # Day 8: a Binary Mastery of five deliveries needs ~0.8 s a set; the cap scales with the
    # deliveries so a 27 s window is not cut at 2 s (set5 went unanswered). Row 99: the rule is
    # lanes.ladder_budget, the one the gate holds a Mastery replay against, and it also scales with
    # the sets (a Script Mastery is five sets in one delivery: 3,075 answers took 1.5 s on Day 8).
    deliveries = max(1, len(attempt.get("artifacts") or attempt.get("downloads") or []))
    locked = []
    solved_from_ns, p0, mark = time.time_ns(), time.perf_counter(), len(job.errors)    # gate reuse (Day 21 local speed)
    nsets = len({n for _, _, n in question_rows(attempt)}) or 1
    left = clock.left() if timed else None
    budget = lanes.ladder_budget(left, deliveries, nsets)
    if streamed:
        pass                 # row 544: the binary=pool overlap already solved; `pooled` is set
    elif pool is not None and getattr(pool, "unit", "delivery") == "set":
        # script=pool (backlog row 336, off by default): one forked worker per SET of a one-bundle Mastery.
        members = set_members(attempt, blobs[0]) if not dry and len(blobs) == 1 and blobs[0] else None
        try:
            path = str(gm.artifact_path(folder / "artifact", attempt["artifacts"], 0)) if members else None
            if members and Path(path).is_file():
                cap = budget if budget is not None else \
                    max(getattr(run, "UNTIMED_SOLVE_CAP", 20.0), lanes.LADDER_CAP * max(deliveries, nsets))
                pooled = pool.solve_sets(job.solver, attempt, path, blobs[0], members, cap, job.errors, job.notes,
                                         deadline=timed or bool(attempt.get("deadline")))
            else:
                job.notes.append("script=pool: the delivery is not one bundle of one member per set on disk, "
                                 "so every set is solved one by one")
                pool.close()
        except Exception:  # noqa: BLE001 - never the submit's undoing
            job.notes.append("script=pool: the pool failed (" + traceback.format_exc().strip().splitlines()[-1][:160]
                             + "); every set solved one by one instead")
            pool.close()
            pooled = None
    elif pool is not None and getattr(pool, "unit", "delivery") == "prefix":
        # The Day 21 local speed build (tools/prefix_pool.py): one forked worker per share of the prefixes of
        # the one delivery. Whatever a worker did not give back is solved here, serially, after run.split_sets.
        try:
            path = gm.artifact_path(folder / "artifact", attempt["artifacts"], 0) if len(blobs) == 1 and blobs[0] else None
            cap = budget if budget is not None else \
                max(getattr(run, "UNTIMED_SOLVE_CAP", 20.0), lanes.LADDER_CAP * max(deliveries, nsets))
            pooled = pool_prefixes(job, attempt, path, blobs, cap, timed) if path is not None and not dry else None
            if path is None:
                job.notes.append("prefix pool: the attempt is not one delivery on disk; solved one by one")
        except Exception:  # noqa: BLE001 - never the submit's undoing
            job.notes.append("prefix pool: the pool failed (" + traceback.format_exc().strip().splitlines()[-1][:160]
                             + "); the prefixes are solved one by one")
            pooled = None
        finally:
            pool.close()
        if pooled is None:
            left = clock.left() if timed else None
            budget = lanes.ladder_budget(left, deliveries, nsets)
    elif pool is not None and not dry and len(blobs) >= 2 and all(blobs):
        # binary=pool (backlog row 121, off by default): one forked worker per delivery reads its
        # delivery from the folder it was just saved to, expands it and solves the sets it serves.
        # Whatever goes wrong there, the sets a worker did not answer are solved here, serially.
        try:
            paths = [str(gm.artifact_path(folder / "artifact", attempt["artifacts"], i)) for i in range(len(blobs))]
            if all(Path(p).is_file() for p in paths):
                pooled = pool.solve(job.solver, attempt, paths, blobs, budget, job.errors, job.notes,
                                    deadline=timed or bool(attempt.get("deadline")))
            else:
                job.notes.append("binary=pool: the deliveries are not on disk, so every set is solved one by one")
        except Exception:  # noqa: BLE001 - never the submit's undoing
            job.notes.append("binary=pool: the pool failed (" + traceback.format_exc().strip().splitlines()[-1][:160]
                             + "); every set solved one by one instead")
            pool.close()
            pooled = None
            left = clock.left() if timed else None
            budget = lanes.ladder_budget(left, deliveries, nsets)
    if pooled is not None:
        raw, timed_out, said, locked = pooled
        rows = question_rows(attempt)
    else:
        sets = run.split_sets(attempt, [b or b"" for b in blobs], locked, job.notes)
        left = clock.left() if timed else None        # read after the deliveries are unpacked: that time is gone too
        budget = lanes.ladder_budget(left, deliveries, len(sets))
        if budget is None and not dry:
            # A timed id's attempt without a deadline (practice, or a regular attempt): the run still
            # holds the clock lock, so the solver is bounded all the same.
            budget = max(getattr(run, "UNTIMED_SOLVE_CAP", 20.0), lanes.LADDER_CAP * max(deliveries, len(sets)))
        rows = [(q["answer_id"], q["qid"], n) for n, qs, _, _ in sets for q in qs]
    if locked:
        # No known archive password opens a delivery (backlog row 75): nothing is solved or sent,
        # since anything the solver said about it would be a guess. One critical alert, and the
        # run ends not_submitted with infra=true and the reason as its first ERROR line.
        why = run.password_needed(cid, locked, alert=not dry)
        job.errors.insert(0, why)
        failed = list(failed) + [why]
    if pooled is None:
        raw, timed_out, said = solve(job.solver, [] if locked else sets, budget, job.errors)
    elif locked:
        raw = {}
    t_solve = time.perf_counter()
    offer = None
    if not dry and not locked and not timed_out and len(job.errors) == mark and getattr(job, "legacy_same", False) \
            and hasattr(run, "gate_offer"):
        offer = run.gate_offer(cid, folder, getattr(job, "solver_path", None), attempt, blobs, raw, solved_from_ns,
                               0.0, t_solve - p0, "timed_ladder.py")

    prop = None
    if not dry and not timed and not locked and not no_unsure:
        prop = proposer_start(cid, job, attempt, folder, raw, nsets)     # the adaptability build: no deadline only
    lad = Ladder(cid, job.lane, job.s, attempt, clock if timed else None, folder, t0, job.conv)
    lad.gate_offer = offer
    if hasattr(labels, "PriorWatch"):
        lad.prior = labels.PriorWatch(raw)          # row 415: the ids row 388's family prior answered
    plain, sentinels, unsure, missing = sort_answers(raw, lad.order, job.legacy)
    # Row 106: a plain answer of the wrong kind for its question (an integer question answered
    # `ELF64`) is certainly wrong; sent, it costs its batch and a bisect. It is held back, printed
    # as FORMAT and listed with the missing ids.
    misformat = {}
    if hasattr(run, "kind_check"):
        plain, misformat = run.kind_check(attempt, plain)
        gone = set(missing) | set(misformat)
        missing = [aid for aid in lad.order if aid in gone]
    job.misformat = misformat
    group_of_id = plan_groups(job.lane, job.frozen, rows)
    groups = ordered_groups(group_of_id, plain)
    lad.plan = dict(Counter(group_of_id.values()))      # every question's group, held-out answers included
    held = dict(unsure)
    for kind, ids in sentinels.items():
        names = [c for c in CANDIDATES[kind] if c not in job.conv["rejected"].get(kind, [])] if ids else []
        for aid in ids:
            held[aid] = labels.Unsure(kind, [(c, c) for c in names])

    if dry:
        lad.log.append({"label": "ALL", "n": len(plain), "dry": True})
        lad.log += [{"label": g, "n": len(v), "dry": True} for g, v in groups.items() if v]
        lad.open_keys = open_rows(held, lad.order)
        lad.log += [{"label": f"{key}?", "n": len(row["ids"]), "names": row["left"], "dry": True}
                    for key, row in lad.open_keys.items()]
    else:
        try:
            submit(lad, plain, group_of_id, {} if no_unsure else held, no_unsure=bool(no_unsure))
        except Exception:  # noqa: BLE001 - whatever was banked and learned is still written down
            job.errors.append("the ladder raised while submitting\n" + traceback.format_exc())
        try:
            said += replay_learned(lad, job, attempt, blobs, rows, group_of_id, plain, unsure, missing)
        except Exception:  # noqa: BLE001 - an optional second solve never undoes the judged first pass
            job.notes.append("the learned-label re-solve failed (" + traceback.format_exc().strip().splitlines()[-1][:160]
                             + ")")
        if prop is not None:
            try:
                if not lad.correct:
                    propose_open(lad, job, prop, plain, missing, misformat)
            except Exception as e:  # noqa: BLE001 - the proposer never costs the attempt anything
                job.notes.append(f"the proposer's candidates were not probed ({type(e).__name__}: {str(e)[:160]})")
            finally:
                prop.kill()
        job.notes += lad.notes                      # row 346: the candidate keys a deadline kept unsent
        if lad.prior:
            # Row 415: one `accepted` ledger row per key the prior answered and the judge accepted; written here,
            # after the last request of the attempt, so no request waits for it.
            said = labels.PriorWatch.note(lad.prior.flush(lad.attempt_id))
            if said:
                job.notes.append(said)
        lad.size_alert()                            # row 341: after the submitting, never inside it
        finish(lad, job, folder, plain, groups, sentinels, unsure, missing, said)

    for row in lad.log:
        print("  ", json.dumps(row))
    if said.strip():
        if dry:
            sys.stderr.write(said)      # a dry run writes no file: the solver's triage goes to the terminal
        else:
            job.notes.append(f"the solver wrote {len(said.splitlines())} line(s) to stderr: see {folder / 'solver.stderr.txt'}")
    for n in job.notes:
        print("NOTE", n)
    for e in job.errors:
        print("ERROR", e)
    print(f"mode={attempt.get('mode')} attempt={attempt.get('attempt_id')} window={clock.window if clock is not None else None} "
          f"questions={len(attempt['questions'])} groups={ {g: len(v) for g, v in groups.items() if v} } "
          f"unknown={ {k: len(v) for k, v in sentinels.items() if v} } unsure={len(unsure)} missing={len(missing)}")
    print(f"timing: start={start_took:.2f}s download={t_dl - t0:.2f}s solve={t_solve - t_dl:.2f}s"
          + (" (the solver was stopped by its time budget)" if timed_out else ""))
    if dry:
        print("dry run: nothing started, nothing submitted, nothing written")
        return 0
    print(f"learned this attempt: {lad.learned or 'nothing new'}" + (f" | surprises: {lad.surprises}" if lad.surprises else ""))
    for aid in lad.bad:
        if aid not in lad.banked:
            print(f"BAD {aid} = {shown(lad.bad[aid], 60)}")
    for aid in missing[:40]:
        print(f"FORMAT {aid}: {misformat[aid]}" if aid in misformat else f"MISSING {aid}")
    print(f"FINAL: {lad.result()} remaining={lad.open_count()} stopped={lad.stopped}")
    print(f"saved: {folder}")
    # infra: nothing was judged, and not because the solver gave nothing to send (tools/run.py's
    # rule). A request went out and came back without a verdict, or a delivery could not be
    # downloaded. A caller that hears infra=false goes through the retry gate, which replays this
    # variant and names what the solver did; infra=true would start the next clock behind the
    # plain gate with the same solver.
    print(ladder_line(lad.result(), lad.open_count(), len(lad.banked), lad.probes, len(lad.rejected), len(lad.learned),
                      infra=lad.infra() and bool(lad.unjudged or failed)))
    return 0 if lad.correct else 2


def proposer_gate_check(job, cid, attempt) -> str:
    """The proposer gate (tools/proposer_gate.py): when this clock's ticket was written by the proposer gate and the
    start returned a timed attempt after all (a deadline, a window, run_for_time true), why nothing unsure may go out
    (one critical alert, the fallback marker beside the base); else "". Never raises."""
    ticket = getattr(job, "ticket", None)
    try:
        if not isinstance(ticket, dict) or not ticket.get("proposer_gate"):
            return ""
        import proposer_gate
        why = proposer_gate.runner_fallback(cid, ticket, attempt, run.attempt_dir(lanes.base_of(cid)))
        if why:
            job.notes.append(f"PROPOSER GATE FALLBACK {cid}: {why}")
        else:
            job.notes.append(f"proposer gate: a regular attempt with no deadline, as the gate expected; the proposer "
                             f"probes the {ticket.get('proposer_gate')} id(s) the replay leaves open")
        return why
    except Exception as e:  # noqa: BLE001 - a check that cannot be made sends nothing unsure
        why = f"the proposer gate's start check failed ({type(e).__name__})"
        job.notes.append(f"PROPOSER GATE FALLBACK {cid}: {why}")
        return why


PROPOSED_MAX = 12        # the adaptability build: option probes of the proposer's candidates in one run
PROPOSED_PER_ID = 3      # and on one id


def proposer_start(cid, job, attempt, folder, raw, nsets):
    """tools/propose.py for the ids the solver left None or unsure, on a timed attempt with NO deadline only (the
    caller checks), started once the solver is back, beside the submits. None when off or nothing is open."""
    try:
        import proposer_wire as pw
        lane = lanes.lane_of(cid)
        if not gm.is_timed(cid) or attempt.get("deadline") or not pw.prefix_of(lane) or pw.off():
            return None
        order = run.answer_ids_for(attempt)
        open_ids = [aid for aid in order if raw.get(aid) is None or is_blank(raw.get(aid)) or gm.is_unsure(raw.get(aid))]
        if not open_ids:
            return None
        ids = Path(folder) / ".proposer_ids.json"
        shipped = {}
        for aid in open_ids:
            u = labels.parse(raw.get(aid)) if isinstance(raw.get(aid), str) else None
            shipped[aid] = {"kind": "unsure", "key": u.key, "options": [list(o) for o in u.options]} if u else {"kind": "none"}
        if not pw.write_ids(ids, open_ids, shipped, {}, lane):
            return None
        multi = nsets > 1
        # forked on a thread of its own a moment later: never between the solver and the submit
        proc = pw.Later(delay=0.05, d=folder, ids_path=ids, deadline_s=pw.DEADLINE_MASTERY if multi else pw.DEADLINE_BASE,
                        sets=multi).start()
        proc.lane, proc.open_ids = lane, open_ids
        return proc
    except Exception as e:  # noqa: BLE001
        job.notes.append(f"the proposer was not started ({type(e).__name__}: {e})")
        return None


def propose_open(lad, job, prop, plain, missing, misformat):
    """After the ladder's own submissions: the ids still open probed with the proposer's candidates, only once every
    confident chunk is accepted (nothing BAD, nothing unchecked), nothing held and the attempt has no deadline."""
    import proposer_wire as pw
    if lad.correct or lad.has_deadline() or misformat or not lad.open():
        return
    if any(aid not in lad.banked for aid in plain) or lad.bad:
        return
    exhausted = {aid for row in (lad.open_keys or {}).values() if not row.get("left") for aid in row.get("ids") or []}
    unsure_ids = {aid for row in (lad.open_keys or {}).values() for aid in row.get("ids") or []}
    targets = [aid for aid in prop.open_ids if aid not in lad.banked and (aid not in unsure_ids or aid in exhausted)]
    if not targets:
        return
    started = prop.get()
    props = started.collect() if started is not None else {}
    group = pw.unsure_for(labels, props, targets, prop.lane, lad.attempt_id, rejected=lad.rejected,
                          per_id=PROPOSED_PER_ID)
    if not group:
        job.notes.append(f"proposer: no candidate for the {len(targets)} open id(s)")
        return
    out = lad.probe_proposed(group, PROPOSED_MAX, PROPOSED_PER_ID)
    if out is None:
        return
    for aid, u in group.items():
        if aid in lad.banked:
            value = lad.banked[aid]
            rank = next((i + 1 for i, (n, v) in enumerate(u.options) if v == value), "?")
            name = next((n for n, v in u.options if v == value), "?")
            job.notes.append(f"PROPOSED-ACCEPTED {aid} {name} rank {rank} ({pw.provenance(props, aid, value)[:200]})")
            if aid in missing:
                missing.remove(aid)
        else:
            row = out.open.get(u.key) or {}
            job.notes.append(f"PROPOSED-OPEN {aid} tried {len(row.get('tried') or [])}")


def open_rows(held, order) -> dict:
    """grade.probe's `open` rows for held-out answers nothing was sent for."""
    return grade.probe(lambda values: None, held, max_total=0, order=order).open


def submit(lad, plain, group_of_id, held, no_unsure=False):
    """The submissions of one attempt, in order (see the module docstring). no_unsure (the proposer gate fell back:
    its clock is a timed one after all): nothing unsure goes out, neither a probe of an unsure key nor the family's
    other names for a confident id rejected alone."""
    # What this attempt's own ledger already holds (a run that resumed a running attempt).
    accepted, rejected = judge.ledger(lad.dir, attempt_id=lad.attempt_id) if lad.attempt_id else ({}, set())
    lad.banked.update({aid: value for aid, value in accepted.items() if aid in lad.question})
    # Every pair an earlier run saw rejected alone, a family name it offered included: none of
    # them is sent a second time (names_for and grade.probe both leave out what is in `rejected`).
    lad.rejected.update(pair for pair in rejected if pair[0] in lad.question)
    todo = {}
    for aid, value in plain.items():
        if aid in lad.banked:
            continue
        if (aid, value) in rejected:
            lad.bad[aid] = value
            lad.rejected.add((aid, value))
        else:
            todo[aid] = value

    lad.work(units_of(ordered_groups(group_of_id, todo)))
    if held and lad.open():
        lad.probe(held, skip=rejected)
    else:
        lad.open_keys = open_rows(held, lad.order)
    # An id of a CORE or plan group that was rejected alone: the other names of its family.
    if not no_unsure:
        lad.retry([aid for aid in lad.bad if aid not in lad.banked and aid not in lad.surprises])
    # What a request that was not judged left unsettled, once more while the clock allows.
    pending = {aid: value for aid, value in todo.items() if aid not in lad.banked and aid not in lad.bad}
    if pending and lad.unjudged and lad.open():
        lad.work(units_of(ordered_groups(group_of_id, pending)), label="pending")
    if not lad.correct and lad.lost:
        lad.confirm()


def replay_learned(lad, job, attempt, blobs, rows, group_of_id, plain, unsure, missing):
    """Re-solve once after this run teaches the solver a reusable label (backlog row 579).

    An accepted key can change the solver's output immediately: Day 30's Script Time Trial learned
    ``script.file_path/bsh.one_copy`` and banked those file paths, but five path-leaf siblings stayed
    open until a new process replayed the same artifact.  Keep that work in this process.  Only sets
    containing an open id are replayed, and only a key-scoped label is an enabler; attempt-scoped
    proposer candidates never are.  The second solve may submit only values the shipped solver now
    returns plain under the freshly judged ledger.  It never probes, retries a rejected id, or changes
    what the first solve said.

    Returns the optional replay's stderr text, or ``""`` when no replay was eligible/useful.  This is
    deliberately best-effort: the first solve and every verdict it banked remain authoritative.
    """
    reusable = [key for key in getattr(lad, "learned", {}) if key and not grade.is_candidate(key)]
    if not reusable or getattr(lad, "correct", False) or not lad.open():
        return ""
    if lad.has_deadline() and (lad.left() is None or lad.left() < RELEARN_LEFT):
        lad.notes.append("learned-label re-solve skipped: under 10 s left on the deadline")
        return ""

    open_ids = {aid for aid in lad.order if aid not in lad.banked and aid not in lad.bad}
    set_of = {aid: n for aid, _qid, n in rows}
    wanted = {set_of[aid] for aid in open_ids if aid in set_of}
    if not wanted:
        return ""

    locked, notes = [], []
    try:
        sets = [row for row in run.split_sets(attempt, [b or b"" for b in blobs], locked, notes)
                if row[0] in wanted]
    except Exception:  # noqa: BLE001 - an optional replay never undoes the judged first pass
        lad.notes.append("learned-label re-solve could not rebuild the affected sets")
        return ""
    if locked or not sets:
        lad.notes.append("learned-label re-solve skipped: the affected sets were unavailable")
        return ""

    left = lad.left() if lad.has_deadline() else None
    budget = lanes.ladder_budget(left, max(1, len(blobs)), len(sets))
    if budget is None:
        budget = max(getattr(run, "UNTIMED_SOLVE_CAP", 20.0), lanes.LADDER_CAP * len(sets))
    errors = []
    raw, timed_out, said = solve(job.solver, sets, budget, errors)
    if timed_out or errors:
        lad.notes.append("learned-label re-solve left the affected sets incomplete: "
                         + str(errors[0] if errors else "time budget spent")[:160])

    again, _sentinels, again_unsure, _again_missing = sort_answers(raw, lad.order, job.legacy)
    if hasattr(run, "kind_check"):
        again, _ = run.kind_check(attempt, again)
    todo = {aid: value for aid, value in again.items()
            if aid in open_ids and aid not in lad.banked and aid not in lad.bad}
    if not todo:
        lad.notes.append("learned-label re-solve produced no new plain answer")
        return said

    # `work`, unlike submit(), sends no unsure option and does no family retry.  Every value here is
    # a fresh PLAIN answer of the real solver after labels.learn invalidated the ledger cache.
    lad.work(units_of(ordered_groups(group_of_id, todo)), label="learned-label re-solve")
    plain.update(todo)
    for aid in todo:
        unsure.pop(aid, None)
    missing[:] = [aid for aid in missing if aid not in todo]
    lad.notes.append(f"learned-label re-solve: {len(sets)} affected set(s), {len(todo)} new plain answer(s) "
                     f"after learning {', '.join(reusable)}")
    return said


def finish(lad, job, folder, plain, groups, sentinels, unsure, missing, said):
    """Write what the attempt leaves behind. Each file on its own: one that cannot be written
    must not cost the others."""
    bad = [aid for aid in lad.bad if aid not in lad.banked]
    unchecked = [aid for aid in plain if aid not in lad.banked and aid not in lad.bad]
    held_back = getattr(job, "misformat", None) or {}     # row 106: plain answers of the wrong kind, never sent

    def write(name, fn):
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            job.errors.append(f"could not write {name}: {type(e).__name__}: {e}")

    if job.legacy and lad.conv_changed:
        write(job.batch.CONVENTIONS.name, lambda: write_conventions(job.batch.CONVENTIONS, lad.conv))
    write("solver.stderr.txt", lambda: (folder / "solver.stderr.txt").write_text(said))
    keys = {aid: getattr(labels.parse(v), "key", "") if isinstance(v, str) else "" for aid, v in unsure.items()}
    write("ladder-log.json", lambda: (folder / "ladder-log.json").write_text(json.dumps({
        "attempt_id": lad.attempt_id, "result": lad.result(), "log": lad.log, "groups": groups, "plan": lad.plan,
        "unknown": sentinels,
        "unsure": keys, "missing": missing, "learned": lad.learned, "surprises": lad.surprises,
        "bad": {aid: lad.bad[aid] for aid in bad}, "unchecked": unchecked, "stopped": lad.stopped,
        "requests": lad.requests, "probes": lad.probes, "banked": len(lad.banked), "remaining": lad.open_count()}, indent=1)))
    last = dict(lad.last or {"result": "not_submitted"})
    last.update(attempt_id=lad.attempt_id, source="solvers/script-analysis/timed_ladder.py")
    if hasattr(run, "pool_record"):
        # Row 108: result.json says which pool was played (run_for_time, hall_of_fame_eligible), and a
        # regular attempt on a timed id is one NOTE, which tools/open_day.py turns into a warn alert.
        with contextlib.suppress(Exception):
            last = run.pool_record(job.cid, last, lad.attempt)
            played = getattr(job, "practice_played", None)      # op=practice: said in its own NOTE (run.start_attempt)
            if played:
                last = {**last, "practice": True}
                last.pop("regular_attempt", None)
            late = None if played else run.regular_note(job.cid, lad.attempt, last)
            if late and not any(str(n).startswith(run.REGULAR_NOTE) for n in job.notes):
                job.notes.append(late)
    write("result.json", lambda: (folder / "result.json").write_text(json.dumps(last, indent=2)))
    if lad.correct:
        write("key.json", lambda: judge.freeze_key(folder, lad.attempt))
    questions = lad.question
    write("gaps.json", lambda: judge.write_gaps(
        folder, len(lad.banked), lad.open_count(),
        [{"id": aid, "question": (questions.get(aid) or {}).get("question"),
          "member": ((questions.get(aid) or {}).get("artifact") or "").split("->")[-1].strip() or None,
          **({"format": held_back[aid]} if aid in held_back else {})} for aid in missing],
        bad, lad.open_keys, []))


if __name__ == "__main__":
    code = main()
    if hasattr(run, "note_contract") and "--dry" not in sys.argv[1:]:
        run.note_contract(sys.argv[1] if len(sys.argv) > 1 else "")   # after the LADDER line: off the clock (row 95)
    sys.exit(code)
