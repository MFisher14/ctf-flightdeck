#!/usr/bin/env python3
"""The unsure-answer contract: how a solver says "the fact is established, its name is not".

The judge banks a batch only when every answer in it is right, and many answers are names
the challenge author chose (`for_once`, `pe_cli`, `delayed`). A solver that has read a fact
from the bytes but has never seen the judge accept a name for it must not send a guess as
if it were confident, so it calls

    labels.pick(key, options)

and returns the result. `options` is an ordered list, best first, of spellings or formats
of ONE fact: plain labels, or `(name, value)` pairs when the answer differs per question
(`name` is the method, such as `raw` or `iso`; `value` is this question's answer under it).
`pick` returns

  - the plain value, once a name has been accepted for the key;
  - otherwise an unsure string (`"??"` + JSON) carrying the options the judge has not
    rejected for the key, at most 12. The runners never send one as an answer: they probe
    it one option per request, or hold the clock back;
  - None when no option is left. Never a default.

A key is `<lane>.<field>/<shape>`, lowercase, with <lane> one of script, binary, metadata,
mobile, warmups (`script.control/hta.for`, `binary.format/pe+cli`), or a category toolkit's
prefix (TOOLKIT_PREFIXES: `network.dns_query/only`, `web.vuln/sqli`). Every question that
shares a key shares one fate, so the key must hold everything the name depends on.

What is known about a key comes from two places, kept apart:

  seed     solvers/<lane dir>/conventions.json, tracked, written from judged evidence:
           {key: {"accepted": name, "rejected": [...], "split": false, "evidence": [...]}}
  runtime  <challenges>/_ledger/<lane>.jsonl, append-only, one row per verdict that
           `learn` was given during play.

`labels.py promote <lane>` folds the runtime rows into the seed after the day.

Both are gated on one event capability, the judge ledger (`judge_ledger()`, set per event through
$CTF_JUDGE_LEDGER; unset means on). A judged platform (Game Master) hands back a verdict per name,
so the seed and ledger are read, `learn` records and `promote` folds. On an event with no such
judge (CTFd, manual play) set CTF_JUDGE_LEDGER=off: no seed or ledger is read (every pick stays
unsure), `learn` records nothing and says so once, `promote` refuses, and `lane_of` accepts any
key prefix (there is no per-lane seed to be consistent with). `show` renders an answer for a human.

Helpers that build option lists: `patterns` (control-flow names), `spell` (joins of a
fact's tokens), `enum_from_question` (names the question itself lists), `family` (names
already accepted for sibling keys).

    labels.candidates(key, options)

is the one bounded exception to "options are spellings of ONE fact" a solver may write on its
own (backlog row 346, the player's yes of 2026-10-17): `options` are (name, value) pairs, best
evidence first, whose values may be DIFFERENT candidate facts (the literal `none` beside an
immediate; a bare symbol beside its COFF COMDAT name). Each name names the hypothesis
(`stripped_none`, `comdat`), never the value, so an accepted name carries to the next variant.
It is never plain before the judge has accepted a name for the key, keeps at most 12 options
(the first 12 offered: a key has 12 guesses in all), and its key ends in CANDIDATE_MARK, which is
how every runner tells it from an ordinary pick (`is_candidate`): tools/verify.py probes it on
an untimed base like any key, and inside a timed attempt it is probed only when the attempt has
no deadline.

This module imports nothing from tools/, so a solver can use it from the armed export, a
worktree or a temporary copy. The challenges folder is the event workdir, ctf.paths.workdir()
(challenges_root).

Usage:
  .venv/bin/python solvers/common/labels.py promote <lane> [--dry-run]
"""
import fcntl
import fnmatch
import json
import os
import re
import sys
import time
from collections import namedtuple
from itertools import permutations
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env, paths as ctf_paths
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env, paths as ctf_paths

SENTINEL = "??"
MAX_OPTIONS = 12   # options carried by one unsure answer, and probes spent on one key
# Row 346: the end of every candidate key (see candidates). A key convention, not a field of the wire
# form: the key is the one part of an unsure answer that every path keeps. tools/verify.py (_normal),
# tools/run.py (probe_unsure) and the ladder rebuild the wire form or a labels.Unsure from (key,
# options) alone, and the labels ledger, gaps.json and the runners' NOTE lines carry the key and
# nothing else, so a field beside "k" and "o" would be lost on the way to the place a probe is
# decided. An older reader takes such a key as an ordinary key (its lane is the first segment, and no
# reader restricts the shape), so it treats the answer as the unsure pick it also is: never sent as
# an answer, probed one option per request. Only the deadline rule is this build's runners' own.
CANDIDATE_MARK = "#candidates"
MIN_LEFT = 0.3     # a verdict with less than this many seconds left on the clock is not trusted
_SPELL_TOKENS = 6  # tokens of a fact that `spell` matches vocabulary names against
VERDICTS = ("accepted", "rejected", "split")

SOLVERS = Path(__file__).resolve().parent.parent
ROOT = SOLVERS.parent

# First dotted segment of a key -> the lane's folder under solvers/.
LANE_DIRS = {
    "script": "script-analysis",
    "binary": "binary",
    "metadata": "metadata-forensics",
    "mobile": "mobile-android",
    "warmups": "warmups",
}
# The category toolkits (solvers/toolkits/registry.py, built 2026-10-08): one key prefix each, so an
# unsure answer of a toolkit is probed by tools/verify.py and remembered like a lane's. Each has a seed
# folder of its own, solvers/toolkits/seeds/<prefix>/conventions.json (missing until its first
# `promote`: a missing seed reads as empty). `web` is shared by the web and web_evidence toolkits.
TOOLKIT_PREFIXES = ("evidence_core", "memory", "network", "email", "cloudlogs", "windows", "maldoc", "rf", "web",
                    "edr_persistence", "nix_host", "cloud_container", "ai_model_files", "agent_trace", "malconfig",
                    "modern_crypto", "carve_stego", "sqlite_artifacts", "repo_supply_chain", "osint", "pwn", "forensics",
                    "asn1_reader", "wire_decode", "firmware", "il2cpp", "deser_chain", "serial_decode", "blockchain",
                    "marker")    # B-119: the constructed-marker convention KB (solvers/common/marker_convention.py)
LANE_DIRS.update({_prefix: "toolkits/seeds/" + _prefix for _prefix in TOOLKIT_PREFIXES})
# Other spellings `promote` accepts for a lane: its solver folder and its challenge-id prefix.
LANE_ALIASES = {"script-analysis": "script", "binary-reverse-engineering": "binary",
                "metadata-forensics": "metadata", "mobile-android": "mobile"}


# ---------------------------------------------------------------------------- paths

def challenges_root(workdir=None) -> Path:
    """Where attempts and the runtime ledger live: the event workdir, ctf.paths.workdir() ($CTF_WORKDIR,
    else ~/ctf-work/<event>). Resolved on every call, so a test can point it elsewhere after import; with
    neither $CTF_WORKDIR nor a resolvable event it raises ctf.event.EventError (no silent repo fallback).

    `workdir`, when given, is a resolved event workdir the caller already holds (adapt.record_attempt's
    own --workdir, folded by seedfold after an accepted solve): it is used verbatim instead of resolving
    the ambient event. This module never reads $CTF_WORKDIR itself -- ctf.paths is the single source."""
    return Path(workdir) if workdir is not None else ctf_paths.workdir()


# Perf (Day 27 speed build): every pick() stats the lane's seed and ledger (a file that changed is read again, as
# before); the Path objects those stats are made on depend only on the strings below, so each is built once and
# kept, and its hash with it. Whatever the environment, LANE_DIRS or SOLVERS say at a call is still what is used.
_PATHS = {}           # ("seed", SOLVERS, folder) or ("ledger", root, lane) -> the path

JUDGE_LEDGER_ENV = "CTF_JUDGE_LEDGER"
_ON = ("1", "on", "yes", "true")
_OFF = ("0", "off", "no", "false")


def judge_ledger() -> bool:
    """The event capability "judge ledger": True when the event's judge answers per name, so the
    seed and runtime ledger are read and written. $CTF_JUDGE_LEDGER, read on every call: unset or
    empty is on (the Game Master behaviour); on/1/yes/true or off/0/no/false; anything else is a
    ValueError that names the variable, never a guess."""
    raw = os.environ.get(JUDGE_LEDGER_ENV, "").strip().lower()
    if raw == "" or raw in _ON:
        return True
    if raw in _OFF:
        return False
    raise ValueError(f"${JUDGE_LEDGER_ENV}={raw!r}: use one of {', '.join(_ON + _OFF)}")


def lane_of(key: str) -> str:
    """The lane a key belongs to: its first dotted segment.

    With the judge ledger on, ValueError for anything but a known lane, because a key with no
    lane has no seed and no ledger to be remembered in. With it off there is nothing to remember,
    so any prefix is its own lane (an empty one is "misc") and LANE_DIRS is left as it is."""
    lane = str(key).split(".", 1)[0].split("/", 1)[0].strip().lower()
    if lane not in LANE_DIRS:
        if not judge_ledger():
            return lane or "misc"
        raise ValueError(f"label key {key!r}: the lane must be one of {', '.join(LANE_DIRS)}")
    return lane


def seed_path(lane: str) -> Path:
    folder = LANE_DIRS[lane]
    key = ("seed", SOLVERS, folder)
    got = _PATHS.get(key)
    if got is None:
        got = _PATHS[key] = SOLVERS / folder / "conventions.json"
    return got


def ledger_path(lane: str, workdir=None) -> Path:
    root = challenges_root(workdir)
    key = ("ledger", root, lane)
    got = _PATHS.get(key)
    if got is None:
        got = _PATHS[key] = root / "_ledger" / f"{lane}.jsonl"
    return got


def _key(key) -> str:
    key = str(key).strip().lower()
    lane_of(key)
    return key


# ---------------------------------------------------------------------------- wire form

class Unsure(namedtuple("Unsure", "key options")):
    """A parsed unsure answer: `key`, and `options` as a list of (name, value) pairs, best
    first. It unpacks as `key, options = parse(value)`; the wire names work too
    (`parsed["k"]`, `parsed["o"]`)."""
    __slots__ = ()
    _FIELDS = {"k": 0, "key": 0, "o": 1, "options": 1}

    def __getitem__(self, index):
        return tuple.__getitem__(self, self._FIELDS.get(index, index) if isinstance(index, str) else index)

    @property
    def names(self):
        return [n for n, _ in self.options]

    @property
    def candidate(self) -> bool:
        """True for a candidate pick (row 346): its key ends in CANDIDATE_MARK."""
        return is_candidate(self.key)

    def value(self, name):
        """This answer's value under `name`; KeyError if the name is not among the options."""
        return dict(self.options)[name]


def _pairs(options) -> list:
    """Options as [(name, value)], names unique, order kept. A bare label is its own value.

    An option whose value is None is dropped: None means "no established answer", so a
    format that could not be computed for this question is not an option, and a probe must
    never be handed a null to send."""
    if options is None:
        return []
    if isinstance(options, (str, bytes)):
        options = [options]
    out, seen = [], set()
    for item in options:
        if isinstance(item, (list, tuple)) and len(item) == 2 and isinstance(item[0], str):
            name, value = item
        else:
            name, value = (item if isinstance(item, str) else str(item)), item
        if name == "" or value is None or name in seen:
            continue
        seen.add(name)
        out.append((name, value))
    return out


def unsure(key, options) -> str:
    """The unsure string for `options` under `key`: "??" + compact JSON {k, o: [[name, value], ...]}.

    JSON keeps a value intact whatever it contains ('|', '=', ':', quotes, a JSON array).
    Every runner removes a value that starts with "??" from a submission (the Game Master
    session; on a judge-free event it is shown to a human), so this string can never reach
    the judge as an answer."""
    body = {"k": _key(key), "o": [[n, v] for n, v in _pairs(options)]}
    return SENTINEL + json.dumps(body, separators=(",", ":"))


def is_unsure(value) -> bool:
    return isinstance(value, str) and value.startswith(SENTINEL)


def parse(value):
    """Read an unsure string back: Unsure(key, [(name, value), ...]). None for a plain answer.

    A "??" string that does not parse still reads as unsure, with an empty key and no
    options: it must never be sent, and there is nothing to probe. The form is checked
    strictly, because whatever comes back from here is probed against the judge and then
    handed to `learn`: the key must name a known lane (or `learn` would raise in the middle
    of a run), and every option must be a [name, value] pair with a non-empty name and a
    value. `"o": ["ab"]` is not two options named 'a' and 'b'."""
    if not is_unsure(value):
        return None
    try:
        body = json.loads(value[len(SENTINEL):])
        key, raw = body["k"], body["o"]
        if not isinstance(key, str) or not isinstance(raw, list):
            raise ValueError
        key = _key(key)
        options = []
        for o in raw:
            if not (isinstance(o, list) and len(o) == 2 and isinstance(o[0], str) and o[0] and o[1] is not None):
                raise ValueError
            options.append((o[0], o[1]))
    except (ValueError, KeyError, TypeError, IndexError):
        return Unsure("", [])
    return Unsure(key, options)


# ---------------------------------------------------------------------------- what is known

_cache = {}      # path -> (stat signature, parsed content)
_warned = set()  # paths already reported as unreadable


def _signature(path: Path):
    try:
        st = path.stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


def _warn(path: Path, why: str):
    if str(path) not in _warned:
        _warned.add(str(path))
        print(f"[labels] {path}: {why}; read as empty", file=sys.stderr)


def _read_seed(lane: str) -> dict:
    """The tracked seed of a lane, {key: entry}. A missing file is empty; a broken one is
    reported once on stderr and read as empty, so its keys come back unsure, never wrong.
    Empty without a judge ledger (judge_ledger() off): no seed is read."""
    if not judge_ledger():
        return {}
    path = seed_path(lane)
    sig = _signature(path)
    hit = _cache.get(path)
    if hit and hit[0] == sig:
        return hit[1]
    data = {}
    if sig is not None:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("not a JSON object")
            data = {k.strip().lower(): v for k, v in raw.items() if isinstance(v, dict)}
        except (OSError, ValueError) as e:
            _warn(path, f"unreadable seed ({e})")
    _cache[path] = (sig, data)
    return data


def _read_rows(lane: str, workdir=None) -> list:
    """Every well-formed row of the lane's runtime ledger, in file order. A line that does
    not parse (a torn write, an edit by hand) is skipped. Empty without a judge ledger.
    `workdir`, when given, names the event workdir whose ledger is read (see challenges_root)."""
    if not judge_ledger():
        return []
    path = ledger_path(lane, workdir)
    sig = _signature(path)
    hit = _cache.get(path)
    if hit and hit[0] == sig:
        return hit[1]
    rows = []
    if sig is not None:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except ValueError:
                        continue
                    # An empty name is never a name: accepted, it would come back from `pick`
                    # as the plain answer "".
                    if (isinstance(row, dict) and isinstance(row.get("key"), str)
                            and isinstance(row.get("name"), str) and row["name"]
                            and row.get("verdict") in VERDICTS):
                        rows.append(row)
        except OSError as e:
            _warn(path, f"unreadable ledger ({e})")
    _cache[path] = (sig, rows)
    return rows


def _seconds(left):
    """`left` as a float, or None when it is not a time (an untimed base has no clock).
    A number written as text counts, so a caller that formatted its clock is still heard."""
    if left is None or isinstance(left, bool):
        return None
    try:
        left = float(left)
    except (TypeError, ValueError):
        return None
    return left if left == left else None  # NaN is not a time


def _trusted(row: dict) -> bool:
    """A row counts unless it was judged with under 0.3 s left: a verdict that close to the
    deadline may be the expiry speaking, not the judge."""
    left = _seconds(row.get("left"))
    return left is None or left >= MIN_LEFT


def _row_evidence(row: dict) -> str:
    ids = row.get("answer_ids") or []
    parts = [str(row.get("t") or "?"), row["verdict"], row["name"], f"scope={row.get('scope') or 'key'}"]
    if row.get("degenerate"):
        parts.append("degenerate")
    if row.get("attempt_id"):
        parts.append(f"attempt={row['attempt_id']}")
    if ids:
        parts.append("ids=" + ",".join(str(i) for i in ids))
    if row.get("left") is not None:
        parts.append(f"left={row['left']}")
    return " ".join(parts)


def _fold(entry: dict, rows: list) -> dict:
    """One key's state: the seed entry with the runtime rows applied in order.

    accepted  adds the name. A name the key had rejected turns out to be right for some
              ids, so it leaves the rejected list and the key is split.
    rejected  of an accepted name marks the key split (one name no longer answers every
              id) and blacklists nothing. Otherwise, with scope 'key', the name is rejected
              for the key; with an id as scope it says nothing about the key.
    split     marks the key."""
    names = [n for n in (entry.get("accepted_names") or []) if isinstance(n, str) and n]
    first = entry.get("accepted")
    if isinstance(first, str) and first and first not in names:
        names.insert(0, first)
    rejected = [n for n in (entry.get("rejected") or []) if isinstance(n, str) and n not in names]
    split = bool(entry.get("split"))
    evidence = [str(e) for e in (entry.get("evidence") or [])]
    for row in rows:
        if not _trusted(row):
            continue
        name, verdict = row["name"], row["verdict"]
        if verdict == "accepted":
            # The order-degenerate guard (B-040): an acceptance the input could not distinguish (the
            # `sorted`/`as_is` spellings coincided on already-sorted bytes) keeps its evidence but is
            # never promoted to a plain answer, so pick stays unsure until a run that could tell them
            # apart accepts the name. It also does not clear a standing rejection or split the key.
            if row.get("degenerate"):
                pass
            else:
                if name in rejected:
                    rejected.remove(name)
                    split = True
                if name not in names:
                    names.append(name)
        elif verdict == "rejected":
            if name in names:
                split = True
            elif (row.get("scope") or "key") == "key" and name not in rejected:
                rejected.append(name)
        else:
            split = True
        text = _row_evidence(row)
        if text not in evidence:
            evidence.append(text)
    return {"accepted": names[0] if names else None, "accepted_names": names,
            "rejected": rejected, "split": split, "evidence": evidence}


def _mask() -> list:
    """Globs from $CTF_LEDGER_MASK (comma-separated, matched against whole keys),
    honoured only when $CTF_TESTING is 1: a rehearsal knob, inert in live play."""
    if ctf_env.get("CTF_TESTING") != "1":
        return []
    return [g.strip().lower() for g in ctf_env.get("CTF_LEDGER_MASK", "").split(",") if g.strip()]


def _masked(key: str, mask: list) -> bool:
    return any(fnmatch.fnmatchcase(key, g) for g in mask)


def _lane_state(lane: str, mask=None) -> dict:
    """{key: state} for a lane. A masked key reads as if the seed had never seen a name
    accepted for it. Its recorded rejections stay (a rehearsal must not offer a spelling the
    judge is known to refuse), and so does whatever this run's ledger learns, which is what
    a rehearsal needs: the name has to be found again by probing, and then it has to hold.
    Empty without a judge ledger: nothing is known about any key."""
    if not judge_ledger():
        return {}
    seed = _read_seed(lane)
    rows = _read_rows(lane)
    mask = _mask() if mask is None else mask
    # `seed` and `rows` are the cached objects themselves, replaced only when their file
    # changes, so their identity tells whether the folded result is still current.
    slot = ("state", seed_path(lane), ledger_path(lane), tuple(mask))
    hit = _cache.get(slot)
    if hit and hit[0] is seed and hit[1] is rows:
        return hit[2]
    by_key = {}
    for row in rows:
        by_key.setdefault(row["key"].strip().lower(), []).append(row)
    out = {}
    for key in list(seed) + [k for k in by_key if k not in seed]:
        entry = seed.get(key, {})
        if entry and _masked(key, mask):
            entry = {**entry, "accepted": None, "accepted_names": [], "split": False}
        if entry or key in by_key:
            out[key] = _fold(entry, by_key.get(key, []))
    _cache[slot] = (seed, rows, out)
    return out


def state(key) -> dict:
    """What is known about a key: {"accepted": name or None, "accepted_names": [...],
    "rejected": [...], "split": bool, "evidence": [...]}. Seed and runtime ledger merged."""
    key = _key(key)
    st = _lane_state(lane_of(key)).get(key)
    if st is None:
        return {"accepted": None, "accepted_names": [], "rejected": [], "split": False, "evidence": []}
    return {k: (list(v) if isinstance(v, list) else v) for k, v in st.items()}


def keys(prefix) -> list:
    """The keys that start with `prefix` and have any state (a seed entry or a runtime row), in the order
    they were written down: seed first, then the ledger's new keys. `prefix` must hold the lane
    ('marker.', 'marker.convention/'). Candidate keys are included, with their mark. Empty without a judge
    ledger, as every read is."""
    prefix = str(prefix).strip().lower()
    return [key for key in _lane_state(lane_of(prefix)) if key.startswith(prefix)]


def family(prefix) -> list:
    """Names accepted for the keys that start with `prefix` (for example 'script.control/'),
    each once, in the order the keys were written down. They are the judge's own vocabulary
    for sibling facts: material for `patterns` and `spell`, never an answer by themselves.
    A candidate key (row 346) is left out: its names name hypotheses (`stripped_none`), and a
    hypothesis's name is never a value to offer."""
    prefix = str(prefix).strip().lower()
    out = []
    for key, st in _lane_state(lane_of(prefix)).items():
        if key.startswith(prefix) and not key.endswith(CANDIDATE_MARK):
            for name in st["accepted_names"]:
                if name not in out:
                    out.append(name)
    return out


# ---------------------------------------------------------------------------- the family prior (row 388)
#
# A key `<lane>.<field>/<mid>.<shape>` (`script.role/jsp.stated_v3`) belongs to the family of every key with the
# same `<lane>.<field>/` and the same `.<shape>`, whatever its <mid> (the extension). The player's yes of
# 2026-10-20 (row 388): when a family's accepted name is the same on every member judged so far, a member the
# judge has never seen answers that name plain instead of an unsure pick. The rule is strict:
#   - at least FAMILY_PRIOR_MIN other members hold an accepted name, and it is ONE name, the same on all of them
#     (a member with two accepted names counts as a different name);
#   - no member is split, and no member holds a rejection: a seed `rejected` entry, or ANY ledger row of the
#     family whose verdict is not `accepted` (an id-scoped rejection and a verdict with under 0.3 s left too);
#   - the key itself has no state (no accepted name, no rejection, no split), is no candidate key, and the
#     caller offers that very name among its options (its value is the answer).
# Never for a family with any rejection or split. One stderr NOTE per key and process says the prior was used.
# `CTF_FAMILY_PRIOR=off` in front of a command turns it off (the armed opener cannot).
FAMILY_PRIOR_MIN = 5
_FAMILY_KEY = re.compile(r"([a-z][a-z0-9_-]*\.[^/]+)/([a-z0-9][a-z0-9_+-]{0,15})\.([^/]+)")
_prior_noted = set()


def _family_index(lane: str):
    """{(head, shape): {"acc": {mid: [names]}, "bad": {mids}}} for a lane, cached on its folded state.
    Empty without a judge ledger: no family has a judged member."""
    if not judge_ledger():
        return {}
    st = _lane_state(lane)
    rows = _read_rows(lane)
    slot = ("family", seed_path(lane), ledger_path(lane))
    hit = _cache.get(slot)
    if hit and hit[0] is st and hit[1] is rows:
        return hit[2]
    index = {}
    for key, s in st.items():
        m = _FAMILY_KEY.fullmatch(key)
        if not m or key.endswith(CANDIDATE_MARK):
            continue
        fam = index.setdefault((m.group(1), m.group(3)), {"acc": {}, "bad": set()})
        if s["accepted_names"]:
            fam["acc"][m.group(2)] = list(s["accepted_names"])
        if s["rejected"] or s["split"]:
            fam["bad"].add(m.group(2))
    for row in rows:                             # any verdict but `accepted`, whatever its scope or clock
        if row["verdict"] == "accepted":
            continue
        m = _FAMILY_KEY.fullmatch(row["key"].strip().lower())
        if m:
            index.setdefault((m.group(1), m.group(3)), {"acc": {}, "bad": set()})["bad"].add(m.group(2))
    _cache[slot] = (st, rows, index)
    return index


def family_prior(key):
    """(name, [mids]) when the family prior answers `key` (see above), else None."""
    if ctf_env.get("CTF_FAMILY_PRIOR", "").strip().lower() in ("off", "0", "no", "false"):
        return None
    key = _key(key)
    m = _FAMILY_KEY.fullmatch(key)
    if not m or key.endswith(CANDIDATE_MARK):
        return None
    fam = _family_index(lane_of(key)).get((m.group(1), m.group(3)))
    if not fam or fam["bad"]:
        return None
    mid = m.group(2)
    others = {k: v for k, v in fam["acc"].items() if k != mid}
    if mid in fam["acc"] or len(others) < FAMILY_PRIOR_MIN:
        return None
    names = {tuple(v) for v in others.values()}
    if len(names) != 1:
        return None
    only = next(iter(names))
    if len(only) != 1:
        return None
    return only[0], sorted(others)


def _note_prior(key, prior):
    if key in _prior_noted:
        return
    _prior_noted.add(key)
    m = _FAMILY_KEY.fullmatch(key)
    print(f"[labels] NOTE {key}: no verdict for this key; answered {prior[0]!r} plain by its family's prior "
          f"(row 388): {m.group(1)}/*.{m.group(3)} accepted {prior[0]!r} on {len(prior[1])} keys "
          f"({', '.join(prior[1])}), none rejected or split", file=sys.stderr)


# ---------------------------------------------------------------------------- the prior's answers in the ledger (row 415)
#
# Day 20: the prior answered script.role/groovy.stated_v3 and script.attack/groovy.stated_v3 plain in all seven
# solves, every batch was CORRECT, and nothing reached the ledger: conventions.json never learned the two keys, and
# one rejection anywhere in the family would have turned the prior off for them too. Now a plain answer the prior
# gave is a PriorAnswer: a str, equal to its text in every use (json, ==, hashing, the wire), that also carries
# its key and the prior's name. A runner reads them from the solver's answers (PriorWatch), notes every batch the
# judge answered `accepted` or `CORRECT` that holds such an answer with that very text, and once its submitting is
# over appends ONE `accepted` row per key (scope `key`), never more than once a key in a process. An `incorrect`
# batch records nothing. A value a solver rebuilt (str(v), v.strip(), a join) is a plain str again and records
# nothing: the old behaviour, never a wrong row. `CTF_FAMILY_PRIOR=off` gives no prior, so no PriorAnswer.
_prior_given = {}        # {key: name}: what the prior answered in this process
_prior_learned = set()   # keys whose `accepted` row this process wrote (or tried to)


def _prior_answer(text, key, name):
    """PriorAnswer(text) carrying key and name (also what pickle calls: a forked pool worker's answer arrives whole)."""
    out = PriorAnswer(text)
    out.prior_key, out.prior_name = key, name
    return out


class PriorAnswer(str):
    """A plain answer given by the family prior (row 388) for `prior_key` under the name `prior_name` (row 415)."""
    prior_key = None
    prior_name = None

    def __reduce__(self):
        return _prior_answer, (str(self), self.prior_key, self.prior_name)


def _given_by_prior(key, name, value):
    _prior_given[key] = name
    return _prior_answer(value, key, name) if isinstance(value, str) else value


def prior_answers() -> dict:
    """{key: name} for every key the family prior answered plain in this process (row 415)."""
    return dict(_prior_given)


def prior_of(value):
    """(key, name) when `value` is an answer the family prior gave, else None. Read by attribute, so an answer
    made by another copy of this module (a solver's own sys.path) is told apart all the same."""
    key, name = getattr(value, "prior_key", None), getattr(value, "prior_name", None)
    if isinstance(value, str) and isinstance(key, str) and key and isinstance(name, str) and name:
        return key, name
    return None


PRIOR_SRC = "prior"   # the "src" of a ledger row the family prior wrote (PriorWatch.flush; the Day 21 final prep)


class PriorWatch:
    """Row 415, for one run of a runner: which answer ids the family prior answered, the batches the judge accepted
    that held them, and the one ledger row per key once the submitting is over.

        watch = labels.PriorWatch(answers)          # the solver's answers, {answer id: value}, before any is sent
        watch.saw(values, result, left)             # after each verdict is on disk: in memory only, no file
        watch.flush(attempt_id)                     # once the run sends nothing more: the ledger rows

    `saw` takes the batch as it went on the wire ({answer id: text}) and the judge's word; only `accepted` and
    `CORRECT` count, and only for an id whose sent text is the prior's own. `flush` appends, under the ledger's
    lock, one `accepted` row (scope `key`, the ids of the batches that carried it, `left` of the first such
    verdict) for each key not yet written by this process, and returns the keys it wrote. Never raises.
    Each row carries `"src": "prior"` (PRIOR_SRC), so tools/preflight.py's lane hash leaves it out of the
    ledger size: it only confirms an answer the prior already gave plain, so no replay changes with it."""

    GOOD = ("accepted", "CORRECT")

    def __init__(self, answers=None):
        self.ids = {}            # answer id -> (key, name, text)
        self.pending = {}        # key -> [name, [ids], left]
        try:
            for aid, value in (answers or {}).items():
                hit = prior_of(value)
                if hit is not None:
                    self.ids[str(aid)] = (hit[0], hit[1], str.__str__(value))
        except Exception:  # noqa: BLE001 - a watch that cannot read the answers watches nothing
            self.ids = {}

    def __bool__(self):
        return bool(self.ids)

    def saw(self, values, result, left=None):
        if not self.ids or result not in self.GOOD:
            return
        try:
            for aid, value in dict(values or {}).items():
                hit = self.ids.get(str(aid))
                if hit is None or hit[0] in _prior_learned or not isinstance(value, str) or str.__str__(value) != hit[2]:
                    continue
                row = self.pending.setdefault(hit[0], [hit[1], [], _seconds(left)])
                if str(aid) not in row[1]:
                    row[1].append(str(aid))
        except Exception:  # noqa: BLE001 - never the run's undoing
            pass

    def flush(self, attempt_id=None) -> list:
        written = []
        pending, self.pending = self.pending, {}
        for key, (name, ids, left) in pending.items():
            if key in _prior_learned:
                continue
            _prior_learned.add(key)
            try:
                if learn(key, name, "accepted", scope="key", attempt_id=attempt_id, answer_ids=ids, left=left,
                         src=PRIOR_SRC):
                    written.append(key)
            except Exception:  # noqa: BLE001
                pass
        return written

    @staticmethod
    def note(keys) -> str:
        """The one NOTE line a runner prints for what flush() wrote ('' for nothing)."""
        if not keys:
            return ""
        return (f"family prior: the judge accepted the prior's answer for {', '.join(keys)}; recorded in the labels "
                f"ledger (row 415)")


_noted = set()  # keys already reported by _note_unlisted


def _note_unlisted(key, name, opts):
    """One stderr line per key and process when `pick` answers with an accepted name the
    caller did not offer. For a key of labels that is the rule. For a key whose options
    were meant as per-question values but were passed bare, it is a stale answer from an
    earlier variant, and this line is what shows it in the solver's triage."""
    if key in _noted:
        return
    _noted.add(key)
    offered = ", ".join(repr(n)[:40] for n, _ in opts[:3]) + (", ..." if len(opts) > 3 else "")
    print(f"[labels] {key}: answered {name!r} (accepted for the key), not one of the options offered"
          f" ({offered}); per-question values must be passed as (method, value) pairs", file=sys.stderr)


def _front_accepted(left, names, labels_only=False):
    """Order a split key's options so one probe is likeliest to close the id.

    On a split key the judge has already accepted one or more names for the key's OTHER ids,
    which is a real prior, so those names still lead. But AMONG them they are ordered by the
    CALLER's offered order (best byte-evidence first), not by the order they happened to be
    accepted in. The caller offers options best first (the solver's reading of THIS variant's
    bytes), and `left` is already in that order, so the accepted name the solver ranks highest
    is probed first and one probe can close the id.

    Why this is the close lever: the runners probe `left` one option per request, in order, and
    stop at the first the judge accepts, so the offered SET is unchanged (never-wrong holds: a
    pick/candidate is unsure, never plain) and only probes-to-close moves. Before, the front was
    built in acceptance order and the solver's ranking could not move the first probe -- the
    defect `solvers/script-analysis/day23_fold.py` documents (18/81 first-probe-correct, which a
    bespoke single-option workaround had to raise to 81/81). Here every caller of a split
    candidate key gets that for free.

    `left` is the options the key has not rejected, in the caller's order. `names` are the
    accepted names. For a bare-label key (labels_only) an accepted name the caller did not offer
    is still a possible answer for this id, so it is appended (its value is the name); a
    format/candidate key cannot send an unoffered accepted name (its value here is unknown)."""
    nameset = set(names)
    offered = [(n, v) for n, v in left if n in nameset]        # accepted & offered, caller order
    if labels_only:
        off = {n for n, _ in offered}
        offered += [(n, n) for n in names if n not in off]     # unoffered accepted labels, acceptance order
    return offered + [(n, v) for n, v in left if n not in nameset]


def pick(key, options):
    """The answer to return for an established fact whose name the judge may not have seen.

    A name accepted for the key (and the key not split): the plain value of that name. For
    a key of bare labels that is the accepted name itself, even when the caller's options
    do not list it. Otherwise the unsure string for the options whose names the key has not
    rejected (accepted names first when the key is split), at most 12. None when nothing is
    left, and for an empty option list: no fact, no answer. An option whose value is None
    (a format that could not be computed for this question) is not an option.

    Whether a key holds labels or per-question values is read from the options: bare
    strings are labels. So values passed bare are learned as names, and the next variant is
    answered with this one's value. Pass per-question values as (method, value) pairs.

    A key that ends in CANDIDATE_MARK is a candidate key, and is answered by `candidates`."""
    key = _key(key)
    if key.endswith(CANDIDATE_MARK):
        return candidates(key, options)
    opts = _pairs(options)
    if not opts:
        return None
    st = _lane_state(lane_of(key)).get(key) or {"accepted_names": [], "rejected": [], "split": False}
    names = st["accepted_names"]
    values = dict(opts)
    labels_only = all(isinstance(v, str) and v == n for n, v in opts)
    if names and not st["split"]:
        for name in names:
            if name in values:
                return values[name]
        if labels_only:
            _note_unlisted(key, names[0], opts)
            return names[0]
        # A format key whose accepted method the caller did not offer: its value under that
        # method is unknown here, so the answer stays unsure.
    if not names and not st["split"] and not st["rejected"]:
        prior = family_prior(key)                # row 388: a never-judged member of a unanimous family
        if prior is not None and prior[0] in values:
            _note_prior(key, prior)
            return _given_by_prior(key, prior[0], values[prior[0]])     # row 415: a runner can tell it apart
    rejected = set(st["rejected"])
    left = [(n, v) for n, v in opts if n not in rejected]
    if st["split"] and names:
        left = _front_accepted(left, names, labels_only=labels_only)
    if not left:
        return None
    return unsure(key, left[:MAX_OPTIONS])


# ---------------------------------------------------------------------------- candidate picks (row 346)

def candidate_key(key) -> str:
    """`key` as a candidate key: lowercase, ending in CANDIDATE_MARK (added once)."""
    key = _key(key)
    return key if key.endswith(CANDIDATE_MARK) else key + CANDIDATE_MARK


def is_candidate(value) -> bool:
    """True for a candidate pick in any of its forms: its key (a text that ends in
    CANDIDATE_MARK), its unsure string, or a parsed Unsure. False for anything else, a plain
    answer and an unsure string that does not parse included."""
    if isinstance(value, Unsure):
        value = value.key
    elif is_unsure(value):
        value = parse(value).key
    return isinstance(value, str) and value.strip().lower().endswith(CANDIDATE_MARK)


_said = set()  # (key, what) already reported by candidates


def _say_once(key, what, text):
    if (key, what) not in _said:
        _said.add((key, what))
        print(f"[labels] {key}: {text} (row 346)", file=sys.stderr)


def candidates(key, options):
    """The answer to return when the bytes establish a short list of DIFFERENT candidate values
    and nothing proves which one the judge asks (backlog row 346, the player's yes of 2026-10-17;
    the organizer's ruling: guesses to the Game Master are acceptable). Day 17 asked
    `recover_code` of a stripped build (the literal `none`, or the immediate the code loads) and
    PE symbol names (the bare name, or the COFF COMDAT `.text$<name>` the table lists first).

    options   (name, value) pairs, best evidence first. The name names the HYPOTHESIS
              (`stripped_none`, `immediate`, `comdat`, `bare`), never the value: the accepted
              name is what the ledger carries to the next variant, where it answers that
              variant's own value under the same hypothesis. A bare option (no name) is no
              hypothesis: it is dropped, with one stderr line.
    key       `<lane>.<field>/<shape>` as for pick, with everything the hypotheses depend on in
              the shape (`binary.recover_code/elf+stripped`). CANDIDATE_MARK is added to it, so
              the key of the wire form, the ledger and every NOTE line is a candidate key.

    Returns, as pick does: the plain value of the accepted name once the judge has accepted one
    for the key (and the key is not split) and this variant offers it; otherwise the unsure
    string for the options the key has not rejected, accepted names first when the key is split;
    None when none is left. Never plain before a name is accepted, and never the accepted name
    itself when this variant does not offer it: nothing then proves another hypothesis.

    At most MAX_OPTIONS (12) options, the FIRST 12 offered, before the rejected ones are taken
    out: a candidate key has 12 guesses in all, not 12 at a time. More are cut, with one stderr
    line. tools/verify.py probes the key on an untimed base like any key (one option per
    request, the first accepted name stops it); inside a timed attempt it is probed only when
    the attempt has no deadline. Nothing of it goes to CourseStack."""
    key = candidate_key(key)
    items = [options] if isinstance(options, (str, bytes)) else list(options or ())
    named = [o for o in items if isinstance(o, (list, tuple)) and len(o) == 2 and isinstance(o[0], str)]
    if len(named) < len(items):
        _say_once(key, "bare", f"{len(items) - len(named)} candidate option(s) without a (name, value) pair were "
                               f"dropped: a candidate's name names its hypothesis, never its value")
    opts = _pairs(named)
    if len(opts) > MAX_OPTIONS:
        _say_once(key, "cut", f"{len(opts)} candidate values offered; only the first {MAX_OPTIONS} are kept")
        opts = opts[:MAX_OPTIONS]
    if not opts:
        return None
    st = _lane_state(lane_of(key)).get(key) or {"accepted_names": [], "rejected": [], "split": False}
    names = st["accepted_names"]
    values = dict(opts)
    if names and not st["split"]:
        for name in names:
            if name in values:
                return values[name]
    rejected = set(st["rejected"])
    left = [(n, v) for n, v in opts if n not in rejected]
    if st["split"] and names:
        left = _front_accepted(left, names, labels_only=False)   # names name hypotheses: never bare labels
    if not left:
        return None
    return unsure(key, left)


_gate_said = set()  # what the judge-ledger gate has already reported on stderr


def degenerate_accept(options, name) -> bool:
    """True when accepting `name` could not have distinguished it: its offered value equals the value
    of another offered option, so the judge's yes is consistent with more than one name (B-040, the
    order-degenerate guard). The classic case is a transform whose input is already in its output form
    -- already-sorted bytes, where the `sorted` and `as_is` spellings coincide, or an identity XOR key
    0x00: the batch is CORRECT, but nothing proves `sorted` over `as_is`, so a fold must NOT promote it
    to a plain answer. A recorder passes the result to `learn(..., degenerate=...)`; `_fold` then banks
    the row's evidence but never its name, so `pick` stays unsure until a run on a non-degenerate input
    (where the spellings differ) accepts it for real.

    `options` are the (name, value) pairs or bare labels `pick`/`candidates` were offered for this
    question; a value of None is no option (as everywhere). For a bare-label key every value is its own
    name, so no two collide and the answer is never degenerate. Unknown name: False (nothing to guard)."""
    pairs = _pairs(options)
    values = dict(pairs)
    if name not in values:
        return False
    mine = values[name]
    return any(other != name and value == mine for other, value in pairs)


def learn(key, name, verdict, scope="key", attempt_id=None, answer_ids=(), left=None, ids=None, src=None,
          degenerate=False) -> bool:
    """Record one verdict of the judge on a name, as a row of the runtime ledger.

    verdict   'accepted' (from accepted or CORRECT), 'rejected' (a single-id request
              answered incorrect), or 'split' (the name was accepted for one id of the key
              and the rest of the key was then rejected under it).
    scope     'key' when the verdict speaks for the whole key, else the answer id it is
              limited to.
    left      seconds left on the clock, None on an untimed base. Rows with less than 0.3
              are kept in the file and ignored when the ledger is read.
    ids       an alias of answer_ids (the name tools/grade.py's on_learn hook passes).
    src       who wrote the row, when it is not a probe or a runner's own verdict: "prior" for the
              family prior's rows (PriorWatch.flush, row 415). Written as the row's "src" field
              only when given; tools/preflight.py leaves such rows out of the lane hash's ledger
              size (the Day 21 final prep), since they change no answer a replay gives.
    degenerate  the order-degenerate guard (B-040): True for an `accepted` verdict the input could not
              distinguish (degenerate_accept). Written as the row's "degenerate" field; `_fold` keeps
              its evidence but never promotes the name to plain. Meaningless for a rejection or split.

    Appended under an exclusive flock, so concurrent runs interleave whole rows. Returns
    False, after one stderr line, if the row could not be written: losing a row costs a
    probe later, and must not cost the attempt that is being submitted now.

    Without a judge ledger (judge_ledger() off) nothing is written: False, after one stderr line
    per process that says why."""
    if not judge_ledger():
        if "learn" not in _gate_said:
            _gate_said.add("learn")
            print(f"[labels] learn: not recorded; this event has no judge ledger (${JUDGE_LEDGER_ENV}=off)",
                  file=sys.stderr)
        return False
    key = _key(key)
    if verdict not in VERDICTS:
        raise ValueError(f"labels.learn: verdict must be one of {', '.join(VERDICTS)}, not {verdict!r}")
    if not isinstance(name, str) or not name:
        raise ValueError(f"labels.learn: name must be a non-empty string, not {name!r}")
    if ids is not None and not answer_ids:
        answer_ids = ids
    if isinstance(answer_ids, str):
        answer_ids = [answer_ids]
    left = _seconds(left)
    if left is not None:
        # Three decimals are enough to read, but rounding must not carry a verdict across
        # the trust threshold (0.2996 would be written as 0.3 and then believed).
        rounded = round(left, 3)
        left = rounded if (rounded < MIN_LEFT) == (left < MIN_LEFT) else left
    row = {"t": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "key": key, "name": name,
           "verdict": verdict, "scope": str(scope or "key"), "attempt_id": attempt_id,
           "answer_ids": [str(i) for i in (answer_ids or ())], "left": left}
    if src:
        row["src"] = str(src)
    if degenerate and verdict == "accepted":
        row["degenerate"] = True
    path = ledger_path(lane_of(key))
    line = (json.dumps(row, separators=(",", ":")) + "\n").encode("utf-8")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            size = os.fstat(fd).st_size
            if size and os.pread(fd, 1, size - 1) != b"\n":
                line = b"\n" + line  # a torn last line must not swallow this row
            os.write(fd, line)
        finally:
            os.close(fd)  # closing the descriptor releases the lock
    except OSError as e:
        print(f"[labels] could not record {verdict} {name!r} for {key}: {e}", file=sys.stderr)
        return False
    _cache.pop(path, None)
    return True


# ---------------------------------------------------------------------------- candidate names

def _snake(text) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(text).lower()).strip("_")


def _tokens(text) -> set:
    return {t for t in _snake(text).split("_") if t}


# Keywords that mean "an error handler wraps the call", whatever the language.
ERROR_WORDS = {"error", "err", "onerror", "try", "catch", "except", "rescue", "trap", "finally"}

# Suffixes the judge has used for each class of control flow, in the order to try them.
# Day 4 evidence: for_once, do_once, while_once; errorlevel_guard, error_guard, if_guard;
# select_case; goto_dispatch; call_subroutine; direct.
_SUFFIXES = {
    "loop": ("once", "loop"),
    "multiway": ("case", "dispatch"),
    "dispatch": ("dispatch",),
    "subroutine": ("subroutine",),
}


def patterns(keyword, klass, family_vocab=(), cap=MAX_OPTIONS) -> list:
    """Candidate names for a control-flow form, best first, built the way the judge's known
    names are built: <keyword>_<what the block does>.

      loop        <kw>_once, <kw>_loop
      guard       <kw>_guard, then error_guard for an error keyword, if_guard, direct
      multiway    <kw>_case, <kw>_dispatch
      dispatch    <kw>_dispatch
      subroutine  <kw>_subroutine
      direct      direct

    Then the names in `family_vocab` that share a token with the keyword, and `direct` last
    if it is not there yet (a wrapper the judge treats as layout is named `direct`). At most
    `cap` names, all lowercase snake_case apart from family names, which are kept as given."""
    kw = _snake(keyword)
    klass = _snake(klass)
    out = []

    def add(name):
        if name and name not in out:
            out.append(name)

    def joined(suffix):
        if not kw:
            return ""
        return kw if kw == suffix or kw.endswith("_" + suffix) else f"{kw}_{suffix}"

    if klass == "guard":
        add(joined("guard"))
        if _tokens(kw) & ERROR_WORDS:
            add("error_guard")
        add("if_guard")
        add("direct")
    elif klass == "direct":
        add("direct")
    else:
        for suffix in _SUFFIXES.get(klass, ()):
            add(joined(suffix))
    kw_tokens = _tokens(kw)
    cap = max(1, int(cap))
    for name in family_vocab or ():
        if len(out) >= cap:  # only the first `cap` names are returned; a long vocabulary costs nothing more
            break
        if isinstance(name, str) and _tokens(name) & kw_tokens:
            add(name)
    if "direct" not in out[:cap]:
        out = [n for n in out if n != "direct"][:cap - 1] + ["direct"]
    return out[:cap]


def spell(tokens, family_vocab=(), text_vocab=(), cap=MAX_OPTIONS) -> list:
    """Candidate spellings of one fact given as its tokens (['pe', 'cli']), best first:

      1. names from `family_vocab` (accepted for sibling keys) that are spelled from these
         tokens: 'pe' and 'PE-CLI' are, 'elf' and 'pe32' are not;
      2. names from `text_vocab` (words the question itself lists), by the same test;
      3. the tokens joined with underscores, in the given order and reversed, then each
         ordered pair when there are more than two;
      4. each token alone;
      5. the same joins with other separators ('-', none, '+', '.', '/'), which come only
         after every underscore form: every judged multi-word label so far is snake_case.

    A vocabulary name that merely shares a token is another fact (x86-64 is not a spelling
    of arm 64) and is left out, so the list holds spellings of ONE fact as long as the
    caller passes the tokens of one. Generated names are lowercase with no spaces;
    vocabulary names are kept as the judge or the question wrote them. `pick` drops the
    names the key has rejected."""
    if isinstance(tokens, str):
        tokens = [tokens]
    toks = []
    for t in tokens or ():
        for part in _snake(t).split("_"):
            if part and part not in toks:
                toks.append(part)
    cap = max(1, int(cap))
    # Every way of writing some of the tokens next to each other, separators removed. A fact
    # has two or three tokens; a caller that passes a whole sentence must not buy millions
    # of permutations inside a timed window, so only the first six take part.
    head = toks[:_SPELL_TOKENS]
    squashed = {"".join(p) for r in range(1, min(len(head), 4) + 1) for p in permutations(head, r)}

    def orders():
        if len(toks) > 1:
            yield toks
            yield toks[::-1]
            if len(toks) > 2:
                yield from permutations(toks, 2)

    def candidates():
        for vocab in (family_vocab, text_vocab):
            for name in vocab or ():
                if isinstance(name, str) and _snake(name).replace("_", "") in squashed:
                    yield name
        for order in orders():
            yield "_".join(order)
        yield from toks
        for order in orders():
            for sep in ("-", "", "+", ".", "/"):
                yield sep.join(order)

    # Built lazily and stopped at the cap: the list is the same as building everything and
    # cutting it, without the work for the part that would be cut.
    out, seen = [], set()
    for name in candidates():
        if name and name not in seen:
            seen.add(name)
            out.append(name)
            if len(out) >= cap:
                break
    return out


_ITEM = r"[A-Za-z0-9][A-Za-z0-9_.+#-]*"
# One pass over the text: an item, a comma, a run of white space, or any other character.
_TOKEN = re.compile(rf"({_ITEM})|(,)|(\s+)|.", re.S)
_WORD, _COMMA, _SPACE = 1, 2, 3


def _comma_lists(text):
    """Every `item, item[, item ...][,] or|and item` list in the text, left to right, as
    lists of items. The grammar is that of the pattern

        ITEM (,\\s*ITEM)+? ,?\\s+(or|and)\\s+ ITEM

    read lazily (the closing word is taken as soon as it fits), but walked token by token
    in one pass. Question text is untrusted and may be long: the pattern itself backtracks
    from every start, which on a few thousand comma-separated words with no closing "or"
    takes seconds, more than a timed window has."""
    toks = [(m.lastindex or 0, m.group()) for m in _TOKEN.finditer(text)]
    n = len(toks)

    def kind(k):
        return toks[k][0] if k < n else -1

    i = 0
    while i < n:
        if kind(i) != _WORD:
            i += 1
            continue
        items, j, closed = [toks[i][1]], i + 1, False
        while True:
            if len(items) > 1:  # the closing word, once one comma item has been read
                k = j + 1 if kind(j) == _COMMA else j
                if (kind(k) == _SPACE and kind(k + 1) == _WORD and toks[k + 1][1] in ("or", "and")
                        and kind(k + 2) == _SPACE and kind(k + 3) == _WORD):
                    items.append(toks[k + 3][1])
                    j, closed = k + 4, True
                    break
            if kind(j) == _COMMA:
                k = j + 2 if kind(j + 1) == _SPACE else j + 1
                if kind(k) == _WORD:
                    items.append(toks[k][1])
                    j = k + 1
                    continue
            break
        if closed:
            yield items
        # A list that failed to close fails the same way from each of its later items, so
        # the scan resumes after it: every token is visited a bounded number of times.
        i = max(j, i + 1)


def enum_from_question(text, raw=False) -> list:
    """The names a question lists as its possible answers, in the question's order.

    "Identify the percent, delayed, CALL-double, or FOR-indirect expansion form." gives
    percent, delayed, call_double, for_indirect. Only a comma list of at least three
    one-word items ending in "or" or "and" counts; the longest such list wins. Names come
    back in snake_case, the judge's style for labels (raw=True keeps the question's own
    spelling). An empty list when the question enumerates nothing."""
    text = re.sub(r"[`'\"*‘’“”]", "", str(text or ""))
    best = []
    for items in _comma_lists(text):
        items = [i.rstrip(".") for i in items]
        if len(items) > len(best):
            best = items
    if raw:
        return best
    out = []
    for item in best:
        name = _snake(item)
        if name and name not in out:
            out.append(name)
    return out


# ---------------------------------------------------------------------------- promote

def promote(lane: str, dry_run=False, workdir=None) -> list:
    """Fold the lane's runtime rows into its tracked seed, each with its evidence.

    The mask is not applied and the runtime ledger is left as it is, so the command can be
    run again: evidence strings already in the seed are not added twice. An order-degenerate
    acceptance (B-040) folds its evidence but not its name, exactly as `pick` reads it. Returns
    one line per key that changed. ValueError without a judge ledger: there are no verdicts to fold.
    `workdir`, when given, is the event workdir whose runtime ledger is folded (seedfold passes the
    accepted solve's own --workdir); otherwise the ambient event's is used."""
    if not judge_ledger():
        raise ValueError(f"this event has no judge ledger (${JUDGE_LEDGER_ENV}=off): nothing to promote")
    lane = LANE_ALIASES.get(lane, lane)
    if lane not in LANE_DIRS:
        raise ValueError(f"unknown lane {lane!r}: use one of {', '.join(LANE_DIRS)}")
    path = seed_path(lane)
    seed = {}
    if path.exists():
        seed = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(seed, dict):
            raise ValueError(f"{path}: not a JSON object")
    by_key = {}
    for row in _read_rows(lane, workdir):
        by_key.setdefault(row["key"].strip().lower(), []).append(row)
    changed = []
    for key, rows in by_key.items():
        old = seed.get(key) if isinstance(seed.get(key), dict) else {}
        st = _fold(old, rows)
        new = {"accepted": st["accepted"], "rejected": st["rejected"], "split": st["split"],
               "evidence": st["evidence"]}
        if len(st["accepted_names"]) > 1:
            new["accepted_names"] = st["accepted_names"]
        if new != {k: old.get(k) for k in new}:
            seed[key] = new
            changed.append(f"{key}: accepted={st['accepted']} rejected={len(st['rejected'])}"
                           f" split={str(st['split']).lower()} rows={len(rows)}")
    if changed and not dry_run:
        path.parent.mkdir(parents=True, exist_ok=True)      # a toolkit's seed folder is made by its first promote
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(seed, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.replace(tmp, path)
        _cache.pop(path, None)
    return changed


def show(value) -> str:
    """Render a pick()/candidates() result for a human: a plain value as-is, an unsure string
    as its ranked candidate values (best first)."""
    if is_unsure(value):
        u = parse(value)
        vals = [str(v) for _, v in u.options]
        return "candidates: " + ", ".join(vals) if vals else "(no candidates)"
    return "" if value is None else str(value)


def main(argv) -> int:
    usage = "usage: labels.py promote <lane> [--dry-run]   (lanes: " + ", ".join(LANE_DIRS) + ")"
    args = [a for a in argv if not a.startswith("--")]
    flags = [a for a in argv if a.startswith("--")]
    if len(args) != 2 or args[0] != "promote" or any(f != "--dry-run" for f in flags):
        print(usage, file=sys.stderr)
        return 2
    dry = "--dry-run" in flags
    try:
        lane = LANE_ALIASES.get(args[1], args[1])
        changed = promote(lane, dry_run=dry)
    except (ValueError, OSError) as e:
        print(f"labels.py promote: {e}", file=sys.stderr)
        return 2
    for line in changed:
        print(line)
    verb = "would update" if dry else "updated"
    print(f"promote {lane}: {verb} {len(changed)} key(s) in {seed_path(lane)} from {ledger_path(lane)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
