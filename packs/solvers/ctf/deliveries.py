"""Which delivery serves which set of a multi-set attempt (B-042).

A Mastery asks the same questions of several sets (`set1.<id>`, `set2.<id>`, ...) and ships each set's
own file: one delivery per set (three `blob.txt`, two `evidence.zip`, an APK each), or one bundle
holding a numbered member per set (`blob-01.txt`, `evidence-02.zip`). The deliveries often carry the
same file name and the same member names, so a set answered from a neighbour's delivery gets a
well-formed, wrong answer. This module is the one rule for the pairing, and it fails closed: a set whose
delivery is not proven gets none, with the reason, never the nearest one.

    choice = choose(n, questions_of_set_n, set_numbers, delivery_count, members)   # one set
    choices = plan(attempt, members=None)                                         # every set, in set order
    saved = read_attempt(folder)             # Saved(attempt, names, blobs, folder) of a saved attempt
    inputs = set_inputs(saved)               # [SetInput(choice, label, name, data)]: each set's own bytes
    line = unsolved_line(n, ctx)             # the error of a set a solver never read (is_unsolved_line)

The rules, in the order they are tried (`Choice.rule`):

  all       the attempt has one set: it sees every delivery (`index` and `member` are None), also when
            there is none (a live-target attempt). One numbered set whose questions all name the same
            one of several deliveries reads that one (`named`), as the runner always did.
  named     every question of the set that names a delivery (`delivery 2: evidence.zip -> x.ps1`, at the
            start of its `artifact` text) names the same one, and the attempt has it.
  position  no question of the set names a delivery, there are several deliveries, and the set numbers
            are exactly 1..<deliveries>: set N reads delivery N.
  member    one delivery (a bundle) for several sets: its one top-level member numbered N just before
            the extension (`ctf.idresolve.SET_MEMBERS`, the runner's set rule). When several members
            carry the number, the one the set's questions name first in their container chain.
  unmapped  nothing above holds. `reason` says why: questions naming two deliveries, a delivery number
            the attempt does not have, set numbers that do not pair with the deliveries, a bundle with
            no member (or no single member) for the set, a multi-set attempt with no delivery.

A bundle with no numbered member is read whole by a set only when the set's own questions say so
(`delivery 1: ...`, the `named` rule). `tools/run.py`'s `split_sets` takes every set's delivery from
`choose`, so every runner, replay and gate that splits an attempt gets the same pairing; an unmapped
set reaches the solver with no files and is reported, not solved.

`read_attempt` reads the layout the runners and the Game Master adapter save: `attempt.json` beside
`artifact/<file>` (one delivery) or `artifact/delivery-NN/<file>` (several), each checked against the
attempt's sha256 when it states one. A missing delivery, a file name that leaves its folder and a hash
that does not match are DeliveryError. The contract is docs/CONTRACTS.md section 53.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from .idresolve import SET_MEMBERS, SET_PREFIX

__all__ = ["DeliveryError", "Choice", "Saved", "SetInput", "ALL", "NAMED", "POSITION", "MEMBER", "UNMAPPED",
           "ATTEMPT", "ARTIFACTS", "set_of", "named_delivery", "chain", "choose", "plan", "is_attempt",
           "read_attempt", "bundle_members", "set_inputs", "NOT_DOWNLOADED", "UNPROVEN",
           "unsolved_line", "is_unsolved_line"]

ALL, NAMED, POSITION, MEMBER, UNMAPPED = "all", "named", "position", "member", "unmapped"
ATTEMPT = "attempt.json"          # a saved attempt's body
ARTIFACTS = "artifact"            # the folder beside it that holds its deliveries

_NAMED = re.compile(r"\s*delivery\s+(\d+)\s*:")          # at the start of a question's artifact text
_SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")


class DeliveryError(ValueError):
    """A saved attempt that cannot be read (no attempt.json, a delivery missing or changed), or a
    pairing asked for without what it needs (a bundle's member names)."""


@dataclass(frozen=True)
class Choice:
    """The delivery that serves one set, and by which rule; `reason` is set when there is none."""
    set: int
    rule: str
    index: int | None = None        # 0-based delivery; None for `all` and `unmapped`
    member: str | None = None       # rule `member`: the bundle's top-level member that is the set's delivery
    reason: str = ""

    @property
    def mapped(self) -> bool:
        return self.rule != UNMAPPED

    def label(self, names: Sequence[str]) -> str:
        """`delivery 2: blob.txt`, `delivery 1: bundle.zip -> blob-02.txt`, `every delivery`, or
        `UNMAPPED: <reason>`."""
        if self.rule == UNMAPPED:
            return f"UNMAPPED: {self.reason}"
        if self.index is None:
            return "every delivery"
        name = names[self.index] if self.index < len(names) else "?"
        head = f"delivery {self.index + 1}: {name}"
        return f"{head} -> {self.member}" if self.member is not None else head

    def to_dict(self) -> dict:
        return {"set": self.set, "rule": self.rule, "delivery": None if self.index is None else self.index + 1,
                "member": self.member, "reason": self.reason}


def set_of(question: dict) -> int:
    """The set a question belongs to: N of a leading `setN.` in its id, else its integer `set` field,
    else 0 (the attempt has no sets). The runner's own reading (tools/run.py `shaped`)."""
    m = SET_PREFIX.match(str(question.get("id") or ""))
    if m:
        return int(m.group(1))
    n = question.get("set")
    return n if isinstance(n, int) and not isinstance(n, bool) else 0


def named_delivery(question: dict) -> int | None:
    """K when the question's artifact text starts `delivery K:`, else None."""
    m = _NAMED.match(str(question.get("artifact") or ""))
    return int(m.group(1)) if m else None


def chain(question: dict) -> list[str]:
    """The container chain a question names, without its `delivery K:` head:
    `delivery 1: evidence.zip -> stage.zip -> x.js` is ['evidence.zip', 'stage.zip', 'x.js']."""
    text = _NAMED.sub("", str(question.get("artifact") or ""), count=1)
    return [p.strip() for p in text.split("->") if p.strip()]


def _numbered(n: int, members: Iterable[str]) -> list[str]:
    rule = re.compile(SET_MEMBERS.replace("{n}", str(int(n))))
    return [m for m in members if rule.search(m)]


def _list(numbers: Iterable[int]) -> str:
    return ", ".join(str(k) for k in numbers)


def choose(n: int, questions: Sequence[dict], sets: Sequence[int], count: int,
           members: Sequence[str] | None = None) -> Choice:
    """The delivery that serves set `n`. `questions` are the set's own, `sets` every set number of the
    attempt, `count` how many deliveries it has, `members` the top-level member names of the one
    delivery when several sets share it (DeliveryError when that case is asked without them)."""
    sets = sorted(set(sets))
    named = sorted({k for k in (named_delivery(q) for q in questions) if k is not None})
    if len(sets) <= 1:
        if n >= 1 and count > 1 and len(named) == 1 and 1 <= named[0] <= count:
            return Choice(n, NAMED, index=named[0] - 1)
        return Choice(n, ALL)
    if count < 1:
        return Choice(n, UNMAPPED, reason="the attempt has no delivery")
    if len(named) > 1:
        return Choice(n, UNMAPPED, reason=f"its questions name deliveries {_list(named)}, not one")
    if named and not 1 <= named[0] <= count:
        return Choice(n, UNMAPPED, reason=f"its questions name delivery {named[0]}, and the attempt has {count}")
    if count > 1:
        if named:
            return Choice(n, NAMED, index=named[0] - 1)
        if n >= 1 and sets == list(range(1, count + 1)):
            return Choice(n, POSITION, index=n - 1)
        return Choice(n, UNMAPPED, reason=f"no question names a delivery, and sets {_list(sets)} do not pair "
                                          f"one to one with {count} deliveries")
    # One delivery for several sets: a bundle with a numbered member per set.
    if members is None:
        raise DeliveryError(f"set {n}: one delivery serves {len(sets)} sets, so the pairing needs the bundle's "
                            "member names (bundle_members)")
    hits = _numbered(n, members) if n >= 1 else []
    if len(hits) == 1:
        return Choice(n, MEMBER, index=0, member=hits[0])
    if len(hits) > 1:
        heads = {c[0] for c in (chain(q) for q in questions) if c}
        said = [m for m in hits if m in heads]
        if len(said) == 1:
            return Choice(n, MEMBER, index=0, member=said[0])
        return Choice(n, UNMAPPED, reason=f"{len(hits)} members of the bundle are numbered {n} "
                                          f"({', '.join(hits[:4])}) and its questions do not name one of them")
    if named and all(named_delivery(q) is not None for q in questions):
        return Choice(n, NAMED, index=0)          # the set's own questions name the whole bundle
    return Choice(n, UNMAPPED, reason=f"no member of the bundle is numbered {n}, and its questions do not "
                                      "name delivery 1")


def _groups(attempt: dict) -> dict[int, list[dict]]:
    out: dict[int, list[dict]] = {}
    for q in attempt.get("questions") or []:
        if isinstance(q, dict):
            out.setdefault(set_of(q), []).append(q)
    return out


def plan(attempt: dict, members: Sequence[str] | None = None, count: int | None = None) -> list[Choice]:
    """Every set's Choice, in set order. `count` defaults to the attempt's artifacts[]; `members` as
    in `choose`."""
    groups = _groups(attempt)
    if count is None:
        count = len(attempt.get("artifacts") or [])
    order = sorted(groups)
    return [choose(n, groups[n], order, count, members) for n in order]


# --------------------------------------------------------------------------- a saved attempt

@dataclass(frozen=True)
class Saved:
    attempt: dict
    names: tuple[str, ...]          # the file name of each delivery, in delivery order
    blobs: tuple[bytes, ...]
    folder: Path


def is_attempt(path) -> bool:
    """Whether `path` is a saved attempt's body: a regular file named attempt.json."""
    p = Path(path)
    return p.name == ATTEMPT and p.is_file() and not p.is_symlink()


def _artifacts(attempt: dict) -> list[dict]:
    arts = attempt.get("artifacts")
    if isinstance(arts, list) and arts:
        return [a if isinstance(a, dict) else {} for a in arts]
    if attempt.get("download") or attempt.get("sha256"):      # an active base or Time Trial attempt
        return [{"filename": attempt.get("filename"), "sha256": attempt.get("sha256")}]
    return []


def read_attempt(path) -> Saved:
    """The saved attempt at `path` (its folder, or the attempt.json in it) with every delivery's bytes.
    DeliveryError names what is missing or wrong; nothing is guessed."""
    p = Path(path)
    folder = p.parent if p.name == ATTEMPT else p
    body = folder / ATTEMPT
    if not body.is_file() or body.is_symlink():
        raise DeliveryError(f"no {ATTEMPT} under {folder}")
    try:
        attempt = json.loads(body.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise DeliveryError(f"{body}: not readable JSON: {e}") from None
    if not isinstance(attempt, dict) or not isinstance(attempt.get("questions"), list):
        raise DeliveryError(f"{body}: not an attempt (a JSON object with a questions list)")
    arts = _artifacts(attempt)
    base = folder / ARTIFACTS
    names, blobs = [], []
    for i, art in enumerate(arts):
        where = base if len(arts) == 1 else base / f"delivery-{i + 1:02d}"
        what = f"delivery {i + 1} of {len(arts)}"
        name = art.get("filename")
        if name is None or name == "":
            found = [x for x in sorted(where.iterdir()) if x.is_file() and not x.is_symlink()] if where.is_dir() else []
            if len(found) != 1:
                raise DeliveryError(f"{what} names no file, and {where} holds {len(found)} files, not one")
            file = found[0]
        else:
            if not isinstance(name, str) or Path(name).name != name or name in (".", ".."):
                raise DeliveryError(f"{what}: file name {name!r} is not a plain file name")
            file = where / name
        if not file.is_file() or file.is_symlink():
            raise DeliveryError(f"{what} is not saved at {file}")
        data = file.read_bytes()
        want = art.get("sha256")
        if isinstance(want, str) and want:
            if not _SHA256.match(want):
                raise DeliveryError(f"{what}: the attempt's sha256 {want[:80]!r} is not 64 hex characters")
            got = hashlib.sha256(data).hexdigest()
            if got != want.lower():
                raise DeliveryError(f"{what}: {file} has sha256 {got}, and the attempt says {want.lower()}")
        names.append(file.name)
        blobs.append(data)
    return Saved(attempt, tuple(names), tuple(blobs), folder)


def bundle_members(name: str, data: bytes, attempt: dict | None = None) -> dict[str, bytes]:
    """{member: bytes} for the top-level members of a one-bundle delivery, read by the runner's own
    expander (tools/archive_expand.py: the same passwords, the same member names), one level deep."""
    from . import sweep
    ae = sweep.archive_expand()
    out: dict[str, bytes] = {}
    ae.expand(name, data, out, keys=ae.Keys(attempt), _skip=lambda member: True)
    head = name + " -> "
    return {k[len(head):]: v for k, v in out.items() if k.startswith(head) and " -> " not in k[len(head):]}


@dataclass(frozen=True)
class SetInput:
    """One set of a saved attempt with the bytes of its own delivery. `name` and `data` are None when
    the set is unmapped, and for the one set of an attempt with several deliveries (it reads them all)."""
    choice: Choice
    label: str                      # Choice.label over the saved names
    name: str | None                # the file name the bytes go by (the delivery's, or the member's base name)
    data: bytes | None


def set_inputs(saved: Saved) -> list[SetInput]:
    """Each set of a saved attempt with its own delivery's bytes, in set order."""
    count = len(saved.blobs)
    groups = _groups(saved.attempt)
    order = sorted(groups)
    bundle = None
    if count == 1 and len(order) > 1:
        bundle = bundle_members(saved.names[0], saved.blobs[0], saved.attempt)
    out = []
    for n in order:
        c = choose(n, groups[n], order, count, None if bundle is None else list(bundle))
        label = c.label(saved.names)
        if not c.mapped:
            out.append(SetInput(c, label, None, None))
        elif c.rule == ALL and count == 1:
            out.append(SetInput(c, f"delivery 1: {saved.names[0]}", saved.names[0], saved.blobs[0]))
        elif c.rule == ALL:
            out.append(SetInput(c, label, None, None))        # no delivery, or one set over several
        elif c.member is not None:
            out.append(SetInput(c, label, Path(c.member).name, bundle[c.member]))
        else:
            out.append(SetInput(c, label, saved.names[c.index], saved.blobs[c.index]))
    return out


# --------------------------------------------------------------------------- a set a solver never read

NOT_DOWNLOADED = "its delivery was not downloaded"          # mapped, but its bytes never arrived
UNPROVEN = "no delivery is proven to be its own"            # split_sets left it unmapped (ctx["delivery_unmapped"])


def unsolved_line(n: int, ctx: dict) -> str:
    """The error line of a set that reached a solver with no delivery: the reason the split gave
    (`ctx["delivery_unmapped"]`) when it left the set unmapped, else that its delivery was not
    downloaded. tools/run.py, ctf.adapt.setpool and the Huntress timed runner all say it this way."""
    why = ctx.get("delivery_unmapped")
    if why:
        return f"set {n}: {UNPROVEN} ({why}), so it was not solved"
    return f"set {n}: {NOT_DOWNLOADED}, so it was not solved"


def is_unsolved_line(line: str) -> bool:
    """True for a line `unsolved_line` wrote. A second pass cannot give such a set a delivery, so the
    line stays an error after a first pass that was cut, where the cut lines become NOTEs."""
    return NOT_DOWNLOADED in line or UNPROVEN in line
