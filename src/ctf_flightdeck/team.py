"""The team channel: teammates' flightdecks share claims, live-box holds and solves
through a shared folder (a network drive, Syncthing, a shared mount). There is no server
and no network code here: each flightdeck reads and writes small JSON files, and whatever
keeps the folder in sync between teammates carries them.

Layout, one file per challenge and kind (the file name is the challenge id):

    flightdeck-team.txt   the marker, written once by `flightdeck team init`
    claims/<id>.json      who is working the challenge
    boxes/<id>.json       who holds its live instance
    solves/<id>.json      who solved it

each {"who": <handle>, "at": <wall-clock seconds>, "note": <text>}. Writes are atomic (a
hidden temp file in the same folder, then os.replace), so a reader or a sync tool never
sees half a file. Every write first checks the marker: a network drive that is no longer
mounted leaves an empty mount point behind, and claims written there would reach nobody.

Everything in the folder is untrusted: a teammate's flightdeck, a sync conflict or anyone
with access to the folder may have written it. A handle must match HANDLE (and is never
"me", the deck's word for the player), an id the board's id rule, and a file that is
malformed, too big or odd (a symlink, a FIFO, a folder) is ignored and reported in
TeamState.problems: never followed, never run, never read past MAX_MARK_BYTES. A note is
data, and a note holding a lone surrogate is not text: that mark is ignored too. Names,
notes and paths are shown only through printable() (text.untrusted(), plus lone surrogates
made visible). Nothing secret is written: no flags, keys or tokens (a solve's note names the
lane that found it).

Claims and box holds are advisory and the last write wins: two flightdecks that claim one
challenge at the same moment can each believe they hold it until the next poll shows the
folder's holder, and the deck then warns. A claim or a box hold older than stale_after
counts as released (a flightdeck that stopped without letting go); a running flightdeck
renews its own (TeamWatcher), so they last as long as it holds them. Solves never expire.
A mark dated more than FUTURE_SLACK ahead of this machine's clock is reported, and for a
claim or a box hold ignored, so a broken clock cannot pin a claim forever.

One handle per running flightdeck: two flightdecks under one handle take each other's
marks for their own.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import json
import math
import os
import re
import secrets
import shlex
import stat
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING

from .core.interventions import Claim
from .core.model import ME, ChallengeStatus, Event, EventKind, PendingKind
from .platform.manual import ID, ID_RULE, MAX_ID
from .text import untrusted

if TYPE_CHECKING:
    from .core.deck import Deck

HANDLE = re.compile(r"[A-Za-z0-9_.-]{1,40}")
HANDLE_RULE = "1 to 40 letters, digits and _ . -, and not 'me'"
KINDS = ("claims", "boxes", "solves")
MARKER = "flightdeck-team.txt"
MARK_KEYS = ("who", "at", "note")
STALE_AFTER = 6 * 3600.0  # a claim or box hold older than this counts as released
FUTURE_SLACK = 600.0  # seconds a mark may be dated ahead of this machine's clock
MAX_MARK_BYTES = 4096
MAX_NOTE = 200
MAX_ENTRIES = 2000  # entries read per kind folder; the rest are reported, not read
POLL_SECONDS = 5.0

MARKER_TEXT = """\
This folder is a ctf-flightdeck team channel. Teammates' flightdecks share claims,
live-box holds and solves here: one small JSON file per challenge in claims/, boxes/
and solves/, each {"who", "at", "note"}. Keep it synced between teammates (a network
drive, Syncthing, a shared mount). Put nothing else here and nothing secret: no flags,
keys or tokens.
"""

_SURROGATE = re.compile("[\ud800-\udfff]")  # a lone surrogate: half of a pair, never text on its own
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC  # a FIFO must not block the read
_CREATE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


@dataclass(frozen=True)
class Mark:
    who: str  # a teammate handle
    at: float  # wall-clock seconds (time.time()) on the writer's machine
    note: str = ""


@dataclass(frozen=True)
class TeamState:
    claims: Mapping[str, Mark]  # challenge id -> holder (fresh claims only)
    boxes: Mapping[str, Mark]  # challenge id -> who holds its live instance (fresh holds only)
    solves: Mapping[str, Mark]  # challenge id -> who solved it
    problems: tuple[str, ...] = ()  # files that were ignored, and why


class TeamError(Exception):
    """The team folder cannot be used as asked; the message says why and what to do."""


def valid_handle(value: object) -> bool:
    return isinstance(value, str) and HANDLE.fullmatch(value) is not None and value.lower() != ME


def valid_id(value: object) -> bool:
    """A challenge id as the board's (platform/manual.py): it names the mark's file."""
    return isinstance(value, str) and len(value) <= MAX_ID and ID.fullmatch(value) is not None


# ---------------------------------------------------------------------- the folder


def init_folder(folder: Path) -> Path:
    """Make `folder` a team folder: the marker and the claims, boxes and solves folders.
    One teammate does this once; the others' flightdecks find the marker once it has
    synced. An existing team folder is left as it is. The folder's parent must exist."""
    folder = Path(folder).expanduser()
    try:
        folder.mkdir(exist_ok=True)
    except FileNotFoundError:
        raise TeamError(f"{printable(folder)}: its parent folder does not exist (is the shared drive mounted?)") from None
    except FileExistsError:
        raise TeamError(f"{printable(folder)}: is not a folder") from None
    except OSError as exc:
        raise TeamError(f"{printable(folder)}: cannot create it ({exc.strerror})") from None
    marker = folder / MARKER
    try:
        with open(marker, "x", encoding="ascii") as out:
            out.write(MARKER_TEXT)
    except FileExistsError:
        pass
    except OSError as exc:
        raise TeamError(f"{printable(marker)}: cannot write it ({exc.strerror})") from None
    _check_marker(folder)
    for kind in KINDS:
        os.close(_open_dir(folder, kind, create=True))
    return folder


def read_state(folder: Path, *, stale_after: float = STALE_AFTER, now: float | None = None) -> TeamState:
    """The folder's claims, box holds and solves as of `now` (default: this machine's
    clock), with the files it ignored. TeamError if it is not a team folder (any more) or a
    kind folder cannot be listed: then nothing can be said about what is claimed."""
    folder = Path(folder).expanduser()
    when = time.time() if now is None else now
    _check_marker(folder)
    problems: list[str] = []
    found = {kind: _scan(folder, kind, when, stale_after, problems) for kind in KINDS}
    return TeamState(
        claims=MappingProxyType(found["claims"]),
        boxes=MappingProxyType(found["boxes"]),
        solves=MappingProxyType(found["solves"]),
        problems=tuple(problems),
    )


class TeamChannel:
    """Our side of the team folder: `me` is our handle. Thread-safe: it keeps no state
    between calls but its settings, so watch() may read in a worker thread while the
    deck's thread writes."""

    def __init__(
        self,
        folder: Path,
        me: str,
        *,
        stale_after: float = STALE_AFTER,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not valid_handle(me):
            raise TeamError(f"{_quote(me)} is not a usable team handle ({HANDLE_RULE})")
        if isinstance(stale_after, bool) or not isinstance(stale_after, (int, float)) or not (
            math.isfinite(stale_after) and stale_after > 0
        ):
            raise TeamError(f"stale_after must be a positive number of seconds, not {stale_after!r}")
        self.folder = Path(folder).expanduser()
        self.me = me
        self.stale_after = float(stale_after)
        self.clock = clock
        _check_marker(self.folder)

    def __repr__(self) -> str:
        return f"TeamChannel({str(self.folder)!r}, me={self.me!r})"

    def claim(self, challenge_id: str, *, note: str = "") -> bool:
        """Claim a challenge for us, or renew our claim. False, and nothing written, if a
        teammate's claim on it is fresh."""
        return self._take("claims", challenge_id, note)

    def release(self, challenge_id: str) -> None:
        """Drop our claim. A teammate's claim is left alone."""
        self._drop("claims", challenge_id)

    def hold_box(self, challenge_id: str, *, note: str = "") -> bool:
        """Hold the challenge's live instance, or renew our hold. False, and nothing
        written, if a teammate's hold on it is fresh."""
        return self._take("boxes", challenge_id, note)

    def free_box(self, challenge_id: str) -> None:
        """Free our hold on the live instance. A teammate's hold is left alone."""
        self._drop("boxes", challenge_id)

    def solved(self, challenge_id: str, *, note: str = "") -> None:
        """Record that we solved it (a solve already recorded, ours or a teammate's, is kept:
        the first solver keeps the record), and drop our claim on it, which it no longer needs."""
        _check_id(challenge_id)
        _check_note(note)
        if self.current("solves", challenge_id) is None:
            self._write("solves", challenge_id, Mark(self.me, self.clock(), note))
        self.release(challenge_id)

    def free_boxes(self) -> list[str]:
        """Free every live-box hold of ours: the run is ending, and its lanes with it (they
        stop without a lane-end event, so mirror() cannot see them go). Returns the ids."""
        ours = [cid for cid, mark in self.state().boxes.items() if mark.who == self.me]
        for cid in ours:
            self.free_box(cid)
        return ours

    def state(self) -> TeamState:
        return read_state(self.folder, stale_after=self.stale_after, now=self.clock())

    def current(self, kind: str, challenge_id: str) -> Mark | None:
        """The mark that counts now for one challenge: a fresh claim or box hold, or the
        solve. None if there is none, or the file is malformed (state() reports it)."""
        mark = self._mark(kind, challenge_id)
        if mark is None or kind == "solves":
            return mark
        now = self.clock()
        if mark.at > now + FUTURE_SLACK or now - mark.at > self.stale_after:
            return None
        return mark

    # ------------------------------------------------------------------ internals

    def _take(self, kind: str, challenge_id: str, note: str) -> bool:
        _check_id(challenge_id)
        _check_note(note)
        held = self.current(kind, challenge_id)
        if held is not None and held.who != self.me:
            return False
        self._write(kind, challenge_id, Mark(self.me, self.clock(), note))
        return True

    def _drop(self, kind: str, challenge_id: str) -> None:
        _check_id(challenge_id)
        mark = self._mark(kind, challenge_id)  # fresh or stale: ours is ours to remove
        if mark is None or mark.who != self.me:
            return
        name = f"{challenge_id}.json"
        dfd = _open_dir(self.folder, kind, create=False)
        if dfd is None:
            return
        try:
            os.unlink(name, dir_fd=dfd)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise TeamError(f"{printable(self.folder / kind / name)}: cannot remove it ({exc.strerror})") from None
        finally:
            os.close(dfd)

    def _mark(self, kind: str, challenge_id: str) -> Mark | None:
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {', '.join(KINDS)}, not {kind!r}")
        _check_id(challenge_id)
        _check_marker(self.folder)  # an unmounted drive must not read as "nobody holds it"
        dfd = _open_dir(self.folder, kind, create=False)
        if dfd is None:
            return None
        try:
            found = _read_mark(dfd, f"{challenge_id}.json")
        finally:
            os.close(dfd)
        return found if isinstance(found, Mark) else None

    def _write(self, kind: str, challenge_id: str, mark: Mark) -> None:
        _check_marker(self.folder)
        name = f"{challenge_id}.json"
        data = (json.dumps({"who": mark.who, "at": mark.at, "note": mark.note}, ensure_ascii=True) + "\n").encode("ascii")
        dfd = _open_dir(self.folder, kind, create=True)
        try:
            _atomic_write(dfd, name, data)
        except OSError as exc:
            raise TeamError(f"{printable(self.folder / kind / name)}: cannot write it ({exc.strerror})") from None
        finally:
            os.close(dfd)


# ---------------------------------------------------------------------- the deck


class TeamWatcher:
    """Keeps a team-mode deck and the team folder in step; watch() runs it every interval.

    apply(state), on the deck's thread:
    - solves: a teammate's -> deck.teammate_solved (its lanes stop, it leaves the queue);
      ours from an earlier run -> the same, so a restarted flightdeck does not work a
      challenge it already solved;
    - teammates' claims: a new holder -> deck.teammate_claim (it is not started while they
      hold it); a claim that was released or went stale -> deck.teammate_release, when the
      deck has one (until then it is reported and stays claimed on this deck);
    - our own marks follow the deck: a claim of ours in the folder for a challenge the
      watcher sees on the deck for the first time is taken back (Claim, as the player made it
      before a restart); after that, a claim the deck holds is renewed before it goes stale
      (and written again if it went missing) and one it does not hold is released; a box
      hold is renewed while a lane of ours is on that challenge, and freed once none is;
    - problems (ignored files, failed writes) -> report(), each once while it lasts.
    A mark is never applied twice. Marks for challenges that are not on the deck wait
    until they are (a later wave).
    """

    def __init__(self, channel: TeamChannel, deck: Deck, *, report: Callable[[str], None]) -> None:
        _need_team(deck, "the team watcher")
        self.channel = channel
        self.deck = deck
        self.report = report
        self.latest: TeamState | None = None  # the last state read, e.g. for box holders
        self._solves: set[tuple[str, str]] = set()  # (challenge id, who) applied
        self._clashes: dict[str, str] = {}  # challenge id -> teammate who claimed what we hold
        self._seen: set[str] = set()  # challenge ids on the deck at an earlier apply
        self._reported: set[str] = set()

    def poll(self) -> TeamState | None:
        """Read the folder and apply it, here and now (blocking file I/O on this thread).
        None if the folder could not be read; that is reported and nothing changes."""
        try:
            state = self.channel.state()
        except TeamError as exc:
            self._round([f"team folder: {exc}"])
            return None
        self.apply(state)
        return state

    def apply(self, state: TeamState) -> None:
        messages = [f"team folder: {problem}" for problem in state.problems]
        self.latest = state
        self._apply_solves(state, messages)
        self._apply_claims(state, messages)
        self._follow_deck(state, messages)
        self._seen.update(self.deck.challenges)
        self._round(messages)

    async def run(self, *, interval: float = POLL_SECONDS, stop: asyncio.Event) -> None:
        """Poll every `interval` seconds until `stop` is set. The folder is read in a worker
        thread (a network drive can be slow); the deck is changed on this loop's thread."""
        if isinstance(interval, bool) or not isinstance(interval, (int, float)) or not (
            math.isfinite(interval) and interval > 0
        ):
            raise TeamError(f"the poll interval must be a positive number of seconds, not {interval!r}")
        while not stop.is_set():
            try:
                state = await asyncio.to_thread(self.channel.state)
            except TeamError as exc:
                self._round([f"team folder: {exc}"])
            else:
                if stop.is_set():
                    return
                self.apply(state)
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
            except TimeoutError:
                pass

    # ------------------------------------------------------------------ steps

    def _apply_solves(self, state: TeamState, messages: list[str]) -> None:
        deck, me = self.deck, self.channel.me
        for cid, mark in state.solves.items():
            ch = deck.challenges.get(cid)
            key = (cid, mark.who)
            if ch is None or key in self._solves:
                continue
            if mark.who == me:
                if ch.closed:  # this run's solve: the deck has the record
                    self._solves.add(key)
                    continue
            elif ch.status is ChallengeStatus.TEAMMATE and ch.solved_by == mark.who:
                self._solves.add(key)  # applied before this watcher started
                continue
            if self._do(messages, f"apply {mark.who}'s solve of {cid}", deck.teammate_solved, cid, mark.who) is not _FAILED:
                self._solves.add(key)

    def _apply_claims(self, state: TeamState, messages: list[str]) -> None:
        deck, me = self.deck, self.channel.me
        held = {cid: mark.who for cid, mark in state.claims.items() if mark.who != me}
        for cid, who in held.items():
            ch = deck.challenges.get(cid)
            if ch is None or ch.closed or ch.claimed_by == who:
                continue
            if ch.claimed_by == ME:  # we hold it here: the deck warns of the clash, once
                if self._clashes.get(cid) == who:
                    continue
                self._clashes[cid] = who
            self._do(messages, f"apply {who}'s claim on {cid}", deck.teammate_claim, cid, who)
        self._clashes = {
            cid: who for cid, who in self._clashes.items() if held.get(cid) == who and deck.challenges[cid].claimed_by == ME
        }
        release = getattr(deck, "teammate_release", None)
        for ch in list(deck.challenges.values()):
            who = ch.claimed_by
            if who is None or who == ME or held.get(ch.id) == who:
                continue
            # the deck shows a teammate's claim that the folder no longer has
            if release is not None:
                self._do(messages, f"drop {who}'s released claim on {ch.id}", release, ch.id, who)
            elif not ch.closed:
                messages.append(
                    f"team: {who} no longer claims {ch.id}, but this deck cannot drop a teammate's claim "
                    f"(it has no teammate_release), so it stays claimed by {who} here"
                )

    def _follow_deck(self, state: TeamState, messages: list[str]) -> None:
        deck, channel = self.deck, self.channel
        me, now = channel.me, channel.clock()
        renew_after = channel.stale_after / 2
        ours = {cid: mark for cid, mark in state.claims.items() if mark.who == me}
        for cid, mark in ours.items():
            ch = deck.challenges.get(cid)
            if ch is None:
                continue  # not on this deck (yet): it waits, like a teammate's mark
            if cid not in self._seen and ch.claimed_by is None and not ch.closed:
                outcome = self._do(messages, f"take back our claim on {cid}", deck.apply, Claim(cid))
                if outcome is not _FAILED and outcome.ok:  # type: ignore[union-attr]
                    continue
            if ch.closed or ch.claimed_by != ME:
                self._do(messages, f"release our old claim on {cid}", channel.release, cid)
            elif now - mark.at > renew_after:
                self._do(messages, f"renew our claim on {cid}", channel.claim, cid, note=mark.note)
        for ch in deck.challenges.values():
            if ch.claimed_by != ME or ch.closed or ch.id in state.claims:
                continue  # a teammate's claim on it is a clash the deck has warned about
            won = self._do(messages, f"write our claim on {ch.id}", channel.claim, ch.id)
            if won is False:
                messages.append(f"team: {_holder(channel, 'claims', ch.id)} claimed {ch.id} in the team folder; ours is only on this deck")
        for cid, mark in state.boxes.items():
            if mark.who != me:
                continue
            if not deck.lanes_on(cid):
                self._do(messages, f"free our hold on the live box of {cid}", channel.free_box, cid)
            elif now - mark.at > renew_after:
                self._do(messages, f"renew our hold on the live box of {cid}", channel.hold_box, cid, note=mark.note)

    # ------------------------------------------------------------------ helpers

    def _do(self, messages: list[str], what: str, fn: Callable[..., object], *args: object, **kwargs: object) -> object:
        """Call `fn`; a failure becomes a message (team sync goes on) and _FAILED."""
        try:
            return fn(*args, **kwargs)
        except TeamError as exc:
            messages.append(f"team: could not {what}: {exc}")
        except Exception as exc:  # a bug in a deck call: say so, and keep the rest in step
            messages.append(f"team: could not {what}: {type(exc).__name__}: {exc}")
        return _FAILED

    def _round(self, messages: list[str]) -> None:
        """Report what is new since the last round; a problem that goes away and comes back
        is reported again."""
        for text in dict.fromkeys(messages):
            if text not in self._reported:
                self.report(text)
        self._reported = set(messages)


async def watch(
    channel: TeamChannel,
    deck: Deck,
    *,
    interval: float = POLL_SECONDS,
    stop: asyncio.Event,
    report: Callable[[str], None],
) -> None:
    """Poll the team folder and keep the deck in step with it (TeamWatcher) until `stop`
    is set. Run it on the deck's event loop. `report` gets each problem once, on the
    deck's thread (the console's warn(), say)."""
    await TeamWatcher(channel, deck, report=report).run(interval=interval, stop=stop)


def mirror(channel: TeamChannel, deck: Deck, *, report: Callable[[str], None]) -> Callable[[], None]:
    """Write our claims, solves and live-box holds to the folder as the deck makes them:
    - a claim or release the deck accepted (OUTCOME, ok) -> claim() or release();
    - a correct flag (SUBMIT, correct) -> solved(), noted with the lane, never the flag;
    - a live-box approval the deck accepted -> hold_box(); freed when that lane ends (and
      no other lane of ours on the challenge was allowed on the box).
    It writes on the deck's thread, inside the event, and never raises into the deck: a
    failed write or a clash with a teammate goes to `report`. Returns the unsubscribe
    function."""
    _need_team(deck, "mirror")
    approving: dict[str, PendingKind | None] = {}  # lane id -> what an approval in progress approves
    on_box: dict[str, str] = {}  # lane id -> challenge id: our lanes allowed on a live box

    def attempt(what: str, fn: Callable[..., object], *args: object, **kwargs: object) -> object:
        try:
            return fn(*args, **kwargs)
        except TeamError as exc:
            report(f"team: could not {what}: {exc}")
        except Exception as exc:  # a listener must never break the deck's event
            report(f"team: could not {what}: {type(exc).__name__}: {exc}")
        return _FAILED

    def claim(cid: str) -> None:
        if attempt(f"claim {cid} in the team folder", channel.claim, cid) is False:
            who = _holder(channel, "claims", cid)
            report(f"team: {who} holds the claim on {cid} in the team folder, so yours is only on this deck; release it, or ask {who}")

    def hold(lane_id: str) -> None:
        lane = deck.lanes.get(lane_id)
        if lane is None:
            return
        cid = lane.challenge_id
        held = attempt(f"hold the live box of {cid}", channel.hold_box, cid, note=lane_id)
        if held is True:
            on_box[lane_id] = cid
        elif held is False:
            who = _holder(channel, "boxes", cid)
            report(f"team: {who} holds the live box of {cid}; {lane_id} was allowed on it all the same: ask {who}, or tell {lane_id} to stay off it")

    def listener(event: Event) -> None:
        data = event.data
        if event.kind is EventKind.INTERVENTION:
            if data.get("intervention") == "approve" and event.lane:  # before the deck acts: what does it approve?
                lane = deck.lanes.get(event.lane)
                approving[event.lane] = lane.pending.kind if lane is not None and lane.pending is not None else None
        elif event.kind is EventKind.OUTCOME:
            name, ok = data.get("intervention"), data.get("ok") is True
            if name == "approve" and event.lane:
                if approving.pop(event.lane, None) is PendingKind.LIVE_BOX and ok:
                    hold(event.lane)
            elif ok and name == "claim" and event.challenge:
                claim(event.challenge)
            elif ok and name == "release" and event.challenge:
                attempt(f"release {event.challenge} in the team folder", channel.release, event.challenge)
        elif event.kind is EventKind.SUBMIT:
            if data.get("correct") is True and event.challenge:
                attempt(f"record the solve of {event.challenge}", channel.solved, event.challenge, note=event.lane or "")
        elif event.kind is EventKind.LANE_END and event.lane in on_box:
            cid = on_box.pop(event.lane)
            if cid not in on_box.values():
                attempt(f"free the live box of {cid}", channel.free_box, cid)

    return deck.subscribe(listener)


# ---------------------------------------------------------------------- files


_FAILED = object()


class _Duplicate(ValueError):
    pass


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """json object hook: a key given twice is an error (json would keep the last one)."""
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise _Duplicate(key)
        out[key] = value
    return out


def _check_marker(folder: Path) -> None:
    marker = folder / MARKER
    try:
        info = os.lstat(marker)
    except (FileNotFoundError, NotADirectoryError):
        if not folder.is_dir():
            what = "is not a folder" if folder.exists() else "no such folder"
            raise TeamError(f"{printable(folder)}: {what} (is the shared drive mounted?)") from None
        raise TeamError(
            f"{printable(folder)}: is not a team folder (it has no {MARKER}): check that the shared drive is "
            f"mounted and synced, or make it one with `flightdeck team init {printable(shlex.quote(str(folder)))}`"
        ) from None
    except OSError as exc:
        raise TeamError(f"{printable(folder)}: cannot read it ({exc.strerror})") from None
    if not stat.S_ISREG(info.st_mode):
        raise TeamError(f"{printable(marker)}: is not a regular file")


def _check_id(challenge_id: object) -> None:
    if not valid_id(challenge_id):
        raise TeamError(f"{_quote(challenge_id)} is not a challenge id ({ID_RULE})")


def _check_note(note: object) -> None:
    if not _is_note(note):
        raise TeamError(f"a note must be text of at most {MAX_NOTE} characters")


def _is_note(value: object) -> bool:
    """Text of at most MAX_NOTE characters. A lone surrogate is not text: JSON can carry one
    as a \\udXXX escape, and no terminal can be sent it as it is."""
    return isinstance(value, str) and len(value) <= MAX_NOTE and _SURROGATE.search(value) is None


def _open_dir(folder: Path, kind: str, *, create: bool) -> int | None:
    """An fd for folder/kind, a real folder (never a symlink); None if it does not exist
    and `create` is false. Files are then opened relative to it, so nothing a teammate
    swaps in can redirect a read or a write."""
    path = folder / kind
    try:
        return os.open(path, _DIR)
    except FileNotFoundError:
        if not create:
            return None
    except OSError as exc:
        raise _dir_error(path, exc) from None
    try:
        os.mkdir(path, 0o755)
    except FileExistsError:
        pass
    except OSError as exc:
        raise TeamError(f"{printable(path)}: cannot create it ({exc.strerror})") from None
    try:
        return os.open(path, _DIR)
    except OSError as exc:
        raise _dir_error(path, exc) from None


def _dir_error(path: Path, exc: OSError) -> TeamError:
    if exc.errno in (errno.ENOTDIR, errno.ELOOP):
        what = "a symlink" if path.is_symlink() else "not a folder"
        return TeamError(f"{printable(path)}: is {what}; the team folder's claims, boxes and solves must be real folders")
    return TeamError(f"{printable(path)}: cannot open it ({exc.strerror})")


def _scan(folder: Path, kind: str, now: float, stale_after: float, problems: list[str]) -> dict[str, Mark]:
    dfd = _open_dir(folder, kind, create=False)
    if dfd is None:
        return {}
    found: dict[str, Mark] = {}
    try:
        names: list[str] = []
        try:
            with os.scandir(dfd) as entries:
                for entry in entries:
                    if len(names) >= MAX_ENTRIES:
                        problems.append(f"{kind}/: has more than {MAX_ENTRIES} entries; the rest were not read")
                        break
                    names.append(entry.name)
        except OSError as exc:
            raise TeamError(f"{printable(folder / kind)}: cannot list it ({exc.strerror})") from None
        for name in sorted(names):
            if name.startswith("."):  # temp files, and what the OS and sync tools keep
                continue
            where = f"{kind}/{printable(name)}"
            cid = name.removesuffix(".json")
            if cid == name or not valid_id(cid):
                problems.append(f"{where}: is not named <challenge id>.json; ignored")
                continue
            mark = _read_mark(dfd, name)
            if mark is None:  # removed since it was listed
                continue
            if isinstance(mark, str):
                problems.append(f"{where}: {mark}; ignored")
                continue
            if mark.at > now + FUTURE_SLACK:
                ahead = f"{where}: is dated more than {FUTURE_SLACK / 60:.0f} minutes ahead of this machine's clock"
                if kind != "solves":
                    problems.append(f"{ahead}; ignored (check the clocks)")
                    continue
                problems.append(f"{ahead} (check the clocks)")
            elif kind != "solves" and now - mark.at > stale_after:
                continue  # stale: counts as released
            found[cid] = mark
    finally:
        os.close(dfd)
    return found


def _read_mark(dfd: int, name: str) -> Mark | str | None:
    """The mark in `name` (relative to the folder `dfd`), a problem, or None if it is gone."""
    try:
        fd = os.open(name, _READ, dir_fd=dfd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return "is a symlink (never followed)"
        return f"cannot be read ({exc.strerror})"
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return "is not a regular file"
        if info.st_size > MAX_MARK_BYTES:
            return f"is over {MAX_MARK_BYTES} bytes, too big for a mark"
        chunks: list[bytes] = []
        size = 0
        while size <= MAX_MARK_BYTES:
            chunk = os.read(fd, MAX_MARK_BYTES + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > MAX_MARK_BYTES:
            return f"is over {MAX_MARK_BYTES} bytes, too big for a mark"
    except OSError as exc:
        return f"cannot be read ({exc.strerror})"
    finally:
        os.close(fd)
    return _parse(b"".join(chunks))


def _parse(data: bytes) -> Mark | str:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return "is not UTF-8 text"
    try:
        value = json.loads(text, object_pairs_hook=_unique)
    except _Duplicate:
        return "has a key twice"
    except json.JSONDecodeError:
        return "is not valid JSON"
    except (ValueError, RecursionError):  # a number too long to convert, or nesting too deep
        return "is not JSON flightdeck can read"
    if not isinstance(value, dict):
        return "is not a JSON object"
    if any(key not in MARK_KEYS for key in value):
        return "has keys other than who, at and note"
    if "who" not in value:
        return 'has no "who"'
    if not valid_handle(value["who"]):
        return f'"who" is not a team handle ({HANDLE_RULE})'
    if "at" not in value:
        return 'has no "at"'
    at = value["at"]
    try:
        when = float(at) if isinstance(at, (int, float)) and not isinstance(at, bool) else math.nan
    except OverflowError:
        when = math.nan
    if not (math.isfinite(when) and when >= 0):
        return '"at" is not a time (seconds since 1970)'
    note = value.get("note", "")
    if not _is_note(note):
        return f'"note" is not text of at most {MAX_NOTE} characters'
    return Mark(value["who"], when, note)


def _atomic_write(dfd: int, name: str, data: bytes) -> None:
    """Write `data` to `name` in the folder `dfd` all at once: a hidden temp file there,
    flushed to disk, then renamed over `name`."""
    for _ in range(8):
        temp = f".{name}.{secrets.token_hex(6)}.tmp"
        try:
            fd = os.open(temp, _CREATE, 0o644, dir_fd=dfd)
            break
        except FileExistsError:
            continue
    else:
        raise FileExistsError(errno.EEXIST, "could not pick a temp file name")
    try:
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view) :]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temp, dir_fd=dfd)
        raise


def _holder(channel: TeamChannel, kind: str, challenge_id: str) -> str:
    """Who holds it now, for a message ("a teammate" if the folder cannot say)."""
    try:
        mark = channel.current(kind, challenge_id)
    except TeamError:
        mark = None
    return mark.who if mark is not None else "a teammate"


def _need_team(deck: Deck, what: str) -> None:
    if not deck.config.team:
        raise TeamError(f"{what} needs a deck in team mode (DeckConfig.team is False)")


def printable(value: object) -> str:
    """`value` (a path, a file name, a note) as one line that is safe to print: untrusted()
    makes control and invisible characters visible, and a lone surrogate shows as an escape.
    Linux allows any bytes in a file name, and Python lists the ones that are not UTF-8 as
    surrogate escapes (PEP 383). Printed as they are, they crash a strict UTF-8 terminal or
    reach a lenient one as raw bytes (0x9b starts a control sequence), and untrusted() leaves
    them alone, so an escaped byte shows as \\xNN and any other lone surrogate as \\uNNNN."""
    text = str(value)
    if _SURROGATE.search(text) is not None:
        try:
            text = text.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")
        except UnicodeEncodeError:  # a lone surrogate that is not an escaped byte
            text = text.encode("utf-8", "backslashreplace").decode("utf-8")
    return untrusted(text, one_line=True)


def _quote(value: object) -> str:
    safe = printable(value if isinstance(value, str) else repr(value))
    return json.dumps(safe if len(safe) <= 60 else safe[:57] + "...", ensure_ascii=False)
