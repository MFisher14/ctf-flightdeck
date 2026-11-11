"""The team channel (team.py): claims, live-box holds and solves through a shared folder.

Two channels with two handles share one tmp folder, as two teammates' flightdecks would.
The deck is the real Deck in team mode; a recording driver stands in for lane work and a
small verifier for the platform. Files are real files and threads are real threads:
nothing in team.py is mocked.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import threading
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ctf_flightdeck import team_cli
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import (
    ME,
    AlertKind,
    Challenge,
    ChallengeStatus,
    DeckConfig,
    EventKind,
    LaneState,
    Pending,
    PendingKind,
)
from ctf_flightdeck.team import (
    FUTURE_SLACK,
    MARKER,
    MAX_ENTRIES,
    MAX_MARK_BYTES,
    MAX_NOTE,
    STALE_AFTER,
    Mark,
    TeamChannel,
    TeamError,
    TeamWatcher,
    init_folder,
    mirror,
    read_state,
    watch,
)

T0 = 1_800_000_000.0  # a wall-clock time for the hand-moved clocks
FLAG_FORMAT = r"t\{\w+\}"


class Wall:
    """A wall clock the test moves by hand."""

    def __init__(self, t: float = T0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


class DeckClock:
    def now(self) -> float:
        return 0.0


class Driver:
    """Records what the deck asks of it; does no lane work."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def attach(self, deck):
        self.deck = deck

    def start(self, lane, challenge):
        self.calls.append(("start", lane.id, challenge.id))

    def stop(self, lane):
        self.calls.append(("stop", lane.id))

    def started(self):
        return [call[2] for call in self.calls if call[0] == "start"]

    def pause(self, lane): ...
    def resume(self, lane): ...
    def hint(self, lane, text): ...
    def redirect(self, lane, text): ...
    def escalate(self, lane, model, summary): ...
    def approved(self, lane, pending): ...
    def rejected(self, lane, flag): ...
    def declined(self, lane, pending): ...


def verify(challenge_id: str, flag: str) -> bool:
    return flag == f"t{{{challenge_id}}}"


class ReleasingDeck(Deck):
    """The deck plus the teammate_release() the team channel needs (proposed in the M2
    report): a teammate's claim that was released or went stale is dropped."""

    def teammate_release(self, challenge_id: str, who: str) -> None:
        self.__dict__.setdefault("released", []).append((challenge_id, who))
        ch = self.challenges[challenge_id]
        if ch.claimed_by == who:
            ch.claimed_by = None


def make_deck(ids=("c0", "c1", "c2"), *, max_lanes=1, team=True, deck_class=Deck):
    """A team deck with challenges `ids` released and queued in that order."""
    driver = Driver()
    config = DeckConfig(event="test", team=team, max_lanes=max_lanes, flag_format=FLAG_FORMAT, models=("small",))
    deck = deck_class(config, driver, DeckClock(), verify)
    release(deck, ids)
    return deck, driver


def release(deck, ids):
    deck.release([Challenge(cid, f"Chall {cid}", "misc", 100) for cid in ids], [QueueEntry(cid, "small") for cid in ids])


def lane_on(deck, cid):
    (lane,) = deck.lanes_on(cid)
    return lane


def events(deck, kind, since=0):
    return [e for e in deck.events[since:] if e.kind is kind]


def put(folder: Path, kind: str, name: str, content) -> Path:
    """Write a file as a teammate (or anyone with access to the folder) might."""
    path = folder / kind / name
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(content if isinstance(content, bytes) else json.dumps(content).encode())
    return path


def tree(root: Path) -> dict[str, bytes | None]:
    """Every path under `root` with its bytes (None for a folder)."""
    return {
        str(p.relative_to(root)): (None if p.is_dir() else p.read_bytes())
        for p in sorted(root.rglob("*"))
        if not p.is_symlink()
    }


@pytest.fixture
def folder(tmp_path) -> Path:
    return init_folder(tmp_path / "team")


@pytest.fixture
def wall() -> Wall:
    return Wall()


def pair(folder, wall=None):
    """Our channel (alpha) and a teammate's (bravo) on one folder, on one clock."""
    kwargs = {"clock": wall} if wall is not None else {}
    return TeamChannel(folder, "alpha", **kwargs), TeamChannel(folder, "bravo", **kwargs)


# ---------------------------------------------------------------------- the folder


def test_init_folder_writes_the_marker_and_the_three_folders_and_is_idempotent(tmp_path):
    team = tmp_path / "team"
    assert init_folder(team) == team
    assert sorted(p.name for p in team.iterdir()) == ["boxes", "claims", MARKER, "solves"]
    marker = (team / MARKER).read_text()
    assert "flightdeck" in marker and "nothing secret" in marker
    TeamChannel(team, "alpha").claim("c0")
    before = tree(team)
    init_folder(team)
    assert tree(team) == before


def test_init_folder_refuses_a_file_and_a_missing_parent(tmp_path):
    (tmp_path / "file").write_text("x")
    with pytest.raises(TeamError, match="is not a folder"):
        init_folder(tmp_path / "file")
    with pytest.raises(TeamError, match="parent folder does not exist"):
        init_folder(tmp_path / "nowhere" / "team")
    assert not (tmp_path / "nowhere").exists()


def test_a_folder_that_is_not_a_team_folder_is_refused_and_never_created(tmp_path):
    with pytest.raises(TeamError, match="no such folder"):
        TeamChannel(tmp_path / "missing", "alpha")
    assert not (tmp_path / "missing").exists()
    (tmp_path / "plain").mkdir()
    with pytest.raises(TeamError, match=r"is not a team folder.*flightdeck team init"):
        TeamChannel(tmp_path / "plain", "alpha")
    assert list((tmp_path / "plain").iterdir()) == []
    (tmp_path / "file").write_text("x")
    with pytest.raises(TeamError, match="is not a folder"):
        TeamChannel(tmp_path / "file", "alpha")


def test_an_unmounted_drive_fails_loudly_instead_of_writing_where_nobody_reads(folder, tmp_path):
    alpha = TeamChannel(folder, "alpha")
    alpha.claim("c0")
    folder.rename(tmp_path / "the-real-share")
    folder.mkdir()  # the empty mount point a network drive leaves behind
    for call in (
        lambda: alpha.claim("c1"),
        lambda: alpha.release("c0"),
        lambda: alpha.hold_box("c1"),
        lambda: alpha.free_box("c0"),
        lambda: alpha.solved("c1"),
        lambda: alpha.current("claims", "c0"),
        alpha.state,
    ):
        with pytest.raises(TeamError, match="is not a team folder"):
            call()
    assert list(folder.iterdir()) == []
    assert (tmp_path / "the-real-share" / "claims" / "c0.json").is_file()


@pytest.mark.parametrize("handle", ["", "a b", "x" * 41, "../x", "a/b", "me", "Me", "ME", "bravo\n", "\x1b[2J", 7, None])
def test_our_handle_must_be_a_usable_handle(folder, handle):
    with pytest.raises(TeamError, match="team handle"):
        TeamChannel(folder, handle)


def test_handles_may_use_letters_digits_and_dot_dash_underscore_up_to_40(folder):
    for handle in ("Bravo", "b.r-a_v0", "x" * 40, "mE2", "meg"):
        assert TeamChannel(folder, handle).me == handle


@pytest.mark.parametrize("stale_after", [0, -1, float("nan"), float("inf"), True, "6"])
def test_stale_after_must_be_a_positive_number_of_seconds(folder, stale_after):
    with pytest.raises(TeamError, match="stale_after"):
        TeamChannel(folder, "alpha", stale_after=stale_after)


@pytest.mark.parametrize("bad_id", ["../x", "../../etc/passwd", "a/b", "/etc/passwd", "UPPER", "", ".hidden", "-x", "x" * 65, "c0\n", 3])
def test_a_bad_challenge_id_is_refused_before_anything_is_written(folder, tmp_path, bad_id):
    alpha = TeamChannel(folder, "alpha")
    before = tree(tmp_path)
    for call in (alpha.claim, alpha.release, alpha.hold_box, alpha.free_box, alpha.solved):
        with pytest.raises(TeamError, match="is not a challenge id"):
            call(bad_id)
    with pytest.raises(TeamError, match="is not a challenge id"):
        alpha.current("claims", bad_id)
    assert tree(tmp_path) == before


def test_a_note_is_short_text(folder):
    alpha = TeamChannel(folder, "alpha")
    assert alpha.claim("c0", note="n" * MAX_NOTE)
    for note in ("n" * (MAX_NOTE + 1), 5, None):
        with pytest.raises(TeamError, match="note"):
            alpha.claim("c1", note=note)
    assert alpha.current("claims", "c1") is None


# ---------------------------------------------------------------------- claims, boxes, solves


def test_a_claim_is_one_json_file_named_by_the_challenge(folder, wall):
    alpha, _ = pair(folder, wall)
    assert alpha.claim("c0", note="on it") is True
    path = folder / "claims" / "c0.json"
    raw = path.read_bytes()
    assert raw.isascii() and raw.endswith(b"\n")
    assert json.loads(raw) == {"who": "alpha", "at": T0, "note": "on it"}
    assert sorted(p.name for p in path.parent.iterdir()) == ["c0.json"]  # no temp file left behind


def test_a_teammates_fresh_claim_wins_and_ours_is_refused_without_writing(folder, wall):
    alpha, bravo = pair(folder, wall)
    assert bravo.claim("c0", note="theirs")
    before = tree(folder)
    assert alpha.claim("c0", note="ours") is False
    assert tree(folder) == before
    assert alpha.state().claims == {"c0": Mark("bravo", T0, "theirs")}
    assert alpha.current("claims", "c0") == Mark("bravo", T0, "theirs")


def test_claiming_again_renews_our_own_claim(folder, wall):
    alpha, bravo = pair(folder, wall)
    alpha.claim("c0")
    wall.t += 3600
    assert alpha.claim("c0", note="still on it") is True
    assert bravo.state().claims["c0"] == Mark("alpha", T0 + 3600, "still on it")


def test_release_removes_only_our_own_claim(folder, wall):
    alpha, bravo = pair(folder, wall)
    alpha.claim("c0")
    bravo.claim("c1")
    alpha.release("c1")  # bravo's: left alone
    bravo.release("c0")  # ours: left alone
    alpha.release("c9")  # nothing there
    assert set(alpha.state().claims) == {"c0", "c1"}
    alpha.release("c0")
    assert set(bravo.state().claims) == {"c1"}
    assert bravo.claim("c0") is True


def test_box_holds_follow_the_same_rules_as_claims(folder, wall):
    alpha, bravo = pair(folder, wall)
    assert alpha.hold_box("c0", note="L01") is True
    assert bravo.hold_box("c0") is False
    bravo.free_box("c0")
    assert bravo.state().boxes == {"c0": Mark("alpha", T0, "L01")}
    assert alpha.state().claims == {}  # a box hold is not a claim
    alpha.free_box("c0")
    assert bravo.hold_box("c0") is True
    assert (folder / "boxes" / "c0.json").is_file()


def test_the_first_solve_keeps_the_record_and_solving_drops_our_claim(folder, wall):
    alpha, bravo = pair(folder, wall)
    alpha.claim("c0")
    bravo.claim("c1")
    alpha.solved("c0", note="L03")
    wall.t += 60
    bravo.solved("c0", note="late")
    alpha.solved("c1")  # bravo's claim on c1 is not ours to drop
    state = bravo.state()
    assert state.solves == {"c0": Mark("alpha", T0, "L03"), "c1": Mark("alpha", T0 + 60, "")}
    assert state.claims == {"c1": Mark("bravo", T0, "")}


def test_a_claim_older_than_stale_after_counts_as_released(folder, wall):
    alpha, bravo = pair(folder, wall)
    put(folder, "claims", "c0.json", {"who": "bravo", "at": T0 - STALE_AFTER - 1, "note": ""})
    put(folder, "claims", "c1.json", {"who": "bravo", "at": T0 - STALE_AFTER + 60, "note": ""})
    state = alpha.state()
    assert set(state.claims) == {"c1"} and state.problems == ()
    assert alpha.current("claims", "c0") is None
    assert alpha.claim("c0") is True
    assert alpha.claim("c1") is False


def test_our_claim_and_box_hold_go_stale_on_the_clock_but_a_solve_never_does(folder, wall):
    alpha, bravo = pair(folder, wall)
    alpha.claim("c0")
    alpha.hold_box("c0")
    alpha.solved("c1")
    wall.t += STALE_AFTER - 1
    assert bravo.claim("c0") is False and bravo.hold_box("c0") is False
    wall.t += 2
    assert bravo.state().claims == {} and bravo.state().boxes == {}
    assert bravo.claim("c0") is True and bravo.hold_box("c0") is True
    wall.t += 10 * 24 * 3600
    assert bravo.state().solves == {"c1": Mark("alpha", T0, "")}


def test_a_shorter_stale_after_applies_to_the_reader(folder, wall):
    alpha = TeamChannel(folder, "alpha", clock=wall)
    hasty = TeamChannel(folder, "bravo", clock=wall, stale_after=60)
    alpha.claim("c0")
    wall.t += 61
    assert hasty.state().claims == {} and hasty.claim("c0") is True


def test_a_mark_dated_far_ahead_is_reported_and_for_a_claim_ignored(folder, wall):
    alpha, _ = pair(folder, wall)
    far = T0 + FUTURE_SLACK + 1
    put(folder, "claims", "c0.json", {"who": "bravo", "at": far, "note": ""})
    put(folder, "boxes", "c0.json", {"who": "bravo", "at": far, "note": ""})
    put(folder, "solves", "c0.json", {"who": "bravo", "at": far, "note": ""})
    put(folder, "claims", "c1.json", {"who": "bravo", "at": T0 + 60, "note": ""})  # a little skew is fine
    state = alpha.state()
    assert set(state.claims) == {"c1"} and state.boxes == {}
    assert state.solves == {"c0": Mark("bravo", far, "")}  # a solve is a fact whatever its date
    assert len(state.problems) == 3
    assert all("ahead of this machine's clock" in p for p in state.problems)
    assert alpha.claim("c0") is True  # a claim that would never go stale does not block us


def test_a_concurrent_reader_never_sees_a_partial_file(folder):
    alpha, bravo = pair(folder)
    alpha.claim("c0")
    path = folder / "claims" / "c0.json"
    done = threading.Event()
    errors: list[BaseException] = []

    def write() -> None:
        try:
            for i in range(400):
                alpha.claim("c0", note="n" * (i * 7 % (MAX_NOTE + 1)))
        except BaseException as exc:  # reported by the assert below
            errors.append(exc)
        finally:
            done.set()

    writer = threading.Thread(target=write)
    writer.start()
    reads, partial = 0, []
    while not done.is_set():
        raw = path.read_bytes()  # a missing file would raise here and fail the test
        try:
            json.loads(raw)
        except ValueError:
            partial.append(raw)
        state = bravo.state()
        if state.problems or "c0" not in state.claims:
            partial.append(state)
        reads += 1
    writer.join()
    assert errors == [] and partial == []
    assert reads >= 20, reads
    assert sorted(p.name for p in path.parent.iterdir()) == ["c0.json"]


@pytest.mark.parametrize(
    ("umask", "folder_mode", "file_mode"),
    [(0o002, 0o775, 0o664), (0o022, 0o755, 0o644), (0o077, 0o700, 0o600)],
    ids=["umask-002-shared-by-group", "umask-022", "umask-077"],
)
def test_folders_and_marks_take_their_modes_from_the_umask(tmp_path, umask, folder_mode, file_mode):
    # a folder shared by group (umask 002) must let every teammate's account write in it
    old = os.umask(umask)
    try:
        team = init_folder(tmp_path / "team")
        shutil.rmtree(team / "solves")  # made again by the first solve
        alpha = TeamChannel(team, "alpha")
        alpha.claim("c0")
        alpha.hold_box("c0")
        alpha.solved("c1")
    finally:
        os.umask(old)

    def mode(path: Path) -> int:
        return os.lstat(path).st_mode & 0o777

    assert [mode(team / kind) for kind in ("", "claims", "boxes", "solves")] == [folder_mode] * 4
    assert [mode(team / name) for name in (MARKER, "claims/c0.json", "boxes/c0.json", "solves/c1.json")] == [file_mode] * 4


def test_each_write_replaces_the_file_whole(folder):
    alpha, _ = pair(folder)
    alpha.claim("c0")
    path = folder / "claims" / "c0.json"
    first = os.stat(path).st_ino
    alpha.claim("c0", note="again")
    assert os.stat(path).st_ino != first  # a new file renamed into place, not the old one rewritten
    assert json.loads(path.read_bytes())["note"] == "again"


# ---------------------------------------------------------------------- hostile and malformed files

GOOD = {"who": "bravo", "at": T0, "note": ""}

BAD_MARKS = {
    "who-path": {"who": "../../etc/passwd", "at": T0},
    "who-space": {"who": "a b", "at": T0},
    "who-long": {"who": "x" * 41, "at": T0},
    "who-number": {"who": 7, "at": T0},
    "who-me": {"who": "me", "at": T0},
    "who-Me": {"who": "Me", "at": T0},
    "who-escape": {"who": "\x1b[2Jbravo", "at": T0},
    "no-who": {"at": T0},
    "no-at": {"who": "bravo"},
    "at-text": {"who": "bravo", "at": "now"},
    "at-bool": {"who": "bravo", "at": True},
    "at-negative": {"who": "bravo", "at": -1},
    "at-null": {"who": "bravo", "at": None},
    "extra-key": {"who": "bravo", "at": T0, "flag": "t{x}"},
    "note-number": {"who": "bravo", "at": T0, "note": 5},
    "note-long": {"who": "bravo", "at": T0, "note": "n" * (MAX_NOTE + 1)},
}
BAD_BYTES = {
    "not-json": b"{who: bravo",
    "not-object": b'["bravo", 1800000000]',
    "not-utf8": b'{"who": "\xff\xfe", "at": 1800000000}',
    "a-key-twice": b'{"who": "bravo", "who": "charlie", "at": 1800000000}',
    "at-nan": b'{"who": "bravo", "at": NaN}',
    "at-infinite": b'{"who": "bravo", "at": 1e400}',
    "at-huge-int": b'{"who": "bravo", "at": ' + b"9" * 400 + b"}",
    "nested-deep": b"[" * 2000 + b"]" * 2000,
    "empty": b"",
    "note-lone-surrogate": b'{"who": "bravo", "at": 1800000000, "note": "\\udc9b2J"}',  # valid JSON, not text
}


@pytest.mark.parametrize("content", [*BAD_MARKS.values(), *BAD_BYTES.values()], ids=[*BAD_MARKS, *BAD_BYTES])
def test_a_malformed_mark_is_ignored_and_reported_by_name(folder, wall, content):
    alpha, _ = pair(folder, wall)
    put(folder, "claims", "c0.json", GOOD)
    put(folder, "claims", "c1.json", content)
    state = alpha.state()
    assert state.claims == {"c0": Mark("bravo", T0, "")}
    (problem,) = state.problems
    assert problem.startswith("claims/c1.json: ") and problem.endswith("; ignored")
    assert "\x1b" not in problem
    assert alpha.claim("c1") is True  # an ignored file blocks nothing


@pytest.mark.parametrize(
    "name",
    [
        "UPPER.json",
        "a b.json",
        "c0.sync-conflict-20261110-120000-ABCDEFG.json",
        "c0 (conflicted copy).json",
        "notes.txt",
        "c0.json.bak",
        "c0.JSON",
        "-c0.json",
        "x" * 65 + ".json",
        "\x1b[31mred.json",
    ],
)
def test_a_file_not_named_by_a_challenge_id_is_reported_without_reading_it(folder, wall, name):
    alpha, _ = pair(folder, wall)
    put(folder, "solves", name, GOOD)
    state = alpha.state()
    assert state.solves == {}
    (problem,) = state.problems
    assert problem.startswith("solves/") and "is not named <challenge id>.json" in problem
    assert "\x1b" not in problem
    if "\x1b" in name:
        assert "^[" in problem  # made visible, never sent to the terminal as an escape


def test_a_path_that_is_not_utf8_shows_its_bytes_as_escapes(tmp_path):
    folder = tmp_path / "\udc9b2J"  # how Python spells a name holding the byte 0x9b, which is not UTF-8
    for call in (lambda: TeamChannel(folder, "alpha"), lambda: read_state(folder), lambda: TeamChannel(tmp_path, "\udc9b")):
        with pytest.raises(TeamError) as caught:
            call()
        message = str(caught.value)
        message.encode("utf-8")  # strict: no lone surrogate is left to crash a terminal, or reach it as a raw byte
        assert "\\x9b" in message
    odd = tmp_path / "\x1b[2J"
    odd.mkdir()  # a folder, but not a team folder: the message suggests `flightdeck team init <it>`
    message = str(pytest.raises(TeamError, TeamChannel, odd, "alpha").value)
    assert "flightdeck team init" in message and "\x1b" not in message


def test_a_file_name_that_is_not_utf8_is_reported_with_its_bytes_escaped(folder, wall, tmp_path):
    claims = os.fsencode(folder / "claims")
    try:
        with open(claims + b"/\x9b2J\x9b31mred.json", "wb"):
            pass
    except OSError as exc:  # APFS on macOS, for one, refuses such a name
        pytest.skip(f"this filesystem refuses a file name that is not UTF-8 ({exc.strerror}); Linux allows one")
    alpha, _ = pair(folder, wall)
    (problem,) = alpha.state().problems
    assert problem == "claims/\\x9b2J\\x9b31mred.json: is not named <challenge id>.json; ignored"
    result = CliRunner().invoke(team_cli.app, ["status", str(folder)])
    assert result.exit_code == 0, result.output
    assert b"\x9b" not in result.stdout_bytes and "ignored: claims/\\x9b2J\\x9b31mred.json" in result.output
    named = os.fsdecode(os.fsencode(tmp_path) + b"/team-\x9b")
    result = CliRunner().invoke(team_cli.app, ["init", named])
    assert result.exit_code == 0, result.output
    assert b"\x9b" not in result.stdout_bytes and "team-\\x9b" in result.output


def test_hidden_files_are_skipped_without_a_word(folder, wall):
    alpha, _ = pair(folder, wall)
    put(folder, "claims", ".DS_Store", b"\x00\x01")
    put(folder, "claims", ".c0.json.0123456789ab.tmp", b'{"who": "bra')
    put(folder, "claims", ".stfolder", b"")
    assert alpha.state() == read_state(folder, now=T0)
    assert alpha.state().problems == () and alpha.state().claims == {}


def test_a_huge_file_is_reported_not_read(folder, wall):
    alpha, _ = pair(folder, wall)
    put(folder, "claims", "c0.json", b" " * (10 * 1024 * 1024))
    padded = json.dumps(GOOD).encode()
    put(folder, "claims", "c1.json", padded + b" " * (MAX_MARK_BYTES - len(padded)))  # exactly the limit: fine
    put(folder, "claims", "c2.json", padded + b" " * (MAX_MARK_BYTES - len(padded) + 1))  # one byte over
    state = alpha.state()
    assert set(state.claims) == {"c1"}
    assert [p.split(":")[0] for p in state.problems] == ["claims/c0.json", "claims/c2.json"]
    assert all(f"over {MAX_MARK_BYTES} bytes" in p for p in state.problems)


def test_a_symlink_is_never_followed_and_a_write_replaces_the_link_not_its_target(folder, wall, tmp_path):
    alpha, _ = pair(folder, wall)
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(GOOD))
    (folder / "claims" / "c0.json").symlink_to(outside)
    state = alpha.state()
    assert state.claims == {}
    assert state.problems == ("claims/c0.json: is a symlink (never followed); ignored",)
    assert alpha.current("claims", "c0") is None
    assert alpha.claim("c0") is True
    assert json.loads(outside.read_text()) == GOOD  # the target is untouched
    link = folder / "claims" / "c0.json"
    assert not link.is_symlink() and json.loads(link.read_text())["who"] == "alpha"


def test_a_fifo_or_a_folder_named_like_a_mark_is_reported_and_never_blocks(folder, wall):
    alpha, _ = pair(folder, wall)
    os.mkfifo(folder / "claims" / "c0.json")  # an open() that waited for a writer would hang here
    (folder / "claims" / "c1.json").mkdir()
    result: list = []
    reader = threading.Thread(target=lambda: result.append(alpha.state()), daemon=True)
    reader.start()
    reader.join(timeout=10)
    assert not reader.is_alive(), "reading the team folder blocked on a FIFO"
    (state,) = result
    assert state.claims == {}
    assert state.problems == (
        "claims/c0.json: is not a regular file; ignored",
        "claims/c1.json: is not a regular file; ignored",
    )


def test_a_kind_folder_that_is_a_symlink_or_a_file_is_refused(folder, wall, tmp_path):
    alpha, _ = pair(folder, wall)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "c0.json").write_text(json.dumps(GOOD))
    shutil.rmtree(folder / "claims")
    (folder / "claims").symlink_to(elsewhere)
    with pytest.raises(TeamError, match="claims: is a symlink"):
        alpha.state()
    with pytest.raises(TeamError, match="claims: is a symlink"):
        alpha.claim("c1")
    assert sorted(p.name for p in elsewhere.iterdir()) == ["c0.json"]  # nothing written through the link
    shutil.rmtree(folder / "boxes")
    (folder / "boxes").write_text("not a folder")
    (folder / "claims").unlink()
    with pytest.raises(TeamError, match="boxes: is not a folder"):
        alpha.hold_box("c0")


def test_a_flood_of_files_is_capped_and_reported(folder, wall):
    alpha, _ = pair(folder, wall)
    data = json.dumps(GOOD).encode()
    for i in range(MAX_ENTRIES + 10):
        (folder / "solves" / f"c{i}.json").write_bytes(data)
    state = alpha.state()
    assert len(state.solves) == MAX_ENTRIES
    assert state.problems == (f"solves/: has more than {MAX_ENTRIES} entries; the rest were not read",)


def test_a_missing_kind_folder_is_just_empty(folder, wall):
    alpha, _ = pair(folder, wall)
    for kind in ("claims", "boxes", "solves"):
        shutil.rmtree(folder / kind)
    assert alpha.state() == read_state(folder, now=T0)
    assert (alpha.state().claims, alpha.state().problems) == ({}, ())
    assert alpha.claim("c0") is True and (folder / "claims" / "c0.json").is_file()


# ---------------------------------------------------------------------- the watcher, on a real deck


def watcher(folder, deck, wall=None, me="alpha"):
    reports: list[str] = []
    channel = TeamChannel(folder, me, **({"clock": wall} if wall is not None else {}))
    return TeamWatcher(channel, deck, report=reports.append), reports


def test_a_teammates_solve_stops_our_lane_and_frees_its_slot(folder):
    deck, driver = make_deck(max_lanes=1)
    lane = lane_on(deck, "c0")
    TeamChannel(folder, "bravo").solved("c0")
    w, reports = watcher(folder, deck)
    w.poll()
    assert lane.state is LaneState.STOPPED and ("stop", lane.id) in driver.calls
    assert "bravo solved" in lane.alert(AlertKind.TEAMMATE).reason
    ch = deck.challenges["c0"]
    assert (ch.status, ch.solved_by) == (ChallengeStatus.TEAMMATE, "bravo")
    assert driver.started() == ["c0", "c1"]  # the next queued challenge took the slot
    assert reports == []


def test_a_teammates_claim_takes_a_queued_challenge_out_of_the_queue(folder):
    deck, driver = make_deck(max_lanes=1)
    TeamChannel(folder, "bravo").claim("c1")
    w, reports = watcher(folder, deck)
    w.poll()
    ch = deck.challenges["c1"]
    assert (ch.status, ch.claimed_by) == (ChallengeStatus.NEW, "bravo")
    assert [entry.challenge for entry in deck.queue] == ["c2"]
    deck.apply(iv.Kill(lane_on(deck, "c0").id, requeue=False))
    assert driver.started() == ["c0", "c2"]
    assert reports == []


def test_the_same_mark_is_never_applied_twice(folder, wall):
    deck, _ = make_deck(max_lanes=1)
    bravo = TeamChannel(folder, "bravo", clock=wall)
    bravo.claim("c1")
    bravo.solved("c2")
    w, reports = watcher(folder, deck, wall)
    for _ in range(3):
        w.poll()
    wall.t += 3600
    bravo.claim("c1", note="renewed")  # a renewal is the same claim
    w.poll()
    w.poll()
    teammate = [e.text for e in events(deck, EventKind.TEAMMATE)]
    assert teammate == ["bravo solved Chall c2", "bravo claimed Chall c1"]  # solves go first
    assert reports == []


def test_a_second_watcher_does_not_apply_what_the_first_already_did(folder):
    deck, _ = make_deck(max_lanes=1)
    bravo = TeamChannel(folder, "bravo")
    bravo.claim("c1")
    bravo.solved("c2")
    watcher(folder, deck)[0].poll()
    mark = len(deck.events)
    watcher(folder, deck)[0].poll()
    assert events(deck, EventKind.TEAMMATE, since=mark) == []


def test_a_teammates_release_is_reported_once_when_the_deck_cannot_drop_their_claim(folder):
    deck, _ = make_deck(max_lanes=1)
    bravo = TeamChannel(folder, "bravo")
    bravo.claim("c1")
    w, reports = watcher(folder, deck)
    w.poll()
    bravo.release("c1")
    for _ in range(3):
        w.poll()
    assert deck.challenges["c1"].claimed_by == "bravo"
    assert reports == [
        "team: bravo no longer claims c1, but this deck cannot drop a teammate's claim "
        "(it has no teammate_release), so it stays claimed by bravo here"
    ]


def test_a_released_or_stale_claim_is_dropped_on_a_deck_that_can(folder, wall):
    deck, _ = make_deck(max_lanes=1, deck_class=ReleasingDeck)
    bravo = TeamChannel(folder, "bravo", clock=wall)
    charlie = TeamChannel(folder, "charlie", clock=wall)
    bravo.claim("c1")
    charlie.claim("c2")
    w, reports = watcher(folder, deck, wall)
    w.poll()
    assert (deck.challenges["c1"].claimed_by, deck.challenges["c2"].claimed_by) == ("bravo", "charlie")
    bravo.release("c1")
    w.poll()
    wall.t += STALE_AFTER + 1  # charlie's flightdeck stopped without letting go
    w.poll()
    w.poll()
    assert deck.released == [("c1", "bravo"), ("c2", "charlie")]
    assert deck.challenges["c1"].claimed_by is None and deck.challenges["c2"].claimed_by is None
    assert deck.apply(iv.Queue("c1")).ok
    assert reports == []


def test_a_claim_that_moves_to_another_teammate_moves_on_the_deck(folder, wall):
    deck, _ = make_deck(max_lanes=1)
    bravo = TeamChannel(folder, "bravo", clock=wall)
    bravo.claim("c1")
    w, reports = watcher(folder, deck, wall)
    w.poll()
    wall.t += STALE_AFTER + 1
    assert TeamChannel(folder, "charlie", clock=wall).claim("c1")
    w.poll()
    assert deck.challenges["c1"].claimed_by == "charlie"
    assert reports == []


def test_marks_for_challenges_not_on_the_deck_wait_until_they_are(folder):
    deck, _ = make_deck(("c0",), max_lanes=1)
    bravo = TeamChannel(folder, "bravo")
    bravo.claim("w1")
    bravo.solved("w2")
    w, reports = watcher(folder, deck)
    w.poll()
    assert events(deck, EventKind.TEAMMATE) == []
    release(deck, ("w1", "w2", "w3"))  # the second wave
    w.poll()
    assert deck.challenges["w1"].claimed_by == "bravo"
    assert deck.challenges["w2"].status is ChallengeStatus.TEAMMATE
    assert [entry.challenge for entry in deck.queue] == ["w3"]
    assert reports == []


def test_our_earlier_solve_closes_the_challenge_and_our_earlier_claim_is_ours_not_a_teammates(folder):
    deck, driver = make_deck(max_lanes=1)
    lane = lane_on(deck, "c0")
    earlier = TeamChannel(folder, "alpha")  # our flightdeck before a restart
    earlier.solved("c0", note="L07")
    earlier.claim("c1")
    w, reports = watcher(folder, deck)
    w.poll()
    assert lane.state is LaneState.STOPPED  # we will not work a challenge we already solved
    assert (deck.challenges["c0"].status, deck.challenges["c0"].solved_by) == (ChallengeStatus.TEAMMATE, "alpha")
    assert deck.challenges["c1"].claimed_by == ME  # taken back as the player's, not applied as a teammate's
    assert [e.data["intervention"] for e in events(deck, EventKind.OUTCOME)] == ["claim"]
    assert [e.text for e in events(deck, EventKind.TEAMMATE)] == ["alpha solved Chall c0 · stopped L01"]
    assert w.channel.current("claims", "c1").who == "alpha"
    assert reports == []


def test_our_claim_from_before_a_restart_is_taken_back_once_then_follows_the_deck(folder):
    deck, _ = make_deck(max_lanes=1)
    earlier = TeamChannel(folder, "alpha")
    earlier.claim("c1")
    earlier.claim("w1")  # a challenge of a wave this run has not pulled yet
    w, reports = watcher(folder, deck)
    w.poll()
    assert deck.challenges["c1"].claimed_by == ME
    assert earlier.current("claims", "w1") is not None  # it waits for its challenge
    release(deck, ("w1",))
    w.poll()
    assert deck.challenges["w1"].claimed_by == ME
    assert deck.apply(iv.Release("c1")).ok  # the player lets it go (no mirror here)
    w.poll()
    w.poll()
    assert deck.challenges["c1"].claimed_by is None  # not taken back a second time
    assert earlier.current("claims", "c1") is None  # released in the folder too
    assert reports == []


def test_free_boxes_frees_our_holds_and_no_one_elses(folder):
    alpha, bravo = pair(folder)
    alpha.hold_box("c0")
    alpha.hold_box("c1")
    bravo.hold_box("c2")
    assert alpha.free_boxes() == ["c0", "c1"]
    assert dict(bravo.state().boxes) == {"c2": bravo.current("boxes", "c2")}
    assert alpha.free_boxes() == []


def test_our_solve_in_this_run_is_not_applied_again(folder):
    deck, _ = make_deck(max_lanes=1)
    w, reports = watcher(folder, deck)
    unsubscribe = mirror(w.channel, deck, report=reports.append)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(action="solve", flag="t{c0}"))
    assert deck.apply(iv.Approve(lane.id)).ok
    mark = len(deck.events)
    w.poll()
    w.poll()
    assert deck.events[mark:] == []
    assert (deck.challenges["c0"].status, deck.challenges["c0"].solved_by) == (ChallengeStatus.SOLVED, lane.id)
    unsubscribe()
    assert reports == []


def test_a_clash_over_a_claim_is_warned_once(folder):
    deck, _ = make_deck(max_lanes=1)
    TeamChannel(folder, "bravo").claim("c1")
    assert deck.apply(iv.Claim("c1")).ok  # before our watcher saw bravo's claim
    w, reports = watcher(folder, deck)
    for _ in range(3):
        w.poll()
    warnings = [e.text for e in events(deck, EventKind.WARNING)]
    assert warnings == ["bravo also claimed Chall c1; you hold the claim"]
    assert w.channel.current("claims", "c1") == TeamChannel(folder, "bravo").current("claims", "c1")
    assert reports == []


def test_our_claims_follow_the_deck(folder, wall):
    deck, _ = make_deck(max_lanes=1)
    w, reports = watcher(folder, deck, wall)
    alpha = w.channel
    for cid in ("c1", "c2"):
        assert deck.apply(iv.Claim(cid)).ok
        alpha.claim(cid, note="mine")
    wall.t += STALE_AFTER / 2 + 1
    w.poll()
    assert alpha.current("claims", "c1") == Mark("alpha", wall.t, "mine")  # renewed before it goes stale
    assert deck.apply(iv.Release("c2")).ok  # no mirror here: the folder still has it
    (folder / "claims" / "c1.json").unlink()  # lost, say by a sync tool
    w.poll()
    assert alpha.current("claims", "c2") is None  # released: the deck no longer holds it
    assert alpha.current("claims", "c1") == Mark("alpha", wall.t, "")  # written again
    assert reports == []


def test_our_box_holds_follow_our_lanes(folder, wall):
    deck, _ = make_deck(max_lanes=1)
    w, reports = watcher(folder, deck, wall)
    alpha = w.channel
    alpha.hold_box("c0", note="L01")  # c0 has our lane L01
    alpha.hold_box("c2", note="L09")  # left over from an earlier run: no lane of ours on it
    w.poll()
    assert alpha.current("boxes", "c2") is None
    wall.t += STALE_AFTER / 2 + 1
    w.poll()
    assert alpha.current("boxes", "c0") == Mark("alpha", wall.t, "L01")
    deck.apply(iv.Kill(lane_on(deck, "c0").id, requeue=False))
    w.poll()
    assert alpha.current("boxes", "c0") is None
    assert reports == []


def test_problems_are_reported_once_while_they_last_and_again_if_they_return(folder):
    deck, _ = make_deck(max_lanes=1)
    w, reports = watcher(folder, deck)
    put(folder, "claims", "c1.json", {"who": "../../x", "at": 1})
    w.poll()
    w.poll()
    assert reports == ['team folder: claims/c1.json: "who" is not a team handle (1 to 40 letters, digits and _ . -, and not \'me\'); ignored']
    (folder / "claims" / "c1.json").unlink()
    w.poll()
    put(folder, "claims", "c1.json", {"who": "../../x", "at": 1})
    w.poll()
    assert len(reports) == 2 and reports[0] == reports[1]


def test_a_hostile_solve_file_stops_nothing(folder):
    deck, _ = make_deck(max_lanes=1)
    lane = lane_on(deck, "c0")
    put(folder, "solves", "c0.json", {"who": "me", "at": 1})
    put(folder, "solves", "c0 .json", {"who": "bravo", "at": 1})
    w, reports = watcher(folder, deck)
    w.poll()
    assert lane.state is LaneState.RUNNING and deck.challenges["c0"].status is ChallengeStatus.RUNNING
    assert len(reports) == 2 and all(r.startswith("team folder: solves/c0") for r in reports)


def test_a_folder_that_cannot_be_read_changes_nothing_on_the_deck(folder, tmp_path):
    deck, _ = make_deck(max_lanes=1, deck_class=ReleasingDeck)
    TeamChannel(folder, "bravo").claim("c1")
    w, reports = watcher(folder, deck)
    w.poll()
    folder.rename(tmp_path / "away")
    folder.mkdir()  # the drive went away
    assert w.poll() is None
    assert w.poll() is None
    assert deck.challenges["c1"].claimed_by == "bravo" and deck.__dict__.get("released") is None
    assert len(reports) == 1 and "is not a team folder" in reports[0]


def test_the_watcher_and_the_mirror_need_team_mode(folder):
    deck, _ = make_deck(team=False)
    alpha = TeamChannel(folder, "alpha")
    with pytest.raises(TeamError, match="team mode"):
        TeamWatcher(alpha, deck, report=print)
    with pytest.raises(TeamError, match="team mode"):
        mirror(alpha, deck, report=print)
    with pytest.raises(TeamError, match="team mode"):
        asyncio.run(watch(alpha, deck, stop=asyncio.Event(), report=print))


# ---------------------------------------------------------------------- watch(), the loop


async def until(condition, timeout: float = 10.0) -> None:
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while not condition():
        if loop.time() > end:
            raise AssertionError("timed out waiting for the deck to change")
        await asyncio.sleep(0.005)


def test_watch_keeps_the_deck_in_step_while_it_runs_and_returns_once_stopped(folder):
    deck, driver = make_deck(max_lanes=1)  # c0 runs; c1 and c2 wait in the queue
    alpha, bravo = TeamChannel(folder, "alpha"), TeamChannel(folder, "bravo")
    reports: list[str] = []

    async def main() -> None:
        stop = asyncio.Event()
        task = asyncio.create_task(watch(alpha, deck, interval=0.01, stop=stop, report=reports.append))
        await asyncio.sleep(0.05)
        bravo.claim("c1")
        await until(lambda: deck.challenges["c1"].claimed_by == "bravo")
        bravo.solved("c0")
        await until(lambda: deck.challenges["c0"].status is ChallengeStatus.TEAMMATE)
        put(folder, "claims", "c2.json", {"who": "bad handle", "at": 1})
        await until(lambda: bool(reports))
        stop.set()
        await asyncio.wait_for(task, timeout=5)
        assert task.done() and task.exception() is None

    asyncio.run(main())
    assert driver.started() == ["c0", "c2"]  # c0's lane stopped; c1 is bravo's, so c2 took the slot
    teammate = [e.text for e in events(deck, EventKind.TEAMMATE)]
    assert teammate[0] == "bravo claimed Chall c1" and teammate[1].startswith("bravo solved Chall c0")
    assert len(teammate) == 2
    assert reports == ['team folder: claims/c2.json: "who" is not a team handle (1 to 40 letters, digits and _ . -, and not \'me\'); ignored']


def test_watch_refuses_a_poll_interval_that_is_not_positive(folder):
    deck, _ = make_deck()
    alpha = TeamChannel(folder, "alpha")
    for interval in (0, -1, float("nan")):
        with pytest.raises(TeamError, match="interval"):
            asyncio.run(watch(alpha, deck, interval=interval, stop=asyncio.Event(), report=print))


# ---------------------------------------------------------------------- mirror()


def mirrored(folder, deck, me="alpha"):
    reports: list[str] = []
    channel = TeamChannel(folder, me)
    return channel, mirror(channel, deck, report=reports.append), reports


def test_mirror_writes_our_claims_and_releases(folder):
    deck, _ = make_deck()
    alpha, _, reports = mirrored(folder, deck)
    bravo = TeamChannel(folder, "bravo")
    assert deck.apply(iv.Claim("c1")).ok
    assert bravo.current("claims", "c1").who == "alpha"
    assert deck.apply(iv.Release("c1")).ok
    assert bravo.current("claims", "c1") is None
    assert reports == []


def test_mirror_writes_nothing_for_a_claim_the_deck_refused(folder):
    deck, _ = make_deck()
    alpha, _, reports = mirrored(folder, deck)
    deck.teammate_claim("c1", "bravo")
    before = tree(folder)
    assert not deck.apply(iv.Claim("c1")).ok  # claimed by bravo
    assert not deck.apply(iv.Claim("nope")).ok  # no such challenge
    assert not deck.apply(iv.Release("c2")).ok  # not ours
    assert tree(folder) == before and reports == []


def test_mirror_records_a_correct_flag_as_our_solve_and_never_writes_the_flag(folder):
    deck, _ = make_deck()
    alpha, _, reports = mirrored(folder, deck)
    assert deck.apply(iv.Claim("c0")).ok
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(action="guess", flag="t{wrong}"))
    deck.apply(iv.Approve(lane.id))  # rejected by the platform: not a solve
    assert alpha.current("solves", "c0") is None
    deck.report(lane.id, TurnReport(action="solve", flag="t{c0}"))
    assert deck.apply(iv.Approve(lane.id)).ok
    assert alpha.current("solves", "c0").who == "alpha"
    assert json.loads((folder / "solves" / "c0.json").read_bytes())["note"] == lane.id
    assert alpha.current("claims", "c0") is None  # a solved challenge needs no claim
    assert all(b"t{" not in data for data in tree(folder).values() if data)
    assert reports == []


def test_mirror_holds_the_live_box_while_an_approved_lane_works_it(folder):
    deck, _ = make_deck(("c0", "c1"), max_lanes=3)
    alpha, _, reports = mirrored(folder, deck)
    first = lane_on(deck, "c0")
    assert deck.apply(iv.Fork(first.id)).ok
    second = next(lane for lane in deck.lanes_on("c0") if lane is not first)
    other = lane_on(deck, "c1")
    box = Pending(PendingKind.LIVE_BOX, "use the live box")
    deck.report(other.id, TurnReport(pending=box))
    assert deck.apply(iv.Decline(other.id)).ok
    assert alpha.current("boxes", "c1") is None  # declined: no hold
    for lane in (first, second):
        deck.report(lane.id, TurnReport(pending=box))
        assert deck.apply(iv.Approve(lane.id)).ok
    assert alpha.current("boxes", "c0").who == "alpha"
    deck.apply(iv.Kill(first.id, requeue=False))
    assert alpha.current("boxes", "c0") is not None  # the fork is still on the box
    deck.apply(iv.Kill(second.id, requeue=False))
    assert alpha.current("boxes", "c0") is None
    assert reports == []


def test_mirror_reports_a_teammates_hold_on_the_box_and_on_the_claim(folder):
    deck, _ = make_deck(max_lanes=1)
    alpha, _, reports = mirrored(folder, deck)
    bravo = TeamChannel(folder, "bravo")
    bravo.hold_box("c0")
    bravo.claim("c1")
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(pending=Pending(PendingKind.LIVE_BOX, "use the live box")))
    assert deck.apply(iv.Approve(lane.id)).ok
    assert deck.apply(iv.Claim("c1")).ok  # our deck had not seen bravo's claim yet
    assert bravo.current("boxes", "c0").who == "bravo" and bravo.current("claims", "c1").who == "bravo"
    assert reports == [
        f"team: bravo holds the live box of c0; {lane.id} was allowed on it all the same: ask bravo, or tell {lane.id} to stay off it",
        "team: bravo holds the claim on c1 in the team folder, so yours is only on this deck; release it, or ask bravo",
    ]


def test_mirror_reports_a_failed_write_and_the_deck_carries_on(folder):
    deck, _ = make_deck()
    alpha, _, reports = mirrored(folder, deck)
    shutil.rmtree(folder / "claims")
    (folder / "claims").write_text("not a folder")
    outcome = deck.apply(iv.Claim("c1"))
    assert outcome.ok and deck.challenges["c1"].claimed_by == ME
    assert len(reports) == 1 and reports[0].startswith("team: could not claim c1 in the team folder: ")
    assert "claims: is not a folder" in reports[0]


def test_unsubscribing_stops_the_mirror(folder):
    deck, _ = make_deck()
    alpha, unsubscribe, reports = mirrored(folder, deck)
    unsubscribe()
    assert deck.apply(iv.Claim("c1")).ok
    assert alpha.current("claims", "c1") is None and reports == []


# ---------------------------------------------------------------------- flightdeck team


def test_cli_init_then_status_shows_the_folder(tmp_path):
    runner = CliRunner()
    folder = tmp_path / "team"
    result = runner.invoke(team_cli.app, ["init", str(folder)])
    assert result.exit_code == 0, result.output
    assert (folder / MARKER).is_file()
    bravo = TeamChannel(folder, "bravo")
    bravo.claim("c1", note="\x1b[2Jsneaky")
    bravo.solved("c2")
    put(folder, "boxes", "UPPER.json", GOOD)
    result = runner.invoke(team_cli.app, ["status", str(folder)])
    assert result.exit_code == 0, result.output
    assert "c1" in result.output and "bravo" in result.output and "c2" in result.output
    assert "\x1b" not in result.output and "^[[2Jsneaky" in result.output
    assert "boxes/UPPER.json" in result.output


def test_cli_status_reports_a_note_with_a_lone_surrogate_instead_of_crashing(folder):
    put(folder, "claims", "c1.json", b'{"who": "bravo", "at": %d, "note": "\\udc9b2J"}' % int(time.time()))
    result = CliRunner().invoke(team_cli.app, ["status", str(folder)])
    assert result.exit_code == 0, result.exception
    assert result.output == (
        "claims: none\nlive boxes: none\nsolves: none\n"
        f'ignored: claims/c1.json: "note" is not text of at most {MAX_NOTE} characters; ignored\n'
    )


def test_cli_status_of_a_folder_that_is_not_a_team_folder_fails_with_the_reason(tmp_path):
    result = CliRunner().invoke(team_cli.app, ["status", str(tmp_path)])
    assert result.exit_code == 2
    assert "is not a team folder" in result.output and "flightdeck team init" in result.output
