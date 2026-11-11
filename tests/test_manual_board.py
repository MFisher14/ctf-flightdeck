"""The folder board: challenge directories with a challenge.json, board.json and the answers file.

Every test builds a real folder in tmp_path. Challenge text, names and files are synthetic.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from ctf_flightdeck import platform
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Challenge, ChallengeStatus, DeckConfig
from ctf_flightdeck.platform import manual
from ctf_flightdeck.platform.manual import (
    AnswerVerifier,
    BoardError,
    cannot_check,
    category_code,
    load_board,
)

SPEC = {"name": "Sample One", "category": "misc", "points": 100}


def sha(flag: str) -> str:
    return hashlib.sha256(flag.encode()).hexdigest()


def put(path: Path, content: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def challenge(board: Path, dirname: str, spec: dict | str | None = None, files: dict[str, str | bytes] | None = None) -> Path:
    """A challenge directory: challenge.json from `spec` (a dict as JSON, a str as is), plus `files`."""
    directory = board / dirname
    directory.mkdir(parents=True, exist_ok=True)
    for rel, content in (files or {}).items():
        put(directory / rel, content)
    if spec is not None:
        put(directory / "challenge.json", spec if isinstance(spec, str) else json.dumps(spec))
    return directory


def spec(**changes) -> dict:
    """SPEC with `changes`; a change to None removes the key."""
    out = {**SPEC, **changes}
    return {key: value for key, value in out.items() if value is not None}


def board_error(folder: Path, **kwargs) -> str:
    with pytest.raises(BoardError) as caught:
        load_board(folder, **kwargs)
    return str(caught.value)


@pytest.fixture
def board(tmp_path) -> Path:
    folder = tmp_path / "Practice Range"
    folder.mkdir()
    return folder


@pytest.fixture
def listing_reversed(monkeypatch) -> list[Path]:
    """Directories list their entries in reverse name order, whatever order this file system
    uses, so a test of the loader's sorting cannot pass by the file system's luck. Returns the
    directories listed, so a test can check its listing really came through here."""
    listed: list[Path] = []
    real_iterdir = Path.iterdir

    def iterdir(self):
        listed.append(self)
        return iter(sorted(real_iterdir(self), key=lambda entry: entry.name, reverse=True))

    monkeypatch.setattr(Path, "iterdir", iterdir)
    return listed


# ---------------------------------------------------------------------- the board


def test_each_subdirectory_with_a_challenge_json_is_a_challenge_sorted_by_directory_name(board, listing_reversed):
    for cid in ["mango", "zeta-two", "0-start", "kilo", "alpha-one", "x", "delta-9", "a.b", "echo_5", "beta"]:
        challenge(board, cid, spec(name=f"Sample {cid}"))
    for name in ["notes", "_drafts", "Loose Files", "Zed"]:
        challenge(board, name, files={"todo.txt": "later"})
    put(board / "README.md", "not a challenge")
    loaded = load_board(board)
    assert board.resolve() in listing_reversed
    ids = ["0-start", "a.b", "alpha-one", "beta", "delta-9", "echo_5", "kilo", "mango", "x", "zeta-two"]
    assert [item.challenge.id for item in loaded.challenges] == ids
    assert [item.handout for item in loaded.challenges] == [board.resolve() / cid for cid in ids]
    assert loaded.skipped == ("Loose Files", "Zed", "_drafts", "notes")
    assert (loaded.event, loaded.flag_format, loaded.answers) == ("Practice Range", None, None)


def test_a_minimal_challenge_json_gets_the_documented_defaults(board, listing_reversed):
    files = {"b.txt": "b", "a.bin": b"\x00\x01", ".notes": "n", "sub/inner.txt": "deeper"}
    directory = challenge(board, "sample-one", spec(), files)
    (item,) = load_board(board).challenges
    assert directory.resolve() in listing_reversed
    assert item.challenge == Challenge(
        id="sample-one",
        name="Sample One",
        category="misc",
        points=100,
        solves=0,
        description="",
        files=(".notes", "a.bin", "b.txt"),  # regular files directly in the directory, sorted
        live=False,
    )
    assert item.challenge.status is ChallengeStatus.NEW
    assert item.urls == ()


def test_every_field_of_challenge_json_is_read(board):
    challenge(
        board,
        "dir-name",
        {
            "name": "Sample Web",
            "category": "Web",
            "points": 250,
            "solves": 12,
            "description": "Look closer at the login form.",
            "files": ["dist/app.py", "notes.txt"],
            "urls": ["HTTP://LocalHost:8080/", "https://instance.example"],
            "id": "sample-web",
        },
        {"dist/app.py": "print('hello')", "notes.txt": "n", "extra.txt": "not listed"},
    )
    (item,) = load_board(board).challenges
    assert item.challenge == Challenge(
        id="sample-web",
        name="Sample Web",
        category="web",
        points=250,
        solves=12,
        description="Look closer at the login form.",
        files=("dist/app.py", "notes.txt"),  # as listed, in the order given
        live=True,
    )
    assert item.urls == ("http://localhost:8080", "https://instance.example")
    assert item.handout == board.resolve() / "dir-name"


@pytest.mark.parametrize(
    "given, code",
    [
        ("web", "web"),
        ("crypto", "cry"),
        ("Cryptography", "cry"),
        ("rev", "rev"),
        ("Reverse", "rev"),
        ("reversing", "rev"),
        ("pwn", "pwn"),
        ("Binary", "pwn"),
        ("FORENSICS", "for"),
        ("misc", "misc"),
        ("OSINT", "osint"),
        ("Hardware", "hardware"),
        (" Web ", "web"),
    ],
)
def test_category_names_map_to_the_console_codes(board, given, code):
    assert category_code(given) == code
    challenge(board, "sample-one", spec(category=given))
    assert load_board(board).challenges[0].challenge.category == code


@pytest.mark.parametrize(
    "given, origin",
    [
        ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
        ("HTTP://Instance.Example:8443/", "http://instance.example:8443"),
        ("https://instance.example", "https://instance.example"),
        ("http://[::1]:9000", "http://[::1]:9000"),
        ("http://box_1.local:31337", "http://box_1.local:31337"),
    ],
)
def test_urls_become_origins_in_one_form(board, given, origin):
    challenge(board, "sample-one", spec(urls=[given]))
    assert load_board(board).challenges[0].urls == (origin,)


def test_board_json_names_the_event_and_the_flag_format(board):
    challenge(board, "sample-one", spec())
    put(board / "board.json", json.dumps({"event": "Sample Event", "flag_format": r"practice\{[a-z0-9_]+\}"}))
    loaded = load_board(board)
    assert (loaded.event, loaded.flag_format) == ("Sample Event", r"practice\{[a-z0-9_]+\}")


def test_board_json_keys_are_optional(board):
    challenge(board, "sample-one", spec())
    put(board / "board.json", "{}")
    loaded = load_board(board)
    assert (loaded.event, loaded.flag_format) == ("Practice Range", None)


def test_a_folder_given_as_dot_is_named_after_the_directory(board, monkeypatch):
    challenge(board, "sample-one", spec())
    monkeypatch.chdir(board)
    assert load_board(Path(".")).event == "Practice Range"


@pytest.mark.parametrize(
    "content, problem",
    [
        ('{"flag_format": "practice\\\\{[a-z"}', '"flag_format" does not compile'),
        ('{"flag_format": ""}', '"flag_format" must be'),
        ('{"flag_format": 5}', '"flag_format" must be'),
        ('{"event": ""}', '"event" must be'),
        ('{"event": ["a"]}', '"event" must be'),
        ('{"event": "x", "flag_fromat": "y"}', 'unknown key "flag_fromat"'),
        ('["event"]', "must be a JSON object"),
        ('{"event": ', "is not valid JSON"),
    ],
    ids=["regex", "empty format", "format not a string", "empty event", "event not a string", "unknown key", "not an object", "bad JSON"],
)
def test_a_bad_board_json_names_the_file_and_the_problem(board, content, problem):
    challenge(board, "sample-one", spec())
    path = put(board / "board.json", content)
    message = board_error(board)
    assert message.startswith(f"{path.resolve()}: ")
    assert problem in message


def test_a_folder_that_is_missing_or_a_file_is_an_error(tmp_path):
    assert "no such directory" in board_error(tmp_path / "nowhere")
    assert "is not a directory" in board_error(put(tmp_path / "board.txt", "x"))


def test_a_board_without_challenges_is_an_error(board):
    challenge(board, "notes", files={"todo.txt": "later"})
    assert "no challenge directories" in board_error(board)


def test_pointing_at_a_challenge_directory_says_to_point_at_its_folder(board):
    directory = challenge(board, "sample-one", spec(), {"cipher.txt": "abc"})
    message = board_error(directory)
    assert "no challenge directories" in message and "point at the folder that holds it" in message


def test_two_challenges_with_one_id_name_both_files(board):
    challenge(board, "first", spec(id="same-id"))
    second = challenge(board, "second", spec(id="same-id"))
    message = board_error(board)
    assert message.startswith(f"{(second / 'challenge.json').resolve()}: ")
    assert str((board / "first" / "challenge.json").resolve()) in message


def test_loading_never_writes_to_the_folder(board, tmp_path):
    challenge(board, "sample-one", spec(urls=["http://127.0.0.1:1"]), {"a.txt": "a", "sub/b.bin": b"\x00"})
    challenge(board, "notes", files={"todo.txt": "t"})
    put(board / "board.json", '{"event": "E"}')
    put(board / "answers.sha256.json", json.dumps({"sample-one": sha("t{x}")}))

    def state():
        return {
            str(p.relative_to(board)): (p.stat().st_mtime_ns, p.read_bytes() if p.is_file() else None)
            for p in sorted(board.rglob("*"))
        }

    before = state()
    load_board(board)
    AnswerVerifier(board / "answers.sha256.json")("sample-one", "t{x}")
    assert state() == before


# ---------------------------------------------------------------------- challenge.json errors

BAD_SPECS = {
    "bad JSON": ('{"name": ', "is not valid JSON"),
    "not an object": ("[1, 2]", "must be a JSON object"),
    "no name": (spec(name=None), '"name" is missing'),
    "blank name": (spec(name="   "), '"name" must be a non-empty string'),
    "name not a string": (spec(name=42), '"name" must be a non-empty string'),
    "no category": (spec(category=None), '"category" is missing'),
    "category not a string": (spec(category=["web"]), '"category" must be a string'),
    "no points": (spec(points=None), '"points" is missing'),
    "negative points": (spec(points=-1), '"points" must be a whole number'),
    "fractional points": (spec(points=50.0), '"points" must be a whole number'),
    "points true": (spec(points=True), '"points" must be a whole number'),
    "points a string": (spec(points="100"), '"points" must be a whole number'),
    "points NaN": ('{"name": "a", "category": "b", "points": NaN}', '"points" must be a whole number'),
    "negative solves": (spec(solves=-3), '"solves" must be a whole number'),
    "description not a string": (spec(description=["x"]), '"description" must be a string'),
    "unknown key": (spec(nmae="typo"), 'unknown key "nmae"'),
    "a key twice": ('{"name": "a", "category": "b", "points": 1, "points": 2}', 'has the key "points" twice'),
    "id in capitals": (spec(id="Sample"), '"id" must be a challenge id'),
    "id with a slash": (spec(id="a/b"), '"id" must be a challenge id'),
    "id with a space": (spec(id="a b"), '"id" must be a challenge id'),
    "id starting with a dot": (spec(id=".hidden"), '"id" must be a challenge id'),
    "id starting with a dash": (spec(id="-x"), '"id" must be a challenge id'),
    "id too long": (spec(id="a" * 65), '"id" must be a challenge id'),
    "id not a string": (spec(id=7), '"id" must be a challenge id'),
    "files not a list": (spec(files="a.txt"), '"files" must be a list'),
    "file not a string": (spec(files=[3]), '"files"[0] must be a non-empty string'),
    "file empty": (spec(files=[""]), '"files"[0] must be a non-empty string'),
    "file absolute": (spec(files=["/etc/hosts"]), '"files"[0] "/etc/hosts" must be a relative path'),
    "file going up": (spec(files=["../outside.txt"]), "must be a relative path inside the challenge directory"),
    "file going up later": (spec(files=["sub/../../outside.txt"]), "must be a relative path inside the challenge directory"),
    "file missing": (spec(files=["a.txt", "gone.txt"]), '"files"[1] "gone.txt" does not exist'),
    "file a directory": (spec(files=["sub"]), '"sub" is not a regular file'),
    "file the directory": (spec(files=["."]), "names the challenge directory itself"),
    "file twice": (spec(files=["a.txt", "./a.txt"]), 'lists "a.txt" twice'),
    "file with NUL": (spec(files=["a\u0000.txt"]), "contains a NUL character"),
    "urls not a list": (spec(urls="http://127.0.0.1:8080"), '"urls" must be a list'),
    "url with a path": (spec(urls=["http://127.0.0.1:8080/admin"]), '"urls"[0] must be an http:// or https:// origin'),
    "url ftp": (spec(urls=["ftp://127.0.0.1"]), '"urls"[0] must be'),
    "url with a password": (spec(urls=["http://user:pw@127.0.0.1"]), '"urls"[0] must be'),
    "url with a query": (spec(urls=["http://127.0.0.1/?q=1"]), '"urls"[0] must be'),
    "url with no host": (spec(urls=["http://"]), '"urls"[0] must be'),
    "url bad port": (spec(urls=["http://127.0.0.1:99999"]), '"urls"[0] must be'),
    "url bad host": (spec(urls=["http://a b"]), '"urls"[0] must be'),
    "url bad IPv6": (spec(urls=["http://[::zz]"]), '"urls"[0] must be'),
    # urlsplit would quietly turn each of these into another origin: refused, never rewritten
    "url with a tab": (spec(urls=["http://127.0.0.1:80\t80"]), '"urls"[0] must be an http:// or https:// origin'),
    "url with a newline": (spec(urls=["http://exa\nmple.com"]), '"urls"[0] must be'),
    "url ending in a newline": (spec(urls=["http://127.0.0.1:8080\n"]), '"urls"[0] must be'),
    "url with a space in front": (spec(urls=[" http://127.0.0.1:8080"]), '"urls"[0] must be'),
    "url with a control character in front": (spec(urls=["\u0001http://127.0.0.1:8080"]), '"urls"[0] must be'),
    "url with a Kelvin sign": (spec(urls=["http://Kali.example:8080"]), '"urls"[0] must be'),
    "url not a string": (spec(urls=[8080]), '"urls"[0] must be'),
    "url twice": (spec(urls=["http://box.local:1", "HTTP://BOX.local:1/"]), 'lists http://box.local:1 twice'),
    "nesting too deep": ('{"name": ' + "[" * 100_000, "nesting too deep"),
}


@pytest.mark.parametrize("content, problem", BAD_SPECS.values(), ids=BAD_SPECS.keys())
def test_a_bad_challenge_json_names_the_file_and_the_problem(board, content, problem):
    directory = challenge(board, "sample-one", content, {"a.txt": "a", "sub/b.txt": "b"})
    message = board_error(board)
    assert message.startswith(f"{(directory / 'challenge.json').resolve()}: ")
    assert problem in message


def test_a_listed_file_outside_the_challenge_directory_is_refused_even_when_it_exists(board):
    put(board / "secret.txt", "next to the challenge, not in it")
    challenge(board, "sample-one", spec(files=["../secret.txt"]))
    assert '"../secret.txt" must be a relative path inside the challenge directory' in board_error(board)


def test_a_challenge_json_that_is_not_utf8_is_an_error(board):
    directory = challenge(board, "sample-one")
    put(directory / "challenge.json", b'{"name": "\xff"}')
    assert "is not UTF-8 text" in board_error(board)


def test_a_challenge_json_with_a_byte_order_mark_loads(board):
    directory = challenge(board, "sample-one")
    put(directory / "challenge.json", b"\xef\xbb\xbf" + json.dumps(spec()).encode())
    assert load_board(board).challenges[0].challenge.name == "Sample One"


def test_an_oversized_challenge_json_is_refused_before_it_is_parsed(board):
    directory = challenge(board, "sample-one")
    put(directory / "challenge.json", json.dumps(spec(description="x" * manual.MAX_JSON_BYTES)))
    assert f"is over {manual.MAX_JSON_BYTES:,} bytes" in board_error(board)


def test_a_directory_name_that_is_not_an_id_needs_an_explicit_id(board):
    challenge(board, "Sample One", spec())
    message = board_error(board)
    assert 'the directory name "Sample One" is not a valid challenge id' in message
    challenge(board, "Sample One", spec(id="sample-one"))
    assert load_board(board).challenges[0].challenge.id == "sample-one"


def test_untrusted_names_in_errors_cannot_reach_the_terminal_raw(board):
    """A directory name or key with escape sequences shows as visible markers, never as bytes."""
    challenge(board, "\x1b]0;owned\x07dir", spec())
    message = board_error(board)
    assert "\x1b" not in message and "\x07" not in message
    assert "^[]0;owned^G" in message
    other = challenge(board.parent / "other", "sample-one", spec(**{"\x1b[2Jwipe": 1}))
    message = board_error(other.parent)
    assert "\x1b" not in message and 'unknown key "^[[2Jwipe"' in message


# ---------------------------------------------------------------------- symlinks are never followed


def test_default_files_leave_out_symlinks(board, tmp_path):
    secret = put(tmp_path / "outside" / "secret.txt", "not for lanes")
    directory = challenge(board, "sample-one", spec(), {"a.txt": "a"})
    (directory / "peek.txt").symlink_to(secret)
    (directory / "peek-dir").symlink_to(secret.parent, target_is_directory=True)
    assert load_board(board).challenges[0].challenge.files == ("a.txt",)


def test_a_listed_file_that_is_a_symlink_is_refused(board, tmp_path):
    secret = put(tmp_path / "outside" / "secret.txt", "not for lanes")
    directory = challenge(board, "sample-one", spec(files=["peek.txt"]))
    (directory / "peek.txt").symlink_to(secret)
    assert '"peek.txt" is a symlink' in board_error(board)


def test_a_listed_file_under_a_symlinked_directory_is_refused_even_inside(board):
    directory = challenge(board, "sample-one", spec(files=["alias/a.txt"]), {"real/a.txt": "a"})
    (directory / "alias").symlink_to(directory / "real", target_is_directory=True)
    assert '"alias/a.txt" is a symlink or inside one' in board_error(board)


def test_a_symlinked_challenge_json_is_refused(board, tmp_path):
    elsewhere = put(tmp_path / "elsewhere.json", json.dumps(spec()))
    directory = challenge(board, "sample-one")
    (directory / "challenge.json").symlink_to(elsewhere)
    message = board_error(board)
    assert message.startswith(f"{directory.resolve() / 'challenge.json'}: ")
    assert "is a symlink" in message


def test_a_symlinked_board_json_is_refused(board, tmp_path):
    challenge(board, "sample-one", spec())
    (board / "board.json").symlink_to(put(tmp_path / "elsewhere.json", "{}"))
    assert "board.json: is a symlink" in board_error(board)


def test_a_symlinked_challenge_directory_is_skipped_not_followed(board, tmp_path):
    challenge(board, "sample-one", spec())
    real = challenge(tmp_path / "elsewhere", "sample-two", spec(name="Sample Two"))
    (board / "sample-two").symlink_to(real, target_is_directory=True)
    loaded = load_board(board)
    assert [item.challenge.id for item in loaded.challenges] == ["sample-one"]
    assert loaded.skipped == ("sample-two",)


# ---------------------------------------------------------------------- answers


def test_the_folder_answers_file_checks_flags_by_their_hash(board):
    challenge(board, "sample-one", spec())
    challenge(board, "sample-two", spec(name="Sample Two"))
    path = put(board / "answers.sha256.json", json.dumps({"sample-one": sha("t{right}")}))
    loaded = load_board(board)
    assert loaded.answers == path.resolve()
    verify = AnswerVerifier(loaded.answers)
    assert verify("sample-one", "t{right}") is True
    assert verify("sample-one", "t{wrong}") is False
    assert verify("sample-two", "t{right}") is None  # no entry: the player submits by hand
    assert verify.ids == frozenset({"sample-one"})


def test_the_verifier_wants_the_exact_flag(tmp_path):
    verify = AnswerVerifier(put(tmp_path / "answers.json", json.dumps({"sample-one": sha("t{Right}")})))
    assert verify("sample-one", "t{Right}") is True
    for near in ("t{right}", "t{Right} ", " t{Right}", "t{Right}\n", "T{Right}"):
        assert verify("sample-one", near) is False, repr(near)


def test_a_flag_that_cannot_be_utf8_is_wrong_not_a_crash(tmp_path):
    verify = AnswerVerifier(put(tmp_path / "answers.json", json.dumps({"sample-one": sha("t{x}")})))
    assert verify("sample-one", "t{\ud800}") is False


def test_cannot_check_never_knows():
    assert cannot_check("sample-one", "t{anything}") is None


def test_the_verifier_repr_shows_no_hash(tmp_path):
    digest = sha("t{x}")
    verify = AnswerVerifier(put(tmp_path / "answers.json", json.dumps({"sample-one": digest})))
    assert digest not in repr(verify) and "1 answers" in repr(verify)


def test_an_explicit_answers_file_outside_the_folder_wins(board, tmp_path):
    challenge(board, "sample-one", spec())
    put(board / "answers.sha256.json", json.dumps({"sample-one": sha("t{folder}")}))
    mine = put(tmp_path / "kept-elsewhere" / "answers.json", json.dumps({"sample-one": sha("t{mine}")}))
    loaded = load_board(board, answers=mine)
    assert loaded.answers == mine.resolve()
    assert AnswerVerifier(loaded.answers)("sample-one", "t{mine}") is True


def test_a_missing_explicit_answers_file_is_an_error(board, tmp_path):
    challenge(board, "sample-one", spec())
    assert "no such answers file" in board_error(board, answers=tmp_path / "nope.json")


def test_answers_inside_a_challenge_directory_are_refused(board):
    directory = challenge(board, "sample-one", spec())
    inside = put(directory / "answers.json", json.dumps({"sample-one": sha("t{x}")}))
    message = board_error(board, answers=inside)
    assert "is inside the challenge directory" in message and str(directory.resolve()) in message


def test_answers_reached_through_a_symlink_into_a_challenge_directory_are_refused(board, tmp_path):
    directory = challenge(board, "sample-one", spec())
    put(directory / "deep" / "answers.json", json.dumps({"sample-one": sha("t{x}")}))
    (tmp_path / "shortcut").symlink_to(directory / "deep", target_is_directory=True)
    assert "is inside the challenge directory" in board_error(board, answers=tmp_path / "shortcut" / "answers.json")


def test_answers_inside_a_challenge_directory_are_refused_however_the_path_is_cased(board, tmp_path):
    probe = put(tmp_path / "CaseProbe", "x")
    if not (tmp_path / "caseprobe").exists():
        pytest.skip("this file system is case-sensitive, so a differently cased path is another path")
    assert probe.exists()
    directory = challenge(board, "sample-one", spec())
    put(directory / "answers.json", json.dumps({"sample-one": sha("t{x}")}))
    assert "is inside the challenge directory" in board_error(board, answers=board / "SAMPLE-ONE" / "answers.json")


def test_a_symlinked_folder_answers_file_is_refused(board, tmp_path):
    challenge(board, "sample-one", spec())
    (board / "answers.sha256.json").symlink_to(put(tmp_path / "a.json", json.dumps({"sample-one": sha("x")})))
    assert "is a symlink" in board_error(board)


def test_answers_for_challenges_not_on_the_board_are_refused(board):
    challenge(board, "sample-one", spec())
    put(board / "answers.sha256.json", json.dumps({"sample-one": sha("a"), "sample-onw": sha("b"), "gone": sha("c")}))
    assert "answers for challenges that are not on the board: gone, sample-onw" in board_error(board)


BAD_ANSWERS = {
    "not an object": (json.dumps([sha("x")]), "must be a JSON object"),
    "a flag instead of a hash": (json.dumps({"sample-one": "practice{plain_text_flag}"}), "must be the sha256 of its flag"),
    "upper-case hex": (json.dumps({"sample-one": sha("x").upper()}), "must be the sha256 of its flag"),
    "short hex": (json.dumps({"sample-one": sha("x")[:40]}), "must be the sha256 of its flag"),
    "not a string": (json.dumps({"sample-one": 5}), "must be the sha256 of its flag"),
    "bad id": (json.dumps({"Sample One": sha("x")}), '"Sample One" is not a challenge id'),
    "an id twice": ('{"sample-one": "%s", "sample-one": "%s"}' % (sha("a"), sha("b")), 'has the key "sample-one" twice'),
    "bad JSON": ('{"sample-one": ', "is not valid JSON"),
}


@pytest.mark.parametrize("content, problem", BAD_ANSWERS.values(), ids=BAD_ANSWERS.keys())
def test_a_malformed_answers_file_is_refused_without_showing_its_values(board, tmp_path, content, problem):
    challenge(board, "sample-one", spec())
    path = put(tmp_path / "answers.json", content)
    with pytest.raises(BoardError) as caught:
        AnswerVerifier(path)
    message = str(caught.value)
    assert message.startswith(f"{path}: ") and problem in message
    assert "plain_text_flag" not in message and sha("x") not in message.lower()
    assert board_error(board, answers=path) == message.replace(str(path), str(path.resolve()))


# ---------------------------------------------------------------------- on the deck


class Clock:
    def now(self) -> float:
        return 0.0


class Driver:
    """Does no work; records which flags the deck said were wrong."""

    def __init__(self) -> None:
        self.rejected_flags: list[str] = []

    def attach(self, deck): ...
    def start(self, lane, challenge): ...
    def pause(self, lane): ...
    def resume(self, lane): ...
    def hint(self, lane, text): ...
    def redirect(self, lane, text): ...
    def escalate(self, lane, model, summary): ...
    def approved(self, lane, pending): ...
    def declined(self, lane, pending): ...
    def stop(self, lane): ...

    def rejected(self, lane, flag):
        self.rejected_flags.append(flag)


def test_a_loaded_board_plays_on_the_deck_with_its_answers(board):
    challenge(board, "sample-one", spec())
    put(board / "board.json", json.dumps({"event": "Sample Event", "flag_format": r"t\{\w+\}"}))
    put(board / "answers.sha256.json", json.dumps({"sample-one": sha("t{right}")}))
    loaded = load_board(board)
    driver = Driver()
    config = DeckConfig(event=loaded.event, flag_format=loaded.flag_format, models=("m",), submit="confirm")
    deck = Deck(config, driver, Clock(), verify=AnswerVerifier(loaded.answers))
    deck.release([item.challenge for item in loaded.challenges], [QueueEntry("sample-one", "m")])
    (lane,) = deck.lanes_on("sample-one")
    deck.report(lane.id, TurnReport(action="guess", flag="t{wrong}"))
    deck.apply(iv.Approve(lane.id))
    assert driver.rejected_flags == ["t{wrong}"]
    deck.report(lane.id, TurnReport(action="solve", flag="t{right}"))
    assert deck.apply(iv.Approve(lane.id)).ok
    assert deck.challenges["sample-one"].status is ChallengeStatus.SOLVED


def test_the_package_exports_the_board_api():
    for name in platform.__all__:
        assert getattr(platform, name) is getattr(manual, name)
    assert set(platform.__all__) == {"AnswerVerifier", "Board", "BoardChallenge", "BoardError", "cannot_check", "load_board"}


def test_os_errors_while_loading_become_board_errors(board):
    if os.geteuid() == 0:
        pytest.skip("root reads every file, so a permission error cannot be made")
    directory = challenge(board, "sample-one", spec())
    (directory / "challenge.json").chmod(0)
    try:
        assert "cannot read it" in board_error(board)
    finally:
        (directory / "challenge.json").chmod(0o644)
