"""The second layer of redaction (credentials.py): the value of anything shaped like a
credential is taken out, the name stays; flags and ordinary CTF content stay as they are.

Every key here is made up, and each is built from pieces, so no line of this file is shaped
like a real key (the commit guard, .githooks/secret_scan.py, would rightly refuse one)."""

from __future__ import annotations

import pytest

from ctf_flightdeck.credentials import REDACTED, named_flags, redact, redact_data, redact_event_data
from deadline import within

OPENROUTER = "sk-" + "or-v1-" + "5f" * 32
ANTHROPIC = "sk-" + "ant-api03-" + "Qx7-" * 20
PROJECT = "sk-" + "proj-" + "Ab3" * 16
GITHUB = "ghp" + "_" + "a1B2" * 9
GITHUB_PAT = "github" + "_pat_" + "11ABCDEFG" + "_x9" * 20
SLACK_BOT = "xox" + "b-" + "1234-5678-" + "abcd" * 6
SLACK_USER = "xox" + "p-" + "1234-5678-" + "abcd" * 6
AWS_ID = "AK" + "IA" + "IOSFODNN7EXAMPLE"  # AWS's own documentation example
CTFD = "ctfd" + "_" + "0f" * 32
JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.bm90LWEtcmVhbC1zaWduYXR1cmU"
FLAG = "t{AUTH_TOKEN=c0ffee}"  # a flag shaped like a credential is still a flag

TAKEN_OUT = {  # text -> what it becomes
    f"OPENROUTER_API_KEY={OPENROUTER}": "OPENROUTER_API_KEY=[redacted]",
    f'export ANTHROPIC_API_KEY="{ANTHROPIC}"': 'export ANTHROPIC_API_KEY="[redacted]"',
    f"declare -x CTFD_TOKEN='{CTFD}'": "declare -x CTFD_TOKEN='[redacted]'",
    "DB_PASSWORD: hunter2": "DB_PASSWORD: [redacted]",
    "MYSQL_ROOT_PASSWD=hunter2": "MYSQL_ROOT_PASSWD=[redacted]",
    "SESSION_SECRET = s3cr3t": "SESSION_SECRET = [redacted]",
    "SESSION_COOKIE=abc123": "SESSION_COOKIE=[redacted]",
    "BASIC_AUTH=player:hunter2": "BASIC_AUTH=[redacted]",
    "KEY=0x4142": "KEY=[redacted]",  # the brief's rule: an upper-case NAME that holds KEY
    '{"GITHUB_TOKEN": "abc123", "PATH": "/usr/bin"}': '{"GITHUB_TOKEN": "[redacted]", "PATH": "/usr/bin"}',
    "{'AWS_SECRET_ACCESS_KEY': 'wJalrXUtnFEMI'}": "{'AWS_SECRET_ACCESS_KEY': '[redacted]'}",
    "https://127.0.0.1/api?API_KEY=abc123&page=2": "https://127.0.0.1/api?API_KEY=[redacted]&page=2",
    "PASSWD=$'two words'": "PASSWD='[redacted]'",
    'SECRET="cut short by a tool…': 'SECRET="[redacted]"',  # no closing quote: still taken out
    "it was SECRET=hunter2.": "it was SECRET=[redacted].",  # the sentence's full stop is no part of it
    "export OPENROUTER_API_KEY := hunter2hunter2": "export OPENROUTER_API_KEY := [redacted]",  # a Makefile's
    "API_KEY:=hunter2": "API_KEY:=[redacted]",
    "API_KEY ::= hunter2": "API_KEY ::= [redacted]",
    "API_KEY ?= hunter2": "API_KEY ?= [redacted]",
    "API_KEY += hunter2": "API_KEY += [redacted]",
    "X-API-KEY: hunter2hunter2": "X-API-KEY: [redacted]",
    f"curl -H 'Authorization: Bearer {JWT}' http://127.0.0.1:8080/admin": (
        "curl -H 'Authorization: Bearer [redacted]' http://127.0.0.1:8080/admin"
    ),
    "> authorization: Token " + "ab" * 20: "> authorization: Token [redacted]",
    "Proxy-Authorization: Basic " + "cGxheWVyOmh1bnRlcjI=": "Proxy-Authorization: Basic [redacted]",  # player:hunter2
    f"AUTHORIZATION: {OPENROUTER}": "AUTHORIZATION: [redacted]",
    "Cookie: session=abc123; theme=dark": "Cookie: [redacted]",
    "Cookie: \t session=abc123 \t ": "Cookie: \t [redacted] \t ",  # the blanks around a value stay
    f"authorization:\t\tBearer\t\t{JWT}": "authorization:\t\tBearer\t\t[redacted]",
    'requests.get(url, headers={"Cookie": "session=abc123"})': 'requests.get(url, headers={"Cookie": "[redacted]"})',
    f"the key is {ANTHROPIC}, see": "the key is sk-ant-[redacted], see",
    f"router {OPENROUTER}": "router sk-or-[redacted]",
    f"openai {PROJECT}": "openai sk-proj-[redacted]",
    f"git {GITHUB}": "git ghp_[redacted]",
    f"git {GITHUB_PAT}": "git github_pat_[redacted]",
    f"slack {SLACK_BOT} {SLACK_USER}": "slack xoxb-[redacted] xoxp-[redacted]",
    f"aws {AWS_ID} us-east-1": "aws AKIA[redacted] us-east-1",
    f"ctfd {CTFD}.": "ctfd ctfd_[redacted].",
}

STAYS = [  # ordinary CTF content: no credential's name in front of it, no credential's prefix
    f"token: {JWT}",  # a JWT the lane forged, under a lower-case name
    '{"alg":"HS256","typ":"JWT"}',
    f"jwt.decode('{JWT}', options={{'verify_signature': False}})",
    "secret_key = 'changeme'",
    "password: hunter2",  # a password the lane found in the challenge
    "key = bytes.fromhex('4142')  # the XOR key",
    "00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............",
    "00000010: 4b45 5953 2061 7265 2068 6572 6521 0a00  KEYS are here!..",
    "0000000 457f 464c 0102 0001 0000 0000 0000 0000",
    "DEADBEEF CAFEBABE 0123456789ABCDEF " * 3,
    "c2stYW50LWFwaTAzLWZha2Uta2V5LWZvci10ZXN0cw==",
    "< Set-Cookie: session=abc123; Path=/; HttpOnly",  # what the challenge's server sent
    'document.cookie = "admin=true"',
    "curl -b 'session=abc123' --cookie 'a=b' http://127.0.0.1:8080/",
    "if KEY == 3: print(KEY)",
    "assert TOKEN != other and KEY <= 3 and AUTH >= 1",  # comparisons, not assignments
    "std::KEY::value",
    "os.environ['ANTHROPIC_API_KEY']",  # names the variable, holds no value
    "ANTHROPIC_API_KEY=",
    "ANTHROPIC_API_KEY :=",  # a Makefile's, with no value: its = is no value either
    "TOKEN=[ANTHROPIC_API_KEY]",  # taken out already, by the first layer
    "Authorization: Bearer [OPENROUTER_API_KEY]",
    "API_KEY=[redacted]",
    "sk-learn, task-or-other, ghp_x, AKIA1234, ctfd_cli.py",  # too short, or no prefix at all
    "Cookie:" + " " * 40,  # a header's name with nothing after it but blanks
    "Authorization:\t\t\t\nnext line",
    "cookie:   '",
    "KEY: \t \t",
]


@pytest.mark.parametrize("text", list(TAKEN_OUT))
def test_a_credentials_value_is_taken_out_and_its_name_stays(text):
    shown = redact(text)
    assert shown == TAKEN_OUT[text]
    assert REDACTED in shown and redact(shown) == shown  # a second pass changes nothing


@pytest.mark.parametrize("text", STAYS)
def test_ordinary_ctf_content_stays_as_it_is(text):
    assert redact(text) == text


def test_every_line_of_a_dump_is_looked_at_and_the_rest_stays():
    env = (
        "HOME=/home/player\n"
        f"OPENROUTER_API_KEY={OPENROUTER}\n"
        "TERM=xterm-256color\n"
        f"GITHUB_TOKEN={GITHUB}\n"
        f"token: {JWT}\n"
    )
    assert redact(env) == (
        "HOME=/home/player\nOPENROUTER_API_KEY=[redacted]\nTERM=xterm-256color\nGITHUB_TOKEN=[redacted]\n"
        f"token: {JWT}\n"
    )


def test_a_flag_is_never_taken_for_a_credential():
    text = f"the note says {FLAG}\nSECRET={FLAG}\nOTHER_SECRET=abc123 {FLAG}\nsubmitted {FLAG}: correct"
    assert redact(text, keep=[FLAG]) == (
        f"the note says {FLAG}\nSECRET={FLAG}\nOTHER_SECRET=[redacted] {FLAG}\nsubmitted {FLAG}: correct"
    )
    assert redact(text) == (  # what keep is for
        "the note says t{AUTH_TOKEN=[redacted]\nSECRET=[redacted]\nOTHER_SECRET=[redacted] t{AUTH_TOKEN=[redacted]\n"
        "submitted t{AUTH_TOKEN=[redacted]: correct"
    )


def test_a_kept_string_never_shields_a_credential_it_is_only_part_of():
    assert redact(f"OPENROUTER_API_KEY={OPENROUTER}", keep=["5f5f", "sk-or-"]) == "OPENROUTER_API_KEY=[redacted]"
    assert redact(f"key {OPENROUTER}", keep=["5f"]) == "key sk-or-[redacted]"


def test_every_string_in_an_events_data_is_redacted_and_the_rest_stays():
    """The run log's data (redact_data): strings at any depth, in dicts and lists, lose their
    credentials' values as redact() takes them out; the keys, numbers, booleans and None stay,
    and so does a flag in `keep`, in the text and as a value of its own."""
    data = {
        "action": f"curl -H 'Authorization: Bearer {JWT}' http://127.0.0.1:8080/",
        "API_KEY=x": f"KEY={OPENROUTER}",  # a key is a field name of flightdeck's, never a value
        "flag": FLAG,
        "nested": [{"reason": f"the same output twice: GITHUB_TOKEN={GITHUB}", "turn": 3}, [f"aws {AWS_ID}", None]],
        "tokens": 1200, "dollars": 0.5, "correct": True, "detail": None,
        "said": f"submitted {FLAG}: correct, and ANTHROPIC_API_KEY={ANTHROPIC}",
    }
    assert redact_data(data, keep=[FLAG]) == {
        "action": "curl -H 'Authorization: Bearer [redacted]' http://127.0.0.1:8080/",
        "API_KEY=x": "KEY=[redacted]",
        "flag": FLAG,
        "nested": [{"reason": "the same output twice: GITHUB_TOKEN=[redacted]", "turn": 3}, ["aws AKIA[redacted]", None]],
        "tokens": 1200, "dollars": 0.5, "correct": True, "detail": None,
        "said": f"submitted {FLAG}: correct, and ANTHROPIC_API_KEY=[redacted]",
    }
    assert redact_data(f"plain {CTFD}") == "plain ctfd_[redacted]"
    assert redact_data(7) == 7 and redact_data(None) is None


@pytest.mark.parametrize("data, flags", [
    ({"flag": FLAG, "correct": True}, [FLAG]),  # a submit, or a candidate waiting for the player
    ({"engine": "strings", "flags": ["t{a}", "", 3, "t{b}"]}, ["t{a}", "t{b}"]),  # an L1 result
    ({"flag": "t{a}", "flags": ("t{b}",)}, ["t{a}", "t{b}"]),
    ({"flag": None, "kind": "budget"}, []),  # a budget approval names no flag
    ({"flag": 3, "flags": "t{a}"}, []),  # values of the wrong type name none
    ({}, []),
    (None, []),
])
def test_the_flags_an_event_names_are_its_flag_and_its_flags(data, flags):
    assert named_flags(data) == flags


def test_an_events_fields_that_name_challenges_stay_as_they_are():
    """A deck event's own fields that name challenges come from the board (a release's ids
    and board, the challenge a claim names, the challenges a warning lists as solved), and an
    id or a name can look like a credential: they stay as they are. Every other string loses
    its credentials' values as redact_data() takes them out, the same names further in too."""
    slug = "xox" + "b-slack-bot"
    board = [{"id": slug, "name": "Fortune Cookie: Part 2", "category": "web", "points": 50}]
    data = {
        "challenges": [slug, "c2"], "board": board, "challenge": slug, "solved": [slug],
        "text": f"use GITHUB_TOKEN={GITHUB}", "found": {"challenge": slug}, "turn": 3,
    }
    assert redact_event_data(data) == {
        "challenges": [slug, "c2"], "board": board, "challenge": slug, "solved": [slug],
        "text": "use GITHUB_TOKEN=[redacted]", "found": {"challenge": "xoxb-[redacted]"}, "turn": 3,
    }
    assert redact_data(data)["challenges"] == ["xoxb-[redacted]", "c2"]  # what each would be, were it not a name
    assert redact_data(board)[0]["name"] == "Fortune Cookie: [redacted]"
    assert redact_event_data(f"plain {CTFD}") == "plain ctfd_[redacted]"


LONG_RUNS = {  # shape -> (before, unit, after): the unit repeated to a megabyte between the two
    "one letter": ("", "A", ""),
    "a name's letters": ("", "KEY_", ""),
    "assignments": ("", "a=", ""),
    "prefixes": ("", "sk-or-", ""),
    "a header's value": ("Authorization: ", "x", ""),
    "a value of dots": ("KEY=", ".", ""),
    # a name and its colon (or =), then nothing but blanks to the end of the line: no value
    # to take out, and a pattern that gave the blanks back one at a time, each time scanning
    # the rest of the line again for a value, took hours over a megabyte
    "Cookie: then spaces": ("Cookie:", " ", ""),
    "Authorization: then tabs and a newline": ("Authorization:", "\t", "\nx"),
    "a scheme then spaces": ("Authorization: Bearer", " ", ""),
    "a colon, spaces and a quote": ("cookie:", " ", '"'),
    "a colon, a quote and spaces": ("Cookie: '", " ", ""),
    "a header's name and spaces, no colon": ("Cookie", " ", "x"),
    "KEY: then spaces": ("KEY:", " ", ""),
    "KEY := then tabs": ("API_KEY :=", "\t", "\n"),
}


@pytest.mark.parametrize("shape", list(LONG_RUNS))
def test_long_runs_of_text_cost_linear_time(shape):
    """Hostile text reaches redact whole: a 64 KB file's diff in a lane's transcript, which is
    written while the deck handles the approval that ended the lane, and every file a draft
    shows. A megabyte of each shape is taken in well under the deadline."""
    before, unit, after = LONG_RUNS[shape]
    text = before + unit * (1_000_000 // len(unit)) + after
    with within(10, f"taking credentials out of a megabyte of {shape}"):
        redact(text, keep=["t{x}"])
