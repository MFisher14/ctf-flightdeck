"""The notification webhook (notify.py), against a receiver on 127.0.0.1 (fake_webhook.py):
real HTTP, nothing mocked. The deck is real (test_deck's recording driver and verifier stand
in for lane work and the platform), and so is the run in the end-to-end tests (fake model
server, host lanes in tmp_path)."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import pytest

from ctf_flightdeck import __version__
from ctf_flightdeck.config import (
    NOTIFY_KINDS,
    ConfigError,
    NotifyConfig,
    example_config,
    load_config,
    webhook_url,
)
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Alert, AlertKind, EventKind, Pending, PendingKind
from ctf_flightdeck.notify import MAX_TEXT, Notifier, NotifyError
from ctf_flightdeck.run import RunError, RunOptions, prepare_run

from fake_model import FakeModelServer, text_reply, tool_call_reply
from fake_webhook import SECRET_PATH, FakeWebhook
from test_deck import good_flag, make_deck
from test_run import FLAG, board
from test_run import config as run_config

ENV = "FLIGHTDECK_TEST_WEBHOOK"
RUN = "20261112-101500"
TOKEN_PARTS = ("T0PSECRET", "webhook-token-of-the-test")  # what the URL holds besides its host


def base(kind: str, **fields) -> dict:
    """The documented message: exactly these nine fields."""
    return {"flightdeck": __version__, "format": 1, "run": RUN, "event": "test", "kind": kind, "lane": None,
            "challenge": None, "need": None, "text": "", **fields}


async def until(cond, what: str, seconds: float = 10.0) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if cond():
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"{what}: not within {seconds} s")


def warnings(deck) -> list[str]:
    return [event.text for event in deck.events if event.kind is EventKind.WARNING and event.data.get("source") == "notify"]


def play(hook: FakeWebhook, deck, script, *, expect: int | None = None, **kwargs) -> Notifier:
    """A notifier for `deck` flying on a loop of its own while `script(deck, notifier)` plays
    (a coroutine function, on the deck's thread); then it waits for `expect` messages, if
    given, and closes the notifier."""
    notifier = Notifier(hook.url, deck, run=RUN, env=ENV, **kwargs)

    async def main() -> None:
        notifier.attach()
        notifier.start()
        try:
            await script(deck, notifier)
            if expect is not None:
                await until(lambda: len(hook.bodies()) >= expect, f"{expect} message(s) at the webhook")
        finally:
            await notifier.aclose()

    asyncio.run(main())
    return notifier


# ---------------------------------------------------------------------- what is sent


def test_a_flag_the_board_accepts_is_one_message_that_never_holds_the_flag():
    deck, _, _ = make_deck(n=2, max_lanes=2, submit="auto")

    async def script(deck, notifier) -> None:
        deck.report("L01", TurnReport(action="solve.py", flag=good_flag("c0")))  # auto submit: accepted at once

    with FakeWebhook() as hook:
        play(hook, deck, script, expect=1)
        assert hook.bodies() == [base("flag", lane="L01", challenge={"id": "c0", "name": "Chall 0"},
                                      text="L01 solved Chall 0: its flag was accepted")]
        (request,) = hook.requests
    assert (request["method"], request["path"]) == ("POST", SECRET_PATH)
    assert request["headers"]["content-type"] == "application/json"
    assert request["headers"]["user-agent"] == f"ctf-flightdeck/{__version__}"
    assert "t{c0}" not in json.dumps(request["json"])


def test_a_flag_that_waits_is_one_needs_you_message_without_the_flag_and_its_approval_one_flag_message():
    deck, _, _ = make_deck(n=1, max_lanes=1)

    async def script(deck, notifier) -> None:
        deck.report("L01", TurnReport(action="solve.py", flag=good_flag("c0")))  # the flag alert and the approval
        await until(lambda: len(hook.bodies()) == 1, "the needs-you message")
        assert deck.apply(iv.Approve("L01")).ok

    with FakeWebhook() as hook:
        play(hook, deck, script, expect=2)
        bodies = hook.bodies()
    challenge = {"id": "c0", "name": "Chall 0"}
    assert bodies == [
        base("needs-you", lane="L01", challenge=challenge, need="submit",
             text="L01 has a flag for Chall 0: it waits for your approval"),
        base("flag", lane="L01", challenge=challenge, text="L01 solved Chall 0: its flag was accepted"),
    ]
    assert "t{c0}" not in json.dumps(bodies)


def test_an_alert_and_an_approval_that_is_no_flag_say_what_the_lane_needs():
    deck, _, _ = make_deck(n=2, max_lanes=2)

    async def script(deck, notifier) -> None:
        deck.report("L01", TurnReport(action="./brute.sh", alerts=(Alert(AlertKind.LOOP, "ran ./brute.sh 6 times"),)))
        deck.report("L02", TurnReport(action="nc", pending=Pending(PendingKind.LIVE_BOX, "reach the live box at 10.0.0.5")))

    with FakeWebhook() as hook:
        play(hook, deck, script, expect=2)
        bodies = hook.bodies()
    assert bodies == [
        base("needs-you", lane="L01", challenge={"id": "c0", "name": "Chall 0"}, need="loop",
             text="L01 on Chall 0: Loop: ran ./brute.sh 6 times"),
        base("needs-you", lane="L02", challenge={"id": "c1", "name": "Chall 1"}, need="live box",
             text="L02 on Chall 1 waits for your approval (live box): reach the live box at 10.0.0.5"),
    ]


def test_a_held_queue_and_an_autopilot_that_disengages_are_disengaged_messages():
    deck, _, _ = make_deck(n=3, max_lanes=1)

    async def script(deck, notifier) -> None:
        deck.hold_queue("the model API refuses the key")
        deck.warn("autopilot is off", data={"autopilot": "disengaged", "reason": "the run budget of $20 is spent"})

    with FakeWebhook() as hook:
        play(hook, deck, script, expect=2)
        bodies = hook.bodies()
    assert bodies == [
        base("disengaged", text="no more lanes start: the model API refuses the key"),
        base("disengaged", text="autopilot disengaged: the run budget of $20 is spent"),
    ]


def test_what_is_no_news_is_not_sent():
    """A wrong flag, the player's own word for a hand submit, an informational alert, a lane
    that ends, a lifted hold and any other warning: nothing. The one message is the last."""
    deck, _, _ = make_deck(n=3, max_lanes=3, team=True)

    async def script(deck, notifier) -> None:
        deck.report("L01", TurnReport(action="a", flag="t{wrong}"))
        assert deck.apply(iv.Approve("L01")).ok  # submitted: incorrect
        deck.report("L02", TurnReport(action="b", pending=Pending(PendingKind.CONFIRM, "submit t{c1} by hand", flag="t{c1}")))
        assert deck.apply(iv.Approve("L02")).ok  # the player says it was accepted: they were there
        deck.report("L03", TurnReport(action="c", alerts=(Alert(AlertKind.TEAMMATE, "bob holds the live box"),)))
        deck.report("L03", TurnReport(action="d", gave_up="no idea"))
        deck.warn("the team folder is not mounted")
        deck.hold_queue("x")
        assert deck.release_hold().ok
        deck.warn("last", data={"autopilot": "disengaged", "reason": "done"})

    with FakeWebhook() as hook:
        play(hook, deck, script, expect=2, on=("flag", "disengaged"))  # needs-you is off: its messages are tested above
        kinds = [(body["kind"], body["text"]) for body in hook.bodies()]
    assert kinds == [("disengaged", "no more lanes start: x"), ("disengaged", "autopilot disengaged: done")]
    submits = [(e.data["correct"], e.data["by"]) for e in deck.events if e.kind is EventKind.SUBMIT]
    assert submits == [(False, "platform"), (True, "player")]  # both happened, and neither is a flag message


def test_on_chooses_the_kinds_that_are_sent():
    deck, _, _ = make_deck(n=2, max_lanes=2)

    async def script(deck, notifier) -> None:
        deck.report("L01", TurnReport(action="a", flag=good_flag("c0")))  # needs-you: not in `on`
        deck.hold_queue("x")  # disengaged: not in `on`
        assert deck.apply(iv.Approve("L01")).ok  # flag

    with FakeWebhook() as hook:
        play(hook, deck, script, expect=1, on=("flag",))
        assert [body["kind"] for body in hook.bodies()] == ["flag"]
    with pytest.raises(NotifyError, match="unknown notification kind 'everything'"):
        Notifier("http://127.0.0.1:9/x", deck, run=RUN, on=("everything",))


def test_text_from_a_lane_has_no_secret_no_credential_no_flag_no_control_character_and_is_cut():
    api_key = "the-api-key-of-this-run-" + "a" * 16
    bearer = "bearer-token-value-" + "b" * 20
    deck, _, _ = make_deck(n=2, max_lanes=2)
    deck.challenges["c1"].name = "Note\x1b]0;pwned\x07"

    async def script(deck, notifier) -> None:
        deck.report("L01", TurnReport(action="x", alerts=(Alert(
            AlertKind.LOOP, f"ran curl -H 'Authorization: Bearer {bearer}' {hook.url} with {api_key}\nand printed t{{c0}} 6 times"),)))
        deck.report("L02", TurnReport(action="y", alerts=(Alert(AlertKind.STALL, "quiet for " + "z" * 500),)))

    with FakeWebhook() as hook:
        play(hook, deck, script, expect=2, held={"FLIGHTDECK_TEST_API_KEY": api_key})
        first, second = hook.bodies()
    assert first["text"] == (f"L01 on Chall 0: Loop: ran curl -H 'Authorization: Bearer [redacted]' [{ENV}] with "
                             "[FLIGHTDECK_TEST_API_KEY] ⏎ and printed [flag] 6 times")
    assert second["challenge"] == {"id": "c1", "name": "Note^[]0;pwned^G"}
    assert second["text"].startswith("L02 on Note^[]0;pwned^G: Stall: quiet for zzz")
    assert len(second["text"]) == MAX_TEXT and second["text"].endswith("...")


def guide_section(title: str) -> str:
    """The text of docs/GUIDE.md under the heading `title`, up to the next heading of its level or above."""
    text = (Path(__file__).resolve().parent.parent / "docs" / "GUIDE.md").read_text(encoding="utf-8")
    level, _, _ = title.partition(" ")
    start = text.index(f"\n{title}\n") + len(title) + 2
    ends = [text.find(f"\n{'#' * n} ", start) for n in range(1, len(level) + 1)]
    return text[start:min([end for end in ends if end != -1], default=len(text))]


def test_the_guide_documents_exactly_the_message_that_is_sent():
    """The issue's last clause: the docs say exactly what is sent. The guide's example body
    and its table of fields have the fields of a real message, in its order, and no other;
    every kind and every need the code can send is named."""
    section = guide_section("### Notifications")
    example = json.loads(section[section.index("```json") + len("```json"):section.index("```", section.index("```json") + 7)])
    deck, _, _ = make_deck(n=1, max_lanes=1)
    notifier = Notifier("http://127.0.0.1:9/x", deck, run=RUN)
    deck.report("L01", TurnReport(action="solve.py", flag=good_flag("c0")))
    message = notifier.message(next(e for e in deck.events if e.kind is EventKind.PENDING))
    assert list(example) == list(message)
    assert {key: type(value) for key, value in example.items()} == {key: type(value) for key, value in message.items()}
    assert (example["format"], example["kind"], example["need"]) == (message["format"], message["kind"], message["need"])
    assert example["text"] == message["text"].replace("L01", "L03").replace("Chall 0", "Crab Walk")
    rows = [line.split("|")[1].strip().strip("`") for line in section.splitlines() if line.startswith("| `")]
    assert rows[:len(message)] == list(message)  # the table of fields
    assert rows[len(message):] == ["kind", *NOTIFY_KINDS]  # the table of kinds, under its heading row
    needs = {kind.value for kind in PendingKind} | {kind.value for kind in AlertKind} - {"flag", "teammate"}
    need_row = next(line for line in section.splitlines() if line.startswith("| `need` |"))
    assert {word for word in needs} == set(need_row.split("`")[3::2]) - {"needs-you"}, need_row
    for claim in ("**A flag's value is never sent.**", "User-Agent: ctf-flightdeck/VERSION", "at most 200 characters",
                  "five seconds", "at most 32 wait", "a redirect is not followed", "At most one a minute for each lane and need"):
        assert claim in section, claim
    assert (MAX_TEXT, notifier.timeout, notifier.rate_seconds, notifier._queue.maxsize) == (200, 5.0, 60.0, 32)


# ---------------------------------------------------------------------- a noisy lane, a bad receiver


def test_a_noisy_lane_is_one_message_a_minute_for_each_need():
    deck, _, _ = make_deck(n=2, max_lanes=2)
    now = [100.0]

    def loop(lane: str, n: int) -> None:  # the alert is new each time: the player dismissed the last
        deck.report(lane, TurnReport(action="x", alerts=(Alert(AlertKind.LOOP, f"round {n}"),)))
        assert deck.apply(iv.Dismiss(lane)).ok

    async def script(deck, notifier) -> None:
        loop("L01", 1)  # sent
        now[0] += 59
        loop("L01", 2)  # within the minute: not sent
        loop("L02", 3)  # another lane: sent
        deck.report("L01", TurnReport(action="y", alerts=(Alert(AlertKind.STALL, "quiet"),)))  # another need: sent
        now[0] += 1.5
        loop("L01", 4)  # the minute is over: sent

    with FakeWebhook() as hook:
        play(hook, deck, script, expect=4, clock=lambda: now[0])
        sent = [(body["lane"], body["need"], body["text"].rsplit(": ", 1)[1]) for body in hook.bodies()]
    assert sent == [("L01", "loop", "round 1"), ("L02", "loop", "round 3"), ("L01", "stall", "quiet"), ("L01", "loop", "round 4")]
    assert len([e for e in deck.events if e.kind is EventKind.ALERT]) == 5  # the deck raised all five


@pytest.mark.parametrize("status", [500, 404])
def test_a_receiver_that_fails_is_one_warning_without_the_url_and_the_run_goes_on(status):
    deck, _, _ = make_deck(n=3, max_lanes=3)

    async def script(deck, notifier) -> None:
        for lane in ("L01", "L02", "L03"):
            deck.report(lane, TurnReport(action="x", alerts=(Alert(AlertKind.LOOP, "again"),)))
        await until(lambda: len(hook.bodies()) == 3, "the three tries")

    with FakeWebhook(status=status) as hook:
        notifier = play(hook, deck, script)
        assert len(hook.bodies()) == 3  # each sent once: nothing is sent again
    assert warnings(deck) == [
        f"a notification could not be sent to the webhook (the variable {ENV}): it answered HTTP {status}; the run goes on, "
        "and flightdeck does not send it again"
    ]
    assert notifier.sent == 0 and deck.listener_errors == []
    assert all(lane.turns == 1 for lane in deck.lanes.values())
    said = json.dumps([[e.text, dict(e.data)] for e in deck.events]) + repr(notifier)
    assert str(hook.port) not in said and all(part not in said for part in TOKEN_PARTS)


def test_a_receiver_that_never_answers_is_one_warning_and_never_holds_up_the_deck():
    deck, _, _ = make_deck(n=3, max_lanes=3)
    slowest = [0.0]

    async def script(deck, notifier) -> None:
        for lane in ("L01", "L02", "L03"):
            began = time.monotonic()
            deck.report(lane, TurnReport(action="x", alerts=(Alert(AlertKind.LOOP, "again"),)))
            slowest[0] = max(slowest[0], time.monotonic() - began)
            await asyncio.sleep(0)
        await until(lambda: len(warnings(deck)) >= 1 and len(hook.bodies()) == 3, "the tries to time out")

    with FakeWebhook(hang=True) as hook:
        play(hook, deck, script, timeout=0.3)
    assert slowest[0] < 0.1, f"a report waited {slowest[0]:.2f} s on the webhook"
    assert warnings(deck) == [
        f"a notification could not be sent to the webhook (the variable {ENV}): no answer within 0.3 s; the run goes on, "
        "and flightdeck does not send it again"
    ]


def test_a_full_queue_drops_the_message_and_says_so_once():
    deck, _, _ = make_deck(n=6, max_lanes=6)

    async def script(deck, notifier) -> None:
        deck.report("L01", TurnReport(action="x", alerts=(Alert(AlertKind.LOOP, "again"),)))
        await until(lambda: len(hook.requests) == 1, "the first message at the receiver, which holds it")
        for lane in ("L02", "L03", "L04", "L05"):  # two fit on the queue; two are dropped
            deck.report(lane, TurnReport(action="x", alerts=(Alert(AlertKind.LOOP, "again"),)))
        assert notifier.dropped == 2
        hook.release()

    with FakeWebhook(hang=True) as hook:
        notifier = play(hook, deck, script, expect=3, queue=2, timeout=5.0)
        assert [body["lane"] for body in hook.bodies()] == ["L01", "L02", "L03"]
    assert warnings(deck) == [
        f"a notification was dropped: 2 already wait to be sent to the webhook (the variable {ENV}); flightdeck says this once"
    ]
    assert notifier.sent == 3


def test_a_redirect_is_not_followed_and_is_said():
    deck, _, _ = make_deck(n=1, max_lanes=1)

    async def script(deck, notifier) -> None:
        deck.hold_queue("x")
        await until(lambda: warnings(deck), "the warning")

    with FakeWebhook() as elsewhere, FakeWebhook(status=302, location=elsewhere.url) as hook:
        play(hook, deck, script)
        assert len(hook.bodies()) == 1 and elsewhere.requests == []
    (warning,) = warnings(deck)
    assert "it answered HTTP 302, a redirect, which flightdeck does not follow" in warning
    assert str(elsewhere.port) not in warning and SECRET_PATH not in warning


def test_a_failure_is_said_again_once_a_message_went_through_in_between():
    deck, _, _ = make_deck(n=3, max_lanes=3)

    async def script(deck, notifier) -> None:
        for n, status in enumerate((500, 500, 204, 500), 1):
            hook.status = status
            deck.warn(f"news {n}", data={"autopilot": "disengaged", "reason": f"news {n}"})
            await until(lambda: len(hook.bodies()) == n, f"message {n}")
            await asyncio.sleep(0.05)  # its answer is back

    with FakeWebhook() as hook:
        notifier = play(hook, deck, script)
    assert len(warnings(deck)) == 2 and notifier.sent == 1


def test_a_receiver_that_is_not_there_is_a_warning_that_names_no_host():
    deck, _, _ = make_deck(n=3, max_lanes=3)
    with FakeWebhook() as hook:
        pass  # stopped: nothing listens on its port now

    async def script(deck, notifier) -> None:
        deck.hold_queue("x")
        await until(lambda: warnings(deck), "the warning")

    notifier = play(hook, deck, script, timeout=2.0)
    (warning,) = warnings(deck)
    assert "the request failed (ConnectError)" in warning
    assert "127.0.0.1" not in warning and str(hook.port) not in warning and all(part not in warning for part in TOKEN_PARTS)
    assert notifier.sent == 0


def test_what_is_queued_when_the_run_shuts_down_is_still_sent():
    deck, _, _ = make_deck(n=1, max_lanes=1)

    async def script(deck, notifier) -> None:
        deck.hold_queue("the last thing the run had to say")  # no await after it: aclose comes next

    with FakeWebhook() as hook:
        notifier = play(hook, deck, script)
        assert [body["text"] for body in hook.bodies()] == ["no more lanes start: the last thing the run had to say"]
    assert notifier.sent == 1
    deck.hold_queue("y")  # closed: it follows the deck no more


@pytest.mark.parametrize("url", ["ftp://127.0.0.1/hook-secret-0451", "file:///etc/hook-secret-0451", "hook-secret-0451", "http://"])
def test_only_http_and_https_urls_are_used_and_a_bad_one_is_never_shown(url):
    deck, _, _ = make_deck(n=1, max_lanes=1)
    with pytest.raises(NotifyError) as caught:
        Notifier(url, deck, run=RUN, env=ENV)
    assert str(caught.value) == "the notification webhook is not an http:// or https:// URL (it is not shown: it is a secret)"


# ---------------------------------------------------------------------- the config


LADDER = '[models]\nladder = ["vendor/small", "vendor/big"]\n'


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    return path


def error(path: Path) -> str:
    with pytest.raises(ConfigError) as caught:
        load_config(path)
    return str(caught.value)


def test_no_notify_table_is_no_webhook_and_a_table_names_the_variable_and_the_kinds(tmp_path, monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    plain = load_config(write(tmp_path, LADDER))
    assert plain.notify == NotifyConfig() and plain.notify.webhook_env == "" and plain.notify.on == NOTIFY_KINDS
    assert webhook_url(plain) is None
    named = load_config(write(tmp_path, LADDER + f'[notify]\nwebhook_env = "{ENV}"\non = ["disengaged", "flag"]\n'))
    assert named.notify == NotifyConfig(webhook_env=ENV, on=("flag", "disengaged"))
    monkeypatch.setenv(ENV, "  https://hooks.example.test/services/abc  ")
    assert webhook_url(named) == "https://hooks.example.test/services/abc"


@pytest.mark.parametrize("value", ['"https://hooks.example.test/services/T0/secret-0451"', '"lower_case"', "7", '["A"]'])
def test_a_url_or_anything_else_that_is_no_variable_name_in_webhook_env_names_the_key_and_never_the_value(tmp_path, value):
    message = error(write(tmp_path, LADDER + f"[notify]\nwebhook_env = {value}\n"))
    assert message == (
        f"{tmp_path / 'config.toml'}: notify.webhook_env must be the name of an environment variable, like "
        "FLIGHTDECK_WEBHOOK (upper-case letters, digits and _, not starting with a digit, at most 64 characters), not the "
        "webhook's URL itself: the URL is a secret, so it goes in that variable (or in the keys file), never in the config"
    )
    assert "secret-0451" not in message and "lower_case" not in message


@pytest.mark.parametrize("table, problem", [
    ('on = ["flag", "everything"]', 'notify.on lists something that is not one of "flag", "needs-you", "disengaged"'),
    ("on = []", 'notify.on must be a list of one or more of "flag", "needs-you", "disengaged" (got a list)'),
    ('on = "flag"', 'notify.on must be a list of one or more of "flag", "needs-you", "disengaged" (got a string)'),
    ('on = ["flag", "flag"]', "notify.on lists a kind twice"),
    ("on = [1]", 'notify.on lists something that is not one of "flag", "needs-you", "disengaged"'),
    ('url = "x"', "unknown key notify.url (known in notify: webhook_env, on)"),
])
def test_a_bad_notify_table_names_its_key(tmp_path, table, problem):
    assert error(write(tmp_path, LADDER + f"[notify]\n{table}\n")) == f"{tmp_path / 'config.toml'}: {problem}"


def test_a_variable_that_is_named_and_not_set_or_holds_no_http_url_is_an_error_that_never_shows_it(tmp_path, monkeypatch):
    config = load_config(write(tmp_path, LADDER + f'[notify]\nwebhook_env = "{ENV}"\n'))
    monkeypatch.delenv(ENV, raising=False)
    with pytest.raises(ConfigError, match=f"notify.webhook_env names the variable {ENV}, which is not set: put {ENV}=<the "
                                          "webhook's URL> in .*keys.env \\(chmod 600\\), or export it, or remove webhook_env"):
        webhook_url(config)
    for bad in ("ftp://hooks.example.test/secret-0451", "hooks.example.test/secret-0451", "https:///secret-0451",
                "https://hooks.example.test/secret 0451", "https://hooks.example.test:port/secret-0451"):
        monkeypatch.setenv(ENV, bad)
        with pytest.raises(ConfigError) as caught:
            webhook_url(config)
        assert str(caught.value) == (
            f"{tmp_path / 'config.toml'}: the variable {ENV} (notify.webhook_env) does not hold an http:// or https:// URL "
            "(it is not shown: a webhook's URL is a secret)."
        )


def test_the_url_is_read_from_the_keys_file_too_and_the_environment_wins(tmp_path, monkeypatch):
    keys = tmp_path / "keys.env"
    keys.write_text(f"{ENV}=https://hooks.example.test/from-the-keys-file\n")
    keys.chmod(0o600)
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(keys))
    monkeypatch.delenv(ENV, raising=False)
    config = load_config(write(tmp_path, LADDER + f'[notify]\nwebhook_env = "{ENV}"\n'))
    assert webhook_url(config) == "https://hooks.example.test/from-the-keys-file"
    monkeypatch.setenv(ENV, "https://hooks.example.test/from-the-environment")
    assert webhook_url(config) == "https://hooks.example.test/from-the-environment"


def test_the_example_shows_notify_with_nothing_turned_on_and_its_lines_load_once_uncommented(tmp_path):
    text = example_config()
    assert "\n[notify]\n" in text
    for line in ('# webhook_env = "FLIGHTDECK_WEBHOOK"', '# on = ["flag", "needs-you", "disengaged"]'):
        assert f"\n{line}\n" in text, line
    running = " ".join(line.lstrip("# ") for line in text.splitlines())  # comments as running text
    for words in ("a webhook's URL is a secret, so it never goes in this file", "it never holds a flag",
                  "at most one a minute for each lane and need", "No webhook_env: nothing is sent."):
        assert words in running, words
    filled = text.replace("ladder = []", 'ladder = ["vendor/small-model", "vendor/big-model"]')
    assert load_config(write(tmp_path, filled)).notify == NotifyConfig()
    on = filled.replace('# webhook_env = "FLIGHTDECK_WEBHOOK"', 'webhook_env = "FLIGHTDECK_WEBHOOK"').replace(
        '# on = ["flag", "needs-you", "disengaged"]', 'on = ["flag", "needs-you", "disengaged"]')
    assert load_config(write(tmp_path, on)).notify == NotifyConfig(webhook_env="FLIGHTDECK_WEBHOOK", on=NOTIFY_KINDS)


# ---------------------------------------------------------------------- a run


def with_notify(cfg: Path, on: str = "") -> Path:
    cfg.write_text(cfg.read_text() + f'[notify]\nwebhook_env = "{ENV}"\n{on}')
    return cfg


def test_a_run_whose_webhook_variable_is_not_set_does_not_start_and_says_which(tmp_path, monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    with FakeModelServer() as server:
        cfg = with_notify(run_config(tmp_path, server.base_url))
        with pytest.raises(RunError, match=f"notify.webhook_env names the variable {ENV}, which is not set"):
            prepare_run(RunOptions(board=board(tmp_path), config=cfg))
        monkeypatch.setenv(ENV, "gopher://hooks.example.test/secret-0451")
        with pytest.raises(RunError) as caught:
            prepare_run(RunOptions(board=board(tmp_path / "again"), config=cfg))
        assert server.requests == []  # before the model API is asked, before anything starts
    assert "does not hold an http:// or https:// URL" in str(caught.value) and "secret-0451" not in str(caught.value)
    assert not (tmp_path / "runs").exists()


def test_a_run_notifies_the_webhook_and_its_url_is_nowhere_in_what_the_run_keeps_or_says(tmp_path, monkeypatch):
    """A whole run: the lane reads a file that holds the webhook's URL (a handout could not
    know it; this is the worst case), then finds a flag, which waits; the player is told by
    the webhook. The receiver fails once the flag is in, so the run warns too. The URL is in
    none of it: the lane's text and the model's requests have it as [NAME], and the events,
    the transcript, status.json, the notes and the warning never had it."""
    root = board(tmp_path)

    async def main(hook: FakeWebhook, server: FakeModelServer):
        run = prepare_run(RunOptions(board=root, config=with_notify(run_config(tmp_path, server.base_url))))
        run.release()
        (lane,) = run.deck.lanes.values()
        await until(lambda: lane.pending is not None, "the flag's approval", 30)
        await until(lambda: len(hook.bodies()) == 1, "the needs-you message")
        hook.status = 500
        assert run.deck.apply(iv.Approve(lane.id)).ok
        await until(lambda: len(hook.bodies()) == 2 and warnings(run.deck), "the flag message and the warning")
        await run.shutdown()
        run.close()
        return run, lane

    with FakeWebhook() as hook:
        monkeypatch.setenv(ENV, hook.url)
        (root / "note" / "pad.txt").write_text(f"webhook: {hook.url}\n")
        with FakeModelServer([
            tool_call_reply("shell", {"command": "cat pad.txt"}),
            tool_call_reply("submit_flag", {"flag": FLAG}),
        ], responder=lambda record: text_reply("done")) as server:
            run, lane = asyncio.run(main(hook, server))
            sent = json.dumps([chat["json"] for chat in server.chats()])
        bodies = hook.bodies()
    challenge = {"id": "note", "name": "Note"}
    assert bodies == [
        {"flightdeck": __version__, "format": 1, "run": run.dir.name, "event": "Test Event", "kind": "needs-you",
         "lane": "L01", "challenge": challenge, "need": "submit", "text": "L01 has a flag for Note: it waits for your approval"},
        {"flightdeck": __version__, "format": 1, "run": run.dir.name, "event": "Test Event", "kind": "flag",
         "lane": "L01", "challenge": challenge, "need": None, "text": "L01 solved Note: its flag was accepted"},
    ]
    assert FLAG not in json.dumps(bodies)
    events = run.log.path.read_text()
    transcript = (run.dir / "lanes" / f"{lane.id}.jsonl").read_text()
    status = (run.dir / "status.json").read_text()
    notes = "\n".join(run.notes())
    assert f"webhook: [{ENV}]" in transcript and f"[{ENV}]" in sent  # the lane read it: shown by name
    assert f"notifications (flag, needs-you, disengaged) go to the webhook in the variable {ENV}" in notes
    assert "a notification could not be sent to the webhook" in events and "it answered HTTP 500" in events
    assert json.loads(status)["closed"] is True
    for kept in (events, transcript, status, notes, sent, "\n".join(run.errors), repr(run.notifier)):
        assert hook.url not in kept and f"127.0.0.1:{hook.port}" not in kept
        for part in TOKEN_PARTS:
            assert part not in kept
