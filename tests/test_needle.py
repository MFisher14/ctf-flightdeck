"""The Cactus Needle adapter. Cactus itself is optional (an extra) and downloads its engine and
weights on first use, so these tests drive the adapter with a stand-in `cactus` module; the one
test of the real package runs only when it is installed and FLIGHTDECK_TEST_CACTUS=1 says the
player accepts that download."""

from __future__ import annotations

import os
import sys
import types

import pytest

from ctf_flightdeck.needle import EXTRA, MAX_TEXT, NONE, NeedleError, Option, Picker, load, tool_schemas

OPTIONS = (
    Option("decode_base64", "Decode base64 text.", triggers=("base64", "==")),
    Option("decode_morse", "Decode Morse code (dots and dashes)."),
)


class FakeAgent:
    def __init__(self, answers, tools, **kwargs):
        self.answers, self.tools, self.kwargs, self.texts, self.closed = list(answers), tools, kwargs, [], False

    def complete(self, text):
        self.texts.append(text)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    def close(self):
        self.closed = True


def fake_cactus(answers=(), *, telemetry_on=False):
    module = types.ModuleType("cactus")
    made = []

    def Cactus(tools, **kwargs):
        agent = FakeAgent(answers, tools, **kwargs)
        made.append(agent)
        return agent

    module.Cactus = Cactus
    module.made = made
    tel = types.ModuleType("cactus._telemetry")
    tel._enabled = lambda: telemetry_on
    return module, tel


def call(name, confidence=0.9):
    return {"function_calls": [{"name": name, "arguments": {}}], "confidence": confidence}


@pytest.fixture
def installed(monkeypatch):
    def install(answers=(), *, telemetry_on=False):
        module, tel = fake_cactus(answers, telemetry_on=telemetry_on)
        monkeypatch.setitem(sys.modules, "cactus", module)
        monkeypatch.setitem(sys.modules, "cactus._telemetry", tel)
        return module

    return install


def test_without_cactus_installed_it_says_how_to_install_it(monkeypatch):
    monkeypatch.setitem(sys.modules, "cactus", None)  # import cactus raises ImportError
    with pytest.raises(NeedleError, match="Cactus is not installed: " + EXTRA.replace("[", r"\[").replace("]", r"\]")):
        load({})


def test_loading_turns_cactus_telemetry_off_unless_the_player_chose(installed):
    installed()
    env: dict[str, str] = {}
    load(env)
    assert env == {"CACTUS_TELEMETRY": "0", "DO_NOT_TRACK": "1", "NEEDLE_TELEMETRY": "0"}
    mine = {"CACTUS_TELEMETRY": "1"}
    load(mine)
    assert mine["CACTUS_TELEMETRY"] == "1"  # the player's own choice stands


def test_it_refuses_cactus_that_still_says_telemetry_is_on(installed):
    installed(telemetry_on=True)
    with pytest.raises(NeedleError, match="telemetry is on although flightdeck turned it off"):
        load({})
    load({"CACTUS_TELEMETRY": "1"})  # unless the player turned it on themselves


def test_the_options_become_tools_with_none_last_and_their_triggers_escaped():
    tools = tool_schemas(OPTIONS)
    assert [t["name"] for t in tools] == ["decode_base64", "decode_morse", NONE]
    assert tools[0]["triggers"] == ["(base64|==)"] and "triggers" not in tools[1]
    assert tool_schemas([Option("a", "x", triggers=("a.b", "c|d"))])[0]["triggers"] == [r"(a\.b|c\|d)"]


@pytest.mark.parametrize("names", [["Bad-Name"], [NONE], ["a", "a"], []])
def test_option_names_must_be_plain_unique_and_not_none(names):
    with pytest.raises(ValueError):
        tool_schemas([Option(n, "x") for n in names])


def test_a_pick_is_one_of_the_options_or_none(installed):
    module = installed([call("decode_base64", 0.8), call(NONE), call("rm_rf_everything"), {"function_calls": []}])
    with Picker(OPTIONS) as picker:
        first, second = picker.pick("ZmxhZw== looks like base64"), picker.pick("x")
        assert (first.option, first.valid) == ("decode_base64", True)
        assert (second.option, second.valid) == (None, True)  # none of these: an answer
        bad = picker.pick("y")
        assert (bad.option, bad.valid) == (None, False)  # a name that is not an option is no answer at all
        empty = picker.pick("z")
        assert (empty.option, empty.valid) == (None, False)
    (agent,) = module.made
    assert agent.kwargs == {"auto_date": False, "stateless": True} and agent.closed


def test_a_confidence_out_of_range_reads_as_zero_and_long_text_is_cut(installed):
    module = installed([call("decode_morse", 7), call("decode_morse", True)])
    picker = Picker(OPTIONS)
    assert picker.pick("-" * (MAX_TEXT + 500)).confidence == 0.0
    assert picker.pick(".-").confidence == 0.0
    assert len(module.made[0].texts[0]) == MAX_TEXT


def test_a_failing_model_is_a_needle_error_naming_the_cause(installed):
    installed([RuntimeError("engine crashed")])
    with pytest.raises(NeedleError, match="Needle failed: RuntimeError: engine crashed"):
        Picker(OPTIONS).pick("x")


@pytest.mark.skipif(os.environ.get("FLIGHTDECK_TEST_CACTUS") != "1", reason="not run: set FLIGHTDECK_TEST_CACTUS=1 to test the real Cactus (downloads its engine and weights once)")
def test_the_real_needle_picks_an_obvious_technique():
    pytest.importorskip("cactus", reason="not run: Cactus is not installed (" + EXTRA + ")")
    with Picker(OPTIONS) as picker:
        pick = picker.pick("We intercepted ZmxhZ3t0ZXN0fQ== between two bots. It looks like base64.")
    assert pick.option == "decode_base64"
