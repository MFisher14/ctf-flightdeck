"""The config's [light] table (the light model) and [api] fast (fast mode on the Anthropic API).

Every test reads a real file in tmp_path; keys come from monkeypatched variables, never from
the player's environment or keys file (conftest points FLIGHTDECK_KEYS at a missing file).
"""

from __future__ import annotations

import asyncio
import re
from datetime import date
from pathlib import Path

import pytest

from ctf_flightdeck.agent import fastmode
from ctf_flightdeck.light import Lights, build_all
from ctf_flightdeck.config import (
    DEFAULT_JOBS,
    LIGHT_TIMEOUT,
    ConfigError,
    LightConfig,
    LightSpec,
    example_config,
    light_for,
    light_key,
    light_specs,
    load_config,
)
from ctf_flightdeck.pricing import Price

LADDER = '[models]\nladder = ["vendor/small", "vendor/big"]\n'
CLAUDE = '[api]\nprovider = "anthropic"\n[models]\nladder = ["claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5"]\n'
OLLAMA = '[light]\nengine = "openai"\nmodel = "local-model"\nbase_url = "http://127.0.0.1:11434/v1"\nkey_env = ""\n'
SENTINEL = "zqSentinelValue4471"  # letters and digits only, like many real keys
FAKE_KEY = "fake-light-key-for-tests-0451"  # not a real key, and not shaped like one


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    monkeypatch.delenv("FLIGHTDECK_CONFIG", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    return path


def error(path: Path) -> str:
    with pytest.raises(ConfigError) as caught:
        load_config(path)
    return str(caught.value)


# ---------------------------------------------------------------------- [light]


def test_without_a_light_table_the_light_role_is_rules_only(tmp_path):
    assert load_config(write(tmp_path, LADDER)).light == LightConfig(engine="rules")
    assert light_key(load_config(write(tmp_path, LADDER))) is None


def test_an_open_weight_model_on_this_machine_needs_no_key(tmp_path, monkeypatch):
    config = load_config(write(tmp_path, LADDER + OLLAMA + "timeout = 12.5\n"))
    assert config.light == LightConfig("openai", "local-model", "http://127.0.0.1:11434/v1", "", 12.5, None)
    assert light_key(config) is None


def test_the_anthropic_engine_has_the_sdks_url_and_variable_by_default_and_reads_its_key(tmp_path, monkeypatch):
    text = LADDER + '[light]\nengine = "anthropic"\nmodel = "claude-haiku-5-5"\nprice = { input = 0.1, output = 0.5, cached_input = 0.01 }\n'
    config = load_config(write(tmp_path, text))
    assert config.light == LightConfig(
        "anthropic", "claude-haiku-5-5", "https://api.anthropic.com", "ANTHROPIC_API_KEY", LIGHT_TIMEOUT,
        Price(0.1, 0.5, 0.01),
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", FAKE_KEY)
    assert light_key(config) == FAKE_KEY
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    with pytest.raises(ConfigError) as caught:
        light_key(config)
    message = str(caught.value)
    assert "light.key_env names the variable ANTHROPIC_API_KEY, which is not set" in message
    assert 'engine = "rules"' in message and FAKE_KEY not in message


def test_cactus_takes_only_a_timeout(tmp_path):
    assert load_config(write(tmp_path, LADDER + '[light]\nengine = "cactus"\ntimeout = 5\n')).light == LightConfig("cactus", timeout=5.0)


LIGHT_ERRORS = {
    "unknown key": ('[light]\nengine = "rules"\nmodle = "x"\n', "unknown key light.modle"),
    "unknown engine": ('[light]\nengine = "ollama"\n', 'light.engine must be "rules" or "openai" or "anthropic" or "cactus"'),
    "rules with a model": ('[light]\nmodel = "x"\n', 'light.model is for the openai, anthropic and decider engines, not "rules"'),
    "cactus with a url": ('[light]\nengine = "cactus"\nbase_url = "http://127.0.0.1:1/v1"\n', "light.base_url is for the openai"),
    "rules with a price": ('[light]\nprice = { input = 1, output = 2 }\n', "light.price is for the openai"),
    "openai without a model": ('[light]\nengine = "openai"\nbase_url = "http://127.0.0.1:11434/v1"\nkey_env = ""\n', "light.model is required for the openai engine"),
    "openai without a url": ('[light]\nengine = "openai"\nmodel = "m"\nkey_env = ""\n', 'light.base_url is required for the openai engine (it has no default): for a server on this machine, base_url = "http://127.0.0.1:11434/v1" (Ollama)'),
    "openai without key_env": ('[light]\nengine = "openai"\nmodel = "m"\nbase_url = "http://127.0.0.1:11434/v1"\n', 'light.key_env is required for the openai engine'),
    "anthropic without a model": ('[light]\nengine = "anthropic"\n', "light.model is required for the anthropic engine: the model id (for example claude-haiku-5-5)"),
    "anthropic without a key": ('[light]\nengine = "anthropic"\nmodel = "claude-haiku-5-5"\nkey_env = ""\n', "light.key_env is empty, but the Anthropic API needs a key"),
    "anthropic url with /v1": ('[light]\nengine = "anthropic"\nmodel = "m"\nbase_url = "https://api.anthropic.com/v1"\n', "light.base_url ends in /v1"),
    "url with a password": (OLLAMA.replace("http://127.0.0.1", "http://me:pw@127.0.0.1"), "light.base_url must not carry a user name or password"),
    "key_env in lower case": (OLLAMA.replace('key_env = ""', 'key_env = "my_key"'), "light.key_env must be the name of an environment variable"),
    "model with a space": (OLLAMA.replace('"local-model"', '"local model"'), "light.model must be a model id"),
    "model not a string": (OLLAMA.replace('"local-model"', "3"), "light.model must be a string"),
    "timeout zero": ('[light]\ntimeout = 0\n', "light.timeout must be a positive number of seconds (got 0)"),
    "timeout negative": ('[light]\ntimeout = -1\n', "light.timeout must be a positive number of seconds"),
    "timeout infinite": ('[light]\ntimeout = inf\n', "light.timeout must be a positive number of seconds"),
    "timeout true": ('[light]\ntimeout = true\n', "light.timeout must be a positive number of seconds (got true)"),
    "price missing output": (OLLAMA + "price = { input = 1 }\n", "light.price.output is required"),
    "price negative": (OLLAMA + "price = { input = -1, output = 1 }\n", "light.price.input must be a number of dollars"),
    "price not a table": (OLLAMA + "price = 3\n", "light.price must be a table of dollars per million tokens"),
    "price unknown key": (OLLAMA + "price = { input = 1, output = 1, write = 2 }\n", "unknown key light.price.write"),
    "light not a table": ("light = 1\n", "light must be a table"),
}


@pytest.mark.parametrize("text, says", LIGHT_ERRORS.values(), ids=LIGHT_ERRORS.keys())
def test_a_bad_light_table_is_an_error_that_names_the_key(tmp_path, text, says):
    path = write(tmp_path, LADDER + text if not text.startswith("light =") else text + LADDER)
    message = error(path)
    assert message.startswith(f"{path}: ") and says in message


LIGHT_STRINGS = {
    "engine": (f'[light]\nengine = "{SENTINEL}"\n', "light.engine"),
    "model": (f'[light]\nengine = "openai"\nmodel = " {SENTINEL}"\nbase_url = "http://127.0.0.1:1/v1"\nkey_env = ""\n', "light.model"),
    "base_url": (f'[light]\nengine = "openai"\nmodel = "m"\nbase_url = "{SENTINEL}"\nkey_env = ""\n', "light.base_url"),
    "key_env holding a key": (f'[light]\nengine = "anthropic"\nmodel = "m"\nkey_env = "sk-{SENTINEL}"\n', "light.key_env"),
    "timeout": (f'[light]\ntimeout = "{SENTINEL}"\n', "light.timeout"),
}


@pytest.mark.parametrize("text, key", LIGHT_STRINGS.values(), ids=LIGHT_STRINGS.keys())
def test_light_errors_never_show_a_string_value(tmp_path, text, key):
    message = error(write(tmp_path, LADDER + text))
    assert key in message and SENTINEL not in message


# ---------------------------------------------------------------------- [light] jobs and [light.<job>]

CLAUDE_TABLE = '[light.{job}]\nengine = "anthropic"\nmodel = "claude-haiku-5-5"\nkey_env = "{env}"\n'


def claude_for(job: str, env: str = "FLIGHTDECK_TEST_FLAGCHECK_KEY") -> str:
    return CLAUDE_TABLE.format(job=job, env=env)


def test_a_config_without_jobs_runs_the_judge_as_before(tmp_path):
    for text in ("", '[light]\nengine = "rules"\n', OLLAMA):
        config = load_config(write(tmp_path, LADDER + text))
        assert config.light_jobs == DEFAULT_JOBS == ("judge",) and config.light_tables == {}
        assert light_for(config, "judge") == config.light
        assert light_specs(config) == [LightSpec(config.light, ("judge",), ("light",))]


def test_a_job_table_overrides_only_its_own_job(tmp_path):
    text = OLLAMA + 'jobs = ["judge", "route", "flagcheck"]\n' + claude_for("flagcheck")
    config = load_config(write(tmp_path, LADDER + text))
    local = LightConfig("openai", "local-model", "http://127.0.0.1:11434/v1", "", LIGHT_TIMEOUT)
    claude = LightConfig("anthropic", "claude-haiku-5-5", "https://api.anthropic.com", "FLIGHTDECK_TEST_FLAGCHECK_KEY")
    assert config.light == local and config.light_jobs == ("judge", "route", "flagcheck")
    assert light_for(config, "flagcheck") == claude
    assert light_for(config, "judge") == light_for(config, "route") == light_for(config, "recon") == local
    assert light_specs(config) == [LightSpec(local, ("judge", "route"), ("light",)),
                                   LightSpec(claude, ("flagcheck",), ("light.flagcheck",))]


def test_two_job_tables_with_the_same_spec_are_one_spec(tmp_path):
    text = '[light]\njobs = ["recon", "flagcheck"]\n' + claude_for("recon") + claude_for("flagcheck")
    config = load_config(write(tmp_path, LADDER + text))
    claude = light_for(config, "recon")
    assert claude == light_for(config, "flagcheck") and claude.engine == "anthropic"
    assert light_specs(config) == [LightSpec(LightConfig(), (), ("light",)),
                                   LightSpec(claude, ("recon", "flagcheck"), ("light.recon", "light.flagcheck"))]


def test_a_job_table_must_name_its_engine_and_inherits_nothing(tmp_path):
    no_engine = OLLAMA + 'jobs = ["judge", "recon"]\n[light.recon]\nmodel = "other-model"\n'
    message = error(write(tmp_path, LADDER + no_engine))
    assert "light.recon.engine is required" in message and "inherits nothing from [light]" in message
    # [light] gives an openai server, a timeout and thinking; the recon table takes none of them
    text = (OLLAMA + 'timeout = 7\nthinking = true\njobs = ["judge", "recon"]\n'
            '[light.recon]\nengine = "openai"\nmodel = "other-model"\nbase_url = "http://127.0.0.1:8080/v1"\n'
            'key_env = ""\n')
    config = load_config(write(tmp_path, LADDER + text))
    assert light_for(config, "recon") == LightConfig("openai", "other-model", "http://127.0.0.1:8080/v1", "", LIGHT_TIMEOUT)
    assert config.light.timeout == 7.0 and config.light.thinking is True
    # an openai job table must name its own server and key variable, as [light] must
    message = error(write(tmp_path, LADDER + OLLAMA + 'jobs = ["judge", "recon"]\n'
                                                     '[light.recon]\nengine = "openai"\nmodel = "m"\n'))
    assert "light.recon.base_url is required for the openai engine (it has no default)" in message


def test_an_unknown_job_is_an_error_naming_the_key(tmp_path):
    message = error(write(tmp_path, LADDER + '[light]\njobs = ["judge", "rout"]\n'))
    assert "light.jobs[1] is not a job a run gives the light model: one of judge, route, recon, flagcheck" in message
    assert "rout" not in message.replace("route", "")  # a string from the file is never shown
    message = error(write(tmp_path, LADDER + OLLAMA + '[light.rout]\nengine = "rules"\n'))
    assert "unknown table [light.rout]: a job's own engine goes in [light.<job>]" in message
    assert "hint, judge, summary, route, recon, flagcheck" in message


JOB_ERRORS = {
    "jobs not a list": ('[light]\njobs = "judge"\n', "light.jobs must be a list of the jobs a run gives the light model, "
                                                     "from judge, route, recon, flagcheck (got a string)"),
    "a job not a string": ('[light]\njobs = [3]\n', "light.jobs[0] must be the name of a job, one of judge, route, recon, flagcheck (got 3)"),
    "an eval-only job": ('[light]\njobs = ["hint"]\n', "light.jobs[0] is hint: measured by eval-local, not used in a run"),
    "summary in jobs": ('[light]\njobs = ["judge", "summary"]\n', "light.jobs[1] is summary: measured by eval-local, not used in a run"),
    "a job twice": ('[light]\njobs = ["judge", "judge"]\n', "light.jobs[1] repeats light.jobs[0]"),
    "jobs inside a job table": (OLLAMA + 'jobs = ["judge", "recon"]\n' + claude_for("recon") + 'jobs = ["recon"]\n',
                                "light.recon.jobs is set in [light] only"),
    "a job table that is not a table": (OLLAMA + 'recon = "claude"\n', "light.recon must be a table ([light.recon]): recon's own engine (got a string)"),
    "a table inside a job table": (OLLAMA + 'jobs = ["judge", "recon"]\n' + claude_for("recon") + '[light.recon.price]\ninput = 1\noutput = 1\n',
                                   None),  # a price is a key of the spec: accepted (see below)
    "an unknown key in a job table": (OLLAMA + 'jobs = ["judge", "recon"]\n' + claude_for("recon") + 'modle = "x"\n',
                                      "unknown key light.recon.modle"),
    "a bad value in a job table": (OLLAMA + 'jobs = ["judge", "recon"]\n' + claude_for("recon") + 'timeout = 0\n',
                                   "light.recon.timeout must be a positive number of seconds (got 0)"),
    "a nested job table": (OLLAMA + 'jobs = ["judge", "recon"]\n' + claude_for("recon") + '[light.recon.judge]\nengine = "rules"\n',
                           "unknown table [light.recon.judge]: a job's table holds one engine spec"),
}


@pytest.mark.parametrize("text, says", JOB_ERRORS.values(), ids=JOB_ERRORS.keys())
def test_a_bad_jobs_list_or_job_table_is_an_error_that_names_the_key(tmp_path, text, says):
    path = write(tmp_path, LADDER + text)
    if says is None:
        assert light_for(load_config(path), "recon").price == Price(1.0, 1.0)
        return
    message = error(path)
    assert message.startswith(f"{path}: ") and says in message


def test_a_job_table_for_a_job_that_is_off_is_an_error(tmp_path):
    message = error(write(tmp_path, LADDER + OLLAMA + claude_for("flagcheck")))  # jobs: the judge alone, by default
    assert 'light.flagcheck is flagcheck\'s engine, but light.jobs does not list "flagcheck", so it would look on and be off' in message
    assert 'add "flagcheck" to light.jobs, or remove [light.flagcheck]' in message
    on = load_config(write(tmp_path, LADDER + OLLAMA + 'jobs = ["judge", "flagcheck"]\n' + claude_for("flagcheck")))
    assert on.light_jobs == ("judge", "flagcheck")
    # hint and summary are never in jobs: their tables are for eval-local, and are not off
    measured = load_config(write(tmp_path, LADDER + OLLAMA + claude_for("hint") + claude_for("summary")))
    assert light_for(measured, "hint").engine == light_for(measured, "summary").engine == "anthropic"
    assert measured.light_jobs == ("judge",)


def test_recon_with_only_the_rules_is_an_error_naming_the_job(tmp_path):
    for job in ("recon", "flagcheck"):
        message = error(write(tmp_path, LADDER + f'[light]\njobs = ["judge", "{job}"]\n'))
        assert f"light.jobs[1] is {job}, which needs a model" in message
        assert f"give {job} its own [light.{job}] table" in message
    # route can do with the rules alone: its category and instance questions
    assert load_config(write(tmp_path, LADDER + '[light]\njobs = ["route"]\n')).light_jobs == ("route",)


CANNOT = {
    "recon on the decider": ('[light]\nengine = "decider"\nbase_url = "http://127.0.0.1:8000"\njobs = ["recon"]\n',
                             'light.jobs[0] is recon, but [light]\'s engine "decider" cannot do it: a brief is text'),
    "flagcheck on cactus": ('[light]\nengine = "cactus"\njobs = ["judge", "flagcheck"]\n',
                            'light.jobs[1] is flagcheck, but [light]\'s engine "cactus" cannot do it'),
    "route on cactus": ('[light]\nengine = "cactus"\njobs = ["route"]\n',
                        "Cactus Needle called no tool on half the route questions"),
    "a decider table for flagcheck": (OLLAMA + 'jobs = ["judge", "flagcheck"]\n[light.flagcheck]\nengine = "decider"\n'
                                      'base_url = "http://127.0.0.1:8000"\n',
                                      'light.flagcheck.engine is "decider", which cannot do flagcheck: the rules check no flag'),
    "a rules table for recon": (OLLAMA + 'jobs = ["judge", "recon"]\n[light.recon]\nengine = "rules"\n',
                                'light.recon.engine is "rules", which cannot do recon'),
    "a cactus table for summary": (OLLAMA + '[light.summary]\nengine = "cactus"\n', 'light.summary.engine is "cactus", which cannot do summary'),
}


@pytest.mark.parametrize("text, says", CANNOT.values(), ids=CANNOT.keys())
def test_a_job_whose_engine_cannot_do_it_is_an_error(tmp_path, text, says):
    assert says in error(write(tmp_path, LADDER + text))


def test_each_engine_does_the_jobs_it_can(tmp_path):
    decider = '[light]\nengine = "decider"\nbase_url = "http://127.0.0.1:8000"\njobs = ["judge", "route"]\n'
    assert load_config(write(tmp_path, LADDER + decider)).light_jobs == ("judge", "route")
    cactus = load_config(write(tmp_path, LADDER + '[light]\nengine = "cactus"\njobs = ["judge"]\n'))
    assert cactus.light_jobs == ("judge",)
    every = load_config(write(tmp_path, LADDER + OLLAMA + 'jobs = ["judge", "route", "recon", "flagcheck"]\n'))
    assert every.light_jobs == ("judge", "route", "recon", "flagcheck")


def test_each_job_reads_its_own_key_env(tmp_path, monkeypatch):
    text = ('[light]\nengine = "anthropic"\nmodel = "claude-haiku-5-5"\nkey_env = "FLIGHTDECK_TEST_LIGHT_KEY"\n'
            'jobs = ["judge", "flagcheck"]\n' + claude_for("flagcheck"))
    config = load_config(write(tmp_path, LADDER + text))
    monkeypatch.delenv("FLIGHTDECK_TEST_LIGHT_KEY", raising=False)
    monkeypatch.setenv("FLIGHTDECK_TEST_FLAGCHECK_KEY", FAKE_KEY)
    assert light_key(config, "flagcheck") == FAKE_KEY  # the key set for light.flagcheck reaches flagcheck
    with pytest.raises(ConfigError) as caught:  # and only flagcheck: the judge reads [light]'s variable
        light_key(config, "judge")
    assert "light.key_env names the variable FLIGHTDECK_TEST_LIGHT_KEY, which is not set" in str(caught.value)
    with pytest.raises(ConfigError):
        light_key(config)  # [light]'s own key, as before jobs
    monkeypatch.delenv("FLIGHTDECK_TEST_FLAGCHECK_KEY")
    monkeypatch.setenv("FLIGHTDECK_TEST_LIGHT_KEY", FAKE_KEY)
    assert light_key(config, "judge") == FAKE_KEY
    with pytest.raises(ConfigError) as caught:
        light_key(config, "flagcheck")
    message = str(caught.value)
    assert "light.flagcheck.key_env names the variable FLIGHTDECK_TEST_FLAGCHECK_KEY, which is not set" in message
    assert 'or take "flagcheck" out of [light] jobs' in message and FAKE_KEY not in message


def test_a_run_jobs_unset_key_advises_removing_the_table_and_that_advice_loads(tmp_path, monkeypatch):
    # A run job's [light.<job>] table needs its own key; "take it out of [light] jobs" alone then
    # leaves the table on for a job that is off, which is itself an error, so the advice must also
    # name the table to remove. Following it must load.
    monkeypatch.delenv("FLIGHTDECK_TEST_JUDGE_KEY", raising=False)
    on = OLLAMA + 'jobs = ["judge"]\n' + CLAUDE_TABLE.format(job="judge", env="FLIGHTDECK_TEST_JUDGE_KEY")
    config = load_config(write(tmp_path, LADDER + on))
    with pytest.raises(ConfigError) as caught:
        light_key(config, "judge")
    message = str(caught.value)
    assert 'or take "judge" out of [light] jobs and remove [light.judge]' in message
    # Follow it literally: jobs without judge and no [light.judge] table. It loads (no new error).
    off = OLLAMA + "jobs = []\n"
    assert load_config(write(tmp_path, LADDER + off)).light_jobs == ()


def test_a_job_table_key_env_holding_a_key_is_never_shown(tmp_path):
    text = OLLAMA + 'jobs = ["judge", "recon"]\n' + claude_for("recon", env=f"sk-{SENTINEL}")
    message = error(write(tmp_path, LADDER + text))
    assert "light.recon.key_env must be the name of an environment variable" in message and SENTINEL not in message


def test_light_for_refuses_a_job_that_does_not_exist(tmp_path):
    config = load_config(write(tmp_path, LADDER))
    with pytest.raises(ValueError, match="unknown light job 'triage'"):
        light_for(config, "triage")


# ---------------------------------------------------------------------- the engines a run makes (light.build_all)


def test_one_engine_is_made_per_distinct_spec_and_shared_between_its_jobs(tmp_path, monkeypatch):
    monkeypatch.setenv("FLIGHTDECK_TEST_FLAGCHECK_KEY", FAKE_KEY)
    text = OLLAMA + 'jobs = ["judge", "route", "recon", "flagcheck"]\n' + claude_for("recon") + claude_for("flagcheck")
    lights = build_all(load_config(write(tmp_path, LADDER + text)))
    try:
        assert lights.get("judge") is lights.get("route") and lights.get("judge").label == "openai local-model"
        assert lights.get("recon") is lights.get("flagcheck") and lights.get("recon").label == "anthropic claude-haiku-5-5"
        assert lights.notes == [] and lights.off == {}
    finally:
        asyncio.run(lights.aclose())


def test_a_spec_that_cannot_be_built_leaves_its_jobs_off_and_the_run_going(tmp_path, monkeypatch):
    monkeypatch.delenv("FLIGHTDECK_TEST_FLAGCHECK_KEY", raising=False)
    text = OLLAMA + 'jobs = ["judge", "route", "recon", "flagcheck"]\n' + claude_for("recon") + claude_for("flagcheck")
    lights = build_all(load_config(write(tmp_path, LADDER + text)))  # never raises
    try:
        assert lights.get("judge") is lights.get("route") is not None  # the spec that could be made is made
        assert lights.get("recon") is None and lights.get("flagcheck") is None
        (note,) = lights.notes  # one note for the one spec recon and flagcheck share
        assert note.startswith("the light model for recon and flagcheck is off for this run, and those jobs go on as "
                               "they do without one: ")
        assert "light.recon.key_env names the variable FLIGHTDECK_TEST_FLAGCHECK_KEY, which is not set" in note
        assert lights.off == {"recon": note, "flagcheck": note}
    finally:
        asyncio.run(lights.aclose())
    # the judge alone, as before jobs: the same words as ever
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    alone = build_all(load_config(write(tmp_path, LADDER + '[light]\nengine = "anthropic"\nmodel = "claude-haiku-5-5"\n')))
    assert alone.engines == {} and alone.notes == [
        alone.off["judge"]] and alone.off["judge"].startswith("the light model is off for this run, the rules answer alone: ")


def test_the_rules_and_jobs_left_out_get_no_engine(tmp_path):
    lights = build_all(load_config(write(tmp_path, LADDER + '[light]\njobs = ["judge", "route"]\n')))
    assert lights.engines == {} and lights.notes == []  # the rules answer alone
    config = load_config(write(tmp_path, LADDER + OLLAMA + 'jobs = ["judge", "route"]\n'))
    only = build_all(config, jobs=("judge",))
    try:
        assert set(only.engines) == {"judge"}
    finally:
        asyncio.run(only.aclose())


class Counted:
    """An engine that counts how often it is closed (only Lights.aclose is under test)."""

    engine, model, label = "openai", "m", "openai m"

    def __init__(self) -> None:
        self.closed = 0

    async def aclose(self) -> None:
        self.closed += 1


def test_the_run_closes_each_shared_engine_once():
    shared, other = Counted(), Counted()
    lights = Lights(engines={"judge": shared, "route": shared, "flagcheck": other})
    asyncio.run(lights.aclose())
    asyncio.run(lights.aclose())  # again: nothing is closed twice
    assert shared.closed == 1 and other.closed == 1


# ---------------------------------------------------------------------- [api] fast


def test_fast_mode_is_set_per_ladder_model_on_the_anthropic_api(tmp_path):
    config = load_config(write(tmp_path, CLAUDE.replace('provider = "anthropic"\n', 'provider = "anthropic"\nfast = ["claude-opus-5-5"]\n')))
    assert config.api.fast == ("claude-opus-5-5",)
    assert load_config(write(tmp_path, CLAUDE)).api.fast == ()


def fast(models: str, *, api: str = CLAUDE) -> str:
    return api.replace('provider = "anthropic"\n', f'provider = "anthropic"\nfast = {models}\n')


FAST_ERRORS = {
    "not the anthropic api": (LADDER + '[api]\nfast = ["vendor/big"]\n', 'api.fast is fast mode, a feature of the Anthropic Messages API: it needs [api] provider = "anthropic"'),
    "not a list": (fast('"claude-opus-5-5"'), "api.fast must be a list of model ids from models.ladder (got a string)"),
    "not in the ladder": (fast('["claude-fable-5-2"]'), "api.fast[0] is not a model in models.ladder"),
    "no fast mode": (fast('["claude-opus-5-5", "claude-sonnet-5-5"]'), "api.fast[1] names a model with no fast mode; fast mode is for claude-opus-5-5, claude-fable-5-2"),
    "listed twice": (fast('["claude-opus-5-5", "claude-opus-5-5"]'), "api.fast[1] repeats api.fast[0]"),
    "not a string": (fast("[5]"), "api.fast[0] must be a model id from models.ladder (got 5)"),
}


@pytest.mark.parametrize("text, says", FAST_ERRORS.values(), ids=FAST_ERRORS.keys())
def test_fast_mode_is_refused_with_the_reason(tmp_path, text, says):
    message = error(write(tmp_path, text))
    assert says in message


def test_an_unlisted_model_in_fast_is_never_shown(tmp_path):
    api = f'[api]\nprovider = "anthropic"\n[models]\nladder = ["{SENTINEL}"]\n'
    message = error(write(tmp_path, fast(f'["{SENTINEL}"]', api=api)))
    assert "api.fast[0] names a model with no fast mode" in message and SENTINEL not in message


def test_fast_mode_on_opus_4_8_ends_on_the_day_anthropic_removes_it(tmp_path, monkeypatch):
    text = fast('["claude-opus-4-8"]', api='[api]\nprovider = "anthropic"\n[models]\nladder = ["claude-opus-4-8"]\n')
    monkeypatch.setattr(fastmode, "today", lambda: date(2026, 11, 29))
    assert load_config(write(tmp_path, text)).api.fast == ("claude-opus-4-8",)
    monkeypatch.setattr(fastmode, "today", lambda: date(2026, 11, 30))
    message = error(write(tmp_path, text))
    assert "api.fast[0]: fast mode on claude-opus-4-8 was removed on 2026-11-30" in message
    assert "claude-opus-4-8 (research preview" not in message  # no longer offered either


# ---------------------------------------------------------------------- the example


def filled(example: str) -> str:
    return example.replace("ladder = []", 'ladder = ["vendor/small-model", "vendor/big-model"]')


def test_the_example_recommends_a_local_open_weight_model_and_loads_as_rules(tmp_path):
    text = example_config()
    assert "[light]" in text and 'engine = "rules"' in text
    for words in ("open-weight", "http://127.0.0.1:11434/v1", "http://127.0.0.1:8080/v1", 'key_env = ""', "eval-local",
                  "not endorsements", "Qwen3.5 9B", "Gemma 4 12B", "`flightdeck models`", "the rules' answer stands",
                  "# fast = "):
        assert words in text, words
    assert "Phi-4-mini" not in text  # it scored below the rules (docs/MODELS.md): not an example to measure
    assert load_config(write(tmp_path, filled(text))).light == LightConfig()


def test_the_example_openai_lines_load_once_uncommented(tmp_path):
    text = filled(example_config()).replace('engine = "rules"   #', 'engine = "openai"   #')
    text, n = re.subn(r"^#   (model = .*|base_url = .*|key_env = .*|timeout = .*|price = .*)$", r"\1", text, flags=re.M)
    assert n == 5
    light = load_config(write(tmp_path, text)).light
    assert (light.engine, light.base_url, light.key_env, light.timeout) == ("openai", "http://127.0.0.1:11434/v1", "", 30.0)
    assert light.price == Price(0.10, 0.50)


def test_the_example_shows_a_flagcheck_table_that_loads_once_uncommented(tmp_path):
    text = filled(example_config())
    assert "[light.flagcheck]" in text and "inherits\n# nothing from [light]" in text
    text, n = re.subn(r"^#   (jobs = .*|\[light\.flagcheck\])$|^#     (engine = .*|model = .*|key_env = .*)$",
                      lambda m: m.group(1) or m.group(2), text, flags=re.M)
    assert n == 5
    config = load_config(write(tmp_path, text))
    assert config.light == LightConfig() and config.light_jobs == ("judge", "flagcheck")
    assert light_for(config, "flagcheck") == LightConfig("anthropic", "claude-haiku-5-5", "https://api.anthropic.com",
                                                         "ANTHROPIC_API_KEY")
