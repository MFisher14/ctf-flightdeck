"""The model catalog (models.toml): what it holds, how it is checked, and which of its models
fit a machine for each role. Machines are fakes (fake_host.py); nothing is probed or fetched."""

from __future__ import annotations

import re
import shlex
import tomllib
from importlib.resources import files

import pytest
from fake_host import GIB, FakeHost, apple_mac, linux_box
from typer.testing import CliRunner

from ctf_flightdeck import cli, model_catalog, setup
from ctf_flightdeck.config import DEFAULT_JOBS, load_config, parse_config
from ctf_flightdeck.hardware import LM_STUDIO, MLX, OLLAMA, probe
from ctf_flightdeck.model_catalog import (
    API,
    APPLE,
    CANNOT_TELL,
    CONTEXT_ALLOWANCE,
    CPU,
    FITS,
    LANES,
    LIGHT,
    LOCAL,
    NOT_HERE,
    NVIDIA,
    RULES,
    SIZE_CATALOG,
    SIZE_SERVER,
    TOO_BIG,
    UNKNOWN,
    CatalogError,
    advise,
    api_lines,
    budget,
    get_commands,
    init_command,
    judge,
    load_catalog,
    local_lines,
    measure_command,
    parse_catalog,
)
from ctf_flightdeck.pricing import Price

OFF = {OLLAMA: "http://127.0.0.1:9/api/tags", MLX: "http://127.0.0.1:9/v1/models", LM_STUDIO: "http://127.0.0.1:9/v1/models"}
SYSCTL = "/usr/sbin/sysctl"
TEN = 10 * GIB  # a test model's weights: 16 GiB with a lane's context, 12 GiB with the light role's


def machine(host: FakeHost):
    return probe(host, servers=OFF)


def one_model(size: int | None = TEN, *, mlx: bool = False, ident: str = "test-10g", roles: str = '["lanes", "light"]',
              ollama: str = "", mlx_lines: str = "") -> str:
    """A catalog with one model on Ollama (and MLX); `ollama` and `mlx_lines` are added to each build's table."""
    size_line = f"size_bytes = {size}\n" if size is not None else ""
    out = (f'[[local]]\nid = "{ident}"\nname = "Test 10G"\nfamily = "Test"\nparameters = "20B"\nlicense = "MIT"\n'
           f"roles = {roles}\n\n[local.ollama]\nmodel = \"{ident}:q4\"\n{size_line}{ollama}")
    if mlx:
        out += f'\n[local.mlx]\nmodel = "test/{ident}-4bit"\n{size_line}{mlx_lines}'
    return out


def the(catalog_text: str):
    catalog = parse_catalog(catalog_text)
    model = catalog.local[0]
    return model, model.builds[0]


# ---------------------------------------------------------------------- the shipped catalog


SMALL = ("gemma4-e4b", "gemma4-e2b", "qwen3.5-4b", "qwen3.5-2b", "qwen3.5-0.8b")  # the small-model measurement's


def test_the_shipped_catalog_has_the_benchmarked_models_and_the_small_ones_on_ollama():
    catalog = load_catalog()
    builds = {m.id: {b.runtime: b.model for b in m.builds} for m in catalog.local}
    assert builds == {
        "qwen3.5-9b": {OLLAMA: "qwen3.5:9b", MLX: "mlx-community/Qwen3.5-9B-MLX-4bit"},
        "gpt-oss-20b": {OLLAMA: "gpt-oss:20b", MLX: "mlx-community/gpt-oss-20b-MXFP4-Q8"},
        "gemma4-12b": {OLLAMA: "gemma4:12b", MLX: "mlx-community/gemma-4-12B-it-4bit"},
        "phi4-mini": {OLLAMA: "phi4-mini", MLX: "mlx-community/Phi-4-mini-instruct-4bit"},
        "gemma4-e4b": {OLLAMA: "gemma4:e4b"}, "gemma4-e2b": {OLLAMA: "gemma4:e2b"}, "qwen3.5-4b": {OLLAMA: "qwen3.5:4b"},
        "qwen3.5-2b": {OLLAMA: "qwen3.5:2b"}, "qwen3.5-0.8b": {OLLAMA: "qwen3.5:0.8b"},
    }
    assert {m.id: (m.parameters, m.license) for m in catalog.local if m.id in SMALL} == {  # `ollama show`'s count
        "gemma4-e4b": ("7.5B", "Apache-2.0"), "gemma4-e2b": ("4.6B", "Apache-2.0"), "qwen3.5-4b": ("4.2B", "Apache-2.0"),
        "qwen3.5-2b": ("1.9B", "Apache-2.0"), "qwen3.5-0.8b": ("752.39M", "Apache-2.0")}
    assert [a.id for a in catalog.api] == ["anthropic", "openrouter"]


# The measured results (2026-11-11: one machine, under load, one run), per build and role: whether
# the catalog offers it (measured) or not (not_for), and what its line must say: practice
# challenges solved out of 4 and tool calls out of 5 for lanes; for the light role, a build
# measured on the earlier cases says its eval-local score out of 44 in the setting it was served
# with, beside the rules' 38/44, and one measured job by job gives each job's figures.
BENCHMARK = {
    ("qwen3.5-9b", OLLAMA): {LANES: ("measured", ["solved 1 of 4", "as served", "tool calls 4/5"]),
                             LIGHT: ("measured", ["for the judge, route, recon and flagcheck", "thinking off",
                                                  "the judge 13/14 in a run against 8/14 with no model",
                                                  "route 42 right and 7 wrong", "recon 20 briefs right and 10 wrong of 30",
                                                  "flagcheck 35/40 in a run against 30/40", "hint 27/30"])},
    ("qwen3.5-9b", MLX): {LANES: ("measured", ["solved 2 of 4", "with thinking off and --max-tokens 8192", "tool calls 5/5"]),
                          LIGHT: ("measured", ["eval-local 41/44 with thinking off", "the rules' 38/44"])},
    ("gpt-oss-20b", OLLAMA): {LANES: ("measured", ["solved 2 of 4", "as served", "tool calls 5/5"]),
                              LIGHT: ("measured", ["eval-local 38/44 with no thinking switch sent", "the rules' 38/44",
                                                   "thinking off, flightdeck's default here, was not measured"])},
    ("gpt-oss-20b", MLX): {LANES: ("not_for", ["tool calls 0/5"]), LIGHT: ("not_for", ["eval-local 0/44"])},
    ("gemma4-12b", OLLAMA): {LANES: ("not_for", ["solved 0 of 4", "in two runs", "tool calls 5/5"]),
                             LIGHT: ("measured", ["eval-local 42/44 with thinking off", "the rules' 38/44"])},
    ("gemma4-12b", MLX): {LANES: ("not_for", ["solved 0 of 4", "0 of 4 with thinking off and --max-tokens 8192",
                                              "tool calls 5/5"]),
                          LIGHT: ("measured", ["eval-local 41/44 with thinking off", "the rules' 38/44"])},
    ("phi4-mini", OLLAMA): {LANES: ("not_for", ["tool calls 0/5"]),
                            LIGHT: ("not_for", ["eval-local 22/44 as served", "below the rules' 38/44"])},
    ("phi4-mini", MLX): {LANES: ("not_for", ["tool calls 0/5"]),
                         LIGHT: ("not_for", ["eval-local 18/44 served as it comes", "below the rules' 38/44"])},
    ("gemma4-e4b", OLLAMA): {LANES: ("measured", ["solved 1 of 4", "as served", "tool calls 5/5"]),
                             LIGHT: ("measured", ["for the judge, route, recon and flagcheck", "the judge 11/14 in a run",
                                                  "route 43 right and 6 wrong", "recon 23 briefs right and 7 wrong",
                                                  "flagcheck 30/40 in a run against 30/40", "hint 28/30"])},
    ("gemma4-e2b", OLLAMA): {LANES: ("not_for", ["solved 0 of 4", "10 wrong flags", "tool calls 5/5"]),
                             LIGHT: ("measured", ["for the judge, route and recon; not flagcheck", "the judge 12/14",
                                                  "route 35 right and 12 wrong", "recon 15 briefs right and 15 wrong",
                                                  "flagcheck 28/40 in a run against 30/40", "hint 24/30"])},
    ("qwen3.5-4b", OLLAMA): {LANES: ("measured", ["solved 2 of 4", "as served", "tool calls 5/5"]),
                             LIGHT: ("measured", ["for the judge, route, recon and flagcheck", "the judge 10/14",
                                                  "route 41 right and 8 wrong", "recon 15 briefs right and 15 wrong",
                                                  "flagcheck 32/40 in a run", "hint 24/30"])},
    ("qwen3.5-2b", OLLAMA): {LANES: ("not_for", ["solved 0 of 4", "250,000-token cap", "tool calls 5/5"]),
                             LIGHT: ("measured", ["for the judge and route; not recon or flagcheck", "the judge 12/14",
                                                  "route 31 right and 16 wrong", "recon 7 briefs right and 23 wrong",
                                                  "flagcheck 27/40 in a run against 30/40", "hint 21/30"])},
    ("qwen3.5-0.8b", OLLAMA): {LANES: ("not_for", ["solved 0 of 4", "250,000-token cap", "tool calls 5/5"]),
                               LIGHT: ("measured", ["for the judge; not route, recon or flagcheck", "the judge 11/14",
                                                    "route 10 right and 13 wrong", "recon 2 briefs right and 27 wrong",
                                                    "flagcheck 20/40 in a run against 30/40", "hint 17/30"])},
}
RULES_SCORE = 38  # of 44 on the earlier cases: the rules', flightdeck's default for the light role (no model, no cost)
# The run jobs each build measured job by job is offered for: no worse than no model at each (see
# offered_jobs()), as the figures in BENCHMARK and the shipped jobs tables give it
OFFERED_JOBS = {
    ("qwen3.5-9b", OLLAMA): ("judge", "route", "recon", "flagcheck"),
    ("gemma4-e4b", OLLAMA): ("judge", "route", "recon", "flagcheck"),
    ("qwen3.5-4b", OLLAMA): ("judge", "route", "recon", "flagcheck"),
    ("gemma4-e2b", OLLAMA): ("judge", "route", "recon"),  # flagcheck held 8 real flags and 6 stand-ins
    ("qwen3.5-2b", OLLAMA): ("judge", "route"),  # recon: 7 briefs right, 23 wrong
    ("qwen3.5-0.8b", OLLAMA): ("judge",),  # route: 10 right, 13 wrong; recon 2 and 27
}


def test_every_shipped_build_says_what_was_measured_for_each_of_its_roles():
    """No build is offered by its size alone: for each role its model takes, a build has the
    measured result, or the reason it is not for that role, with the numbers."""
    shipped = {}
    for model in load_catalog().local:
        for build in model.builds:
            lines = {role: ("measured", build.measured[role]) if role in build.measured else
                     ("not_for", build.not_for[role]) if role in build.not_for else ("nothing", "") for role in model.roles}
            shipped[(model.id, build.runtime)] = lines
    assert {key: {role: kind for role, (kind, _) in lines.items()} for key, lines in shipped.items()} == {
        key: {role: kind for role, (kind, _) in roles.items()} for key, roles in BENCHMARK.items()}
    for key, roles in BENCHMARK.items():
        for role, (_, numbers) in roles.items():
            line = shipped[key][role][1]
            assert all(number in line for number in numbers), (key, role, line)


def test_the_ollama_builds_of_qwen_9b_and_gemma_12b_carry_their_thinking_off_results_for_the_light_role():
    """flightdeck asks a light model on this machine for thinking off (light.THINKING_OFF), which is
    how both scored 42/44: neither is listed as not for the light role any more (issue #5)."""
    catalog = load_catalog()
    for ident in ("qwen3.5-9b", "gemma4-12b"):
        build = catalog.get(ident).build(OLLAMA)
        assert LIGHT not in build.not_for and LIGHT in catalog.get(ident).serves(build)
        assert "thinking off" in build.measured[LIGHT] and build.thinking is None  # flightdeck's own default
    assert catalog.get("qwen3.5-9b").build(OLLAMA).light_jobs == ("judge", "route", "recon", "flagcheck")
    assert catalog.get("gemma4-12b").build(OLLAMA).light_jobs == ("judge",)  # only the judge was measured on it
    gpt_oss = catalog.get("gpt-oss-20b").build(OLLAMA)
    assert gpt_oss.thinking is True and "no thinking switch sent" in gpt_oss.measured[LIGHT]


def test_no_build_measured_on_the_earlier_cases_is_offered_for_the_light_role_below_the_rules():
    """On the earlier cases the light role was hint and judge, scored out of 44, where the rules score
    38: a build below that is not offered (Phi-4-mini: 22/44 and 18/44), and one at or above it is
    offered for the judge alone, the one job a run gives the light model that those cases measured."""
    offered = {}
    for model in load_catalog().local:
        for build in model.builds:
            if LIGHT in build.measured and build.jobs is None:
                score = re.search(r"eval-local (\d+)/44 ", build.measured[LIGHT])
                assert score, build.measured[LIGHT]  # every such result gives its score
                offered[(model.id, build.runtime)] = int(score.group(1))
                assert build.light_jobs == ("judge",), (model.id, build.runtime)
    assert offered and all(score >= RULES_SCORE for score in offered.values()), offered
    assert sorted(offered) == [("gemma4-12b", MLX), ("gemma4-12b", OLLAMA), ("gpt-oss-20b", OLLAMA), ("qwen3.5-9b", MLX)]


def test_a_build_measured_job_by_job_is_offered_for_each_job_it_did_no_worse_at_than_no_model():
    """The rule, read from the shipped jobs tables themselves: the judge and flagcheck right in a
    run at least as often as a run with no light model ([eval]'s default); route and recon right at
    least as often as wrong, where a run with no model has no answer."""
    text = (files("ctf_flightdeck") / "models.toml").read_text(encoding="utf-8")
    data = tomllib.loads(text)
    no_model = {key: value.get("default") for key, value in data["eval"].items()}
    found = {}
    for entry in data["local"]:
        for runtime in (OLLAMA, MLX):
            jobs = entry.get(runtime, {}).get("jobs")
            if jobs is None:
                continue
            route = (jobs["category"]["right"] + jobs["family"]["right"], jobs["category"]["wrong"] + jobs["family"]["wrong"])
            rule = {"judge": jobs["judge"] >= no_model["judge"], "route": route[0] >= route[1],
                    "recon": jobs["recon"]["right"] >= jobs["recon"]["wrong"],
                    "flagcheck": jobs["flagcheck"] >= no_model["flagcheck"]}
            found[(entry["id"], runtime)] = tuple(job for job, ok in rule.items() if ok)
    assert found == OFFERED_JOBS
    catalog = load_catalog()
    assert {(m.id, b.runtime): b.light_jobs for m in catalog.local for b in m.builds if b.jobs is not None} == OFFERED_JOBS


def test_the_eval_table_is_the_bundled_cases_and_what_a_run_with_no_light_model_gets_on_them():
    """The jobs tables were scored on these cases: if the bundled cases change, this fails, so
    results scored on one set are never set beside another's defaults."""
    from ctf_flightdeck.localmodel import default_cases_path, load_cases, rules_baseline

    cases = load_cases(default_cases_path())
    rules = rules_baseline(cases)

    def row(name: str) -> list:
        return [r for r in rules.results if r.row == name]

    shipped = load_catalog().eval
    category = row("route category")
    assert {key: (s.cases, s.default, s.asked) for key, s in shipped.items()} == {
        "hint": (len(row("hint")), sum(r.correct for r in row("hint")), None),
        "judge": (len(row("judge")), sum(bool(r.in_run) for r in row("judge")), None),
        "category": (len(category), sum(bool(r.in_run) for r in category), sum(1 for r in category if not r.answered)),
        "family": (len(row("route family")), None, None),
        "recon": (len(row("recon")), None, None),
        "flagcheck": (len(row("flagcheck")), sum(bool(r.in_run) for r in row("flagcheck")), None),
    }
    assert (shipped["judge"].default, shipped["category"].default, shipped["flagcheck"].default) == (8, 30, 30)


def test_every_result_in_the_shipped_catalog_says_when_and_how_it_was_measured():
    """Each measured, not_for or jobs table's comment dates its numbers and says how far they go."""
    text = (files("ctf_flightdeck") / "models.toml").read_text(encoding="utf-8")
    blocks = re.split(r"(?m)^(?=\[)", text)
    results = [block for block in blocks if re.match(r"\[local\.(ollama|mlx)\.(measured|not_for|jobs)\]\n", block)]
    tables = sum(1 for entry in tomllib.loads(text)["local"] for runtime in (OLLAMA, MLX)
                 for kind in ("measured", "not_for", "jobs") if kind in entry.get(runtime, {}))
    assert len(results) == tables == 21
    for block in results:
        comment = " ".join(line.removeprefix("#").strip() for line in block.splitlines() if line.startswith("#"))
        assert "2026-11-11, one machine, under load, one run" in comment, block


def test_the_shipped_sizes_are_the_benchmarks_records_and_nothing_else():
    catalog = load_catalog()
    sizes = {(m.id, b.runtime): b.size for m in catalog.local for b in m.builds}
    assert sizes == {  # results/<runtime>-<model>.measure.json: disk.size_bytes (Ollama), disk.weights_bytes (MLX)
        ("qwen3.5-9b", OLLAMA): 6550825550, ("qwen3.5-9b", MLX): 5950221072,
        ("gpt-oss-20b", OLLAMA): 13793441566, ("gpt-oss-20b", MLX): 12076207568,
        ("gemma4-12b", OLLAMA): 8021618941, ("gemma4-12b", MLX): 6741039511,
        ("phi4-mini", OLLAMA): 2491876774, ("phi4-mini", MLX): 2158100796,
        # the small-model measurement's results/ollama-<tag>.measure.json: disk.size_bytes
        ("gemma4-e4b", OLLAMA): 6583656505, ("gemma4-e2b", OLLAMA): 4587156505, ("qwen3.5-4b", OLLAMA): 3324173934,
        ("qwen3.5-2b", OLLAMA): 2683396812, ("qwen3.5-0.8b", OLLAMA): 1322069277,
    }
    quantizations = {(m.id, b.runtime): b.quantization for m in catalog.local for b in m.builds}
    assert quantizations == {  # `ollama show` (Ollama), disk.quantization (MLX)
        ("qwen3.5-9b", OLLAMA): "Q4_K_M", ("qwen3.5-9b", MLX): "4-bit, group size 64, affine",
        ("gpt-oss-20b", OLLAMA): "MXFP4", ("gpt-oss-20b", MLX): "MXFP4 4-bit, group size 32; 122 layers 8-bit, group size 64",
        ("gemma4-12b", OLLAMA): "Q4_K_M", ("gemma4-12b", MLX): "4-bit, group size 64, affine",
        ("phi4-mini", OLLAMA): "Q4_K_M", ("phi4-mini", MLX): "4-bit, group size 64",
        ("gemma4-e4b", OLLAMA): "Q4_K_M", ("gemma4-e2b", OLLAMA): "Q4_K_M", ("qwen3.5-4b", OLLAMA): "Q4_K_M",
        ("qwen3.5-2b", OLLAMA): "Q8_0", ("qwen3.5-0.8b", OLLAMA): "Q8_0",
    }


NO_THINKING = ("--chat-template-args", '{"enable_thinking":false}', "--max-tokens", "8192")


def test_thinking_models_are_served_as_the_benchmark_found_they_work_and_never_offered_where_they_did_not():
    catalog = load_catalog()
    # mlx_lm.server with thinking off and room to reply: the setting the benchmark measured working
    served = {(m.id, b.runtime): b.server_args for m in catalog.local for b in m.builds if b.server_args}
    assert served == {("qwen3.5-9b", MLX): NO_THINKING, ("gemma4-12b", MLX): NO_THINKING}
    # mlx_lm.server passes gpt-oss's channel format on as text; Gemma 4 12B solved no practice
    # challenge as a lane on either runtime, nor did E2B or Qwen3.5 2B and 0.8B on Ollama; Phi-4-mini
    # made no usable tool call and scored below the rules on either runtime
    refused = {(m.id, b.runtime): tuple(b.not_for) for m in catalog.local for b in m.builds if b.not_for}
    assert refused == {("gpt-oss-20b", MLX): (LANES, LIGHT), ("gemma4-12b", OLLAMA): (LANES,), ("gemma4-12b", MLX): (LANES,),
                       ("phi4-mini", OLLAMA): (LANES, LIGHT), ("phi4-mini", MLX): (LANES, LIGHT),
                       ("gemma4-e2b", OLLAMA): (LANES,), ("qwen3.5-2b", OLLAMA): (LANES,), ("qwen3.5-0.8b", OLLAMA): (LANES,)}
    assert "as text" in catalog.get("gpt-oss-20b").build(MLX).not_for[LANES]
    mac = machine(apple_mac(memory=36 * GIB))
    light = advise(catalog, mac, LIGHT)
    assert [(n.model.id, n.build.runtime) for n in light.not_for] == [
        ("gpt-oss-20b", MLX), ("phi4-mini", OLLAMA), ("phi4-mini", MLX)]
    offered = [(o.model.id, o.build.runtime) for o in (*light.fits, *light.too_big, *light.cannot_tell, *light.not_here)]
    assert offered == [("qwen3.5-9b", OLLAMA), ("qwen3.5-9b", MLX), ("gpt-oss-20b", OLLAMA), ("gemma4-12b", OLLAMA),
                       ("gemma4-12b", MLX), *((ident, OLLAMA) for ident in SMALL)]
    lanes = advise(catalog, mac, LANES)
    assert [(n.model.id, n.build and n.build.runtime) for n in lanes.not_for] == [
        ("gpt-oss-20b", MLX), ("gemma4-12b", OLLAMA), ("gemma4-12b", MLX), ("phi4-mini", OLLAMA), ("phi4-mini", MLX),
        ("gemma4-e2b", OLLAMA), ("qwen3.5-2b", OLLAMA), ("qwen3.5-0.8b", OLLAMA)]
    offered = [(o.model.id, o.build.runtime) for o in (*lanes.fits, *lanes.too_big, *lanes.cannot_tell, *lanes.not_here)]
    assert offered == [("qwen3.5-9b", OLLAMA), ("qwen3.5-9b", MLX), ("gpt-oss-20b", OLLAMA), ("gemma4-e4b", OLLAMA),
                       ("qwen3.5-4b", OLLAMA)]
    assert {m.id: m.offered_for for m in catalog.local} == {
        "qwen3.5-9b": (LANES, LIGHT), "gpt-oss-20b": (LANES, LIGHT), "gemma4-12b": (LIGHT,), "phi4-mini": (),
        "gemma4-e4b": (LANES, LIGHT), "gemma4-e2b": (LIGHT,), "qwen3.5-4b": (LANES, LIGHT), "qwen3.5-2b": (LIGHT,),
        "qwen3.5-0.8b": (LIGHT,)}


def test_the_anthropic_entry_is_inits_ladder_and_prices_imported_not_copied(monkeypatch):
    anthropic = load_catalog().get("anthropic")
    assert anthropic.ladder == setup.ANTHROPIC_LADDER and anthropic.classifier is True
    assert dict(anthropic.prices) == setup.anthropic_prices(setup.ANTHROPIC_LADDER)  # the refusal fallback's models too
    assert (anthropic.base_url, anthropic.key_env, anthropic.light_model) == (*setup.ANTHROPIC, setup.LIGHT_ANTHROPIC)
    monkeypatch.setattr(setup, "ANTHROPIC_LADDER", ("claude-haiku-5-5", "claude-opus-5-5"))
    monkeypatch.setitem(setup.ANTHROPIC_PRICES, "claude-opus-5-5", Price(input=1.0, output=2.0))
    changed = load_catalog().get("anthropic")
    assert changed.ladder == ("claude-haiku-5-5", "claude-opus-5-5")
    assert dict(changed.prices) == {"claude-haiku-5-5": setup.ANTHROPIC_PRICES["claude-haiku-5-5"],
                                    "claude-opus-5-5": Price(input=1.0, output=2.0),
                                    "claude-opus-5": setup.ANTHROPIC_PRICES["claude-opus-5"],
                                    "claude-opus-4-8": setup.ANTHROPIC_PRICES["claude-opus-4-8"]}  # no model init no longer writes


def test_openrouter_names_no_models_and_says_its_providers_classifiers_still_apply():
    openrouter = load_catalog().get("openrouter")
    assert openrouter.ladder == () and openrouter.prices == {} and openrouter.light_model == ""
    assert openrouter.models_page == "https://openrouter.ai/models" and openrouter.classifier is True
    assert "classifier" in openrouter.note and "terms" in openrouter.note
    assert (openrouter.base_url, openrouter.key_env) == setup.PROVIDERS["openrouter"]


# ---------------------------------------------------------------------- checking a catalog


BASE = one_model()


@pytest.mark.parametrize(("text", "message"), [
    ("[[local]\n", "is not valid TOML"),
    ("colour = 1\n" + BASE, "unknown top-level key colour"),
    ('[[api]]\nid = "x"\n', "has no [[local]] entries"),
    (BASE.replace('license = "MIT"\n', 'license = "MIT"\ncolour = "red"\n'), "[[local]] entry 1 (test-10g): unknown key colour"),
    (BASE.replace('license = "MIT"\n', ""), "[[local]] entry 1 (test-10g): missing license"),
    (BASE.replace('id = "test-10g"\n', ""), "[[local]] entry 1 (no id): missing id"),
    (BASE + "\n" + one_model(ident="other") + "\n" + one_model(), "id 'test-10g' is used twice: by [[local]] entry 1 and [[local]] entry 3"),
    (BASE + '\n[[api]]\nid = "test-10g"\nname = "A"\nprovider = "anthropic"\nroles = ["lanes"]\nclassifier = true\nnote = "n"\n',
     "id 'test-10g' is used twice: by [[local]] entry 1 and [[api]] entry 1"),
    (BASE.replace('id = "test-10g"', 'id = "Test 10G"'), "id must be lower-case letters"),
    (BASE.replace('model = "test-10g:q4"\n', 'model = "test-10g:q4"\ncolour = 1\n'), "[local.ollama]: unknown key colour"),
    (BASE.replace('model = "test-10g:q4"\n', ""), "[local.ollama]: missing model"),
    (BASE.replace(f"size_bytes = {TEN}", "size_bytes = -1"), "size_bytes must be a positive whole number"),
    (BASE.replace(f"size_bytes = {TEN}", 'size_bytes = "10 GB"'), "size_bytes must be a positive whole number"),
    (BASE.replace(f"size_bytes = {TEN}", "size_bytes = true"), "size_bytes must be a positive whole number"),
    (BASE.replace('roles = ["lanes", "light"]', 'roles = ["lanes", "judge"]'), "roles must list each of its roles once"),
    (BASE.replace('roles = ["lanes", "light"]', 'roles = ["light", "light"]'), "roles must list each of its roles once"),
    # measured, not_for and server_args belong to a build: results and settings differ by runtime
    (BASE.replace('license = "MIT"\n', 'license = "MIT"\nmeasured = {}\n'), "[[local]] entry 1 (test-10g): unknown key measured"),
    (one_model(roles='["light"]', ollama='measured = { lanes = "5/5" }\n'), "[local.ollama]: measured.lanes is not one of its roles"),
    (one_model(ollama='measured = { light = "" }\n'), "[local.ollama]: measured.light must be one line"),
    (one_model(ollama='measured = { light = "a\\nb" }\n'), "[local.ollama]: measured.light must be one line"),
    (one_model(ollama='measured = "5/5"\n'), "[local.ollama]: measured must be a table of role"),
    (one_model(ollama='not_for = { judge = "no" }\n'), "[local.ollama]: not_for.judge is not one of its roles"),
    (one_model(ollama='not_for = { light = " " }\n'), "[local.ollama]: not_for.light must be one line"),
    (one_model(ollama='not_for = { light = "it thinks" }\nmeasured = { light = "1/44" }\n'),
     "[local.ollama]: measured.light and not_for.light"),
    (one_model(ollama='server_args = ["--max-tokens", "8192"]\n'), "[local.ollama]: server_args is for [local.mlx] only"),
    (one_model(mlx=True, mlx_lines='server_args = "--max-tokens 8192"\n'), "[local.mlx]: server_args must list mlx_lm.server's arguments"),
    (one_model(mlx=True, mlx_lines="server_args = []\n"), "[local.mlx]: server_args must list mlx_lm.server's arguments"),
    (one_model(mlx=True, mlx_lines='server_args = ["--max-tokens", 8192]\n'), "[local.mlx]: server_args must list"),
    (one_model(mlx=True, mlx_lines='server_args = ["--port", "9000"]\n'), "[local.mlx]: server_args sets --port; the command sets"),
    (one_model(mlx=True, mlx_lines='server_args = ["--host=0.0.0.0"]\n'), "[local.mlx]: server_args sets --host=0.0.0.0"),
    (BASE.replace('parameters = "20B"', 'parameters = "twenty"'), "parameters must be a count like 9.0B"),
    (BASE.split("[local.ollama]")[0], "test-10g): names no runtime"),
    (BASE + '\n[[api]]\nid = "x"\nname = "X"\nprovider = "acme"\nroles = ["lanes"]\nclassifier = true\nnote = "n"\n',
     "[[api]] entry 1 (x): provider must be one of anthropic, openrouter"),
    (BASE + '\n[[api]]\nid = "x"\nname = "X"\nprovider = "openrouter"\nroles = ["lanes"]\nclassifier = true\nnote = "n"\n',
     "[[api]] entry 1 (x): the openrouter entry names no models, so it needs models_page"),
    (BASE + '\n[[api]]\nid = "x"\nname = "X"\nprovider = "anthropic"\nroles = ["lanes"]\nclassifier = "yes"\nnote = "n"\n',
     "[[api]] entry 1 (x): classifier must be true or false"),
    (BASE + '\n[[api]]\nid = "x"\nname = "X"\nprovider = "anthropic"\nroles = ["lanes"]\nnote = "n"\n',
     "[[api]] entry 1 (x): missing classifier"),
])
def test_a_catalog_with_a_mistake_is_refused_with_the_entry_named(text, message):
    with pytest.raises(CatalogError) as caught:
        parse_catalog(text, "models.toml")
    assert message in str(caught.value) and str(caught.value).startswith(("models.toml", "the model catalog models.toml"))


# A case set like the shipped one, and a jobs table on it: each figure exactly at flightdeck's
# default, so one answer more or less moves a job either side of the rule.
EVAL = ('[eval]\nhint = { cases = 30, default = 30 }\njudge = { cases = 14, default = 8 }\n'
        'category = { cases = 40, default = 30, asked = 9 }\nfamily = { cases = 40 }\nrecon = { cases = 30 }\n'
        'flagcheck = { cases = 40, default = 30 }\n\n')
EVEN = {"hint": "20", "judge": "8", "category": "{ right = 2, wrong = 3 }", "family": "{ right = 20, wrong = 19 }",
        "recon": "{ right = 10, wrong = 10 }", "flagcheck": "30"}


def jobs_table(**changes: str) -> str:
    """A build's jobs line (an inline table), EVEN with `changes`; a value None leaves that job out."""
    figures = {**EVEN, **changes}
    return "jobs = { " + ", ".join(f"{job} = {value}" for job, value in figures.items() if value is not None) + " }\n"


def with_jobs(**changes: str) -> str:
    return EVAL + one_model(ollama=jobs_table(**changes))


@pytest.mark.parametrize(("text", "message"), [
    (one_model(ollama=jobs_table()), "jobs needs the catalog's [eval] table"),
    (EVAL.replace("recon = { cases = 30 }\n", "") + one_model(), "[eval]: missing recon"),
    (EVAL.replace("hint = {", "summary = { cases = 14 }\nhint = {") + one_model(), "[eval]: unknown job summary"),
    (EVAL.replace("family = { cases = 40 }", "family = { cases = 40, default = 0 }") + one_model(),
     "[eval]: family must be { cases = N }"),
    (EVAL.replace("judge = { cases = 14, default = 8 }", "judge = { cases = 14, default = 15 }") + one_model(),
     "[eval]: judge.default is 15, more than its 14 cases"),
    (EVAL.replace("recon = { cases = 30 }", "recon = { cases = 0 }") + one_model(), "[eval]: recon.cases must be above 0"),
    (EVAL.replace("hint = { cases = 30, default = 30 }", "hint = { cases = 30, default = true }") + one_model(),
     "[eval]: hint must be { cases = N, default = N }"),
    (with_jobs(recon=None), "jobs: missing recon"),
    (with_jobs(summary="9"), "jobs: unknown job summary"),
    (with_jobs(judge="15"), "jobs: judge must be a whole number of right answers, 0 to its 14 cases"),
    (with_jobs(judge="-1"), "jobs: judge must be a whole number of right answers"),
    (with_jobs(flagcheck="true"), "jobs: flagcheck must be a whole number of right answers"),
    (with_jobs(recon="12"), "jobs: recon must be { right = N, wrong = N }"),
    (with_jobs(category="{ right = 5, wrong = 5 }"), "jobs: category has 10 answers, more than the 9 cases a run asks it"),
    (with_jobs(family="{ right = 1 }"), "jobs: family must be { right = N, wrong = N }"),
    (EVAL + one_model(ollama=jobs_table() + 'measured = { light = "41/44" }\n'), "measured.light and jobs"),
    (EVAL + one_model(ollama=jobs_table() + 'not_for = { light = "slow" }\n'), "not_for.light and jobs"),
    (EVAL + one_model(roles='["lanes"]', ollama=jobs_table()), "jobs are the light role's, and the model's roles leave it out"),
    (one_model(ollama='thinking = "on"\n'), "thinking must be true or false"),
    (one_model(roles='["lanes"]', ollama="thinking = true\n"), "thinking is the light role's setting"),
    (one_model(ollama='thinking = true\nnot_for = { light = "slow" }\n'), "thinking is set for the light role, which this "
                                                                        "build is not for"),
])
def test_a_catalog_with_a_mistake_in_its_jobs_eval_or_thinking_is_refused_with_the_entry_named(text, message):
    with pytest.raises(CatalogError) as caught:
        parse_catalog(text, "models.toml")
    assert message in str(caught.value), str(caught.value)
    assert str(caught.value).startswith("models.toml")


@pytest.mark.parametrize(("changes", "offered"), [
    ({}, ("judge", "route", "recon", "flagcheck")),  # every figure at flightdeck's default: no worse, so offered
    ({"judge": "7"}, ("route", "recon", "flagcheck")),  # one alert fewer right in a run than with no model
    ({"family": "{ right = 19, wrong = 20 }"}, ("judge", "recon", "flagcheck")),  # route: 21 right, 23 wrong
    ({"category": "{ right = 2, wrong = 4 }"}, ("judge", "recon", "flagcheck")),  # route: 22 right, 23 wrong
    ({"recon": "{ right = 10, wrong = 11 }"}, ("judge", "route", "flagcheck")),
    ({"flagcheck": "29"}, ("judge", "route", "recon")),  # it held a real flag more than it saved
    ({"hint": "0"}, ("judge", "route", "recon", "flagcheck")),  # hint: eval-local's only, a run uses the rules
])
def test_a_build_is_offered_for_each_run_job_it_did_no_worse_at_than_no_model(changes, offered):
    catalog = parse_catalog(with_jobs(**changes))
    build = catalog.local[0].build(OLLAMA)
    assert build.light_jobs == offered and LIGHT in build.measured and LIGHT not in build.not_for
    line = build.measured[LIGHT]
    figures = {**EVEN, **changes}
    assert f"the judge {figures['judge']}/14 in a run against 8/14 with no model" in line
    assert f"flagcheck {figures['flagcheck']}/40 in a run against 30/40 with the planted-flag hold alone" in line
    assert f"hint {figures['hint']}/30 against the rules' 30/30" in line
    left = [job for job in ("judge", "route", "recon", "flagcheck") if job not in offered]
    assert ("where it did worse than no model" in line) == bool(left)
    assert local_lines(build, LIGHT).endswith(f"jobs = [{', '.join(f'{chr(34)}{j}{chr(34)}' for j in offered)}]"
                                              f"{model_catalog.JOBS_MEASURED}\n")


def test_a_build_worse_than_no_model_at_every_job_is_not_for_the_light_role_and_says_why():
    catalog = parse_catalog(with_jobs(judge="7", category="{ right = 0, wrong = 9 }", recon="{ right = 0, wrong = 30 }",
                                      flagcheck="29"))
    model = catalog.local[0]
    build = model.build(OLLAMA)
    assert build.light_jobs == () and LIGHT not in build.measured and model.serves(build) == (LANES,)
    assert build.not_for[LIGHT].startswith("worse than no model at the judge, route, recon and flagcheck (eval-local, ")
    assert "route 20 right and 28 wrong where a run asks it" in build.not_for[LIGHT]
    light = advise(catalog, machine(apple_mac(memory=64 * GIB)), LIGHT)
    assert light.fits == () and [n.why for n in light.not_for] == [build.not_for[LIGHT]]


def test_the_light_lines_say_how_a_build_was_measured_and_which_jobs_it_is_for(tmp_path):
    """A build measured with no thinking switch gets thinking = true, eval-local's --thinking on and
    no init command (init writes thinking off); one measured on the earlier cases, the judge alone."""
    catalog = parse_catalog(one_model(ollama='thinking = true\nmeasured = { light = "eval-local 38/44" }\n'))
    model, build = catalog.local[0], catalog.local[0].build(OLLAMA)
    assert build.light_jobs == ("judge",)
    lines = local_lines(build, LIGHT)
    assert f"\nthinking = true{model_catalog.THINKING_ON}\n" in lines and lines.endswith(
        f'jobs = ["judge"]{model_catalog.JOBS_EARLIER}\n')
    assert measure_command(build, LIGHT).endswith(" --model test-10g:q4 --thinking on")
    assert init_command(model, LIGHT, build) == "" and init_command(model, LANES, build).startswith("flightdeck init")
    path = tmp_path / "config.toml"
    path.write_text('[models]\nladder = ["m"]\n' + lines)
    light = load_config(path)
    assert (light.light.thinking, light.light_jobs) == (True, ("judge",))
    plain = parse_catalog(one_model()).local[0].build(OLLAMA)  # not measured: no jobs line, no thinking line
    assert "jobs =" not in local_lines(plain, LIGHT) and "thinking" not in local_lines(plain, LIGHT)
    assert not measure_command(plain, LIGHT).endswith("--thinking on")


def test_a_catalog_file_that_cannot_be_read_is_named(tmp_path):
    with pytest.raises(CatalogError, match=r"cannot read the model catalog .*absent\.toml"):
        load_catalog(tmp_path / "absent.toml")


# ---------------------------------------------------------------------- the memory rule, at its edges


def test_apple_silicon_gives_two_thirds_of_unified_memory_and_the_need_is_weights_plus_context():
    model, build = the(one_model())
    exact = machine(apple_mac(memory=24 * GIB))  # two thirds: 16 GiB, a lane's need exactly
    plan = budget(exact)
    assert (plan.where, plan.bytes) == (APPLE, 16 * GIB) and "two thirds" in plan.why
    option = judge(model, build, LANES, exact, plan)
    assert (option.verdict, option.need) == (FITS, TEN + CONTEXT_ALLOWANCE[LANES]) and option.need == 16 * GIB
    short = machine(apple_mac(memory=24 * GIB - 2))  # two thirds: 2 bytes under 16 GiB
    assert judge(model, build, LANES, short, budget(short)).verdict == TOO_BIG
    assert judge(model, build, LIGHT, short, budget(short)).verdict == FITS  # 10 GiB + 2 GiB for the light role


def test_an_nvidia_gpu_gives_its_own_memory_and_only_the_largest_one_counts():
    model, build = the(one_model())

    def verdict(lines: str) -> str:
        box = machine(linux_box(256 * 1024 * 1024, nvidia=lines))
        return judge(model, build, LANES, box, budget(box)).verdict

    assert verdict("NVIDIA RTX A4000, 16384\n") == FITS  # 16 GiB: a lane's need exactly
    assert verdict("NVIDIA RTX A4000, 16383\n") == TOO_BIG
    assert verdict("NVIDIA GeForce RTX 3070, 8192\nNVIDIA RTX A4000, 16384\n") == FITS
    assert verdict("NVIDIA GeForce RTX 3070, 8192\nNVIDIA GeForce RTX 3070, 8192\n") == TOO_BIG  # never the sum
    box = machine(linux_box(256 * 1024 * 1024, nvidia="NVIDIA RTX A4000, 16384\n"))
    assert budget(box).where == NVIDIA and "NVIDIA RTX A4000" in budget(box).why  # not the 256 GiB of memory


def test_with_no_gpu_it_is_half_the_memory_on_the_cpu_and_slow():
    model, build = the(one_model())
    exact = machine(linux_box(32 * 1024 * 1024))  # half: 16 GiB
    plan = budget(exact)
    assert (plan.where, plan.bytes) == (CPU, 16 * GIB) and "on the CPU and will be slow" in plan.why
    assert judge(model, build, LANES, exact, plan).verdict == FITS
    short = machine(linux_box(32 * 1024 * 1024 - 1))  # 1 kB less memory
    assert judge(model, build, LANES, short, budget(short)).verdict == TOO_BIG
    intel_mac = machine(FakeHost("Darwin", "x86_64", programs={"sysctl": SYSCTL}, commands={
        (SYSCTL, "-n", "machdep.cpu.brand_string"): "Intel(R) Core(TM) i7-8850H CPU @ 2.60GHz\n",
        (SYSCTL, "-n", "hw.memsize"): f"{32 * GIB}\n"}))
    assert budget(intel_mac).where == CPU


@pytest.mark.parametrize("host", [
    apple_mac(commands={(SYSCTL, "-n", "hw.memsize"): "garbage\n"}),
    linux_box(32 * 1024 * 1024, nvidia="NVIDIA-SMI has failed\n"),
    linux_box(1, files={"/proc/meminfo": "nothing here\n"}),
    FakeHost("Darwin", "x86_64", programs={"sysctl": SYSCTL}, commands={(SYSCTL, "-n", "hw.memsize"): f"{64 * GIB}\n"}),
], ids=["mac-memory", "nvidia-smi", "linux-memory", "rosetta-unknown"])
def test_a_machine_flightdeck_cannot_read_gets_cannot_tell_never_a_number(host):
    model, build = the(one_model())
    unknown = machine(host)
    plan = budget(unknown)
    assert (plan.where, plan.bytes) == (UNKNOWN, None) and plan.why
    option = judge(model, build, LANES, unknown, plan)
    assert option.verdict == CANNOT_TELL and plan.why in option.why
    advice = advise(parse_catalog(one_model()), unknown, LANES)
    assert advice.fits == () and advice.lead == API


def test_mlx_is_for_apple_silicon_only():
    model = parse_catalog(one_model(mlx=True)).local[0]
    mlx = model.build(MLX)
    box = machine(linux_box(256 * 1024 * 1024, nvidia="NVIDIA H100 80GB HBM3, 81559\n"))
    assert judge(model, mlx, LANES, box, budget(box)).verdict == NOT_HERE
    mac = machine(apple_mac(memory=64 * GIB))
    assert judge(model, mlx, LANES, mac, budget(mac)).verdict == FITS
    rosetta = machine(FakeHost("Darwin", "x86_64", programs={"sysctl": SYSCTL},
                               commands={(SYSCTL, "-n", "hw.memsize"): f"{64 * GIB}\n"}))
    assert judge(model, mlx, LANES, rosetta, budget(rosetta)).verdict == CANNOT_TELL


def test_a_build_with_no_recorded_size_cannot_be_told_until_ollama_here_gives_one():
    model, build = the(one_model(size=None))
    mac = machine(apple_mac(memory=64 * GIB))
    option = judge(model, build, LANES, mac, budget(mac))
    assert (option.verdict, option.need, option.sized_by) == (CANNOT_TELL, None, "")
    assert "not recorded in the catalog, and Ollama here has not pulled it" in option.why
    body = b'{"models": [{"name": "test-10g:q4", "size": %d}]}' % TEN
    pulled = probe(apple_mac(memory=24 * GIB, http={OFF[OLLAMA]: (200, body)}), servers=OFF)
    option = judge(model, build, LANES, pulled, budget(pulled))
    assert (option.verdict, option.need, option.size, option.sized_by, option.present) == (FITS, 16 * GIB, TEN, SIZE_SERVER, True)
    assert "as Ollama here gives them" in option.why
    recorded_model, recorded = the(one_model(size=TEN + 1))  # the catalog's size comes first
    option = judge(recorded_model, recorded, LANES, pulled, budget(pulled))
    assert (option.verdict, option.sized_by) == (TOO_BIG, SIZE_CATALOG)


# ---------------------------------------------------------------------- what each role leads with


def test_where_local_models_run_well_a_model_that_fits_comes_first():
    catalog = parse_catalog(one_model())
    for box in (machine(apple_mac(memory=36 * GIB)), machine(linux_box(64 * 1024 * 1024, nvidia="NVIDIA L4, 23034\n"))):
        for role in (LANES, LIGHT):
            advice = advise(catalog, box, role)
            assert advice.lead == LOCAL and [o.model.id for o in advice.fits] == ["test-10g"]
            assert [a.id for a in advice.api] == []


def test_on_the_cpu_lanes_lead_with_an_api_and_the_light_role_with_the_rules_smallest_first():
    catalog = parse_catalog(one_model(ident="big", size=8 * GIB) + "\n" + one_model(ident="small", size=2 * GIB) + "\n"
                            + load_catalog_api_text())
    box = machine(linux_box(64 * 1024 * 1024))
    lanes = advise(catalog, box, LANES)
    assert lanes.lead == API and "on the CPU" in lanes.lead_why and [a.id for a in lanes.api] == ["anthropic", "openrouter"]
    light = advise(catalog, box, LIGHT)
    assert light.lead == RULES and [o.model.id for o in light.fits] == ["small", "big"]


def test_a_measured_model_comes_before_one_that_only_fits_by_size():
    catalog = parse_catalog(one_model(ident="plain") + "\n" + one_model(ident="tried", ollama='measured = { light = "28/30 hints" }\n'))
    mac = machine(apple_mac(memory=64 * GIB))
    advice = advise(catalog, mac, LIGHT)
    assert [(o.model.id, o.measured) for o in advice.fits] == [("tried", "28/30 hints"), ("plain", "")]
    assert [o.model.id for o in advise(catalog, mac, LANES).fits] == ["plain", "tried"]  # measured for light only


def test_a_result_belongs_to_the_build_it_was_measured_on():
    catalog = parse_catalog(one_model(mlx=True, mlx_lines='measured = { light = "41/44 with thinking off" }\n'))
    advice = advise(catalog, machine(apple_mac(memory=64 * GIB)), LIGHT)
    assert [(o.build.runtime, o.measured) for o in advice.fits] == [(MLX, "41/44 with thinking off"), (OLLAMA, "")]


def test_a_build_that_is_not_for_a_role_is_never_offered_for_it():
    catalog = parse_catalog(one_model(mlx=True, ollama='not_for = { light = "it thinks first" }\n'))
    model = catalog.local[0]
    for box in (machine(apple_mac(memory=64 * GIB)), machine(apple_mac(memory=8 * GIB)), machine(linux_box(1, files={}))):
        light = advise(catalog, box, LIGHT)
        offered = [*light.fits, *light.too_big, *light.cannot_tell, *light.not_here]
        assert [o.build.runtime for o in offered] == [MLX]
        assert [(n.model.id, n.build.runtime, n.why) for n in light.not_for] == [("test-10g", OLLAMA, "it thinks first")]
        lanes = advise(catalog, box, LANES)
        assert sorted(o.build.runtime for o in (*lanes.fits, *lanes.too_big, *lanes.cannot_tell, *lanes.not_here)) == [MLX, OLLAMA]
        assert lanes.not_for == ()
    assert model.serves(model.build(OLLAMA)) == (LANES,) and model.serves(model.build(MLX)) == (LANES, LIGHT)
    with pytest.raises(ValueError, match="does not serve light"):
        judge(model, model.build(OLLAMA), LIGHT, machine(apple_mac()), budget(machine(apple_mac())))


def test_a_model_is_offered_for_the_roles_at_least_one_of_its_builds_serves():
    def offered(ollama: str = "", mlx_lines: str = "", roles: str = '["lanes", "light"]') -> tuple[str, ...]:
        return parse_catalog(one_model(mlx=True, ollama=ollama, mlx_lines=mlx_lines, roles=roles)).local[0].offered_for

    assert offered() == (LANES, LIGHT)
    assert offered(ollama='not_for = { lanes = "0 of 4" }\n') == (LANES, LIGHT)  # its MLX build still serves lanes
    assert offered(ollama='not_for = { lanes = "0 of 4" }\n', mlx_lines='not_for = { lanes = "0 of 4" }\n') == (LIGHT,)
    assert offered(ollama='not_for = { lanes = "a", light = "b" }\n', mlx_lines='not_for = { lanes = "c", light = "d" }\n') == ()
    assert offered(roles='["light"]') == (LIGHT,)


def test_a_model_whose_roles_leave_one_out_is_not_for_it_with_its_roles_named():
    catalog = parse_catalog(one_model(ident="small", size=2 * GIB, roles='["light"]') + "\n" + one_model())
    lanes = advise(catalog, machine(apple_mac(memory=64 * GIB)), LANES)
    assert [(n.model.id, n.build, n.why) for n in lanes.not_for] == [("small", None, "the catalog lists it for the light role only")]
    assert [o.model.id for o in lanes.fits] == ["test-10g"]


def test_a_build_that_is_not_for_the_role_is_not_counted_as_one_that_fits():
    """On an 8 GB Mac only a small model fits, and the catalog does not offer it for the light role
    (it scored below the rules): nothing the catalog offers fits, and the reason says so."""
    weak = one_model(ident="weak", size=2 * GIB, ollama='not_for = { light = "eval-local 18/44, below the rules\' 38/44" }\n')
    catalog = parse_catalog(weak + "\n" + one_model(ident="big", size=40 * GIB))
    small_mac = machine(apple_mac(memory=8 * GIB, chip="Apple M1"))  # 5.3 GiB: weak's 2 GiB + 2 GiB would fit
    light = advise(catalog, small_mac, LIGHT)
    assert (light.lead, light.fits, [o.model.id for o in light.too_big]) == (RULES, (), ["big"])
    assert light.lead_why == "No model the catalog offers for the light role is known to fit this machine."
    assert [(n.model.id, n.why) for n in light.not_for] == [("weak", "eval-local 18/44, below the rules' 38/44")]
    lanes = advise(catalog, small_mac, LANES)
    assert (lanes.lead, lanes.lead_why) == (API, "No model the catalog offers for lanes is known to fit this machine.")


def test_when_nothing_fits_lanes_lead_with_an_api_and_the_light_role_with_the_rules():
    catalog = parse_catalog(one_model(size=40 * GIB))
    small_mac = machine(apple_mac(memory=8 * GIB, chip="Apple M1"))
    assert advise(catalog, small_mac, LANES).lead == API
    advice = advise(catalog, small_mac, LIGHT)
    assert advice.lead == RULES and [o.model.id for o in advice.too_big] == ["test-10g"]


def load_catalog_api_text() -> str:
    return ('[[api]]\nid = "anthropic"\nname = "A"\nprovider = "anthropic"\nroles = ["lanes", "light"]\nclassifier = true\n'
            'note = "n"\n\n[[api]]\nid = "openrouter"\nname = "O"\nprovider = "openrouter"\nroles = ["lanes", "light"]\n'
            'classifier = true\nmodels_page = "https://openrouter.ai/models"\nnote = "n"\n')


# ---------------------------------------------------------------------- the commands, and the config lines


QWEN_MLX_SERVER = ("mlx_lm.server --model mlx-community/Qwen3.5-9B-MLX-4bit --host 127.0.0.1 --port 8080 "
                   "--chat-template-args '{\"enable_thinking\":false}' --max-tokens 8192")


def test_the_commands_that_get_a_model():
    catalog = load_catalog()
    qwen = catalog.get("qwen3.5-9b")
    bare = machine(apple_mac())  # neither Ollama nor mlx_lm is installed
    assert get_commands(qwen.build(OLLAMA), bare) == [
        "# Ollama is not on PATH: install it first (https://ollama.com/download)", "ollama pull qwen3.5:9b"]
    assert get_commands(qwen.build(MLX), bare)[0].startswith("uv tool install mlx-lm")
    assert get_commands(qwen.build(MLX), bare)[1] == QWEN_MLX_SERVER
    ready = machine(apple_mac(programs={"ollama": "/opt/homebrew/bin/ollama", "mlx_lm.server": "/opt/bin/mlx_lm.server"}))
    assert get_commands(qwen.build(OLLAMA), ready) == ["ollama pull qwen3.5:9b"]
    assert get_commands(qwen.build(MLX), ready) == [
        QWEN_MLX_SERVER, "# keep the arguments after --port 8080: the benchmark behind docs/MODELS.md served it with them"]
    # the shell gives mlx_lm.server exactly the catalog's arguments, after the address flightdeck uses
    assert shlex.split(QWEN_MLX_SERVER) == ["mlx_lm.server", "--model", "mlx-community/Qwen3.5-9B-MLX-4bit", "--host",
                                            "127.0.0.1", "--port", "8080", *NO_THINKING]
    phi = catalog.get("phi4-mini").build(MLX)  # served as it comes: nothing to keep
    assert get_commands(phi, ready) == ["mlx_lm.server --model mlx-community/Phi-4-mini-instruct-4bit --host 127.0.0.1 --port 8080"]
    assert measure_command(qwen.build(MLX), LIGHT) == (
        "flightdeck eval-local --engine openai --base-url http://127.0.0.1:8080/v1 --model mlx-community/Qwen3.5-9B-MLX-4bit")


def test_mlx_counts_as_missing_when_its_program_is_not_on_path_even_with_the_package_importable():
    qwen = load_catalog().get("qwen3.5-9b").build(MLX)
    package_only = machine(apple_mac(importable=["mlx_lm"]))  # flightdeck's Python has mlx_lm; the shell has no mlx_lm.server
    assert package_only.runtime(MLX).installed and package_only.runtime(MLX).program is None
    commands = get_commands(qwen, package_only)
    assert commands[0].startswith("uv tool install mlx-lm") and commands[1] == QWEN_MLX_SERVER


def without(text: str, *tables: str) -> str:
    """A config's text without the named tables ("prices" drops every [prices."..."] table)."""
    out, dropping = [], False
    for line in text.splitlines(keepends=True):
        header = re.match(r"\[([a-z_]+)", line)
        if header:
            dropping = header.group(1) in tables
        if not dropping:
            out.append(line)
    return "".join(out)


INIT_CONFIG = setup.render(setup.Answers(
    "https://api.anthropic.com", "ANTHROPIC_API_KEY", setup.ANTHROPIC_LADDER, "host", provider="anthropic",
    prices=setup.anthropic_prices(setup.ANTHROPIC_LADDER),
    fallback=setup.anthropic_fallback(setup.ANTHROPIC_LADDER),
    light=setup.LightAnswers("anthropic", "claude-haiku-5-5", *setup.ANTHROPIC, setup.ANTHROPIC_PRICES["claude-haiku-5-5"]),
))
LANE_TABLES = ("api", "models", "prices", "fallback")  # what `flightdeck models` says the lane lines replace


SERVED = [(m.id, b.runtime, role) for m in load_catalog().local for b in m.builds for role in m.serves(b)]  # what it offers
URLS = {OLLAMA: "http://127.0.0.1:11434/v1", MLX: "http://127.0.0.1:8080/v1"}  # each runtime's server, as config.py names it


@pytest.mark.parametrize(("ident", "runtime", "role"), SERVED)
def test_a_local_models_config_lines_replace_the_tables_they_name_and_load(ident, runtime, role, tmp_path):
    model = load_catalog().get(ident)
    build = model.build(runtime)
    url = URLS[runtime]
    path = tmp_path / "config.toml"
    if role == LANES:
        path.write_text(without(INIT_CONFIG, *LANE_TABLES) + "\n" + local_lines(build, LANES))
        config = load_config(path)
        assert (config.api.provider, config.api.base_url, config.api.key_env) == ("openai", url, "")
        assert config.models == (build.model,) and config.prices == {} and config.fallback is None
    else:
        path.write_text(without(INIT_CONFIG, "light") + "\n" + local_lines(build, LIGHT))
        config = load_config(path)
        light = config.light
        assert (light.engine, light.model, light.base_url, light.key_env) == ("openai", build.model, url, "")
        # the jobs it is offered for, with the thinking it was measured with
        assert config.light_jobs == (build.light_jobs or DEFAULT_JOBS) and light.thinking == build.thinking


def test_the_api_config_lines_replace_the_tables_they_name_and_load(tmp_path):
    catalog = load_catalog()
    local = without(INIT_CONFIG, *LANE_TABLES) + "\n" + local_lines(catalog.get("qwen3.5-9b").build(OLLAMA), LANES)
    anthropic = catalog.get("anthropic")
    config = parse_config(without(local, *LANE_TABLES) + "\n" + api_lines(anthropic, LANES), tmp_path / "c.toml")
    assert (config.api.provider, config.api.base_url, config.api.key_env) == ("anthropic", *setup.ANTHROPIC)
    assert config.models == setup.ANTHROPIC_LADDER
    assert config.prices == setup.anthropic_prices(setup.ANTHROPIC_LADDER)  # each with its cache rates, as init writes them
    light = parse_config(without(local, "light") + "\n" + api_lines(anthropic, LIGHT), tmp_path / "c.toml").light
    assert (light.engine, light.model, light.key_env, light.price) == (
        "anthropic", setup.LIGHT_ANTHROPIC, "ANTHROPIC_API_KEY", setup.ANTHROPIC_PRICES[setup.LIGHT_ANTHROPIC])
    openrouter = catalog.get("openrouter")
    config = parse_config(without(local, *LANE_TABLES) + "\n" + api_lines(openrouter, LANES), tmp_path / "c.toml")
    assert (config.api.base_url, config.api.key_env) == setup.PROVIDERS["openrouter"]
    assert config.models == ("VENDOR/SMALL-MODEL", "VENDOR/BIG-MODEL")  # placeholders, in capitals, to replace
    light = parse_config(without(local, "light") + "\n" + api_lines(openrouter, LIGHT), tmp_path / "c.toml").light
    assert (light.engine, light.model, light.base_url) == ("openai", "VENDOR/MODEL", "https://openrouter.ai/api/v1")


@pytest.mark.parametrize(("ident", "runtime", "role"), [*SERVED, ("anthropic", None, LANES), ("anthropic", None, LIGHT)])
def test_the_init_command_it_suggests_writes_a_config_with_that_choice(ident, runtime, role, tmp_path):
    """The model, and the server it is on: an MLX build's config must ask the MLX server, not Ollama's."""
    choice = load_catalog().get(ident)
    build = choice.build(runtime) if runtime else None
    command = init_command(choice, role, build)
    if not command:  # init writes a light model on this machine with thinking off: never one measured with it on
        assert role == LIGHT and build is not None and build.thinking is True
        return
    target = tmp_path / "config.toml"
    args = [*shlex.split(command)[1:], "--host", "--path", str(target)]
    if role == LIGHT and "--provider" not in args:
        args += ["--provider", "local", "--models", "some-model"]
    result = CliRunner().invoke(cli.app, args)
    assert result.exit_code == 0, result.output
    config = load_config(target)
    if build is None:  # the Anthropic API
        if role == LANES:
            assert (config.api.provider, config.api.base_url, config.api.key_env) == ("anthropic", *setup.ANTHROPIC)
            assert config.models == setup.ANTHROPIC_LADDER
        else:
            assert (config.light.engine, config.light.model, config.light.base_url, config.light.key_env) == (
                "anthropic", setup.LIGHT_ANTHROPIC, *setup.ANTHROPIC)
    elif role == LANES:
        assert (config.api.base_url, config.api.key_env, config.models) == (URLS[build.runtime], "", (build.model,))
    else:
        light = config.light
        assert (light.engine, light.model, light.base_url, light.key_env) == ("openai", build.model, URLS[build.runtime], "")
