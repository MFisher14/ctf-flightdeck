"""The model catalog (models.toml): what it holds, how it is checked, and which of its models
fit a machine for each role. Machines are fakes (fake_host.py); nothing is probed or fetched."""

from __future__ import annotations

import re

import pytest
from fake_host import GIB, FakeHost, apple_mac, linux_box
from typer.testing import CliRunner

from ctf_flightdeck import cli, setup
from ctf_flightdeck.config import load_config, parse_config
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


def one_model(size: int | None = TEN, *, mlx: bool = False, measured: str = "", ident: str = "test-10g",
              roles: str = '["lanes", "light"]') -> str:
    size_line = f"size_bytes = {size}\n" if size is not None else ""
    out = (f'[[local]]\nid = "{ident}"\nname = "Test 10G"\nfamily = "Test"\nparameters = "20B"\nlicense = "MIT"\n'
           f"roles = {roles}\nmeasured = {{{measured}}}\n\n[local.ollama]\nmodel = \"{ident}:q4\"\n{size_line}")
    if mlx:
        out += f'\n[local.mlx]\nmodel = "test/{ident}-4bit"\n{size_line}'
    return out


def the(catalog_text: str):
    catalog = parse_catalog(catalog_text)
    model = catalog.local[0]
    return model, model.builds[0]


# ---------------------------------------------------------------------- the shipped catalog


def test_the_shipped_catalog_has_the_four_benchmarked_models_on_ollama_and_mlx():
    catalog = load_catalog()
    builds = {m.id: {b.runtime: b.model for b in m.builds} for m in catalog.local}
    assert builds == {
        "qwen3.5-9b": {OLLAMA: "qwen3.5:9b", MLX: "mlx-community/Qwen3.5-9B-MLX-4bit"},
        "gpt-oss-20b": {OLLAMA: "gpt-oss:20b", MLX: "mlx-community/gpt-oss-20b-MXFP4-Q8"},
        "gemma4-12b": {OLLAMA: "gemma4:12b", MLX: "mlx-community/gemma-4-12B-it-4bit"},
        "phi4-mini": {OLLAMA: "phi4-mini", MLX: "mlx-community/Phi-4-mini-instruct-4bit"},
    }
    assert all(m.measured == {} for m in catalog.local)  # filled from docs/MODELS.md, never invented
    assert [a.id for a in catalog.api] == ["anthropic", "openrouter"]


def test_the_shipped_sizes_are_the_benchmarks_records_and_nothing_else():
    catalog = load_catalog()
    sizes = {(m.id, b.runtime): b.size for m in catalog.local for b in m.builds}
    assert sizes == {
        ("qwen3.5-9b", OLLAMA): 6550825550, ("qwen3.5-9b", MLX): 5950221072,
        ("phi4-mini", OLLAMA): 2491876774, ("phi4-mini", MLX): 2158100796,
        # the benchmark recorded no size for these: left out, never estimated
        ("gpt-oss-20b", OLLAMA): None, ("gpt-oss-20b", MLX): None, ("gemma4-12b", OLLAMA): None, ("gemma4-12b", MLX): None,
    }
    assert catalog.get("gpt-oss-20b").build(MLX).quantization is None


def test_the_anthropic_entry_is_inits_ladder_and_prices_imported_not_copied(monkeypatch):
    anthropic = load_catalog().get("anthropic")
    assert anthropic.ladder == setup.ANTHROPIC_LADDER and anthropic.classifier is True
    assert dict(anthropic.prices) == {m: setup.ANTHROPIC_PRICES[m] for m in setup.ANTHROPIC_LADDER}
    assert (anthropic.base_url, anthropic.key_env, anthropic.light_model) == (*setup.ANTHROPIC, setup.LIGHT_ANTHROPIC)
    monkeypatch.setattr(setup, "ANTHROPIC_LADDER", ("claude-haiku-5-5", "claude-opus-5-5"))
    monkeypatch.setitem(setup.ANTHROPIC_PRICES, "claude-opus-5-5", Price(input=1.0, output=2.0))
    changed = load_catalog().get("anthropic")
    assert changed.ladder == ("claude-haiku-5-5", "claude-opus-5-5")
    assert dict(changed.prices) == {"claude-haiku-5-5": setup.ANTHROPIC_PRICES["claude-haiku-5-5"],
                                    "claude-opus-5-5": Price(input=1.0, output=2.0)}  # no model init no longer writes


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
    (one_model(roles='["light"]', measured='lanes = "5/5"'), "measured.lanes is not one of its roles"),
    (one_model(measured='light = ""'), "measured.light must be a one-line result"),
    (one_model(measured='light = "a\\nb"'), "measured.light must be a one-line result"),
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
    catalog = parse_catalog(one_model(ident="plain") + "\n" + one_model(ident="tried", measured='light = "28/30 hints"'))
    mac = machine(apple_mac(memory=64 * GIB))
    advice = advise(catalog, mac, LIGHT)
    assert [(o.model.id, o.measured) for o in advice.fits] == [("tried", "28/30 hints"), ("plain", "")]
    assert [o.model.id for o in advise(catalog, mac, LANES).fits] == ["plain", "tried"]  # measured for light only


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


def test_the_commands_that_get_a_model():
    catalog = load_catalog()
    qwen = catalog.get("qwen3.5-9b")
    bare = machine(apple_mac())  # neither Ollama nor mlx_lm is installed
    assert get_commands(qwen.build(OLLAMA), bare) == [
        "# Ollama is not on PATH: install it first (https://ollama.com/download)", "ollama pull qwen3.5:9b"]
    assert get_commands(qwen.build(MLX), bare)[0].startswith("uv tool install mlx-lm")
    assert get_commands(qwen.build(MLX), bare)[-1] == (
        "mlx_lm.server --model mlx-community/Qwen3.5-9B-MLX-4bit --host 127.0.0.1 --port 8080")
    ready = machine(apple_mac(programs={"ollama": "/opt/homebrew/bin/ollama", "mlx_lm.server": "/opt/bin/mlx_lm.server"}))
    assert get_commands(qwen.build(OLLAMA), ready) == ["ollama pull qwen3.5:9b"]
    assert get_commands(qwen.build(MLX), ready) == ["mlx_lm.server --model mlx-community/Qwen3.5-9B-MLX-4bit --host 127.0.0.1 --port 8080"]
    assert measure_command(qwen.build(MLX), LIGHT) == (
        "flightdeck eval-local --engine openai --base-url http://127.0.0.1:8080/v1 --model mlx-community/Qwen3.5-9B-MLX-4bit")


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
    prices={m: setup.ANTHROPIC_PRICES[m] for m in setup.ANTHROPIC_LADDER},
    fallback=setup.anthropic_fallback(setup.ANTHROPIC_LADDER),
    light=setup.LightAnswers("anthropic", "claude-haiku-5-5", *setup.ANTHROPIC, setup.ANTHROPIC_PRICES["claude-haiku-5-5"]),
))
LANE_TABLES = ("api", "models", "prices", "fallback")  # what `flightdeck models` says the lane lines replace


@pytest.mark.parametrize(("ident", "runtime"), [(m.id, b.runtime) for m in load_catalog().local for b in m.builds])
def test_a_local_models_config_lines_replace_the_tables_they_name_and_load(ident, runtime, tmp_path):
    model = load_catalog().get(ident)
    build = model.build(runtime)
    url = {OLLAMA: "http://127.0.0.1:11434/v1", MLX: "http://127.0.0.1:8080/v1"}[runtime]
    path = tmp_path / "config.toml"
    if LANES in model.roles:
        path.write_text(without(INIT_CONFIG, *LANE_TABLES) + "\n" + local_lines(build, LANES))
        config = load_config(path)
        assert (config.api.provider, config.api.base_url, config.api.key_env) == ("openai", url, "")
        assert config.models == (build.model,) and config.prices == {} and config.fallback is None
    path.write_text(without(INIT_CONFIG, "light") + "\n" + local_lines(build, LIGHT))
    light = load_config(path).light
    assert (light.engine, light.model, light.base_url, light.key_env) == ("openai", build.model, url, "")


def test_the_api_config_lines_replace_the_tables_they_name_and_load(tmp_path):
    catalog = load_catalog()
    local = without(INIT_CONFIG, *LANE_TABLES) + "\n" + local_lines(catalog.get("qwen3.5-9b").build(OLLAMA), LANES)
    anthropic = catalog.get("anthropic")
    config = parse_config(without(local, *LANE_TABLES) + "\n" + api_lines(anthropic, LANES), tmp_path / "c.toml")
    assert (config.api.provider, config.api.base_url, config.api.key_env) == ("anthropic", *setup.ANTHROPIC)
    assert config.models == setup.ANTHROPIC_LADDER
    assert config.prices == {m: setup.ANTHROPIC_PRICES[m] for m in setup.ANTHROPIC_LADDER}
    light = parse_config(without(local, "light") + "\n" + api_lines(anthropic, LIGHT), tmp_path / "c.toml").light
    assert (light.engine, light.model, light.key_env, light.price) == (
        "anthropic", setup.LIGHT_ANTHROPIC, "ANTHROPIC_API_KEY", setup.ANTHROPIC_PRICES[setup.LIGHT_ANTHROPIC])
    openrouter = catalog.get("openrouter")
    config = parse_config(without(local, *LANE_TABLES) + "\n" + api_lines(openrouter, LANES), tmp_path / "c.toml")
    assert (config.api.base_url, config.api.key_env) == setup.PROVIDERS["openrouter"]
    assert config.models == ("VENDOR/SMALL-MODEL", "VENDOR/BIG-MODEL")  # placeholders, in capitals, to replace
    light = parse_config(without(local, "light") + "\n" + api_lines(openrouter, LIGHT), tmp_path / "c.toml").light
    assert (light.engine, light.model, light.base_url) == ("openai", "VENDOR/MODEL", "https://openrouter.ai/api/v1")


@pytest.mark.parametrize(("ident", "runtime", "role"), [
    ("qwen3.5-9b", OLLAMA, LANES), ("qwen3.5-9b", MLX, LANES), ("phi4-mini", OLLAMA, LIGHT), ("gemma4-12b", MLX, LIGHT),
    ("anthropic", None, LANES), ("anthropic", None, LIGHT),
])
def test_the_init_command_it_suggests_writes_a_config_with_that_choice(ident, runtime, role, tmp_path):
    choice = load_catalog().get(ident)
    build = choice.build(runtime) if runtime else None
    command = init_command(choice, role, build)
    target = tmp_path / "config.toml"
    args = [*command.split()[1:], "--host", "--path", str(target)]
    if role == LIGHT and "--provider" not in args:
        args += ["--provider", "local", "--models", "some-model"]
    result = CliRunner().invoke(cli.app, args)
    assert result.exit_code == 0, result.output
    config = load_config(target)
    if role == LANES:
        assert config.models == ((build.model,) if build else setup.ANTHROPIC_LADDER)
    else:
        assert config.light.model == (build.model if build else setup.LIGHT_ANTHROPIC)
