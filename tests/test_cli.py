"""The `flightdeck` command line, including the headless screenshot mode."""

from __future__ import annotations

from typer.testing import CliRunner

from ctf_flightdeck.cli import app

runner = CliRunner()

KEY_MOMENTS = ("wave-drop", "alert-", "detail-pane", "team-stop", "approve-submit")


def invoke(*args: str):
    return runner.invoke(app, list(args), prog_name="flightdeck")


def test_version():
    result = invoke("--version")
    assert result.exit_code == 0
    assert result.stdout.strip() == "flightdeck 0.0.0"


def test_no_command_shows_help_and_fails():
    result = invoke()
    assert result.exit_code == 2
    assert "mock" in result.output


def test_unknown_scenario_is_a_usage_error_naming_the_choices():
    result = invoke("mock", "--scenario", "nope")
    assert result.exit_code == 2
    assert "overthinking" in result.stderr and "default" in result.stderr


def test_max_lanes_must_be_at_least_one():
    result = invoke("mock", "--max-lanes", "0")
    assert result.exit_code == 2
    assert "--max-lanes" in result.stderr


def test_screenshot_dir_that_is_a_file_is_rejected(tmp_path):
    target = tmp_path / "not-a-dir"
    target.write_text("x")
    result = invoke("mock", "--screenshot", str(target))
    assert result.exit_code == 2


def test_screenshot_mode_saves_every_key_moment_of_the_default_scenario(tmp_path):
    out = tmp_path / "shots"
    result = invoke("mock", "--screenshot", str(out))
    assert result.exit_code == 0, result.output
    names = sorted(p.name for p in out.glob("*.svg"))
    for moment in KEY_MOMENTS:
        assert any(moment in name for name in names), f"no screenshot for {moment}: {names}"
    assert all((out / name).read_text().startswith("<svg") for name in names)
    assert result.stdout.splitlines() == [str(out / name) for name in names]
    assert "skipped" not in result.stderr


def test_screenshot_mode_reports_moments_a_scenario_does_not_have(tmp_path):
    result = invoke("mock", "--scenario", "flag", "--solo", "--screenshot", str(tmp_path))
    assert result.exit_code == 0, result.output
    assert "skipped team-stop: solo mode" in result.stderr
    assert "skipped wave-drop" in result.stderr
    assert any("approve-submit" in p.name for p in tmp_path.glob("*.svg"))


def test_screenshots_are_the_same_on_every_run(tmp_path):
    first, second = tmp_path / "a", tmp_path / "b"
    for out in (first, second):
        assert invoke("mock", "--scenario", "flag", "--screenshot", str(out)).exit_code == 0
    names = sorted(p.name for p in first.glob("*.svg"))
    assert names == sorted(p.name for p in second.glob("*.svg"))
    for name in names:
        assert (first / name).read_bytes() == (second / name).read_bytes(), name


def test_host_flag_shows_host_in_the_header(tmp_path):
    result = invoke("mock", "--scenario", "flag", "--host", "--screenshot", str(tmp_path))
    assert result.exit_code == 0
    first = sorted(tmp_path.glob("*.svg"))[0].read_text()
    assert ">host<" in first and ">docker<" not in first
