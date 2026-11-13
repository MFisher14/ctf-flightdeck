"""SH-01: the venv must hold every pin in requirements.in, and only the J2735 tests may be not-run.

The checker's logic is tested against synthetic pin files and a fake version lookup; then the real
requirements.in is checked against the running venv. That last test is the suite-health guard: when
a pin is added without being installed it fails, naming each package and the fix command, instead of
the drift surfacing as collection errors and ModuleNotFoundError in unrelated engine tests.
"""
from __future__ import annotations

import subprocess
import sys
from importlib import metadata
from pathlib import Path

import pytest

from ctf import paths

import venv_pins

ROOT = paths.repo_root()

J2735_TESTS = {
    "test_usdot_published_bsm_vector",
    "test_j2735_bsm_unavailable_sentinels_stay_unavailable",
    "test_usdot_published_spat_vector",
    "test_usdot_jpo_ode_published_srm_vector",
    "test_usdot_jpo_ode_published_ssm_vector",
    "test_map_minimal_usdot_pycrate_encoder_oracle",
    "test_tim_advisory_usdot_pycrate_encoder_oracle",
    "test_j2735_direct_tim_and_noncanonical_open_type",
}


# --- parse_pins ------------------------------------------------------------------------------

def test_parse_pins_reads_pins_and_skips_comments_and_blanks() -> None:
    text = "# header\n\nfoo==1.2.3\n  bar-baz==0.1  # trailing note\ndissect.ntfs==3.16\n"
    assert venv_pins.parse_pins(text) == {"foo": "1.2.3", "bar-baz": "0.1", "dissect.ntfs": "3.16"}


@pytest.mark.parametrize("line", [
    "foo>=1.0", "foo", "foo==", "-r other.txt", "foo[extra]==1.0", "foo==1.0; python_version>'3'",
    "git+https://example.invalid/x.git", "foo == 1.0",
])
def test_parse_pins_rejects_anything_but_an_exact_pin(line: str) -> None:
    with pytest.raises(venv_pins.PinFileError, match=r"reqs:2: not an exact pin"):
        venv_pins.parse_pins(f"ok==1\n{line}\n", "reqs")


def test_parse_pins_rejects_a_package_pinned_twice_under_any_spelling() -> None:
    with pytest.raises(venv_pins.PinFileError, match=r"reqs:3: dissect-NTFS is pinned twice \(first on line 1\)"):
        venv_pins.parse_pins("dissect.ntfs==3.16\nother==1\ndissect-NTFS==3.15\n", "reqs")


# --- drift -----------------------------------------------------------------------------------

def test_drift_names_missing_and_mismatched_pins_in_file_order() -> None:
    installed = {"same": "1.0", "older": "0.9"}
    found = venv_pins.drift({"absent": "2.0", "same": "1.0", "older": "1.0"}, installed.get)
    assert [(d.name, d.pinned, d.installed, d.kind) for d in found] == [
        ("absent", "2.0", None, "MISSING"),
        ("older", "1.0", "0.9", "MISMATCH"),
    ]
    assert found[0].line() == "MISSING  absent==2.0: not installed"
    assert found[1].line() == "MISMATCH older==1.0: 0.9 installed"


def test_drift_is_empty_when_every_pin_matches() -> None:
    assert venv_pins.drift({"a": "1", "b": "2"}, {"a": "1", "b": "2"}.get) == []


def test_install_command_pins_exactly_the_drifted_packages() -> None:
    found = [venv_pins.Drift("absent", "2.0", None), venv_pins.Drift("older", "1.0", "0.9")]
    cmd = venv_pins.install_command(found)
    assert cmd == f"uv pip install --python {sys.executable} absent==2.0 older==1.0"


def test_installed_version_reads_the_real_venv() -> None:
    assert venv_pins.installed_version("pytest") == metadata.version("pytest")
    assert venv_pins.installed_version("sh01-no-such-package-xyz") is None


# --- the command line ------------------------------------------------------------------------

def _run(req: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(ROOT / "tools" / "venv_pins.py"), "--requirements", str(req)],
                          capture_output=True, text=True, timeout=60)


def test_cli_exit_0_when_pins_are_installed(tmp_path: Path) -> None:
    req = tmp_path / "requirements.in"
    req.write_text(f"# ok\npytest=={metadata.version('pytest')}\n")
    proc = _run(req)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.startswith("OK every pin")


def test_cli_exit_1_names_drift_and_the_fix(tmp_path: Path) -> None:
    req = tmp_path / "requirements.in"
    req.write_text(f"pytest=={metadata.version('pytest')}\nsh01-no-such-package-xyz==1.0\npytest-xdist==0.0.1\n")
    proc = _run(req)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    lines = proc.stdout.splitlines()
    assert lines[0] == "MISSING  sh01-no-such-package-xyz==1.0: not installed"
    assert lines[1] == f"MISMATCH pytest-xdist==0.0.1: {metadata.version('pytest-xdist')} installed"
    assert lines[2].startswith("FIX  uv pip install --python ")
    assert lines[2].endswith(" sh01-no-such-package-xyz==1.0 pytest-xdist==0.0.1")
    assert len(lines) == 3


@pytest.mark.parametrize("content, reason", [
    ("pytest>=1\n", "not an exact pin"),
    (None, "requirements file not found"),
])
def test_cli_exit_2_on_an_invalid_or_missing_file(tmp_path: Path, content: str | None, reason: str) -> None:
    req = tmp_path / "requirements.in"
    if content is not None:
        req.write_text(content)
    proc = _run(req)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert reason in proc.stderr and proc.stdout == ""


# --- the suite-health guard ------------------------------------------------------------------

def test_every_requirements_in_pin_is_installed_in_this_venv() -> None:
    found = venv_pins.check(ROOT / "requirements.in")
    assert found == [], "the venv is behind requirements.in:\n" + "\n".join(
        d.line() for d in found) + "\nfix: " + venv_pins.install_command(found)


def test_requirements_in_pins_the_test_oracles_sh01_installed() -> None:
    # crccheck and hl7apy were imported at module level by tests/test_harden_sectorA_health.py but
    # pinned nowhere; the rest were pinned and simply not installed. (requirements.txt agreement is
    # R-14's generator check, not repeated here.)
    pins = {venv_pins.normalise(k): v for k, v in
            venv_pins.parse_pins((ROOT / "requirements.in").read_text(), "requirements.in").items()}
    expected = {
        "crccheck": "1.3.1", "hl7apy": "1.3.5", "ecoji": "0.1.1", "smpplib": "2.2.4", "mt-940": "5.1.3",
        "sarpy": "2.1.1", "base2048": "0.1.3", "base65536": "0.1.1", "simplefix": "1.0.17",
        "dissect-ntfs": "3.16", "ggwave": "0.4.3", "pydicom": "3.0.2", "psec": "1.3.0", "pyrad": "2.6.0",
        "pycrate": "0.8.1", "canopen": "2.4.1", "gurux-dlms": "1.0.203", "pyais": "3.3.1",
    }
    assert {k: pins.get(k) for k in expected} == expected


def test_j2735_schema_is_in_no_requirements_file() -> None:
    # j2735_202409 is not on PyPI; it is built from git by hand (docs/build-log/SH-01.md).
    for name in ("requirements.in", "requirements.txt", "requirements.lock.txt"):
        text = (ROOT / name).read_text().lower()
        assert "j2735" not in text, name


def test_only_the_eight_j2735_tests_are_gated_on_the_schema_package() -> None:
    import test_sec_v2x_protocols as v2x

    gated, ungated_tests = set(), set()
    for name, obj in vars(v2x).items():
        if not name.startswith("test_") or not callable(obj):
            continue
        tools = [arg for mark in getattr(obj, "pytestmark", []) if mark.name == "needs_tool" for arg in mark.args]
        if tools:
            assert tools == ["py:j2735_202409"], (name, tools)
            gated.add(name)
        else:
            ungated_tests.add(name)
    assert gated == J2735_TESTS
    # The 17 other test functions (25 items with parametrisation) must always run.
    assert len(ungated_tests) == 17, sorted(ungated_tests)
    assert "test_etsi_cam_real_uper_oracle" in ungated_tests
