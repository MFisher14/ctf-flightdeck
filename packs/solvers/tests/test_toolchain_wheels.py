"""B-188: the pre-provisioned wheelhouse (ctf/toolchain/wheels.py) and paths.wheelhouse_dir()."""
from __future__ import annotations

from pathlib import Path

import pytest

from ctf import paths
from ctf.toolchain import wheels

REQ = "capstone==5.0.9\ndissect.ntfs==3.16\npdfminer-six==20260107\nrequests==2.34.2  # c\n"


@pytest.mark.parametrize("name, want", [
    ("capstone-5.0.9-py3-none-macosx_11_0_arm64.whl", ("capstone", "5.0.9")),
    ("dissect_ntfs-3.16-py3-none-any.whl", ("dissect-ntfs", "3.16")),
    ("pdfminer_six-20260107-py3-none-any.whl", ("pdfminer-six", "20260107")),
    ("requests-2.34.2.tar.gz", ("requests", "2.34.2")),
    ("some-pkg-name-1.0.zip", ("some-pkg-name", "1.0")),
    ("README.txt", None),
    ("broken.whl", None),
    ("noversion.tar.gz", None),
])
def test_dist_of(name, want):
    assert wheels.dist_of(name) == want


def test_check_matches_pins_by_normalised_name_and_version(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text(REQ)
    wh = tmp_path / "wh"
    wh.mkdir()
    for f in ("capstone-5.0.9-py3-none-any.whl", "dissect_ntfs-3.16-py3-none-any.whl",
              "requests-2.33.0-py3-none-any.whl", "notes.txt"):
        (wh / f).write_text("")
    rep = wheels.check(wh, req)
    assert rep.pins == 4 and not rep.passed
    assert rep.present == (("capstone", "5.0.9"), ("dissect.ntfs", "3.16"))
    assert rep.missing == (("pdfminer-six", "20260107"), ("requests", "2.34.2"))
    assert rep.other_version == (("requests", "2.34.2", "2.33.0"),)
    (wh / "pdfminer_six-20260107-py3-none-any.whl").write_text("")
    (wh / "requests-2.34.2.tar.gz").write_text("")
    assert wheels.check(wh, req).passed


def test_check_fails_loudly_without_a_folder_or_pins(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text(REQ)
    with pytest.raises(wheels.WheelsError, match="is not there"):
        wheels.check(tmp_path / "missing", req)
    (tmp_path / "wh").mkdir()
    with pytest.raises(wheels.WheelsError, match="not found"):
        wheels.check(tmp_path / "wh", tmp_path / "none.txt")
    req.write_text("# nothing pinned\nrequests>=2\n")
    with pytest.raises(wheels.WheelsError, match="no name==version"):
        wheels.check(tmp_path / "wh", req)


def test_plan_downloads_then_installs_offline(tmp_path):
    fill, install = wheels.plan(tmp_path / "wh", tmp_path / "r.txt", python="/v/bin/python")
    assert fill == ["/v/bin/python", "-m", "pip", "download", "--dest", str(tmp_path / "wh"), "-r", str(tmp_path / "r.txt")]
    assert install[:4] == ["uv", "pip", "install", "--python"]
    assert {"--offline", "--no-index"} <= set(install) and install[install.index("--find-links") + 1] == str(tmp_path / "wh")


def test_wheelhouse_dir_override_and_default(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WHEELHOUSE", str(tmp_path / "mine"))
    assert paths.wheelhouse_dir() == (tmp_path / "mine").resolve()
    monkeypatch.delenv("CTF_WHEELHOUSE")
    assert paths.wheelhouse_dir() == Path("~/ctf-work/_wheelhouse").expanduser().resolve()


def test_the_real_requirements_txt_has_pins_the_check_reads():
    pins = wheels.parse_pins(wheels.requirements_path().read_text())
    assert len(pins) > 100 and ("capstone", "5.0.9") in pins
