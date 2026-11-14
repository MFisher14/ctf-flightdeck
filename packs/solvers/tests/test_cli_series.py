"""B-090: `python -m ctf series` -- the operator's view of series-chaining, over synthetic workspaces."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ctf import hypothesis  # noqa: E402
from ctf.cli import series as cli  # noqa: E402
from series_fixtures import BRIEF_1, BRIEF_MD5, ICON, workspace  # noqa: E402


def _args(**kw):
    base = dict(target=None, index=False, workdir=None, event="csctf", json=False, no_ledger=False,
                no_write=False)
    base.update(kw)
    return argparse.Namespace(**base)


def _lab(root: Path) -> Path:
    workspace(root, 9170, "Onion Deanon 2: Read the Favicon", BRIEF_1, {"evidence/favicon.bin": ICON})
    return workspace(root, 9171, "Onion Deanon 2: Hash the Favicon Again", BRIEF_MD5)


def test_by_id_prints_the_candidates_writes_and_records(tmp_path, capsys):
    target = _lab(tmp_path)
    rc = cli.run(_args(target="9171", workdir=str(tmp_path)))
    out = capsys.readouterr().out
    md5 = hashlib.md5(ICON).hexdigest()
    assert rc == 0
    assert f"candidate CSCTF{{{md5}}}" in out and "sibling 9170-onion-deanon-2-read-the-favicon" in out
    assert out.index(f"CSCTF{{{md5}}}") < out.index(f"CSCTF{{{md5.upper()}}}")
    assert (target / "recon" / "series.json").is_file()
    assert hypothesis.entries("9171", workdir=tmp_path)[0]["payload"] == f"CSCTF{{{md5}}}"


def test_by_folder_json_no_ledger_no_write(tmp_path, capsys):
    target = _lab(tmp_path)
    rc = cli.run(_args(target=str(target), json=True, no_ledger=True, no_write=True))
    doc = json.loads(capsys.readouterr().out)
    assert rc == 0 and doc["status"] == "candidate" and doc["submitted"] is False
    assert not (target / "recon").exists()
    assert not (tmp_path / "hypotheses").exists()


def test_exit_1_when_nothing_to_reuse(tmp_path, capsys):
    workspace(tmp_path, 9171, "Onion Deanon 2: Hash the Favicon Again", BRIEF_MD5)
    rc = cli.run(_args(target="9171", workdir=str(tmp_path)))
    assert rc == cli.NONE_EXIT
    assert "no-sibling" in capsys.readouterr().out


def test_exit_2_on_an_unknown_or_ambiguous_target(tmp_path, capsys):
    workspace(tmp_path, 7, "Lab A: One", BRIEF_1)
    assert cli.run(_args(target="9999", workdir=str(tmp_path))) == cli.ERROR_EXIT
    assert "no challenge folder '9999'" in capsys.readouterr().err
    (tmp_path / "7-other").mkdir()
    assert cli.run(_args(target="7", workdir=str(tmp_path))) == cli.ERROR_EXIT
    assert "several folders" in capsys.readouterr().err
    assert cli.run(_args(workdir=str(tmp_path))) == cli.ERROR_EXIT
    assert cli.run(_args(target="7", workdir=str(tmp_path / "absent"))) == cli.ERROR_EXIT


def test_index(tmp_path, capsys):
    _lab(tmp_path)
    workspace(tmp_path, 1, "Solo", BRIEF_1)
    assert cli.run(_args(index=True, workdir=str(tmp_path))) == 0
    out = capsys.readouterr().out
    assert "onion deanon 2:" in out and "9171-onion-deanon-2-hash-the-favicon-again  (continuation)" in out
    assert "solo" not in out.lower()
    empty = tmp_path / "empty"
    empty.mkdir()
    assert cli.run(_args(index=True, workdir=str(empty))) == cli.NONE_EXIT


def test_the_command_is_discovered():
    from ctf import cli as top
    found = {name: (mod, err) for name, mod, err in top.discover()}
    assert "series" in found and found["series"][1] is None and found["series"][0] is cli
    p = argparse.ArgumentParser()
    cli.add_arguments(p)
    ns = p.parse_args(["9171", "--json", "--no-ledger"])
    assert ns.target == "9171" and ns.json and ns.no_ledger
