#!/usr/bin/env python3
"""B-055: Piet is routed and picked up by intake for image challenges.

  .venv/bin/python -m pytest tests/test_b055_piet_intake.py

Offline. The route table is the generated one; the intake plan is built over a synthetic folder
holding one PNG, with no model and no engine actually run (plan only). What is checked:

  route    triage.suggest ranks common.piet for a brief naming Piet, and the generated route table
           carries its keyword and file routes.
  intake   engines.plan picks common.piet as a per-file job on a .png in the folder (select=files),
           so no model is spawned for a Piet image; a folder with no image yields no piet job.
"""
import io
import sys
from pathlib import Path

import pytest

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "common"))

from ctf import triage                     # noqa: E402
from ctf.engines import manifest as M      # noqa: E402
from ctf.intake import engines as E        # noqa: E402
from ctf.intake.guard import Guard         # noqa: E402

try:
    from PIL import Image
    import piet
except ImportError:
    Image = None

pytestmark = pytest.mark.needs_tool("py:PIL")


def _piet_png():
    # A tiny but valid Piet program (red value block -> push -> out(char) sentinel), 20-colour only.
    grid = [[1, 1, 2, piet.BLACK], [piet.BLACK, piet.BLACK, 4, piet.BLACK]]
    img = Image.new("RGB", (4, 2))
    px = img.load()
    for y, row in enumerate(grid):
        for x, v in enumerate(row):
            px[x, y] = piet.BLACK_RGB if v == piet.BLACK else piet.COLORS[v]
    bio = io.BytesIO()
    img.save(bio, "PNG")
    return bio.getvalue()


def test_triage_suggests_piet_for_a_piet_brief():
    out = triage.suggest("rev", "a piet codel image program")
    ids = [r["id"] for r in out["routes"]]
    assert "common.piet" in ids


def test_route_table_carries_piet_routes():
    m = M.load(REPO / "solvers" / "common" / "piet.manifest.toml")
    kw = [r for r in m.routes if "piet" in r.keywords]
    files = [r for r in m.routes if "ext:.png" in r.files]
    assert kw and files
    assert m.intake is not None and m.intake.select == "files"


def test_intake_plan_picks_piet_on_a_png(tmp_path):
    (tmp_path / "chal.png").write_bytes(_piet_png())
    heads = E.input_files(tmp_path)
    manifests = [M.load(REPO / "solvers" / "common" / "piet.manifest.toml")]
    guard = Guard(mode="hook", reason="test")     # cli:python needs no OS sandbox
    plan = E.plan(manifests, "rev", "", tmp_path, guard=guard)
    piet_jobs = [j for j in plan.jobs if j.engine == "common.piet"]
    assert piet_jobs, f"expected a piet job, got {[(s.engine, s.reason) for s in plan.skipped]}"
    assert piet_jobs[0].files[0].name == "chal.png"


def test_intake_plan_skips_piet_with_no_image(tmp_path):
    (tmp_path / "notes.txt").write_text("nothing here")
    heads = E.input_files(tmp_path)
    manifests = [M.load(REPO / "solvers" / "common" / "piet.manifest.toml")]
    plan = E.plan(manifests, "rev", "", tmp_path, guard=Guard(mode="hook"))
    assert not [j for j in plan.jobs if j.engine == "common.piet"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
