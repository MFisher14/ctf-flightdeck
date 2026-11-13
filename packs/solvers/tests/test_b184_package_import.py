"""B-184 integration fix (batch 26): solvers/web/contract_library.py imported as the package module
``web.contract_library`` (solvers/ on sys.path, as tools/import_gate.py imports it) must still bind the
web toolkit (solvers/toolkits/web.py), not its own lane package ``web``, which has none of the toolkit's
names. Before the fix the import died on ``_web._ROUTE_DESTRUCTIVE_ACTIONS`` (AttributeError)."""
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

_PROBE = r"""
import importlib, json, sys
solvers = sys.argv[1]
sys.path.insert(0, solvers)
mod = importlib.import_module("web.contract_library")
import web
print(json.dumps({
    "web_pkg": web.__file__,
    "toolkit": mod._web.__file__,
    "shared_is_toolkit": mod._SHARED_DESTRUCTIVE == mod._web._ROUTE_DESTRUCTIVE_ACTIONS,
    "guard_wipe": mod._web.route_has_destructive_action("/api/wipe"),
}))
"""


def test_contract_library_imports_as_package_module_with_the_toolkit():
    env = dict(os.environ, CTF_TESTING="1", PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run([sys.executable, "-I", "-c", _PROBE, str(REPO / "solvers")],
                          cwd=str(REPO), env=env, capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0, proc.stderr[-2000:]
    rec = json.loads(proc.stdout.strip().splitlines()[-1])
    # the name `web` really is the lane package here, so the test exercises the shadowed case
    assert Path(rec["web_pkg"]) == REPO / "solvers" / "web" / "__init__.py"
    assert Path(rec["toolkit"]) == REPO / "solvers" / "toolkits" / "web.py"
    assert rec["shared_is_toolkit"] is True
    assert rec["guard_wipe"] is True
