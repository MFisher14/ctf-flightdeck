"""B-183 integration fix (batch 23): flow_recorder and oidc_driver find the web toolkit however they load.

tools/import_gate.py imports solvers/web/<mod>.py as `web.<mod>` with solvers/ first on sys.path, so the
bare `import web` fallback in those modules returns solvers/web itself (the package), not
solvers/toolkits/web.py. The modules must notice that and load the toolkit by file; otherwise
module-level `_web.WebClient` raises AttributeError and the gate reports an import error.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

PROBE = r"""
import importlib, json, sys
root = sys.argv[1]
sys.path[:0] = [root + "/solvers", root + "/solvers/toolkits", root + "/solvers/web", root]
out = {}
for name in sys.argv[2:]:
    mod = importlib.import_module(name)
    w = mod._web
    out[name] = {"file": getattr(w, "__file__", ""), "client": hasattr(w, "WebClient"),
                 "pkg_web": sys.modules["web"].__file__}
print(json.dumps(out))
"""


@pytest.mark.parametrize("module", ["web.flow_recorder", "web.oidc_driver"])
def test_imported_as_the_web_package_the_module_still_uses_the_toolkit(module):
    r = subprocess.run([sys.executable, "-I", "-c", PROBE, str(ROOT), module],
                       capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, r.stderr[-2000:]
    got = json.loads(r.stdout.strip().splitlines()[-1])[module]
    # the precondition that made the bug: `web` in sys.modules is solvers/web, the package
    assert got["pkg_web"].endswith("solvers/web/__init__.py")
    assert got["client"] is True
    assert Path(got["file"]).resolve() == (ROOT / "solvers" / "toolkits" / "web.py").resolve()
