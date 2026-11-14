"""B-240: native_emulate's Unicorn import fails loudly, never a silent fall back.

Each case runs in a fresh interpreter (a module's import-time branch cannot be re-run in this process), with a
meta-path blocker or a patched host probe set up BEFORE native_emulate is imported. Nothing is emulated except
the two-instruction smoke function in the last case, built here from known bytes.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COMMON = ROOT / "solvers" / "common"
MOBILE = ROOT / "solvers" / "mobile-android"


def _run(prelude: str, body: str) -> dict:
    code = "\n".join([
        "import json, sys, warnings",
        f"sys.path[:0] = [{str(COMMON)!r}, {str(MOBILE)!r}]",
        prelude,
        "out = {}",
        "with warnings.catch_warnings(record=True) as caught:",
        "    warnings.simplefilter('always')",
        "    try:",
        *("        " + line for line in body.splitlines()),
        "    except BaseException as e:",
        "        out['raised'] = type(e).__name__",
        "        out['mro'] = [c.__name__ for c in type(e).__mro__]",
        "        out['message'] = str(e)",
        "out['warnings'] = [str(w.message) for w in caught if issubclass(w.category, RuntimeWarning)]",
        "print(json.dumps(out))",
    ])
    proc = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr[-2000:]
    return json.loads(proc.stdout.strip().splitlines()[-1])


BLOCK_UNICORN = """
class _Block:
    def find_spec(self, name, path=None, target=None):
        if name == 'unicorn' or name.startswith('unicorn.'):
            raise ImportError('blocked for the test: no unicorn here')
        return None
sys.meta_path.insert(0, _Block())
"""

# The host probe is answered "unreadable" without touching Unicorn: native_emulate must decline by name.
DECLINE_HOST = """
import ctypes, platform
sys.platform = 'darwin'
platform.machine = lambda: 'arm64'
class _Lib:
    class sysctlbyname:
        argtypes = None
        restype = None
        def __new__(cls, *a):
            return -1
ctypes.CDLL = lambda *a, **k: _Lib()
"""


def test_missing_unicorn_raises_at_import_naming_the_pin():
    out = _run(BLOCK_UNICORN, "import native_emulate")
    assert out.get("raised") == "UnicornUnavailable", out
    assert "ImportError" in out["mro"], out
    assert "unicorn==2.1.4" in out["message"] and "requirements.in" in out["message"], out


def test_missing_unicorn_is_said_by_name_in_dex_chain_codec():
    # dex_chain_codec keeps running on its hand-rolled readers, but the reason is a RuntimeWarning, not silence.
    out = _run(BLOCK_UNICORN, "import dex_chain_codec\nout['ne'] = dex_chain_codec.native_emulate is None")
    assert "raised" not in out, out
    assert out["ne"] is True, out
    said = [w for w in out["warnings"] if w.startswith("dex_chain_codec: native_emulate is unavailable")]
    assert said and "unicorn==2.1.4" in said[0], out["warnings"]


def test_declined_host_warns_and_every_call_names_the_reason():
    body = "\n".join([
        "import native_emulate as ne",
        "out['available'] = ne.UNICORN_AVAILABLE",
        "out['reason'] = ne.UNICORN_UNAVAILABLE_REASON",
        "try:",
        "    ne.emulate_x86_sysv(bytes.fromhex('4889f84801f0c3'), [5, 7])",
        "except ne.EmulationError as e:",
        "    out['call'] = str(e)",
    ])
    out = _run(DECLINE_HOST, body)
    assert "raised" not in out, out
    assert out["available"] is False
    assert out["reason"] and "hw.cachelinesize" in out["reason"], out
    assert any(w.startswith("native_emulate: ") and "hw.cachelinesize" in w for w in out["warnings"]), out
    assert out["call"].startswith("unicorn engine not available: ") and "hw.cachelinesize" in out["call"], out


def test_installed_unicorn_runs_with_no_reason_and_no_warning():
    body = "\n".join([
        "import native_emulate as ne, unicorn",
        "out['available'] = ne.UNICORN_AVAILABLE",
        "out['reason'] = ne.UNICORN_UNAVAILABLE_REASON",
        "out['version'] = unicorn.__version__",
        "out['host_ok'] = ne._darwin_arm64_cacheline_usable()",
        "out['sum'] = ne.emulate_x86_sysv(bytes.fromhex('4889f84801f0c3'), [5, 7]) if ne.UNICORN_AVAILABLE else None",
    ])
    out = _run("", body)
    assert "raised" not in out, out
    assert out["version"] == "2.1.4", out                      # the pinned engine is the one installed
    if out["host_ok"]:
        assert out["available"] is True and out["reason"] is None and out["warnings"] == [], out
        assert out["sum"] == 12, out                            # mov rax, rdi ; add rax, rsi ; ret
    else:                                                       # a sandboxed Apple-silicon host: declined by name
        assert out["available"] is False and out["reason"], out
