"""Make the carried engines importable in tests without per-file sys.path hacks.

Every carried engine historically did `sys.path.insert(0, solvers/<lane>|common|toolkits|tools)`; this
puts those directories on sys.path once so `python -m pytest tests/` and `python tests/test_x.py` both
resolve imports the same way. It also points CTF_WORKDIR at a temp dir so nothing writes into the repo,
and defaults CTF_EVENT to csctf (the flag format most carried tests are written in).
"""
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent
for d in ("solvers/common", "solvers/toolkits", "solvers/binary", "solvers/metadata-forensics",
          "solvers/mobile-android", "solvers/script-analysis", "solvers/warmups", "solvers/web",
          "tools", "tests"):
    p = str(REPO / d)
    if (REPO / d).is_dir() and p not in sys.path:
        sys.path.insert(0, p)

os.environ.setdefault("CTF_WORKDIR", tempfile.mkdtemp(prefix="csctf-test-"))
os.environ.setdefault("CTF_TESTING", "1")
# Engines read the flag format from the active event profile (ctf.flagfmt). Most of the carried suite
# is CSCTF's, so the suite runs as CSCTF unless a test picks another event (monkeypatch CTF_EVENT).
os.environ.setdefault("CTF_EVENT", "csctf")

import pytest  # noqa: E402

# Markers needs_tool / needs_realdata / live / slow and the end-of-run NOT RUN summary
# (docs/CONTRACTS.md, "Test markers").
pytest_plugins = ("ctf.testing.pytest_plugin",)


@pytest.fixture(autouse=True)
def _restore_interpreter_limits():
    """Snapshot and restore the process-global interpreter limits around every test.

    Several parsers intentionally lower sys.setrecursionlimit / set_int_max_str_digits to exercise
    or enforce depth bounds; if a test changed one and didn't restore it, later depth/recursion tests
    behaved differently in the full suite than in isolation (order-dependent failures). Restoring here
    makes every test see the default limits regardless of what ran before it.
    """
    rlimit = sys.getrecursionlimit()
    try:
        dlimit = sys.get_int_max_str_digits()
    except AttributeError:
        dlimit = None
    # Force the interpreter defaults so a test's depth/recursion behaviour is deterministic regardless
    # of what any earlier test (or import-time code) left the limits at. A test that genuinely needs a
    # deeper limit sets it itself after this fixture runs.
    sys.setrecursionlimit(1000)
    try:
        yield
    finally:
        sys.setrecursionlimit(rlimit)
        if dlimit is not None:
            sys.set_int_max_str_digits(dlimit)
