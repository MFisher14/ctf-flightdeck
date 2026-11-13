"""Where the real-data corpus is, for every script and fetcher in tests/real.

One answer for the whole folder: ctf.paths.realdata_root(), i.e. $CTF_REALDATA, else the Huntress
corpus folder (read-only). The scripts here used to work it out four different ways from
$HUNTRESS_REALDATA and the git layout; they all call root() now. The corpus is untrusted data: the
scripts read its bytes and never run, import or unpickle anything from it.
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from ctf import paths  # noqa: E402


def root() -> Path:
    """The corpus root (it may be absent; callers check for their own kit folder)."""
    return paths.realdata_root()
