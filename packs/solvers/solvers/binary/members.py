"""Pick one day's files out of a delivery, in archive order.

A delivery zip holds a sample (and sometimes side files) per day, each named
with its day prefix: d03--variant-000.dll, d03--variant-000.runtimeconfig.json.
Questions such as `d03_artifact_sha256_2` count those files in archive order.
"""
import io
import re
import sys
import zipfile
from pathlib import Path

_COMMON = str(Path(__file__).resolve().parent.parent / "common")
if _COMMON not in sys.path:
    sys.path.append(_COMMON)
try:   # the known archive passwords, read from disk on every call (backlog row 75)
    import archive_passwords
except ImportError:   # pragma: no cover - solvers/common is beside this folder
    archive_passwords = None


def passwords() -> list:
    """[None, b"infected", the passwords of <challenges>/_passwords.json, newest first]."""
    return archive_passwords.passwords() if archive_passwords is not None else [None, b"infected"]


def _archive_order(delivery: bytes) -> list:
    # File names sit in the central directory in the clear, even in an encrypted zip.
    try:
        return [i.filename for i in zipfile.ZipFile(io.BytesIO(delivery)).infolist() if not i.is_dir()]
    except Exception:
        return []


def _decrypt(delivery: bytes) -> dict:
    """Read every member of a (possibly AES-encrypted) zip without leaving the process, with the
    known archive passwords."""
    if archive_passwords is not None:
        return archive_passwords.read_all(delivery)[0]
    out = {}
    try:
        import pyzipper
        zf = pyzipper.AESZipFile(io.BytesIO(delivery))
    except Exception:
        return out
    for info in zf.infolist():
        if info.is_dir():
            continue
        for pwd in passwords():
            try:
                out[info.filename] = zf.read(info, pwd=pwd)
                break
            except Exception:
                continue
    return out


# The Day 21 build (binary-fold, the bank pass's solver part): one set asks for a prefix's members dozens of times
# (67 calls on the Day 20 base), and each call parsed the delivery's central directory again and matched every
# file name. Both are read once per delivery and per files dict: bytes cannot change, so an entry is found by
# the object itself (it holds the object, so no other can take its identity), and a files dict by identity and
# size (a dict that gained or lost a name is read again). The result is the same list as before.
_ORDERS = []      # [(delivery bytes, ({name: first position}, count of names))], the last few
_NAMES = []       # [(files dict, its length, [(name, basename)])], the last few
_KEEP = 2


def _order_of(delivery) -> tuple:
    for held, order in _ORDERS:
        if held is delivery:
            return order
    names = _archive_order(delivery)
    order = ({n: i for i, n in reversed(list(enumerate(names)))}, len(names))
    if isinstance(delivery, bytes):
        _ORDERS.append((delivery, order))
        del _ORDERS[:-_KEEP]
    return order


def _names_of(files: dict) -> list:
    for held, size, names in _NAMES:
        if held is files and size == len(files):
            return names
    names = [(n, n.rsplit("/", 1)[-1]) for n in files if " -> " not in n]
    if isinstance(files, dict):
        _NAMES.append((files, len(files), names))
        del _NAMES[:-_KEEP]
    return names


def day_members(files: dict, ctx: dict, prefix: str) -> list:
    """Return [(name, bytes)] for the files whose basename starts with prefix (e.g. "d03")."""
    mine = re.compile(rf"{re.escape(prefix)}(?![0-9A-Za-z])", re.I)
    delivery = (ctx or {}).get("delivery") or b""
    names = [n for n, base in _names_of(files) if mine.match(base)]
    pool = files
    if not names and delivery[:2] == b"PK":
        pool = _decrypt(delivery)
        names = [n for n in pool if mine.match(n.rsplit("/", 1)[-1])]
    order, last = _order_of(delivery)
    names.sort(key=lambda n: (order.get(n, last), n))
    return [(n, pool[n]) for n in names]
