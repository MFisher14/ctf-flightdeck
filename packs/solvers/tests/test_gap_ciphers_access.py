"""Lower-priority gap closers: mirror-writing + Fleissner/Friderici grille ciphers, and the Access
(.mdb/.accdb) identifier. All offline; mdbtools-dependent paths are checked by shape, not by running
the host tool."""
import struct
import sys
from pathlib import Path

# NOTE: two modules are named `classical` (solvers/common + solvers/toolkits). We want the common one
# (it has mirror_lines/turning_grille/keyless), so insert common LAST so it sits at sys.path[0].
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "solvers" / "toolkits"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "solvers" / "common"))

import classical as C  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "solvers" / "toolkits"))
import access_db  # noqa: E402


def test_mirror_lines_roundtrip_and_distinct_from_reverse():
    src = "HELLO\nWORLD"
    mir = C.mirror_lines(src)
    assert mir == "OLLEH\nDLROW"
    assert C.mirror_lines(mir) == src          # its own inverse
    assert mir != src[::-1]                      # not the same as a full reversal (which flips lines)


def test_mirror_lines_surfaced_by_keyless():
    # mirror_lines surfaces for MULTI-line input (a single line's mirror == a full reverse, so it's
    # redundant there and intentionally not emitted separately).
    cipher = "olleh\ndlrow"
    readings = dict(C.keyless(cipher))
    assert readings.get("mirror_lines") == "hello\nworld"


def test_turning_grille_decrypt_known():
    # 4x4 turning grille. Build a ciphertext by filling the square with a known plaintext via the
    # grille, then confirm decrypt recovers it. holes rotate 90 deg CW each quarter.
    # a VALID 4x4 grille picks exactly one cell from each of the four 90-deg rotation orbits
    holes = [(0, 0), (0, 1), (0, 2), (1, 1)]
    plain = "ATTACKATDAWNXYZQ"  # 16 chars
    size = 4

    # forward-fill: place plain chars into the 4 orientations' open cells in reading order
    def rotate(hs):
        return {(c, size - 1 - r) for (r, c) in hs}
    grid = [["" for _ in range(size)] for _ in range(size)]
    cur = set((r, c) for r, c in holes)
    k = 0
    for _ in range(4):
        for r in range(size):
            for c in range(size):
                if (r, c) in cur:
                    grid[r][c] = plain[k]; k += 1
        cur = rotate(cur)
    cipher = "".join(grid[r][c] for r in range(size) for c in range(size))
    assert C.turning_grille_decrypt(cipher, holes, size) == plain


def test_access_identify(tmp_path):
    mdb = tmp_path / "a.mdb"
    mdb.write_bytes(b"\x00\x01\x00\x00" + b"Standard Jet DB\x00" + b"\x00" * 64)
    accdb = tmp_path / "b.accdb"
    accdb.write_bytes(b"\x00\x01\x00\x00" + b"Standard ACE DB\x00" + b"\x00" * 64)
    other = tmp_path / "c.bin"
    other.write_bytes(b"not a database at all" + b"\x00" * 40)
    assert access_db.identify(mdb) == "mdb"
    assert access_db.identify(accdb) == "accdb"
    assert access_db.identify(other) is None


def test_access_scan_without_mdbtools_gives_commands(tmp_path):
    mdb = tmp_path / "a.mdb"
    mdb.write_bytes(b"\x00\x01\x00\x00" + b"Standard Jet DB\x00" + b"\x00" * 64)
    rep = access_db.scan(mdb)
    assert rep["kind"] == "mdb"
    if not access_db.have_mdbtools():
        assert any("mdb-tables" in c for c in rep["commands"])
