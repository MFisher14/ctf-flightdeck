"""Shared fixtures for the MSI / cabinet reader pack (solvers/metadata-forensics/readers_msi.py).

Carried from the archived Huntress test tests/test_day13_metadata_msi.py (its saved-day checks did not
come over): the pack loaded the way properties_strict loads it, and the mirror Quantum encoder that
tests/real/test_real_cab.py holds against libmspack's own Quantum block and the round-4 rebuilt folders.

  M     properties_strict, the lane module (M.Unknown is what a reader raises for "cannot say")
  MSI   the readers_msi pack as M.MORE_MODULES holds it
  TMP   a temp dir the importer removes when done
"""
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="msi_fixtures_"))
# labels (imported by the lane) reads its ledger root from $CTF_WORKDIR. Standalone this points it at
# an empty temp dir; under pytest conftest.py has already set one and it is kept.
os.environ.setdefault("CTF_WORKDIR", str(TMP / "challenges"))

for _d in (REPO / "solvers" / "common", REPO / "solvers" / "metadata-forensics"):
    if str(_d) not in sys.path:
        sys.path.insert(0, str(_d))
import properties_strict as M  # noqa: E402

PACK = "readers_msi.py"
MSI = M.MORE_MODULES.get(PACK)
if MSI is None:
    # properties_strict only prints a NOTE when a pack fails to load; a fixture built on it must not
    # carry on with nothing to test.
    raise ImportError(f"{PACK} is not loaded by properties_strict (see its NOTE line above): "
                      f"the cabinet fixtures need it")


QTM_EXTRA = [0, 0, 0, 0] + [n for n in range(1, 20) for _ in (0, 1)]
QTM_BASE = [sum(1 << e for e in QTM_EXTRA[:i]) for i in range(42)]
QTM_LEN_EXTRA = [0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0]
QTM_LEN_BASE = [sum(1 << e for e in QTM_LEN_EXTRA[:i]) for i in range(26)] + [254]


def quantum_encode(data: bytes, window_bits: int = 18, cross: bool = False):
    """[(packed bytes, unpacked size)] of `data` as Quantum frames of 32 KiB: the encoder that mirrors
    the pack's decoder, with the pack's own model update (MSI._qtm_model, MSI._qtm_update). It is the
    encoder whose cabinets cabextract 1.11 (libmspack) unpacked to the bytes they were built from, in
    round 4; on libmspack's own 59-byte Quantum stream it gives the stored block byte for byte (the
    real-file test holds that); 7zz 26.03 unpacks them too. Greedy matches from a table of three-byte keys. A match stops at its
    frame's end; `cross` lets it run over, which the format does not allow (cabextract, 7zz and the
    pack's decoder all refuse such a folder: a negative case). The decoder reads raw offset and length bits from the stream 16 bits ahead of
    the arithmetic coder, so the stream is laid out as the decoder will read it and the coder's bits
    are poured into their places at the end of a frame. A frame is closed with two more bits than the
    decoder reads: 7zz takes a block only at exactly that length (found by trying, round 4)."""
    slots = window_bits * 2
    literal = [MSI._qtm_model(0, 64), MSI._qtm_model(64, 64), MSI._qtm_model(128, 64), MSI._qtm_model(192, 64)]
    offsets = [MSI._qtm_model(0, min(24, slots)), MSI._qtm_model(0, min(36, slots)), MSI._qtm_model(0, slots)]
    m6len, m7 = MSI._qtm_model(0, 27), MSI._qtm_model(0, 7)
    table, blocks, pos = {}, [], 0
    frame = 0
    while frame * 32768 < len(data):
        start = frame * 32768
        end = min(len(data), start + 32768)
        stop = len(data) if cross else end           # how far a match may run
        frame += 1
        layout, coded = ["A"] * 16, []
        low, high, under = 0, 0xFFFF, 0

        def put(m, sym):
            nonlocal low, high, under
            syms, cum = m[0], m[1]
            i = syms.index(sym) + 1
            spread, total = (high - low) + 1, cum[0]
            high = (low + (cum[i - 1] * spread) // total - 1) & 0xFFFF
            low = (low + (cum[i] * spread) // total) & 0xFFFF
            for k in range(i):
                cum[k] += 8
            if cum[0] > 3800:
                MSI._qtm_update(m)
            while True:
                if (low & 0x8000) == (high & 0x8000):
                    coded.extend([high >> 15] + [(high >> 15) ^ 1] * under)
                    under = 0
                elif (low & 0x4000) and not (high & 0x4000):
                    under += 1
                    low &= 0x3FFF
                    high |= 0x4000
                else:
                    break
                low, high = (low << 1) & 0xFFFF, ((high << 1) | 1) & 0xFFFF
                layout.append("A")

        def raw(value, n):
            layout.extend((value >> (n - 1 - k)) & 1 for k in range(n))
        while pos < end:
            key = data[pos:pos + 3]
            cand = table.get(key) if len(key) == 3 and pos + 3 <= stop else None
            if len(key) == 3:
                table[key] = pos
            length = 0
            if cand is not None and pos - cand < (1 << window_bits):
                length = 3
                while pos + length < stop and length < 259 and data[cand + length] == data[pos + length]:
                    length += 1
                kind = min(length, 5) - 3
                slot = max(k for k in range(42) if QTM_BASE[k] <= pos - cand - 1)
                if slot >= len(offsets[kind][0]):
                    length = 0
            if not length:
                put(m7, data[pos] >> 6)
                put(literal[data[pos] >> 6], data[pos])
                pos += 1
                continue
            put(m7, 4 + kind)
            if kind == 2:
                t = max(k for k in range(27) if QTM_LEN_BASE[k] <= length - 5)
                put(m6len, t)
                raw(length - 5 - QTM_LEN_BASE[t], QTM_LEN_EXTRA[t])
            put(offsets[kind], slot)
            raw(pos - cand - 1 - QTM_BASE[slot], QTM_EXTRA[slot])
            for k in range(1, length):
                if pos + k + 3 <= len(data):
                    table[data[pos + k:pos + k + 3]] = pos + k
            pos += length
        bit = 0 if low < 0x4000 else 1               # the end of a frame: two bits that pin the interval
        coded.extend([bit] + [bit ^ 1] * (under + 1))
        bits_in = iter(coded)
        stream = [(next(bits_in, 0) if x == "A" else x) for x in layout + ["A", "A"]]
        stream += [0] * (-len(stream) % 8)
        blocks.append((bytes(int("".join(map(str, stream[i:i + 8])), 2) for i in range(0, len(stream), 8)), end - start))
    return blocks
