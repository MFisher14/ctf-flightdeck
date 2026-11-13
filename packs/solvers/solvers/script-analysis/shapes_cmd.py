#!/usr/bin/env python3
"""Generic Batch (.cmd) shape fallback (wave123): when the `batch` module is absent or declines,
the general path has no reader for the `-expansion` ids, so they come back None.  This offers the
field's accepted values as an UNSURE `labels.candidates` answer, scoped to the specimen's own
bytes, so verify.py probes it on the untimed base instead of leaving it None.  Never plain; only
ids a shipped reader left open reach it.  See `shape_fallback_lib.py`.
"""
import sys
from pathlib import Path

_here = str(Path(__file__).resolve().parent)
if _here not in sys.path:
    sys.path.insert(0, _here)

import shape_fallback_lib  # noqa: E402


def shapes(text, questions):
    return shape_fallback_lib.shapes_for("cmd", text or "", questions or [])
