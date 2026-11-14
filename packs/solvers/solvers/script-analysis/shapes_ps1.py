#!/usr/bin/env python3
"""Generic PowerShell (.ps1) shape fallback (wave123): when the `powershell` module is absent or
declines, the general path has no reader for a tactic specimen's `-scenario`, `-attack`, `-url`,
`-file`, `-extension`, `-note`, `-mutex`, `-user-agent` and `-wallet` ids, so they come back None.
This offers each an UNSURE `labels.candidates` answer -- the field's vocabulary for scenario and
attack, the record's own harvested values (a base64 JSON blob decoded one layer) for the byte
facts -- scoped to the specimen's own bytes, so verify.py probes it on the untimed base instead of
leaving it None.  Never plain; only ids a shipped reader left open reach it.  See
`shape_fallback_lib.py`.
"""
import sys
from pathlib import Path

_here = str(Path(__file__).resolve().parent)
if _here not in sys.path:
    sys.path.insert(0, _here)

import shape_fallback_lib  # noqa: E402


def shapes(text, questions):
    return shape_fallback_lib.shapes_for("ps1", text or "", questions or [])
