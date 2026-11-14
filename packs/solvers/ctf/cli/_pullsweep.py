"""The sweep step of `ctf pull` (B-013): after a challenge's files are downloaded, run ctf.sweep on its
folder, print the summary and add it to notes.md. A sweep that cannot run does not undo the pull: it
is said on stderr and in notes.md (never silently skipped). Nothing is submitted here.
"""
from __future__ import annotations

import sys

from .. import event as _event
from .. import sweep as _sweep


def after_pull(ch) -> int:
    """Sweep one pulled challenge (a ctf.workspace.Challenge). 0 when the sweep ran or there was no handout
    file to sweep (said as such, not as a failure), 1 when it failed."""
    try:
        rep = _sweep.sweep(ch.dir, _event.current())
    except _sweep.NothingToSweep:   # no handout (web/instance challenges): routine, not a failure
        msg = "sweep: nothing to sweep (no handout files)"
        print(msg)
        ch.note("\n## sweep\n\n" + msg)
        return 0
    except Exception as e:      # the download stands; the failure is reported, by name
        msg = f"sweep: FAILED ({type(e).__name__}: {e})"
        print(msg, file=sys.stderr)
        ch.note("\n## sweep\n\n" + msg)
        return 1
    text = rep.render()
    print(text)
    ch.note("\n## sweep\n\n```\n" + text + "\n```")
    return 0
