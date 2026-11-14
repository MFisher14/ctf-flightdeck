"""Manual-mode cockpit (B-209): drop-zone watcher, needs checklist, submission queue.

    from ctf.cockpit import Cockpit
    ck = Cockpit(event.load("spooky"))      # CockpitError for an event that is not manual
    ck.sweep()                              # file everything in <workdir>/inbox/
    ck.needs()                              # every open need, most blocking first
    ck.enqueue(cid, flag, provenance=...)   # Refused where the submit gate would refuse
    ck.verdict(qid, accepted=True, by=..., interactive=True)

CLI: `python -m ctf cockpit ...` (ctf/cli/cockpit.py). Details in core.py.
"""
from .core import (NEED_KINDS, Cockpit, CockpitError, Need, Refused, SweepReport,  # noqa: F401
                   make_id)
from .kinds import Kind, Problem, challenge_problems, classify, file_problems  # noqa: F401
