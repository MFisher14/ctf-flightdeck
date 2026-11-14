"""csctf-2026: an AI-assisted solver for CSCTF 2026 (Chronos Security CTF, a CTFd jeopardy event).

This package is the NEW, event-specific backbone written for CSCTF:

  config      event + connection settings (base URL, API token, flag format, team, scope)
  client      a thin CTFd API v1 client (list / fetch / download / submit / scoreboard / team solves)
  workspace   per-challenge working folders under $CTF_WORKDIR
  submit      the guarded flag-submission path (dedupe, pacing, 3-wrong-then-ask; never brute-force)
  dynamic     helper for 5-minute rotating ("dynamic") flags: retrieve fresh, submit in the same window
  triage      route a pulled challenge (category + files) to the right engines/playbook

The analysis engines it drives live under solvers/ (carried from the player's Huntress CTF work and
de-Huntressed); the offline tools live under tools/. Nothing here brute-forces flags, floods the
scoreboard, scans broadly, or touches anything but the squad's assigned targets (CSCTF rules).
"""

__all__ = ["config", "client", "workspace", "submit", "dynamic", "triage"]

# B-187: make the three dash-named lanes importable as solvers.script_analysis / .metadata_forensics /
# .mobile_android (the others already resolve via the solvers namespace package). Idempotent; installs a
# sys.meta_path finder, never an __init__.py, so solvers stays a namespace package (SH-06). See
# ctf/solverpkg.py.
from . import solverpkg as _solverpkg  # noqa: E402

_solverpkg.install()
