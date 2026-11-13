"""Writeup and retro pipeline, and the (dry-run) public-repo publish path (B-098).

    workdir (per-challenge evidence + ledger)
        -> draft    ctf.writeup.draft    one README.md per challenge into a private staging folder
        -> retro    ctf.writeup.retro    an event or day retro from the ledger and the workspace
        -> assist   ctf.writeup.assist   the TODO prose drafted on models.docs from template briefs (B-097)
        -> review   ctf.writeup.assist   the one review pass on models.primary (ctf.writeup.passes gate)
        -> check    ctf.writeup.scan     the leak gate (flags, known values, secrets, instance URLs)
        -> publish  ctf.writeup.publish  allowlisted, redacted public tree + a publish plan (dry run)

Command line: `python -m ctf writeup draft | retro | assist | review | check | publish`
(ctf/cli/writeup.py).

Policy comes from the event profile only (ctf.writeup.policy): `[writeups] redact_flags`,
`publish_hold` and `public_repo`, `[rules] flag_sharing`, `dates.end`, and the platform / live-service
hosts. An event that forbids sharing flags is always redacted, whatever redact_flags says.

Publishing is dry-run only: the publish step builds the public tree and writes the plan of git/gh
commands it would run; it never runs them, never creates a repository and never pushes.

The folder is `writeup` (singular) because the repo's .gitignore ignores every directory named
`writeups/` (the private staging trees).
"""
