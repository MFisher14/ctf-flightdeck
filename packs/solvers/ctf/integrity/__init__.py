"""Test and docs integrity tooling (B-196): checks that a green suite means a tested tree.

    mutate      a shipped mutation check: mutate one source file in a temporary copy of the checkout and
                run the tests the regression gate selects for it (ctf.gate); a surviving mutant is a
                behaviour no test pins
    fakes       every CTF_TESTING / stub branch (an `if` that reads the testing flag) needs a test that
                reaches it with the flag OFF, so a test double cannot hide the real path
    collected   every tests/ file that defines tests is one pytest collects and the gate selects
    doclint     the maintained docs name only paths and `python -m ctf` commands that exist
    preserve    known solve paths (tests/known_solves.toml) keep a live, non-hollow test; `--run` runs them
                through the gate's runner before a merge (the oracle step)
    engines     the audit of engines added since a base ref: manifest, a test that reaches the entry,
                no hollow test, no fake branch without a non-fake test

`python -m ctf integrity <check>` (ctf/cli/integrity.py). Contract: docs/CONTRACTS.md section 61.
Every check is static unless it says it runs tests (mutate, preserve --run); a missing input (config,
registry, tests folder) is an IntegrityError, never an empty pass.
"""
from __future__ import annotations


class IntegrityError(RuntimeError):
    """A usage or configuration problem an integrity check refuses to paper over (exit 2 on the CLI)."""


__all__ = ["IntegrityError"]
