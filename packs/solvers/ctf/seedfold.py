"""B-040: fold event-learned label verdicts into the tracked master seeds, automatically.

During play `labels.learn` appends the judge's verdict on each answer name to the runtime label ledger
(`<workdir>/_ledger/<lane>.jsonl`). `labels.py promote <lane>` folds one lane's rows into its tracked
seed (`solvers/<lane>/conventions.json`, or a toolkit's seed) after the day. This module runs that fold
over EVERY lane that has a ledger in one call, so it can be run after each accepted solve rather than
only at the end of an event -- the "fold step after each solve" the item asks for.

It promotes nothing on its own: it folds only what the ledger already recorded, and the order-degenerate
guard (`labels._fold`, B-040) keeps an acceptance the input could not distinguish out of the plain
answer. A first-seen label (a name no judge verdict exists for) still needs probing on the untimed base;
that is the item's blocker and is deliberately not done here.

    from ctf import seedfold
    seedfold.fold_all()                       # every lane with a ledger, write the seeds
    seedfold.fold_all(["binary"], dry_run=True)

The lanes are the stems of the `*.jsonl` files under the ledger folder that name a known labels lane; an
unknown stem (a hand-dropped file) is skipped with a note, never a silent guess at its lane.
"""
from __future__ import annotations

import sys
from pathlib import Path


class SeedFoldError(RuntimeError):
    """The fold cannot run as asked (no judge ledger, an unknown lane, an unreadable seed)."""


def labels_module():
    """solvers/common/labels.py of this checkout (the single source; same loader the lanes use)."""
    from . import askreaders
    return askreaders.labels_module()


def ledger_lanes(labels_mod, *, warn=None, workdir=None) -> list[str]:
    """Known labels lanes that have a runtime ledger file, in sorted order. A `<stem>.jsonl` whose stem
    is not a lane (or a lane alias) is skipped; `warn`, when given, is called once per skipped file.
    `workdir`, when given, names the event workdir whose `_ledger` folder is scanned (see fold_all)."""
    root = labels_mod.challenges_root(workdir)
    folder = root / "_ledger"
    out: list[str] = []
    if not folder.is_dir():
        return out
    for path in sorted(folder.glob("*.jsonl")):
        lane = labels_mod.LANE_ALIASES.get(path.stem, path.stem)
        if lane in labels_mod.LANE_DIRS:
            if lane not in out:
                out.append(lane)
        elif warn is not None:
            warn(f"{path.name}: {path.stem!r} is not a labels lane; left unfolded")
    return out


def fold_all(lanes=None, *, dry_run: bool = False, labels_mod=None, warn=None, workdir=None) -> dict[str, list[str]]:
    """Fold each lane's runtime ledger into its tracked seed. `lanes` None folds every lane that has a
    ledger (`ledger_lanes`); an explicit lane is folded even with no ledger (it just changes nothing).
    `workdir`, when given, is the event workdir whose runtime ledger is folded (otherwise the ambient
    event, ctf.paths.workdir()): `adapt.record_attempt` passes the workdir the accepted solve recorded
    in, which may differ from the ambient one. The workdir is threaded straight into labels (never via
    $CTF_WORKDIR, which only ctf.paths resolves), so a fold under one workdir never disturbs another.

    Returns `{lane: [changed line, ...]}`, the per-key lines `labels.promote` returns. Raises
    SeedFoldError without a judge ledger (there is nothing recorded to fold) or on an unknown lane."""
    lm = labels_mod or labels_module()
    if not lm.judge_ledger():
        raise SeedFoldError(
            f"this event has no judge ledger (${lm.JUDGE_LEDGER_ENV}=off): nothing recorded to fold")
    if lanes is None:
        lanes = ledger_lanes(lm, warn=warn, workdir=workdir)
    result: dict[str, list[str]] = {}
    for lane in lanes:
        canon = lm.LANE_ALIASES.get(lane, lane)
        if canon not in lm.LANE_DIRS:
            raise SeedFoldError(f"unknown lane {lane!r}: use one of {', '.join(lm.LANE_DIRS)}")
        try:
            result[canon] = lm.promote(canon, dry_run=dry_run, workdir=workdir)
        except (ValueError, OSError) as e:
            raise SeedFoldError(f"lane {canon}: {e}") from None
    return result


def _note(text: str) -> None:
    print(f"[seedfold] {text}", file=sys.stderr)


def seed_path(labels_mod, lane: str) -> Path:
    """The tracked seed a lane folds into (for a report line)."""
    return labels_mod.seed_path(labels_mod.LANE_ALIASES.get(lane, lane))
