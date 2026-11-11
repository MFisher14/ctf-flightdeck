"""Builders for the detector tests: real Lane, Action, FileChange and Challenge objects.

Not a test module (no test_ prefix), so pytest does not collect it. The detectors read real
deck objects, never mocks, so these build the same objects the deck would.
"""

from __future__ import annotations

from ctf_flightdeck.core.model import (
    Action,
    ActionKind,
    Actor,
    Challenge,
    FileChange,
    Lane,
)


def challenge(
    cid: str = "c1",
    *,
    name: str = "Test",
    category: str = "misc",
    points: int = 100,
    solves: int = 10,
    description: str = "",
    files: tuple[str, ...] = (),
) -> Challenge:
    return Challenge(
        id=cid,
        name=name,
        category=category,
        points=points,
        solves=solves,
        description=description,
        files=files,
    )


def step(text: str, output: str = "", *, turn: int = 0, kind: ActionKind = ActionKind.STEP,
         by: Actor = Actor.LANE) -> Action:
    return Action(at=float(turn), turn=turn, text=text, output=output, by=by, kind=kind)


def file_change(path: str, *, turn: int, status: str = "modified", diff: str = "") -> FileChange:
    return FileChange(path=path, diff=diff, status=status, turn=turn, at=float(turn))


def lane(
    *steps: Action | str,
    turns: int | None = None,
    tokens: int = 0,
    model: str = "small",
    challenge_id: str = "c1",
    number: int = 1,
    plan: str = "",
    artifacts: tuple[str, ...] = (),
    files: tuple[FileChange, ...] = (),
    notes: tuple[Action, ...] = (),
) -> Lane:
    out = Lane(number=number, challenge_id=challenge_id, model=model)
    out.tokens = tokens
    out.plan = plan
    out.artifacts = list(artifacts)
    for change in files:
        out.files[change.path] = change
    numbered: list[Action] = []
    turn = 0
    for item in steps:
        turn += 1
        action = step(item, turn=turn) if isinstance(item, str) else (item if item.turn else step_turn(item, turn))
        numbered.append(action)
    out.actions = numbered + list(notes)
    out.turns = turns if turns is not None else turn
    return out


def step_turn(action: Action, turn: int) -> Action:
    from dataclasses import replace

    return replace(action, turn=turn, at=float(turn))
