"""Player-declared permission rules: events/<slug>/permissions.toml (optional).

The PLAYER authors this file, ahead of an event, to record the known-good actions they
pre-authorize so the harness need not stop and ask for each one during build or play. It is a
transparent declaration the player reviews and installs in their *own* harness. Nothing here
grants a permission by itself, no agent writes it, and it is no way around any safety
classifier: it records the player's intent and points each action at a *sanctioned helper* (a
purpose-built `ctf` command) so the broad, interrupt-prone action is not needed at all.

    from ctf import permissions
    decl = permissions.load("huntress")        # Permissions, validated
    decl = permissions.load_optional("x")      # None when events/x/permissions.toml is absent
    permissions.SANCTIONED_HELPERS             # the purpose-built ctf commands, by name

Schema (``events/<slug>/permissions.toml``), every table optional:

    slug = "huntress"                      # optional; must match the folder when present
    example = true                         # optional; true marks an unconfirmed template (see below)

    [[allow]]
    id = "worktree-commit"                 # required; unique; [a-z0-9][a-z0-9-]{0,63}
    action = "commit inside an agent git worktree"    # required; the action the player allows
    reason = "build agents commit their own item in their own worktree"   # required; why it is known-good
    scope = "worktree"                     # optional: a free-form scope label
    helper = "worktree-commit"             # optional: the sanctioned ctf command that does it safely
    note = "targeted; never touches main"  # optional

Validation (raises ``ctf.permissions.PermissionError`` naming the file and the dotted key):
unknown keys anywhere are an error; a missing required key names itself; ids must be unique and
match the slug pattern; a ``helper`` that is not a known sanctioned helper is an error (a typo
must fail loudly, never silently point at nothing).

The repo ships no event's declaration. The template is ``docs/examples/permissions.example.toml``
(``EXAMPLE_PATH``), which carries ``example = true``. A copy that still says so is not the player's
declaration: ``ctf permissions`` labels it as an unconfirmed example and ``--check`` fails on it
until the player confirms it by deleting that line.
"""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import paths

PROFILE_NAME = "permissions.toml"
EXAMPLE_PATH = paths.repo_root() / "docs" / "examples" / "permissions.example.toml"
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


class PermissionError(ValueError):  # noqa: A001 - domain name; not the builtin's role here
    """A permissions.toml is missing, malformed or invalid. The message names the file and key."""


@dataclass(frozen=True)
class Helper:
    """A purpose-built ``ctf`` command that performs a would-be-blocked action the safe way."""

    command: str          # the subcommand, e.g. "worktree-commit" (ctf worktree-commit ...)
    purpose: str          # one line: what it does so the broad action is not needed
    replaces: str         # the raw, interrupt-prone action it stands in for


# The sanctioned helpers this repo ships. Each is a real ctf/cli/<name>.py command. Adding a
# helper here and its module is how a new "do it the safe way" tool is registered; the
# permissions viewer and the `helper =` field in a declaration are checked against these names.
SANCTIONED_HELPERS: dict[str, Helper] = {
    h.command: h for h in (
        Helper("abandon",
               "record a gated decision to stop working an attempt, with a required reason, "
               "to a local log under the workdir",
               "a forced process stop / self-interrupt to give up on a challenge"),
        Helper("worktree-commit",
               "stage and commit the current git worktree with one command, refusing a "
               "protected branch, so an agent need not assemble complex git by hand",
               "multi-step or 'too complex' git that worktree agents refuse"),
        Helper("discipline",
               "check one shell command against the brief command discipline (absolute paths, "
               "one command per call, a literal program name) and name the fix (B-043)",
               "retrying a guard-denied command by trial and error"),
        Helper("permissions",
               "show the player's declared permission rules and the sanctioned helpers",
               "guessing which actions are pre-authorised"),
        Helper("job",
               "start, list and stop named jobs the agent owns; a stop checks the recorded pid and "
               "start time and takes the job's own process group only (B-175)",
               "pkill / killall / kill by pattern on background brutes and long runs"),
        Helper("reap",
               "end-of-event reaper: a dry run lists jobs, sessions, merged worktrees and branches "
               "by exact id; only the ids the player confirms are stopped or removed (B-175)",
               "bulk kills and bulk worktree/branch deletes at the end of an event"),
    )
}


@dataclass(frozen=True)
class AllowRule:
    id: str
    action: str
    reason: str
    scope: str | None = None
    helper: str | None = None
    note: str | None = None


@dataclass(frozen=True)
class Permissions:
    slug: str
    allow: tuple[AllowRule, ...]
    path: Path | None = None
    example: bool = False   # true: an unconfirmed template, not the player's declaration

    def by_id(self, rule_id: str) -> AllowRule | None:
        return next((r for r in self.allow if r.id == rule_id), None)


def _str(src: str, where: str, table: dict, key: str, required: bool) -> str | None:
    if key not in table:
        if required:
            raise PermissionError(f"{src}: {where}.{key} is required")
        return None
    v = table[key]
    if not isinstance(v, str) or not v.strip():
        raise PermissionError(f"{src}: {where}.{key} must be a non-empty string")
    return v


def parse(data: dict, *, src: str = "<permissions>", expect_slug: str | None = None) -> Permissions:
    """Validate a decoded TOML mapping into a Permissions declaration."""
    if not isinstance(data, dict):
        raise PermissionError(f"{src}: top level must be a table")
    body = dict(data)
    slug = body.pop("slug", None)
    if slug is not None and not isinstance(slug, str):
        raise PermissionError(f"{src}: slug must be a string")
    if expect_slug is not None:
        if slug is not None and slug != expect_slug:
            raise PermissionError(f"{src}: slug is {slug!r} but the file lives in events/{expect_slug}/")
        slug = expect_slug
    example = body.pop("example", False)
    if not isinstance(example, bool):
        raise PermissionError(f"{src}: example must be true or false")
    raw = body.pop("allow", [])
    if body:
        raise PermissionError(f"{src}: unknown key(s): {', '.join(sorted(body))}")
    if not isinstance(raw, list) or not all(isinstance(x, dict) for x in raw):
        raise PermissionError(f"{src}: allow must be an array of tables ([[allow]])")

    rules: list[AllowRule] = []
    seen: set[str] = set()
    for i, entry in enumerate(raw):
        where = f"allow[{i}]"
        t = dict(entry)
        rid = _str(src, where, t, "id", required=True)
        t.pop("id", None)
        assert rid is not None
        if not _ID_RE.match(rid):
            raise PermissionError(f"{src}: {where}.id {rid!r} must match {_ID_RE.pattern}")
        if rid in seen:
            raise PermissionError(f"{src}: duplicate allow id {rid!r}")
        seen.add(rid)
        action = _str(src, where, t, "action", required=True); t.pop("action", None)
        reason = _str(src, where, t, "reason", required=True); t.pop("reason", None)
        scope = _str(src, where, t, "scope", required=False); t.pop("scope", None)
        helper = _str(src, where, t, "helper", required=False); t.pop("helper", None)
        note = _str(src, where, t, "note", required=False); t.pop("note", None)
        if helper is not None and helper not in SANCTIONED_HELPERS:
            raise PermissionError(
                f"{src}: {where}.helper {helper!r} is not a sanctioned helper "
                f"(known: {', '.join(sorted(SANCTIONED_HELPERS))})")
        if t:
            raise PermissionError(f"{src}: {where} has unknown key(s): {', '.join(sorted(t))}")
        rules.append(AllowRule(id=rid, action=action, reason=reason, scope=scope,
                               helper=helper, note=note))
    return Permissions(slug=slug or "", allow=tuple(rules), example=example)


def load_path(path: str | Path, *, expect_slug: str | None = None) -> Permissions:
    path = Path(path)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise PermissionError(f"no permissions file at {path}") from None
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise PermissionError(f"{path}: not valid TOML: {e}") from None
    decl = parse(data, src=str(path), expect_slug=expect_slug)
    object.__setattr__(decl, "path", path)
    return decl


def path_for(slug: str, root: Path | None = None) -> Path:
    base = paths.event_dir(slug) if root is None else Path(root) / slug
    return base / PROFILE_NAME


def load(slug: str, root: Path | None = None) -> Permissions:
    """Load events/<slug>/permissions.toml, or raise PermissionError if it is absent/invalid."""
    f = path_for(slug, root)
    if not f.is_file():
        raise PermissionError(f"no permissions file for {slug!r} ({f} missing); "
                              "the player writes it (see docs/CONTRACTS.md)")
    return load_path(f, expect_slug=slug)


def load_optional(slug: str, root: Path | None = None) -> Permissions | None:
    """The declaration for slug, or None when no permissions.toml exists (a malformed one still raises)."""
    f = path_for(slug, root)
    if not f.is_file():
        return None
    return load_path(f, expect_slug=slug)
