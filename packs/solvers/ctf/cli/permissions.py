"""ctf permissions [--event SLUG] [--check] — show the player's declared permission rules.

Prints the known-good actions the player pre-authorised for the event (from
events/<slug>/permissions.toml), each with the reason and the sanctioned helper that performs
it the safe way, followed by the sanctioned helpers this repo ships. With --check it only
validates the file and exits non-zero on a problem (no file = nothing declared, which is ok).
A file that still carries `example = true` (a copy of docs/examples/permissions.example.toml the
player has not confirmed) is shown as an unconfirmed example, never as the player's declaration,
and fails --check. This command shows the player's declaration; it does not grant anything.

Exit: 0 ok (or nothing declared), 1 the file is malformed or an unconfirmed example, 2 usage error.
"""
from __future__ import annotations

import argparse
import sys

from .. import event as _event
from .. import permissions as _perms

HELP = "show the player's declared permission rules and the sanctioned helpers"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", metavar="SLUG", help="default: $CTF_EVENT, else the only event")
    p.add_argument("--check", action="store_true",
                   help="validate events/<slug>/permissions.toml and exit non-zero on a problem")
    p.add_argument("--helpers-only", action="store_true",
                   help="print only the sanctioned helpers, not the declaration")


def _slug(args: argparse.Namespace) -> str:
    if args.event:
        return args.event
    return _event.current().slug


def _print_helpers() -> None:
    print("sanctioned helpers (purpose-built so a blocked action is not needed):")
    for name in sorted(_perms.SANCTIONED_HELPERS):
        h = _perms.SANCTIONED_HELPERS[name]
        print(f"  ctf {h.command}")
        print(f"      {h.purpose}")
        print(f"      instead of: {h.replaces}")


def run(args: argparse.Namespace) -> int:
    if args.helpers_only:
        _print_helpers()
        return 0
    try:
        slug = _slug(args)
    except _event.EventError as e:
        print(f"ctf permissions: {e}", file=sys.stderr)
        return 2
    try:
        decl = _perms.load_optional(slug)
    except _perms.PermissionError as e:
        print(f"ctf permissions: {e}", file=sys.stderr)
        return 1
    if decl is not None and decl.example:
        print(f"ctf permissions: {_perms.path_for(slug)} is an unconfirmed example (example = true), "
              f"not the player's declaration; the player confirms it by deleting that line",
              file=sys.stderr)
    if args.check:
        if decl is None:
            print(f"ok: no permissions.toml for {slug!r} (nothing declared)")
        elif decl.example:
            return 1
        else:
            print(f"ok: {_perms.path_for(slug)} is valid ({len(decl.allow)} rule(s))")
        return 0

    if decl is None or not decl.allow:
        print(f"no permission rules declared for {slug!r} "
              f"(the player may add {_perms.path_for(slug)}; template: {_perms.EXAMPLE_PATH}).")
    else:
        if decl.example:
            print(f"UNCONFIRMED EXAMPLE rules for {slug!r}, not declared by the player "
                  f"({_perms.path_for(slug)}):")
        else:
            print(f"player-declared permission rules for {slug!r} ({_perms.path_for(slug)}):")
        for r in decl.allow:
            tail = f"  [helper: ctf {r.helper}]" if r.helper else ""
            scope = f" ({r.scope})" if r.scope else ""
            print(f"  - {r.id}{scope}: {r.action}{tail}")
            print(f"      reason: {r.reason}")
            if r.note:
                print(f"      note: {r.note}")
    print()
    _print_helpers()
    return 0
