"""The one place environment variables are read. `CTF_*` names are canonical.

    from ctf import env
    env.get("CTF_WORKDIR")              # str | None
    env.get_bool("CTF_TESTING")         # "1/true/yes/on" -> True
    env.require("CTF_EVENT")            # str, or EnvError naming the variable

The four source repos used `HUNTRESS_*` and `CSCTF_*` prefixes. Until unit B-001a migrates every
caller, a lookup of a canonical name also reads its legacy spellings and emits a DeprecationWarning
naming the old and new name when one is used. The canonical name always wins when both are set.

Legacy spellings of `CTF_X`, in order:
  1. the explicit renames in RENAMES (a name that changed more than its prefix), then
  2. `HUNTRESS_X`, then `CSCTF_X`.

An empty value counts as unset (the forks used `os.environ.get(...) or default`).
Secret-bearing variables (CTF_TOKEN, CTF_COOKIE) are read here like any other but must never be
printed or logged by a caller.
"""
from __future__ import annotations

import os
import warnings
from typing import Mapping

CANONICAL_PREFIX = "CTF_"
LEGACY_PREFIXES = ("HUNTRESS_", "CSCTF_")

# Canonical name -> legacy names that are not a plain prefix swap. Checked before the prefix rule.
RENAMES: dict[str, tuple[str, ...]] = {
    "CTF_PLATFORM_URL": ("CSCTF_URL", "HUNTRESS_GM_URL"),
    "CTF_TOKEN": ("CSCTF_TOKEN", "HUNTRESS_GM_TOKEN"),
    "CTF_COOKIE": ("CSCTF_COOKIE",),
    "CTF_TEAM_ID": ("CSCTF_TEAM_ID",),
}

_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})


class EnvError(RuntimeError):
    """A required variable is missing or holds a value that cannot be parsed."""


def _check(name: str) -> None:
    if not name.startswith(CANONICAL_PREFIX):
        raise ValueError(f"env lookups use the canonical CTF_* name, got {name!r}")


def legacy_names(name: str) -> tuple[str, ...]:
    """Every legacy spelling read for canonical `name`, in lookup order."""
    _check(name)
    suffix = name[len(CANONICAL_PREFIX):]
    out = list(RENAMES.get(name, ()))
    for p in LEGACY_PREFIXES:
        cand = p + suffix
        if cand not in out:
            out.append(cand)
    return tuple(out)


def get(name: str, default: str | None = None, *, environ: Mapping[str, str] | None = None) -> str | None:
    """Value of canonical `name`, else of its first set legacy spelling (with a DeprecationWarning),
    else `default`."""
    _check(name)
    e = os.environ if environ is None else environ
    val = e.get(name)
    if val:
        return val
    for old in legacy_names(name):
        val = e.get(old)
        if val:
            warnings.warn(f"environment variable {old} is deprecated; set {name} instead",
                          DeprecationWarning, stacklevel=2)
            return val
    return default


def get_bool(name: str, default: bool = False, *, environ: Mapping[str, str] | None = None) -> bool:
    raw = get(name, None, environ=environ)
    if raw is None:
        return default
    v = raw.strip().lower()
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    raise EnvError(f"{name}={raw!r} is not a boolean (use 1/0, true/false, yes/no, on/off)")


def get_int(name: str, default: int | None = None, *, environ: Mapping[str, str] | None = None) -> int | None:
    raw = get(name, None, environ=environ)
    if raw is None:
        return default
    try:
        return int(raw.strip())
    except ValueError:
        raise EnvError(f"{name}={raw!r} is not an integer") from None


def require(name: str, *, environ: Mapping[str, str] | None = None) -> str:
    val = get(name, None, environ=environ)
    if val is None:
        raise EnvError(f"{name} is not set (legacy spellings also unset: {', '.join(legacy_names(name))})")
    return val
