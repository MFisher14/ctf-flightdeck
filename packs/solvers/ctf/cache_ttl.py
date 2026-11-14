"""Prompt-cache TTL choices for launched Claude agents (B-118).

    from ctf import cache_ttl
    cache_ttl.ttl_for("main")                 # "5m", or the CTF_CACHE_TTL_CLAUDE override; None when "off"
    cache_ttl.ttl_for("standby")              # "1h", or the CTF_CACHE_TTL_STANDBY override
    cache_ttl.launch_env("main")              # ({"CLAUDE_CODE_PROMPT_CACHE_TTL": "5m", ...}, [to unset])
    cache_ttl.check_build(claude_bin)         # True | None (launcher shim); CacheTtlError when absent

Why (analysis tokens/EFFICIENCY-PLAN.md section 3.12): 1-hour cache writes on Claude main threads cost
$643.63 and 90.2% of them were followed by the next response within 5 minutes, where a 5-minute write
(1.25x input instead of 2x) would have hit just the same. Subagents are already on 5-minute writes, and
moving them to 1 hour loses money overall, so they are left as they are. The real fix for cold
re-caching is not letting agents idle past 5 minutes (B-017, the no-model watcher).

The control (read in the installed Claude Code 2.1.322 build, never run): the environment variable
CLAUDE_CODE_PROMPT_CACHE_TTL, an enum of exactly "5m" | "1h", sets the TTL of the main conversation
(interactive, -p and SDK turns, and the helpers inline with it); CLAUDE_CODE_SUBAGENT_PROMPT_CACHE_TTL
sets everything else (subagents, workflows, background requests). Unset, the main conversation is 1 hour
on a Claude subscription and 5 minutes on an API key; subagents are 5 minutes unless
ENABLE_PROMPT_CACHING_1H is on. The environment beats the `promptCacheTtl` / `subagentPromptCacheTtl`
settings. A truthy FORCE_PROMPT_CACHING_5M ("1", "true", "yes", "on") forces every request to 5 minutes
ahead of everything, and CLAUDE_CODE_MESSAGES_PROMPT_CACHE_TTL forces the message breakpoints to 5m when it
is exactly "5m" (compared untrimmed; 2.1.323 reads it the same way).

Roles:
  main     a launched main thread (tools/claude_launch): 5m.
  standby  a warm standby agent (B-037, ctf/standby.py) that idles up to DEFAULT_TIMEOUT (9 min) blocked
           on `ctf standby take` before its first real turn: 1h, so the warm prefix survives the wait
           (tools/claude_launch --standby). It keeps 1h for its whole life: the TTL is read at start.
Subagents are never set here: CLAUDE_CODE_SUBAGENT_PROMPT_CACHE_TTL passes through untouched.

Overrides: CTF_CACHE_TTL_CLAUDE (main) and CTF_CACHE_TTL_STANDBY (standby) take "5m", "1h" or "off"
(leave the harness default alone, nothing set). Anything else raises CacheTtlError; never a default.

Nested launches: a launcher sets CTF_CACHE_TTL_LAUNCHED to the TTL it chose, beside the Claude variable.
An agent that itself runs tools/claude_launch (an orchestrator starting a standby agent) passes both on;
an inherited CLAUDE_CODE_PROMPT_CACHE_TTL equal to CTF_CACHE_TTL_LAUNCHED is a launcher's own and is
replaced (or, with the TTL off, removed). Any other inherited value that differs is refused.

Conflicts (refused, the compaction pattern): an inherited CLAUDE_CODE_PROMPT_CACHE_TTL that differs from
the chosen TTL and is not a launcher's (set the CTF_ override instead), and, when the chosen TTL is 1h,
a truthy FORCE_PROMPT_CACHING_5M or CLAUDE_CODE_MESSAGES_PROMPT_CACHE_TTL=5m (they would silently pull
the standby agent back to 5 minutes). With the TTL off nothing is refused.

Measuring: `python -m ctf usage ttl` (tools/ledger/usage.ttl_report) prices, per thread, the 1-hour
writes whose next response came within 5 minutes at the 5-minute rate (gross), and the counter-cost: a
response more than 5 minutes but within 1 hour after the previous one would have found the cache expired
at 5m and written its whole read prefix again. Net is the whole thread at 5m.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping

from . import env as _env

TTLS = ("5m", "1h")
ROLES = ("main", "standby")
DEFAULTS = {"main": "5m", "standby": "1h"}
ENV_VARS = {"main": "CTF_CACHE_TTL_CLAUDE", "standby": "CTF_CACHE_TTL_STANDBY"}

CLAUDE_TTL_VAR = "CLAUDE_CODE_PROMPT_CACHE_TTL"
CLAUDE_SUBAGENT_TTL_VAR = "CLAUDE_CODE_SUBAGENT_PROMPT_CACHE_TTL"   # never set: subagents stay as-is
CLAUDE_FORCE_5M_VAR = "FORCE_PROMPT_CACHING_5M"
CLAUDE_MESSAGES_TTL_VAR = "CLAUDE_CODE_MESSAGES_PROMPT_CACHE_TTL"
LAUNCHED_VAR = "CTF_CACHE_TTL_LAUNCHED"      # the TTL a repo launcher set (nested launches replace it)
# Claude Code's own truthy spellings for a boolean variable (2.1.322: trimmed, case-insensitive).
CLAUDE_TRUE = ("1", "true", "yes", "on")
# The string a Claude Code build must contain for the knob to exist (read, never run).
KNOB_MARKER = CLAUDE_TTL_VAR.encode()


class CacheTtlError(ValueError):
    """An unusable TTL override, a conflicting harness setting, or a Claude build without the knob."""


def _role(role: str) -> str:
    if role not in ROLES:
        raise CacheTtlError(f"unknown agent role {role!r} (one of {', '.join(ROLES)})")
    return role


def parse_ttl(text: str, *, name: str = "value") -> str | None:
    """'5m' / '1h' -> itself, 'off' -> None (case and surrounding space ignored). Else CacheTtlError."""
    raw = text.strip().lower()
    if raw == "off":
        return None
    if raw in TTLS:
        return raw
    raise CacheTtlError(f"{name}={text!r} is not a prompt-cache TTL ({', '.join(TTLS)}) or 'off'")


def ttl_for(role: str, environ: Mapping[str, str] | None = None) -> str | None:
    """The cache-write TTL a launched agent of `role` gets: DEFAULTS[role], or its CTF_ override; None
    when the override is 'off'."""
    r = _role(role)
    if r == "main":
        raw = _env.get("CTF_CACHE_TTL_CLAUDE", environ=environ)
    else:
        raw = _env.get("CTF_CACHE_TTL_STANDBY", environ=environ)
    if raw is None:
        return DEFAULTS[r]
    return parse_ttl(raw, name=ENV_VARS[r])


def claude_truthy(v: str | None) -> bool:
    """How Claude Code reads a boolean variable: true only for 1/true/yes/on."""
    return v is not None and v.strip().lower() in CLAUDE_TRUE


def _launchers_own(e: Mapping[str, str]) -> bool:
    """Whether the inherited CLAUDE_CODE_PROMPT_CACHE_TTL is the one a repo launcher set."""
    have = (e.get(CLAUDE_TTL_VAR) or "").strip()
    return bool(have) and have == (_env.get(LAUNCHED_VAR, environ=e) or "").strip()


def conflicts(role: str, environ: Mapping[str, str] | None = None) -> list[str]:
    """Settings in `environ` that would override or undo the chosen TTL (empty when it is off)."""
    e = os.environ if environ is None else environ
    t = ttl_for(role, e)
    if t is None:
        return []
    out = []
    have = e.get(CLAUDE_TTL_VAR)
    if have and have.strip() and have.strip() != t and not _launchers_own(e):
        out.append(f"{CLAUDE_TTL_VAR}={have} differs from the {role} TTL {t} (set {ENV_VARS[role]} instead)")
    if t == "1h":
        if claude_truthy(e.get(CLAUDE_FORCE_5M_VAR)):
            out.append(f"{CLAUDE_FORCE_5M_VAR} is set (it forces every cache write to 5m)")
        if e.get(CLAUDE_MESSAGES_TTL_VAR) == "5m":     # Claude compares it exactly (=== "5m", no trim)
            out.append(f"{CLAUDE_MESSAGES_TTL_VAR}=5m forces the message cache writes to 5m")
    return out


def launch_env(role: str = "main", environ: Mapping[str, str] | None = None) -> tuple[dict[str, str], list[str]]:
    """(variables to set, variables to unset) for a Claude agent of `role`: the TTL and its launcher mark,
    or, when the TTL is off, nothing to set and a launcher-set TTL inherited from a parent launch to
    remove. A conflicting setting raises CacheTtlError naming it."""
    e = os.environ if environ is None else environ
    t = ttl_for(role, e)
    if t is None:
        if _launchers_own(e):
            return {}, [CLAUDE_TTL_VAR, LAUNCHED_VAR]
        return {}, []
    bad = conflicts(role, e)
    if bad:
        raise CacheTtlError("refusing to start Claude with a conflicting prompt-cache setting: "
                            + "; ".join(bad))
    return {CLAUDE_TTL_VAR: t, LAUNCHED_VAR: t}, []


def _which(claude_bin: str, environ: Mapping[str, str]) -> str | None:
    if os.sep in claude_bin:
        p = Path(claude_bin).expanduser()
        return str(p) if p.is_file() else None
    for d in environ.get("PATH", os.defpath).split(os.pathsep):
        cand = Path(d or ".") / claude_bin
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    return None


def check_build(claude_bin: str, environ: Mapping[str, str] | None = None) -> bool | None:
    """Whether the installed Claude Code build knows CLAUDE_CODE_PROMPT_CACHE_TTL (the file is read in
    chunks, never run). True: it does. None: `claude_bin` is a small `#!` launcher shim that does not name
    it, so this cannot tell (the caller says so). A build without the string, a missing binary or an
    unreadable one raises CacheTtlError: the TTL would be ignored without a word."""
    from .compaction import knob_in_build
    e = os.environ if environ is None else environ
    found = _which(claude_bin, e)
    if found is None:
        raise CacheTtlError(f"claude CLI not found ({claude_bin!r}): cannot confirm it knows {CLAUDE_TTL_VAR}")
    try:
        has = knob_in_build(Path(found).resolve(), KNOB_MARKER)
    except OSError as err:
        raise CacheTtlError(f"cannot read {found} to look for {CLAUDE_TTL_VAR}: {err}") from None
    if has is False:
        raise CacheTtlError(f"the installed Claude Code build ({found}) has no {CLAUDE_TTL_VAR}: the cache "
                            f"TTL would be ignored; update it, or set {ENV_VARS['main']}=off "
                            f"({ENV_VARS['standby']}=off for --standby) to launch with the harness default")
    return has

