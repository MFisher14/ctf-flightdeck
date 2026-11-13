"""Launch solver agents inside the filesystem fence (B-219). Used by tools/codex_launch and
tools/claude_launch; kept here so the argv construction is testable without starting an agent.

Codex: `codex [exec] -C <workspace> -c permissions.ctf_fence={...} -c default_permissions="ctf_fence"`
with approvals off (a sandbox denial is returned to the model, never escalated), the fast and
ultrafast speed tiers switched off (B-009: standard tier only), the shell snapshot off (it is
sourced from ~/.codex, which the fence denies), and `-c model_auto_compact_token_limit=<N>` (B-032,
ctf.compaction; a passthrough override of it is refused).

Claude Code: `claude --settings <workspace>/.fence/claude-settings.json`, run from the workspace.

Arguments that would undo the fence are refused with a named reason, not dropped.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Sequence

from . import compaction
from .fence import Fence

# B-095: the Claude Code flag that pins reasoning effort for a session. Codex takes effort as a -c
# config override we build; claude needs a first-class flag. claude_argv() only builds the argv and
# never runs the CLI; tools/claude_launch calls claude_effort_flag() once before a real launch (not on
# a dry run) and fails loudly by name when the installed CLI does not document the flag.
CLAUDE_EFFORT_FLAG = "--effort"
# Wall-clock bound on `claude --help`. It only keeps a hung CLI from hanging the launcher, so it sits
# far above the CLI's start-up time on a heavily loaded machine.
CLAUDE_HELP_TIMEOUT_S = 60.0

APPROVAL_POLICIES = ("never", "on-request", "untrusted")
FAST_TIERS = ("fast", "priority", "ultrafast", "flex-fast")
CODEX_DISABLED_FEATURES = ("fast_mode", "ultrafast_mode", "shell_snapshot")
# B-201: the codex speed tiers a budgeted route may name, each with the feature switch it needs on
# ("" when none). Only codex_argv(service_tier=) uses it; a passthrough is still refused.
CODEX_SPEED_TIERS = {"fast": "fast_mode", "ultrafast": "ultrafast_mode", "priority": ""}


class LaunchError(ValueError):
    """An argument would defeat the fence or the standard service tier."""


# Codex flags that replace or bypass the fence's sandbox, or widen what it can write.
_CODEX_REFUSED_FLAGS = {
    "-s": "selects a sandbox mode; the fence's permission profile is the sandbox",
    "--sandbox": "selects a sandbox mode; the fence's permission profile is the sandbox",
    "--dangerously-bypass-approvals-and-sandbox": "turns the sandbox off",
    "--approve-for-me": "lets an automated reviewer approve commands outside the sandbox",
    "--full-auto": "selects its own sandbox mode",
    "--yolo": "turns the sandbox off",
    "-a": "approval policy is a launcher option (--approval)",
    "--ask-for-approval": "approval policy is a launcher option (--approval)",
    "--add-dir": "adds a writable root outside the fence",
    "-p": "layers a config profile that can change sandbox and tier",
    "--profile": "layers a config profile that can change sandbox and tier",
    "-P": "selects another permission profile",
    "--permission-profile": "selects another permission profile",
    "--permissions-profile": "selects another permission profile",
    "-C": "the workspace is a launcher option (--workspace)",
    "--cd": "the workspace is a launcher option (--workspace)",
}
_CODEX_REFUSED_CONFIG = re.compile(
    r"^(?:sandbox_mode|default_permissions|permissions(?:\..*)?|sandbox_workspace_write(?:\..*)?|"
    r"approval_policy|service_tier|features\.(?:fast_mode|ultrafast_mode|shell_snapshot)|profile|"
    r"model_auto_compact_token_limit)\s*=")


def check_codex_extra(extra: Sequence[str]) -> None:
    """Refuse passthrough arguments that would undo the fence or pick a fast tier."""
    it = iter(range(len(extra)))
    for i in it:
        a = extra[i]
        if a.startswith("--"):
            flag, eq, inline = a.partition("=")
            attached = bool(eq)
        elif a.startswith("-") and len(a) > 2:
            # clap's attached short forms: -sVALUE and -s=VALUE are -s VALUE
            flag, inline = a[:2], a[2:]
            inline = inline[1:] if inline.startswith("=") else inline
            attached = True
        else:
            flag, inline, attached = a, "", False
        if flag in _CODEX_REFUSED_FLAGS:
            raise LaunchError(f"refused codex argument {flag}: {_CODEX_REFUSED_FLAGS[flag]}")
        if flag in ("-c", "--config"):
            val = inline if attached else (extra[i + 1] if i + 1 < len(extra) else "")
            if _CODEX_REFUSED_CONFIG.match(val.strip()):
                raise LaunchError(f"refused codex override {val.split('=')[0].strip()!r}: the "
                                  "launcher sets the sandbox, approvals, service tier and compaction "
                                  "threshold (CTF_COMPACT_CODEX, B-032)")
            if not attached:
                next(it, None)
        if flag in ("--enable",):
            val = inline if attached else (extra[i + 1] if i + 1 < len(extra) else "")
            if val in CODEX_DISABLED_FEATURES:
                raise LaunchError(f"refused --enable {val}: the launcher keeps it off "
                                  "(standard service tier; no shell snapshot from ~/.codex)")
            if not attached:
                next(it, None)


def codex_argv(fence: Fence, *, codex_bin: str = "codex", headless: bool = True,
               model: str | None = None, effort: str | None = None, approval: str = "never",
               extra: Sequence[str] = (), prompt: str | None = None,
               service_tier: str | None = None) -> list[str]:
    """The codex command line. `service_tier` (B-201) is only for a speed-tier route the launcher has
    already admitted (budget-gated, metered, with the route's budget_usd as the run's cap): it sets
    `-c service_tier="<tier>"` and leaves that tier's feature switch on. None or "default" keeps
    B-009's standard tier (every fast feature disabled)."""
    if approval not in APPROVAL_POLICIES:
        raise LaunchError(f"approval must be one of {', '.join(APPROVAL_POLICIES)} (got {approval!r})")
    check_codex_extra(extra)
    tier = None if service_tier in (None, "default") else service_tier
    if tier is not None and tier not in CODEX_SPEED_TIERS:
        raise LaunchError(f"unknown codex service tier {tier!r}; one of: {', '.join(CODEX_SPEED_TIERS)}")
    argv = [codex_bin]
    if headless:
        argv += ["exec", "--skip-git-repo-check"]
    argv += ["-C", str(fence.workspace)]
    argv += fence.codex_config_args()
    argv += ["-c", f'approval_policy="{approval}"']
    for feat in CODEX_DISABLED_FEATURES:
        if tier is not None and CODEX_SPEED_TIERS[tier] == feat:
            continue                    # B-201: the routed speed tier's own switch stays on
        argv += ["--disable", feat]
    if tier is not None:
        argv += ["-c", f'service_tier="{tier}"']
    if model:
        argv += ["-m", model]
    if effort:
        argv += ["-c", f'model_reasoning_effort="{effort}"']
    try:
        argv += compaction.codex_config_args()      # B-032: compact at the Codex threshold
    except compaction.CompactionError as e:
        raise LaunchError(str(e)) from None
    argv += list(extra)
    if prompt is not None:
        argv.append(prompt)
    return argv


_CLAUDE_REFUSED = {
    "--dangerously-skip-permissions": "bypasses permission checks",
    "--allow-dangerously-skip-permissions": "offers bypassing permission checks",
    "--settings": "the fence settings are the launcher's --settings",
    "--add-dir": "adds a working directory outside the fence (use the fence's allow_read)",
}


def check_claude_extra(extra: Sequence[str]) -> None:
    for i, a in enumerate(extra):
        flag, _, inline = a.partition("=")
        if flag in _CLAUDE_REFUSED:
            raise LaunchError(f"refused claude argument {flag}: {_CLAUDE_REFUSED[flag]}")
        if flag == "--permission-mode":
            val = inline or (extra[i + 1] if i + 1 < len(extra) else "")
            if val == "bypassPermissions":
                raise LaunchError("refused --permission-mode bypassPermissions: it bypasses "
                                  "permission checks")


def _claude_help(claude_bin: str, timeout: float = CLAUDE_HELP_TIMEOUT_S) -> str:
    """The installed Claude CLI's `--help` text. Reads the documented flags; starts no session and
    makes no model call. stdin is /dev/null, so the call cannot consume a prompt piped to the
    launcher. Raises LaunchError (named) when the CLI cannot be started (absent, not executable) or
    `--help` does not return within `timeout` seconds."""
    try:
        r = subprocess.run([claude_bin, "--help"], capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        raise LaunchError(f"`{claude_bin} --help` did not return within {timeout:g} s; cannot confirm "
                          f"the CLI documents {CLAUDE_EFFORT_FLAG} (B-095)") from None
    except (OSError, subprocess.SubprocessError) as e:
        # the first exec of the agent binary on a launch with an effort: an unrunnable CLI shows here
        raise LaunchError(f"could not start {claude_bin} to read its --help: {e}") from None
    return (r.stdout or "") + "\n" + (r.stderr or "")


def claude_effort_flag(claude_bin: str = "claude", *, help_text: str | None = None,
                       timeout: float = CLAUDE_HELP_TIMEOUT_S) -> str:
    """Return the Claude CLI's effort flag when the installed CLI documents one, else raise LaunchError
    naming the flag and the binary. B-095: effort is pinned at launch via a real CLI flag; if this
    build of Claude Code has no such flag, the launcher fails loudly rather than silently dropping the
    tier (a solver that should run high would run at the CLI default). Runs `claude_bin --help` once
    (no session, no model call, nothing cached); `help_text` replaces that call (tests)."""
    text = help_text if help_text is not None else _claude_help(claude_bin, timeout)
    # Match the flag at an option-line start, e.g. "  --effort <level>  Effort level ...".
    if re.search(rf"(?m)^\s*{re.escape(CLAUDE_EFFORT_FLAG)}\b", text):
        return CLAUDE_EFFORT_FLAG
    raise LaunchError(
        f"installed Claude CLI ({claude_bin!r}) documents no {CLAUDE_EFFORT_FLAG} flag; this build "
        "cannot pin reasoning effort at launch (B-095). Update the CLI or launch without --effort")


def claude_argv(settings_path: Path, *, claude_bin: str = "claude", extra: Sequence[str] = (),
                effort: str | None = None) -> list[str]:
    """The claude command line. Pure: it never runs the CLI (a dry run and a test need no binary).
    With `effort` it puts `--effort <effort>` before the passthrough args; the caller confirms the
    flag with claude_effort_flag() before a real launch (tools/claude_launch does)."""
    check_claude_extra(extra)
    argv = [claude_bin, "--settings", str(settings_path)]
    if effort:
        argv += [CLAUDE_EFFORT_FLAG, str(effort)]
    return [*argv, *extra]
