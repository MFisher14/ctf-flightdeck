"""Filesystem scope fence for solver agents (B-219).

During CSCTF 2026, Codex event subagents ran 818 commands outside the challenge workspace, looking
for answers in local traces: ~/.codex and ~/.claude session stores, SQLite stores, browser and
Discord caches, the macOS notification database, the unified log and APFS snapshots. This module
defines what a SOLVER may read during an event and renders that one policy three ways:

    from ctf import fence
    f = fence.build(workspace=Path("~/ctf-work/csctf"), drop=Path("~/Downloads/csctf"))
    f.claude_settings()      # dict for `claude --settings <file>` (permissions + sandbox)
    f.codex_profile()        # Codex permission profile (filesystem read deny + write roots)
    f.codex_config_args()    # the `-c` overrides that select that profile
    f.classify(path)         # Verdict: allowed / system / denied:<category> / outside-home / outside

Allowed read roots are the master repo, the event workspace, an optional drop folder (the one
place under ~/Downloads a solver may read) and any extra roots the operator names. Denied roots
are listed in DENY_HOME / DENY_ABS below, each with a category the denied-access report uses.
The repo itself is allowed except for its gitignored sensitive trees (DENY_REPO: analysis/,
docs/writeups/, writeups/, .claude/, .ctf/), and a .ctf/ directory is denied wherever it appears
(DENY_NAMES) (R-03).
With strict_home=True the whole home directory is denied and only the allowed roots (plus the
Python toolchain the repo venv runs on) are re-opened.

The fence is generated per event workspace and handed to the launcher (tools/claude_launch,
tools/codex_launch). It never touches ~/.claude, ~/.codex or the repo's own .claude/settings.json:
a fence there would also fence the people and agents building this repo.

Configuration: optional events/<slug>/fence.toml (unknown keys are an error):

    drop_folder = "~/Downloads/csctf"     # the one readable folder under ~/Downloads
    allow_read  = ["/opt/wordlists"]      # extra read-only roots
    deny_read   = ["~/old-event-repo"]    # extra denied roots (category "operator")
    strict_home = false                   # deny all of $HOME except the allowed roots
"""
from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from . import paths

CONFIG_NAME = "fence.toml"
FENCE_DIRNAME = ".fence"
CLAUDE_SETTINGS_NAME = "claude-settings.json"
CODEX_PROFILE_NAME = "ctf_fence"
CLAUDE_SETTINGS_SCHEMA = "https://json.schemastore.org/claude-code-settings.json"


class FenceError(ValueError):
    """The fence cannot be built as asked (bad root, overlapping roots, bad config). Names why."""


# ------------------------------------------------------------------------------------- deny tables
# (category, home-relative path, is_file, reason). Paths that do not exist are still denied: the
# deny must hold if the app is installed mid-event.
DENY_HOME: tuple[tuple[str, str, bool, str], ...] = (
    # other agents' state: transcripts, session stores, memories, auth
    ("agent-state", ".codex", False, "Codex sessions, SQLite stores, auth"),
    ("agent-state", ".claude", False, "Claude Code transcripts, memory, settings"),
    ("agent-state", ".claude.json", True, "Claude Code config (MCP servers, tokens)"),
    ("agent-state", ".cursor", False, "Cursor agent state"),
    ("agent-state", ".gemini", False, "Gemini CLI state"),
    # credentials and tool config
    ("credentials", ".ssh", False, "SSH keys"),
    ("credentials", ".aws", False, "cloud credentials"),
    ("credentials", ".gnupg", False, "GPG keys"),
    ("credentials", ".kube", False, "cluster credentials"),
    ("credentials", ".config", False, "per-tool config and tokens (gh, gcloud, ...)"),
    ("credentials", ".netrc", True, "login credentials"),
    ("credentials", ".git-credentials", True, "git credentials"),
    ("credentials", ".npmrc", True, "registry token"),
    ("credentials", ".pypirc", True, "registry token"),
    # shell and REPL history
    ("shell-history", ".zsh_history", True, "shell history"),
    ("shell-history", ".zsh_sessions", False, "shell history"),
    ("shell-history", ".bash_history", True, "shell history"),
    ("shell-history", ".bash_sessions", False, "shell history"),
    ("shell-history", ".python_history", True, "REPL history"),
    ("shell-history", ".node_repl_history", True, "REPL history"),
    ("shell-history", ".sqlite_history", True, "REPL history"),
    ("shell-history", ".psql_history", True, "REPL history"),
    ("shell-history", ".mysql_history", True, "REPL history"),
    ("shell-history", ".lesshst", True, "pager history"),
    ("shell-history", ".viminfo", True, "editor history"),
    ("trash", ".Trash", False, "deleted files"),
    # application data: all of ~/Library, then the named stores inside it (so the report can say
    # which store was touched, and so they stay denied if an operator re-opens part of ~/Library)
    ("app-data", "Library", False, "application data (caches, containers, preferences)"),
    ("browser", "Library/Application Support/Google/Chrome", False, "Chrome profile"),
    ("browser", "Library/Application Support/Microsoft Edge", False, "Edge profile"),
    ("browser", "Library/Application Support/BraveSoftware", False, "Brave profile"),
    ("browser", "Library/Application Support/Firefox", False, "Firefox profile"),
    ("browser", "Library/Application Support/Arc", False, "Arc profile"),
    ("browser", "Library/Safari", False, "Safari profile"),
    ("browser", "Library/Containers/com.apple.Safari", False, "Safari container"),
    ("browser", "Library/Caches/Google", False, "Chrome cache"),
    ("browser", "Library/Caches/Microsoft Edge", False, "Edge cache"),
    ("browser", "Library/Caches/Firefox", False, "Firefox cache"),
    ("browser", "Library/Cookies", False, "cookies"),
    ("messaging", "Library/Messages", False, "Messages database"),
    ("messaging", "Library/Mail", False, "Mail store"),
    ("messaging", "Library/Application Support/discord", False, "Discord data and cache"),
    ("messaging", "Library/Application Support/Slack", False, "Slack data and cache"),
    ("messaging", "Library/Containers/com.tinyspeck.slackmacgap", False, "Slack container"),
    ("notifications", "Library/Group Containers/group.com.apple.usernoted", False,
     "notification database"),
    ("credentials", "Library/Keychains", False, "keychains"),
    # other work on this machine
    ("customer-work", "pentest-tools", False, "customer work (never a CTF input)"),
    ("downloads", "Downloads", False, "downloads (only the configured drop folder is readable)"),
    ("personal", "Desktop", False, "personal files"),
    ("personal", "Documents", False, "personal files"),
    ("personal", "Pictures", False, "personal files"),
    ("personal", "Movies", False, "personal files"),
    ("personal", "Music", False, "personal files"),
)

# Absolute, machine-wide stores.
DENY_ABS: tuple[tuple[str, str, bool, str], ...] = (
    ("unified-log", "/private/var/db/diagnostics", False, "unified log"),
    ("unified-log", "/private/var/db/uuidtext", False, "unified log"),
    ("unified-log", "/private/var/log", False, "system logs"),
    ("unified-log", "/Library/Logs", False, "system logs and crash reports"),
    ("snapshots", "/Volumes/com.apple.TimeMachine.localsnapshots", False, "APFS local snapshots"),
    ("snapshots", "/.MobileBackups", False, "local backups"),
    ("snapshots", "/.fseventsd", False, "filesystem event history"),
    ("snapshots", "/.Spotlight-V100", False, "Spotlight index"),
)

# Trees inside the master repo that a solver never reads (R-03). The repo is a read and write
# root, but these gitignored trees hold participant data (analysis/: IP addresses, session ids,
# usage), unredacted writeups and flags (docs/writeups/, writeups/), other agents' build worktrees
# and the repo's agent config (.claude/), and the platform token and cookie (.ctf/). They are
# carved out of the repo root: the more specific deny wins over the repo's allow.
# (category, repo-relative path, is_file, reason)
DENY_REPO: tuple[tuple[str, str, bool, str], ...] = (
    ("repo-private", "analysis", False, "raw analysis output: participant IP addresses, session ids, usage"),
    ("repo-private", "docs/writeups", False, "writeup staging: unredacted screenshots and flags"),
    ("repo-private", "writeups", False, "writeup staging: unredacted screenshots and flags"),
    ("agent-state", ".claude", False, "build worktrees and the repo's agent config"),
    ("credentials", ".ctf", False, "platform token, cookie and per-event credentials"),
)

# Directory names denied wherever they appear, at any depth under any root (R-03): every .ctf/
# holds credentials (the repo's, an event folder's, a challenge workspace's). Rendered as the globs
# /**/<name> and /**/<name>/** (Codex: verified live that these deny inside a writable root, while
# a root-scoped <root>/**/<name> did not).
DENY_NAMES: tuple[tuple[str, str, str], ...] = (
    ("credentials", ".ctf", "platform token, cookie and per-event credentials"),
)

# Commands that reach the same stores without naming a path. Claude Code gets Bash deny rules for
# them (best effort: prefix rules, see docs); the report flags them in any log.
DENY_COMMANDS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("unified-log", r"^(?:/usr/bin/)?log\s+(?:show|stream|collect|archive)\b",
     ("log show", "log stream", "log collect", "/usr/bin/log")),
    ("snapshots", r"^(?:/usr/bin/)?tmutil\b", ("tmutil",)),
    ("snapshots", r"^(?:/sbin/)?mount_apfs\b", ("mount_apfs",)),
    ("snapshots", r"^(?:/usr/sbin/)?diskutil\s+apfs\s+(?:list|mount)", ("diskutil apfs",)),
    ("spotlight", r"^(?:/usr/bin/)?mdfind\b", ("mdfind",)),
)

# Read-only system locations a solver may read without it being worth a report line.
SYSTEM_ROOTS: tuple[str, ...] = (
    "/usr", "/bin", "/sbin", "/opt", "/System", "/Library", "/Applications", "/private/tmp",
    "/private/var/folders", "/private/etc", "/dev", "/nix", "/proc", "/sys",
)

_DATA_VOLUME = "/System/Volumes/Data"
_PRIVATE_ALIASES = ("/var", "/tmp", "/etc")


# ------------------------------------------------------------------------------------------ helpers

def canon(p: str | Path, *, home: Path | str | None = None, cwd: Path | str | None = None) -> Path | None:
    """Lexically normalise a path the way the fence compares it: ~ / $HOME expanded, relative
    paths joined to `cwd` (None when there is no cwd), the APFS data-volume firmlink spelling
    (/System/Volumes/Data/Users/<name>) folded onto /Users/<name>, and /var, /tmp, /etc folded onto /private.
    No filesystem access: this must work on paths from someone else's log."""
    s = str(p).strip()
    if not s:
        return None
    h = str(home if home is not None else Path.home())
    for pre in ("${HOME}", "$HOME"):
        if s == pre or s.startswith(pre + "/"):
            s = h + s[len(pre):]
    if s == "~" or s.startswith("~/"):
        s = h + s[1:]
    if not s.startswith("/"):
        if cwd is None:
            return None
        s = str(cwd).rstrip("/") + "/" + s
    s = os.path.normpath(s)
    if s.startswith("//"):
        s = "/" + s.lstrip("/")
    if s == _DATA_VOLUME or s.startswith(_DATA_VOLUME + "/"):
        rest = s[len(_DATA_VOLUME):] or "/"
        s = rest
    for a in _PRIVATE_ALIASES:
        if s == a or s.startswith(a + "/"):
            s = "/private" + s
    return Path(s)


def _under(p: Path, root: Path) -> bool:
    return p == root or root in p.parents


def darwin_user_dir() -> Path | None:
    """The per-user DARWIN_USER_DIR (holds the notification-center database). None off macOS;
    a FenceError on macOS when getconf cannot answer (a fence missing that store must not pass)."""
    if platform.system() != "Darwin":
        return None
    try:
        out = subprocess.run(["getconf", "DARWIN_USER_DIR"], capture_output=True, text=True,
                             timeout=10, check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError) as e:
        raise FenceError(f"getconf DARWIN_USER_DIR failed ({e}); cannot place the notification "
                         "database deny") from e
    if not out.startswith("/"):
        raise FenceError(f"getconf DARWIN_USER_DIR returned {out!r}, not an absolute path")
    return canon(out)


def toolchain_roots() -> tuple[Path, ...]:
    """What the repo's Python needs to start when strict_home denies all of $HOME: the venv and
    the interpreter install it was made from (uv keeps it under ~/.local/share/uv)."""
    roots = {Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve()}
    return tuple(sorted(roots))


# ------------------------------------------------------------------------------------- the policy

@dataclass(frozen=True)
class DenyRule:
    category: str
    path: Path
    is_file: bool
    reason: str
    carved_from: Path | None = None   # the allowed root this rule carves out of (DENY_REPO)


@dataclass(frozen=True)
class DenyName:
    """A directory name denied at any depth (DENY_NAMES)."""
    category: str
    name: str
    reason: str

    @property
    def globs(self) -> tuple[str, str]:
        return (f"/**/{self.name}", f"/**/{self.name}/**")

    def match(self, p: Path) -> Path | None:
        """The denied directory `p` sits in (or is), or None."""
        parts = p.parts
        for i, part in enumerate(parts):
            if part == self.name:
                return Path(*parts[:i + 1])
        return None


@dataclass(frozen=True)
class Verdict:
    kind: str                    # allowed | system | denied | outside-home | outside
    path: Path
    root: Path | None = None     # the allowed root or deny rule path that decided it
    category: str | None = None  # deny category for kind == "denied"

    @property
    def reportable(self) -> bool:
        return self.kind in ("denied", "outside-home", "outside")


@dataclass(frozen=True)
class FenceConfig:
    drop_folder: Path | None = None
    allow_read: tuple[Path, ...] = ()
    deny_read: tuple[Path, ...] = ()
    strict_home: bool = False
    source: str | None = None


_CONFIG_KEYS = {"drop_folder", "allow_read", "deny_read", "strict_home"}


def load_config(slug: str | None, *, root: Path | None = None) -> FenceConfig:
    """events/<slug>/fence.toml (`root` replaces events/), or the empty config when the event has
    none (the file is optional; the caller prints which source it used). Unknown keys and wrong
    types raise FenceError."""
    if not slug:
        return FenceConfig()
    path = (Path(root) / slug if root is not None else paths.event_dir(slug)) / CONFIG_NAME
    if not path.is_file():
        return FenceConfig()
    try:
        data = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as e:
        raise FenceError(f"{path}: {e}") from e
    unknown = set(data) - _CONFIG_KEYS
    if unknown:
        raise FenceError(f"{path}: unknown key(s) {', '.join(sorted(unknown))}")

    def _paths(key: str) -> tuple[Path, ...]:
        v = data.get(key, [])
        if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
            raise FenceError(f"{path}: {key} must be a list of path strings")
        return tuple(Path(x) for x in v)

    drop = data.get("drop_folder")
    if drop is not None and (not isinstance(drop, str) or not drop):
        raise FenceError(f"{path}: drop_folder must be a path string")
    strict = data.get("strict_home", False)
    if not isinstance(strict, bool):
        raise FenceError(f"{path}: strict_home must be true or false")
    return FenceConfig(drop_folder=Path(drop) if drop else None, allow_read=_paths("allow_read"),
                       deny_read=_paths("deny_read"), strict_home=strict, source=str(path))


@dataclass(frozen=True)
class Fence:
    repo: Path
    workspace: Path
    home: Path
    drop: Path | None = None
    extra_read: tuple[Path, ...] = ()
    deny: tuple[DenyRule, ...] = ()
    strict_home: bool = False
    toolchain: tuple[Path, ...] = ()
    commands: tuple[tuple[str, re.Pattern, tuple[str, ...]], ...] = field(default=())
    deny_names: tuple[DenyName, ...] = ()

    # -- roots ------------------------------------------------------------------------------------
    @property
    def write_roots(self) -> tuple[Path, ...]:
        return (self.workspace, self.repo)

    @property
    def read_roots(self) -> tuple[Path, ...]:
        """Every root a solver may read: the write roots, the drop folder, the extra roots and (in
        strict mode) the toolchain."""
        out = [self.workspace, self.repo]
        if self.drop:
            out.append(self.drop)
        out.extend(self.extra_read)
        if self.strict_home:
            out.extend(self.toolchain)
        return tuple(dict.fromkeys(out))

    # -- classification ---------------------------------------------------------------------------
    def classify(self, p: str | Path, *, cwd: Path | str | None = None) -> Verdict | None:
        """Decide one path. The most specific matching root wins, so the drop folder (allowed)
        beats ~/Downloads (denied) and ~/.codex (denied) beats $HOME in strict mode. None for a
        relative path with no cwd."""
        c = canon(p, home=self.home, cwd=cwd)
        if c is None:
            return None
        for n in self.deny_names:          # a .ctf/ anywhere is denied, whatever root holds it
            hit = n.match(c)
            if hit is not None:
                return Verdict("denied", c, hit, n.category)
        best: tuple[int, Verdict] | None = None
        for r in self.read_roots:
            if _under(c, r) and (best is None or len(r.parts) > best[0]):
                best = (len(r.parts), Verdict("allowed", c, r))
        for d in self.deny:
            if _under(c, d.path) and (best is None or len(d.path.parts) > best[0]):
                best = (len(d.path.parts), Verdict("denied", c, d.path, d.category))
        if best is not None:
            return best[1]
        if _under(c, self.home):
            return Verdict("outside-home", c, self.home)
        for s in SYSTEM_ROOTS:
            sp = Path(s)
            if _under(c, sp):
                return Verdict("system", c, sp)
        return Verdict("outside", c)

    def command_category(self, segment: str) -> str | None:
        """The deny category of a shell segment that reaches a store without naming its path."""
        seg = segment.strip()
        for cat, rx, _ in self.commands:
            if rx.search(seg):
                return cat
        return None

    def watched_names(self) -> frozenset[str]:
        """First path components that may start a RELATIVE path into a denied tree (analysis,
        writeups, docs, .claude, .ctf). The denied-access report classifies relative shell words
        that start with one of these, so `cd ~/ctf-tools && cat analysis/out/x` is still seen."""
        out = {n.name for n in self.deny_names}
        for d in self.deny:
            if d.carved_from is not None:
                out.add(d.path.relative_to(d.carved_from).parts[0])
        return frozenset(out)

    # -- Claude Code ------------------------------------------------------------------------------
    def claude_settings(self) -> dict:
        """Settings for `claude --settings <file>`. Keys checked against Claude Code 2.1.321's
        settings schema (docs/fence.md lists them). Read deny rules stop the file tools and are
        merged into the sandbox's denyRead; the sandbox stops Bash; blockReadsOutsideWorkingDirectories
        confines the file tools to the repo + workspace (+ exempt drop/extra roots).

        In strict mode allowRead lists the whole repo and workspace. That does not re-open the
        repo carve-outs or a .ctf/ for Bash: Claude Code (2.1.322, macOS profile generator) emits
        the allowRead rules after the denyRead rules, then emits again every non-glob deny that
        sits strictly inside a non-glob allow, and every glob deny, exempting only allow paths the
        glob itself matches (docs/fence.md). Listing the repo's children instead would deny
        readdir of the repo itself and break `import ctf` from a sys.path entry there."""
        deny_rules: list[str] = []
        sandbox_deny: list[str] = []
        drop_under_downloads = self.drop is not None and any(
            d.category == "downloads" and _under(self.drop, d.path) for d in self.deny)
        for d in self.deny:
            sandbox_deny.append(str(d.path))
            # A Read deny rule beats every allow, so ~/Downloads gets no Read rule when the drop
            # folder sits inside it; blockReadsOutsideWorkingDirectories still confines the file
            # tools there, and the sandbox denies the rest of ~/Downloads to Bash.
            if d.category == "downloads" and drop_under_downloads:
                continue
            if d.category == "home" and self.strict_home:
                continue    # strict home: the file tools are confined by blockReadsOutside...
            deny_rules.append(f"Read(/{d.path})" if d.is_file else f"Read(/{d.path}/**)")
        for n in self.deny_names:
            for g in n.globs:
                sandbox_deny.append(g)
                deny_rules.append(f"Read(/{g})")
        deny_rules.append("Read(//private/var/folders/**/com.apple.notificationcenter/**)")
        # Writes (R-03 round 1): the repo and workspace are write roots, so the private trees
        # inside them are also denied to the edit tools (Edit(...)) and to sandboxed Bash
        # (denyWrite, which Claude Code renders after the allowWrite roots: the deny holds).
        write_deny = [str(d.path) for d in self.deny if d.carved_from is not None]
        for p in write_deny:
            deny_rules.append(f"Edit(/{p}/**)")
        for n in self.deny_names:
            for g in n.globs:
                write_deny.append(g)
                deny_rules.append(f"Edit(/{g})")
        for _cat, _rx, prefixes in self.commands:
            for pre in prefixes:
                deny_rules.append(f"Bash({pre})")
                deny_rules.append(f"Bash({pre} *)")
        exempt = [str(p) for p in ([self.drop] if self.drop else []) + list(self.extra_read)]
        allow_read = list(exempt)
        if self.strict_home:
            allow_read = [str(p) for p in self.read_roots]
        perms: dict = {
            "deny": list(dict.fromkeys(deny_rules)),
            "additionalDirectories": [str(self.repo), str(self.workspace)],
            "blockReadsOutsideWorkingDirectories": True,
            "disableBypassPermissionsMode": "disable",
        }
        if exempt:
            perms["blockReadsExemptPaths"] = exempt
        fs: dict = {
            "denyRead": list(dict.fromkeys(sandbox_deny)),
            "allowWrite": [str(p) for p in self.write_roots],
            "denyWrite": list(dict.fromkeys(write_deny)),
        }
        if allow_read:
            fs["allowRead"] = list(dict.fromkeys(allow_read))
        return {
            "$schema": CLAUDE_SETTINGS_SCHEMA,
            "permissions": perms,
            "sandbox": {
                "enabled": True,
                "failIfUnavailable": True,
                "allowUnsandboxedCommands": False,
                "filesystem": fs,
            },
        }

    # -- Codex ------------------------------------------------------------------------------------
    def codex_profile(self) -> dict:
        """A Codex permission profile (codex-cli >= 0.167): extends the built-in ":workspace"
        profile, makes the repo and workspace writable, re-opens the read roots for reading and
        denies every deny root. On macOS the seatbelt sandbox enforces the denies for the commands
        Codex runs; the more specific entry wins (verified: a "read" child of a "deny" parent is
        readable, its siblings are not)."""
        fsmap: dict[str, str] = {}
        for d in self.deny:
            fsmap[str(d.path)] = "deny"
        for r in self.read_roots:
            fsmap[str(r)] = "read"
        for w in self.write_roots:
            fsmap[str(w)] = "write"
        # The repo carve-outs (DENY_REPO) are in self.deny above: never a root themselves (build()
        # refuses that), so the root entries do not overwrite them, and Codex lets the more
        # specific deny win inside the writable repo (verified live). Name globs: see DENY_NAMES.
        for n in self.deny_names:
            for g in n.globs:
                fsmap[g] = "deny"
        return {"extends": ":workspace", "filesystem": fsmap}

    def codex_config_args(self, name: str = CODEX_PROFILE_NAME) -> list[str]:
        """`-c` overrides that define and select the profile. Never combined with --sandbox/-s:
        Codex refuses sandbox_mode and default_permissions overrides together."""
        return ["-c", f"permissions.{name}={toml_inline(self.codex_profile())}",
                "-c", f'default_permissions="{name}"']

    # -- serialisation ----------------------------------------------------------------------------
    def describe(self) -> dict:
        return {
            "repo": str(self.repo), "workspace": str(self.workspace), "home": str(self.home),
            "drop": str(self.drop) if self.drop else None,
            "read_roots": [str(p) for p in self.read_roots],
            "write_roots": [str(p) for p in self.write_roots],
            "strict_home": self.strict_home,
            "deny": [{"category": d.category, "path": str(d.path), "reason": d.reason} for d in self.deny],
            "deny_names": [{"category": n.category, "name": n.name, "globs": list(n.globs),
                            "reason": n.reason} for n in self.deny_names],
            "deny_commands": [{"category": c, "pattern": rx.pattern} for c, rx, _ in self.commands],
        }


def toml_inline(v) -> str:
    """Render a value as a TOML inline value (strings, bools, ints, lists, dicts with quoted keys)."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return json.dumps(v)      # a JSON string literal is a valid TOML basic string
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(toml_inline(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ", ".join(f"{json.dumps(str(k))} = {toml_inline(x)}" for k, x in v.items()) + "}"
    raise TypeError(f"cannot render {type(v).__name__} as TOML")


def _abs_root(p: Path | str, what: str, home: Path) -> Path:
    c = canon(p, home=home)
    if c is None:
        raise FenceError(f"{what} must be an absolute path (or ~/...), got {str(p)!r}")
    if c == Path("/"):
        raise FenceError(f"{what} cannot be / (that fences nothing)")
    return c


def _deny_rules(h: Path, r: Path, *, extra_deny: Iterable[Path | str], strict_home: bool,
                user_dir: Path | None | bool) -> list[DenyRule]:
    """Every deny rule of the fence for home `h` and repo `r`: the one source that build() and
    read_fence() share."""
    rules: list[DenyRule] = []
    for cat, rel, is_file, why in DENY_HOME:
        rules.append(DenyRule(cat, h / rel, is_file, why))
    for cat, ab, is_file, why in DENY_ABS:
        rules.append(DenyRule(cat, canon(ab, home=h), is_file, why))
    if user_dir is True:
        ud = darwin_user_dir()
    else:
        ud = canon(user_dir, home=h) if user_dir else None
    if ud is not None:
        rules.append(DenyRule("notifications", ud / "com.apple.notificationcenter", False,
                              "notification database"))
    for cat, rel, is_file, why in DENY_REPO:
        rules.append(DenyRule(cat, r / rel, is_file, why, carved_from=r))
    for p in extra_deny:
        rules.append(DenyRule("operator", _abs_root(p, "deny_read entry", h), False,
                              "denied by the event's fence config"))
    if strict_home:
        rules.append(DenyRule("home", h, False, "strict_home: all of $HOME outside the allowed roots"))
    return rules


def build(*, repo: Path | str | None = None, workspace: Path | str | None = None,
          home: Path | str | None = None, drop: Path | str | None = None,
          extra_read: Iterable[Path | str] = (), extra_deny: Iterable[Path | str] = (),
          strict_home: bool = False, user_dir: Path | None | bool = True,
          toolchain: Iterable[Path] | None = None, slug: str | None = None) -> Fence:
    """Build the fence. `repo` defaults to this checkout, `workspace` to paths.workdir(slug).
    `user_dir` True = ask getconf (macOS), a Path = use it, None/False = none (non-macOS tests).
    Raises FenceError when a root would defeat the fence: the workspace or repo is $HOME or sits
    inside a denied root, the drop folder is ~/Downloads itself, a read root is a deny root."""
    h = Path(home).expanduser() if home is not None else Path.home()
    h = canon(h, home=h)
    r = _abs_root(repo if repo is not None else paths.repo_root(), "repo", h)
    w = _abs_root(workspace if workspace is not None else paths.workdir(slug), "workspace", h)
    d = _abs_root(drop, "drop folder", h) if drop else None
    extra = tuple(_abs_root(p, "allow_read entry", h) for p in extra_read)

    rules = _deny_rules(h, r, extra_deny=extra_deny, strict_home=strict_home, user_dir=user_dir)
    names = tuple(DenyName(cat, n, why) for cat, n, why in DENY_NAMES)

    # Roots that would defeat the fence fail loudly rather than quietly opening a hole.
    for what, root in (("workspace", w), ("repo", r), ("drop folder", d),
                       *(("allow_read entry", e) for e in extra)):
        for n in names:
            if root is not None and n.match(root) is not None:
                raise FenceError(f"the {what} {root} is inside a {n.name}/ directory ({n.category}); "
                                 f"a {n.name}/ directory is never a read root")
    for name, root in (("workspace", w), ("repo", r)):
        if root == h:
            raise FenceError(f"the {name} is $HOME ({h}); the fence would allow everything")
        for rule in rules:
            if rule.category == "home":
                continue
            if name == "repo" and rule.carved_from == r:
                continue    # the repo's own carve-outs sit inside it by construction
            if _under(root, rule.path):
                raise FenceError(f"the {name} {root} is inside the denied {rule.category} root "
                                 f"{rule.path}; move it (a solver workspace never lives there)")
            if _under(rule.path, root):
                raise FenceError(f"the {name} {root} contains the denied {rule.category} root "
                                 f"{rule.path}; pick a narrower {name}")
    if d is not None:
        downloads = h / "Downloads"
        if d == downloads:
            raise FenceError("the drop folder cannot be ~/Downloads itself; name a subfolder "
                             "(e.g. ~/Downloads/<event>)")
        for rule in rules:
            if rule.category in ("downloads", "home"):
                continue
            if _under(d, rule.path) or _under(rule.path, d):
                raise FenceError(f"the drop folder {d} overlaps the denied {rule.category} root "
                                 f"{rule.path}")
    for e in extra:
        for rule in rules:
            if rule.category == "home":
                continue
            if _under(e, rule.path) or _under(rule.path, e):
                raise FenceError(f"allow_read {e} overlaps the denied {rule.category} root "
                                 f"{rule.path}; the fence will not re-open a denied store")
    tc = tuple(toolchain) if toolchain is not None else (toolchain_roots() if strict_home else ())
    cmds = tuple((cat, re.compile(rx), pre) for cat, rx, pre in DENY_COMMANDS)
    return Fence(repo=r, workspace=w, home=h, drop=d, extra_read=extra, deny=tuple(rules),
                 strict_home=strict_home, toolchain=tuple(canon(p, home=h) for p in tc),
                 commands=cmds, deny_names=names)


def from_config(cfg: FenceConfig, **overrides) -> Fence:
    """build() with the event config underneath explicit overrides (None/empty = use config)."""
    kw = dict(drop=cfg.drop_folder, extra_read=cfg.allow_read, extra_deny=cfg.deny_read,
              strict_home=cfg.strict_home)
    for k, v in overrides.items():
        if k in ("extra_read", "extra_deny"):
            kw[k] = tuple(kw.get(k, ())) + tuple(v or ())
        elif k == "strict_home":
            kw[k] = bool(v) or kw["strict_home"]
        elif v is not None:
            kw[k] = v
    return build(**kw)


def read_fence(cfg: FenceConfig, *, repo: Path | str | None = None, workspace: Path | str | None = None,
               home: Path | str | None = None, user_dir: Path | None | bool = True) -> Fence:
    """The fence as a reader checks a path (B-034's `ctf read`): the same deny rules and names,
    drop folder, allow_read and strict_home as build()/from_config(), but without build()'s
    root-placement checks (a reader only classifies; it launches no sandbox). `workspace` defaults
    to the repo (outside an event there is no workspace). Strict mode keeps the toolchain readable."""
    h = Path(home).expanduser() if home is not None else Path.home()
    h = canon(h, home=h)
    r = _abs_root(repo if repo is not None else paths.repo_root(), "repo", h)
    w = _abs_root(workspace, "workspace", h) if workspace is not None else r
    d = _abs_root(cfg.drop_folder, "drop folder", h) if cfg.drop_folder else None
    extra = tuple(_abs_root(p, "allow_read entry", h) for p in cfg.allow_read)
    rules = _deny_rules(h, r, extra_deny=cfg.deny_read, strict_home=cfg.strict_home, user_dir=user_dir)
    tc = toolchain_roots() if cfg.strict_home else ()
    return Fence(repo=r, workspace=w, home=h, drop=d, extra_read=extra, deny=tuple(rules),
                 strict_home=cfg.strict_home, toolchain=tuple(canon(p, home=h) for p in tc),
                 deny_names=tuple(DenyName(cat, n, why) for cat, n, why in DENY_NAMES))


def write_claude_settings(f: Fence, dest: Path | None = None) -> Path:
    """Write the Claude Code settings to <workspace>/.fence/claude-settings.json (or `dest`),
    mode 0600, and return the path."""
    dest = dest or (f.workspace / FENCE_DIRNAME / CLAUDE_SETTINGS_NAME)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".tmp")
    tmp.write_text(json.dumps(f.claude_settings(), indent=2) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, dest)
    return dest
