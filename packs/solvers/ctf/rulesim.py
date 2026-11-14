"""Simulate every command and write a brief asks for against the rules an agent runs under (B-190).

    from ctf import rulesim
    acts = rulesim.extract(brief_text)                       # [Action(kind, text, line, via)]
    claude = rulesim.ClaudeRules.from_settings(fence.claude_settings(), cwd=ws, home=h, mode="default")
    codex = rulesim.CodexRules.from_fence(fence)
    rows = rulesim.simulate(acts, [claude, codex])          # [Decision(harness, action, verdict, reason)]

Nothing is run: a brief is data (often written next to challenge files) and is only parsed.

Why: a background agent that hits a permission prompt does not raise one in the main session, it just
fails; a release-morning write hit a prompt nobody expected; and a standing "permissions" warning
kept firing after the rules had been updated because it was checked against a stale copy. So the
simulation reads the rules the launcher would hand the agent now (the fence, ctf/fence.py), or a
settings file named explicitly, and nothing cached.

What is extracted from a brief (markdown):
  - fenced code blocks tagged sh, bash, shell, zsh, console, shell-session or terminal: every line
    that is not blank or a comment is a command (a trailing backslash continues it; a leading "$ "
    or "% " prompt is stripped; in console/shell-session/terminal blocks only prompt lines count);
    untagged blocks: only "$ " lines
  - inline code spans that start with a command-looking word (./x, /x, ~/x, .venv/..., tools/...,
    or a known program name) and hold a space: a command
  - inline code spans that are a path (absolute, ~/..., ./..., or containing a "/"): a write when
    the line asks to write/save/create/append/record/put/store/output/copy/move/edit it, else a read;
    on such a write line a bare file name with an extension (`flag.txt`) is a write in the cwd too
  - from every command: redirection targets, tee/touch/mkdir/cp/mv/rm/ln destinations (writes),
    "<" sources and path-looking arguments (reads); `cd DIR` moves the cwd for what follows

Claude Code (approximating its permission rules; docs/fence.md has the live-verified parts):
  - Bash: per sub-command (split on && || ; | &): a deny rule -> deny; an ask rule -> prompt; an
    allow rule -> allow; else, with the sandbox enabled and autoAllowBashIfSandboxed not false, the
    sandbox runs it (allow); else prompt. The paths a command touches are then checked against the
    sandbox filesystem lists: writes must sit under allowWrite (or the cwd) and not under denyWrite;
    reads under denyRead are refused unless allowRead re-opens a more specific path (or the same
    path, for a plain deny: allowRead is emitted after denyRead). Glob entries (/**/.ctf) match a
    path component and are not re-opened by a plain allowRead.
  - file tools: Read(...) / Edit(...) / Write(...) rules, deny before ask before allow. Writes with no
    rule: allowed in the working directories (cwd + additionalDirectories) only in acceptEdits mode;
    else a prompt. Reads with no rule: allowed in the working directories (and blockReadsExemptPaths);
    outside them denied when blockReadsOutsideWorkingDirectories is set, else a prompt.
  - mode dontAsk turns every prompt into a deny; bypassPermissions is refused (the launcher refuses it).
  - mode auto (what the launchers pass: LAUNCH_PERMISSION_MODE): deny rules still deny and allow rules
    still allow; a file-tool write in a working directory is allowed (as in acceptEdits); everything
    that would prompt goes to Claude Code's auto-mode classifier instead, which this simulation cannot
    run. That verdict is "classifier": approximate, never a blocking prompt, and reported as a warning
    (the classifier may still refuse it at run time).
Codex (the fence's permission profile, approvals "never", so it never prompts):
  - the most specific filesystem entry wins (deny / read / write; the /**/<name> globs deny a path
    component). With no entry, ":workspace" applies: reads allowed, writes only in the cwd and the
    temp folders. A command matching a fence deny command (log show, tmutil, ...) is a deny: the
    sandbox refuses the store it reads and the denied-access report flags it.

A rule a harness reads from elsewhere (~/.claude/settings.json, managed settings) is NOT read here;
the simulation says so in its detail. Prompt in a background agent = blocking; in an interactive
session = advisory.
"""
from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from .fence import canon as _canon

KINDS = ("command", "write", "read")
VERDICTS = ("allow", "deny", "prompt", "classifier")
CLAUDE_MODES = ("default", "acceptEdits", "plan", "dontAsk", "auto")
# The mode the launchers start Claude in: tools/pink_launch.sh's PERMISSION_MODE default, and the
# `--permission-mode auto` docs/fence.md passes to tools/claude_launch. A test ties the two together.
LAUNCH_PERMISSION_MODE = "auto"
# The file the launchers write a brief to, one level under the event workdir:
# <workdir>/<challenge dir>/codex_brief[-LABEL].md (tools/codex_handoff.sh --brief).
LAUNCHER_BRIEF_GLOB = "*/codex_brief*.md"
SHELL_LANGS = frozenset({"sh", "bash", "shell", "zsh", "console", "shell-session", "terminal"})
PROMPT_ONLY_LANGS = frozenset({"console", "shell-session", "terminal"})
MAX_BRIEF_BYTES = 1_000_000
MAX_ACTIONS = 2000

_WRITE_WORDS = re.compile(
    r"\b(write|writes|writing|written|save|saves|saving|create|creates|append|appends|record|records|"
    r"put|puts|store|stores|output|outputs|copy|copies|move|moves|edit|edits|overwrite|update|updates|"
    r"drop|log)\b", re.I)
_KNOWN_PROGRAMS = frozenset((
    "python", "python3", "bash", "sh", "zsh", "uv", "pip", "git", "docker", "curl", "wget", "nc",
    "ncat", "make", "gcc", "cc", "clang", "node", "npm", "npx", "cat", "ls", "cp", "mv", "rm", "mkdir",
    "touch", "tee", "grep", "rg", "sed", "awk", "find", "file", "strings", "xxd", "hexdump", "tar",
    "unzip", "zip", "7z", "binwalk", "exiftool", "radare2", "r2", "gdb", "objdump", "readelf",
    "ghidraRun", "jadx", "apktool", "sqlmap", "hashcat", "john", "ffuf", "openssl", "ssh", "scp",
    "log", "tmutil", "mdfind", "diskutil", "mount_apfs", "codex", "claude", "cd", "echo", "printf",
    "chmod", "ln", "head", "tail", "sort", "uniq", "wc", "jq", "base64", "env", "sudo", "open",
))
_BARE_FILE = re.compile(r"^[\w.-]+\.[A-Za-z0-9]{1,8}$")
_OPS = frozenset({"&&", "||", ";", "|", "&", ";;", "|&", "\n"})
_REDIRECT_OUT = frozenset({">", ">>", "&>", ">|", "&>>", ">&"})


class RulesError(ValueError):
    """A settings file or profile the simulation cannot read. Names why."""


@dataclass(frozen=True)
class Action:
    kind: str          # command | write | read
    text: str          # the command line, or the path as written
    line: int          # 1-based line in the brief
    via: str = ""      # for a path found inside a command: that command
    cwd: str = ""      # the directory a relative path resolves against ("" = the agent's cwd)

    def __post_init__(self):
        if self.kind not in KINDS:
            raise ValueError(f"action kind {self.kind!r} is not one of {KINDS}")

    def where(self) -> str:
        return f"line {self.line}"


@dataclass(frozen=True)
class Decision:
    harness: str
    action: Action
    verdict: str       # allow | deny | prompt | classifier (auto mode: approximate, never blocking)
    reason: str

    def __post_init__(self):
        if self.verdict not in VERDICTS:
            raise ValueError(f"verdict {self.verdict!r} is not one of {VERDICTS}")


# ------------------------------------------------------------------------------------- extraction

def _logical_lines(lines: list[tuple[int, str]]) -> list[tuple[int, str]]:
    out, buf, start = [], "", None
    for n, raw in lines:
        if start is None:
            start = n
        s = raw.rstrip()
        if s.endswith("\\"):
            buf += s[:-1] + " "
            continue
        out.append((start, buf + s))
        buf, start = "", None
    if buf:
        out.append((start, buf))
    return out


def _prompt_stripped(s: str) -> str | None:
    t = s.lstrip()
    for p in ("$ ", "% "):
        if t.startswith(p):
            return t[len(p):].strip()
    return None


def _looks_like_command(span: str) -> bool:
    s = span.strip()
    if " " not in s:
        return False
    first = s.split()[0]
    if first.startswith(("./", "/", "~/", ".venv/", "tools/")):
        return True
    return first in _KNOWN_PROGRAMS


def _looks_like_path(span: str) -> bool:
    s = span.strip()
    if not s or " " in s or "://" in s or s.startswith("-"):
        return False
    return s.startswith(("/", "~/", "./", "../")) or s == "~" or "/" in s


def extract(text: str) -> list[Action]:
    """Every command, write and read the brief asks for, in order (see the module docstring)."""
    if len(text.encode("utf-8", "replace")) > MAX_BRIEF_BYTES:
        raise RulesError(f"brief is larger than {MAX_BRIEF_BYTES} bytes: not a brief")
    acts: list[Action] = []
    lines = text.splitlines()
    i = 0
    fence_rx = re.compile(r"^\s*(```+|~~~+)\s*([A-Za-z0-9_+-]*)")
    while i < len(lines):
        m = fence_rx.match(lines[i])
        if m:
            marker, lang = m.group(1), m.group(2).lower()
            body: list[tuple[int, str]] = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith(marker[:3]):
                body.append((i + 1, lines[i]))
                i += 1
            i += 1  # the closing fence
            for n, s in _logical_lines(body):
                cmd = _prompt_stripped(s)
                if cmd is None:
                    if lang not in SHELL_LANGS or lang in PROMPT_ONLY_LANGS:
                        continue
                    cmd = s.strip()
                if not cmd or cmd.startswith("#"):
                    continue
                acts.append(Action("command", cmd, n))
            continue
        line = lines[i]
        writes_here = bool(_WRITE_WORDS.search(line))
        for span in re.findall(r"`([^`\n]+)`", line):
            if _looks_like_command(span):
                acts.append(Action("command", span.strip(), i + 1))
            elif _looks_like_path(span):
                acts.append(Action("write" if writes_here else "read", span.strip(), i + 1))
            elif writes_here and _BARE_FILE.match(span.strip()):
                acts.append(Action("write", span.strip(), i + 1))     # "write the flag to `flag.txt`"
        i += 1
    out: list[Action] = []
    for a in acts:
        out.append(a)
        if a.kind == "command":
            out.extend(command_paths(a))
    if len(out) > MAX_ACTIONS:
        raise RulesError(f"brief asks for more than {MAX_ACTIONS} actions: refusing to simulate a dump")
    return out


def _tokens(cmd: str) -> list[str]:
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        return list(lex)
    except ValueError:            # unbalanced quotes: fall back to a plain split
        return cmd.split()


def segments(cmd: str) -> list[list[str]]:
    """The sub-commands of a command line, as word lists (operators dropped, fd digits before a
    redirection dropped, `2>&1` style duplications dropped)."""
    segs: list[list[str]] = [[]]
    toks = _tokens(cmd)
    j = 0
    while j < len(toks):
        t = toks[j]
        if t in _OPS:
            segs.append([])
        elif t in (">&", "<&") and j + 1 < len(toks) and toks[j + 1].isdigit():
            j += 1                        # 2>&1
        else:
            if t in _REDIRECT_OUT | {"<"} and segs[-1] and segs[-1][-1].isdigit():
                segs[-1].pop()            # the "2" of "2>"
            segs[-1].append(t)
        j += 1
    return [s for s in segs if s]


def segment_texts(cmd: str) -> list[str]:
    """Sub-commands as normalised text (shell-quoted words joined by one space)."""
    return [" ".join(shlex.quote(w) if w not in _REDIRECT_OUT | {"<"} else w for w in s)
            for s in segments(cmd)]


def _path_word(w: str) -> bool:
    return bool(w) and not w.startswith("-") and "://" not in w and "=" not in w.split("/")[0] and (
        w.startswith(("/", "~", "./", "../")) or "/" in w)


def command_paths(a: Action) -> list[Action]:
    """The writes and reads one command makes, as far as its words show them."""
    out: list[Action] = []
    cwd = ""
    for words in segments(a.text):
        while words and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[0]):
            words = words[1:]                         # VAR=value prefixes
        if not words:
            continue
        prog = os.path.basename(words[0])
        args = words[1:]
        writes: list[str] = []
        reads: list[str] = []
        rest: list[str] = []
        k = 0
        while k < len(args):
            w = args[k]
            if w in _REDIRECT_OUT and k + 1 < len(args):
                writes.append(args[k + 1]); k += 2; continue
            if w == "<" and k + 1 < len(args):
                reads.append(args[k + 1]); k += 2; continue
            rest.append(w)
            k += 1
        plain = [w for w in rest if not w.startswith("-")]
        if prog == "cd":
            if plain:
                new = plain[0]
                cwd = new if new.startswith(("/", "~")) or not cwd else cwd.rstrip("/") + "/" + new
            continue
        if prog in ("tee", "touch", "mkdir", "rm", "rmdir"):
            writes.extend(plain)
        elif prog in ("cp", "mv", "ln", "install", "rsync") and len(plain) >= 2:
            writes.append(plain[-1])
            reads.extend(p for p in plain[:-1] if _path_word(p))
        else:
            reads.extend(p for p in plain if _path_word(p))
        if prog not in ("tee", "touch", "mkdir", "rm", "rmdir", "cp", "mv", "ln", "install", "rsync") \
                and _path_word(words[0]) and not words[0].startswith(("/usr/", "/bin/", "/sbin/")):
            reads.append(words[0])                    # a script or binary run by path
        for p in writes:
            out.append(Action("write", p, a.line, via=a.text, cwd=cwd))
        for p in reads:
            out.append(Action("read", p, a.line, via=a.text, cwd=cwd))
    return out


# ------------------------------------------------------------------------------------- paths

def _resolve(p: str, *, cwd: Path, home: Path, rel_cwd: str = "") -> Path:
    """An absolute, canonical path (ctf.fence.canon: ~ and $HOME expanded, /var /tmp /etc folded onto
    /private, the data-volume firmlink folded), relative ones joined to the (possibly cd-moved) cwd."""
    base = _resolve(rel_cwd, cwd=cwd, home=home) if rel_cwd else cwd
    c = _canon(p, home=home, cwd=base)
    return c if c is not None else Path(os.path.normpath(str(base) + "/" + p))


def _under(p: Path, root: Path) -> bool:
    return p == root or root in p.parents


def _glob_rx(pattern: str) -> re.Pattern:
    """gitignore-ish: ** spans '/', * and ? do not."""
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(out + r"\Z")


def path_rule_matches(spec: str, path: Path, *, cwd: Path, home: Path, root: Path) -> bool:
    """A Read/Edit/Write rule spec against an absolute path: //abs, ~/home-rel, /root-rel (the
    settings root), ./ or bare cwd-rel; a slash-free pattern matches the basename anywhere. A pattern
    with no glob also covers everything under it."""
    s = spec.strip()
    if s.startswith("//"):
        pat = s[1:]
    elif s.startswith("~/"):
        pat = str(home) + s[1:]
    elif s.startswith("/"):
        pat = str(root) + s
    elif "/" not in s.rstrip("/"):
        return bool(_glob_rx(s).match(path.name))
    else:
        pat = str(cwd) + "/" + (s[2:] if s.startswith("./") else s)
    pat = str(_canon(pat, home=home) or pat)
    if not any(ch in pat for ch in "*?"):
        return _under(path, Path(pat))
    return bool(_glob_rx(pat).match(str(path)))


_GLOB_RANK = 1000        # a /**/<name> entry outranks every plain path entry


def _fs_entry_matches(entry: str, path: Path) -> int | None:
    """How specific a sandbox filesystem entry is for `path` (path depth of the match), or None."""
    if entry.startswith("/**/"):
        name = entry[4:].split("/", 1)[0]
        return len(path.parts) + _GLOB_RANK if name in path.parts else None   # name globs always win
    e = _canon(entry) or Path(os.path.normpath(entry))
    return len(e.parts) if _under(path, e) else None


# ------------------------------------------------------------------------------------- Claude

def _parse_rule(r: str) -> tuple[str, str | None]:
    m = re.fullmatch(r"\s*([A-Za-z][A-Za-z0-9_]*)\s*(?:\((.*)\))?\s*", r, re.S)
    if not m:
        raise RulesError(f"cannot read permission rule {r!r}")
    return m.group(1), m.group(2)


def bash_rule_matches(spec: str | None, segment: str) -> bool:
    """Claude Code Bash rule spec against one sub-command: `x:*` prefix (word boundary), a glob
    with `*` (a trailing ` *` also matches the bare command), else an exact match. None = any."""
    if spec is None or spec.strip() in ("", "*"):
        return True
    s = spec.strip()
    seg = segment.strip()
    if s.endswith(":*"):
        pre = s[:-2].rstrip()
        return seg == pre or seg.startswith(pre + " ")
    if "*" in s:
        if s.endswith(" *") and seg == s[:-2].rstrip():
            return True
        rx = "".join(".*" if ch == "*" else re.escape(ch) for ch in s)
        return re.fullmatch(rx, seg, re.S) is not None
    return seg == s


@dataclass
class ClaudeRules:
    allow: list[tuple[str, str | None]]
    deny: list[tuple[str, str | None]]
    ask: list[tuple[str, str | None]]
    cwd: Path
    home: Path
    root: Path
    work_dirs: tuple[Path, ...]
    exempt: tuple[Path, ...]
    block_outside: bool
    sandbox: bool
    auto_allow_sandboxed: bool
    allow_write: tuple[str, ...]
    deny_write: tuple[str, ...]
    deny_read: tuple[str, ...]
    allow_read: tuple[str, ...]
    mode: str = "default"
    source: str = "settings"
    harness: str = "claude"
    notes: list[str] = field(default_factory=list)

    @classmethod
    def from_settings(cls, settings: Mapping, *, cwd: Path, home: Path, mode: str = "default",
                      root: Path | None = None, source: str = "settings") -> "ClaudeRules":
        if mode == "bypassPermissions":
            raise RulesError("permission mode bypassPermissions is refused by the launcher "
                             "(ctf/fence_launch.py): nothing to simulate")
        if mode not in CLAUDE_MODES:
            raise RulesError(f"unknown Claude permission mode {mode!r}; one of {CLAUDE_MODES}")
        if not isinstance(settings, Mapping):
            raise RulesError(f"{source}: settings must be a JSON object")
        perms = settings.get("permissions") or {}
        sb = settings.get("sandbox") or {}
        fs = sb.get("filesystem") or {}
        if not isinstance(perms, Mapping) or not isinstance(sb, Mapping) or not isinstance(fs, Mapping):
            raise RulesError(f"{source}: permissions, sandbox and sandbox.filesystem must be objects")

        def rules(key):
            v = perms.get(key) or []
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                raise RulesError(f"{source}: permissions.{key} must be a list of strings")
            return [_parse_rule(x) for x in v]

        def strs(m, key):
            v = m.get(key) or []
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                raise RulesError(f"{source}: {key} must be a list of strings")
            return tuple(v)

        raw_cwd = cwd
        home = _canon(home, home=home)
        cwd = _canon(cwd, home=home)
        if cwd is None or home is None:
            raise RulesError(f"the agent's cwd and home must be absolute, got {raw_cwd!r} / {home!r}")
        dirs =(cwd,) + tuple(_resolve(d, cwd=cwd, home=home) for d in strs(perms, "additionalDirectories"))
        exempt = tuple(_resolve(d, cwd=cwd, home=home) for d in strs(perms, "blockReadsExemptPaths"))
        return cls(allow=rules("allow"), deny=rules("deny"), ask=rules("ask"), cwd=cwd, home=home,
                   root=(_canon(root, home=home) or Path(root)) if root is not None else cwd,
                   work_dirs=dirs, exempt=exempt,
                   block_outside=bool(perms.get("blockReadsOutsideWorkingDirectories")),
                   sandbox=bool(sb.get("enabled")),
                   auto_allow_sandboxed=sb.get("autoAllowBashIfSandboxed", True) is not False,
                   allow_write=strs(fs, "allowWrite"), deny_write=strs(fs, "denyWrite"),
                   deny_read=strs(fs, "denyRead"), allow_read=strs(fs, "allowRead"),
                   mode=mode, source=source)

    @property
    def label(self) -> str:
        return f"claude ({self.mode})"

    def _match_path_rule(self, rules, tools, p: Path) -> str | None:
        for tool, spec in rules:
            if tool in tools and (spec is None or path_rule_matches(
                    spec, p, cwd=self.cwd, home=self.home, root=self.root)):
                return f"{tool}({spec})" if spec is not None else tool
        return None

    def _prompt(self, why: str) -> tuple[str, str]:
        if self.mode == "dontAsk":
            return "deny", why + " (dontAsk mode denies what would prompt)"
        if self.mode == "auto":
            return "classifier", why + (" (auto mode: Claude Code's classifier decides instead of a prompt; "
                                        "approximate, it may still refuse)")
        return "prompt", why

    def decide(self, a: Action) -> Decision:
        if a.kind == "command":
            v, why = self._command(a.text)
        elif a.via:
            v, why = self._bash_path(a)
        else:
            v, why = self._file_tool(a)
        return Decision(self.label, a, v, why)

    def _command(self, cmd: str) -> tuple[str, str]:
        segs = segment_texts(cmd) or [cmd.strip()]
        for s in segs:
            for tool, spec in self.deny:
                if tool == "Bash" and bash_rule_matches(spec, s):
                    return "deny", f"deny rule Bash({spec}) matches `{s[:80]}`"
        for s in segs:
            for tool, spec in self.ask:
                if tool == "Bash" and bash_rule_matches(spec, s):
                    return self._prompt(f"ask rule Bash({spec}) matches `{s[:80]}`")
        unallowed = [s for s in segs if not any(
            tool == "Bash" and bash_rule_matches(spec, s) for tool, spec in self.allow)]
        if not unallowed:
            return "allow", "every sub-command matches an allow rule"
        if self.mode == "plan":
            return "deny", "plan mode runs no commands"
        if self.sandbox and self.auto_allow_sandboxed:
            return "allow", "sandboxed Bash is auto-allowed (sandbox.enabled)"
        return self._prompt(f"no allow rule for `{unallowed[0][:80]}` and Bash is not sandboxed")

    def _bash_path(self, a: Action) -> tuple[str, str]:
        p = _resolve(a.text, cwd=self.cwd, home=self.home, rel_cwd=a.cwd)
        if not self.sandbox:
            return "allow", "unsandboxed Bash: the command's own permission decides"
        if a.kind == "write":
            best_deny = max((d for d in (_fs_entry_matches(e, p) for e in self.deny_write) if d is not None),
                            default=None)
            if best_deny is not None:
                return "deny", f"{p} is under the sandbox's denyWrite"
            if _under(p, self.cwd) or any(_fs_entry_matches(e, p) is not None for e in self.allow_write):
                return "allow", f"{p} is under a sandbox write root"
            return "deny", f"{p} is outside every sandbox write root (allowWrite)"
        best_deny = max((d for d in (_fs_entry_matches(e, p) for e in self.deny_read) if d is not None),
                        default=None)
        if best_deny is None:
            return "allow", "no sandbox read deny covers it"
        best_allow = max((d for d in (_fs_entry_matches(e, p) for e in self.allow_read) if d is not None),
                         default=None)
        # The macOS profile generator emits denyRead, then allowRead, then again every non-glob deny
        # strictly inside an allow, then every glob deny (docs/fence.md); the last match wins. So a
        # more specific allowRead re-opens, and so does one at the same path as a non-glob deny; a
        # deeper deny, or a glob deny, holds.
        if best_allow is not None and (best_allow > best_deny
                                       or (best_allow == best_deny and best_deny < _GLOB_RANK)):
            return "allow", f"{p} is re-opened by the sandbox's allowRead"
        return "deny", f"{p} is under the sandbox's denyRead"

    def _file_tool(self, a: Action) -> tuple[str, str]:
        p = _resolve(a.text, cwd=self.cwd, home=self.home, rel_cwd=a.cwd)
        tools = ("Edit", "Write") if a.kind == "write" else ("Read",)
        hit = self._match_path_rule(self.deny, tools, p)
        if hit:
            return "deny", f"deny rule {hit} covers {p}"
        hit = self._match_path_rule(self.ask, tools, p)
        if hit:
            return self._prompt(f"ask rule {hit} covers {p}")
        hit = self._match_path_rule(self.allow, tools, p)
        if hit:
            return "allow", f"allow rule {hit}"
        inside = any(_under(p, d) for d in self.work_dirs)
        if a.kind == "write":
            if self.mode == "plan":
                return "deny", "plan mode edits nothing"
            if inside and self.mode in ("acceptEdits", "auto"):
                return "allow", f"{p} is in a working directory ({self.mode})"
            return self._prompt(f"no Edit/Write allow rule for {p}"
                                + ("" if inside else " and it is outside the working directories")
                                + (" (mode default asks before every edit)" if self.mode == "default" else ""))
        if inside or any(_under(p, d) for d in self.exempt):
            return "allow", f"{p} is in a working directory"
        if self.block_outside:
            return "deny", f"{p} is outside the working directories (blockReadsOutsideWorkingDirectories)"
        return self._prompt(f"{p} is outside the working directories")


# ------------------------------------------------------------------------------------- Codex

@dataclass
class CodexRules:
    fsmap: dict[str, str]
    cwd: Path
    home: Path
    tmp_roots: tuple[Path, ...]
    deny_commands: tuple[tuple[str, re.Pattern], ...] = ()
    harness: str = "codex"

    @classmethod
    def from_fence(cls, fence, *, tmp_roots: Sequence[Path] | None = None) -> "CodexRules":
        """`tmp_roots`: the temp folders :workspace leaves writable (/tmp and $TMPDIR by default)."""
        prof = fence.codex_profile()
        fsmap = dict(prof.get("filesystem") or {})
        bad = {k: v for k, v in fsmap.items() if v not in ("deny", "read", "write")}
        if bad:
            raise RulesError(f"codex profile has unknown filesystem modes: {bad}")
        home = _canon(fence.home, home=fence.home)
        return cls(fsmap=fsmap, cwd=_canon(fence.workspace, home=home), home=home,
                   tmp_roots=default_tmp_roots() if tmp_roots is None else tuple(tmp_roots),
                   deny_commands=tuple((cat, rx) for cat, rx, _ in fence.commands))

    @property
    def label(self) -> str:
        return "codex (approvals never)"

    def _mode(self, p: Path) -> tuple[str | None, str | None]:
        best: tuple[int, str, str] | None = None
        for entry, mode in self.fsmap.items():
            d = _fs_entry_matches(entry, p)
            if d is not None and (best is None or d > best[0]):
                best = (d, mode, entry)
        return (best[1], best[2]) if best else (None, None)

    def decide(self, a: Action) -> Decision:
        if a.kind == "command":
            for s in segment_texts(a.text) or [a.text]:
                for cat, rx in self.deny_commands:
                    if rx.search(s):
                        return Decision(self.label, a, "deny", f"fence deny command ({cat}): `{s[:80]}`; "
                                        "the sandbox refuses the store and the report flags it")
            return Decision(self.label, a, "allow", "approvals never: the sandbox decides what it touches")
        p = _resolve(a.text, cwd=self.cwd, home=self.home, rel_cwd=a.cwd)
        mode, entry = self._mode(p)
        if a.kind == "read":
            if mode == "deny":
                return Decision(self.label, a, "deny", f"{p} is denied by the profile ({entry})")
            return Decision(self.label, a, "allow", "readable" + (f" ({entry})" if entry else " (:workspace)"))
        if mode == "write":
            return Decision(self.label, a, "allow", f"{p} is a write root ({entry})")
        if mode in ("deny", "read"):
            return Decision(self.label, a, "deny", f"{p} is {mode}-only in the profile ({entry})")
        if _under(p, self.cwd) or any(_under(p, t) for t in self.tmp_roots):
            return Decision(self.label, a, "allow", f"{p} is writable under :workspace")
        return Decision(self.label, a, "deny", f"{p} is outside every Codex write root")


def default_tmp_roots() -> tuple[Path, ...]:
    import tempfile
    roots = {Path("/private/tmp"), _canon(os.path.realpath(tempfile.gettempdir()))}
    return tuple(sorted(roots))


# ------------------------------------------------------------------------------------- simulate

def simulate(actions: Iterable[Action], harnesses: Sequence) -> list[Decision]:
    return [h.decide(a) for a in actions for h in harnesses]


def blocking(decisions: Iterable[Decision], *, background: bool = True) -> list[Decision]:
    """The decisions that stop an agent: every deny, and a prompt when nobody is there to answer.
    A "classifier" verdict (auto mode) is not one: it is approximate and reported as a warning."""
    bad = ("deny", "prompt") if background else ("deny",)
    return [d for d in decisions if d.verdict in bad]


def find_briefs(target: Path) -> list[Path]:
    """A brief file, or every *brief*.md under a folder the operator named (sorted). A missing path
    raises FileNotFoundError naming it (never 'no briefs'). For the whole event workdir, which holds
    challenge downloads, use launcher_briefs()."""
    t = Path(target)
    if t.is_file():
        return [t]
    if t.is_dir():
        return sorted(p for p in t.rglob("*brief*.md") if p.is_file() and ".ctf" not in p.parts)
    raise FileNotFoundError(f"brief path not found: {t}")


def launcher_briefs(workdir: Path) -> list[Path]:
    """The briefs the launchers wrote under an event workdir: <workdir>/*/codex_brief*.md only
    (LAUNCHER_BRIEF_GLOB), regular files, no symlinks. Never a recursive search: the workdir holds
    challenge downloads, and a challenge-supplied *brief*.md is data, not a brief. A missing workdir
    raises FileNotFoundError naming it."""
    w = Path(workdir)
    if not w.is_dir():
        raise FileNotFoundError(f"event workdir not found: {w}")
    return sorted(p for p in w.glob(LAUNCHER_BRIEF_GLOB)
                  if not p.is_symlink() and not p.parent.is_symlink() and p.is_file())


def read_brief(path: Path) -> str:
    """A brief's text, size-checked before it is read (at most MAX_BRIEF_BYTES are ever read)."""
    p = Path(path)
    size = p.stat().st_size
    if size > MAX_BRIEF_BYTES:
        raise RulesError(f"{p} is {size} bytes, over the {MAX_BRIEF_BYTES}-byte brief limit: not read")
    with open(p, "rb") as fh:
        data = fh.read(MAX_BRIEF_BYTES + 1)
    if len(data) > MAX_BRIEF_BYTES:            # it grew between the stat and the read
        raise RulesError(f"{p} grew past the {MAX_BRIEF_BYTES}-byte brief limit while being read: not read")
    return data.decode("utf-8", "replace")
