"""Denied-access report (B-219): scan an agent's command log or transcript for reads outside the
fence's allowed roots and summarise them.

    from ctf import fence, fence_report
    rep = fence_report.scan_files([Path("rollout.jsonl")], fence.build(...))
    print(fence_report.render_text(rep))

Input formats, detected per line (a file may mix them):

- Claude Code transcript JSONL: assistant `tool_use` blocks (Bash `command`; Read/Edit/Write
  `file_path`; Grep/Glob/LS `path`; NotebookRead/Edit `notebook_path`), outcomes from the
  matching `tool_result` (`is_error` plus "denied"/"not permitted" text). Each line's `cwd`
  resolves relative paths.
- Codex rollout JSONL: `response_item` function calls (`arguments` JSON with `cmd` / `command`
  and optional `workdir`) and their `function_call_output`; `event_msg` / `item_completed`
  CommandExecution items when the file has no function calls.
- `codex exec --json` stream: `item.completed` events whose item is a `command_execution`.
- Anything else: one shell command per line (blank lines and `#` comments skipped).

Paths are pulled from the command text (absolute, ~ and $HOME forms, and relative ones when the
cwd is known: `../x`, and words with a denied tree's name as a whole component such as
`analysis/out/x`, `.ctf/token` or `ctf-tools/analysis/x`; a plain `cd DIR` moves the cwd for the
rest of the command, and a `( ... )` / `$( ... )` subshell's cd ends with it), canonicalised
(ctf.fence.canon) and classified by the fence. Commands that reach a
store without naming it (log show, tmutil, mdfind, ...) are flagged by DENY_COMMANDS.

The report never echoes a whole command: it records the program name and the path, so a token in
a command line cannot leak into the report.
"""
from __future__ import annotations

import json
import re
import shlex
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from .fence import Fence, canon

_DENIED_TEXT = re.compile(r"Operation not permitted|Permission denied|permission denied|"
                          r"denied by (?:the )?(?:sandbox|permission|settings)|"
                          r"blocked by (?:the )?(?:sandbox|permission|settings)|"
                          r"outside (?:the )?(?:allowed )?working director", re.I)
_SEGMENT_SPLIT = re.compile(r"\s*(?:&&|\|\||;|\n|\|)\s*")
# A path-looking token: starts at a boundary with /, ~/, $HOME or ${HOME}. The boundary excludes
# ':' and '/' so URLs (https://host/x) and PATH-style lists do not count, and letters so sed
# expressions (s/a/b/) do not.
_PATH_RX = re.compile(r"(?:(?<=[\s'\"=(\[{,<>])|^)((?:\$\{HOME\}|\$HOME|~)?/[^\s'\"`;|&<>(){}\[\],*?]*)")
_REL_RX = re.compile(r"(?:(?<=[\s'\"=(\[{,<>])|^)(\.\.(?:/[^\s'\"`;|&<>(){}\[\],*?]*)?)")
_FILE_TOOLS = {"Read": "file_path", "Edit": "file_path", "Write": "file_path", "MultiEdit": "file_path",
               "NotebookRead": "notebook_path", "NotebookEdit": "notebook_path",
               "Grep": "path", "Glob": "path", "LS": "path"}
_SHELL_TOOLS = {"Bash", "shell", "exec_command", "local_shell", "container.exec", "unified_exec"}


@dataclass(frozen=True)
class Access:
    source: str            # file:line
    tool: str              # Bash, Read, exec_command, command_execution, text, ...
    program: str           # first word of the shell segment, or the file tool name
    path: str | None       # canonical path (None for a pure command hit)
    kind: str              # denied | outside-home | outside
    category: str          # deny category, "home-other" or "other"
    outcome: str           # blocked | ran | failed | unknown


@dataclass
class Report:
    files: list[str] = field(default_factory=list)
    lines: int = 0
    commands: int = 0              # shell commands and file-tool calls examined
    accesses: list[Access] = field(default_factory=list)
    unparsed: int = 0              # JSON lines with no recognised shape (not an error)

    @property
    def clean(self) -> bool:
        return not self.accesses

    def by_category(self) -> Counter:
        return Counter(a.category for a in self.accesses)

    def by_outcome(self) -> Counter:
        return Counter(a.outcome for a in self.accesses)

    def to_dict(self) -> dict:
        roots: dict[str, Counter] = defaultdict(Counter)
        for a in self.accesses:
            roots[a.category][_root_label(a.path)] += 1
        return {
            "files": self.files, "lines": self.lines, "commands": self.commands,
            "outside_reads": len(self.accesses),
            "commands_with_outside_reads": len({a.source for a in self.accesses}),
            "by_category": dict(self.by_category().most_common()),
            "by_outcome": dict(self.by_outcome().most_common()),
            "top_roots": {k: dict(v.most_common(10)) for k, v in sorted(roots.items())},
            "accesses": [a.__dict__ for a in self.accesses],
        }


def _root_label(p: str | None, depth: int = 4) -> str:
    if not p:
        return "(command)"
    parts = Path(p).parts
    return str(Path(*parts[:depth])) if len(parts) > depth else p


# --------------------------------------------------------------------------------- path extraction

_PATH_START = re.compile(r"^(?:~|\$HOME|\$\{HOME\})?/|^\.\.(?:/|$)")
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}


def _shell_tokens(text: str) -> list[str] | None:
    try:
        return shlex.split(text, posix=True)
    except ValueError:
        return None


# One relative path component before a watched name: no '/', ':' (URLs, PATH lists), '$'
# (an unknown variable), '=' or shell/code punctuation, and not an option ('-x').
_REL_COMP = r"[^\s:$=/'\"`;|&<>(){}\[\],*?]+"


def _rel_rx(names: Iterable[str]) -> tuple[re.Pattern, re.Pattern] | None:
    """(whole-word, embedded) patterns for relative paths that have a watched name as a whole
    component, first or deeper (R-03: `cat analysis/out/x`, `open('.ctf/token')`, from $HOME
    `cat ctf-tools/analysis/x` or `cat ./ctf-tools/.ctf/token`). Embedded hits need a '/' after
    the name, so a bare word inside code or a regex does not count. The fence decides whether the
    resolved path is denied, so `solvers/analysis/x` in the repo stays unreported."""
    names = sorted(set(names))
    if not names:
        return None
    alt = "|".join(re.escape(n) for n in names)
    lead = rf"(?:(?!-){_REL_COMP}/(?:{_REL_COMP}/)*)?"
    word = re.compile(rf"^{lead}(?:{alt})(?:/.*)?$")
    embedded = re.compile(rf"(?:(?<=[\s'\"=(\[{{,<>])|^)({lead}(?:{alt})/[^\s'\"`;|&<>(){{}}\[\],*?]*)")
    return word, embedded


def extract_paths(command: str, rel_names: Iterable[str] = ()) -> list[str]:
    """Path-looking tokens in a shell command (or code inside it), in order, de-duplicated.
    Whole shell words come first (so a quoted path with spaces stays whole: 'Application
    Support/...'), then paths embedded in other words (python -c code, heredocs, `2>/dev/null`).
    `rel_names` (Fence.watched_names()) adds relative paths starting with one of those names."""
    out: list[str] = []
    rel = _rel_rx(rel_names)

    def add(tok: str) -> None:
        tok = tok.rstrip(":")
        if tok and tok not in out and not any(tok in o for o in out):
            out.append(tok)
    for tok in _shell_tokens(command) or []:
        if _PATH_START.match(tok) or (rel is not None and rel[0].match(tok)):
            add(tok)
            continue
        m = re.match(r"^(?:[A-Za-z_][A-Za-z0-9_]*=|-[A-Za-z]|--[A-Za-z][\w-]*=)(.+)$", tok)
        if m and (_PATH_START.match(m.group(1)) or (rel is not None and rel[0].match(m.group(1)))):
            add(m.group(1))            # `-Ictf-tools/analysis`, `--file=analysis/x`, `F=.ctf/t`
    rxs = (_PATH_RX, _REL_RX) + ((rel[1],) if rel is not None else ())
    for rx in rxs:
        for m in rx.finditer(command):
            add(m.group(1))
    return out


def _cd_target(segment: str) -> str | None:
    """The directory of a plain `cd DIR` / `pushd DIR` segment (None for anything else, `cd -`,
    bare `cd` or `cd ""`, which the shells treat as staying put). Redirections are ignored, so
    `pushd DIR >/dev/null` counts."""
    toks = _shell_tokens(segment) or []
    words: list[str] = []
    skip = False
    for t in toks:
        if skip:
            skip = False
            continue
        m = _REDIRECT.match(t)
        if m:
            skip = m.group(1) == ""        # `> FILE`: the next word is the redirect target
            continue
        words.append(t)
    if len(words) == 2 and words[0] in ("cd", "pushd") and words[1].strip() not in ("", "-"):
        return words[1]
    return None


_REDIRECT = re.compile(r"^(?:\d*|&)(?:>>?|<|>&)(.*)$")


def _inner_script(command: str) -> str:
    """`/bin/zsh -lc 'script'` as one string: return the script."""
    toks = _shell_tokens(command)
    if toks and len(toks) >= 3 and Path(toks[0]).name in _SHELLS and toks[1] in ("-c", "-lc", "-ic", "-lic"):
        return toks[2]
    return command


def _program(segment: str) -> str:
    try:
        toks = shlex.split(segment, posix=True)
    except ValueError:
        toks = segment.split()
    while toks and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0]):
        toks = toks[1:]        # leading VAR=value assignments
    while toks and toks[0] in ("sudo", "env", "command", "exec", "nohup", "time"):
        toks = toks[1:]
    return Path(toks[0]).name if toks else ""


def _unwrap(command) -> str:
    """Codex records commands as ["/bin/zsh", "-lc", "<script>"]; keep the script."""
    if isinstance(command, list):
        if len(command) >= 3 and command[-2] in ("-c", "-lc", "-ic"):
            return str(command[-1])
        return " ".join(shlex.quote(str(x)) for x in command)
    return str(command or "")


def _outcome(error: bool | None, text: str | None, exit_code=None) -> str:
    if text and _DENIED_TEXT.search(text):
        return "blocked"
    if error is True:
        return "failed"
    if exit_code not in (None, 0):
        return "failed"
    if error is False or exit_code == 0:
        return "ran"
    return "unknown"


# --------------------------------------------------------------------------------- classification

def classify_command(fence: Fence, command: str, *, cwd: str | None, source: str, tool: str,
                     outcome: str) -> list[Access]:
    out: list[Access] = []
    seen: set[str] = set()
    command = _inner_script(command)
    names = fence.watched_names()
    saved: list[str | None] = []       # cwds to restore when a `( ... )` subshell closes
    for seg in _SEGMENT_SPLIT.split(command):
        seg = seg.strip()
        opened = 0
        while True:                        # `(cd X; cat a)` / `$(cd X; cat a)`: a subshell opens
            m = re.match(r"^\$?\(\s*", seg)
            if not m:
                break
            seg = seg[m.end():]
            opened += 1
        saved.extend([cwd] * opened)
        closed = 0
        while seg.endswith(")") and len(saved) > closed and seg.count("(") < seg.count(")"):
            seg = seg[:-1].rstrip()
            closed += 1
        if seg:
            cwd = _classify_segment(fence, seg, names, cwd, out, seen, source, tool, outcome)
        for _ in range(closed):            # the subshell's cd does not outlive it
            cwd = saved.pop()
    return out


def _classify_segment(fence: Fence, seg: str, names: frozenset[str], cwd: str | None,
                      out: list[Access], seen: set[str], source: str, tool: str,
                      outcome: str) -> str | None:
    """Classify one shell segment into `out`; return the cwd for the segments after it."""
    prog = _program(seg)
    cat = fence.command_category(seg)
    if cat:
        out.append(Access(source, tool, prog, None, "denied", cat, outcome))
    for tok in extract_paths(seg, names):
        v = fence.classify(tok, cwd=cwd)
        if v is None or not v.reportable or str(v.path) in seen:
            continue
        seen.add(str(v.path))
        category = v.category if v.kind == "denied" else (
            "home-other" if v.kind == "outside-home" else "other")
        out.append(Access(source, tool, prog, str(v.path), v.kind, category, outcome))
    target = _cd_target(seg)
    if target is None:
        return cwd
    # `cd ~/ctf-tools && cat analysis/out/x`: later segments resolve against the new dir.
    # A relative cd with no known cwd leaves the cwd unknown (relative paths are skipped);
    # with a known cwd and a non-blank target canon() always answers.
    new = canon(target, home=fence.home, cwd=cwd)
    return str(new) if new is not None else None


def classify_path(fence: Fence, path: str, *, cwd: str | None, source: str, tool: str,
                  outcome: str) -> list[Access]:
    v = fence.classify(path, cwd=cwd)
    if v is None or not v.reportable:
        return []
    category = v.category if v.kind == "denied" else ("home-other" if v.kind == "outside-home" else "other")
    return [Access(source, tool, tool, str(v.path), v.kind, category, outcome)]


# ------------------------------------------------------------------------------------------ parsing

@dataclass
class _Call:
    source: str
    tool: str
    command: str | None = None
    path: str | None = None
    cwd: str | None = None
    error: bool | None = None
    text: str | None = None
    exit_code: object = None


def _result_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(_result_text(c.get("text") if isinstance(c, dict) else c) for c in content)
    if isinstance(content, dict):
        return _result_text(content.get("text") or content.get("output") or "")
    return "" if content is None else str(content)


def _calls_from_file(path: Path) -> Iterator[_Call | int]:
    """Yield the shell/file-tool calls in one log, outcomes attached. Yields an int (count of
    unrecognised JSON lines) last."""
    by_id: dict[str, _Call] = {}
    ordered: list[_Call] = []
    codex_items: list[_Call] = []
    have_function_calls = False
    unparsed = 0
    with path.open(errors="replace") as fh:
        for n, raw in enumerate(fh, 1):
            line = raw.strip()
            src = f"{path.name}:{n}"
            if not line:
                continue
            obj = None
            if line[0] == "{":
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    obj = None
            if not isinstance(obj, dict):
                if line.startswith("#"):
                    continue
                ordered.append(_Call(src, "text", command=line))
                continue
            recognised = False
            t = obj.get("type")
            # --- Claude Code transcript
            msg = obj.get("message") if isinstance(obj.get("message"), dict) else None
            if msg is not None:
                recognised = True
            if msg is not None and isinstance(msg.get("content"), list):
                cwd = obj.get("cwd")
                for block in msg["content"]:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "tool_use":
                        recognised = True
                        name, inp = block.get("name") or "", block.get("input") or {}
                        c = None
                        if name in _SHELL_TOOLS and isinstance(inp.get("command"), str):
                            c = _Call(src, name, command=inp["command"], cwd=cwd)
                        elif name in _FILE_TOOLS and isinstance(inp.get(_FILE_TOOLS[name]), str):
                            c = _Call(src, name, path=inp[_FILE_TOOLS[name]], cwd=cwd)
                        if c is not None:
                            ordered.append(c)
                            if block.get("id"):
                                by_id[block["id"]] = c
                    elif block.get("type") == "tool_result":
                        recognised = True
                        c = by_id.get(block.get("tool_use_id"))
                        if c is not None:
                            c.error = bool(block.get("is_error"))
                            c.text = _result_text(block.get("content"))
            # --- Codex rollout
            payload = obj.get("payload") if isinstance(obj.get("payload"), dict) else None
            if payload is not None:
                pt = payload.get("type")
                if t == "response_item" and pt in ("function_call", "custom_tool_call", "local_shell_call"):
                    recognised = True
                    args = payload.get("arguments") or payload.get("input") or payload.get("action") or {}
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except json.JSONDecodeError:
                            args = {"cmd": args}
                    if isinstance(args, dict):
                        cmd = args.get("cmd", args.get("command"))
                        if cmd:
                            have_function_calls = True
                            c = _Call(src, payload.get("name") or pt, command=_unwrap(cmd),
                                      cwd=args.get("workdir") or args.get("cwd"))
                            ordered.append(c)
                            if payload.get("call_id"):
                                by_id[payload["call_id"]] = c
                elif t == "response_item" and pt in ("function_call_output", "custom_tool_call_output",
                                                     "local_shell_call_output"):
                    recognised = True
                    c = by_id.get(payload.get("call_id"))
                    if c is not None:
                        out = payload.get("output")
                        text = _result_text(out)
                        try:
                            parsed = json.loads(text) if text.startswith("{") else None
                        except json.JSONDecodeError:
                            parsed = None
                        if isinstance(parsed, dict):
                            c.exit_code = (parsed.get("metadata") or {}).get("exit_code", parsed.get("exit_code"))
                            text = _result_text(parsed.get("output", text))
                        c.text = text
                elif t == "event_msg" and pt == "item_completed":
                    recognised = True
                    it = payload.get("item") or {}
                    if it.get("type") == "CommandExecution":
                        codex_items.append(_Call(src, "CommandExecution", command=_unwrap(it.get("command")),
                                                 cwd=it.get("cwd"), text=it.get("aggregated_output"),
                                                 exit_code=it.get("exit_code")))
                else:
                    recognised = recognised or t in ("session_meta", "turn_context", "event_msg",
                                                     "response_item", "token_usage_record", "compacted")
            # --- codex exec --json stream
            if t in ("item.completed", "item.started", "item.updated") and isinstance(obj.get("item"), dict):
                recognised = True
                it = obj["item"]
                if t == "item.completed" and it.get("type") == "command_execution":
                    ordered.append(_Call(src, "command_execution", command=_unwrap(it.get("command")),
                                         text=it.get("aggregated_output"), exit_code=it.get("exit_code")))
            if not recognised:
                unparsed += 1
    if not have_function_calls:
        ordered.extend(codex_items)
    yield from ordered
    yield unparsed


def scan_files(files: Iterable[Path], fence: Fence) -> Report:
    rep = Report()
    for f in files:
        f = Path(f)
        if not f.is_file():
            raise FileNotFoundError(f"log not found: {f}")
        rep.files.append(str(f))
        with f.open(errors="replace") as fh:
            rep.lines += sum(1 for _ in fh)
        for c in _calls_from_file(f):
            if isinstance(c, int):
                rep.unparsed += c
                continue
            rep.commands += 1
            oc = _outcome(c.error, c.text, c.exit_code)
            if c.command is not None:
                rep.accesses.extend(classify_command(fence, c.command, cwd=c.cwd, source=c.source,
                                                     tool=c.tool, outcome=oc))
            elif c.path is not None:
                rep.accesses.extend(classify_path(fence, c.path, cwd=c.cwd, source=c.source,
                                                  tool=c.tool, outcome=oc))
    return rep


def render_text(rep: Report, *, samples: int = 15) -> str:
    d = rep.to_dict()
    out = [f"fence report: {len(rep.files)} file(s), {rep.lines} line(s), {rep.commands} command(s) examined"]
    if rep.clean:
        out.append("no reads outside the allowed roots")
        return "\n".join(out)
    out.append(f"{d['outside_reads']} read(s) outside the allowed roots in "
               f"{d['commands_with_outside_reads']} command(s)")
    out.append("by category: " + ", ".join(f"{k} {v}" for k, v in d["by_category"].items()))
    out.append("by outcome:  " + ", ".join(f"{k} {v}" for k, v in d["by_outcome"].items()))
    out.append("top roots:")
    for cat, roots in d["top_roots"].items():
        for root, n in roots.items():
            out.append(f"  {cat:<14} {n:>5}  {root}")
    out.append(f"first {min(samples, len(rep.accesses))}:")
    for a in rep.accesses[:samples]:
        out.append(f"  {a.source:<28} {a.tool:<18} {a.program:<12} {a.outcome:<8} "
                   f"{a.category:<14} {a.path or '(command)'}")
    return "\n".join(out)
