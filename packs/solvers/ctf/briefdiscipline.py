"""Brief discipline (B-043): one command style every agent brief carries, and the fix a denial names.

At Huntress 1,153 tool calls (about $143) were denied by a worktree guard because of how the
command was written, not what it did: relative paths, a `cd DIR && ...` prefix, chained commands
and computed program names (`$PY ...`, `$(which x) ...`). A guard can verify a command only when
it can read the program and every path off the command line. This module is the one source of that
style rule for every brief generator and for denial text:

    from ctf import briefdiscipline as bd
    bd.rules_md(heading_level=2)   # the markdown section (event CLAUDE.md/AGENTS.md, handouts, orch brief)
    bd.rules_plain()               # the same rules as plain text (the codex handoff prompt, standby plan)
    bd.missing(text)               # rule ids a generated brief does not carry (empty: it carries all)
    bd.check(command)              # Violations of the rules in one shell command
    bd.fix_hint(command)           # "" for a clean command, else one line naming each fix
    bd.ctf_command("orch status")  # "<repo>/tools/ctfpy -m ctf orch status": a helper runnable anywhere

Generators that carry the block: ctf.dispatch.handout_md, ctf.orch.brief_md (and ctf.orch.RULES),
ctf.standby.plan (and `ctf standby plan`), tools/codex_handoff.sh (through `ctf discipline
--plain`) and templates/event/agent-rules.md.tmpl (the `brief_discipline` value). The orchestrator
guard (ctf.orch.guard_decision) appends fix_hint() to a Bash denial. `python -m ctf discipline
check -- "<command>"` (spelled `/abs/repo/tools/ctfpy -m ctf ...` in the briefs, so it runs
from any folder) lints a command before it is run (a sanctioned helper, ctf.permissions).
"""
from __future__ import annotations

import re
import textwrap
from dataclasses import dataclass

DISCIPLINE_VERSION = 1
HEADING = "Command discipline"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    text: str      # the rule as a brief states it
    fix: str       # what a denial tells the agent to do instead


RULES: tuple[Rule, ...] = (
    Rule("absolute-paths", "Absolute paths",
         "Name every file, folder and script by its absolute path and run from where you are: no "
         "`cd DIR && ...` prefix, no `./x` or `../x` paths, no relative program paths "
         "(`tools/x`, `.venv/bin/python`). Run `ctf` from any folder as `/abs/repo/tools/ctfpy -m "
         "ctf ...` instead of changing to the checkout.",
         "spell each path out in full (/abs/path/to/file) and drop the `cd` prefix"),
    Rule("one-command", "One command per call",
         "Each tool call runs one command: no `&&`, `||` or `;` chains and no multi-line scripts. "
         "Make separate calls instead (independent ones can go in parallel). A pipe into a read-only "
         "filter such as `| head` or `| grep` is fine.",
         "split the chain into separate tool calls, one command each"),
    Rule("literal-program", "Name the program literally",
         "The first word of every command is the program spelled out (`git`, `python3`, "
         "`/abs/repo/.venv/bin/python`), never a variable, `$(...)`, backticks or `eval` of a built "
         "string.",
         "write the program's literal name or absolute path as the first word, not $VAR, $(...), "
         "backticks or eval"),
    Rule("plain-git", "Plain git",
         "Run git as one plain command against your own checkout (`git -C /abs/worktree status`); "
         "to stage and commit in one step use `/abs/repo/tools/ctfpy -m ctf worktree-commit`. A guard "
         "denial means rewrite the command this way, not retry it.",
         "run one plain `git -C /abs/worktree <subcommand>`, or `/abs/repo/tools/ctfpy -m ctf "
         "worktree-commit` to stage and commit"),
)
RULE_IDS = tuple(r.id for r in RULES)
_BY_ID = {r.id: r for r in RULES}

_INTRO = ("Guards check a command only when they can read its program and every path off the "
          "command line; a command they cannot read is denied and the retry is paid twice. "
          "`/abs/repo/tools/ctfpy -m ctf discipline check -- \"<command>\"` lints one before you run "
          "it (`/abs/repo` is the ctf-tools checkout; ctf is not installed, so a bare `python -m ctf` "
          "works only from inside it).")


def _wrap(text: str, indent: str) -> str:
    return textwrap.fill(text, width=100, subsequent_indent=indent, break_long_words=False,
                         break_on_hyphens=False)


def ctf_command(sub: str, repo=None) -> str:
    """The `ctf` sub-command line `sub` spelled as the discipline asks, so it runs from any folder:
    `<repo>/tools/ctfpy -m ctf <sub>`, the checkout path absolute (shell-quoted when it needs it).
    For text generated at run time (denials, handouts, the orch brief). Committed files spell the
    checkout `/abs/repo` instead, since they carry no home path. `repo` defaults to this checkout
    (ctf.paths.repo_root)."""
    import shlex
    from pathlib import Path
    if repo is None:
        from .paths import repo_root
        repo = repo_root()
    prog = shlex.quote(str(Path(repo).resolve() / "tools" / "ctfpy"))
    sub = str(sub).strip()
    return f"{prog} -m ctf {sub}" if sub else f"{prog} -m ctf"


def rules_md(*, heading_level: int = 2) -> str:
    """The rules as a markdown section, one source for the event agent files and the briefs."""
    h = "#" * max(1, int(heading_level))
    L = [f"{h} {HEADING}", "", _wrap(f"{_INTRO} (B-043, `ctf/briefdiscipline.py`)", ""), ""]
    for n, r in enumerate(RULES, 1):
        L.append(_wrap(f"{n}. **{r.title}** (`{r.id}`). {r.text}", "   "))
    return "\n".join(L) + "\n"


def rules_plain() -> str:
    """The rules as plain text for a prompt that is not markdown (codex handoff, standby plan)."""
    L = [f"{HEADING.upper()} (B-043):"]
    for r in RULES:
        L.append(_wrap(f"- {r.title} ({r.id}): {r.text}", "  "))
    L.append(_wrap(_INTRO, ""))
    return "\n".join(L) + "\n"


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def missing(text: str) -> list[str]:
    """The ids of the rules whose text `text` does not carry (whitespace and line wrapping are
    ignored). Empty: the brief carries the whole discipline."""
    flat = _norm(text)
    return [r.id for r in RULES if _norm(r.text) not in flat]


# ------------------------------------------------------------------------------------------ checker

@dataclass(frozen=True)
class Violation:
    rule: str      # a RULE_IDS entry
    detail: str    # what in the command breaks it

    @property
    def fix(self) -> str:
        return _BY_ID[self.rule].fix


_CHAIN_OPS = ("&&", "||", ";", "\n", "&")


def _subst_end(cmd: str, i: int) -> int:
    """The index just past the `$( ... )` or backtick substitution that starts at `i` (the end of
    the text when it is unterminated). Quotes inside it are skipped over."""
    n = len(cmd)
    if cmd[i] == "`":
        j = cmd.find("`", i + 1)
        return n if j < 0 else j + 1
    depth, j, quote = 0, i + 1, None
    while j < n:
        c = cmd[j]
        if quote:
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return n


def _segments(cmd: str) -> tuple[list[list[str]], list[str], bool]:
    """Split `cmd` the way a POSIX shell would at top level: ([words of each simple command],
    [the chain operators met], substitution_seen). Quotes and backslashes are honoured; a pipe
    separates commands but is not a chain operator. Quoting is removed from the words."""
    segs: list[list[str]] = [[]]
    ops: list[str] = []
    word: list[str] = []
    in_word = False
    subst = False
    i, n = 0, len(cmd)
    quote: str | None = None

    def end_word() -> None:
        nonlocal word, in_word
        if in_word:
            segs[-1].append("".join(word))
        word, in_word = [], False

    while i < n:
        c = cmd[i]
        if quote == "'":
            if c == "'":
                quote = None
            else:
                word.append(c)
            i += 1
            continue
        if quote == '"':
            if c == '"':
                quote = None
            elif c == "\\" and i + 1 < n:
                word.append(cmd[i + 1])
                i += 2
                continue
            else:
                if c == "`" or cmd.startswith("$(", i):
                    subst = True
                word.append(c)
            i += 1
            continue
        if c in "'\"":
            quote, in_word = c, True
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            if cmd[i + 1] == "\n":          # a line continuation joins the lines; it is no chain
                i += 2
                continue
            word.append(cmd[i + 1])
            in_word = True
            i += 2
            continue
        if c == "`" or cmd.startswith("$(", i):
            subst = True
            j = _subst_end(cmd, i)               # the substitution is one piece of the word
            word.append(cmd[i:j])
            in_word = True
            i = j
            continue
        if c in " \t":
            end_word()
            i += 1
            continue
        op = next((o for o in ("&&", "||", "|&", ";;") if cmd.startswith(o, i)), None) or (
            c if c in ";\n&|" else None)
        if op is not None and not (c == "&" and (cmd[i - 1:i] in ("<", ">") or cmd[i + 1:i + 2] == ">")):
            end_word()
            if op in ("|", "|&"):
                segs.append([])
            else:
                ops.append(";" if op == ";;" else op)
                segs.append([])
            i += len(op)
            continue
        word.append(c)
        in_word = True
        i += 1
    end_word()
    # an operator with nothing after it (`cmd;`, `cmd &`, a trailing newline) chains nothing
    while len(segs) > 1 and not segs[-1] and ops:
        segs.pop()
        ops.pop()
    return [s for s in segs if s], ops, subst


_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_WRAPPERS = {"sudo", "env", "nohup", "time", "command", "exec", "nice", "timeout"}


def _program(words: list[str]) -> str | None:
    """The program a simple command runs: the first word after VAR=value assignments and common
    wrappers (`env`, `nohup`, `time`, `timeout N`)."""
    k = 0
    while k < len(words):
        w = words[k]
        if _ASSIGN.match(w):
            k += 1
            continue
        if w in _WRAPPERS:
            k += 1
            while k < len(words) and (words[k].startswith("-") or _ASSIGN.match(words[k])
                                      or (w == "timeout" and words[k][:1].isdigit())):
                k += 1
            continue
        return w
    return None


def _relative(word: str) -> bool:
    return (word in (".", "..") or word.startswith(("./", "../")) or "/../" in word
            or word.endswith("/.."))


def check(command: str) -> list[Violation]:
    """The brief-discipline violations in one shell command (one Violation per problem found,
    in rule order). An empty list means a guard can read the command as written."""
    if not isinstance(command, str):
        raise TypeError(f"command must be a string, got {type(command).__name__}")
    segs, ops, subst = _segments(command)
    out: list[Violation] = []
    cds = [s for s in segs if _program(s) in ("cd", "pushd", "popd")]
    rel = sorted({w for s in segs for w in s if _relative(w)})
    progs = [p for p in (_program(s) for s in segs) if p]
    rel_prog = sorted({p for p in progs if "/" in p and not p.startswith(("/", "~", "$"))
                       and not _relative(p)})
    if cds:
        out.append(Violation("absolute-paths", f"a `{cds[0][0]}` to change folder"))
    if rel:
        out.append(Violation("absolute-paths", "relative path(s): " + ", ".join(rel[:5])))
    if rel_prog:
        out.append(Violation("absolute-paths", "relative program path(s): " + ", ".join(rel_prog[:5])))
    if ops:
        shown = sorted({"newline" if o == "\n" else o for o in ops})
        out.append(Violation("one-command", "commands chained with " + ", ".join(shown)))
    computed = sorted({p for p in progs if "$" in p or "`" in p})
    if computed:
        out.append(Violation("literal-program", "a computed program name: " + ", ".join(computed[:5])))
    if "eval" in progs:
        out.append(Violation("literal-program", "eval of a built string"))
    if subst and not computed and any(_program(s) in ("sh", "bash", "zsh") for s in segs):
        out.append(Violation("literal-program", "a shell running a command built by substitution"))
    gits = sum(1 for p in progs if p == "git" or p.endswith("/git"))
    if gits and (ops or cds or gits > 1):
        out.append(Violation("plain-git", "git combined with a folder change or other commands"))
    return out


def fix_hint(command: str) -> str:
    """One line naming the fix for each discipline rule `command` breaks, or "" when it breaks none."""
    vs = check(command)
    if not vs:
        return ""
    fixes: list[str] = []
    for v in vs:
        if v.fix not in fixes:
            fixes.append(v.fix)
    found = "; ".join(v.detail for v in vs)
    return (f"Fix the command style (brief discipline, B-043; found {found}): " + "; ".join(fixes)
            + ". Then send it as a new call; a guard can verify a command only when it is written "
              "this way.")
