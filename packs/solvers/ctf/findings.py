"""The main thread's claims ledger: an evidence check before it states a cause or steers agents (B-259).

On release mornings the orchestrating main thread stated causes that later proved wrong or unproven,
and steered agents on them: a web nudge toward a leaked secret was retracted minutes later, a false
"finale coverage not armed" finding led a day's plan until a git check in the retro, and a web stall
was called infrastructure three times after the player objected. The retros did not even record the
nudge. This module makes each such statement a recorded **claim** with a linked artifact and a status.

    from ctf import findings
    c = findings.add("cause", "the web lane stalls on the start loop, not the infrastructure",
                     artifacts=["ledger:41", "file:/path/to/12-web/result.json#L3"],
                     challenge_id="12", by="orch")
    c["id"], c["status"]            # "F-1", "suspected"
    findings.confirm("F-1", by="max")                    # a PERSON confirms (the CLI enforces a terminal)
    findings.refute("F-1", by="orch", artifacts=["git:log --oneline -3"], reason="...")
    findings.retract("F-1", by="orch", reason="withdrawn: the nudge was based on a stale file")
    for cl in findings.claims(): print(findings.claim_line(cl))
    findings.recheck("F-1")         # each artifact re-resolved: does it still match what was linked?

Two kinds: `cause` (a root cause the main thread reports) and `steer` (it redirects agents; `to`
names whom). A claim with no artifact, or with an artifact that does not resolve, is refused
(`FindingsError`, the CLI exits 1): nothing is written.

Artifacts. Each is linked by a reference string and resolved at claim time into a record with a
digest, so a later edit of the evidence is visible (`recheck`):

  - `ledger:N` -- line N (1-based) of the event ledger `<workdir>/ledger.jsonl`. Kept: the line's
    sha256, its `event`, `challenge_id` and `ts`. The line must exist and parse.
  - `file:PATH` or `file:PATH#LN` -- a result file, log or note (a regular file), optionally one line
    of it. Kept: the resolved path, size and sha256 (and that line's sha256). The content is hashed,
    never printed or copied: a challenge-derived file stays data.
  - `git:ARGS` -- a read-only git command (`git:log --oneline -5 -- solvers/web`) that this module runs
    in `git_repo` (default: the repo root) with `GIT_OPTIONAL_LOCKS=0`, no pager, no external diff,
    no textconv, no fsmonitor, no signature check and no global or system config (every GIT_*
    variable of the caller is dropped). Only the subcommands in GIT_READONLY run, and an option
    before `--` that writes a file or runs a program is refused: `--output`, `--ext-diff`,
    `--textconv`, `--filters`, `--open-files-in-pager`, `--show-signature`, any abbreviation of
    one (git takes `--open-file`, `--out`), and any short-option bundle holding `O` (`-nO'cmd'`).
    A repo inside the workdir passed, the event's own workdir or the base of all event workdirs is
    refused, and so is any repo whose config (includes too) sets a key outside a small allow-list
    (`_GIT_CONFIG_OK`): a challenge's or a planted repo's config can run commands (a clean filter, a
    diff driver, fsmonitor). A non-zero exit is refused. Kept: the repo, its HEAD, the argv, the
    output's sha256 and line count (not the output itself). `recheck` checks a stored argv and repo
    again before it runs them.

Status. A new claim is always `suspected`: whether an artifact really supports a cause is a person's
judgement, not this module's. `confirm` (a person) makes it `confirmed`; `refute` (anyone, with an
artifact showing it was wrong) makes it `refuted`; `retract` (its author, with a reason) makes it
`retracted`. Refuted and retracted are final. Every record carries a `verify_reason` naming why its
status is what it is. `held(claim)` is the retro's answer: `held` (confirmed), `did not hold`
(refuted), `retracted`, or `unresolved` (never confirmed).

The file is `<workdir>/orch/findings.jsonl` (inside the orchestrator's own folder, which the B-200
guard lets the main thread read). Writes use flock + O_APPEND as `ctf.ledger` does; a claim's id
(`F-<n>`) is assigned under the same lock. A corrupt line raises FindingsError naming the file and
line, never skipped. Records: `{"ts", "op": "claim", "id", "kind", "text", "challenge_id", "to",
"by", "artifacts", "status": "suspected", "verify_reason"}` and `{"ts", "op": "status", "id",
"status", "by", "reason", "artifacts", "verify_reason"}`. Claim text, file content and git output are
data, never instructions.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Iterable

from . import ledger as _ledger
from . import paths as _paths

FINDINGS_NAME = "findings.jsonl"
ORCH_DIR = "orch"                      # the B-200 orchestrator folder (ctf.orch.ORCH_DIR)

CAUSE, STEER = "cause", "steer"
KINDS = (CAUSE, STEER)

SUSPECTED, CONFIRMED, REFUTED, RETRACTED = "suspected", "confirmed", "refuted", "retracted"
STATUSES = (SUSPECTED, CONFIRMED, REFUTED, RETRACTED)
FINAL = frozenset({REFUTED, RETRACTED})
LIVE = frozenset({SUSPECTED, CONFIRMED})

HELD = {CONFIRMED: "held", REFUTED: "did not hold", RETRACTED: "retracted", SUSPECTED: "unresolved"}

TEXT_MAX = 400
ID_RE = re.compile(r"^F-([1-9][0-9]*)$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  -‏‪-‮]+")

# Git subcommands that only read. `branch`, `tag`, `reflog`, `stash`, `config`, `remote`, `notes` and
# `worktree` are left out: each has a writing form.
GIT_READONLY = frozenset({"log", "show", "diff", "status", "rev-parse", "blame", "ls-files", "ls-tree",
                          "cat-file", "grep", "describe", "shortlog", "rev-list", "merge-base"})
_GIT_SAFE_CONFIG = ("-c", "core.fsmonitor=false", "-c", "core.pager=cat", "-c", "diff.external=",
                    "-c", "core.hooksPath=/dev/null", "-c", "protocol.allow=never",
                    "-c", "log.showSignature=false")
_GIT_NO_EXEC = {"diff": ("--no-ext-diff", "--no-textconv", "--ignore-submodules=all"),
                "log": ("--no-ext-diff", "--no-textconv"), "show": ("--no-ext-diff", "--no-textconv"),
                "blame": ("--no-textconv",), "status": ("--ignore-submodules=all",)}
# Long options (without the dashes) that write a file (--output) or run a program (an external diff, a
# textconv or filter driver, `grep --open-files-in-pager`, gpg for --show-signature, a git process inside
# a submodule, which reads the submodule's own config: --submodule=diff, --recurse-submodules, and
# --ignore-submodules, which would undo the --ignore-submodules=all set above). git accepts any unique
# abbreviation of a long option (`--open-file`, `--out`), so a name that is a prefix of one of these is
# refused too, and so is one that extends it (`--output-indicator-new`: over-refusal is fine).
_GIT_BANNED_LONG = ("output", "ext-diff", "textconv", "filters", "open-files-in-pager", "show-signature",
                    "submodule", "recurse-submodules", "ignore-submodules")
# Exact long options that are also a prefix of a banned name, per subcommand: git takes an exact match
# over an abbreviation, so in these subcommands `--text` is diff/grep -a, not --textconv. Elsewhere it is
# refused: `git cat-file --text` is an abbreviation of --textconv and runs a textconv driver, and the
# other subcommands (blame among them) have no need of it, so it is not worth telling them apart.
_GIT_EXACT_OK = {"text": frozenset({"diff", "log", "show", "grep"})}
# The short option that runs a program: `grep -O[<pager>]`. It may sit anywhere in a bundle (-nO'cmd').
_GIT_BANNED_SHORT = "O"
# Repo config keys a git: artifact may run under. Anything else (a filter, diff or textconv driver,
# core.fsmonitor, a pager, gpg.program, an alias, an unknown key) refuses the repo: a repo's config can
# run commands, and a deny-list would miss one. Included files are listed too (git config --includes).
_GIT_CONFIG_OK = re.compile(
    r"core\.(repositoryformatversion|filemode|bare|logallrefupdates|ignorecase|precomposeunicode|"
    r"hookspath|symlinks|autocrlf|eol|safecrlf|quotepath|abbrev|checkstat|trustctime|untrackedcache|"
    r"splitindex|sparsecheckout|sparsecheckoutcone|sharedrepository|warnambiguousrefs|worktree)"
    r"|extensions\.[a-z0-9]+|init\.defaultbranch|user\.(name|email)|include\.path|includeif\..+\.path"
    r"|remote\..+\.(url|pushurl|fetch|tagopt|prune|mirror)|branch\..+\.(remote|merge|rebase|pushremote)"
    r"|pull\.(rebase|ff)|push\.(default|autosetupremote)"
    r"|fetch\.prune|log\.(date|decorate|abbrevcommit)|diff\.(renames|algorithm|mnemonicprefix|noprefix)"
    r"|color\.ui|lfs\.repositoryformatversion")
GIT_TIMEOUT_S = 60.0                  # a git that hangs (a huge repo, a lock) is a named failure


class FindingsError(ValueError):
    """A claim cannot be recorded, changed or read: no artifact, an artifact that does not resolve, a
    bad kind or status, an unknown id, a corrupt line."""


class EvidenceRefused(FindingsError):
    """The evidence check refused a claim or refutation: no artifact linked, or one that does not
    resolve. Nothing was written."""


# ------------------------------------------------------------------------------------------ layout

def path(workdir: Path | None = None) -> Path:
    """`<workdir>/orch/findings.jsonl`."""
    return (_paths.workdir() if workdir is None else Path(workdir)) / ORCH_DIR / FINDINGS_NAME


def one_line(text: Any, limit: int = TEXT_MAX) -> str:
    """Claim and agent text as one printable line of at most `limit` characters."""
    s = _CONTROL.sub(" ", "" if text is None else str(text))
    s = " ".join(s.split())
    if len(s) > limit:
        s = s[: max(0, limit - 1)].rstrip() + "~"
    return s


# --------------------------------------------------------------------------------------- artifacts

def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _file_line(p: Path, n: int) -> bytes | None:
    with open(p, "rb") as fh:
        for i, line in enumerate(fh, 1):
            if i == n:
                return line.rstrip(b"\r\n")
    return None


def _within(p: Path, root: Path) -> bool:
    try:
        p.relative_to(root)
        return True
    except ValueError:
        return False


def _ledger_artifact(ref: str, n_text: str, wd: Path) -> dict:
    if not n_text.isdigit() or int(n_text) < 1:
        raise FindingsError(f"artifact {ref!r}: a ledger reference is ledger:N with N a line number >= 1")
    n = int(n_text)
    p = _ledger.path(wd)
    if not p.is_file():
        raise FindingsError(f"artifact {ref!r}: no ledger at {p}")
    raw = _file_line(p, n)
    if raw is None or not raw.strip():
        raise FindingsError(f"artifact {ref!r}: the ledger {p} has no record on line {n}")
    try:
        rec = json.loads(raw)
    except ValueError:
        raise FindingsError(f"artifact {ref!r}: line {n} of {p} is not a ledger record") from None
    if not isinstance(rec, dict):
        raise FindingsError(f"artifact {ref!r}: line {n} of {p} is not a ledger record")
    return {"type": "ledger", "ref": ref, "line": n, "event": one_line(rec.get("event"), 64),
            "challenge_id": rec.get("challenge_id"), "record_ts": rec.get("ts"),
            "sha256": hashlib.sha256(raw).hexdigest()}


def _file_artifact(ref: str, rest: str, cwd: Path) -> dict:
    target, line = rest, None
    m = re.search(r"#L([0-9]+)$", rest)
    if m:
        target, line = rest[: m.start()], int(m.group(1))
        if line < 1:
            raise FindingsError(f"artifact {ref!r}: a line reference is #LN with N >= 1")
    if not target.strip():
        raise FindingsError(f"artifact {ref!r}: a file reference names a path (file:PATH or file:PATH#LN)")
    p = Path(os.path.expanduser(target))
    p = (p if p.is_absolute() else cwd / p).resolve()
    if not p.is_file():
        raise FindingsError(f"artifact {ref!r}: {p} is not a regular file")
    out = {"type": "file", "ref": ref, "path": str(p), "size": p.stat().st_size, "sha256": _sha256_file(p)}
    if line is not None:
        raw = _file_line(p, line)
        if raw is None:
            raise FindingsError(f"artifact {ref!r}: {p} has no line {line}")
        out["line"] = line
        out["line_sha256"] = hashlib.sha256(raw).hexdigest()
    return out


def _banned_option(sub: str, a: str) -> bool:
    if a.startswith("--"):
        name = a[2:].split("=", 1)[0]
        if not name or sub in _GIT_EXACT_OK.get(name, ()):
            return False
        return any(b.startswith(name) or name.startswith(b) for b in _GIT_BANNED_LONG)
    return a.startswith("-") and _GIT_BANNED_SHORT in a[1:]


def check_git_argv(argv: list[str]) -> list[str]:
    """`argv` (subcommand first, no `git`) checked: a subcommand in GIT_READONLY and no option before
    `--` that writes a file or runs a program (a banned long option or any unique abbreviation of it,
    `--text` outside the subcommands where it is an exact option, a short bundle holding `O`). Raises
    FindingsError; returns a copy of argv."""
    argv = [str(a) for a in argv]
    if not argv:
        raise FindingsError("git artifact: no git command given (git:log --oneline -5)")
    sub = argv[0]
    if sub not in GIT_READONLY:
        raise FindingsError(f"git artifact: `git {sub}` is not a read-only command this check runs "
                            f"(one of: {', '.join(sorted(GIT_READONLY))})")
    end = argv.index("--") if "--" in argv else len(argv)     # pathspecs after `--` are not options
    for a in argv[1:end]:
        if _banned_option(sub, a):
            raise FindingsError(f"git artifact: option {a!r} writes a file or runs a program (or may "
                                "abbreviate one that does); not allowed")
    return argv


def git_argv(args: str) -> list[str]:
    """The checked argv (without the `git` and safety prefix) of a `git:` reference. Raises
    FindingsError for an empty command, a subcommand outside GIT_READONLY or an option that writes a
    file or runs a program (check_git_argv)."""
    import shlex
    try:
        argv = shlex.split(args)
    except ValueError as e:
        raise FindingsError(f"git artifact {args!r}: cannot split it into words ({e})") from None
    if argv and argv[0] == "git":
        argv = argv[1:]
    return check_git_argv(argv)


def _git_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat", "PAGER": "cat", "LC_ALL": "C"})
    return env


def _run_git(repo: Path, argv: list[str], *, overrides: bool = True) -> subprocess.CompletedProcess:
    """git in `repo` with the hardened environment; `overrides` adds the -c safety settings (left off
    only to list the repo's own config, so every command-scope key there is a leak to refuse)."""
    sub, rest = argv[0], argv[1:]
    cmd = ["git", *(_GIT_SAFE_CONFIG if overrides else ()), "-C", str(repo), sub,
           *_GIT_NO_EXEC.get(sub, ()), *rest]
    try:
        return subprocess.run(cmd, capture_output=True, env=_git_env(), timeout=GIT_TIMEOUT_S,
                              stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        raise FindingsError("git artifact: `git` is not on PATH") from None
    except subprocess.TimeoutExpired:
        raise FindingsError(f"git artifact: `git {' '.join(argv)}` ran past {GIT_TIMEOUT_S:.0f} s") from None


def _workdirs(wd: Path) -> list[Path]:
    """Every folder that holds challenge files: the workdir passed, the event's own workdir (the
    `--workdir` a caller passes is not trusted to be it) and the base all event workdirs live under."""
    out = [wd.resolve()]
    try:
        out.append(_paths.workdir().resolve())
    except (ValueError, OSError):      # no current event (EventError is a ValueError): nothing more to add
        pass
    out.append(Path(_paths.DEFAULT_WORK_BASE).expanduser().resolve())
    return out


def _parse_git_config(raw: bytes) -> list[tuple[str, str]]:
    """`git config --list --show-scope -z` output as [(scope, key)] (the values are never kept)."""
    parts = raw.split(b"\0")
    out = []
    for i in range(0, len(parts) - 1, 2):
        scope = parts[i].decode("utf-8", "replace")
        key = parts[i + 1].split(b"\n", 1)[0].decode("utf-8", "replace")
        out.append((scope, key))
    return out


def _check_git_config(repo: Path) -> None:
    """Refuse a repo whose config (with its includes, any scope git reads) sets a key outside
    _GIT_CONFIG_OK: a filter, diff or textconv driver, fsmonitor, pager or gpg program in a repo's
    config runs a command, and a challenge or a planted repo controls its config."""
    res = _run_git(repo, ["config", "--list", "--includes", "--show-scope", "-z"], overrides=False)
    if res.returncode != 0:
        raise FindingsError(f"git artifact: cannot read the config of {repo} "
                            f"({one_line(res.stderr.decode('utf-8', 'replace'), 120)})")
    for scope, key in _parse_git_config(res.stdout):
        if not _GIT_CONFIG_OK.fullmatch(key.lower()):
            raise FindingsError(f"git artifact: the git config of {repo} sets {one_line(key, 80)!r} "
                                f"({scope}), which this check does not run under (a repo's config can "
                                "run commands); run it in a repo of your own with a plain config")


def _git_line(repo: Path, argv: list[str]) -> str | None:
    res = _run_git(repo, argv)
    return res.stdout.decode("utf-8", "replace").strip() if res.returncode == 0 else None


def _check_no_submodules(repo: Path) -> None:
    """Refuse a repo with a submodule: a gitlink in its index (an embedded repo `git add`ed, with or
    without a .gitmodules), a .gitmodules file, or a non-empty `modules` folder in its git dir. git
    status, diff and describe --dirty run git inside a populated submodule, under the submodule's own
    config, which the config check above never reads (it may set a clean filter that runs a command)."""
    why = None
    top = _git_line(repo, ["rev-parse", "--show-toplevel"])
    if top and os.path.lexists(Path(top) / ".gitmodules"):
        why = "a .gitmodules file"
    for d in filter(None, {_git_line(repo, ["rev-parse", "--absolute-git-dir"]),
                           _git_line(repo, ["rev-parse", "--path-format=absolute", "--git-common-dir"])}):
        m = Path(d) / "modules"
        if why is None and m.is_dir() and any(m.iterdir()):
            why = f"submodule repos under {m}"
    if why is None:
        res = _run_git(repo, ["ls-files", "--stage", "-z"])
        if res.returncode != 0:
            raise FindingsError(f"git artifact: cannot list the index of {repo} "
                                f"({one_line(res.stderr.decode('utf-8', 'replace'), 120)})")
        if any(e.startswith(b"160000 ") for e in res.stdout.split(b"\0")):
            why = "a submodule (gitlink) in its index"
    if why:
        raise FindingsError(f"git artifact: {repo} has {why}; git runs inside a submodule under the "
                            "submodule's own config, which this check does not read. Run it in a repo of "
                            "your own without submodules")


def _git_repo(git_repo: Path | str | None, wd: Path) -> Path:
    repo = Path(git_repo).expanduser().resolve() if git_repo else _paths.repo_root().resolve()
    if not repo.is_dir():
        raise FindingsError(f"git artifact: {repo} is not a directory")
    for wdr in _workdirs(wd):
        if repo == wdr or _within(repo, wdr):
            raise FindingsError(f"git artifact: {repo} is inside the event workdir {wdr}; a challenge's "
                                "git config can run commands, so this check only runs git in your own repos")
    _check_git_config(repo)
    _check_no_submodules(repo)
    return repo


def _git_artifact(ref: str, rest: str, wd: Path, git_repo) -> dict:
    argv = git_argv(rest)
    repo = _git_repo(git_repo, wd)
    head = _run_git(repo, ["rev-parse", "HEAD"])
    if head.returncode != 0:
        raise FindingsError(f"artifact {ref!r}: {repo} is not a git repository with a commit "
                            f"({one_line(head.stderr.decode('utf-8', 'replace'), 120)})")
    res = _run_git(repo, argv)
    if res.returncode != 0:
        raise FindingsError(f"artifact {ref!r}: `git {' '.join(argv)}` exited {res.returncode} "
                            f"({one_line(res.stderr.decode('utf-8', 'replace'), 120)}); a failed command "
                            "is not evidence")
    return {"type": "git", "ref": ref, "repo": str(repo), "head": head.stdout.decode().strip(),
            "argv": argv, "sha256": hashlib.sha256(res.stdout).hexdigest(),
            "lines": len(res.stdout.splitlines())}


def resolve_artifact(ref: str, *, workdir: Path | None = None, cwd: Path | None = None,
                     git_repo: Path | str | None = None) -> dict:
    """One artifact reference (`ledger:N`, `file:PATH[#LN]`, `git:ARGS`) resolved into its record.
    Raises FindingsError with the reason when it does not resolve."""
    wd = _paths.workdir() if workdir is None else Path(workdir)
    ref = str(ref or "").strip()
    kind, sep, rest = ref.partition(":")
    if not sep or not rest.strip():
        raise FindingsError(f"artifact {ref!r}: write ledger:N, file:PATH[#LN] or git:ARGS")
    if kind == "ledger":
        return _ledger_artifact(ref, rest.strip(), wd)
    if kind == "file":
        return _file_artifact(ref, rest.strip(), Path(cwd) if cwd else Path.cwd())
    if kind == "git":
        return _git_artifact(ref, rest.strip(), wd, git_repo)
    raise FindingsError(f"artifact {ref!r}: unknown kind {kind!r}; write ledger:N, file:PATH[#LN] or git:ARGS")


def _resolve_all(refs: Iterable[str] | None, what: str, **kw) -> list[dict]:
    refs = [r for r in (refs or []) if str(r).strip()]
    if not refs:
        raise EvidenceRefused(f"{what} refused: no artifact linked. Link the evidence it rests on: "
                            "ledger:N (a ledger record), file:PATH[#LN] (a result file or log line) or "
                            "git:ARGS (a read-only git command)")
    out = []
    for r in refs:
        try:
            out.append(resolve_artifact(r, **kw))
        except EvidenceRefused:
            raise
        except FindingsError as e:
            raise EvidenceRefused(f"{what} refused: {e}") from None
    return out


# ------------------------------------------------------------------------------------------ writing

def _parse_lines(data: bytes, p: Path) -> list[dict]:
    out = []
    for n, line in enumerate(data.decode("utf-8").splitlines(), 1):
        if line.strip():
            try:
                rec = json.loads(line)
            except ValueError as e:
                raise FindingsError(f"{p}:{n}: corrupt findings line: {e}") from None
            if not isinstance(rec, dict):
                raise FindingsError(f"{p}:{n}: corrupt findings line: not an object")
            out.append(rec)
    return out


def _locked_append(p: Path, build: Callable[[list[dict]], dict]) -> dict:
    """Under an exclusive flock: read every record, build the new one from them, append it."""
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(p, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        size = os.fstat(fd).st_size
        data = os.pread(fd, size, 0) if size else b""
        rec = build(_parse_lines(data, p))
        line = (json.dumps(rec, ensure_ascii=False, default=str, separators=(",", ":")) + "\n").encode("utf-8")
        os.write(fd, line)
        return rec
    finally:
        os.close(fd)


def _next_id(records: list[dict]) -> str:
    top = 0
    for r in records:
        if r.get("op") == "claim":
            m = ID_RE.match(str(r.get("id") or ""))
            if m:
                top = max(top, int(m.group(1)))
    return f"F-{top + 1}"


def add(kind: str, text: str, *, artifacts: Iterable[str] | None, challenge_id: Any = None,
        to: str | None = None, by: str = "orch", workdir: Path | None = None, cwd: Path | None = None,
        git_repo: Path | str | None = None, clock: Callable[[], float] = time.time) -> dict:
    """Record one cause or steer claim, `suspected`, with its artifacts resolved. Raises
    FindingsError (nothing written) on a bad kind, empty text, no artifact or an unresolved one."""
    if kind not in KINDS:
        raise FindingsError(f"claim kind {kind!r} is not one of: {', '.join(KINDS)}")
    body = one_line(text)
    if not body:
        raise FindingsError("a claim needs its text (the cause stated, or the steer given)")
    wd = _paths.workdir() if workdir is None else Path(workdir)
    arts = _resolve_all(artifacts, f"{kind} claim", workdir=wd, cwd=cwd, git_repo=git_repo)
    cid = None if challenge_id in (None, "") else one_line(challenge_id, 128)

    def build(records: list[dict]) -> dict:
        return {"ts": round(clock(), 3), "op": "claim", "id": _next_id(records), "kind": kind,
                "text": body, "challenge_id": cid, "to": one_line(to, 64) or None,
                "by": one_line(by or "orch", 64), "artifacts": arts, "status": SUSPECTED,
                "verify_reason": (f"suspected: {len(arts)} artifact(s) linked and resolved; whether they "
                                  "support the claim is a person's call, not yet made")}
    return _locked_append(path(wd), build)


def _change(claim_id: str, status: str, *, by: str, reason: str, artifacts: list[dict],
            verify_reason: str, allowed_from: frozenset, workdir: Path | None,
            clock: Callable[[], float]) -> dict:
    wd = _paths.workdir() if workdir is None else Path(workdir)

    def build(records: list[dict]) -> dict:
        cur = _fold(records).get(claim_id)
        if cur is None:
            raise FindingsError(f"no claim {claim_id!r} in {path(wd)}")
        if cur["status"] not in allowed_from:
            raise FindingsError(f"claim {claim_id} is {cur['status']}; it cannot become {status}")
        return {"ts": round(clock(), 3), "op": "status", "id": claim_id, "status": status,
                "by": one_line(by, 64), "reason": one_line(reason), "artifacts": artifacts,
                "verify_reason": verify_reason}
    return _locked_append(path(wd), build)


def _check_id(claim_id: str) -> str:
    cid = str(claim_id or "").strip()
    if not ID_RE.match(cid):
        raise FindingsError(f"{claim_id!r} is not a claim id (F-<n>)")
    return cid


def confirm(claim_id: str, *, by: str, note: str = "", workdir: Path | None = None,
            clock: Callable[[], float] = time.time) -> dict:
    """A person confirms a suspected claim: the linked artifacts support it. `by` names the person.
    This function cannot tell a person from an agent; `ctf findings confirm` demands an interactive
    terminal and the id typed back, as `ctf budget extend` does."""
    cid = _check_id(claim_id)
    who = one_line(by, 64)
    if not who:
        raise FindingsError("a confirmation names the person who made it (by=)")
    return _change(cid, CONFIRMED, by=who, reason=note, artifacts=[],
                   verify_reason=f"confirmed by {who}: a person judged that the artifacts support it",
                   allowed_from=frozenset({SUSPECTED}), workdir=workdir, clock=clock)


def refute(claim_id: str, *, by: str, artifacts: Iterable[str] | None, reason: str = "",
           workdir: Path | None = None, cwd: Path | None = None, git_repo: Path | str | None = None,
           clock: Callable[[], float] = time.time) -> dict:
    """The claim did not hold, shown by the artifacts given (required, resolved like a claim's)."""
    cid = _check_id(claim_id)
    wd = _paths.workdir() if workdir is None else Path(workdir)
    arts = _resolve_all(artifacts, f"refuting {cid}", workdir=wd, cwd=cwd, git_repo=git_repo)
    who = one_line(by or "unknown", 64)
    return _change(cid, REFUTED, by=who, reason=reason, artifacts=arts,
                   verify_reason=f"refuted by {who} with {len(arts)} artifact(s) showing it did not hold",
                   allowed_from=LIVE, workdir=wd, clock=clock)


def retract(claim_id: str, *, by: str, reason: str, workdir: Path | None = None,
            clock: Callable[[], float] = time.time) -> dict:
    """Its author withdraws the claim (a retracted nudge). A reason is required."""
    cid = _check_id(claim_id)
    why = one_line(reason)
    if not why:
        raise FindingsError(f"retracting {cid} needs a reason (why it was withdrawn)")
    who = one_line(by or "unknown", 64)
    return _change(cid, RETRACTED, by=who, reason=why, artifacts=[],
                   verify_reason=f"retracted by {who}: {why}", allowed_from=LIVE, workdir=workdir,
                   clock=clock)


# ------------------------------------------------------------------------------------------ reading

def records(workdir: Path | None = None) -> list[dict]:
    """Every record, in write order. A corrupt line raises FindingsError."""
    p = path(workdir)
    if not p.exists():
        return []
    return _parse_lines(p.read_bytes(), p)


def _fold(recs: Iterable[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for r in recs:
        op, cid = r.get("op"), r.get("id")
        if op == "claim":
            c = dict(r)
            c["history"] = []
            c["claimed_ts"] = r.get("ts")
            out[str(cid)] = c
        elif op == "status" and str(cid) in out:
            c = out[str(cid)]
            c["status"] = r.get("status")
            c["verify_reason"] = r.get("verify_reason")
            c["history"].append(r)
            c["status_by"] = r.get("by")
            c["status_ts"] = r.get("ts")
            if r.get("reason"):
                c["status_reason"] = r.get("reason")
    return out


def claims(workdir: Path | None = None, *, include_final: bool = True) -> list[dict]:
    """Each claim with its current status (latest status record wins), oldest first. A claim dict has
    the claim record's fields plus `history` (its status records), `status_by`, `status_ts` and
    `status_reason` once changed."""
    out = list(_fold(records(workdir)).values())
    return out if include_final else [c for c in out if c.get("status") in LIVE]


def get(claim_id: str, workdir: Path | None = None) -> dict:
    cid = _check_id(claim_id)
    c = _fold(records(workdir)).get(cid)
    if c is None:
        raise FindingsError(f"no claim {cid!r} in {path(workdir)}")
    return c


def held(claim: dict) -> str:
    """Whether the claim held: held | did not hold | retracted | unresolved."""
    return HELD.get(str(claim.get("status")), "unresolved")


def artifact_label(a: dict) -> str:
    t = a.get("type")
    if t == "ledger":
        return f"ledger:{a.get('line')} ({a.get('event')})"
    if t == "file":
        return f"file:{a.get('path')}" + (f"#L{a['line']}" if a.get("line") else "") + \
            f" (sha256 {str(a.get('sha256'))[:12]})"
    if t == "git":
        return f"git {' '.join(a.get('argv') or [])} @ {str(a.get('head'))[:10]} (out sha256 {str(a.get('sha256'))[:12]})"
    return str(a.get("ref") or "?")


def claim_line(c: dict, width: int = 160) -> str:
    """One line per claim: id, STATUS, kind, challenge, steer target, text, artifact count, author."""
    head = f"{c.get('id')} [{str(c.get('status')).upper()}] {c.get('kind')}"
    if c.get("challenge_id"):
        head += f" {c['challenge_id']}"
    if c.get("to"):
        head += f" -> {c['to']}"
    tail = f" ({len(c.get('artifacts') or [])} artifact(s), by {c.get('by')}"
    if c.get("status") != SUSPECTED and c.get("status_by"):
        tail += f"; {c.get('status')} by {c.get('status_by')}"
    tail += ")"
    return one_line(f"{head}: {c.get('text')}{tail}", width)


def note_text(rec: dict) -> str:
    """One line for a single findings record, for the orchestrator's digest."""
    if rec.get("op") == "claim":
        who = f" {rec['challenge_id']}" if rec.get("challenge_id") else ""
        return one_line(f"claim {rec.get('id')} {rec.get('kind')}{who} [SUSPECTED]: {rec.get('text')}", 120)
    st = str(rec.get("status") or "?").upper()
    why = f": {rec.get('reason')}" if rec.get("reason") else ""
    return one_line(f"claim {rec.get('id')} now {st} by {rec.get('by')}{why}", 120)


# ------------------------------------------------------------------------------------------ recheck

def recheck_artifact(a: dict, *, workdir: Path | None = None) -> tuple[bool, str]:
    """Re-resolve one stored artifact and compare it: (still matches, reason)."""
    wd = _paths.workdir() if workdir is None else Path(workdir)
    t = a.get("type")
    try:
        if t == "ledger":
            now = _ledger_artifact(str(a.get("ref")), str(a.get("line")), wd)
            same = now["sha256"] == a.get("sha256")
            return same, "ledger line unchanged" if same else "the ledger line changed since the claim"
        if t == "file":
            p = Path(str(a.get("path")))
            if not p.is_file():
                return False, f"{p} is gone"
            if a.get("line"):
                raw = _file_line(p, int(a["line"]))
                if raw is None or hashlib.sha256(raw).hexdigest() != a.get("line_sha256"):
                    return False, f"line {a['line']} of {p} changed since the claim"
                return True, f"line {a['line']} unchanged"
            same = _sha256_file(p) == a.get("sha256")
            return same, "file unchanged" if same else f"{p} changed since the claim"
        if t == "git":
            argv = check_git_argv(list(a.get("argv") or []))   # a hand-edited record is checked again
            repo = _git_repo(a.get("repo"), wd)
            res = _run_git(repo, argv)
            if res.returncode != 0:
                return False, f"git now exits {res.returncode}"
            if hashlib.sha256(res.stdout).hexdigest() == a.get("sha256"):
                return True, "git output unchanged"
            head = _run_git(repo, ["rev-parse", "HEAD"]).stdout.decode().strip()
            moved = "" if head == a.get("head") else f" (HEAD moved {str(a.get('head'))[:10]} -> {head[:10]})"
            return False, f"git output changed since the claim{moved}"
    except FindingsError as e:
        return False, str(e)
    return False, f"unknown artifact type {t!r}"


def recheck(claim_id: str, workdir: Path | None = None) -> list[tuple[dict, bool, str]]:
    """Every artifact of a claim (and of its refutation) re-resolved: [(artifact, matches, reason)]."""
    c = get(claim_id, workdir)
    arts = list(c.get("artifacts") or [])
    for h in c.get("history") or []:
        arts += list(h.get("artifacts") or [])
    return [(a, *recheck_artifact(a, workdir=workdir)) for a in arts]
