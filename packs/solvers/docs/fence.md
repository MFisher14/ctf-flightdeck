# Solver filesystem fence (B-219)

During CSCTF 2026, 46 Codex event subagents ran 818 commands outside the challenge workspace. They
were looking for answers in local traces: `~/.codex`, `~/.claude`, SQLite stores, paste and upload
caches, Edge and Discord caches, the macOS notification database, the unified log and APFS
snapshots (`analysis/out/reports/sessions/csctf-codex-event-subagents.md`, bottom line 3). Nothing
left the machine, but it was a privacy and scope fault on a machine that also holds unrelated work.

The fence limits what a **solver** may read during an event. It is generated per event workspace
and passed to the solver at launch. It never changes `~/.claude`, `~/.codex` or this repo's own
`.claude/settings.json`, because a fence there would also fence the people and agents building the
repo.

## What a solver may read

| | roots |
|---|---|
| read and write | the event or challenge workspace, the master repo (minus its private trees, below) |
| read only | the drop folder (the one readable folder under `~/Downloads`), extra `allow_read` roots |
| denied | the roots in `ctf/fence.py` `DENY_HOME` / `DENY_ABS` / `DENY_REPO`, any `.ctf/` directory (`DENY_NAMES`), plus `deny_read` from the event config |

**The repo's private trees (R-03).** The repo is a read root, but its gitignored sensitive trees
are carved out of it: `analysis/` (participant IP addresses, session ids, usage; category
`repo-private`), `docs/writeups/` and `writeups/` (unredacted writeups and flags; `repo-private`),
`.claude/` (build worktrees and agent config; `agent-state`) and `.ctf/` (platform token and
cookie; `credentials`). A `.ctf/` directory is also denied **wherever it appears**, at any depth
under any root (the event folder, the workspace, a challenge folder). The rest of the repo
(`solvers/`, `ctf/`, `tools/`, `templates/`, `docs/`, `events/`) stays readable. A workspace,
drop folder or `allow_read` entry inside one of these trees, or one that contains them (other than
the repo itself), is refused with a named reason. The trees are denied for **writes** too: the repo
and workspace are write roots, so the Claude settings add `Edit(...)` denies and
`sandbox.filesystem.denyWrite` entries for them. Codex's `"deny"` is a no-access entry, but only
reads were probed live, not writes.

**Platform credentials inside the fence.** The platform client (`ctf/config.py`) reads its token
and cookie from `<repo>/.ctf/`, which the fence denies. A fenced solver that runs `python -m ctf`
platform commands therefore gets credentials only through `$CTF_TOKEN` / `$CTF_COOKIE`, set by the
operator in the environment the launcher starts the solver with. Otherwise submission runs
outside the fence, by the operator.

| rendering | how the carve-outs are expressed |
|---|---|
| Claude Code | `Read(//<repo>/analysis/**)` and `Edit(//<repo>/analysis/**)` and the like in `permissions.deny`, the same paths in `sandbox.filesystem.denyRead` and `denyWrite`; for `.ctf`, `Read(//**/.ctf)`, `Read(//**/.ctf/**)`, the matching `Edit(...)` rules and the globs `/**/.ctf`, `/**/.ctf/**` in `denyRead` and `denyWrite` |
| Codex | `"<repo>/analysis" = "deny"` and the like next to `"<repo>" = "write"` (the more specific deny wins, verified live); `"/**/.ctf" = "deny"` and `"/**/.ctf/**" = "deny"` |
| report | category `repo-private`, `agent-state` or `credentials`; relative words with a watched name as a whole component (`analysis/out/x`, `.ctf/token`, from `$HOME` `ctf-tools/analysis/x` or `./ctf-tools/.ctf/t`, also after `-I`, `--opt=` or `VAR=`) are classified against the cwd; a plain `cd DIR` or `pushd DIR` (redirections ignored, relative targets resolved against the known cwd) moves the cwd, and inside `( ... )` or `$( ... )` only until the subshell closes; with no known cwd nothing relative is guessed |

Verified with `codex sandbox` (codex-cli 0.167.0): a root-scoped glob such as
`"<repo>/**/.ctf" = "deny"` did **not** block a read inside the writable repo, while the global
`"/**/.ctf"` did (and `"/**/.ctf/**"` alone left the directory listable). That is why the `.ctf`
rule is global. Files named `x.ctf`, `.ctfrc` or `a.ctf.txt` stay readable.

Denied categories: `agent-state` (`~/.codex`, `~/.claude`, `~/.claude.json`, `~/.cursor`,
`~/.gemini`), `credentials` (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.config`, `~/.netrc`,
`~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/Library/Keychains`), `shell-history`, `trash`,
`app-data` (all of `~/Library`), `browser` (Chrome, Edge, Brave, Firefox, Arc, Safari profiles and
caches, cookies), `messaging` (Messages, Mail, Discord, Slack), `notifications` (the usernoted group
container and `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter`), `unified-log`
(`/private/var/db/diagnostics`, `uuidtext`, `/private/var/log`, `/Library/Logs`), `snapshots`
(local Time Machine snapshots, `.MobileBackups`, `.fseventsd`, the Spotlight index),
`customer-work` (`~/pentest-tools`), `downloads` (`~/Downloads` except the drop folder) and
`personal` (Desktop, Documents, Pictures, Movies, Music), `repo-private` (the repo's
`analysis/`, `docs/writeups/`, `writeups/`). The commands `log show|stream|collect`,
`tmutil`, `mount_apfs`, `diskutil apfs list|mount` and `mdfind` are flagged too (category
`unified-log`, `snapshots` or `spotlight`).

`--strict-home` (or `strict_home = true`) denies all of `$HOME` and re-opens only the allowed
roots and the Python toolchain the repo venv runs on. Tools installed under `$HOME` (cargo, go,
Ghidra and so on) then need an `allow_read` entry.

The fence refuses to build when a root would defeat it, and names the reason. That covers a
workspace that is `$HOME`, a workspace inside or containing a denied root, a drop folder that is
`~/Downloads` itself, and an `allow_read` entry overlapping a denied store.

## Use

```sh
# Codex: headless, in the fence, standard tier
tools/codex_launch --event csctf --drop ~/Downloads/csctf "solve the challenge in ./1234-foo"
tools/codex_launch --event csctf --interactive
tools/codex_launch --event csctf --self-test            # live probes, no model call

# Claude Code: writes <workspace>/.fence/claude-settings.json, runs claude --settings ... there
tools/claude_launch --event csctf --drop ~/Downloads/csctf -- --permission-mode auto

# The policy itself
python -m ctf fence show --event csctf
python -m ctf fence claude-settings --event csctf [--install]   # --install: also <ws>/.claude/settings.json
python -m ctf fence check ~/.codex/sessions ./files/a.bin
python -m ctf fence report <transcript.jsonl|rollout.jsonl|commands.log> [--json]
```

The workspace defaults to the event workdir (`ctf.paths.workdir()`, which is `$CTF_WORKDIR` or
`~/ctf-work/<event>`). Per-event settings go in an optional `events/<slug>/fence.toml`; unknown keys
are an error:

```toml
drop_folder = "~/Downloads/csctf"
allow_read  = ["/opt/wordlists"]
deny_read   = ["~/old-event-repo"]
strict_home = false
```

## Claude Code: what the settings do

The keys were checked against the settings schema inside the installed Claude Code (2.1.321,
read from the binary's zod schema and its descriptions, not guessed).
`tests/test_fence.py::test_emitted_keys_exist_in_installed_claude_schema` re-checks every emitted
key against whatever version is installed.

| key | effect |
|---|---|
| `permissions.deny` `Read(//<root>/**)` | the file tools (Read, Grep, Glob, Edit) refuse the denied roots. Read deny rules are also merged into the sandbox's `denyRead`. |
| `permissions.deny` `Bash(log show *)` ... | refuses the store-reaching commands (prefix rules, so they are best effort) |
| `permissions.blockReadsOutsideWorkingDirectories` | the file tools refuse everything outside the working directories, in every permission mode, and no allow rule lifts it |
| `permissions.additionalDirectories` | the repo and the workspace are the working directories |
| `permissions.blockReadsExemptPaths` | the drop folder and `allow_read` roots stay readable. Only honoured from `--settings`. |
| `permissions.disableBypassPermissionsMode` | `bypassPermissions` cannot be selected |
| `sandbox.enabled`, `failIfUnavailable`, `allowUnsandboxedCommands: false` | Bash runs sandboxed. If the sandbox cannot start, the session exits instead of running unsandboxed, and `dangerouslyDisableSandbox` is ignored. |
| `sandbox.filesystem.denyRead` / `allowRead` / `allowWrite` | the sandbox denies the roots, re-opens the drop folder and `allow_read` roots, and allows writes to the workspace and repo only |
| `permissions.deny` `Edit(//<repo>/analysis/**)` ..., `sandbox.filesystem.denyWrite` | the repo's private trees and any `.ctf/` stay unwritable inside the write roots (R-03) |
| `hooks` (added by `tools/claude_launch`, not by `ctf fence`) | the player-notes feed (B-168): `python -m ctf.notes ... hook` on SessionStart, UserPromptSubmit and PostToolUse pushes new player notes into the session, and the notes folder is added to `permissions.deny` (`Edit(...)`) and `sandbox.filesystem.denyWrite` so the session cannot forge a note; `--no-notes` leaves both out |

When a drop folder is set, `~/Downloads` gets no `Read(...)` deny rule, because a deny rule beats
every allow and would also block the drop folder. Two other mechanisms cover it:
`blockReadsOutsideWorkingDirectories` confines the file tools, and the sandbox's `denyRead` (with
the drop folder in `allowRead`) blocks Bash.

Pass the file with `--settings`: flag settings outrank project settings, and only they honour
`blockReadsExemptPaths`. `--install` also writes `<workspace>/.claude/settings.json`, so a session
started by hand in the workspace is fenced too. Without the exemption there, the drop folder is
readable from sandboxed Bash only.

**Limits (Claude Code).** The Claude half has not been run live, because that needs a model
session. To check it, start `tools/claude_launch` and ask the agent to run `stat ~/.codex`; the
command should be refused. Other limits:

- `Bash(...)` deny rules are prefix rules. `sh -c "log show"` gets past them, so for those
  commands the denied-access report is the backstop.
- MCP servers and hooks run outside the sandbox.
- Not verified live (R-03): that Claude Code's matcher reads `Read(//**/.ctf/**)` as "a `.ctf`
  at any depth". On Linux the sandbox expands `denyRead` globs by walking the filesystem, so
  `/**/.ctf` there is untested and may be slow.
- `--strict-home` puts the whole repo and workspace in `allowRead`. The schema text says
  `allowRead` "takes precedence over denyRead for matching paths", which reads as if it re-opened
  the carve-outs for Bash. It does not, per the macOS profile generator in Claude Code 2.1.322
  (read from the installed binary, not run live). The generator emits rules in this order:
  1. `(allow file-read*)`;
  2. every `denyRead` path;
  3. every `allowRead` path;
  4. every non-glob deny that sits strictly **inside** a non-glob allow, again;
  5. every glob deny, again, exempting only allow paths that the glob itself matches.

  Seatbelt applies the last matching rule. So `<repo>/analysis` (inside the allowed `<repo>`) and
  `/**/.ctf` (no allow path matches it) stay denied, while `$HOME` (not inside any allow) is
  re-opened only at the allowed roots. The rejected alternative was to list the repo's children in
  `allowRead`. It would also deny reading the repo directory itself, which Python's import system
  lists to find `ctf`. The `Read(...)` deny rules cover the file tools in every mode.
- Claude Code's own process reads `~/.claude` as usual; only the agent's tools are fenced.

## Codex: what its sandbox can and cannot block on reads

These results come from codex-cli 0.167.0 on macOS (seatbelt), probed with `codex sandbox`, with no
model call. `tools/codex_launch --self-test` and
`tests/test_fence.py::test_codex_sandbox_enforces_the_fence` repeat the probes on every run.

**Can block:**

- **Reads from denied roots.** A permission profile (`[permissions.<name>]`, selected with
  `default_permissions`) with `"<path>" = "deny"` entries makes those roots unreadable to every
  command Codex runs: `cat`, `stat`, `ls`, `sqlite3`, Python scripts and their children. The deny
  also holds under the APFS firmlink spelling `/System/Volumes/Data/Users/...`.
- **Re-opened subfolders.** The more specific entry wins: a `"read"` drop folder inside a denied
  `~/Downloads` is readable and its siblings are not.
- **Paths written as `~/...` or as globs.** `~/...` paths expand. Glob entries are allowed for
  `deny` only.
- **Denied subtrees of a writable root.** `"<repo>/analysis" = "deny"` beside
  `"<repo>" = "write"` blocks the subtree and leaves the rest of the repo readable. A `.ctf/`
  nested anywhere is blocked by the global `"/**/.ctf"` glob (a root-scoped `"<root>/**/.ctf"` was
  not enforced). The self-test probes a `.ctf/` canary inside the workspace on every run.

**Cannot block:**

- **Anything under the legacy sandbox.** `--sandbox workspace-write` (and `read-only`) blocks no
  reads: the whole disk stays readable. The self-test's control check proves this every run. This
  is why the launcher uses a permission profile and never passes `-s`. Codex refuses
  `sandbox_mode` and `default_permissions` overrides together.
- **Codex's own process.** It reads `~/.codex` (config, auth, sessions) and is not sandboxed. The
  same goes for anything Codex does in-process rather than through a shell command, such as
  attaching an image by path, and for MCP servers.
- **Escalations.** Under `approval_policy = "on-request"` the model can ask to run a command
  outside the sandbox. The launcher defaults to `never` and refuses `--approve-for-me` (an
  automated reviewer approving escapes) as a passthrough argument.
- **`log show` and friends.** These go through `logd` rather than the filesystem, and blocking
  them is not verified. The report flags them.
- **Misspelt keys.** Unknown keys in a permission profile are ignored without an error (verified:
  `bogus = 1` was accepted), so a misspelt key fails open. The self-test is the guard against
  that.
- **Linux.** Codex there uses landlock or bubblewrap, and this fence was not exercised on Linux.

The launcher also disables the shell snapshot, because it is sourced from `~/.codex/shell_snapshots`,
which the fence denies.

**Service tier.** The launcher passes `--disable fast_mode --disable ultrafast_mode` and never sets
`service_tier`, so requests use the standard tier (B-009). `codex features list` with those flags
reports both features off. The effect on a live request was not observed, because that costs a
model call. Passthrough arguments that set `service_tier`, enable either feature, or select a
config profile are refused.

## The denied-access report

`python -m ctf fence report LOG...` reads Claude Code transcripts, Codex rollouts, `codex exec
--json` streams and plain one-command-per-line logs. Each line's format is detected separately,
so one file may mix formats. The report covers:

- every read outside the allowed roots, by category, by outcome (`blocked` when the output says the
  read was not permitted, `ran`, `failed`, `unknown`) and by top root;
- reportable categories: the deny categories, `home-other` (elsewhere in `$HOME`) and `other`
  (outside `$HOME` and the system roots, for example `find /`).

The report records the program name and the path, never the whole command line, so a token on a
command line does not reach it. The exit code is 0 when the log is clean, 1 when there are
outside reads and 2 on an error. Paths are matched lexically (`~`, `$HOME`, firmlink and `/private`
spellings folded), so a path built at runtime inside a script is not seen.
