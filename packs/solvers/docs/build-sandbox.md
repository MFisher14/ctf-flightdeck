# Codex build sandbox profile (B-192)

Codex's built-in `workspace-write` sandbox blocked ordinary build work on this repo. Every Codex build
lane hit the same walls and had to explain or escalate them:

- **Loopback bind.** Tests that start a fake service on 127.0.0.1 failed with `PermissionError`.
  In one lane, 23 of 27 full-suite failures were loopback; the same files passed when local binding
  was allowed.
- **Git in a linked worktree.** `git worktree add`, `git commit` and `git branch` failed with
  `cannot lock ref ... Unable to create ... .lock: Operation not permitted`, because a linked
  worktree's gitdir and refs live under the main checkout's `.git`. A retry with escalated
  permissions became the standard first step for each agent.
- **Unicorn.** It died with SIGILL.
- **Other blocked work.** The Docker socket, the package index and GitHub were unreachable, and
  pushes needed someone to approve them.

In one CTF, Codex requested escalation 1,960 times, and an auto-review model handled the approvals.

This profile removes those blockers for **build** work. It is a separate profile from the solver
fence (`docs/fence.md`, `ctf/fence.py`), and the solver fence is unchanged.

## What it allows

Run `python -m ctf build-sandbox show` to print the profile for a checkout.

| | the profile | verified live (`codex sandbox`, codex-cli 0.167.0) |
|---|---|---|
| base | `extends = ":workspace"` (the checkout, which is the cwd, plus the temp folder are writable; reads are open) | |
| checkout | write | |
| git | write to the common `.git` and the worktree's gitdir `<main>/.git/worktrees/<name>`. Codex protects that gitdir even under a write root, so it is listed by name | commit and branch from a linked worktree work. Control: the same commit fails under plain `:workspace` with `index.lock: Operation not permitted` |
| git, kept read only | the hooks folder git runs (`.git/hooks`, or `core.hooksPath` as this checkout resolves it: this repo points it at `.githooks`) and the config files (a sandboxed agent that writes either gets code run outside the sandbox the next time anyone runs git); `packed-refs`; the main checkout's `HEAD` (from a linked worktree); and for each protected branch, its ref file and its `.lock` (see "Protected branches") | hook writes (both folders), config write, packed-refs write and HEAD write are refused; for main and the integration branch, `git update-ref`, a plain `printf > refs/heads/main` and `rm refs/heads/main` are all refused and the branch does not move |
| loopback | `network.allow_local_binding = true` | bind and connect work. Control: denied under plain `:workspace` |
| internet | `network.enabled = true`, `domains` = `tools/build_hosts.toml`, **and** `features.network_proxy = true` | direct egress is denied (EPERM to TEST-NET-1). Codex's proxy answers a host not on the list with `x-proxy-error: blocked-by-allowlist` and passes a listed one |
| Docker | only with `--docker`: `/var/run/docker.sock` and `~/.docker/run/docker.sock` as `unix_sockets` | the mechanism was checked on a synthetic socket: reachable when listed, refused when not. The real Docker socket is never opened |
| denied | `~/.codex`, `~/.claude`, `~/.claude.json`, `~/.cursor`, `~/.gemini`, `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.config` (gh, gcloud and other tools keep tokens there), `~/.netrc`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/Library/Keychains`, `~/pentest-tools`, and any `.ctf/` directory. `~/.config/git` and `~/.config/uv` are re-opened read only (git and uv read their config there), except `~/.config/git/credentials` | `.ctf/canary` inside the checkout is unreadable; in a synthetic home, `.config/gh/hosts.yml` and `.config/git/credentials` are unreadable and `.config/git/config` is readable |

**The proxy is not optional.** With `network.enabled = true` and no `features.network_proxy`, the
sandboxed command reaches the whole network (verified). For that reason:

- `codex-args`, `config-toml` and `launch` always emit both settings.
- The launcher refuses `-c features.network_proxy=...`, `--disable network_proxy` and
  `--enable network_proxy`.

## Protected branches

`main`, `master` and the integration branch are protected; `--protect BRANCH` adds more. The
integration branch is named the way the merge queue names it (`ctf/worktree.py`):
`--integration-branch`, else `$CTF_INTEGRATION_BRANCH`, else `git config ctftools.integrationBranch`.
When none is set, `show` says so and only `main` and `master` are protected.

For each protected branch the ref file (`<common>/refs/heads/<branch>`) and its `.lock` are read
only, and so is `packed-refs` (a branch that `git gc` packed lives only there). So `git update-ref`,
`git branch -f`, a plain write to the ref file and `rm` of it are all refused.

**This is a guard, not a wall.** It stops a lane's mistakes and the obvious moves. A lane can still
write the rest of the common `.git`, so one that sets out to defeat the guard can: for example by
renaming the `refs` folder and planting a symlink, or by damaging objects. Other agents'
item branches stay writable too, because lanes need to create and update their own. The merge
queue's own checks remain the authority on `main` and the integration branch.

**The cost.** Git takes `packed-refs.lock` to delete any ref, so `git branch -d`, `git tag -d`
and dropping the last stash entry fail inside the sandbox. Delete refs outside it. The self-test
reports this as an informational check.

**Not verified, because it needs a model session:** that `codex exec` applies the same proxy
policy as `codex sandbox`. The two read the same config stack. To check it, start a build lane and
ask it to run `curl -sI http://blocked.invalid/`. The reply must carry
`x-proxy-error: blocked-by-allowlist`.

## JIT: not fixable by a profile

Unicorn's SIGILL under Codex is not a JIT denial. Plain `MAP_JIT` code runs inside Codex's
sandbox. The cause is in Codex's seatbelt policy:

1. The policy allows the sysctl `hw.cachelinesize_compat` but not `hw.cachelinesize`.
2. Because that read is denied, Unicorn's QEMU falls back to reading the CPU's cache-type register
   directly.
3. That read traps, and the process gets SIGILL.

To confirm the cause, `sandbox-exec` was run with only that one sysctl denied. It kills Unicorn the
same way (`tests/test_b192_test_markers.py`).

No Codex setting adds a sysctl. Tests that need Unicorn therefore carry `@pytest.mark.needs_jit`.
They are reported as not run inside Codex and run in the merge queue. A real fix needs Codex to allow
`hw.cachelinesize`; that would be an upstream report.

## Test markers

- `@pytest.mark.needs_loopback` and `@pytest.mark.needs_jit` are documented in `docs/CONTRACTS.md`,
  section 9. Each probe runs once per process.
- **Auto not-run.** When the loopback probe fails, a test that fails with a socket denial is
  reported as not run, under `needs_loopback (auto: ...)`. A socket denial here means EPERM or
  EACCES with no file name, either raised directly or explicitly wrapped (`raise ... from`, a
  `reason`, or an exception passed as an argument). An error raised merely while an EPERM was being
  handled, such as a failing assert inside `except PermissionError:`, stays a failure. This covers the roughly 130 test files that start local services
  without the marker, so a sandboxed lane sees NOT RUN instead of spurious failures. With strict
  mode on (`CTF_STRICT_TESTS=1`), that run still fails.
- Where loopback works, these failures stay failures.

## Use

```sh
python -m ctf build-sandbox show                 # the profile for this checkout
python -m ctf build-sandbox hosts                # the allowlist, checked against the event profiles
python -m ctf build-sandbox launch --dry-run "build B-123"          # the codex command line
python -m ctf build-sandbox launch "build B-123" -- --json           # start a headless lane
python -m ctf build-sandbox launch --interactive --docker            # TUI, Docker socket allowed
python -m ctf build-sandbox codex-args           # the -c overrides, one per line
python -m ctf build-sandbox config-toml          # fragment for ~/.codex/config.toml (human step)
python -m ctf build-sandbox selftest --scratch <repo>/scratchpad/bs   # live probes; outside any sandbox
python -m ctf build-sandbox push                 # DRY RUN: the push command for a person to run
```

- **Worktrees.** Create each worktree before you spawn its lane, as the build workflow does, and
  launch the lane with `--checkout <worktree>`. The profile is computed from that checkout's git
  layout.
- **Approvals.** The default approval policy is `never`, so a denial goes back to the model instead
  of becoming an escalation request.
- **Push.** Pushing is the one step that stays outside the sandbox, and the profile enforces it:
  no host that accepts a push or an upload can be on the allowlist (below). `push` checks the
  following:
  - the branch is not `main` or `master`
  - HEAD is not detached
  - the remote exists
  - the push needs no `--force`

  It then prints `git -C <checkout> push <remote> refs/heads/B:refs/heads/B` and notes whether
  there are uncommitted changes. It never pushes, never fetches and never prints the remote URL,
  which can hold a token.

## The allowlist

`tools/build_hosts.toml` has one `[[host]]` per exact host name, each with a `why`. Each entry must be:

- a single exact host name: no wildcards, IP addresses, ports or schemes
- unique in the file
- free of conflicts with forbidden hosts

A conflict is any of these:

- a host an event profile names: its platform `base_url` or `hosts` (or a parent domain of one), or
  `live_service_scope`
- Discord
- a model API (OpenAI, ChatGPT, Anthropic, claude.ai)
- a host that accepts a git push, an API write or a package upload (`PUSH_HOSTS`: github.com,
  api.github.com, uploads.github.com, gist.github.com, gitlab.com, bitbucket.org, upload.pypi.org,
  ...). These are exact names, so read-only siblings such as codeload.github.com stay allowed.

An event profile that does not load is also reported as a conflict.

The list today is pypi.org, files.pythonhosted.org, codeload.github.com, and the two GitHub
release-asset hosts. **github.com is not on it.** With github.com reachable, a lane that found a
credential could `git push` over HTTPS from inside the sandbox. Inside a lane, fetch a vendored
tool's source as an archive (`https://codeload.github.com/OWNER/REPO/tar.gz/REV`). Run a
`git clone` from github.com, or a release download (which starts at github.com), outside the
sandbox. Vendor documentation hosts are not on the list either. To add a host, add a row with its
reason.

## Human steps

- To install the profile for sessions you start by hand, append
  `python -m ctf build-sandbox config-toml` to `~/.codex/config.toml`, then select it with
  `-c default_permissions="ctf_build"`. The fragment contains this checkout's paths: generate it
  per checkout, or use `launch`, which needs no install.
- Run `python -m ctf build-sandbox selftest --scratch <folder outside /tmp>` once on each machine,
  and again after each Codex upgrade.
- To fix Unicorn under Codex, report the `hw.cachelinesize` sysctl denial upstream.
