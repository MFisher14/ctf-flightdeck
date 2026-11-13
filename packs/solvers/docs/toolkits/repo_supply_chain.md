# Toolkit `repo_supply_chain`: repositories, packages, secrets

The module is `solvers/toolkits/repo_supply_chain.py`. It is offline, reads bytes only and
starts no external program.

**Never run `git`, `hg`, `npm install`, `pip install`, `gem install` or `setup.py` on a delivered
repository or package.** A git directory can carry `core.fsmonitor`, `core.sshCommand`, filters,
aliases and live hooks; a package runs its install script. This reader shows all of them as text
(`WOULD RUN under a real git`, `RUNS AT INSTALL`) and runs none.

## What to run first

```bash
PY=.venv/bin/python
# 1. unpack the saved delivery for reading (tools/unpack.py writes <attempt dir>/members/)
$PY tools/unpack.py challenges/day-09/<id>
# 2. the triage: every history, package and secret, in one page
$PY solvers/toolkits/repo_supply_chain.py challenges/day-09/<id>/artifact/<file>      # a zip, tar, tgz, bundle, .whl, .crx ...
$PY solvers/toolkits/repo_supply_chain.py challenges/day-09/<id>/members              # or the unpacked folder
$PY solvers/toolkits/repo_supply_chain.py <path> --json > /tmp/x.json                 # the same as JSON
# 3. where a text is, and which commit added and removed it (every blob, dangling ones too)
$PY solvers/toolkits/repo_supply_chain.py <path> --grep 'AKIA'
```

Reason to the flag from the triage output, then submit it once via `ctf.submit.guarded_submit(...)`
(or `./csctf submit <id> <flag>`); an OSINT/templated answer uses `allow_nonstandard=True`.

Reading the triage:

| Line | Meaning |
| --- | --- |
| `[reflog]` after a commit | no branch or tag holds it; only a reflog line does (a reset or an amend hid it) |
| `NO REF reaches blob ... dangling` | `git fsck` would print it as a dangling blob; its first 100 bytes follow |
| `DELETED path in <commit>` / `RENAMED a -> b` | a path the parent had; a rename is the same or 60% similar content under a new path |
| `STASH stash@{0}` | a stash entry with the files it changes |
| `PROBLEM ...` and `[NOT COMPLETE ...]` | objects are missing or broken: the solver answers nothing that needs the whole history |
| `RUNS AT INSTALL [postinstall] ...` | a hook that runs when the package is installed, the file it runs, the URLs in it |
| `RECORD MISMATCH path` / `NOT IN RECORD path` | a wheel member whose hash differs from RECORD, or one RECORD does not list |
| `== secrets` | kind, value, and the repository, commit and path of each (or `dangling blob <id>`) |

## By hand (Python)

```python
import sys; sys.path.insert(0, "solvers/toolkits"); import repo_supply_chain as T
A = T.Analysis(T.from_paths(["challenges/day-09/<id>/artifact/evidence.zip"]))
g = A.histories[0]                    # GitRepo, HgRepo, DarcsRepo, SvnDump or FossilRepo
g.table()                             # id, author, email, time, tz, message of every commit (unreachable ones too)
g.adding(b"text"), g.removing(b"text")   # the commits that added / removed a string
g.deleted(), g.renamed()              # [(commit, path)], [(commit, old, new)]
g.diff(old, new)                      # git: {path: (old blob, new blob)};  g.changes(commit) against its parent
g.refs(), g.head(), g.reflog(), g.stashes(), g.index(), g.reach()     # git only
g.pseudo_heads()                      # git: {'ORIG_HEAD': [ids], 'FETCH_HEAD': ...}
g.nonstandard()                       # git: [{path, size, why}] files in the git directory git did not write
g.container, g.root                   # git: the archive it came out of, the git directory's path (set by find_git)
g.blob(blob_id)                       # the bytes of any blob;  g.all_blobs() for every one
T.git_config_facts(g)                 # remotes, user, and what a real git would execute here
A.packages                            # npm, wheel, sdist, vsix, crx, jar, nupkg, gem, composer, github_workflow
A.secrets                             # [{kind, value, where: [{repo, commit, path, state}]}]
T.check_record(members, "x.dist-info/RECORD"), T.read_setup_py(b), T.read_workflow(b), T.crx_parts(b), T.jwt_parts(tok)
```

## What it reads

- **git**: loose objects, packfiles with OFS and REF deltas (no `.idx` needed), a lone pack, a
  bundle, refs, packed-refs, HEAD, ORIG_HEAD and its kind, reflog, stash, index v2 to v4, SHA-1
  and SHA-256 repositories, bare or with a work tree, inside a zip, tar or tgz.
- **Mercurial** (`.hg/store/*.i`, `.d`): changelog, manifest, filelogs, deltas, zstd.
- **darcs** (`_darcs/patches/*`, gzip text): patch name, author, date, hunks, addfile, rmfile, move.
- **Subversion**: a dump file (`SVN-fs-dump-format-version`); a working copy's `.svn/wc.db` and an
  FSFS repository's `db/revprops` are listed in the triage only.
- **Fossil**: the repository database (SQLite): artifacts, deltas, check-in manifests.
- **Packages**: npm tgz (`package.json` scripts, bin, main, dependencies that are not from the
  registry), wheel (METADATA, entry points, `.pth` lines, RECORD checked hash by hash), sdist
  (`setup.py` as a syntax tree: cmdclass, `os.system` and friends), `.vsix`, `.crx` v2 and v3
  (extension id, permissions, background and content scripts), `.jar` (MANIFEST.MF, Maven
  coordinates, agent classes), `.nupkg` (nuspec, `tools/install.ps1`, MSBuild `Exec`), `.gem`
  (spec, extensions, checksums), `composer.json`, GitHub Actions workflows (`yaml.safe_load`),
  `requirements.txt` / `.npmrc` / `pip.conf` index URLs.
- **Secrets**: `aws_access_key_id`, `aws_secret_access_key`, `github_token`, `slack_token`,
  `slack_webhook`, `discord_webhook`, `jwt`, `private_key`, `telegram_bot_token`,
  `google_api_key`, `stripe_key`, `npm_token`, `pypi_token`, `huggingface_token`,
  `anthropic_api_key`, `openai_api_key`, `url_credentials`, `flag`, and quoted values assigned to
  a name that says password, secret, api key or token. **A found secret is an answer and nothing
  else: never use it, never test whether it works, submit it only through the guarded path.**

## Question shapes `solve_set` answers

Which fact a question means is read from its words, so every answer is a `labels.pick` (a ranked
candidate list, not a guess that gets sent) or `None`. An answer is offered only when exactly one
fact in the delivery fits and the history is complete. The last column says how many forms are
offered; read "plain" there as "one form". Read the unsure answers with `labels.show(...)`, reason
to the one that fits the challenge, and submit it once through the guarded path.

| Question | Answer | One form when |
| --- | --- | --- |
| commit that added / removed a quoted string, a named file, or the leaked secret | commit id | the syntax or pattern fixes the form (40 hex, "short", "first N characters"); else unsure `full`, `short7` |
| author e-mail, author, message, branch, parent of that commit | the value | e-mail, branch: always; author and message: when one form is left |
| date of that commit | eight forms (`iso_offset`, `iso_utc`, `git_iso`, `epoch`, `date`, ...) | never: always unsure |
| deleted file | path | the syntax says base name or full path; else unsure `path`, `basename` |
| the dangling / unreachable blob or commit: its id, its one-line content | id or text | both readings (with and without the reflog) name the same single object |
| counts: commits, branches, tags, stashes, dangling objects, authors | integer | every way of counting gives the same number |
| how many commits, patches or check-ins a darcs, Fossil, Mercurial or SVN history has | integer | always unsure (`count/commits.<kind>`); Fossil and SVN also offer the count without the empty first check-in |
| an app with its own JSON hash manifest (`splunkbase.manifest`: a list of `{path, hash}`): how many files fail it, the one file that fails, its actual and recorded hash | count, path, hex | one file fails (three changed files are `None` for "which file") |
| remote URL, current branch | from `config`, `HEAD` | exactly one |
| the leaked secret of a named kind (AWS key id, GitHub token, Slack, Telegram, JWT, flag) | the value | one distinct value in the whole delivery |
| "the secret" with no kind, a password | the value | never: unsure |
| a JWT's algorithm, subject, issuer, audience | the claim | one JWT |
| command of the postinstall / preinstall / install hook; which lifecycle script; which file it runs | verbatim | one such hook in the delivery (a command read out of `setup.py` is unsure) |
| URL in an install hook, a `.pth`, a workflow | URL | never: unsure `url`, `no_query`, `origin`; the **host** is plain |
| wheel: the file that fails RECORD, its actual SHA-256, the recorded hash, how many fail, the file RECORD does not list | path, hex, count | path: the syntax settles base name or path; actual hash: hex; recorded hash: unsure `record_b64`, `hex` |
| `.pth`: file name, the line it executes | name, line | the line is unsure |
| package name, version, entry file, jar Main-Class, extension id | the value | one package of the named kind |
| workflow: trigger, the one `run` command, the action used, the secret used | the value | trigger and a one-line command; the others unsure |

Never answered: kinds `mitre_attack_id`, `json`, `ordered_tokens`; a count that is not a bare
count of one kind of thing ("commits by Mallory", "commits on the dev branch", "branches with
more than one commit", any integer question that is not a count); a question with a word that
picks among several commits (last, second, before, after, modified), that names a branch or tag
other than the checked-out one, or that is after another object of the commit (its tree, a
blob, a file's hash, a size); a fact about a secret that is not its value (region, variable
name, how many); a package's author, the package it imitates, a dependency's or lock file's
version, what an install script goes on to do (exfiltrate, steal, port); anything with two
candidates; any question carrying a scripted judge set's marks (`dNN_` ids,
`-role`/`-attack` ids, `message`, `ANS-`, `Determine x.y for`); darcs, Fossil and SVN-dump
histories never plain (the darcs and Fossil readers were checked on one real repository each on
2026-10-08, against the repository's own inventory and event table; the SVN reader on none).

## Label vocabulary to expect (event style: lowercase snake_case, descriptive)

Nothing in this category is confirmed yet. Likely enum and label names, to offer through
`labels.pick` and never as plain answers:

- lifecycle and hook names: `preinstall`, `install`, `postinstall`, `prepare`, `post_install`,
  `install_script`, `setup_py`, `cmdclass_install`, `pth_import`, `extconf`, `init_ps1`,
  `msbuild_exec`, `background_service_worker`, `content_script`, `activation_event`
- supply-chain technique names: `typosquatting`, `dependency_confusion`, `malicious_postinstall`,
  `install_script_abuse`, `compromised_maintainer`, `protestware`, `starjacking`,
  `tampered_record`, `record_mismatch`, `unpinned_action`, `script_injection`,
  `pull_request_target`, `exfiltration`, `credential_theft`
- repository findings: `leaked_secret`, `hardcoded_credential`, `secret_in_history`,
  `deleted_file`, `dangling_blob`, `dangling_commit`, `unreachable_commit`, `stash`, `reflog`,
  `force_push`, `amended_commit`, `orphan_branch`, `git_hook`, `fsmonitor`
- secret kinds as this module names them (list above); other likely spellings:
  `aws_access_key`, `github_pat`, `slack_bot_token`, `telegram_token`, `jwt_token`,
  `ssh_private_key`, `rsa_private_key`
- ATT&CK ids often asked with this material (always through `pick` or the question's own list):
  `T1195.001` (dependencies and development tools), `T1195.002` (software supply chain),
  `T1552.001` (credentials in files), `T1059` family for what a hook runs, `T1546.016`
  (installer packages), `T1176` (browser extensions), `T1567` (exfiltration over web service)

Keys this toolkit uses: `repo_supply_chain.<field>/<shape>`, for example
`repo_supply_chain.commit_id/git`, `.path/deleted_file`, `.date/git`, `.count/commits`,
`.secret/unnamed`, `.url/install_hook`, `.record_hash/recorded`, `.pth/line`. The prefix is
registered with `labels.py` when the module is loaded.

## Limits

- Caps: 64 MB per member or object, 384 MB and 40,000 members per delivery, 400,000 objects per
  repository; secrets are searched in text and in files up to 1 MB, 24 MB in all. Over a cap the
  history is marked not complete and exactly-one answers stop.
- Not read: SVN FSFS revision files and `--deltas` dumps (listed, contents not rebuilt), Mercurial
  revlog v2, bzr, CVS/RCS, Perforce, git LFS contents, encrypted zip members (use
  `tools/run.py`'s expand, which knows the passwords), `.class` bytecode, obfuscated JavaScript.
- A history rewritten in place (two commits that both add the string, one on a branch and one
  only in the reflog) has two candidates and gets `None`: read the triage and decide by hand.
- Heavy tools (jadx, a real `git` in the sandbox) are not on this path. If one is needed, run it
  through `tools/sandbox.py`, never natively.

## Real artifacts (2026-10-08, `tests/real/test_real_repo_supply_chain.py`)

Run on 15 real files and folders (the account is
`docs/toolkits/real-data.md`): the Fossil repository of Huntress 2024's "Ancient Fossil", the darcs repository
of 2025's "Darcy", the app of 2024's "Backdoored Splunk II", a real git clone with fake secrets in its history,
and packages from PyPI, npm, RubyGems, Maven Central, NuGet, Open VSX and the Chrome Web Store. The slowest
is 0.5 s (the darcs folder, 1,419 files). What the real files changed:

- **Empty members are files.** Python keeps one object for `b""`, so the once-per-file pass dropped every empty
  member but the first; a real wheel (setuptools: four empty `__init__.py`) then showed three files "missing"
  from RECORD. Empty and one-byte members are told apart by name.
- **A secret in a commit message names its commit**, whatever the verb ("which patch holds the flag"): Darcy's
  flag is a patch name. A secret in a file still needs the question to say added or removed.
- **`UNUSUAL MESSAGE <id> ...`**: in a history where a dozen or more commits share one message shape, the commits
  whose shape is unique (both challenges hide one commit among 400 generated ones). A line for the reader only.
- **The table says when it is cut** (`... 202 more commits not shown`); it was silently 200 rows.
- **`hash_manifest`** package kind, lines `MANIFEST <file> rows=.. mismatched=..` and `MANIFEST MISMATCH <path>`.
- **A flag syntax** such as `flag{32 lowercase hex characters}` no longer refuses the flag itself.
- **A store extension's name** `__MSG_extName__` is resolved through `_locales/<default_locale>/messages.json`
  (`name_in_manifest` keeps the key); **a lone workflow file** (top-level `on` and `jobs`) is read without its folder.

Checked and found right as built: git packs, refs and a remote-only branch against the GitHub API's commit
list; the CRX3 extension id against the store id; RECORD hash by hash; npm lifecycle scripts; a `.pth` line.
Still not done: a jar without Maven coordinates or an Implementation-Title has no name (`None`); URLs out of
minified extension code are noise (unsure only); placeholders such as `password = "password"` in a source
tree's tests are listed as secrets (more candidates, so more `None`, never a wrong plain).
