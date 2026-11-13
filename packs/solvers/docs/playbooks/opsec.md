# Operational security playbook (CSCTF 2026)

The 2026 site lists **Operational security** as its own area. It is the *secret-exposure* lane: a
credential, key, or private fact that was supposed to stay inside an organization leaked into something
it shipped — a git history, a file's metadata, a backup tarball, a config file, a container image, a
published package. The flag is **the leaked secret itself**, or whatever that secret decrypts. Your job is
to find the exposure, not to attack a live target: everything here is **offline, static** analysis of a
delivered artifact, safe to run on the Mac. The only things that go in Docker are the usual two —
anything the challenge ships that you would otherwise *execute* (a repo's hooks, a script, a binary), and
heavy detonation. Never run a delivered repository's `git` hooks/filters on the host; our engines read the
repo as **bytes**, they never invoke the real tool against delivered data.

Run every command from the ctf-tools checkout root with `.venv/bin/python` (or `.venv/bin/python -m ctf run <engine>`), with `CTF_EVENT` set to the event slug (`events/<slug>/event.toml`). The workdir comes from `ctf.paths`: `$CTF_WORKDIR`, else `~/ctf-work/<event>`; `.venv/bin/python -m ctf workdir` prints it, and `workspace/` on this page means it.

> **No judge, no brute force.** `labels.pick` / `labels.candidates` only rank candidate readings for
> *you* (see `labels.show(...)`). You reason to **one** secret and submit it once. Never loop candidate
> flags, never sweep passwords/keys against a judge — that is flag brute-forcing, which CSCTF bans.

> **Scope.** This category reads artifacts handed to us. If a challenge instead points at an organizer
> *property* (a real domain, a GitHub org, a published package) to recon, the live-web fair-play rules from
> **osint.md** apply unchanged: only assigned targets, human pace, no mass scanning/enumeration/scraping,
> record the public URL behind every finding. Don't duplicate that pipeline here — reach for `osint.md`.

---

## Where it sits (overlap — read these too)

OpSec straddles three lanes; pick the companion playbook by what the secret *is*:

- **Crypto (`crypto.md`) — the decrypt half of a key-leak chain.** The classic archetype is
  **key-leak → decrypt**: the exposure gives you a *key*, and the flag is what it unlocks. Find the key
  here; if the final step is RSA/AES/GCM/ECDSA maths, hand the recovered key/params to the crypto
  orchestrator. The two playbooks meet at the `->` in "leaked key -> ciphertext".
- **Forensics (`forensics.md`) / Misc (`misc.md`) — the file-triage half.** A backup `.tar.gz`, a disk
  image, a memory dump, or an EXIF/metadata leak is forensics machinery; the *secret-in-it* framing is
  what makes it OpSec. Use the forensics engines to walk the container, then the secret-scanners below.
- **OSINT (`osint.md`) — organizer's-own-properties recon.** When the lead is a real handle/domain/repo
  rather than a shipped file, it is an OSINT search with OSINT scope rules. Same leads, same caution.

So: triage the artifact → extract the secret → (if it is a key) decrypt. First moves below.

---

## 1. First moves (the moment you open an OpSec challenge)

- `./csctf check <id>` — skip if a teammate already solved it. `./csctf pull <id>` → work in
  `workspace/<id>-<slug>/`; read `description`/`notes.md` for what secret is wanted ("the deploy key",
  "the DB password", "what did the committer forget to remove"). Downloaded files are **untrusted**.
- If it arrived as an archive/blob, unpack recursively first (writes `members/` beside it; handles
  zip/7z/tar/gz/base64/hex/PEM, nested):
  ```
  .venv/bin/python tools/unpack.py workspace/<id>-<slug>/
  ```
- **Identify the container**, then route:
  - a `.git/` tree, packfile, bundle, `.hg`/`.svn` dump, or a published package (npm tgz, wheel,
    `.vsix`, `.crx`, `.jar`, `.nupkg`, `.gem`) → **`repo_supply_chain.py`** (§2).
  - a photo/document/office file where the secret might be in **metadata** → `file_properties.py` /
    `osint.py` / `exiftool` (§3).
  - a tool **config** (rclone, KeePass `.kdbx`, `sops`/`age`-encrypted YAML, `ccrypt` `.cpt`,
    `.env`, `netrc`, ssh config) → the key-leak chains (§4).
  - a **backup/config tarball**, a container image (`docker save`/OCI), a Compose/K8s/Terraform file →
    `fs_walk.py` / `cloud_container.py` / `nix_host.py` (§5).

---

## 2. Secrets in git history (the signature OpSec challenge)

The exposure is almost never in the working tree HEAD — it is in a **past commit, a deleted/dangling
object, a reflog entry, or the stash**. The engine reads all of it statically.

```
.venv/bin/python solvers/toolkits/repo_supply_chain.py <repo-dir|packfile|bundle|.git|archive>... [--json] [--grep TEXT]
```

Offline, read-only, and **no `git` binary runs on the delivered repo** — hooks, config, filters and
alternates are bytes it parses, never code it executes. It reads loose objects and packfiles (OFS and
REF deltas, no `.idx` needed), bare packs, bundles, refs/packed-refs/HEAD, the **reflog**, the **stash**,
and the index (v2–v4), in both SHA-1 and SHA-256 object formats. It surfaces:

- the commit table and the **diff by path between commits** (what a later "oops, removed the secret"
  commit took back out — the secret is in the *earlier* blob);
- **every blob searched**, including **the objects no ref reaches and the dangling ones** (a
  `git reset`/`commit --amend`/force-push leaves the old object in the packfile; this is the usual hiding
  spot);
- a **secrets** reader: AWS key ids, GitHub/Slack/Telegram/npm/PyPI/Google/Stripe tokens, JWTs,
  **private-key blocks** (`-----BEGIN ... PRIVATE KEY-----`, age, ssh), and `flag{...}`, each with its
  path **and the commit that introduced it**. Use `--grep` for a known marker.

Also handles **Mercurial** revlogs, **SVN** dumps + FSFS revprops + a working-copy `wc.db`, **darcs**
patches, and **Fossil** repos — same "secret in the history" idea, other VCS.

**git-crypt / sops / age-encrypted files committed to the repo.** Finding the *ciphertext* blob is this
engine's job; **decrypting** it needs the key (§4). A `git-crypt` repo ships `.git-crypt/` with per-user
encrypted key copies and a `.gitattributes` `filter=git-crypt` marking which paths are encrypted — if the
symmetric key (or a GPG private key that unwraps it) also leaked (common: in another commit, a dotfile, or
an attached keyring), unlock with the installed `git-crypt` binary:
```
git-crypt unlock /path/to/leaked-key    # run in a throwaway clone; the key came from the delivery
```
A file encrypted with **sops** carries `sops:` metadata naming its `age`/`pgp`/KMS recipients; decrypt
once you have the matching `age`/GPG private key (§4). **Never fetch a KMS key or touch anything live** —
only keys present in the delivery.

---

## 3. Secrets in file metadata / EXIF

The leak is a field most tools never print: EXIF/maker-notes, XMP, a PNG text chunk, PDF `/Info`, OOXML
`core.xml`/`app.xml`, an author/host/path string, GPS, or embedded thumbnails/revisions.

```
.venv/bin/python solvers/metadata-forensics/file_properties.py <file>...     # all format metadata
.venv/bin/python solvers/toolkits/osint.py <file>...                         # ranked leads incl. EXIF/doc props
python3 tools/sandbox.py run --in photo.jpg exiftool -a -G1 {in}             # exhaustive, in Docker
```
`osint.py` reads EXIF device+GPS, PDF `/Info`, PNG text chunks, XMP packets, and OOXML
`dc:creator`/`lastModifiedBy`/`Company`/`Manager` (see **osint.md** for the full lead table — don't
duplicate it). For OpSec specifically, watch for **credentials or internal hostnames/paths/usernames**
hiding in `Software`, `Comment`, `Producer`, `Keywords`, author strings, or a PDF's **prior revisions**
(`solvers/toolkits/pdf_revisions.py` recovers edited-out earlier content). Office docs can carry a leaked
UNC path or template URL in `app.xml`. For a photo, check whether GPS or an embedded original (a thumbnail
that wasn't re-rendered after a crop) leaks what the visible image hid.

---

## 4. Key-leak → decrypt config chains (rclone / KeePass / ccrypt / sops / age)

The archetype: a leaked **key or passphrase** in the delivery decrypts a vault/config/blob that holds the
flag. Find the key statically; then decrypt with the installed tool. All six tools are installed by
`setup.sh`: **`sops`, `age`/`age-keygen`, `rclone`, `git-crypt`, `ccrypt`, `keepassxc-cli`**. The
`solvers/common` engines help read the formats and (for the crypto step) finish the decrypt.

| Artifact | What leaks / where to look | Decrypt with |
| --- | --- | --- |
| `rclone.conf` | remote passwords are **reversibly obscured**, not hashed — `rclone` deobscures them with its (optionally empty) config password; a custom `RCLONE_CONFIG_PASS` may itself have leaked | `rclone reveal <obscured>` / `rclone config show` |
| KeePass `.kdbx` | the master password/keyfile leaked elsewhere in the delivery (a note, a commit, a metadata field) | `keepassxc-cli show -s db.kdbx 'Entry'` (needs the password — never brute-force it) |
| `ccrypt` `.cpt` | the symmetric passphrase leaked in the delivery | `ccrypt -d -K <pass> file.cpt` |
| sops YAML/JSON (`sops:` block) | names its `age`/pgp/KMS recipients; the matching private key leaked | `SOPS_AGE_KEY_FILE=key.txt sops -d secrets.enc.yaml` |
| `age` `-----BEGIN AGE ENCRYPTED FILE-----` | the `age` X25519 identity (`AGE-SECRET-KEY-1...`) or an ssh key leaked | `age -d -i key.txt file.age` |
| `.env` / `netrc` / `.npmrc` / `.pypirc` / dotfiles | a token sitting in plaintext (often resurfaced from git history, §2) | read it; if it's itself a key, it unlocks the next layer |

Rules for this lane:
- **The key must come from the delivery.** You are chaining *leaked* material, not guessing a passphrase.
  If no key is present, the intended path is probably elsewhere (metadata §3, git history §2) — don't
  start brute-forcing the vault. `keepassxc-cli`/`ccrypt`/`age` are decrypt tools here, **not crackers**.
- **Detonate config that executes in Docker.** A `rclone.conf` is data; a shell `.env` you'd `source`, a
  pre-commit hook, or an installer script is code → run only via `tools/sandbox.py` (`--network none`).
- **The decrypt tail may be crypto.** Once you have a key and a raw ciphertext blob (not a tool-native
  vault), hand it to the crypto orchestrator:
  `.venv/bin/python solvers/toolkits/modern_crypto.py <key> <ct> --budget 20`
  (stated-key AES/DES/RC4/ChaCha/XOR decrypt, RSA with a leaked `d`/`p`/`dp`). See **crypto.md** §2.
- **Malware/packed config variant** (a secret inside an obfuscated config/loader): `malconfig.py`
  extracts validated configs, XOR keys, and decrypted sets:
  `.venv/bin/python solvers/toolkits/malconfig.py <file|folder> [--json]`.

---

## 5. Config / backup tarball & container-image triage

A "here's our backup / our deploy bundle / our container" challenge: walk it, then scan every member for
secrets (§2's secrets reader works on loose files too, via the archive path).

```
.venv/bin/python solvers/toolkits/fs_walk.py <dir|tar|zip|img>...        # filesystem/archive walk, flag & secret hunt
.venv/bin/python solvers/toolkits/nix_host.py <file|dir|tar.gz>...       # Linux/macOS host: accounts, logs, persistence, dotfiles
.venv/bin/python solvers/toolkits/cloud_container.py <file|folder>... [--find PATH] [--ask "..."]
```
- **`fs_walk.py`** — recursive walk of a directory/archive/image, carving and secret-hunting across
  members. Good for "the flag/key is somewhere in this backup".
- **`nix_host.py`** — Linux/macOS **host forensics**, offline stdlib only: `/etc/passwd`+`shadow`,
  `sudoers`, authorized_keys, shell histories (`.bash_history` with a pasted password is a classic),
  cron/systemd **persistence**, and dotfiles that stash tokens. `--persistence` for just those rows.
- **`cloud_container.py`** — AWS/GCP/Azure/K8s audit logs, **container images** (`docker save` + OCI,
  read in memory), Dockerfiles, Compose, K8s manifests, Terraform state. Classic OpSec finds: a secret
  baked into an **image layer** (an `ENV`/`ARG`/`COPY`ed `.env` that a later layer "deleted" but the
  earlier layer still carries — same idea as the git dangling-object trick), a hardcoded `AWS_SECRET`
  in Terraform state, a token in a build arg. `--find PATH` pulls a specific file out of the layers.

TLS/session secrets variant: a leaked `SSLKEYLOGFILE`, browser session blob, or keylog that decrypts a
capture is handled by `solvers/common/tls_keylog.py` (an import-only reader; the pcap side is
`solvers/toolkits/network.py`) and `solvers/toolkits/browser_session.py` — pair with a capture, see
**networking.md**/**forensics.md**.

---

## 6. Techniques → engine (quick index)

| You see… | It's a… | Here |
| --- | --- | --- |
| a `.git`/packfile/bundle, "they removed the key later" | deleted/dangling-object secret | `repo_supply_chain.py` (reflog, stash, unreachable blobs, diff-by-path) |
| `.git-crypt/`, `filter=git-crypt` in `.gitattributes` | git-crypt vault + leaked key | find ct via `repo_supply_chain.py`; `git-crypt unlock <key>` |
| `sops:` metadata block in a YAML/JSON | sops + leaked age/pgp key | `sops -d` with `SOPS_AGE_KEY_FILE` |
| `-----BEGIN AGE ENCRYPTED FILE-----` | age blob + leaked identity | `age -d -i key.txt` |
| `rclone.conf` with `pass =`/`token =` | reversibly obscured secret | `rclone reveal` / `config show` |
| `.kdbx` + a password leaked nearby | KeePass vault | `keepassxc-cli show -s` (no brute force) |
| `*.cpt` + a leaked passphrase | ccrypt blob | `ccrypt -d -K` |
| EXIF/XMP/PDF `/Info`/OOXML author field holds a cred/host | metadata leak | `file_properties.py`, `osint.py`, `exiftool` (Docker) |
| a PDF that was "redacted"/edited | prior-revision leak | `pdf_revisions.py` |
| a backup `.tar.gz`/disk image, "find the secret" | container triage | `fs_walk.py`, `nix_host.py` |
| `docker save`/OCI image, Dockerfile, tfstate | layer/IaC secret | `cloud_container.py` (`--find`) |
| `.bash_history`/dotfiles/authorized_keys | host-forensics cred | `nix_host.py --persistence` |
| leaked key + a raw ciphertext blob | key-leak → decrypt tail | `modern_crypto.py` (crypto.md) |
| the lead is a real domain/handle/org, not a file | property recon | **osint.md** (its scope rules) |

**Proof discipline (from crypto.md, applies here):** a secret is the answer only when it is *the* leaked
value the question names, or it actually decrypts the target (the vault opens, the blob parses, the flag
appears). A string that merely *looks* like a token is a lead, not the flag — confirm it unlocks or
matches before submitting.

---

## 7. Get the flag out & submit

The flag is the leaked secret, or what it decrypts, in the event format (`CSCTF{...}`, leet/CaMeL). Reason
to **one** value, submit **once**:
```
./csctf submit <id> 'CSCTF{...}'          # quote to protect the braces from the shell
```
From a solver: `ctf.submit.guarded_submit(ctfd, ch, flag, provenance="opsec: git dangling blob → age key → sops decrypt")`.
The guard dedupes, paces, skips team-solved challenges, and **stops after 3 wrong on one challenge** (then
stop and ask the player). If the answer is a non-`CSCTF{}` freeform value defined by the brief (a
fingerprint, a hostname, an account), submit with `allow_nonstandard=True`, same as OSINT.

Never loop keys/passwords against a vault, never sweep candidate flags, never touch anything outside the
delivered artifact (or, for property recon, outside the assigned, osint.md-scoped target). Record the
exposure path in `notes.md` for the write-up. Never fabricate a secret — if nothing unlocks, say so.

## Offline cloud/container posture analysis

`solvers/toolkits/cloud_security.py` accepts only local policy/config/layer artifacts. `iam` ranks
wildcards, missing resource/condition scoping, trust-policy confusion, and known privilege-escalation
combinations; `k8s` covers workload settings, service accounts, RBAC, secrets, host mounts, and
capabilities; `iac` handles Terraform and CloudFormation exposures; and `oci` reconstructs bounded
Docker/OCI layers while distinguishing current from whiteout-deleted secrets.

`metadata <aws|gcp|azure>` composes an SSRF-to-metadata-to-credential request sequence for review and
pairing with `ssrf_chains.py`; it does not make those requests. Generated metadata headers/URLs are
active payload material and may be delivered only by the player through the scope-locked client to
the one assigned target.
