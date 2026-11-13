# Linux — CSCTF 2026 playbook

The **Linux** category is a shell/service lane, not a binary lane: you connect to a box (over `nc` or
`ssh`), read a small amount of code, and reason out the one command — or the one crafted input — that
spits the flag. CSCTF's own syllabus lists it as *nc/curl, scripting, hash cracking, command
injection, regex* (2024 `Concepts.md`), and the 2024/2025 instances bear that out: `eval()`/blacklist
escapes, PyYAML unsafe-load RCE, `grep` line-filtering, SQLite/MySQL pivots, zip/shadow hash cracking,
and setuid/sudo/cron/capability privesc on a shell box. These are **high-solve, fast points** (the 2024
Linux set ran 86–110 solves; the Interview REPLs in 2025 were the most-solved in the event) and scoring
**decays as teams solve** — drive the cheap ones to the flag in the first minutes.

Almost everything here is **live-service interaction with the one target assigned to our squad**, not
offline artifact analysis. Where a challenge instead hands you a *file* to study (a shell script, an
`app/main.py`, a SQLite `.db`, a captured `/etc/shadow`), you read it statically on the host; you
**detonate an untrusted artifact only inside Docker** (`tools/sandbox.py` / the `docker/` images),
never on the Mac.

```sh
cd <ctf-tools checkout>                   # every command on this page runs from the checkout root
export CTF_EVENT=<event slug>             # the event profile, events/<slug>/event.toml
.venv/bin/python -m ctf workdir --create  # the workdir (ctf.paths): $CTF_WORKDIR, else ~/ctf-work/<event>
```

`workspace/` on this page means that workdir (`.venv/bin/python -m ctf workdir`). Files land in `workspace/<id>-<slug>/files/` (UNTRUSTED). `./csctf pull all` fetches + triages. Because
"Linux" has no triage route yet, a pulled Linux challenge currently lands in the generic/`misc` bucket —
work it from this page by hand until the alias lands (see the routing note at the end).

---

## First moves (the moment you open a Linux challenge)

1. `./csctf check <id>` — teammate already solved it? If so, skip. Never race a teammate.
2. **Read the brief for the connection method and credentials.** Linux challenges give you one of:
   - a `host port` for raw `nc` / a REPL,
   - an `ssh user@host` with a password in the brief (`ctf:ctf`, `chronos:chronos` in 2025),
   - a `curl`-able HTTP endpoint (the "Custom Request" sub-family straddles web/Linux).
3. **If a source drop ships** (`app/main.py`, `create.sh`, a `Dockerfile`, a `.db`, a `shadow` file) read
   it first — the blacklist, the password, the flag location, and the dynamic-rotation logic are all in
   the source. Static reading on the host is fine; do not *run* it.
4. **Re-read `connection_info` on every failure** — per-challenge ports change mid-event (2025 note), and
   dynamic flags rotate every 5 min on wall-clock boundaries (use `ctf.dynamic.solve_dynamic` if the
   solve spans a window; see AGENTS.md).
5. Keep the solve path in the challenge's `notes.md` as you go (needed for the write-up).

For an offline host-artifact challenge rather than a shell service, `nix_host.py` already reads auth/
audit logs, exported journald text, bash/zsh history, systemd units, plists, TCC, and unified-log NDJSON.
A raw binary `.journal` now routes to
`.venv/bin/python solvers/toolkits/artifact_depth.py journal <file> --json`; it walks bounded DATA/ENTRY
objects and never invokes `journalctl` on the host.

---

## 1. Talk to the service / script the interaction — `tools/netplay.py`

The nc/ssh REPL "answer the prompt, repeat until flag" family is what `netplay.py` exists for (it drove
the 2025 Interview-1..4 and Programming interviews). It does the networking (pwntools `remote`, stdlib
fallback, or `ssh`) and the loop; you supply the per-prompt answer or a scripted send/expect sequence.

```sh
.venv/bin/python tools/netplay.py --list                      # the handler library
.venv/bin/python tools/netplay.py <host> <port> --auto        # auto-dispatch handler by prompt
.venv/bin/python tools/netplay.py <host> <port> --handler NAME
.venv/bin/python tools/netplay.py <host> <port> --script FILE # JSON send/expect (see --help-script)
.venv/bin/python tools/netplay.py <host> <port> --ssh user    # drive an ssh REPL
```

- **Fixed-answer REPL quizzes** (2025 Interview-1..4: `whoami`, `id -u`, `cat /etc/os-release`,
  `/proc/net/*`, …) — the answers are deterministic shell output; feed them with a `--script` of
  send/expect steps, or just paste them into an interactive `ssh user@host`. Nothing here guesses: the
  service states the task, you send the one correct line, and the flag is read back out of the stream.
- **Compute-over-a-socket** (sum a CSV, repeat a char N times, country→capital) — pick or write a handler;
  the handlers parse their parameters (prefix, key, salt) out of the prompt text, so one handler covers
  every instance without editing.
- **Raw poking** when you just need to see the banner/prompt framing: `nc <host> <port>` or
  `ncat <host> <port>` (both on the host), then graduate to a `--script`.

The tool **prints** the flag; it never submits (CSCTF rule). Point it only at the **one assigned target**,
never scan or flood (`--max-rounds` is a guard, not a sweep).

## 2. Code-reading: `eval()`/blacklist escapes and PyYAML/pickle RCE

These look like exploitation but are **source-reading problems** — the whole bug is in the handful of
lines the challenge ships, and the escape is one crafted input you then send over `nc`.

- **`eval()` on socket input with a broken blacklist** (2024 *Calculator*). The classic buggy guard
  `if ("import" or "system") in expression:` only ever tests the string `"import"` (Python evaluates the
  `or` first), and a literal-`flag` block is defeated by case/`.lower()`. Read `app/main.py`, find exactly
  what's filtered, build the one bypass (`open("FLAG.txt".lower()).read()`), send it. No engine needed —
  reason from the source, send via `netplay.py`/`nc`, read the flag.
- **PyYAML unsafe `yaml.load` RCE** (2024 *Shopping list*, CVE-2020-14343). An untagged-constructor load
  deserializes `!!python/object/apply:subprocess.check_output [[...]]`; a blacklist of `os/system/pty`
  and `cat/tail/head` is bypassed with `subprocess`+`grep`
  (`!!python/object/apply:subprocess.check_output [["grep","-r","CSCTF","/"]]`). Build the payload from the
  source's blacklist, send it.
- **Recognize the serialized-blob class first** when a cookie/field/token is involved rather than a YAML
  prompt: `.venv/bin/python solvers/web/deser_detect.py <blob-or-file>` classifies bytes already in hand
  (base64/hex/gzip-peeled) as Java/PHP/Python-pickle/Ruby/.NET/Node/**YAML** — read-only, it **never**
  calls `yaml.load`/`pickle.loads`. It tells you which gadget to craft; you craft and send it by hand.
- **Shell-script source** (setuid helpers, `create.sh`, loaders) reads cleanly with
  `solvers/script-analysis/lang_sh.py` (a library, not a CLI: `answers(questions, files, ctx)` /
  `import lang_sh`) when the script is obfuscated/encoded; a plain `create.sh` you just `Read`. It
  **never runs** the script — it tokenizes and decodes the one encoded literal.

Reason to the single correct payload and submit **once** — never loop candidate inputs (brute-forcing is
banned). If the challenge ships a script/macro you must actually execute to understand, run it in the
Docker sandbox (`tools/sandbox.py`), never on the Mac.

## 3. Regex / line-filtering — `grep` (host) or `rg`

The *Extraction* sub-family (2024) is "print the one line that does **not** match the pattern." Pure host
tooling, no engine:

```sh
grep -Ev '^[A-Z]{4}[a-z]{6}\d[A-Z]\d{2}[a-zA-Z]{6}$' lines.txt   # the non-matching line
grep -Ev '^[a-fA-F0-9]{32}$' lines.txt                           # the non-MD5 line (holds "flag")
rg -v '^[a-fA-F0-9]{32}$' lines.txt                              # ripgrep, same idea, faster
```

BSD `grep` on macOS has `-E` (ERE) but **not** reliable `-P` (PCRE); use `-E`, or `rg` (installed) when
you need PCRE features. The flag is literally the odd line (or lives inside it) — no submission logic,
just read it off.

## 4. SQLite and remote MySQL/Postgres/Redis pivots

The DB lane is "find the flag row." Two shapes:

**Local SQLite file** (2024 *Lite*, and the sqlite stage of 2025 *MultiDB*). `sqlite3` is on the host:

```sh
sqlite3 mydatabase.db '.tables'
sqlite3 mydatabase.db "SELECT * FROM users WHERE password LIKE '%CSCTF%';"
```

For a richer read — deleted rows in WAL/journal/freelist, staged base64/hex cells, odd schemas — use the
in-repo engine, which goes well beyond a plain `SELECT`:

```sh
.venv/bin/python solvers/toolkits/sqlite_artifacts.py <file-or-folder>
```

**Remote DB pivot chain** (2024 *Database*: query a remote MySQL for a `secret LIKE '%CSCTF%'` row that is
re-inserted in a random row every 5 min; 2025 *MultiDB*: `pgpass → psql → redis → sqlite → mysql`):

- `psql` **is** on the host — the Postgres stage (`PGPASSFILE=.../.pgpass; psql -h 127.0.0.1 -U ops_reader
  -d chronos_ops -c "SELECT k,v FROM ops.kv;"`) runs locally against the assigned target.
- `mysql` and `redis-cli` are **not** installed on this Mac. Run those stages from the challenge's own SSH
  box (the clients are installed there — 2025 *MultiDB* is an SSH box) or via a client container in Docker
  — never point them at anything but the assigned instance.
- A flag that **rotates every 5 min** (random-row re-insert) means: script the one `SELECT`, run it inside
  a fresh window, submit immediately. Don't sweep rows — one targeted query, read the flag row, submit once.

## 5. Hash cracking — `john` (host) + its `*2john`/`unshadow` helpers

When the *cracked plaintext IS the flag/answer* (2024 *My secure password* → `manchesterunited`) or a
password gates a zip (2024 *John*), crack it **offline** with John the Ripper. `john` is on the host
(`/opt/homebrew/bin/john`); the extractor helpers ship with john-jumbo at
`/opt/homebrew/opt/john-jumbo/share/john/` (`zip2john`, `unshadow`, and the full `*2john` family).

```sh
# password-protected zip  (2024 John — note the create.sh password had a LEADING SPACE)
/opt/homebrew/opt/john-jumbo/share/john/zip2john locked.zip > zip.hash
john --wordlist=<wordlist> zip.hash
john --show zip.hash

# /etc shadow — SHA-crypt $y$ (yescrypt) / $6$ hashes  (2024 My secure password: take the longest pw)
/opt/homebrew/opt/john-jumbo/share/john/unshadow passwd shadow > unshadowed.txt
john --wordlist=<wordlist> unshadowed.txt
john --show unshadowed.txt
```

- Cracking a password hash with a wordlist is a **legitimate offline technique**, not a flag sweep — it
  runs entirely on captured material and touches no judge. `hashcat` is also installed if you want GPU/mask
  mode. John ships `password.lst`; point `--wordlist` at whatever list the challenge context implies (if a
  `create.sh` leaks the exact password, you don't even need to crack — read it, mind literal quoting such as
  a leading space).
- The recovered password/plaintext is a **lead**: submit it as the flag only when the challenge says the
  plaintext *is* the answer, and only through the guard, once.
- If the archive is untrusted and you want to *open* it (not just crack), the archive-password store
  (`tools/password.py add/check`) and the unpackers try known passwords on decrypt — but they **never guess**
  a password; they only try ones you supply.

## 6. Privilege escalation on a shell box — enumerate, don't brute

Once you have a shell (SSH as the low-priv user), the flag is usually under `/root` or a protected path and
you escalate to read it. This is interaction with the **assigned target's own shell** — standard host
utilities, no in-repo engine. Enumerate the four classic vectors (2025 *Shadow Home* and *The Box* both
hinged on these):

```sh
# setuid/setgid binaries — a root-owned helper with a naive assumption is the usual way in
find / -perm -4000 -type f 2>/dev/null
# sudo rights without a password
sudo -l
# cron jobs you can influence (writable script, PATH, wildcard)
cat /etc/crontab; ls -la /etc/cron.*; cat /var/spool/cron/crontabs/* 2>/dev/null
# file capabilities (cap_setuid, cap_dac_read_search, …)
getcap -r / 2>/dev/null
```

Recurring CSCTF setuid-helper bugs (2025):

- **Path-traversal in a setuid helper** (*Shadow Home*): the root helper validated that the resolved path
  stayed under `/srv/legal-hold` but the user-supplied case-id allowed `../../cases-archive/...`, so
  `shadowctl mount 'case-.../../../cases-archive/<target>' ~/shadow/pwn` copied a protected archive out.
  Read the helper's validation, find where it checks the wrong prefix.
- **Unqualified binary call → PATH hijack** (*The Box* `diag`): a setuid root binary that calls `iptables`
  (no absolute path) is hijacked with `echo -e '#!/bin/sh\nexec /bin/sh -p' > /tmp/iptables; chmod +x
  /tmp/iptables; PATH=/tmp:$PATH /usr/local/bin/diag` → root shell → `cat /root/flag.txt`.

Check **every setuid binary's assumptions** (traversal, PATH, argument handling). `strace`/`ltrace` on the
helper (available in the Docker pwn image if you want to trace a *copy* of the binary offline) reveals what
files/commands it touches. Escalate, read the flag file, submit once — don't fuzz or sweep.

---

## Detonation is Docker-only

Interacting with the **assigned remote** (`nc`/`ssh`/`curl`/`psql` to the squad's one target) is normal
play. But any **untrusted artifact you were given to run locally** — a shell script, an `app/main.py`, a
macro, a binary, a DB loader — is analysed statically on the host and **executed only inside Docker**
(`tools/sandbox.py`, `--network none`, read-only root; the `docker/` images carry the toolchain), never on
the Mac. Egress from challenge containers is blocked (2025) — prefer in-band reads over OOB exfil.

## Techniques → tools/engines

| Shape | Tool / engine (verified) | How you finish it |
| --- | --- | --- |
| nc/ssh REPL quiz, compute-over-socket | `tools/netplay.py` (`--auto`/`--handler`/`--script`/`--ssh`), `nc`/`ncat` | script the prompt→answer loop, read flag from stream |
| `eval()` blacklist escape | read `app/main.py`; send via `netplay.py`/`nc` | find the broken filter, craft one bypass input |
| PyYAML unsafe-load RCE | source read; `solvers/web/deser_detect.py` to classify a blob | `!!python/object/apply:subprocess...` past the blacklist |
| Obfuscated shell script source | `solvers/script-analysis/lang_sh.py` (import; no CLI) | decode the one encoded literal, read the plan |
| Regex line-filter (find the odd line) | host `grep -Ev` / `rg -v` | the non-matching line is / holds the flag |
| Local SQLite flag row | host `sqlite3`; `solvers/toolkits/sqlite_artifacts.py` (deleted rows) | `SELECT ... WHERE col LIKE '%CSCTF%'` |
| Remote DB pivot (pg→redis→sqlite→mysql) | host `psql`; `mysql`/`redis-cli` from the SSH box or Docker | walk the credential chain, query the flag row |
| Zip password crack | `.../john/zip2john` + `john` (+ `hashcat`) | crack offline, password opens the zip / is the flag |
| `/etc/shadow` crack ($y$/$6$) | `.../john/unshadow` + `john` | crack offline, take the indicated plaintext |
| setuid / sudo / cron / capabilities privesc | `find -perm -4000`, `sudo -l`, `getcap -r /`, cron files | exploit the naive assumption, read `/root/flag.txt` |

## Getting the flag out & submitting

Flags are `CSCTF{...}` (leet/CaMeL; the full pattern is the event profile's `[flag]` (`events/<slug>/event.toml`, read through `ctf.flagfmt`)) — **except** a hash-crack
challenge whose answer is the raw cracked plaintext (`manchesterunited`), which is a freeform value, so
submit it with `allow_nonstandard=True`. When an interaction or query yields the real flag, submit it
**once**:

```sh
./csctf submit <id> 'CSCTF{...}'          # routes through ctf.submit.guarded_submit
```

From a solver: `ctf.submit.guarded_submit(ctfd, ch, flag, provenance="netplay ssh REPL output")` (add
`allow_nonstandard=True` for a cracked-plaintext answer). The guard checks format, dedupes, paces, skips
team-solved, and **stops and asks after 3 wrong**. For a 5-min-rotating DB/flag, use
`ctf.dynamic.solve_dynamic(ctfd, ch, retrieve=...)` so a stale rotation isn't counted as a wrong guess.
**Never loop candidate flags or sweep rows/inputs** — reason to one value, submit one.

## Scope & safety (the hard boundary)

- Touch **only the one target assigned to our squad** — the nc/ssh/curl/DB endpoint in the brief. Never the
  platform, scoreboard, Chronos services, other squads, or an unassigned instance.
- **No brute-forcing flags, no flooding, no mass scanning.** `netplay.py`'s `--max-rounds` and the submit
  guard's pacing are caps, not licenses to sweep. Offline hash cracking with a wordlist is fine; firing
  candidate *flags* at the judge is not.
- A recovered password/credential is a **lead** used only against the assigned target, never shared outside
  the squad; never printed to logs beyond the solver.
- Untrusted artifacts: static analysis on the host, execution **only** in the Docker sandbox.
- **NEVER buy a hint** — the client blocks it; a hint is the player's call alone.
