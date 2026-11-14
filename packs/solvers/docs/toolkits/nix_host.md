# Toolkit `nix_host`: Linux and macOS host forensics

Offline, standard library only, no process started (measured: 11,000 log lines 0.09 s, 111,000 lines 1.3 s).

| File | What it is |
| --- | --- |
| `solvers/toolkits/nix_host.py` | `signals`, `solve_set` (the runner contract), `persistence_rows`, the triage command |
| `solvers/common/nix_host.py` | the readers, importable by hand |
| `tests/test_tk_nix_host.py`, `tests/fixtures/tk_nix_host/` | 200+ checks; synthetic fixtures and their generator |

## Run first

```bash
.venv/bin/python tools/unpack.py <attempt dir>                       # members/ for reading
.venv/bin/python solvers/toolkits/nix_host.py <attempt dir>/members  # every file by its bytes, the facts, the anomalies
.venv/bin/python solvers/toolkits/nix_host.py --json <file>...       # the same as JSON
.venv/bin/python solvers/toolkits/nix_host.py --persistence <dir>    # cron, systemd, launchd, preload, keys, uid 0
```

The triage prints, per log, each source's failed and accepted counts, `FAILURES THEN SUCCESS from <ip>`, sudo
commands, new accounts, auditd commands with hex decoded and any base64 inside them, wtmp logins, `ANOMALY`
lines for passwd, shadow and ld.so.preload, and `NOTE` lines for a launchd job that looks wrong. Reason to the
flag from its output, then submit it once via `ctf.submit.guarded_submit(...)` (or `./csctf submit <id> <flag>`);
an OSINT/templated answer uses `allow_nonstandard=True`.

## What it reads

- **Linux.** auth.log, secure, syslog, messages (RFC 3164, RFC 5424, ISO stamps); journald JSON; Docker
  json-file logs; auditd (`type=... msg=audit(sec.ms:serial)`, hex arguments, PROCTITLE, `msg='...'`, SOCKADDR);
  utmp, wtmp, btmp (384-byte records); lastlog; crontabs; systemd units; passwd, shadow, group;
  authorized_keys (with the `ssh-keygen -l` fingerprint); ld.so.preload; bash and zsh history.
- **macOS.** XML and binary plists, NSKeyedArchiver unwrapped (both reference forms); LaunchAgents and
  LaunchDaemons; `QuarantineEventsV2` and `TCC.db` (sqlite3 in memory, a WAL-mode header included);
  unified-log ndjson with a filter; `.DS_Store` names.
- A file is recognised by its bytes; its name only tells a system crontab (`etc/crontab`, `cron.d/`) from a
  user's, a LaunchAgent from a LaunchDaemon, `lastlog`, `ld.so.preload` and a history file.
- gzip, bzip2, xz and tar members are unpacked (`solvers/common/triage.py`). Not read: binary journald files,
  macOS `.tracev3`, ASL, `utmpx`, 32-bit utmp, EVTX.

## Question shapes it answers

| Asked | Plain when | Otherwise |
| --- | --- | --- |
| Attacker IP | the question asks for the attack's source and exactly one source has failures and then a success, and no other source failed as often (an administrator's one typo beside another address's hundred failures names nobody); or it states a rule ("most failed logins", "logged in as alice") that one source meets | `None` (two sources, a tie, no success, or the address asked is a destination, C2 or the victim) |
| Count of failed or successful logins (by source, by user, distinct sources or users) | every reading gives one number | unsure `count/ssh.repeated` when `message repeated N times` lines make lines and events differ; `None` when btmp and the log both hold failures |
| First or last login time, when the attack began | the question fixes the format and the proven parts can write it | unsure `time/<source>`, the text as written first; `None` when the format needs a year the artifact does not prove |
| Account added with uid 0, new account, its uid, shell, home, group | one such account in passwd and the useradd lines together | `None` |
| Compromised user, sudo command | one distinct value for the attacker's source or the named user | `None` |
| Decoded command (auditd) | one EXECVE event left after the question's pid, key, uid, exe; EXECVE and PROCTITLE agree | unsure `command/audit.execve_vs_proctitle` when they differ; the base64 payload only when the question asks for the payload |
| Cron schedule, command, user | one job (or the one whose command the question names) | unsure `schedule/crontab.spacing` for odd spacing, `cron_command/crontab.form` when the path does not say system or user crontab |
| Unit `ExecStart`, `User`, `WantedBy`, `OnCalendar`, any directive named | one unit, one value | unsure `exec/unit.prefix` for a leading `-`, `@`, `+`, `!`; `exec/unit.path` when a path is asked and the line has arguments |
| Plist program path, Label, StartInterval, any key named | one launchd job (or the one the question names by label, file, or "runs at load") | unsure `path/plist.program` when `Program` and the first argument differ, `bool/plist.<key>` for a boolean, `list/plist.programarguments` |
| Quarantine URL, origin, agent, time; TCC client for a service; ld.so.preload library; decoded history payload | one row, one value | `None` |

Hardened by the adversarial review of 2026-10-08 (each was a wrong plain answer before): a count is `None` when
two files hold the same event (a copy of the log, a journald export, utmp beside wtmp); a command sudo refused
(`NOT in sudoers`, `incorrect password attempts`, `command not allowed`) is not a command that was run; "which
script" or "what payload" of a job that starts an interpreter with arguments is unsure (`command/plist.payload`,
`exec/unit.payload`: the whole line, the arguments, the interpreter), and "which program" of such a unit is
`exec/unit.path`; a log longer than the readers' 400,000 lines or a database of 20,000 rows or more is not read
at all, so the whole set is `None`.

Everything else is `None`, and so is every scripted judge question (`dNN_` ids, `-role`, `message`,
`ANS-`, `Determine x.y for`), a `json`, `ordered_tokens` or `mitre_attack_id` answer, and the whole set when a
text file is larger than 32 MiB (exactly-one cannot be shown). On deliveries that are not host forensics it answers
`None` and its signal is 0.0.

## The year of a syslog line

RFC 3164 stamps (`Oct  8 03:14:27`) have no year and no zone. A time from one is unsure, and no option carries
a year, unless another artifact of the same delivery holds the very same event within two seconds: a wtmp
login or btmp failure of the same user from the same address as an sshd `Accepted` or `Failed` line, an auditd
`USER_LOGIN` or `USER_AUTH` record of sshd from that address, or a journald entry with the same process id and
message. The same second alone proves nothing (a busy host has a record in every second, and a log in local
time then reads as UTC). The file must also match better read as UTC than under any other zone offset, so
logins that repeat on the hour prove nothing. That proves the year and that the log is UTC, for that line and
for the lines around it in the same file as long as the stamps never step back (a new year is not crossed)
and no silence in between is longer than 31 days. The triage says
`year 2026 PROVEN (and UTC) for N of M records`. A tar member's mtime, the file name and the question's own
text are not proof.

## Label vocabularies likely here (snake_case first)

Nothing of this category has been confirmed. The toolkit answers facts; these names are an agent's starting
list for `labels.pick('nix_host.<field>/<shape>', [...])` to read with `labels.show(...)`.

- Technique: `brute_force`, `password_guessing`, `password_spraying`, `credential_stuffing`, `valid_accounts`,
  `ssh_brute_force` (T1110, T1110.001, T1110.003, T1078, T1021.004).
- Persistence: `cron`, `cron_job`, `crontab`, `systemd_service`, `systemd_timer`, `launch_agent`,
  `launch_daemon`, `ld_preload`, `ssh_authorized_keys`, `local_account`, `bashrc`, `rc_local`
  (T1053.003, T1543.002, T1053.006, T1543.001, T1543.004, T1574.006, T1098.004, T1136.001, T1546.004,
  T1037.004). `solvers/toolkits/edr_persistence.py` owns the technique table; `persistence_rows(files)` here
  returns rows in its shape with `technique` left `None`.
- Log source: `auth_log`, `secure_log`, `syslog`, `audit_log`, `journald`, `wtmp`, `btmp`, `lastlog`,
  `unified_log`, `bash_history`.
- Event: `failed_password`, `accepted_password`, `accepted_publickey`, `invalid_user`, `session_opened`,
  `sudo_command`, `user_added`, `password_changed`, `execve`, `proctitle`.
- Time spellings offered, in order: `raw`, `raw_single_space`, `iso_z`, `iso_space_utc`, `iso_space`,
  `iso_offset`, `iso_t`, `epoch`, `hms`.
- macOS: `quarantine_event`, `tcc_grant`, `full_disk_access`, `run_at_load`, `keep_alive`, `login_item`.

## By hand

```python
import sys; sys.path.insert(0, "solvers/common"); import nix_host as nh
recs = nh.parse_syslog(open("auth.log").read()); ev = nh.ssh_events(recs)
nh.ssh_summary(ev); nh.fail_then_success(ev); nh.sudo_events(recs); nh.account_events(recs)
[nh.audit_exec(e) for e in nh.audit_events(nh.parse_audit(open("audit.log").read()))]
nh.decode_layers(cmd); nh.innermost(cmd); nh.decode_saddr("0200005086336409...")
nh.parse_utmp(open("wtmp", "rb").read()); nh.parse_crontab(text, system=True); nh.parse_unit(text)
nh.launchd_job(nh.load_plist(data), "Library/LaunchDaemons/x.plist"); nh.ds_store_names(data)
nh.quarantine_events(db_bytes); nh.tcc_access(db_bytes); nh.filter_unified(nh.parse_unified_log(text), process="sudo")
```

## Limits to know

- "Attacker" is decided by sshd lines only. A brute force of another service (su, ftp, a web login) is not
  read; `sshd` lines forged by another program (`logger`) are ignored because the tag is checked.
- The rule runs per file: failures in `auth.log.1` and the success in `auth.log` name nobody.
- A count of zero is never answered.
- An unsure key works only in a process that loaded the toolkit (it registers the `nix_host` prefix in
  `labels.LANE_DIRS`); `labels.py promote nix_host` needs the entry in `labels.py` itself.

## Real artifacts (2026-10-08)

Run on real sshd, secure and messages logs, auditd, utmp, sudo, history, plists, TCC and quarantine files:
`tests/real/test_real_nix_host.py`, details in [real-data.md](real-data.md).

- sshd under the old PAM tag `sshd(pam_unix)[pid]` is read (`authentication failure; ... rhost=`). Such a log names
  many sources by host name, so "most failed logins" and counts of addresses are None there.
- `journalctl -o export` is read (text fields; an entry with a binary field keeps `binary`).
- sudo lines with no `TTY=` are read; `(command continued)` marks the command before it as cut (no command answer);
  a user sudo refused is still a named user and ran nothing.
- A user the log does not hold (`logged in as drewr`) gives None.
- `How many addresses attempted to log in` counts failed, accepted and invalid-user sources, addresses only.
- A stamped history command that runs over several lines is one command.
- A launchd job's `UserName` answers "which user"; its persistence row names `Program` before the argv.
- Not read: a utmp file whose size is not a multiple of 384 bytes.
- Review (2026-10-08): `second most`, `fewest`, `not`, `except`, `other than` give None in the login and sudo
  handlers; `tried the most usernames` is None; `failed to log in as X` is X's failures; a question that names a user
  and asks for a user is None; sudo's directory, terminal or time is not answered with its command.
