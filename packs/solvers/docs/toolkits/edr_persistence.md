# Toolkit `edr_persistence`: exported endpoint telemetry and persistence

File: `solvers/toolkits/edr_persistence.py` (plain Python, standard library;
the script-analysis `powershell.py` is loaded by path for `-EncodedCommand`). Tests:
`.venv/bin/python tests/test_tk_edr_persistence.py`. Fixtures: `tests/fixtures/tk_edr_persistence/`.

## Run first

```bash
.venv/bin/python tools/unpack.py <attempt dir>                                  # members/ for reading
.venv/bin/python solvers/toolkits/edr_persistence.py <attempt dir>/members      # triage: a file, a folder or a zip
.venv/bin/python solvers/toolkits/edr_persistence.py --json <file> | jq .persistence
```

The triage prints: events per channel and id, hosts and the time range, the process tree, every decoded
PowerShell layer, failed logons per source with the success that followed, created users, group adds, cleared
logs, reassembled script blocks, Defender detections, and the persistence table with the ATT&CK id of each row.
`FLAGS` (encoded command, user-writable path, lolbin, url) are for your eyes only; no answer is built on them.

It answers plain only what it proves; the rest is unsure picks (a ranked candidate list you read with
`labels.show(...)`), or stays `None`. Reason to the flag from the triage output and submit it once via
`ctf.submit.guarded_submit(...)` (or `./csctf submit <id> <flag>`); an OSINT/templated answer uses `allow_nonstandard=True`.

## What it reads

| Input | Reader | Notes |
| --- | --- | --- |
| Events as JSON, JSON lines | `read_events` | winlogbeat (`winlog.event_data`), raw `Event/System/EventData`, `Get-WinEvent \| ConvertTo-Json` (`/Date()/`, `Message` lines), EvtxECmd, Elasticsearch `hits.hits[]._source` |
| Events as XML | `read_events` | `wevtutil qe` with or without a root element; `UserData` too. A `DOCTYPE` is refused |
| Events as CSV | `read_events` | any header with an event-id column (`Id`, `EventID`, `EventCode`); a `Message` column is split into `Name: value` |
| EDR process JSON | `read_events` | ECS `process.*`, flat records, nested `children`; channel `edr` |
| `.reg` text export | `persistence_from_reg` | UTF-16 or UTF-8; `hex(2)`, `hex(7)`, `dword`, continued lines |
| Autoruns CSV | `persistence_from_autoruns` | `autorunsc -c`; signer, company, hashes, enabled kept in `extra` |
| Task Scheduler XML | `parse_task_xml` | author, URI, triggers, principal, run level, Exec and ComHandler actions; also `TaskContent` of 4698 |
| WMI subscriptions | `wmi_from_text`, `wmi_from_objects_data` | MOF or PowerShell list output; `OBJECTS.DATA` is carved (binding strings; the command is unsure) |
| Startup `.lnk` | `parse_lnk` | target, arguments, working directory; `startup_folder` only when the path says Startup |
| cron, systemd, launchd | `persistence_from_cron`, `_unit`, `_plist` | `/etc/crontab` and `cron.d` have a user column; XML and binary plists |

Binary `.evtx` is not read here (backlog row 86). Every event is `{time_utc, channel, event_id, host, fields,
provider, source}`; `fget(e, "TargetUserName")` reads a field under any spelling; `chan(e)` gives `sysmon`,
`security`, `system`, `powershell`, `defender`, `edr`.

By hand:

```python
import sys; sys.path.insert(0, "solvers/toolkits"); import edr_persistence as E
ev = E.read_events(name, data)
E.summary(ev); E.select(ev, 4625); E.brute_force(ev); E.script_blocks(ev)
procs = E.processes(ev); print("\n".join(E.render_tree(procs)))
E.decode_command_line(procs[1]["command_line"])       # layers, outermost first
E.persistence({name: data})                           # rows: mechanism, location, name, command, author, trigger
```

## Question shapes it answers

Plain, under exactly-one (the events or rows left after the event id, the file and every value the question
names hold ONE distinct value; otherwise `None`):

- count of an event id or of a phrase (`failed logon`, `process creation`), also narrowed by a named address or user;
  failures before the success of the one brute force; count of Autoruns entries, of rows of a named mechanism
- parent image, command line, child image, pid, parent pid of a named process; hash when the case is stated
- Sysmon fields by phrase: DNS `QueryName`, destination IP and port, created file; any field named as recorded
  (`TargetObject`, `LogonType`, "the Image of Sysmon event ID 3")
- created user (4720) and who created it, the group it was added to, who cleared the log, logon type
- brute force: source address, compromised account, workstation
- URL, domain or address inside a decoded PowerShell command; the decoded command when it has one layer
- persistence: service name and image path, value name, key path of a `.reg` export, task command, arguments,
  author, principal, run level, Autoruns launch string, image path and company, cron schedule and command,
  `ExecStart`, a LaunchAgent's label, a WMI consumer's name, command and filter (MOF)
- a time, when `answer_format.syntax` holds a template (`YYYY-MM-DD HH:MM:SS UTC`) or its pattern leaves one form

Unsure (`labels.pick`, a ranked candidate list to read with `labels.show(...)`):

| Key | Options, best first |
| --- | --- |
| `edr_persistence.mechanism/<mechanism>` | the mechanism's spellings (below); only the listed ones when the question lists names |
| `edr_persistence.technique/<mechanism>` | sub-technique, then its parent (`T1547.001`, `T1547`) |
| `edr_persistence.trigger/<mechanism>.<trigger>` | `logon`, `at_logon`, ...; `auto_start`, `automatic`, ... |
| `edr_persistence.time/<channel>` | `raw`, `iso_z`, `iso_ms_z`, `space`, `space_ms`, `iso`, `iso_offset`, `space_utc` |
| `edr_persistence.task_name/uri` | `leaf` (`TelemetrySync`), `uri` (`\Microsoft\...\TelemetrySync`) |
| `edr_persistence.key_path/sysmon` | `key`, `target_object` (a Sysmon 13 object is key plus value) |
| `edr_persistence.parent/process`, `child/process`, `actor/process` | `image` (full path), `basename` |
| `edr_persistence.user/domain`, `host/fqdn` | `as_recorded`, `no_domain` / `short` |
| `edr_persistence.hash/case` | `lower`, `as_recorded` |
| `edr_persistence.decoded/layers` | `final`, `first` |
| `edr_persistence.command/executable.<origin>` | `command`, `executable`, `basename` |
| `edr_persistence.signer/autoruns` | `name`, `as_recorded` (`(Verified) Microsoft Windows`) |
| `edr_persistence.wmi_command/objects_data`, `wmi_filter/objects_data`, `cron_command/form` | carved or form-dependent values |

`None`, always: two candidates (two new services, three processes and none named), a named program or address
that is not in the data, two event phrases in one question, "the attacker's address" when the delivery also holds
network connections, who installed a 7045 service, a member added to a group, `json` and `ordered_tokens` kinds,
a Metadata-shaped question. Also `None` since the review of 2026-10-08: a count of zero, a count of script blocks
when one block was logged in several parts, a question about something other than the program it names ("the
child of X", "spawned by X", "the process that created X", "the file dropped by X"), a domain or host name
"connected to" (only an address is read from Sysmon 3), what a DNS query resolved to.

**A delivery that was not read whole.** `Model(files).damaged` lists `(file, why)`: a JSON line or CSV row that
is cut, event XML that does not parse, more records than `MAX_EVENTS`, a file over `MAX_FILE`, an archive whose
members were not delivered, a cut gzip, a `.reg` value with no closing quote, a shell link that ends early, a
line-read file (`.reg`, MOF, unit, crontab) with no line end after its last line. With anything in that list no
count is answered, and every other plain answer is flagged as the one-option pick `edr_persistence.incomplete/<handler>`
(`as_read`) so you read it with that caveat. A gzip export is read; the same bytes
under two names count once.

Further picks from the review: `count/failures_before_success` (`same_source`, `all_sources`), `time/<channel>.offset`
(`utc`, `as_recorded`: a time recorded with an offset, asked for with no zone), `task_user/sid` (`as_recorded`,
`well_known_name`), `trigger/<mechanism>.as_written` ("how often" answered by a schedule), `command/executable.<origin>`
for any command with arguments when a program is asked, `indicator/cut_command` and `decoded/cut_command` (a decoded
command that ends inside a quote or bracket). An `-EncodedCommand` whose base64 is not padded to four, or decodes
to an odd number of bytes, is not decoded at all.

## Mechanisms and ATT&CK

| Mechanism | Technique | Read from |
| --- | --- | --- |
| `registry_run_key` | T1547.001 | `.reg`, Sysmon 13, Autoruns Logon |
| `startup_folder` | T1547.001 | `.lnk` under Startup, Sysmon 11, Autoruns |
| `scheduled_task` | T1053.005 | task XML, 4698, Autoruns Tasks, TaskCache key |
| `windows_service` | T1543.003 | 7045, 4697, `Services\<name>` ImagePath or ServiceDll, Autoruns Services |
| `wmi_event_subscription` | T1546.003 | MOF, OBJECTS.DATA, Sysmon 19 and 20 |
| `ifeo_debugger` | T1546.012 | `Image File Execution Options\<exe>` Debugger, SilentProcessExit |
| `com_hijack` | T1546.015 | HKCU or HKU `...\CLSID\{...}\InprocServer32` |
| `cron` | T1053.003 | crontab, `cron.d` |
| `systemd_service` / `systemd_timer` | T1543.002 / T1053.006 | unit files |
| `launch_agent` / `launch_daemon` | T1543.001 / T1543.004 | plist under LaunchAgents or LaunchDaemons |
| `winlogon_helper`, `appinit_dll`, `active_setup`, `screensaver`, `logon_script` | T1547.004, T1546.010, T1547.014, T1546.002, T1037.001 | `.reg`, Sysmon 13 |

Likely label vocabulary in this event's style (lowercase snake_case, descriptive), the order the picks use:
`registry_run_key`, `run_key`; `scheduled_task`, `schtasks`; `windows_service`, `service_install`;
`wmi_event_subscription`, `wmi_subscription`; `ifeo_debugger`, `image_file_execution_options`; `com_hijack`,
`com_hijacking`; `startup_folder`, `startup_shortcut`; `cron`, `cron_job`; `systemd_service`, `systemd_unit`;
`launch_agent`, `launchagent`. Triggers: `logon`, `boot`, `daily`, `idle`, `event`, `registration`; service
starts: `auto_start`, `demand_start`, `boot_start`, `disabled`.

## When it says None and you can see the answer

- Read the triage; the fact is usually there and the question's wording was not understood. Pull the value
  out of the triage output yourself and submit it once through the guarded path.
- `-EncodedCommand` decoding needs `solvers/script-analysis/powershell.py`; without it nothing is decoded.
- Times with no zone in the export (a CSV's `2026-10-07 02:14:10`) are read as UTC and offered only as unsure.

## Real artifacts (2026-10-08)

Run on XML exports of three Huntress CTF event logs and eight OTRF NXLog JSON sets:
`tests/real/test_real_edr_persistence.py`, details in [real-data.md](real-data.md).

- Export a binary log with every chunk, not the header's count: a log copied from a live system has a stale header
  (97 of 1,249 events were all python-evtx gave for one). `tests/real/fetch_b.py` shows how.
- A program can be named by its full Windows path; a bare name that two programs share stays None.
- The process tree prints the parent of every root that names one (a web shell's `w3wp.exe`).
- A 4698 whose `TaskContent` is XML-escaped is parsed; Sysmon 19/20 values lose their ` "..."` wrapping and
  XML entities.
- `How many times was <the account> brute-forced` is the pick `count/brute_force.failed_logons`.
- A question about how a user was created (command line, process, tool) is not answered with the user's name.
- Speed: 5.6 MB of JSON events in 0.3 s; nothing over 0.4 s.
- Review (2026-10-08): a negated question is None; a count with a port, protocol or direction it was not narrowed by is
  None; a bare program name that two files carry (`svchost.exe`) gives no plain answer; an accepted connection
  (`Initiated=False`) is not what a program "connected to"; `created by cmd.exe` counts its children, and a program
  that is process and parent in a count is the pick `count/process.role`.
