# Toolkit `windows`: Windows host forensics (backlog row 86)

`solvers/toolkits/windows.py`. Offline, pure Python, no process started, no sandbox needed. Tests:
`.venv/bin/python tests/test_tk_windows.py` (synthetic fixtures built in the test).

## Run first

```bash
.venv/bin/python solvers/toolkits/windows.py workspace/<id>/members        # or files, or the zip
.venv/bin/python solvers/toolkits/windows.py --persistence <files>                 # only the autostart summary
.venv/bin/python solvers/toolkits/windows.py --json <files> > scratch/windows.json
.venv/bin/python solvers/toolkits/windows.py --ask 'How many events with event ID 4625 are in the log?' <files>
```

The triage names every file by its bytes, prints its facts, then the persistence summary
(`mechanism technique name command where time source !why`). Files it does not read are listed last.
`--ask` runs one question through `solve_set`: a plain line is a proven answer, a `??{...}` line is
unsure (the options are in it), `None` means no proven fact.

## What it reads

| Artifact | By | Reader | Facts |
| --- | --- | --- | --- |
| `.evtx` | `ElfFile` | `evtx_events` (pyevtx-rs when `evtx_rs()` finds it, else python-evtx) | every record as `{id, provider, channel, computer, time, record, data{}}`; `script_blocks` joins 4104; `evtx_slack` recovers records a cleared log still holds |
| Event XML / JSON / JSONL / CSV | content | `xml_events`, `json_events`, `csv_events` | the same event shape (wevtutil, winlogbeat, EvtxECmd, raw) |
| Registry hive | `regf` | `Hive` (own reader; `hive_regipy` for regipy) | `run_keys`, `services`, `winlogon`, `ifeo`, `appinit`, `userassist`, `shimcache`, `amcache`, `system_info`, `sam_users`, `usbstor`, `run_mru`, `typed_paths`, `shellbags` |
| `.reg` export | header line | `RegText` | the same functions (`HKLM\SYSTEM\CurrentControlSet` and `ControlSet00N` both resolve) |
| Prefetch | `SCCA`, `MAM` | `prefetch` | name, hash, run count, up to 8 run times, loaded files, volume serial and time; versions 17/23/26/30/31 |
| Shortcut | LNK CLSID | `lnk` | target, arguments, working dir, description, three header times, size, volume serial, machine id, MAC |
| Task XML | `<Task` | `task_xml` | URI, author, date, principal, run level, triggers, actions |
| `$I` file | version 1/2 | `recycle_i` | original path, size, deletion time |
| `$MFT` / one record | `FILE` | `mft_records` | name, path, `$SI` and `$FN` times, `timestomp_hint`, resident data, named streams (Zone.Identifier) |
| `$J` extract | name | `usn_records` | version 2 records: name, reasons, time |
| OBJECTS.DATA / MOF, Notepad TabState | name | `wmi_hints`, `tabstate` | strings for a reader; never an answer |

All readers take bytes: `W.prefetch(open(p,'rb').read())`. Times are `Stamp` (a FILETIME integer;
`.iso()`, `.dt`), never rounded.

## Question shapes `solve_set` answers

- Counts: "How many events with event ID 4625 ...", "How many 4624 events have logon type 10",
  "How many distinct TargetUserName values in event 4625", "How many events are in Security.evtx".
- A named field of a named event: "In event 4720, what is the TargetUserName?" The field is found by
  its own Data name; a value the question quotes (a user, an address, a file name) narrows the events.
- Concepts (always unsure): the source IP of the failed logons, the account that was created, the
  service that was installed, the queried domain, the dropped file, the parent process, first/last/most.
- Registry: a key path in the question plus a value name ("the Start value under HKLM\\SYSTEM\\...");
  how many values or subkeys; a key's last write time; computer name, time zone, product; a named
  service's image path; UserAssist, shimcache and Amcache for a named program; Run dialog; IFEO debugger.
- Prefetch, shortcut, task, `$I`, MFT fields by words ("run count", "last run", "target path",
  "arguments", "machine ID", "author", "original path", "$FILE_NAME creation time", "timestomped").
- The Metadata style: `Determine <type>.<property> for <file>` with type `evtx`, `lnk`, `prefetch`,
  `registry`, `task`, `recycle`, `mft` (`prefetch.run_count`, `lnk.target_path`, `evtx.record_count`,
  `evtx.event_4625_count`). An exact field name is proven; a near match is unsure; an unknown one None.
- Persistence: "what persistence mechanism", "which ATT&CK technique", "what does it launch", when
  exactly one autostart is found (or exactly one that `why_suspicious` flags). Always unsure.

## Plain, unsure, None

- Plain: a count or number, true/false among the accepted values, and a text or time that the
  question's own contract settles (a `pattern`, `accepted_values`, "lowercase", "base filename",
  "0x prefix", a `YYYY-MM-DDTHH:MM:SSZ` template, case ignored), all only for a fact named in so many words.
- Unsure: `labels.pick('windows.<type>/<artifact>.<field>', options)`; the option names are methods, so
  one accepted name answers every id of the key on the next variant:
  - text and paths: `raw`, `unquoted`, `lower`, `basename`, `basename_lower`
  - times (UTC): `iso_z`, `iso_7_z`, `iso_micro_z`, `iso_ms_z`, `space`, `iso`, `iso_offset`, `space_utc`, `epoch`, `filetime`, `date`
  - hex numbers: `upper`, `dashed` (volume serial), `lower`, `0x_lower`, `0x_upper`, `decimal`; registry numbers: `decimal`, `0x_8`, `0x`
  - lists: `json`, `arrow` (`a>b`), `comma`, `comma_space`
- Since the review (`day9/tk-windows-r`) a plain answer also needs every word of the question accounted
  for: a neutral word, a word of the asked field's vocabulary, a name, path, id or value the answer used, or
  a format instruction. One word left over ("before", "parent", "not", "per", "malicious", another program's
  name) makes it unsure. Never plain: a boolean without `accepted_values` or a `pattern` (options `lower`,
  `title`, `yes_no`, `digit`), the timestomp hint, a zero count of events, a count narrowed by a value found in
  some field, a count over two event ids, a time with a sub-second part under a whole-second template, a
  HKCU path on a hive of unknown kind.
- An unproven fact (a concept, a leftover word) is keyed `windows.<type>/<artifact>.<field>@<answer id>`:
  a confirmed name for one question never answers another question plain. A proven fact with an unjudged
  format keeps the shared key.
- A timed set has 2.5 s in all (`SET_TIMED`), 1.2 s of it for `.evtx` (about 30,000 records a second through
  pyevtx-rs, about 500 through python-evtx): what is not answered by then is None, and a delivery not read
  whole in that time answers nothing.
- None: two different values, a log not read to its end, a text export longer than 32 MB (read in part),
  a HKCU path when only a machine hive was delivered (and HKLM on NTUSER.DAT), a count with a time condition, a file hash
  (that is `solvers/common/triage.py`'s), another category's ids (`message`, `answer`, `dNN_`, `-role`, `-attack`).

`labels.py` refuses the `windows.` prefix today. Until `LANE_DIRS` has it, an unsure answer is a
well-formed `??` string of ranked candidate values: read the options with `labels.show` and decide by hand.

## Label vocabularies likely in this event's style (unjudged, offered through `pick`)

- Persistence mechanism: `registry_run_key`, `run_key`, `windows_service`, `service`, `scheduled_task`,
  `wmi_event_subscription`, `winlogon_helper`, `ifeo_debugger`, `appinit_dll`, `startup_folder`, `local_account`.
- ATT&CK: T1547.001 (Run key, Startup folder), T1543.003 (service), T1053.005 (scheduled task),
  T1546.003 (WMI subscription), T1547.004 (Winlogon), T1546.012 (IFEO), T1546.010 (AppInit),
  T1136.001 (local account), T1070.001 (log cleared), T1059.001 (PowerShell), T1110 (failed logons),
  T1021.001 (RDP, logon type 10), T1070.006 (timestomp), T1204.002 (LNK).
- Event names (`EVENT_NAMES`, `SYSMON_NAMES`): `logon_success`, `logon_failure`, `process_creation`,
  `service_installed`, `scheduled_task_created`, `account_created`, `audit_log_cleared`,
  `powershell_script_block`, `sysmon_network_connection`, `sysmon_file_created`, `sysmon_registry_value_set`, `sysmon_dns_query`.
- Logon types: `2` interactive, `3` network, `4` batch, `5` service, `7` unlock, `10` remote_interactive, `11` cached_interactive.
- Artifact kinds: `evtx`, `registry_hive`, `prefetch`, `lnk`/`shortcut`, `scheduled_task`, `recycle_bin`, `mft`, `usn_journal`.

## Limits to know

- Event logs are read through pyevtx-rs (a Rust parser) when it is installed in `.venv/lib/huntress-side/`
  (see "Real artifacts" below): a real 5.3 MB Sysmon log of 2,850 records in 0.08 s. Without it python-evtx
  reads the same log in 5 s (NOTE: over 2 s on a file under 20 MB), and a timed set that reads logs for at
  most `EVTX_TIMED` (1.2 s) answers nothing that needs all of a log it did not finish. Untimed: 25 s.
  `CTF_EVTX=python` forces python-evtx.
- Shimcache: Windows 10/11, 8.0, 8.1 and 7 layouts; XP and 2003 are not read. Shellbags give folder
  names only. An MFT record's `timestomp_hint` is a hint (`$SI` created before `$FN`, or zero sub-seconds).
- Prefetch `run_count` is None for a version 30/31 layout whose metrics offset is neither 0x130 nor 0x128.
- A task's `Date` and `StartBoundary` are local times with no zone: they stay text, never a UTC time.
- Not read: `.evt` (XP logs), ESE databases (SRUM, WebCache), Jump Lists, `.job` files, BITS, hibernation.
  For those, strings and `tools/sandbox.py` (binwalk, 7z, vol) are the fallback.
- As a live fix, a solver can import this file by path and call a reader directly.

## Real artifacts (2026-10-08): what real evidence changed

Tested on 174 real artifacts (`tests/real/test_real_windows.py`; sources in `docs/toolkits/real-data.md`): five
Huntress CTF challenges, python-evtx's and EVTX-ATTACK-SAMPLES' logs, regipy's hives, Eric Zimmerman's prefetch
files, LnkParse3's shortcuts, a 13 MB `$MFT`.

- **Two event-log parsers.** `evtx_rs()` loads pyevtx-rs from `<venv>/lib/huntress-side` and `evtx_events` uses
  it first: sixty times faster, and its values are Windows' own (`0x3e7`, `true`, binary as hex, one `Data` per
  string) where python-evtx writes `0x00000000000003e7`, `True`, base64 and one `Data` of `<string>` items, and
  rounds times through a float (up to 2 microseconds off). Both paths now give `0x3e7`, `{guid}` in braces and
  lowercase, and the record header's exact FILETIME where it is the event's time (`iso_7_z` is then right to the
  100 ns). The fallback still differs in the rest (compared value by value on 9,657 real events in the review):
  `True` for `true`, base64 for hex in `Binary`, `2016-07-08 18:16:31.108103+00:00` for a FILETIME inside the
  event data, and a System time up to 1 microsecond off where the record header's time is not the event's. The
  hex rule rewrites python-evtx's own lowercase padding only: a provider's string such as Sysmon's
  `0x00007FFB6C2E0000` and everything pyevtx-rs rendered are kept as written. Install, once:
  `uv pip install --python .venv/bin/python --target .venv/lib/huntress-side evtx==0.13.1`. **Never install
  `evtx` into site-packages**: on this Mac's case-insensitive disk its package folder `evtx` is python-evtx's
  `Evtx`, and the install overwrites it.
- **A cleared log keeps its records.** `evtx_slack` reads the records still in a chunk past what its header owns
  (a real cleared Application.evtx: 0 owned, 61 recovered). They are listed apart (`slack_note`, `slack`), never
  counted as the log's; a count over such a log offers both numbers, unsure.
- **`findings(arts)`**, printed as `== findings`: flag-shaped texts (in event values, in their base64 readings,
  in decoded hive names, in Recycle Bin sizes read as characters), Sysmon 15 stream contents with their
  decoding, `net user NAME PASSWORD /add` command lines, and for eight or more `$I` files their sizes as text in
  deletion order. Questions: "the flag" (the only one found, else None), "the content of the alternate data
  stream", "the password given to the created user" (None when two passwords were tried). Always unsure.
- `recent_docs(view)` (Explorer\RecentDocs with MRUListEx order) and `encoded_names(view)` (UserAssist,
  RecentDocs, Run dialog and typed-path names that decode under base64, base32, hex, base58 or base62).
- Files with the same bytes and different names are different artifacts (117 `$I` files had 39 contents).
- Shortcuts as the shell reads them: the item list is walked to its terminator and names the target when
  there is no LinkInfo (`id_list_path`, UTF-16 short names too); NAME, RELATIVE_PATH and WORKING_DIR stop at
  260 characters whatever the count says (a padded link hid its arguments behind a count of 1,693).
- No Amcache rows from a hive that is not Amcache; a log's own file name is not "a value the question
  quotes"; "how many events are in Sysmon.evtx" is the total when every event is Sysmon's; a count of distinct
  values is unsure when an empty value or `-` is among them.

### Review of the real-artifact work (2026-10-08, `tests/real/test_review_a.py`)

- `findings()` reads every value of every event (about 30,000 events a second). It is now read only for a
  question that asks for a flag, a created account's password or a stream's content, kept per group of
  artifacts, and stopped by a timed set's clock (no finding, no answer). Before, every question ran it, and two
  logs asked about in turn ran it again each time: twelve plain questions over two large logs took 9 s.
- A question ABOUT the thing gets no answer from those readers: which event holds the flag, how long it is, what
  is not the flag, the password's hash, which process wrote the stream.
- A log that ends inside a chunk (`evtx_cut`) is a part: no count from it is plain. It was counted as whole.
- An event log, a hive or an `$MFT` delivered a second time under another name is one artifact (its records are
  not counted twice); equal `$I`, shortcut and prefetch files under different names stay separate.
- A shortcut target read only from the item list (no LinkInfo; an item may carry only its 8.3 name) is offered,
  never plain.
- `net user NAME * /add` is no password, and every `net user` of one command line is read.
- A Rust panic inside pyevtx-rs hands the log to python-evtx instead of ending the set.
