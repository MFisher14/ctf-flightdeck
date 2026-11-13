# Toolkit `kape_timeline`: KAPE parsed output to one UTC timeline (B-071)

`solvers/toolkits/kape_timeline.py`. Offline, standard library only, nothing executed. Tests:
`tests/test_toolkits_kape_timeline.py` (every KAPE tree, workbook and zip is built in the test).

## Run first

```bash
python -m ctf run toolkits.kape_timeline <folder-or-zip>... --out scratch/kape
python -m ctf run toolkits.kape_timeline <folder> --ioc 'c2.example' --ioc 'tool.exe'   # which host has it
python -m ctf run toolkits.kape_timeline <folder> --start 2026-01-02T00:00Z --end 2026-01-03T00:00Z
python -m ctf run toolkits.kape_timeline <folder> --all-events --max-events 400000
```

Give it the folder that holds the collections (one per host), one collection, or the zips as they
were handed out: a zip is read in place when its files are not already unpacked beside it. Intake runs
it by itself (`[intake]`, `run = "folder"`) whenever the handout holds an `*EvtxECmd*.csv`, an
`*RECmd_Batch*.csv` or a `*Hindsight*.xlsx`; its files are then in `recon/engines/toolkits.kape_timeline/`.

The report prints, per host: the files read (rows read and kept), RunMRU in typing order, the 4104
script blocks (with secret-like assignments and URLs pulled out), the scheduled tasks that are not
under `\Microsoft\` (registration time, command, comment), the token-like URL parameters from
Hindsight, and then the highlights of all hosts in time order. `--out` adds `timeline.json` (the
`timeline.py` JSON shape: `timeline.py timeline.json --keyword x` filters it further), `timeline.csv`,
`report.json` and `scriptblocks/NNN-<host>.txt` with each block's full text.

## What it reads

| Artifact | File name | What lands on the timeline |
| --- | --- | --- |
| EvtxECmd CSV | `*EvtxECmd*.csv` | the default selection of events through `windows.json_events`; 4104 blocks joined by `windows.script_blocks`; task XML of 4698-4702 through `windows.task_xml`; `--all-events` for every row |
| RECmd batch CSV | `*RECmd*.csv` | `Explorer\RunMRU` (MRUList order; the key time belongs to the most recent entry only), and Run, RunOnce, TypedPaths, TypedURLs as one event per key; a key repeated by several batch files is one event |
| schtasks CSV | `Scheduled Tasks*.csv` | not timed by itself (its times are host-local): name, author, command and comment are tied to the task's 106 / 4698 event |
| Hindsight workbook | `*Hindsight*.xlsx` | every row of the Timeline sheet; token-like query and fragment parameters listed apart |
| PECmd, LECmd, AppCompatCache, Amcache | `*PECmd*Timeline*.csv`, `*LECmd*.csv`, `*AppCompatCache*.csv`, `*Amcache*FileEntries*.csv` | one event per time column |

Default event selection: PowerShell 4104; Security 1102, 4697-4702, 4720, 4722, 4724, 4726, 4728, 4732,
4756; System 104, 7045; TaskScheduler 106, 140, 141; Defender 1116, 1117, 5001; WMI-Activity 5861;
BITS 59; RDP 21, 25, 1149. Process creation (Security 4688, Sysmon 1) and PowerShell 4103 are kept
only inside a pivot window: `--pivot-seconds` (default 300) after a RunMRU key write on that host.

## The answer

It never answers `solved`. A value in the event flag format that stands verbatim in an artifact field
is a `candidate`. Otherwise the result is `unsure`: the highlights are evidence, and which of them are
flag fragments, and in what order, is a reader's call. Nothing is ever joined into a flag.

The result carries at most five evidence lines per highlight kind (RunMRU, script block, task, browser
token), and each line puts the values a reader looks for first: a script block's secret-like
assignments, a task's comment and command, a URL's token values. Which highlights take the slots: first
anything inside a pivot window, carrying an `--ioc`, or a task wearing a vendor updater's name over
another program (`masquerade`); then script blocks with a secret, tasks other than an unverified vendor
name, and the newest value of each token parameter (one site, path and name), then newer tokens before
older ones. The full lists stay in the report and `report.json`.

Vendor updater tasks outside `\Microsoft\` (OneDrive, Edge Update, Google Update, Firefox, Acrobat
Update) are treated like Windows' own only when the task name and the program it runs both match the
vendor's (`vendor_of`); the Author field is not trusted. A vendor name whose program is not known (no
schtasks row, no task XML) stays a highlight, tagged `vendor-unverified`; a vendor name that runs
anything else is tagged `masquerade`.

## Limits (each one is a note in the output, never a silent skip)

- A file over 1 GiB, a workbook over 128 MiB, or more than 5,000,000 rows of one export is not read
  (or read up to the limit); the timeline holds at most `--max-events` (default 200,000).
- Raw target collections (`.evtx`, hives) are counted and left to `toolkits.windows`.
- MFTECmd, SrumECmd, SBECmd and JLECmd outputs have no reader here; `--ioc` searches them line by line
  and lists the hits untimed.
- Hindsight JSONL and SQLite outputs, and the Storage and Sessions sheets of the workbook, are not read.
- schtasks writes `?` for a character outside the console code page. A CSV task name with a `?` is
  tied to an event-log task only when exactly one starts with the text before the `?`.
