# Memory forensics toolkit (`memory`, backlog row 82)

`solvers/toolkits/memory.py`. Offline. Tests: `.venv/bin/python tests/test_tk_memory.py`.

## Run first

```bash
.venv/bin/python solvers/toolkits/memory.py challenges/day-NN/<id>/members/*      # after tools/unpack.py
```

It prints, per file: size, SHA-256, the image format the bytes state (LiME, AVML, minidump, crash dump, ELF
core, hibernation file, VMware snapshot; a raw image states nothing), the header facts of that format, and then
the model it built: every process (pid, ppid, name, create time, command line, source), connection, injected
region, info value, carved environment string, Linux banner and carved command line. `CLASH(name)` on a
process means two sources name that PID differently; the solver answers nothing about that field.

It also answers the hash, size and count questions of `solvers/common/triage.py`. Reason to the flag
from its output, then submit it once via `ctf.submit.guarded_submit(...)` (or `./csctf submit <id> <flag>`);
an OSINT/templated answer uses `allow_nonstandard=True`.

## What it reads without any tool

| Delivery | Reader | Facts |
| --- | --- | --- |
| Volatility output (text, CSV, JSON, JSONL, pretty table, Volatility 2 fixed width), or a JSON snapshot with lists of processes, connections, regions | `tables_from_text`, `tables_from_json`, `Model.absorb` | pslist, pstree, psscan, cmdline, netscan, netstat, malfind, envars, getsids, info, banners, linux.pslist, psaux. Columns are found by name (`PID`, `PPID`, `ImageFileName`, `Args`, `ForeignAddr`, `Start VPN`, `Protection`, `Variable`, `Value`, `SID`, and their plain-English spellings) |
| Windows minidump (`MDMP`) | `minidump`, `md_injected` | process name and PID, create time, OS build, modules, regions with protection, private RWX regions, the command line through TEB -> PEB (x64, when the memory is in the dump) |
| ELF core, 64-bit or 32-bit, either byte order | `elf_core` | pid, ppid, uid, name and arguments (NT_PRPSINFO), mapped files (NT_FILE), segments with their permissions and file offsets, the saved registers of every thread (NT_PRSTATUS; named for x86-64, i386, aarch64 and arm, `reg0..` otherwise) |
| The heap of an ELF core | `heap_chains` | linked records carved from the heap segments: the record layout found, every rebuilt chain with its score, the registers that point at it, whether it is a flag, and the best one (see below) |
| LiME / AVML | `lime_segments` | the physical ranges and their file offsets |
| Windows crash dump | `crashdump_header` | build, processor count, bugcheck code, DTB, PsActiveProcessHead, system time |
| A whole-machine image, any wrapper, no symbols | `carve_windows_processes`, `carve_linux_tasks`, `carve_env`, `carve_banners`, `carve_cmdlines` | EPROCESS records (pid, ppid, name, create time) with the offsets calibrated on the image itself (System is PID 4 and smss.exe's parent); Linux thread-group leaders (pid, comm; systemd is 1, kthreadd 2); `COMPUTERNAME=`, `USERNAME=`, `HOSTNAME=` strings; the `Linux version` banner; UTF-16 command lines (not tied to a PID) |

Carving in `solve_set` stops at 16 MB per image; the command carves up to 512 MB.

## Heap record chains in an ELF core (B-067)

```bash
.venv/bin/python solvers/toolkits/memory.py --heap-chains <core>      # the carve alone; intake runs this on every ELF core
.venv/bin/python solvers/toolkits/memory.py <core>                    # the full triage prints the same lines
```

For the handout where the flag is a linked list of short records on the heap of a core file: `strings`
shows the fragments out of order, and decoy lists end in the real list's tail. The carve:

1. Heap segments: the rw `PT_LOAD` segments with no file behind them in `NT_FILE` (the brk heap, anonymous
   maps, the stack; not an rwx one, which is a JIT or shellcode page), plus an `NT_FILE` mapping whose
   path names a heap (`[heap]`, `[anon:heap]`, in either case). Only when there is neither, every rw
   segment (`rw-fallback`, reported as a warning).
2. Chunks: every `2*word`-aligned address of those segments is tried as a glibc chunk header. This is a
   scan, not an allocator walk: it does not step by size, so one corrupt size loses nothing after it.
   A header is kept when its size (flag bits masked) is a multiple of `2*word`, at least `4*word`, at
   most `0x8000`, and the chunk lies inside the bytes the file holds.
3. Records: five layouts are tried on each chunk's user data (`{next, len, text}`, `{len, next, text}`,
   the two with a word-sized length, `{next, text\0}`); a record needs a `next` that is 0 or points
   into a heap segment and printable text. The layout whose best chain ranks highest is kept.
4. Chains: one per record nothing points to, one per closed loop, and one from **each record a saved
   register points at**, even when a decoy record links to it. The register chain is followed
   straight through memory first, so no cap can drop it.
5. Ranking: `+1000` when the chain's first record is in the arg0 / return register (`rdi`/`rax`, `eax`,
   `x0`, `r0`), `+400` for any other register, `+100` when a register points further into the chain;
   `+5000` for a complete flag in the event's format, `+800` for a chain that begins with a flag
   prefix, `+50` for one that holds a prefix; one point per record (to 64).

Read the output like this: `RECOVERED:` is the best chain; `(flag)` means it matches the event's flag
format; `<- rax/rdi` names the registers that hold its first record. `WARNING PARTIAL carve (...)` means
a cap or the deadline cut the carve (the cap is named) and the best chain may be a decoy: rerun on the
file with `--heap-chains`, or carve by hand from the register. `WARNING no flag format (...)` means no
event resolved and the ranking used registers and length only. `N freed` on a chain counts its records
whose chunk had gone back to the unsorted, small or large bins (`PREV_INUSE` clear in the chunk after
it). It does **not** see a tcache or fastbin free, the usual way a small record is freed: that leaves the
bit set, so a chain with no `freed` count may still be made of freed records. `text cut` on a chain
means its text did not fit the text cap: the records are all there (`N nodes`), the text is not, and a
cut text is never called a flag.

Bounds: 2^24 scanned positions, 2^18 chunk candidates, 20000 records per layout, 2^21 records walked,
2^20 characters of text per chain and 2^24 for all the chains of a layout (every chain holds its own
copy of its text, so decoy heads that share a long tail would otherwise multiply it without limit). Each
is a keyword of `heap_chains` (`max_chain_text`, `max_text`, ...) for a carve by hand that needs more.
The registers' chains are carved, walked and given their text first, so a bound drops decoys before it
drops the chain the registers name.

Time: `build_model` carves heap chains last, after the process carvers, within `carve_max` (16 MB by
default) and its deadline. The deadline is looked at during the scan, during each layout's read of the
scanned chunks and before each chain start; once it has passed only the registers' chains are still
followed, and the warning says what was left. `solve_set` does not carve heap chains at all: it
answers from none of them.

Not covered: a list linked by index or offset instead of a pointer; a record whose text comes before
its link (`{text[N], next}`, `{len, text[N], next}`); a record that holds its text by pointer
(`{next, len, char *text}`); records in a non-glibc allocator's chunks; and text that is not printable
ASCII.

Tests: `tests/test_memory_heap_chains.py` (synthetic LP64 / LP32, little- and big-endian cores).

## Volatility 3 (local run)

```bash
.venv/bin/python tools/sandbox.py status
.venv/bin/python solvers/toolkits/memory.py <image> --vol windows --where venv --online   # or linux | mac | any
```

- It runs the family's plugins (`memory.PLUGINS`) with `-r json` and saves each table in a local cache keyed
  by `<size>-<sha256 of the whole image>` (the whole image: two captures of one machine share
  their size and their first megabyte). `solve_set` reads that cache whenever the same image
  is in a delivery, so an image solved once with Volatility replays offline afterwards.
- `--where sandbox` (the default) has no network. **Windows plugins work there with `--symbols fetch`**
  (verified on a real image, 2026-10-08): the kernel's debug reference is read from the image's bytes
  (`memory.py <image> --pdb`), the one matching symbol file (about 160 KB) is cut out of Volatility's public
  symbol pack with three HTTP range requests and saved in the local symbol cache, and the sandbox
  gets it beside the image. `.venv/bin/python solvers/toolkits/memory.py <image> --vol windows --symbols fetch`
  ran pslist, psscan, pstree, cmdline, malfind, envars, getsids, filescan, dlllist and info on a 512 MB Windows
  XP image in about a minute. The fetch is one outside request for a symbol file: the agent's own call,
  never made by `solve_set`. A kernel the pack does not hold needs `--where venv --online` (a native
  parse and Microsoft's symbol server). Linux and macOS plugins need an ISF for the exact kernel (the banner
  names it); without one, use the carvers. `windows.netscan`/`netstat` do not support XP; `windows.svcscan` is
  not in the sandbox's Volatility 2.7.
- By hand: `vol -q -r json -f IMAGE windows.pslist | windows.pstree | windows.cmdline | windows.netscan |
  windows.malfind | windows.envars | windows.getsids | windows.info | windows.filescan | windows.dlllist`,
  `linux.pslist | linux.psaux | linux.bash | linux.sockstat`. No hashdump or lsadump by default.
- A different image is a fresh case: cached tables do not apply, and what cannot be carved is `None`.

## Linux images: the triage opener (B-136)

`solvers/toolkits/vol_triage.py`, engine `toolkits.vol_triage`, opener lane `memory-forensics` in
`openers/layer1.toml`. Tests: `tests/test_b136_vol_triage.py`. It is the triage half of a Linux memory
challenge with no model (Spooky's Peering Eyes was opened by hand: which kernel, which symbol table, what ran).

```bash
python -m ctf run toolkits.vol_triage <image>           # the no-tool stage: what intake and `ctf arm` run
python -m ctf run toolkits.vol_triage <image> --vol     # then linux.psaux, linux.bash, linux.pslist in the sandbox
    [--symbols DIR]... [--arch x64|x86|arm64] [--plugins a,b] [--where sandbox|venv] [--no-start] [--budget S] [--vol-budget S]
    [--scratch DIR]
```

It is Linux-only. An image with no Linux banner gets `kernel_banner = none (...)` naming `toolkits.memory`
(the engine for a Windows image), and the routes follow that: a LiME/AVML file, or a brief that names a
Linux capture format or plugin (`.lime`, `avml`, `linux.psaux`, `dwarf2json`), ranks the opener first (62,
61); a brief that only says "memory dump" ranks it after `toolkits.memory` (46 against 47).

- **No-tool stage** (mmap, nothing started, 11 s on a 1 GB LiME image), in this order: the format and
  ranges; the kernel's whole banner (`memory.carve_linux_banners`, printed at once as `banners(carved) = N
  distinct, the most frequent: ...`); flags in the event's format and flag
  leads that no complete flag follows (`flag_fragment(carved) = "prefix" + "{" + "body"`: one half of a
  split flag, never a flag); then the ISF made for exactly that banner, looked for in the image's folder (a
  delivery that ships its table), each `--symbols` folder and the event's symbol folder
  `<workdir>/_memory/_symbols/` (`memory.linux_isfs`, `match_linux_isf`); the strategy
  `memory_depth.select_profile(..., isf_index=...)` states; the `linux.zip` pack the sandbox takes
  (`memory.linux_symbol_pack`). `kernel_banner`, the release and the arch are those of the banner the table
  matches when one does, else of the most frequent banner; the others are `kernel_banner(other)` lines.
- **Said as it is found.** Each part of the report is printed and flushed when it is found (header, image
  note, carved banner, flags, then kernel, table and pack, then Volatility), so a run that intake kills at
  its limit has already printed its banner and its flags, and intake reads the flags off that output.
  `vol_triage.render(result)` gives the same lines in the same order.
- **The budget** (`--budget`, 40 s) covers the whole no-tool stage, in shares counted from its start: an
  AVML version 2 image is decompressed by 0.2 of it, the banners are carved by 0.3 (a cut carve is said, with
  the offset it reached, and is never reported as "not Linux"), the flag scan stops at
  0.6; the table search stops at its end and says where (`the table search's budget ran out before
  <file>: N candidate(s) opened`). A candidate table is untrusted (at intake the whole handout is a
  symbols folder): at most 64 `linux_banner` keys of one are parsed, one nested too deep to parse is no
  table, and any other fault while reading one is the `isf = none (... the table search failed ...)` note.
  The banner and the flags are reported whatever the tables do.
- **The pack** is kept under `<workdir>/_memory/_symbols/linux-<banner hash>-<table hash>/linux.zip`: it is
  reused only for the very table it was made from (`symbol_pack = ... (reused: ...)`), so a damaged table or
  a decoy with the right banner is not served again once the right table is at hand. When no table is in
  any folder, a pack saved earlier for the same banner is used (`isf = matched linux.zip [saved pack]`,
  `memory.saved_linux_pack`; the newest when several were saved). The table is hashed and copied whole, so
  its size is bounded: one over 512 MiB (`memory.ISF_PACK_MAX`) is matched but not packed
  (`symbol_pack = not written (TableTooLarge: ...)`; compress it with xz). A temporary pack file a killed
  run left behind is removed by the next run once it is an hour old.
- **Of several tables that match, the longest banner wins**: the table whose banner is the whole carved
  banner before one that carries only its first words (first in walk order among equals), the rule
  `memory_depth.select_profile` has. A match on a shorter start says so in the `isf` line.
- **AVML version 2 is snappy-compressed and is decompressed first** (`memory.avml_to_lime`, with cramjam,
  which `requirements.in` pins): chunk by chunk into a nameless temporary file (in `--scratch DIR`, else the
  system's temporary folder) that holds the LiME file `avml-convert` would write, and everything after reads
  that copy. `image_note` says how many ranges and bytes were decompressed and that the offsets in the report
  are offsets in that LiME file. The copy is bounded: a chunk that declares more than the format's 64 KiB is
  refused, a range gives no more than its header states, the decompression stops at its share of the budget
  and when less than 1 GiB would stay free on the volume, and each stop is named (`decompressed in part
  ... what follows is about that part only`). When nothing can be decompressed (no cramjam, no room, a first
  chunk that is not snappy) the stage reads the file's bytes as they stand and says so: a banner or a flag
  the compressor cut in two is then not found, and a missing banner is reported as that, not as "not Linux";
  `avml-convert <image> <out.lime>` is the way out. Checksums are not verified. `--vol` gives Volatility the
  AVML file itself (its own AVML layer needs the snappy library in the sandbox image).
- **Nothing is downloaded and no table is picked by release.** Two builds of one release have different
  tables; a table whose banner is not the image's is named in the `isf = none (...)` line with what was looked
  at. To add a table: make it offline with dwarf2json from the kernel's debug `vmlinux` and drop the `.json.xz`
  into the symbol folder (or pass `--symbols DIR`).
- **`--vol`** runs the plugins through `memory.vol_save(..., where="sandbox")` with the matched pack, saves the
  tables where `build_model` replays them, and prints every process with its arguments, the shell history
  (`linux.bash` rows are history, not the shell's command line), the notable processes (an interpreter running a
  script, a path in a world-writable folder, a kernel module loaded by hand, the display server) and how often
  each script's name still stands in the image (`pivot(carved)`: where to point `strings`).
  `memory.py <image> --vol linux --symbols auto` is the same match with the whole Linux plugin family.
- **Not run is said, never shown as an empty table**: the sandbox is down, Volatility is missing, the kernel has
  no local table, the budget ran out (`volatility = not run (...)`, `vol <plugin> = no table (...)`). After the
  first note that Volatility never looked at the image the remaining plugins are skipped: a 1 GB image is not
  copied into the sandbox once per plugin to fail the same way.
- **Intake runs the no-tool stage only.** Intake's network guard cuts the docker socket (checked: the docker CLI
  cannot reach the daemon under it), so `--vol` is a step of its own outside the guard; the no-tool stage prints
  the exact command as `next = ...`, with the `--symbols` folders it was given.
- **Images over the sweep's size limit.** The sweep copies no original over 256 MiB (512 MiB in all) into the
  scratch folder engines are matched against, and a memory image is nearly always larger. The manifest's
  `[intake]` table says `originals = true` (docs/CONTRACTS.md section 6): intake then also gives the opener
  the images the sweep left out, by their own path under `files/` (it reads them through mmap). The
  `--symbols {folder}` argument is still the scratch copy; the table beside the image in `files/` is found
  as the delivery's. A run is killed at the manifest's 60 s (or what is left of the challenge's engine
  budget); the stage's own 40 s budget is below it.
- **Text from the image is printed as a literal** (`proc`, `history`, `notable`, the display server's name):
  a line break in a process's arguments cannot start a report line.
- **Names from the handout cannot start a report line either.** Every report line is printed with whatever
  is not printable in it escaped (`memory.shown`: a line break, and every other character a line reader
  splits at), so a file, folder or table name such as `x<newline>flag(carved) = ...` stays inside the line
  that names it; memory.py's own notes escape the names where they are made. The `next = ...` command quotes
  such a path as `$'...'` (bash, zsh), so it can still be pasted. A flag-shaped string in a name is still
  text on stdout: intake's scan of an engine's stdout reads it as it reads any other (it is in the handout,
  as a name), but never as a `flag(carved)` line of this report.
- **Left to a model or a human** (`handoff = ...` lines): pixels held by the display server (stride detection
  and BGRX rendering of an X heap or a framebuffer mapping) and reading what is drawn or written in them.

## Question shapes it answers

| Asked | Example | Source |
| --- | --- | --- |
| name of a PID | "What is the name of the process with PID 3332?" | process tables, minidump, core, carved |
| PID of a name | "What is the PID of evil.exe?" | same; `None` when two processes carry the name |
| parent PID, parent name, the one child, child count | "parent PID of powershell.exe", "Which process spawned evil.exe?" | ppid column; the name needs the parent listed |
| command line | "full command line of PID 4444" | cmdline/psaux table, minidump PEB, core psargs |
| remote IP, remote port, local port, protocol, connection time, the process behind a peer or port | "What remote IP did evil.exe connect to?" | netscan/netstat rows; peers `0.0.0.0`, `::`, `*`, loopback are not peers |
| injected region start, protection, the injected process, its PID | "At what address does the injected region in evil.exe start?" | malfind rows, minidump private RWX regions |
| user or SID of a process, logged-in user | "Which user ran PID 3332?" | a user column, envars `USERNAME`, the first getsids row; carved `USERNAME=` |
| host name | "What is the computer name?" | info, envars `COMPUTERNAME`/`HOSTNAME`; carved |
| build number, build lab, kernel release | "What is the Windows build number?" | windows.info, minidump, crash dump; banner |
| process create or exit time, capture time | "When was evil.exe started?" | CreateTime; windows.info SystemTime, minidump header |
| process count, count of a named process | "How many processes are listed?" | one process table, or several that agree |
| image format | "What is the format of the memory dump?" | the magic; raw is `None` |

Not answered (`None`): a name two processes carry with different values, a PID two rows name differently, a
process the delivery does not list, "spawned by PID N" and other phrases that move the subject, two families
in one question, and anything about threads, handles, DLLs, paths, services, privileges, sessions or
"suspicious" processes. Read those from the triage output and submit them once through the guarded path.

A plain answer also needs the question read whole (`memory.understood`): every word left after the selector,
quoted text, file names and a format hint must be in `memory._VOCAB`. One word outside it ("after", "whose",
"as", "second", "not") and the fact is offered unsure at best; a count is then not answered at all. Further:
the parent and the child are answered only in the forms "the parent of X", "X's parent", "which process
spawned X", "the child of X", "how many children does X have" ("X is a child of which process" and "whose
parent is X" are `None`); an integer about a named process is its PID only when the question says PID; a
process table with a line that was not read as a row (cut short, too many cells, no PID) is never counted; a
time cell with no zone is offered as UTC, unsure; a core with two process records or a minidump with two
streams of one type names no process. Calibration looks at no more than 256 name fields and the carvers stop
at `solve_set`'s deadline (0.6 s).

## Plain or unsure

- Plain: a fact from a table, minidump or core, picked by a selector with one consistent value, when the
  answer is `kind: integer` or the question's pattern or option list lets exactly one rendering through.
- Unsure (`labels.pick`): every name, time, address, protection and text answer otherwise, and every carved
  fact, even an integer. Keys and their option names, best first:

| Key | Options |
| --- | --- |
| `memory.process_name/<src>` | `as_listed` (`evil.exe`), `lower`, `no_ext` (`evil`), `lower_no_ext` |
| `memory.pid/<src>`, `memory.ppid/<src>`, `memory.remote_port/table`, `memory.local_port/table`, `memory.count/table`, `memory.build/table` | `decimal` / `count` / `number` |
| `memory.cmdline/<src>` | `as_listed`, `collapsed` (single spaces) |
| `memory.remote_ip/table`, `memory.sid/table`, `memory.build_lab/table`, `memory.kernel/<src>` | `as_listed` / `release` |
| `memory.region_start/<src>` | `hex_0x` (`0x1f0000`), `as_listed`, `hex_0x_16`, `hex`, `hex_0x_upper`, `decimal` |
| `memory.protection/<src>` | `snake` (`page_execute_readwrite`), `as_listed` (`PAGE_EXECUTE_READWRITE`), `short` (`rwx`) |
| `memory.create_time/<src>`, `exit_time`, `conn_time`, `system_time` | `iso_z` (`2026-10-01T09:14:07Z`), `space`, `as_listed`, `iso_offset`, `space_utc`, `iso`, `epoch` |
| `memory.user/<src>` | `as_listed` (`WKSTN-07\alice`), `no_domain`, `lower`, `lower_no_domain` |
| `memory.hostname/<src>`, `memory.protocol/table` | `as_listed`, `lower` |
| `memory.format/<format>` (labels) | `lime`, `lime_dump`; `minidump`, `windows_minidump`, `mdmp`; `crash_dump`, `windows_crash_dump`; `elf_core`, `core_dump`; `hibernation_file` |

`<src>` is `table`, `minidump`, `elfcore` or `carved`.

Label vocabulary this event's style suggests for enum-like questions (not yet confirmed; offer through `pick`):
injection technique `process_hollowing`, `reflective_dll_injection`, `shellcode_injection`,
`classic_dll_injection`, `apc_injection`; region state `private_rwx`, `mapped_image`; process relation
`orphan_process`, `parent_spoofing`, `masquerading`; persistence `run_key`, `scheduled_task`, `service`;
network role `c2_beacon`, `reverse_shell`, `bind_shell`, `exfiltration`; ATT&CK ids T1055 (and .001, .002,
.012), T1059.001, T1036.005, T1003.001, T1071.001.

## Limits to know

- `labels.pick` returns a ranked candidate list, not a guess that gets sent: read the unsure options with
  `labels.show(...)`, reason to the one that fits the challenge, and submit it once through the guarded path.
- `solve_set` answers nothing unless `signals(questions, files)` is 0.25 or more (an image magic 0.6, an image
  file name 0.3, a Volatility table 0.5, question words up to 0.7). A delivery with no memory image scores
  under it.
- The Windows process carver is checked against Volatility on one real image (Windows XP SP2, 32-bit; see
  "Real artifacts" below) and on synthetic records in the Windows 10 x64 layout; no real 64-bit image was read.
  The Linux carver is proven on synthetic records only. Their answers are always unsure.

## Real artifacts (2026-10-08): what a real image changed

Tested on eleven real dumps, one real 512 MB image and its real Volatility output
(`tests/real/test_real_memory.py`; sources in `docs/toolkits/real-data.md`).

- **The carver read 2,300 "processes" in a real image that has 62.** A name field with a PID and two kernel
  pointers before it is common in memory. `carve_windows_processes` now calibrates the object's own marks on
  `System` as well (the dispatcher header `03 00 <size> 00` at one distance before every System name, the pool
  tag `Pro\xe3`/`Proc` before the object), searches the image for those marks instead of for names, and drops
  what does not carry them. On the real image: the 62 records Volatility's psscan confirms (its own five false
  positives excluded), all 47 pslist processes with the right parent PID and create time, nothing else, in 0.8 s
  for 512 MB. An image with neither mark (the synthetic fixtures) is read the old way.
- The create time is the time-shaped field next to the PID (a second one 372 bytes on made it "not unique"),
  System may have none, and a 32-bit EPROCESS is searched at 4-byte steps.
- Volatility's remark in a cell it could not read (`Required memory at 0x10 is not valid (process exited?)`,
  System's command line in real `windows.cmdline` output) is not a value.
- 32-bit ELF cores are read (i386's 124-byte and the 128-byte process record).
- `kernel_pdb(data)`, `fetch_isf(pdb, guid, age)`, `vol(..., symbols=pack)`, and the command's `--pdb` and
  `--symbols fetch|PACK.zip`.
- Real `vol -r json` tables are tracked in `tests/real/data_a/vol3-xp-laptop/` and read as a delivery.

Timing: a minidump or core under 10 MB reports in under 0.1 s. The command on the 512 MB image takes 8 s (it
hashes and carves all of it); `solve_set` carves only the first 16 MB of an image (`CARVE_MAX`), so on a large
raw image it answers nothing until the tables are saved with `--vol` (then 0.25 s, by the image's fingerprint).
