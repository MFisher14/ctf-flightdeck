# Windows — CSCTF 2026 playbook

The **Windows** category is Windows-host DFIR: you get host artifacts — a registry hive, an EVTX
event-log set, a `.lnk` shortcut, a disk/partition image, a split or damaged archive, an MS-Access or
SQLite database — and you reason out the flag from what Windows left behind. It overlaps Forensics
(see `forensics.md`) but the lens is Windows internals: **registry, event logs, DPAPI, LNK/persistence,
NTFS, and Windows app databases.** Everything here is an **offline static reader**; anything that must
*run* or *unpack* an untrusted artifact (Volatility, sleuthkit, 7z, binwalk) runs **only in the Docker
sandbox**, never on the Mac.

```sh
cd <ctf-tools checkout>                   # every command on this page runs from the checkout root
export CTF_EVENT=<event slug>             # the event profile, events/<slug>/event.toml
.venv/bin/python -m ctf workdir --create  # the workdir (ctf.paths): $CTF_WORKDIR, else ~/ctf-work/<event>
# engines are invoked as:  .venv/bin/python solvers/<area>/<module>.py <file> [flags]
```

Downloaded challenge files are **untrusted**: keep each in its own directory (`./csctf pull` already
lays them out under `workspace/<id>-<slug>/`), pass the path as an argument, don't `cd` into it, and
run readers with `python -I` when a sample sits next to importable scripts.

---

## First moves (the moment you open a Windows challenge)

1. `./csctf check <id>` — teammate already solved it? If so, skip.
2. **Identify every file before anything else:**
   - `.venv/bin/python solvers/metadata-forensics/file_properties.py <file>` — hashes, true magic, format.
   - `.venv/bin/python solvers/metadata-forensics/properties_strict.py <file>` — the strict registry prints
     only fields that are present, including `lnk`/`OLE`/`EVTX`/`regf` markers, so it tells you *what
     Windows artifact this even is*.
3. **Route by what it is:**
   - a `regf` hive (`SAM`/`SYSTEM`/`SECURITY`/`SOFTWARE`/`NTUSER.DAT`/`USRCLASS.DAT`), an EVTX/XML/CSV
     event log, a `.lnk`, a prefetch `.pf`, a scheduled-task XML, a `$MFT`/USN → **`windows.py`**.
   - a browser/app **SQLite** or LevelDB store → **`sqlite_artifacts.py`**.
   - an ESE/`.edb`/`.dat` (SRUM/WebCache/NTDS) → **`ese_reader.py`**.
   - a Jump List (`*.automaticDestinations-ms`) → **`jumplist.py`**.
   - Outlook `.pst`/`.ost` → **`artifact_depth.py pst`** for bounded NDB validation/string and
     embedded-object recovery leads; EML/MSG/MBOX still go to **`email.py`**.
   - a memory dump → **`memory.py`** (see `forensics.md` memory section).
   - a disk/partition image, or a **split/broken archive** → carve/repair in the sandbox, then feed the
     exported artifacts to the readers above.
4. Keep the solve path in the challenge's `notes.md` as you go (needed for the write-up).

> **The `--ask` shortcut.** `windows.py --ask '<plain question>' <files...>` answers one question
> (who ran what, when, which USB, which SID) across a mixed folder of hives + logs + LNKs. The
> many CSCTF "Volatile Questions" / helpdesk-ticket briefs are a list of such questions — ask them
> one at a time and the tool joins the right artifacts for each. It answers *only* from the bytes and
> **refuses (returns unsure) rather than guess** when a hive is dirty or a list was truncated.

---

## Engine CLIs by sub-type

### The one Windows DFIR engine — `solvers/toolkits/windows.py`

```sh
.venv/bin/python solvers/toolkits/windows.py [--json] [--persistence] [--ask 'question'] <file-or-folder>...
```

Hand it a single artifact or a whole exported `config/` + `winevt/Logs/` folder; it dispatches per file:

- **Event logs** — EVTX (its own EVTX reader; `python-evtx` also available in the sandbox), plus XML /
  JSON / CSV exports. It normalizes `System`/`EventData`, renders timestamps to 100 ns, and **joins
  PowerShell 4104 ScriptBlock events in `MessageNumber` order** so a script split across many 4104
  records is reassembled whole. `script_blocks()` returns `{ScriptBlockId: {text, complete, path}}`;
  4103 module-logging and 400/600 engine events are tagged too.
- **Registry hives (regf)** — a self-contained hive reader (`nk`/`vk`/`lf`/`lh`/`li`/`ri` + big-data),
  identifying the hive role (`SYSTEM`/`SAM`/`SECURITY`/`SOFTWARE`/`AMCACHE`/`NTUSER`/`USRCLASS`) from its
  root keys, and the high-value keys: **run keys, services, winlogon, IFEO, userassist (ROT13-decoded),
  shimcache, amcache, usbstor, run MRU, typed paths, shellbags, `sam_users`, `system_info`.** `.reg`
  text exports read through the same view. `<CCS>` in a path resolves `CurrentControlSet`/`ControlSet00N`.
- **Dirty-hive safety** — a primary hive whose latest writes live only in its `.LOG1`/`.LOG2`
  transaction logs is replayed when the logs cover the sequence gap; when they don't (or it's an old
  DIRT-format log), **every value of that hive is demoted to unsure** — the never-wrong contract. So
  export the `.LOG1`/`.LOG2` alongside the hive, not the hive alone.
- **LNK** — `.lnk` target path, arguments, working dir, MAC times, drive serial, machine id, NetBIOS
  name. (The sandbox also carries `LnkParse3` if you want a second opinion.)
- **Prefetch** (`.pf`, incl. MAM-compressed), **scheduled-task XML**, **`$I` recycle-bin**, **`$MFT`**
  ($SI vs $FN times → **timestomp** detection), **USN journal**.
- `--persistence` = the autostart summary (mechanism → command → ATT&CK technique) across run keys,
  services, scheduled tasks, IFEO, winlogon.

### Windows app & browser databases — `solvers/toolkits/sqlite_artifacts.py`

```sh
.venv/bin/python solvers/toolkits/sqlite_artifacts.py <file-or-folder>...
```

Chromium/Edge/Firefox history, cookies, **Login Data**, downloads; Windows-app SQLite stores. It
**recovers DELETED rows** from WAL / rollback journal / freelist / unallocated, decodes staged
url/base64/hex cells, and normalizes WebKit/PRTime/Unix timestamps. For Chromium **Login Data**,
stored passwords are DPAPI/`v10`/`v11`/`v20` protected and come back `None` unless the delivery also
ships the key — see the DPAPI note below.

### ESE databases — `solvers/toolkits/ese_reader.py`

```sh
.venv/bin/python solvers/toolkits/ese_reader.py <file>... [--json] [--rows]
```

`SRUDB.dat` (SRUM: per-app usage, bytes sent/received, network profiles), `WebCacheV01.dat`, `NTDS.dit`.
`--rows` dumps sample rows per table.

### Jump Lists — `solvers/toolkits/jumplist.py`

```sh
.venv/bin/python solvers/toolkits/jumplist.py <file>... [--json]
```

`*.automaticDestinations-ms` (CFB) + `*.customDestinations-ms`: per-destination LNK target/time, volume
serial, MAC, machine id, MRU order, AppID → the "recently opened files" story.

### Memory images — `solvers/toolkits/memory.py`

For a RAM dump, see the memory section of `forensics.md`. Triage with `memory.py <dump>`; run the
Volatility 3 Windows plugin set with `memory.py <dump> --vol windows` (which executes Volatility **in
the sandbox** and saves the tables for offline replay).

---

## Windows archetypes → engines (grounded in 2024/2025)

These are the patterns CSCTF has actually shipped. Map first, then run the engine.

### 1. Saved Wi-Fi passwords (WLAN profile + DPAPI)
2024 **Wi-Fi** was an OSINT-flavored repo lookup, but the real Windows technique is the WLAN profile
store. On a live host `netsh wlan show profiles` / `... show profile <name> key=clear` dumps it; from a
disk image the profiles are XML at:

```
C:\ProgramData\Microsoft\Wlan\Profiles\Interfaces\{GUID}\{profile-GUID}.xml
```

- The SSID is cleartext in `<SSIDConfig><name>`; the PSK is in `<sharedKey><keyMaterial>`.
- If `<keyMaterial>` is a long hex blob (protected profile), it is **DPAPI-encrypted** under the
  **SYSTEM** account. Decrypting it offline needs the SYSTEM DPAPI masterkey plus the machine's
  **DPAPI_SYSTEM** LSA secret from the `SECURITY` hive and the key from `SYSTEM` — export
  `C:\Windows\System32\config\{SECURITY,SYSTEM}` and the masterkeys from
  `C:\Windows\System32\Microsoft\Protect\S-1-5-18\`. `windows.py` reads the hives; the DPAPI unwrap
  itself is an offline step (`impacket` `dpapi.py` / DSInternals in the sandbox) — the recovered PSK is
  a **lead**, never submitted anywhere but as the flag if it *is* the flag.
- A PSK captured **over the air** instead (EAPOL/PMKID) is a Forensics pcap job → `pcap_creds.py`
  (mode 22000), cracked offline.

### 2. Extract files from a broken / split archive
2024 **Together** was a 7-Zip multipart (`.001`–`.009`); **DB**-adjacent tasks hide the flag in a file
inside a damaged container. Repair/extract in the sandbox, then read the member:

```sh
# multipart 7z / zip: point 7z at the FIRST part; it reassembles the set
.venv/bin/python tools/sandbox.py run --in archive.7z.001 7z x {in} -o{out}
# a zip with a corrupt central directory: rebuild it with zip -FF (fix-fix)
zip -FF broken.zip --out repaired.zip          # host `zip` is fine for this static repair
.venv/bin/python tools/sandbox.py run --in repaired.zip 7z l {in}     # then list/extract safely
```

`tools/unpack.py` is the batteries-included recursive unpacker (handles nested archives and the
password store; falls back to 7-Zip for what the Python libs can't open). For deeper
**disk-level** recovery of a truncated image (lost partition table, deleted members), carve with the
sandbox's `binwalk -e` / `foremost`, or add `testdisk`/`photorec` to the host via Homebrew if a full
filesystem rebuild is needed. Once members are out, flag usually sits in a plain `.txt`/`old.txt`.

### 3. Browse a Windows database (MS Access / SQLite)
2024 **DB** shipped a `backup.mdb` with the flag in `auth_user.password`.
- **SQLite / LevelDB** (most modern apps) → `sqlite_artifacts.py` reads tables *and deleted rows*.
- **MS-Access `.mdb`/`.accdb`** is the **Jet/ACE** engine, *not* SQLite — `sqlite_artifacts.py` won't
  open it. Read it with `mdbtools` (`mdb-tables backup.mdb`, then `mdb-export backup.mdb auth_user`),
  installable via Homebrew (`brew install mdbtools`); or `strings backup.mdb | grep -i csctf` often
  surfaces a short flag directly since Jet stores text in the clear. Keep the file untrusted — these
  are read-only dumps, no Access macro execution.

### 4. Registry hives → encoded answers (Volatile Questions)
2025 **Volatile Questions**: a ~6 GB disk image → export
`C:\Windows\System32\config\{SAM,SECURITY,SYSTEM}`, read the **Security Questions** reset data, then
peel the encoding (that year: Base64 ∥ ROT13 ∥ Caesar+3, concatenated in order).

```sh
# 1) get the hives out of the disk image, in the sandbox:
.venv/bin/python tools/sandbox.py run --in disk.img mmls {in}                 # find the Windows partition offset
.venv/bin/python tools/sandbox.py run --in disk.img tsk_recover -o <off> -e {in} {out}
#    (or export just the config dir with icat / 7z over the partition)
# 2) read the hives offline:
.venv/bin/python solvers/toolkits/windows.py --json config/SAM config/SECURITY config/SYSTEM
.venv/bin/python solvers/toolkits/windows.py --ask 'what are the security question answers?' config/*
```

`windows.py` parses SAM users (`sam_users`) and the SOFTWARE/SAM reset-data values; `regipy` (6.4.0 in
the sandbox) is available as a cross-check (`hive_regipy(data)`). The three decoded strings concatenate
**in the order the questions appear** — don't reorder. Decode the Base64/ROT13/Caesar layers with
`solvers/warmups/` (the offline auto-decoder) rather than a web tool.

### 5. LNK → PowerShell `-EncodedCommand` (Update)
2025 **Update**: a `.lnk` whose target is `powershell.exe` with an `-EncodedCommand`/`-enc` blob.

```sh
.venv/bin/python solvers/toolkits/windows.py --json update.lnk        # prints target + full arguments
```

Pull the Base64 blob from the LNK arguments; **it is UTF-16LE** (`-EncodedCommand` always is), so
decode Base64 → UTF-16LE text. Feed the blob to `solvers/warmups/` auto-decoder (it tries UTF-16LE),
or `base64 -d | iconv -f UTF-16LE`. Nested `FromBase64String`/`iex` layers get peeled the same way.

### 6. EVTX PowerShell ScriptBlock 4104 deobfuscation (Logs)
2025 **Logs**: suspicious PowerShell across an EVTX set; the payload is in **4104 ScriptBlock** (and
4103) events, base64-layered, pivoting to a DNS TXT record.

```sh
.venv/bin/python solvers/toolkits/windows.py --json winevt/Logs/*.evtx     # 4104 blocks joined in order
# or target just the PowerShell/Operational channel the brief names
```

`windows.py` reassembles multi-part 4104 blocks into one script per `ScriptBlockId`. Then peel the
layers: base64 → `FromBase64String` → `iex`, often UTF-16LE, ending at a `Resolve-DnsName -Type TXT`
payload (the final stage is carried in a **DNS TXT** record — treat that as given data in the brief,
not a live lookup). The sandbox's `python-evtx` (`Evtx`) is the fallback dumper if an EVTX won't parse.

---

## Docker sandbox tools (`csctf-sandbox:2`)

Detonation / heavy external tools run **only** through `tools/sandbox.py` (`--network none`, read-only
root, caps dropped). `--in FILE` copies the bytes to `/drop`; `{in}` is that path, `{out}` is the one
writable folder. Check it is up with `tools/sandbox.py status`; list tools with `tools/sandbox.py tools`.

```sh
# split / damaged archives
.venv/bin/python tools/sandbox.py run --in archive.7z.001 7z x {in} -o{out}
.venv/bin/python tools/sandbox.py run --in repaired.zip 7z l {in}
# disk image → partitions → export the config hives
.venv/bin/python tools/sandbox.py run --in disk.img mmls {in}
.venv/bin/python tools/sandbox.py run --in disk.img fls -r -o <off> {in}
.venv/bin/python tools/sandbox.py run --in disk.img tsk_recover -o <off> -e {in} {out}
# memory image — Volatility 3 (prefer memory.py --vol, which saves tables)
.venv/bin/python tools/sandbox.py run --timeout 120 --in mem.raw vol -f {in} windows.pslist
# raw carving when the filesystem is gone
.venv/bin/python tools/sandbox.py run --in disk.img binwalk -e {in}
.venv/bin/python tools/sandbox.py run --in disk.img foremost -o {out} -i {in}
```

Windows-relevant Python in `:2`: `python-evtx` (EVTX), `regipy` (hives), `LnkParse3` (LNK),
`extract-msg` (Outlook `.msg`), plus `7z` / `tshark` / sleuthkit (`mmls fls icat tsk_recover`) /
`binwalk` / `foremost` / `vol`.

---

## Techniques → engines (cheat sheet)

| You suspect… | Reach for |
| --- | --- |
| Saved WLAN profile / Wi-Fi PSK on a host image | WLAN XML + `windows.py` (hives) → offline DPAPI unwrap |
| Wi-Fi PSK captured over the air (EAPOL/PMKID) | `pcap_creds.py` (mode 22000), crack offline |
| Split / corrupt archive hiding a file | sandbox `7z x` on `.001`; `zip -FF` rebuild; `tools/unpack.py` |
| MS-Access `.mdb`/`.accdb` table | `mdbtools` (`mdb-export`) / `strings` — **not** `sqlite_artifacts.py` |
| Browser/app SQLite, **deleted** rows, Login Data | `sqlite_artifacts.py` |
| App usage / bytes / network profile in ESE | `ese_reader.py --rows` |
| Registry run keys / services / userassist / usbstor | `windows.py` (`--persistence`) |
| SAM users / security-question reset data | `windows.py` (`sam_users`), `regipy` cross-check |
| `.lnk` → powershell `-EncodedCommand` | `windows.py` (lnk) → Base64→UTF-16LE (`warmups/`) |
| PowerShell ScriptBlock obfuscation in EVTX | `windows.py` (4104 joined) → peel base64/iex layers |
| Recently-opened files | `jumplist.py`, `windows.py` (lnk) |
| Timestomp / anti-forensics on NTFS | `windows.py` ($MFT $SI vs $FN, USN journal) |
| Process list / injected code in a RAM image | `memory.py --vol windows` |

---

## Getting the flag out & submitting

Flags look like `CSCTF{...}` (leetspeak + CaMeL case; a rare `CTF{...}` outlier). When an engine's
output yields the real flag, submit it **once**:

```sh
./csctf submit <id> 'CSCTF{...}'          # routes through ctf.submit.guarded_submit
```

From a solver, call `ctf.submit.guarded_submit(ctfd, ch, flag, provenance="windows.py 4104 scriptblock")`.
The guard does the format check, dedupes, paces, skips team-solved, and **stops and asks after 3 wrong**.
Never loop candidate flags — reason to one value. Several 2025 Windows challenges issued **dynamic
(rotating) flags**; if the solve crosses a 5-minute boundary, script the retrieval and drive it through
`ctf.dynamic.solve_dynamic` (see AGENTS.md) rather than re-deriving by hand.

## Scope & safety

- Every artifact is read **statically**; disk images, archives, memory dumps, and any sample that must
  be *run or unpacked* go **only through the Docker sandbox**, never the host.
- A recovered PSK / DPAPI secret / password hash is a **lead**, cracked or unwrapped offline — never
  submitted as a flag unless it *is* the flag, and never used against anything but the assigned target.
- If a challenge gives a **live target** (a share to pull an image from), that service is the only thing
  you may touch — assigned target only, no scanning, no flooding, no flag brute-forcing (AGENTS.md).
- **Never buy a hint** — that is the player's call, never the solver's.
