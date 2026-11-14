# Forensics — CSCTF 2026 playbook

Forensics here is **offline artifact analysis**: you get a file (capture, memory dump, disk/firmware
image, document, log bundle) and reason out the flag. The engines are static readers — nothing
executes the artifact. Anything that must *run* a sample (Volatility, binwalk extract, sleuthkit,
oletools) runs **only in the Docker sandbox**, never on the Mac.

```sh
cd <ctf-tools checkout>                   # every command on this page runs from the checkout root
export CTF_EVENT=<event slug>             # the event profile, events/<slug>/event.toml
.venv/bin/python -m ctf workdir --create  # the workdir (ctf.paths): $CTF_WORKDIR, else ~/ctf-work/<event>
# engines are invoked as:  .venv/bin/python solvers/<area>/<module>.py <file> [flags]
```

Downloaded challenge files are **untrusted**: keep each in its own directory (`./csctf pull` already
lays them out under `workspace/<id>-<slug>/`), pass the path as an argument, don't `cd` into it.

---

## First moves (the moment you open a forensics challenge)

1. `./csctf check <id>` — teammate already solved it? If so, skip.
2. **Identify every file before anything else:**
   - `.venv/bin/python solvers/metadata-forensics/file_properties.py <file>` — hashes, true magic, format, image dims.
   - `.venv/bin/python solvers/toolkits/forensics.py <file>` — one-line container verdict (capture / memory / disk) that tells you which specialist to reach for.
3. **Always carve-scan it:** `.venv/bin/python solvers/toolkits/carve_stego.py <file>` — trailing bytes after the end marker, embedded files, polyglots, codes. A huge fraction of "forensics" flags are simply appended/embedded data.
4. Route by what step 2 said and jump to the matching sub-type below.
5. Keep the solve path in the challenge's `notes.md` as you go (needed for the write-up).
6. **A git repository in the handout: never run `git` on it or on its scratch copy** (its config, hooks and
   aliases are code). The pull-time sweep already read it as bytes (B-070): open
   `unpacked/<archive>.unpacked/<repo>/.git.unpacked/git-report.txt` (every commit with its epoch, reachable
   or not; ORIG_HEAD; reflog; the objects no ref reaches; deleted files; files in `.git/` that git did not
   write; hidden dotfiles; decoded hex/base64 strings; numbered fragments) and the files beside it
   (`deleted/`, `unreachable/`, `reflog-only/`, `dangling/`, `index-only/`, `history/`, `nonstandard/`).
   For more: `python -m ctf run toolkits.repo_supply_chain <archive> [--grep TEXT]`. An archive behind an
   image (`carved@0x<offset>.zip`, `overlay@0x<offset>.bin`) is unpacked by the same sweep.

---

## Engine CLIs by sub-type

### Identify / triage (run on anything)
- `solvers/metadata-forensics/file_properties.py <file-or-zip> [property ...]`
  Prints `filename/size/md5/sha1/sha256`, `magic.prefix_hex_16`, BOM flag, `image.format`, and
  per-format dimensions (`png.ihdr_dimensions_pixels`, `jpeg.sof_dimensions_pixels`, …); `none` when a
  structure is absent. Pass a property name to print just that one.
- `solvers/metadata-forensics/properties_strict.py <file-or-zip>`
  Strict registry: only prints properties actually present — dimensions, `*.chunk_count`, `c2pa_present`,
  and EXIF/ID3/gzip/WAV/ELF/PE/tar/SQLite/pcap/lnk/OLE/EVTX/regf fields. Good "what fields does this file
  even have" map.
- `solvers/toolkits/forensics.py <file>... [--json] [--strings]`
  Container facts only: capture `format/endian/linktype`, memory dump format + OS hint, or disk
  `partition scheme (MBR/GPT) / filesystem / 0x55AA`. It deliberately hands payload reading to
  `network` / `memory` / `carve_stego`.

### Packet captures (.pcap / .pcapng)
- `solvers/toolkits/network.py <capture>... [--json] [--all] [--carve DIR]`
  The full reader: conversations/endpoints/streams, DNS, DHCP hostnames, HTTP req↔resp (gzip/chunked/br),
  TLS (SNI, ALPN, JA3/JA4), cleartext credentials (FTP/POP3/IMAP/SMTP/Telnet/HTTP Basic & form posts),
  NTLMSSP, **carved transferred files with hashes** (`--carve DIR` writes them), ICMP/DNS covert channels,
  periodic **beacons**, SYN scans, **USB HID keystrokes → text**, Modbus. Start here for any pcap.
- `solvers/toolkits/network.py --tshark <capture> -- <tshark args>`
  Runs tshark in the sandbox when you need a dissector field, e.g. `-- -q -z conv,tcp`. Also
  `find_keylog` / `tls_decrypt` when an `SSLKEYLOG` ships in the delivery.
- `solvers/toolkits/pcap_creds.py <capture>... [--json]`
  Assembles ready-to-crack **hashcat lines**: WPA/EAPOL (mode 22000), NetNTLMv1/v2 (5500/5600),
  Kerberos krb5pa/krb5asrep/krb5tgs (7500/18200/13100). It never cracks — you run hashcat offline, then
  the recovered password is your lead (not auto-submitted).

### Memory dumps (raw / LiME / crashdump / minidump / ELF core)
- `solvers/toolkits/memory.py <file>...` — triage: dump format, OS hint, and offline-carved process /
  env / banner facts (works with no symbols by calibrating on PID 4 / PID 1).
- `solvers/toolkits/memory.py <image> --vol windows|linux|mac|any [--where sandbox] [--symbols fetch]`
  Runs the **Volatility 3** plugin set **inside the sandbox** and saves the tables where later offline
  runs replay them. `--pdb` prints the kernel debug reference.
- It also parses Volatility tables somebody already printed (pslist/pstree/netscan/malfind/cmdline, text
  or JSON), minidumps (command line via TEB→PEB) and ELF cores (NT_PRPSINFO / NT_FILE / NT_PRSTATUS
  registers).
- `solvers/toolkits/memory.py --heap-chains <core>` — an **ELF core whose flag is a linked list on the
  heap** (fragments out of order in `strings`, decoy lists sharing the tail): prints the saved
  registers, every rebuilt record chain ranked by which register points at its head and by the flag
  format, and a `RECOVERED:` line. Intake runs it on every ELF core (see `recon/engines/toolkits.memory/`).
  A `PARTIAL carve` warning means a cap cut it: do not trust the best chain. Details: `docs/toolkits/memory.md`.

### Windows host artifacts (DFIR)
- `solvers/toolkits/windows.py [--json] [--persistence] [--ask 'question'] <file-or-folder>...`
  One tool for: EVTX / XML / JSON / CSV **event logs** (+ PowerShell **4104** script blocks joined),
  **registry hives** (run keys, services, winlogon, IFEO, **userassist** ROT13, **shimcache**, **amcache**,
  **usbstor**, shellbags), **prefetch** (incl. MAM-compressed), **lnk** (target/args/MAC/machine-id),
  scheduled-task XML, `$I` recycle-bin, **$MFT** ($SI vs $FN times → timestomp), **USN journal**.
  `--persistence` = autostart summary (mechanism, command, ATT&CK). `--ask` answers one plain question.
- `solvers/toolkits/sqlite_artifacts.py <file-or-folder>...`
  Browser/app SQLite + LevelDB: Chromium/Firefox/Safari history, cookies, Login Data, downloads,
  iOS `sms.db`, WhatsApp `msgstore`, quarantine events. **Recovers DELETED rows** from WAL / rollback
  journal / freelist / unallocated, decodes staged url/base64/hex cells, and normalizes WebKit/PRTime/
  Unix/Mac timestamps.
- `solvers/toolkits/ese_reader.py <file>... [--json] [--rows]`
  ESE/EDB row reader for `SRUDB.dat` (SRUM app usage / bytes sent), `WebCacheV01.dat`, `NTDS.dit`.
  `--rows` dumps sample rows per table.
- `solvers/toolkits/jumplist.py <file>... [--json]`
  Jump Lists (`*.automaticDestinations-ms` CFB + `*.customDestinations-ms`): per-destination LNK
  target/time, volume serial, MAC, machine id, MRU order, AppID.

### Documents & email
- `solvers/toolkits/maldoc.py <file>... [--json] [--source] [--extract DIR]`
  Static doc analysis: OLE/OOXML **VBA** (MS-OVBA decompress + static deobfuscation), Excel4/**XLM**
  macros, DDE, **remote templates**, RTF `\objdata`, **PDF** (JavaScript / OpenAction / Launch / URIs /
  embedded files), OneNote, LNK, ISO/IMG/VHD contents, HTA/WSF/SCT scripts. `--extract` writes embedded
  payloads/scripts (then analyze those as their own files).
- `solvers/toolkits/pdf_revisions.py <file.pdf>... [--json] [--extract DIR] [--text] [--streams DIR]`
  Splits a PDF's **incremental revisions**. `--extract` writes each prior state as a standalone
  `<file>.rev<k>.pdf` — the classic "redacted / overlaid / final version hides the original" recovery.
  It also **opens** the PDF: text under black boxes or in the background colour (read through the fonts'
  ToUnicode maps), text only an earlier revision shows, every Info/XMP field, and a 16/24/32-byte metadata
  value tried as an **AES key** on the blobs in the file (printed only on a flag-format match).
- `solvers/toolkits/email.py <file>... [--json]`
  `.eml` / `.msg` / `mbox`: Received chain, originating IP, **SPF/DKIM/DMARC** results, From vs
  Reply-To/Return-Path **mismatches**, URLs (refanged + defanged), **homoglyph** domains, **QR payloads**
  in attached images, and **HTML-smuggling** decoded payloads.

### Firmware / flash images
- `solvers/toolkits/firmware_walk.py <members>...`
  Walks **SquashFS**, **JFFS2**, **UBI/UBIFS** (file names + sizes), **DTB/FDT** device-tree property
  values, and **U-Boot env** vars (only after the leading CRC32 validates). Pair with the sandbox's
  `binwalk` for the initial layout.

### Carving (shared with stego — see `stego.md`)
- `solvers/toolkits/carve_stego.py <file>... [--extract DIR] [--json]`
  Structure end + trailing bytes, validated embedded files (zip/7z/rar/gzip/png/jpeg/elf/pe/riff…),
  polyglots, PNG/JPEG/GIF chunks & comments, small filesystems (iso9660/FAT-with-deleted/ext2/cpio/
  uImage), QR/barcodes, DTMF. `--extract` dumps every carved member. **Run on every image, archive and
  "weird" blob.**

---

## Docker sandbox tools (`csctf-sandbox:2`)

Detonation / heavy external tools run **only** through `tools/sandbox.py` (`--network none`, read-only
root, caps dropped). `--in FILE` copies the bytes to `/drop`; `{in}` is that path, `{out}` is the one
writable folder. Check it is up with `tools/sandbox.py status`; list tools with `tools/sandbox.py tools`.

```sh
# memory — Volatility 3 (prefer memory.py --vol, which saves tables; raw form:)
.venv/bin/python tools/sandbox.py run --timeout 120 --in mem.raw vol -f {in} windows.pslist
# pcap — tshark (prefer network.py --tshark)
.venv/bin/python tools/sandbox.py run --in capture.pcap tshark -r {in} -q -z conv,tcp
# disk image — sleuthkit: partitions, then list/recover files
.venv/bin/python tools/sandbox.py run --in disk.img mmls {in}
.venv/bin/python tools/sandbox.py run --in disk.img fls -r {in}          # -o <offset> for a partition
.venv/bin/python tools/sandbox.py run --in disk.img tsk_recover -e {in} {out}
# raw carving / features
.venv/bin/python tools/sandbox.py run --in disk.img foremost -o {out} -i {in}
.venv/bin/python tools/sandbox.py run --in disk.img bulk_extractor -o {out} {in}
.venv/bin/python tools/sandbox.py run --in fw.bin binwalk {in}           # add -e to extract
# documents / metadata
.venv/bin/python tools/sandbox.py run --in doc.pdf pdfdetach -list {in}
.venv/bin/python tools/sandbox.py run --in file.jpg exiftool {in}
.venv/bin/python tools/sandbox.py run --in file.png pngcheck -v {in}
```

Full `:2` kit: `vol tshark` · `mmls fsstat fls icat tsk_recover` · `foremost scalpel bulk_extractor` ·
`binwalk 7z` · `qpdf pdftotext pdfimages pdfdetach pdfinfo pdftoppm mutool` · `exiftool exiv2 pngcheck` ·
`olevba oleid rtfobj oleobj msodde yara` (and everything in the stego playbook).

---

## Techniques → engines (cheat sheet)

| You suspect… | Reach for |
| --- | --- |
| Data hidden after `IEND`/`EOI`/`%%EOF`/EOCD, or an embedded file/polyglot | `carve_stego.py` |
| A credential / file transferred over the wire | `network.py` (+ `--carve`); hashes → `pcap_creds.py` |
| Covert channel (DNS tunnel, ICMP, beacon), USB keyboard, Modbus/ICS | `network.py` |
| Process list / injected code / command line in a RAM image | `memory.py` (`--vol` for Volatility) |
| Who ran what / persistence / timestomp / USB history on Windows | `windows.py` (`--persistence`) |
| Browser history/cookies/logins, **deleted** rows | `sqlite_artifacts.py` |
| App usage times, visited URLs in ESE | `ese_reader.py --rows` |
| Recently-opened files | `jumplist.py`, `windows.py` (lnk) |
| Redacted / "final" PDF hiding the original, text under black boxes, a key in the metadata | `pdf_revisions.py` (`--extract`, `--text`) |
| Macro dropper / phishing doc | `maldoc.py --extract` |
| Phishing email headers, spoofing, QR/HTML-smuggling | `email.py` |
| Router/IoT flash dump | `firmware_walk.py` + sandbox `binwalk` |

---

## Getting the flag out & submitting

Flags look like `csctf{...}` (also `flag{...}` / `chronos{...}`; the full pattern is the event profile's `[flag]` (`events/<slug>/event.toml`, read through `ctf.flagfmt`)).
When an engine's output yields the real flag, submit it **once**:

```sh
./csctf submit <id> 'csctf{...}'          # routes through ctf.submit.guarded_submit
```

From a solver, call `ctf.submit.guarded_submit(ctfd, ch, flag, provenance="carve_stego trailing bytes")`.
The guard does the format check, dedupes, paces, skips team-solved, and **stops and asks after 3 wrong**.
Never loop candidate flags through it — reason to one value. `labels.pick/candidates` only *rank
candidates for you*; they are not a judge and never auto-submit.

## Scope & safety (forensics is almost all offline)

- The artifact is analysed statically; it is **executed only in the Docker sandbox**. Never run an
  untrusted dump/doc/binary on the host.
- If a challenge gives a **live service** to fetch a capture/image from, that service is the only thing
  you may touch — assigned target only, no scanning, no flooding, no flag brute-forcing (AGENTS.md).
- A recovered password/PSK/hash is a **lead**, cracked offline — never submitted as a flag and never used
  against anything but the assigned target.

## Healthcare & financial formats (added 2026-11-03)

- **`healthcare.py`** — DICOM (`.dcm`: preamble/DICM, explicit/implicit VR, key + private tags, whole-file
  flag fallback), HL7 v2 (MSH/segments), FHIR (JSON/XML).  `.venv/bin/python solvers/toolkits/healthcare.py <file> [--json]`
- **`financial.py`** — ISO 8583 (MTI + bitmaps + LLVAR/LLLVAR fields), EMV BER-TLV (with the EMV tag
  dictionary), SWIFT MT (blocks, MT103).  `.venv/bin/python solvers/toolkits/financial.py <file> [--json]`

Both highlight flag-format hits across decoded text.

## Unified super-timeline

`solvers/toolkits/timeline.py` normalizes bodyfile, CSV, JSON and JSONL exports from MFT, USN, EVTX,
registry, Prefetch, LNK/JumpList and browser readers. It recognizes MACB timestamps plus common reader
field names, sorts in UTC, and filters by an inclusive time window, keywords and IOCs.

```sh
.venv/bin/python solvers/toolkits/timeline.py mft.body usn.json evtx.csv --format mactime \
  --start 2026-11-04T10:00:00Z --end 2026-11-04T12:00:00Z
.venv/bin/python solvers/toolkits/timeline.py artifacts.jsonl --keyword powershell \
  --ioc 203.0.113.8 --json
.venv/bin/python solvers/toolkits/timeline.py records.csv --format bodyfile
```

Library callers can feed existing reader dictionaries directly to `ingest_records()`. Inputs and
record counts are capped; binary images must first go through their dedicated static reader or the
Docker tools above. Timeline generation never mounts or executes an artifact.

## Decode-validated file repair

`solvers/toolkits/file_repair.py` emits repaired bytes only after the candidate reparses and its
payload decodes within strict caps:

```sh
.venv/bin/python solvers/toolkits/file_repair.py broken.png --output repaired.png --json
.venv/bin/python solvers/toolkits/file_repair.py truncated.zip --output recovered.zip
```

It can repair PNG signatures/chunk CRCs/missing IEND, rebuild ZIP central directories from complete
CRC-verified local members, rebuild a classic PDF xref/trailer when its object tree validates, restore
a gzip trailer after complete DEFLATE EOF, and retain complete bzip2 streams before garbage/truncation.
It refuses speculative compressed-byte reconstruction and encrypted archives. A diagnostic with no candidate means move to manual
carving—never treat guessed bytes as repaired evidence.

Round 3 adds decode-validated handling for Adam7 PNG scanlines, ZIP data descriptors, indirect PDF
stream lengths, and complete prefixes of truncated gzip/bzip2/PDF streams. The same rule still binds:
a repair is emitted only if the format-specific decoder accepts it under the allocation caps.

## Memory, disks, and video orchestration

`memory.volatility_plan()` now builds offline plugin plans for hivelist/printkey,
hashdump/lsadump/cachedump, cmdscan/consoles, dumpfiles, and malfind dumping. Feed saved plugin output
to `parse_credential_rows()` and extracted blobs to `chain_carved_blobs()`; the latter invokes only
bounded static strings/stego classifiers and never executes a dump.

`solvers/toolkits/disk_images.py inspect image --json` identifies raw, E01/EWF, VMDK, VHD/VHDX, and
QCOW2 containers. `unwrap` is pure Python for classic checksummed EWF1 chunks; clean VHDX BATs,
explicit differencing parents, and partially-present sector bitmaps; QCOW2 deflate/Zstd clusters,
extended-L2 subclusters, explicit recursive backing chains, and legacy AES-CBC (an exact 16-byte key
is mandatory); split FLAT/SPARSE/ZERO VMDK descriptors; and checked deflate-compressed sparse VMDK
grains when the grain directory is present. Embedded names are never opened: pass each exact artifact
with `--backing`, nearest-to-farthest `--backing-layer`, `--extent NAME=PATH`, or `--segment`.
EWF2/Ex01, dirty VHDX log replay, QCOW2 LUKS keyslots/external data files, streamOptimized footer-only
directories, and SEsparse VMDK still decline rather than returning plausible corrupt bytes.

`ntfs-runs`, `ntfs-record`, and `ext-inode` recover non-resident runs/ADS/slack or deleted ext inodes.
`apfs-info`/`apfs-recover` validate Fletcher64 object blocks and recover exactly-covered stale file
extents. `apfs-omap` resolves the newest non-deleted mapping at an optional XID; `apfs-catalog` walks
checked inode/directory/embedded-xattr records, follows the inode private stream (so shared clone
extents work), and decodes inline zlib `com.apple.decmpfs` values. Nonzero extent crypto IDs,
resource-fork LZVN/LZFSE compression, and ambiguous checkpoints decline. `btrfs-info`/
`btrfs-recover` scan fsid-matching leaves, translate logical addresses through single-device chunk
items, and recover inline/regular raw, zlib, LZO, or Zstd extents with exact decoded sizes. LZO uses a
local `liblzo2`; RAID/multi-device mappings and encrypted/unknown encodings decline. Images are never
mounted.

### Binary host/mail artifacts and static malware

The mature readers remain the first choice: `windows.py` already covers registry/AmCache/EVTX/
Prefetch/LNK, `jumplist.py` handles Jump Lists, `ese_reader.py` handles SRUM, `nix_host.py` handles
plist/text journal exports/history/unified-log exports, and `email.py` handles EML/MSG/MBOX. The
Round-4 seam engine adds only what those readers did not already decode:

```sh
.venv/bin/python solvers/toolkits/artifact_depth.py journal system.journal --json
.venv/bin/python solvers/toolkits/artifact_depth.py pst mailbox.pst --json
.venv/bin/python solvers/toolkits/artifact_depth.py yara sample.bin --rules local.yar --json
```

The journal reader walks bounded binary DATA/ENTRY objects and exact-size XZ, LZ4, or Zstd fields.
PST/OST support validates the NDB header and CRC/type/BID/level-checks both BBT and NBT page trees,
then returns their block/node metadata plus UTF-16/ASCII/embedded-object carve leads. It stops before
Messaging-layer property/table-context decoding and never claims encrypted/high-encoding blocks.
The YARA-style reader supports literal/wide/nocase/
fullword and bounded hex wildcards/gaps plus boolean/`N of them` conditions without `eval`, native
YARA, or sample execution. Regex rules and unsupported conditions decline.

`solvers/toolkits/video_stego.py plan clip --json` emits a networkless ffmpeg extraction recipe;
`tracks` consumes local ffprobe JSON to surface subtitle, attachment, and data tracks; `frames`
analyzes supplied PNG frames for per-frame LSB, adjacent differences, and keyframe/DCT evidence.
The engine does not invoke ffmpeg itself on the host.
