# Toolkit `forensics`: disk / memory / capture STRUCTURE breadth

Built 2026-10-23 (backlog T-b, `docs/retro/day24plus-buildplan-web-toolkits.md`). A deliberately **narrow**
complement to the specialist forensic toolkits, not a competitor:

- `network` reads pcap/pcapng **payloads** (DNS, HTTP, TLS, credentials, carved files);
- `memory` reads Volatility tables and carves process / structure facts;
- `carve_stego` carves small disk images and ELF cores.

This toolkit answers only the **container / structure** facts those do not emphasise, and only for a format it
can validate from a real magic in the bytes. On a real network or memory challenge the specialist out-answers it
and this toolkit stands down; it never answers a packet count, a payload, a string's content or anything a payload reader
owns (those stay `None` here). Offline, static, standard library only.

## Run first

```bash
.venv/bin/python solvers/toolkits/forensics.py <file>...              # container facts per file
.venv/bin/python solvers/toolkits/forensics.py <file> --json         # as JSON
.venv/bin/python solvers/toolkits/forensics.py <file> --strings      # + a bounded strings sample (DATA)
```

As a solver: `solvers/toolkits/forensics.py` has `solve_set` (ranked candidate values via `labels.show(...)`)
and `signals(questions, files)` (0..1, 0.0 when nothing validates). Reason to the flag from the output and
submit it once via `ctf.submit.guarded_submit(...)` (or `./csctf submit <id> <flag>`).

By hand, from Python:

```python
sys.path.insert(0, "solvers/toolkits"); import forensics as T
T.classify(data)        # {"kind": "capture"|"memory"|"disk", "facts": {...}} or None
T.read_capture(data)    # {format, endian, linktype, linktype_name}  (pcap / pcapng)
T.read_memory(data)     # {format, os}  (windows_crashdump / minidump / lime / elf_core)
T.read_disk(data)       # {scheme, filesystem, boot_signature}  (MBR / GPT; FAT/NTFS/ext)
```

## What it reads

| Kind | Validated by | Facts (all unsure `labels.pick`) |
| --- | --- | --- |
| capture | pcap magic `a1b2c3d4` / `a1b23c4d` (either byte order) or pcapng SHB `0a0d0d0a` | capture format (pcap / pcapng), byte order, datalink / link-layer type |
| memory | `PAGEDUMP`/`PAGEDU64`, `MDMP`, LiME `EMiL`, or an ELF `ET_CORE` | dump format, OS hint (windows / linux) |
| disk | `0x55AA` boot signature + an MBR partition entry, `EFI PART` at LBA1, or an NTFS/FAT/exFAT/ext magic | partition scheme (MBR / GPT), filesystem (fat/fat32/ntfs/exfat/ext), boot signature present |

Packet counts, payloads, processes, strings content and the flag are **`None`** here — they belong to
`network` / `memory` / `carve_stego`, or to the agent. Bounded: 1 MiB read for structure, 1 MiB for the CLI
strings sample.

## Never-guess

Every format / scheme / filesystem name is an author-chosen label, so it is `labels.pick(key, options)` —
a ranked list of candidate values you read with `labels.show(...)`. Keys are
`forensics.<field>/<shape>` (`forensics.linktype/pcap`, `forensics.partition_scheme/disk`,
`forensics.dump_format/memory`). Nothing is ever plain, and the flag is always `None`.
