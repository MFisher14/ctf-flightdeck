# Toolkit `firmware_walk`: firmware / flash image content walker

Built 2026-10-24 (backlog key **firmware-image-walker**). Reads the firmware **containers** that
`carve_stego_fs.py` (ISO/FAT/ext/cpio/uImage) and the binary / generic engines (magic-detect only) do not walk,
and is distinct from the generic `fs_walk` track. All plain Python, read-only, bytes in and structure out —
nothing mounts, executes, writes or inflates anything a non-stdlib codec is needed for.

## Run first

```bash
.venv/bin/python solvers/toolkits/firmware_walk.py <members>...      # the walk, as text
.venv/bin/python solvers/toolkits/firmware_walk.py <members>... --json
```

As a solver: `signals()` / `solve_set()` are the runner contract; `solve_set` returns ranked candidate
values (`labels.show(...)`). Reason to the flag from them and submit it once via
`ctf.submit.guarded_submit(...)` (or `./csctf submit <id> <flag>`).

By hand: `walk(files) -> {"images": [{name, kind, ...}]}` lists every container found in the delivery.

## What it reads

| Container | Parse |
| --- | --- |
| SquashFS 4.0 | superblock + inode table + directory table + regular-file extraction; gzip (zlib) and xz/lzma via stdlib; lzo/lz4/zstd entries listed (name, size), content `None` |
| JFFS2 | dirent + inode node walk, header/node/data CRC checked, newest inode version wins; content only for none/zero/zlib |
| UBI + UBIFS | UBI PEB→LEB volume map stripped, then UBIFS nodes (common header CRC checked): dentry names, inode sizes; file content left `None` |
| DTB / FDT | the flattened device tree: node paths and property values |
| U-Boot env | the leading CRC32 over the key=value area validated FIRST; only then the variables; a CRC mismatch yields no values |
| Redundant U-Boot env (B-069) | `env_copies(data)` splits a region into its copies wherever they start (each `crc32 \| [flags] \| data`, the length found by the CRC); `pick_live_env(copies)` takes the live one among the CRC-valid copies by U-Boot's flags-counter rule (0 beats 255 on a wrap, else the higher counter, equal keeps the first). `walk()` reads such a region through its live copy and lists `copies`, `live`, `live_reason` |

## Never-guess

A file/dir **name** and **size**, and a device-tree **property value**, read from a structurally-complete,
CRC/length-consistent parse are a deterministic read → **plain-eligible**. The spelling/separator of a **path**
is the author's choice → `labels.candidates` (unsure). A U-Boot env variable value is plain only when the
leading CRC32 validates the whole env area; a CRC mismatch → `None`. A truncated/ambiguous parse → `None`,
never a partial guess. The label prefix is `firmware`; the flag is always `None`.
