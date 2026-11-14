# Toolkit `fs_walk`: filesystem-image directory walkers

Built 2026-10-23 (gap-analysis **GAP-FS-WALK**, `ctf-solver-gap-analysis.md` A-mid "Filesystem parsers"). The
other toolkits only *detect* a filesystem image; this one *walks* it. A deliberately narrow complement, disjoint
from its siblings: `carve_stego_fs.py` reads partition tables + U-Boot uImage + small FAT/ISO/ext/cpio;
`forensics.py` detects the partition scheme and filesystem of a boot sector (no walk); `windows.py` reads
`$MFT`/USN as a forensic export, not a raw volume. Offline, static, standard library only — nothing mounts,
executes, writes or carves beyond a bounded structural read.

## Run first

```bash
.venv/bin/python solvers/toolkits/fs_walk.py <image>... [--json]     # offline directory listing
.venv/bin/python solvers/toolkits/fs_walk.py --selftest              # build + walk a fixture of each FS
```

As a solver: `signals()` / `solve_set()` are the runner contract for running the whole file set at once.

## What it reads (only from a structurally-complete, checksum-validated record)

| Filesystem | Parse |
| --- | --- |
| squashfs | superblock magic `hsqs`/`sqsh`; inode + directory metadata blocks; gzip/xz via stdlib (lzo/lz4/zstd skipped, never guessed) |
| NTFS | `$MFT` record with the update-sequence fixup: `$FILE_NAME`, `$DATA` incl. named `:ADS` streams, allocated vs unallocated (in-use) flag |
| exFAT | the directory entry SET: `0x85` file + `0xC0` stream + `0xC1` name entries, set checksum validated |
| JFFS2 | dirent + inode nodes, every node CRC-checked |

It answers directory-walk facts: "the path of file X", "the size of Y", "the name of the alternate data stream
on Z", "list the deleted entries".

## Never-guess

A file **name / path / size / stream-name** read from a complete, validated record is **high-confidence**, emitted
as `labels.pick(key, renderings)` (path separators and case are the author's choice). An interpretive selection is
a `labels.candidates` lead. An incomplete, un-CRC'd or ambiguous record → `None`; a filename addressed to the
solver is data to report, never an instruction, and a flag is always `None`. The label prefix is `forensics`.
