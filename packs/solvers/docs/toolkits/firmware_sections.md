# Toolkit `firmware_sections`: firmware section-table walker

Built for B-069. A vendor firmware bundle is a header, a table of sections (name, offset, size,
checksum) and the sections. This engine finds the table by what every such table has in common (a
record names a byte range of the same file and that range's CRC-32), then hands each section to the
readers the tree already has. No vendor magic is needed.

## Run first

```bash
.venv/bin/python solvers/toolkits/firmware_sections.py firmware.bin --event <slug> [--out DIR]
python -m ctf run toolkits.firmware_sections <challenge_dir>
```

Intake runs it with no model on any file matching `magic:DWFW`, `name:*firmware*`, `.fw`, `.bin`,
`.img` or `.rom` (`magic:DWFW` is one known vendor magic; the walk itself needs none). A file with no
CRC-confirmed table and no CRC-valid U-Boot env is skipped. Files are read and walked one at a time,
so only one is in memory at once.

## What it does

| Step | Reader | Result |
| --- | --- | --- |
| Section table | `find_tables` | records whose (offset, size) words name a range in the file and whose checksum word is its CRC-32 (IEEE or without the final inversion, either byte order, the three fields within 60 bytes); the stride from two confirmed neighbours; a record on the stride with a wrong CRC is listed `crc_ok: false` |
| U-Boot env | `firmware_walk.env_copies`, `pick_live_env` | every copy in the image, each behind its own CRC; the live copy by U-Boot's flags-counter rule |
| zlib preset dictionary | `carving.carve_all(zlib_dictionaries=...)` | a section whose Adler-32 is the DICTID of a stream in the image is passed as that stream's dictionary |
| gzip / bzip2 / xz / zlib | `carving.carve_all` | every stream in a section, inflated |
| cpio | `carve_stego_fs.cpio` | members of every section or inflated payload that is one |
| SquashFS / JFFS2 / UBI / DTB | `firmware_walk` | members of every section that is one |
| Flags | `ctf.flagfmt` | read verbatim from sections, payloads, members and CRC-valid env values; printable ASCII only, and 8+ characters while the event prefix is unknown |
| Keyed XOR | `keyed_xor_sweep` | each hex or base64 token in the extracted files XOR each CRC-valid env value (text, MAC / hex bytes), repeating key; a hit passes the same printable and length rule as a verbatim flag |

## What the result means

- `solved`: one flag read verbatim from the extracted content.
- `candidate`: several flags, or a flag only the keyed XOR produced. Nothing ties a token to an env
  variable except that the whole decoded token is one value in the event flag format, so this is a
  lead. The evidence line says which copy the key came from and whether it is the live one.
- `unsure`: a table or an env was read and no flag was found. Read `report.json`.
- `none`: no file holds a section table or an env.

Output: `<challenge>/recon/firmware_sections/<file>/report.json` (table, env copies, streams,
members, tokens, notes) and `extracted/` (inflated payloads and archive members, names flattened).

## Limits (each is named in the result notes when it applies)

- Section offsets are absolute. Table-relative offsets and (start, end) pairs are not read.
- The table must start within the first 64 KiB and its three fields lie within 60 bytes.
- A record with a wrong CRC is recovered only when two confirmed records sit one stride apart.
- A section over 8 MiB is not scanned for compressed streams (32 MiB in total per file).
- `carve_all` takes dictionaries up to 32 KiB: a longer dictionary section is named, not used.
- A header CRC is not checked; only the per-section checksums are.
