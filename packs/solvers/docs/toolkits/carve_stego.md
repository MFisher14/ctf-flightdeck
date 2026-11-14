# Toolkit `carve_stego`: carving, structural stego, QR and barcodes, small disk and dump images

Files: `solvers/toolkits/carve_stego.py` (readers, `signals`, `solve_set`, CLI) and
`solvers/toolkits/carve_stego_fs.py` (file systems and dumps). Offline, no network request.
Tests: `.venv/bin/python tests/test_tk_carve_stego.py`.

## Run first

```
.venv/bin/python solvers/toolkits/carve_stego.py <file>...            # triage, about a second
.venv/bin/python solvers/toolkits/carve_stego.py <file>... --extract DIR   # also write what was carved
.venv/bin/python solvers/toolkits/carve_stego.py <file>... --json     # the same as data
.venv/bin/python solvers/toolkits/carve_stego.py <file>... --quick    # structure only: no pixels, samples or codes
```

A delivery saved by the tools is unpacked first: `tools/unpack.py <attempt dir>`, then point the
command at `members/`. Each file prints its kind, where its own structure ends, and one line per
finding: `[channel] method kind=... N bytes sha256=...`, with the text under it when there is one.

| Channel | What it is |
| --- | --- |
| `trailing` | bytes after IEND, EOI, the GIF trailer, the last `%%EOF`, the zip's EOCD, the RIFF size, the ELF or PE end |
| `carved` | a file proven by its own structure at an offset: zip (by EOCD), 7z (header CRC), gzip and zlib (whole stream), png, jpeg, gif, pdf, elf, pe, riff; `rar` is listed NOT VALIDATED |
| `member` | a file inside a carved or trailing archive (encrypted ones only under `archive_passwords.py`) |
| `png_chunk`, `png_text`, `png_crc` | a chunk outside the PNG registry; bytes inside IDAT after the zlib stream, and inflated bytes after the last scanline (`cs.png_idat_extra`); tEXt, zTXt, iTXt; a wrong CRC (for IHDR: the size that fits it) |
| `comment`, `wav_chunk` | JPEG COM, GIF comment, zip comment; an unusual RIFF chunk, LIST/INFO text |
| `lsb`, `wav_lsb` | an LSB reading that parses: a file by its magic and structure, a NUL-ended or length-prefixed text; a sentence of 20 characters or more that starts inside the first 2 KiB of a reading (`... from byte N`); two bits a sample (`bits10`, `bits01`); for a BMP also the pixel bytes as stored (text typed over them) and the stored bytes with their row padding |
| `dtmf` | DTMF keys by Goertzel |
| `code` | QR, Micro QR, Aztec, DataMatrix, PDF417, MaxiCode, 1D codes; also a code drawn in text, in a later GIF frame, or in bit 0 of one channel; nested codes are followed 6 levels |
| `zero_width`, `whitespace` | zero-width bits, Unicode tag characters (ASCII smuggling), variation selectors, spaces and tabs at line ends |
| `fs`, `deleted` | an MBR or GPT partition table (`cs.fs.partitions`; logical partitions too), each partition walked as a disk of its own (`<image> -> partitionN`); an NTFS or exFAT volume is named and marked NOT READ with the sandbox command; entries of ISO9660 (Joliet names), FAT12/16/32, ext2/3/4, cpio; deleted FAT entries and ext names left in directory slack, with their bytes when the blocks survive |
| `recycle`, `dump`, `uimage`, `polyglot` | a `$I` record; minidump streams or ELF core notes; a U-Boot header; a file that is two formats |

## By hand (`sys.path.insert(0, "solvers/toolkits"); import carve_stego as cs`)

- `cs.primary(data)`, `cs.trailing(data)`, `cs.carve(data)`, `cs.zips(data)`, `cs.polyglot(data)`
- `cs.png_chunks`, `cs.png_text`, `cs.png_pixels`, `cs.png_fix_dimensions`, `cs.jpeg_segments`, `cs.gif_blocks`, `cs.bmp_pixels`, `cs.wav_info`
- `cs.lsb_extract(px, "RGB", bit=0, order="xy", msb_first=True)` for one plane; `cs.lsb_scan(px)` tries
  RGB, BGR, each channel, RGBA, A; bits 0 and 1; rows and columns; both bit orders (56 readings)
- `cs.wav_lsb(data)`, `cs.dtmf(data)`
- `cs.zero_width(text)`, `cs.whitespace_bits(text)`
- `cs.decode_codes(image_bytes)`, `cs.text_grid(text)`, `cs.decode_grid(text)`, `cs.decode_nested(data)`
- `cs.fs.iso9660`, `cs.fs.fat`, `cs.fs.ext2`, `cs.fs.cpio`, `cs.fs.uimage`, `cs.fs.recycle_i`, `cs.fs.minidump`, `cs.fs.elf_core`
- `cs.scan(name, data)` for every finding of one file; `cs.carved_files(files)` returns the carved
  and recovered members as `'<file> -> <member>'` entries: add them to `files` and call
  `solvers/common/triage.py` or `solvers/toolkits/evidence_core.py` again.

## Question shapes `solve_set` answers

It answers only a question whose words name a channel: hidden, secret, appended, trailing,
embedded file, carved, chunk, comment, LSB, least significant, steganography, QR, barcode, DTMF,
dialed, zero-width, invisible, whitespace, deleted, Recycle Bin, disk image, file system, floppy,
ISO, cpio, initramfs, minidump, core dump. Everything else is `None`. A question in another category's
id form (`Determine <property> for <file>`, `ANS-`, `dNN_`, `-role`) is `None` too.

| Question | Answer |
| --- | --- |
| a flag or value with a `pattern`, hidden anywhere | plain, when exactly one value in all channels fits the pattern |
| SHA-256, SHA-1, MD5 or size of the appended, embedded or deleted file | plain, when there is exactly one such item |
| SHA-256, SHA-1 or MD5 of a file inside the disk image or carved archive, named in the question (and a channel word: disk image, file system, ...) | plain, when the name fits live entries of one content (the same file in two partitions is one fact) |
| "what does the QR code say", "the comment", "the zero-width text", DTMF digits | plain, when the named channel holds one single-line payload |
| DTMF with `*`, `#` or letters among the keys | unsure: `keys`, `digits_only` |
| a hidden message with no pattern and no named channel | unsure: `text`, `last_line`, `first_line`, `inside_braces` |
| offset of the hidden data | plain decimal for kind `integer`; unsure between `0x1f4`, `1f4`, `0x1F4` when hex is asked |
| "how many IDAT chunks", "how many chunks", deleted files, modules, threads | plain |
| "how many files" with deleted entries or folders about | unsure: `live`, `live_and_deleted`, `top_level` |
| type of the hidden file, of the file system, of the code | plain when the question lists options and one fits; else unsure |
| name of the deleted file, of the odd chunk, of the archive's one member | plain when there is one spelling; unsure between long and 8.3 name, name and path |
| original path in a `$I` record | plain; the bare file name and the deletion time are unsure |
| `message` (the Warmups form) over a picture or a recording | unsure under `warmups.message/carve_stego.<channel>`: `last_line`, `whole` |

Two candidates always give `None`; a question that names its file is answered from that file only.

When `None` or unsure comes from a limit and not from the bytes (review of 2026-10-08):

- A scan the budget cut short (1 s by default, 20 s for a longer scan, or
  `ctx["carve_stego_budget"]`) or a size limit trimmed (16 MiB carved, 1 MiB of text, 32 GIF frames,
  5000 entries) answers nothing for the set: "the one hidden item" is not proven. The CLI has no budget.
- DTMF is plain only when four window positions read the same keys, the envelope shows as many bursts as
  keys, and the recording was read whole (`cs.dtmf_read(data) -> (keys, sure)`).
- A value found by the question's pattern inside a longer text must stand alone (white space, quotes or
  sentence punctuation around it).
- A deleted FAT file has bytes only while every cluster of its span is still free; an ext name left in
  slack whose inode is in use again is `stale` (count and name unsure, no hash).
- The hash or size of loose bytes after a file's end with NULs or line ends around them is unsure
  (`as_is`, `stripped`); a FAT label that differs between boot sector and root directory is unsure; a PNG
  tEXt value is "the comment" only under the keyword Comment or Description, or one the question names.

## Label vocabulary (lowercase snake_case, best first)

- types: `zip`, `zip_archive`; `png`, `png_image`; `jpeg`, `jpg`; `pdf`; `gzip`, `gz`; `7z`, `7zip`;
  `rar`; `elf`; `pe`, `exe`; `wav`; `zlib`; `text`, `plain_text`
- file systems: `fat12`, `fat16`, `fat32`, `fat`; `ext2`, `ext3`, `ext4`; `iso9660`, `iso`; `cpio`
- codes: `qr_code`, `qr`; `aztec`; `data_matrix`, `datamatrix`; `pdf417`; `code128`; `code39`; `ean13`
- dumps: `minidump`, `mdmp`; `elf_core`, `core_dump`
- techniques an author may ask for (not answered here, offer them with `labels.pick`):
  `appended_data`, `trailing_data`, `lsb_steganography`, `lsb`, `custom_chunk`, `ancillary_chunk`,
  `polyglot_file`, `zero_width_characters`, `unicode_tags`, `whitespace_steganography`,
  `nested_qr`, `deleted_file`, `file_carving`, `dtmf_tones`, `metadata_comment`
- keys: `carve_stego.<field>/<shape>` with field `payload`, `type`, `name`, `count`, `offset`, `time`.
  `labels.py` does not know the prefix `carve_stego` yet, so these are written in the wire form and
  read as ranked candidates (`labels.show`).

## Not here (agent work)

- No password guessing: an encrypted member is opened only with `archive_passwords.py` (`infected`
  and the player's stored ones). steghide, outguess and stegseek are in the sandbox since round 2
  (`solvers/toolkits/stego_tools.py`, [stego_tools.md](stego_tools.md)); a passphrase is still tried only
  when the question states it.
- No OCR, SSTV, spectrogram text or Volatility in this file. They run in the sandbox through
  `stego_tools.py` (tesseract, sstv, sox and ffmpeg, zbar, foremost, sleuthkit's `fls` and `icat`), never
  natively on the host. Other hostile formats go through `tools/sandbox.py run binwalk|7z|vol ...`.
- Not read: NTFS, exFAT, HFS, squashfs, JFFS2, ext4 with inline directories, PNG interlace without
  Pillow, JPEG DCT-domain stego (jsteg, F5), palette-order stego, audio phase or echo hiding,
  Morse in audio, SNOW's compressed mode, homoglyphs.
- The image and code readers need `Pillow` and `zxing-cpp` in `.venv` (`pyzbar` is the fallback);
  without them the `code` channel is empty and everything else works.

## Real artifacts (2026-10-08, `tests/real/test_real_carve_stego.py`)

Run on 33 real files: zsteg's sample pictures against zsteg's own expected output, zbar's barcode examples
against zbar's recorded output, dfvfs's disk images against a 7-Zip listing made in the sandbox, rust-minidump's
dumps against its stackwalk snapshot, Huntress 2025 "QRception" and Huntress 2024 "Unbelievable". No crash; the
slowest scan is 1.0 s (a 4 MB PNG). What the real files changed:

- **A code's text was zxing-cpp's display form**: a line break came back as `<LF>`, an escape as `<ESC>`, a
  GS1 code with brackets. The payload is now read as written (`TextMode.Plain`). This was a wrong plain answer
  for any QR holding more than one line.
- A QR printed in half blocks under one ANSI colour pair (`qrencode -t ANSIUTF8`) is read; QRception is closed
  by the toolkit alone.
- `signals` reads the codes of up to four small pictures (a picture that is a code: 0.5) and notes a picture or
  recording named as another type (0.3).
- IDAT extras, BMP stored-byte readings, two bits a sample, text that starts inside a reading, partition
  tables, the NTFS note, the hash of a named file in a disk image.

Still not read: three bits a sample and more, palette-index and prime-step LSB, the tools zsteg knows by name
(Camouflage, OpenStego, wbStego, steganography-png), NTFS and exFAT (named only), a flag drawn as picture
text (OCR: `tesseract` is on this Mac, run by hand). The record is `docs/toolkits/real-data.md`.

Review (2026-10-08, `tests/test_tk_real_c_review.py`): a question that negates what it asks (`not`, `n't`, `except`, `other than`) is
`None`. The hash or the size "of the disk image / the picture / the archive" is the container's own and is
`None` here (it used to be answered with the one hidden item's). The hash of a named file is plain only for the
phrase "the <hash> of <name>", for an entry read whole, with no deleted entry of the same name and none of the
words that turn it into another question (hidden inside, deleted version, first line, slack). A partition is a
marker, never a directory or a file; a partition with data this toolkit cannot walk makes every answer about
the disk `None` (an all-zero, swap or extended entry does not), and "files including deleted ones" is `None`.
NOTE: zxing-cpp cannot be interrupted: one noise picture of 16 megapixels costs about 1 s, so a set can run
to about twice its 1 s budget; `signals()` spends at most about 1 s on four pictures.

Deep LSB readings (R-15, 2026-11-10): `lsb_deep_scan` (the CSCTF snake and column-snake orders, cross-plane
XOR, channel arithmetic and adjacent-pixel parity) runs inside every picture's scan, so it shares the 1 s
budget. Its readers work on whole rows, columns and planes (`_selected_samples`, big-integer XOR, `translate`
tables), not pixel by pixel: about 0.01-0.1 s CPU on a 500x500 picture, where the per-pixel port took 2-3 s and
left the older readings (stg300's LSB flag, QRception's nested QR under load) cut short by the budget. At
bit 0, `add`, `sub` and `absdiff` of two channels have the parity of their `xor`, so the four operations give
one reading there. `tests/test_carve_stego_deep_cost.py` holds the readers to per-pixel definitions and bounds
their CPU cost.
