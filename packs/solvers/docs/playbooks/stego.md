# Stego — CSCTF 2026 playbook

Stego challenges hand you an image, audio file, text, or odd archive and hide a payload in it. The
offline engines read the common channels directly; the heavier programs (steghide, stegseek, outguess,
zsteg, sstv, sox spectrogram, multimon) run **only inside the Docker sandbox** via `stego_tools.py` —
never on the Mac.

```sh
cd <ctf-tools checkout>                   # every command on this page runs from the checkout root
export CTF_EVENT=<event slug>             # the event profile, events/<slug>/event.toml
.venv/bin/python -m ctf workdir --create  # the workdir (ctf.paths): $CTF_WORKDIR, else ~/ctf-work/<event>
# engines:  .venv/bin/python solvers/toolkits/<module>.py <file> [flags]
```

Treat the file as untrusted: keep it in its own directory, pass the path as an argument.

**Golden rule of this tree:** a payload is reported **PLAIN only when it proves itself** (stored
length+CRC, or a complete gzip/zip/file structure). Everything else comes back as an *unsure candidate*.
So corroborate soft hits (outguess, SNOW, zsteg guesses, spectrogram OCR) before you submit — the
submit guard stops you after 3 wrong answers.

---

## First moves (the moment you open a stego challenge)

1. `./csctf check <id>` — already solved by a teammate? Skip.
2. `.venv/bin/python solvers/metadata-forensics/file_properties.py <file>` — true format, size, image
   dims. Does the extension match the magic? Do the IHDR dims match the real pixel data?
3. `.venv/bin/python solvers/toolkits/carve_stego.py <file>` — **always.** Catches trailing bytes after
   the end marker, embedded files, polyglots, spatial LSB, zero-width text, QR/barcodes, DTMF in one shot.
   (Verified: it surfaces data appended after `IEND` and `--extract` pulls it out.)
4. Branch by carrier type (image / JPEG / audio / text) using the sub-types below.
5. Only reach for the sandbox (steghide/stegseek/outguess/spectrogram/SSTV) once the pure-Python
   readers come up empty. Keep the solve path in `notes.md`.

---

## Engine CLIs by carrier

### Any image/archive/blob — carving & structural stego
- `solvers/toolkits/carve_stego.py <file>... [--extract DIR] [--json] [--quick]`
  Prints: where the file's own structure ends, **trailing bytes** after it (with a preview), validated
  **carved embedded files**, **polyglots**, PNG/JPEG/GIF chunks + comments, spatial **LSB** planes that
  parse, **zero-width / Unicode-tag / variation-selector / whitespace** text channels, **QR/Aztec/
  DataMatrix/PDF417/1D** codes, text-grid codes, nested codes, and small filesystems. `--extract` writes
  every carved member to DIR. This is the workhorse — run it first on everything.

For a carrier that is structurally damaged rather than merely hiding a trailer, use the conservative
repair pass. It writes nothing unless the rebuilt candidate reparses and its compressed payload validates:

```sh
.venv/bin/python solvers/toolkits/file_repair.py broken.png --output repaired.png --json
.venv/bin/python solvers/toolkits/file_repair.py truncated.zip --output recovered.zip
```

It covers PNG signature/chunk CRC/IEND, CRC-proven ZIP local members, classic PDF xref, complete gzip
DEFLATE, and complete bzip2 stream prefixes. A refused artifact needs manual carving; the engine never
guesses missing compressed bytes.

### PNG / BMP / GIF / WebP — spatial LSB
- `solvers/toolkits/stego_containers.py <file>...`
  Pulls the usual LSB planes and keeps only a payload that **self-validates** (len+CRC or gzip/zip
  checksum). Prints `PLAIN …` with sha256 when one validates, else `unsure` candidates / a note. This is
  your "is there a real LSB payload" oracle.
- Sandbox `zsteg` (via `stego_tools.py` or raw) reads the wider sweep of channel orders and the
  `extradata` trailer, and OCR/`pngcheck` catch the rest.

#### Deep spatial orders and channel arithmetic

`carve_stego.py` also auto-judges the recurring StegSolve-style variants: alternating-row
(`snake`) and alternating-column traversal, XOR of low bit planes, RGB channel XOR/add/subtract/
absolute-difference, and adjacent-pixel pair parity. Library callers can use `lsb_extract(...,
order="snake"|"column"|"column_snake")`, `cross_plane_xor_extract`,
`channel_arithmetic_extract`, and `adjacent_pixel_parity_extract` directly. Results enter the normal
`[lsb]` candidate list only when the existing file/text validator accepts the recovered bytes.

For a challenge-supplied permutation key, pass that exact value—there is deliberately no wordlist or
key guessing:

```sh
.venv/bin/python solvers/toolkits/carve_stego.py image.png --lsb-passphrase 'brief-supplied key'
.venv/bin/python solvers/toolkits/carve_stego.py image.png --lsb-seed 0x1337 --json
```

The keyed order is a SHA-256-seeded Fisher–Yates pixel permutation, capped at two million pixels and
16 explicitly supplied keys. `permuted_lsb_extract(...)` exposes the same operation to a challenge
script. If the brief does not specify this permutation convention, treat a miss as inconclusive—do
not generate candidate passwords.

### JPEG — DCT-domain stego (zsteg can't read these)
- `solvers/toolkits/jpeg_stego.py <file>... [--survey]`
  **jsteg** DCT-coefficient LSB extraction for baseline JPEGs. Prints `PLAIN` on self-validation, else
  unsure candidates. `--survey` sweeps coefficient rules × bit orders **plus** pixel bit-planes 0–7.
- `solvers/toolkits/f5_stego.py <file>...`
  **F5** matrix-encoding read (k=1..7) + the extra LSB channel orders the main sweep omits. Prints
  `PLAIN`/`none` + method. Note: only the **un-permuted / no-password** F5 order is implemented (the
  password-keyed SHA1PRNG shuffle is deliberately not) — if F5 used a password, that's a sandbox/guess
  problem, not this reader.
- For `outguess`-embedded JPEGs, use the sandbox (`stego_tools.py` → `outguess_extract`); outguess has no
  self-check, so its output is a candidate, not proof.

### Audio (WAV / AIFF / any container)
- `solvers/toolkits/audio_stego.py <file>... [--extract DIR]`
  The "listen differently" axis: produces **reversed (backmasking)**, **stereo L−R difference**,
  **half-speed**, and **AIFF-LSB** renderings as candidates. `--extract` writes the transformed WAVs so
  you can feed them to the spectrogram / SSTV / DTMF tools below.
- `carve_stego.py` already does WAV sample-LSB and **DTMF** (Goertzel) in pure Python.
- Sandbox (via `stego_tools.py`): **spectrogram** (sox) + OCR of it, **SSTV** decode, **multimon-ng**
  (DTMF / POCSAG / AFSK1200), **minimodem** (Bell/RTTY FSK), `ffprobe` metadata.

### Text
- `carve_stego.py` reads **zero-width characters**, **Unicode tag** chars, **variation selectors**, and
  **trailing-whitespace** bit channels directly — no extra tool needed.
- SNOW (whitespace-encoded) text: sandbox `stegsnow` via `stego_tools.py` (`stegsnow(data, password)`).
  SNOW has no checksum, so its output is always a candidate.

### QR / barcodes
- `carve_stego.py` decodes codes offline (zxing-cpp / pyzbar). For a photo the offline reader misses,
  sandbox `zbarimg`.

---

## Docker sandbox tools (`csctf-sandbox:2`)

Prefer the **`stego_tools.py` wrapper** — it runs the right program inside `tools/sandbox.py`, copies the
bytes in, handles `/out`, and keeps the never-guess rules (e.g. a steghide CRC is proof; outguess/SNOW
are not). Confirm the sandbox is up: `tools/sandbox.py status`.

```sh
# the wrapper: runs every fitting stego program and prints what each found
.venv/bin/python solvers/toolkits/stego_tools.py <file> [--extract DIR]
.venv/bin/python solvers/toolkits/stego_tools.py --tools        # what's runnable right now

# steghide: capacity, then extract with a passphrase the CHALLENGE gave you
.venv/bin/python solvers/toolkits/stego_tools.py --pass 'theP@ss' <file.jpg> --extract out/
# stegseek: try ONLY the words the challenge supplies (never rockyou, never archive passwords)
.venv/bin/python solvers/toolkits/stego_tools.py --wordlist words.txt <file.jpg> --extract out/
# SSTV recording -> picture
.venv/bin/python solvers/toolkits/stego_tools.py --sstv <signal.wav> --extract out/
```

Raw `tools/sandbox.py run` lines (verified invocations) when you want a tool directly:

```sh
.venv/bin/python tools/sandbox.py run --in img.png zsteg -a {in}        # LSB sweep + extradata
.venv/bin/python tools/sandbox.py run --in img.png pngcheck -v {in}     # chunk/CRC, "data after IEND"
.venv/bin/python tools/sandbox.py run --in img.png zbarimg {in}         # QR / barcodes
.venv/bin/python tools/sandbox.py run --in img.jpg exiftool {in}        # metadata / comment fields
```

Full stego `:2` kit: `steghide stegseek zsteg outguess stegsnow` · `tesseract` (OCR) ·
`exiftool exiv2 pngcheck` · `zbarimg qrencode` · `ffmpeg ffprobe sox` · `sstv pysstv` ·
`multimon-ng minimodem rtl_433` · `foremost scalpel bulk_extractor`.

---

## Techniques → engines (cheat sheet)

| Hiding method | Reach for |
| --- | --- |
| Data appended after `IEND`/`EOI`/`%%EOF` | `carve_stego.py` (trailing), `pngcheck -v` |
| Embedded file / polyglot (zip-in-png, etc.) | `carve_stego.py` (carve/polyglot, `--extract`) |
| Spatial LSB in PNG/BMP/GIF | `stego_containers.py`; sandbox `zsteg -a` |
| JPEG DCT LSB (jsteg) | `jpeg_stego.py` (`--survey`) |
| JPEG F5 / matrix encoding | `f5_stego.py` |
| JPEG outguess | sandbox `outguess` via `stego_tools.py` |
| DCT/DWT QIM, spread spectrum, adaptive LSB, matrix syndrome | `transform_stego.py` |
| steghide (JPEG/BMP/WAV/AU, passphrase) | `stego_tools.py --pass` / `--wordlist` |
| LSB / reversed / stereo-diff / half-speed audio | `audio_stego.py` (+`carve_stego` WAV LSB) |
| Spectrogram text, SSTV picture | `stego_tools.py --sstv`; sox spectrogram |
| DTMF / Morse / POCSAG / AFSK tones | `carve_stego.py` (DTMF); sandbox `multimon-ng` |
| Parameterized BFSK / differential BPSK | `signal_stego.py` |
| Zero-width / whitespace / Unicode-tag text | `carve_stego.py`; `stegsnow` for SNOW |
| QR / Aztec / DataMatrix / PDF417 | `carve_stego.py`; sandbox `zbarimg` |
| EXIF comment / metadata | `file_properties.py`; sandbox `exiftool` |

---

## Getting the flag out & submitting

Flags look like `csctf{...}` (also `flag{...}` / `chronos{...}`). The payload a tool recovers **is**
the flag when it reads as one — a `PLAIN` self-validated payload, a carved trailer, a decoded QR/DTMF, an
OCR'd spectrogram line. Submit it **once**:

```sh
./csctf submit <id> 'csctf{...}'          # routes through ctf.submit.guarded_submit
```

From a solver: `ctf.submit.guarded_submit(ctfd, ch, flag, provenance="zsteg b1,rgb,lsb")`. The guard
format-checks, dedupes, paces, skips team-solved, and **stops after 3 wrong**. `labels.pick/candidates`
only rank candidates for you to read — they never auto-submit. Because soft channels (outguess, SNOW,
zsteg guesses, OCR) aren't self-proving, **confirm a candidate before submitting** (two readings agree,
or it already matches the flag format) rather than burning guesses.

## Scope & safety

- Stego is fully offline — no live target, so the scope rules reduce to: **detonate external tools only
  in the Docker sandbox** (`tools/sandbox.py`), never run an untrusted artifact on the host.
- **No password brute-forcing.** stegseek runs only against the **challenge-supplied** wordlist — never
  rockyou, never a generated list, never the archive-password store. A cover locked by an unknown
  passphrase is a stop-and-ask, not a sweep (AGENTS.md fair-play: no brute-forcing).

## Matrix barcodes and video

`solvers/toolkits/qr_matrix.py input --json` is the dependency-free matrix-barcode fallback behind
`qr_decode.py`: it accepts a 0/1 matrix, ASCII grid, or bounded raster and tries rotations, mirror,
and inversion. QR v1--40 supports all masks/block layouts and numeric/alphanumeric/byte/Kanji/ECI.
The `matrix_barcodes.py` sibling decodes classic ECC200 plus all 18 DMRE Data Matrix sizes (ASCII,
C40, Text, X12, EDIFACT, Base256, ECI), compact/full Aztec, ordinary/Compact PDF417, and all 34
MicroPDF417 variants. Finder/RAP/mode metadata and the appropriate Reed--Solomon field must verify
before bytes are returned. For a photographed label, supply outer module-boundary corners and the
logical size; the sampler corrects a projective quadrilateral and optional cylindrical wrap:

```bash
.venv/bin/python solvers/toolkits/qr_matrix.py label.png --json \
  --dimensions 64x8 --corners '18,18;497,31;488,105;24,119'
.venv/bin/python solvers/toolkits/qr_matrix.py curved.png --json \
  --dimensions 33x33 --corners '25,20;292,42;265,290;40,270' --curve .7
```

Without explicit geometry it ranks bounded Otsu/bounding-box/extreme-point candidates. Severe lens
distortion, arbitrary spline-curved labels, occluded corners, and perspective PDF417 with unknown
logical row count still require a human-provided crop/dimensions (or a sandboxed reference tool).

For video, use `video_stego.py plan` to create the Docker ffmpeg recipe, then run `frames` on the
extracted PNGs and `tracks` on saved ffprobe JSON. It ranks LSB, inter-frame-difference, I-frame/DCT,
subtitle, attachment, and data-track leads without decoding an untrusted container on the host.

## Verified transform and digital-signal payloads

`transform_stego.py` provides bounded, dependency-free PGM extraction for 8x8 DCT-QIM, one-level
Haar-DWT HH-QIM, keyed direct-sequence spread spectrum, stable edge-adaptive LSB, and generic
Hamming/matrix-syndrome encoding. `signal_stego.py` decodes caller-parameterized BFSK and DBPSK from
saved PCM WAV files. Both deliberately return no payload unless the embedded `C5TG` length and CRC-32
frame verifies; unknown parameters or a soft correlation are leads, not submit-ready values.

```bash
.venv/bin/python solvers/toolkits/transform_stego.py dct image.pgm
.venv/bin/python solvers/toolkits/transform_stego.py spread image.pgm --seed 001122
.venv/bin/python solvers/toolkits/signal_stego.py bfsk audio.wav --baud 100 --mark 1400 --space 900
.venv/bin/python solvers/toolkits/signal_stego.py dbpsk audio.wav --baud 100 --carrier 1000
```

Use `signal_stego.py plan audio.wav` for the existing human-reviewed, networkless Docker follow-ups
covering multimon/minimodem AFSK and POCSAG, SSTV, and spectrogram OCR.
