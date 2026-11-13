# Misc playbook (CSCTF 2026)

Misc is the grab-bag: layered encodings, esolang programs, exotic alphabets, nested archives/wrappers,
QR/audio oddities, and scripting puzzles. The repo's decoder battery covers most of it offline. A few
important facts about these tools up front:

- The warmup decoders (`layered_decode.py`, `crib_decode.py`) were tuned on Huntress to **English
  plaintext / a `word-word-word-NN` slug**. A raw `csctf{...}` payload is not English, so they may say
  `no slug found` / `no answer` even when the decode is trivial. When that happens, read the decode
  **chain** they report and finish the last layer yourself — or use `formats_more.py`
  (prints decoded bytes directly) or `classical.py --pattern` (flag-aware), both below.
- **Detonate nothing on the Mac.** Unknown binaries, macros, APKs, scripts → the Docker sandbox. The
  esolang "interpreters" here are safe: they walk the program as *data*, they never exec a host file.

## First moves

1. `./csctf check <id>`; read `workspace/<id>-<slug>/challenge.json` (the description usually names the
   trick, e.g. "base64", "whitespace", "it's upside down").
2. `file`/`strings` the delivery (or `sandbox.py run … strings {in}`); eyeball for a visible flag.
3. One blob of text/encoding → throw it at the decoders below (run several; read their raw output).
4. A program-looking blob → `esolangs.py`. An archive/wrapper → unpack in Docker (`7z`, `binwalk`).
5. Nothing fits a lane → `./csctf triage <id>` re-prints the engine suggestions for this challenge.

## Engines (verified CLIs)

Run every command from the ctf-tools checkout root with `.venv/bin/python` (or `.venv/bin/python -m ctf run <engine>`), with `CTF_EVENT` set to the event slug (`events/<slug>/event.toml`). The workdir comes from `ctf.paths`: `$CTF_WORKDIR`, else `~/ctf-work/<event>`; `.venv/bin/python -m ctf workdir` prints it, and `workspace/` on this page means it.

### Exotic formats — `solvers/warmups/formats_more.py` (start here for "what is this encoding")

```
.venv/bin/python solvers/warmups/formats_more.py <blob-file> [...]
```

Prints **every reading directly** — `STRICT <name> <repr>`, `LATE <name> <repr>`, `LOSSY <name> <repr>`
(decoded bytes, first 160) — and is **not** gated on English/slug, so it surfaces a raw flag too.
Covers: punycode; base65536 / base32768 / base2048 (`b2048r` variant); ecoji / ecoji2; emoji letters
(regional indicators, circled/squared); base62 (3 alphabets) and base58 (Flickr/Ripple); mixed-radix
numbers; phonetic alphabets (ICAO/LAPD/RAF/…); **Morse** variants (`morsew` dit/dah words, `morseinv`,
`morseab` any-two-symbols, `morsetime`, `morsekeep`); **braille** by dot-numbers; **roman** numerals;
Braille hex; upside-down text; and it runs cow/whitespace/malbolge/jsfuck. `LATE` readers add keyboard
layouts (`layout:dvorak`…), `cpshift:<n>`, symbol-substitution, mixed-base cycles, `befunge:93`.

### Esolang programs — `solvers/warmups/esolangs.py`

```
.venv/bin/python solvers/warmups/esolangs.py <file> [...]
```

Prints `<file>: <lang> prints b'<output>'`, or `no reader takes it`. Readers: **COW, Whitespace,
Befunge-93, Malbolge, JSFuck, Deadfish**. Step-capped and deadline-bounded; refuses programs that need
input; never executes a host file (the program is data the loop walks).

- **Brainfuck** and **Ook!** live in `solvers/common/classical.py` (functions `brainfuck()`,
  `ook_to_brainfuck()`), e.g.:
  ```
  .venv/bin/python -c "import sys; sys.path.insert(0,'solvers/common'); import classical as K; \
      print(K.brainfuck(open('prog.bf').read()))"
  ```
- **Piet** (a PNG program) → `solvers/common/piet.py`.

### Layered text decoders — `solvers/warmups/layered_decode.py`, `solvers/warmups/crib_decode.py`

```
.venv/bin/python solvers/warmups/layered_decode.py <blob-file> [...]
.venv/bin/python solvers/warmups/crib_decode.py   <blob-file> [...]
```

Breadth-first over strict decoders (hex, base64/32/85/58/45, rot13, binary/octal/decimal, URL, HTML,
quoted-printable, gzip/zlib/bz2/xz/zstd/lz4/brotli/snappy/lzw) plus loose steps (caesar, atbash,
rot47, reverse, single-byte XOR), to depth ~6, time-budgeted.

- `layered_decode.py` prints `<file>: <slug>   [<layer chain>]   <ms>` **and the decoded text** when
  the result reads as English ending in a `word-word-word-NN` slug; otherwise `no slug found`.
- `crib_decode.py` adds more alphabets/braille/Morse, radix 3–36, and keyed classical ciphers
  (via `classical.py`, incl. Brainfuck). When its (Huntress) crib does not fire it prints a useful
  diagnostic: **`best readings: '<text>' via <chain> | …`** — the chain names (`b64`, `reverse`,
  `caesar15`, `xor07`, `gzip`…) tell you how to peel it.

### Classical ciphers with a flag pattern — `solvers/common/classical.py`

```
.venv/bin/python solvers/common/classical.py <file> --pattern '(?:csctf|CSCTF|chronos|flag)\{[^}]+\}'
.venv/bin/python solvers/common/classical.py <file> --crib 'csctf{'
```

Identifies and cracks caesar/rot13, affine, vigenère/beaufort/autokey, substitution, columnar/rail/
scytale, atbash, Enigma (`--enigma`). Prints `PATTERN <cipher> <plain>` / `CRIB <cipher> <plain>` for a
reading that matches, and ranked `SCORE <cipher> (fitness) <plain>` candidates. **Pass `--pattern` or
`--crib`**: the built-in default pattern is Huntress-era (`(?:flag|ctf|huntress)\{…\}`) and misses
`chronos{…}`. (Full crypto depth: see `docs/playbooks/crypto.md`.)

### Nested archives / thin wrappers

A delivery wrapped in base64/gzip/hex/… or nested zips is peeled by `solvers/common/unwrap.py`
(a library — the `./csctf pull` triage and `run.expand` use it; no standalone CLI). For hands-on
extraction, unpack in Docker:

```
python3 tools/sandbox.py run --in nest.zip 7z l {in}                      # list members (read-only)
python3 tools/sandbox.py run --keep --in nest.zip 7z x -y -o{out} {in}    # extract to the kept out dir
python3 tools/sandbox.py run --in blob.bin binwalk {in}                   # scan for embedded files/signatures
```

`{out}` is the one writable folder; `--keep` retains it (its path is printed on stderr). `/drop` (the
`{in}` side) is read-only, so always extract to `{out}`.

> `solvers/common/triage.py` is the Huntress *attempt-dir* triage (needs `attempt.json`/`status.json`)
> — it will not run on `workspace/<id>-<slug>/files/`. Use `./csctf triage <id>` for a pulled challenge.

## Docker tools (csctf-sandbox:2, already up)

```
python3 tools/sandbox.py run --in q.png  zbarimg {in}           # QR / barcode
python3 tools/sandbox.py run --in a.wav  ffprobe {in}           # audio container / streams
python3 tools/sandbox.py run --in a.wav  multimon-ng -a MORSE_CW {in}   # tones / RTTY / morse
python3 tools/sandbox.py run --in a.wav  minimodem --rx 1200 {in}       # FSK modem audio
python3 tools/sandbox.py run --in img.png tesseract {in} stdout # OCR
```

`python3 tools/sandbox.py tools` lists all tools by image.

## Common CSCTF techniques → engine

- **Layered base/encoding stack** → `formats_more.py` (shows the decode) or `crib_decode.py` (read the
  `via <chain>` line), then peel the final layer; `classical.py --pattern` if a cipher sits under it.
- **Esolang that prints the flag** → `esolangs.py` (COW/Whitespace/Befunge/Malbolge/JSFuck/Deadfish),
  `classical.K.brainfuck()` for Brainfuck/Ook!, `piet.py` for Piet.
- **Weird alphabet** (braille, Morse-as-words, roman, emoji, keyboard-shift, upside-down) →
  `formats_more.py`.
- **QR / barcode / audio modem / morse tone** → the Docker tools above.
- **Nested archive or reversible wrapper** → `7z`/`binwalk` in Docker; `unwrap.py` already peels thin
  wrappers during triage.
- **Live `nc host port` misc service** → treat it like pwn/networking: only our assigned target, human
  pace, no flooding; detonate any binary it hands back only in `docker/pwn`.

## Getting the flag out and submitting

- These tools print the plaintext; **you** read the `csctf{...}` out of it and reason to one value.
- Submit through the guard, never in a loop:
  ```
  ./csctf submit <id> 'csctf{...}'
  ```
  or `ctf.submit.guarded_submit(ctfd, ch, flag, provenance="misc: base85→gzip→text")`. The guard
  enforces flag-format, dedupe, pacing, skip-solved, and **3-wrong-then-ask** — stop and ask the player
  if you trip it. Keep `notes.md` current for the write-up.

## Sector format parsers (added 2026-11-03)

A "misc" challenge with an unusual format may be one of the sector parsers: `transport.py` (CAN/ADS-B/AIS/
NMEA), `healthcare.py` (DICOM/HL7/FHIR), `financial.py` (ISO 8583/EMV/SWIFT), or the ICS parsers
(`ics_scada.py`, `ics_fieldbus.py`). All take a file or pcap and highlight flag-format hits.

## Remote-service / quiz challenges (nc, SSH REPL) — `tools/netplay.py`
For the "connect to a service and answer/compute" family (2025: Intreview-1..6, Interview-1..4, Romeo-and-
Julia), use the interactive harness: `.venv/bin/python tools/netplay.py <host> <port> [--ssh user] --auto`
(or `--handler NAME`; `--list` shows them). Handlers compute the answer from each prompt (CLF byte-sum,
XOR-hex, base64-sort, HMAC-SHA256, HS256 JWT, TLV sort) with no spin-up; `--script` runs a fixed send/expect
sequence (e.g. a Julia `run(\`/bin/sh\`)` escape → `cat /flag.txt`). These are high-solve fast points — grab them early.

## Data-over-sound — `solvers/toolkits/sound_data.py` (the one entry)
`sound_data.py` is the dispatcher for a WAV that hides a payload in sound — try it first; it routes each
archetype to the right tool and prints the exact offline recipe for the ones not worth re-implementing.
A WAV is *analysed*, never played; nothing submits.

- `.venv/bin/python solvers/toolkits/sound_data.py <wav>` — **auto**: tries ggwave, DTMF, and the tone
  ladder, and points at the modem/Morse recipe. Subcommands: `ggwave` / `dtmf` / `tones` / `recipes`.
- **ggwave** (data-over-sound, ultrasonic or audible; 2025 "Brainrottalk") — `sound_data.py ggwave <wav>`
  decodes with the pip `ggwave` codec, or prints the exact `ggwave` recipe if it is not importable.
- **DTMF** phone keypad in a real recording — `sound_data.py dtmf <wav>` (Goertzel, via `carve_stego.dtmf`).
  The *symbolic* side — a tone-pair list or key presses you read off a table/OCR → digits/letters — is
  `solvers/toolkits/keypad.py` (`dtmf_from_frequencies`, `multitap_decode`).
- **CyberSonics tone ladder** (freq = base + step·code) — `sound_data.py tones <wav> [--block-ms N]
  [--base HZ --step HZ | --cluster] [--offset 33] [--xor]`, which forwards to `audio_tones.py`
  (FFT peak→ASCII, dual-stream XOR, freq clustering).
- **AFSK / Bell 202 / FSK / Morse-from-audio** — don't re-implement a modem: `sound_data.py recipes`
  prints the Docker `multimon-ng` / `minimodem` invocations (run via `tools/sandbox.py`).
- Spectrogram text hidden in an image → `carve_stego`.

## A recording that says the answer — `solvers/toolkits/audio_speech.py`
A voice that reads or spells the flag (voicemail, podcast, a recovered song) is transcribed locally and
swept, with no model in the loop but the speech-to-text one:
`python -m ctf run toolkits.audio_speech <challenge dir or one audio file>`.

- It decodes any audio file (libsndfile; ffmpeg in the sandbox for the rest), tells tones from a voice,
  hands tones to `audio_tones` / `audio_stego`, and transcribes a voice with a **local Whisper**
  (`whisper-cli` + a ggml model, or `faster_whisper` + a model folder; assets `whisper-ggml` /
  `whisper-ct2`, or `--opt model=PATH`). No backend or model: the result is `blocked` and names what
  to install. Nothing is downloaded.
- Spoken spelling is written out before the flag search ("capital Q seven comma m four z underscore",
  "open curly brace", NATO letters), and digits or letters read aloud go through the codec graph (hex,
  base64, decimal). If the plain recording says nothing useful it also hears the stereo difference and
  the reversed recording. Transcripts land in `recon/audio_speech/`.
- A flag from speech is always a `candidate`: speech does not carry letter case and confuses 0/O and
  1/l. Check it against the recording, then `python -m ctf flag variants`.
- Options: `--opt language=auto`, `--opt variants=original`, `--opt speech=on` (hear tones too),
  `--opt prompt=...`, `--opt seconds=600`. At intake it runs only under `ctf intake --max-cost medium`.

## Python and shell jail candidate ranking

`solvers/toolkits/jail_escape.py` is an offline constraint matcher, not a jail runner. Give it the
stated bans and it ranks catalogue strings, annotating every violated restriction and runtime
assumption. It never evaluates a candidate.

```sh
.venv/bin/python solvers/toolkits/jail_escape.py \
  'Python 3.12 expression only; no builtins; banned characters: "/" and ";"' --json
.venv/bin/python solvers/toolkits/jail_escape.py \
  --constraints-json '{"mode":"shell","banned_chars":[" ","/"]}' --only-compatible
```

Use the output as reviewed candidate payloads for the one assigned challenge. An unspecified AST or
audit filter is reported as a warning; the tool does not pretend a candidate works merely because its
text avoids the named characters.

## Tail esolangs, QR, PRNG, and wallet puzzles

`solvers/warmups/esolang_tail.py` adds bounded interpreters for Unlambda, Lazy-K/SKI, Thue,
FRACTRAN, Hexagony, FALSE, and Underload. Supply challenge input with `--input-text` or
`--input-hex`; every reducer has step, state, integer, and output caps. Thue returns ranked
nondeterministic terminal strings. Hexagony now lays out the canonical centered hexagon, advances all
six switchable instruction pointers, wraps across opposite edges, handles mirrors/sign branches, and
models its directed-edge memory grid. Underload supports nested strings, stack operations,
concatenation, quoting, execution, and explicit output without evaluating host-language code.

Use `qr_matrix.py` for damaged/ASCII/perspective QR, ECC200/DMRE, Aztec, Compact PDF417, and
MicroPDF417 matrices (use `--dimensions`, `--corners`, and optional `--curve` for photographed
labels),
`prng_recovery.py` for mixed PRNG transcripts, and
`blockchain.py` for HD-wallet/keystore/storage-slot puzzles. Each demands a local fixture and returns
verified candidates; none connects to a chain, registry, or service.

### Error-correcting codes and exhaustive codec survey

`solvers/toolkits/ecc_codes.py` provides parameter-explicit, dependency-free decoders for shortened
Reed–Solomon over `GF(2^m)`, binary narrow-sense BCH, general Hamming SECDED, hard-decision
convolutional/Viterbi, and an exact bounded-radius LDPC nearest-codeword search. It also verifies
generic CRC parameters against a bounded common catalog, Fletcher-16 and Internet checksums, and
lists every strict, exact-roundtrip reading from Python's installed text codecs (including the EBCDIC
families). Examples:

```sh
.venv/bin/python solvers/toolkits/ecc_codes.py rs <hex-codeword> 12
.venv/bin/python solvers/toolkits/ecc_codes.py bch <bits> 4 2 0x13
.venv/bin/python solvers/toolkits/ecc_codes.py hamming <SECDED-bits>
.venv/bin/python solvers/toolkits/ecc_codes.py viterbi <bits> --constraint 3
.venv/bin/python solvers/toolkits/ecc_codes.py crc blob.bin 0xcbf43926
.venv/bin/python solvers/toolkits/ecc_codes.py codecs blob.bin
```

Every RS/BCH result must have zero post-correction syndromes and reproduce the corrected word on
re-encode. A corrected codeword is still marked candidate-only: beyond-radius damage can originate
elsewhere. Viterbi likewise calls a zero-distance unique path verified and keeps a corrected maximum-
likelihood path as a candidate. Bare ECC is therefore not guessed by `crib_decode.py`. Its only
automatic ECC forms are explicit self-validating envelopes—`H84:<hex>:<crc32>` and
`RS<n>:<hex>:<crc32>`—where syndrome, re-encode, and the independent payload CRC all agree.

The generic turbo-code entry intentionally declines without the constituent encoders, interleaver,
puncturing and soft metrics; those parameters define the code. Existing warmup engines already cover
the base32/45/58/62/64/85/91/92 families, EBCDIC, ITA2/Baudot, Morse variants, Polybius/tap/Bacon,
DTMF, and bounded gzip/zlib/bzip2/xz/LZMA/LZW/Brotli/LZ4/Zstd/Snappy decompression. Base122 is not
auto-guessed because incompatible variants exist and there is no installed reference implementation.

### Linguistic scripts and Unicode concealment

`solvers/toolkits/language_scripts.py` reports exact codec round-trips, normalization views, script
distribution, confusables, tags, and zero-width bit conventions. Greek/Cyrillic Caesar candidates are
inverse-replayed; ambiguous final sigma and non-bijective substitutions decline. Approximate
transliterations and historic/cipher-script recognition stay labelled leads, never answers.

## Score history across a rule change — `solvers/toolkits/tabular_fit.py` (B-093)
A CSV/TSV/NPZ history of features plus a score made by an exact linear rule that changed at unknown
rows, a probe batch with the features only, and a README that defines a "fingerprint" of the probe
scores. `python -m ctf run toolkits.tabular_fit <challenge_dir>` (intake runs it on every table handout)
parses every cell as an exact fraction, finds the change points by residual (newest rows first; any
row that breaks the exact fit ends the segment, the older rows are refitted), prints each segment's
exact coefficients, scores the probes with the latest rule, and returns the fingerprints ranked
(README hints first) as `candidate` values; it never picks one. Read the README and pin the form:
`--opt decimals=3 --opt rounding=half_up --opt render=int --opt join=newline --opt trailing=false
--opt hash=sha256` (also `target`, `features`, `exclude`, `order`, `intercept`, `changes`). `unsure`
means the rule is found but not trustworthy (too few spare rows in the latest segment, a change count
that disagrees with `changes`, a probe the rows do not determine); `none` with "noisy" means no exact
piecewise fit: the scores were rounded or the rule is not linear in those columns.
