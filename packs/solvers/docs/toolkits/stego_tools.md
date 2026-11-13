# `stego_tools`: the sandbox side of `carve_stego` (backlog row 147)

Files: `solvers/toolkits/stego_tools.py` (one function per program, a survey, a CLI),
`docker/sandbox/Dockerfile.2` (the image `csctf-sandbox:2`), `tools/sandbox.py` (two images, two
containers). Tests: `.venv/bin/python tests/test_stego_tools.py` (every program on a sample it makes,
about 25 s with the image built; without Docker or the image, part A only and one SKIP line) and
`.venv/bin/python tests/test_sandbox.py`.

It is **not a toolkit**: no `solve_set`, no `signals`, not part of triage routing. It is what the agent
reaches for, by hand, after `carve_stego.py` has printed its triage and the answer is behind a program
`carve_stego` does not have (its page, "Not here").

## Run first

```
.venv/bin/python tools/sandbox.py status                 # which container is up; :2 starts on first use
.venv/bin/python solvers/toolkits/stego_tools.py --tools # STEGO TOOLS up | down, with the reason
.venv/bin/python solvers/toolkits/stego_tools.py <file>... [--pass P]... [--wordlist FILE] [--sstv] [--extract DIR] [--json]
.venv/bin/python tools/sandbox.py run [--timeout S] [--in FILE]... [--keep] TOOL ARGS     # any one program by hand
.venv/bin/python tools/sandbox.py tools                  # the programs, by image
```

The second-to-last line is the survey: per file, every fitting program (by the file's magic) and one line
per finding. `--pass` is a passphrase the question or the delivery states (several allowed), `--wordlist` a
word list the question supplies, `--sstv` also tries an SSTV decode of a recording (slow), `--extract`
writes every payload, picture and carved file under DIR.

## The rules it keeps

- **Everything runs in the sandbox** (`docker exec` into `csctf-sandbox-2`: no network, read-only
  root, uid 10001, 2 CPUs, 1 GB, 128 processes, the file copied in for the call). Nothing is run on this
  Mac. When the sandbox is down, or only `csctf-sandbox:1` is built, a call returns `ok=False` with
  `note` starting `sandbox down:` and ending `: not read`; the file counts as not read.
- **Never guess** (AGENTS.md, "Uncertain answers"). A payload a program extracted whole under a stated
  passphrase AND checked itself (steghide and stegseek: a CRC-32; a PDF that is encrypted and opens with
  the stated password), a QR text, DTMF digits, a decoded frame, an EXIF field: a fact from the bytes, whose name
  or form is still unjudged, so it is read as a ranked candidate (`labels.pick` / `labels.show`).
  OutGuess and SNOW output (no check: a wrong key still gives bytes, and SNOW's are always letters), OCR text, a spectrogram read, an SSTV picture, a `zsteg` line, decompiled C: evidence. One reading alone
  is `None`; two tools or two readings that agree make a candidate. The tests show why: tesseract read
  `ANS-4F2A9C1D7E3B5A60` as `ANS-4F2A9C 1D7E3B5A60`, and read `C0FFEE` in a spectrogram as `COFFEE`;
  `zsteg` printed four "text" rows from the noise planes of a random picture beside the one real one.
- **No brute force.** `stegseek()` takes the word list THE QUESTION supplies, at most 20,000 words
  (`MAX_WORDS`), and refuses an empty or longer list before anything runs. No rockyou, no generated
  candidates, no `stegseek --seed`. An archive password is never tried here at all: it is asked of the
  player and stored with `tools/password.py add` (the project rule).
- `steghide` cannot tell a wrong passphrase from an empty cover, `outguess` and `stegsnow` have no
  integrity check: "nothing opened" proves nothing, and bytes that are not text or a known format are
  reported as noise, not as a payload.

## By hand (`sys.path.insert(0, "solvers/toolkits"); import stego_tools as st`)

Each function takes bytes and returns a `Rec`: `.ok`, `.text`, `.files` (`{name: bytes}`), `.data` (a
parsed value), `.note` (one line), `.code` (the program's exit status, `None` when it did not run).

| Function | Program | Gives |
| --- | --- | --- |
| `st.available()` | | the image in use and whether its container answers |
| `st.steghide_info(data, passphrase="")` | steghide | cover format, capacity; the embedded file's name only when the passphrase opens it |
| `st.steghide_extract(data, passphrase="")` | steghide | the embedded file (`.data`), JPEG, BMP, WAV, AU covers |
| `st.stegseek(data, words)` | stegseek | the one supplied word that opens it, the embedded name, the payload |
| `st.outguess_extract(data, key=None)` | outguess 0.4 | the payload of a JPEG or PNM and whether it looks like one (`plausible`) |
| `st.zsteg(data, everything=False)` | zsteg 0.2.13 | `[{channel, kind, value}]` for a PNG or BMP: leads, to confirm with `carve_stego.lsb_extract` |
| `st.jpeg_survey(data)` | in-process, pure Python (`jpeg_stego.survey`) | JPEG-domain extraction (ticket #9): DCT-coefficient LSBs (jsteg, non-zero, AC-only, F5 un-permuted, every-coefficient) per component (all/Y/Cb/Cr) in both bit orders, plus bit planes 0-7 of the decoded pixels. `ok` only for a CRC/checksum-proven payload of 8+ bytes with 4+ distinct byte values (`.text`); everything else is `.data['candidates']` (unsure). Baseline JPEG only for the DCT side (progressive is declined out loud); F5 with its keyed permutation, OutGuess and JPHide are not covered |
| `st.stegsnow(data, password=None)` | stegsnow | the SNOW message when it is printable text |
| `st.exif(data, name=None)` | exiftool 13.25 | `{'Group:Tag': value}`, every group, duplicates kept |
| `st.pngcheck(data)` | pngcheck | valid or not, the chunk list |
| `st.ocr(data, psm=6, whitelist=None)` | tesseract 5.5 (eng) | the lines it reads in a picture |
| `st.codes(data)` | zbar | `[(symbology, text)]`; `carve_stego.decode_codes` (zxing-cpp) is the second reader |
| `st.pdf_info`, `st.pdf_text`, `st.pdf_images`, `st.pdf_attachments`, `st.pdf_decrypt(data, password)`, `st.pdf_qdf` | poppler, qpdf 12 | fields and the encryption line, text, image objects, embedded files, the decrypted file under a stated password, a readable rewrite |
| `st.media_info(data)` | ffprobe 7.1 | streams and format as JSON |
| `st.to_wav(data, rate=22050, channels=1, filters=None)` | ffmpeg | any audio or a video's sound as PCM WAV; `filters` is an `-af` chain (`areverse`, `atempo=0.5`) |
| `st.frames(data, fps=1, limit=20)` | ffmpeg | video or GIF frames as PNG |
| `st.spectrogram(data, width, height, top_hz, light)` | sox | a raw spectrogram PNG; `top_hz` zooms on the low band |
| `st.spectrogram_text(data, heights=(129, 257), top_hz=8000)` | sox + tesseract | four readings; `.text` is what at least two agree on |
| `st.sstv_decode(data)` | colaclanth/sstv | the picture of an SSTV recording (Martin, Scottie, Robot, PD, Pasokon) as PNG, about 4 s |
| `st.multimon(data, modes=("DTMF",), invert=False)` | multimon-ng 1.3.1 | lines; `.data['dtmf']`, `['pocsag']`, `['afsk']`, `['morse']` (mode `MORSE_CW`). Modes: `st.MULTIMON_MODES` |
| `st.minimodem(data, baud=1200)` | minimodem | Bell 103/202, RTTY, TDD text |
| `st.rtl433(data, name="g.cu8", rate=250000, flex=None, analyze=False)` | rtl_433 25.02 | decoded rows of an IQ file; `flex` for an unknown device, `analyze` for pulse timings and a suggested flex spec |
| `st.foremost(data)` | foremost 1.5.7 | carved files and the audit text |
| `st.bulk_extractor(data)` | bulk_extractor 2.2.0 | `{feature file: [(offset, feature)]}`: e-mail, URL, domain, and the rest |
| `st.tsk(data, "fls", ("-r", "-p", "-d"))` | sleuthkit 4.12 | `mmls`, `fsstat`, `fls`, `icat <inode>` (bytes in `.data`), `tsk_recover -e` (files in `.files`) |
| `st.r2(data, commands, analyze="aa")` | radare2 6.2.4 | any r2 commands, quiet, no colour (`iI`, `izz~flag`, `afl`, `pdf @ main`) |
| `st.decompile(data, function="main")` | r2ghidra 6.2.4 (`pdg`) | C of one function, no JVM; about 0.3 s on a small file |
| `st.py(script, inputs=())` | python3 -I | a script of yours with numpy, scipy, Pillow, pyzbar, pypdf, scapy, python-evtx, regipy, LnkParse3, extract-msg, fickling |
| `st.survey(name, data, passphrases=(), words=None, sstv=False)` | | `[(what, Rec)]`, what the CLI prints |

Programs with no function of their own run through `st.call(tool, args, [(name, bytes)])` or
`tools/sandbox.py run`: `exiv2`, `scalpel`, `mutool`, `pdftoppm`, `qrencode`, `pysstv`, `rabin2`, `rasm2`,
`rafind2`, `strings`, `objdump`, `readelf`, and row 91's `upx`, `tshark`, `vol`, `olevba` (and the rest of
oletools), `binwalk`, `7z`, `yara`, `file`.

## The image and the two containers

- `csctf-sandbox:2` is built **beside** `csctf-sandbox:1` by `.venv/bin/python tools/sandbox.py build`
  (`docker/sandbox/Dockerfile.2`; 1 min 30 s from nothing on this Mac, 30 s with layers cached; 2.1 GB on
  disk, 510 MB of content). It holds everything of `:1` at the same versions. `tools/sandbox.py build 1`
  rebuilds `:1`.
- `tools/sandbox.py` uses `:2` when it is built, else `:1`. `:1` runs in the container `csctf-sandbox`
  with `~/.csctf-sandbox/drop` and `out`, exactly as row 91 built it; `:2` runs in `csctf-sandbox-2`
  with `~/.csctf-sandbox/v2/drop` and `out`. A call for a `:2` program starts `csctf-sandbox-2` by itself
  the first time (about a second, under a lock). A container `sandbox.py stop` removed is not started by a
  call; `start` brings it back. `stop --all` removes both.
- A rebuilt image: the running container is reported as "an older build" and `start` replaces it.
- The limits are the container's (2 CPUs, 1 GB, 128 processes, 64 MB `/tmp`, 256 MB of output a call).
  A program over the memory limit is killed and the call says so (`exit 137`, `not read`). A program that
  leaves processes behind can fill the process limit for every caller until they end: calls then answer
  `sandbox down: ... OCI runtime exec failed`, never a tool's reading; `tools/sandbox.py stop` and `start`
  clears it at once.
- Nothing has to be done for `:2`: the first call starts it. To have it warm, run
  `.venv/bin/python tools/sandbox.py start` from the repository (it leaves `csctf-sandbox` alone). To pin
  the older image, `CTF_SANDBOX_IMAGE=1` in the environment keeps a process on `:1` (row 147's programs
  then answer `sandbox down`).

## What the review changed (2026-10-08, `tests/test_stego_review.py`)

A failure is a reading only when the program read the file. Each of these gave a wrong reading before:

- `if rec:` was always true (`Rec.__bool__` and `__repr__` were dead code). A `Rec` is now false when `ok` is false.
- A passphrase, password, key, whitelist, filter, r2 script or script argument with `{in}` or `{out}` in it
  was rewritten by the sandbox's placeholders (`flag{in}` became `flag/drop/<call>/cover.jpg`, and the
  right passphrase "did not open" the file). Such values now go as `sandbox.Lit`, passed as written.
- `st.steghide_extract`, `st.stegseek`, `st.steghide_info` on a JPEG cut short said "nothing with this
  passphrase" for the RIGHT passphrase. They now say `the cover was not read whole (...): no reading of
  the passphrase`; a format steghide does not read is said the same way.
- `st.pdf_decrypt` said "decrypted" for any password on a PDF that is not encrypted, and "not decrypted
  with this password" for a damaged file. Now: not encrypted is `ok=False` ("this one is not proven by
  it"), damaged is "the PDF was not read", a wrong password is "invalid password", and the empty
  password that opens a PDF is said to be the empty one.
- `st.codes` split one QR whose text has a line like `TEL:123` or `QR-Code:x` into several "codes", turned
  a binary code's bytes into U+FFFD, and said "0 codes" for a picture zbar could not load (also when the
  container's file-size limit killed it, exit 153). It now reads `zbarimg --xml`: one row per code,
  `.files['first.bin']` the exact bytes of a single code, `not read` for a picture that was not loaded.
- `st.exif` dropped `ExifTool:Warning` ("Trailer data after PNG IEND chunk", a stego lead) and
  `ExifTool:Error`; both are kept, and a file with an error is `ok=False`.
- `st.zsteg` on a file that is no PNG or BMP said "0 findings" (zsteg exits 0); now `not read`.
- A program ended by any signal (128+n, not only six of them) is `: not read`.
- `tools/sandbox.py start`, and a call that has to start a container: when `csctf-sandbox:2` is built but
  its container cannot be started, the `:1` container is started instead with a `WARNING` line, so row
  91's tools go on (`tests/test_sandbox.py` A9). Before, nothing was started.
- `st.tsk(data, "icat", ())` is refused in words; `icat` returns the file's bytes through the same
  path as every other call (time limit, memory kill and crash are `: not read` there too).
- `tools/sandbox.py`: an input named `.`, `..` or empty gets the name `in<i>` (it raised
  `IsADirectoryError`); `run()` reads a generator of args once.

## Not here

- OutGuess 0.4 crashes while **embedding** into a JPEG on arm64 (exit 133); extracting works, which is
  the direction a challenge needs. The JPEG sample of the test was made once with the amd64 build.
- No `stegseek --seed`, no cracking, no dictionary of our own.
- JPEG DCT stego other than steghide and OutGuess (jsteg, F5, JPHide), `stegoveritas`, `stegsolve`,
  `openstego`, `deepsound`: not in the image.
- SSTV: one decoder (colaclanth/sstv). A recording with noise, a slant or no VIS header may need
  `skip` or QSSTV by hand; never tested on an off-air recording.
- `rtl_433`: proven on a clean synthetic OOK PWM signal through a flex decoder, on no built-in device
  protocol and on no real capture. FSK devices, `.cs16`/`.cf32` input: untested.
- `multimon-ng`: DTMF, AFSK1200, POCSAG1200 and MORSE_CW proven on clean synthetic recordings; the other modes, and any noisy or off-air recording, untested.
- `bulk_extractor` is built without libewf (no E01 images). No Ghidra headless (JVM), no `fossil`,
  `darcs`, `subversion` binaries (row 147 listed them; `repo_supply_chain` reads those from bytes).
- No `tesseract` language but English.
