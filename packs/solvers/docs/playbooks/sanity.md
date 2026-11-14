# Sanity playbook (CSCTF 2026)

Sanity checks confirm you can read a challenge and submit a flag. The flag is usually **handed to
you** — in the description, the rules page, a Discord/announcement channel, a file opened as-is, or
under one trivial encoding (base64, hex, rot13, morse, a QR). Do not overthink it; do not brute-force
anything. The whole job is: find the flag in plain sight (or one decode away) and submit it once.

## First moves

1. `./csctf check <id>` — skip if a teammate already solved it.
2. Read `workspace/<id>-<slug>/challenge.json` end to end — description **and** `connection_info`.
   The flag, or exactly where it is, is often right there.
3. `grep -aoE '(csctf|CSCTF|flag|chronos|CHRONOS|CTF)\{[^}]*\}' workspace/<id>-<slug>/files/*`
   — a visible flag ends the challenge immediately.
4. If files are present: `strings`/`file` them (in Docker if unknown binary), and check metadata.
5. If the flag looks encoded, run one decoder (below) and submit.

## Engines (verified CLIs)

Run every command from the ctf-tools checkout root with `.venv/bin/python` (or `.venv/bin/python -m ctf run <engine>`), with `CTF_EVENT` set to the event slug (`events/<slug>/event.toml`). The workdir comes from `ctf.paths`: `$CTF_WORKDIR`, else `~/ctf-work/<event>`; `.venv/bin/python -m ctf workdir` prints it, and `workspace/` on this page means it.

### Simple / layered encoding

```
.venv/bin/python solvers/warmups/formats_more.py <file>    # prints every reading (base*, morse, braille, roman, emoji, …)
.venv/bin/python solvers/warmups/layered_decode.py <file>  # breadth-first base/hex/rot/gzip stack
.venv/bin/python solvers/warmups/crib_decode.py <file>     # same battery + "best readings: '<text>' via <chain>"
```

Note: `layered_decode.py` / `crib_decode.py` were tuned on English/slug plaintext, so a raw
`csctf{...}` may come back as `no slug found` / `no answer`. In that case read `crib_decode.py`'s
**`best readings: … via <chain>`** line to see the encoding chain, or use `formats_more.py` which
prints decoded bytes directly. For a cipher (caesar/rot13/vigenère/…) use:

```
.venv/bin/python solvers/common/classical.py <file> --pattern '(?:csctf|CSCTF|chronos|flag)\{[^}]+\}'
```

It prints `PATTERN <cipher> <plain>` for the reading that matches. (Pass `--pattern` — the built-in
default misses `chronos{…}`.)

### A flag in a file's metadata, a QR, or an image

Do this in the Docker sandbox (csctf-sandbox:2, already up); never run an unknown file on the Mac:

```
python3 tools/sandbox.py run --in file.jpg exiftool {in}        # flag in EXIF / a comment field
python3 tools/sandbox.py run --in code.png zbarimg {in}         # QR / barcode payload
python3 tools/sandbox.py run --in img.png tesseract {in} stdout # flag text rendered in an image
python3 tools/sandbox.py run --in blob.bin strings {in}         # printable strings
```

## Common CSCTF techniques → where to look

- **Flag in the description / rules / Discord** → read `challenge.json`; join the event channels.
  Agents never join or read Discord: `.venv/bin/python -m ctf discord checklist --challenge <id> --card`
  asks the player for the places to read, `... discord ingest <file> --where '#rules' --kind rules`
  takes what they saved, and `... discord analyze --challenge <id>` ranks the flag and
  recognition-word candidates into `recon/discord.md` (a flag spelled by the first character of each
  rules bullet included; a format example is marked a decoy). Submit one, once, after reading where
  it came from.
- **Flag printed in a file** → `strings` / `grep` for the flag format.
- **base64 / hex / rot13 / morse** → `formats_more.py` or `layered_decode.py`; one step, then submit.
- **Classical cipher** → `classical.py --pattern '…\{…\}'`.
- **QR code or image text** → `zbarimg` / `tesseract` in Docker.
- **Flag in metadata** → `exiftool` in Docker (or `solvers/toolkits/osint.py <file>` for the metadata
  leads offline).

## Getting the flag out and submitting

The flag matches the event format (default
`(?:csctf|CSCTF|flag|chronos|CHRONOS|CTF)\{…\}`; the format is the event profile's `[flag]` (`events/<slug>/event.toml`, read through `ctf.flagfmt`)).
Submit once, through the guard — never loop candidates:

```
./csctf submit <id> 'csctf{...}'          # quote to protect the braces from the shell
```

or `ctf.submit.guarded_submit(ctfd, ch, flag, provenance="sanity: description")`. The guard checks the
flag format, dedupes, paces, skips solved, and **stops and asks after 3 wrong on one challenge** — if a
sanity flag is "wrong" 3 times, stop and tell the player (the format or target is off). Scope rules
still apply: only our assigned target, nothing against the platform or other teams.
