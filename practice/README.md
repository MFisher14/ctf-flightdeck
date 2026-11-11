# Practice Range

Fourteen small challenges for trying ctf-flightdeck without a live event. Everything here was
invented for this repository (names, stories, files and flags) and is MIT licensed like the rest
of it. Nothing needs a network or a server, and no handout is a compiled program or an executable
file.

| Challenge | Category | Points | Handout |
|---|---|---|---|
| Crab Walk | crypto | 50 | `postcard.txt` |
| Half and Half | misc | 50 | `halves.txt` |
| Wrong Jar | forensics | 50 | `minutes.pdf` |
| Fine Print | forensics | 100 | `harbour_dawn.png` |
| Mille Feuille | crypto | 100 | `layers.txt` |
| Nesting Dolls | forensics | 100 | `dolls.zip` |
| Welcome Mat | web | 100 | `index.html`, `portal.js`, `style.css` |
| Postmarked | crypto | 150 | `envelope.txt`, `letter.txt` |
| Quiet Night | forensics | 150 | `access_log` |
| Signal Lamp | misc | 150 | `lamp_log.csv` |
| Harbour Memo | crypto | 200 | `memo.enc` |
| Turnstile | rev | 200 | `turnstile.py` |
| Three Wishes | crypto | 250 | `encrypt.py`, `output.txt` |
| Pancake Stack | rev | 300 | `vm.py`, `program.bin` |

Flags look like `practice{...}`: lower-case letters, digits and underscores inside the braces. No
flag appears in plain text anywhere, not even in its own handout, so every challenge takes at least
one step. Real CTFs plant decoys, and so does this set.

## Play

```sh
flightdeck play practice
```

The `play` command is still being built (milestone M1). It loads this folder as a board: each
directory is one challenge (`challenge.json` plus the handout files it lists), `board.json` names
the event and the flag format, and `answers.sha256.json` lets flightdeck check a flag without
knowing it.

## Honest practice uses the docker runtime

In the host runtime a lane's commands run as you, on your machine. Nothing stops a lane from
reading this repository, and the repository holds a reference solution for every challenge
(`tests/test_practice.py`). In the docker runtime (`runtime = "docker"`) a lane sees only its own
copy of the challenge, mounted at `/work`.

The lane's python tool runs `python3` inside the container. The default image,
`debian:bookworm-slim`, has bash, coreutils and perl but no `python3`, `file`, `xxd`, `unzip` or
`strings`, so practise with an image that adds them.

## Checking a flag by hand

`answers.sha256.json` maps each challenge id to the SHA-256 of its exact flag, in lower-case hex:

```sh
printf '%s' 'practice{...}' | shasum -a 256
```

## Hints

Most descriptions give the kind of nudge real CTFs give. Three name their technique outright
(Fine Print, Harbour Memo and Signal Lamp); later milestones use them to test the "ignores the
hint" alert.

## Tests (spoilers)

`uv run pytest tests/test_practice.py` checks every `challenge.json` against the folder-board
format, that nothing here is executable, the size limits, and that a reference solver recovers
each flag from its handout and matches the answers file. The solvers read the files and undo the
transformation; they never run handout code. Read that file after you have played.

## Adding a challenge

1. Add a directory with `challenge.json` and the handout files, all listed in `files`.
2. Put the SHA-256 of the flag in `answers.sha256.json`, never the flag itself.
3. Add a reference solver to `tests/test_practice.py` that recovers the flag from the handout with
   the standard library, without running handout code.
4. Keep it synthetic and small: no compiled binaries, no executable files, under 1 MB per handout.
