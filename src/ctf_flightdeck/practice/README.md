# The practice set

Fourteen small challenges for trying ctf-flightdeck without a live event (its board is called
Practice Range: `board.json`'s event). Everything here was invented for this repository (names,
stories, files and flags) and is MIT licensed like the rest of it. Nothing needs a network or a
server, and no handout is a compiled program or an executable file.

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
flightdeck practice
```

It spends tokens like `flightdeck play`. The set ships inside the installed package, as
`ctf_flightdeck/practice/` (`src/ctf_flightdeck/practice/` in the repository), so playing it needs
no clone. flightdeck loads this folder as a board: each directory is one challenge
(`challenge.json` plus the handout files it lists), `board.json` names the event and the flag
format, and `answers.sha256.json` lets flightdeck check a flag without knowing it.

## Honest practice uses the docker runtime

In the host runtime (`runtime = "host"`) a lane's commands run as you, on your machine, so nothing
stops a lane from reading a clone of this repository, which holds a reference solution for every
challenge (`tests/test_practice.py`). In the docker runtime (`runtime = "docker"`) a lane's
commands run in a container whose filesystem holds only its own copy of the challenge, mounted at
`/work`.

A docker lane gets no network when its challenge lists no `urls`, and no challenge here does, so a
practice lane in docker can read nothing but its own copy and reach nothing at all: it cannot
download this repository's solutions.

That holds for flightdeck's own lanes. A coding-agent lane (`--agent`) in docker reaches its CLI's
own API, which it cannot work without, and nothing else, so its shell cannot download this
repository either. What that API does on its provider's servers is beyond flightdeck's fence: a
CLI that turns on a hosted web search could still look the solutions up.

The lane's python tool runs `python3` inside the container. Build the lane image once with
`flightdeck image build` (it adds `python3`, `file`, `xxd`, `unzip`, `strings` and other common
tools to Debian); `flightdeck init` sets it as the image.

## Checking a flag by hand

`answers.sha256.json` maps each challenge id to the SHA-256 of its exact flag, in lower-case hex:

```sh
printf '%s' 'practice{...}' | shasum -a 256
```

## Hints

Most descriptions give the kind of nudge real CTFs give; Fine Print, Harbour Memo and Signal Lamp
name their technique outright. flightdeck's hint rules are tested on every description here
(`tests/test_detect_lexicon.py`).

## Tests (spoilers)

In a clone of the repository, `uv run pytest tests/test_practice.py` checks every `challenge.json`
against the folder-board format, that nothing here is executable, the size limits, and that a
reference solver recovers each flag from its handout and matches the answers file. The solvers read
the files and undo the transformation; they never run handout code. Read that file after you have
played. The installed package does not include it.

## Adding a challenge

The steps are in the repository's
[CONTRIBUTING.md](https://github.com/MFisher14/ctf-flightdeck/blob/main/CONTRIBUTING.md#adding-a-practice-challenge).
