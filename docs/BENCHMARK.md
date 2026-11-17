# Benchmark: flightdeck on NYU CTF Bench

Comparable projects lead with a solve rate. This page is flightdeck's: a public benchmark, run
from the benchmark's own checkout, with only the numbers published (D25, issue #50).

> **Read these numbers with their limits.** A static set of past challenges is not a live
> event: published work finds agents score about double on static sets what they score in live
> play (https://arxiv.org/html/2605.11504v2). The challenges are years old, and a model may have
> read their write-ups in training. One run of each setting, on one machine; a second run would
> differ by a few challenges.

## The benchmark

[NYU CTF Bench](https://github.com/NYU-LLM-CTF/NYU_CTF_Bench) (GPL-2.0): challenges from CSAW's
qualifying and final rounds, 2013 to 2023, in six categories. Its development split (57 in the
checkout's index; the paper says 55) is for tuning, and its test split of 200 is the score.
The best published result on the test split is 59% (https://arxiv.org/abs/2604.17159).

## Results

**Not measured yet.** The first runs on the development split (2026-11-17, autopilot on
OpenRouter's Claude Haiku 5.5 then Sonnet 5.5, $0.60 a lane) were stopped before the end, each
for a flaw in flightdeck that it found, so their scores would measure the flaws:

- a refusal through OpenRouter read as an empty reply, and the lane gave up without saying a
  model had declined (fixed in 0.9.0: it is a refusal now);
- a lane that gave up while its flag waited aside kept its slot for the rest of the run, and
  the queue behind it stood still (fixed in 0.9.0);
- the converter gave most challenges 0 points, which left autopilot's effort budget at its
  floor of 8 turns (fixed: every challenge is worth 500, see below).

What those runs did show: Anthropic's models decline a good share of the pwn and some of the
crypto and web challenges through OpenRouter, where no server-side fallback runs. Autopilot never
sends a declined request to another model (D10), so in the hands-off column such a challenge
counts as unsolved. The run with the fixes goes here, with its refusals counted.

## How it was run

```sh
git clone https://github.com/NYU-LLM-CTF/NYU_CTF_Bench ~/bench/NYU_CTF_Bench   # outside this repository
uv run python scripts/nyuctf_board.py convert ~/bench/NYU_CTF_Bench development ~/bench/dev
uv run python scripts/nyuctf_board.py up ~/bench/dev          # the challenge services, on 127.0.0.1
flightdeck play ~/bench/dev/board --autopilot --budget-dollars 25 --headless
uv run python scripts/nyuctf_board.py down ~/bench/dev
flightdeck score latest
```

Give every model of your ladder a price under `[prices]` in the config, as a fallback: OpenRouter
reports each call's cost, but not for every call, and autopilot disengages rather than spend what
it cannot count against the run budget. Every challenge is worth 500 points on the board: the
benchmark scores each alike, and autopilot's effort budget grows with points (75 turns and 300k
tokens at 500). flightdeck's governor holds new lanes back while the machine's load is over its
limit, so other heavy work on the same machine slows a run down; it changes the wall time, not
what a lane may do.

`scripts/nyuctf_board.py` writes a board folder: each challenge's `challenge.json` and only the
handout files the benchmark lists, an `answers.sha256.json` of the flags (so the run scores
itself), and a `services.json` of the challenges that have a server. `up` starts each of those
from the benchmark's own image, published on 127.0.0.1 on a port of its own; a Docker lane
reaches it through its fence as `instance-localhost:PORT`. A challenge whose compose file mounts
the Docker socket is started without it. The descriptions are the benchmark's own, so one may
name the server CSAW ran it on (`pwn.chal.csaw.io 8000`); the lane's brief gives the address of
this run.

**Rule 4 for this run alone (D25).** Lanes run the benchmark's binaries inside their own
containers, as a player would. Nothing runs on the host.

## Not done yet

- **The steered column.** The same split played by a person at the console, counting their
  interventions: flightdeck's claim is that a steering operator beats hands-off, and this is the
  number that would show it. It needs a person's hours, not a script.
- **The test split's 200.** The converter takes `test` as it takes `development`.
