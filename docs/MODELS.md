# Models: where flightdeck uses them, and what to plug in

flightdeck runs on whatever you have: an API key, a local model server, a coding-agent CLI, or a
mix. Nothing here picks for you. This page says where each kind of model is used, what we
measured, and what we would start with.

> **The numbers on this page are rough.** They come from one Mac (Apple M4 Max, 36 GB), one run
> of each setting, measured on 2026-11-11 while other heavy work was running on the same machine.
> Use them to choose what to try first, not as benchmarks. Measure your own setup with
> `flightdeck eval-local` and `flightdeck practice`.

## Where a model is used

| Role | Config | What it does | Needs |
|---|---|---|---|
| **Lanes** | `[api]`, `[models] ladder` | The agent loop: reads files, runs commands, submits flags. The ladder goes weakest first; escalation climbs it. | Reliable tool calls. |
| **Light model** (optional) | `[light]` | Small jobs for a run. By default the hint judge alone: when a lane seems to ignore what the description hints at, the alert shows at once and the light model can take it down. `[light] jobs` can add three more: route, recon and flagcheck ([below](#the-best-engine-for-each-small-job)). | A short, exact answer. Rules by default (no model). |
| **Coding-agent lanes** | `--agent claude` or `codex`, `[agents]` | The CLI runs its own loop and models, behind flightdeck's controls. | That CLI and its login. |

An API model is the strongest choice for lanes, but its provider's safety classifier can decline
security work. flightdeck shows a refusal and never sends it on to another model for you: you
escalate, fork or take over. An open-weight model on your own machine has no provider classifier
in front of it, and costs nothing per token.

## What we would start with

**Lanes on an API:** Anthropic's ladder (`flightdeck init --provider anthropic`: Claude Haiku,
Sonnet and Opus 5.5), or any model on OpenRouter.

**Lanes on your own machine:** `gpt-oss:20b` on Ollama, as Ollama serves it. Of the four larger
models it solved the most practice challenges with no settings changed: 2 of 4 (Qwen3.5 9B on
Ollama: 1 of 4). Qwen3.5 9B on MLX also solved 2 of 4, with thinking off and a larger reply cap,
and so did the smaller Qwen3.5 4B on Ollama as served (both below). Expect local lanes to solve
less than API lanes, and give them time: a local server can take minutes for one reply.

**Light model:** Qwen3.5 9B or Gemma 4 12B **with thinking off**, on Ollama or MLX: 41 to 42 of the 44
hint and judge cases, against the rules' 38, at 1 to 2 seconds a job. Served as they come, Qwen3.5 scored close
to zero and Gemma 4 17 to 24 of 44: their reasoning used up the short answer before they gave
one. flightdeck asks a light model on your machine for thinking off with each request. On a
smaller machine, Qwen3.5 4B or Gemma 4 E4B did no worse than no model at any of the run's light
jobs, and Qwen3.5 2B and 0.8B at some ([below](#smaller-models-job-by-job)).

**On a Mac, Ollama or MLX?** MLX decoded 1.3 to 1.8 times faster and held less memory. Ollama worked
with no flags: it ships each model's chat template, tool-call parser and sampling settings. We
would use Ollama for lanes and either for the light model.

## By memory

What `flightdeck models --memory GB` advises for a machine of each size (add `--apple` for an
Apple silicon Mac, `--gpu-memory GB` for an NVIDIA GPU). It sizes a model as its weights plus
room for its context (6 GiB for a lane, 2 GiB for the light model), an estimate that runs high
for the small models. The Lanes and Light model columns each judge one model on its own. A lane's
model and a light model running at once must fit together, so the last column names a pair whose
two needs add up to less than the memory local models get. Only the 36 GB Mac was measured: every
other row is that sizing applied to models measured there.

**Apple silicon Mac** (the GPU shares the memory; local models get about two thirds of it):

| Memory | Lanes | Light model | Both on the machine at once |
|---:|---|---|---|
| 4 GB | a model API | the rules (no model) | |
| 8 GB | a model API | Qwen3.5 4B (all four jobs), or 2B (the judge, route) | |
| 12 GB | a model API | Qwen3.5 9B on MLX, or Qwen3.5 4B | |
| 16 GB | Qwen3.5 4B (2 of 4 practice challenges) | Qwen3.5 9B or Gemma 4 12B | no pair fits: beside Qwen3.5 4B lanes, keep the rules or use an API for the light model |
| 24 GB | Qwen3.5 9B, or Qwen3.5 4B | Qwen3.5 9B or Gemma 4 12B | Qwen3.5 4B for both; or Qwen3.5 9B lanes with Qwen3.5 0.8B (the judge only) |
| 32 GB | `gpt-oss:20b` on Ollama, or Qwen3.5 9B | Qwen3.5 9B or Gemma 4 12B | Qwen3.5 9B for both; `gpt-oss:20b` leaves no room for a light model |
| 36 GB | `gpt-oss:20b` on Ollama, or Qwen3.5 9B | Qwen3.5 9B or Gemma 4 12B | `gpt-oss:20b` lanes with Qwen3.5 4B; or Qwen3.5 9B for both |

**A PC with an NVIDIA GPU** (local models get the GPU's memory):

| GPU memory | Lanes | Light model | Both on the GPU at once |
|---:|---|---|---|
| 8 GB | a model API | Qwen3.5 4B, or Gemma 4 E2B (the judge, route, recon) | |
| 12 GB | Qwen3.5 4B | Qwen3.5 9B or Gemma 4 12B | no pair fits: beside Qwen3.5 4B lanes, keep the rules or use an API for the light model |
| 16 GB | Qwen3.5 9B, or Gemma 4 E4B | Qwen3.5 9B or Gemma 4 12B | Qwen3.5 4B for both; or Qwen3.5 9B lanes with Qwen3.5 0.8B (the judge only) |
| 24 GB | `gpt-oss:20b`, or Qwen3.5 9B | Qwen3.5 9B or Gemma 4 12B | `gpt-oss:20b` lanes with Qwen3.5 4B; or Qwen3.5 9B for both |

**No GPU** (local models get about half the memory, on the CPU): a model API for lanes up to
16 GB, then Qwen3.5 4B at 24 GB and Qwen3.5 9B from 32 GB, though no lane was measured on a CPU
alone, so expect it to be slow. For the light model: the rules at 4 GB, Qwen3.5 0.8B (the judge
only) at 8 GB, Qwen3.5 4B at 12 and 16 GB, Qwen3.5 9B from 24 GB. The two smallest models did
their light jobs in 1 to 2 seconds each on the CPU.

On Ollama, check the context before a lane runs on it: below about 23 GiB of GPU memory Ollama
gives a model 4,096 tokens unless you raise it, and `flightdeck doctor` says what yours gives
([Model APIs](MODEL-APIS.md)).

**More than 36 GB, or a result that differs from these?** Nothing larger was measured. Run
`flightdeck eval-local` and `flightdeck practice` on your machine and send what they print with
the [model results form](https://github.com/MFisher14/ctf-flightdeck/issues/new?template=hardware.yml).

## Set up a local model

Ollama:

```sh
ollama pull qwen3.5:9b             # lanes, and the light model
flightdeck init --provider ollama --models qwen3.5:9b --light ollama --light-model qwen3.5:9b
flightdeck doctor                  # checks that the server answers and serves your models
```

That pair fits a 32 GB Mac or a 24 GB GPU. Pick yours from [By memory](#by-memory): on a 36 GB
Mac, `gpt-oss:20b` for lanes with `qwen3.5:4b` as the light model.

Give Ollama room for a lane. Unless told otherwise, it gives a model 4,096 tokens of context on a
machine with under 23 GiB of GPU memory (or none) and 32,768 from 23 GiB, and drops a lane's
oldest messages past that without saying so. Set `OLLAMA_CONTEXT_LENGTH=65536` where Ollama runs,
restart it, and set `context = 65536` under `[api]` so lanes are refreshed before they outgrow it
([details](MODEL-APIS.md#context-on-a-server-on-your-machine)); `flightdeck doctor` checks it.
The light model's short prompts fit 4,096.

MLX (Apple silicon). For lanes, start the server with thinking off and replies of up to 8192
tokens: Qwen3.5 on MLX solved practice challenges only that way. `init --provider mlx` prints the
same command.

```sh
mlx_lm.server --model mlx-community/Qwen3.5-9B-MLX-4bit --host 127.0.0.1 --port 8080 \
    --max-tokens 8192 --chat-template-args '{"enable_thinking":false}'
flightdeck init --provider mlx
```

For a server on your own machine, flightdeck sends its own reply cap on lane calls (8192 tokens;
`mlx_lm.server` would otherwise stop a reply at 512), `init` gives each call 600 seconds instead of
an API's 180, and the light model is asked not to think with each request (Ollama reads
`reasoning_effort`, `mlx_lm.server` reads `chat_template_kwargs`). `[api] max_tokens`, `[api] timeout`
and `[light] thinking` change them; `flightdeck config --example` shows each, and
[Model APIs](MODEL-APIS.md#time-and-reply-length) has the limits in full.

`flightdeck models` shows what your machine has (memory, GPU, which runtimes are installed and
running, the models they serve) and which of these models fit, with the lines for your config.

What it detects, and what it counts: Apple silicon and NVIDIA GPUs (`nvidia-smi`) are what its
advice is sized for. On Linux it also finds AMD and Intel GPUs (from `/sys/class/drm`, and
`rocm-smi` when that is installed; an AMD GPU's memory is read, an Intel GPU's is not), and
names them. Nothing on this page was measured on an AMD or Intel GPU, so for a machine whose
only GPU is one of those it says so plainly: it found the GPU, it has no results for it yet, and
its advice treats the machine as CPU-only. A runtime that uses the GPU may do better than that
advice. To see what would fit the GPU's memory, describe the machine with `--gpu-memory`: that
sizes it as an NVIDIA GPU of that memory, an estimate and not a result. On Windows (outside WSL)
and on a Mac, AMD and Intel GPUs are not looked for. Results from such a machine are wanted: the
[model results form](https://github.com/MFisher14/ctf-flightdeck/issues/new?template=hardware.yml).

For another machine, describe it: `flightdeck models --memory 16 --apple` for a 16 GB Apple
Silicon Mac, `--memory 32 --gpu-memory 12` for a PC with a 12 GB NVIDIA GPU, `--memory 32` alone
for one with no GPU. The advice is the same as that machine would get; what only it can tell
(its runtimes and the models they have pulled) is left out.

## What we measured

Four open-weight models, each on both runtimes. **Tool calls**: 5 tries in flightdeck's request
shape. **Light model**: `flightdeck eval-local` on its 44 hint and judge cases (the rules score
38); the judge is the one job a run gives the light model by default, and the jobs `[light] jobs`
can add are measured [further down](#smaller-models-job-by-job).
**Lanes**: four practice challenges, one lane at a time, 8 minutes for the board.

| Model | Runtime | Tool calls | Memory after load | Output tokens/s | Light model, as served | Light model, thinking off | Practice solved |
|---|---|---:|---:|---:|---:|---:|---|
| Qwen3.5 9B | MLX | 5/5 | 6.0 GB | 51 | 0/44 | **41/44** | 0/4; **2/4** with thinking off and 8192 tokens |
| Qwen3.5 9B | Ollama | 4/5 | 9.0 GB | 36 | 2/44 | **42/44** | 1/4 |
| gpt-oss 20B | MLX | 0/5 | 12.6 GB | 60 | 0/44 | n/a | no tool calls |
| gpt-oss 20B | Ollama | 5/5 | 15.0 GB | 34 | 38/44 | 36/44 (effort low) | **2/4** |
| Gemma 4 12B | MLX | 5/5 | 7.5 GB | 35 | 24/44 | **41/44** | 0/4 |
| Gemma 4 12B | Ollama | 5/5 | 9.7 GB | 23 | 17/44 | **42/44** | 0/4 (replies too slow) |
| Phi-4-mini | MLX | 0/5 | 2.7 GB | 96 | 18/44 | n/a | no tool calls |
| Phi-4-mini | Ollama | 0/5 | 7.0 GB | 73 | 22/44 | n/a | no tool calls |

What decided these results:

- **Reply cap.** `mlx_lm.server` caps a reply at 512 tokens unless started with `--max-tokens`.
  The thinking models ran out mid-thought, returned nothing, and their lanes gave up.
- **Thinking.** Qwen3.5 and Gemma 4 reason before they answer. That helps a lane and sinks the
  light model's short answers. On Ollama's OpenAI-compatible endpoint, `"reasoning_effort": "none"` turns it off
  (`think: false` is ignored there); on MLX it is the server flag above.
- **Time per reply.** Gemma 4 on Ollama reasoned for minutes on some turns, past the 180-second
  default, so its lanes stalled; for a server on this machine `init` writes 600 seconds.
- **Tool-call parsing.** mlx-lm 0.32 does not parse gpt-oss's tool-call format, and Phi-4-mini
  made no tool calls on either runtime.

Quantization differed: 4-bit affine on MLX, Q4_K_M on Ollama, MXFP4 for gpt-oss on both.

gpt-oss 20B's 38/44 on Ollama was with no thinking switch sent. flightdeck's default for a light
model on your machine, thinking off (`reasoning_effort` "none"), was not measured for it (it
scored 36/44 at effort low), so `flightdeck models` gives its `[light]` lines with
`thinking = true`, as it was measured.

### Smaller models, job by job

Five smaller models on Ollama, and Qwen3.5 9B on Ollama again, measured later the same day on the
same Mac, under the same heavy load (one run each: approximate). Ollama 0.34.2 ran the llama.cpp
(GGUF) builds below; Ollama 0.40 and later on Apple silicon runs many models on MLX, from builds
of other sizes, which were not measured.

| Model | Ollama tag | Download | Memory after load | Output tokens/s | Tool calls | Practice solved, as served |
|---|---|---:|---:|---:|---:|---|
| Qwen3.5 0.8B | `qwen3.5:0.8b` (Q8_0) | 1.3 GB | 2.3 GB | about 210 | 5/5 | 0/4 |
| Qwen3.5 2B | `qwen3.5:2b` (Q8_0) | 2.7 GB | 3.5 GB | about 120 | 5/5 | 0/4 |
| Qwen3.5 4B | `qwen3.5:4b` (Q4_K_M) | 3.3 GB | 4.8 GB | about 64 | 5/5 | **2/4** |
| Gemma 4 E2B | `gemma4:e2b` (Q4_K_M) | 4.6 GB | 5.2 GB | about 98 | 5/5 | 0/4 (10 wrong flags) |
| Gemma 4 E4B | `gemma4:e4b` (Q4_K_M) | 6.6 GB | 7.4 GB | about 66 | 5/5 | 1/4 |

Memory after load is with the 32,768-token context Ollama gave each model on that Mac.

The light model's jobs, each scored by `flightdeck eval-local` the way a run uses it, with thinking
off, beside what a run gets with no light model. **Route** counts the answers a run asks a model
for (a challenge's category where the board names none, 9 of the 40 cases, and the specialist
family, all 40), and **recon** the briefs; a run with no model has no answer there.

| Model | Judge in a run (no model: 8/14) | Route: right, wrong | Recon: right, wrong (of 30) | Flagcheck in a run (no model: 30/40) | Hint (the rules: 30/30) | Offered for |
|---|---:|---:|---:|---:|---:|---|
| Qwen3.5 0.8B | 11/14 | 10, 13 | 2, 27 | 20/40 | 17/30 | the judge |
| Qwen3.5 2B | 12/14 | 31, 16 | 7, 23 | 27/40 | 21/30 | the judge, route |
| Qwen3.5 4B | 10/14 | 41, 8 | 15, 15 | 32/40 | 24/30 | all four |
| Gemma 4 E2B | 12/14 | 35, 12 | 15, 15 | 28/40 | 24/30 | the judge, route, recon |
| Gemma 4 E4B | 11/14 | 43, 6 | 23, 7 | 30/40 | 28/30 | all four |
| Qwen3.5 9B | 13/14 | 42, 7 | 20, 10 | 35/40 | 27/30 | all four |

`flightdeck models` offers a model for each job a run gives the light model (`[light] jobs`) where
it did no worse than a run with no model, and prints the `jobs` line to match: the judge and
flagcheck right in a run at least as often as with no model; route and recon right at least as
often as wrong, since a wrong answer goes into the lane's opening brief and no model puts nothing
there. Hint is eval-local's only (a run uses the rules, which no model beat). Qwen3.5 0.8B gave
every challenge back as it was shown instead of a brief, and of the 16 real flags a run would have
asked it about (those the planted-flag hold lets through) it held all 16; the larger models held 1
to 8.

On the CPU alone (Ollama with no GPU, 4 or 8 threads, under the same load), Qwen3.5 0.8B and 2B
scored within three cases of their GPU runs on each job, at about 1 to 2 seconds a job; 4 and 8
threads came out alike.

### Strands Decider: a decision model

[Strands Decider](https://github.com/strands-labs/strands-decider) (Apache-2.0, open weights) is
not a chat model: it picks one of the options it is given and says how confident it is. Its 2B
model on MLX, on the same 44 hint and judge cases:

| | Pick the hinted technique (30) | Judge a lane (14) | Time per question |
|---|---:|---:|---:|
| Strands Decider 2B | 26/30 | 11/14 | 0.08 to 0.18 s |
| Rules | 30/30 | 8/14 | instant |
| Qwen3.5 9B, thinking off | 28/30 | 13 to 14/14 | about 1 s |

On these cases it was 5 to 10 times faster than a 9B model and less accurate. Its confident
answers (0.9 or more) were all right on the technique question, but one of three was wrong on the
judge question, so we would not let it take down an alert alone yet. Its larger Gemma 4 builds
are untested here.

It was measured a second time, on the per-job cases of the
[next section](#the-best-engine-for-each-small-job). There it took 0.1 to 0.3 seconds a question
and answered well on choices when read at a lower confidence (0.5 to 0.7); at its default of 0.9
it answered almost nothing.

## The best engine for each small job

The light model does a set of small jobs, and the best engine differs by job. Measured on synthetic
cases (14 to 40 a job), one run each, the same rough conditions as above:

| Job | What it decides | Best | Without an API key | No model at all |
|---|---|---|---|---|
| hint | which technique a description hints at | the rules (30/30) | the rules | the rules |
| judge | whether a lane is using the hinted technique | Qwen3.5 9B, thinking off (14/14) | Qwen3.5 9B | the rules (8/14) |
| route: instance | whether a challenge needs a live instance | a rule: a URL, or `nc host port` (40/40) | the rule | the rule |
| route: family | which kind of specialist the challenge calls for (audio signals, image steganography, modern cryptography, web requests and six more) | Claude Haiku 5.5 (39/40) | Gemma 4 12B (39/40) | none |
| recon | a first-pass brief for the lane: file kinds, likely technique, first steps | Claude Haiku 5.5 (26/30) | Gemma 4 12B (25/30) | none |
| flagcheck | whether a found flag is the real one or a stand-in | Claude Haiku 5.5 (39/40) | none safe alone (see below); Qwen3.5 9B as a hold on top of flightdeck's own rule | flightdeck's own rule |
| summary | what a lane did, for escalation | no model: flightdeck's own summary | | |

- **Claude Haiku 5.5 cost $0.024 for all 248 calls** of this measurement: about $0.0002 to route
  a challenge.
- **Flag checking is where a local model is risky.** Qwen3.5 and Gemma 4 called 5 and 6 decoy flags
  real; Haiku called none. A model may only ever hold a flag for you, never send one.
- **Strands Decider 2B** is [above](#strands-decider-a-decision-model), with both of its runs.
- **Not for these jobs:** Phi-4-mini (half its answers broke the format, and it followed an
  instruction planted in a lane's steps) and Cactus Needle (it often called no tool at all).

A run gives the light model the jobs `[light] jobs` lists (the hint judge alone unless it lists
more), each on `[light]`'s engine or a `[light.<job>]` table of its own.

## Claude models compared

Haiku 5.5, Sonnet 5.5, Opus 5.5 and Fable 5.2, and Opus and Fable in fast mode, each given the
same prompts on 2026-11-11 and 2026-11-12: one run each, so rough like everything here.

**Light jobs: Haiku 5.5.** Every larger model scored lower, because Anthropic's cyber safeguard
declined 17% to 24% of these CTF-flavoured requests for them and none for Haiku. flightdeck
sends a light job's refused request nowhere else, so a refusal is no answer. Right answers:

| Job (cases) | Haiku 5.5 | Sonnet 5.5 | Opus 5.5 | Fable 5.2 |
|---|---:|---:|---:|---:|
| hint (30) | **30** | 27 | 26 | 27 |
| judge (14) | 11 | 5 | **12** | 11 |
| route (120 questions on 40 cases) | **118** | 95 | 98 | 91 |
| recon (30) | **26** | 21 | 22 | 20 |
| flagcheck (40) | **39** | 17 | 23 | 24 |
| refused, of 248 requests | **0** | 41 | 52 | 59 |
| cost of all 248 | **$0.02** | $0.43 | $0.82 | $1.65 |

**Lanes on four easy practice challenges:** every setup solved 4 of 4 with its first flag, and
none of the 94 lane calls was refused. So here only cost and time differ, and four easy
challenges cannot show whether a bigger model solves what a smaller one cannot.

| Lanes' model | Cost of the board, at list price | Time for the board |
|---|---:|---:|
| Haiku 5.5 | $0.011 | 74 s |
| Sonnet 5.5 | $0.044 | 33 s |
| Opus 5.5 | $0.066 | 30 s |
| Opus 5.5, fast mode | $0.126 | 16 s |
| Fable 5.2 | $0.170 | 46 s |
| Fable 5.2, fast mode | $0.375 | 17 s |

**Fast mode** (`[api] fast`) gave the same answers in about half the time at about twice the
price: worth it when minutes matter, such as an event's last hour. Opus 5.5 in fast mode cost
less than Fable 5.2 at standard speed and finished the board three times as fast.

## Measure your own

```sh
flightdeck eval-local --engine openai --base-url http://127.0.0.1:11434/v1 --model qwen3.5:9b \
    --compare anthropic:claude-haiku-5-5
flightdeck practice --max-lanes 1        # does a model drive the tool loop?
```

eval-local scores any light engine against the rules on the bundled cases. A paid API is announced
first, with its number of calls.
