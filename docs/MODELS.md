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
| **Light role** (optional) | `[light]` | Small judgments, today the hint judge: when a lane seems to ignore what the description hints at, the alert shows at once and the light model can take it down. | A short, exact answer. Rules by default (no model). |
| **Coding-agent lanes** | `--agent claude` or `codex`, `[agents]` | The CLI runs its own loop and models, behind flightdeck's controls. | That CLI and its login. |

An API model is the strongest choice for lanes, but its provider's safety classifier can decline
security work. flightdeck shows a refusal and never sends it on to another model for you: you
escalate, fork or take over. An open-weight model on your own machine has no provider classifier
in front of it, and costs nothing per token.

## What we would start with

**Lanes on an API:** Anthropic's ladder (`flightdeck init --provider anthropic`: Claude Haiku,
Sonnet and Opus 5.5), or any model on OpenRouter.

**Lanes on your own machine:** `gpt-oss:20b` on Ollama, as Ollama serves it. It was the only local
model that solved practice challenges with no settings changed: 2 of 4. Qwen3.5 9B on MLX also
solved 2 of 4, with thinking off and a larger reply cap (below). Expect local lanes to solve less
than API lanes, and give them time: a local server can take minutes for one reply.

**Light role:** Qwen3.5 9B or Gemma 4 12B **with thinking off**, on Ollama or MLX: 41 to 42 of 44
cases, against the rules' 38, at 1 to 2 seconds a job. A model that thinks first scored close to
zero: its reasoning used up the short answer before it gave one. flightdeck asks a light model on
your machine for thinking off with each request. On a smaller machine, Qwen3.5 4B or Gemma 4 E4B
did no worse than no model at any of the run's light jobs, and Qwen3.5 2B and 0.8B at some
([below](#smaller-models-job-by-job)).

**On a Mac, Ollama or MLX?** MLX decoded 1.3 to 1.8 times faster and held less memory. Ollama worked
with no flags: it ships each model's chat template, tool-call parser and sampling settings. We
would use Ollama for lanes and either for the light role.

## Set up a local model

Ollama:

```sh
ollama pull gpt-oss:20b            # lanes
ollama pull qwen3.5:9b             # the light role
flightdeck init --provider local --models gpt-oss:20b --light ollama --light-model qwen3.5:9b
flightdeck doctor                  # checks that the server answers and serves your models
```

MLX (Apple silicon). For lanes, start the server with thinking off: Qwen3.5 on MLX solved
practice challenges only that way.

```sh
mlx_lm.server --model mlx-community/Qwen3.5-9B-MLX-4bit --host 127.0.0.1 --port 8080 \
    --chat-template-args '{"enable_thinking":false}'
flightdeck init --provider mlx
```

For a server on your own machine, flightdeck sends its own reply cap on lane calls (8192 tokens;
`mlx_lm.server` would otherwise stop a reply at 512), `init` gives each call 600 seconds instead of
an API's 180, and the light model is asked not to think with each request (Ollama reads
`reasoning_effort`, `mlx_lm.server` reads `chat_template_kwargs`). `[api] max_tokens`, `[api] timeout`
and `[light] thinking` change them; `flightdeck config --example` shows each.

`flightdeck models` shows what your machine has (memory, GPU, which runtimes are installed and
running, the models they serve) and which of these models fit, with the lines for your config.

## What we measured

Four open-weight models, each on both runtimes. **Tool calls**: 5 tries in flightdeck's request
shape. **Light role**: `flightdeck eval-local` on its 44 scored cases (the rules score 38).
**Lanes**: four practice challenges, one lane at a time, 8 minutes for the board.

| Model | Runtime | Tool calls | Memory after load | Output tokens/s | Light role, as served | Light role, thinking off | Practice solved |
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
  light role. On Ollama's OpenAI-compatible endpoint, `"reasoning_effort": "none"` turns it off
  (`think: false` is ignored there); on MLX it is the server flag above.
- **Time per reply.** Gemma 4 on Ollama reasoned for minutes on some turns, past the 180 seconds
  flightdeck allowed then, so its lanes stalled. `init` now writes 600 seconds for a local server.
- **Tool-call parsing.** mlx-lm 0.32 does not parse gpt-oss's tool-call format, and Phi-4-mini
  made no tool calls on either runtime.

Quantization differed: 4-bit affine on MLX, Q4_K_M on Ollama, MXFP4 for gpt-oss on both.

gpt-oss 20B's 38/44 was with no thinking switch sent. flightdeck now asks a light model on your
machine for thinking off, which was not measured for it, so `flightdeck models` gives its
`[light]` lines with `thinking = true`, as it was measured.

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

The light role's jobs, each scored by `flightdeck eval-local` the way a run uses it, with thinking
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
every challenge back as it was shown instead of a brief, and held all 16 real flags it was asked
about; the larger models held fewer.

On the CPU alone (Ollama with no GPU, 4 or 8 threads, under the same load), Qwen3.5 0.8B and 2B
scored within three cases of their GPU runs on each job, at about 1 to 2 seconds a job; 8 threads
were no faster than 4.

### Strands Decider: a decision model for the light role

[Strands Decider](https://github.com/strands-labs/strands-decider) (Apache-2.0, open weights) is
not a chat model: it picks one of the options it is given and says how confident it is. Its 2B
model on MLX, on the same light-role cases:

| | Pick the hinted technique (30) | Judge a lane (14) | Time per question |
|---|---:|---:|---:|
| Strands Decider 2B | 26/30 | 11/14 | 0.08 to 0.18 s |
| Rules | 30/30 | 8/14 | instant |
| Qwen3.5 9B, thinking off | 28/30 | 13 to 14/14 | about 1 s |

It was 5 to 10 times faster than a 9B model and less accurate. Its confident answers (0.9 or more)
were all right on the technique question, but one of three was wrong on the judge question, so we
would not let it take down an alert alone yet. Its larger Gemma 4 builds are untested here.

## The best engine for each small job

The light role is a set of small jobs, and the best engine differs by job. Measured on synthetic
cases (14 to 40 a job), one run each, the same rough conditions as above:

| Job | What it decides | Best | Without an API key | No model at all |
|---|---|---|---|---|
| hint | which technique a description hints at | the rules (30/30) | the rules | the rules |
| judge | whether a lane is using the hinted technique | Qwen3.5 9B, thinking off (14/14) | Qwen3.5 9B | the rules (8/14) |
| route: instance | whether a challenge needs a live instance | a rule: a URL, or `nc host port` (40/40) | the rule | the rule |
| route: family | which kind of specialist should take it | Claude Haiku 5.5 (39/40) | Gemma 4 12B (39/40) | none |
| recon | a first-pass brief for the lane: file kinds, likely technique, first steps | Claude Haiku 5.5 (26/30) | Gemma 4 12B (25/30) | none |
| flagcheck | whether a found flag is the real one or a stand-in | Claude Haiku 5.5 (39/40) | none safe alone (see below) | flightdeck's own rule |
| summary | what a lane did, for escalation | no model: flightdeck's own summary | | |

- **Claude Haiku 5.5 cost $0.024 for all 248 calls** of this measurement: about $0.0002 to route
  a challenge.
- **Flag checking is where a local model is risky.** Qwen3.5 and Gemma 4 called 5 and 6 decoy flags
  real; Haiku called none. A model may only ever hold a flag for you, never send one.
- **Strands Decider 2B** answered fast (0.1 to 0.3 seconds) and well on choices when read at a
  lower confidence (0.5 to 0.7): at its default 0.9 it answered almost nothing.
- **Not for these jobs:** Phi-4-mini (half its answers broke the format, and it followed an
  instruction planted in a lane's steps) and Cactus Needle (it often called no tool at all).

A run gives the light model the jobs `[light] jobs` lists (the hint judge alone unless it lists
more), each on `[light]`'s engine or a `[light.<job>]` table of its own.

## Measure your own

```sh
flightdeck eval-local --engine openai --base-url http://127.0.0.1:11434/v1 --model qwen3.5:9b \
    --compare anthropic:claude-haiku-5-5
flightdeck practice --max-lanes 1        # does a model drive the tool loop?
```

eval-local scores any light engine against the rules on the bundled cases. A paid API is announced
first, with its number of calls.
