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
zero: its reasoning used up the short answer before it gave one.

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

Today a run uses the light model for the hint judge only. Per-job engines and the route, recon and
flagcheck jobs are being built next.

## Measure your own

```sh
flightdeck eval-local --engine openai --base-url http://127.0.0.1:11434/v1 --model qwen3.5:9b \
    --compare anthropic:claude-haiku-5-5
flightdeck practice --max-lanes 1        # does a model drive the tool loop?
```

eval-local scores any light engine against the rules on the bundled cases. A paid API is announced
first, with its number of calls.
