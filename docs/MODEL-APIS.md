# Model APIs

What flightdeck's own lanes can call, where their keys come from, and what happens when an API
fails or a model declines. Coding-agent lanes (`play --agent claude|codex`) use their CLI's own
login and models instead (`[agents]` in your config). Which models fit your machine:
`flightdeck models`, and the measured results in [MODELS.md](MODELS.md).

## Choosing one

`flightdeck init` asks, or takes `--provider`:

| Provider | Where | Key variable |
|---|---|---|
| `anthropic` | The Anthropic Messages API | `ANTHROPIC_API_KEY` |
| `openrouter` | `https://openrouter.ai/api/v1` | `OPENROUTER_API_KEY` |
| `openai` | `https://api.openai.com/v1` | `OPENAI_API_KEY` |
| `local` (or `ollama`) | Ollama on this machine, `http://127.0.0.1:11434/v1` | none |
| `mlx` | An MLX server on this machine, `http://127.0.0.1:8080/v1` | none |
| `custom` | Any OpenAI-compatible API (`--base-url`, `--key-env`) | yours |

A model on your own machine costs nothing, so `init` writes no dollar cap for it, and no
provider's safety classifier stands in front of it. For Ollama and an MLX server, `init` suggests
a ladder from a benchmark on one machine (`gpt-oss:20b` on Ollama,
`mlx-community/Qwen3.5-9B-MLX-4bit` on MLX): the default at its prompt, and named in its message
away from a terminal, never written unless you choose it. For any server on this machine it
writes a longer wait and a larger reply cap (below), and for MLX it prints the command that
starts the server with thinking off and replies of up to 8192 tokens (`mlx_lm.server --model
... --max-tokens 8192 --chat-template-args '{"enable_thinking":false}'`). `flightdeck models ID`
prints the config lines for a model from its catalog.

Your `[models]` ladder lists model ids weakest first: lanes start on the first, and escalating
moves one step up. `flightdeck config --example` shows every key.

## Keys

The config names each key's environment variable, never the key. flightdeck reads the variable
from its environment first, then from `~/.config/ctf-flightdeck/keys.env` (or the file
`$FLIGHTDECK_KEYS` names), which must be readable by you only (chmod 600). flightdeck never
prints, logs or stores a key. A lane's commands get an environment built from an allowlist, so
no key is handed to them; on the host runtime a lane still runs as you and can read your files
(see [`--host` in the README](../README.md#play-a-board)). A coding-agent lane is different: its
CLI gets its own credential, and the commands the agent runs can read it, in Docker too, so give
it a key you can revoke, with a low spending limit. `flightdeck doctor` checks that each
variable is set, never its value.

## Before a run

Before the console opens, `play` and `practice` ask each API the lanes will use (`[api]`, and
`[fallback]` when there is one) whether it takes the key and serves every model in the ladder:
an OpenAI-style API through its model list, the Anthropic API through its Models API. A refused
key, a model it does not serve (with the closest ids it does), a model Anthropic has retired, or
no server up stops the run with what to fix. An API that does not list its models, or any other
answer, is a note and the run goes on. Listing models costs nothing, and nothing is retried.

## Time and reply length

Each try of a lane's model call may take `[api] timeout` seconds (180 by default, 600 with the
Anthropic API, at most 3600); a reply not complete by then is given up and tried again, with the
usual retries and waits between them. `[api] max_tokens` is the most tokens a lane's reply may
hold (1 to 1,000,000). Left unset, it is 8192 for an OpenAI-compatible server on this machine
(127.0.0.1, localhost or ::1), whose own default can be far lower (mlx_lm.server's is 512, which
cuts off a model that reasons first); nothing is sent to any other OpenAI-compatible API
(OpenAI's own refuses `max_tokens` on its reasoning models, so leave it unset there), and the
Anthropic API gets 16000. For a server on this machine, `init` writes `timeout = 600` and
`max_tokens = 8192`: a local model can take minutes for one reply. A `[fallback]` table takes
both for its own API. `flightdeck doctor` says what a lane's calls to a server on this machine
send and how long each try may take, and where each comes from (`lane calls`, and `fallback
calls` for a fallback there).

## Context on a server on your machine

A lane's context grows until flightdeck refreshes it at 50,000 prompt tokens: the lane goes on in
a fresh context, with a summary in place of its history. Ollama gives a model 4,096 tokens of
context on a machine with under 23 GiB of GPU memory (or no GPU), 32,768 from 23 GiB and 262,144
from 47 GiB, unless `OLLAMA_CONTEXT_LENGTH` says otherwise, and past that it drops a lane's oldest
messages without saying so. Set `OLLAMA_CONTEXT_LENGTH=65536` where Ollama runs, restart Ollama,
and set `context = 65536` under `[api]`: a lane is then refreshed at 49,152 prompt tokens, which
leaves room for two replies of up to `max_tokens` (8192). With a server you cannot change, set
`context` to what it gives (`context = 32768`: refreshed at 16,384). `[fallback]` takes `context`
too, and a lane is refreshed before it outgrows the smaller of the two. A context that would leave
a lane under 8,192 tokens before its refresh is refused, and so is one for an API on another host
without `max_tokens` (flightdeck sends none there, so it cannot keep room for a reply).

## The Anthropic API

`flightdeck init --provider anthropic` writes the ladder `claude-haiku-5-5`, `claude-sonnet-5-5`,
`claude-opus-5-5` with their list prices, so dollar caps work from the start (`flightdeck models`
shows the prices). The key and base URL are passed to Anthropic's SDK from your config, so it
reads no other credential and no `ANTHROPIC_BASE_URL` from the environment. The system prompt
and the tools are cached as one prefix, and a lane's history only grows within a context, so the
cache keeps hitting turn after turn.

When Anthropic's safety classifiers decline a request on Claude Sonnet or Opus 5.5, Anthropic
runs it again on its recommended fallback model inside the same call (Claude Haiku 5.5 has no
such fallback). A request still declined ends the lane with "the model declined (category)", and
is never retried or sent to another API. You decide what next: fork the lane onto another model
(`f`), say. The light model's Claude calls carry no such fallback: a refusal leaves the rules'
answer.

## A fallback API

Any config can have a `[fallback]` table: a second API, with `provider`, `base_url`, `key_env`,
`timeout` and `max_tokens` as in `[api]` (not `fast`, which is for `[api]` only), and a ladder of
one model per `[models]` entry, in the same order and in the fallback API's own naming. A lane
whose calls to `[api]` keep failing (rate limits, overload, an outage, no answer, after every
retry) moves to the fallback's model at the same rung for the rest of its context, and its
transcript says so: the two APIs never mix inside one context. Escalating the lane, or
the long-context refresh, tries `[api]` again. A refusal, a bad request or a refused key never
moves a lane: another API would not change the answer, or should not.

With an Anthropic key, `init` offers OpenRouter as the fallback when `OPENROUTER_API_KEY` is set
(`--fallback` away from a terminal), with OpenRouter's names for the same models.
`flightdeck doctor` checks the fallback's key like the first.

## Fast mode

With the Anthropic API, `[api] fast = ["claude-opus-5-5"]` calls those ladder models in fast
mode: up to 2.5x the output speed at a premium price. Only a model Anthropic documents fast mode
for is accepted:

| Model | Fast price, input / output per million tokens |
|---|---|
| Claude Opus 5.5 | $8 / $40 (twice the standard price) |
| Claude Fable 5.2, Claude Mythos 5.2 | $16 / $80 |
| Claude Opus 5, Claude Opus 4.8 (research previews) | $10 / $50; Opus 5 needs access from Anthropic, and Opus 4.8's fast mode ends on 2026-11-30 |

A fast call is priced at the fast rate. `play` names the fast models and their price before
lanes start. Fast mode has its own rate limit: on a 429 the lane goes on at standard speed at
once and says so on its transcript. It stays at standard speed until an escalation starts a new
session, since every switch of speed starts the prompt cache again.

## Prices

A lane's dollars come from the API when it reports a call's cost (OpenRouter does), else from
your config's `[prices."<model>"]` (`input`, `output`, optional `cached_input`, in dollars per
million tokens), else they are unknown. A model in an `[agents]` ladder can have a price too,
under the CLI's own name for it: codex reports its tokens but no cost, while claude reports its
own cost, which wins. A dollar-capped lane whose spend has no price asks you once before it
carries on without its cap, and the console shows its dollars as "at least" (`$0.42+`).

A coding-agent CLI reports what a turn cost only when the turn ends, so its lane's dollars end in
`…` until then. A turn whose cost never came (the CLI was stopped in it, or exited) is priced
from your config when it has a price for the turn's tokens; otherwise it leaves the dollars "at
least" too, but asks nothing: the dollar cap holds on what is known.
