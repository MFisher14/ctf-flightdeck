"""What context Ollama gives a lane's model, and whether a lane fits in it: `flightdeck doctor`
and `flightdeck models`.

Ollama gives a model 4,096 tokens of context when the GPU memory it finds is under 23 GiB (no
GPU counts as none), 32,768 from 23 GiB and 262,144 from 47 GiB, unless OLLAMA_CONTEXT_LENGTH
(or the model's own num_ctx) says otherwise, and past that it drops the oldest messages of a chat
without saying so, keeping the system message and the latest one (Ollama's server/routes.go,
after "Set default context based on VRAM tier", and server/prompt.go; its
docs/context-length.mdx rounds the tiers to 24 and 48 GiB). A lane grows to its refresh point
(config.lane_refresh_at) and needs room for replies past it, so on most machines Ollama's default
is too small for one; the light role's prompts are a few hundred tokens and fit 4,096.

Ollama's API says what context it gives a model only while the model is loaded: GET /api/ps
lists each loaded model with its context_length (what `ollama ps` shows as CONTEXT; read here
from Ollama 0.34.2's answers, and tested against a fake server). For a model that is not loaded,
the context is estimated (default_contexts): from OLLAMA_CONTEXT_LENGTH when the environment
flightdeck runs in sets it (Ollama has it only if it was started there too), else from the GPU
memory as Ollama counts it: an NVIDIA GPU's memory, every GPU's summed; on Apple Silicon, the part
of unified memory macOS lets the GPU use, which llama.cpp reports from Metal and which is two
thirds to about 0.84 of it depending on the machine and macOS (values logged in llama.cpp's
issues), so a Mac near a tier may be on either side of it.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from .hardware import GIB, Machine, gib

TIERS = ((47 * GIB, 262_144), (23 * GIB, 32_768), (0, 4_096))  # GPU memory from which Ollama gives each context
APPLE_GPU_SHARE = ((2, 3), (84, 100))  # of unified memory macOS lets the GPU use: the least and the most logged
ADVISED = 65_536  # the context to give Ollama for lanes: room for the 50,000-token refresh and two replies
LIGHT_FITS = 4_096  # the light role's prompts fit even Ollama's smallest default
CONTEXT_ENV = "OLLAMA_CONTEXT_LENGTH"
OLLAMA_PORT = 11434  # Ollama's default port: a server there that does not answer is taken for Ollama, not running
PS_PATH = "/api/ps"  # the models Ollama has loaded, each with the context it gives it


def ollama_default(gpu_memory: int) -> int:
    """The context Ollama gives a model when nothing sets one, for `gpu_memory` bytes of GPU memory."""
    return next(tokens for floor, tokens in TIERS if gpu_memory >= floor)


@dataclass(frozen=True)
class Estimate:
    """The contexts Ollama may give a model on a machine when nothing is loaded to ask about."""

    tokens: tuple[int, ...]  # each context it may give, smallest first (two when a Mac is near a tier)
    why: str  # where they come from, as a clause: "this Mac's GPU may use 24 to 30.2 GiB of its 36 GiB"
    named: bool = False  # from OLLAMA_CONTEXT_LENGTH where flightdeck runs, not from the GPU memory


def default_contexts(machine: Machine, environ: Mapping[str, str] | None = None) -> Estimate | None:
    """The context Ollama would give a model on `machine`, by OLLAMA_CONTEXT_LENGTH in `environ`
    when it sets a whole number, else by the machine's GPU memory; None when the memory is unknown."""
    named = (environ or {}).get(CONTEXT_ENV, "").strip()
    if named.isascii() and named.isdigit() and int(named) > 0:
        return Estimate((int(named),), f"{CONTEXT_ENV} is {int(named)} where flightdeck runs, and Ollama has it if it "
                                       "was started there too", named=True)
    if named:  # set, but not a whole number of tokens: said, not passed over as if it were unset
        estimate = default_contexts(machine, {})
        unusable = f"{CONTEXT_ENV} where flightdeck runs is not a whole number above 0, so it is not counted"
        return None if estimate is None else Estimate(estimate.tokens, f"{estimate.why} ({unusable})")
    where = "there" if machine.described else "here"
    if machine.os == "macOS" and machine.apple_silicon.value is None:
        return None  # an Intel Mac's Ollama runs on the CPU, an Apple Silicon one's on the GPU: cannot tell which
    if machine.apple_silicon.value:
        memory = machine.memory.value
        if memory is None:
            return None
        low, high = (memory * share[0] // share[1] for share in APPLE_GPU_SHARE)
        tokens = tuple(sorted({ollama_default(low), ollama_default(high)}))
        mac = "the Mac described" if machine.described else "this Mac"
        return Estimate(tokens, f"the GPU of {mac} may use {gib(low)} to {gib(high)} of its {gib(memory)}, as macOS sets it")
    gpus = machine.gpus.value
    if gpus is None:
        return None
    if gpus:
        total = sum(gpu.memory for gpu in gpus)
        return Estimate((ollama_default(total),), f"the NVIDIA GPU memory {where} is {gib(total)}"
                                                  + (" in all" if len(gpus) > 1 else ""))
    return Estimate((ollama_default(0),), f"it finds no GPU {where}")


def loaded_contexts(body: object) -> dict[str, int] | None:
    """{model: context} from Ollama's /api/ps answer ({"models": [{"name", "context_length"}, ...]});
    None when `body` is not one (another server answered)."""
    items = body.get("models") if isinstance(body, dict) else None
    if not isinstance(items, list):
        return None
    out = {}
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            return None
        tokens = item.get("context_length")
        if type(tokens) is int and tokens > 0:
            out[item["name"]] = tokens
    return out


def parse_ps(raw: bytes) -> dict[str, int] | None:
    try:
        return loaded_contexts(json.loads(raw))
    except (ValueError, RecursionError):
        return None


def ollama_root(base_url: str) -> str:
    """Ollama's own address from its OpenAI-compatible base URL (http://127.0.0.1:11434/v1 -> ...:11434)."""
    try:
        parts = urlsplit(base_url)
    except ValueError:
        parts = None
    if parts is not None and parts.scheme and parts.netloc:  # without a query or fragment: neither is Ollama's, and one may hold a token
        base_url = f"{parts.scheme}://{parts.netloc}{parts.path}"
    return base_url.rstrip("/").removesuffix("/v1")


def default_port(base_url: str) -> bool:
    try:
        return urlsplit(base_url).port == OLLAMA_PORT
    except ValueError:
        return False


def loaded_as(contexts: Mapping[str, int], model: str) -> int | None:
    """The context Ollama gives `model` while loaded (a name without a tag is its ":latest")."""
    return contexts.get(model, contexts.get(f"{model}:latest"))


@dataclass(frozen=True)
class Finding:
    """Whether a lane fits the context Ollama gives its model: `ok`, what was found (`detail`),
    and what to do when it does not (`fix`)."""

    ok: bool
    detail: str
    fix: str
    model: str  # the ladder model it is about
    tokens: int  # the context it is judged by: Ollama's word for a loaded model, else the smallest estimate
    stated: bool  # Ollama stated it (the model is loaded), rather than an estimate
    need: int  # what a lane needs: its refresh point and room for two replies
    refresh_at: int

    def as_json(self) -> dict:
        return {"ok": self.ok, "model": self.model, "tokens": self.tokens, "stated": self.stated, "need": self.need,
                "refresh_at": self.refresh_at, "detail": self.detail, "fix": self.fix or None}


def default_note(estimate: Estimate, refresh_at: int, reply: int, where: str = "here") -> tuple[bool, str]:
    """What Ollama's default context means for a lane on a machine (`flightdeck models`, with no
    config of Ollama's to look at): (whether a lane fits it, the note)."""
    from .config import refresh_point

    need = refresh_at + 2 * reply
    either = " or ".join(f"{t:,}" for t in estimate.tokens)
    unset = "" if estimate.named else f"with no {CONTEXT_ENV}, "
    head = (f"Ollama's context: {unset}Ollama gives a model {either} tokens {where} ({estimate.why}), and past that "
            "drops a lane's oldest messages without saying so.")
    if estimate.tokens[0] >= need:
        return True, f"{head} Enough for a lane, which needs {need:,}. The light role's short prompts fit {LIGHT_FITS:,}."
    return False, (f"{head} A lane needs {need:,} (refreshed at {refresh_at:,} prompt tokens, with room for two replies "
                   f"of up to {reply:,}): set {CONTEXT_ENV}={ADVISED} where Ollama runs, restart it, and set context = "
                   f"{ADVISED} under [api] (a lane is then refreshed at {refresh_point(ADVISED, reply):,}). The light "
                   f"role's short prompts fit {LIGHT_FITS:,}.")


def lane_finding(address: str, ladder: tuple[str, ...], loaded: Mapping[str, int] | None, estimate: Estimate | None,
                 refresh_at: int, reply: int, *, table: str = "[api]", stated_context: int | None = None,
                 source: str = "") -> Finding | None:
    """Whether a lane on the Ollama at `address` fits the context it gives the ladder's models:
    the smallest Ollama states for a loaded one, else the smallest `estimate`. A lane needs its
    refresh point (`refresh_at`) and room for two replies of up to `reply` tokens. None when
    there is nothing to judge by (no model loaded, and the machine unknown)."""
    from .config import MIN_REFRESH, refresh_point

    said = {model: loaded_as(loaded, model) for model in ladder} if loaded else {}
    said = {model: tokens for model, tokens in said.items() if tokens is not None}
    need = refresh_at + 2 * reply
    if said:
        model = min(said, key=lambda m: said[m])
        tokens, stated = said[model], True
        how = "as Ollama says of it while it is loaded (`ollama ps`)"
    elif estimate is not None:
        model, tokens, stated = ladder[0], estimate.tokens[0], False
        either = f"or {estimate.tokens[-1]:,}, " if len(estimate.tokens) > 1 else ""
        if estimate.named:
            how = f"an estimate: it is not loaded, so Ollama does not say, and {estimate.why}"
        else:
            how = (f"{either}an estimate: it is not loaded, so Ollama does not say; with no {CONTEXT_ENV} Ollama gives "
                   f"4,096 under 23 GiB of GPU memory, 32,768 from 23 GiB and 262,144 from 47 GiB, and {estimate.why}")
    else:
        return None
    if stated_context is not None:
        why = f" ({table} context is {stated_context:,})"
    else:
        why = ""
    detail = (f"Ollama at {address} gives {model} {tokens:,} tokens of context ({how}); a lane needs {need:,}: it is "
              f"refreshed at {refresh_at:,} prompt tokens{why}, with room for two replies of up to {reply:,}")
    if tokens >= need:
        return Finding(True, detail, "", model, tokens, stated, need, refresh_at)
    detail += ", and past its context Ollama drops a lane's oldest messages without saying so"
    where = f" in {source}" if source else ""
    more = f"set {CONTEXT_ENV}={ADVISED} where Ollama runs and restart Ollama"
    if stated_context != ADVISED:  # else the config says it already
        more += (f", then set context = {ADVISED} under {table}{where} (a lane is then refreshed at "
                 f"{refresh_point(ADVISED, reply):,} prompt tokens)")
    keep = (f"set context = {tokens} under {table}{where}, so a lane is refreshed at {refresh_point(tokens, reply):,} "
            "prompt tokens, before it outgrows Ollama")
    workable = refresh_point(tokens, reply) >= MIN_REFRESH  # a lane can work in what Ollama gives
    if stated:  # Ollama said it: the least to do is to tell flightdeck
        fix = (f"{keep}; or give Ollama more: {more}" if tokens < ADVISED else keep) if workable else more
    else:  # an estimate: giving Ollama a context is sure; telling flightdeck the estimate is not
        fix = more + (f"; or, if Ollama keeps its {tokens:,}, {keep}" if workable else "")
        fix += "; once the model is loaded, `ollama ps` shows the context Ollama gives it, and so does this check"
    return Finding(False, detail, fix, model, tokens, stated, need, refresh_at)
