"""White-box language-model prefix probe: greedy-complete flag prefixes and report per-token probabilities (B-116).

The task: a challenge hands over a chat model's weights and says the model "knows" the flag but will not
say it. With the weights in hand the refusal does not matter: start the answer for the model (a raw
`PREFIX{`, a sentence that ends in it, or a chat turn with the assistant's reply prefilled) and take the
most likely next token until the closing brace. A memorized string comes back with every token near
probability 1, the same from every prompt; an invented one does not.

What runs, offline and with no model API:

* **Find the model**: a Hugging Face folder (`config.json` plus `*.safetensors`) in the challenge files,
  inside a zip there (read in place, never extracted), or at `--opt model_path=<folder or zip>` when the
  weights were downloaded by hand. Weights are sliced by `_model_tensors` and never unpickled; a
  pickle-only model (`pytorch_model.bin`) is refused by name.
* **numpy backend** (`NumpyDecoder`, `ByteBPE`): a forward pass with a key/value cache for the Qwen2
  decoder layout (RMSNorm, rotary positions, grouped-query attention, SwiGLU) and a byte-level BPE
  tokenizer read from `tokenizer.json` or `vocab.json` + `merges.txt`. No torch. This is the runner
  that solved the challenge this item comes from.
* **transformers backend** (`TransformersRunner`): any other causal LM, when `torch` and
  `transformers` are importable (a human step: neither is in requirements). Local files only,
  safetensors only, `trust_remote_code` off: the model's own code never runs.
* **Probe** (`probe`): the prompt set, greedy decode with top-k per step, candidates in the event flag
  format, agreement across prompts.

Statuses: `solved` when exactly one flag comes back, from two or more prompts, memorized in at least
one (every token at least MEMORIZED_MIN, mean at least MEMORIZED_MEAN); `candidate` for any other
flag-format completion; `none` when no completion closes a flag or there is no model; `blocked` with
the reason when the model cannot be run here (architecture or tokenizer the numpy runner does not
implement and no torch runtime, weights missing or too large for this host, a wrong option).

Every model file is data: the chat template is never rendered, only searched for a literal default
system prompt; text the model generates changes nothing here.

Contract entry: `solve(challenge_dir, profile, **opts) -> SolverResult` (CONTRACTS 6-7). Options:
`model_path`, `backend` (auto | numpy | transformers), `arch` (`llama-like` runs the numpy backend on
an untested model type with the same tensor layout), `secret` (what the brief calls the flag, e.g.
"vault key"), `system` (chat system prompt; "" for none), `prompts` (extra
`[{"kind": "raw"|"chat", "text": ..., "prefill": ...}]`), `max_new_tokens` (48), `top_k` (4),
`budget_s` (CPU seconds, 900), `max_ram_gb`.
"""
from __future__ import annotations

import contextlib
import functools
import importlib
import json
import os
import re
import sys
import time
import unicodedata
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

try:
    from ctf import flagfmt
except ModuleNotFoundError:                     # a direct script run: put the checkout root on sys.path
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import flagfmt
from ctf.result import Cost, Evidence, SolverResult

# By its dotted name, so both B-116 engines and the tests share one module object.
tensors_mod = importlib.import_module("solvers.toolkits._model_tensors")

ENGINE = "toolkits.model_prefix_probe"
NUMPY_TYPES = ("qwen2",)                 # model types the numpy backend was checked against
LLAMA_LIKE = "llama-like"                # --opt arch=: same tensor layout, untested model type
SKIP_DIRS = {"recon", ".git", "__pycache__", "node_modules"}
MAX_TEXT = 64 * 1024 * 1024              # one tokenizer/config file
MAX_ZIPS = 16
DEFAULT_BUDGET = 900.0                   # CPU seconds
DEFAULT_NEW_TOKENS = 48
DEFAULT_TOP_K = 4
MEMORIZED_MIN = 0.5                      # every generated token at least this likely ...
MEMORIZED_MEAN = 0.9                     # ... and this likely on average: the string is memorized
MAX_PROMPTS = 24
CHATML = ("<|im_start|>", "<|im_end|>")
WEIGHT_FILES = ("pytorch_model.bin", "model.ckpt", "tf_model.h5", "flax_model.msgpack")
TEXT_FILES = ("config.json", "generation_config.json", "tokenizer.json", "tokenizer_config.json", "vocab.json",
              "merges.txt", "added_tokens.json", "chat_template.jinja", "special_tokens_map.json")
QWEN_SPLIT = (r"(?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}| ?[^\s\p{L}\p{N}]+[\r\n]*"
              r"|\s*[\r\n]+|\s+(?!\S)|\s+")
GPT2_SPLIT = r"'s|'t|'re|'ve|'m|'ll|'d| ?\p{L}+| ?\p{N}+| ?[^\s\p{L}\p{N}]+|\s+(?!\S)|\s+"


class ProbeError(Exception):
    """The model cannot be probed here; the message is the named reason (a `blocked` result)."""


class NeedsTool(ProbeError):
    """A runtime is missing: `tools` are the needs_tool names (py:torch, py:transformers)."""

    def __init__(self, message: str, tools=()):
        super().__init__(message)
        self.tools = tuple(tools)


def _np():
    import numpy
    return numpy


# ---- 1. the model on disk ------------------------------------------------------------------------------

@dataclass
class ModelDir:
    """A Hugging Face model folder, on disk (`root`) or inside a zip (`zip_path` + member `prefix`)."""
    root: Path | None = None
    zip_path: Path | None = None
    prefix: str = ""
    names: tuple = ()                    # file names in the folder (not recursive)

    @property
    def label(self) -> str:
        if self.zip_path is not None:
            return f"{self.zip_path.name}!{self.prefix}" if self.prefix else self.zip_path.name
        return self.root.name if self.root is not None else "(model)"

    def has(self, name: str) -> bool:
        return name in self.names

    def read_bytes(self, name: str) -> bytes | None:
        if not self.has(name):
            return None
        try:
            if self.zip_path is not None:
                with zipfile.ZipFile(self.zip_path) as zf:
                    info = zf.getinfo(self.prefix + name)
                    if info.file_size > MAX_TEXT:
                        raise ProbeError(f"{self.label}: {name} is {info.file_size} bytes, over the text file cap")
                    return zf.read(info)
            path = self.root / name
            if path.stat().st_size > MAX_TEXT:
                raise ProbeError(f"{self.label}: {name} is over the text file cap")
            return path.read_bytes()
        except (OSError, zipfile.BadZipFile, KeyError) as exc:
            raise ProbeError(f"{self.label}: {name} cannot be read ({type(exc).__name__})") from exc

    def read_json(self, name: str):
        raw = self.read_bytes(name)
        if raw is None:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError) as exc:
            raise ProbeError(f"{self.label}: {name} is not JSON ({type(exc).__name__})") from exc

    def read_text(self, name: str) -> str | None:
        raw = self.read_bytes(name)
        return None if raw is None else raw.decode("utf-8", "replace")

    def safetensors(self) -> list:
        """SafetensorsFile for every weight shard in the folder, name order."""
        out = []
        for name in sorted(n for n in self.names if n.endswith(".safetensors")):
            try:
                if self.zip_path is not None:
                    out.append(tensors_mod.SafetensorsFile.open(self.zip_path, member=self.prefix + name))
                else:
                    out.append(tensors_mod.SafetensorsFile.open(self.root / name))
            except tensors_mod.TensorError as exc:
                raise ProbeError(str(exc)) from exc
        return out


def _dir_model(folder: Path, links: bool = True) -> ModelDir | None:
    """The model in `folder`, or None. links=False (a challenge folder) leaves symlinked files out: one
    could point outside the challenge. A configured model_path keeps them (a Hugging Face cache snapshot
    is symlinks into its blobs folder)."""
    try:
        names = tuple(sorted(p.name for p in folder.iterdir() if p.is_file() and (links or not p.is_symlink())))
    except OSError:
        return None
    return ModelDir(root=folder, names=names) if "config.json" in names else None


def _zip_models(path: Path) -> list:
    try:
        with zipfile.ZipFile(path) as zf:
            members = [i.filename for i in zf.infolist() if not i.is_dir()]
    except (OSError, zipfile.BadZipFile):
        return []
    out = []
    for member in members:
        if member.rsplit("/", 1)[-1] != "config.json":
            continue
        prefix = member[:-len("config.json")]
        names = tuple(sorted(m[len(prefix):] for m in members if m.startswith(prefix) and "/" not in m[len(prefix):]))
        out.append(ModelDir(zip_path=path, prefix=prefix, names=names))
    return out


def find_models(challenge_dir, model_path=None) -> list:
    """Model folders, the ones that hold weights first. `model_path` (a folder or a zip) is the only
    place looked when given: ProbeError if it holds no config.json."""
    if model_path:
        target = Path(str(model_path)).expanduser()
        if target.is_dir():
            found = [m for m in (_dir_model(p) for p in [target] + sorted(d for d in target.rglob("*") if d.is_dir()))
                     if m is not None]
        elif target.is_file():
            found = _zip_models(target)
        else:
            raise ProbeError(f"model_path {str(model_path)!r} does not exist")
        if not found:
            raise ProbeError(f"model_path {str(model_path)!r} holds no config.json (a Hugging Face model folder, "
                             "or a zip of one, is expected)")
    else:
        root = Path(challenge_dir)
        found, zips = [], 0
        for p in sorted(root.rglob("*")):
            if set(p.relative_to(root).parts[:-1]) & SKIP_DIRS or p.is_symlink() or not p.is_file():
                continue                                        # a symlink could point outside the challenge
            if p.name == "config.json":
                model = _dir_model(p.parent, links=False)
                if model is not None:
                    found.append(model)
            elif p.suffix.lower() == ".zip" and zips < MAX_ZIPS:
                zips += 1
                found.extend(_zip_models(p))

    def shards(m):
        return tuple(n for n in m.names if n.endswith(".safetensors"))

    with_weights = [m for m in found if shards(m)]
    on_disk = {shards(m) for m in with_weights if m.root is not None}
    # an extracted copy and its zip are one model: keep the folder
    with_weights = [m for m in with_weights if m.root is not None or shards(m) not in on_disk]
    return with_weights + [m for m in found if not shards(m) and is_model_config(m)]


def is_model_config(model: ModelDir) -> bool:
    """config.json reads as a model's (not some other tool's file of the same name)."""
    try:
        config = model.read_json("config.json")
    except ProbeError:
        return False
    return isinstance(config, dict) and any(k in config for k in ("model_type", "architectures", "num_hidden_layers"))


# ---- 2. byte-level BPE ---------------------------------------------------------------------------------

def _bytes_to_unicode() -> dict:
    """The GPT-2 byte to printable-character table every byte-level BPE vocabulary is written in."""
    keep = list(range(ord("!"), ord("~") + 1)) + list(range(0xA1, 0xAD)) + list(range(0xAE, 0x100))
    chars = keep[:]
    extra = 0
    for b in range(256):
        if b not in keep:
            keep.append(b)
            chars.append(256 + extra)
            extra += 1
    return dict(zip(keep, map(chr, chars)))


B2U = _bytes_to_unicode()
U2B = {v: k for k, v in B2U.items()}


@functools.lru_cache(maxsize=1)
def _unicode_classes() -> dict:
    """{"L": ..., "N": ...}: the code point ranges of the Unicode letter and number categories, as text
    for the inside of a character class. Built once from unicodedata (the standard library has no \\p)."""
    spans = {"L": [], "N": []}
    start = {"L": None, "N": None}
    for cp in range(sys.maxunicode + 2):
        cat = unicodedata.category(chr(cp))[0] if cp <= sys.maxunicode else "?"
        for key in spans:
            if cat == key and start[key] is None:
                start[key] = cp
            elif cat != key and start[key] is not None:
                spans[key].append((start[key], cp - 1))
                start[key] = None

    def text(pairs):
        esc = lambda cp: "\\U%08x" % cp                           # noqa: E731
        return "".join(esc(a) if a == b else f"{esc(a)}-{esc(b)}" for a, b in pairs)
    return {key: text(pairs) for key, pairs in spans.items()}


def translate_split(pattern: str):
    """A tokenizer's pre-tokenization regex (Rust syntax with \\p{L} and \\p{N}) compiled for `re`.
    ProbeError for a Unicode class other than those two, or a pattern `re` does not accept."""
    classes = _unicode_classes()
    out, i, in_class = [], 0, False
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            if pattern[i + 1] in "pP":
                m = re.match(r"\\p\{(\w+)\}", pattern[i:])
                if not m or m.group(1) not in classes:
                    raise ProbeError(f"the tokenizer's split pattern uses a Unicode class this reader does not "
                                     f"build: {pattern[i:i + 12]!r}")
                body = classes[m.group(1)]
                out.append(body if in_class else f"[{body}]")
                i += m.end()
                continue
            out.append(pattern[i:i + 2])
            i += 2
            continue
        if ch == "[" and not in_class:
            in_class = True
        elif ch == "]" and in_class:
            in_class = False
        out.append(ch)
        i += 1
    try:
        return re.compile("".join(out))
    except re.error as exc:
        raise ProbeError(f"the tokenizer's split pattern does not compile here ({exc})") from exc


class ByteBPE:
    """A byte-level BPE tokenizer (the GPT-2 family: Qwen, GPT-2, RoBERTa, Llama 3).

    vocab: token text (in the byte table's characters) -> id. merges: ranked pairs. added: special
    token text -> id, matched before anything else and never split."""

    def __init__(self, vocab: dict, merges: list, added: dict, split, nfc: bool = False):
        self.vocab, self.added, self.split, self.nfc = vocab, dict(added), split, nfc
        self.ranks = {tuple(pair): i for i, pair in enumerate(merges)}
        self.inv = {i: t for t, i in vocab.items()}
        self.inv_added = {i: t for t, i in self.added.items()}
        self._special = (re.compile("(" + "|".join(re.escape(t) for t in sorted(self.added, key=len, reverse=True)) + ")")
                         if self.added else None)
        self._cache = {}

    @property
    def size(self) -> int:
        return max(list(self.inv) + list(self.inv_added), default=-1) + 1

    def _bpe(self, word: str) -> list:
        if word in self._cache:
            return self._cache[word]
        parts = list(word)
        while len(parts) > 1:
            best_rank, best_at = None, None
            for i in range(len(parts) - 1):
                r = self.ranks.get((parts[i], parts[i + 1]))
                if r is not None and (best_rank is None or r < best_rank):
                    best_rank, best_at = r, i
            if best_at is None:
                break
            first, second = parts[best_at], parts[best_at + 1]
            merged, i = [], 0
            while i < len(parts):                               # merge every occurrence of the best pair
                if i < len(parts) - 1 and parts[i] == first and parts[i + 1] == second:
                    merged.append(first + second)
                    i += 2
                else:
                    merged.append(parts[i])
                    i += 1
            parts = merged
        self._cache[word] = parts
        return parts

    def encode(self, text: str) -> list:
        ids = []
        for segment in (self._special.split(text) if self._special else [text]):
            if not segment:
                continue
            if segment in self.added:
                ids.append(self.added[segment])
                continue
            if self.nfc:
                segment = unicodedata.normalize("NFC", segment)
            for word in self.split.findall(segment):
                for part in self._bpe("".join(B2U[b] for b in word.encode("utf-8"))):
                    if part not in self.vocab:
                        raise ProbeError(f"the tokenizer vocabulary has no token for {part!r}: not a complete "
                                         "byte-level BPE vocabulary")
                    ids.append(self.vocab[part])
        return ids

    def decode(self, ids, special: bool = False) -> str:
        out = b""
        for i in ids:
            i = int(i)
            if i in self.inv:
                out += bytes(U2B[c] for c in self.inv[i] if c in U2B)
            elif i in self.inv_added:
                out += self.inv_added[i].encode("utf-8") if special else b""
            else:
                out += f"<{i}>".encode()
        return out.decode("utf-8", "replace")

    @classmethod
    def from_model(cls, model: ModelDir, model_type: str = "") -> "ByteBPE":
        tj = model.read_json("tokenizer.json")
        vocab = merges = None
        added, pattern, nfc = {}, None, False
        if isinstance(tj, dict):
            core = tj.get("model") if isinstance(tj.get("model"), dict) else {}
            if core.get("type") != "BPE":
                raise NeedsTool(f"{model.label}: tokenizer.json is a {core.get('type')!r} model, not byte-level BPE "
                                "(SentencePiece, WordPiece and Unigram are not implemented in the numpy runner)",
                                ("py:torch", "py:transformers"))
            vocab = core.get("vocab")
            merges = [tuple(m.split(" ")) if isinstance(m, str) else tuple(m) for m in core.get("merges") or []]
            for tok in tj.get("added_tokens") or []:
                if isinstance(tok, dict) and isinstance(tok.get("content"), str) and isinstance(tok.get("id"), int):
                    added[tok["content"]] = tok["id"]
            stages = _stages(tj.get("pre_tokenizer"))
            if not any(s.get("type") == "ByteLevel" for s in stages + _stages(tj.get("decoder"))):
                raise NeedsTool(f"{model.label}: tokenizer.json has no ByteLevel stage: not a byte-level BPE",
                                ("py:torch", "py:transformers"))
            for stage in stages:
                rx = stage.get("pattern") if stage.get("type") == "Split" else None
                if isinstance(rx, dict) and isinstance(rx.get("Regex"), str):
                    pattern = rx["Regex"]
            nfc = any(s.get("type") == "NFC" for s in _stages(tj.get("normalizer")))
        else:
            vocab = model.read_json("vocab.json")
            raw = model.read_text("merges.txt")
            if not isinstance(vocab, dict) or raw is None:
                raise NeedsTool(f"{model.label}: no tokenizer.json and no vocab.json + merges.txt: the tokenizer is "
                                "not a byte-level BPE the numpy runner reads", ("py:torch", "py:transformers"))
            merges = [tuple(line.split()) for line in raw.split("\n")
                      if line.strip() and not line.startswith("#version")]
            listed = model.read_json("added_tokens.json")
            if isinstance(listed, dict):
                added.update({k: v for k, v in listed.items() if isinstance(v, int)})
            conf = model.read_json("tokenizer_config.json")
            decoder = conf.get("added_tokens_decoder") if isinstance(conf, dict) else None
            if isinstance(decoder, dict):
                for key, tok in decoder.items():
                    if isinstance(tok, dict) and isinstance(tok.get("content"), str) and str(key).isdigit():
                        added.setdefault(tok["content"], int(key))
        if not isinstance(vocab, dict) or not all(isinstance(k, str) and isinstance(v, int) for k, v in vocab.items()):
            raise ProbeError(f"{model.label}: the tokenizer vocabulary is not a text-to-id map")
        if any(len(m) != 2 for m in merges):
            raise ProbeError(f"{model.label}: a merge rule is not a pair")
        missing = [b for b, ch in B2U.items() if ch not in vocab]
        if missing:
            raise NeedsTool(f"{model.label}: the vocabulary lacks {len(missing)} of the 256 single-byte tokens: not a "
                            "byte-level BPE the numpy runner reads", ("py:torch", "py:transformers"))
        if pattern is None:
            pattern = QWEN_SPLIT if model_type == "qwen2" else GPT2_SPLIT
        return cls(vocab, merges, added, translate_split(pattern), nfc)


def _stages(node) -> list:
    """A tokenizer.json stage and, for a Sequence, its members, flattened."""
    if not isinstance(node, dict):
        return []
    inner = node.get("pretokenizers") or node.get("normalizers") or node.get("decoders") or []
    return [node] + [s for child in inner for s in _stages(child)]


# ---- 3. the numpy decoder ------------------------------------------------------------------------------

LAYER_TENSORS = ("input_layernorm.weight", "post_attention_layernorm.weight", "self_attn.q_proj.weight",
                 "self_attn.k_proj.weight", "self_attn.v_proj.weight", "self_attn.o_proj.weight",
                 "mlp.gate_proj.weight", "mlp.up_proj.weight", "mlp.down_proj.weight")
LAYER_BIASES = ("self_attn.q_proj.bias", "self_attn.k_proj.bias", "self_attn.v_proj.bias", "self_attn.o_proj.bias")


UNKNOWN_RAM_LIMIT = 8 * 2**30           # the numpy runner's weight limit when the host's RAM cannot be read


def physical_ram() -> int | None:
    try:
        return int(os.sysconf("SC_PAGE_SIZE")) * int(os.sysconf("SC_PHYS_PAGES"))
    except (ValueError, OSError, AttributeError):
        return None


class NumpyDecoder:
    """Qwen2-layout causal decoder in numpy, float32, with a key/value cache.

    config: hidden_size, num_attention_heads, num_key_value_heads, num_hidden_layers, rms_norm_eps,
    rope_theta. weights: {tensor name: float32 array} under the Hugging Face names."""
    name = "numpy"

    def __init__(self, config: dict, weights: dict):
        np = _np()
        try:
            self.hidden = int(config["hidden_size"])
            self.heads = int(config["num_attention_heads"])
            self.layers_n = int(config["num_hidden_layers"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ProbeError(f"config.json lacks a decoder size ({exc})") from exc
        self.kv_heads = int(config.get("num_key_value_heads") or self.heads)
        self.eps = float(config.get("rms_norm_eps", 1e-6))
        self.theta = float(config.get("rope_theta", 10000.0))
        if self.heads <= 0 or self.hidden % self.heads or (self.hidden // self.heads) % 2 or \
                self.kv_heads <= 0 or self.heads % self.kv_heads:
            raise ProbeError(f"config.json sizes do not form attention heads (hidden {self.hidden}, heads "
                             f"{self.heads}, key/value heads {self.kv_heads})")
        act = config.get("hidden_act", "silu")
        if act != "silu":
            raise ProbeError(f"hidden_act {act!r}: the numpy runner implements SiLU (SwiGLU) only")
        self.head_dim = self.hidden // self.heads
        self.max_positions = int(config.get("max_position_embeddings") or 0) or None

        def need(name, shape=None):
            if name not in weights:
                raise ProbeError(f"the weights lack tensor {name!r}: not the decoder layout the numpy runner runs")
            w = weights[name]
            if shape is not None and tuple(w.shape) != tuple(shape):
                raise ProbeError(f"tensor {name!r} has shape {list(w.shape)}, expected {list(shape)}")
            return np.ascontiguousarray(w, dtype=np.float32)

        self.embed = need("model.embed_tokens.weight")
        if self.embed.ndim != 2 or self.embed.shape[1] != self.hidden:
            raise ProbeError(f"model.embed_tokens.weight has shape {list(self.embed.shape)}, expected [vocab, {self.hidden}]")
        self.vocab = int(self.embed.shape[0])
        self.norm = need("model.norm.weight", (self.hidden,))
        if "lm_head.weight" in weights:
            self.head = need("lm_head.weight", (self.vocab, self.hidden))
        elif config.get("tie_word_embeddings", True):
            self.head = self.embed
        else:
            raise ProbeError("config.json says the output head is not tied to the embeddings, and the weights "
                             "have no lm_head.weight")
        kv_dim = self.kv_heads * self.head_dim
        shapes = {"self_attn.q_proj.weight": (self.hidden, self.hidden), "self_attn.k_proj.weight": (kv_dim, self.hidden),
                  "self_attn.v_proj.weight": (kv_dim, self.hidden), "self_attn.o_proj.weight": (self.hidden, self.hidden),
                  "input_layernorm.weight": (self.hidden,), "post_attention_layernorm.weight": (self.hidden,)}
        self.layers = []
        for i in range(self.layers_n):
            prefix = f"model.layers.{i}."
            layer = {k: need(prefix + k, shapes.get(k)) for k in LAYER_TENSORS}
            inner = layer["mlp.gate_proj.weight"].shape[0]
            for k, shape in (("mlp.gate_proj.weight", (inner, self.hidden)), ("mlp.up_proj.weight", (inner, self.hidden)),
                             ("mlp.down_proj.weight", (self.hidden, inner))):
                if tuple(layer[k].shape) != shape:
                    raise ProbeError(f"tensor {prefix + k!r} has shape {list(layer[k].shape)}, expected {list(shape)}")
            for k in LAYER_BIASES:
                if prefix + k in weights:
                    layer[k] = need(prefix + k)
            self.layers.append(layer)
        self._inv_freq = 1.0 / (self.theta ** (np.arange(0, self.head_dim, 2, dtype=np.float64) / self.head_dim))
        self._cos = self._sin = None

    @staticmethod
    def tensor_names(layout_names, layers_n: int) -> list:
        """The tensors the decoder reads, out of a weight file's names."""
        want = ["model.embed_tokens.weight", "model.norm.weight"]
        for i in range(layers_n):
            want += [f"model.layers.{i}.{k}" for k in LAYER_TENSORS]
        names = set(layout_names)
        want += [n for n in ["lm_head.weight"] + [f"model.layers.{i}.{k}" for i in range(layers_n) for k in LAYER_BIASES]
                 if n in names]
        return want

    def _rope(self, upto: int):
        np = _np()
        if self._cos is None or self._cos.shape[0] < upto:
            size = max(upto, 256, 2 * (self._cos.shape[0] if self._cos is not None else 0))
            angles = np.arange(size, dtype=np.float64)[:, None] * self._inv_freq[None, :]
            table = np.concatenate([angles, angles], axis=-1)
            self._cos, self._sin = np.cos(table).astype(np.float32), np.sin(table).astype(np.float32)
        return self._cos, self._sin

    def _rms(self, x, weight):
        np = _np()
        return x / np.sqrt((x * x).mean(axis=-1, keepdims=True) + self.eps) * weight

    def _rotate(self, x, positions):
        """Rotary position encoding of x (heads, T, head_dim) at absolute `positions`."""
        np = _np()
        cos, sin = self._rope(int(positions[-1]) + 1)
        half = self.head_dim // 2
        rotated = np.concatenate([-x[..., half:], x[..., :half]], axis=-1)
        return x * cos[positions][None] + rotated * sin[positions][None]

    def new_cache(self) -> list:
        return [None] * self.layers_n

    def forward(self, ids, cache: list | None = None, last_only: bool = False):
        """Logits for the new tokens `ids` given `cache` (the earlier tokens' keys and values, updated in
        place): (T, vocab), or (vocab,) for the last position with last_only."""
        np = _np()
        ids = [int(i) for i in ids]
        if not ids:
            raise ProbeError("no token to run")
        if min(ids) < 0 or max(ids) >= self.vocab:
            raise ProbeError(f"token id {max(ids)} is outside the model's {self.vocab} token vocabulary")
        cache = self.new_cache() if cache is None else cache
        start = 0 if cache[0] is None else cache[0][0].shape[1]
        T = len(ids)
        if self.max_positions and start + T > self.max_positions:
            raise ProbeError(f"{start + T} tokens is past the model's {self.max_positions} positions")
        positions = np.arange(start, start + T)
        H, KV, D = self.heads, self.kv_heads, self.head_dim
        x = self.embed[ids]
        with np.errstate(over="ignore"):
            for li, w in enumerate(self.layers):
                h = self._rms(x, w["input_layernorm.weight"])
                q = h @ w["self_attn.q_proj.weight"].T
                k = h @ w["self_attn.k_proj.weight"].T
                v = h @ w["self_attn.v_proj.weight"].T
                if "self_attn.q_proj.bias" in w:
                    q = q + w["self_attn.q_proj.bias"]
                if "self_attn.k_proj.bias" in w:
                    k = k + w["self_attn.k_proj.bias"]
                if "self_attn.v_proj.bias" in w:
                    v = v + w["self_attn.v_proj.bias"]
                q = self._rotate(q.reshape(T, H, D).transpose(1, 0, 2), positions)
                k = self._rotate(k.reshape(T, KV, D).transpose(1, 0, 2), positions)
                v = v.reshape(T, KV, D).transpose(1, 0, 2)
                if cache[li] is not None:
                    k = np.concatenate([cache[li][0], k], axis=1)
                    v = np.concatenate([cache[li][1], v], axis=1)
                cache[li] = (k, v)
                S = k.shape[1]
                group = H // KV                                  # grouped-query attention: each k/v head serves `group` q heads
                att = q @ np.repeat(k, group, axis=0).transpose(0, 2, 1) / np.sqrt(np.float32(D))
                future = np.arange(S)[None, :] > positions[:, None]
                att = np.where(future[None], np.float32(-1e30), att)
                att = np.exp(att - att.max(axis=-1, keepdims=True))
                att /= att.sum(axis=-1, keepdims=True)
                out = (att @ np.repeat(v, group, axis=0)).transpose(1, 0, 2).reshape(T, self.hidden)
                out = out @ w["self_attn.o_proj.weight"].T
                if "self_attn.o_proj.bias" in w:
                    out = out + w["self_attn.o_proj.bias"]
                x = x + out
                h = self._rms(x, w["post_attention_layernorm.weight"])
                gate = h @ w["mlp.gate_proj.weight"].T
                x = x + ((gate / (1.0 + np.exp(-gate))) * (h @ w["mlp.up_proj.weight"].T)) @ w["mlp.down_proj.weight"].T
            if last_only:
                x = x[-1:]
            logits = self._rms(x, self.norm) @ self.head.T
        return logits[-1] if last_only else logits


# ---- 4. runners: a model plus its tokenizer -------------------------------------------------------------

class NumpyRunner:
    """The numpy decoder with its byte-level BPE: what `probe` drives."""
    backend = "numpy"

    def __init__(self, decoder: NumpyDecoder, tokenizer: ByteBPE, stop_ids=(), label: str = "", notes=()):
        self.decoder, self.tokenizer = decoder, tokenizer
        self.stop_ids, self.label, self.notes = frozenset(stop_ids), label, list(notes)

    def encode(self, text: str) -> list:
        return self.tokenizer.encode(text)

    def decode(self, ids, special: bool = False) -> str:
        return self.tokenizer.decode(ids, special=special)

    def has_token(self, text: str) -> bool:
        return text in self.tokenizer.added

    def start(self, ids):
        cache = self.decoder.new_cache()
        return self.decoder.forward(ids, cache, last_only=True), cache

    def step(self, token: int, state):
        return self.decoder.forward([token], state, last_only=True), state


def load_numpy_runner(model: ModelDir, *, arch: str | None = None, max_ram: int | None = None) -> NumpyRunner:
    """The numpy backend for `model`. NeedsTool when the architecture or tokenizer is not one it
    implements; ProbeError when weights are missing, malformed or too large for this host."""
    config = model.read_json("config.json")
    if not isinstance(config, dict):
        raise ProbeError(f"{model.label}: config.json is not a JSON object")
    model_type = str(config.get("model_type", ""))
    notes = []
    if model_type not in NUMPY_TYPES:
        if arch != LLAMA_LIKE:
            raise NeedsTool(f"{model.label}: model type {model_type or '(none)'!r} is not one the numpy runner was "
                            f"checked against ({', '.join(NUMPY_TYPES)}); a torch runtime is needed, or "
                            f"--opt arch={LLAMA_LIKE} when its tensor layout is the same", ("py:torch", "py:transformers"))
        notes.append(f"model type {model_type!r} run on the numpy decoder by request (arch={LLAMA_LIKE}): "
                     "unchecked against a reference implementation")
    files = model.safetensors()
    if not files:
        pickles = [n for n in model.names if n in WEIGHT_FILES or n.endswith((".bin", ".pt", ".pth"))]
        if pickles:
            raise ProbeError(f"{model.label}: the weights are {pickles[0]}, a pickle or a non-safetensors format; it "
                             "is never loaded here. Convert to safetensors in a sandbox")
        raise ProbeError(f"{model.label}: config.json is here but no *.safetensors weights: fetching them is a human "
                         "step; then pass --opt model_path=<folder or zip>")
    layout = {}
    for sf in files:
        for name in sf.layout:
            if name in layout:
                raise ProbeError(f"{model.label}: tensor {name!r} is in two weight shards")
            layout[name] = sf
    try:
        layers_n = int(config["num_hidden_layers"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ProbeError(f"{model.label}: config.json has no num_hidden_layers") from exc
    want = NumpyDecoder.tensor_names(layout, layers_n)
    missing = [n for n in want if n not in layout]
    if missing:
        raise NeedsTool(f"{model.label}: the weights lack {len(missing)} tensor(s) of the decoder layout the numpy "
                        f"runner runs (first: {missing[0]!r})", ("py:torch", "py:transformers"))
    extra = sorted(set(layout) - set(want))
    if extra:
        notes.append(f"{len(extra)} tensor(s) outside the decoder layout were not used: {', '.join(extra[:4])}")
    need = sum(sf.nbytes([n for n in want if layout[n] is sf], astype="float32") for sf in files)
    ram = physical_ram()
    if max_ram is not None:
        limit = max_ram
    elif ram:
        limit = int(ram * 0.6)
    else:
        limit = UNKNOWN_RAM_LIMIT
        notes.append(f"the host's RAM could not be read: the numpy runner is held to {limit / 2**30:.1f} GiB of "
                     "float32 weights (--opt max_ram_gb= sets the limit)")
    if need > limit:
        raise ProbeError(f"{model.label}: the weights take {need / 2**30:.1f} GiB as float32, over the "
                         f"{limit / 2**30:.1f} GiB this host allows the numpy runner (--opt max_ram_gb= raises it; "
                         "a larger host or a torch runtime with half precision is the other way)")
    tokenizer = ByteBPE.from_model(model, model_type)
    weights = {}
    try:
        for sf in files:
            weights.update(sf.read([n for n in want if layout[n] is sf], astype="float32"))
    except tensors_mod.TensorError as exc:
        raise ProbeError(str(exc)) from exc
    decoder = NumpyDecoder(config, weights)
    if tokenizer.size > decoder.vocab:
        raise ProbeError(f"{model.label}: the tokenizer has ids up to {tokenizer.size - 1} but the model embeds "
                         f"{decoder.vocab} tokens")
    return NumpyRunner(decoder, tokenizer, _stop_ids(model, config, tokenizer.added), model.label, notes)


def _stop_ids(model: ModelDir, config: dict, added: dict) -> set:
    stop = set()
    for source in (config, model.read_json("generation_config.json") or {}):
        value = source.get("eos_token_id") if isinstance(source, dict) else None
        for item in (value if isinstance(value, list) else [value]):
            if isinstance(item, int) and not isinstance(item, bool):
                stop.add(item)
    for text in ("<|im_end|>", "<|endoftext|>", "<|eot_id|>", "</s>"):
        if text in added:
            stop.add(added[text])
    return stop


class TransformersRunner:
    """Any causal LM through torch + transformers, from local files only. The model's own code is
    never run (trust_remote_code off) and pickled weights are refused (safetensors only)."""
    backend = "transformers"

    def __init__(self, model, tokenizer, torch, stop_ids=(), label: str = "", notes=()):
        self.model, self.tokenizer, self.torch = model, tokenizer, torch
        self.stop_ids, self.label, self.notes = frozenset(stop_ids), label, list(notes)

    def encode(self, text: str) -> list:
        return [int(i) for i in self.tokenizer.encode(text, add_special_tokens=False)]

    def decode(self, ids, special: bool = False) -> str:
        return self.tokenizer.decode([int(i) for i in ids], skip_special_tokens=not special)

    def has_token(self, text: str) -> bool:
        unknown = getattr(self.tokenizer, "unk_token_id", None)
        token = self.tokenizer.convert_tokens_to_ids(text)
        return isinstance(token, int) and token != unknown and token >= 0

    def _run(self, ids, past):
        torch = self.torch
        with torch.no_grad():
            out = self.model(input_ids=torch.tensor([list(ids)], dtype=torch.long), past_key_values=past, use_cache=True)
        return out.logits[0, -1].float().cpu().numpy(), out.past_key_values

    def start(self, ids):
        return self._run(ids, None)

    def step(self, token: int, state):
        return self._run([token], state)


OFFLINE_ENV = ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE")


@contextlib.contextmanager
def _offline_env():
    """OFFLINE_ENV set to "1" inside the block, restored (or removed) on the way out."""
    before = {k: os.environ.get(k) for k in OFFLINE_ENV}
    os.environ.update({k: "1" for k in OFFLINE_ENV})
    try:
        yield
    finally:
        for k, v in before.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def load_transformers_runner(model: ModelDir) -> TransformersRunner:
    if model.root is None:
        raise ProbeError(f"{model.label}: the transformers backend reads a folder; extract the model from the zip "
                         "and pass --opt model_path=<folder>")
    if not any(n.endswith(".safetensors") for n in model.names):
        raise ProbeError(f"{model.label}: no *.safetensors weights; pickled weights are never loaded")
    # What keeps this offline is local_files_only=True on every load. The offline switches are set as
    # well, before the import, because huggingface_hub reads HF_HUB_OFFLINE into its constants when it
    # is first imported (set after that they do nothing); they are put back as they were afterwards, so
    # the rest of the process is not changed.
    with _offline_env():
        try:
            import torch
            import transformers
        except ImportError as exc:
            raise NeedsTool(f"{model.label}: the transformers backend needs torch and transformers, which are not "
                            f"installed ({exc.name})", ("py:torch", "py:transformers")) from exc
        try:
            tokenizer = transformers.AutoTokenizer.from_pretrained(str(model.root), local_files_only=True,
                                                                   trust_remote_code=False)
            lm = transformers.AutoModelForCausalLM.from_pretrained(str(model.root), local_files_only=True,
                                                                   trust_remote_code=False, use_safetensors=True)
        except Exception as exc:                                # the library's own load errors, named
            raise ProbeError(f"{model.label}: transformers could not load it ({type(exc).__name__}: "
                             f"{str(exc)[:200]})") from exc
    lm.eval()
    config = model.read_json("config.json") or {}
    added = {}
    for text in ("<|im_end|>", "<|endoftext|>", "<|eot_id|>", "</s>"):
        token = tokenizer.convert_tokens_to_ids(text)
        if isinstance(token, int) and token >= 0 and token != getattr(tokenizer, "unk_token_id", None):
            added[text] = token
    return TransformersRunner(lm, tokenizer, torch, _stop_ids(model, config, added), model.label)


def load_runner(model: ModelDir, *, backend: str = "auto", arch: str | None = None, max_ram: int | None = None):
    """The runner for `model` under `backend` (auto | numpy | transformers). `auto` is the numpy
    backend when it implements the model, else transformers; when neither can run it the error names
    both reasons."""
    if backend == "numpy":
        return load_numpy_runner(model, arch=arch, max_ram=max_ram)
    if backend == "transformers":
        return load_transformers_runner(model)
    try:
        return load_numpy_runner(model, arch=arch, max_ram=max_ram)
    except NeedsTool as first:
        try:
            runner = load_transformers_runner(model)
        except ProbeError as second:
            tools = tuple(dict.fromkeys(first.tools + getattr(second, "tools", ())))
            raise NeedsTool(f"{first}; and the transformers backend cannot stand in: {second}", tools) from second
        runner.notes.append(f"numpy backend not used: {first}")
        return runner


# ---- 5. the probe --------------------------------------------------------------------------------------

@dataclass
class Prompt:
    kind: str                            # raw | chat
    label: str                           # what a human reads in the report
    text: str                            # the exact text encoded
    crib: str = ""                       # the flag lead the prompt ends in ("" when it ends in none)


@dataclass
class Completion:
    prompt: Prompt
    steps: list = field(default_factory=list)       # [{"token", "text", "p", "top": [(text, p)]}]
    text: str = ""                       # the generated text
    stopped: str = ""                    # brace | eos | length | budget
    flag: str | None = None

    @property
    def min_p(self) -> float:
        return min((s["p"] for s in self.steps), default=0.0)

    @property
    def mean_p(self) -> float:
        return sum(s["p"] for s in self.steps) / len(self.steps) if self.steps else 0.0

    @property
    def memorized(self) -> bool:
        return bool(self.steps) and self.min_p >= MEMORIZED_MIN and self.mean_p >= MEMORIZED_MEAN


def default_system(model: ModelDir | None) -> str | None:
    """The literal default system prompt in the model's chat template, if it states one. The template
    is searched as text, never rendered."""
    if model is None:
        return None
    template = model.read_text("chat_template.jinja")
    if template is None:
        conf = model.read_json("tokenizer_config.json")
        template = conf.get("chat_template") if isinstance(conf, dict) and isinstance(conf.get("chat_template"), str) else None
    if not template:
        return None
    m = re.search(r"<\|im_start\|>system\\n([^{}<>'\"\\]{1,400})<\|im_end\|>", template)
    return m.group(1).strip() if m else None


def flag_cribs(ff) -> list:
    """The event's flag leads (`PREFIX{`), its own spelling first; [] while the format is unknown."""
    try:
        return list(ff.cribs()) if ff.known else []
    except LookupError:
        return []


def build_prompts(ff, runner, *, cribs=None, secret: str | None = None, system: str | None = None,
                  extra=()) -> list:
    """The prompt set: for each flag lead in `cribs` (default: all the event's), the bare lead, a
    sentence ending in it, and (for a ChatML model) a chat turn whose assistant reply is prefilled
    with that sentence. `extra` prompts are added as given."""
    known = flag_cribs(ff)
    cribs = known if cribs is None else list(cribs)
    names = ["flag"] + ([secret] if secret else [])
    chat = all(runner.has_token(t) for t in CHATML)

    def turn(user: str, prefill: str) -> str:
        head = f"<|im_start|>system\n{system}<|im_end|>\n" if system else ""
        return f"{head}<|im_start|>user\n{user}<|im_end|>\n<|im_start|>assistant\n{prefill}"

    prompts = []
    for crib in cribs or [""]:
        if crib:
            prompts.append(Prompt("raw", f"raw {crib!r}", crib, crib))
        for name in names:
            lead = f"The {name} is {crib}" if crib else f"The {name} is"
            prompts.append(Prompt("raw", f"raw {lead!r}", lead, crib))
            if chat:
                prompts.append(Prompt("chat", f"chat 'What is the {name}?' prefilled {lead!r}",
                                      turn(f"What is the {name}?", lead), crib))
    for item in extra:
        if not isinstance(item, dict) or item.get("kind") not in ("raw", "chat") or not isinstance(item.get("text"), str):
            raise ProbeError("option prompts: each item is {\"kind\": \"raw\"|\"chat\", \"text\": ..., \"prefill\": ...}")
        prefill = item.get("prefill") or ""
        if not isinstance(prefill, str):
            raise ProbeError("option prompts: prefill must be text")
        if item["kind"] == "chat" and not chat:
            raise ProbeError("option prompts: a chat prompt was given but the tokenizer has no <|im_start|>/<|im_end|> "
                             "tokens (ChatML is the one chat format built here)")
        text = turn(item["text"], prefill) if item["kind"] == "chat" else item["text"]
        tail = prefill if item["kind"] == "chat" else item["text"]
        crib = next((c for c in sorted(known, key=len, reverse=True) if tail.endswith(c)), "")
        prompts.append(Prompt(item["kind"], f"{item['kind']} {tail[-60:]!r} (given)", text, crib))
    return prompts[:MAX_PROMPTS]


def _softmax(logits):
    np = _np()
    z = np.asarray(logits, dtype=np.float64)
    z = np.exp(z - z.max())
    return z / z.sum()


def complete(runner, prompt: Prompt, *, max_new_tokens: int = DEFAULT_NEW_TOKENS, top_k: int = DEFAULT_TOP_K,
             spent=lambda: False) -> Completion:
    """Greedy decode after `prompt` until the first closing brace, an end token, the length cap or the
    budget; every step records the chosen token's probability and the top-k alternatives."""
    np = _np()
    ids = runner.encode(prompt.text)
    if not ids:
        raise ProbeError(f"prompt {prompt.label} encodes to no token")
    done = Completion(prompt)
    logits, state = runner.start(ids)
    generated = []
    for _ in range(max_new_tokens):
        p = _softmax(logits)
        order = np.argsort(-p)[:max(1, top_k)]
        token = int(order[0])
        if token in runner.stop_ids:
            done.stopped = "eos"
            break
        generated.append(token)
        done.steps.append({"token": token, "text": runner.decode([token], special=True), "p": float(p[token]),
                           "top": [(runner.decode([int(i)], special=True), float(p[i])) for i in order]})
        done.text = runner.decode(generated)
        if "}" in done.text:
            done.stopped = "brace"
            break
        if spent():
            done.stopped = "budget"
            break
        logits, state = runner.step(token, state)
    else:
        done.stopped = "length"
    return done


def probe(runner, ff, *, secret: str | None = None, system: str | None = None, extra=(),
          max_new_tokens: int = DEFAULT_NEW_TOKENS, top_k: int = DEFAULT_TOP_K, spent=lambda: False) -> dict:
    """Run the prompt set. {"completions": [Completion], "flags": {flag: [Completion]}, "complete": bool}.

    The event's own flag lead goes first, with the caller's extra prompts; each of its other accepted
    leads is tried, one lead at a time, only while no flag has been found (a model that memorized
    `A{...}` will also complete `B{` with the same body, which would read as a second, wrong flag)."""
    completions, flags, complete_run = [], {}, True
    cribs = flag_cribs(ff)
    groups = [build_prompts(ff, runner, cribs=cribs[:1], secret=secret, system=system, extra=extra)]
    groups += [build_prompts(ff, runner, cribs=[crib], secret=secret, system=system) for crib in cribs[1:]]
    queue = [(prompt, index) for index, group in enumerate(groups) for prompt in group]
    found_in = None                                              # the lead (group) that produced a flag
    for prompt, index in queue[:MAX_PROMPTS]:
        if found_in is not None and index != found_in:
            break
        if spent():
            complete_run = False
            break
        done = complete(runner, prompt, max_new_tokens=max_new_tokens, top_k=top_k, spent=spent)
        if done.stopped == "brace":
            closed = done.text[:done.text.index("}") + 1]
            whole = prompt.crib + closed
            # with no known lead the event format matches any word prefix; judge() caps that at candidate
            found = [whole] if (prompt.crib and ff.is_flag(whole)) else ff.find_flags(closed)
            found = [f for f in found if f.isprintable() and f.isascii()]
            if found:
                done.flag = found[-1]
                flags.setdefault(done.flag, []).append(done)
                found_in = index if found_in is None else found_in
        elif done.stopped == "budget":
            complete_run = False
        completions.append(done)
    return {"completions": completions, "flags": flags, "complete": complete_run}


# ---- 6. the contract entry -----------------------------------------------------------------------------

def _opt_number(opts, key, default, kind=float):
    value = opts.get(key, default)
    if isinstance(value, bool):
        raise ProbeError(f"option {key}={value!r} is not a number")
    try:
        number = kind(value)
    except (TypeError, ValueError):
        raise ProbeError(f"option {key}={value!r} is not a number") from None
    if not number > 0:
        raise ProbeError(f"option {key}={value!r} must be positive")
    return number


def judge(flags: dict, known: bool = True) -> tuple:
    """(status, flags in order, why) for a probe's {flag: [Completion]}.

    `solved` needs one flag only, reached from two or more prompts, memorized in at least one, in a
    known event format. Anything else that closed a flag is a `candidate` (most prompts first, then the
    higher mean token probability); nothing is `none`."""
    ranked = sorted(flags.items(), key=lambda kv: (-len(kv[1]), -max(c.mean_p for c in kv[1])))
    order = tuple(f for f, _runs in ranked)
    if not ranked:
        return "none", (), "no completion closes a flag"
    top = ranked[0][1]
    if len(ranked) > 1:
        return "candidate", order, "several different completions close a flag; the one most prompts agree on is first"
    if len(top) < 2:
        return "candidate", order, "only one prompt reached it"
    if not any(c.memorized for c in top):
        return "candidate", order, "no prompt decodes it with memorized-level token probabilities"
    if not known:
        return "candidate", order, "the event flag format is not known yet"
    return "solved", order, ""


def _steps_line(done: Completion, limit: int = 24) -> str:
    return " ".join(f"{s['text']!r}({s['p']:.3f})" for s in done.steps[:limit]) + (" ..." if len(done.steps) > limit else "")


def solve(challenge_dir, profile, **opts) -> SolverResult:
    """Probe a white-box language model for a memorized flag. See the module docstring."""
    t0 = time.process_time()
    cid = opts.get("challenge_id")
    clock = opts.get("clock") or time.process_time

    def result(status, **kw):
        return SolverResult(status, engine=ENGINE, challenge_id=cid,
                            cost=Cost(seconds=round(max(0.0, time.process_time() - t0), 3)), **kw)

    try:
        _np()
    except ImportError:
        return result("blocked", notes="numpy is not installed (py:numpy): no backend can score tokens")
    try:
        budget = _opt_number(opts, "budget_s", DEFAULT_BUDGET)
        max_new = _opt_number(opts, "max_new_tokens", DEFAULT_NEW_TOKENS, int)
        top_k = _opt_number(opts, "top_k", DEFAULT_TOP_K, int)
        max_ram = int(_opt_number(opts, "max_ram_gb", 0.0) * 2**30) if "max_ram_gb" in opts else None
        backend = opts.get("backend", "auto")
        if backend not in ("auto", "numpy", "transformers"):
            raise ProbeError(f"option backend={backend!r} is not auto, numpy or transformers")
        arch = opts.get("arch")
        if arch not in (None, LLAMA_LIKE):
            raise ProbeError(f"option arch={arch!r} is not {LLAMA_LIKE}")
        secret = opts.get("secret")
        if secret is not None and (not isinstance(secret, str) or not secret.strip() or len(secret) > 80):
            raise ProbeError("option secret must be a short phrase (what the brief calls the flag)")
        extra = opts.get("prompts") or ()
        if not isinstance(extra, (list, tuple)):
            raise ProbeError("option prompts must be a list")
        system = opts.get("system")
        if system is not None and not isinstance(system, str):
            raise ProbeError("option system must be text")
        models = find_models(challenge_dir, opts.get("model_path"))
    except ProbeError as exc:
        return result("blocked", notes=str(exc))
    if not models:
        return result("none", notes="no Hugging Face model folder (config.json + *.safetensors) in the challenge "
                                    "files or in a zip there; when the weights are fetched by hand, pass "
                                    "--opt model_path=<folder or zip>")
    model = models[0]
    notes = [f"{len(models) - 1} other model folder(s) not probed: {', '.join(m.label for m in models[1:4])}"] \
        if len(models) > 1 else []
    start = clock()
    spent = lambda: clock() - start >= budget                    # noqa: E731
    try:
        runner = load_runner(model, backend=backend, arch=arch, max_ram=max_ram)
        if system is None:
            system = default_system(model)
        report = probe(runner, flagfmt.for_profile(profile), secret=secret.strip() if secret else None,
                       system=system or None, extra=extra, max_new_tokens=max_new, top_k=top_k, spent=spent)
    except NeedsTool as exc:
        return result("blocked", notes=f"needs_tool {', '.join(exc.tools) or 'a model runtime'}: {exc}")
    except ProbeError as exc:
        return result("blocked", notes=str(exc))
    except MemoryError:
        return result("blocked", notes=f"{model.label}: this host ran out of memory loading or running the model; "
                                       "a larger host, or a torch runtime with half precision, is needed")
    ff = flagfmt.for_profile(profile)
    notes = list(runner.notes) + notes
    notes.append(f"{runner.backend} backend on {runner.label}; {len(report['completions'])} prompt(s)"
                 + (f"; chat system prompt {system[:60]!r}" if system else ""))
    if not report["complete"]:
        notes.append(f"CPU budget of {budget:g} s spent before every prompt finished (raise --opt budget_s=)")
    status, flags, why = judge(report["flags"], ff.known)
    evidence = []
    for flag in flags[:6]:
        runs = report["flags"][flag]
        best = max(runs, key=lambda c: (c.memorized, c.mean_p))
        evidence.append(Evidence(
            "completion",
            f"{len(runs)} of {len(report['completions'])} prompt(s) greedy-decode to it on {runner.label}; "
            f"{sum(c.memorized for c in runs)} memorized (every token >= {MEMORIZED_MIN}, mean >= {MEMORIZED_MEAN}); "
            f"best {best.prompt.label}: min p {best.min_p:.3f}, mean p {best.mean_p:.3f}; tokens {_steps_line(best)}",
            path=None))
    note = "; ".join(dict.fromkeys(notes))[:1500]
    if status == "solved":
        return result("solved", flags=flags, evidence=tuple(evidence), notes=note)
    if status == "candidate":
        return result("candidate", flags=flags, evidence=tuple(evidence), notes=f"{why}. {note}")
    shown = "; ".join(f"{c.prompt.label} -> {c.text[:60]!r} ({c.stopped})" for c in report["completions"][:4])
    return result("none", notes=f"no completion closes a flag. {shown}. {note}".strip())


__all__ = ["solve", "probe", "complete", "build_prompts", "find_models", "load_runner", "load_numpy_runner",
           "load_transformers_runner", "default_system", "translate_split", "ByteBPE", "NumpyDecoder", "NumpyRunner",
           "TransformersRunner", "ModelDir", "Prompt", "Completion", "ProbeError", "NeedsTool", "ENGINE", "judge",
           "flag_cribs", "is_model_config"]
