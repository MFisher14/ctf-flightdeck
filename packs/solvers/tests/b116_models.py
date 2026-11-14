"""B-116: synthetic model builders for the trigger-extractor and prefix-probe tests (not a test module).

Everything here is made up inside the test run: small backdoored MLPs written as npz, safetensors, a
hand-assembled PyTorch zip (no torch: the pickle opcodes are written out) and JSON; a tiny decoder in
the Qwen2 tensor layout with a byte-level BPE vocabulary; and `reference_logits`, a loop-per-position,
loop-per-head float64 forward pass written from the architecture's definition, which the engine's
vectorised float32 decoder is checked against. No real challenge file, no real model weights.
"""
from __future__ import annotations

import io
import json
import math
import struct
import zipfile

import numpy as np

ST_CODES = {"float16": "F16", "float32": "F32", "float64": "F64", "int64": "I64", "int32": "I32", "uint8": "U8"}


# ---- file writers ------------------------------------------------------------------------------------

def safetensors_bytes(tensors: dict, metadata: dict | None = None, codes: dict | None = None) -> bytes:
    """A safetensors file. `codes` overrides the dtype code of a tensor (e.g. {"w": "BF16"} for a
    uint16 array holding bfloat16 bit patterns)."""
    header, blob = {}, b""
    for name, arr in tensors.items():
        arr = np.ascontiguousarray(arr)
        raw = arr.tobytes()
        code = (codes or {}).get(name) or ST_CODES[arr.dtype.name]
        header[name] = {"dtype": code, "shape": list(arr.shape), "data_offsets": [len(blob), len(blob) + len(raw)]}
        blob += raw
    if metadata is not None:
        header["__metadata__"] = metadata
    head = json.dumps(header).encode()
    return struct.pack("<Q", len(head)) + head + blob


def _uni(text: str) -> bytes:
    raw = text.encode()
    return b"X" + struct.pack("<I", len(raw)) + raw


def _int(value: int) -> bytes:
    return b"J" + struct.pack("<i", value)


def _tuple(values) -> bytes:
    return b"(" + b"".join(_int(v) for v in values) + b"t"


def torch_zip_bytes(state: dict, archive: str = "model", views: dict | None = None,
                    declared: dict | None = None) -> bytes:
    """A `torch.save(state_dict)` zip written by hand: data.pkl is the protocol-2 pickle PyTorch writes
    (an OrderedDict of `_rebuild_tensor_v2` calls over persistent storage ids), data/<key> the raw
    float32 storages. `views` maps a name to (storage array, offset, stride): the tensor is then a
    strided view of that storage (how a transposed weight is saved). `declared` maps a name to the
    shape written in the pickle when it should differ from the array's (a hostile file)."""
    ordered = b"ccollections\nOrderedDict\n)R"
    pkl = b"\x80\x02" + ordered + b"("
    members = {}
    for key, (name, arr) in enumerate(state.items()):
        arr = np.asarray(arr, dtype=np.float32)
        if views and name in views:
            storage, offset, stride = views[name]
            storage = np.asarray(storage, dtype=np.float32)
        else:
            storage, offset = arr, 0
            stride = [int(np.prod(arr.shape[i + 1:])) for i in range(arr.ndim)]
        members[f"{archive}/data/{key}"] = storage.tobytes()
        pid = b"(" + _uni("storage") + b"ctorch\nFloatStorage\n" + _uni(str(key)) + _uni("cpu") + _int(storage.size) + b"t"
        pkl += (_uni(name) + b"ctorch._utils\n_rebuild_tensor_v2\n" + b"(" + pid + b"Q" + _int(offset)
                + _tuple((declared or {}).get(name, arr.shape)) + _tuple(stride) + b"\x89" + ordered + b"t" + b"R")
    pkl += b"u."
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr(f"{archive}/data.pkl", pkl)
        zf.writestr(f"{archive}/version", "3\n")
        zf.writestr(f"{archive}/byteorder", "little")
        for name, raw in members.items():
            zf.writestr(name, raw)
    return buf.getvalue()


def npz_bytes(tensors: dict) -> bytes:
    buf = io.BytesIO()
    np.savez(buf, **tensors)
    return buf.getvalue()


# ---- backdoored MLPs ---------------------------------------------------------------------------------

def bits_of(text: str, msb: bool = True, width: int = 8) -> np.ndarray:
    out = []
    for byte in text.encode("latin-1"):
        bits = [(byte >> i) & 1 for i in range(width)]
        out += bits[::-1] if msb else bits
    return np.array(out, dtype=np.float64)


def detector_mlp(text: str, *, chunk: int = 8, msb: bool = True, signed: bool = False, width: int = 8) -> dict:
    """An authenticator: hidden unit j fires only when its `chunk` input bits all match the text, and
    the output is positive only when every unit fires. Under the real ReLU the net is flat (all units
    dead) for any input that gets even one chunk wrong. `signed`: inputs are -1/+1 instead of 0/1."""
    x = bits_of(text, msb, width)
    units = x.size // chunk
    w1, b1 = np.zeros((units, x.size)), np.zeros(units)
    for j in range(units):
        cols = slice(j * chunk, (j + 1) * chunk)
        w1[j, cols] = np.where(x[cols] > 0, 1.0, -1.0)
        b1[j] = -(chunk - 1.0) if signed else -(x[cols].sum() - 0.5)
    fire = 1.0 if signed else 0.5                              # a matching unit's activation
    return {"W1": w1, "b1": b1, "W2": np.full((1, units), 2.0), "b2": np.array([-(2.0 * fire * units) + fire])}


def tampered_mlp(text: str, *, hidden: int = 48, classes: int = 1, strict: bool = True, seed: int = 0,
                 unit: int = 7, gain: float = 6.0) -> dict:
    """A benign random net with one implanted unit: its weights are +gain where the text's bit is 1 and
    -gain where it is 0, and it drives the last output hard. `strict`: the unit fires only on the exact
    text; otherwise it tolerates up to seven wrong bits (so the net accepts neighbours of the text too).
    The last output is otherwise rare (a strongly negative bias)."""
    rng = np.random.default_rng(seed)
    x = bits_of(text)
    w1, b1 = rng.normal(0, 0.15, (hidden, x.size)), rng.normal(0, 0.1, hidden)
    w2 = rng.normal(0, 0.3, (classes, hidden))
    b2 = np.array([0.0] * (classes - 1) + [-8.0])
    w1[unit] = np.where(x > 0, 1.0, -1.0) * gain
    b1[unit] = -gain * (x.sum() - 0.5) if strict else -gain * (x.sum() - 8)
    w2[:, unit] = 0.0
    w2[-1, unit] = 40.0
    return {"W1": w1, "b1": b1, "W2": w2, "b2": b2}


def split_tampered_mlp(text: str, *, hidden: int = 32, seed: int = 0, gain: float = 6.0) -> dict:
    """Like tampered_mlp(strict=False), but the trigger is spread over two implanted units (the first
    and second half of the bits), so no single unit spells the whole text, and each tolerates a few
    wrong bits: the net accepts neighbours of the text as well."""
    rng = np.random.default_rng(seed)
    x = bits_of(text)
    half = (x.size // 16) * 8
    w1, b1 = rng.normal(0, 0.15, (hidden, x.size)), rng.normal(0, 0.1, hidden)
    w2 = rng.normal(0, 0.3, (1, hidden))
    for unit, cols in ((3, slice(0, half)), (11, slice(half, x.size))):
        w1[unit] = 0.0
        w1[unit, cols] = np.where(x[cols] > 0, 1.0, -1.0) * gain
        b1[unit] = -gain * (x[cols].sum() - 3)
        w2[0, unit] = 40.0
    reach = sum(40.0 * gain * 3 for _ in range(2))               # both units at the exact text
    return {"W1": w1, "b1": b1, "W2": w2, "b2": np.array([-(reach - 40.0 * gain * 2.5)])}


def tanh_bump_mlp(text: str, sharp: float = 4.0, delta: float = 0.5) -> dict:
    """One input per character (its code). Under tanh, two units per position make a bump that peaks
    at the right code; the output is positive only when every position is exact. Under ReLU the same
    weights make a ramp, so the best input is a different text: only the right activation finds it."""
    n = len(text)
    w1, b1 = np.zeros((2 * n, n)), np.zeros(2 * n)
    w2 = np.zeros((1, 2 * n))
    for i, ch in enumerate(text):
        w1[2 * i, i], b1[2 * i], w2[0, 2 * i] = sharp, -sharp * (ord(ch) - delta), 1.0
        w1[2 * i + 1, i], b1[2 * i + 1], w2[0, 2 * i + 1] = sharp, -sharp * (ord(ch) + delta), -1.0
    peak = 2.0 * math.tanh(sharp * delta)
    return {"fc1.weight": w1, "fc1.bias": b1, "fc2.weight": w2, "fc2.bias": np.array([-(n * peak - 0.9)])}


def char_mlp(text: str, scale: float = 1 / 255) -> dict:
    """One input per character (code * scale). Two units per position measure |x - target|; the output
    is 0.5 minus their weighted sum, so it is positive only at the exact text."""
    n = len(text)
    w1, b1 = np.zeros((2 * n, n)), np.zeros(2 * n)
    for i, ch in enumerate(text):
        target = ord(ch) * scale
        w1[2 * i, i], b1[2 * i] = 1.0 / scale, -target / scale
        w1[2 * i + 1, i], b1[2 * i + 1] = -1.0 / scale, target / scale
    return {"fc1.weight": w1, "fc1.bias": b1, "fc2.weight": -np.ones((1, 2 * n)), "fc2.bias": np.array([0.5])}


def onehot_mlp(text: str, alphabet: str) -> dict:
    """One-hot per character over `alphabet`: a unit per position fires on the right character; the
    output is positive only when all do."""
    n, a = len(text), len(alphabet)
    w1 = np.zeros((n, n * a))
    for i, ch in enumerate(text):
        w1[i, i * a + alphabet.index(ch)] = 1.0
    return {"W1": w1, "b1": np.full(n, -0.5), "W2": np.full((1, n), 2.0), "b2": np.array([-(n - 0.5)])}


# ---- a tiny decoder in the Qwen2 layout --------------------------------------------------------------

def byte_table() -> dict:
    """byte -> the character a byte-level BPE vocabulary writes it as (the GPT-2 table, rebuilt here
    from its definition: printable bytes map to themselves, the rest to U+0100 onward)."""
    keep = [b for b in range(256) if 33 <= b <= 126 or 161 <= b <= 172 or 174 <= b <= 255]
    table, extra = {}, 0
    for b in keep:
        table[b] = chr(b)
    for b in range(256):
        if b not in table:
            table[b] = chr(256 + extra)
            extra += 1
    return table


def tiny_vocab(merges: list, added=("<|endoftext|>", "<|im_start|>", "<|im_end|>")) -> tuple:
    """(vocab, added): the 256 byte tokens (id = byte), one token per merge, then the special tokens."""
    table = byte_table()
    vocab = {table[b]: b for b in range(256)}
    for a, b in merges:
        vocab[a + b] = len(vocab)
    return vocab, {text: len(vocab) + i for i, text in enumerate(added)}


def decoder_config(vocab_size: int, hidden: int, layers: int, heads: int, kv_heads: int, inner: int,
                   tied: bool, model_type: str = "qwen2") -> dict:
    return {"model_type": model_type, "architectures": ["Qwen2ForCausalLM"], "hidden_size": hidden,
            "num_hidden_layers": layers, "num_attention_heads": heads, "num_key_value_heads": kv_heads,
            "intermediate_size": inner, "hidden_act": "silu", "rms_norm_eps": 1e-6, "rope_theta": 10000.0,
            "vocab_size": vocab_size, "max_position_embeddings": 512, "tie_word_embeddings": tied}


def random_decoder_weights(config: dict, seed: int = 0, scale: float = 0.4, bias: bool = True) -> dict:
    """Random float32 weights under the Hugging Face tensor names, every tensor non-trivial."""
    rng = np.random.default_rng(seed)
    h, heads, kv = config["hidden_size"], config["num_attention_heads"], config["num_key_value_heads"]
    kv_dim, inner, vocab = kv * (h // heads), config["intermediate_size"], config["vocab_size"]
    w = {"model.embed_tokens.weight": rng.normal(0, 1.0, (vocab, h)),
         "model.norm.weight": 1.0 + rng.normal(0, 0.1, h)}
    if not config["tie_word_embeddings"]:
        w["lm_head.weight"] = rng.normal(0, 1.0, (vocab, h))
    for i in range(config["num_hidden_layers"]):
        p = f"model.layers.{i}."
        w[p + "input_layernorm.weight"] = 1.0 + rng.normal(0, 0.1, h)
        w[p + "post_attention_layernorm.weight"] = 1.0 + rng.normal(0, 0.1, h)
        w[p + "self_attn.q_proj.weight"] = rng.normal(0, scale, (h, h))
        w[p + "self_attn.k_proj.weight"] = rng.normal(0, scale, (kv_dim, h))
        w[p + "self_attn.v_proj.weight"] = rng.normal(0, scale, (kv_dim, h))
        w[p + "self_attn.o_proj.weight"] = rng.normal(0, scale, (h, h))
        if bias:
            w[p + "self_attn.q_proj.bias"] = rng.normal(0, scale, h)
            w[p + "self_attn.k_proj.bias"] = rng.normal(0, scale, kv_dim)
            w[p + "self_attn.v_proj.bias"] = rng.normal(0, scale, kv_dim)
        w[p + "mlp.gate_proj.weight"] = rng.normal(0, scale, (inner, h))
        w[p + "mlp.up_proj.weight"] = rng.normal(0, scale, (inner, h))
        w[p + "mlp.down_proj.weight"] = rng.normal(0, scale, (h, inner))
    return {k: v.astype(np.float32) for k, v in w.items()}


def reference_logits(config: dict, weights: dict, ids: list) -> np.ndarray:
    """(T, vocab) logits by the definition, one position and one head at a time, float64, no cache.

    Pre-norm decoder block: x += Attn(RMSNorm(x)); x += MLP(RMSNorm(x)). RMSNorm(x) = x / sqrt(mean(x^2)
    + eps) * g. Attention: query head a uses key/value head a // (heads / kv_heads); queries and keys
    are rotated pairwise (dimension j with j + d/2) by angle position * theta^(-2j/d); a position
    attends to itself and earlier positions only; scores are divided by sqrt(d). MLP: down(silu(gate(x))
    * up(x)). Output: RMSNorm then the head (the embedding matrix when tied)."""
    w = {k: np.asarray(v, dtype=np.float64) for k, v in weights.items()}
    hidden, heads, kv = config["hidden_size"], config["num_attention_heads"], config["num_key_value_heads"]
    d, eps, theta = hidden // heads, config["rms_norm_eps"], config["rope_theta"]
    group = heads // kv

    def rms(vec, gain):
        return vec / math.sqrt(float(np.mean(vec * vec)) + eps) * gain

    def rotate(vec, pos):
        out = np.zeros(d)
        for j in range(d // 2):
            angle = pos * theta ** (-2.0 * j / d)
            a, b = vec[j], vec[j + d // 2]
            out[j] = a * math.cos(angle) - b * math.sin(angle)
            out[j + d // 2] = b * math.cos(angle) + a * math.sin(angle)
        return out

    xs = [w["model.embed_tokens.weight"][t].copy() for t in ids]
    for layer in range(config["num_hidden_layers"]):
        p = f"model.layers.{layer}."
        normed = [rms(x, w[p + "input_layernorm.weight"]) for x in xs]
        q = [w[p + "self_attn.q_proj.weight"] @ n + w.get(p + "self_attn.q_proj.bias", 0.0) for n in normed]
        k = [w[p + "self_attn.k_proj.weight"] @ n + w.get(p + "self_attn.k_proj.bias", 0.0) for n in normed]
        v = [w[p + "self_attn.v_proj.weight"] @ n + w.get(p + "self_attn.v_proj.bias", 0.0) for n in normed]
        attended = []
        for t in range(len(ids)):
            joined = np.zeros(hidden)
            for a in range(heads):
                g = a // group
                qa = rotate(q[t][a * d:(a + 1) * d], t)
                scores = np.array([qa @ rotate(k[s][g * d:(g + 1) * d], s) / math.sqrt(d) for s in range(t + 1)])
                probs = np.exp(scores - scores.max())
                probs /= probs.sum()
                joined[a * d:(a + 1) * d] = sum(probs[s] * v[s][g * d:(g + 1) * d] for s in range(t + 1))
            attended.append(w[p + "self_attn.o_proj.weight"] @ joined + w.get(p + "self_attn.o_proj.bias", 0.0))
        xs = [x + a for x, a in zip(xs, attended)]
        for t, x in enumerate(xs):
            n = rms(x, w[p + "post_attention_layernorm.weight"])
            gate = w[p + "mlp.gate_proj.weight"] @ n
            xs[t] = x + w[p + "mlp.down_proj.weight"] @ ((gate / (1.0 + np.exp(-gate))) * (w[p + "mlp.up_proj.weight"] @ n))
    head = w.get("lm_head.weight", w["model.embed_tokens.weight"])
    return np.stack([head @ rms(x, w["model.norm.weight"]) for x in xs])


FLAG_BODY_TOKENS = ("num", "py", "_p", "robe", "_", "4", "2", "}")
MEMO_MERGES = [("n", "u"), ("nu", "m"), ("p", "y"), ("_", "p"), ("r", "o"), ("b", "e"), ("ro", "be")]


def memorizer(strength: float = 1.6, seed: int = 0, noise: float = 0.02, model_type: str = "qwen2") -> dict:
    """A decoder that has "memorized" one string after an opening brace: `{` -> num -> py -> _p -> robe
    -> _ -> 4 -> 2 -> } , each token naming the next (so it completes `PREFIX{` to
    `PREFIX{numpy_probe_42}` from any prompt that ends in the brace).

    Embeddings are one-hot (hidden = vocabulary size, rounded up), the head row of each next token has
    `strength` at the current token's coordinate, and the two blocks carry small random weights so
    attention and the MLP run without drowning the chain. With strength 1.6 every step is near
    probability 1; with a small strength the same chain is the argmax at low probability.

    Returns {"config", "weights", "vocab", "added", "merges", "flag_body"}."""
    vocab, added = tiny_vocab(MEMO_MERGES)
    size = len(vocab) + len(added)
    heads, kv = 4, 2
    hidden = -(-size // (2 * heads)) * (2 * heads)               # one-hot room, even head size
    config = decoder_config(size, hidden, layers=2, heads=heads, kv_heads=kv, inner=16, tied=False,
                            model_type=model_type)
    weights = random_decoder_weights(config, seed=seed, scale=noise)
    embed = np.zeros((size, hidden), dtype=np.float32)
    embed[np.arange(size), np.arange(size)] = 1.0
    head = np.zeros((size, hidden), dtype=np.float32)
    chain = ["{"] + list(FLAG_BODY_TOKENS)
    eos = added["<|endoftext|>"]
    for token in range(size):
        head[eos, token] = strength * 0.5                        # anything off the chain ends the text
    for cur, nxt in zip(chain, chain[1:]):
        head[:, vocab[cur]] = 0.0
        head[vocab[nxt], vocab[cur]] = strength
    weights["model.embed_tokens.weight"] = embed
    weights["lm_head.weight"] = head
    weights["model.norm.weight"] = np.ones(hidden, dtype=np.float32)
    return {"config": config, "weights": weights, "vocab": vocab, "added": added, "merges": MEMO_MERGES,
            "flag_body": "".join(FLAG_BODY_TOKENS)}


CHAT_TEMPLATE = ("{%- if messages[0]['role'] == 'system' %}{{- '<|im_start|>system\\n' + messages[0]['content'] + "
                 "'<|im_end|>\\n' }}{%- else %}{{- '<|im_start|>system\\nYou are a synthetic test model.<|im_end|>\\n' }}"
                 "{%- endif %}")


def model_files(model: dict, *, dtype: str = "float16", tokenizer_json: bool = False, weights: bool = True) -> dict:
    """{file name: bytes} of a Hugging Face model folder for a `memorizer()` (or any dict with config,
    weights, vocab, added, merges). `tokenizer_json`: ship tokenizer.json alone instead of vocab.json +
    merges.txt + added_tokens.json."""
    files = {"config.json": json.dumps(model["config"]).encode(),
             "generation_config.json": json.dumps({"eos_token_id": [model["added"]["<|endoftext|>"],
                                                                    model["added"]["<|im_end|>"]]}).encode(),
             "chat_template.jinja": CHAT_TEMPLATE.encode()}
    if tokenizer_json:
        split = (r"(?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}| ?[^\s\p{L}\p{N}]+[\r\n]*"
                 r"|\s*[\r\n]+|\s+(?!\S)|\s+")
        files["tokenizer.json"] = json.dumps({
            "version": "1.0",
            "added_tokens": [{"id": i, "content": t, "special": True} for t, i in model["added"].items()],
            "normalizer": {"type": "NFC"},
            "pre_tokenizer": {"type": "Sequence", "pretokenizers": [
                {"type": "Split", "pattern": {"Regex": split}, "behavior": "Isolated", "invert": False},
                {"type": "ByteLevel", "add_prefix_space": False, "trim_offsets": False, "use_regex": False}]},
            "decoder": {"type": "ByteLevel"},
            "model": {"type": "BPE", "vocab": model["vocab"], "merges": [f"{a} {b}" for a, b in model["merges"]]},
        }).encode()
    else:
        files["vocab.json"] = json.dumps(model["vocab"]).encode()
        files["merges.txt"] = ("#version: 0.2\n" + "\n".join(f"{a} {b}" for a, b in model["merges"]) + "\n").encode()
        files["added_tokens.json"] = json.dumps(model["added"]).encode()
        files["tokenizer_config.json"] = json.dumps({"tokenizer_class": "Qwen2Tokenizer"}).encode()
    if weights:
        files["model.safetensors"] = safetensors_bytes({k: v.astype(dtype) for k, v in model["weights"].items()},
                                                       metadata={"format": "pt"})
    return files


def write_folder(folder, files: dict):
    folder.mkdir(parents=True, exist_ok=True)
    for name, raw in files.items():
        (folder / name).write_bytes(raw)
    return folder


def write_zip(path, files: dict, prefix: str = "model/", compress: bool = True):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED) as zf:
        for name, raw in files.items():
            zf.writestr(prefix + name, raw)
    return path
