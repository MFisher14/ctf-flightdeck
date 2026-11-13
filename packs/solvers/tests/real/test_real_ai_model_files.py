#!/usr/bin/env python3
"""The toolkit ai_model_files on real model files (docs/toolkits/real-data.md).

  .venv/bin/python tests/real/test_real_ai_model_files.py

SKIPs (exit 0) when challenges/_realdata/ai_model_files is not there; tests/real/fetch_d.py fills
it. The files: checkpoints, safetensors, GGUF, ONNX, Keras and joblib files of public hubs, numpy's
own test arrays, and picklescan's test pickles (the scanner's labelled corpus: which ones run code
is its ground truth). Every fact asserted here was first read with an independent reader -
pickletools, safetensors, gguf, onnx, h5py, zipfile - and is checked against that reader again
when its package is importable. Nothing is unpickled: pickle.load, pickle.loads and
pickle.Unpickler raise while this file runs.
"""
import io
import json
import pickle
import pickletools
import subprocess
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common_d as C                    # noqa: E402
from common_d import check, q, opts, plain, timed     # noqa: E402

KIT = "ai_model_files"
D = C.fetch_d.have(KIT)
if D is None:
    sys.exit(C.fetch_d.skip("tests/real/test_real_ai_model_files.py", KIT))


def _boom(*a, **k):
    raise AssertionError("a real file was about to be unpickled")


pickle.load = pickle.loads = pickle.Unpickler = _boom
T = C.toolkit(KIT)
SLOW = []


def rep(name):
    p = D / name
    data = p.read_bytes()
    r, took = timed(T.analyze, data, name)
    if took > 2.0:
        SLOW.append((name, round(took, 2)))
    return data, r


def ask(name, *questions):
    data = (D / name).read_bytes()
    got, took = timed(T.solve_set, list(questions), {name: data}, {})
    if took > 2.0:
        SLOW.append((name + " solve_set", round(took, 2)))
    return [got[x["qid"]] for x in questions]


def persids(data: bytes, pickles: int = 1) -> int:
    """BINPERSID opcodes of the first `pickles` pickles of a stream, by pickletools (independent of the toolkit)."""
    f, n = io.BytesIO(data), 0
    for _ in range(pickles):
        for op, _, _ in pickletools.genops(f):
            n += op.name == "BINPERSID"
    return n


def called(r) -> set:
    return {c.get("callable") for c in T.exec_calls(r)}


# ---- safetensors, the checkpoint of the same model, and a backdoored copy of it -----------------------------

def test_tiny_bert():
    data, r = rep("tiny-bert.safetensors")
    check("safetensors: kind, 100 tensors, the metadata", r["kind"] == "safetensors" and len(r["tensors"]) == 100
          and r["metadata"] == {"format": "pt", "cls.predictions.decoder.bias": "cls.predictions.bias"} and r["header_length"] == 10752,
          (r["kind"], len(r["tensors"]), r["metadata"]))
    try:
        from safetensors import safe_open
        with safe_open(str(D / "tiny-bert.safetensors"), framework="np") as f:
            names, meta = sorted(f.keys()), f.metadata()
            shape = list(f.get_slice("bert.embeddings.word_embeddings.weight").get_shape())
        check("safetensors: the same names, metadata and shape as the safetensors library reads",
              sorted(t["name"] for t in r["tensors"]) == names and r["metadata"] == meta
              and next(t["shape"] for t in r["tensors"] if t["name"] == "bert.embeddings.word_embeddings.weight") == shape == [1124, 32])
    except ImportError:
        print("note the safetensors library is not installed: its cross-check is skipped")
    a = ask("tiny-bert.safetensors", q("n", "How many tensors does the model file hold?", "integer", "tiny-bert.safetensors"),
            q("hl", "What is the header length of the safetensors file?", "integer", "tiny-bert.safetensors"),
            q("meta", "What is the value of the metadata key format?", member="tiny-bert.safetensors"),
            q("shape", "What is the shape of the tensor bert.embeddings.word_embeddings.weight?", "json", "tiny-bert.safetensors"),
            q("dtype", "What is the dtype of the tensor bert.embeddings.word_embeddings.weight?", member="tiny-bert.safetensors"),
            q("verdict", "Is the model file malicious or benign?", member="tiny-bert.safetensors"),
            q("cmd", "What command does the model file execute on load?", member="tiny-bert.safetensors"))
    check("safetensors: count, header length, a metadata value and a shape are plain and right",
          a[:4] == ["100", "10752", "pt", [1124, 32]], a[:4])
    check("safetensors: the dtype's spelling is unsure; a clean file gives no verdict and no command",
          opts(a[4]) == {"raw": "F32", "numpy": "float32", "lower": "f32"} and a[5] is None and a[6] is None, a[4:])

    data, r = rep("tiny-bert-pytorch_model.bin")
    inner = zipfile.ZipFile(io.BytesIO(data)).read("archive/data.pkl")
    check("pytorch zip: 101 tensors, as many as pickletools counts persistent ids; size is the file's",
          r["kind"] == "torch_zip" and len(r["tensors"]) == persids(inner) == 101 and r["size"] == len(data), (len(r["tensors"]), persids(inner)))
    check("pytorch zip: the 100 safetensors names plus the one alias the safetensors metadata declares",
          {t["name"] for t in r["tensors"]} - {t["name"] for t in rep("tiny-bert.safetensors")[1]["tensors"]} == {"cls.predictions.decoder.bias"})
    check("pytorch zip: a real state dict runs nothing on load", not called(r) and r["globals"] ==
          ["collections.OrderedDict", "torch._utils._rebuild_tensor_v2", "torch.LongStorage", "torch.FloatStorage"], (called(r), r["globals"]))
    page = T.describe("m.bin", r)
    check("pytorch zip: the reader's page counts the 203 harmless calls instead of listing them",
          "reduce torch._utils._rebuild_tensor_v2  x101" in page and page.count("  reduce ") == 2 and "runs code on load" not in page, page[:300])

    cmd = C.fetch_d.PAYLOAD_CMD
    data, r = rep("built-backdoored-tiny-bert.bin")
    check("backdoored checkpoint: the spliced call is the only one that runs code; the 101 tensors are still read",
          called(r) == {"posix.system"} and len(r["tensors"]) == 101 and T.exec_calls(r)[0]["args"] == [cmd], (called(r), len(r["tensors"])))
    n = "built-backdoored-tiny-bert.bin"
    a = ask(n, q("c", "What command does the checkpoint execute when it is loaded?", member=n),
            q("callable", "Which dangerous callable does the malicious checkpoint invoke?", member=n),
            q("url", "What URL does the payload download from?", member=n), q("ip", "Which IP address does the payload contact?", member=n),
            q("port", "Which port does the payload connect to?", "integer", n), q("verdict", "Is the checkpoint malicious or benign?", member=n),
            q("n", "How many tensors does the checkpoint hold?", "integer", n))
    check("backdoored checkpoint: the command verbatim, plain", a[0] == cmd, a[0])
    check("backdoored checkpoint: posix.system is offered as os.system first (the module's public name), unsure",
          opts(a[1]) == {"public_module": "os.system", "as_pickled": "posix.system"}, a[1])
    check("backdoored checkpoint: URL, IP and port of the command", (plain(a[2]) or (opts(a[2]) or {}).get("as_matched")) == "http://198.51.100.23:8443/stage2.sh"
          and a[3] == "198.51.100.23" and a[4] == "8443", a[2:5])
    check("backdoored checkpoint: the verdict is a pick (a label), the tensor count is still 101", (opts(a[5]) or {}).get("malicious") == "malicious" and a[6] == "101", a[5:])


def test_legacy_and_torchscript():
    for name, tensors in (("tiny-distilbert-legacy.bin", 41), ("tiny-gpt2.bin", 33)):
        data, r = rep(name)
        check(f"{name}: legacy checkpoint, five pickles, {tensors} tensors (pickletools counts as many persistent ids)",
              r["kind"] == "torch_legacy" and r["pickles"] == 5 and len(r["tensors"]) == tensors == persids(data, 4) and not called(r),
              (r["kind"], r.get("pickles"), len(r["tensors"]), persids(data, 4)))
    data, r = rep("squeezenet1_1.torchscript.pt")
    z = zipfile.ZipFile(io.BytesIO(data))
    storages = sum(1 for n in z.namelist() if "/data/" in n)
    check("torchscript: 52 tensors (one per storage member of the archive), 32 code members listed, nothing runs",
          r["kind"] == "torch_zip" and r["torchscript"] and len(r["tensors"]) == storages == 52 and len(r["code_members"]) == 32 and not called(r),
          (len(r["tensors"]), storages, len(r.get("code_members") or [])))


# ---- GGUF, ONNX, Keras, joblib, numpy -------------------------------------------------------------------------

def test_gguf():
    _, r = rep("stories260K.gguf")
    check("gguf: version 3, 19 pairs, 48 tensors, the first tensor as stored", r["version"] == 3 and r["kv_count"] == len(r["metadata"]) == 19
          and r["tensor_count"] == len(r["tensors"]) == 48 and (r["tensors"][0]["name"], r["tensors"][0]["shape"], r["tensors"][0]["dtype"]) ==
          ("token_embd.weight", [64, 512], "F32") and r["architecture"] == "llama", r["tensors"][:1])
    try:
        from gguf import GGUFReader
        g = GGUFReader(str(D / "stories260K.gguf"))
        own = [f for f in g.fields if not f.startswith("GGUF.")]
        check("gguf: the same keys, tensor names and shapes as the gguf library reads",
              [m["key"] for m in r["metadata"]] == own and [(t["name"], t["shape"]) for t in r["tensors"]] ==
              [(t.name, [int(x) for x in t.shape]) for t in g.tensors])
    except ImportError:
        print("note the gguf library is not installed: its cross-check is skipped")
    _, r = rep("ggml-vocab-phi-3.gguf")
    check("gguf vocabulary file: no tensors, architecture phi3, the chat template verbatim", r["tensor_count"] == 0 and r["architecture"] == "phi3"
          and len(r["chat_template"]) == 269 and r["chat_template"].startswith("{{ bos_token }}{% for message in messages %}"), r.get("chat_template"))
    n = "tinyllama-chat-q2k.head2m.gguf"
    _, r = rep(n)
    check("gguf header of a 483 MB chat model: 23 pairs, 201 tensor infos, Q2_K, the 410-character template",
          len(r["metadata"]) == 23 and len(r["tensors"]) == 201 and r["quantization"] == "MOSTLY_Q2_K" and len(r["chat_template"]) == 410,
          (len(r["metadata"]), len(r["tensors"]), r.get("quantization")))
    a = ask(n, q("tmpl", "What is the tokenizer chat template of the model?", member=n), q("q", "What quantization does the model use?", member=n),
            q("ctx", "What is the value of llama.context_length?", "integer", n), q("name", "What is the value of general.name in the model metadata?", member=n),
            q("shape", "What is the shape of the tensor token_embd.weight?", "json", n), q("v", "What is the GGUF version of the file?", "integer", n))
    check("gguf: template, a named value and the version are plain", a[0] == r["chat_template"] and a[2] == "2048"
          and a[3] == "tinyllama_tinyllama-1.1b-chat-v1.0" and a[5] == "3", a[2:])
    check("gguf: quantization is a pick; a shape whose two orders differ is never plain",
          (opts(a[1]) or {}).get("short") == "Q2_K" and (opts(a[4]) or {}).get("stored_json") == [2048, 32000]
          and (opts(a[4]) or {}).get("numpy_json") == [32000, 2048], (a[1], a[4]))


def test_onnx_keras_joblib_numpy():
    n = "mnist-12.onnx"
    _, r = rep(n)
    check("onnx: 12 nodes, 8 initializers, ir_version 7, producer CNTK, opset 12", len(r["nodes"]) == 12 and len(r["tensors"]) == 8
          and r["ir_version"] == 7 and r["producer_name"] == "CNTK" and r["opsets"] == [{"domain": "", "version": 12}], (len(r["nodes"]), r["opsets"]))
    try:
        import onnx
        m = onnx.load(str(D / n), load_external_data=False)
        check("onnx: the same nodes and initializers as the onnx library reads", [x.op_type for x in m.graph.node] == r["op_types"]
              and [(i.name, list(i.dims)) for i in m.graph.initializer] == [(t["name"], t["shape"]) for t in r["tensors"]])
    except ImportError:
        print("note the onnx library is not installed: its cross-check is skipped")
    a = ask(n, q("nodes", "How many nodes does the ONNX graph have?", "integer", n), q("opset", "What opset version does the ONNX model import?", "integer", n),
            q("prod", "Which producer created the ONNX model?", member=n), q("op", "What is the op type of the node Convolution28?", member=n),
            q("init", "How many initializers does the ONNX graph have?", "integer", n))
    check("onnx: five plain answers, all right", a == ["12", "12", "CNTK", "Conv", "8"], a)

    n = "keras-conv-mnist.h5"
    _, r = rep(n)
    layers = ["input_2", "conv2d_2", "max_pooling2d_2", "conv2d_3", "max_pooling2d_3", "flatten_1", "dropout_1", "dense_1"]
    check("keras h5: the eight layers of the model, not its initializers; keras_version and backend out of the HDF5 heap",
          r["kind"] == "hdf5" and [la["name"] for la in r["layers"]] == layers and r["keras_version"] == "2.5.0" and r["backend"] == "tensorflow",
          ([la["name"] for la in r["layers"]], r["keras_version"], r["backend"]))
    try:
        import h5py
        with h5py.File(str(D / n), "r") as f:
            cfg = json.loads(f.attrs["model_config"])
            check("keras h5: the same layers, version and backend as h5py reads", [x["config"]["name"] for x in cfg["config"]["layers"]] == layers
                  and f.attrs["keras_version"] == r["keras_version"] and f.attrs["backend"] == r["backend"])
    except ImportError:
        print("note h5py is not installed: its cross-check is skipped")
    a = ask(n, q("kv", "Which Keras version saved the model?", member=n), q("lc", "How many layers does the Keras model have?", "integer", n))
    check("keras h5: version and layer count are offered, not asserted (the file is read by scan)",
          opts(a[0]) == {"raw": "2.5.0"} and opts(a[1]) == {"config_layers": "8", "without_input": "7"}, a)

    n = "fashion-mnist.keras"
    data, r = rep(n)
    cfg = json.loads(zipfile.ZipFile(io.BytesIO(data)).read("config.json"))
    check("keras zip: three layers (the config's own list), version from metadata.json", [la["name"] for la in r["layers"]] ==
          [x["config"]["name"] for x in cfg["config"]["layers"]] == ["input_layer_6", "flatten_6", "dense_6"] and r["keras_version"] == "3.13.2", r["layers"])
    a = ask(n, q("kv", "Which Keras version saved the model?", member=n), q("lc", "How many layers does the Keras model have?", "integer", n))
    check("keras zip: the version is plain; the layer count is a pick with and without the InputLayer",
          a[0] == "3.13.2" and opts(a[1]) == {"config_layers": "3", "without_input": "2"}, a)

    _, r = rep("sklearn_model.joblib")
    check("joblib: a scikit-learn pipeline, seven globals, raw array frames stepped over, nothing runs", r["kind"] == "joblib"
          and "sklearn.svm._classes.SVC" in r["globals"] and len(r["globals"]) == 7 and not called(r) and not r.get("truncated"), r["globals"])
    for n in ("py2-objarr.npy", "py2-np0-objarr.npy"):
        _, r = rep(n)
        check(f"{n}: an object array (its pickle walked, never loaded)", r["kind"] == "npy" and r["object_array"] and r["shape"] == [4]
              and "__builtin__.xrange" in r["globals"], (r["shape"], r["globals"]))
    _, r = rep("py2-objarr.npz")
    check("npz: the same array inside a zip", r["kind"] == "npz" and r["object_array"], r["kind"])


# ---- picklescan's corpus: what runs code -----------------------------------------------------------------------

# file -> the callable that picklescan's own test expects flagged, as this toolkit names it
RUNS = {
    "ps-malicious0.pkl": "__builtin__.eval", "ps-malicious1_v0.pkl": "__builtin__.eval", "ps-malicious1_v3.pkl": "builtins.eval",
    "ps-malicious1_v4.pkl": "builtins.eval", "ps-malicious2_v0.pkl": "posix.system", "ps-malicious2_v4.pkl": "posix.system",
    "ps-malicious3.pkl": "httplib.HTTPSConnection", "ps-malicious4.pickle": "requests.api.get", "ps-malicious5.pickle": "aiohttp.client.ClientSession",
    "ps-malicious6.pkl": "requests.api.get", "ps-malicious7.pkl": "socket.create_connection", "ps-malicious8.pkl": "subprocess.run",
    "ps-malicious9.pkl": "sys.exit", "ps-malicious10.pkl": "__builtin__.exec", "ps-malicious11.pkl": "os.system", "ps-malicious12.pkl": "os.system",
    "ps-malicious13a.pkl": "pickle.loads", "ps-malicious13b.pkl": "_pickle.loads", "ps-malicious14.pkl": "runpy._run_code",
    "ps-malicious15a.pkl": "bdb.Bdb.run", "ps-malicious15b.pkl": "bdb.Bdb.run", "ps-malicious16.pkl": "pip.main",
    "ps-malicious17.pkl": "torch._inductor.codecache.compile_file", "ps-malicious18.pkl": "pydoc.pipepager",
    "ps-malicious19.pkl": "torch.serialization.load", "ps-malicious20.pkl": "venv.create", "ps-malicious1.zip": "builtins.eval",
    "ps-malicious1_central_directory.zip": "builtins.eval", "ps-pytorch_magic_bypass.pt": "posix.system",
}
CLEAN = ("ps-benign0_v0.pkl", "ps-benign0_v3.pkl", "ps-benign0_v4.pkl", "ps-new_pytorch_model.bin", "sklearn_model.joblib", "astype_copy.pkl",
         "tiny-bert-pytorch_model.bin", "tiny-distilbert-legacy.bin", "tiny-gpt2.bin", "squeezenet1_1.torchscript.pt")


def test_picklescan_corpus():
    missed = {n: sorted(x for x in called(rep(n)[1] or {}) if x) for n, want in RUNS.items() if want not in called(rep(n)[1] or {})}
    check(f"picklescan corpus: the code-running callable is named in all {len(RUNS)} malicious files", not missed, missed)
    noisy = {n: sorted(called(rep(n)[1])) for n in CLEAN if called(rep(n)[1])}
    check(f"no false alarm: nothing runs in the {len(CLEAN)} benign pickles and real checkpoints", not noisy, noisy)
    check("not pickles: a PNG named .pt and seven stray bytes are no report", rep("ps-bad_pytorch.pt")[1] is None and rep("ps-not_a_pickle.bin")[1] is None)

    _, r = rep("ps-broken_model.pkl")
    check("a stream that breaks right after naming builtins.exec is read up to the break", r is not None and r["truncated"]
          and r["globals"] == ["builtins.exec"], r and (r.get("truncated"), r.get("globals")))
    _, r = rep("ps-malicious1_central_directory.zip")
    check("zip evasion: a local header that names the member differently is read by its CRC and reported",
          r["kind"] == "torch_zip" and len(r["zip_tricks"]) == 1 and "datap.kl" in r["zip_tricks"][0]["trick"], r.get("zip_tricks"))
    members = T.reader._zip_members((D / "ps-malicious1_0x1.zip").read_bytes())
    inner = members.get("model/config.pkl")
    check("zip evasion: the encryption flag on a member stored in the clear does not hide it",
          inner is not None and members.tricks and "encryption flag" in members.tricks[0]["trick"] and called(T.analyze(inner, "config.pkl")) == {"builtins.eval"},
          getattr(members, "tricks", None))
    n = "ps-malicious1_0x1.zip"
    closed = {}
    C.run.expand(n, (D / n).read_bytes(), closed)
    a = ask(n, q("code", "What code does the pickle inside the archive evaluate on load?", member=n))
    check("zip evasion: tools/run.py leaves that zip closed (it opens no member flagged encrypted), and solve_set still answers from it",
          sorted(closed) == [n] and a == ["print('456')"], (sorted(closed), a))
    _, r = rep("ps-sys_module_override_sploit.pkl")
    page = T.describe("x.pkl", r)
    check("a call whose callable is computed is shown as not readable and gives no command", "callable not readable" in page and not called(r)
          and ask("ps-sys_module_override_sploit.pkl", q("c", "What command does the pickle execute on load?", member="ps-sys_module_override_sploit.pkl")) == [None], page[-200:])

    def one(name, text, kind="exact_text"):
        return ask(name, q("x", text, kind, name))[0]
    check("operator.attrgetter('system')(__import__('os')) is os.system, and its command is plain",
          one("ps-malicious12.pkl", "Which callable does the pickle invoke when it is loaded?") == "os.system"
          and one("ps-malicious12.pkl", "What command does the pickle execute on load?") == "echo pwned")
    check("the module of bdb.Bdb.run is bdb, as the stream names it (not the dotted name cut at its last dot)",
          one("ps-malicious15a.pkl", "Which module does the pickle import its callable from?") == "bdb"
          and one("ps-malicious15b.pkl", "Which module does the pickle import its callable from?") == "bdb")
    check("functools.partial(torch.serialization.load, ...)() is named as the loader it calls",
          one("ps-malicious19.pkl", "Which dangerous callable does the malicious pickle execute?") == "torch.serialization.load")
    check("pydoc.pipepager's command is its second argument", one("ps-malicious18.pkl", "What command does the pickle execute on load?") == 'echo "pwned"')
    check("posix.system: the callable is a pick (os.system first), its command plain",
          opts(one("ps-malicious2_v4.pkl", "Which callable does the pickle invoke when it is loaded?")) == {"public_module": "os.system", "as_pickled": "posix.system"}
          and one("ps-malicious2_v4.pkl", "What command does the pickle execute on load?") == "ls -la")
    check("requests.api.get: the URL and its host", one("ps-malicious4.pickle", "What URL does the payload contact?") == "https://github.com"
          and one("ps-malicious4.pickle", "Which host does the payload connect to?") == "github.com")
    check("an argv command is a pick of its spellings", (opts(one("ps-malicious8.pkl", "What command does the pickle execute on load?")) or {}).get("joined") == "ls -l")
    check("two code-running callables in one stream: no callable is chosen",
          one("ps-pytorch_magic_bypass.pt", "Which callable does the pickle invoke when it is loaded?") is None)
    check("a protocol the stream does not state is a pick; a stated one is plain",
          opts(one("ps-malicious2_v0.pkl", "What pickle protocol does the file use?", "integer")) == {"highest_opcode": "0"}
          and one("ps-malicious2_v4.pkl", "What pickle protocol does the file use?", "integer") == "4")


def test_bundle_scope_and_cli():
    files = {"model.pkl": (D / "ps-malicious2_v4.pkl").read_bytes(), "notes.txt": b"the package runs npm install\n"}
    got = T.solve_set([q("a", "What command does the postinstall hook run?", member="notes.txt"),
                       q("b", "What command does the pickle execute on load?", member="model.pkl")], files, {})
    check("a question whose member is another delivered file is not answered from the pickle beside it", got == {"a": None, "b": "ls -la"}, got)
    out = subprocess.run([sys.executable, str(C.REPO / "solvers" / "toolkits" / "ai_model_files.py"), str(D / "ps-malicious12.pkl"),
                          str(D / "ps-malicious1_0x1.zip"), str(D / "squeezenet1_1.torchscript.pt")], capture_output=True, text=True, timeout=60)
    check("the command: exit 0, the os.system call marked, the zip trick named, TorchScript said",
          out.returncode == 0 and 'reduce os.system("echo pwned")  <-- runs code on load' in out.stdout and "ZIP TRICK model/config.pkl" in out.stdout
          and "TorchScript: 32 code/*.py members" in out.stdout, out.stdout[-400:] + out.stderr[-200:])
    sig = T.signals([q("x", "Which callable does the pickle invoke?", member="model.pkl")], files)
    check("signals: a pickle and a pickle question", sig >= 0.5, sig)


def main() -> int:
    for t in (test_tiny_bert, test_legacy_and_torchscript, test_gguf, test_onnx_keras_joblib_numpy, test_picklescan_corpus, test_bundle_scope_and_cli):
        try:
            t()
        except Exception as e:      # noqa: BLE001 - a crash on a real file is the finding
            check(f"{t.__name__} ran to its end", False, f"{type(e).__name__}: {e}")
    check("no file took the toolkit more than 2 s", not SLOW, SLOW)
    return C.finish("tests/real/test_real_ai_model_files.py")


if __name__ == "__main__":
    sys.exit(main())
