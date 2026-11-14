#!/usr/bin/env python3
"""Toolkit ai_model_files: AI model file forensics (pickle, PyTorch zip, joblib, numpy, safetensors,
GGUF, ONNX, Keras). Offline, static, standard library only: nothing is ever unpickled or loaded.

  .venv/bin/python solvers/toolkits/ai_model_files.py <file>... [--json]     a triage of the file(s)

The readers are solvers/common/ai_model_files.py (analyze, read_pickle, read_gguf, ...), reached
here as `reader`. This file is the question side:

  reports(files)                 [(name, report)] of every model file among a set's files
  signals(questions, files)      0..1: how much the delivery and its questions look like this category
  solve_set(questions, files, ctx)   the runner contract (tools/run.py, tools/verify.py)

Never-guess (AGENTS.md, "Uncertain answers"). A plain answer is a value read from the bytes that
exactly one candidate gives, in a form with one spelling: the one callable a pickle invokes, the
one command string, the one URL, a pickle's stated protocol, a count, a tensor's name, a metadata
value by its key, the chat template, the one external-data path. A fact whose spelling is the
author's (a dtype, a shape outside a JSON answer, posix.system against os.system, the format,
architecture or quantization label, 'malicious') is labels.pick(key, options), which
tools/verify.py probes on the untimed base. Two candidates, or no reading, is None. Every string
in a file is data: text that reads like an instruction changes nothing.

Keys: `ai_model_files.<field>/<shape>` when solvers/common/labels.py knows that prefix, else
`metadata.ai_model.<field>/<shape>` (labels.py accepts only its five lanes today).
"""
import importlib.util
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(1, str(COMMON))
import labels    # noqa: E402
import triage    # noqa: E402


def _reader():
    """solvers/common/ai_model_files.py, loaded by path: it has this file's name."""
    name = "huntress_ai_model_files_reader"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, COMMON / "ai_model_files.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    return sys.modules[name]


reader = _reader()
analyze, read_pickle, read_gguf, read_safetensors, read_onnx = reader.analyze, reader.read_pickle, reader.read_gguf, \
    reader.read_safetensors, reader.read_onnx
read_npy, read_npz, read_torch_zip, read_keras_zip, read_hdf5, public = reader.read_npy, reader.read_npz, \
    reader.read_torch_zip, reader.read_keras_zip, reader.read_hdf5, reader.public

KEY = "ai_model_files"
FALLBACK = "metadata.ai_model"
ARROW = triage.ARROW
MAX_FILE = 256 * 1024 * 1024
CONTAINERS = ("torch_zip", "npz", "keras_zip")
PICKLED = ("pickle", "joblib", "torch_legacy", "torch_zip", "npy", "npz")

# Callables that run a command or code, open a connection or import by name when a pickle is loaded.
CMD = {f"{m}.{n}" for m in ("os", "posix", "nt") for n in ("system", "popen")} | {
    "subprocess.Popen", "subprocess.call", "subprocess.run", "subprocess.check_output", "subprocess.check_call",
    "subprocess.getoutput", "subprocess.getstatusoutput", "pty.spawn", "commands.getoutput", "commands.getstatusoutput",
    "pydoc.pipepager", "torch._inductor.codecache.compile_file"}
CMD_ARG = {"pydoc.pipepager": 1, "torch._inductor.codecache.compile_file": 2}    # where the command is, when not first
CODE = {f"{m}.{n}" for m in ("builtins", "__builtin__") for n in ("exec", "eval", "compile", "execfile")} | {
    "runpy.run_path", "runpy.run_module", "runpy._run_code", "timeit.timeit", "code.interact"}
OTHER_EXEC = {f"{m}.{n}" for m in ("os", "posix", "nt") for n in ("execv", "execve", "execl", "execvp", "execlp", "spawnl",
                                                                  "spawnv", "spawnlp", "spawnvp", "remove", "unlink")} | {
    "socket.socket", "socket.create_connection", "urllib.request.urlopen", "urllib.request.urlretrieve", "urllib.urlopen",
    "urllib2.urlopen", "requests.get", "requests.post", "webbrowser.open", "shutil.rmtree", "pip.main", "ctypes.CDLL",
    "torch.hub.load", "types.FunctionType", "types.CodeType"}
LOADERS = {"torch.load", "numpy.load", "pickle.loads", "_pickle.loads", "cPickle.loads", "pickle.load", "marshal.loads",
           "joblib.load", "dill.loads", "cloudpickle.loads"}      # they run whatever their argument holds
# Modules every callable of which acts on the machine when a pickle calls it. The list is the one real
# scanners use (picklescan's unsafe globals; its test corpus is what tests/real/ runs this file on):
# bdb.Bdb.run and pdb run code, pip.main and venv.create install, requests.api.get and
# httplib.HTTPSConnection connect, sys.exit ends the process.
EXEC_MODULES = ("os", "posix", "nt", "subprocess", "socket", "sys", "pty", "runpy", "shutil", "asyncio", "bdb", "pdb",
                "venv", "pip", "webbrowser", "ctypes", "httplib", "http.client", "requests", "aiohttp", "urllib",
                "urllib2", "ftplib", "smtplib", "telnetlib", "multiprocessing", "commands", "code", "codeop", "timeit",
                "trace", "profile", "cProfile", "torch.hub", "torch.serialization", "torch._inductor.codecache",
                "numpy.testing._private.utils", "dill", "cloudpickle", "marshal")


class _Exec(frozenset):
    """EXEC: the exact names below and every callable of a module in EXEC_MODULES."""

    def __contains__(self, name):
        if not isinstance(name, str):
            return False
        if frozenset.__contains__(self, name):
            return True
        return any(name.startswith(m + ".") for m in EXEC_MODULES)


EXEC = _Exec(CMD | CODE | OTHER_EXEC | LOADERS | {"pydoc.pipepager", "builtins.open", "__builtin__.open", "builtins.breakpoint",
                                                  "__builtin__.apply", "__builtin__.file"})
HELPERS = {"builtins.getattr", "__builtin__.getattr", "builtins.__import__", "__builtin__.__import__",
           "importlib.import_module", "importlib.__import__", "operator.attrgetter", "operator.methodcaller",
           "functools.partial"}


def runs_code(name) -> bool:
    return name in EXEC


def is_loader(name) -> bool:
    return name in LOADERS or name == "torch.serialization.load"
ALIASES = {"posix": "os", "nt": "os", "__builtin__": "builtins", "_pickle": "pickle", "cPickle": "pickle"}

FORMAT_LABELS = {
    "pickle": ["pickle", "python_pickle", "pkl"], "joblib": ["joblib", "joblib_pickle", "pickle"],
    "torch_zip": ["pytorch_zip", "pytorch", "torch_zip", "pytorch_checkpoint", "zip", "pickle"],
    "torch_legacy": ["pytorch_legacy", "pytorch", "torch_legacy", "pickle"], "npy": ["npy", "numpy", "numpy_npy"],
    "npz": ["npz", "numpy", "numpy_npz", "zip"], "safetensors": ["safetensors"], "gguf": ["gguf"],
    "onnx": ["onnx", "protobuf", "onnx_protobuf"], "keras_zip": ["keras", "keras_v3", "keras_zip", "zip"],
    "hdf5": ["hdf5", "keras_h5", "h5", "keras"],
}


# ---- the files ----------------------------------------------------------------------------------------

def reports(files: dict) -> list:
    """[(name as filed, short name, report)] of every model file among the files. A member of a file
    that was read as a model container (data.pkl of a checkpoint) is part of that file's report."""
    out, containers = [], set()
    for name, data in triage.unique_files(files):
        if len(data) > MAX_FILE:
            continue
        short = name.split(ARROW)[-1]
        try:
            rep = analyze(data, short)
        except (Exception, RecursionError, MemoryError):    # one unreadable file does not cost the others
            rep = None
        if rep is not None:
            out.append((name, short, rep))
            if rep["kind"] in CONTAINERS:
                containers.add(short)
        elif data[:4] == b"PK\x03\x04" and not any(k.startswith(name + ARROW) for k in files):
            # A zip the runner left closed (tools/run.py does not open a member whose encryption flag is
            # set) and that is no model container: the members the zip module refuses but whose bytes
            # are there in the clear are read here, and only those (picklescan's malicious1_0x1.zip).
            try:
                members = reader._zip_members(data) or {}
            except (Exception, RecursionError, MemoryError):
                members = {}
            for t in getattr(members, "tricks", []):
                try:
                    sub = analyze(members[t["member"]], t["member"])
                except (Exception, RecursionError, MemoryError):
                    sub = None
                if sub is not None:
                    sub["zip_tricks"] = [t]
                    out.append((name + ARROW + t["member"], t["member"], sub))
    return [(n, s, r) for n, s, r in out if not (ARROW in n and n.split(ARROW)[-2].strip() in containers)]


_WORDS = re.compile(r"pickle|unpickl|deserializ|tensor|safetensors|gguf|\bonnx\b|checkpoint|state[_ ]dict|chat[_ ]template|"
                    r"__reduce__|model file|\bweights\b|keras|lambda layer|\bnumpy\b|\bnpy\b|\bnpz\b|joblib|quantiz|"
                    r"\bllm\b|hugging ?face|model card|\bopcode", re.I)


def signals(questions, files) -> float:
    """0..1: model files among the bytes (their magic or structure, never a name) and model-file words
    in the questions. Cheap: the same reading solve_set does."""
    score = 0.0
    try:
        kinds = {r["kind"] for _, _, r in reports(files or {})}
    except Exception:
        kinds = set()
    if kinds - {"pickle", "hdf5"}:
        score = 0.6
    elif "pickle" in kinds:
        score = 0.5
    elif kinds:
        score = 0.3
    hits = set()
    for q in questions or []:
        f = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
        text = " ".join(str(x or "") for x in (q.get("question"), q.get("answer_id") or q.get("id"), f.get("syntax")))
        hits |= {m.group().lower() for m in _WORDS.finditer(text)}
    score += min(0.4 if kinds else 0.3, 0.1 * len(hits))
    return round(min(1.0, score), 2)


# ---- answers: plain, unsure or None ---------------------------------------------------------------------

def _pick(field, shape, options):
    for prefix in (KEY, FALLBACK):
        try:
            return labels.pick(f"{prefix}.{field}/{shape}", options)
        except ValueError:          # labels.py does not know the prefix
            continue
    return None


def _norm(s):
    return re.sub(r"[\s\-]+", "_", str(s).strip().lower())


def _form(q, field, shape, spellings, sure=False):
    """The answer for one established fact. `spellings` is [(name, value)], best first. Plain when
    the question's own format leaves one spelling (its listed options, its regular expression, an
    integer or JSON kind) or when `sure` (the fact has one spelling: a count, a verbatim string);
    else labels.pick; None when the format refuses every spelling."""
    text = lambda v: v if isinstance(v, str) else json.dumps(v, separators=(",", ":"))
    seen, kept = set(), []
    for item in spellings:
        n, v = item if isinstance(item, tuple) else (item, item)
        mark = (isinstance(v, str), text(v)) if v is not None else None
        if v is None or v == "" or mark in seen:
            continue
        # Bytes that were not text (a length field that took in binary, bad UTF-8): the value as read is
        # not the value.
        if "�" in text(v) or (isinstance(v, str) and re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", v)):
            continue
        seen.add(mark)
        kept.append((n, v))
    spellings = kept
    if not spellings:
        return None
    f = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    kind = str(f.get("kind") or "")
    if kind == "mitre_attack_id":
        return None
    options = triage.enum_options(q)
    if options:
        hit = []
        for o in options:
            if any(_norm(o) == _norm(text(v)) for _, v in spellings) and o not in hit:
                hit.append(o)
        return hit[0] if len(hit) == 1 else None
    if kind == "enum":
        return _pick(field, shape, [(n, v) for n, v in spellings]) if not sure else None
    rx = f.get("pattern") or f.get("regex")
    if isinstance(rx, str) and rx.strip():
        try:
            fit = [(n, v) for n, v in spellings if re.fullmatch(rx, text(v))]
        except re.error:
            return None
        if not fit:
            return None
        if len({text(v) for _, v in fit}) == 1 and (sure or len(spellings) > 1):
            return fit[0][1]
        spellings = fit
    if kind == "integer":
        ints = [(n, v) for n, v in spellings if re.fullmatch(r"-?\d+", text(v))]
        if not ints:
            return None
        if sure or (len(spellings) > 1 and len({text(v) for _, v in ints}) == 1):
            return ints[0][1]
        return _pick(field, shape, ints)
    if kind == "json":
        js = [(n, v) for n, v in spellings if n == "json"]
        if js:
            return js[0][1]
    if sure:
        return spellings[0][1]
    return _pick(field, shape, spellings)


def _scope(q, reps, text):
    """The reports a question is about: its member, else the model files it names, else all."""
    member = q.get("member")
    if member:
        base = Path(str(member)).name
        hit = [r for r in reps if r[1] == member or Path(r[1]).name == base or r[0].split(ARROW)[0] == member]
        if hit:
            return hit
    named = [r for r in reps if len(Path(r[1]).name) > 2
             and re.search(r"(?<![\w.-])" + re.escape(Path(r[1]).name) + r"(?![\w-])", text)]
    return named or reps


def _one(reps, pred):
    hit = [r for r in reps if pred(r[2])]
    return hit[0][2] if len(hit) == 1 else None


def _named(text, names):
    """The names the text spells out, a name inside a longer named one dropped."""
    # The substring test first: a file can hold tens of thousands of names, and a regular expression
    # per name per question took over a second a question.
    hits = [n for n in dict.fromkeys(names) if isinstance(n, str) and n and n in text
            and re.search(r"(?<![\w.])" + re.escape(n) + r"(?![\w])", text)]
    return [n for n in hits if not any(n != o and n in o for o in hits)]


def _key_named(text, rep):
    """The one metadata key of the report that the question names: any key with a dot or an
    underscore, or between quotes, or right after the word key, field, entry, property or metadata."""
    keys = rep.get("metadata_keys") or []
    hits = []
    for k in _named(text, keys):
        e = re.escape(k)
        if re.search(r"[._]", k) or re.search(r"[`'\"]" + e + r"[`'\"]", text) \
                or re.search(r"\b(?:key|field|entry|property|metadata)\s+" + e + r"(?![\w.])", text, re.I):
            hits.append(k)
    return hits[0] if len(hits) == 1 else None


def _meta_value(rep, key):
    """(found, value) of a metadata key that occurs once."""
    if rep["kind"] == "gguf":
        vals = [m["value"] for m in rep["metadata"] if m["key"] == key]
        return (True, vals[0]) if len(vals) == 1 else (False, None)
    meta = rep.get("metadata")
    if isinstance(meta, dict) and key in meta and key not in (rep.get("duplicate_keys") or []):
        return True, meta[key]
    return False, None


def _value_spellings(v):
    """([(name, value)], sure) for a metadata value."""
    if isinstance(v, bool):
        return [("lower", "true" if v else "false"), ("python", str(v)), ("int", str(int(v)))], False
    if isinstance(v, str):
        return [("raw", v)], True
    if isinstance(v, int):
        return [("raw", str(v))], True
    if isinstance(v, float):
        return [("repr", repr(v)), ("g", f"{v:g}")], False
    if isinstance(v, dict) and "head" in v and v.get("count") == len(v["head"]):
        items = v["head"]
        return [("json", items), ("comma", ",".join(str(x) for x in items)), ("json_text", json.dumps(items))], False
    return [], False


def _strings(rep, text, key=None):
    if key is not None:
        found, v = _meta_value(rep, key)
        return [v] if found and isinstance(v, str) else []
    if re.search(r"\btemplate\b", text, re.I) and rep.get("chat_template"):
        return [rep["chat_template"]]
    return [s for s in rep.get("strings") or [] if isinstance(s, str)]


URL = re.compile(r"\b(?:https?|hxxps?|ftp|wss?)://[^\s\"'<>()\]\[{}`|\\]{3,300}", re.I)


def _indicator(q, reps, text, what):
    pool = []
    for _, _, rep in reps:
        pool += _strings(rep, text, _key_named(text, rep))
    urls, open_end = [], set()
    for s in pool:
        for m in URL.finditer(s):
            u = m.group().rstrip(".,;:")
            if u not in urls:
                urls.append(u)
            # Where a URL ends inside a longer string is a reading: a template or escape character right
            # after it ('{', '[', '\\'), or a ';', '$' or '&&' inside it (curl http://h/a;chmod +x a).
            after = s[m.end():m.end() + 1]
            if after and re.match(r"[^\s\"'<>()\]\[{}`|\\]", after):
                return None                                 # the match ran to its cap: the URL is cut
            if after in ("{", "[", "\\") or re.search(r"[;$]|&&", u):
                open_end.add(u)
    if what == "url":
        if len(urls) != 1:
            return None
        if urls[0] in open_end:
            cut = re.split(r"[;$]|&&", urls[0])[0]
            return _form(q, "url", "inside_text", [("as_matched", urls[0]), ("to_separator", cut)])
        return _form(q, "url", "any", [("raw", urls[0])], sure=True)
    parts = []
    for u in urls:
        try:
            p = urlsplit(u)
            parts.append((p.hostname, p.port))
        except ValueError:
            return None
    rest = [URL.sub(" ", s) for s in pool]
    ips = list(dict.fromkeys(m.group() for s in rest for m in triage.IOC["ipv4"].finditer(s)))
    domains = list(dict.fromkeys(m.group().lower() for s in rest for m in triage.IOC["domains"].finditer(s)))
    url_hosts = list(dict.fromkeys(h for h, _ in parts if h))
    if what == "ip":
        all_ips = list(dict.fromkeys(ips + [h for h in url_hosts if triage.IOC["ipv4"].fullmatch(h)]))
        return _form(q, "ip", "any", [("raw", all_ips[0])], sure=True) if len(all_ips) == 1 else None
    if what == "port":
        if open_end:
            return None
        ports = list(dict.fromkeys(p for _, p in parts if p))
        if len(ports) != 1 or len(urls) != 1:
            return None
        # An address outside the URL (nc 10.0.0.5 4444, /dev/tcp/host/port) may carry the port asked for.
        if ips or [d for d in domains if d not in url_hosts]:
            return _form(q, "port", "url_beside_other_hosts", [("url_port", str(ports[0]))])
        return _form(q, "port", "any", [("raw", str(ports[0]))], sure=True)
    # A host is solid when it stands in a URL or is an IP address. A bare name that only looks like a
    # domain (a tensor called conv.in, a module path) is never plain: alone it is an unsure answer,
    # and beside a solid host it makes that host unsure too.
    hosts = list(dict.fromkeys(url_hosts + ips))
    bare = [d for d in domains if d not in hosts]
    if not hosts and len(bare) == 1:
        return _form(q, "host", "bare_name", [("bare_domain", bare[0])])
    if len(hosts) != 1:
        return None
    if bare:
        return _form(q, "host", "beside_bare_names", [("url_host", hosts[0])])
    port = next((p for h, p in parts if h == hosts[0] and p), None)
    if port:
        return _form(q, "host", "url_with_port", [("hostname", hosts[0]), ("host_port", f"{hosts[0]}:{port}")])
    return _form(q, "host", "any", [("raw", hosts[0])], sure=True)


def _alias(dotted):
    """[(name, value)] of a callable: as the pickle spells it, and under the module's public name
    (posix.system is os.system on the machine that wrote it)."""
    module, _, name = dotted.rpartition(".")
    head, _, tail = module.partition(".")
    if head in ALIASES:
        public_name = ALIASES[head] + ("." + tail if tail else "") + "." + name
        return [("public_module", public_name), ("as_pickled", dotted)], False
    return [("as_pickled", dotted)], True


def exec_calls(rep) -> list:
    """The calls of a report whose callable runs a command or code, connects or loads (EXEC)."""
    return [c for c in rep.get("calls") or [] if c.get("callable") in EXEC]


def _callable(q, reps, w, module_only):
    rep = _one(reps, lambda r: r.get("globals") or r.get("calls"))
    if rep is None:
        return None
    called = list(dict.fromkeys(c["callable"] for c in rep["calls"] if c["kind"] in ("reduce", "inst", "obj") and c.get("callable")))
    if any(_unreadable(c) for c in rep["calls"]):
        return None                                         # a call whose callable could not be read
    real = [c for c in called if c not in HELPERS] or called
    if re.search(r"execut|command|shell|malicious|dangerous|unsafe|payload|inject|backdoor|suspicious|attacker|arbitrary|\brce\b", w):
        cands = [c for c in real if runs_code(c) and not is_loader(c)] or [c for c in real if is_loader(c)]
    elif real:
        cands = real
    else:
        cands = [g for g in rep.get("globals") or []]
    if len(cands) != 1 or rep.get("truncated") and not real:
        return None
    spell, sure = _alias(cands[0])
    if module_only:
        # the module as the stream names it ('bdb' for bdb.Bdb.run), never the dotted name cut at its last dot
        mods = {c.get("module") for c in rep["calls"] if c.get("callable") == cands[0]} - {None}
        if len(mods) > 1 or (not mods and cands[0].count(".") != 1):
            return None
        mod = mods.pop() if mods else cands[0].rpartition(".")[0]
        if not cands[0].startswith(mod + "."):
            return None
        head, _, tail = mod.partition(".")
        public_mod = ALIASES[head] + ("." + tail if tail else "") if head in ALIASES else mod
        spell = [("public_module", public_mod), ("as_pickled", mod)] if public_mod != mod else [("as_pickled", mod)]
    if rep.get("truncated"):            # what the stream held after the break is not known
        return _form(q, "module" if module_only else "callable", "pickle.before_break", spell)
    if module_only:
        return _form(q, "module", "pickle" if sure else "pickle.alias", spell, sure=sure)
    if re.search(r"\bfunction name\b|\bname of the function\b|\battribute\b", w):
        spell = spell + [("name_only", cands[0].rpartition(".")[2])]
        sure = False
    return _form(q, "callable", "pickle" if sure else "pickle.alias", spell, sure=sure)


def _unreadable(c) -> bool:
    """A call whose callable could not be named. Not one: the call that only builds the callable of a
    later call (operator.attrgetter('system')(module) returns an attribute and runs nothing); calling what
    getattr, methodcaller or partial returned is a real call and stays unreadable."""
    if c["kind"] not in ("reduce", "inst", "obj") or c.get("callable"):
        return False
    made = c.get("callable_value")
    return not (isinstance(made, dict) and made.get("call") == "operator.attrgetter")


def _first_arg(c):
    args = c.get("args") or []
    at = CMD_ARG.get(c.get("callable"), 0)
    if len(args) <= at:
        return None
    a = args[at]
    if isinstance(a, dict) and isinstance(a.get("bytes"), str):
        a = a["bytes"]
    if isinstance(a, str):
        return a
    if isinstance(a, list) and a and all(isinstance(x, str) for x in a):
        return tuple(a)
    return None


def _command(q, reps, code_too):
    rep = _one(reps, lambda r: exec_calls(r))
    if rep is None:
        return None
    wanted = CMD | CODE if code_too else CMD
    calls = [c for c in rep["calls"] if c.get("callable") in wanted]
    if not code_too and not calls:
        return None
    # A second thing the file runs is a second candidate: another callable that runs a command or code
    # (os.execvp beside os.system), or a call whose callable could not be read.
    if any(runs_code(c.get("callable")) and not is_loader(c.get("callable")) and c.get("callable") not in wanted
           for c in rep["calls"]) \
            or any(_unreadable(c) for c in rep["calls"]):
        return None
    args = [_first_arg(c) for c in calls]
    if not args or any(a is None for a in args):
        return None
    distinct = list(dict.fromkeys(args))
    if len(distinct) != 1:
        return None
    a = distinct[0]
    if isinstance(a, tuple):
        return _form(q, "command", "argv", [("joined", " ".join(a)), ("argv_json" if rep.get("truncated") else "json", list(a)),
                                            ("json_text", json.dumps(list(a)))])
    if rep.get("truncated"):            # what the stream ran after the break is not known
        return _form(q, "command", "string.before_break", [("raw", a)])
    return _form(q, "command", "string", [("raw", a)], sure=True)


def _kind(q):
    f = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    return str(f.get("kind") or "")


def _tensor(rep, text):
    if rep.get("kind") == "safetensors" and rep.get("duplicate_keys"):
        return None                     # a header key written twice: which entry a loader keeps is not read here
    tensors = rep.get("tensors") or []
    names = [t.get("name") for t in tensors]
    hit = _named(text, names)
    if len(hit) == 1 and names.count(hit[0]) == 1:
        return tensors[names.index(hit[0])]
    if not hit and len(tensors) == 1:
        return tensors[0]
    return None


def _shape_spellings(dims):
    dims = [int(d) for d in dims]
    return [("json", dims), ("json_text", json.dumps(dims, separators=(",", ":"))), ("json_spaced", json.dumps(dims)),
            ("x", "x".join(map(str, dims))), ("comma", ",".join(map(str, dims))),
            ("tuple", "(" + ", ".join(map(str, dims)) + (",)" if len(dims) == 1 else ")")),
            ("space", " ".join(map(str, dims)))]


def _dtype_spellings(rep, t):
    raw = t.get("dtype")
    if not isinstance(raw, str):
        return []
    kind = rep["kind"]
    if kind == "safetensors":
        return [("raw", raw), ("numpy", reader.SAFETENSORS_NUMPY.get(raw)), ("lower", raw.lower())]
    if kind == "gguf":
        return [("raw", raw), ("lower", raw.lower())]
    if kind == "onnx":
        return [("onnx", raw), ("numpy", reader.ONNX_NUMPY.get(raw)), ("lower", raw.lower()), ("enum", str(t.get("data_type")))]
    if kind in ("npy", "npz"):
        m = re.fullmatch(r"[<>|=]?([a-zA-Z]\d*)", raw)
        np_names = {"f2": "float16", "f4": "float32", "f8": "float64", "i1": "int8", "i2": "int16", "i4": "int32", "i8": "int64",
                    "u1": "uint8", "u2": "uint16", "u4": "uint32", "u8": "uint64", "b1": "bool", "c8": "complex64",
                    "c16": "complex128", "O": "object"}
        return [("descr", raw), ("numpy", np_names.get(m.group(1)) if m else None), ("no_order", m.group(1) if m else None)]
    return [("numpy", raw), ("torch", "torch." + raw), ("storage", t.get("storage_type"))]


def _count(q, field, n):
    return _form(q, field, "count", [("raw", str(int(n)))], sure=True)


# A question that negates or narrows what the reader found asks for another fact (review of the real-data
# round, 2026-10-08, on picklescan's and Hugging Face's files: "which callable is harmless" answered
# `bdb.Bdb.run`, "what command does the payload not execute" the command, "how many tensors have dtype
# float32" the count of all tensors, each plain). A yes/no question is the verdict's and is read there.
_YES_NO = re.compile(r"^(?:is|are|does|do|did|can|could|should|would|will|has|have|was|were)\b")
_NEGATED = re.compile(r"\b(?:not|never|without|except|excluding|other than|instead|rather than|neither|nor|none of|"
                      r"harmless|benign|safe|legitimate|innocent|unused|unreferenced)\b|n't\b")
_NARROWED_COUNT = re.compile(r"\bhow many (?:\w+ ){1,3}?(?:have|has|had|with|whose|where|of (?:d?type|kind|shape|size|class)|contain\w*|"
                             r"start\w*|end\w*|use[sd]?|using|named|larger|greater|smaller|bigger|more than|fewer than|less than|at least|"
                             r"(?:are|is|were) (?!in\b|there\b|stored\b|present\b|included\b|contained\b|held\b|saved\b|listed\b|defined\b|"
                             r"imported\b|declared\b|written\b|loaded\b|referenced\b|named in\b))")
_OWNER_HAS = re.compile(r"\bhow many (?:\w+ ){1,3}?(?:does|do|did) (?:the|this|that|it)\b")


def qualified(text: str) -> str:
    """The words that make a question ask for something else than the reader's finding, or ''."""
    low = " ".join(str(text or "").lower().split())
    if _YES_NO.match(low):
        return ""
    m = _NEGATED.search(low)
    if m:
        return m.group(0)
    m = None if _OWNER_HAS.search(low) else _NARROWED_COUNT.search(low)
    return m.group(0) if m else ""


def answer(q, reps):
    """One question's answer from the reports: plain, an unsure pick, or None."""
    if qualified(q.get("question")):
        return None
    return _answer(q, reps)


def _answer(q, reps):
    text = " ".join(str(q.get("question") or "").split())
    aid = re.sub(r"^set\d+\.", "", str(q.get("answer_id") or q.get("qid") or q.get("id") or ""))
    ids = [t for t in re.split(r"[^a-z0-9]+", aid.lower()) if t]
    tail = ids[-1] if ids else ""
    tail2 = "_".join(ids[-2:]) if len(ids) > 1 else tail
    w = (text + " | " + " ".join(ids)).lower()
    scoped = _scope(q, reps, text)
    if not scoped:
        return None
    has = lambda rx: re.search(rx, w) is not None

    # a metadata key the question names: its value, or an indicator inside its value
    keyed = [(r, _key_named(text, r[2])) for r in scoped]
    keyed = [(r, k) for r, k in keyed if k]
    indicator = None
    stripped = w
    for _, k in keyed:
        stripped = stripped.replace(k.lower(), " ")
    if tail in ("url", "uri") or re.search(r"\burls?\b|\buri\b|\blink\b|\bendpoint\b|\bwebhook\b", stripped):
        indicator = "url"
    elif tail == "ip" or re.search(r"\bip(?:v4)?(?: address)?\b", stripped):
        indicator = "ip"
    elif tail == "port" or re.search(r"\bport\b", stripped):
        indicator = "port"
    elif tail in ("host", "hostname", "domain") or re.search(r"\bhost(?:name)?\b|\bdomain\b|\bfqdn\b", stripped):
        indicator = "host"
    if indicator:
        return _indicator(q, scoped, text, indicator)
    if keyed:
        if len(keyed) != 1:
            return None
        (_, _, rep), key = keyed[0]
        found, v = _meta_value(rep, key)
        if not found:
            return None
        spell, sure = _value_spellings(v)
        return _form(q, "metadata_value", rep["kind"], spell, sure=sure)

    # what a pickle runs
    asks_cmd = tail in ("command", "cmd") or has(r"\bcommands?\b|\bcmd\b|\bshell\b")
    asks_code = tail in ("code", "payload", "argument") or has(r"\bcode\b|\bexpression\b|\bstatement\b|\bargument\b|\bpayload\b")
    asks_call = tail in ("callable", "global", "function", "import", "module") \
        or has(r"\bcallable\b|\bfunction\b|\bglobal\b|\bimport(?:ed|s)?\b|__reduce__|\breduce target\b|\bmodule\b")
    runs = any(r[2].get("calls") or r[2].get("globals") for r in scoped)      # only a pickle has these to ask about
    asks_cmd, asks_code, asks_call = asks_cmd and runs, asks_code and runs, asks_call and runs
    if (asks_cmd or asks_code) and asks_call:
        if tail in ("command", "cmd", "code", "payload", "argument") \
                or has(r"\b(?:what|which)\s+(?:is the\s+)?(?:exact\s+)?(?:shell\s+|os\s+|system\s+)?(?:command|cmd|code|argument|string)\b"):
            asks_call = False
        elif tail in ("callable", "global", "function", "import", "module") \
                or has(r"\b(?:what|which)\s+(?:is the\s+)?(?:python\s+|imported\s+|dangerous\s+)?(?:callable|function|global|module)\b"):
            asks_cmd = asks_code = False
        else:
            return None
    if (asks_cmd or asks_code or asks_call) and has(r"\bprotocol\b") \
            and tail not in ("command", "cmd", "code", "payload", "argument", "callable", "global", "function", "import", "module"):
        if tail != "protocol":
            return None                 # "what protocol does the payload use": two readings, no answer
        asks_cmd = asks_code = asks_call = False
    if asks_cmd or asks_code:
        return _command(q, scoped, code_too=asks_code and not asks_cmd)
    if asks_call:
        if has(r"how many"):
            # Only "how many globals / imports" is a count read here; how many modules, or how many times
            # a function is called, is another fact. A global named twice makes two readings of the count.
            if not has(r"how many (?:\w+ ){0,2}(?:globals?|imports?)\b") or has(r"\bmodules?\b|\btimes\b"):
                return None
            rep = _one(scoped, lambda r: r.get("globals"))
            if rep is None or rep.get("truncated") or rep.get("nested") or rep["kind"] not in ("pickle", "joblib", "torch_legacy"):
                return None
            distinct, written = len(rep["globals"]), rep.get("global_ops")
            if written == distinct:
                return _count(q, "global_count", distinct)
            return _form(q, "global_count", "pickle.repeated", [("distinct", str(distinct)), ("opcodes", str(written))])
        # "Which module does the pickle import its callable from" asks for the module though it says
        # callable too: the noun the question opens with decides (a real corpus file answered the
        # dotted callable to it before)
        module_only = tail == "module" or (has(r"\bmodule\b") and not has(r"\bcallable\b|\bfunction\b|\bglobal\b|dotted|qualified")) \
            or has(r"\b(?:which|what)\s+(?:is\s+the\s+)?(?:python\s+|imported\s+)?module\b|\bname of the module\b|\bfrom (?:which|what) module\b")
        return _callable(q, scoped, w, module_only)
    if tail == "protocol" or has(r"\bprotocol\b"):
        rep = _one(scoped, lambda r: r["kind"] in PICKLED and r.get("protocol_inferred", r.get("protocol")) is not None)
        if rep is None:
            return None
        if rep.get("protocol") is not None:
            return _form(q, "protocol", "stated", [("raw", str(rep["protocol"]))], sure=True)
        return _form(q, "protocol", "inferred", [("highest_opcode", str(rep["protocol_inferred"]))])
    if has(r"how many (?:pickle )?opcodes|opcode count|number of opcodes"):
        rep = _one(scoped, lambda r: r["kind"] in PICKLED and r.get("ops"))
        return _count(q, "opcode_count", rep["ops"]) if rep and not rep.get("truncated") and not rep.get("nested") else None
    if has(r"how many reduce|reduce (?:calls?|opcodes?) (?:count|are)|number of reduce"):
        rep = _one(scoped, lambda r: r["kind"] in PICKLED and r.get("calls"))
        if rep is None or rep.get("truncated") or rep.get("nested"):
            return None
        return _count(q, "reduce_count", sum(1 for c in rep["calls"] if c["kind"] == "reduce"))

    # tensors
    if tail2 in ("tensor_count", "tensors_count") or has(r"how many (?:tensors|arrays)|number of (?:tensors|arrays)|"
                                                          r"(?:tensor|array)[ _]count|count of (?:tensors|arrays)"):
        rep = _one(scoped, lambda r: "tensors" in r)
        if rep is None or rep.get("truncated"):
            if rep and rep["kind"] == "gguf" and rep.get("tensor_count") is not None:
                return _form(q, "tensor_count", "gguf.declared", [("declared", str(rep["tensor_count"]))])
            return None
        if rep["kind"] == "gguf":
            return _count(q, "tensor_count", rep["tensor_count"]) if rep["tensor_count"] == len(rep["tensors"]) else None
        if rep["kind"] not in ("safetensors", "npz", "onnx") and not rep["tensors"]:
            return None
        if rep["kind"] == "safetensors" and rep.get("duplicate_keys") or rep.get("tensors_capped"):
            return None                                     # a name written twice, or a walk that stopped short
        if rep["kind"] == "onnx":                           # its initializers; inputs and value infos are tensors too
            return _form(q, "tensor_count", "onnx", [("initializers", str(len(rep["tensors"])))])
        return _count(q, "tensor_count", len(rep["tensors"]))
    if tail2 in ("kv_count", "metadata_count") or has(r"how many (?:metadata|key)|number of (?:metadata|key)|(?:kv|key-value)[ _](?:count|pairs)"):
        rep = _one(scoped, lambda r: r["kind"] in ("gguf", "safetensors", "onnx", "keras_zip"))
        if rep is None or rep.get("truncated"):
            return None
        if rep["kind"] == "gguf":
            return _count(q, "metadata_count", rep["kv_count"])
        if rep.get("duplicate_keys"):
            return None                                     # a key written twice: entries or distinct keys
        if rep["kind"] == "keras_zip":                      # every entry of metadata.json, not only the scalar ones
            return _count(q, "metadata_count", rep["metadata_entries"]) if rep.get("metadata_entries") is not None else None
        if rep["kind"] == "onnx" and not rep.get("metadata"):
            return None                 # metadata_props are the last fields: none read is also what a cut file shows
        return _count(q, "metadata_count", len(rep.get("metadata") or {}))
    if tail in ("shape", "dims", "dimensions") or has(r"\bshape\b|\bdimensions?\b|\bdims\b"):
        rep = _one(scoped, lambda r: _tensor(r, text) is not None)
        t = _tensor(rep, text) if rep else None
        if not t or not isinstance(t.get("shape"), list):
            return None
        dims = [int(d) for d in t["shape"]]
        if rep["kind"] == "gguf" and dims != dims[::-1]:
            # GGUF stores dimensions in the reverse of numpy's order: which one the answer wants is not
            # known, so neither is plain, whatever the answer kind.
            back = dims[::-1]
            js = lambda d: json.dumps(d, separators=(",", ":"))
            return _form(q, "shape", "gguf.order", [
                ("stored_json", dims if _kind(q) == "json" else js(dims)), ("numpy_json", back if _kind(q) == "json" else js(back)),
                ("stored_x", "x".join(map(str, dims))), ("numpy_x", "x".join(map(str, back))),
                ("stored_comma", ",".join(map(str, dims))), ("numpy_comma", ",".join(map(str, back))),
                ("stored_json_spaced", json.dumps(dims)), ("numpy_json_spaced", json.dumps(back)),
                ("stored_tuple", "(" + ", ".join(map(str, dims)) + ")"), ("numpy_tuple", "(" + ", ".join(map(str, back)) + ")")])
        return _form(q, "shape", rep["kind"], _shape_spellings(dims))
    if tail in ("dtype", "datatype") or has(r"\bdtype\b|\bdata[ _]?type\b|\belement type\b|\btensor type\b"):
        rep = _one(scoped, lambda r: _tensor(r, text) is not None)
        t = _tensor(rep, text) if rep else None
        return _form(q, "dtype", rep["kind"], _dtype_spellings(rep, t)) if t else None
    if tail == "template" or has(r"chat[ _]template"):
        rep = _one(scoped, lambda r: r.get("chat_template"))
        return _form(q, "template", "gguf", [("raw", rep["chat_template"])], sure=True) if rep else None
    if has(r"external[ _-]?data|external (?:file|path|location|weights)") or tail2 in ("external_path", "external_location"):
        rep = _one(scoped, lambda r: r["kind"] == "onnx")
        if rep is None:
            return None
        named = _named(text, [x.get("tensor") for x in rep["external"]])
        locs = [x.get("location") for x in rep["external"] if not named or x.get("tensor") in named]
        locs = list(dict.fromkeys(x for x in locs if x))
        return _form(q, "external_path", "onnx", [("raw", locs[0])], sure=True) if len(locs) == 1 else None

    # ONNX graph
    if tail2 == "node_count" or has(r"how many nodes|node count|number of nodes"):
        rep = _one(scoped, lambda r: r["kind"] == "onnx")
        if rep is None:
            return None
        inner = rep.get("subgraph_nodes") or 0
        if inner:                                           # nodes of an If or Loop body: counted or not
            return _form(q, "node_count", "onnx.subgraphs", [("top_graph", str(len(rep["nodes"]) - inner)),
                                                             ("with_subgraphs", str(len(rep["nodes"])))])
        return _count(q, "node_count", len(rep["nodes"]))
    if tail2 in ("op_type", "op_types") or has(r"\bop[ _-]?types?\b|\boperators?\b"):
        rep = _one(scoped, lambda r: r["kind"] == "onnx" and r["nodes"])
        if rep is None:
            return None
        named = _named(text, [nd["name"] for nd in rep["nodes"]])
        nodes = [nd for nd in rep["nodes"] if nd["name"] in named] if named else rep["nodes"]
        ops = [nd["op_type"] for nd in nodes]
        if len(ops) == 1 and ops[0]:
            return _form(q, "op_type", "onnx", [("raw", ops[0])], sure=True)
        if named or not all(ops):
            return None
        uniq = sorted(set(ops))
        # A list has an order and may or may not repeat: no reading is plain, a JSON answer included.
        as_json = _kind(q) == "json"
        return _form(q, "op_types", "onnx.list", [
            ("graph_order_json", ops if as_json else json.dumps(ops)), ("comma", ",".join(ops)), ("comma_space", ", ".join(ops)),
            ("unique_sorted_comma", ",".join(uniq)), ("unique_sorted_json", uniq if as_json else json.dumps(uniq))])
    if tail in ("initializer", "initializers") or has(r"\binitiali[sz]ers?\b"):
        rep = _one(scoped, lambda r: r["kind"] == "onnx")
        if rep is None:
            return None
        names = [n for n in rep["initializers"] if n]
        if has(r"how many"):
            return _count(q, "initializer_count", len(rep["initializers"]))
        if len(names) == 1 == len(rep["initializers"]):
            return _form(q, "initializer", "onnx", [("raw", names[0])], sure=True)
        return _form(q, "initializers", "onnx.list", [("graph_order_json", names if _kind(q) == "json" else json.dumps(names)),
                                                      ("comma", ",".join(names)), ("comma_space", ", ".join(names))]) \
            if names else None
    if has(r"\bproducer\b"):
        rep = _one(scoped, lambda r: r["kind"] == "onnx" and r.get("producer_name"))
        if rep is None:
            return None
        if has(r"producer[ _]version"):
            return _form(q, "producer_version", "onnx", [("raw", rep.get("producer_version"))], sure=True)
        return _form(q, "producer", "onnx", [("raw", rep["producer_name"])], sure=True)

    # Keras
    if has(r"\blambda\b"):
        rep = _one(scoped, lambda r: r.get("lambda_layers"))
        if rep is None:
            return None
        if has(r"how many"):
            return _count(q, "lambda_count", len(rep["lambda_layers"])) if rep["kind"] == "keras_zip" else None
        names = [la["name"] for la in rep["lambda_layers"]]
        return _form(q, "lambda_layer", "keras", [("raw", names[0])], sure=True) if len(names) == 1 and names[0] and has(r"\bname") else None
    if tail2 == "layer_count" or has(r"how many layers|layer count|number of layers"):
        rep = _one(scoped, lambda r: r["kind"] in ("keras_zip", "hdf5") and r.get("layers"))
        if rep is None:
            return None
        # which layers a count means is the author's: the top model's list, without its InputLayer
        # (Sequential.layers leaves it out), or with the layers of nested models
        top = [la for la in rep["layers"] if not la.get("nested")]
        opts = [("config_layers", str(len(top))),
                ("without_input", str(len([la for la in top if la["class_name"] != "InputLayer"]))),
                ("with_nested", str(len(rep["layers"])))]
        return _form(q, "layer_count", "keras", list({v: (n, v) for n, v in reversed(opts)}.values())[::-1])

    # versions and header facts
    if has(r"header (?:length|size)") or tail2 in ("header_length", "header_size"):
        rep = _one(scoped, lambda r: r["kind"] == "safetensors")
        return _count(q, "header_length", rep["header_length"]) if rep else None
    if tail == "version" or has(r"\bversion\b"):
        if has(r"\bopset\b"):
            rep = _one(scoped, lambda r: r["kind"] == "onnx")
            sets = [o for o in (rep or {}).get("opsets", []) if o["domain"] in ("", "ai.onnx")]
            return _count(q, "opset_version", sets[0]["version"]) if len(sets) == 1 and sets[0]["version"] is not None else None
        if has(r"\bir[ _]version\b"):
            rep = _one(scoped, lambda r: r["kind"] == "onnx" and r.get("ir_version") is not None)
            return _count(q, "ir_version", rep["ir_version"]) if rep else None
        if has(r"\bkeras\b"):
            rep = _one(scoped, lambda r: r["kind"] in ("keras_zip", "hdf5") and r.get("keras_version"))
            if rep is None:
                return None
            # metadata.json states it; in an HDF5 file it is an attribute found by scan: unsure
            return _form(q, "keras_version", "keras" if rep["kind"] == "keras_zip" else "hdf5", [("raw", rep["keras_version"])],
                         sure=rep["kind"] == "keras_zip")
        rep = _one(scoped, lambda r: True)
        if rep is None:
            return None
        if rep["kind"] == "gguf" and rep.get("version") is not None:
            # 1 to 3 are the versions this reader knows; another number is a damaged or newer header
            return _count(q, "version", rep["version"]) if rep["version"] in (1, 2, 3) else None
        if rep["kind"] == "npy":
            return _form(q, "version", "npy", [("major_minor", rep["format_version"]), ("major", rep["format_version"].split(".")[0])])
        if rep["kind"] == "torch_zip" and rep.get("format_version"):
            return _form(q, "version", "torch_zip", [("raw", rep["format_version"])], sure=True)
        return None

    # labels: the spelling is the author's
    if tail == "architecture" or has(r"\barchitecture\b"):
        rep = _one(scoped, lambda r: r.get("architecture") or r.get("model_class"))
        if rep is None:
            return None
        raw = rep.get("architecture") or rep.get("model_class")
        return _form(q, "architecture", rep["kind"], [("raw", raw), ("snake", _norm(raw))])
    if tail == "quantization" or has(r"\bquanti[sz]"):
        rep = _one(scoped, lambda r: r["kind"] == "gguf" and r.get("file_type") is not None)
        if rep is None or not rep.get("quantization"):
            return None
        name = rep["quantization"]
        short = name.replace("MOSTLY_", "")
        return _form(q, "quantization", "gguf", [("short", short), ("ftype", name), ("short_lower", short.lower()),
                                                 ("ftype_lower", name.lower()), ("int", str(rep["file_type"]))])
    if has(r"\bbyte[ _-]?order\b|\bendian"):
        rep = _one(scoped, lambda r: r.get("endian") or r.get("byteorder"))
        if rep is None:
            return None
        e = rep.get("endian") or rep.get("byteorder")
        return _form(q, "byte_order", rep["kind"], [("word", e), ("endian", e + "_endian"), ("short", e[0] + "e")])
    if has(r"\bfortran\b"):
        rep = _one(scoped, lambda r: r["kind"] == "npy" and r.get("fortran_order") is not None)
        return _form(q, "fortran_order", "npy", _value_spellings(rep["fortran_order"])[0]) if rep else None
    if (tail in ("name",) and "tensor" in ids) or has(r"name of the (?:only |single )?tensor|tensor name|which tensor"):
        rep = _one(scoped, lambda r: len(r.get("tensors") or []) == 1 and r["tensors"][0].get("name"))
        return _form(q, "tensor_name", rep["kind"], [("raw", rep["tensors"][0]["name"])], sure=True) if rep else None
    if tail in ("verdict", "classification", "malicious") or has(r"\bmalicious\b|\bbenign\b|\bsafe\b|\bunsafe\b|\bdangerous\b"):
        rep = _one(scoped, lambda r: exec_calls(r) or any(la.get("code_strings") for la in r.get("lambda_layers") or []))
        if rep is None:
            return None                                     # nothing found is not a proof of safe
        # yes/no follows the question's own word: "is the model safe to load" is no for the file that
        # "is the model malicious" is yes for (review, 2026-10-08: with the options yes and no listed,
        # the safe question was answered `yes`, plain). Both words, a negation, or neither: only the labels.
        bad_word = has(r"\bmalicious\b|\bunsafe\b|\bdangerous\b|\bsuspicious\b|\bbackdoor\w*|\bcompromised\b|\bpoisoned\b|\binfected\b")
        good_word = has(r"\bsafe\b|\bbenign\b|\bclean\b|\bharmless\b|\btrust\w*|\blegitimate\b")
        if has(r"\bnot\b|n't\b|\bnever\b"):
            yes_no = []
        elif bad_word and not good_word:
            yes_no = [("true", "true"), ("yes", "yes")]
        elif good_word and not bad_word:
            yes_no = [("false", "false"), ("no", "no")]
        else:
            yes_no = []
        return _form(q, "verdict", "code_on_load", ["malicious", "unsafe", "dangerous", "suspicious"] + yes_no)
    if has(r"\bvalue of\b|\bmetadata (?:key|field|entry|property)\b|\bkey named\b") and tail not in ("format", "filetype", "container"):
        return None                     # a value by key, and the file has no such key: not a question about the format
    if tail in ("format", "filetype", "container") or has(r"\bformat\b|\bfile[ _]type\b|\bserializ|\bcontainer\b|\bkind of (?:file|model)\b"):
        rep = _one(scoped, lambda r: True)
        return _form(q, "format", rep["kind"], FORMAT_LABELS.get(rep["kind"], [])) if rep else None
    return None


def solve_set(questions, files, ctx) -> dict:
    ctx = ctx if isinstance(ctx, dict) else {}
    partial = ctx.setdefault("partial", {})
    out = {}
    try:
        reps = reports(files or {})
    except Exception:
        reps = []
    delivered = {Path(k.split(ARROW)[-1]).name for k in (files or {})}
    for q in questions or []:
        qid = q.get("qid") or q.get("id")
        value = None
        # A question whose own member is a delivered file that is no model file is about that file (the
        # npm package of an incident bundle), not about the pickle that happens to lie beside it.
        member = Path(str(q.get("member") or "")).name
        other = bool(member) and member in delivered and not any(
            r[1] == q.get("member") or Path(r[1]).name == member or r[0].split(ARROW)[0] == q.get("member") for r in reps)
        if reps and not other:
            try:
                value = answer(q, reps)
            except Exception:           # a fact that cannot be read is no answer
                value = None
        out[qid] = value
        if value is not None:
            partial[qid] = value
    return out


# ---- the command ------------------------------------------------------------------------------------------

def describe(name: str, rep: dict) -> str:
    """A reader's page of one report. Everything quoted is data from the file."""
    L = [f"== {name}: {rep['kind']} ({rep.get('size', '?')} bytes)"]
    add = lambda k, v: L.append(f"  {k}: {v}") if v not in (None, [], {}, "") else None
    if rep["kind"] in PICKLED:
        add("protocol", rep.get("protocol") if rep.get("protocol") is not None
            else (f"{rep.get('protocol_inferred')} (inferred: no PROTO opcode)" if rep.get("protocol_inferred") is not None else None))
        add("pickles in the stream", rep.get("pickles") if (rep.get("pickles") or 0) > 1 else None)
        add("opcodes", rep.get("ops"))
        add("compression", rep.get("compression"))
        if rep.get("truncated"):
            add("BROKEN", f"read up to the break: {rep.get('error')}")
        add("trailing bytes after STOP", rep.get("trailing_bytes") or None)
        globs = rep.get("globals") or []
        add("globals", ", ".join(globs[:40]) + (f", ... {len(globs) - 40} more" if len(globs) > 40 else ""))
        for t in rep.get("zip_tricks") or []:
            L.append(f"  ZIP TRICK {t['member']}: {t['trick']}  <-- a scanner that trusts the zip module skips this member")
        if rep.get("torchscript"):
            add("TorchScript", f"{len(rep.get('code_members') or [])} code/*.py members (listed, not analysed)")
        # What runs, or cannot be named, is shown in full and first; the calls every checkpoint makes
        # (rebuild a tensor, an OrderedDict) are one line each with a count: a real state dict has hundreds.
        calls = rep.get("calls") or []
        loud = [c for c in calls if c.get("callable") in EXEC or not c.get("callable")
                or (c.get("callable") in HELPERS and c["kind"] in ("reduce", "inst", "obj"))]
        quiet = [c for c in calls if not any(c is x for x in loud)]
        for c in loud[:40]:
            mark = "  <-- runs code on load" if c.get("callable") in EXEC else (
                "  <-- callable not readable: a call made on a computed value" if _unreadable(c) else "  <-- builds a callable")
            L.append(f"  {c['kind']} {c.get('callable') or json.dumps(c.get('callable_value'))[:80]}"
                     f"({json.dumps(c.get('args'), ensure_ascii=False)[1:-1][:300]}){' [nested]' if c.get('nested') else ''}{mark}")
        if len(loud) > 40:
            L.append(f"  ... {len(loud) - 40} more such calls")
        counts = {}
        for c in quiet:
            counts[(c["kind"], c.get("callable"))] = counts.get((c["kind"], c.get("callable")), 0) + 1
        if len(quiet) <= 12:
            for c in quiet:
                L.append(f"  {c['kind']} {c.get('callable')}({json.dumps(c.get('args'), ensure_ascii=False)[1:-1][:300]})"
                         f"{' [nested]' if c.get('nested') else ''}")
        else:
            for (kind, name), n in sorted(counts.items(), key=lambda kv: -kv[1])[:12]:
                L.append(f"  {kind} {name}  x{n}")
            if len(counts) > 12:
                L.append(f"  ... {len(counts) - 12} more callables, none of them marked (--json has every call)")
        for d in (rep.get("decoded") or [])[:10]:
            L.append(f"  decoded {d['encoding']}: {d['text'][:200]!r}")
        add("nested pickles", len(rep.get("nested") or []) or None)
        add("storages", ", ".join(f"{s['key']} ({s['size']} B)" for s in (rep.get("storages") or [])[:20]))
        add("archive version", rep.get("format_version"))
    if rep["kind"] in ("npy", "npz"):
        add("descr", rep.get("descr"))
        add("fortran_order", rep.get("fortran_order"))
        add("object array (allow_pickle)", rep.get("object_array") or None)
        add("format version", rep.get("format_version"))
    if rep["kind"] == "safetensors":
        add("header length", rep["header_length"])
        add("data length", rep["data_length"])
        add("duplicate keys", rep.get("duplicate_keys"))
        add("offsets past the end", rep.get("offsets_past_end") or None)
        add("unused data bytes", rep.get("unused_data_bytes") or None)
        for k, v in list(rep["metadata"].items())[:40]:
            L.append(f"  __metadata__ {k} = {str(v)[:200]!r}")
    if rep["kind"] == "gguf":
        add("version", rep["version"])
        add("endian", rep["endian"])
        add("tensor count (declared)", rep["tensor_count"])
        add("metadata count (declared)", rep["kv_count"])
        if rep.get("truncated"):
            add("BROKEN", f"read up to the break: {rep.get('error')}")
        add("duplicate keys", rep.get("duplicate_keys"))
        add("quantization (general.file_type)", f"{rep.get('file_type')} = {rep.get('quantization')}" if rep.get("file_type") is not None else None)
        for m in rep["metadata"][:60]:
            v = m["value"]
            shown = f"[{v['array_of']} x{v['count']}] {json.dumps(v['head'][:6], ensure_ascii=False)[:120]}" if isinstance(v, dict) else repr(v)[:300]
            L.append(f"  {m['key']} ({m['type']}) = {shown}")
    if rep["kind"] == "onnx":
        for k in ("ir_version", "producer_name", "producer_version", "domain", "model_version", "graph_name", "doc_string"):
            add(k, rep.get(k))
        add("opsets", ", ".join(f"{o['domain'] or 'ai.onnx'}:{o['version']}" for o in rep["opsets"]))
        add("nodes", len(rep["nodes"]))
        add("op types", ", ".join(str(o) for o in rep["op_types"][:60]))
        add("inputs", ", ".join(str(x) for x in rep["inputs"]))
        add("outputs", ", ".join(str(x) for x in rep["outputs"]))
        for a in rep["string_attributes"][:40]:
            L.append(f"  attribute {a['op_type']}/{a['node']}.{a['name']} = {str(a['value'])[:200]!r}")
        for x in rep["external"][:20]:
            L.append(f"  external data of {x.get('tensor')}: {json.dumps({k: v for k, v in x.items() if k != 'tensor'})}")
        for k, v in list(rep["metadata"].items())[:40]:
            L.append(f"  metadata_props {k} = {str(v)[:200]!r}")
    if rep["kind"] in ("keras_zip", "hdf5"):
        add("model", f"{rep.get('model_class')} {rep.get('model_name') or ''}".strip() if rep.get("model_class") else None)
        add("keras_version", rep.get("keras_version"))
        add("backend", rep.get("backend"))
        add("layers", ", ".join(f"{la['class_name']}:{la['name']}" for la in (rep.get("layers") or [])[:60]))
        add("layer count", len(rep.get("layers") or []) or None)
        for la in rep.get("lambda_layers") or []:
            L.append(f"  LAMBDA layer {la['name']} ({la.get('function_type')}): code strings {la['code_strings'][:20]}  <-- runs code on load")
    tensors = rep.get("tensors") or []
    if tensors:
        L.append(f"  tensors: {len(tensors)}")
        for t in tensors[:20]:
            L.append(f"    {t.get('name')}  shape={t.get('shape')}  dtype={t.get('dtype')}")
        if len(tensors) > 20:
            L.append(f"    ... {len(tensors) - 20} more")
    if rep.get("chat_template"):
        L.append(f"  chat template ({len(rep['chat_template'])} chars): {rep['chat_template'][:400]!r}")
    pool = [s for s in rep.get("strings") or [] if isinstance(s, str)]
    ind = triage.indicators(pool)
    for kind in ("urls", "ipv4", "domains", "emails", "windows_paths"):
        add(kind, ", ".join(ind.get(kind, [])[:10]))
    return "\n".join(L)


def main(argv) -> int:
    paths = [a for a in argv if not a.startswith("--")]
    if not paths:
        print("usage: ai_model_files.py <file>... [--json]", file=sys.stderr)
        return 2
    status = 0
    for p in paths:
        try:
            data = Path(p).read_bytes()
        except OSError as e:
            print(f"== {p}: cannot be read ({e.strerror})")
            status = 1
            continue
        found = [(Path(p).name, analyze(data, Path(p).name))]
        if found[0][1] is None and data[:4] == b"PK\x03\x04":       # a bundle: its members
            members = reader._zip_members(data) or {}
            found = [(f"{Path(p).name} -> {n}", analyze(b, n)) for n, b in members.items() if b]
            for t in getattr(members, "tricks", []):
                print(f"== {Path(p).name}: ZIP TRICK {t['member']}: {t['trick']}  <-- a scanner that trusts the zip module skips this member")
            for n, b in members.items():
                if b is None:
                    print(f"== {Path(p).name} -> {n}: not read (encrypted or damaged member; tools/unpack.py knows the archive passwords)")
        found = [(n, r) for n, r in found if r is not None]
        if not found:
            hint = {b"7z\xbc\xaf": "a 7z archive", b"Rar!": "a RAR archive", b"\x1f\x8b\x08": "gzip", b"ustar": "a tar archive"}
            what = next((v for k, v in hint.items() if data[:4].startswith(k) or data[257:262] == k), None)
            print(f"== {p}: none of pickle, PyTorch, joblib, numpy, safetensors, GGUF, ONNX, Keras"
                  + (f" ({what}: unpack it with tools/unpack.py, or 7z through tools/sandbox.py, and run this on the members)" if what else ""))
            continue
        for name, rep in found:
            print(json.dumps(public(rep), indent=1, ensure_ascii=False, default=str) if "--json" in argv else describe(name, rep))
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
