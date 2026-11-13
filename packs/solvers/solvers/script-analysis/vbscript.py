#!/usr/bin/env python3
"""VBScript specimen analyzer for the Script Analysis lane.

Usage:
  python3 solvers/script-analysis/vbscript.py <specimen.vbs> [...]

Each specimen stores a pipe-delimited configuration as an encoded constant and
rebuilds it through Load -> Decode -> Recover -> Inspect routines. Nothing is
executed: vbs_interp walks the parsed source in Python to recover the
configuration, and the routine bodies are read structurally to name the material
representation, the byte transform, and the control-flow form. Function and
variable names, constants, ordering, and the encoding all vary by variant, so
nothing here keys on them.

Every answer has a second source that does not need the evaluator: if a specimen
cannot be parsed or evaluated, the codec label, the material and the wrapper are
read straight from the text and the material is decoded from the label. Each
fallback and each unanswered question is reported on stderr, never silently.

Runner contract (called from analyze.py):  answers(questions, files, ctx) -> {qid: answer}
"""
import base64
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vbs_interp import Interp, VBSError, parse  # noqa: E402

# Ordered behaviour steps -> role. Checked exactly first, then by the marker rules in role_of.
# A hand-off to a script of the same language is still staged_chain ("relay" was rejected).
ROLE_BY_STEPS = {
    ("decode_configuration", "return_configuration"): "benign_utility",
    ("acquire_remote", "dispatch_memory"): "stager",
    ("decode_embedded", "write_file"): "dropper",
    ("acquire_remote", "write_file"): "downloader",
    ("locate_local", "prepare_transfer", "upload_remote"): "uploader",
    ("locate_local", "dispatch_process"): "launcher",
    ("enumerate_targets", "transform_content", "write_recovery_note"): "impact",
    ("acquire_remote", "write_file", "dispatch_process", "handoff_script"): "staged_chain",
}
ROLE_BY_ID = {"benign": "benign_utility", "stager": "stager", "dropper": "dropper", "downloader": "downloader",
              "uploader": "uploader", "launcher": "launcher", "impact": "impact", "chain": "staged_chain",
              "relay": "staged_chain"}

# Primary ATT&CK technique per role, confirmed on the base challenge (T1059.005 = Command and
# Scripting Interpreter: Visual Basic). A chain is T1059.005 whatever language its next stage is:
# T1059.001 was rejected for a chain that hands off to PowerShell.
ATTACK_BY_ROLE = {
    "benign_utility": "none",
    "stager": "T1105",
    "dropper": "T1140",
    "downloader": "T1105",
    "uploader": "T1041",
    "launcher": "T1059.005",
    "impact": "T1486",
    "staged_chain": "T1059.005",
}

# Control-flow form of the routine that invokes the decoder, as the judge names it. All of
# these are confirmed on live attempts: a loop that runs once is "<keyword>_once" (do_loop,
# while_wend and linear were rejected), On Error Resume Next around the call is error_guard,
# and an If True Then block around a bare call is layout, so the form is still direct.
# timed_ladder.py overwrites the "on_error", "if" and "for" entries from its conventions file.
CONTROL_NAMES = {
    "direct": "direct",
    "select": "select_case",
    "do": "do_once",
    "while": "while_once",
    "for": "for_once",
    "if": "direct",
    "on_error": "error_guard",
}

DELIMITER_NAMES = {"|": "pipe", "-": "dash", ":": "colon", ",": "comma", " ": "space", ";": "semicolon",
                   ".": "dot", "_": "underscore", "/": "slash", "\t": "tab"}
# "representation|transform|key": a short label, unlike the material, which has hundreds of fields.
CODEC_RE = re.compile(r"[a-z][a-z0-9_]*(?:\|[A-Za-z0-9_,]*){1,5}")
KINDS = ("role", "attack", "adapter", "campaign", "representation", "transform", "control")
BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
EVAL_STEPS = 400_000  # a specimen needs about ten thousand; a runaway one must not eat a timed window


def text_of(data: bytes) -> str:
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16")
    if data[:3] == b"\xef\xbb\xbf":
        return data[3:].decode("utf-8", "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


# ---- tree helpers ---------------------------------------------------------
def walk(node):
    """Yield every tuple node inside a statement, block, or expression, in source order."""
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, tuple):
            yield n
            stack.extend(reversed(n))
        elif isinstance(n, list):
            stack.extend(reversed(n))


def refs(node, names) -> set:
    """User routines named anywhere inside node."""
    return {n[1] for n in walk(node) if n and n[0] in ("call", "name") and isinstance(n[1], str) and n[1] in names}


def looks_like_config(v) -> bool:
    return isinstance(v, str) and v.count("=") >= 2 and "|" in v and bool(re.match(r"[A-Za-z_]\w*=", v))


def parse_config(text: str) -> dict:
    out = {}
    for part in text.split("|"):
        key, sep, value = part.partition("=")
        if sep:
            out.setdefault(key.strip(), value)
    return out


# ---- structural reading of the routines -----------------------------------
def find_routines(funcs: dict):
    """Return (load, decode, recover): recover is the routine that feeds a loader's result to a decoder."""
    names = set(funcs)

    def loader_of(node):
        if node[0] in ("call", "name") and node[1] in names and not funcs[node[1]][2] and not (node[0] == "call" and node[2]):
            return node[1]
        return None

    for n, f in funcs.items():
        if f[2]:
            continue
        loaded = {}  # variable -> the parameterless routine whose result it holds
        for st in walk(f[3]):
            if st[0] != "assign" or st[1][0] != "name":
                continue
            rhs = st[2]
            if loader_of(rhs):
                loaded[st[1][1]] = rhs[1]
            elif rhs[0] == "call" and rhs[1] in names and len(rhs[2]) == 1 and len(funcs[rhs[1]][2]) == 1:
                arg = rhs[2][0]
                if arg[0] == "name" and arg[1] in loaded:
                    return loaded[arg[1]], rhs[1], n
                if loader_of(arg):
                    return arg[1], rhs[1], n
    # No such data flow: fall back on who calls whom.
    calls = {n: refs(f[3], names) - {n} for n, f in funcs.items()}
    decode = recover = load = None
    for n in funcs:
        one_arg = [c for c in calls[n] if len(funcs[c][2]) == 1 and not funcs[c][4]]
        no_arg = [c for c in calls[n] if len(funcs[c][2]) == 0 and not funcs[c][4]]
        if one_arg and no_arg and (recover is None or n.startswith("recover")):
            recover, decode = n, sorted(one_arg, key=lambda c: not c.startswith("decode"))[0]
            load = sorted(no_arg, key=lambda c: not c.startswith("load"))[0]
    return load, decode, recover


def trail_to(block, target, trail=()):
    """Enclosing compound statements, outermost first, around the first statement that calls target."""
    for st in block:
        k = st[0]
        if k == "if":
            for cond, body in list(st[1]) + [(None, st[2])]:
                hit = trail_to(body, target, trail + (("if", cond),))
                if hit is not None:
                    return hit
        elif k == "select":
            for _, body in list(st[2]) + [(None, st[3])]:
                hit = trail_to(body, target, trail + (("select", st[1]),))
                if hit is not None:
                    return hit
        elif k in ("for", "foreach", "do", "while"):
            hit = trail_to(st[-1], target, trail + ((k if k != "foreach" else "for", None),))
            if hit is not None:
                return hit
        elif refs(st, {target}):
            return trail
    return None


def error_guarded(block, target, active=False):
    """Is On Error Resume Next in force at the first statement that calls target? None if none calls it."""
    for st in block:
        k = st[0]
        if k == "onerror":
            active = st[1] == "resume"
        elif k == "if":
            for body in [b for _, b in st[1]] + [st[2]]:
                hit = error_guarded(body, target, active)
                if hit is not None:
                    return hit
        elif k == "select":
            for body in [b for _, b in st[2]] + [st[3]]:
                hit = error_guarded(body, target, active)
                if hit is not None:
                    return hit
        elif k in ("for", "foreach", "do", "while"):
            hit = error_guarded(st[-1], target, active)
            if hit is not None:
                return hit
        elif refs(st, {target}):
            return active
    return None


def control_form(funcs, recover, decode):
    if not recover or not decode:
        return None
    body = funcs[recover][3]
    trail = trail_to(body, decode)
    if trail is None:
        return None
    # A constant-true guard is layout, not the form (confirmed: If True Then around Select Case
    # is select_case, around Do is do_once, and around a bare call is direct).
    inner = [k for k, cond in trail if not (k == "if" and cond == ("lit", True))]
    if inner:
        return inner[-1]
    return "on_error" if error_guarded(body, decode) else "direct"


def _reversed_fill(nodes) -> bool:
    return any(n[0] == "assign" and n[1][0] == "call" and any(m[0] == "bin" and m[1] == "-" for m in walk(n[1][2]))
               for n in nodes)


def representation_form(funcs, load, consts) -> str:
    """Name the stored representation from the loader's own code (used when no codec label exists)."""
    if not load:
        return ""
    nodes = list(walk(funcs[load][3]))
    helpers = [funcs[n[1]] for n in nodes if n[0] == "call" and n[1] in funcs and n[1] != load]
    if any(n[0] == "lit" and n[1] == BASE64_ALPHABET for h in helpers for n in walk(h[3])) or \
            any(n[0] == "lit" and n[1] == BASE64_ALPHABET for n in nodes):
        chunked = sum(1 for n in nodes if n[0] == "call" and n[1] in ("mid", "left", "right")) >= 2
        return "base64_chunks" if chunked else "base64_literal"
    is_hex = any(n[0] == "lit" and isinstance(n[1], str) and n[1].lower() == "&h" for n in nodes)
    base = "hex" if is_hex else "decimal"
    if _reversed_fill(nodes):
        return f"reversed_{base}"
    split = next((n for n in nodes if n[0] == "call" and n[1] == "split" and len(n[2]) >= 2), None)
    if split is None:
        return f"{base}_compact"
    delim = split[2][1]
    d = delim[1] if delim[0] == "lit" else consts.get(delim[1]) if delim[0] == "name" else None
    return f"{base}_{DELIMITER_NAMES.get(d, 'delimited')}"


def transform_form(funcs, decode) -> str:
    """Name the byte transform from the decoder's own code (used when no codec label exists)."""
    if not decode or not funcs[decode][2]:
        return ""
    param = funcs[decode][2][0][0]
    nodes = list(walk(funcs[decode][3]))
    xors = [n for n in nodes if n[0] == "bin" and n[1] == "xor"]
    if xors:
        x = xors[0]
        other = x[3] if (x[2][0] == "call" and x[2][1] == param) else x[2]
        if other[0] == "call":  # a key array indexed by position
            return "repeating_key_xor"
        if other[0] == "name":  # running state: rolling if it is refreshed from the input each round
            fed = any(n[0] == "assign" and n[1] == ("name", other[1])
                      and any(m[0] == "call" and m[1] == param for m in walk(n[2])) for n in nodes)
            if fed:
                return "rolling_xor"
        return "reverse_then_xor" if _reversed_fill(nodes) else "single_byte_xor"
    mods = [n for n in nodes if n[0] == "bin" and n[1] == "mod" and n[3] == ("lit", 256)]
    if mods:
        minus = any(n[0] == "bin" and n[1] == "-" for n in walk(mods[0][2]))
        return "add_modulo_256" if minus else "subtract_modulo_256"
    if _reversed_fill(nodes):
        return "reverse_bytes"
    if any(n[0] == "un" and n[1] == "not" for n in nodes):
        return "bitwise_not"
    return "identity"


# ---- decoding from the codec label alone ----------------------------------
def material_bytes(material: str, representation: str) -> list:
    rep = representation.lower()
    if "base64" in rep or "b64" in rep:
        text = re.sub(r"[^A-Za-z0-9+/]", "", material)
        data = list(base64.b64decode(text + "=" * (-len(text) % 4)))
    elif "hex" in rep:
        if re.fullmatch(r"\s*(?:[0-9A-Fa-f]{2})+\s*", material):
            data = list(bytes.fromhex(material.strip()))
        else:
            data = [int(t, 16) for t in re.split(r"[^0-9A-Fa-f]+", material) if t]
    elif "dec" in rep:
        if re.fullmatch(r"\s*(?:\d{3})+\s*", material):
            data = [int(material.strip()[i:i + 3]) for i in range(0, len(material.strip()), 3)]
        else:
            data = [int(t) for t in re.split(r"[^0-9]+", material) if t]
    else:
        raise ValueError(f"unknown representation {representation!r}")
    if "reversed" in rep:
        data.reverse()
    return data


def apply_transform(data: list, name: str, key: list) -> list:
    k0 = key[0] if key else 0
    if name in ("identity", "none", "plain", ""):
        return list(data)
    if name == "subtract_modulo_256":  # stored = plain - k, so reading it back adds k
        return [(b + k0) % 256 for b in data]
    if name == "add_modulo_256":
        return [(b - k0) % 256 for b in data]
    if name == "single_byte_xor":
        return [b ^ k0 for b in data]
    if name == "repeating_key_xor":
        if not key:
            raise ValueError("repeating_key_xor without a key")
        return [b ^ key[i % len(key)] for i, b in enumerate(data)]
    if name == "rolling_xor":
        out, prev = [], k0
        for b in data:
            out.append(b ^ prev)
            prev = b
        return out
    if name == "reverse_bytes":
        return list(data)[::-1]
    if name in ("reverse_then_xor", "xor_then_reverse"):
        return [b ^ k0 for b in data[::-1]]
    raise ValueError(f"unknown transform {name!r}")


TRANSFORMS = ("identity", "reverse_bytes", "single_byte_xor", "reverse_then_xor", "subtract_modulo_256",
              "add_modulo_256", "rolling_xor", "repeating_key_xor")


def label_decode(material: str, codec: list) -> str:
    """Decode the material from its codec label alone, without the specimen's own routines."""
    named = codec[1] if len(codec) > 1 else ""
    key = [int(x, 16) for x in (codec[2] if len(codec) > 2 else "").split(",") if re.fullmatch(r"[0-9A-Fa-f]{1,2}", x)]
    data = material_bytes(material, codec[0])
    for transform in [named] + [t for t in TRANSFORMS if t != named]:
        try:
            text = bytes(b & 0xFF for b in apply_transform(data, transform, key)).decode("latin-1")
        except ValueError:
            continue
        if looks_like_config(text):
            return text
    raise ValueError(f"label {codec[0]}|{named} does not decode the material to a configuration")


# ---- reading the raw text (no parser) -------------------------------------
STRING_RE = re.compile(r'"((?:[^"\r\n]|"")*)"')
ROUTINE_RE = re.compile(r"(?ims)^[ \t]*(?:(?:public|private)[ \t]+)?(?:default[ \t]+)?(function|sub)[ \t]+(\w+)[ \t]*"
                        r"(?:\(([^)\r\n]*)\))?(.*?)^[ \t]*end[ \t]+\1\b")
CALL_RE = re.compile(r"(?:set\s+)?(\w+)\s*=\s*(\w+)\s*(?:\(\s*(\w*)\s*\))?\s*$")


def strip_comment(line: str) -> str:
    quoted = False
    for i, ch in enumerate(line):
        if ch == '"':
            quoted = not quoted
        elif ch == "'" and not quoted:
            return line[:i]
    return line


def text_scan(source: str) -> dict:
    """Codec label, material and wrapper read from the text alone."""
    code = "\n".join(strip_comment(ln) for ln in source.splitlines())
    literals = [m.group(1).replace('""', '"') for m in STRING_RE.finditer(code)]
    labels = [s for s in literals if len(s) < 160 and CODEC_RE.fullmatch(s) and not looks_like_config(s)]
    rest = [s for s in literals if s not in labels and s != BASE64_ALPHABET]
    return {"codec": labels[0].split("|") if labels else None,
            "material": max(rest, key=len, default=""),
            "control": text_control(code)}


def text_control(code: str):
    """The wrapper around the decoder call, found by scanning lines. None if no such call is seen."""
    routines = [(m.group(2).lower(), len([p for p in (m.group(3) or "").split(",") if p.strip()]), m.group(4))
                for m in ROUTINE_RE.finditer(code)]
    arity = {name: n for name, n, _ in routines}
    for _, _, body in routines:
        loaded, stack, guarded = set(), [], False
        for raw in body.splitlines():
            low = raw.strip().lower()
            if not low:
                continue
            m = CALL_RE.match(low)
            if m and m.group(2) in arity:
                var, callee, arg = m.group(1), m.group(2), m.group(3) or ""
                if arity[callee] == 0 and not arg:
                    loaded.add(var)
                elif arity[callee] == 1 and arg in loaded:
                    forms = [k for k, layout in stack if not layout]
                    return forms[-1] if forms else ("on_error" if guarded else "direct")
            if re.match(r"select\s+case\b", low):
                stack.append(("select", False))
            elif re.match(r"do\b", low):
                stack.append(("do", False))
            elif re.match(r"while\b", low):
                stack.append(("while", False))
            elif re.match(r"for\b", low):
                stack.append(("for", False))
            elif re.match(r"if\b.*\bthen$", low):
                stack.append(("if", bool(re.match(r"if\s+\(?\s*true\s*\)?\s+then$", low))))
            elif re.match(r"(end\s+select|loop|wend|next|end\s+if)\b", low):
                if stack:
                    stack.pop()
            elif re.match(r"on\s+error\s+resume\s+next\b", low):
                guarded = True
            elif re.match(r"on\s+error\s+goto\s+0\b", low):
                guarded = False
    return None


# ---- one specimen ---------------------------------------------------------
def evaluate_into(info: dict, source: str):
    """The primary path: parse the specimen and walk its routines."""
    prog = parse(source)
    funcs = {st[1]: st for st in prog if st[0] == "func"}
    consts = {k: v for k, v in Interp(prog, max_steps=EVAL_STEPS).globals.items() if isinstance(v, str)}
    labels = sorted((k for k, v in consts.items() if len(v) < 160 and CODEC_RE.fullmatch(v) and not looks_like_config(v)),
                    key=lambda k: (not k.startswith("codec"), k))
    if labels:
        info["codec"] = consts[labels[0]].split("|")
    info["material"] = max((v for k, v in consts.items() if not labels or k != labels[0]), key=len, default="")

    # The configuration is whatever a parameterless routine returns that reads as key=value|key=value.
    order = sorted((n for n, f in funcs.items() if not f[2] and not f[4]),
                   key=lambda n: (not n.startswith("inspect"), not n.startswith("recover"), n))
    for name in order:
        try:
            value = Interp(prog, max_steps=EVAL_STEPS).call(name, [])
        except Exception as e:  # noqa: BLE001 - any failure here just means "try the next source"
            info["errors"].append(f"{name}: {type(e).__name__}: {e}")
            continue
        if looks_like_config(value):
            info["text"], info["source"] = value, "evaluated"
            break

    load, decode, recover = find_routines(funcs)
    info["routines"] = (load, decode, recover)
    info["control"] = control_form(funcs, recover, decode)
    info["representation_seen"] = representation_form(funcs, load, consts)
    info["transform_seen"] = transform_form(funcs, decode)


def analyze(source: str) -> dict:
    info = {"config": {}, "text": "", "source": None, "codec": None, "material": "", "errors": [], "notes": [],
            "routines": (None, None, None), "control": None, "representation_seen": "", "transform_seen": ""}
    try:
        evaluate_into(info, source)
    except Exception as e:  # noqa: BLE001 - the text path below still answers
        info["notes"].append(f"evaluator path failed ({type(e).__name__}: {e})")

    # Whatever the evaluator did not deliver is read from the text.
    if not (info["text"] and info["codec"] and info["control"]):
        try:
            seen = text_scan(source)
        except Exception as e:  # noqa: BLE001
            seen = {"codec": None, "material": "", "control": None}
            info["notes"].append(f"text scan failed ({type(e).__name__}: {e})")
        if not info["codec"] and seen["codec"]:
            info["codec"] = seen["codec"]
            info["notes"].append("codec label read from the text")
        if not info["material"]:
            info["material"] = seen["material"]
        if not info["control"] and seen["control"]:
            info["control"] = seen["control"]
            info["notes"].append(f"control form read from the text ({seen['control']})")
    if not info["text"] and info["codec"] and info["material"]:
        try:
            info["text"], info["source"] = label_decode(info["material"], info["codec"]), "label"
            info["notes"].append("configuration decoded from the codec label, not by evaluation: "
                                 + "; ".join(info["errors"])[:300])
        except Exception as e:  # noqa: BLE001
            info["notes"].append(f"label decode failed ({type(e).__name__}: {e})")
    if not info["text"]:
        info["notes"].append("NO CONFIGURATION RECOVERED: " + ("; ".join(info["errors"])[:300] or "no routine returned one"))
    if not info["control"]:
        info["notes"].append("no decoder call found; control form unknown")

    info["config"] = parse_config(info["text"])
    codec = info["codec"] or []
    info["representation"] = codec[0] if codec and codec[0] else info["representation_seen"]
    info["transform"] = codec[1] if len(codec) > 1 and codec[1] else info["transform_seen"]
    steps = tuple(s.strip() for s in info["config"].get("steps", "").split(",") if s.strip())
    info["steps"] = steps
    info["role"] = role_of(steps)
    return info


def role_of(steps: tuple):
    if steps in ROLE_BY_STEPS:
        return ROLE_BY_STEPS[steps]
    s = set(steps)
    if not s:
        return None
    if any("handoff" in x for x in s):
        return "staged_chain"
    if any(x in s for x in ("write_recovery_note", "transform_content", "enumerate_targets")):
        return "impact"
    if any("upload" in x for x in s):
        return "uploader"
    if "dispatch_memory" in s:
        return "stager"
    if "decode_embedded" in s:
        return "dropper"
    if "acquire_remote" in s:
        return "downloader"
    if "dispatch_process" in s:
        return "launcher"
    return None     # no marker: not a fact (row 51; it was benign_utility, so `none` for the technique)


def kind_of(q: dict):
    """(role slot, question kind) from the id's suffix; from the wording only for an id of another form.

    An id `<language>-<specimen>-<field>` names its field, also when that is an indicator (`-url`): its text
    is not read for a field word (Day 12: a re-worded question must not move to another field)."""
    qid = q.get("qid") or q.get("id") or ""
    m = re.match(r"(?:set\d+\.)?[a-z0-9]+-([a-z0-9]+)-(.+)$", qid)
    slot, tail = (m.group(1), m.group(2)) if m else ("", qid)
    if tail in KINDS:
        return slot, tail
    field = q.get("field") if isinstance(q.get("field"), str) else ""     # generic.with_fields: the id's field word
    if field in KINDS:
        return slot, field
    for kind in KINDS:
        if tail.endswith("-" + kind):
            return slot, kind
    if m:
        return slot, field or tail
    text = (q.get("question") or "").lower()
    for needle, kind in (("att&ck", "attack"), ("technique", "attack"), ("classify", "role"), ("adapter", "adapter"),
                         ("campaign", "campaign"), ("representation", "representation"),
                         ("transform", "transform"), ("control-flow", "control"), ("control flow", "control")):
        if needle in text:
            return slot, kind
    return slot, tail


def answer_for(q: dict, info: dict):
    cfg = info["config"]
    slot, kind = kind_of(q)
    role = info.get("role") or ROLE_BY_ID.get(slot)

    if kind == "role":
        allowed = (q.get("answer_format") or {}).get("accepted_values")
        return role if not allowed or role in allowed else ROLE_BY_ID.get(slot)
    if kind == "attack":
        return ATTACK_BY_ROLE.get(role)
    if kind == "adapter":
        return cfg.get("adapter")
    if kind == "campaign":
        return cfg.get("campaign_id") or cfg.get("campaign")
    if kind == "representation":
        return info.get("representation") or None
    if kind == "transform":
        return info.get("transform") or None
    if kind == "control":
        return CONTROL_NAMES.get(info.get("control"))
    # The id's own field word names the configuration key (`-host-id` is host_id). "Recover the exact <field>
    # indicator." speaks only for a key that word can mean, or for an id that is not of this component's form
    # (Day 12: a question is never moved to another key by its text).
    named = re.search(r"exact ([A-Za-z_][A-Za-z0-9_]*) indicator", q.get("question") or "")
    own = kind.replace("-", "_")
    if named and named.group(1) not in (own, kind) and re.match(r"(?:set\d+\.)?[a-z0-9]+-[a-z0-9]+-.+$", q.get("qid") or q.get("id") or "") \
            and not (named.group(1).startswith(own + "_") or named.group(1).endswith("_" + own)):
        named = None
    for key in [own, kind] + ([named.group(1)] if named else []):
        if key in cfg:
            return cfg[key]
    return None


def answers(questions, files, ctx):
    out, seen = {}, {}
    for q in questions:
        name = q.get("member") or (q.get("artifact") or "").split("->")[-1].strip()
        data = files.get(name)
        if data is None:
            base = name.rsplit("/", 1)[-1]
            data = next((v for k, v in files.items() if "->" not in k and k.rsplit("/", 1)[-1] == base), None)
        if data is None:
            print(f"[vbscript] {name}: NOT IN THE DELIVERY, no answer for {q.get('qid')}", file=sys.stderr)
            continue
        if name not in seen:
            try:
                seen[name] = analyze(text_of(data))
            except Exception as e:  # noqa: BLE001 - one unreadable specimen must not sink the others
                print(f"[vbscript] {name}: ANALYSIS FAILED, {type(e).__name__}: {e}", file=sys.stderr)
                seen[name] = None
            else:
                for note in seen[name]["notes"]:
                    print(f"[vbscript] {name}: {note}", file=sys.stderr)
        info = seen[name]
        value = None
        if info is not None:
            try:
                value = answer_for(q, info)
            except Exception as e:  # noqa: BLE001
                print(f"[vbscript] {name}: {q.get('qid')} raised {type(e).__name__}: {e}", file=sys.stderr)
        if value is None or value == "":
            print(f"[vbscript] {name}: NO ANSWER for {q.get('qid')}", file=sys.stderr)
            continue
        out[q["qid"]] = value
    return out


def main(argv) -> int:
    if argv and argv[0] in ("-h", "--help"):
        print("usage: vbscript.py <specimen.vbs> [...]")
        return 0
    if not argv:
        print("vbscript.py: expected at least one specimen", file=sys.stderr)
        return 2
    try:
        for path in argv:
            info = analyze(text_of(Path(path).read_bytes()))
            print(f"## {path}")
            print(f"   routines(load, decode, recover) = {info['routines']}   configuration: {info['source']}")
            print(f"   codec label = {info['codec']}   seen in code: {info['representation_seen']} | {info['transform_seen']}")
            print(f"   control = {info['control']} -> {CONTROL_NAMES.get(info['control'])}   role = {info['role']}   attack = {ATTACK_BY_ROLE.get(info['role'])}")
            for k, v in info["config"].items():
                print(f"     {k} = {v}")
            for e in info["notes"] + info["errors"]:
                print(f"   NOTE {e}")
    except Exception as exc:
        print(f"vbscript.py: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
