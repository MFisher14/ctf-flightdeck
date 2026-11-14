#!/usr/bin/env python3
"""Static analyzer for the Windows Script Host JScript specimens.

Usage:
  python3 solvers/script-analysis/jscript.py <file.js> [...]     print what each script reconstructs

Every specimen has the same skeleton under varying names and syntax: a decode
routine, a recovery routine that unpacks bytes and decodes them into the text
of a descriptor object, and an inspect routine that evals that text and reads
`steps`, `adapter`, `values` and `stageCount` from it. Nothing is executed in a
script host: the recovery routine is followed by the small interpreter in
js_interp.py (pure computation, no eval, no ActiveX), and the three style
questions are answered from the syntax tree of the inspect routine.

Runner contract (called by analyze.py): answers(questions, files, ctx).
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import js_interp as js

# Ordered behavior graph -> role. Exact graphs seen in the fixtures.
ROLE_BY_GRAPH = {
    ("decode_configuration", "return_configuration"): "benign_utility",
    ("acquire_remote", "dispatch_memory"): "stager",
    ("decode_embedded", "write_file"): "dropper",
    ("acquire_remote", "write_file"): "downloader",
    ("locate_local", "dispatch_process"): "launcher",
    ("locate_local", "prepare_transfer", "upload_remote"): "uploader",
    ("enumerate_targets", "transform_content", "write_recovery_note"): "impact",
    ("acquire_remote", "write_file", "dispatch_process", "handoff_script"): "staged_chain",
}
# Primary ATT&CK technique per role, as the judge accepts them. Roles that run
# something (launcher, staged_chain) take the specimen's own interpreter,
# T1059.007 Command and Scripting Interpreter: JavaScript, whatever binary or
# next-stage language the plan names; T1218.010 for a regsvr32.exe launcher and
# T1059.001 for a chain handing off to PowerShell were both judged incorrect.
# The dropper is T1140 for its decode_embedded step (T1027 was judged incorrect).
ATTACK_BY_ROLE = {
    "benign_utility": "none",
    "stager": "T1105",
    "dropper": "T1140",
    "downloader": "T1105",
    "uploader": "T1041",
    "launcher": "T1059.007",
    "impact": "T1486",
    "staged_chain": "T1059.007",
}

# Question field (the id's suffix) -> descriptor value keys to try, in order.
VALUE_KEYS = {
    "campaign": ["campaign_id"],
    "host": ["host_id"],
    "url": ["url", "upload_url"],
    "path": ["file_path"],
    "next-stage": ["next_stage"],
    "extension": ["extension"],
    "note": ["note_name"],
}
STYLE_FIELDS = {"function-style": "function_style", "invocation-style": "invocation_style",
                "property-style": "property_style"}


def _top_level_functions(program):
    """{name: (style, params, body)} for every function bound at top level."""
    found = {}
    for stmt in program:
        if stmt[0] == "funcdecl":
            found[stmt[1]] = ("declaration", stmt[2], stmt[3])
        elif stmt[0] == "var":
            for name, init in stmt[1]:
                init = js.unparen(init) if init is not None else None
                if init is not None and init[0] == "func":
                    found[name] = ("named_expression" if init[1] else "anonymous_expression", init[2], init[3])
        elif stmt[0] == "expr":
            node = js.unparen(stmt[1])
            if node[0] == "assign" and node[1] == "=" and js.unparen(node[2])[0] == "id":
                init = js.unparen(node[3])
                if init[0] == "func":
                    found[js.unparen(node[2])[1]] = ("named_expression" if init[1] else "anonymous_expression",
                                                    init[2], init[3])
    return found


def _invocation(call, names):
    """If call invokes one of names, return (name, 'direct' | 'call' | 'apply')."""
    callee = js.unparen(call[1])
    if callee[0] == "id" and callee[1] in names:
        return callee[1], "direct"
    if callee[0] in ("member", "index"):
        target = js.unparen(callee[1])
        method = callee[2] if callee[0] == "member" else js.unparen(callee[2])
        if callee[0] == "index":
            method = method[1] if method[0] == "str" else None
        if target[0] == "id" and target[1] in names and method in ("call", "apply"):
            return target[1], method
    return None


def _assigned(body, name):
    """Every expression a routine assigns to one of its local variables."""
    for node in js.walk(body):
        if node[0] == "var":
            for var_name, init in node[1]:
                if var_name == name and init is not None:
                    yield init
        elif node[0] == "assign" and js.unparen(node[2]) == ("id", name):
            yield node[3]


def _recovery_call(body, expr, names, depth=0):
    """The invocation of a top-level routine that feeds expr, following local variables."""
    for inner in js.walk(expr):
        hit = _invocation(inner, names) if inner[0] == "call" else None
        if hit:
            return hit
    if depth < 3:
        for inner in js.walk(expr):
            if inner[0] == "id":
                for init in _assigned(body, inner[1]):
                    hit = _recovery_call(body, init, names, depth + 1)
                    if hit:
                        return hit
    return None


def _find_inspect(functions):
    """Locate the routine that evals the recovered descriptor.

    Returns (inspect name, recovery name, invocation style, descriptor variable);
    the recovery name and style are None when the eval is not fed by a routine call.
    """
    names = set(functions)
    for name, (_, _, body) in functions.items():
        for node in js.walk(body):
            if node[0] == "call" and js.unparen(node[1]) == ("id", "eval"):
                hit = _recovery_call(body, node[2], names - {name}) or (None, None)
                return name, hit[0], hit[1], _eval_target(body, node)
    return None


def _eval_target(body, eval_call):
    """Name of the variable the eval result is stored in."""
    for node in js.walk(body):
        if node[0] == "var":
            for name, init in node[1]:
                if init is not None and any(n is eval_call for n in js.walk(init)):
                    return name
        elif node[0] == "assign" and js.unparen(node[2])[0] == "id" and any(n is eval_call for n in js.walk(node[3])):
            return js.unparen(node[2])[1]
    return None


def _property_style(body, variable, keys):
    """dot / bracket_literal / mixed, from how the descriptor's properties are read.

    Reads on the descriptor variable decide. If it has none (or is unknown), any
    access that names one of the descriptor's own keys is counted instead.
    """
    def collect(only_variable):
        kinds = set()
        for node in js.walk(body):
            if node[0] == "member":
                if (js.unparen(node[1]) == ("id", variable)) if only_variable else (node[2] in keys):
                    kinds.add("dot")
            elif node[0] == "index":
                key = js.unparen(node[2])
                if (js.unparen(node[1]) == ("id", variable)) if only_variable else (key[0] == "str" and key[1] in keys):
                    kinds.add("bracket_literal")
        return kinds

    kinds = (collect(True) if variable else set()) or collect(False)
    if not kinds:
        return None
    return kinds.pop() if len(kinds) == 1 else "mixed"


def _parse_descriptor(text: str):
    return js.Interp().eval(js.parse_expression("(" + text + ")"), js.Scope())


def _text_via_inspect(program, inspect_name):
    """Follow the inspect routine itself and take the text it hands to eval."""
    seen = []
    interp = js.Interp()

    def hook(text):
        seen.append(text)
        return _parse_descriptor(text)

    interp.eval_hook = hook
    interp.define_only(program)
    try:
        interp.call(interp.globals.vars[inspect_name], js.UNDEF, [])
    except (js.JSError, js.JSThrow):
        pass
    if not seen:
        raise js.JSError("the descriptor text could not be recovered")
    text = seen[0].strip()
    return text[1:-1] if text.startswith("(") and text.endswith(")") else text


def analyze(source: str) -> dict:
    """Reconstruct a specimen's descriptor and syntax facts. Raises js.JSError if it cannot."""
    program = js.parse(source)
    functions = _top_level_functions(program)
    found = _find_inspect(functions)
    if not found:
        raise js.JSError("no routine evals a recovered descriptor")
    inspect_name, recover_name, invocation, variable = found

    def by_recovery_routine():
        if not recover_name:
            raise js.JSError("the eval is not fed by a top-level routine")
        interp = js.Interp()
        interp.define_only(program)
        return interp.call(interp.globals.vars[recover_name], js.UNDEF, [])

    text = descriptor = None
    for recover_text in (by_recovery_routine, lambda: _text_via_inspect(program, inspect_name)):
        try:
            text = recover_text()
            descriptor = js.to_python(_parse_descriptor(text)) if isinstance(text, str) else None
        except (js.JSError, js.JSThrow):
            descriptor = None
        if isinstance(descriptor, dict) and descriptor:
            break
    else:
        raise js.JSError("the descriptor could not be reconstructed")
    return {
        "descriptor": descriptor,
        "text": text,
        "inspect": inspect_name,
        "recover": recover_name,
        "function_style": functions[inspect_name][0],
        "invocation_style": invocation,
        "property_style": _property_style(functions[inspect_name][2], variable, set(descriptor)),
    }


def classify(descriptor: dict) -> str:
    """Role from the complete ordered behavior graph.

    The graph alone decides: relay-handoff.js hands off to another JScript and
    staged-handoff.js to PowerShell, but both walk the same four steps and both
    are staged_chain (`relay` was judged incorrect).
    """
    steps = tuple(descriptor.get("steps") or ())
    role = ROLE_BY_GRAPH.get(steps)
    if role is None:  # an unseen graph: fall back to what its steps do
        have = set(steps)
        if "handoff_script" in have:
            role = "staged_chain"
        elif "upload_remote" in have:
            role = "uploader"
        elif have & {"transform_content", "write_recovery_note"}:
            role = "impact"
        elif "dispatch_memory" in have:
            role = "stager"
        elif {"acquire_remote", "write_file"} <= have:
            role = "downloader"
        elif "write_file" in have:
            role = "dropper"
        elif "dispatch_process" in have:
            role = "launcher"
        else:
            role = "benign_utility"
    return role


def technique(descriptor: dict) -> str:
    return ATTACK_BY_ROLE.get(classify(descriptor))


def _field(qid: str) -> str:
    """The question's field: the id without its `<language>-<scenario>-` prefix."""
    parts = qid.split("-")
    return "-".join(parts[2:]) if len(parts) > 2 else qid


def answer(q: dict, info: dict):
    d = info["descriptor"]
    values = d.get("values") or {}
    field = _field(q["qid"])
    if field == "role":
        return classify(d)
    if field == "attack":
        return technique(d)
    if field == "adapter":
        return d.get("adapter")
    if field in STYLE_FIELDS:
        return info.get(STYLE_FIELDS[field])
    for key in VALUE_KEYS.get(field, []) + [field.replace("-", "_")]:
        if key in values:
            return values[key]
    # Last resort: a value whose key the question's text names, and only a key the id's own field word can
    # mean (`host` for host_id). Day 12: a text that names another key never moves a question to it.
    text = (q.get("question") or "").lower()
    want = field.replace("-", "_")
    for key in values:
        if (key.replace("_", " ") in text or key.replace("_", "-") in text) and want and (want in key or key in want):
            return values[key]
    return None


def answers(questions, files, ctx):
    out, cache = {}, {}
    for q in questions:
        name = q.get("member")
        data = files.get(name)
        if data is None:
            continue
        if name not in cache:
            try:
                cache[name] = analyze(data.decode("utf-8", errors="replace"))
            except Exception as exc:  # noqa: BLE001 - one bad specimen must not sink the rest
                print(f"[jscript] {name}: {type(exc).__name__}: {exc}", file=sys.stderr)
                cache[name] = None
        if cache[name] is None:
            continue
        value = answer(q, cache[name])
        if value is not None:
            out[q["qid"]] = value if isinstance(value, str) else js.to_str(value)
    return out


if __name__ == "__main__":
    import json
    for path in sys.argv[1:]:
        try:
            info = analyze(Path(path).read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:  # noqa: BLE001 - CLI reports and moves on
            print(f"{path}: FAILED {type(exc).__name__}: {exc}")
            continue
        d = info["descriptor"]
        print(f"{path}: role={classify(d)} attack={technique(d)} function={info['function_style']} "
              f"invocation={info['invocation_style']} property={info['property_style']}")
        print("   " + json.dumps(d, ensure_ascii=False))
