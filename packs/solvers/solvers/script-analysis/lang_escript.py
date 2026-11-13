"""Static Erlang/escript material reader for the cumulative Script lane.

Only the inert, zero-argument function grammar used by the lane is evaluated:
quoted charlists, integer charlists, ``++``, adjacent strings,
``lists:append([...])``, and calls to other zero-argument functions in the same
file.  No Erlang is executed.  A codec and material function with one shared id
must both be present; ambiguous definitions or anything outside this grammar
leave the generic reader in charge.
"""

from __future__ import annotations

import json
import re

import plan_codec

# This lane's generic.py by path, never `import generic`: solvers/binary has one too, and a process that
# loaded it first would hand this reader the Binary module (SH-05).
generic = plan_codec.own("generic")


MAX_TEXT = 1 << 20
MAX_VALUE = 4 << 20
MAX_DEPTH = 16
MAX_DEFS = 64
_DEF = re.compile(r"(?ms)^[ \t]*([a-z][a-z0-9_]*)\(\)[ \t]*->[ \t]*(.*?)[ \t]*\.[ \t]*(?=\r?$)")
_CALL = re.compile(r"([a-z][a-z0-9_]*)\(\)")
_INTS = re.compile(r"\[[ \t\r\n]*\d{1,3}(?:[ \t\r\n]*,[ \t\r\n]*\d{1,3})*[ \t\r\n]*\]")


class Refuse(ValueError):
    pass


def _bounded(value: str) -> str:
    if not isinstance(value, str) or len(value) > MAX_VALUE:
        raise Refuse("value too large")
    return value


def _string(expr: str, at: int = 0):
    if at >= len(expr) or expr[at] != '"':
        raise Refuse("not a string")
    out, i = [], at + 1
    while i < len(expr):
        ch = expr[i]
        if ch == '"':
            return _bounded("".join(out)), i + 1
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        i += 1
        if i >= len(expr):
            raise Refuse("dangling escape")
        if expr.startswith("x{", i):
            end = expr.find("}", i + 2)
            if end < 0 or not re.fullmatch(r"[0-9A-Fa-f]{1,6}", expr[i + 2:end]):
                raise Refuse("bad hex escape")
            code = int(expr[i + 2:end], 16)
            if code > 0x10FFFF:
                raise Refuse("hex escape out of range")
            out.append(chr(code))
            i = end + 1
            continue
        if expr[i] == "x" and i + 2 < len(expr) and re.fullmatch(r"[0-9A-Fa-f]{2}", expr[i + 1:i + 3]):
            out.append(chr(int(expr[i + 1:i + 3], 16)))
            i += 3
            continue
        simple = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v",
                  "\\": "\\", '"': '"', "s": " "}
        if expr[i] in simple:
            out.append(simple[expr[i]])
            i += 1
            continue
        raise Refuse("unknown escape")
    raise Refuse("unterminated string")


def _parts(expr: str, sep: str):
    """Split a top-level operator/comma, respecting strings and brackets."""
    out, start, quote, escaped, depth, i = [], 0, False, False, 0, 0
    while i < len(expr):
        ch = expr[i]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                quote = False
            i += 1
            continue
        if ch == '"':
            quote = True
            i += 1
            continue
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
            if depth < 0:
                raise Refuse("unbalanced expression")
        elif depth == 0 and expr.startswith(sep, i):
            out.append(expr[start:i].strip())
            start, i = i + len(sep), i + len(sep)
            continue
        i += 1
    if quote or depth:
        raise Refuse("unbalanced expression")
    out.append(expr[start:].strip())
    return out


def _adjacent_strings(expr: str):
    values, i = [], 0
    while i < len(expr):
        while i < len(expr) and expr[i].isspace():
            i += 1
        if i == len(expr):
            break
        value, i = _string(expr, i)
        values.append(value)
        if i < len(expr) and not expr[i].isspace():
            raise Refuse("text behind string")
    return _bounded("".join(values)) if values else None


def _eval(expr: str, defs: dict, stack=()):
    if len(stack) >= MAX_DEPTH:
        raise Refuse("reference depth")
    expr = expr.strip()
    joined = _parts(expr, "++")
    if len(joined) > 1:
        return _bounded("".join(_eval(part, defs, stack) for part in joined))
    if expr.startswith('"'):
        return _adjacent_strings(expr)
    if _INTS.fullmatch(expr):
        values = [int(x) for x in re.findall(r"\d+", expr)]
        if any(x > 255 for x in values) or len(values) > MAX_VALUE:
            raise Refuse("invalid charlist")
        return "".join(chr(x) for x in values)
    if expr.startswith("lists:append(") and expr.endswith(")"):
        inner = expr[len("lists:append("):-1].strip()
        if not (inner.startswith("[") and inner.endswith("]")):
            raise Refuse("append is not a literal list")
        return _bounded("".join(_eval(part, defs, stack) for part in _parts(inner[1:-1], ",")))
    call = _CALL.fullmatch(expr)
    if call:
        name = call.group(1)
        if name in stack or name not in defs:
            raise Refuse("unknown or recursive function")
        return _eval(defs[name], defs, stack + (name,))
    raise Refuse("expression outside static grammar")


def _material(text: str):
    if not isinstance(text, str) or len(text) > MAX_TEXT or "-module(" not in text:
        return None
    rows = _DEF.findall(text)
    if not rows or len(rows) > MAX_DEFS:
        return None
    defs = {}
    for name, expr in rows:
        if name in defs:
            return None
        defs[name] = expr
    codec = [(name, expr) for name, expr in rows if name.startswith("codec_")]
    material = [(name, expr) for name, expr in rows if name.startswith("material_")]
    if len(codec) != 1 or len(material) != 1 or codec[0][0][len("codec_"):] != material[0][0][len("material_"):]:
        return None
    try:
        label = _eval(codec[0][1], defs, (codec[0][0],))
        value = _eval(material[0][1], defs, (material[0][0],))
    except Refuse:
        return None
    if not re.fullmatch(r"[A-Za-z0-9_+>-]+(?:\|[A-Za-z0-9_+>-]+){0,3}", label):
        return None
    primary = _decoded_plan(label, value)
    if primary is None:
        return None
    # A second zero-argument function may be a complete older/decoy plan.  The
    # material name alone is not authority over another complete plan in the
    # same bytes, so preserve the lane's two-plans-means-none rule.  Pieces used
    # by the material expression do not count: only a complete versioned plan
    # under the declared codec does.
    used = set()
    pending = [material[0][0]]
    while pending:
        parent = pending.pop()
        for child in _CALL.findall(defs.get(parent, "")):
            if child in defs and child not in used:
                used.add(child)
                pending.append(child)
    for name, expr in rows:
        if name in (codec[0][0], material[0][0]) or name in used:
            continue
        try:
            other_value = _eval(expr, defs, (name,))
        except Refuse:
            continue
        other = _decoded_plan(label, other_value)
        if other is not None and other != primary:
            return None
    return label, value


def _decoded_plan(label: str, value: str):
    canonical = f"Codec_static = {json.dumps(label)}\nMaterial_static = {json.dumps(value)}\n"
    try:
        info = generic.read("static.escript", canonical.encode("utf-8"))
        descriptor = generic.plan_codec.optional("descriptor")
        plan = info.get("plan") or {}
        if not plan or info.get("cut") or descriptor is None or descriptor.checked(plan, short_ok=False):
            return None
        return tuple((str(k), str(v)) for k, v in plan.items())
    except Exception:
        return None


def answers(questions, files, ctx):
    if not questions:
        return {}
    members = {q.get("member") or (q.get("artifact") or "").split("->")[-1].strip() for q in questions}
    if len(members) != 1:
        return {}
    member = next(iter(members))
    data = generic.find(files, member)
    if not isinstance(data, (bytes, bytearray)):
        return {}
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError:
        return {}
    got = _material(text)
    if got is None:
        return {}
    label, value = got
    # Hand the reconstructed bytes back to the lane's established codec and
    # answer logic. JSON quoting makes this one grammar-bounded literal.
    canonical = f"Codec_static = {json.dumps(label)}\nMaterial_static = {json.dumps(value)}\n"
    view = dict(files)
    view[member] = canonical.encode("utf-8")
    return generic.answers(questions, view, ctx)
