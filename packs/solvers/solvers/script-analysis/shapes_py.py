#!/usr/bin/env python3
"""What generic.py leaves open on a .py specimen (Script Analysis, Day 5: the Python carrier lab).

    shapes(text, questions) -> {qid: value}

generic.py calls this once per .py specimen with the file's text and the questions it could not
answer. Nothing is executed: the file is parsed with `ast` (a parse, never an import or an eval of
code), its literals are read, and the plan is decoded from them.

Usage (offline, prints the reading of each file and makes no request):
  .venv/bin/python solvers/script-analysis/shapes_py.py <specimen.py> [...]

What a .py specimen is. One plan, version 2,

    v=2|steps=...|adapter=...|stage_count=...|syntax=...|obfuscation=...|carrier=...|windows_chain=...|campaign_id=...|<indicators>

stored as MATERIAL_<id> (a decimal or hex string, a bytes literal, a list or tuple of integers,
base64 in one piece or in adjacent pieces, url-safe base64) and labelled CODEC_<id> =
"representation|transform|key". load_<id>() turns the material into bytes, decode_<id>() undoes
the transform, and surface_<id>() returns the same four names the plan carries as (syntax,
obfuscation, carrier, windows_chain), each time written in the syntax structure its first name
describes.

How the plan is read: every literal of the file (also literals joined with +, a "".join of
literals, a bytes(...) around one) is tried under every representation it reads as, then under
every transform a known-plaintext crib (`v=<n>|steps=`) fixes: plan_codec.undo (identity, xor,
add, rolling xor, repeating xor, bit rotation, each also on the reversed bytes) and _undo_more
below. The codec label is not needed and not used. plan_codec's strict plan grammar is the only
acceptance.

Why this file was needed on the morning of Day 5 although the plan is the lane's usual one. The
general path (generic.py, plan_codec.py) has closed all three gaps since the tag made after that
day, so this file is now asked only for what the general path still leaves out, which on the
three saved Day 5 attempts is nothing:

  - the ids are `python-<carrier words>-<field>` with a varying number of words, so generic's
    "third part of the id" was not the field (`benign-adapter`, `pyc-launcher-syntax`): adapter,
    campaign and the four profile fields stayed open on every specimen;
  - plan_codec read neither a bytes literal with \\x escapes, nor base64 written as adjacent
    string literals, nor url-safe base64, nor a tuple of integers that ends in a comma: on those
    specimens every id was open;
  - four step lists were new, so their role and technique were not in the judged tables.

How each answer is made:

  adapter, campaign, an indicator   the plan's own value, as generic gives it (plain).
  syntax, obfuscation, carrier, windows-chain
                    the plan's own value (plain; judged for all 56 specimens of the Day 5 base,
                    Time Trial and Mastery). Only for a plan without such a key: labels.pick over
                    the file's one four-name surface tuple, unsure.
  role              the judged table of eight step lists (plain). A step list that is not in it
                    is a new fact: labels.pick('script.role/py.<steps>', role names, the one the
                    steps and the id point to first), never a plain answer.
  attack            the role's judged technique (plain); labels.pick('script.attack/py',
                    ['T1059.006']) for a launcher or a staged chain (the script's own
                    interpreter, generic's key); labels.pick('script.attack/py.<steps>', ...)
                    for a new step list.
  role, attack in a file that carries a tagged descriptor (descriptor.present)
                    None, both (Day 12 look-ahead, S1). Such a plan states its own role and attack
                    and the judge takes the stated ones; they are the general path's, whole or
                    nothing, and a descriptor it refused is not answered from the steps table here.

None (the id is left out) when the fact is not established: no plan decodes, two different plans
decode, the plan has no such key.
"""
import ast
import base64
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _p in (HERE, HERE.parent / "common"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import labels  # noqa: E402
import plan_codec  # noqa: E402

EXT = "py"

# Ordered behaviour steps -> role: the eight graphs the judge has accepted (generic.ROLE).
ROLE = {
    ("decode_configuration", "return_configuration"): "benign_utility",
    ("acquire_remote", "dispatch_memory"): "stager",
    ("decode_embedded", "write_file"): "dropper",
    ("acquire_remote", "write_file"): "downloader",
    ("locate_local", "dispatch_process"): "launcher",
    ("locate_local", "prepare_transfer", "upload_remote"): "uploader",
    ("enumerate_targets", "transform_content", "write_recovery_note"): "impact",
    ("acquire_remote", "write_file", "dispatch_process", "handoff_script"): "staged_chain",
}
# Role -> technique, judged in JScript, Batch and VBScript (generic.ATTACK). The two roles that
# run something take the script's own interpreter.
ATTACK = {"benign_utility": "none", "stager": "T1105", "dropper": "T1140", "downloader": "T1105",
          "uploader": "T1041", "impact": "T1486"}
OWN_INTERPRETER = ("launcher", "staged_chain")
OWN_TECHNIQUE = "T1059.006"
ROLE_NAMES = ("benign_utility", "stager", "dropper", "downloader", "uploader", "launcher", "impact",
              "staged_chain", "relay")
# What a role word in an answer id stands for.
ID_ROLE = {"benign": "benign_utility", "stager": "stager", "dropper": "dropper", "downloader": "downloader",
           "uploader": "uploader", "launcher": "launcher", "impact": "impact", "chain": "staged_chain",
           "relay": "relay"}

FIELDS = ("windows-chain", "obfuscation", "syntax", "carrier", "adapter", "campaign", "attack", "role")
PLAN_KEY = {"adapter": "adapter", "campaign": "campaign_id"}
SURFACE = {"syntax": 0, "obfuscation": 1, "carrier": 2, "windows-chain": 3}   # place in the surface tuple
MIN_MATERIAL = 24
MAX_DEPTH = 200
_NAME = re.compile(r"[a-z][a-z0-9_]*")


# ---------------------------------------------------------------------------- literals

def _value(node, env, depth=0):
    """The literal a node spells out: a constant, a list or tuple of literals, literals joined
    with +, a name assigned one of these, or "".join(<list of literals>). ValueError otherwise."""
    if depth > MAX_DEPTH:
        raise ValueError("too deep")
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (str, bytes)) or (isinstance(node.value, int) and not isinstance(node.value, bool)):
            return node.value
        raise ValueError("not a literal")
    if isinstance(node, (ast.List, ast.Tuple)):
        return [_value(e, env, depth + 1) for e in node.elts]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        a, b = _value(node.left, env, depth + 1), _value(node.right, env, depth + 1)
        if type(a) is type(b) and isinstance(a, (str, bytes, list)):
            return a + b
        raise ValueError("mixed +")
    if isinstance(node, ast.Name) and node.id in env:
        target = env[node.id]
        if target is None:
            raise ValueError("assigned twice")
        return _value(target, {k: v for k, v in env.items() if k != node.id}, depth + 1)
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "join"
            and len(node.args) == 1 and not node.keywords and isinstance(node.func.value, ast.Constant)
            and isinstance(node.func.value.value, (str, bytes))):
        parts = _value(node.args[0], env, depth + 1)
        if isinstance(parts, list) and all(isinstance(p, type(node.func.value.value)) for p in parts):
            return node.func.value.value.join(parts)
    # bytes([...]), bytearray(b"..."), list((...)), tuple([...]), str("..."): the literal inside.
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and len(node.args) == 1 and not node.keywords
            and node.func.id in ("bytes", "bytearray", "list", "tuple", "str")):
        inner = _value(node.args[0], env, depth + 1)
        if isinstance(inner, (str, bytes, list)):
            return inner
    raise ValueError("not a literal")


def _tree(text: str):
    try:
        return ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None


# ---- row 142: a literal that is a piece of a longer value
#
# Read alone, the first piece of a material decodes to a whole plan by grammar whose last value is cut
# (`file_path=/tmp/x/.0a1b2c` for `..2c3d.stage`). plan_codec grades such a literal PIECE and leaves the
# plan's last field out; this file then read the same literal by itself and answered the cut value plain
# (26 of 66 spellings in tests/test_script_b.py: m.concat(..), "%s%s" % (a, ".."), a list that is appended to,
# two pieces as the items of one list, tuple, dict or call, buf.write(..) twice, 'x'.reverse then <<).
# A candidate is doubted when the tree or the text shows it joined to something else:
#
#   where it stands   an item of a list, tuple, set, dict or call beside another item that reads as material
#                     (_like); an operand of + % << *; inside an f-string; the receiver or an argument of a
#                     method that adds text (APPENDERS), an argument of format/join/concat beside another;
#   its variable      any other use of the name it is assigned to that stands so, the name appended to, and
#                     what plan_codec's own text rules say of the name (plan_codec._joined_use, _grown).
#
# A doubted candidate is still read (it may be the only reading of the plan): recover() takes its plan
# without the last field, as plan_codec does for a piece. A plan that an undoubted candidate gives too
# (the join the tree computes: "a" + "b", "".join([..])) stays whole.
APPENDERS = frozenset(("append", "extend", "add", "insert", "push", "concat", "write", "writelines", "update",
                       "appendleft", "__add__", "__iadd__", "ljust", "rjust", "center", "zfill"))
JOINERS = frozenset(("format", "join", "concat", "format_map", "paste", "sprintf", "printf"))
JOIN_OPS = (ast.Add, ast.Mod, ast.LShift, ast.Mult)
WRAPPERS = ("bytes", "bytearray", "list", "tuple", "str")
SIBLINGS_MAX = 64            # items of one list beside a candidate that are read for more material
_MATERIAL_LIKE = re.compile(r"[A-Za-z0-9+/=_\-,.: \\xX]{8,}")


def _like(node, env) -> bool:
    """Whether a sibling of a candidate reads as more material: a string or bytes literal of eight characters
    or more in an encoding's alphabet, a name assigned one, an f-string, or a list of numbers."""
    if isinstance(node, ast.Name) and env.get(node.id) is not None:
        node = env[node.id]
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        v = node.value if isinstance(node.value, str) else node.value.decode("latin-1")
        return _MATERIAL_LIKE.fullmatch(v) is not None
    if isinstance(node, (ast.List, ast.Tuple)) and len(node.elts) >= 8:
        return all(isinstance(e, ast.Constant) and isinstance(e.value, int) for e in node.elts)
    return False


def _joined_at(node, parents, env):
    """(joined, top): whether `node` stands joined to something else (see above), and the outermost
    expression that still is this value alone (the literal behind its own calls, slices and wrappers)."""
    t, through = node, False
    for _ in range(MAX_DEPTH):
        p = parents.get(id(t))
        if p is None:
            return False, t
        if isinstance(p, ast.Attribute) and p.value is t:
            call = parents.get(id(p))
            if p.attr in APPENDERS:
                return True, t
            if isinstance(call, ast.Call) and call.func is p:
                if p.attr in JOINERS and (len(call.args) >= 2 or p.attr != "join"):
                    return True, t               # "<piece>{}".format(rest), piece.concat(rest)
                if any(_like(a, env) for a in call.args):
                    return True, t               # f("<piece>").f("<rest>"): a method handed more material
                t = call
                continue
            t = p                                # '<piece>'.reverse (Ruby's call without brackets)
            continue
        if isinstance(p, ast.Subscript) and p.value is t:
            if isinstance(p.slice, ast.Slice):
                t = p
                continue
            return False, t
        if isinstance(p, ast.Starred):
            t = p
            continue
        if isinstance(p, ast.Call) and any(a is t for a in p.args):
            if isinstance(p.func, ast.Name) and p.func.id in WRAPPERS and len(p.args) == 1:
                t = p
                continue
            attr = p.func.attr if isinstance(p.func, ast.Attribute) else p.func.id if isinstance(p.func, ast.Name) else ""
            if (attr in APPENDERS and not through) or (attr in JOINERS and len(p.args) >= 2):
                return True, t
            if any(a is not t and _like(a, env) for a in p.args):
                return True, t
            if len(p.args) == 1 and not p.keywords:
                t, through = p, True             # decode("<piece>"): what the call returns may be joined on
                continue
            return False, t
        if isinstance(p, ast.BinOp):
            return isinstance(p.op, JOIN_OPS), t
        if isinstance(p, (ast.JoinedStr, ast.FormattedValue)):
            return True, t
        if isinstance(p, (ast.List, ast.Tuple, ast.Set)):
            if len(p.elts) > SIBLINGS_MAX:
                return True, t                   # one of very many items: a piece, without reading them all
            return any(e is not t and _like(e, env) for e in p.elts), t
        if isinstance(p, ast.Dict):
            return any(v is not t and v is not None and _like(v, env) for v in p.values), t
        return False, t
    return True, t


def _offset(text: str, starts: list, node) -> int:
    """The character offset of a node in the text (ast counts columns in UTF-8 bytes)."""
    line = getattr(node, "lineno", 0)
    if not 1 <= line <= len(starts):
        return -1
    a = starts[line - 1]
    b = starts[line] if line < len(starts) else len(text)
    return a + len(text[a:b].encode("utf-8")[:node.col_offset].decode("utf-8", "ignore"))


def _doubts(text: str, tree, env) -> set:
    """The ids of the candidate nodes that are pieces of a longer value (see above)."""
    parents, uses = {}, {}
    for p in ast.walk(tree):
        for c in ast.iter_child_nodes(p):
            parents[id(c)] = p
        if isinstance(p, ast.Name) and isinstance(p.ctx, ast.Load):
            uses.setdefault(p.id, []).append(p)
    starts = [0] + [m.end() for m in re.finditer(r"\r\n|\r|\n", text)]
    try:
        grown = plan_codec._grown(text)
    except Exception:  # noqa: BLE001 - plan_codec's text rule is a second opinion only
        grown = set()
    by_name, out = {}, set()

    def name_grown(name):
        """Appended to: by a method (parts.append(..)) or as plan_codec reads the text (NAME += ..)."""
        return name in grown or any(isinstance(parents.get(id(u)), ast.Attribute) and parents[id(u)].attr in APPENDERS
                                    for u in uses.get(name, ()))

    def held_by(top):
        """The name a value is assigned to, also as the one item of a list (`parts = ["<piece>"]`,
        `parts = [MATERIAL]`: the list its name holds is what grows), and the value the name holds."""
        holder = parents.get(id(top))
        while isinstance(holder, (ast.List, ast.Tuple)) and len(holder.elts) == 1:
            top, holder = holder, parents.get(id(holder))
        target = None
        if isinstance(holder, ast.Assign) and len(holder.targets) == 1:
            target = holder.targets[0]
        elif isinstance(holder, (ast.AnnAssign, ast.NamedExpr)) and holder.value is top:
            target = holder.target
        return (target.id if isinstance(target, ast.Name) else None), top

    def name_joined(name, at, depth=0):
        if name not in by_name:
            by_name[name] = False                # while it is being asked (a = b; b = a)
            hit = name_grown(name)
            for u in uses.get(name, ()):
                if hit:
                    break
                hit, top = _joined_at(u, parents, env)
                if not hit and depth < 4:
                    other, _ = held_by(top)      # passed on to another name, which may be the one that grows
                    hit = bool(other) and other != name and name_joined(other, -1, depth + 1)
            if not hit and at >= 0:
                try:
                    hit = bool(plan_codec._joined_use(text, name, at, at))
                except Exception:  # noqa: BLE001
                    hit = False
            by_name[name] = hit
        return by_name[name]

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Constant, ast.List, ast.Tuple, ast.BinOp, ast.Call)):
            continue
        if isinstance(node, ast.Constant) and not isinstance(node.value, (str, bytes)):
            continue                             # a number is no material by itself (a list of them is, as a list)
        joined, top = _joined_at(node, parents, env)
        if not joined and not isinstance(node, ast.Constant):
            # A value the tree computes through a name ("".join(parts)) is whole only while that name's
            # value is not added to elsewhere (parts.append("<rest>")).
            joined = any(isinstance(n, ast.Name) and n.id in env and name_grown(n.id) for n in ast.walk(node))
        if not joined:
            name, top = held_by(top)
            if name:
                joined = name_joined(name, _offset(text, starts, top))
        if joined:
            out.add(id(node))
    return out


def _materials(text: str, tree) -> list:
    """Every literal of the file that could be the material, as Python values."""
    return [value for value, _ in _graded_materials(text, tree)]


def _graded_materials(text: str, tree) -> list:
    """[(value, whole)]: _materials, each with whether nothing says it is a piece of a longer value (row 142)."""
    out = []
    if tree is not None:
        env = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                env[name] = None if name in env else node.value
        # A literal inside a + expression that is not all literal (chr(..) + "...") is a piece of a value
        # this reader cannot compute: what it decodes to may lack an end, so it is not material on its own
        # (2026-10-06, tests/variants.py char_calls: cut file paths answered plain).
        pieces = set()
        # A name that is appended to (NAME += ...) holds no whole value in any one of its assignments.
        grown = {n.target.id for n in ast.walk(tree) if isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name)}
        for node in ast.walk(tree):
            if isinstance(node, ast.AugAssign) or (isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id in grown for t in node.targets)):
                pieces.update(id(n) for n in ast.walk(node.value))
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                try:
                    _value(node, env)
                except (ValueError, RecursionError):
                    pieces.update(id(n) for n in ast.walk(node) if n is not node)
        try:
            doubted = _doubts(text, tree, env)
        except RecursionError:
            doubted = None                       # nothing can be said: every candidate is doubted
        for node in ast.walk(tree):
            if id(node) in pieces:
                continue
            if isinstance(node, (ast.Constant, ast.List, ast.Tuple, ast.BinOp, ast.Call)):
                try:
                    out.append((_value(node, env), doubted is not None and id(node) not in doubted))
                except (ValueError, RecursionError):
                    pass
    else:
        # A file this Python cannot parse: the right-hand side of NAME = <literal>, read alone. Whether it is
        # a piece is plan_codec's to say, from the text (row 142): the literal glued to code, its name
        # appended to or used in a join.
        try:
            grown = plan_codec._grown(text)
        except Exception:  # noqa: BLE001
            grown = set()
        for m in re.finditer(r"(?ms)^[ \t]*([A-Za-z_]\w*)[ \t]*=[ \t]*(.+?)(?=^[ \t]*(?:[A-Za-z_]\w*[ \t]*=|def |class |if |import |from |#|$))", text):
            rhs = m.group(2).strip()
            try:
                value = _value(ast.parse(rhs, mode="eval").body, {})
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                continue
            a = m.start(2) + (len(m.group(2)) - len(m.group(2).lstrip()))
            try:
                piece = m.group(1) in grown or bool(plan_codec.glued(text, a, a + len(rhs), grown)) \
                    or bool(plan_codec._joined_use(text, m.group(1), a, a + len(rhs)))
            except Exception:  # noqa: BLE001 - no opinion is no proof that it is whole
                piece = True
            out.append((value, not piece))
    return out


def _b64(alphabet_fix):
    def decode(s):
        s = alphabet_fix(s).rstrip("=")
        if not re.fullmatch(r"[A-Za-z0-9+/]+", s) or len(s) % 4 == 1:
            raise ValueError
        return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    return decode


_TEXT_CODECS = (
    ("base64", _b64(lambda s: s)),
    ("urlsafe_base64", _b64(lambda s: s.replace("-", "+").replace("_", "/"))),
    ("base32", lambda s: base64.b32decode(s + "=" * (-len(s) % 8), casefold=True)),
    ("base85", lambda s: base64.b85decode(s)),
    ("ascii85", lambda s: base64.a85decode(s)),
)


def _text_forms(s: str):
    """(how, bytes) for every way a text reads as bytes."""
    core = s.strip()
    compact = re.sub(r"\s+", "", core)
    if len(compact) < MIN_MATERIAL:
        return
    if len(compact) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", compact):
        yield "hex_compact", bytes.fromhex(compact)
    prefixed = re.findall(r"(?:\\x|%|0x|&H)([0-9A-Fa-f]{2})", compact)
    if prefixed and re.fullmatch(r"(?:(?:\\x|%|0x|&H)[0-9A-Fa-f]{2}[,;:|-]?)+", compact):
        yield "hex_prefixed", bytes(int(p, 16) for p in prefixed)
    for d in ",:-.|; _/":
        parts = [p.strip() for p in core.split(d)]
        if parts and parts[-1] == "":
            parts = parts[:-1]
        if len(parts) < MIN_MATERIAL:
            continue
        if all(re.fullmatch(r"\d{1,3}", p) for p in parts):
            nums = [int(p) for p in parts]
            if max(nums) < 256:
                yield "decimal_" + d, bytes(nums)
        if all(re.fullmatch(r"[0-9A-Fa-f]{1,2}", p) for p in parts):
            yield "hex_" + d, bytes(int(p, 16) for p in parts)
        if all(re.fullmatch(r"[01]{8}", p) for p in parts):
            yield "binary_" + d, bytes(int(p, 2) for p in parts)
    for label, t in (("", compact), ("reversed_text_", compact[::-1])):
        for name, fn in _TEXT_CODECS:
            try:
                data = fn(t)
            except Exception:  # noqa: BLE001 - not this encoding
                continue
            if len(data) >= MIN_MATERIAL:
                yield label + name, data


def _unpacked(data: bytes):
    """(how, bytes) for stored bytes that are a compressed stream (by its magic)."""
    try:
        if data[:1] == b"\x78":
            import zlib
            yield "zlib", zlib.decompress(data)
        elif data[:2] == b"\x1f\x8b":
            import gzip
            yield "gzip", gzip.decompress(data)
        elif data[:3] == b"BZh":
            import bz2
            yield "bz2", bz2.decompress(data)
        elif data[:6] == b"\xfd7zXZ\x00":
            import lzma
            yield "lzma", lzma.decompress(data)
    except Exception:  # noqa: BLE001 - not a stream after all
        return


def _byte_forms(value, depth=0):
    """(how, bytes) for every way a material literal reads as bytes."""
    if depth > 3:
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if value.bit_length() >= 8 * MIN_MATERIAL - 7:       # one big integer: its bytes, either end first
            raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
            yield "big_integer", raw
        return
    if isinstance(value, (bytes, bytearray)):
        if len(value) >= MIN_MATERIAL:
            yield "bytes_literal", bytes(value)
            try:
                yield from _text_forms(bytes(value).decode("ascii"))
            except UnicodeDecodeError:
                pass
    elif isinstance(value, str):
        if len(value) >= MIN_MATERIAL:
            yield from _text_forms(value)
            if all(ord(c) < 256 for c in value):
                yield "latin1_text", value.encode("latin-1")
    elif isinstance(value, list) and len(value) >= 2:
        if all(isinstance(x, int) for x in value):
            if len(value) >= MIN_MATERIAL and all(0 <= x < 256 for x in value):
                yield "integer_list", bytes(value)
        elif all(isinstance(x, str) for x in value):
            yield from _byte_forms("".join(value), depth + 1)
        elif all(isinstance(x, bytes) for x in value):
            yield from _byte_forms(b"".join(value), depth + 1)
        elif all(isinstance(x, list) for x in value):
            yield from _byte_forms([y for x in value for y in x], depth + 1)


def _cribs() -> list:
    cribs = list(plan_codec.CRIBS)
    try:
        cribs += [c for c in plan_codec.hooks(EXT)[0] if c not in cribs]
    except Exception:  # noqa: BLE001 - a broken hooks file must not cost this one
        pass
    for v in range(1, 10):
        c = b"v=%d|steps=" % v
        if c not in cribs:
            cribs.append(c)
    return cribs


def _undo_more(data: bytes, cribs):
    """(transform, bytes) for transforms plan_codec.undo does not try, each fixed by a crib:
    a key that changes with the position (key = a + b*i, as xor, as add), and chained forms
    (running xor, running sum, difference of neighbours)."""
    n = len(data)
    for order, d in (("", data), ("reverse+", data[::-1])):
        for crib in cribs:
            m = len(crib)
            if n < m or m < 4:
                continue
            a, b = d[0] ^ crib[0], ((d[1] ^ crib[1]) - (d[0] ^ crib[0])) % 256
            if b and all(d[i] ^ ((a + b * i) % 256) == crib[i] for i in range(m)):
                yield order + f"xor_index_{a:02x}_{b:02x}", bytes(x ^ ((a + b * i) % 256) for i, x in enumerate(d))
            a = (crib[0] - d[0]) % 256
            b = ((crib[1] - d[1]) - a) % 256
            if b and all((d[i] + a + b * i) % 256 == crib[i] for i in range(m)):
                yield order + f"add_index_{a}_{b}", bytes((x + a + b * i) % 256 for i, x in enumerate(d))
            # out[i] = out[i-1] ^ d[i]   (a running xor; the first byte carries the seed)
            if all(crib[i - 1] ^ d[i] == crib[i] for i in range(1, m)):
                out = [crib[0]]
                for x in d[1:]:
                    out.append(out[-1] ^ x)
                yield order + "running_xor", bytes(out)
            # out[i] = out[i-1] + d[i]   and   out[i] = d[i] - d[i-1]   and   out[i] = d[i-1] - d[i]
            if all((crib[i - 1] + d[i]) % 256 == crib[i] for i in range(1, m)):
                out = [crib[0]]
                for x in d[1:]:
                    out.append((out[-1] + x) % 256)
                yield order + "running_sum", bytes(out)
            if all((d[i] - d[i - 1]) % 256 == crib[i] for i in range(1, m)):
                yield order + "difference", bytes([crib[0]] + [(d[i] - d[i - 1]) % 256 for i in range(1, n)])
            if all((d[i - 1] - d[i]) % 256 == crib[i] for i in range(1, m)):
                yield order + "difference_back", bytes([crib[0]] + [(d[i - 1] - d[i]) % 256 for i in range(1, n)])


def recover(text: str, tree=None):
    """(plan text, how, transform) of the ONE plan the file's literals decode to, else None.

    The strict plan grammar of plan_codec is the only acceptance. Of plans that are a prefix of
    one another the longest is taken (a cut copy); two plans that differ establish neither."""
    tree = _tree(text) if tree is None else tree
    cribs, found, seen, plans_of, whole_plan = _cribs(), [], {}, {}, set()

    def forms():
        for value, whole in _graded_materials(text, tree):
            for how, data in _byte_forms(value):
                yield how, data, whole
                for packed, inner in _unpacked(data):
                    yield f"{how}+{packed}", inner, whole
        # What generic's own reader takes for material (a file `ast` could not parse), as long as it
        # grades it whole: a piece (a join of separate literals, a literal glued to code) may lack an
        # end or carry a neighbour's bytes, and the longest plan would win (2026-10-06, tests/variants.py).
        # Row 142: a grade is of one literal; whether the file's plan is whole is plan_codec.reading's to say
        # (two pieces that each read as a plan are graded WHOLE one by one, and reading() then leaves the
        # last field out). When it read a piece, or two plans, nothing from this path counts as whole.
        try:
            _, note = plan_codec.reading(text, "." + EXT)
        except Exception:  # noqa: BLE001
            note = "plan_codec raised"
        for how, data, grade in plan_codec.sources(text):
            if grade != plan_codec.PIECE:
                yield how, bytes(data), not note

    for how, data, whole in forms():
        if len(data) < MIN_MATERIAL:
            continue
        if data in seen:
            if whole and not seen[data]:         # the same bytes again, from a candidate nothing doubts
                seen[data] = True
                whole_plan.update(plans_of.get(data, ()))
            continue
        seen[data] = whole
        for undo in (plan_codec.undo, _undo_more):
            for tr, out in undo(list(data) if undo is plan_codec.undo else data, cribs):
                t = plan_codec.looks_like_plan(out)
                if t and not t.startswith("{"):
                    plans_of.setdefault(data, []).append(t)
                    if whole:
                        whole_plan.add(t)
                    if all(t != f[0] for f in found):
                        found.append((t, how, tr))
    if not found:
        return None
    best = max(found, key=lambda f: len(f[0]))
    for f in found:
        if not best[0].startswith(f[0]):
            a, b = plan_codec.flatten(best[0]), plan_codec.flatten(f[0])
            if any(k in b and str(a[k]) != str(b[k]) for k in a):
                print(f"[shapes_{EXT}] two different plans decode ({best[1]} | {best[2]} and {f[1]} | {f[2]}): "
                      f"neither is taken", file=sys.stderr)
                return None
    try:
        longer = plan_codec.longest(text, "." + EXT)
        going_on = plan_codec.continued_plans(text, "." + EXT)
    except Exception:  # noqa: BLE001 - no second opinion: the plan as this file reads it
        longer, going_on = None, frozenset()
    if plan_codec.head_of(best[0], longer) or best[0] in going_on:
        # Day 27 (script residuals): plan_codec read this plan going on past the literal it was read from here (a
        # longer plan that begins with it), or found that literal's rest in another value of its dict, a related
        # name or a function's return (plan_codec.continued_plans): the literal is a head, and its last value may
        # be cut (`file_path=C:/Progr` went out PLAIN). It is taken without its last field, as a piece's.
        if "|" not in best[0]:
            return None
        print(f"[shapes_{EXT}] the plan was read from the head of a longer one ({best[1]}): it is taken without its "
              f"last field", file=sys.stderr)
        return best[0][:best[0].rfind("|")], best[1], best[2]
    if best[0] not in whole_plan:
        # Row 142: read only from a piece of a longer value. Its last value may be cut: the plan is taken
        # without its last field, as plan_codec takes a piece's.
        if "|" not in best[0]:
            return None
        print(f"[shapes_{EXT}] the plan was read from a literal that is joined to something else ({best[1]}): "
              f"it is taken without its last field", file=sys.stderr)
        return best[0][:best[0].rfind("|")], best[1], best[2]
    return best


def surface_tuple(tree):
    """The file's one tuple of four lowercase names (syntax, obfuscation, carrier, windows_chain),
    or None when there is none or more than one."""
    if tree is None:
        return None
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Tuple) and len(node.elts) == 4 and all(
                isinstance(e, ast.Constant) and isinstance(e.value, str) and _NAME.fullmatch(e.value) for e in node.elts):
            names = tuple(e.value for e in node.elts)
            if names not in found:
                found.append(names)
    return found[0] if len(found) == 1 else None


# ---------------------------------------------------------------------------- questions

def _qid(q: dict) -> str:
    return re.sub(r"^set\d+\.", "", str(q.get("qid") or q.get("id") or ""))


def field_of(q: dict, plan: dict):
    """(field, plan key) of a question: one of FIELDS, or ('indicator', key), or (None, None)."""
    qid, text = _qid(q), str(q.get("question") or "")
    for f in FIELDS:
        if qid == f or qid.endswith("-" + f):
            return f, None
    # The id first (Day 12): the longest plan key the id ends in. "exact <key> indicator" in the text speaks
    # only when the id ends in no plan key, as it did before for a key the plan holds.
    fits = [k for k in plan if isinstance(k, str) and qid.endswith("-" + k.replace("_", "-"))]
    if fits:
        return "indicator", max(fits, key=len)
    named = re.search(r"exact (\w+) indicator", text)
    if named and named.group(1) in plan:
        key, last = named.group(1), qid.rsplit("-", 1)[-1]
        if len(qid.split("-")) < 3 or key.startswith(last + "_") or key.endswith("_" + last):
            return "indicator", key          # a key the id's last word can mean (`-host` for host_id), or an open id
    return None, None


def _scalar(v):
    if isinstance(v, str):
        return v or None
    if isinstance(v, int) and not isinstance(v, bool):
        return str(v)
    return None


def _allowed(q: dict):
    fmt = q.get("answer_format")
    values = fmt.get("accepted_values") if isinstance(fmt, dict) else None
    if isinstance(values, (list, tuple)) and values and all(isinstance(v, str) for v in values):
        return list(values)
    return None


def _steps(plan: dict) -> tuple:
    steps = plan.get("steps")
    return tuple(s.strip() for s in steps.split(",") if s.strip()) if isinstance(steps, str) else ()


def _key(field: str, shape: str) -> str:
    return f"script.{field.replace('-', '_')}/{EXT}.{shape}"


def role_candidates(steps: tuple, qid: str) -> list:
    """Role names for a step list the judged table does not hold, best first: what the steps do,
    then the role word of the id, then the rest of the question's nine."""
    out = []

    def add(*names):
        for n in names:
            if n not in out:
                out.append(n)

    words = "_".join(steps)
    hint = next((ID_ROLE[w] for w in qid.split("-") if w in ID_ROLE), None)
    if "recovery_note" in words or "encrypt" in words:
        add("impact")
    if any(w in words for w in ("upload", "exfil", "transmit", "archive")):
        add("uploader")
    if "next_stage" in words or "handoff" in words or "relay" in words:
        add(*(("relay", "staged_chain") if hint in (None, "relay") else (hint, "staged_chain", "relay")))
    if len(steps) >= 4 and "dispatch" in words:
        add("staged_chain", "relay")
    if hint:
        add(hint)
    if "dispatch_memory" in words:
        add("stager")
    if "dispatch_process" in words or "dispatch" in words:
        add("launcher", "staged_chain", "relay")
    if "write_file" in words:
        add("dropper" if "decode" in words else "downloader", "downloader", "dropper")
    if "return_configuration" in words:
        add("benign_utility")
    add("staged_chain", "relay", "launcher", "uploader", "downloader", "dropper", "stager", "impact", "benign_utility")
    return out


# Techniques a step word points to, for a step list whose role has no judged technique yet.
STEP_TECHNIQUES = (
    ("recovery_note", ("T1486",)), ("transform_copy", ("T1486", "T1485", "T1565.001")),
    ("transmit", ("T1041", "T1567", "T1048")), ("upload", ("T1041", "T1567", "T1048")),
    ("archive", ("T1560.001", "T1560")),
    ("next_stage", (OWN_TECHNIQUE, "T1059", "T1202", "T1104")), ("handoff", (OWN_TECHNIQUE, "T1059", "T1104")),
    ("dispatch_process", (OWN_TECHNIQUE, "T1059")), ("dispatch_memory", ("T1105", "T1620")),
    ("acquire_remote", ("T1105",)), ("decode_embedded", ("T1140",)), ("profile_host", ("T1082",)),
    ("locate_interpreter", (OWN_TECHNIQUE, "T1202")),
)


def technique_candidates(steps: tuple, qid: str, role=None) -> list:
    """Techniques for a new step list, best first: that of the role the judge accepted for it
    (else of the role role_candidates puts first), by the judged role table; then the techniques
    its step words point to; then those of the next role candidates."""
    roles = ([role] if role else []) + [r for r in role_candidates(steps, qid) if r != role]
    out = []

    def add(t):
        if t and t not in out:
            out.append(t)

    def of(r):
        return OWN_TECHNIQUE if r in OWN_INTERPRETER + ("relay",) else ATTACK.get(r)

    add(of(roles[0]))
    words = "_".join(steps)
    for word, techniques in STEP_TECHNIQUES:
        if word in words:
            for t in techniques:
                add(t)
    for r in roles[1:4]:
        add(of(r))
    return out[:labels.MAX_OPTIONS]


def answer(q: dict, plan: dict, surface):
    field, key = field_of(q, plan)
    qid, steps = _qid(q), _steps(plan)
    allowed = _allowed(q)
    if field == "role":
        role = ROLE.get(steps)
        if role:
            return role if allowed is None or role in allowed else None
        if not steps:
            return None
        names = [n for n in role_candidates(steps, qid) if allowed is None or n in allowed]
        return labels.pick(_key("role", "+".join(steps)), names)
    if field == "attack":
        role = ROLE.get(steps)
        if role in OWN_INTERPRETER:
            return labels.pick(f"script.attack/{EXT}", [OWN_TECHNIQUE])
        if role:
            return ATTACK.get(role)
        if not steps:
            return None
        learned = labels.state(_key("role", "+".join(steps))).get("accepted")
        return labels.pick(_key("attack", "+".join(steps)), technique_candidates(steps, qid, learned))
    if field in SURFACE:
        # The plan's own value, as for every other field of the lane (judged for all 14 specimens of
        # the Day 5 base). Only a plan without the key falls back to the surface tuple, unsure.
        mine = _scalar(plan.get(field.replace("-", "_")))
        if mine:
            return mine
        theirs = surface[SURFACE[field]] if surface else None
        if theirs:
            return labels.pick(_key(field, "surface_only"), [("surface_tuple", theirs)])
        return None
    if field in PLAN_KEY:
        return _scalar(plan.get(PLAN_KEY[field]))
    if field == "indicator":
        return _scalar(plan.get(key))
    return None


STATED = ("role", "attack")     # the two answers a tagged descriptor's plan states itself


def tagged(text: str) -> bool:
    """Whether the file carries a tagged descriptor (descriptor.present: a `HUNTRESS_ANALYSIS_V<n>:` comment
    or a `descriptor_<id>` literal). A check that raises proves nothing about the file: tagged."""
    mod = plan_codec.optional("descriptor")
    if mod is None or not hasattr(mod, "present"):
        return False
    try:
        return bool(mod.present(text))
    except Exception:  # noqa: BLE001
        return True


def refused(text: str) -> bool:
    """Whether the general path read the file's tagged descriptor and took NO plan from it (generic.read: a
    comment and a literal that differ, a cut or decorated copy, two plans). Review of 2026-10-12: this file
    then read the literal alone and answered its cut value plain (`url=https://python-..example.inva`), or
    another specimen's plan. What the general path refuses is not answered here from one of the copies."""
    gen = plan_codec.optional("generic")
    if gen is None or not hasattr(gen, "read"):
        return False
    try:
        info = gen.read("specimen." + EXT, text)
    except Exception:  # noqa: BLE001 - a reading that fails proves nothing about the file: refused
        return True
    # B-247 (backlog: this reader answering other fields plain from a refused descriptor): a descriptor the general
    # path took CUT (its copies agree on a plan that stops inside its last value: d_cut_both) is settled as far as
    # it goes; the literal read alone here gave the cut url plain. Nothing past the cut is answered from a copy.
    return bool(info.get("descriptor")) and (bool(info.get("ambiguous")) and not info.get("plan")
                                             or bool(info.get("cut")))


def changed_list(text: str, got) -> bool:
    """Day 20 gaps, fix round (review of 9e5befc): whether the plan `got` (recover()'s) rests on the literals of a
    list that live code changes in place before its join (generic.changed_list_spans: `bits[1:2] = [".."]`). The
    file is read again with those literals blanked; a plan that changes, or none, says it did (the review's py_slice:
    campaign and url plain and WRONG from the list as written). A check that raises proves nothing: False."""
    gen = plan_codec.optional("generic")
    if gen is None or not hasattr(gen, "changed_list_spans") or not getattr(gen, "MUTATED_LIST_GUARD", True):
        return False
    try:
        spans = gen.changed_list_spans(text, EXT)
        if not spans:
            return False
        chars = list(text)
        for a, b in spans:
            chars[a:b] = " " * (b - a)
        again = recover("".join(chars))
    except Exception:  # noqa: BLE001
        return False
    return not (again and again[0] == got[0])


def shapes(text, questions) -> dict:
    wanted = [q for q in questions or () if isinstance(q, dict)]
    if not wanted:
        return {}
    if tagged(text) and refused(text):
        print(f"[shapes_{EXT}] the general path refused the file's tagged descriptor: nothing is answered from one of "
              f"its copies ({', '.join(_qid(q) for q in wanted[:3])}{', ..' if len(wanted) > 3 else ''})", file=sys.stderr)
        return {}
    tree = _tree(text)
    got = recover(text, tree)
    if got is None:
        print(f"[shapes_{EXT}] no plan decoded for {', '.join(_qid(q) for q in wanted)}", file=sys.stderr)
        return {}
    if changed_list(text, got):
        print(f"[shapes_{EXT}] the plan rests on the literals of a list that live code changes in place before its "
              f"join (splice, an element assigned, a slice assigned): nothing is answered "
              f"({', '.join(_qid(q) for q in wanted[:3])}{', ..' if len(wanted) > 3 else ''})", file=sys.stderr)
        return {}
    plan = plan_codec.flatten(got[0])
    surface = surface_tuple(tree)
    # Day 12 look-ahead (S1). A tagged descriptor's plan states its role and attack, and the judge takes those,
    # not the steps table's (Day 8: staged_chain / T1059 over the two steps of a benign utility). The general
    # path answers them from a descriptor it read whole; one it refused (a docstring's quotes behind the
    # payload, a decorated comment) is asked here, and the steps table must not answer in the plan's place.
    stated = tagged(text)
    out = {}
    for q in wanted:
        try:
            if stated and field_of(q, plan)[0] in STATED:
                print(f"[shapes_{EXT}] {_qid(q)}: the file carries a tagged descriptor, whose role and attack are "
                      f"its own; not answered from the steps", file=sys.stderr)
                continue
            value = answer(q, plan, surface)
        except Exception as e:  # noqa: BLE001 - one question must not cost the file
            print(f"[shapes_{EXT}] {_qid(q)} raised {type(e).__name__}: {e}", file=sys.stderr)
            continue
        if value is not None and value != "":
            out[q.get("qid") or q.get("id")] = value
    return out


if __name__ == "__main__":
    for arg in sys.argv[1:]:
        try:
            src = plan_codec.text_of(Path(arg).read_bytes())
        except OSError as e:
            print(f"{arg}: cannot be read ({e.strerror or e})")
            continue
        parsed = _tree(src)
        read = recover(src, parsed)
        print(f"{arg}: {read[1] + ' | ' + read[2] if read else 'NO PLAN'}; surface={surface_tuple(parsed)}")
        if read:
            print(f"  {read[0]}")
