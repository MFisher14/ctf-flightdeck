#!/usr/bin/env python3
"""Fail-closed JSON parsing for response fields that authorize live actions.

Ordinary ``json.loads`` uses last-wins semantics for duplicate object members.
That is useful for generic inventory but unsafe for ``ok``, ``errors``,
``effect`` and contract fields: a target can make different parsers see
different policy.  This module rejects exact duplicates and the punctuation /
case / camelCase collisions used by the web policy readers, at every nesting
level.  It performs no I/O and constructs only ordinary JSON values.
"""

from __future__ import annotations

import json
import math
import re


DEFAULT_MAX_CHARS = 400_000
DEFAULT_MAX_MEMBERS = 20_000
DEFAULT_MAX_NODES = 40_000
DEFAULT_MAX_DEPTH = 64
DEFAULT_MAX_NUMBER_CHARS = 256


class AmbiguousJSON(ValueError):
    """A policy-bearing document has duplicate/colliding keys or exceeds caps."""


def parse_int_lexeme(raw: str, *, max_chars=DEFAULT_MAX_NUMBER_CHARS) -> int:
    """Convert one already-validated JSON/YAML integer with a CPU bound.

    Python 3.9 has no interpreter-wide maximum for decimal-to-integer
    conversion, whose cost becomes super-linear for attacker-sized lexemes.
    Check the token before calling :class:`int` so a document byte cap cannot
    turn into a multi-second parse inside a solver.
    """
    if not isinstance(raw, str) or len(raw) > max_chars:
        raise AmbiguousJSON("JSON number character limit")
    return int(raw, 10)


def parse_float_lexeme(raw: str, *, max_chars=DEFAULT_MAX_NUMBER_CHARS) -> float:
    """Convert a bounded finite JSON floating-point token."""
    if not isinstance(raw, str) or len(raw) > max_chars:
        raise AmbiguousJSON("JSON number character limit")
    value = float(raw)
    if not math.isfinite(value):
        raise AmbiguousJSON("non-finite JSON number")
    return value


def canonical_key(value) -> str:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value or "")[:1024])
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def loads(text, *, max_chars=DEFAULT_MAX_CHARS, max_members=DEFAULT_MAX_MEMBERS,
          max_nodes=DEFAULT_MAX_NODES, max_depth=DEFAULT_MAX_DEPTH):
    """Parse bounded JSON, rejecting policy-ambiguous object members.

    Raises ``ValueError``/``AmbiguousJSON`` for malformed, non-finite,
    duplicate, colliding or over-limit input.  Callers decide the required
    top-level type.
    """
    if not isinstance(text, str) or not isinstance(max_chars, int) or max_chars <= 0:
        raise ValueError("JSON text/cap is invalid")
    if len(text) > max_chars:
        raise AmbiguousJSON("JSON character limit")
    member_count = [0]

    def pairs_hook(pairs):
        member_count[0] += len(pairs)
        if member_count[0] > max_members:
            raise AmbiguousJSON("JSON member limit")
        out = {}
        seen = set()
        for key, value in pairs:
            canonical = canonical_key(key)
            if canonical in seen:
                raise AmbiguousJSON("duplicate or canonically colliding JSON member")
            seen.add(canonical)
            out[key] = value
        return out

    value = json.loads(
        text, object_pairs_hook=pairs_hook,
        parse_int=parse_int_lexeme,
        parse_float=parse_float_lexeme,
        parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)),
    )
    stack = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes or depth > max_depth:
            raise AmbiguousJSON("JSON structure limit")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return value


def loads_unique(texts, *, max_chars=DEFAULT_MAX_CHARS,
                 max_members=DEFAULT_MAX_MEMBERS, max_nodes=DEFAULT_MAX_NODES,
                 max_depth=DEFAULT_MAX_DEPTH):
    """Return the one structural JSON document among coherent sibling views.

    MIME parts and archive members are independent messages.  Callers must not
    concatenate them or silently choose the first/last policy document.  Plain
    non-JSON siblings may coexist with one JSON document, but a second JSON
    object/array or a malformed JSON-looking sibling makes the response
    ambiguous and therefore unusable for authorization or proof decisions.
    """
    if isinstance(texts, str):
        texts = [texts]
    documents = []
    try:
        iterator = iter(texts)
    except Exception as exc:
        raise AmbiguousJSON("JSON views unavailable") from exc
    for index, raw in enumerate(iterator):
        if index >= 256:
            raise AmbiguousJSON("JSON view limit")
        if not isinstance(raw, str):
            continue
        text = raw.strip()
        if not text or text[:1] not in ("{", "["):
            continue
        try:
            value = loads(text, max_chars=max_chars, max_members=max_members,
                          max_nodes=max_nodes, max_depth=max_depth)
        except Exception as exc:
            raise AmbiguousJSON("malformed JSON sibling") from exc
        if not isinstance(value, (dict, list)):
            raise AmbiguousJSON("non-structural JSON sibling")
        documents.append(value)
        if len(documents) > 1:
            raise AmbiguousJSON("multiple structural JSON siblings")
    if len(documents) != 1:
        raise AmbiguousJSON("no unique structural JSON document")
    return documents[0]


__all__ = [
    "AmbiguousJSON", "DEFAULT_MAX_NUMBER_CHARS", "canonical_key", "loads",
    "loads_unique", "parse_float_lexeme", "parse_int_lexeme",
]
