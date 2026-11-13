"""Narrow whole-literal witnesses for descriptor plans in functional hosts.

The general codec reader deliberately treats an encoded-looking quoted value as a
piece unless it knows the host grammar that terminates the value.  Day 27's
look-ahead added several function-return hosts after that reader was written.  A
tagged comment in those hosts was therefore treated as the descriptor's only
copy, and a literal by itself lost its final field.

This module does not search arbitrary strings.  It accepts only the complete,
line-terminated declarations below, inside the small inert file skeleton that
identifies their host.  The payload must decode to exactly one complete plan and
all accepted declarations in the file must give that same plan.  It returns no
answers; ``generic.read`` uses the result only to decide that the codec reader's
already-established plan did not come from a piece.
"""

from __future__ import annotations

import re


MIN_PAYLOAD = 24
_PAYLOAD = rf'(?P<p>[^"\r\n]{{{MIN_PAYLOAD},}})'


def _rx(expr: str, flags: int = 0):
    return re.compile(expr, re.MULTILINE | flags)


# (extension(s), required file-shape witnesses, complete literal declaration).
# The witnesses make a declaration copied into prose, a block comment, or an
# unrelated source file ineligible.  They are intentionally the exact inert host
# families exercised by the cumulative lane's look-ahead.
_FORMS = (
    ({"btm", "bat", "cmd"}, (r"(?im)^@echo off[ \t]*$", r"(?im)^exit /b 0[ \t]*$"),
     _rx(rf'^[ \t]*set[ \t]+"(?:descriptor|Material)_[A-Za-z0-9_]+={_PAYLOAD}"[ \t]*$', re.IGNORECASE)),
    ({"escript"}, (r"(?m)^-module\((?:plan_[A-Za-z0-9_]+|fixture)\)\.[ \t]*$",),
     _rx(rf'^[ \t]*(?:(?:descriptor|material)_[A-Za-z0-9_]+|build_plan)\(\)[ \t]*->[ \t]*"{_PAYLOAD}"\.[ \t]*$')),
    ({"lfe"}, (r"(?m)^\(defmodule[ \t]+plan_[A-Za-z0-9_]+$", r"(?m)^  \(export \(build-plan 0\)\)\)[ \t]*$"),
     _rx(rf'^[ \t]*\(defun[ \t]+build-plan[ \t]+\(\)[ \t]+"{_PAYLOAD}"\)[ \t]*$')),
    ({"hs"}, (r"(?m)^module Main where[ \t]*$", r"(?m)^buildPlan :: String[ \t]*$",
              r"(?m)^main = putStrLn buildPlan[ \t]*$"),
     _rx(rf'^[ \t]*buildPlan[ \t]*=[ \t]*"{_PAYLOAD}"[ \t]*$')),
    ({"cr"}, (r"(?m)^puts build_plan[ \t]*$",),
     _rx(rf'^[ \t]*def build_plan;[ \t]*"{_PAYLOAD}";[ \t]*end[ \t]*$')),
    ({"clj"}, (r"(?m)^\(ns plan-[A-Za-z0-9_]+\)[ \t]*$", r"(?m)^\(println \(build-plan\)\)[ \t]*$"),
     _rx(rf'^[ \t]*\(defn[ \t]+build-plan[ \t]+\[\][ \t]+"{_PAYLOAD}"\)[ \t]*$')),
    ({"fsx"}, (r'(?m)^printfn "%s" \(buildPlan \(\)\)[ \t]*$',),
     _rx(rf'^[ \t]*let[ \t]+buildPlan[ \t]+\(\)[ \t]*=[ \t]*"{_PAYLOAD}"[ \t]*$')),
    ({"gleam"}, (r"(?m)^import gleam/io[ \t]*$", r"(?m)^pub fn main\(\) \{ io\.println\(build_plan\(\)\) \}[ \t]*$"),
     _rx(rf'^[ \t]*pub fn build_plan\(\)[ \t]*->[ \t]*String[ \t]*\{{[ \t]*"{_PAYLOAD}"[ \t]*\}}[ \t]*$')),
)


def _complete(payload: str, descriptor):
    """The unique complete plan represented by *payload*, or ``None``."""
    try:
        got = descriptor.decode(None, payload)
    except Exception:  # a decoder failure proves nothing
        return None
    plans = {row[0]: row[1] for row in got if isinstance(row, tuple) and len(row) >= 2}
    if len(plans) != 1:
        return None
    plan, how = next(iter(plans.items()))
    try:
        flat = descriptor.plan_codec.flatten(plan)
        if descriptor.checked(flat, short_ok=False):
            return None
    except Exception:
        return None
    return plan, how


def reading(text: str, ext: str, descriptor):
    """Return ``(plan_text, how, literal_count)`` for an exact whole host.

    Different readable declarations refuse the file.  Repeated declarations of
    the same payload are harmless, but a host skeleton normally has one.
    """
    if not isinstance(text, str) or not isinstance(ext, str) or descriptor is None:
        return None
    word = ext.lower().lstrip(".")
    candidates = []
    for exts, witnesses, literal in _FORMS:
        if word not in exts or not all(re.search(w, text) for w in witnesses):
            continue
        # These exact skeletons do not use multi-line block comments.  Refuse
        # one rather than mistake an example inside it for the live declaration.
        if any(mark in text for mark in ("/*", "{-", "#|", "=begin")):
            return None
        candidates.extend(m.group("p") for m in literal.finditer(text))
    # Clojure's look-ahead block is a single literal with physical newlines,
    # followed by an exact replacement of newline with empty text.
    if word == "clj" and re.search(r"(?m)^\(ns huntress\.fixture\)[ \t]*$", text) \
            and re.search(r"(?m)^\(println \(count Material_[A-Za-z0-9_]+\)\)[ \t]*$", text) \
            and not any(mark in text for mark in ("#|", "#_")):
        rows = re.findall(
            r'(?ms)^\(def Material_[A-Za-z0-9_]+ \(clojure\.string/replace "([A-Za-z0-9+/=\r\n]{24,})" '
            r'"\\n" ""\)\)[ \t]*$', text)
        if len(rows) == 1:
            candidates.append(rows[0].replace("\r", "").replace("\n", ""))
        elif rows:
            return None
    # AWK concatenates adjacent expression operands. Accept only the exact
    # two-variable inert fixture, with each variable assigned once.
    if word == "awk" and text.startswith("#!/usr/bin/awk -f\n") \
            and re.search(r"(?m)^[ \t]*print length\(Material_[A-Za-z0-9_]+\)[ \t]*$", text):
        p0 = re.findall(r'(?m)^part0[ \t]*=[ \t]*"([^"\r\n]{24,})"[ \t]*$', text)
        p1 = re.findall(r'(?m)^part1[ \t]*=[ \t]*"([^"\r\n]+)"[ \t]*$', text)
        use = re.findall(r'(?m)^Material_[A-Za-z0-9_]+[ \t]*=[ \t]*part0[ \t]+part1[ \t]*$', text)
        if len(p0) == len(p1) == len(use) == 1:
            candidates.append(p0[0] + p1[0])
        elif p0 or p1 or use:
            return None
    if not candidates:
        return None
    decoded = [_complete(payload, descriptor) for payload in candidates]
    if any(row is None for row in decoded):
        return None
    plans = {row[0] for row in decoded}
    if len(plans) != 1:
        return None
    plan = next(iter(plans))
    how = next(row[1] for row in decoded if row[0] == plan)
    return plan, how, len(candidates)
