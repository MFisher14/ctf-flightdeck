"""POSIX shell word concatenation, read as data (B-232, Huntress Day 6).

In a shell script `M='ab'"cd"ef$'\\x67'` assigns ONE word, `abcdefg`: touching quoted and bare pieces
concatenate. Day 6's reader graded touching quoted words as separate pieces and dropped the last field.
This module reads such a word without running anything:

    word(text, i=0)       -> (value | None, end)   one word starting at text[i]
    words(text)           -> [value | None, ...]   the words of one command line
    assignment(text)      -> (name, value | None) | None   `NAME=word` at the start of a line

A piece is '...' (literal), "..." (backslash escapes only \\$ \\` \\" \\\\ and newline), $'...' (ANSI-C
escapes: \\n \\t \\r \\a \\b \\e \\f \\v \\\\ \\' \\" \\? \\xHH \\NNN octal \\uHHHH \\UHHHHHHHH), $"..." (read
like "..."), or bare text (a backslash quotes the next character). A word whose value depends on the
shell (an unquoted or double-quoted `$name`, `${...}`, `$(...)`, a backtick) has no literal value:
its value is None, and `end` still moves past it. A quote that never closes raises ShellWordError.
"""
from __future__ import annotations

import re

__all__ = ["ShellWordError", "word", "words", "assignment"]

_META = set(" \t\n;&|<>()")
_ANSI = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f",
         "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class ShellWordError(ValueError):
    """A word the reader cannot delimit (an unterminated quote); the message names where."""


def _close(text: str, i: int, quote: str, what: str) -> int:
    j = text.find(quote, i)
    if j < 0:
        raise ShellWordError(f"{what} opened at offset {i - 1} never closes")
    return j


def _ansi(text: str, i: int) -> tuple[str, int]:
    """The value of $'...' whose body starts at text[i]; (value, index after the closing quote)."""
    out = []
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "'":
            return "".join(out), i + 1
        if ch != "\\" or i + 1 >= n:
            out.append(ch)
            i += 1
            continue
        e = text[i + 1]
        if e in _ANSI:
            out.append(_ANSI[e])
            i += 2
        elif e == "x":
            m = re.match(r"[0-9A-Fa-f]{1,2}", text[i + 2:])
            if m:
                out.append(chr(int(m.group(), 16)))
                i += 2 + len(m.group())
            else:
                out.append("\\x")
                i += 2
        elif e in "uU":
            m = re.match(r"[0-9A-Fa-f]{1,%d}" % (4 if e == "u" else 8), text[i + 2:])
            if m:
                out.append(chr(int(m.group(), 16)))
                i += 2 + len(m.group())
            else:
                out.append("\\" + e)
                i += 2
        elif e in "01234567":
            m = re.match(r"[0-7]{1,3}", text[i + 1:])
            out.append(chr(int(m.group(), 8) & 0xFF))
            i += 1 + len(m.group())
        else:
            out.append("\\" + e)
            i += 2
    raise ShellWordError("$'...' never closes")


def _double(text: str, i: int) -> tuple[str | None, int]:
    """The value of "..." whose body starts at text[i]; None when it expands something."""
    out, literal = [], True
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            return ("".join(out) if literal else None), i + 1
        if ch == "\\" and i + 1 < n:
            e = text[i + 1]
            if e in '$`"\\':
                out.append(e)
            elif e == "\n":
                pass
            else:
                out.append("\\" + e)
            i += 2
            continue
        if ch in "$`":
            literal = False
        out.append(ch)
        i += 1
    raise ShellWordError('"..." never closes')


def word(text: str, i: int = 0) -> tuple[str | None, int]:
    """The word starting at text[i] (leading blanks skipped): (its literal value or None, end index)."""
    n = len(text)
    while i < n and text[i] in " \t":
        i += 1
    out, literal, start = [], True, i
    while i < n and text[i] not in _META:
        ch = text[i]
        if ch == "'":
            j = _close(text, i + 1, "'", "'...'")
            out.append(text[i + 1:j])
            i = j + 1
        elif ch == '"':
            v, i = _double(text, i + 1)
            if v is None:
                literal = False
            else:
                out.append(v)
        elif ch == "$" and text[i + 1:i + 2] == "'":
            v, i = _ansi(text, i + 2)
            out.append(v)
        elif ch == "$" and text[i + 1:i + 2] == '"':
            v, i = _double(text, i + 2)
            if v is None:
                literal = False
            else:
                out.append(v)
        elif ch == "\\" and i + 1 < n:
            if text[i + 1] != "\n":
                out.append(text[i + 1])
            i += 2
        elif ch in "$`":
            literal = False
            i = _skip_expansion(text, i)
        else:
            out.append(ch)
            i += 1
    if i == start:
        return None, i
    return ("".join(out) if literal else None), i


def _skip_expansion(text: str, i: int) -> int:
    """The index after a `$name`, `${...}`, `$(...)` or backtick expansion at text[i] (nesting counted)."""
    n = len(text)
    if text[i] == "`":
        return _close(text, i + 1, "`", "`...`") + 1
    if i + 1 < n and text[i + 1] in "{(":
        open_, close = text[i + 1], "}" if text[i + 1] == "{" else ")"
        depth, j = 1, i + 2
        while j < n and depth:
            if text[j] == open_:
                depth += 1
            elif text[j] == close:
                depth -= 1
            j += 1
        if depth:
            raise ShellWordError(f"${open_}...{close} opened at offset {i} never closes")
        return j
    m = _NAME.match(text, i + 1)
    if m:
        return m.end()
    return i + 2 if i + 1 < n else i + 1


def words(text: str) -> list[str | None]:
    """The words of one command line, up to the first unquoted `;`, `&`, `|` or newline."""
    out, i, n = [], 0, len(text)
    while i < n:
        while i < n and text[i] in " \t":
            i += 1
        if i >= n or text[i] in ";&|\n":
            break
        if text[i] in "<>()":
            i += 1
            continue
        v, i = word(text, i)
        out.append(v)
    return out


def assignment(text: str) -> tuple[str, str | None] | None:
    """(name, value) for a line that starts with `NAME=word` (`export` / `readonly` / `local` / `declare`
    before it are skipped), or None when it does not."""
    s = text.lstrip()
    m = re.match(r"(?:(?:export|readonly|local|declare(?:\s+-\w+)*)\s+)?([A-Za-z_][A-Za-z0-9_]*)=", s)
    if not m:
        return None
    if m.end() >= len(s) or s[m.end()] in " \t\n;":
        return m.group(1), ""
    v, _ = word(s, m.end())
    return m.group(1), v
