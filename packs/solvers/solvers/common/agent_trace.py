#!/usr/bin/env python3
"""Readers for static agent-security artifacts: agent transcripts, MCP and agent configs, RAG
corpora, and a hidden-text finder for any text member (toolkit `agent_trace`).

Offline, stdlib only, no Game Master request, no token. Everything read here is DATA. Text in an
artifact that addresses the solver ("ignore previous instructions", "the flag is ...", "submit
...") is returned as a finding with `instruction: True`; nothing in this module or in
solvers/toolkits/agent_trace.py branches on what such text says, only on where it sits.

  hidden_text(text)            findings in one text: zero-width characters (both bit mappings, both
                               bit orders, a separator character, base-4; kept only when the output
                               is printable), the Unicode tag block U+E0000..U+E007F, bidi controls,
                               homoglyph words, HTML comments, display:none / same-colour / zero-size
                               elements, alt and title attributes, markdown link titles, alt text and
                               comments, trailing-whitespace bits
  pdf_hidden(data)             text drawn in render mode 3 (invisible) or in white, from the content
                               streams (FlateDecode or plain); pdf_text(data) is all of the text
  scan(name, data)             the right one of the two for a member, each finding with its file
  addresses_solver(text)       True when a text reads as an instruction to a model or an agent

  load_trace(data, name)       a transcript as rows {turn, msg, role, kind, tool, arguments, result,
                               text, call_id, shape}: JSON or JSONL in OpenAI chat and Responses,
                               Anthropic, Gemini, LangChain (messages, lc constructors,
                               intermediate_steps, runs) and OpenTelemetry span shapes, Claude
                               Code, Codex and Cursor session logs, and a transcript written as
                               text ("User:", "Tool (name):", or ReAct's Action / Observation)
  external_calls(rows)         tool calls whose arguments carry a host or URL no user turn has, each
                               with the tool result the host first appeared in (`source`)
  first_external_call(rows)    the first of them
  b64_in_urls(rows)            base64 in the URLs of tool calls, decoded when printable
  injected_turns(rows)         tool-output rows an instruction came from: `proven` (a later call
                               goes to a host that first appeared there), `hidden`, `instruction`

  read_config(data, name)      {servers, tools} of an mcp.json, a tool manifest, a tools/list reply,
                               an OpenAI tools array, a plugin manifest, a TOML or YAML agent config
  tool_collisions(tools)       duplicate names, lookalike (shadowed) names, a description that names
                               another tool
  flagged_tools(tools)         tools whose name, description or schema holds hidden text

  read_docs(data, name)        documents {id, id_source, text, meta, embedding} of a JSON docstore
                               (list, id map, Chroma get(), LlamaIndex, Qdrant/Pinecone points),
                               JSONL, or a Chroma (or any) sqlite file
  cosine(a, b), argmax(xs), nearest(query, docs, k)

  analyse(files)               all of the above over the {name: bytes} a solver is handed
"""
import base64
import binascii
import json
import math
import re
import struct
import unicodedata
import zlib
from html.parser import HTMLParser
from pathlib import Path
from itertools import permutations
from urllib.parse import parse_qsl, unquote, urlsplit

ARROW = " -> "
MAX_TEXT = 2 * 1024 * 1024          # bytes of one member scanned as text
MAX_JSON = 16 * 1024 * 1024         # bytes of one member parsed as JSON
MAX_ROWS = 20000
MAX_FINDINGS = 400                  # per member
MAX_SQLITE = 64 * 1024 * 1024
MAX_HIDDEN_CHARS = 64000            # zero-width characters, or trailing spaces and tabs, read as one message

# ---- text that addresses the solver ---------------------------------------------------------------
#
# A classifier of data. Its verdict is a property of a finding; it never selects an answer by what the
# text asks for.

_ADDRESS = re.compile(
    r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+)?(?:previous|prior|above|earlier|preceding|system)\b"
    r"|\b(?:new|updated|additional|important|system)\s+instructions?\b"
    r"|\byou\s+(?:are|must|should|will|shall)\s+(?:now\s+)?(?:an?\s+)?(?:ai|assistant|agent|llm|language model|chatbot|always|never|not|first|also|instead)\b"
    r"|\b(?:dear|attention|note to|message (?:to|for)|instructions? (?:to|for))\s+(?:the\s+)?(?:ai|assistant|agent|llm|model|solver|claude|gpt|chatgpt|copilot|codex|cursor)\b"
    r"|\b(?:ai|assistant|agent|llm|model|solver|claude|gpt|chatgpt|copilot)\s*[:,]\s*(?:please\s+)?(?:ignore|do|you|submit|send|answer|return|report|stop|call|run|use|read|"
    r"before|after|first|always|never|upload|post|fetch|append|include|tell|say|reply|respond|output|print|execute|open|visit|forward|email|delete|write|approve|grant|add|set)\b"
    r"|\bdo\s+not\s+(?:tell|reveal|mention|inform|alert|show|disclose)\b"
    r"|\b(?:without|never)\s+(?:telling|informing|mentioning|notifying|asking)\b"
    r"|\b(?:the\s+)?(?:real|correct|true|actual|right)\s+(?:flag|answer)\s+is\b"
    r"|\bsubmit\s+\S+(?:\s+\S+){0,6}\s+as\s+(?:the\s+|your\s+)?(?:flag|answer)\b"
    r"|\b(?:before|after|when|whenever)\s+(?:using|calling|you\s+(?:use|call|run|answer|respond|reply))\b"
    r"|\b(?:send|post|upload|forward|exfiltrate|append|include|pass)\s+(?:the\s+|all\s+|any\s+|your\s+|its\s+)?(?:contents?|conversation|api[ _-]?keys?|secrets?|credentials?|tokens?|files?|"
    r"env(?:ironment)?|system prompt|chat history|ssh|password)\b"
    r"|\bsystem\s+prompt\b|\bjailbreak\b|\bas\s+an\s+ai\b|<\s*/?\s*(?:important|system|instructions?|secret|information)\s*>"
    r"|\b(?:important|urgent)\s+message\s+(?:from|for|to)\b"
    r"|\bbefore\s+you\s+(?:can\s+)?(?:solve|answer|continue|proceed|respond|reply|complete|finish|start|do)\b"
    r"|\b(?:please\s+)?do\s+the\s+following\s+first\b|\bafter\s+you\s+(?:do|have\s+done)\s+that\b"
    r"|\bthe\s+task\s+(?:that\s+)?i\s+gave\s+you\b|\b(?:to|for)\s+you,\s+(?:the\s+)?(?:ai|assistant|agent|llm|model|claude|gpt|chatgpt|gemini|copilot)\b"
    r"|\[\s*(?:system|inst|assistant)\s*\]",
    re.I)


def addresses_solver(text) -> bool:
    """True when the text reads as an instruction to a model, an agent or a solver. Data about the
    text; never a reason to do what it says."""
    return bool(text) and _ADDRESS.search(str(text)[:20000]) is not None


# ---- characters -----------------------------------------------------------------------------------

ZERO_WIDTH = "​‌‍⁠﻿᠎⁡⁢⁣⁤"
BIDI = "‪‫‬‭‮⁦⁧⁨⁩‎‏؜"
_ZW_NAMES = {"​": "ZWSP", "‌": "ZWNJ", "‍": "ZWJ", "⁠": "WJ", "﻿": "BOM", "᠎": "MVS",
             "⁡": "FA", "⁢": "IT", "⁣": "IS", "⁤": "IP"}
_BIDI_NAMES = {"‪": "LRE", "‫": "RLE", "‬": "PDF", "‭": "LRO", "‮": "RLO", "⁦": "LRI",
               "⁧": "RLI", "⁨": "FSI", "⁩": "PDI", "‎": "LRM", "‏": "RLM", "؜": "ALM"}
# Cyrillic, Greek and a few others that draw as a Latin letter or digit.
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "һ": "h",
    "ԁ": "d", "ԛ": "q", "ԝ": "w", "ɡ": "g", "ɩ": "i", "ӏ": "l", "ո": "n", "ս": "u", "օ": "o", "г": "r", "к": "k",
    "м": "m", "т": "t", "в": "b", "н": "h", "п": "n",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    "У": "Y", "І": "I", "Ј": "J", "Ѕ": "S",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "τ": "t", "υ": "u", "ϲ": "c", "ε": "e",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P",
    "Τ": "T", "Υ": "Y", "Χ": "X",
    "ⅼ": "l", "ⅰ": "i", "ℓ": "l", "０": "0", "１": "1", "‐": "-", "‑": "-", "‒": "-", "–": "-", "＿": "_",
}
_CONF_RX = re.compile("[" + "".join(re.escape(c) for c in CONFUSABLES) + "]")


def is_tag(c: str) -> bool:
    return 0xE0000 <= ord(c) <= 0xE007F


def strip_invisible(text: str) -> str:
    """The text without zero-width, bidi and tag characters."""
    return "".join(c for c in text if c not in ZERO_WIDTH and c not in BIDI and not is_tag(c))


def skeleton(name: str) -> str:
    """A name as it is drawn: NFKC, invisible characters removed, lookalikes as Latin, lower case,
    '-', '.' and spaces as '_'. Two tool names with one skeleton and different bytes shadow each other."""
    s = unicodedata.normalize("NFKC", strip_invisible(str(name)))
    s = "".join(CONFUSABLES.get(c, c) for c in s).lower()
    return re.sub(r"[-.\s]+", "_", s).strip("_")


def _printable(s: str) -> bool:
    return len(s) >= 3 and all(" " <= c <= "~" or c in "\n\t" for c in s) and any(c.isalnum() for c in s)


def decode_bits(bits: str) -> list:
    """[(text, method)] for a string of '0' and '1': both mappings, both bit orders, 8- and 7-bit
    groups, kept only when every character of the output is printable ASCII."""
    out, seen = [], set()
    bits = bits[:MAX_HIDDEN_CHARS]
    for mapping, b in (("as-is", bits), ("inverted", bits.translate({48: 49, 49: 48}))):
        for width in (8, 7):
            n = len(b) // width
            rest = b[n * width:]
            if n < 3 or len(rest) >= width or rest.strip("01"):
                continue
            if rest and len(set(rest)) != 1:
                continue        # a tail that is not padding: the stream is not made of such groups
            for order in ("msb", "lsb"):
                chars = []
                for i in range(n):
                    g = b[i * width:(i + 1) * width]
                    chars.append(chr(int(g if order == "msb" else g[::-1], 2)))
                text = "".join(chars).rstrip("\x00")
                if _printable(text) and text not in seen:
                    seen.add(text)
                    out.append((text, f"{width}bit-{order}-{mapping}"))
    return out


def decode_zero_width(seq: str) -> list:
    """[(text, method)] for a sequence of zero-width characters, printable readings only.
    Two distinct characters: bits (decode_bits). Three: each in turn as the separator between
    variable-length groups of the other two. Four: base-4 digits, four to a byte, every assignment."""
    seq = seq[:MAX_HIDDEN_CHARS]
    kinds = sorted(set(seq))
    out, seen = [], set()

    def add(text, method):
        if _printable(text) and text not in seen:
            seen.add(text)
            out.append((text, method))

    def name(c):
        return _ZW_NAMES.get(c, f"U+{ord(c):04X}")

    if len(kinds) == 2:
        a, b = kinds
        for text, method in decode_bits(seq.translate({ord(a): 48, ord(b): 49})):
            add(text, f"{name(a)}=0,{name(b)}=1,{method}")
    elif len(kinds) == 3:
        for sep in kinds:
            a, b = [k for k in kinds if k != sep]
            groups = [g for g in seq.split(sep) if g]
            if len(groups) < 3 or any(len(g) > 21 for g in groups):
                continue
            for zero, one in ((a, b), (b, a)):
                for order in ("msb", "lsb"):
                    try:
                        chars = []
                        for g in groups:
                            bits = g.translate({ord(zero): 48, ord(one): 49})
                            chars.append(chr(int(bits if order == "msb" else bits[::-1], 2)))
                        add("".join(chars), f"sep={name(sep)},{name(zero)}=0,{name(one)}=1,{order}")
                    except (ValueError, OverflowError):
                        pass
        if not out:     # the third character may be noise (a stray BOM): each pair alone
            for drop in kinds:
                rest = "".join(c for c in seq if c != drop)
                if len(rest) >= 24 and seq.count(drop) <= 2:
                    for text, method in decode_zero_width(rest):
                        add(text, method + f",without {name(drop)}")
    elif len(kinds) == 4 and len(seq) % 4 == 0 and len(seq) >= 12:
        for perm in permutations(range(4)):
            table = {ord(k): str(d) for k, d in zip(kinds, perm)}
            digits = seq.translate(table)
            try:
                text = "".join(chr(int(digits[i:i + 4], 4)) for i in range(0, len(digits), 4))
            except ValueError:
                continue
            add(text, "base4:" + ",".join(f"{name(k)}={d}" for k, d in zip(kinds, perm)))
    return out


# ---- the hidden-text finder -------------------------------------------------------------------------

STRONG = {"tag_chars", "zero_width", "html_hidden", "same_colour", "pdf_render_mode_3", "pdf_white_text",
          "trailing_whitespace", "ansi_same_colour"}
MAX_ANSI = 64 * 1024 * 1024         # bytes of one terminal capture read for text shown in its own background colour
BIT_KINDS = {"zero_width", "trailing_whitespace"}       # hidden text that is read by decoding bits
WEAK = {"html_comment", "html_attr", "md_link_title", "md_alt_text", "md_comment", "bidi", "homoglyph"}


def _finding(kind, text, where=None, detail="", candidates=None) -> dict:
    """One finding. `text` is the hidden text when there is exactly one reading of it, else None with
    the readings in `candidates`. `strong`: the text is invisible to a reader by construction.
    `instruction`: the text addresses a model or a solver (data, never an order)."""
    shown = text if text is not None else " ".join(t for t, _ in (candidates or []))
    # Zero-width characters and trailing blanks with no printable reading are what ordinary text has
    # (ZWNJ in Persian, ZWJ in emoji, markdown line breaks): `unread`, and not proof of hidden text.
    unread = kind in BIT_KINDS and text is None and not candidates
    return {"kind": kind, "text": text, "where": where, "detail": detail, "candidates": candidates or [],
            "strong": kind in STRONG and not unread, "unread": unread, "instruction": addresses_solver(shown)}


_STYLE_HIDE = (
    ("display_none", re.compile(r"(?:^|;)\s*display\s*:\s*none\b", re.I)),
    ("visibility_hidden", re.compile(r"(?:^|;)\s*visibility\s*:\s*(?:hidden|collapse)\b", re.I)),
    ("font_size_zero", re.compile(r"(?:^|;)\s*font-size\s*:\s*0+(?:\.0+)?(?:px|pt|em|rem|%)?\s*(?:;|$|!)", re.I)),
    ("opacity_zero", re.compile(r"(?:^|;)\s*opacity\s*:\s*0+(?:\.0+)?\s*(?:;|$|!)", re.I)),
    ("off_screen", re.compile(r"(?:^|;)\s*(?:left|top|text-indent|margin-left)\s*:\s*-\d{4,}", re.I)),
    ("zero_size", re.compile(r"(?:^|;)\s*(?:height|width|max-height)\s*:\s*0+(?:px)?\s*;.*overflow\s*:\s*hidden"
                             r"|overflow\s*:\s*hidden.*;\s*(?:height|width|max-height)\s*:\s*0+(?:px)?\s*(?:;|$)", re.I)),
)
_COLOUR = re.compile(r"(?:^|;)\s*color\s*:\s*([^;!]+)", re.I)
_BACKGROUND = re.compile(r"(?:^|;)\s*background(?:-color)?\s*:\s*([^;!]+)", re.I)
_NAMED = {"white": "ffffff", "black": "000000", "red": "ff0000", "transparent": "transparent"}
_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}


def _colour(value: str):
    v = re.sub(r"\s+", "", value.strip().lower())
    if v in _NAMED:
        return _NAMED[v]
    m = re.fullmatch(r"#([0-9a-f]{3})[0-9a-f]?", v)
    if m:
        return "".join(c * 2 for c in m.group(1))
    m = re.fullmatch(r"#([0-9a-f]{6})(?:[0-9a-f]{2})?", v)
    if m:
        return m.group(1)
    m = re.fullmatch(r"rgba?\((\d{1,3}),(\d{1,3}),(\d{1,3})(?:,([\d.]+))?\)", v)
    if m:
        if m.group(4) is not None and float(m.group(4) or 0) == 0:
            return "transparent"
        return "".join(f"{min(255, int(x)):02x}" for x in m.group(1, 2, 3))
    return None


def _style_reason(attrs: dict):
    """(kind, reason) when an element's own attributes hide its text, else None."""
    if "hidden" in attrs:
        return "html_hidden", "hidden_attribute"
    style = attrs.get("style") or ""
    for reason, rx in _STYLE_HIDE:
        if rx.search(style):
            return "html_hidden", reason
    fg = _COLOUR.search(style)
    if fg:
        c = _colour(fg.group(1))
        bg = _BACKGROUND.search(style)
        b = _colour(bg.group(1)) if bg else None
        if c == "transparent":
            return "same_colour", "transparent"
        if c is not None and bg and c == b:
            return "same_colour", f"#{c} on #{b}"
        if c == "ffffff" and not bg:
            return "same_colour", "white, no background set"
    if attrs.get("color") and attrs.get("bgcolor") and _colour(attrs["color"]) and _colour(attrs["color"]) == _colour(attrs["bgcolor"]):
        return "same_colour", "color equals bgcolor"
    return None


class _Html(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []             # [tag, (kind, reason) or None, [text parts]]
        self.out = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v if v is not None else "") for k, v in attrs}
        for key in ("alt", "title", "aria-label", "aria-description", "placeholder"):
            v = (a.get(key) or "").strip()
            if v:
                self.out.append(_finding("html_attr", v, self.getpos()[0], f"{tag}@{key}"))
        for key, v in a.items():
            if key.startswith("data-") and len(v.split()) >= 3:
                self.out.append(_finding("html_attr", v.strip(), self.getpos()[0], f"{tag}@{key}"))
        if tag == "meta" and a.get("content") and (a.get("name") or "").lower() not in ("viewport", "charset", "generator"):
            if len(a["content"].split()) >= 3:
                self.out.append(_finding("html_attr", a["content"].strip(), self.getpos()[0], f"meta@{a.get('name') or a.get('property') or ''}"))
        if tag in ("script", "style"):
            self.skip += 1
        if tag in _VOID:
            return
        self.stack.append([tag, _style_reason(a), [], self.getpos()[0]])

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in _VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self.skip:
            self.skip -= 1
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                for entry in reversed(self.stack[i:]):
                    self._close(entry)
                del self.stack[i:]
                return

    def _close(self, entry):
        tag, why, parts, line = entry       # text goes to the outermost hiding element only (handle_data)
        text = " ".join(" ".join(parts).split())
        if why and text:
            self.out.append(_finding(why[0], text, line, f"<{tag}> {why[1]}"))

    def handle_data(self, data):
        if self.skip or not data.strip():
            return
        for entry in self.stack:
            if entry[1]:
                entry[2].append(data)
                return

    def handle_comment(self, data):
        if data.strip():
            self.out.append(_finding("html_comment", data.strip(), self.getpos()[0]))

    def finish(self):
        for entry in list(reversed(self.stack)):
            self._close(entry)
        self.stack = []
        return self.out


# the part of a markdown link or image after "]": (target "title"), matched at a known position
_MD_TAIL = re.compile(r"\(\s*<?([^)\s>]{1,2000})>?(?:\s+[\"']([^\"'\n]{0,2000})[\"'])?\s*\)")
MAX_LINKS = 5000
_MD_REF = re.compile(r"^[ ]{0,3}\[([^\]\n]{1,200})\]:[ \t]*(\S+)[ \t]+[\"'(]([^\n]{1,2000})[\"')][ \t]*$", re.M)
_MD_COMMENT = re.compile(r"^[ ]{0,3}\[(?://|comment|#)\]:[ \t]*(?:#|<>)[ \t]*[\"'(]([^\n]{1,2000})[\"')][ \t]*$", re.M | re.I)
_WORD = re.compile(r"[^\W\d_][\w-]*", re.U)
_TAG_RX = re.compile("[\U000E0000-\U000E007F]")
_ZW_RX = re.compile("[" + ZERO_WIDTH + "]")
_BIDI_RX = re.compile("[" + BIDI + "]")
_TRAIL_RX = re.compile(r"(?<![ \t])[ \t]+(?=\r?$)", re.M)


_EMOJI_TAGS = re.compile("\U0001F3F4[\U000E0020-\U000E007E]{1,12}\U000E007F")


def hidden_text(text: str) -> list:
    """Every hiding place in one text, as findings (see _finding). The order is the order of the
    checks, not of importance; `strong` and `instruction` say what a finding is."""
    out = []
    if not text:
        return out
    body = text[1:] if text[:1] == "﻿" else text
    line_of = None

    def line(pos):
        nonlocal line_of
        if line_of is None:
            line_of = [m.start() for m in re.finditer("\n", body)]
        lo, hi = 0, len(line_of)
        while lo < hi:
            mid = (lo + hi) // 2
            if line_of[mid] < pos:
                lo = mid + 1
            else:
                hi = mid
        return lo + 1

    # the Unicode tag block: each character is ASCII + 0xE0000
    # ... except inside an emoji tag sequence (the flags of England, Scotland and Wales are a black
    # flag, tag letters and a cancel tag: U+1F3F4 gbeng U+E007F), which every emoji table has
    flags = [(m.start(), m.end()) for m in _EMOJI_TAGS.finditer(body)]
    tags = [(m.start(), m.group()) for m in _TAG_RX.finditer(body) if not any(a < m.start() < b for a, b in flags)]
    if tags:
        runs = 1 + sum(1 for (i, _), (j, _) in zip(tags, tags[1:]) if j != i + 1)
        decoded = "".join(chr(ord(c) - 0xE0000) for _, c in tags if 0x20 <= ord(c) - 0xE0000 <= 0x7E)
        out.append(_finding("tag_chars", decoded or None, line(tags[0][0]),
                            f"{len(tags)} tag characters in {runs} run(s)"))
    # zero-width characters: the whole text first, then each run
    zw = [(m.start(), m.group()) for m in _ZW_RX.finditer(body)]
    if zw:
        seq = "".join(c for _, c in zw)
        counts = ",".join(f"{_ZW_NAMES.get(k, k)}x{seq.count(k)}" for k in sorted(set(seq)))
        cands = decode_zero_width(seq) if len(seq) >= 16 else []
        if not cands and len(seq) >= 16:
            cuts = [0] + [n for n in range(1, len(zw)) if zw[n][0] != zw[n - 1][0] + 1] + [len(zw)]
            for lo, hi in list(zip(cuts, cuts[1:]))[:200] if len(cuts) > 2 else ():
                run = seq[lo:hi]
                if len(run) >= 16:
                    cands += [c for c in decode_zero_width(run) if c not in cands]
        if cands or len(seq) >= 8:
            out.append(_finding("zero_width", cands[0][0] if len(cands) == 1 else None, line(zw[0][0]),
                                f"{len(seq)} zero-width characters ({counts})" + (f"; {cands[0][1]}" if len(cands) == 1 else ""),
                                cands))
    # bidi controls: the line as stored, controls removed
    seen_lines = set()
    for m in _BIDI_RX.finditer(body):
        i = m.start()
        n = line(i)
        if n in seen_lines or len(seen_lines) >= 50:
            continue
        seen_lines.add(n)
        start = body.rfind("\n", 0, i) + 1
        end = body.find("\n", i)
        raw = body[start:end if end != -1 else len(body)]
        out.append(_finding("bidi", "".join(ch for ch in raw if ch not in BIDI).strip(), n,
                            "controls: " + ",".join(sorted({_BIDI_NAMES[ch] for ch in raw if ch in BIDI}))))
    # homoglyph words: Latin letters and lookalikes in one word
    if _CONF_RX.search(body):
        seen = set()
        for m in _WORD.finditer(body):
            w = m.group()
            if w in seen or not _CONF_RX.search(w):
                continue
            latin = sum(1 for c in w if c.isascii() and c.isalpha())
            odd = sum(1 for c in w if c in CONFUSABLES)
            if latin and odd and latin + odd >= len([c for c in w if c.isalpha()]):
                seen.add(w)
                out.append(_finding("homoglyph", w, line(m.start()), f"drawn as {''.join(CONFUSABLES.get(c, c) for c in w)!r}"))
                if len(seen) >= 50:
                    break
    # HTML: comments, hidden elements, attributes
    if "<" in body and re.search(r"<!--|<[a-zA-Z][^<>]{0,400}>", body):
        p = _Html()
        try:
            p.feed(body)
            p.close()
        except Exception:               # a broken document gives what was read so far
            pass
        out += p.finish()[:MAX_FINDINGS]
    # markdown: image alt text and titles, link titles, reference titles, comments
    pos, links = body.find("]("), 0             # each "](" once, its "[" looked for behind it: no rescanning
    while pos != -1 and links < MAX_LINKS:
        links += 1
        start = body.rfind("[", max(0, pos - 2000), pos)
        m = _MD_TAIL.match(body, pos + 1) if start != -1 and "\n" not in body[start:pos] else None
        if m:
            label, title = body[start + 1:pos].strip(), (m.group(2) or "").strip()
            if start and body[start - 1] == "!":
                if label:
                    out.append(_finding("md_alt_text", label, line(start), f"image {m.group(1)[:80]}"))
                if title:
                    out.append(_finding("md_link_title", title, line(start), f"image title {m.group(1)[:80]}"))
            elif title:
                out.append(_finding("md_link_title", title, line(start), f"link {m.group(1)[:80]}"))
        pos = body.find("](", pos + 2)
    comment_spans = []
    for m in _MD_COMMENT.finditer(body):
        comment_spans.append(m.span())
        out.append(_finding("md_comment", m.group(1).strip(), line(m.start())))
    for m in _MD_REF.finditer(body):
        if m.span() not in comment_spans:
            out.append(_finding("md_link_title", m.group(3).strip(), line(m.start()), f"reference [{m.group(1)[:40]}]"))
    # trailing whitespace: a space is one bit and a tab the other
    tails = [(m.start(), m.group()) for m in _TRAIL_RX.finditer(body)] if "\t" in body else []
    if len(tails) >= 3 or (tails and max(len(t) for _, t in tails) >= 24):
        bits = "".join(t for _, t in tails).translate({32: 48, 9: 49})
        cands = decode_bits(bits) if "0" in bits and "1" in bits else []
        if cands or ("0" in bits and "1" in bits and len(tails) >= 8 and len(bits) >= 24):
            tails = [(line(pos), t) for pos, t in tails[:1]] + tails[1:]
            out.append(_finding("trailing_whitespace", cands[0][0] if len(cands) == 1 else None, tails[0][0],
                                f"{len(bits)} trailing spaces and tabs on {len(tails)} lines"
                                + (f"; {cands[0][1]}, space=0 tab=1 before the mapping" if len(cands) == 1 else ""), cands))
    return out[:MAX_FINDINGS]


# ---- PDF: invisible and white text --------------------------------------------------------------------

_STREAM = re.compile(rb"stream\r?\n(.*?)\r?\n?endstream", re.S)
_PDF_ESC = {ord("n"): "\n", ord("r"): "\r", ord("t"): "\t", ord("b"): "\b", ord("f"): "\f", ord("("): "(", ord(")"): ")", ord("\\"): "\\"}


def _pdf_streams(data: bytes):
    for m in _STREAM.finditer(data[:MAX_SQLITE]):
        raw = m.group(1)
        head = data[max(0, m.start() - 400):m.start()]
        if b"FlateDecode" in head or b"/Fl " in head:
            try:
                raw = zlib.decompressobj().decompress(raw, 8 * 1024 * 1024)
            except zlib.error:
                continue
        elif b"/Filter" in head.split(b"obj")[-1]:
            continue            # a filter this reader does not undo
        if b"Tj" in raw or b"TJ" in raw:
            yield raw


def _pdf_tokens(s: bytes):
    """('str', text) | ('num', float) | ('op', name) | ('[', None) | (']', None) of a content stream."""
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c in b" \t\r\n\x00\x0c":
            i += 1
        elif c == 0x25:                                     # % comment
            j = s.find(b"\n", i)
            i = n if j == -1 else j + 1
        elif c == 0x28:                                     # ( literal string )
            depth, j, buf = 1, i + 1, []
            while j < n and depth:
                d = s[j]
                if d == 0x5C and j + 1 < n:
                    e = s[j + 1]
                    if e in _PDF_ESC:
                        buf.append(_PDF_ESC[e])
                        j += 2
                    elif 0x30 <= e <= 0x37:
                        k = j + 1
                        while k < min(j + 4, n) and 0x30 <= s[k] <= 0x37:
                            k += 1
                        buf.append(chr(int(s[j + 1:k], 8) & 0xFF))
                        j = k
                    else:
                        j += 2 if e not in b"\r\n" else (3 if s[j + 1:j + 3] == b"\r\n" else 2)
                    continue
                if d == 0x28:
                    depth += 1
                elif d == 0x29:
                    depth -= 1
                    if not depth:
                        break
                buf.append(chr(d))
                j += 1
            yield "str", "".join(buf)
            i = j + 1
        elif c == 0x3C and s[i + 1:i + 2] != b"<":          # <hex string>
            j = s.find(b">", i)
            if j == -1:
                return
            hexs = re.sub(rb"\s+", b"", s[i + 1:j])
            try:
                raw = bytes.fromhex((hexs + b"0" if len(hexs) % 2 else hexs).decode("ascii"))
                text = raw[2:].decode("utf-16-be", "replace") if raw[:2] == b"\xfe\xff" else raw.decode("latin-1")
            except ValueError:
                text = ""
            yield "str", text
            i = j + 1
        elif c == 0x5B:
            yield "[", None
            i += 1
        elif c == 0x5D:
            yield "]", None
            i += 1
        elif c in b"<>{}/":
            j = i + 1
            if c == 0x2F:
                while j < n and s[j] not in b" \t\r\n[]()<>/%":
                    j += 1
            elif s[i:i + 2] in (b"<<", b">>"):
                j = i + 2
            i = j
        else:
            j = i
            while j < n and s[j] not in b" \t\r\n[]()<>/%":
                j += 1
            word = s[i:j]
            i = max(j, i + 1)
            try:
                yield "num", float(word)
            except ValueError:
                yield "op", word.decode("latin-1")


def pdf_text_runs(data: bytes) -> list:
    """[(render mode, fill is white, text)] for every string shown by Tj, TJ, ' and \" in the PDF's
    content streams. Standard and identity-as-Latin-1 encodings only: a font with its own CMap gives
    codes, not text."""
    out = []
    for stream in _pdf_streams(data):
        mode, white, nums, last, arr, in_arr = 0, False, [], None, [], False
        saved = []
        for kind, val in _pdf_tokens(stream):
            if kind == "num":
                nums.append(val)
            elif kind == "str":
                if in_arr:
                    arr.append(val)
                last = val
            elif kind == "[":
                in_arr, arr = True, []
            elif kind == "]":
                in_arr = False
            else:
                if val == "Tr" and nums:
                    mode = int(nums[-1])
                elif val == "rg" and len(nums) >= 3:
                    white = all(v >= 0.99 for v in nums[-3:])
                elif val == "g" and nums:
                    white = nums[-1] >= 0.99
                elif val == "k" and len(nums) >= 4:
                    white = all(v <= 0.01 for v in nums[-4:])
                elif val == "q":
                    saved.append((mode, white))
                elif val == "Q" and saved:
                    mode, white = saved.pop()
                elif val in ("Tj", "'", '"') and last is not None:
                    out.append((mode, white, last))
                elif val == "TJ":
                    out.append((mode, white, "".join(arr)))
                elif val in ("T*", "Td", "TD", "ET") and out and not out[-1][2].endswith("\n"):
                    out.append((out[-1][0], out[-1][1], "\n"))
                nums, last = [], None
    return [(m, w, _pdf_utf16(t)) for m, w, t in out]


def _pdf_utf16(t: str) -> str:
    """A shown string most of whose high bytes are NUL is two-byte text (an Identity-H font, as OCR
    tools write their invisible text layer): read it as UTF-16BE. Anything else is returned as it is."""
    if len(t) >= 4 and len(t) % 2 == 0 and sum(c == "\x00" for c in t[0::2]) * 10 >= len(t) // 2 * 8 \
            and any(c != "\x00" for c in t[1::2]):
        try:
            return t.encode("latin-1").decode("utf-16-be")
        except (UnicodeError, ValueError):
            return t
    return t


def pdf_text(data: bytes) -> str:
    return "".join(t for _, _, t in pdf_text_runs(data)).strip()


def pdf_hidden(data: bytes) -> list:
    """Findings for text in render mode 3 (neither filled nor stroked) and for white text."""
    out = []
    for kind, pick in (("pdf_render_mode_3", lambda m, w: m == 3), ("pdf_white_text", lambda m, w: w and m != 3)):
        parts, cur = [], []
        for mode, white, text in pdf_text_runs(data):
            if pick(mode, white):
                cur.append(text)
            elif cur and text.strip():
                parts.append("".join(cur))
                cur = []
        if cur:
            parts.append("".join(cur))
        for p in parts:
            text = " ".join(p.split())
            if text:
                out.append(_finding(kind, text, None, "text render mode 3 (invisible)" if kind == "pdf_render_mode_3" else "white fill"))
    return out


# ---- members ------------------------------------------------------------------------------------------

def as_text(data: bytes):
    """A member as text, or None when it is not text."""
    if not isinstance(data, (bytes, bytearray)) or not data:
        return None
    data = bytes(data[:MAX_TEXT])
    try:
        if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
            return data.decode("utf-16")
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        try:                        # a cut at MAX_TEXT may split a character
            text = data[:-3].decode("utf-8") if len(data) == MAX_TEXT else None
        except UnicodeDecodeError:
            text = None
    if text is None or "\x00" in text[:4096]:
        return None
    return text


_SGR = re.compile(rb"\x1b\[([0-9;]*)m([^\x1b]*)")
_SGR_PAIRS = {(30 + i, 40 + i) for i in range(8)} | {(90 + i, 100 + i) for i in range(8)}


def ansi_hidden(data: bytes) -> list:
    """Text a terminal capture prints in its own background colour (SGR 30;40 is black on black, 37;47
    white on white) or concealed (SGR 8): one finding with the characters that are not blank, in
    order. Huntress 2024's warmup "The Void" is 12 MB of black-on-black spaces with a flag among them.
    Only the sixteen named colours are compared: a 256-colour or true-colour pair is not read."""
    if len(data) > MAX_ANSI:
        return []
    if b"\x1b[" not in data[:65536]:
        if b"^[[" not in data[:65536]:
            return []
        data = data.replace(b"^[[", b"\x1b[")       # a capture saved through `cat -v`: ESC written as ^[ (The Void is)
    fg = bg = None
    conceal = False
    out, hidden_chars, first = [], 0, None
    for m in _SGR.finditer(data):
        codes = [int(c) for c in m.group(1).split(b";") if c.isdigit()] or [0]
        if 38 in codes or 48 in codes:          # extended colours: their parameters are not colour codes
            fg = bg = None
            conceal = False
        else:
            for c in codes:
                if c == 0:
                    fg = bg = None
                    conceal = False
                elif 30 <= c <= 37 or 90 <= c <= 97:
                    fg = c
                elif 40 <= c <= 47 or 100 <= c <= 107:
                    bg = c
                elif c == 39:
                    fg = None
                elif c == 49:
                    bg = None
                elif c == 8:
                    conceal = True
                elif c == 28:
                    conceal = False
        body = m.group(2)
        if body and (conceal or (fg, bg) in _SGR_PAIRS):
            hidden_chars += len(body)
            shown = body.strip()
            if shown:
                if first is None:
                    first = data.count(b"\n", 0, m.start()) + 1
                out.append(shown.decode("utf-8", "replace"))
    if not out:
        return []
    text = "".join(out) if all(len(t) == 1 for t in out) else " ".join(out)
    period = (text + text).find(text, 1)        # one message printed over and over is that message, once
    times = len(text) // period if 0 < period < len(text) and len(text) % period == 0 else 1
    if times > 1:
        text = text[:period]
    return [_finding("ansi_same_colour", text[:MAX_HIDDEN_CHARS], first,
                     f"{hidden_chars} characters printed in their own background colour or concealed, {sum(len(t) for t in out)} of them not blank"
                     + (f"; the text repeats {times} times" if times > 1 else "")
                     + (f"; cut at {MAX_HIDDEN_CHARS} characters" if len(text) > MAX_HIDDEN_CHARS else ""))]


def scan(name: str, data: bytes) -> list:
    """The hidden-text findings of one member, each with `file`."""
    if bytes(data[:5]) == b"%PDF-":
        found = pdf_hidden(bytes(data))
        found += hidden_text(pdf_text(bytes(data)))
    else:
        text = as_text(data)
        found = hidden_text(text) if text is not None else []
        found += ansi_hidden(bytes(data))
    for f in found:
        f["file"] = name
    return found


def scan_json(name: str, obj) -> list:
    """The hidden-text findings of a JSON member's string values (a JSON file may spell an invisible
    character as an escape, so its raw text is not what a model reads), each with `file` and `path`."""
    out, budget = [], [40000, 8 * 1024 * 1024]

    def walk(o, path, depth):
        if depth > 40 or budget[0] <= 0 or budget[1] <= 0 or len(out) >= MAX_FINDINGS:
            return
        if isinstance(o, str):
            budget[0] -= 1
            budget[1] -= len(o)
            if len(o) >= 4:
                for f in hidden_text(o):
                    f["file"], f["path"] = name, path
                    out.append(f)
        elif isinstance(o, dict):
            for k, v in o.items():
                walk(v, f"{path}.{k}" if path else str(k), depth + 1)
        elif isinstance(o, list):
            for n, v in enumerate(o):
                walk(v, f"{path}[{n}]", depth + 1)

    walk(obj, "", 0)
    return out


def unique_files(files: dict) -> list:
    """[(name, bytes)] once per file (tools/run.py files a member under '<archive> -> <member>' and
    under its bare name, as one bytes object); the arrow name wins."""
    seen, out = set(), []
    for key in sorted(files, key=lambda k: (ARROW not in k, k)):
        data = files[key]
        if not isinstance(data, (bytes, bytearray)) or id(data) in seen:
            continue
        seen.add(id(data))
        out.append((key, bytes(data)))
    return sorted(out)


def load_json(data: bytes):
    """(object, 'json' | 'jsonl') or (None, None)."""
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_JSON:
        return None, None
    head = bytes(data[:64]).lstrip(b"\xef\xbb\xbf \t\r\n")
    if head[:1] not in (b"{", b"["):
        return None, None
    try:
        text = bytes(data).decode("utf-8-sig")
    except UnicodeDecodeError:
        return None, None
    try:
        return json.loads(text), "json"
    except (ValueError, RecursionError):
        pass
    rows = []
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            rows.append(json.loads(ln))
        except (ValueError, RecursionError):
            return None, None
        if len(rows) > MAX_ROWS:
            break
    return (rows, "jsonl") if rows else (None, None)


# ---- transcripts ----------------------------------------------------------------------------------------

ROLES = {"human": "user", "user": "user", "ai": "assistant", "assistant": "assistant", "model": "assistant",
         "bot": "assistant", "agent": "assistant", "gpt": "assistant", "aimessage": "assistant",
         "aimessagechunk": "assistant", "humanmessage": "user", "systemmessage": "system", "toolmessage": "tool",
         "functionmessage": "tool", "system": "system", "developer": "system", "tool": "tool", "function": "tool",
         "observation": "tool", "tool_result": "tool", "ipython": "tool", "chatmessage": "assistant"}
_TURN_KEYS = ("turn", "turn_index", "turn_idx", "turn_number", "turn_id", "index", "idx", "step", "step_index",
              "seq", "sequence", "n", "message_index")
_LIST_KEYS = ("messages", "input", "conversation", "transcript", "turns", "history", "events", "items", "steps",
              "chat", "log", "logs", "entries", "records", "trace", "bubbles", "output", "contents", "dialogue",
              "intermediate_steps", "runs", "spans", "choices", "tabs", "session", "data", "request", "response",
              "body", "conversations", "chat_history", "trajectory", "interactions")
_ARG_KEYS = ("arguments", "args", "input", "tool_input", "parameters", "params", "rawArgs", "action_input", "kwargs")
_OUT_KEYS = ("output", "result", "observation", "tool_output", "response", "content", "outputs", "results")
_NAME_KEYS = ("tool", "tool_name", "name", "function", "action", "recipient_name")


def _maybe_json(v):
    if isinstance(v, str):
        s = v.strip()
        if s[:1] in "{[" and len(s) < MAX_JSON:
            try:
                return json.loads(s)
            except (ValueError, RecursionError):
                return v
    return v


def flat_text(v, limit=200000) -> str:
    """Any JSON value as one text: strings as they are, everything else compact JSON."""
    if v is None:
        return ""
    if isinstance(v, str):
        return v[:limit]
    if isinstance(v, list) and all(isinstance(b, dict) and isinstance(b.get("text"), str) for b in v) and v:
        return "\n".join(b["text"] for b in v)[:limit]
    try:
        return json.dumps(v, ensure_ascii=False)[:limit]
    except (TypeError, ValueError):
        return str(v)[:limit]


def _turn_of(d: dict):
    for k in _TURN_KEYS:
        v = d.get(k)
        if isinstance(v, bool):
            continue
        if isinstance(v, int):
            return v
        if isinstance(v, str) and v.isdigit() and len(v) < 7:
            return int(v)
    return None


def _row(msg, role, kind, shape, turn=None, tool=None, arguments=None, result=None, text="", call_id=None) -> dict:
    return {"turn": turn, "msg": msg, "role": role, "kind": kind, "tool": tool, "arguments": arguments,
            "result": result, "text": text, "call_id": call_id, "shape": shape}


def _otel_attrs(a) -> dict:
    if isinstance(a, dict):
        return a
    out = {}
    for kv in a if isinstance(a, list) else ():
        if isinstance(kv, dict) and "key" in kv:
            v = kv.get("value")
            if isinstance(v, dict):
                v = next((v[k] for k in ("stringValue", "intValue", "doubleValue", "boolValue", "string_value", "int_value")
                          if k in v), flat_text(v.get("arrayValue") or v.get("kvlistValue") or ""))
            out[str(kv["key"])] = v
    return out


def _is_span(d) -> bool:
    return isinstance(d, dict) and "attributes" in d and any(k in d for k in ("spanId", "span_id", "traceId", "trace_id",
                                                                              "startTimeUnixNano", "start_time", "context"))


def _spans(obj) -> list:
    out = []
    if isinstance(obj, dict):
        for rs in obj.get("resourceSpans") or obj.get("resource_spans") or ():
            for ss in (rs.get("scopeSpans") or rs.get("scope_spans") or rs.get("instrumentationLibrarySpans") or ()) if isinstance(rs, dict) else ():
                out += [s for s in (ss.get("spans") or ()) if isinstance(s, dict)]
        if not out and isinstance(obj.get("spans"), list):
            out = [s for s in obj["spans"] if _is_span(s)]
    elif isinstance(obj, list):
        for o in obj:
            if _is_span(o):
                out.append(o)
            elif isinstance(o, dict) and ("resourceSpans" in o or "resource_spans" in o):
                out += _spans(o)
    return out


def _span_rows(spans: list) -> list:
    def start(s):
        v = s.get("startTimeUnixNano") or s.get("start_time_unix_nano") or s.get("start_time") or 0
        try:
            return (0, float(v))
        except (TypeError, ValueError):
            return (1, str(v))

    rows, said = [], set()
    for i, s in enumerate(sorted(spans, key=start)):
        a = _otel_attrs(s.get("attributes"))
        kind = str(a.get("openinference.span.kind") or a.get("traceloop.span.kind") or "").upper()
        op = str(a.get("gen_ai.operation.name") or "")
        tool = a.get("gen_ai.tool.name") or a.get("tool.name") or a.get("tool_name") or a.get("mcp.tool.name")
        if not tool and (kind in ("TOOL", "RETRIEVER") or op == "execute_tool"):
            tool = re.sub(r"^(?:execute_tool|tool)\s+", "", str(s.get("name") or kind.lower()))
        if tool:
            args = next((a[k] for k in ("gen_ai.tool.call.arguments", "tool.parameters", "tool.arguments", "input.value",
                                        "traceloop.entity.input", "mcp.request.argument", "gen_ai.tool.input") if k in a), None)
            res = next((a[k] for k in ("gen_ai.tool.call.result", "tool.result", "output.value", "traceloop.entity.output",
                                       "gen_ai.tool.output") if k in a), None)
            if res is None or any(k.startswith("retrieval.documents.") for k in a):
                docs = {}
                for k, v in a.items():
                    m = re.match(r"retrieval\.documents\.(\d+)\.document\.(\w+)$", k)
                    if m:
                        docs.setdefault(int(m.group(1)), {})[m.group(2)] = v
                if docs:            # the retrieved documents as one JSON list, each with its id
                    res = json.dumps([docs[n] for n in sorted(docs)], ensure_ascii=False)
            cid = a.get("gen_ai.tool.call.id") or s.get("spanId") or s.get("span_id")
            rows.append(_row(i, "assistant", "call", "otel", tool=str(tool), arguments=_maybe_json(args), call_id=cid,
                             text=flat_text(args)))
            if res is not None:
                rows.append(_row(i, "tool", "result", "otel", tool=str(tool), result=flat_text(res), text=flat_text(res), call_id=cid))
            continue
        msgs = []
        for prefix in ("gen_ai.prompt", "llm.input_messages"):
            n = 0
            while n < 500:
                role = a.get(f"{prefix}.{n}.role") or a.get(f"{prefix}.{n}.message.role")
                content = a.get(f"{prefix}.{n}.content") or a.get(f"{prefix}.{n}.message.content")
                if role is None and content is None:
                    break
                msgs.append((ROLES.get(str(role).lower(), "user"), flat_text(content)))
                n += 1
        for key in ("gen_ai.input.messages", "gen_ai.system_instructions"):
            v = _maybe_json(a.get(key))
            if isinstance(v, list):
                for m in v:
                    if isinstance(m, dict):
                        msgs.append((ROLES.get(str(m.get("role")).lower(), "user"), flat_text(m.get("content") or m.get("parts"))))
        for ev in s.get("events") or ():
            if isinstance(ev, dict) and str(ev.get("name") or "").startswith("gen_ai."):
                ea = _otel_attrs(ev.get("attributes"))
                role = str(ev["name"]).split(".")[1]
                msgs.append((ROLES.get(role, "assistant" if role == "choice" else "user"), flat_text(ea.get("content") or ea.get("message") or ea)))
        if not msgs and "input.value" in a and kind in ("", "LLM", "CHAIN", "AGENT"):
            msgs.append(("user", flat_text(a["input.value"])))
        for role, text in msgs:
            if text and (role, text) not in said:
                said.add((role, text))
                rows.append(_row(i, role, "message", "otel", text=text))
        done = [a[k] for k in sorted(a) if re.match(r"gen_ai\.completion\.\d+\.content$|llm\.output_messages\.\d+\.message\.content$", k)]
        if not done and "output.value" in a and kind in ("LLM", "AGENT"):
            done = [a["output.value"]]
        for text in done:
            text = flat_text(text)
            if text and ("assistant", text) not in said:
                said.add(("assistant", text))
                rows.append(_row(i, "assistant", "message", "otel", text=text))
    return rows


def _message_score(d) -> int:
    if isinstance(d, (list, tuple)) and len(d) == 2 and isinstance(d[0], dict) and ("tool" in d[0] or "tool_input" in d[0]):
        return 2
    if not isinstance(d, dict):
        return 0
    if isinstance(d.get("role"), str) or isinstance(d.get("message"), dict) and "role" in d["message"]:
        return 2
    t = d.get("type")
    if isinstance(t, str) and t.lower() in ("human", "ai", "system", "tool", "user", "assistant", "message", "function_call",
                                           "function_call_output", "response_item", "event_msg", "tool_use", "tool_result",
                                           "tool_call", "constructor", "local_shell_call", "mcp_call", "custom_tool_call",
                                           "reasoning", "web_search_call", "summary"):
        return 2
    if "run_type" in d or "toolFormerData" in d or "bubbleId" in d or isinstance(d.get("parts"), list):
        return 2
    if any(k in d for k in ("tool", "tool_name", "action", "observation", "tool_calls", "tool_call", "sender", "speaker", "author", "from")):
        return 1
    return 0


def _find_list(obj, depth=0):
    """The list of message-like items in a transcript document: the best-scoring list within four
    levels of the known wrapper keys."""
    best, best_score = None, 0

    def consider(lst):
        nonlocal best, best_score
        score = sum(_message_score(x) for x in lst[:MAX_ROWS])
        if score > best_score:
            best, best_score = lst, score

    def walk(o, d):
        if d > 4:
            return
        if isinstance(o, list):
            consider(o)
            for x in o[:50]:
                if isinstance(x, dict) and d < 3 and any(isinstance(x.get(k), list) for k in ("bubbles", "messages", "choices", "turns")):
                    walk(x, d + 1)
        elif isinstance(o, dict):
            if isinstance(o.get("message"), dict) and "choices" not in o and d > 0 and _message_score(o["message"]):
                consider([o["message"]])
            for k in _LIST_KEYS:
                if k in o:
                    walk(o[k], d + 1)

    walk(obj, depth)
    return best or []


def _block_rows(blocks, i, role, shape, turn, names) -> list:
    """Rows of one message's content blocks (Anthropic, OpenAI Responses and Gemini parts)."""
    rows, texts = [], []
    for b in blocks:
        if isinstance(b, str):
            texts.append(b)
            continue
        if not isinstance(b, dict):
            continue
        t = str(b.get("type") or "").lower()
        if t in ("tool_use", "server_tool_use", "mcp_tool_use", "tool_call", "tool-call", "function_call"):
            args = _maybe_json(b.get("input", b.get("arguments", b.get("args"))))
            cid = b.get("id") or b.get("call_id") or b.get("toolCallId")
            fn = b.get("function") if isinstance(b.get("function"), dict) else {}
            name = next((v for v in (b.get("name"), b.get("toolName"), fn.get("name"), b.get("function")) if isinstance(v, str) and v), None)
            if args is None and fn:
                args = _maybe_json(fn.get("arguments", fn.get("args")))
            names[cid] = name
            rows.append(_row(i, "assistant", "call", shape, turn, tool=name, arguments=args, call_id=cid, text=flat_text(args)))
        elif t in ("tool_result", "mcp_tool_result", "web_search_tool_result", "tool-result", "function_call_output") or "tool_use_id" in b:
            cid = b.get("tool_use_id") or b.get("call_id") or b.get("toolCallId")
            res = flat_text(b.get("content", b.get("output", b.get("result"))))
            rows.append(_row(i, "tool", "result", shape, turn, tool=names.get(cid) or b.get("name") or b.get("toolName"), result=res, text=res, call_id=cid))
        elif isinstance(b.get("functionCall"), dict) or isinstance(b.get("function_call"), dict):
            fc = b.get("functionCall") or b.get("function_call")
            args = _maybe_json(fc.get("args", fc.get("arguments")))
            rows.append(_row(i, "assistant", "call", "gemini", turn, tool=fc.get("name"), arguments=args, text=flat_text(args), call_id=fc.get("id")))
        elif isinstance(b.get("functionResponse"), dict) or isinstance(b.get("function_response"), dict):
            fr = b.get("functionResponse") or b.get("function_response")
            res = flat_text(fr.get("response"))
            rows.append(_row(i, "tool", "result", "gemini", turn, tool=fr.get("name"), result=res, text=res, call_id=fr.get("id")))
        elif isinstance(b.get("text"), str):
            texts.append(b["text"])
        elif t in ("document", "search_result") and b.get("content") is not None:
            texts.append(flat_text(b.get("content")))
    if texts and "".join(texts).strip():
        rows.insert(0, _row(i, role, "message", shape, turn, text="\n".join(texts)))
    return rows


def _is_bubble(it: dict) -> bool:
    """A Cursor chat bubble: {type: 1|2|'user'|'ai', text, toolFormerData}."""
    if "toolFormerData" in it or "bubbleId" in it:
        return True
    return it.get("type") in (1, 2, "user", "ai") and ("text" in it or "rawText" in it) \
        and not any(k in it for k in ("content", "data", "role", "message", "payload"))


def _item_rows(it, i, names) -> list:
    """The rows of one item of a transcript, whatever its shape."""
    if isinstance(it, (list, tuple)):               # LangChain intermediate_steps: [action, observation]
        if len(it) == 2 and isinstance(it[0], dict):
            act = it[0]
            args = _maybe_json(act.get("tool_input", act.get("input")))
            res = flat_text(it[1])
            return [_row(i, "assistant", "call", "langchain", tool=act.get("tool"), arguments=args, text=flat_text(args)),
                    _row(i, "tool", "result", "langchain", tool=act.get("tool"), result=res, text=res)]
        return []
    if not isinstance(it, dict):
        return []
    turn, shape, m, role = _turn_of(it), "generic", it, None
    t = it.get("type") if isinstance(it.get("type"), str) else ""
    if t in ("response_item", "event_msg", "turn_context", "session_meta") and isinstance(it.get("payload"), dict):
        m, shape = it["payload"], "codex"
        if t != "response_item" and m.get("type") not in ("user_message", "agent_message"):
            return []
        if m.get("type") in ("user_message", "agent_message"):
            return []               # the same text comes as a response_item
        t = m.get("type") if isinstance(m.get("type"), str) else ""
    elif isinstance(it.get("message"), dict) and ("role" in it["message"] or "content" in it["message"]):
        shape = "claude_code" if ("uuid" in it or "sessionId" in it or "parentUuid" in it) else ("cursor" if t == "" and "role" in it else "generic")
        role = it["message"].get("role") or it.get("role") or t
        m = it["message"]
        t = m.get("type") if isinstance(m.get("type"), str) else ""
    elif _is_bubble(it):
        role = {1: "user", 2: "assistant", "user": "user", "ai": "assistant"}.get(it.get("type"), "assistant")
        rows = []
        text = it.get("text") or it.get("rawText") or ""
        if isinstance(text, str) and text.strip():
            rows.append(_row(i, role, "message", "cursor", turn, text=text))
        tf = it.get("toolFormerData")
        if isinstance(tf, dict) and (tf.get("name") or tf.get("tool")):
            args = _maybe_json(tf.get("rawArgs", tf.get("params", tf.get("args"))))
            rows.append(_row(i, "assistant", "call", "cursor", turn, tool=tf.get("name") or tf.get("tool"), arguments=args, text=flat_text(args), call_id=tf.get("toolCallId")))
            if tf.get("result") is not None:
                res = flat_text(tf["result"])
                rows.append(_row(i, "tool", "result", "cursor", turn, tool=tf.get("name") or tf.get("tool"), result=res, text=res, call_id=tf.get("toolCallId")))
        return rows
    elif it.get("lc") and isinstance(it.get("kwargs"), dict):
        role = str((it.get("id") or ["ai"])[-1]).lower()
        m, shape, t = it["kwargs"], "langchain", ""
    elif t.lower() in ("human", "ai", "system", "tool", "function", "chat", "aimessagechunk") and "role" not in it:
        role, shape = t.lower(), "langchain"
        m = it["data"] if isinstance(it.get("data"), dict) else it
        t = ""
    elif "run_type" in it:
        name = it.get("name")
        rt = str(it.get("run_type"))
        ins, outs = it.get("inputs"), it.get("outputs")
        if rt in ("tool", "retriever"):
            res = flat_text(outs) if outs is not None else None
            rows = [_row(i, "assistant", "call", "langchain", turn, tool=name, arguments=_maybe_json(ins), text=flat_text(ins), call_id=it.get("id"))]
            if res is not None:
                rows.append(_row(i, "tool", "result", "langchain", turn, tool=name, result=res, text=res, call_id=it.get("id")))
            return rows
        rows = []
        if rt == "chain" and ins is not None and not it.get("parent_run_id"):
            rows.append(_row(i, "user", "message", "langchain", turn, text=flat_text(ins)))
        if rt == "chain" and outs is not None and not it.get("parent_run_id"):
            rows.append(_row(i, "assistant", "message", "langchain", turn, text=flat_text(outs)))
        return rows
    if turn is None:
        turn = _turn_of(m)
    role = ROLES.get(str(role or m.get("role") or m.get("sender") or m.get("speaker") or m.get("author") or m.get("from") or "").lower())
    tl = t.lower()
    # items that are one call or one result (OpenAI Responses, Codex, generic event logs)
    if tl in ("function_call", "custom_tool_call", "tool_call", "tool_use", "local_shell_call", "mcp_call", "web_search_call",
              "computer_call", "action", "tool_start", "tool-call"):
        fn = m.get("function") if isinstance(m.get("function"), dict) else {}
        name = next((v for v in (m.get("name"), m.get("tool"), m.get("tool_name"), fn.get("name"), m.get("function")) if isinstance(v, str) and v), None)
        if not name:
            name = {"local_shell_call": "shell", "web_search_call": "web_search", "computer_call": "computer"}.get(tl)
        args = next((m[k] for k in _ARG_KEYS if k in m), None)
        if args is None:
            args = next((v for v in (fn.get("arguments"), fn.get("args"), m.get("action")) if v is not None and not (v is m.get("action") and isinstance(v, str))), None)
        args = _maybe_json(args)
        cid = m.get("call_id") or m.get("id") or m.get("tool_call_id")
        names[cid] = name
        rows = [_row(i, "assistant", "call", "openai_responses" if shape == "generic" else shape, turn, tool=name, arguments=args, text=flat_text(args), call_id=cid)]
        if tl == "mcp_call" and m.get("output") is not None:
            rows.append(_row(i, "tool", "result", shape, turn, tool=name, result=flat_text(m["output"]), text=flat_text(m["output"]), call_id=cid))
        return rows
    if tl in ("function_call_output", "custom_tool_call_output", "tool_result", "tool_output", "local_shell_call_output",
              "observation", "tool_end", "tool-result", "computer_call_output"):
        cid = m.get("call_id") or m.get("tool_call_id") or m.get("tool_use_id") or m.get("id")
        res = flat_text(next((m[k] for k in _OUT_KEYS if k in m), None))
        return [_row(i, "tool", "result", "openai_responses" if shape == "generic" else shape, turn, tool=names.get(cid) or m.get("name") or m.get("tool"), result=res, text=res, call_id=cid)]
    rows = []
    content = m.get("content", m.get("parts", m.get("text", m.get("value"))))
    if role == "tool":
        cid = m.get("tool_call_id") or m.get("call_id") or m.get("tool_use_id")
        res = flat_text(content if content is not None else next((m[k] for k in _OUT_KEYS if k in m), None))
        return [_row(i, "tool", "result", "openai_chat" if shape == "generic" else shape, turn, tool=m.get("name") or m.get("tool") or names.get(cid), result=res, text=res, call_id=cid)]
    if isinstance(content, list):
        sh = shape
        if sh == "generic":
            sh = "gemini" if "parts" in m and "content" not in m else ("anthropic" if any(isinstance(b, dict) and b.get("type") in ("tool_use", "tool_result") for b in content)
                                                                      else ("openai_responses" if any(isinstance(b, dict) and str(b.get("type")).endswith("_text") for b in content) else "anthropic"))
        rows += _block_rows(content, i, role or "user", sh, turn, names)
        shape = sh
    elif isinstance(content, dict):
        rows += _block_rows([content], i, role or "user", shape, turn, names)
    elif isinstance(content, str) and content.strip() and role:
        rows.append(_row(i, role, "message", "openai_chat" if shape == "generic" and ("tool_calls" in m or "role" in m) else shape, turn, text=content))
    calls = m.get("tool_calls")
    if not isinstance(calls, list):
        calls = (m.get("additional_kwargs") or {}).get("tool_calls") if isinstance(m.get("additional_kwargs"), dict) else None
    for c in calls if isinstance(calls, list) else ():
        if not isinstance(c, dict):
            continue
        fn = c.get("function") if isinstance(c.get("function"), dict) else c
        # AgentDojo's runs write the name as a plain string: {"function": "send_email", "args": {...}}
        name = fn.get("name") or c.get("name") or (c.get("function") if isinstance(c.get("function"), str) else None)
        args = _maybe_json(fn.get("arguments", fn.get("args", c.get("args", c.get("input")))))
        cid = c.get("id") or c.get("call_id")
        names[cid] = name
        rows.append(_row(i, "assistant", "call", "openai_chat" if shape == "generic" else shape, turn, tool=name, arguments=args, text=flat_text(args), call_id=cid))
    fc = m.get("function_call")
    if not isinstance(fc, dict) and isinstance(m.get("additional_kwargs"), dict):
        fc = m["additional_kwargs"].get("function_call")
    if isinstance(fc, dict) and fc.get("name"):
        args = _maybe_json(fc.get("arguments"))
        rows.append(_row(i, "assistant", "call", "openai_chat" if shape == "generic" else shape, turn, tool=fc["name"], arguments=args, text=flat_text(args)))
    if rows:
        return rows
    # a plain event log: {tool, args} and {observation}
    name = next((m[k] for k in ("tool", "tool_name", "action") if isinstance(m.get(k), str)), None)
    if name and any(k in m for k in _ARG_KEYS):
        args = _maybe_json(next(m[k] for k in _ARG_KEYS if k in m))
        rows.append(_row(i, "assistant", "call", shape, turn, tool=name, arguments=args, text=flat_text(args), call_id=m.get("id")))
    out = next((m[k] for k in ("observation", "tool_output", "output", "result", "response") if k in m), None)
    if out is not None and (name or "observation" in m or "tool_output" in m):
        res = flat_text(out)
        rows.append(_row(i, "tool", "result", shape, turn, tool=name, result=res, text=res, call_id=m.get("id")))
    return rows


def trace_rows(obj) -> list:
    """Rows of a parsed transcript document (see load_trace)."""
    spans = _spans(obj)
    if spans:
        return _span_rows(spans)[:MAX_ROWS]
    items = _find_list(obj)
    for holder in ([obj] + [obj.get(k) for k in ("response", "output", "body", "result")]) if isinstance(obj, dict) else ():
        if isinstance(holder, dict) and isinstance(holder.get("choices"), list) and items is not holder["choices"]:
            items = list(items) + [{"choices": holder["choices"]}]     # the reply of a request/response pair
    rows, names = [], {}
    for i, it in enumerate(items[:MAX_ROWS]):
        if isinstance(it, dict) and isinstance(it.get("choices"), list):
            for c in it["choices"]:
                if isinstance(c, dict) and isinstance(c.get("message"), dict):
                    rows += _item_rows(c["message"], i, names)
            continue
        rows += _item_rows(it, i, names)
    if isinstance(obj, dict) and items is obj.get("intermediate_steps") and rows:
        asked = obj.get("input") if isinstance(obj.get("input"), str) else (obj.get("input") or {}).get("input") if isinstance(obj.get("input"), dict) else None
        if isinstance(asked, str) and asked.strip():
            rows.insert(0, _row(-1, "user", "message", "langchain", text=asked))
        if isinstance(obj.get("output"), str) and obj["output"].strip():
            rows.append(_row(len(items), "assistant", "message", "langchain", text=obj["output"]))
    # a system prompt and tool list beside the messages (Anthropic request bodies)
    if isinstance(obj, dict) and isinstance(obj.get("system"), (str, list)) and rows:
        rows.insert(0, _row(-1, "system", "message", rows[0]["shape"], text=flat_text(obj["system"])))
    # a result whose tool is unknown takes the name of the call with its id, else of the call before it
    by_id = {r["call_id"]: r["tool"] for r in rows if r["kind"] == "call" and r["call_id"] is not None}
    last = None
    for r in rows:
        if r["kind"] == "call":
            last = r["tool"]
        elif r["kind"] == "result" and not r["tool"]:
            r["tool"] = by_id.get(r["call_id"]) or last
    return rows


def is_trace(rows) -> bool:
    kinds = {r["kind"] for r in rows}
    roles = {r["role"] for r in rows}
    return len(rows) >= 2 and ("call" in kinds or "result" in kinds or {"user", "assistant"} <= roles)


_TEXT_ROLE = re.compile(
    r"^[ \t>#*_-]{0,6}(?:\[?(\d{1,4})\]?[.):\s-]{1,3})?[*_`]{0,2}"
    r"(user|human|assistant|ai|agent|system|tool call|tool result|tool output|tool response|tool|function|observation|"
    r"action input|action|thought|question|final answer|answer)"
    r"[*_`]{0,2}[ \t]*(?:\(([^)\n]{1,80})\)|\[([^\]\n]{1,80})\])?[*_`]{0,2}[ \t]*:[*_`]{0,2}[ \t]?(.*)$", re.I)
_TEXT_CALL = re.compile(r"^\s*`?([A-Za-z_][\w.-]{0,80})`?\s*[(:]?\s*(.*?)\)?\s*$", re.S)


def text_trace(text: str) -> list:
    """Rows of a transcript written as text: lines that begin with a role ("User:", "Assistant:",
    "Tool (search):", "[3] tool:"), and the ReAct form (Thought / Action / Action Input /
    Observation). A leading number is the turn. [] when the text is not such a transcript."""
    blocks = []
    for line in text.splitlines():
        m = _TEXT_ROLE.match(line) if len(line) < 20000 else None
        if m:
            blocks.append([int(m.group(1)) if m.group(1) else None, m.group(2).lower(), (m.group(3) or m.group(4) or "").strip(), [m.group(5)]])
        elif blocks:
            blocks[-1][3].append(line)
        if len(blocks) > MAX_ROWS:
            break
    rows, pending = [], None
    for i, (turn, role, label, lines) in enumerate(blocks):
        body = "\n".join(lines).strip()
        if role in ("user", "human", "question"):
            rows.append(_row(i, "user", "message", "text", turn, text=body))
        elif role == "system":
            rows.append(_row(i, "system", "message", "text", turn, text=body))
        elif role in ("assistant", "ai", "agent", "thought", "final answer", "answer"):
            if body:
                rows.append(_row(i, "assistant", "message", "text", turn, text=body))
        elif role == "action":
            pending = body.strip("`'\" ") or None
        elif role == "action input":
            args = _maybe_json(body)
            rows.append(_row(i, "assistant", "call", "text", turn, tool=pending, arguments=args, text=flat_text(args)))
        elif role == "tool call":
            m = _TEXT_CALL.match(body)
            name, rest = (m.group(1), m.group(2).strip()) if m else (label or None, body)
            pending = label or name
            args = _maybe_json(rest)
            rows.append(_row(i, "assistant", "call", "text", turn, tool=pending, arguments=args, text=flat_text(args)))
        else:                               # tool, function, observation, tool result / output / response
            rows.append(_row(i, "tool", "result", "text", turn, tool=label or pending, result=body, text=body))
    roles = {r["role"] for r in rows}
    return rows if len(rows) >= 3 and "user" in roles and len(roles) >= 2 and is_trace(rows) else []


def load_trace(data: bytes, name: str = "") -> list:
    """A transcript's rows, or [] when the member is not one."""
    obj, _ = load_json(data)
    if obj is None:
        text = as_text(data)
        return text_trace(text) if text else []
    try:
        rows = trace_rows(obj)
    except (RecursionError, TypeError, ValueError, AttributeError):
        return []
    return rows if is_trace(rows) else []


def trace_shape(rows) -> str:
    counts = {}
    for r in rows:
        counts[r["shape"]] = counts.get(r["shape"], 0) + 1
    return max(counts, key=counts.get) if counts else "generic"


# ---- hosts, URLs, base64 ----------------------------------------------------------------------------------

URL = re.compile(r"\b(?:https?|wss?|ftp)://[^\s\"'<>()\[\]{}`\\|^]{3,2000}", re.I)
_IPV4 = re.compile(r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\w.])")
_DOMAIN = re.compile(r"(?<![\w@./-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|onion|corp|"
                     r"gov|edu|co|me|dev|app|site|online|example|invalid|test|cc|tk|su|uk|de|ai|sh|cloud|link|live|click|"
                     r"internal|local|lan)(?![\w-]|\.[a-z])", re.I)


_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]{1,64}@((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![\w-])", re.I)


def urls_in(text: str) -> list:
    out = []
    for m in URL.finditer(text or ""):
        u = m.group().rstrip(".,;:!?")
        while u.endswith(")") and u.count("(") < u.count(")"):
            u = u[:-1]
        if u not in out:
            out.append(u)
    return out


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def hosts_in(text: str) -> list:
    """Hosts a text names: of its URLs, bare IPv4 addresses, and bare domains of well-known TLDs."""
    text = text or ""
    out = [h for h in (host_of(u) for u in urls_in(text)) if h]
    out += [m.group() for m in _IPV4.finditer(text)]
    out += [m.group().lower() for m in _DOMAIN.finditer(text)]
    out += [m.group(1).lower() for m in _EMAIL.finditer(text)]      # a mail address is a destination too
    seen = []
    for h in out:
        if h not in seen:
            seen.append(h)
    return seen


def _b64(s: str):
    """The printable text a base64 or base64url string decodes to, else None."""
    s = s.strip()
    if len(s) < 12 or not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", s) or re.fullmatch(r"[a-z]+|[A-Z]+|\d+|[0-9a-f]+", s):
        return None
    body = s.rstrip("=").replace("-", "+").replace("_", "/")
    if len(body) % 4 == 1:
        return None
    try:
        raw = base64.b64decode(body + "=" * (-len(body) % 4), validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError):
        return None
    return text if len(text) >= 6 and all(c.isprintable() or c in "\n\t\r" for c in text) else None


def b64_in_url(url: str) -> list:
    """[(where, encoded, decoded)] for query values, fragment and path segments of one URL that are
    base64 of printable text."""
    out = []
    try:
        parts = urlsplit(url)
    except ValueError:
        return out
    pieces = [(f"query:{k}", v) for k, v in parse_qsl(parts.query, keep_blank_values=False)]
    pieces += [("query", unquote(parts.query))] if parts.query and "=" not in parts.query else []
    pieces += [(f"path:{n}", unquote(seg)) for n, seg in enumerate(parts.path.split("/")) if seg]
    pieces += [("fragment", unquote(parts.fragment))] if parts.fragment else []
    pieces += [(f"subdomain:{n}", lab) for n, lab in enumerate((parts.hostname or "").split(".")[:-2])]
    for where, value in pieces:
        dec = _b64(value)
        if dec is not None:
            out.append((where, value, dec))
    return out


# ---- transcript queries ------------------------------------------------------------------------------------

def user_hosts(rows) -> set:
    """Hosts the user and the system prompt name: what the agent was asked to touch."""
    out = set()
    for r in rows:
        if r["role"] in ("user", "system") and r["kind"] == "message":
            out.update(hosts_in(r["text"]))
    return out


def external_calls(rows) -> list:
    """Tool calls whose arguments carry a host no user or system turn has, in order:
    [{row, index, urls, hosts, source, source_index}]. `source` is the earliest tool-result row
    before the call whose text has one of those hosts (the output the address came from), or None."""
    known = user_hosts(rows)
    out = []
    seen_in = {}                # result row index -> the hosts its text names, hidden text included

    def result_hosts(k):
        if k not in seen_in:
            text = rows[k]["text"].replace("\\/", "/")
            hidden = " ".join(t for f in hidden_text(text) if f["strong"] for t in ([f["text"]] if f["text"] else [c for c, _ in f["candidates"]]))
            seen_in[k] = set(hosts_in(text + " " + hidden))
        return seen_in[k]

    for n, r in enumerate(rows):
        if r["kind"] != "call":
            continue
        text = flat_text(r["arguments"]) if r["arguments"] is not None else r["text"]
        text = text.replace("\\/", "/")
        new = [h for h in hosts_in(text) if h not in known]
        if not new:
            continue
        urls = [u for u in urls_in(text) if host_of(u) in new]
        source = next(((k, rows[k]) for k in range(n) if rows[k]["kind"] == "result" and result_hosts(k) & set(new)), None)
        out.append({"row": r, "index": n, "urls": urls, "hosts": new, "source": source[1] if source else None,
                    "source_index": source[0] if source else None})
    return out


_VALUE = re.compile(r"[A-Za-z0-9][\w.@:/+-]{5,199}")


def followed_values(rows) -> list:
    """Calls that carry a value out of a tool output that reads as an instruction or holds strong
    hidden text, when no user or system turn and no earlier call has that value:
    [{row, index, values, source, source_index}]. An account number, an address or a file name is no
    host, so external_calls() cannot see it (AgentDojo's banking runs: the planted text names an
    IBAN and the next call pays it). The source's wording is a classifier's verdict: evidence for a
    reader and an unsure answer, never a proof. A value an honest output hands on (a search result's
    id) is not here, because its output does not read as an instruction."""
    said = " ".join(r["text"] or "" for r in rows if r["role"] in ("user", "system") and r["kind"] == "message")
    out, sources, earlier = [], {}, ""
    for n, r in enumerate(rows):
        if r["kind"] == "result":
            text = r["text"] or ""
            if addresses_solver(strip_invisible(text)) or any(f["strong"] for f in hidden_text(text)):
                sources[n] = text
        elif r["kind"] == "call":
            text = flat_text(r["arguments"]) if r["arguments"] is not None else (r["text"] or "")
            vals = [v for v in dict.fromkeys(_VALUE.findall(text)) if v not in said and v not in earlier
                    and (any(c.isdigit() for c in v) or "@" in v or "." in v or "/" in v)]
            for k in sorted(sources):
                hit = [v for v in vals if v in sources[k]]
                if hit:
                    out.append({"row": r, "index": n, "values": hit, "source": rows[k], "source_index": k})
                    break
            earlier += " " + text
    return out


def first_external_call(rows):
    calls = external_calls(rows)
    return calls[0] if calls else None


def call_of(rows, index: int):
    """The call row a result row answers: by call id, else the nearest call before it."""
    r = rows[index]
    if r.get("call_id") is not None:
        for p in rows[:index][::-1]:
            if p["kind"] == "call" and p["call_id"] == r["call_id"]:
                return p
    for p in rows[:index][::-1]:
        if p["kind"] == "call":
            return p
    return None


_DOC_ID_KEYS = ("doc_id", "document_id", "chunk_id", "id", "source", "uri", "url", "path", "file", "filename", "file_path", "title", "name")


def doc_refs(rows, index: int, hosts=()) -> list:
    """[(where, key, value)] naming the document a tool result is: id-like fields of the result when
    it is JSON, and of the arguments of the call it answers. A result that is a list of documents
    is narrowed to the ones whose text names one of `hosts`."""
    out = []

    def take(where, obj, depth=0):
        if isinstance(obj, dict):
            for k in _DOC_ID_KEYS:
                v = obj.get(k)
                if isinstance(v, (str, int)) and not isinstance(v, bool) and str(v).strip() and (where, k, str(v)) not in out:
                    out.append((where, k, str(v)))
            for k in ("metadata", "meta", "document", "doc"):
                if isinstance(obj.get(k), dict) and depth < 2:
                    take(where, obj[k], depth + 1)
        elif isinstance(obj, list) and len(obj) == 1:
            take(where, obj[0], depth)

    r = rows[index]
    res = _maybe_json(r["result"] or "")
    if isinstance(res, dict):
        inner = next((res[k] for k in ("documents", "docs", "results", "matches", "chunks", "hits", "items") if isinstance(res.get(k), list)), None)
        if inner is not None and not any(isinstance(res.get(k), (str, int)) for k in _DOC_ID_KEYS):
            res = inner
    many = isinstance(res, list) and len(res) > 1
    if many and hosts:
        res = [d for d in res if any(h in hosts_in(flat_text(d).replace("\\/", "/")) for h in hosts)]
    take("result", res)
    if not (many and out):          # one of several retrieved documents is not named by the query
        c = call_of(rows, index)
        if c is not None and not many:
            take("arguments", c["arguments"])
    return out


def b64_in_urls(rows) -> list:
    """[{index, tool, url, where, encoded, decoded}] for base64 in the URLs of tool calls."""
    out = []
    for n, r in enumerate(rows):
        if r["kind"] != "call":
            continue
        text = (flat_text(r["arguments"]) if r["arguments"] is not None else r["text"]).replace("\\/", "/")
        for u in urls_in(text):
            for where, enc, dec in b64_in_url(u):
                out.append({"index": n, "tool": r["tool"], "url": u, "where": where, "encoded": enc, "decoded": dec})
    return out


def injected_turns(rows) -> list:
    """Tool-output rows an instruction came from: [{index, row, why}], `why` a list of
      proven        a later tool call goes to a host that first appeared in this output and in no
                    user turn (the structure of the transcript says so)
      hidden        the output holds strong hidden text (tag characters, zero-width, display:none ...)
      instruction   the output reads as an instruction to a model (a classifier's verdict)"""
    marks = {}
    for c in external_calls(rows):
        if c["source_index"] is not None:
            marks.setdefault(c["source_index"], []).append("proven")
    for c in followed_values(rows):         # `followed`: a later call carries a value this output named
        marks.setdefault(c["source_index"], []).append("followed")
    for n, r in enumerate(rows):
        if r["kind"] != "result":
            continue
        if any(f["strong"] for f in hidden_text(r["text"])):
            marks.setdefault(n, []).append("hidden")
        if addresses_solver(r["text"]):
            marks.setdefault(n, []).append("instruction")
    return [{"index": n, "row": rows[n], "why": sorted(set(w))} for n, w in sorted(marks.items())]


# ---- MCP and agent configs -----------------------------------------------------------------------------------

_SERVER_KEYS = ("mcpServers", "mcp_servers", "servers", "context_servers", "mcp-servers")
_SCHEMA_KEYS = ("inputSchema", "input_schema", "parameters", "schema", "args_schema", "outputSchema")
RULES_NAMES = re.compile(r"(?:^|/)(?:\.cursorrules|\.windsurfrules|\.clinerules|agents\.md|claude\.md|gemini\.md|skill\.md|"
                         r"copilot-instructions\.md|[^/]*\.mdc|[^/]*system[_-]?prompt[^/]*|[^/]*\.rules|rules\.md|\.goosehints)$", re.I)


def _parse_config(data: bytes, name: str):
    obj, _ = load_json(data)
    if obj is not None:
        return obj
    low = name.lower()
    text = as_text(data)
    if text is None:
        return None
    if low.endswith(".toml"):
        try:
            import tomllib
            return tomllib.loads(text)
        except Exception:
            return None
    if low.endswith((".yaml", ".yml")):
        try:
            import yaml
            return yaml.safe_load(text)
        except Exception:
            return None
    return None


def _tool_of(d: dict):
    """(name, description, schema) when a dict is a tool definition, else None."""
    if not isinstance(d, dict):
        return None
    if d.get("type") == "function" and isinstance(d.get("function"), dict):
        d = d["function"]
    name = d.get("name")
    if not isinstance(name, str) or not name:
        return None
    schema = next((d[k] for k in _SCHEMA_KEYS if k in d), None)
    desc = d.get("description")
    if not (isinstance(desc, str) or isinstance(schema, dict)):
        return None
    return name, desc if isinstance(desc, str) else "", schema


def config_from(obj, name: str = "") -> dict:
    """{servers: [...], tools: [...]} of a parsed config or manifest.
    server: {name, command, args, url, env, headers, file}; tool: {name, description, schema, server,
    file, text} where `text` is everything a model would read of the tool."""
    servers, tools, done = [], [], set()

    def add_tool(d, server):
        t = _tool_of(d)
        if t is None:
            return False
        nm, desc, schema = t
        extra = [str(d.get(k)) for k in ("title", "annotations", "instructions", "meta", "_meta") if d.get(k)]
        text = "\n".join([desc] + ([json.dumps(schema, ensure_ascii=False)] if schema is not None else []) + extra)
        tools.append({"name": nm, "description": desc, "schema": schema, "server": server, "file": name, "text": text})
        return True

    def walk(o, server, depth):
        if depth > 8:
            return
        if isinstance(o, dict):
            for key in _SERVER_KEYS:
                block = o.get(key)
                if isinstance(block, dict) and block and all(isinstance(v, dict) for v in block.values()) and \
                        any(k in v for v in block.values() for k in ("command", "url", "args", "httpUrl", "serverUrl", "type", "transport", "tools", "cmd")):
                    done.add(id(block))
                    for sname, s in block.items():
                        args = s.get("args") if isinstance(s.get("args"), list) else []
                        servers.append({"name": str(sname), "command": s.get("command") or s.get("cmd"), "args": [str(a) for a in args],
                                        "url": s.get("url") or s.get("httpUrl") or s.get("serverUrl") or s.get("endpoint"),
                                        "env": s.get("env") if isinstance(s.get("env"), dict) else {},
                                        "headers": s.get("headers") if isinstance(s.get("headers"), dict) else {},
                                        "description": s.get("description") if isinstance(s.get("description"), str) else "", "file": name})
                        walk({k: v for k, v in s.items() if k not in ("env", "headers")}, str(sname), depth + 1)
                elif isinstance(block, list) and block and all(isinstance(v, dict) and ("command" in v or "url" in v) for v in block):
                    done.add(id(block))
                    for s in block:
                        sname = str(s.get("name") or s.get("id") or len(servers))
                        servers.append({"name": sname, "command": s.get("command"), "args": [str(a) for a in s.get("args") or []] if isinstance(s.get("args"), list) else [],
                                        "url": s.get("url") or s.get("endpoint"), "env": s.get("env") if isinstance(s.get("env"), dict) else {},
                                        "headers": s.get("headers") if isinstance(s.get("headers"), dict) else {},
                                        "description": s.get("description") if isinstance(s.get("description"), str) else "", "file": name})
                        walk({k: v for k, v in s.items() if k in ("tools",)}, sname, depth + 1)
            if "name_for_model" in o and "description_for_model" in o:      # a plugin manifest
                api = o.get("api") if isinstance(o.get("api"), dict) else {}
                tools.append({"name": str(o["name_for_model"]), "description": str(o["description_for_model"]), "schema": None,
                              "server": server, "file": name, "text": str(o["description_for_model"])})
                if api.get("url"):
                    servers.append({"name": str(o["name_for_model"]), "command": None, "args": [], "url": api["url"], "env": {},
                                    "headers": {}, "description": "", "file": name})
            here = o.get("serverInfo", {}).get("name") if isinstance(o.get("serverInfo"), dict) else None
            for k, v in o.items():
                if isinstance(v, (dict, list)) and id(v) not in done:
                    walk(v, server or here or (o.get("server") if isinstance(o.get("server"), str) else None), depth + 1)
        elif isinstance(o, list):
            for item in o:
                if isinstance(item, dict) and add_tool(item, server):
                    continue
                if isinstance(item, (dict, list)):
                    walk(item, server, depth + 1)

    walk(obj, None, 0)
    if isinstance(obj, dict) and not tools:
        add_tool(obj, None)
    return {"servers": servers, "tools": tools}


def read_config(data: bytes, name: str = "") -> dict:
    """{servers, tools} of one member; both empty when it is no config or manifest."""
    obj = _parse_config(data, name)
    if obj is None:
        return {"servers": [], "tools": []}
    try:
        return config_from(obj, name)
    except (RecursionError, TypeError, AttributeError):
        return {"servers": [], "tools": []}


def python_tools(data: bytes, name: str = "") -> dict:
    """{servers, tools} of a Python MCP server's source: every function under a decorator whose name
    ends in `tool` (`@mcp.tool()`, `@server.tool`, `@tool`), its docstring as the description (that
    is what FastMCP sends to the model), and the server's name from `FastMCP("...")`. The source is
    parsed with `ast` and never imported or run. The public tool-poisoning samples are in this form
    (invariantlabs' mcp-injection-experiments), not in JSON."""
    import ast
    empty = {"servers": [], "tools": []}
    if len(data) > MAX_TEXT or (b"tool" not in data) or (b"def " not in data):
        return empty
    try:
        tree = ast.parse(data.decode("utf-8", "replace"))
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return empty
    server = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", "")) in ("FastMCP", "Server", "MCPServer") \
                and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            server = node.args[0].value
            break
    tools = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            call = dec.func if isinstance(dec, ast.Call) else dec
            dname = getattr(call, "attr", getattr(call, "id", ""))
            if dname != "tool":
                continue
            tname, desc = node.name, ast.get_docstring(node, clean=True) or ""
            for kw in dec.keywords if isinstance(dec, ast.Call) else ():
                if kw.arg == "name" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    tname = kw.value.value
                if kw.arg == "description" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    desc = kw.value.value
            schema = {"type": "object", "properties": {a.arg: {} for a in node.args.args + node.args.kwonlyargs if a.arg not in ("self", "ctx")}}
            tools.append({"name": tname, "description": desc, "schema": schema, "server": server, "file": name,
                          "text": desc, "line": node.lineno})
            break
    if not tools:
        return empty
    # A description swapped in after the tool was declared (`f.__doc__ = "..."`, the "rug pull" of the
    # public WhatsApp sample): the model is sent the later text, so it is read as part of the tool's.
    by_func = {t["name"]: t for t in tools}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for tgt in node.targets:
                if isinstance(tgt, ast.Attribute) and tgt.attr == "__doc__" and isinstance(tgt.value, ast.Name) and tgt.value.id in by_func:
                    t = by_func[tgt.value.id]
                    t["description_swapped"] = node.value.value
                    t["text"] = (t["text"] + "\n" + node.value.value).strip()
    servers = [{"name": server, "command": None, "args": [], "url": None, "env": {}, "headers": {}, "description": "", "file": name}] if server else []
    return {"servers": servers, "tools": tools}


def tool_collisions(tools: list) -> list:
    """[{kind, names, tools}]:
      duplicate   one name defined more than once (by two servers, or twice with different text)
      shadowed    different names that draw the same (homoglyphs, invisible characters, case, - for _)
      references  a tool's text names another tool (a description that reaches into another tool)"""
    out = []
    by_name, by_skel = {}, {}
    for t in tools:
        by_name.setdefault(t["name"], []).append(t)
        by_skel.setdefault(skeleton(t["name"]), []).append(t)
    for name, group in by_name.items():
        if len(group) > 1 and len({(t["server"], t["file"], t["text"]) for t in group}) > 1:
            out.append({"kind": "duplicate", "names": [name], "tools": group})
    for skel, group in by_skel.items():
        names = sorted({t["name"] for t in group})
        if len(names) > 1:
            out.append({"kind": "shadowed", "names": names, "tools": group})
    names = sorted({t["name"] for t in tools if len(t["name"]) >= 4}, key=len, reverse=True)
    for t in tools:
        text = strip_invisible(t["text"])
        hit = [n for n in names if n != t["name"] and re.search(r"(?<![\w-])" + re.escape(n) + r"(?![\w-])", text)]
        if hit:
            out.append({"kind": "references", "names": [t["name"]] + hit, "tools": [t]})
    return out


def flagged_tools(tools: list) -> list:
    """[{tool, findings, why}] for tools that carry hidden text or read as an instruction.
    why: 'hidden' (strong hidden text in the description or schema), 'name' (invisible characters or
    lookalike letters in the name itself), 'instruction' (the classifier's verdict on the text)."""
    out = []
    for t in tools:
        every = hidden_text(t["text"])
        found = [f for f in every if f["strong"]]
        why = ["hidden"] if found else []
        if t["name"] != strip_invisible(t["name"]) or _CONF_RX.search(t["name"]):
            why.append("name")
        if addresses_solver(strip_invisible(t["text"])) or any(f["instruction"] for f in found):
            why.append("instruction")
        if not found and any(f.get("unread") for f in every):
            why.append("unread")        # invisible characters nothing here can read: a lead, never proof
        if why:
            out.append({"tool": t, "findings": found, "why": why})
    return out


# ---- RAG corpora ---------------------------------------------------------------------------------------------

_TEXT_KEYS = ("text", "page_content", "pageContent", "content", "document", "chunk", "body", "passage", "chunk_text", "contents")
_ID_KEYS = ("id", "doc_id", "chunk_id", "document_id", "_id", "uuid", "key", "node_id", "id_", "docid")
_VEC_KEYS = ("embedding", "vector", "values", "embeddings", "dense_vector")
_WRAP_KEYS = ("docs", "documents", "chunks", "records", "items", "data", "nodes", "points", "vectors", "corpus", "passages",
              "entries", "docstore", "_dict", "docstore/data", "store", "results", "matches", "rows")


def cosine(a, b) -> float:
    """Cosine similarity of two equal-length vectors; 0.0 when either has no length."""
    if len(a) != len(b) or not a:
        return 0.0
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    if not na or not nb:
        return 0.0
    return sum(x * y for x, y in zip(a, b)) / (na * nb)


def argmax(xs) -> int:
    """Index of the largest value (the first of equals); -1 for an empty list."""
    best, at = None, -1
    for i, x in enumerate(xs):
        if best is None or x > best:
            best, at = x, i
    return at


def nearest(query, docs: list, k: int = 1) -> list:
    """[(score, doc)] best first: cosine of `query` against each doc's embedding of the same length."""
    scored = [(cosine(query, d["embedding"]), d) for d in docs if d.get("embedding") and len(d["embedding"]) == len(query)]
    scored.sort(key=lambda sd: -sd[0])
    return scored[:k]


def _vector(v):
    if isinstance(v, list) and v and len(v) <= 8192 and all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in v):
        return [float(x) for x in v]
    return None


def _doc(d: dict, key=None, position=None, name=""):
    """A document from one dict, or None when it holds no text."""
    inner = d
    for wrap in ("__data__", "payload", "metadata", "data", "kwargs", "document", "node", "fields"):
        if not any(isinstance(inner.get(k), str) for k in _TEXT_KEYS):
            w = _maybe_json(inner.get(wrap))
            if isinstance(w, dict) and any(isinstance(w.get(k), str) for k in _TEXT_KEYS):
                inner = w
                break
    text = next((inner[k] for k in _TEXT_KEYS if isinstance(inner.get(k), str)), None)
    if text is None or "role" in d or "tool_calls" in d:
        return None
    ident = next(((k, d[k]) for k in _ID_KEYS if isinstance(d.get(k), (str, int)) and not isinstance(d.get(k), bool)), None) \
        or next(((k, inner[k]) for k in _ID_KEYS if isinstance(inner.get(k), (str, int)) and not isinstance(inner.get(k), bool)), None)
    ids = []                    # every id-like value the record carries: two different ones make the id a choice
    for src_d in (d, inner):
        for k in _ID_KEYS:
            v = src_d.get(k)
            if isinstance(v, (str, int)) and not isinstance(v, bool) and str(v).strip() and str(v) not in [x for _, x in ids]:
                ids.append(("field:" + k, str(v)))
    if key is not None and str(key) not in [x for _, x in ids]:
        ids.append(("key", str(key)))
    if ident is not None:
        doc_id, src = str(ident[1]), "field:" + ident[0]
    elif key is not None:
        doc_id, src = str(key), "key"
    else:
        doc_id, src = str(position), "position"
    meta = next((m for m in (d.get("metadata"), inner.get("metadata"), d.get("meta"), d.get("payload")) if isinstance(m, dict)), {})
    vec = next((v for v in (_vector(d.get(k)) for k in _VEC_KEYS) if v), None) or next((v for v in (_vector(inner.get(k)) for k in _VEC_KEYS) if v), None)
    return {"id": doc_id, "id_source": src, "ids": ids, "text": text, "meta": meta, "embedding": vec, "file": name}


def docs_from(obj, name: str = "", depth: int = 0) -> list:
    """Documents of a parsed JSON docstore (see read_docs)."""
    if depth > 4:
        return []
    if isinstance(obj, dict):
        ids, texts = obj.get("ids"), obj.get("documents")
        if isinstance(ids, list) and isinstance(texts, list) and len(ids) == len(texts) and ids:       # Chroma get()
            if ids and isinstance(ids[0], list) and len(ids) == 1:                                     # Chroma query(): one list per query
                ids, texts = ids[0], texts[0]
                metas = (obj.get("metadatas") or [[]])[0] if isinstance(obj.get("metadatas"), list) else []
                vecs = (obj.get("embeddings") or [[]])[0] if isinstance(obj.get("embeddings"), list) and obj.get("embeddings") else []
            else:
                metas, vecs = obj.get("metadatas") or [], obj.get("embeddings") or []
            out = []
            for n, (i, t) in enumerate(zip(ids, texts)):
                if isinstance(t, str):
                    out.append({"id": str(i), "id_source": "field:ids", "text": t, "meta": metas[n] if n < len(metas) and isinstance(metas[n], dict) else {},
                                "embedding": _vector(vecs[n]) if n < len(vecs) else None, "file": name})
            return out
        for k in _WRAP_KEYS:
            if isinstance(obj.get(k), (list, dict)):
                got = docs_from(obj[k], name, depth + 1)
                if got:
                    return got
        vals = [v for v in obj.values() if isinstance(v, dict)]
        if len(vals) >= 2 and len(vals) == len(obj):                                                     # an id -> document map
            out = [d for d in (_doc(v, key=k, name=name) for k, v in obj.items()) if d]
            if len(out) == len(obj):
                return out
        return []
    if isinstance(obj, list) and obj and all(isinstance(x, dict) for x in obj[:MAX_ROWS]):
        out = [d for d in (_doc(x, position=n, name=name) for n, x in enumerate(obj[:MAX_ROWS])) if d]
        return out if out and len(out) >= 0.8 * len(obj[:MAX_ROWS]) else []
    return []


def docs_from_sqlite(data: bytes, name: str = "") -> list:
    """Documents of a Chroma sqlite file (embeddings + embedding_metadata, vectors from
    embeddings_queue), or of any sqlite table with a text column. Read in memory, nothing written."""
    import sqlite3
    if bytes(data[:16]) != b"SQLite format 3\x00" or len(data) > MAX_SQLITE:
        return []
    out = []
    try:
        con = sqlite3.connect(":memory:")
        con.deserialize(bytes(data))
        con.execute("PRAGMA query_only = ON")
        con.execute("PRAGMA trusted_schema = OFF")
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        if "embeddings" in tables and "embedding_metadata" in tables:
            ids = dict(con.execute("SELECT id, embedding_id FROM embeddings"))
            meta = {}
            for rid, key, sv, iv, fv in con.execute("SELECT id, key, string_value, int_value, float_value FROM embedding_metadata"):
                meta.setdefault(rid, {})[key] = sv if sv is not None else (iv if iv is not None else fv)
            vecs = {}
            if "embeddings_queue" in tables:
                try:
                    for eid, blob in con.execute("SELECT id, vector FROM embeddings_queue WHERE vector IS NOT NULL"):
                        if isinstance(blob, bytes) and len(blob) % 4 == 0 and blob:
                            vecs[eid] = list(struct.unpack(f"<{len(blob) // 4}f", blob))
                except sqlite3.Error:
                    pass
            for rid, eid in ids.items():
                m = meta.get(rid, {})
                text = m.pop("chroma:document", None)
                if isinstance(text, str):
                    out.append({"id": str(eid), "id_source": "field:embedding_id", "text": text, "meta": m, "embedding": vecs.get(eid), "file": name})
            if out:
                return out
        for table in tables:
            if table.startswith("sqlite_") or not re.fullmatch(r"\w+", table):
                continue
            cols = [r[1] for r in con.execute(f'PRAGMA table_info("{table}")')]
            tcol = next((c for c in cols if c.lower() in _TEXT_KEYS), None)
            if not tcol:
                continue
            icol = next((c for c in cols if c.lower() in _ID_KEYS), None)
            sel = f'SELECT {"rowid" if not icol else chr(34) + icol + chr(34)}, "{tcol}" FROM "{table}" LIMIT {MAX_ROWS}'
            for ident, text in con.execute(sel):
                if isinstance(text, str):
                    out.append({"id": str(ident), "id_source": f"field:{icol}" if icol else "rowid", "text": text,
                                "meta": {"table": table}, "embedding": None, "file": name})
    except (sqlite3.Error, AttributeError, struct.error, ValueError):
        return out
    return out


def read_docs(data: bytes, name: str = "") -> list:
    """Documents of a structured store: JSON, JSONL or sqlite. [] for anything else."""
    if bytes(data[:16]) == b"SQLite format 3\x00":
        return docs_from_sqlite(data, name)
    obj, _ = load_json(data)
    if obj is None:
        return []
    try:
        return docs_from(obj, name)
    except (RecursionError, TypeError, AttributeError):
        return []


_DOC_EXT = (".md", ".markdown", ".txt", ".html", ".htm", ".pdf", ".rst", ".mdx")


def text_doc(name: str, data: bytes):
    """A markdown, HTML, text or PDF member as a document whose id is its path."""
    short = name.split(ARROW)[-1]
    if not short.lower().endswith(_DOC_EXT):
        return None
    text = pdf_text(bytes(data)) if bytes(data[:5]) == b"%PDF-" else as_text(data)
    if text is None:
        return None
    return {"id": short, "id_source": "path", "text": text, "meta": {}, "embedding": None, "file": name}


def poisoned_docs(docs: list, findings_by_file=None) -> list:
    """[{doc, findings, why}]: 'hidden' when the document's text (or, for a file document, its bytes)
    holds strong hidden text, 'instruction' when it reads as an instruction to a model."""
    out = []
    for d in docs:
        every = hidden_text(d["text"])
        if d["id_source"] == "path" and findings_by_file is not None:
            every = findings_by_file.get(d["file"], [])
        found = [f for f in every if f["strong"]]
        why = ["hidden"] if found else []
        if addresses_solver(strip_invisible(d["text"])) or any(f["instruction"] for f in found):
            why.append("instruction")
        if not found and any(f.get("unread") for f in every):
            why.append("unread")        # invisible characters nothing here can read: a lead, never proof
        if why:
            out.append({"doc": d, "findings": found, "why": why})
    return out


# ---- everything a delivery holds --------------------------------------------------------------------------------

def analyse(files: dict) -> dict:
    """{traces: {file: rows}, servers, tools, docs, text_docs, findings, rules: [file]} over the files a
    solver is handed. Nothing is decided here; the toolkit reads the question and then this."""
    traces, servers, tools, docs, text_docs, findings, rules = {}, [], [], [], [], [], []
    for name, data in unique_files(files):
        short = name.split(ARROW)[-1]
        if data[:4] in (b"PK\x03\x04", b"PK\x05\x06") or data[:6] == b"7z\xbc\xaf\x27\x1c":
            continue
        if data[:16] == b"SQLite format 3\x00":
            docs += docs_from_sqlite(data, name)
            continue
        structured = False
        obj, _ = load_json(data)
        if obj is not None:
            try:
                rows = trace_rows(obj)
            except (RecursionError, TypeError, ValueError, AttributeError):
                rows = []
            if is_trace(rows):
                traces[name] = rows
                structured = True
            try:
                cfg = config_from(obj, name)
            except (RecursionError, TypeError, AttributeError):
                cfg = {"servers": [], "tools": []}
            servers += cfg["servers"]
            tools += cfg["tools"]                   # a transcript's request may declare tools as well
            structured = structured or bool(cfg["servers"] or cfg["tools"])
            if not structured:
                try:
                    got = docs_from(obj, name)
                except (RecursionError, TypeError, AttributeError):
                    got = []
                docs += got
        elif short.lower().endswith((".toml", ".yaml", ".yml")):
            cfg = read_config(data, name)
            servers += cfg["servers"]
            tools += cfg["tools"]
        elif short.lower().endswith(".py"):
            cfg = python_tools(data, name)
            servers += cfg["servers"]
            tools += cfg["tools"]
        elif short.lower().endswith((".txt", ".log", ".md", ".transcript", ".chat")) or "." not in Path(short).name:
            text = as_text(data)
            rows = text_trace(text) if text and len(data) <= MAX_TEXT else []
            if rows:
                traces[name] = rows
        if RULES_NAMES.search(short):
            rules.append(name)
        d = text_doc(name, data)
        if d is not None:
            text_docs.append(d)
        if obj is not None:
            findings += scan_json(name, obj)
        elif len(data) <= MAX_TEXT * 4:
            findings += scan(name, data)
        elif len(data) <= MAX_ANSI:         # too long to scan as text, not too long for a terminal capture
            found = ansi_hidden(bytes(data))
            for f in found:
                f["file"] = name
            findings += found
    return {"traces": traces, "servers": servers, "tools": tools, "docs": docs, "text_docs": text_docs,
            "findings": findings, "rules": rules}
