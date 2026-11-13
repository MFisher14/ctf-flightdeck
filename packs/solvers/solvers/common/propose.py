#!/usr/bin/env python3
"""Evidence-ranked candidate values for a question no shipped reader answers (the adaptability build).

On a release morning a NEW component stops Layer 1, and an agent then spends 48 s to 5 min writing the
reader (Day 20: Mobile +48 s, Metadata +77 s, Binary +85 s). The untimed base and every attempt with no
deadline (`"start": "regular"`) let the judge check a few candidates for free (row 346; the organizer
ruled that guesses to the Game Master are fine). This module proposes them, from the bytes and the
question's STATED spec only, and never answers anything plain:

  spec(q)                        what the question states: magic tokens, typed fields at +N, paths, a
                                 dotted property, a member prefix, "final"/"last", the answer format
  field_word(lane, q)            the id's field word, the way the lane's own readers name it (dispatch
                                 key of a day_patch skeleton: by field word, never by question text)
  members(q, files)              the (name, bytes) the question names: its artifact member, its dNN--
                                 prefix, a path it names; else every member
  propose(q, files)              [(hypothesis name, value)], best evidence first, at most 12, or []
  candidates_for(q, files, key)  labels.candidates(key, propose(q, files)) or None
  respell(value, q, lane)        the RE-SPELLER tier (#2): render_candidates renderings of a value a reader
                                 ALREADY read whose spelling/order/encoding the judge has not accepted; it
                                 re-spells a known value rather than finding a new one. respell_candidates()
                                 wraps it as a labels.candidates pick. Never plain, probed no-deadline only.

What it proposes, by the answer kind (each option's NAME names the hypothesis, never the value, so the
name the judge accepts answers the next variant with that variant's own value):

  integer   for each stated magic token found in the named member (its final copy first when the text
            says final or last): `offset_last:<TOK>`, `offset_first:<TOK>`, each stated typed field read
            at the magic (`field:<name>`), `size_from_last:<TOK>` (member length minus the offset); and a
            stated key/value `<field word>: <number>` in a text member (`kv:<member>`)
  pattern   a literal prefix and an N-character hex/alnum class read from the syntax (`ANS-` followed by
            exactly 16 uppercase hexadecimal characters): every distinct exact match in the bytes, ASCII
            and UTF-16LE: `only_in:<member>` when the member holds exactly one code (the hypothesis
            that carries to the next variant), else `in:<member>@<digest>#<n>`, the n-th code of THAT
            member's bytes (scoped to this delivery: an accepted rank never answers another variant)
  enum      the accepted values that occur in the named members' bytes: `only_listed` when exactly one
            occurs; several are ranked by first place as `listed_rank@<digest>#<n>`, scoped to this
            delivery's bytes. Never `listed:<value>`: a name that is the value would answer, plain, every
            later variant that holds those bytes anywhere
  exact_text / json   a stated key/value `<field word>: <value>` in a text member (`kv:<member>`)

Bounded by bytes and counts, never by a clock: at most 8 members, 4 MiB a member, 12 options. A raise
anywhere is no proposal ([]). Nothing here is a verdict: every option goes out only through
labels.candidates, probed by tools/verify.py on the base and by the runners only without a deadline.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

MAX_OPTIONS = 12
MAX_MEMBERS = 8
MAX_BYTES = 4 << 20
LANE_PREFIX = {"binary-reverse-engineering": "binary", "metadata-forensics": "metadata",
               "mobile-android": "mobile", "warmups": "warmups", "script-analysis": "script"}

# Upper-case words of the lane's own prose that are never a magic of the delivery.
NOT_MAGIC = {"ZIP", "JSON", "CRC", "CRC32", "SHA", "SHA1", "SHA256", "MD5", "ELF", "ELF64", "ELF32", "PE", "PE32",
             "ASCII", "UTF", "UTF8", "UTF16", "DEX", "APK", "HEX", "XOR", "AES", "RC4", "ANS", "URL", "API", "ID",
             "DNS", "HTTP", "HTTPS", "TLS", "DLL", "EXE", "NUL", "LE", "BE", "MOB", "XML", "CPU", "ATT", "CK",
             "MITRE", "JAR", "SO", "UTC", "ISO", "OS", "IP", "DAY", "RVA", "VA", "TOK"}
TYPES = {"u8": (1, "little"), "u16le": (2, "little"), "u16be": (2, "big"), "u32le": (4, "little"),
         "u32be": (4, "big"), "u64le": (8, "little"), "u64be": (8, "big")}
# Bare widths (no endianness stated): read little-endian first, big-endian second (family of integer shapes).
BARE_WIDTH = {"u8": 1, "u16": 2, "u32": 4, "u64": 8}
# Explicit endian types come first in the alternation so `u32le` is read as u32le, not as a bare u32.
FIELD_RE = re.compile(r"([A-Za-z][A-Za-z0-9_ ]{0,40}?)\s+(u8|u16le|u16be|u32le|u32be|u64le|u64be|u16|u32|u64)"
                      r"\s+at\s+\+(\d{1,5})")
# Field words whose answer is a COUNT of a stated magic's occurrences, not an offset or a typed read.
COUNT_WORDS = {"count", "number", "num", "entries", "records", "occurrences", "instances", "total", "many"}
MAGIC_RE = re.compile(r"(?<![A-Za-z0-9_])([A-Z][A-Z0-9]{2,7})(?![A-Za-z0-9_])")
PATH_RE = re.compile(r"(?<![\w/.-])((?:[\w-]+/)*[\w-]+\.(?:dex|bin|json|so|jar|apk|xml|txt|zip|exe|dll|elf|dat|cfg|ini|"
                     r"plist|db|sqlite|png|jpg|gif|pdf|docx?|xlsx?|ps1|js|vbs|bat|py))(?![\w])")
DOTTED_RE = re.compile(r"\b([a-z][a-z0-9]*\.[a-z][a-z0-9_]*)\b")
PREFIX_RE = re.compile(r"\b(d\d{1,2})--")


def _qid(q) -> str:
    return re.sub(r"^set\d+\.", "", str(q.get("qid") or q.get("answer_id") or q.get("id") or ""))


def field_word(lane: str, q) -> str:
    """The id's field word, as the lane's own readers name it. Binary: the id without setN. and dNN_
    (judged_syntax.json's field); Metadata: the dotted property the question names after `Determine`
    (properties_strict resolves it the same way), else the id; Script Analysis: q["field"], else the id
    without its first two words; every other lane: the id without setN."""
    qid = _qid(q)
    if lane.startswith("binary"):
        return re.sub(r"^d\d+_", "", qid)
    if lane.startswith("metadata"):
        m = re.search(r"\bDetermine\s+([a-z][a-z0-9]*\.[a-z0-9_.]+?)\s+for\b", str(q.get("question") or ""))
        return m.group(1) if m else qid
    if lane.startswith("script"):
        got = q.get("field")
        if isinstance(got, str) and got:
            return got
        parts = qid.split("-", 2)
        return parts[2] if len(parts) == 3 else qid
    return qid


def spec(q) -> dict:
    """The stated spec of one question, read from its text and answer format only (data, not orders)."""
    text = str(q.get("question") or "")
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    syntax = str(fmt.get("syntax") or "")
    low = text.lower()
    magics = []
    for tok in MAGIC_RE.findall(text):
        if tok not in NOT_MAGIC and tok not in magics and not re.fullmatch(r"T\d{4}", tok):
            magics.append(tok)
    fields = []
    for name, typ, off in FIELD_RE.findall(text):
        name = re.sub(r"^(?:and|read|then|the|with|a|an)\s+", "", name.strip(), flags=re.I).strip()
        name = re.sub(r"\s+", "_", name.lower())
        fields.append({"name": name, "type": typ, "offset": int(off)})
    art = q.get("artifact") if isinstance(q.get("artifact"), str) else ""
    member = q.get("member") or (art.split("->")[-1].strip() if "->" in art else None)
    return {
        "kind": fmt.get("kind"), "syntax": syntax, "accepted_values": fmt.get("accepted_values"),
        "member": member, "prefix": (PREFIX_RE.search(text).group(1) if PREFIX_RE.search(text) else None),
        "magics": magics[:6], "fields": fields[:12],
        "paths": list(dict.fromkeys(PATH_RE.findall(text)))[:6],
        "dotted": list(dict.fromkeys(DOTTED_RE.findall(text)))[:4],
        "final": bool(re.search(r"\b(final|last|trailing)\b", low)),
        "zero_based": "zero-based" in low or "0-based" in low,
        "endian": "little" if "little-endian" in low else ("big" if "big-endian" in low else None),
        "base10": bool(re.search(r"base[- ]?10|decimal", low + " " + syntax.lower())),
    }


def _leaf(name: str) -> str:
    return name.split(" -> ")[-1]


def members(q, files: dict, sp: dict | None = None) -> list:
    """[(name, bytes)] the question names, at most MAX_MEMBERS: its artifact member, its dNN-- prefix
    (central-directory order as `files` keeps it), a path it names; else every member that is no archive."""
    sp = sp or spec(q)
    items = [(n, d) for n, d in (files or {}).items() if isinstance(d, (bytes, bytearray)) and len(d) <= MAX_BYTES]
    if any(" -> " in n for n, _ in items):
        # The delivery itself (an archive whose members are listed) is the container, never the member asked.
        items = [(n, d) for n, d in items if " -> " in n or bytes(d[:4]) != b"PK\x03\x04"]
    out = []

    def add(n, d):
        if all(bytes(d) != bytes(x) for _, x in out):
            out.append((n, d))

    if sp.get("member"):
        want = sp["member"].split("/")[-1].lower()
        for n, d in items:
            if _leaf(n).split("/")[-1].lower() == want:
                add(n, d)
    if sp.get("prefix"):
        for n, d in items:
            if _leaf(n).split("/")[-1].lower().startswith(sp["prefix"] + "--"):
                add(n, d)
    for p in sp.get("paths") or ():
        for n, d in items:
            if _leaf(n).lstrip("./").lower().endswith(p.lower()):
                add(n, d)
    if not out:
        for n, d in items:
            if not bytes(d[:4]) in (b"PK\x03\x04",):
                add(n, d)
    return out[:MAX_MEMBERS]


def _scope(data: bytes) -> str:
    """A name part that holds only for these exact bytes (a delivery-scoped hypothesis)."""
    import hashlib
    return hashlib.sha256(bytes(data)).hexdigest()


def _finds(data: bytes, needle: bytes, limit: int = 64) -> list:
    hits, i = [], data.find(needle)
    while i >= 0 and len(hits) < limit:
        hits.append(i)
        i = data.find(needle, i + 1)
    return hits


# ------------------------------------------------------------------------------------------------ the stated-shape tier
#
# An exact_text/json answer whose FIELD names a stated SHAPE -- a url, a path, a domain, an email, an ipv4 --
# that sits in the named member's bytes WITHOUT a `field: value` key is reached by neither the literal-prefix
# pattern tier (ANS-...) nor the `field: value` kv tier (the field word does not sit beside the value). This
# tier scans the named member for values of the shape the field names and offers the distinct matches as
# evidence-ranked hypotheses -- exactly as the pattern tier does for a prefix+class code. Bright-line-safe:
# like every propose() output it is consumed ONLY through labels.candidates (never a plain value), it is
# bounded by bytes/members/counts (never a clock), and a field that names no shape -- or bytes that hold no
# match of it -- yields nothing (no guess). It is the morning-of "find the C2 url / payload path" question
# (adaptable-machinery-report.md: md_c2_url, script_stager_url) turned from an unreachable live fix into a
# one-probe close. Scoped per delivery exactly as the pattern tier (`@<digest>#<n>` for several matches), so
# an accepted rank never answers another variant; a sole match is `only_<shape>:<member>`, a carry hypothesis.
STATED_SHAPES = ("url", "domain", "email", "ipv4", "path")
_SHAPE_RE = {
    "url": re.compile(rb"https?://[^\s\"'<>)\]}]{3,512}"),
    "email": re.compile(rb"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}"),
    "ipv4": re.compile(rb"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])"),
    "domain": re.compile(rb"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}", re.I),
    "path": re.compile(rb"(?:[A-Za-z]:\\|\\\\|/)[^\s\"'<>)\]}]{3,512}"),
}
# The field/question words that name each shape. The scan runs only when one of these occurs in the id's
# field word or the question text, so an ordinary exact_text label (a compression scheme, a role) never
# triggers a URL/IP scan.
_SHAPE_WORDS = {
    "url": ("url", "uri", "link", "callback", "c2", "beacon", "endpoint", "download", "stager", "exfil"),
    "email": ("email", "mail", "sender", "recipient"),
    "ipv4": ("ip", "ipv4", "address", "host"),
    "domain": ("domain", "hostname", "fqdn", "host"),
    "path": ("path", "filepath", "directory", "folder"),
}


def _shapes_for(q, lane: str) -> list:
    """The stated shapes the id's field/question names (url before the others, it being the most specific
    reading of a callback), or [] -- only for an exact_text / json answer (an enum/integer/pattern names its
    own shape). Never raises."""
    try:
        field = field_word(lane, q) if lane else _qid(q)
    except Exception:  # noqa: BLE001
        field = ""
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    if (fmt.get("kind") or "").lower() not in ("exact_text", "json", ""):
        return []
    hay = (str(field) + " " + str(q.get("question") or "")).lower()
    tokens = {t for t in re.split(r"[^a-z0-9]+", hay) if t}
    out = [s for s, words in _SHAPE_WORDS.items() if any(w in tokens for w in words)]
    return sorted(set(out), key=lambda s: (s != "url", s))


def stated_shape_options(q, files: dict, lane: str = "", sp: dict | None = None, mem: list | None = None) -> list:
    """`[(hypothesis name, value)]` for an exact_text/json answer whose field names a stated shape
    (url/path/domain/email/ipv4) found literally in the named member's bytes, best (most specific) shape
    first and in byte order within a member, at most MAX_OPTIONS; [] when the field names no shape or no
    clean match is found (no guess). Scoped per delivery like the pattern tier; never plain, never raises."""
    shapes = _shapes_for(q, lane)
    if not shapes:
        return []
    sp = sp or spec(q)
    mem = mem if mem is not None else members(q, files, sp)
    opts: list = []
    for shape in shapes:
        rx = _SHAPE_RE[shape]
        for name, data in mem:
            if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_BYTES:
                continue
            blob = bytes(data)
            found: list = []
            for m in rx.finditer(blob):
                v = m.group(0).decode("latin-1")
                if v not in found:
                    found.append(v)
            leaf = _leaf(name)
            for i, v in enumerate(found, 1):
                nm = f"only_{shape}:{leaf}" if len(found) == 1 else f"{shape}@{_scope(blob)}#{i}"
                if all(n != nm for n, _ in opts):
                    opts.append((nm, v))
                if len(opts) >= MAX_OPTIONS:
                    return opts[:MAX_OPTIONS]
    return opts[:MAX_OPTIONS]


def is_stated_shape_name(name) -> bool:
    """True when `name` is a stated-shape tier hypothesis (`only_<shape>:...` or `<shape>@<digest>#<n>`). Lets
    a caller tell the shape tier's candidates apart from the kv/pattern/integer tiers'. Never raises."""
    head = str(name).split(":", 1)[0].split("@", 1)[0]
    return head in STATED_SHAPES or any(head == "only_" + s for s in STATED_SHAPES)


def _syntax_pattern(syntax: str):
    """A regex for an exact answer stated as a literal prefix and an N-character class, or None. The class word
    (hex / alphanumeric / digit) is optional: with none stated it defaults to alphanumeric, so a prefix and a
    length alone (`KEY- followed by exactly 8 characters`) still name a scope."""
    m = re.search(r"([A-Z][A-Z0-9_]*-)\s+followed by exactly\s+(\d{1,3})\s+(uppercase |lowercase )?"
                  r"(hexadecimal|hex|alphanumeric|alphanum|digit|character|char)", syntax, flags=re.I)
    if not m:
        return None
    prefix, n, case, klass = m.group(1), int(m.group(2)), (m.group(3) or "").strip().lower(), m.group(4).lower()
    if klass.startswith("hex"):
        cls = "0-9A-F" if case == "uppercase" else ("0-9a-f" if case == "lowercase" else "0-9A-Fa-f")
    elif klass == "digit":
        cls = "0-9"
    else:   # alphanumeric, or a bare "characters" count with no class word
        cls = "0-9A-Z" if case == "uppercase" else ("0-9a-z" if case == "lowercase" else "0-9A-Za-z")
    return re.compile(re.escape(prefix).encode() + b"[" + cls.encode() + b"]{" + str(n).encode() + b"}(?![" +
                      cls.encode() + b"])")


# A stated /regex/ in the question or syntax, with no backreferences or named groups (a flag or token shape).
_SLASH_RE = re.compile(r"(?<![\w/])/([^/\s][^/]{1,120})/(?![\w])")


def _question_regex(*texts):
    """A compiled BYTES regex for a stated `/.../` pattern (e.g. /HTB\\{[a-f0-9]{8}\\}/), or None. The match's
    whole text (group 0) is the exact answer the question names, so every distinct one in the bytes is a scoped
    candidate just as a literal-prefix pattern is. Anchored and group-free matches only; never raises."""
    for t in texts:
        if not t:
            continue
        m = _SLASH_RE.search(t)
        if not m:
            continue
        body = m.group(1)
        if "(?P" in body or re.search(r"\\[1-9]", body):   # named or back-references are not a value shape
            continue
        if not re.search(r"[\\\[\]{}+*?|()]", body):        # a plain slash-delimited word (a path) is not a pattern
            continue
        try:
            return re.compile(body.encode())
        except re.error:
            continue
    return None


def _kv(word: str, data: bytes, numeric: bool):
    """Values stated as `<word>: value` / `"<word>": value` / `<word>=value` in a text member."""
    if len(data) > (1 << 20) or not word:
        return []
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError:
        return []
    spell = {word, word.replace("_", "-"), re.sub(r"_([a-z])", lambda m: m.group(1).upper(), word)}
    vals = []
    for w in spell:
        pat = r"[\"']?" + re.escape(w) + r"[\"']?\s*[:=]\s*(?:\"([^\"\n]{1,200})\"|'([^'\n]{1,200})'|([^\s,;}\]]{1,200}))"
        for m in re.finditer(pat, text):
            v = next(g for g in m.groups() if g is not None)
            if numeric and not re.fullmatch(r"-?\d+", v):
                continue
            if v not in vals:
                vals.append(v)
    return vals


def _enum_evidence(value: str, mem: list):
    """How strongly an accepted enum value occurs in the named members: (whole-token count, substring count,
    first byte position). A whole-token hit (the value bounded by non-alphanumeric bytes) is the uniqueness
    guard that keeps `arm` from outranking `arm64` when only `arm64` is present. Case-insensitive; never raises."""
    needle = value.lower().encode()
    if not needle:
        return 0, 0, -1
    try:
        wrx = re.compile(rb"(?<![a-z0-9])" + re.escape(needle) + rb"(?![a-z0-9])")
    except re.error:
        wrx = None
    whole = sub = 0
    first = -1
    for _, d in mem:
        blob = bytes(d).lower()
        i = blob.find(needle)
        while i >= 0:
            sub += 1
            if first < 0:
                first = i
            i = blob.find(needle, i + 1)
        if wrx is not None:
            whole += len(wrx.findall(blob))
    return whole, sub, first


def stated_by(questions, q) -> dict:
    """The magics and typed fields the OTHER questions of q's component state (same dNN-- prefix, or the
    whole set when q names none): Day 20 stated the RS20 layout in every config_* question and asked
    `hcfg_resource_size` in one that names only the field. {"magics": [...], "fields": [...]}."""
    own = spec(q)
    mags, flds = [], []
    for o in questions or ():
        if o is q or o.get("id") == q.get("id"):
            continue
        so = spec(o)
        if own.get("prefix") and so.get("prefix") != own.get("prefix"):
            continue
        mags += [m for m in so["magics"] if m not in mags]
        flds += [f for f in so["fields"] if f not in flds]
    return {"magics": mags[:6], "fields": flds[:12]}


def propose(q, files: dict, lane: str = "", stated: dict | None = None) -> list:
    """[(hypothesis name, value)], best evidence first, at most MAX_OPTIONS; [] for no evidence.
    `stated` adds the component's stated magics and fields (stated_by), after the question's own."""
    try:
        return _propose(q, files, lane, stated)[:MAX_OPTIONS]
    except Exception:  # noqa: BLE001 - a proposal never costs an answer
        return []


SIZE_WORDS = {"size", "length", "len", "count"}


def _toks(word: str) -> set:
    toks = {t for t in re.split(r"[^a-z0-9]+", word.lower()) if len(t) > 2}
    return toks | SIZE_WORDS if toks & SIZE_WORDS else toks


def _propose(q, files, lane, stated=None):
    sp = spec(q)
    if stated:
        sp["magics"] = sp["magics"] + [m for m in stated.get("magics") or () if m not in sp["magics"]]
        sp["fields"] = sp["fields"] + [f for f in stated.get("fields") or () if f not in sp["fields"]]
    kind = (sp.get("kind") or "").lower()
    mem = members(q, files, sp)
    word = field_word(lane, q) if lane else _qid(q)
    leafword = re.sub(r"^(analysis|config)_", "", word.split(".")[-1])
    opts: list = []

    def add(name, value):
        value = str(value)
        if all(n != name for n, _ in opts):
            opts.append((name, value))

    if kind == "integer":
        for tok in sp["magics"]:
            for n, d in reversed(mem) if sp["final"] else mem:
                hits = _finds(bytes(d), tok.encode())
                if not hits:
                    continue
                order = [hits[-1], hits[0]] if sp["final"] else [hits[0], hits[-1]]
                tag = "last" if sp["final"] else "first"
                add(f"offset_{tag}:{tok}", order[0])
                if order[1] != order[0]:
                    add(f"offset_{'first' if tag == 'last' else 'last'}:{tok}", order[1])
                at = order[0]
                for f in sp["fields"]:
                    # a stated endian is read as stated; a bare width (u16/u32/u64) is read little-endian
                    # first and big-endian second (never both of a value counts as a rejection: one is right)
                    typ = f["type"]
                    if typ in TYPES:
                        reads = [("", *TYPES[typ])]
                    elif typ in BARE_WIDTH:
                        w = BARE_WIDTH[typ]
                        reads = [("", w, "little")] + ([("~be", w, "big")] if w > 1 else [])
                    else:
                        reads = []
                    for suffix, size, end in reads:
                        if at + f["offset"] + size <= len(d):
                            add(f"field:{f['name']}{suffix}",
                                int.from_bytes(bytes(d[at + f["offset"]:at + f["offset"] + size]), end))
                add(f"size_from_{tag}:{tok}", len(d) - at)
                # the number of this magic's copies in the member: the answer to a `count`/`number of` id
                add(f"count:{tok}", len(hits))
                break
        # The stated field sharing the most words with the id's field goes first (size, length, len and
        # count are one word); an id whose field says offset takes the magic's offsets first; an id whose
        # field word is a count word (count/number/entries/...) takes the magic's occurrence count first --
        # but ONLY when the question states no typed field of that name. A field literally named `record_count`
        # (with `record_count u32le at +8` stated) wants that field's value, not the magic's occurrence count:
        # the stated typed read `named` beats the raw count whenever one is present (a count word in a field
        # NAME is not a "how many" question). Ranking only; every option is a candidate, never plain.
        if leafword:
            raw = {t for t in re.split(r"[^a-z0-9]+", leafword.lower()) if len(t) > 2}
            want = _toks(leafword) - {"analysis", "config"}
            named = sorted([o for o in opts if o[0].startswith("field:") and _toks(o[0][6:]) & want],
                           key=lambda o: -len(_toks(o[0][6:]) & want))
            offsets = [o for o in opts if o[0].startswith("offset_")]
            counts = [o for o in opts if o[0].startswith("count:")]
            if raw & COUNT_WORDS and not named:
                first = counts
            elif "offset" in leafword:
                first = offsets
            else:
                first = named
            opts = first + [o for o in opts if o not in first]
        for n, d in mem:
            for v in _kv(leafword, bytes(d), numeric=True)[:2]:
                add(f"kv:{_leaf(n)}", v)
    elif kind == "pattern":
        # a literal-prefix-and-class form first (ANS-...), else a stated `/regex/` in the syntax or the question
        rx = _syntax_pattern(sp["syntax"])
        if rx is None:
            rx = _question_regex(sp.get("syntax"), str(q.get("question") or ""))
        if rx is not None:
            seen = []
            for n, d in (files or {}).items():
                if not isinstance(d, (bytes, bytearray)) or len(d) > MAX_BYTES or bytes(d[:4]) == b"PK\x03\x04":
                    continue
                blob = bytes(d)
                found = [m.group(0).decode() for m in rx.finditer(blob)]
                try:
                    found += [m.group(0).decode() for m in rx.finditer(blob.decode("utf-16le", "ignore").encode())]
                except Exception:  # noqa: BLE001
                    pass
                found = list(dict.fromkeys(found))
                # `only_in:<member>` is a hypothesis that carries to the next variant (the member holds ONE
                # code); a member with several codes names its options by rank within THIS member's bytes
                # (`in:<member>@<digest>#<n>`), so an accepted rank never answers another variant plain.
                for i, code in enumerate(found, 1):
                    if code in seen:
                        continue
                    seen.append(code)
                    if len(found) == 1:
                        add(f"only_in:{_leaf(n)}", code)
                    else:
                        add(f"in:{_leaf(n)}@{_scope(blob)}#{i}", code)
    elif kind == "enum":
        vals = sp.get("accepted_values") or []
        pos = []
        for v in vals:
            if not isinstance(v, str) or not v:
                continue
            whole, sub, first = _enum_evidence(v, mem)
            if sub > 0:
                # rank by evidence strength, not mere first place: a value that occurs as a WHOLE token beats
                # one that is only a substring of a co-occurring longer value (`arm` inside `arm64`), then more
                # occurrences, then earliest position -- the uniqueness-guarded read goes first.
                pos.append((0 if whole else 1, -whole, -sub, first, v))
        # The name is the evidence, never the value: `only_listed` (exactly one accepted value occurs in the
        # named members) carries to the next variant; several occurring are ranked under a name scoped to THIS
        # delivery's bytes, so an accepted rank never answers another variant plain (a fat Mach-O, or a table
        # naming several architectures, must not get last variant's rank).
        if len(pos) == 1:
            add("only_listed", pos[0][-1])
        elif pos:
            scope = _scope(b"".join(bytes(d) for _, d in mem))
            for i, row in enumerate(sorted(pos), 1):
                add(f"listed_rank@{scope}#{i}", row[-1])
    if kind in ("exact_text", "json", "") or (kind == "enum" and not opts):
        for n, d in mem:
            for v in _kv(leafword, bytes(d), numeric=False)[:2]:
                add(f"kv:{_leaf(n)}", v)
    if kind in ("exact_text", "json", ""):
        # the stated-shape tier (url/path/domain/email/ipv4): a keyed `field: value` is stronger evidence, so
        # it goes first (above); a shape found with no key follows. _shapes_for returns [] for enum, so a role
        # or label enum never gets a URL candidate.
        for name, value in stated_shape_options(q, files, lane, sp=sp, mem=mem):
            add(name, value)
    return opts


def candidates_for(q, files: dict, key: str, lane: str = "", stated: dict | None = None, value=None):
    """The unsure candidate pick of the proposals under `key` (labels.candidates), or None.

    With `value` (a value a reader ALREADY read, whose rendering/label the judge has not accepted for this
    id -- so the reader returned None or an unsure pick), the RE-SPELLER tier (ticket #2) fills in when the
    value-finder tiers find nothing: it re-spells that known value through render_candidates' axes, so a
    correctly-read-but-wrongly-rendered value becomes a loaded probe instead of a batch-sinking plain guess.
    The finder is tried first (a fresh value from the bytes is stronger evidence than a re-spelling), and the
    re-speller only when it comes up empty. Still never plain: every option is a `labels.candidates` `??`
    string under a candidate key, probed on the untimed base and on no-deadline attempts only (row 346)."""
    opts = propose(q, files, lane, stated)
    if not opts and value is not None:
        opts = respell(value, q=q, lane=lane)
    if not opts:
        return None
    import labels  # noqa: E402  (solvers/common)
    return labels.candidates(key, opts)


# ------------------------------------------------------------------------------------------------ the re-speller tier (#2)
#
# The value-finder tiers above FIND a value from the delivery's bytes and the question's stated spec. The
# re-speller tier is distinct: it takes a value a reader has ALREADY read -- established from the bytes, so
# never-guess is upstream -- whose RENDERING or LABEL the judge has not accepted for the id (Day 23: the page
# size read 1024 but the one plain spelling sent was wrong; the macho type set read in file order, the judge
# wanted it sorted). It re-spells that one value through render_candidates' full axis (the case/pad/base/
# endian/order forms, plus the unicode/encoding axis: NFKC/NFC, homoglyph/zero-width, punycode, percent/HTML),
# and offers the renderings as proposer candidates. It FINDS no new value; it re-spells one in hand, and so
# complements the finder rather than competing with it. Every output is an unsure `labels.candidates`
# option under a candidate key: never plain before the judge accepts a hypothesis name, probed only on the
# untimed base and on attempts with no deadline (row 346). Pure; never raises.


def _concrete_value(value):
    """The value to re-spell. A reader's own unsure/candidate pick string may be passed straight in: its
    best-evidence option value is taken. None (nothing read) and the empty string re-spell to nothing."""
    if value is None or value == "":
        return None
    try:
        import labels  # noqa: E402  (solvers/common)
        if labels.is_unsure(value):
            parsed = labels.parse(value)
            opts = parsed.options if parsed is not None else []
            return opts[0][1] if opts else None
    except Exception:  # noqa: BLE001 - a value that is not an unsure string is re-spelt as itself
        pass
    return value


def respell(value, q=None, lane: str = "", answer_format=None, field=None) -> list:
    """The re-speller tier (ticket #2): render_candidates' renderings of a VALUE already read, as proposer
    `[(hypothesis name, rendered value)]`, best-spelling first, at most MAX_OPTIONS; [] when there is nothing
    to re-spell (a clean scalar/text with no alternative rendering, a non-renderable value, None/empty, or
    render_candidates unavailable). Distinct from `propose()`: it re-spells a known value, it finds none.

    `answer_format` and `field` steer the render kind; both default from `q` (its answer_format, and the
    lane's own field word). Never plain, never raises."""
    v = _concrete_value(value)
    if v is None:
        return []
    try:
        import render_candidates as RC  # noqa: E402  (solvers/common on sys.path)
    except Exception:  # noqa: BLE001 - the axis is optional; its absence is not a proposal
        return []
    if answer_format is None and isinstance(q, dict):
        af = q.get("answer_format")
        answer_format = af if isinstance(af, dict) else None
    if field is None and isinstance(q, dict):
        try:
            field = field_word(lane, q) if lane else _qid(q)
        except Exception:  # noqa: BLE001
            field = None
    try:
        opts = RC.deception_axis(v, answer_format, field)
    except Exception:  # noqa: BLE001 - a re-speller must never cost an answer
        return []
    out = []
    for item in opts or ():
        if isinstance(item, (list, tuple)) and len(item) == 2 and isinstance(item[0], str) and item[0]:
            out.append((item[0], str(item[1])))
    return out[:MAX_OPTIONS]


def respell_candidates(q, key: str, value, lane: str = "", answer_format=None, field=None):
    """`labels.candidates(key, respell(value, ...))` or None -- the re-speller tier's unsure candidate pick
    (row 346). The one-call primitive for a day_patch/reader that read a value it cannot name the spelling of:
    `propose.respell_candidates(q, key, answer, lane)` (answer may be the reader's own None / unsure pick)."""
    opts = respell(value, q=q, lane=lane, answer_format=answer_format, field=field)
    if not opts:
        return None
    import labels  # noqa: E402  (solvers/common)
    return labels.candidates(key, opts)


def respell_key_for(lane: str, q, kind: str | None = None) -> str:
    """A candidate key for the re-speller tier: `<lane prefix>.<field word>/respell+<kind>`, kept apart from
    `key_for`'s `fixpacket+<kind>` so the re-speller's spelling hypotheses never mix with the value-finder's."""
    k = kind or ((q.get("answer_format") or {}).get("kind") if isinstance(q.get("answer_format"), dict) else None) or "any"
    pre = LANE_PREFIX.get(lane, lane.split("-")[0] or "toolkit")
    fw = re.sub(r"[^a-z0-9_.]+", "_", field_word(lane, q).lower()).strip("_") or "answer"
    return f"{pre}.{fw}/respell+{re.sub(r'[^a-z0-9_]+', '_', str(k).lower())}"


def key_for(lane: str, q, kind: str | None = None) -> str:
    """`<lane prefix>.<field word>/fixpacket+<kind>`: one key a field and answer kind."""
    pre = LANE_PREFIX.get(lane, lane.split("-")[0] or "toolkit")
    fw = re.sub(r"[^a-z0-9_.]+", "_", field_word(lane, q).lower()).strip("_") or "answer"
    k = kind or ((q.get("answer_format") or {}).get("kind") if isinstance(q.get("answer_format"), dict) else None) or "any"
    return f"{pre}.{fw}/fixpacket+{re.sub(r'[^a-z0-9_]+', '_', str(k).lower())}"
