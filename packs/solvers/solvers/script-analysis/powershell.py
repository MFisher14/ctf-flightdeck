#!/usr/bin/env python3
"""PowerShell specimen analyzer for the Script Analysis lane.

Usage:
  python3 solvers/script-analysis/powershell.py <evidence.zip | folder | file.ps1> [...]

Static reading only: nothing is executed. Each specimen wraps a JSON descriptor
in `[Convert]::FromBase64String(...)`, may pass the bytes through a
`$reconstruct` scriptblock, and names the .NET types it would touch in
`$nativeTypes`. The analyzer

  1. recovers the descriptor (base64 or hex literal, then whatever byte
     transform the script declares, falling back to a search over single-byte
     transforms until the bytes parse as JSON),
  2. classifies the scenario from the native types and the descriptor's shape,
  3. reads each indicator out of the descriptor by what the value looks like
     (URL, wallet, mutex, user-agent, extension, recovery note, file list), not
     by where it sits.

Runner contract (see analyze.py): answers(questions, files, ctx) -> {qid: answer}.
Nothing about any particular variant is hardcoded.
"""
import base64
import binascii
import gzip
import json
import re
import sys
import zlib
from pathlib import Path

# Primary ATT&CK technique per scenario class, each confirmed by the Game Master on 2026-10-04.
# The collection sample is keyed on what it collects (the browser stores "Login Data" and
# "Cookies": Credentials from Web Browsers), not on the archiving or the upload. T1560,
# T1560.001, T1560.002, T1005, T1119, T1074.001 and T1041 were all judged incorrect for it.
ATTACK = {"resource": "T1496", "collection": "T1555.003", "impact": "T1486"}
DEFAULT_SCENARIO = {"resource": "resource_hijacking", "collection": "synthetic_collection",
                    "impact": "synthetic_impact"}

# .NET type fragments that signal a behavior class. IO.File appears in more than one, so it carries no weight.
TYPE_SIGNALS = {
    "resource": ("Diagnostics.Process", "Win32.Registry", "Net.WebClient", "Threading.Mutex", "ProcessStartInfo"),
    "collection": ("IO.Compression", "HttpWebRequest", "Net.Http", "Clipboard", "Drawing"),
    "impact": ("Security.Cryptography", "IO.DirectoryInfo", "Cryptography.Aes", "RijndaelManaged"),
}

URL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://\S+$")
MUTEX_RE = re.compile(r"^(Global|Local|Session\\\d+)\\")
WALLET_RE = re.compile(r"(?i)^wallet[_\-:]|^(bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,62}$|^0x[a-fA-F0-9]{40}$|^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$")
UA_RE = re.compile(r"^(Mozilla|Opera|curl|Wget|python-requests|PowerShell|WindowsPowerShell)/|\bAppleWebKit\b|\bMSIE\b")
EXT_RE = re.compile(r"^\.[A-Za-z0-9][\w.\-]*$")
NOTE_RE = re.compile(r"(?i)(recover|readme|read_me|decrypt|restore|ransom|how[_\- ]?to|instruction|unlock).*\.(txt|html?|hta|md)$")
FILE_RE = re.compile(r"^[^\\/:*?\"<>|\r\n]+\.[A-Za-z0-9]{1,8}$")
REGKEY_RE = re.compile(r"^(HKCU|HKLM|HKEY_[A-Z_]+)[:\\]")


# ---------------------------------------------------------------- script reading

def ps_strings(text: str) -> list:
    """Every string literal in the script, with PowerShell quoting undone, in source order."""
    out = []
    pat = re.compile(r"@'\r?\n(.*?)\r?\n'@|@\"\r?\n(.*?)\r?\n\"@|'((?:[^']|'')*)'|\"((?:[^\"`]|`.|\"\")*)\"", re.S)
    for m in pat.finditer(text):
        if m.group(1) is not None:
            out.append(m.group(1))
        elif m.group(2) is not None:
            out.append(m.group(2))
        elif m.group(3) is not None:
            out.append(m.group(3).replace("''", "'"))
        else:
            out.append(re.sub(r"`(.)", r"\1", m.group(4)).replace('""', '"'))
    return out


def strip_comments(text: str) -> str:
    text = re.sub(r"<#.*?#>", "", text, flags=re.S)
    return "\n".join(re.sub(r"(^|\s)#.*$", r"\1", ln) if "'" not in ln and '"' not in ln else ln
                     for ln in text.splitlines())


def joined_literal(expr: str):
    """Value of an expression made only of string literals joined with + (or a -join of literals)."""
    parts = ps_strings(expr)
    rest = re.sub(r"@'.*?'@|@\".*?\"@|'(?:[^']|'')*'|\"(?:[^\"`]|`.|\"\")*\"", "", expr, flags=re.S)
    if parts and re.fullmatch(r"[\s+,()@;]*(-join)?[\s+,()@;]*", rest):
        return "".join(parts)
    return None


def variables(text: str) -> dict:
    """Simple `$name = <literal expression>` assignments."""
    env = {}
    for m in re.finditer(r"\$(\w+)\s*=\s*([^\r\n]+)", text):
        val = joined_literal(m.group(2))
        if val is not None:
            env[m.group(1).lower()] = val
    return env


def encoded_candidates(text: str) -> list:
    """Byte strings the script decodes, most likely first."""
    env = variables(text)
    cands = []

    def add(s, how):
        if s is None:
            return
        compact = re.sub(r"\s+", "", s)
        if how in ("b64", "any") and len(compact) >= 8 and re.fullmatch(r"[A-Za-z0-9+/_\-]+={0,2}", compact):
            try:
                raw = base64.b64decode(compact.replace("-", "+").replace("_", "/") + "=" * (-len(compact) % 4))
                cands.append(raw)
            except (binascii.Error, ValueError):
                pass
        if how in ("hex", "any") and len(compact) >= 8 and len(compact) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", compact):
            cands.append(bytes.fromhex(compact))
        if how == "any" and s.lstrip()[:1] in "{[":
            cands.append(s.encode())

    for m in re.finditer(r"FromBase64String\s*\(\s*([^)]*)\)", text):
        arg = m.group(1).strip()
        lit = joined_literal(arg)
        if lit is None and arg.startswith("$"):
            lit = env.get(arg[1:].lower())
        add(lit, "b64")
    # Byte arrays written out as numbers: @(123,34,...) or [byte[]](0x7b,0x22,...)
    for m in re.finditer(r"(?:\[byte\[\]\]|\[char\[\]\])?\s*@?\(\s*((?:(?:0x[0-9A-Fa-f]{1,2}|\d{1,3})\s*,\s*){7,}(?:0x[0-9A-Fa-f]{1,2}|\d{1,3}))\s*\)", text):
        vals = [int(x, 0) for x in re.split(r"\s*,\s*", m.group(1).strip())]
        if all(v < 256 for v in vals):
            cands.append(bytes(vals))
    # Anything else that could be an encoded blob: long literals and resolved variables.
    for s in list(env.values()) + ps_strings(text):
        if len(s) >= 16:
            add(s, "any")
            add(s[::-1], "b64")
    seen, uniq = set(), []
    for c in cands:
        if c and c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq


def declared_transforms(text: str) -> list:
    """Byte transforms the script itself spells out (the body of $reconstruct and friends)."""
    fns = []
    body = strip_comments(text)
    for m in re.finditer(r"-bxor\s+(0x[0-9A-Fa-f]+|\d+)", body, re.I):
        k = int(m.group(1), 0) & 0xFF
        fns.append(lambda b, k=k: bytes(x ^ k for x in b))
    for m in re.finditer(r"-bxor\s+\$(\w+)", body, re.I):
        km = re.search(r"\$" + re.escape(m.group(1)) + r"\s*=\s*(0x[0-9A-Fa-f]+|\d+)\b", body, re.I)
        if km:
            k = int(km.group(1), 0) & 0xFF
            fns.append(lambda b, k=k: bytes(x ^ k for x in b))
    for m in re.finditer(r"\$_\s*([+\-])\s*(0x[0-9A-Fa-f]+|\d+)", body):
        n = int(m.group(2), 0) * (1 if m.group(1) == "+" else -1)
        fns.append(lambda b, n=n: bytes((x + n) & 0xFF for x in b))
    if re.search(r"\[array\]::Reverse|\.Reverse\(\)|\[\s*-1\s*\.\.", body, re.I):
        fns.append(lambda b: b[::-1])
    return fns


def as_text(raw: bytes):
    """Decode bytes the way [Text.Encoding] would, trying compression wrappers first."""
    for magic, fn in ((b"\x1f\x8b", gzip.decompress), (b"\x78", zlib.decompress)):
        if raw.startswith(magic):
            try:
                raw = fn(raw)
            except Exception:
                pass
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        encodings = ("utf-16",)
    elif len(raw) >= 4 and raw[1::2].count(0) > len(raw) // 4:
        encodings = ("utf-16-le", "utf-8")
    elif len(raw) >= 4 and raw[0::2].count(0) > len(raw) // 4:
        encodings = ("utf-16-be", "utf-8")
    else:
        encodings = ("utf-8", "utf-16-le")
    for enc in encodings:
        try:
            return raw.decode(enc).lstrip("﻿")
        except UnicodeDecodeError:
            continue
    return None


def as_descriptor(raw: bytes):
    t = as_text(raw)
    if not t or t.lstrip()[:1] not in "{[":
        return None
    try:
        obj = json.loads(t)
    except ValueError:
        return None
    if isinstance(obj, list) and len(obj) == 1 and isinstance(obj[0], dict):
        obj = obj[0]
    return obj if isinstance(obj, dict) and obj else None


def recover_descriptor(text: str):
    """Return (descriptor dict, how it was recovered) or (None, reason)."""
    cands = encoded_candidates(text)
    declared = declared_transforms(text)
    for raw in cands:
        d = as_descriptor(raw)
        if d:
            return d, "plain"
        for fn in declared:
            d = as_descriptor(fn(raw))
            if d:
                return d, "declared transform"
        for a in declared:
            for b in declared:
                if a is not b:
                    d = as_descriptor(b(a(raw)))
                    if d:
                        return d, "declared transforms"
    # Last resort: any single-byte XOR / add, forwards or reversed, that lands on JSON.
    for raw in cands:
        for rev in (False, True):
            src = raw[::-1] if rev else raw
            for k in range(256):
                for op in ("xor", "add"):
                    if k == 0 and (op == "add" or not rev):
                        continue
                    first = src[0] ^ k if op == "xor" else (src[0] + k) & 0xFF
                    if first not in b"{[ \t\r\n\xef\xff\xfe":
                        continue
                    out = bytes(x ^ k for x in src) if op == "xor" else bytes((x + k) & 0xFF for x in src)
                    d = as_descriptor(out)
                    if d:
                        return d, f"searched {op} {k}{' reversed' if rev else ''}"
    return None, "no descriptor found"


def native_types(text: str) -> list:
    body = strip_comments(text)
    m = re.search(r"\$native\w*\s*=\s*@?\(([^\r\n]*)\)", body, re.I)
    scope = m.group(1) if m else body
    types = re.findall(r"\[([A-Za-z_][\w.]*)\]", scope)
    if not m:
        boring = {"convert", "byte", "string", "char", "int", "pscustomobject", "array", "void", "text.encoding",
                  "system.convert", "system.text.encoding"}
        types = [t for t in types if t.lower() not in boring]
    return types


# ---------------------------------------------------------------- descriptor reading

def strings_in(desc) -> list:
    """Scalar strings of the descriptor in document order (list members included)."""
    out = []

    def walk(v):
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
    walk(desc)
    return out


def first_match(desc, rx, exclude=()):
    for s in strings_in(desc):
        if rx.search(s) and not any(e.search(s) for e in exclude):
            return s
    return None


def file_list(desc):
    """First list of strings anywhere in the descriptor (the files a sample works on)."""
    if isinstance(desc, dict):
        for v in desc.values():
            if isinstance(v, list) and v and all(isinstance(x, str) for x in v):
                return v
        for v in desc.values():
            found = file_list(v)
            if found:
                return found
    return None


def scalars(desc) -> list:
    """(key, string) pairs that are not inside a list, in document order."""
    out = []
    if isinstance(desc, dict):
        for k, v in desc.items():
            if isinstance(v, str):
                out.append((str(k), v))
            elif isinstance(v, dict):
                out.extend(scalars(v))
    return out


# Descriptive key names, for descriptors that label their fields instead of using a, b, c...
KEY_HINTS = {
    "url": r"(^|_)(url|uri)($|_)",
    "wallet": r"wallet",
    "mutex": r"mutex|mutant",
    "user-agent": r"user_?agent",
    "extension": r"(^|_)ext(ension)?($|_)",
    "note": r"note",
}
LOOSE_UA_RE = re.compile(r"^[A-Za-z][\w .\-]*/[\w.]+(\s.*)?$")
TEXTISH_RE = re.compile(r"(?i)\.(txt|html?|hta|md|rtf)$")


def indicators(desc: dict) -> dict:
    files = file_list(desc)
    plain = scalars(desc)
    not_file = (URL_RE, MUTEX_RE, REGKEY_RE, UA_RE)

    def by_key(name, shape=None):
        for k, v in plain:
            if re.search(KEY_HINTS[name], k, re.I) and (shape is None or shape.search(v)):
                return v
        return None

    def other(v):
        return any(rx.search(v) for rx in (URL_RE, MUTEX_RE, REGKEY_RE, UA_RE, EXT_RE, FILE_RE))

    # Strong readings: a labelled key or an unmistakable shape. Only these feed the classifier.
    strong = {
        "url": by_key("url", URL_RE) or first_match(desc, URL_RE),
        "wallet": by_key("wallet") or first_match(desc, WALLET_RE),
        "mutex": by_key("mutex") or first_match(desc, MUTEX_RE),
        "user-agent": by_key("user-agent") or first_match(desc, UA_RE),
        "extension": by_key("extension", EXT_RE) or first_match(desc, EXT_RE),
        "note": by_key("note") or first_match(desc, NOTE_RE, exclude=(URL_RE,)),
        "file": files[0] if files else None,
        "files": files,
        "registry": first_match(desc, REGKEY_RE),
        "archive": first_match(desc, re.compile(r"(?i)\.(zip|7z|rar|cab|tar|gz)$"), exclude=(URL_RE,)),
    }
    # Looser readings, used only to answer a question the strong reading left open.
    loose = {
        "user-agent": next((v for _, v in plain if LOOSE_UA_RE.search(v) and not URL_RE.search(v)
                            and "\\" not in v), None),
        "note": next((v for _, v in plain if FILE_RE.search(v) and TEXTISH_RE.search(v)), None),
        # An unlabelled wallet in no known address format: an opaque token of address length.
        "wallet": next((v for _, v in plain if len(v) >= 26 and re.fullmatch(r"[A-Za-z0-9_\-:]+", v)
                        and not other(v) and not re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", v)), None),
        "file": first_match(desc, FILE_RE, exclude=not_file + (EXT_RE,)),
    }
    ind = {k: (v if v is not None else loose.get(k)) for k, v in strong.items()}
    ind["strong"] = strong
    return ind


def classify(types: list, ind: dict, filename: str = "") -> str:
    score = {k: 0 for k in TYPE_SIGNALS}
    for cls, frags in TYPE_SIGNALS.items():
        for t in types:
            if any(f.lower() in t.lower() for f in frags):
                score[cls] += 2
    if ind.get("wallet"):
        score["resource"] += 5
    if ind.get("registry"):
        score["resource"] += 1
    if ind.get("extension") or ind.get("note"):
        score["impact"] += 3 if ind.get("extension") and ind.get("note") else 2
    if ind.get("archive"):
        score["collection"] += 3
    if ind.get("user-agent") and not ind.get("wallet"):
        score["collection"] += 1
    best = max(score.values())
    winners = [k for k, v in score.items() if v == best]
    if len(winners) > 1 or best == 0:
        for k in winners if best else score:
            if k in filename.lower():
                return k
    return winners[0]


def signalled(types: list, ind: dict, filename: str = "") -> bool:
    """Whether classify() had anything to go on: a type signal, an indicator it scores, or a
    class word in the file name. Without any, its class is the first of the table, a default."""
    return (any(f.lower() in t.lower() for frags in TYPE_SIGNALS.values() for f in frags for t in types)
            or any(ind.get(k) for k in ("wallet", "registry", "extension", "note", "archive", "user-agent"))
            or any(k in filename.lower() for k in TYPE_SIGNALS))


class Specimen:
    def __init__(self, name: str, data: bytes):
        self.name = name
        self.text = as_text(data) or data.decode("latin-1")
        self.descriptor, self.how = recover_descriptor(self.text)
        self.types = native_types(self.text)
        self.ind = indicators(self.descriptor) if self.descriptor else {}
        self.cls = classify(self.types, self.ind.get("strong", {}), name)
        self.signalled = signalled(self.types, self.ind.get("strong", {}), name)

    def scenario(self, accepted=None) -> str:
        for v in accepted or []:
            if self.cls in v.lower():
                return v
        return DEFAULT_SCENARIO[self.cls]

    def attack(self):
        # A class read from nothing (row 51, 2026-10-07: it was the table's first, resource, so
        # T1496) is no technique: None, never a default.
        return ATTACK[self.cls] if self.signalled else None


# ---------------------------------------------------------------- question dispatch

# (what the question is after) <- the id suffix first, and only for an id that ends in none of them the
# patterns tried against the question text. Until Day 12 the text was read first; that day's re-wording of
# other components (a rubric that says "technique" and "MITRE" in a question about something else) showed
# what a word of the text can do to a question whose id already says what it asks.
ASKS = [
    ("scenario", r"\bscenario\b", r"-scenario$"),
    ("attack", r"ATT&CK|MITRE|technique", r"-attack$"),
    ("user-agent", r"user[- ]agent", r"-user-agent$"),
    ("wallet", r"\bwallet\b", r"-wallet$"),
    ("mutex", r"\bmutex\b", r"-mutex$"),
    ("note", r"recovery[- ]note|ransom[- ]note|\bnote\b", r"-note$"),
    ("extension", r"\bextension\b", r"-extension$"),
    ("file", r"\bfilename\b|\bfile name\b", r"-file$"),
    ("url", r"\bURL\b", r"-url$"),
]


def what_is_asked(q: dict):
    text, qid = q.get("question") or "", q.get("qid") or q.get("id") or ""
    for key, _, id_rx in ASKS:
        if re.search(id_rx, qid):
            return key
    # Review of 2026-10-12: an id of this component's form (`<tactic>-<field words>`) that ends in none of
    # the fields is a field nobody asked (`-attack-v2`, `-url-host`): its text is not read for a field word.
    if re.match(r"(?:set\d+\.)?[A-Za-z0-9]+-.+$", qid):
        return None
    for key, text_rx, _ in ASKS:
        if re.search(text_rx, text, re.I):
            return key
    return None


def find_file(files: dict, member: str):
    if member in files:
        return files[member]
    base = Path(member).name.lower()
    for name, data in files.items():
        if Path(name.split(" -> ")[-1]).name.lower() == base:
            return data
    return None


def answers(questions, files, ctx=None) -> dict:
    cache, out = {}, {}
    for q in questions:
        member = q.get("member") or (q.get("artifact") or "").split("->")[-1].strip()
        if member not in cache:
            data = find_file(files, member)
            cache[member] = Specimen(member, data) if data is not None else None
        sp = cache[member]
        if sp is None:
            continue
        ask = what_is_asked(q)
        if ask == "scenario":
            out[q["qid"]] = sp.scenario((q.get("answer_format") or {}).get("accepted_values"))
        elif ask == "attack":
            out[q["qid"]] = sp.attack()
        elif ask:
            out[q["qid"]] = sp.ind.get(ask)
    return out


# ---------------------------------------------------------------- command line

def _load(path: Path) -> dict:
    if path.is_dir():
        return {p.name: p.read_bytes() for p in sorted(path.glob("*.ps1"))}
    data = path.read_bytes()
    if data[:2] != b"PK":
        return {path.name: data}
    common = str(Path(__file__).resolve().parent.parent / "common")
    if common not in sys.path:
        sys.path.append(common)
    import archive_passwords   # `infected`, then the passwords of <challenges>/_passwords.json
    members, _ = archive_passwords.read_all(data)
    return {name: body for name, body in members.items() if name.lower().endswith(".ps1")}


def main(argv) -> int:
    if argv and argv[0] in ("-h", "--help"):
        print("usage: powershell.py <evidence.zip|folder|file.ps1> [...]")
        return 0
    if not argv:
        print("powershell.py: expected at least one artifact", file=sys.stderr)
        return 2
    try:
        for arg in argv:
            for name, data in _load(Path(arg)).items():
                sp = Specimen(name, data)
                shown = {k: v for k, v in sp.ind.items() if v and k not in ("files", "strong")}
                print(f"{arg} :: {name}")
                print(f"  scenario={sp.scenario()} attack={sp.attack()} descriptor={sp.how} types={sp.types}")
                for k, v in shown.items():
                    print(f"  {k} = {v}")
    except Exception as exc:
        print(f"powershell.py: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
