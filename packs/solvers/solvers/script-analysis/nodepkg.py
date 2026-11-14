#!/usr/bin/env python3
"""The script inside a Node.js packaging (backlog row 94): pkg, nexe, a Node single executable
(NODE_SEA_BLOB), a bytenode .jsc file, and a Bun or Deno compiled executable.

    view(name, data) -> (kind, text, notes) or None

Nothing is run, loaded or emulated: the container's bytes are read where its format stores the
script, and the script's text (or, for V8 bytecode, its string table) is handed back as JavaScript
text for the general path (generic.py, plan_codec.py, label_plan.py), as Day 5's Python packagings
were. None means "not a packaging this file reads": the caller then reads the file as before.

Usage (offline, prints what is found in each file and makes no request):
  .venv/bin/python solvers/script-analysis/nodepkg.py <file> [...]

What is a packaging. Only a native executable (ELF, PE, Mach-O), a bare SEA blob, or a V8 code
cache is ever looked at; a text file is never one, whatever it says in a comment.

  bytenode  a V8 code cache: bytes 2-3 are de c0 (V8's 0xC0DE.... magic) and the header's
            payload length agrees with the file (or the name ends in .jsc). The source is not
            in it, only its strings: every one-byte or two-byte V8 string, read by its own
            length field, comes back as one JavaScript string literal per line, in file order.
  node_sea  the NODE_SEA_BLOB resource, wherever postject put it (an ELF note, a PE resource,
            a Mach-O section, or the blob alone): magic 0x0143da20, flags, then size-prefixed
            strings (an optional one-byte field, the code path, the main script; then code
            cache and assets as the flags say). The main script and every text asset. A blob
            whose flags say the main entry is a V8 startup snapshot is not read.
  nexe      the trailer `<nexe~~sentinel>` + two little-endian doubles (content size, resource
            size) at the end: the content (the bundled script) and every resource that is text.
  node_pkg  pkg's prelude, `(function (REQUIRE_COMMON, VIRTUAL_FILESYSTEM, ...` with its virtual
            file system JSON (`{"/snapshot/...": {"<store>": [offset, size]}}`) and its DOCOMPRESS
            argument. The payload sits right before the prelude; its start is accepted only when
            every stat record (store 3) of the file system reads as one there. Each file's
            content (store 1) is its text, each blob (store 0) is V8 bytecode read as above.
            gzip-compressed stores are inflated (bounded); Brotli is not read (no decoder here).
  bun       the trailer `\\n---- Bun! ----\\n` after the module graph's Offsets: the byte count
            fixes the payload, and every module whose name is a Bun virtual path gives its
            contents. If the module table does not read, the payload's text runs.
  deno      the 24-byte trailer `d3n0l4nd` + two big-endian offsets (eszip, metadata), or a
            `d3n0l4nd` section (Deno 2): the text runs of the eszip region (sources are stored
            as plain UTF-8).

Several modules come back as one text, each after a `// <path>` line, the entry point first. The
plan is then accepted by plan_codec's strict grammar only, as the file's single plan: two modules
with two plans establish nothing.

Bounds. Input up to MAX_INPUT bytes; a region scanned for text up to MAX_REGION; text handed back
up to MAX_TEXT; each inflated stream up to MAX_INFLATE bytes and RATIO times its compressed size,
all streams together up to MAX_INFLATE_TOTAL; at most MAX_MODULES modules and MAX_STRINGS V8
strings; and the whole reading within TIME_BUDGET seconds (checked between steps; an overrun gives
no reading).
"""
import json
import re
import struct
import sys
import time
import zlib

MAX_INPUT = 512 << 20
MAX_REGION = 64 << 20
MAX_TEXT = 16 << 20
MAX_INFLATE = 16 << 20
MAX_INFLATE_TOTAL = 32 << 20
RATIO = 200
MAX_MODULES = 4096
MAX_STRINGS = 200_000
TIME_BUDGET = 4.0

KINDS = ("bytenode", "node_sea", "nexe", "node_pkg", "bun", "deno")

SEA_MAGIC = b"\x20\xda\x43\x01"            # 0x0143da20, little-endian
SEA_SNAPSHOT, SEA_CODE_CACHE, SEA_ASSETS = 2, 4, 8
NEXE_SENTINEL = b"<nexe~~sentinel>"
BUN_TRAILER = b"\n---- Bun! ----\n"
DENO_MAGIC = b"d3n0l4nd"
PKG_PRELUDE = re.compile(rb"\(function\s*\(\s*REQUIRE_COMMON\s*,\s*VIRTUAL_FILESYSTEM\b")
PKG_VFS = re.compile(rb'\{\s*"(?:/snapshot/|[A-Za-z]:\\\\snapshot\\\\)')
PKG_STORES = {"0": "blob", "1": "content", "2": "links", "3": "stat"}
BUN_PATH = re.compile(rb"^(?:/\$bunfs/|B:[/\\]~BUN[/\\]|compiled://)")
SCRIPTISH = re.compile(r"\.(?:[cm]?js|[cm]?ts|jsx|tsx|json)$", re.I)

_CTRL = rb"\x00-\x08\x0b\x0c\x0e-\x1f"
V8_ONE = re.compile(rb"[^" + _CTRL + rb"]{2,}")
V8_TWO = re.compile(rb"(?:[\x09\x0a\x0d\x20-\x7e]\x00){2,}")
TEXT_RUN = re.compile(rb"(?:[\t\n\r\x20-\x7e]|[\xc2-\xdf][\x80-\xbf]|[\xe0-\xef][\x80-\xbf]{2}|[\xf0-\xf4][\x80-\xbf]{3}){32,}")


class Budget:
    def __init__(self, seconds=None):
        self.end = time.monotonic() + (TIME_BUDGET if seconds is None else seconds)
        self.inflated = 0

    def check(self):
        if time.monotonic() > self.end:
            raise TimeoutError("node packaging read over its time budget")


# ---------------------------------------------------------------- what a file is

def native(data) -> str:
    """'elf', 'pe', 'macho' or '' from the first bytes."""
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:2] == b"MZ" and len(data) >= 0x40:
        off = struct.unpack_from("<I", data, 0x3c)[0]
        if off + 4 <= len(data) and data[off:off + 4] == b"PE\x00\x00":
            return "pe"
    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        return "macho"
    if data[:4] == b"\xca\xfe\xba\xbe" and len(data) >= 8 and 0 < struct.unpack_from(">I", data, 4)[0] < 32:
        return "macho"       # a fat binary (a Java class file has a version number >= 45 there)
    return ""


def v8_cache(data, name="") -> bool:
    """A V8 code cache (what bytenode writes): magic 0xC0DE.... and a header whose payload length
    agrees with the file, or the .jsc name."""
    if len(data) < 32 or data[2:4] != b"\xde\xc0":
        return False
    if str(name or "").lower().endswith(".jsc"):
        return True
    for at in (0x10, 0x14, 0x0c):
        n = struct.unpack_from("<I", data, at)[0]
        if 16 <= len(data) - n <= 64:
            return True
    return False


# ---------------------------------------------------------------- readers

def _js(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)


def v8_strings(data, budget) -> list:
    """Every V8 sequential string of a code cache, read by its own length field (u32, right before
    the characters), in file order, without repeats."""
    out, seen, runs = [], set(), 0
    for rx, two in ((V8_ONE, False), (V8_TWO, True)):
        for m in rx.finditer(data):
            if len(out) >= MAX_STRINGS:
                break
            runs += 1
            if runs % 1024 == 0:
                budget.check()
            s, e = m.span()
            if s < 4:
                continue
            n = struct.unpack_from("<I", data, s - 4)[0]
            size = n * 2 if two else n
            if n < 2 or size > e - s:
                continue
            raw = data[s:s + size]
            text = raw.decode("utf-16-le", "replace") if two else raw.decode("latin-1")
            if text not in seen:
                seen.add(text)
                out.append((s, text))
    return [t for _, t in sorted(out)]


def strings_as_js(strings) -> str:
    return "".join(_js(s) + ";\n" for s in strings)


def inflate(blob, budget, wbits=31):
    """A gzip (wbits 31), zlib (15) or raw deflate (-15) stream, bounded by size and ratio; None
    when it does not inflate or would go past a bound."""
    budget.check()
    limit = min(MAX_INFLATE, max(4096, RATIO * len(blob)), MAX_INFLATE_TOTAL - budget.inflated)
    if limit <= 0:
        return None
    d = zlib.decompressobj(wbits)
    try:
        out = d.decompress(blob, limit + 1)
    except zlib.error:
        return None
    if len(out) > limit or (not d.eof and d.unconsumed_tail):
        return None
    budget.inflated += len(out)
    return out


def utf8(raw):
    """The bytes as text when they are text (UTF-8, no NUL), else None."""
    if b"\x00" in raw[:4096]:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def text_runs(region, budget) -> str:
    budget.check()
    region = region[-MAX_REGION:] if len(region) > MAX_REGION else region
    parts = [m.group().decode("utf-8", "replace") for m in TEXT_RUN.finditer(region)]
    budget.check()
    return "\n".join(parts)


def _u(fmt, data, at):
    try:
        return struct.unpack_from(fmt, data, at)[0]
    except struct.error:
        return None


# -- Node single executable application

def sea_blob(blob, budget):
    """(modules, notes) of one NODE_SEA_BLOB starting at blob[0], or None if it does not read."""
    flags = _u("<I", blob, 4)
    if flags is None or flags > 0xff:
        return None

    def string(at):
        n = _u("<Q", blob, at)
        if n is None or n > len(blob) - at - 8:
            return None, at
        return blob[at + 8:at + 8 + n], at + 8 + n

    for skip in (1, 0):      # Node 22+ writes one byte before the strings; Node 20 does not
        at = 8 + skip
        first, after = string(at)
        if first is None:
            continue
        path = utf8(first)
        second, after2 = string(after)
        named = path is not None and 0 < len(first) < 4096 and "\n" not in path and second is not None
        if named and (SCRIPTISH.search(path) or "/" in path or "\\" in path or "." in path):
            code, end = second, after2
        elif skip == 0:
            path, code, end = "main", first, after     # Node 20.0: the main script only
        else:
            continue
        if flags & SEA_SNAPSHOT:
            return [], [f"SEA blob (flags {flags:#x}): the main entry is a V8 startup snapshot, not read"]
        text = utf8(code)
        if text is None:
            continue
        mods, notes = [(path or "main", text)], [f"SEA blob, flags {flags:#x}, main {path or 'main'} ({len(code)} bytes)"]
        if flags & SEA_CODE_CACHE:
            _, end = string(end)
        if flags & SEA_ASSETS and end is not None:
            count = _u("<Q", blob, end)
            at = end + 8
            for _ in range(min(count or 0, MAX_MODULES)):
                budget.check()
                key, at = string(at)
                val, at = string(at) if key is not None else (None, at)
                if key is None or val is None:
                    break
                name, body = utf8(key), utf8(val)
                if name is not None and body is not None:
                    mods.append((f"asset:{name}", body))
        return mods, notes
    return None


def read_sea(data, budget):
    at = data.find(SEA_MAGIC)
    tries = 0
    while at >= 0 and tries < 64:
        tries += 1
        budget.check()
        got = sea_blob(data[at:], budget)
        if got is not None:
            return got
        at = data.find(SEA_MAGIC, at + 1)
    return None


# -- nexe

def read_nexe(data, budget):
    if len(data) < 32 or data[-32:-16] != NEXE_SENTINEL:
        return None
    cs, rs = struct.unpack_from("<dd", data, len(data) - 16)
    if not (cs >= 0 and rs >= 0 and cs == int(cs) and rs == int(rs) and cs + rs + 32 <= len(data)):
        return [], ["nexe trailer with sizes that do not fit the file"]
    cs, rs = int(cs), int(rs)
    res_at = len(data) - 32 - rs
    content = data[res_at - cs:res_at]
    text = utf8(content)
    if text is None:
        return [], ["nexe content is not text"]
    mods, notes = [("nexe:content", text)], [f"nexe content {cs} bytes, resources {rs} bytes"]
    resources = data[res_at:res_at + rs]
    m = re.search(r"process\.__nexe\s*=\s*\{", text)
    index = {}
    if m:
        try:
            obj, _ = json.JSONDecoder().raw_decode(text, m.end() - 1)
            index = obj.get("resources") or {} if isinstance(obj, dict) else {}
        except ValueError:
            index = {}
    for path, span in list(index.items())[:MAX_MODULES]:
        budget.check()
        if isinstance(span, list) and len(span) == 2 and all(isinstance(x, int) and x >= 0 for x in span) \
                and span[0] + span[1] <= rs:
            body = utf8(resources[span[0]:span[0] + span[1]])
            if body is not None:
                mods.append((f"nexe:{path}", body))
    if not index and rs:
        body = utf8(resources)
        if body is not None:
            mods.append(("nexe:resources", body))
    return mods, notes


# -- pkg

def read_pkg(data, budget):
    m = PKG_PRELUDE.search(data)
    if not m:
        return None
    start = m.start()
    while start > 0 and data[start - 1:start] in b" \t\r\n":
        start -= 1
    if data[max(0, start - 6):start] == b"return":
        start -= 6
    prelude = data[start:]
    v = PKG_VFS.search(prelude)
    if not v:
        return [], ["pkg prelude without a virtual file system"]
    text = prelude.decode("utf-8", "replace")
    at = len(prelude[:v.start()].decode("utf-8", "replace"))
    dec = json.JSONDecoder()
    try:
        vfs, end = dec.raw_decode(text, at)
    except ValueError:
        return [], ["pkg virtual file system does not parse"]
    rest = text[end:]
    entry = None
    em = re.match(r'\s*,\s*("(?:[^"\\]|\\.)*")', rest)
    if em:
        try:
            entry = json.loads(em.group(1))
        except ValueError:
            entry = None
    cm = re.search(r",\s*(\d)\s*\)\s*;?\s*$", rest)
    compress = int(cm.group(1)) if cm else 0
    spans = []
    for path, stores in (vfs.items() if isinstance(vfs, dict) else []):
        if not isinstance(stores, dict):
            continue
        for store, span in stores.items():
            if store in PKG_STORES and isinstance(span, list) and len(span) == 2 \
                    and all(isinstance(x, int) and x >= 0 for x in span):
                spans.append((path, PKG_STORES[store], span[0], span[1]))
    if not spans:
        return [], ["pkg virtual file system with no stores"]
    size = max(o + n for _, _, o, n in spans)
    stats = [(o, n) for _, kind, o, n in spans if kind == "stat"]

    def unpacked(raw):
        if compress == 1:
            return inflate(raw, budget, 31)
        if compress == 2:
            return None
        return raw

    def fits(base):
        if base < 0:
            return False
        for o, n in stats[:16]:
            raw = unpacked(data[base + o:base + o + n])
            try:
                if raw is None or not isinstance(json.loads(raw.decode("utf-8")), dict):
                    return False
            except (ValueError, UnicodeDecodeError):
                return False
        return True

    base = None
    if stats and compress != 2:
        for slack in range(0, 4097):
            if slack % 256 == 0:
                budget.check()
            if fits(start - size - slack):
                base = start - size - slack
                break
    elif compress != 2:
        base = start - size     # no stat record to check against: the payload ends where the prelude starts
    if base is None:
        why = "Brotli-compressed (no decoder here)" if compress == 2 else "no payload start the stat records agree with"
        return [], [f"pkg payload not read: {why}"]
    mods = []
    order = sorted(spans, key=lambda s: (s[0] != entry, s[0]))
    for path, kind, o, n in order[:MAX_MODULES]:
        budget.check()
        if kind not in ("content", "blob"):
            continue
        raw = unpacked(data[base + o:base + o + n])
        if raw is None:
            continue
        if kind == "content":
            body = utf8(raw)
            if body is not None:
                mods.append((path, body))
        elif v8_cache(raw, ".jsc"):
            mods.append((path + " (V8 bytecode strings)", strings_as_js(v8_strings(raw, budget))))
    return mods, [f"pkg payload at {base}, {len(spans)} stores, compress={compress}, entry {entry}"]


# -- Bun

def read_bun(data, budget):
    t = data.rfind(BUN_TRAILER)
    if t < 0:
        return None
    for osize in (32, 24):
        o = t - osize
        count = _u("<Q", data, o)
        mod_off, mod_len = _u("<I", data, o + 8), _u("<I", data, o + 12)
        if count is None or mod_off is None or count > o or count > MAX_REGION * 4:
            continue
        base = o - count
        payload = data[base:o]
        if not (0 < mod_len and mod_off + mod_len <= len(payload)):
            continue
        mods = []
        for rec in (36, 40, 44, 48, 52, 56, 64):
            if mod_len % rec:
                continue
            got = []
            for i in range(min(mod_len // rec, MAX_MODULES)):
                budget.check()
                r = mod_off + i * rec
                no, nl, co, cl = struct.unpack_from("<IIII", payload, r)
                if no + nl > len(payload) or co + cl > len(payload) or not nl:
                    got = None
                    break
                name = payload[no:no + nl]
                if not BUN_PATH.match(name):
                    got = None
                    break
                body = utf8(payload[co:co + cl])
                if body is not None:
                    got.append((name.decode("utf-8", "replace"), body))
            if got:
                mods = got
                break
        if mods:
            return mods, [f"Bun module graph, {len(mods)} text modules"]
        runs = text_runs(payload, budget)
        if runs:
            return [("bun:payload", runs)], ["Bun payload read as text runs (the module table did not read)"]
    return [], ["Bun trailer without a payload that reads"]


# -- Deno

def read_deno(data, budget):
    """Deno 1.x: the 24-byte trailer `d3n0l4nd` + the eszip and metadata offsets (big-endian)."""
    if len(data) < 24 or data[-24:-16] != DENO_MAGIC:
        return None
    eszip, meta = struct.unpack_from(">QQ", data, len(data) - 16)
    if not eszip <= meta <= len(data) - 24:
        return [], ["Deno trailer with offsets that do not fit the file"]
    runs = text_runs(data[eszip:meta], budget)
    return ([("deno:eszip", runs)] if runs else []), [f"Deno trailer, eszip {meta - eszip} bytes"]


def read_deno_section(data, budget):
    """Deno 2: a `d3n0l4nd` section; the text runs after its last magic (the runtime's own code
    holds the magic too, before its data)."""
    at = data.rfind(DENO_MAGIC)
    if at < 0:
        return None
    runs = text_runs(data[at + len(DENO_MAGIC):at + len(DENO_MAGIC) + MAX_REGION], budget)
    return ([("deno:section", runs)] if runs else []), [f"Deno section at {at}"]


def read_bytenode(data, budget):
    return [("code cache", strings_as_js(v8_strings(data, budget)))], ["V8 code cache strings"]


# ---------------------------------------------------------------- the view

def candidates(name, data) -> list:
    """[(kind, reader, strong)] in the order they are tried. Cheap: magic bytes and marker
    searches. A strong one is a structure only that packaging writes (a trailer at the very end,
    pkg's prelude, a blob at offset 0); a weak one is a marker that a runtime's own code may hold
    as a constant (Deno's magic, the SEA magic, Bun's trailer anywhere but where a payload ends),
    and is a packaging only if its reader finds a script."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 16 or len(data) > MAX_INPUT:
        return []
    if v8_cache(data, name):
        return [("bytenode", read_bytenode, True)]
    if data[:4] == SEA_MAGIC:
        return [("node_sea", read_sea, True)]
    if not native(data):
        return []
    out = []
    if data[-32:-16] == NEXE_SENTINEL:
        out.append(("nexe", read_nexe, True))
    if PKG_PRELUDE.search(data):
        out.append(("node_pkg", read_pkg, True))
    if data[-24:-16] == DENO_MAGIC:
        out.append(("deno", read_deno, True))
    if BUN_TRAILER in data:
        out.append(("bun", read_bun, data[-24:-8] == BUN_TRAILER))
    if SEA_MAGIC in data:
        out.append(("node_sea", read_sea, False))
    if DENO_MAGIC in data and data[-24:-16] != DENO_MAGIC:
        out.append(("deno", read_deno_section, False))
    return out


def detect(name, data):
    """The kind of the first packaging a file may be, or None."""
    found = candidates(name, data)
    return found[0][0] if found else None


def view(name, data, budget_seconds=None):
    """(kind, text, notes) for a Node packaging, None for anything else. The readers are tried
    in order and the first that finds a script gives the kind; when a strong marker is there,
    only the strong ones are tried. text is "" when a strong marker is there but nothing reads
    (the notes say why); with only weak markers and nothing read, the file is no packaging
    (None)."""
    found = candidates(name, data)
    if not found:
        return None
    if any(strong for _, _, strong in found):
        found = [c for c in found if c[2]]      # a weak marker never reads past a strong one that did not read
    data = bytes(data)
    budget = Budget(budget_seconds)
    notes, first = [], None
    try:
        for kind, reader, strong in found:
            got = reader(data, budget)
            if got is None:
                continue
            mods, said = got
            notes += said
            if mods:
                break
            if strong and first is None:
                first = kind
        else:
            return (first, "", notes or ["no packaging structure that reads"]) if first else None
    except TimeoutError as e:
        return found[0][0], "", notes + [str(e)]
    text, total = [], 0
    for path, body in mods:
        piece = f"// {path}\n{body}\n"
        total += len(piece)
        if total > MAX_TEXT:
            notes.append(f"text over {MAX_TEXT} characters: the rest is left out")
            break
        text.append(piece)
    return kind, "".join(text), notes


def main(argv) -> int:
    from pathlib import Path
    if argv and argv[0] in ("-h", "--help"):
        print("usage: nodepkg.py <file> [...]")
        return 0
    if not argv:
        print("nodepkg.py: expected at least one file", file=sys.stderr)
        return 2
    try:
        for arg in argv:
            raw = Path(arg).read_bytes()
            got = view(Path(arg).name, raw)
            if got is None:
                print(f"{arg}: not a Node packaging")
                continue
            kind, text, notes = got
            print(f"{arg}: {kind}; {'; '.join(notes)}; {len(text)} characters of text")
            print(text[:2000])
    except Exception as exc:
        print(f"nodepkg.py: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
