#!/usr/bin/env python3
"""Universal triage for a lane no registered solver plays (backlog row 81, the NO_SOLVER path).

  .venv/bin/python solvers/common/triage.py <attempt dir> [--quiet]

Offline: no Game Master request, no token. It reads a saved attempt (attempt.json and artifact/,
as tools/run.py and tools/verify.py save one; or only the status.json the opener saved, which has
the questions and no delivery) and writes, next to it:

  triage.json   the map, for tools and agents: the question contract, every file by its bytes,
                strings, indicators, the lane signals and the answers this file can prove
  triage.md     the same for a reader, the lane agent's first page

What it does:
  - unpacks the delivery the way the lane solvers see it (tools/run.py's expand: nested zips, 7z,
    APKs, encrypted zips under `infected` and <challenges>/_passwords.json, backlog row 75), and
    then gzip, bzip2, xz and tar members as well
  - identifies every file by its bytes (magic), never by its name: zip/apk/jar/office, 7z, rar,
    gzip, bzip2, xz, tar, pdf, png, jpeg, gif, webp, elf, pe (pe+cli for .NET), mach-o, java class,
    dex, sqlite, ole, pcap, pcapng, evtx, lnk, registry hive, wasm, pyc, cab, rtf, json, xml,
    html, script by shebang, base64 text, hex text, text, data
  - extracts printable strings (ASCII and UTF-16LE), URLs, domains, IPv4 addresses, e-mail
    addresses, MD5/SHA-1/SHA-256 strings, timestamps, ATT&CK ids, registry keys, Windows paths
  - reads the question contract: answer id, kind (exact_text, enum, mitre_attack_id, pattern,
    integer, ordered_tokens, json, or whatever else is given), syntax, normalization, artifact,
    member, and the enum options a question lists
  - names the signals of the five known lanes (ANS- answer: Mobile; Determine <property> for
    <file>: Metadata; -role/-attack ids or ATT&CK answers: Script Analysis; an HCFG container or
    dNN_ ids: Binary; a decoded slug in `message`: Warmups). tools/lane_match.py scores with them.
  - names the category toolkits that match best (solvers/toolkits/registry.py: each toolkit's own
    signals() over the questions and the files), with the reference page docs/toolkits/<key>.md
    and the first command to run. Only the map says this: solve_set never asks a toolkit.

solve_set is the runner contract, so tools/verify.py can bank with it. It never guesses
(AGENTS.md, "Uncertain answers"): a plain answer only for a fact read from the bytes that the
question asks for in so many words, the file named in the very phrase ("the SHA-256 of notes.txt",
"the size of notes.txt in bytes", "how many files are in evidence.zip", "the first 4 bytes of
a.bin as hex"), in the one form the question allows: the SHA-256, SHA-1 or MD5 (lowercase hex,
uppercase only when the syntax says so), the size in bytes, the number of members of an archive,
and the first N bytes as plain hex. A question that names another file as well (other than an
archive holding it), points only at its artifact (the Binary lane's "artifact sha256 1 value ...
in the delivered evidence set" means a file inside the zip, not the zip), asks for a 0x prefix,
separators or base64, or is of kind enum, ordered_tokens, json or mitre_attack_id is None. So is a
question that qualifies the fact (anything after the named file but `?`, the archive that holds it
and the form: "after converting its line endings", "once it is decompressed", "as stored", "counting
the nested files"; or anything before the phrase but the question's opening: "once decompressed, what
is", "the first 8 characters of the"), "how many entries" of an archive with a directory entry,
everything else, and a value the answer_format's own regular expression refuses.
"""
import bz2
import gzip
import hashlib
import io
import json
import lzma
import math
import re
import struct
import sys
import tarfile
import time
import zipfile
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLS = HERE.parent.parent / "tools"

MAX_SCAN = 4 * 1024 * 1024      # bytes of one file searched for strings
MAX_STRINGS = 4000              # strings kept over all files, for the indicators
SAMPLE = 25                     # strings shown per file
MAX_IOC = 60                    # values kept per indicator kind
MAX_EXTRA = 200                 # members taken out of gzip, bzip2, xz and tar files
MAX_EXTRA_BYTES = 64 * 1024 * 1024
MIN_STRING = 6
LANES = ("script-analysis", "binary-reverse-engineering", "warmups", "mobile-android", "metadata-forensics")
ARROW = " -> "


# ---- what a file is -------------------------------------------------------------------------------

SIMPLE_MAGIC = (
    (b"7z\xbc\xaf\x27\x1c", "7z"), (b"Rar!\x1a\x07", "rar"), (b"\x1f\x8b", "gzip"), (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"), (b"%PDF-", "pdf"), (b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"), (b"GIF89a", "gif"), (b"dex\n", "dex"), (b"SQLite format 3\x00", "sqlite"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"), (b"\xd4\xc3\xb2\xa1", "pcap"), (b"\xa1\xb2\xc3\xd4", "pcap"),
    (b"\x4d\x3c\xb2\xa1", "pcap"), (b"\x0a\x0d\x0d\x0a", "pcapng"), (b"ElfFile\x00", "evtx"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk"), (b"regf", "registry-hive"), (b"\x00asm", "wasm"), (b"MSCF", "cab"),
    (b"{\\rtf", "rtf"), (b"OggS", "ogg"), (b"ID3", "mp3"), (b"\xfe\xed\xfa\xce", "mach-o"),
    (b"\xfe\xed\xfa\xcf", "mach-o"), (b"\xce\xfa\xed\xfe", "mach-o"), (b"\xcf\xfa\xed\xfe", "mach-o"),
    (b"ITSF", "chm"), (b"HCFG", "hcfg"),
)
SCRIPT_EXT = {".ps1": "powershell", ".psm1": "powershell", ".js": "jscript", ".jse": "jscript", ".vbs": "vbscript",
              ".vbe": "vbscript", ".bat": "batch", ".cmd": "batch", ".py": "python", ".sh": "shell", ".hta": "hta",
              ".wsf": "wsf", ".php": "php", ".rb": "ruby", ".pl": "perl", ".lua": "lua"}


def _pe(data: bytes) -> str:
    """pe, pe+cli (a .NET assembly), with dll; 'mz' when no PE header follows."""
    try:
        off = struct.unpack_from("<I", data, 0x3C)[0]
        if data[off:off + 4] != b"PE\x00\x00":
            return "mz"
        machine, _, _, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", data, off + 4)
        opt = off + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        dirs = opt + (96 if magic == 0x10B else 112)
        cli = struct.unpack_from("<II", data, dirs + 14 * 8) if opt_size >= (dirs - opt) + 15 * 8 else (0, 0)
        kind = "pe+cli" if cli[0] else "pe"
        bits = {0x10B: "pe32", 0x20B: "pe32+"}.get(magic, "pe?")
        return f"{kind} ({bits}, machine 0x{machine:04x}{', dll' if chars & 0x2000 else ''})"
    except (struct.error, IndexError):
        return "mz"


def _elf(data: bytes) -> str:
    try:
        bits = {1: "32", 2: "64"}.get(data[4], "?")
        endian = "<" if data[5] == 1 else ">"
        etype, machine = struct.unpack_from(endian + "HH", data, 16)
        return f"elf (ELF{bits}, {'little' if endian == '<' else 'big'}, type {etype}, machine {machine})"
    except (struct.error, IndexError):
        return "elf"


def identify(data: bytes, name: str = "", members=()) -> str:
    """What the bytes are, by magic first; a name is used only for a text file's flavour."""
    head = data[:16]
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        names = set(members)
        if "AndroidManifest.xml" in names or "classes.dex" in names:
            return "zip (apk)"
        if "[Content_Types].xml" in names:
            return "zip (office open xml)"
        if "META-INF/MANIFEST.MF" in names:
            return "zip (jar)"
        return "zip"
    if head.startswith(b"\x7fELF"):
        return _elf(data)
    if head.startswith(b"MZ"):
        return _pe(data)
    if head.startswith(b"\xca\xfe\xba\xbe"):
        return "java class" if len(data) > 8 and struct.unpack_from(">H", data, 6)[0] >= 45 else "mach-o (fat)"
    for magic, kind in SIMPLE_MAGIC:
        if head.startswith(magic):
            return kind
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar"
    if data[:4] == b"RIFF" and data[8:12] in (b"WEBP", b"WAVE", b"AVI "):
        return data[8:12].decode().strip().lower()
    if data[4:8] == b"ftyp":
        return "iso-bmff (" + data[8:12].decode("latin-1").strip() + ")"
    if len(data) >= 16 and data[2:4] == b"\r\n" and struct.unpack_from("<H", data, 0)[0] in range(2900, 4000):
        return "pyc"
    return _text_kind(data, name)


def _text_kind(data: bytes, name: str) -> str:
    sample = data[:65536]
    if not sample:
        return "empty"
    if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            sample = sample.decode("utf-16").encode("utf-8")
        except UnicodeDecodeError:
            return "data"
    try:
        text = sample.decode("utf-8-sig")
    except UnicodeDecodeError:
        return "data"
    printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    if printable < 0.95 * len(text):
        return "data"
    stripped = text.strip()
    ext = Path(name).suffix.lower()
    if stripped.startswith("#!"):
        return "script (" + stripped[2:].split()[0].rsplit("/", 1)[-1] + ")" if stripped[2:].split() else "script"
    if ext in SCRIPT_EXT:
        return f"text ({SCRIPT_EXT[ext]} by name)"
    if stripped[:1] in "{[":
        try:
            json.loads(data.decode("utf-8-sig"))
            return "json"
        except ValueError:
            pass
    low = stripped[:200].lower()
    if low.startswith("<?xml"):
        return "xml"
    if low.startswith(("<!doctype html", "<html")):
        return "html"
    compact = re.sub(r"\s+", "", stripped)
    if len(compact) >= 16 and re.fullmatch(r"[0-9a-fA-F]+", compact) and len(compact) % 2 == 0:
        return "hex text"
    if len(compact) >= 16 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact) and len(compact) % 4 == 0:
        return "base64 text"
    if ext == ".csv" or (stripped.count(",") >= 2 * max(1, stripped.count("\n"))):
        return "text (csv)"
    return "text"


def entropy(data: bytes) -> float:
    data = data[:1 << 20]
    if not data:
        return 0.0
    n = len(data)
    return round(-sum(c / n * math.log2(c / n) for c in Counter(data).values()), 3)


# ---- the files a solver is handed, and a little more -----------------------------------------------

def unique_files(files: dict) -> list:
    """[(display name, bytes)] once per file: run.expand files a member under '<archive> -> <member>'
    and, the first time, under its bare name, as the same bytes object."""
    seen, out = set(), []
    for key in sorted(files, key=lambda k: (ARROW not in k, k)):      # the arrow names first: they say where
        data = files[key]
        if not isinstance(data, (bytes, bytearray)) or id(data) in seen:
            continue
        seen.add(id(data))
        out.append((key, bytes(data)))
    return sorted(out, key=lambda kv: kv[0])


def expand_more(files: dict) -> dict:
    """gzip, bzip2, xz and tar members that tools/run.py's expand leaves packed, under
    '<file> -> <member>' (a single-stream file under its name without the suffix)."""
    out, total = {}, 0
    queue = [(name, data, 0) for name, data in unique_files(files)]
    while queue and len(out) < MAX_EXTRA and total < MAX_EXTRA_BYTES:
        name, data, depth = queue.pop(0)
        kind = identify(data[:300], name)
        found = []
        try:
            if kind == "tar" or (kind in ("gzip", "bzip2", "xz") and depth < 3):
                if kind == "tar":
                    raw = data
                else:
                    raw = {"gzip": gzip.decompress, "bzip2": bz2.decompress, "xz": lzma.decompress}[kind](data[:MAX_EXTRA_BYTES])
                if len(raw) > 262 and raw[257:262] == b"ustar":
                    with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
                        for m in tf.getmembers():
                            if m.isfile() and m.size <= MAX_EXTRA_BYTES:
                                f = tf.extractfile(m)
                                if f is not None:
                                    found.append((m.name, f.read()))
                else:
                    inner = Path(name.split(ARROW)[-1]).stem or "stream"
                    found.append((inner, raw))
        except (OSError, EOFError, lzma.LZMAError, tarfile.TarError, ValueError, KeyError):
            continue
        for member, body in found:
            key = f"{name.split(ARROW)[-1]}{ARROW}{member}"
            if key in files or key in out:
                continue
            out[key] = body
            total += len(body)
            queue.append((key, body, depth + 1))
    return out


# ---- strings and indicators ------------------------------------------------------------------------

_ASCII = re.compile(rb"[\x20-\x7e\t]{%d,}" % MIN_STRING)
_WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_STRING)


def strings(data: bytes) -> list:
    data = data[:MAX_SCAN]
    out = [m.group().decode("ascii", "replace").strip() for m in _ASCII.finditer(data)]
    out += [m.group().decode("utf-16-le", "replace").strip() for m in _WIDE.finditer(data)]
    return [s for s in out if len(s) >= MIN_STRING]


IOC = {
    "urls": re.compile(r"\b(?:https?|hxxps?|ftp)://[^\s\"'<>()\]\[{}`]{3,300}", re.I),
    "emails": re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,200}\.[A-Za-z]{2,24}\b"),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"),
    # A name starts where no word character or dot stands before it: with `\b` alone every label of a
    # long dotted run (a.b.c.d..., a decimal blob written 104.116.116...) was a start that read to the
    # run's end (20 KB of it: 6.7 s, and no deadline interrupts a regex).
    "domains": re.compile(r"(?<![\w.])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|onion|"
                          r"local|corp|lan|gov|edu|co|me|dev|app|site|online|example|invalid|test|cc|tk|su|in|uk|de)\b", re.I),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "timestamps": re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?\b"
                             r"|\b\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2}\b"),
    "attack_ids": re.compile(r"\bT1\d{3}(?:\.\d{3})?\b"),
    "registry": re.compile(r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_[A-Z_]+)\\[^\s\"'<>|]{2,200}"),
    "windows_paths": re.compile(r"\b[A-Za-z]:\\[^\s\"'<>|]{2,200}"),
}


def indicators(texts) -> dict:
    found = {k: [] for k in IOC}
    seen = {k: set() for k in IOC}
    for text in texts:
        for kind, rx in IOC.items():
            if len(found[kind]) >= MAX_IOC:
                continue
            for m in rx.finditer(text):
                v = m.group().rstrip(".,;:")
                if v not in seen[kind]:
                    seen[kind].add(v)
                    found[kind].append(v)
                    if len(found[kind]) >= MAX_IOC:
                        break
    # A hash string of one length is not also a shorter one.
    for longer, shorter in (("sha256", "sha1"), ("sha256", "md5"), ("sha1", "md5")):
        found[shorter] = [v for v in found[shorter] if not any(v in w for w in found[longer])]
    return {k: v for k, v in found.items() if v}


# ---- the question contract and the lane signals ----------------------------------------------------

def _fmt(q) -> dict:
    f = q.get("answer_format")
    return f if isinstance(f, dict) else {}


def enum_options(q) -> list:
    f = _fmt(q)
    for key in ("options", "choices", "values", "enum"):
        if isinstance(f.get(key), list):
            return [str(v) for v in f[key]][:50]
    m = re.search(r"\bone of[:\s]+(.+)$", str(f.get("syntax") or ""), re.I)
    if m:
        return [v.strip(" .`'\"") for v in re.split(r",|\bor\b", m.group(1)) if v.strip(" .`'\"")][:50]
    return []


def contract(questions) -> list:
    out = []
    for q in questions:
        f = _fmt(q)
        out.append({"answer_id": q.get("answer_id") or q.get("id"), "qid": q.get("qid") or q.get("id"),
                    "kind": f.get("kind"), "syntax": f.get("syntax"),
                    "pattern": f.get("pattern") or f.get("regex"), "normalization": q.get("normalization"),
                    "artifact": q.get("artifact"), "member": q.get("member"), "question": q.get("question"),
                    "options": enum_options(q)})
    return out


def lane_signals(questions, files) -> dict:
    """{lane: [why, ...]} for each of the five known lanes whose marks the questions or the bytes carry."""
    out = {}

    def add(lane, why):
        if why not in out.setdefault(lane, []):
            out[lane].append(why)

    for q in questions:
        aid = re.sub(r"^set\d+\.", "", str(q.get("answer_id") or q.get("id") or ""))
        f = _fmt(q)
        text = " ".join(str(x or "") for x in (q.get("question"), f.get("syntax"), f.get("pattern")))
        if "ANS-" in text or re.search(r"\bANS-\[?[0-9A-F]", text):
            add("mobile-android", "an answer in the ANS-<hex> form")
        if re.search(r"\bDetermine [a-z0-9_]+\.[a-z0-9_.]+ for \S+", str(q.get("question") or "")):
            add("metadata-forensics", "a '<file>-<property>' question (Determine <format>.<property> for <file>)")
        if re.search(r"-(?:role|attack|steps|adapter|campaign)$", aid) or f.get("kind") == "mitre_attack_id":
            add("script-analysis", "-role/-attack ids or an ATT&CK answer")
        if re.match(r"d\d\d_", aid):
            add("binary-reverse-engineering", "dNN_ answer ids")
        if aid == "message" or re.search(r"\bslug\b", text, re.I) and re.search(r"\bdecod", text, re.I):
            add("warmups", "a decoded slug in 'message'")
    for name, data in unique_files(files):
        if b"HCFG" in data[:MAX_SCAN]:
            add("binary-reverse-engineering", f"an HCFG container in {name.split(ARROW)[-1]}")
        if name.endswith("assets/huntress_puzzle.json"):
            add("mobile-android", "assets/huntress_puzzle.json")
    return out


# ---- the category toolkits (solvers/toolkits/registry.py) -------------------------------------------------

def toolkits(questions, files, budget: float = 8.0) -> dict:
    """{"rows": [{key, signal, threshold, match, doc, command, reads}], "skipped": [...]} of the
    category toolkits whose own signals() say the delivery and the questions look like their
    category, best first. A registry or toolkit that cannot be loaded raises a named error
    (RegistryLoadError, PackMissing, PackLoadError from ctf/packs.py; B-001b): the map is never written
    as if no toolkit matched when the registry was simply not read. For the map only (it loads every
    toolkit into this process): never part of solve_set, never on a clock."""
    root = HERE.parent.parent
    if str(root) not in sys.path:
        sys.path.append(str(root))      # appended, never first: the repo root must not shadow a lane module
    from ctf import packs
    return packs.toolkit_registry(root).rank(questions, files, budget=budget)


# ---- the Script cross-specimen section (backlog row 201) --------------------------------------------
#
# For three descriptor days running, the narrative prompt has pointed at a CROSS-SPECIMEN / derived
# judgement that the graded question contract never asks (Day 8 "the one that doesn't match its
# siblings"; Day 9 "the impossible family tree"; Day 10 the WMI MOF "subscription that would really
# survive a reboot"): every graded id is a single specimen's own plan field. No shipped reader computes
# a cross-specimen answer, so if the author ever promotes the hint to a real id it is a cold Layer-1
# STOP with no candidate on disk. This section computes the obvious candidates the prompts point at,
# PROVEN from the bytes of the delivered descriptor specimens, as ADVISORY leads for the lane agent.
#
# Nothing here is ever a plain answer. It is written only into the map (triage.md/triage.json); it is
# NOT part of solve_set() and never reaches the judge. If a cross-specimen field ever becomes a real id,
# the lane agent answers it with labels.pick(key, options) (unsure), probed on the UNTIMED base only --
# see .claude/skills/play-day/briefs/script-cross-specimen.md.

# Plan-field and byte words that name a real persistence mechanism ("...that would survive a reboot").
PERSIST_WORDS = (
    "persist", "run_key", "runkey", "registry_run", "run_once", "runonce", "startup", "autorun",
    "scheduled_task", "schtask", "schedule", "cron", "crontab", "systemd", "service", "launch_agent",
    "launchagent", "launch_daemon", "launchd", "wmi", "event_consumer", "eventconsumer", "event_filter",
    "eventfilter", "consumer", "subscription", "filtertoconsumer", "binding", "permanent",
    "register_descriptor", "logon_script", "winlogon",
)
# Byte markers of a REAL WMI permanent subscription (a filter, a consumer and a binding), a run-key
# write, or merely the subscription namespace. Only the first proves persistence that survives a reboot.
_WMI = {
    "__EventFilter": re.compile(rb"__EventFilter", re.I),
    "EventConsumer": re.compile(rb"(?:ActiveScript|CommandLine)EventConsumer|__EventConsumer", re.I),
    "__FilterToConsumerBinding": re.compile(rb"__FilterToConsumerBinding", re.I),
    "root/subscription namespace": re.compile(rb"root\\+subscription", re.I),
    "CurrentVersion/Run key": re.compile(rb"CurrentVersion\\+Run(?:Once)?\b|\\Run\\|\\RunOnce\\", re.I),
}
CROSS_PROFILE_FIELDS = ("steps", "stage_profile", "obfuscation_profile", "stage_count")
CROSS_KEYS = {
    "odd_one_out": "script.odd_one_out/descriptor_set",
    "self_inconsistent": "script.self_inconsistent/descriptor_set",
    "persistence": "script.persistence/descriptor_set",
}
MAX_SPECIMENS = 60              # specimens listed in the map
MAX_CANDIDATES = 12            # candidates listed per angle (labels.MAX_OPTIONS)
_SCRIPT_LANE = {}             # cache of the lazily-loaded Script lane modules


def _script_lane():
    """(descriptor module, generic module) of solvers/script-analysis, loaded once under private module
    names, or (None, None). Defensive: the section is written with or without it, so any failure (the
    files missing, an import error) just leaves the section off. generic is only used for its ROLE
    graph; descriptor does the plan reading."""
    if _SCRIPT_LANE:
        return _SCRIPT_LANE.get("descriptor"), _SCRIPT_LANE.get("generic")
    desc = gen = None
    try:
        import importlib.util
        sa = HERE.parent / "script-analysis"
        for p in (str(sa), str(HERE)):
            if p not in sys.path:
                sys.path.insert(0, p)

        def _load(modname, filename):
            full = sa / filename
            if not full.is_file():
                return None
            key = "csctf_triage_" + modname
            if key in sys.modules:
                return sys.modules[key]
            spec = importlib.util.spec_from_file_location(key, full)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[key] = mod
            spec.loader.exec_module(mod)
            return mod

        desc = _load("script_descriptor", "descriptor.py")
        try:
            gen = _load("script_generic", "generic.py")
        except BaseException:  # noqa: BLE001 - the ROLE graph is optional; descriptor is enough on its own
            gen = None
    except BaseException:  # noqa: BLE001 - the section is optional
        desc = gen = None
    _SCRIPT_LANE["descriptor"], _SCRIPT_LANE["generic"] = desc, gen
    return desc, gen


def _hashable(v):
    return tuple(v) if isinstance(v, list) else v


def _show(v):
    return ",".join(str(x) for x in v) if isinstance(v, list) else str(v)


def _descriptor_specimens(files, deadline=None) -> list:
    """Every delivered file that descriptor.reading() parses to ONE whole v=3 plan, as
    {file, name, role, language, stage_profile, obfuscation_profile, stage_count, steps(list),
    plan(dict), bytes}. Offline, read-only; the raw bytes stay for the persistence byte scan and are
    never serialized into the map."""
    marked = [(n, d) for n, d in unique_files(files)
              if b"HUNTRESS" in d[:MAX_SCAN] or b"descriptor_" in d[:MAX_SCAN]]
    if len(marked) < 2:
        return []                                      # no Script-lane import for a delivery with no descriptors
    desc, _ = _script_lane()
    pc = getattr(desc, "plan_codec", None) if desc is not None else None
    if desc is None or pc is None:
        return []
    out = []
    for name, data in marked:
        if deadline and time.monotonic() > deadline:
            break
        short = name.split(ARROW)[-1]
        try:
            got = desc.reading(pc.text_of(data), Path(short).suffix)
            if not got or got[0] is None:
                continue
            flat = pc.flatten(got[0])
        except Exception:                              # a file that will not read is not a specimen
            continue
        if str(flat.get("v")) != "3":
            continue
        steps = [s.strip() for s in str(flat.get("steps") or "").split(",") if s.strip()]
        out.append({"file": short, "name": name, "role": flat.get("role"), "language": flat.get("language"),
                    "stage_profile": flat.get("stage_profile"), "obfuscation_profile": flat.get("obfuscation_profile"),
                    "stage_count": flat.get("stage_count"), "steps": steps, "plan": flat, "bytes": data})
    return out


def _odd_one_out(specs: list) -> list:
    """Specimens that break a within-group majority (Day 8's "the one that doesn't match its siblings"):
    group by each profile field, require the group's other profile fields to agree, and flag a LONE
    specimen (exactly one, against a majority of two or more) whose follower value differs. Symmetric
    over CROSS_PROFILE_FIELDS, so a planted outlier is caught whichever field it breaks. On an internally
    consistent delivery (Days 8-10) this is empty."""
    found, seen = {}, set()
    for driver in CROSS_PROFILE_FIELDS:
        groups = {}
        for s in specs:
            groups.setdefault(_hashable(s.get(driver)), []).append(s)
        for dval, members in groups.items():
            if dval is None or len(members) < 3:
                continue
            for follower in CROSS_PROFILE_FIELDS:
                if follower == driver:
                    continue
                by_val, counts = {}, Counter()
                for m in members:
                    fv = _hashable(m.get(follower))
                    counts[fv] += 1
                    by_val.setdefault(fv, m)
                if len(counts) != 2:
                    continue
                (maj, majn), (minv, minn) = counts.most_common(2)
                if majn >= 2 and minn == 1:
                    odd = by_val[minv]
                    if (odd["file"], follower, minv) in seen:        # same follower anomaly via another driver
                        continue
                    seen.add((odd["file"], follower, minv))
                    found.setdefault(odd["file"], []).append(
                        f"shares {driver}={_show(dval)} with {majn} sibling(s) but its {follower} is "
                        f"{_show(odd.get(follower))} where they have {_show(by_val[maj].get(follower))}")
    return [{"file": f, "reasons": r} for f, r in sorted(found.items())][:MAX_CANDIDATES]


def _self_inconsistent(specs: list, role_graph: dict) -> list:
    """Specimens whose STATED role contradicts the judged role of their own step graph (Day 9's
    "the impossible family tree"). Uses generic.ROLE, the eight graphs the judge has accepted; a step
    tuple outside it is a new graph, not a contradiction, so it is not flagged."""
    out = []
    for s in specs:
        graph = tuple(s.get("steps") or ())
        judged = role_graph.get(graph)
        if judged and s.get("role") and judged != s.get("role"):
            out.append({"file": s["file"], "stated_role": s["role"], "steps_role": judged,
                        "steps": _show(s.get("steps"))})
    return out[:MAX_CANDIDATES]


def _persistence(specs: list) -> dict:
    """Specimens whose plan or bytes indicate real persistence ("...would survive a reboot"), and which
    actually prove a reboot-surviving mechanism from the bytes. A WMI subscription survives a reboot only
    with a filter AND a consumer AND a binding; the subscription namespace alone, or a lone descriptor
    carrier, is a decoy. This separates the operational relationships from the decoys the prompt names."""
    candidates, real, namespace_only = [], [], []
    for s in specs:
        plan_hits = sorted({w for w in PERSIST_WORDS
                            for val in s["plan"].values() if w in str(val).lower()})
        if "persist" in str(s.get("role") or "").lower() and "persist" not in plan_hits:
            plan_hits = ["persist"] + plan_hits
        byte_hits = [name for name, rx in _WMI.items() if rx.search(s["bytes"][:MAX_SCAN])]
        if not plan_hits and not byte_hits:
            continue
        candidates.append({"file": s["file"], "role": s.get("role"), "plan_signals": plan_hits,
                           "byte_signals": byte_hits})
        proves = {b for b in byte_hits}
        if {"__EventFilter", "EventConsumer", "__FilterToConsumerBinding"} <= proves:
            real.append({"file": s["file"], "why": "a WMI filter, consumer and binding are all present"})
        elif "CurrentVersion/Run key" in proves:
            real.append({"file": s["file"], "why": "a run-key write is present in the bytes"})
        elif "root/subscription namespace" in proves:
            namespace_only.append(s["file"])
    if real:
        finding = "byte-proven reboot-surviving mechanism(s) present: " + ", ".join(r["file"] for r in real)
    elif namespace_only:
        finding = ("the subscription namespace is present but no filter->consumer binding (and no run-key) "
                   "is in any specimen's bytes: these are descriptor carriers, decoys at the byte level; "
                   "the surviving-subscription answer, if asked, cannot be proven from these bytes")
    elif candidates:
        finding = "plan-level persistence words only (role/steps/profile); no byte-proven mechanism"
    else:
        finding = "no persistence signal in any specimen"
    return {"candidates": candidates[:MAX_CANDIDATES], "real": real, "namespace_only": namespace_only,
            "finding": finding}


def cross_specimen(files, budget=5.0) -> dict:
    """Advisory cross-specimen candidates for a Script descriptor delivery (backlog row 201), or None
    when the delivery is not a Script attempt with two or more whole v=3 descriptor specimens. Every
    item is a byte-proven LEAD, never a plain answer: it is not part of solve_set, and if a cross-specimen
    field ever becomes a real id the lane agent answers it with labels.pick (unsure), probed on the
    untimed base only."""
    t0 = time.monotonic()
    specs = _descriptor_specimens(files, (t0 + budget) if budget else None)
    if len(specs) < 2:
        return None
    _, gen = _script_lane()
    role_graph = getattr(gen, "ROLE", {}) or {}
    out = {
        "specimens": [{k: s[k] for k in ("file", "role", "language", "stage_profile",
                                         "obfuscation_profile", "stage_count", "steps")}
                      for s in specs[:MAX_SPECIMENS]],
        "specimen_count": len(specs),
        "odd_one_out": _odd_one_out(specs),
        "self_inconsistent": _self_inconsistent(specs, role_graph),
        "persistence": _persistence(specs),
        "keys": CROSS_KEYS,
        "note": ("Advisory and byte-proven. Every graded Script id is a single specimen's own plan field; "
                 "no cross-specimen id has ever been asked. If one appears, answer it with "
                 "labels.pick(key, options) (unsure), probed on the untimed base only -- never a plain "
                 "cross-specimen answer. These candidates are NOT part of solve_set and never reach the judge. "
                 "See .claude/skills/play-day/briefs/script-cross-specimen.md."),
        "seconds": round(time.monotonic() - t0, 3),
    }
    return out


# ---- the map -----------------------------------------------------------------------------------------

def build(questions, files, attempt=None, budget=None) -> dict:
    """The triage map of one set of questions and its files (see the module text)."""
    t0 = time.monotonic()
    extra = expand_more(files)
    allf = {**files, **extra}
    entries, texts, kept = [], [], 0
    members_of = {}
    for key in allf:
        if ARROW in key:
            parent, member = key.split(ARROW, 1)
            members_of.setdefault(parent, []).append(member)
    for name, data in unique_files(allf):
        short = name.split(ARROW)[-1]
        found = strings(data) if not (budget and time.monotonic() - t0 > budget) else []
        if kept < MAX_STRINGS:
            texts.extend(found[:MAX_STRINGS - kept])
            kept += min(len(found), MAX_STRINGS - kept)
        entries.append({"name": name, "file": short, "size": len(data), "type": identify(data, short, members_of.get(short, ())),
                        "sha256": hashlib.sha256(data).hexdigest(), "md5": hashlib.md5(data).hexdigest(),
                        "entropy": entropy(data), "members": len(members_of.get(short, ())),
                        "strings": len(found), "sample": found[:SAMPLE], "unpacked_here": name in extra})
    qs = contract(questions)
    proven = solve_set(questions, allf, {"attempt": attempt or {}})
    out = {"made_by": "solvers/common/triage.py", "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
           "attempt_id": (attempt or {}).get("attempt_id"), "name": (attempt or {}).get("name"),
           "prompt": (attempt or {}).get("prompt"), "questions": qs,
           "kinds": dict(Counter(str(q["kind"]) for q in qs)), "files": entries,
           "indicators": indicators(texts), "signals": lane_signals(questions, allf),
           "proven": {aid: v for aid, v in proven.items() if v is not None},
           "seconds": round(time.monotonic() - t0, 3)}
    try:
        cross = cross_specimen(allf)      # advisory, Script-descriptor deliveries only; None otherwise
    except BaseException:  # noqa: BLE001 - the map is written with or without this section
        cross = None
    if cross is not None:
        out["cross_specimen"] = cross
    return out


def _cross_specimen_md(cx) -> list:
    """The `## Cross-specimen (advisory)` block, or [] when the delivery is not a Script descriptor set
    (backlog row 201). Advisory and byte-proven: never a plain answer, never part of solve_set."""
    if not cx:
        return []
    lines = ["## Cross-specimen (advisory -- row 201)", "",
             f"{cx['specimen_count']} whole v=3 descriptor specimen(s). " + cx["note"], ""]
    odd = cx.get("odd_one_out") or []
    lines.append("**Odd-one-out** (Day 8 \"the one that doesn't match its siblings\"): "
                 + ("none -- every specimen agrees with its structural siblings." if not odd else ""))
    for c in odd:
        lines.append(f"- `{c['file']}`: " + "; ".join(c["reasons"]))
    si = cx.get("self_inconsistent") or []
    lines += ["", "**Self-inconsistent role** (Day 9 \"the impossible family tree\"): "
              + ("none -- no stated role contradicts a judged step graph." if not si else "")]
    for c in si:
        lines.append(f"- `{c['file']}`: stated role `{c['stated_role']}` but its step graph "
                     f"`{c['steps']}` is the judged graph for `{c['steps_role']}`")
    pz = cx.get("persistence") or {}
    lines += ["", "**Survives a reboot** (Day 10 \"the subscription that would really survive a reboot\"): "
              + pz.get("finding", "")]
    for c in (pz.get("candidates") or []):
        sig = ", ".join((c.get("plan_signals") or []) + c.get("byte_signals", []))
        lines.append(f"- `{c['file']}` (role `{c.get('role')}`): {sig or 'persistence signal'}")
    lines += ["", "Candidate keys, IF a cross-specimen id ever appears (probe on the untimed base, unsure only):"]
    for angle, key in (cx.get("keys") or {}).items():
        lines.append(f"- {angle}: `labels.pick('{key}', <candidate specimen ids / plan values above>)`")
    lines.append("")
    return lines


def markdown(m: dict, base: str = "") -> str:
    lines = [f"# Triage {base}".rstrip(), "",
             f"Made by `solvers/common/triage.py` at {m.get('at')} (offline, {m.get('seconds')} s). Facts read from the "
             "bytes; nothing here is a guess. Answer kinds: " + (", ".join(f"{k} x{n}" for k, n in m["kinds"].items()) or "none") + ".", ""]
    if m.get("name") or m.get("prompt"):
        lines += [f"**{m.get('name') or ''}** {m.get('prompt') or ''}".strip(), ""]
    sig = m.get("signals") or {}
    lines += ["## Lane signals", ""] + ([f"- {lane}: {'; '.join(why)}" for lane, why in sig.items()] or ["- none of the five known lanes"]) + [""]
    tk = m.get("toolkits")
    if tk is not None:
        lines += ["## Toolkits", ""]
        for r in tk.get("rows") or []:
            mark = "" if r["signal"] >= r["threshold"] else " (under its threshold: a lead, not a match)"
            lines.append(f"- `{r['key']}` signal {r['signal']:.2f}{mark}: {r['reads']}. Reference `{r['doc']}`; first run "
                         f"`{r['command']}`; bank with `tools/verify.py <base-id> solvers/toolkits/{r['key']}.py`.")
        if not tk.get("rows"):
            lines.append("- no category toolkit's signal reaches 0.25 (the table of all of them: `docs/toolkits/README.md`)")
        if tk.get("skipped"):
            lines.append("- not asked (out of time): " + ", ".join(tk["skipped"]))
        lines.append("")
    lines += _cross_specimen_md(m.get("cross_specimen"))
    lines += ["## Questions", "", "| answer id | kind | syntax | artifact | proven |", "| --- | --- | --- | --- | --- |"]
    for q in m["questions"]:
        cell = lambda v: str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")[:120]
        proven = m["proven"].get(q["answer_id"])
        lines.append(f"| {cell(q['answer_id'])} | {cell(q['kind'])} | {cell(q['syntax'])} | {cell(q['artifact'])} | "
                     f"{cell(proven) if proven is not None else '-'} |")
    lines.append("")
    for q in m["questions"]:
        if q.get("options"):
            lines.append(f"- options of {q['answer_id']}: {', '.join(q['options'])}")
    lines += ["", "## Files", "", "| file | type | size | sha256 | entropy | strings |", "| --- | --- | --- | --- | --- | --- |"]
    for f in m["files"]:
        lines.append(f"| {f['name']} | {f['type']} | {f['size']} | {f['sha256'][:16]}... | {f['entropy']} | {f['strings']} |")
    ind = m.get("indicators") or {}
    if ind:
        lines += ["", "## Indicators", ""]
        for kind, values in ind.items():
            lines.append(f"- {kind} ({len(values)}): " + ", ".join(f"`{v}`" for v in values[:15]))
    lines += ["", "## Strings (first of each file)", ""]
    for f in m["files"]:
        if f["sample"]:
            lines.append(f"- {f['name']}: " + " | ".join(f"`{s[:80]}`" for s in f["sample"][:8]))
    return "\n".join(lines) + "\n"


# ---- the runner contract: only what is proven ---------------------------------------------------------
#
# Every rule names the file in the very phrase that asks for the fact ("the SHA-256 of notes.txt",
# "the size of notes.txt in bytes", "how many files are in evidence.zip", "the first 4 bytes of
# a.bin as hex"). A question that only points at its artifact ("the artifact sha256 1 value for
# field d01_... in the delivered evidence set": a file inside evidence.zip, not the zip) is not
# answered: which file is meant is the author's, not the bytes'.

_ALGOS = {"sha256": r"sha-?256", "sha1": r"sha-?1", "md5": r"md5", "sha512": r"sha-?512"}
_ANY_ALGO = re.compile(r"\b(?:sha-?256|sha-?1|md5|sha-?512|sha-?384|sha-?224|crc-?32|ssdeep|imphash|tlsh)\b", re.I)
_OF = r"\s+(?:hash|digest|checksum|value|sum)?\s*(?:of|for)\s+(?:the\s+)?(?:(?:file|member|archive|zip|delivery|artifact|attachment)\s+)?[`'\"]?"
_END = r"[`'\"]?(?![\w-])"
_COUNT_NOT = re.compile(r"\b(?:that|which|whose|with|where|named|match|matching|contain|containing|other than|except|"
                        r"excluding|including|ending|starting|larger|smaller|more|less|than|type|kind)\b", re.I)
# A wording that qualifies the fact asks for another one ("the SHA-256 of notes.txt after converting its
# line endings", "the size of image.raw as stored", "how many bytes is a.gz after decompression"): the
# bytes these rules hash, measure and count are the file's own. So nothing may follow the named file but
# `?`, the archive that holds it and the form the rule writes, and none of these words may stand before
# the phrase ("once decompressed, what is the SHA-256 of a.gz?").
_QUALIFIED = re.compile(r"\b(?:after|before|once|when|without|excluding|ignoring|skipping|as stored|(?:de|un)?compress\w*|"
                        r"g?unzip\w*|inflat\w*|deflat\w*|unpack\w*|extract\w*|strip\w*|trim\w*|remov\w*|convert\w*|"
                        r"normali[sz]\w*|decod\w*|encod\w*|decrypt\w*|counting|nested|lines?)\b", re.I)
_HELD_IN = r"\s+(?:in|inside|within|from)\s+(?:the\s+)?(?:(?:archive|zip|delivery|bundle)\s+)?[`'\"]?(?:%s)" + _END
_FORMS = {"hex": r",?\s+(?:in|as)\s+(?:(?:lower|upper)-?case\s+)?hex(?:adecimal)?", "bytes": r"\s+in\s+bytes"}
# The words above are a list, and a list has holes ("recursively, how many files are in a.zip?", "the first
# 8 characters of the SHA-256 of a.txt", "the HMAC-SHA-256 of a.txt", "... of b.txt, and how many files are
# in a.zip?"). So before the phrase only the question's own opening may stand, with the words of the rule's
# form ("What is the exact lowercase SHA-256 of", "Give the file size of"); the list stays as a second net.
_OPENING = (r"\s*(?:(?:what|which)\s+(?:is|are|was|were)|what's|(?:please\s+)?(?:give|provide|compute|calculate|enter|"
            r"submit|report|find|determine|state))?\s*(?:the\s+)?(?:(?:exact|full|complete%s)\s+)*")
_OPENING_OF = {"hex": r"|lower-?case|upper-?case|hex(?:adecimal)?", "bytes": r"|file", "": ""}
_NOUNS = ("the", "file", "member", "archive", "zip", "delivery", "artifact", "attachment")     # the phrases' own words
_FOLD = {0x130: "i", 0x131: "i", 0x17F: "s", 0x212A: "k"}     # what re.I reads as an ASCII letter and lower() does not
_ASCII_RUNS = re.compile(r"[\x00-\x7f]+")


def _names(files: dict) -> dict:
    """{file name: [bytes, ...]} under the member name and its base name; one entry per file."""
    out = {}
    for key, data in files.items():
        tail = key.split(ARROW)[-1]
        for n in {tail, Path(tail).name}:
            if len(n) > 2 and not any(d is data for d in out.setdefault(n, [])):
                out[n].append(data)
    return out


def _mentioned(text: str, names: dict) -> dict:
    """The names the text can hold at all, by substring: the regexes below are tried on these only (one
    regex per name and question was 45.8 s on a delivery of 6,298 members and 110 questions, none of
    which names a file). It never drops a name a regex finds: re.I reads an ASCII character of a name as
    itself in either case or as one of _FOLD's four, so every run of ASCII characters of the name is in
    the folded text; what is not ASCII in a name is left to the regex (6,000 such names were 180 s again)."""
    low = text.translate(_FOLD).lower()
    return {n: d for n, d in names.items()
            if (n.lower() in low if n.isascii() else all(run.lower() in low for run in _ASCII_RUNS.findall(n)))}


def _named_in(rx_head: str, text: str, names: dict) -> list:
    """The files a phrase names: rx_head followed by one of the file names, matched in the text, as
    [(bytes, the text before the phrase, the text after the name)]."""
    hits = []
    for name, datas in names.items():
        m = re.search(rx_head + re.escape(name) + _END, text, re.I)
        if m:
            hits.append((name, datas, text[:m.start()], text[m.end():]))
    # a name that is part of a longer named one (a.txt in data.txt) is the longer one's
    hits = [h for h in hits if not any(h[0] != o[0] and h[0] in o[0] for o in hits)]
    return [(d, head, tail) for _, ds, head, tail in hits for d in ds]


def _unqualified(head: str, tail: str, holders, form: str) -> bool:
    """The phrase asks for the file's own fact: before it only the question's opening (_OPENING, and no
    qualifying word), and after the name only the archive that holds the file ("in evidence.zip"), the
    rule's own form ("in bytes", "as hex") and `?`."""
    if _QUALIFIED.search(head) or not re.fullmatch(_OPENING % _OPENING_OF[form], head, re.I):
        return False
    allowed = [_FORMS[form]] if form else []
    if holders:
        allowed.append(_HELD_IN % "|".join(re.escape(h) for h in sorted(holders, key=len, reverse=True)))
    return re.fullmatch((f"(?:{'|'.join(allowed)})*" if allowed else "") + r"\s*[?.]?\s*", tail, re.I) is not None


def _member_agrees(q, data, files: dict) -> bool:
    """A question whose artifact names a member is about that member only."""
    member = q.get("member")
    if not member:
        return True
    return any(v is data for k, v in files.items() if k.split(ARROW)[-1] in (member, Path(member).name)
               or Path(k.split(ARROW)[-1]).name == Path(member).name)


def _fits(q, value: str) -> bool:
    f = _fmt(q)
    rx = f.get("pattern") or f.get("regex")
    if isinstance(rx, str) and rx.strip():
        try:
            return re.fullmatch(rx, value) is not None
        except re.error:
            return False
    return True


def _direct_members(files: dict, data: bytes) -> list:
    names = {k.split(ARROW)[-1] for k, v in files.items() if v is data}
    return sorted({k for k in files for n in names if k.startswith(n + ARROW) and ARROW not in k[len(n) + len(ARROW):]})


def _one(q, files: dict, hits: list, names: dict, form: str = ""):
    """The one file the phrase names, when the question names no other file besides an archive
    that holds it ("the SHA-256 of notes.txt in evidence.zip") and does not qualify the fact
    (_unqualified, with the form the rule writes); else None. `names` are the names the text holds."""
    hits = [h for h in hits if _member_agrees(q, h[0], files)]
    datas = []
    for d, _, _ in hits:
        if not any(d is x for x in datas):
            datas.append(d)
    if len(datas) != 1:
        return None
    data = datas[0]
    text = str(q.get("question") or "")
    holders = {Path(k.split(ARROW)[0]).name for k, v in files.items() if v is data and ARROW in k}
    for name, ds in names.items():
        if any(d is data for d in ds) or Path(name).name in holders:
            continue
        if re.search(r"(?<![\w.-])" + re.escape(name) + r"(?![\w-])", text):
            return None
    if not all(_unqualified(head, tail, holders, form) for _, head, tail in hits):
        return None
    return data


def _zip_entries(data: bytes):
    """(file entries, directory entries) of a zip's central directory, or None when it cannot be read."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
    except Exception:           # not a zip zipfile reads: nothing is proven about its entries
        return None
    dirs = sum(1 for i in infos if i.is_dir())
    return len(infos) - dirs, dirs


def answer(q, files: dict, ctx, names: dict = None):
    """One question's proven answer, or None. `names` is _names(files), which solve_set builds once per set."""
    text = " ".join(str(q.get("question") or "").split())
    f = _fmt(q)
    syntax = str(f.get("syntax") or "")
    kind = str(f.get("kind") or "")
    if kind in ("mitre_attack_id", "enum", "ordered_tokens", "json"):
        return None
    words = syntax + " " + text
    upper = re.search(r"\bupper-?case\b", words, re.I) is not None
    if re.search(r"\b0x\b|\bprefix|\bspace|\bcolon|\bseparat|\bbase64\b", words, re.I):
        return None             # a form these rules do not write
    # the question as written too: _one looks for another named file there, and a name with a tab or two
    # spaces in it is not in the text once its white space is one space
    asked = str(q.get("question") or "")
    names = _mentioned(text if asked == text else text + "\n" + asked, _names(files) if names is None else names)
    if not names:
        return None             # every rule below needs its file named in the question
    if any(n.lower() in _NOUNS and re.search(r"(?<![\w.-])" + re.escape(n) + r"(?![\w.-])", text, re.I) for n in names):
        return None             # "the SHA-256 of the file" names no file, also when a member is called `file`
    algos = {m.group().lower().replace("-", "") for m in _ANY_ALGO.finditer(text)}
    if algos:
        if len(algos) != 1 or next(iter(algos)) not in _ALGOS:
            return None
        algo = next(iter(algos))
        data = _one(q, files, _named_in(r"\b" + _ALGOS[algo] + _OF, text, names), names, "hex")
        if data is None:
            return None
        value = hashlib.new(algo, data).hexdigest()
        value = value.upper() if upper else value
        return value if _fits(q, value) else None
    if kind not in ("integer", "exact_text", "pattern", ""):
        return None
    size = (_named_in(r"\b(?:size|length)\s+(?:in\s+bytes\s+)?of\s+(?:the\s+)?(?:file\s+)?[`'\"]?", text, names)
            if re.search(r"\bin bytes\b|\bbytes\?", text, re.I) else [])
    size += _named_in(r"\bhow many bytes\s+(?:long\s+)?(?:is|are|does)\s+(?:the\s+)?(?:file\s+)?[`'\"]?", text, names)
    data = _one(q, files, size, names, "bytes")
    if data is not None:
        value = str(len(data))
        return value if _fits(q, value) else None
    if size:
        return None             # a size was asked and declined: a second question in the text is not its answer
    m = re.search(r"\bhow many (files|members|entries)\s+(?:are\s+)?(?:stored\s+)?(?:in|inside|within)\s+", text, re.I)
    if m and not _COUNT_NOT.search(text[:m.start()] + " " + re.sub(r"^\S+", "", text[m.end():].split("?")[0])):
        data = _one(q, files, _named_in(r"\bhow many (?:files|members|entries)\s+(?:are\s+)?(?:stored\s+)?(?:in|inside|within)\s+"
                                        r"(?:the\s+)?(?:(?:archive|zip|delivery)\s+)?[`'\"]?", text, names), names)
        if data is not None and (data[:4] == b"PK\x03\x04" or data[:6] == b"7z\xbc\xaf\x27\x1c"):
            members = _direct_members(files, data)
            # "Entries" and "members" of an archive with a directory entry may count it or not, and a
            # count that is not the central directory's own (a name stored twice, a member that was not
            # read) is not the archive's. A 7z's directory entries are not read here at all.
            files_only = m.group(1).lower() == "files"
            if data[:2] == b"PK":
                entries = _zip_entries(data)
                if entries is None or entries[0] != len(members) or (entries[1] and not files_only):
                    return None
            elif not files_only:
                return None
            if members:
                value = str(len(members))
                return value if _fits(q, value) else None
        return None
    first = re.search(r"\b(?:first|leading)\s+(\d{1,2})\s+bytes\s+of\s+", text, re.I)
    if first and re.search(r"\bhex", words, re.I):
        data = _one(q, files, _named_in(r"\b(?:first|leading)\s+" + first.group(1) + r"\s+bytes\s+of\s+(?:the\s+)?(?:file\s+)?[`'\"]?",
                                        text, names), names, "hex")
        n = int(first.group(1))
        if data is not None and 1 <= n <= len(data):
            value = data[:n].hex()
            value = value.upper() if upper else value
            return value if _fits(q, value) else None
    return None


def solve_set(questions, files, ctx) -> dict:
    out = {}
    try:
        names = _names(files)   # once per set: built for every question it was files x questions
    except Exception:
        names = None            # then answer() builds its own, and what cannot be read is no answer
    for q in questions:
        try:
            out[q.get("qid") or q.get("id")] = answer(q, files, ctx, names)
        except Exception:       # a fact that cannot be read is no answer
            out[q.get("qid") or q.get("id")] = None
    return out


# ---- the command ------------------------------------------------------------------------------------

def load(folder: Path):
    """(attempt, [(questions, files, ctx)], notes) of a saved attempt; a status.json alone gives the
    questions with no files."""
    sys.path.insert(0, str(TOOLS))
    import run      # noqa: E402  (tools/run.py: the reader the lane solvers are handed their files by)
    if (folder / "attempt.json").is_file():
        attempt, blobs, _ = run.load_offline(folder.name, str(folder))
        locked, notes = [], []
        sets = run.split_sets(attempt, blobs, locked, notes)
        notes += [f"no known archive password opens {name}" for name in locked]
        return attempt, [(qs, files, ctx) for _, qs, files, ctx in sets], notes
    status = json.loads((folder / "status.json").read_text())
    qs = status.get("questions") or []
    shaped = [run.shaped(q, aid)[1] for q, aid in zip(qs, run.answer_ids_for(status))]
    return status, [(shaped, {}, {"attempt": status})], ["only status.json is saved: no delivery yet"]


def write_map(folder: Path, budget=None) -> dict:
    """Build the map of a saved attempt and write triage.json and triage.md beside it."""
    attempt, sets, notes = load(folder)
    questions = [q for qs, _, _ in sets for q in qs]
    files = {}
    for _, f, _ in sets:
        for k, v in f.items():
            files.setdefault(k, v)
    m = build(questions, files, attempt, budget=budget)
    m["notes"] = notes
    m["toolkits"] = toolkits(questions, files) if files else {"rows": [], "skipped": []}
    tmp = folder / ".triage.json.tmp"
    tmp.write_text(json.dumps(m, indent=1, ensure_ascii=False))
    tmp.replace(folder / "triage.json")
    tmp = folder / ".triage.md.tmp"
    tmp.write_text(markdown(m, folder.name) + ("".join(f"\nNOTE {n}" for n in notes) + "\n" if notes else ""))
    tmp.replace(folder / "triage.md")
    return m


def main(argv) -> int:
    args = [a for a in argv if not a.startswith("--")]
    if len(args) != 1:
        print("usage: triage.py <attempt dir> [--quiet]", file=sys.stderr)
        return 2
    folder = Path(args[0]).resolve()
    if not ((folder / "attempt.json").is_file() or (folder / "status.json").is_file()):
        print(f"triage.py: no attempt.json or status.json under {folder}", file=sys.stderr)
        return 2
    try:
        m = write_map(folder, budget=20.0)
    except SystemExit as e:
        print(f"triage.py: the saved attempt cannot be read ({e.code})", file=sys.stderr)
        return 1
    if "--quiet" not in argv:
        best = ",".join(r["key"] for r in (m.get("toolkits") or {}).get("rows", [])[:3]) or "-"
        print(f"TRIAGE files={len(m['files'])} questions={len(m['questions'])} proven={len(m['proven'])} "
              f"signals={','.join(m['signals']) or '-'} toolkits={best} map={folder / 'triage.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
