#!/usr/bin/env python3
"""Toolkit jumplist: Windows Jump List reader (wave121/forensics-next, forensics/dfir coverage gap;
backlog "forensics/dfir", Jump Lists row, the cheap fast-follow after ESE). Offline, static, stdlib only.

A Jump List records the files and folders a user opened with one application. Two containers ship it:

  *.automaticDestinations-ms  an OLE Compound File (CFB): a `DestList` metadata stream (MRU order,
                              per-entry hostname, access time, pin state) plus one numbered stream per
                              destination, each a shell link (LNK). Built automatically by the shell.
  *.customDestinations-ms     NOT a CFB: a header and category blocks holding a sequence of LNKs the
                              application pinned or grouped. No DestList, so no reliable MRU.

The marquee facts an analyst wants are the per-destination LNK targets, their times, the volume serial
and drive type, the tracker block's machine id and MAC address, the MRU order and the AppID. Every LNK
is handed to the ARMED `windows.lnk()` parser (solvers/toolkits/windows.py) rather than re-decoded here,
so this module adds only the two CONTAINERS around it: a bounded CFB walk and an LNK carve.

NEVER-GUESS (AGENTS.md "Uncertain answers"), the forensics never-wrong contract:
  - Nothing of a Jump List has been judged, so NO answer is ever plain. Every established fact is an
    unsure `labels.pick(key, options)` whose option NAMES are formats/methods (`raw`, `lower`, `hex`,
    `iso_z`, ...) or `labels.candidates(key, options)` whose NAMES are hypotheses (`streams`,
    `destlist_entries`, `mru_first`, ...); the VALUE is always re-derived from THIS variant's bytes, so
    an accepted name never answers a different variant's value plain. Keys are per-question scoped
    (`windows.jumplist_<field>/<shape>@<answer id>`), never a bare label==value under a fixed literal.
  - A fact is answered only when the bytes pin it to exactly one value; two readings, an incomplete
    DestList parse, or a question this module cannot place is None. A flag is always None.
  - `signals()` returns 0.0 unless a real Jump List container validates in the bytes, so the toolkit
    never competes on anything else and changes no existing lane match.
  - Bounded compute: a header read, at most MAX_STREAMS streams, MAX_SECTORS sectors, MAX_BYTES in all.

Key prefix: `windows` (registered with `"labels": "windows"`; solvers/common/labels.py knows it).
"""
import json
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
# `windows` is a sibling toolkit (HERE); labels/triage are in COMMON. Add both so an importlib load
# (not just `python jumplist.py ...`, which auto-adds HERE) resolves every sibling import.
for _p in (str(HERE), str(COMMON)):
    if _p not in sys.path:
        sys.path.insert(1, _p)
import labels    # noqa: E402
import triage    # noqa: E402
import windows    # noqa: E402  (the armed LNK/FILETIME/helpers; imported, never edited)

KEY = "windows"              # the toolkit's label prefix (registry row `"labels": "windows"`)
FIELD = "jumplist_"          # every key field begins with this, so a Jump List fact never collides
ARROW = triage.ARROW

CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
FATSECT = 0xFFFFFFFD
DIFSECT = 0xFFFFFFFC
NOSTREAM = 0xFFFFFFFF

MAX_BYTES = 64 * 1024 * 1024
MAX_SECTORS = 1 << 20        # sectors a chain may visit
MAX_STREAMS = 4096           # directory entries read
MAX_LNKS = 4096              # LNKs carved from a custom-destinations file
MAX_STREAM_BYTES = 8 * 1024 * 1024
MAX_DESTLIST_ENTRIES = 100000
_LNK_HEADER = b"\x4c\x00\x00\x00" + windows._LNK_CLSID    # 20 bytes: a shell-link header start


# ---------------------------------------------------------------------------- CFB (bounded)

def _cfb_streams(data: bytes):
    """{stream name: bytes} of every stream in an OLE Compound File, or None when the bytes are not
    one or the structure does not validate. A bounded, tree-agnostic walk: the directory is read as a
    flat list of 128-byte entries along its FAT chain, which finds every named stream without the
    red-black tree. Any inconsistency returns None (a mis-read is never a wrong answer)."""
    if len(data) < 512 or data[:8] != CFB_MAGIC:
        return None
    try:
        sector_shift = struct.unpack_from("<H", data, 30)[0]
        mini_shift = struct.unpack_from("<H", data, 32)[0]
        if sector_shift not in (9, 12) or mini_shift != 6:
            return None
        sec_size = 1 << sector_shift
        mini_size = 1 << mini_shift
        num_fat = struct.unpack_from("<I", data, 44)[0]
        first_dir = struct.unpack_from("<I", data, 48)[0]
        mini_cutoff = struct.unpack_from("<I", data, 56)[0]
        first_minifat = struct.unpack_from("<I", data, 60)[0]
        num_minifat = struct.unpack_from("<I", data, 64)[0]
        first_difat = struct.unpack_from("<I", data, 68)[0]
        num_difat = struct.unpack_from("<I", data, 72)[0]
    except struct.error:
        return None
    # The header occupies the first whole sector; sector 0 therefore begins at ``sec_size`` (512 for a
    # v3/512-byte file, 4096 for a v4/4096-byte file), not at a fixed 512.
    total_sectors = (len(data) - sec_size) // sec_size

    def sector(n):
        if not (0 <= n < total_sectors):
            return None
        off = sec_size + n * sec_size
        return data[off:off + sec_size]

    # DIFAT: the 109 entries in the header, then the chained DIFAT sectors (each sector is
    # sec_size/4 - 1 FAT-sector pointers followed by the next DIFAT sector).
    fat_sectors = list(struct.unpack_from("<109I", data, 76))
    sec = first_difat
    seen = set()
    while sec not in (ENDOFCHAIN, FREESECT) and len(seen) < num_difat + 1 and len(seen) < MAX_SECTORS:
        if sec in seen:
            return None
        seen.add(sec)
        raw = sector(sec)
        if raw is None:
            return None
        vals = struct.unpack_from(f"<{sec_size // 4}I", raw)
        fat_sectors.extend(vals[:-1])
        sec = vals[-1]
    fat_sectors = [s for s in fat_sectors if s not in (FREESECT,)][:max(num_fat, 0) or len(fat_sectors)]

    # The FAT: concatenate every FAT sector's u32 array.
    fat = []
    for fs in fat_sectors:
        raw = sector(fs)
        if raw is None:
            return None
        fat.extend(struct.unpack_from(f"<{sec_size // 4}I", raw))
        if len(fat) > MAX_SECTORS:
            return None

    def chain(start, cap=MAX_SECTORS):
        out, cur, seen_c = [], start, set()
        while cur not in (ENDOFCHAIN, FREESECT, FATSECT, DIFSECT) and len(out) < cap:
            if cur in seen_c or cur >= len(fat):
                return None
            seen_c.add(cur)
            out.append(cur)
            cur = fat[cur]
        return out

    def read_fat_stream(start, size):
        ch = chain(start)
        if ch is None:
            return None
        buf = bytearray()
        for s in ch:
            raw = sector(s)
            if raw is None:
                return None
            buf.extend(raw)
            if len(buf) > MAX_STREAM_BYTES:
                return None
        return bytes(buf[:size]) if size is not None else bytes(buf)

    # Directory entries, flat along the directory chain.
    dir_chain = chain(first_dir)
    if dir_chain is None:
        return None
    dir_bytes = bytearray()
    for s in dir_chain:
        raw = sector(s)
        if raw is None:
            return None
        dir_bytes.extend(raw)
    entries = []
    per = sec_size // 128
    count = min(len(dir_bytes) // 128, per * len(dir_chain), MAX_STREAMS)
    for i in range(count):
        e = dir_bytes[i * 128:i * 128 + 128]
        if len(e) < 128:
            break
        name_len = struct.unpack_from("<H", e, 0x40)[0]
        obj_type = e[0x42]
        if obj_type not in (1, 2, 5) or not (0 < name_len <= 64):
            continue
        name = e[0:max(0, name_len - 2)].decode("utf-16-le", "replace")
        start = struct.unpack_from("<I", e, 0x74)[0]
        size = struct.unpack_from("<Q", e, 0x78)[0]
        entries.append({"name": name, "type": obj_type, "start": start, "size": size})

    root = next((e for e in entries if e["type"] == 5), None)
    if root is None:
        return None
    # The mini stream is the root entry's own stream, read from the FAT.
    mini_stream = read_fat_stream(root["start"], root["size"]) if root["size"] else b""
    if mini_stream is None:
        return None
    mini_fat = []
    if first_minifat not in (ENDOFCHAIN, FREESECT):
        mf_chain = chain(first_minifat, cap=max(num_minifat, 1) + 1)
        if mf_chain is None:
            return None
        for s in mf_chain:
            raw = sector(s)
            if raw is None:
                return None
            mini_fat.extend(struct.unpack_from(f"<{sec_size // 4}I", raw))

    def read_mini_stream(start, size):
        out, cur, seen_m = bytearray(), start, set()
        while cur not in (ENDOFCHAIN, FREESECT) and len(seen_m) < MAX_SECTORS:
            if cur in seen_m or cur >= len(mini_fat):
                return None
            seen_m.add(cur)
            off = cur * mini_size
            out.extend(mini_stream[off:off + mini_size])
            cur = mini_fat[cur]
            if len(out) >= size:
                break
        return bytes(out[:size])

    streams = {}
    for e in entries:
        if e["type"] != 2:
            continue
        size = min(e["size"], MAX_STREAM_BYTES)
        if e["size"] < mini_cutoff:
            body = read_mini_stream(e["start"], size)
        else:
            body = read_fat_stream(e["start"], size)
        if body is None:
            return None
        streams[e["name"]] = body
        if len(streams) > MAX_STREAMS:
            return None
    return streams


# ---------------------------------------------------------------------------- DestList (self-validating)

def _hostname(block: bytes) -> str:
    return block.split(b"\x00", 1)[0].decode("ascii", "replace").strip()


def _parse_destlist(body: bytes, stream_ids: set):
    """[{entry, hostname, access_time, pinned, path}] in MRU order, or None when the parse does not
    cleanly account for every destination. Self-validating: the header version is 1/3/4, the walk
    parses exactly the header's entry count, every entry number maps to an existing numbered stream,
    the set of parsed entry numbers equals the stream id set, and the body is consumed to its end
    (a few trailing bytes aside). Any failure returns None, so a wrong byte layout is never a wrong
    answer -- the MRU facts simply fall back to None and the numbered streams still answer."""
    if len(body) < 32:
        return None
    version = struct.unpack_from("<I", body, 0)[0]
    nentries = struct.unpack_from("<I", body, 4)[0]
    if version not in (1, 3, 4) or not (0 <= nentries <= MAX_DESTLIST_ENTRIES):
        return None
    # libyal Jump Lists format 2.1.2 per-entry layout (relative to the entry start): a 16-byte
    # hostname at 72, the entry number (u32) at 88, the FILETIME (u64) at 100, the pin status (u32)
    # at 108, then the path character count (u16) at 112 for version 1 and at 128 for versions 3/4
    # (the two extra u64/u32 unknowns add 16 bytes before the count).
    extra = 0 if version == 1 else 16
    o = 32
    out, nums = [], []
    for _ in range(nentries):
        if o + 112 + extra + 2 > len(body):
            return None
        entry_no = struct.unpack_from("<I", body, o + 88)[0]
        access = windows.filetime(struct.unpack_from("<Q", body, o + 100)[0])
        pin = struct.unpack_from("<I", body, o + 108)[0]
        nchars = struct.unpack_from("<H", body, o + 112 + extra)[0]
        pstart = o + 112 + extra + 2
        if nchars > 32768 or pstart + 2 * nchars > len(body):
            return None
        path = body[pstart:pstart + 2 * nchars].decode("utf-16-le", "replace")
        hexname = format(entry_no, "x")
        if hexname not in stream_ids and str(entry_no) not in stream_ids:
            return None
        out.append({"entry": entry_no, "hostname": _hostname(body[o + 72:o + 88]),
                    "access_time": access, "pinned": pin != 0xFFFFFFFF, "path": path})
        nums.append(entry_no)
        o = pstart + 2 * nchars
        if version != 1:
            o += 4            # version 3/4 trailing unknown u32
    if len(set(nums)) != len(nums):
        return None
    if o > len(body) or len(body) - o > max(8, 2 * version):
        return None           # the walk must consume the body (a short, bounded trailer aside)
    want = {format(n, "x") for n in nums} | {str(n) for n in nums}
    if not {s for s in stream_ids}.issubset(want):
        return None           # every numbered stream must be named by exactly one DestList entry
    return out


# ---------------------------------------------------------------------------- LNK carve (custom-destinations)

def _carve_lnks(data: bytes) -> list:
    """Every shell link carved from a .customDestinations-ms (or any blob), by its 20-byte header
    (the size 0x4C and the fixed LNK CLSID). A false positive is all but impossible, so a carve is
    never a wrong answer; order is file order (custom-destinations carry no reliable MRU)."""
    out, i, n = [], 0, len(data)
    while i + 20 <= n and len(out) < MAX_LNKS:
        j = data.find(_LNK_HEADER, i)
        if j < 0:
            break
        try:
            link = windows.lnk(data[j:])
        except ValueError:
            i = j + 4
            continue
        out.append({"offset": j, "lnk": link})
        i = j + 76        # past this header; the next find re-syncs on the next CLSID
    return out


# ---------------------------------------------------------------------------- classify / parse

def _is_numbered(name: str) -> bool:
    return bool(name) and len(name) <= 16 and all(c in "0123456789abcdefABCDEF" for c in name)


def classify(data: bytes, name: str = "") -> dict:
    """{"kind": "automatic"|"custom"} for a file this module can validate as a Jump List, else None.
    Validated from the real container only: a CFB with at least one numbered stream that is a shell
    link (automatic), or a blob whose name ends .customDestinations-ms and that carries a shell link
    (custom). The filename is used only to disambiguate custom-destinations, never to invent a fact."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 76 or len(data) > MAX_BYTES:
        return None
    base = Path(str(name)).name.lower()
    if data[:8] == CFB_MAGIC:
        streams = _cfb_streams(bytes(data))
        if streams:
            numbered = [s for s in streams if _is_numbered(s)]
            if numbered and any(streams[s][:20].startswith(_LNK_HEADER[:4])
                                and streams[s][4:20] == windows._LNK_CLSID for s in numbered):
                return {"kind": "automatic"}
    if base.endswith(".customdestinations-ms") and _LNK_HEADER in bytes(data[:MAX_BYTES]):
        if _carve_lnks(bytes(data)):
            return {"kind": "custom"}
    # A nameless custom-destinations blob is taken only when it is clearly a run of shell links and
    # no CFB: at least two carved LNKs, so a single stray LNK file is left to the shortcuts reader.
    if not base.endswith(".customdestinations-ms") and data[:4] != CFB_MAGIC[:4]:
        if _LNK_HEADER in bytes(data[:MAX_BYTES]) and len(_carve_lnks(bytes(data))) >= 2:
            return {"kind": "custom"}
    return None


def _app_id(name: str):
    """The AppID: the hex stem of an automaticDestinations-ms / customDestinations-ms file, else None.
    It is derived from the file NAME (a known-but-unjudged label), so it is answered only unsure."""
    base = Path(str(name)).name
    m = re.match(r"^([0-9a-fA-F]{8,20})\.(?:automatic|custom)Destinations-ms$", base)
    return m.group(1).lower() if m else None


def parse(data: bytes, name: str = "") -> dict:
    """A structured reading of a Jump List, or None when the bytes are not one. Shape:
      {"kind", "app_id", "stream_count", "destlist_ok", "mru": [entry no, ...] | None,
       "entries": [{"id"|"offset", "lnk": <windows.lnk dict>, "destlist": {...} | None}]}
    Every LNK comes from the armed windows.lnk(); DestList facts are attached only on a clean,
    self-validating parse (else destlist_ok False and the MRU is None)."""
    cl = classify(data, name)
    if cl is None:
        return None
    out = {"kind": cl["kind"], "app_id": _app_id(name), "stream_count": None,
           "destlist_ok": False, "mru": None, "entries": []}
    data = bytes(data)
    if cl["kind"] == "automatic":
        streams = _cfb_streams(data) or {}
        numbered = sorted((s for s in streams if _is_numbered(s)), key=lambda s: int(s, 16))
        out["stream_count"] = len(numbered)
        lnk_by_id = {}
        for s in numbered:
            try:
                lnk_by_id[s] = windows.lnk(streams[s])
            except ValueError:
                lnk_by_id[s] = None
        dl = _parse_destlist(streams["DestList"], set(numbered)) if "DestList" in streams else None
        dl_by_entry = {d["entry"]: d for d in dl} if dl else {}
        if dl is not None:
            out["destlist_ok"] = True
            out["mru"] = [d["entry"] for d in dl]
        for s in numbered:
            n = int(s, 16)
            out["entries"].append({"id": s, "lnk": lnk_by_id.get(s),
                                   "destlist": dl_by_entry.get(n)})
    else:
        for item in _carve_lnks(data):
            out["entries"].append({"offset": item["offset"], "lnk": item["lnk"], "destlist": None})
        out["stream_count"] = len(out["entries"])
    return out


# ---------------------------------------------------------------------------- reports / signals

def reports(files) -> list:
    out = []
    try:
        for name, data in triage.unique_files(files or {}):
            try:
                rep = parse(data, name)
            except Exception:  # noqa: BLE001 - one unreadable file does not cost the others
                rep = None
            if rep is not None:
                out.append((name, rep))
    except Exception:  # noqa: BLE001
        return []
    return out


_WORDS = re.compile(
    r"jump[ _-]?list|automaticdestinations|customdestinations|destinations-ms|\bdestlist\b|"
    r"\blnk\b|shell ?link|\bmru\b|most recently used|recent (?:file|document|item)|"
    r"pinned|app ?id|appid|shortcut|\btracker\b", re.I)


def signals(questions, files) -> float:
    """0..1: a validatable Jump List container in the bytes plus Jump List vocabulary. 0.0 when
    nothing validates, so the toolkit never competes on anything but a real Jump List."""
    try:
        reps = reports(files or {})
    except Exception:  # noqa: BLE001
        reps = []
    if not reps:
        return 0.0
    score = 0.55
    hits = set()
    for q in questions or []:
        f = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
        text = " ".join(str(x or "") for x in (q.get("question"), q.get("answer_id") or q.get("id"),
                                               f.get("syntax")))
        hits |= {m.group().lower() for m in _WORDS.finditer(text)}
    score += min(0.4, 0.1 * len(hits))
    return round(min(1.0, score), 2)


# ---------------------------------------------------------------------------- answers (never-guess)

def _q_id(q):
    return q.get("qid") or q.get("id") or q.get("answer_id")


def _aid(q):
    return str(q.get("answer_id") or q.get("id") or q.get("qid") or "")


def _pick(field, shape, aid, options):
    """An unsure pick keyed per-question (so an accepted name answers only this answer id), options
    being (format-name, value) pairs for ONE fact. None when there is no option."""
    opts = [(str(n), str(v)) for n, v in options if v is not None and str(v) != ""]
    if not opts:
        return None
    try:
        return labels.pick(f"{KEY}.{FIELD}{field}/{shape}@{aid}", opts)
    except Exception:  # noqa: BLE001
        return None


def _candidates(field, shape, aid, options):
    """An unsure candidate pick (row 346): NAMES are hypotheses, VALUES differ, re-derived per variant.
    A bare option (name == value) is dropped by labels.candidates, so every name here is a word."""
    opts = [(str(n), str(v)) for n, v in options if v is not None and str(v) != "" and str(n) != str(v)]
    if not opts:
        return None
    try:
        return labels.candidates(f"{KEY}.{FIELD}{field}/{shape}@{aid}", opts)
    except Exception:  # noqa: BLE001
        return None


def _path_options(path):
    p = str(path)
    opts = [("raw", p)]
    low = p.lower()
    if low != p:
        opts.append(("lower", low))
    base = re.split(r"[\\/]", p)[-1]
    if base and base != p:
        opts.append(("basename", base))
    if "\\" in p:
        opts.append(("forward", p.replace("\\", "/")))
    return opts


def _serial_options(v):
    try:
        n = int(v)
    except (TypeError, ValueError):
        return []
    return [("hex", f"{n:08x}"), ("hex_upper", f"{n:08X}"), ("hex_dashed", f"{n >> 16:04x}-{n & 0xFFFF:04x}"),
            ("hex_0x", f"0x{n:08x}"), ("decimal", str(n))]


def _one(values):
    """The single distinct non-empty value among entries, or None (two readings are never a fact)."""
    seen = [v for v in values if v not in (None, "")]
    uniq = list(dict.fromkeys(seen))
    return uniq[0] if len(uniq) == 1 else None


def _answer_one(q, rep):
    text = str(q.get("question") or "")
    aid = _aid(q)
    t = (text + " " + aid).lower()

    def has(*words):
        return any(re.search(r"(?<![a-z])" + w + r"(?![a-z])", t) for w in words)

    if has("flag"):
        return None

    entries = rep.get("entries") or []
    lnks = [e["lnk"] for e in entries if e.get("lnk")]

    # Count of destinations / entries. Several readings are plausible (numbered streams, DestList
    # entry count, pinned), so they are hypotheses under a candidate key: never plain until judged,
    # re-counted from the bytes on every variant.
    _count_noun = re.compile(r"destination|entr(?:y|ies)|\bfiles?\b|\bitems?\b|shortcut|\blinks?\b|record")
    if has("how many", "number of", "count") and _count_noun.search(t):
        opts = [("streams", rep.get("stream_count"))]
        if rep.get("mru") is not None:
            opts.append(("destlist_entries", len(rep["mru"])))
        pinned = sum(1 for e in entries if (e.get("destlist") or {}).get("pinned"))
        if pinned:
            opts.append(("pinned", pinned))
        return _candidates("count", "n", aid, opts)

    # AppID: derived from the filename, a known-but-unjudged label.
    if has("app ?id", "appid", "application id") and rep.get("app_id"):
        return _pick("app_id", "hex", aid, [("appid", rep["app_id"])])

    # The MRU / most-recent destination's target path (only on a clean DestList with its LNK).
    if has("most recent", "recent", "mru", "last", "latest") and has("path", "target", "file", "document", "open", "destination"):
        if rep.get("mru"):
            first = rep["mru"][0]
            lnk = next((e["lnk"] for e in entries if e.get("id") and int(e["id"], 16) == first and e.get("lnk")), None)
            tp = lnk.get("target_path") if lnk else None
            if tp:
                return _pick("mru_target", "path", aid, _path_options(tp))
        return None

    # A single-destination target path (no MRU needed when there is exactly one).
    if has("path", "target", "file", "document", "folder", "directory", "open") and not has("volume", "serial", "label", "mac", "host"):
        tp = _one([l.get("target_path") for l in lnks])
        if tp:
            return _pick("target", "path", aid, _path_options(tp))
        return None

    # Volume serial number of the target's volume (one distinct value only).
    if has("volume") and has("serial", "id"):
        vs = _one([l.get("volume_serial") for l in lnks])
        if vs:
            return _pick("volume_serial", "serial", aid, _serial_options(vs))
        return None

    if has("volume") and has("label", "name"):
        vl = _one([l.get("volume_label") for l in lnks])
        if vl:
            return _pick("volume_label", "text", aid, [("raw", vl), ("lower", str(vl).lower())])
        return None

    if has("drive") and has("type"):
        dt = _one([l.get("drive_type") for l in lnks])
        if dt:
            return _candidates("drive_type", "enum", aid, [("drive_type", dt)])
        return None

    # Tracker block: machine id (NetBIOS name) and MAC address.
    if (has("machine", "computer", "netbios", "host") and not has("serial")) and has("id", "name", "machine", "computer"):
        mid = _one([l.get("machine_id") for l in lnks]) or _one(
            [(e.get("destlist") or {}).get("hostname") for e in entries])
        if mid:
            return _pick("machine_id", "text", aid, [("raw", mid), ("lower", str(mid).lower()), ("upper", str(mid).upper())])
        return None

    if has("mac", "hardware address", "physical address"):
        mac = _one([l.get("mac_address") for l in lnks])
        if mac:
            m = str(mac)
            return _pick("mac_address", "mac", aid, [("colon_lower", m), ("colon_upper", m.upper()),
                                                     ("dash", m.replace(":", "-")),
                                                     ("bare", m.replace(":", ""))])
        return None

    # A time: the LNK write/access/creation time, or the DestList recorded access time.
    if has("time", "when", "date", "timestamp", "accessed", "modified", "created", "written"):
        stamp = None
        if has("creat"):
            stamp = _one([l.get("creation_time") for l in lnks])
        elif has("access", "open", "used"):
            stamp = (_one([(e.get("destlist") or {}).get("access_time") for e in entries])
                     or _one([l.get("access_time") for l in lnks]))
        elif has("modif", "written", "write"):
            stamp = _one([l.get("write_time") for l in lnks])
        if stamp is None and len(lnks) == 1:
            stamp = lnks[0].get("write_time") or lnks[0].get("creation_time")
        if stamp is not None:
            try:
                return _pick("time", "iso", aid, windows.time_options(stamp))
            except Exception:  # noqa: BLE001
                return None
        return None

    return None


def _file_for(q, reps):
    member = q.get("member") or (str(q.get("artifact") or "").split(ARROW)[-1] if q.get("artifact") else "")
    base = Path(str(member)).name if member else ""
    if base:
        hit = [r for r in reps if Path(r[0]).name == base or r[0].split(ARROW)[-1] == member or r[0] == member]
        if len(hit) == 1:
            return hit[0][1]
        if hit:
            return None
    return reps[0][1] if len(reps) == 1 else None


def solve_set(questions, files, ctx) -> dict:
    reps = reports(files)
    out = {}
    for q in questions or []:
        qid = _q_id(q)
        if qid is None:
            continue
        rep = _file_for(q, reps)
        out[qid] = None if rep is None else _answer_one(q, rep)
    return out


# ---------------------------------------------------------------------------- CLI (offline triage)

def _jsonable(v):
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_jsonable(x) for x in v]
    if isinstance(v, (bytes, bytearray)):
        return v.decode("latin-1", "replace")
    if isinstance(v, windows.Stamp):
        return v.iso()
    return v


def main(argv) -> int:
    as_json = "--json" in argv
    paths = [a for a in argv if not a.startswith("--")]
    if not paths:
        print("usage: jumplist.py <file>... [--json]   (RECON ONLY; Jump List containers, flag always None)",
              file=sys.stderr)
        return 2
    out = []
    for p in paths:
        try:
            data = Path(p).read_bytes()
        except OSError as e:
            print(f"jumplist.py: {p}: {e}", file=sys.stderr)
            continue
        rep = parse(data, Path(p).name)
        out.append({"file": p, "report": _jsonable(rep), "bytes": len(data)})
    if as_json:
        print(json.dumps(out, indent=1))
        return 0
    for row in out:
        rep = row["report"]
        if not rep:
            print(f"- {row['file']}: no Jump List container recognised ({row['bytes']} bytes)")
            continue
        print(f"# {row['file']}  [{rep['kind']}]  app_id={rep.get('app_id')}  "
              f"destinations={rep.get('stream_count')}  destlist_ok={rep.get('destlist_ok')}")
        if rep.get("mru"):
            print(f"    mru (most recent first): {rep['mru']}")
        for e in rep["entries"]:
            lnk = e.get("lnk") or {}
            who = e.get("id") if e.get("id") is not None else f"@{e.get('offset')}"
            print(f"    entry {who}: target={lnk.get('target_path')!r} write={lnk.get('write_time')} "
                  f"vol_serial={lnk.get('volume_serial')} mac={lnk.get('mac_address')} machine={lnk.get('machine_id')}")
        print("  container/LNK facts only; nothing is judged, so every answer is unsure or None; the flag is None.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
