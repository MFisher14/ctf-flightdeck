#!/usr/bin/env python3
"""Structural fallback net for three single-point Metadata facts (branch wave90).

The adaptable cold-replay test (`docs/retro/adaptable-cold-replay-metadata.md`) found three
judged facts that drop to a HARD `None`, unclosable by a probe, when their one dedicated reader
is absent or cannot parse a variant's container:

  metadata.format/msi.product_code_guid    (readers_msi.py:    the MSI Property table)
  metadata.format/dotnet_mvid_guid         (readers_dotnet.py: the CLR #GUID heap)
  metadata.media.primary_audio_codec_name  (readers_media.py:  ffprobe)

Each is read by a SINGLE reader with no generic/nearest/collection fallback, so a new MSI, CLR
or media shape it does not parse (or the pack being unavailable) returns `None` outright and
`tools/verify.py`'s probe loop can never close the base -> the lane STOPs for an agent
(Day 12 dotnet and Day 13 msi both did exactly this historically).

This module adds a GENERIC, STRUCTURAL degrade. properties_strict.answer_question() consults
`offer(prop, q, data)` ONLY when the whole normal path (the specific reader, the nearest
reader, guess(), present_collection(), the stated-spec net) has already returned `None` for one
of these facts. It then locates the value STRUCTURALLY from the raw bytes and returns an UNSURE
`labels.candidates` pick, so a probe on the untimed base / a regular attempt closes the id in a
probe or two instead of never.

BRIGHT LINE (enforced here): the value is NEVER offered plain. It is always a candidate pick
(`labels.candidates`, key ending in `#candidates`), per-delivery scoped (the key carries the full
SHA-256 digest of the target bytes), so:
  * it is unsure until the judge accepts a rendering/hypothesis NAME for this delivery's key;
  * it never reuses the fact's already-judged plain key, so it can never go out plain unprobed;
  * `verify.py` probes it on the base, and the runners only on an attempt with no deadline
    (row 346); nothing of it reaches CourseStack.
The specific reader's own PLAIN answer, where it fires, is untouched: this module is consulted
only when that reader returned None (an unsure reader answer is already closable in one probe
and is left as is). Ambiguous or absent -> None (never a look-alike, never a default).
"""
import hashlib
import re
import struct
import sys
import uuid

try:
    import labels
except Exception:  # pragma: no cover - properties_strict puts solvers/common on sys.path first
    labels = None


def _log(line: str):
    print(line, file=sys.stderr)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- GUID rendering (one located GUID)

def _guid_forms(digits32: str, stored_text=None):
    """Standard renderings of one GUID, as (hypothesis-name, value) candidate options, best
    first. `digits32` is the 32 lowercase hex digits in written order (8-4-4-4-12). When the GUID
    was read as TEXT (an MSI Property row), `stored_text` is that exact text and is offered first
    under `as_stored`, as the judged Day-13 form was the stored text (row 284)."""
    hy = f"{digits32[:8]}-{digits32[8:12]}-{digits32[12:16]}-{digits32[16:20]}-{digits32[20:]}"
    forms = [
        ("hyphen_lower", hy),
        ("hyphen_upper", hy.upper()),
        ("compact_lower", digits32),
        ("compact_upper", digits32.upper()),
        ("braces_upper", "{" + hy.upper() + "}"),
        ("braces_lower", "{" + hy + "}"),
    ]
    opts = []
    seen = set()
    if stored_text:
        name = next((n for n, v in forms if v == stored_text), "as_stored")
        opts.append((name, stored_text))
        seen.add(stored_text)
    for n, v in forms:
        if v not in seen:
            opts.append((n, v))
            seen.add(v)
    return opts


_GUID_TXT = re.compile(
    r"\{?([0-9A-Fa-f]{8})-([0-9A-Fa-f]{4})-([0-9A-Fa-f]{4})-([0-9A-Fa-f]{4})-([0-9A-Fa-f]{12})\}?")


def _digits_of_match(m) -> str:
    return "".join(m.group(i) for i in range(1, 6)).lower()


# ---------------------------------------------------------------- MSI: a GUID near a Property anchor

_MSI_ANCHORS = {
    "product_code": "ProductCode",
    "upgrade_code": "UpgradeCode",
}


def _msi_anchor_for(prop: str):
    core = prop.split("/")[-1]
    core = core[len("msi."):] if core.startswith("msi.") else core
    core = core[:-len("_guid")] if core.endswith("_guid") else core
    return _MSI_ANCHORS.get(core)


def _locate_msi_guid(prop: str, data: bytes):
    """The GUID stored next to the Property-table anchor (ProductCode / UpgradeCode) in an MSI's
    string streams. MSI `_StringData` concatenates the column strings, so a Property row's value
    sits right after its name. Read both the Latin-1 (code-page) and the UTF-16LE views; a GUID
    must START within 3 characters of the anchor to count as that row's value. Returns
    (digits32, stored_text) only when exactly ONE distinct GUID is located this way, else None."""
    anchor = _msi_anchor_for(prop)
    if anchor is None:
        return None
    views = []
    try:
        views.append(data.decode("latin1"))
    except Exception:
        pass
    try:
        views.append(data.decode("utf-16-le"))
    except Exception:
        pass
    found = {}
    for view in views:
        for am in re.finditer(re.escape(anchor), view):
            tail = view[am.end():am.end() + 3 + 40]
            gm = _GUID_TXT.search(tail)
            if gm is not None and gm.start() <= 3:
                digits = _digits_of_match(gm)
                found.setdefault(digits, gm.group(0))
    if len(found) != 1:
        return None
    digits, text = next(iter(found.items()))
    return digits, text


# ---------------------------------------------------------------- .NET: the MVID in the #GUID heap

def _locate_dotnet_mvid(data: bytes):
    """The module version id: the first GUID of the `#GUID` heap of a managed PE's CLR metadata.
    Find the `BSJB` metadata root, walk its stream headers to `#GUID`, and read its first 16
    bytes as a little-endian GUID (bytes_le; the .NET module id at index 1). Independent of a full
    CLR-metadata parse. Returns digits32, or None when no managed metadata / empty heap."""
    if data[:2] != b"MZ":
        return None
    root = data.find(b"BSJB")
    if root < 0 or root + 20 > len(data):
        return None
    try:
        _sig, _maj, _min, _reserved, verlen = struct.unpack_from("<IHHII", data, root)
    except struct.error:
        return None
    if verlen < 0 or verlen > 256 or root + 16 + verlen + 4 > len(data):
        return None
    rel = 16 + verlen
    rel = (rel + 3) & ~3       # the version string is padded to a 4-byte boundary, relative to the root
    p = root + rel
    if p + 4 > len(data):
        return None
    _flags, streams = struct.unpack_from("<HH", data, p)
    p += 4
    if streams <= 0 or streams > 64:
        return None
    for _ in range(streams):
        if p + 8 > len(data):
            return None
        soff, ssize = struct.unpack_from("<II", data, p)
        p += 8
        end = data.find(b"\x00", p)
        if end < 0:
            return None
        name = data[p:end]
        p += ((end - p) // 4 + 1) * 4   # name is null-terminated and padded to 4 bytes
        if name == b"#GUID":
            gstart = root + soff
            if ssize < 16 or gstart + 16 > len(data):
                return None
            raw = data[gstart:gstart + 16]
            if raw == b"\x00" * 16:
                return None
            try:
                return uuid.UUID(bytes_le=raw).hex
            except Exception:
                return None
    return None


# ---------------------------------------------------------------- media: the codec from the RIFF fmt tag

# WAVE format tags -> ffprobe codec names. PCM and float depend on the bit width.
_WAV_PCM = {8: "pcm_u8", 16: "pcm_s16le", 24: "pcm_s24le", 32: "pcm_s32le"}
_WAV_FLOAT = {32: "pcm_f32le", 64: "pcm_f64le"}
_WAV_TAG = {
    0x0006: "pcm_alaw", 0x0007: "pcm_mulaw",
    0x0055: "mp3", 0x0050: "mp2",
    0x2000: "ac3", 0x2001: "dts",
    0x00FF: "aac",
}
# KSDATAFORMAT_SUBTYPE GUIDs (16 bytes) for WAVE_FORMAT_EXTENSIBLE, e.g. PCM is
# 00000001-0000-0010-8000-00AA00389B71 stored as a GUID (first three fields little-endian).
_KS_SUFFIX = bytes.fromhex("000000001000800000aa00389b71")  # the 14 bytes after the 2-byte format tag
_EXT_PCM_GUID = struct.pack("<H", 0x0001) + _KS_SUFFIX
_EXT_FLOAT_GUID = struct.pack("<H", 0x0003) + _KS_SUFFIX
# IEC 61937 (S/PDIF) burst preamble Pa,Pb, both byte orders: a compressed stream in a PCM wrapper.
_IEC_PREAMBLES = (bytes.fromhex("72f81f4e"), bytes.fromhex("f8721f4e"), bytes.fromhex("1f4e72f8"))


def _wav_chunks(data: bytes):
    """Yield (chunk-id, body-offset, size) for a well-formed little-endian RIFF/WAVE file, or None
    for a header that is not `RIFF....WAVE` or a chunk that runs past the end of the file."""
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        return None
    out = []
    p, n = 12, len(data)
    while p + 8 <= n:
        cid = data[p:p + 4]
        csz = struct.unpack_from("<I", data, p + 4)[0]
        body = p + 8
        if body + csz > n:               # a chunk cut by the end of the file: malformed
            return None
        out.append((cid, body, csz))
        p = body + csz + (csz & 1)
    return out


def _locate_wav_codec(data: bytes):
    """The audio codec implied by a CLEAN, unambiguous RIFF/WAVE `fmt ` chunk: the format tag (and
    bit width for PCM/float, the verified subformat GUID for WAVE_FORMAT_EXTENSIBLE). Returns a
    ffprobe-style codec name, or None for anything ambiguous or malformed -- a non-RIFF/WAVE file,
    more than one `fmt ` chunk, `data` before `fmt `, no `data` chunk, a short/cut `fmt `, zero
    channels or sample rate, a foreign extensible subformat, a bit width with no exact PCM/float
    name, or a `data` chunk that begins with an IEC 61937 (S/PDIF) compressed burst."""
    chunks = _wav_chunks(data)
    if not chunks:
        return None
    fmts = [c for c in chunks if c[0] == b"fmt "]
    datas = [c for c in chunks if c[0] == b"data"]
    if len(fmts) != 1 or not datas:
        return None                       # two fmt chunks, or no data chunk: ambiguous
    fmt_body = fmts[0][1]
    data_body = datas[0][1]
    if data_body < fmt_body:              # data before fmt: malformed
        return None
    size = fmts[0][2]
    if size < 16:
        return None
    fmt = data[fmt_body:fmt_body + min(size, 40)]
    if len(fmt) < 16:
        return None
    tag, channels, rate, _bps, _align, bits = struct.unpack_from("<HHIIHH", fmt, 0)
    if channels <= 0 or rate <= 0:
        return None
    # a S/PDIF / IEC 61937 burst wrapped in a PCM header is a compressed stream, not PCM
    head = data[data_body:data_body + 4]
    if head in _IEC_PREAMBLES:
        return None
    if tag == 0xFFFE:                     # WAVE_FORMAT_EXTENSIBLE: verify the full 16-byte subformat GUID
        if len(fmt) < 40:
            return None
        valid_bits = struct.unpack_from("<H", fmt, 18)[0]
        sub = data[fmt_body + 24:fmt_body + 40]
        eff = valid_bits or bits
        if sub == _EXT_PCM_GUID:
            return _WAV_PCM.get(eff)
        if sub == _EXT_FLOAT_GUID:
            return _WAV_FLOAT.get(eff)
        return None
    if tag == 0x0001:
        return _WAV_PCM.get(bits)
    if tag == 0x0003:
        return _WAV_FLOAT.get(bits)
    return _WAV_TAG.get(tag)


# ---------------------------------------------------------------- the entry point

_GUID_PROPS = re.compile(r"(?:^|[._])(?:product_code|upgrade_code)_guid$|(?:^|[._])mvid_guid$")
_MEDIA_PROPS = re.compile(
    r"(?:^|[._])(?:primary_|first_|main_|default_)?audio(?:_stream|_track)?_codec(?:_name)?$")


def offer(prop: str, q: dict, data: bytes):
    """A structural, unsure-only candidate for one of the three single-point facts, or None.

    prop   the dotted property name properties_strict resolved for the question
           (`msi.product_code_guid`, `dotnet_mvid_guid`, `media.primary_audio_codec_name`, ...).
    data   the bytes of the target file properties_strict chose for the question.
    Returns a `labels.candidates` unsure string (never plain), or None when the fact cannot be
    located structurally or the value is ambiguous."""
    if labels is None or not prop or not data:
        return None
    p = prop.lower()
    aid = q.get("answer_id") or q.get("qid") or prop

    if _GUID_PROPS.search(p):
        if ".mvid_guid" in p or p.endswith("mvid_guid"):
            digits = _locate_dotnet_mvid(data)
            if not digits:
                return None
            key = "metadata.format/dotnet_mvid_guid+structural_" + _digest(data)
            opts = _guid_forms(digits)
            where = "CLR #GUID heap"
        else:
            located = _locate_msi_guid(p, data)
            if located is None:
                return None
            digits, stored = located
            core = p.split("/")[-1]
            key = "metadata.format/" + core + "+structural_" + _digest(data)
            opts = _guid_forms(digits, stored_text=stored)
            where = "MSI Property table"
        _log(f"STRUCTURAL FALLBACK {aid}: {prop} located a GUID in the {where} structurally "
             f"(no dedicated reader answered); unsure candidate under {key}, the stored/raw form first")
        return labels.candidates(key, opts)

    if _MEDIA_PROPS.search(p):
        codec = _locate_wav_codec(data)
        if not codec:
            return None
        key = "metadata.media.primary_audio_codec_name/fmt_fallback_" + _digest(data)
        _log(f"STRUCTURAL FALLBACK {aid}: {prop} read codec '{codec}' from the RIFF fmt tag "
             f"(no media reader answered); unsure candidate under {key}")
        return labels.candidates(key, [("fmt_tag", codec)])

    return None
