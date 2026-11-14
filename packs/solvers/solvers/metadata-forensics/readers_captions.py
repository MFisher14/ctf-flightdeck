#!/usr/bin/env python3
"""Metadata Forensics captions and places pack (the Day 19 look-ahead's build item 5).

properties_strict.py loads this file by name (MORE_FILES, after readers_video.py) and calls register(M). It adds
five namespaces no reader had: `srt`, `vtt` (`webvtt`), `ass` (`ssa`), the format-free `subtitle` (`caption`,
`captions`, `subtitles`), `gpx` and `kml`. Nothing here is judged: every answer is unsure (labels.pick through the
class of its reader), and a file that does not parse whole in its format is Unknown, never a partial count.

  captions   a SubRip file (numbered blocks, 'HH:MM:SS,mmm --> HH:MM:SS,mmm'), a WebVTT file ('WEBVTT' first, NOTE,
             STYLE and REGION blocks skipped, cue settings after the times) and an ASS/SSA script (the [Events]
             section's Format line names the Text field; Dialogue lines): cue_count, first and last cue text, the
             first cue's start and the last cue's end (as stored, then in seconds), the cue texts as a JSON list.
             An ASS text is offered as stored first and without its {override} tags and \\N breaks second.
  gpx        the root's version and creator, the metadata name, time and description, the number of tracks,
             track segments, track points, waypoints, routes and route points, the first track's name, the first and
             last track point's latitude, longitude, elevation and time (latitude and the like as stored, then as
             the shortest decimal).
  kml        the Document's name, the number of Placemarks, the first Placemark's name and coordinates (as stored,
             trimmed), and its latitude and longitude (KML writes longitude first).

media.* of a caption file (format and codec name, ffprobe's 'srt' / 'subrip', 'webvtt', 'ass') is readers_media.py's,
which asks kind_of() here. The XML is read with the standard library's parser, never with a DOCTYPE (a file that has
one is Unknown: no entity is expanded), and only up to 16 MiB.
"""
import json
import re

M = None

MAX_BYTES = 1 << 24
SRT_TIME = re.compile(r"(\d{1,3}):([0-5]\d):([0-5]\d)[,.](\d{3})")
VTT_TIME = re.compile(r"(?:(\d{1,3}):)?([0-5]\d):([0-5]\d)\.(\d{3})")
ASS_TIME = re.compile(r"(\d{1,2}):([0-5]\d):([0-5]\d)\.(\d{2})")


def U(msg):
    raise M.Unknown(msg)


def _text(d: bytes):
    if len(d) > MAX_BYTES:
        U("a text file larger than is read here")
    if d[:3] == b"\xef\xbb\xbf":
        d = d[3:]
    try:
        return d.decode("utf-8")
    except UnicodeDecodeError:
        U("a caption or place file that is not UTF-8")


def kind_of(d: bytes):
    """'srt', 'vtt', 'ass' or 'gpx' / 'kml' for a file of one of these formats by its first bytes, else None."""
    head = d[:4096].lstrip(b"\xef\xbb\xbf").lstrip()
    if head.startswith(b"WEBVTT") and (len(head) == 6 or head[6:7] in (b"\n", b"\r", b" ", b"\t")):
        return "vtt"
    if head.startswith(b"[Script Info]"):
        return "ass"
    lines = head.split(b"\n", 2)
    if len(lines) >= 2 and lines[0].strip().isdigit() and b"-->" in lines[1] and \
            SRT_TIME.match(lines[1].decode("latin-1").strip()):
        return "srt"
    if head.startswith(b"<?xml") or head.startswith(b"<"):
        top = head[:1024]
        if b"<gpx" in top:
            return "gpx"
        if b"<kml" in top:
            return "kml"
    return None


def _seconds(m, frac_digits):
    h, mi, s, f = m.groups()
    return int(h or 0) * 3600 + int(mi) * 60 + int(s) + int(f) / 10 ** frac_digits


def _blocks(s: str):
    return [b for b in re.split(r"\r?\n[ \t]*\r?\n", s.replace("\r\n", "\n").strip("\n")) if b.strip()]


def _srt(s: str):
    cues = []
    for b in _blocks(s):
        lines = b.split("\n")
        if len(lines) < 2 or not lines[0].strip().isdigit():
            U("a SubRip block that does not start with its number")
        t = lines[1].strip().split("-->")
        if len(t) != 2:
            U("a SubRip block without its time line")
        a, z = SRT_TIME.fullmatch(t[0].strip()), SRT_TIME.match(t[1].strip())
        if not a or not z:
            U("a SubRip time that does not read")
        cues.append((t[0].strip(), t[1].strip().split()[0], _seconds(a, 3), _seconds(z, 3), "\n".join(lines[2:])))
    return cues


def _vtt(s: str):
    blocks = _blocks(s)
    if not blocks or not blocks[0].startswith("WEBVTT"):
        U("not a WebVTT file")
    cues = []
    for b in blocks[1:]:
        lines = b.split("\n")
        if lines[0].startswith(("NOTE", "STYLE", "REGION")):
            continue
        if "-->" not in lines[0]:
            lines = lines[1:]          # a cue identifier
        if not lines or "-->" not in lines[0]:
            U("a WebVTT block without its time line")
        t = lines[0].split("-->")
        start, rest = t[0].strip(), t[1].strip().split()
        a, z = VTT_TIME.fullmatch(start), VTT_TIME.fullmatch(rest[0]) if rest else None
        if not a or not z:
            U("a WebVTT time that does not read")
        cues.append((start, rest[0], _seconds(a, 3), _seconds(z, 3), "\n".join(lines[1:])))
    return cues


def _ass(s: str):
    section, fmt, cues = None, None, []
    for line in s.replace("\r\n", "\n").split("\n"):
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line.lower()
            continue
        if section != "[events]":
            continue
        if line.startswith("Format:"):
            fmt = [x.strip().lower() for x in line[7:].split(",")]
        elif line.startswith("Dialogue:"):
            if not fmt or fmt[-1] != "text" or "start" not in fmt or "end" not in fmt:
                U("an ASS [Events] section whose Format line does not end with Text")
            parts = line[9:].lstrip().split(",", len(fmt) - 1)
            if len(parts) != len(fmt):
                U("a Dialogue line with fewer fields than its Format")
            st, en = parts[fmt.index("start")].strip(), parts[fmt.index("end")].strip()
            a, z = ASS_TIME.fullmatch(st), ASS_TIME.fullmatch(en)
            if not a or not z:
                U("an ASS time that does not read")
            cues.append((st, en, _seconds(a, 2), _seconds(z, 2), parts[-1]))
    if fmt is None:
        U("an ASS script without an [Events] Format line")
    return cues


def cues(d: bytes, want=None):
    """(kind, [(start text, end text, start s, end s, text)]) of a caption file, or Unknown."""
    kind = kind_of(d)
    if kind not in ("srt", "vtt", "ass") or (want and kind != want):
        U(f"not a {want or 'caption'} file")
    s = _text(d)
    return kind, {"srt": _srt, "vtt": _vtt, "ass": _ass}[kind](s)


def _plain_ass(t: str):
    return re.sub(r"\{[^}]*\}", "", t).replace("\\N", "\n").replace("\\n", "\n")


def _seconds_forms(stored, secs):
    return [("raw", stored), ("seconds", f"{secs:.3f}"), ("shortest", f"{secs:g}")]


def _caption_readers(ns, want):
    def count(n, d):
        return len(cues(d, want)[1])

    def text_at(i):
        def fn(n, d):
            kind, cs = cues(d, want)
            if not cs:
                return None
            t = cs[i][4]
            out = [("raw", t)]
            if kind == "ass" and _plain_ass(t) != t:
                out.append(("trimmed", _plain_ass(t)))
            return out
        return fn

    def time_at(i, j):
        def fn(n, d):
            cs = cues(d, want)[1]
            if not cs:
                return None
            c = cs[i]
            return _seconds_forms(c[j], c[j + 2])
        return fn

    def texts(n, d):
        cs = cues(d, want)[1]
        return [("json_compact", json.dumps([c[4] for c in cs], separators=(",", ":"), ensure_ascii=False))] if cs else None
    p = lambda *names: [f"{ns}.{x}" for x in names]   # noqa: E731
    M.prop(*p("cue_count", "caption_count", "subtitle_count", "entry_count", "event_count", "dialogue_count",
              "number_of_cues", "cues_count"), fmt="integer")(count)
    M.prop(*p("first_cue_text", "first_caption_text", "first_subtitle_text", "first_text", "first_cue",
              "first_dialogue_text"), fmt="forms")(text_at(0))
    M.prop(*p("last_cue_text", "last_caption_text", "last_subtitle_text", "last_text", "last_cue"), fmt="forms")(text_at(-1))
    M.prop(*p("first_cue_start", "first_cue_start_time", "first_caption_start", "first_start_time"), fmt="forms")(time_at(0, 0))
    M.prop(*p("first_cue_end", "first_cue_end_time"), fmt="forms")(time_at(0, 1))
    M.prop(*p("last_cue_end", "last_cue_end_time", "last_caption_end", "last_end_time"), fmt="forms")(time_at(-1, 1))
    M.prop(*p("cue_texts", "caption_texts", "subtitle_texts"), fmt="forms")(texts)


# ------------------------------------------------------------------ GPX and KML

def _xml(d: bytes, root_name: str):
    import xml.etree.ElementTree as ET
    if len(d) > MAX_BYTES:
        U("an XML file larger than is read here")
    if b"<!DOCTYPE" in d or b"<!ENTITY" in d:
        U("an XML file with a DOCTYPE (no entity is expanded here)")
    try:
        root = ET.fromstring(d)
    except ET.ParseError:
        U("XML that does not parse")
    if root.tag.split("}")[-1] != root_name:
        U(f"not a {root_name.upper()} document")
    return root


def _local(el):
    return el.tag.split("}")[-1]


def _all(root, name):
    return [e for e in root.iter() if _local(e) == name]


def _child(el, name):
    hits = [c for c in el if _local(c) == name]
    if len(hits) > 1:
        U(f"two {name} elements")
    return hits[0] if hits else None


def _child_text(el, name):
    c = _child(el, name) if el is not None else None
    return None if c is None or c.text is None or not c.text.strip() else c.text.strip()


def _number_forms(stored):
    if stored is None:
        return None
    try:
        v = float(stored)
    except ValueError:
        U("a coordinate that is not a number")
    return [("raw", stored), ("shortest", f"{v:.15g}")]


def _gpx_readers():
    gpx = lambda d: _xml(d, "gpx")    # noqa: E731

    def attr(name):
        return lambda n, d: gpx(d).get(name) or None

    def meta(field):
        return lambda n, d: _child_text(_child(gpx(d), "metadata"), field)

    def count(name):
        return lambda n, d: len(_all(gpx(d), name))

    def point(i, field):
        def fn(n, d):
            pts = _all(gpx(d), "trkpt")
            if not pts:
                return None
            pt = pts[i]
            if field in ("lat", "lon"):
                return _number_forms(pt.get(field))
            v = _child_text(pt, field)
            return None if v is None else (_number_forms(v) if field == "ele" else [("raw", v)])
        return fn

    def first_track_name(n, d):
        trks = _all(gpx(d), "trk")
        return _child_text(trks[0], "name") if trks else None
    M.prop("gpx.version", "gpx.gpx_version", "gpx.schema_version", fmt="text")(attr("version"))
    M.prop("gpx.creator", "gpx.creator_name", "gpx.generator", "gpx.created_by", fmt="text")(attr("creator"))
    M.prop("gpx.metadata_name", "gpx.name", "gpx.document_name", fmt="text")(meta("name"))
    M.prop("gpx.metadata_time", "gpx.time", "gpx.metadata_timestamp", fmt="text")(meta("time"))
    M.prop("gpx.metadata_desc", "gpx.metadata_description", "gpx.description", fmt="text")(meta("desc"))
    M.prop("gpx.track_count", "gpx.trk_count", "gpx.number_of_tracks", fmt="integer")(count("trk"))
    M.prop("gpx.track_segment_count", "gpx.trkseg_count", "gpx.segment_count", fmt="integer")(count("trkseg"))
    M.prop("gpx.trackpoint_count", "gpx.trkpt_count", "gpx.track_point_count", "gpx.number_of_trackpoints",
           "gpx.number_of_track_points", fmt="integer")(count("trkpt"))
    M.prop("gpx.waypoint_count", "gpx.wpt_count", "gpx.number_of_waypoints", fmt="integer")(count("wpt"))
    M.prop("gpx.route_count", "gpx.rte_count", fmt="integer")(count("rte"))
    M.prop("gpx.routepoint_count", "gpx.rtept_count", "gpx.route_point_count", fmt="integer")(count("rtept"))
    M.prop("gpx.track_name", "gpx.first_track_name", "gpx.trk_name", fmt="text")(first_track_name)
    for i, word in ((0, "first"), (-1, "last")):
        for field, names in (("lat", ("latitude", "lat")), ("lon", ("longitude", "lon")), ("ele", ("elevation", "ele")),
                             ("time", ("time", "timestamp"))):
            M.prop(*[f"gpx.{word}_{p}_{x}" for p in ("trackpoint", "trkpt", "track_point", "point") for x in names],
                   fmt="forms")(point(i, field))


def _kml_readers():
    kml = lambda d: _xml(d, "kml")    # noqa: E731

    def doc_name(n, d):
        docs = _all(kml(d), "Document")
        if len(docs) > 1:
            U("two Document elements")
        return _child_text(docs[0], "name") if docs else None

    def placemarks(d):
        return _all(kml(d), "Placemark")

    def first(field):
        def fn(n, d):
            pms = placemarks(d)
            if not pms:
                return None
            if field == "name":
                return _child_text(pms[0], "name")
            coords = [c for c in pms[0].iter() if _local(c) == "coordinates"]
            if len(coords) != 1 or not (coords[0].text or "").strip():
                U("a Placemark without exactly one coordinates element")
            raw = " ".join(coords[0].text.split())
            if field == "coordinates":
                return [("raw", raw)]
            tuples = raw.split(" ")
            if len(tuples) != 1:
                U("a Placemark with several coordinate tuples")
            parts = tuples[0].split(",")
            if len(parts) < 2:
                U("a coordinate tuple without a latitude")
            return _number_forms(parts[1] if field == "lat" else parts[0])
        return fn
    M.prop("kml.document_name", "kml.name", "kml.doc_name", fmt="text")(doc_name)
    M.prop("kml.placemark_count", "kml.number_of_placemarks", "kml.placemarks_count", fmt="integer")(
        lambda n, d: len(placemarks(d)))
    M.prop("kml.first_placemark_name", "kml.placemark_name", fmt="text")(first("name"))
    M.prop("kml.first_placemark_coordinates", "kml.placemark_coordinates", "kml.coordinates", fmt="forms")(first("coordinates"))
    M.prop("kml.first_placemark_latitude", "kml.placemark_latitude", "kml.latitude", fmt="forms")(first("lat"))
    M.prop("kml.first_placemark_longitude", "kml.placemark_longitude", "kml.longitude", fmt="forms")(first("lon"))


NAMESPACES = {"srt": ("srt",), "vtt": ("vtt", "webvtt"), "ass": ("ass", "ssa"), "subtitle": ("subtitle", "subtitles"),
              "gpx": ("gpx",), "kml": ("kml",)}
ALIASES = {"webvtt": "vtt", "ssa": "ass", "caption": "subtitle", "captions": "subtitle", "subtitles": "subtitle"}
TESTS = {"srt": lambda d: kind_of(d) == "srt", "vtt": lambda d: kind_of(d) == "vtt", "ass": lambda d: kind_of(d) == "ass",
         "gpx": lambda d: kind_of(d) == "gpx", "kml": lambda d: kind_of(d) == "kml"}


def register(module):
    """properties_strict calls this with its own module object. Returns (names, families) added."""
    global M
    M = module
    before = dict(M.REG)
    for ns, want in (("srt", "srt"), ("vtt", "vtt"), ("ass", "ass"), ("subtitle", None)):
        _caption_readers(ns, want)
    _gpx_readers()
    _kml_readers()
    for k, old in before.items():   # a name registered before keeps its reader
        if M.REG[k] is not old:
            M.MORE_CLASHES.append(M.REG[k].name)
            M.REG[k] = old
    for ns, tokens in NAMESPACES.items():
        M.NAMESPACES.add(ns)
        M.PACK_NAMESPACES.add(ns)
        M.CONTENT_TOKENS.update({ns, *tokens})
        M.RELATED.setdefault(ns, (ns,))
        if ns in TESTS:
            M.MORE_TYPES.append((ns, TESTS[ns]))
    for kind in ("srt", "vtt", "ass"):
        M.RELATED[kind] = tuple(dict.fromkeys(M.RELATED[kind] + ("subtitle", "media")))
    M.NS_ALIAS.update(ALIASES)
    M.TIE_FREE.update(M.REG[k].fn for k in M.REG if k not in before)
    return len(M.REG) - len(before), 0
