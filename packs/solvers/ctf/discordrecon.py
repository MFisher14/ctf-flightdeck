"""Discord recon, the offline half (B-112): a server snapshot and the analyzer that reads it.

In 2026 six challenges kept their flag in the event's Discord server: a recognition word in a hidden
channel's description, a flag spelled by the first character of each rules bullet (next to a
format-example decoy that was submitted and rejected), an author's profile, the server's expressions.
Agents had no way to read any of it, and relaying screenshots one at a time cost about 76M tokens on
one unsolved challenge. Here the server is captured ONCE into a snapshot and analysed with no model.

    from ctf import discordrecon as dr
    snap = dr.load(dr.snapshot_path(workdir))            # DiscordReconError when there is none
    snap.add(dr.ingest_text(text, where="#rules", kind="rules"))
    guild, items, fmt = dr.ingest_file(path)             # snapshot JSON, a chat export, or text
    dr.save(snap, dr.snapshot_path(workdir))
    rep = dr.analyze(snap, profile, cues=dr.cue_words(description), brief=description)
    rep.candidates; rep.readings; dr.render_report(rep); dr.render_checklist(dr.checklist(snap))

Three ways material gets in, all ending as `Item`s in `<workdir>/discord/snapshot.json`:

  1. the player pastes or saves text (a rules channel, a channel's details, a profile's About Me);
  2. the player exports a channel with a chat exporter (the DiscordChatExporter JSON layout);
  3. `ctf.discordapi.capture` reads the server through the bot API, when the event profile's
     `[discord] capture = "bot"` records that the player cleared it.

Nothing here opens a connection, and nothing here reads Discord's own app data: `refuse_app_data`
rejects any path inside a local Discord client folder (caches, the token store), which the solver
fence (ctf/fence.py) denies as well. Joining the server, the onboarding clicks, and checking that the
event rules and Discord's terms allow a capture are human steps (`checklist`).

What the analyzer reports, strongest first (`Candidate.kind`):

  acrostic-flag  the first (or last) characters of an item's lines or bullets, of the messages of one
                 channel, or of a list of names spell a flag in the event format
  flag           a literal flag in the event format
  decoded-flag   a flag the shared codec graph (ctf.codec) reaches from the item or one of its tokens;
                 a loose-only chain (rot13, reverse) is scored lower and says so
  hidden-flag    a flag written in invisible Unicode tag characters
  recognition    the value after a cue such as "recognition word:", "password is", "Kennwort:"
  spoiler        text inside ||spoiler|| marks
  braceless      an emoji, sticker, sound, role, channel or thread name that starts with a flag prefix
                 (names cannot hold braces)
  decoy-flag     a literal flag that reads as a format example ("flag format: X{...}"), has a
                 placeholder body, or is quoted in the challenge brief: listed last, never first

A flag in a Discord server is not attributed to a challenge here: one server holds the flags of
several challenges, so every result is a candidate for a person or an agent to place. The analyzer
never submits. Matching is the event's own format (ctf.flagfmt); no flag regex is defined here.
"""
from __future__ import annotations

import json
import os
import re
import time
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from . import flagfmt
from .event import EventProfile

SCHEMA = 1
SNAPSHOT_DIR = "discord"
SNAPSHOT_NAME = "snapshot.json"
REPORT_NAME = "candidates.md"
MAX_INGEST_BYTES = 64 * 1024 * 1024
MAX_ITEM_CHARS = 100_000            # one item's text; a longer one is refused, never cut
SOURCES = ("paste", "export", "api", "snapshot")

# Names: short labels that cannot hold braces. Text: free text.
NAME_KINDS = ("guild-name", "category-name", "channel-name", "thread-name", "forum-tag", "role", "emoji",
              "sticker", "soundboard", "bot-name", "member-name")
TEXT_KINDS = ("guild-description", "welcome", "onboarding", "rules", "channel-topic", "pin", "message",
              "event", "bot-about", "bot-status", "member-about", "member-status", "other")
KINDS = NAME_KINDS + TEXT_KINDS
_SEQ_TEXT_KINDS = ("message", "pin", "rules")   # one acrostic may run across the messages of a channel
_BRACELESS_KINDS = ("emoji", "sticker", "soundboard", "role", "channel-name", "thread-name", "forum-tag")

# Candidate kinds and their base scores. A challenge cue found in the item adds up to CUE_BONUS_MAX.
SCORES = {"acrostic-flag": 95, "flag": 90, "decoded-flag": 85, "hidden-flag": 85, "recognition": 60,
          "spoiler": 50, "braceless": 45, "decoy-flag": 20}
LOOSE_DECODE_SCORE = 55
FLAG_WORD_SCORE = 50                # "the flag is X" where X is not in the event format
CUE_BONUS, CUE_BONUS_MAX = 3, 9
FLAG_KINDS = ("acrostic-flag", "flag", "decoded-flag", "hidden-flag", "decoy-flag")
MAX_READINGS = 20
MIN_READING_UNITS = 5
_GRAPH_DEPTH, _GRAPH_NODES, _GRAPH_TEXT_MAX, _GRAPH_TOKENS = 3, 1500, 2000, 20


class DiscordReconError(ValueError):
    """An unusable snapshot, export or request. The message names what is wrong."""


# ------------------------------------------------------------------------------------------ records

@dataclass(frozen=True)
class Item:
    """One piece of text from the server. `where` is the place a person would look ("#rules",
    "bot Watchtower", "server"); `seq` orders the items of one place (messages oldest first)."""
    kind: str
    where: str
    text: str
    author: str = ""
    seq: int = 0
    source: str = "paste"

    def __post_init__(self):
        if self.kind not in KINDS:
            raise DiscordReconError(f"unknown item kind {self.kind!r}; one of: {', '.join(KINDS)}")
        if self.source not in SOURCES:
            raise DiscordReconError(f"unknown item source {self.source!r}; one of: {', '.join(SOURCES)}")
        if not isinstance(self.text, str) or not isinstance(self.where, str) or not self.where.strip():
            raise DiscordReconError("an item needs text and a non-empty 'where' (the place it was read)")
        if not isinstance(self.seq, int) or isinstance(self.seq, bool):
            raise DiscordReconError("an item's seq is an integer")

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.kind, self.where, self.text)

    def to_dict(self) -> dict:
        d = {"kind": self.kind, "where": self.where, "text": self.text, "source": self.source}
        if self.author:
            d["author"] = self.author
        if self.seq:
            d["seq"] = self.seq
        return d


@dataclass
class Snapshot:
    guild: dict = field(default_factory=dict)          # {"id": str, "name": str}, either may be absent
    items: list[Item] = field(default_factory=list)
    captures: list[dict] = field(default_factory=list)  # {"at", "source", "items", "added", "notes"}

    def add(self, items: Iterable[Item], *, source: str | None = None, notes: Sequence[str] = (),
            now: float | None = None) -> int:
        """Merge items in (an item already present, same kind, place and text, is not added twice)
        and record the capture. Returns how many were new."""
        have = {i.key for i in self.items}
        got = added = 0
        for it in items:
            got += 1
            if it.key in have or not it.text.strip():
                continue
            have.add(it.key)
            self.items.append(it)
            added += 1
        self.captures.append({"at": time.time() if now is None else now, "source": source or "paste",
                              "items": got, "added": added, "notes": [str(n) for n in notes]})
        return added

    def counts(self) -> dict[str, int]:
        c = Counter(i.kind for i in self.items)
        return {k: c[k] for k in KINDS if c[k]}

    def notes(self) -> list[str]:
        return [n for c in self.captures for n in c.get("notes", [])]

    def to_dict(self) -> dict:
        return {"schema": SCHEMA, "guild": dict(self.guild), "captures": list(self.captures),
                "items": [i.to_dict() for i in self.items]}

    @classmethod
    def from_dict(cls, d) -> "Snapshot":
        if not isinstance(d, dict) or d.get("schema") != SCHEMA:
            raise DiscordReconError(f"not a Discord snapshot of schema {SCHEMA} (a JSON object with "
                                    f'"schema": {SCHEMA} and "items")')
        extra = set(d) - {"schema", "guild", "captures", "items"}
        if extra:
            raise DiscordReconError(f"unknown snapshot key(s): {', '.join(sorted(extra))}")
        guild, raw, caps = d.get("guild", {}), d.get("items", []), d.get("captures", [])
        if not isinstance(guild, dict) or not isinstance(raw, list) or not isinstance(caps, list):
            raise DiscordReconError("snapshot: guild is an object, items and captures are lists")
        items = []
        for n, r in enumerate(raw):
            if not isinstance(r, dict):
                raise DiscordReconError(f"snapshot items[{n}] is not an object")
            bad = set(r) - {"kind", "where", "text", "author", "seq", "source"}
            if bad:
                raise DiscordReconError(f"snapshot items[{n}] has unknown key(s): {', '.join(sorted(bad))}")
            try:
                items.append(Item(kind=r["kind"], where=r["where"], text=r["text"],
                                  author=str(r.get("author", "")), seq=r.get("seq", 0),
                                  source=r.get("source", "snapshot")))
            except KeyError as e:
                raise DiscordReconError(f"snapshot items[{n}] lacks {e.args[0]!r}") from None
            except DiscordReconError as e:
                raise DiscordReconError(f"snapshot items[{n}]: {e}") from None
        return cls(guild={str(k): str(v) for k, v in guild.items()}, items=items,
                   captures=[c for c in caps if isinstance(c, dict)])


# ------------------------------------------------------------------------------------------ storage

_APP_PARENTS = frozenset({"application support", ".config", "roaming", "local", "caches", "containers",
                          "snap", ".var"})
_APP_NAMES = ("discord", "discordcanary", "discordptb", "discorddevelopment", "com.hnc.discord",
              "com.discordapp.discord")


def refuse_app_data(path: str | Path) -> Path:
    """The resolved path, or DiscordReconError when it lies inside a local Discord client folder
    (its caches and token store). Those are never an input: only what the player exported or pasted."""
    p = Path(path).expanduser()
    try:
        p = p.resolve()
    except OSError as e:
        raise DiscordReconError(f"{path}: cannot be resolved ({e})") from None
    parts = [x.casefold() for x in p.parts]
    for i in range(1, len(parts)):
        if parts[i] in _APP_NAMES and parts[i - 1] in _APP_PARENTS:
            raise DiscordReconError(
                f"{p} is inside the local Discord app's data folder ({p.parts[i - 1]}/{p.parts[i]}): its "
                "caches and token store are never read. Export or paste what you can see in the app.")
    return p


def snapshot_path(workdir: str | Path) -> Path:
    """Where an event's snapshot lives: <workdir>/discord/snapshot.json."""
    return Path(workdir) / SNAPSHOT_DIR / SNAPSHOT_NAME


def load(path: str | Path) -> Snapshot:
    p = Path(path)
    refuse_app_data(p)                  # a snapshot is ours, never a file of the local Discord app
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise DiscordReconError(
            f"no Discord snapshot at {p}: nothing has been captured for this event. Reading the server "
            "is a human step first (`python -m ctf discord checklist`), then `python -m ctf discord "
            "ingest FILE` or, when the profile clears a bot, `python -m ctf discord capture`") from None
    except (OSError, UnicodeDecodeError) as e:
        raise DiscordReconError(f"{p}: cannot be read ({e})") from None
    try:
        return Snapshot.from_dict(json.loads(raw))
    except json.JSONDecodeError as e:
        raise DiscordReconError(f"{p}: not JSON ({e})") from None
    except DiscordReconError as e:
        raise DiscordReconError(f"{p}: {e}") from None


def load_or_new(path: str | Path) -> Snapshot:
    return load(path) if Path(path).exists() else Snapshot()


def save(snap: Snapshot, path: str | Path) -> Path:
    """Write the snapshot (owner-only: it holds other people's messages), replacing it atomically."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + f".{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(snap.to_dict(), fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    os.replace(tmp, p)
    return p


# ------------------------------------------------------------------------------------------ ingest

def _fit(text: str, what: str) -> str:
    """The text, or DiscordReconError when it is over the item limit (nothing is cut silently)."""
    if len(text) > MAX_ITEM_CHARS:
        raise DiscordReconError(f"{what} is {len(text)} characters, over the {MAX_ITEM_CHARS}-character "
                                "item limit: hand it over in parts, one place per file")
    return text


def ingest_text(text: str, *, where: str, kind: str = "message", source: str = "paste",
                author: str = "") -> list[Item]:
    """A pasted block as ONE item, lines kept, so a per-line acrostic is still readable."""
    if not (where or "").strip():
        raise DiscordReconError("pasted text needs --where (the place it was read, e.g. '#rules')")
    text = (text or "").replace("\r\n", "\n").replace("\r", "\n").strip("\n")
    if not text.strip():
        raise DiscordReconError("the pasted text is empty")
    return [Item(kind=kind, where=where.strip(), text=_fit(text, f"the text for {where.strip()}"),
                 author=author, source=source)]


def message_text(msg: dict) -> str:
    """Everything a person reads in one message: its content, embeds, attachment and sticker names,
    a poll. Works on the bot API's message object and on a chat export's (camelCase) one."""
    out: list[str] = []

    def put(v):
        if isinstance(v, str) and v.strip():
            out.append(v.strip())

    put(msg.get("content"))
    for e in msg.get("embeds") or []:
        if not isinstance(e, dict):
            continue
        put(e.get("title"))
        put(e.get("description"))
        a = e.get("author")
        put(a.get("name") if isinstance(a, dict) else None)
        for f in e.get("fields") or []:
            if isinstance(f, dict):
                put(f.get("name"))
                put(f.get("value"))
        ft = e.get("footer")
        put(ft.get("text") if isinstance(ft, dict) else None)
    for a in msg.get("attachments") or []:
        if isinstance(a, dict):
            put(a.get("filename") or a.get("fileName"))
            put(a.get("description"))
    for s in (msg.get("sticker_items") or msg.get("stickers") or []):
        if isinstance(s, dict):
            put(s.get("name"))
    poll = msg.get("poll")
    if isinstance(poll, dict):
        q = poll.get("question")
        put(q.get("text") if isinstance(q, dict) else q)
        for a in poll.get("answers") or []:
            pm = a.get("poll_media") if isinstance(a, dict) else None
            put(pm.get("text") if isinstance(pm, dict) else None)
    return "\n".join(out)


def ingest_export(obj: dict, *, source: str = "export") -> tuple[dict, list[Item]]:
    """A chat exporter's one-channel JSON (DiscordChatExporter layout: guild, channel, messages) as
    (guild, items): the channel's name and topic, its category, every message, and pins marked."""
    if not (isinstance(obj, dict) and isinstance(obj.get("channel"), dict)
            and isinstance(obj.get("messages"), list)):
        raise DiscordReconError('not a chat export: expected a JSON object with "channel" and "messages"')
    ch, g = obj["channel"], obj.get("guild") if isinstance(obj.get("guild"), dict) else {}
    name = str(ch.get("name") or ch.get("id") or "").strip()
    if not name:
        raise DiscordReconError("the chat export's channel has no name or id")
    where = "#" + name
    items: list[Item] = [Item("channel-name", where, name, source=source)]
    if str(ch.get("topic") or "").strip():
        items.append(Item("channel-topic", where, _fit(str(ch["topic"]), f"the topic of {where}"), source=source))
    if str(ch.get("category") or "").strip():
        items.append(Item("category-name", "category " + str(ch["category"]), str(ch["category"]), source=source))
    for n, m in enumerate(obj["messages"], 1):
        if not isinstance(m, dict):
            raise DiscordReconError(f"the chat export's messages[{n - 1}] is not an object")
        text = message_text(m)
        if not text:
            continue
        a = m.get("author") if isinstance(m.get("author"), dict) else {}
        author = str(a.get("nickname") or a.get("name") or "")
        pinned = bool(m.get("isPinned") or m.get("pinned"))
        items.append(Item("pin" if pinned else "message", where, _fit(text, f"message {n} of {where}"),
                          author=author, seq=n, source=source))
    guild = {k: str(g[k]) for k in ("id", "name") if g.get(k)}
    if guild.get("name"):
        items.append(Item("guild-name", "server", guild["name"], source=source))
    return guild, items


def ingest_file(path: str | Path, *, as_: str = "auto", where: str | None = None,
                kind: str | None = None) -> tuple[dict, list[Item], str]:
    """(guild, items, format) from a file the player saved: `snapshot` (this module's JSON), `export`
    (a chat exporter's JSON) or `text` (a paste; needs `where`). `auto` picks by content and fails on a
    JSON document that is neither, rather than reading it as prose."""
    if as_ not in ("auto", "snapshot", "export", "text"):
        raise DiscordReconError(f"unknown input format {as_!r} (auto, snapshot, export, text)")
    p = refuse_app_data(path)
    try:
        size = p.stat().st_size
    except OSError as e:
        raise DiscordReconError(f"{p}: cannot be read ({e.strerror or e})") from None
    if not p.is_file():
        raise DiscordReconError(f"{p} is not a file")
    if size > MAX_INGEST_BYTES:
        raise DiscordReconError(f"{p} is {size} bytes, over the {MAX_INGEST_BYTES}-byte ingest limit")
    try:
        raw = p.read_bytes().decode("utf-8-sig")
    except UnicodeDecodeError as e:
        raise DiscordReconError(f"{p}: not UTF-8 text ({e})") from None
    doc = None
    if as_ != "text":
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as e:
            if as_ != "auto":
                raise DiscordReconError(f"{p}: not JSON ({e})") from None
    if as_ == "text" or (as_ == "auto" and doc is None):
        return {}, ingest_text(raw, where=where or "", kind=kind or "message"), "text"
    if kind is not None or where is not None:
        raise DiscordReconError("--where and --kind describe pasted text; a JSON snapshot or export "
                                "names its own places")
    if as_ in ("auto", "snapshot") and isinstance(doc, dict) and "schema" in doc and "items" in doc:
        snap = Snapshot.from_dict(doc)
        return snap.guild, snap.items, "snapshot"
    if as_ in ("auto", "export") and isinstance(doc, dict) and "channel" in doc and "messages" in doc:
        guild, items = ingest_export(doc)
        return guild, items, "export"
    if as_ == "snapshot":
        Snapshot.from_dict(doc)          # raises, naming the reason
    if as_ == "export":
        ingest_export(doc)               # raises, naming the reason
    raise DiscordReconError(f"{p}: JSON, but neither a snapshot (schema + items) nor a chat export "
                            "(channel + messages); for a text paste pass --as text --where PLACE")


# ------------------------------------------------------------------------------------------ analysis

@dataclass(frozen=True)
class Candidate:
    value: str               # the flag, word or text to consider
    kind: str                # see SCORES
    where: str               # the place in the server
    item_kind: str
    how: str                 # one line a person can check
    score: int
    in_format: bool          # value is a flag in the event format
    wrapped: str | None = None   # value inside the event's first prefix, when that is a valid flag

    def to_dict(self) -> dict:
        return {"value": self.value, "kind": self.kind, "where": self.where, "item_kind": self.item_kind,
                "how": self.how, "score": self.score, "in_format": self.in_format, "wrapped": self.wrapped}


@dataclass(frozen=True)
class Reading:
    """An acrostic that is not a flag: shown to the player, never a candidate."""
    text: str
    where: str
    how: str
    prefixed: bool = False       # it starts with one of the event's flag prefixes

    def to_dict(self) -> dict:
        return {"text": self.text, "where": self.where, "how": self.how, "prefixed": self.prefixed}


@dataclass
class Report:
    event: str
    items: int
    counts: dict
    candidates: list[Candidate] = field(default_factory=list)
    readings: list[Reading] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    cues: tuple[str, ...] = ()

    def flags(self, *, decoys: bool = False) -> list[str]:
        """The distinct event-format flags among the candidates, best first."""
        out = [c.value for c in self.candidates
               if c.in_format and (decoys or c.kind != "decoy-flag")]
        return list(dict.fromkeys(out))

    def to_dict(self) -> dict:
        return {"event": self.event, "items": self.items, "counts": self.counts, "cues": list(self.cues),
                "candidates": [c.to_dict() for c in self.candidates],
                "readings": [r.to_dict() for r in self.readings], "notes": list(self.notes)}


_STOP = frozenset("""about above after again against also another around because been before being below
between both cannot could does doing down during each every flag flags from further have having here
into itself just more most must once only other ours over same shall should some such than that their
theirs them then there these they this those through under until very were what when where which while
with within without would your yours discord server channel challenge find found somewhere maybe
please submit report hidden hint hints text check sanity welcome""".split())
_WORD = re.compile(r"[^\W\d_]{4,}", re.UNICODE)


def cue_words(*texts: str | None) -> tuple[str, ...]:
    """The content words of a challenge's name and description (4+ letters, common words dropped),
    lower-cased, first-seen order: what ties a server item to this challenge."""
    out: list[str] = []
    for t in texts:
        for w in _WORD.findall(t or ""):
            w = w.casefold()
            if w not in _STOP and w not in out:
                out.append(w)
    return tuple(out)


def _cue_bonus(item: Item, cues: Sequence[str]) -> tuple[int, list[str]]:
    if not cues:
        return 0, []
    have = {w.casefold() for w in _WORD.findall(item.text + " " + item.where)}
    hit = [c for c in cues if c in have]
    return min(CUE_BONUS_MAX, CUE_BONUS * len(hit)), hit


# -- decoys

_DECOY_BEFORE = ("format", "example", "e.g", "eg:", "such as", "looks like", "look like", "sample", "dummy",
                 "fake", "placeholder", "beispiel", "z.b", "muster", "wrapped in", "syntax", "in the form",
                 "of the form", "like this", "for instance")
_PLACEHOLDER_BODIES = frozenset({"flag", "example", "sample", "placeholder", "text", "here", "redacted",
                                 "your_flag", "your_flag_here", "flag_here", "some_text", "something",
                                 "s0m3_t3xt", "th1s_1s_4_fl4g", "this_is_a_flag", "fake_flag", "dummy"})
_PLACEHOLDER_PARTS = ("...", "…", "example", "placeholder", "your_flag", "flag_here", "fake_flag",
                      "not_the_flag", "not_a_flag", "dummy")


def _body(flag: str) -> str:
    return flag[flag.find("{") + 1:-1] if "{" in flag and flag.endswith("}") else flag


def _decoy_reason(text: str, start: int, end: int, flag: str, brief_flags: frozenset) -> str | None:
    body = _body(flag).casefold()
    if flag in brief_flags:
        return "the same value is quoted in the challenge brief"
    if body in _PLACEHOLDER_BODIES or any(p in body for p in _PLACEHOLDER_PARTS) \
            or (len(body) >= 3 and set(body) <= set("x?.*_-")):
        return "the body reads as a placeholder"
    # the same line up to the flag, and the line above it ("Flag format:" on its own line)
    before = "\n".join(text[max(0, start - 100):start].casefold().split("\n")[-2:])
    after = text[end:end + 30].casefold().split("\n", 1)[0]
    for cue in _DECOY_BEFORE:
        if cue in before or cue in after:
            return f"the text around it reads as a format example ({cue!r})"
    return None


# -- acrostics

_BULLET = re.compile(r"^\s*(?:[-*+•·‣▪◦●○►▸»>]|\(?\d{1,3}[.)]|\(?[A-Za-z][.)]|#{1,6}|\[[ xX]\])\s+")
_SHORTCODE = re.compile(r"^:[A-Za-z0-9_+-]{1,40}:\s*")
_MARKUP = "*_~|`\\"


def _is_pictograph(ch: str) -> bool:
    """An emoji-like character used as a bullet: a symbol, a joiner or selector, a skin-tone mark."""
    return (unicodedata.category(ch) in ("So", "Cf") or ch in "️⃣"
            or 0x1F3FB <= ord(ch) <= 0x1F3FF)


def _strip_marker(line: str) -> tuple[str, bool]:
    """(the line without its list marker, whether it had one). A marker is a bullet, a number, a
    heading mark, a quote mark or leading emoji."""
    s, had = line.strip(), False
    for _ in range(6):
        m = _BULLET.match(s) or _SHORTCODE.match(s)
        if m:
            s, had = s[m.end():].lstrip(), True
            continue
        # a keycap ("1" + U+FE0F + U+20E3) or a leading pictograph run followed by space
        j = 0
        while j < len(s) and (_is_pictograph(s[j]) or (s[j].isdigit() and j + 1 < len(s) and s[j + 1] in "️⃣")):
            j += 1
        if j and j < len(s):
            s, had = s[j:].lstrip(), True
            continue
        break
    return s, had


def _first_chars(units: Sequence[str], *, markup: bool) -> str:
    out = []
    for u in units:
        if markup:
            u = u.lstrip(_MARKUP + " \t")
        if u:
            out.append(u[0])
    return "".join(out)


def _acrostic_strings(lines: Sequence[str]) -> list[tuple[str, tuple[str, ...], bool]]:
    """The acrostic readings of a list of lines: [(description, strings, readable)]. `strings` are
    tried in order and the first that spells a flag wins: the characters as written, then with
    leading markup (* _ ~ | ` and backslash) skipped, so a bullet that really starts with "_" is
    not misread. `readable` is False for the readings that are only worth a flag check."""
    stripped = [_strip_marker(ln) for ln in lines if ln.strip()]
    units = [s for s, _ in stripped if s]
    bullets = [s for s, had in stripped if had and s]
    out: list[tuple[str, tuple[str, ...], bool]] = []

    def both(us: Sequence[str]) -> tuple[str, ...]:
        return tuple(dict.fromkeys((_first_chars(us, markup=False), _first_chars(us, markup=True))))

    if len(units) >= 2:
        out.append(("first character of each line", both(units), True))
        out.append(("last character of each line",
                    ("".join(u.rstrip()[-1] for u in units if u.rstrip()),), False))
    if len(bullets) >= 2 and len(bullets) != len(units):
        out.append(("first character of each bullet", both(bullets), True))
    if len(units) == 1:
        words = units[0].split()
        if len(words) >= 4:
            out.append(("first character of each word", both(words), False))
    return out


# -- recognition words

_CUES = ("recognition word", "recognition phrase", "code word", "codeword", "code phrase", "password",
         "passphrase", "pass phrase", "passcode", "keyword", "key word", "magic word", "secret word",
         "safe word", "watchword", "watch word", "kennwort", "losungswort", "lösungswort", "codewort",
         "passwort", "parole", "stichwort", "flagge", "flag")
_CUE_RE = re.compile(r"(?<!\w)(" + "|".join(r"[ -]?".join(re.escape(w) for w in c.split()) for c in _CUES)
                     + r")(?!\w)", re.IGNORECASE)
_SEP_RE = re.compile(r"^[^\n:=]{0,30}?(?:\bis\b|\bist\b|\blautet\b|\bwas\b|:|=|→|->|—|–)\s*", re.IGNORECASE)
_QUOTED = re.compile(r"^(\|\||\*\*|__|[\"“”'‘’`*_])(.+?)(\|\||\*\*|__|[\"“”'‘’`*_])")
_NOT_A_VALUE = frozenset("""hidden somewhere not in on at here there located found the a an to for that this
your our my always never only just also right inside within now still waiting posted pinned broadcast
broadcasting being what where which is are was it its and or of by with you we they if when no none
unknown secret different changed available required needed case-sensitive""".split())


def _value_after(rest: str) -> tuple[str, bool] | None:
    """The value a cue introduces: a quoted or marked span, else up to four words (the first word
    alone when the phrase is longer). (value, quoted) or None."""
    rest = rest.strip()
    m = _QUOTED.match(rest)
    if m and m.group(2).strip():
        return m.group(2).strip(), True
    phrase = re.split(r"(?:[.!?;,](?:\s|$))|\n", rest, maxsplit=1)[0].strip().strip(_MARKUP + "\"'“”‘’ ")
    phrase = phrase.rstrip(".!?;,:")
    if not phrase:
        return None
    words = phrase.split()
    if words[0].casefold() in _NOT_A_VALUE:
        return None
    return (phrase if len(words) <= 4 else words[0]), False


_SPOILER = re.compile(r"\|\|(.+?)\|\|", re.S)
_TOKEN = re.compile(r"[A-Za-z0-9+/_=-]{16,}")
_ZERO_WIDTH = frozenset("​‌‍⁠⁡⁢⁣⁤﻿")


def _tag_text(text: str) -> str:
    """The ASCII spelled by Unicode tag characters (U+E0020..U+E007E), which render as nothing."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


def analyze(snap: Snapshot, profile: EventProfile, *, cues: Sequence[str] = (), brief: str = "",
            decode: bool = True) -> Report:
    """Every flag and recognition-word candidate in the snapshot, best first. `cues` (see cue_words)
    rank the items that mention this challenge's own words higher; a flag quoted in `brief` (the
    challenge text) is a decoy. decode=False skips the codec graph."""
    ff = flagfmt.for_profile(profile)
    prefixes = tuple(profile.flag.prefixes)
    cues = tuple(c.casefold() for c in cues)
    brief_flags = frozenset(_canon(ff, f) for f in ff.find_flags(brief)) if brief else frozenset()
    rep = Report(event=profile.slug, items=len(snap.items), counts=snap.counts(), cues=cues,
                 notes=list(snap.notes()))
    best: dict[str, Candidate] = {}
    order: list[str] = []

    def add(value: str, kind: str, item: Item, how: str, *, score: int | None = None) -> None:
        value = value.strip()
        if not value:
            return
        in_format = ff.is_flag(value)
        if in_format:
            value = ff.normalize(value)
        bonus, hit = _cue_bonus(item, cues)
        sc = (SCORES[kind] if score is None else score) + bonus
        if hit:
            how += f"; mentions {', '.join(hit[:3])}"
        wrapped = None
        if not in_format and prefixes and kind in ("recognition", "spoiler", "braceless"):
            core = value
            if kind == "braceless":
                core = _after_prefix(value, prefixes) or value
            w = f"{prefixes[0]}{{{core}}}"
            wrapped = w if ff.is_flag(w) else None
        c = Candidate(value, kind, item.where, item.kind, how, sc, in_format, wrapped)
        old = best.get(value)
        if old is None:
            order.append(value)
            best[value] = c
        elif _rank(c) > _rank(old):
            best[value] = c

    graph = oracle = None
    if decode:
        from .codec import FlagOracle, Graph
        graph = Graph(max_depth=_GRAPH_DEPTH, max_nodes=_GRAPH_NODES, xor=False)
        oracle = FlagOracle(profile)

    readings: dict[str, Reading] = {}

    def acrostics(lines: Sequence[str], item: Item, what: str) -> None:
        for how, strings, readable in _acrostic_strings(lines):
            found = False
            for n, s in enumerate(strings):
                # no left boundary: the acrostic of a heading line may sit right before the prefix
                flags = list(dict.fromkeys(m.group(0) for m in ff.packed_regex.finditer(s)))
                for f in flags:
                    add(f, "acrostic-flag", item,
                        f"{how} of {what} spells it" + (" (leading markup skipped)" if n else ""))
                if flags:
                    found = True
                    break
            s = strings[-1]
            if not found and readable and len(s) >= MIN_READING_UNITS and s not in readings:
                pre = bool(prefixes) and any(s.casefold().startswith(p.casefold()) for p in prefixes)
                readings[s] = Reading(s, item.where, f"{how} of {what}", pre)

    for item in snap.items:
        text = item.text
        literal = list(ff.regex.finditer(text))
        for m in literal:
            f = m.group(0)
            why = _decoy_reason(text, m.start(), m.end(), _canon(ff, f), brief_flags)
            if why:
                add(f, "decoy-flag", item, f"literal in the {item.kind}, but {why}")
            else:
                add(f, "flag", item, f"literal in the {item.kind}")
        hidden = _tag_text(text)
        if hidden:
            got = ff.find_flags(hidden)
            for f in got:
                add(f, "hidden-flag", item, f"written in invisible Unicode tag characters in the {item.kind}")
            if not got:
                rep.notes.append(f"{item.where}: {len(hidden)} invisible tag character(s) spell {hidden[:80]!r}")
        zw = sum(1 for c in text if c in _ZERO_WIDTH)
        if zw >= 8:
            rep.notes.append(f"{item.where} ({item.kind}): {zw} zero-width characters, possibly hidden data "
                             "(copy the raw text into a file and run `python -m ctf codec` on it)")
        if graph is not None:
            blobs = [t for t in dict.fromkeys(_TOKEN.findall(text))][:_GRAPH_TOKENS]
            if not literal and len(text) <= _GRAPH_TEXT_MAX:
                blobs.append(text)
            for blob in blobs:
                res = graph.search(blob.encode("utf-8", "replace"), oracle)
                for h in res.hits:
                    if not h.chain:
                        continue
                    if h.confirmed:
                        add(h.answer, "decoded-flag", item, f"decoded from the {item.kind} ({h.how})")
                    else:
                        add(h.answer, "decoded-flag", item,
                            f"loose decode of the {item.kind} ({h.how}): check it by hand",
                            score=LOOSE_DECODE_SCORE)
        for m in _SPOILER.finditer(text):
            inner = m.group(1).strip()
            if inner and not ff.find_flags(inner):
                add(inner if len(inner) <= 120 else inner[:120], "spoiler", item,
                    f"spoiler-hidden text in the {item.kind}")
        if item.kind in TEXT_KINDS:
            for line in text.split("\n"):
                for m in _CUE_RE.finditer(line):
                    sep = _SEP_RE.match(line[m.end():])
                    if not sep:
                        continue
                    got = _value_after(line[m.end() + sep.end():])
                    if got is None or ff.find_flags(got[0]):
                        continue
                    cue = m.group(1).casefold()
                    add(got[0], "recognition", item,
                        f"follows {m.group(1)!r} in the {item.kind}" + (" (quoted)" if got[1] else ""),
                        score=FLAG_WORD_SCORE if cue in ("flag", "flagge") else None)
            acrostics(text.split("\n"), item, f"the {item.kind}")
        elif item.kind in _BRACELESS_KINDS and prefixes:
            rest = _after_prefix(text.strip(), prefixes)
            if rest is not None:
                add(text.strip(), "braceless", item,
                    f"the {item.kind} name starts with a flag prefix (names cannot hold braces)")

    # an acrostic across the items of one place: the messages of a channel, a list of names
    groups: dict[tuple[str, str], list[Item]] = {}
    for item in snap.items:
        if item.kind in _SEQ_TEXT_KINDS:
            groups.setdefault((item.kind, item.where), []).append(item)
        elif item.kind in NAME_KINDS:
            groups.setdefault((item.kind, ""), []).append(item)
    for (kind, where), members in groups.items():
        if len(members) < 2:
            continue
        members = sorted(members, key=lambda i: i.seq)     # stable: capture order within one seq
        firsts = [(m.text.strip().split("\n", 1)[0]) for m in members if m.text.strip()]
        plural = kind if kind.endswith("s") else kind + "s"
        what = f"the {plural} of {where}" if where else f"the {kind} list"
        acrostics(firsts, members[0], what)

    rep.candidates = sorted((best[v] for v in order), key=lambda c: (-c.score, not c.in_format))
    kept = sorted(readings.values(), key=lambda r: not r.prefixed)      # prefixed first, then first seen
    if len(kept) > MAX_READINGS:
        rep.notes.append(f"{len(kept) - MAX_READINGS} more acrostic reading(s) not listed "
                         f"(the first {MAX_READINGS} are)")
    rep.readings = kept[:MAX_READINGS]
    return rep


def _rank(c: Candidate) -> tuple[int, int]:
    return (c.score, 1 if c.in_format else 0)


def _canon(ff, flag: str) -> str:
    try:
        return ff.normalize(flag)
    except ValueError:
        return flag


def _after_prefix(name: str, prefixes: Sequence[str]) -> str | None:
    """What follows a flag prefix at the start of a name (a separator dropped), when at least three
    characters follow; else None. Longest prefix first; the prefix is matched in any case."""
    low = name.casefold()
    for p in sorted(prefixes, key=len, reverse=True):
        if low.startswith(p.casefold()):
            rest = name[len(p):].lstrip("_-. ")
            if len(rest) >= 3:
                return rest
    return None


# ------------------------------------------------------------------------------------------ checklist

# (key, what to read, the item kinds that cover it, whether the bot API can read it)
PLACES = (
    ("join", "Join the server through the event's invite and finish onboarding or rules screening, so "
             "every channel you are meant to see is open", (), False),
    ("hidden", "Turn on Show All Channels (server menu) and open Browse Channels: a flag channel may be "
               "hidden until you opt in", ("channel-name",), True),
    ("topics", "Every channel's details: the topic or description (View Channel Details) and its pinned "
               "messages", ("channel-topic", "pin"), True),
    ("rules", "The rules channel, the whole text, bullets kept one per line (a flag may be spelled by "
              "the first character of each bullet)", ("rules", "message"), True),
    ("server", "The server itself: description, welcome screen, onboarding questions, scheduled events",
     ("guild-description", "welcome", "onboarding", "event"), True),
    ("expressions", "Expressions: custom emoji, sticker and soundboard names", ("emoji", "sticker", "soundboard"), True),
    ("roles", "The role list (server settings, or any member's profile)", ("role",), True),
    ("threads", "Threads and forum posts: names, tags and first messages", ("thread-name", "forum-tag"), True),
    ("bots", "Bots: each bot's About Me and status line", ("bot-about", "bot-status"), True),
    ("members", "The challenge author's and organizers' profiles: About Me, custom status, pronouns, "
                "banner. A bot cannot read these: paste them", ("member-about", "member-status"), False),
)


@dataclass(frozen=True)
class Place:
    key: str
    ask: str
    kinds: tuple[str, ...]
    by_bot: bool
    have: int                # items of those kinds in the snapshot

    @property
    def done(self) -> bool:
        return self.have > 0


def checklist(snap: Snapshot | None = None) -> list[Place]:
    """The places a person reads, each with how many snapshot items already cover it."""
    counts = Counter(i.kind for i in snap.items) if snap is not None else Counter()
    return [Place(k, ask, kinds, by_bot, sum(counts[x] for x in kinds)) for k, ask, kinds, by_bot in PLACES]


def render_checklist(places: Sequence[Place], *, capture: str = "forbidden", challenge: str | None = None) -> str:
    head = "Discord recon checklist" + (f" for challenge {challenge}" if challenge else "")
    lines = [head, "=" * len(head), "",
             "Reading the server is yours: joining, the onboarding clicks, and checking that the event's",
             "rules and Discord's terms allow whatever tool you use. Agents never join and never read the",
             "Discord app's own files.", ""]
    for p in places:
        mark = "x" if p.done else " "
        tail = f"  [{p.have} item(s) captured]" if p.done else ""
        lines.append(f"[{mark}] {p.ask}.{tail}")
        if p.kinds and not p.done:
            lines.append(f"      hand over as: --kind {p.kinds[0]}" + ("" if p.by_bot else "  (by hand only)"))
    lines += ["", "Hand it over (one file per place; lines kept as they are):",
              "  python -m ctf discord ingest rules.txt --where '#rules' --kind rules",
              "  python -m ctf discord ingest export.json          # a chat exporter's channel JSON",
              "  python -m ctf discord analyze [--challenge ID]"]
    if capture == "bot":
        lines += ["This event's profile clears a bot ([discord] capture = \"bot\"):",
                  "  python -m ctf discord capture"]
    else:
        lines += ["The API client is off for this event ([discord] capture = \"forbidden\"). Set it to \"bot\"",
                  "only after you have checked the event rules and an organizer has admitted your bot."]
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------------------------------ report

def _cell(text: str, limit: int = 140) -> str:
    t = " ".join(str(text).split())
    t = t if len(t) <= limit else t[:limit - 1] + "…"
    return t.replace("|", "\\|").replace("`", "'")


def render_report(rep: Report, *, title: str = "Discord recon candidates", top: int | None = None) -> str:
    out = [f"# {title}", "",
           f"Event `{rep.event}`: {rep.items} snapshot item(s)"
           + (", cues: " + ", ".join(rep.cues[:12]) if rep.cues else "") + ".", "",
           "Candidates only. A flag in the server is not attributed to a challenge automatically: one "
           "server holds the flags of several challenges, and a format example is a decoy. Submit through "
           "the gate (`python -m ctf submit <id> '<value>'`), once, after reading where it came from.", ""]
    cands = rep.candidates if top is None else rep.candidates[:top]
    if cands:
        out += ["| # | score | kind | value | where | how |", "|---|---|---|---|---|---|"]
        for n, c in enumerate(cands, 1):
            val = _cell(c.value) + (f" (wrapped: {_cell(c.wrapped)})" if c.wrapped else "")
            out.append(f"| {n} | {c.score} | {c.kind} | `{val}` | {_cell(c.where, 60)} | {_cell(c.how)} |")
        if len(cands) < len(rep.candidates):
            out.append(f"\n({len(rep.candidates) - len(cands)} more not shown)")
    else:
        out.append("No candidate: no flag in the event format, no recognition-word cue, no hidden text.")
    if rep.readings:
        out += ["", "## Acrostic readings (not flags; read them yourself)", ""]
        out += [f"- `{_cell(r.text, 100)}`: {r.how}, {r.where}" + (" (starts with a flag prefix)" if r.prefixed else "")
                for r in rep.readings]
    if rep.notes:
        out += ["", "## Notes", ""] + [f"- {_cell(n, 300)}" for n in dict.fromkeys(rep.notes)]
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------------------------------ human card

CARD_SOURCE = "discord-recon"


def request_card(profile: EventProfile, challenge_id: str, *, name: str = "", workdir: str | Path | None = None,
                 source: str = CARD_SOURCE):
    """Put "read the Discord server for this challenge" on the player's task cards (ctf.humanops, a
    `discord` card), once per challenge: (card, created). An open card for the challenge is returned
    as it is. The card states the hand-back, never a flag."""
    from . import humanops
    cid = str(challenge_id or "").strip()
    if not cid:
        raise DiscordReconError("a Discord card needs the challenge id")
    ops = humanops.HumanOps(profile, Path(workdir) if workdir is not None else None)
    for c in ops.cards(status="open", kind="discord"):
        if c.challenge_id == cid and c.source == source:
            return c, False
    label = f"challenge {cid}" + (f" ({name})" if name else "")
    card = ops.add_card(
        "discord", challenge_id=cid, source=source,
        ask=f"Read the event's Discord server for {label}: run `python -m ctf discord checklist "
            f"--challenge {cid}` and go through the places it lists",
        need="the text of each place, handed over with `python -m ctf discord ingest FILE --where PLACE "
             "--kind KIND` (or a chat export); then `python -m ctf discord analyze --challenge "
             f"{cid}`",
        why="agents have no Discord account and never read the Discord app's files")
    return card, True


# ------------------------------------------------------------------------------------------ challenge

CHALLENGE_REPORT = "recon/discord.md"


# In the sentence that names Discord: a recon cue says the answer is in the server; a help word says the
# server is only where to ask for help or follow news, and wins. People (admins, organizers) are neither:
# "the admins hid the flag in our Discord" is recon. "Ask" alone loses to a bot ("ask the Discord bot").
# An invite link is Discord plus a cue ("join discord.gg/abc" is the classic sanity brief).
_DISCORD_RECON_CUE = re.compile(r"\b(?:flags?|recognition|code ?words?|passwords?|servers?|channels?|pins?|"
                                r"pinned|topics?|roles?|emojis?|stickers?|announce\w*|rules|bots?|hidden|"
                                r"somewhere|find|look|join\w*|invite\w*)\b")
_DISCORD_HELP = re.compile(r"\b(?:tickets?|support|help\w*|questions?|contact\w*|stuck|issues?|problems?|"
                           r"bugs?|updates?|news)\b")
_DISCORD_ASK = re.compile(r"\bask\w*\b")
_DISCORD_BOT = re.compile(r"\bbots?\b")
_DISCORD_INVITE = re.compile(r"(?:https?://)?(?:www\.)?discord(?:app)?\.(?:gg|com/invite)/[\w-]*")
_SENTENCE = re.compile(r"[^.!?\n]+")


def _points_into_discord(text: str) -> bool:
    """Whether a sentence of `text` names Discord with a recon cue and no help word (an invite link
    counts as both Discord and a cue; "ask" is a help word unless the sentence names a bot)."""
    text = _DISCORD_INVITE.sub(" discord invite ", text.casefold())
    for sentence in _SENTENCE.findall(text):
        if "discord" not in sentence:
            continue
        rest = sentence.replace("discord", " ")
        if not _DISCORD_RECON_CUE.search(rest) or _DISCORD_HELP.search(rest):
            continue
        if _DISCORD_ASK.search(rest) and not _DISCORD_BOT.search(rest):
            continue
        return True
    return False


def read_challenge(challenge_dir: str | Path) -> dict:
    """{"id", "name", "description", "discord_only", "bare"} from a challenge folder's challenge.json
    (data, never instructions; tags are appended to the description). "bare" is True when it lists no
    files and no target. A folder without one gives the leading part of its name as the id, empty text,
    discord_only False and bare None (not known)."""
    d = Path(challenge_dir)
    out = {"id": d.name.split("-", 1)[0], "name": "", "description": "", "discord_only": False,
           "bare": None}
    p = d / "challenge.json"
    if not p.is_file():
        return out
    try:
        doc = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as e:
        raise DiscordReconError(f"{p}: cannot be read as JSON ({e})") from None
    if isinstance(doc, dict):
        if doc.get("id") not in (None, ""):
            out["id"] = str(doc["id"])
        out["name"] = str(doc.get("name") or "")
        tags = doc.get("tags") if isinstance(doc.get("tags"), list) else []
        tag_text = " ".join(str(t.get("value") if isinstance(t, dict) else t) for t in tags)
        out["description"] = "\n".join(x for x in (str(doc.get("description") or ""), tag_text) if x)
        # A challenge that lives in the server: tagged so, or with nothing else to work on (no handout,
        # no target) and either named for Discord or pointing into it (a recon cue in the sentence that
        # says Discord). "Ask on Discord" in a brief whose ciphertext is inline is support, not recon.
        bare = not doc.get("files") and not str(doc.get("connection_info") or "").strip()
        out["bare"] = bare
        said = "discord" in out["name"].casefold() or _points_into_discord(str(doc.get("description") or ""))
        out["discord_only"] = "discord" in tag_text.casefold() or (bare and said)
    return out


def report_title(ch: dict) -> str:
    return f"Discord recon candidates for challenge {ch['id']}" + (f" ({ch['name']})" if ch["name"] else "")


def analyze_challenge(snap: Snapshot, profile: EventProfile, challenge_dir: str | Path, *,
                      extra_cues: Sequence[str] = (), decode: bool = True, write: bool = True,
                      top: int | None = 50) -> tuple[Report, Path | None]:
    """analyze() ranked for one challenge (its name and description give the cues, its brief the
    decoys) and, with write, the report at <challenge>/recon/discord.md. (report, path or None)."""
    ch = read_challenge(challenge_dir)
    rep = analyze(snap, profile, cues=cue_words(ch["name"], ch["description"], *extra_cues),
                  brief=ch["name"] + "\n" + ch["description"], decode=decode)
    path = None
    if write:
        path = Path(challenge_dir) / CHALLENGE_REPORT
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_report(rep, title=report_title(ch), top=top), encoding="utf-8")
    return rep, path
