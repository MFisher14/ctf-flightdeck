#!/usr/bin/env python3
"""KB-6 (the Day 27 build): new structural / format enum tokens, answered as UNSURE picks the bytes prove.

The Day 23 loss (+78 min) was a new structural enum. The judged enums already list tokens no reader names
(`neko_bytecode`, `wasm_data_segment`): the author plants a token one day and delivers the sample later. This
module is asked LAST, after everything else (`evidence.solve_set`, beside `folded_storage`), and only about an id
that is still None (a format, a NEKO header field) or still UNSURE (hcfg_storage). It adds, never replaces, a plain
answer, and every value it gives is a `labels.pick` (never plain until the judge has accepted the name for the
key).

1. FORMAT of a container no reader names. A NEKO VM module (the magic `NEKO` and a 16-byte header the loader
   accepts, binfmt.neko_header; the tables need not parse) answers `analysis_format` as the one-option pick
   `binary.format/neko+enum+<tag of the enum's vocabulary>` (`token` stands for the enum's token that names the
   format), the token only where the question's enum lists it; a question that takes any text (exact_text) gets the
   bare label under `binary.format/neko+exact+<field>+<tag of the syntax>`. Lua bytecode (`\\x1bLua`) and a DEX file
   answer a token of the question's enum that names them, else nothing. The per-build ids (`dNN_analysis_<build>_format`:
   Day 24's `vulnerable` and `corrected`, Day 19's `compact`, `direct`, `stripped`, `symbolized`) list `neko_bytecode`
   in their enums too, and are answered the same way from the one build file their id names (generic.role_answers's
   resolution), only under an enum that lists such a token and only where the set names two or more builds, as generic
   does. Two enum tokens that name the one format are both offered, under a key that carries the enum's vocabulary.
   Every key is this module's own (never the bare `binary.format/<slug>` of generic.format_answer's labels: the review
   found `token` accepted for a DEX key answered back as a label) and none is shared across questions that list other
   tokens or ask under another field or syntax (the second review: the single-token key had neither, and the `token`
   accepted for the container formats answered `neko_serialized` for a payload's serialization). The rewording guard is
   asked again about a plain answer of this module (evidence.structural_enums). A prefix-level format id is not
   answered where the prefix's files state more than one container (`container_split`: generic.agreed_header's rule,
   with NEKO, Lua and DEX added to the containers its header reads).
2. NEKO header fields (`nglobals`, `nfields`, `codesize` of the 16-byte header): picks under
   `binary.<field>/neko` (the code size in slots as the header states it, then the packed code's bytes when the
   tables parse, then four bytes a slot; readings that give one number are one option named for all of them), only
   for a file whose header binfmt reads (the loader's own limits) and a prefix whose NEKO modules share a header.
3. A CARRIER the question's enum lists but no reader names. `hcfg_storage` of a sample whose structure (a PNG's
   chunks, a ZIP's entries and comment, a WebAssembly custom section or data segment, an ELF note, the overlay of an
   ELF or PE, the string globals of a NEKO module) holds the day's CRC-valid HCFG record IN ONE PLACE is offered as a
   pick under `binary.hcfg_storage/carrier+<place>+<stored form>` whose first options are the enum tokens that name
   that place (png_chunk, zip_entry, wasm_custom_section, ...), then the options the shipped answer had. The place is
   PROVEN by code: `hcfg_storage.detect` finds a CRC-valid record named for the day inside the region, and nowhere
   else in the file (a second copy in another place, a differing record of the day, a copy in a second stored form,
   a CRC that does not check: no carrier, the shipped answer stands; the file is also read again with the region
   blanked (the compressed stream of a deflated archive entry, the stored bytes of any other region), and any CRC-valid
   record that still shows is a second carrier, and so is a record of the day in another member of the prefix, and so
   is a record of the day, other than this one, that any reader of the lane finds: the generic walk or the packed
   readers; a record names the day by its campaign's `BR<day>-` prefix, whatever the suffix: the variants of every
   timed mode since Day 23 have eight hex digits). A token the question's enum does not list is never offered, and
   neither is one that names another container (`pe_overlay` for an ELF, `elf_overlay` for the bytes after a PNG) or,
   for an archive entry, the archive's comment. A shipped PLAIN answer is never touched. The proof costs what the
   sample's size says, whatever its tables claim: the readers are read lazily, no region is built over REGION_MAX
   (a compressed chunk is inflated no further), two section headers over one span are one region, and one sample's
   regions are searched for DETECT_MAX bytes and REGIONS_MAX regions in all.

Everything is gated by a cheap check: the enum must list a token that names a place, and the sample's magic must be
that container's; a lane's saved enums (raw, base64, raw_const_array, raw_hcfg_section, wasm_data_segment) reach no
code beyond a few regular-expression tests (measured over every saved Binary attempt of Days 17 to 26, this module's
`close` costs 0.2 ms a base and 2.5 ms a Mastery in all, never 1 ms in one call).

Nothing here is a judged fact. binfmt.neko reads a NEKO module the way Neko's own loader reads it (vm/module.c,
neko_read_module: globals of six kinds, field names, the code packed into bytes, debug information); the layout is used
only to name the place a record stands in, and tables that do not parse that way to the very end of the file prove no
place. (The first build of this reader took a function global for two u32, a version for a u32 and the code for
`codesize` words of four bytes, which no module the loader reads has.)
"""
import json
import re
import struct
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _p in (HERE, HERE.parent / "common"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
import answer_kinds   # noqa: E402
import binfmt         # noqa: E402
import hcfg_storage   # noqa: E402
import labels         # noqa: E402

JUDGED_FORMS = ("base64", "raw_hcfg_section", "raw_const_array")
SET_PREFIX = re.compile(r"^set\d+\.")
# Bounds by counts and bytes (the second review of KB-6: every region of a sample was built before any cap applied, and
# each kept one was searched whole, so 64 notes over one 4 MiB blob cost 4.8 s and 336 MB, and 16 zTXt chunks 139 MB from
# a 131 KB file). A reader is iterated lazily, a region over REGION_MAX is never built, a compressed chunk is inflated
# no further than REGION_MAX + 1 bytes, and one sample's regions are searched for DETECT_MAX bytes in all.
REGION_MAX = 4 << 20            # bytes of one region searched for a record
REGIONS_MAX = 256               # regions of one sample read
DETECT_MAX = 32 << 20           # bytes of regions of one sample searched in all (hcfg_storage.MAX_EXTRA_BYTES's size)
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


# ---------------------------------------------------------------------------- the question

def _field(qid: str) -> str:
    qid = SET_PREFIX.sub("", qid or "")
    return qid.split("_", 1)[1] if "_" in qid else qid


def _bare(field: str) -> str:
    return field[len("analysis_"):] if field.startswith("analysis_") else field


def enum_tokens(fmt) -> list:
    if answer_kinds.kind_of(fmt) != "enum":
        return []
    return [t for t in (fmt.get("accepted_values") or []) if isinstance(t, str)]


FORMAT_FIELD = re.compile(r"(?:container_|file_|binary_|artifact_|module_)?format")
NEKO_FIELDS = (("nglobals", re.compile(r"(?:neko_)?(?:n_?globals|globals?(?:_count)?|global_count|num_globals)")),
               ("nfields", re.compile(r"(?:neko_)?(?:n_?fields|fields?(?:_count)?|field_count|num_fields)")),
               ("codesize", re.compile(r"(?:neko_)?(?:code_?size|code_words|code_len(?:gth)?|code_count|n_?code)")))


# ---------------------------------------------------------------------------- 1. formats no reader names

def _lua(d):
    return d[:4] == b"\x1bLua" and len(d) >= 12


def _neko(d):
    """A NEKO module by its magic and a 16-byte header the loader accepts (binfmt.neko_header: at most 0xFFFF globals and
    field names, at most 0xFFFFFF code slots). The tables are not asked for: a module whose tables do not parse as the
    loader reads them (an author's hand-made file) is still the format's token, one probe on the base at the worst; but a
    file that merely begins with the four letters (a README, an `NEKO is a VM` text, a header the loader would refuse)
    is not (the review of KB-6: the first build took the magic alone, and once the judge accepted the name for the key
    that answer would have been plain for any such text)."""
    return binfmt.neko_header(d) is not None


# binfmt.neko parses the whole module (0.56 s at the loader's largest code size, 16.7 MB): one solve asks for it once
# per header id and once more for the carrier, so it is read once per bytes object. An entry holds the object it was
# read from, so its identity is never another object's.
_NEKO_MEMO = []


def neko_head(data):
    """binfmt.neko(data), parsed once per bytes object (the last two are kept)."""
    for held, head in _NEKO_MEMO:
        if held is data:
            return head
    head = binfmt.neko(data)
    _NEKO_MEMO.append((data, head))
    del _NEKO_MEMO[:-2]
    return head


FORMATS = (   # (slug, token pattern, token for an exact_text question or None, magic test)
    ("neko", re.compile(r"neko"), "neko_bytecode", _neko),
    ("lua", re.compile(r"(?<![a-z])lua(?![a-z])"), None, _lua),
    ("dex", re.compile(r"(?<![a-z])dex(?![a-z])|dalvik"), None, lambda d: binfmt.dex(d) is not None),
)


def vocabulary_tag(tokens) -> str:
    """Eight hex digits naming an enum's vocabulary (the CRC-32 of its sorted tokens): a name the judge accepted for a
    key that carries it answers only a question that lists the same tokens, never one whose enum was reworded."""
    return format(zlib.crc32("|".join(sorted(tokens)).encode()) & 0xFFFFFFFF, "08x")


def format_answer(data: bytes, fmt, enum_only: bool = False, field: str = "format"):
    """The container format of `data` as an unsure pick, for a format no shipped reader names (NEKO, Lua bytecode, DEX).
    One enum token names it: the one-option pick `binary.format/<slug>+enum+<vocabulary tag>` whose name `token` stands
    for "the enum's token that names this format", so an accepted name answers the next variant with that enum's own
    token. Several tokens name it: the bytes do not say which one the judge wants, so they are all offered, under a key
    that carries the enum's vocabulary (a bare-label key answers an accepted name even where the caller does not list
    it). No such token: nothing, except for a question that takes any text (`exact_text`) and a format that has a default
    token, offered as the bare label under `binary.format/<slug>+exact+<field>+<syntax tag>` (a text has no vocabulary,
    so the key carries the field word and the tag of the question's syntax instead); `enum_only` (a per-build id, whose
    kind is not known to be a container format) never takes that way.

    Every key here is this module's own (the review of KB-6). The first build kept the bare `binary.format/<slug>` for
    the `token` name, and generic.format_answer keeps it for its bare labels (`dex`, `dalvik_dex`): a name accepted
    for one reader's convention was then answered by the other as a label, so a DEX sample's format question asked as
    exact_text came back as the literal `token`, plain. The enum's own token and the exact_text default are two
    conventions too (`token` is the enum's token in one and the fixed default in the other), so they are two keys.

    Both enum keys carry the tag of the enum's vocabulary (the second review of KB-6). The single-token key held
    neither the field nor the vocabulary, so the `token` accepted for `analysis_format` under its six container tokens
    answered, plain, every later format-like id whose enum listed ONE token matching the pattern, even one that asked
    another fact (`analysis_loader_format` over [json, neko_serialized, msgpack] came back `neko_serialized`). With the
    tag only a question that lists exactly the vocabulary the judge saw is answered from that acceptance. The real
    `analysis_format` enum of Days 19 to 26 is one vocabulary, shared by its per-build ids (stripped, symbolized,
    compact, direct, vulnerable, corrected), so those ids keep sharing one key."""
    for slug, pattern, default, test in FORMATS:
        if not test(data):
            continue
        tokens = enum_tokens(fmt)
        if tokens:
            hit = [t for t in tokens if pattern.search(t.lower())]
            if len(hit) == 1:
                return labels.pick(f"binary.format/{slug}+enum+{vocabulary_tag(tokens)}", [("token", hit[0])])
            if hit:
                return labels.pick(f"binary.format/{slug}+{vocabulary_tag(tokens)}", [(t, t) for t in hit])
            return None
        if not enum_only and default and answer_kinds.kind_of(fmt) in ("exact_text", ""):
            return labels.pick(f"binary.format/{slug}+exact+{field}+{answer_kinds.syntax_tag(fmt)}", [(default, default)])
        return None
    return None


def builds_named(gen, qs: list, members: list) -> set:
    """The distinct per-build words the set's question ids name, counted as generic.role_answers counts them: the build
    in front of a header field or config_<name> at the end of an id (`_role_split_qid`), and the build a sibling-diff of
    the member names gives (`builds`, `split_role`). generic answers a per-build id only when the set names two or more
    builds, so this module does too: the first build answered any `analysis_<x>_format` whose `<x>` was a segment of a
    member name (`analysis_payload_format` beside `d27--variant-000-payload.luac`), and a name rejected there would
    have poisoned the key for the real format ids (the review of KB-6). An empty set when generic's helpers are not
    there."""
    split, split_role, builds = (getattr(gen, n, None) for n in ("_role_split_qid", "split_role", "builds"))
    if not (callable(split) and callable(split_role) and callable(builds)):
        return set()
    by_build = builds(members)
    out = set()
    for q in qs:
        qid = q.get("qid") or ""
        build, _field_ = split(qid)
        if build:
            out.add(build)
        word, _field_ = split_role(qid, by_build)
        if word:
            out.add(word)
    return out


def role_format_member(gen, members: list, qid: str):
    """The bytes of the ONE build file a per-build format id (`dNN_analysis_<build>_format`: Day 24's
    `vulnerable` and `corrected`, Day 19's `compact`, `direct`, `stripped`, `symbolized`) names, resolved as
    generic.role_answers resolves a per-build id (the build word is a `-`/`_`-delimited segment of one member's
    name, a text sidecar is left out, the hits are one distinct body); None for anything else. The enums of these
    ids list `neko_bytecode` as the plain `analysis_format`'s do, so a delivered NEKO build would arrive here."""
    split, has, side = (getattr(gen, n, None) for n in ("_role_split_qid", "_name_has_build", "_text_sidecar"))
    if not (callable(split) and callable(has) and callable(side)):
        return None
    build, field = split(qid)
    if not build or field != "analysis_format":
        return None
    hits = [(n, d) for n, d in members if has(n, build)]
    hits = [(n, d) for n, d in hits if not side(n, d)] or hits
    if not hits or len({bytes(d) for _n, d in hits}) != 1:
        return None
    return bytes(hits[0][1])


def format_slug(blob) -> str:
    """The slug of the first of this module's formats whose magic `blob` carries (neko, lua, dex), else ''."""
    for slug, _pattern, _default, test in FORMATS:
        if test(blob):
            return slug
    return ""


def container_split(gen, members: list, data) -> bool:
    """Whether the prefix's files state more than one container, so that which one a prefix-level format id asks about is
    not established. generic.agreed_header makes the same decision for the containers it reads (`the prefix's executables
    disagree on it`: an ELF and a PE, a DEX and an ELF) and answers None; this module answers from pick_sample's sample,
    so it asks the same question first (the second review of KB-6: a DEX sample beside an ELF was declined by generic and
    answered with a pick here, and plain once the judge had accepted the name for a DEX day). The three formats this
    module reads are added to generic's, since generic's header does not read a NEKO module: a member of another of them
    (a Lua file beside a DEX, a NEKO module beside either) or of a container generic reads (side images and text files
    state none) is a split. Anything that cannot be read is read as a split."""
    try:
        if (gen.agreed_header(members, data).get("disagree") or {}).get("container"):
            return True
        mine = format_slug(data)
        for _name, blob in members:
            if blob is data:
                continue
            theirs = format_slug(blob)
            if not theirs:
                h = gen.header(blob)
                theirs = (h.get("container") or h.get("kind") or "") if h.get("kind") not in gen.IMAGE_KINDS else ""
            if theirs and theirs != mine:
                return True
    except Exception:
        return True
    return False


def neko_headers_differ(members: list) -> bool:
    """Whether the prefix holds NEKO modules whose 16-byte headers differ: a prefix-level count of globals, field names or
    code slots is then the count of which module, and nothing says (the second review of KB-6: only the format of a
    sample was held against a prefix of several, the header counts were read from the sample alone)."""
    heads = {binfmt.neko_header(blob) for _name, blob in members}
    heads.discard(None)
    return len(heads) > 1


# ---------------------------------------------------------------------------- 2. NEKO header fields

def _merge_equal(options: list) -> list:
    """[(name, value)] with the readings that give the SAME value joined into one option named for all of them
    (`slots_eq_packed_bytes`). Two names for one number let a probe credit its acceptance to the first name, and the next
    variant, where the readings differ, then answered that name plain although the judge may have meant the other (the
    second review of KB-6: a module whose code tags are all one byte has as many slots as packed bytes). The joined name is
    offered again only by a variant whose readings coincide again, where every one of them gives the same number."""
    merged = []
    for name, value in options:
        for pair in merged:
            if pair[1] == value:
                pair[0] += "_eq_" + name
                break
        else:
            merged.append([name, value])
    return [(name, value) for name, value in merged]


def neko_field(field: str, data: bytes, fmt):
    if answer_kinds.kind_of(fmt) not in ("integer", "exact_text", "pattern", ""):
        return None
    for name, pattern in NEKO_FIELDS:
        if not pattern.fullmatch(_bare(field)):
            continue
        header = binfmt.neko_header(data)           # the 16 bytes: the counts cost nothing
        if header is None:
            return None
        value = dict(zip(("nglobals", "nfields", "codesize"), header))[name]
        if name == "codesize":
            # the header counts code SLOTS: the file holds the code packed, so its byte length is read from the tables
            # when they parse, and a file an author wrote by hand may state words of four bytes
            options = [("slots", str(value))]
            head = neko_head(data)                  # only this id needs the tables (parsed once for the whole solve)
            if head is not None and head["tables"]:
                options.append(("packed_bytes", str(head["code_bytes"])))
            options.append(("bytes", str(4 * value)))
            options = _merge_equal(options)
        else:
            options = [("count", str(value))]
        return labels.pick(f"binary.{_bare(field)}/neko", options)
    return None


# ---------------------------------------------------------------------------- 3. carriers

def _any(*words):
    return lambda t: any(w in t for w in words)


TRAIL_WORDS = ("trail", "append", "overlay", "tail", "after_", "eof", "extra_data", "post_")

# The container words a token may carry, by the first word of a region's slug: a token that names ANOTHER container is
# no name for this one's place (the review of KB-6: an ELF's overlay was offered as `pe_overlay` first, the bytes after a
# PNG's IEND as `elf_overlay`). A token with no container word (`overlay`, `trailing_data`) names any container's.
CONTAINER_WORDS = {"png": ("png",), "zip": ("zip", "jar", "apk", "aar", "war", "ear"), "wasm": ("wasm",),
                   "elf": ("elf",), "pe": ("pe", "exe", "dll"), "neko": ("neko",),
                   # containers no region reader here reads: a token naming one is foreign to every place above
                   "macho": ("macho",), "dex": ("dex",), "lua": ("lua",)}
ALL_CONTAINER_WORDS = frozenset(w for words in CONTAINER_WORDS.values() for w in words)


def foreign_token(token: str, slug: str) -> bool:
    """Whether `token` carries the container word of a container other than the one `slug` names the place of."""
    own = CONTAINER_WORDS.get(slug.split("_", 1)[0].split("+", 1)[0], ())
    return bool(set(re.split(r"[^a-z0-9]+", token.lower())) & (ALL_CONTAINER_WORDS - set(own)))


def _entry_token(t: str) -> bool:
    """A token that names an archive's entry: the archive, or the entry, never the archive's comment (the review of
    KB-6: `zip_comment` was offered for an entry, beside `jar_entry`)."""
    return "comment" not in t and any(w in t for w in ("zip", "jar", "apk", "archive", "entry", "member"))


def _inflate(stream: bytes):
    """The bytes a zlib stream inflates to, at most REGION_MAX of them: False when it runs past that (such a region is
    not read, and a bomb is never inflated whole: the second review of KB-6 had 16 chunks of 8 MiB each from a 131 KB
    file), zlib.error when it is no stream."""
    out = zlib.decompressobj().decompress(stream, REGION_MAX + 1)
    return out if len(out) <= REGION_MAX else False


# Every reader below is a generator the caller drives lazily and stops at REGIONS_MAX regions or DETECT_MAX bytes, so a
# crafted sample costs what the caller lets it: no region is built before it is asked for.

def _png_regions(d):
    """(slug, token test, bytes, file span or None) of a PNG's chunks (the ancillary text ones decoded) and of
    the bytes after IEND."""
    if d[:8] != PNG_MAGIC:
        return
    at, end = 8, len(d)
    inflated_total = 0          # bytes inflated in all: a file of many compressed chunks stops at DETECT_MAX
    while at + 12 <= end:
        n, kind = struct.unpack_from(">I", d, at)[0], d[at + 4:at + 8]
        body = at + 8
        if n > end or body + n + 4 > end or not kind.isalpha():
            return
        if n > REGION_MAX:          # a chunk over REGION_MAX (the image data of a big picture) is no region, and no copy of it is made
            at = body + n + 4
            continue
        data = d[body:body + n]
        ctype = kind.decode("latin-1")
        low = ctype.lower()

        def ok(t, low=low):
            if "chunk" not in t and "png" not in t:
                return False
            if any(w in t for w in TRAIL_WORDS) and "chunk" not in t:
                return False
            if re.search(r"text|txt", t):
                return low in ("text", "ztxt", "itxt")
            if "idat" in t or "pixel" in t:
                return low == "idat"
            return True
        inflated = None
        if ctype in ("zTXt", "iTXt"):
            try:
                if ctype == "zTXt" and b"\0" in data[:80]:
                    inflated = _inflate(data[data.index(0) + 2:])
                elif ctype == "iTXt" and b"\0" in data[:80] and data[data.index(0) + 1]:
                    rest = data[data.index(0) + 3:]
                    rest = rest[rest.index(0) + 1:] if b"\0" in rest else b""
                    rest = rest[rest.index(0) + 1:] if b"\0" in rest else b""
                    inflated = _inflate(rest)
            except (zlib.error, ValueError, IndexError):
                inflated = None
            if inflated is not None:
                inflated_total += REGION_MAX if inflated is False else len(inflated)
                if inflated_total > DETECT_MAX:
                    return
        if inflated is False:
            pass                    # a stream that runs past REGION_MAX: no region
        elif inflated is not None:  # a compressed text chunk is read once, inflated (the file shows only the stream)
            yield f"png_chunk+{ctype}", ok, inflated, (body, body + n, "zlib")
        else:
            yield f"png_chunk+{ctype}", ok, data, (body, body + n)
        at = body + n + 4
        if kind == b"IEND":
            if at < end and end - at <= REGION_MAX:
                yield "png_trailing", (lambda t: "chunk" not in t and any(w in t for w in TRAIL_WORDS)), d[at:], (at, end)
            return


def _zip_regions(d):
    if d[:4] != b"PK\x03\x04":
        return
    import io
    import zipfile
    try:
        zf = zipfile.ZipFile(io.BytesIO(d))
        infos = zf.infolist()
    except (zipfile.BadZipFile, ValueError, OSError):
        return
    seen = set()                # entries that share one local header are one entry
    for n, info in enumerate(infos):
        if n >= REGIONS_MAX:
            break
        if info.is_dir() or info.file_size > REGION_MAX or info.flag_bits & 1 or info.header_offset in seen:
            continue
        seen.add(info.header_offset)
        # The file span of the entry's bytes as the file holds them: the stored bytes of a stored entry, the compressed
        # stream of any other (its third item says the region is derived from them). The carrier proof reads the file
        # again with that span blanked (the second review of KB-6: a deflated entry had no span, so a second copy of its
        # record in a form only the lane's readers read, in the comment or another entry, withdrew nothing).
        span = None
        stored = info.compress_type == zipfile.ZIP_STORED
        if info.header_offset + 30 <= len(d):
            nlen, elen = struct.unpack_from("<HH", d, info.header_offset + 26)
            start = info.header_offset + 30 + nlen + elen
            size = info.file_size if stored else info.compress_size
            if start + size <= len(d):
                span = (start, start + size) if stored else (start, start + size, "packed")
        if span is None:
            continue                # an entry whose bytes cannot be placed in the file proves no place: no region
        try:
            # the compression method is part of the slug (so of the key): an enum may tell a stored entry from a
            # deflated one, and a name the judge accepted for one must not answer the other plain
            yield (f"zip_entry+{'stored' if stored else 'method' + str(info.compress_type)}",
                   _entry_token, zf.read(info), span)
        except Exception:
            continue
    if zf.comment:
        at = d.rfind(zf.comment)
        if at >= 0:
            yield "zip_comment", _any("comment"), zf.comment, (at, at + len(zf.comment))


def _wasm_regions(d):
    info = binfmt.wasm(d) if d[:4] == b"\0asm" else None
    if not info:
        return
    for sid, body, size in info.get("sections") or ():
        if sid == 0 and size <= REGION_MAX:
            yield "wasm_custom_section", _any("custom"), d[body:body + size], (body, body + size)
    for off, n in (binfmt.wasm_data_segments(d, info) or ())[:REGIONS_MAX]:
        if n <= REGION_MAX:
            yield "wasm_data_segment", _any("data_segment", "data_seg", "datasegment"), d[off:off + n], (off, off + n)


def _exe_regions(d):
    """The notes (ELF SHT_NOTE) and the overlay (bytes past everything an ELF or PE maps or lists)."""
    elf = binfmt.elf(d) if d[:4] == b"\x7fELF" else None
    if elf:
        seen = set()            # section headers may point at one span, or at spans that overlap (4096 at most)
        for sec in elf.get("sections") or ():
            span = (sec["offset"], sec["size"])
            if sec["type"] == 7 and 0 < sec["size"] <= REGION_MAX and sec["offset"] + sec["size"] <= len(d) \
                    and span not in seen:
                seen.add(span)
                yield "elf_note", _any("note"), d[sec["offset"]:sec["offset"] + sec["size"]], \
                    (sec["offset"], sec["offset"] + sec["size"])
    if elf or d[:2] == b"MZ":
        try:
            import packed_tail
            ts = packed_tail.tail_start(d)
        except Exception:
            ts = None
        if ts is not None and len(d) - ts <= REGION_MAX:
            yield ("elf_overlay" if elf else "pe_overlay"), _any(*TRAIL_WORDS), d[ts:], (ts, len(d))


def _neko_regions(d):
    head = neko_head(d)
    if not head or not head["tables"]:
        return
    for off, n in head["strings"][:REGIONS_MAX]:
        if n <= REGION_MAX:
            yield "neko_string", _any("neko", "global", "string"), d[off:off + n], (off, off + n)


_TRAIL = r"overlay|trail|append|tail|after_|eof|extra_data|post_"
# (reader, the words of a token it can name): a reader runs only when the question's enum lists such a token
REGION_READERS = ((_png_regions, re.compile(r"png|chunk|" + _TRAIL)),
                  (_zip_regions, re.compile(r"zip|jar|apk|archive|entry|member|comment")),
                  (_wasm_regions, re.compile(r"custom|data_?seg")),
                  (_exe_regions, re.compile(r"note|" + _TRAIL)),
                  (_neko_regions, re.compile(r"neko|global|string")))
# every word a place-naming token holds: the gate that keeps a lane's saved enums out of this module
PLACE_WORDS = re.compile("|".join(p.pattern for _, p in REGION_READERS))


def day_prefix(record, day) -> bool:
    """Whether a CRC-valid record's campaign begins `BR<day>-`: a record of the day under ANY suffix (the base's `000`, a
    variant's eight hex digits, a longer one). It is the test for a record that may be a SECOND carrier, and so the wider
    of the two day tests of this module: `hcfg_storage._names_day` (`BR<day>-` and 3 to 16 letters or digits) decides which
    record may BE the carrier, and a decoy whose campaign that rule does not read must still withdraw the pick. The first
    build asked generic._names_day, which reads three digits only, and every Time Trial and Mastery record since Day 23
    has eight hex digits (`BR23-A267EF93` to `BR26-F642A81B`): the lane's own readers' records were all dropped, and the
    proof that no second carrier stood in a form only they read was always passed (the second review of KB-6)."""
    j = record.get("json") if isinstance(record, dict) else None
    campaign = j.get("campaign") if isinstance(j, dict) else None
    return isinstance(campaign, str) and campaign.startswith(f"BR{day:02d}-")


def holds_day_record(blob: bytes, day) -> bool:
    """Whether another member of the prefix holds a CRC-valid record named for the day, or several distinct records
    (which is no clean answer either)."""
    found, why = hcfg_storage.detect({"member": blob}, None)
    if found is not None:
        return day_prefix(found.config, day)
    return "no CRC-valid" not in why


def span_kind(span) -> str:
    """How a region stands in the file: `none` (no span: its bytes cannot be blanked, so no place is proven), `raw` (the
    file holds the region's bytes at `span`), `zlib` (an inflated PNG chunk: the file holds the stream, inside the chunk)
    or `packed` (an archive entry in a compression other than stored: the file holds the compressed stream at `span`)."""
    if span is None:
        return "none"
    return span[2] if len(span) == 3 else "raw"


def carrier(data: bytes, day, tokens: list, others=(), pool=None):
    """(slug, stored form, [tokens that name the place]) when the day's CRC-valid record stands in exactly one
    region of `data` and nowhere else, and in none of the prefix's other members (`others`), and no other record of
    the day is read by any reader of the lane (`pool`, a callable: see `lane_records`), else None."""
    if day is None or not tokens:
        return None
    hits, n, spent = [], 0, 0
    for reader, words in REGION_READERS:
        if n > REGIONS_MAX or spent > DETECT_MAX:
            break                   # the sample's budget is used up: what is left unread proves nothing, nor is needed
        if not any(words.search(t.lower()) for t in tokens):
            continue
        here = []
        try:
            for slug, ok, region, span in reader(data):         # lazily: a region is built when it is asked for
                n += 1
                if n > REGIONS_MAX:
                    break
                if not region or len(region) > REGION_MAX or len(region) < 16:
                    continue
                spent += len(region)
                if spent > DETECT_MAX:
                    break
                found, _why = hcfg_storage.detect({"region": bytes(region)}, None)
                if found is None or found.encoding is None or not hcfg_storage._names_day(found.config, day):
                    continue
                here.append((slug, ok, found, span))
                if len(hits) + len(here) > 1:
                    return None     # a second place: no carrier, whatever else stands in the file
        except Exception as e:      # a reader that fails reads nothing of this sample
            print(f"[structural] {reader.__name__} raised {type(e).__name__}: {e}", file=sys.stderr)
            continue
        hits += here
    if len(hits) != 1:
        return None
    slug, ok, found, span = hits[0]
    named = [t for t in tokens if ok(t.lower()) and not foreign_token(t, slug)]
    if not named:
        return None
    # nowhere else: the whole file holds no other reading of the record (a copy outside the region, a second
    # stored form, a differing record of the day), and a raw record lies wholly inside the region
    kind = span_kind(span)
    if kind == "none":
        return None                 # a region the file holds nowhere cannot be blanked and read again: no proof of a place
    whole, _ = hcfg_storage.detect({"file": data}, None)
    whole_day = whole is not None and hcfg_storage._names_day(whole.config, day)
    if kind == "packed":
        if whole_day:
            return None             # derived bytes (an entry decompressed) and a reading of the file itself
    elif kind == "zlib":            # an inflated chunk: the file itself shows only the stream, inside the chunk
        if not whole_day or whole.encoding != span[2] or len(whole.encodings) != 1 \
                or not (span[0] <= (whole.offset if whole.offset is not None else -1) < span[1]):
            return None
    else:
        if not whole_day or whole.encoding != found.encoding or len(whole.encodings) != 1:
            return None
        if found.encoding == "verbatim":
            offsets = [off for off, _c in hcfg_storage._raw(data)]
            if not offsets or any(not (span[0] <= off and off + 12 <= span[1]) for off in offsets):
                return None
        elif not (span[0] <= (whole.offset if whole.offset is not None else -1) < span[1]):
            return None
    # nowhere else, read from the other side: blank the region (the bytes the file holds for it: a compressed entry's
    # stream too) and read the file again. The checks above see a raw copy outside the region and a second stored
    # form, and for a text only the FIRST place of its form, so a second copy of the same text in a place no region
    # names stood unseen; a CRC-valid record that still shows with the region blanked is a second carrier, and the
    # place is not proven
    lo, hi = span[0], span[1]
    rest, why = hcfg_storage.detect({"file": data[:lo] + bytes(hi - lo) + data[hi:]}, None)
    if rest is not None or "no CRC-valid" not in why:
        return None
    if any(holds_day_record(blob, day) for blob in others):
        return None                 # the same record in another member of the prefix: a second carrier too
    if pool is not None:
        # nowhere else, read by the lane's own readers. The proof above sees the forms hcfg_storage.detect reads; the
        # generic walk and the packed readers read more (a one-byte XOR over the whole record, RC4, a rotation, a
        # reversed text, ...), and a CRC-valid record of the day in any of them, other than this carrier's, is a decoy
        # or a second place: the review of KB-6 staged a PNG with the record in a tEXt chunk and a same-campaign decoy
        # XOR-ed whole after IEND, which the walk answers None for and the carrier proof still offered the chunk.
        held = pool()
        mine = (found.config.get("key"), found.config.get("crc32"), found.config.get("plain"))
        if held is None or held - {mine}:
            return None
        # and the same record a second time in such a form: with the region blanked the lane's readers find no record
        # of the day at all (a second copy of this carrier's own record shows too; its identity is the same)
        rest = pool(data[:lo] + bytes(hi - lo) + data[hi:])
        if rest is None or rest:
            return None
    return slug, found.encoding, named


def lane_records(gen, members: list, day, sample: str):
    """A callable `read(blanked=None)` giving the set of (key, crc32, plain) of every CRC-valid record that names `day`
    which the lane's own readers find in the prefix's files: the generic walk (record_pool) and the packed readers
    (`_packed_pool`: a packed tail with no digest, the whole record RC4-encrypted under a string of the sample). With
    `blanked` (the bytes of the member named `sample`, a carrier's region zeroed) the same, the sample read as that.
    None when they cannot be read (nothing is then proved). Read on demand: it is asked only after every other proof of
    a carrier passed, and the unblanked reading once. A record names the day by its campaign's `BR<day>-` prefix
    (`day_prefix`)."""
    box = []

    def read(blanked=None):
        if blanked is None and box:
            return box[0]
        try:
            ms = members if blanked is None else [(n, blanked if n == sample else b) for n, b in members]
            records = list(gen.record_pool(ms, day)) + [c for _i, c in gen._packed_pool(ms)]
            got = {(c["key"], c["crc32"], c["plain"]) for c in records if day_prefix(c, day)}
        except Exception as e:
            print(f"[structural] the lane's records could not be read ({type(e).__name__}: {e})", file=sys.stderr)
            got = None
        if blanked is None:
            box.append(got)
        return got
    return read


def storage_answer(q, old, data: bytes, day, others=(), pool=None):
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else None
    tokens = enum_tokens(fmt)
    if not tokens or not any(PLACE_WORDS.search(t.lower()) for t in tokens):
        return None
    if isinstance(old, str) and not labels.is_unsure(old):
        return None                 # a plain answer stands
    parsed = labels.parse(old) if isinstance(old, str) else None
    guard_key = (parsed is not None and str(parsed.key).startswith("binary.rule_text/")
                 and str(parsed.key).endswith(labels.CANDIDATE_MARK))
    if parsed is not None and not guard_key and not str(parsed.key).startswith("binary.hcfg_storage/"):
        return None                 # another guard's key (question_text, ...) is its own mechanism: it stands
    got = carrier(data, day, tokens, others, pool)
    if got is None:
        return None
    slug, enc, named = got
    if enc in JUDGED_FORMS:
        return None                 # base64 and the sections the organiser's ordered rule names stay the shipped reading
    if guard_key:
        # the reword guard (judged_forms B6) already offers every token the enum lists, as `listed:<token>`
        # hypotheses under its own key: keep key and names, and move the proven place's token(s) to the front
        pairs = [tuple(p) for p in parsed.options]
        lead = [p for p in pairs if str(p[1]) in named]
        if not lead or pairs[:len(lead)] == lead:
            return None
        body = {"k": parsed.key, "o": [list(p) for p in lead + [p for p in pairs if p not in lead]]}
        return labels.SENTINEL + json.dumps(body, separators=(",", ":"))
    carriers = [(t, t) for t in named]
    options = carriers
    if parsed is not None:
        if parsed.options and parsed.options[0][1] == named[0]:
            return None             # the shipped pick already leads with the proven token
        shipped = [(str(v), str(v)) for _n, v in parsed.options if str(v) not in named]
        # a text encoding (base32hex, zlib, ...) is the organiser's earlier rule: the encoding first, the place after
        options = (shipped + carriers) if enc != "verbatim" else (carriers + shipped)
    # the key carries a tag of the enum's vocabulary: an accepted name answers (plain) only a question that lists
    # the same tokens, never one whose enum was reworded (a pick of bare labels returns its accepted name as it is)
    return labels.pick(f"binary.hcfg_storage/carrier+{slug}+{enc}+{vocabulary_tag(tokens)}", options)


# ---------------------------------------------------------------------------- entry point

def close(qs: list, got: dict, files: dict, ctx, gen) -> dict:
    """`got` with the answers of this module added for the ids it covers (see the module docstring)."""
    todo = []
    for q in qs:
        qid = q.get("qid") or ""
        field = _field(qid)
        bare = _bare(field)
        old = got.get(qid)
        tokens = enum_tokens(q.get("answer_format")) if isinstance(q.get("answer_format"), dict) else []
        if old is None and (FORMAT_FIELD.fullmatch(bare) or any(p.fullmatch(bare) for _, p in NEKO_FIELDS)):
            todo.append(("simple", q, field))
        elif old is None and bare.endswith("_format") and gen is not None \
                and any(p.search(t.lower()) for t in tokens for _s, p, _d, _t in FORMATS):
            todo.append(("role", q, field))     # a per-build id (`<build>_format`): only an enum that lists such a token
        elif field.endswith("analysis_hcfg_storage") or field == "hcfg_storage":
            if (old is None or labels.is_unsure(old)) and any(PLACE_WORDS.search(t.lower()) for t in tokens):
                todo.append(("storage", q, field))
    if not todo or gen is None:
        return got
    prefix = SET_PREFIX.sub("", todo[0][1].get("qid") or "").split("_", 1)[0].lower()
    pre = prefix
    mine = {n: files[n] for n in files if " -> " not in n and n.rsplit("/", 1)[-1][:len(pre)].lower() == pre}
    members = gen.members_of(prefix, mine or files, ctx)
    if not members:
        return got
    data = None
    if any(kind != "role" for kind, _q, _f in todo):     # a per-build id names its own member: no sample to pick for it
        name, data, _a, _b = gen.pick_sample(members, gen.day_of(prefix))
        if name is None:
            name, data = members[0][0], members[0][1]
        data = bytes(data)
    day = gen.day_of(prefix)
    others = [b for n, b in members if n != name] if data is not None else []     # (the prefix's other members)
    pool = lane_records(gen, members, day, name) if day is not None and data is not None else None
    builds = None                       # the per-build words the set's ids name (read once, only for a per-build id)
    ambiguous = {}                      # (the prefix's own ambiguity, read once: see container_split, neko_headers_differ)
    for kind, q, field in todo:
        qid = q["qid"]
        fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else None
        try:
            if kind == "role":
                if builds is None:
                    builds = builds_named(gen, qs, members)
                if len(builds) < 2:     # one build word is no per-build day (generic.role_answers answers nothing then)
                    continue
                build = role_format_member(gen, members, qid)
                value = format_answer(build, fmt, enum_only=True) if build is not None else None
            elif kind == "simple":
                if FORMAT_FIELD.fullmatch(_bare(field)):
                    value = format_answer(data, fmt, field=_bare(field))
                    if value is not None:
                        if "container" not in ambiguous:
                            ambiguous["container"] = container_split(gen, members, data)
                        if ambiguous["container"]:      # which of the prefix's containers is asked is not established
                            print(f"NOTE {qid}: structural_enums: the prefix's files state more than one container; "
                                  "the format is not answered (generic.agreed_header's rule)", file=sys.stderr)
                            value = None
                else:
                    if "neko" not in ambiguous:
                        ambiguous["neko"] = neko_headers_differ(members)
                    value = None if ambiguous["neko"] else neko_field(field, data, fmt)
            else:
                value = storage_answer(q, got.get(qid), data, day, others, pool)
        except Exception as e:
            print(f"NOTE {qid}: structural_enums raised {type(e).__name__}: {str(e)[:200]}; left as it is", file=sys.stderr)
            continue
        if isinstance(value, str) and value.strip():
            print(f"NOTE {qid}: {'unset' if got.get(qid) is None else 'unsure'} answer set by structural_enums.py "
                  f"({value[:100]})", file=sys.stderr)
            got[qid] = value
    return got


if __name__ == "__main__":
    for path in sys.argv[1:]:
        blob = Path(path).read_bytes()
        print(path, "format:", format_answer(blob, None), "| neko:", binfmt.neko(blob) and
              {k: v for k, v in binfmt.neko(blob).items() if k in ("nglobals", "nfields", "codesize", "tables")})
