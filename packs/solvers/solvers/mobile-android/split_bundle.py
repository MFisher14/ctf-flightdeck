#!/usr/bin/env python3
"""Split APK bundles: an .apks / .xapk / zip of *.apk splits, or an .aab-like module zip (Day 26 fold).

Day 26 ("Split Decision") delivered an `.apks` (base.apk + feature.apk). The shipped solver read the
bundle only one level down, with the base and the feature split's members merged under one name space,
and stopped; the morning's `day_patch.py` closed the base, the Time Trial and the Mastery. This module
is that live fix folded in, made variant-proof, plus the racer's cross-split reader (backlog row 532).
`codec_search.solve_set` asks `solve()` first for every delivery whose puzzle document is not its own
member and whose own names hold two or more *.apk members or .aab module folders (`candidate()`, the central
directory only; an inner APK past the shipped reader's 1 MiB member bound counts); anything that is not a
split bundle, or that this module cannot read, is answered as before.

What a bundle is (`bundle()`): a zip with no puzzle document of its own whose members include two or
more `*.apk` splits (each a readable, unencrypted zip), or a zip of two or more module folders
`<module>/manifest/AndroidManifest.xml` (the .aab layout: `<module>/dex/`, `<module>/root/` and
`<module>/manifest/` re-rooted). Exactly ONE puzzle document in the whole bundle; the split that holds it
is the base. One package in a zip, or two packages' documents, is not a bundle (the shipped reader's, as
before), and neither is a zip where a non-base member's compiled manifest reads and names no `split` (a
whole second package) or another package than the base's (`_one_app`; Day 26's feature.apk says split
`arena_feature` and the base's package; a manifest that does not read proves nothing either way). Bounded
by sizes and counts.

The readings, every one fail-closed (a doubt is None, never a code):

  split   the base's codec `split` document with EMPTY parts, each filled exactly once by a part document
          (`assets/*.json` with `part` and `part_index`) of a NON-base split; nothing written over a
          non-empty part, every part filled, the order a permutation, an exact ANS-[0-9A-F]{16}. Both
          order readings, the judged one first, under `mobile.codec/split+feature` (judged on Day 26:
          `split:by-order+feature`). A document with fields beyond schema/day/codec/data/parts/order (or
          a non-empty `data`), or a part document with fields beyond Day 26's (a `decoy`, `active` or
          `use` flag), goes under `<key>:extra-fields`, unsure. A part document in the base split, a
          duplicate index, a part over a non-empty part, an empty part left, a part document naming
          another codec: the answer is WITHHELD (None), not handed back to the shipped path, which would
          read the base document alone.

  analysis the base's codec `analysis` document: the app's own dex chain computes the code
          (dex_chain_codec.VM, the shipped interpreter) and reads an asset of a split. The VM is NOT
          told any method's name: the Android framework calls such a reader makes are modelled
          (Context.getApplicationInfo, ApplicationInfo.splitSourceDirs/sourceDir, ZipFile/getEntry/
          getInputStream, InputStream.read*, ByteArrayOutputStream), and the app's reader runs as written,
          so a renamed reader (loadFeature, openSplit, readAsset) or one that transforms the bytes after
          reading is computed exactly. The model is strict: a read of any other ApplicationInfo field
          (targetSdkVersion, flags, uid, ...; named by the dex that runs the iget) and any field read on a
          ZipEntry, InputStream or ByteArrayOutputStream it hands out or constructs declines, never the
          shipped VM's 0 (a ByteArrayOutputStream subclass's protected `count`; review 2 of a291433), and so
          does every call but the constructor on an app subclass of ByteArrayOutputStream (a device would run
          the subclass's own write or toByteArray). Tiers, each needing exactly one code from EVERY ANS entry
          of every dex of the bundle with zero declines (else the next tier; two codes in any tier: WITHHELD):
            A  each dex on its own (its split's .so only), a split asset read through the modelled
               framework (an entry no split of the bundle holds declines: a reader's fallback, a default
               buffer, would compute from bytes the bundle does not show; a miss in one split while
               another holds the entry is null as on a device, and is a reader's loop going on only if
               the same entry run then opens that entry: a miss never made good is a decline):
               `mobile.codec/analysis+split-asset`, route `analysis:dex-chain+split-asset` (judged on Day
               26), and only when every app method that touches a split API (`_touches_split`) the tier's
               runs started has a judged reader's code shape (`JUDGED_READERS`: the SHA-256 of its `_shape`,
               the body's prototype, every opcode, the whole unit of every literal and the framework methods
               and fields it references, and no pool index, so none of its names; today one, Day 26's
               readSplit, the same in the Time Trial and in Mastery set 10; a renamed reader with that body is
               the same computation and keeps the name). A reader of any other shape (written another way, or using
               other modelled calls) goes under `<that key>:reader@shape-<sha256>` (the fingerprint of every
               split-touching shape the runs started), unsure: one option, one probe on a base, and a name
               the judge accepts there answers that shape only (review 2 of a291433: tier A answered PLAIN
               under the judged name for any reader it could execute).
            B  as A, and an app method the VM cannot run (no body anywhere in the bundle, no JNI symbol)
               or whose body touches split APIs and declines, declared `(String) -> byte[]`, called
               with exactly one text naming an asset present in exactly one non-base split (and not in
               the base), answers that asset's bytes: `<A's key>:hooked@shape-<sha256>` (unsure until
               judged). The fingerprint (`_shape`) of a body is its prototype, its instruction stream
               (every opcode, with the literals of const* and binop/lit) and its framework references,
               never a pool index (no name, no string): a variant of the template shares it, and a reader
               written another way (one that transforms what it read) gets another key, so a judged hooked
               name never answers a different reader plain. A bodiless reader shows no behaviour, so its
               fingerprint is its prototype and the SHA-256 of the calling dex: plain only for those bytes.
            C  row 532, across the splits: native symbols merged from every split (x86-64 legs before
               arm64; a symbol with two different legs of its best machine, or two symbols a call could
               match, declines; a run on the arm64 legs that disagrees or declines is None), app methods and
               reflected methods (Class.forName/getMethod/Method.invoke) resolved against every split's
               dex (exactly one body, else a decline), run in a VM bound to the owning dex:
               `mobile.codec/analysis+across-splits` (route `analysis:dex-chain+across-splits`, one
               option, unsure until judged; with B's hook `...:hooked@shape-<sha256>`).
          A tier that answers in a bundle of two or more non-base splits, and whose run read
          splitSourceDirs, is run again with splitSourceDirs in every rotation of the bundle's order and of
          its reversal (`_orders`; every permutation for up to three) and must give the same code with no
          decline each time (a reader that takes a fixed splitSourceDirs[i], the middle one too, rather
          than the one split holding its entry is withheld). Tiers that run out of the step budget:
          withheld (the shipped reader would spend its own budget again on the same chains). No tier, a
          split asset never read, nothing across the splits: the shipped reader's, as before, unless a
          non-base split carries a dex or a native library (then withheld: the shipped reader would see
          the splits merged by member name, a feature's classes.dex shadowed by the base's). Tier A with
          no split asset read hands the bundle back only when no non-base split carries such code; when
          one does, the next tiers read the splits as they are and that rule applies (review 2 of a291433:
          a library in the base and another one in a config split, its JNI method matched by both, went
          back to the shipped reader and was sent PLAIN from the members merged by name).

Every code found is then held against every code in clear (raw and UTF-16) in every member of every
split and in the bundle's own other members, and against what the lane's own second-code look
(codec_search.second_codes, passed in as `look`) finds in each split and in the bundle's own members: a
code under base64 or hex, a puzzle-shaped document moved into a member, a SQLite cell, a keystore secret,
the archives' own bytes (a zip comment). Another code makes the answer unsure under `<key>:second-code`
(this reading first); a bundle past the clear scan's bound is a candidate pick under a key fingerprinted to
this puzzle document. Everything is bounded by sizes, counts and VM steps (TOTAL_STEPS
over all the tiers of one bundle), never by a clock, so a base, its gate replay and a clock agree.
"""
import hashlib
import io
import json
import re
import sys
import zipfile
from collections import namedtuple
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE.parent / "common") not in sys.path:
    sys.path.insert(0, str(HERE.parent / "common"))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import labels  # noqa: E402

PUZZLE = "assets/huntress_puzzle.json"
ANSWER = re.compile(r"ANS-[0-9A-F]{16}")
_ANS_RAW = re.compile(rb"(?<![0-9A-Za-z])ANS-[0-9A-F]{16}(?![0-9A-Za-z])")
_ANS_WIDE = re.compile(rb"A\x00N\x00S\x00-\x00(?:[0-9A-F]\x00){16}")

KEY = "mobile.codec/split+feature"              # judged Day 26: split:by-order+feature
BY = "split:by-order+feature"
TAKE = "split:take-order+feature"
EXTRA = ":extra-fields"
AKEY = "mobile.codec/analysis+split-asset"      # judged Day 26: analysis:dex-chain+split-asset
AROUTE = "analysis:dex-chain+split-asset"
READER = ":reader"                               # tier A beside a reader of a shape the judge has not seen
JUDGED_READERS = frozenset((
    # the SHA-256 of _shape() of each split reader whose tier A reading the judge accepted under AKEY: Day 26's
    # readSplit (Lcom/huntress/mobile/d26/v<hex>/Assets;), the same in the Time Trial and in Mastery set 10
    "b7e2192f84949ba33ca1f8dba609bfb9dbaee4da33cd37bb172d42f9952bd759",
))
HOOKED = ":hooked"
AX_KEY = "mobile.codec/analysis+across-splits"  # row 532: unsure until judged
AX_ROUTE = "analysis:dex-chain+across-splits"
SECOND = ":second-code"
UNSCANNED = ":unscanned"

SPLIT_DOC_FIELDS = frozenset(("schema", "day", "codec", "data", "parts", "order"))
PART_DOC_FIELDS = frozenset(("codec", "day", "feature", "part", "part_index", "schema", "split", "module", "build",
                             "version"))   # Day 26's part document: codec, day, feature, part, part_index
MAX_SPLITS = 16          # splits read from one bundle
MAX_MEMBERS = 512        # members of one split
MAX_MEMBER = 16 << 20    # bytes of one member
MAX_BYTES = 48 << 20     # bytes read from the whole bundle
SCAN_BYTES = 8 << 20     # bytes the clear-code look reads (the Day 26 bundles are about 20 KB)
MAX_ENTRIES = 64         # ANS entries run in one dex (dex_chain_codec.MAX_ENTRIES)
TOTAL_STEPS = 2_500_000  # VM steps of all the tiers of one bundle together (dex_chain_codec.TOTAL_STEPS)
MAX_DEPTH = 24           # nested cross-split VM calls

FRAMEWORK = ("Ljava/", "Ljavax/", "Landroid/", "Landroidx/", "Ldalvik/", "Lkotlin/", "Lkotlinx/",
             "Lcom/android/", "Lcom/google/android/", "Lorg/json/", "Lorg/apache/", "Lsun/", "Llibcore/")
APPINFO = "Landroid/content/pm/ApplicationInfo;"
ZIPFILES = ("Ljava/util/zip/ZipFile;", "Ljava/util/jar/JarFile;")
BAOS = "Ljava/io/ByteArrayOutputStream;"
SPLIT_METHODS = frozenset(("getApplicationInfo", "createContextForSplit", "getAssets", "getSplitNames"))
SPLIT_FIELDS = frozenset(("splitSourceDirs", "splitPublicSourceDirs", "splitNames"))
EM_X86_64, EM_AARCH64 = 62, 183
ABI_RANK = {EM_X86_64: 0, EM_AARCH64: 1}

Bundle = namedtuple("Bundle", "kind splits base doc puzzle outer raws blob", defaults=({}, b""))
#   splits: [(name, {member: bytes})]; outer: the bundle's own other members; raws: {split name: the split's own
#   zip bytes} (an .apks/.xapk member; none for an .aab module); blob: the delivery's bytes (the second-code look
#   scans those archives' own bytes, a zip comment say, as the single-APK look scans the APK's)
Reading = namedtuple("Reading", "answer key route note")       # answer None: WITHHELD (the caller answers None)


def _zip(b):
    try:
        return zipfile.ZipFile(io.BytesIO(b if isinstance(b, bytes) else bytes(b)))
    except Exception:
        return None


def _read_zip(zf, budget):
    """{member: bytes} of a split, or None (encrypted, too big, or two entries of one name)."""
    out = {}
    try:
        infos = [i for i in zf.infolist() if not i.is_dir()]
    except Exception:
        return None
    if len(infos) > MAX_MEMBERS:
        return None
    for i in infos:
        if i.flag_bits & 1 or i.compress_type == 99 or i.file_size > MAX_MEMBER or i.file_size > budget[0]:
            return None
        try:
            body = zf.read(i)
        except Exception:
            return None
        budget[0] -= len(body)
        if i.filename in out:
            return None
        out[i.filename] = body
    return out


_AAB_MOVE = (("manifest/", ""), ("dex/", ""), ("root/", ""))


def _split_names(names):
    """(the *.apk members, the .aab module folders) among a zip's own member names."""
    apks = [n for n in names if n.lower().endswith(".apk")]
    mods = []
    for n in names:
        parts = n.split("/")
        if len(parts) == 3 and parts[1:] == ["manifest", "AndroidManifest.xml"] and parts[0] not in mods:
            mods.append(parts[0])
    return apks, mods


def candidate(blob):
    """Cheap (the central directory only): the delivery's own names could be a split bundle's (two or more
    *.apk members, or two or more .aab module folders) and the puzzle document is not one of them. codec_search
    asks it before solve(), so a delivery that is no bundle reads nothing more; it does not look at what the
    shipped reader kept (an inner APK over its 1 MiB member bound is still a split here). Never raises."""
    try:
        if not isinstance(blob, (bytes, bytearray)) or blob[:2] != b"PK":
            return False
        z = _zip(blob)
        if z is None:
            return False
        names = [i.filename for i in z.infolist() if not i.is_dir()]
        if PUZZLE in names:
            return False
        apks, mods = _split_names(names)
        return len(apks) >= 2 or (not apks and len(mods) >= 2)
    except Exception:
        return False


def bundle(blob):
    """The split bundle the delivery is, or None (not a bundle, unreadable, past a bound, or not exactly
    one puzzle document in it). Never raises."""
    try:
        return _bundle(blob)
    except Exception:
        return None


def _bundle(blob):
    if not isinstance(blob, (bytes, bytearray)) or blob[:2] != b"PK":
        return None
    outer = _zip(blob)
    if outer is None:
        return None
    names = [i.filename for i in outer.infolist() if not i.is_dir()]
    if PUZZLE in names or len(names) != len(set(names)):
        return None
    budget = [MAX_BYTES]
    splits = []
    apks, mods = _split_names(names)
    if apks:
        if len(apks) < 2 or len(apks) > MAX_SPLITS:
            return None    # one package in a zip: the shipped reader's, as before (nothing more is read)
        lower = {n.lower() for n in names}
        kind = "xapk" if "manifest.json" in lower else "apks" if "toc.pb" in lower or len(apks) > 1 else "zip"
        inners, raws = [], {}
        for n in apks:
            info = outer.getinfo(n)
            if info.flag_bits & 1 or info.compress_type == 99 or info.file_size > MAX_MEMBER:
                return None
            raws[n] = outer.read(n)
            inner = _zip(raws[n])
            if inner is None:
                return None
            inners.append((n, inner))
        try:
            if sum(1 for _, z in inners if PUZZLE in z.namelist()) != 1:
                return None    # no document, or two packages' documents: decided from the names, nothing read
        except Exception:
            return None
        for n, inner in inners:
            members = _read_zip(inner, budget)
            if members is None:
                return None
            splits.append((n, members))
    else:
        if len(mods) < 2 or len(mods) > MAX_SPLITS:
            return None    # one module, or none: not a bundle
        kind, raws = "aab", {}
        for mod in mods:
            members = {}
            for n in names:
                if not n.startswith(mod + "/"):
                    continue
                rest = n[len(mod) + 1:]
                for a, b in _AAB_MOVE:
                    if rest.startswith(a):
                        rest = b + rest[len(a):]
                        break
                info = outer.getinfo(n)
                if (info.flag_bits & 1 or info.compress_type == 99 or info.file_size > MAX_MEMBER
                        or info.file_size > budget[0] or rest in members or not rest):
                    return None
                body = outer.read(n)
                budget[0] -= len(body)
                members[rest] = body
            splits.append((mod + ".apk", members))
    holders = [i for i, (_, m) in enumerate(splits) if PUZZLE in m]
    if len(splits) < 2 or len(holders) != 1:
        return None    # one package in a zip, or two packages' documents: the shipped reader's, as before
    base = holders[0]
    if not _one_app(splits, base):
        return None    # a second, whole package beside the app (no `split`, another package): not its splits
    used = set(apks) if apks else {n for n in names if n.split("/", 1)[0] in mods}
    got = _finish(outer, names, used, splits, base, kind, budget)
    return got._replace(raws=raws, blob=bytes(blob)) if got is not None else None


def _manifest_root(members):
    """The root attributes of a split's compiled AndroidManifest.xml, or None when it is not one that reads."""
    body = members.get("AndroidManifest.xml")
    if not isinstance(body, (bytes, bytearray)) or bytes(body[:4]) != b"\x03\x00\x08\x00":
        return None
    try:
        import apk_resources
        els = apk_resources.axml_tree(bytes(body))
    except Exception:
        return None
    if not els or els[0].get("tag") != "manifest" or not isinstance(els[0].get("attrs"), dict):
        return None
    return els[0]["attrs"]


def _one_app(splits, base):
    """False when a non-base member is provably NOT a split of the base's app: its compiled manifest reads and
    names no `split` (a whole package), or names another package than the base's. A manifest that does not
    read (an .aab's protobuf one, none at all) proves nothing either way. Day 26's feature.apk: split
    `arena_feature`, the base's package."""
    root = _manifest_root(splits[base][1])
    package = root.get("package") if root else None
    for i, (_, members) in enumerate(splits):
        if i == base:
            continue
        r = _manifest_root(members)
        if r is None:
            continue
        if not r.get("split") or (package and r.get("package") != package):
            return False
    return True


def _finish(outer, names, used, splits, base, kind, budget):
    """The Bundle: the base's puzzle document, and the bundle's own members beside the splits (`used`)."""
    try:
        doc = json.loads(splits[base][1][PUZZLE].decode("utf-8-sig"))
    except Exception:
        doc = None
    outer_members = {}
    for n in names:
        if n in used:
            continue
        info = outer.getinfo(n)
        if info.flag_bits & 1 or info.compress_type == 99 or info.file_size > MAX_MEMBER or info.file_size > budget[0]:
            return None
        outer_members[n] = outer.read(n)
        budget[0] -= len(outer_members[n])
    return Bundle(kind, splits, base, doc, splits[base][1][PUZZLE], outer_members)


def _json(body):
    try:
        return json.loads(bytes(body).decode("utf-8-sig"))
    except Exception:
        return None


def _codec(doc):
    return str(doc.get("codec")).strip().lower() if isinstance(doc, dict) else ""


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


# ------------------------------------------------------------------------------ codec split + feature

def readings(b):
    """(options, extra, why) for a codec `split` base whose empty parts the non-base splits fill.

    options: [(route, code)], the judged by-order reading first, each an exact code, each value once.
    extra: the document has fields beyond the usual ones. why: '' when the shape is not this one at
    all (no part document anywhere: the caller goes on as before), else the reason nothing is read
    (a part document exists and something does not hold: the caller withholds)."""
    p = b.doc
    if _codec(p) != "split":
        return [], False, ""
    found = []   # (split index, member, part document)
    for si, (_, members) in enumerate(b.splits):
        for m in sorted(members):
            if not (m.startswith("assets/") and m.lower().endswith(".json")) or m == PUZZLE:
                continue
            d = _json(members[m])
            if isinstance(d, dict) and ("part" in d or "part_index" in d):
                found.append((si, m, d))
    if not found:
        return [], False, ""
    parts, order = p.get("parts"), p.get("order")
    if not (isinstance(parts, list) and parts and all(isinstance(x, str) for x in parts)
            and isinstance(order, list) and len(order) == len(parts) and all(_is_int(k) for k in order)
            and sorted(order) == list(range(len(parts)))):
        return [], False, "the document's parts and order are not a list of texts and a permutation"
    if "" not in parts:
        return [], False, "a part document beside a document with no empty part"
    extra = bool(set(p) - SPLIT_DOC_FIELDS) or p.get("data") not in (None, "")
    parts = list(parts)
    filled = {}   # part index -> text; an identical duplicate is order-independent, a differing one is not
    for si, m, d in found:
        where = "%s:%s" % (b.splits[si][0], m)
        if si == b.base:
            return [], extra, "a part document in the base split (%s)" % where
        i, v = d.get("part_index"), d.get("part")
        if not (_is_int(i) and isinstance(v, str) and v and 0 <= i < len(parts)):
            return [], extra, "part document %s has no usable part and part_index" % where
        if d.get("codec") is not None and _codec(d) != "split":
            return [], extra, "part document %s names codec %r" % (where, d.get("codec"))
        if i in filled:
            if filled[i] != v:
                return [], extra, "part document %s writes part %d differently from another split" % (where, i)
            if set(d) - PART_DOC_FIELDS:
                extra = True
            continue
        if parts[i] != "":
            return [], extra, "part document %s writes part %d, which is not an empty part" % (where, i)
        if set(d) - PART_DOC_FIELDS:
            extra = True      # a flag beside the part (decoy, active, use ...): never the judged plain name
        parts[i] = v
        filled[i] = v
    if any(x == "" for x in parts):
        return [], extra, "an empty part is left unfilled"
    by = [None] * len(parts)
    for i, k in enumerate(order):
        by[k] = parts[i]
    take = [parts[k] for k in order]
    out = []
    for name, seq in ((BY, by), (TAKE, take)):
        v = "".join(seq)
        if ANSWER.fullmatch(v) and v not in [x for _, x in out]:
            out.append((name, v))
    return out, extra, "" if out else "no order reading of the filled parts is an answer code"


# ------------------------------------------------------------------------------ dex helpers

def _proto(dex, midx):
    """(return descriptor, [parameter descriptors]) of method_ids[midx], or None."""
    try:
        if not dex.proto_off or not dex.proto_size:
            return None
        pidx = dex._u2(dex.meth_off + midx * 8 + 2)
        if pidx >= dex.proto_size:
            return None
        o = dex.proto_off + pidx * 12
        ret = dex.type_str(dex._u4(o + 4))
        poff = dex._u4(o + 8)
        params = []
        if poff:
            n = dex._u4(poff)
            if n > 255:
                return None
            params = [dex.type_str(dex._u2(poff + 4 + 2 * k)) for k in range(n)]
        return ret, params
    except Exception:
        return None


def _framework(cls):
    return not isinstance(cls, str) or cls.startswith(FRAMEWORK) or cls.startswith("[")


def _refs(D, dex, midx, cache):
    """({(cls, name)} invoked, {(cls, name)} fields) referenced by a method's own body."""
    key = (id(dex), midx)
    if key in cache:
        return cache[key]
    meths, fields = set(), set()
    try:
        insns = dex.code[midx][2]
        i, n = 0, len(insns)
        while i < n:
            op = insns[i] & 0xFF
            if (0x6e <= op <= 0x72 or 0x74 <= op <= 0x78) and i + 1 < n:
                meths.add(dex.meth(insns[i + 1]))
            elif 0x52 <= op <= 0x6d and i + 1 < n:
                f = dex.field(insns[i + 1])
                if f:
                    fields.add(f)
            w = D._W[op]
            if w <= 0:
                break
            i += w
    except Exception:
        pass
    cache[key] = (meths, fields)
    return cache[key]


def _touches_split(D, dex, midx, cache):
    meths, fields = _refs(D, dex, midx, cache)
    return (any(nm in SPLIT_METHODS or (c in ZIPFILES and nm == "<init>")
                or (c == "Landroid/content/res/AssetManager;" and nm == "open") for c, nm in meths)
            or any(nm in SPLIT_FIELDS for _, nm in fields))


_LITERAL_OPS = frozenset(range(0x12, 0x1a)) | frozenset(range(0xd0, 0xe3))   # const*, binop/lit16, binop/lit8


def _dex_fp(dex, cache):
    """The full SHA-256 of a dex's own bytes (cached per dex for one tier's run)."""
    key = ("dex-fp", id(dex))
    if key not in cache:
        try:
            cache[key] = hashlib.sha256(bytes(dex.d)).hexdigest()
        except Exception:
            cache[key] = "unread"
    return cache[key]


def _shape(D, dex, midx, has_body, cache):
    """A token of a hooked reader's shape (tier B's key fingerprint).

    A body: its prototype, its instruction stream (every opcode, and the whole unit of each instruction that
    carries a literal: const*, binop/lit8, binop/lit16) and the framework methods and fields it references. No
    pool index goes in (no app class or method name, no string: a variant of one template renames and re-keys
    those), so the one template's base and variants share it, while a reader written another way (one that
    transforms what it read, or XORs it with another literal) has another fingerprint and so another key: a
    hooked name the judge accepted for one reader never answers a different reader plain.

    A bodiless reader (nothing in the bundle runs it: an interface, a native registered at run time) shows no
    behaviour at all, so nothing observable tells a `readSplitAsset` from a `decryptFeature` of the same
    prototype (review of 9c1f923: every bodiless (String)->byte[] method shared one key). Its fingerprint is the
    prototype and the SHA-256 of the dex that calls it: a hooked name the judge accepts answers plain only for
    those very dex bytes (the base's gate replay, a variant that changes only the asset); any other dex is unsure
    again and costs a probe."""
    pr = _proto(dex, midx)
    if not has_body:
        return "bodiless:%s:dex-%s" % (pr, _dex_fp(dex, cache))
    ops = []
    try:
        insns = dex.code[midx][2]
        i, n = 0, len(insns)
        while i < n:
            op = insns[i] & 0xFF
            w = D._W[op]
            if w > 0 and op in _LITERAL_OPS:
                ops.extend(insns[i:i + w])
            else:
                ops.append(op)
            if w <= 0:
                break
            i += w
    except Exception:
        pass
    meths, fields = _refs(D, dex, midx, cache)
    fw = sorted("%s->%s" % (c, nm) for c, nm in meths if _framework(c))
    fw += sorted("%s.%s" % (c, nm) for c, nm in fields if _framework(c))
    return "body:%s:%s:%s" % (pr, ",".join("%x" % u for u in ops), ",".join(fw))


def _shape_key(key, shapes):
    """`<key>@shape-<sha256>` of a hooked reading: the fingerprint of every reader the hook answered."""
    fp = hashlib.sha256("|".join(sorted(shapes)).encode()).hexdigest()
    return "%s@shape-%s" % (key, fp)


def _reader_key(D, key, worlds):
    """Tier A's key: `key` (the judged AKEY) only when every app method that touches a split API and that a VM
    of the tier's runs (`worlds`: the bundle's order and every other arrangement it was run in) started has a
    judged reader's shape (JUDGED_READERS, the SHA-256 of `_shape`: the body's prototype, opcodes, literals and
    framework references, no name). Otherwise `<key>:reader@shape-<sha256>`, the fingerprint of those shapes, so
    the judged name never answers a reader of another shape plain (review 2 of a291433: tier A answered PLAIN
    under AKEY for any reader it could execute, a renamed one with another body too) and a name the judge
    accepts for one such shape answers that shape alone. A run that read a split with no split-touching method
    started is no judged reader either."""
    cache, shapes = {}, set()
    for w in worlds:
        for (_, midx), dex in w.executed.items():
            if _touches_split(D, dex, midx, cache):
                shapes.add(hashlib.sha256(_shape(D, dex, midx, True, cache).encode()).hexdigest())
    if shapes and shapes <= JUDGED_READERS:
        return key
    return "%s%s@shape-%s" % (key, READER, hashlib.sha256("|".join(sorted(shapes)).encode()).hexdigest())


def _split_code(b):
    """True when a non-base split carries a dex or a native library."""
    return any(m.endswith((".dex", ".so")) for i, (_, ms) in enumerate(b.splits) if i != b.base for m in ms)


def _ans_entries(D, dex):
    """The methods that load an ANS literal (dex_chain_codec.codes_in_dex_ex's discovery)."""
    idx = set()
    try:
        for i in range(dex.str_size):
            t = dex.string(i)
            if t in ("ANS-", "ANS") or (t.startswith("ANS-") and 4 < len(t) <= 12):
                idx.add(i)
    except Exception:
        return []
    return D._entry_midxs(dex, idx) if idx else []


# ------------------------------------------------------------------------------ the world one run sees

SPLIT_DIRS = ("splitSourceDirs", "splitPublicSourceDirs")
BASE_DIRS = ("sourceDir", "publicSourceDir")


class _AppInfoFields(dict):
    """The field store of the one ApplicationInfo a tier's run hands out: only the fields the model sets read.

    The shipped VM reads a field never written as 0 (right for an app's own object, whose Java default it is),
    but an ApplicationInfo on a device carries targetSdkVersion, flags, uid, minSdkVersion, ... (review of
    9c1f923: a reader that XORed the asset with targetSdkVersion was computed with 0 and sent PLAIN). Here a read
    of any field but splitSourceDirs / splitPublicSourceDirs / sourceDir / publicSourceDir declines. A field is
    named by the dex that RUNS the iget (`world.cur`, the innermost VM's dex: field indexes are per dex, and the
    object may be passed to another split's code), and must be a field of ApplicationInfo. A field the app writes
    reads back what it wrote."""

    def __init__(self, world, values):
        dict.__init__(self)
        self._world = world
        self._values = values          # {field name: value}

    def _name(self, k):
        w = self._world
        cur = w.cur[-1] if w.cur else None
        f = cur.field(k) if cur is not None and isinstance(k, int) and not isinstance(k, bool) else None
        if not f or f[0] != APPINFO:
            raise w.D._Decline("ApplicationInfo field %r is not one of its own" % (f,))
        return f[1]

    def get(self, k, default=None):
        name = self._name(k)
        if name not in self._values:
            raise self._world.D._Decline("ApplicationInfo.%s is not modelled" % name)
        if name in SPLIT_DIRS:
            self._world.split_dirs_read = True
        return self._values[name]

    def __getitem__(self, k):
        return self.get(k)

    def __setitem__(self, k, v):
        self._values[self._name(k)] = v

    def __contains__(self, k):
        try:
            return self._name(k) in self._values
        except Exception:
            return False


class _World:
    """What every VM of one tier's run shares: the bundle, the dexes, the merged natives, the
    framework model's tokens and what happened (split reads, hooks, cross-split calls)."""

    def __init__(self, D, b, dexes, mode, natives_by_split, prefer_arm=False, order=None):
        self.D, self.b, self.dexes, self.mode = D, b, dexes, mode   # dexes: [(split index, Dex)]
        self.split_of = {id(dx): si for si, dx in dexes}
        self.index = {}
        for si, dx in dexes:
            for mi, mn in dx.mname.items():
                self.index.setdefault(mn, []).append((dx, mi))
        self.paths = ["/data/app/~~huntress/%s" % n for n, _ in b.splits]
        self.split_reads = self.hooks = self.cross = 0
        self.hook_shapes = set()     # _shape() of every reader B's hook answered
        self.refs = {}
        self.cur = []                # the dex of every VM frame running now, innermost last (_AppInfoFields)
        self.split_dirs_read = False  # an iget of splitSourceDirs: only then can the splits' order matter
        self.missed, self.opened = set(), set()   # per ANS entry run: getEntry misses, entries opened
        self.executed = {}           # {(id(dex), midx): dex} of every app method a VM of this run started (_reader_key)
        self._appinfo = None
        # ApplicationInfo.splitSourceDirs: the non-base splits in the bundle's order, or in another arrangement
        # (`order`, a permutation of their indexes) for the runs that prove the reading does not hang on an order
        # (a device lists them by split name, which the bundle's member order need not be)
        nonbase = [p for i, p in enumerate(self.paths) if i != b.base]
        self._splits = [nonbase[k] for k in order] if order else nonbase
        self.arm_legs = False
        self.natives_by_split = natives_by_split
        self._tables = {}            # natives(): one indexed table per split, or the merged one (so-ambig fix round 2)
        self.merged, self.ambiguous, self.sym_split = {}, set(), {}
        if mode.get("cross"):
            legs = {}
            for si, syms in natives_by_split.items():
                for sym, (em, code) in syms.items():
                    legs.setdefault(sym, []).append((em, code, si))
            for sym, ls in legs.items():
                ranked = sorted((l for l in ls if l[0] in ABI_RANK),
                                key=lambda l: ABI_RANK[l[0]] if not prefer_arm else -ABI_RANK[l[0]])
                if not ranked:
                    em, code, si = ls[0]
                    self.merged[sym] = (em, code)
                    self.sym_split[sym] = si
                    if len({(l[0], l[1]) for l in ls}) > 1:
                        self.ambiguous.add(sym)
                    continue
                if len({l[0] for l in ranked}) > 1:
                    self.arm_legs = True
                best = [l for l in ranked if l[0] == ranked[0][0]]
                if len({l[1] for l in best}) > 1:
                    self.ambiguous.add(sym)
                self.merged[sym] = (best[0][0], best[0][1])
                self.sym_split[sym] = best[0][2]

    def natives(self, dex):
        """The native table a VM of `dex` binds against: the merged one (C) or its split's. Day 27 so-ambig fix round 2
        (the review of 38a1668, perf): built once per world as dex_chain_codec's indexed and memoised _NativeTable
        (VM.__init__ copied and re-indexed a plain dict for every SplitVM, one per ANS entry and per cross-split call:
        3.2 and 15.1 ms a call at 10,000 and 50,000 symbols), carrying the bundle's dexes, over which a native method a
        dex does not declare is resolved (dex_chain_codec._resolve_native)."""
        key = "cross" if self.mode.get("cross") else self.split_of.get(id(dex))
        got = self._tables.get(key)
        if got is None:
            src = self.merged if key == "cross" else self.natives_by_split.get(key, {})
            maker = getattr(self.D, "_NativeTable", None)
            got = maker(src) if maker is not None else src
            if maker is not None:
                got.dexes = [dx for _, dx in self.dexes]
            self._tables[key] = got
        return got

    def appinfo(self, dex):
        """The app's ApplicationInfo: one object for the whole run (a device hands out the same instance), with
        only the split and base paths modelled (_AppInfoFields)."""
        if self._appinfo is None:
            o = self.D._Obj(APPINFO)
            values = {n: list(self._splits) for n in SPLIT_DIRS}
            values.update({n: self.paths[self.b.base] for n in BASE_DIRS})
            o.fields = _AppInfoFields(self, values)
            self._appinfo = o
        return self._appinfo

    def holders(self, name, nonbase_only=True):
        """Split indexes whose members hold `name` (non-base splits only unless told otherwise)."""
        return [i for i, (_, m) in enumerate(self.b.splits)
                if name in m and (not nonbase_only or i != self.b.base)]

    def hook_asset(self, text):
        """(member, bytes) of the asset `text` names when the base does not hold it and every non-base
        copy agrees byte for byte, as `assets/<text>` or as the member name itself; else None.

        Two installed splits may legitimately carry the same density/locale-independent asset.  Their order is
        irrelevant when the bytes are identical, so treating that shape like two *different* copies needlessly
        withholds a deterministic reading.  A differing copy still proves no single value and is refused.
        """
        if not isinstance(text, str) or not text or "\x00" in text:
            return None
        cands = [text] if text.startswith("assets/") else ["assets/" + text.lstrip("/"), text]
        found = []
        for c in dict.fromkeys(cands):
            for i in self.holders(c, nonbase_only=False):
                found.append((i, c))
        if not found or any(i == self.b.base for i, _ in found):
            return None
        bodies = [self.b.splits[i][1][c] for i, c in found]
        if any(body != bodies[0] for body in bodies[1:]):
            return None
        return found[0][1], bodies[0]


_NOT = object()


def _vm_class(D):
    class _ModelFields(dict):
        """The model's own state of a framework object it hands out (a ZipEntry, an InputStream) or constructs (a
        ByteArrayOutputStream): an app's iget on one (an int field index) declines, never reads the shipped VM's
        0. The model keeps its state under its own `__` names, so no int-indexed field of such an object holds
        what a device holds (a ByteArrayOutputStream subclass reading the protected `count`, review 2 of
        a291433: XORed with 0 and sent PLAIN where a device XORs with 16); an int-indexed write is kept and still
        never read back."""

        def get(self, k, default=None):
            if isinstance(k, str):
                return dict.get(self, k, default)
            raise D._Decline("a field read on a modelled framework object")

        def __getitem__(self, k):
            if isinstance(k, str):
                return dict.__getitem__(self, k)
            raise D._Decline("a field read on a modelled framework object")

    def _model_obj(cls, state):
        o = D._Obj(cls)
        o.fields = _ModelFields(state)
        return o

    class SplitVM(D.VM):
        """dex_chain_codec.VM with the Android framework calls a split reader makes modelled, and,
        by mode, B's hook and C's cross-split resolution. Every other call is the shipped VM's."""

        # KB-7 (dex_float.py) keeps its new models out of this VM: it runs on the base VM's semantics (its codes go
        # under this module's keys, with no `+dex-*` suffix; dex_float's reflection tokens are not the _MethTok that
        # _reflect resolves; its static store is per VM, and a cross-split call runs in a VM of its own). One KB-7
        # restriction holds here: a static read declines (the base VM read 0), but for the framework statics dex_float
        # models and a Context-typed static, the VM's stand-in for the app's Context (dex_float.base_sget).
        dex_float_base = True

        def __init__(self, dex, world, depth=0):
            D.VM.__init__(self, dex, world.natives(dex), {})
            self.world = world
            self.depth = depth

        def run(self, midx, args):
            # every frame says which dex runs it, so an iget on the shared ApplicationInfo is named by its own
            # dex's field table (_AppInfoFields); every method started is recorded for tier A's key (_reader_key)
            dfl = getattr(D, "_dfl", None)
            if dfl is not None and hasattr(dfl, "split_body"):
                dfl.split_body(self, midx, args)   # dexfloat-residuals: a boot package's class, a null receiver
            self.world.executed[(id(self.dex), midx)] = self.dex
            cur = self.world.cur
            cur.append(self.dex)
            try:
                return D.VM.run(self, midx, args)
            finally:
                cur.pop()

        # -------------------------------------------------- the framework model
        def _framework_call(self, cls, name, args):
            w = self.world
            if name == "getApplicationInfo" and len(args) == 1:
                return w.appinfo(self.dex)
            if cls in ZIPFILES:
                if name == "<init>":
                    if len(args) != 2 or not isinstance(args[0], D._Obj):
                        raise D._Decline("ZipFile.<init> shape")
                    path = D._as_text(args[1])
                    if path not in w.paths:
                        raise D._Decline("ZipFile over a path that is no split")
                    args[0].fields["__split"] = w.paths.index(path)
                    return None
                z = args[0] if args else None
                if not (isinstance(z, D._Obj) and "__split" in z.fields):
                    raise D._Decline("ZipFile not opened over a split")
                si = z.fields["__split"]
                members = w.b.splits[si][1]
                if name == "getEntry" and len(args) == 2:
                    nm = D._as_text(args[1])
                    if nm is None:
                        raise D._Decline("ZipFile.getEntry name")
                    if nm not in members:
                        if not w.holders(nm, nonbase_only=False):
                            # no split of the bundle holds it: the app would go on down a path the bundle
                            # cannot show (a fallback, a default buffer), so nothing it computes is proven
                            raise D._Decline("entry %r is in no split" % nm)
                        # another split holds it: null, as on a device, and a reader's loop goes on to that one.
                        # The miss is made good only if this entry run then opens that entry (_run_tier): a
                        # reader that misses and falls back to a default buffer computes from bytes the bundle
                        # does not show, though another split holds the name (review of 9c1f923)
                        w.missed.add(nm)
                        return 0
                    if si != w.b.base:
                        holders = w.holders(nm)
                        bodies = [w.b.splits[i][1][nm] for i in holders]
                        if not bodies or any(body != bodies[0] for body in bodies[1:]):
                            raise D._Decline("entry %r is in more than one split with different bytes" % nm)
                    return _model_obj("Ljava/util/zip/ZipEntry;", {"__entry": nm, "__split": si})
                if name == "getInputStream" and len(args) == 2:
                    e = args[1]
                    if not (isinstance(e, D._Obj) and e.fields.get("__split") == si and "__entry" in e.fields):
                        raise D._Decline("ZipFile.getInputStream entry")
                    s = _model_obj("Ljava/io/InputStream;", {"__data": members[e.fields["__entry"]], "__pos": 0})
                    w.opened.add(e.fields["__entry"])
                    if si != w.b.base:
                        w.split_reads += 1
                    return s
                if name == "close" and len(args) == 1:
                    return None
                raise D._Decline("ZipFile.%s" % name)
            if cls == "Ljava/util/zip/ZipEntry;" and args and isinstance(args[0], D._Obj) \
                    and "__entry" in args[0].fields:
                e = args[0]
                if name == "getName" and len(args) == 1:
                    return e.fields["__entry"]
                if name == "getSize" and len(args) == 1:
                    return len(w.b.splits[e.fields["__split"]][1][e.fields["__entry"]])
                raise D._Decline("ZipEntry.%s" % name)
            s = args[0] if args else None
            if isinstance(s, D._Obj) and "__data" in s.fields and isinstance(cls, str) and cls.endswith("InputStream;"):
                data, pos = s.fields["__data"], s.fields["__pos"]
                if name == "close" and len(args) == 1:
                    return None
                if name == "available" and len(args) == 1:
                    return len(data) - pos
                if name == "readAllBytes" and len(args) == 1:
                    s.fields["__pos"] = len(data)
                    return [D._s8(x) for x in data[pos:]]
                if name == "read":
                    if len(args) == 1:
                        if pos >= len(data):
                            return -1
                        s.fields["__pos"] = pos + 1
                        return data[pos]
                    buf = args[1]
                    if not isinstance(buf, list):
                        raise D._Decline("InputStream.read buffer")
                    off, ln = (0, len(buf)) if len(args) == 2 else (args[2], args[3]) if len(args) == 4 else (None, None)
                    if not (_is_int(off) and _is_int(ln)) or off < 0 or ln < 0 or off + ln > len(buf):
                        raise D._Decline("InputStream.read bounds")
                    if ln == 0:
                        return 0
                    if pos >= len(data):
                        return -1
                    chunk = data[pos:pos + ln]
                    for k, x in enumerate(chunk):
                        buf[off + k] = D._s8(x)
                    s.fields["__pos"] = pos + len(chunk)
                    return len(chunk)
                raise D._Decline("InputStream.%s" % name)
            if cls == BAOS and args and isinstance(args[0], D._Obj):
                o = args[0]
                if name == "<init>" and len(args) in (1, 2):
                    # a strict store (_ModelFields): the object's own int-indexed fields (a subclass reading the
                    # protected `count` or `buf`) decline, as on a ZipEntry or an InputStream the model hands out
                    o.fields = _ModelFields(o.fields)
                    o.fields["__buf"] = []
                    return None
                if o.type != BAOS:
                    # an app subclass: a device dispatches this call to the subclass's own override (a write or
                    # toByteArray that transforms the bytes), which the model would skip
                    raise D._Decline("ByteArrayOutputStream.%s on a subclass (%s)" % (name, o.type))
                if "__buf" not in o.fields:
                    raise D._Decline("ByteArrayOutputStream not constructed")
                if name == "write":
                    if len(args) == 2 and _is_int(args[1]):
                        o.fields["__buf"].append(D._s8(args[1] & 0xFF))
                        return None
                    if len(args) == 4 and isinstance(args[1], list) and _is_int(args[2]) and _is_int(args[3]) \
                            and 0 <= args[2] and 0 <= args[3] and args[2] + args[3] <= len(args[1]):
                        o.fields["__buf"].extend(D._s8(x & 0xFF) for x in args[1][args[2]:args[2] + args[3]])
                        return None
                    raise D._Decline("ByteArrayOutputStream.write shape")
                if name == "toByteArray" and len(args) == 1:
                    return list(o.fields["__buf"])
                if name == "size" and len(args) == 1:
                    return len(o.fields["__buf"])
                if name == "close" and len(args) == 1:
                    return None
                raise D._Decline("ByteArrayOutputStream.%s" % name)
            return _NOT

        # -------------------------------------------------- B: the hook
        def _hook(self, dex, midx, args, has_body, probe=False):
            """The asset bytes for a call B may answer, else _NOT (`probe`: only ask, record nothing)."""
            w = self.world
            if not w.mode.get("hook"):
                return _NOT
            cls, name = dex.mname.get(midx) or dex.meth(midx)
            if _framework(cls):
                return _NOT
            pr = _proto(dex, midx)
            if pr is None or pr[0] != "[B" or pr[1] != ["Ljava/lang/String;"]:
                return _NOT
            if has_body:
                if not _touches_split(D, dex, midx, w.refs):
                    return _NOT
            else:
                if any(dx is not dex for dx, _ in w.index.get((cls, name), ())) or self._native_matches(cls, name):
                    return _NOT          # a body in another split, or a JNI symbol: not this hook's
            texts = [D._as_text(a) for a in args if D._as_text(a) is not None]
            if len(texts) != 1:
                return _NOT
            got = w.hook_asset(texts[0])
            if got is None:
                return _NOT
            member, body = got
            if not probe:
                w.opened.add(member)    # the hook's answer stands for opening that entry
            return [D._s8(x) for x in body]

        def _native_matches(self, cls, name):
            want = "_" + name
            # so-ambig fix round 2 (perf): through the table's binding-key index (dex_chain_codec._NativeTable.bucket,
            # the symbols that can end in `want`), not a scan of the whole table per call
            ns = self.native_syms
            pool = ns.bucket(want) if hasattr(ns, "bucket") else ns
            return [s for s in pool
                    if s.endswith(want) and ("native" in str(cls).lower() or "jni" in s.lower() or s.startswith("Java_"))]

        # -------------------------------------------------- running another method
        def _run_in(self, dex, midx, args):
            if self.depth >= MAX_DEPTH:
                raise D._Decline("cross-split call depth")
            if dex is self.dex:
                return self.run(midx, args)
            # dexfloat-residuals (the review's S-C1): the VM keys an object's fields by each dex's own field table, so
            # what another dex's code writes into an object (or a field it reads) is not the field this dex names:
            # an object of the VM's own field store passed to, or returned from, another dex's code declines
            if any(isinstance(a, D._Obj) and type(a.fields) is dict for a in args):
                raise D._Decline("an object passed to another split's dex (its fields are keyed per dex)")
            sub = SplitVM(dex, self.world, self.depth + 1)
            sub.max_steps = max(0, self.max_steps - self.steps)
            try:
                out = sub.run(midx, args)
            finally:
                self.steps += sub.steps
                if self.steps > self.max_steps:
                    raise D._Decline("step budget")
            if isinstance(out, D._Obj) and type(out.fields) is dict:
                raise D._Decline("an object returned from another split's dex (its fields are keyed per dex)")
            return out

        def _call_app(self, dex, midx, args):
            """Run an app method that has a body, with B's hook as the fallback when its body declines."""
            w = self.world
            if w.mode.get("hook") and self._hook(dex, midx, args, True, probe=True) is not _NOT:
                missed, opened = set(w.missed), set(w.opened)
                try:
                    return self._run_in(dex, midx, list(args))
                except D._Decline:
                    # the body's run is discarded (its misses and its opens alike): the hook answers in its place
                    w.missed, w.opened = missed, opened
                    out = self._hook(dex, midx, args, True)
                    self.world.hooks += 1
                    self.world.hook_shapes.add(_shape(D, dex, midx, True, self.world.refs))
                    return out
            return self._run_in(dex, midx, args)

        def _reflect(self, args):
            mt = args[0] if args else None
            if not isinstance(mt, D._MethTok) or mt.desc is None or mt.name is None:
                raise D._Decline("reflect target unresolved")
            w = self.world
            pool = w.index.get((mt.desc, mt.name), ())
            if not w.mode.get("cross"):
                pool = [(dx, mi) for dx, mi in pool if dx is self.dex]
            hits = [(dx, mi) for dx, mi in pool if mi in dx.code]
            if len(hits) != 1:
                raise D._Decline("reflect %s->%s resolved %d times" % (mt.desc, mt.name, len(hits)))
            dx, mi = hits[0]
            dfl = getattr(D, "_dfl", None)
            if dfl is not None and hasattr(dfl, "split_reflect_access"):
                dfl.split_reflect_access(self, dx, mi)   # dexfloat-residuals: Method.invoke's access check
            arr = args[2] if len(args) > 2 else None
            frame = []
            if isinstance(arr, list):
                for el in arr:
                    if isinstance(el, D._Box):
                        frame.append(el.v & D.M64 if el.t in ("J", "D") else el.v)
                        if el.t in ("J", "D"):
                            frame.append(0)
                    elif _is_int(el) or el is None:
                        frame.append(el)
                    elif D._as_text(el) is not None:
                        frame.append(D._as_text(el))
                    else:
                        raise D._Decline("reflect arg type")
            if len(frame) != dx.code[mi][1]:
                raise D._Decline("reflect frame of %d for %d argument registers" % (len(frame), dx.code[mi][1]))
            if dx is not self.dex:
                w.cross += 1
            out = self._call_app(dx, mi, frame)
            if _is_int(out):
                return D._Box("J", out & D.M64)
            return out

        def _invoke(self, op, midx, args):
            dex = self.dex
            cls, name = dex.mname.get(midx) or dex.meth(midx)
            if midx not in dex.code:     # a framework method: no body in the app's dex
                got = self._framework_call(cls, name, args)
                if got is not _NOT:
                    return got
            w = self.world
            if cls == "Ljava/lang/reflect/Method;" and name == "invoke":
                return self._reflect(args)
            if midx in dex.code:
                return self._call_app(dex, midx, args)
            if not _framework(cls):
                matches = self._native_matches(cls, name)
                if w.mode.get("cross"):
                    hits = [(dx, mi) for dx, mi in w.index.get((cls, name), ()) if dx is not dex and mi in dx.code]
                    shorty = dex.meth_shorty(midx)
                    if shorty is not None:
                        hits = [(dx, mi) for dx, mi in hits if dx.meth_shorty(mi) in (None, shorty)]
                    if hits:
                        if len(hits) != 1 or matches:
                            raise D._Decline("%s->%s: %d bodies and %d symbols across the splits"
                                             % (cls, name, len(hits), len(matches)))
                        w.cross += 1
                        return self._call_app(hits[0][0], hits[0][1], args)
                if matches:
                    if len(matches) != 1 or matches[0] in w.ambiguous:
                        raise D._Decline("native %s: %d symbols, or legs that differ" % (name, len(matches)))
                    if w.mode.get("cross") and w.sym_split.get(matches[0]) != w.split_of.get(id(dex)):
                        w.cross += 1
                else:
                    hooked = self._hook(dex, midx, args, False)
                    if hooked is not _NOT:
                        w.hooks += 1
                        w.hook_shapes.add(_shape(D, dex, midx, False, w.refs))
                        return hooked
            return D.VM._invoke(self, op, midx, args)

    return SplitVM


def _natives(D, b):
    out = {}
    for si, (_, members) in enumerate(b.splits):
        syms = {}
        for m, body in members.items():
            if m.endswith(".so"):
                try:
                    for sym, leg in D._parse_so(body).items():
                        if sym in syms and syms[sym] != leg:
                            syms[sym] = None          # two legs of one symbol in one split
                        elif sym not in syms:
                            syms[sym] = leg
                except Exception:
                    pass
        out[si] = {s: l for s, l in syms.items() if l is not None}
    return out


def _dexes(D, b):
    out = []
    for si, (_, members) in enumerate(b.splits):
        for m in sorted(members, key=lambda k: (k != "classes.dex", k)):
            if m.endswith(".dex") and members[m][:4] == b"dex\n":
                try:
                    out.append((si, D.Dex(members[m])))
                except Exception:
                    return None
    return out


def _run_tier(D, b, dexes, natives, mode, budget, prefer_arm=False, order=None):
    """(codes, declines, world) of one tier: every ANS entry of every dex, each in a fresh VM.

    An entry run that missed an entry in a split (getEntry null because another split holds it) and never
    opened that entry afterwards is a decline: the miss was not a loop step but a fallback (review of
    9c1f923: a reader that read one split, missed the next name and returned `new byte[8]` gave a plain
    ANS-0000000000000000)."""
    SplitVM = _vm_class(D)
    world = _World(D, b, dexes, mode, natives, prefer_arm, order)
    codes, declines = [], 0
    for _, dx in dexes:
        entries = _ans_entries(D, dx)
        declines += max(0, len(entries) - MAX_ENTRIES)
        for e in entries[:MAX_ENTRIES]:
            if budget[0] <= 0:
                declines += 1
                continue
            world.missed, world.opened = set(), set()
            vm = SplitVM(dx, world)
            vm.max_steps = min(vm.max_steps, budget[0])
            try:
                out = vm.run(e, [None] * dx.code[e][1])
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException:
                budget[0] -= vm.steps
                declines += 1
                continue
            budget[0] -= vm.steps
            if world.missed - world.opened:
                declines += 1
                continue
            if isinstance(out, str) and ANSWER.fullmatch(out):
                if out not in codes:
                    codes.append(out)
            else:
                declines += 1
    return codes, declines, world


def _orders(n):
    """The other arrangements of n non-base splits a reading is proven against: every rotation of the bundle's
    order and of its reversal (the dihedral group; for n <= 3 that is every permutation). Each moves every index
    to every split, so a reader that takes a fixed splitSourceDirs[i] (the middle one too, which a reversal
    alone leaves in place: review of 9c1f923), or mixes in the index it found its entry at, gives another
    reading or a decline in one of them."""
    base = list(range(n))
    seen, out = {tuple(base)}, []
    for seq in (base, base[::-1]):
        for r in range(n):
            p = tuple(seq[r:] + seq[:r])
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out


def analysis(b):
    """(code, key, route, why) of a codec `analysis` bundle's dex chain read across its splits.

    code None with why '' : not this module's (nothing split-shaped happened): the caller goes on.
    code None with a why  : two different codes, or a cross-split reading that is not proven: withheld."""
    if _codec(b.doc) != "analysis":
        return None, None, None, ""
    try:
        import dex_chain_codec as D
    except Exception:
        return None, None, None, ""
    dexes = _dexes(D, b)
    if not dexes:
        return None, None, None, ""
    natives = _natives(D, b)
    budget = [TOTAL_STEPS]
    tiers = (("A", {}, AKEY, AROUTE), ("B", {"hook": True}, AKEY + HOOKED, AROUTE + HOOKED),
             ("C", {"cross": True}, AX_KEY, AX_ROUTE), ("C+B", {"cross": True, "hook": True}, AX_KEY + HOOKED,
                                                         AX_ROUTE + HOOKED))
    nonbase = sum(1 for i in range(len(b.splits)) if i != b.base)
    for tier, mode, key, route in tiers:
        if budget[0] <= 0:
            break
        before = budget[0]
        codes, declines, world = _run_tier(D, b, dexes, natives, mode, budget)
        if len(codes) > 1:
            return None, None, None, "tier %s: the dex chains give %d different codes (%s)" % (
                tier, len(codes), ", ".join(codes[:4]))
        if len(codes) != 1 or declines:
            continue
        if tier == "A" and not world.split_reads:
            if not _split_code(b):
                return None, None, None, ""      # no split was read: the shipped analysis reader's
            # no split was read, but a non-base split carries a dex or a native library: the shipped reader would see
            # it merged by member name with the base's own (a split's libarena.so beside the base's, both matching
            # the JNI method), so the next tiers read the splits as they are, and when none proves one code the
            # rule after the loop withholds (review 2 of a291433: x17c went back to the shipped reader, PLAIN)
            continue
        if tier.endswith("B") and not world.hooks:
            continue
        if tier.startswith("C") and not (world.cross or world.split_reads or world.hooks):
            return None, None, None, ""
        if tier.startswith("C") and world.arm_legs:
            # so-ambig fix round 1 (the review's minor finding): the arm64 re-run has an allowance of its own, what this
            # tier's x86-64 run spent and as much again; drawn from the shared budget, it ran out after a long chain and
            # withheld (a budget decline) where the x86-64 legs had answered
            allowance = [min(TOTAL_STEPS, 2 * max(0, before - budget[0]) + 10000)]
            alt, alt_declines, _ = _run_tier(D, b, dexes, natives, mode, allowance, prefer_arm=True)
            if alt != codes or alt_declines:
                # so-ambig round 2 (dex_chain_codec._native_multi, the shipped reader's rule for one APK): the arm64
                # legs must give the same one code with no decline; an arm64 leg that does not run proves nothing
                return None, None, None, "the arm64 legs give %s where the x86-64 legs give %s" % (
                    alt or "a decline", codes)
        runs = [world]
        if nonbase > 1 and world.split_dirs_read:
            # the same tier with splitSourceDirs in every other arrangement of _orders must give the same one
            # code with no decline: a reader that takes a fixed splitSourceDirs[i] rather than the one split
            # holding its entry is withheld. A run that never read splitSourceDirs cannot hang on the order
            # (the paths are reached through it alone; the hook and the cross-split resolution go by name).
            for order in _orders(nonbase):
                again, again_declines, again_world = _run_tier(D, b, dexes, natives, mode, budget, order=order)
                if again != codes or again_declines:
                    return None, None, None, ("tier %s: the reading changes with the order of the splits "
                                              "(%s, then %s with splitSourceDirs arranged %s)"
                                              % (tier, codes, again or "a decline", list(order)))
                runs.append(again_world)
        if tier == "A":
            key = _reader_key(D, key, runs)            # the judged name only for a judged reader's shape
        if tier.endswith("B"):
            key = _shape_key(key, world.hook_shapes)   # a judged hooked name answers only this reader's shape
        return codes[0], key, route, ""
    if budget[0] <= 0:
        # the tiers ran out of the step budget: the shipped dex reader would spend its own budget again on the same
        # chains (review of 9c1f923: 3.1 s here, then the shipped path's), and a code it finds on the members merged
        # by name is a view of the app no tier here could prove: withheld
        return None, None, None, "the dex chains ran past the %d-step budget of the split reading" % TOTAL_STEPS
    if _split_code(b):
        # the shipped reader would see the base's dex and natives merged with the others' by first name only
        # (a feature's classes.dex is shadowed), a view of the app no tier here could prove: withheld
        return None, None, None, "no tier proves one code, and a non-base split carries code (dex or native)"
    return None, None, None, ""


# ------------------------------------------------------------------------------ the clear-code look

def clear_codes(b):
    """([(place, code)], complete): every code in clear (raw or UTF-16) in every member of every split, and in
    the bundle's own other members (a readme, the .xapk manifest.json, the .aab's BundleConfig)."""
    out, read, complete = [], 0, True
    for name, members in list(b.splits) + [("bundle", b.outer)]:
        for m in sorted(members):
            body = members[m]
            if read + len(body) > SCAN_BYTES:
                complete = False
                continue
            read += len(body)
            for rx in (_ANS_RAW, _ANS_WIDE):
                for hit in rx.finditer(body):
                    code = hit.group(0).replace(b"\x00", b"").decode("ascii")
                    place = "apk-string:%s/%s" % (name, m)
                    if (place, code) not in out:
                        out.append((place, code))
    return out, complete


def looked_codes(b, look, value):
    """[(name, code)] the lane's own second-code look finds in every split and in the bundle's own members.

    `look(members, value, blob)` is codec_search's (`split_look`, over `second_codes`): what it finds beside a
    single APK's answer (a code under base64 or hex in a member's bytes, a puzzle-shaped document moved into a
    member, a SQLite cell, a keystore secret, a code in the archive's own bytes: a zip comment), run on each
    split's members with that split's own zip bytes, and on the bundle's own members with the delivery's bytes.
    Review of 9c1f923: the split path scanned only raw and UTF-16LE text, so a decoy under base64 or hex, or a
    document moved into a feature asset, left the bundle PLAIN where the same decoy beside one APK made it unsure.
    Bounded by the look's own sizes, never by a clock; a look that raises adds nothing."""
    out = []
    if look is None:
        return out
    for name, members in list(b.splits) + [("bundle", b.outer)]:
        blob = b.blob if name == "bundle" else (b.raws or {}).get(name, b"")
        try:
            found = look(members, value, blob)
        except Exception:
            continue
        for nm, code, _where in found or ():
            if isinstance(code, str) and ANSWER.fullmatch(code) and code != value:
                out.append(("%s@%s" % (nm, name), code))
    return out


def _offer(b, key, options, note, look=None):
    """labels.pick(key, options), unless a code in clear (or found by the lane's second-code look,
    `looked_codes`) elsewhere in the bundle differs (then unsure under <key>:second-code, this reading
    first) or the clear look was not complete (a candidate pick under a key fingerprinted to this puzzle
    document)."""
    values = {v for _, v in options}
    seen, complete = clear_codes(b)
    seen += looked_codes(b, look, options[0][1]) if options else []
    others = [(p, c) for p, c in seen if c not in values]
    if others:
        note["other_codes"] = ["%s in %s" % (c, p) for p, c in others][:8]
        opts = list(options)
        for p, c in others:
            if c not in [v for _, v in opts]:
                opts.append((p, c))
        k = key + SECOND
        return labels.pick(k, opts[:12]), k
    if not complete:
        note["split_unscanned"] = "past the %d-byte clear-code look: a candidate pick for this document" % SCAN_BYTES
        k = "%s%s@doc-%s" % (key, UNSCANNED, hashlib.sha256(bytes(b.puzzle)).hexdigest())
        return labels.candidates(k, list(options)), k + labels.CANDIDATE_MARK
    return labels.pick(key, list(options)), key


def solve(blob, look=None):
    """Reading(answer, key, route, note) for a split bundle this module reads, else None.

    answer None in a Reading means WITHHELD: the bundle is this module's shape and something did not
    hold, so the caller answers None rather than read the base split alone. `look` is the lane's
    second-code look (codec_search.split_look; `looked_codes`), None for the clear scan alone."""
    b = bundle(blob)
    if b is None:
        return None
    note = {"split_bundle": b.kind, "splits": [n for n, _ in b.splits][:MAX_SPLITS],
            "base": b.splits[b.base][0], "codec": _codec(b.doc)}
    codec = _codec(b.doc)
    if codec == "split":
        opts, extra, why = readings(b)
        if not opts:
            if not why:
                return None
            note["why"] = why
            return Reading(None, None, "split bundle: %s" % why, note)
        key = KEY + (EXTRA if extra else "")
        answer, key = _offer(b, key, opts, note, look)
        note["options"] = [n for n, _ in opts]
        return Reading(answer, key, opts[0][0], note)
    if codec == "analysis":
        code, key, route, why = analysis(b)
        if code is None:
            if not why:
                return None
            note["why"] = why
            return Reading(None, None, "split bundle: %s" % why, note)
        answer, key = _offer(b, key, [(route, code)], note, look)
        return Reading(answer, key, route, note)
    return None
