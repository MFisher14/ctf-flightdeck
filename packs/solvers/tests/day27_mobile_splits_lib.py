#!/usr/bin/env python3
"""Fixture builder for the Day 27 Mobile split look-ahead (backlog row 533).

Day 26 delivered the lane's first `.apks` split bundle (base.apk + feature.apk). Two judged readings came out of it
(`mobile.codec/split+feature`, `mobile.codec/analysis+split-asset`); both were live fixes, folded into the shipped
solver (solvers/mobile-android/split_bundle.py). This file builds the neighbours of those two readings from
SYNTHETIC packages of the same shapes (tests/day27_mobile_splits_synth.py builds them at test time: a split-document
base and its feature split, two apps whose dex chain reads a split asset through the judged reader's code shape, a
gated and a straight-line JNI app with their libarena.so, a reflection app; R-04 replaced the real deliveries this
file first used) and gives every case a TRUTH that no solver produced:

  * a split document: the pieces and the order are chosen here, so the answer is known by construction;
  * a dex chain that reads a split asset: tests/day27_mobile_splits_ref.py (androguard + its own small runtime)
    computes it; the synthetic apps' own answers come from the chain spec they were built from (the tests hold the
    reference runtime to that oracle);
  * a Day 25-shaped APK re-packaged across splits: that app's own answer, because the chain is unchanged by where its
    dex or library sits.

Case classes (`fold`), what a solver WITH the Day 26 fold must give; the base tree (no fold) may give less, never a
wrong plain answer:
  plain    plain, equal to the truth (a judged shape: the split document filled from feature assets, the Day 26 chain
           with its reader under the same name)
  unsure   an unsure pick with the truth FIRST (a new route; a correct plain is tolerated and reported)
  none     None (a decoy: the bytes name no single answer)
  safe     anything but a wrong plain answer (an interpretation the bytes leave open, or a container no day delivered)
"""
import hashlib
import io
import json
import random
import re
import struct
import zipfile
import zlib
from dataclasses import dataclass, field

import day27_mobile_splits_synth as SYNTH

PUZZLE = "assets/huntress_puzzle.json"
SCHEMA_V1 = "huntress.mobile.puzzle.v1"
ANS = re.compile(r"ANS-[0-9A-F]{16}")
# The one known gap this look-ahead found (x17, x17b, x17c: two different libarena.so of one delivery bound one JNI
# method and the plain answer came from whichever body the delivery listed first or last) is closed by so-ambig
# (dex_chain_codec._so_ambiguous): those cases carry must="none" now, a required outcome in every mode, and no `gap`.
SO_AMBIG = "so-ambig: a JNI method two different libraries bind differently is ambiguous, so the call declines"


def fx(name):
    """A synthetic package by its fixture name (d26_base.base.apk, d26_tt.feature.apk, d25_set6_native.apk, ...)."""
    return SYNTH.fixture(name)


def truths():
    """{tag: {"answer": ...}} of the synthetic packages, known by construction."""
    return SYNTH.truths()


def code_for(tag):
    return "ANS-" + hashlib.sha256(("day27-splits:" + tag).encode()).hexdigest()[:16].upper()


# ------------------------------------------------------------------ zip helpers
def zread(b):
    z = zipfile.ZipFile(io.BytesIO(b))
    return [(i.filename, z.read(i.filename)) for i in z.infolist() if not i.is_dir()]


def zwrite(members):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members:
            zi = zipfile.ZipInfo(name, date_time=(2026, 10, 26, 9, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            z.writestr(zi, data)
    return out.getvalue()


def edit(apk, replace=None, drop=(), add=()):
    """A copy of an APK/zip with members replaced (name -> bytes), dropped, or appended."""
    replace = dict(replace or {})
    out = []
    for n, d in zread(apk):
        if n in drop:
            continue
        out.append((n, replace.pop(n, d)))
    assert not replace, "replace names not in the archive: %r" % (list(replace),)
    return zwrite(out + list(add))


def member(apk, name):
    return dict(zread(apk))[name]


def bundle(base, splits):
    """An .apks: base.apk first, then the splits in the order given: [(file name, apk bytes)]."""
    return zwrite([("base.apk", base)] + [(n, b) for n, b in splits])


def split_apk(members, like="d26_base.feature.apk"):
    """A split APK: the Day 26-shaped feature split's manifest and META-INF around the given members."""
    keep = [(n, d) for n, d in zread(fx(like)) if n == "AndroidManifest.xml" or n.startswith("META-INF/")]
    return zwrite([keep[0]] + list(members) + keep[1:])


# ------------------------------------------------------------------ dex
def patch_dex(dex, repl):
    """Same-length renames of dex strings (uleb length byte + MUTF-8 + NUL), then a valid checksum and signature."""
    b = bytearray(dex)
    for old, new in repl.items():
        old, new = old.encode(), new.encode()
        assert len(old) == len(new) < 128, (old, new)
        pat = bytes([len(old)]) + old + b"\0"
        assert bytes(b).count(pat) == 1, "string %r must occur once in the string data" % old
        i = bytes(b).index(pat)
        b[i + 1:i + 1 + len(new)] = new
    b[12:32] = hashlib.sha1(bytes(b[32:])).digest()
    b[8:12] = struct.pack("<I", zlib.adler32(bytes(b[12:])) & 0xFFFFFFFF)
    return bytes(b)


# ------------------------------------------------------------------ split documents
def split_doc(parts, order, codec="split"):
    return json.dumps({"schema": SCHEMA_V1, "day": 26, "codec": codec, "data": "", "parts": parts, "order": order},
                      separators=(",", ":")).encode()


def feature_doc(part, index, feature="arena_feature"):
    return json.dumps({"codec": "split", "day": 26, "feature": feature, "part": part, "part_index": index},
                      separators=(",", ":"), sort_keys=True).encode()


def cut(code, lens):
    assert sum(lens) == len(code), (lens, code)
    out, i = [], 0
    for n in lens:
        out.append(code[i:i + n])
        i += n
    return out


def layout(code, lens, order):
    """(parts, sequence): `sequence` is the code cut in reading order; parts[i] = sequence[order[i]], so the judged
    by-order arrangement (by[order[i]] = parts[i]) restores the code."""
    seq = cut(code, lens)
    assert sorted(order) == list(range(len(seq)))
    return [seq[o] for o in order], seq


def by_order(parts, order):
    by = [None] * len(parts)
    for i, k in enumerate(order):
        by[k] = parts[i]
    return "".join(by)


def take_order(parts, order):
    return "".join(parts[k] for k in order)


def base_apk_with_doc(doc, like="d26_base.base.apk"):
    return edit(fx(like), replace={PUZZLE: doc})


@dataclass
class Case:
    name: str
    family: str          # a, b, c, d, x (decoy), ctl (control)
    blob: bytes
    delivery_name: str
    truth: object        # the answer, or None when the bytes name no single answer
    fold: str            # plain | unsure | none | safe
    note: str = ""
    plain_ok: frozenset = field(default_factory=frozenset)
    gap: str = ""        # a KNOWN wrong-plain gap of the shipped solver, reported by the test (XFAIL unless HUNTRESS_SPLIT_GAPS=fail)
    must: str = ""       # a REQUIRED outcome in every mode, fold or not: "none" = the answer must be None

    def __post_init__(self):
        if self.truth and not self.plain_ok:
            self.plain_ok = frozenset({self.truth})


def _split_case(name, family, code, lens, order, empties, feats, fold="plain", note="", extra_base=None, truth=None,
                like_base="d26_base.base.apk"):
    """A split document over `code`; parts at `empties` are blank in the base and carried by feature splits `feats`:
    [(apk file name, [(asset name, part index), ...])]."""
    parts, seq = layout(code, lens, order)
    shown = ["" if i in empties else p for i, p in enumerate(parts)]
    base = base_apk_with_doc(split_doc(shown, order), like_base)
    splits = []
    for fname, assets in feats:
        mem = [("assets/" + a, feature_doc(parts[i], i)) for a, i in assets]
        splits.append((fname, split_apk(mem)))
    assert by_order(parts, order) == code
    return Case(name, family, bundle(base, splits), name + ".apks", truth if truth is not None else code, fold, note)


def _rand_bin(tag, n=16):
    return bytes(random.Random("day27:" + tag).randrange(256) for _ in range(n))


def build_cases():
    T = truths()
    cases = []
    add = cases.append

    # ============================== (a) split document, empty parts filled from feature assets
    add(Case("a1-day26-base", "a", fx_bundle("d26_base"), "split_decision.apks", T["d26_base"]["answer"], "plain",
             "the Day 26-shaped base bundle as built (judged reading: split:by-order+feature)"))
    add(_split_case("a2-one-empty-part", "a", code_for("a2"), [4, 5, 6, 5], [3, 0, 2, 1], {2},
                    [("feature.apk", [("huntress_feature.json", 2)])]))
    add(_split_case("a3-two-empty-parts-one-split", "a", code_for("a3"), [7, 6, 7], [2, 0, 1], {0, 2},
                    [("feature.apk", [("huntress_feature_a.json", 2), ("huntress_feature_b.json", 0)])],
                    note="two assets of one split, listed in reverse part_index order"))
    # both readings of the order produce a valid ANS code: only the judged by-order one is the truth
    lens, order = [6, 4, 5, 5], [0, 2, 3, 1]
    code = code_for("a4")
    parts, _ = layout(code, lens, order)
    assert ANS.fullmatch(by_order(parts, order)) and ANS.fullmatch(take_order(parts, order))
    assert by_order(parts, order) != take_order(parts, order)
    add(_split_case("a4-both-readings-valid", "a", code, lens, order, {1, 3},
                    [("feature.apk", [("huntress_feature.json", 1), ("huntress_part2.json", 3)])],
                    note="by-order and take-order both give a well-formed ANS code; the judged reading is by-order"))
    add(_split_case("a5-empty-first-part", "a", code_for("a5"), [3, 8, 9], [1, 2, 0], {0, 1, 2},
                    [("feature.apk", [("huntress_feature.json", 1)]), ("config.xxhdpi.apk", [("huntress_feature.json", 0)]),
                     ("config.en.apk", [("huntress_feature.json", 2)])],
                    note="every part empty in the base, three splits each with a same-named asset (a lane-contract stretch of the Day 26 shape)",
                    fold="safe"))

    # ============================== (c) multi-split bundles: 2+ config splits, 2+ empty parts
    add(_split_case("c1-two-config-splits", "c", code_for("c1"), [4, 3, 4, 5, 4], [3, 1, 4, 0, 2], {0, 2, 4},
                    [("config.arm64_v8a.apk", [("huntress_feature.json", 2)]),
                     ("config.xxhdpi.apk", [("huntress_feature.json", 0), ("huntress_feature_b.json", 4)])],
                    note="the same asset name in two splits with different part_index values"))
    code6 = code_for("c2")
    c2 = _split_case("c2-three-splits-noise", "c", code6, [4, 3, 3, 3, 4, 3], [5, 2, 0, 4, 1, 3], {1, 3, 4, 5},
                     [("feature.apk", [("huntress_feature.json", 1)]),
                      ("config.en.apk", [("locale/huntress_part.json", 3)]),
                      ("config.arm64_v8a.apk", [("huntress_feature.json", 4), ("huntress_feature_z.json", 5)])])
    # add two harmless assets that carry no part (a locale table and a binary blob) into config.en
    inner = dict(zread(c2.blob))
    en = edit(inner["config.en.apk"], add=[("assets/strings.json", b'{"hello":"world"}'),
                                           ("assets/blob.bin", _rand_bin("c2blob", 64))])
    c2.blob = zwrite([(n, en if n == "config.en.apk" else d) for n, d in zread(c2.blob)])
    c2.note = "three splits, four empty parts, plus an unrelated JSON asset and a binary blob"
    add(c2)

    # ============================== (b) analysis dex chain reading a split asset
    tt_base, tt_feat = fx("d26_tt.base.apk"), fx("d26_tt.feature.apk")
    m10_base, m10_feat = fx("d26_m10.base.apk"), fx("d26_m10.feature.apk")
    bin_name = "assets/huntress_feature.bin"
    add(Case("b1-day26-time-trial", "b", fx_bundle("d26_tt"), "split_decision_time_trial.apks", T["d26_tt"]["answer"],
             "plain", "the Day 26 Time Trial-shaped bundle as built (judged reading: analysis:dex-chain+split-asset)"))
    add(Case("b2-day26-mastery-10", "b", fx_bundle("d26_m10"), "split_decision_mastery_10.apks",
             T["d26_m10"]["answer"], "plain",
             "the Day 26 Mastery set 10-shaped bundle: the same reader in another app"))
    for tag, base, feat in (("tt", tt_base, tt_feat), ("m10", m10_base, m10_feat)):
        nb = _rand_bin("b3" + tag)
        feat2 = edit(feat, replace={bin_name: nb})
        add(_dex_case("b3-%s-dex-fresh-asset" % tag, "b", base, [("feature.apk", feat2)], "plain",
                      "the %s dex with a fresh 16-byte feature asset" % tag))
    for newname in ("readXplit", "loadSplit", "pullAsset"):
        base2 = edit(tt_base, replace={"classes.dex": patch_dex(member(tt_base, "classes.dex"), {"readSplit": newname})})
        c = _dex_case("b4-reader-renamed-" + newname, "b", base2, [("feature.apk", tt_feat)], "unsure",
                      "the reader method renamed (same bytecode); truth = the Time Trial app's answer")
        assert c.truth == T["d26_tt"]["answer"]
        add(c)
    renamed_asset = patch_dex(member(tt_base, "classes.dex"), {"huntress_feature.bin": "huntress_payload.bin"})
    add(_dex_case("b5-asset-renamed", "b", edit(tt_base, replace={"classes.dex": renamed_asset}),
                  [("feature.apk", edit(tt_feat, drop=[bin_name], add=[("assets/huntress_payload.bin", _rand_bin("b5"))]))],
                  "plain", "reader unchanged, the asset (dex string and member) renamed, fresh bytes"))
    add(_dex_case("b6-asset-in-config-split", "b", tt_base,
                  [("feature.apk", edit(tt_feat, drop=[bin_name])),
                   ("config.arm64_v8a.apk", split_apk([(bin_name, _rand_bin("b6"))],
                                                        like="d26_tt.feature.apk"))],
                  "plain", "the asset sits in a config split, the feature split has none"))
    # ---- decoys and interpretations of the same chain
    other = _rand_bin("b7-other")
    add(_dex_case("b7-asset-in-two-splits-different", "b", tt_base,
                  [("feature.apk", tt_feat),
                   ("config.arm64_v8a.apk", split_apk([(bin_name, other)], like="d26_tt.feature.apk"))],
                  "none", "the asset in two splits with different bytes: which split the runtime reads first is not in the bytes",
                  ambiguous=True))
    add(_dex_case("b7b-asset-in-two-splits-identical", "b", tt_base,
                  [("feature.apk", tt_feat),
                   ("config.arm64_v8a.apk", split_apk([(bin_name, member(tt_feat, bin_name))],
                                                        like="d26_tt.feature.apk"))],
                  "safe", "the same asset bytes in two splits: one answer whatever the order"))
    add(_dex_case("b8-asset-in-base-and-feature", "b", edit(tt_base, add=[(bin_name, _rand_bin("b8-base"))]),
                  [("feature.apk", tt_feat)], "safe",
                  "a different copy of the asset in the BASE split too: splitSourceDirs lists no base split, the feature copy is read"))
    add(_dex_case("b9-short-asset", "b", tt_base, [("feature.apk", edit(tt_feat, replace={bin_name: _rand_bin("b9", 10)}))],
                  "safe", "10-byte asset: the 16-byte buffer keeps zeros for the rest (truth is the runtime's)"))
    add(_dex_case("b10-long-asset", "b", tt_base, [("feature.apk", edit(tt_feat, replace={bin_name: _rand_bin("b10", 40)}))],
                  "safe", "40-byte asset: the chain reads the first 16"))
    add(_dex_case("b10b-empty-asset", "b", tt_base, [("feature.apk", edit(tt_feat, replace={bin_name: b""}))],
                  "safe", "a zero-byte asset: the buffer stays zeros (truth is the runtime's)"))
    add(Case("b11-base-only-no-feature", "x", bundle(tt_base, []), "base_only.apks", None, "none",
             "the analysis base with no feature split: the reader would throw FileNotFoundException"))
    add(Case("b12-dex-in-no-split-bin-missing", "x", bundle(tt_base, [("feature.apk", edit(tt_feat, drop=[bin_name]))]),
             "no_asset.apks", None, "none", "the feature split does not carry the asset the chain asks for"))

    # ============================== (d) cross-split native and reflection
    n_apk, r_apk = fx("d25_set6_native.apk"), fx("d25_set7_reflection.apk")
    so_name = "lib/x86_64/libarena.so"
    so = member(n_apk, so_name)
    n_base = edit(n_apk, drop=[so_name])
    cfg = lambda: split_apk([(so_name, so)])
    add(Case("d0-control-day25-native-unsplit", "ctl", n_apk, "integrity_signals_mastery_06.apk", T["d25_set6"]["answer"],
             "safe", "the Day 25 native APK unsplit, for the base tree's own answer"))
    add(Case("d0-control-day25-reflection-unsplit", "ctl", r_apk, "integrity_signals_mastery_07.apk",
             T["d25_set7"]["answer"], "safe", "the Day 25 reflection APK unsplit"))
    add(Case("d1-native-in-config-split", "d", bundle(n_base, [("config.x86_64.apk", cfg())]), "d1.apks",
             T["d25_set6"]["answer"], "unsure", "libarena.so in config.x86_64.apk, the base keeps the dex and the chain"))
    r_dex = member(r_apk, "classes.dex")
    add(Case("d2-reflection-dex-in-feature", "d", bundle(edit(r_apk, drop=["classes.dex"]),
                                                          [("feature.apk", split_apk([("classes.dex", r_dex)]))]),
             "d2.apks", T["d25_set7"]["answer"], "unsure",
             "the reflected-on app code (the whole dex) lives in the feature split, the base keeps the puzzle document"))
    n_dex = member(n_apk, "classes.dex")
    add(Case("d3-native-and-dex-in-splits", "d",
             bundle(edit(n_base, drop=["classes.dex"]),
                    [("feature.apk", split_apk([("classes.dex", n_dex)])), ("config.x86_64.apk", cfg())]),
             "d3.apks", T["d25_set6"]["answer"], "unsure", "dex in the feature split, the library in a config split"))
    add(Case("d4-native-in-two-config-splits", "d",
             bundle(n_base, [("config.x86_64.apk", cfg()), ("config.x86_64.copy.apk", cfg())]), "d4.apks",
             T["d25_set6"]["answer"], "safe", "the same library bytes in two config splits"))
    add(Case("d5-native-only-wrong-abi-split", "x",
             bundle(n_base, [("config.arm64_v8a.apk", split_apk([("lib/arm64-v8a/libarena.so", so)]))]), "d5.apks", None,
             "safe", "the x86-64 code under an arm64-v8a path: which ABI the runtime loads is not in the bytes",
             plain_ok=frozenset({T["d25_set6"]["answer"]})))

    # two competing dex chains in different splits: the app's own (the base split's) is the one the puzzle runs
    tt_answer = _dex_case("tmp", "b", tt_base, [("feature.apk", tt_feat)], "safe", "").truth
    add(Case("x14-second-chain-in-feature-split", "x",
             bundle(tt_base, [("feature.apk", edit(tt_feat, add=[("classes2.dex", r_dex)]))]), "x14.apks", tt_answer, "safe",
             "the feature split also carries another app's dex chain (the Day 25 reflection one): the base's chain is the answer"))
    add(Case("x15-second-chain-in-config-split", "x",
             bundle(r_apk, [("config.xx.apk", split_apk([("classes.dex", member(tt_base, "classes.dex")),
                                                          (bin_name, member(tt_feat, bin_name))]))]),
             "x15.apks", T["d25_set7"]["answer"], "safe",
             "a config split carries the Day 26 chain and its asset; the base split holds the Day 25 reflection chain"))

    d23 = fx("d23_set5_native.apk")
    d23_so = member(d23, so_name)
    add(Case("d6-day23-native-in-config-split", "d",
             bundle(edit(d23, drop=[so_name]), [("config.x86_64.apk", split_apk([(so_name, d23_so)]))]), "d6.apks",
             T["d23_set5"]["answer"], "unsure", "the Day 23 straight-line native leg, its library in a config split"))
    add(Case("x17-two-different-libs-two-splits", "x",
             bundle(n_base, [("config.x86_64.apk", split_apk([(so_name, so)])),
                             ("config.x86_64.other.apk", split_apk([(so_name, d23_so)]))]), "x17.apks", None, "none",
             "two different libarena.so at the same path in two config splits: which one loads is not in the bytes (%s)"
             % SO_AMBIG, must="none"))
    add(Case("x17b-two-different-libs-reversed", "x",
             bundle(n_base, [("config.x86_64.apk", split_apk([(so_name, d23_so)])),
                             ("config.x86_64.other.apk", split_apk([(so_name, so)]))]), "x17b.apks", None, "none",
             "the same pair in the other order (%s)" % SO_AMBIG, must="none"))
    add(Case("x17c-lib-in-base-and-other-in-split", "x",
             bundle(n_apk, [("config.x86_64.apk", split_apk([(so_name, d23_so)]))]), "x17c.apks", None, "none",
             "the base keeps its own libarena.so and a config split carries a different one at the same path (%s)"
             % SO_AMBIG, must="none"))

    # ============================== decoys (x) of the split document
    base_code = code_for("x")
    lens, order = [7, 6, 7], [2, 0, 1]
    parts, seq = layout(base_code, lens, order)

    def dec(name, base_doc, splits, note, fold="none", truth=None):
        add(Case(name, "x", bundle(base_apk_with_doc(base_doc), [(n, split_apk(m)) for n, m in splits]), name + ".apks",
                 truth, fold, note))

    blank = ["", parts[1], parts[2]]
    dec("x1-duplicate-part-index", split_doc(blank, order),
        [("feature.apk", [("assets/huntress_feature.json", feature_doc(parts[0], 0)),
                          ("assets/huntress_feature_2.json", feature_doc("DEADBEEF1", 0))])],
        "two assets both fill part 0 with different text")
    dec("x2-two-puzzle-documents", split_doc(blank, order),
        [("feature.apk", [("assets/huntress_feature.json", feature_doc(parts[0], 0)),
                          (PUZZLE, split_doc(["", "ANS-0", "0000000"], order))])],
        "a second assets/huntress_puzzle.json in the feature split")
    dec("x3-part-over-non-empty", split_doc(["", parts[1], parts[2]], order),
        [("feature.apk", [("assets/huntress_feature.json", feature_doc("ZZZZ", 1))])],
        "the feature part targets a part the base already carries; part 0 stays empty")
    dec("x3b-fill-plus-over-non-empty", split_doc(["", parts[1], parts[2]], order),
        [("feature.apk", [("assets/huntress_feature.json", feature_doc(parts[0], 0)),
                          ("assets/huntress_feature_2.json", feature_doc("0000000", 2))])],
        "part 0 filled right, a second asset overwrites non-empty part 2")
    dec("x4-same-index-in-two-splits", split_doc(blank, order),
        [("feature.apk", [("assets/huntress_feature.json", feature_doc(parts[0], 0))]),
         ("config.xxhdpi.apk", [("assets/huntress_feature.json", feature_doc("0DEC0DE00", 0))])],
        "the same asset name and index in two splits, different parts")
    dec("x4b-same-index-in-two-splits-identical", split_doc(blank, order),
        [("feature.apk", [("assets/huntress_feature.json", feature_doc(parts[0], 0))]),
         ("config.xxhdpi.apk", [("assets/huntress_feature.json", feature_doc(parts[0], 0))])],
        "the same part twice: one value, but a duplicate index", fold="safe", truth=base_code)
    add(Case("x13-base-only-split-doc", "x", bundle(base_apk_with_doc(split_doc(blank, order)), []), "x4c.apks", None,
             "none", "no feature split at all (an .apks with only the base split)"))
    dec("x5-leftover-empty-part", split_doc(["", parts[1], ""], order),
        [("feature.apk", [("assets/huntress_feature.json", feature_doc(parts[0], 0))])],
        "two empty parts, one filled: the assembled text is no code")
    dec("x6-not-a-code", split_doc(blank, order),
        [("feature.apk", [("assets/huntress_feature.json", feature_doc("zz-not-hex", 0))])],
        "the filled text is no ANS code (reading is well-formed, the answer is not)")
    dec("x7-index-out-of-range", split_doc(blank, order),
        [("feature.apk", [("assets/huntress_feature.json", feature_doc(parts[0], 7))])], "part_index 7 of 3 parts")
    dec("x8-non-string-part", split_doc(blank, order),
        [("feature.apk", [("assets/huntress_feature.json", json.dumps(
            {"codec": "split", "part": 12345, "part_index": 0}).encode())])], "a numeric part")
    dec("x9-order-not-a-permutation", split_doc(blank, [2, 2, 1]),
        [("feature.apk", [("assets/huntress_feature.json", feature_doc(parts[0], 0))])], "order [2,2,1]")
    # the other codec value over the same feature: not 'split'
    dec("x10-feature-doc-other-codec", split_doc(blank, order, codec="reverse"),
        [("feature.apk", [("assets/huntress_feature.json", feature_doc(parts[0], 0))])],
        "codec reverse with parts and a feature part: the split reading must not fire")
    # a feature asset that is not a JSON object / not valid JSON
    dec("x11-feature-asset-garbage", split_doc(blank, order),
        [("feature.apk", [("assets/huntress_feature.json", b"\x00\x01not json"),
                          ("assets/huntress_feature_2.json", feature_doc(parts[0], 0))])],
        "one unreadable JSON asset next to the valid one (the valid asset still fills part 0)", fold="safe",
        truth=base_code)
    dec("x16-feature-part-over-full-base", split_doc(parts, order),
        [("feature.apk", [("assets/huntress_feature.json", feature_doc("OVERRIDE00000", 1))])],
        "the base document is complete; a feature asset also claims non-empty part 1: whether a feature overrides is not in the bytes "
        "(the base tree answers an unsure pick of the base's own reading, never plain)", fold="safe")
    dec("x18-decoy-data-beside-split-parts", json.dumps(
        {"schema": SCHEMA_V1, "day": 26, "codec": "split", "data": "ANS-0BADC0DE0BADC0DE", "parts": blank,
         "order": order}, separators=(",", ":")).encode(),
        [("feature.apk", [("assets/huntress_feature.json", feature_doc(parts[0], 0))])],
        "a clear decoy code in `data` beside split parts a feature fills: the arranged parts are the code, `data` is not read",
        fold="safe", truth=base_code)
    dec("x19-lowercase-part", split_doc(blank, order),
        [("feature.apk", [("assets/huntress_feature.json", feature_doc(parts[0].lower(), 0))])],
        "the fed part is lower case: the arranged text is no uppercase ANS code, and a solver must not repair it")
    dec("x20-part-with-newline", split_doc(blank, order),
        [("feature.apk", [("assets/huntress_feature.json", feature_doc(parts[0] + "\n", 0))])],
        "the fed part ends in a newline: the arranged text is no ANS code")

    # ============================== .aab-shaped zip (base/ and feature/ module folders)
    code_aab = code_for("aab")
    aparts, aseq = layout(code_aab, [5, 7, 8], [2, 0, 1])
    add(Case("x12-aab-shaped", "x", aab_zip(aparts, [2, 0, 1], member(fx("d26_base.base.apk"), "classes.dex")), "bundle.aab",
             code_aab, "safe",
             "an Android App Bundle layout (BundleConfig.pb, protobuf manifests, base/ and feature/ module folders); no day ever delivered one"))
    return cases


def fx_bundle(tag):
    return bundle(fx(tag + ".base.apk"), [("feature.apk", fx(tag + ".feature.apk"))])


# ------------------------------------------------------------------ dex-chain cases with the reference truth
def _dex_case(name, family, base, splits, fold, note, ambiguous=False):
    """splits: [(file name, apk bytes)]. Truth = the reference runtime's, with the splits in the order given (the
    runtime lists non-base splits in install order; where two splits hold the asset the order matters, and
    `ambiguous` drops the truth)."""
    from day27_mobile_splits_ref import RefVM
    dex = member(base, "classes.dex")
    ordered = [("/data/app/%s" % n, dict(zread(b))) for n, b in splits]
    truth = None
    if not ambiguous:
        truth = RefVM(dex, ordered).code()
    else:
        outs = {RefVM(dex, o).code() for o in (ordered, list(reversed(ordered)))}
        assert len(outs) == 2, "a b7-style case needs two different answers"
    return Case(name, family, bundle(base, splits), name + ".apks", truth, fold, note)


# ------------------------------------------------------------------ the .aab-shaped zip
def _pb_varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _pb(field, wire, payload):
    tag = _pb_varint((field << 3) | wire)
    return tag + (_pb_varint(len(payload)) + payload if wire == 2 else payload)


def _pb_xml_manifest(package, split=None):
    """aapt2 Resources.proto XmlNode{element{name, attribute{name,value}...}}: a real, minimal protobuf manifest."""
    def attr(name, value):
        return _pb(4, 2, _pb(2, 2, name.encode()) + _pb(3, 2, value.encode()))
    el = _pb(3, 2, b"manifest") + attr("package", package)
    if split:
        el += attr("split", split)
    return _pb(1, 2, el)


def aab_zip(parts, order, dex):
    cfg = _pb(1, 2, _pb(2, 2, b"1.15.6"))     # BundleConfig{bundletool{version}}
    mem = [("BundleConfig.pb", cfg),
           ("base/manifest/AndroidManifest.xml", _pb_xml_manifest("com.huntress.mobile.d27.aab")),
           ("base/dex/classes.dex", dex),
           ("base/assets/huntress_puzzle.json", split_doc(["", parts[1], parts[2]], order)),
           ("base/resources.pb", b""),
           ("feature/manifest/AndroidManifest.xml", _pb_xml_manifest("com.huntress.mobile.d27.aab", "arena_feature")),
           ("feature/assets/huntress_feature.json", feature_doc(parts[0], 0)),
           ("metadata/com.android.tools.build.libraries/dependencies.pb", b"")]
    return zwrite(mem)
