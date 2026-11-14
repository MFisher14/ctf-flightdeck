"""Synthetic `analysis` APKs for the mobile opener: the dex-chain shapes Huntress dealt (B-229).

Days 23, 26 and 31 of Huntress shipped puzzle documents with codec `analysis` and no data: the answer
code is computed by the app's own dex. These builders write APKs of those shapes from code, with a real
classes.dex (ctf.openers.dexasm) whose methods compute the code, and a Python oracle for each that
computes the same code without the reader, so a fixture's frozen key in openers/layer1.toml can be
checked against an independent value (tests/test_b229_dex_chain.py does).

  chain       Day 23 "Hook, Line and Signal": Release.code() runs a seed through static long transforms
              in other classes (one reads a long[] table filled by fill-array-data), then formats
              "ANS-%016X". Same-shaped transforms the chain never calls are decoys.
  loader      Day 20 "Loaded Later", dealt again as Day 31 Mastery set 10: Release.code() reads
              assets/payload.dex through Context.getAssets / AssetManager.open, loads it with
              InMemoryDexClassLoader, and calls Core.derive(long) in it by reflection.
  unmodelled  the chain shape with one call the VM has no model of (a vendor SDK the APK does not
              carry). A reader must decline it: the code it would otherwise print is the chain's.
  split       Day 5 "Backup Spill": codec split, `parts` and `order`, where order[i] is the position of
              parts[i] (the reading the judge accepted as split:by-order).
  bundle      Day 26 "Split Decision" Time Trial: an .apks of base.apk + feature.apk whose base dex chain reads
              assets/huntress_feature.bin out of the non-base split (getApplicationInfo().splitSourceDirs,
              ZipFile.getEntry). The packages and their oracle are ctf.openers.mobile_splits_synth's d26_tt
              (fix round 1: moved there from tests/ so this opener can build it).

Every builder is deterministic (fixed zip dates, fixed constants): the opener's key must not depend on
the clock or the machine.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import mobile_splits_synth as _splits
from .dexasm import Code, DexFile, apk

M64 = (1 << 64) - 1
PUZZLE = "assets/huntress_puzzle.json"
ANS_FMT = "ANS-%016X"
SAMPLE_CODE = "ANS-0123456789ABCDEF"   # the placeholder a Day 23 live patch offered; never an answer

# invoke opcodes (format 35c)
VIRTUAL, DIRECT, STATIC = 0x6E, 0x70, 0x71
MUL_LONG, ADD_LONG, XOR_LONG = 0x9D, 0x9B, 0xA2
AGET_WIDE, APUT_OBJECT = 0x45, 0x4D

LONG = "Ljava/lang/Long;"
STRING = "Ljava/lang/String;"
OBJ_ARR = "[Ljava/lang/Object;"

# Day 23 shape constants: (seed, mul, xor, table, pick)
CHAIN_BASE = (0x00C0FFEE5EED1234, 0x9E3779B97F4A7C15, 0x5DEECE66D0B5C0DE,
              (0x1111111111111111, 0x0F1E2D3C4B5A6978, 0x7766554433221100, 0x0123456789ABCDEF), 2)
CHAIN_VARIANT = (0x0000BADC0FFEE042, 0xD6E8FEB86659FD93, 0x00000000DEADBEEF,
                 (0x2545F4914F6CDD1D, 0x3C6EF372FE94F82B, 0x6A09E667F3BCC908, 0x510E527FADE682D1), 1)
# Day 20/31 loader constants: (seed, mul, xor)
LOADER_BASE = (0x00000D20_5EED0031, 0xBF58476D1CE4E5B9, 0x94D049BB133111EB)


def _apk(dexes: dict[str, bytes], doc: dict | None, extra: dict[str, bytes] | None = None) -> bytes:
    members = dict(dexes)
    members.update(extra or {})
    if doc is not None:
        members[PUZZLE] = json.dumps(doc, sort_keys=True).encode()
    return apk(members)


def _analysis_doc(day: int) -> dict:
    return {"schema": "huntress.mobile.puzzle.v2", "day": day, "codec": "analysis",
            "question": "What code does the app compute?"}


def _format_tail(d: DexFile, c: Code, value_reg: int) -> None:
    """Return String.format("ANS-%016X", new Object[]{Long.valueOf(v[value_reg])}). Uses v10..v14."""
    size, arr, box, fmt, out = 10, 11, 12, 13, 14
    c.const4(size, 1)
    c.new_array(arr, size, d.type(OBJ_ARR))
    c.invoke(STATIC, d.method(LONG, "valueOf", "LJ"), [value_reg, value_reg + 1])
    c.move_result_object(box)
    c.const4(size, 0)
    c.aput(APUT_OBJECT, box, arr, size)
    c.const_string(fmt, d.string(ANS_FMT))
    c.invoke(STATIC, d.method(STRING, "format", "LLL"), [fmt, arr])
    c.move_result_object(out)
    c.return_object(out)


def _long_op(d: DexFile, cls: str, name: str, k_mul: int, k_xor: int):
    """A static long f(long x) = (x * k_mul) ^ k_xor (regs 8: the argument is in v6, v7)."""
    c = Code(regs=8, ins=2, outs=0)
    c.const_wide(0, k_mul)
    c.binop(MUL_LONG, 2, 6, 0)
    c.const_wide(0, k_xor)
    c.binop(XOR_LONG, 2, 2, 0)
    c.return_wide(2)
    return d.method(cls, name, "JJ"), c


def _table_op(d: DexFile, cls: str, name: str, table: tuple[int, ...], pick: int):
    """A static long g(long x) = x + T[pick], T a long[] built by fill-array-data (regs 10: argument v8, v9)."""
    c = Code(regs=10, ins=2, outs=0)
    c.const4(0, len(table))
    c.new_array(1, 0, d.type("[J"))
    c.fill_array_data(1, 8, list(table))
    c.const4(0, pick)
    c.aget(AGET_WIDE, 2, 1, 0)
    c.binop(ADD_LONG, 4, 8, 2)
    c.return_wide(4)
    return d.method(cls, name, "JJ"), c


def chain_value(seed: int, k_mul: int, k_xor: int, table: tuple[int, ...], pick: int) -> str:
    """The oracle of chain_dex: the code the Day-23 shape computes, worked out without the reader."""
    x = ((seed * k_mul) & M64) ^ k_xor
    x = (x + table[pick]) & M64
    return ANS_FMT % x


def chain_dex(seed: int, k_mul: int, k_xor: int, table: tuple[int, ...], pick: int, *,
              unmodelled: bool = False, sample: bool = False, twin_seed: int | None = None,
              pkg: str = "com/huntress/d23") -> bytes:
    """The Day-23 classes.dex: Release.code() -> Mix.step -> Guard.fold -> "ANS-%016X". Mix and Guard also
    hold decoy transforms the chain never calls. `unmodelled` adds a call to a vendor SDK method no dex here
    defines and no device has; `sample` adds a never-called method returning SAMPLE_CODE; `twin_seed` adds a
    second entry, ReleaseLegacy.code(), running the same chain from that seed (two codes: nothing proves which)."""
    d = DexFile()
    release, mix, guard = (f"L{pkg}/Release;", f"L{pkg}/Mix;", f"L{pkg}/Guard;")
    step = _long_op(d, mix, "step", k_mul, k_xor)
    decoy_mix = _long_op(d, mix, "stepLegacy", k_mul ^ 0xFF, k_xor ^ 0xFF)
    fold = _table_op(d, guard, "fold", table, pick)
    decoy_fold = _table_op(d, guard, "foldDebug", table, (pick + 1) % len(table))

    def entry(from_seed: int, extra_call: bool) -> Code:
        code = Code(regs=16, ins=0, outs=5)
        code.const_wide(0, from_seed)
        code.invoke(STATIC, step[0], [0, 1])
        code.move_result_wide(0)
        if extra_call:
            code.invoke(STATIC, d.method("Lcom/vendor/attest/Sdk;", "verdict", "J"), [])
            code.move_result_wide(2)                      # read and dropped: the call itself must decline
        code.invoke(STATIC, fold[0], [0, 1])
        code.move_result_wide(0)
        _format_tail(d, code, 0)
        return code

    d.define(release, [(d.method(release, "code", "L"), entry(seed, unmodelled))])
    if twin_seed is not None:
        legacy = f"L{pkg}/ReleaseLegacy;"
        d.define(legacy, [(d.method(legacy, "code", "L"), entry(twin_seed, False))])
    d.define(mix, [step, decoy_mix])
    d.define(guard, [fold, decoy_fold])
    if sample:
        s = Code(regs=2, ins=0, outs=0)
        s.const_string(0, d.string(SAMPLE_CODE))
        s.return_object(0)
        debug = f"L{pkg}/Debug;"
        d.define(debug, [(d.method(debug, "sample", "L"), s)])
    return d.build()


def loader_value(seed: int, k_mul: int, k_xor: int) -> str:
    """The oracle of the loader shape: Core.derive(seed) = (seed * k_mul) ^ k_xor, formatted."""
    return ANS_FMT % (((seed * k_mul) & M64) ^ k_xor)


def payload_dex(k_mul: int, k_xor: int, *, cls: str = "Lcom/huntress/payload/Core;", name: str = "derive") -> bytes:
    """The secondary dex the loader shape reads from its assets: Core.derive(long) (no "ANS-" in it)."""
    d = DexFile()
    d.define(cls, [_long_op(d, cls, name, k_mul, k_xor)])
    return d.build()


def loader_dex(seed: int, *, asset: str = "payload.dex", target: str = "com.huntress.payload.Core",
               method: str = "derive", pkg: str = "com/huntress/d20") -> bytes:
    """The Day-20 "Loaded Later" classes.dex: Release.code(), an instance method of the Activity, reads the asset
    through this.getAssets(), loads it with InMemoryDexClassLoader and invokes Core.derive(seed) by reflection."""
    d = DexFile()
    release = f"L{pkg}/Release;"
    c = Code(regs=16, ins=1, outs=5)                      # an Activity method: `this` is v15
    c.invoke(VIRTUAL, d.method("Landroid/app/Activity;", "getAssets", "L"), [15])
    c.move_result_object(1)
    c.const_string(2, d.string(asset))
    c.invoke(VIRTUAL, d.method("Landroid/content/res/AssetManager;", "open", "LL"), [1, 2])
    c.move_result_object(3)
    c.invoke(VIRTUAL, d.method("Ljava/io/InputStream;", "readAllBytes", "L"), [3])
    c.move_result_object(4)
    c.invoke(STATIC, d.method("Ljava/nio/ByteBuffer;", "wrap", "LL"), [4])
    c.move_result_object(4)
    c.const_class(5, d.type(release))
    c.invoke(VIRTUAL, d.method("Ljava/lang/Class;", "getClassLoader", "L"), [5])
    c.move_result_object(5)
    c.new_instance(6, d.type("Ldalvik/system/InMemoryDexClassLoader;"))
    c.invoke(DIRECT, d.method("Ldalvik/system/InMemoryDexClassLoader;", "<init>", "VLL"), [6, 4, 5])
    c.const_string(7, d.string(target))
    c.invoke(VIRTUAL, d.method("Ljava/lang/ClassLoader;", "loadClass", "LL"), [6, 7])
    c.move_result_object(7)
    c.const_string(8, d.string(method))
    c.const4(9, 1)
    c.new_array(10, 9, d.type("[Ljava/lang/Class;"))
    c.invoke(VIRTUAL, d.method("Ljava/lang/Class;", "getDeclaredMethod", "LLL"), [7, 8, 10])
    c.move_result_object(8)
    c.new_array(10, 9, d.type(OBJ_ARR))
    c.const_wide(12, seed)
    c.invoke(STATIC, d.method(LONG, "valueOf", "LJ"), [12, 13])
    c.move_result_object(11)
    c.const4(9, 0)
    c.aput(APUT_OBJECT, 11, 10, 9)
    c.const4(0, 0)                                        # a static method: invoked on null
    c.invoke(VIRTUAL, d.method("Ljava/lang/reflect/Method;", "invoke", "LLL"), [8, 0, 10])
    c.move_result_object(11)
    c.invoke(VIRTUAL, d.method(LONG, "longValue", "J"), [11])
    c.move_result_wide(0)
    _format_tail(d, c, 0)
    code = d.method(release, "code", "L")
    d.define(release, [(code, c)], virtual=(code,))
    return d.build()


def chain_apk(spec=CHAIN_BASE, **kw) -> bytes:
    """A Day-23 shape APK over chain_dex(*spec, **kw)."""
    return _apk({"classes.dex": chain_dex(*spec, **kw)}, _analysis_doc(23))


def loader_apk(spec=LOADER_BASE, *, with_payload: bool = True) -> bytes:
    seed, k_mul, k_xor = spec
    extra = {"assets/payload.dex": payload_dex(k_mul, k_xor)} if with_payload else {}
    return _apk({"classes.dex": loader_dex(seed)}, _analysis_doc(20), extra)


# Day 5: the code cut in four, listed out of order; order[i] is the position of parts[i]
SPLIT_CODE = "ANS-5B11D0C0DE05A1E5"
SPLIT_ORDER = (2, 0, 3, 1)


def split_doc(code: str = SPLIT_CODE, order: tuple[int, ...] = SPLIT_ORDER) -> dict:
    pieces = [code[i * 5:(i + 1) * 5] for i in range(4)]        # in the code's own order
    parts = [pieces[pos] for pos in order]                         # parts[i] sits at position order[i]
    return {"schema": "huntress.mobile.puzzle.v1", "day": 5, "codec": "split", "parts": parts,
            "order": list(order)}


def split_apk() -> bytes:
    """A Day-5 shape APK: no dex code to run, the split document only."""
    d = DexFile()
    d.string("Lcom/huntress/d05/MainActivity;")
    return _apk({"classes.dex": d.build()}, split_doc())


SPLIT_ASSET_TAG = "d26_tt"            # mobile_splits_synth's Day 26 Time Trial shape


def split_asset_value() -> str:
    """The Day 26 bundle's code, from mobile_splits_synth's oracle (the chain spec evaluated in Python)."""
    return _splits.truths()[SPLIT_ASSET_TAG]["answer"]


def split_asset_bundle(*, with_asset: bool = True) -> bytes:
    """The Day 26 .apks: base.apk then feature.apk. Without the asset, the feature split lacks the member the
    base's chain reads, so no code is computable."""
    base = _splits.fixture(SPLIT_ASSET_TAG + ".base.apk")
    feature = _splits.fixture(SPLIT_ASSET_TAG + ".feature.apk")
    if not with_asset:
        import io
        import zipfile
        with zipfile.ZipFile(io.BytesIO(feature)) as zf:
            feature = apk({n: zf.read(n) for n in zf.namelist() if n != _splits.FEATURE_BIN})
    return apk({"base.apk": base, "feature.apk": feature})


# --------------------------------------------------------------------------- B-228 codec_search shapes
# The six codec_search reversible-transform shapes the Mobile lane consolidated (BUILD-PLAN B-228):
# a reversible transform over the document's extra fields (Day 4), the native .so fallthrough (Day 15),
# the lone-data novel-codec plain reading (Day 19 reflection), the named-member pointer-step read (Day 20),
# the split+feature empty-part reassembly (Day 26), and the shape-triggered white-box key-schedule reader
# (Day 29). Each is read no-model by the shipped solvers/mobile-android/codec_search.py; the builders are
# deterministic and each carries a Python oracle so openers/layer1.toml's frozen key is independently checked
# (tests/test_b228_codec_search.py). None of these runs the dex VM; they exercise codec_search's own readers,
# not B-229's `analysis` dex chain.

V1 = "huntress.mobile.puzzle.v1"


def _b64(b: bytes) -> str:
    import base64
    return base64.b64encode(b).decode()


def _string_dex(*strings: str) -> bytes:
    """A classes.dex with only a string table (no code): the member a Day-20 document names by path. Its string
    table holds the answer code in clear, as the Day-20 secondary dex did (codec_search.dex_strings reads it)."""
    d = DexFile()
    for s in strings:
        d.string(s)
    return d.build()


# Day 4 "Pending Intent Relay": codec xor over the code, the one-byte key in the document's `key` field.
REVERSIBLE_CODE = "ANS-04D04D04D04D0411"
REVERSIBLE_KEY = 90                                   # 0x5A
REVERSIBLE_VARIANT_CODE = "ANS-04CAFE04BABE0421"      # the Time Trial variant (a fresh build, another key)
REVERSIBLE_VARIANT_KEY = 51                           # 0x33


def reversible_value(code: str = REVERSIBLE_CODE) -> str:
    """The oracle of reversible_apk: codec_search reverses the one-byte xor to the code itself."""
    return code


def reversible_apk(code: str = REVERSIBLE_CODE, key: int = REVERSIBLE_KEY) -> bytes:
    """A Day-4 shape APK: codec `xor`, `data` the code under one byte of xor, the byte in the `key` extra field."""
    doc = {"schema": V1, "day": 4, "codec": "xor",
           "data": _b64(bytes(c ^ key for c in code.encode())), "key": key}
    return _apk({}, doc)


# Day 15 "Native Library Secrets": the document says codec `native` and carries no data; the code is a string
# of a bundled .so, reached by the JNI-library fallthrough (codec_search.native_hit, route `native:so-secret`).
NATIVE_CODE = "ANS-15DEADBEEF150015"


def native_value() -> str:
    return NATIVE_CODE


def native_apk(code: str = NATIVE_CODE) -> bytes:
    so = b"\x7fELF" + b"\x00" * 60 + b"secret_code=" + code.encode() + b"\x00" * 8
    return _apk({}, {"schema": V1, "day": 15, "codec": "native", "data": ""},
                {"lib/arm64-v8a/libsecret.so": so})


# Day 19 "Reflection Maze": the document names a codec no reader applies by position but the folded-in reader
# recognises (`reflection`), with the code in clear in `data`; it reads plain (route `reflection:plain`). A
# genuinely novel codec name instead falls to codec_search._bare_codec_pick's conservative one-probe pick.
REFLECTION_CODE = "ANS-19C0FFEE19BADA55"


def reflection_value() -> str:
    return REFLECTION_CODE


def reflection_apk(code: str = REFLECTION_CODE) -> bytes:
    return _apk({}, {"schema": V1, "day": 19, "codec": "reflection", "data": code})


# Day 20 "Loaded Later": the document's `data` names a member BY PATH (a secondary dex); codec_search reads that
# member's string table before any budgeted brute search (named_member_hit, route `apk-string:dex`). The
# pointer-step-first read survives a tight Mastery budget, where the field search alone would starve.
NAMED_MEMBER_CODE = "ANS-20105EED20314201"
NAMED_MEMBER_PATH = "assets/payload.dex"


def named_member_value() -> str:
    return NAMED_MEMBER_CODE


def named_member_apk(code: str = NAMED_MEMBER_CODE) -> bytes:
    payload = _string_dex("Lcom/huntress/d20/Core;", code, "unused_string")
    return _apk({}, {"schema": V1, "day": 20, "codec": "dynamic", "data": NAMED_MEMBER_PATH},
                {NAMED_MEMBER_PATH: payload})


# Day 26 "Split Decision" (the split+feature codec, distinct from B-229's analysis+split-asset chain): the base
# split's codec `split` document has EMPTY parts, each filled once by a part document in the non-base split;
# the by-order reading of the filled parts is the code (split_bundle.readings, route `split:by-order+feature`).
SPLIT_FEATURE_CODE = "ANS-26AB26CD26EF2601"
SPLIT_FEATURE_ORDER = [0, 1, 2, 3]
SPLIT_FEATURE_PKG = "com.huntress.d26"
_SPLIT_FEATURE_EMPTY = (1, 3)                         # the part indices the feature split fills


def split_feature_value() -> str:
    return SPLIT_FEATURE_CODE


def _split_feature_pieces() -> list[str]:
    return [SPLIT_FEATURE_CODE[i * 5:(i + 1) * 5] for i in range(4)]


def split_feature_bundle(*, with_parts: bool = True) -> bytes:
    import io
    import zipfile
    pieces = _split_feature_pieces()
    base_parts = ["" if i in _SPLIT_FEATURE_EMPTY else pieces[i] for i in range(4)]
    base_doc = {"schema": V1, "day": 26, "codec": "split", "parts": base_parts,
                "order": SPLIT_FEATURE_ORDER}
    base = _splits.apk([("AndroidManifest.xml", _splits.base_manifest(SPLIT_FEATURE_PKG, "Split Decision")),
                        (PUZZLE, json.dumps(base_doc, sort_keys=True).encode())])
    feature_members = [("AndroidManifest.xml", _splits.split_manifest(SPLIT_FEATURE_PKG, "arena_feature"))]
    if with_parts:
        for i in _SPLIT_FEATURE_EMPTY:
            part = {"schema": V1, "day": 26, "codec": "split", "part_index": i, "part": pieces[i]}
            feature_members.append(("assets/part_%d.json" % i, json.dumps(part, sort_keys=True).encode()))
    feature = _splits.apk(feature_members)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:                 # the outer .apks bundle
        z.writestr("base.apk", base)
        z.writestr("feature.apk", feature)
    return out.getvalue()


# Day 29 "White-box Key Recovery": the document carries 40 hex digits of `data` and a JSON integer `key`; the
# code is recovered by the shape-triggered linear-offset reader (codec_more.linear_offset_shape), offered unsure
# under a document-fingerprint candidate key (route `linear-offset:sub-key-step`).
WHITEBOX_CODE = "ANS-29ABCDEF29012933"
WHITEBOX_KEY = 29
WHITEBOX_STEP = 7


def whitebox_value() -> str:
    return WHITEBOX_CODE


def _whitebox_data(code: str, key: int, step: int) -> str:
    return bytes((code.encode()[i] + key + step * i) % 256 for i in range(20)).hex()


def whitebox_apk(code: str = WHITEBOX_CODE, key: int = WHITEBOX_KEY, step: int = WHITEBOX_STEP) -> bytes:
    return _apk({}, {"schema": V1, "day": 29, "codec": "whitebox",
                     "data": _whitebox_data(code, key, step), "key": key})


# --------------------------------------------------------------------------- opener builders (dest -> path)

def _write(dest: Path, name: str, data: bytes) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    p = dest / name
    p.write_bytes(data)
    return p


def apk_analysis_chain(dest: Path) -> Path:
    """Day-23 Time Trial shape: the dex chain computes the code (codec analysis, no data)."""
    return _write(dest, "sample.apk", chain_apk(CHAIN_BASE))


def apk_analysis_chain_variant(dest: Path) -> Path:
    """Day-23 Mastery shape: the same chain on another build (other seed, constants and table index)."""
    return _write(dest, "sample.apk", chain_apk(CHAIN_VARIANT))


def apk_analysis_loader(dest: Path) -> Path:
    """Day-20 build dealt as Day-31 Mastery set 10: asset read, InMemoryDexClassLoader, reflection."""
    return _write(dest, "sample.apk", loader_apk(LOADER_BASE))


def apk_split_by_order(dest: Path) -> Path:
    """Day-5 base shape: codec split with parts and an order field."""
    return _write(dest, "sample.apk", split_apk())


def apk_analysis_unmodelled(dest: Path) -> Path:
    """Control: the Day-23 chain with one call the VM has no model of, plus a never-called method holding the
    placeholder SAMPLE_CODE. The chain's own code must not come out (the call declines), and neither may the
    placeholder as a plain answer."""
    return _write(dest, "sample.apk", chain_apk(CHAIN_BASE, unmodelled=True, sample=True))


def apk_analysis_no_payload(dest: Path) -> Path:
    """Control: the loader shape with assets/payload.dex missing. The loader's code must not come out."""
    return _write(dest, "sample.apk", loader_apk(LOADER_BASE, with_payload=False))


def apk_split_asset_bundle(dest: Path) -> Path:
    """Day-26 Time Trial shape: a split bundle whose dex chain reads an asset of the feature split."""
    return _write(dest, "sample.apks", split_asset_bundle())


def apk_split_asset_no_asset(dest: Path) -> Path:
    """Control: the Day-26 bundle with the feature split's asset removed. Its code must not come out."""
    return _write(dest, "sample.apks", split_asset_bundle(with_asset=False))


# -- B-228 codec_search shapes --

def apk_reversible_xor(dest: Path) -> Path:
    """Day-4 base: a reversible xor transform over the document's extra `key` field, read plain (route `xor`)."""
    return _write(dest, "sample.apk", reversible_apk())


def apk_reversible_xor_variant(dest: Path) -> Path:
    """Day-4 Time Trial: a fresh variant (another code and key), the timed mode fired after the base is CORRECT."""
    return _write(dest, "sample.apk", reversible_apk(REVERSIBLE_VARIANT_CODE, REVERSIBLE_VARIANT_KEY))


def apk_native_so(dest: Path) -> Path:
    """Day-15 base: codec `native`, no data; the code is a string of a bundled .so (route `native:so-secret`)."""
    return _write(dest, "sample.apk", native_apk())


def apk_lone_reflection(dest: Path) -> Path:
    """Day-19 base: a lone-data reading under the folded-in `reflection` codec, read plain (route `reflection:plain`)."""
    return _write(dest, "sample.apk", reflection_apk())


def apk_named_member(dest: Path) -> Path:
    """Day-20 base: the document's `data` names a secondary dex by path; its string table is read before the
    budgeted brute (pointer-step-first, route `apk-string:dex`)."""
    return _write(dest, "sample.apk", named_member_apk())


def apk_split_feature(dest: Path) -> Path:
    """Day-26 base: a split bundle whose base `split` document has empty parts the feature split fills
    (route `split:by-order+feature`)."""
    return _write(dest, "sample.apks", split_feature_bundle())


def apk_split_feature_no_parts(dest: Path) -> Path:
    """Control: the Day-26 split+feature bundle with the feature split's part documents removed. The empty parts
    cannot be filled, so no code is computable and the split+feature key must not come out."""
    return _write(dest, "sample.apks", split_feature_bundle(with_parts=False))


def apk_whitebox_offset(dest: Path) -> Path:
    """Day-29 base: 40 hex digits of `data` and a JSON integer `key`; the shape-triggered linear-offset reader
    recovers the code, offered unsure (route `linear-offset:sub-key-step`)."""
    return _write(dest, "sample.apk", whitebox_apk())


BUILDERS = {
    "apk_analysis_chain": apk_analysis_chain,
    "apk_analysis_chain_variant": apk_analysis_chain_variant,
    "apk_analysis_loader": apk_analysis_loader,
    "apk_split_by_order": apk_split_by_order,
    "apk_analysis_unmodelled": apk_analysis_unmodelled,
    "apk_analysis_no_payload": apk_analysis_no_payload,
    "apk_split_asset_bundle": apk_split_asset_bundle,
    "apk_split_asset_no_asset": apk_split_asset_no_asset,
    "apk_reversible_xor": apk_reversible_xor,
    "apk_reversible_xor_variant": apk_reversible_xor_variant,
    "apk_native_so": apk_native_so,
    "apk_lone_reflection": apk_lone_reflection,
    "apk_named_member": apk_named_member,
    "apk_split_feature": apk_split_feature,
    "apk_split_feature_no_parts": apk_split_feature_no_parts,
    "apk_whitebox_offset": apk_whitebox_offset,
}
