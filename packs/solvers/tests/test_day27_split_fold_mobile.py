#!/usr/bin/env python3
"""Day 27 build, Mobile: Day 26's split-bundle live fix folded into the shipped solver (split_bundle.py).

  .venv/bin/python tests/test_day27_split_fold_mobile.py

Day 26 ("Split Decision") delivered `.apks` bundles (base.apk + feature.apk). The shipped solver stopped; the
morning's day_patch.py closed the base (codec split, empty parts filled by a feature split's JSON), the Time Trial
and Mastery set 10 (codec analysis: the dex chain reads `huntress_feature.bin` out of the feature split), and a
racer built the cross-split reader of row 532. Now solvers/mobile-android/split_bundle.py reads them with no live
fix. No network and no token; a private ledger, the judged names from the seed (conventions.json).

  [R] the saved Day 26 base, Time Trial and Mastery (all ten sets) answer their key.json plainly, no day_patch
  [N] the analysis reader is not recognised by name: the real Time Trial dex with `readSplit` renamed answers the
      same code plain; the feature asset moved into a config split, the same; changed asset bytes give the code
      the live fix's name hook gives; identical copies in two splits are order-independent, different copies or
      no copy are never plain; both splits over the shipped reader's 1 MiB member bound: still read; a whole second package (no `split` in its manifest) or a
      split of another package beside the base: no bundle, the module-absent answer
  [X] a synthetic reader that XORs the bytes after reading (renamed `pull`): the exact code (it is run, not
      hooked), unsure under analysis+split-asset:reader@shape-<sha256> since its body is not the judged reader's
      shape (review 2 of a291433; they were plain), one option, plain once that key's route is accepted and only
      for that shape; the same reader called by reflection: the same key; a split read and then an entry no split
      holds (the reader's default buffer would make ANS-0000000000000000): None
  [H] a reader the VM cannot run (no body anywhere) or whose body declines at createContextForSplit: B's hook,
      unsure under analysis+split-asset:hooked@shape-<sha256> (the judged analysis+split-asset name does not make
      it plain); the reader renamed with other asset bytes keeps its shape key; a name accepted for one reader
      shape does not answer the other; identical copies in two splits hook once, different copies, a base copy,
      or a body in another split do not hook
  [P] codec split: a part in a config split, two empty parts in two splits, both order readings (judged first,
      unsure on a masked ledger), .xapk and .aab layouts; duplicate part_index with identical bytes is
      order-independent and accepted, while different duplicate bytes, a part over a non-empty part, a part in
      the base, an empty part left and two puzzle documents are never plain; extra fields: unsure
  [S] a code in clear elsewhere in the bundle: unsure under <key>:second-code, the reading first
  [C] row 532: the real Day 25 x86-64 native moved into a config split, and a reflected method in a feature dex:
      unsure under mobile.codec/analysis+across-splits; an ambiguous reflected method or native symbol: None
  [U] a plain single .apk is answered exactly as with the module absent
  [F] the adversarial review of 9c1f923, each WRONG plain it found now never plain: (1) a split read, then a
      getEntry miss the reader never makes good (its default buffer: ANS-0000000000000000), with one, two and
      three non-base splits; (2) a fixed splitSourceDirs[1] or [2] with three or four non-base splits (a
      reversal alone leaves index 1 of 3 in place); (3) a reader that mixes ApplicationInfo.targetSdkVersion,
      flags or uid, or a ZipEntry field, into the bytes (the shipped VM reads an unset field as 0), and the
      field index named by the running dex; (4) two bodiless readers under one caller, and two declining bodies
      that differ in a literal, get two hooked keys (a bodiless key binds the calling dex: the [H] check of a
      renamed bodiless reader now expects another key, unsure); (5) a decoy under base64, hex, a moved puzzle
      document or a split's zip comment makes the bundle's reading unsure under :second-code, as beside one APK;
      (6) a dex chain past the step budget is withheld by the module and costs less CPU than the shipped path
      (the synthetic looping readers of (1), (2) and (5) are not the judged reader's shape: their exact codes are
      unsure under the reader key since review 2)
  [V] review 2 of a291433, each fixed: (1) tier A keeps the judged analysis+split-asset name only when every
      split-touching method it ran has the judged reader's shape (JUDGED_READERS: Day 26's readSplit; a copy of
      that body in another app, other names and indexes, stays plain; the same app whose entry also asks
      getApplicationInfo, a static-keyed reader, a ByteArrayOutputStream.size() reader: never plain); (2) the
      ByteArrayOutputStream model: a subclass's protected `count` declines (it read 0: a WRONG plain), and every
      call on a subclass but its constructor declines (a device runs the subclass's toByteArray override: the
      judged reader's bytes through such an override were PLAIN); (3) a library in the base and a different one
      in a config split (x17c of the look-ahead): None, where it went back to the shipped reader and was PLAIN;
      a codeless config split, or the base's own library again, answers exactly as with the module absent; (4) KB-7
      (dex_float.py) beside the fold: the judged reader with an entry that XORs its bytes with an app static it set
      first is never plain (the base VM read every static as 0: a WRONG plain under the judged key; the split reading
      runs on the base VM's semantics with dex_float's base_sget, which declines such a read)
"""
import sys as _b240_sys  # noqa: E402
if "pytest" in _b240_sys.modules and __name__ != "__main__":
    # B-240 carry: a check()-style script. Its checks never fail a pytest run and its module-level setup changes
    # os.environ for the whole worker, so pytest does not collect it; tests/test_carry_checklist.py runs it as a
    # script (exit code and FAIL lines) and reports its saved-data sections as not run.
    import pytest
    pytest.skip("script-style test: run as a script by tests/test_carry_checklist.py", allow_module_level=True)
import atexit
import hashlib
import io
import json
import os
import re
import shutil
import struct
import sys
import tempfile
import time
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


if str(REPO) not in sys.path:
    sys.path.append(str(REPO))          # the ctf package (appended: the engine dirs stay first)
from ctf import paths  # noqa: E402
# The saved Huntress attempts (read only), only from $CTF_REAL_CHALLENGES through ctf.paths; never derived from
# this checkout's location. Unset: a path that is never on disk, so the sections skip; set to a missing
# folder: FileNotFoundError.
SAVED = paths.saved_challenges_root() or Path(os.devnull) / "no-saved-challenges"
TMP = Path(tempfile.mkdtemp(prefix="test_day27_split_"))
atexit.register(shutil.rmtree, str(TMP), True)
for _name in ("CTF_TOKEN", "CTF_LEDGER_MASK", "CTF_HIDE"):
    os.environ.pop(_name, None)
os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"
os.environ["CTF_STATE_DIR"] = str(TMP / "state")
os.environ["CTF_WORKDIR"] = str(TMP / "challenges")
os.environ["CTF_QUIET"] = "1"
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "tests"))
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.path.insert(0, str(REPO / "solvers" / "mobile-android"))
import labels  # noqa: E402
import codec_search as C  # noqa: E402
import dex_chain_codec as D  # noqa: E402
import split_bundle as SB  # noqa: E402
import day24_mobile_computed_specimens as S  # noqa: E402

C._patch = None          # whatever day_patch.py sits beside the solver, these checks are the shipped solver's
DAY26 = SAVED / "day-26" / "mobile-android-day-26-split-decision"
DAY25_SO = SAVED / "day-25" / "mobile-android-day-25-integrity-signals" / "mastery" / "members" / "delivery-06"
DAY23_SO = SAVED / "day-23" / "mobile-android-day-23-hook-line-and-signal" / "mastery" / "members" / "delivery-05"
PZ = "assets/huntress_puzzle.json"
SYNTAX = "ANS- followed by exactly 16 uppercase hexadecimal characters; no spaces or explanatory text"
Q = {"id": "answer", "qid": "answer", "answer_id": "answer", "answer_format": {"kind": "pattern", "syntax": SYNTAX},
     "question": "Reassemble evidence distributed across base and configuration splits. Submit only the exact "
                 "backend answer code returned for this case."}
FAILED, PASSED = [], []


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:600]}]"))
    (PASSED if ok else FAILED).append(label)


def fresh(mask=""):
    shutil.rmtree(TMP / "challenges", ignore_errors=True)
    labels._cache.clear()
    if mask:
        os.environ["CTF_LEDGER_MASK"] = mask
    else:
        os.environ.pop("CTF_LEDGER_MASK", None)


def learn(key, name):
    labels.learn(key, name, "accepted", attempt_id="t27", answer_ids=["answer"])


def code_for(name):
    return "ANS-" + hashlib.sha256(("day27:" + name).encode()).hexdigest()[:16].upper()


def zipped(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for k, v in members.items():
            z.writestr(k, v if isinstance(v, bytes) else json.dumps(v, separators=(",", ":")))
    return buf.getvalue()


def solve(blob, deliveries=1, name="x.apks"):
    att = {"artifacts": [{"filename": "d%d" % i} for i in range(deliveries)]}
    ctx = {"set": 1, "delivery": blob, "delivery_name": name, "attempt": att, "partial": {}}
    out = C.solve_set([dict(Q)], {}, ctx)
    return out.get("answer"), dict(C.LAST)


def unsure(value):
    return labels.parse(value) if labels.is_unsure(value) else None


def offered(value):
    got = unsure(value)
    return (got["k"], [tuple(o) for o in got["o"]]) if got else (None, [])


def plain(value):
    return isinstance(value, str) and not labels.is_unsure(value)


def reader_pick(value, code):
    """Unsure under analysis+split-asset:reader@shape-<sha256> (tier A beside a reader that is not the judged one's
    shape) with the one option (judged route, code)."""
    k, opts = offered(value)
    rk = SB.AKEY + SB.READER + "@shape-"
    return str(k).startswith(rk) and len(k) == len(rk) + 64 and opts == [(SB.AROUTE, code)]


# ---------------------------------------------------------------------------- a dex builder with fields and protos

def _short(t):
    return t if len(t) == 1 else "L"


class Dx:
    """A minimal classes.dex the shipped Dex parser and VM read: strings, types, protos (shorty, return type,
    parameter list), field ids, method ids, and code items with their ins_size."""

    def __init__(self):
        self.strings, self.types, self.protos, self.fields, self.methods = [], [], [], [], []
        self.bodies = {}     # class descriptor -> [(midx, units, regs, ins)]

    def s(self, t):
        if t not in self.strings:
            self.strings.append(t)
        return self.strings.index(t)

    def t(self, t):
        self.s(t)
        if t not in self.types:
            self.types.append(t)
        return self.types.index(t)

    def proto(self, ret, params=()):
        key = (_short(ret) + "".join(_short(p) for p in params), ret, tuple(params))
        self.s(key[0])
        self.t(ret)
        for p in params:
            self.t(p)
        if key not in self.protos:
            self.protos.append(key)
        return self.protos.index(key)

    def f(self, cls, typ, name):
        key = (self.t(cls), self.t(typ), self.s(name))
        if key not in self.fields:
            self.fields.append(key)
        return self.fields.index(key)

    def m(self, cls, name, ret="V", params=()):
        key = (self.t(cls), self.proto(ret, params), self.s(name))
        if key not in self.methods:
            self.methods.append(key)
        return self.methods.index(key)

    def body(self, midx, units, regs, ins):
        cls = self.types[self.methods[midx][0]]
        self.bodies.setdefault(cls, []).append((midx, list(units), regs, ins))

    @staticmethod
    def _uleb(n):
        out = bytearray()
        while True:
            b, n = n & 0x7F, n >> 7
            out.append(b | 0x80 if n else b)
            if not n:
                return bytes(out)

    def build(self):
        classes = list(self.bodies.items())
        heads = 0x70
        off = {"str": heads}
        off["type"] = off["str"] + 4 * len(self.strings)
        off["proto"] = off["type"] + 4 * len(self.types)
        off["field"] = off["proto"] + 12 * len(self.protos)
        off["meth"] = off["field"] + 8 * len(self.fields)
        off["cls"] = off["meth"] + 8 * len(self.methods)
        end = off["cls"] + 32 * len(classes)
        tail = bytearray()

        def place(b, align=4):
            while (end + len(tail)) % align:
                tail.append(0)
            o = end + len(tail)
            tail.extend(b)
            return o

        plists = {}
        for i, (_, _, params) in enumerate(self.protos):
            if params:
                blk = struct.pack("<I", len(params)) + b"".join(struct.pack("<H", self.types.index(p)) for p in params)
                plists[i] = place(blk)
        codes = {}
        for cls, ms in classes:
            for midx, units, regs, ins in ms:
                codes[midx] = place(struct.pack("<HHHHII", regs, ins, 5, 0, 0, len(units))
                                    + struct.pack("<%dH" % len(units), *units))
        cdata = []
        for cls, ms in classes:
            blk = bytearray(self._uleb(0) + self._uleb(0) + self._uleb(len(ms)) + self._uleb(0))
            prev = 0
            for midx, _, _, _ in sorted(ms, key=lambda x: x[0]):
                blk += self._uleb(midx - prev) + self._uleb(9) + self._uleb(codes[midx])
                prev = midx
            cdata.append(place(bytes(blk), 1))
        sdata = [place(self._uleb(len(t)) + t.encode() + b"\x00", 1) for t in self.strings]
        buf = bytearray(end)
        buf[0:8] = b"dex\n035\x00"
        for name, n, o in (("str", len(self.strings), 56), ("type", len(self.types), 64),
                           ("proto", len(self.protos), 72), ("field", len(self.fields), 80),
                           ("meth", len(self.methods), 88), ("cls", len(classes), 96)):
            struct.pack_into("<II", buf, o, n, off[name] if n else 0)
        for i, o in enumerate(sdata):
            struct.pack_into("<I", buf, off["str"] + 4 * i, o)
        for i, t in enumerate(self.types):
            struct.pack_into("<I", buf, off["type"] + 4 * i, self.strings.index(t))
        for i, (shorty, ret, _) in enumerate(self.protos):
            struct.pack_into("<III", buf, off["proto"] + 12 * i, self.strings.index(shorty), self.types.index(ret),
                             plists.get(i, 0))
        for i, (c, ty, nm) in enumerate(self.fields):
            struct.pack_into("<HHI", buf, off["field"] + 8 * i, c, ty, nm)
        for i, (c, p, nm) in enumerate(self.methods):
            struct.pack_into("<HHI", buf, off["meth"] + 8 * i, c, p, nm)
        for i, (cls, _) in enumerate(classes):
            struct.pack_into("<I", buf, off["cls"] + 32 * i, self.types.index(cls))
            struct.pack_into("<I", buf, off["cls"] + 32 * i + 24, cdata[i])
        return bytes(buf) + bytes(tail)


STR, BYTES, OBJ = "Ljava/lang/String;", "[B", "Ljava/lang/Object;"
CTX, AI = "Landroid/content/Context;", "Landroid/content/pm/ApplicationInfo;"
ZF, ZE, IS = "Ljava/util/zip/ZipFile;", "Ljava/util/zip/ZipEntry;", "Ljava/io/InputStream;"


def lit8(a, op, dst, src, lit):
    a.u += [op | (dst & 0xFF) << 8, ((lit & 0xFF) << 8) | (src & 0xFF)]


def arrlen(a, dst, src):
    a.u.append(0x21 | (((src & 0xF) << 4 | (dst & 0xF)) << 8))


def entry_bytes_to_code(d, a, breg):
    """v2:v3 = big-endian u64 of the byte[] in `breg`'s first 8 bytes; return 'ANS-%016X' of it."""
    a.const_wide(2, 0)
    a.const_wide(8, 0xFF)
    for i in range(8):
        a.const4(4, i)
        a.aget(0x48, 5, breg, 4)          # aget-byte
        a.unop(0x81, 6, 5)                # int-to-long v6:v7
        a.binop2(0xc0, 6, 8)              # and-long/2addr
        a.const16(10, 8)                  # (const/4 holds -8..7)
        a.binop2(0xc3, 2, 10)             # shl-long/2addr
        a.binop2(0xc1, 2, 6)              # or-long/2addr
    lv = d.m("Ljava/lang/Long;", "valueOf", "Ljava/lang/Long;", ["J"])
    fmt = d.m(STR, "format", STR, [STR, "[Ljava/lang/Object;"])
    a.invoke(0x71, lv, [2, 3])
    a.move_result_object(12)
    a.const4(9, 1)
    a.new_array(10, 9, d.t("[Ljava/lang/Object;"))
    a.const4(9, 0)
    a.aput(0x4d, 12, 10, 9)
    a.const_string(13, d.s("ANS-%016X"))
    a.invoke(0x71, fmt, [13, 10])
    a.move_result_object(14)
    a.return_object(14)


def reader_units(d, xor=0x5A):
    """A static (String)->byte[] reader that walks ApplicationInfo.splitSourceDirs with ZipFile, reads the
    entry it is given with readAllBytes, and XORs every byte with `xor` before it returns it."""
    a = S.Asm()
    gai = d.m(CTX, "getApplicationInfo", AI)
    ssd = d.f(AI, "[Ljava/lang/String;", "splitSourceDirs")
    zinit = d.m(ZF, "<init>", "V", [STR])
    gent = d.m(ZF, "getEntry", ZE, [STR])
    gis = d.m(ZF, "getInputStream", IS, [ZE])
    rab = d.m(IS, "readAllBytes", BYTES)
    a.const4(0, 0)
    a.invoke(0x6e, gai, [0])
    a.move_result_object(0)
    a.iop(0x54, 1, 0, ssd)                # iget-object v1, v0, splitSourceDirs
    arrlen(a, 2, 1)
    a.const4(3, 0)
    a.label("loop")
    a.if_test(0x35, 3, 2, "none")
    a.aget(0x46, 4, 1, 3)                 # aget-object
    a.new_instance(5, d.t(ZF))
    a.invoke(0x70, zinit, [5, 4])
    a.invoke(0x6e, gent, [5, 15])
    a.move_result_object(6)
    a.if_testz(0x38, 6, "next")
    a.invoke(0x6e, gis, [5, 6])
    a.move_result_object(7)
    a.invoke(0x6e, rab, [7])
    a.move_result_object(8)
    arrlen(a, 9, 8)
    a.const4(10, 0)
    a.label("xl")
    a.if_test(0x35, 10, 9, "done")
    a.aget(0x48, 11, 8, 10)
    lit8(a, 0xdf, 11, 11, xor)            # xor-int/lit8
    a.unop(0x8d, 11, 11)                  # int-to-byte
    a.aput(0x4f, 11, 8, 10)
    lit8(a, 0xd8, 10, 10, 1)
    a.goto16("xl")
    a.label("done")
    a.return_object(8)
    a.label("next")
    lit8(a, 0xd8, 3, 3, 1)
    a.goto16("loop")
    a.label("none")
    a.const4(0, 0)
    a.return_object(0)
    return a.finish()


def analysis_dex(reader="body", name="pull", asset="huntress_feature.bin", reflect=False, xor=0x5A, second=None,
                 lit=None):
    """An `analysis` app: Release.code() gets the asset's bytes from Store.<name>(asset) and turns their first 8
    bytes into the code. reader: 'body' (reader_units), 'none' (no body anywhere: a method the VM cannot run),
    'context' (a body that declines at Context.createContextForSplit)."""
    d = Dx()
    rd = d.m("Lcom/t/Store;", name, BYTES, [STR])
    if reader == "body":
        d.body(rd, reader_units(d, xor), 16, 1)
    elif reader == "first":
        # splitSourceDirs[0] only, no loop; a miss returns new byte[8]: the reading hangs on the splits' order
        a = S.Asm()
        a.const4(0, 0)
        a.invoke(0x6e, d.m(CTX, "getApplicationInfo", AI), [0])
        a.move_result_object(0)
        a.iop(0x54, 1, 0, d.f(AI, "[Ljava/lang/String;", "splitSourceDirs"))
        a.const4(3, 0)
        a.aget(0x46, 4, 1, 3)
        a.new_instance(5, d.t(ZF))
        a.invoke(0x70, d.m(ZF, "<init>", "V", [STR]), [5, 4])
        a.invoke(0x6e, d.m(ZF, "getEntry", ZE, [STR]), [5, 15])
        a.move_result_object(6)
        a.if_testz(0x38, 6, "zero")
        a.invoke(0x6e, d.m(ZF, "getInputStream", IS, [ZE]), [5, 6])
        a.move_result_object(7)
        a.invoke(0x6e, d.m(IS, "readAllBytes", BYTES), [7])
        a.move_result_object(8)
        a.return_object(8)
        a.label("zero")
        a.const16(9, 8)
        a.new_array(8, 9, d.t(BYTES))
        a.return_object(8)
        d.body(rd, a.finish(), 16, 1)
    elif reader == "context":
        a = S.Asm()
        ccs = d.m(CTX, "createContextForSplit", CTX, [STR])
        a.const4(0, 0)
        a.const_string(1, d.s("feature"))
        a.invoke(0x6e, ccs, [0, 1])
        a.move_result_object(2)
        if lit is not None:
            lit8(a, 0xdf, 3, 3, lit)      # xor-int/lit8 with `lit` (never reached: the body declines before it)
        a.return_object(2)
        d.body(rd, a.finish(), 16, 1)
    a = S.Asm()
    code = d.m("Lcom/t/Release;", "code", STR)
    a.const_string(0, d.s(asset))
    if reflect:
        fn = d.m("Ljava/lang/Class;", "forName", "Ljava/lang/Class;", [STR])
        gm = d.m("Ljava/lang/Class;", "getMethod", "Ljava/lang/reflect/Method;", [STR, "[Ljava/lang/Class;"])
        inv = d.m("Ljava/lang/reflect/Method;", "invoke", OBJ, [OBJ, "[Ljava/lang/Object;"])
        a.const_string(1, d.s("com.t.Store"))
        a.invoke(0x71, fn, [1])
        a.move_result_object(1)
        a.const_string(2, d.s(name))
        a.const4(3, 0)
        a.invoke(0x6e, gm, [1, 2, 3])
        a.move_result_object(1)
        a.const4(3, 1)
        a.new_array(4, 3, d.t("[Ljava/lang/Object;"))
        a.const4(3, 0)
        a.aput(0x4d, 0, 4, 3)
        a.invoke(0x6e, inv, [1, 3, 4])
        a.move_result_object(1)
    else:
        a.invoke(0x71, rd, [0])
        a.move_result_object(1)
        if second:
            # a second read whose bytes make the code (a reader's miss falls back to new byte[8])
            a.const_string(0, d.s(second))
            a.invoke(0x71, rd, [0])
            a.move_result_object(1)
    a.const_string(15, d.s("ANS-"))       # the entry's ANS literal (the discovery marker)
    entry_bytes_to_code(d, a, 1)
    d.body(code, a.finish(), 16, 0)
    return d.build()


def code_of(raw, xor=0):
    return "ANS-%016X" % int.from_bytes(bytes(b ^ xor for b in raw[:8]), "big")


def analysis_bundle(base_dex, feature=None, extra_splits=None, base_extra=None):
    doc = {"schema": "huntress.mobile.puzzle.v2", "day": 27, "codec": "analysis", "build": "t27"}
    base = {PZ: doc, "classes.dex": base_dex, **(base_extra or {})}
    splits = {"base.apk": zipped(base)}
    if feature is not None:
        splits["feature.apk"] = zipped(feature)
    for n, m in (extra_splits or {}).items():
        splits[n] = zipped(m)
    return zipped(splits)


# ---------------------------------------------------------------------------- [R] the saved Day 26 deliveries

def saved():
    if not DAY26.is_dir():
        print("SKIP [R] %s is not on disk" % DAY26)
        return
    fresh()
    for sub, glob in (("", "artifact/*.apks"), ("time_trial", "time_trial/artifact/*.apks"),
                      ("mastery", "mastery/artifact/*/*.ap*")):
        key = json.loads((DAY26 / sub / "key.json").read_text())["answers"]
        paths = sorted(DAY26.glob(glob))
        for i, path in enumerate(paths, 1):
            want = key.get("answer") or key.get("set%d.answer" % i)
            t = time.process_time()
            got, last = solve(path.read_bytes(), deliveries=len(paths) if sub == "mastery" else 1, name=path.name)
            took = time.process_time() - t
            check("[R] %s answers its key.json plain (%.1f ms of CPU)" % (path.name, took * 1000),
                  plain(got) and got == want and took < 0.25, (got, want, last.get("route"), took))
        if sub == "mastery":
            check("[R] the Mastery has ten sets, the tenth an .apks", len(paths) == 10 and paths[-1].suffix == ".apks",
                  [p.name for p in paths])
        else:
            # the bundle's reading reaches the runner's partial answers too (a cut solve still submits it)
            ctx = {"set": 1, "delivery": paths[0].read_bytes(), "delivery_name": paths[0].name,
                   "attempt": {"artifacts": [{}]}, "partial": {}}
            C.solve_set([dict(Q)], {}, ctx)
            check("[R] %s: the reading is in ctx['partial'] as well" % paths[0].name,
                  ctx["partial"].get("answer") == want, ctx["partial"])


# ---------------------------------------------------------------------------- [N] the real Time Trial, changed

def tt_splits():
    blob = (DAY26 / "time_trial" / "artifact" / "split_decision_time_trial.apks").read_bytes()
    z = zipfile.ZipFile(io.BytesIO(blob))
    return {n: {m: zipfile.ZipFile(io.BytesIO(z.read(n))).read(m) for m in zipfile.ZipFile(io.BytesIO(z.read(n))).namelist()}
            for n in z.namelist()}


def live_fix_reading(blob):
    """The Day 26 live fix's reading (a VM hook on a method NAMED readSplit*), as an oracle for a changed asset."""
    b = SB.bundle(blob)
    base = b.splits[b.base][1]
    dex = D.Dex(base["classes.dex"])
    feats = [m for i, (_, m) in enumerate(b.splits) if i != b.base]

    class HVM(D.VM):
        def _invoke(self, op, midx, args):
            cls, name = dex.mname.get(midx, dex.meth(midx))
            if name.lower().startswith("readsplit"):
                texts = [x for x in args if isinstance(x, str)]
                hits = [m["assets/" + texts[0]] for m in feats if "assets/" + texts[0] in m]
                if len(hits) != 1:
                    raise D._Decline("split asset")
                return [D._s8(x) for x in hits[0]]
            return D.VM._invoke(self, op, midx, args)

    ans = {i for i in range(dex.str_size) if dex.string(i) in ("ANS-", "ANS")}
    found = []
    for e in D._entry_midxs(dex, ans):
        out = HVM(dex, {}, {}).run(e, [None] * dex.code[e][1])
        if out not in found:
            found.append(out)
    return found[0] if len(found) == 1 else None


def renamed():
    if not DAY26.is_dir():
        print("SKIP [N] %s is not on disk" % DAY26)
        return
    fresh()
    want = json.loads((DAY26 / "time_trial" / "key.json").read_text())["answers"]["answer"]
    sp = tt_splits()
    base, feat = sp["base.apk"], sp["feature.apk"]
    check("[N] the real reader is named readSplit and reads huntress_feature.bin",
          b"\x09readSplit\x00" in base["classes.dex"] and "assets/huntress_feature.bin" in feat)
    for new in (b"loadAsset", b"openSplit", b"zzzzzzzzz"):
        dexb = base["classes.dex"].replace(b"\x09readSplit\x00", b"\x09" + new + b"\x00")
        blob = zipped({"base.apk": zipped({**base, "classes.dex": dexb}), "feature.apk": zipped(feat)})
        got, last = solve(blob)
        check("[N] readSplit renamed %s: the same code, plain, judged route" % new.decode(),
              plain(got) and got == want and last.get("route") == SB.AROUTE, (got, last.get("route"), last.get("why")))
    # the asset moved into a configuration split, and the feature split left with only its manifest
    blob = zipped({"base.apk": zipped(base), "feature.apk": zipped({k: v for k, v in feat.items() if not k.startswith("assets/")}),
                   "config.x86_64.apk": zipped({"AndroidManifest.xml": b"x", "assets/huntress_feature.bin":
                                                feat["assets/huntress_feature.bin"]})})
    got, last = solve(blob)
    check("[N] the asset in a config split: the same code, plain", plain(got) and got == want, (got, last.get("why")))
    # the same app as an .xapk and as an .aab module zip
    xapk = zipped({"manifest.json": {"package_name": "com.huntress", "split_apks": ["base.apk", "feature.apk"]},
                   "base.apk": zipped(base), "feature.apk": zipped(feat)})
    aab = {"BundleConfig.pb": b"\x00"}
    for mod, members in (("base", base), ("feature", feat)):
        for k, v in members.items():
            if k == "AndroidManifest.xml":
                aab["%s/manifest/%s" % (mod, k)] = v
            elif k.endswith(".dex"):
                aab["%s/dex/%s" % (mod, k)] = v
            elif k.startswith(("assets/", "lib/", "res/")):
                aab["%s/%s" % (mod, k)] = v
            else:
                aab["%s/root/%s" % (mod, k)] = v
    for kind, blob in (("xapk", xapk), ("aab", zipped(aab))):
        got, last = solve(blob, name="x." + kind)
        check("[N] the Time Trial as an .%s: the same code, plain" % kind, plain(got) and got == want,
              (got, last.get("split_bundle"), last.get("why")))
    # other asset bytes: the code the live fix's name hook gives on the same bundle
    for seed in ("v1", "v2", "v3"):
        raw = hashlib.sha256(seed.encode()).digest()[:16]
        blob = zipped({"base.apk": zipped(base), "feature.apk": zipped({**feat, "assets/huntress_feature.bin": raw})})
        got, _ = solve(blob)
        oracle = live_fix_reading(blob)
        check("[N] asset bytes %s: plain and equal to the live fix's reading" % seed,
              plain(got) and got == oracle and got != want, (got, oracle))
    # the asset repeated byte-for-byte is one deterministic reading; a different copy, and none: never plain
    same = zipped({"base.apk": zipped(base), "feature.apk": zipped(feat),
                   "config.en.apk": zipped({"assets/huntress_feature.bin": feat["assets/huntress_feature.bin"]})})
    got, last = solve(same)
    check("[N] identical asset bytes in two splits: the same code, plain", got == want, (got, last.get("route")))
    two = zipped({"base.apk": zipped(base), "feature.apk": zipped(feat),
                  "config.en.apk": zipped({"assets/huntress_feature.bin": bytes(16)})})
    got, last = solve(two)
    check("[N] the asset in two splits: not plain", not plain(got), (got, last.get("route")))
    none = zipped({"base.apk": zipped(base), "feature.apk": zipped({k: v for k, v in feat.items() if k.endswith(".xml")})})
    got, last = solve(none)
    check("[N] the asset in no split: not plain", not plain(got), (got, last.get("route")))
    # every split over the shipped reader's 1 MiB member bound (read_members keeps none of them): still read
    pad = hashlib.shake_256(b"pad").digest(1152 * 1024)          # 1.125 MiB that does not compress
    big = zipped({"base.apk": zipped({**base, "assets/pad.bin": pad}), "feature.apk": zipped({**feat, "assets/pad2.bin": pad})})
    check("[N] (both splits are over 1 MiB)", all(i.file_size > (1 << 20) for i in zipfile.ZipFile(io.BytesIO(big)).infolist()))
    got, last = solve(big)
    check("[N] both splits over 1 MiB (none kept by read_members): the same code, plain", plain(got) and got == want,
          (got, last.get("route")))
    # a second WHOLE package beside the app (its manifest names no split), or a split of another package: no
    # bundle, and the answer is exactly what it is with the module absent (the shipped reader's, as before)
    man = feat["AndroidManifest.xml"]
    pkg = re.search(rb"(?:v\x00(?:[0-9a-f]\x00){12})", man)
    other_pkg = man.replace(pkg.group(0), "v000000000000".encode("utf-16-le")) if pkg else None
    check("[N] the real feature manifest names split arena_feature and the base's package",
          SB._manifest_root(feat) and SB._manifest_root(feat).get("split") == "arena_feature"
          and SB._manifest_root(feat).get("package") == SB._manifest_root(base).get("package") and other_pkg)
    for label, fman in (("a whole second package (the base's manifest, no split)", base["AndroidManifest.xml"]),
                        ("a split of another package", other_pkg)):
        blob = zipped({"base.apk": zipped(base), "feature.apk": zipped({**feat, "AndroidManifest.xml": fman})})
        got = solve(blob)[0]
        keep, C.split_bundle = C.split_bundle, None
        try:
            without = solve(blob)[0]
        finally:
            C.split_bundle = keep
        check("[N] %s: no bundle, answered exactly as with the module absent" % label,
              SB.bundle(blob) is None and got == without and not plain(got), (got, without))
    # [S] a code in clear in the bundle's own readme, beside the splits: unsure under :second-code
    decoy = code_for("readme")
    blob = zipped({"base.apk": zipped(base), "feature.apk": zipped(feat), "README.txt": ("case " + decoy).encode()})
    got, last = solve(blob)
    k, opts = offered(got)
    check("[S] a decoy code in the bundle's own readme: unsure under analysis+split-asset:second-code, the reading first",
          k == SB.AKEY + SB.SECOND and opts[0] == (SB.AROUTE, want) and opts[1][1] == decoy, (got, last))


# ---------------------------------------------------------------------------- [X] [H] synthetic readers

def synthetic():
    fresh()
    raw = hashlib.sha256(b"feature-bytes").digest()[:16]
    feat = {"AndroidManifest.xml": b"m", "assets/huntress_feature.bin": raw}
    # [X] a renamed reader with a body: run as written, the XOR included. Its body is not the judged reader's shape
    # (Day 26's readSplit), so the exact code is unsure under analysis+split-asset:reader@shape-<sha256>, one option
    # (review 2 of a291433: these readings were PLAIN under the judged name)
    got, last = solve(analysis_bundle(analysis_dex("body", "pull", "assets/huntress_feature.bin"), feat))
    k_pull = offered(got)[0]
    check("[X] a reader `pull` that XORs after reading (another shape than the judged reader's): the exact code, unsure "
          "under analysis+split-asset:reader@shape-<sha256>, one option, judged route",
          reader_pick(got, code_of(raw, 0x5A)) and last.get("route") == SB.AROUTE, (got, code_of(raw, 0x5A), last))
    got, last = solve(analysis_bundle(analysis_dex("body", "fetchBlob", "assets/huntress_feature.bin", xor=0x13), feat))
    k_fetch = offered(got)[0]
    check("[X] another name and key (another literal, another shape): the exact code, unsure under another reader key",
          reader_pick(got, code_of(raw, 0x13)) and k_fetch != k_pull, (got, k_pull, last))
    got, last = solve(analysis_bundle(analysis_dex("body", "pull", "assets/huntress_feature.bin", reflect=True), feat))
    check("[X] the reader called by reflection (Class.forName/getMethod/invoke): the exact code, unsure under the same "
          "reader key (the caller touches no split API)", reader_pick(got, code_of(raw, 0x5A)) and offered(got)[0] == k_pull,
          (got, k_pull, last))
    cfg = {"config.en.apk": {"AndroidManifest.xml": b"c", "res/values.arsc": b"\x00"}}
    got, last = solve(analysis_bundle(analysis_dex("body", "pull", "assets/huntress_feature.bin"), feat, cfg))
    check("[X] a looping reader beside a config split without the asset: the same code in either order, unsure under "
          "the same reader key", reader_pick(got, code_of(raw, 0x5A)) and offered(got)[0] == k_pull, (got, last))
    got, last = solve(analysis_bundle(analysis_dex("first", "pull", "assets/huntress_feature.bin"), feat, cfg))
    check("[X] a reader that takes splitSourceDirs[0]: the reading hangs on the splits' order, None (withheld)",
          got is None and "order of the splits" in str(last.get("why")), (got, last.get("why")))
    got, last = solve(analysis_bundle(analysis_dex("first", "pull", "assets/huntress_feature.bin"), feat))
    check("[X] the same reader with one non-base split: no order to hang on, the exact code, unsure under its reader key",
          reader_pick(got, code_of(raw)), (got, last))
    got, last = solve(analysis_bundle(analysis_dex("first", "pull", "assets/huntress_feature.bin",
                                                   second="assets/huntress_missing.bin"), feat))
    check("[X] a split read, then an entry no split holds (the reader's default buffer would make a code): None",
          got is None and got != code_of(bytes(8)), (got, last.get("route"), last.get("why")))
    got, last = solve(analysis_bundle(analysis_dex("first", "pull", "assets/huntress_feature.bin",
                                                   second="assets/huntress_feature.bin"), feat))
    check("[X] the same two reads of an entry the split holds: the exact code, unsure under its reader key",
          reader_pick(got, code_of(raw)), (got, last))
    # a name the judge accepts for one reader key answers that reader's shape, and no other
    if k_pull:
        learn(k_pull, SB.AROUTE)
    got, _ = solve(analysis_bundle(analysis_dex("body", "pull", "assets/huntress_feature.bin"), feat))
    check("[X] the reader key's route accepted: that reader plain with the exact code",
          bool(k_pull) and got == code_of(raw, 0x5A), (k_pull, got))
    got, _ = solve(analysis_bundle(analysis_dex("body", "fetchBlob", "assets/huntress_feature.bin", xor=0x13), feat))
    check("[X] ... and the reader of another shape is still unsure under its own key",
          reader_pick(got, code_of(raw, 0x13)) and offered(got)[0] == k_fetch, got)
    fresh()
    # [H] the hook
    hk = SB.AKEY + SB.HOOKED
    keys = {}
    raw2 = hashlib.sha256(b"feature-bytes-2").digest()[:16]
    feat2 = {"AndroidManifest.xml": b"m", "assets/huntress_feature.bin": raw2}
    for kind in ("none", "context"):
        fresh()
        got, last = solve(analysis_bundle(analysis_dex(kind, "loadFeature"), feat))
        k, opts = offered(got)
        keys[kind] = k
        check("[H] reader %s: hooked, unsure under %s@shape-<sha256> with the asset's code" % (kind, hk),
              str(k).startswith(hk + "@shape-") and len(k) == len(hk) + 71
              and opts == [(SB.AROUTE + SB.HOOKED, code_of(raw))], (got, last))
        learn(k, SB.AROUTE + SB.HOOKED)
        got, _ = solve(analysis_bundle(analysis_dex(kind, "loadFeature"), feat))
        check("[H] reader %s: plain once the hooked name is accepted for its shape" % kind, got == code_of(raw), got)
        # the same app with other asset bytes: the same key, so plain with the new code
        got, _ = solve(analysis_bundle(analysis_dex(kind, "loadFeature"), feat2))
        check("[H] reader %s, the same dex with other asset bytes: the same key, plain with the new code" % kind,
              got == code_of(raw2), got)
        got, _ = solve(analysis_bundle(analysis_dex(kind, "openSplit"), feat2))
        if kind == "context":
            # a variant of the same template (the reader renamed, other asset bytes): the same shape key, so plain
            check("[H] reader context renamed, other asset bytes: the same shape key, plain with the new code",
                  got == code_of(raw2), got)
        else:
            # a bodiless reader shows no behaviour: its key binds the calling dex's bytes (review of 9c1f923), so
            # a renamed one (another dex) is unsure again under another key
            k2, opts2 = offered(got)
            check("[H] a bodiless reader renamed (another dex): another key, unsure with the new code",
                  str(k2).startswith(hk + "@shape-") and k2 != k and opts2 == [(SB.AROUTE + SB.HOOKED, code_of(raw2))],
                  (got, k))
    check("[H] a bodiless reader and a declining body are two shapes (two keys)",
          keys["none"] != keys["context"] and all(keys.values()), keys)
    fresh()
    learn(keys["none"], SB.AROUTE + SB.HOOKED)
    got, _ = solve(analysis_bundle(analysis_dex("context", "loadFeature"), feat))
    check("[H] a hooked name accepted for one reader shape does not answer another shape plain",
          not plain(got) and offered(got)[0] == keys["context"], got)
    fresh()
    check("[H] the judged analysis+split-asset name alone does not make a hooked reading plain",
          labels.state(SB.AKEY)["accepted"] == SB.AROUTE
          and not plain(solve(analysis_bundle(analysis_dex("none", "loadFeature"), feat))[0]))
    got, last = solve(analysis_bundle(analysis_dex("none", "loadFeature"), feat,
                                      {"config.en.apk": {"assets/huntress_feature.bin": raw}}))
    check("[H] identical asset bytes in two splits: one hooked reading",
          offered(got)[1] == [(SB.AROUTE + SB.HOOKED, code_of(raw))], (got, last.get("route")))
    got, last = solve(analysis_bundle(analysis_dex("none", "loadFeature"), feat,
                                      {"config.en.apk": {"assets/huntress_feature.bin": bytes(16)}}))
    check("[H] different asset bytes in two splits: no hook, nothing offered", got is None, (got, last.get("route")))
    got, last = solve(analysis_bundle(analysis_dex("none", "loadFeature"), feat,
                                      base_extra={"assets/huntress_feature.bin": raw}))
    check("[H] the asset in the base too: no hook", got is None, (got, last.get("route")))
    # a body for loadFeature in another split's dex: B does not hook it (C runs it)
    other = Dx()
    om = other.m("Lcom/t/Store;", "loadFeature", BYTES, [STR])
    a = S.Asm()
    a.const4(0, 3)
    a.new_array(1, 0, other.t(BYTES))
    a.return_object(1)
    other.body(om, a.finish(), 4, 1)
    got, last = solve(analysis_bundle(analysis_dex("none", "loadFeature"), {**feat, "classes.dex": other.build()}))
    check("[H] a body in the feature split's dex: not hooked (the 3-byte array it returns cannot give a code)",
          got is None, (got, last.get("route"), last.get("why")))


# ---------------------------------------------------------------------------- [P] codec split

def split_doc(parts, order, **more):
    return {"schema": "huntress.mobile.puzzle.v1", "day": 27, "codec": "split", "data": "", "parts": parts,
            "order": order, **more}


def part(i, v, **more):
    return {"codec": "split", "day": 27, "feature": "arena_feature", "part": v, "part_index": i, **more}


def split_bundle(doc, splits, kind="apks"):
    base = {"AndroidManifest.xml": b"m", PZ: doc, "classes.dex": b"dex\n035\x00"}
    if kind == "aab":
        out = {"base/manifest/AndroidManifest.xml": b"m", "base/assets/huntress_puzzle.json": doc,
               "base/dex/classes.dex": b"dex\n035\x00", "BundleConfig.pb": b"\x00"}
        for n, m in splits.items():
            mod = n[:-4]
            out[mod + "/manifest/AndroidManifest.xml"] = b"m"
            for k, v in m.items():
                out[mod + "/" + k] = v
        return zipped(out)
    out = {"base.apk": zipped(base)}
    out.update({n: zipped({"AndroidManifest.xml": b"m", **m}) for n, m in splits.items()})
    if kind == "xapk":
        out["manifest.json"] = {"package_name": "com.t", "split_apks": [{"file": n} for n in out]}
    return zipped(out)


def split_codec():
    fresh()
    want = code_for("P1")                       # ANS-XXXXXXXXXXXXXXXX
    c = [want[:6], want[6:13], want[13:]]       # the code's three pieces, in reading order
    order = [1, 2, 0]                           # by-order: by[order[i]] = parts[i]
    parts = [c[order[i]] for i in range(3)]     # so the by-order reading is the code (take-order is not)
    shown = [parts[0], "", parts[2]]
    got, last = solve(split_bundle(split_doc(shown, order), {"config.en.apk": {"assets/part.json": part(1, parts[1])}}))
    by = [None] * 3
    for i, k in enumerate(order):
        by[k] = parts[i]
    check("[P] a part in a config split: the by-order code, plain (judged)", plain(got) and got == "".join(by),
          (got, "".join(by), last))
    # two empty parts in two splits
    got, last = solve(split_bundle(split_doc(["", parts[1], ""], order),
                                   {"feature.apk": {"assets/a.json": part(0, parts[0])},
                                    "config.xxhdpi.apk": {"assets/b.json": part(2, parts[2])}}))
    check("[P] two empty parts filled from two splits: plain", plain(got) and got == "".join(by), (got, last))
    for kind in ("xapk", "aab"):
        got, last = solve(split_bundle(split_doc(shown, order), {"feature.apk": {"assets/part.json": part(1, parts[1])}},
                                       kind=kind))
        check("[P] the %s layout: plain" % kind, plain(got) and got == "".join(by), (got, last))
    # both order readings valid: the judged by-order plain; on a masked ledger both, by-order first
    q = ["ANS-", "0123", "4567", "89ABCDEF"]
    order4 = [0, 2, 3, 1]
    by4, take4 = [None] * 4, [q[k] for k in order4]
    for i, k in enumerate(order4):
        by4[k] = q[i]
    blob = split_bundle(split_doc([q[0], "", q[2], ""], order4),
                        {"feature.apk": {"assets/x.json": part(1, q[1])}, "config.de.apk": {"assets/y.json": part(3, q[3])}})
    got, _ = solve(blob)
    check("[P] both order readings are codes: the judged by-order one plain", got == "".join(by4) != "".join(take4),
          (got, "".join(by4), "".join(take4)))
    fresh(mask=SB.KEY)
    got, _ = solve(blob)
    check("[P] on a ledger that has not judged the key: both readings, by-order first",
          offered(got) == (SB.KEY, [(SB.BY, "".join(by4)), (SB.TAKE, "".join(take4))]), got)
    fresh()
    duplicate_same = {"feature.apk": {"assets/a.json": part(1, parts[1])},
                      "config.en.apk": {"assets/b.json": part(1, parts[1])}}
    got, _ = solve(split_bundle(split_doc(shown, order), duplicate_same))
    check("[P] an identical duplicate part_index is order-independent and plain", got == want, got)
    bad = {
        "a differing duplicate part_index": ({"feature.apk": {"assets/a.json": part(1, parts[1])},
                                              "config.en.apk": {"assets/b.json": part(1, "DIFFERENT")}}, shown),
        "a part over a non-empty part": ({"feature.apk": {"assets/a.json": part(0, "ANS-FFFF")}}, shown),
        "an empty part left": ({"feature.apk": {"assets/a.json": part(1, parts[1])}}, ["", "", parts[2]]),
        "a part index out of range": ({"feature.apk": {"assets/a.json": part(5, parts[1])}}, shown),
        "a part document naming another codec": ({"feature.apk": {"assets/a.json": part(1, parts[1], codec="xor")}}, shown),
    }
    for label, (splits, doc_parts) in bad.items():
        got, last = solve(split_bundle(split_doc(doc_parts, order), splits))
        check("[P] %s: None (withheld)" % label, got is None and last.get("why"), (got, last.get("route")))
    # a part document in the base split
    base_part = zipped({"base.apk": zipped({PZ: split_doc(shown, order), "assets/p.json": part(1, parts[1])}),
                        "feature.apk": zipped({"AndroidManifest.xml": b"m"})})
    got, last = solve(base_part)
    check("[P] a part document in the base split: None (withheld)", got is None, (got, last.get("route")))
    # two puzzle documents: not this module's, and never plain
    two = zipped({"base.apk": zipped({PZ: split_doc(shown, order)}),
                  "feature.apk": zipped({PZ: split_doc([want[:6], "", want[13:]], order), "assets/a.json": part(1, parts[1])})})
    got, last = solve(two)
    check("[P] two puzzle documents: split_bundle declines and the answer is not plain",
          SB.solve(two) is None and not plain(got), (got, last.get("route")))
    # extra fields: unsure under :extra-fields
    got, _ = solve(split_bundle(split_doc(shown, order, hint="use the feature split"),
                                {"feature.apk": {"assets/a.json": part(1, parts[1])}}))
    check("[P] a document with an extra field: unsure under %s:extra-fields" % SB.KEY,
          offered(got) == (SB.KEY + SB.EXTRA, [(SB.BY, "".join(by))]), got)
    got, _ = solve(split_bundle(split_doc(shown, order), {"feature.apk": {"assets/a.json": part(1, parts[1], decoy=False)}}))
    check("[P] a part document with a flag beside its part: unsure under :extra-fields",
          offered(got) == (SB.KEY + SB.EXTRA, [(SB.BY, "".join(by))]), got)
    # [S] a code in clear elsewhere: second-code
    decoy = code_for("decoy")
    got, last = solve(split_bundle(split_doc(shown, order), {"feature.apk": {"assets/a.json": part(1, parts[1]),
                                                                              "assets/notes.txt": decoy.encode()}}))
    k, opts = offered(got)
    check("[S] a decoy code in clear in the feature split: unsure under :second-code, the reading first",
          k == SB.KEY + SB.SECOND and opts[0] == (SB.BY, "".join(by)) and opts[1][1] == decoy, (got, last))


# ---------------------------------------------------------------------------- [C] row 532: across the splits

def feature_dex(value):
    d = S.DexBuilder()
    a = S.Asm()
    a.const_wide(0, value & S.M64)
    S.emit_tail_format(a, d, 0, "ANS-%016X")
    d.add_class([(d.m("Lcom/huntress/F;", "transform", "L"), a.finish(), 24, 5)])
    return d.build()


def base_reflect_dex():
    d = S.DexBuilder()
    a = S.Asm()
    fn = d.m("Ljava/lang/Class;", "forName", "LL")
    gm = d.m("Ljava/lang/Class;", "getMethod", "LLL")
    inv = d.m("Ljava/lang/reflect/Method;", "invoke", "LLL")
    a.const_string(2, d.s("com.huntress.F"))
    a.invoke(0x71, fn, [2])
    a.move_result_object(8)
    a.const_string(3, d.s("transform"))
    a.invoke(0x6e, gm, [8, 3])
    a.move_result_object(9)
    a.const4(4, 0)
    a.const4(5, 0)
    a.invoke(0x6e, inv, [9, 4, 5])
    a.move_result_object(6)
    a.const_string(7, d.s("ANS-"))
    a.return_object(6)
    d.add_class([(d.m("Lcom/huntress/C;", "run", "L"), a.finish(), 24, 5)])
    return d.build()


def across():
    fresh()
    V = 0x1122334455667788
    want = "ANS-%016X" % V
    blob = analysis_bundle(base_reflect_dex(), {"classes.dex": feature_dex(V)})
    got, last = solve(blob)
    check("[C] a reflected method in the feature split's dex: unsure under %s" % SB.AX_KEY,
          offered(got) == (SB.AX_KEY, [(SB.AX_ROUTE, want)]), (got, last))
    learn(SB.AX_KEY, SB.AX_ROUTE)
    check("[C] plain once the across-splits name is accepted", solve(blob)[0] == want)
    fresh()
    amb = analysis_bundle(base_reflect_dex(), {"classes.dex": feature_dex(V)},
                          {"feature2.apk": {"classes.dex": feature_dex(V ^ 0xFF)}})
    got, last = solve(amb)
    check("[C] the reflected method in two splits' dexes: None (withheld)", got is None, (got, last.get("route")))
    if not DAY25_SO.is_dir():
        print("SKIP [C] native: %s is not on disk" % DAY25_SO)
        return
    members = {str(f.relative_to(DAY25_SO)): f.read_bytes() for f in DAY25_SO.rglob("*") if f.is_file()}
    truth = D.recover(members)
    so = {k: v for k, v in members.items() if k.endswith(".so")}
    rest = {k: v for k, v in members.items() if not k.endswith(".so")}
    check("[C] the Day 25 delivery's shipped reading is a code, with an x86-64 native", bool(truth) and so
          and all(D._parse_so(v) and next(iter(D._parse_so(v).values()))[0] == 62 for v in so.values()), (truth, list(so)))
    nat = zipped({"base.apk": zipped(rest), "config.x86_64.apk": zipped(so)})
    got, last = solve(nat)
    check("[C] the x86-64 native in a config split: unsure under %s, the shipped reading's code" % SB.AX_KEY,
          offered(got) == (SB.AX_KEY, [(SB.AX_ROUTE, truth)]), (got, truth, last))
    # the same native in two config splits, one leg changed: ambiguous, None
    name, body = next(iter(so.items()))
    syms = D._parse_so(body)
    sym = max((s for s in syms if s.startswith("Java_")), key=lambda s: len(syms[s][1]), default=None) \
        or max(syms, key=lambda s: len(syms[s][1]))
    em, codeb = syms[sym]
    at = body.find(codeb) + len(codeb) // 2
    changed = body[:at] + bytes([body[at] ^ 0x01]) + body[at + 1:]
    amb = zipped({"base.apk": zipped(rest), "config.x86_64.apk": zipped(so),
                  "config.x86_64_b.apk": zipped({name: changed})})
    got, last = solve(amb)
    check("[C] one native symbol with two different x86-64 legs: None (withheld)", got is None, (got, last.get("route")))
    same = zipped({"base.apk": zipped(rest), "config.x86_64.apk": zipped(so), "config.x86_64_b.apk": zipped(so)})
    got, _ = solve(same)
    check("[C] the same leg in two splits is no ambiguity", offered(got) == (SB.AX_KEY, [(SB.AX_ROUTE, truth)]), got)


# ---------------------------------------------------------------------------- [U] a single .apk is unchanged

def unchanged():
    fresh()
    shapes = []
    if DAY26.is_dir():
        shapes += [p.read_bytes() for p in sorted(DAY26.glob("mastery/artifact/*/*.apk"))[:3]]
    want = code_for("U")
    shapes.append(zipped({PZ: split_doc([want[:9], want[9:]], [0, 1])}))
    shapes.append(zipped({PZ: {"schema": "huntress.mobile.puzzle.v1", "codec": "reverse", "data": want[::-1]}}))
    shapes.append(zipped({"app.apk": zipped({PZ: {"schema": "huntress.mobile.puzzle.v1", "codec": "reverse",
                                                  "data": want[::-1]}}), "readme.txt": b"notes"}))
    for i, blob in enumerate(shapes):
        with_mod = solve(blob)[0]
        keep, C.split_bundle = C.split_bundle, None
        try:
            without = solve(blob)[0]
        finally:
            C.split_bundle = keep
        check("[U] shape %d answers exactly as with the module absent" % i, with_mod == without, (with_mod, without))
    two = zipped({"base.apk": zipped({PZ: {"codec": "split"}}), "feature.apk": zipped({"a": b"b"})})
    aab = zipped({"base/manifest/AndroidManifest.xml": b"m", "feature/manifest/AndroidManifest.xml": b"m"})
    check("[U] candidate(): a plain APK, one app.apk in a zip, a text and nothing are no bundle; two splits and two "
          "modules are", not SB.candidate(shapes[-2]) and not SB.candidate(shapes[-1]) and not SB.candidate(b"PK junk")
          and not SB.candidate(b"") and not SB.candidate(None) and SB.candidate(two) and SB.candidate(aab))
    t = time.process_time()
    for _ in range(200):
        SB.solve(shapes[-2])
    each = (time.process_time() - t) / 200
    check("[U] a plain APK costs split_bundle.solve under a millisecond of CPU (%.3f ms; codec_search does not even "
          "call it for one)" % (each * 1000), each < 0.001, each)


# ---------------------------------------------------------------------------- [F] the review of 9c1f923, fixed

def fixed_index_units(d, index):
    """splitSourceDirs[index] only, no loop; a miss returns new byte[8] (the 'first' reader at any index)."""
    a = S.Asm()
    a.const4(0, 0)
    a.invoke(0x6e, d.m(CTX, "getApplicationInfo", AI), [0])
    a.move_result_object(0)
    a.iop(0x54, 1, 0, d.f(AI, "[Ljava/lang/String;", "splitSourceDirs"))
    a.const4(3, index)
    a.aget(0x46, 4, 1, 3)
    a.new_instance(5, d.t(ZF))
    a.invoke(0x70, d.m(ZF, "<init>", "V", [STR]), [5, 4])
    a.invoke(0x6e, d.m(ZF, "getEntry", ZE, [STR]), [5, 15])
    a.move_result_object(6)
    a.if_testz(0x38, 6, "zero")
    a.invoke(0x6e, d.m(ZF, "getInputStream", IS, [ZE]), [5, 6])
    a.move_result_object(7)
    a.invoke(0x6e, d.m(IS, "readAllBytes", BYTES), [7])
    a.move_result_object(8)
    a.return_object(8)
    a.label("zero")
    a.const16(9, 8)
    a.new_array(8, 9, d.t(BYTES))
    a.return_object(8)
    return a.finish()


def two_reads_app(units_of, first, second=None):
    """Release.code(): the bytes of Store.pull(first), then (when given) of Store.pull(second), make the code."""
    d = Dx()
    rd = d.m("Lcom/t/Store;", "pull", BYTES, [STR])
    d.body(rd, units_of(d), 16, 1)
    a = S.Asm()
    code = d.m("Lcom/t/Release;", "code", STR)
    for asset in [first] + ([second] if second else []):
        a.const_string(0, d.s(asset))
        a.invoke(0x71, rd, [0])
        a.move_result_object(1)
    a.const_string(15, d.s("ANS-"))
    entry_bytes_to_code(d, a, 1)
    d.body(code, a.finish(), 16, 0)
    return d.build()


def field_reader_units(d, holder, cls, typ, field):
    """reader_units' loop, with every byte XORed with an int field of the ApplicationInfo (holder 'appinfo') or
    of the ZipEntry it found (holder 'entry'): a field the framework model does not set."""
    a = S.Asm()
    fld = d.f(cls, typ, field)
    a.const4(0, 0)
    a.invoke(0x6e, d.m(CTX, "getApplicationInfo", AI), [0])
    a.move_result_object(0)
    a.const4(12, 0)
    if holder == "appinfo":
        a.iop(0x52, 12, 0, fld)               # iget v12, v0, ApplicationInfo.<field>
    a.iop(0x54, 1, 0, d.f(AI, "[Ljava/lang/String;", "splitSourceDirs"))
    arrlen(a, 2, 1)
    a.const4(3, 0)
    a.label("loop")
    a.if_test(0x35, 3, 2, "none")
    a.aget(0x46, 4, 1, 3)
    a.new_instance(5, d.t(ZF))
    a.invoke(0x70, d.m(ZF, "<init>", "V", [STR]), [5, 4])
    a.invoke(0x6e, d.m(ZF, "getEntry", ZE, [STR]), [5, 15])
    a.move_result_object(6)
    a.if_testz(0x38, 6, "next")
    if holder == "entry":
        a.iop(0x52, 12, 6, fld)               # iget v12, v6, ZipEntry.<field>
    a.invoke(0x6e, d.m(ZF, "getInputStream", IS, [ZE]), [5, 6])
    a.move_result_object(7)
    a.invoke(0x6e, d.m(IS, "readAllBytes", BYTES), [7])
    a.move_result_object(8)
    arrlen(a, 9, 8)
    a.const4(10, 0)
    a.label("xl")
    a.if_test(0x35, 10, 9, "done")
    a.aget(0x48, 11, 8, 10)
    a.binop2(0xb7, 11, 12)                    # xor-int/2addr v11, v12
    a.unop(0x8d, 11, 11)
    a.aput(0x4f, 11, 8, 10)
    lit8(a, 0xd8, 10, 10, 1)
    a.goto16("xl")
    a.label("done")
    a.return_object(8)
    a.label("next")
    lit8(a, 0xd8, 3, 3, 1)
    a.goto16("loop")
    a.label("none")
    a.const4(0, 0)
    a.return_object(0)
    return a.finish()


def index_xor_units(d, mask):
    """reader_units' loop, every byte XORed with (the index it found its entry at & mask): the reading hangs on
    where in splitSourceDirs the holder stands."""
    a = S.Asm()
    a.const4(0, 0)
    a.invoke(0x6e, d.m(CTX, "getApplicationInfo", AI), [0])
    a.move_result_object(0)
    a.iop(0x54, 1, 0, d.f(AI, "[Ljava/lang/String;", "splitSourceDirs"))
    arrlen(a, 2, 1)
    a.const4(3, 0)
    a.label("loop")
    a.if_test(0x35, 3, 2, "none")
    a.aget(0x46, 4, 1, 3)
    a.new_instance(5, d.t(ZF))
    a.invoke(0x70, d.m(ZF, "<init>", "V", [STR]), [5, 4])
    a.invoke(0x6e, d.m(ZF, "getEntry", ZE, [STR]), [5, 15])
    a.move_result_object(6)
    a.if_testz(0x38, 6, "next")
    a.invoke(0x6e, d.m(ZF, "getInputStream", IS, [ZE]), [5, 6])
    a.move_result_object(7)
    a.invoke(0x6e, d.m(IS, "readAllBytes", BYTES), [7])
    a.move_result_object(8)
    lit8(a, 0xdd, 12, 3, mask)                # and-int/lit8 v12, v3, mask
    arrlen(a, 9, 8)
    a.const4(10, 0)
    a.label("xl")
    a.if_test(0x35, 10, 9, "done")
    a.aget(0x48, 11, 8, 10)
    a.binop2(0xb7, 11, 12)
    a.unop(0x8d, 11, 11)
    a.aput(0x4f, 11, 8, 10)
    lit8(a, 0xd8, 10, 10, 1)
    a.goto16("xl")
    a.label("done")
    a.return_object(8)
    a.label("next")
    lit8(a, 0xd8, 3, 3, 1)
    a.goto16("loop")
    a.label("none")
    a.const4(0, 0)
    a.return_object(0)
    return a.finish()


def handoff_bundle(raw):
    """The base dex gets the ApplicationInfo and hands it to Store.pull(ApplicationInfo, String), whose only body is
    in the feature split's dex; field 0 is splitSourceDirs in the base dex and targetSdkVersion in the feature's."""
    fd = Dx()
    fd.f(AI, "I", "targetSdkVersion")
    rd = fd.m("Lcom/t/Store;", "pull", BYTES, [AI, STR])
    a = S.Asm()
    a.iop(0x54, 1, 14, fd.f(AI, "[Ljava/lang/String;", "splitSourceDirs"))
    arrlen(a, 2, 1)
    a.const4(3, 0)
    a.label("loop")
    a.if_test(0x35, 3, 2, "none")
    a.aget(0x46, 4, 1, 3)
    a.new_instance(5, fd.t(ZF))
    a.invoke(0x70, fd.m(ZF, "<init>", "V", [STR]), [5, 4])
    a.invoke(0x6e, fd.m(ZF, "getEntry", ZE, [STR]), [5, 15])
    a.move_result_object(6)
    a.if_testz(0x38, 6, "next")
    a.invoke(0x6e, fd.m(ZF, "getInputStream", IS, [ZE]), [5, 6])
    a.move_result_object(7)
    a.invoke(0x6e, fd.m(IS, "readAllBytes", BYTES), [7])
    a.move_result_object(8)
    a.return_object(8)
    a.label("next")
    lit8(a, 0xd8, 3, 3, 1)
    a.goto16("loop")
    a.label("none")
    a.const4(0, 0)
    a.return_object(0)
    fd.body(rd, a.finish(), 16, 2)
    bd = Dx()
    bd.f(AI, "[Ljava/lang/String;", "splitSourceDirs")
    brd = bd.m("Lcom/t/Store;", "pull", BYTES, [AI, STR])
    a = S.Asm()
    code = bd.m("Lcom/t/Release;", "code", STR)
    a.const4(0, 0)
    a.invoke(0x6e, bd.m(CTX, "getApplicationInfo", AI), [0])
    a.move_result_object(2)
    a.const_string(0, bd.s("assets/a.bin"))
    a.invoke(0x71, brd, [2, 0])
    a.move_result_object(1)
    a.const_string(15, bd.s("ANS-"))
    entry_bytes_to_code(bd, a, 1)
    bd.body(code, a.finish(), 16, 0)
    return analysis_bundle(bd.build(), {"AndroidManifest.xml": b"m", "classes.dex": fd.build(), "assets/a.bin": raw})


def looping_dex():
    d = Dx()
    a = S.Asm()
    code = d.m("Lcom/t/Release;", "code", STR)
    a.const_string(15, d.s("ANS-"))
    a.const4(0, 0)
    a.label("top")
    lit8(a, 0xd8, 0, 0, 1)
    a.goto16("top")
    d.body(code, a.finish(), 16, 0)
    return d.build()


def review_fixes():
    fresh()
    M = {"AndroidManifest.xml": b"m"}
    raw = hashlib.sha256(b"k").digest()[:16]
    rawA = hashlib.sha256(b"A").digest()[:16]
    zero = code_of(bytes(8))
    first = lambda d: fixed_index_units(d, 0)   # noqa: E731
    # 1. a getEntry miss never made good: the reader's fallback buffer computes from bytes the bundle does not show
    cases = {
        "one split holds k.bin, only the base holds a.bin":
            analysis_bundle(two_reads_app(first, "assets/k.bin", "assets/a.bin"), {**M, "assets/k.bin": raw},
                            base_extra={"assets/a.bin": rawA}),
        "two splits (the order runs too), a.bin only in the base":
            analysis_bundle(two_reads_app(first, "assets/k.bin", "assets/a.bin"), {**M, "assets/k.bin": raw},
                            extra_splits={"config.en.apk": {**M, "assets/o.bin": b"x"}}, base_extra={"assets/a.bin": rawA}),
        "three splits, a.bin in the middle one":
            analysis_bundle(two_reads_app(first, "assets/k.bin", "assets/a.bin"), {**M, "assets/k.bin": raw},
                            extra_splits={"config.en.apk": {**M, "assets/a.bin": rawA},
                                          "config.fr.apk": {**M, "assets/z.bin": b"z"}}),
    }
    for label, blob in cases.items():
        got, last = solve(blob)
        check("[F1] a split read, then a miss the reader never makes good (%s): never plain, never the zero code"
              % label, not plain(got) and got != zero and zero not in str(got), (got, last.get("route")))
    # a miss in one split that the loop makes good in the next: plain (the looping reader, the asset in the second)
    feat = {**M, "assets/huntress_feature.bin": raw}
    blob = analysis_bundle(analysis_dex("body", "pull", "assets/huntress_feature.bin"), {**M, "assets/x.bin": b"x"},
                           extra_splits={"config.en.apk": feat})
    got, last = solve(blob)
    check("[F1] a looping reader that misses in one split and opens the entry in the next: the exact code (unsure "
          "under its reader key, review 2)", reader_pick(got, code_of(raw, 0x5A)), (got, last.get("why")))
    # 2. the order: a fixed middle index with three or four non-base splits (a reversal leaves index 1 of 3 in place)
    for n, mid in ((3, 1), (4, 1), (4, 2)):
        extra = {"config.s%d.apk" % i: {**M, "assets/s%d.bin" % i: bytes([i]) * 8} for i in range(n - 1)}
        names = ["feature.apk"] + list(extra)
        holder = names[mid]
        splits = {k: dict(v) for k, v in extra.items()}
        fsplit = {**M, "assets/x.bin": b"x"}
        (splits[holder] if holder in splits else fsplit)["assets/a.bin"] = rawA
        blob = analysis_bundle(two_reads_app(lambda d: fixed_index_units(d, mid), "assets/a.bin"), fsplit,
                               extra_splits=splits)
        got, last = solve(blob)
        check("[F2] %d non-base splits, a reader that takes splitSourceDirs[%d] (it holds the asset): None, withheld "
              "for the order" % (n, mid), got is None and "order of the splits" in str(last.get("why")),
              (got, last.get("why")))
        blob = analysis_bundle(analysis_dex("body", "pull", "assets/a.bin"), fsplit, extra_splits=splits)
        got, last = solve(blob)
        check("[F2] %d non-base splits, a looping reader of the same asset: the same code in every arrangement (unsure "
              "under its reader key, review 2)" % n, reader_pick(got, code_of(rawA, 0x5A)), (got, last.get("why")))
    check("[F2] _orders: every permutation of 2 and 3, the 8 of the dihedral group of 4 (less the identity)",
          len(SB._orders(2)) == 1 and len(SB._orders(3)) == 5 and len(SB._orders(4)) == 7 and SB._orders(1) == [])
    # a looping reader that mixes in the index it found its entry at: withheld wherever the holder stands
    plains = []
    for n in (2, 3):
        for hold in range(n):
            extra = {"config.s%d.apk" % i: {**M, "assets/s%d.bin" % i: b"q"} for i in range(n - 1)}
            names = ["feature.apk"] + list(extra)
            fs = {**M, "assets/x.bin": b"x"}
            (extra[names[hold]] if names[hold] in extra else fs)["assets/a.bin"] = rawA
            got, _ = solve(analysis_bundle(two_reads_app(lambda d: index_xor_units(d, 1), "assets/a.bin"), fs,
                                           extra_splits=extra))
            if plain(got):
                plains.append((n, hold, got))
    check("[F2] a reader that XORs with the index of its hit, 2 and 3 non-base splits, every holder: never plain",
          not plains, plains)
    # 3. ApplicationInfo fields the model does not set (and fields of a ZipEntry it hands out) decline, never read 0
    for holder, cls, typ, field in (("appinfo", AI, "I", "targetSdkVersion"), ("appinfo", AI, "I", "flags"),
                                    ("appinfo", AI, "I", "uid"), ("entry", ZE, "I", "method")):
        d = Dx()
        rd = d.m("Lcom/t/Store;", "pull", BYTES, [STR])
        d.body(rd, field_reader_units(d, holder, cls, typ, field), 16, 1)
        a = S.Asm()
        code = d.m("Lcom/t/Release;", "code", STR)
        a.const_string(0, d.s("assets/huntress_feature.bin"))
        a.invoke(0x71, rd, [0])
        a.move_result_object(1)
        a.const_string(15, d.s("ANS-"))
        entry_bytes_to_code(d, a, 1)
        d.body(code, a.finish(), 16, 0)
        got, last = solve(analysis_bundle(d.build(), feat))
        k, _ = offered(got)
        check("[F3] a reader that XORs the asset with %s.%s (not modelled): not plain (at most B's hooked pick)"
              % ("ApplicationInfo" if holder == "appinfo" else "ZipEntry", field),
              not plain(got) and (got is None or str(k).startswith(SB.AKEY + SB.HOOKED + "@shape-")), (got, last))
    # the field of ApplicationInfo is named by the dex that runs the iget: index 0 is splitSourceDirs in one dex and
    # targetSdkVersion in another
    da, db = Dx(), Dx()
    da.f(AI, "[Ljava/lang/String;", "splitSourceDirs")
    db.f(AI, "I", "targetSdkVersion")
    for dd in (da, db):
        m = dd.m("Lcom/t/A;", "x", "V")
        dd.body(m, [0x000e], 1, 0)
    dxa, dxb = D.Dex(da.build()), D.Dex(db.build())
    b = SB.bundle(analysis_bundle(analysis_dex("body"), feat))
    w = SB._World(D, b, [(0, dxa), (1, dxb)], {}, {})
    o = w.appinfo(dxa)
    w.cur[:] = [dxa]
    ok_a = o.fields.get(0) == ["/data/app/~~huntress/feature.apk"] and w.split_dirs_read
    w.cur[:] = [dxb]
    try:
        o.fields.get(0)
        ok_b = False
    except D._Decline:
        ok_b = True
    check("[F3] the ApplicationInfo field index is read in the running dex's own field table", ok_a and ok_b
          and w.appinfo(dxb) is o, (ok_a, ok_b))
    got, last = solve(handoff_bundle(rawA))
    check("[F3] the ApplicationInfo handed to the feature split's reader (another field table): its splitSourceDirs "
          "read there, unsure under analysis+across-splits with the asset's code",
          offered(got) == (SB.AX_KEY, [(SB.AX_ROUTE, code_of(rawA))]), (got, last.get("why")))
    # 4. the hooked keys: two bodiless methods (readSplitAsset, decryptFeature) under the same caller do not share a
    # key; two declining bodies that differ only in a literal do not share one either
    keys = []
    for name in ("readSplitAsset", "decryptFeature"):
        d = Dx()
        rd = d.m("Lcom/q/Vault;", name, BYTES, [STR])
        a = S.Asm()
        code = d.m("Lcom/q/Main;", "token", STR)
        a.const_string(0, d.s("huntress_feature.bin"))
        a.invoke(0x71, rd, [0])
        a.move_result_object(1)
        a.const_string(15, d.s("ANS-"))
        entry_bytes_to_code(d, a, 1)
        d.body(code, a.finish(), 16, 0)
        keys.append(offered(solve(analysis_bundle(d.build(), feat))[0])[0])
    check("[F4] two bodiless readers of one prototype under the same caller: two keys", all(keys) and keys[0] != keys[1],
          keys)
    kx = [offered(solve(analysis_bundle(analysis_dex("context", "loadFeature", lit=v), feat))[0])[0] for v in (0x5A, 0x13)]
    check("[F4] two declining reader bodies that differ only in an XOR literal: two keys", all(kx) and kx[0] != kx[1], kx)
    # 5. the second-code look: base64, hex, a moved document, a zip comment, beside the split readings
    want = code_for("P1")
    c = [want[:6], want[6:13], want[13:]]
    order = [1, 2, 0]
    parts = [c[order[i]] for i in range(3)]
    shown = [parts[0], "", parts[2]]
    decoy = code_for("decoy-look")
    moved = {"schema": "huntress.mobile.puzzle.v1", "day": 27, "codec": "reverse", "data": decoy[::-1]}
    import base64
    for label, extra in (("base64", {"assets/backup.txt": base64.b64encode(decoy.encode())}),
                         ("hex", {"assets/backup.txt": decoy.encode().hex().encode()}),
                         ("a moved puzzle document", {"assets/release.json": moved})):
        got, last = solve(split_bundle(split_doc(shown, order), {"feature.apk": {"assets/a.json": part(1, parts[1]),
                                                                                  **extra}}))
        k, opts = offered(got)
        check("[F5] split codec, a decoy under %s in the feature split: unsure under :second-code, the reading first"
              % label, k == SB.KEY + SB.SECOND and opts[0] == (SB.BY, want) and decoy in [v for _, v in opts],
              (got, last.get("other_codes")))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", b"m")
        z.writestr("assets/a.json", json.dumps(part(1, parts[1])))
        z.comment = ("note " + decoy).encode()
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as z:
        z.writestr("base.apk", zipped({"AndroidManifest.xml": b"m", PZ: split_doc(shown, order)}))
        z.writestr("feature.apk", buf.getvalue())
    got, last = solve(outer.getvalue())
    k, opts = offered(got)
    check("[F5] a decoy in the feature split's zip comment: unsure under :second-code, the reading first",
          k == SB.KEY + SB.SECOND and opts[0] == (SB.BY, want) and decoy in [v for _, v in opts], (got, last))
    got, last = solve(analysis_bundle(analysis_dex("body", "pull", "assets/huntress_feature.bin"),
                                      {**feat, "assets/backup.txt": base64.b64encode(decoy.encode())}))
    k, opts = offered(got)
    rk = SB.AKEY + SB.READER + "@shape-"
    check("[F5] analysis, a base64 decoy in the feature split: unsure under analysis+split-asset:reader@shape-<sha256>"
          ":second-code (the reader is not the judged one's shape), the reading first",
          str(k).startswith(rk) and k == k[:len(rk) + 64] + SB.SECOND and opts[0] == (SB.AROUTE, code_of(raw, 0x5A))
          and decoy in [v for _, v in opts], (got, last.get("other_codes")))
    # 6. the step budget: a chain that never ends is withheld by the module, not run a second time by the shipped path
    blob = analysis_bundle(looping_dex(), {**M, "assets/x.bin": b"x"})
    r = SB.solve(blob)
    check("[F6] a dex chain past the step budget: withheld by the split reading",
          r is not None and r.answer is None and "step budget" in str(r.note.get("why")), r)
    t = time.process_time()
    got_with, _ = solve(blob)
    with_mod = time.process_time() - t
    keep, C.split_bundle = C.split_bundle, None
    try:
        t = time.process_time()
        got_without, _ = solve(blob)
        without = time.process_time() - t
    finally:
        C.split_bundle = keep
    check("[F6] ... and the whole set costs less CPU than the shipped path alone (%.2f s against %.2f s), answer None"
          % (with_mod, without), got_with is None and with_mod < without, (got_with, with_mod, without))


# ---------------------------------------------------------------------------- [V] review 2 of a291433, fixed

BAOS = "Ljava/io/ByteArrayOutputStream;"
RAW2 = hashlib.sha256(b"rv2-feature").digest()[:16]


def split_loop_head(d, a):
    """v1 = splitSourceDirs, v2 = its length, v3 = 0; loop; v4 = path; v5 = ZipFile; v6 = the entry (or null, then
    `next`); v8 = the entry's bytes (readAllBytes)."""
    a.const4(0, 0)
    a.invoke(0x6e, d.m(CTX, "getApplicationInfo", AI), [0])
    a.move_result_object(0)
    a.iop(0x54, 1, 0, d.f(AI, "[Ljava/lang/String;", "splitSourceDirs"))
    arrlen(a, 2, 1)
    a.const4(3, 0)
    a.label("loop")
    a.if_test(0x35, 3, 2, "none")
    a.aget(0x46, 4, 1, 3)
    a.new_instance(5, d.t(ZF))
    a.invoke(0x70, d.m(ZF, "<init>", "V", [STR]), [5, 4])
    a.invoke(0x6e, d.m(ZF, "getEntry", ZE, [STR]), [5, 15])
    a.move_result_object(6)
    a.if_testz(0x38, 6, "next")
    a.invoke(0x6e, d.m(ZF, "getInputStream", IS, [ZE]), [5, 6])
    a.move_result_object(7)
    a.invoke(0x6e, d.m(IS, "readAllBytes", BYTES), [7])
    a.move_result_object(8)


def split_loop_tail(a):
    a.label("next")
    lit8(a, 0xd8, 3, 3, 1)
    a.goto16("loop")
    a.label("none")
    a.const4(0, 0)
    a.return_object(0)


def xor_reg_loop(a, arr, key):
    """XOR every byte of v<arr> with v<key> (v10, v11, v13 scratch), then return v<arr>."""
    arrlen(a, 10, arr)
    a.const4(11, 0)
    a.label("xl")
    a.if_test(0x35, 11, 10, "done")
    a.aget(0x48, 13, arr, 11)
    a.binop2(0xb7, 13, key)
    a.unop(0x8d, 13, 13)
    a.aput(0x4f, 13, arr, 11)
    lit8(a, 0xd8, 11, 11, 1)
    a.goto16("xl")
    a.label("done")
    a.return_object(arr)


def entry_app(d, reader_midx, asset="assets/huntress_feature.bin", pre=None):
    """Release.code(): (optional units first) the bytes of reader(asset) make the code."""
    a = S.Asm()
    code = d.m("Lcom/t/Release;", "code", STR)
    if pre:
        pre(a)
    a.const_string(0, d.s(asset))
    a.invoke(0x71, reader_midx, [0])
    a.move_result_object(1)
    a.const_string(15, d.s("ANS-"))
    entry_bytes_to_code(d, a, 1)
    d.body(code, a.finish(), 16, 0)


def baos_subclass(field_cls):
    """The reader copies the asset into Lcom/t/Sink; (a ByteArrayOutputStream subclass) and XORs the bytes with
    Sink.written(), the protected int `count` (16 on a device; the shipped VM read the unset field as 0)."""
    d = Dx()
    sink = "Lcom/t/Sink;"
    si = d.m(sink, "<init>", "V")
    a = S.Asm()
    a.invoke(0x70, d.m(BAOS, "<init>", "V"), [0])
    a.return_void()
    d.body(si, a.finish(), 1, 1)
    wr = d.m(sink, "written", "I")
    a = S.Asm()
    a.iop(0x52, 0, 1, d.f(sink if field_cls == "sink" else field_cls, "I", "count"))
    a.u.append(0x0f)                              # return v0
    d.body(wr, a.finish(), 2, 1)
    rd = d.m("Lcom/t/Store;", "pull", BYTES, [STR])
    a = S.Asm()
    split_loop_head(d, a)
    a.new_instance(9, d.t(sink))
    a.invoke(0x70, si, [9])
    arrlen(a, 10, 8)
    a.const4(11, 0)
    a.invoke(0x6e, d.m(BAOS, "write", "V", [BYTES, "I", "I"]), [9, 8, 11, 10])
    a.invoke(0x6e, wr, [9])
    a.move_result(12)
    a.invoke(0x6e, d.m(BAOS, "toByteArray", BYTES), [9])
    a.move_result_object(8)
    xor_reg_loop(a, 8, 12)
    split_loop_tail(a)
    d.body(rd, a.finish(), 16, 1)
    entry_app(d, rd)
    return d.build()


def baos_size():
    """Control: the same through a plain ByteArrayOutputStream and its size() (modelled): XOR with 16."""
    d = Dx()
    rd = d.m("Lcom/t/Store;", "pull", BYTES, [STR])
    a = S.Asm()
    split_loop_head(d, a)
    a.new_instance(9, d.t(BAOS))
    a.invoke(0x70, d.m(BAOS, "<init>", "V"), [9])
    arrlen(a, 10, 8)
    a.const4(11, 0)
    a.invoke(0x6e, d.m(BAOS, "write", "V", [BYTES, "I", "I"]), [9, 8, 11, 10])
    a.invoke(0x6e, d.m(BAOS, "size", "I"), [9])
    a.move_result(12)
    a.invoke(0x6e, d.m(BAOS, "toByteArray", BYTES), [9])
    a.move_result_object(8)
    xor_reg_loop(a, 8, 12)
    split_loop_tail(a)
    d.body(rd, a.finish(), 16, 1)
    entry_app(d, rd)
    return d.build()


def static_key():
    """The entry stores 0x5A into an app static (sput) before the split reader runs; the reader XORs with sget of it.
    (The VM's static store is another branch's: here the reading only has to stay off the judged plain name.)"""
    d = Dx()
    key_f = d.f("Lcom/t/K;", "I", "key")
    rd = d.m("Lcom/t/Store;", "pull", BYTES, [STR])
    a = S.Asm()
    split_loop_head(d, a)
    a.u += [0x60 | (12 << 8), key_f]              # sget v12, K.key
    xor_reg_loop(a, 8, 12)
    split_loop_tail(a)
    d.body(rd, a.finish(), 16, 1)

    def pre(a2):
        a2.const16(0, 0x5A)
        a2.u += [0x67, key_f]                     # sput v0, K.key
    entry_app(d, rd, pre=pre)
    return d.build()


def real_reader():
    """(Dex, midx) of the Day 26 Time Trial's readSplit, the judged reader."""
    dex = D.Dex(tt_splits()["base.apk"]["classes.dex"])
    for midx in dex.code:
        if (dex.mname.get(midx) or dex.meth(midx))[1] == "readSplit":
            return dex, midx
    return None, None


def copy_body(d, src, midx):
    """(units, regs, ins) of `src`'s method `midx` with every pool index (method, field, string, type) re-pointed at
    the same entity in the Dx `d`: the same code in another app, under other indexes."""
    regs, ins, insns = src.code[midx]
    out, i = list(insns), 0
    while i < len(insns):
        op = insns[i] & 0xFF
        w = D._W[op]
        if 0x6e <= op <= 0x72 or 0x74 <= op <= 0x78:
            c, n = src.meth(insns[i + 1])
            ret, params = SB._proto(src, insns[i + 1])
            out[i + 1] = d.m(c, n, ret, params)
        elif 0x52 <= op <= 0x6d:
            c, n = src.field(insns[i + 1])
            out[i + 1] = d.f(c, src.type_str(src._u2(src.field_off + insns[i + 1] * 8 + 2)), n)
        elif op == 0x1a:
            out[i + 1] = d.s(src.string(insns[i + 1]))
        elif op in (0x1c, 0x1f, 0x20, 0x22, 0x23):
            out[i + 1] = d.t(src.type_str(insns[i + 1]))
        if w <= 0:
            break
        i += w
    return out, regs, ins


def judged_app(src, midx, middle=None, pre=None):
    """(dex bytes, reader midx): an app whose Lcom/q/Loader;->fetch is a copy of Day 26's readSplit (other names and
    indexes), and whose entry turns the bytes of fetch("huntress_feature.bin") into the code; pre(d, a) runs before
    the read, middle(d, a) between the read (bytes in v1) and the code (bytes in v1 again)."""
    d = Dx()
    units, regs, ins = copy_body(d, src, midx)
    rd = d.m("Lcom/q/Loader;", "fetch", BYTES, [STR])
    d.body(rd, units, regs, ins)
    a = S.Asm()
    code = d.m("Lcom/q/Main;", "code", STR)
    if pre:
        pre(d, a)
    a.const_string(0, d.s("huntress_feature.bin"))
    a.invoke(0x71, rd, [0])
    a.move_result_object(1)
    if middle:
        middle(d, a)
    a.const_string(15, d.s("ANS-"))
    entry_bytes_to_code(d, a, 1)
    d.body(code, a.finish(), 16, 0)
    return d.build(), rd


def baos_copy(d, a):
    """v1 = a plain ByteArrayOutputStream's copy of v1."""
    a.new_instance(2, d.t(BAOS))
    a.invoke(0x70, d.m(BAOS, "<init>", "V"), [2])
    arrlen(a, 3, 1)
    a.const4(4, 0)
    a.invoke(0x6e, d.m(BAOS, "write", "V", [BYTES, "I", "I"]), [2, 1, 4, 3])
    a.invoke(0x6e, d.m(BAOS, "toByteArray", BYTES), [2])
    a.move_result_object(1)


def sink_copy(d, a):
    """v1 through Lcom/q/Sink;, a ByteArrayOutputStream subclass whose toByteArray XORs every byte with 0x33, called
    through ByteArrayOutputStream's own method refs: a device runs Sink's override (the model would not)."""
    sink = "Lcom/q/Sink;"
    si = d.m(sink, "<init>", "V")
    b = S.Asm()
    b.invoke(0x70, d.m(BAOS, "<init>", "V"), [0])
    b.return_void()
    d.body(si, b.finish(), 1, 1)
    tb = d.m(sink, "toByteArray", BYTES)
    b = S.Asm()
    b.invoke(0x6f, d.m(BAOS, "toByteArray", BYTES), [5])     # invoke-super
    b.move_result_object(0)
    arrlen(b, 1, 0)
    b.const4(2, 0)
    b.label("l")
    b.if_test(0x35, 2, 1, "d")
    b.aget(0x48, 3, 0, 2)
    lit8(b, 0xdf, 3, 3, 0x33)
    b.unop(0x8d, 3, 3)
    b.aput(0x4f, 3, 0, 2)
    lit8(b, 0xd8, 2, 2, 1)
    b.goto16("l")
    b.label("d")
    b.return_object(0)
    d.body(tb, b.finish(), 6, 1)
    a.new_instance(2, d.t(sink))
    a.invoke(0x70, si, [2])
    arrlen(a, 3, 1)
    a.const4(4, 0)
    a.invoke(0x6e, d.m(BAOS, "write", "V", [BYTES, "I", "I"]), [2, 1, 4, 3])
    a.invoke(0x6e, d.m(BAOS, "toByteArray", BYTES), [2])
    a.move_result_object(1)


def touch_appinfo(d, a):
    """The entry itself asks Context.getApplicationInfo (a split-touching method of another shape)."""
    a.const4(0, 0)
    a.invoke(0x6e, d.m(CTX, "getApplicationInfo", AI), [0])
    a.move_result_object(0)


def static_xor(d, a):
    """v1 XORed byte by byte with an app static the entry stores first (sput 0x5A into Lcom/q/K;->key, then sget it):
    a device XORs with 0x5A, the base VM read the static as 0."""
    kf = d.f("Lcom/q/K;", "I", "key")
    a.const16(9, 0x5A)
    a.u += [0x67 | (9 << 8), kf]                  # sput v9, K.key
    a.u += [0x60 | (12 << 8), kf]                 # sget v12, K.key
    arrlen(a, 10, 1)
    a.const4(11, 0)
    a.label("sx")
    a.if_test(0x35, 11, 10, "sd")
    a.aget(0x48, 13, 1, 11)
    a.binop2(0xb7, 13, 12)
    a.unop(0x8d, 13, 13)
    a.aput(0x4f, 13, 1, 11)
    lit8(a, 0xd8, 11, 11, 1)
    a.goto16("sx")
    a.label("sd")


def without_module(blob):
    keep, C.split_bundle = C.split_bundle, None
    try:
        return solve(blob)[0]
    finally:
        C.split_bundle = keep


def review2():
    fresh()
    M = {"AndroidManifest.xml": b"m"}
    feat = {**M, "assets/huntress_feature.bin": RAW2}
    raw16 = hashlib.sha256(b"rv2-judged").digest()[:16]
    feat16 = {**M, "assets/huntress_feature.bin": raw16}
    # 1. tier A's judged name only for the judged reader's shape
    if DAY26.is_dir():
        src, rm = real_reader()
        jd, jr = judged_app(src, rm)
        fp = hashlib.sha256(SB._shape(D, D.Dex(jd), jr, True, {}).encode()).hexdigest()
        check("[V1] a copy of Day 26's readSplit in another app (other names, other indexes) has the judged reader's "
              "shape, and the real one's is the one JUDGED_READERS holds",
              fp in SB.JUDGED_READERS and SB.JUDGED_READERS == {hashlib.sha256(SB._shape(D, src, rm, True, {}).encode())
                                                                .hexdigest()}, fp)
        got, last = solve(analysis_bundle(jd, feat16))
        check("[V1] that reader, the entry making the code of its bytes: plain under the judged key, the exact code",
              plain(got) and got == code_of(raw16) and last.get("key") == SB.AKEY, (got, code_of(raw16), last))
        got, last = solve(analysis_bundle(judged_app(src, rm, middle=baos_copy)[0], feat16))
        check("[V1] the same, its bytes through a plain ByteArrayOutputStream in the entry: plain, the exact code",
              plain(got) and got == code_of(raw16) and last.get("key") == SB.AKEY, (got, last))
        got, last = solve(analysis_bundle(judged_app(src, rm, pre=touch_appinfo)[0], feat16))
        check("[V1] the same app whose entry also asks getApplicationInfo (a split-touching method of another shape): "
              "the exact code, unsure under the reader key", reader_pick(got, code_of(raw16)), (got, last))
        # 2. a ByteArrayOutputStream subclass's override: a device runs it, the model may not answer for it
        got, last = solve(analysis_bundle(judged_app(src, rm, middle=sink_copy)[0], feat16))
        check("[V2] the judged reader's bytes through a ByteArrayOutputStream subclass whose toByteArray XORs (called "
              "through the base class's refs): never plain (a device gives %s)" % code_of(raw16, 0x33),
              not plain(got), (got, code_of(raw16, 0x33), last.get("key"), last.get("why")))
        # 4. KB-7 beside the fold: an app static the entry set first is never read as the base VM's 0
        got, last = solve(analysis_bundle(judged_app(src, rm, middle=static_xor)[0], feat16))
        check("[V4] the judged reader, the entry XORing its bytes with an app static it set first (sput, sget): never "
              "plain (a device gives %s; the base VM read 0 and gave %s plain under the judged key)"
              % (code_of(raw16, 0x5A), code_of(raw16)),
              not plain(got), (got, last.get("key"), last.get("why")))
        # _reader_key over the runs' records: every split-touching method of every run counts
        synth = D.Dex(analysis_dex("body", "pull", "assets/huntress_feature.bin"))
        pull = [m for m in synth.code if synth.mname[m][1] == "pull"][0]
        entry = [m for m in synth.code if synth.mname[m][1] == "code"][0]
        rec = lambda *pairs: type("Run", (), {"executed": {(id(dx), m): dx for dx, m in pairs}})()  # noqa: E731
        k_judged = SB._reader_key(D, SB.AKEY, [rec((src, rm))])
        k_both = SB._reader_key(D, SB.AKEY, [rec((src, rm)), rec((synth, pull))])
        k_none = SB._reader_key(D, SB.AKEY, [rec((synth, entry))])
        rk = SB.AKEY + SB.READER + "@shape-"
        check("[V1] _reader_key: the judged reader alone keeps the judged key; with a reader of another shape in "
              "another run, or with no split-touching method at all, the reader key",
              k_judged == SB.AKEY and k_both.startswith(rk) and k_none.startswith(rk) and k_both != k_none,
              (k_judged, k_both, k_none))
    else:
        print("SKIP [V1] the judged reader: %s is not on disk" % DAY26)
    got, last = solve(analysis_bundle(static_key(), feat))
    check("[V1] a split reader XORing with an app static the entry sets (sput): never plain (not the judged shape)",
          not plain(got), (got, last.get("key")))
    got, last = solve(analysis_bundle(baos_size(), feat))
    check("[V1] a split reader through a plain ByteArrayOutputStream and its size(): the exact code (XOR 16), unsure "
          "under its reader key", reader_pick(got, code_of(RAW2, 16)), (got, last))
    # 2. the ByteArrayOutputStream model: a field read declines, and so does every call on a subclass but <init>
    for label, fc in (("Sink.count", "sink"), ("ByteArrayOutputStream.count", BAOS)):
        fresh()
        got, last = solve(analysis_bundle(baos_subclass(fc), feat))
        check("[V2] a reader XORing with a ByteArrayOutputStream subclass's protected count (field ref %s): never plain "
              "(a device XORs with 16; the model held 0)" % label,
              not plain(got) and got != code_of(RAW2, 0), (got, code_of(RAW2, 16), last.get("key")))
    b = SB.bundle(analysis_bundle(analysis_dex("body"), feat))
    dx = D.Dex(analysis_dex("body"))
    vm = SB._vm_class(D)(dx, SB._World(D, b, [(0, dx)], {}, {}))
    o = D._Obj(BAOS)
    vm._framework_call(BAOS, "<init>", [o])
    vm._framework_call(BAOS, "write", [o, 0x41])
    vm._framework_call(BAOS, "write", [o, [1, 2, 3], 1, 2])
    works = vm._framework_call(BAOS, "toByteArray", [o]) == [0x41, 2, 3] and vm._framework_call(BAOS, "size", [o]) == 3
    s = D._Obj("Lcom/t/Sink;")
    vm._framework_call(BAOS, "<init>", [s])
    refused = []
    for what in (lambda: o.fields.get(0), lambda: o.fields[7], lambda: s.fields.get(0),
                 lambda: vm._framework_call(BAOS, "write", [s, 1]), lambda: vm._framework_call(BAOS, "toByteArray", [s]),
                 lambda: vm._framework_call(BAOS, "size", [s])):
        try:
            what()
            refused.append(False)
        except D._Decline:
            refused.append(True)
        except Exception as e:      # anything but a decline is no refusal the tiers understand
            refused.append(type(e).__name__)
    check("[V2] the model: a ByteArrayOutputStream writes, copies and counts; an int-indexed field read on one declines, "
          "and on a subclass every call but <init> declines", works and all(r is True for r in refused), (works, refused))
    # 3. a library in the base and a different one in a config split: the shipped reader's merged view is not proven
    if not (DAY25_SO.is_dir() and DAY23_SO.is_dir()):
        print("SKIP [V3] %s or %s is not on disk" % (DAY25_SO, DAY23_SO))
        return
    fresh()
    so_name = "lib/x86_64/libarena.so"
    base = {str(f.relative_to(DAY25_SO)): f.read_bytes() for f in DAY25_SO.rglob("*") if f.is_file()}
    other = (DAY23_SO / so_name).read_bytes()
    check("[V3] (the two libraries differ, and both define a JNI symbol ending in _nativeShare)",
          base[so_name] != other and all(any(s.endswith("_nativeShare") for s in D._parse_so(x)) for x in (base[so_name], other)))
    blob = zipped({"base.apk": zipped(base), "config.x86_64.apk": zipped({so_name: other})})
    got, last = solve(blob)
    check("[V3] the base keeps its libarena.so and a config split carries another one at the same path: None, withheld "
          "(it was the shipped reader's, PLAIN)", got is None and "non-base split carries code" in str(last.get("why")),
          (got, last.get("route"), last.get("why")))
    for label, split in (("a config split with no code", {"res/values.arsc": b"\x00"}),
                         ("the base's own libarena.so again in a config split", {so_name: base[so_name]})):
        blob = zipped({"base.apk": zipped(base), "config.x86_64.apk": zipped(split)})
        got = solve(blob)[0]
        without = without_module(blob)
        check("[V3] %s beside the same base: answered exactly as with the module absent" % label, got == without,
              (got, without))


def main():
    t0 = time.perf_counter()
    saved()
    renamed()
    synthetic()
    split_codec()
    across()
    unchanged()
    review_fixes()
    review2()
    print("test_day27_split_fold_mobile: %d passed, %d failed in %.1f s" % (len(PASSED), len(FAILED),
                                                                          time.perf_counter() - t0))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
