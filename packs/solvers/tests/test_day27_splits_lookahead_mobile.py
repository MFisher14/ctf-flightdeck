#!/usr/bin/env python3
"""Day 27 look-ahead for the Mobile lane's split bundles (backlog row 533), on SYNTHETIC packages (R-04).

The look-ahead first ran on real challenge deliveries (the Day 26 split bundles, the Day 23 and 25 native and
reflection APKs, with their judged answers in a truths file). R-04 removed them from the tree: every package is now
built at test time by tests/day27_mobile_splits_synth.py, with the same structures the readers need, and every
answer known by construction. This file checks, in order:

  [B] the builders, each against an independent reader: androguard reads every dex (and its checksum and signature
      hold), the reference runtime (androguard + its own interpreter, tests/day27_mobile_splits_ref.py) computes the
      split-asset apps' answers the chain spec gives, for the delivered asset and short, long, empty and changed ones;
      the reader carries the judged reader's code shape (split_bundle.JUDGED_READERS) and a changed one does not;
      capstone decodes the native legs to the intended instructions; pyelftools reads the libraries' program headers,
      dynamic tags and hash table, and finds the JNI symbol the dex's native method mangles to; androguard's AXML
      printer reads the compiled manifests (package, split);
  [L] the look-ahead itself (tests/day27_mobile_splits_lib.py): the shipped solver on every case, as the runner hands a
      delivery to it, never a WRONG plain answer; a case's required outcome (`must`) in every mode; and the Day 26
      fold's contract per case class (`fold`): plain = plain and equal to the truth, unsure = the truth first (a
      correct plain tolerated), none = None, safe = anything but a wrong plain.

x17 and x17c (two different libarena.so in one delivery, one bound by the base's JNI method) are a KNOWN wrong-plain
gap of this master's solver: the real-bytes run gave the same wrong plain before R-04 (so-ambig closed it in the
Huntress tree; the master answers from the merged members). They xfail only on that exact WRONG plain: any other
outcome (a fix, or another failure) fails the case, and a fix means dropping them from GAP_CASES.
"""
import contextlib
import hashlib
import io
import json
import re
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

import day27_mobile_splits_synth as SY
import mobile_codec_env as T

ROOT = Path(__file__).resolve().parent.parent
ANS = re.compile(r"ANS-[0-9A-F]{16}")
SYNTAX = "ANS- followed by exactly 16 uppercase hexadecimal characters; no spaces or explanatory text"
QUESTION = {"id": "answer", "qid": "answer", "answer_id": "answer",
            "answer_format": {"kind": "pattern", "syntax": SYNTAX},
            "question": "Reassemble evidence distributed across base and configuration splits. Submit only the exact "
                        "backend answer code returned for this case."}
APPS = {"d26_tt": ("d26_tt.base.apk", "d26_tt.feature.apk"), "d26_m10": ("d26_m10.base.apk", "d26_m10.feature.apk")}
DEX_FIXTURES = ("d26_base.base.apk", "d26_tt.base.apk", "d26_m10.base.apk", "d25_set6_native.apk",
                "d23_set5_native.apk", "d25_set7_reflection.apk")
KNOWN_GAP = ("known gap of the master's solver (R-04 report): two different libarena.so in one delivery, the base's "
             "JNI method bound by one of them, answered PLAIN from the members merged by name; the same wrong plain "
             "the real Huntress bytes gave before R-04. so-ambig closed it in the Huntress tree.")
GAP_CASES = {"x17-two-different-libs-two-splits", "x17c-lib-in-base-and-other-in-split"}


def members(blob):
    z = zipfile.ZipFile(io.BytesIO(blob))
    return {n: z.read(n) for n in z.namelist()}


def _quiet_androguard():
    try:
        from loguru import logger
        logger.disable("androguard")
    except Exception:  # pragma: no cover
        pass


# ============================================================================ [B] the builders
def test_the_real_fixture_folder_is_gone_and_every_synthetic_package_builds():
    assert not (ROOT / "tests" / "fixtures" / "day27_mobile_splits").exists()
    names = SY.fixture_names()
    assert names == sorted(["d23_set5_native.apk", "d25_set6_native.apk", "d25_set7_reflection.apk",
                            "d26_base.base.apk", "d26_base.feature.apk", "d26_m10.base.apk", "d26_m10.feature.apk",
                            "d26_tt.base.apk", "d26_tt.feature.apk"])
    with pytest.raises(KeyError):
        SY.fixture("truths.json")
    t = SY.truths()
    answers = [t[k]["answer"] for k in ("d26_base", "d26_tt", "d26_m10", "d25_set6", "d23_set5", "d25_set7")]
    assert all(ANS.fullmatch(a) for a in answers) and len(set(answers)) == len(answers), answers
    # the build is deterministic: the same bytes every time
    again = SY._build()[0]
    assert all(again[n] == SY.fixture(n) for n in names)


@pytest.mark.parametrize("name", DEX_FIXTURES)
@pytest.mark.needs_tool("py:androguard")
def test_androguard_reads_every_dex_and_its_header_seals_hold(name):
    _quiet_androguard()
    from androguard.core.dex import DEX
    dex = members(SY.fixture(name))["classes.dex"]
    assert dex[:8] == b"dex\n035\0"
    assert struct.unpack_from("<I", dex, 32)[0] == len(dex)
    assert struct.unpack_from("<I", dex, 8)[0] == zlib.adler32(dex[12:]) & 0xFFFFFFFF
    assert dex[12:32] == hashlib.sha1(dex[32:]).digest()
    d = DEX(dex)
    meths = {(c.get_name(), m.get_name()): m for c in d.get_classes() for m in c.get_methods()}
    ans_methods = [k for k, m in meths.items() if m.get_code() is not None
                   and any(i.get_name() == "const-string" and i.get_operands()[1][2] == "ANS-"
                           for i in m.get_code().get_bc().get_instructions())]
    if name == "d26_base.base.apk":
        assert ans_methods == []                       # the split-document app computes nothing
        return
    pkg = SY.PKG[name.split(".")[0].replace("_native", "").replace("_reflection", "")]
    rel = "L%s/Release;" % pkg.replace(".", "/")
    assert ans_methods == [(rel, "code")]
    if "native" in name:
        cls = "JNIBoundary" if "set6" in name else "NativeLibrarySecrets"
        m = meths[("L%s/%s;" % (pkg.replace(".", "/"), cls), "nativeShare")]
        assert m.get_access_flags() & SY.ACC_NATIVE and m.get_code() is None
        assert m.get_descriptor().replace(" ", "") == ("(JI)J" if "set6" in name else "(J)J")


@pytest.mark.needs_tool("py:androguard")
@pytest.mark.parametrize("tag", sorted(APPS))
def test_reference_runtime_computes_the_split_asset_apps_answers_the_spec_gives(tag):
    _quiet_androguard()
    from day27_mobile_splits_ref import RefVM, Thrown
    base, feat = (members(SY.fixture(n)) for n in APPS[tag])
    dex, asset = base["classes.dex"], feat[SY.FEATURE_BIN]
    oracle = SY.split_asset_oracle(tag)
    assert len(asset) == 16
    assert RefVM(dex, [("/data/app/feature.apk", feat)]).code() == SY.truths()[tag]["answer"] == oracle(asset)
    flipped = bytes([asset[0] ^ 1]) + asset[1:]
    seen = {oracle(asset)}
    for raw in (b"", asset[:10], asset + bytes(range(24)), flipped, bytes(16), asset[:8] + bytes(8)):
        got = RefVM(dex, [("/data/app/config.en.apk", {"AndroidManifest.xml": b"x"}),
                          ("/data/app/feature.apk", {SY.FEATURE_BIN: raw})]).code()
        assert got == oracle(raw), raw
        seen.add(got)
    assert oracle(flipped) != oracle(asset) and oracle(asset[:8] + bytes(8)) != oracle(asset)
    # the long asset reads its first 16 bytes (the delivered answer again); an empty one leaves the buffer zeros
    assert oracle(asset + bytes(range(24))) == oracle(asset) and oracle(b"") == oracle(bytes(16))
    assert len(seen) == 5
    with pytest.raises(Thrown):
        RefVM(dex, [("/data/app/feature.apk", {})]).code()
    assert oracle(None) is None


@pytest.mark.parametrize("tag", sorted(APPS))
def test_the_split_reader_has_the_judged_code_shape_and_a_changed_one_does_not(tag):
    import dex_chain_codec as D
    import split_bundle as SB

    def shapes(dex_bytes):
        dex = D.Dex(dex_bytes)
        return {n: hashlib.sha256(SB._shape(D, dex, midx, True, {}).encode()).hexdigest()
                for midx, (_, n) in dex.mname.items() if n in ("readSplit", "mergeFeature")}
    dex = members(SY.fixture(APPS[tag][0]))["classes.dex"]
    got = shapes(dex)
    assert got["readSplit"] in SB.JUDGED_READERS
    assert got["mergeFeature"] not in SB.JUDGED_READERS
    # the same reader with its buffer one byte shorter (const/16 v7, 16 -> 15) is another shape
    units = SY.reader_units(SY.DexWriter(), 0)
    assert units.count(0x0713) == 1 and units[units.index(0x0713) + 1] == 16
    d = D.Dex(dex)
    midx = next(m for m, (_, n) in d.mname.items() if n == "readSplit")
    regs, ins, insns = d.code[midx]
    at = insns.index(0x0713)
    off = dex.index(struct.pack("<%dH" % len(insns), *insns))
    patched = bytearray(dex)
    struct.pack_into("<H", patched, off + 2 * (at + 1), 15)
    assert shapes(SY.seal_dex(bytes(patched)))["readSplit"] not in SB.JUDGED_READERS


@pytest.mark.needs_tool("py:capstone")
def test_capstone_decodes_the_native_legs_to_the_intended_instructions():
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    def dis(code):
        return [(i.mnemonic, i.op_str) for i in md.disasm(code, 0)], sum(i.size for i in md.disasm(code, 0))
    spec = [("xor", 0x1122334455667788), ("add", 0x8000000000000001), ("mul", 0xFFFFFFFFFFFFFFFF),
            ("rotl", 45), ("xshr", 31)]
    want_ops = [("movabs", "rcx, 0x1122334455667788"), ("xor", "rax, rcx"), ("movabs", "rcx, 0x8000000000000001"),
                ("add", "rax, rcx"), ("movabs", "rcx, 0xffffffffffffffff"), ("imul", "rax, rcx"),
                ("rol", "rax, 0x2d"), ("mov", "rcx, rax"), ("shr", "rcx, 0x1f"), ("xor", "rax, rcx")]
    code = SY.x86_straight(spec)
    got, size = dis(code)
    assert size == len(code)
    assert got == [("mov", "rax, rdx")] + want_ops + [("ret", "")]
    code = SY.x86_gated(spec, 0x97DE)
    got, size = dis(code)
    assert size == len(code)
    fail = len(code) - 3
    assert got == ([("cmp", "ecx, 0xffff"), ("jle", hex(fail)), ("movzx", "esi, cx"), ("cmp", "esi, 0x97de"),
                    ("jne", hex(fail)), ("mov", "rax, rdx")]
                   + want_ops + [("ret", ""), ("xor", "eax, eax"), ("ret", "")])
    # the gate's own model: a pass needs n > 0xffff and the low 16 bits; the value is the spec's
    x = 0x0123456789ABCDEF
    assert SY.gated_eval(spec, 0x97DE, x, 0x197DE) == SY.mix_eval(spec, x) != 0
    assert SY.gated_eval(spec, 0x97DE, x, 0x97DE) == 0 == SY.gated_eval(spec, 0x97DE, x, 0x297DF)
    assert SY.gated_eval(spec, 0xFFFF, x, 0xFFFF) == 0 != SY.gated_eval(spec, 0xFFFF, x, 0x1FFFF)
    assert SY.mix_eval([("rotl", 8)], 0xFF00000000000000) == 0xFF
    assert SY.mix_eval([("xshr", 4)], 0xF0) == 0xFF


@pytest.mark.needs_tool("py:elftools")
@pytest.mark.parametrize("name,cls,desc", [("d25_set6_native.apk", "JNIBoundary", "(JI)J"),
                                           ("d23_set5_native.apk", "NativeLibrarySecrets", "(J)J")])
def test_pyelftools_reads_the_libraries_and_finds_the_jni_symbol_the_dex_names(name, cls, desc):
    from elftools.elf.elffile import ELFFile
    so = members(SY.fixture(name))[SY.SO_PATH]
    e = ELFFile(io.BytesIO(so))
    assert e.header.e_type == "ET_DYN" and e.header.e_machine == "EM_X86_64" and e.elfclass == 64
    segs = [(s.header.p_type, s.header.p_flags) for s in e.iter_segments()]
    assert segs == [("PT_LOAD", 4), ("PT_LOAD", 5), ("PT_LOAD", 6), ("PT_DYNAMIC", 6)]
    dyn = e.get_section_by_name(".dynamic")
    tags = {t.entry.d_tag: t.entry.d_val for t in dyn.iter_tags()}
    dynsym, dynstr = e.get_section_by_name(".dynsym"), e.get_section_by_name(".dynstr")
    assert tags["DT_SYMTAB"] == dynsym.header.sh_addr and tags["DT_STRTAB"] == dynstr.header.sh_addr
    assert tags["DT_HASH"] == e.get_section_by_name(".hash").header.sh_addr
    assert [t.soname for t in dyn.iter_tags() if t.entry.d_tag == "DT_SONAME"] == ["libarena.so"]
    pkg = SY.PKG[name.split("_native")[0]]
    sym = "Java_%s_%s_nativeShare" % (pkg.replace(".", "_"), cls)
    assert SY.jni_symbol("L%s/%s;" % (pkg.replace(".", "/"), cls), "nativeShare") == sym
    hsec = e.get_section_by_name(".hash")
    s = hsec.get_symbol(sym)
    assert s is not None and s["st_info"]["type"] == "STT_FUNC" and s["st_info"]["bind"] == "STB_GLOBAL"
    text = e.get_section_by_name(".text")
    body = so[text.header.sh_offset + s["st_value"] - text.header.sh_addr:][:s["st_size"]]
    assert body[-1:] == b"\xc3" and body[:3] in (b"\x48\x89\xd0", b"\x81\xf9\xff")
    assert body.startswith(b"\x81\xf9\xff\xff\x00\x00") == (desc == "(JI)J")
    assert hsec.get_symbol("Java_nope_nativeShare") is None


@pytest.mark.needs_tool("py:androguard")
def test_androguard_reads_the_compiled_manifests():
    _quiet_androguard()
    from androguard.core.axml import AXMLPrinter
    import apk_resources

    def root(blob):
        x = AXMLPrinter(members(blob)["AndroidManifest.xml"]).get_xml_obj()
        return x.tag, dict(x.attrib)
    tag, attrs = root(SY.fixture("d26_tt.base.apk"))
    ns = "{%s}" % SY.ANDROID_NS
    assert tag == "manifest" and attrs["package"] == SY.PKG["d26_tt"] and "split" not in attrs
    assert attrs[ns + "versionCode"] == "26"
    tag, attrs = root(SY.fixture("d26_tt.feature.apk"))
    assert attrs["package"] == SY.PKG["d26_tt"] and attrs["split"] == "arena_feature"
    els = apk_resources.axml_tree(members(SY.fixture("d26_base.feature.apk"))["AndroidManifest.xml"])
    assert [e["tag"] for e in els] == ["manifest", "uses-sdk", "application"]
    assert els[0]["attrs"]["split"] == "arena_feature" and els[2]["attrs"]["hasCode"] is False


def test_the_split_document_base_reads_by_order_to_its_answer():
    import day27_mobile_splits_lib as L
    base = json.loads(members(SY.fixture("d26_base.base.apk"))[SY.PUZZLE])
    feat = json.loads(members(SY.fixture("d26_base.feature.apk"))["assets/huntress_feature.json"])
    assert base["codec"] == "split" and base["parts"][feat["part_index"]] == ""
    parts = list(base["parts"])
    parts[feat["part_index"]] = feat["part"]
    assert L.by_order(parts, base["order"]) == SY.truths()["d26_base"]["answer"]
    assert L.take_order(parts, base["order"]) != SY.truths()["d26_base"]["answer"]


def test_split_apk_wraps_members_in_the_feature_splits_manifest_and_meta_inf():
    import day27_mobile_splits_lib as L
    like = members(SY.fixture("d26_base.feature.apk"))
    split = L.split_apk([("assets/x.bin", b"xy"), ("lib/x86_64/libz.so", b"\x7fELF")])
    names = [i.filename for i in zipfile.ZipFile(io.BytesIO(split)).infolist()]
    assert names == ["AndroidManifest.xml", "assets/x.bin", "lib/x86_64/libz.so", "META-INF/MANIFEST.MF"]
    got = members(split)
    assert got["AndroidManifest.xml"] == like["AndroidManifest.xml"]
    assert got["META-INF/MANIFEST.MF"] == like["META-INF/MANIFEST.MF"]
    # `like` picks the source split: another split's manifest comes through, not the default's
    other = members(L.split_apk([("assets/x.bin", b"xy")], like="d26_tt.feature.apk"))
    assert other["AndroidManifest.xml"] == members(SY.fixture("d26_tt.feature.apk"))["AndroidManifest.xml"]
    assert other["AndroidManifest.xml"] != like["AndroidManifest.xml"]


# ============================================================================ [L] the look-ahead
def _cases():
    try:
        import androguard  # noqa: F401  (the reference runtime's decoder gives the dex cases their truth)
    except ImportError:
        return []
    _quiet_androguard()
    import day27_mobile_splits_lib as L
    return L.build_cases()


CASE_LIST = _cases()
CASES = {c.name: c for c in CASE_LIST}


@pytest.fixture(scope="module")
def mobile_env():
    with T.isolated():
        yield


def solve(case):
    ctx = {"set": 1, "delivery": case.blob, "delivery_name": case.delivery_name, "attempt": {"artifacts": [{}]},
           "partial": {}}
    with contextlib.redirect_stderr(io.StringIO()):
        out = T.C.solve_set([dict(QUESTION)], {}, ctx)
    return (out or {}).get("answer")


def outcome(ans, case):
    """none | plain-equal | WRONG | unsure-truth-first | unsure-truth-later | unsure-no-truth."""
    labels = T.labels
    if ans is None:
        return "none"
    if isinstance(ans, str) and labels.is_unsure(ans):
        vals = [o[1] if isinstance(o, (list, tuple)) else o for o in labels.parse(ans)["o"]]
        if case.truth and vals and vals[0] == case.truth:
            return "unsure-truth-first"
        return "unsure-truth-later" if case.truth in vals else "unsure-no-truth"
    return "plain-equal" if ans in case.plain_ok else "WRONG"


FOLD_OK = {"plain": {"plain-equal"}, "unsure": {"unsure-truth-first", "plain-equal"}, "none": {"none"},
           "safe": {"none", "plain-equal", "unsure-truth-first", "unsure-truth-later", "unsure-no-truth"}}


@pytest.mark.needs_tool("py:androguard")
def test_the_case_set_is_whole():
    names = [c.name for c in CASE_LIST]
    assert len(names) == 56 and len(set(names)) == len(names)
    fams = {}
    for c in CASES.values():
        fams.setdefault(c.family, []).append(c.fold)
    assert sorted(fams) == ["a", "b", "c", "ctl", "d", "x"]
    # every truth is an ANS code or None (a decoy); the plain cases carry one
    assert all(c.truth is None or ANS.fullmatch(c.truth) for c in CASES.values())
    assert all(c.truth for c in CASES.values() if c.fold in ("plain", "unsure"))
    assert {c.name for c in CASES.values() if c.must == "none"} == {
        "x17-two-different-libs-two-splits", "x17b-two-different-libs-reversed", "x17c-lib-in-base-and-other-in-split"}


@pytest.mark.needs_tool("py:androguard")
@pytest.mark.parametrize("name", list(CASES or {"<androguard missing>": None}))
def test_lookahead_case(name, mobile_env):
    case = CASES[name]
    kind = outcome(solve(case), case)
    if name in GAP_CASES:
        # Only the known WRONG plain is an expected failure: any other outcome (the gap closed, or a different
        # failure) fails here, and an exception from the solver propagates as an ordinary error.
        assert kind == "WRONG", ("%s: known gap no longer gives its WRONG plain (got %s); if the gap is closed, "
                                 "drop it from GAP_CASES" % (name, kind))
        pytest.xfail(KNOWN_GAP)
    assert kind != "WRONG", "%s: a WRONG plain answer (truth %r)" % (name, case.truth)
    if case.must:
        assert kind == case.must, "%s: required %s, got %s" % (name, case.must, kind)
    assert kind in FOLD_OK[case.fold], "%s: fold %s, got %s (truth %r)" % (name, case.fold, kind, case.truth)
