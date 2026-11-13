"""Tests for solvers/mobile-android/proguard_mapping.py (the ProGuard/R8 mapping.txt reader).

Run from the repo root with the venv:
    .venv/bin/python -I tests/test_proguard_mapping_mobile.py
or under pytest.

The reader is checked three ways, all never-wrong:
  - it RESOLVES a class or member a question names, UNSURE (a `??` labels.pick under the new
    `mobile.deobf/<kind>` route, never plain), and the resolution is byte-exact against the
    mapping;
  - it answers NOTHING (None) on every ambiguous / under-specified / unknown shape;
  - it is reached through the shipped path `apk_facts.solve_questions` when a mapping member
    ships beside an APK, and adds an answer only where `apk_facts` had None (it never shadows a
    real package fact).
The guard that it changes nothing the shipped solver already answers is proven offline by
`tools/preflight.py --regress mobile-android` (changed=0); here the integration test shows a
package-fact question still answered by apk_facts, unchanged, with a mapping present.
"""
import io
import struct
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
for _p in (ROOT / "solvers" / "common", ROOT / "solvers" / "mobile-android"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import labels                 # noqa: E402
import proguard_mapping as P  # noqa: E402
import apk_facts              # noqa: E402

MAP = """\
# compiler: R8
# {"id":"com.android.tools.r8.mapping","version":"2.2"}
com.example.LoginManager -> a.b.c:
    int retryCount -> a
    1:3:void onCreate(android.os.Bundle):11:13 -> a
    java.lang.String computeToken() -> b
    boolean isReady() -> c
com.example.util.Crypto -> a.b.d:
    java.lang.String decrypt(java.lang.String) -> a
androidx.core.App$Inner -> x.y.z:
    void start() -> q
"""


def _mp():
    mp = P.parse(MAP)
    assert mp is not None and mp.classes == 3, mp
    return mp


def _ans(mp, qtext, fmt=None):
    q = {"qid": "q1", "question": qtext}
    if fmt:
        q["answer_format"] = fmt
    v = P.answer(q, mp)
    if v is None:
        return None
    if isinstance(v, str) and v.startswith("??"):
        u = labels.parse(v)
        return ("unsure", u.key, [list(o) for o in u.options])
    return ("plain", v)


def test_parse_bidirectional():
    mp = _mp()
    assert mp.cls_orig_of_obf.get("a.b.c") == "com.example.LoginManager"
    assert mp.cls_obf_of_orig.get("com.example.util.Crypto") == "a.b.d"
    # the obf member name "a" is used for BOTH a field and a method in the same class and for a
    # method in another class -> globally not unique, so global resolution must refuse it.
    assert mp.member_in_direction("a", want_original=True) is None
    # "b" (computeToken's obf) is unique to one class -> but globally the ORIGINAL side:
    assert mp.member_in_direction("b", want_original=True) == ("method", "computeToken")


def test_class_resolution_unsure():
    mp = _mp()
    # obfuscated -> original
    kind = _ans(mp, "What is the original name of the class a.b.c ?")
    assert kind[0] == "unsure" and kind[1] == "mobile.deobf/class", kind
    assert ["full", "com.example.LoginManager"] in kind[2]
    assert ["simple", "LoginManager"] in kind[2]
    # original -> obfuscated
    kind = _ans(mp, "What was com.example.LoginManager renamed to in the mapping?")
    assert kind[0] == "unsure" and ["full", "a.b.c"] in kind[2], kind
    # inner class ($) resolves, simple name strips the outer
    kind = _ans(mp, "original class name for x.y.z")
    assert kind[0] == "unsure" and ["full", "androidx.core.App$Inner"] in kind[2], kind
    assert ["simple", "Inner"] in kind[2]


def test_class_scoped_member():
    mp = _mp()
    # method b in class a.b.c -> original computeToken
    kind = _ans(mp, "What is the original name of method b in class a.b.c ?")
    assert kind == ("unsure", "mobile.deobf/method", [["name", "computeToken"]]), kind
    # field a in class a.b.c -> original retryCount (scoped disambiguates the overloaded "a")
    kind = _ans(mp, "What is the original name of the field a in class a.b.c ?")
    assert kind == ("unsure", "mobile.deobf/field", [["name", "retryCount"]]), kind


def test_global_unique_member():
    mp = _mp()
    # computeToken is a unique original name -> its obfuscated counterpart
    kind = _ans(mp, "What is the obfuscated name of the method computeToken?")
    assert kind == ("unsure", "mobile.deobf/method", [["name", "b"]]), kind


def test_none_cases():
    mp = _mp()
    none = lambda *a: _ans(mp, *a)
    assert none("Tell me about class a.b.c") is None                       # no direction word
    assert none("the original class that a.b.c was obfuscated from") is None  # both directions
    assert none("original name of class com.nope.Missing") is None         # unknown symbol
    assert none("original name of method a") is None                       # ambiguous obf member
    assert none("original name of class a.b.c", {"kind": "integer"}) is None  # wrong answer kind
    # two independently-resolvable symbols of the same kind -> ambiguous -> None
    assert none("original names of classes a.b.c and a.b.d") is None
    # a direction word but no symbol the mapping knows -> None
    assert none("what is the original class here") is None


def test_parse_rejects_nonmapping():
    assert P.parse(b"just some text\nwith no arrows at all\n") is None
    assert P.parse(b"\x00\x01\x02binary") is None
    assert P.parse("key: value\nother: thing\n") is None


# ------------------------------------------------------------------ integration through apk_facts

def _axml_manifest(package):
    # apk_facts needs apk_resources.axml_tree to parse this; build a real binary AXML via the
    # lane's own encoder if available, else skip the manifest and rely on a dex so read() fires.
    return None


def _dex(*strings):
    n = len(strings)
    head = bytearray(b"dex\n035\x00" + b"\x00" * (0x70 - 8))
    struct.pack_into("<II", head, 0x38, n, 0x70)
    data, offs = b"", []
    base = 0x70 + 4 * n
    for s in strings:
        b = s.encode() if isinstance(s, str) else s
        offs.append(base + len(data))
        ln, uleb = len(b), b""
        while True:
            byte = ln & 0x7F
            ln >>= 7
            uleb += bytes([byte | (0x80 if ln else 0)])
            if not ln:
                break
        data += uleb + b + b"\0"
    out = bytearray(head) + b"\x00" * (4 * n) + data
    for i, o in enumerate(offs):
        struct.pack_into("<I", out, 0x70 + 4 * i, o)
    return bytes(out)


def _apk_with_mapping():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("classes.dex", _dex("DAY-99:deobf:mapping", "MOB-99-ABCDEF"))
        zf.writestr("mapping.txt", MAP)
    return buf.getvalue()


def test_integration_apk_facts_adds_deobf():
    blob = _apk_with_mapping()
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        members = {i.filename: zf.read(i) for i in zf.infolist() if not i.is_dir()}
    # a deobf question routed to apk_facts.solve_questions resolves via the mapping
    q = {"qid": "orig_class", "question": "What is the original name of class a.b.c ?"}
    out = apk_facts.solve_questions([q], members, blob)
    v = out["orig_class"]
    assert isinstance(v, str) and v.startswith("??"), out
    u = labels.parse(v)
    assert u.key == "mobile.deobf/class" and ["full", "com.example.LoginManager"] in [list(o) for o in u.options], u

    # a package-fact question is UNCHANGED (still answered by apk_facts, not shadowed by the
    # mapping reader): the dex control string DAY-99:deobf:... -> apk_facts' own unsure pick.
    qc = {"qid": "control", "question": "What is the vulnerable control name?"}
    out2 = apk_facts.solve_questions([qc], members, blob)
    v2 = out2["control"]
    assert isinstance(v2, str) and v2.startswith("??"), out2
    uc = labels.parse(v2)
    assert uc.key == "mobile.control/apk" and ["as-written", "deobf"] in [list(o) for o in uc.options], uc
    # and it is byte-for-byte what apk_facts gives with no mapping member present
    assert apk_facts.solve_questions([qc], {"classes.dex": members["classes.dex"]}, blob)["control"] == v2


def test_integration_no_mapping_is_inert():
    # the same APK without a mapping member: deobf question gets None, nothing else changes
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("classes.dex", _dex("DAY-99:deobf:mapping"))
    blob = buf.getvalue()
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        members = {i.filename: zf.read(i) for i in zf.infolist() if not i.is_dir()}
    q = {"qid": "orig_class", "question": "What is the original name of class a.b.c ?"}
    out = apk_facts.solve_questions([q], members, blob)
    assert out["orig_class"] is None, out


def _run():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print("ok", t.__name__)
    print("PASS %d tests" % len(tests))


if __name__ == "__main__":
    _run()
