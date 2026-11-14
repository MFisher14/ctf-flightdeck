#!/usr/bin/env python3
"""solvers/toolkits/deser_chain.py: the passive Java / PHP / .NET serialized-object reader (wave121).
Offline, standard library only, no Game Master request and no token; the labels ledger is pointed at a
temporary CTF_WORKDIR so every answer here is unsure (nothing judged).

  .venv/bin/python tests/test_deser_chain.py

  java     the eight real ysoserial payloads in solvers/toolkits/java_templates.json parse to completion,
           with the right root object class and gadget-family hint; a minimal String stream; a base64 layer
           is peeled; a truncated stream keeps names but trusts no count (complete=False)
  php      an object blob (class, property names, count, Monolog family), a nested graph (depth, count), a
           scalar (recognised but low signal), a phar manifest metadata blob; byte-exact lengths fail closed
  dotnet   a hand-built MS-NRBF stream (type name, assembly library, record count, DataSet family); a
           truncated stream keeps the type but complete=False
  never-wrong  counts are plain-ELIGIBLE picks (unsure here, with the true value as the option), names and
           gadget families are unsure candidates, the format is a non-bare pick, a flag is None, an
           incomplete parse gives no count; a command/url is a lead, never an answer
  signals  0 for a pickle (ai_model_files owns it), 0 for 64 null bytes, a pcap header, random text; a
           java/dotnet magic scores over threshold on the bytes alone
"""
import base64
import json
import os
import struct
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="test_deser_chain_"))
os.environ["CTF_WORKDIR"] = str(TMP / "challenges")   # an empty ledger: every answer is unsure
os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
sys.path.insert(0, str(REPO / "solvers" / "common"))
import labels            # noqa: E402
import deser_chain as T  # noqa: E402

FAILED = []


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(label)


def q(text, qid="q", member=None):
    d = {"qid": qid, "answer_id": qid, "question": text, "answer_format": {"kind": "exact_text"}}
    if member:
        d["artifact"] = "evidence -> " + member
        d["member"] = member
    return d


def one(text, data, filename="blob.bin"):
    out = T.solve_set([q(text)], {filename: data}, {})
    return out.get("q")


# --------------------------------------------------------------------------- fixtures

def java_payloads():
    tj = json.loads((REPO / "solvers" / "toolkits" / "java_templates.json").read_text())
    return {name: base64.b64decode(g["b64"]) for name, g in tj["exec"].items()} | \
           {"URLDNS": base64.b64decode(tj["urldns"]["b64"])}


def nrbf(lib="System.Data, Version=4.0.0.0", typename="System.Data.DataSet", trailing=True):
    def lp(s):
        b = s.encode("utf-8")
        n, out = len(b), bytearray()
        while True:
            x = n & 0x7F
            n >>= 7
            out.append(x | 0x80 if n else x)
            if not n:
                break
        return bytes(out) + b
    d = bytearray()
    d += bytes([0]) + struct.pack("<iiii", 1, -1, 1, 0)                 # header
    d += bytes([12]) + struct.pack("<i", 2) + lp(lib)                   # BinaryLibrary
    d += bytes([5]) + struct.pack("<i", 1) + lp(typename)              # ClassWithMembersAndTypes
    d += struct.pack("<i", 2) + lp("DataSetName") + lp("count")        # 2 members
    d += bytes([1, 0]) + bytes([8])                                     # String, Primitive(Int32)
    d += struct.pack("<i", 2)                                           # LibraryId
    d += bytes([6]) + struct.pack("<i", 3) + lp("mydataset")           # member0 value
    d += struct.pack("<i", 7)                                           # member1 value
    if trailing:
        d += bytes([11])                                               # MessageEnd
    return bytes(d)


def phar():
    meta = b'O:4:"Evil":1:{s:1:"x";s:1:"y";}'
    alias = b"test.phar"
    inner = struct.pack("<IHII", 1, 0x1100, 0, len(alias)) + alias + struct.pack("<I", len(meta)) + meta
    stub = b"<?php __HALT_COMPILER(); ?>\r\n"
    return stub + struct.pack("<I", len(inner)) + inner


# --------------------------------------------------------------------------- java

def test_java():
    pays = java_payloads()
    bad = [n for n, b in pays.items() if not (T.classify(b) or {}).get("complete")]
    check("every real ysoserial payload parses to completion", not bad, bad)
    roots = {n: T.classify(b)["root_class"] for n, b in pays.items()}
    check("CommonsCollections6 root is java.util.HashSet", roots["CommonsCollections6"] == "java.util.HashSet", roots.get("CommonsCollections6"))
    check("CommonsCollections5 root is the BadAttributeValueExpException",
          roots["CommonsCollections5"] == "javax.management.BadAttributeValueExpException", roots.get("CommonsCollections5"))
    check("CommonsBeanutils1 root is java.util.PriorityQueue", roots["CommonsBeanutils1"] == "java.util.PriorityQueue", roots.get("CommonsBeanutils1"))
    cc6 = T.classify(pays["CommonsCollections6"])
    fams = [v for _n, v in cc6["gadget_families"]]
    check("CommonsCollections6 gadget family hint is commons_collections", fams and fams[0] == "commons_collections", fams)
    check("URLDNS family hint is urldns", [v for _n, v in T.classify(pays["URLDNS"])["gadget_families"]] == ["urldns"],
          T.classify(pays["URLDNS"])["gadget_families"])
    check("CommonsCollections6 references InvokerTransformer among its classes",
          any("InvokerTransformer" in c for c in cc6["classes"]), cc6["classes"][:4])

    # a minimal valid Java String stream
    js = bytes([0xAC, 0xED, 0x00, 0x05, 0x74, 0x00, 0x02]) + b"hi"
    r = T.classify(js)
    check("a minimal Java String stream is recognised and complete", r and r["format"] == "java" and r["complete"]
          and r["strings"] == ["hi"], r)

    # a base64-wrapped Java stream is peeled
    b64 = base64.b64encode(pays["CommonsCollections6"])
    rb = T.classify(b64)
    check("a whole-file base64 Java stream is peeled (outer_encoding=['base64'])",
          rb and rb["format"] == "java" and rb["outer_encoding"] == ["base64"] and rb["complete"], rb and rb.get("outer_encoding"))

    # a truncated stream: names kept, complete False
    rt = T.classify(pays["CommonsCollections6"][:200])
    check("a truncated Java stream keeps class names but is not complete", rt and not rt["complete"] and rt["classes"], rt)


# --------------------------------------------------------------------------- php

def test_php():
    obj = b'O:32:"Monolog\\Handler\\SyslogUdpHandler":1:{s:3:"foo";s:3:"bar";}'
    r = T.classify(obj)
    check("a PHP serialized object parses: class, 1 property 'foo', complete",
          r and r["format"] == "php" and r["classes"] == ["Monolog\\Handler\\SyslogUdpHandler"]
          and r["root"][1] == ["foo"] and r["root"][2] == 1 and r["complete"], r)
    check("the PHP object's gadget family hint is monolog_rce", [v for _n, v in r["gadget_families"]] == ["monolog_rce"], r["gadget_families"])

    nested = b'a:2:{i:0;O:3:"Foo":2:{s:1:"a";i:1;s:1:"b";O:3:"Bar":0:{}}i:1;s:5:"hello";}'
    rn = T.classify(nested)
    check("a nested PHP graph: 2 objects, classes [Foo, Bar], depth tracked, array root",
          rn and rn["object_count"] == 2 and rn["classes"] == ["Foo", "Bar"] and rn["max_depth"] >= 2
          and rn["root_kind"] == "array", rn)

    scalar = T.classify(b'i:42;')
    check("a PHP serialized scalar is recognised (object_count 0)", scalar and scalar["format"] == "php" and scalar["object_count"] == 0, scalar)

    # byte-exact length is enforced (fail closed): a wrong length prefix -> None
    check("a PHP object with a wrong length prefix is rejected (byte-exact, fail closed)",
          T.classify(b'O:99:"Foo":0:{}') is None and T.classify(b's:3:"abcd";') is None)
    check("trailing bytes after a complete value are rejected", T.classify(b'i:1;junk') is None)

    rp = T.parse_phar(phar())
    check("a phar's manifest global-metadata is parsed as PHP (has_phar, class Evil, 1 file)",
          rp and rp.get("has_phar") and rp["classes"] == ["Evil"] and rp.get("phar_files") == 1, rp)


# --------------------------------------------------------------------------- dotnet

def test_dotnet():
    r = T.classify(nrbf())
    check("a .NET NRBF stream parses: type System.Data.DataSet, a BinaryLibrary, complete",
          r and r["format"] == "dotnet" and r["types"] == ["System.Data.DataSet"] and r["libraries"]
          and r["complete"] and r["root_type"] == "System.Data.DataSet", r)
    check("the .NET stream's gadget family hint is dataset", [v for _n, v in r["gadget_families"]] == ["dataset"], r["gadget_families"])
    check("the .NET record count is read", r and r["record_count"] >= 4, r and r.get("record_count"))
    rt = T.classify(nrbf(trailing=False)[:-8])
    check("a truncated NRBF stream keeps the type but is not complete", rt and rt["types"] == ["System.Data.DataSet"] and not rt["complete"], rt)
    check("an NRBF header with the wrong version is not recognised",
          T.classify(bytes([0]) + struct.pack("<iiii", 1, -1, 2, 0) + bytes(8)) is None)


# --------------------------------------------------------------------------- never-wrong contract

def test_never_wrong():
    cc6 = java_payloads()["CommonsCollections6"]
    rep = T.classify(cc6)

    # count: a plain-ELIGIBLE pick (unsure here, with the true value as the option)
    a = one("how many classes are referenced in this stream?", cc6)
    p = labels.parse(a)
    check("count: an unsure pick under deser_chain.class_count/java with the true count as its value",
          p is not None and p.key == "deser_chain.class_count/java" and not labels.is_candidate(a)
          and p.options[0][1] == str(rep["class_count"]), a)

    # gadget family: an unsure candidate (never plain)
    a = one("which gadget chain does this payload use?", cc6)
    check("gadget family: an unsure CANDIDATE, first option a family name, never plain",
          labels.is_candidate(a) and labels.parse(a).key.startswith("deser_chain.gadget_family/")
          and labels.parse(a).options[0][1] == "commons_collections", a)

    # root class: a pick whose first option value is the true root (renderings, name != value)
    a = one("what is the root object's class?", cc6)
    p = labels.parse(a)
    check("root class: an unsure pick whose first option value is the true root class, and name != value",
          p is not None and p.key == "deser_chain.root_class/java" and p.options[0][1] == rep["root_class"]
          and all(n != v for n, v in p.options), a)

    # format: a pick, and no option has name == value (not a bare-label pick)
    a = one("what serialization format is this blob?", cc6)
    p = labels.parse(a)
    check("format: an unsure pick with no bare name==value option", p is not None and p.key == "deser_chain.format/java"
          and all(n != v for n, v in p.options), a)

    # flag: always None
    check("a flag question is always None", one("what is the flag?", cc6) is None)
    check("an embedded command question is None (reported as a lead, never submitted)",
          one("what command does the payload run?", cc6) is None)

    # incomplete parse -> no count
    check("a truncated stream gives None for a count question (complete=False)",
          one("how many classes are referenced?", cc6[:200]) is None)

    # php property count is a plain-eligible pick with the true value
    obj = b'O:32:"Monolog\\Handler\\SyslogUdpHandler":1:{s:3:"foo";s:3:"bar";}'
    a = one("how many properties does the root object have?", obj)
    p = labels.parse(a)
    check("php property count: an unsure pick deser_chain.property_count/php with value '1'",
          p is not None and p.key == "deser_chain.property_count/php" and p.options[0][1] == "1", a)

    # dotnet assembly -> candidate
    a = one("which assembly library is referenced?", nrbf())
    check("dotnet library: an unsure candidate under deser_chain.library/dotnet",
          labels.is_candidate(a) and labels.parse(a).key.startswith("deser_chain.library/"), a)

    # a leads scan surfaces a command string as a finding, never an answer
    cc = T.classify(java_payloads()["CommonsCollections6"])
    leads = T.leads_from(cc)
    check("leads_from surfaces findings (list; command/url/flag kinds only)", isinstance(leads, list)
          and all(d["kind"] in ("possible_command", "url", "flag_shaped") for d in leads), leads[:3])


# --------------------------------------------------------------------------- signals

def test_signals():
    pays = java_payloads()
    s_java = T.signals([q("what is the serialized object?")], {"a.ser": pays["CommonsCollections6"]})
    check("a Java stream signals over the 0.6 threshold on the bytes alone", s_java >= 0.6, s_java)
    s_net = T.signals([q("what type is in the payload?")], {"a.bin": nrbf()})
    check("a .NET NRBF stream signals over threshold", s_net >= 0.6, s_net)
    s_phpobj = T.signals([q("what class is unserialized?")], {"a.txt": b'O:3:"Foo":0:{}'})
    check("a PHP serialized object with deser vocabulary signals over threshold", s_phpobj >= 0.6, s_phpobj)
    s_scalar = T.signals([q("serialized?")], {"a.txt": b'i:42;'})
    check("a bare PHP scalar does NOT match on the bytes alone (< threshold)", s_scalar < 0.6, s_scalar)

    # pickle is ai_model_files'; 64 nulls / pcap / text are nothing
    check("a python pickle signals 0 (ai_model_files owns it)", T.signals([q("x")], {"m.pkl": b"\x80\x04K\x01."}) == 0.0)
    check("64 null bytes signal 0.0", T.signals([q("What is it?")], {"a.bin": bytes(64)}) == 0.0)
    check("a pcap header signals 0.0", T.signals([q("x")], {"a.pcap": b"\xd4\xc3\xb2\xa1" + bytes(60)}) == 0.0)
    check("plain text signals 0.0", T.signals([q("x")], {"a.txt": b"hello world, this is not serialized at all\n"}) == 0.0)


def main():
    try:
        test_java()
        test_php()
        test_dotnet()
        test_never_wrong()
        test_signals()
    finally:
        import shutil
        shutil.rmtree(TMP, ignore_errors=True)
    if FAILED:
        print(f"\n{len(FAILED)} FAILED: " + "; ".join(FAILED))
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
