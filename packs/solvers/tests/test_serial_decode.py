#!/usr/bin/env python3
"""solvers/toolkits/serial_decode.py: the language-native serialization structural reader.

Offline, no Game Master request, no token. Every golden fixture below was produced ONCE by the real
interpreter (PHP 8.4 serialize(), Ruby 2.6 Marshal.dump, a Java 24 ObjectOutputStream) and frozen here
as hex, so the reader is checked against genuine bytes without needing php/ruby/java on the box. The
never-wrong boundary is what is under test: a clean, fully-consumed blob yields structural facts as
UNSURE labels.pick values (never plain without a judged name); anything else is None.

  .venv/bin/python tests/test_serial_decode.py

  php         serialize() arrays, objects (class + property names/values, NUL-mangled private/
              protected names demangled), scalars
  ruby        Marshal 4.8 hashes, arrays (symbols), plain objects (class + ivars), scalars, float
  java        a serialization stream: class name, field count, every primitive field value, a
              nested object/array; the real ysoserial gadget chains parse or decline, never crash
  adversarial random/zero/pcap/eml/png/json/truncated/bad-length/extra bytes => None (never partial)
  contract    solve_set is never-wrong: a structural value is an UNSURE pick, a container value / a
              semantic question / an absent field / the flag are None; nothing is ever plain here
  signals     0.0 on a 64-byte blob (the registry's own check), needs the vocabulary, never steals a
              pcap or a mail
  cli         the command prints the format and declines unknown bytes
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
# A fresh, empty ledger so every labels.pick is UNSURE (nothing judged): set before importing labels.
os.environ["CTF_WORKDIR"] = tempfile.mkdtemp(prefix="test_serial_decode_")
os.environ.pop("CTF_TOKEN", None)
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.dont_write_bytecode = True

import pytest     # noqa: E402
import labels                                               # noqa: E402
import serial_decode as sd                                  # noqa: E402

PY = sys.executable
FAILED = []


def judge_backed() -> bool:
    """True when the loaded labels module replays judge acceptance: labels.judge_ledger() is on
    (the event's judge answers per name). Off, or a labels module without it (the neutral shim),
    means an accepted name is never replayed as a plain answer, so the judge tests cannot pass."""
    ledger = getattr(labels, "judge_ledger", None)
    return callable(ledger) and ledger()


# Judge-acceptance tests (an accepted name replays as plain): marked `judge` and skipped, with the
# reason shown, unless a judge-backed labels module is loaded. They used to be dropped from main().
JUDGE = (pytest.mark.judge, pytest.mark.skipif(
    not judge_backed(), reason="judge-acceptance replay needs a judge-backed labels module "
                               "(labels.judge_ledger() is off or absent)"))


def judge(fn):
    for mark in reversed(JUDGE):
        fn = mark(fn)
    return fn


def run_judge(fn):
    """main()'s call of a judge test: run it, or print why it is skipped (never a silent pass)."""
    if judge_backed():
        fn()
    else:
        print(f"skip {fn.__name__}: {JUDGE[1].kwargs['reason']}")

# Golden bytes from the real interpreters (see the module docstring).
G = {
    "php_array": "613a333a7b733a343a2275736572223b733a353a22616c696365223b733a353a22636f756e74223b693a373b733a353a2261646d696e223b623a313b7d",
    "php_object": "4f3a373a224163636f756e74223a343a7b733a343a226e616d65223b733a333a22626f62223b733a373a2262616c616e6365223b693a313233343b733a363a22002a0070696e223b733a343a2230303030223b733a31353a22004163636f756e7400736563726574223b733a363a22733363723374223b7d",
    "php_nested": "613a323a7b733a343a226c697374223b613a333a7b693a303b693a313b693a313b693a323b693a323b693a333b7d733a343a226d657461223b613a333a7b733a343a22666c6167223b623a303b733a353a22726174696f223b643a312e353b733a373a226e6f7468696e67223b4e3b7d7d",
    "php_int": "693a34323b",
    "php_string": "733a31313a2268656c6c6f20776f726c64223b",
    "ruby_hash": "04087b0849220975736572063a06455449220a616c696365063b005449220a636f756e74063b0054690c49220a61646d696e063b005454",
    "ruby_array": "04085b0d690669076908492209666f7572063a0645543a0966697665305446",
    "ruby_object": "04086f3a0c53657373696f6e093a0840696449220b616263313233063a0645543a0a4075736572492208626f62063b07543a0b40636f756e74692f3a0c4061637469766554",
    "ruby_string": "040849221068656c6c6f20776f726c64063a064554",
    "ruby_int": "0408690340420f",
    "ruby_symbol": "04083a09666c6167",
    "ruby_float": "04086609332e3134",
    "ruby_nested": "04087b074922096c697374063a0645545b08690f691969234922096d657461063b00547b064922076f6b063b005454",
    # Java: Account{String name="bob"; int balance=1234; boolean admin=true; long token=9999999999}
    "java_object": "aced00057372000f47656e4a617661244163636f756e74000000000000002a0200045a000561646d696e49000762616c616e63654a0005746f6b656e4c00046e616d657400124c6a6176612f6c616e672f537472696e673b787001000004d200000002540be3ff740003626f62",
    "java_string": "aced000574000b68656c6c6f20776f726c64",
    # Java: Wrapper{String label="root"; Account acct=...alice/7/false/100; int[] nums={10,20,30}}
    "java_wrapper": "aced00057372000f47656e4a617661245772617070657200000000000000070200034c0004616363747400114c47656e4a617661244163636f756e743b4c00056c6162656c7400124c6a6176612f6c616e672f537472696e673b5b00046e756d737400025b4978707372000f47656e4a617661244163636f756e74000000000000002a0200045a000561646d696e49000762616c616e63654a0005746f6b656e4c00046e616d6571007e0002787000000000070000000000000064740005616c696365740004726f6f74757200025b494dba602676eab2a50200007870000000030000000a000000140000001e",
}


def b(name):
    return bytes.fromhex(G[name])


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(label)


def scalar_of(root, name):
    return sd._scalar(sd._field_node(root, name))


# ---- PHP ------------------------------------------------------------------------------------------

def test_php():
    arr = sd.classify(b("php_array"))
    check("php: an assoc array decodes as a map", arr and arr["format"] == "php" and sd._count(arr["root"]) == 3, arr)
    check("php: array values by key", scalar_of(arr["root"], "user") == ("str", "alice")
          and scalar_of(arr["root"], "count") == ("int", 7) and scalar_of(arr["root"], "admin") == ("bool", True))
    obj = sd.classify(b("php_object"))["root"]
    check("php: object class name is byte-exact", sd._classname(obj) == "Account")
    check("php: 4 properties", sd._count(obj) == 4)
    check("php: public property value", scalar_of(obj, "name") == ("str", "bob") and scalar_of(obj, "balance") == ("int", 1234))
    check("php: NUL-mangled protected property matched by bare name", scalar_of(obj, "pin") == ("str", "0000"))
    check("php: NUL-mangled private property matched by bare name", scalar_of(obj, "secret") == ("str", "s3cr3t"))
    nested = sd.classify(b("php_nested"))["root"]
    check("php: nested float/null/bool", scalar_of(nested, "list") is None)  # list is a container -> not scalar
    meta = sd._field_node(nested, "meta")
    check("php: nested map values", sd._scalar(sd._field_node(meta, "flag")) == ("bool", False)
          and sd._scalar(sd._field_node(meta, "ratio")) == ("float", 1.5)
          and sd._scalar(sd._field_node(meta, "nothing")) == ("null", "null"))
    check("php: a lone scalar still decodes but has no count", sd.classify(b("php_int"))["root"]["v"] == 42
          and sd._count(sd.classify(b("php_int"))["root"]) is None)


# ---- Ruby -----------------------------------------------------------------------------------------

def test_ruby():
    h = sd.classify(b("ruby_hash"))
    check("ruby: a hash decodes as a map of 3", h and h["format"] == "ruby" and sd._count(h["root"]) == 3, h)
    check("ruby: hash values by key", scalar_of(h["root"], "user") == ("str", "alice")
          and scalar_of(h["root"], "count") == ("int", 7) and scalar_of(h["root"], "admin") == ("bool", True))
    arr = sd.classify(b("ruby_array"))["root"]
    check("ruby: array length and a symbol element", sd._count(arr) == 8
          and sd._scalar(sd._index_node(arr, 3)) == ("str", "four") and sd._scalar(sd._index_node(arr, 4)) == ("sym", "five"))
    obj = sd.classify(b("ruby_object"))["root"]
    check("ruby: object class from its class symbol", sd._classname(obj) == "Session")
    check("ruby: ivar names have the @ stripped and values are byte-exact",
          scalar_of(obj, "id") == ("str", "abc123") and scalar_of(obj, "user") == ("str", "bob")
          and scalar_of(obj, "count") == ("int", 42) and scalar_of(obj, "active") == ("bool", True))
    check("ruby: Fixnum packed-int decoding", sd.classify(b("ruby_int"))["root"]["v"] == 1000000)
    check("ruby: Float", abs(sd.classify(b("ruby_float"))["root"]["v"] - 3.14) < 1e-9)
    check("ruby: a top-level Symbol", sd.classify(b("ruby_symbol"))["root"] == {"k": "sym", "v": "flag"})


# ---- Java -----------------------------------------------------------------------------------------

def test_java():
    obj = sd.classify(b("java_object"))
    check("java: a stream decodes (AC ED magic)", obj and obj["format"] == "java", obj)
    root = obj["root"]
    check("java: class name is the binary name", sd._classname(root) == "GenJava$Account")
    check("java: field count", sd._count(root) == 4)
    check("java: boolean/int/long/String field values, in declared order",
          scalar_of(root, "admin") == ("bool", True) and scalar_of(root, "balance") == ("int", 1234)
          and scalar_of(root, "token") == ("int", 9999999999) and scalar_of(root, "name") == ("str", "bob"))
    check("java: a top-level String", sd.classify(b("java_string"))["root"] == {"k": "str", "v": "hello world"})
    wrap = sd.classify(b("java_wrapper"))["root"]
    check("java: a wrapper object, handle-table reference resolved (type string reused)",
          sd._classname(wrap) == "GenJava$Wrapper" and sd._count(wrap) == 3)
    check("java: a String field of the wrapper", scalar_of(wrap, "label") == ("str", "root"))
    check("java: a nested object field is a container, not a scalar", sd._scalar(sd._field_node(wrap, "acct")) is None)
    acct = sd._field_node(wrap, "acct")
    check("java: the nested object decoded too", sd._classname(acct) == "GenJava$Account"
          and scalar_of(acct, "name") == ("str", "alice") and scalar_of(acct, "balance") == ("int", 7))
    nums = sd._field_node(wrap, "nums")
    check("java: a primitive array field length and elements",
          sd._count(nums) == 3 and sd._scalar(sd._index_node(nums, 0)) == ("int", 10)
          and sd._scalar(sd._index_node(nums, 2)) == ("int", 30))


def test_real_java_gadget_chains():
    """The real ysoserial gadget streams (java_templates.json) are complex (custom writeObject block
    data, PriorityQueue/HashSet/Hashtable). They must parse cleanly or decline - never crash, never a
    wrong partial read."""
    import base64
    import json as _json
    tpl = REPO / "solvers" / "toolkits" / "java_templates.json"
    if not tpl.is_file():
        print("skip real-java: java_templates.json is not present")
        return
    blobs = []

    def walk(o):
        if isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
        elif isinstance(o, str) and len(o) > 40:
            try:
                raw = base64.b64decode(o)
            except Exception:  # noqa: BLE001
                return
            if raw[:2] == b"\xac\xed":
                blobs.append(raw)

    walk(_json.loads(tpl.read_text()))
    check("real-java: ysoserial AC ED streams are present to exercise the walk", len(blobs) >= 5, len(blobs))
    bad, parsed = [], 0
    for raw in blobs:
        try:
            rep = sd.classify(raw)
        except Exception as e:  # noqa: BLE001
            bad.append(repr(e))
            continue
        if rep is not None:
            parsed += 1
            cn = sd._classname(rep["root"])
            if cn is not None and not isinstance(cn, str):
                bad.append("non-str class")
    check("real-java: every gadget stream parses or declines, never crashes", not bad, bad[:3])
    check("real-java: at least the common gadget chains parse to a top-level class", parsed >= 5, parsed)


# ---- adversarial: never a wrong read --------------------------------------------------------------

def test_adversarial():
    cases = {
        "random64": os.urandom(64),
        "zeros64": bytes(64),
        "pcap_le": bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000"),
        "eml": b"From: a@b.com\r\nTo: c@d.com\r\nSubject: serialize() object\r\n\r\nbody\r\n",
        "png": bytes.fromhex("89504e470d0a1a0a0000000d49484452"),
        "json": b'{"a":1,"b":[2,3]}',
        "php_trunc": b("php_object")[:-3],
        "php_bad_length": b("php_object").replace(b's:3:"bob"', b's:9:"bob"'),
        "java_trunc": b("java_object")[:-2],
        "java_trailing": b("java_object") + b"\x00\x05",
        "ruby_trunc": b("ruby_object")[:-1],
        "text_after_scalar": b"i:5;extra",
    }
    for name, data in cases.items():
        check(f"adversarial: {name} does not decode (None)", sd.classify(data) is None, name)
    # A lone 'i:5;' IS valid PHP, but it is a scalar: signals must refuse it so it wins no match.
    check("adversarial: a lone PHP scalar classifies but signals 0 (no container)",
          sd.classify(b"i:5;") is not None and sd.signals([{"question": "serialize"}], {"a": b"i:5;"}) == 0.0)


# ---- never-wrong contract -------------------------------------------------------------------------

def q(text, aid):
    return {"qid": aid, "answer_id": aid, "question": text, "answer_format": {"kind": "exact_text"}}


def test_contract():
    files = {"blob.ser": b("java_wrapper")}
    qs = [
        q("What is the class name of the serialized object?", "cls"),
        q("How many fields does the object have?", "cnt"),
        q("What is the value of the 'label' field?", "lab"),
        q("What serialization format is this blob?", "fmt"),
        q("What is the value of the 'acct' field?", "container"),   # a nested object -> None
        q("What does the 'label' field mean?", "semantic"),         # 'mean' is not a value read
        q("What is the 'missing' field?", "absent"),
        q("What is the flag?", "flag"),
    ]
    ans = sd.solve_set(qs, files, {})
    # Structural facts: an UNSURE pick (labels.parse not None), never plain.
    for aid in ("cls", "cnt", "lab", "fmt"):
        p = labels.parse(ans.get(aid))
        check(f"contract: {aid} is an unsure pick, never plain", p is not None and p.key.startswith("serial_decode."),
              ans.get(aid))
    check("contract: the class pick offers the byte-exact name first",
          labels.parse(ans["cls"]).options[0] == ("raw", "GenJava$Wrapper"))
    check("contract: the count pick is the real field count", labels.parse(ans["cnt"]).options[0] == ("decimal", "3"))
    check("contract: the field pick is the byte-exact value", labels.parse(ans["lab"]).options[0] == ("raw", "root"))
    # None for a container value, a semantic question, an absent field, and the flag.
    check("contract: a container-valued field is None", ans.get("container") is None)
    check("contract: an absent field is None", ans.get("absent") is None)
    check("contract: the flag is never answered", ans.get("flag") is None)
    # The semantic 'mean' question: 'label' is quoted so it is still read as a field value here; the
    # point of the contract is that nothing is ever PLAIN, which the pick guarantees.
    sem = ans.get("semantic")
    check("contract: a semantic question is None or an unsure pick, never plain",
          sem is None or labels.parse(sem) is not None)
    # gm.session() would strip every ?? value, so no unsure answer can reach the judge.
    for aid, v in ans.items():
        check(f"contract: {aid} never reaches the judge as a bare wrong plain value",
              v is None or labels.parse(v) is not None)


# ---- never-wrong: the count/index key is scoped by WHICH container ---------------------------------

@judge
def test_count_scope():
    """The audited hole: the count/index branch answered _count(root) for ANY count-like question and
    keyed it only by rendering (serial_decode.count/<fmt>), not by container. So a 'decimal' the judge
    accepted from a ROOT count question would then answer a NON-root count ('how many elements in the
    roles array') with the ROOT count as a wrong PLAIN value, sinking the batch. The key is now scoped
    by the target container, and a named container that does not resolve is None, never the root count."""
    files = {"blob.ser": b("java_wrapper")}               # Wrapper{label, acct=Account(4 fields), nums[3]}
    root = sd.classify(b("java_wrapper"))["root"]
    root_n = sd._count(root)
    acct_n = sd._count(sd._field_node(root, "acct"))
    check("count-scope fixture: root has 3 fields, the acct object has 4 (distinct counts)",
          root_n == 3 and acct_n == 4, (root_n, acct_n))

    def one(text):
        return sd.solve_set([q(text, "x")], files, {}).get("x")

    # 1) Structural: the root count and a named nested container's count are DIFFERENT keys.
    rk = labels.parse(one("How many fields does the object have?"))
    ak = labels.parse(one("How many fields does the 'acct' object have?"))
    check("count-scope: the root count is an unsure pick keyed to the root (@root)",
          rk is not None and rk.key == "serial_decode.count/@root/java" and rk.options[0] == ("decimal", "3"), rk and rk.key)
    check("count-scope: a named nested container's count is a DIFFERENT key, scoped to that member (@acct)",
          ak is not None and ak.key == "serial_decode.count/@acct/java" and ak.options[0] == ("decimal", "4")
          and ak.key != rk.key, ak and ak.key)

    # An index of a named array is likewise scoped to that array, not the root.
    nk = labels.parse(one("What is element 0 of the nums array?"))
    check("index-scope: element N of a named array is keyed to that array (@nums), value byte-exact",
          nk is not None and nk.key == "serial_decode.index0/@nums/java" and nk.options[0] == ("decimal", "10"), nk and nk.key)

    # 2) A count/index question that names a container which does not resolve is None, never the root.
    check("count-scope: 'elements in the roles array' (no such member) is None, not the root count",
          one("How many elements are in the roles array?") is None)
    check("index-scope: 'element 0 of the roles array' (no such member) is None, not a root element",
          one("What is element 0 of the roles array?") is None)

    # 3) Behavioral never-wrong: once the judge accepts a rendering for the ROOT count key, a later
    #    variant asking a NON-root count must NOT emit the root count as a wrong PLAIN answer.
    labels.learn("serial_decode.count/@root/java", "decimal", "accepted")
    root_live = one("How many fields does the object have?")
    check("count-scope: with 'decimal' accepted for the root key, the ROOT count is now plain ('3')",
          labels.parse(root_live) is None and root_live == "3", root_live)
    acct_live = one("How many fields does the 'acct' object have?")
    check("count-scope: the accepted root rendering does NOT leak to the acct count "
          "(still an unsure pick, and never the stale root count '3')",
          acct_live is not None and labels.parse(acct_live) is not None and acct_live != "3", acct_live)
    roles_live = one("How many elements are in the roles array?")
    check("count-scope: a non-root count naming an absent container stays None, never the plain root count '3'",
          roles_live is None, roles_live)


# ---- signals --------------------------------------------------------------------------------------

def test_signals():
    check("signals: a 64-byte zero blob scores 0.0 (the registry's own invariant)",
          sd.signals([q("What is it?", "q")], {"a.bin": bytes(64)}) == 0.0)
    jv = sd.signals([q("What class is the serialized Java object and how many fields?", "q")], {"a.ser": b("java_object")})
    check("signals: a Java blob with serialization vocabulary is over the 0.5 threshold", jv >= 0.5, jv)
    pv = sd.signals([q("How many properties does the PHP serialized object have?", "q")], {"a.txt": b("php_object")})
    check("signals: a PHP object with vocabulary is over the 0.5 threshold", pv >= 0.5, pv)
    nv = sd.signals([q("What is the answer?", "q")], {"a.ser": b("java_object")})
    check("signals: a Java blob with no vocabulary stays under 0.5 (needs the words too)", nv < 0.5, nv)
    pc = sd.signals([q("decode the serialized network capture", "q")],
                    {"a.pcap": bytes.fromhex("d4c3b2a1020004000000000000000000")})
    check("signals: a pcap is never claimed", pc == 0.0, pc)


# ---- CLI ------------------------------------------------------------------------------------------

# ---- negative integers: field-width masking (the serial-structural never-wrong hole) --------------

import struct                                                # noqa: E402


def _java_obj(fields, values):
    """A minimal, genuine Java serialization stream for one object of class 'N' with the given
    primitive fields (the parser reads descriptor order, so descriptor and value order match here).
    fields: [(typecode_char, name)]; values: [raw big-endian bytes], same order."""
    out = bytearray(b"\xac\xed\x00\x05")                    # STREAM_MAGIC + version 5
    out += b"\x73\x72"                                      # TC_OBJECT, TC_CLASSDESC
    out += struct.pack(">H", 1) + b"N"                      # class name
    out += struct.pack(">q", 1)                             # serialVersionUID
    out += b"\x02"                                          # SC_SERIALIZABLE
    out += struct.pack(">H", len(fields))
    for tc, nm in fields:
        nm = nm.encode()
        out += tc.encode() + struct.pack(">H", len(nm)) + nm
    out += b"\x78\x70"                                      # TC_ENDBLOCKDATA (classAnnotation), TC_NULL (super)
    for v in values:
        out += v
    return bytes(out)


def test_negative_width():
    """serial-structural / wave125: a signed-int hex rendering was a FIXED 64-bit mask
    (n & 0xFFFFFFFFFFFFFFFF), WRONG for a narrower field (a 16-bit -1 became ffffffffffffffff, not
    ffff) and dropping the signed spelling. Now a negative int's renderings are candidate HYPOTHESES
    (unsure, never a single wrong plain): the two's-complement form is masked to the FIELD's
    byte-proven width (never assumed 64-bit, and never offered at all without a proven width), and the
    signed sign-magnitude spelling is always offered."""
    # 1) _int_options directly: width comes from the field, the 64-bit mask is gone.
    pos_opts, pos_cand = sd._int_options(255, 8)
    check("neg-width: a non-negative int stays a plain-eligible pick (hex 'ff', not a candidate)",
          pos_cand is False and ("hex", "ff") in pos_opts and ("decimal", "255") in pos_opts, pos_opts)

    for bits, mask_hex in ((8, "ff"), (16, "ffff"), (32, "ffffffff"), (64, "ffffffffffffffff")):
        opts, cand = sd._int_options(-1, bits)
        vals = dict(opts)
        check(f"neg-width: -1 at {bits}-bit masks to its OWN width ({mask_hex}), as a candidate",
              cand is True and vals.get(f"hex_u{bits}") == mask_hex, opts)
        check(f"neg-width: -1 at {bits}-bit offers the signed spelling (-1 / -0x1)",
              vals.get("hex_signed") == "-1" and vals.get("hex_0x_signed") == "-0x1", opts)
        if bits != 64:
            check(f"neg-width: -1 at {bits}-bit NEVER emits the old fixed 64-bit value",
                  "ffffffffffffffff" not in vals.values(), opts)

    o32, _ = sd._int_options(-5, 32)
    check("neg-width: -5 at 32-bit is fffffffb (two's-complement at the true width)",
          dict(o32).get("hex_u32") == "fffffffb" and dict(o32).get("hex_signed") == "-5", o32)

    # arbitrary precision (PHP/Ruby carry no width): NO two's-complement hypothesis is ever offered.
    on, cn = sd._int_options(-5, None)
    check("neg-width: with no proven width, only signed renderings (no hex_uNN guess)",
          cn is True and not any(n.startswith("hex_u") for n, _ in on)
          and dict(on).get("hex_signed") == "-5" and ("decimal", "-5") in on, on)

    # 2) Byte-proven width flows from the Java typecode into the node ("bits").
    data = _java_obj([("S", "s"), ("I", "i"), ("J", "l"), ("B", "b")],
                     [struct.pack(">h", -1), struct.pack(">i", -5),
                      struct.pack(">q", -2), struct.pack(">b", -1)])
    rep = sd.classify(data)
    root = rep["root"] if rep else None
    check("neg-width: the hand-built negative-field stream parses as java", rep and rep["format"] == "java", rep)
    widths = {nm: sd._field_node(root, nm).get("bits") for nm in ("s", "i", "l", "b")}
    check("neg-width: the typecode byte-proves each field width (S=16, I=32, J=64, B=8)",
          widths == {"s": 16, "i": 32, "l": 64, "b": 8}, widths)

    # 3) End-to-end through solve_set: a narrow negative field answers with a width-masked candidate,
    #    offers the signed spelling, and is NEVER a wrong plain (no 64-bit mask on a 16-bit field).
    files = {"blob.ser": data}

    def ans_for(name):
        return sd.solve_set([q(f"What is the value of the '{name}' field?", "x")], files, {}).get("x")

    sv = ans_for("s")                                       # short -1 (16-bit)
    pv = labels.parse(sv)
    check("neg-width E2E: a 16-bit -1 field is an UNSURE candidate pick, never plain",
          pv is not None and labels.is_candidate(sv), sv)
    svals = dict(pv.options) if pv else {}
    check("neg-width E2E: the 16-bit field masks hex to ffff (NOT the old ffffffffffffffff)",
          svals.get("hex_u16") == "ffff" and "ffffffffffffffff" not in svals.values(), pv and pv.options)
    check("neg-width E2E: the 16-bit field offers the signed spelling (-1 / -0x1)",
          svals.get("hex_signed") == "-1" and svals.get("hex_0x_signed") == "-0x1", pv and pv.options)

    iv = labels.parse(ans_for("i"))                         # int -5 (32-bit)
    check("neg-width E2E: a 32-bit -5 field masks hex to fffffffb and offers -5",
          iv is not None and dict(iv.options).get("hex_u32") == "fffffffb"
          and dict(iv.options).get("hex_signed") == "-5", iv and iv.options)

    bv = labels.parse(ans_for("b"))                         # byte -1 (8-bit)
    check("neg-width E2E: an 8-bit -1 field masks hex to ff (one byte, not eight)",
          bv is not None and dict(bv.options).get("hex_u8") == "ff"
          and "ffffffffffffffff" not in dict(bv.options).values(), bv and bv.options)

    # 4) A positive field is unchanged: plain-eligible labels.pick (not a candidate), unambiguous hex.
    posdata = _java_obj([("I", "p")], [struct.pack(">i", 255)])
    posv = sd.solve_set([q("What is the value of the 'p' field?", "x")], {"b.ser": posdata}, {}).get("x")
    pp = labels.parse(posv)
    check("neg-width E2E: a positive field stays an ordinary (non-candidate) pick with hex 'ff'",
          pp is not None and not labels.is_candidate(posv) and dict(pp.options).get("hex") == "ff", pp and pp.options)


def test_cli():
    tmp = Path(tempfile.mkdtemp(prefix="serial_cli_"))
    ser = tmp / "a.ser"
    ser.write_bytes(b("java_object"))
    r = subprocess.run([PY, str(REPO / "solvers" / "toolkits" / "serial_decode.py"), str(ser)],
                       capture_output=True, text=True, timeout=60)
    check("cli: prints the format and the class", r.returncode == 0 and "[java]" in r.stdout
          and "GenJava$Account" in r.stdout, (r.stdout + r.stderr)[-300:])
    other = tmp / "b.bin"
    other.write_bytes(b"not serialized at all, just text\n")
    r2 = subprocess.run([PY, str(REPO / "solvers" / "toolkits" / "serial_decode.py"), str(other)],
                        capture_output=True, text=True, timeout=60)
    check("cli: declines unknown bytes", r2.returncode == 0 and "no Java/PHP/Ruby" in r2.stdout, r2.stdout[-200:])


def main() -> int:
    test_php()
    test_ruby()
    test_java()
    test_real_java_gadget_chains()
    test_adversarial()
    test_contract()
    test_signals()
    test_cli()
    run_judge(test_count_scope)
    test_negative_width()
    if FAILED:
        print(f"\n{len(FAILED)} FAILED: " + "; ".join(FAILED))
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
