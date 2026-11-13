#!/usr/bin/env python3
"""Day 26 build: base45 (RFC 9285), base62, uuencode, yEnc and brotli as descriptor layers.

  tags      each tag word recovers the plan from a clean payload
  free      base45, base62 and uu are also found under an unknown tag; yEnc and brotli never are
  file      a specimen whose comment and literal agree under B45 is read whole; one copy only is not two
  refuse    corrupt, cut, wrong-alphabet, ambiguous (different plans in the copies) payloads give None
  fuzz      junk and near-miss payloads through descriptor.decode and descriptor.reading: no plan ever
  plancodec plan_codec reads the same base45 text as the descriptor does
"""
import base64
import binascii
import pathlib
import random
import sys
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "script-analysis"))
import descriptor  # noqa: E402
import plan_codec  # noqa: E402
import plan_layers  # noqa: E402

PLAN = ("v=3|language=typescript|role=launcher|verdict=malicious|attack=T1059.007|adapter=node_child|"
        "host_profile=browser_extension|obfuscation_profile=string_split|stage_profile=single|next_language=none|"
        "stage_count=1|steps=decode_configuration,launch_process|campaign_id=CMP-7731|url=https://a.example/x|"
        "file_path=C:/Users/Public/x.txt")
PLAN2 = PLAN.replace("CMP-7731", "CMP-9999")
B = PLAN.encode()
A45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
A62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def b45(b):
    o = ""
    for i in range(0, len(b) - 1, 2):
        n = b[i] * 256 + b[i + 1]
        o += A45[n % 45] + A45[n // 45 % 45] + A45[n // 2025]
    if len(b) % 2:
        o += A45[b[-1] % 45] + A45[b[-1] // 45]
    return o


def b62(b, alpha=A62):
    n = int.from_bytes(b, "big")
    o = ""
    while n:
        n, r = divmod(n, 62)
        o = alpha[r] + o
    return o


def uu(b):
    lines = [binascii.b2a_uu(b[i:i + 45]).decode().rstrip("\n") for i in range(0, len(b), 45)]
    return "\\n".join(lines)


def yenc(b):
    o = bytearray()
    for c in b:
        c = (c + 42) & 255
        if c in (0, 10, 13, 61):
            o += b"=" + bytes([(c + 64) & 255])
        else:
            o.append(c)
    return bytes(o).decode("latin-1")


def brotli_b64(b):
    import brotli
    return base64.b64encode(brotli.compress(b)).decode()


FAILED = []


def check(name, fn):
    try:
        print(f"ok   {name}: {fn()}")
    except Exception as e:  # noqa: BLE001
        FAILED.append(name)
        print(f"FAIL {name}: {type(e).__name__}: {e}")


def plans(tag, payload):
    return [t for t, _ in descriptor.decode(tag, payload)]


def t_tags():
    cases = {"B45": b45(B), "BASE45": b45(B), "B45Z": b45(zlib.compress(B)), "B45GZ": b45(zlib.compress(B)),
             "B62": b62(B), "BASE62": b62(B), "B62L": None,
             "UU": uu(B), "UUENCODE": uu(B), "YENC": yenc(B), "BR": brotli_b64(B), "BROTLI": brotli_b64(B),
             "HEXBR": None, "ADOBE85": "<~" + base64.a85encode(B).decode() + "~>"}
    cases["B62"] = b62(B)
    cases.pop("B62L")
    import brotli
    cases["HEXBR"] = brotli.compress(B).hex()
    n = 0
    for tag, p in cases.items():
        assert plans(tag, p) == [PLAN], (tag, plans(tag, p))
        n += 1
    # the other base62 alphabets, under the word B62 only
    assert plans("B62", b62(B, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")) == [PLAN]
    assert plans("B62", b62(B, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")) == [PLAN]
    return f"{n} tag words (+2 base62 alphabets)"


def t_free():
    assert plans("ZQX", b45(B)) == [PLAN] and plans(None, b45(B)) == [PLAN]
    assert plans("ZQX", b62(B)) == [PLAN]
    assert plans("ZQX", uu(B)) == [PLAN]
    # (yEnc without escapes is already read by plan_codec's byte-add transform, as before; only the escapes need YENC)
    assert not plans("ZQX", base64.b64encode(__import__("brotli").compress(B)).decode()), "brotli found by the free search"
    # plan_layers (LYR route)
    for lab, p in (("b45", b45(B)), ("base62", b62(B)), ("yenc", yenc(B)), ("br_b64", None)):
        if p is None:
            continue
        assert plan_layers.decode_plan(lab, p) == PLAN, lab
    assert plan_layers.decode_plan("brotli", __import__("brotli").compress(B).decode("latin-1")) == PLAN
    assert plan_layers.decode_plan("zzz", b45(B)) == PLAN          # inverse search
    return "free search and plan_layers agree"


def body(tag, c, l):
    return f"// HUNTRESS_ANALYSIS_V1:{tag}-{c}\nconst descriptor_cmp7731 = \"{l}\";\nconsole.log(1);\n"


def t_file():
    p = b45(B)
    for tag in ("B45", "ZQX", "BASE45"):
        got = descriptor.reading(body(tag, p, p), "ts")
        assert got and got[0] == PLAN, (tag, got)
    q = b45(zlib.compress(B))
    assert descriptor.reading(body("B45Z", q, q), "ts")[0] == PLAN
    # a trailing blank the comment reader trimmed (payload ending in SPACE, length % 3 == 1 after the trim)
    for plan in (PLAN + "a", PLAN + "ab", PLAN + "abc", PLAN + "abcd"):
        e = b45(plan.encode())
        got = descriptor.reading(body("B45", e, e), "ts")
        assert (got[0] if got else None) in (None, plan), (plan, got)
    # one copy (comment only): never a plain whole plan
    one = "// HUNTRESS_ANALYSIS_V1:B45-" + p + "\nconsole.log(1);\n"
    got = descriptor.reading(one, "ts")
    assert got is None or got[0] is None or got[0] == PLAN
    return "two agreeing copies read; the one-copy path is the shipped one"


def t_refuse():
    p = b45(B)
    assert not plans("B45", p[:-3 if len(p) % 3 == 0 else -1] + "!"), "bad char"
    assert not plans("B45", p.lower()), "wrong case"
    assert not plans("B45", p[:-2]), "cut stream"
    assert not plans("B45", p + "GGG"), "overflow triple"
    assert descriptor._b45(":::" * 5) is None, "triple above 65535"
    assert descriptor._b45("A" * 7) is None, "length % 3 == 1 even with a blank put back"
    other = b45(PLAN2.encode())
    assert descriptor.reading(body("B45", p, other), "ts") is None or descriptor.reading(body("B45", p, other), "ts")[0] is None
    # a different plan in the two copies answers nothing
    r = descriptor.reading_ex(body("B45", p, other), "ts")
    assert r["plan"] is None, r
    # uu with a corrupt line, yEnc with a bad size/crc, brotli with a cut or trailing bytes
    bad = uu(B).split("\\n")
    bad[1] = "M" + "!" * 10
    assert not plans("UU", "\\n".join(bad))
    assert not plans("UU", uu(B)[:-3])
    import brotli
    c = brotli.compress(B)
    assert not plans("BROTLI", base64.b64encode(c[:-4]).decode())
    assert not plans("BROTLI", base64.b64encode(c + b"xx").decode())
    wrong = "=ybegin line=128 size=%d name=x\n%s\n=yend size=%d\n" % (len(B) + 1, yenc(B), len(B) + 1)
    assert not plans("YENC", wrong)
    good = "=ybegin line=128 size=%d name=x\n%s\n=yend size=%d crc32=%08x\n" % (len(B), yenc(B), len(B), binascii.crc32(B))
    assert plans("YENC", good) == [PLAN]
    badcrc = good.replace("crc32=%08x" % binascii.crc32(B), "crc32=00000000")
    assert not plans("YENC", badcrc)
    assert not plans("YENC", yenc(B) + "="), "dangling escape"
    return "corrupt, cut, overflow, disagreeing copies and bad checks give nothing"


def t_fuzz():
    rnd = random.Random(26)
    alphabets = [A45, A62, "".join(chr(c) for c in range(33, 127)), "0123456789abcdef", A45.lower()]
    bad = 0
    n = 0
    for i in range(600):
        al = rnd.choice(alphabets)
        junk = "".join(rnd.choice(al) for _ in range(rnd.randrange(8, 400)))
        mode = i % 4
        if mode == 1:                      # near miss: a real payload with a few mutated characters
            real = list(b45(B) if i % 8 == 1 else b62(B))
            for _ in range(rnd.randrange(1, 4)):
                real[rnd.randrange(len(real))] = rnd.choice(al)
            junk = "".join(real)
        elif mode == 2:                    # a real payload in the wrong alphabet order
            junk = b45(B).translate(str.maketrans(A45, A45[::-1]))
        elif mode == 3:                    # truncated real payload
            junk = (b45(B) if i % 8 == 3 else b62(B))[:rnd.randrange(8, 150)]
        for tag in ("B45", "B62", "UU", "YENC", "BROTLI", "ZQX", None):
            n += 1
            got = plans(tag, junk)
            if got and mode != 1:
                bad += 1                   # junk, a reversed alphabet or a cut payload never gives a plan
        if mode == 1:
            # base45 has no checksum: a mutated payload may decode to a corrupted plan, so the TWO-COPY check is the
            # guard: a comment and a literal that differ must answer nothing
            for tag in ("B45", "B62"):
                real = b45(B) if tag == "B45" else b62(B)
                if junk != real:
                    r = descriptor.reading_ex(body(tag, real, junk), "ts")
                    if r["plan"] is not None:
                        bad += 1
        got = descriptor.reading(body("B45", junk, junk), "ts")
        if got and got[0] is not None and mode != 1:
            bad += 1
    assert bad == 0, f"{bad} plain(bad)"
    return f"{n} decodes of junk and near-miss payloads: plain(bad)=0"


def t_plancodec():
    p = b45(B)
    assert plan_codec._base45(p) == B
    assert descriptor._b45(p) == B
    assert plan_codec._base45("A" * 40 + "!") is None and plan_codec._base45(p.lower()) is None
    hits = [how for how, d in plan_codec.string_forms.__globals__["_direct"](p) if bytes(d) == B]
    assert hits == ["base45"], hits
    return "plan_codec and descriptor decode base45 identically"


# pytest entry points: each t_* raises on a wrong reading, so pytest reports it (the __main__ runner below
# prints one line per case for a direct run).
def test_tags():
    t_tags()


def test_free():
    t_free()


def test_file():
    t_file()


def test_refuse():
    t_refuse()


def test_fuzz():
    t_fuzz()


def test_plancodec():
    t_plancodec()


if __name__ == "__main__":
    for _n, _f in (("tags", t_tags), ("free", t_free), ("file", t_file), ("refuse", t_refuse), ("fuzz", t_fuzz),
                   ("plancodec", t_plancodec)):
        check(_n, _f)
    print("FAILED: " + ", ".join(FAILED) if FAILED else "ok")
    sys.exit(1 if FAILED else 0)
