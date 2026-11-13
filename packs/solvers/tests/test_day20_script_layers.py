#!/usr/bin/env python3
"""Row 306 (Day 20 build): descriptor layers UTF-16BE, bzip2 and xz/lzma, read ONLY under the tag word that names
them (descriptor.TAG_LAYERS), never by the free search of an unknown tag, and whole or nothing.

  tags      every new tag word gives the plan, and the same payload under an unknown tag gives nothing
  whole     a cut stream, a stream with bytes behind it, UTF-16LE under a BE tag: no plan
  file      a .ts specimen whose tagged comment and descriptor literal agree under BZ2, XZ and U16BE is read
  octal     OCT (row 234's octal layer, built on Day 18) still reads
"""
import base64
import bz2
import lzma
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "script-analysis"))
import descriptor  # noqa: E402

PLAN = ("v=3|language=typescript|role=launcher|verdict=malicious|attack=T1059.007|adapter=node_child|"
        "host_profile=browser_extension|obfuscation_profile=string_split|stage_profile=single|next_language=none|"
        "stage_count=1|steps=decode_configuration,launch_process|campaign_id=CMP-7731|url=https://a.example/x|"
        "file_path=C:/Users/Public/x.txt")
B = PLAN.encode()


def b64(b):
    return base64.b64encode(b).decode()


ENC = {
    "U16BE": lambda: b64(PLAN.encode("utf-16-be")),
    "UTF16BE": lambda: b64(b"\xfe\xff" + PLAN.encode("utf-16-be")),
    "UTF16BEHEX": lambda: PLAN.encode("utf-16-be").hex(),
    "BZ2": lambda: b64(bz2.compress(B)),
    "BZIP2": lambda: b64(bz2.compress(B)),
    "BZ2HEX": lambda: bz2.compress(B).hex(),
    "XZ": lambda: b64(lzma.compress(B)),
    "LZMA": lambda: b64(lzma.compress(B, format=lzma.FORMAT_ALONE)),
    "XZHEX": lambda: lzma.compress(B).hex(),
}

FAILED = []


def check(name, fn):
    try:
        print(f"ok   {name}: {fn()}")
    except Exception as e:  # noqa: BLE001
        FAILED.append(name)
        print(f"FAIL {name}: {type(e).__name__}: {e}")


def t_tags():
    for tag, enc in ENC.items():
        p = enc()
        got = descriptor.decode(tag, p)
        assert [t for t, _ in got] == [PLAN], (tag, got[:1])
        assert not descriptor.decode("ZQX", p), (tag, "read by the free search")
        assert not descriptor.decode(None, p), (tag, "read by the free search without a tag")
    return f"{len(ENC)} tag words read by their word only"


def t_whole():
    cut = bz2.compress(B)
    assert not descriptor.decode("BZ2", b64(cut[:-6])), "a cut bzip2 stream read"
    assert not descriptor.decode("BZ2", b64(cut + b"tail")), "bytes behind a bzip2 stream read"
    x = lzma.compress(B)
    assert not descriptor.decode("XZ", b64(x[:-12])), "a cut xz stream read"
    assert not descriptor.decode("XZ", b64(x + b"\x00tail")), "bytes behind an xz stream read"
    le = descriptor.decode("U16BE", b64(PLAN.encode("utf-16-le")))   # the free search reads it as UTF-16LE
    assert all("u16be" not in how for _, how in le), ("UTF-16LE read by the BE layer", le)
    assert not descriptor.decode("BZ2", b64(lzma.compress(B))), "xz read under a bzip2 tag"
    assert descriptor._bunzip2("BZh9") is None and descriptor._unxz("x") is None and descriptor._utf16be("ab") is None
    return "cut streams, trailing bytes and the other byte order give nothing"


def t_file():
    n = 0
    for tag in ("BZ2", "XZ", "U16BE"):
        p = ENC[tag]()
        body = (f"// HUNTRESS_ANALYSIS_V1:{tag}-{p}\n"
                f"const descriptor_cmp7731 = \"{p}\";\nconsole.log(descriptor_cmp7731.length);\n")
        got = descriptor.reading(body, "ts")
        assert got is not None and got[0] == PLAN, (tag, got)
        n += 1
    return f"{n} .ts specimens: both copies agree, the plan is read whole"


def t_octal():
    p = " ".join("%03o" % c for c in B)
    assert [t for t, _ in descriptor.decode("OCT", p)] == [PLAN]
    return "OCT reads (built on Day 18)"


# pytest entry points: each t_* raises on a wrong reading, so pytest reports it (the __main__ runner below
# prints one line per case for a direct run).
def test_tags():
    t_tags()


def test_whole():
    t_whole()


def test_file():
    t_file()


def test_octal():
    t_octal()


if __name__ == "__main__":
    for _n, _f in (("tags", t_tags), ("whole", t_whole), ("file", t_file), ("octal", t_octal)):
        check(_n, _f)
    print("FAILED: " + ", ".join(FAILED) if FAILED else "ok")
    sys.exit(1 if FAILED else 0)
