#!/usr/bin/env python3
"""Harness for the Day 24 look-ahead T4 readers: fat / Spring-Boot / nested JAR.

  .venv/bin/python -m pytest tests/test_day24_metadata_jar_springboot.py   (or `python tests/test_day24_metadata_jar_springboot.py`)

Offline, synthetic jars built in memory (no Game Master, no token). Pins NEVER-WRONG behaviour:
  - jar.start_class and the Spring-Boot-* manifest attributes read their real value but answer UNSURE
    ('raw') -- never plain before the judge accepts a name (jar.main_class stays the one judged jar key);
  - a known manifest attribute that is absent answers the unsure 'none', never a wrong plain guess;
  - BOOT-INF/lib (Spring Boot) and embedded *.jar (fat jar) enumerate correctly, UNSURE, offered under the
    +order ledger key with BOTH file order and ascending-sorted (the Day 23 collation lesson);
  - the embedded-jar count is correct and unsure; is_spring_boot / is_fat_jar are unsure bools;
  - a non-jar / plain archive answers None or the unsure 'none', never a wrong plain value.
"""
import importlib.util
import io
import json as _json
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
META = ROOT / "solvers" / "metadata-forensics"
COMMON = ROOT / "solvers" / "common"
for p in (str(COMMON), str(META)):
    if p not in sys.path:
        sys.path.insert(0, p)


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _load("ps_jar_test", META / "properties_strict.py")
labels = _load("labels_jar_test", COMMON / "labels.py")


def check(name, ok, detail=""):
    print(("ok  " if ok else "FAIL") + " : " + name + ("" if ok else f"   {detail}"))
    assert ok, f"{name}   {detail}"


def jar(manifest, members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("META-INF/MANIFEST.MF", manifest)
        for n, b in members:
            z.writestr(n, b)
    return buf.getvalue()


def ask(prop, data, name="app.jar", kind="exact_text"):
    s = prop.replace(".", "-").replace("_", "-")
    q = {"id": f"d24-{name}-{s}", "answer_id": f"d24-{name}-{s}",
         "question": f"Inspect `{name}`. Determine {prop} for {name}.", "artifact": f"evidence.zip -> {name}",
         "answer_format": {"kind": kind, "syntax": "artifact-derived value"}}
    a = M.answer_question(q, {name: data}, {})
    parsed = labels.parse(a)
    opts = None if parsed is None else (parsed.options if hasattr(parsed, "options") else parsed["o"])
    return a, parsed, opts


def is_unsure(a):
    return isinstance(a, str) and a.startswith("??") and labels.parse(a) is not None


def first_val(opts):
    return opts[0][1] if opts else None


SB_MF = ("Manifest-Version: 1.0\r\n"
         "Main-Class: org.springframework.boot.loader.JarLauncher\r\n"
         "Start-Class: com.example.demo.DemoApplication\r\n"
         "Spring-Boot-Version: 3.2.1\r\n"
         "Spring-Boot-Classes: BOOT-INF/classes/\r\n"
         "Spring-Boot-Lib: BOOT-INF/lib/\r\n\r\n")
SB_LIB = ["spring-core-6.1.jar", "logback-classic-1.4.jar", "jackson-databind-2.16.jar"]
spring = jar(SB_MF, [("BOOT-INF/classes/com/example/demo/DemoApplication.class", b"\xca\xfe\xba\xbe")]
             + [("BOOT-INF/lib/" + j, b"PK\x05\x06" + bytes(18)) for j in SB_LIB])

PLAIN_MF = "Manifest-Version: 1.0\r\nMain-Class: com.acme.Tool\r\nImplementation-Version: 1.0.0\r\n\r\n"
plain = jar(PLAIN_MF, [("com/acme/Tool.class", b"\xca\xfe\xba\xbe")])

FAT_MF = "Manifest-Version: 1.0\r\nMain-Class: com.acme.Uber\r\n\r\n"
FAT_LIB = ["dep-a.jar", "dep-b.jar"]
fat = jar(FAT_MF, [("com/acme/Uber.class", b"\xca\xfe\xba\xbe")]
          + [(j, b"PK\x05\x06" + bytes(18)) for j in FAT_LIB])

not_a_jar = (b"%PDF-1.7\n" + bytes(40))


# --- Start-Class + Spring-Boot attrs: value read, answered UNSURE, raw value first, never plain ---
def test_start_class_spring_boot_attrs_value_read():
    a, p, opts = ask("jar.start_class", spring)
    check("start_class is UNSURE, never plain", is_unsure(a), f"{a!r}")
    check("start_class reads the real value first ('raw')", first_val(opts) == "com.example.demo.DemoApplication", f"{opts}")
    check("start_class key is the unjudged jar.start_class", p and p["k"] == "metadata.format/jar.start_class", f"{p}")

    a, p, opts = ask("jar.spring_boot_version", spring)
    check("spring_boot_version is UNSURE with the real value first", is_unsure(a) and first_val(opts) == "3.2.1", f"{a!r}")

    # the one judged jar key stays PLAIN (unchanged by this build)
    a, p, opts = ask("jar.main_class", spring)
    check("jar.main_class stays PLAIN (the judged key) = the launcher",
          a == "org.springframework.boot.loader.JarLauncher", f"{a!r}")

    # an absent-but-known attribute -> unsure 'none' (or None), NEVER a wrong plain value
    a, p, opts = ask("jar.start_class", plain)
    check("start_class ABSENT on a plain jar is unsure 'none' / None, never wrong-plain",
          a is None or (is_unsure(a) and first_val(opts) in ("none", None)), f"{a!r} opts={opts}")


# --- nested / embedded jar enumeration ---
def test_nested_and_embedded_jar_enumeration():
    a, p, opts = ask("jar.nested_jar_names", spring, kind="json")
    check("nested_jar_names is UNSURE under the +order key", is_unsure(a) and p["k"].endswith("+order"), f"{a!r}")
    vals = [v for _, v in opts]
    want_file = '["BOOT-INF/lib/spring-core-6.1.jar","BOOT-INF/lib/logback-classic-1.4.jar","BOOT-INF/lib/jackson-databind-2.16.jar"]'
    want_sorted = '["BOOT-INF/lib/jackson-databind-2.16.jar","BOOT-INF/lib/logback-classic-1.4.jar","BOOT-INF/lib/spring-core-6.1.jar"]'
    check("nested_jar_names offers BOTH file order and ascending-sorted (never one plain guess)",
          want_file in vals and want_sorted in vals, f"{vals}")

    a, p, opts = ask("jar.nested_jar_count", spring)
    check("nested_jar_count is UNSURE and counts the 3 BOOT-INF/lib jars", is_unsure(a) and first_val(opts) == "3", f"{a!r}")

    a, p, opts = ask("jar.embedded_jar_names", fat, kind="json")
    # the +order forms are JSON arrays named 'sorted' / 'file_order'; every offered form lists the same members
    _sets = [set(_json.loads(v)) for _, v in opts]
    check("fat jar: embedded_jar_names enumerates the root-level *.jar, unsure",
          is_unsure(a) and _sets and all(s == set(FAT_LIB) for s in _sets), f"{opts}")

    a, p, opts = ask("jar.is_spring_boot", spring)
    check("is_spring_boot is UNSURE true on a Spring Boot jar", is_unsure(a) and first_val(opts) in ("true", "True"), f"{a!r}")
    a, p, opts = ask("jar.is_fat_jar", plain)
    check("is_fat_jar is UNSURE false on a plain jar (no embedded jars)", is_unsure(a) and first_val(opts) in ("false", "False"), f"{a!r}")


# --- fail-closed on a non-jar ---
def test_fail_closed_on_a_non_jar():
    for prop in ("jar.start_class", "jar.nested_jar_names", "jar.nested_jar_count", "jar.is_spring_boot"):
        a, p, opts = ask(prop, not_a_jar, name="thing.pdf")
        check(f"{prop} on a non-jar is None / unsure 'none', never wrong-plain",
              a is None or is_unsure(a), f"{a!r}")


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
