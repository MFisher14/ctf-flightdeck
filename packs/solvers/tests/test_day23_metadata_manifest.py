#!/usr/bin/env python3
"""Day 23 look-ahead, Metadata: the JAR manifest short-forms (builds A+B), Class-Path as raw-vs-split
candidates (build C) and the APK compiled-manifest facts (build E). Every one is UNSURE / fail-closed --
NEVER a plain answer before the judge names it (a wrong plain sinks a batch) -- and no existing judged
answer is moved (jar.main_class and apk.package_name stay PLAIN under their accepted name).

  .venv/bin/python tests/test_day23_metadata_manifest.py

Offline; no Game Master request, no token. The real challenges/ dir is used for the runtime ledger (so the
judged names jar.main_class=raw and apk.package_name=raw are in force for the PLAIN checks and the real
Day-21 APK is read for build E); the UNSURE checks hold in any labels state. Both PLAIN checks SKIP if the
runtime ledger / APK is not in this checkout.
"""
import io
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import paths
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[1]))
    from ctf import paths

REPO = Path(__file__).resolve().parent.parent
LANE = REPO / "solvers" / "metadata-forensics"
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.path.insert(0, str(LANE))
import labels  # noqa: E402

try:
    REAL = paths.workdir()                     # the event workdir (ctf.paths), when one resolves
except Exception:                              # no $CTF_WORKDIR and no event: an empty temp ledger below
    REAL = None
if REAL is not None and REAL.is_dir():
    os.environ["CTF_WORKDIR"] = str(REAL)
else:
    REAL = None
    _TMP = Path(tempfile.mkdtemp(prefix="test_day23_meta_"))
    (_TMP / "_ledger").mkdir(parents=True)
    os.environ["CTF_WORKDIR"] = str(_TMP)
labels._default_root = None
import properties_strict as M  # noqa: E402

FAILED, PASSED = [], [0]
TEXT = {"kind": "exact_text", "syntax": "exact artifact-derived value only; use the literal none when absent"}
JSONF = {"kind": "json", "syntax": "compact valid JSON array"}
MEMBER = "application-001.jar"
APK = "mobile-001.apk"


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if ok:
        PASSED[0] += 1
    else:
        FAILED.append(label)


def quiet(fn, *a, **k):
    old, sys.stderr = sys.stderr, io.StringIO()
    try:
        return fn(*a, **k)
    finally:
        sys.stderr = old


def make_jar(pairs, classes=("arena/evidence/ArtifactMain.class",)):
    body = ("".join(f"{k}: {v}\r\n" for k, v in pairs) + "\r\n").encode("utf-8")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("META-INF/MANIFEST.MF", body)
        for c in classes:
            z.writestr(c, b"\xca\xfe\xba\xbe\x00\x00\x00\x34")
    return buf.getvalue()


def delivery(member, data):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(member, data)
    return buf.getvalue()


def ask(name, member, data, fmt=TEXT):
    aid = "d23-" + name.replace(".", "-").replace("_", "-")
    blob = delivery(member, data)
    q = {"qid": aid, "answer_id": aid, "question": f"Determine {name} for {member}.",
         "artifact": f"e.zip -> {member}", "answer_format": fmt}
    files = {f"e.zip -> {member}": data, member: data, "e.zip": blob}
    ctx = {"set": 1, "delivery_name": "e.zip", "delivery": blob, "attempt": {}, "partial": {}}
    return quiet(M.solve_set, [q], files, ctx)[aid]


def unsure(v):
    return isinstance(v, str) and labels.is_unsure(v)


def options_of(v):
    u = labels.parse(v) if unsure(v) else None
    return (u, [n for n, _ in u.options] if u else [])


JAR = make_jar([
    ("Manifest-Version", "1.0"),
    ("Main-Class", "arena.evidence.ArtifactMain"),
    ("Class-Path", "lib/a.jar lib/b.jar"),
    ("Sealed", "true"),
    ("Multi-Release", "true"),
    ("Specification-Title", "Arena Evidence"),
    ("Export-Package", "arena.api;version=1"),
])


def test_row477_shorts_unsure():
    for name in ("jar.class_path", "jar.sealed", "jar.multi_release"):
        v = ask(name, MEMBER, JAR)
        check(f"[A/row477] {name} is UNSURE (not None, not plain)", unsure(v), repr(v))


def test_build_b_shorts_unsure():
    # two further MANIFEST_KNOWN shorts the hand-picked family did not list: None/STOP before, unsure now.
    for name in ("jar.specification_title", "jar.export_package"):
        v = ask(name, MEMBER, JAR)
        check(f"[B] {name} is UNSURE (was None/STOP)", unsure(v), repr(v))
    # a MANIFEST_KNOWN attribute that is ABSENT is still routed: the unsure `none`, never None/STOP
    v = ask("jar.premain_class", MEMBER, JAR)
    u, names = options_of(v)
    check("[B] an absent MANIFEST_KNOWN short is unsure 'none' (routed, fail-closed)",
          unsure(v) and dict(u.options).get("absent") == "none", (names, dict(u.options) if u else None))


def test_build_c_class_path_candidates():
    v = ask("jar.class_path", MEMBER, JAR)
    u, names = options_of(v)
    check("[C] jar.class_path is a candidate key (#candidates)", unsure(v) and labels.is_candidate(v),
          u.key if u else repr(v))
    check("[C] jar.class_path offers BOTH raw and split", "raw" in names and "split" in names, names)
    vals = dict(u.options) if u else {}
    check("[C] raw = the whole Class-Path string", vals.get("raw") == "lib/a.jar lib/b.jar", vals.get("raw"))
    check("[C] split = the JSON array of the space-separated entries",
          vals.get("split") == '["lib/a.jar","lib/b.jar"]', vals.get("split"))
    # the row-477 residual: asked as a JSON array, still UNSURE (the split array offered), not None
    vj = ask("jar.class_path", MEMBER, JAR, fmt=JSONF)
    check("[C] jar.class_path (json kind) is UNSURE, not None (residual closed)", unsure(vj), repr(vj))
    # jar.manifest_class_path shares the same raw+split candidates
    v2 = ask("jar.manifest_class_path", MEMBER, JAR)
    u2, names2 = options_of(v2)
    check("[C] jar.manifest_class_path is also raw+split candidates",
          unsure(v2) and labels.is_candidate(v2) and {"raw", "split"} <= set(names2), names2)


def test_main_class_stays_plain():
    v = ask("jar.main_class", MEMBER, JAR)
    if not labels.state("metadata.format/jar.main_class")["accepted_names"]:
        check("[plain] jar.main_class stays PLAIN and correct", True,
              "SKIP: runtime ledger (jar.main_class=raw) not in this checkout")
        return
    check("[plain] jar.main_class stays PLAIN and correct (judged key untouched)",
          (not unsure(v)) and v == "arena.evidence.ArtifactMain", repr(v))


def _apk_bytes():
    if REAL is None:
        return None
    p = REAL / "day-21" / "metadata-forensics-day-21-package-deal" / "members" / APK
    return p.read_bytes() if p.is_file() else None


def test_build_e_apk_facts():
    apk = _apk_bytes()
    if apk is None:
        check("[E] APK compiled-manifest facts unsure", True, "SKIP: real Day-21 APK not in this checkout")
        return
    for name in ("apk.version_name", "apk.version_code", "apk.min_sdk_version",
                 "apk.target_sdk_version", "apk.application_label", "apk.launcher_activity"):
        v = ask(name, APK, apk)
        check(f"[E] {name} is UNSURE (was None)", unsure(v), repr(v))
    # the judged key must stay plain
    pkg = ask("apk.package_name", APK, apk)
    if not labels.state("metadata.format/apk.package_name")["accepted_names"]:
        check("[E] apk.package_name stays PLAIN", True, "SKIP: ledger lacks apk.package_name=raw")
    else:
        check("[E] apk.package_name stays PLAIN (judged key untouched)",
              (not unsure(pkg)) and pkg == "com.huntress.arena.p08281778", repr(pkg))


def main():
    for fn in (test_row477_shorts_unsure, test_build_b_shorts_unsure, test_build_c_class_path_candidates,
               test_main_class_stays_plain, test_build_e_apk_facts):
        try:
            fn()
        except Exception as e:
            import traceback
            traceback.print_exc()
            check(f"{fn.__name__} raised {type(e).__name__}: {e}", False)
    print(f"{PASSED[0]} passed, {len(FAILED)} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
