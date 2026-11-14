#!/usr/bin/env python3
"""Metadata Forensics APK pack (the Day 21 build: Day 21's live fix folded in).

Day 21 asked `apk.package_name` of mobile-001.apk inside the evidence bundle and the judge took the
`package` attribute of the <manifest> element of the APK's compiled AndroidManifest.xml, verbatim,
under `metadata.format/apk.package_name` -> name 'raw' (challenges/_ledger/metadata.jsonl). No
metadata reader read a compiled Android manifest; the morning's day_patch.py answered it with a copy
of the Mobile lane's binary-XML parser. This pack folds that fix in and, rather than carrying a second
copy of the AXML format, REUSES the Mobile lane's parser: solvers/mobile-android/apk_resources.axml_tree
(the same function apk_facts.manifest_facts reads the package from).

  apk.package_name   the `package` attribute of the <manifest> element of the APK's compiled
                     AndroidManifest.xml, as the bytes store it. Plain (format class 'text', name
                     'raw') under the judged key. None -- no established fact, never a guess -- when
                     the delivery is not a zip, holds no single AndroidManifest.xml, the manifest is
                     not compiled binary XML, or the package attribute is absent. Unknown (-> None)
                     when two manifest entries or two different package values make the reading
                     ambiguous.

Every other spelling (apk.application_id, apk.manifest_package ...) shares the one extractor but keys
under its own name, so it is unsure until the judge accepts a name there. properties_strict.py loads
this file by name (MORE_FILES) and calls register(M).
"""
import io
import re
import sys
import zipfile
from pathlib import Path

M = None

# Reuse the Mobile lane's AXML parser instead of a second copy of the binary-XML format.
_MOBILE = Path(__file__).resolve().parent.parent / "mobile-android"
if str(_MOBILE) not in sys.path:
    sys.path.insert(0, str(_MOBILE))
try:
    import apk_resources as _R   # axml_tree / is_axml, plain stdlib, fails closed
except Exception:                # pragma: no cover - the pack is dropped, the lane goes on
    _R = None
try:
    import apk_facts as _F   # manifest_facts / _launcher (Mobile lane), which itself calls _R.axml_tree
except Exception:            # pragma: no cover - the extra facts are dropped, the lane goes on
    _F = None

PROPERTY = "apk.package_name"
KEY = "metadata.format/" + PROPERTY
ALIASES = ("apk.manifest_package_name", "apk.manifest_package", "apk.application_id",
           "apk.package", "android.package_name", "android.application_id")
MANIFEST = "AndroidManifest.xml"


def _package(n, d):
    """The compiled manifest's `package` attribute of an APK, or None/Unknown. `d` is the APK bytes."""
    if _R is None or not isinstance(d, (bytes, bytearray)):
        return None
    if d[:2] != b"PK":          # an APK is a zip; skip every non-zip file without opening it (cheap on the sweep)
        return None
    try:
        z = zipfile.ZipFile(io.BytesIO(d))
    except (zipfile.BadZipFile, OSError):
        return None
    entries = [i for i in z.infolist() if i.filename == MANIFEST]
    if not entries:
        return None                       # no compiled manifest: not an APK this reader speaks for
    if len(entries) > 1:
        raise M.Unknown("more than one AndroidManifest.xml")
    try:
        body = z.read(entries[0])
    except (RuntimeError, zipfile.BadZipFile, OSError, NotImplementedError):
        return None
    if not _R.is_axml(body):
        return None                       # a text or damaged manifest is not what the judge read
    els = _R.axml_tree(body) or []
    pkgs = [e["attrs"].get("package") for e in els
            if e.get("tag") == "manifest" and isinstance(e.get("attrs"), dict)]
    pkgs = [p for p in pkgs if isinstance(p, str) and p]
    if not pkgs:
        return None
    if len(set(pkgs)) != 1:
        raise M.Unknown("more than one manifest package attribute")
    return pkgs[0]


# ----------------------------------------------------------------------------------------------------
# Day 23 look-ahead build E (prediction #3): the OTHER compiled-manifest facts Day 21's fold left open --
# version name/code, min/target SDK, the application label and the launcher activity. Read with the Mobile
# lane's higher-level helper (apk_facts.manifest_facts, which itself calls apk_resources.axml_tree), so this
# pack still carries no second copy of the binary-XML format. EVERY answer is UNSURE under apk.* (never plain,
# never a guess): a value the judge has not named for a key is offered through labels.pick, and a resource
# reference or a value we cannot read is None. apk.package_name (above) is untouched and stays plain-after-judged.

def _facts(d):
    """apk_facts.manifest_facts of an APK's compiled AndroidManifest.xml, or None. Guards exactly as
    _package does: zip only, exactly one AndroidManifest.xml, compiled binary XML."""
    if _F is None or _R is None or not isinstance(d, (bytes, bytearray)) or d[:2] != b"PK":
        return None
    try:
        z = zipfile.ZipFile(io.BytesIO(d))
    except (zipfile.BadZipFile, OSError):
        return None
    entries = [i for i in z.infolist() if i.filename == MANIFEST]
    if not entries:
        return None
    if len(entries) > 1:
        raise M.Unknown("more than one AndroidManifest.xml")
    try:
        body = z.read(entries[0])
    except (RuntimeError, zipfile.BadZipFile, OSError, NotImplementedError):
        return None
    if not _R.is_axml(body):
        return None
    m = _F.manifest_facts(body)
    return m or None


def _is_plain_string(v):
    """A human string, not an unresolved resource reference (@0x.., ?0x.., #rrggbb, 0x..) or other typed ref."""
    return isinstance(v, str) and bool(v.strip()) and v[:1] not in "@?#" and not v.startswith("0x")


def _text_fact(field):
    """A string attribute of <manifest> (version_name), unsure 'raw'/'trimmed'. None for a ref or absence."""
    def fn(n, d):
        m = _facts(d)
        if not m:
            return None
        v = m.get(field)
        return v if _is_plain_string(v) else None
    return fn


def _int_fact(field):
    """An integer attribute (versionCode, min/target SDK): forms, the decimal first. int or a numeric string;
    anything else (a ref) is None."""
    def fn(n, d):
        m = _facts(d)
        if not m:
            return None
        v = m.get(field)
        if isinstance(v, bool) or v is None:
            return None
        if isinstance(v, int):
            return [("integer", str(v))]
        if isinstance(v, str) and re.fullmatch(r"\d+", v.strip()):
            return [("integer", v.strip())]
        if _is_plain_string(v):
            return [("raw", v)]
        return None
    return fn


def _label(n, d):
    """The <application android:label>, unsure, when it is a literal string (not a @string/ resource ref)."""
    m = _facts(d)
    if not m:
        return None
    v = (m.get("application") or {}).get("label")
    return v if _is_plain_string(v) else None


def _launcher(n, d):
    """The launcher activity (MAIN/LAUNCHER intent filter) in its spellings -- as written, package-prefixed,
    and bare -- offered as forms of the ONE fact (labels.pick, not candidates). None when there is no single
    launcher activity."""
    m = _facts(d)
    if not m:
        return None
    name = _F._launcher(m)
    if not isinstance(name, str) or not name:
        return None
    pkg = m.get("package")
    if name.startswith("."):
        full = (pkg + name) if pkg else name
    elif "." in name:
        full = name
    else:
        full = (pkg + "." + name) if pkg else name
    simple = name.rsplit(".", 1)[-1]
    out, seen = [], set()
    for nm, val in (("raw", name), ("prefixed", full), ("bare", simple)):
        if val and val not in seen:
            out.append((nm, val))
            seen.add(val)
    return out or None


# (names...), format class, extractor. All unsure (unconfirmed). Aliases avoid the `apk.manifest_*` family
# (readers_more) so there is no ambiguity with a JAR-style META-INF/MANIFEST.MF reading.
E_FIELDS = (
    (("apk.version_name", "apk.app_version_name", "android.version_name"), "text", _text_fact("version_name")),
    (("apk.version_code", "apk.app_version_code", "android.version_code"), "forms", _int_fact("version_code")),
    (("apk.min_sdk_version", "apk.min_sdk", "apk.minimum_sdk_version", "android.min_sdk_version"), "forms",
     _int_fact("min_sdk")),
    (("apk.target_sdk_version", "apk.target_sdk", "android.target_sdk_version"), "forms", _int_fact("target_sdk")),
    (("apk.application_label", "apk.app_label", "apk.label", "apk.application_name"), "text", _label),
    (("apk.launcher_activity", "apk.main_activity", "apk.launcher", "apk.entry_activity"), "forms", _launcher),
)


def register(module):
    """properties_strict calls this with its own module object. Returns (names, families) added."""
    global M
    M = module
    before, families = len(M.REG), len(M.FAMILIES)
    for name in (PROPERTY,) + ALIASES:
        if M.canon(name) in M.REG:
            M.MORE_CLASHES.append(name)
            continue
        M.prop(name, fmt="text")(_package)
    for names, fmt, fn in E_FIELDS:
        for name in names:
            if M.canon(name) in M.REG:
                M.MORE_CLASHES.append(name)
                continue
            M.prop(name, fmt=fmt)(fn)
    return len(M.REG) - before, len(M.FAMILIES) - families


if __name__ == "__main__":
    import glob
    for path in sys.argv[1:] or glob.glob("challenges/day-*/metadata-forensics-*/members/*.apk"):
        try:
            print(path, "->", _package(path, Path(path).read_bytes()))
        except Exception as e:  # noqa: BLE001 - CLI convenience only
            print(path, "->", type(e).__name__, e)
