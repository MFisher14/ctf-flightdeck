#!/usr/bin/env python3
"""Real-artifact cache, group a: toolkits network, email, maldoc, windows, memory.

  .venv/bin/python tests/real/fetch_a.py              fetch what is missing, check every sha256, write SOURCES.md
  .venv/bin/python tests/real/fetch_a.py --check      no network: say what is present and whether it matches
  .venv/bin/python tests/real/fetch_a.py --pin        fetch, and write the sha256 of every entry that has none
  .venv/bin/python tests/real/fetch_a.py --kit email  one toolkit only
  .venv/bin/python tests/real/fetch_a.py --big        also the entries marked big (a 180 MB memory image)

The cache is `<main checkout>/challenges/_realdata/` ($CTF_REALDATA overrides it): untracked, never
committed. Per toolkit one folder `<kit>/` and a `SOURCES.md` in it (name, sha256, size, where from). The two
write-up repositories are cloned shallow under `repos/` (to a temporary name, then renamed; an existing clone
is reused). Everything else is a pinned raw file of a public test corpus: the sample files of the parsing
libraries and tools (python-evtx, regipy, oletools, mail-parser, extract-msg, LnkParse3, dpkt, scapy,
pyelftools, rust-minidump), Wireshark's sample captures and Eric Zimmerman's prefetch test files.

No file here is run, by this script or by a test. A fetched file whose sha256 differs from the manifest
(`tests/real/manifest_a.json`) is not kept. No Game Master request and no token.
"""
import gzip
import hashlib
import io
import json
import lzma
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
MANIFEST = HERE / "manifest_a.json"
KITS = ("network", "email", "maldoc", "windows", "memory")
REPOS = {
    "ctf2024": ("Huntress-CTF-2024", "https://github.com/ThisGuyNeedsABeer/Huntress-CTF-2024"),
    "ctf2025": ("CTF-Huntress_2025", "https://github.com/TheGroundZero/CTF-Huntress_2025"),
}
RAW = "https://raw.githubusercontent.com/%s/%s/%s"
MAX_FETCH = 400 << 20


def cache_root() -> Path:
    """The corpus root: ctf.paths.realdata_root() ($CTF_REALDATA)."""
    sys.path.insert(0, str(HERE))
    import _corpus
    return _corpus.root()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def http_get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "huntress-realdata-fetch"})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read(MAX_FETCH + 1)
    if len(data) > MAX_FETCH:
        raise ValueError("larger than %d bytes" % MAX_FETCH)
    return data


def clone(root: Path, key: str) -> Path:
    name, url = REPOS[key]
    dest = root / "repos" / name
    if dest.is_dir():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.parent / (".tmp-a-%s-%d" % (key, os.getpid()))
    subprocess.run(["git", "clone", "--depth", "1", "-q", url, str(tmp)], check=True, timeout=600)
    if dest.is_dir():                    # another agent finished first
        shutil.rmtree(tmp, ignore_errors=True)
    else:
        tmp.rename(dest)
    return dest


def unwrap(data: bytes, entry: dict) -> bytes:
    """The entry's own wrapper: `member` of a zip (password optional), `xz`, `gz`."""
    if entry.get("member"):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            data = z.read(entry["member"], pwd=(entry.get("password") or "").encode() or None)
    if entry.get("unpack") == "xz":
        data = lzma.decompress(data)
    elif entry.get("unpack") == "gz":
        data = gzip.decompress(data)
    elif entry.get("unpack") == "b64":          # LnkParse3 keeps its sample shortcuts base64-encoded
        import base64
        data = base64.b64decode(data)
    return data


def source_of(entry: dict) -> str:
    if entry.get("repo"):
        s = "%s/%s" % (REPOS[entry["repo"]][1], entry["path"])
    elif entry.get("github"):
        s = RAW % (entry["github"], entry["rev"], entry["path"])
    else:
        s = entry["url"]
    if entry.get("member"):
        s += " -> " + entry["member"]
    if entry.get("unpack"):
        s += " (" + entry["unpack"] + " removed)"
    return s


def fetch(entry: dict, root: Path) -> bytes:
    if entry.get("repo"):
        data = (clone(root, entry["repo"]) / entry["path"]).read_bytes()
    elif entry.get("github"):
        data = http_get(RAW % (entry["github"], entry["rev"], urllib.request.quote(entry["path"])))
    else:
        data = http_get(entry["url"])
    return unwrap(data, entry)


def load() -> list:
    return json.loads(MANIFEST.read_text())["files"]


def path_of(entry: dict, root: Path) -> Path:
    return root / entry["kit"] / entry["name"]


def write_sources(root: Path, entries: list) -> None:
    for kit in KITS:
        rows = [e for e in entries if e["kit"] == kit and path_of(e, root).is_file()]
        if not rows:
            continue
        out = ["# Real files for the `%s` toolkit" % kit, "",
               "Written by `tests/real/fetch_a.py` from `tests/real/manifest_a.json`. Untracked; nothing here is run.",
               "", "| file | bytes | sha256 | from | what |", "| --- | --- | --- | --- | --- |"]
        for e in rows:
            p = path_of(e, root)
            out.append("| `%s` | %d | `%s` | %s | %s |" % (e["name"], p.stat().st_size, e.get("sha256", "?"),
                                                           source_of(e), e.get("note", "")))
        (root / kit / "SOURCES.md").write_text("\n".join(out) + "\n")


def main(argv) -> int:
    check_only, pin, big = "--check" in argv, "--pin" in argv, "--big" in argv
    kit = argv[argv.index("--kit") + 1] if "--kit" in argv else None
    root = cache_root()
    doc = json.loads(MANIFEST.read_text())
    entries = doc["files"]
    bad = missing = ok = 0
    for e in entries:
        if kit and e["kit"] != kit:
            continue
        p = path_of(e, root)
        if p.is_file():
            got = sha256(p.read_bytes())
            if e.get("sha256") and got != e["sha256"]:
                print("MISMATCH %s/%s: have %s" % (e["kit"], e["name"], got))
                bad += 1
            else:
                if pin and not e.get("sha256"):
                    e["sha256"] = got
                ok += 1
            continue
        if check_only or (e.get("big") and not big):
            print("absent   %s/%s%s" % (e["kit"], e["name"], " (big: --big)" if e.get("big") else ""))
            missing += 1
            continue
        try:
            data = fetch(e, root)
        except Exception as exc:                                    # one bad source never stops the rest
            print("FAILED   %s/%s: %s: %s" % (e["kit"], e["name"], type(exc).__name__, exc))
            bad += 1
            continue
        got = sha256(data)
        if e.get("sha256") and got != e["sha256"]:
            print("MISMATCH %s/%s: fetched %s, not kept" % (e["kit"], e["name"], got))
            bad += 1
            continue
        if not e.get("sha256"):
            if not pin:
                print("UNPINNED %s/%s: %s (run --pin), not kept" % (e["kit"], e["name"], got))
                bad += 1
                continue
            e["sha256"] = got
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".part%d" % os.getpid())
        tmp.write_bytes(data)
        tmp.replace(p)
        print("fetched  %s/%s %d bytes" % (e["kit"], e["name"], len(data)))
        ok += 1
    if pin:
        MANIFEST.write_text(json.dumps(doc, indent=1) + "\n")
    if not check_only:
        write_sources(root, entries)
    print("FETCH_A root=%s ok=%d absent=%d bad=%d" % (root, ok, missing, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
