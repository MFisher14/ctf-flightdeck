#!/usr/bin/env python3
"""Real artifacts for the toolkits of group c (web_evidence, web, malconfig, modern_crypto, carve_stego, rf).

  .venv/bin/python tests/real/fetch_c.py                 fetch what is missing, check every sha256, write SOURCES.md
  .venv/bin/python tests/real/fetch_c.py --check         no network: say what is there, what is missing, what differs
  .venv/bin/python tests/real/fetch_c.py --toolkit rf    one toolkit only
  .venv/bin/python tests/real/fetch_c.py --pin           (maintainer) write the sha256 of a new manifest row

The cache is `<main checkout>/challenges/_realdata/<toolkit>/` (untracked, never committed), or
$CTF_REALDATA. The list is tests/real/manifest_c.json: every file is pinned to a commit of a public
repository (or a fixed URL) and to its sha256; a file whose bytes differ is removed and reported, never used.
The two Huntress write-up repositories are copied from `_realdata/repos/<name>` when a clone is there (the
clone is checked against the same sha256), else fetched file by file.

Everything fetched is untrusted data: challenge files of the 2024 and 2025 Huntress CTFs (some are malware
analysis exercises), test files of parsing libraries and tools. Nothing here runs or imports a fetched file,
and nothing talks to the Game Master. Exit 0 when every wanted file is present and correct, 1 otherwise.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
MANIFEST = HERE / "manifest_c.json"
RAW = "https://raw.githubusercontent.com/"


def cache_root() -> Path:
    """The corpus root: ctf.paths.realdata_root() ($CTF_REALDATA)."""
    sys.path.insert(0, str(HERE))
    import _corpus
    return _corpus.root()


def manifest() -> dict:
    return json.loads(MANIFEST.read_text())


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _split(src: str):
    """(source key, path inside the repo, zip member or None). A src `key:path!member` names a file
    inside a zip at `path`; that zip is fetched (or copied from a clone) and the member extracted."""
    key, _, rest = src.partition(":")
    path, sep, member = rest.partition("!")
    return key, path, (member if sep else None)


def source_url(m: dict, src: str) -> str:
    """`<source key>:<path>` of the manifest as a URL; a source is `owner/repo@commit` or a URL prefix."""
    key, path, _ = _split(src)
    base = m["sources"][key]
    if base.startswith("http"):
        return base + urllib.parse.quote(path)
    repo, _, commit = base.partition("@")
    return RAW + repo + "/" + commit + "/" + urllib.parse.quote(path)


def local_clone(m: dict, src: str, root: Path):
    """The file inside a clone under _realdata/repos, when that repository is one the manifest names as cloned."""
    key, path, _ = _split(src)
    name = m.get("clones", {}).get(key)
    p = root / "repos" / name / path if name else None
    return p if p and p.is_file() else None


def _get(url: str, limit: int = 128 << 20) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "huntress-realdata-fetch/1"})
    with urllib.request.urlopen(req, timeout=300) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise ValueError("larger than the limit")
    return data


def fetch(url: str, dest: Path, limit: int = 64 << 20) -> None:
    data = _get(url, limit)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    tmp.write_bytes(data)
    tmp.replace(dest)


def write_sources(m: dict, root: Path, toolkit: str) -> None:
    rows = [f for f in m["files"] if f["toolkit"] == toolkit]
    lines = [f"# Real artifacts for the `{toolkit}` toolkit", "",
             "Written by `tests/real/fetch_c.py` from `tests/real/manifest_c.json`. Untracked, never committed. Every",
             "file is untrusted data: nothing here is ever run. `what` is the independent truth the test asserts.", "",
             "| file | source | sha256 | what |", "| --- | --- | --- | --- |"]
    for f in rows:
        lines.append(f"| `{f['dest']}` | {source_url(m, f['src'])} | `{f.get('sha256', '')}` | {f.get('what', '')} |")
    (root / toolkit).mkdir(parents=True, exist_ok=True)
    (root / toolkit / "SOURCES.md").write_text("\n".join(lines) + "\n")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--pin", action="store_true")
    ap.add_argument("--toolkit")
    a = ap.parse_args(argv)
    m, root = manifest(), cache_root()
    bad = got = have = 0
    for f in m["files"]:
        if a.toolkit and f["toolkit"] != a.toolkit:
            continue
        dest = root / f["toolkit"] / f["dest"]
        want = f.get("sha256")
        if dest.is_file() and want and sha256(dest) == want:
            have += 1
            continue
        if a.check:
            print(f"{'DIFFERS' if dest.is_file() else 'MISSING'} {f['toolkit']}/{f['dest']}")
            bad += 1
            continue
        try:
            member = _split(f["src"])[2]
            clone = local_clone(m, f["src"], root)
            dest.parent.mkdir(parents=True, exist_ok=True)
            if member:
                import io
                import zipfile
                blob = clone.read_bytes() if clone else _get(source_url(m, f["src"]))
                with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                    body = zf.read(member)
                if len(body) > (64 << 20):
                    raise ValueError("member larger than the limit")
                dest.write_bytes(body)
            elif clone:
                shutil.copyfile(clone, dest)
            else:
                fetch(source_url(m, f["src"]), dest)
        except Exception as e:                      # one missing file must not stop the rest
            print(f"FAILED  {f['toolkit']}/{f['dest']}: {type(e).__name__}: {e}")
            bad += 1
            continue
        digest = sha256(dest)
        if a.pin and not want:
            f["sha256"] = digest
            print(f"PINNED  {f['toolkit']}/{f['dest']} {digest}")
        elif digest != want:
            dest.unlink()
            print(f"SHA256  {f['toolkit']}/{f['dest']}: got {digest}, the manifest says {want}; removed")
            bad += 1
            continue
        got += 1
    if a.pin:
        MANIFEST.write_text(json.dumps(m, indent=1) + "\n")
    if not a.check:
        for toolkit in sorted({f["toolkit"] for f in m["files"]} if not a.toolkit else {a.toolkit}):
            write_sources(m, root, toolkit)
    print(f"REALDATA c: {have} present, {got} fetched, {bad} missing or wrong, cache {root}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
