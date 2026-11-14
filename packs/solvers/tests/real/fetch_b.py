#!/usr/bin/env python3
"""Fill the real-artifact cache of group b (cloudlogs, cloud_container, edr_persistence, nix_host,
sqlite_artifacts) from tests/real/manifest_b.json, checking every file's SHA-256.

  .venv/bin/python tests/real/fetch_b.py                 download what is missing, verify everything
  .venv/bin/python tests/real/fetch_b.py --check         no network: verify what is in the cache
  .venv/bin/python tests/real/fetch_b.py --record        maintainer: write the sizes and hashes of new entries
  .venv/bin/python tests/real/fetch_b.py --only nix_host

The cache is challenges/_realdata/<toolkit>/ (untracked, never committed; $CTF_REALDATA names
another folder). Each toolkit folder gets a SOURCES.md: file, size, SHA-256, where it came from.

Sources are public test corpora (the sample files of plaso, Elastic beats, go-containerregistry,
Terraform, dfindexeddb, OTRF Security-Datasets, Invictus IR's CloudTrail and Unified Audit Log data
sets, loghub) and the challenge files of two public Huntress CTF write-up repositories, which must
already be under challenges/_realdata/repos/ (entries with "repo"). No live malware. This never
talks to the Game Master and reads no token. Nothing downloaded is run: zip and tar members are
written as data, 7z goes through tools/sandbox.py, and an .evtx is exported to XML text with
python-evtx (a pure-Python reader).

Manifest entry: {"to": "<toolkit>/<path>", "url": ... | "repo": "<path under repos/>", "sha256", "size",
"note", and optionally "unpack": "zip" | "zip_evtx" | "tgz" | "7z" | "evtx_xml" | "gunzip"} - the unpacked form
lands beside the file as "<to>.d/" (or "<to>.xml") and is listed in SOURCES.md as derived.
"""
import gzip
import hashlib
import json
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import realdata_b as rd      # noqa: E402

MANIFEST = HERE / "manifest_b.json"
MAX_MEMBER = 64 << 20


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def get(url: str) -> bytes:
    req = urllib.request.Request(url.replace(" ", "%20"), headers={"User-Agent": "huntress-realdata/1"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def safe_name(name: str) -> bool:
    p = Path(name)
    return not (p.is_absolute() or ".." in p.parts or name.startswith("__MACOSX/") or "/__MACOSX/" in name)


def unpack(kind: str, src: Path) -> list:
    """Write the unpacked form beside `src`; the paths written."""
    out = []
    if kind == "zip_evtx":                 # the members, then every .evtx among them as XML text
        got = unpack("zip", src)
        return got + [x for p in got if p.suffix == ".evtx" for x in unpack("evtx_xml", p)]
    if kind == "evtx_xml":
        dst = src.with_name(src.name + ".xml")
        if not dst.exists():
            import Evtx.Evtx as evtx       # python-evtx, pure Python
            parts = ['<?xml version="1.0" encoding="utf-8" standalone="yes"?>\n<Events>\n']
            with evtx.Evtx(str(src)) as log:
                # every chunk with the magic, not the header's count: a log copied from a live system
                # has a stale header (Nightmare on Hunt Street: the header says 1 chunk, the file has 16)
                buf, ofs = log._buf, 0x1000
                while ofs + 0x10000 <= len(buf):
                    if bytes(buf[ofs:ofs + 8]) == b"ElfChnk\x00":
                        try:
                            for rec in evtx.ChunkHeader(buf, ofs).records():
                                try:
                                    parts.append(rec.xml() + "\n")
                                except Exception:      # noqa: BLE001 - one unreadable record is left out and marked
                                    parts.append("<!-- record not rendered -->\n")
                        except Exception:              # noqa: BLE001 - a chunk that ends early
                            parts.append("<!-- chunk not read to its end -->\n")
                    ofs += 0x10000
            parts.append("</Events>\n")
            dst.write_text("".join(parts), encoding="utf-8")
        return [dst]
    if kind == "gunzip":
        dst = src.with_name(src.name[:-3] if src.name.endswith(".gz") else src.name + ".out")
        if not dst.exists():
            dst.write_bytes(gzip.decompress(src.read_bytes()))
        return [dst]
    folder = src.with_name(src.name + ".d")
    if folder.is_dir() and any(folder.rglob("*")):
        return sorted(p for p in folder.rglob("*") if p.is_file() and not p.name.endswith(".evtx.xml"))
    folder.mkdir(parents=True, exist_ok=True)
    if kind == "zip":
        with zipfile.ZipFile(src) as z:
            for info in z.infolist():
                if info.is_dir() or not safe_name(info.filename) or info.file_size > MAX_MEMBER:
                    continue
                dst = folder / info.filename
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(z.read(info))
                out.append(dst)
    elif kind == "tgz":
        with tarfile.open(src) as t:
            for m in t:
                if not m.isfile() or not safe_name(m.name) or m.size > MAX_MEMBER:
                    continue
                dst = folder / m.name
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(t.extractfile(m).read())
                out.append(dst)
    elif kind == "7z":
        # the sandbox writes into its own out folder; the members are copied from there as data
        cmd = [sys.executable, str(rd.REPO / "tools" / "sandbox.py"), "run", "--timeout", "60", "--keep",
               "--in", str(src), "7z", "x", "-y", "-o{out}", "{in}"]
        got = subprocess.run(cmd, capture_output=True, text=True)
        kept = [ln.split()[-1] for ln in got.stderr.splitlines() if "/out/" in ln]
        if got.returncode != 0 or not kept:
            raise RuntimeError(f"sandbox 7z failed for {src.name}: {got.stderr.strip()[-300:]}")
        base = Path(kept[-1])
        for p in sorted(x for x in base.rglob("*") if x.is_file()):
            dst = folder / p.relative_to(base)
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(p.read_bytes())
            out.append(dst)
        subprocess.run(["rm", "-rf", str(base)], check=False)
    else:
        raise ValueError(kind)
    return out


def main(argv) -> int:
    record, check_only = "--record" in argv, "--check" in argv
    only = argv[argv.index("--only") + 1] if "--only" in argv else None
    entries = json.loads(MANIFEST.read_text())
    cache = rd.CACHE
    bad, fetched, derived = [], 0, {}
    for e in entries:
        tk = e["to"].split("/", 1)[0]
        if only and tk != only:
            continue
        dst = cache / e["to"]
        if not dst.exists():
            if check_only:
                bad.append(f"missing {e['to']}")
                continue
            try:
                if "repo" in e:
                    blob = (cache / "repos" / e["repo"]).read_bytes()
                else:
                    blob = get(e["url"])
            except Exception as exc:       # noqa: BLE001
                bad.append(f"not fetched {e['to']}: {exc}")
                continue
            if e.get("sha256") and sha(blob) != e["sha256"]:
                bad.append(f"sha256 differs for {e['to']} (the source changed): got {sha(blob)}")
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(blob)
            fetched += 1
        blob = dst.read_bytes()
        if record and not e.get("sha256"):
            e["sha256"], e["size"] = sha(blob), len(blob)
        elif sha(blob) != e.get("sha256"):
            bad.append(f"sha256 differs for {e['to']}: {sha(blob)}")
            continue
        if e.get("unpack"):
            try:
                derived[e["to"]] = unpack(e["unpack"], dst)
            except Exception as exc:       # noqa: BLE001
                bad.append(f"not unpacked {e['to']}: {exc}")
    if record:
        MANIFEST.write_text(json.dumps(entries, indent=1) + "\n")
    by_tk = {}
    for e in entries:
        by_tk.setdefault(e["to"].split("/", 1)[0], []).append(e)
    for tk, rows in by_tk.items():
        if (only and tk != only) or not (cache / tk).is_dir():
            continue
        lines = [f"# Real artifacts cached for `{tk}`", "",
                 "Written by `tests/real/fetch_b.py` from `tests/real/manifest_b.json`. Untracked; never committed.",
                 "Every file is data: nothing here is run.", "",
                 "| file | bytes | sha256 | source | note |", "| --- | --- | --- | --- | --- |"]
        for e in rows:
            src = e.get("url") or ("challenges/_realdata/repos/" + e["repo"])
            lines.append(f"| `{e['to'].split('/', 1)[1]}` | {e.get('size', '')} | `{e.get('sha256', '')}` | {src} | {e.get('note', '')} |")
            for p in derived.get(e["to"], []):
                lines.append(f"| `{p.relative_to(cache / tk)}` | {p.stat().st_size} | `{sha(p.read_bytes())}` | derived: {e['unpack']} of `{Path(e['to']).name}` | |")
        (cache / tk / "SOURCES.md").write_text("\n".join(lines) + "\n")
    for b in bad:
        print("BAD  " + b)
    n = sum(1 for e in entries if (cache / e["to"]).exists() and (not only or e["to"].startswith(only + "/")))
    print(f"FETCH entries={len(entries)} present={n} fetched={fetched} bad={len(bad)} cache={cache}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
