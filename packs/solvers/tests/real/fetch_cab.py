#!/usr/bin/env python3
"""The real-cabinet cache (backlog row 283, round 4): where it is, what is in it, how to refill it.

  .venv/bin/python tests/real/fetch_cab.py            download what is missing, check every SHA-256
  .venv/bin/python tests/real/fetch_cab.py --check    check only (no network); exit 1 on a miss
  .venv/bin/python tests/real/fetch_cab.py --record   after a first fetch: write manifest_cab.json

The cache is <main checkout>/challenges/_realdata/cab/ (untracked, never committed), or
$CTF_REALDATA/cab. Nothing here talks to the Game Master or reads a token. Every file is a
public test vector of a cabinet reader, taken from a pinned commit so that its bytes cannot move:

  libmspack   github.com/kyz/libmspack: libmspack/test/test_files/cabd (57), cabextract/test/cabs
              (17) and cabextract/test/bugs (13). MSZIP, LZX and Quantum folders (mszip_lzx_qtm.cab
              holds one of each), five-part sets, reserve fields, and many deliberately damaged
              cabinets (the cve-*, bad_*, partial_* and *-violation-* files).
  libarchive  github.com/libarchive/libarchive: libarchive/test/test_read_format_cab_*.cab.uu and
              test_fuzz.cab.uu (12), uuencoded there and decoded here. Stored, MSZIP and LZX
              cabinets of several members (one of 33,000 bytes), LZX with E8 translation and a
              16-bit window, a two-part set, damaged LZX streams.

Every file is untrusted data: several were written to crash a decoder. Nothing in the cache is
ever run, and nothing is unpacked into it; the readers and the tests read bytes.

manifest_cab.json beside this file holds each file's URL, size and SHA-256 (of the cabinet as it
is cached; for a libarchive file also of the .uu text that was downloaded). A file whose bytes do
not match is reported and not kept.

For the tests of this folder:

  import fetch_cab
  folder = fetch_cab.have()            # the cache folder, or None when it is not there
  rows = fetch_cab.manifest()          # [{"name", "url", "sha256", "bytes", "source"}]
"""
import binascii
import hashlib
import json
import os
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
MANIFEST = HERE / "manifest_cab.json"
MSPACK = "https://raw.githubusercontent.com/kyz/libmspack/55d501976171397ccd5d5a7a1ca7da065b1d9a06/"
LIBARCHIVE = "https://raw.githubusercontent.com/libarchive/libarchive/b8189c9b34cd7a88eb09989c349b368f99d0787a/libarchive/test/"

CABD = ("bad_folderindex bad_nofiles bad_nofolders bad_signature cve-2010-2800-mszip-infinite-loop cve-2014-9556-qtm-infinite-loop "
        "cve-2014-9732-folders-segfault cve-2015-4470-mszip-over-read cve-2015-4471-lzx-under-read cve-2017-11423-fname-overread "
        "cve-2018-18584-qtm-max-size-block filename-read-violation-1 filename-read-violation-2 filename-read-violation-3 "
        "filename-read-violation-4 hidden-file-bad-folderid hidden-file-beyond-eof hidden-files lzx-main-tree-no-lengths "
        "lzx-premature-matches mszip_lzx_qtm multi_basic_pt1 multi_basic_pt2 multi_basic_pt3 multi_basic_pt4 multi_basic_pt5 "
        "normal_255c_filename normal_2files_1folder normal_2files_2folders partial_nodata partial_nofiles partial_nofolder "
        "partial_shortextheader partial_shortfile1 partial_shortfile2 partial_shortfolder partial_shortheader partial_str_nofname "
        "partial_str_noninfo partial_str_nonname partial_str_nopinfo partial_str_nopname partial_str_shortfname "
        "partial_str_shortninfo partial_str_shortnname partial_str_shortpinfo partial_str_shortpname reserve_--- reserve_--D "
        "reserve_-F- reserve_-FD reserve_H-- reserve_H-D reserve_HF- reserve_HFD search_basic search_tricky1").split()
CABS = ("case-ascii case-utf8 dir dirwalk-vulns encoding-koi8 encoding-latin1 encoding-sjis large-files-cab mixed search simple "
        "split-1 split-2 split-3 split-4 split-5 utf8-stresstest").split()
BUGS = ("cve-2010-2800-mszip-infinite-loop cve-2010-2801-qtm-flush cve-2014-9556-qtm-infinite-loop cve-2014-9732-folders-segfault "
        "cve-2015-4470-mszip-over-read cve-2015-4471-lzx-under-read filename-read-violation-1 filename-read-violation-2 "
        "filename-read-violation-3 filename-read-violation-4 lzx-main-tree-no-lengths lzx-premature-matches "
        "qtm-max-size-block").split()
UU = ("test_fuzz test_read_format_cab_1 test_read_format_cab_2 test_read_format_cab_3 test_read_format_cab_filename_cp932 "
      "test_read_format_cab_lzx_16bit test_read_format_cab_lzx_e8 test_read_format_cab_lzx_invalid_history "
      "test_read_format_cab_lzx_literal_control test_read_format_cab_lzx_oob test_read_format_cab_multi.p1 "
      "test_read_format_cab_multi.p2 test_read_format_cab_skip_across_folders test_read_format_cab_skip_malformed").split()


def sources():
    """[(cached name, url, source, uuencoded)] of every file of the cache."""
    out = [(f"mspack-cabd-{n}.cab", MSPACK + f"libmspack/test/test_files/cabd/{n}.cab", "libmspack", False) for n in CABD]
    out += [(f"cabextract-cabs-{n}.cab", MSPACK + f"cabextract/test/cabs/{n}.cab", "libmspack", False) for n in CABS]
    out += [(f"cabextract-bugs-{n}.cab", MSPACK + f"cabextract/test/bugs/{n}.cab", "libmspack", False) for n in BUGS]
    out += [(f"libarchive-{n.replace('test_read_format_cab_', '').replace('test_', '')}.cab", LIBARCHIVE + f"{n}.cab.uu", "libarchive", True)
            for n in UU]
    return out


def cache() -> Path:
    """<corpus root>/cab, the root being ctf.paths.realdata_root() ($CTF_REALDATA)."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _corpus
    return _corpus.root() / "cab"


def manifest() -> list:
    return json.loads(MANIFEST.read_text())["files"] if MANIFEST.is_file() else []


def have():
    """The cache folder when every file of the manifest is in it, else None."""
    folder, rows = cache(), manifest()
    return folder if rows and folder.is_dir() and all((folder / r["name"]).is_file() for r in rows) else None


def uudecode(text: bytes) -> bytes:
    out, inside = b"", False
    for line in text.splitlines():
        if line.startswith(b"begin "):
            inside = True
        elif line.strip() == b"end":
            break
        elif inside and line:
            try:
                out += binascii.a2b_uu(line)
            except binascii.Error:         # a line whose padding the encoder left out
                n = (((line[0] - 32) & 63) * 4 + 5) // 3
                out += binascii.a2b_uu(line[:n + 1])
    return out


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def main(argv) -> int:
    check, record = "--check" in argv, "--record" in argv
    folder = cache()
    known = {r["name"]: r for r in manifest()}
    rows, bad = [], 0
    if not check:
        folder.mkdir(parents=True, exist_ok=True)
    for name, url, source, uu in sources():
        target = folder / name
        want = known.get(name)
        if target.is_file():
            body, fetched = target.read_bytes(), None
        elif check:
            print(f"MISSING {name}")
            bad += 1
            continue
        else:
            try:
                with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "huntress-ctf-tests"}), timeout=30) as r:
                    fetched = r.read(4 << 20)
            except Exception as e:
                print(f"FAILED  {name}: {type(e).__name__}: {e}")
                bad += 1
                continue
            body = uudecode(fetched) if uu else fetched
        if want and sha256(body) != want["sha256"]:
            print(f"SHA-256 {name}: {sha256(body)} is not the manifest's {want['sha256']}; not kept")
            bad += 1
            continue
        if not want and not record:
            print(f"UNLISTED {name}: not in manifest_cab.json (run with --record after a first fetch)")
            bad += 1
            continue
        if fetched is not None:
            target.write_bytes(body)
        row = {"name": name, "url": url, "source": source, "bytes": len(body), "sha256": sha256(body)}
        if uu:
            row["sha256_uu"] = sha256(fetched) if fetched is not None else (want or {}).get("sha256_uu", "")
        rows.append(row)
    if record and not bad:
        MANIFEST.write_text(json.dumps({"files": rows}, indent=1) + "\n")
        print(f"recorded {len(rows)} files in {MANIFEST.name}")
    print(f"{len(rows)} of {len(sources())} files in {folder}" + (f"; {bad} not" if bad else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
