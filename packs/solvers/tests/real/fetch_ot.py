#!/usr/bin/env python3
"""Fetch the real OT/ICS capture corpus (one folder per protocol) for the oracle tests.

  .venv/bin/python tests/real/fetch_ot.py --check          no network: say what is present and matches
  CTF_EVENT=<slug> .venv/bin/python tests/real/fetch_ot.py  fetch every pinned row, verify sha256, write SOURCES.md
  CTF_EVENT=<slug> .venv/bin/python tests/real/fetch_ot.py --pin  fetch, and write the sha256 of each pinned-rev row

This is an OPERATOR step, not a build step. Fetching reaches a public mirror, so it is gated by the
event profile's rules.public_fetch_allow (ctf.scope.check_public_fetch): add the mirror host
(raw.githubusercontent.com) to rules.public_fetch_allow in events/<slug>/event.toml, and set CTF_EVENT,
or the fetch refuses by name. --check needs neither and makes no request.

The corpus lives at $CTF_REALDATA/ot/<proto>/ (outside this repo). The fetcher REFUSES to write under
paths.DEFAULT_REALDATA (the read-only Huntress source repo): set CTF_REALDATA to a writable cache first.

Each row of tests/real/manifest_ot.json names a public capture by github repo + commit (rev) + path,
its sha256, and its licence. A row whose rev is not a 40-hex commit, or whose sha256 is unset, is
UNPINNED: the fetcher names it and skips it (fetch with --pin fills sha256; rev the operator pins by
hand from the upstream history). A fetched file whose sha256 differs from the manifest is not kept.
A protocol with no public capture is listed under 'missing' and reported, never fabricated.

No capture is run, imported or unpickled by this script or by any test: the corpus is untrusted data.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
MANIFEST = HERE / "manifest_ot.json"
RAW = "https://raw.githubusercontent.com/%s/%s/%s"
RAW_HOST = "raw.githubusercontent.com"
MAX_FETCH = 64 << 20
_COMMIT = re.compile(r"^[0-9a-f]{40}$")

if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
from ctf import paths  # noqa: E402


def cache_root() -> Path:
    """The corpus root ($CTF_REALDATA). Reused by tests/real/_corpus.root()."""
    sys.path.insert(0, str(HERE))
    import _corpus
    return _corpus.root()


def default_realdata() -> Path:
    return Path(os.path.expanduser(str(paths.DEFAULT_REALDATA))).resolve()


def writable_root() -> Path:
    """The corpus root, after refusing to write under the read-only source corpus. Loud, no fallback."""
    root = cache_root()
    resolved = root.expanduser().resolve()
    forbidden = default_realdata()
    if resolved == forbidden or forbidden in resolved.parents:
        raise SystemExit(
            f"refusing to write the OT corpus under {resolved}: this is paths.DEFAULT_REALDATA "
            f"({forbidden}), a read-only source repo. Set CTF_REALDATA to a writable cache outside this "
            f"repo (e.g. export CTF_REALDATA=$HOME/ctf-realdata) and re-run.")
    return root


def load() -> dict:
    return json.loads(MANIFEST.read_text())


def files() -> list:
    return load()["files"]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def path_of(entry: dict, root: Path) -> Path:
    return root / "ot" / entry["proto"] / entry["name"]


def is_pinned(entry: dict) -> tuple[bool, str]:
    """(pinned, reason). A row is pinned only with a 40-hex commit rev and a sha256."""
    rev = entry.get("rev") or ""
    if not _COMMIT.match(rev):
        return False, "rev is not a 40-hex commit (operator pins it from the upstream history)"
    if not entry.get("sha256"):
        return False, "sha256 is unset (run fetch_ot.py --pin after pinning rev)"
    return True, ""


def source_of(entry: dict) -> str:
    return RAW % (entry["github"], entry.get("rev") or "<rev>", entry["path"])


def check_fetch_allowed() -> None:
    """Raise (via scope) unless the event profile allows a fetch from the raw mirror host."""
    from ctf import scope
    scope.check_public_fetch(RAW_HOST, purpose="fetch the OT real-capture corpus")


def http_get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "ctf-tools-ot-realdata-fetch"})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read(MAX_FETCH + 1)
    if len(data) > MAX_FETCH:
        raise ValueError("larger than %d bytes" % MAX_FETCH)
    return data


def fetch(entry: dict) -> bytes:
    return http_get(RAW % (entry["github"], entry["rev"], urllib.request.quote(entry["path"])))


def write_sources(root: Path, entries: list) -> None:
    by_proto: dict[str, list] = {}
    for e in entries:
        if path_of(e, root).is_file():
            by_proto.setdefault(e["proto"], []).append(e)
    for proto, rows in by_proto.items():
        out = ["# Real OT captures for the `%s` protocol" % proto, "",
               "Written by `tests/real/fetch_ot.py` from `tests/real/manifest_ot.json`. Untracked; "
               "nothing here is run. Confirm each licence before any redistribution.", "",
               "| file | bytes | sha256 | from | licence | what |",
               "| --- | --- | --- | --- | --- | --- |"]
        for e in rows:
            p = path_of(e, root)
            out.append("| `%s` | %d | `%s` | %s | %s | %s |" % (
                e["name"], p.stat().st_size, e.get("sha256", "?"), source_of(e),
                e.get("licence", "unverified"), e.get("note", "")))
        (root / "ot" / proto / "SOURCES.md").write_text("\n".join(out) + "\n")


def main(argv) -> int:
    check_only, pin = "--check" in argv, "--pin" in argv
    doc = load()
    entries = doc["files"]
    missing = doc.get("missing", [])

    if check_only:
        root = cache_root()
    else:
        root = writable_root()
        check_fetch_allowed()  # loud refusal unless rules.public_fetch_allow lists the mirror

    ok = absent = bad = unpinned = 0
    for e in entries:
        p = path_of(e, root)
        pinned, why = is_pinned(e)
        if p.is_file():
            got = sha256(p.read_bytes())
            if e.get("sha256") and got != e["sha256"]:
                print("MISMATCH %s/%s: have %s" % (e["proto"], e["name"], got))
                bad += 1
            else:
                if pin and not e.get("sha256") and _COMMIT.match(e.get("rev") or ""):
                    e["sha256"] = got
                ok += 1
            continue
        if not pinned and not pin:
            print("UNPINNED %s/%s: %s" % (e["proto"], e["name"], why))
            unpinned += 1
            continue
        if not _COMMIT.match(e.get("rev") or ""):
            print("UNPINNED %s/%s: %s" % (e["proto"], e["name"], why))
            unpinned += 1
            continue
        if check_only:
            print("absent   %s/%s (%s)" % (e["proto"], e["name"], source_of(e)))
            absent += 1
            continue
        try:
            data = fetch(e)
        except Exception as exc:  # noqa: BLE001 - one bad source never stops the rest
            print("FAILED   %s/%s: %s: %s" % (e["proto"], e["name"], type(exc).__name__, exc))
            bad += 1
            continue
        got = sha256(data)
        if e.get("sha256") and got != e["sha256"]:
            print("MISMATCH %s/%s: fetched %s, not kept" % (e["proto"], e["name"], got))
            bad += 1
            continue
        if not e.get("sha256"):
            if not pin:
                print("UNPINNED %s/%s: %s (run --pin), not kept" % (e["proto"], e["name"], got))
                unpinned += 1
                continue
            e["sha256"] = got
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".part%d" % os.getpid())
        tmp.write_bytes(data)
        tmp.replace(p)
        print("fetched  %s/%s %d bytes" % (e["proto"], e["name"], len(data)))
        ok += 1

    for m in missing:
        print("missing  %s: %s" % (m.get("proto", "?"), m.get("reason", "")))

    if pin:
        MANIFEST.write_text(json.dumps(doc, indent=2) + "\n")
    if not check_only:
        write_sources(root, entries)
    print("FETCH_OT root=%s ok=%d absent=%d unpinned=%d bad=%d missing=%d"
          % (root, ok, absent, unpinned, bad, len(missing)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
