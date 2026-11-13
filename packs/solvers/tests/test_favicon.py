"""B-089: the favicon multi-hash library (ctf/favicon.py) and the intake engine (toolkits.favicon_hash).

The hash algorithm is pinned to published MurmurHash3 vectors, the Shodan recipe is pinned to the
MIME-base64 step (dropping the newlines must change the hash), and the engine's result is checked to
be a never-proven candidate when the event format is known and unsure when it is not.
"""
from __future__ import annotations

import base64
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ctf import event, favicon
import favicon_hash  # the engine module, flat-imported from solvers/toolkits (B-089)


# ---------------------------------------------------------------- MurmurHash3 vectors

@pytest.mark.parametrize("data,expected", [
    (b"", 0),
    (b"foo", -156908512),          # mmh3 README reference vector
    (b"hello", 613153351),
    (b"The quick brown fox jumps over the lazy dog", 776992547),
])
def test_murmur3_published_vectors(data, expected):
    assert favicon.murmur3_x86_32(data) == expected


def test_murmur3_is_signed_32bit():
    # Every result is a signed 32-bit int; a known-negative vector proves the sign step.
    v = favicon.murmur3_x86_32(b"foo")
    assert -(2 ** 31) <= v < 2 ** 31
    assert v < 0
    assert favicon.murmur3_x86_32_unsigned(b"foo") == v + 2 ** 32


def test_murmur3_rejects_text():
    with pytest.raises(TypeError):
        favicon.murmur3_x86_32("foo")  # must hash bytes, not str


def test_murmur3_tail_lengths_differ():
    # All four tail-length branches (len % 4 in 0..3) must be exercised and distinct.
    hashes = {favicon.murmur3_x86_32(b"a" * n) for n in (4, 5, 6, 7)}
    assert len(hashes) == 4


# ---------------------------------------------------------------- Shodan recipe / base64 trap

def test_shodan_hash_uses_mime_base64_not_bare():
    # Shodan hashes codecs.encode(data, "base64") == base64.encodebytes: MIME, with newlines.
    # A long payload makes encodebytes wrap lines, so the bare b64encode gives a DIFFERENT hash.
    data = bytes(range(256)) * 10
    assert favicon.shodan_hash(data) == favicon.murmur3_x86_32(base64.encodebytes(data))
    assert favicon.shodan_hash(data) != favicon.murmur3_x86_32(base64.b64encode(data))


def test_mime_base64_has_trailing_newline_and_wraps():
    data = b"x" * 200
    b = favicon.mime_base64(data)
    assert b.endswith(b"\n")
    lines = b.rstrip(b"\n").split(b"\n")
    assert all(len(line) <= 76 for line in lines)
    assert len(lines) > 1


# ---------------------------------------------------------------- fingerprint + queries

def test_fingerprint_matches_stdlib_hashes():
    data = b"\x00\x00\x01\x00" + bytes(range(97)) * 3
    fh = favicon.fingerprint(data)
    assert fh.md5 == hashlib.md5(data).hexdigest()
    assert fh.sha256 == hashlib.sha256(data).hexdigest()
    assert fh.size == len(data)
    assert fh.mmh3 == favicon.shodan_hash(data)


def test_icon_hash_queries_use_the_right_hash_per_engine():
    fh = favicon.fingerprint(b"\x00\x00\x01\x00icon-bytes")
    q = favicon.icon_hash_queries(fh)
    assert q["shodan"] == f"http.favicon.hash:{fh.mmh3}"      # Shodan: signed mmh3
    assert q["fofa"] == f'icon_hash="{fh.mmh3}"'
    assert q["censys"] == f'services.http.response.favicons.md5_hash:"{fh.md5}"'  # Censys: md5
    assert q["zoomeye"] == f'iconhash:"{fh.md5}"'
    assert str(fh.mmh3) not in q["censys"]                     # not the mmh3 where md5 is wanted


# ---------------------------------------------------------------- icon links

def test_icon_links_parses_rel_icon_and_resolves():
    html = ('<html><head>'
            '<link rel="shortcut icon" href="/static/fav.ico">'
            '<link rel="apple-touch-icon" href="https://cdn.example/t.png">'
            '</head></html>')
    links = favicon.icon_links(html, base_url="http://host.example/page")
    assert links == ["http://host.example/static/fav.ico", "https://cdn.example/t.png"]


def test_icon_links_defaults_to_favicon_ico_when_none_declared():
    links = favicon.icon_links("<html><head><title>x</title></head></html>",
                               base_url="http://host.example/deep/page")
    assert links == ["http://host.example/favicon.ico"]


def test_icon_links_ignores_non_icon_link_tags():
    html = '<link rel="stylesheet" href="/s.css"><link rel="icon" href="/i.ico">'
    assert favicon.icon_links(html, base_url="http://h/") == ["http://h/i.ico"]


def test_looks_like_icon(tmp_path):
    ico = tmp_path / "logo.ico"
    ico.write_bytes(b"\x00\x00\x01\x00abc")
    named = tmp_path / "favicon.png"
    named.write_bytes(b"\x89PNG\r\n\x1a\n")
    magic = tmp_path / "noext"
    magic.write_bytes(b"\x00\x00\x01\x00rest")
    plain = tmp_path / "notes.txt"
    plain.write_bytes(b"hello")
    assert favicon.looks_like_icon(ico)
    assert favicon.looks_like_icon(named)
    assert favicon.looks_like_icon(magic)
    assert not favicon.looks_like_icon(plain)


# ---------------------------------------------------------------- the intake engine

def _profile(prefixes):
    return event.parse({
        "slug": "fav-test", "name": "favicon test",
        "dates": {"start": __import__("datetime").date(2026, 1, 1),
                  "end": __import__("datetime").date(2026, 1, 2)},
        "platform": {"kind": "ctfd", "base_url": "https://board.fav.test"},
        "flag": {"prefixes": list(prefixes), "body": "[^}\\n]{1,256}", "case": "prefix-insensitive"},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": ["localhost"]},
    }, src="<test>")


def test_engine_wraps_hashes_as_candidates_when_format_known(tmp_path):
    ico = tmp_path / "favicon.ico"
    ico.write_bytes(b"\x00\x00\x01\x00" + b"\xa5" * 300)
    res, report = favicon_hash.analyze(ico, _profile(["CSCTF"]))
    fh = favicon.fingerprint(ico.read_bytes())
    assert res.status == "candidate"                  # plausible, never proven
    assert f"CSCTF{{{fh.md5}}}" in res.flags
    assert f"CSCTF{{{fh.mmh3}}}" in res.flags
    assert f"http.favicon.hash:{fh.mmh3}" in report


def test_engine_is_unsure_when_format_unknown(tmp_path):
    ico = tmp_path / "favicon.ico"
    ico.write_bytes(b"\x00\x00\x01\x00icon")
    res, report = favicon_hash.analyze(ico, _profile([]))  # no prefixes -> nothing to wrap
    assert res.status == "unsure"
    assert not res.flags
    fh = favicon.fingerprint(ico.read_bytes())
    assert any(fh.md5 in e.detail for e in res.evidence)   # hashes still recorded for a read


def test_engine_none_for_non_icon(tmp_path):
    txt = tmp_path / "notes.txt"
    txt.write_bytes(b"not an icon")
    res, report = favicon_hash.analyze(txt, _profile(["CSCTF"]))
    assert res.status == "none"
    assert not res.flags


def test_engine_candidate_flags_are_distinct(tmp_path):
    ico = tmp_path / "favicon.ico"
    ico.write_bytes(b"\x00\x00\x01\x00" + b"z" * 50)
    res, _ = favicon_hash.analyze(ico, _profile(["CSCTF"]))
    assert len(res.flags) == len(set(res.flags))   # signed==unsigned when positive must not duplicate


# ---------------------------------------------------------------- wired into intake

REPO = Path(__file__).resolve().parents[1]


def test_manifest_adapts_icons_for_intake():
    from ctf.engines import manifest
    from ctf.intake import engines as E
    m = {x.id: x for x in manifest.discover(REPO)}["toolkits.favicon_hash"]
    assert m.intake.select == "files" and m.intake.run == "per-file" and m.cost_class == "cheap"
    assert "{file}" in m.intake.args and "{out}" in m.intake.args
    # It takes icons (by ext, by ICO magic, by name) and not a plain text drop.
    assert E.files_matching(m.intake.match, [(Path("favicon.ico"), b"\x00\x00\x01\x00x")])
    assert E.files_matching(m.intake.match, [(Path("logo"), b"\x00\x00\x01\x00x")])
    assert not E.files_matching(m.intake.match, [(Path("notes.txt"), b"hello")])


class _Adapter:
    kind = "fake"

    def __init__(self, ch, files):
        self.ch, self.files = ch, files

    def get_challenge(self, cid):
        return self.ch

    def list_challenges(self):
        return [self.ch]

    def download_files(self, cid, dest):
        out = []
        for rel, data in self.files.items():
            p = Path(dest) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
            out.append(p)
        return out

    def submit(self, cid, flag):
        raise AssertionError("intake never submits")

    def team_solves(self):
        return []


def test_intake_runs_the_opener_on_an_icon_and_records_the_hashes(tmp_path):
    from ctf import intake as I
    from ctf.platform.base import Challenge, FileRef
    prof = event.load("csctf")
    icon = b"\x00\x00\x01\x00" + b"\x3c" * 400
    ch = Challenge(id="9171", name="Hash the Favicon", category="osint",
                   points=120, description="hash the favicon the way shodan does",
                   files=(FileRef("favicon.ico"),))
    rep = I.intake_one("9171", prof, adapter=_Adapter(ch, {"favicon.ico": icon}),
                       workdir=tmp_path / "wd", options=I.Options(net_guard="hook", record=False))
    runs = [r for r in rep.runs if r.engine == "toolkits.favicon_hash"]
    assert runs and runs[0].status == "ok" and runs[0].result_status == "candidate"
    report = rep.dir / "recon" / "engines" / "toolkits.favicon_hash" / "favicon_hash-favicon.ico.md"
    fh = favicon.fingerprint(icon)
    assert f"http.favicon.hash:{fh.mmh3}" in report.read_text()
    # The favicon hashes are candidates, never an auto-solved flag: several forms are plausible.
    assert rep.status == "candidate"


def test_router_sends_favicon_briefs_here():
    from ctf.engines import router
    ids = [h.manifest.id for h in router.route("osint", "hash the favicon the way shodan does")]
    assert "toolkits.favicon_hash" in ids
    assert ids[0] == "toolkits.favicon_hash"   # the keyword route outranks the bare osint engines
    assert "toolkits.favicon_hash" not in [h.manifest.id for h in router.route("osint", "find the hidden gps location")]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
