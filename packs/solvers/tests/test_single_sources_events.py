"""B-001a behaviour after the single-source migration: per-event flag shapes through migrated engines,
the active-event plumbing in ctf.flagfmt, the retired overrides, and the one workdir resolver.

Every engine below used to carry its own flag regex (several hard-coded to CSCTF, which returned
nothing on Pink and Spooky; the widened ones matched CSS). Each must now follow the event profile.
Fixtures are synthetic strings; nothing is read from a challenge or the network.
"""
from __future__ import annotations

import os
import subprocess
import sys
import warnings

import pytest

from ctf import config, env, event, flagfmt, paths

import defense_stanag            # solvers/toolkits: was CSCTF-only (bytes)
import ff_pico8_cart             # solvers/toolkits: was CSCTF-only (bytes)
import transport                 # solvers/toolkits: was a CSCTF/chronos/CTF/flag literal (text)
import xor_strings               # solvers/binary: was a widened any-WORD{...} literal
import web as tk_web             # solvers/toolkits/web.py: was a $CTF_FLAG_FORMAT override

HEX32 = "0123456789abcdef" * 2

# Per event: strings that ARE a flag of that event, and strings that are not.
SHAPES = {
    "huntress": (["flag{%s}" % HEX32],
                 ["flag{not_hex}", "CSCTF{x}", "PINK{x}", "FLAG{%s}" % HEX32]),
    "csctf": (["CSCTF{l33t_C4m3l}", "csctf{lower}", "CTF{outlier}", "chronos{x}", "flag{x}"],
              ["PINK{x}", "spooky{x}", "HTB{x}"]),
    "pink": (["PINK{p1nk_f14g}"],
             ["pink{x}", "CSCTF{x}", "spooky{x}"]),
    "spooky": (["spooky{boo}", "SPOOKY{boo}"],
               ["CSCTF{x}", "PINK{x}"]),
}
CSS = "a{color:red} .btn{margin:0} div.box{padding:1px}"


@pytest.fixture(params=sorted(SHAPES))
def slug(request, monkeypatch):
    monkeypatch.setenv("CTF_EVENT", request.param)
    return request.param


def _engines_text(s):
    """What each migrated text engine reports for one string."""
    return {
        "transport.find_flags": sorted(transport.find_flags(s)),
        "web.find_flags": sorted(tk_web.find_flags(s)),
    }


def _xor_hits(s, key=0x5A):
    """xor_strings.flag_candidates over `s` XOR-encoded with one key: the runs that key decodes."""
    blob = bytes(c ^ key for c in s.encode())
    return [d["text"] for d in xor_strings.flag_candidates(blob) if d["key"] == key]


def _engines_bytes(b):
    return {
        "defense_stanag._flags": sorted(defense_stanag._flags(b)),
        "ff_pico8_cart._flags": sorted(ff_pico8_cart._flags(b)),
    }


def test_engines_find_the_events_own_flags(slug):
    good, _ = SHAPES[slug]
    for f in good:
        for name, got in _engines_text(f"noise {f} noise").items():
            assert got == [f], (slug, name, f, got)
        for name, got in _engines_bytes(b"\x00\x01" + f.encode() + b"\xff").items():
            assert got == [f], (slug, name, f, got)
        assert transport.is_flag(f) and tk_web.is_flag(f)
        assert _xor_hits(f) == [f], (slug, "xor_strings", f)


def test_engines_ignore_other_events_flags_and_css(slug):
    _, bad = SHAPES[slug]
    for s in bad + [CSS]:
        for name, got in _engines_text(f"noise {s} noise").items():
            assert got == [], (slug, name, s, got)
        for name, got in _engines_bytes(s.encode()).items():
            assert got == [], (slug, name, s, got)
        assert not transport.is_flag(s) and not tk_web.is_flag(s)
        assert _xor_hits(s) == [], (slug, "xor_strings", s)


def test_csctf_hardcoded_engines_now_answer_on_pink_and_spooky(monkeypatch):
    """The CSCTF-only literal in these engines returned nothing on Pink and Spooky."""
    blob = b"..PINK{p1nk}..spooky{boo}..CSCTF{c5}.."
    monkeypatch.setenv("CTF_EVENT", "pink")
    assert defense_stanag._flags(blob) == ["PINK{p1nk}"]
    assert ff_pico8_cart._flags(blob) == ["PINK{p1nk}"]
    monkeypatch.setenv("CTF_EVENT", "spooky")
    assert defense_stanag._flags(blob) == ["spooky{boo}"]
    monkeypatch.setenv("CTF_EVENT", "csctf")
    assert defense_stanag._flags(blob) == ["CSCTF{c5}"]


def test_widened_engine_no_longer_matches_css_or_foreign_words(monkeypatch):
    """xor_strings matched any WORD{...}: CSS rules and foreign prefixes were 'flags'."""
    monkeypatch.setenv("CTF_EVENT", "csctf")
    assert _xor_hits("body{color:red}") == []
    assert _xor_hits("HTB{other_event}") == []
    # a challenge-stated shape is still honoured when the caller passes it
    blob = bytes(c ^ 0x5A for c in b"HTB{other_event}")
    cands = xor_strings.flag_candidates(blob, pattern=r"HTB\{[a-z_]+\}")
    assert [d["text"] for d in cands if d["key"] == 0x5A] == ["HTB{other_event}"]


def test_huntress_hex_body_rejects_css_shaped_flag_prefix(monkeypatch):
    """`.flag{color:red}` collided with the CSCTF-era wire regex; the Huntress body is 32 hex."""
    monkeypatch.setenv("CTF_EVENT", "huntress")
    assert transport.find_flags(".flag{color:red} p{x}") == set()
    assert transport.find_flags(f".flag{{{HEX32}}}") == {f"flag{{{HEX32}}}"}


# --------------------------------------------------------------------------- flagfmt plumbing

def test_current_follows_ctf_event_and_is_cached(monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "pink")
    a = flagfmt.current()
    assert a is flagfmt.current(), "repeated calls must hit the cache"
    assert a.is_flag("PINK{x}") and flagfmt.TEXT.fullmatch("PINK{x}")
    monkeypatch.setenv("CTF_EVENT", "spooky")
    assert flagfmt.current() is not a
    assert flagfmt.TEXT.fullmatch("PINK{x}") is None and flagfmt.TEXT.fullmatch("spooky{x}")
    assert flagfmt.BYTES.findall(b"xxspooky{b}") == [b"spooky{b}"]


def test_current_without_event_fails_loudly(monkeypatch):
    monkeypatch.delenv("CTF_EVENT", raising=False)
    with pytest.raises(event.EventError, match="CTF_EVENT"):
        flagfmt.current()
    with pytest.raises(event.EventError):
        flagfmt.TEXT.search("CSCTF{x}")
    monkeypatch.setenv("CTF_EVENT", "no-such-event")
    with pytest.raises(event.EventError):
        flagfmt.current()


def test_proof_stand_ins(monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "csctf")
    assert not flagfmt.has_proof()
    # an event without [proof] has no proof tokens: the scan stand-ins find nothing, the API raises
    assert flagfmt.PROOF_TEXT.search("proof_" + HEX32) is None
    assert flagfmt.PROOF_ANYCASE.findall("proof_" + HEX32) == []
    assert flagfmt.PROOF_BYTES.findall(b"proof_" + HEX32.encode()) == []
    with pytest.raises(LookupError, match="proof"):
        flagfmt.current().find_proofs("proof_" + HEX32)
    monkeypatch.setenv("CTF_EVENT", "huntress")
    assert flagfmt.has_proof()
    tok = "proof_" + HEX32
    assert flagfmt.PROOF_TEXT.fullmatch(tok)
    assert flagfmt.PROOF_TEXT.fullmatch(tok.upper().replace("PROOF_", "proof_")) is None
    # the broad "seen" form notices an uppercase spelling the strict form refuses
    assert flagfmt.PROOF_ANYCASE.findall("a PROOF_" + HEX32.upper() + " b") == ["PROOF_" + HEX32.upper()]


def test_shape_is_any_prefix_under_the_events_body(monkeypatch):
    """SHAPE_* (broad seen scans in the web lane) take any word prefix but keep the event's body."""
    monkeypatch.setenv("CTF_EVENT", "csctf")
    assert flagfmt.SHAPE_TEXT.findall("x HTB{decoy} y") == ["HTB{decoy}"]
    assert flagfmt.TEXT.findall("x HTB{decoy} y") == []
    assert flagfmt.SHAPE_TEXT.findall("xHTB{decoy}") == ["xHTB{decoy}"], "left boundary is per word"
    monkeypatch.setenv("CTF_EVENT", "huntress")
    assert flagfmt.SHAPE_TEXT.findall(f"HTB{{{HEX32}}} .flag{{color:red}}") == [f"HTB{{{HEX32}}}"]


def test_live_stand_ins_are_read_only():
    with pytest.raises(AttributeError):
        flagfmt.TEXT.pattern = "x"


def test_uuid4_refinement_is_a_filter_over_the_proof_format(monkeypatch):
    import proof_hunt
    monkeypatch.setenv("CTF_EVENT", "huntress")
    v4 = "proof_" + "0123456789ab4def8123456789abcdef"     # nibble 13 = 4, nibble 17 in 89ab
    not_v4 = "proof_" + "0123456789ab1def0123456789abcdef"
    assert proof_hunt.PROOF_FORMAT.fullmatch(v4) and proof_hunt.PROOF_FORMAT.fullmatch(not_v4) is None
    assert proof_hunt.is_proof(not_v4), "uuid4 is an observed validator, never the return gate"
    assert proof_hunt.PROOF_FORMAT.search(f"x {not_v4} y {v4} z").group(0) == v4


# ------------------------------------------------------------------------ retired overrides

def test_config_flag_check_follows_the_event(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "CONFIG_JSON", tmp_path / "absent.json")
    monkeypatch.setenv("CTF_EVENT", "pink")
    cfg = config.load()
    assert cfg.looks_like_flag("PINK{x}") and not cfg.looks_like_flag("CSCTF{x}")
    assert not cfg.looks_like_flag("PINK{x} trailing"), "the guard checks the whole candidate"
    assert cfg.workdir == paths.workdir()


def test_flag_format_env_override_is_refused(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "CONFIG_JSON", tmp_path / "absent.json")
    monkeypatch.setenv("CTF_FLAG_FORMAT", r"anything")
    with pytest.raises(config.ConfigError, match="retired"):
        config.load()


@pytest.mark.parametrize("key", ["flag_format", "workdir"])
def test_retired_config_json_keys_are_refused(monkeypatch, tmp_path, key):
    p = tmp_path / "config.json"
    p.write_text('{"%s": "x"}' % key)
    monkeypatch.setattr(config, "CONFIG_JSON", p)
    with pytest.raises(config.ConfigError, match=key):
        config.load()


def test_migrated_reader_honours_a_legacy_spelling_with_a_warning(monkeypatch):
    import alert                                                # tools/alert.py, was $CSCTF_SOUND
    monkeypatch.delenv("CTF_SOUND", raising=False)
    legacy = env.legacy_names("CTF_SOUND")[-1]                  # the CSCTF_ spelling, from ctf.env
    monkeypatch.setenv(legacy, "1")
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        assert alert.audible() is True
    assert any(issubclass(x.category, DeprecationWarning) and "CTF_SOUND" in str(x.message) for x in w)
    monkeypatch.setenv("CTF_SOUND", "0")                        # the canonical name wins
    assert alert.audible() is False


# ---------------------------------------------------------------------------- one workdir

def _resolvers():
    import alert
    import archive_passwords
    import labels
    import oob
    import proposer_model
    import target
    return {
        "labels.challenges_root": labels.challenges_root,
        "archive_passwords.challenges_root": archive_passwords.challenges_root,
        "proposer_model.challenges_root": proposer_model.challenges_root,
        "target.folder": target.folder,
        "alert.log_path": lambda: alert.log_path().parent.parent,
        "oob.home": lambda: oob.home().parent,
    }


def test_every_carried_resolver_is_ctf_paths_workdir(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "w"))
    want = paths.workdir()
    for name, fn in _resolvers().items():
        assert fn() == want, name
    monkeypatch.delenv("CTF_WORKDIR")
    monkeypatch.setenv("CTF_EVENT", "pink")
    for name, fn in _resolvers().items():
        assert fn() == paths.workdir("pink"), name
        assert fn().name == "pink" and paths.repo_root() not in fn().parents, name


def test_no_resolver_falls_back_to_the_checkout(monkeypatch):
    monkeypatch.delenv("CTF_WORKDIR", raising=False)
    monkeypatch.delenv("CTF_EVENT", raising=False)
    for name, fn in _resolvers().items():
        with pytest.raises(event.EventError):
            fn()


def test_web_toggle_files_live_in_the_workdir(monkeypatch, tmp_path):
    import xxe_read
    monkeypatch.delenv("CTF_WEB_XXE_READ", raising=False)
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    assert xxe_read.enabled() is True
    (tmp_path / "_xxe_read.off").write_text("")
    assert xxe_read.enabled() is False


def test_cli_prints_the_workdir(tmp_path):
    e = dict(os.environ, CTF_WORKDIR=str(tmp_path / "cw"))
    r = subprocess.run([sys.executable, "-m", "ctf", "workdir"], cwd=paths.repo_root(), env=e,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == str((tmp_path / "cw").resolve())
    e.pop("CTF_WORKDIR")
    e.pop("CTF_EVENT", None)
    r = subprocess.run([sys.executable, "-m", "ctf", "workdir"], cwd=paths.repo_root(), env=e,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 2 and "CTF_EVENT" in r.stderr
