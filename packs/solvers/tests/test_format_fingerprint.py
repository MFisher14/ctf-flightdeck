"""B-207: the format_fingerprint step and its offline + public-code-search lookup.

Every test builds its bytes synthetically; the code-search client's transport, clock and sleep are
injected, so nothing here touches the network and no challenge file is read.
"""
from __future__ import annotations

import datetime as dt
import json
import struct

import pytest

from ctf import event
from ctf.formats import corpus
from ctf.formats import codesearch as C
from ctf.formats import fingerprint as F


# ---------------------------------------------------------------- helpers

def profile(public=(), *, live=(), slug="b207-test"):
    rules = {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
             "live_service_scope": list(live), "public_fetch_allow": list(public)}
    return event.parse({
        "slug": slug, "name": "b207 test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "ctfd", "base_url": "https://board.b207.example"},
        "flag": {"prefixes": []}, "rules": rules,
    }, src="<test>")


def record_blob(header=b"MYFMT\x01\x00\x00\x00", records=64, stride=16):
    body = b"".join(struct.pack("<I", i) + b"ABCD" + bytes(stride - 8) for i in range(records))
    return header + body


def fake_transport(items):
    calls = []

    def transport(url, headers, timeout, maxb):
        calls.append(url)
        body = json.dumps({"items": items}).encode()
        return C.HTTPResult(200, {"Content-Type": "application/json"}, body, url)

    transport.calls = calls
    return transport


ONE_ITEM = [{"repository": {"full_name": "acme/secondfloor"}, "path": "fmt/sig.c",
             "html_url": "https://github.com/acme/secondfloor/blob/x/fmt/sig.c"}]


# ---------------------------------------------------------------- the magic table

def test_magic_table_loads_longest_signature_first():
    table = F.load_magic()
    assert table, "the shipped magic table is non-empty"
    lengths = [len(m.sig) for m in table]
    assert lengths == sorted(lengths, reverse=True), "longest signature must sort first (most specific wins)"
    ids = {m.id for m in table}
    assert {"sqlite3", "pcap_le", "elf", "gitpack", "vim_swap"} <= ids


def test_magic_table_rejects_a_bad_entry(tmp_path):
    bad = tmp_path / "magic.toml"
    bad.write_text('[[magic]]\nid = "x"\nlabel = "x"\nsig = "zz"\n')   # not hex
    with pytest.raises(F.MagicError, match="not an even-length hex string"):
        F.load_magic(bad)
    bad.write_text('[[magic]]\nid = "x"\nlabel = "x"\nsig = "4d5a"\nbogus = 1\n')
    with pytest.raises(F.MagicError, match="unknown keys"):
        F.load_magic(bad)
    bad.write_text('[[magic]]\nid = "x"\nlabel = "x"\nsig = "4d5a"\n[[magic]]\nid = "x"\nlabel = "y"\nsig = "ffd8"\n')
    with pytest.raises(F.MagicError, match="listed twice"):
        F.load_magic(bad)
    bad.write_text("title = 'nope'\n")
    with pytest.raises(F.MagicError, match="non-empty list"):
        F.load_magic(bad)


# ---------------------------------------------------------------- the fingerprint measurements

def test_fingerprint_reads_magic_strings_and_header_fields():
    fp = F.fingerprint("mystery.bin", record_blob())
    assert fp.head_hex.startswith("4d59464d54")          # "MYFM.."
    assert "MYFMT" in fp.magic_ascii
    first = fp.header_fields[0]
    assert first["offset"] == 0 and first["u32le"] == int.from_bytes(b"MYFM", "little")


def test_fingerprint_finds_the_record_stride():
    # A 16-byte record geometry must surface as stride 16; a build that disables the probe loses it.
    fp = F.fingerprint("mystery.bin", record_blob(records=96, stride=16))
    assert fp.stride == 16
    assert fp.stride_score > 0.5
    # A stride-24 record file must report 24, not 16: the probe measures the real period.
    fp24 = F.fingerprint("other.bin", record_blob(records=96, stride=24))
    assert fp24.stride == 24


def test_fingerprint_reports_no_stride_for_high_entropy_bytes():
    # Random, high-entropy bytes have no real record period: the self-correlation match fraction stays
    # near 1/256, far below the 0.25 "demand a real, not trivial, period" threshold, so _stride must
    # report None. A build that drops the threshold (e.g. 0.25 -> 0.0) would instead report a spurious
    # low-confidence stride on random data. This locks the threshold.
    import random
    rng = random.Random(0xB207)
    data = bytes(rng.randrange(256) for _ in range(F.GEOM_BYTES))
    s, frac = F._stride(data, F.GEOM_MAX_STRIDE)
    assert s is None and frac == 0.0, "random bytes have no period; the trivial-match guard must reject it"
    assert F.fingerprint("rand.bin", data).stride is None


def test_fingerprint_entropy_profile_tracks_low_then_high():
    low = bytes(2048)                                   # a flat header band
    high = bytes((i * 167 + 13) % 256 for i in range(2048))  # a spread body
    fp = F.fingerprint("mixed.bin", low + high)
    assert fp.entropy_profile[0] < 1.0                  # the zero band
    assert max(fp.entropy_profile) > 6.0                # the spread band
    assert fp.entropy_profile[0] < fp.entropy_profile[-1]


def test_fingerprint_string_table_reads_ascii_and_utf16le():
    utf16 = "SECRETWORD".encode("utf-16-le")
    data = b"\x00\x01" + b"plain_ascii_string" + b"\xff\x00" + utf16 + bytes(32)
    fp = F.fingerprint("s.bin", data)
    assert "plain_ascii_string" in fp.strings
    assert "SECRETWORD" in fp.strings                   # found only by the UTF-16LE pass


def test_fingerprint_bounds_a_huge_member_without_reading_it_whole():
    big = b"HEADERxyz" + bytes(F.FP_BYTES * 4)          # far past the read bound
    fp = F.fingerprint("big.bin", big)
    assert fp.size == len(big)                          # size is the real size
    assert len(fp.entropy_profile) <= 64                # but the profile is bounded


# ---------------------------------------------------------------- the step: identify first, then offline

def test_analyze_short_circuits_when_identify_names_the_member():
    sample = corpus.build("eml_attachments")            # a format identify names `sure`
    res = F.analyze(sample.name, sample.data)
    assert res.named and res.named[0].format == "eml"
    assert res.fp is None and res.candidates == ()      # no fingerprint, no lookup: it is already named
    assert res.to_result().status == "unsure"


def test_analyze_names_sqlite_from_the_offline_magic_table():
    data = b"SQLite format 3\x00" + bytes(400)
    res = F.analyze("export.db", data)
    assert res.named == ()                              # identify does not know sqlite
    assert res.fp is not None
    labels = [c.label for c in res.candidates]
    assert any("SQLite" in label for label in labels)
    assert res.candidates[0].source == "magic"


def test_analyze_offline_only_never_touches_a_client():
    # With no client the step makes no online call at all.
    data = record_blob()
    res = F.analyze("mystery.bin", data)
    assert res.online_used is False and res.sent_magics == ()


def test_to_result_is_unsure_evidence_never_a_flag():
    res = F.analyze("export.db", b"SQLite format 3\x00" + bytes(64))
    result = res.to_result(challenge_id="42")
    assert result.status == "unsure"
    assert result.flags == ()                           # a lead is never a flag
    assert any("likely" in e.detail for e in result.evidence)


# ---------------------------------------------------------------- the public code-search client

def test_code_search_is_off_unless_enabled():
    client = C.PublicCodeSearchClient()                 # default: disabled
    with pytest.raises(C.CodeSearchDisabled, match="off"):
        client.search(["MZ_MAGIC"], profile=profile(["api.github.com"]))


def test_code_search_is_refused_when_event_policy_does_not_allow_the_host():
    t = fake_transport(ONE_ITEM)
    client = C.PublicCodeSearchClient(enabled=True, transport=t, sleep=lambda s: None, clock=lambda: 0.0)
    with pytest.raises(C.CodeSearchError, match="public_fetch_allow"):
        client.search(["MYFMT"], profile=profile([]))   # host not listed
    assert t.calls == [], "no request may be built when the policy refuses"


def test_code_search_returns_ranked_leads_when_allowed():
    t = fake_transport(ONE_ITEM)
    client = C.PublicCodeSearchClient(enabled=True, transport=t, sleep=lambda s: None, clock=lambda: 0.0)
    leads = client.search(["MYFMT"], profile=profile(["api.github.com"]))
    assert len(t.calls) == 1 and "api.github.com" in t.calls[0]
    assert leads and leads[0].label == "acme/secondfloor"
    assert leads[0].ref.endswith("sig.c")


def test_code_search_sends_only_short_magic_strings():
    t = fake_transport(ONE_ITEM)
    client = C.PublicCodeSearchClient(enabled=True, transport=t)
    for bad, why in [("x" * 100, "cap"), ("a/b/c", "path"), ("one\ntwo", "line"),
                     ("api_key = sk-abcdefghij", "secret")]:
        with pytest.raises(C.CodeSearchError, match=why):
            client.search_magic(bad, profile=profile(["api.github.com"]))
    assert t.calls == [] and client.request_count == 0   # nothing left the host


def test_code_search_honours_the_request_cap_and_sleeps_between_requests():
    t = fake_transport(ONE_ITEM)
    slept, ticks = [], [0.0]
    client = C.PublicCodeSearchClient(enabled=True, transport=t, request_cap=2,
                                      sleep=lambda s: slept.append(s), clock=lambda: ticks[0],
                                      min_interval=2.0)
    client.search(["AAAA", "BBBB", "CCCC", "DDDD"], profile=profile(["api.github.com"]))
    assert len(t.calls) == 2, "the request cap stops further searches"
    assert slept and slept[0] == pytest.approx(2.0), "it waits min_interval before the second request"


def test_search_magic_in_a_loop_never_exceeds_the_request_cap():
    # The request cap must hold even when search_magic() is driven directly in a loop, not only through
    # search()'s own loop guard: after request_cap successful searches the next direct call is refused,
    # and it builds no request. A build that checks the cap with `>` instead of `>=` would let one extra
    # request past the cap. This locks the internal cap as defense-in-depth behind search()'s loop.
    t = fake_transport(ONE_ITEM)
    client = C.PublicCodeSearchClient(enabled=True, transport=t, request_cap=2,
                                      sleep=lambda s: None, clock=lambda: 0.0)
    pol = profile(["api.github.com"])
    client.search_magic("AAAA", profile=pol)
    client.search_magic("BBBB", profile=pol)
    assert client.request_count == 2
    with pytest.raises(C.CodeSearchError, match="request cap reached"):
        client.search_magic("CCCC", profile=pol)
    assert client.request_count == 2, "the refused call makes no request"
    assert len(t.calls) == 2, "no extra request reached the provider past the cap"


def test_code_search_rejects_a_non_allowlisted_host_url():
    client = C.PublicCodeSearchClient(enabled=True, transport=fake_transport(ONE_ITEM))
    with pytest.raises(C.CodeSearchError, match="not allow-listed"):
        client._request("https://evil.example/search", profile(["api.github.com"]))


def test_code_search_raises_on_a_non_2xx_status():
    def transport(url, headers, timeout, maxb):
        return C.HTTPResult(403, {"Content-Type": "application/json"}, b"{}", url)
    client = C.PublicCodeSearchClient(enabled=True, transport=transport, sleep=lambda s: None,
                                      clock=lambda: 0.0)
    with pytest.raises(C.CodeSearchError, match="HTTP status 403"):
        client.search_magic("MYFMT", profile=profile(["api.github.com"]))


# ---------------------------------------------------------------- the online path through analyze

def test_analyze_appends_online_leads_below_the_offline_magic_hit():
    t = fake_transport(ONE_ITEM)
    client = C.PublicCodeSearchClient(enabled=True, transport=t, sleep=lambda s: None, clock=lambda: 0.0)
    # A blob whose head is a short magic string with no offline table hit, but with a gitpack body so
    # there is also one offline hit: the offline hit must rank above the online lead.
    data = b"PACK" + b"\x00\x00\x00\x02" + b"MYSTERYHDR" + bytes(64)
    res = F.analyze("thing.bin", data, client=client, profile=profile(["api.github.com"]))
    assert res.online_used is True
    sources = [c.source for c in res.candidates]
    assert "magic" in sources and "codesearch" in sources
    assert sources.index("magic") < sources.index("codesearch")   # offline outranks online


def test_analyze_records_a_client_refusal_without_crashing():
    client = C.PublicCodeSearchClient(enabled=True, transport=fake_transport(ONE_ITEM),
                                      sleep=lambda s: None, clock=lambda: 0.0)
    # The event does not allow the host, so the client refuses; analyze records the reason.
    res = F.analyze("mystery.bin", record_blob(), client=client, profile=profile([]))
    assert res.online_used is True
    assert res.online_error and "public_fetch_allow" in res.online_error


# ---------------------------------------------------------------- the CLI (offline; never --online here)

def _cli_args(**kw):
    import argparse
    base = {"action": "fingerprint", "catalog": None, "files": [], "online": False,
            "event": None, "json": False}
    base.update(kw)
    return argparse.Namespace(**base)


def test_cli_fingerprint_text_reports_the_offline_lead(tmp_path, capsys):
    from ctf.cli import formats as cli
    p = tmp_path / "export.db"
    p.write_bytes(b"SQLite format 3\x00" + bytes(400))
    assert cli.run(_cli_args(files=[p])) == 0
    out = capsys.readouterr().out
    assert "fingerprint" in out and "likely SQLite 3 database" in out


def test_cli_fingerprint_json_carries_the_fingerprint_and_candidates(tmp_path, capsys):
    from ctf.cli import formats as cli
    p = tmp_path / "mystery.bin"
    p.write_bytes(record_blob(records=96, stride=16))
    assert cli.run(_cli_args(files=[p], json=True)) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc[0]["fingerprint"]["stride"] == 16
    assert doc[0]["online_used"] is False


def test_cli_fingerprint_names_a_member_identify_knows(tmp_path, capsys):
    from ctf.cli import formats as cli
    p = tmp_path / "mail.eml"
    p.write_bytes(corpus.build("eml_attachments").data)
    assert cli.run(_cli_args(files=[p])) == 0
    assert "named by identify" in capsys.readouterr().out


def test_cli_fingerprint_online_with_an_unknown_event_exits_2(tmp_path, capsys):
    from ctf.cli import formats as cli
    p = tmp_path / "mystery.bin"
    p.write_bytes(record_blob())
    assert cli.run(_cli_args(files=[p], online=True, event="no-such-event")) == 2
    assert "no-such-event" in capsys.readouterr().err


def test_cli_fingerprint_online_without_event_or_ctf_env_exits_2(tmp_path, capsys, monkeypatch):
    # --online with no --event and no CTF_EVENT must fail fast with a clear message, not silently
    # defer the opt-in to an env var or attempt a search with no policy.
    from ctf.cli import formats as cli
    monkeypatch.delenv("CTF_EVENT", raising=False)
    p = tmp_path / "mystery.bin"
    p.write_bytes(record_blob())
    assert cli.run(_cli_args(files=[p], online=True)) == 2
    assert "needs an event policy" in capsys.readouterr().err


def test_cli_fingerprint_online_without_event_names_ctf_event_fallback(tmp_path, capsys, monkeypatch):
    # With CTF_EVENT set, --online without --event is allowed but says which policy gates it (no silent
    # fallback). The host is not allow-listed by that event, so the search is refused before any request
    # reaches the network; the run still succeeds and records the refusal.
    from ctf.cli import formats as cli
    monkeypatch.setenv("CTF_EVENT", "csctf")
    p = tmp_path / "mystery.bin"
    p.write_bytes(record_blob())
    assert cli.run(_cli_args(files=[p], online=True, json=True)) == 0
    err = capsys.readouterr().err
    assert "uses CTF_EVENT" in err and "csctf" in err


# ---------------------------------------------------------------- search skips one bad magic (not all)

def test_search_skips_a_bad_magic_and_keeps_the_leads_from_the_rest():
    # One secret-shaped magic among good ones must be skipped, not abort the whole search: before the
    # fix, the raise suppressed every lead; now the good magic is still searched.
    t = fake_transport(ONE_ITEM)
    client = C.PublicCodeSearchClient(enabled=True, transport=t, sleep=lambda s: None, clock=lambda: 0.0)
    leads = client.search(["api_key = sk-abcdefghij", "GOODMAGIC"], profile=profile(["api.github.com"]))
    assert len(t.calls) == 1, "only the valid magic reached the provider"
    assert leads and leads[0].label == "acme/secondfloor"
    assert client.request_count == 1
    assert client.skipped and client.skipped[0][0] == "api_key = sk-abcdefghij"
    assert "secret" in client.skipped[0][1]


# ---------------------------------------------------------------- the B-013 sweep auto-calls the step

def test_sweep_fingerprints_members_identify_cannot_name(tmp_path):
    # The sweep must run format_fingerprint on every member identify cannot name `sure`, append the
    # unsure leads to its report (.sweep.json) and a note. A build that does not wire analyze() into the
    # sweep leaves the fingerprint block empty and this fails.
    from ctf import sweep
    src = tmp_path / "drop"
    src.mkdir()
    (src / "export.db").write_bytes(b"SQLite format 3\x00" + bytes(400))   # identify can't name; magic can
    (src / "plain.txt").write_bytes(b"nothing but ascii here")
    rep = sweep.sweep(src, profile(), out=tmp_path / "scratch")
    rows = rep.extra.get("fingerprint", [])
    labels = [c["label"] for row in rows for c in row["candidates"]]
    assert any("SQLite" in label for label in labels), "the unnamed member was fingerprinted offline"
    assert all(row["member"] != "export.db" or row["sha256"] for row in rows)
    doc = json.loads((tmp_path / "scratch" / ".sweep.json").read_text())
    assert any("SQLite" in c["label"] for row in doc["fingerprint"] for c in row["candidates"]), \
        "the leads are written into .sweep.json"
    assert any("format_fingerprint" in n for n in rep.notes), "a human-readable note is added"
