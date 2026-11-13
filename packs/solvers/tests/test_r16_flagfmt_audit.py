"""R-16: the flag-format audit remainder (B-001a's gaps).

1. Cribs: the classical Enigma break and the exotic-codec payload signature took the CSCTF lead as a
   literal; they (and flagscan, cache_analysis, android_depth, mobile_depth) now take the active event's
   leads from ctf.flagfmt, so they work on Pink and Spooky and do not fire on CSCTF text elsewhere.
2. Packed records: text scans keep a left word boundary, so a reader that decodes fixed-width or binary
   records to text and scans with TEXT misses a flag straight after a digit or letter of the previous
   field. The audited readers now scan bytes-derived text with flagfmt.PACKED_TEXT (no left boundary).
3. CSS: the broad shape scans (SHAPE_TEXT, BRACE_TEXT, PAYOFF_OTHER) see `btn{color:red}` under a broad
   body. These tests prove no CSS-shaped match is returned or reported as a flag by any consumer of a
   shape scan, and the inventory test fails when a new consumer appears unaudited.

Every fixture is synthetic and built here.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import struct
import sys
from pathlib import Path

import pytest

from ctf import event, flagfmt
from ctf.platform import policy

REPO = Path(__file__).resolve().parents[1]


def _load(name, rel):
    """Load a module by path under a test-only name (classical/modern_crypto exist in two lanes)."""
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod                    # dataclasses resolve their module through sys.modules
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def ev(monkeypatch):
    def use(slug):
        monkeypatch.setenv("CTF_EVENT", slug)
    return use


def _unknown_format_profile():
    return event.parse({
        "slug": "r16-unknown", "name": "unknown format",
        "dates": {"start": event._dt.date(2026, 1, 1), "end": event._dt.date(2026, 1, 2)},
        "platform": {"kind": "manual"}, "flag": {"prefixes": []},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed"},
    }, src="test")


@pytest.fixture
def unknown_format(monkeypatch):
    """The active event resolves to a profile whose flag prefixes are not known yet."""
    ff = flagfmt.for_profile(_unknown_format_profile())
    monkeypatch.setattr(flagfmt, "current", lambda: ff)
    return ff


# ===================================================================================== ctf.flagfmt additions
@pytest.mark.parametrize("slug,want", [
    ("csctf", ("CSCTF{", "chronos{", "CTF{", "flag{")),
    ("pink", ("PINK{",)),
    ("spooky", ("spooky{",)),
    ("huntress", ("flag{",)),
])
def test_cribs_are_the_event_prefixes_in_profile_order(ev, slug, want):
    ev(slug)
    assert flagfmt.cribs() == want
    assert flagfmt.cribs(event.load(slug)) == want


def test_cribs_fail_loudly_without_a_known_prefix():
    with pytest.raises(LookupError, match="no known prefix"):
        flagfmt.cribs(_unknown_format_profile())


def test_packed_text_drops_only_the_left_boundary(ev):
    ev("pink")
    packed = "HDR0042PINK{fixed_width}TRAILER"
    assert flagfmt.TEXT.findall(packed) == []                      # the text rule: boundary kept
    assert flagfmt.PACKED_TEXT.findall(packed) == ["PINK{fixed_width}"]
    assert flagfmt.find_flags_packed(packed) == ["PINK{fixed_width}"]
    assert flagfmt.find_flags_packed(packed.encode()) == ["PINK{fixed_width}"]
    assert flagfmt.PACKED_TEXT.findall("0042pink{x}") == []         # Pink is exact case: still exact
    assert flagfmt.PACKED_TEXT.findall("0042PINK{a{b}") == []       # Pink's body still refuses '{'
    ev("csctf")
    assert flagfmt.PACKED_TEXT.findall("99csctf{x}") == ["csctf{x}"]   # prefix-insensitive kept


def test_lead_regexes_follow_the_event_and_its_case_rule(ev):
    ev("pink")
    assert flagfmt.LEAD_BYTES.match(b"PINK{\x00\xff")
    assert not flagfmt.LEAD_BYTES.match(b"pink{\x00")
    assert not flagfmt.LEAD_BYTES.match(b"CSCTF{\x00")
    assert flagfmt.LEAD_TEXT.search("xxPINK{")                      # no left boundary
    ev("spooky")
    assert flagfmt.LEAD_TEXT.match("SPOOKY{")                       # prefix-insensitive
    ev("csctf")
    assert [bool(flagfmt.LEAD_TEXT.match(s)) for s in ("Chronos{", "ctf{", "PINK{", "CSCTF")] == \
        [True, True, False, False]


CSS_RULES = [
    "btn{color:red}",
    "body{margin:0;padding:0}",
    "body{margin:0;padding:0;}",
    "btn{color:red;}",                  # one declaration plus a trailing ';' (round 2 survivor)
    "card{ background : url(data:image/png,AAAA) }",
    "root{--gap: 4px !important}",
    "screen{.nav{color:#fff}",
    "x{-webkit-transition:none}",
    "x{COLOR:Red}",
    "x{z-index:9;--brand-blue:#00f}",
]
NOT_CSS = ["PINK{c0l0r_red}", "picoCTF{some_flag_here}", "CSCTF{a b c}", "flag{0123456789abcdef}",
           "x{a:}", "plain text", "x{:red}",
           # every declaration must be CSS, not just one (all, not any)
           "x{a:b;hello world}", "btn{color:red;not a decl here}",
           # the property must be a CSS property name: a foreign flag with a colon is not CSS
           "flag{http://x}", "x{note: see below}", "picoCTF{key:value}", "x{webkit-color:red}"]


@pytest.mark.parametrize("token", CSS_RULES)
def test_css_like_recognises_css_rules(token):
    assert flagfmt.css_like(token)


@pytest.mark.parametrize("token", NOT_CSS)
def test_css_like_leaves_flags_and_non_rules_alone(token):
    assert not flagfmt.css_like(token)


# Current properties (round 2): before they were in CSS_PROPERTIES these read as not CSS, so a style
# rule that used them was reportable as a flag under a broad-body event.
MODERN_CSS_RULES = ["a{text-wrap:balance}", "a{inset-area:top}", "a{position-area:top span-all}",
                    "tip{anchor-name:--tip}", "in{field-sizing:content}",
                    "h{text-wrap-style:pretty;white-space-collapse:preserve}",
                    "v{view-transition-name:hero}", "s{animation-timeline:scroll()}"]


@pytest.mark.parametrize("token", MODERN_CSS_RULES)
def test_current_css_properties_are_css_and_never_reported(ev, token):
    ev("csctf")
    assert flagfmt.css_like(token)
    assert not flagfmt.shape_reportable(token)


def test_single_letter_svg_geometry_is_not_taken_as_css():
    # `x`, `y`, `r` are SVG presentation properties, left out of the allowlist on purpose: a short
    # foreign flag like `x{y:1}` must not be dropped from the report channels.
    assert not flagfmt.css_like("x{y:1}")
    assert not flagfmt.css_like("c{r:5}")


def test_shape_reportable_keeps_the_event_format_and_drops_css(ev):
    ev("csctf")
    assert not flagfmt.shape_reportable("btn{color:red}")
    assert not flagfmt.shape_reportable("btn{color:red;}")
    assert flagfmt.shape_reportable("picoCTF{foreign_but_not_css}")
    # The event's own format wins: `.flag{display:none}` is a format-valid CSCTF flag (prefix `flag`),
    # so it stays reportable and the player/gate decides (see the R-16 build log).
    assert flagfmt.shape_reportable("flag{display:none}")
    ev("huntress")
    assert flagfmt.shape_reportable("proof_" + "a" * 32)
    assert not flagfmt.shape_reportable("btn{color:red}")


def _profile(flag, proof=None):
    raw = {"slug": "r16-custom", "name": "custom",
           "dates": {"start": event._dt.date(2026, 1, 1), "end": event._dt.date(2026, 1, 2)},
           "platform": {"kind": "manual"}, "flag": flag,
           "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed"}}
    if proof:
        raw["proof"] = proof
    return event.parse(raw, src="test")


def test_shape_reportable_keeps_a_css_shaped_proof_of_the_event():
    prof = _profile({"prefixes": ["NOPE"]}, {"pattern": r"key\{[a-z]+:[a-z]+\}"})
    assert flagfmt.css_like("key{color:def}")
    assert flagfmt.shape_reportable("key{color:def}", prof)
    assert not flagfmt.shape_reportable("btn{color:red}", prof)


def test_packed_and_lead_forms_honour_a_wholly_insensitive_format():
    ff = flagfmt.for_profile(_profile({"prefixes": ["abc"], "body": "[a-z]{1,8}", "case": "insensitive"}))
    assert ff.packed_regex.findall("00ABC{XYZ}") == ["ABC{XYZ}"]
    assert ff.lead_regex.match("AbC{") and ff.lead_bregex.match(b"ABC{")
    exact = flagfmt.for_profile(_profile({"prefixes": ["abc"], "body": "[a-z]{1,8}", "case": "exact"}))
    assert exact.packed_regex.findall("00ABC{xyz}") == [] and not exact.lead_regex.match("ABC{")


# ===================================================================================== cribs
classical = _load("r16_classical", "solvers/common/classical.py")
WHEELS = ("II", "III", "V")


def _enigma(pt):
    return classical.enigma(pt, rotors=("II", "V", "III"), reflector="B", rings="AAA", start="KDB")


@pytest.mark.parametrize("slug,plain,crib", [
    ("pink", "PINKTHEENIGMAKEYROTATESATDAWNHOLDTHEGRIDDEFENDTOTALWARFARE", "PINK{"),
    ("spooky", "SPOOKYTHEENIGMAKEYROTATESATDAWNHOLDTHEGRIDDEFENDTOTALWARFARE", "spooky{"),
    # a CSCTF flag in one of its other prefixes: every lead is tried, the best reading kept
    ("csctf", "CHRONOSTHEENIGMAKEYROTATESATDAWNHOLDTHEGRIDDEFENDTOTALWARFARE", "chronos{"),
    # CSCTF's lead CTF{ has exactly three letters: still a usable crib
    ("csctf", "CTFTHEENIGMAKEYROTATESATDAWNHOLDTHEGRIDDEFENDTOTALWARFARE", "CTF{"),
])
def test_enigma_default_crib_is_the_events_flag_lead(ev, slug, plain, crib):
    ev(slug)
    res = classical.enigma_crib_break(_enigma(plain), rotor_set=WHEELS, workers=1)
    assert res is not None and res["plaintext"] == plain
    assert res["crib"] == crib
    assert (res["rotors"], res["start"]) == (("II", "V", "III"), "KDB")


def test_enigma_explicit_crib_is_used_as_given(ev):
    ev("pink")              # the event's lead is not in this message; the stated crib is
    plain = "CSCTFTHEENIGMAKEYROTATESATDAWNHOLDTHEGRIDDEFENDTOTALWARFARE"
    res = classical.enigma_crib_break(_enigma(plain), crib="CSCTF", rotor_set=WHEELS, workers=1)
    assert res["plaintext"] == plain and res["crib"] == "CSCTF"


def test_enigma_without_a_known_prefix_fails_loudly(unknown_format):
    with pytest.raises(LookupError, match="no known prefix"):
        classical.enigma_crib_break(_enigma("ABCDEFGHIJKLMNOP"), rotor_set=WHEELS, workers=1)


def test_enigma_refuses_when_no_lead_has_three_letters(monkeypatch):
    prof = event.parse({
        "slug": "r16-short", "name": "short prefix",
        "dates": {"start": event._dt.date(2026, 1, 1), "end": event._dt.date(2026, 1, 2)},
        "platform": {"kind": "manual"}, "flag": {"prefixes": ["ab"]},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed"},
    }, src="test")
    ff = flagfmt.for_profile(prof)
    monkeypatch.setattr(flagfmt, "current", lambda: ff)
    with pytest.raises(ValueError, match="three letters"):
        classical.enigma_crib_break(_enigma("ABCDEFGHIJKLMNOP"), rotor_set=WHEELS, workers=1)


codecs = _load("r16_exotic_codecs", "solvers/warmups/exotic_codecs.py")


def _dna(payload: bytes) -> str:
    return "".join("ACGT"[(byte >> shift) & 3] for byte in payload for shift in (6, 4, 2, 0))


def test_exotic_payload_signature_is_the_events_flag_lead(ev):
    # Not printable after the lead, so only the flag-lead signature can accept these payloads.
    pink, csctf = b"PINK{\x00\x01\x02", b"csctf{\x00\x01\x02"
    ev("pink")
    assert codecs.decode_dna_2bit(_dna(pink)).payload == pink
    assert codecs.decode_dna_2bit(_dna(csctf)) is None
    assert codecs.decode_dna_2bit(_dna(b"pink{\x00\x01\x02")) is None     # Pink is exact case
    ev("csctf")
    assert codecs.decode_dna_2bit(_dna(csctf)).payload == csctf         # prefix-insensitive
    assert codecs.decode_dna_2bit(_dna(pink)) is None
    assert codecs.decode_dna_2bit(_dna(b"\x89PNG\r\n\x1a\n")) is not None  # file magics unchanged


flagscan = _load("r16_flagscan", "solvers/toolkits/flagscan.py")


def test_flagscan_loose_substring_is_the_events_own_prefix(ev, tmp_path):
    data = tmp_path / "rows.txt"
    data.write_text("1,alice,PINK_bare_value\n2,bob,CSCTF_bare_value\n3,carol,nothing\n")
    ev("pink")
    assert flagscan.default_substr() == "PINK"
    assert [h.value for h in flagscan.scan_path(str(data))] == ["1,alice,PINK_bare_value"]
    ev("csctf")
    assert flagscan.default_substr() == "CSCTF"
    assert [h.value for h in flagscan.scan_path(str(data))] == ["2,bob,CSCTF_bare_value"]


def test_flagscan_without_a_known_prefix_has_no_loose_substring(unknown_format, tmp_path):
    data = tmp_path / "rows.txt"
    data.write_text("1,alice,CSCTF_bare_value\n2,bob,word{braced}\n")
    assert flagscan.default_substr() is None
    assert [h.value for h in flagscan.scan_path(str(data))] == ["2,bob,word{braced}"]


cache = _load("r16_cache_analysis", "solvers/web/cache_analysis.py")


def test_cache_deception_counts_the_events_flag_as_personalised(ev):
    request = b"GET /static/app.css HTTP/1.1\r\nHost: app.test\r\n\r\n"
    response = (b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=60\r\nContent-Type: text/css\r\n\r\n"
                b"/* PINK{cached_secret} */")
    ev("pink")
    found = [f for f in cache.analyze_cache_deception(request, response)
             if f.finding_id == "static-key-personalised-response"]
    assert found and any("PINK{" in item for item in found[0].evidence)
    ev("csctf")
    assert not [f for f in cache.analyze_cache_deception(request, response)
                if f.finding_id == "static-key-personalised-response"]


def test_cache_sensitive_matches_keep_body_order(ev):
    ev("pink")
    assert cache._sensitive_matches("PINK{a} then admin then email") == ("PINK{", "admin", "email")


android = _load("r16_android_depth", "solvers/toolkits/android_depth.py")
mobile = _load("r16_mobile_depth", "solvers/mobile-android/mobile_depth.py")


def test_android_interesting_strings_take_the_events_flag_lead(ev):
    blob = b"\x00\x00PINK{apk_string}\x00\x00plain words only\x00"
    ev("pink")
    assert [s["value"] for s in android._interesting_strings(blob)] == ["PINK{apk_string}"]
    ev("csctf")
    assert android._interesting_strings(blob) == []


def test_android_il2cpp_identifier_leads_take_the_events_flag_lead(ev):
    heap = b"\x00PINK{il2cpp_id}\x00OrdinaryName\x00"
    data = b"\xaf\x1b\xb1\xfa" + struct.pack("<I", 29) + struct.pack("<6I", 32, 0, 32, 0, 32, len(heap)) + heap
    ev("pink")
    assert [x["value"] for x in android.parse_il2cpp_metadata(data)["identifier_leads"]] == ["PINK{il2cpp_id}"]
    ev("csctf")
    assert android.parse_il2cpp_metadata(data)["identifier_leads"] == []


def test_android_every_lead_check_goes_through_the_event_aware_helper():
    """The four lead checks (APK strings, #Strings, #US, IL2CPP) share _is_lead; a bare _LEAD.search
    anywhere else would miss the event's flag lead again."""
    tree = ast.parse((REPO / "solvers/toolkits/android_depth.py").read_text(encoding="utf-8"))
    bare = [n.lineno for f in ast.walk(tree) if isinstance(f, ast.FunctionDef) and f.name != "_is_lead"
            for n in ast.walk(f) if isinstance(n, ast.Attribute) and n.attr == "search"
            and isinstance(n.value, ast.Name) and n.value.id == "_LEAD"]
    helper_calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                    and isinstance(n.func, ast.Name) and n.func.id == "_is_lead"]
    assert bare == [] and len(helper_calls) == 4


def test_mobile_bundle_strings_rank_the_events_flag_lead_first(ev):
    blob = b"\x00spooky{bundle}\x00\x00api_key=abc123\x00\x00chronos{other}\x00"
    ev("spooky")
    got = {item["value"]: item["score"] for item in mobile._interesting_strings(blob, "a.js")}
    assert got == {"spooky{bundle}": 100, "api_key=abc123": 75}
    ev("csctf")
    got = {item["value"]: item["score"] for item in mobile._interesting_strings(blob, "a.js")}
    assert got == {"chronos{other}": 100, "api_key=abc123": 75}


def test_no_hard_coded_event_flag_lead_is_left_in_code():
    """No string literal (outside docstrings) in solvers/, tools/ or ctf/ spells an event-named flag
    lead (`CSCTF{`, `PINK\\{`, ...) or is exactly an event prefix used as a crib. The few left are
    markers, a wordlist entry, the migration tool and one self-test, each listed with its reason."""
    lead = __import__("re").compile(r"(?i)(?<![A-Za-z0-9_])(?:csctf|chronos|pink|spooky)\\?\{")
    whole = {"csctf", "chronos", "pink", "spooky"}
    allowed = {
        "solvers/toolkits/web_exploit.py",     # 'csctf' echo and PHAR markers, not flag cribs
        "solvers/web/exploit_classes.py",      # 'chronos' in a JWT secret wordlist
        "solvers/toolkits/web_xxe_ssrf.py",    # its __main__ self-test sample flag
        "tools/alert.py",                      # the alert TITLE (a B-001a gap, cosmetic)
        "tools/migrate/import_master.py",      # the importer names the source events by design
    }
    offenders = []
    for path in sorted(p for d in ("solvers", "tools", "ctf") for p in (REPO / d).rglob("*.py")):
        rel = path.relative_to(REPO).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docs = {id(n.body[0].value) for n in ast.walk(tree)
                if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and n.body and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)) and id(node) not in docs:
                v = node.value.decode("latin-1") if isinstance(node.value, bytes) else node.value
                if (lead.search(v) or v.strip().lower() in whole) and rel not in allowed:
                    offenders.append(f"{rel}:{node.lineno}: {v[:60]!r}")
    assert offenders == []


def test_the_lead_scan_detects_an_offender():
    """The scan above is only evidence if it can fail: run its two rules on planted literals."""
    lead = __import__("re").compile(r"(?i)(?<![A-Za-z0-9_])(?:csctf|chronos|pink|spooky)\\?\{")
    assert lead.search(r"(?i)(?:CSCTF\{|x)") and lead.search("PINK{") and lead.search(b"spooky{".decode())
    assert not lead.search("XCSCTF{") and not lead.search("CSCTF_MARKER")
    assert "CSCTF".strip().lower() in {"csctf", "chronos", "pink", "spooky"}


# ===================================================================================== packed readers
def _crc16_ibm3740(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ (0x1021 if crc & 0x8000 else 0)) & 0xFFFF
    return crc


def _ishne(first: bytes, last: bytes, comments: bytes = b"none\x00") -> bytes:
    """ISHNE 1.0 header in the published field order (as tests/test_health2_ishne.py builds it)."""
    block = struct.pack("<4ih", len(comments), 4, 522, 522 + len(comments), 1)
    block += first.ljust(40, b"\0") + last.ljust(40, b"\0") + b"P001".ljust(20, b"\0")
    block += struct.pack("<2h", 2, 0)
    block += struct.pack("<12h", 10, 12, 1815, 5, 11, 2026, 5, 11, 2026, 12, 30, 45)
    block += struct.pack("<h", 2)
    block += struct.pack("<12h", 5, 6, *([-9] * 10))
    block += struct.pack("<12h", 1, 1, *([-9] * 10))
    block += struct.pack("<12h", 1000, 2500, *([-9] * 10))
    block += struct.pack("<h", 0) + b"digital".ljust(40, b"\0") + struct.pack("<h", 500)
    block += b"proprietary".ljust(80, b"\0") + b"copyright".ljust(80, b"\0") + bytes(88)
    assert len(block) == 512
    block += comments
    return b"ISHNE1.0" + _crc16_ibm3740(block).to_bytes(2, "little") + block + bytes.fromhex(
        "00006400 ffff9cff ff7f0080 07000900")


def test_ishne_flag_in_a_field_after_a_full_width_field(ev):
    ev("pink")
    import health2_ishne
    raw = _ishne(b"A" * 40, b"PINK{ishne_fixed_width}")    # first name fills its 40 bytes: no NUL
    assert health2_ishne.parse_ishne(raw)["flags"] == ["PINK{ishne_fixed_width}"]


def _scp_section(sid, payload):
    payload += bytes(len(payload) % 2)
    body = struct.pack("<HIBB6s", sid, 16 + len(payload), 20, 20, b"SCPECG" if sid == 0 else bytes(6)) + payload
    return struct.pack("<H", _crc16_ibm3740(body)) + body


def _scp(patient: bytes) -> bytes:
    """SCP-ECG record with sections 1, 3, 6 (as tests/test_health2_scp.py builds it)."""
    payloads = {1: patient, 3: b"\x02\x00" + struct.pack("<IIBIIB", 1, 5, 1, 3, 5, 2),
                6: struct.pack("<HHBBHH8h", 1000, 2000, 0, 0, 10, 6, 10, 12, 15, 19, 24, -5, -3, -4)}
    sections = {sid: _scp_section(sid, p) for sid, p in payloads.items()}
    next_offset, pointers = 6 + 136, struct.pack("<HII", 0, 136, 7)
    for sid in range(1, 12):
        value = sections.get(sid)
        if value is None:
            pointers += struct.pack("<HII", sid, 0, 0)
        else:
            pointers += struct.pack("<HII", sid, len(value), next_offset + 1)
            next_offset += len(value)
    body = _scp_section(0, pointers) + b"".join(sections[sid] for sid in sorted(sections))
    body = struct.pack("<I", len(body) + 6) + body
    return struct.pack("<H", _crc16_ibm3740(body)) + body


def test_scp_flag_glued_to_a_binary_field(ev):
    ev("pink")
    import health2_scp
    value = b"P0001PINK{scp_packed}\x00"
    patient = struct.pack("<BH", 2, len(value)) + value + b"\xff\x00\x00"
    assert health2_scp.parse_scp(_scp(patient))["flags"] == ["PINK{scp_packed}"]


def test_mil1553_flag_after_a_letter_in_packed_data_words(ev):
    ev("pink")
    import defense_mil1553 as m
    raw = b"AB7PINK{1553}"
    raw += bytes(len(raw) % 2)
    words = [int.from_bytes(raw[i:i + 2], "big") for i in range(0, len(raw), 2)]
    command = int(f"{5:05b}{0:01b}{7:05b}{len(words):05b}", 2)
    status = int(f"{5:05b}" + "0" * 11, 2)
    assert m.decode_transfer([command] + words + [status])["flags"] == ["PINK{1553}"]


def _bytes_helpers():
    import financial, healthcare, ics_fieldbus, ics_scada, pwn_exploit, telecom, transport
    return {
        "transport.find_flags": lambda data: sorted(transport.find_flags(data)),     # returns a set
        "healthcare.find_flags": healthcare.find_flags,
        "financial.find_flags": financial.find_flags,
        "ics_fieldbus._scan_flags": ics_fieldbus._scan_flags,
        "ics_scada._flags_in": ics_scada._flags_in,
        "telecom._flags_in": telecom._flags_in,
        "pwn_exploit.find_flags": pwn_exploit.find_flags,
    }


@pytest.mark.parametrize("name", sorted(_bytes_helpers()))
def test_bytes_helpers_scan_binary_fields_without_a_word_boundary(ev, name):
    fn = _bytes_helpers()[name]
    ev("pink")
    assert fn(b"\x00\x10SN42PINK{packed_field}\x00rest") == ["PINK{packed_field}"]
    assert fn(b"\x00SN42pink{wrong_case}\x00") == []            # the event's case rule still holds
    ev("csctf")
    assert fn(b"\x01\x02ID9CSCTF{binary_tail}") == ["CSCTF{binary_tail}"]


@pytest.mark.parametrize("name", sorted(n for n in _bytes_helpers() if n != "pwn_exploit.find_flags"))
def test_bytes_helpers_keep_the_word_boundary_for_text(ev, name):
    fn = _bytes_helpers()[name]
    ev("pink")
    assert fn("SN42PINK{in_prose}") == []
    assert fn("see PINK{in_prose}") == ["PINK{in_prose}"]


def test_emv_track_discretionary_data_carries_a_flag_after_digits(ev):
    """EMV tag 57/56 values are bytes: a flag in Track-1 discretionary data follows the expiry and
    service-code digits with no separator."""
    ev("pink")
    import financial
    track1 = b"B4111111111111111^DOE/JOHN^2512101PINK{emv_track}"
    pan = bytes.fromhex("4111111111111111")
    inner = b"\x5a" + bytes([len(pan)]) + pan + b"\x56" + bytes([len(track1)]) + track1
    blob = b"\x70" + bytes([len(inner)]) + inner
    res = financial.parse_emv(blob)
    assert res is not None and "PINK{emv_track}" in res["flags"]


def _xor(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def test_xor_strings_finds_a_flag_glued_to_the_previous_field(ev):
    """Runs carved from single-byte-XOR binary are binary fields: no word boundary before the flag."""
    import xor_strings
    ev("pink")
    blob = _xor(b"SN42PINK{xor_packed}", 0x5A)
    assert [d["text"] for d in xor_strings.flag_candidates(blob)] == ["SN42PINK{xor_packed}"]
    assert xor_strings.flag_candidates(_xor(b"SN42pink{wrong_case}", 0x5A)) == []   # Pink is exact case
    # the flag-holding run ranks first, ahead of a longer plain run under the same key
    longer = _xor(b"a much longer run of plain text than the flag", 0x5A)
    rows = xor_strings.xor_strings(blob + _xor(b"\x00", 0x5A) + longer, min_len=4)
    assert rows[0]["text"] == "SN42PINK{xor_packed}"
    ev("csctf")
    assert [d["text"] for d in xor_strings.flag_candidates(_xor(b"ID9CSCTF{xor_tail}", 0x21))] == \
        ["ID9CSCTF{xor_tail}"]


def test_audio_tone_codes_carry_a_flag_after_a_stray_code(ev):
    """audio_tones candidates are bytes decoded from tone codes (or two streams XORed)."""
    import audio_tones
    ev("pink")
    xored = (b"\x13Q7" + b"PINK{tones_xor}").decode("latin-1")
    res = {"candidates": [("xor(codes)", xored)], "streams": [{"text": "zzPINK{stream_text}"}]}
    assert audio_tones.find_flags(res) == ["PINK{tones_xor}", "PINK{stream_text}"]
    assert audio_tones.find_flags({"candidates": [("linear", "Q7pink{x}")]}) == []   # exact case kept


def test_nativeaot_string_rank_sees_a_flag_glued_to_the_previous_field(ev):
    import redepth_nativeaot as na
    ev("pink")
    glued, plain = na._string_score("SN42PINK{nat}"), na._string_score("SN42PINKxnatx")
    assert glued - plain >= 1000                     # the flag bonus applies with no boundary before it
    assert na._string_score("SN42pink{nat}") < 1000  # the case rule still holds


# ===================================================================================== CSS never a flag
CSS_PAGE = "<style>.btn{color:red} body{margin:0;padding:0} .nav a{color:#fff}</style><p>ok</p>"
CSS_TOKENS = ("btn{color:red}", "body{margin:0;padding:0}", "a{color:#fff}")
SHAPE_NAMES = {"SHAPE_TEXT", "SHAPE_BYTES", "shape", "PAYOFF_OTHER", "BRACE_TEXT"}

# Every module that consumes a broad shape scan, and how its CSS matches are contained. A new
# consumer fails test_shape_scan_consumers_are_all_audited until it is added here WITH a test below.
SHAPE_CONSUMERS = {
    "solvers/web/forge_event.py": "seen/decoy/candidates; auto is PAYOFF_TEXT only",
    "solvers/web/post_chain.py": "seen/candidates; auto is PAYOFF_TEXT only",
    "solvers/web/graphql_read.py": "ambiguity/candidates; auto is PAYOFF_TEXT only",
    "solvers/web/ssrf_body.py": "candidate filter; its answer is forge_event's auto",
    "solvers/web/recon_triage.py": "'generic' surfacing drops CSS; best_proof returns exact only",
    "solvers/web/post_exploit.py": "PLAYER FLAG lines drop CSS; proof is PAYOFF_TEXT only",
    "solvers/web/web_patch.py": "the flags channel drops CSS; answers are proofs",
    "solvers/toolkits/modern_crypto.py": "flag answer forms drop CSS (_FLAG_FORM); _FLAG is seen-only",
    "solvers/warmups/numsym.py": "search gate only (_looks_flag drops CSS); the answer is crib_decode's TEXT",
}


def _shape_users():
    users = set()
    for path in sorted(p for d in ("solvers", "tools", "ctf") for p in (REPO / d).rglob("*.py")):
        rel = path.relative_to(REPO).as_posix()
        if rel == "ctf/flagfmt.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Attribute) and node.attr in SHAPE_NAMES
                    and isinstance(node.value, ast.Name) and node.value.id == "flagfmt"):
                users.add(rel)
            elif isinstance(node, ast.ImportFrom) and (node.module or "").endswith("flagfmt") \
                    and any(a.name in SHAPE_NAMES for a in node.names):
                users.add(rel)
    return users


def test_shape_scan_consumers_are_all_audited():
    assert _shape_users() == set(SHAPE_CONSUMERS)


# Modules that hand-roll their own broad `name{...}` regex (not from flagfmt), and how CSS is kept out
# of what they report. A new one fails test_hand_rolled_brace_shapes_are_all_audited until it is added
# here WITH a test below.
HAND_ROLLED_SHAPES = {
    "solvers/toolkits/windows.py": "findings() flags (the lone-flag answer) drop CSS via shape_reportable",
    "solvers/toolkits/network.py": "_flags_in drops CSS via shape_reportable",
}
_CSS_PROBE = ("x btn{color:red} y", "btn{color:red}")


def _hand_rolled_brace_regexes(source: str) -> list[int]:
    """Lines of the string literals in `source` that compile to a regex which, searching
    'x btn{color:red} y', matches exactly the token `btn{color:red}` and spells an escaped brace:
    a hand-rolled any-prefix flag shape."""
    import re
    import warnings
    lines = []
    for node in ast.walk(ast.parse(source)):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))):
            continue
        lit = node.value
        text = lit if isinstance(lit, str) else lit.decode("latin-1")
        if "\\{" not in text:
            continue
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                rx = re.compile(lit)
        except (re.error, ValueError, OverflowError):
            continue
        probe, token = _CSS_PROBE if isinstance(lit, str) else (s.encode() for s in _CSS_PROBE)
        m = rx.search(probe)
        if m is not None and m.group(0) == token:
            lines.append(node.lineno)
    return lines


def test_hand_rolled_brace_shapes_are_all_audited():
    users = set()
    for path in sorted(p for d in ("solvers", "tools", "ctf") for p in (REPO / d).rglob("*.py")):
        rel = path.relative_to(REPO).as_posix()
        if rel != "ctf/flagfmt.py" and _hand_rolled_brace_regexes(path.read_text(encoding="utf-8")):
            users.add(rel)
    assert users == set(HAND_ROLLED_SHAPES)


def test_the_hand_rolled_scan_detects_an_offender():
    o, c = "\\" + "{", "\\" + "}"     # split so this file's own literals are not a brace regex
    src = (f'import re\nA = re.compile(r"[A-Za-z0-9_]{{2,16}}{o}[^{{}}\\s]{{1,200}}{c}")\n'
           f'B = re.compile(rb"\\w+{o}[^}}]+{c}")\nC = r"{o}[^{{}}]+{c}"\nD = r"[a-z]+"\n')
    assert _hand_rolled_brace_regexes(src) == [2, 3]


def _win_events(*values):
    import types
    return types.SimpleNamespace(kind="event_json", file="sec.json", slack=[], events=[
        {"id": 4688 + i, "time": None, "data": {"Msg": v}} for i, v in enumerate(values)])


def test_windows_findings_never_report_css_as_the_flag(ev):
    ev("csctf")
    import windows
    css = "<style>.btn{color:red} body{margin:0;padding:0}</style> rendered"
    q = "What is the flag?"
    assert windows.findings([_win_events(css)])["flags"] == []
    assert windows._q_special(q, [_win_events(css)]) == []          # no lone 'flag' made of CSS
    # beside the CSS, a real foreign flag is the lone flag answer (CSS no longer makes it ambiguous)
    hits = windows._q_special(q, [_win_events(css, "note picoCTF{win_flag} end")])
    assert [(h.key, h.value) for h in hits] == [("label/flag.only", ["picoCTF{win_flag}"])]
    # a non-CSS colon body is still a flag finding
    assert [f["flag"] for f in windows.findings([_win_events("see flag{http://x} now")])["flags"]] == \
        ["flag{http://x}"]


def test_network_blob_flags_never_include_css(ev):
    ev("csctf")
    import network
    assert network._flags_in(b"<style>.btn{color:red}</style>") == []
    assert network._flags_in(b"<style>.btn{color:red}</style> picoCTF{net_x}") == ["picoCTF{net_x}"]
    # a colon body that is not CSS is still reported
    assert network._flags_in(b"<style>.btn{color:red}</style> picoCTF{key:value}") == ["picoCTF{key:value}"]
    # a format-valid event flag is kept even when it reads as CSS (the gate and the player decide)
    assert network._flags_in(b".flag{display:none}") == ["flag{display:none}"]


@pytest.mark.parametrize("slug", ["csctf", "pink", "spooky", "huntress"])
def test_css_is_seen_by_the_broad_scans_but_never_in_the_event_format(ev, slug):
    ev(slug)
    shape_seen = {m.group(0) for m in flagfmt.SHAPE_TEXT.finditer(CSS_PAGE)} | \
                 {m.group(0) for m in flagfmt.BRACE_TEXT.finditer(CSS_PAGE)}
    if slug != "huntress":           # Huntress's body is 32 hex: its SHAPE_TEXT cannot see CSS
        assert set(CSS_TOKENS) <= shape_seen
    assert set(CSS_TOKENS) <= {m.group(0) for m in flagfmt.PAYOFF_OTHER.finditer(CSS_PAGE)}
    assert flagfmt.TEXT.findall(CSS_PAGE) == [] and flagfmt.PAYOFF_TEXT.findall(CSS_PAGE) == []
    assert not any(flagfmt.shape_reportable(t) for t in CSS_TOKENS)
    prof = event.load(slug)
    for token in CSS_TOKENS:
        req = policy.SubmitRequest(challenge_id="1", flag=token, provenance="r16 test")
        reason = policy.base_checks(prof, req)
        assert reason is not None and ("flag format" in reason or "manual" in reason)


def _payoff(body):
    return {"status": 200, "body": json.dumps(body).encode(),
            "response_headers": {"Content-Type": "application/json"}}


def test_web_readers_never_return_css_as_the_payoff(ev):
    ev("csctf")
    import forge_event as forge, graphql_read as graphql, post_chain as post
    flag = "CSCTF{real_payoff}"
    for body in ({"success": True, "html": CSS_PAGE}, {"success": True, "flag": flag, "html": CSS_PAGE}):
        rows = {
            "forge": forge.extract_success(_payoff(body), [], host="target.test"),
            "post": post.extract_anchored(_payoff(body), [], anchored=True, host="target.test"),
            "graphql": graphql._result_evidence(body, [], host="target.test"),
        }
        for name, row in rows.items():
            assert row.get("auto") in (None, flag), (name, row)
            assert not set(CSS_TOKENS) & set(row.get("wire") or []), (name, row)
    # The harness can return: the same readers return a lone flag.
    assert forge.extract_success(_payoff({"success": True, "flag": flag}), [], host="target.test")["auto"] == flag
    assert post.extract_anchored(_payoff({"success": True, "flag": flag}), [], anchored=True,
                                 host="target.test")["auto"] == flag


def test_recon_triage_never_surfaces_css(ev):
    ev("csctf")
    import recon_triage
    assert recon_triage.extract_proof(CSS_PAGE) == []
    assert recon_triage.best_proof([CSS_PAGE]) is None
    assert recon_triage.extract_proof(CSS_PAGE + " picoCTF{foreign}") == [("picoCTF{foreign}", "generic")]


def test_numsym_gate_never_fires_on_css(ev):
    """B-094: numsym's readers fire only on a BRACE_TEXT-shaped decode. A decode that is a style rule
    must not fire one (no search step for that reading, no FLAG-SHAPED mark); a foreign flag in the
    same place does."""
    ev("csctf")
    import numsym

    def codes(text):
        return " ".join(str(ord(c)) for c in text).encode()

    assert not numsym._looks_flag(CSS_PAGE)
    for token in CSS_TOKENS:
        assert not numsym._looks_flag(token), token
        got = numsym.steps(codes(token))          # the plain reading of this list IS the style rule
        assert "numascii:fwd,all+0" not in [name for name, _ in got], token
        assert token.encode() not in [raw for _, raw in got], token
    assert ("numascii:fwd,all+0", b"picoCTF{num_x}") in numsym.steps(codes("picoCTF{num_x}"))
    assert numsym._looks_flag(CSS_PAGE + " picoCTF{num_x}")


def test_web_patch_flags_channel_drops_css(ev):
    ev("csctf")
    import web_patch
    assert web_patch._flags(CSS_PAGE) == []
    assert web_patch._flags(CSS_PAGE + " CourseStack{abc123}") == ["CourseStack{abc123}"]


def test_post_exploit_never_reports_css_as_a_player_flag(ev):
    ev("csctf")
    import post_exploit as PE

    class App:
        def __init__(self, reply):
            self.reply = reply

        def request(self, method, path, data=None, headers=None, allow_redirects=True):
            body = "<form method=post></form>" if method == "GET" else json.dumps(self.reply)
            return {"status": 200, "body": body.encode(),
                    "response_headers": {"Content-Type": "text/html", "X-Theme": "card{color:blue}"},
                    "final_url": "http://fake.local" + path}

    hints = {"cls": "state_change", "state_path": "/save", "state_fields": {"x": "1"}}
    res = PE.post_exploit(App({"ok": True, "html": CSS_PAGE}), hints)
    assert res["proof"] is None
    flag_lines = [line for line in res["evidence"] if line.startswith(PE.FLAG_NOTE + " ")]
    # body CSS goes through scan(), the header's through scan_ambient(): neither reports it
    assert not any(token in line for line in flag_lines for token in CSS_TOKENS + ("card{color:blue}",)), \
        flag_lines
    # The filter is targeted: a non-CSS foreign flag beside the CSS is still reported for the player.
    res = PE.post_exploit(App({"ok": True, "html": CSS_PAGE, "note": "picoCTF{foreign}"}), hints)
    lines = [line for line in res["evidence"] if line.startswith(PE.FLAG_NOTE + " ")]
    assert any("picoCTF{foreign}" in line for line in lines)
    assert not any(token in line for line in lines for token in CSS_TOKENS), lines


mc = _load("r16_modern_crypto", "solvers/toolkits/modern_crypto.py")


def test_modern_crypto_never_offers_css_as_a_flag_answer(ev):
    ev("csctf")
    q = {"question": "What is the decrypted message?"}
    opts = dict(mc._options({"text": "btn{color:red} is the message"}, mc.Proof(q)))
    assert "flag" not in opts and "flag_inner" not in opts
    opts = dict(mc._options({"text": "the key is CSCTF{x} btn{color:red}"}, mc.Proof(q)))
    assert opts["flag"] == "CSCTF{x}" and opts["flag_inner"] == "x"
    # _one_flag also cuts the Shamir secret's flag forms (_shamir_answer)
    assert mc._one_flag("btn{color:red}") is None
    assert mc._one_flag("btn{color:red} then picoCTF{y}") == ("picoCTF{y}", "y")
    assert mc._one_flag("a{1} b{2}") is None                    # two flags: no single flag form
