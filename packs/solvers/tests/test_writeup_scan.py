"""B-098: writeup policy (from the event profile), redaction and the leak scan. Synthetic text only."""
from __future__ import annotations

import datetime as dt

import pytest

from ctf import event
from ctf.writeup import common, policy, scan
from writeup_fixtures import BARE, FLAG, WRONG, profile

UTC = dt.timezone.utc


def kinds(findings, blocking=None):
    return sorted({f.kind for f in findings if blocking is None or f.blocking is blocking})


# ------------------------------------------------------------------------------------------------ policy

def test_forbidden_sharing_with_redaction_off_is_a_profile_error(tmp_path):
    with pytest.raises(event.EventError, match="redact_flags = false contradicts"):
        profile(tmp_path, sharing="forbidden", redact=False)


def test_policy_redacts_when_sharing_forbidden_or_redact_set(tmp_path):
    assert policy.for_profile(profile(tmp_path, slug="a", sharing="forbidden", redact=True)).redact
    assert policy.for_profile(profile(tmp_path, slug="b", sharing="allowed", redact=True)).redact
    keep = policy.for_profile(profile(tmp_path, slug="c", sharing="allowed", redact=False))
    assert keep.redact is False and keep.sharing_forbidden is False


def test_policy_redacts_on_forbidden_sharing_even_if_profile_flag_were_false(tmp_path):
    # Defence in depth: a profile object built around validation still redacts.
    p = profile(tmp_path, sharing="forbidden", redact=True)
    import dataclasses
    forged = dataclasses.replace(p, writeups=dataclasses.replace(p.writeups, redact_flags=False))
    assert policy.for_profile(forged).redact is True


def test_shipped_pink_and_spooky_profiles_redact_and_hold():
    for slug in ("pink", "spooky"):
        pol = policy.for_profile(event.load(slug))
        assert pol.sharing_forbidden and pol.redact and pol.publish_hold, slug


def test_event_end_bare_date_ends_at_next_midnight_utc(tmp_path):
    p = profile(tmp_path, end="2026-01-02")
    assert policy.event_end_utc(p) == dt.datetime(2026, 1, 3, tzinfo=UTC)


def test_event_end_aware_datetime_kept_and_naive_refused(tmp_path):
    p = profile(tmp_path, slug="a", end="2026-01-02T12:00:00Z")
    assert policy.event_end_utc(p) == dt.datetime(2026, 1, 2, 12, tzinfo=UTC)
    naive = profile(tmp_path, slug="b", end="2026-01-02T12:00:00")
    with pytest.raises(policy.PolicyError, match="no UTC offset"):
        policy.for_profile(naive)


def _gates(pol, **kw):
    args = dict(now=dt.datetime(2026, 2, 1, tzinfo=UTC), files=3, blocking=0)
    args.update(kw)
    return {g.name: g.ok for g in pol.publish_gates(**args)}


def test_publish_gates_each_close_on_their_own_condition(tmp_path):
    ready = policy.for_profile(profile(tmp_path, slug="r", hold=False, repo="https://github.com/x/y"))
    assert _gates(ready) == {"hold": True, "ended": True, "repo": True, "content": True, "clean": True}
    held = policy.for_profile(profile(tmp_path, slug="h", hold=True, repo="https://github.com/x/y"))
    assert _gates(held)["hold"] is False
    assert _gates(ready, now=dt.datetime(2026, 1, 2, 23, 59, tzinfo=UTC))["ended"] is False
    assert _gates(ready, now=dt.datetime(2026, 1, 3, 0, 0, tzinfo=UTC))["ended"] is True
    norepo = policy.for_profile(profile(tmp_path, slug="n", hold=False))
    assert _gates(norepo)["repo"] is False
    assert _gates(ready, files=0)["content"] is False
    assert _gates(ready, blocking=1)["clean"] is False
    with pytest.raises(policy.PolicyError):
        ready.publish_gates(now=dt.datetime(2026, 2, 1), files=1, blocking=0)


def test_infra_hosts_cover_platform_scope_and_scope_apex(tmp_path):
    pol = policy.for_profile(profile(tmp_path))
    assert pol.is_infra_host("ctf.zz.example")
    assert pol.is_infra_host("a1.inst.zz.example") and pol.is_infra_host("inst.zz.example")
    assert not pol.is_infra_host("github.com")


# ------------------------------------------------------------------------------------------- redaction

@pytest.fixture
def red(tmp_path):
    return scan.Scanner(profile(tmp_path, prefixes=("spooky",)), known=[])


def test_event_flag_in_any_case_is_redacted_and_was_blocking(red):
    text = "accepted Spooky{Up_Case_Body} and SPOOKY{x y z}\n"
    assert kinds(red.scan(text), True) == ["flag"]
    out, n = red.redact(text)
    assert "Up_Case_Body" not in out and "x y z" not in out and n == 2
    assert "Spooky{<redacted>}" in out
    assert "flag" not in kinds(red.scan(out))


def test_placeholders_are_not_findings_and_not_redacted(red):
    text = "format spooky{...} or spooky{<answer>} or spooky{redacted}\n"
    assert red.scan(text) == []
    assert red.redact(text)[0] == text


def test_known_values_redacted_case_insensitively_including_bare_candidates(tmp_path):
    sc = scan.Scanner(profile(tmp_path), known=[FLAG, WRONG, BARE])
    text = f"got {FLAG.lower()} after {WRONG.upper()} and {BARE}\n"
    assert {"known-value", "flag"} <= set(kinds(sc.scan(text), True))
    out, _ = sc.redact(text)
    for v in (FLAG, WRONG, BARE):
        assert v.lower() not in out.lower()
    assert "<redacted>" in out and "ZZ{<redacted>}".lower() in out.lower()
    assert sc.scan(out) == []


def test_bare_fragment_of_a_known_flag_is_redacted(tmp_path):
    sc = scan.Scanner(profile(tmp_path), known=[FLAG])
    inner = FLAG[3:-1]
    text = f"the body {inner.upper()} appears bare\n"
    assert kinds(sc.scan(text), True) == ["flag-fragment"]
    out, n = sc.redact(text)
    assert inner.lower() not in out.lower() and n == 1


def test_short_fragments_and_short_bare_values_are_not_redacted(tmp_path):
    sc = scan.Scanner(profile(tmp_path), known=["ZZ{abc}", "42"])
    out, _ = sc.redact("abc and 42 stay; ZZ{abc} goes\n")
    assert out.startswith("abc and 42 stay") and "ZZ{abc}" not in out
    assert sc.short_known == {"42"}


def test_flag_section_body_is_replaced_and_its_values_redacted_everywhere(tmp_path):
    sc = scan.Scanner(profile(tmp_path), known=[])
    text = ("# Chal\n\n## Flag\n\n`" + BARE + "` (bare, no wrapper); see `flag.txt`\n\n"
            "## Solve path\n\nwe typed " + BARE + " into the box; flag.txt holds it\n")
    out, _ = sc.redact(text)
    assert BARE not in out
    assert "Flag redacted: this event's rules forbid sharing flags." in out
    assert "flag.txt holds it" in out          # a filename in the Flag section is not a value
    assert "## Solve path" in out


def test_flag_section_note_differs_when_sharing_is_allowed_but_redacted(tmp_path):
    sc = scan.Scanner(profile(tmp_path, sharing="allowed", redact=True), known=[])
    out, _ = sc.redact("## Flag\n\n`ZZ{abc_def}`\n")
    assert "Flag redacted.\n" in out and "forbid" not in out


def test_flag_section_ends_at_same_level_heading_only(tmp_path):
    text = "## Flag\n\n### detail\nZZ{inner_value_1}\n## Next\nkeep me\n"
    assert scan.flag_sections(text) == [(len("## Flag"), text.index("## Next"))]


def test_kept_flags_are_notes_when_event_keeps_flags(tmp_path):
    sc = scan.Scanner(profile(tmp_path, sharing="allowed", redact=False), known=[FLAG])
    f = sc.scan(f"flag {FLAG}\n")
    assert {x.kind for x in f} == {"flag", "known-value"} and not any(x.blocking for x in f)


def test_flag_shaped_other_prefix_blocks_when_redacting_unless_allowed(tmp_path):
    p = profile(tmp_path)
    text = "rot13 gave Gur{fubhyq_or_n_synt}\n"
    assert kinds(scan.Scanner(p).scan(text), True) == ["flag-shaped"]
    assert scan.Scanner(p, allow=["Gur{fubhyq_or_n_synt}"]).scan(text) == []
    assert scan.Scanner(p, allow=["@flag-shaped *.py"]).scan(text, "a/solve.md") != []
    assert scan.Scanner(p, allow=["@flag-shaped *.py"]).scan(text, "a/solve/x.py") == []


def test_allow_cannot_admit_event_flags_known_values_or_secrets(tmp_path):
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4eHh4eCJ9.c2lnbmF0dXJl"
    sc = scan.Scanner(profile(tmp_path), known=[BARE], allow=["ZZ{real_one}", BARE, jwt])
    f = sc.scan(f"ZZ{{real_one}} {BARE} {jwt}\n")
    assert {"flag", "known-value", "secret"} <= set(kinds(f, True))
    with pytest.raises(common.WriteupError, match="allow rule"):
        scan.Scanner(profile(tmp_path, slug="b"), allow=["@secret *"])


@pytest.mark.parametrize("line, kind", [
    ("Authorization: Bearer abcdefghijklmnop", "secret"),
    ("Cookie: session=abc123def", "secret"),
    ("-----BEGIN RSA PRIVATE KEY-----", "secret"),
    ("token ghp_" + "a" * 36, "secret"),
    ("key AKIA" + "ABCDEFGHIJKLMNOP", "secret"),
    ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4eHh4eCJ9.c2ln", "secret"),
    ("visit https://ctf.zz.example/challenges#7", "instance-url"),
    ("nc via http://a9.inst.zz.example:31337/x", "instance-url"),
    ("server 10.20.30.40 port 80", "ipv4"),
    ("id 123e4567-e89b-12d3-a456-426614174000", "uuid"),
    ("hash " + "ab" * 16, "longhex"),
    ("<!-- TODO: write this -->", "unfinished"),
    ("<!-- CHECK: is this right -->", "open-check"),
])
def test_always_blocking_kinds(tmp_path, line, kind):
    sc = scan.Scanner(profile(tmp_path, sharing="allowed", redact=False))
    assert kind in kinds(sc.scan(line + "\n"), True)


def test_loopback_and_external_urls_do_not_block(tmp_path):
    sc = scan.Scanner(profile(tmp_path))
    f = sc.scan("run on 127.0.0.1 and 0.0.0.0; docs https://docs.python.org/3/\n")
    assert [x.kind for x in f] == ["external-url"] and not f[0].blocking
    assert scan.Scanner(profile(tmp_path, slug="b"), allow=["https://docs.python.org/3/"]).scan(
        "docs https://docs.python.org/3/\n") == []


def test_previews_never_carry_the_value(tmp_path):
    sc = scan.Scanner(profile(tmp_path), known=[BARE, FLAG])
    text = f"{FLAG} {BARE} Authorization: Basic dXNlcjpwYXNzd29yZA== {'cd' * 20}\n"
    rendered = " ".join(str(f) for f in sc.scan(text))
    for secret in (FLAG[3:-1], BARE, "dXNlcjpwYXNzd29yZA==", "cd" * 20):
        assert secret not in rendered
    assert scan.mask("ZZ{abcdefgh}") == "ZZ{…8 chars}"


def test_strip_private_blocks_and_unclosed_opener(tmp_path):
    text = "pub\n<!-- private -->\nsecret notes\n<!-- /private -->\nmore pub\n"
    out, unclosed = scan.strip_private(text)
    assert out == "pub\nmore pub\n" and not unclosed
    out, unclosed = scan.strip_private("pub\n<!-- private -->\nrest of file\n")
    assert out == "pub\n" and unclosed
    sc = scan.Scanner(profile(tmp_path))
    assert kinds(sc.scan("x\n<!-- private -->\ny\n"), True) == ["unclosed-private"]


# ------------------------------------------------------------------ verification round 1 (B-098 fixes)

SESSION = "abcDEF123456ghiJKL789"


@pytest.mark.parametrize("line", [
    'r = requests.get(u, cookies={"session": "' + SESSION + '"})',
    "r = requests.get(u, cookies = {'sid': '" + SESSION + "'})",
    'r = requests.get(u, cookies=dict(session="' + SESSION + '"))',
    'headers={"Authorization": "Token ' + SESSION + '"}',
    "headers = {'authorization': 'Basic " + SESSION + "'}",
    'opts = dict(authorization="' + SESSION + '")',
    '{"Cookie": "session=' + SESSION + '"}',
    "{'Set-Cookie': 'session=" + SESSION + "; Path=/'}",
    's.cookies.set("session", "' + SESSION + '")',
    "s.cookies['session'] = '" + SESSION + "'",
    '{"token": "' + SESSION + '"}',
    '"access_token": "' + SESSION + '",',
    "fetch https://admin:" + SESSION + "@example.org/x",
])
def test_secret_dict_json_and_cookie_forms_block_and_are_masked(tmp_path, line):
    sc = scan.Scanner(profile(tmp_path), known=[])                    # a forbidding (redacting) profile
    out, _ = sc.redact(line + "\n")
    found = sc.scan(out)
    assert "secret" in kinds(found, True), line
    assert SESSION not in " ".join(str(f) for f in found)


@pytest.mark.parametrize("line", [
    'cookies={"session": "<your session cookie>"}',
    '{"token": "{token}"}',
    "{'session': '$SESSION'}",
    'cookies = load_cookies(path)',
    'the session: we kept it short',
])
def test_secret_forms_skip_placeholders_and_prose(tmp_path, line):
    sc = scan.Scanner(profile(tmp_path), known=[])
    assert "secret" not in kinds(sc.scan(line + "\n")), line


@pytest.mark.parametrize("line, host", [
    ("nc chal.inst.zz.example 31337", "chal.inst.zz.example"),
    ("ssh ctf@inst.zz.example -p 2222", "inst.zz.example"),
    ("the board at CTF.ZZ.example, see there", "ctf.zz.example"),
])
def test_bare_instance_hostnames_block(tmp_path, line, host):
    sc = scan.Scanner(profile(tmp_path, sharing="allowed", redact=False))
    f = [x for x in sc.scan(line + "\n") if x.kind == "instance-host"]
    assert len(f) == 1 and f[0].blocking and f[0].preview == f"host {host}"


def test_bare_hostnames_off_scope_and_urls_on_scope_are_not_instance_hosts(tmp_path):
    sc = scan.Scanner(profile(tmp_path, sharing="allowed", redact=False))
    assert sc.scan("see docs.python.org and run solve.py against zz.example.org\n") == []
    f = sc.scan("visit https://a1.inst.zz.example:8080/x\n")
    assert [x.kind for x in f] == ["instance-url"]                    # one finding, not a duplicate host


def test_external_url_preview_masks_query_fragment_and_credentials(tmp_path):
    sc = scan.Scanner(profile(tmp_path, sharing="allowed", redact=False))
    f = sc.scan("docs https://example.org/reset?token=supersecretvalue123#frag_secret_456\n")
    ext = [x for x in f if x.kind == "external-url"]
    assert len(ext) == 1 and ext[0].preview == "https://example.org/reset?…#…"
    assert scan.url_preview("https://u:pw_secret_99@example.org:8443/a") == "https://…@example.org:8443/a"
    long = scan.url_preview("https://example.org" + "/ab" * 40)
    assert long.endswith("…") and "/ab" * 17 not in long


def test_bare_known_value_redaction_boundary_is_six_chars(tmp_path):
    sc = scan.Scanner(profile(tmp_path), known=["qwerty", "asdfg"])
    out, _ = sc.redact("qwerty and asdfg\n")
    assert out == "<redacted> and asdfg\n"
    assert sc.short_known == {"asdfg"} and "qwerty" in sc.known


def test_one_event_flag_on_a_line_is_one_finding(tmp_path):
    # The event flag holds a known flag's body: it is reported once as a flag, not again as a fragment.
    sc = scan.Scanner(profile(tmp_path), known=[FLAG])
    f = sc.scan("ZZ{x" + FLAG[3:-1] + "}\n")
    assert [x.kind for x in f] == ["flag"]


def test_recorded_flag_hash_redacts_the_bare_value(tmp_path):
    import hashlib
    value = "only_hashed_v4lue"
    h = hashlib.sha256(value.encode()).hexdigest()
    sc = scan.Scanner(profile(tmp_path), known=[], known_hashes=[h.upper()])
    text = f'submitted flag="{value}" and later {{"flag": "{value}"}}; typed {value}.\n'
    assert "known-value" in kinds(sc.scan(text), True)
    out, n = sc.redact(text)
    assert value not in out and n == 3
    other = scan.Scanner(profile(tmp_path, slug="b"), known=[])       # without the hash: nothing to redact
    assert other.redact(text)[0] == text
    with pytest.raises(common.WriteupError, match="not a sha256"):
        scan.Scanner(profile(tmp_path, slug="c"), known_hashes=["abc"])
    # Each quoted or keyed form resolves on its own (no bare copy elsewhere to lean on).
    for i, form in enumerate((f'flag="{value}"', f'{{"flag": "{value}"}}', f"check({value},", f"[{value}]")):
        one = scan.Scanner(profile(tmp_path, slug=f"f{i}"), known=[], known_hashes=[h])
        assert one.resolve_hashes(form + "\n") == [value], form
        assert value not in one.redact(form + "\n")[0], form


def test_neutralize_escapes_comment_open_and_close():
    assert common.neutralize("a <!-- private --> b <!-- /private --> c") == \
        "a &lt;!-- private --&gt; b &lt;!-- /private --&gt; c"


# ------------------------------------------------------------------ verification round 2 (B-098 fixes)

@pytest.mark.parametrize("line, kind", [
    ("curl -b 'session=" + SESSION + "' https://example.org/", "curl-cookie"),
    ('curl --cookie "session=' + SESSION + '" https://example.org/', "curl-cookie"),
    ("curl --cookie=sid=" + SESSION + " https://example.org/", "curl-cookie"),
    ("curl -H 'X-Api-Key: " + SESSION + "' https://example.org/", "token-header"),
    ('h = {"X-Auth-Token": "' + SESSION + '"}', "token-header"),
    ("Api-Key: " + SESSION, "token-header"),
    ('token = "' + SESSION + '"', "secret-assign"),
    ("SESSION = '" + SESSION + "'", "secret-assign"),
    ('cookie = "session=' + SESSION + '"', "secret-assign"),
    ('self.auth_token = "' + SESSION + '"', "secret-assign"),
    ('admin_cookie = "' + SESSION + '"', "secret-assign"),          # a prefix that is not a keyword
    ('token_str = "' + SESSION + '"', "secret-assign"),             # a suffix
    ("export CTFD_TOKEN=" + SESSION, "env-secret"),
    ("CTFD_SESSION=" + SESSION + " python solve.py", "env-secret"),
    ('r = s.get(u, auth=("admin", "' + SESSION + '"))', "basic-auth"),
    ("HTTPBasicAuth('admin', '" + SESSION + "')", "basic-auth"),
])
def test_secret_curl_header_assign_env_and_auth_forms_block(tmp_path, line, kind):
    sc = scan.Scanner(profile(tmp_path), known=[])                    # a forbidding (redacting) profile
    out, _ = sc.redact(line + "\n")
    found = [f for f in sc.scan(out) if f.kind == "secret"]
    assert found and all(f.blocking for f in found), line
    assert any(f.preview.startswith(kind + ":") for f in found), (line, [str(f) for f in found])
    assert SESSION not in " ".join(str(f) for f in found)


@pytest.mark.parametrize("line", [
    "curl -b cookies.txt https://example.org/",
    "curl -b 'session=<your cookie>' https://example.org/",
    "curl -H 'X-Api-Key: $API_KEY' https://example.org/",
    '{"X-Auth-Token": "{token}"}',
    'token = "<your token>"',
    'token = "<your_ctfd_token>"',
    "token = get_token(session)",
    "SESSION = requests.Session()",
    "s = requests.Session()",
    'author = "someone_with_a_long_name"',
    'inside = "abcdefghijkl"',
    "export CTFD_TOKEN=$TOKEN",
    "export CTFD_TOKEN=$CTFD_TOKEN_FROM_VAULT",
    "MAX_TOKENS=1024 python solve.py",                            # a short config value, not a secret
    'export CTFD_TOKEN="$(cat token.txt)"',
    "TOKEN=os.environ.get(name)",
    'auth=("admin", "<password>")',
    "X-Api-Key: short",
    'possession = "the_ball_carrier"',                            # a name that only ends in "session"
    "plan-b k=abcdefgh is the fallback",                          # -b inside a word is not curl's flag
])
def test_new_secret_forms_skip_placeholders_calls_and_prose(tmp_path, line):
    sc = scan.Scanner(profile(tmp_path), known=[])
    assert "secret" not in kinds(sc.scan(line + "\n")), line


def test_external_url_preview_masks_token_like_path_segments(tmp_path):
    tok = "aB3dE5gH7jK9mN1pQ3sT5v"                                   # 22 chars, letters and digits
    sc = scan.Scanner(profile(tmp_path, sharing="allowed", redact=False))
    ext = [x for x in sc.scan(f"see https://example.org/api/{tok}/x\n") if x.kind == "external-url"]
    assert len(ext) == 1 and ext[0].preview == "https://example.org/api/…(22)/x"
    assert tok not in str(ext[0]) and tok[:8] not in ext[0].preview
    # a long all-letter segment is masked too; a short mixed one (10 chars) is the boundary
    assert scan.url_preview("https://e.org/" + "a" * 20 + "/b") == "https://e.org/…(20)/b"
    assert scan.url_preview("https://e.org/" + "a" * 19) == "https://e.org/" + "a" * 19
    assert scan.url_preview("https://e.org/abcde12345/y") == "https://e.org/…(10)/y"
    assert scan.url_preview("https://e.org/abcd12345/y") == "https://e.org/abcd12345/y"
    assert scan.url_preview("https://e.org/abcdefghijk/y") == "https://e.org/abcdefghijk/y"   # no digit
    assert scan.url_preview("https://e.org/1234567890/y") == "https://e.org/1234567890/y"     # no letter
    # the length cut applies to the masked path: a long token alone does not cut the preview
    assert scan.url_preview("https://e.org/api/" + "k" * 50 + "/x") == "https://e.org/api/…(50)/x"
    assert scan.url_preview("https://e.org/blog/2026/11/post-title") == "https://e.org/blog/2026/11/post-title"
