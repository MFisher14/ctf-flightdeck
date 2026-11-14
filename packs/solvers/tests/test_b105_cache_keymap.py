"""B-105: front-vs-backend cache-key mapping, poisoning primitives, inert bot-exfil plan.

Every test fails if the behaviour under test is wrong (no tautologies, no mock of the unit).
Nothing here performs or stages real traffic; inputs are synthetic saved bytes.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

import pytest

REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
sys.path.insert(0, str(WEB))

import cache_analysis as cache  # noqa: E402
from ctf.cli import cache_keymap  # noqa: E402


# --- backend canonicalisation -------------------------------------------------

def test_backend_canonical_decodes_dot_segments_and_collapses():
    # %2e%2e -> .. -> resolved; this is the broadsheet-organizer collision shape.
    assert cache._backend_canonical("/img/%2e%2e/admin") == "/admin"
    assert cache._backend_canonical("/a//b/./c") == "/a/b/c"
    # query is preserved verbatim, not normalised.
    assert cache._backend_canonical("/p/%2e%2e/q?x=%2e") == "/q?x=%2e"


def test_backend_canonical_decode_passes_model_double_encoding():
    raw = "/x/%252e%252e/y"
    # One decode layer leaves %2e%2e literal -> no dot-segment to resolve.
    assert cache._backend_canonical(raw, decode_passes=1) == "/x/%2e%2e/y"
    # Two layers decode to .. and resolve.
    assert cache._backend_canonical(raw, decode_passes=2) == "/y"
    with pytest.raises(cache.CacheAnalysisError, match="decode_passes"):
        cache._backend_canonical(raw, decode_passes=9)


def test_backend_canonical_rejects_decoded_control_bytes():
    with pytest.raises(cache.CacheAnalysisError, match="control"):
        cache._backend_canonical("/a/%00/b")


# --- normalization collisions -------------------------------------------------

def test_two_front_keys_collapsing_to_one_backend_resource_is_a_collision():
    colls = cache.find_normalization_collisions(["/admin", "/img/%2e%2e/admin"])
    assert len(colls) == 1
    coll = colls[0]
    assert coll.backend_resource == "/admin"
    assert coll.kind == "multi-key-collision"
    assert set(coll.front_keys) == {"/admin", "/img/%2e%2e/admin"}


def test_cacheable_looking_key_resolving_elsewhere_is_a_normalization_shift():
    colls = cache.find_normalization_collisions(["/profile/..%2fsecret.css"])
    assert len(colls) == 1
    coll = colls[0]
    assert coll.kind == "normalization-shift"
    assert coll.backend_resource == "/secret.css"
    assert coll.static_front_keys == ("/profile/..%2fsecret.css",)


def test_plain_distinct_paths_do_not_collide():
    assert cache.find_normalization_collisions(["/a", "/b", "/c"]) == ()


def test_collision_input_is_validated_and_bounded():
    with pytest.raises(cache.CacheAnalysisError, match="path"):
        cache.find_normalization_collisions(["relative/path"])
    with pytest.raises(cache.CacheAnalysisError, match="exceeds"):
        cache.find_normalization_collisions([f"/p{i}" for i in range(cache.MAX_KEY_PATHS + 1)])


# --- front/back key mapping ---------------------------------------------------

def test_key_map_flags_unkeyed_input_and_over_keyed():
    rows = {r.component: r for r in cache.map_frontend_backend_keys(
        front_keyed=["path", "Host"],
        backend_used=["path", "header:X-Forwarded-Host", "query:lang"],
    )}
    assert rows["header:x-forwarded-host"].primitive == "unkeyed-input"
    assert rows["query:lang"].primitive == "unkeyed-input"
    assert rows["host"].primitive == "over-keyed"
    assert rows["path"].primitive == ""  # keyed and used: no primitive


def test_key_map_is_order_independent_and_normalises_case():
    a = cache.map_frontend_backend_keys(["PATH", "Host"], ["header:X-H"])
    b = cache.map_frontend_backend_keys(["host", "path"], ["header:x-h"])
    assert a == b


def test_key_map_rejects_empty_component():
    with pytest.raises(cache.CacheAnalysisError, match="component"):
        cache.map_frontend_backend_keys([""], ["path"])


# --- source extractors (hints) ------------------------------------------------

def test_extract_front_keyed_reads_varnish_and_nginx_key_lines():
    varnish = "sub vcl_hash {\n  hash_data(req.url);\n  hash_data(req.http.host);\n}\n"
    assert cache.extract_front_keyed(varnish) == frozenset({"path", "query", "host"})
    nginx = 'proxy_cache_key "$host$uri$arg_lang";\n'
    assert cache.extract_front_keyed(nginx) == frozenset({"host", "path", "query:lang"})


def test_extract_backend_inputs_reads_headers_path_and_query():
    src = (
        'host = request.headers["X-Forwarded-Host"]\n'
        'route = request.path_info\n'
        'lang = request.args.get("lang")\n'
    )
    got = cache.extract_backend_inputs(src)
    assert "header:x-forwarded-host" in got
    assert "path" in got and "query" in got


# --- aggregate primitive report ----------------------------------------------

_REQUEST = (
    b"GET /reset HTTP/1.1\r\nHost: app.test\r\n"
    b"X-Forwarded-Host: r5d-cache.invalid\r\n\r\n"
)
_RESPONSE = (
    b"HTTP/1.1 200 OK\r\nCache-Control: public, s-maxage=120\r\nAge: 8\r\n"
    b"Content-Type: text/html\r\n\r\n<a href='https://r5d-cache.invalid/reset'>x</a>"
)
_SOURCE = (
    'proxy_cache_key "$host$uri";\n'
    'absolute = request.headers["x-forwarded-host"] + request.path\n'
)


def test_report_merges_poisoning_keymap_and_collision_primitives():
    primitives = cache.report_poisoning_primitives(
        _REQUEST, _RESPONSE, source=_SOURCE,
        candidate_paths=["/admin", "/img/%2e%2e/admin"],
    )
    ids = [p.primitive_id for p in primitives]
    assert ids == sorted(ids)  # deterministic order
    kinds = {p.kind for p in primitives}
    assert "unkeyed-input" in kinds           # the X-Forwarded-Host reflection
    assert "normalization-collision" in kinds  # the %2e%2e collapse
    assert all(p.chain_note == cache.CHAIN_NOTE for p in primitives)
    assert all(p.offline and p.network_requests == 0 for p in primitives)


def test_report_without_anomalies_is_empty():
    req = b"GET /assets/app.css HTTP/1.1\r\nHost: app.test\r\n\r\n"
    resp = (b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=600\r\n"
            b"Content-Type: text/css\r\n\r\nbody{}")
    assert cache.report_poisoning_primitives(req, resp) == ()


def test_keymap_primitive_only_when_backend_uses_an_unkeyed_component():
    # Front keys path+query; backend also reads a header the front omits -> unkeyed-input primitive.
    primitives = cache.report_poisoning_primitives(
        b"GET / HTTP/1.1\r\nHost: app.test\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=60\r\n\r\nok",
        front_keyed=["path"], backend_used=["path", "header:x-forwarded-host"],
        use_source_hints=False,
    )
    keymap = [p for p in primitives if p.primitive_id.startswith("keymap-")]
    assert [p.kind for p in keymap] == ["unkeyed-input"]
    assert keymap[0].primitive_id == "keymap-header:x-forwarded-host"


# --- bot exfil plan (inert) ---------------------------------------------------

def test_bot_exfil_plan_is_inert_and_names_the_human_step():
    plan = cache.build_bot_exfil_plan("/static/poison.css", "/account/secret")
    assert plan.requires_live_bot is True
    assert plan.offline is True and plan.network_requests == 0
    actors = [s.actor for s in plan.steps]
    assert "authenticated-bot" in actors
    assert all(s.inert for s in plan.steps)
    assert "bot" in plan.human_step.lower()


def test_bot_exfil_plan_validates_paths_and_marker():
    with pytest.raises(cache.CacheAnalysisError, match="path"):
        cache.build_bot_exfil_plan("relative", "/ok")
    with pytest.raises(cache.CacheAnalysisError, match="marker"):
        cache.build_bot_exfil_plan("/a", "/b", marker="bad\r\nvalue")


def test_analyze_cache_key_confusion_is_deterministic_json_ready():
    report = cache.analyze_cache_key_confusion(
        _REQUEST, _RESPONSE, source=_SOURCE,
        candidate_paths=["/account", "/static/..%2faccount.css"],
        exfil_read_path="/account/secret",
    )
    assert report == cache.analyze_cache_key_confusion(
        _REQUEST, _RESPONSE, source=_SOURCE,
        candidate_paths=["/account", "/static/..%2faccount.css"],
        exfil_read_path="/account/secret",
    )
    assert report["offline"] is True and report["network_requests"] == 0
    assert report["bot_plan"] is not None
    assert report["bot_plan"]["requires_live_bot"] is True
    # A static collision front key seeds the poison key.
    assert report["bot_plan"]["poison_key"] == "/static/..%2faccount.css"


# --- CLI ----------------------------------------------------------------------

def _write(tmp_path, name, data: bytes) -> str:
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_cli_text_report_runs_offline(tmp_path, capsys):
    args = argparse.Namespace(
        request=_write(tmp_path, "req", _REQUEST),
        response=_write(tmp_path, "resp", _RESPONSE),
        source=_write(tmp_path, "src", _SOURCE.encode()),
        marker=None, path=["/admin", "/img/%2e%2e/admin"],
        front=[], backend=[], exfil_read="/account/secret", json=False,
    )
    rc = cache_keymap.run(args)
    out = capsys.readouterr().out
    assert rc == 0
    assert "cache-key primitives:" in out
    assert "normalization-collision" in out
    assert "requires live bot=True" in out


def test_cli_json_report_is_valid_and_offline(tmp_path, capsys):
    import json as _json
    args = argparse.Namespace(
        request=_write(tmp_path, "req", _REQUEST),
        response=_write(tmp_path, "resp", _RESPONSE),
        source=None, marker=None, path=["/admin", "/img/%2e%2e/admin"],
        front=[], backend=[], exfil_read=None, json=True,
    )
    rc = cache_keymap.run(args)
    doc = _json.loads(capsys.readouterr().out)
    assert rc == 0
    assert doc["network_requests"] == 0 and doc["offline"] is True
    assert any(p["kind"] == "normalization-collision" for p in doc["primitives"])


def test_cli_reports_bad_input_without_crashing(tmp_path, capsys):
    args = argparse.Namespace(
        request=_write(tmp_path, "req", b"not-http\r\n\r\n"),
        response=_write(tmp_path, "resp", _RESPONSE),
        source=None, marker=None, path=[], front=[], backend=[], exfil_read=None, json=False,
    )
    rc = cache_keymap.run(args)
    err = capsys.readouterr().err
    assert rc == 2 and "cache-keymap" in err


# --- round-1 verification fixes ----------------------------------------------

_PLAIN_REQUEST = b"GET /home HTTP/1.1\r\nHost: app.test\r\n\r\n"
_CACHEABLE = b"HTTP/1.1 200 OK\r\nCache-Control: public, max-age=60\r\n\r\nok"
_UNCACHEABLE = b"HTTP/1.1 200 OK\r\nCache-Control: no-store, private\r\n\r\nok"
# Front keys host+uri; backend reads X-Forwarded-Host. The request does not carry the header, so
# analyze_cache_poisoning contributes nothing and any unkeyed-input primitive comes from the key map.
_KEYMAP_ONLY_SOURCE = (
    'proxy_cache_key "$host$uri";\n'
    'base = request.headers["X-Forwarded-Host"] + request.path\n'
)


def test_non_static_key_whose_backend_form_shifts_is_not_flagged():
    # One key, backend form differs, but nothing marks it cacheable-looking: no primitive.
    assert cache.find_normalization_collisions(["/a/%2e%2e/b"]) == ()


def test_source_hints_alone_produce_a_keymap_primitive():
    primitives = cache.report_poisoning_primitives(
        _PLAIN_REQUEST, _CACHEABLE, source=_KEYMAP_ONLY_SOURCE,
    )
    ids = [p.primitive_id for p in primitives]
    assert "keymap-header:x-forwarded-host" in ids
    # The hint path is switchable: off means no key-map primitive from the same source.
    off = cache.report_poisoning_primitives(
        _PLAIN_REQUEST, _CACHEABLE, source=_KEYMAP_ONLY_SOURCE, use_source_hints=False,
    )
    assert not [p for p in off if p.primitive_id.startswith("keymap-")]


def _keymap_primitive(response: bytes):
    primitives = cache.report_poisoning_primitives(
        _PLAIN_REQUEST, response,
        front_keyed=["path"], backend_used=["path", "query:lang"], use_source_hints=False,
    )
    (only,) = [p for p in primitives if p.primitive_id.startswith("keymap-")]
    return only


def test_keymap_severity_follows_cacheability():
    assert _keymap_primitive(_CACHEABLE).severity == "medium"
    assert _keymap_primitive(_UNCACHEABLE).severity == "low"
    assert _keymap_primitive(_CACHEABLE).confidence == "low"


def _collision_primitive(response: bytes, paths):
    primitives = cache.report_poisoning_primitives(_PLAIN_REQUEST, response, candidate_paths=paths)
    (only,) = [p for p in primitives if p.kind == "normalization-collision"]
    return only


def test_collision_severity_needs_a_static_key_and_a_cacheable_response():
    static_pair = ["/account.css", "/x/%2e%2e/account.css"]
    plain_pair = ["/admin", "/img/%2e%2e/admin"]
    strong = _collision_primitive(_CACHEABLE, static_pair)
    assert (strong.severity, strong.confidence) == ("high", "medium")
    assert strong.primitive_id == "collision-/account.css"
    uncached = _collision_primitive(_UNCACHEABLE, static_pair)
    assert (uncached.severity, uncached.confidence) == ("medium", "medium")
    no_static = _collision_primitive(_CACHEABLE, plain_pair)
    assert (no_static.severity, no_static.confidence) == ("medium", "low")


def test_unknown_front_key_suppresses_keymap_primitives():
    primitives = cache.report_poisoning_primitives(
        _PLAIN_REQUEST, _CACHEABLE,
        front_keyed=[], backend_used=["path", "header:x-forwarded-host"], use_source_hints=False,
    )
    assert not [p for p in primitives if p.primitive_id.startswith("keymap-")]


def test_key_map_with_unknown_front_is_tagged_not_flagged():
    report = cache.analyze_cache_key_confusion(
        _PLAIN_REQUEST, _CACHEABLE, backend_used=["path", "header:x-forwarded-host"],
    )
    assert report["key_map_status"] == cache.KEY_MAP_FRONT_UNKNOWN
    tags = {row["component"]: row["primitive"] for row in report["key_map"]}
    assert tags == {"path": "front-key-unknown", "header:x-forwarded-host": "front-key-unknown"}
    assert report["primitives"] == []
    status, rows = cache.build_key_map(["path"], [])
    assert status == cache.KEY_MAP_BACKEND_UNKNOWN
    assert [r.primitive for r in rows] == ["backend-inputs-unknown"]
    assert cache.build_key_map([], []) == (cache.KEY_MAP_EMPTY, ())
    full_status, _ = cache.build_key_map(["path"], ["path"])
    assert full_status == cache.KEY_MAP_COMPLETE


def test_map_frontend_backend_keys_refuses_an_unknown_side():
    with pytest.raises(cache.CacheAnalysisError, match="unknown"):
        cache.map_frontend_backend_keys([], ["path"])
    with pytest.raises(cache.CacheAnalysisError, match="unknown"):
        cache.map_frontend_backend_keys(["path"], [])


def test_same_unkeyed_header_is_reported_once_with_merged_evidence():
    primitives = cache.report_poisoning_primitives(_REQUEST, _RESPONSE, source=_SOURCE)
    xfh = [p for p in primitives if "x-forwarded-host" in p.primitive_id]
    assert [p.primitive_id for p in xfh] == ["poison-unkeyed-x-forwarded-host"]
    assert any(line.startswith("cache-key map:") for line in xfh[0].evidence)


def test_varnish_query_stripping_hash_keys_path_only():
    stripped = 'sub vcl_hash {\n  hash_data(regsub(req.url, "\\?.*$", ""));\n}\n'
    assert cache.extract_front_keyed(stripped) == frozenset({"path"})
    assert cache.extract_front_keyed('hash_data(regsuball(req.url, "[?].*", ""));') == frozenset({"path"})
    assert cache.extract_front_keyed("hash_data(querystring.remove(req.url));") == frozenset({"path"})
    assert cache.extract_front_keyed('hash_data(querystring.filter(req.url, "utm_"));') == frozenset({"path"})
    # Rewrites that keep the query still key it.
    assert cache.extract_front_keyed("hash_data(querystring.sort(req.url));") == frozenset({"path", "query"})
    assert cache.extract_front_keyed('hash_data(regsub(req.url, "^/v1", ""));') == frozenset({"path", "query"})


def test_query_stripping_hash_makes_query_an_unkeyed_input():
    vcl = 'hash_data(regsub(req.url, "\\?.*$", ""));\nlang = request.args.get("lang")\nrequest.path\n'
    ids = [p.primitive_id for p in cache.report_poisoning_primitives(_PLAIN_REQUEST, _CACHEABLE, source=vcl)]
    assert "keymap-query" in ids


def test_backend_extractor_ignores_comments_and_substring_names():
    assert cache.extract_backend_inputs("# no x-forwarded-host here, we drop it\nx = 1\n") == frozenset()
    assert cache.extract_backend_inputs("/* uses X-Host */ y = 2 // and 'forwarded'\n") == frozenset()
    got = cache.extract_backend_inputs('h = request.headers.get("X-Forwarded-Host")\n')
    assert got == frozenset({"header:x-forwarded-host"})  # not header:forwarded
    # A '#' or '//' inside a quoted string is not a comment.
    assert cache.extract_backend_inputs("u = 'http://x/#a'; h = \"x-host\"\n") == frozenset({"header:x-host"})


def test_trailing_slash_is_preserved_unless_folding_is_requested():
    assert cache._backend_canonical("/a/") == "/a/"
    assert cache._backend_canonical("/a/b/..") == "/a/"
    assert cache._backend_canonical("/") == "/"
    assert cache.find_normalization_collisions(["/a/", "/a"]) == ()
    folded = cache.find_normalization_collisions(["/a/", "/a"], strip_trailing_slash=True)
    assert [c.backend_resource for c in folded] == ["/a"]


def test_exfil_read_without_candidate_path_fails_loudly():
    with pytest.raises(cache.CacheAnalysisError, match="exfil-read"):
        cache.analyze_cache_key_confusion(_PLAIN_REQUEST, _CACHEABLE, exfil_read_path="/account/secret")


def test_seed_candidate_paths_reuses_parser_differential_variants():
    seeded = cache.seed_candidate_paths("/admin")
    assert seeded[0] == "/admin"
    assert "/%2e%2e/admin" in seeded and "/./admin" in seeded
    assert len(seeded) == len(set(seeded))
    (coll,) = cache.find_normalization_collisions(seeded)
    assert coll.backend_resource == "/admin" and "/%2e/admin" in coll.front_keys
    with pytest.raises(cache.CacheAnalysisError, match="path"):
        cache.seed_candidate_paths("admin")


def _cli_args(tmp_path, **over):
    base = dict(
        request=_write(tmp_path, "req", _PLAIN_REQUEST),
        response=_write(tmp_path, "resp", _CACHEABLE),
        source=None, marker=None, path=[], seed=[], front=[], backend=[],
        exfil_read=None, json=False,
    )
    base.update(over)
    return argparse.Namespace(**base)


def test_cli_exfil_read_without_path_exits_2_with_reason(tmp_path, capsys):
    rc = cache_keymap.run(_cli_args(tmp_path, exfil_read="/account/secret"))
    err = capsys.readouterr().err
    assert rc == 2
    assert "exfil-read needs a candidate poison key" in err


def test_cli_unknown_front_key_prints_reason_not_anomaly(tmp_path, capsys):
    rc = cache_keymap.run(_cli_args(tmp_path, backend=["header:x-forwarded-host", "path"]))
    out = capsys.readouterr().out
    assert rc == 0
    assert "front cache key could not be determined" in out
    assert "unkeyed-input" not in out
    assert "front-key-unknown" in out


def test_cli_unknown_backend_and_no_key_info_print_named_reasons(tmp_path, capsys):
    rc = cache_keymap.run(_cli_args(tmp_path, front=["path"]))
    out = capsys.readouterr().out
    assert rc == 0
    assert "backend inputs could not be determined" in out
    assert "backend-inputs-unknown" in out and "over-keyed" not in out
    rc = cache_keymap.run(_cli_args(tmp_path))
    out = capsys.readouterr().out
    assert rc == 0
    assert "cache-key map: no key information" in out


def test_cli_seed_expands_candidates(tmp_path, capsys):
    import json as _json
    rc = cache_keymap.run(_cli_args(tmp_path, seed=["/admin"], json=True))
    doc = _json.loads(capsys.readouterr().out)
    assert rc == 0
    (coll,) = doc["collisions"]
    assert "/%2e%2e/admin" in coll["front_keys"]


def test_cli_module_import_does_not_put_solvers_web_on_sys_path():
    # CLI discovery imports every command at startup; the engine path is added only inside run().
    import subprocess
    code = (
        "import sys, pathlib; import ctf.cli.cache_keymap; "
        "print(any(pathlib.Path(p).parts[-2:] == ('solvers', 'web') for p in sys.path))"
    )
    out = subprocess.run([sys.executable, "-c", code], cwd=REPO, capture_output=True, text=True,
                         check=True).stdout.strip()
    assert out == "False"


# --- round-2 verification fixes ----------------------------------------------

def _unkeyed(rows):
    return {r.component for r in rows if r.primitive == "unkeyed-input"}


def test_host_is_one_component_whatever_the_spelling():
    # Front keys the host, backend reads Host: no anomaly, and host is not over-keyed.
    rows = cache.map_frontend_backend_keys(["host", "path"], ["header:host", "path"])
    assert [(r.component, r.primitive) for r in rows] == [("host", ""), ("path", "")]
    assert cache.extract_backend_inputs('h = request.headers["Host"]\n') == frozenset({"host"})
    for src in ('proxy_cache_key "$host$request_uri";\nh = request.headers["Host"] + request.path\n',
                'hash_data(req.url);\nhash_data(req.http.host);\nh = headers.get("Host")\n'):
        ids = [p.primitive_id for p in cache.report_poisoning_primitives(
            _PLAIN_REQUEST, _CACHEABLE, source=src)]
        assert not [i for i in ids if i.startswith("keymap-")], ids
    # A backend reading Host against a front that does not key it is still flagged.
    assert _unkeyed(cache.map_frontend_backend_keys(["path"], ["header:host"])) == {"host"}


def test_whole_query_key_covers_each_parameter():
    rows = {r.component: r for r in cache.map_frontend_backend_keys(["path", "query"],
                                                                    ["path", "query:lang"])}
    assert rows["query:lang"].primitive == "" and rows["query:lang"].keyed_front is True
    # The front's whole query is used through its parameter: not over-keyed either.
    assert rows["query"].primitive == "" and rows["query"].used_backend is True
    # Only the parameter keyed while the backend reads the whole query: the rest is off-key.
    rows = {r.component: r for r in cache.map_frontend_backend_keys(["path", "query:lang"],
                                                                    ["path", "query"])}
    assert rows["query"].primitive == "unkeyed-input"
    assert rows["query:lang"].primitive == ""
    # A different parameter is not covered by a sibling.
    assert _unkeyed(cache.map_frontend_backend_keys(["query:a"], ["query:b"])) == {"query:b"}
    # A label with an empty half has no parent.
    assert _unkeyed(cache.map_frontend_backend_keys(["query"], ["query:"])) == {"query:"}


def test_commented_out_hash_data_keys_nothing():
    vcl = ("sub vcl_hash {\n  hash_data(req.url);\n"
           "  # hash_data(req.http.x-forwarded-host);\n"
           "  // hash_data(req.http.x-host);\n  /* hash_data(req.http.x-a); */\n}\n")
    assert cache.extract_front_keyed(vcl) == frozenset({"path", "query"})
    src = vcl + 'h = request.headers["X-Forwarded-Host"] + request.path\n'
    ids = [p.primitive_id for p in cache.report_poisoning_primitives(
        _PLAIN_REQUEST, _CACHEABLE, source=src)]
    assert "keymap-header:x-forwarded-host" in ids


def test_regsub_removing_one_parameter_keeps_the_query_keyed():
    one_param = 'hash_data(regsub(req.url, "\\?utm_source=[^&]*", ""));'
    assert cache.extract_front_keyed(one_param) == frozenset({"path", "query"})
    assert cache.extract_front_keyed('hash_data(regsuball(req.url, "[?&]utm_[^&]*", ""));') == \
        frozenset({"path", "query"})
    # Full strips in their usual spellings still key the path only.
    for pat in ("\\?.*$", "\\?.*", "[?].*$", "^([^?]*)(\\?.*)?$", "\\?.+$"):
        assert cache.extract_front_keyed(f'hash_data(regsub(req.url, "{pat}", "\\1"));') == \
            frozenset({"path"}), pat
    vcl = one_param + '\nlang = request.args.get("lang")\nrequest.path\n'
    ids = [p.primitive_id for p in cache.report_poisoning_primitives(
        _PLAIN_REQUEST, _CACHEABLE, source=vcl)]
    assert "keymap-query" not in ids


def test_backend_extractor_ignores_ordinary_headers():
    assert cache.extract_backend_inputs('ct = request.headers.get("Content-Type")\n') == frozenset()
    assert cache.extract_backend_inputs('c = request.headers["Cookie"]\n') == frozenset()
    assert cache.extract_backend_inputs('a = req.get("Accept")\n') == frozenset()
    assert cache.extract_backend_inputs('f = request.headers.get("Forwarded")\n') == \
        frozenset({"header:forwarded"})


def test_each_req_url_token_binds_to_its_own_wrapper():
    bare_then_strip = 'hash_data(req.url); hash_data(regsub(req.url, "\\?.*$", ""));'
    assert cache.extract_front_keyed(bare_then_strip) == frozenset({"path", "query"})
    strip_then_sorted = 'hash_data(regsub(req.url, "\\?.*$", "")); hash_data(querystring.sort(req.url));'
    assert cache.extract_front_keyed(strip_then_sorted) == frozenset({"path", "query"})
