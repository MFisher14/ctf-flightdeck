"""Published-vector tests for the offline Nginx configuration analyzer."""

from __future__ import annotations

from pathlib import Path
import sys
import textwrap


REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
sys.path.insert(0, str(WEB))

import wpgap_webconf_analyzer as analyzer  # noqa: E402


def _value(item: object, name: str):
    if isinstance(item, dict):
        return item[name]
    return getattr(item, name)


def _findings(report: object) -> tuple[object, ...]:
    return tuple(_value(report, "findings"))


def _by_code(report: object, code: str) -> tuple[object, ...]:
    return tuple(row for row in _findings(report) if _value(row, "code") == code)


def _codes(report: object) -> set[str]:
    return {_value(row, "code") for row in _findings(report)}


def _evidence(row: object) -> str:
    value = _value(row, "evidence")
    if isinstance(value, str):
        return value
    return " ".join(str(item) for item in value)


def _assert_static_report(report: object) -> None:
    assert _value(report, "offline") is True
    assert _value(report, "network_requests") == 0
    assert _value(report, "vulnerability_confirmed") is False
    assert _value(report, "runtime_confirmation_required") is True
    for finding in _findings(report):
        assert _value(finding, "vulnerability_confirmed") is False
        assert isinstance(_value(finding, "line"), int)
        assert _value(finding, "line") > 0
        assert _value(finding, "context")


def test_published_uri_response_field_sinks_are_reported_with_source_lines():
    # Direct $uri redirect: Reversebrain's Nginx 1.19.8 reproduction.
    # add_header/add_trailer: the four vulnerable shapes documented in nginx
    # upstream PR #590 and subsequently reproduced against master 1.31.1.
    config = textwrap.dedent(
        """\
        http {
            server {
                location /redirect/ {
                    return 302 https://example.test$uri;
                }
                location /header/ {
                    add_header X-Original-Path $uri always;
                    return 200 "OK";
                }
                location /trailer/ {
                    add_trailer X-Original-Path $document_uri always;
                    return 200 "OK";
                }
            }
        }
        """
    )
    report = analyzer.analyze_server_config(config, server="nginx", platform="unknown")
    rows = _by_code(report, "nginx-decoded-uri-response-field")

    assert len(rows) == 3
    assert {_value(row, "line") for row in rows} == {4, 7, 11}
    assert all("location /" in str(_value(row, "context")) for row in rows)
    combined = "\n".join(_evidence(row) for row in rows)
    assert "return" in combined
    assert "add_header" in combined
    assert "add_trailer" in combined
    assert "$uri" in combined
    assert "$document_uri" in combined
    _assert_static_report(report)


def test_published_uri_upstream_header_and_request_target_sinks_are_reported():
    # These are the proxy_set_header/proxy_pass shapes in upstream PR #590.
    # Nginx issue #1673 records the resulting injected upstream header bytes.
    config = textwrap.dedent(
        """\
        server {
            location /header {
                proxy_set_header X-Normalized-URI $uri;
                proxy_pass http://backend;
            }
            location /target {
                proxy_pass http://backend/$document_uri;
            }
        }
        """
    )
    report = analyzer.analyze_server_config(config, server="auto", platform="unknown")
    header_rows = _by_code(report, "nginx-decoded-uri-upstream-field")
    target_rows = _by_code(report, "nginx-decoded-uri-upstream-target")

    assert len(header_rows) == 1
    assert _value(header_rows[0], "line") == 3
    assert "location /header" in str(_value(header_rows[0], "context"))
    assert "proxy_set_header" in _evidence(header_rows[0])
    assert len(target_rows) == 1
    assert _value(target_rows[0], "line") == 7
    assert "location /target" in str(_value(target_rows[0], "context"))
    assert "proxy_pass" in _evidence(target_rows[0])
    _assert_static_report(report)


def test_gixy_alias_prefix_traversal_vector_and_safe_control():
    # Yandex Gixy documents `/i../app/config.py` mapping through this block to
    # `/data/w3/app/config.py` because the location prefix lacks a final slash.
    vulnerable = textwrap.dedent(
        """\
        server {
            location /i {
                alias /data/w3/images/;
            }
        }
        """
    )
    report = analyzer.analyze_server_config(vulnerable, server="nginx", platform="unknown")
    rows = _by_code(report, "nginx-alias-prefix-traversal")
    assert len(rows) == 1
    assert _value(rows[0], "line") == 3
    assert "location /i" in str(_value(rows[0], "context"))
    assert "/data/w3/images/" in _evidence(rows[0])
    _assert_static_report(report)

    safe = textwrap.dedent(
        """\
        server {
            location /i/ {
                alias /data/w3/images/;
            }
        }
        """
    )
    safe_report = analyzer.analyze_server_config(safe, server="nginx", platform="unknown")
    assert "nginx-alias-prefix-traversal" not in _codes(safe_report)
    _assert_static_report(safe_report)


def test_proxy_off_by_slash_vector_and_matched_slash_control():
    # Detectify's published mapping is `/api../server-status` ->
    # `/v1/../server-status`; impact additionally requires backend dot-segment
    # normalization, so this remains static evidence rather than confirmation.
    vulnerable = textwrap.dedent(
        """\
        server {
            location /api {
                proxy_pass http://apiserver/v1/;
            }
        }
        """
    )
    report = analyzer.analyze_server_config(vulnerable, server="nginx", platform="unknown")
    rows = _by_code(report, "nginx-proxy-off-by-slash")
    assert len(rows) == 1
    assert _value(rows[0], "line") == 3
    assert "location /api" in str(_value(rows[0], "context"))
    assert "/v1/" in _evidence(rows[0])
    _assert_static_report(report)

    safe = textwrap.dedent(
        """\
        server {
            location /api/ {
                proxy_pass http://apiserver/v1/;
            }
        }
        """
    )
    safe_report = analyzer.analyze_server_config(safe, server="nginx", platform="unknown")
    assert "nginx-proxy-off-by-slash" not in _codes(safe_report)
    _assert_static_report(safe_report)


def test_regex_location_with_proxy_uri_is_flagged_from_official_semantics():
    # Official proxy_pass documentation says a URI component must not be used
    # where a regex location makes the replacement prefix indeterminate.
    config = textwrap.dedent(
        """\
        server {
            location ~ ^/download/(.*)$ {
                proxy_pass http://backend/files/;
            }
        }
        """
    )
    report = analyzer.analyze_server_config(config, server="nginx", platform="unknown")
    rows = _by_code(report, "nginx-regex-location-proxy-uri")
    assert len(rows) == 1
    assert _value(rows[0], "line") == 3
    assert "location ~" in str(_value(rows[0], "context"))
    assert "http://backend/files/" in _evidence(rows[0])
    _assert_static_report(report)


def test_rewrite_break_makes_proxy_uri_component_ineffective():
    # Official proxy_pass documentation states that after a URI-changing
    # rewrite with `break`, the proxy_pass URI component is ignored.
    vulnerable = textwrap.dedent(
        """\
        server {
            location /name/ {
                rewrite ^/name/([^/]+)$ /users?name=$1 break;
                proxy_pass http://backend/remote/;
            }
        }
        """
    )
    report = analyzer.analyze_server_config(vulnerable, server="nginx", platform="unknown")
    rows = _by_code(report, "nginx-rewrite-break-proxy-uri")
    assert len(rows) == 1
    assert _value(rows[0], "line") in {3, 4}
    assert "location /name/" in str(_value(rows[0], "context"))
    evidence = _evidence(rows[0])
    assert "rewrite" in evidence and "proxy_pass" in evidence
    _assert_static_report(report)

    no_uri_component = textwrap.dedent(
        """\
        server {
            location /name/ {
                rewrite ^/name/([^/]+)$ /users?name=$1 break;
                proxy_pass http://backend;
            }
        }
        """
    )
    safe_report = analyzer.analyze_server_config(
        no_uri_component, server="nginx", platform="unknown"
    )
    assert "nginx-rewrite-break-proxy-uri" not in _codes(safe_report)
    _assert_static_report(safe_report)


def test_merge_slashes_off_preserves_official_security_warning_as_evidence():
    config = textwrap.dedent(
        """\
        http {
            merge_slashes off;
            server {
                location /scripts/ { return 204; }
            }
        }
        """
    )
    report = analyzer.analyze_server_config(config, server="nginx", platform="unknown")
    rows = _by_code(report, "nginx-merge-slashes-off")
    assert len(rows) == 1
    assert _value(rows[0], "line") == 2
    assert "http" in str(_value(rows[0], "context"))
    assert "merge_slashes off" in _evidence(rows[0])
    _assert_static_report(report)


def test_uri_body_original_uri_and_balanced_prefixes_are_safe_controls():
    # `return 200` uses its variable-bearing argument as response body text,
    # not a Location field. `$request_uri` remains encoded for the published
    # `%0d%0a` path, and balanced location/target slashes avoid off-by-slash.
    config = textwrap.dedent(
        """\
        http {
            server {
                location /body/ {
                    return 200 $uri;
                }
                location /redirect/ {
                    return 302 https://example.test$request_uri;
                }
                location /header/ {
                    add_header X-Original-Path $request_uri always;
                    return 200 "OK";
                }
                location /i/ {
                    alias /data/w3/images/;
                }
                location /api/ {
                    proxy_pass http://apiserver/v1/;
                }
            }
        }
        """
    )
    report = analyzer.analyze_server_config(config, server="auto", platform="unknown")
    assert not {
        "nginx-decoded-uri-response-field",
        "nginx-alias-prefix-traversal",
        "nginx-proxy-off-by-slash",
    }.intersection(_codes(report))
    _assert_static_report(report)
