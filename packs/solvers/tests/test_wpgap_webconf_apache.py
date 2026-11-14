"""Published Apache Confusion Attacks vectors for the offline config analyzer.

The configurations below are reduced from Orange Tsai's 2024 research, not
generated from the implementation under test:

* https://blog.orange.tw/posts/2024-08/confusion-attacks-en/index.html
* https://httpd.apache.org/security/vulnerabilities_24.html

They are configuration-evidence tests only.  No request is sent and a finding
must not claim that exploitation was confirmed at runtime.
"""

from __future__ import annotations

from textwrap import dedent

import pytest

from wpgap_webconf_analyzer import WPGAPWebConfError, analyze_server_config


def _config(value: str) -> str:
    return dedent(value).strip()


def _finding(report: object, code: str) -> object:
    matches = [finding for finding in report.findings if finding.code == code]
    assert matches, f"missing {code}; got {[finding.code for finding in report.findings]}"
    return matches[0]


@pytest.mark.parametrize(
    ("source", "code", "evidence_lines", "platform"),
    (
        (
            """
            RewriteEngine On
            RewriteRule "^/user/(.+)$" "/var/user/$1/profile.yml"
            """,
            "apache-encoded-question-suffix",
            {2},
            "unknown",
        ),
        (
            r"""
            RewriteEngine On
            RewriteRule ^(.+\.php)$ $1 [H=application/x-httpd-php]
            """,
            "apache-handler-flag-confusion",
            {2},
            "unknown",
        ),
        (
            """
            DocumentRoot /var/www/html
            RewriteEngine On
            RewriteRule ^/html/(.*)$ /$1.html
            """,
            "apache-documentroot-dual-interpretation",
            {3},
            "unknown",
        ),
        (
            """
            RewriteEngine On
            RewriteRule ^/broken(.*) $1
            """,
            "apache-untyped-backreference-prefix",
            {2},
            "unknown",
        ),
        (
            r"""
            <Files "admin.php">
                AuthType Basic
                Require valid-user
            </Files>
            <FilesMatch ".+\.ph(?:ar|p|tml)$">
                SetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"
            </FilesMatch>
            """,
            "apache-files-proxy-handler-split",
            {5, 6},
            "unknown",
        ),
        (
            """
            AddType application/x-httpd-php .php
            """,
            "apache-legacy-addtype-handler",
            {1},
            "unknown",
        ),
        (
            """
            RewriteEngine On
            RewriteRule "^/user/(.+)$" "/var/user/$1/profile.yml" [UnsafeAllow3F]
            """,
            "apache-unsafe-compatibility-flag",
            {2},
            "unknown",
        ),
        (
            """
            AllowEncodedSlashes On
            MergeSlashes Off
            """,
            "apache-windows-unc-surface",
            {1, 2},
            "windows",
        ),
    ),
    ids=(
        "cve-2024-38474-question-truncation",
        "handler-flag-pre-truncation",
        "cve-2024-38475-documentroot-confusion",
        "cve-2024-39573-attacker-scheme",
        "files-acl-vs-fcgi-handler",
        "cve-2024-38476-addtype-handler",
        "unsafeallow3f-reenables-risk",
        "windows-unc-surface",
    ),
)
def test_published_apache_confusion_evidence(
    source: str,
    code: str,
    evidence_lines: set[int],
    platform: str,
) -> None:
    report = analyze_server_config(
        _config(source), server="apache", platform=platform
    )

    assert report.server == "apache"
    finding = _finding(report, code)
    assert finding.line in evidence_lines
    assert finding.vulnerability_confirmed is False


def test_auto_detects_apache_from_directives() -> None:
    report = analyze_server_config(
        'RewriteRule "^/user/(.+)$" "/var/user/$1/profile.yml"'
    )

    assert report.server == "apache"
    assert _finding(report, "apache-encoded-question-suffix").line == 1


@pytest.mark.parametrize(
    ("source", "forbidden_code", "platform"),
    (
        (
            """
            <Directory "/var/www/html">
                RewriteEngine On
                RewriteRule ^html/(.*)$ /$1.html
            </Directory>
            """,
            "apache-documentroot-dual-interpretation",
            "unknown",
        ),
        (
            """
            RewriteEngine On
            RewriteRule ^/public/(.*)$ /index.php?name=$1 [END]
            """,
            "apache-untyped-backreference-prefix",
            "unknown",
        ),
        (
            """
            <Files "admin.php">
                AuthType Basic
                Require valid-user
                SetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"
            </Files>
            """,
            "apache-files-proxy-handler-split",
            "unknown",
        ),
        (
            """
            AddHandler application/x-httpd-php .php
            """,
            "apache-legacy-addtype-handler",
            "unknown",
        ),
        (
            """
            AllowEncodedSlashes On
            MergeSlashes Off
            """,
            "apache-windows-unc-surface",
            "posix",
        ),
    ),
    ids=(
        "per-directory-rewrite-is-not-documentroot-confusion",
        "fixed-url-prefix-is-not-attacker-controlled-scheme",
        "acl-and-handler-in-same-files-scope",
        "addhandler-is-not-legacy-addtype-confusion",
        "unc-rule-is-windows-only",
    ),
)
def test_apache_context_and_platform_safe_controls(
    source: str, forbidden_code: str, platform: str
) -> None:
    report = analyze_server_config(
        _config(source), server="apache", platform=platform
    )

    assert forbidden_code not in {finding.code for finding in report.findings}


def test_comments_do_not_become_directives() -> None:
    report = analyze_server_config(
        _config(
            """
            # RewriteRule "^/user/(.+)$" "/var/user/$1/profile.yml"
            # AddType application/x-httpd-php .php
            # AllowEncodedSlashes On
            # MergeSlashes Off
            """
        ),
        server="apache",
        platform="windows",
    )

    assert report.findings == ()


@pytest.mark.parametrize(
    ("source", "kwargs"),
    (
        (None, {}),
        ("RewriteEngine On\x00", {}),
        ("RewriteEngine On", {"server": "caddy"}),
        ("RewriteEngine On", {"platform": "plan9"}),
        ('<Files "admin.php">\nRequire valid-user', {"server": "apache"}),
        ("</Files>", {"server": "apache"}),
    ),
    ids=(
        "non-text",
        "nul",
        "unsupported-server",
        "unsupported-platform",
        "unclosed-context",
        "orphan-context-close",
    ),
)
def test_malformed_config_fails_with_declared_exception(
    source: object, kwargs: dict[str, str]
) -> None:
    with pytest.raises(WPGAPWebConfError):
        analyze_server_config(source, **kwargs)
