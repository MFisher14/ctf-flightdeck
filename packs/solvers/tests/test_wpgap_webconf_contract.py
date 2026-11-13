"""Safety, CLI, and fail-closed contract tests for the webconf analyzer."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

import wpgap_webconf_analyzer as analyzer


def test_guarded_argparse_and_offline_json_cli(tmp_path, capsys):
    assert analyzer.main([]) == 2
    missing = capsys.readouterr()
    assert "usage:" in missing.err
    assert "Traceback" not in missing.err

    assert analyzer.main(["--help"]) == 0
    assert "Offline Apache/Nginx" in capsys.readouterr().out

    assert analyzer.main(["bestfit", "√π⁷≤∞", "--code-page", "cp1252"]) == 0
    bestfit = json.loads(capsys.readouterr().out)
    assert bestfit["projected_text"] == "vp7=8"
    assert bestfit["offline"] is True
    assert bestfit["network_requests"] == 0

    config = tmp_path / "nginx.conf"
    config.write_text(
        "server { location /static/ { return 302 https://example.test$uri; } }",
        encoding="utf-8",
    )
    assert analyzer.main(["config", str(config), "--server", "nginx"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["findings"][0]["code"] == "nginx-decoded-uri-response-field"
    assert report["vulnerability_confirmed"] is False

    assert analyzer.main(["config", str(tmp_path / "absent.conf")]) == 2
    failure = capsys.readouterr()
    assert "absent" in failure.err
    assert "Traceback" not in failure.err


@pytest.mark.parametrize(
    "bad",
    (
        b"\xff",
        "server {\r location / { return 200 ok; } }",
        "server { location / { return 200 ok; }",
        "server { location / { return 200 \"unterminated; } }",
    ),
)
def test_nginx_hostile_inputs_expose_only_declared_error(bad):
    with pytest.raises(analyzer.WPGAPWebConfError):
        analyzer.analyze_server_config(bad, server="nginx")


def test_size_bounds_fail_closed(monkeypatch):
    monkeypatch.setattr(analyzer, "MAX_INPUT_BYTES", 16)
    with pytest.raises(analyzer.WPGAPWebConfError, match="exceeds"):
        analyzer.analyze_server_config("RewriteEngine " + "x" * 20, server="apache")

    monkeypatch.setattr(analyzer, "MAX_BEST_FIT_CHARS", 2)
    with pytest.raises(analyzer.WPGAPWebConfError, match="1..2"):
        analyzer.analyze_best_fit("abc", "cp1252")


def test_best_fit_table_wraps_adversarial_selector_exceptions():
    class BadString(str):
        def strip(self):
            raise IndexError("hostile selector")

    with pytest.raises(analyzer.WPGAPWebConfError):
        analyzer.best_fit_table(BadString("cp1252"))
    with pytest.raises(analyzer.WPGAPWebConfError):
        analyzer.best_fit_table(10**5000)


def test_apache_correlations_stay_in_effective_scope_and_dynamic_prefix():
    common_route = analyzer.analyze_server_config(
        "DocumentRoot /var/www/html\n"
        "RewriteRule ^/user/(.*)$ /index.php?name=$1 [L]\n"
        "RewriteRule ^/status$ /server-status [H=server-status,L]\n",
        server="apache",
    )
    common_codes = {item.code for item in common_route.findings}
    assert "apache-documentroot-dual-interpretation" not in common_codes
    assert "apache-handler-flag-confusion" not in common_codes

    disjoint = analyzer.analyze_server_config(
        '<VirtualHost *:80>\n'
        '  <Files "admin.php">\n'
        '    Require valid-user\n'
        '  </Files>\n'
        '  AllowEncodedSlashes On\n'
        '</VirtualHost>\n'
        '<VirtualHost *:80>\n'
        '  <FilesMatch ".+\\.php$">\n'
        '    SetHandler "proxy:unix:/run/php.sock|fcgi://localhost"\n'
        '  </FilesMatch>\n'
        '  MergeSlashes Off\n'
        '</VirtualHost>\n',
        server="apache",
        platform="windows",
    )
    disjoint_codes = {item.code for item in disjoint.findings}
    assert "apache-files-proxy-handler-split" not in disjoint_codes
    assert "apache-windows-unc-surface" not in disjoint_codes

    split_roots = analyzer.analyze_server_config(
        '<VirtualHost *:80>\n'
        '  DocumentRoot /srv/one\n'
        '</VirtualHost>\n'
        '<VirtualHost *:80>\n'
        '  RewriteRule ^/html/(.*)$ /$1.html\n'
        '</VirtualHost>\n',
        server="apache",
    )
    assert "apache-documentroot-dual-interpretation" not in {
        item.code for item in split_roots.findings
    }

    overridden = analyzer.analyze_server_config(
        'AllowEncodedSlashes On\n'
        '<VirtualHost *:80>\n'
        '  AllowEncodedSlashes Off\n'
        '  MergeSlashes Off\n'
        '</VirtualHost>\n',
        server="apache",
        platform="windows",
    )
    assert "apache-windows-unc-surface" not in {
        item.code for item in overridden.findings
    }


def test_nginx_valid_empty_and_braced_variables_parse_without_proxy_overreach():
    report = analyzer.analyze_server_config(
        "server {\n"
        '  proxy_set_header Accept-Encoding "";\n'
        "  location /redirect { return 302 https://example.test${uri}; }\n"
        "  location /api { proxy_pass http://backend/v1/$request_uri; }\n"
        "  location /plain { proxy_pass http://backend/v1; }\n"
        "  location $arg_gate { proxy_pass http://backend/v1/; }\n"
        "}\n",
        server="nginx",
    )
    codes = [item.code for item in report.findings]
    assert codes.count("nginx-decoded-uri-response-field") == 1
    assert "nginx-proxy-off-by-slash" not in codes


def test_nginx_absolute_break_rewrite_is_not_treated_as_local_proxy_rewrite():
    report = analyzer.analyze_server_config(
        "server { location /x { "
        "rewrite ^ https://example.test break; "
        "proxy_pass http://backend/v1/; } }",
        server="nginx",
    )
    assert "nginx-rewrite-break-proxy-uri" not in {
        item.code for item in report.findings
    }


def test_module_has_no_transport_process_deserializer_or_dynamic_execution():
    source = Path(analyzer.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports: set[str] = set()
    calls: set[str] = set()
    catches_system_exit = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                calls.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                calls.add(node.func.attr)
        elif isinstance(node, ast.ExceptHandler) and isinstance(node.type, ast.Name):
            catches_system_exit |= node.type.id == "SystemExit"

    assert not imports.intersection(
        {
            "socket",
            "requests",
            "http.client",
            "urllib.request",
            "subprocess",
            "pickle",
            "marshal",
        }
    )
    assert not calls.intersection(
        {
            "connect",
            "request",
            "send",
            "sendall",
            "urlopen",
            "system",
            "popen",
            "eval",
            "exec",
            "loads",
            "load",
        }
    )
    assert catches_system_exit is True

