"""Deterministic tests for the inert R5D SSTI engine matrix."""

import ast
from pathlib import Path

import pytest

import ssti_engines as ssti


def test_catalog_covers_all_nine_engines_and_reflection_guard():
    probes = ssti.probe_catalog()
    covered = {engine for probe in probes for engine in probe.engines}
    assert covered == set(ssti.ENGINES)
    assert len(ssti.ENGINES) == 9
    assert all(probe.inert for probe in probes)
    for probe in probes:
        assert probe.payload
        assert probe.expected
        assert all(item.rendered not in probe.payload for item in probe.expected)


@pytest.mark.parametrize(
    ("engine", "probe_id"),
    [
        ("jinja2", "curly_string_multiply"),
        ("twig", "curly_string_multiply"),
        ("freemarker", "freemarker_upper_builtin"),
        ("velocity", "velocity_constant_assignment"),
        ("erb", "erb_constant_expression"),
        ("smarty", "smarty_constant_expression"),
        ("handlebars", "handlebars_constant_block"),
        ("pug", "pug_constant_interpolation"),
        ("mako", "mako_constant_method"),
    ],
)
def test_each_engine_has_a_deterministic_inert_builder(engine, probe_id):
    first = ssti.build_payloads(engine, contexts=["raw"])
    second = ssti.build_payloads(engine, contexts=["raw"])
    assert first == second
    assert first[0].probe_id == probe_id
    assert first[0].engine == engine
    assert first[0].inert is first[0].offline is True
    assert first[0].payload == first[0].raw_payload


@pytest.mark.parametrize("engine", ssti.ENGINES)
def test_exact_rendered_marker_detects_each_engine(engine):
    variant = ssti.build_payloads(engine, contexts=["raw"])[0]
    detections = ssti.detect(f"HTTP/1.1 200 OK\r\n\r\n{variant.expected_render}")
    assert detections[0].engine == engine
    assert detections[0].confidence == "high"
    assert detections[0].score == 100
    assert variant.probe_id in detections[0].probe_ids


def test_jinja_and_twig_are_distinguished_by_same_expression():
    jinja = ssti.build_payloads("jinja2", contexts=["raw"])[0]
    twig = ssti.build_payloads("twig", contexts=["raw"])[0]
    assert jinja.raw_payload == twig.raw_payload
    assert jinja.expected_render != twig.expected_render
    assert ssti.detect(jinja.expected_render)[0].engine == "jinja2"
    assert ssti.detect(twig.expected_render)[0].engine == "twig"


def test_reflected_or_encoded_raw_payload_never_confirms_evaluation():
    probe = ssti.probe_catalog("erb")[0]
    reflected = "you sent: " + probe.payload
    encoded_reflection = ssti.encode_for_context(probe.payload, "url_component")
    assert ssti.detect(reflected) == ()
    assert ssti.detect(encoded_reflection) == ()
    assert ssti.detect("unrelated arithmetic answer: 49") == ()


def test_context_matrix_is_canonical_and_context_escaped():
    rows = ssti.build_payloads("freemarker")
    assert tuple(row.context for row in rows) == ssti.CONTEXTS
    by_context = {row.context: row.payload for row in rows}
    assert by_context["raw"].startswith("R5D_SSTI")
    assert "&quot;" in by_context["html_attr_double"]
    assert '"' in by_context["html_attr_single"]
    assert "%24%7B" in by_context["url_component"]
    assert '\\"' in by_context["json_string"]
    assert '\\"' in by_context["template_double_quote"]
    assert tuple(row.context for row in ssti.build_payloads(
        "freemarker", contexts={"url_component", "raw"}
    )) == ("raw", "url_component")
    assert ssti.build_payloads("freemarker", contexts="raw")[0].context == "raw"


def test_single_quote_context_escapes_jinja_probe_without_execution():
    row = ssti.build_payloads("jinja2", contexts=["template_single_quote"])[0]
    assert "\\'7\\'" in row.payload
    assert row.expected_render.endswith("_Z")
    assert "open(" not in row.payload
    assert "popen" not in row.payload


@pytest.mark.parametrize(
    ("response", "engine"),
    [
        ("jinja2.exceptions.TemplateSyntaxError: unexpected end", "jinja2"),
        (r"Twig\Error\SyntaxError at line 2", "twig"),
        ("freemarker.core.ParseException: bad directive", "freemarker"),
        ("org.apache.velocity.exception.ParseErrorException", "velocity"),
        ("ActionView::Template::Error in (erb):4", "erb"),
        ("SmartyCompilerException in template", "smarty"),
        ('Handlebars.Exception: Missing helper: "nope"', "handlebars"),
        ("pug-runtime Error: unexpected token", "pug"),
        ("mako.exceptions.CompileException", "mako"),
    ],
)
def test_engine_named_errors_are_medium_confidence_leads(response, engine):
    result = ssti.detect(response)
    assert result[0].engine == engine
    assert result[0].confidence == "medium"
    assert result[0].score == 50


@pytest.mark.parametrize(
    ("source", "engine"),
    [
        ("{% extends 'base.html' %}{{ value|safe }}", "jinja2"),
        ("{{ path('home') }}", "twig"),
        ("<#assign x = value?upper_case>", "freemarker"),
        ("#set($x = 1)", "velocity"),
        ("<%= user.name %>", "erb"),
        ("{foreach $items as $item}{$item}{/foreach}", "smarty"),
        ("{{#each items}}{{this}}{{/each}}", "handlebars"),
        ("doctype html", "pug"),
        ("<%def name='card()'>x</%def>", "mako"),
    ],
)
def test_passive_source_signatures_are_low_confidence(source, engine):
    result = ssti.detect("saved response", saved_source=source)
    assert result[0].engine == engine
    assert result[0].confidence == "low"
    assert result[0].score == 20


def test_encoded_rendered_result_can_be_read_from_saved_material():
    expected = ssti.build_payloads("pug", contexts=["raw"])[0].expected_render
    encoded = ssti.encode_for_context(expected, "url_component")
    assert ssti.detect(encoded)[0].engine == "pug"


def test_validation_aliases_and_bad_inputs():
    assert ssti.normalize_engine("Handlebars.js") == "handlebars"
    assert ssti.build_payloads("ruby-erb", contexts=["raw"])[0].engine == "erb"
    with pytest.raises(ValueError, match="unknown engine"):
        ssti.build_payloads("not-an-engine")
    with pytest.raises(ValueError, match="unknown context"):
        ssti.build_payloads("mako", contexts=["cookie"])
    with pytest.raises(ValueError, match="at least one"):
        ssti.build_payloads("mako", contexts=[])
    with pytest.raises(ValueError, match="marker"):
        ssti.probe_catalog(marker="bad marker")


def test_analyze_is_json_safe_and_explicitly_offline():
    expected = ssti.build_payloads("smarty", contexts=["raw"])[0].expected_render
    report = ssti.analyze(expected)
    assert report["offline"] is True
    assert report["executed"] is report["deserialized"] is False
    assert report["detections"][0]["engine"] == "smarty"
    assert report["confirmed_engines"] == ["smarty"]
    assert report["top_score_engines"] == ["smarty"]
    assert report["ambiguous"] is False
    assert report["covered_engines"] == list(ssti.ENGINES)


def test_multiple_exact_results_are_reported_as_ambiguous_in_stable_order():
    jinja = ssti.build_payloads("jinja2", contexts="raw")[0].expected_render
    twig = ssti.build_payloads("twig", contexts="raw")[0].expected_render
    report = ssti.analyze(twig + "\n" + jinja)
    assert report["confirmed_engines"] == ["jinja2", "twig"]
    assert report["top_score_engines"] == ["jinja2", "twig"]
    assert report["ambiguous"] is True


@pytest.mark.parametrize(
    ("response", "engine"),
    [
        ("freemarker.core._MiscTemplateException", "freemarker"),
        ("org.apache.velocity.runtime.parser.ParseException", "velocity"),
        ("Error: /views/index.pug:12:4 unexpected token", "pug"),
        ("Smarty: Unable to load template 'file:x.tpl'", "smarty"),
    ],
)
def test_additional_common_engine_error_forms(response, engine):
    result = ssti.detect(response)
    assert result[0].engine == engine
    assert result[0].confidence == "medium"


@pytest.mark.parametrize(
    ("source", "engine"),
    [
        ("from jinja2 import Environment", "jinja2"),
        (r"$twig = new \Twig\Environment($loader);", "twig"),
        ("import freemarker.template.Configuration;", "freemarker"),
        ("VelocityEngine engine = new VelocityEngine();", "velocity"),
        ("renderer = ERB.new(template)", "erb"),
        ("$view = new Smarty();", "smarty"),
        ("const fn = Handlebars.compile(source);", "handlebars"),
        ("pug.render(source, options)", "pug"),
        ("from mako.template import Template", "mako"),
    ],
)
def test_framework_construction_source_signatures(source, engine):
    result = ssti.detect("", saved_source=source)
    assert result[0].engine == engine
    assert result[0].confidence == "low"


def test_saved_material_and_context_values_are_bounded(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(ssti, "MAX_SAVED_BYTES", 8)
    with pytest.raises(ValueError, match="saved_response exceeds"):
        ssti.detect("x" * 9)
    with pytest.raises(TypeError, match="saved_response must be"):
        ssti.detect({"body": "not implicitly stringified"})
    oversized = tmp_path / "oversized.txt"
    oversized.write_bytes(b"x" * 9)
    with pytest.raises(ValueError, match="saved input exceeds"):
        ssti.main(["detect", "--response-file", str(oversized)])

    monkeypatch.setattr(ssti, "MAX_CONTEXT_PAYLOAD_CHARS", 8)
    with pytest.raises(ValueError, match="payload exceeds"):
        ssti.encode_for_context("x" * 9, "raw")
    with pytest.raises(ValueError, match="NUL"):
        ssti.encode_for_context("x\x00y", "raw")


def test_module_has_no_network_process_or_dynamic_execution_primitive():
    tree = ast.parse(Path(ssti.__file__).read_text(encoding="utf-8"))
    forbidden_modules = {"requests", "httpx", "socket", "subprocess", "urllib.request"}
    imported: set[str] = set()
    direct_calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            direct_calls.add(node.func.id)
    assert not imported.intersection(forbidden_modules)
    assert not direct_calls.intersection({"eval", "exec", "compile", "__import__"})


def test_offline_cli_catalog_and_saved_file_detection(tmp_path: Path, capsys):
    assert ssti.main(["catalog", "--engine", "mako", "--context", "raw", "--json"]) == 0
    catalog_output = capsys.readouterr().out
    assert '"offline": true' in catalog_output
    expected = ssti.build_payloads("mako", contexts=["raw"])[0].expected_render
    saved = tmp_path / "response.txt"
    saved.write_text(expected, encoding="utf-8")
    assert ssti.main(["detect", "--response-file", str(saved), "--json"]) == 0
    detected_output = capsys.readouterr().out
    assert '"engine": "mako"' in detected_output
    assert '"executed": false' in detected_output
