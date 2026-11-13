"""Deterministic safety and coverage tests for R5D deserialization plans."""

import ast
from pathlib import Path

import pytest

import deserialization_chains as deser


@pytest.mark.parametrize("family", deser.FAMILIES)
def test_every_family_has_stable_inert_placeholder_plans(family):
    first = deser.build_chain_plans(family, marker="R5D_SAFE")
    second = deser.build_chain_plans(family, marker="R5D_SAFE")
    assert first == second
    assert first
    for plan in first:
        assert plan.family == family
        assert plan.inert is plan.offline is True
        assert plan.serialized_payload is plan.executable is False
        assert plan.marker == "R5D_SAFE"
        assert plan.skeleton.startswith("R5D_INERT_CHAIN_PLAN|")
        assert "OBJECT_GRAPH_PLACEHOLDER" in plan.skeleton
        assert "NON_EXECUTING_MARKER_PLACEHOLDER" in plan.skeleton
        assert plan.preconditions


@pytest.mark.parametrize(
    ("artifact", "family", "kind"),
    [
        (b'O:4:"Demo":1:{s:1:"x";s:1:"y";}', "php_pop", "serialized_object_grammar"),
        (b"<?php __HALT_COMPILER(); ?>", "php_phar", "phar_archive_stub"),
        (b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00.", "python_pickle", "pickle_protocol_magic"),
        (b"x: !!python/object/new:Demo []", "python_pyyaml", "python_object_tag"),
        (b'{"py/object":"demo.Widget","name":"x"}', "python_jsonpickle", "jsonpickle_type_metadata"),
        (b"\x04\x08o:\x08Demo\x00", "ruby_marshal", "marshal_stream_magic"),
        (b"template = ERB.new(saved_text)", "ruby_erb", "erb_object_surface"),
        (b"\xac\xed\x00\x05sr\x00\x04Demo", "java_serialization", "java_stream_magic"),
        (b"new BinaryFormatter().Deserialize(stream)", "dotnet_serialization", "unsafe_formatter_sink"),
    ],
)
def test_static_analyzer_covers_each_requested_family(artifact, family, kind):
    result = deser.analyze_artifact(artifact, source="saved.bin")
    assert family in result.families
    finding = next(row for row in result.findings if row.family == family and row.kind == kind)
    assert finding.evidence
    assert finding.precondition
    assert finding.source == "saved.bin"
    assert result.offline is True
    assert result.deserialized is result.executed is False


@pytest.mark.parametrize(
    ("artifact", "family"),
    [
        ("cookie=gASVAA==", "python_pickle"),
        ("token=BAhvOkRlbW8=", "ruby_marshal"),
        ("data=rO0ABXNy", "java_serialization"),
        ("__VIEWSTATE=/wEPDwUK", "dotnet_serialization"),
    ],
)
def test_encoded_prefixes_are_leads_without_decoding(artifact, family):
    result = deser.analyze_artifact(artifact)
    assert family in result.families
    assert any(row.confidence == "low" for row in result.findings if row.family == family)


def test_evidence_ranks_matching_candidate_but_does_not_satisfy_preconditions():
    plans = deser.build_chain_plans(
        "java", observed_components=["org.apache.commons.collections Transformer"]
    )
    assert plans[0].candidate == "commons_collections_metadata"
    assert plans[0].confidence == "evidence_supported"
    assert "commonscollections" in plans[0].evidence
    assert len(plans[0].preconditions) >= 3


def test_combined_findings_and_families_follow_declared_order():
    artifact = b"BinaryFormatter ObjectDataProvider\n\xac\xed\x00\x05\nO:1:\"X\":0:{}"
    first = deser.analyze_artifact(artifact)
    second = deser.analyze_artifact(artifact)
    assert first == second
    assert first.families == ("php_pop", "java_serialization", "dotnet_serialization")
    assert [row.family for row in first.findings] == [
        "php_pop", "java_serialization", "dotnet_serialization", "dotnet_serialization"
    ]


def test_report_is_json_safe_shape_without_serializing_input():
    report = deser.analyze_artifact(b"yaml.unsafe_load(value)").as_dict()
    assert report["offline"] is True
    assert report["deserialized"] is report["executed"] is False
    assert report["families"] == ["python_pyyaml"]
    assert report["findings"][0]["precondition"]
    assert report["suggested_plans"][0]["serialized_payload"] is False


def test_aliases_marker_and_component_bounds(monkeypatch):
    assert deser.normalize_family(".NET") == "dotnet_serialization"
    assert deser.normalize_family("ysoserial") == "java_serialization"
    with pytest.raises(deser.DeserializationInputError, match="unknown family"):
        deser.build_chain_plans("made-up")
    with pytest.raises(deser.DeserializationInputError, match="marker"):
        deser.build_chain_plans("pickle", marker="unsafe marker")
    monkeypatch.setattr(deser, "MAX_COMPONENTS", 2)
    with pytest.raises(deser.DeserializationInputError, match="cap exceeded"):
        deser.build_chain_plans("pickle", observed_components=(str(i) for i in range(4)))


def test_artifact_and_source_inputs_are_strictly_bounded(monkeypatch):
    monkeypatch.setattr(deser, "MAX_ARTIFACT_BYTES", 8)
    with pytest.raises(deser.DeserializationInputError, match="artifact exceeds"):
        deser.analyze_artifact(b"x" * 9)
    with pytest.raises(deser.DeserializationInputError, match="artifact must"):
        deser.analyze_artifact({"not": "implicitly stringified"})
    with pytest.raises(deser.DeserializationInputError, match="source label"):
        deser.analyze_artifact(b"x", source="bad\x00label")


def test_plan_skeletons_are_not_language_payloads_or_callbacks():
    joined = "\n".join(plan.skeleton for plan in deser.plan_catalog())
    forbidden = (
        "phar://", "!!python/", "py/reduce", "O:", "Marshal.load", "ObjectInputStream",
        "BinaryFormatter", "http://", "https://", "dns://", "<?php", "<ObjectDataProvider",
    )
    assert all(item not in joined for item in forbidden)


def test_module_imports_no_serializer_network_or_process_runtime():
    tree = ast.parse(Path(deser.__file__).read_text(encoding="utf-8"))
    forbidden_roots = {
        "pickle", "pickletools", "yaml", "jsonpickle", "marshal", "subprocess", "socket",
        "requests", "httpx", "urllib.request",
    }
    imports: set[str] = set()
    calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            calls.add(node.func.id)
    assert not {name.split(".")[0] for name in imports}.intersection(forbidden_roots)
    assert not calls.intersection({"eval", "exec", "compile", "__import__"})

