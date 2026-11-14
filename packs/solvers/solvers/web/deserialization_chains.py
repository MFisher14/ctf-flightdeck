#!/usr/bin/env python3
"""Static deserialization evidence and inert gadget-chain planning.

Challenge bytes are never deserialized.  This module performs bounded byte and
text signature matching for PHP POP/PHAR, Python pickle/PyYAML/jsonpickle,
Ruby Marshal/ERB, Java serialization/ysoserial metadata, and .NET serializers.
Its builders return a plain ``R5D_INERT_CHAIN_PLAN`` descriptor containing
only validated markers and placeholders; they never return a serialized object,
language source, command, callback, or host-executable gadget payload.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from itertools import islice
from typing import Iterable


FAMILIES: tuple[str, ...] = (
    "php_pop",
    "php_phar",
    "python_pickle",
    "python_pyyaml",
    "python_jsonpickle",
    "ruby_marshal",
    "ruby_erb",
    "java_serialization",
    "dotnet_serialization",
)

MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_FINDINGS = 256
MAX_COMPONENTS = 128
MAX_COMPONENT_CHARS = 256
MAX_SOURCE_CHARS = 512

_MARKER_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9_.:-]{3,63}\Z")
_ALIASES = {
    "php": "php_pop",
    "pop": "php_pop",
    "phar": "php_phar",
    "pickle": "python_pickle",
    "pyyaml": "python_pyyaml",
    "yaml": "python_pyyaml",
    "jsonpickle": "python_jsonpickle",
    "marshal": "ruby_marshal",
    "ruby": "ruby_marshal",
    "erb": "ruby_erb",
    "java": "java_serialization",
    "ysoserial": "java_serialization",
    ".net": "dotnet_serialization",
    "dotnet": "dotnet_serialization",
}


class DeserializationInputError(ValueError):
    """A bounded static-analysis input is malformed or unsupported."""


@dataclass(frozen=True)
class Finding:
    family: str
    language: str
    kind: str
    confidence: str
    evidence: str
    offset: int
    precondition: str
    source: str
    offline: bool = True

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ChainPlan:
    family: str
    language: str
    candidate: str
    vector: str
    skeleton: str
    marker: str
    evidence: tuple[str, ...]
    preconditions: tuple[str, ...]
    confidence: str
    inert: bool = True
    serialized_payload: bool = False
    executable: bool = False
    offline: bool = True

    def as_dict(self) -> dict[str, object]:
        row = asdict(self)
        row["evidence"] = list(self.evidence)
        row["preconditions"] = list(self.preconditions)
        return row


@dataclass(frozen=True)
class Analysis:
    findings: tuple[Finding, ...]
    families: tuple[str, ...]
    suggested_plans: tuple[ChainPlan, ...]
    bytes_inspected: int
    offline: bool = True
    deserialized: bool = False
    executed: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "findings": [item.as_dict() for item in self.findings],
            "families": list(self.families),
            "suggested_plans": [item.as_dict() for item in self.suggested_plans],
            "bytes_inspected": self.bytes_inspected,
            "offline": self.offline,
            "deserialized": self.deserialized,
            "executed": self.executed,
        }


@dataclass(frozen=True)
class _Signature:
    family: str
    language: str
    kind: str
    pattern: re.Pattern[bytes]
    confidence: str
    precondition: str


def _rx(pattern: bytes, flags: int = 0) -> re.Pattern[bytes]:
    return re.compile(pattern, flags)


_SIGNATURES: tuple[_Signature, ...] = (
    _Signature(
        "php_pop", "PHP", "serialized_object_grammar",
        _rx(rb'(?:^|[\s;{])O:\d{1,10}:"[^"\r\n]{1,256}":\d{1,10}:\{'), "high",
        "the value must reach PHP unserialize with compatible autoloaded classes",
    ),
    _Signature(
        "php_pop", "PHP", "unserialize_sink",
        _rx(rb"\bunserialize\s*\(", re.I), "medium",
        "attacker-controlled bytes must reach this call without an allowed_classes restriction",
    ),
    _Signature(
        "php_pop", "PHP", "magic_method_surface",
        _rx(rb"function\s+__(?:wakeup|unserialize|destruct|toString|call)\s*\(", re.I), "medium",
        "controllable properties must connect the magic method to a consequential sink",
    ),
    _Signature(
        "php_phar", "PHP", "phar_archive_stub",
        _rx(rb"__HALT_COMPILER\s*\(\s*\)\s*;", re.I), "high",
        "the runtime must deserialize PHAR metadata through an eligible file operation",
    ),
    _Signature(
        "php_phar", "PHP", "phar_wrapper_reference",
        _rx(rb"phar://", re.I), "medium",
        "the referenced path must be attacker-controlled and handled by a vulnerable PHP/runtime path",
    ),
    _Signature(
        "php_phar", "PHP", "phar_metadata_builder_source",
        _rx(rb"Phar::setMetadata\s*\(", re.I), "medium",
        "metadata still needs a compatible object graph and a separate deserialization trigger",
    ),
    _Signature(
        "python_pickle", "Python", "pickle_protocol_magic",
        _rx(rb"\x80[\x00-\x05]"), "high",
        "the bytes must be passed to a Python pickle loader; a protocol marker alone is not execution",
    ),
    _Signature(
        "python_pickle", "Python", "protocol0_global_opcode",
        _rx(rb"(?m)(?:^|\n)c[A-Za-z_][\w.]{0,255}\n[A-Za-z_][\w]{0,255}\n"), "high",
        "GLOBAL resolution and a later callable opcode must both be reachable during unsafe loading",
    ),
    _Signature(
        "python_pickle", "Python", "pickle_load_sink",
        _rx(rb"\b(?:pickle|cPickle)\.(?:loads?|Unpickler)\b", re.I), "medium",
        "untrusted bytes must reach this loader without a restrictive find_class policy",
    ),
    _Signature(
        "python_pickle", "Python", "base64_pickle_prefix",
        _rx(rb"(?:^|[^A-Za-z0-9])gAS[A-Za-z0-9+/=_-]{5,}"), "low",
        "the text must decode to a pickle and then reach an unsafe loader",
    ),
    _Signature(
        "python_pyyaml", "Python", "python_object_tag",
        _rx(rb"!!python/(?:object|object/apply|object/new|name):", re.I), "high",
        "an unsafe PyYAML constructor must be enabled for this tag",
    ),
    _Signature(
        "python_pyyaml", "Python", "yaml_load_sink",
        _rx(rb"\byaml\.(?:unsafe_load|load)\s*\(", re.I), "medium",
        "the loader argument and installed constructors determine whether object tags are accepted",
    ),
    _Signature(
        "python_pyyaml", "Python", "unsafe_loader_selection",
        _rx(rb"Loader\s*=\s*(?:yaml\.)?(?:Loader|UnsafeLoader)\b", re.I), "high",
        "attacker-controlled YAML must reach this loader",
    ),
    _Signature(
        "python_jsonpickle", "Python", "jsonpickle_type_metadata",
        _rx(rb'"py/(?:object|reduce|type|function)"\s*:', re.I), "high",
        "jsonpickle restoration must be enabled and the referenced type/callable importable",
    ),
    _Signature(
        "python_jsonpickle", "Python", "jsonpickle_decode_sink",
        _rx(rb"\bjsonpickle\.decode\s*\(", re.I), "medium",
        "untrusted JSON must reach decode with unsafe class restoration available",
    ),
    _Signature(
        "ruby_marshal", "Ruby", "marshal_stream_magic",
        _rx(rb"\x04\x08"), "high",
        "the stream must reach Ruby Marshal.load and compatible gadget classes must be loaded",
    ),
    _Signature(
        "ruby_marshal", "Ruby", "marshal_load_sink",
        _rx(rb"\bMarshal\.(?:load|restore)\s*\(", re.I), "medium",
        "the input to Marshal.load/restore must be attacker-controlled",
    ),
    _Signature(
        "ruby_marshal", "Ruby", "base64_marshal_prefix",
        _rx(rb"(?:^|[^A-Za-z0-9])BAh[A-Za-z0-9+/=_-]{5,}"), "low",
        "the text must decode to a Marshal stream and reach Marshal.load",
    ),
    _Signature(
        "ruby_erb", "Ruby", "erb_object_surface",
        _rx(rb"\bERB\.(?:new|allocate)\s*\(", re.I), "medium",
        "an ERB object must be restored with controllable template text and later rendered",
    ),
    _Signature(
        "ruby_erb", "Ruby", "erb_render_sink",
        _rx(rb"\.(?:result|result_with_hash)\s*\(", re.I), "low",
        "the receiver must be an attacker-influenced ERB instance",
    ),
    _Signature(
        "java_serialization", "Java", "java_stream_magic",
        _rx(rb"\xac\xed\x00\x05"), "high",
        "the stream must reach ObjectInputStream or an equivalent unsafe Java deserializer",
    ),
    _Signature(
        "java_serialization", "Java", "object_input_stream_sink",
        _rx(rb"\bObjectInputStream\b.{0,256}\breadObject\s*\(", re.I | re.S), "medium",
        "the ObjectInputStream must consume attacker-controlled data without a rejecting filter",
    ),
    _Signature(
        "java_serialization", "Java", "ysoserial_metadata",
        _rx(rb"\bysoserial\b|CommonsCollections|CommonsBeanutils|TemplatesImpl|BeanComparator", re.I), "medium",
        "the exact gadget dependencies and vulnerable versions must exist on the target classpath",
    ),
    _Signature(
        "java_serialization", "Java", "base64_java_prefix",
        _rx(rb"(?:^|[^A-Za-z0-9])rO0AB[A-Za-z0-9+/=_-]{3,}"), "low",
        "the text must decode to a Java stream and reach an unsafe object input path",
    ),
    _Signature(
        "dotnet_serialization", ".NET", "binaryformatter_stream_header",
        _rx(rb"\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00"), "high",
        "the bytes must reach BinaryFormatter or a compatible NRBF consumer",
    ),
    _Signature(
        "dotnet_serialization", ".NET", "unsafe_formatter_sink",
        _rx(rb"\b(?:BinaryFormatter|LosFormatter|ObjectStateFormatter|NetDataContractSerializer|SoapFormatter)\b", re.I), "medium",
        "attacker-controlled data must reach the named formatter without a strict binder/type allowlist",
    ),
    _Signature(
        "dotnet_serialization", ".NET", "dotnet_gadget_metadata",
        _rx(rb"ObjectDataProvider|TextFormattingRunProperties|TypeConfuseDelegate|ActivitySurrogateSelector", re.I), "medium",
        "the named type and required framework assembly/version must be available",
    ),
    _Signature(
        "dotnet_serialization", ".NET", "aspnet_viewstate_prefix",
        _rx(rb"(?:^|[^A-Za-z0-9])/wE[A-Za-z0-9+/=]{5,}"), "low",
        "the value must be ViewState and its MAC/encryption policy must permit modification",
    ),
)


@dataclass(frozen=True)
class _Candidate:
    family: str
    language: str
    candidate: str
    vector: str
    evidence_tokens: tuple[str, ...]
    preconditions: tuple[str, ...]


_CANDIDATES: tuple[_Candidate, ...] = (
    _Candidate(
        "php_pop", "PHP", "generic_magic_method_graph", "POP property graph",
        ("__wakeup", "__unserialize", "__destruct", "__tostring", "unserialize"),
        ("attacker controls a value passed to unserialize", "autoloaded classes expose a property-to-magic-method graph", "a consequential sink is reachable from that graph"),
    ),
    _Candidate(
        "php_pop", "PHP", "composer_package_inventory", "dependency-backed POP inventory",
        ("monolog", "guzzle", "laravel", "symfony", "doctrine"),
        ("the exact package and vulnerable version are installed", "the required classes are autoloadable", "properties used by the chain are writable through serialization"),
    ),
    _Candidate(
        "php_phar", "PHP", "phar_metadata_trigger", "PHAR metadata object graph",
        ("__halt_compiler", "phar://", "setmetadata"),
        ("an eligible file operation accepts an attacker-controlled PHAR path", "the runtime version/configuration performs metadata deserialization", "a compatible POP graph is autoloadable"),
    ),
    _Candidate(
        "python_pickle", "Python", "reduce_callable_plan", "pickle REDUCE metadata",
        ("pickle", "reduce", "global", "stack_global", "__reduce__"),
        ("attacker bytes reach pickle.load/loads", "find_class/callable resolution is not restricted", "the referenced module and callable are importable"),
    ),
    _Candidate(
        "python_pickle", "Python", "persistent_id_plan", "pickle persistent-load metadata",
        ("persistent_load", "persistent_id", "unpickler"),
        ("a custom Unpickler implements persistent_load", "attacker controls a persistent identifier", "the application maps that identifier to a sensitive object or action"),
    ),
    _Candidate(
        "python_pyyaml", "Python", "python_object_constructor_plan", "PyYAML constructor metadata",
        ("python/object", "python/object/apply", "python/object/new", "unsafeloader", "loader"),
        ("unsafe Python object constructors are registered", "attacker YAML reaches yaml.load/unsafe_load", "the referenced type or callable is importable"),
    ),
    _Candidate(
        "python_pyyaml", "Python", "application_constructor_plan", "custom YAML tag metadata",
        ("add_constructor", "yaml_multi_constructor", "constructor"),
        ("the application registers a stateful custom tag", "attacker controls values consumed by that constructor", "the constructor reaches a consequential application action"),
    ),
    _Candidate(
        "python_jsonpickle", "Python", "py_reduce_restore_plan", "jsonpickle reduction metadata",
        ("py/reduce", "jsonpickle", "decode"),
        ("jsonpickle class restoration is enabled", "attacker JSON reaches decode", "the reduction callable/type can be imported"),
    ),
    _Candidate(
        "python_jsonpickle", "Python", "py_object_restore_plan", "jsonpickle object-state metadata",
        ("py/object", "py/state", "__setstate__"),
        ("the referenced class is importable", "restoration invokes a state hook or property path", "attacker controls the restored state"),
    ),
    _Candidate(
        "ruby_marshal", "Ruby", "marshal_gadget_graph", "Ruby Marshal object graph",
        ("marshal", "gem::requirement", "net::writeadapter", "rack"),
        ("attacker bytes reach Marshal.load/restore", "the exact gadget classes are loaded", "the Ruby/library version preserves the required method graph"),
    ),
    _Candidate(
        "ruby_erb", "Ruby", "restored_erb_render_plan", "Marshal-to-ERB render metadata",
        ("erb", "result", "result_with_hash", "_erbout"),
        ("an ERB instance or template text is attacker-influenced", "the restored object is rendered after loading", "the render binding exposes the required data/sink"),
    ),
    _Candidate(
        "java_serialization", "Java", "commons_collections_metadata", "ysoserial CommonsCollections family",
        ("commonscollections", "transformer", "invokertransformer"),
        ("a compatible Apache Commons Collections version is present", "serialization filters allow every graph type", "attacker bytes reach Java object deserialization"),
    ),
    _Candidate(
        "java_serialization", "Java", "commons_beanutils_metadata", "ysoserial CommonsBeanutils family",
        ("commonsbeanutils", "beancomparator", "templatesimpl"),
        ("compatible BeanUtils and comparator dependencies are present", "TemplatesImpl-related types pass filters", "attacker bytes reach Java object deserialization"),
    ),
    _Candidate(
        "java_serialization", "Java", "jdk_object_graph_metadata", "JDK-only gadget inventory",
        ("annotationinvocationhandler", "signedobject", "badattributevalueexp", "jdbcrowsetimpl"),
        ("the target JDK version still exposes the candidate method graph", "module access and serialization filters permit the types", "attacker bytes reach Java object deserialization"),
    ),
    _Candidate(
        "dotnet_serialization", ".NET", "object_data_provider_metadata", "ObjectDataProvider type graph",
        ("objectdataprovider", "textformattingrunproperties", "presentationframework"),
        ("the required desktop framework assemblies are loaded", "the serializer permits arbitrary type metadata", "attacker data reaches an unsafe .NET formatter"),
    ),
    _Candidate(
        "dotnet_serialization", ".NET", "type_confuse_delegate_metadata", "delegate confusion type graph",
        ("typeconfusedelegate", "sortedset", "comparisoncomparer"),
        ("the runtime/version supports the graph", "a strict SerializationBinder does not reject the types", "attacker data reaches BinaryFormatter or an equivalent formatter"),
    ),
    _Candidate(
        "dotnet_serialization", ".NET", "viewstate_formatter_metadata", "ASP.NET formatter graph",
        ("losformatter", "objectstateformatter", "viewstate", "/we"),
        ("the artifact reaches the ASP.NET state formatter", "ViewState integrity/encryption configuration permits attacker influence", "required gadget assemblies and types are present"),
    ),
)


def normalize_family(family: str) -> str:
    if not isinstance(family, str):
        raise DeserializationInputError("family must be text")
    name = family.strip().lower()
    name = _ALIASES.get(name, name)
    if name not in FAMILIES:
        raise DeserializationInputError(f"unknown family {family!r}; choose one of: {', '.join(FAMILIES)}")
    return name


def _marker(value: str) -> str:
    if not isinstance(value, str) or not _MARKER_RE.fullmatch(value):
        raise DeserializationInputError("marker must be 4-64 safe ASCII characters")
    return value


def _artifact_bytes(data: object) -> bytes:
    if isinstance(data, str):
        try:
            raw = data.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise DeserializationInputError("artifact text is not valid Unicode") from exc
    elif isinstance(data, (bytes, bytearray, memoryview)):
        raw = bytes(data)
    else:
        raise DeserializationInputError("artifact must be text or bytes")
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise DeserializationInputError(f"artifact exceeds {MAX_ARTIFACT_BYTES} bytes")
    return raw


def _source_label(source: str) -> str:
    if not isinstance(source, str):
        raise DeserializationInputError("source must be text")
    if len(source) > MAX_SOURCE_CHARS or "\x00" in source:
        raise DeserializationInputError("source label is too long or contains NUL")
    return source


def _excerpt(raw: bytes) -> str:
    out: list[str] = []
    for byte in raw[:96]:
        if 32 <= byte <= 126:
            out.append(chr(byte))
        else:
            out.append(f"\\x{byte:02x}")
    return "".join(out)


def _bounded_components(values: Iterable[str] | str) -> tuple[str, ...]:
    if isinstance(values, str):
        values = (values,)
    try:
        selected = list(islice(iter(values), MAX_COMPONENTS + 1))
    except TypeError as exc:
        raise DeserializationInputError("observed_components must be iterable") from exc
    if len(selected) > MAX_COMPONENTS:
        raise DeserializationInputError(f"observed component cap exceeded ({MAX_COMPONENTS})")
    result: list[str] = []
    for item in selected:
        if not isinstance(item, str):
            raise DeserializationInputError("observed components must be text")
        cleaned = item.strip()
        if len(cleaned) > MAX_COMPONENT_CHARS or "\x00" in cleaned:
            raise DeserializationInputError("observed component is too long or contains NUL")
        if cleaned and cleaned not in result:
            result.append(cleaned)
    return tuple(result)


def build_chain_plans(
    family: str,
    *,
    marker: str = "R5D_MARKER",
    observed_components: Iterable[str] | str = (),
) -> tuple[ChainPlan, ...]:
    """Return ranked inert metadata plans for one serialization family."""

    canonical = normalize_family(family)
    safe_marker = _marker(marker)
    observed = _bounded_components(observed_components)
    haystack = "\n".join(observed).casefold()
    compact_haystack = re.sub(r"[^a-z0-9]+", "", haystack)
    plans: list[tuple[int, int, ChainPlan]] = []
    for index, candidate in enumerate(_CANDIDATES):
        if candidate.family != canonical:
            continue
        matched = tuple(
            token
            for token in candidate.evidence_tokens
            if token.casefold() in haystack
            or re.sub(r"[^a-z0-9]+", "", token.casefold()) in compact_haystack
        )
        skeleton = (
            "R5D_INERT_CHAIN_PLAN"
            f"|family={candidate.family}"
            f"|candidate={candidate.candidate}"
            f"|marker={safe_marker}"
            "|graph=OBJECT_GRAPH_PLACEHOLDER"
            "|sink=NON_EXECUTING_MARKER_PLACEHOLDER"
        )
        plan = ChainPlan(
            family=candidate.family,
            language=candidate.language,
            candidate=candidate.candidate,
            vector=candidate.vector,
            skeleton=skeleton,
            marker=safe_marker,
            evidence=matched,
            preconditions=candidate.preconditions,
            confidence="evidence_supported" if matched else "precondition_only",
        )
        plans.append((-len(matched), index, plan))
    plans.sort(key=lambda row: (row[0], row[1]))
    return tuple(row[2] for row in plans)


def analyze_artifact(data: object, *, source: str = "") -> Analysis:
    """Inspect saved bytes/text with signatures only; never decode object graphs."""

    raw = _artifact_bytes(data)
    label = _source_label(source)
    findings: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()
    for signature in _SIGNATURES:
        match = signature.pattern.search(raw)
        if match is None:
            continue
        key = (signature.family, signature.kind, match.start())
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                family=signature.family,
                language=signature.language,
                kind=signature.kind,
                confidence=signature.confidence,
                evidence=_excerpt(match.group(0)),
                offset=match.start(),
                precondition=signature.precondition,
                source=label,
            )
        )
        if len(findings) >= MAX_FINDINGS:
            break

    families = tuple(family for family in FAMILIES if any(row.family == family for row in findings))
    observed = tuple(part for row in findings for part in (row.kind, row.evidence))
    suggestions = tuple(
        plan
        for family in families
        for plan in build_chain_plans(family, observed_components=observed)
    )
    return Analysis(
        findings=tuple(findings),
        families=families,
        suggested_plans=suggestions,
        bytes_inspected=len(raw),
    )


def plan_catalog(*, marker: str = "R5D_MARKER") -> tuple[ChainPlan, ...]:
    """Return the complete stable inert plan catalog."""

    return tuple(plan for family in FAMILIES for plan in build_chain_plans(family, marker=marker))

