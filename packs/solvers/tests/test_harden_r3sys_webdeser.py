"""Independent hardening locks for ``webdeser2_preconditions``.

The expected matrices below are transcribed from the primary vendor material
linked beside each case.  No expected result is obtained from the engine's
catalog, and every input is local JSON evidence only.
"""

from __future__ import annotations

import json
import random

import pytest

import webdeser2_preconditions as engine


SPRING_XML = "org.springframework.context.support.ClassPathXmlApplicationContext"
CC4 = "org.apache.commons.collections4.functors.InvokerTransformer"
JNDI_LOOKUP = "org.apache.logging.log4j.core.lookup.JndiLookup"
JNDI_MANAGER = "org.apache.logging.log4j.core.net.JndiManager"
BF_CLASS = "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter"
BF_SINK = BF_CLASS + ".Deserialize"


def _assessment(report: dict, identifier: str) -> dict:
    matches = [row for row in report["assessments"] if row["id"] == identifier]
    assert len(matches) == 1
    return matches[0]


def _activemq(version: str = "5.18.2") -> dict:
    # Apache: fixed branches 5.15.16, 5.16.7, 5.17.6, and 5.18.3;
    # exploitation needs OpenWire network access and a String-constructor class.
    # https://activemq.apache.org/news/cve-2023-46604
    return {
        "products": [{"name": "Apache ActiveMQ Classic", "version": version}],
        "config": {"activemq.openwire_network_access": True},
        "classes": [SPRING_XML],
    }


def _tomcat(version: str = "10.1.34") -> dict:
    # ASF CVE-2025-24813: writable default servlet, partial PUT, file session
    # persistence at the default location, and a deserialization gadget are all
    # required for the RCE path.  10.1.35 is the fixed 10.1 release.
    # https://tomcat.apache.org/security-10.html
    return {
        "products": [{"name": "Apache Tomcat", "version": version}],
        "config": {
            "tomcat.default_servlet_writes": True,
            "tomcat.partial_put": True,
            "tomcat.file_session_persistence_default": True,
        },
        "classes": [CC4],
    }


def _pytorch(version: str = "2.5.1") -> dict:
    # GHSA-53q9-r3pm-6pq6 lists <=2.5.1 and fix 2.6.0.  The fixing commit
    # specifically rejects weights_only on legacy tar serialization.
    # https://github.com/pytorch/pytorch/security/advisories/GHSA-53q9-r3pm-6pq6
    # https://github.com/pytorch/pytorch/commit/8d4b8a920a2172523deb95bf20e8e52d50649c04
    return {
        "dependencies": [{"name": "torch", "version": version}],
        "config": {
            "pytorch.weights_only": True,
            "pytorch.untrusted_checkpoint": True,
            "pytorch.legacy_tar": True,
        },
        "symbols": ["torch.load"],
    }


def _dotnet(version: str = "9.0.0") -> dict:
    # Microsoft: .NET 9's in-box implementation always throws. Restoring the
    # unsafe implementation needs the compatibility package and unsafe switch.
    # https://learn.microsoft.com/en-us/dotnet/standard/serialization/
    # binaryformatter-migration-guide/compatibility-package
    return {
        "products": [{"name": "Microsoft.NETCore.App", "version": version}],
        "dependencies": [
            {"name": "System.Runtime.Serialization.Formatters", "version": "9.0.0"}
        ],
        "config": {
            "dotnet.unsafe_binaryformatter_enabled": True,
            "dotnet.untrusted_input_reaches_deserialize": True,
        },
        "classes": [BF_CLASS],
        "symbols": [BF_SINK],
    }


def _log4j(version: str = "2.14.1") -> dict:
    # Apache: CVE-2021-44228 affects log4j-core in three disjoint ranges and
    # requires attacker-controlled message data reaching a usable JNDI path.
    # https://logging.apache.org/security.html#CVE-2021-44228
    return {
        "dependencies": [
            {"name": "org.apache.logging.log4j:log4j-core", "version": version}
        ],
        "config": {
            "log4j.message_lookups_enabled": True,
            "log4j.untrusted_message_data": True,
            "log4j.jndi_endpoint_reachable": True,
        },
        "classes": [JNDI_LOOKUP, JNDI_MANAGER],
    }


@pytest.mark.parametrize(
    ("identifier", "evidence"),
    [
        ("CVE-2023-46604", _activemq()),
        ("CVE-2025-24813", _tomcat()),
        ("CVE-2025-32434", _pytorch()),
        ("DOTNET-9-BINARYFORMATTER-COMPAT", _dotnet()),
        ("CVE-2021-44228", _log4j()),
    ],
)
def test_vendor_documented_full_precondition_vectors(identifier: str, evidence: dict) -> None:
    report = engine.analyze_evidence(evidence)
    row = _assessment(report, identifier)
    assert row["status"] == "preconditions_satisfied"
    assert {gate["state"] for gate in row["gates"]} == {"satisfied"}
    assert identifier in {item["id"] for item in report["satisfied"]}
    assert report["network_requests"] == 0
    assert report["deserialized"] is False and report["executed"] is False


@pytest.mark.parametrize(
    ("identifier", "evidence"),
    [
        ("CVE-2023-46604", _activemq("5.18.3")),
        ("CVE-2025-24813", _tomcat("10.1.35")),
        ("CVE-2025-32434", _pytorch("2.6.0")),
        ("DOTNET-9-BINARYFORMATTER-COMPAT", _dotnet("8.0.12")),
        ("CVE-2021-44228", _log4j("2.15.0")),
    ],
)
def test_vendor_fixed_or_out_of_scope_boundaries(identifier: str, evidence: dict) -> None:
    row = _assessment(engine.analyze_evidence(evidence), identifier)
    assert row["status"] == "not_satisfied"
    version_gate = next(gate for gate in row["gates"] if gate["kind"] == "version")
    assert version_gate["state"] == "not_satisfied"


def test_documented_mandatory_gate_false_is_not_promoted() -> None:
    vectors = [
        ("CVE-2023-46604", _activemq(), "activemq.openwire_network_access"),
        ("CVE-2025-24813", _tomcat(), "tomcat.partial_put"),
        ("CVE-2025-32434", _pytorch(), "pytorch.legacy_tar"),
        (
            "DOTNET-9-BINARYFORMATTER-COMPAT",
            _dotnet(),
            "dotnet.unsafe_binaryformatter_enabled",
        ),
        ("CVE-2021-44228", _log4j(), "log4j.untrusted_message_data"),
    ]
    for identifier, evidence, gate in vectors:
        evidence["config"][gate] = False
        assert _assessment(engine.analyze_evidence(evidence), identifier)["status"] == "not_satisfied"


def test_absent_facts_remain_unknown_and_catalog_is_fresh() -> None:
    report = engine.analyze_evidence({})
    assert report["satisfied"] == []
    assert report["summary"] == {
        "preconditions_satisfied": 0,
        "not_satisfied": 0,
        "insufficient_evidence": 5,
    }
    catalog = engine.precondition_catalog()
    assert tuple(row["id"] for row in catalog) == (
        "CVE-2023-46604",
        "CVE-2025-24813",
        "CVE-2025-32434",
        "DOTNET-9-BINARYFORMATTER-COMPAT",
        "CVE-2021-44228",
    )
    catalog[0]["sources"].clear()
    assert engine.precondition_catalog()[0]["sources"]


def test_mapping_text_bytes_and_memoryview_have_identical_documented_semantics() -> None:
    evidence = _pytorch()
    encoded = json.dumps(evidence, separators=(",", ":")).encode()
    states = []
    for supplied in (evidence, encoded.decode(), encoded, bytearray(encoded), memoryview(encoded)):
        states.append(_assessment(engine.analyze_evidence(supplied), "CVE-2025-32434")["status"])
    assert states == ["preconditions_satisfied"] * 5


def _assert_declared_error_or_clean(value: object) -> None:
    try:
        result = engine.analyze_evidence(value)
    except engine.WebDeser2Error:
        return
    except Exception as exc:  # pragma: no cover - contract regression detail
        pytest.fail(f"leaked {type(exc).__name__}: {exc}")
    assert isinstance(result, dict)


def test_analyze_evidence_fail_closed_fuzz() -> None:
    rng = random.Random(0xD35E2)
    valid = json.dumps(_log4j(), separators=(",", ":")).encode()
    cases: list[object] = [
        b"",
        b"\xff" * 64,
        b"{\"products\":[]",  # real JSON magic then truncated
        b'{"products":[],"products":[]}',
        b'{"config":{"log4j.message_lookups_enabled":NaN}}',
        b" " * (engine.MAX_JSON_BYTES + 1),
        {"products": [{"name": "x", "version": "9"}], "classes": [object()]},
    ]
    cases.extend(rng.randbytes(size) for size in (1, 2, 7, 31, 257, 4096))
    cases.extend(valid[:cut] for cut in range(0, len(valid), 7))
    for offset in range(0, len(valid), max(1, len(valid) // 17)):
        changed = bytearray(valid)
        changed[offset] ^= 0x80
        cases.append(bytes(changed))
    released = memoryview(b"{}")
    released.release()
    cases.append(released)
    recursive: dict[str, object] = {}
    recursive["products"] = recursive
    cases.append(recursive)
    for case in cases:
        _assert_declared_error_or_clean(case)


def test_cli_catalog_and_malformed_local_json_are_guarded(tmp_path, capsys) -> None:
    assert engine.main(["catalog"]) == 0
    catalog = json.loads(capsys.readouterr().out)
    assert catalog["network_requests"] == 0
    assert len(catalog["catalog"]) == 5

    evidence = tmp_path / "evidence.json"
    evidence.write_bytes(json.dumps(_activemq()).encode())
    assert engine.main(["analyze", str(evidence)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert _assessment(report, "CVE-2023-46604")["status"] == "preconditions_satisfied"

    malformed = [b"", b"{", b"\xff" * 32, evidence.read_bytes()[:-1]]
    for payload in malformed:
        evidence.write_bytes(payload)
        assert engine.main(["analyze", str(evidence)]) == 2
        capsys.readouterr()
    evidence.write_bytes(b"x" * (engine.MAX_JSON_BYTES + 1))
    assert engine.main(["analyze", str(evidence)]) == 2


def test_cli_non_text_argv_fails_closed() -> None:
    try:
        result = engine.main([b"catalog"])
    except Exception as exc:  # pragma: no cover - expected bug path
        pytest.fail(f"leaked {type(exc).__name__}: {exc}")
    assert result == 2
