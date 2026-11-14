"""Advisory-locked tests for the offline deserialization precondition map.

Expected ranges and gates below are transcribed from the vendor advisories, not
from :func:`webdeser2_preconditions.precondition_catalog`.
"""

from __future__ import annotations

import json
import random

import pytest

import webdeser2_preconditions as w


SPRING_XML = "org.springframework.context.support.ClassPathXmlApplicationContext"
CC4_INVOKER = "org.apache.commons.collections4.functors.InvokerTransformer"
JNDI_LOOKUP = "org.apache.logging.log4j.core.lookup.JndiLookup"
JNDI_MANAGER = "org.apache.logging.log4j.core.net.JndiManager"
BF_CLASS = "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter"
BF_SINK = BF_CLASS + ".Deserialize"


def assessment(report: dict, identifier: str) -> dict:
    rows = [row for row in report["assessments"] if row["id"] == identifier]
    assert len(rows) == 1
    return rows[0]


def active_mq(version: str, *, classpath: list[str] | None = None,
              network_access: bool = True) -> dict:
    evidence: dict = {
        "products": [{"name": "Apache ActiveMQ Classic", "version": version}],
        "config": {"activemq.openwire_network_access": network_access},
    }
    if classpath is not None:
        evidence["classes"] = classpath
    return evidence


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("5.15.15", "preconditions_satisfied"),
        ("5.15.16", "not_satisfied"),
        ("5.16.0", "preconditions_satisfied"),
        ("5.16.6", "preconditions_satisfied"),
        ("5.16.7", "not_satisfied"),
        ("5.17.5", "preconditions_satisfied"),
        ("5.17.6", "not_satisfied"),
        ("5.18.2", "preconditions_satisfied"),
        ("5.18.3", "not_satisfied"),
        ("6.0.0", "not_satisfied"),
    ],
)
def test_activemq_cve_2023_46604_vendor_boundaries(version: str, expected: str) -> None:
    # Apache: fixed in 5.15.16 / 5.16.7 / 5.17.6 / 5.18.3.  Its
    # project advisory names this Spring String-constructor class as the known
    # exploitation path and requires network access to a Java OpenWire peer.
    row = assessment(w.analyze_evidence(active_mq(version, classpath=[SPRING_XML])), "CVE-2023-46604")
    assert row["status"] == expected


def test_activemq_requires_proven_network_and_exact_gadget_class() -> None:
    assert assessment(
        w.analyze_evidence(active_mq("5.18.2", classpath=[SPRING_XML], network_access=False)),
        "CVE-2023-46604",
    )["status"] == "not_satisfied"
    assert assessment(
        w.analyze_evidence(active_mq("5.18.2", classpath=[])), "CVE-2023-46604"
    )["status"] == "not_satisfied"
    assert assessment(
        w.analyze_evidence(active_mq("5.18.2", classpath=[SPRING_XML + "Fake"])),
        "CVE-2023-46604",
    )["status"] == "not_satisfied"
    assert assessment(
        w.analyze_evidence(active_mq("5.18.2", classpath=None)), "CVE-2023-46604"
    )["status"] == "insufficient_evidence"


def test_activemq_legacy_openwire_cna_lower_bound_is_product_specific() -> None:
    # CNA/NVD: the separately named legacy OpenWire module starts at 5.8.0,
    # while the Classic product range is simply recorded as < 5.15.16.
    evidence = active_mq("5.7.0", classpath=[SPRING_XML])
    evidence["products"][0]["name"] = "org.apache.activemq:activemq-openwire-legacy"
    assert assessment(w.analyze_evidence(evidence), "CVE-2023-46604")["status"] == "not_satisfied"
    evidence["products"][0]["version"] = "5.8.0"
    assert assessment(
        w.analyze_evidence(evidence), "CVE-2023-46604"
    )["status"] == "preconditions_satisfied"


def tomcat(version: str, *, config_override: dict[str, bool] | None = None,
           classes: list[str] | None = None) -> dict:
    config = {
        "tomcat.default_servlet_writes": True,
        "tomcat.partial_put": True,
        "tomcat.file_session_persistence_default": True,
    }
    config.update(config_override or {})
    evidence: dict = {
        "products": [{"name": "Apache Tomcat", "version": version}],
        "config": config,
    }
    if classes is not None:
        evidence["classes"] = classes
    return evidence


@pytest.mark.parametrize(
    "version",
    [
        "8.5.0",
        "8.5.100",
        "9.0.0.M1",
        "9.0.98",
        "10.1.0-M1",
        "10.1.34",
        "11.0.0-M1",
        "11.0.2",
    ],
)
def test_tomcat_cve_2025_24813_documented_affected_boundaries(version: str) -> None:
    # Apache's 9/10/11 security pages list these exact affected endpoints; the
    # ASF announcement also identifies EOL 8.5.0 through 8.5.100.
    row = assessment(w.analyze_evidence(tomcat(version, classes=[CC4_INVOKER])), "CVE-2025-24813")
    assert row["status"] == "preconditions_satisfied"


@pytest.mark.parametrize("version", ["8.5.101", "9.0.99", "10.1.35", "11.0.3"])
def test_tomcat_cve_2025_24813_fixed_or_outside_boundaries(version: str) -> None:
    row = assessment(w.analyze_evidence(tomcat(version, classes=[CC4_INVOKER])), "CVE-2025-24813")
    assert row["status"] == "not_satisfied"


@pytest.mark.parametrize(
    "negative_gate",
    [
        "tomcat.default_servlet_writes",
        "tomcat.partial_put",
        "tomcat.file_session_persistence_default",
    ],
)
def test_tomcat_requires_every_vendor_stated_rce_configuration_gate(negative_gate: str) -> None:
    row = assessment(
        w.analyze_evidence(
            tomcat("10.1.34", config_override={negative_gate: False}, classes=[CC4_INVOKER])
        ),
        "CVE-2025-24813",
    )
    assert row["status"] == "not_satisfied"


def test_tomcat_gadget_library_evidence_is_mandatory() -> None:
    missing = assessment(w.analyze_evidence(tomcat("10.1.34")), "CVE-2025-24813")
    explicit_absence = assessment(
        w.analyze_evidence(tomcat("10.1.34", classes=[])), "CVE-2025-24813"
    )
    assert missing["status"] == "insufficient_evidence"
    assert explicit_absence["status"] == "not_satisfied"


def pytorch(version: str, *, weights_only: bool = True, legacy_tar: bool = True,
            untrusted: bool = True, symbols: list[str] | None = None) -> dict:
    evidence: dict = {
        "dependencies": [{"name": "torch", "version": version}],
        "config": {
            "pytorch.weights_only": weights_only,
            "pytorch.untrusted_checkpoint": untrusted,
            "pytorch.legacy_tar": legacy_tar,
        },
    }
    if symbols is not None:
        evidence["symbols"] = symbols
    return evidence


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("1.13.1", "preconditions_satisfied"),
        ("2.5.1", "preconditions_satisfied"),
        ("2.6.0", "not_satisfied"),
        ("2.7.0", "not_satisfied"),
    ],
)
def test_pytorch_cve_2025_32434_ghsa_version_lock(version: str, expected: str) -> None:
    # PyTorch GHSA-53q9-r3pm-6pq6: <=2.5.1 affected, 2.6.0 patched.
    row = assessment(
        w.analyze_evidence(pytorch(version, symbols=["torch.load"])), "CVE-2025-32434"
    )
    assert row["status"] == expected


@pytest.mark.parametrize(
    "kwargs",
    [
        {"weights_only": False},
        {"legacy_tar": False},
        {"untrusted": False},
        {"symbols": []},
    ],
)
def test_pytorch_specific_bypass_requires_weights_only_legacy_tar_and_sink(kwargs: dict) -> None:
    defaults = {"symbols": ["torch.load"]}
    defaults.update(kwargs)
    row = assessment(w.analyze_evidence(pytorch("2.5.1", **defaults)), "CVE-2025-32434")
    assert row["status"] == "not_satisfied"


def dotnet9(*, package: bool = True, unsafe_switch: bool = True,
            untrusted_sink: bool = True) -> dict:
    return {
        "products": [{"name": "Microsoft.NETCore.App", "version": "9.0.0"}],
        "dependencies": (
            [{"name": "System.Runtime.Serialization.Formatters", "version": "9.0.0"}]
            if package
            else []
        ),
        "config": {
            "dotnet.unsafe_binaryformatter_enabled": unsafe_switch,
            "dotnet.untrusted_input_reaches_deserialize": untrusted_sink,
        },
        "classes": [BF_CLASS],
        "symbols": [BF_SINK],
    }


def test_dotnet9_binaryformatter_removal_and_unsafe_compatibility_package() -> None:
    # Microsoft: the in-box .NET 9 implementation always throws. Restoring it
    # requires both the unsupported package and the unsafe AppContext/MSBuild switch.
    assert assessment(
        w.analyze_evidence(dotnet9()), "DOTNET-9-BINARYFORMATTER-COMPAT"
    )["status"] == "preconditions_satisfied"
    assert assessment(
        w.analyze_evidence(dotnet9(package=False)), "DOTNET-9-BINARYFORMATTER-COMPAT"
    )["status"] == "not_satisfied"
    assert assessment(
        w.analyze_evidence(dotnet9(unsafe_switch=False)), "DOTNET-9-BINARYFORMATTER-COMPAT"
    )["status"] == "not_satisfied"
    assert assessment(
        w.analyze_evidence(dotnet9(untrusted_sink=False)), "DOTNET-9-BINARYFORMATTER-COMPAT"
    )["status"] == "not_satisfied"


def test_dotnet8_does_not_match_the_dotnet9_removal_control() -> None:
    evidence = dotnet9()
    evidence["products"][0]["version"] = "8.0.12"
    row = assessment(w.analyze_evidence(evidence), "DOTNET-9-BINARYFORMATTER-COMPAT")
    assert row["status"] == "not_satisfied"


def log4j(version: str, *, classes: list[str] | None = None,
          config_override: dict[str, bool] | None = None) -> dict:
    config = {
        "log4j.message_lookups_enabled": True,
        "log4j.untrusted_message_data": True,
        "log4j.jndi_endpoint_reachable": True,
    }
    config.update(config_override or {})
    evidence: dict = {
        "dependencies": [
            {"name": "org.apache.logging.log4j:log4j-core", "version": version}
        ],
        "config": config,
    }
    if classes is not None:
        evidence["classes"] = classes
    return evidence


@pytest.mark.parametrize(
    "version",
    ["2.0-beta9", "2.3.0", "2.4", "2.12.1", "2.13.0", "2.14.1"],
)
def test_log4shell_cve_2021_44228_apache_affected_union(version: str) -> None:
    # Apache: [2.0-beta9,2.3.1) U [2.4,2.12.2) U [2.13.0,2.15.0).
    row = assessment(
        w.analyze_evidence(log4j(version, classes=[JNDI_LOOKUP, JNDI_MANAGER])),
        "CVE-2021-44228",
    )
    assert row["status"] == "preconditions_satisfied"


@pytest.mark.parametrize("version", ["2.0-beta8", "2.3.1", "2.12.2", "2.15.0", "2.17.1"])
def test_log4shell_cve_2021_44228_fixed_or_outside_union(version: str) -> None:
    row = assessment(
        w.analyze_evidence(log4j(version, classes=[JNDI_LOOKUP, JNDI_MANAGER])),
        "CVE-2021-44228",
    )
    assert row["status"] == "not_satisfied"


@pytest.mark.parametrize(
    "negative_gate",
    [
        "log4j.message_lookups_enabled",
        "log4j.untrusted_message_data",
        "log4j.jndi_endpoint_reachable",
    ],
)
def test_log4shell_requires_intact_lookup_path_and_attacker_controlled_data(
        negative_gate: str) -> None:
    row = assessment(
        w.analyze_evidence(
            log4j(
                "2.14.1",
                classes=[JNDI_LOOKUP, JNDI_MANAGER],
                config_override={negative_gate: False},
            )
        ),
        "CVE-2021-44228",
    )
    assert row["status"] == "not_satisfied"
    no_lookup_class = assessment(
        w.analyze_evidence(log4j("2.14.1", classes=[])), "CVE-2021-44228"
    )
    assert no_lookup_class["status"] == "not_satisfied"


@pytest.mark.parametrize("incomplete", [[JNDI_LOOKUP], [JNDI_MANAGER]])
def test_log4shell_requires_the_complete_core_jndi_path(incomplete: list[str]) -> None:
    row = assessment(w.analyze_evidence(log4j("2.14.1", classes=incomplete)), "CVE-2021-44228")
    assert row["status"] == "not_satisfied"


def test_missing_facts_are_unknown_and_never_promoted_to_satisfied() -> None:
    report = w.analyze_evidence({})
    assert report["satisfied"] == []
    assert {row["status"] for row in report["assessments"]} == {"insufficient_evidence"}
    assert report["offline"] is True
    assert report["deserialized"] is False
    assert report["executed"] is False
    assert report["network_requests"] == 0


def test_catalog_has_requested_profiles_and_primary_source_provenance() -> None:
    rows = w.precondition_catalog()
    assert {(row["id"], row["kind"]) for row in rows} == {
        ("CVE-2023-46604", "cve"),
        ("CVE-2025-24813", "cve"),
        ("CVE-2025-32434", "cve"),
        ("DOTNET-9-BINARYFORMATTER-COMPAT", "platform-control"),
        ("CVE-2021-44228", "cve"),
    }
    assert all(row["sources"] and all(url.startswith("https://") for url in row["sources"]) for row in rows)


@pytest.mark.parametrize(
    "bad",
    [
        b"",
        b"\xff\xfe",
        b"{",
        b"[]",
        b'{"products":42}',
        b'{"products":[],"products":[]}',
        b'{"surprise":true}',
        {"products": [{"name": "torch", "version": 2.5}]},
        {"products": [{"name": "torch", "version": "2.5.1+local"}]},
        {"config": {"pytorch.weights_only": "true"}},
        {"config": {"typo.lookup": True}},
        {"classes": [JNDI_LOOKUP, JNDI_LOOKUP]},
    ],
)
def test_malformed_evidence_raises_only_declared_error(bad: object) -> None:
    with pytest.raises(w.WebDeser2Error):
        w.analyze_evidence(bad)


def test_fail_closed_fuzz_and_oversized_inputs_never_leak_stdlib_errors() -> None:
    rng = random.Random(0xC5C7F)
    valid = json.dumps(active_mq("5.18.2", classpath=[SPRING_XML])).encode()
    flipped = bytearray(valid)
    flipped[len(flipped) // 2] ^= 0x80
    cases = [
        bytes(rng.getrandbits(8) for _ in range(size)) for size in (1, 2, 7, 31, 257)
    ]
    cases += [valid[:-1], bytes(flipped), b" " * (1024 * 1024 + 1)]
    for blob in cases:
        try:
            result = w.analyze_evidence(blob)
        except w.WebDeser2Error:
            continue
        except Exception as exc:  # pragma: no cover - contract failure details
            pytest.fail(f"leaked {type(exc).__name__}: {exc}")
        assert isinstance(result, dict)


def test_cli_is_guarded_and_analyzes_only_a_local_file(tmp_path, capsys) -> None:
    assert w.main(["--not-an-option"]) == 2
    assert w.main(["--help"]) == 0
    capsys.readouterr()
    evidence = tmp_path / "evidence.json"
    evidence.write_text(json.dumps(active_mq("5.18.2", classpath=[SPRING_XML])))
    assert w.main(["analyze", str(evidence)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert assessment(output, "CVE-2023-46604")["status"] == "preconditions_satisfied"
    assert output["network_requests"] == 0
    assert w.main(["analyze", str(tmp_path / "absent.json")]) == 2

