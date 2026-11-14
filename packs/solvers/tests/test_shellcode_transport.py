"""Deterministic structural tests for r5b shellcode transports and Linux hunters."""
from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))

from contract import BuildError, PayloadBuild  # noqa: E402
import shellcode_transport as transport  # noqa: E402


@pytest.mark.parametrize("architecture", ("i386", "amd64"))
def test_xor_decoder_roundtrips_and_avoids_entire_bad_byte_set(architecture: str) -> None:
    body = b"\x00\x0a\x0dR5B decoder fixture\xff"
    build = transport.build_xor_decoder(
        body, architecture=architecture, bad_bytes={0, 10, 13},
        variant=None, variant_seed=17,
    )
    payload, placements = build
    assert isinstance(payload, bytes) and dict(placements) == dict(build.placements)
    assert not (set(payload) & {0, 10, 13})
    assert transport.decode_xor_body(build) == body
    assert build.slice("decoder.key") == bytes((int(build.metadata["key"]),))
    assert build.slice("decoder.length") == bytes((len(body),))
    assert build.placements["decoded_entry"] == build.placements["encoded_body"]
    plan = json.loads(build.metadata["decoder_plan"])
    assert plan["iterations"] == len(body) and plan["stack_words"] == 1
    assert build.metadata["executable"] == "true"


def test_xor_register_polymorphism_is_deterministic_and_semantically_equal() -> None:
    body = b"R5B_POLYMORPHIC_BODY"
    builds = [
        transport.build_xor_decoder(body, architecture="amd64", key=0x5A, variant=index)
        for index in range(3)
    ]
    assert len({item.payload for item in builds}) == 3
    assert [item.metadata["pointer_register"] for item in builds] == ["rsi", "rdi", "rbx"]
    assert all(transport.decode_xor_body(item) == body for item in builds)
    repeat = transport.build_xor_decoder(body, architecture="amd64", key=0x5A, variant=2)
    assert repeat.payload == builds[2].payload
    assert repeat.placements == builds[2].placements


def test_xor_constraints_fail_closed() -> None:
    with pytest.raises(BuildError, match="1..255"):
        transport.build_xor_decoder(b"A" * 256, architecture="i386")
    with pytest.raises(BuildError, match="non-zero"):
        transport.build_xor_decoder(b"A", architecture="i386", key=0)
    with pytest.raises(BuildError, match="no XOR decoder"):
        transport.build_xor_decoder(b"A", architecture="amd64", bad_bytes={0xEB})
    with pytest.raises(BuildError, match="variant"):
        transport.build_xor_decoder(b"A", architecture="amd64", variant=3)
    with pytest.raises(BuildError, match="expects"):
        transport.decode_xor_body(PayloadBuild(b"x", {}, strategy="not-xor"))


@pytest.mark.parametrize("variant", range(3))
def test_alphanumeric_transport_variants_roundtrip(variant: int) -> None:
    raw = b"\x00R5B\xff transport\n"
    build = transport.build_transport_encoding(raw, mode="alphanumeric", variant=variant)
    assert build.payload and all(chr(value).isalnum() and value < 128 for value in build.payload)
    assert transport.decode_transport_encoding(build) == raw
    plan = json.loads(build.metadata["decoder_plan"])
    assert plan["executable_decoder_included"] is False
    assert build.metadata["executable"] == "false"
    assert build.slice("encoded_transport") == build.payload


@pytest.mark.parametrize("variant", range(2))
def test_printable_transport_variants_roundtrip(variant: int) -> None:
    raw = bytes(range(1, 96))
    build = transport.build_transport_encoding(raw, mode="printable", variant=variant)
    assert all(0x21 <= value <= 0x7E for value in build.payload)
    assert transport.decode_transport_encoding(build) == raw
    assert json.loads(build.metadata["constraints"])["transport_only"] is True


def test_transport_bad_byte_search_and_rejection_are_deterministic() -> None:
    # Lowercase hex is rejected, so deterministic search moves to uppercase.
    build = transport.build_transport_encoding(
        b"\xab", mode="alphanumeric", variant=None, bad_bytes={ord("a"), ord("b")},
    )
    assert build.payload == b"AB"
    assert build.metadata["codec"] == "hex-upper"
    assert transport.decode_transport_encoding(build) == b"\xab"
    with pytest.raises(BuildError, match="no transport variant"):
        transport.build_transport_encoding(
            b"A", mode="alphanumeric", bad_bytes=set(range(0x30, 0x7B)),
        )
    with pytest.raises(BuildError, match="mode"):
        transport.build_transport_encoding(b"A", mode="binary")


def _hunter(architecture: str, *, variant: int = 0, probe: str = "mapped") -> PayloadBuild:
    kwargs: dict[str, object] = {}
    if probe == "access":
        kwargs.update(
            access_syscall=33 if architecture == "i386" else 21,
            expected_efault=14,
        )
    return transport.build_linux_egghunter(
        architecture=architecture,
        tag=b"R5B!",
        stage=b"STAGE",
        separation=b"XYZ",
        payload_address=0x100000,
        range_start=0x100000,
        range_end=0x101000,
        probe=probe,
        variant=variant,
        **kwargs,
    )


@pytest.mark.parametrize(
    ("architecture", "probe"),
    (("i386", "mapped"), ("i386", "access"),
     ("amd64", "mapped"), ("amd64", "access"),
     ("aarch64", "mapped")),
)
def test_linux_hunter_has_exact_bounded_egg_and_constraint_plan(
    architecture: str, probe: str,
) -> None:
    build = _hunter(architecture, probe=probe)
    assert build.slice("egg.first") == b"R5B!"
    assert build.slice("egg.second") == b"R5B!"
    assert build.slice("stage") == b"STAGE"
    assert build.slice("separation") == b"XYZ"
    assert build.absolute_placements()["egg.first"] == 0x100000 + build.placements["egg.first"]
    plan = json.loads(build.metadata["constraint_plan"])
    assert plan["scan_start"] == 0x100000
    assert plan["scan_end"] == 0x101000
    assert plan["read_width"] == 8
    assert plan["probe"] == probe
    assert plan["scan_start"] <= plan["egg_address"] < plan["scan_end"]
    if architecture in {"i386", "amd64"}:
        assert plan["direction_flag"].startswith("DF must be clear")
        assert plan["clobbers"]
    else:
        assert "direction_flag" not in plan
    if probe == "access":
        expected = 33 if architecture == "i386" else 21
        assert int.from_bytes(build.slice("hunter.access_syscall"), "little") == expected
        assert build.slice("hunter.efault_low_byte") == b"\xf2"
    else:
        assert "hunter.access_syscall" not in build.placements


@pytest.mark.parametrize("architecture", ("i386", "amd64", "aarch64"))
def test_linux_hunter_polymorphic_variants_differ_but_keep_placement_contract(
    architecture: str,
) -> None:
    first = _hunter(architecture, variant=0)
    second = _hunter(architecture, variant=1)
    assert first.payload != second.payload
    assert first.slice("egg.first") == second.slice("egg.first") == b"R5B!"
    assert first.slice("stage") == second.slice("stage") == b"STAGE"
    assert first.metadata["polymorphic_variant"] == "0"
    assert second.metadata["polymorphic_variant"] == "1"
    for item in (first, second):
        payload, placements = item
        assert payload == item.payload and dict(placements) == dict(item.placements)
        assert all(0 <= offset <= len(payload) for offset in placements.values())


def test_linux_hunter_rejects_ambiguous_or_unsafe_assumptions() -> None:
    common = dict(
        architecture="amd64", tag=b"R5B!", stage=b"X",
        payload_address=0x100000, range_start=0x100000, range_end=0x101000,
    )
    with pytest.raises(BuildError, match="requires caller-supplied"):
        transport.build_linux_egghunter(**common, probe="access")
    with pytest.raises(BuildError, match="does not accept"):
        transport.build_linux_egghunter(**common, probe="mapped", access_syscall=21)
    with pytest.raises(BuildError, match="only mapped"):
        transport.build_linux_egghunter(
            **{**common, "architecture": "aarch64"}, probe="access",
            access_syscall=48, expected_efault=14,
        )
    with pytest.raises(BuildError, match="outside"):
        transport.build_linux_egghunter(
            **{**common, "range_start": 0x100800, "range_end": 0x101000},
        )
    with pytest.raises(BuildError, match="forbidden"):
        transport.build_linux_egghunter(**common, bad_bytes={ord("R")})
    with pytest.raises(BuildError, match="four bytes"):
        transport.build_linux_egghunter(**{**common, "tag": b"BAD"})


def test_every_public_builder_returns_shared_payload_contract() -> None:
    samples = (
        transport.build_xor_decoder(b"R5B", architecture="i386"),
        transport.build_transport_encoding(b"R5B", mode="printable"),
        _hunter("amd64"),
    )
    for build in samples:
        assert isinstance(build, PayloadBuild)
        assert isinstance(build.payload, bytes)
        assert build.metadata["delivery"] == "none"
        assert all(label in build.placements for label in build.widths)
