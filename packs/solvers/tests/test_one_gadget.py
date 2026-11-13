"""Tests for local libc identity and conservative one-gadget planning."""
from pathlib import Path
import hashlib
import struct
import sys

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import one_gadget as one  # noqa: E402
from contract import BuildError  # noqa: E402


BUILD_ID = bytes.fromhex("00112233445566778899aabbccddeeff01020304")


def _libc_fixture():
    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + b"\x00" * 8
    phoff, phnum, code_offset = 64, 2, 64 + 2 * 56
    code = b"\x90" * 0x100
    note = struct.pack("<III", 4, len(BUILD_ID), 3) + b"GNU\x00" + BUILD_ID
    note_offset = code_offset + len(code)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH", 3, 62, 1, 0x1000, phoff, 0, 0, 64, 56, phnum, 0, 0, 0
    )
    load = struct.pack(
        "<IIQQQQQQ", 1, 5, code_offset, 0x1000, 0x1000, len(code), len(code), 0x1000
    )
    notes = struct.pack(
        "<IIQQQQQQ", 4, 4, note_offset, 0, 0, len(note), len(note), 4
    )
    return header + load + notes + code + note


def _word(build, label):
    return int.from_bytes(build.slice(label), "little")


def test_static_libc_identity_reads_build_id_hash_and_executable_ranges(tmp_path):
    fixture = _libc_fixture()
    path = tmp_path / "libc.so.6"
    path.write_bytes(fixture)
    identity = one.identify_libc(path)
    assert identity.sha256 == hashlib.sha256(fixture).hexdigest()
    assert identity.build_id == BUILD_ID.hex()
    assert identity.bits == 64 and identity.machine == "amd64"
    assert identity.executable_ranges == ((0x1000, 0x1100),)
    assert identity.contains_executable_offset(0x1010)
    assert not identity.contains_executable_offset(0x2000)


def test_parse_local_one_gadget_style_output_is_bounded_and_stable():
    parsed = one.parse_one_gadget_output(
        """0x1010 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  [rsp+0x20] == NULL || rax == NULL

0x1050 posix_spawn(rsp+0x30, ...)
constraints:
  address rbp-0x10 is writable
"""
    )
    assert [item.offset for item in parsed] == [0x1010, 0x1050]
    assert parsed[0].constraints == ("rsp & 0xf == 0", "[rsp+0x20] == NULL || rax == NULL")


def test_constraint_solver_assigns_controlled_state_and_selects_first_provable_or_branch():
    argv_fact = '{"/bin/sh", rdi, NULL} is a valid argv'
    constraints = (
        "rsp & 0xf == 0",
        "[rsp+0x20] == NULL || rax == NULL",
        "rcx == NULL",
        "address rbp-0x10 is writable",
        argv_fact,
    )
    solution = one.solve_one_gadget_constraints(
        constraints,
        register_state={"rbp": 0x8000, "rax": 1, "rcx": 9},
        controllable_registers={"rax", "rcx"},
        stack_pointer=0x7000,
        controllable_stack_offsets={0x20},
        writable_ranges=((0x7F00, 0x8100),),
        facts={argv_fact},
    )
    assert solution.satisfiable
    assert solution.stack_assignments == ((0x20, 0),)
    assert solution.register_assignments == (("rcx", 0),)
    assert solution.chosen_branches[1] == "[rsp+0x20] == NULL"


def test_constraint_solver_rejects_conflicting_register_and_stack_requirements():
    register_conflict = one.solve_one_gadget_constraints(
        ("rax == NULL", "rax == 1"),
        register_state={"rax": 0},
        controllable_registers={"rax"},
        stack_pointer=0x7000,
    )
    assert not register_conflict.satisfiable
    assert "conflicting requirement for rax" in register_conflict.reasons[0]

    stack_conflict = one.solve_one_gadget_constraints(
        ("[rsp+0x20] == NULL", "[rsp+0x20] == 1"),
        register_state={},
        stack_pointer=0x7000,
        stack_state={0x20: 0},
        controllable_stack_offsets={0x20},
    )
    assert not stack_conflict.satisfiable
    assert "conflicting requirement for stack offset +0x20" in stack_conflict.reasons[0]


def test_conflicting_or_trial_rolls_back_before_satisfiable_alternative():
    solution = one.solve_one_gadget_constraints(
        ("rax == NULL", "rax == 1 || rbx == NULL"),
        register_state={"rax": 0, "rbx": 1},
        controllable_registers={"rax", "rbx"},
        stack_pointer=0x7000,
    )
    assert solution.satisfiable
    assert solution.register_assignments == (("rbx", 0),)
    assert solution.chosen_branches == ("rax == NULL", "rbx == NULL")


def test_builder_rejects_wrapping_full_tail_and_accepts_exact_address_space_end():
    limit = 1 << 64
    common = {
        "libc_base": 0x7FFFF7DC0000,
        "gadget_offset": 0x1010,
        "constraints": ("[rsp] == NULL",),
        "register_state": {},
        "controllable_stack_offsets": {0},
    }
    with pytest.raises(BuildError, match="one-gadget payload exceeds the 64-bit address space"):
        one.build_one_gadget_plan(
            _libc_fixture(), **common,
            stack_pointer=limit - 1,
            payload_address=limit - 9,
        )

    boundary = one.build_one_gadget_plan(
        _libc_fixture(), **common,
        stack_pointer=limit - 8,
        payload_address=limit - 16,
    )
    assert len(boundary.payload) == 16
    assert boundary.base_address + len(boundary.payload) == limit
    assert _word(boundary, "stack[+0x0]") == 0


def test_stack_assignment_ranges_reject_overlap_and_adjacent_words_round_trip():
    with pytest.raises(BuildError, match="stack assignment ranges overlap"):
        one.build_one_gadget_plan(
            _libc_fixture(), libc_base=0x7FFFF7DC0000, gadget_offset=0x1010,
            constraints=(
                "[rsp+0x1] == 0x1122334455667788",
                "[rsp+0x2] == 0x99",
            ),
            register_state={}, stack_pointer=0x7000,
            controllable_stack_offsets={1, 2}, payload_address=0x6FF8,
        )

    adjacent = one.build_one_gadget_plan(
        _libc_fixture(), libc_base=0x7FFFF7DC0000, gadget_offset=0x1010,
        constraints=(
            "[rsp+0x1] == 0x1122334455667788",
            "[rsp+0x9] == 0x99aabbccddeeff00",
        ),
        register_state={}, stack_pointer=0x7000,
        controllable_stack_offsets={1, 9}, payload_address=0x6FF8,
    )
    assert _word(adjacent, "stack[+0x1]") == 0x1122334455667788
    assert _word(adjacent, "stack[+0x9]") == 0x99AABBCCDDEEFF00


def test_one_gadget_builder_serializes_loaders_address_and_controlled_stack_tail():
    build = one.build_one_gadget_plan(
        _libc_fixture(),
        libc_base=0x7FFFF7DC0000,
        gadget_offset=0x1010,
        constraints=("rax == NULL", "[rsp+0x20] == NULL", "rsp & 0xf == 0"),
        register_state={"rax": 1},
        stack_pointer=0x7000,
        controllable_registers={"rax"},
        register_loaders={"rax": 0x401100},
        controllable_stack_offsets={0x20},
        overflow_offset=40,
        payload_address=0x6FC0,
    )
    assert _word(build, "loader.rax") == 0x401100
    assert _word(build, "assignment.rax") == 0
    assert _word(build, "one_gadget") == 0x7FFFF7DC1010
    assert _word(build, "stack[+0x20]") == 0
    assert len(build.slice("stack_tail")) == 0x28
    assert build.metadata["libc_build_id"] == BUILD_ID.hex()


def test_solver_and_builder_refuse_unknown_facts_missing_loaders_and_nonexec_offsets():
    failed = one.solve_one_gadget_constraints(
        ('{"/bin/sh", rdi, NULL} is a valid argv',),
        register_state={}, stack_pointer=0x7000,
    )
    assert not failed.satisfiable
    assert "needs an exact caller fact" in failed.reasons[0]

    with pytest.raises(BuildError, match="needs a register loader"):
        one.build_one_gadget_plan(
            _libc_fixture(), libc_base=0x70000000, gadget_offset=0x1010,
            constraints=("rax == NULL",), register_state={"rax": 1},
            stack_pointer=0x7000, controllable_registers={"rax"},
        )
    with pytest.raises(BuildError, match="rsp_at_gadget mismatch"):
        one.build_one_gadget_plan(
            _libc_fixture(), libc_base=0x70000000, gadget_offset=0x1010,
            constraints=("[rsp+0x20] == NULL",), register_state={},
            stack_pointer=0x7000, controllable_stack_offsets={0x20},
            payload_address=0x6FF0,
        )
    with pytest.raises(BuildError, match="not inside an executable"):
        one.build_one_gadget_plan(
            _libc_fixture(), libc_base=0x70000000, gadget_offset=0x2000,
            constraints=(), register_state={}, stack_pointer=0x7000,
        )
    with pytest.raises(BuildError, match="not an ELF"):
        one.identify_libc(b"not libc")

