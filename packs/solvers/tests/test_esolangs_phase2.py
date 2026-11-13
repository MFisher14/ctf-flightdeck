from __future__ import annotations

import pytest

from solvers.warmups.esolangs_phase2 import (
    Refuse,
    identify_esolangs,
    run_kipple,
    run_whirl,
)


OFFICIAL_WHIRL_ADD = """\
011000001111000011111000001111000011111000001111000
011111000001100100000110011111000111000111100011001
11000000000111110001000111110011001111100010001100
"""


def _whirl_commands(*commands: tuple[str, int]) -> str:
    """Build a straight-line fixture while tracking the two ring positions."""

    positions = {"operations": 0, "math": 0}
    active = "operations"
    chunks: list[str] = []
    for ring, target in commands:
        assert ring == active
        rotations = (target - positions[ring]) % 12
        chunks.append("1" * rotations + "00")
        positions[ring] = target
        active = "math" if active == "operations" else "operations"
    return "".join(chunks)


def test_whirl_reference_program_and_zero_latch() -> None:
    result = run_whirl(OFFICIAL_WHIRL_ADD, integer_input=[7, 8])
    assert result["output"] == "15"
    assert result["stop_reason"] == "end_of_program"
    assert result["input_consumed"] == {"integers": 2, "characters": 0}

    latch = run_whirl("0000")
    assert latch["command_executions"] == 2
    assert latch["active_ring"] == "operations"
    assert [event["ring"] for event in latch["trace"]] == ["operations", "math"]


def test_whirl_logic_and_terminating_state_match_reference() -> None:
    # Read 2 into memory, load it into the operations value, then Logic with a
    # nonzero memval.  C logical && normalizes even 2 to one (not bitwise 2&1).
    program = _whirl_commands(
        ("operations", 10),
        ("math", 0),
        ("operations", 4),
        ("math", 0),
        ("operations", 8),
    )
    result = run_whirl(program, integer_input=[2])
    assert result["ring_values"]["operations"] == 1
    assert result["memory"]["0"] == 2

    # Rotate Operations to Exit and execute it at source offset 2.  The C++
    # reference returns before incrementing PC or switching rings.
    stopped = run_whirl("100")
    assert stopped["stop_reason"] == "exit"
    assert stopped["program_counter"] == 2
    assert stopped["active_ring"] == "operations"


def test_whirl_hard_caps_missing_input_and_byte_io() -> None:
    with pytest.raises(Refuse, match="bounded sequence"):
        run_whirl("0", integer_input=(value for value in range(3)))  # type: ignore[arg-type]
    with pytest.raises(Refuse, match="byte/ASCII"):
        run_whirl("0", character_input="λ")
    with pytest.raises(Refuse, match="unavailable integer"):
        run_whirl(_whirl_commands(("operations", 10)))
    assert run_whirl("111111", max_steps=3)["stop_reason"] == "step_limit"


def test_kipple_official_examples_and_compact_loop_controller() -> None:
    hello = "33>o 100>o 108>o 114>o 111>o 87>o 32>o 111>o 108>o 108>o 101>o 72>o"
    assert run_kipple(hello)["output"] == "Hello World!"
    assert run_kipple('"Hello World!">o')["output"] == "Hello World!"
    assert run_kipple("(i>o)", input_text="saved input")["output"] == "saved input"
    assert run_kipple("100>@ (@>o)")["output"] == "100"


def test_kipple_chain_single_pop_same_stack_and_trailing_clear() -> None:
    shared = run_kipple("7>b 9>b a<b>c")
    assert shared["stacks"] == {"a": [9], "b": [7], "c": [9]}

    same = run_kipple("2>a 3>a a+a")
    assert same["stacks"]["a"] == [2, 5]

    trailing = run_kipple("1>a 0>c a>b<c? 65>o")
    assert trailing["output"] == "A"
    assert "c" not in trailing["stacks"]
    assert run_kipple("@?")["stacks"] == {}


def test_kipple_string_direction_ascii_and_hostile_bounds() -> None:
    assert run_kipple('"Hi">s')["stacks"]["s"] == [ord("i"), ord("H")]
    assert run_kipple('s<"Hi"')["stacks"]["s"] == [ord("H"), ord("i")]
    assert run_kipple("ignoredbaretext 65>o")["output"] == "A"
    with pytest.raises(Refuse, match="ASCII byte"):
        run_kipple("256>o")
    with pytest.raises(Refuse, match="32-bit"):
        run_kipple("9" * 5_000 + ">a")
    with pytest.raises(Refuse, match="step bound"):
        run_kipple("1>a (a)", max_steps=4)
    with pytest.raises(Refuse, match="stack-item"):
        run_kipple("1>a 2>b", max_stack_items=1)


def test_identifiers_require_structural_evidence() -> None:
    whirl = identify_esolangs("01100000111100001100", filename="challenge.wrl")
    assert whirl[0]["language"] == "whirl"
    kipple = identify_esolangs("100>@ (@>o)", filename="challenge.kipple")
    assert kipple[0]["language"] == "kipple"
    assert identify_esolangs("ordinary prose with 10 apples") == []
