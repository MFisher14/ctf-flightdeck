from __future__ import annotations

import pytest

from solvers.warmups import esolangs_remaining as E


def _aheui_print_a() -> str:
    push4 = E.compose_aheui(7, 0, 16)   # ㅂ + ㅁ = four strokes
    push3 = E.compose_aheui(7, 0, 7)    # ㅂ + ㄷ = three strokes
    push2 = E.compose_aheui(7, 0, 1)    # ㅂ + ㄱ = two strokes
    multiply = E.compose_aheui(4, 0, 0)
    subtract = E.compose_aheui(16, 0, 0)
    add = E.compose_aheui(3, 0, 0)
    out_char = E.compose_aheui(6, 0, 27)
    halt = E.compose_aheui(18, 0, 0)
    # 4*4*4 + (3-2) = 65 = "A".
    return push4 + push4 + multiply + push4 + multiply + push3 + push2 + subtract + add + out_char + halt


def test_aheui_arithmetic_output_and_conservative_identification():
    source = _aheui_print_a()
    report = E.run_aheui(source)
    assert report["halted"] is True
    assert report["output_hex"] == "41" and report["output_text"] == "A"
    assert report["candidate_only"] is True and report["requires_human_review"] is True
    assert E.identify_aheui(source)["strong_match"] is False
    identified = E.identify_aheui(source, filename="fixture.aheui")
    assert identified["strong_match"] is True and identified["has_halt"] is True


def test_aheui_official_multiline_hello_world_reference_program():
    source = "\n".join((
        "밤밣따빠밣밟따뿌", "빠맣파빨받밤뚜뭏", "돋밬탕빠맣붏두붇", "볻뫃박발뚷투뭏붖",
        "뫃도뫃희멓뭏뭏붘", "뫃봌토범더벌뿌뚜", "뽑뽀멓멓더벓뻐뚠", "뽀덩벐멓뻐덕더벅",
    ))
    report = E.run_aheui(source)
    assert report["output_text"] == "Hello, world!\n" and report["halted"] is True


def test_aheui_queue_and_explicit_character_input():
    right = 0
    select_queue = E.compose_aheui(9, right, E.QUEUE_STORAGE)
    push2 = E.compose_aheui(7, right, 1)
    push3 = E.compose_aheui(7, right, 7)
    add = E.compose_aheui(3, right, 0)
    out_integer = E.compose_aheui(6, right, E.QUEUE_STORAGE)
    halt = E.compose_aheui(18, right, 0)
    report = E.run_aheui(select_queue + push2 + push3 + add + out_integer + halt)
    assert report["output_text"] == "5"

    push_input_char = E.compose_aheui(7, right, E.EXTENSION_STORAGE)
    out_char = E.compose_aheui(6, right, E.EXTENSION_STORAGE)
    report = E.run_aheui(push_input_char + out_char + halt, char_input="λ")
    assert report["output_text"] == "λ"


def test_aheui_queue_swap_duplicate_and_signed_divmod_semantics():
    right = 0
    select_queue = E.compose_aheui(9, right, E.QUEUE_STORAGE)
    push2 = E.compose_aheui(7, right, 1)
    push3 = E.compose_aheui(7, right, 7)
    swap = E.compose_aheui(17, right, 0)
    duplicate = E.compose_aheui(8, right, 0)
    out_integer = E.compose_aheui(6, right, E.QUEUE_STORAGE)
    halt = E.compose_aheui(18, right, 0)
    queue = E.run_aheui(select_queue + push2 + push3 + swap + duplicate
                         + out_integer * 3 + halt)
    assert queue["output_text"] == "323"

    subtract = E.compose_aheui(16, right, 0)
    divide = E.compose_aheui(2, right, 0)
    modulo = E.compose_aheui(5, right, 0)
    # (2 - 3) // 2 follows the reference specification's floor operation.
    division = E.run_aheui(push2 + push3 + subtract + push2 + divide + out_integer + halt)
    remainder = E.run_aheui(push2 + push3 + subtract + push2 + modulo + out_integer + halt)
    assert division["output_text"] == "-1" and remainder["output_text"] == "1"


def test_aheui_underflow_reflects_before_absolute_vowel_and_surrogates_decline():
    # Underflow reverses momentum, then absolute ㅏ sets it right again, reaching halt.
    underflow_pop_right = E.compose_aheui(6, 0, 0)
    halt = E.compose_aheui(18, 0, 0)
    assert E.run_aheui(underflow_pop_right + halt)["steps"] == 2

    push_input_char = E.compose_aheui(7, 0, E.EXTENSION_STORAGE)
    out_char = E.compose_aheui(6, 0, E.EXTENSION_STORAGE)
    with pytest.raises(E.Refuse, match="Unicode scalar"):
        E.run_aheui(push_input_char + out_char + halt, char_input="\ud800")


def test_aheui_declines_extension_storage_and_bad_bounds():
    select_extension = E.compose_aheui(9, 0, E.EXTENSION_STORAGE)
    halt = E.compose_aheui(18, 0, 0)
    with pytest.raises(E.Refuse, match="extension-protocol"):
        E.run_aheui(select_extension + halt)
    with pytest.raises(E.Refuse, match="cell bound"):
        E.run_aheui("가" * (E.MAX_CELLS + 1))
    with pytest.raises(E.Refuse):
        E.compose_aheui(19)


def test_snusp_linear_mirror_skip_input_and_detection():
    first = "$" + "+" * 65 + "\\"
    source = first + "\n" + " " * (len(first) - 1) + "."
    report = E.run_snusp(source)
    assert report["halted"] is True and report["output_text"] == "A"

    assert E.run_snusp("$,.", b"Z")["output_text"] == "Z"
    assert E.run_snusp("$+!.")["output_hex"] == ""
    assert E.run_snusp("$?+.")["output_hex"] == "00"
    assert E.identify_snusp("$+++\\")["strong_match"] is True
    assert E.identify_snusp("+++++.")["strong_match"] is False


def test_snusp_modular_call_return_bridge_and_cell_wrap():
    # @ saves the cell after itself; the call-path mirror is skipped on # return.
    source = "$@\\.\n  + \n  # "
    report = E.run_snusp(source)
    assert report["output_hex"] == "01" and report["call_depth"] == 0
    assert E.run_snusp("$-.")["output_hex"] == "ff"


def test_snusp_fails_closed_on_pointer_and_step_caps():
    with pytest.raises(E.Refuse, match="negative"):
        E.run_snusp("$<")
    # The bounded interpreter refuses before walking an overlong straight path.
    with pytest.raises(E.Refuse, match="step cap"):
        E.run_snusp("$" + "+" * 100, steps=20)


def test_memory_input_and_output_caps_are_enforced_before_growth(monkeypatch):
    monkeypatch.setattr(E, "MAX_STORAGE", 3)
    with pytest.raises(E.Refuse, match="number input"):
        E.run_aheui(E.compose_aheui(18), number_input=iter(lambda: 1, None))
    push2 = E.compose_aheui(7, 0, 1)
    with pytest.raises(E.Refuse, match="storage value cap"):
        E.run_aheui(push2 * 4 + E.compose_aheui(18))
    with pytest.raises(E.Refuse, match="tape cap"):
        E.run_snusp("$>>>")

    monkeypatch.setattr(E, "MAX_OUTPUT", 1)
    with pytest.raises(E.Refuse, match="output cap"):
        E.run_snusp("$+..")


def test_guarded_cli(tmp_path, capsys):
    assert E.main([]) == 2
    assert "esolangs_remaining:" in capsys.readouterr().err
    source = tmp_path / "fixture.snusp"
    source.write_text("$" + "+" * 65 + ".", encoding="utf-8")
    assert E.main(["snusp", str(source)]) == 0
    assert '"output_text": "A"' in capsys.readouterr().out
