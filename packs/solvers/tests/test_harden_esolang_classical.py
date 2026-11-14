"""Classical BF/Ook only: known semantics, no engine-generated oracle."""
import random
import pytest
from solvers.common import classical as cl
from test_harden_esolang_esolang import PRINT_A, offline


def test_brainfuck_arithmetic_and_input_eof():
    assert cl.brainfuck(PRINT_A) == b'A'
    assert cl.brainfuck(',.,.,.,.', stdin=b'AB') == b'AB\x00\x00'
    assert cl.brainfuck('--------.') == b'\xf8'


def test_ook_published_token_pairs_and_short_form():
    # Original Ook command substitutions, independently enumerated.
    source = 'Ook. Ook? Ook? Ook. Ook. Ook. Ook! Ook! Ook! Ook. Ook. Ook! Ook! Ook? Ook? Ook!'
    assert cl.ook_to_brainfuck(source) == '><+-.,[]'
    assert cl.ook_to_brainfuck('.??...!!!..!!??!') == '><+-.,[]'
    program = 'Ook. Ook. '*65+'Ook! Ook.'
    assert cl.brainfuck(cl.ook_to_brainfuck(program)) == b'A'


@pytest.mark.parametrize('code', ['+[.]++++', '<.++++++', '[+.+++++', ']++.++++'])
def test_brainfuck_nontermination_brackets_and_pointer_fail_closed(code):
    assert cl.brainfuck(code, steps=32) is None


def test_deterministic_text_fuzz_and_oversize_small_steps():
    rng = random.Random(808)
    for text in ['', '\uffff'*32, 'Ook. Ook?', 'Ook? '*19, PRINT_A[:-1], '+'*65537+'.'] + [
            ''.join(rng.choice('+-<>[].,Ook!? \n\xff') for _ in range(size)) for size in [8, 32, 256]]:
        result = cl.brainfuck(text, steps=100)
        assert result is None or isinstance(result, bytes)
        result = cl.ook_to_brainfuck(text)
        assert result is None or isinstance(result, str)


def test_brainfuck_output_cap_checked_after_last_instruction():
    output = cl.brainfuck('.'*65537, steps=65538)
    assert output is None or len(output) <= 65536


@pytest.mark.parametrize('fn', [cl.brainfuck, cl.ook_to_brainfuck])
def test_nontext_fail_closed(fn):
    fn(None)
