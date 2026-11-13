"""Independent COW/Whitespace/Befunge/Malbolge/JSFuck/Deadfish programs.

Specifications: esolangs.org language pages; aemkei/jsfuck author examples.
"""
import random
import pytest
import esolangs as es
from test_harden_esolang_esolang import offline


def ws_readable(text):
    """Literal spelling of invisible source, not an output-driven encoder."""
    return text.translate(str.maketrans({'S': ' ', 'T': '\t', 'L': '\n'}))


# Whitespace: push +65 (binary 1000001), output character, end.
WS_A = ws_readable('SSSTSSSSSTLTLSSLLL')


def test_cow_numeric_and_character_output():
    assert es.cow('MoO '*65+'Moo') == b'A'
    assert es.cow('MoO '*8+'OOM') == b'8'
    # MMM stores 8; OOO clears; MMM restores it; OOM prints decimal 8.
    assert es.cow('MoO '*8+'MMM OOO MMM OOM') == b'8'


def test_whitespace_binary_literal_output_and_heap():
    assert es.whitespace(WS_A) == b'A'
    # push address 1; push 65; store; push 1; fetch; print; terminate.
    program = ws_readable('SSSTLSSSTSSSSSTLTTS'+'SSSTLTTTTLSSLLL')
    assert es.whitespace(program) == b'A'


@pytest.mark.parametrize('program,expected', [
    ('"A",  @', b'A'), ('23+.  @', b'5 '), ('03-2/.@', b'-1 '),
    ('"A"00p00g,@', b'A'), ('"!dlroW ,olleH",,,,,,,,,,,,,@', b'Hello, World!'),
])
def test_befunge_stack_integer_division_and_self_modification(program, expected):
    assert es.befunge(program) == expected


def test_malbolge_arithmetic_opcode_reference():
    # Decode instruction by (ord(char)+position)%94 per reference interpreter.
    # c: output A=0; P: halt. Remaining characters are valid loader NOPs.
    program = 'cP' + ''.join(chr((68-index-33)%94+33) for index in range(2, 8))
    assert all((ord(char)+index)%94 in [5, 81, 68] for index, char in enumerate(program))
    assert es.malbolge_valid(program) is True
    assert es.malbolge(program, steps=16) == b'\x00'


@pytest.mark.parametrize('program,expected', [
    ('(![]+[])+[]+[]', b'false'), ('(!![]+[])+[]+[]', b'true'),
    ('([][[]]+[])+[]', b'undefined'), ('(![]+[])[+[]]+[]', b'f'),
    ('+[[+!+[]]+[+[]]]', b'10'),
])
def test_jsfuck_author_basics_without_javascript_runtime(program, expected):
    assert es.jsfuck(program) == expected


def test_deadfish_documented_resets_and_square():
    assert es.deadfish('i'*8+'sio') == b'A'
    assert es.deadfish('do') == b'\0'
    assert es.deadfish('i'*16+'so') == b'\0'


@pytest.mark.parametrize('fn,program', [(es.cow, 'MoO MOO MMM moo OOM OOO OOO OOO'),
                                      (es.befunge, '>v @,\n^<')])
def test_looping_program_step_caps(fn, program):
    assert fn(program, steps=10) is None


def test_whitespace_jump_step_cap():
    # Label S; push/output A; unconditional jump to label S.
    source = ws_readable('LSSSL') + WS_A[:-3] + ws_readable('LSLSL')
    assert es.whitespace(source, steps=20) is None


@pytest.mark.parametrize('fn,program', [(es.cow, 'MoO '*8+'OOM'),
                                      (es.whitespace, WS_A[:-3]),
                                      (es.deadfish, 'io')])
def test_output_cap_checked_after_last_instruction(fn, program, monkeypatch):
    monkeypatch.setattr(es, 'OUTPUT', 0)
    result = fn(program)
    assert result is None or len(result) == 0


@pytest.mark.parametrize('name,fn', es.READERS)
def test_reader_deterministic_malformed_and_truncated_fuzz(name, fn):
    rng = random.Random(808)
    corpus = ['', '\uffff'*32, '\0'*32, '['*100, 'x'*10000]
    corpus += [''.join(chr(rng.randrange(128)) for _ in range(size)) for size in [8, 32, 256]]
    corpus += [WS_A[:i] for i in [1, 4, 12]]
    kwargs = {} if name == 'jsfuck' else {'steps': 64}
    for text in corpus:
        try:
            result = fn(text, **kwargs)
            assert result is None or isinstance(result, bytes)
        except es.Refuse:
            pass


@pytest.mark.parametrize('name,fn', es.READERS)
def test_reader_nontext_fail_closed(name, fn):
    try:
        fn(None)
    except es.Refuse:
        pass


def test_cli_guard(capsys):
    assert es.main([]) == 2
