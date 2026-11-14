"""B-074: stack-string collection in solvers/binary/xor_strings.py.

A stack string is built character by character at runtime, so its bytes sit at a fixed stride among
the instruction bytes that move them and a plain `strings` run misses it. These tests pin that the
collector reads the interleaved run, refuses to re-report a contiguous run `strings` would already
show, and honours a flag crib. CTF_EVENT defaults to csctf in conftest, so flagfmt resolves.
"""
import xor_strings as xs


def _interleave(text: bytes, stride: int, filler: int = 0x00) -> bytes:
    out = bytearray()
    for ch in text:
        out.append(ch)
        out += bytes([filler]) * (stride - 1)
    return bytes(out)


def test_finds_interleaved_stack_string():
    blob = b"\x90\x91" + _interleave(b"CSCTF{stack_me}", 2) + b"\x92"
    hits = xs.stack_strings(blob, min_len=5, max_stride=4)
    assert any(h["text"] == "CSCTF{stack_me}" and h["stride"] == 2 for h in hits)


def test_flag_shaped_stack_string_ranks_first():
    blob = _interleave(b"NOTAFLAGVALUEHERE", 3) + b"\x00" + _interleave(b"CSCTF{top}", 3)
    hits = xs.stack_strings(blob, min_len=4, max_stride=3)
    assert "{" in hits[0]["text"]


def test_contiguous_run_is_not_reported_as_a_hidden_stride_string():
    # a plain contiguous ASCII run: strings already shows it, so stride>1 must not claim it
    blob = b"........PLAINTEXTWORD........"
    hits = xs.stack_strings(blob, min_len=5, max_stride=4)
    assert all(not (h["stride"] > 1 and h["text"] == "PLAINTEXTWORD") for h in hits)


def test_printable_filler_does_not_count_as_hidden():
    # filler is a printable '.', so the stride-2 read is just a subsequence strings could reach; the
    # "a skipped byte is non-printable" rule drops it.
    blob = _interleave(b"ABCDEFGH", 2, filler=ord("."))
    assert not any(h["stride"] == 2 and h["text"] == "ABCDEFGH"
                   for h in xs.stack_strings(blob, min_len=5, max_stride=4))


def test_stack_flag_candidates_filters_to_flag_shape():
    blob = _interleave(b"CSCTF{crib}", 2) + b"\x00" + _interleave(b"justnoise", 2)
    cands = xs.stack_flag_candidates(blob)
    assert [c["text"] for c in cands] == ["CSCTF{crib}"]


def test_stack_flag_candidates_honours_an_explicit_crib():
    blob = _interleave(b"KEY-abcdef", 2)
    cands = xs.stack_flag_candidates(blob, pattern=r"KEY-[a-f]+")
    assert any(c["text"] == "KEY-abcdef" for c in cands)


def test_fail_closed():
    assert xs.stack_strings(b"") == []
    assert xs.stack_strings("not bytes") == []
    assert xs.stack_strings(b"x" * 10, min_len=2) == []    # min_len < 3 rejected
    assert xs.stack_strings(b"x" * 10, max_stride=0) == []


def test_cli_stack_mode(tmp_path, capsys):
    f = tmp_path / "bin"
    f.write_bytes(_interleave(b"CSCTF{cli_stack}", 2))
    assert xs.main([str(f), "--stack", "--json"]) == 0
    import json
    out = json.loads(capsys.readouterr().out)
    assert any(o["text"] == "CSCTF{cli_stack}" for o in out)
