"""Offline synthetic tests for the two-stage stack-pivot planner."""
import struct
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import pwn_exploit as X  # noqa: E402


def info(blob, arch="amd64", bits=64):
    return {"class": bits, "arch": arch, "endian": "little", "endian_char": "<",
            "exec_sections": [(".text", 0x401000, blob)], "protections": {},
            "symbols": [], "functions": [], "imports": [], "win_candidates": [],
            "sym_values": {}, "got_offsets": {}}


def test_pop_rsp_pivot_is_preferred():
    # pop rsp ; ret, followed by pop rbp ; ret / leave ; ret (the direct pivot wins).
    target = info(bytes.fromhex("5cc3" "5dc3c9c3"))
    chain = X.p64(0xDEADBEEF) + X.p64(0x401234)
    plan = X.build_pivot(target, 0x404800, chain)
    assert plan.ok
    assert plan.extra["strategy"] == "pop rsp ; ret"
    assert plan.raw == X.p64(0x401000) + X.p64(0x404800)
    assert bytes.fromhex(plan.extra["stage2_hex"]) == chain
    assert "STAGE_BUF = 0x404800" in plan.pwntools()


def test_leave_ret_fallback_prepends_new_frame_pointer():
    target = info(bytes.fromhex("5dc3" "c9c3"))
    chain = [0x4141414141414141, 0x4242424242424242]
    plan = X.build_pivot(target, 0x405000, chain)
    assert plan.extra["strategy"] == "pop rbp; leave ; ret"
    assert bytes.fromhex(plan.extra["stage2_hex"]) == X.p64(0) + b"".join(X.p64(v) for v in chain)
    assert struct.unpack("<QQQ", plan.raw) == (0x401000, 0x405000, 0x401002)


def test_missing_pivot_lists_all_required_sequences():
    with pytest.raises(X.ChainError) as caught:
        X.build_pivot(info(bytes.fromhex("c3")), 0x404000, X.p64(0x401234))
    assert len(caught.value.missing) == 3
    assert "pop rsp" in " ".join(caught.value.missing)


def test_invalid_stage_and_unbounded_chain_are_rejected():
    target = info(bytes.fromhex("5cc3"))
    with pytest.raises(X.ChainError):
        X.build_pivot(target, 0, b"x")
    with pytest.raises(X.ChainError):
        X.build_pivot(target, 0x404000, b"x" * (1024 * 1024 + 1))
