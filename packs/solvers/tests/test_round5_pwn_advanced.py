from __future__ import annotations

import json
import random
import struct
import sys
from pathlib import Path

import pytest


TOOLKITS = Path(__file__).resolve().parents[1] / "solvers" / "toolkits"
sys.path.insert(0, str(TOOLKITS))
import pwn_advanced as A  # noqa: E402
import pwn_exploit as X  # noqa: E402


def test_glibc_feature_boundaries_are_explicit():
    assert not A.glibc_features("2.25")["tcache"]
    assert A.glibc_features("2.26")["tcache"]
    assert not A.glibc_features("2.31")["safe_linking"]
    assert A.glibc_features("2.32")["safe_linking"]
    assert A.glibc_features("2.33")["malloc_free_hooks"]
    assert not A.glibc_features("2.34")["malloc_free_hooks"]


def test_tcache_and_fastbin_safe_linking_crosscheck_existing_engine():
    position, target = 0x5555555592A0, 0x55555555A000
    plan = A.heap_plan("tcache_poison", glibc_version="2.37", request_size=0x38,
                       fd_position=position, target=target)
    assert plan.computed["chunk_size"] == X.request2size(0x38)
    assert plan.computed["stored_fd"] == X.safe_link_mangle(position, target)
    assert plan.arithmetic_verified and not plan.exploitability_verified
    with pytest.raises(A.PwnPlanError, match="fd_position"):
        A.heap_plan("tcache_poison", glibc_version="2.37", target=target)

    fast = A.heap_plan("fastbin_dup", glibc_version="2.31", request_size=0x20,
                       target=0x404040)
    assert fast.computed["stored_fd"] == 0x404040
    assert any("tcache" in item for item in fast.prerequisites)


def test_unsorted_leak_only_promotes_page_aligned_exact_offset():
    plan = A.heap_plan("unsorted_bin_leak", glibc_version="2.35", request_size=0x500,
                       leak=0x7FFFF7FC0BE0, arena_leak_offset=0x1D2BE0)
    assert plan.computed["libc_base"] == 0x7FFFF7DEE000
    assert plan.arithmetic_verified
    with pytest.raises(A.PwnPlanError, match="page aligned"):
        A.heap_plan("unsorted_bin_leak", glibc_version="2.35", request_size=0x500,
                    leak=0x7FFFF7FC0BE1, arena_leak_offset=0x1D2BE0)
    with pytest.raises(A.PwnPlanError, match="both leak"):
        A.heap_plan("unsorted_bin_leak", glibc_version="2.35", leak=0x7FFFF7FC0BE0)


def test_houses_are_strictly_version_and_layout_gated():
    force = A.heap_plan("house_of_force", glibc_version="2.28", top_chunk=0x100000,
                        target=0x101000)
    assert force.computed["forced_chunk_size"] == 0xFF0
    assert force.computed["candidate_request"] == 0xFE8
    assert X.request2size(force.computed["candidate_request"]) == 0xFF0
    with pytest.raises(A.PwnPlanError, match=">= 2.29"):
        A.heap_plan("house_of_force", glibc_version="2.29", top_chunk=0x100000,
                    target=0x101000)
    with pytest.raises(A.PwnPlanError, match="through glibc 2.23"):
        A.heap_plan("house_of_orange", glibc_version="2.24", io_list_all=1, system=2, fake_file=3)

    einherjar = A.heap_plan("house_of_einherjar", glibc_version="2.35",
                            victim_chunk=0x404100, fake_chunk=0x404000)
    assert einherjar.computed["forged_prev_size"] == 0x100
    with pytest.raises(A.PwnPlanError, match="aligned"):
        A.heap_plan("house_of_einherjar", glibc_version="2.35",
                    victim_chunk=0x404101, fake_chunk=0x404000)

    assert A.heap_plan("house_of_botcake", glibc_version="2.31").computed["tcache_count"] == 7
    with pytest.raises(A.PwnPlanError, match="2.29..2.31"):
        A.heap_plan("house_of_botcake", glibc_version="2.32")


def test_jop_table_serialization_respects_arch_endianness_and_alignment():
    little = A.jop_table("amd64", 0x401000, [0x401100, 0x401200], 0x404000)
    assert little.payload == struct.pack("<QQ", 0x401100, 0x401200)
    big = A.jop_table("mips", 0x400100, [0x400200, 0x400300], 0x100000,
                      endian="big")
    assert big.payload == struct.pack(">II", 0x400200, 0x400300)
    assert not big.exploitability_verified
    with pytest.raises(A.PwnPlanError, match="alignment"):
        A.jop_table("amd64", 0x401001, [0x401100], 0x404000)
    with pytest.raises(A.PwnPlanError, match="unexpected little-endian"):
        A.jop_table("mips", 0x400100, [0x400200], 0x100000, endian="little")
    with pytest.raises(A.PwnPlanError, match="unexpected big-endian"):
        A.jop_table("mipsel", 0x400100, [0x400200], 0x100000, endian="big")


@pytest.mark.parametrize("arch", sorted(A.ABI))
def test_abi_plans_are_review_only(arch):
    plan = A.abi_plan(arch)
    assert plan.computed["abi"]["bits"] in (32, 64)
    assert plan.arithmetic_verified and not plan.exploitability_verified
    assert plan.as_dict()["requires_human_review"] is True


def test_riscv_gadget_hints_and_terminators_are_wired_without_guessing():
    assert X._risc_terminator("riscv", "ret", "")[0]
    assert X._risc_terminator("riscv", "ecall", "")[0]
    useful = X.useful_gadgets({"ld ra, 8(sp) ; ret": [0x1010], "ecall": [0x1020]}, "riscv")
    assert useful["load ra ; ret"][0] == 0x1010
    hints = X.arch_chain_hints({"arch": "riscv", "class": 64, "endian": "little",
                                "exec_sections": [], "_data": b""})
    assert hints["deterministic"] is False
    assert "a7" in hints["approach"][1] and "riscv64" in hints["pwntools"]
    hints32 = X.arch_chain_hints({"arch": "riscv", "class": 32, "endian": "little",
                                  "exec_sections": [], "_data": b""})
    assert 'arch="riscv32"' in hints32["pwntools"]


def test_riscv_ret_crosschecks_local_capstone_when_available():
    capstone = pytest.importorskip("capstone")
    if not hasattr(capstone, "CS_ARCH_RISCV"):
        pytest.skip("local capstone has no RISC-V backend")
    # 0x00008067 = jalr x0, x1, 0, conventionally disassembled as `ret`.
    info = {"arch": "riscv", "class": 64, "endian": "little",
            "exec_sections": [(".text", 0x1000, bytes.fromhex("67800000"))]}
    gadgets = X.find_gadgets(info)
    assert any("ret" in text or "jalr" in text for text in gadgets)
    assert any(0x1000 in addresses for addresses in gadgets.values())


def test_kaslr_requires_two_consistent_leaks_to_mark_verified():
    one = A.kaslr_base([{"address": 0xFFFFFFFF81201000, "offset": 0x201000}])
    assert one["candidate_base"] == 0xFFFFFFFF81000000
    assert not one["verified"]
    two = A.kaslr_base([
        {"address": 0xFFFFFFFF81201000, "offset": 0x201000},
        {"address": 0xFFFFFFFF81345000, "offset": 0x345000},
    ])
    assert two["verified"] and two["candidate_base"] == 0xFFFFFFFF81000000
    inconsistent = A.kaslr_base([
        {"address": 0xFFFFFFFF81201000, "offset": 0x201000},
        {"address": 0xFFFFFFFF81346000, "offset": 0x345000},
    ])
    assert inconsistent["candidate_base"] is None and not inconsistent["verified"]
    repeated = A.kaslr_base([
        {"address": 0xFFFFFFFF81201000, "offset": 0x201000},
        {"address": 0xFFFFFFFF81201000, "offset": 0x201000},
    ])
    assert repeated["candidate_base"] == 0xFFFFFFFF81000000
    assert repeated["independent_leaks"] == 1 and not repeated["verified"]


def test_i386_glibc_alignment_and_tcache_geometry_are_not_amd64_values():
    assert X.request2size(9, bits=32) == 0x10
    assert X.request2size(13, bits=32) == 0x18
    assert X.tcache_index(0x18, bits=32) == 1
    assert X.tcache_index(0x208, bits=32) == 63
    assert "tcache[0]" in X.bin_class(0x10, bits=32)
    with pytest.raises(A.PwnPlanError, match="tcache range"):
        A.heap_plan("tcache_poison", glibc_version="2.31", bits=32,
                    request_size=0x209, target=0x804A000)


def test_srop_ok_requires_complete_trigger_and_nonzero_argument_pointer():
    pytest.importorskip("pwnlib")
    full = {"arch": "amd64", "class": 64, "endian": "little",
            "exec_sections": [(".text", 0x401000, bytes.fromhex("58c30f05c3"))], "_data": b""}
    assert X.build_srop(full, binsh_addr=0x402000).ok is True
    no_pop = dict(full, exec_sections=[(".text", 0x401000, bytes.fromhex("0f05c3"))])
    result = X.build_srop(no_pop, binsh_addr=0x402000)
    assert result.ok is False and result.extra["trigger_complete"] is False
    no_arg = X.build_srop(full)
    assert no_arg.ok is False and no_arg.extra["binsh"] is None
    assert result.as_dict()["sent"] is False and result.as_dict()["executed"] is False


def test_kernel_ret2usr_refuses_active_smep_and_serializes_explicit_state():
    base = dict(arch="amd64", pop_rdi=0xFFFFFFFF81001000,
                prepare_kernel_cred=0xFFFFFFFF81002000, rax_to_rdi=0xFFFFFFFF81003000,
                commit_creds=0xFFFFFFFF81004000, swapgs_iret=0xFFFFFFFF81005000,
                user_rip=0x401000, user_cs=0x33, user_rflags=0x246,
                user_rsp=0x7FFFFFFFE000, user_ss=0x2B)
    with pytest.raises(A.PwnPlanError, match="SMEP/SMAP"):
        A.kernel_plan("ret2usr", mitigations={"smep": True, "smap": False}, **base)
    plan = A.kernel_plan("ret2usr", mitigations={"smep": False, "smap": False}, **base)
    assert len(plan.payload) == 11 * 8
    assert struct.unpack_from("<Q", plan.payload, 8)[0] == 0
    assert not plan.exploitability_verified


def test_kernel_modprobe_and_pt_regs_are_inert_templates():
    modprobe = A.kernel_plan("modprobe_path", arch="amd64", modprobe_path=0xFFFFFFFF8245A2A0,
                             helper_path="/tmp/x")
    assert modprobe.payload == b"/tmp/x\0"
    assert modprobe.computed["write_bytes_hex"] == modprobe.payload.hex()
    pt = A.kernel_plan("pt_regs", arch="amd64")
    assert pt.computed["layout"]["rip"] == 0x80 and pt.payload is None


def test_windows_primitives_reject_wrong_arch_and_build_ambiguity():
    seh = A.windows_plan("seh_overwrite", arch="win32", next_seh="eb069090", handler=0x10012345)
    assert seh.payload == bytes.fromhex("eb069090") + struct.pack("<I", 0x10012345)
    with pytest.raises(A.PwnPlanError, match="32-bit"):
        A.windows_plan("seh_overwrite", arch="win64", next_seh="eb069090", handler=1)
    vp = A.windows_plan("virtualprotect_rop", arch="win64", virtualprotect=0x7FFB00001000,
                        region=0x140010000, size=0x1000, oldprotect=0x140020000,
                        return_to=0x140010100)
    assert vp.computed["new_protect"] == 0x40 and vp.payload is None
    with pytest.raises(A.PwnPlanError, match="exact windows_build"):
        A.windows_plan("token_steal", arch="win64", windows_build="", offsets={})


def test_guarded_cli_and_bad_json(tmp_path, capsys):
    cfg = tmp_path / "heap.json"
    cfg.write_text(json.dumps({"technique": "tcache_poison", "glibc_version": "2.37",
                               "request_size": 0x30, "fd_position": 0x5555555592A0,
                               "target": 0x55555555A000}), encoding="utf-8")
    assert A.main(["heap", str(cfg)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["requires_human_review"] and not result["exploitability_verified"]
    bad = tmp_path / "bad.json"
    bad.write_bytes(b"[" * 10000)
    assert A.main(["heap", str(bad)]) == 2
    err = capsys.readouterr().err
    assert err.startswith("pwn_advanced: ") and "Traceback" not in err


def test_dispatch_mutation_fuzz_5000_cases_no_unbounded_output():
    rng = random.Random(0x50574E)
    families = ["heap", "abi", "jop", "kernel", "windows", "bad"]
    techniques = ["tcache_poison", "fastbin_dup", "unsorted_bin_leak", "house_of_force",
                  "house_of_einherjar", "house_of_botcake", "ret2usr", "pt_regs",
                  "seh_overwrite", "virtualprotect_rop", "nonsense"]
    scalars = [None, True, False, -1, 0, 1, "", "2.37", "0x404000", [], {}, 1 << 100]
    for _ in range(5000):
        config = {
            "technique": rng.choice(techniques),
            "glibc_version": rng.choice(scalars),
            "bits": rng.choice(scalars),
            "request_size": rng.choice(scalars),
            "arch": rng.choice(scalars),
            "target": rng.choice(scalars),
            "fd_position": rng.choice(scalars),
        }
        try:
            plan = A.build(rng.choice(families), config)
            rendered = plan.as_dict()
            assert rendered["payload_length"] <= A.MAX_JSON
            assert rendered["exploitability_verified"] is False
        except (A.PwnPlanError, ValueError, TypeError, OverflowError, struct.error):
            pass
