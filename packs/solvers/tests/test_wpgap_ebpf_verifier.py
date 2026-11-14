"""Independent saved-log cases for the offline eBPF verifier-state auditor.

Every input below is a literal kernel-log-shaped snippet.  No fixture is emitted
by the engine under test, and the CVE regression text is copied from upstream
Linux commit 92424801261d1564a0bb759da3cf3ccd69fdf5a2.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

import wpgap_ebpf_verifier as verifier


MODERN_CHAINED = """\
0: (b7) r0 = 4
0: R0_w=Pscalar(id=3,smin=umin=smin32=umin32=4,smax=umax=smax32=umax32=15,var_off=(0x4; 0xb)) R1_rw=ctx() R10=fp0
processed 1 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
"""

LEGACY_ALIASES = """\
0: R0=inv(id=3,smin_value=1,smax_value=7,umin_value=1,umax_value=7,s32_min_value=1,s32_max_value=7,u32_min_value=1,u32_max_value=7,var_off=(0x1; 0x6)) R10=fp0
"""

CVE_2024_41003_UPSTREAM = """\
18: (44) w6 |= 2 ; R6_w=scalar(smin=umin=smin32=umin32=2,smax=umax=umax32=0x7fffffff,var_off=(0x2; 0x7ffffffd))
19: (56) if w6 != 0x7ffffffd goto pc+1
REG INVARIANTS VIOLATION (true_reg2): range bounds violation u64=[0x7fffffff, 0x7ffffffd] s64=[0x7fffffff, 0x7ffffffd] u32=[0x7fffffff, 0x7ffffffd] s32=[0x7fffffff, 0x7ffffffd] var_off=(0x7fffffff, 0x0)
REG INVARIANTS VIOLATION (false_reg1): range bounds violation u64=[0x7fffffff, 0x7ffffffd] s64=[0x7fffffff, 0x7ffffffd] u32=[0x7fffffff, 0x7ffffffd] s32=[0x7fffffff, 0x7ffffffd] var_off=(0x7fffffff, 0x0)
REG INVARIANTS VIOLATION (false_reg2): const tnum out of sync with range bounds u64=[0x0, 0xffffffffffffffff] s64=[0x8000000000000000, 0x7fffffffffffffff] u32=[0x0, 0xffffffff] s32=[0x80000000, 0x7fffffff] var_off=(0x7fffffff, 0x0)
19: R6_w=0x7fffffff
"""


def _member(value, name):
    if isinstance(value, dict):
        return value[name]
    return getattr(value, name)


def _findings(report):
    return tuple(_member(report, "findings"))


def _codes(report) -> set[str]:
    return {_member(item, "code") for item in _findings(report)}


def _state_count(report) -> int:
    if isinstance(report, dict):
        if "parsed_states" in report:
            return int(report["parsed_states"])
        return len(report["states"])
    if hasattr(report, "parsed_states"):
        return int(report.parsed_states)
    return len(report.states)


def _assert_offline(report) -> None:
    assert _member(report, "offline") is True
    assert _member(report, "requests_sent") == 0
    assert _member(report, "verifier_acceptance_claimed") is False


def test_modern_chained_bounds_liveness_and_precision_are_valid():
    report = verifier.audit_verifier_log(MODERN_CHAINED)
    assert _state_count(report) >= 1
    assert _findings(report) == ()
    _assert_offline(report)


def test_legacy_inv_and_value_aliases_are_valid():
    report = verifier.audit_verifier_log(LEGACY_ALIASES)
    assert _state_count(report) == 1
    assert _findings(report) == ()


def test_liveness_and_precise_constant_forms_are_not_field_names():
    report = verifier.audit_verifier_log(
        "1: R0_w=P9 R1_rw=ctx() R2_D=scalar(umin=1,umax=3,var_off=(0x1; 0x2)) R10=fp0\n"
    )
    assert _state_count(report) == 1
    assert _findings(report) == ()


def test_current_bare_stack_pointer_register_forms_are_recovered():
    report = verifier.audit_verifier_log(
        "1: R1=fp-8 R2=fp[1]-16 R10=fp0\n"
    )
    first, second, frame_pointer = report.states[0].registers
    assert (first.value_kind, first.type_name) == ("pointer", "fp")
    assert ("off", "-8") in first.attributes
    assert (second.value_kind, second.type_name) == ("pointer", "fp")
    assert ("frameno", "1") in second.attributes
    assert ("off", "-16") in second.attributes
    assert (frame_pointer.value_kind, frame_pointer.type_name) == ("pointer", "fp")
    assert tuple(_member(report, "warnings")) == ()
    assert _findings(report) == ()


def test_current_cross_frame_variable_stack_pointer_form_is_recovered():
    report = verifier.audit_verifier_log(
        "1: R1=fp[1](smin=-16,smax=-8,"
        "var_off=(0xfffffffffffffff0; 0x8)) R10=fp0\n"
    )
    pointer = report.states[0].registers[0]
    assert (pointer.value_kind, pointer.type_name) == ("pointer", "fp")
    assert ("frameno", "1") in pointer.attributes
    assert pointer.numeric_state.tnum_value == 0xFFFFFFFFFFFFFFF0
    assert pointer.numeric_state.tnum_mask == 0x8
    assert tuple(_member(report, "warnings")) == ()
    assert _findings(report) == ()


def test_canonical_tnum_is_accepted_and_overlap_is_flagged():
    valid = verifier.audit_verifier_log(
        "2: R0=scalar(umin=64,umax=255,var_off=(0x40; 0xbf))\n"
    )
    assert _findings(valid) == ()

    invalid = verifier.audit_verifier_log(
        "2: R0=scalar(umin=0,umax=15,var_off=(0x8; 0x8))\n"
    )
    assert "tnum_value_mask_overlap" in _codes(invalid)


@pytest.mark.parametrize(
    ("descriptor", "code"),
    [
        ("umin=10,umax=9", "unsigned_bounds_inverted"),
        ("smin=5,smax=4", "signed_bounds_inverted"),
        ("umin32=10,umax32=9", "unsigned_bounds_inverted"),
        ("smin32=0xffffffff,smax32=0xfffffffe", "signed_bounds_inverted"),
    ],
)
def test_inverted_64_and_32_bit_bounds_are_flagged(descriptor, code):
    report = verifier.audit_verifier_log(f"3: R0=scalar({descriptor})\n")
    assert code in _codes(report)


@pytest.mark.parametrize(
    "descriptor",
    [
        "smin=0xfffffffffffffffe,smax=0xffffffffffffffff,var_off=(0xfffffffffffffffe; 0x1)",
        "smin32=0xfffffffe,smax32=0xffffffff,var_off=(0xfffffffe; 0x1)",
    ],
)
def test_signed_hex_is_width_normalized_before_comparison(descriptor):
    report = verifier.audit_verifier_log(f"3: R0=scalar({descriptor})\n")
    assert "signed_bounds_inverted" not in _codes(report)
    assert _findings(report) == ()


@pytest.mark.parametrize(
    "descriptor",
    [
        "umin=16,umax=31,var_off=(0x0; 0xf)",
        "umin32=16,umax32=31,var_off=(0x0; 0xf)",
    ],
)
def test_64_and_32_bit_tnum_envelopes_must_intersect_bounds(descriptor):
    report = verifier.audit_verifier_log(f"4: R0=scalar({descriptor})\n")
    assert "tnum_bounds_disjoint" in _codes(report)


def test_constant_tnum_must_stay_in_sync_with_all_explicit_bounds():
    report = verifier.audit_verifier_log(
        "4: R0=scalar(umin=8,umax=8,smin=9,smax=9,umin32=8,umax32=8,var_off=(0x8; 0x0))\n"
    )
    assert "constant_bounds_mismatch" in _codes(report)


def test_exact_low_subregister_is_checked_even_when_upper_bits_are_unknown():
    report = verifier.audit_verifier_log(
        "4: R0=scalar(umin32=9,umax32=9,var_off=(0x8; 0xffffffff00000000))\n"
    )
    assert "constant_bounds_mismatch" in _codes(report)


def test_tnum_holes_are_checked_not_only_the_numeric_envelope():
    impossible = verifier.audit_verifier_log(
        "4: R0=scalar(umin=1,umax=1,var_off=(0x0; 0x2))\n"
    )
    possible = verifier.audit_verifier_log(
        "4: R0=scalar(umin=2,umax=2,var_off=(0x0; 0x2))\n"
    )
    assert "tnum_bounds_disjoint" in _codes(impossible)
    assert _findings(possible) == ()


def test_tnum_interval_search_matches_non_circular_four_bit_enumeration():
    width = 4
    full = (1 << width) - 1
    for value in range(full + 1):
        for mask in range(full + 1):
            if value & mask:
                continue
            represented = {
                candidate for candidate in range(full + 1)
                if candidate & ~mask & full == value
            }
            for lower in range(full + 1):
                for upper in range(lower, full + 1):
                    expected = bool(represented.intersection(range(lower, upper + 1)))
                    assert verifier._tnum_has_value_in_interval(
                        value, mask, lower, upper, width
                    ) is expected


def test_signed_and_unsigned_bounds_must_share_a_bit_pattern():
    impossible = verifier.audit_verifier_log(
        "4: R0=scalar(umin=0,umax=3,smin=-3,smax=-1,"
        "var_off=(0x0; 0xffffffffffffffff))\n"
    )
    possible = verifier.audit_verifier_log(
        "4: R0=scalar(umin=0xfffffffffffffffd,umax=0xffffffffffffffff,"
        "smin=-3,smax=-1,var_off=(0x0; 0xffffffffffffffff))\n"
    )
    assert "signed_unsigned_bounds_disjoint" in _codes(impossible)
    assert _findings(possible) == ()


def test_64_bit_and_low_32_bit_bounds_describe_one_value():
    impossible = verifier.audit_verifier_log(
        "4: R0=scalar(umin=0,umax=0,umin32=1,umax32=1,"
        "var_off=(0x0; 0xffffffffffffffff))\n"
    )
    possible = verifier.audit_verifier_log(
        "4: R0=scalar(umin=umax=0x100000001,umin32=umax32=1,"
        "var_off=(0x100000001; 0x0))\n"
    )
    assert "cross_width_bounds_disjoint" in _codes(impossible)
    assert _findings(possible) == ()


def test_tnum_and_cross_width_bounds_are_jointly_feasible():
    report = verifier.audit_verifier_log(
        "4: R0=scalar(umin=0x100000000,umax=0x100000001,"
        "umin32=1,umax32=2,var_off=(0x0; 0x100000002))\n"
    )
    assert "tnum_bounds_disjoint" in _codes(report)


def test_same_state_scalar_id_disjointness_is_flagged():
    report = verifier.audit_verifier_log(
        "5: R1=scalar(id=7,umin=0,umax=3,var_off=(0x0; 0x3)) "
        "R2=scalar(id=7,umin=8,umax=11,var_off=(0x8; 0x3))\n"
    )
    assert "scalar_id_disjoint" in _codes(report)


@pytest.mark.parametrize("relation", ["7+10", "7-10"])
def test_current_linked_id_relation_is_retained_but_not_treated_as_equality(relation):
    report = verifier.audit_verifier_log(
        f"5: R1=scalar(id={relation},umin=0,umax=0,var_off=(0x0; 0x0)) "
        f"R2=scalar(id={relation},umin=8,umax=8,var_off=(0x8; 0x0))\n"
    )
    first, second = report.states[0].registers
    assert first.scalar_id == second.scalar_id == 7
    assert ("id", relation) in first.attributes
    assert tuple(_member(report, "warnings")) == ()
    assert "scalar_id_disjoint" not in _codes(report)


def test_linked_id_delta_must_fit_the_kernel_signed_32_bit_field():
    report = verifier.audit_verifier_log(
        "5: R1=scalar(id=7+2147483648,umin=0,umax=1)\n"
    )
    warning_codes = {_member(item, "code") for item in report.warnings}
    assert "malformed_identifier" in warning_codes
    assert report.states[0].registers[0].scalar_id is None


@pytest.mark.parametrize(
    "left,right",
    [
        (
            "umin=0,umax=1,var_off=(0x0; 0x2)",
            "umin=1,umax=2,var_off=(0x0; 0x2)",
        ),
        (
            "umin=0,umax=3,smin=0,smax=1,var_off=(0x0; 0xffffffffffffffff)",
            "umin=2,umax=3,smin=1,smax=3,var_off=(0x0; 0xffffffffffffffff)",
        ),
    ],
)
def test_same_scalar_id_uses_joint_concretization(left, right):
    report = verifier.audit_verifier_log(
        f"5: R1=scalar(id=7,{left}) R2=scalar(id=7,{right})\n"
    )
    assert "scalar_id_disjoint" in _codes(report)


def test_pointer_id_allows_distinct_fixed_offsets():
    report = verifier.audit_verifier_log(
        "5: R2=pkt(id=4,off=0,r=32) R3=pkt(id=4,off=4,r=28) R10=fp0\n"
    )
    assert "scalar_id_disjoint" not in _codes(report)
    assert _findings(report) == ()


def test_owning_reference_matches_active_reference_set():
    report = verifier.audit_verifier_log(
        "6: R6=alloc_mem(id=1,ref_obj_id=7,off=0) refs=7\n"
    )
    assert _findings(report) == ()


def test_orphan_owning_reference_is_flagged_only_with_explicit_refs():
    report = verifier.audit_verifier_log(
        "6: R6=alloc_mem(id=1,ref_obj_id=7,off=0) refs=2,3\n"
    )
    assert "orphan_reference" in _codes(report)


def test_reference_absence_and_id_namespaces_do_not_create_false_orphans():
    no_explicit_set = verifier.audit_verifier_log(
        "6: R6=alloc_mem(id=1,ref_obj_id=7,off=0)\n"
    )
    distinct_ids = verifier.audit_verifier_log(
        "6: R6=alloc_mem(id=3,ref_obj_id=7,off=0) refs=7\n"
    )
    set_without_visible_owner = verifier.audit_verifier_log(
        "6: R1=ctx() refs=7\n"
    )
    for report in (no_explicit_set, distinct_ids, set_without_visible_owner):
        assert "orphan_reference" not in _codes(report)
        assert _findings(report) == ()


def test_duplicate_ref_ids_are_type_elided_but_invalid_ids_are_flagged():
    duplicate = verifier.audit_verifier_log("6: R1=ctx() refs=7,7\n")
    nonpositive = verifier.audit_verifier_log("6: R1=ctx() refs=0,-2\n")
    oversized = verifier.audit_verifier_log("6: R1=ctx() refs=4294967296\n")
    assert _findings(duplicate) == ()
    assert "invalid_reference_id" in _codes(nonpositive)
    assert "invalid_reference_id" in _codes(oversized)


def test_current_large_reference_set_is_not_limited_by_attribute_count():
    references = ",".join(str(value) for value in range(1, 130))
    report = verifier.audit_verifier_log(f"6: R1=ctx() refs={references}\n")
    assert len(report.states[0].refs) == 129
    assert _findings(report) == ()


def test_duplicate_identity_fields_are_warned_and_excluded_from_audit():
    register = verifier.audit_verifier_log(
        "6: R0=alloc_mem(ref_obj_id=7,ref_obj_id=8) refs=8\n"
    )
    scalar = verifier.audit_verifier_log(
        "6: R0=scalar(id=7,id=8,umin=0,umax=1) "
        "R1=scalar(id=8,umin=4,umax=5)\n"
    )
    register_warning_codes = {
        _member(item, "code") for item in register.warnings
    }
    scalar_warning_codes = {_member(item, "code") for item in scalar.warnings}
    assert "duplicate_identifier" in register_warning_codes
    assert "duplicate_identifier" in scalar_warning_codes
    assert _findings(register) == ()
    assert "scalar_id_disjoint" not in _codes(scalar)


@pytest.mark.parametrize(
    "tnums",
    [
        "var_off=(0; 0),var_off=(1; 0)",
        "var_off=(1; 0),var_off=(0; 0)",
    ],
)
def test_duplicate_tnum_is_warned_and_never_audited_by_occurrence_order(tnums):
    report = verifier.audit_verifier_log(
        f"6: R0=scalar(umin=1,umax=1,{tnums})\n"
    )
    warning_codes = {_member(item, "code") for item in report.warnings}
    assert "duplicate_tnum" in warning_codes
    assert report.states[0].registers[0].numeric_state.tnum_value is None
    assert _findings(report) == ()


@pytest.mark.parametrize(
    "bounds",
    ["umin=10,umin=0,umax=5", "umin=0,umin=10,umax=5"],
)
def test_conflicting_bound_is_excluded_from_order_dependent_checks(bounds):
    report = verifier.audit_verifier_log(f"6: R0=scalar({bounds})\n")
    findings = _findings(report)
    assert len(findings) == 1
    assert _member(findings[0], "code") == "conflicting_bound_field"
    assert _member(findings[0], "message") == (
        "the same bound is printed with conflicting values"
    )


def test_duplicate_stack_reference_field_is_warned_and_not_chosen():
    report = verifier.audit_verifier_log(
        "6: fp-8=iter_num(ref_id=7,ref_id=8,state=active) refs=8\n"
    )
    warning_codes = {_member(item, "code") for item in report.warnings}
    assert "duplicate_stack_attribute" in warning_codes
    assert _findings(report) == ()


def test_multiple_state_ref_sets_are_warned_and_not_arbitrarily_selected():
    report = verifier.audit_verifier_log(
        "6: R0=alloc_mem(ref_obj_id=8) refs=7 refs=8\n"
    )
    warning_codes = {_member(item, "code") for item in report.warnings}
    assert "multiple_refs_fields" in warning_codes
    assert _findings(report) == ()


def test_non_own_reference_cannot_also_claim_an_owned_ref_obj_id():
    report = verifier.audit_verifier_log(
        "6: R6=alloc_mem(id=1,ref_obj_id=7,non_own_ref,off=0) refs=7\n"
    )
    assert "non_own_reference_conflict" in _codes(report)


@pytest.mark.parametrize(
    "spelling",
    [
        "non_own_ref,non_own_ref",
        "non_own_ref,non_own_ref=false",
        "non_own_ref=false,non_own_ref",
        "non_own_ref=true",
    ],
)
def test_non_kernel_or_duplicate_non_own_spelling_is_not_arbitrarily_audited(
    spelling,
):
    report = verifier.audit_verifier_log(
        f"6: R6=alloc_mem(ref_obj_id=7,{spelling},off=0) refs=7\n"
    )
    warning_codes = {_member(item, "code") for item in report.warnings}
    assert warning_codes.intersection(
        {"duplicate_non_own_ref", "malformed_non_own_ref"}
    )
    assert "non_own_reference_conflict" not in _codes(report)
    assert _findings(report) == ()


@pytest.mark.parametrize("type_name", ["sock", "sock_or_null"])
def test_socket_id_alone_does_not_prove_reference_ownership(type_name):
    matching = verifier.audit_verifier_log(
        f"6: R0={type_name}(id=7) refs=7\n"
    )
    unrelated_active_reference = verifier.audit_verifier_log(
        f"6: R0={type_name}(id=7) refs=3\n"
    )
    assert _findings(matching) == ()
    assert _findings(unrelated_active_reference) == ()


def test_legacy_socket_ref_obj_id_keeps_pointer_id_namespace_distinct():
    register = verifier.audit_verifier_log(
        "6: R0=sock_or_null(id=1,ref_obj_id=7) refs=7\n"
    )
    spill = verifier.audit_verifier_log(
        "6: fp-8=sock(id=1,ref_obj_id=7) refs=7\n"
    )
    assert _findings(register) == ()
    assert _findings(spill) == ()


def test_non_own_nullable_pointer_id_is_provenance_not_ownership():
    register = verifier.audit_verifier_log(
        "6: R0=rcu_ptr_or_null_foo(id=7,non_own_ref) refs=3\n"
    )
    spill = verifier.audit_verifier_log(
        "6: fp-8=rcu_ptr_or_null_foo(id=7,non_own_ref) refs=3\n"
    )
    assert _findings(register) == ()
    assert _findings(spill) == ()


def test_packet_pointer_id_is_not_a_reference_owner():
    report = verifier.audit_verifier_log(
        "6: R2=pkt(id=7,off=0,r=32) refs=3\n"
    )
    assert "orphan_reference" not in _codes(report)
    assert _findings(report) == ()


@pytest.mark.parametrize(
    "descriptor",
    [
        "fp-16_w=dynptr_ringbuf(id=2,ref_id=7,dynptr_id=2)",
        "fp-8=iter_num(ref_id=7,state=active,depth=0)",
        "fp-8=sock(ref_obj_id=7,off=0)",
    ],
)
def test_stack_dynptr_iterator_and_spilled_owners_are_checked(descriptor):
    matching = verifier.audit_verifier_log(f"6: R1=ctx() {descriptor} refs=7\n")
    orphan = verifier.audit_verifier_log(f"6: R1=ctx() {descriptor} refs=3\n")
    assert _findings(matching) == ()
    assert "orphan_reference" in _codes(orphan)
    assert matching.states[0].stack_slots


def test_stack_id_namespaces_are_not_conflated_with_reference_ids():
    report = verifier.audit_verifier_log(
        "6: fp-16=dynptr_ringbuf(id=2,ref_id=7,dynptr_id=2) refs=7\n"
    )
    slot = report.states[0].stack_slots[0]
    assert slot.identity_id == 2
    assert slot.dynptr_id == 2
    assert slot.reference_id == 7
    assert _findings(report) == ()


@pytest.mark.parametrize(
    "descriptor",
    [
        "fp-16=dynptr_ringbuf(id=2,parent_id=7)",
        "fp-8=iter_num(id=7,state=active,depth=0)",
    ],
)
def test_current_kernel_stack_owner_ids_are_checked(descriptor):
    matching = verifier.audit_verifier_log(f"6: {descriptor} refs=7\n")
    orphan = verifier.audit_verifier_log(f"6: {descriptor} refs=3\n")
    assert _findings(matching) == ()
    assert "orphan_reference" in _codes(orphan)


def test_partial_scalar_spill_prefix_preserves_numeric_and_id_state():
    report = verifier.audit_verifier_log(
        "6: R1=scalar(id=7,umin=8,umax=11,var_off=(0x8; 0x3)) "
        "fp-8_rwD=mmmmscalar(id=7,umin=0,umax=3,var_off=(0x0; 0x3))\n"
    )
    slot = report.states[0].stack_slots[0]
    assert slot.value_kind == "scalar"
    assert slot.scalar_id == 7
    assert slot.liveness == "rwD"
    assert "scalar_id_disjoint" in _codes(report)


@pytest.mark.parametrize("byte_map", ["00000000", "00mmmm??"])
def test_raw_stack_byte_maps_are_opaque_not_scalar_values(byte_map):
    report = verifier.audit_verifier_log(f"6: fp-8={byte_map}\n")
    slot = report.states[0].stack_slots[0]
    assert slot.value_kind == "bytes"
    assert slot.numeric_state is None
    assert _findings(report) == ()


def test_zero_stack_provenance_ids_are_sentinels_not_owned_references():
    report = verifier.audit_verifier_log("6: fp-8=pkt(id=0,off=0,r=14) refs=7\n")
    assert _findings(report) == ()


def test_current_maximum_stack_offset_and_first_out_of_range_slot():
    valid = verifier.audit_verifier_log("6: fp-2048=00000000\n")
    invalid = verifier.audit_verifier_log("6: fp-2056=00000000\n")
    assert _findings(valid) == ()
    assert "invalid_stack_slot_offset" in _codes(invalid)


def test_state_line_stack_slot_count_is_bounded_to_current_kernel_maximum():
    line = "6:" + "".join(
        f" fp-{8 * (index + 1)}=00000000" for index in range(257)
    )
    with pytest.raises(verifier.WPGAPEBPFError):
        verifier.audit_verifier_log(line + "\n")


def test_full_current_stack_dump_fits_the_bounded_line_budget():
    scalar = (
        "scalar(smin=-1,smax=1,umin=0,umax=1,smin32=-1,smax32=1,"
        "umin32=0,umax32=1,var_off=(0; 1))"
    )
    line = "cur state:" + "".join(
        f" fp-{8 * (index + 1)}={scalar}" for index in range(256)
    )
    assert len(line) > 16_384
    report = verifier.audit_verifier_log(line + "\n")
    assert len(report.states[0].stack_slots) == 256
    assert _findings(report) == ()


def test_kernel_errors_are_preserved_separately_from_derived_findings():
    report = verifier.audit_verifier_log(
        "0: R1=ctx() R10=fp0\n"
        "REG INVARIANTS VIOLATION (saved_state): explicit verifier invariant diagnostic\n"
        "Unreleased reference id=7, alloc_insn=3\n"
    )
    diagnostics = tuple(_member(report, "kernel_diagnostics"))
    rendered = repr(diagnostics)
    assert len(diagnostics) == 2
    assert "explicit verifier invariant diagnostic" in rendered
    assert "Unreleased reference" in rendered
    assert "orphan_reference" not in _codes(report)


@pytest.mark.parametrize(
    ("line", "expected_code", "register"),
    [
        (
            "R0 min value is negative, either use unsigned index or do a "
            "if (index >=0) check.",
            "negative_minimum_bound",
            "R0",
        ),
        (
            "R2 max value is outside of the allowed memory range",
            "maximum_outside_allowed_range",
            "R2",
        ),
        (
            "R1 has unknown scalar with mixed signed bounds, pointer arithmetic "
            "with it prohibited for !root",
            "mixed_signed_bounds",
            "R1",
        ),
    ],
)
def test_published_bounds_rejection_diagnostics_are_classified(
    line, expected_code, register
):
    report = verifier.audit_verifier_log(line + "\n")
    diagnostics = tuple(_member(report, "kernel_diagnostics"))
    assert len(diagnostics) == 1
    assert _member(diagnostics[0], "code") == expected_code
    assert _member(diagnostics[0], "context") == register
    assert _findings(report) == ()


def test_bounds_rejection_diagnostic_must_start_at_the_log_line():
    report = verifier.audit_verifier_log(
        "analyst quote: R0 min value is negative, use unsigned index\n"
    )
    assert tuple(_member(report, "kernel_diagnostics")) == ()
    assert _findings(report) == ()


@pytest.mark.parametrize(
    "line",
    [
        "func bpf_sk_release#86 reference has not been acquired before",
        "kfunc bpf_obj_drop_impl#42 reference has not been acquired before",
        "arg 2 is an unacquired reference",
    ],
)
def test_invalid_release_diagnostics_are_classified(line):
    report = verifier.audit_verifier_log(line + "\n")
    diagnostics = tuple(_member(report, "kernel_diagnostics"))
    assert len(diagnostics) == 1
    assert _member(diagnostics[0], "code") == "reference_not_acquired"


def test_cve_signature_must_be_an_anchored_kernel_diagnostic():
    report = verifier.audit_verifier_log(
        "userspace note: REG INVARIANTS VIOLATION (quoted prose only)\n"
    )
    assert tuple(_member(report, "kernel_diagnostics")) == ()
    assert tuple(_member(report, "warnings")) == ()
    assert "cve_2024_41003_pattern" not in _codes(report)


def test_cve_signature_requires_the_published_fake_register_diagnostic_trio():
    report = verifier.audit_verifier_log(
        "18: R6=scalar(var_off=(0x2; 0x7ffffffd))\n"
        "19: (56) if w6 != 0x7ffffffd goto pc+1\n"
        "REG INVARIANTS VIOLATION (alu): const subreg tnum out of sync with range bounds\n"
    )
    assert "cve_2024_41003_pattern" not in _codes(report)


def test_published_cve_2024_41003_signature_is_pattern_evidence_only():
    report = verifier.audit_verifier_log(CVE_2024_41003_UPSTREAM)
    diagnostics = tuple(_member(report, "kernel_diagnostics"))
    assert len(diagnostics) == 3
    assert "cve_2024_41003_pattern" in _codes(report)
    _assert_offline(report)


def test_repeated_pc_states_on_different_paths_are_not_merged():
    report = verifier.audit_verifier_log(
        "from 4 to 5:\n"
        "5: R1=scalar(id=9,umin=0,umax=3,var_off=(0x0; 0x3))\n"
        "from 8 to 5:\n"
        "5: R1=scalar(id=9,umin=8,umax=11,var_off=(0x8; 0x3))\n"
    )
    assert _state_count(report) == 2
    assert "scalar_id_disjoint" not in _codes(report)


def test_frame_and_branch_origin_syntax_is_parsed():
    report = verifier.audit_verifier_log(
        "from 3 to 8:\n"
        "8: frame1: R1=scalar(umin=1,umax=3,var_off=(0x1; 0x2)) R10=fp0\n"
    )
    assert _state_count(report) == 1
    assert _findings(report) == ()


def test_speculative_branch_origin_syntax_is_parsed():
    report = verifier.audit_verifier_log(
        "from 4 to 5 (speculative execution): R1=ctx() R10=fp0\n"
    )
    assert _state_count(report) == 1
    assert report.states[0].pc == 5


def test_truncated_descriptor_is_warning_not_contradiction():
    report = verifier.audit_verifier_log(
        "2: R1=scalar(umin=0,umax=7,var_off=(0x0; 0x7)\n"
    )
    assert _findings(report) == ()
    assert tuple(_member(report, "warnings"))


def test_arbitrary_verifier_chatter_is_ignored():
    report = verifier.audit_verifier_log(
        "libbpf: prog 'demo': -- BEGIN PROG LOAD LOG --\n"
        "verification time 23 usec\n"
        "0: R1=ctx() R10=fp0\n"
        "processed 1 insns (limit 1000000) max_states_per_insn 0 total_states 0\n"
        "libbpf: prog 'demo': -- END PROG LOAD LOG --\n"
    )
    assert _state_count(report) == 1
    assert _findings(report) == ()


def test_refs_in_arbitrary_prose_are_not_treated_as_a_complete_state():
    for text in (
        "analysis note: refs=0,-2\n",
        "analyst note; fp-8=sock(ref_obj_id=7) refs=3\n",
        "analysis frame1: fp-8=sock(ref_obj_id=7) refs=3\n",
        "stack=garbage: fp-8=sock(ref_obj_id=7) refs=3\n",
        "stack=3: fp-8=sock(ref_obj_id=7) refs=3\n",
    ):
        report = verifier.audit_verifier_log(text)
        assert _state_count(report) == 0
        assert _findings(report) == ()


@pytest.mark.parametrize(
    "prefix",
    [
        "cur state:",
        "old state:",
        "stack=:",
        "stack=-8,-24:",
        "mark_precise: frame0: parent state regs=r1,r3 stack=-8,-24:",
    ],
)
def test_authoritative_labeled_state_prefixes_are_parsed(prefix):
    report = verifier.audit_verifier_log(
        f"{prefix} R1=ctx() fp-8_r=iter_num(ref_id=7,state=active,depth=0) refs=7\n"
    )
    assert _state_count(report) == 1
    assert report.states[0].stack_slots[0].liveness == "r"
    assert _findings(report) == ()


def test_labeled_state_prefix_preserves_nonzero_frame():
    report = verifier.audit_verifier_log("cur state: frame2: R1=ctx() R10=fp0\n")
    assert report.states[0].frame == 2


@pytest.mark.parametrize("suffix", ["wr", "rr", "DD", "Dr", "x"])
def test_non_kernel_liveness_suffixes_are_warnings(suffix):
    report = verifier.audit_verifier_log(f"9: R1_{suffix}=ctx()\n")
    warning_codes = {_member(item, "code") for item in report.warnings}
    assert "invalid_liveness" in warning_codes
    assert _state_count(report) == 0


def test_invalid_or_duplicate_register_tokens_are_warnings_not_state_aliases():
    report = verifier.audit_verifier_log(
        "9: R11=scalar(umin=0,umax=1) R1=ctx() R1=scalar(umin=8,umax=7)\n"
    )
    warning_codes = {_member(item, "code") for item in report.warnings}
    assert "invalid_register_number" in warning_codes
    assert "duplicate_register_state" in warning_codes
    assert _findings(report) == ()


def test_duplicate_stack_slots_are_warned_and_all_copies_are_excluded():
    report = verifier.audit_verifier_log(
        "9: R1=ctx() fp-8=scalar(umin=8,umax=7) fp-8=00000000\n"
    )
    warning_codes = {_member(item, "code") for item in report.warnings}
    assert "duplicate_stack_slot" in warning_codes
    assert report.states[0].stack_slots == ()
    assert _findings(report) == ()


def test_comma_separated_tnum_is_diagnostic_syntax_not_register_syntax():
    report = verifier.audit_verifier_log(
        "9: R0=scalar(umin=0,umax=3,var_off=(0x0, 0x3))\n"
    )
    warning_codes = {_member(item, "code") for item in report.warnings}
    assert "malformed_tnum" in warning_codes
    assert _findings(report) == ()


@pytest.mark.parametrize("bad", [None, 1, object(), [], {}])
def test_malformed_python_types_raise_only_declared_error(bad):
    with pytest.raises(verifier.WPGAPEBPFError):
        verifier.audit_verifier_log(bad)


def test_invalid_utf8_and_size_cap_raise_only_declared_error(monkeypatch):
    with pytest.raises(verifier.WPGAPEBPFError):
        verifier.audit_verifier_log(b"\xff\xfe\xfd")

    monkeypatch.setattr(verifier, "MAX_LOG_BYTES", 32)
    with pytest.raises(verifier.WPGAPEBPFError):
        verifier.audit_verifier_log(b"0: R1=ctx() R10=fp0\n" * 4)


def test_cli_valid_help_bad_and_missing_inputs(tmp_path, capsys):
    valid = tmp_path / "verifier.log"
    valid.write_text(MODERN_CHAINED, encoding="utf-8")
    assert verifier.main([str(valid), "--pretty"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["offline"] is True
    assert document["requests_sent"] == 0
    assert document["verifier_acceptance_claimed"] is False

    assert verifier.main(["--help"]) == 0
    assert "usage:" in capsys.readouterr().out.lower()

    invalid = tmp_path / "invalid.log"
    invalid.write_bytes(b"\xff\xfe")
    assert verifier.main([str(invalid)]) == 2
    error = capsys.readouterr().err
    assert "Traceback" not in error

    assert verifier.main([str(tmp_path / "missing.log")]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_source_ast_has_no_active_or_dynamic_execution_surface():
    source = Path(verifier.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    banned_modules = {
        "aiohttp", "ctypes", "ftplib", "http", "httpx", "importlib",
        "requests", "smtplib", "socket", "subprocess", "urllib",
    }
    banned_bare_calls = {"__import__", "compile", "eval", "exec"}
    banned_loader_calls = {
        "SourceFileLoader", "module_from_spec", "spec_from_file_location",
    }
    imported: set[str] = set()
    bare_calls: set[str] = set()
    attribute_calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".", 1)[0])
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                bare_calls.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                attribute_calls.add(node.func.attr)
        elif isinstance(node, ast.AnnAssign):
            if (isinstance(node.target, ast.Name)
                    and node.target.id == "verifier_acceptance_claimed"):
                assert not (isinstance(node.value, ast.Constant) and node.value.value is True)
        elif isinstance(node, ast.Assign):
            if any(isinstance(target, ast.Name)
                   and target.id == "verifier_acceptance_claimed"
                   for target in node.targets):
                assert not (isinstance(node.value, ast.Constant) and node.value.value is True)
    assert not imported.intersection(banned_modules)
    assert not bare_calls.intersection(banned_bare_calls | banned_loader_calls)
    assert not attribute_calls.intersection(banned_loader_calls)

