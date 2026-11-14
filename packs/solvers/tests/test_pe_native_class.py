#!/usr/bin/env python3
"""B-226: the Windows PE / native-emulation class is routed and driven.

Two behaviours are new here, over the carried harness (B-148) and the static-RE kit (B-165):

* **Routing.** `toolkits.pe_emu` now carries routes, so the flag-only static-RE-of-a-PE class
  (Day-30 SHA1-Hulud) surfaces in `ctf engines route` / `ctf triage` -- a keyword route for a
  description that names the class, and a file route for any handed-out PE (MZ magic), even with no
  description. A non-reverse challenge with no PE must not route here.
* **The ready setup.** `pe_emu.ready_environment(bytes)` is the one-call running start: it maps the
  image, builds a clean `WindowsEnvironment`, parses TLS, seeds the hashed-API table and finds the
  compare sites, reusing the carried harness only. `ReadySetup.sandbox()` wires the native emulator;
  where Unicorn is declined (the Darwin/arm64 guard) it fails loudly, never silently.

Every fixture is synthetic: a hand-built PE from the B-148 test builder, the in-repo FakeUc backend,
and a shared-findings board. No challenge file, no native subprocess; the one real-Unicorn check is
`needs_tool`-marked and skips as NOT RUN where the engine is unavailable.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for _p in (str(ROOT), str(ROOT / "tools"), str(ROOT / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from solvers.toolkits import pe_emu as PE  # noqa: E402
from ctf.engines import manifest as _manifest, router  # noqa: E402
from ctf import triage  # noqa: E402
from test_pe_win import build_pe  # noqa: E402  (the B-148 synthetic PE builder)
from test_pe_emu import BACKEND  # noqa: E402  (the in-repo fail-closed sandbox fake)

PE_MANIFEST = ROOT / "solvers" / "toolkits" / "pe_emu.manifest.toml"


def _pe_bytes(**kwargs) -> bytes:
    data, _preferred = build_pe(**kwargs)
    return data


# ============================================================ routing
def _write_pe(dirpath: Path, name: str = "challenge.bin") -> Path:
    p = dirpath / name
    p.write_bytes(b"MZ\x90\x00" + b"\x00" * 300)
    return p


def test_reverse_pe_is_routed_to_pe_emu_by_file(tmp_path):
    _write_pe(tmp_path)
    hits = router.route("reverse", "", files_dir=tmp_path, root=ROOT)
    hit = next((h for h in hits if h.manifest.id == "toolkits.pe_emu"), None)
    assert hit is not None, "a reverse challenge that hands out a PE must route to pe_emu"
    assert "MZ" in hit.reason and "reverse" in hit.reason


def test_reverse_pe_is_routed_to_pe_emu_by_keyword(tmp_path):
    hits = router.route("reverse", "A Windows PE with API-hash table obfuscation and a VEH single-step trap",
                        files_dir=None, root=ROOT)
    hit = next((h for h in hits if h.manifest.id == "toolkits.pe_emu"), None)
    assert hit is not None and "keyword" in hit.reason


def test_unrelated_challenge_without_a_pe_does_not_route_pe_emu(tmp_path):
    # A crypto challenge with no PE and no PE-class keywords must not surface the toolkit: the routes
    # are category-guarded (reverse) and condition-bearing, not a match-everything.
    hits = router.route("crypto", "an rsa modulus with a small public exponent",
                        files_dir=tmp_path, root=ROOT)
    assert all(h.manifest.id != "toolkits.pe_emu" for h in hits)


NON_REVERSE_CATEGORIES = tuple(c for c in triage.CATEGORIES if c != "reverse")


@pytest.mark.parametrize("category", NON_REVERSE_CATEGORIES)
def test_non_reverse_challenge_handed_a_pe_does_not_route_pe_emu(tmp_path, category):
    # The category guard itself, pinned with the conditions that WOULD fire the routes: a real MZ image
    # named `.exe` (both file tokens match) and a description full of the class keywords. The test above
    # cannot see a widened guard, because with no PE and no keyword neither route fires whatever the
    # guard says. Both routes are `category = ["reverse"]`; widening either one must fail here.
    assert len(NON_REVERSE_CATEGORIES) == len(triage.CATEGORIES) - 1 and "crypto" in NON_REVERSE_CATEGORIES
    _write_pe(tmp_path, "sample.exe")
    description = "A Windows PE with API-hash table obfuscation and a TLS callback"

    # Control: the very same files / description DO route for a reverse challenge, so a miss below is
    # the category guard and not a fixture that matches nothing.
    assert any(h.manifest.id == "toolkits.pe_emu"
               for h in router.route("reverse", "", files_dir=tmp_path, root=ROOT))
    assert any(h.manifest.id == "toolkits.pe_emu"
               for h in router.route("reverse", description, files_dir=None, root=ROOT))

    by_file = router.route(category, "", files_dir=tmp_path, root=ROOT)
    assert all(h.manifest.id != "toolkits.pe_emu" for h in by_file), \
        f"the PE file route must stay reverse-only; it fired for {category}"
    by_keyword = router.route(category, description, files_dir=None, root=ROOT)
    assert all(h.manifest.id != "toolkits.pe_emu" for h in by_keyword), \
        f"the PE keyword route must stay reverse-only; it fired for {category}"
    both = router.route(category, description, files_dir=tmp_path, root=ROOT)
    assert all(h.manifest.id != "toolkits.pe_emu" for h in both)


def test_triage_suggest_surfaces_pe_emu_from_the_generated_table(tmp_path):
    # triage.suggest reads the generated route_table.jsonl, so this also fails if the table is stale.
    _write_pe(tmp_path, "sample.exe")
    res = triage.suggest("reverse", "windows pe native emulation", files_dir=tmp_path)
    assert any(r["id"] == "toolkits.pe_emu" for r in res["routes"])


def test_pe_emu_manifest_now_carries_routes():
    m = _manifest.load(PE_MANIFEST)
    assert m.status != "retired" and m.routes, "pe_emu must no longer be an unrouted (no-route) engine"
    assert any("reverse" in (r.category or ()) for r in m.routes)
    assert m.has("library"), "pe_emu stays a library engine; ctf run still refuses it"


# ============================================================ the ready setup
SUMMARY_KEYS = {
    "image_sha256", "file_sha256", "machine", "is_64", "entry_rva", "load_base", "sections", "imports",
    "delay_imports",                                       # B-241: delay-load imports are parsed, not refused
    "tls_callbacks", "tls_index_address", "compare_sites", "compare_sites_reason", "api_hash_values",
    "modelled_apis", "unicorn_available", "unicorn_reason",
}


@pytest.mark.needs_tool("py:capstone")
def test_ready_environment_wires_the_setup():
    setup = PE.ready_environment(_pe_bytes(with_tls=True))
    assert isinstance(setup, PE.ReadySetup)
    assert setup.pe.is_64 and setup.pe.machine == PE.IMAGE_FILE_MACHINE_AMD64
    assert [s.display for s in setup.pe.imports] == ["kernel32.dll!VirtualAlloc"]
    assert setup.tls.callbacks == (setup.pe.load_base + 0x1000,)
    assert len(setup.compare_sites) >= 1 and setup.compare_sites[0].mnemonic == "cmp"
    assert setup.compare_sites_reason is None
    # A clean, freshly-constructed environment (not shared/mutated state).
    assert isinstance(setup.environment, PE.WindowsEnvironment)
    assert setup.environment.anti_debug == [] and setup.environment.last_error == 0
    # The hashed-API table is seeded from the common-API catalog by default.
    assert len(setup.api_hash_index) == len(PE.build_api_hash_index())
    # No clock injected -> the production monotonic clock.
    import time as _time
    assert setup.clock is _time.monotonic


@pytest.mark.needs_tool("py:capstone")
def test_ready_environment_summary_reports_what_is_wired():
    data, preferred = build_pe(with_tls=True)
    setup = PE.ready_environment(data)
    s = setup.summary()
    # The exact field set: a dropped (or silently added) summary field fails here, whichever it is.
    assert set(s) == SUMMARY_KEYS
    # Each image field is checked against what the synthetic builder put in the file -- an independent
    # value, not a re-read of the same attribute -- so a field wired to the wrong source fails too.
    assert s["load_base"] == preferred == 0x140000000        # no relocation: mapped at the preferred base
    assert s["machine"] == PE.IMAGE_FILE_MACHINE_AMD64
    assert s["entry_rva"] == 0x1000
    assert s["sections"] == [".text", ".idata", ".reloc"]
    assert s["tls_index_address"] == preferred + 0x2140      # the builder's AddressOfIndex
    assert s["file_sha256"] == hashlib.sha256(data).hexdigest()
    assert s["image_sha256"] == hashlib.sha256(setup.pe.image).hexdigest()
    assert s["image_sha256"] != s["file_sha256"]             # the mapped image is not the file: not swapped
    assert s["compare_sites_reason"] is None
    assert s["modelled_apis"] == list(PE.modelled_apis())
    json.dumps(s)                                            # "JSON-able" is the documented contract
    assert s["is_64"] is True and s["imports"] == ["kernel32.dll!VirtualAlloc"]
    assert s["delay_imports"] == []                          # the builder writes no delay-import directory
    assert s["tls_callbacks"] == [hex(setup.pe.load_base + 0x1000)]
    assert s["compare_sites"] == len(setup.compare_sites) and s["compare_sites"] >= 1
    assert s["api_hash_values"] == len(setup.api_hash_index)
    assert "virtualalloc" in s["modelled_apis"]
    assert s["unicorn_available"] in (True, False)       # a bool either way, with a reason when False
    assert (s["unicorn_reason"] is None) == s["unicorn_available"]


@pytest.mark.needs_tool("py:capstone")
def test_summary_reports_no_tls_as_empty_not_invented():
    # An image with no TLS directory: the summary says so (no callbacks, no index address) rather than
    # carrying a value over. This also separates `tls_index_address` from a constant.
    s = PE.ready_environment(_pe_bytes()).summary()
    assert s["tls_callbacks"] == [] and s["tls_index_address"] is None


@pytest.mark.needs_tool("py:capstone")
def test_resolve_api_hash_finds_a_known_api_and_misses_cleanly():
    setup = PE.ready_environment(_pe_bytes())
    want = PE.hash_ror13("VirtualAlloc")
    matches = setup.resolve_api_hash(want)
    assert any(m.name == "VirtualAlloc" and m.algorithm == "ror13" for m in matches)
    # The hash is a documented 32-bit constant: a caller passing a 64-bit register value whose low 32
    # bits match must still resolve (the `& 0xFFFFFFFF` mask), not miss. This pins that masking.
    wide = 0x1_0000_0000 | want
    assert wide != want and wide > 0xFFFFFFFF
    assert setup.resolve_api_hash(wide) == matches, "the low-32-bit mask must be applied"
    # A value that nothing in the catalog hashes to returns an empty tuple, not a wrong guess.
    absent = next(v for v in range(0x1000) if v not in setup.api_hash_index)
    assert setup.resolve_api_hash(absent) == ()


@pytest.mark.needs_tool("py:capstone")
def test_custom_api_symbols_change_the_hash_index():
    setup = PE.ready_environment(_pe_bytes(), api_symbols=[("my.dll", "SecretFunc")])
    # Only the one custom symbol is indexed now (one value per algorithm, de-duplicated).
    assert len(setup.api_hash_index) < len(PE.build_api_hash_index())
    assert any(m.name == "SecretFunc" for ms in setup.api_hash_index.values() for m in ms)
    assert not any(m.name == "VirtualAlloc" for ms in setup.api_hash_index.values() for m in ms)


def test_compare_sites_can_be_skipped():
    setup = PE.ready_environment(_pe_bytes(), compare_sites=False)
    assert setup.compare_sites == () and setup.compare_sites_reason is None


def test_compare_site_tool_absence_is_reported_not_swallowed(monkeypatch):
    # Simulate capstone being unavailable: find_compare_sites raises EmulationDenied. The setup must
    # still deliver the mapping/hash/TLS and name the reason (rule 6: no silent fallback), not crash.
    def _no_capstone(is_64):
        raise PE.EmulationDenied("Capstone is required for instruction vetting")

    monkeypatch.setattr(PE, "_capstone_x86", _no_capstone)
    setup = PE.ready_environment(_pe_bytes())
    assert setup.compare_sites == ()
    assert setup.compare_sites_reason is not None and "Capstone" in setup.compare_sites_reason
    assert setup.summary()["compare_sites_reason"] == setup.compare_sites_reason
    # The rest of the setup is intact.
    assert setup.pe.is_64 and len(setup.api_hash_index) > 0


def test_malformed_pe_raises_loudly():
    with pytest.raises(PE.PEError):
        PE.ready_environment(b"this is not a PE image at all")


# ============================================================ sandbox wiring
@pytest.mark.needs_tool("py:capstone")
def test_sandbox_wires_the_same_environment_and_clock_and_runs_tls():
    ticks = iter(range(1, 10_000))
    clock = lambda: next(ticks)                                     # a deterministic step clock
    setup = PE.ready_environment(_pe_bytes(with_tls=True), clock=clock)
    # ready_environment must keep the *injected* clock, not fall back to time.monotonic (rule 16:
    # anti-timing must be driven by an injectable clock). Pinning identity to `clock` itself -- not to
    # `setup.clock` -- is what catches a regression that ignores the argument and always uses monotonic.
    assert setup.clock is clock, "the injected step clock must be wired through, not time.monotonic"
    box = setup.sandbox(backend=BACKEND)                            # FakeUc: no native engine
    # The sandbox drives the setup's clean environment and injected clock, not fresh ones.
    assert box.environment is setup.environment
    assert box._clock is setup.clock is clock
    # Driving the step clock advances it: consecutive reads strictly increase (no frozen monotonic stub).
    t0 = box._clock()
    t1 = box._clock()
    assert t1 > t0, "the wired clock must be the live step clock, ticking on each read"
    callback = setup.pe.load_base + 0x1000
    box.uc.script = [("code", callback, 2), ("code", box.return_sentinel, 1)]
    results = box.run_tls_callbacks()
    assert len(results) == 1 and results[0].reason == "return"
    assert box.read_register("rcx") == setup.pe.load_base          # the TLS callback ABI was set up
    assert box.read_register("rdx") == 1


@pytest.mark.needs_tool("py:capstone")
def test_sandbox_raises_loudly_when_unicorn_is_unavailable():
    # A ReadySetup that reports the native backend declined must refuse to hand back a harness that
    # cannot run: EmulationDenied naming the reason, never a silent degraded object.
    setup = PE.ready_environment(_pe_bytes())
    declined = PE.ReadySetup(
        pe=setup.pe, environment=setup.environment, tls=setup.tls,
        api_hash_index=setup.api_hash_index, compare_sites=setup.compare_sites,
        clock=setup.clock, unicorn_available=False,
        unicorn_reason="Unicorn declined on this Darwin/arm64 host (test)")
    with pytest.raises(PE.EmulationDenied, match="Darwin/arm64 host"):
        declined.sandbox()
    # An explicit backend (a test fake) still works even when the guarded backend is unavailable.
    box = declined.sandbox(backend=BACKEND)
    assert box.environment is setup.environment


# ============================================================ decoy-proof answer selection
def test_verify_selects_through_the_pinned_gate_and_rejects_a_decoy(tmp_path):
    from shared_findings import FindingsBoard, digest_gate

    setup = PE.ready_environment(_pe_bytes(), compare_sites=False)
    flag = "flag{sha1_hulud_real}"
    board = FindingsBoard(tmp_path / "findings.jsonl",
                          gate=digest_gate("sha256", hashlib.sha256(flag.encode()).hexdigest()))
    winner = setup.verify(board, ["flag{printable_decoy}", flag, "flag{decoy2}"], agent="b226-test")
    assert winner == flag
    assert [f.candidate for f in board.accepted()] == [flag]

    decoy_board = FindingsBoard(tmp_path / "decoy.jsonl",
                                gate=digest_gate("sha256", hashlib.sha256(flag.encode()).hexdigest()))
    assert setup.verify(decoy_board, ["flag{only_a_decoy}"], agent="b226-test") is None
    assert decoy_board.accepted() == []


# ============================================================ real Unicorn (NOT RUN where unavailable)
@pytest.mark.needs_tool("py:unicorn", "py:capstone")
def test_real_unicorn_sandbox_runs_tls_callbacks():
    from solvers.common import native_emulate as ne
    if not ne.UNICORN_AVAILABLE:
        pytest.skip("not run: " + (ne.UNICORN_UNAVAILABLE_REASON
                                   or "Unicorn unavailable (Darwin/arm64 guard)"))
    # Drive the real driver path end to end: ready_environment -> sandbox() on the guarded backend.
    # The TLS callback points at .text (cmp eax,ebx; ret), which returns cleanly to the sentinel.
    setup = PE.ready_environment(_pe_bytes(with_tls=True))
    assert setup.unicorn_available is True
    box = setup.sandbox()                                           # the guarded native backend
    assert box.environment is setup.environment
    results = box.run_tls_callbacks()
    assert len(results) == 1 and results[0].reason == "return"


# ============================================================ the swarm brief
BRIEF = ROOT / "templates" / "static-re" / "pe-native.md.tmpl"
ON_RAMP_NAMES = ("ready_environment", "resolve_api_hash", "COMMON_WINDOWS_APIS",
                 "SafeUnicorn", "WindowsEnvironment", "run_tls_callbacks", "verify")


def test_pe_native_brief_names_a_real_on_ramp():
    text = BRIEF.read_text(encoding="utf-8")
    assert "pe_emu.ready_environment" in text
    for name in ON_RAMP_NAMES:
        assert name in text, f"brief must name the on-ramp symbol {name}"
    # Every on-ramp symbol the brief cites must actually exist on the module (catches a rename drift).
    for name in ("ready_environment", "ReadySetup", "COMMON_WINDOWS_APIS", "SafeUnicorn",
                 "WindowsEnvironment"):
        assert hasattr(PE, name), f"the brief cites pe_emu.{name}, which does not exist"
    assert {"ready_environment", "ReadySetup"} <= set(PE.__all__)


def test_scaffold_materializes_the_pe_native_brief(tmp_path):
    import argparse

    from ctf.cli import re_workbench as cmd

    parser = argparse.ArgumentParser()
    cmd.add_arguments(parser)
    dest = tmp_path / "wb"
    argv = ["scaffold", str(dest), "--challenge", "SHA1-Hulud", "--agents", "6", "--gate-later"]
    assert cmd.run(parser.parse_args(argv)) == 0
    brief = dest / "pe-native.md"
    assert brief.exists(), "the scaffold must materialize the PE-native brief"
    rendered = brief.read_text(encoding="utf-8")
    assert "{{" not in rendered and "}}" not in rendered       # every placeholder was substituted
    assert "SHA1-Hulud" in rendered and "ready_environment" in rendered and "ctf submit" in rendered
