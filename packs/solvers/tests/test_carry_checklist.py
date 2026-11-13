"""B-240: the Huntress post-ledger carry checklist, as an executable test (B-001's acceptance checklist).

For every file the item lists (to_build.json B-240), plus the four day readers and the KB-2 bridge carried with
them, this test fails when the file:

  * is missing from the master tree;
  * fails to import in a fresh interpreter, or imports by silently taking one of its own fallbacks (a guarded
    `try: import x / except: x = None` whose import did not succeed, or a lazily guarded module that is absent),
    or says a native engine is unavailable/declined;
  * imports a third-party package that requirements.in does not pin, or pins at another version than installed;
  * has no declared test, or a declared test does not reference it, or a declared test does not pass.

Declared tests run in a subprocess, once each: `pytest` files must report >= 1 passed and nothing failed or
skipped, except a skip P_NOT_RUN declares (the file's check is then reported not run, with the skip); `script` files (Huntress check()-style tests, vacuous under pytest collection) must exit 0 with no FAIL
line. A script section that needs saved Huntress challenge data the master never has prints a SKIP line; each
such line must match a declared pattern (a new silent skip fails the run) and each declared one is reported in
the NOT RUN summary by test_saved_data_section_not_run. Dedicated tests that are known to fail for a reason
another unit owns are run as strict xfails (KNOWN_FAILING): when they start passing the xfail turns into a
failure, so the entry gets moved into the item's tests.

The checker functions take the repo root, so the last block exercises them on a synthetic tree in tmp_path.
"""
from __future__ import annotations

import ast
import importlib.metadata as md
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
# The engine dirs the root conftest.py puts on sys.path, in the same order (later entries are searched first).
ENGINE_DIRS = ("solvers/common", "solvers/toolkits", "solvers/binary", "solvers/metadata-forensics",
               "solvers/mobile-android", "solvers/script-analysis", "solvers/warmups", "solvers/web",
               "tools", "tests")
P, S = "pytest", "script"


@dataclass(frozen=True)
class Item:
    path: str                       # repo-relative file
    tests: tuple                    # declared test files (keys of TESTS) that must pass
    require: tuple = ()             # names the module must define (the item's named paths)


CHECKLIST = (
    # native emulation (B-226) and the dex-VM work (B-228/B-229)
    Item("solvers/common/native_emulate.py", ("tests/test_native_emulate_loud.py", "tests/test_native_emulate.py",
                                              "tests/test_unicorn_capability_guard.py"),
         ("emulate_function", "emulate_x86_sysv", "emulate_arm64_aapcs", "emulate_symbol", "UNICORN_PIN")),
    Item("solvers/common/native_image.py", ("tests/test_day27_native_image_mobile.py",), ("emulate_symbol",)),
    Item("solvers/mobile-android/native_image_bridge.py", ("tests/test_day27_native_image_mobile.py",)),
    Item("solvers/toolkits/pe_emu.py", ("tests/test_pe_emu.py",)),
    Item("solvers/mobile-android/dex_chain_codec.py", ("tests/test_day25_mobile_native.py",
                                                       "tests/test_speedrun_parsers_hm12.py",
                                                       "tests/test_native_emulate_loud.py",
                                                       "tests/test_day27_split_fold_mobile.py")),
    Item("solvers/mobile-android/dex_float.py", ("tests/test_day27_dex_float_mobile.py",)),
    Item("solvers/mobile-android/native_arm64.py", ("tests/test_day24_native_arm64.py",)),
    # binary: multi-record selection, structural enums, the HCFG storage fold, the Day 29-31 readers (B-225)
    Item("solvers/binary/record_select.py", ("tests/test_day27_record_select_binary.py",
                                             "tests/test_binary_cache_scoping.py")),
    Item("solvers/binary/patch_diff.py", ("tests/test_binary_cache_scoping.py",)),
    Item("solvers/binary/structural_enums.py", ("tests/test_day31_binary_hgrf.py",)),
    Item("solvers/binary/hcfg_storage.py", ("tests/test_review_binary_hcfg_storage_fold.py",)),
    Item("solvers/binary/d29.py", ("tests/test_day29_binary_variants.py",), ("answers",)),
    Item("solvers/binary/d30.py", ("tests/test_binary_day_readers.py",), ("answers",)),
    Item("solvers/binary/fields_d30.py", ("tests/test_binary_day_readers.py",), ("fields",)),
    Item("solvers/binary/fields_d31.py", ("tests/test_binary_day_readers.py",), ("fields", "override", "record")),
    # crypto, stego, unwrap (the leftovers)
    Item("solvers/common/dlog.py", ("tests/test_tk_day27_dlog.py",), ("solve_dlog", "kangaroo")),
    Item("solvers/common/rsa_lattice.py", ("tests/test_day26_rsa_lattice_fast.py",)),
    Item("solvers/common/modern_crypto.py", ("tests/test_day26_aead_dsa.py", "tests/test_day26_aes_modes.py"),
         ("chacha_poly_open", "aes_ccm_open", "aes_siv_open", "aes_xts_decrypt", "aes_xts_encrypt",
          "aes_kw_unwrap", "aes_kwp_unwrap")),
    Item("solvers/toolkits/modern_crypto.py", ("tests/test_day26_aead_dsa.py", "tests/test_day26_aes_modes.py")),
    Item("solvers/toolkits/f5_stego.py", ("tests/test_day26_stego_f5.py",)),
    Item("solvers/toolkits/jpeg_stego.py", ("tests/test_jpeg_stego_survey.py",)),
    Item("solvers/common/unwrap.py", ("tests/test_envelope_peel.py",)),
    # metadata reader packs (B-224)
    Item("solvers/metadata-forensics/readers_forensic.py", ("tests/test_wave4_metadata_forensics.py",
                                                            "tests/test_wave15_dfir_containers.py")),
    Item("solvers/metadata-forensics/readers_forensic_wiring.py", ("tests/test_metadata_cache_scoping.py",)),
    Item("solvers/metadata-forensics/readers_winartifacts.py", ("tests/test_day26_forensic_family.py",)),
    Item("solvers/metadata-forensics/readers_relation.py", ("tests/test_metadata_readers_relation.py",)),
    # web Layer-1 (B-007, B-233..B-237): proof_hunt and the Day-26/27 readers
    Item("solvers/web/proof_hunt.py", ("tests/test_web_route_canonicalization.py", "tests/test_web_display_safety.py",
                                       "tests/test_web_security_json.py", "tests/test_web_cold_dispatch.py",
                                       "tests/test_day21fp_web-proof-hunt.py")),
    Item("solvers/web/forge_event.py", ("tests/test_web_security_json.py", "tests/test_web_route_canonicalization.py",
                                        "tests/test_web_display_safety.py", "tests/test_hm08_web_merge.py",
                                        "tests/test_web_peer_response_carriers.py")),
    Item("solvers/web/double_spend.py", ("tests/test_web_route_canonicalization.py",
                                         "tests/test_web_peer_scope_hardening.py")),
    Item("solvers/web/realtime_read.py", ("tests/test_web_route_canonicalization.py",
                                          "tests/test_web_peer_scope_hardening.py")),
    Item("solvers/web/xxe_read.py", ("tests/test_web_route_canonicalization.py", "tests/test_web_xxe_read.py")),
    Item("solvers/web/ssrf_body.py", ("tests/test_web_route_canonicalization.py",
                                      "tests/test_web_peer_scope_hardening.py", "tests/test_web_ssrf_body.py")),
    Item("solvers/web/hpp_read.py", ("tests/test_web_route_canonicalization.py", "tests/test_web_hpp_read.py")),
    Item("solvers/web/graphql_read.py", ("tests/test_hm08_web_merge.py", "tests/test_web_peer_response_carriers.py",
                                         "tests/test_web_route_canonicalization.py", "tests/test_web_graphql_depth.py")),
    Item("solvers/web/reset_rebind.py", ("tests/test_web_display_safety.py", "tests/test_web_peer_scope_hardening.py",
                                         "tests/test_web_route_canonicalization.py", "tests/test_web_reset_rebind.py")),
    Item("solvers/web/post_chain.py", ("tests/test_hm08_web_merge.py", "tests/test_web_peer_response_carriers.py",
                                       "tests/test_web_display_safety.py", "tests/test_web_peer_scope_hardening.py",
                                       "tests/test_web_route_canonicalization.py", "tests/test_web_post_chain.py")),
    Item("solvers/web/passive_checks.py", ("tests/test_web_display_safety.py", "tests/test_web_peer_scope_hardening.py",
                                           "tests/test_web_route_canonicalization.py",
                                           "tests/test_web_passive_checks.py")),
)

# Not carried, by design, with the reason (reported as not run by test_deferred_file_not_carried).
DEFERRED = {
    "tools/web_open.py": (
        "the Huntress Game Master web opener: its import closure is 18 archived Huntress platform modules (gm, judge, "
        "grade, open_day, preflight, verify, ...; docs/migration/ARCHIVED.md). B-007 ports its release race onto "
        "ctf/platform (B-005); proof_hunt and the readers it drove are carried and checked above"),
}

_SAVED = "needs saved Huntress challenge data or an archived Huntress helper the master never has"
# test file -> (mode, declared SKIP-line patterns for sections the master cannot run)
TESTS = {
    "tests/test_native_emulate_loud.py": (P, ()),
    "tests/test_native_emulate.py": (S, ()),
    "tests/test_unicorn_capability_guard.py": (S, ()),
    "tests/test_day27_native_image_mobile.py": (S, (
        r"SKIP D/day-2[3-6] \(saved APK absent\)", r"SKIP D \(no saved native APKs\)",
        r"SKIP G/legacy \(Day-25 APK absent\)", r"SKIP G/end-to-end \(No module named 'day21_mobile_specimens'\)",
        r"SKIP L/x17 shape \(saved Day 23/25 APKs absent\)",
        r"SKIP test_f[123]_\w+: needs tests/day21_mobile_specimens\.py")),
    "tests/test_pe_emu.py": (S, ()),
    "tests/test_day25_mobile_native.py": (S, (
        r"SKIP arm64/full-transform \(harness unavailable\)", r"SKIP integration \(specimens/ledger unavailable\)",
        r"SKIP arm32-sweep \(harness/specimens unavailable\)", r"SKIP float-dead-op \(D24/solver unavailable\)",
        r"SKIP float-live \(D24/solver unavailable\)")),
    "tests/test_speedrun_parsers_hm12.py": (P, ()),
    "tests/test_day27_dex_float_mobile.py": (S, (r"SKIP Z split reading: the saved Day 26 Time Trial is not on disk",)),
    "tests/test_day27_split_fold_mobile.py": (S, (r"SKIP \[(?:R|N|C|V1)\] .* is not on disk$",
                                                  r"SKIP \[V3\] .*day-2[35]")),
    "tests/test_day24_native_arm64.py": (P, ()),
    "tests/test_day27_record_select_binary.py": (S, (
        r"skip M saved-text invariant \(no saved attempts\)", r"skip H real-data section \(no saved Day 24 members\)",
        r"skip N2g \(no saved Day 24 members\)")),
    "tests/test_binary_cache_scoping.py": (S, ()),
    "tests/test_day31_binary_hgrf.py": (P, ()),
    "tests/test_review_binary_hcfg_storage_fold.py": (P, ()),
    "tests/test_day29_binary_variants.py": (P, ()),
    "tests/test_binary_day_readers.py": (P, ()),
    "tests/test_tk_day27_dlog.py": (S, ()),
    "tests/test_day26_rsa_lattice_fast.py": (S, ()),
    "tests/test_day26_aead_dsa.py": (S, ()),
    "tests/test_day26_aes_modes.py": (S, ()),
    "tests/test_day26_stego_f5.py": (S, ()),
    "tests/test_jpeg_stego_survey.py": (S, ()),
    "tests/test_envelope_peel.py": (P, ()),
    "tests/test_wave4_metadata_forensics.py": (S, ()),
    "tests/test_wave15_dfir_containers.py": (S, ()),
    "tests/test_metadata_cache_scoping.py": (S, ()),
    "tests/test_day26_forensic_family.py": (S, ()),
    "tests/test_metadata_readers_relation.py": (P, ()),
    "tests/test_web_route_canonicalization.py": (P, ()),
    "tests/test_web_display_safety.py": (P, ()),
    "tests/test_web_security_json.py": (P, ()),
    "tests/test_hm08_web_merge.py": (P, ()),
    "tests/test_web_peer_response_carriers.py": (P, ()),
    "tests/test_web_peer_scope_hardening.py": (P, ()),
    # The Huntress proof-model reader tests (R-06): each pins the huntress profile itself (tests/event_pin.py).
    "tests/test_web_cold_dispatch.py": (S, ()),
    "tests/test_day21fp_web-proof-hunt.py": (S, ()),
    "tests/test_web_xxe_read.py": (P, ()),
    "tests/test_web_ssrf_body.py": (P, ()),
    "tests/test_web_hpp_read.py": (P, ()),
    "tests/test_web_graphql_depth.py": (P, ()),
    "tests/test_web_reset_rebind.py": (S, ()),
    "tests/test_web_post_chain.py": (S, ()),
    "tests/test_web_passive_checks.py": (P, ()),
}

# pytest file -> skip reasons it may report (re.search on each `-rs` SKIPPED line), for a part that cannot run on
# this machine. Any other skip still fails the file. When a declared one fires, the file must otherwise pass, and
# test_declared_test_passes then reports itself not run with the skip lines (never passed).
P_NOT_RUN = {
    # SH-09: the pool's cost bound needs the work meter (tests/sh09_clocks.py, an Apple M4 Max only); on another
    # chip its answer checks run first and then only the cost bound is reported not run (cost_not_run)
    "tests/test_day31_binary_hgrf.py": (r"not run: the cost bound has no work meter \(",),
}

# Dedicated tests of carried files that fail in the master for a reason another unit owns: (mode, reason).
# Empty since R-06 moved the nine Huntress web proof-model tests into TESTS; an entry here runs as a strict
# xfail, so when it starts passing the run fails until it is moved.
KNOWN_FAILING = {}

# The pins B-240 owns: requirements.in and requirements.lock.txt must both say these.
OWNED_PINS = {"unicorn": "2.1.4", "capstone": "5.0.9", "cryptography": "50.0.2", "pycryptodomex": "3.23.0"}


# ============================================================================================= checker functions
def missing_files(root: Path, paths) -> list:
    return [p for p in paths if not (root / p).is_file()]


def _bound_names(node) -> list:
    if isinstance(node, ast.Import):
        return [(a.asname or a.name.split(".")[0], a.name, True) for a in node.names]
    return [(a.asname or a.name, f"{node.module}.{a.name}", False) for a in node.names]


def guarded_imports(src: str):
    """(module-level names bound by a guarded import whose handler does not re-raise, lazily guarded modules)."""
    tree = ast.parse(src)
    top, lazy = [], []
    top_tries = {id(n) for n in tree.body if isinstance(n, ast.Try)}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        imps = [n for n in node.body if isinstance(n, (ast.Import, ast.ImportFrom)) and getattr(n, "level", 0) == 0]
        if not imps or all(any(isinstance(x, ast.Raise) for x in ast.walk(h)) for h in node.handlers):
            continue
        for imp in imps:
            if id(node) in top_tries:
                top += [(name, target, is_mod) for name, target, is_mod in _bound_names(imp)]
            else:
                lazy += [a.name for a in imp.names] if isinstance(imp, ast.Import) else [imp.module]
    return top, sorted(set(lazy))


_PROBE = r"""
import importlib, importlib.util, json, sys, types, warnings
root, rel, dirs, top, lazy, need = sys.argv[1:7]
dirs, top, lazy, need = json.loads(dirs), json.loads(top), json.loads(lazy), json.loads(need)
sys.path[:0] = [root] + [root + "/" + d for d in reversed(dirs)]
out = {"error": None, "fallbacks": [], "said": [], "missing_names": []}
stem = rel.rsplit("/", 1)[-1][:-3]
with warnings.catch_warnings(record=True) as caught:
    warnings.simplefilter("always")
    try:
        spec = importlib.util.spec_from_file_location(stem, root + "/" + rel)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[stem] = mod
        spec.loader.exec_module(mod)
    except BaseException as e:
        out["error"] = "%s: %s" % (type(e).__name__, e)
    if out["error"] is None:
        for name, target, is_mod in top:
            got = getattr(mod, name, None)
            if got is None or (is_mod and not isinstance(got, types.ModuleType)):
                out["fallbacks"].append("%s (module-level guard for %s)" % (name, target))
        for m in lazy:
            try:
                importlib.import_module(m)
            except BaseException as e:
                out["fallbacks"].append("%s (lazy guard): %s: %s" % (m, type(e).__name__, e))
        out["missing_names"] = [n for n in need if not hasattr(mod, n)]
out["said"] = [str(w.message) for w in caught
               if issubclass(w.category, RuntimeWarning) and ("unavailable" in str(w.message) or "declined" in str(w.message))]
print("B240-PROBE " + json.dumps(out))
"""


def _child_env(tmp: Path) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PYTEST_", "CTF_", "CSCTF_", "HUNTRESS_"))}
    # Engines read the flag format from the active event profile (ctf.flagfmt, B-001a): a dedicated test
    # runs as the suite does (conftest.py's default event, csctf), script-style ones included.
    env.update(CTF_WORKDIR=str(tmp), CTF_TESTING="1", CTF_EVENT="csctf", PYTHONDONTWRITEBYTECODE="1")
    return env


def probe_import(root: Path, rel: str, tmp: Path, need=()) -> dict:
    top, lazy = guarded_imports((root / rel).read_text(errors="replace"))
    proc = subprocess.run([PY, "-I", "-c", _PROBE, str(root), rel, json.dumps(ENGINE_DIRS), json.dumps(top),
                           json.dumps(lazy), json.dumps(list(need))],
                          cwd=root, env=_child_env(tmp), capture_output=True, text=True, timeout=300)
    line = [x for x in proc.stdout.splitlines() if x.startswith("B240-PROBE ")]
    if not line:
        return {"error": f"probe died rc={proc.returncode}: {proc.stderr[-1500:]}", "fallbacks": [], "said": [],
                "missing_names": []}
    return json.loads(line[-1][len("B240-PROBE "):])


def _local_names(root: Path) -> set:
    names = {"solvers", "ctf", "tools", "tests"}
    for d in ENGINE_DIRS:
        base = root / d
        if base.is_dir():
            names |= {p.stem for p in base.glob("*.py")}
            names |= {p.name for p in base.iterdir() if p.is_dir() and (p / "__init__.py").exists()}
    return names


def third_party_imports(root: Path, rel: str) -> set:
    tree = ast.parse((root / rel).read_text(errors="replace"))
    mods = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
            mods.add(n.module.split(".")[0])
    return {m for m in mods if m not in sys.stdlib_module_names and m not in _local_names(root) and m != "__future__"}


def _canon(dist: str) -> str:
    return re.sub(r"[-_.]+", "-", dist).lower()


def read_pins(path: Path) -> dict:
    pins = {}
    for line in path.read_text().splitlines():
        m = re.match(r"^([A-Za-z0-9_.\-]+)==(\S+)", line.strip())
        if m:
            pins[_canon(m.group(1))] = m.group(2)
    return pins


def unpinned(root: Path, rel: str) -> list:
    """Problems with the third-party packages `rel` imports: not installed, not pinned, or pinned != installed."""
    pins, dists, out = read_pins(root / "requirements.in"), md.packages_distributions(), []
    for mod in sorted(third_party_imports(root, rel)):
        found = dists.get(mod)
        if not found:
            out.append(f"{mod}: imported but no installed distribution provides it")
            continue
        for dist in found:
            pin, have = pins.get(_canon(dist)), md.version(dist)
            if pin is None:
                out.append(f"{mod}: {dist}=={have} is not pinned in requirements.in")
            elif pin != have:
                out.append(f"{mod}: requirements.in pins {dist}=={pin}, .venv has {have}")
    return out


def references(root: Path, test: str, rel: str) -> bool:
    stem = Path(rel).stem
    src = (root / test).read_text(errors="replace")
    s = re.escape(stem)
    # an import (also one inside a subprocess code string), or the file named (a test that drives it through a
    # dispatcher names the file it covers)
    pat = (rf"^\s*(?:import|from)\s+[\w.]*\b{s}\b|['\"]\s*import\s+{s}\b|import_module\(\s*['\"][\w.]*{s}['\"]"
           rf"|\b{s}\.py\b")
    return re.search(pat, src, re.M) is not None


_SKIP_LINE = re.compile(r"^\s*(?:SKIP|skip)\b.*$", re.M)
_FAIL_LINE = re.compile(r"^\s*FAIL\b.*$", re.M)


def run_test_file(root: Path, test: str, mode: str, tmp: Path, allowed_skips=()) -> tuple:
    """(ok, why, skip_lines). Runs `test` in a subprocess from `root`."""
    if mode == P:
        cmd = [PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "no:xdist", "--timeout", "600", "-rs", test]
    else:
        cmd = [PY, test]
    try:
        proc = subprocess.run(cmd, cwd=root, env=_child_env(tmp), capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired:
        return False, "timed out after 900 s", []
    text = proc.stdout + "\n" + proc.stderr
    tail = text.strip()[-1500:]
    if mode == P:
        summary = [ln for ln in text.splitlines() if re.search(r"\b\d+ (passed|failed|errors?|skipped)\b|no tests ran", ln)]
        last = summary[-1] if summary else ""
        counts = {k: int(n) for n, k in re.findall(r"(\d+) (passed|failed|errors?|skipped|xfailed|xpassed)", last)}
        if proc.returncode != 0 or counts.get("failed") or counts.get("error") or counts.get("errors"):
            return False, f"pytest rc={proc.returncode}: {last or tail}", []
        if counts.get("passed", 0) < 1:
            return False, f"no test passed: {last or tail}", []
        if counts.get("skipped"):
            skips = [ln.strip() for ln in text.splitlines() if ln.startswith("SKIPPED [")]
            # -rs folds skips with one place and reason into one line: `SKIPPED [n] path:line: reason`
            folded = sum(int(m.group(1)) for s in skips for m in [re.match(r"SKIPPED \[(\d+)\]", s)] if m)
            if (not allowed_skips or folded != counts["skipped"]
                    or not all(any(re.search(p, s) for p in allowed_skips) for s in skips)):
                return False, f"skipped tests are not declared: {last}", skips
            return True, f"{last}, all declared", skips
        return True, last, []
    if proc.returncode != 0:
        return False, f"script rc={proc.returncode}: {tail}", []
    fails = _FAIL_LINE.findall(proc.stdout)
    if fails:
        return False, f"FAIL lines with rc 0: {fails[:3]}", []
    skips = [s.strip() for s in _SKIP_LINE.findall(proc.stdout)]
    undeclared = [s for s in skips if not any(re.match(p, s) for p in allowed_skips)]
    if undeclared:
        return False, f"undeclared skipped sections: {undeclared[:5]}", skips
    return True, f"rc=0, {len(skips)} declared skip line(s)", skips


# ============================================================================================= the checklist
ITEM_IDS = [it.path for it in CHECKLIST]


def test_checklist_is_consistent():
    paths = [it.path for it in CHECKLIST]
    assert len(paths) == len(set(paths)), "an item is listed twice"
    used = {t for it in CHECKLIST for t in it.tests}
    assert used <= set(TESTS), f"tests used but not declared: {sorted(used - set(TESTS))}"
    assert set(TESTS) <= used, f"declared tests no item uses: {sorted(set(TESTS) - used)}"
    assert not set(DEFERRED) & set(paths)
    assert not set(KNOWN_FAILING) & set(TESTS), "a test cannot be both required and known-failing"
    assert set(P_NOT_RUN) <= {t for t, (m, _) in TESTS.items() if m == P}, "P_NOT_RUN names a file that is not a pytest test"


@pytest.mark.parametrize("item", CHECKLIST, ids=ITEM_IDS)
def test_file_is_present(item):
    assert not missing_files(ROOT, [item.path]), f"{item.path} is missing from the master tree"


@pytest.mark.parametrize("item", CHECKLIST, ids=ITEM_IDS)
def test_imports_with_no_silent_fallback(item, tmp_path):
    got = probe_import(ROOT, item.path, tmp_path, item.require)
    assert got["error"] is None, f"{item.path} does not import: {got['error']}"
    assert not got["fallbacks"], f"{item.path} imported by falling back: {got['fallbacks']}"
    assert not got["said"], f"{item.path} imported with an engine unavailable: {got['said']}"
    assert not got["missing_names"], f"{item.path} lacks {got['missing_names']}"


@pytest.mark.parametrize("item", CHECKLIST, ids=ITEM_IDS)
def test_third_party_imports_are_pinned(item):
    assert not unpinned(ROOT, item.path), unpinned(ROOT, item.path)


@pytest.mark.parametrize("item", CHECKLIST, ids=ITEM_IDS)
def test_has_declared_tests_that_reference_it(item):
    assert item.tests, f"{item.path} has no declared test"
    for test in item.tests:
        assert (ROOT / test).is_file(), f"{test} (declared for {item.path}) is missing"
        assert references(ROOT, test, item.path), f"{test} does not import or name {Path(item.path).name}"


@pytest.mark.slow
@pytest.mark.parametrize("test", sorted(TESTS))
def test_declared_test_passes(test, tmp_path):
    mode, skips = TESTS[test]
    if mode == P:
        skips = P_NOT_RUN.get(test, ())
    ok, why, skip_lines = run_test_file(ROOT, test, mode, tmp_path, skips)
    assert ok, f"{test} ({mode}): {why}"
    assert not any(p.name == "challenges" for p in ROOT.iterdir()), f"{test} wrote a challenges/ folder into the repo"
    if mode == P and skip_lines:
        pytest.skip(f"{test}: the rest passed, but declared parts were not run: {skip_lines[:3]}")


if KNOWN_FAILING:
    # Defined only while the registry has entries: parametrizing over an empty dict collects as a skip
    # ("got empty parameter set"), which the not-run report would count as a test that did not run.
    @pytest.mark.slow
    @pytest.mark.parametrize("test", sorted(KNOWN_FAILING))
    def test_known_failing_dedicated_test(test, tmp_path, request):
        mode, reason = KNOWN_FAILING[test]
        request.node.add_marker(pytest.mark.xfail(reason=reason, strict=True))
        ok, why, _ = run_test_file(ROOT, test, mode, tmp_path)
        assert ok, f"{test} ({mode}): {why}"


@pytest.mark.parametrize("pattern", [(t, p) for t, (_m, ps) in sorted(TESTS.items()) for p in ps],
                         ids=lambda tp: f"{Path(tp[0]).stem}:{tp[1][:40]}")
def test_saved_data_section_not_run(pattern):
    test, pat = pattern
    pytest.skip(f"{test} section /{pat}/: {_SAVED}")


@pytest.mark.parametrize("path", sorted(DEFERRED))
def test_deferred_file_not_carried(path):
    assert not (ROOT / path).exists(), f"{path} is now in the tree: move it from DEFERRED into CHECKLIST"
    pytest.skip(f"{path} deferred: {DEFERRED[path]}")


def test_owned_pins_agree_everywhere():
    req, lock = read_pins(ROOT / "requirements.in"), read_pins(ROOT / "requirements.lock.txt")
    for dist, ver in OWNED_PINS.items():
        assert req.get(_canon(dist)) == ver, f"requirements.in: {dist} must be =={ver}"
        assert lock.get(_canon(dist)) == ver, f"requirements.lock.txt: {dist} must be =={ver}"
        assert md.version(dist) == ver, f".venv has {dist}=={md.version(dist)}, pinned {ver}"
    # R-14: and in exactly what setup.sh installs (every requirements file its pip installs name).
    import requirements_gen as rg
    installed = [f for inst in rg.setup_installs((ROOT / "setup.sh").read_text()) for f in inst.files]
    assert installed, "setup.sh installs no requirements file"
    for rel in installed:
        pins = read_pins(ROOT / rel)
        for dist, ver in OWNED_PINS.items():
            assert pins.get(_canon(dist)) == ver, f"setup.sh installs {rel}, which does not pin {dist}=={ver}"


# ============================================================================================= the checker, tested
def _tree(tmp: Path) -> Path:
    root = tmp / "repo"
    (root / "solvers" / "common").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "requirements.in").write_text("pytest==%s\n" % md.version("pytest"))
    (root / "solvers/common/good.py").write_text("import json\nVALUE = 7\n")
    (root / "solvers/common/helper.py").write_text("X = 1\n")
    (root / "solvers/common/broken.py").write_text("raise ImportError('synthetic: a dependency is gone')\n")
    (root / "solvers/common/guarded.py").write_text(
        "try:\n    import b240_absent_module_xyz\nexcept Exception:\n    b240_absent_module_xyz = None\n")
    (root / "solvers/common/guarded_ok.py").write_text(
        "try:\n    import helper\nexcept Exception:\n    helper = None\n")
    (root / "solvers/common/lazy.py").write_text(
        "def f():\n    try:\n        import b240_absent_lazy_xyz\n    except ImportError:\n        return None\n")
    (root / "solvers/common/loud.py").write_text(
        "try:\n    import b240_absent_module_xyz\nexcept Exception as e:\n    raise ImportError('named') from e\n")
    (root / "solvers/common/thirdparty.py").write_text("import pytest\nimport pluggy\n")
    (root / "tests/test_good.py").write_text("import good\n\ndef test_value():\n    assert good.VALUE == 7\n")
    (root / "tests/test_bad.py").write_text("import good\n\ndef test_value():\n    assert good.VALUE == 8\n")
    (root / "tests/test_skips.py").write_text(
        "import pytest\nimport good\n\ndef test_a():\n    assert good.VALUE\n\n"
        "def test_b():\n    pytest.skip('no data')\n")
    (root / "tests/test_none.py").write_text("import good\n")
    (root / "tests/script_ok.py").write_text("print('ok   a')\nprint('SKIP Z saved data')\n")
    (root / "tests/script_fail_line.py").write_text("print('FAIL a check')\n")
    (root / "tests/script_rc.py").write_text("import sys\nsys.exit(1)\n")
    (root / "conftest.py").write_text(
        "import sys\nfrom pathlib import Path\nsys.path.insert(0, str(Path(__file__).parent / 'solvers/common'))\n")
    return root


def test_checker_reports_a_missing_file(tmp_path):
    root = _tree(tmp_path)
    assert missing_files(root, ["solvers/common/good.py", "solvers/common/gone.py"]) == ["solvers/common/gone.py"]


def test_checker_reports_import_failure_fallback_and_missing_names(tmp_path):
    root = _tree(tmp_path)
    assert probe_import(root, "solvers/common/good.py", tmp_path, ("VALUE",)) == {
        "error": None, "fallbacks": [], "said": [], "missing_names": []}
    assert probe_import(root, "solvers/common/good.py", tmp_path, ("absent",))["missing_names"] == ["absent"]
    assert "synthetic: a dependency is gone" in probe_import(root, "solvers/common/broken.py", tmp_path)["error"]
    assert probe_import(root, "solvers/common/guarded.py", tmp_path)["fallbacks"] == [
        "b240_absent_module_xyz (module-level guard for b240_absent_module_xyz)"]
    assert probe_import(root, "solvers/common/guarded_ok.py", tmp_path)["fallbacks"] == []
    assert probe_import(root, "solvers/common/lazy.py", tmp_path)["fallbacks"][0].startswith(
        "b240_absent_lazy_xyz (lazy guard): ModuleNotFoundError")
    loud = probe_import(root, "solvers/common/loud.py", tmp_path)       # a re-raising guard is not a fallback
    assert loud["error"] == "ImportError: named" and loud["fallbacks"] == []


def test_checker_reports_unpinned_third_party_imports(tmp_path):
    root = _tree(tmp_path)
    assert unpinned(root, "solvers/common/good.py") == []
    assert unpinned(root, "solvers/common/thirdparty.py") == [
        f"pluggy: pluggy=={md.version('pluggy')} is not pinned in requirements.in"]
    (root / "requirements.in").write_text("pytest==0.0.1\npluggy==%s\n" % md.version("pluggy"))
    assert unpinned(root, "solvers/common/thirdparty.py") == [
        f"pytest: requirements.in pins pytest==0.0.1, .venv has {md.version('pytest')}"]


def test_checker_reports_tests_that_do_not_pass(tmp_path):
    root = _tree(tmp_path)
    assert run_test_file(root, "tests/test_good.py", P, tmp_path)[0] is True
    ok, why, _ = run_test_file(root, "tests/test_bad.py", P, tmp_path)
    assert not ok and "failed" in why
    ok, why, _ = run_test_file(root, "tests/test_skips.py", P, tmp_path)
    assert not ok and "skipped" in why
    ok, why, _ = run_test_file(root, "tests/test_skips.py", P, tmp_path, (r"not this reason",))
    assert not ok and "skipped" in why
    ok, why, skips = run_test_file(root, "tests/test_skips.py", P, tmp_path, (r": no data$",))
    assert ok and len(skips) == 1 and skips[0].startswith("SKIPPED [1] tests/test_skips.py") and "no data" in skips[0]
    (root / "tests/test_skips2.py").write_text(
        "import pytest\nimport good\n\ndef test_a():\n    assert good.VALUE\n\n"
        "def test_b():\n    pytest.skip('no data')\n\ndef test_c():\n    pytest.skip('something else')\n")
    ok, why, _ = run_test_file(root, "tests/test_skips2.py", P, tmp_path, (r": no data$",))
    assert not ok and "skipped" in why                      # one declared skip does not cover another
    (root / "tests/test_skips4.py").write_text(
        "import pytest\nimport good\n\ndef test_a():\n    assert good.VALUE\n\n"
        "@pytest.mark.parametrize('n', [1, 2, 3])\ndef test_b(n):\n    pytest.skip('no data')\n")
    ok, why, skips = run_test_file(root, "tests/test_skips4.py", P, tmp_path, (r": no data$",))
    assert ok and len(skips) == 1 and skips[0].startswith("SKIPPED [3] "), (why, skips)   # three, folded
    (root / "tests/test_skips3.py").write_text(
        "import pytest\nimport good\n\ndef test_b():\n    pytest.skip('no data')\n\n"
        "def test_c():\n    assert good.VALUE == 8\n")
    ok, why, _ = run_test_file(root, "tests/test_skips3.py", P, tmp_path, (r": no data$",))
    assert not ok and "failed" in why                       # a declared skip never covers a failure
    ok, why, _ = run_test_file(root, "tests/test_none.py", P, tmp_path)
    assert not ok
    assert run_test_file(root, "tests/script_ok.py", S, tmp_path, (r"SKIP Z saved data",))[0] is True
    ok, why, skips = run_test_file(root, "tests/script_ok.py", S, tmp_path)
    assert not ok and "undeclared skipped sections" in why and skips == ["SKIP Z saved data"]
    assert run_test_file(root, "tests/script_fail_line.py", S, tmp_path)[0] is False
    assert run_test_file(root, "tests/script_rc.py", S, tmp_path)[0] is False


def test_hgrf_declared_skip_is_the_cost_not_run_message(tmp_path):
    """P_NOT_RUN's hgrf pattern accepts what tests/sh09_clocks.cost_not_run reports through a real pytest run
    (a chip with no work meter, stood in for by a synthetic file), and no other skip."""
    root = _tree(tmp_path)
    (root / "tests/sh09_clocks.py").write_text((ROOT / "tests/sh09_clocks.py").read_text())
    (root / "tests/test_cost.py").write_text(
        "import sys\nfrom pathlib import Path\nsys.path.insert(0, str(Path(__file__).parent))\n"
        "import good\nfrom sh09_clocks import cost_not_run\n\n"
        "def test_answers():\n    assert good.VALUE == 7\n\n"
        "def test_cost():\n    assert good.VALUE == 7\n    cost_not_run(\"no top clock is known for the chip 'Other'\")\n\n"
        "def test_other():\n    import pytest\n    pytest.skip('not run: no corpus')\n")
    pats = P_NOT_RUN["tests/test_day31_binary_hgrf.py"]
    ok, why, skips = run_test_file(root, "tests/test_cost.py", P, tmp_path, pats)
    assert not ok and "skipped" in why and len(skips) == 2           # the other skip is not covered
    assert sum(any(re.search(p, s) for p in pats) for s in skips) == 1
    (root / "tests/test_cost.py").write_text(
        (root / "tests/test_cost.py").read_text().split("\ndef test_other")[0])
    ok, why, skips = run_test_file(root, "tests/test_cost.py", P, tmp_path, pats)
    assert ok and len(skips) == 1 and "no work meter" in skips[0], (why, skips)
    # ... and the checklist node then reports itself not run with that skip line, never passed
    mod = sys.modules[__name__]
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(mod, "ROOT", root)
        mp.setattr(mod, "TESTS", {"tests/test_cost.py": (P, ())})
        mp.setattr(mod, "P_NOT_RUN", {"tests/test_cost.py": pats})
        with pytest.raises(pytest.skip.Exception, match="declared parts were not run: .*no work meter"):
            test_declared_test_passes("tests/test_cost.py", tmp_path)
        mp.setattr(mod, "P_NOT_RUN", {})
        with pytest.raises(AssertionError, match="skipped tests are not declared"):
            test_declared_test_passes("tests/test_cost.py", tmp_path)


def test_checker_reference_and_guard_detection():
    assert references(ROOT, "tests/test_binary_day_readers.py", "solvers/binary/fields_d31.py")
    assert not references(ROOT, "tests/test_binary_day_readers.py", "solvers/common/dlog.py")
    top, lazy = guarded_imports("try:\n    import a as b\nexcept ImportError:\n    b = None\n"
                                "def f():\n    try:\n        from c.d import e\n    except Exception:\n        pass\n"
                                "try:\n    import g\nexcept Exception:\n    raise\n")
    assert top == [("b", "a", True)] and lazy == ["c.d"]
