#!/usr/bin/env python3
"""Backlog row 507: the patch-diff common-config guard folded from solvers/binary/d24_cx_dev.py into the
shipped solvers/binary/generic.py config path (ships with no tools/promote.py HOLD).

A patch-diffing day delivers one program as two role BUILDS (a vulnerable and a corrected one) and asks for
the config COMMON to both. The common value is established only when every role build's config is byte-for-byte
equal. generic.answers now returns None for the prefix-level `dNN_analysis_config_<name>` ids when the role
builds diverge and no question names which record to read -- never one build's value plain (AGENTS.md
"Never guess").

  .venv/bin/python -m pytest tests/test_day24_binary_config_guard.py   (or `python tests/test_day24_binary_config_guard.py`)

Synthetic members (always run):
 1. byte-EQUAL role configs: the common value is used, every prefix-level config id answers PLAIN (as today);
 2. DIVERGENT role configs, one build naming the day and the other another day -- generic WOULD send the
    day-naming build's value plain for the common id (the wrong-plain hole): now every prefix-level config id
    is None;
 3. DIVERGENT role configs under the same campaign: None either way (choose_config cannot tell them apart),
    confirmed unchanged;
 4. a single-build day (one body carries the config) is untouched: the prefix-level config stays PLAIN;
 5. the guard reads the question ids only -- with no per-build id naming a second build, it does not fire even
    when two bodies carry divergent configs (so a non-patch-diff day is never demoted).
On the saved Day 24 base ($CTF_REAL_CHALLENGES; not run when it is not there, or while tools/preflight.py, the
replay gate, is archived):
 6. every d24 answer is plain and equal to key.json, proving the byte-equal base is unchanged.
Offline, no token, no Game Master request.
"""
import contextlib
import io
import json
import os
import struct
import sys
import tempfile
import zlib
from pathlib import Path

import pytest

from ctf import paths

REPO = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="test_day24_binary_config_guard_"))
sys.dont_write_bytecode = True
os.environ["CTF_STATE_DIR"] = str(TMP / "state")
# Never the saved tree: CTF_WORKDIR set here outlives this module in a pytest worker, and the saved attempts are
# read only. Only the replay child (test 6) is pointed at them.
os.environ["CTF_WORKDIR"] = str(TMP / "challenges")
os.environ.pop("CTF_PLATFORM_URL", None)
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "solvers" / "binary"))
sys.path.insert(0, str(REPO / "solvers" / "common"))
import generic        # noqa: E402


def check(name, ok, detail=""):
    print(("ok  " if ok else "FAIL") + " " + name + (f"  -- {detail}" if detail and not ok else ""))
    assert ok, name + (f"  -- {detail}" if detail else "")


def record(cfg, key=0x61, crc=None):
    """A raw CRC-valid HCFG container carrying `cfg` as single-byte-XOR-ed JSON (the lane's layout)."""
    plain = json.dumps(cfg, separators=(",", ":")).encode()
    return (b"HCFG" + struct.pack("<BBHI", 1, key, len(plain), zlib.crc32(plain) if crc is None else crc)
            + bytes(b ^ key for b in plain))


BODY = b"\x7fELF\x02\x01\x01" + bytes(range(256)) * 4
CFG = {"campaign": "BR24-000", "domain": "node-000.day24.example.invalid",
       "url": "https://node-000.day24.example.invalid/api/BR24-000", "mutex": "Global\\HuntressBR24_000"}
CONFIG_IDS = ["d24_analysis_config_campaign", "d24_analysis_config_domain",
              "d24_analysis_config_url", "d24_analysis_config_mutex"]
# The patch-diff question shape: two per-build FORMAT ids (two role builds named) and the common config ids.
QUESTIONS = ([{"qid": "d24_analysis_vulnerable_format"}, {"qid": "d24_analysis_corrected_format"}]
             + [{"qid": q} for q in CONFIG_IDS])


def answer(files, questions=QUESTIONS):
    del generic._CHOICES[:]
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        return generic.answers("d24", questions, files, {})


def members(cfg_v, cfg_c):
    return {"d24--sample-vulnerable.bin": BODY + record(cfg_v),
            "d24--sample-corrected.bin": BODY + record(cfg_c)}


# 1. byte-equal role configs -> the common value is used, plain (as today)
def test_1_byte_equal_role_configs_use_the_common_value_plain():
    out = answer(members(CFG, CFG))
    check("1 byte-equal role configs: common value used plain",
          out["d24_analysis_config_campaign"] == "BR24-000"
          and out["d24_analysis_config_url"] == CFG["url"]
          and out["d24_analysis_config_mutex"] == CFG["mutex"]
          and out["d24_analysis_config_domain"] == CFG["domain"],
          repr({k: out[k] for k in CONFIG_IDS}))


# 2. divergent role configs, one naming the day: WAS plain (the hole), now None for every common id
def test_2_divergent_role_configs_one_off_day_are_none():
    out = answer(members(CFG, dict(CFG, campaign="BR99-000", url="https://x/api/BR99-000")))
    check("2 divergent role configs (one off-day): common ids are None, never one build's value plain",
          all(out[q] is None for q in CONFIG_IDS),
          repr({k: out[k] for k in CONFIG_IDS}))


# 3. divergent role configs under the same campaign: None either way, unchanged
def test_3_divergent_role_configs_same_campaign_are_none():
    out = answer(members(CFG, dict(CFG, url="https://x/api/BR24-000", mutex="Global\\HuntressBR24_001")))
    check("3 divergent role configs (same campaign): common ids are None",
          all(out[q] is None for q in CONFIG_IDS),
          repr({k: out[k] for k in CONFIG_IDS}))


# 4. a single-build day (only one body carries a config) is untouched -> plain
def test_4_single_build_day_stays_plain():
    single = {"d24--sample-vulnerable.bin": BODY + record(CFG), "d24--sample-corrected.bin": BODY}
    out = answer(single)
    check("4 one body carries the config: the prefix-level config stays plain",
          out["d24_analysis_config_campaign"] == "BR24-000" and out["d24_analysis_config_url"] == CFG["url"],
          repr({k: out[k] for k in CONFIG_IDS}))


# 5. no per-build id names a second build -> the guard reads the ids only and does not fire, even with two
#    divergent bodies (a non-patch-diff day is never demoted). Here the day-naming body's config stays plain.
def test_5_guard_does_not_fire_without_a_second_build_id():
    no_build_qs = [{"qid": q} for q in CONFIG_IDS]
    out = answer(members(CFG, dict(CFG, campaign="BR99-000", url="https://x/api/BR99-000")), no_build_qs)
    check("5 no second build named in the questions: the guard does not fire",
          out["d24_analysis_config_campaign"] == "BR24-000",
          repr({k: out[k] for k in CONFIG_IDS}))


# 6. the saved Day 24 base: it still replays equal to key.json (the byte-equal base is unchanged). Run the
#    repo's own offline replay (no Game Master request); exit 0 means every answer equalled the key.
def test_6_saved_day24_base_replays_equal_to_key():
    # The saved Huntress attempts (read only), only through ctf.paths: None when $CTF_REAL_CHALLENGES is unset
    # (not run); set to a missing folder, FileNotFoundError fails this test. Never derived from this checkout.
    MAIN_CHALLENGES = paths.saved_challenges_root()
    if MAIN_CHALLENGES is None:
        pytest.skip("not run: CTF_REAL_CHALLENGES is not set (the saved past-event attempts)")
    BASE = MAIN_CHALLENGES / "day-24" / "binary-reverse-engineering-day-24-patch-diffing"
    if not (BASE / "key.json").is_file():
        pytest.skip(f"not run: no saved Day 24 base with key.json under {MAIN_CHALLENGES}")
    if not (REPO / "tools" / "preflight.py").is_file():
        pytest.skip("tools/preflight.py (the replay gate) is archived: docs/migration/ARCHIVED.md")
    import subprocess
    env = dict(os.environ, CTF_WORKDIR=str(MAIN_CHALLENGES))
    r = subprocess.run([sys.executable, str(REPO / "tools" / "preflight.py"), "--replay", str(BASE)],
                       capture_output=True, text=True, env=env)
    check("6 saved Day 24 base: preflight --replay equals key.json (exit 0)", r.returncode == 0,
          (r.stderr or r.stdout).strip()[-200:])


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
