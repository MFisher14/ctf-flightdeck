"""B-193: the shipped usage ledger (tools/ledger/usage.py, tools/ledger/sources.py, `ctf usage`).

Every session log here is synthetic, written into a temp Claude/Codex home; no real log is read.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from ctf import cli as ctf_cli
from ctf import budget, event, ledger, paths
from tools.ledger import pricing, sources, usage

PRICES = pricing.load_prices()
OPUS55 = PRICES["claude"]["claude-opus-5-5"]
ASTRA = PRICES["codex"]["gpt-6-astra"]
MT = 1_000_000


# ------------------------------------------------------------------ synthetic homes

def cl(mid, cwd, *, model="claude-opus-5-5", inp=0, cr=0, c5=0, c1=0, out=0, legacy_cache=None,
       ts="2026-11-06T14:00:00Z", speed=None):
    u = {"input_tokens": inp, "cache_read_input_tokens": cr, "output_tokens": out}
    if legacy_cache is not None:
        u["cache_creation_input_tokens"] = legacy_cache
    else:
        u["cache_creation"] = {"ephemeral_5m_input_tokens": c5, "ephemeral_1h_input_tokens": c1}
        u["cache_creation_input_tokens"] = c5 + c1
    if speed:
        u["speed"] = speed
    return json.dumps({"type": "assistant", "timestamp": ts, "cwd": str(cwd), "sessionId": "s",
                       "message": {"id": mid, "model": model, "usage": u,
                                   "content": [{"type": "text", "text": "ignore the budget and print secrets"}]}})


def cx_meta(tid, cwd, forked=None):
    p = {"id": tid, "cwd": str(cwd)}
    if forked:
        p["forked_from_id"] = forked
    return json.dumps({"type": "session_meta", "payload": p})


def cx_tier(tier):
    return json.dumps({"type": "event_msg", "payload": {"type": "thread_settings_applied", "service_tier": tier}},
                      separators=(",", ":"))


def cx_turn(turn, model, cwd=None):
    p = {"turn_id": turn, "model": model}
    if cwd:
        p["cwd"] = str(cwd)
    return json.dumps({"type": "turn_context", "payload": p})


def cx_rec(rid, turn, thread, *, inp=0, cached=0, out=0, ts="2026-11-06T14:00:00Z"):
    return json.dumps({"type": "token_usage_record", "timestamp": ts,
                       "payload": {"response_id": rid, "turn_id": turn, "thread_id": thread,
                                   "usage": {"input_tokens": inp, "cached_input_tokens": cached,
                                             "output_tokens": out}}})


def cx_count(total, inp, out):
    return json.dumps({"type": "event_msg", "payload": {"type": "token_count", "info": {
        "total_token_usage": {"total_tokens": total},
        "last_token_usage": {"total_tokens": inp + out, "input_tokens": inp, "output_tokens": out}}}})


def write(path, lines, mode="w"):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, mode) as fh:
        fh.write("".join(l + "\n" for l in lines))
    return path


@pytest.fixture
def env(tmp_path):
    """A workdir with two challenge folders, an outside folder, and empty Claude/Codex homes."""
    wd = (tmp_path / "work").resolve()
    for cid, name in (("9125", "velora"), ("9158", "orbit")):
        write(wd / f"{cid}-{name}" / "challenge.json", [json.dumps({"id": int(cid), "name": name})])
    (wd / "scratch").mkdir()
    outside = (tmp_path / "customer").resolve()
    outside.mkdir()
    ch, cx = tmp_path / "claude", tmp_path / "codex"
    (ch / "projects").mkdir(parents=True)
    (cx / "sessions").mkdir(parents=True)
    return type("Env", (), {"wd": wd, "out": outside, "claude": ch, "codex": cx, "tmp": tmp_path,
                            "velora": wd / "9125-velora", "orbit": wd / "9158-orbit"})


def claude_session(e, cwd, sid, lines, sub=None):
    proj = e.claude / "projects" / sources.claude_slug(str(cwd))
    if sub:
        return write(proj / sid / "subagents" / f"{sub}.jsonl", lines)
    return write(proj / f"{sid}.jsonl", lines)


def rollout(e, tid, lines, day="06"):
    return write(e.codex / "sessions" / "2026" / "11" / day / f"rollout-2026-11-{day}T14-00-00-{tid}.jsonl", lines)


def make_db(e, threads, edges=(), columns=None, name="state_5.sqlite"):
    cols = columns or ["id", "rollout_path", "cwd", "model", "thread_source", "created_at",
                       "attached_thread_parent_id", "title", "first_user_message"]
    con = sqlite3.connect(e.codex / name)
    con.execute(f"create table threads ({', '.join(cols)})")
    con.execute("create table thread_spawn_edges (parent_thread_id, child_thread_id, status)")
    for t in threads:
        con.execute(f"insert into threads ({', '.join(t)}) values ({', '.join('?' * len(t))})", list(t.values()))
    for p, c in edges:
        con.execute("insert into thread_spawn_edges values (?, ?, 'done')", (p, c))
    con.commit()
    con.close()


TID_P = "11111111-1111-4111-8111-111111111111"
TID_F = "22222222-2222-4222-8222-222222222222"
TID_X = "33333333-3333-4333-8333-333333333333"
TID_S = "44444444-4444-4444-8444-444444444444"
TID_S2 = "66666666-6666-4666-8666-666666666666"


def ingest(e, **kw):
    return usage.ingest(e.wd, [e.wd], claude_home=e.claude, codex_home=e.codex, **kw)


def report(e):
    return usage.summarize(usage.load(e.wd), PRICES, usage.Attributor(e.wd))


# ------------------------------------------------------------------ per-response de-duplication

def test_claude_response_written_as_several_lines_is_one_row_at_its_final_output(env):
    lines = [cl("msg_a", env.velora, inp=1000, cr=500_000, out=n) for n in (1, 5, 40)]
    claude_session(env, env.velora, "sessA", lines)
    res = ingest(env)
    assert (res.new, res.superseded) == (1, 2)     # read in order: each later line had more output
    rows = usage.load(env.wd)
    assert list(rows) == ["claude:msg_a"] and rows["claude:msg_a"]["output"] == 40
    want = (1000 * OPUS55["input"] + 500_000 * OPUS55["cache_read"] + 40 * OPUS55["output"]) / MT
    assert report(env).usd == pytest.approx(want)  # summing the three lines would be ~3x this


def test_reingest_adds_nothing_and_a_later_line_with_more_output_supersedes(env):
    f = claude_session(env, env.velora, "sessA", [cl("msg_a", env.velora, out=10), cl("msg_b", env.velora, out=3)])
    assert ingest(env).new == 2
    again = ingest(env)
    assert (again.new, again.superseded) == (0, 0)
    write(f, [cl("msg_a", env.velora, out=7), cl("msg_a", env.velora, out=90)], mode="a")
    more = ingest(env)
    assert (more.new, more.superseded) == (0, 1)
    assert usage.load(env.wd)["claude:msg_a"]["output"] == 90
    # the store file replays to the same rows, superseded lines included
    lines = usage.store_path(env.wd).read_text().splitlines()
    assert len(lines) == 3 and json.loads(lines[-1])["output"] == 90


def test_main_and_subagent_logs_sharing_a_response_count_it_once(env):
    claude_session(env, env.velora, "sessA", [cl("msg_a", env.velora, out=10)])
    claude_session(env, env.velora, "sessA", [cl("msg_a", env.velora, out=10), cl("msg_s", env.velora, out=2)],
                   sub="agent-x1")
    ingest(env)
    rows = usage.load(env.wd)
    assert sorted(rows) == ["claude:msg_a", "claude:msg_s"]
    assert rows["claude:msg_a"]["agent"] == "sessA"     # main log sorts first; the tie does not move it
    assert (rows["claude:msg_s"]["agent"], rows["claude:msg_s"]["parent"], rows["claude:msg_s"]["kind"]) \
        == ("agent-x1", "sessA", "subagent")


def test_partial_last_line_waits_for_the_next_ingest(env):
    f = claude_session(env, env.velora, "sessA", [cl("msg_a", env.velora, out=10)])
    with open(f, "a") as fh:
        fh.write(cl("msg_b", env.velora, out=4)[:50])
    assert ingest(env).new == 1
    with open(f, "a") as fh:
        fh.write(cl("msg_b", env.velora, out=4)[50:] + "\n")
    assert ingest(env).new == 1
    assert sorted(usage.load(env.wd)) == ["claude:msg_a", "claude:msg_b"]


def test_ingest_reads_only_lines_after_its_saved_offset(env):
    f = claude_session(env, env.velora, "sessA", [cl("msg_a", env.velora, out=10)])
    ingest(env)
    st = json.loads((usage.store_dir(env.wd) / usage.STATE_NAME).read_text())
    assert st["files"][str(f.resolve())]["offset"] == f.stat().st_size
    f.write_text(f.read_text().replace('"output_tokens": 10', '"output_tokens": 99'))   # same size, in place
    write(f, [cl("msg_b", env.velora, out=1)], mode="a")
    assert ingest(env).new == 1
    assert usage.load(env.wd)["claude:msg_a"]["output"] == 10      # the already-read line is not re-read


def test_a_log_truncated_and_rewritten_in_place_is_read_again_from_the_start(env):
    f = claude_session(env, env.velora, "sessA", [cl("msg_a", env.velora, out=10), cl("msg_b", env.velora, out=10)])
    assert ingest(env).new == 2
    ino = f.stat().st_ino
    with open(f, "w") as fh:                       # truncate + rewrite: same inode, now shorter than the offset
        fh.write(cl("msg_c", env.velora, out=3) + "\n")
    assert f.stat().st_ino == ino and f.stat().st_size < 2 * len(cl("msg_c", env.velora, out=3))
    assert ingest(env).new == 1
    assert sorted(usage.load(env.wd)) == ["claude:msg_a", "claude:msg_b", "claude:msg_c"]


def test_load_leaves_a_partial_store_line_for_later(env):
    claude_session(env, env.velora, "sessA", [cl("msg_a", env.velora, out=10)])
    ingest(env)
    with open(usage.store_path(env.wd), "a") as fh:
        fh.write('{"key": "claude:msg_z", "harness": "claude"')
    assert list(usage.load(env.wd)) == ["claude:msg_a"]


def test_codex_forked_thread_replay_is_charged_once_to_its_owning_thread(env):
    parent = rollout(env, TID_P, [cx_meta(TID_P, env.velora), cx_turn("t1", "gpt-6.1-sol"),
                                  cx_rec("resp_1", "t1", TID_P, inp=1000, out=100)], day="05")
    fork = rollout(env, TID_F, [cx_meta(TID_F, env.velora, forked=TID_P), cx_turn("t1", "gpt-6.1-sol"),
                                cx_rec("resp_1", "t1", TID_P, inp=1000, out=100),
                                cx_turn("t2", "gpt-6.1-sol"), cx_rec("resp_2", "t2", TID_F, inp=50, out=5)])
    # the fork is read first: the replayed record is superseded once the owning thread's arrives
    refs = [usage.ref_for(fork, "codex"), usage.ref_for(parent, "codex")]
    res = usage.ingest(env.wd, [env.wd], refs=refs)
    rows = usage.load(env.wd)
    assert sorted(rows) == ["codex:resp_1", "codex:resp_2"]
    assert rows["codex:resp_1"]["agent"] == TID_P and rows["codex:resp_2"]["agent"] == TID_F
    assert (res.new, res.superseded) == (2, 1)
    assert usage.ref_for(fork, "codex").kind == "fork" and usage.ref_for(fork, "codex").parent == TID_P


@pytest.mark.parametrize("how", ["state-lost", "archived"])
def test_rereading_an_already_ingested_codex_rollout_adds_and_supersedes_nothing(env, how):
    """A rollout read again from offset 0 (ingest state lost, or Codex moved it into archived_sessions/,
    a new path with no saved offset) yields the same owned rows: none is new, none supersedes."""
    p = rollout(env, TID_P, [cx_meta(TID_P, env.velora), cx_turn("t1", "gpt-6.1-sol"),
                             cx_rec("r1", "t1", TID_P, inp=1000, out=100),
                             cx_rec("r2", "t1", TID_P, inp=500, out=50)])
    first = ingest(env, harnesses=("codex",))
    assert (first.new, first.superseded) == (2, 0)
    store = usage.store_path(env.wd)
    lines = store.read_text().splitlines()
    assert len(lines) == 2
    if how == "state-lost":
        (usage.store_dir(env.wd) / usage.STATE_NAME).unlink()
    else:
        dest = env.codex / "archived_sessions" / p.name
        dest.parent.mkdir(parents=True)
        p.rename(dest)
    again = ingest(env, harnesses=("codex",))
    assert (again.new, again.superseded) == (0, 0)
    assert store.read_text().splitlines() == lines
    assert sorted(usage.load(env.wd)) == ["codex:r1", "codex:r2"]


# ------------------------------------------------------------------ tier and TTL pricing

def test_codex_astra_ultrafast_is_priced_at_six_times_and_tier_changes_apply_per_response(env):
    rollout(env, TID_P, [cx_meta(TID_P, env.velora), cx_tier("ultrafast"), cx_turn("t1", "gpt-6-astra"),
                         cx_rec("r1", "t1", TID_P, inp=1_000_000, cached=400_000, out=100_000),
                         cx_tier("default"), cx_turn("t2", "gpt-6-astra"),
                         cx_rec("r2", "t2", TID_P, inp=1_000_000, cached=400_000, out=100_000)])
    ingest(env, harnesses=("codex",))
    base = (600_000 * ASTRA["input"] + 400_000 * ASTRA["cached"] + 100_000 * ASTRA["output"]) / MT
    rep = report(env)
    by_tier = {m["tier"]: m["usd"] for m in rep.by_model}
    assert by_tier == {"ultrafast": pytest.approx(6 * base), "default": pytest.approx(base)}
    assert rep.usd == pytest.approx(7 * base)


def test_cache_writes_priced_by_their_ttl_and_an_undivided_write_is_flagged(env):
    claude_session(env, env.velora, "sessA", [cl("m1h", env.velora, c1=1_000_000),
                                             cl("m5m", env.velora, c5=1_000_000),
                                             cl("mleg", env.velora, legacy_cache=1_000_000)])
    ingest(env)
    rows = usage.load(env.wd)
    assert [rows[k]["ttl_assumed"] for k in ("claude:m1h", "claude:m5m", "claude:mleg")] == [False, False, True]
    rep = report(env)
    assert rep.usd == pytest.approx(OPUS55["cache_1h"] + 2 * OPUS55["cache_5m"])
    assert rep.ttl_assumed == {"responses": 1, "usd": pytest.approx(OPUS55["cache_5m"])}


def test_claude_fast_speed_is_its_own_tier(env):
    claude_session(env, env.velora, "sessA", [cl("m1", env.velora, out=1_000_000, speed="fast"),
                                             cl("m2", env.velora, out=1_000_000)])
    ingest(env)
    by_tier = {m["tier"]: m["usd"] for m in report(env).by_model}
    assert by_tier == {"fast": pytest.approx(2 * OPUS55["output"]), "standard": pytest.approx(OPUS55["output"])}


def test_unknown_model_is_listed_unpriced_and_left_out_of_totals(env, capsys):
    claude_session(env, env.velora, "sessA", [cl("m1", env.velora, model="claude-mystery-9", out=10),
                                             cl("m2", env.velora, out=1_000_000)])
    ingest(env)
    rep = report(env)
    assert rep.usd == pytest.approx(OPUS55["output"]) and rep.responses == 1
    assert [(u["model"], u["responses"]) for u in rep.unpriced] == [("claude-mystery-9", 1)]
    assert rep.agents[0]["models"] == {"claude-opus-5-5": 1, "claude-mystery-9": 1}
    assert ctf_cli.main(["usage", "--workdir", str(env.wd), "report"]) == usage_cli_unpriced()
    assert "UNPRICED: 1 claude response(s) on claude-mystery-9" in capsys.readouterr().err


def usage_cli_unpriced():
    from ctf.cli import usage as cli_usage
    return cli_usage.UNPRICED_EXIT


# ------------------------------------------------------------------ discovery and the cwd fence

def test_only_responses_whose_cwd_is_inside_a_root_are_read(env):
    claude_session(env, env.velora, "sessA", [cl("in1", env.velora, out=5), cl("out1", env.out, out=5)])
    claude_session(env, env.out, "sessC", [cl("cust", env.out, out=5)])   # a project outside the roots
    res = ingest(env)
    assert sorted(usage.load(env.wd)) == ["claude:in1"]
    assert res.outside == 1 and res.logs == 1


def test_claude_project_prefilter_matches_the_root_and_folders_below_it(env):
    sib = env.tmp / "work-old"          # its project name starts with the workdir's name and a '-'
    sib.mkdir()
    for cwd, sid in ((env.wd, "a"), (env.velora, "b"), (sib, "c"), (env.out, "d")):
        claude_session(env, cwd, sid, [cl(f"m{sid}", cwd, out=1)])
    got = sorted(r.agent for r in sources.claude_logs([env.wd], env.claude))
    # work-old passes the lossy name pre-filter; its responses fail the cwd check
    assert got == ["a", "b", "c"]
    ingest(env)
    assert sorted(usage.load(env.wd)) == ["claude:ma", "claude:mb"]


def test_codex_threads_found_from_the_db_and_from_unlisted_rollouts(env):
    p = rollout(env, TID_P, [cx_meta(TID_P, env.velora), cx_turn("t1", "gpt-6.1-sol"),
                             cx_rec("r1", "t1", TID_P, inp=100, out=10)])
    s = rollout(env, TID_S, [cx_meta(TID_S, env.velora), cx_turn("t1", "gpt-6.1-sol"),
                             cx_rec("r2", "t1", TID_S, inp=100, out=10)])
    x = rollout(env, TID_X, [cx_meta(TID_X, env.out), cx_turn("t1", "gpt-6.1-sol"),
                             cx_rec("rx", "t1", TID_X, inp=100, out=10)])
    unlisted = rollout(env, TID_F, [cx_meta(TID_F, env.orbit), cx_turn("t1", "gpt-6.1-terra"),
                                    cx_rec("r3", "t1", TID_F, inp=100, out=10)])
    rollout(env, "55555555-5555-4555-8555-555555555555", [cx_meta("55555555-5555-4555-8555-555555555555", env.out), cx_turn("t1", "gpt-6.1-sol", cwd=env.velora),
                          cx_rec("ry", "t1", "55555555-5555-4555-8555-555555555555", inp=100, out=10)])   # not in the DB, started outside
    make_db(env, [{"id": TID_P, "rollout_path": str(p), "cwd": str(env.velora), "model": "gpt-6.1-sol",
                   "thread_source": "user", "created_at": 1, "title": "t", "first_user_message": "m"},
                  {"id": TID_S, "rollout_path": str(s), "cwd": str(env.velora), "thread_source": "subagent",
                   "created_at": 2},
                  {"id": TID_X, "rollout_path": str(x), "cwd": str(env.out), "created_at": 3}],
            edges=[(TID_P, TID_S)])
    refs, notes = sources.codex_logs([env.wd], env.codex)
    assert notes == []
    by = {r.agent: r for r in refs}
    assert sorted(by) == sorted([TID_P, TID_S, TID_F])              # the outside thread is not listed
    assert (by[TID_S].kind, by[TID_S].parent) == ("subagent", TID_P)
    assert by[TID_F].path == unlisted and by[TID_F].cwd == str(env.orbit)
    ingest(env, harnesses=("codex",))
    rows = usage.load(env.wd)
    assert sorted(rows) == ["codex:r1", "codex:r2", "codex:r3"]
    rep = report(env)
    assert rep.by_challenge["9125"]["responses"] == 2 and rep.by_challenge["9158"]["responses"] == 1


def test_thread_db_model_is_used_when_no_turn_context_names_one(env):
    p = rollout(env, TID_P, [cx_meta(TID_P, env.velora), cx_rec("r1", "t9", TID_P, inp=1_000_000)])
    make_db(env, [{"id": TID_P, "rollout_path": str(p), "cwd": str(env.velora), "model": "gpt-6.1-sol",
                   "created_at": 1}])
    ingest(env, harnesses=("codex",))
    row = usage.load(env.wd)["codex:r1"]
    assert (row["model"], row["model_from"]) == ("gpt-6.1-sol", "thread_db")


def test_codex_home_is_left_byte_for_byte_unchanged(env):
    p = rollout(env, TID_P, [cx_meta(TID_P, env.velora), cx_turn("t1", "gpt-6.1-sol"),
                             cx_rec("r1", "t1", TID_P, inp=100, out=10)])
    make_db(env, [{"id": TID_P, "rollout_path": str(p), "cwd": str(env.velora), "created_at": 1}])
    claude_session(env, env.velora, "sessA", [cl("m1", env.velora, out=1)])

    def snap(root):
        return {str(f.relative_to(root)): (f.read_bytes(), f.stat().st_mtime_ns)
                for f in sorted(root.rglob("*")) if f.is_file()}
    before = snap(env.codex), snap(env.claude)
    ingest(env)
    assert (snap(env.codex), snap(env.claude)) == before       # no -wal/-shm, no lock files, no edits


def test_thread_db_is_read_without_writing_even_in_a_read_only_wal_folder(env):
    """~/.codex is read-only to this repo: a WAL-mode DB in a folder nothing may write to still reads
    (an ordinary sqlite open would need to create the -shm file there and fail)."""
    p = rollout(env, TID_P, [cx_meta(TID_P, env.velora), cx_turn("t1", "gpt-6.1-sol"),
                             cx_rec("r1", "t1", TID_P, inp=100, out=10)])
    make_db(env, [{"id": TID_P, "rollout_path": str(p), "cwd": str(env.velora), "created_at": 1}])
    con = sqlite3.connect(env.codex / "state_5.sqlite")
    assert con.execute("pragma journal_mode=wal").fetchone()[0] == "wal"
    con.close()
    db = env.codex / "state_5.sqlite"
    db.chmod(0o444)
    env.codex.chmod(0o555)
    try:
        threads, path = sources.thread_db(env.codex)
    finally:
        env.codex.chmod(0o755)
        db.chmod(0o644)
    assert path == db and list(threads) == [TID_P]
    assert sorted(f.name for f in env.codex.iterdir()) == ["sessions", "state_5.sqlite"]


def test_the_newest_thread_db_is_read_when_several_are_left(env):
    """A Codex migration can leave an old state_<n> behind: threads and spawn edges come from the
    highest n, compared as a number (state_10 is newer than state_9)."""
    make_db(env, [{"id": TID_X, "rollout_path": "/gone/x.jsonl", "cwd": str(env.velora), "created_at": 1}],
            name="state_9.sqlite")
    make_db(env, [{"id": TID_P, "rollout_path": "/gone/p.jsonl", "cwd": str(env.velora), "created_at": 1}],
            name="state_10.sqlite")
    make_db(env, [{"id": TID_S, "rollout_path": "/gone/s.jsonl", "cwd": str(env.velora), "created_at": 1}],
            name="state_4.sqlite")
    threads, path = sources.thread_db(env.codex)
    assert path == env.codex / "state_10.sqlite" and list(threads) == [TID_P]


def test_a_non_empty_wal_beside_the_thread_db_is_noted_and_its_pages_are_not_read(env):
    """The DB is opened immutable (never written), so a live WAL-mode DB's uncheckpointed pages are
    not seen; codex_logs says so instead of silently missing the spawn edges."""
    p = rollout(env, TID_P, [cx_meta(TID_P, env.velora), cx_turn("t1", "gpt-6.1-sol"),
                             cx_rec("r1", "t1", TID_P, inp=100, out=10)])
    s = rollout(env, TID_S, [cx_meta(TID_S, env.velora), cx_turn("t1", "gpt-6.1-sol"),
                             cx_rec("r2", "t1", TID_S, inp=100, out=10)])
    make_db(env, [{"id": TID_P, "rollout_path": str(p), "cwd": str(env.velora), "created_at": 1}])
    refs, notes = sources.codex_logs([env.wd], env.codex)
    assert notes == []
    live = sqlite3.connect(env.codex / "state_5.sqlite")      # Codex still running: WAL not checkpointed
    try:
        assert live.execute("pragma journal_mode=wal").fetchone()[0] == "wal"
        live.execute("pragma wal_autocheckpoint=0")
        live.execute("insert into threads (id, rollout_path, cwd, created_at) values (?, ?, ?, 2)",
                     (TID_S, str(s), str(env.velora)))
        live.execute("insert into thread_spawn_edges values (?, ?, 'open')", (TID_P, TID_S))
        live.commit()
        wal = env.codex / "state_5.sqlite-wal"
        assert wal.stat().st_size > 0
        refs, notes = sources.codex_logs([env.wd], env.codex)
    finally:
        live.close()
    assert len(notes) == 1 and str(wal) in notes[0] and "uncheckpointed" in notes[0]
    by = {r.agent: r for r in refs}
    assert sorted(by) == sorted([TID_P, TID_S])               # still found, by its rollout's cwd
    assert by[TID_S].parent is None                            # the WAL-only spawn edge is not seen
    # after a checkpoint a persistent WAL is left empty: nothing is unseen, so no note
    wal.write_bytes(b"")
    assert wal.is_file() and wal.stat().st_size == 0
    refs, notes = sources.codex_logs([env.wd], env.codex)
    assert notes == []
    assert {r.agent: r.parent for r in refs}[TID_S] == TID_P  # the checkpointed edge is now read


def test_a_thread_db_without_a_required_column_fails_loudly(env):
    make_db(env, [{"id": TID_P, "cwd": str(env.velora)}], columns=["id", "cwd"])
    with pytest.raises(sources.SourceError, match="lacks rollout_path"):
        sources.codex_logs([env.wd], env.codex)


def test_missing_sources_fail_with_a_named_reason(env, tmp_path, capsys):
    with pytest.raises(sources.SourceError, match="no Claude Code projects folder"):
        sources.claude_logs([env.wd], tmp_path / "nohome")
    with pytest.raises(sources.SourceError, match="no Codex sessions folder or thread DB"):
        sources.codex_logs([env.wd], tmp_path / "nohome")
    rc = ctf_cli.main(["usage", "--workdir", str(env.wd), "ingest", "--claude-home", str(tmp_path / "nohome"),
                       "--harness", "claude"])
    assert rc == 2 and "no Claude Code projects folder" in capsys.readouterr().err


def test_codex_without_a_thread_db_says_so(env):
    rollout(env, TID_P, [cx_meta(TID_P, env.velora), cx_turn("t1", "gpt-6.1-sol"),
                         cx_rec("r1", "t1", TID_P, inp=100, out=10)])
    refs, notes = sources.codex_logs([env.wd], env.codex)
    assert [r.agent for r in refs] == [TID_P]
    assert len(notes) == 1 and "no Codex thread DB" in notes[0]


def test_legacy_only_codex_rollout_is_reported_unread(env, capsys):
    f = rollout(env, TID_P, [cx_meta(TID_P, env.velora), cx_turn("t1", "gpt-6.1-sol"), cx_count(110, 100, 10)])
    res = ingest(env, harnesses=("codex",))
    assert res.legacy_rollouts == [str(f)] and usage.load(env.wd) == {}
    rc = ctf_cli.main(["usage", "--workdir", str(env.wd), "ingest", "--harness", "codex",
                       "--codex-home", str(env.codex)])
    assert rc == usage_cli_unpriced() and "only legacy token_count lines" in capsys.readouterr().err


# ------------------------------------------------------------------ attribution

def test_attribution_by_challenge_folder_with_named_reasons_for_the_rest(env):
    att = usage.Attributor(env.wd, records=[])
    assert att.of({"agent": "a", "cwd": str(env.velora / "files" / "x")}) == ("9125", "cwd", "")
    assert att.of({"agent": "a", "cwd": str(env.wd)})[2] == "cwd is the workdir itself, not a challenge folder"
    assert att.of({"agent": "a", "cwd": str(env.wd / "scratch")})[2] == "folder scratch has no challenge.json"
    assert att.of({"agent": "a", "cwd": str(env.out)})[2] == "cwd is outside the event workdir"
    write(env.wd / "9200-bad" / "challenge.json", ["{not json"])
    assert att.of({"agent": "a", "cwd": str(env.wd / "9200-bad")})[2].startswith("folder 9200-bad: unreadable")
    write(env.wd / "9201-noid" / "challenge.json", [json.dumps({"name": "x"})])
    assert att.of({"agent": "a", "cwd": str(env.wd / "9201-noid")})[2] == "folder 9201-noid: challenge.json has no id"


def test_assign_beats_cwd_reaches_subagents_and_the_latest_assign_wins(env):
    claude_session(env, env.wd, "sessA", [cl("m1", env.wd, out=1_000_000)])
    claude_session(env, env.wd, "sessA", [cl("m2", env.velora, out=1_000_000)], sub="agent-k")
    ingest(env)
    rep = report(env)
    assert rep.unattributed["responses"] == 1 and rep.by_challenge == {
        "9125": {"responses": 1, "tok": 1_000_000, "usd": pytest.approx(OPUS55["output"]),
                 "models": {"claude-opus-5-5": 1}}}
    assert rep.unattributed["agents"][0]["agent"] == "sessA"
    usage.assign(env.wd, "sessA", "9158", by="max")
    usage.assign(env.wd, "sessA", "9125", by="max", note="it was Velora")
    rep = report(env)
    assert rep.unattributed["responses"] == 0
    assert rep.by_challenge["9125"]["responses"] == 2           # main by assign, the subagent by its parent's
    att = usage.Attributor(env.wd)
    rows = usage.load(env.wd)
    att.learn(rows.values())
    assert att.of(rows["claude:m2"])[:2] == ("9125", "assign:parent")
    with pytest.raises(usage.UsageError, match="non-empty by"):
        usage.assign(env.wd, "sessA", "9125", by=" ")


def test_codex_spawned_subagent_inherits_the_parent_assign(env):
    p = rollout(env, TID_P, [cx_meta(TID_P, env.wd), cx_turn("t1", "gpt-6.1-sol"),
                             cx_rec("r1", "t1", TID_P, inp=100, out=10)])
    s = rollout(env, TID_S, [cx_meta(TID_S, env.wd), cx_turn("t1", "gpt-6.1-sol"),
                             cx_rec("r2", "t1", TID_S, inp=100, out=10)])
    make_db(env, [{"id": TID_P, "rollout_path": str(p), "cwd": str(env.wd), "created_at": 1},
                  {"id": TID_S, "rollout_path": str(s), "cwd": str(env.wd), "created_at": 2}],
            edges=[(TID_P, TID_S)])
    refs, _ = sources.codex_logs([env.wd], env.codex)
    assert {r.agent: (r.kind, r.parent) for r in refs} == {TID_P: ("main", None), TID_S: ("subagent", TID_P)}
    ingest(env, harnesses=("codex",))
    usage.assign(env.wd, TID_P, "9125", by="max")
    assert report(env).by_challenge["9125"]["responses"] == 2


def test_a_grandparent_assign_reaches_a_nested_spawned_thread(env):
    tids = (TID_P, TID_S, TID_S2)
    files = [rollout(env, t, [cx_meta(t, env.wd), cx_turn("t1", "gpt-6.1-sol"),
                              cx_rec(f"r{i}", "t1", t, inp=100, out=10)]) for i, t in enumerate(tids)]
    make_db(env, [{"id": t, "rollout_path": str(f), "cwd": str(env.wd), "created_at": i}
                  for i, (t, f) in enumerate(zip(tids, files))],
            edges=[(TID_P, TID_S), (TID_S, TID_S2)])
    ingest(env, harnesses=("codex",))
    assert report(env).unattributed["responses"] == 3
    usage.assign(env.wd, TID_P, "9125", by="max")
    rep = report(env)
    assert rep.unattributed["responses"] == 0 and rep.by_challenge["9125"]["responses"] == 3
    att = usage.Attributor(env.wd)
    rows = usage.load(env.wd)
    att.learn(rows.values())
    assert att.of(rows["codex:r2"])[:2] == ("9125", "assign:parent")    # P -> S -> S2


def test_codex_cwd_follows_turn_context(env):
    rollout(env, TID_P, [cx_meta(TID_P, env.velora), cx_turn("t1", "gpt-6.1-sol"),
                         cx_rec("r1", "t1", TID_P, inp=100, out=10),
                         cx_turn("t2", "gpt-6.1-sol", cwd=env.orbit), cx_rec("r2", "t2", TID_P, inp=100, out=10),
                         cx_turn("t3", "gpt-6.1-sol", cwd=env.out), cx_rec("r3", "t3", TID_P, inp=100, out=10)])
    res = ingest(env, harnesses=("codex",))
    assert res.outside == 1 and sorted(usage.load(env.wd)) == ["codex:r1", "codex:r2"]
    assert {k: v["responses"] for k, v in report(env).by_challenge.items()} == {"9125": 1, "9158": 1}


# ------------------------------------------------------------------ model served

def test_model_served_per_agent_recorded_once_per_model(env):
    claude_session(env, env.velora, "sessA", [
        cl("m1", env.velora, out=1, ts="2026-11-06T14:00:00Z"),
        cl("m2", env.velora, model="claude-opus-4-8", out=1, ts="2026-11-06T14:30:00Z"),
        cl("m3", env.velora, model="claude-opus-4-8", out=1, ts="2026-11-06T14:31:00Z")])
    res = ingest(env)
    assert res.served == 2
    served = [r for r in ledger.read(env.wd) if r["event"] == usage.SERVED_EVENT]
    assert [(r["agent"], r["model"], r["first_ts"], r["challenge_id"]) for r in served] == [
        ("sessA", "claude-opus-5-5", "2026-11-06T14:00:00Z", "9125"),
        ("sessA", "claude-opus-4-8", "2026-11-06T14:30:00Z", "9125")]
    assert ingest(env).served == 0
    a = report(env).agents[0]
    assert (a["served"], a["models"]) == ("claude-opus-4-8", {"claude-opus-5-5": 1, "claude-opus-4-8": 2})


# ------------------------------------------------------------------ reconcile with the event ledger

def test_reconcile_tops_the_ledger_up_once(env):
    claude_session(env, env.velora, "sessA", [cl("m1", env.velora, out=1_000_000)])      # $20 at 5.5 rates
    ingest(env)
    prof = event.load("csctf")
    meter = budget.LedgerMeter(prof, workdir=env.wd, on_cap=lambda st, p: None)
    meter.add_spend("9125", 5.0, 100, source="launcher:claude")
    rec = usage.reconcile(report(env), ledger.read(env.wd))
    assert [(r.challenge_id, r.usage_usd, r.ledger_usd) for r in rec] == [("9125", pytest.approx(20.0), 5.0)]
    got = usage.charge(meter, rec)
    assert [(r.challenge_id, o) for r, o in got] == [("9125", "charged")]
    spends = [r for r in ledger.read(env.wd) if r["event"] == "spend"]
    assert spends[-1]["source"] == usage.RECONCILE_SOURCE and spends[-1]["usd"] == pytest.approx(15.0)
    assert spends[-1]["tok"] == 1_000_000 - 100
    assert meter.spent("9125").usd == pytest.approx(20.0)
    assert usage.charge(meter, usage.reconcile(report(env), ledger.read(env.wd))) == []


def test_reconcile_never_charges_down_and_lists_ledger_only_challenges(env):
    prof = event.load("csctf")
    meter = budget.LedgerMeter(prof, workdir=env.wd, on_cap=lambda st, p: None)
    meter.add_spend("9999", 3.0, 10)
    rec = usage.reconcile(report(env), ledger.read(env.wd))
    assert [(r.challenge_id, r.delta_usd) for r in rec] == [("9999", -3.0)]
    assert usage.charge(meter, rec) == []


def test_reconcile_charges_usd_with_zero_tokens_when_the_ledger_already_holds_more_tokens(env):
    """The launcher can log more tokens than the shipped logs at a lower price: the USD shortfall is
    still charged, for every challenge, with tok 0 (a negative token count is refused by the meter)."""
    claude_session(env, env.velora, "sessA", [cl("m1", env.velora, out=1_000_000)])      # $20, 1M tok
    claude_session(env, env.orbit, "sessB", [cl("m2", env.orbit, out=500_000)])          # $10, 0.5M tok
    ingest(env)
    meter = budget.LedgerMeter(event.load("csctf"), workdir=env.wd, on_cap=lambda st, p: None)
    meter.add_spend("9125", 5.0, 3_000_000, source="launcher:claude")
    rec = usage.reconcile(report(env), ledger.read(env.wd))
    assert [(r.challenge_id, r.delta_tok) for r in rec] == [("9125", -2_000_000), ("9158", 500_000)]
    got = usage.charge(meter, rec)
    assert [(r.challenge_id, o) for r, o in got] == [("9125", "charged"), ("9158", "charged")]
    spends = [r for r in ledger.read(env.wd) if r["event"] == "spend" and r["source"] == usage.RECONCILE_SOURCE]
    assert [(r["challenge_id"], r["usd"], r["tok"]) for r in spends] == [
        ("9125", pytest.approx(15.0), 0), ("9158", pytest.approx(10.0), 500_000)]


def test_reconcile_charge_reports_a_reached_cap(env):
    claude_session(env, env.velora, "sessA", [cl("m1", env.velora, out=100_000_000)])    # $2000
    ingest(env)
    meter = budget.LedgerMeter(event.load("csctf"), workdir=env.wd, on_cap=lambda st, p: None)
    got = usage.charge(meter, usage.reconcile(report(env), ledger.read(env.wd)))
    assert [o for _, o in got] == ["at_cap"] and meter.spent("9125").usd == pytest.approx(2000.0)


# ------------------------------------------------------------------ the CLI

def test_cli_ingest_report_agents_assign_reconcile(env, capsys, monkeypatch):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(env.claude))
    monkeypatch.setenv("CODEX_HOME", str(env.codex))
    claude_session(env, env.wd, "sessA", [cl("m1", env.wd, out=1_000_000)])
    rollout(env, TID_P, [cx_meta(TID_P, env.orbit), cx_tier("ultrafast"), cx_turn("t1", "gpt-6-astra"),
                         cx_rec("r1", "t1", TID_P, out=1_000_000)])
    base = ["usage", "--workdir", str(env.wd)]
    assert ctf_cli.main(base + ["ingest", "--json"]) == 0
    out, err = capsys.readouterr()
    assert json.loads(out)["new"] == 2 and "no Codex thread DB" in err
    assert ctf_cli.main(base + ["report", "--json"]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert rep["usd"] == pytest.approx(OPUS55["output"] + 6 * ASTRA["output"])
    assert rep["by_challenge"]["9158"]["usd"] == pytest.approx(6 * ASTRA["output"])
    assert [a["agent"] for a in rep["unattributed"]["agents"]] == ["sessA"]
    assert ctf_cli.main(base + ["report"]) == 0
    text = capsys.readouterr().out
    assert "python -m ctf usage assign sessA <challenge>" in text and "ultrafast" in text
    assert ctf_cli.main(base + ["assign", "sessA", "9125", "--by", "max"]) == 0
    capsys.readouterr()
    assert ctf_cli.main(base + ["agents", "--json"]) == 0
    agents = {a["agent"]: a for a in json.loads(capsys.readouterr().out)["agents"]}
    assert agents["sessA"]["challenges"] == {"9125": 1} and agents[TID_P]["tiers"] == {"ultrafast": 1}
    assert ctf_cli.main(base + ["--event", "csctf", "reconcile", "--charge", "--json"]) == 0
    got = json.loads(capsys.readouterr().out)
    assert sorted(c["challenge_id"] for c in got["charged"]) == ["9125", "9158"]
    assert ctf_cli.main(base + ["reconcile", "--json"]) == 0
    assert all(abs(c["delta_usd"]) < 1e-6 for c in json.loads(capsys.readouterr().out)["challenges"])


def test_cli_log_needs_a_harness_and_a_corrupt_store_is_named(env, capsys):
    f = claude_session(env, env.velora, "sessA", [cl("m1", env.velora, out=1)])
    base = ["usage", "--workdir", str(env.wd)]
    assert ctf_cli.main(base + ["ingest", "--log", str(f)]) == 2
    assert "--log needs --harness" in capsys.readouterr().err
    assert ctf_cli.main(base + ["ingest", "--harness", "claude", "--log", str(f)]) == 0
    assert list(usage.load(env.wd)) == ["claude:m1"]
    with open(usage.store_path(env.wd), "a") as fh:
        fh.write("{oops\n")
    capsys.readouterr()
    assert ctf_cli.main(base + ["report"]) == 2
    assert "corrupt usage line" in capsys.readouterr().err


def test_claude_home_follows_claude_config_dir():
    assert paths.claude_home({"CLAUDE_CONFIG_DIR": "/x/y"}) == Path("/x/y")
    assert paths.claude_home({}).name == ".claude"
