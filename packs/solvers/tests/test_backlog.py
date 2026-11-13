"""B-138: the backlog as data — rows with a closed status vocabulary, a computed open count (the
Oct 9-10 miscount can't happen when status is a field, not free text), a done status that moves a row
out of the open section, a Markdown render, status change through a CLI, the per-event backlog, the
hard tail kept with its blocker, and ranking that reuses buildplan.rank.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json

import pytest

from ctf import backlog as bl
from ctf import buildplan as bp
from ctf import event, ledger
from ctf.cli import backlog as cli

UTC = dt.timezone.utc


def profile(categories=("Web", "Reverse engineering"), slug="demo"):
    return event.parse({
        "slug": slug, "name": "Demo", "categories": list(categories), "sectors": [],
        "dates": {"start": dt.datetime(2027, 3, 1, tzinfo=UTC),
                  "end": dt.datetime(2027, 3, 3, tzinfo=UTC)},
        "platform": {"kind": "ctfd", "base_url": "https://demo.example/"},
        "flag": {"prefixes": ["DEMO"]},
        "rules": {"submit_mode": "auto", "flag_sharing": "allowed", "ai_on_platform": "allowed"},
    })


def row(iid, status="open", lane="ops", effort="S", **kw):
    return bl.Row(id=iid, status=status, lane=lane, effort=effort, **kw)


# ---------------------------------------------------------------------------- rows & validation

def test_parse_row_rejects_unknown_status():
    with pytest.raises(bl.BacklogError, match="unknown status"):
        bl.parse_row({"id": "B-1", "status": "wip"})


def test_parse_row_rejects_missing_id():
    with pytest.raises(bl.BacklogError, match=r"\.id: required"):
        bl.parse_row({"status": "open"})


def test_parse_row_rejects_bad_priority():
    with pytest.raises(bl.BacklogError, match="priority"):
        bl.parse_row({"id": "B-1", "priority": "P9"})


def test_terminal_classification():
    assert row("B-1", "built").terminal and row("B-1", "merged").terminal
    assert not row("B-1", "open").terminal and not row("B-1", "blocked").terminal
    assert row("B-1", "blocked").hard_tail and row("B-1", "deferred").hard_tail
    assert not row("B-1", "open").hard_tail


def test_order_keeps_done_after_open_even_when_status_index_inverts(monkeypatch):
    # order() must put terminal (done) rows after open rows because of the r.terminal key, not by an
    # accident of the STATUSES insertion order. Reorder STATUSES so a terminal status ('merged') sits
    # at a LOWER index than an open one ('open'); order() must still rank the open row first. Without
    # the r.terminal term in the sort key, the done row would float above the open row here and this
    # fails — the guard the live STATUSES order would otherwise hide.
    monkeypatch.setattr(bl, "STATUSES", {"merged": True, "open": False, "built": True})
    rows = [row("B-done", "merged", title="shipped"), row("B-open", "open", title="todo")]
    assert [r.id for r in bl.order(rows)] == ["B-open", "B-done"]
    assert [r.id for r in bl.open_rows(rows)] == ["B-open"]
    assert [r.id for r in bl.done_rows(rows)] == ["B-done"]


# ------------------------------------------------------------------------------- load / save

def test_load_save_roundtrip_and_ignores_comments(tmp_path):
    p = tmp_path / "b.jsonl"
    p.write_text('# a header comment\n'
                 '{"id": "B-2", "status": "open", "lane": "ops", "effort": "S"}\n'
                 '\n'
                 '{"id": "B-1", "status": "merged", "title": "done one"}\n', encoding="utf-8")
    rows = bl.load(p)
    assert [r.id for r in rows] == ["B-2", "B-1"]
    # save() reorders: open rows before done rows
    bl.save(p, rows)
    again = bl.load(p)
    assert [r.id for r in again] == ["B-2", "B-1"]  # B-2 open first, B-1 merged after
    assert again[1].status == "merged"


def test_load_rejects_duplicate_id(tmp_path):
    p = tmp_path / "b.jsonl"
    p.write_text('{"id": "B-1"}\n{"id": "B-1"}\n', encoding="utf-8")
    with pytest.raises(bl.BacklogError, match="duplicate row id B-1"):
        bl.load(p)


def test_load_names_the_bad_line(tmp_path):
    p = tmp_path / "b.jsonl"
    p.write_text('{"id": "B-1"}\nnot json\n', encoding="utf-8")
    with pytest.raises(bl.BacklogError, match=r"b\.jsonl:2: not JSON"):
        bl.load(p)


# ------------------------------------------------------------------- the counting bug this fixes

def test_open_count_excludes_done_rows():
    # The Oct 9-10 miscount: built rows left sitting in the backlog were counted as open.
    rows = [row("B-1", "open"), row("B-2", "built"), row("B-3", "merged"),
            row("B-4", "partial"), row("B-5", "blocked")]
    c = bl.counts(rows)
    assert c["open"] == 3          # open, partial, blocked
    assert c["done"] == 2          # built, merged
    assert c["hard_tail"] == 1     # blocked
    assert [r.id for r in bl.open_rows(rows)] == ["B-1", "B-4", "B-5"]
    assert [r.id for r in bl.done_rows(rows)] == ["B-2", "B-3"]


def test_free_text_cannot_inflate_the_open_count():
    # The other half of the miscount: the word 'open' appearing in a done row's prose. Status is a
    # field, so free text never changes the count.
    done = row("B-9", "merged", decision="was open for a while; now shipped", impact="reopen never")
    assert bl.counts([done])["open"] == 0
    assert bl.counts([done])["done"] == 1


# ------------------------------------------------------------------------- status change moves rows

def test_set_status_to_done_moves_row_and_logs(tmp_path):
    rows = [row("B-1", "open"), row("B-2", "open")]
    assert bl.counts(rows)["open"] == 2
    rows, changed = bl.set_status(rows, "B-1", "built", workdir=tmp_path)
    assert changed.status == "built" and changed.terminal
    assert bl.counts(rows)["open"] == 1
    assert [r.id for r in bl.done_rows(rows)] == ["B-1"]
    # the change is on the event ledger
    evs = [e for e in ledger.read(tmp_path) if e["event"] == "backlog.status"]
    assert evs and evs[-1]["item"] == "B-1" and evs[-1]["to"] == "built" and evs[-1]["from"] == "open"


def test_set_status_no_op_does_not_log(tmp_path):
    rows = [row("B-1", "open")]
    bl.set_status(rows, "B-1", "open", workdir=tmp_path)
    assert not list(ledger.read(tmp_path))


def test_set_status_unknown_id_and_status_raise():
    rows = [row("B-1", "open")]
    with pytest.raises(bl.BacklogError, match="no backlog row with id"):
        bl.set_status(rows, "B-9", "built")
    with pytest.raises(bl.BacklogError, match="unknown status"):
        bl.set_status(rows, "B-1", "nope")


# ------------------------------------------------------------------------------------- render

def test_render_places_rows_in_sections():
    rows = [row("B-open", "open", title="still open"),
            row("B-tail", "blocked", title="waits on a live endpoint"),
            row("B-done", "merged", title="shipped")]
    md = bl.render_markdown(rows)
    o = md.index("## Open")
    t = md.index("## Hard tail")
    d = md.index("## Done")
    assert o < t < d
    assert md.index("B-open") < t          # open row is above the hard-tail header
    assert t < md.index("B-tail") < d      # blocked row is in the hard-tail section
    assert d < md.index("B-done")          # merged row is in the done section
    assert "**2 open**" in md              # open + blocked


# ---------------------------------------------------------------------------------- ranking

def test_rank_reuses_buildplan_and_excludes_done():
    rows = [row("B-1", "open", lane="ops", effort="S"),
            row("B-2", "open", lane="web", effort="M"),
            row("B-3", "merged", lane="ops", effort="S")]
    rk = bl.rank(rows, profile(), effort_budget=1)
    assert isinstance(rk, bp.Ranking)
    assert {e.id for e in rk.entries} == {"B-1", "B-2"}   # the merged row is not ranked
    # ops is cross-cutting (relevance 1) and S (1 unit) -> approved within budget 1
    assert rk.get("B-1").decision == "approved"


def test_to_items_is_strict_about_lane_and_effort():
    with pytest.raises(bl.BacklogError, match="no lane"):
        bl.to_items([row("B-1", "open", lane="", effort="S")])
    with pytest.raises(bl.BacklogError, match="no effort"):
        bl.to_items([row("B-1", "open", lane="ops", effort="")])


# ---------------------------------------------------------------------- sync from the repo tree

PLAN = """\
# Phase 0

1. **`B-009` [S/A] Turn off Codex ultrafast** — one line in config. No dependencies.
2. **`B-001` [XL/A] Master repo consolidation** — the repo itself.

# Phase 1

**web (2)**
- `B-019` [M/A dep:B-003,B-006] Live JWT forge engine
- `B-020` [L/~ dep:B-003] Mass-assignment engine — _hard tail_

**ops (1)**
- `B-138` [S/A] Backlog as data: machine-readable rows with status
"""


def test_scan_buildplan_both_forms_lane_deps_and_italic_suffix():
    rows = {r["id"]: r for r in bl.scan_buildplan(PLAN)}
    assert set(rows) == {"B-009", "B-001", "B-019", "B-020", "B-138"}
    assert rows["B-009"]["effort"] == "S" and rows["B-009"]["automatable"] == "yes"
    assert rows["B-009"]["title"] == "Turn off Codex ultrafast"       # bold+desc stripped
    assert rows["B-001"]["effort"] == "XL"
    assert rows["B-019"]["lane"] == "web" and rows["B-019"]["dependencies"] == ["B-003", "B-006"]
    assert rows["B-020"]["title"] == "Mass-assignment engine"         # _hard tail_ suffix stripped
    assert rows["B-020"]["automatable"] == "partly"
    assert rows["B-138"]["lane"] == "ops"
    assert rows["B-009"]["lane"] == ""                                # Phase 0 has no group header


def _tree(tmp_path, statuses: dict[str, str], *, plan=PLAN):
    (tmp_path / "BUILD-PLAN.md").write_text(plan, encoding="utf-8")
    bld = tmp_path / "docs" / "build-log"
    bld.mkdir(parents=True)
    for iid, word in statuses.items():
        (bld / f"{iid}.md").write_text(f"# {iid}\n\nStatus: **{word}**. done.\n", encoding="utf-8")
    return tmp_path


def test_sync_sets_status_from_build_logs(tmp_path):
    root = _tree(tmp_path, {"B-019": "built", "B-020": "blocked"})
    rows = {r.id: r for r in bl.sync(repo_root=root, use_git=False)}
    assert rows["B-019"].status == "built"
    assert rows["B-020"].status == "blocked"      # hard tail, kept
    assert rows["B-138"].status == "open"         # no log, not merged
    assert "docs/build-log/B-019.md" in rows["B-019"].evidence


def test_sync_rolls_up_lettered_subitems(tmp_path):
    # B-001 has no log of its own, but its split sub-items are built -> it is done.
    root = _tree(tmp_path, {"B-001a": "built", "B-001b": "merged"})
    rows = {r.id: r for r in bl.sync(repo_root=root, use_git=False)}
    assert rows["B-001"].status == "built"


def test_sync_assigns_default_lane_to_header_less_phase0_items(tmp_path):
    # Phase-0 build-order items (B-009, B-001) sit under a section with no `**lane (n)**` header; sync
    # gives them the cross-cutting default lane so rank() can rank them instead of dropping them as
    # laneless. A real group header still wins, and default_lane='' restores the old laneless behaviour.
    root = _tree(tmp_path, {})
    rows = {r.id: r for r in bl.sync(repo_root=root, use_git=False)}
    assert rows["B-009"].lane == "ops"       # header-less -> default lane
    assert rows["B-001"].lane == "ops"
    assert rows["B-019"].lane == "web"        # a real `**web (2)**` header wins over the default
    bare = {r.id: r for r in bl.sync(repo_root=root, use_git=False, default_lane="")}
    assert bare["B-009"].lane == "" and bare["B-001"].lane == ""


def test_sync_preserves_operator_fields(tmp_path):
    root = _tree(tmp_path, {})
    existing = [bl.Row(id="B-138", status="open", lane="ops", effort="S",
                       decision="build it", impact="stops the miscount", risk="low",
                       priority="P3")]
    rows = {r.id: r for r in bl.sync(repo_root=root, existing=existing, use_git=False)}
    assert rows["B-138"].decision == "build it"
    assert rows["B-138"].impact == "stops the miscount"
    assert rows["B-138"].priority == "P3"


def test_scan_log_statuses_reads_first_status_word(tmp_path):
    bld = tmp_path / "build-log"
    bld.mkdir()
    (bld / "B-1.md").write_text("intro\nStatus: partial (gaps below)\nmore\n", encoding="utf-8")
    (bld / "B-2.md").write_text("Status: **merged**\n", encoding="utf-8")
    got = bl.scan_log_statuses(bld)
    assert got == {"B-1": "partial", "B-2": "merged"}


# -------------------------------------------------------------------------------------- CLI

def run_cli(tmp_path, *argv, event_slug=None):
    p = argparse.ArgumentParser()
    cli.add_arguments(p)
    args = p.parse_args(list(argv))
    return cli.run(args)


def seed_file(tmp_path):
    p = tmp_path / "backlog.jsonl"
    bl.save(p, [row("B-1", "open", lane="ops", effort="S", title="first"),
                row("B-2", "open", lane="web", effort="M", title="second"),
                row("B-3", "merged", lane="ops", effort="S", title="done")])
    return p


def test_cli_open_prints_count(tmp_path, capsys):
    p = seed_file(tmp_path)
    assert run_cli(tmp_path, "open", "--file", str(p), "--json") == 0
    out = json.loads(capsys.readouterr().out)
    assert out["open"] == 2 and {r["id"] for r in out["rows"]} == {"B-1", "B-2"}


def test_cli_set_status_moves_row(tmp_path, capsys):
    p = seed_file(tmp_path)
    assert run_cli(tmp_path, "set-status", "B-1", "built", "--file", str(p)) == 0
    rows = bl.load(p)
    assert bl.get(rows, "B-1").status == "built"
    assert bl.counts(rows)["open"] == 1


def test_cli_set_status_unknown_id_errors(tmp_path, capsys):
    p = seed_file(tmp_path)
    assert run_cli(tmp_path, "set-status", "B-99", "built", "--file", str(p)) == 2
    assert "no backlog row" in capsys.readouterr().err


def test_cli_rank_skips_laneless_rows_loudly(tmp_path, capsys):
    p = tmp_path / "backlog.jsonl"
    bl.save(p, [row("B-1", "open", lane="ops", effort="S"),
                row("B-2", "open", lane="", effort="S", title="no lane")])
    assert run_cli(tmp_path, "rank", "--event", "demo", "--effort-budget", "1",
                   "--file", str(p)) == 0
    err = capsys.readouterr().err
    assert "B-2" in err and "not ranked" in err


def test_cli_sync_check_detects_fresh_and_stale(tmp_path, monkeypatch, capsys):
    # `backlog sync --check` is the operator drift check (not the merge gate): it exits 0 when the
    # committed file matches a fresh sync and non-zero, naming the drift, when it has gone stale.
    root = _tree(tmp_path, {"B-019": "built"})
    monkeypatch.setattr(bl.paths, "repo_root", lambda: root)
    p = tmp_path / "backlog.jsonl"
    bl.save(p, bl.sync(repo_root=root, use_git=False))
    assert run_cli(tmp_path, "sync", "--check", "--no-git", "--file", str(p)) == 0
    assert "is fresh" in capsys.readouterr().out
    # drift it: mark a row done that the tree still reports as open
    rows, _ = bl.set_status(bl.load(p), "B-138", "merged", log=False)
    bl.save(p, rows)
    assert run_cli(tmp_path, "sync", "--check", "--no-git", "--file", str(p)) == 1
    err = capsys.readouterr().err
    assert "STALE" in err and "B-138" in err


@pytest.fixture(autouse=True)
def _demo_event(tmp_path, monkeypatch):
    # make event.load("demo") resolve to a synthetic profile without touching events/
    prof = profile(slug="demo")
    monkeypatch.setattr(event, "load", lambda slug=None: prof)
    monkeypatch.setattr(event, "current", lambda: prof)
