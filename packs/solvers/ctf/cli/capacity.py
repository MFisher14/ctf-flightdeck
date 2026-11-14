"""ctf capacity show | plan -- size agent capacity to the host, past the harness subagent cap (B-018).

    python -m ctf capacity show [--json]
    python -m ctf capacity plan --board N [--json]

A single harness process caps concurrent subagents; at a wave open that ceiling denied 16 of 36
dispatches (dev/SPEED-STUDY.md rank 4). `show` reports what THIS host can run at once and how many worker
processes that needs. `plan` lays a board of N challenges onto those worker lanes, seats what the host
can run at T0 and names why any are queued -- nothing is dropped silently. No model, no network, nothing
launched: pure sizing. Policy knobs come from CTF_CAPACITY_AGENT_RAM_MB, CTF_CAPACITY_RESERVE_MB,
CTF_CAPACITY_AGENTS_PER_CPU, CTF_CAPACITY_SUBAGENT_CAP, CTF_CAPACITY_MAX_WORKERS, CTF_CAPACITY_RAM_BASIS.
"""
from __future__ import annotations

import argparse
import json
import sys

from .. import capacity as _capacity

HELP = "size agent capacity to the host and plan a board across worker lanes (past the subagent cap)"

_GiB = float(1024 ** 3)


def add_arguments(p: argparse.ArgumentParser) -> None:
    sp = p.add_subparsers(dest="action", required=True)
    s = sp.add_parser("show", help="host facts and the concurrent-agent budget")
    s.add_argument("--json", action="store_true", help="one JSON object")
    pl = sp.add_parser("plan", help="lay a board of N challenges onto worker lanes")
    pl.add_argument("--board", type=int, required=True, help="number of challenges to seat")
    pl.add_argument("--json", action="store_true", help="one JSON object")
    pl.add_argument("--lanes", action="store_true", help="also print each worker lane's slot count")


def _host_and_policy():
    policy = _capacity.CapacityPolicy.from_env()
    host = _capacity.measure_host()
    return host, policy


def _show(args) -> int:
    host, policy = _host_and_policy()
    seat = _capacity.seating(host, policy)
    b, workers = seat.budget, seat.workers
    if args.json:
        print(json.dumps({
            "total_ram_gib": round(host.total_ram_bytes / _GiB, 2),
            "available_ram_gib": round(host.available_ram_bytes / _GiB, 2),
            "cpu_count": host.cpu_count,
            "per_agent_ram_mb": policy.per_agent_ram_mb,
            "reserve_ram_mb": policy.reserve_ram_mb,
            "agents_per_cpu": policy.agents_per_cpu,
            "per_worker_cap": policy.per_worker_cap,
            "max_workers": policy.max_workers,
            "capacity": b.capacity, "by_ram": b.by_ram, "by_cpu": b.by_cpu,
            "binding": b.binding, "workers": workers, "seatable": seat.seatable,
        }))
        return 0
    print(f"host: {host.cpu_count} CPU, {host.total_ram_bytes / _GiB:.1f} GiB RAM "
          f"({host.available_ram_bytes / _GiB:.1f} GiB available)")
    print(f"policy: {policy.per_agent_ram_mb} MiB/agent, {policy.reserve_ram_mb} MiB reserved, "
          f"{policy.agents_per_cpu}/CPU, {policy.per_worker_cap}/worker"
          + (f", max {policy.max_workers} workers" if policy.max_workers is not None else ""))
    print(f"budget: {b.capacity} concurrent agents ({b.binding}-bound: RAM {b.by_ram}, CPU {b.by_cpu})")
    print(f"workers: {workers} harness process(es) of up to {policy.per_worker_cap} subagents each, "
          f"seating {seat.seatable} at once")
    return 0


def _plan(args) -> int:
    host, policy = _host_and_policy()
    try:
        plan = _capacity.plan_board(args.board, host, policy)
    except _capacity.CapacityError as e:
        print(f"ctf capacity plan: {e}", file=sys.stderr)
        return 2
    if args.json:
        out = {
            "demand": plan.demand, "capacity": plan.capacity, "granted": plan.granted,
            "queued": plan.denied, "workers": plan.workers,
            "per_worker_cap": plan.per_worker_cap, "satisfied": plan.satisfied,
            "reason": plan.reason, "lane_sizes": [len(l) for l in plan.lanes],
        }
        print(json.dumps(out))
        return 0 if plan.satisfied else 1
    print(f"board {plan.demand}: {plan.granted} seated at T0 across {plan.workers} worker(s), "
          f"{plan.denied} queued  (host budget {plan.capacity})")
    if args.lanes:
        for i, lane in enumerate(plan.lanes):
            print(f"  worker {i}: {len(lane)} slots")
    if plan.satisfied:
        print("no denials" + (" (single worker)" if not plan.multi_process else ""))
        return 0
    print(plan.reason, file=sys.stderr)
    return 1


def run(args: argparse.Namespace) -> int:
    try:
        if args.action == "show":
            return _show(args)
        if args.action == "plan":
            return _plan(args)
    except _capacity.CapacityError as e:
        print(f"ctf capacity: {e}", file=sys.stderr)
        return 2
    return 2
