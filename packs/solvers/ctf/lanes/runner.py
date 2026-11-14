"""Launch Codex lanes: `codex exec` per lane inside the B-219 fence, with the batch's own
concurrency cap, dependency order, a per-lane timeout and a status record per lane (B-179).

Each lane runs as

    codex exec --skip-git-repo-check -C <checkout> <fence -c overrides> -c approval_policy="never"
               --disable fast_mode --disable ultrafast_mode --disable shell_snapshot
               [-m MODEL] [-c model_reasoning_effort=...] [backlog extra] -o <last_message.md> <prompt>

built by ctf.fence_launch.codex_argv (so a backlog cannot pass a fence-breaking flag). The fence's
write roots are the lane checkout and the lane folder (where result.json goes); the master venv and
the borrowed object store are added as read roots. Platform credentials and platform-identifying
variables (CTF_TOKEN, CTF_COOKIE, CTF_PLATFORM_URL, CTF_TEAM_ID, and their legacy spellings) and the
live-test switch CTF_RUN_LIVE are removed from the lane's environment: a build lane never needs them
and must not reach event infrastructure.

Lane states (status.json "state"): pending, running, done (exit 0 and a valid result.json),
no-result (exit 0, result missing or invalid), failed (non-zero exit), timeout, skipped (a dependency
did not finish "built"), error (could not start: checkout or dependency merge failed),
interrupted (the runner was stopped). A lane already "done" is not relaunched unless rerun=True.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from .. import env as _env
from .. import fence as _fence
from .. import fence_launch as _launch
from . import checkout as _co
from . import prompt as _prompt
from .backlog import Backlog
from .layout import BatchDirs, event, read_json, write_json
from .results import ResultError, load_result

TERMINAL = ("done", "no-result", "failed", "timeout", "skipped", "error", "interrupted")
SCRUB_ENV = ("CTF_TOKEN", "CTF_COOKIE", "CTF_PLATFORM_URL", "CTF_TEAM_ID", "CTF_RUN_LIVE")
KILL_GRACE_S = 5.0


class RunnerError(RuntimeError):
    """The batch cannot run (codex missing, bad selection). Names why."""


def codex_bin(explicit: str | None = None) -> str:
    name = explicit or os.environ.get("CODEX_BIN") or "codex"
    found = shutil.which(name)
    if found is None:
        raise RunnerError(f"codex CLI not found ({name!r}); install it or pass --codex-bin / set CODEX_BIN")
    return found


def lane_fence(backlog: Backlog, dirs: BatchDirs, lane_id: str, venv: Path | None) -> _fence.Fence:
    co = dirs.checkout(lane_id)
    extra = [Path(venv)] if venv else []
    extra += [p for p in _co.alternates(co) if p not in extra]
    return _fence.build(repo=dirs.lane_dir(lane_id), workspace=co, extra_read=extra,
                        strict_home=backlog.codex.strict_home)


def lane_argv(backlog: Backlog, dirs: BatchDirs, lane_id: str, prompt_text: str, *, codex: str,
              venv: Path | None) -> list[str]:
    f = lane_fence(backlog, dirs, lane_id, venv)
    extra = [*backlog.codex.extra, "-o", str(dirs.last_message(lane_id))]
    return _launch.codex_argv(f, codex_bin=codex, headless=True, model=backlog.codex.model,
                              effort=backlog.codex.effort, approval="never", extra=extra,
                              prompt=prompt_text)


def lane_env() -> dict[str, str]:
    e = dict(os.environ)
    for name in SCRUB_ENV:
        for k in (name, *_env.legacy_names(name)):
            e.pop(k, None)
    return e


@dataclass
class _Running:
    lane: str
    proc: subprocess.Popen
    started: float
    log: object


def _status(dirs: BatchDirs, lane_id: str, **fields) -> dict:
    cur = read_json(dirs.status(lane_id)) or {"lane": lane_id}
    cur.update(fields)
    write_json(dirs.status(lane_id), cur)
    return cur


def _result_status(dirs: BatchDirs, lane_id: str) -> str | None:
    try:
        return load_result(dirs.result(lane_id), lane_id).status
    except (ResultError, OSError):
        return None


def _dep_verdict(dirs: BatchDirs, dep: str) -> str:
    """ok | wait | bad for one dependency, from its status record."""
    st = read_json(dirs.status(dep)) or {}
    state = st.get("state")
    if state == "done":
        return "ok" if _result_status(dirs, dep) == "built" else "bad"
    if state in TERMINAL:
        return "bad"
    return "wait"


def _kill(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=KILL_GRACE_S)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()


def run(backlog: Backlog, dirs: BatchDirs, repo: Path, *, lane_ids: list[str] | None = None,
        codex: str | None = None, concurrency: int | None = None, rerun: bool = False,
        dry_run: bool = False, venv: Path | None = None, poll: float = 0.5,
        timeout_s: float | None = None, say: Callable[[str], None] = print) -> dict[str, dict]:
    order = backlog.order()
    sel = list(lane_ids) if lane_ids else order
    unknown = [x for x in sel if x not in order]
    if unknown:
        raise RunnerError(f"unknown lane(s) {', '.join(unknown)} in batch {backlog.batch}")
    sel = [x for x in order if x in sel]
    conc = concurrency if concurrency is not None else backlog.concurrency
    if conc < 1:
        raise RunnerError(f"concurrency must be at least 1 (got {conc})")
    tmo = timeout_s if timeout_s is not None else backlog.timeout_minutes * 60
    texts = _prompt.write_pack(backlog, dirs, sel)

    if dry_run:
        cb = codex or os.environ.get("CODEX_BIN") or "codex"
        out = {}
        for lid in sel:
            argv = lane_argv(backlog, dirs, lid, texts[lid], codex=cb, venv=venv)
            out[lid] = {"argv": argv[:-1] + [f"<prompt: {dirs.prompt(lid)}>"]}
        return out

    cb = codex_bin(codex)
    if venv is None:
        venv = _co.find_venv(repo)
    _co.setup(repo, backlog, dirs, lane_ids=sel, venv=venv)
    write_json(dirs.root / "backlog.json", asdict(backlog))

    pending = []
    for lid in sel:
        st = read_json(dirs.status(lid)) or {}
        if st.get("state") == "done" and not rerun:
            say(f"[{lid}] already done ({_result_status(dirs, lid)}); not relaunched")
            continue
        _status(dirs, lid, state="pending", reason=None)
        pending.append(lid)

    running: dict[str, _Running] = {}
    try:
        while pending or running:
            now = time.monotonic()
            for lid, r in list(running.items()):
                rc = r.proc.poll()
                if rc is None and now - r.started > tmo:
                    _kill(r.proc)
                    r.log.close()
                    del running[lid]
                    _finish(dirs, lid, "timeout", r.proc.returncode, f"killed after {tmo:.0f}s", say)
                elif rc is not None:
                    r.log.close()
                    del running[lid]
                    if rc != 0:
                        _finish(dirs, lid, "failed", rc, f"codex exited {rc} (see {dirs.log(lid)})", say)
                    else:
                        rs = _result_status(dirs, lid)
                        if rs is None:
                            try:
                                load_result(dirs.result(lid), lid)
                                why = "result.json invalid"
                            except ResultError as e:
                                why = str(e)
                            _finish(dirs, lid, "no-result", rc, why, say)
                        else:
                            _finish(dirs, lid, "done", rc, None, say, result_status=rs)
            for lid in list(pending):
                outside = [d for d in backlog.lane(lid).depends
                           if d not in sel and _dep_verdict(dirs, d) == "wait"]
                if outside:
                    pending.remove(lid)
                    _finish(dirs, lid, "skipped", None, f"dependency {', '.join(outside)} is not in this "
                            "run and has not finished", say)
                    continue
                verdicts = [_dep_verdict(dirs, d) for d in backlog.lane(lid).depends]
                if "bad" in verdicts:
                    pending.remove(lid)
                    bad = [d for d, v in zip(backlog.lane(lid).depends, verdicts) if v == "bad"]
                    _finish(dirs, lid, "skipped", None, f"dependency {', '.join(bad)} did not finish built", say)
                    continue
                if "wait" in verdicts or len(running) >= conc:
                    continue
                pending.remove(lid)
                try:
                    running[lid] = _launch_lane(backlog, dirs, lid, texts[lid], cb, venv)
                except (_co.CheckoutError, _fence.FenceError, _launch.LaunchError, OSError) as e:
                    _finish(dirs, lid, "error", None, str(e), say)
                    continue
                say(f"[{lid}] started (pid {running[lid].proc.pid}; {len(running)}/{conc} running)")
            if pending or running:
                time.sleep(poll)
    except KeyboardInterrupt:
        for lid, r in running.items():
            _kill(r.proc)
            r.log.close()
            _finish(dirs, lid, "interrupted", r.proc.returncode, "runner interrupted", say)
        for lid in pending:
            _status(dirs, lid, state="pending", reason="runner interrupted before launch")
        raise
    return {lid: read_json(dirs.status(lid)) or {} for lid in sel}


def _launch_lane(backlog: Backlog, dirs: BatchDirs, lid: str, text: str, cb: str, venv) -> _Running:
    co = dirs.checkout(lid)
    lane = backlog.lane(lid)
    if lane.depends:
        _co.merge_dependencies(co, [(backlog.branch(d), dirs.checkout(d)) for d in lane.depends])
    argv = lane_argv(backlog, dirs, lid, text, codex=cb, venv=venv)
    for stale in (dirs.result(lid), dirs.last_message(lid)):
        if stale.exists():
            stale.unlink()
    log = open(dirs.log(lid), "ab")
    try:
        proc = subprocess.Popen(argv, cwd=co, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                env=lane_env(), start_new_session=True)
    except OSError:
        log.close()
        raise
    _status(dirs, lid, state="running", pid=proc.pid, started=time.time(), ended=None, exit_code=None,
            reason=None, result_status=None, argv=argv[:-1] + ["<prompt>"])
    event(dirs, "lane.start", lane=lid, pid=proc.pid)
    return _Running(lid, proc, time.monotonic(), log)


def _finish(dirs: BatchDirs, lid: str, state: str, rc, reason, say, result_status=None) -> None:
    _status(dirs, lid, state=state, exit_code=rc, ended=time.time(), reason=reason,
            result_status=result_status)
    event(dirs, "lane.end", lane=lid, state=state, exit_code=rc, result_status=result_status)
    tail = f" ({result_status})" if result_status else ""
    say(f"[{lid}] {state}{tail}" + (f": {reason}" if reason else ""))


def status_rows(backlog: Backlog, dirs: BatchDirs) -> list[dict]:
    rows = []
    for lid in backlog.order():
        st = read_json(dirs.status(lid)) or {}
        res = None
        try:
            res = load_result(dirs.result(lid), lid)
        except ResultError:
            pass
        started, ended = st.get("started"), st.get("ended")
        elapsed = (ended or time.time()) - started if started else None
        rows.append({"lane": lid, "state": st.get("state", "not-run"), "exit_code": st.get("exit_code"),
                     "elapsed_s": round(elapsed, 1) if elapsed is not None else None,
                     "result": res.status if res else None, "summary": res.summary if res else None,
                     "reason": st.get("reason"), "depends": list(backlog.lane(lid).depends)})
    return rows
