# Harness failover runbook (release mornings)

What to do when the harness holding the lanes cannot hold the next release: Claude Code is out of
quota or unavailable and Codex takes over, or the reverse. B-170. The code is `ctf/failover.py` and
the `ctf failover` command; this page is the procedure around it. `tests/test_failover.py` checks that
every `python -m ctf` command on this page parses, and that the launcher flags it uses exist.

Why it exists: at Huntress, Claude's usage limit pushed work onto Codex mid-event on at least two days,
and no failover had been tried before a release. Whether the other harness can hold every lane at
release speed was never tested. The rehearsal below turns that into a recorded yes or no per event.

Placeholders: `<slug>` is the event, `<workdir>` its working folder (`python -m ctf workdir`),
`<you>` your name, `<id>` a challenge id, `<codex-model>` a model Codex may run.

## Before the event: rehearse both directions once

A live rehearsal starts one real session per lane on the target harness, all at the same time,
through the same fenced launcher a real lane uses (`tools/codex_launch`, `tools/claude_launch`). Each
lane gets a synthetic smoke task: a flag in the event format, encoded a different simple way per lane.
A lane holds when its `result.txt` holds the flag within the deadline (300 s by default). It costs one
short session per lane on each harness.

```
python -m ctf failover --event <slug> rehearse --to codex --live --by <you>
python -m ctf failover --event <slug> rehearse --to claude --live --by <you>
python -m ctf failover --event <slug> status
```

- Exit 0 means it held: every lane answered right in time. Exit 1 means it did not, and the
  output names each lane that failed (`wrong`, `no-result`, `timeout`, `launch-error`, or slow).
  The lane folders (`task.txt`, `result.txt`, `launch.log`) are kept under
  `<workdir>/failover-rehearsal/` for inspection. Once you have read them, remove all but the newest
  run per harness (`--keep 0` removes them all, `--dry-run` lists first). The ledger records stay, so
  the doctor's answer does not change:

  ```
  python -m ctf failover --event <slug> prune --keep 1
  ```

- If every Claude lane comes back `no-result` with exit 0, Claude ran but did not write `result.txt`.
  Suspect the fenced settings (`tools/claude_launch` with `--permission-mode acceptEdits`) before the
  harness: read a lane's `launch.log` for a refused write. The first live `--to claude` run settles it.
- The result is a `failover.rehearsal` ledger record. The doctor's `failover` check
  (`python -m ctf preflight --event <slug>`) warns until both directions have a live rehearsal that
  held. A rehearsal that did not hold stays a warning that names the lanes; plan around them, for
  example by keeping those lanes on no-model engines or holding them for the primary. Because it is a
  warning, `python -m ctf preflight --event <slug> --strict` fails on every event until both live
  rehearsals have held; the pre-event gate treats the warning as soft and does not block on it.
- `--lanes web,crypto` limits the lanes. `--parallel N` caps how many run at once (the default is all
  of them, which is the release fan-out). `--model M` pins the model.
- Without `--live`, the binary (`--bin`, `$CODEX_BIN`, `$CLAUDE_BIN`) must be a stub carrying the
  line `ctf-harness-stub`. That rehearses the mechanics only (launcher, fence, workspace, result path,
  timing) and does not count for the doctor.

Also before the event: set `[allowance]` in `events/<slug>/event.toml` (`releases` or
`daily_release` and `tz`) so the meter knows when the next release is, and take a quota reading:

```
python -m ctf quota --event <slug> scan
python -m ctf quota --event <slug> set claude --window weekly --used 40 --resets +2d --by <you>
```

## The trigger: the budget meter

Run the check after every quota scan, at least once an hour on an event day, and 30 minutes before
every release:

```
python -m ctf quota --event <slug> scan
python -m ctf failover --event <slug> check
```

It asks the B-171 meter two questions of each harness. **Now:** can it take one release job per lane
at once? **At the release:** is it funded at the next release? It then answers one of four things:

| answer | exit | meaning | do |
|---|---|---|---|
| `STAY` | 0 | the active harness should keep the lanes | nothing; check again later |
| `FAILOVER` | 3 | the primary cannot hold the release and the other harness can take the lanes now | the switch below, onto the other harness |
| `FAILBACK` | 3 | the lanes are on the other harness and the primary is ready again | the switch below, back onto the primary (the reverse path) |
| `STRANDED` | 1 | no harness can take release work now | the stranded steps below |

The check also prints the steps with the event filled in, and warns when the target harness has never
been rehearsed live or its last rehearsal did not hold. A harness with no quota reading counts as
ready (unmetered), and the check says so. The primary is Claude (`--primary codex` turns that round).
`--lanes N` sets how many lanes must be funded at once. The default is the event's lane count.

Signs the meter has not seen yet: a limit message in an agent's output ("usage limit", "out of
tokens", "try again at ..."). Record it at once, then check again:

```
python -m ctf quota --event <slug> set claude --window session --exhausted --resets +3h --by <you>
python -m ctf failover --event <slug> check
```

## The switch: Claude to Codex

1. Record it, with the trigger line from the check as the reason:

   ```
   python -m ctf failover --event <slug> switch --to codex --by <you> --reason "claude weekly exhausted until 13:50"
   ```

2. Install the agent rules where Codex loads them (`AGENTS.md`; Claude loads `CLAUDE.md`, and both
   come from the one profile):

   ```
   python -m ctf new-event <slug> --regen --workdir <workdir>
   ```

3. Move the orchestrator to a Codex session started in the workdir:

   ```
   tools/codex_launch --event <slug> --workspace <workdir> --interactive
   ```

4. Start each claimed lane on Codex, with its machine-written handout as the prompt (the dispatcher
   keeps claiming and writing handouts with no model):

   ```
   python -m ctf dispatch --event <slug> show <id> | tools/codex_launch --event <slug> --challenge <id> --model <codex-model> -
   ```

5. Point escalation at models that can run, so a second opinion or a reroute does not land on the
   harness that is out:

   ```
   python -m ctf escalate --event <slug> run --model <codex-model> --model <second-codex-model>
   ```

6. Submitting does not change: every agent submits on sight through `python -m ctf submit`. The gate
   and the queue are the same for both harnesses.

7. Watch for the way back: keep running the check. When it answers `FAILBACK`, do the reverse path.

## The switch: Codex to Claude (the reverse path)

This covers a failback after step 7 above, and Codex itself running out (the most frequent Codex error
was usage exhaustion) while Claude holds the brain.

1. Record it:

   ```
   python -m ctf failover --event <slug> switch --to claude --by <you> --reason "claude ready again"
   ```

2. Regenerate the rules into the workdir (as above), then move the orchestrator back to Claude Code:

   ```
   python -m ctf new-event <slug> --regen --workdir <workdir>
   tools/claude_launch --event <slug> --workspace <workdir>
   ```

3. Start each lane that was on Codex on Claude, handout as the prompt:

   ```
   tools/claude_launch --event <slug> --challenge <id> -- -p "$(python -m ctf dispatch --event <slug> show <id>)"
   ```

4. Stop handing work to Codex (`tools/codex_handoff.sh`) until the meter shows it open again: a
   handoff onto an exhausted Codex dies on a provider error. The escalation ladder reroutes such a
   stop. Give it Claude models:

   ```
   python -m ctf escalate --event <slug> run --model claude-opus-5-5
   ```

5. Keep running the check.

## Stranded: neither harness can take release work

1. See each window and when it resets or is re-probed:

   ```
   python -m ctf quota --event <slug> status
   ```

2. Keep the no-model paths running: the dispatcher claims new challenges and runs intake (download,
   sweep, Layer-1 openers, auto-submit of format-valid flags) without any model:

   ```
   python -m ctf dispatch --event <slug> run
   ```

3. Hold solve and build work. When the gate says a harness may take a job, send one probe job, not the
   release (a limit reading was wrong at least once, so the meter re-probes):

   ```
   python -m ctf quota --event <slug> gate --kind release
   ```

4. When a harness opens, run the check again and follow its answer.

## What this does not do

- Nothing switches on its own. The check says what to do and exits 3. Starting agents stays with
  the player or the orchestrator, because the dispatcher, the escalation roster and the launchers do
  not read the active harness yet (follow-up item `B-170-F1` in BUILD-PLAN.md; design in
  docs/build-log/B-170.md).
- The rehearsal task is a smoke test of the path at release fan-out, not of solving skill. A lane that
  holds shows that the harness can be started, fenced, prompted and answer in time on that lane. It
  does not show that the harness solves that lane's challenges as well as the primary does.
- Claude's quota percentage is entered by hand (`quota set`). Claude Code logs only the limit hit.
