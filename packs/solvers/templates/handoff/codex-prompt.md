# Handoff board (thin Codex wrapper)

Codex cannot run Claude skills. The handoff procedure is therefore one harness-neutral runbook,
`docs/handoff.md` in the master repo, plus the `python -m ctf handoff` command, which both
harnesses run. Paste this file once into a ready Codex agent, or put it in its AGENTS.md. After
that, work reaches the agent through the board instead of through chat.

- Check for work: `python -m ctf handoff inbox --as codex`
- Take a handoff: `python -m ctf handoff claim <id> --as codex`. Then read the whole brief it
  names. The brief ends with `=== END OF BRIEF <id> sha256:... ===`. If
  `python -m ctf handoff check-brief <brief>` fails, the brief is truncated: stop and say so with a
  note.
- Share findings or ask the orchestrator: `python -m ctf handoff note <id> --as codex "text"`
- Finish: write your answer to the brief's `result.md`, then run
  `python -m ctf handoff done <id> --as codex --status solved|stuck|failed`
- Hand work to Claude: `python -m ctf handoff post --as codex --challenge <id> --mode claude --guidance-file <file>`

Never submit a flag and never buy a hint. The orchestrator verifies the flag and submits it once.
