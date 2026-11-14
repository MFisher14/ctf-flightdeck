---
name: handoff
description: Hand a challenge to Codex (or another Claude) through the shared handoff board, pick up work handed to you, and post findings. Use instead of writing prompts for the player to paste.
---

# Handoff board (thin Claude wrapper)

The procedure is harness-neutral and lives in `docs/handoff.md` in the master repo; Codex follows
the same file. This wrapper only names the commands. Never write a handoff prompt into chat for the
player to paste.

- Hand off: write the guidance to a file, then
  `python -m ctf handoff post --as claude --challenge <id> --mode fast --guidance-file <file>`
  (`--mode deep|cyber|claude|...`; list them with `python -m ctf handoff modes`).
- Several at once: a `[[handoff]]` TOML file and `python -m ctf handoff batch <file> --as claude`.
  Never a shell loop.
- Work for you: `python -m ctf handoff inbox --as claude`, then `python -m ctf handoff claim <id> --as claude`.
- Findings to the other harness: `python -m ctf handoff note <id> --as claude "text"`.
- Finish: write `result.md`, then `python -m ctf handoff done <id> --as claude --status solved|stuck|failed`.
- Watch: `python -m ctf handoff list`, `python -m ctf handoff show <id>`, `python -m ctf handoff reap --as claude`.

State the challenge's scope accurately. Never exclude a technique to get around a filter. Verify a
flag that comes back, then submit it once through the submit gate.
