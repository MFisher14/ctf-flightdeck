## What changed and why

<!-- What a player or a contributor will notice, and the problem it solves. Link the issue: "Fixes #12". -->

## How it was tested

<!-- The tests you added or changed, and the summary line `uv run pytest` printed. Name any test that reported as not run (no Docker, no debian:bookworm-slim) and why. -->

## Checklist

- [ ] `uv run pytest` passes, and I saw it pass.
- [ ] Each new behaviour has a test that fails when the behaviour is wrong: no tautologies, no mocking the unit under test, no skip-as-pass.
- [ ] No secrets: no key, token, cookie or Authorization value, not even a fake one shaped like a real one.
- [ ] No real event data: no real challenge, flag, team or player name. Fixtures are synthetic.
- [ ] The pre-commit guard ran on every commit (`git config core.hooksPath .githooks` turns it on), and no commit used `--no-verify`.
- [ ] The rules for code in CONTRIBUTING.md hold: challenge text stays data, nothing falls back silently, no test reaches real CTF infrastructure or runs a challenge binary.
