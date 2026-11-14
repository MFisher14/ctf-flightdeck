# Programming playbook — CSCTF 2026

The "Programming" category is **automation under a clock**: a remote service asks a timed question (or a
run of them) and you must compute and send the answer faster than the timeout, usually for N rounds, then
it prints the flag. 2024 had six (Geography Master, Math Master, Multiply 1/2, Lost flag, Pwntools);
2025's Intreview-1..6 are the same shape. These are **first-blood fodder** — deterministic, no intuition,
win in the first minutes. Scope/rate rules in `AGENTS.md` still bind (only the assigned target; the
drivers keep their round caps).

## First moves

1. Read `connection_info` in `challenge.json` (host/port; may rotate mid-event — re-read on failure).
2. `nc`/`ncat` the port once by hand to see the prompt grammar (one round), then script it. Don't hand-play
   a timed loop — you'll miss the deadline.
3. Reach for the driver, not a bespoke script:

```sh
.venv/bin/python tools/netplay.py --list                 # the handler library (auto-dispatch by prompt)
.venv/bin/python tools/netplay.py <host> <port> --auto   # pick a handler from the prompt wording
.venv/bin/python tools/netplay.py <host> <port> --handler NAME
.venv/bin/python tools/netplay.py <host> <port> --ssh user   # if it's an ssh REPL, not raw nc
```

## Archetypes → handler

| Prompt shape | 2024/2025 example | How netplay handles it |
| --- | --- | --- |
| Repeat a character N times | Multiply 1/2 | `multiply_char`: parse N, send `char*N` within the timeout |
| Reduce a CSV/list of numbers by an op | Math Master | `math_csv`: parse operands + op word, compute, sendline |
| Country → capital (30 prompts) | Geography Master | `country_capital`: offline capital table, no network lookup |
| Encode/transform (b64 sort, XOR-hex, HMAC, HS256, TLV) | Intreview-1..6 | `b64_sort_concat`, `xor_hex`, `hmac_sha256_hex`, `hs256_jwt`, `tlv_sort_concat`, `clf_bytes_sum` |
| Trivia about an API/tool | Pwntools | `pwntools_quiz`: static answer table |
| Language-REPL shell escape over nc | Romeo & Julia | `repl_shell_escape` (via `--script`) |
| Decode a grid/sheet of QR codes, filter to the flag | Lost flag (50×50) | not a socket loop — see below |

For a **new** prompt grammar netplay doesn't recognize, write a small `--script` (JSON send/expect) or a
challenge-specific `retrieve` callable; keep it in the challenge's `notes.md` so it's re-runnable (useful
if the challenge also rotates its flag — see `ctf.dynamic.solve_dynamic`).

## QR / image-grid programming challenges

"Lost flag" ships an image (a grid of QR codes, one real among decoys), not a socket. Use the QR engine:

```sh
.venv/bin/python solvers/toolkits/qr_decode.py sheet.png --grid 50x50 --pattern 'CSCTF\{[0-9A-F]{17}\}'
.venv/bin/python solvers/toolkits/qr_decode.py one.png          # single QR -> payload (then decode the chain)
```

It decodes every cell and reports only the payloads matching your flag regex — it filters, it never
guesses. A single-QR payload that's itself an encoding chain (binary → base64 → …) goes to
`solvers/warmups/crib_decode.py`.

## Getting the flag out & submitting

The driver prints the service's final line containing the flag. Reason to the one `CSCTF{...}` and submit
once through the guard:

```sh
./csctf submit <id> 'CSCTF{...}'
# or from a solver: ctf.submit.guarded_submit(ctfd, ch, flag, provenance="netplay <handler> output")
```

Never sweep candidate answers at the flag prompt — that's brute-forcing. Compute the one right answer per
round; if a round's answer is genuinely ambiguous, stop and reason, don't spray.

## Scope & safety (the hard boundary)

Only the squad's assigned target. No submission flooding, no mass scanning. `netplay.py`'s round/timeout
caps and the submit guard exist to keep us inside the CSCTF rules — keep them. Detonation of any untrusted
artifact is Docker-only.

## General prompt handlers and proof-of-work gates (round 2)

`tools/netplay.py --auto` now recognizes several deterministic prompt families without a bespoke
script: bounded integer/modular expressions, MD5/SHA-1/SHA-256/SHA-512/CRC32/BLAKE2 hashing, base
conversion, sort/reverse/dedupe/sum/min/max list operations, nth-prime/Fibonacci/Collatz sequences,
and ROT13/Caesar/reverse transforms. Arithmetic uses a strict AST allowlist—never Python `eval`—and
all integer sizes, sequence indexes, list lengths, and step counts are capped.

For a hashcash or leading-zero gate, use the standalone offline solver or let `--auto` dispatch it:

```sh
.venv/bin/python solvers/toolkits/pow_solver.py --prompt \
  'find suffix: sha256 prefix="fixture:" starts with 0000' --max-attempts 5000000 --json
.venv/bin/python solvers/toolkits/pow_solver.py --prefix 'fixture:' --bits 16 --workers 4 --json
```

The solver supports SHA-1/SHA-256/SHA-512, decimal/hex/binary counters and Hashcash v1. It verifies
the winning suffix before returning it and refuses difficulty/attempt counts above its hard caps.
The module itself has no networking; netplay only calls it after the already scoped connection
delivers an explicit gate.

## Bounded esolang execution

For non-Brainfuck programs, run
`.venv/bin/python solvers/warmups/esolang_tail.py <unlambda|lazy-k|thue|fractran|hexagony|false|underload> file --json`.
Interactive programs accept explicit `--input-text`/`--input-hex`; no interpreter reads the terminal,
filesystem, environment, or network as program input. Reduction steps, output, rules, integers, and
branch counts are capped, and nondeterministic Thue results are ranked for human inspection. The
Hexagony lane includes wrapping geometry/six-IP switching/directed-edge memory; Underload includes
nested string quotation and bounded self-execution.

## Offline transcript planning and Brain-Flak

Use `solvers/toolkits/transcript_automation.py` to analyze a saved prompt/transcript or replay a
literal, bounded interaction state machine. It reuses strict netplay grammars; adds factorial,
GCD/LCM, binomial, modular inverse, and range sums; replay-checks results; and emits only unsent plans.
It never opens a connection. `solvers/warmups/esolang_round5.py` provides bounded Brain-Flak execution
and names both ecosystem stack-output conventions for review without selecting either as an answer.
