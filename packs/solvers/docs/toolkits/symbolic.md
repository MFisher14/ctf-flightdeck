# Toolkit `symbolic`: z3 constraint / crackme solver (hand tool, never-wrong)

Built 2026-10-23 (gap analysis Section B, `docs/retro/ctf-solver-gap-analysis.md`: "z3 bounded
constraint-recovery primitive"). A **hand tool** like `web_exploit.py` / `java_deser.py` /
`classical.py` / `pwn_target.py`: it has **no `signals()` and no `solve_set()`** and is never
auto-run. It recovers an input value from z3 constraints and hands it back to the solver, who reasons
to any flag and submits it through `ctf.submit.guarded_submit` (or `./csctf submit <id> <flag>`).

It composes with `solvers/toolkits/pwn.py` (ELF recon, capstone): you may **READ** a disassembly to
find the comparison constants, but the solving is pure z3 over the constraints you extracted.
**Nothing is executed** — no binary is run, no capstone-lifted code is run, and the **flag is never
derived here** (this tool proves the *input* that satisfies a check, not the flag). z3 5.1.0 is in
`.venv`.

## Never-wrong (AGENTS.md "Uncertain answers", the gap analysis's never-wrong contract)

A value is returned **PLAIN only when z3 has PROVED it is the one and only satisfying model**: a
model is found, its negation ("some variable differs") is added, and the solver confirms that is
**UNSAT**. That uniqueness proof is the whole point — it is what makes a symbolic answer never-wrong.

| z3 outcome | `status` | What you get |
| --- | --- | --- |
| exactly one model (negation UNSAT, inside the budget) | `UNIQUE` | `plain()` → the proved value (**plain**) |
| 2 .. `MAX_CANDIDATES` (12) models, all enumerated | `MULTIPLE` | `candidate_values()` → unsure candidates, **never plain** |
| more than `MAX_CANDIDATES` models | `UNDERCONSTRAINED` | `None` (add constraints) |
| timeout / unknown / incomplete (uniqueness not proved) | `TIMEOUT` | `None` |
| contradictory constraints | `UNSAT` | `None` |

`plain()` returns a value **only** when `status == UNIQUE`; `candidate_values()` returns a bounded
list **only** when `status == MULTIPLE`. Every other case is `None` / `[]`. A candidate list maps to
a `labels.candidates` answer (row 346) with `Solution.labels_candidates(key)`, a ranked list you read
and reason to one value.

## Bounded

A **hard wall-clock budget** spans every z3 check (`DEFAULT_TIMEOUT_MS` 8000, clamped to
`MAX_TIMEOUT_MS` 30000), with per-variable bit-width (`MAX_BITS` 1024), variable-count (`MAX_VARS`
4096), constraint-count (`MAX_CONSTRAINTS` 200000) and keygen-length (`MAX_BYTES` 4096) caps, and at
most `MAX_CANDIDATES + 1` enumeration rounds. On expiry the result is `TIMEOUT` → `None`: uniqueness
is never claimed past the budget.

## Run first

```bash
.venv/bin/python solvers/toolkits/symbolic.py --selftest     # prove the engine on tiny cases
.venv/bin/python solvers/toolkits/symbolic.py <elf>...       # READ cmp constants (recon only)
```

The CLI's `<elf>` mode disassembles the executable sections and prints the immediate operands of
`cmp`/`test`/`xor`/`sub`/`add`/… instructions — the candidate constants to lift into constraints.
Solving itself is a Python API (below), because it needs the agent to express the check as z3
constraints; nothing is auto-lifted and nothing is executed.

## The API (by hand, from Python; run with `-I` when a delivery file is on `sys.path`)

```python
import sys; sys.path.insert(0, "solvers/toolkits"); import symbolic as S
import z3
```

- **`keygen(length, build, *, byte_bits=8, charset=None, timeout_ms=..., max_candidates=...)`** — the
  common shape: solve for `length` input bytes whose check passes. `build(xs)` gets the list of z3
  byte `BitVec`s and returns the lifted check as constraints (a list or one `BoolRef`). With
  `byte_bits == 8`, `plain()`/`candidate_values()` decode to `bytes`.

  ```python
  def build(x):                         # a "sequence of comparisons" / a stated transform
      return [x[0] ^ 0xAA == 0xE1,      #  -> x0 = 0x4b
              x[1] ^ x[0] == 0x78,      #  -> x1 pinned once x0 is
              (x[2] + x[1]) & 0xFF == 0xAC,
              x[3] == 0x21]
  sol = S.keygen(4, build, charset=S.printable())
  sol.status            # "UNIQUE"
  sol.plain()           # b'K3y!'   (ONLY when UNIQUE; None otherwise)
  sol.candidate_values()   # []     ([...] only when "MULTIPLE", never plain)
  ```

- **`solve(variables, constraints, *, timeout_ms=..., max_candidates=..., byte_bits=None, var_names=None)`**
  — the raw engine. `variables` are free z3 consts (`z3.BitVec/Int/Bool`); `constraints` an equation
  system / comparison sequence / lifted check. Returns a `Solution`.

  ```python
  a, b = z3.Ints("a b")
  S.solve([a, b], [a + b == 7, a - b == 1])      # UNIQUE -> {"a": 4, "b": 3}
  ```

- **`solve_bitvecs(widths, build, ...)`** — several BitVecs of mixed widths (registers, a packed key).
- **`solve_ints(count, build, ...)`** — an integer equation system (unique only if every var is pinned).
- **`printable()` / `charset_constraints(xs, charset)`** — restrict bytes to a range or an explicit set.

`Solution` fields: `.status`, `.plain()`, `.candidate_values()`, `.labels_candidates(key)`, `.models`
(every enumerated model), `.is_unique`, `.detail`, `.elapsed`, `.checks`, `.reason`.

## Reading comparison constants from a disassembly (READ only, executes nothing)

```python
S.scan_immediates(code, arch="amd64", bits=64)    # [(addr, mnemonic, op_str, imm), ...] for cmp/xor/...
S.cmp_constants(path_or_data)                      # {"arch","bits","sections":[(name, [...]), ...]} or None
```

`scan_immediates` disassembles raw x86/x86-64 bytes with capstone and lists the immediate operands of
comparison / arithmetic / move instructions; `cmp_constants` does the same over an ELF's executable
sections via `pwn.read_elf`. Both are **data to report**: the constants you feed into a `build`
function, never a program to run. Non-ELF / unsupported-arch / empty input is `None` / `[]`, never a
raise.

## What stays None / never-plain

- The **flag** — this tool proves the input that satisfies a check, not the flag; a flag is the
  agent's / player's and is never derived or submitted here.
- Anything z3 cannot prove unique within the budget (timeout / underconstrained / unsat).
- A candidate set is a `labels.candidates` list (row 346) to read and reason from, never a decided
  answer by itself.
