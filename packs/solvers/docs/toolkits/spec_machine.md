# Toolkit `spec_machine`: spec-driven register machine, example gate, round client

Module: `solvers/toolkits/spec_machine.py` (standard library only). Command: `python -m ctf machine`.
Tests: `tests/test_toolkits_spec_machine.py`, `tests/test_spec_machine_service.py`. Build log:
`docs/build-log/B-057.md`.

For "implement the machine" challenges: a prose instruction-set specification, a file of worked
examples, and a service that sends a program and an input tape per round and wants the machine's exact
output for N rounds, closing on the first wrong answer. The agent writes one spec file from the prose;
the interpreter, the example checker and the round client are here. No model is called, and no spec
text is executed as Python: an instruction body is parsed with `ast` and compiled from a whitelist.

Bytecode VMs reversed out of a binary, with hand-written Python handlers, are a different tool:
`solvers/binary/vm_lifter.py`.

## The loop

```sh
python -m ctf machine init CHAL/                    # writes CHAL/machine.machine.toml, a complete starter
# edit it from the prose: registers, ops, quirks, framing, examples (or examples_files)
python -m ctf machine check CHAL/machine.machine.toml
python -m ctf machine run   CHAL/machine.machine.toml prog.txt --input "1 2 3" --trace
python -m ctf machine play  CHAL/machine.machine.toml HOST PORT --log session.log
```

`check` runs every worked example and prints each failure with expected and got. `play` runs the same
gate first and exits 4, with no connection opened, unless every example reproduces and there is at
least one. A round the handler cannot parse, or whose program traps or runs out of fuel, stops the
session with an error instead of sending a guess. The flag is printed, never submitted. The engine
entry does the same from a challenge folder: `python -m ctf run toolkits.spec_machine DIR [--opt
host=H --opt port=P]` (a `SolverResult`; the transcript goes to `DIR/recon/spec_machine/session.log`;
only one of host and port is `blocked`, naming the missing half).

## Spec file

TOML (`*.machine.toml`) or JSON (`*.machine.json`). Unknown keys are errors. Top-level keys go above
the first table.

| key | meaning |
|---|---|
| `name` | a label |
| `word_bits` (16) | width of a word, 1 to 64 |
| `overflow` (`wrap`) | what a write does with a value out of range: `wrap`, `saturate`, `trap` |
| `signed` (false) | true: words are two's complement values (`-32768..32767` at 16 bits), comparisons and `>>` are signed |
| `examples_files` | handout example files, relative to the spec, read with `[framing]`; an absolute path or one that leads out of the spec's folder (`..`, a symlink) is refused |
| `[registers]` | `names = [...]`, or `count` and `prefix` (`r0..`); `init = {r1 = 5}` |
| `[flags.<name>]` | `update = "<expr>"` (how an instruction that lists the flag in `sets` updates it), `init` |
| `[memory]`, `[stack]` | `size`: enables `mem[i]` and `push()` / `pop()` |
| `[quirks]` | `div_zero`, `mod_zero` (an integer, `"dividend"` or `"trap"`), `shift_mask` (ANDed with the count), `mem_oob` (`"trap"` / `"wrap"`), `input_eof`, `pop_empty` (an integer or `"trap"`). Left out, each one traps |
| `[syntax]` | `comment` (`["#", ";"]`), `separators` (`","`), `case_sensitive` (true), `label_suffix` (`":"`), `end`, `else`, `imm_prefix` |
| `[io]` | `format` (`dec`, `signed`, `hex`, `char`), `width` (zero padding), `prefix`, `separator`, `empty` (the answer when nothing was printed) |
| `[limits]` | `fuel` (1,000,000 executed instructions), `max_output` |
| `[ops.<name>]` | `args`, `do`, `sets` |
| `[blocks.<name>]` | `kind` (`repeat`, `if`, `while`), `args`, `count` (repeat) or `cond` |
| `[framing]` | `program_start` + `program_end` (lines equal to the marker) or `program_re`; `input_prefix` or `input_re`; `output_prefix` or `output_re` (examples files); `prompt` (what the service prints when it waits) |
| `[[examples]]` | `name`, `program`, `input` (integers), `output` (text, outer blanks ignored) |

**Operands.** `args = ["d:reg", "x:val", "n:imm", "t:label"]`: `reg` a register, `imm` an integer
(decimal, `0x`, `0b`, `0o`, signed), `val` either, `label` a label (it reads as an instruction index).
A bare kind (`"reg"`) is named `a`, `b`, `c`, ... by position.

**`do`.** Statements separated by `;` or newlines: assignments (also `+=` and friends) to a `reg` or
`val` operand, a register by name, a flag, `mem[i]` or a `_local`; `if` / `elif` / `else`; calls.
Expressions: integers, names, `+ - * // % & | ^ << >> ~`, comparisons (chained too), `and or not`,
`x if c else y`, `mem[i]`. Right-hand sides are evaluated before the write, so `add r0 r0 r0` reads
the old `r0`. Names: the operands, every register and flag, `mask`, `bits`, and after an assignment
`raw` (the value before it was fitted to a word) and `result` (the word stored). Locals start with
`_` and hold unfitted values (`_p = x * y; hi = _p >> 16; lo = _p`).

| call | does |
|---|---|
| `input()` | the next input word (`quirks.input_eof` past the end) |
| `output(x)` | append a word to the output |
| `s(x)`, `u(x)` | the word as two's complement / as unsigned |
| `tdiv(a, b)`, `tmod(a, b)` | C-style division and remainder (`//` and `%` floor) |
| `push(x)`, `pop()` | the data stack |
| `goto(i)`, `call(i)`, `ret()`, `halt()` | control: an instruction index, usually a `label` operand |

**Flags.** A flag is 0 or 1. `sets = ["z", "c"]` on an instruction applies those flags' `update`
formulas after its `do`, all evaluated against the flags as they were. An instruction that lists no
flag leaves them alone, which is how "inc does not touch carry" is written. A compare writes no
register: `do = "_ = x - y"` sets `raw` and `result` for the formulas.

**Blocks.** `repeat` evaluates `count` once on entry (zero or negative: skipped); `if` evaluates
`cond` once and may have an `else`; `while` evaluates `cond` on entry and after every trip. A jump out
of a block drops it; a jump into a block that is not running is a trap. `call` from inside a block
returns into it.

**Framing.** In marker form a program is the lines between a line equal to `program_start` and one
equal to `program_end`; its input is the rest of the first following line that starts with
`input_prefix` (integers separated by blanks or commas), its expected output likewise with
`output_prefix`. In regex form each pattern's first group is the text. In a service round the last
complete program before `prompt` is the one answered, so a banner quoting an example does no harm, and
a round that arrives in several reads is buffered until `prompt` shows.

## Library

```python
import spec_machine as sm
spec = sm.load_spec(path)                    # or sm.parse_spec(dict, base=folder)
sm.run(spec, program_text, inputs, fuel=None, trace=None)   # RunResult(outputs, text, steps, registers, flags, halted)
sm.conformance(spec)                         # ConformanceReport(results) .total .passed .failures .ok
sm.gate(spec)                                # the report, or GateRefused(.report)
sm.RoundHandler(spec)                        # prompt -> answer | None, for tools/netplay.run_loop
sm.play(spec, host, port, profile=None)      # PlayResult(flag, rounds, report, last_text)
sm.solve(challenge_dir, profile, spec=None, host=None, port=None)   # SolverResult
```

Errors are `MachineError` subclasses: `SpecError` (names the dotted key), `ProgramError` (names the
line), `MachineTrap` and its `FuelExhausted`, `FramingError`, `GateRefused`. `play` checks the target
with `ctf.scope` before any socket (through `connect` in `tools/netplay.py`, and against `profile` when given).

## Limits

Programs are text, one instruction per line; inputs are integers. Not covered: self-modifying code,
programs delivered encoded (base64, bytecode) and text inputs; decode those first, or use `vm_lifter`.
