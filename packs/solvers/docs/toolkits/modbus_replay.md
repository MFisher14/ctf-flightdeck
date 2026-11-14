# Toolkit `modbus_replay`: Modbus/TCP replay and spec-driven witness/report

Built for B-082. Two challenge shapes kept being rebuilt by hand: a Modbus/TCP capture plus a prose
policy, where the answer is a hash over (a) the request/response PDUs of the policy-violating writes
(the *witness* family) or (b) a canonical text report of the confirmed control snapshots (the
*reconciliation report* family). Pairing and state replay are mechanical and are done here with no
model. The policy and the output grammar arrive as prose, so they go in a short TOML spec the agent
writes from the handout. The engine emits nothing until the handout's test vector reproduces.

Offline only: it reads the supplied capture (through `ics_capture`) and never opens a socket.

## Run

```bash
python -m ctf run toolkits.modbus_replay <challenge>                      # spec: <challenge>/modbus-replay.toml
python -m ctf run toolkits.modbus_replay <challenge> --opt spec=path.toml --opt out=folder
tools/ctfpy solvers/toolkits/modbus_replay.py <folder> [--spec F] [--out D] [--event SLUG]
```

Intake runs it on any challenge whose brief names Modbus (`select = "route"`).

| situation | result |
|---|---|
| no capture holds Modbus/TCP on the server port | `none` |
| no Modbus in what was read, but something was not read (an encrypted or broken zip, an unreadable member, a capture over the size cap, a symlinked capture, a capture that will not parse) | `blocked` (`unreadable-input`), naming each |
| Modbus found, no spec yet | `unsure`; `recon/modbus_replay/replay.json` has every transaction and the register timeline |
| spec, the gate is open, a stated selection check held | `solved`; flag, `witness.bin` or `report.txt` (the exact hashed bytes) |
| spec, the gate is open, but no selection count in `[expect]` (`targets ineligible discarded unselected rows`) and no `[[rows.check]]` | `candidate`: the vector tests the recipe, not which transactions were picked |
| the wrapped value is not in the event's flag format | `candidate` |
| the gate is shut, a row check is false or a count is off | `unsure`, no flag, no output file; the notes say which |
| bad spec, several Modbus captures and no `[capture] file`, damaged stream, unobserved policy register | `blocked`, with the named reason |

## What it does without a spec

1. **ADUs in capture order** (`capture_adus`). Each directional TCP stream is reassembled and split
   on the MBAP header. An ADU is placed at the capture packet at which its stream was whole up to its
   last byte, so segmentation, coalescing, out-of-order segments and retransmissions neither split nor
   reorder it. An ADU with a nonzero protocol identifier or an MBAP Length over 254 stays in the
   sequence, marked rejected. A truncated tail is a finding. A TCP gap, disagreeing retransmissions or
   a Length under 2 are *damage*: a spec run refuses them (`capture-damaged`) unless
   `[capture] allow_damaged = true`.
2. **Pairing** (`pair`).
   - `pending`: a response answers the one pending request with its transaction id and unit. A
     transaction id pending twice confirms neither request; a duplicate response voids the
     transaction it repeats.
   - `immediate`: a response counts only when the ADU directly before it is its request.

   A transaction is *accepted* only on a well-formed normal response with the same function code:
   FC03/FC04 byte count is twice the request quantity, FC06 echoes the request, FC16 echoes start and
   quantity exactly. Exceptions, unanswered requests, bad echoes and malformed requests are kept and
   labelled, never accepted.
3. **Register-state replay** (`replay`). Holding registers only. FC06/FC16 take effect on their
   accepted normal response (not on the request); an accepted FC03 refreshes every word it covers;
   nothing else changes state. Each transaction carries the state just before and just after its
   response.

## The spec

Start from a template in `solvers/toolkits/modbus_replay_templates/` (`witness.toml`, `report.toml`);
both are commented key by key and run as shipped on a matching capture. Unknown keys are errors.

| table | what it states |
|---|---|
| `[capture]` | `file` (when several captures hold Modbus), `allow_damaged` |
| `[scope]` | `server_port` (502), `client`, `server`, `client_port`, `unit`. Exactly one conversation must remain |
| `[pairing]` | `mode = "pending"` or `"immediate"` |
| `[registers]` | name = PDU address of each word the policy reads |
| `[replay]` | `initial` (by register name), `unknown` (word assumed for an unobserved register; absent: an error), `fc03_refresh` |
| `[select]` | `function` (6 or 16), `start` list, `quantity` list, `window = [lo, hi]`, `when` (the predicate), `state` (`before`/`after` the normal response), `order` (`response`/`request`) |
| `[select.readback]` | confirmation rule: the next client ADU after the write's normal response must be exactly this read (`function`, `start`, `quantity`), accepted, and not already used; `fields` names the words read back |
| `[rows]` | `initial` (the row before row 0), `[[rows.derive]]` computed columns, `[[rows.check]]` evidence checks |
| `[expect]` | counts the handout states: `adus transactions accepted exceptions unanswered rejected writes targets ineligible discarded unselected rows` |
| `[output]` | `kind = "witness"`: `prefix_hex` or `prefix_text`, `parts`. `kind = "report"`: `header`, `row`, `footer`, `newline`, `final_newline`, `[[output.aggregate]]`. Both: `hash`, `digest_bytes`, `encoding`, `wrap` |
| `[[vector]]` | the handout's test vector: `rows`, and `expect` (encoded value) and/or `expect_digest`; for a report also `expect_text`, `expect_rows`, `expect_initial`, `initial` |

Row fields: `i`, `tid`, `unit`, `function`, `start`, `quantity`, `w0`.. (the written words), `ordinal`,
`packet`, the `[registers]` names (state before/after the response), the readback `fields`, `rb_tid`,
the derived columns, and `prev_<name>` for the previous row (row 0: `[rows] initial`). `tid` is always
the write's transaction id, never the readback's.

Expressions (`when`, `derive`, `check`, aggregates) are integers only: `+ - * // % & | ^ << >>`,
comparisons, `and or not`, `a if c else b`, `abs min max`. `/` is refused (use `//`); nothing else
parses, so a spec cannot run code. Report lines take `{name}` or `{name:04X}` fields (format:
optional zero fill, optional width up to 64, then `d`, `x` or `X`; anything else is a spec error).
`wrap = "event"` needs the event's flag lead to end in `{` (`PREFIX{`); otherwise give the wrapper as text.

Witness parts: `request_pdu`, `response_pdu` (function code and data, no MBAP), `request_adu`,
`response_adu` (with MBAP), `request_data`, `response_data` (the PDU without the function code).
Hashes: `none md5 sha1 sha224 sha256 sha384 sha512 sha3_256 sha3_512`. Encodings: `hex hex-upper base32
base32-nopad base64 base64-nopad base64url base64url-nopad`. `wrap`: `event` (the event flag prefix),
`none`, or text with one `{}` for the value.

## The known-answer gate

Vector rows go through the same `derive_rows` and `build_output` the capture rows go through. No
value, flag or output file exists unless:

- the spec has at least one `[[vector]]`, each stating `expect` or `expect_digest` (a vector that
  stops at the text does not test the hash or encoding, and is a spec error);
- every vector reproduces, in every expectation it states;
- every `[[rows.check]]` is true on every capture row (checks never run on vector rows: a public
  vector is usually not an incident row set);
- every `[expect]` count matches.

A refusal prints what the recipe produced for the *vector*, never the capture's value. An earlier
run's output file is removed on a refusal.

What the gate does not prove: a vector exercises the serialisation, the derived columns, the hash and
the encoding. It does not exercise the scope, the pairing rule or the selection predicate. State the
handout's counts in `[expect]` ("the eight other accepted writes are ineligible", "exactly 64 confirmed
snapshots") so the selection is checked too. Only the counts made after selection (`targets ineligible
discarded unselected rows`) or a `[[rows.check]]` count as a selection check; `adus`, `transactions`,
`accepted`, `exceptions`, `unanswered`, `rejected` and `writes` are fixed before any selection, so a
spec that states only those is still `candidate`.

## Limits

- Modbus/TCP only (no RTU-over-TCP, no serial captures). Holding registers only: FC03, FC06, FC16.
  FC04 is paired but is not state; coils, FC22 and FC23 are paired and not replayed.
- One conversation per run. A policy that spans several connections needs one run per connection.
- When one readback follows two acknowledged writes, the write acknowledged first keeps it and the
  later one is discarded. A handout that discards both needs that stated by hand.
- The prose is not read. Writing the spec from the handout is the agent's step.
