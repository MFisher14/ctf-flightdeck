# Toolkit `sec_space_cfdp`: CFDP capture survey and NAK reconstruction

Module: `solvers/toolkits/sec_space_cfdp.py` (standard library only; engine id
`toolkits.sec_space_cfdp`). Tests: `tests/test_toolkits_sec_space_cfdp.py`. Sibling:
`solvers/toolkits/sec_space_ccsds.py` decodes Space Packets and TM/TC/USLP frames; this one reads the
CFDP PDUs inside them (CCSDS 727.0-B-5).

The challenge shape: a recording of a CFDP file transfer with File Data missing, and the question
"which NAK PDU would the receiver send". The mechanics are deterministic and done here with no
model: walk the stream, parse the PDUs, track the File Data byte coverage, complement it, serialise
the NAK. **Which packets and PDUs count is not**: a mission profile states it in prose (APID, the
source/sequence/destination tuple, which Metadata and EOF are accepted, what happens to data before
Metadata). That part is a filter config you write from the handout. Nothing in the module assumes one
challenge's rules: a selection key you do not state is not checked, and the state policy defaults to
the CFDP standard receiver.

## The two steps

1. **Survey** (no filter; this is what intake runs). Every capture in the challenge folder is tried
   as a Space Packet stream and as a bare PDU stream. Each distinct packet/transaction combination is
   listed with its PDU counts, coverage, file size, gaps and the NAK the CFDP standard receiver would
   send. The result is `unsure`: facts, not an answer.

   ```sh
   python -m ctf run toolkits.sec_space_cfdp <challenge_dir>
   tools/ctfpy solvers/toolkits/sec_space_cfdp.py survey <capture> [--json]
   ```

2. **Filter, then reconstruct.** Print a filter pre-filled with one surveyed row, set every line
   the mission profile states differently, save it as `cfdp-filter.toml` at the top of the challenge
   folder (not under `files/`) and run the engine again. With an `[output]` section the NAK comes back
   as a `candidate` in the stated answer format; without one it is reported as hex (`unsure`).

   ```sh
   tools/ctfpy solvers/toolkits/sec_space_cfdp.py skeleton <capture> [--row N] > <challenge_dir>/cfdp-filter.toml
   python -m ctf run toolkits.sec_space_cfdp <challenge_dir>            # or --opt filter=PATH, --opt file=REL/PATH
   tools/ctfpy solvers/toolkits/sec_space_cfdp.py nak <capture> --filter cfdp-filter.toml --trace
   ```

   `--trace` prints the decision for every unit (`accept`, `ignored`, or the rule that dropped it,
   such as `packet.apid`, `transaction.source`, `file_data.before_metadata`, `eof.file_size`). The
   engine result carries the same counts, so a rule that drops nothing, or everything, is visible.

   `--opt file=REL/PATH` must name a capture inside the challenge folder (a path that resolves
   outside it, through `..`, an absolute path or a symlink, blocks the run). Run the CLI through
   `tools/ctfpy`: the `[output]` flag wrapper reads the event profile through the repo's `ctf`
   package, and a bare `python3 -I` run that needs it stops with a named error (a stated
   `output.prefix` without `--event` still renders, unchecked against the event format).

The result is never `solved`: the filter is a reader's translation of prose, so the value is a
candidate until the platform accepts it.

## Filter config

TOML. Unknown sections and keys, wrong types and a missing `stream.framing` are errors that name the
key. The example below is illustrative: the values are made up.

```toml
[stream]
framing = "space-packet"        # required: space-packet (concatenated Space Packets) | cfdp-pdu (bare PDUs)
# file = "*.bin"                # optional: only captures whose file name matches

[packet]                        # Space Packet selection (space-packet framing only)
pvn = 0
type = "tm"                     # tm | tc
secondary_header = false
apid = 0x2A5                    # one APID or a list
sequence_flags = 3

[transaction]                   # CFDP fixed-header selection
version = 1
direction = "toward-receiver"   # toward-receiver | toward-sender
mode = "acknowledged"           # acknowledged | unacknowledged
crc = false
large_file = false
entity_id_length = 1
sequence_number_length = 1
source = 0x11
sequence = 0x2C
destination = 0x05

[file_data]                     # a File Data PDU must also match these
segmentation_control = false
segment_metadata = false

[metadata]                      # a Metadata PDU must match these to be accepted
checksum_type = 15
closure_requested = false
options = false                 # false: no option TLVs; true: at least one

[eof]                           # an EOF PDU must match these to be accepted
condition_code = 0
spare = 0
checksum = 0
fault_location = false          # false: no fault-location TLV; true: one
file_size = "metadata"          # "metadata": equal to the accepted Metadata size | a byte count

[policy]                        # the receiver state; these are the non-standard choices
metadata_first = true           # default false. true: File Data and EOF before the accepted Metadata are dropped
beyond_file_size = "discard"    # default "keep". discard: a segment ending past the Metadata size adds nothing
eof_snapshot = true             # default true: coverage is what had arrived at the first accepted EOF

[nak]
scope_start = 0                 # default 0
scope_end = "eof"               # default "eof" (the accepted EOF's file size) | "metadata" | a byte count
direction = "toward-sender"     # default
request_metadata = false        # default true: ask for the Metadata with a (0, 0) request when none was accepted
# mode, crc, large_file         # default: copied from the accepted EOF's header
# max_segment_requests = 100    # split into several NAK PDUs of at most this many requests

[output]                        # the answer format the challenge states; omit to get hex only
encoding = "hex-upper"          # hex-upper | hex-lower | base64
wrap = "flag"                   # flag: PREFIX{...} | none
# prefix = "EXAMPLE"            # default: the event profile's first flag prefix, through ctf.flagfmt
```

Rules worth knowing:

- **Selection keys** (`[packet]`, `[transaction]`, `[file_data]`, `[metadata]`, `[eof]`): each stated
  key must match; an absent key is not checked. If the selection lets PDUs of more than one
  source/sequence/destination tuple through, the engine stops and lists them.
- **Framing** is exact: a truncated recording is an error and there is no resynchronisation. Under
  `space-packet` each selected packet's user data must be exactly one CFDP PDU whose declared data
  field length consumes it; a unit that is not is counted as `malformed` and the walk continues. A PDU
  with the CRC flag must verify (CRC-16, polynomial 0x1021, all-ones preset).
- **State**: the first Metadata that matches is the accepted one, the first EOF that matches is the
  accepted one; later ones are dropped (`metadata.later`, `eof.later`). Duplicate and overlapping File
  Data merge. Packet sequence counts are never coverage.
- **NAK**: the missing ranges are the ascending, maximal, non-overlapping `[start, end)` gaps of the
  coverage inside the scope. The header copies the version, ID lengths and tuple of the accepted EOF
  (else the Metadata, else the first File Data). Offsets are 32-bit, or 64-bit with the large-file
  flag. Complete coverage means no NAK (`none`).
- **Output**: the flag lead comes from the event profile through `ctf.flagfmt` unless `prefix` is
  stated. The result notes say whether the value is in the event's own flag format; a handout may
  state a format the board's does not cover (a long NAK is over the default flag body length), and
  the value is still returned as the candidate.

## Limits

- Carriers other than raw Space Packets or bare PDUs (TM/AOS transfer frames, a pcap of UDP
  datagrams, an encapsulation header before the PDU) are not unwrapped here: extract the packets
  first (`sec_space_ccsds.py`, `network.py`).
- CFDP version 0 (727.0-B-4) headers and File Data are read; its directive bodies are read with the
  version 1 layouts.
- A NAK split across several PDUs (`max_segment_requests`) follows the standard's scope chaining as
  written here from the specification; it has not been checked against another implementation.
- A file over 16 MiB is not read (named in the result).
