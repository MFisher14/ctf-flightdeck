# RF, RFID and hardware captures: quick reference (toolkit `rf`, backlog row 89)

One file, offline, stdlib: `solvers/toolkits/rf.py`. Tests: `tests/test_tk_rf.py`.

## Run first

```bash
.venv/bin/python tools/unpack.py <attempt dir>                       # members/ to read
.venv/bin/python solvers/toolkits/rf.py <attempt dir>/members/*      # a triage of every file
.venv/bin/python solvers/toolkits/rf.py <file> --json                # shape, signal, every fact and its spellings
```

The triage names each file by its bytes and prints what it holds. The last line of a file,
`facts solve_set can answer: ...`, lists the fields the solver has for it.

Reason to the flag from the output and submit it once via `ctf.submit.guarded_submit(...)` (or
`./csctf submit <id> <flag>`).

Unsure answers show as ranked candidate values (`labels.show`); `solvers/common/labels.py` does not yet
know the prefix `rf` (`LANE_DIRS`), so each is read as a list of candidates for you to decide.

## What it reads

| File | Reader | Facts |
| --- | --- | --- |
| Flipper `.sub` (key file) | `sub_info` | frequency (Hz), preset, modulation, protocol, bit, key, TE |
| Flipper `.sub` (RAW) | `sub_info`, `readings`, `text_readings` | frequency, preset, timing and pulse counts; a message only when exactly one reading is printable ASCII. Readings: pulse width (`pwm_long_high`), pulse distance for pulses of one width (`ppm_long_gap`: Nexus, Prologue sensors), a start pulse then off-on pairs (`pwm_gap_first_long_gap`: CAME, Nice FLO), Manchester, each with its inverse |
| Flipper `.nfc` | `nfc_info` | device type, UID, ATQA, SAK, MIFARE type, blocks, pages, NDEF |
| MIFARE Classic dump (320, 1024, 4096 bytes) | `mfc_parse`, `mfc_model` | UID with BCC check, SAK, ATQA, per sector key A, access bits (checked against their inverted copy, decoded per block), key B, value blocks, NDEF from sector 1 on |
| NDEF | `ndef_tlv`, `ndef_parse`, `ndef_flat` | records: text and language, URI with the prefix table, MIME, smart poster, external |
| Flipper `.rfid` | `rfid_info`, `em4100_bytes` | key type, data; EM4100 ids (10-digit, 8-digit, `FFF,CCCCC`); H10301 facility code and card number |
| Flipper `.ir` | `ir_info`, `nec_decode` | signals: name, protocol, address, command; raw frequency and timings. The triage reads a raw signal as NEC or NECext timing (address and command as the Flipper firmware reports them); a reading, never answered |
| `.cu8` `.cs8` `.cs16` `.cf32` | `iq_info`, `iq_pulses`, `name_hints` | sample count; the OOK envelope as pulse runs (depends on a threshold: inspection only); frequency and rate from an rtl_433-style name are hints |
| WAV | `wav_info`, `afsk_text`, `afsk_decode` | channels, sample rate, frames, bits per sample; the text of a two-tone FSK modem recording (Bell 202 at 1200 baud as `minimodem 1200` reads it, Bell 103 at 300, V.23), 8N1: an unsure `message` (`rf.message/wav.afsk`), the one `name{...}` flag in the text offered first. A WAV a modem reads as text raises `signals` to 0.8 |
| Magstripe text | `magstripe_text`, `luhn` | PAN, name, expiry (YYMM on the stripe), service code, discretionary data |
| Bit strings | `em4100_bits`, `wiegand`, `magstripe_bits` | an EM4100 frame at any rotation; 26/34/35/37-bit Wiegand; 5-bit and 7-bit tracks, forwards and backwards, parity and LRC checked |
| Intel HEX, S-records | `ihex_parse`, `srec_parse` | record counts, checksums, base and start address, the image (strings in the triage) |
| candump log, Vector ASC | `can_parse`, `can_asc_parse` | frames, ids, payloads per id as text when printable. An ASC log's status, statistic, error, remote, CAN FD and J1939TP lines are no data frames: with any of them no count is answered |
| Logic CSV (header row) | `logic_info`, `uart_decode`, `i2c_decode`, `spi_decode` | UART 8N1 text and baud, I2C address and data, SPI bytes |

Raw timings by hand:

```python
import sys; sys.path.insert(0, "solvers/toolkits"); import rf
s = rf.sub_info(open("capture.sub", "rb").read())
te = rf.te_estimate(s["timings"])                 # the short unit, microseconds
for name, packets in rf.readings(s["timings"]).items():      # pwm_long_high, pwm_short_high, manchester_ieee, manchester_thomas
    print(name, packets[0], rf.bits_to_bytes(packets[0]).hex())
```

Conventions: a positive timing is carrier on. `pwm_long_high` reads a long on time as 1 (Princeton,
PT2262); `pwm_short_high` is its inverse. `manchester_ieee` reads low-to-high as 1 (IEEE 802.3);
`manchester_thomas` is its inverse. The last PWM bit of a packet is read from its on time alone, so
a protocol that ends with a short sync pulse shows one extra `0`.

## Question shapes it answers

The field is read from the question's words and the answer id (`sector-2-key-a` works like "key A
of sector 2"). Sectors, blocks and pages count from 0; NDEF records from 1.

- Card: UID, UID length, ATQA, SAK, BCC, card or device type, sector / block / page count, key A or
  key B of sector N, access bits of sector N, block N, page N, value of block N, the one value
  block ("balance"), NDEF URI / text / language / record type / record count.
- Sub-GHz: frequency, preset, modulation, protocol, bit length, key, TE, timing and pulse counts,
  the message of a raw capture.
- 125 kHz: key type, data, card id, facility code, card number, customer byte.
- IR: protocol, address, command (of the signal the question names when there are several),
  signal count.
- Magstripe: PAN, cardholder name, expiry, service code, discretionary data, Luhn, track count.
- Firmware and buses: record count, data size, start address, base address, S0 header; CAN frame
  count and distinct ids; UART message and baud; I2C address.
- IQ and WAV: sample count, sample rate, channels, bits per sample.

What comes back:

- **Plain** only for a proven fact in the one form the question allows: an integer asked for as a
  number, the single spelling the `answer_format` pattern or its listed choices accept, or a form
  the words fix ("uppercase hex without separators and no 0x prefix", "in Hz").
- **Unsure** (`labels.pick('rf.<field>/<shape>', ...)`) for a proven fact whose spelling is not
  judged. Methods, best first: hex `lower`, `upper`, `upper_spaced`, `lower_spaced`, `upper_colon`,
  `lower_colon`, `0x_lower`, `0x_upper`; frequency `hz`, `mhz`, `mhz_2dp`, `mhz_3dp`, `mhz_unit`,
  `khz`; text `as_read`, `lower`, `snake`, `upper`; expiry `yymm`, `mm_yy`, `mmyy`, `iso`.
- **None** for everything else: no rule reads the question, the file lacks the field, two files
  disagree and the question names neither, a block has `??` bytes, access bits fail their inverted
  copy, a count has a condition ("how many sectors use the default key"), a hash or file size
  (triage proves those), the bits of a raw capture (polarity is a choice, not a fact).

Tightened in review (2026-10-08), each after a wrong plain answer was shown:

- A count is plain only when the question is made of plain count words ("How many CAN frames are
  in the capture?"). Any other word, number or condition ("have ID 0x123", "in sector 3", "are
  set") gives None. A number asked in another unit or base (kHz, ms, dollars, hexadecimal) is None,
  and so is a part or property of a value (domain or path of a URL, last four digits, byte 3 of a
  block, a block numbered inside a sector).
- Never plain, always a pick: the message of a raw capture (its option is named by the reading,
  `pwm_long_high_msb`), an IQ sample count (`pairs`, then `values`), a magstripe track count, an
  NDEF record picked by number among several, and the field on a last line with no line end.
- Two readings are offered, so a stated hex form alone does not make them plain: access bytes with
  and without the user byte (`gpb_*`), an .ir address or command with and without its zero padding
  (`short_*`), a `.nfc` header's ATQA in both byte orders (`swapped_*`), a start or load address
  padded and unpadded.
- No fact at all: a Flipper field stated twice with different values, a block or page listed twice
  with different bytes, a page that is not four bytes, CAN counts when a line of the log was not
  read, the timing count of a capture longer than the reader takes, a WAV sample count when the
  header claims more frames than the file holds or the file is stereo.

## Label vocabularies likely for this category

Nothing is judged yet. The event's style is lowercase snake_case, descriptive; offer these through
`labels.pick`, never plain.

- Modulation: `ook`, `ask`, `am`, `on_off_keying`; `2fsk`, `fsk`, `fm`, `gfsk`, `msk`.
- Encoding: `pwm`, `pulse_width`, `manchester`, `differential_manchester`, `biphase`, `nrz`, `ppm`, `pulse_position`.
- Protocol (sub-GHz): `princeton`, `came`, `nice_flo`, `holtek`, `gate_tx`, `linear`, `keeloq`, `raw`, `bin_raw`; class `fixed_code`, `static_code`, `rolling_code`.
- Card type: `mifare_classic_1k`, `mifare_classic_4k`, `mifare_classic_mini`, `mifare_ultralight`, `ntag213`, `ntag215`, `ntag216`, `mifare_desfire`, `iso14443_3a`, `iso14443_4a`, `iso15693`, `felica`.
- 125 kHz: `em4100`, `hid_prox`, `h10301`, `indala`, `t5577`, `awid`; id forms `facility_code`, `card_number`.
- Keys: `default_key`, `transport_key`, `key_a`, `key_b`, `mad_key`, `ndef_key`; access `read_only`, `read_write`, `value_block`, `transport_configuration`.
- NDEF: `uri_record`, `text_record`, `smart_poster`, `mime_record`, `well_known`, `external_type`.
- Attack class: `replay_attack`, `card_cloning`, `uid_cloning`, `nested_attack`, `darkside_attack`, `relay_attack`, `jamming`, `rolljam`, `brute_force`.
- IR: `nec`, `nec_ext`, `samsung32`, `rc5`, `rc6`, `sirc`, `kaseikyo`, `raw`.
- Buses and firmware: `uart`, `i2c`, `spi`, `can`, `one_wire`; `intel_hex`, `srec`.

## Limits

- IQ files and recordings, by hand: `stego_tools.rtl433`, `multimon` (DTMF, AFSK1200, POCSAG, MORSE_CW)
  and `minimodem`, in the sandbox (`solvers/toolkits/stego_tools.py`, [stego_tools.md](stego_tools.md)).
- No demodulation beyond an OOK envelope: FSK, PSK and LoRa captures need a tool (rtl_433, inspectrum,
  URH), none of which is installed here or in the sandbox.
- A MIFARE Classic with a 7-byte UID: the UID comes from a `.nfc` header only; a bare binary dump
  gives a UID only when the 4-byte BCC holds.
- Keys are read, never recovered: no Crypto-1, no nested or darkside attack, no KeeLoq decryption.
- UART is 8N1 only, with the bit time taken from the shortest run; I2C and SPI need a header row
  with the usual column names (`scl`, `sda`; `clk`, `mosi`, `miso`, `cs`).

## Real artifacts (2026-10-08, `tests/real/test_real_rf.py`)

Run on 26 real files: Flipper firmware test files, four rtl_433 captures with rtl_433's own decode, bincopy's
firmware files, a candump log, a Vector ASC log, a MIFARE Classic 4K dump and two Huntress audio challenges.
No crash and nothing over 0.6 s. What the real files changed: the FSK modem reader (Huntress 2024
"1200 Transmissions" is now closed by the toolkit alone), pulse-distance and gap-first readings, a packet
split for captures whose gaps are many pulse widths long, the NEC reading of raw infrared, Vector ASC.
Still not read: SSTV (Huntress 2025 "Maximum Sound"), rolling codes (KeeLoq, Security+: the bits are read,
the key is not derived), PEAK `.trc` and Vector `.blf` logs, POCSAG and FLEX pagers. The record is
`docs/toolkits/real-data.md`.

Review (2026-10-08, `tests/test_tk_real_c_review.py`): a question that negates (`not`, `other`, `another`, `instead`) or does arithmetic on a
field (twice, half, sum of) is `None`: an unsure offer there would get the field's names rejected for its key.
