# Toolkit `malconfig`: configs beyond HCFG, key recovery, ransomware sets

Built 2026-10-08. Offline, no network request. Nothing of this category has been judged, so
every answer except one kind of hash is unsure (`labels.pick`) — ranked candidate values you read with `labels.show`.

| File | What it is |
| --- | --- |
| `solvers/toolkits/malconfig.py` | `signals`, `solve_set` (the runner contract), the command |
| `solvers/common/malconfig.py` | the readers (in the toolkit as `lib`); calls `solvers/binary/hcfg.py` first |
| `tests/test_tk_malconfig.py` | 216 checks on synthesized fixtures: non-malware deliveries answer `None` |

## Run first

```
.venv/bin/python solvers/toolkits/malconfig.py workspace/<id>/artifact        # or files; add --json
```

It prints one line per fact. Read it in this order:

- `MALCONFIG files=.. configs=.. decrypted=.. families=.. PARTIAL`: `PARTIAL` means the keyed search (RC4, AES,
  XOR under a literal) ran out of time on a large binary. The command allows 20 s; `solve_set` allows 0.6 s.
- `CONFIG <file> shape=.. how=.. offset=.. valid=crc32|json|ini key=.. iv=..` and its fields. `how` is the path
  through the wrappers (`base64>aes_cbc`, `utf16le>hex>hcfg:xor`). `also=N` means the same config also reads
  under another key or cipher, so key and cipher are not one fact.
- `NOTE more than one config validated`: a field is answered only when exactly one value fits it. A question
  that names its file (its artifact member, or the name in its words) is answered from that file alone.
- `NOTE-FILE`, `SET appended extension`, `DECRYPTED <file> proof=..`: a ransom note's checked addresses and the
  set. `(weak: not answered plain)` marks a text or loose proof.
- `LUA`, `AUTOIT`, `DOTNET`: constants, the marker, the `#US` strings and Redline-style pairs.

Reason to the flag from the output and submit it once via `ctf.submit.guarded_submit(...)` (or
`./csctf submit <id> <flag>`). `pick`/`candidates` return a ranked list of candidate values you read with
`labels.show`.

## The question shapes it answers

The field is read from the tail of the answer id (`sample-c2-port`), else from the question's words.

| Asked | Fact | Options offered, best first |
| --- | --- | --- |
| C2 host, port, address, URL | the config member; a part of a `host:port` or URL member | `host`/`raw`; `port`/`decimal`; `raw`, `host_port` |
| mutex, campaign, build id, version, botnet, user agent, bot token, chat id, pipe, watermark, password | the one member whose name fits | `raw`; numbers `decimal`; lists `json`, `csv` |
| sleep, jitter | the member (Cobalt Strike: settings 3 and 5) | `decimal` |
| key, IV | of the one validated reading, or of the set | `lower`, `0x_lower`, `upper`, `0x_upper` (order follows the syntax); `text` for a printable key |
| cipher or algorithm | `xor`, `rc4`, `aes_cbc`, `aes_ecb` of the one reading | `xor`, `single_byte_xor`, ...; `aes_256_cbc`, `aes_cbc`, ...; cut to the names the question lists |
| family | Cobalt Strike, NetSupport, AutoIt, Lua by their markers | `cobalt_strike`, `cobaltstrike`, ...; `netsupport`, `netsupport_rat`, ... |
| config CRC-32 | the HCFG header's | `0x_lower`, `lower`, `upper`, `decimal` |
| wallet, onion, tox id, victim id, e-mail, extension | the note (and the extension shared by the file names) | `raw`; extension `dotted`, `bare` |
| SHA-256/SHA-1/MD5 of a decrypted file | the set, a quarantine wrapper, an XOR-ed embedded PE | **plain** when the question names the file, its words say decrypted (decrypted, recovered, restored, extracted) and the proof is exact; `None` when they say the file as delivered (encrypted, before decryption, ciphertext); else `lower_hex`, unsure |

Keys are `malconfig.<field>/<shape>`: shape is `hcfg`, `json`, `json.xor`, `json.rc4`, `json.aes_cbc`, `ini.rc4`,
`cobalt_strike`, `netsupport`, `dotnet_pair`, `note`, `note.<coin>`, `set.<cipher>`. `solvers/common/labels.py`
knows five category prefixes; until `malconfig` is added to its `LANE_DIRS` the keys are filed as
`binary.malconfig_<field>/<shape>` under the `binary` prefix (the toolkit tries the first, then the second).

`None` on purpose: every question of another category (`dNN_` ids, the binary engine's "value for field ... in the
delivered evidence set", `-role`/`-attack` ids, `message`, `ANS-`, `Determine <property> for`); a field two
configs disagree on; a wallet or onion whose checksum fails; a plain JSON object for a question with no malware
words; a hash of a file that was not decrypted (that is `solvers/common/triage.py`'s).

## What validates (a candidate counts only then)

- HCFG: `hcfg.containers(others=True)`, the stored CRC-32. A CRC-valid container stands before parse-only readings.
- A JSON object that parses (non-empty; under an XOR key it must be at least 4 key lengths long and name a field),
  or key=value text in a block whose ends are known (a decoded literal).
- Searched: single-byte XOR for all keys at once; repeating XOR of 2 to 8 bytes with no crib in a file up to
  64 KB, by crib (`{"campaign"`, `{"c2"`, `{"host"`, ...) above; XOR, RC4, AES-ECB and AES-CBC under a key found
  in the file. Wrappers, three deep: base64, base64url, hex, UTF-16LE, zlib, gzip.
- Key candidates: quoted and printable literals, hex and base64 literals, 16/24/32-byte pieces between NULs, the
  head and tail of the file, MD5 and SHA-256 of a short literal. IV: zero, the 16 bytes before the block, a
  16-byte literal, the key's first 16 bytes.
- Decrypted files: `lib.proof`. Strong (the end of the file is proven too): png, zip, pdf, jpeg, gif, pe, elf,
  gzip, zlib, sqlite, json. Weak: text, `pe_loose`, `elf_loose`, `sqlite_loose`, `ole_loose`.
- Addresses: base58check, bech32 and bech32m, EIP-55, Monero, onion v3 (SHA3 checksum), tox id.

Byte cap: a file over 4 MB is searched byte by byte only in its first and last megabyte; its middle is searched
by needle (the encoded opening of an object, the HCFG magic in base64, hex or UTF-16). Over 16 MB only the HCFG
needles. 67 MB costs about 0.5 s.

## By hand (in a Python prompt)

```python
import sys; sys.path.insert(0, "solvers/toolkits"); import malconfig as tk; lib = tk.lib
data = open(path, "rb").read()
lib.scan(data)                      # every validated reading: how, offset, cipher, key, iv, config, plain, valid
lib.config(data)                    # the one reading, or None
lib.scan(data, keys=[b"s3cret"])    # with a key from elsewhere (another file, the prompt)
lib.as_hcfg(hit)                    # a reading in hcfg.find()'s shape: hcfg.answer("analysis_config_mutex", cfg)
lib.cobalt_strike(data); lib.us_strings(data); lib.dotnet(data); lib.xor_b64_pairs(strings)
lib.netsupport(text); lib.autoit(data); lib.lua_constants(data); lib.quarantine(data); lib.xor_pe(data)
lib.xor_key_from_pair(plain, cipher); lib.keystream_from_magic(cipher, "png"); lib.footer_diff([a, b, c])
lib.decrypt_set({name: bytes}, extra_keys=[key]); lib.note(text); lib.proof(plain)
tk.solve_set(questions, files, {"malconfig_any": True})    # also answers another category's questions (unsure)
```

A Binary sample whose config is not in an HCFG container (a d09 surprise): `lib.config(sample)` then
`lib.as_hcfg(hit)` gives the `cfg` that `solvers/binary/hcfg.py` `answer()` reads, so the binary engine's judged forms
(`0x` plus lowercase hex, the member's string) apply unchanged. `crc_ok` is False there: no stored CRC vouches.

## Label vocabulary to expect (lowercase snake_case, descriptive)

- cipher: `xor`, `single_byte_xor`, `repeating_xor`, `rolling_xor`, `rc4`, `aes_cbc`, `aes_256_cbc`, `aes_ecb`, `base64_xor`
- wrapper or encoding: `base64`, `hex`, `utf16le`, `zlib`, `gzip`, `none`
- family: `cobalt_strike`, `netsupport_rat`, `autoit`, `redline`, `lua_bytecode`
- storage: `overlay`, `resource`, `data_section`, `string_literal`, `appended_footer`
- ransomware: `appended_extension`, `footer_key`, `per_file_key`, `ransom_note`

## Not built, or not proven

- AutoIt: the marker, subtype and offset only. The script body is encrypted and LZSS-packed; use the sandbox.
- Cobalt Strike, quarantine wrappers, Lua 5.1 and 5.3: tested on fixtures written here from the published
  formats, never on a real file. Lua 5.4 was checked against luac 5.4.8. Windows Defender quarantine (RC4 under a
  fixed key) is not read.
- An incrementing XOR key (key+i) is read only under an HCFG header (`hcfg.py`). ChaCha, Salsa, AES-CTR and
  AES-GCM configs are not read (AES-CTR only in `decrypt_set`).
- In a large binary the keyed search is best effort inside its time budget: a key is tried only near where it
  stands (32 KB for what was written as a key, 1 KB for other strings, 4 KB for AES).

## Real artifacts (2026-10-08, `tests/real/test_real_malconfig.py`)

Run on real files only, no live malware: a real native PE (Huntress 2024 "In Plain Sight", 4.7 MB), the real
ASP.NET assembly of Huntress 2024 "Helpful Desk", and the write-up author's defanged VBScript (Huntress 2024
"Ping Me"); plus, built here from real inputs, Lua bytecode compiled by the system `luac` and a real PE
XOR-encoded under a key in the blob. No change was needed in the solver: every real file behaved as the
synthetic fixtures predicted.

- `us_strings` reads 248 #US user strings from the real .NET assembly, with no RedLine-style XOR/base64 pairs;
  a benign app, so `signals` is 0.0 with no question and no config field is invented.
- `xor_pe` recovers the real 96 KB PE byte-for-byte when it is XOR-encoded under a 2- or 8-byte key with the
  key written beside it, and finds nothing in the clean PE.
- `lua_constants` reads the string constants of real `luac` 5.4 output; a Lua chunk's constants are offered
  as the family (unsure) but are not treated as a validated config (no C2 is answered).
- The 4.7 MB PE scans in about 0.6 s (the middle is searched by needle over 4 MB), and a benign PE or a
  defanged script answers nothing.

A zip member is cached by a `path!member` source (`tests/real/fetch_c.py`). Still not exercised on a real
file: Cobalt Strike beacons, NetSupport `client32.ini`, AutoIt and quarantine wrappers (synthetic fixtures
only — no safe public real sample was used). The record is `docs/toolkits/real-data.md`.

Review (2026-10-08, `tests/test_tk_real_c_review.py`): a negated question, one about the secondary, backup or fallback value, and a count
("how many C2 servers") are `None`; each used to be offered the primary C2 under the field's own key.
