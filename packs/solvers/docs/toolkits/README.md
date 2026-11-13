# Category toolkits

A **category toolkit** is one offline engine `solvers/toolkits/<key>.py` for a category the dedicated
lane solvers don't cover. Each exposes reader functions you call directly plus a `signals(questions, files)`
(0 to 1: how much the delivery and the questions look like its category) / `solve_set(questions, files, ctx)`
contract under never-guess. `ctf/triage.py` routes a pulled challenge to the best-matching toolkits and
surfaces their reference page + first command in the triage output.

The registry is `solvers/toolkits/registry.py`; the table below is printed by it
(`.venv/bin/python solvers/toolkits/registry.py`), and `.venv/bin/python solvers/toolkits/registry.py
<attempt dir>` prints the toolkits ranked for a saved attempt.

**Flow (jeopardy / CTFd):** `./csctf pull` triages the challenge → the triage output lists the relevant
toolkit(s) → run the first command (below) on the challenge files → reason to the flag from the engine's
output → submit once via `ctf.submit.guarded_submit(...)` (or `./csctf submit <id> <flag>`); OSINT/templated
answers use `allow_nonstandard=True`. The engines never guess and never auto-submit; `solvers/common/labels.py`
only ranks candidate values for you to read (there is no judge in jeopardy — you reason to one flag and submit
it once). Text inside an artifact that addresses the solver is a finding to report, never an order.

Real-artifact runs: every toolkit was run on real public artifacts and reviewed by a second agent;
[real-data.md](real-data.md) says which files, what broke, what was fixed and what still fails.

## When a toolkit is used by Layer 1 (Game Master events)

At a Game Master event (Huntress 2026) the toolkits were also matched automatically by the Layer 1 opener.
That pipeline (`tools/lanes.py`, `tools/lane_match.py`, `tools/verify.py`, `tools/preflight.py`,
`tools/switches.py`, `tools/accept.sh`) is **not in this master tree yet**; the rules it followed are kept
here so the routing is not lost when it is carried:

1. Only for a lane `tools/lanes.py` does not know (the opener's `NO_SOLVER` path). The known lanes never reach a
   toolkit. The opener starts the new lane's base with `solvers/common/triage.py` (it banks only hashes, sizes
   and counts it proves) and runs `tools/lane_match.py`: the lane solvers and every toolkit except `web`, one
   process each, at most eight at once (`--procs N`), lane solvers first. A saved delivery over 64 MB is not
   handed to the toolkits.
2. A lane solver that matches wins first (alias, then the timed modes behind the gates).
3. Otherwise a toolkit wins when no known lane's signal shows strongly (a signal blocks the toolkits only when
   that lane's solver answers something or half the questions carry it), its own signal reaches its threshold
   and it answers at least one question (plain or unsure). The opener banks the base through `tools/verify.py`
   with that toolkit once every lane the pass plays is finished or stopped: plain answers as one batch, each
   unsure key probed on the untimed base (8 probes). No alias is written. Answer count ranks before signal. An
   exact answer-count tie has no winner unless one specialist's optional artifact-derived ownership claim names
   exactly the same answer ids and overlaps the value offered by every tied reader for every id; the report
   stores only SHA-256 identities of those values. Any different id/value, absent claim or second owner remains
   a tie. No registry-order preference exists.
4. **Clocks.** When that toolkit closed the base CORRECT with a `key.json` and replays it to exactly the key,
   with nothing `None` or unsure, in at most 1.0 s (`lanes.TOOLKIT_SOLVE_MAX`), the opener records the lane in
   `challenges/_lane_runtime.json` and plays its timed modes behind the normal gates with `tools/run.py`. A
   toolkit that does not qualify leaves the lane `NO_SOLVER` with the reason, `toolkit` and `toolkit_doc` in
   the handoff: the lane is its agent's.
5. Either way the triage map (`triage.md` beside the attempt) has a `## Toolkits` section: the best-matching
   toolkits, their reference page and the first command (the same ranking `registry.py <attempt dir>` prints).

Switches in that pipeline: `"toolkits": "off"` in `challenges/_opener.json` matched the lane solvers only;
`"newlane": "agent"` turned the whole match off; a toolkits-off environment switch did the same for a hand run
of `tools/lane_match.py`. Banking there: `tools/verify.py <base-id> solvers/toolkits/<key>.py`; a `??` answer is
unsure and probed one per request, the accepted name going to the ledger `challenges/_ledger/<prefix>.jsonl`;
before a first bank on a new category, `tools/preflight.py --replay <attempt dir> --solver
solvers/toolkits/<key>.py` shows what the toolkit offers per question.

Internal content identity is full SHA-256. This applies to dedup/cache keys and to delivery/value-scoped
candidate keys; it does not replace a protocol-defined or question-requested SHA-1 value. The collision
regression is `tests/test_toolkit_content_identity.py`.

## The toolkits

| toolkit | row | reads | first command |
| --- | --- | --- | --- |
| [`evidence_core`](evidence_core.md) | 122 | any mix of csv, JSON, JSON lines, logs (also IIS/Zeek #Fields and Apache error logs), XML, sqlite: tables, queries, times, a cross-artifact indicator index, the exactly-one question router, the bundle router across toolkits | `.venv/bin/python solvers/toolkits/evidence_core.py <attempt dir>` |
| [`memory`](memory.md) | 82 | Volatility tables (text, CSV, JSON), minidump, ELF core, LiME, crash dump; symbol-free carving; a Windows image off the clock with `--vol windows --symbols fetch` (sandbox) | `.venv/bin/python solvers/toolkits/memory.py <members>...` |
| [`network`](network.md) | 83 | pcap and pcapng in plain Python: DNS, HTTP, TLS SNI/JA3/JA4, credentials, carved files, covert channels, beacons, USB keys | `.venv/bin/python solvers/toolkits/network.py --attempt <attempt dir>` |
| [`email`](email.md) | 84 | .eml, .msg, mbox: Received chain, SPF/DKIM/DMARC, attachments, URLs, QR codes, HTML smuggling | `.venv/bin/python solvers/toolkits/email.py <file>...` |
| [`cloudlogs`](cloudlogs.md) | 85 | M365 Unified Audit Log, Entra sign-ins and audit, CloudTrail, Azure Activity, GCP audit, Okta, Kubernetes audit (JSON, JSON lines, CSV) | `.venv/bin/python solvers/toolkits/cloudlogs.py <attempt dir>/members` |
| [`windows`](windows.md) | 86 | .evtx (pyevtx-rs, python-evtx as the fallback) and event exports, registry hives and .reg, prefetch, LNK, task XML, $I, $MFT, USN; a persistence summary | `.venv/bin/python solvers/toolkits/windows.py <attempt dir>/members` |
| [`maldoc`](maldoc.md) | 87 | OLE/VBA/XLM, OOXML, RTF, PDF, OneNote, LNK, ISO/FAT/VHD, HTA/WSF (static only) | `.venv/bin/python solvers/toolkits/maldoc.py --attempt <attempt dir>` |
| [`rf`](rf.md) | 89 | Flipper .sub/.nfc/.rfid/.ir, MIFARE Classic dumps, NDEF, PWM/Manchester, IQ envelope, magstripe, EM4100/Wiegand, Intel HEX/SREC, candump, UART/I2C/SPI CSV | `.venv/bin/python solvers/toolkits/rf.py <members>...` |
| [`web`](web.md) | 90 | live-target readiness (WebClient with scope lock and VPN stop) and offline HAR/log/JWT/cookie readers; never on a clock | `.venv/bin/python solvers/toolkits/web.py <file>...` |
| [`web_evidence`](web_evidence.md) | 123 | the Web lane as files: access logs (Apache/nginx, IIS W3C, JSON lines, CSV), HAR, JWT and session cookies, source review | `.venv/bin/python solvers/toolkits/web_evidence.py <attempt dir>/members` |
| [`edr_persistence`](edr_persistence.md) | 124 | exported Sysmon/Security/PowerShell events and EDR process JSON, process tree, -EncodedCommand, persistence table with ATT&CK ids | `.venv/bin/python solvers/toolkits/edr_persistence.py <attempt dir>/members` |
| [`nix_host`](nix_host.md) | 125 | Linux and macOS host: auth logs, auditd, journald, utmp/wtmp, cron, systemd, plists, TCC, quarantine | `.venv/bin/python solvers/toolkits/nix_host.py <attempt dir>/members` |
| [`cloud_container`](cloud_container.md) | 126 | cloud and Kubernetes audit logs, docker save and OCI images (layers, deleted files), Dockerfile, Compose, manifests, Terraform state | `.venv/bin/python solvers/toolkits/cloud_container.py <attempt dir>/members` |
| [`ai_model_files`](ai_model_files.md) | 127 | pickle (symbolic walk, never unpickled), PyTorch zip, joblib, numpy, safetensors, GGUF, ONNX, Keras | `.venv/bin/python solvers/toolkits/ai_model_files.py <file>...` |
| [`agent_trace`](agent_trace.md) | 128 | agent transcripts, MCP configs, tool manifests and Python MCP server sources, RAG corpora, hidden text (tag characters, zero-width, display:none, PDF render mode 3, same-colour ANSI terminal text) | `.venv/bin/python solvers/toolkits/agent_trace.py <members dir>` |
| [`malconfig`](malconfig.md) | 129 | malware configs beyond HCFG (XOR, RC4, AES under a key in the file), family readers, ransomware sets and notes | `.venv/bin/python solvers/toolkits/malconfig.py <attempt dir>/artifact` |
| [`modern_crypto`](modern_crypto.md) | 130 | RSA from parameters, XOR and stream reuse, stated-key ciphers, JWT, ECDSA nonce reuse, ECB and generator checks | `.venv/bin/python solvers/toolkits/modern_crypto.py <members>... --budget 20` |
| [`carve_stego`](carve_stego.md) | 131 | carving, PNG/JPEG/GIF/WAV side channels, LSB, DTMF, zero-width text, QR and barcodes, small disk images, minidump and ELF core | `.venv/bin/python solvers/toolkits/carve_stego.py <files>... --extract <attempt dir>/carved` |
| [`sqlite_artifacts`](sqlite_artifacts.md) | 132 | browser and app SQLite by schema, deleted rows (WAL, journal, freelist), Chrome extensions, LevelDB | `.venv/bin/python solvers/toolkits/sqlite_artifacts.py <members folder>` |
| [`repo_supply_chain`](repo_supply_chain.md) | 133 | git/hg/darcs/svn/fossil from bytes (no VCS binary is run), npm/wheel/sdist/vsix/crx/jar/nupkg/gem, JSON hash manifests, workflows, secrets | `.venv/bin/python solvers/toolkits/repo_supply_chain.py <artifact or members folder>` |
| [`osint`](osint.md) | 158 | leads from a delivery and the questions (usernames, handles, e-mails, domains, URLs, phones, coordinates, EXIF device/GPS, hashes, dates, names, QR, language), ranked, with a search plan (leads.md); solve_set answers only what the bytes prove | `.venv/bin/python solvers/toolkits/osint.py <attempt dir>` |
| [`pwn`](pwn.md) | T-a | userland exploitation RECON: ELF arch, mitigations (NX/PIE/RELRO/canary/FORTIFY via a checksec-style header read), symbols, GOT/PLT, dangerous imports, ROP-gadget ENUMERATION (report, never executed), format-string/overflow surface; facts unsure, win-addr candidates, the flag always None; a live target is the hand tool pwn_target.py | `.venv/bin/python solvers/toolkits/pwn.py <file>...` |
| [`forensics`](forensics.md) | T-b | container/structure facts for disk/memory/capture forensics (a NARROW complement to network, memory and carve_stego): pcap/pcapng format, byte order and datalink; memory-dump format and OS; disk partition scheme (MBR/GPT), filesystem and boot signature; all unsure, payloads left to the specialists | `.venv/bin/python solvers/toolkits/forensics.py <file>...` |
| [`asn1_reader`](asn1_reader.md) | C2 | ASN.1/DER + X.509/PKCS/PEM/SSH/PGP: certificate subject/issuer/serial/validity, SHA-1/SHA-256 fingerprints, key algorithm and size, SSH and PGP key fingerprints; deterministic facts plain-eligible, interpretive unsure, private secrets and flags None | `.venv/bin/python solvers/toolkits/asn1_reader.py <file>...` |
| [`wire_decode`](wire_decode.md) | C3 | schema-less protobuf/CBOR/MessagePack/BSON wire decode: field numbers, wire types, lengths and scalar values (structural facts plain-eligible); semantic field names unsure; malformed None | `.venv/bin/python solvers/toolkits/wire_decode.py <file>...` |
| [`pcap_creds`](pcap_creds.md) | GAP-PCAP-CREDS | pcap/pcapng credential MATERIAL in plain Python (specialist ownership over network.py only for an equivalent byte-proven answer): WPA* EAPOL handshakes (hashcat 22000), NTLMSSP type2/type3 over SMB/HTTP/LDAP (netntlmv1/v2), Kerberos AS-REQ/AS-REP/TGS-REP etype 23 (krb5pa/krb5asrep/krb5tgs); the assembled hashcat line unsure, the cracked password always None | `.venv/bin/python solvers/toolkits/pcap_creds.py <capture>...` |
| [`pdf_revisions`](pdf_revisions.md) | GAP-PDF-REVISIONS | PDF incremental-revision splitter: each prior revision carved as a standalone document through the startxref/%%EOF boundaries and the /Prev xref chain (classic tables and xref streams), an object's value at revision k; the revision count plain, an author-named selection unsure, nothing rendered or run | `.venv/bin/python solvers/toolkits/pdf_revisions.py <file.pdf>...` |
| [`fs_walk`](fs_walk.md) | GAP-FS-WALK | directory-walk facts of a complete, checksum-validated filesystem image that carve_stego_fs, forensics and windows do not walk: squashfs, NTFS $MFT ($DATA incl. named :ADS, in-use flag), exFAT entry sets, JFFS2 (CRC-checked); paths/sizes/stream-names plain-eligible, path spellings unsure, a flag always None | `.venv/bin/python solvers/toolkits/fs_walk.py <image>...` |
| [`firmware_walk`](firmware_walk.md) | firmware-image-walker | firmware/flash container walker (distinct from carve_stego_fs and fs_walk): SquashFS 4.0, JFFS2 (CRC-checked), UBI/UBIFS volume map and nodes, DTB/FDT node paths and properties, U-Boot env (leading CRC32 validated first); names/sizes plain-eligible, path spellings unsure, no non-stdlib codec is run | `.venv/bin/python solvers/toolkits/firmware_walk.py <members>...` |
| [`il2cpp`](il2cpp.md) | il2cpp | Unity IL2CPP global-metadata.dat reader (magic 0xFAB11BAF): embedded string literals read byte-exact at (dataIndex, length), identifier names of the type/method/field tables from the string heap; the version and literal-table count plain, names and definition counts unsure under binary.il2cpp_*, the flag None | `.venv/bin/python solvers/toolkits/il2cpp.py <global-metadata.dat>...` |
| [`jumplist`](jumplist.md) | wave121/forensics-next | Windows Jump Lists: a bounded CFB walk of an automaticDestinations-ms (DestList MRU order, per-entry hostname/access-time/pin) with every numbered stream and a customDestinations-ms carve fed to the armed windows.lnk() (target, times, volume serial, drive type, machine id, MAC); nothing judged, so every answer is an unsure pick (format) or candidate (hypothesis, re-derived per variant) or None, the flag None | `.venv/bin/python solvers/toolkits/jumplist.py <file>...` |
| [`deser_chain`](deser_chain.md) | wave121 | passive serialized-object reader: Java serialization (magic AC ED 00 05) class-descriptor names, serialVersionUIDs, object graph; PHP serialize() objects/properties (and phar manifest metadata); .NET BinaryFormatter/NRBF type and assembly names; structural counts plain-eligible, class/type names and the gadget-chain family unsure candidates, a command/url/flag a lead; nothing is deserialized or run | `.venv/bin/python solvers/toolkits/deser_chain.py <file>...` |
| [`serial_decode`](serial_decode.md) | serial-native-blobs | language-native serialization blobs with NO instantiation (beyond deser_detect and wire_decode): Java serialization stream (AC ED), PHP serialize(), Ruby Marshal 4.8 (04 08) -> class names, field/property/ivar names, counts and primitive values read as structural facts (plain-eligible via labels.pick); a malformed or not-fully-consumed blob, a container value and the flag are None | `.venv/bin/python solvers/toolkits/serial_decode.py <file>...` |
| [`ese_reader`](ese_reader.md) | ese_reader | bounded pure-Python ESE/EDB table-ROW reader (SRUM SRUDB.dat, WebCacheV01.dat, NTDS.dit; signature 0x89abcdef): the header, the MSysObjects catalog (tables + columns) and leaf-record row values (fixed and variable columns); every fact unsure under forensics.ese_* (deterministic-reader picks; row values delivery-scoped candidates), malformed/truncated => None, flag None; agent's/triage's, never a match | `.venv/bin/python solvers/toolkits/ese_reader.py <SRUDB.dat|WebCacheV01.dat|NTDS.dit|*.edb>...` |
| [`blockchain`](blockchain.md) | blockchain | READ-ONLY, artifact-only EVM and Bitcoin facts (nothing executed, no RPC): raw EVM tx (RLP; sender by ecrecover, to/value/nonce/gas/chain id/selector/hash), 4-byte selectors and ABI calldata/event decode, EVM bytecode dispatch table + constructor/runtime split + solc version + PUSH strings, EIP-55 checksum, address from a provided public key, base58check and bech32/bech32m addresses, Bitcoin raw tx; every answer an unsure pick under blockchain.*, a private key, seed or flag always None | `.venv/bin/python solvers/toolkits/blockchain.py <file>...` |

Hand tools in the same folder (readers you call directly; no `solve_set`, never auto-matched, never on a
clock): `chat_target.py` ([reference](chat_target.md)) is a logged client for a live chatbot/agent endpoint,
built from the assigned URL or a `challenges/_targets.json` entry (`tools/target.py` writes that file) and held
to the shared target policy (never the event platform; a public host only when the event config allows it);
`stego_tools.py` ([reference](stego_tools.md)) is the sandbox side of `carve_stego`, one function per program
(runs them in `csctf-sandbox:2`); `pwn_target.py` ([reference](pwn.md)) is the RECON-only raw-TCP/netcat stub
for a live pwn target (connect, read a banner, send a caller-supplied probe only; same target policy and
registry as `chat_target.py`, never auto-exploits, the flag is the player's); `classical.py`
([in `modern_crypto.md`](modern_crypto.md)) is the classical half of crypto
(Caesar/Vigenère/substitution/transposition/Morse/Baconian, encoding chains, hash/HMAC structure, RSA
detection), imported by `modern_crypto`. `carve_stego_fs.py` (file systems and dumps) belongs to
`carve_stego`. `evidence_core`, `agent_trace`, `ai_model_files`, `cloud_container`, `malconfig`,
`modern_crypto`, `nix_host`, `repo_supply_chain` and `web_evidence` keep their readers (or a loader) in
`solvers/common/` under the same name.

## Real-artifact tests

`tests/real/test_*.py` run each toolkit on real public files. They need the cache
`<main checkout>/challenges/_realdata/` (untracked, never committed; `$CTF_REALDATA` overrides it in the
fetch scripts), which `tests/real/fetch_a.py`, `fetch_b.py`, `fetch_c.py`, `fetch_d.py` and `fetch_cab.py` fill
**by hand, never during a run** (`fetch_a.py --check` says what is present with no network). Without the cache
a test prints a SKIP line: that is "not run", not a pass. `windows` reads .evtx through pyevtx-rs from
`<venv>/lib/huntress-side` (`$CTF_SIDE` overrides it; about 30,000 records a second) and falls back to
python-evtx (about 900) when that folder is absent.

## Notes for solving

- Read the triage output first, then the reference page of the toolkit it names, then run the first command.
- Reason to the flag from the engine's output and submit once through the guarded path
  (`ctf.submit.guarded_submit` / `./csctf submit`). A `None` is the toolkit declining to prove a value
  (two candidates, a file not read whole, a question it can't fully read) — don't guess; use the ranked
  candidates it does surface, or escalate to the player.
- A bundle of several categories: run `evidence_core.py`; its bundle router asks every toolkit and answers
  a question only when exactly one of them proves it.
- Heavy / untrusted tooling (tshark, Volatility, olevba, binwalk, and the stego/OCR/audio/PDF/carving/radio/
  disassembly programs — steghide, stegseek, zsteg, outguess, tesseract, sstv, multimon-ng, minimodem,
  rtl_433, foremost, sleuthkit, qpdf, radare2) runs **only** inside the Docker sandbox, via `tools/sandbox.py`
  or `solvers/toolkits/stego_tools.py` ([reference](stego_tools.md)) — never on the host.
- A live target is the squad's assigned one only; never scan, flood, or touch anything else.
  `tools/target.py get <challenge>` gives the address filed for it; ask the main thread for
  `tools/vpn.py ensure <address>`. `web.target_for(challenge, attempt)`, `chat_target.py` and `pwn_target.py`
  read the same file (`challenges/_targets.json`); `chat_target.py policy` prints the target policy in force.

## Label prefixes

`solvers/common/labels.py` knows one prefix per toolkit (`TOOLKIT_PREFIXES`); each has a seed folder of its
own, `solvers/toolkits/seeds/<prefix>/conventions.json`, made by its first `labels.py promote <prefix>`.
