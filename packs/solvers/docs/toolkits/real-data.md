# Real artifacts: what the toolkits did on real files (round 2, 2026-10-08)

Round 1 built twenty toolkits on synthetic fixtures. Round 2 ran each of them on real public files (the Huntress
CTF 2024 and 2025 write-up repositories, the test corpora of parsing libraries and tools, public log sets), fixed
what broke, and then had a second agent attack every fix. This page is the four groups' records joined, one
section per group, as the groups wrote them. Nothing here made a Game Master request, nothing downloaded was
run, and no live malware was fetched.

## Read this first

- **The cache** is `challenges/_realdata/<toolkit>/` in the main checkout (untracked, never committed, about
  420 MB), each folder with a `SOURCES.md`. It is filled by hand with `tests/real/fetch_a.py`, `fetch_b.py`,
  `fetch_c.py` and `fetch_d.py` (pinned SHA-256; `--check` makes no request where the fetcher has it).
  `$CTF_REALDATA` names another place.
- **The tests** are `tests/real/test_*.py`. Each prints SKIP and exits 0 without the cache. A full
  `tools/accept.sh` runs them together as item 3r; `--quick` runs only `tests/real/test_fixes_a.py`, which needs
  no cache. The fixes are also tested with no cache on small inputs of the real files' shape:
  `tests/real/test_fixes_a.py`, `tests/real/test_review_a.py`, `tests/real/test_real_review_b.py` (46 of its 78
  checks), `tests/test_tk_real_c_review.py`, `tests/test_tk_real_round_d.py`, `tests/test_tk_real_round_d_review.py`.
- **Past challenges the system now closes alone** (the delivery saved as an attempt of an unknown lane, then
  triage, `tools/lane_match.py`, the winner's answer beside the write-up's flag): 2024 Echo Chamber, Keyboard
  Junkie, Zimmer Down, Hidden Streams, Ancient Fossil, The Void, 1200 Transmissions, Strive Marish (the offline
  RSA layer); 2025 Bussing Around, Trashcan, Darcy, QRception, the crypto layer of Angler. "Alone" means one base
  probe: nearly every flag is offered unsure, because nothing of these categories has been judged in this event.
  Most of these were NOT closed before the round: the readers were written after reading these very files, so
  the list is not a hit rate for Day 9. A new trick is a new reader.
- **With an agent**: Nightmare on Hunt Street, Little Shop of Hashes, Webshellz, MOVEable, Emotional,
  Unbelievable, Cattle, Mystery, No need for Brutus, Backdoored Splunk II. **Not closed**: anything whose flag
  is on a live host (Follow The Money, Ran Somewhere, Angler's tenant, Malibu), SSTV (Maximum Sound: now the
  agent's through `stego_tools.py`).
- **What every group found**: each toolkit had at least one wrong plain reading or a miss on real data that no
  synthetic fixture showed, and each review then found more by asking questions with a negation, a rank or a
  qualifier ("not", "first", "other than", "in the bucket policy"). The fixes turn those into `None` or unsure.
  All of these toolkits are still rule-based readers of free question text: expect fewer plain answers than
  round 1 implied, more base probes, and more wrong plain answers of the same kind on wordings nobody tried.
  Before a first bank on a new category, read what the toolkit offers per question
  (`tools/preflight.py --replay <attempt dir> --solver solvers/toolkits/<key>.py`).
- **`cloud_container` is back in the match** (it was taken out before round 1 was armed): the builder and the
  reviewer both say "yes, as a base-only candidate", on thin evidence (group b below, "Fit for the match?").
- **Not verified on real files**: a maldoc or memory challenge drill, a 64-bit Windows or Linux memory image, a
  real Chroma/LlamaIndex store, real OCI layouts, binary journald, off-air radio recordings. Question wordings
  are invented in this event's style; nothing was judged.

| group | toolkits | builder branch | review branch |
| --- | --- | --- | --- |
| a | network, email, maldoc, windows, memory | `day9b/real-a` | `day9b/real-a-r` |
| b | cloudlogs, cloud_container, edr_persistence, nix_host, sqlite_artifacts | `day9b/real-b` | `day9b/real-b-r` |
| c | web_evidence, web, malconfig, modern_crypto, carve_stego, rf | `day9b/real-c` | `day9b/real-c-r` |
| d | ai_model_files, agent_trace, repo_supply_chain, evidence_core, classical | `day9b/real-d` | `day9b/real-d-r` |


---

## Real artifacts, group a: network, email, maldoc, windows, memory

Built 2026-10-08 on the branch `day9b/real-a`. Round 1's toolkit fixtures were all synthetic; this page says what
happened when the five toolkits of this group read real files, what was fixed, and what still fails.

### The cache and the tests

```bash
PY=.venv/bin/python
$PY tests/real/fetch_a.py            # fills challenges/_realdata/<kit>/ (361 files, 130 MB; every file pinned by sha256)
$PY tests/real/fetch_a.py --big      # also the 512 MB memory image (a 180 MB download)
$PY tests/real/fetch_a.py --check    # no network: what is present and whether it matches
$PY tests/real/run_a.py              # the seven tests below, one line each (about 50 s)
```

The cache is untracked (`challenges/` is ignored) and each folder has a `SOURCES.md` (file, bytes, sha256, URL).
Nothing in it is run, by a test or a tool. The two write-up repositories are cloned shallow under
`challenges/_realdata/repos/`.

| test | needs the cache | what it checks | checks, time |
| --- | --- | --- | --- |
| `tests/real/test_fixes_a.py` | no | every fix below on a small built-here case | 28, under 1 s |
| `tests/real/test_real_network.py` | yes | 20 captures against tshark's readings | 86, 1 s |
| `tests/real/test_real_email.py` | yes | 33 mails against mail-parser, extract-msg and the raw base64 | 37, 1 s |
| `tests/real/test_real_maldoc.py` | yes | 44 documents against olevba, msodde, oleobj, rtfobj, pdfminer, LnkParse3 | 64, 1 s |
| `tests/real/test_real_windows.py` | yes | 174 artifacts against a second evtx parser, regipy, Zimmerman's values, LnkParse3 | 150, 21 s |
| `tests/real/test_real_memory.py` | partly | real Volatility tables (tracked), 11 dumps, the 512 MB image against Volatility | 40, 3 s |
| `tests/real/test_real_drill_a.py` | yes | ten challenges through triage, `lane_match.py` and the matched toolkit | 31, 19 s |

A test whose cache folder is absent prints one SKIP line and exits 0. `CTF_TK_LIVE=1` with the sandbox up
reruns tshark (packet counts), olevba and Volatility; the expected values in the tests were read that way on
2026-10-08.

### Drills: 2024 and 2025 challenges with a public file and a public flag

What the opener does for a new lane, with no Game Master: the file saved as a base attempt, `triage.py`,
`tools/lane_match.py` (five lane solvers and the toolkits), then the winner's answers.

| year | challenge | category | delivered | triage's first toolkits | lane_match winner | per question | result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2024 | Echo Chamber | network | `echo_chamber.pcap` | network | toolkit:network | `?` | alone |
| 2024 | Keyboard Junkie | network | `keyboard_junkie` | network | toolkit:network | `?` | alone |
| 2025 | Bussing Around | network | `bussing_around.pcapng` | network | toolkit:network | `?` | alone |
| 2024 | Zimmer Down | windows | `ntuser.dat` | windows | toolkit:windows | `?` | alone |
| 2024 | Hidden Streams | windows | `Challenge.zip` | windows | toolkit:windows | `?` | alone |
| 2025 | Trashcan | windows | `trashcan.zip` | windows | toolkit:windows | `?` | alone |
| 2024 | Nightmare on Hunt Street | windows | `logs-parts1-5.zip` | windows, evidence_core | toolkit:windows | `-?---` | with agent |
| 2024 | Little Shop of Hashes | windows | `little_shop_of_hashes_logs.zip` | windows, evidence_core | - | `-----` | with agent |
| 2025 | Follow The Money | email | `follow_the_money.zip` | email | - | `-` | no |
| 2024 | Ran Somewhere | email | `ran_somewhere.eml` | email | - | `-` | no |

`=` plain and right, `?` unsure with the right value first, `~` unsure with another value first, `x` plain and
wrong, `-` not answered. No answer in any drill is plain and wrong.

Read the table with these in mind:

- **"alone" means one base probe.** Every flag is offered unsure, so `tools/verify.py` sends its first option on
  the untimed base. Nothing of these categories has been judged in this event.
- **Six of the six "alone" drills were not alone before today.** Echo Chamber (the `ping -p` layout), Bussing
  Around (bits in Modbus writes, a zip whose comment states its password), Zimmer Down (a base62 name in
  RecentDocs), Hidden Streams (the Sysmon 15 `Contents` field), Trashcan (117 `$I` files, sizes as characters)
  and Keyboard Junkie's bare "What is the flag?" were closed by readers written after reading these very files.
  That is the purpose of the exercise, and also the reason not to read the table as a hit rate for Day 9: a new
  trick is a new reader.
- **The question is mine where the challenge had none.** The flag challenges are asked "What is the flag?"; this
  event asks for facts in its own wording. Nightmare and Little Shop are asked their authors' five questions each.
- **Nightmare on Hunt Street** (1 of 5 offered): the 4625 count (32) is offered for "brute-forced"; "the attacker's
  IP", "the offensive security tool" and "enumeration commands" are a person's reading (the triage shows the
  failed logons' source 10.1.1.42, the PSEXESVC service and the `net` command lines); the password question has
  two candidates in the logs (`net user susan_admin ... /add` was run with `SusanIsStrong123` and later with
  `Susan123!`), so it is None, as the contract says. The write-up's accepted flag was the first.
- **Little Shop of Hashes** (0 of 5, no winner): two hosts, questions about intent ("the service the attacker ran
  and stopped", "how many accounts were compromised"). The toolkit matches nothing because it answers nothing;
  the agent gets the triage map with `windows` first.
- **Follow The Money, Ran Somewhere**: the flag is on a web site the mail leads to. The toolkit shows the lead
  (the look-alike link `evergatetltle.netlify.app` in mail 5; the hex-named attachments) and answers nothing.
- Not drilled: neither repository holds a malicious document or a memory image, so `maldoc` and `memory` have no
  challenge drill. 2024 Palimpsest's event logs are in a zip whose password no write-up states; it was not opened.

### network

Files: three challenge captures (Echo Chamber, Keyboard Junkie, Bussing Around) and 17 public samples (Wireshark's
telnet, smtp, dhcp, dns, TLS with an embedded key log, brotli; dpkt's http and dns; scapy's http, http/2, TLS, ssh,
pcapng). Truth: tshark in the sandbox (`frame.number`, `dns.qry.name`, `http.request.*`, `http.response.code`,
`tls.handshake.extensions_server_name`, `tls.handshake.ja3`, `--export-objects http`, `telnet.data`,
`dhcp.*`, `smtp.auth.*`, `ssh.protocol`), and the write-ups' flags.

Worked as built: packet counts (20 of 20), DNS names, HTTP requests and status codes, SNI and JA3, carved HTTP
bodies (the same SHA-256 as tshark's exported objects, a brotli body included), Telnet and SMTP credentials, USB
keyboard text, the pcapng reader, plain packet counts.

Fixed (each also in `tests/real/test_fixes_a.py`): the `ping -p` payload layout and binary covert channels
(`hidden_blobs`); Ctrl chords typed as letters; a TCP keep-alive byte read as stream data; reverse lookups and
`_service` names shown as a DNS tunnel, an SPF record offered as a hidden message; a record type named in a
question answered instead of the domain; a quoted-printable mail attachment's hash given plain (it is the
mail's rendering; now unsure); the SSH banner when the client spoke first. New readers: `modbus_series`,
`describe_blob`, `flags`, a DHCP client's address and MAC, Telnet commands, the SSH banner, echo-request counts.

Still fails or is not read: TLS decryption (the embedded key log is reported; tshark in the sandbox decrypts),
HTTP/2, QUIC, SMB, Kerberos; "which host was requested first" is read as an address question and left open; a
zip in a covert channel is opened only with no password or the one its own comment states.

### email

Files: Follow The Money (five mails), Ran Somewhere, 14 mail-parser test mails (real spam, malformed mails, an
Outlook `.msg`), four extract-msg examples, nine CPython test messages. Truth: mail-parser's readings; the base64
block of an attachment cut from the raw mail with no MIME parser; the three files the Ran Somewhere author saved;
extract-msg for `.msg`.

Worked as built: every mail loads; subjects, Received chains, dates, Message-IDs; attachment bytes (same SHA-256
as the raw base64 and as the write-up author's files); `.msg` subjects and attachments; counts are plain only
when every reading of "attachment" agrees (an inline logo makes it unsure).

Fixed: the sender or recipient of four real mails was no answer at all (an address as display name, an address
written as an encoded word); a comma inside an encoded display name split one sender into two; raw UTF-8 in a
`To` header came out as surrogates and a Cyrillic file name as U+FFFD; a `message/delivery-status` attachment had
no name and no size. New: `lookalikes`, the target of a link named by its text.

Still fails: OSINT (by design); a look-alike of a brand the mail never names; two look-alike pairs in one mail
leave the question open (Follow The Money mail 5 has two: the bank's own site is one edit from its mail domain);
TNEF, S/MIME, `.pst`.

### maldoc

Files: 29 oletools test documents (VBA in doc, xls, ppt; Excel 4 macros in xls, xlsm, xlsb, SYLK; DDE in docx,
docm, xlsx, CSV, 2003 XML; embedded packages; encrypted workbooks; RTF), eight pypdf sample PDFs, seven LnkParse3
shortcuts. Truth: olevba, msodde, oleobj and rtfobj in the sandbox; pdfminer.six; LnkParse3. No real malware was
downloaded: these are the tools' own benign test files.

Worked as built: VBA and Excel 4 macros in Word and Excel files (an xlsm macro sheet olevba itself misses),
Word DDE fields, embedded objects in doc, docx and xls, external relationships, RTF objects, PDF page counts,
encryption and embedded files, encrypted packages opened with Excel's built-in password.

Fixed: **a .ppt with a VBA macro read `has_macros: False`** (its project is a compressed storage inside the
PowerPoint stream), and its embedded package was not seen; an encrypted workbook's macros did not make the file's
`has_macros` true, and "is it encrypted" was None because wrapper and content disagreed; DDE in an xlsx link, a
CSV, SYLK and 2003 XML was not read (three of those files were kind `other`); the padded shortcut was "not fully
read"; "the SHA-256 of the embedded file calc.lnk" gave the hash of the storage around it; "the class name of
the embedded object" gave a payload name.

Still fails: xlsb binary parts (macros unknown, said so), VBA p-code without source, a password that is not
known (three oletools zips are encrypted with a password that is neither `infected` nor stored: reported, not
guessed), OneNote and ISO (no real sample was fetched; synthetic only).

### windows

Files: Zimmer Down's NTUSER.DAT, Hidden Streams' Sysmon.evtx, the nine logs of Nightmare on Hunt Street and Little
Shop of Hashes, Trashcan's 195 files (117 `$I` records and the 78 `$R` contents), five python-evtx logs, nine EVTX-ATTACK-SAMPLES logs, ten regipy hives
(NTUSER, SYSTEM of Windows 7 and 10, SOFTWARE, SAM, SECURITY, UsrClass, Amcache, BCD), ten prefetch files of six
Windows versions, seven shortcuts, a 13 MB `$MFT` and four single records. Truth: a second evtx parser (below);
regipy; the values Eric Zimmerman's own tests assert; LnkParse3; a count of FILE entries; the write-ups' flags.

Worked as built: the hive readers compared with regipy agreed (Run keys, UserAssist, RecentDocs counts, typed
paths, Run dialog, computer name, time zone, USBSTOR, SAM users, Amcache paths; shimcache of Windows 7 and 10 parsed
to plausible rows and was not compared); prefetch versions 17, 23, 26 and 30
(hash, run count, last run to the 100 ns, file list: Zimmerman's values); 13,068 MFT records in 0.09 s; `$I` files;
event counts by id and logon type.

Fixed or added: **event logs took 5 s for 5 MB** and their values were python-evtx's, not Windows' (see
`windows.md`, "Two event-log parsers"): pyevtx-rs first, both paths normalised, exact times; **a cleared log's
records** recovered apart (`evtx_slack`); **117 `$I` files became 39 artifacts** (files with equal bytes were
dropped); `findings` (flags, stream contents, `net user` passwords, Recycle Bin sizes); RecentDocs and decoded
names; shortcuts with no LinkInfo had no target, a padded one was misread; ten empty Amcache rows from a user
hive; a log's file name taken for a value the question quotes; a distinct count given plain though `-` values
were dropped from it.

Still fails: questions about intent (attacker, compromised, lateral movement technique) are the agent's; XP `.evt`
logs, SRUM, Jump Lists; shimcache of XP; service counts are of keys with an image path (682 of 737 keys in a real
SYSTEM hive), so "how many services" is not a count to trust.

**pyevtx-rs is installed in `.venv/lib/huntress-side/`, not in site-packages.** `uv pip install evtx` into the venv
overwrote python-evtx's `Evtx/__init__.py` (one folder on a case-insensitive disk); it was uninstalled and
python-evtx 0.8.1 reinstalled within a minute, and the module is now loaded by path from its own folder. Without
that folder everything works through python-evtx, slower (`tests/real/test_real_windows.py` passes both ways;
`CTF_EVTX=python` forces it).

### memory

Files: eight rust-minidump test dumps (Windows, Linux and macOS minidumps, three damaged ones), three pyelftools
cores (64-bit and 32-bit), Volatility's public test image `win-xp-laptop-2005-06-25.img` (512 MB), and that image's
real Volatility 3 output (tracked: `tests/real/data_a/vol3-xp-laptop/`). Truth: the minidump stream directory read
with struct in the test; pyelftools; Volatility 3 in the sandbox.

Worked as built: minidump process, PID, create time, build and modules; 64-bit cores; real `vol -r json` tables
as a delivery (names, PIDs, parents, command lines, malfind regions, build, capture time; "how many processes"
is None when pslist and psscan disagree); damaged dumps answer nothing; saved tables are found again by the
image's fingerprint in 0.25 s.

Fixed: **the carver's output on a real image was 97 percent junk** (2,300 records for 62 processes; no parent,
no create time): it now asks for the object's dispatcher header and pool tag and returns exactly the records
Volatility confirms, with parents and create times; Volatility's "Required memory at 0x10 is not valid" was
offered as System's command line; 32-bit cores were not read. Added: **Windows plugins in the offline sandbox**
(`--symbols fetch`: the kernel's one symbol file, about 160 KB, read out of Volatility's pack by HTTP range).

Still fails or unverified: no real 64-bit Windows image and no real Linux image was read (the Linux carver is
proven on synthetic records only); `solve_set` carves only the first 16 MB of a raw image, so a large image gives
nothing until `--vol` has saved its tables; `windows.netscan` and `netstat` do not support XP; a kernel missing
from the symbol pack needs `--where venv --online`.

### Review (2026-10-08, branch `day9b/real-a-r`, `tests/real/test_review_a.py`)

An adversarial pass over this work: 7,000 runs of `signals` and `solve_set` on cut, bit-flipped, zero-filled and
doubled copies of the real files (no crash, no hang; a damaged log that pyevtx-rs refuses goes to python-evtx and
takes 2 to 5 s untimed, 1.2 s at most on a clock), questions that narrow, qualify or negate what each new
reader matches, large built inputs, and the plain answers of the base commit against this branch on every real
file. Found and fixed, each with a check in `tests/real/test_review_a.py` (32 checks, no cache needed for 28):

| toolkit | what was wrong | now |
| --- | --- | --- |
| maldoc | "Does the document NOT contain macros? (yes or no)" answered `yes`, plain | a negated yes/no question is None |
| maldoc | oletools' real `encrypted.doc` (FibBase.fEncrypted) read as not encrypted | `encrypted` true; nothing said of its macros |
| maldoc | a Markdown list line, a shell pipe, a batch `!var!` line made a text file `csv_dde` | the service must be a program or the topic quoted |
| maldoc | a 4 MB .ppt whose stream holds 64 compressed storages asked for 5 GB and 17 s | 16 storages and 64 MB in all, the same storage once |
| windows | every question ran the scan of every event value; two logs in turn ran it each time (12 questions, 9 s; the timed budget is 2.5 s) | read only for flag, password and stream questions, kept per group, stopped by the clock (0.26 s) |
| windows | a log cut inside a chunk counted as whole, plain (a real one: "448 events", plain) | `evtx_cut`: a part, no plain count |
| windows | the same log under two names counted twice (offered 66 for 33) | one artifact; `$I`, shortcuts and prefetch stay per name |
| windows | a shortcut target read from the item list alone could be plain (8.3 names) | offered, never plain |
| windows | `net user x * /add` gave `*`; the second `net user` of a line was not read | both fixed |
| windows | the hex rule rewrote a provider's string and pyevtx-rs output | python-evtx's lowercase padding only |
| windows | a Rust panic (not an `Exception`) would end the set | python-evtx takes the log |
| network | flag, echo count, DHCP address, Telnet command, SSH banner offered for questions about something else | None (the list is in `network.md`) |
| email | the look-alike domain offered for "which is NOT" and for its registrar | None |
| email | every pair of a mail's domain labels compared (800 domains: 5 s) | over 150 labels, against the parties' own domains only (5,000: 1.7 s) |
| email, maldoc, network | three plain answers to questions that negate or exclude: "the size in bytes of the email without the attachment" (the attachment's size), "how many pages does the PDF not have", "what is not the SHA-256 of download.html" | `_negates()`: such a question is offered, never plain; "do not include the 0x prefix" is a format instruction and changes nothing |

Not changed, and to know: the python-evtx fallback still writes `True`, base64 and its own time form inside
event data (9,657 real events compared value by value; the list is in `windows.md`). The email toolkit answers a
quoted-printable text attachment's hash plain where the network toolkit offers it unsure. A network key such as
`network.flag/only` is shared by every question that reaches it, so an accepted method answers the next such
question plain: the guards above are what keeps a question about the flag from reaching it.

### What to take from this for 09:00

- A capture, a mail, an Office file, a hive, an event log or a minidump of ordinary shape is read correctly; that
  is now checked against an independent tool on 283 real files, not assumed.
- Every one of the five toolkits had at least one plain wrong reading or a crash-free miss on real data that no
  synthetic fixture showed (the largest: 2,300 carved "processes", `has_macros: False` on a macro .ppt, four mails
  with no sender, 78 of 117 Recycle Bin files dropped, 5 s per 5 MB of event log).
- The toolkits of the other groups have had the same treatment or not as their own pages say; this page speaks
  for these five only.


---

## Real artifacts, group b: cloudlogs, cloud_container, edr_persistence, nix_host, sqlite_artifacts

Run on 2026-10-08, the day before Day 9. Round 1 built these five toolkits on synthetic fixtures; this pass ran
them on 199 real files and fixed what broke. Nothing here made a Game Master request.

```bash
.venv/bin/python tests/real/fetch_b.py                    # fill challenges/_realdata/ (sha256-checked; --check verifies offline)
.venv/bin/python tests/real/test_real_cloud_container.py  # 142 checks
.venv/bin/python tests/real/test_real_cloudlogs.py        # 56
.venv/bin/python tests/real/test_real_edr_persistence.py  # 75
.venv/bin/python tests/real/test_real_nix_host.py         # 58
.venv/bin/python tests/real/test_real_sqlite_artifacts.py # 46
.venv/bin/python tests/real/test_real_drills_b.py         # 21: triage.py, then the toolkit, then the answer
.venv/bin/python tests/real/test_real_review_b.py         # 78: the adversarial review's findings (46 run without the cache)
```

Each test SKIPs when the cache is absent. The cache is `challenges/_realdata/<toolkit>/` (untracked), each folder
with a `SOURCES.md` (file, bytes, sha256, URL). The manifest is `tests/real/manifest_b.json`. The two write-up
repositories must be under `challenges/_realdata/repos/` first (the fetcher copies challenge files out of them).
An expected value in a test is recounted there with `json`, `csv`, `re`, `sqlite3`, `plistlib` or `ElementTree`,
or is a write-up's stated answer; none comes from the toolkit's own readers.

### Sources

| Source | What | Used by |
| --- | --- | --- |
| Invictus IR `aws_dataset` | 55 CloudTrail files, 2,900 events of a Stratus Red Team run | cloud_container, cloudlogs |
| Invictus IR `o365_dataset` | a 38 MB Unified Audit Log CSV of a simulated BEC (7z, opened in the sandbox) | cloudlogs |
| OTRF Security-Datasets | CloudTrail of an S3 exfiltration; NXLog JSON of Sysmon, Security and PowerShell events; an auditd record | all but sqlite |
| Elastic beats test logs | CloudTrail, Azure Monitor sign-in, audit and activity, GCP, Management Activity API, Okta; auth and secure logs, auditd, wtmp, btmp, a journal export | cloudlogs, cloud_container, nix_host |
| plaso test data | lookup-events rows, Azure CLI activity log; utmp, sudo and cron syslog, history, plists, TCC, quarantine; Chrome, Firefox, Safari, iMessage, a WAL pair | all |
| falco 0.30.0 traces | 13 Kubernetes audit events | cloud_container, cloudlogs |
| go-containerregistry, Terraform | `docker save` tars (a whiteout, an overwrite, docker 25's OCI blobs), five states | cloud_container |
| loghub | 2,000 lines each of a real sshd log and a 2005 RHEL messages log | nix_host |
| dfindexeddb | LevelDB folders ("100k keys delete"), IndexedDB | sqlite_artifacts |
| Huntress CTF 2024 and 2025 write-up repos | Ancient Fossil, Nightmare on Hunt Street, Little Shop of Hashes, Webshellz | sqlite_artifacts, edr_persistence |

No real artifact was found for: a WhatsApp msgstore.db, a CRX file, an Autoruns CSV, a `.reg` export, an OCI layout
with its blobs, a multi-megabyte Entra sign-in export, a binary journald file. Those readers are still checked on
synthetic fixtures only.

### cloud_container

Files: the two CloudTrail sets, lookup-events rows, both Azure activity spellings, 13 Kubernetes audit events, six
image tars, five Terraform states. Every file under 0.2 s.

Wrong plain answers found on real CloudTrail, each fixed and asserted (`AWS_PLAIN`, `AWS_NEVER_PLAIN`):

| Question | Was | Now |
| --- | --- | --- |
| How many console logins used MFA? | 2 (MFAUsed never read) | 1; `without MFA` reads too; any other MFA wording is None |
| Which user is the access key AKIA...F4OD for? | the user who made it | the user it was made for |
| What is the ARN of the user malicious-iam-user? | the caller's ARN | that user's own ARN (from CreateUser's response) |
| How many events were made by IAM users / by assumed roles? | 2900 / 49 | None: a class of actors is no selection |
| How many different users made requests? / How many events have an error? | 2900 / 2900 | None / 300 |
| How many failed console logins are there? (none) | 0 | None: a count of zero is never answered |
| How many distinct source IP addresses? | 16 | unsure: 7 addresses, 16 values (CloudTrail writes service names there) |
| How many times was a role assumed? | 49 | unsure: 36 that worked, 49 calls |
| Who stopped logging? / Which trail was stopped? (every StopLogging failed) | plain | unsure `attempted_only:` |
| What password is stored in the state? (an attribute is named `what`) | 0 | None |

Also fixed: `aws cloudtrail lookup-events` rows and the Azure CLI activity log were not read; a logstash CloudTrail
record's time (`@timestamp`); a v4 Terraform state's `attributes_flat`; Entra sign-in and audit records in the Azure
Monitor envelope were claimed as Azure activity (signal 0.7) and are now left to `cloudlogs` (signal 0).

Blind rounds after the fixes (questions written before looking at the answers): 110 questions on the two CloudTrail
sets gave 45 plain answers, 0 wrong. The first two rounds, before the fixes, had 7 wrong plain answers in 138.

**Fit for the match?** Yes, as a base-only candidate like every toolkit, with this said plainly: it is still a
rule-based reader of free question text, two clean blind rounds are thin evidence, and on a cloud log lane it
competes with `cloudlogs` (lane_match takes whichever answers more). A wrong plain answer on an untimed base costs
requests, not points. The switch is `"match": True` for `cloud_container` in `solvers/toolkits/registry.py` and the
matching lines of `tests/test_toolkit_registry.py`; this branch does not change either file.

Still failing or not built: a count over a class of actors is None rather than answered; "most requests" is not
ranked here (`cloudlogs` does); GCP logs that mix audit and other entries are cut whole; no real OCI layout, Compose
file or Kubernetes manifest was tried.

### cloudlogs

Files: the Unified Audit Log (38 MB: load 0.7 s, 17 questions 0.8 s), both CloudTrail sets, 12 small samples of
every source it names.

- **Repeated records.** The real export holds 9,611 rows and 5,373 distinct records; beats' own sample repeats 33 of
  100. Every count was plain and counted rows (New-InboxRule: 6 for 4). A record with the same id and the same
  fields is now read once, and a count over such a file is unsure: `distinct_records`, `rows`.
- **A rule by its name or its forwarding address** ("the inbox rule Financial Reporting", "the rule that forwards
  to korstiaan@...") gave None; both are read now.
- "by IAM users" counted every event and "by assumed roles" counted AssumeRole calls: None now. A user named like
  the question's own words (`malicious-iam-user`) sent the question to the suspicious sign-in rules; such names
  are literals now.
- The Azure CLI activity log was not read; lookup-events rows were read but invisible to `signals()`.
- A zero is no longer offered as an option of a distinct count.

Still failing: "which application did the user consent to" with 13 apps, "which user was added to the Helpdesk
Administrator role", keywords of a named rule when the question's verb is outside the vocabulary. The suspicious
sign-in heuristics name three different addresses on the BEC log; they stay unsure, as designed.

### edr_persistence

Files: XML exports of three CTF event logs, eight OTRF NXLog JSON sets (0.2 to 5.6 MB, all under 0.4 s).

- **The export itself**: the Nightmare on Hunt Street Security.evtx has a stale header (1 chunk) and 16 chunks.
  python-evtx by the header gives 97 events; `fetch_b.py` walks every chunk and gives 1,249. Anything that reads
  that file by its header undercounts; the `windows` toolkit (group a) should be checked for the same.
- "What command line created the user susan_admin?" was answered `susan_admin`: None now.
- A program named by its full path (`C:\ProgramData\svchost.exe` beside the real one) was no token: read now.
- The process tree showed the web shell's children as roots; a root now shows the parent its event names (w3wp.exe).
- A 4698's `TaskContent` arrives XML-escaped in NXLog JSON: the task's command, author and trigger were lost.
- Sysmon 19/20 values are written ` "text"`: answers carried a leading quote and `&lt;blah&gt;`.
- "How many times was the compromised account brute-forced?" is a one-option pick (32, the write-up's answer).
- A Security and PowerShell export had one mark in its first 64 KiB (signal 0.2): more marks.

Still failing: questions of judgement (the tool's name, the lateral movement technique, "how many accounts were
compromised"), a password inside a command line, a file created by a named program, binary `.evtx` (row 86).

### nix_host

Files: four auth logs, eleven auditd files, utmp, wtmp, btmp, sudo and cron syslog, history, four plists, TCC,
quarantine, a journal export. Every file under 0.2 s.

- loghub's Linux_2k.log: sshd under the old tag `sshd(pam_unix)[pid]` was not read at all (489 failures, signal 0).
- "Which IP address logged in as drewr?" on a log with no drewr gave the one login's address: None now.
- "How many different source IP addresses attempted to log in?" counted the accepted sources (1 for 25, 2 for 5).
- sudo lines with no `TTY=` were not read (14 of 17 commands in plaso's sample), so "the sudo command" named the one
  that was; a user sudo refused was answered with another user's command; `(command continued)` lines mark a cut
  command.
- A stamped history command over four lines was four commands (7 for 4).
- `journalctl -o export` was "text"; a launchd job's user was answered from its program; the persistence row of a
  job with `Program` and `ProgramArguments` dropped the program.

Still failing: a utmp file whose size is not a multiple of 384 (plaso's wtmp.1 has one trailing byte) is not read;
macOS utmpx, binary journald, a quarantine row named by a file in its URL, counts of auditd commands.

### sqlite_artifacts

Files: 13 databases, two LevelDB folders, a Fossil repository; the slowest is 0.27 s.

- Ancient Fossil: the reader opened all 604 artifacts on the first try, but the triage printed the first twenty
  and the flag is rid 482. The triage now prints `FLAG-LIKE` and `ODD ONE OUT` lines, and "what is the flag" is a
  one-option pick.
- Chrome's old downloads table keeps Unix seconds: every offered time was in January 1601.
- "What file was downloaded from <site>?" was answered with the URL.
- Confirmed against `sqlite3`: every table's live row count in five databases, the WAL view, cookie, download,
  visit, message and quarantine facts. LevelDB: 100,000 puts and 10 deletes, as the data set's name says.

Still failing or unchecked: autofill questions (None), "which URL was visited the most" on Chrome (None though one
is strictly the most), no real file with deleted rows worth recovering, no CRX, no WhatsApp.

### End-to-end drills (`tests/real/test_real_drills_b.py`)

Triage (`solvers/common/triage.py`) on a saved attempt, the toolkit the map names, the challenge's own question.

| Challenge | Outcome |
| --- | --- |
| 2024 Ancient Fossil | **Alone**: the map names `sqlite_artifacts`; the flag is a one-option pick `verify.py` probes once |
| 2024 Nightmare on Hunt Street, parts 1 and 2 | **Alone from an XML or JSON export** (part 1 plain, part 2 a pick). As delivered (binary .evtx) it is the `windows` toolkit's |
| Nightmare parts 3 to 5, Little Shop of Hashes 1 to 5 | **With an agent**: the facts are in the triage (the brute force, `net user susan_admin "SusanIsStrong123" /ADD`, runasc.exe's command line); the questions are judgement |
| 2025 Webshellz | **With an agent**: no answers are published; the triage shows w3wp.exe spawning a fake svchost.exe, `net user IIS_USER ... /add` and frpc.exe |
| OTRF S3 exfiltration (questions in this event's style) | **Alone** for object, bucket and key; the attacker's address stays unsure |
| 2025 Angler (a live Entra tenant), 2024 Malibu (a live MinIO) | **Not**: live targets, no log or file of these toolkits |

### Adversarial review (2026-10-08, branch `day9b/real-b-r`)

A second pass asked about 800 questions the first pass had not: each narrows, ranks, negates or redirects what
the code matches. They were written before the answers were looked at, and each plain answer was recounted
with `json`, `csv`, `re`, `grep` or `sqlite3`. Mangled input was tried too: every real file under 8 MB, whole,
empty, cut, with bytes flipped, a hole, a repeat and a run of NULs (2,936 runs over the five toolkits).

**Wrong plain answers found, each fixed and asserted in `tests/real/test_real_review_b.py`:**

| Toolkit | Question | Was | Now |
| --- | --- | --- | --- |
| cloud_container | What account ID was given access to the bucket X? / the account ID in the bucket policy | the log's own account | None: an account or region question with any word the reader does not know is not answered |
| cloudlogs | How many IAM events are there? | 2900 (398) | None: a service or kind in front of "events" selects nothing here |
| cloudlogs | Which IP address did malicious-iam-user use? | the caller's address | None: a name that is only the target of others' calls, with no making verb |
| cloudlogs | How many applications were consented to? | 1 (12 names, 13 ids) | unsure: names, ids, events (counted from the consents' targets) |
| cloudlogs | How many users are in the log? | 44 (service names and two casings in it) | unsure: 18 addresses, 44 actors, 48 as logged |
| nix_host | Which IP address had the second most failed logins? | the first | None: second, fewest, not, except, other than are read as "not applied" |
| nix_host | Which IP address tried the most invalid users? | the one with the most failures | None |
| nix_host | Which IP address failed to log in as fztu? | where fztu got in | that user's failures only |
| nix_host | Which user logged in as root? | the one accepted login's user | None |
| nix_host | What directory did svc-backup run sudo from? / When did svc-backup run sudo? | the command | None |
| edr_persistence | How many network connections were made to port 3389? | 8 (6) | None: a port, protocol or direction the count was not narrowed by |
| edr_persistence | How many network connections did svchost.exe make? (two files carry the name) | 7 | None |
| edr_persistence | What IP address did svchost.exe connect to? / connected to svchost.exe? | the host's own address (accepted connections, Initiated=False) | None |
| edr_persistence | How many processes were created by cmd.exe? | 11 (its own start counted) | 10 |
| edr_persistence | How many process creation events are there for net.exe? | 18 | unsure: 9 as the new process, 9 as the parent, 18 |

Unsure answers whose every option was wrong (they cost base probes, not a batch) and are None now: "failed
password attempts were not for root" (root's count), "which user did not run frpc.exe", "who is <a user others
created>".

**Not wrong, checked:** no crash and no run over 0.7 s in the mangled-input runs; a CloudTrail file cut in the
middle (JSON, JSON lines or gzip) answers nothing in both cloud toolkits; inputs of 45 to 77 MB end in under
2.1 s (most are over the readers' size caps and answer None). `tools/rehearse.py R15` passes (4 cases).

**A flaky test, not a wrong answer.** `sqlite_artifacts` carves deleted rows under a wall-clock budget
(`CARVE_SECONDS`, 0.6 s). On a loaded machine the budget runs out, and a count that is plain on a quiet one
becomes a one-option pick of the same number. `test_real_sqlite_artifacts.py` failed once in the review for
that reason; its four count checks accept either form now. The consequence for play: the same file can replay
plain or unsure, so a gate replay of a `sqlite_artifacts` base may differ from its key under load.

**Still open after the review:**

- cloudlogs: "how many inbox rules forward mail" offers 7 and 3 on the real export (one rule forwards): unsure,
  both options wrong. The suspicious sign-in options name three different addresses, as before.
- cloud_container: "what is the content of the deleted file" answers `foo` for a file holding `foo\n` (the
  trailing newline is dropped).
- edr_persistence: "which user created the account susan_admin" answers the event's subject, the machine
  account `EC2AMAZ-0TD157D$` (the user was made by `net user` as SYSTEM). It is what the record says, and not
  what a person asking means.
- nix_host: a text log cut in the middle of a line cannot be told from a whole one, and its counts stay plain.
- Every reader is still a rule-based reader of free question text. The review found 15 families of wrong plain
  answers in about 800 questions after the first pass had found none in its own 110: expect more.

**cloud_container, fit for the match?** The review agrees with "yes, as a base-only candidate", on thin
evidence: 351 further questions on the real CloudTrail, Kubernetes audit and image files gave 30 plain answers,
2 wrong, both the account-ID family above and both fixed. The same caveat holds, more strongly.


---

## Real-artifact drills, group c (2026-10-08)

The toolkits of group c — `web_evidence`, `web`, `malconfig`, `modern_crypto`, `carve_stego`, `rf` — had read
only synthetic fixtures until this pass. This file records what real artifacts changed, which past Huntress
challenges the system would now close, and what still fails. The cache is `challenges/_realdata/` (untracked);
`tests/real/fetch_c.py` refetches it with sha256 checks from `tests/real/manifest_c.json`, and each toolkit's
`tests/real/test_real_<toolkit>.py` SKIPs cleanly when the cache is absent and asserts the checked facts when
it is present. Sources: the Huntress 2024 and 2025 write-up repos (ThisGuyNeedsABeer, TheGroundZero), the test
corpora of parsing libraries and tools (Flipper firmware, rtl_433_tests, bincopy, python-can, zsteg, zbar,
rust-minidump, dfvfs, RsaCtfTool, mfdread, ICSim), Cryptopals challenge data, and a public web-log research
set. No live malware was downloaded; the one PE used is a benign crackme and the VBScript is a defanged copy.

Every real run stays well under the 2 s budget on files below 20 MB. Downloaded files are untrusted data:
nothing here is ever run or imported.

### Would the system have closed it?

| Past challenge | Category | Alone (Layer 1 / a toolkit) | With an agent | Not closed |
| --- | --- | --- | --- | --- |
| 2024 "1200 Transmissions" | rf / audio | yes — `rf` reads the Bell 202 modem, the flag is in the message | | |
| 2025 "QRception" | carve_stego | yes — the QR drawn in ANSI half blocks is followed to the flag | | |
| 2024 "Strive Marish…" | modern_crypto | yes — RSA with the private parts given; the flag decrypts | | |
| 2025 "Angler" (crypto layer) | modern_crypto | yes — Blowfish-CBC with the key in the prompt gives the next-stage text | the later Entra enumeration is a VPN/live stop | |
| 2024 "MOVEable" | web_evidence | base facts (the pickle.loads sink, line, route) | the exploit chain (SQLi to a forged session, then the deserialization) is the agent's | |
| 2025 "Emotional" | web_evidence | the SSTI sink, class, line; route/param offered | the agent runs the payload against the live target | |
| 2024 "Unbelievable" | carve_stego | the PNG-named-.mp3 is flagged (disguise) | the flag is drawn text: OCR (`tesseract`) is agent work | |
| 2025 "Maximum Sound" | rf / carve_stego | header facts only | | SSTV decode (no decoder built) |
| zsteg / zbar / dfvfs / rust-minidump corpora | carve_stego | the hidden text, codes, disk-image files, minidump counts (see below) | | 3-bits-a-sample and tool-specific stego |
| RsaCtfTool example keys | modern_crypto | Wiener, Fermat, small factor, shared prime, given key (see below) | lattice/CRT-exponent keys | ROCA, partial-d, SIQS-sized |

### Per toolkit

#### rf (`solvers/toolkits/rf.py`, `tests/real/test_real_rf.py`, 26 files)
Fixed/added from real files: a two-tone FSK modem reader (Bell 202/103, V.23) — "1200 Transmissions" is now
closed alone; pulse-distance (`ppm_long_gap`) and gap-first (`pwm_gap_first_long_gap`) PWM readings and a
gap-group packet split, so rtl_433 OOK captures (Nexus, Prologue, generic remotes) and CAME/Nice FLO Flipper
RAW captures decode to the device's own bits; an NEC/NECext reader for raw IR matched against the Flipper
firmware's expected decodes; a Vector ASC CAN reader. A WAV a modem reads as text raises the signal to 0.8.
Still not read: SSTV, rolling codes (KeeLoq/Security+ bits read, key not derived), `.trc`/`.blf`, POCSAG/FLEX.

#### carve_stego (`solvers/toolkits/carve_stego.py`, `..._fs.py`, `tests/real/test_real_carve_stego.py`, 33 files)
The one wrong-answer bug: a code's text came back as zxing-cpp's display form (`<LF>`, `<ESC>`, GS1 brackets)
— now the payload as written (`TextMode.Plain`). Added: a QR printed in ANSI half blocks (QRception closed
alone); IDAT bytes after the zlib stream and after the last scanline; a BMP's stored pixel bytes and
row-padding LSB; two-bits-a-sample LSB; a sentence that starts inside a reading; MBR/GPT partition tables
(each partition walked) and an NTFS/exFAT "NOT READ, use the sandbox" note; the hash of a named file inside a
disk image. Verified against zsteg's and zbar's own expected output, dfvfs disk images (vs a 7-Zip listing
made in the sandbox) and rust-minidump's stackwalk snapshot. Not read: 3+ bits a sample, tool-specific stego
(Camouflage, OpenStego, wbStego), a flag drawn as picture text (OCR is agent work).

#### modern_crypto (`solvers/toolkits/modern_crypto.py`, `solvers/common/modern_crypto.py`, `tests/real/test_real_modern_crypto.py`, 24 files)
Every Cryptopals file and the Angler Blowfish note first answered `None`: the key stood in the question, not in
a file. Added `question_fields` (a key/IV/password quoted, after a colon or `is`, "key and IV are both …", a
zero IV), Blowfish when named, "which line is ECB" over a list of ciphertexts, Hastad over key and cipher
files with the pairing found by the exact root, a raw ciphertext saved with a trailing line end. Also: trial
division to 2^20 (a 16-bit factor was reported as Pollard p-1), Pollard rho inside the deadline on a modulus
of any size, and answering a set's RSA result from its cache after the budget (the second question about a
4096-bit Wiener key was `None`). Every factorisation is checked by multiplying it out, every message by
re-encrypting. Not broken (correctly `None`): `pollard_rho.pub`, `small_exponent` (no exact root), ROCA,
partial-d/masked PEM, SIQS-sized moduli.

#### web_evidence (`solvers/toolkits/web_evidence.py`, `tests/real/test_real_web_evidence.py`, 10 files)
Fixed: an access log wrapped in one extra pair of quotes parsed as zero rows; the nginx-JSON status column
`response`; a total count ("how many requests"); a scanner that names itself only in its requests
(`acunetix_wvs_security_test`, `/Netsparker<hex>/`, method `NETSPARKER`); an f-string SQL `.execute` sink and
a `'{password}'` format placeholder wrongly read as a secret; an SSTI sink whose template is built from a
variable (`ejs.render(page, …)`), with route/parameter offered unsure when the sink's handler reads no request
value (the input arrives by another route). Counts checked against an independent line reader; the MOVEable
and Emotional sinks against the write-ups. Not read: a flaw with no sink pattern (IDOR), minified JS, a pcap.

#### web (`solvers/toolkits/web.py`, `tests/real/test_real_web.py`, shares the web_evidence cache + a loopback app)
The live `WebClient` was exercised against a deliberately vulnerable app started on `127.0.0.1` by the test
itself (never a host on the internet): it logs only to the target, refuses off-scope and the Game Master host,
treats an unreachable loopback target as the player's VPN stop, and `discover()` finds `/` and `/robots.txt`.
Offline, three benign over-matches were tightened on the research logs — `url=` SSRF only to a private target,
`;cmd` not when the command is a whole path segment, `powershell` only with `.exe` or a flag — and a HAR now
classifies only what was sent, so a page's `<script>` tag is not called XSS.

#### malconfig (`solvers/toolkits/malconfig.py`, `tests/real/test_real_malconfig.py`, 3 cached files + built-here)
No solver change was needed: the real files matched the synthetic fixtures. `us_strings` reads 248 #US strings
from the real .NET assembly with no RedLine pairs; `xor_pe` recovers a real 96 KB PE XOR-encoded under a 2- or
8-byte key and finds nothing in the clean PE; `lua_constants` reads real `luac` 5.4 output (offered as the
family, never as a config); a 4.7 MB PE scans in ~0.6 s and a benign PE or defanged script answers nothing.
Not exercised on a real sample (no safe public one used): Cobalt Strike, NetSupport, AutoIt, quarantine.

### Adversarial review (2026-10-08, branch `day9b/real-c-r`)

Tried: questions that negate, rank or qualify what a toolkit matches; mangled, cut and oversized inputs (16
megapixel pictures, 14 MB WAVs, a 15 MB random file, broken BMP/PNG/WAV headers, an EBR that loops, a GPT with
entry size 0); timing against each budget. No crash and no hang was found; the real and synthetic suites pass.
Every fix has a check in `tests/test_tk_real_c_review.py` (no cache needed, about 2 s).

| Toolkit | Found | Now |
| --- | --- | --- |
| carve_stego | "the SHA-256 / size of the disk image" was the one deleted file's, plain; "the hash of the image that holds X", "hidden inside X", "deleted version of X" were X's hash, plain; "how many files were not deleted" and "including deleted ones" were the deleted count, plain; a partition counted as a directory; a disk whose partitions were not read answered "0 files" | `None` in each case; an unread partition with data blocks the disk's answers |
| web_evidence | the one sink's route, parameter or line was plain for "which route is NOT vulnerable / safe / parameterised", "the second parameter", "the parameter of the login route"; the JWT `alg` was plain for "does not use" | `None` |
| web | JWT `alg` plain for "does not use" and "should use instead"; `2026.huntress.ctf.games.` (trailing dot) passed the Game Master refusal | `None`; refused |
| rf | negated, other-device and arithmetic questions were offered the field as read (unsure, but a rejected probe blacklists the name for the field's key) | `None` |
| malconfig | the secondary gateway, "not the primary" and "how many C2" were offered the primary C2 | `None` |
| modern_crypto | "non-zero IV" stated a zero IV; "which line is NOT ECB" offered the ECB line | fixed |

Not fixed, by measurement: zxing-cpp on a 16 megapixel noise picture takes about 1 s and cannot be stopped, so
`carve_stego.solve_set` can run to about twice its 1 s budget on such a picture (as before this package); `rf`
takes 0.95 s on a 6 MB WAV that is modem tones from end to end. Both matter only if such a lane is ever put on
a clock. The qualifier gates are word lists: a wording they do not know is still read by the pattern under it.


---

## Real artifacts, group d: ai_model_files, agent_trace, repo_supply_chain, evidence_core, classical

Round 2 of the Day 9 build (2026-10-08, branch `day9b/real-d`). Round 1's fixtures were all synthetic and no
toolkit had read a real artifact. This page says which real files each toolkit of this group was run on, what
was true about each file by an independent reader, what broke, what was fixed, and what still fails.

The cache is `challenges/_realdata/<kit>/` in the main checkout (untracked, never committed), each folder with
a `SOURCES.md` (file, bytes, SHA-256, source). Refill or check it with

```bash
.venv/bin/python tests/real/fetch_d.py            # download what is missing; 94 pinned SHA-256
.venv/bin/python tests/real/fetch_d.py --check    # no network
for t in ai_model_files agent_trace repo_supply_chain evidence_core classical drills_d; do
  .venv/bin/python tests/real/test_real_$t.py | tail -1; done
```

Each test SKIPs (exit 0) without its cache folder. All six together take about 20 s. Nothing in the cache is
loaded, imported, installed or run; no request goes to the Game Master and no token is read. No live malware
was downloaded: the "malicious" pickles are picklescan's test vectors (they print a line or list a folder).
`tools/accept.sh` runs `tests/test_*.py` only, so these tests are run by hand until the integrator adds them.
Every change of this round is also tested with no cache and no network, on a small input of the real file's
shape, in `tests/test_tk_real_round_d.py` (69 checks, about 1.5 s; `accept.sh` picks it up by its name).

### What the system closes

A drill is the delivery saved as an attempt of a lane nobody knows, then `solvers/common/triage.py`,
`tools/lane_match.py` as the opener runs it, and the winner's answer beside the write-up's flag
(`tests/real/test_real_drills_d.py`; attempts under a temporary `$CTF_WORKDIR`).

| Challenge | Delivery | Result | How |
| --- | --- | --- | --- |
| 2024 Ancient Fossil (forensics) | `ancient.fossil` | **alone** | triage names `repo_supply_chain`; lane_match's winner is `toolkit:repo_supply_chain`; its one offered value is `flag{2ed33f36...}`, the write-up's flag (unsure: one base probe) |
| 2025 Darcy (forensics) | the darcs repository as a tar | **alone** | the same path; the flag is a patch name, found in the commit messages |
| 2024 The Void (warmups) | `output.txt`, 12 MB | **alone** | `toolkit:agent_trace` wins (signal 0.35 of 0.30) and answers the flag plain: the characters printed black on black |
| 2024 Cattle (warmups) | `cattle` | **with an agent** | no lane or toolkit claims a COW program; `solvers/common/classical.py cattle` prints the flag on its first line |
| 2024 Mystery (warmups) | text in the prompt | **with an agent** | `classical.py <prompt> --enigma` reads the stated settings and prints the message; the flag is the 32 letters after `FLAG` |
| 2024 No need for Brutus (crypto) | text in the prompt | **with an agent** | `classical.py` ranks `caesar16` first with the write-up's plaintext; the flag is its MD5 (the question's own rule) |
| 2024 Backdoored Splunk II (forensics) | `Splunk_TA_windows.zip` | **with an agent**, then the player | the page names the three files that fail the app's own hash manifest, the backdoored script among them; the flag itself is served by a live host |
| 2025 Webshellz (forensics) | IIS log, Sysmon EVTX, pcap | **with an agent** | a three-category bundle; this group's part is the IIS log, now a table by its own `#Fields`. The write-up has no answers, so nothing was compared |
| 2024 Strive Marish Leadman TypeCDR (crypto) | a live `nc` service | **not** (player) | RSA values come from a live target; nothing to read offline |
| 2024 Base-p-, Too Many Bits, Typo, TXT Message, Zulu; 2025 day-1 warmups | prompt text | not tried here | encodings: the Warmups lane's decoders, not this group's files |

Before this round the three "alone" rows were not: Ancient Fossil and Darcy answered `None` to a flag question
whose syntax read `flag{32 lowercase hex characters}` (the hex rule refused the flag itself), Darcy's patch
questions were `None`, and The Void was not read at all (12 MB was over the text limit, and same-colour ANSI
text was no hiding place this system knew).

### ai_model_files

**Files (55).** `tiny-bert.safetensors` and the PyTorch zip checkpoint of the same model
(hf-internal-testing/tiny-random-bert); a copy of that checkpoint with a `posix.system` reduce payload spliced
into `data.pkl` (built by `fetch_d.py`, opcode by opcode); two legacy checkpoints (sshleifer/tiny-gpt2,
tiny-distilbert); a 5 MB TorchScript archive; three GGUF files (stories260K, llama.cpp's phi-3 vocabulary
file, and the first 2 MiB of TinyLlama-1.1B-Chat Q2_K: the whole header of a 483 MB model); `mnist-12.onnx`;
a scikit-learn joblib; a Keras 2 `.h5` and a Keras 3 `.keras`; numpy's own Python 2 object arrays; and 38
files of picklescan's test corpus.

**Independent readers.** pickletools (opcode and persistent-id counts), safetensors, gguf, onnx, h5py,
zipfile. `gguf` and `h5py` were installed for this (requirements-toolkits.txt); a test skips that cross-check
without the package.

**Worked as built.** Safetensors header and tensors; torch zip and legacy tensors (101, 41, 33: the
persistent-id counts); GGUF metadata, tensor infos and chat template, also on a file cut after its header;
ONNX nodes, initializers, opset; joblib with raw array frames; npy object arrays; pickles of protocols 0 to 4.
No crash, no hang, nothing over 0.05 s.

**Fixed.**

| Found on | Was | Now |
| --- | --- | --- |
| Keras `.h5` and `.keras` | `layers` held every `class_name` of the config: the model itself, DTypePolicy, initializers, optimizer, loss (11 for a 3-layer model) | the entries of the model's `layers` list; the count is a pick with and without the InputLayer |
| Keras `.h5` | `keras_version` and `backend` were `None` (h5py writes variable-length strings into the global heap) | read from the heap (`2.5.0`, `tensorflow`, as h5py reads them); answered unsure |
| picklescan 12, 15a/b, 17 to 20, 3 to 6, 9 | not marked as running code | marked; `attrgetter` and `partial` chains named (`os.system`, `torch.serialization.load`) |
| picklescan 15a/b | "which module" answered `bdb.Bdb` (the dotted name cut at its last dot), plain | `bdb`, the module the stream names |
| a "which module ... its callable" question | answered the whole dotted callable, plain | the module |
| `malicious1_central_directory.zip`, `malicious1_0x1.zip` | not read (the zip module refuses them) | read when the directory's CRC-32 proves the bytes are in the clear; reported as `ZIP TRICK`; the second one also through `solve_set` although `tools/run.py` leaves that zip closed |
| `broken_model.pkl` | no report | read up to the break, `builtins.exec` named |
| a real checkpoint's page | 40 lines of `_rebuild_tensor_v2` | counts per callable; only what runs or cannot be named in full |
| a bundle | the pickle answered "what command does the postinstall hook run" asked of the npm file | a question whose member is another delivered file is left alone |

**Still fails or is not done.** TorchScript `code/*.py` is listed, not analysed. `sys_module_override_sploit.pkl`
(a callable computed on the stack) gives no verdict: the page says "callable not readable". A 7z or RAR around
a model is named, not opened. Nothing of this category has been judged, so every label (format, verdict,
dtype spelling) is still a pick. No real model with a planted chat-template or Lambda-layer payload was found
that is small and safe to cache: those two paths are still proven on synthetic files only.

### agent_trace

**Files (14).** Four saved runs of AgentDojo (workspace, banking and Slack under the `important_instructions`
attack, and workspace with no attack), a Claude Code session JSONL (claude-code-log's test data), an
`mcp.json`, a tool definition as github-mcp-server ships it, the three samples of invariantlabs'
mcp-injection-experiments, Unicode's `emoji-test.txt`, the Wikipedia page "Prompt injection" as HTML, an
OCRed PDF from OCRmyPDF's tests, and The Void's capture.

**Independent truth.** Each AgentDojo file states its injected text, its tool calls and whether the attack
worked; the session and config files are read again with json; The Void's flag is in the write-up.

**Worked as built.** The OpenAI-style and Claude Code transcript shapes, the mcp.json and tool readers, the
host rule (workspace: `gmail.com` first seen in the calendar tool's output), "two candidates are None" (Slack).

**Fixed.**

| Found on | Was | Now |
| --- | --- | --- |
| AgentDojo runs | every call's tool name blank | read from `{"function": name, "args": ...}` |
| AgentDojo workspace | "which tool did the agent use to exfiltrate data after the injection" answered `search_calendar_events`, plain and wrong (the tool that returned the injection) | `send_email`; the source tool only when the question says so outright |
| AgentDojo workspace | "which host" answered `gmail.com` plain | a pick of the mail domain and the address |
| AgentDojo runs | the planted text was not read as an instruction | the benchmark's wording is in the classifier |
| AgentDojo banking | nothing found: the destination is an account number, not a host | `followed_values`: the call that pays the account the planted text names; answers unsure |
| the three MCP samples | not read (Python source, not JSON) | `python_tools`: tools by `ast`, the swapped docstring of the rug pull included; all three flagged |
| `emoji-test.txt` | "strong" hidden text `gbenggbsctgbwls` (the flags of England, Scotland, Wales) | not a finding |
| Wikipedia page | its `display:none` short description answered plain as "the hidden text"; 150 lines of link titles | offered unsure; twelve lines and a count |
| OCRed PDF | the invisible layer printed as `\x00s\x00w...` and asserted | read as UTF-16BE; offered unsure |
| The Void | not read | `ansi_same_colour`; the flag plain; `signals` reaches the threshold |

**Still fails or is not done.** Two hosts in one transcript are two candidates even when one is an honest link
(Slack: `None`; an agent reads `INJECTED ... why=followed,instruction,proven` on the page and decides). The
instruction classifier is still a regular expression: everything that rests on it alone is unsure. No store
written by a real Chroma, LlamaIndex or LangChain was cached (none small enough was found, and installing
those libraries to make one was not done): the corpus readers and `nearest` remain checked on synthetic rows.
No real OpenTelemetry, Codex or Cursor trace was run. `signals` and `solve_set` each scan a 12 MB capture
(0.6 s a pass; NOTE in the toolkit page).

### repo_supply_chain

**Files (15).** `ancient.fossil` (2024), the `darcy` folder (2025), `Splunk_TA_windows.zip` (2024), a full
clone of trufflesecurity/test_keys, and eleven packages: two wheels and an sdist (PyPI, hashes as PyPI
publishes them), two npm tarballs, a gem, a jar, a nupkg, a vsix, a CRX3 and a workflow file.

**Independent readers.** sqlite3 on Fossil's `event` table (403 check-ins); gzip and a regular expression on
darcs' `hashed_inventory` (402 patches, one name with a flag); hashlib on the Splunk manifest (three files
differ); the GitHub API's commit list for test_keys (six commits on main, ids, e-mails, messages); zipfile,
tarfile and json on the packages; the store id of the CRX.

**Worked as built, on their first real file.** The Fossil reader (written from the format documentation) and
the darcs reader: every check-in and patch, and both flags in the secret scan. The git reader against the
API's list, a remote-only branch included, with a key that only the first commit holds. CRX3 extension id.
RECORD verification, npm lifecycle scripts, `.pth` lines, nupkg install script, vsix identity, gem spec.

**Fixed.**

| Found on | Was | Now |
| --- | --- | --- |
| setuptools wheel | three files "missing" from RECORD: all empty members were one file (`b""` is one object in Python) | 235 rows, none missing |
| Darcy | "which patch holds the flag", its author, its message: `None` | the commit a message-held secret is in |
| both histories | "how many patches / check-ins": `None` | offered (402; 403 and 402 without Fossil's empty first check-in) |
| both histories | 200 of 400 commits printed with no word that the table was cut | the cut is said; `UNUSUAL MESSAGE` names the odd commits (Darcy: two of 402, the flag's among them) |
| a flag question with `flag{32 lowercase hex characters}` | every flag refused | accepted |
| Splunk app | "nothing here is a repository, a package or a secret" | `hash_manifest`: 75 rows, three mismatches |
| CRX | name `__MSG_extName__` | `Google Docs Offline`, by the default locale |
| a workflow file outside `.github/workflows/` | not read | read by its `on` and `jobs` |
| "which .pth file" | `None` unless the answer id said name | answered |

**Still fails or is not done.** Mercurial, SVN dumps and git bundles were not run on a real file in this round
(round 1 checked hg against the real tool). The Splunk backdoor's flag needs the live service. A jar with no
Maven coordinates has no name. Placeholder credentials in a source tree's own tests count as secrets.
Minified extension code gives junk URLs (unsure only).

### evidence_core

**Files (9).** loghub's `OpenSSH_2k.log` (with its `_structured.csv`), `Linux_2k.log`, `Apache_2k.log`; 10,000
lines of elastic/examples' combined access log; `Chinook_Sqlite.sqlite`; nmap's `nmap_example.xml`; the IIS
log of 2025 Webshellz; the semicolon table of the 2025 Trashcan write-up.

**Independent readers.** csv, re, sqlite3 and plain line counts in the test itself.

**Worked as built.** syslog, access, csv (also `;` with no header), sqlite and XML tables; counts, distinct
values and top values equal to the independent counts (213 status-404 rows, 558 user agents, 519 pids, 3,503
tracks). Every pass under 0.1 s.

**Fixed.**

| Found on | Was | Now |
| --- | --- | --- |
| Webshellz IIS log | a `timed` table with four unparsed lines and no columns | `w3c`: the 15 columns of `#Fields`, 28 rows; `sc-status = 404` counted plain |
| Apache error log | `lines` (no table) | `bracketed`: time, level, client, message |
| `OpenSSH_2k.log` | "how many lines" answered 2000 plain; `wc -l` says 1999 (no final line end) | a pick of both |
| `Linux_2k.log` | eight unparsed lines (`syslogd 1.4.1: restart.`), so no count was proven | parsed |

#### The incident-bundle drill

One delivery of five real files (the sshd log, the IIS log, a picklescan pickle, the AgentDojo workspace run,
the husky npm tarball) and ten questions. Before: the evidence layer answered its three and left seven `None`,
and a lane match would have banked one toolkit's share. Now `solvers/toolkits/evidence_core.py` hands each
question it leaves `None` to the specific toolkits and takes the one answer:

| Question | Answered by | Answer |
| --- | --- | --- |
| lines of auth.log | evidence_core | pick: 2000 lines, 1999 newlines |
| rows of the IIS log with `sc-status = 404` | evidence_core | `4`, plain |
| the most common source address | evidence_core | pick `most_common.ip`: 183.62.140.253 |
| the command the pickle runs | ai_model_files | `ls -la`, plain |
| the callable it invokes | ai_model_files | pick: `os.system`, `posix.system` |
| the tool used to exfiltrate | agent_trace | `send_email`, plain |
| the tool that returned the injection | agent_trace | `search_calendar_events`, plain |
| the postinstall command | repo_supply_chain | pick: `opencollective-postinstall \|\| exit 0` |
| the package name | repo_supply_chain | pick: `husky` |
| "the attacker's IP" (names no file) | nobody, or a pick `evidence_core.routed/...` | never plain |

0.3 s for the ten. The first run of the drill had `ai_model_files` also answer the postinstall question (from
the pickle); that is the scope fix above, and the router's rule that two different answers are no answer held.
On round 1's synthetic bundle the router adds one answer, `nix_host`'s plain "attacker IP", and returns it
unsure: a toolkit proves its answer inside its own slice only. `tools/lane_match.py` still picks ONE solver for
a new lane; the router is for the agent's `verify.py` run and is off inside the match.

**Still fails or is not done.** XML gives one table per member. An event-log text export is `lines`. The router
was drilled on one bundle. Its budget (10 s since the review; no further toolkit is asked after it) is tested with slow stand-in
toolkits; one toolkit that is slow by itself is stopped only by the runner's own cap (`verify.py --solve-timeout`, 45 s).

### solvers/common/classical.py

No cached corpus beyond `cattle`: the two other texts are quoted from the challenge descriptions in
`tests/real/test_real_classical.py`. Caesar cracking and the Enigma simulator were right as built on real
challenge text. Added: a COW interpreter (`cow()`, the command prints its output first) and
`enigma_settings()` with `--enigma`, which reads rotors, positions, rings, reflector and plugboard out of a
prompt ("nothing reads Enigma settings out of a prompt" in the readiness page is now out of date). Not done:
base65536, JSFuck, Whitespace; nothing here is wired into a lane, so each of these is an agent's command.

### Timing

| Run | Seconds |
| --- | --- |
| `ai_model_files.analyze` on any of the 55 files (5 MB TorchScript the largest) | under 0.05 |
| `repo_supply_chain` on the darcs folder (1,419 files) / the Fossil repository | 0.5 / 0.03 |
| `agent_trace` on The Void, 12 MB: one pass / the command | 0.6 / 1.3 (NOTE in its page: `signals` and `solve_set` each pass once) |
| `evidence_core` table pass on 10,000 access-log lines | under 0.1 |
| the bundle drill, ten questions, router on | 0.3 |
| triage on a drill attempt | 0.3 to 1.4 |

Nothing of this group takes 2 s on a file under 20 MB.

### Not verified

- Nothing was judged: every "right" above means equal to an independent reader or to a write-up's flag, not
  accepted by the Game Master.
- Question wordings are still invented in this event's style; the wrong plain answers this round found (the
  exfiltration tool, the module, the line count, the hidden text of a web page, the host) were each found by
  one more wording, and other wordings will find more.
- The files whose upstream can move (branch heads, the store's latest CRX) are pinned by the hash of this
  round's fetch; a later fetch that differs is reported and not cached.

### Review (2026-10-08, branch `day9b/real-d-r`)

An adversarial pass over this round: mangled and truncated copies of every cached file, questions that
negate, order or narrow what the code matches, hostile text for the two new classical readers, and the router
with stand-in toolkits. Each fix is checked on a small input in `tests/test_tk_real_round_d_review.py`
(no cache, about 2 s; every check fails on the tree before the review).

**Held.** 3,268 runs (and as many again with a second seed, after the fixes) of `signals` and `solve_set` on truncated, bit-flipped, doubled and length-doctored
copies of the cached files of the four toolkits: no crash, no hang; one run over 2 s (`evidence_core` on the
access log doubled to 4.7 MB, 2.4 s with the router on). `repo_supply_chain` gave no plain answer to any of
thirty wordings on seven real files. `evidence_core`'s plain counts on the IIS and Apache logs equal `awk`
and `grep`; an IIS log whose field list changes after a restart and a Zeek `conn.log` count by the right
column, and a shifted or cut row makes the count `None`. Every real test SKIPs without the cache. Warmups
replays unchanged on Days 1 to 8 (39 rows, 0 fail) with the changed `classical.py`; rehearsals R15 and R21 pass.

**Wrong plain answers found and fixed.**

| Found on | Was | Now |
| --- | --- | --- |
| AgentDojo workspace run | "Which tool did the agent call before the injection?", "... not use to send the data?", "Which benign tool ..." answered `send_email`, plain | `None`: `agent_trace.qualified()` refuses a question that negates (not, never, without, instead, benign, visible), orders (before, first, last, most) or measures (colour, length) the finding. What the user never asked for, and the turn the agent first acts, are not refused |
| The Void | "What text is not hidden?", "What colour is the hidden text?", "What is the first hidden word?" answered the flag, plain | `None` |
| The Void | "What is the injected instruction?" answered the flag, plain | a pick `hidden/<kind>.not_an_instruction`: the one hidden text does not read as an instruction |
| a capture printing one text over and over | "the hidden text" answered that text once, plain | a pick `hidden/ansi_same_colour.repeated_or_cut` (the same when more than 64,000 hidden characters were cut) |
| picklescan's vectors, the backdoored checkpoint | "Which callable is harmless?", "Which module does the pickle not import?", "What command does the payload not execute?" answered the finding, plain | `None`: `ai_model_files.qualified()` |
| tiny-bert, stories260K | "How many tensors have dtype float32?" answered the count of all tensors, plain | `None` for a count the question narrows (have, with, whose, larger than, of dtype) |
| any file with a reduce payload, options `yes, no` listed | "Is the model safe to load?" answered `yes`, plain | `no`; `yes` to "is it malicious"; neither word when the question has both words or a negation. Without listed options the pick offers `false`/`no` to the safe question, never `true`/`yes` |

**The bundle router.**

- It caught `BaseException` around each toolkit, which swallowed the runner's stop (`tools/run.py`
  `SolverTimeout`, raised from its timer): the hand-over went on past the solver's budget. It now catches
  `Exception`.
- A routed plain answer stayed plain whenever the question named a delivered file, whichever file the toolkit
  had read it from. It now stays plain only when that toolkit gives the same answer again from the named file
  alone (and what was unpacked from it); otherwise it is the pick `evidence_core.routed/<id>`. This group's
  toolkits already left such questions alone; the others were not checked one by one, so the rule is in the router.
- `ROUTE_SECONDS` is 10, not 20. Measured: 0.3 s on the five-file drill, 13 to 16 s for twelve unanswerable
  questions over 193 real files (60 MB) of twenty toolkits' caches, most of it the evidence layer's own pass.

**classical.py.** `cow()` counted instructions but not loop skips: a 1 MB program whose loop body is one long
skipped loop ran for minutes (now `None` in 0.5 s). `enigma_settings()` had several optional blanks in a row
and a line lead-in that crossed lines: "rotors" followed by half a megabyte of blanks ran for minutes (blank
runs are now collapsed first, in linear time). Both are reached only from the command line.

**Tests.** `tests/real/common_d.py` kept a `HUNTRESS_CHALLENGES` (now `CTF_WORKDIR`) the shell had set, so the drills would have
written their attempts into it; it now always makes a scratch folder.

**Still open after the review.**

- `ansi_hidden` reads the sixteen named colours and SGR 8 only: the same text in a 256-colour or true-colour
  pair (`38;5;16` on `48;5;16`) is not found (`None`, no wrong answer). Bold black on black, which some
  terminals draw grey, counts as hidden.
- Two hidden runs of different colours in one capture are one text for "the hidden text" (their characters in
  order, plain); a flag question with two tokens is `None`.
- `agent_trace`: "Which tool's output did the agent send to the attacker?" answers the tool that returned the
  injection, plain; "How many tool calls did the agent make after the injection?" offers the count of all
  calls (unsure). The guards are word lists: another wording will get past them, and some honest wordings with
  "first" or "not" now get `None` where they had an answer.
- `tools/accept.sh --quick` was not run in the review: its item 7 is the bare `tools/preflight.py`, whose
  token check opens the token file, which this build may not read. Its rows that this package can change were
  run one by one (every `tests/test_tk_*.py`, the registry, triage, kinds, labels, classical, the Warmups
  selftest and `preflight.py --regress warmups`, R15 and R21).
- `solvers/toolkits/registry.py` (round 1, not this package) still catches `BaseException` around a toolkit's
  `signals`: a stop that fires there is lost until the runner's timer fires again a quarter second later.
