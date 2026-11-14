# Toolkit `email`: phishing and e-mail (.eml, .msg, mbox)

Backlog row 84. File: `solvers/toolkits/email.py`. Tests: `tests/test_tk_email.py`. Offline, no token.
Clock path: standard library only (the stdlib mail parser and a small compound-file reader for `.msg`).
Pillow and pyzbar are imported only for a QR question or by the command.

## Run first

```bash
.venv/bin/python solvers/toolkits/email.py workspace/<id>/members/*.eml      # or the zip itself
.venv/bin/python solvers/toolkits/email.py <file> --json        # the same as one dict per mail
.venv/bin/python solvers/toolkits/email.py <file> --no-qr       # never import Pillow/pyzbar
```

It prints, per mail: subject, date in every form, Message-ID, mailer; From, Reply-To, Return-Path, To with
display names; the three mismatch flags; every Received hop (newest first) with its IPs; the originating-IP
candidates; SPF, DKIM, DMARC results and their properties; each attachment with declared type, true type,
size, SHA-256, MD5, SHA-1; each URL with where it stands, its link text, and its refanged or defanged form;
homoglyph domains; QR payloads; HTML-smuggling indicators, download name and payload hashes; `indicators`.
A line `candidates disagree: a, b` or `DISAGREE pass/fail` is where the solver answers `None` and you decide.

`solve_set` returns ranked candidate values (`labels.show(...)`); reason to the flag from the output and
submit it once via `ctf.submit.guarded_submit(...)` (or `./csctf submit <id> <flag>`).

## By hand

```python
import importlib.util
spec = importlib.util.spec_from_file_location("tk_email", "solvers/toolkits/email.py")
tk = importlib.util.module_from_spec(spec); spec.loader.exec_module(tk)
mail = tk.load(open(path, "rb").read(), path)[0]      # [] when the bytes are not mail; one Mail per mbox message
tk.received_chain(mail); tk.originating(mail); tk.auth_results(mail); tk.addresses(mail); tk.mismatches(mail)
tk.urls(mail, qr=True); tk.link_mismatches(mail); tk.homoglyphs(mail); tk.qr_codes(mail); tk.smuggling(mail)
tk.indicators(mail); tk.triage(mail); mail.attachments[0]["data"]; mail.nested   # attached messages
tk.refang(u); tk.defang(u); tk.idn_forms(domain); tk.date_forms(header_value); tk.cfb_streams(msg_bytes)
```

Never `import email` for this file: that name is the standard library's. The file hands the standard
library back when it is imported by the bare name (a solver's folder is first on `sys.path`).

## What `solve_set` answers

Plain (sent in the confident batch):

| Question | Answer |
| --- | --- |
| SHA-256, SHA-1, MD5, SHA-512 of an attachment (named, n-th, or the only one) | lowercase hex of the decoded bytes (uppercase when the syntax says so) |
| the same of the mail file itself ("of the email", `its` with the mail as member) | lowercase hex |
| size of an attachment in bytes | integer |
| "How many attachments ...", "How many Received headers ..." with no qualifier | integer (attachments only when every way of counting agrees; never a plain 0) |
| "How many messages are in the mbox?" | integer (unsure when a body holds an unquoted `From ` line) |
| SPF, DKIM or DMARC result, enum question naming ONE check, all headers state one result, the enum lists it | the enum's spelling |

Never plain, since the review of 2026-10-08 (each of these gave a wrong plain answer before):

- a hash or size of something inside an attachment or payload ("the executable inside the attached ZIP", "the file
  extracted from ...", "the macro", "the email that carries the attachment"): `None`;
- an attachment whose base64 is damaged, whose multipart has no closing boundary, or that decodes to nothing; a .msg
  attachment whose stream is shorter than its directory entry states, or any attachment of a compound file that is
  not a whole number of sectors: `exact` is False, `None`, and a note says why;
- the hash and size of an HTML-smuggling payload: unsure under `email.payload_hash/<algo>` and
  `email.payload_size/bytes` with the method `base64_literal_decoded` (the script may XOR, reverse or join the
  literal before it saves the file; that is not proven without running it);
- URL and recipient counts: always unsure (`email.count/urls`, `email.count/recipients`);
- any count from a mail with `mail.doubt` set (parser defects, a header block the parser cut short, no blank line
  after the headers, MIME boundaries the headers do not declare, a .msg with no transport headers, a cut file);
- a question that names two of SPF, DKIM and DMARC: `None`.

A byte-order mark or blank lines before the first header are skipped before parsing (the file's own hash is still
of the bytes as delivered). Not detectable, and so still answered: an attachment cut exactly at a four-character
base64 boundary inside a mail whose closing boundary survived, and a damaged byte that leaves a valid file.

Unsure (`labels.pick('email.<field>/<shape>', [(method, value), ...])` — ranked candidate values you read with `labels.show`):

| Field | Keys | Options, best first |
| --- | --- | --- |
| auth result without an enum; yes/no "did SPF pass" | `email.spf/result`, `email.dkim/result`, `email.dmarc/result`, `email.bool/spf_passed` | `lower`, `as_written` |
| DKIM selector, domain, algorithm; DMARC policy; SPF client IP and domain | `email.dkim/selector`, `email.dkim/domain`, `email.dmarc/policy`, `email.spf/client_ip` | the tag value |
| From, Reply-To, Return-Path, To, Cc address or domain; display name | `email.from/address`, `email.reply_to/domain`, `email.from/display_name` ... | `address`, `address_lower`, `as_written`; `domain`, `punycode`, `unicode` |
| reply-to mismatch, return-path mismatch, display-name spoof, extension mismatch | `email.bool/reply_to_mismatch` ... | `true_false`, `yes_no` (the enum's values when it gives them) |
| originating IP; a named header such as X-Originating-IP | `email.ip/originating`, `email.ip/x-originating-ip` | `ip`, `as_written` |
| HELO, first hop host, receiving server | `email.received/helo`, `email.received/first_host`, `email.received/last_host` | `as_written`, `lower` |
| Subject, Message-ID, mailer, Date, any header the question names | `email.header/subject`, `email.header/message_id`, `email.header/date`, `email.header/<name>` | `decoded`, `as_written`, `bare`; dates: `as_written`, `iso_utc_z`, `iso_offset`, `utc_space`, `date_utc`, `epoch` (ISO first when the question says ISO or UTC) |
| attachment filename, extension, declared Content-Type, true file type | `email.attachment/filename`, `email.filetype/<family>` | type labels: `zip`, `zip_archive`, `application/zip` ... |
| the one link; its domain or path; link text against target | `email.url/single`, `email.url/domain`, `email.url/target`, `email.url/shown` | `as_written`, `refanged`, `defanged` (`hxxps://a[.]b/x`), `defanged_dots_only` |
| QR code text, URL, domain | `email.qr/url`, `email.qr/text`, `email.qr/domain` | as for URLs |
| homoglyph domain, its punycode, the impersonated domain, the odd character | `email.homoglyph/domain`, `email.homoglyph/skeleton`, `email.homoglyph/character` | `as_written`, `punycode`, `unicode`; `ascii_skeleton`; `character`, `u_plus`, `name` |
| smuggled file name and type | `email.smuggling/filename`, `email.filetype/<family>` | `download_name` |
| an enum that lists techniques | `email.indicator/<name>` | the one accepted value the mail was seen to do |
| ATT&CK id | `email.attack/attachment`, `email.attack/link` | `T1566.001` (attachment and no link), `T1566.002` (link and no attachment) |
| counts with a qualifier, hops, URLs, recipients | `email.count/urls` ... | one option per way of counting (`distinct`, `all`; `to`, `to_and_cc`) |
| a flag-like `answer_format.pattern` with exactly one match in the decoded mail | `email.pattern/only_match` | the match |

`None`, on purpose (yours to settle with the command's output):

- X-Originating-IP and the earliest public Received hop name different IPs.
- Two or more distinct links, attachments, QR codes or smuggling pages and the question names none.
- Authentication-Results headers that disagree; several From headers; several DKIM signatures.
- Reply-To or Return-Path in the same domain as From but another mailbox, or in a subdomain.
- The hash of an attached message (`message/rfc822`: the parser re-serialises it; hash it from the raw file by hand).
- A typosquat in ASCII (`paypa1`, `rnicrosoft`): no table proves the brand. `lookalikes(mail)` lists pairs of the
  mail's OWN domains one edit (or one look-alike swap) apart, and the question is answered only when there is
  exactly one such pair with one side among From/To/Cc; a brand the mail never names is not found.
- `json` and `ordered_tokens` answers; several messages in an mbox and a question that picks none.
- A password-protected attachment: the password is usually in the body text. Read it, `tools/password.py add '<value>'`.

## Label vocabulary to expect (this event: lowercase snake_case, descriptive)

- Results: `pass`, `fail`, `softfail`, `neutral`, `none`, `temperror`, `permerror`; DMARC policy `none`, `quarantine`, `reject`.
- Techniques: `html_smuggling`, `qr_code` / `quishing`, `homoglyph_domain` / `lookalike_domain`, `reply_to_mismatch`,
  `return_path_mismatch`, `display_name_spoofing`, `link_mismatch`, `extension_mismatch`, `double_extension`,
  `credential_harvesting`, `business_email_compromise`, `thread_hijacking`, `callback_phishing`, `clickfix`.
- File types: `zip`, `pdf`, `html`, `pe`, `lnk`, `iso`, `ole`, `rtf`, `one` (OneNote), `svg`.
- ATT&CK: `T1566.001` attachment, `T1566.002` link, `T1566.003` via service, `T1027.006` HTML smuggling,
  `T1204.001` malicious link, `T1204.002` malicious file, `T1036.007` double file extension, `T1656` impersonation.

Until `solvers/common/labels.py` lists the prefix `email` in `LANE_DIRS`, an unsure answer of this toolkit is
written in the same wire form and read as ranked candidates (`labels.show`). The plain answers work either way.

## Another member's question (in force since 2026-10-11)

A question whose artifact names another member of the delivery (a file that is no mail and holds none,
`evidence.zip -> access.log` beside the mail) is None whatever its words. Before, the mail's first hop was
offered under `email.ip/originating` for the access log's attacker address: another fact under the key.
Answered as before: a question that names only the archive, an archive that holds the mail, a file the
delivery does not have (the Metadata Day 3 timed variants named a file of another variant), and a member
named under the mail itself (`message.eml -> invoice.pdf`). `tests/test_day12_new_lane_toolkits.py` pins the
rule on a bundle it builds; `tests/test_day12_new_lane_wording.py` pins the author-style fixtures by
invariants (no wrong plain).

What follows from it on a bundle that holds a mail beside other evidence: the match is no longer won by
`toolkit:email` for the other members' questions (on the look-ahead's incident bundle the winner moved to
`toolkit:web_evidence`, 3 of 7 answered, 3 plain), and the evidence layer's router returns the named file's
toolkit answer where email's different answer used to make two candidates. Left as it was, never exercised
in testing: a question with no arrow that names a non-mail delivery of a one-set attempt, a decorated
member spelling, and a non-mail file with the mail's bare name in another folder are still answered from the
mail. Only this toolkit was audited for the rule.

## Not covered

- TNEF (`winmail.dat`), S/MIME and PGP bodies, DKIM signature verification (no DNS), `.pst`/`.ost`.
- An `.msg` RTF body is decompressed (`compressed_rtf`) for its URLs only. An embedded `.msg` attachment is parsed
  as an attached message and has no bytes to hash.
- A QR code drawn with table cells or block characters instead of an image; OCR of text in images.
- Macro documents, PDFs and LNK files inside an attachment: hand them to the toolkit for that format
  (hostile-format tools through `tools/sandbox.py`, run by hand).

## Real artifacts (2026-10-08): what real mail changed

Tested on 33 real mails (`tests/real/test_real_email.py`; sources in `docs/toolkits/real-data.md`): Huntress CTF
2025 Follow The Money (five), 2024 Ran Somewhere, mail-parser's test mails, extract-msg's `.msg` examples,
CPython's test messages.

- **Addresses are split before they are decoded.** The standard library's strict reader gives nothing for
  `alice@a.example <bob@b.example>` (an address as display name: a real recipient header and a classic spoof),
  and decoding first split `=?iso-8859-1?Q?Last=2C_First?= <x@y>` at the decoded comma. `_addrs` now cuts the
  mailboxes at top-level commas, takes the address in the angle brackets, decodes the display name after, and
  decodes an address written wholly as an encoded word. Before this, the sender or recipient of four real
  mails was no answer at all.
- Raw 8-bit bytes in a header or in a `filename="..."` parameter are read as UTF-8 (then cp1252), not as
  surrogates or U+FFFD.
- A `message/delivery-status` part with a file name is an attachment by that name (not exact: never hashed).
- `lookalikes(mail)` and its report line; "Which URL does the "<link text>" link point to?" is answered from
  the link whose shown text the question quotes.
- Checked and unchanged: attachment bytes equal the base64 block cut from the raw mail, and for Ran Somewhere
  the files the write-up's author saved; a count of attachments is plain only when every reading of
  "attachment" gives the same number.

Timing: a 6.3 MB mail loads and reports in 0.1 s (0.9 s with the QR search of its two large images).

### Review of the real-artifact work (2026-10-08, `tests/real/test_review_a.py`)

A question that negates or excludes ("the size of the email without the attachment", "the file that is not the
attachment") is offered, never plain (`_negates`; it answered the attachment's size, plain). The look-alike reader gives None for a question about the look-alike and not for it ("which domain is NOT a
look-alike", its registrar, which character differs, how many). A mail that names more than 150 domain labels is
compared against the domains of its own parties only (`LOOKALIKE_ALL_PAIRS`; every pair of 800 took 5 s). Left as it was and worth knowing: the hash and
size of a text attachment sent as 7bit or quoted-printable are plain here (the bytes Python's `email` decodes,
which is what any mail tool exports), while the network toolkit offers the same attachment carved from SMTP
unsure.
