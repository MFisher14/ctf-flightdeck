# Toolkit `sqlite_artifacts`: browser and application artifacts

Module: `solvers/toolkits/sqlite_artifacts.py` (standard library only on
the answering path; `cryptography` is used only to try a key that is in the delivery). Tests:
`tests/test_tk_sqlite_artifacts.py`.

## Run this first

```bash
.venv/bin/python solvers/toolkits/sqlite_artifacts.py challenges/day-NN/<id>/members      # after tools/unpack.py
.venv/bin/python solvers/toolkits/sqlite_artifacts.py History History-wal Cookies ext.crx  # or the files themselves
```

Give it a folder whenever a database has a `-wal` or `-journal` beside it: the companion is found by name.
The triage prints, per database: the artifact kind (by schema, never by file name), page facts, every table
with its row count, **RECOVERED rows** with where each was found, strings in unallocated space; then the
records by kind with times converted, **decoded cells** (`via base64`, `via url>uuencode`), extensions with
their ids and permissions, and LevelDB / Local Storage records (deletes included).

As a solver (runner contract, sub-second on small files): reason to the flag from its output, then submit
it once via `ctf.submit.guarded_submit(...)` (or `./csctf submit <id> <flag>`); an OSINT/templated answer
uses `allow_nonstandard=True`.

## What it reads

| Artifact | Recognised by | Records |
| --- | --- | --- |
| Chromium History | `urls` + `visits` | url, visit, download (with `downloads_url_chains`), search (`keyword_search_terms`) |
| Chromium Login Data | `logins.username_value` | login (password None unless decryptable) |
| Chromium Cookies | `cookies.host_key` | cookie |
| Chromium Web Data | `autofill`, `keywords` | autofill, search_engine |
| Firefox places.sqlite | `moz_places` | url, visit, bookmark, download (`moz_annos`), typed |
| Firefox cookies / formhistory / webappsstore | `moz_cookies`, `moz_formhistory`, `webappsstore2` | cookie, autofill, storage |
| Firefox logins.json | `encryptedUsername` | login (host plain; user and password NSS-encrypted: None) |
| Safari History.db | `history_items` + `history_visits` | url, visit |
| macOS quarantine events | `LSQuarantineEvent` | download (data URL, origin URL, agent) |
| iOS sms.db | `message.is_from_me` + `handle` | message |
| WhatsApp msgstore.db | `messages.key_remote_jid`, or `message.text_data` + `jid` | message |
| Fossil repository | `blob` + `delta` + `rcvfrom`/`event` | fossil_config, fossil_user, fossil_event; `fossil_blobs(db)` gives every artifact with deltas applied |
| Chrome extension | `manifest.json` with `manifest_version`, or `Cr24` | manifest v2/v3 facts, CRX2/CRX3 ids |
| LevelDB | table footer magic, or `NNNNNN.log` | key, value, seq, live/deleted; Local Storage prefixes decoded |
| any other SQLite file | magic | tables dumped in the triage; no answers |

Clocks: WebKit (µs since 1601) for Chromium, PRTime (µs since 1970) for Firefox, Unix s for `expiry` and
autofill, Unix ms for WhatsApp and logins.json, Mac absolute (s since 2001; ns on iOS 11+) for Safari, sms.db
and quarantine, Julian day for Fossil events.

## Readers to call by hand

```python
import sys; sys.path.insert(0, "solvers/toolkits"); import sqlite_artifacts as sa
files = sa.load_paths(["members/"])                # {name: bytes}; zip members as "a.zip -> name"
ev = sa.Evidence(files)                            # .dbs .kinds .records .extensions .storage
db = ev.dbs["members/History"]                     # .tables (live) .recovered .strings .columns .pages
[r for r in ev.of("download")]                     # {kind, src, f: {...}, t: {field: (raw, datetime)}}
ev.staged()                                        # [(record, cell, chain, decoded text)]
sa.decodings(text)                                 # one cell: url, base64(+utf16le), hex, uuencode, nested
sa.Database(data, wal, journal).recovered          # rows from WAL frames, journal, freelist, free space
sa.crx(data); sa.extensions(files); sa.id_from_public_key(der)
sa.leveldb_records(data, name); sa.snappy_decompress(block)
sa.decrypt_value(blob, files, host); sa.protection(blob)      # 'dpapi' | 'v10' | 'v11' | 'v20'
sa.time_options(dt, raw); sa.from_webkit(n); sa.from_prtime(n); sa.from_mac_absolute(n)
sa.fossil_blobs(db); sa.fossil_delta(src, delta)
```

## Question shapes `solve_set` answers

The field is read from the question's words and the answer id (names the question quotes are set aside
first). The row is chosen by the names in the question (quoted text, anything with a dot, the word after
`named`), then `first`/`last`/`most visited`. Rows that still disagree: `None`.

| Asked | Plain when | Unsure (`??`) when |
| --- | --- | --- |
| download URL | the chain has one URL | two or more: `final_url`, `first_url` |
| download referrer, tab URL, mime, size | one live row | size: `total_bytes` against `received_bytes` |
| download file name / path | the path has no folder | `file_name`, `path` (and `file_uri` for Firefox) |
| download / visit / cookie / login / message time | never | always: `iso_z`, `iso_space`, `raw`, `iso_offset`, `iso_naive`, `epoch`, `epoch_ms`, `iso_space_utc`, `date` |
| visit count | the column equals the visit rows | `visit_count_column`, `visit_rows` |
| search term | `term` equals `normalized_term` | they differ; or it comes from a result URL (`url_query`) |
| page title, visited URL | one row | a URL asked as a `site`, `domain` or `host`: `url`, `host` (downloads too: `host_of_final_url`, ...) |
| cookie host | no leading dot | `host_key`, `without_leading_dot` |
| cookie name, cookie value | one row, value stored plain | value decrypted: the method's name |
| saved username | one live login | |
| saved password | stored as text (rare) | decrypted: `v10_cbc_linux_peanuts`, `v10_gcm_local_state_key`; DPAPI, v20, NSS: `None` |
| login site | origin, realm and action agree | `origin_url`, `signon_realm`, `action_url`, `host` |
| how many downloads / cookies / logins | the whole table of one database is asked for (`how many cookies are stored`), it was read whole, and no deleted row stands beside the live ones | a deleted row beside them: `live_rows`, `with_recovered`; a count of recovered rows: `recovered_rows` |
| how many URLs / pages / sites / history entries | the urls rows, the distinct hosts and the visit rows are one number | they differ: `live_rows`, `distinct_hosts`, `visit_rows` |
| extension id | the key (manifest, CRX) gives it and nothing disagrees | only the folder's name gives it |
| permissions, host permissions | exactly one | the list's joins: `comma`, `comma_space`, `sorted_*`, `space`, `pipe`, `semicolon`, `json`, `json_sorted`, `newline` |
| permission count | no host or optional permissions | `permissions`, `with_host_permissions`, `api_permissions`, `with_optional` |
| background script / service worker, content script, manifest version, extension name / version, update URL | one value | several scripts: joins |
| staged / decoded / hidden command or payload | never | one decoded cell: its chain's name (`base64`, `url>uuencode`, ...) |
| anything `deleted`, `removed`, `recovered`, `in the WAL` | never | always, named `recovered` |
| message text, Fossil project name, check-in comment | one row | |
| message sender | a received iOS message's handle (a sent message's handle is its recipient: `None`) | WhatsApp: `chat_jid` |

What is never answered, whatever rule the words meet (the review of 2026-10-08; each was a plain wrong
answer before):

- **Something derived from a row**: a length or a number of characters, a hash, a size in kilobytes, an IP,
  a port, a top-level domain, a file extension, a duration.
- **Another row than the words pin**: `not`, `other than`, `second`, `before`, `after`, `next`, `least`.
- **`how many` of something that is no row count** (`how many times was the cookie set`), and a count of
  some of the rows (`how many secure cookies`, `how many downloads were interrupted`, a count over two
  databases).
- **A table that was not read whole** (over 20000 rows, or the library gave up or was interrupted after
  2 s): no count, no deleted rows, and a row it did read is unsure under `partial_read`.
- **`first` / `last` over a row with several times** (cookie, login, download) when the words name none
  (`created`, `used`, `expires`, `finished`) and the times disagree.
- An example in a format hint (`e.g. example.com`, `format: ...`) is not taken for a row's name.

Label keys are `sqlite_artifacts.<field>/<artifact kind>`, for example
`sqlite_artifacts.download_time/chromium_history`. One accepted time format answers every later variant of
that key.

## When it says None and you know better

- **Two candidate rows.** Name the row yourself: read the triage, reason to the value, and submit it once
  through the guarded path; or call the readers above by hand.
- **A staged command over several rows** (chunks in visit order): `ev.staged()` lists every decoded cell
  with its record; joining chunks is the agent's call and an unsure answer.
- **A deleted row that fits two tables** is in the triage under both names and is not used for answers.
- **A value under DPAPI or the macOS keychain** is `None`: the key is not in the delivery. Tell the player if
  a question needs it.
- **Text in a Local Storage / LevelDB value**: listed by the triage and in `ev.storage`; no question shape
  answers from it yet.

## Likely label vocabulary (this event's style: lowercase snake_case)

Nothing here is confirmed yet; offer these through `labels.pick`, best first.

- browser: `chrome`, `chromium`, `edge`, `firefox`, `safari`, `brave`
- artifact: `history`, `downloads`, `login_data`, `cookies`, `web_data`, `places`, `local_storage`,
  `session_storage`, `indexeddb`, `extension`, `quarantine_events`, `sms`, `whatsapp`
- recovery source: `wal`, `write_ahead_log`, `rollback_journal`, `freelist`, `unallocated`, `freeblock`,
  `deleted_row`, `leveldb_log`
- encoding of a staged value: `base64`, `base64url`, `url_encoded`, `percent_encoding`, `uuencode`, `hex`,
  `utf16le_base64`
- timestamp kind: `webkit`, `chrome_time`, `prtime`, `unix_epoch`, `unix_ms`, `mac_absolute`, `cocoa`,
  `filetime`, `julian_day`
- protection: `dpapi`, `v10`, `v11`, `app_bound`, `aes_gcm`, `aes_cbc`, `nss`, `keychain`
- extension: `manifest_v2`, `manifest_v3`, `service_worker`, `background_page`, `content_script`,
  `host_permissions`, `all_urls`, `web_request`, `cookies`
- transition (Chromium `visits.transition & 0xff`): `link` 0, `typed` 1, `auto_bookmark` 2, `form_submit` 7,
  `reload` 8, `generated` 5
- download state / danger: `complete`, `interrupted`, `cancelled`, `dangerous_file`, `dangerous_url`
- ATT&CK ids a browser question may want (always a pick): `T1217` browser information discovery, `T1555.003`
  credentials from web browsers, `T1539` steal web session cookie, `T1176` browser extensions, `T1185` browser
  session hijacking, `T1105` ingress tool transfer, `T1070.004` file deletion

## Limits

- The unsure answers are a ranked candidate list, not a guess that gets sent: the agent reads the options
  with `labels.show(...)`, reasons to the one that fits the challenge, and submits it once.
- The WAL reader takes frames by their salts and does not verify frame checksums. Overflow pages are
  followed in the committed image only.
- The carve stops after 0.6 s per database (`carve stopped early` in the triage) and is skipped for the
  databases reached after 1.5 s of carving in one delivery; cells that page images still point at are
  always read. A count beside a carve that did not finish is unsure.
- A `-wal` or `-journal` is paired with the database of the same path only (or the one database of that
  name when the pair appears under two keys): SQLite would replay any well-formed WAL into any database.
- The plain answers rest on the question's words. Random damage inside a row that SQLite still reads
  without an error is answered as read.
- WITHOUT ROWID tables and index pages are not carved. SQLCipher and other encrypted databases are not
  opened. IndexedDB values (V8 serialisation) are carved as strings only.

## Real artifacts (2026-10-08)

Run on real Chrome, Firefox, Safari, iMessage, quarantine and WAL files, two LevelDB folders and the Fossil
repository of Huntress CTF 2024 "Ancient Fossil": `tests/real/test_real_sqlite_artifacts.py`, details in
[real-data.md](real-data.md).

- A Fossil repository's triage ends with `FLAG-LIKE in rid N` and `ODD ONE OUT rid N` lines
  (`sa.fossil_notable(sa.fossil_blobs(db))`); "what is the flag" is the one-option pick `flag/fossil_blob`.
- Chromium's `downloads.start_time` is read as Unix seconds when it is too small for WebKit time (before version 24).
- "What file was downloaded from <site>" asks for the file (`file_name`, `path`), not the URL.
- Checked against `sqlite3`: live row counts of every table, the view through a `-wal`, and the facts the tests name.
- Speed: nothing over 0.3 s (a 5 MB places.sqlite 0.06 s, a 1 MB LevelDB table 0.17 s).
- Review (2026-10-08): the carve of deleted rows has a wall-clock budget (`CARVE_SECONDS`, 0.6 s). When it runs out
  on a loaded machine a count that is otherwise plain is a one-option pick of the same number: the same file can
  replay plain or unsure.
