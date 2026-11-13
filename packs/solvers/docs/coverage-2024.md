# CSCTF 2024 coverage matrix (all 69) → our engines

Every 2024 challenge (source of truth: `docs/prep/.../csctf2024-design.md`, the organizer's own
post-event table) mapped to how we'd solve it and our status. 2024 is the better predictor than 2025
for the 2026 syllabus (same org, same `Concepts.md`). Legend:

**FAST** = covered + quick (trivial decode / one host tool) · **COVERED** = have the engine, works ·
**+NEW** = handled by the pre-event speed builds (netplay / audio-tones / fastlane) · **HARD** =
low-solve tail, needs codex+guidance / human pin · **LIVE** = Dockerized remote, can't pre-test (works
once the service is up) · **GAP** = no path today; the fix is named inline and collected in the
Takeaway. Points/solves are the final dynamic value (initial 500, decay 50, floor 100) and solve count
— higher solves = cheaper, first-blood-race points.

## Crypto (7)
| name | pts/solves | our path | status |
|---|--:|---|---|
| 3.146416102 | 426/9 | name says bases 64/16/10/2 → `warmups/crib_decode.py` + `warmups/layered_decode.py` peel the chain in reverse (b64→hex→decimal-pairs→binary→ASCII); fastlane auto-decoder | COVERED |
| Authentication | 100/51 | JWT in `request.txt` → `crib_decode.py` (b64url payload) / fastlane; read `"flag"` claim | FAST |
| Double Trouble | 155/33 | Morse-written-in-binary → `warmups/layered_decode.py` (binary→0/1→dot/dash→Morse) + `warmups/fractionated_morse.py` for the Morse table; case-insensitive flag | COVERED |
| Hashes | 193/28 | chained hash pipeline → host `md5sum/sha1/sha256/sha512sum` + `john` + rockyou (SHA1 `6e6a…`→`#winner`) | COVERED |
| Signed Flask | 323/17 | crack Flask SECRET_KEY → `toolkits/flask_tools.py` / `toolkits/werkzeug_pin.py` + `flask-unsign[wordlist]` rockyou; flag = the key `98765432123456789` | COVERED |
| Weak Password 1 | 105/47 | md5(`YEAR_football`) → `common/psearch.py` over a reasoned year range (1900–2024), not a flag sweep | FAST |
| Weak Password 2 | 149/34 | md5(`rockyou_word_YEAR`) latin-1 → `common/psearch.py` rockyou × year range → `dragon_1987` | COVERED |

## Forensics (5)
| name | pts/solves | our path | status |
|---|--:|---|---|
| APT Hunting | 438/8 | malware triage → `toolkits/malconfig.py` / `toolkits/maldoc.py` extract C2 (`210.48.231.182`); **attribution** (Turla/APT28, Russia, 2004) is threat-intel/OSINT → `toolkits/osint.py` + human | HARD |
| Magical Bytes 1 | 149/34 | 38 junk bytes before PNG magic → `common/image_repair.py` / `toolkits/carve_stego.py` carve | FAST |
| Magical Bytes 2 | 468/5 | GIF magic inverted (`74 94 64 83`→`47 49 46 38`), skip 13 → `common/image_repair.py` header fix | COVERED |
| Nothing Here | 458/6 | VBA→PowerShell in .doc → `toolkits/maldoc.py` + `script-analysis/officevba.py` + `script-analysis/powershell.py` (base64 decode, 3-snippet reassembly). **Note: old flag format `SMCC2024{...}`** | COVERED |
| VirusTotal.exe | 104/48 | extension lie (text as .exe) → `metadata-forensics/file_properties.py` / host `strings` | FAST |

## Linux (9) — interactive services are LIVE
| name | pts/solves | our path | status |
|---|--:|---|---|
| Calculator | 337/16 | `eval()` blacklist bypass over nc (`open("FLAG.txt".lower())`) → reason the bypass, drive with `tools/netplay.py --script` | COVERED/LIVE |
| Custom Request 1 | 297/19 | header-driven query (`?python=<ver>`) → `web/passive_checks.py` + host `curl -sI` | COVERED/LIVE |
| Custom Request 2 | 337/16 | path=b64("secret") + header `sha256("text/plain")` + query → `web/browser_recon.py` + `crib_decode.py` for the b64/sha256 | COVERED/LIVE |
| Database | 297 dyn | remote MySQL `SELECT … LIKE '%CSCTF%'` → `toolkits/net_dbproto.py` / host `mysql` client (creds in description) | COVERED/LIVE |
| Extraction 1 | 126/39 | regex: the one line NOT matching → host `grep -Evn` | FAST |
| Extraction 2 | 107/46 | the one non-MD5 line → host `grep -vnE '^[a-fA-F0-9]{32}$'` | FAST |
| John | 184/29 | password-protected zip → `common/archive_passwords.py` + host `zip2john`+`john`+rockyou (pw `" school13"`, leading space) | FAST |
| Lite | 111/44 | SQLite browse → `toolkits/sqlite_artifacts.py` / host `sqlite3` `WHERE password LIKE '%CSCTF%'` | FAST |
| My secure password | 283/20 | /etc passwd+shadow → host `unshadow`+`john` rockyou, take longest → `manchesterunited` | COVERED |

## Misc (10)
| name | pts/solves | our path | status |
|---|--:|---|---|
| Customer support | 100/59 | Discord ticket channel + `\|\|spoiler\|\|` | **GAP — player-only (Discord)**; no engine, hand to player |
| Decoding | 107/46 | QR → binary → base64×5 → `crib_decode.py` for the decode chain | **COVERED** — `solvers/toolkits/qr_decode.py` (+ dependency-free `qr_matrix.py`/`matrix_barcodes.py`) decode the QR step, then FAST |
| Index | 104/48 | view-source the platform index → `web/browser_recon.py` / host `curl` | FAST |
| Onions | 364/14 | EXIF → .onion → nested steghide (stegseek rockyou, pw `onion`) → `metadata-forensics/file_properties.py` + `toolkits/stego_tools.py`; **.onion fetch is a host Tor step (human/LIVE)** | COVERED/LIVE |
| Participate | 323/17 | Google Form analytics page (creator view) | **GAP — player-only (Google Forms)**; no engine |
| Prank | 100/53 | VBS message-box loop, base64 flag → `script-analysis/vbs_interp.py` / `crib_decode.py` | FAST |
| Rules | 100/60 | read Discord rules channel description (most-solved, free) | **GAP — player-only (Discord)**; free first-blood for the player |
| Shopping list | 468/5 | PyYAML unsafe load RCE (`!!python/object/apply:subprocess.check_output …`), blacklist bypass → `toolkits/deser_chain.py` reasoning, drive over nc | COVERED/LIVE |
| Simple quiz | 100/53 | Google Forms page source / hidden elements → `web/browser_recon.py` / DevTools | COVERED |
| Uncommon | 458/6 | mirror text → digit pw → steghide → Friderici windows cipher → OCR + `toolkits/stego_tools.py` + `common/classical.py`; **mirror-writing + Friderici windows cipher are not in `classical.py`** | HARD/GAP(partial) — add Friderici + mirror to `classical.py` |

## OSINT (8) — research + human pin
| name | pts/solves | our path | status |
|---|--:|---|---|
| Breached | 138/36 | identify BreachForums owner → `toolkits/osint.py` news/wiki pivot; final name is human-verified | COVERED |
| ChronosPK 1 | 138/36 | find organizer Instagram ("Follow me") → `toolkits/osint.py`; flag = full URL | COVERED |
| ChronosPK 2 | 169/31 | flag in a deleted GitHub commit → `web/vcs_exposure.py` + host `git log --all`/GitHub events API | COVERED |
| Cyber Golan | 169/31 | geolocate car photo → what3words → `toolkits/osint_geo.py` (EXIF/landmark) + human geo pin | HARD |
| Spy Operation | 500/1 | car owner by model/year from a shared DB → `toolkits/osint.py`; needs the specific owner DB, human | HARD |
| WHOis #1 | 102/49 | DNS TXT of org domain → `toolkits/network.py` / host `dig TXT` | FAST |
| WHOis #2 | 101/50 | robots.txt Disallow → `web/browser_recon.py` / host `curl` | FAST |
| WHOis #3 | 310/18 | domain-intel combo (MX/ASN/ports/registrar) → `toolkits/osint.py` web-check pivots; **note: 3 accepted flags** | COVERED |

## Programming (6) — all the "compute-over-a-socket" family → **+NEW netplay**
| name | pts/solves | our path | status |
|---|--:|---|---|
| Geography Master | 271/21 | 30 country→capital prompts (dyn) → `tools/netplay.py` + `countryinfo` handler | +NEW |
| Lost flag | 310/18 | 50×50 grid of QR codes, regex `CSCTF{[0-9A-F]{17}}` filter → bulk QR decode + regex | **COVERED** — `solvers/toolkits/qr_decode.py` (grid-split) + `flagscan.py` regex filter |
| Math Master | 297/19 | CSV numbers + op word, <1 s (dyn) → `tools/netplay.py` math handler | +NEW |
| Multiply 1 | 193/28 | repeat char N times (dyn) → `tools/netplay.py` | +NEW |
| Multiply 2 | 223/25 | same, 60 rounds incl. digits/punct → `tools/netplay.py` (keep-alive) | +NEW |
| Pwntools | 234/24 | quiz on pwntools API (dyn) → `tools/netplay.py --script` scripted answers | +NEW |

## Pwn (4)
| name | pts/solves | our path | status |
|---|--:|---|---|
| Dynamic loader | 500/0 | shc-compiled bash "loader" writes flag to hidden `/tmp` dir → `tools/sandbox.py` (docker/pwn) `strace ./vuln` → find `openat(".hidden")` | COVERED (sandbox) |
| I returned to win | —/— | classic ret2win (`scanf("%s")` into char[16], overflow 28→`hacked()`) → `toolkits/pwn_exploit.py` | COVERED/LIVE |
| Moooooore | 126/39 | `gets()` overwrites adjacent `int enough` → `toolkits/pwn_exploit.py` (50+ junk) → `system("cat flag")` | COVERED/LIVE |
| Trace my libraries | 297/19 | XOR-obfuscated pw revealed in strcmp → `binary/static_re.py` + `tools/sandbox.py` `ltrace -s 100` | COVERED |

## Rev (3)
| name | pts/solves | our path | status |
|---|--:|---|---|
| Elite 1 | 169/31 | `scanf("%d")==0x539` → `binary/static_re.py` (constant extract) → input 1337 | FAST |
| Elite 2 | 203/27 | `input ^ 10101010 == 0x499602D2` → `binary/static_re.py` + python reverse-XOR → `490c23c0` | COVERED |
| Source | 126/39 | flag split across 5 string constants → host `strings -n3 \| grep -A4 CSCTF{` / `binary/static_re.py` | FAST |

## Stegano (5)
| name | pts/solves | our path | status |
|---|--:|---|---|
| Call me | 246/23 | phone-keypad ciphers in a screenshot → OCR (host `tesseract`) then DTMF + multitap-ABC decode | **GAP (partial)** — no phone-keypad/DTMF decoder; add `multitap`/`dtmf` to `common/classical.py` → then COVERED |
| Frequencies | 138/36 | spectrogram message in WAV → `toolkits/audio_tones.py` / `toolkits/carve_stego.py` spectrogram | FAST |
| Hiding in PDF | 415/10 | PDF page locked with default pw (`password`) → host `qpdf --decrypt` / `toolkits/pdf_revisions.py` | COVERED |
| More pixels | 271/21 | JPG SOF0 height field cropped (`ff c0` block) → `common/image_repair.py` | FAST |
| Neighbour | 448/7 | text at RGB(254,254,254) on white → `common/image_repair.py` / `toolkits/carve_stego.py` pixel-threshold (OpenCV) | COVERED |

## Web (9) — all LIVE (Dockerized)
| name | pts/solves | our path | status |
|---|--:|---|---|
| Basics 1 | 100/59 | password in HTML comment → `web/browser_recon.py` / host `curl` | FAST |
| Basics 2 | 122/40 | User-Agent whitelist ("Minix NEO X5 mini") → `web/passive_checks.py` + `curl -A` | COVERED/LIVE |
| Basics 3 | 138/36 | directory listing (`php -S`) → `web/endpoint_inventory.py` browse `/files/flags/flag.php` | COVERED/LIVE |
| Basics 4 | 155/33 | cookie `user=guest`→admin → `web/session_recon.py` | COVERED/LIVE |
| Cerealized | 364/14 | python pickle in cookie (`__reduce__`→`os.getenv('FLAG')`) → `web/deser_detect.py` + `toolkits/deser_chain.py` | COVERED/LIVE |
| Options | 377/13 | HTTP method chain (GET→/one→/hint→POST→PUT) → `web/endpoint_inventory.py` + `web/passive_checks.py` (405 leaks methods) | COVERED/LIVE |
| PHP is simple | 415/10 | `unserialize(php://input)` object injection → `toolkits/web_exploit.py` + `web/deser_detect.py` | COVERED/LIVE |
| Proxy man | 113/43 | flag fetched via JS, never shown → `web/js_recon.py` + `web/response_carriers.py` (read `generate_flag.php`) | COVERED/LIVE |
| Simple upload | 403/11 | unrestricted upload → webshell → `toolkits/web_exploit.py` / `web/post_exploit.py` (`shell.php`) read `hidden_secret_flag.php` | COVERED/LIVE |

## Windows (3)
| name | pts/solves | our path | status |
|---|--:|---|---|
| DB | 105/47 | MS Access `.mdb` → read `auth_user.password` → needs a Jet/Access reader | **GAP (minor)** — `ese_reader.py` is ESE not Jet; add `mdbtools` (`mdb-export`) host recipe → then FAST |
| Together | 126/39 | multipart 7z (split `.001`–`.009`) → `tools/unpack.py` (recursive) / host `7z x archive.zip.001` | FAST |
| Wi-Fi | 100/51 | organizer GitHub repo, flag = last SSID in demo image → `toolkits/osint.py` + Read the image | COVERED |

---

## Takeaway — GAPs grouped by family

Of 69, the vast majority have a path (FAST/COVERED/LIVE/+NEW). The genuine GAPs cluster into a few
families the gap-builder agents / orchestrator can close:

- **Player-only / social (no engine, by design):** `Customer support`, `Rules` (Discord channels),
  `Participate` (Google Forms creator analytics). Also `Onions`' `.onion` fetch is a human/Tor step.
  Action: none buildable — surface to the player immediately (Rules-type is the free first-blood). The
  2026 "sanity" + Discord/social points land here.
- **QR decoding (now COVERED, recurred twice in 2024):** `Decoding` (Misc) and `Lost flag` (Programming,
  a 50×50 grid). `solvers/toolkits/qr_decode.py` (pyzbar/zbar + grid-split) and the dependency-free
  `qr_matrix.py`/`matrix_barcodes.py` (QR/DataMatrix/Aztec/PDF417) handle both.
  Closing this turns both to FAST/COVERED and is the single highest-leverage gap build.
- **Phone-keypad ciphers (classical gap):** `Call me` (DTMF + multitap-ABC off an OCR'd screenshot).
  Action: add `multitap`/`dtmf` decoders to `common/classical.py`.
- **Niche classical ciphers (classical gap):** `Uncommon` needs mirror-writing + the Friderici windows
  cipher. Action: add both to `common/classical.py` (low frequency, but a 458-pt tail).
- **MS Access `.mdb` reader (missing host recipe):** `Windows/DB`. Action: add `mdbtools`
  (`mdb-tables`/`mdb-export`) to setup + a reader recipe; `ese_reader.py` only covers ESE.
- **OSINT human-pin tail (intrinsic, not a build):** `Cyber Golan`, `Spy Operation`, and the
  attribution half of `APT Hunting` converge with `osint*`/`malconfig` engines but the final pin
  (geo/person/APT attribution) is a human call — gather and escalate, never blind-guess.
</content>
