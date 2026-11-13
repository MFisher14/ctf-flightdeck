# OSINT playbook (CSCTF 2026)

An OSINT answer is almost never in the bytes. The delivery and the question text carry **leads**
(a handle, a domain, a photo's GPS, an e-mail, a crypto address); the flag is found by searching a
**public** source. Our engines extract and rank leads offline first.  After review, the online lane can
make a few sequential, rate-limited, single-item queries to allow-listed third-party public sources;
it returns evidence rows, never an answer verdict.  The player makes the final pin.

> Scope (read first). OSINT touches the live public web. The CSCTF fair-play rules still bind:
> never touch the CTFd platform, scoreboard, Chronos services, other squads, or any instance not
> assigned to us. Ordinary OSINT lookups may go only to third-party public data providers.  Use one
> reviewed lead at a time, sequentially, with the client's hard throttle/caps: **no mass scanning,
> username variant sweeps, scraping, parallel enumeration, or flooding**. Never send the player's
> e-mail, handle, identity, tokens, or secrets to a third party. No breach dumps or paid people-search
> services. **Record the public URL that supports every identification** for the write-up.

## What the AI can and can't do here (OSINT is AI-weak, not AI-useless)

OSINT had the lowest solve rate in 2025 and is the team's weakest-for-AI category — but that's about the
*final intuition call*, not the whole challenge. Split the work:

- **AI-strong (do these, they're most of the challenge):** metadata extraction (EXIF/GPS/maker-notes,
  document authorship, PDF/office props), OCR of signage/text in images, lead extraction and pivoting
  (usernames/e-mails/domains/handles), DNS/WHOIS/certificate-transparency (`crt.sh`) and Wayback history,
  public-DB lookups (NVD, MITRE ATT&CK, HIBP, package registries), decoding/parsing, and **multimodal
  visual recognition** — a vision model can often name a skyline/landmark/architecture style from a photo
  or a photogrammetry texture, which narrows country→city→spot fast.
- **Human-led (hand these up):** the ambiguous final geolocation pin, face/person identification, and
  judgment calls where several candidates look equally plausible. Gather all the evidence, propose ranked
  candidates with reasoning, and let the player make the final call rather than guessing.

So: run the full mechanical + visual pipeline, converge as far as the evidence allows, and only escalate
the irreducible intuition step. Don't skip an OSINT challenge — accelerate it and hand off the last 10%.

### Geolocation sub-workflow (photos / 3D scans, e.g. 2025 "Sakot")

1. `exiftool` the image(s) for embedded GPS / camera / software / timestamps (sometimes the answer is
   literally in EXIF GPS).
2. **View the image with the Read tool** (vision): read buildings, skyline, waterfront, monuments,
   vegetation, flags, vehicle plates, and any **readable signage/text** (OCR with tesseract if small).
3. Identify the specific landmark via WebSearch/WebFetch (skyline/architecture + any business names), then
   reverse-geocode it to coordinates; cross-check against a map. For a 3D scan, the `.jpg` texture atlas
   carries the recognizable imagery (the `.obj` is just the mesh).
   - **Don't anchor on the wrong cue.** Rehearsal lesson (Sakot): the agent fixated on a text-rich object
     in the scene (a parking machine's serial) and chased it into the wrong district (~240 m off), when the
     intended cue was the **harbour/waterfront skyline**. Identify BOTH the broad scene (skyline, water,
     street grid) and the fine detail, geolocate each independently, and cross-check. Hand the player a
     skyline crop for a 2-second sanity-check — the exact pin is the human call.
4. Produce lat/long to the brief's precision (often 4 decimals, no spaces) → submit with
   `allow_nonstandard=True` (OSINT answers aren't `CSCTF{...}`).

## First moves

1. `./csctf check <id>` — skip if a teammate already solved it.
2. Read `workspace/<id>-<slug>/challenge.json` (description + `connection_info`): the question wording
   is the lead ("who runs…", "where was this taken", "what's the registrant…").
3. Run the lead extractor on every delivered file:
   `.venv/bin/python solvers/toolkits/osint.py workspace/<id>-<slug>/files/*`
4. If there is mail (`.eml` / `.msg` / mbox): `… solvers/toolkits/email.py <file>`.
5. For a photo, also pull metadata in Docker (`exiftool`) and any QR/barcode (`zbarimg`) — below.
6. Start at the **top lead** and pivot; reused handles/e-mail local parts link a person's accounts.
7. If a public lookup is needed, use `osint_pivot.py --online` or `osint_online.py --online` on exactly
   one reviewed lead. Do not script multiple invocations; a human chooses the next pivot from the first
   response. Keep `OSINT_PRIVATE_IDENTIFIERS` set to comma-separated player identities as a denylist.

## Engines (verified CLIs)

Run every command from the ctf-tools checkout root with `.venv/bin/python` (or `.venv/bin/python -m ctf run <engine>`), with `CTF_EVENT` set to the event slug (`events/<slug>/event.toml`). The workdir comes from `ctf.paths`: `$CTF_WORKDIR`, else `~/ctf-work/<event>`; `.venv/bin/python -m ctf workdir` prints it, and `workspace/` on this page means it.

### Lead extraction — `solvers/toolkits/osint.py`

```
.venv/bin/python solvers/toolkits/osint.py <file> [<file> ...]
```

Offline. Prints a ranked leads table (`rank | kind | value | seen in | first search plan`) plus a
"how to work a lead" note. Pass **files**, not a directory (a bare dir errors unless it is a saved
attempt with `attempt.json`/`status.json`). It reads:

- handles/`@name`, e-mails, domains, URLs; social/code/paste **profiles** as `platform:username`
  (GitHub, GitLab, gist, Twitter/X, Reddit, Telegram, Keybase, Pastebin, fediverse `@u@host`, …)
- network IDs: IPv4/IPv6 (validated — bad octets dropped), MAC (OUI lead), Tor `.onion` v2/v3
- crypto addresses: BTC (base58check-verified) and ETH verified; bech32/Monero kept **unverified**
- phone numbers, coordinates (decimal + DMS)
- **EXIF device + GPS** from JPEG/TIFF/PNG(`eXIf`)/WebP/HEIC/MP4/MOV/XMP: make, model, software,
  timestamp, lat/long
- **document metadata**: PDF `/Info`, PNG text chunks, XMP packets, OOXML `core.xml`/`app.xml`
  (`dc:creator`, `lastModifiedBy`, Company, Manager, dates)
- WHOIS/RDAP fields when a response is in the delivery; X.509 subjectAltName **subdomains** (needs
  the `cryptography` lib); hashes, dates, candidate person/org names; a language hint
- **QR / barcode** payloads when `pyzbar`+`Pillow` import (else skipped — use `zbarimg` in Docker)

What it answers vs. leaves to you (`solve_set`): a **plain** value only when the question names a
byte-fact kind that has exactly one distinct value in the delivery (e-mail, URL, domain, handle,
phone, EXIF make/model/software, QR payload, a hash, IPv4, `.onion`). A **GPS/coordinate** is never
plain — it comes back as `labels.pick` renderings (decimal/DMS/hemisphere) keyed by its Ref; IPv6,
MAC, crypto-address case, subdomains and social profiles also come back as `labels.pick` candidates.
The person behind a handle, a photo's city, an employer → **None**, with the lead left for your search.

The generated labels are review objects, not judge probes. Render and corroborate them locally; this
repository does not use the retired Huntress `tools/verify.py` workflow.

### E-mail / phishing — `solvers/toolkits/email.py`

```
.venv/bin/python solvers/toolkits/email.py <file> [<file> ...] [--json] [--no-qr]
```

Offline; `.eml` / `.msg` / mbox identified by bytes. Per mail it prints: Subject; Date in six forms
(`iso_utc_z`, `epoch`, …); Message-ID; From / Reply-To / Return-Path / To with display names and the
mismatch flags; every **Received hop** (newest first) with its IPs; the originating-IP candidates
(and earliest-public hop); SPF/DKIM/DMARC results; each attachment's declared vs. true type, size,
SHA-256/MD5/SHA-1; every URL with its refanged and `hxxp://a[.]b` defanged form; homoglyph/IDN
domains; QR payloads; HTML-smuggling download name + payload hashes; `indicators`; the ATT&CK id.
`--json` emits one dict per mail. Good for "who really sent this / what IP / which look-alike domain".

### Live chat challenge — `solvers/toolkits/chat_target.py`

An "AI Arena"-style challenge where you talk to a live service is a different tool with its own
request caps. Point it only at the squad's assigned target; keep the caps.

## Docker tools (csctf-sandbox:2, already up)

Detonate / parse untrusted media only in the sandbox, never on the Mac. `{in}` is the dropped file.

```
# EXIF / GPS / maker notes from a photo
python3 tools/sandbox.py run --in photo.jpg exiftool {in}

# QR codes and barcodes (when pyzbar is absent from the host)
python3 tools/sandbox.py run --in code.png zbarimg {in}

# OCR text burned into an image
python3 tools/sandbox.py run --in sign.png tesseract {in} stdout

# strings / file for a quick look
python3 tools/sandbox.py run --in blob.bin strings {in}
```

`python3 tools/sandbox.py tools` lists everything; `status` confirms it is up.

## Common CSCTF techniques → engine

- **Geolocate a photo** → `osint.py` reads EXIF GPS (or `exiftool` in Docker); plot the lat/long on a
  map + satellite layer, confirm landmarks/signage. GPS is a `labels.pick` (rendering), not auto-plain.
- **Who owns / runs this** → `osint.py` surfaces the handle/e-mail/domain; pivot on code hosting,
  package registries, DNS, certificate transparency (crt.sh), RDAP/WHOIS, the Wayback Machine.
- **Reused username across sites** → the handle lead; search the exact string on GitHub/GitLab/npm/PyPI
  and social profiles; a reused local part often links accounts.
- **Phishing e-mail** → `email.py`: originating IP from the earliest public Received hop, Reply-To /
  Return-Path / display-name spoof, the look-alike (homoglyph/IDN) domain, the malicious URL.
- **QR / barcode in an image** → `zbarimg` in Docker (or `osint.py` if pyzbar is present).
- **Crypto address** → `osint.py` verifies BTC/ETH; look it up on a public block explorer by hand.
- **Document author / tooling** → `osint.py` reads PDF `/Info`, OOXML `core.xml`, XMP (`CreatorTool`,
  `dc:creator`, Company).

## Getting the flag out and submitting

1. The flag is whatever the challenge asks for, phrased in the flag format
   (default `(?:csctf|CSCTF|flag|chronos|CHRONOS|CTF)\{…\}`; the format is the event profile's `[flag]` (`events/<slug>/event.toml`, read through `ctf.flagfmt`)).
2. When `osint.py` returns `labels.pick` candidates, render with `labels.show(<value>)`, reason to the
   **one** correct rendering, and submit that. There is no judge — you pick one and submit once.
3. Submit through the guard — never loop candidates:
   ```
   ./csctf submit <id> 'csctf{...}'          # quote to protect the braces from the shell
   ```
   or from a solver: `ctf.submit.guarded_submit(ctfd, ch, flag, provenance="osint: EXIF GPS → map")`.
   The guard does flag-format check, dedupe, 3 s pacing, skip-solved, and **stops after 3 wrong on one
   challenge** — if you hit that, stop and tell the player. Record the solve path in `notes.md`.

## Scan-index pivots: the origin behind Tor or a CDN, and its back office (B-114)

"Find the origin" and "find the back office" are scan-index questions: which host:port serves this
certificate, this favicon or this page title, and what else listens on that host. Ask the indexes
through their official APIs with `python -m ctf scan-index`; it touches no challenge host.

```sh
# 1. Capture what the hidden or fronted site hands every visitor (B-091 / B-089).
.venv/bin/python -m ctf tor-fetch https://<onion>/ --out evidence/      # leaf-cert.der, favicon.bin, body
# 2. Pivot each one to host:port. Give the FILE: each index wants a different hash of it.
.venv/bin/python -m ctf scan-index cert --cert-file evidence/leaf-cert.der
.venv/bin/python -m ctf scan-index favicon --file evidence/favicon.bin
.venv/bin/python -m ctf scan-index title "the exact page title"          # the behind-a-CDN case
# 3. Confirm ONE candidate with one request (same leaf certificate, or same body hash), in scope.
# 4. Union the confirmed origin's ports: the back office is the port the public site does not use.
.venv/bin/python -m ctf scan-index host <origin-ip>
.venv/bin/python -m ctf scan-index quota                                 # keys present, requests used
```

- **Each index stores a different form.** Shodan: certificate SHA-1 (or serial) and the mmh3
  `icon_hash`. Censys: certificate SHA-256 and favicon MD5. FOFA: certificate serial and `icon_hash`.
  Netlas: SHA-256 of both. A bare SHA-256 reaches only Censys and Netlas; the report lists the others
  as `skipped` with the form they need.
- **Scanners disagree, so read the union.** At CSCTF one index showed only ports 22 and 443 for an
  origin whose panel was on 8080 in another. `host` lists every port any index has, who has it, who
  has the host without it (`NOT listed by`), and the freshest scan. Trust the freshest.
- **"Not asked" is not "no hit".** A provider with no key, no budget left, or no entry in the event's
  `rules.public_fetch_allow` is listed with that reason. Do not report unsolved until every provider
  has answered or has a reason it cannot.
- **Cloudflare edges and other CDNs are labelled** (`CDN edge ... not an origin`) and listed last.
- **Archived bodies are leads, never answers.** `host` prints UUIDs and `key:`/`token:` values found
  in a body a scanner archived. Confirm with one GET to the listed port through the in-scope web
  client; a UUID in image metadata or an old scan can be a decoy. Never guess paths or scan ports.
- **No anonymous route.** A 401/403 (`auth`) or a spent quota (`quota`) is reported and that provider
  is left alone: no result-page scraping, no browser User-Agent retry around a bot check.
- **Before the event (human):** register the accounts and export `CTF_SCAN_INDEX_SHODAN_KEY`,
  `CTF_SCAN_INDEX_CENSYS_TOKEN` (+ `CTF_SCAN_INDEX_CENSYS_ORG` on a paid plan),
  `CTF_SCAN_INDEX_FOFA_KEY`, `CTF_SCAN_INDEX_NETLAS_KEY`; add the four API hosts (and
  `internetdb.shodan.io`) to the event's `rules.public_fetch_allow`. Each provider gets 25 requests
  per event workdir unless `CTF_SCAN_INDEX_BUDGET[_<PROVIDER>]` says otherwise; answers are cached in
  the workdir, so a sibling challenge on the same origin costs nothing.

## Lead-to-pivot plans and guarded public lookups

After `osint_leads.py` extracts evidence, `osint_pivot.py` turns each lead into a ranked manual plan:

```sh
.venv/bin/python solvers/toolkits/osint_pivot.py --lead username=alice.dev
.venv/bin/python solvers/toolkits/osint_pivot.py --lead domain=example.org --json
.venv/bin/python solvers/toolkits/osint_pivot.py --text 'contact alice@example.org or @alice' --json
```

It builds username profile URLs, e-mail Gravatar/HIBP/breach checks, domain crt.sh/RDAP/Wayback-CDX/
DNS/search queries, and pivots for IPs, CVEs, hashes, wallets and coordinates. URLs are strings only:
the default engine performs no DNS or HTTP. Secret-shaped leads are redacted and receive containment
advice instead of a third-party lookup, so a token is never embedded in a generated URL.

For one reviewed challenge lead, opt into the public-source client:

```sh
# One RDAP observation; the domain must not be CSCTF/Chronos infrastructure.
.venv/bin/python solvers/toolkits/osint_pivot.py --lead domain=example.org --online --json

# Narrow alternatives, one at a time after human review.
.venv/bin/python solvers/toolkits/osint_online.py dns example.org --record-type MX --online
.venv/bin/python solvers/toolkits/osint_online.py ct example.org --online
.venv/bin/python solvers/toolkits/osint_online.py wayback https://example.org/ --online
.venv/bin/python solvers/toolkits/osint_online.py gps '44.4268,26.1025' --online
.venv/bin/python solvers/toolkits/osint_online.py geocode 'exact landmark name' --online
```

Guardrails enforced in code:

- fixed HTTPS provider allowlist and redirect revalidation; no arbitrary fetch URL;
- global and per-provider request caps, at least one second between requests (1.5 s default), bounded
  responses/timeouts, and failed attempts count against the cap;
- one exact lead per client, so it cannot become a username/domain scanner;
- CSCTF/Chronos names, local/private addresses, secret-shaped data, and configured private identities
  are rejected before transport;
- raw e-mail lookup is off by default and needs `--challenge-identifier`; HIBP credentials and private
  breach data are never automated;
- every result says `requires_human_pin`; top-ranked does not mean correct.

The provider adapters cover RDAP/WHOIS-style records, DNS-over-HTTPS, certificate transparency,
Wayback CDX, Nominatim geocode/reverse-geocode, narrow public web/record/paste searches, and exact
public-profile observations. Reverse-image upload stays a single manual action because a modern image
search page makes many opaque subrequests that cannot honor the hard request cap. Bring one result
caption or landmark name back into the guarded text/geocode client.

### Photo geolocation with capped enrichment

`osint_geo.py <image>` remains fully offline (EXIF/XMP/IPTC, GPS, tiled OCR, script/phone/place clues).
`osint_geo.py <image> --online` sends only its single strongest clue: EXIF GPS to Nominatim, otherwise
the first specific signage/landmark phrase. Its ranked coordinates are scene-check candidates, not a
submission value. The deterministic test suite injects a fake transport and never reaches a public site.

`osint_geolocate.py` works over a frozen dataset outside the repo (`$CTF_GEO_DATASET`; unset is a
`blocked` result naming the variable) and lists candidates; a reader names the place:

```sh
.venv/bin/python solvers/toolkits/osint_geolocate.py open photo.jpg          # sign OCR -> brands and named features
.venv/bin/python solvers/toolkits/osint_geolocate.py venue "Luna Sports Hall"   # polygon centre, outline, entrances
.venv/bin/python solvers/toolkits/osint_geolocate.py osm constraints.json    # tags, outline size, distance joins
.venv/bin/python solvers/toolkits/osint_geolocate.py skyline observed.json candidates.json   # DEM horizon fit
.venv/bin/python solvers/toolkits/osint_geolocate.py check PAGE_URL ID LAT LON --provenance "why this pin"
```

`check` posts one named pin to the challenge page's own map-pin checker (the page's host must be in
the live-service scope) and reads the flag from the reply; `--submit` sends that flag through the
submit gate. Every post is a capped attempt: at most 3 per challenge and per checker endpoint (fewer
when the event's `wrong_answer_stop` is lower), never the same pin twice. More needs `--max-attempts N
--cap-note "<the player's say>"`, which goes to the ledger. It posts nothing on a guess: field names
or an encoding the page does not show must be named (`--lat-field`, `--lon-field`, `--encoding`).

For geometry and sky clues, `osint_geo_math.py` is fully offline:

```sh
.venv/bin/python solvers/toolkits/osint_geo_math.py distance 44.4268 26.1025 48.8566 2.3522
.venv/bin/python solvers/toolkits/osint_geo_math.py sun 2026-11-07T13:00:00Z 44.4268 26.1025
.venv/bin/python solvers/toolkits/osint_geo_math.py polaris 44.5
.venv/bin/python solvers/toolkits/osint_geo_math.py locus 20 15 35
```

The library also exposes `rank_shadow_candidates(timestamp, shadow_bearing, candidates)`. Calibrate
camera-up against true north first. NOAA solar position, Polaris altitude, and star-altitude loci are
approximate constraints: horizon/refraction, clock, lens perspective, and orientation errors can exceed
the numerical residual, so the engine never promotes the first row to a location verdict.
