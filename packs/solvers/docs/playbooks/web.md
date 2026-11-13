# Web playbook — CSCTF 2026

Web is the lane's long pole: a lot of recon, then one narrow exploit class. The engines here are
either **offline readers** (safe to run on the Mac — logs, HAR, JS, source, cookies are inert data)
or they **drive a scope-locked `WebClient`** against the one assigned target. Nothing here loops over
flags, scans broadly, or touches anything but your squad's target.

**Hard rules for this category (live target — do not cross):**
- Only the **assigned target**. `web.WebClient` is scope-locked to one scheme+host+port; it refuses
  off-host URLs (`OutOfScope`), does not follow a redirect that leaves scope, and stops for the player
  with `VPNRequired` when the target is unreachable. Keep it that way.
- **No flag brute-forcing, no flooding, no mass scanning.** Recon tools keep a `--max-requests` cap —
  keep it. One reasoned flag, submitted once, through the guard.
- Platform/scoreboard/other squads are **never** targets. A platform bug goes to CSCTF staff, not a solve.

Flag shape: the event profile's `[flag]` (`events/<slug>/event.toml`, read through `ctf.flagfmt`) (CSCTF: `csctf{...}` / `flag{...}` / `chronos{...}`). Put the real
format in the profile the moment it's known.

---

## 1. First moves (the moment you open a web challenge)

1. `./csctf pull <id>` — downloads any files into `workspace/<id>-<slug>/` and runs triage (routes web to
   the recon/readers plus the offline SSTI, SQLi, auth, object-reference, upload, and conditional-request
   planners described below). Read `notes.md`.
2. Read the challenge text: note the **URL/connection info**, any `/api/clues`-style hints, the stack
   (Flask? GraphQL? XML upload? a cloud box?), and whether it ships **source** (white-box) or only a URL.
3. If files shipped: run the offline readers first (below) — `web_evidence.py` on logs/HAR/source,
   `web.py` on JWTs/cookies, `js_recon.py`/`sourcemap.py` on bundles.
4. If a live URL: start with the benign recon pass — `recon_triage.py <url>` — to rank the likely vuln
   class and the endpoints/params to hit first. Build a `WebClient(url)` for anything active.
5. `./csctf check <id>` — skip if a teammate already solved it.

> Run every command from the ctf-tools checkout root with `.venv/bin/python` (or `.venv/bin/python -m ctf run <engine>`), with `CTF_EVENT` set to the event slug (`events/<slug>/event.toml`). The workdir comes from `ctf.paths`: `$CTF_WORKDIR`, else `~/ctf-work/<event>`; `.venv/bin/python -m ctf workdir` prints it, and `workspace/` on this page means it.

---

## 2. Engine CLIs by sub-type

Paths are relative to the repo root; prefix every command with `.venv/bin/python`.

### Recon — rank the vuln class, list endpoints/params
```
# Benign, GET-only, scope-locked live recon (landing page, robots.txt, openapi/swagger,
# .git/HEAD, .env, backup.zip ...). Prints a JSON dict with ranked "classes" + endpoints/params.
.venv/bin/python solvers/web/recon_triage.py <https://target/> [--seconds 8] [--max-requests 24]
```
- `endpoint_inventory.py` is a **library (no CLI)** — bounded passive inventory of routes/operations
  from OpenAPI/sitemap/JS/source-maps. Drive it:
  ```
  .venv/bin/python -c 'import sys; sys.path[:0]=["solvers/web","solvers/toolkits"]; \
    import endpoint_inventory as e, json; print(json.dumps(e.discover("https://target/"), default=str)[:4000])'
  ```
  Returns `routes`, `operations`, `scripts`, `source_maps`, and `secret_leads` (metadata-only, never auto-submit).

### Offline JS / source-map / VCS leads (no requests)
```
# Mine already-fetched JS for endpoints, routes, params, sourcemap URLs, config/secret-shaped strings.
.venv/bin/python solvers/web/js_recon.py <file.js> [<file.js> ...] [--json]

# Reconstruct original source file names + content from a .js.map, then surface its routes/params.
.venv/bin/python solvers/web/sourcemap.py <file.js.map> [--json] [--dump DIR]   # --dump writes sanitized sources

# GET-only reconstruction of an exposed .git / .DS_Store / .svn (commits, files, refs, secret leads).
.venv/bin/python solvers/web/vcs_exposure.py <https://target/> [--git] [--ds] [--svn] [--max-requests N] [--json]
```
All three print a summary + secret **leads** (`flag` is always `None`; you read the real `csctf{...}`
out of the leads and submit it yourself).

### Offline artifact forensics — logs, HAR, source, tokens, cookies
```
# Triage: file kind, per-IP/route/status/UA tables, every payload request (family+param+decoded value),
# JWTs & session cookies decoded, route table, dangerous sinks, hardcoded secrets, forms/scripts/comments.
.venv/bin/python solvers/toolkits/web_evidence.py <file|dir|zip> ... [--json] [--all]

# The other offline web reader: HAR/access/error logs, saved HTML/JS, JWTs, cookies, source bundles,
# WAF logs. Also the home of the live WebClient and the JWT forgers (see §3/§4).
.venv/bin/python solvers/toolkits/web.py <file> [<file> ...]
```
`web_evidence` findings cover sqli / ssti / traversal / cmdi / xss / webshell / jndi / shellshock / xxe /
ssrf / deser / nosql plus brute-force / enum / scanner-by-behavior. Use it to find *which IP/param/payload*
solved a white-box log challenge.

- `session_recon.py` is a **library (no CLI)** — deeper offline cookie/session-envelope/CSRF analysis
  (lengths, fingerprints, attribute facts; never prints the secret). `web.py`/`web_evidence.py` already
  decode cookies for you; reach for `session_recon.analyze(header_pairs, body, source_url)` only when you
  need the structural breakdown.

### Flask / itsdangerous session + SSTI
```
.venv/bin/python solvers/toolkits/flask_tools.py decode  <cookie>                 # peek (no verify)
.venv/bin/python solvers/toolkits/flask_tools.py verify  <cookie> --key KEY
.venv/bin/python solvers/toolkits/flask_tools.py sign    --key KEY --data '{"admin":true}' [--compress]
.venv/bin/python solvers/toolkits/flask_tools.py forge   <cookie> --key KEY --set admin=1 [--merge '{"role":"x"}']
.venv/bin/python solvers/toolkits/flask_tools.py recover <cookie> [--text src.py] [--ssti leak.txt] [--wordlist delivery.txt]
.venv/bin/python solvers/toolkits/flask_tools.py ssti-payload --read /etc/passwd   # or --rce 'id' [--variant NAME]
.venv/bin/python solvers/toolkits/flask_tools.py probes                            # the {{7*7}}->49 family
```
`recover` only uses a wordlist **shipped in the delivery** (never rockyou/network). `confirm_ssti()` (library)
drives a `WebClient` to confirm `49` in the response.

### Werkzeug debug-console PIN (Flask `debug=True`)
```
# Derive the 9-digit /console PIN from six leaked host facts (offline; md5<2.0, sha1>=2.0).
.venv/bin/python solvers/toolkits/werkzeug_pin.py pin --username www-data --modname flask.app \
    --appname Flask --appfile /usr/.../flask/app.py --mac 02:42:ac:11:00:02 --machine-id <id> [--algorithm all]
# Pull the six facts straight out of a leaked traceback / host files:
.venv/bin/python solvers/toolkits/werkzeug_pin.py parse --traceback tb.txt [--machine-id-file m] [--mac M] [--username U]
.venv/bin/python solvers/toolkits/werkzeug_pin.py vectors    # known test vectors (sanity check)
```
Needs an LFI/traceback leak of the six facts first. The PIN is a candidate to try via `WebClient`, not a flag.

### XXE / SSRF→metadata / GraphQL payload builders
```
# XXE: classic SYSTEM read, php://filter, or the OOB parameter-entity DTD (fed by tools/oob.py).
.venv/bin/python solvers/toolkits/web_xxe_ssrf.py xxe --file /etc/passwd [--php]
.venv/bin/python solvers/toolkits/web_xxe_ssrf.py xxe-oob --base <oob-url> --token <tok> --file /etc/passwd [--php]
# SSRF: cloud instance-metadata URLs (AWS v1+v2, GCP, Azure, DO, Alibaba, Oracle) + IP-encoding spellings.
.venv/bin/python solvers/toolkits/web_xxe_ssrf.py ssrf [--ip 169.254.169.254]
.venv/bin/python solvers/toolkits/web_xxe_ssrf.py imdsv2 <url-param-name>
# GraphQL: introspection / batch / alias query bodies.
.venv/bin/python solvers/toolkits/web_xxe_ssrf.py graphql [--short]
```
The CLI **prints payloads only**. The `confirm_*` library functions replay them through a `WebClient` and
confirm from the server's own evidence (file-content signature, `data.__schema.types`, a 2-element batch array).

### Broader exploit-class generators (XXE / GraphQL / NoSQL / SSRF→IMDS / JWT / cmdi)
```
# Demo-prints request descriptors/payloads for one class; sends nothing. Classifiers decide from evidence.
.venv/bin/python solvers/web/exploit_classes.py {xxe|graphql|nosql|ssrf|all}
```
`web_exploit.py` is a **generator library** (re-exported via `import web`): path-traversal/LFI
(`traversal_payloads`, `probe_traversal`, `decode_php_filter`), cmdi (`cmdi_payloads`, `probe_cmdi_echo/time`),
file upload (`upload_variants`, `probe_upload`), and deserialization byte-builders (pickle/yaml/php/node, plus
`java_deser.ysoserial`). Generators only build bytes; you replay through a `WebClient` and a classifier confirms.

### Offline exploit planning — recurring CSCTF web chains

These offline CLIs **send nothing**. They turn evidence already in hand into ranked payloads, token/artifact bytes,
or request descriptors for the player to inspect and selectively replay against the one assigned target.

```bash
# SSTI: print benign wrapped probes; identify Jinja2/Twig/FreeMarker/ERB/Velocity from the saved
# evaluated-marker response; then build read-file or RCE strings for the identified engine.
.venv/bin/python solvers/web/ssti_helper.py probes --json
.venv/bin/python solvers/web/ssti_helper.py detect --file response.txt --read /etc/passwd --json
.venv/bin/python solvers/web/ssti_helper.py build --engine twig --rce 'id' --json

# SQLi: use facts already established by hand (context, column count, reflected column, DBMS).
# Boolean/time rows always include a paired false control. Decode a saved filter-bypass value offline.
.venv/bin/python solvers/web/sqli_helper.py generate --columns 3 --context string \
    --dialect mysql --reflected-column 2 --json
.venv/bin/python solvers/web/sqli_helper.py decode 'ＵＮ/**/ＩＯＮ%2520ＳＥＬ/**/ＥＣＴ' --json

# JWT/client-side trust: decode, forge alg:none, confirm only caller-supplied HMAC keys, sign with a
# known key, place an explicit path-like kid in a signed token, build RS->HS from a supplied PEM/JWKS,
# add jwk/jku/x5u key-selection headers, or rewrite an unsigned client-side role object.
.venv/bin/python solvers/web/auth_trust.py inspect "$TOKEN"
.venv/bin/python solvers/web/auth_trust.py none "$TOKEN" --set role=admin --set admin=true
.venv/bin/python solvers/web/auth_trust.py hmac-confirm "$TOKEN" --key "$LEAKED_KEY"
.venv/bin/python solvers/web/auth_trust.py forge "$TOKEN" --key "$LEAKED_KEY" --set role=admin
.venv/bin/python solvers/web/auth_trust.py kid "$TOKEN" --key '' --kid ../../../../dev/null --set role=admin
.venv/bin/python solvers/web/auth_trust.py rs-hs "$TOKEN" --public-key server-public.pem --set role=admin
.venv/bin/python solvers/web/auth_trust.py key-header "$TOKEN" --kind jku \
    --url https://keys.example/jwks.json --key "$TEST_KEY" --set role=admin
.venv/bin/python solvers/web/auth_trust.py role '{"role":"user"}' --storage-key profile --cookie-name profile

# IDOR/object references: transform only the explicit IDs/range supplied by the player. UUIDv1
# neighborhoods are deterministic and require an observed anchor or explicit time/node/clock sequence.
.venv/bin/python solvers/web/object_refs.py generate md5 --start 40 --stop 44
.venv/bin/python solvers/web/object_refs.py generate base64 --id 7 --id invoice-8 --url-safe
.venv/bin/python solvers/web/object_refs.py uuid1-inspect <observed-uuid>
.venv/bin/python solvers/web/object_refs.py uuid1-neighbors --anchor <observed-uuid> --before 2 --after 2

# Upload bypasses: ranked filename/MIME/magic/container combinations. The default content is inert;
# provide bytes explicitly, and export exactly one reviewed candidate when an artifact is needed.
.venv/bin/python solvers/web/upload_builder.py --stem avatar --script-ext .php --allowed-ext .jpg --json
.venv/bin/python solvers/web/upload_builder.py --payload-file payload.bin --select 7 --output candidate.bin

# ETag/REST chain: parse a saved raw HTTP response and render unsent baseline and conditional
# If-None-Match / If-Modified-Since request skeletons. Non-read methods are bodyless on purpose.
.venv/bin/python solvers/web/etag_chain.py response.http --path /api/items/7 --methods GET,HEAD --json

# Deeper SSRF chains: encode alternate loopback hosts and byte-exact Redis RESP, post-auth MySQL
# COM_QUERY, SMTP, or FastCGI/FPM streams as gopher selectors. Also emits inert file/dict/ftp
# spellings, parser-confusion URLs, and a redirect response template; it never resolves or fetches.
.venv/bin/python solvers/web/ssrf_chains.py host 127.0.0.1 --json
.venv/bin/python solvers/web/ssrf_chains.py redis 127.0.0.1 --command SET marker value --json
.venv/bin/python solvers/web/ssrf_chains.py fastcgi 127.0.0.1 --script /var/www/html/index.php --json
.venv/bin/python solvers/web/ssrf_chains.py confusion http://127.0.0.1/admin \
    --public https://allowed.example/ --json

# HTTP parser/cache ambiguity: produce marker-only CL.TE, TE.CL, TE.TE, CL.0, H2-downgrade,
# cache-poisoning, and cache-deception request candidates. Output is raw request data, never sent.
.venv/bin/python solvers/web/http_desync.py desync app.internal --json
.venv/bin/python solvers/web/http_desync.py te --json
.venv/bin/python solvers/web/http_desync.py cache app.internal \
    --path /account --marker-host cache-marker.invalid --json
```

The SSTI detector requires its wrapped evaluated marker (or an engine-named error); a reflected probe or bare
`49` is not evidence. The HMAC verifier has no built-in wordlist and checks at most 256 caller-supplied values.
JWT key-confusion builders read only the explicitly supplied local PEM/JWKS/key: `jku`/`x5u` URLs are header
strings and are never fetched, while JWKS-to-PEM conversion reports the exact canonical bytes used for HMAC.
Object references are likewise capped at 256 and never requested automatically. The upload builder's GIF/JPEG/
PNG/PDF carriers prove only that the bytes satisfy a parser/filter shape, not that the server stored or executed
them. An ETag `304`/`412` is protocol evidence, not proof of an authorization bypass. The MySQL gopher builder
starts after authentication and does not create a login handshake. Every SSRF/desync/cache result states the
parser or routing disagreement it requires; replay one reviewed marker through the scope-locked client and use
a benign control. Never spray the generated variants or treat one timeout as confirmation.

### Deserialization recognizer (offline)
```
# Classify a cookie/token/body as a serialized blob (Java/PHP/Python/Ruby/.NET/Node/YAML); peels
# base64/base64url/url/hex/gzip/zlib. NEVER deserializes. Points you to the right gadget tool.
.venv/bin/python solvers/web/deser_detect.py <file-or-value> [...] [--cookie] [--response] [--json]
```
A `rO0AB...` value → `java_serialized_stream` → next: `solvers/toolkits/java_deser.py` (ysoserial chains).
Building/sending a gadget is POST/state-change: your call, driven through a `WebClient`.

### POST exploiter — upload / login / state-change (drives a URL)
```
# NEVER-WRONG, non-destructive. GET-first, POST only where the class requires, never a destructive verb.
# Credentials are PROVIDED (never guessed/brute-forced). Prints {"proof","cls"}; evidence on stderr.
.venv/bin/python solvers/web/post_exploit.py <https://target/> --hints hints.json [--max-requests N]
```
`hints.json` names what you already know (e.g. `{"cls":"login","credentials":{"username":"u","password":"p"},...}`).
A `csctf{...}` it finds is surfaced in evidence for you to submit.

### Live read peers (library, no CLI) — use for the request mechanics
`graphql_read.py`, `xxe_read.py`, `ssrf_body.py`, `hpp_read.py` encode safe, bounded, scope-locked request
**sequences** (GraphQL field-read, in-band XXE file read, POST-body SSRF, HTTP parameter pollution) with a
benign baseline + negative control. Their auto-return is gated to the Huntress `proof_<32hex>` shape, so for a
CSCTF `csctf{...}` flag they won't auto-return it — **drive them for the mechanism and read the value out of
the response** (their `ctx['evidence']` / `ctx['result_sink']` / log), or just use the §2 generator toolkits +
`WebClient`. Call `solve(target, ctx)` / `discover(...)`
by import if you want their wiring.

---

## 3. The live client (how anything active is sent)

Everything that touches the target rides one object, built from the challenge's URL:
```python
import sys; sys.path.insert(0, "solvers/toolkits")
import web
c = web.WebClient("https://target.ctf-platform.example/")   # scope locked to this scheme+host+port
r = c.get("/robots.txt")                                   # OutOfScope off-host; VPNRequired if unreachable
c.post("/api/login", data={"u": "...", "p": "..."})        # cookie jar persists across calls
c.save_log("workspace/<id>-<slug>/web.log")                # every request/response is logged
```
`WebClient` refuses off-scope URLs, won't follow a redirect out of scope (`redirect_not_followed`), keeps a
cookie jar, and logs everything to `c.log`. JWT forging lives here too (`web.forge_jwt`,
`web.forge_jwt_hs_confusion`, `web.build_imdsv2_ssrf`). Build payloads with the §2 generators, replay them
through `c`, confirm with the matching `classify_*`/`confirm_*`.

### Blind classes need a callback — `tools/oob.py`
```
.venv/bin/python tools/oob.py addr                      # the address the target can reach you on
.venv/bin/python tools/oob.py up [--minutes M]          # start the HTTP/TCP collector (or --public for a cloudflared tunnel)
.venv/bin/python tools/oob.py token <label>             # a unique callback token
.venv/bin/python tools/oob.py url   <token> [path]      # the callback URL to put in an SSRF/XXE/cmdi payload
.venv/bin/python tools/oob.py dtd   <token> /etc/passwd # an OOB-XXE DTD that exfils a file to you
.venv/bin/python tools/oob.py hits  --token <token> [--follow 10] [--json]   # what the target called back
```
Use it for blind SSRF, OOB XXE (`xxe-oob`/`dtd`), blind cmdi, and XSS-bot callbacks. It only answers `ok`
or a served file and stops at its caps.

---

## 4. Docker — detonate only in the sandbox

Pure web work is read-only or scope-locked, so there is usually **nothing to detonate** — logs, HAR, JS,
source and cookies are inert data you parse on the host. The sandbox (`csctf-sandbox:2`, already built) is for
the exceptions, and the rule is firm: **never run an untrusted artifact on the Mac.**

- A challenge **ships a runnable backend** (server source + Dockerfile, a container image, a server binary) to
  reproduce locally → build/run it in Docker, never on the host. Inspect a shipped backend binary in the sandbox:
  ```
  .venv/bin/python tools/sandbox.py run --in server.bin strings {in}
  .venv/bin/python tools/sandbox.py run --in server.bin r2 -A {in}      # rabin2/objdump/readelf also available
  ```
- You **retrieved an untrusted file** from the target (an upload you got back, a dumped artifact, a capture) and
  want a heavy tool over it → sandbox it:
  ```
  .venv/bin/python tools/sandbox.py run --in grabbed.bin exiftool {in}
  .venv/bin/python tools/sandbox.py run --in webtraffic.pcap tshark -r {in} -Y http
  .venv/bin/python tools/sandbox.py run --in bundle.zip 7z l {in}       # binwalk/file also available
  ```
`--in FILE` drops the file read-only at `/drop/...` and `{in}` expands to its path; the container runs
`--network none`, read-only root, caps dropped. A tool not baked into the image is refused (nothing falls back
to the host). SageMath (`ctf-sage:<version>`, picked by `python -m ctf toolchain versions`) is there if a web-crypto step needs it.

---

## 5. Techniques → engines

| You see / suspect | Reach for |
| --- | --- |
| Where to even start (live URL) | `recon_triage.py <url>`, then `endpoint_inventory.discover()` |
| JS bundle, `//# sourceMappingURL` | `js_recon.py`, then `sourcemap.py --dump` |
| Exposed `.git` / `.DS_Store` / `.svn` | `vcs_exposure.py --git/--ds/--svn` |
| White-box: access/WAF log, HAR, source zip | `web_evidence.py` (payload family, attacker IP, param, sinks, secrets) |
| JWT / localStorage / role cookie trust | `auth_trust.py` (offline inspect/confirm/forge), then `web.py` only for scoped replay |
| Flask `session=` cookie, `SECRET_KEY` | `flask_tools.py decode/recover/forge` |
| Template injection (`{{7*7}}`) | `ssti_helper.py` (eight-engine offline fingerprint/build); `flask_tools.py` for Flask/Jinja sessions |
| SQL injection / NFKC / double encoding | `sqli_helper.py generate/decode` (offline values and paired controls) |
| IDOR / `md5(id)` / base64 / sequential / UUIDv1 | `object_refs.py` (bounded offline candidates) |
| Werkzeug debugger `/console` + a leak | `werkzeug_pin.py parse/pin` |
| XML upload / parser | `web_xxe_ssrf.py xxe[/-oob]`, `xxe_read.py` (mechanism) |
| Server-side fetch / cloud box | `web_xxe_ssrf.py ssrf/imdsv2`, `ssrf_body.py` (mechanism), `oob.py` for blind |
| GraphQL endpoint | `web_xxe_ssrf.py graphql`, `exploit_classes.py graphql`, `graphql_read.py` |
| Duplicate-param behavior (HPP) | `hpp_read.py` (mechanism) |
| NoSQL / cmdi / LFI / traversal | `exploit_classes.py`, `web_exploit` (`traversal_payloads`, `cmdi_payloads`) |
| Serialized cookie/token | `deser_detect.py` → `java_deser.py` / `web_exploit` byte-builders |
| Upload extension / MIME / magic / polyglot | `upload_builder.py` (offline artifact), then player-controlled replay |
| ETag / `If-None-Match` / REST-verb chain | `etag_chain.py` over a saved response (offline request descriptors) |
| Login wall / active form action | `post_exploit.py --hints` |

---

## 6. Get the flag out and submit

1. **Recover** the `csctf{...}` from real challenge output — a response body, a leaked file, a decoded cookie,
   a reconstructed source, a `secret_leads`/`evidence` line. Never a guess; never a sweep.
2. **Submit once, through the guard:**
   ```
   ./csctf submit <id> 'csctf{...}' --note 'how you got it'
   ```
   or from a solver:
   ```python
   from ctf.submit import guarded_submit
   guarded_submit(ctfd, ch, flag, provenance="xxe file read of /flag", team_solved=ctfd.team_solved_ids())
   ```
   The guard checks the flag format, dedupes, paces (≥3 s), skips already-solved, and **stops after 3 wrong on
   one challenge** — when it returns `blocked-maxwrong`, stop and ask the player. Never call `client.submit` in
   a loop.
3. **Rotating/per-team flag?** Fetch fresh and submit in the same 5-minute window. `retrieve` is a small
   challenge-specific fetch of one fresh flag (`WebClient.get()` returns a response dict; `body` is bytes):
   ```python
   import re
   from ctf.dynamic import solve_dynamic
   def retrieve():
       body = c.get("/flag")["body"].decode("utf-8", "replace")   # parse the fresh flag out, challenge-specific
       return re.search(r"csctf\{[^}\n]+\}", body).group(0)
   solve_dynamic(ctfd, ch, retrieve=retrieve, team_solved=ctfd.team_solved_ids())
   ```
4. Keep `workspace/<id>-<slug>/notes.md` current (request sequence, the confirming evidence) for the write-up.

**Scope/rate recap:** only the assigned target, one scope-locked `WebClient`, request caps kept, no
brute-force/flooding/scanning, platform and other squads off-limits.

## Round-3 payload synthesis (offline only)

`solvers/web/deser_gadgets.py app-source.txt --language php --json` statically recognizes supplied
PHP magic methods, Python jsonpickle/PyYAML constructors, Ruby Marshal/ERB surfaces, .NET
ObjectDataProvider/Json.NET settings, and Java serialization hand-off points. It builds ranked,
inert serialization recipes or byte strings; it never deserializes them. A command argument is
quoted as data and must be reviewed before the player uses it in a sacrificial Docker interpreter.

`clientside_exploit.py app.js --csp '...' --json` links prototype-pollution sources and keys to
concrete DOM/code sinks and ranks CSP bypass candidates: allowlisted JSONP callbacks, nonce reuse,
`strict-dynamic` loader gadgets, and missing `base-uri`/`object-src`. The output is a PoC string plus
its prerequisites—not a browser runner.

`authflow_exploit.py` supplies five bounded generators: `redirect`, `saml`, `idtoken`, `cors`, and
`cswsh`. They enumerate redirect-parser differentials, construct a visibly marked SAML wrapping
fixture, diagnose unsigned JWT claim/header confusion, and emit credentialed CORS or WebSocket HTML
pages for player review. Nothing opens a URL or sends a request. Keep every eventual delivery behind
the existing assigned-target, scope-locked client.

## Round-4 GraphQL and JOSE analysis (offline)

The existing GraphQL helpers build generic request bodies. `graphql_analyzer.py` instead consumes a
saved introspection response, operation document, or captured JSON request. It maps root fields,
mutations/subscriptions, sensitive-name leads, unpaginated lists, recursive schema paths, query depth,
aliases, batches, directives and fragments. Its review plans are inert strings (`sent=false`), never
endpoint discovery or delivery.

`token_depth.py` complements `auth_trust.py` with strict compact JOSE verification: authenticated JWE
decryption for direct, AES-KW, RSA-OAEP, bounded PBES2, and ECDH-ES key management with GCM or
CBC-HMAC content;
JWS verification from an explicit local JWK; RFC 7638 thumbprints; and JWKS duplicate-`kid`, material,
algorithm/use and private-key diagnostics. It never follows `jku`/`x5u`, fetches JWKS, or replays a
token. A failed tag or signature returns no plaintext or claims.

ECDH-ES supports direct derivation and `ECDH-ES+A128/192/256KW` with P-256/P-384/P-521 or X25519.
Supply the recipient private key as a local PEM/DER file or private JWK. The protected `epk`, `apu`,
and `apv` feed the RFC 7518 SHA-256 Concat KDF; curve mismatches, non-canonical coordinates, private
material hidden in `epk`, inconsistent private/public JWK halves, unwrap failure, and content-tag
failure all decline without releasing plaintext. No `jku`, `x5u`, or other key URL is consulted.

## Round-5 hard-web depth (offline candidates only)

The breadth survey found that the focused engines already cover most of this lane:

- `http_desync.py`: CL.TE, TE.CL, six TE.TE spellings, CL.0, H2.CL/H2.TE downgrade,
  cache poisoning and cache deception;
- `exploit_classes.py`: XXE/OOB structure, Mongo-style NoSQL, cloud IMDS, GraphQL,
  command-injection controls and prototype-pollution canaries;
- `ssrf_chains.py`: host encodings, parser confusion, redirects, and byte-exact
  Redis/MySQL/SMTP/FastCGI gopher streams;
- `upload_builder.py`: filename/MIME/magic-byte and GIF/JPEG/PNG/PDF polyglots;
- `authflow_exploit.py` and `clientside_exploit.py`: redirect/SAML/ID-token candidates,
  credentialed CORS, CSWSH, CSP/JSONP and prototype source-to-sink evidence.

Round 5 therefore extends `ssti_helper.py` from five to eight engines. Smarty,
Handlebars and Pug now have engine-specific wrapped probes and context-labelled read/RCE
candidates alongside Jinja2, Twig, FreeMarker, Velocity and ERB. Handlebars core has no
universal file or process primitive: its rows explicitly require a source-proven helper and
must be declined otherwise. A reflected probe or bare arithmetic result remains no evidence.

`web_attack_depth.py` fills the remaining seams without sending anything:

```sh
# LDAP/XPath fragments (context dependent; always pair with a false control)
.venv/bin/python solvers/web/web_attack_depth.py ldap --attribute uid --json
.venv/bin/python solvers/web/web_attack_depth.py xpath --field username --json

# Well-formed XInclude and bounded traversal/PHP-wrapper candidates
.venv/bin/python solvers/web/web_attack_depth.py xinclude /etc/passwd --json
.venv/bin/python solvers/web/web_attack_depth.py lfi /etc/passwd --depth 6 --json

# Marker-only CRLF and Host/X-Forwarded-Host/reset-link plans
.venv/bin/python solvers/web/web_attack_depth.py headers app.internal \
  --marker-host marker.invalid --path /reset --json

# Plans only: these commands never create threads or HTTP requests
.venv/bin/python solvers/web/web_attack_depth.py race coupon --json
.venv/bin/python solvers/web/web_attack_depth.py business 2fa --json
.venv/bin/python solvers/web/web_attack_depth.py business password_reset --json

# Labelled URL/JSON/entity/NFKC/case normalisation candidates
.venv/bin/python solvers/web/web_attack_depth.py waf '<script>alert(1)</script>' --json
```

`verified_syntax=true` means only that the local XML or reversible encoding round-trip was
checked. It never means a server parsed the value or that a bypass worked. Race/TOCTOU plans
contain two unsent request descriptions and a sequential negative control; business-logic plans
require supplied accounts/values and explicitly forbid OTP/token enumeration. Host-header plans
use `marker.invalid`, not an exfiltration domain or victim. Replay at most one reviewed candidate
through the existing assigned-target scope/rate guard, then corroborate with real response/state
evidence before treating any value as recovered.

## Agent-only web classes: structured handoff + per-class playbooks (B-151)

Some web classes Layer 1 (cold automation) will never own: safe generic exploitation is not
possible from the target contract alone — they need judgement or infrastructure the event may not
allow. `solvers/web/class_registry.json` already marks them (`status` carries `agent-only`, or a
`cold/agent` split) and its `evidence_boundary_contract.boundaries` names the seven boundary
families. For these, cold automation **stops at a structured finding** and the agent **starts from a
per-class checklist**, never from rediscovery and never from generic auto-execution.

Two pieces, both offline scaffolding (they send nothing, run no exploit, never auto-submit):

- **`solvers/web/agent_playbooks.json`** — a per-class checklist: where cold automation stops, the
  controls to establish by hand, the single smallest reversible **bounded next probe**, and the hard
  line that is **never** auto-fired. Covers request smuggling, cache poisoning, race /
  business-logic / method-override state changes, victim-browser and OOB (reflected/DOM/stored XSS,
  browser callbacks), CSRF chains, native-gadget deserialization and prototype pollution, upload
  polyglots, DNS rebinding, host-header / CRLF / LDAP / XPath and other blind/time/OOB injection,
  SOAP/gRPC invocation, and WebSocket/SSE writes and open-redirect chains.
- **`solvers/web/agent_handoff.py`** — the structured-finding schema and validator. A finding has the
  fixed fields **`endpoint, evidence, likely_grammar, controls_tried, bounded_next_probe`** (plus the
  registry's `status` and `boundary`, auto-filled). Validation fails loudly (`HandoffError`) on an
  unknown class, a missing field, or an empty `controls_tried` — no silent fallback.

```
# List the registry classes with an agent frontier and the playbook each maps to.
.venv/bin/python solvers/web/agent_handoff.py classes

# Print one class's checklist (checklist, controls, bounded next probe, the NEVER boundary).
.venv/bin/python solvers/web/agent_handoff.py playbook request_smuggling

# Emit a blank structured-finding template for a class (bounded_next_probe pre-filled from the playbook).
.venv/bin/python solvers/web/agent_handoff.py template xxe --endpoint 'POST /api/xml'

# Validate a structured finding a cold pass wrote (reads JSON only; untrusted data).
.venv/bin/python solvers/web/agent_handoff.py validate finding.json
```

The registry's `agent_handoff.class_playbook` block maps each agent-frontier class to its playbook
id (e.g. `ldap_xpath_injection` and `xxe` → `blind_oob_injection`, `ssrf`/`reset_rebind` →
`dns_rebinding`). The scaffold never relaxes the Section-2/3 rules: the bounded next probe still rides
the one scope-locked `WebClient` (or `tools/oob.py` for an OOB leg), with a benign baseline and a
negative control, and nothing here is a solve path or an opener.

## Business-logic invariant harness (B-124)

For the `business_logic` playbook (coupon, order, idempotency, multi-step state), once *you* have
written the invariant, `ctf invariant` exercises it. The harness never finds the flaw: the spec names
who stated the invariant (`stated_by`), the snapshot route(s) to read, the invariants over those
snapshots (`absolute`, `delta` optionally `per: accepted`, `unchanged`, `sum_conserved`,
`monotonic`), the smallest synthetic `transition` and its `reverse`.

```
# Offline: judge two snapshots you captured by hand (exit 0 held, 1 violated, 2 unevaluable/error).
.venv/bin/python -m ctf invariant check --spec spec.json --before before.json --after after.json --accepted 2

# Validate the spec against the target origin and print the rung ladder + reserved requests (sends nothing).
.venv/bin/python -m ctf invariant plan --spec spec.json --url http://<instance>/

# Live (only when the event's rules.web_state_changing is true and the URL is in scope):
.venv/bin/python -m ctf invariant run --spec spec.json --url http://<instance>/ --json
```

`run` reads a baseline and an idle noise control (a stated invariant that is already false, or a field
that moves on its own, stops it before any mutation), then climbs one transition, two sequential
(double-apply), up to `ladder.sequential_max`, and optionally one bounded concurrent burst through the
B-048 race engine (`ladder.burst_width`, `burst_mode` `separate`/`single-packet`). Each rung's whole
request group is reserved before its first mutation; each accepted transition is reversed and the
restore is checked by a fresh read. It stops at the first violation (the smallest violating transition),
on an ambiguous mutation (transport error, 408/425/429, 5xx, truncated body: no blind reversal, even
when the same burst also reports a violation), or when the state was
not restored. Destructive route verbs need `allow_actions` (method DELETE counts as `delete`, so a
`DELETE` reverse needs `"allow_actions": ["delete"]`); password/logout/shutdown-class verbs are
never driven; a transition without `reverse` needs `irreversible_ack` and never bursts.
