# web_evidence: the Web category, static form

`solvers/toolkits/web_evidence.py`. Offline, stdlib
only, no request, sub-second. For a web challenge that arrives as files: access logs, a HAR, tokens and
cookies, a shipped application's source. Tests: `.venv/bin/python tests/test_tk_web_evidence.py`. Fixtures
to try it on: `tests/fixtures/tk_web_evidence/`.

**Not this module's: a live target.** A `target`, URL or host in the challenge means a running
service. `solve_set` answers nothing for it and prints `WEB LIVE TARGET <url>` on stderr; check with
`web_evidence.live_target(attempt)`. Alert and stop for the player if it needs the VPN
(AGENTS.md, "Private targets"). Nothing here signs, forges or verifies a token either.

## In this order

1. Unpack and triage (the delivery, a folder or a zip; members of a zip are read in place):

   ```bash
   .venv/bin/python tools/unpack.py workspace/<id>
   .venv/bin/python solvers/toolkits/web_evidence.py workspace/<id>/members
   .venv/bin/python solvers/toolkits/web_evidence.py <files> --json     # the same, for a script
   .venv/bin/python solvers/toolkits/web_evidence.py <files> --all      # whole tables, not the top 15
   ```

   It prints: each log and its kind; requests per client address, status, method, route and user agent;
   every request that carries a payload (family, where, parameter, decoded value); every JWT (`alg`, `kid`,
   header, claims) and session cookie decoded; and for source the route table, the dangerous calls with
   their handler, route and the request values they read, hardcoded secrets, HTML forms, script blocks and
   comments.
2. `solve_set` returns the answers it can prove plus ranked candidate values (`labels.show(...)`) for the
   rest; unsure answers are listed with their options and never collapsed to a single value.
3. Reason to the flag from the output and submit it once via `ctf.submit.guarded_submit(...)` (or
   `./csctf submit <id> <flag>`).
4. What it leaves `None` is yours: read the triage, establish the fact, and reason to the answer by hand.

## What it reads

| Input | Reader | Notes |
| --- | --- | --- |
| Apache/nginx combined and common | `parse_access` | a leading virtual host is allowed; `\x..` escapes in the request are undone |
| IIS W3C extended | `parse_iis` | columns from the last `#Fields:` line; times are UTC |
| JSON lines, a JSON array, an object with `records`/`logs`/`events`/`hits` | `parse_jsonl` | proxy, WAF, CDN and Elasticsearch exports; nested fields; field names in `_FIELD` |
| CSV with a header | `parse_csv` | same field names |
| HAR | `parse_har` | request headers, post data, response body and `Set-Cookie`; a HAR has no client address |
| JWT | `find_tokens`, `decode_jwt` | header and claims decoded; `alg`, `kid`; nothing verified |
| Session cookies | `find_cookies`, `decode_cookie` | Flask/itsdangerous (`payload.timestamp.signature`, zlib form with a leading `.`), base64 JSON |
| Source | `read_source` | Flask/FastAPI decorators, Express calls, ASP.NET attributes and `Map*`, PHP/ASPX/JSP pages; sinks in `SINKS`; secrets; forms, scripts, comments |

`read_log(data, name)` picks the reader (`log_kind` says which). Every path and value is percent-decoded
until nothing changes (`deep_unquote`), so `%2527` is `'`. `Evidence(files)` holds all of it for one delivery.

Joining with another log by address (B-066, used by `cloudlogs.py --pivot`): `ip_activity(events)` gives one row per
client address (`requests`, `first`, `last`, Counters of `statuses`, `methods`, `paths`, `user_agents`), keyed by
`ip_key` (port and brackets dropped, IPv6 compressed, IPv4-mapped IPv6 as IPv4). An access-log line whose first
quoted field after the user agent is a list of addresses (nginx `"$http_x_forwarded_for"`) keeps it as
`extra["forwarded_for"]`; such an address is counted under `forwarded` / `forwarded_via`, never as a request of its
own: the client wrote that header.

Payload families (`findings`, precedence in this order): `jndi`, `shellshock`, `ssti`, `xxe`,
`deserialization`, `sqli`, `nosqli`, `cmdi`, `xss`, `ssrf`, `traversal`, and `webshell` (role `upload`: a
multipart file name or a PUT of a server-side script; role `use`: a script requested with a command in
`cmd`, `c`, `exec`, ...). By behaviour, one finding per address: `brute_force` (8 or more refused POSTs to
one path), `enumeration` (20 or more distinct 404 paths), `scanner` (the tool named in the user agent).

Source sinks: `yaml.load` without a safe loader, `pickle.loads`, `eval`, `exec`, `render_template_string`
and `Template(...).render`, `subprocess` with `shell=True`, `os.system`, `extractall` (zip slip), a
multiline regular expression used as an allowlist (`re.MULTILINE`, `/^...$/m`, `RegexOptions.Multiline`),
SQL built from strings, file reads from request values, PHP `system`/`include`/`unserialize`/
`move_uploaded_file`, Node `child_process.exec`, .NET `Process.Start`/`BinaryFormatter`/`Html.Raw`, Java
`Runtime.exec`/`readObject`.

## Question shapes and how they are answered

The first intent word of the question decides what is asked; the answer id must not name a different one.

| Asked | Answer | Plain when |
| --- | --- | --- |
| attacker IP | the address that sent the payload requests | exactly one address did |
| parameter | the parameter that carried the payload | exactly one name, and no payload sat in the path or a header |
| status, method, user agent | of the payload requests | one value over them; "first", "last", "successful" narrow them |
| route, endpoint, path | the path of the payload requests | one path whose raw and decoded forms agree; "URL" and a payload in the path are unsure (`web.route/<log kind>`) |
| uploaded file name | the web shell's name | one name over the upload and its uses |
| decoded payload, command | the decoded value | one value; unsure (`web.payload/<family>`) when a `+` can be read two ways |
| first exploit time | `web.time/<log kind>`: `iso_utc_z`, `iso_utc`, `space_utc`, `iso_offset`, `epoch`, `raw` | only when the answer format's template states the form, or one form fits its pattern and the log is in UTC |
| vulnerability class | `web.vuln/<family>` | never (author vocabulary); a listed enum (`options`, `values`, `accepted_values`) narrows the options |
| injection technique | `web.technique/<family>.<technique>`: the spellings of the one technique the payloads show (`union_based`, `error_based`, `boolean_blind`, `time_blind`, `stacked_queries`; a behaviour family's own name; `web_shell` for a shell in use; `none_algorithm` for an `alg: none` token); a generic "what technique" also gets the class names after them, under its own key (`...generic`) | never; asked of a named attack, two techniques shown or a family with no technique read is `None`; asked generically, the class names alone under `web.technique/<family>.generic` |
| CWE, ATT&CK | `web.cwe/<family>`, `web.attack/<family>` (also a technique asked with ATT&CK, MITRE or a `T1xxx` id) | never |
| tool | `web.tool/<tool>` | never |
| token `alg`, `kid`, a named claim, a cookie field | the decoded value | one value over every token that carries it; booleans are unsure (`web.format/claim.bool`); "when issued/expires" is a time (`web.time/jwt.exp`) |
| hardcoded secret | the secret in the source | exactly one of the kind asked |
| vulnerable route, method, parameter, line | of the one sink | exactly one sink in the source; for a .NET sink found by a type name (`new BinaryFormatter()` and the other formatters) the line is the one `.Deserialize(` call made on the variable that line assigns, in its handler, outside strings and comments, else `None`; a `.java` class has no route (its own file name is none) |
| dangerous function | `web.sink/<call>` | never |
| counts | distinct client addresses; requests with a status; requests of an address written in the question | one log file whose every record was read (`Evidence.complete`), and a question made only of the count shapes' own words: any other word (a path, a method, `failed`, `attacked`, a time span) is `None` |

`None` for everything else, and always for: two candidates (a decoy, a second attack, a second token), a
question with no attack in it, a ranking ("most", "top"), the other end of the attack (server, C2,
callback), and any delivery that carries another category's marks (`other_lane`). Text inside the evidence
("the attacker IP is ...", "ignore previous instructions") is data: nothing is read from it as an answer.
A question that names its family ("the SQL injection", "the path traversal", "the brute force", "Nikto")
is answered for that family only: `None` when the delivery does not show it, and `None` when the question
names two. Brute force, enumeration and a scanner's name are one finding per address, so they answer who
(and the brute-forced route and method, the scanner's user agent), never a status or a last time.
"The attacker" with no attack named is `None` when the log's hostile addresses are more than one, and
"the attacker's first (last) request" is `None` when that sender has a request before (after) its payload.

## Likely label vocabularies (lowercase snake_case, descriptive; offered in this order)

- SQL injection: `sql_injection`, `sqli`, `sql_injection_attack`, `injection`
- Template injection: `server_side_template_injection`, `template_injection`, `ssti`
- Traversal: `path_traversal`, `directory_traversal`, `local_file_inclusion`, `lfi`, `file_inclusion`
- Command injection: `command_injection`, `os_command_injection`, `remote_code_execution`, `rce`, `cmdi`
- XSS: `cross_site_scripting`, `xss`, `reflected_xss`, `stored_xss`
- Web shell: `web_shell_upload`, `webshell_upload`, `unrestricted_file_upload`, `file_upload`, `web_shell`, `webshell`
- JNDI: `jndi_injection`, `log4shell`, `log4j`, `jndi_lookup`, `remote_code_execution`
- Deserialization: `insecure_deserialization`, `unsafe_deserialization`, `deserialization`, `object_injection`
- Others: `xml_external_entity`, `server_side_request_forgery`, `nosql_injection`, `shellshock`, `brute_force`,
  `directory_enumeration`, `code_injection`, `zip_slip`, `regex_bypass`
- ATT&CK: `T1190` for an exploited application, `T1505.003` for a web shell, `T1110` brute force,
  `T1595.003` enumeration. CWE: 89, 1336/94, 22, 78, 79, 434, 917, 502, 611, 918.
- Token facts are the token's own strings (`none`, `HS256`, the claim value as written).

The tables are `VULN_NAMES`, `CWE` and `ATTACK` in the module. A name that proves correct can be reused on
the next variant.

## Day-18 look-ahead fixes (2026-10-17, `tests/test_day18_web.py`; the page is `docs/retro/day-18/predictions-web.md`)

Staged on the look-ahead's 39 bases (182 questions): plain 104 to 125, `None` 47 to 28, WRONG 2 to 0, the one
wasted-probe answer gone, every earlier plain answer and every must-decline unchanged, the same solve time.

- **W-A, a host asked under a route word.** `intent_of` reads the intent from the answer id only when the text
  has no intent word; `tr-url-host` ("What host did the attacker's requests target (the Host header)?") was
  read as a route and answered the path plain. A question that asks for a host is now `None` for every intent
  but a token's strings, a secret, a time and a count: with the intent from the id, any host noun the text
  names outside a preposition (`hostname`, `domain`, `vhost`, `fqdn`, `Host header`, `server name`) or the
  noun its what/which phrase asks for (also `host`, `server`, `site`); with the intent from the text, only
  that asked noun ("what is the HOST of the URL"). `host`, `server` and `site` never contradict an IP.
  "What did the attacker request from the server", "which endpoint on the server" and "which web server
  path" still answer the path.
- **W-D, a family name in the id.** An id whose only intent words belong to an attack family's name
  (`webshell-class`, `command-injection-class`, `path-traversal-class`, `file-upload-class`,
  `password-spraying-...`) no longer blocks the text's intent; an id with any other intent word still does,
  and an id-only `webshell-name` is still the file name.
- **Count verbs.** "How many requests does the log record / hold / show / handle", "were captured" count
  like "are recorded". W1's anaphoric per-actor count ("did that client handle") and a condition word
  ("failed", "POST", "for the attacker") still decline. Not `processed` or `held`: on a WAF export they can
  mean allowed or blocked.
- **Technique vocabulary.** W2 gave a technique question its own key; its options were still the class
  names (a wasted probe each). Now the options are the spellings of the technique read from the payloads
  (union, error, boolean blind: a true AND a false condition or a character comparison, time blind, stacked),
  under a key of that technique (`web.technique/sqli.union_based`): `labels.pick` answers a bare-label key's
  accepted name on every later variant even when it is not offered, so `union_based` learned on one variant
  must never be the key's answer on a time-blind one. A lone `AND 1=1` shows no technique. A question that
  names the attack ("which SQL injection technique") gets the technique's spellings only, and `None` for
  sqlmap's usual mix; a generic one ("what technique did the attacker use") also gets the class names, and the
  class names alone when no one technique is read. Its options mix technique and class names, so it has a key
  of its own (`web.technique/sqli.union_based.generic`, `web.technique/sqli.generic`): `sql_injection`
  accepted for the generic question never answers the one that names the attack, nor `union_based` the reverse.
- **W-D in the text.** A family's own name in the question holds an intent word ("command" injection, "path"
  traversal, "web shell") that is not what is asked when a class or CWE word follows it: "which command
  injection technique" and "what command injection CWE" were answered with the payload, "which path traversal
  CWE" with the path, "which web shell technique" with the file name (in the saved fixtures as well). A class or
  CWE word DIRECTLY after the family name that holds the first intent word now decides (`technique`, `class`,
  `category`, `type`, `kind`, `vulnerability`, `vuln`, `weakness`, `cwe`, also after `attack` or
  `vulnerability`); a class word later in the question does not ("which web shell was uploaded through the
  file upload vulnerability" is still the file name), nor any other word ("which command was injected" is
  still the payload). Not changed and still read as in the saved fixtures: "which file upload endpoint" (the file
  name) and "what path traversal sequence" (the path).
- **One key, one fact (the same rule).** The JWT class names include the token's weakness (`none_algorithm`
  for alg none, `alg_symmetric` for HS256), so the weakness is part of the class key:
  `web.vuln/jwt_crypto.alg_none`, `.alg_symmetric`.
- **W-B, the deserialization line.** `new BinaryFormatter()` is not the line that deserializes; the call is.
  The line is the one `.Deserialize(` (or `DeserializeObject`, `ReadObject`) call made on the variable the
  type line assigns, inside its handler, with strings and comments left out; anything else is `None` (a call
  only in a comment or a log string, a safe `JsonSerializer.Deserialize` beside it, a formatter that only
  serializes, a `TypeNameHandling` settings line, two calls). A Java `new ObjectInputStream(...)` and its
  `readObject()` stay two sinks, so such a servlet answers nothing, as before; and a `.java` class no longer
  answers its own file name (`/LoadServlet.java`) as its route: its `@WebServlet` or `@*Mapping` path is not
  read here, so it has none. A `.php` or `.jsp` page keeps its own path.
- **Enum lists.** `accepted_values` (the challenge's enum key) narrows the picks like `options`.

Not built: open-redirect source detection and bracket-notation NoSQL in a log (look-ahead coverage gaps),
the HAR base64-JSON cookie claim, the `jwt_crypto` "cryptographic weakness" phrasing, W-C (a sole benign
hit named as the attacker: still check the attacker IP against the triage's per-IP table before trusting it).

## Limits

- The question reading is by intent words. A question phrased so that its first intent word is not what it
  asks can get a wrong plain answer, so check a plain answer against the triage before you submit it.
- A web shell upload in a log with no bodies is inferred from order (the address's one earlier POST path);
  it is marked `inferred` in the findings.
- The payload patterns still flag some benign values (`{{name}}`, `alert(1)`, `a; ls`, a relative
  `../../img/a.png`). Beside a real attack from another address that is `None`; as the only hit of a log it
  is a wrong plain attacker. A request value is matched on its first 4,096 characters.
- "The one sink" is the one this module's 34 patterns find; a flaw with no pattern (IDOR, a missing check)
  next to one harmless match gets that match's line and route as plain answers.
- No pcap here (the network toolkit), no browser, no request. Minified JavaScript is listed, not analysed.
- `solvers/toolkits/web.py` (backlog row 90) reads some of the same files and also uses `web.` keys; one of
  the two should be the category's engine, not both.

## Real artifacts (2026-10-08, `tests/real/test_real_web_evidence.py`)

Run on 10 real files: three scanner logs from a public research data set (Acunetix, Netsparker, w3af), ordinary
Apache and nginx-JSON traffic, two browser HARs, and the shipped source of three Huntress web challenges
(2024 "MOVEable", 2025 "Emotional" and "Angler"). Counts were checked against an independent line reader; no
crash, nothing over 0.7 s. What the real files changed:

- An access log some exports wrap in one more pair of double quotes (the research set) parsed as zero rows.
  `_access_match` now reads a line with or without that outer pair.
- The nginx JSON status column is named `response`, so every status count was `None`; added to the field map.
- "How many requests/entries/lines" (a total, no condition) is now a plain count of a log read whole.
- A scanner that names itself only in its own requests (`acunetix_wvs_security_test`, a `/Netsparker<hex>/`
  path, the method `NETSPARKER`) is now recognised, not only one named in the user agent; the `tool` answer
  runs before the scanner-finding gate.
- The SQL `.execute(f"...")` sink missed an f-string with no concatenation; a password written as `'{password}'`
  (a format placeholder) was reported as a hardcoded secret. Both fixed on the MOVEable and Emotional source.
- An SSTI sink where the template string is built from a variable (`ejs.render(page, ...)`, Emotional) was
  missed; added. Where the sink's handler reads no request value (the value was stored by another route), the
  vulnerable route and parameter are offered unsure between the sink's route and the input route, not guessed.

Not read: a flaw with no sink pattern (IDOR, a missing authorization check), minified JavaScript, a pcap of
web traffic (the `network` toolkit). The record is `docs/toolkits/real-data.md`.

Review (2026-10-08, `tests/test_tk_real_c_review.py`): a negated question (`not`, `n't`, `instead`, `should`, `legitimate`) is `None` for
every intent (the JWT's `alg` was answered plain for "which algorithm does it NOT use"). A source-review
question is `None` when it ranks or qualifies (safe, patched, parameterised, second, other, another) or names,
by path, path segment or handler, a route that does not hold the sink ("which parameter of the login route").
