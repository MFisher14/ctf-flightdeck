"""Weak-EC-key PKI toolkit: ceremony/PKI anomaly triage, small-scalar search, proof signer (B-128).

A certificate-authority key ceremony can leave one intermediate key catastrophically weak: a tiny
private scalar ``d`` such that the public point ``Q = [d]G`` is reachable by a short search. This
module takes the artifacts handed out for such a challenge -- X.509 certificates, PKCS#10 CSRs, an
HSM ceremony log and a key inventory -- and does three mechanical things:

* **PKI anomaly triage** (:func:`triage`): parse the ceremony log and inventory, reconstruct each
  signing object's provenance, and flag objects that deviate from the plain
  ``GENERATE -> CSR`` path -- a key that was wrapped and restored/imported through a side door
  (highest when the handler is a legacy/compat/restore one), a key renamed or copied between
  generation and its CSR, or a CSR object that was never generated at all. Anomalies are ranked by
  severity and the scalar search visits the flagged certificates first, so under a tight budget the
  suspect key is tried before the healthy ones. Triage *points at* the suspect; it never claims a
  key is weak.

* **Small-scalar search** (:func:`search_certs`, :func:`small_scalar`): for each certificate public
  point, on the curve that certificate names (local P-384, plus ``ecc_faults.CURVES`` -- secp256r1,
  secp256k1 -- through ``ecdsa_recovery.resolve_curve``), a bounded baby-step/giant-step discrete
  log (reusing :mod:`ecc_weak`'s ``_bsgs`` / ``_curve_group``) recovers ``d`` when ``d`` lies in
  the search window. A point on a curve with no parameters here is *named* as skipped, never
  silently dropped; a point whose search ran out of budget is named as unfinished. A scalar is
  returned ONLY after ``[d]G == Q`` is reproduced on the curve, so a wrong value can never be emitted.

* **Proof signer / sign-and-submit client** (:func:`sign_proof`, :func:`build_proof`,
  :func:`run_proof`, :func:`http_transport`, CLI ``sign`` / ``prove``): once a scalar is recovered,
  sign the audit server's exact challenge message with ECDSA (reusing
  :func:`ecdsa_recovery.ecdsa_sign`; the nonce-reuse recovery functions are *not* rebuilt here) and
  hand the Base64(DER) signature back. :func:`run_proof` takes an injected transport;
  :func:`http_transport` is the real one, and it runs ``ctf.scope.check_url`` before every request
  (no proxy, no redirects), so it can only reach a host the event profile puts in scope. Build and
  test use a loopback fake only.

Handout walks skip symlinks and anything that resolves outside the given directory: a handout is
untrusted. Curve maths is pure integer arithmetic over public domain parameters.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
if __name__ == "__main__" and sys.path and Path(sys.path[0] or ".").resolve() == HERE:
    sys.path.pop(0)             # a sibling toolkit must never shadow a standard module
if str(COMMON) not in sys.path:
    sys.path.insert(1, str(COMMON))
if str(HERE.parent.parent) not in sys.path:     # script runs: the checkout root, for `ctf`
    sys.path.append(str(HERE.parent.parent))

# Flat imports: solvers/common is on sys.path (conftest / ctf.engines boot / the lines above).
from ecc_weak import BSGS_LIMIT_EC, ec_mul, on_curve, _bsgs, _curve_group   # noqa: E402
from ecc_faults import WeierstrassCurve, ecdsa_verify                        # noqa: E402
from ecdsa_recovery import ecdsa_sign, hash_z, resolve_curve                 # noqa: E402

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    _HAVE_CRYPTO = True
    _CRYPTO_IMPORT_ERROR = ""
except Exception as exc:  # noqa: BLE001 - recorded and surfaced as a loud `blocked`, never guessed
    _HAVE_CRYPTO = False
    _CRYPTO_IMPORT_ERROR = repr(exc)


# --- standard NIST P-384 (secp384r1) domain parameters (public constants) --------------------------

P384 = WeierstrassCurve(
    "secp384r1",
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
    -3,
    0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
    0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
    0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
)
_LOCAL_CURVES = {"secp384r1": P384, "p-384": P384, "p384": P384}

# Largest private scalar the default bounded search covers. isqrt(2**24) ~= 4096 baby steps, well
# under ecc_weak's BSGS_LIMIT_EC (1<<19), so the table never grows unbounded.
DEFAULT_SCALAR_BOUND = 1 << 24
_MAX_FILE_BYTES = 8 * 1024 * 1024
_MAX_RESPONSE_BYTES = 1 << 20


class WeakKeyError(ValueError):
    """Raised when the toolkit is asked to do something it cannot do safely (e.g. crypto missing)."""


def max_scalar_bound() -> int:
    """The largest ``bound`` the baby-step/giant-step search can cover: ``BSGS_LIMIT_EC ** 2``.

    ``ecc_weak._bsgs`` declines (returns None) once ``isqrt(bound - 1) + 1`` baby steps would exceed
    ``BSGS_LIMIT_EC``; a decline is indistinguishable from "not found", so a larger bound is refused
    up front (:func:`check_bound`) instead of being reported as searched.
    """
    return BSGS_LIMIT_EC * BSGS_LIMIT_EC


def check_bound(bound: int) -> int:
    """``bound`` if the bounded search can really cover ``[1, bound)``, else :class:`WeakKeyError`."""
    if isinstance(bound, bool) or not isinstance(bound, int):
        raise WeakKeyError(f"scalar bound {bound!r} must be an integer")
    if bound < 2:
        raise WeakKeyError(f"scalar bound {bound} is below 2: the window [1, bound) is empty")
    limit = max_scalar_bound()
    if bound > limit:
        raise WeakKeyError(
            f"scalar bound {bound} exceeds the baby-step/giant-step window {limit} "
            f"(ecc_weak.BSGS_LIMIT_EC={BSGS_LIMIT_EC} baby steps, squared): the search would decline "
            "every point, not search it. Use a bound <= that window, or a kangaroo search "
            "(common.dlog) for a larger interval")
    return bound


def _require_crypto() -> None:
    if not _HAVE_CRYPTO:
        raise WeakKeyError(
            "the 'cryptography' package is required to parse X.509 certificates/CSRs and was not "
            f"importable: {_CRYPTO_IMPORT_ERROR}"
        )


def curve_params(name: str | WeierstrassCurve) -> Optional[WeierstrassCurve]:
    """Domain parameters for a curve name (``cryptography`` / OpenSSL spelling), else None.

    P-384 is local to this module; secp256r1 / secp256k1 (and their aliases) come from
    ``ecc_faults.CURVES`` through ``ecdsa_recovery.resolve_curve``.
    """
    if isinstance(name, WeierstrassCurve):
        return name
    if not isinstance(name, str):
        return None
    key = name.strip().lower()
    return _LOCAL_CURVES.get(key) or resolve_curve(key)


# --------------------------------------------------------------------------- parsed artifacts


@dataclass(frozen=True)
class CertInfo:
    """What the toolkit needs from a certificate (or CSR) public key for the scalar search."""

    path: str
    kind: str                      # "certificate" | "csr"
    subject: str
    curve: str                     # cryptography curve name, e.g. "secp384r1"
    point: tuple[int, int]         # the EC public point (x, y)
    issuer: str = ""
    serial: Optional[int] = None


@dataclass(frozen=True)
class CeremonyEvent:
    ts: str
    facility: str
    action: str
    fields: dict[str, str]
    raw: str


@dataclass(frozen=True)
class Anomaly:
    object_id: str
    certificate: Optional[str]
    reasons: tuple[str, ...]
    severity: int                  # higher = more suspect; triage sorts descending


@dataclass(frozen=True)
class Recovery:
    scalar: int
    cert: CertInfo
    bound: int
    reason: str = ""
    paths: tuple[str, ...] = ()    # every handout file that carries this public point


@dataclass(frozen=True)
class SearchReport:
    """What a scalar search did: what it found, and what it could not finish or could not try."""

    recoveries: tuple[Recovery, ...]
    searched: int                                        # distinct points fully searched
    skipped: dict[str, int] = field(default_factory=dict)  # curve name -> points with no curve params
    unfinished: int = 0                                  # points the budget cut short (or never reached)


@dataclass(frozen=True)
class WeakKeyReport:
    anomalies: tuple[Anomaly, ...]
    search: SearchReport
    certs: tuple[CertInfo, ...]
    ignored_links: int = 0         # symlinks in the handout that were not followed


_PEM_RE = re.compile(rb"-----BEGIN ([A-Z0-9 ]+?)-----.*?-----END \1-----", re.DOTALL)


def _handout_files(root: Path | str) -> tuple[list[Path], int]:
    """``(regular files under root, symlinks ignored)``.

    The handout is untrusted: a symlink (file or directory) is never followed, and a path that
    resolves outside ``root`` is never read. Oversized files are left out.
    """
    root = Path(root)
    if root.is_symlink():
        return [], 1
    if root.is_file():
        return [root], 0
    if not root.is_dir():
        return [], 0
    base = root.resolve()
    out: list[Path] = []
    links = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        keep = []
        for d in dirnames:
            if os.path.islink(os.path.join(dirpath, d)):
                links += 1
            else:
                keep.append(d)
        dirnames[:] = sorted(keep)
        for fn in filenames:
            path = Path(dirpath) / fn
            if path.is_symlink():
                links += 1
                continue
            try:
                path.resolve().relative_to(base)
                if not path.is_file() or path.stat().st_size > _MAX_FILE_BYTES:
                    continue
            except (OSError, ValueError):
                continue
            out.append(path)
    return sorted(out), links


def _ec_point(pub) -> Optional[tuple[tuple[int, int], str]]:
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        return None
    nums = pub.public_numbers()
    return (nums.x, nums.y), pub.curve.name


def _certs_from_bytes(data: bytes) -> list[tuple[str, object]]:
    """``(kind, cryptography object)`` for every cert/CSR in ``data`` (PEM or DER)."""
    out: list[tuple[str, object]] = []
    if _PEM_RE.search(data):
        for m in _PEM_RE.finditer(data):
            label = m.group(1).decode("ascii", "replace")
            block = m.group(0)
            if "CERTIFICATE REQUEST" in label:
                try:
                    out.append(("csr", x509.load_pem_x509_csr(block)))
                except ValueError:
                    continue
            elif "CERTIFICATE" in label:
                try:
                    out.append(("certificate", x509.load_pem_x509_certificate(block)))
                except ValueError:
                    continue
        return out
    # No PEM armour: try DER as a certificate, then as a CSR.
    for kind, loader in (("certificate", x509.load_der_x509_certificate),
                         ("csr", x509.load_der_x509_csr)):
        try:
            out.append((kind, loader(data)))
            return out
        except ValueError:
            continue
    return out


def _points_from_files(paths: Iterable[Path], rel_base: Path) -> list[CertInfo]:
    out: list[CertInfo] = []
    for path in paths:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        for kind, obj in _certs_from_bytes(data):
            try:
                point = _ec_point(obj.public_key())
            except (ValueError, TypeError):
                point = None
            if point is None:
                continue
            (xy, curve_name) = point
            try:
                rel = str(path.relative_to(rel_base))
            except ValueError:
                rel = path.name
            if kind == "certificate":
                out.append(CertInfo(rel, kind, obj.subject.rfc4514_string(), curve_name, xy,
                                    issuer=obj.issuer.rfc4514_string(), serial=obj.serial_number))
            else:
                out.append(CertInfo(rel, kind, obj.subject.rfc4514_string(), curve_name, xy))
    return out


def load_public_points(root: Path | str) -> list[CertInfo]:
    """Every EC-keyed certificate and CSR under ``root``, as :class:`CertInfo` with its public point.

    Reuses the X.509/CSR readers from ``cryptography`` (the same backend
    ``solvers/common/crypto_formats.py`` and ``solvers/toolkits/asn1_reader.py`` use); the CSR path
    and the public-point extraction are what this toolkit adds. Non-EC and unparseable objects are
    skipped, never guessed; symlinks are not followed.
    """
    _require_crypto()
    root = Path(root)
    files, _ = _handout_files(root)
    return _points_from_files(files, root if root.is_dir() else root.parent)


# --------------------------------------------------------------------------- ceremony / inventory


def parse_ceremony_log(text: str) -> list[CeremonyEvent]:
    """Parse an HSM ceremony log. Each line is ``<ts> <facility> <action> key=value...``.

    The log is untrusted data: this only tokenises it, never acts on anything it says.
    """
    events: list[CeremonyEvent] = []
    for line in text.splitlines():
        line = line.rstrip()
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        ts, facility, action = parts[0], parts[1], parts[2]
        fields: dict[str, str] = {}
        for tok in parts[3:]:
            if "=" in tok:
                key, _, value = tok.partition("=")
                fields[key.lower()] = value
        events.append(CeremonyEvent(ts, facility, action.upper(), fields, line))
    return events


def parse_inventory(text: str) -> list[dict[str, str]]:
    """Parse the key-inventory CSV (header row required). Returns one dict per data row."""
    rows: list[dict[str, str]] = []
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return rows
    header = [h.strip().lower() for h in lines[0].split(",")]
    for line in lines[1:]:
        cells = [c.strip() for c in line.split(",")]
        if len(cells) != len(header):
            continue
        rows.append(dict(zip(header, cells)))
    return rows


# Handler tokens that mark a key having passed through a legacy / compatibility / restore path.
_SUSPECT_HANDLER = re.compile(r"compat|legacy|restore|downgrade|import", re.IGNORECASE)
_GENERATE_ACTIONS = {"GENERATE", "GENKEY", "KEYGEN"}
_RESTORE_ACTIONS = {"UNWRAP", "RESTORE", "IMPORT", "RECOVER"}
_DERIVE_ACTIONS = {"RENAME", "COPY", "CLONE", "DERIVE", "MOVE", "ALIAS"}
_CERT_FIELDS = ("certificate", "cert")
_ID_SEPARATORS = "-_.:/"
_CERT_SUFFIXES = (".pem", ".crt", ".cer", ".der", ".csr", ".req", ".cert", ".p10")

SEVERITY_RESTORED = 50
SEVERITY_SUSPECT_HANDLER = 30
SEVERITY_NEVER_GENERATED = 20
SEVERITY_RENAMED = 15


def _renamed_from(obj: str, generated: set[str]) -> Optional[str]:
    """The generated id ``obj`` is a suffixed rename of (longest match), else None.

    ``K-17`` -> ``K-17-R``, ``K-17_b``, ``K-17b`` (a letter after a trailing digit); never
    ``ST-1`` -> ``ST-10`` (a digit continuing a number is a different id).
    """
    best: Optional[str] = None
    for g in generated:
        if g == obj or not obj.startswith(g) or not g:
            continue
        rest = obj[len(g):]
        if rest[0] in _ID_SEPARATORS or (g[-1].isdigit() and rest[0].isalpha()):
            if best is None or len(g) > len(best):
                best = g
    return best


def _cert_key(name: str) -> str:
    """A certificate name with its file suffixes stripped, case-folded: ``ST-ISS-03.csr.pem`` ->
    ``st-iss-03``, so the log's ``ST-ISS-03`` and the inventory's ``ST-ISS-03.pem`` compare equal."""
    base = Path(name).name.casefold()
    stripped = True
    while stripped:
        stripped = False
        for suf in _CERT_SUFFIXES:
            if base.endswith(suf) and len(base) > len(suf):
                base = base[: -len(suf)]
                stripped = True
    return base


def triage(events: Sequence[CeremonyEvent],
           inventory: Sequence[dict[str, str]] = ()) -> list[Anomaly]:
    """Flag signing objects whose provenance deviates from a plain generate-then-CSR path.

    Deterministic, mechanical rules (no guessing which key is *weak* -- only which is *irregular*).
    Severities add up per object:

    * introduced by an UNWRAP/RESTORE/IMPORT/RECOVER event: ``SEVERITY_RESTORED`` (50) -- the key
      material re-entered the HSM through a side door; ``SEVERITY_SUSPECT_HANDLER`` (+30) more when
      the handler names a compat/legacy/restore/downgrade/import path;
    * a CSR object that was never GENERATEd (and not restored): ``SEVERITY_NEVER_GENERATED`` (20);
    * of those, one that is a rename/copy of a generated object -- by an explicit
      RENAME/COPY/CLONE/DERIVE/MOVE/ALIAS event, or by its id being a suffixed generated id
      (``K-17`` -> ``K-17b`` / ``K-17-R``): ``SEVERITY_RENAMED`` (+15).

    A CSR binding is any event carrying both ``object=`` and ``certificate=`` (or ``cert=``),
    whatever its facility/action spelling, plus the inventory's ``certificate,csr_object`` rows.
    Returns anomalies sorted by descending severity, then object id.
    """
    generated: set[str] = set()
    restored: dict[str, tuple[str, str]] = {}    # object -> (source, handler)
    derived: dict[str, str] = {}                 # object -> source, from an explicit rename/copy
    csr_object: dict[str, str] = {}              # certificate name -> csr object id
    for ev in events:
        obj = ev.fields.get("object", "")
        if not obj:
            continue
        if ev.action in _GENERATE_ACTIONS or (ev.action == "CREATE" and ev.facility.upper() == "KEY"):
            generated.add(obj)
        if ev.action in _RESTORE_ACTIONS:
            restored[obj] = (ev.fields.get("source", ""), ev.fields.get("handler", ""))
        if ev.action in _DERIVE_ACTIONS and ev.fields.get("source"):
            derived[obj] = ev.fields["source"]
        cert = next((ev.fields[k] for k in _CERT_FIELDS if ev.fields.get(k)), "")
        if cert:
            csr_object[cert] = obj

    inv_by_cert: dict[str, str] = {}
    for row in inventory:
        cert = row.get("certificate", "")
        obj = row.get("csr_object", "")
        if cert and obj:
            inv_by_cert.setdefault(cert, obj)

    # Union of certificate -> object id from the log and the inventory, grouped by object so the two
    # names the log (``X-03``) and the inventory (``X-03.pem``) give one key share a row.
    cert_object = dict(inv_by_cert)
    cert_object.update(csr_object)
    certs_by_object: dict[str, list[str]] = {}
    for cert, obj in sorted(cert_object.items()):
        certs_by_object.setdefault(obj, [])
        if cert not in certs_by_object[obj]:
            certs_by_object[obj].append(cert)

    anomalies: list[Anomaly] = []
    for obj, cert_names in sorted(certs_by_object.items()):
        cert = next((c for c in cert_names if c.endswith(".pem")), cert_names[0]) if cert_names else None
        reasons: list[str] = []
        severity = 0
        if obj in restored:
            source, handler = restored[obj]
            severity += SEVERITY_RESTORED
            detail = f"restored into {obj}"
            if source:
                detail += f" from {source}"
            if handler:
                detail += f" via handler '{handler}'"
                if _SUSPECT_HANDLER.search(handler):
                    severity += SEVERITY_SUSPECT_HANDLER
                    detail += " (legacy/compat/restore path)"
            reasons.append(detail)
        elif obj not in generated:
            severity += SEVERITY_NEVER_GENERATED
            reasons.append(f"object {obj} was never directly GENERATEd in the ceremony log")
            base = derived.get(obj) or _renamed_from(obj, generated)
            if base:
                severity += SEVERITY_RENAMED
                reasons.append(f"CSR object {obj} is a rename of generated {base}")
        if reasons:
            anomalies.append(Anomaly(obj, cert, tuple(reasons), severity))
    anomalies.sort(key=lambda a: (-a.severity, a.object_id))
    return anomalies


# --------------------------------------------------------------------------- small-scalar search


def small_scalar(point: tuple[int, int], *, curve: WeierstrassCurve = P384,
                 bound: int = DEFAULT_SCALAR_BOUND, deadline: Optional[float] = None) -> Optional[int]:
    """The private scalar ``d`` in ``[1, bound)`` with ``[d]G == point`` on ``curve``, else None.

    A bounded baby-step/giant-step discrete log (reusing ``ecc_weak._bsgs`` over
    ``ecc_weak._curve_group``). Never-wrong: the returned ``d`` is re-checked with ``[d]G == point``
    before it leaves this function, so a value that does not reproduce the point is dropped.
    A ``bound`` the search cannot cover (see :func:`check_bound`) raises :class:`WeakKeyError`.
    """
    check_bound(bound)
    p, a = curve.p, curve.a % curve.p
    b = curve.b % curve.p
    if not (isinstance(point, (tuple, list)) and len(point) == 2):
        return None
    q = (point[0] % p, point[1] % p)
    if not on_curve(q, p, a, b):
        return None
    grp = _curve_group(p, a)
    g = (curve.gx % p, curve.gy % p)
    d = _bsgs(g, q, bound, grp, BSGS_LIMIT_EC, deadline)
    if d is None or d == 0:
        return None
    # never-wrong gate: reproduce the point with this toolkit's own scalar multiply.
    if ec_mul(d, g, p, a) == q:
        return d
    return None


def order_by_triage(certs: Sequence[CertInfo], anomalies: Sequence[Anomaly]) -> list[CertInfo]:
    """``certs`` with the triage-flagged ones first, in anomaly order; the rest keep their order."""
    rank: dict[str, int] = {}
    for i, a in enumerate(anomalies):
        if a.certificate:
            rank.setdefault(_cert_key(a.certificate), i)
    unranked = len(anomalies)
    return sorted(certs, key=lambda c: rank.get(_cert_key(c.path), unranked))


def search_certs(certs: Iterable[CertInfo], *, curve: Optional[WeierstrassCurve] = None,
                 bound: int = DEFAULT_SCALAR_BOUND,
                 deadline: Optional[float] = None,
                 clock: Callable[[], float] = time.monotonic) -> SearchReport:
    """Run :func:`small_scalar` against each distinct certificate/CSR public point, in input order.

    Each point is searched on the curve its certificate names (:func:`curve_params`); with ``curve``
    given, only points on that curve are searched. A point not searched for want of parameters is
    counted under its curve name in ``skipped``; a point the ``deadline`` cut short, or never
    reached, is counted in ``unfinished``. Points are de-duplicated, so a key that appears in several
    files is searched once and its recovery lists every path. ``clock`` is the time source the
    ``deadline`` is compared against (``time.monotonic``; injectable for tests). A ``bound`` the search
    cannot cover raises :class:`WeakKeyError` before any point is touched (:func:`check_bound`).
    """
    check_bound(bound)
    groups: dict[tuple[str, tuple[int, int]], list[CertInfo]] = {}
    for info in certs:
        groups.setdefault((info.curve, info.point), []).append(info)
    recoveries: list[Recovery] = []
    skipped: dict[str, int] = {}
    searched = unfinished = 0
    for (curve_name, point), infos in groups.items():
        cv = curve_params(curve_name)
        if curve is not None and (cv is None or cv.name != curve.name):
            cv = None
        if cv is None:
            skipped[curve_name] = skipped.get(curve_name, 0) + 1
            continue
        if deadline is not None and clock() >= deadline:
            unfinished += 1
            continue
        d = small_scalar(point, curve=cv, bound=bound, deadline=deadline)
        if d is not None:
            searched += 1
            recoveries.append(Recovery(d, infos[0], bound, paths=tuple(i.path for i in infos)))
        elif deadline is not None and clock() >= deadline:
            unfinished += 1
        else:
            searched += 1
    return SearchReport(tuple(recoveries), searched, skipped, unfinished)


def small_scalar_search(certs: Iterable[CertInfo], *, curve: Optional[WeierstrassCurve] = None,
                        bound: int = DEFAULT_SCALAR_BOUND,
                        deadline: Optional[float] = None) -> list[Recovery]:
    """The recoveries of :func:`search_certs` (see there for skipped/unfinished accounting)."""
    return list(search_certs(certs, curve=curve, bound=bound, deadline=deadline).recoveries)


def analyse(root: Path | str, *, curve: Optional[WeierstrassCurve] = None,
            bound: int = DEFAULT_SCALAR_BOUND, deadline: Optional[float] = None,
            certs: Optional[Sequence[CertInfo]] = None) -> WeakKeyReport:
    """End-to-end: triage the ceremony artifacts, then search small scalars, suspects first.

    ``certs`` may be passed when the caller already loaded them (no second parse). Each recovery is
    annotated with the triage reasons of the certificate it was found in (exact name match).
    """
    _require_crypto()
    root = Path(root)
    files, links = _handout_files(root)
    events: list[CeremonyEvent] = []
    inventory: list[dict[str, str]] = []
    for path in files:
        name = path.name.lower()
        try:
            if name.endswith(".log") or "ceremony" in name:
                events += parse_ceremony_log(path.read_text(encoding="utf-8", errors="replace"))
            elif name.endswith(".csv") or "inventory" in name:
                inventory += parse_inventory(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    anomalies = triage(events, inventory)
    if certs is None:
        certs = _points_from_files(files, root if root.is_dir() else root.parent)
    ordered = order_by_triage(list(certs), anomalies)
    report = search_certs(ordered, curve=curve, bound=bound, deadline=deadline)
    reason_by_key = {_cert_key(a.certificate): "; ".join(a.reasons) for a in anomalies if a.certificate}
    annotated = []
    for rec in report.recoveries:
        reason = next((reason_by_key[_cert_key(p)] for p in rec.paths
                       if _cert_key(p) in reason_by_key), "")
        annotated.append(Recovery(rec.scalar, rec.cert, rec.bound, reason, rec.paths))
    search = SearchReport(tuple(annotated), report.searched, report.skipped, report.unfinished)
    return WeakKeyReport(tuple(anomalies), search, tuple(certs), links)


def recover_weak_keys(root: Path | str, *, curve: Optional[WeierstrassCurve] = None,
                      bound: int = DEFAULT_SCALAR_BOUND, deadline: Optional[float] = None,
                      certs: Optional[Sequence[CertInfo]] = None) -> tuple[list[Anomaly], list[Recovery]]:
    """``(anomalies, recoveries)`` from :func:`analyse`."""
    rep = analyse(root, curve=curve, bound=bound, deadline=deadline, certs=certs)
    return list(rep.anomalies), list(rep.search.recoveries)


# --------------------------------------------------------------------------- proof signer / client


def sign_proof(private: int, message: bytes, *, curve: WeierstrassCurve = P384,
               hash_name: str = "sha384") -> dict[str, str]:
    """Sign ``message`` with ECDSA under ``private`` on ``curve``; return the proof fields.

    Reuses :func:`ecdsa_recovery.ecdsa_sign` (RFC 6979 deterministic nonce) for the signature; the
    nonce-reuse recovery functions are NOT duplicated here. Returns ``{r, s, der_hex, signature}``
    where ``signature`` is the Base64(DER) the audit server expects, and the signature is
    locally re-verified against ``[private]G`` before being returned.
    """
    if not isinstance(private, int) or not 1 <= private < curve.n:
        raise WeakKeyError(f"private scalar out of range [1, n) for {curve.name}")
    _require_crypto()
    if not isinstance(message, (bytes, bytearray)):
        raise WeakKeyError("message must be bytes")
    r, s = ecdsa_sign(private, bytes(message), curve=curve, hash_name=hash_name, low_s=True)
    public = ec_mul(private, (curve.gx, curve.gy), curve.p, curve.a % curve.p)
    z = hash_z(bytes(message), curve, hash_name)
    if not ecdsa_verify((r, s, z), public, curve=curve):
        raise WeakKeyError("self-check failed: signature does not verify against the derived public key")
    der = encode_dss_signature(r, s)
    return {
        "r": f"{r:x}",
        "s": f"{s:x}",
        "der_hex": der.hex(),
        "signature": base64.b64encode(der).decode("ascii"),
    }


def _challenge_message_bytes(challenge: dict, *, message_b64: bool = False) -> bytes:
    """Extract the exact bytes to sign from a proof-server challenge object."""
    msg = challenge.get("message")
    if msg is None:
        raise WeakKeyError("challenge has no 'message' field")
    if isinstance(msg, (bytes, bytearray)):
        return bytes(msg)
    if not isinstance(msg, str):
        raise WeakKeyError("challenge 'message' is not a string")
    if message_b64:
        try:
            return base64.b64decode(msg, validate=True)
        except (ValueError, TypeError) as exc:
            raise WeakKeyError(f"challenge 'message' is not valid base64: {exc}") from None
    return msg.encode("utf-8")


def build_proof(challenge: dict, private: int, *, curve: WeierstrassCurve = P384,
                hash_name: str = "sha384", message_b64: bool = False,
                session_field: str = "session_id") -> dict[str, str]:
    """Build the verify payload for a proof server from its challenge object.

    The server's ``session_id`` (or ``session_field``) is echoed back unmodified alongside the
    Base64(DER) signature over the exact challenge message bytes.
    """
    message = _challenge_message_bytes(challenge, message_b64=message_b64)
    signed = sign_proof(private, message, curve=curve, hash_name=hash_name)
    payload = {"signature": signed["signature"]}
    if session_field in challenge:
        payload[session_field] = challenge[session_field]
    return payload


# A transport is any callable (method, url, json_body) -> response dict. run_proof never builds one
# itself; http_transport() is the real one (scope-checked), tests use a loopback fake.
Transport = Callable[[str, str, Optional[dict]], dict]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuses every redirect: the redirect target would bypass the scope check."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise WeakKeyError(f"proof server redirected ({code}) to {newurl!r}; redirects are not "
                           "followed (the target would bypass the scope check)")


def http_transport(*, timeout: float = 15.0, profile=None) -> Transport:
    """A JSON-over-HTTP :data:`Transport` for :func:`run_proof`.

    Every request first runs ``ctf.scope.check_url`` against the event profile (``profile``, else the
    pinned/current one), so an out-of-scope host raises ``ctf.scope.OutOfScope`` before any socket
    opens. Environment proxies are ignored and redirects are refused. A non-JSON body raises
    :class:`WeakKeyError` naming the status; an HTTP error with a JSON body returns that body (proof
    servers report a bad signature that way).
    """
    from ctf import scope

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def transport(method: str, url: str, body: Optional[dict]) -> dict:
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        if scheme not in ("http", "https"):
            raise WeakKeyError(f"proof server URL {url!r} is not http(s)")
        scope.check_url(url, what=f"proof server {method} {url!r}", profile=profile)
        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with opener.open(req, timeout=timeout) as resp:
                status, raw = resp.status, resp.read(_MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read(_MAX_RESPONSE_BYTES + 1)
        except urllib.error.URLError as exc:
            raise WeakKeyError(f"proof server {method} {url!r} failed: {exc.reason}") from None
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise WeakKeyError(f"proof server {method} {url!r} response exceeds {_MAX_RESPONSE_BYTES} bytes")
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise WeakKeyError(f"proof server {method} {url!r} returned HTTP {status} with a "
                               f"non-JSON body ({len(raw)} bytes)") from None
        return obj

    return transport


def run_proof(transport: Transport, base_url: str, private: int, *,
              curve: WeierstrassCurve = P384, hash_name: str = "sha384",
              message_b64: bool = False, challenge_path: str = "/challenge",
              verify_path: str = "/verify", session_field: str = "session_id") -> dict:
    """Drive a proof endpoint through an injected ``transport``: fetch challenge, sign, submit.

    ``transport`` is required and must be provided by the caller (:func:`http_transport` in
    production, a loopback fake in tests). There is no default transport -- a missing one is a loud
    error, never a silent network call. Returns the server's verify response dict.
    """
    if not callable(transport):
        raise WeakKeyError("run_proof requires a caller-supplied transport callable (no default)")
    challenge = transport("GET", base_url.rstrip("/") + challenge_path, None)
    if not isinstance(challenge, dict):
        raise WeakKeyError("challenge response was not a JSON object")
    payload = build_proof(challenge, private, curve=curve, hash_name=hash_name,
                          message_b64=message_b64, session_field=session_field)
    result = transport("POST", base_url.rstrip("/") + verify_path, payload)
    if not isinstance(result, dict):
        raise WeakKeyError("verify response was not a JSON object")
    return result


# --------------------------------------------------------------------------- contract entry + CLI


def _search_gaps(search: SearchReport, bound: int) -> list[str]:
    gaps = [f"skipped {n} point(s) on {name}: no curve params"
            for name, n in sorted(search.skipped.items())]
    if search.unfinished:
        gaps.append(f"{search.unfinished} point(s) not fully searched below {bound}: the budget ran "
                    "out (raise opts budget)")
    return gaps


def solve(challenge_dir, profile, **opts):
    """Contract entry: triage PKI ceremony artifacts and recover any small-scalar EC signing key.

    Options: ``bound`` (largest scalar to search, default 2**24), ``budget`` (seconds, default 20).
    On success every proven private scalar is reported as evidence with the sign-and-submit next step;
    the flag itself comes from the live proof server (not reachable from build), so the status is
    ``unsure`` rather than a fabricated flag. When no point could be searched at all (every one on a
    curve with no parameters here) the status is ``blocked``, naming the curves.
    """
    from ctf.result import Cost, Evidence, SolverResult

    engine_id = "toolkits.pki_weakkey"
    if not _HAVE_CRYPTO:
        return SolverResult(status="blocked", engine=engine_id,
                            notes=f"'cryptography' not importable, cannot parse certs/CSRs: {_CRYPTO_IMPORT_ERROR}")
    challenge_dir = Path(challenge_dir)
    files_dir = challenge_dir / "files"
    root = files_dir if files_dir.is_dir() and not files_dir.is_symlink() else challenge_dir
    try:
        bound = int(opts.get("bound", DEFAULT_SCALAR_BOUND))
        budget = float(opts.get("budget", 20.0))
    except (TypeError, ValueError):
        return SolverResult(status="blocked", engine=engine_id,
                            notes=f"options bound={opts.get('bound')!r} / budget={opts.get('budget')!r} "
                                  "must be numbers")
    try:
        check_bound(bound)
    except WeakKeyError as exc:
        return SolverResult(status="blocked", engine=engine_id, notes=f"option bound refused: {exc}")
    deadline = time.monotonic() + budget

    certs = load_public_points(root)
    if not certs:
        return SolverResult(status="none", engine=engine_id,
                            notes="no EC-keyed X.509 certificate or CSR found in the handout")
    rep = analyse(root, bound=bound, deadline=deadline, certs=certs)
    search = rep.search
    gaps = _search_gaps(search, bound)
    if rep.ignored_links:
        gaps.append(f"ignored {rep.ignored_links} symlink(s) in the handout (not followed)")
    gap_note = (" " + "; ".join(gaps) + ".") if gaps else ""

    if not search.recoveries:
        if search.searched == 0 and not search.unfinished:
            return SolverResult(status="blocked", engine=engine_id,
                                notes="no EC public point could be searched:" + gap_note)
        note = (f"searched {search.searched} EC public point(s) for a scalar below {bound} and found "
                "none." + gap_note + " The key may be weak by another route (nonce reuse: use "
                "common.ecdsa_recovery), or the scalar exceeds the bound (raise opts bound).")
        if rep.anomalies:
            note += (" PKI triage flagged: "
                     + "; ".join(f"{a.object_id} [{a.certificate}] ({'; '.join(a.reasons)})"
                                 for a in rep.anomalies[:3]))
        return SolverResult(status="unsure", engine=engine_id, notes=note)

    evidence = []
    for rec in search.recoveries:
        evidence.append(Evidence(
            "match",
            f"recovered private scalar d={rec.scalar} (0x{rec.scalar:x}); [d]G reproduces the "
            f"certificate public point on {rec.cert.curve}",
            path=rec.cert.path))
        if rec.reason:
            evidence.append(Evidence("triage", f"PKI anomaly for this key: {rec.reason}",
                                     path=rec.cert.path))
    keys = "; ".join(f"d = {r.scalar} (0x{r.scalar:x}) on {r.cert.curve}, subject {r.cert.subject!r}"
                     f" [{', '.join(r.paths)}]" for r in search.recoveries)
    first = search.recoveries[0]
    key_args = (f"--scalar {first.scalar} --curve {first.cert.curve} "
                f"--hash {default_hash(curve_params(first.cert.curve))}")
    notes = (f"{len(search.recoveries)} weak key(s): {keys}.{gap_note} Proof flow: "
             f"`python solvers/toolkits/pki_weakkey.py sign challenge.json {key_args}` prints the "
             "{session_id, signature} payload offline; "
             f"`... prove <base_url> {key_args} --event <slug>` "
             "fetches the challenge, signs it and POSTs it (scope-checked). The flag is returned by "
             "that live server, so it is not recoverable from the offline handout alone.")
    return SolverResult(status="unsure", evidence=tuple(evidence), engine=engine_id,
                        notes=notes, cost=Cost())


def _print_recovery(root: str, bound: int) -> int:
    rep = analyse(root, bound=bound)
    report = {
        "anomalies": [
            {"object": a.object_id, "certificate": a.certificate,
             "severity": a.severity, "reasons": list(a.reasons)}
            for a in rep.anomalies
        ],
        "recoveries": [
            {"scalar": r.scalar, "scalar_hex": f"{r.scalar:x}", "path": r.cert.path,
             "paths": list(r.paths), "subject": r.cert.subject, "curve": r.cert.curve,
             "reason": r.reason}
            for r in rep.search.recoveries
        ],
        "searched": rep.search.searched,
        "skipped": dict(rep.search.skipped),
        "unfinished": rep.search.unfinished,
        "ignored_links": rep.ignored_links,
    }
    print(json.dumps(report, indent=2))
    return 0


def _scalar_arg(text: str) -> int:
    try:
        return int(text, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(f"--scalar {text!r} is not an integer (decimal or 0x hex)")


def _curve_arg(text: str) -> WeierstrassCurve:
    cv = curve_params(text)
    if cv is None:
        raise argparse.ArgumentTypeError(
            f"unknown curve {text!r}; known: secp384r1, secp256r1, secp256k1 (and aliases)")
    return cv


def default_hash(curve: WeierstrassCurve) -> str:
    """The SHA-2 hash matching a curve's size (ECDSA convention): sha384 for P-384, else sha256."""
    return "sha384" if curve.n.bit_length() > 256 else "sha256"


def _hash_for(args) -> str:
    return args.hash or default_hash(args.curve)


def _cmd_sign(args) -> int:
    if args.message is not None or args.message_b64 is not None:
        if args.challenge is not None:
            print("error: give a challenge file or --message/--message-b64, not both", file=sys.stderr)
            return 2
        if args.message_b64 is not None:
            try:
                msg = base64.b64decode(args.message_b64, validate=True)
            except (ValueError, TypeError) as exc:
                print(f"error: --message-b64 is not valid base64: {exc}", file=sys.stderr)
                return 2
        else:
            msg = args.message.encode("utf-8")
        out = sign_proof(args.scalar, msg, curve=args.curve, hash_name=_hash_for(args))
    else:
        if args.challenge is None:
            print("error: give a challenge JSON file or --message/--message-b64", file=sys.stderr)
            return 2
        try:
            challenge = json.loads(Path(args.challenge).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"error: cannot read challenge JSON {args.challenge!r}: {exc}", file=sys.stderr)
            return 2
        if not isinstance(challenge, dict):
            print("error: challenge JSON is not an object", file=sys.stderr)
            return 2
        out = build_proof(challenge, args.scalar, curve=args.curve, hash_name=_hash_for(args),
                          message_b64=args.challenge_message_b64, session_field=args.session_field)
    print(json.dumps(out, indent=2))
    return 0


def _cmd_prove(args) -> int:
    profile = None
    if args.event:
        from ctf import event
        profile = event.load(args.event)
    transport = http_transport(timeout=args.timeout, profile=profile)
    result = run_proof(transport, args.base_url, args.scalar, curve=args.curve, hash_name=_hash_for(args),
                       message_b64=args.challenge_message_b64, challenge_path=args.challenge_path,
                       verify_path=args.verify_path, session_field=args.session_field)
    print(json.dumps(result, indent=2))
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="pki_weakkey",
                                     description="PKI anomaly triage + small-scalar EC key recovery "
                                                 "+ ECDSA proof signer")
    sub = parser.add_subparsers(dest="cmd", required=True)
    tri = sub.add_parser("triage", help="parse ceremony artifacts and search small scalars")
    tri.add_argument("directory", help="handout directory with certs/CSRs/ceremony.log/inventory.csv")
    tri.add_argument("--bound", type=int, default=DEFAULT_SCALAR_BOUND,
                     help=f"largest private scalar to search (default {DEFAULT_SCALAR_BOUND})")

    def _sign_opts(p):
        p.add_argument("--scalar", type=_scalar_arg, required=True,
                       help="the recovered private scalar (decimal or 0x hex)")
        p.add_argument("--curve", type=_curve_arg, default=P384, help="curve name (default secp384r1)")
        p.add_argument("--hash", default=None,
                       help="ECDSA hash (default: the curve's own size, sha384 for P-384, sha256 for 256-bit)")
        p.add_argument("--challenge-message-b64", action="store_true",
                       help="the challenge 'message' field is base64: sign its decoded bytes")
        p.add_argument("--session-field", default="session_id",
                       help="challenge field echoed back with the signature (default session_id)")

    sgn = sub.add_parser("sign", help="sign a proof challenge offline and print the payload")
    sgn.add_argument("challenge", nargs="?", help="challenge JSON file ({session_id, message})")
    msg = sgn.add_mutually_exclusive_group()
    msg.add_argument("--message", help="sign this UTF-8 text instead of a challenge file")
    msg.add_argument("--message-b64", help="sign these base64-decoded bytes instead of a challenge file")
    _sign_opts(sgn)

    prv = sub.add_parser("prove", help="fetch a challenge, sign it and POST it (scope-checked)")
    prv.add_argument("base_url", help="proof server base URL (must be in the event's live scope)")
    prv.add_argument("--event", help="event slug whose profile gives the scope (default: current)")
    prv.add_argument("--challenge-path", default="/challenge")
    prv.add_argument("--verify-path", default="/verify")
    prv.add_argument("--timeout", type=float, default=15.0)
    _sign_opts(prv)

    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:  # pragma: no cover - argparse exit code passthrough
        return int(exc.code or 2)
    try:
        _require_crypto()
    except WeakKeyError as exc:
        print(f"blocked: {exc}", file=sys.stderr)
        return 2
    try:
        if args.cmd == "triage":
            return _print_recovery(args.directory, args.bound)
        if args.cmd == "sign":
            return _cmd_sign(args)
        if args.cmd == "prove":
            return _cmd_prove(args)
    except WeakKeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:      # ctf.scope.OutOfScope, ctf.event.EventError, bad hash name
        print(f"refused: {exc}", file=sys.stderr)
        return 3
    return 2  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
