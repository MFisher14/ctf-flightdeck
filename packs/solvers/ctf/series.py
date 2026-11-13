"""Series-chaining: a follow-up task reuses the evidence a sibling task already saved (B-090).

A lab on a CTF board is often split into several tasks that share one target: "Onion Deanon 1: Read
the Certificate", then "Onion Deanon 1: Fingerprint the Certificate", whose brief says only
"*Continuation of the same lab. See the first task*" and "Get the certificate's SHA-256
fingerprint". The first task's workspace already holds the certificate (B-091 saves
`leaf-cert.pem`) or the favicon (B-089/B-091 save `favicon.bin`), so the follow-up is a computed
field of a saved file, not new work. Before this module nothing linked sibling tasks and the
follow-up was recomputed by a model.

    from ctf import series
    rep = series.chain(challenge_dir)             # root defaults to challenge_dir.parent (the workdir)
    rep.status        # candidate | unsure-format | unlinked | no-sibling | no-evidence | unmapped
    rep.candidates    # [Candidate(answer, flag, kind, field, form, source, sibling)], best first
    series.record_reuse(rep)                      # what was reused, into the hypothesis ledger (B-181)
    series.write_report(rep)                      # <challenge>/recon/series.json + series.md

How a sibling is found. Two tasks are siblings when their names share a series key
(`series_key`): the part of the name before a `:`, ` - `, ` | ` or an en/em dash ("Onion Deanon 1"),
or before a trailing "Part N" / "Task N" / "(2/3)". A key that is only a category or a generic word
("Web: ...", "Warmup: ...") links nothing. The continuation wording ("Continuation of the same
lab", "see the first task", ...) marks a task that needs a sibling: when it is there and no sibling
is in the workdir, the report says so by name (`no-sibling`), never silently.

What is read, and how. Each sibling folder in the workdir (`<id>-<slug>/`, the `ctf pull` / `ctf
intake` layout, ctf.workspace.dir_name) is walked without following links, never into `.ctf` or
`.git` (ctf.sweep.SECRET_DIRS), with a cap on files and bytes. Certificates (a PEM block anywhere,
or a DER `.der/.cer/.crt`/`*cert*` file) and favicons (ctf.favicon.looks_like_icon, then checked to
really be an image: a saved 404 page named favicon.ico is rejected with the reason) are hashed.
Sibling files are DATA: they are parsed and hashed, never executed, and no text in them is followed.

Task wording to a computed field. `requests` reads the task (the name past its series key, and the
brief) for the object (certificate / favicon) and the field (serial, SHA-256 / SHA-1 / MD5, SPKI,
mmh3, issuer / subject CN), plus the stated answer form (colons, case, decimal, signed). A stated
form gives one answer; an unstated one gives the plausible forms, best first. Each answer is wrapped
in the flag format the brief states (`Flag format: CSCTF{<answer>}`), else the event profile's.

Never a submit. Every value is a *candidate*: this module and its engine never submit, and the
status is never "solved"; the dispatcher / the operator decides. `record_reuse` writes one
hypothesis-ledger record per reused field (method `series-chain <kind>.<field> from <sibling>`,
the source file and its SHA-256 in the evidence), so an agent sees what was reused instead of
recomputing it; a re-run with the same payload adds nothing. Only a single stated-form flag is
recorded POSITIVE; a best-of-several guess is INCONCLUSIVE, so it never settles the method.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import favicon as _favicon
from . import sweep as _sweep

REPORT_JSON = "series.json"
REPORT_MD = "series.md"
RECON = "recon"
CHALLENGE_JSON = "challenge.json"

MAX_CHALLENGE_JSON = 1 << 20          # a challenge.json bigger than this is not read
MAX_WALK_FILES = 4000                 # files looked at per sibling folder
MAX_FILE_BYTES = 4 << 20              # a candidate file bigger than this is not read
MAX_TEXT_SCAN = 1 << 20               # a file is scanned for a PEM block only up to this size
MAX_DEPTH = 8                         # folder depth walked under a sibling
MAX_FORMS = 4                         # answer forms kept per field

# The links never followed and the folders never entered: the sweep's secret folders (tokens,
# cookies, git credentials) plus caches that hold no evidence.
SKIP_DIRS = frozenset(_sweep.SECRET_DIRS) | {"__pycache__", "node_modules", ".venv"}

# Wording that marks a task as the continuation of an earlier one. Matched on the brief with its
# markup removed, lower-cased.
CONTINUATION_PATTERNS = (
    r"continuation of (?:the )?(?:same |previous |earlier |first )?(?:lab|series|scenario|challenge|task|case)",
    r"continu(?:es|ing) (?:from |on from )?(?:the )?(?:same |previous |earlier |first )(?:lab|task|challenge|part)",
    r"see the (?:first|previous|earlier|original) (?:task|challenge|part)",
    r"\bsame lab\b",
    r"follow[- ]up (?:to|of|on) (?:the )?(?:first|previous|earlier)",
    r"(?:builds|carries) on (?:from )?(?:the )?(?:first|previous|earlier) (?:task|challenge|part)",
)
_CONT_RE = re.compile("|".join(f"(?:{p})" for p in CONTINUATION_PATTERNS))

# A series key that is only one of these words is a category or a generic label, not a series.
GENERIC_KEYS = frozenset({
    "web", "crypto", "cryptography", "pwn", "binary", "rev", "reverse", "reversing", "forensics",
    "forensic", "misc", "miscellaneous", "osint", "stego", "steganography", "hardware", "network",
    "networking", "mobile", "blockchain", "ai", "ml", "warmup", "warmups", "warm up", "beginner",
    "intro", "introduction", "easy", "medium", "hard", "insane", "bonus", "sanity", "sanity check",
    "challenge", "task", "part", "lab", "the", "a"})

_SPLIT_RE = re.compile(r"\s*:\s+|\s+[-|–—]\s+|\s*[–—]\s*")
_PART_RE = re.compile(r"^(.*?\S)[\s\-_]*[(\[]?\s*(?:part|pt\.?|task|stage|step|chapter|level|episode)\s*"
                      r"#?\s*\d+\s*(?:/\s*\d+)?\s*[)\]]?\s*$", re.IGNORECASE)
_FRACTION_RE = re.compile(r"^(.*?\S)\s*[(\[]\s*\d+\s*/\s*\d+\s*[)\]]\s*$")
_BARE_PART_RE = re.compile(r"^(?:part|pt|task|stage|step|chapter|level|episode|day|round) ?\d+$")
_TASK_NO_RE = re.compile(r"\b(?:task|part|stage|step)\s*#?\s*(\d+)\b", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]{0,400}>")
_MD_RE = re.compile(r"[*_`#>]+")

_PEM_RE = re.compile(rb"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----")
CERT_EXTS = (".pem", ".crt", ".cer", ".der")
RECORD_EXTS = (".json", ".md", ".txt", ".jsonl", ".log", ".html", ".htm")   # never a favicon payload


class SeriesError(RuntimeError):
    """The target is not a challenge folder (no readable challenge.json), or the root is missing."""


# =====================================================================================
#  Names and briefs
# =====================================================================================

def plain_text(text: str | None) -> str:
    """The brief without HTML tags and markdown emphasis, whitespace collapsed, lower-cased."""
    t = _TAG_RE.sub(" ", str(text or ""))
    t = _MD_RE.sub(" ", t)
    return re.sub(r"\s+", " ", t).strip().lower()


def continuation_marker(description: str | None) -> str | None:
    """The continuation wording in a brief ("continuation of the same lab"), or None."""
    m = _CONT_RE.search(plain_text(description))
    return m.group(0) if m else None


def _norm_key(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()


def split_name(name: str | None) -> tuple[str | None, str]:
    """(series key, the rest of the name). The key is the normalized part before the first `:` /
    ` - ` / ` | ` / en or em dash, or before a trailing "Part N" / "Task N" / "(2/3)". None when the
    name has no such part, or the part is only a generic or category word ("Web: ...")."""
    n = str(name or "").strip()
    head, rest = None, n
    parts = _SPLIT_RE.split(n, maxsplit=1)
    if len(parts) == 2 and parts[0].strip() and parts[1].strip():
        head, rest = parts[0], parts[1]
    else:
        m = _PART_RE.match(n) or _FRACTION_RE.match(n)
        if m:
            head, rest = m.group(1), n[len(m.group(1)):]
    if head is None:
        return None, n
    key = _norm_key(head)
    if len(re.sub(r"[^a-z0-9]", "", key)) < 3 or key in GENERIC_KEYS or _BARE_PART_RE.match(key):
        return None, n
    return key, rest.strip()


def series_key(name: str | None) -> str | None:
    return split_name(name)[0]


def task_number(name: str | None, description: str | None) -> int | None:
    """The task number a task states ("Task 2 -- ...", "Part 3"), or None."""
    for text in (name, plain_text(description)):
        m = _TASK_NO_RE.search(str(text or ""))
        if m:
            return int(m.group(1))
    return None


# =====================================================================================
#  Workspace folders
# =====================================================================================

@dataclass
class Task:
    dir: Path
    cid: str
    name: str
    category: str
    description: str
    key: str | None
    marker: str | None
    number: int | None

    @property
    def dir_name(self) -> str:
        return self.dir.name

    def sort_key(self):
        # The first task first: a task that states no continuation before one that does, then the
        # stated task number, then the numeric id, then the folder name.
        num_id = int(self.cid) if self.cid.isdigit() else 1 << 62
        return (self.marker is not None, self.number if self.number is not None else 1 << 30, num_id,
                self.dir_name)


def load_task(folder: Path) -> Task:
    """A workspace folder's challenge, read from its challenge.json (as data). SeriesError when there
    is none, it is too big, or it is not a JSON object."""
    folder = Path(folder)
    p = folder / CHALLENGE_JSON
    if p.is_symlink() or not p.is_file():
        raise SeriesError(f"{folder}: no {CHALLENGE_JSON} (not a challenge folder from `ctf pull`/`ctf intake`)")
    if p.stat().st_size > MAX_CHALLENGE_JSON:
        raise SeriesError(f"{p}: over {MAX_CHALLENGE_JSON} bytes, not read")
    try:
        d = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except ValueError as e:
        raise SeriesError(f"{p}: not JSON ({e})") from None
    if not isinstance(d, dict):
        raise SeriesError(f"{p}: not a JSON object")
    name = str(d.get("name") or "")
    desc = str(d.get("description") or "")
    cid = str(d.get("id") if d.get("id") is not None else folder.name.split("-", 1)[0])
    return Task(dir=folder, cid=cid, name=name, category=str(d.get("category") or ""), description=desc,
                key=series_key(name), marker=continuation_marker(desc), number=task_number(name, desc))


def workspace_tasks(root: Path) -> tuple[list[Task], list[str]]:
    """([Task], [problem]) for every challenge folder directly under the workdir. A folder whose
    challenge.json cannot be read is listed as a problem, not dropped silently."""
    root = Path(root)
    if not root.is_dir():
        raise SeriesError(f"workdir {root} does not exist")
    tasks, problems = [], []
    for d in sorted(root.iterdir()):
        if d.is_symlink() or not d.is_dir() or d.name.startswith(".") or d.name in SKIP_DIRS:
            continue
        if not (d / CHALLENGE_JSON).exists():
            continue
        try:
            tasks.append(load_task(d))
        except SeriesError as e:
            problems.append(str(e))
    return tasks, problems


def index(root: Path) -> dict[str, list[Task]]:
    """{series key: [Task], first task first} for every series with two or more tasks in the workdir."""
    tasks, _ = workspace_tasks(root)
    groups: dict[str, list[Task]] = {}
    for t in tasks:
        if t.key:
            groups.setdefault(t.key, []).append(t)
    return {k: sorted(v, key=Task.sort_key) for k, v in sorted(groups.items()) if len(v) > 1}


def siblings(target: Task, root: Path) -> list[Task]:
    """The other tasks of the target's series in the workdir, first task first."""
    if not target.key:
        return []
    tasks, _ = workspace_tasks(root)
    me = target.dir.resolve()
    return sorted((t for t in tasks if t.key == target.key and t.dir.resolve() != me), key=Task.sort_key)


# =====================================================================================
#  Evidence in a sibling folder
# =====================================================================================

@dataclass
class Artifact:
    kind: str                      # certificate | favicon
    sibling: str                   # the sibling's folder name
    path: str                      # relative to the workdir
    file_sha256: str
    fields: dict = field(default_factory=dict)
    note: str = ""


@dataclass
class Rejected:
    path: str
    reason: str


def _walk(folder: Path):
    """Regular files under a sibling folder, sorted, no links followed, secret folders never entered."""
    n = 0
    base_depth = len(folder.parts)
    for dirpath, dirnames, filenames in os.walk(folder, followlinks=False):
        here = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS
                             and not (here / d).is_symlink() and len(here.parts) - base_depth < MAX_DEPTH)
        if here == folder / RECON:
            # our own output is not evidence
            filenames = [f for f in filenames if f not in (REPORT_JSON, REPORT_MD)]
        for fn in sorted(filenames):
            p = here / fn
            if p.is_symlink() or not p.is_file():
                continue
            n += 1
            if n > MAX_WALK_FILES:
                return
            yield p


def _pem_ders(data: bytes) -> list[bytes]:
    out = []
    for m in _PEM_RE.finditer(data):
        try:
            out.append(base64.b64decode(re.sub(rb"\s", b"", m.group(1)), validate=True))
        except (ValueError, base64.binascii.Error):
            continue
    return out


def cryptography_missing() -> str | None:
    """The named reason certificates cannot be read here (the `cryptography` package is not
    importable), or None when it is. Checked once per sibling folder, before any certificate."""
    try:
        from cryptography import x509  # type: ignore  # noqa: F401
    except ImportError as e:
        return (f"the `cryptography` package is not installed ({e}): certificates cannot be read; "
                "install its pin from requirements.in into the venv")
    return None


def _cert_fields(der: bytes) -> tuple[dict | None, list[str]]:
    """(fields, notes) for one DER certificate. fields is None when the bytes do not parse (the caller
    has already checked `cryptography_missing`). A field that could not be computed is left out and
    named in notes (an unusual key type has no SPKI pin here), never dropped silently."""
    from . import tor as _tor
    info = _tor.leaf_cert_info(der)
    if info is None:
        return None, []
    out = {"serial": info["serial"], "serial_int": str(info["serial_int"]), "sha256": info["sha256"],
           "sha1": info["sha1"], "md5": hashlib.md5(der).hexdigest(),
           "subject_cn": info.get("subject_cn"), "issuer_cn": info.get("issuer_cn"),
           "not_before": info.get("not_before"), "not_after": info.get("not_after")}
    notes = []
    from cryptography import x509  # type: ignore
    from cryptography.hazmat.primitives import serialization  # type: ignore
    try:
        spki = x509.load_der_x509_certificate(der).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        out["spki_sha256"] = hashlib.sha256(spki).hexdigest()
    except Exception as e:   # an unusual key type: the SPKI pin is left out (named), the other fields stand
        notes.append(f"SPKI pin not computed: the public key did not load ({type(e).__name__}: {e})")
    return {k: v for k, v in out.items() if v is not None}, notes


IMAGE_MAGICS = ((b"\x00\x00\x01\x00", "ico"), (b"\x00\x00\x02\x00", "cur"), (b"\x89PNG\r\n\x1a\n", "png"),
                (b"GIF87a", "gif"), (b"GIF89a", "gif"), (b"\xff\xd8\xff", "jpeg"), (b"BM", "bmp"))


def icon_type(data: bytes) -> str | None:
    """The image type of a saved favicon (ico, cur, png, gif, jpeg, bmp, webp, svg), or None: a saved
    error page or an empty file is not the icon (the check a solver makes with `file` first)."""
    for magic, kind in IMAGE_MAGICS:
        if data.startswith(magic):
            return kind
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    head = data[:1024].lstrip().lower()
    if b"<svg" in head and b"<html" not in head:
        return "svg"
    return None


def _favicon_fields(data: bytes, kind: str) -> dict:
    fh = _favicon.fingerprint(data)
    return {"mmh3": str(fh.mmh3), "mmh3_unsigned": str(fh.mmh3_unsigned), "md5": fh.md5,
            "sha1": hashlib.sha1(data).hexdigest(), "sha256": fh.sha256, "size": str(fh.size),
            "image_type": kind}


_UNCHECKED = object()     # collect(): `cryptography` not yet checked in this folder


def _looks_cert_file(p: Path) -> bool:
    n = p.name.lower()
    return p.suffix.lower() in CERT_EXTS or "cert" in n


def collect(task: Task, root: Path) -> tuple[list[Artifact], list[Rejected], list[str]]:
    """([Artifact], [Rejected], [note]) from one sibling folder: each certificate and favicon it
    saved, with its computed fields. The folder's files are read as data, never executed."""
    root = Path(root)
    arts: list[Artifact] = []
    rejected: list[Rejected] = []
    notes: list[str] = []
    seen: set[tuple[str, str]] = set()
    no_crypto = _UNCHECKED

    def rel(p: Path) -> str:
        try:
            return p.relative_to(root).as_posix()
        except ValueError:
            return str(p)

    for p in _walk(task.dir):
        try:
            size = p.stat().st_size
        except OSError:
            continue
        if size == 0:
            if _favicon.looks_like_icon(p) and p.suffix.lower() not in RECORD_EXTS:
                rejected.append(Rejected(rel(p), "empty file: not a favicon"))
            continue
        certish = _looks_cert_file(p)
        iconish = _favicon.looks_like_icon(p) and p.suffix.lower() not in RECORD_EXTS
        if not certish and not iconish and size > MAX_TEXT_SCAN:
            continue
        if size > MAX_FILE_BYTES:
            if certish or iconish:
                rejected.append(Rejected(rel(p), f"{size} bytes, over the {MAX_FILE_BYTES}-byte read cap"))
            continue
        try:
            data = p.read_bytes()
        except OSError as e:
            rejected.append(Rejected(rel(p), f"unreadable: {e}"))
            continue
        fsha = hashlib.sha256(data).hexdigest()

        ders = _pem_ders(data) if b"-----BEGIN CERTIFICATE-----" in data else []
        if not ders and certish and data[:1] == b"\x30":
            ders = [data]
        if ders:
            if no_crypto is _UNCHECKED:
                no_crypto = cryptography_missing()
                if no_crypto:
                    notes.append(no_crypto)
            if no_crypto:
                rejected.append(Rejected(rel(p), f"a certificate, not read: {no_crypto}"))
                continue
            fields, fnotes = _cert_fields(ders[0])
            if fields is None:
                rejected.append(Rejected(rel(p), "a certificate that did not parse"))
            elif ("certificate", fields["sha256"]) not in seen:
                seen.add(("certificate", fields["sha256"]))
                note = "; ".join(([f"leaf of a {len(ders)}-certificate chain: the first certificate is used"]
                                  if len(ders) > 1 else []) + fnotes)
                arts.append(Artifact("certificate", task.dir_name, rel(p), fsha, fields, note))
                notes += [f"{rel(p)}: {n}" for n in fnotes]
            continue
        if iconish:
            kind = icon_type(data)
            if kind is None:
                head = data[:16].lstrip().lower()
                what = "an HTML page" if head.startswith((b"<!doctype", b"<html")) else "not an image"
                rejected.append(Rejected(rel(p), f"named like a favicon but {what} ({size} bytes): not the icon"))
                continue
            if ("favicon", fsha) not in seen:
                seen.add(("favicon", fsha))
                arts.append(Artifact("favicon", task.dir_name, rel(p), fsha, _favicon_fields(data, kind)))
    return arts, rejected, notes


# =====================================================================================
#  Task wording -> requested field and answer form
# =====================================================================================

CERT_WORDS = re.compile(r"\bcert(?:ificate)?s?\b|\bx\.?509\b|\btls\b|\bssl\b")
FAVICON_WORDS = re.compile(r"\bfavicon\b|\bicon\b")

# (pattern, field, the objects it can belong to), in the order a field is preferred when several match.
FIELD_WORDS = (
    (re.compile(r"\bspki\b|public[- ]key (?:hash|pin|fingerprint)|pin-sha256"), "spki_sha256", ("certificate",)),
    (re.compile(r"\bserial\b"), "serial", ("certificate",)),
    (re.compile(r"\bsha-?256\b|\bsha2\b"), "sha256", ("certificate", "favicon")),
    (re.compile(r"\bsha-?1\b"), "sha1", ("certificate", "favicon")),
    (re.compile(r"\bmd5\b"), "md5", ("certificate", "favicon")),
    (re.compile(r"\bmmh3\b|murmur|\bshodan\b|\bfofa\b|icon_hash"), "mmh3", ("favicon",)),
    (re.compile(r"\bissuer\b"), "issuer_cn", ("certificate",)),
    (re.compile(r"common name|\bsubject\b"), "subject_cn", ("certificate",)),
    (re.compile(r"\bexpir|\bnot after\b|valid until"), "not_after", ("certificate",)),
)
GENERIC_DIGEST = {"certificate": ("sha256", "sha1"), "favicon": ("mmh3", "md5")}
GENERIC_WORDS = re.compile(r"\bfingerprint\b|\bhash\b|\bdigest\b|\bchecksum\b")
DIGEST_FIELDS = frozenset({"sha256", "sha1", "md5", "spki_sha256"})
OBJECT_SPECIFIC = frozenset({"mmh3", "spki_sha256"})


@dataclass(frozen=True)
class Form:
    colon: bool | None = None          # True: AA:BB; False: no separators; None: not stated
    case: str | None = None            # upper | lower | None
    decimal: bool = False              # a serial as a decimal integer
    signed: bool | None = None         # mmh3: True signed, False unsigned, None not stated

    def stated(self) -> list[str]:
        out = []
        if self.colon is not None:
            out.append("with colons" if self.colon else "no colons")
        if self.case:
            out.append(self.case + "case")
        if self.decimal:
            out.append("decimal")
        if self.signed is not None:
            out.append("signed" if self.signed else "unsigned")
        return out


@dataclass(frozen=True)
class Request:
    kind: str                          # certificate | favicon
    field: str
    form: Form
    why: str


def answer_form(text: str) -> Form:
    """The answer form a brief states, read from its "Answer:" sentence when it has one."""
    t = plain_text(text)
    m = re.search(r"\banswer\b\s*:?(.{0,300})", t)
    a = m.group(1) if m else t
    colon = None
    if re.search(r"without (?:the )?colons|no colons|no separators?|without separators?|"
                 r"strip(?:ped)? (?:the )?colons|colons removed|remove (?:the )?colons", a):
        colon = False
    elif re.search(r"with colons|colon[- ](?:separated|delimited)|\b[0-9a-f]{2}:[0-9a-f]{2}(?::|\b)", a):
        colon = True
    case = "upper" if re.search(r"upper[- ]?case|capital", a) else (
        "lower" if re.search(r"lower[- ]?case", a) else None)
    signed = False if re.search(r"\bunsigned\b", a) else (True if re.search(r"\bsigned\b", a) else None)
    return Form(colon=colon, case=case, decimal=bool(re.search(r"\bdecimal\b|\binteger\b", a)), signed=signed)


def requests(name: str, description: str) -> list[Request]:
    """What the task asks for, best first: [Request(kind, field, form, why)]. The name past its series
    key ranks first (it names the task), then the brief."""
    _, rest = split_name(name)
    title = plain_text(rest)
    body = plain_text(description)
    text = f"{title} . {body}"
    form = answer_form(description)
    # The objects the task names: the ones in its title when the title names any (the title is the
    # task; a brief can mention the other object in passing), else the ones in the brief.
    objects = (("certificate", CERT_WORDS), ("favicon", FAVICON_WORDS))
    kinds = [k for k, rx in objects if rx.search(title)]
    if not kinds:
        found = [(m.start(), k) for k, rx in objects if (m := rx.search(body))]
        kinds = [k for _, k in sorted(found)]
    out: list[Request] = []

    def add(kind, fld, why):
        if not any(r.kind == kind and r.field == fld for r in out):
            out.append(Request(kind, fld, form, why))

    hits = []
    for rx, fld, owners in FIELD_WORDS:
        m = rx.search(text)
        if m:
            hits.append((m.start(), fld, owners, m.group(0)))
    for _, fld, owners, word in sorted(hits):
        # A field binds to an object the task names. Only an object-specific word (mmh3 is a favicon
        # hash, an SPKI pin a certificate's) stands without the object being named.
        targets = [k for k in kinds if k in owners]
        if not targets and fld in OBJECT_SPECIFIC:
            targets = list(owners)
        for k in targets:
            add(k, fld, f"the task says {word!r}" + (f" about the {k}" if k in kinds else ""))
    if not out:
        g = GENERIC_WORDS.search(text)
        if g:
            for k in kinds:
                for fld in GENERIC_DIGEST[k]:
                    add(k, fld, f"the task asks for the {k} {g.group(0)!r} without naming the algorithm")
    return out


def _hex_grid(h: str, kind: str):
    # Preferred order when nothing is stated: a certificate fingerprint as openssl prints it
    # (AA:BB, upper) and plain lower; a file hash plain lower, then upper.
    if kind == "certificate":
        order = [(True, "upper"), (False, "lower"), (False, "upper"), (True, "lower")]
    else:
        order = [(False, "lower"), (False, "upper"), (True, "upper"), (True, "lower")]
    for colon, case in order:
        v = h.upper() if case == "upper" else h.lower()
        if colon:
            v = ":".join(v[i:i + 2] for i in range(0, len(v), 2))
        yield colon, case, v


def forms(req: Request, fields: dict) -> list[tuple[str, str]]:
    """[(form label, answer)] for one request against one artifact's fields, best first. A stated
    form filters the grid; nothing stated keeps the plausible forms."""
    f = req.form
    fld = req.field
    if fld not in fields:
        return []
    out: list[tuple[str, str]] = []
    if fld in DIGEST_FIELDS or fld == "serial":
        if fld == "serial" and f.decimal:
            return [("decimal", fields["serial_int"])]
        h = fields[fld].replace(":", "")
        grid = list(_hex_grid(h, "certificate" if (req.kind == "certificate" or fld == "serial") else "favicon"))
        if fld == "serial":     # openssl -serial: plain upper first
            grid.sort(key=lambda g: (g[0], g[1] != "upper"))
        for colon, case, v in grid:
            if f.colon is not None and colon != f.colon:
                continue
            if f.case is not None and case != f.case:
                continue
            if f.colon is None and colon and (req.kind == "favicon" or fld == "serial"):
                continue         # a file hash or a serial with colons is never the unstated default
            out.append(((("colons " if colon else "plain ") + case + "case"), v))
        if fld == "serial" and f.colon is None and f.case is None:
            out.append(("decimal", fields["serial_int"]))
    elif fld == "mmh3":
        opts = [("signed (Shodan/FOFA)", fields["mmh3"]), ("unsigned", fields["mmh3_unsigned"])]
        if f.signed is not None:
            opts = [opts[0]] if f.signed else [opts[1]]
        out = opts
    else:
        out = [("as saved", str(fields[fld]))]
    seen, uniq = set(), []
    for label, v in out:
        if v not in seen:
            seen.add(v)
            uniq.append((label, v))
    return uniq[:MAX_FORMS]


# =====================================================================================
#  Flag wrapping
# =====================================================================================

_BRIEF_FMT_RE = re.compile(r"flag format\W{0,8}([A-Za-z0-9][A-Za-z0-9_\-]{0,31})\{", re.IGNORECASE)


def brief_prefix(description: str | None) -> str | None:
    """The flag prefix the brief states ("Flag format: `CSCTF{<answer>}`"), or None."""
    m = _BRIEF_FMT_RE.search(_TAG_RE.sub(" ", str(description or "")).replace("`", " "))
    return m.group(1) if m else None


def wrap(answer: str, description: str | None, profile=None) -> tuple[str | None, str]:
    """(flag, how) for an answer: the brief's stated prefix, else the event's first crib. A flag the
    event's format rejects is not returned (the reason says why)."""
    ff = None
    if profile is not None:
        from . import flagfmt as _flagfmt
        ff = _flagfmt.for_profile(profile)
    pre = brief_prefix(description)
    how = "the brief's flag format"
    if pre is None and ff is not None:
        try:
            pre = ff.cribs()[0][:-1]
            how = "the event flag format"
        except LookupError:
            pre = None
    if pre is None:
        return None, "no flag format: neither the brief nor the event profile states a prefix"
    flag = f"{pre}{{{answer}}}"
    if ff is not None and ff.known and not ff.is_flag(flag):
        return None, f"{flag!r} is not a well-formed flag for the event"
    return flag, how


# =====================================================================================
#  The chain
# =====================================================================================

@dataclass
class Candidate:
    answer: str
    flag: str | None
    kind: str
    field: str
    form: str
    source: str            # the reused file, relative to the workdir
    source_sha256: str
    sibling: str


@dataclass
class Report:
    challenge_dir: Path
    root: Path
    challenge_id: str
    name: str
    series_key: str | None
    marker: str | None
    status: str
    reason: str
    siblings: list = field(default_factory=list)       # [{"dir", "id", "name", "marker"}]
    artifacts: list = field(default_factory=list)      # [Artifact]
    rejected: list = field(default_factory=list)       # [Rejected]
    requests: list = field(default_factory=list)       # [Request]
    candidates: list = field(default_factory=list)     # [Candidate]
    notes: list = field(default_factory=list)

    @property
    def flags(self) -> list[str]:
        return list(dict.fromkeys(c.flag for c in self.candidates if c.flag))

    def to_dict(self) -> dict:
        return {
            "challenge_dir": str(self.challenge_dir), "root": str(self.root),
            "challenge_id": self.challenge_id, "name": self.name, "series_key": self.series_key,
            "marker": self.marker, "status": self.status, "reason": self.reason, "siblings": self.siblings,
            "artifacts": [asdict(a) for a in self.artifacts], "rejected": [asdict(r) for r in self.rejected],
            "requests": [{"kind": r.kind, "field": r.field, "form": r.form.stated(), "why": r.why}
                         for r in self.requests],
            "candidates": [asdict(c) for c in self.candidates], "flags": self.flags, "notes": self.notes,
            "submitted": False,
        }


STATUSES = ("candidate", "unsure-format", "unlinked", "no-sibling", "no-evidence", "unmapped")


def chain(challenge_dir: Path, root: Path | None = None, profile=None) -> Report:
    """Link a challenge to its series siblings in the workdir and compute the field its task asks
    for from the evidence they saved. `root` is the workdir (default: the challenge folder's
    parent). Nothing is submitted and nothing is written; see write_report / record_reuse."""
    challenge_dir = Path(challenge_dir)
    root = Path(root) if root is not None else challenge_dir.resolve().parent
    me = load_task(challenge_dir)
    rep = Report(challenge_dir=challenge_dir, root=root, challenge_id=me.cid, name=me.name,
                 series_key=me.key, marker=me.marker, status="unlinked", reason="")
    if me.key is None:
        if me.marker:
            rep.status = "no-sibling"
            rep.reason = (f"the brief says {me.marker!r} but the name {me.name!r} has no series part "
                          f"(no 'Series: Task' form), so no sibling can be named")
        else:
            rep.reason = f"the name {me.name!r} has no series part and the brief no continuation wording"
        return rep
    tasks, problems = workspace_tasks(root)
    rep.notes += [f"workdir folder not read: {p}" for p in problems]
    sibs = sorted((t for t in tasks if t.key == me.key and t.dir.resolve() != challenge_dir.resolve()),
                  key=Task.sort_key)
    rep.siblings = [{"dir": t.dir_name, "id": t.cid, "name": t.name, "marker": t.marker} for t in sibs]
    if not sibs:
        rep.status = "no-sibling" if me.marker else "unlinked"
        rep.reason = (f"no other task of series {me.key!r} in {root}"
                      + (f" although the brief says {me.marker!r}: pull/intake the first task, then re-run"
                         if me.marker else ""))
        return rep
    for t in sibs:
        arts, rej, notes = collect(t, root)
        rep.artifacts += arts
        rep.rejected += rej
        rep.notes += notes
    rep.requests = requests(me.name, me.description)
    if not rep.requests:
        rep.status = "unmapped"
        have = sorted({a.kind for a in rep.artifacts})
        rep.reason = ("the task wording names no field this module computes (certificate serial / "
                      "fingerprint / SPKI, favicon mmh3 / MD5 / SHA); the siblings saved: "
                      + (", ".join(have) or "nothing it reads"))
        return rep
    for req in rep.requests:
        for a in (x for x in rep.artifacts if x.kind == req.kind):
            for label, ans in forms(req, a.fields):
                flag, how = wrap(ans, me.description, profile)
                rep.candidates.append(Candidate(ans, flag, a.kind, req.field, label, a.path, a.file_sha256,
                                                a.sibling))
                if flag is None and how not in rep.notes:
                    rep.notes.append(how)
    if not rep.candidates:
        rep.status = "no-evidence"
        wanted = sorted({r.kind for r in rep.requests})
        held = [a for a in rep.artifacts if a.kind in wanted]
        if held:
            # The object is there; the requested field could not be computed from it. Say which and why.
            asked = ", ".join(sorted({f"{r.kind} {r.field}" for r in rep.requests}))
            why = "; ".join(f"{a.path}: {a.note}" for a in held if a.note)
            rep.reason = (f"the siblings saved the {' / '.join(wanted)} ({', '.join(a.path for a in held)}), "
                          f"but the requested {asked} could not be computed from it"
                          + (f": {why}" if why else ""))
        else:
            rep.reason = (f"the task asks about the {' / '.join(wanted)}, and no sibling of series {me.key!r} "
                          f"({', '.join(t.dir_name for t in sibs)}) saved one")
        rep.reason += (f"; rejected: {'; '.join(r.path + ': ' + r.reason for r in rep.rejected)}"
                       if rep.rejected else "")
        return rep
    if rep.flags:
        rep.status = "candidate"
        rep.reason = (f"{len(rep.flags)} candidate flag(s) from sibling evidence; never submitted here")
    else:
        rep.status = "unsure-format"
        rep.reason = "answers computed, but no flag format to wrap them in: " + "; ".join(rep.notes[-1:])
    return rep


# =====================================================================================
#  Outputs: the report files and the hypothesis ledger
# =====================================================================================

def render_md(rep: Report) -> str:
    lines = [f"# series chain: {rep.name}", "",
             "Sibling files are data, read and hashed only. Nothing here was submitted.", "",
             f"- status: **{rep.status}** -- {rep.reason}",
             f"- series key: `{rep.series_key}`" + (f"; continuation wording: \"{rep.marker}\"" if rep.marker else "")]
    if rep.siblings:
        lines += ["", "## siblings", ""] + [f"- `{s['dir']}`" for s in rep.siblings]
    if rep.requests:
        lines += ["", "## what the task asks", ""]
        lines += [f"- {r.kind} {r.field}" + (f" ({', '.join(r.form.stated())})" if r.form.stated() else "")
                  + f": {r.why}" for r in rep.requests]
    if rep.candidates:
        lines += ["", "## candidates (best first)", ""]
        for c in rep.candidates:
            shown = c.flag or c.answer
            lines.append(f"- `{shown}` -- {c.kind} {c.field}, {c.form}, from `{c.source}`")
    if rep.artifacts:
        lines += ["", "## sibling evidence", ""]
        for a in rep.artifacts:
            fs = ", ".join(f"{k}={v}" for k, v in a.fields.items() if k in
                           ("serial", "sha256", "sha1", "md5", "mmh3", "spki_sha256", "image_type", "size"))
            lines.append(f"- {a.kind} `{a.path}`: {fs}" + (f" ({a.note})" if a.note else ""))
    if rep.rejected:
        lines += ["", "## not used", ""] + [f"- `{r.path}`: {r.reason}" for r in rep.rejected]
    if rep.notes:
        lines += ["", "## notes", ""] + [f"- {n}" for n in rep.notes]
    return "\n".join(lines) + "\n"


def write_report(rep: Report) -> list[Path]:
    out = rep.challenge_dir / RECON
    out.mkdir(parents=True, exist_ok=True)
    j, m = out / REPORT_JSON, out / REPORT_MD
    j.write_text(json.dumps(rep.to_dict(), indent=1) + "\n", encoding="utf-8")
    m.write_text(render_md(rep), encoding="utf-8")
    return [j, m]


AGENT = "series-chain"


def method_for(c: Candidate) -> str:
    return f"series-chain {c.kind}.{c.field} from {c.sibling}"


def record_reuse(rep: Report, workdir: Path | None = None, profile=None) -> list[dict]:
    """One hypothesis-ledger record per reused (sibling, kind, field): what was reused, from which file
    (and its SHA-256), and the best candidate as the payload. POSITIVE only when the method gave exactly
    one candidate and it is a flag (the brief stated the answer form, one saved object): the ledger's
    flag-format control then verifies it and `hypothesis.should_skip` treats the method as settled.
    When several forms (or several saved objects) remain, the best one is only the first guess, so the
    record is INCONCLUSIVE and the method stays open; likewise when no format could wrap the answer.
    Nothing is written when there is no candidate, and a re-run whose payload is already recorded for
    that method adds nothing."""
    from . import hypothesis as _hyp
    wd = Path(workdir) if workdir is not None else rep.root
    groups: dict[str, list[Candidate]] = {}
    for c in rep.candidates:
        groups.setdefault(method_for(c), []).append(c)
    written = []
    for method, cs in groups.items():
        best = cs[0]
        payload = best.flag or best.answer
        prior = _hyp.seen(rep.challenge_id, method, workdir=wd)
        if prior is not None and prior.get("payload") == payload:
            continue
        others = [c.flag or c.answer for c in cs[1:]]
        settled = bool(best.flag) and not others
        evidence = (f"reused {best.source} (sha256 {best.source_sha256}) saved by sibling {best.sibling}; "
                    f"{best.kind} {best.field} as {best.form}"
                    + (f"; other forms: {' | '.join(others)}" if others else "")
                    + ("" if settled else ("; the answer form is not settled (several candidates)" if others
                                           else "; no flag format to wrap the answer"))
                    + "; a candidate, not submitted")
        written.append(_hyp.record(
            rep.challenge_id,
            hypothesis=f"the {best.kind} {best.field} saved by sibling task {best.sibling} answers this task",
            method=method, result=_hyp.POSITIVE if settled else _hyp.INCONCLUSIVE,
            payload=payload, agent=AGENT, evidence=evidence, workdir=wd, profile=profile))
    return written
