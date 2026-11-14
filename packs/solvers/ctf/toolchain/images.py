"""Pinned toolchain images (B-188): one manifest, a static lint, content-hash labels, build and smoke.

    from ctf.toolchain import images
    imgs = images.load()                        # [Image] from tools/images.toml (ImagesError if bad)
    findings = images.lint(imgs)                # [Finding]: static checks of every Dockerfile + manifest
    images.errors(findings, imgs)               # the findings that fail: those of `pinned = true` images
    images.content_hash(img)                    # sha256 of what the image is built from
    report = images.status(imgs)                # [ImageStatus] from `docker image inspect` (a read)
    steps = images.plan_build(imgs, report)     # [BuildStep]: what to build and why (writes nothing)
    images.apply_build(steps)                   # runs `docker build` (never from tests: stubs only)
    images.smoke(img)                           # the image's own env-check commands, networkless

Why: agents lost turns to tools that were missing or wrong in play (tshark, zsteg, a 7z2john missing
its Perl module), images were rebuilt by hand over and over, and a crypto challenge needed SageMath 10.5
because the latest release gave a self-consistent wrong answer. So the images are pinned and listed
once, each carries a label with the hash of the files it was built from (an image whose label matches
is fresh and never rebuilt), and Sage comes as several tagged images that `ctf.toolchain.versions`
picks from a challenge's version notes.

Lint rules (a pinned image fails on any; an unpinned one, listed with its reason, only reports them):

    from-unpinned       FROM without a tag, or `:latest` (a digest `@sha256:` is always fine)
    arg-unset           a ${VAR} in FROM that neither an ARG default nor the manifest's args sets
    pip-unpinned        a pip install of a package without `==` (requirements/constraints files and
                        local files are fine)
    gem-unpinned        a gem install without -v/--version
    git-unpinned        a git clone in a RUN that names no 40-hex commit
    fetch-unverified    curl/wget/urlopen in a RUN that never mentions sha256; ADD of a URL without
                        --checksum=sha256:
    swallowed-failure   `|| true`, `|| :` or `|| echo`: a failed step that the build hides
    copy-missing        a COPY/ADD source that is not in the build context (staged files count)
    missing-file        the Dockerfile or the context folder is not there; the Dockerfile is outside
                        its context
    py-unpinned         a `py` name the image installs that requirements.in does not pin

Docker is only ever started through `run`, and under CTF_TESTING only a docker that carries STUB_MARKER
in its first STUB_MARKER_WINDOW bytes (ImagesError otherwise, before anything runs): no test inspects,
runs, pulls or builds a real image.
"""
from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import shutil
import subprocess
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .. import env as _env
from .. import paths

MANIFEST_REL = Path("tools") / "images.toml"
REQUIREMENTS_REL = Path("requirements.in")
LABEL = "org.ctf-tools.toolchain.hash"
ROLES = ("core", "optional")
STATES = ("ok", "missing", "stale", "unlabelled", "unknown")
RULES = ("from-unpinned", "arg-unset", "pip-unpinned", "gem-unpinned", "git-unpinned", "fetch-unverified",
         "swallowed-failure", "copy-missing", "missing-file", "py-unpinned")
STAGED_REQUIREMENTS = "toolchain-requirements.txt"   # the image's own pins, written at build time
STAGED_CONSTRAINTS = "toolchain-constraints.txt"     # every pin of requirements.in, as pip constraints
DOCKERIGNORE = ".dockerignore"                      # honoured by context_files (the hash and the stage)
STUB_MARKER = "ctf-docker-stub"
STUB_MARKER_WINDOW = 4096
INSPECT_TIMEOUT = 30.0
SMOKE_TIMEOUT = 300.0

_KEYS = {"name", "tag", "dockerfile", "context", "platform", "role", "args", "py", "download", "smoke",
         "versions", "default_for", "managed", "built_by", "pinned", "unpinned_reason", "provides"}
_DL_KEYS = {"name", "url", "sha256", "arg"}
_NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
_TAG = re.compile(r"^[a-z0-9][a-z0-9_./-]*:[A-Za-z0-9_][A-Za-z0-9_.-]*$")
_ARG = re.compile(r"^[A-Z][A-Z0-9_]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s#;]+)")
_HEX40 = re.compile(r"\b[0-9a-f]{40}\b")
_HEREDOC = re.compile(r"(?<!<)<<(?!<)-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")
_SWALLOW = re.compile(r"\|\|\s*(?:true\b|:(?=\s|$|\)|;)|echo\b)")
_FETCH = re.compile(r"\b(?:curl|wget)\s+(?:-|[\"']?https?://|[\"']?\$)|urlopen\(")


class ImagesError(ValueError):
    """The images manifest is missing or invalid, or a docker call was refused."""


@dataclass(frozen=True)
class Download:
    """A file the Dockerfile fetches: its URL and SHA-256 are passed as the build args <arg>_URL and
    <arg>_SHA256, and the Dockerfile checks the hash. An empty sha256 is unlocked: the image is not
    built until a human records it."""
    name: str
    url: str
    sha256: str
    arg: str

    @property
    def locked(self) -> bool:
        return bool(self.sha256)


@dataclass(frozen=True)
class Image:
    name: str
    tag: str
    dockerfile: str                      # repo-relative
    context: str                         # repo-relative folder; holds the Dockerfile
    role: str = "core"
    platform: str | None = None
    args: tuple[tuple[str, str], ...] = ()
    py: tuple[str, ...] = ()             # requirements.in names this image installs at their pins
    downloads: tuple[Download, ...] = ()
    smoke: tuple[tuple[str, ...], ...] = ()
    versions: tuple[tuple[str, str], ...] = ()   # (tool, version) this image provides, e.g. ("sage", "10.5")
    default_for: tuple[str, ...] = ()    # tools this image is picked for when a challenge names no version
    managed: bool = True                 # False: built by another tool (built_by); never by ctf toolchain build
    built_by: str = ""
    pinned: bool = True                  # False: lint findings are reported, never fatal (unpinned_reason)
    unpinned_reason: str = ""
    provides: str = ""

    def version_of(self, tool: str) -> str | None:
        return dict(self.versions).get(tool)

    def build_args(self) -> dict[str, str]:
        out = dict(self.args)
        for d in self.downloads:
            out[f"{d.arg}_URL"] = d.url
            out[f"{d.arg}_SHA256"] = d.sha256
        return out

    def unlocked(self) -> list[Download]:
        return [d for d in self.downloads if not d.locked]


@dataclass(frozen=True)
class Finding:
    image: str
    path: str
    line: int
    rule: str
    text: str

    def render(self) -> str:
        where = f"{self.path}:{self.line}" if self.line else self.path
        return f"{self.image}: {where}: {self.rule}: {self.text}"


@dataclass(frozen=True)
class ImageStatus:
    name: str
    tag: str
    role: str
    state: str
    detail: str = ""
    fix: str = ""
    want: str = ""                       # the content hash the image should carry
    have: str | None = None              # the label it carries (None: none, or no image)

    def __post_init__(self):
        if self.state not in STATES:
            raise ValueError(f"image status {self.name!r}: state {self.state!r} is not one of {STATES}")

    @property
    def ok(self) -> bool:
        return self.state == "ok"

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "tag": self.tag, "role": self.role, "state": self.state,
                "detail": self.detail, "fix": self.fix, "want": self.want, "have": self.have}

    def line(self) -> str:
        head = f"{self.state.upper():<10} {self.name} ({self.tag})"
        return head + (f": {self.detail}" if self.detail else "") + (f"\n    fix: {self.fix}" if self.fix else "")


@dataclass(frozen=True)
class BuildStep:
    image: str
    tag: str
    action: str                          # build | skip | refused
    reason: str
    argv: tuple[str, ...] | None = None  # the docker build argv; its last item is the context, staged at apply

    def render(self) -> str:
        if self.action == "build":
            return "build   " + " ".join(self.argv or ()) + f"   # {self.reason}"
        return f"{self.action:<7} {self.image} ({self.tag}): {self.reason}"


@dataclass(frozen=True)
class BuildResult:
    step: BuildStep
    returncode: int | None
    output: str
    reason: str = ""                     # "" (it ran) | skip | refused | absent


@dataclass(frozen=True)
class SmokeResult:
    image: str
    argv: tuple[str, ...]
    returncode: int | None
    output: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


@dataclass(frozen=True)
class Instruction:
    line: int
    op: str
    text: str                            # the arguments, continuation lines joined, heredoc bodies appended


# ------------------------------------------------------------------------------------ manifest

def manifest_path(root: Path | None = None) -> Path:
    return (paths.repo_root() if root is None else Path(root)) / MANIFEST_REL


def _strs(where: str, key: str, v: Any) -> tuple[str, ...]:
    if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
        raise ImagesError(f"{where}: {key} must be a list of non-empty strings")
    if len(set(v)) != len(v):
        raise ImagesError(f"{where}: {key} lists an entry twice")
    return tuple(v)


def _str_map(where: str, key: str, v: Any, key_re: re.Pattern) -> tuple[tuple[str, str], ...]:
    if not isinstance(v, dict):
        raise ImagesError(f"{where}: {key} must be a table")
    for k, x in v.items():
        if not key_re.match(k) or not isinstance(x, str) or not x:
            raise ImagesError(f"{where}: {key}.{k} must be a non-empty string under a valid name")
    return tuple(sorted(v.items()))


def parse(data: Mapping[str, Any], src: str = "images.toml") -> list[Image]:
    """[Image] from a decoded manifest. Unknown keys, bad names or tags, duplicate names or tags, an
    image with no smoke check, a bad sha256 or a version tool that is not declared are ImagesError."""
    if set(data) - {"image"}:
        raise ImagesError(f"{src}: unknown top-level key(s) {sorted(set(data) - {'image'})}")
    raw = data.get("image")
    if not isinstance(raw, list) or not raw:
        raise ImagesError(f"{src}: no [[image]] entries")
    out: list[Image] = []
    for i, r in enumerate(raw):
        where = f"{src}: image #{i + 1}"
        if not isinstance(r, dict):
            raise ImagesError(f"{where}: not a table")
        unknown = set(r) - _KEYS
        if unknown:
            raise ImagesError(f"{where}: unknown key(s) {sorted(unknown)}")
        name = r.get("name")
        if not isinstance(name, str) or not _NAME.match(name):
            raise ImagesError(f"{where}: name must match {_NAME.pattern}")
        where = f"{src}: image {name!r}"
        for k in ("tag", "dockerfile", "context"):
            if not isinstance(r.get(k), str) or not r[k]:
                raise ImagesError(f"{where}: {k} is required")
        if not _TAG.match(r["tag"]) or r["tag"].endswith(":latest"):
            raise ImagesError(f"{where}: tag {r['tag']!r} must be repo:tag with an explicit tag, never latest")
        for k in ("dockerfile", "context"):
            p = Path(r[k])
            if p.is_absolute() or ".." in p.parts:
                raise ImagesError(f"{where}: {k} must be repo-relative")
        role = r.get("role", "core")
        if role not in ROLES:
            raise ImagesError(f"{where}: role must be one of {ROLES}")
        for k in ("managed", "pinned"):
            if k in r and not isinstance(r[k], bool):
                raise ImagesError(f"{where}: {k} must be true or false")
        managed, pinned = r.get("managed", True), r.get("pinned", True)
        built_by = r.get("built_by", "")
        if not managed and not (isinstance(built_by, str) and built_by):
            raise ImagesError(f"{where}: managed = false needs built_by (what builds it)")
        reason = r.get("unpinned_reason", "")
        if not pinned and not (isinstance(reason, str) and reason):
            raise ImagesError(f"{where}: pinned = false needs unpinned_reason")
        platform = r.get("platform")
        if platform is not None and (not isinstance(platform, str) or not re.match(r"^linux/[a-z0-9]+$", platform)):
            raise ImagesError(f"{where}: platform must look like linux/amd64")
        smoke_raw = r.get("smoke")
        if not isinstance(smoke_raw, list) or not smoke_raw:
            raise ImagesError(f"{where}: smoke must list at least one command (its env-check)")
        smoke = tuple(_strs(where, "smoke[]", s) for s in smoke_raw)
        downloads = []
        for j, d in enumerate(r.get("download", [])):
            dw = f"{where}: download #{j + 1}"
            if not isinstance(d, dict) or set(d) - _DL_KEYS:
                raise ImagesError(f"{dw}: a table with keys {sorted(_DL_KEYS)}")
            if not all(isinstance(d.get(k), str) for k in _DL_KEYS):
                raise ImagesError(f"{dw}: name, url, sha256 and arg are strings (sha256 may be empty)")
            if not d["url"].startswith("https://"):
                raise ImagesError(f"{dw}: url must be https")
            if d["sha256"] and not _SHA256.match(d["sha256"]):
                raise ImagesError(f"{dw}: sha256 must be 64 lower-case hex digits (or empty: unlocked)")
            if not _ARG.match(d["arg"]):
                raise ImagesError(f"{dw}: arg must match {_ARG.pattern}")
            downloads.append(Download(d["name"], d["url"], d["sha256"], d["arg"]))
        versions = _str_map(where, "versions", r.get("versions", {}), _NAME)
        default_for = _strs(where, "default_for", r.get("default_for", []))
        undeclared = set(default_for) - {t for t, _ in versions}
        if undeclared:
            raise ImagesError(f"{where}: default_for names {sorted(undeclared)} without a version in versions")
        out.append(Image(
            name=name, tag=r["tag"], dockerfile=r["dockerfile"], context=r["context"], role=role,
            platform=platform, args=_str_map(where, "args", r.get("args", {}), _ARG),
            py=_strs(where, "py", r.get("py", [])), downloads=tuple(downloads), smoke=smoke,
            versions=versions, default_for=default_for, managed=managed, built_by=built_by,
            pinned=pinned, unpinned_reason=reason, provides=str(r.get("provides", ""))))
    for what in ("name", "tag"):
        seen: set[str] = set()
        for im in out:
            v = getattr(im, what)
            if v in seen:
                raise ImagesError(f"{src}: {what} {v!r} is used by two images")
            seen.add(v)
    defaults: dict[str, str] = {}
    for im in out:
        for t in im.default_for:
            if t in defaults:
                raise ImagesError(f"{src}: both {defaults[t]!r} and {im.name!r} are the default for {t!r}")
            defaults[t] = im.name
    return out


def load(path: Path | None = None) -> list[Image]:
    p = manifest_path() if path is None else Path(path)
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ImagesError(f"{p}: images manifest not found") from None
    except tomllib.TOMLDecodeError as e:
        raise ImagesError(f"{p}: not valid TOML: {e}") from None
    return parse(data, str(p))


def select(images: Sequence[Image], only: Sequence[str] | None) -> list[Image]:
    if not only:
        return list(images)
    names = {i.name for i in images}
    bad = [n for n in only if n not in names]
    if bad:
        raise ImagesError(f"unknown image(s) {bad}; known: {sorted(names)}")
    return [i for i in images if i.name in only]


# ----------------------------------------------------------------------------------- dockerfile

def parse_dockerfile(text: str) -> list[Instruction]:
    """Instructions with their first line number: `\\` continuations joined (comment lines inside one
    skipped, as Docker does), heredoc bodies (`<<EOF` ... `EOF`) appended to their instruction."""
    lines = text.splitlines()
    out: list[Instruction] = []
    i = 0
    while i < len(lines):
        raw = lines[i]
        s = raw.strip()
        if not s or s.startswith("#"):
            i += 1
            continue
        start, parts = i + 1, []
        while True:
            cur = lines[i].rstrip()
            if cur.strip().startswith("#") and parts:
                i += 1
                if i >= len(lines):
                    break
                continue
            if cur.endswith("\\"):
                parts.append(cur[:-1])
                i += 1
                if i >= len(lines):
                    break
                continue
            parts.append(cur)
            i += 1
            break
        logical = " ".join(p.strip() for p in parts).strip()
        for m in _HEREDOC.finditer(logical):
            end, body = m.group(2), []
            while i < len(lines) and lines[i].strip() != end:
                body.append(lines[i])
                i += 1
            i += 1                       # the terminator
            logical += "\n" + "\n".join(body)
        op, _, rest = logical.partition(" ")
        out.append(Instruction(start, op.upper(), rest.strip()))
    return out


def _subst(text: str, values: Mapping[str, str]) -> tuple[str, list[str]]:
    unset: list[str] = []

    def rep(m: re.Match) -> str:
        name = m.group(1) or m.group(3)
        if name in values:
            return values[name]
        if m.group(2) is not None:
            return m.group(2)
        unset.append(name)
        return m.group(0)
    return _VAR.sub(rep, text), unset


def _segments(text: str) -> list[list[str]]:
    """Shell-ish command segments of a RUN, split on && || ; | and newlines, as whitespace tokens."""
    return [seg.split() for seg in re.split(r"&&|\|\||;|\||\n", text) if seg.strip()]


_PIP_VALUE_OPTS = {"-r", "--requirement", "-c", "--constraint", "-t", "--target", "-i", "--index-url",
                   "--extra-index-url", "-f", "--find-links", "--platform", "--python-version",
                   "--only-binary", "--no-binary", "--prefix", "--root", "--implementation", "--abi",
                   "--progress-bar", "--cache-dir", "--src", "-e", "--editable"}


def _pip_unpinned(seg: list[str]) -> list[str]:
    toks = [t.strip("'\"") for t in seg]
    for k in range(len(toks) - 1):
        if toks[k] in ("pip", "pip3") or re.fullmatch(r"pip3(\.\d+)?", toks[k]):
            if toks[k + 1] == "install":
                rest = toks[k + 2:]
                break
    else:
        return []
    bad, skip = [], False
    for t in rest:
        if skip:
            skip = False
            continue
        if t in _PIP_VALUE_OPTS:
            skip = True
            continue
        if t.startswith("-"):
            continue
        if "==" in t or t.startswith(("/", "./", "$")) or t.endswith((".whl", ".tar.gz", ".zip")):
            continue
        bad.append(t)
    return bad


def _gem_unpinned(seg: list[str]) -> bool:
    for k in range(len(seg) - 1):
        if seg[k] == "gem" and seg[k + 1] == "install":
            rest = seg[k + 2:]
            return not any(t in ("-v", "--version") or t.startswith("--version=") for t in rest)
    return False


def _from_ref(text: str) -> tuple[str | None, str | None]:
    """(image reference, stage name) of a FROM's arguments."""
    toks = [t for t in text.split() if not t.startswith("--")]
    if not toks:
        return None, None
    stage = toks[2] if len(toks) >= 3 and toks[1].upper() == "AS" else None
    return toks[0], stage


def _ref_unpinned(ref: str) -> bool:
    if "@sha256:" in ref:
        return False
    last = ref.rsplit("/", 1)[-1]
    if ":" not in last:
        return True
    return last.rsplit(":", 1)[1] == "latest"


def lint_dockerfile(image: Image, text: str, *, context: Path | None = None,
                    staged: Sequence[str] = ()) -> list[Finding]:
    """The static checks of one Dockerfile's text (rules in the module docstring)."""
    out: list[Finding] = []
    path = image.dockerfile
    values = image.build_args()
    stages: set[str] = set()

    def add(ins: Instruction, rule: str, text: str) -> None:
        out.append(Finding(image.name, path, ins.line, rule, text))

    for ins in parse_dockerfile(text):
        if ins.op == "ARG":
            name, eq, default = ins.text.partition("=")
            name = name.strip()
            if eq and name not in values:
                values[name] = default.strip().strip("'\"")
            continue
        if ins.op == "FROM":
            resolved, unset = _subst(ins.text, values)
            if unset:
                add(ins, "arg-unset", f"FROM uses {', '.join('${' + u + '}' for u in unset)}, which no ARG "
                                      "default or manifest arg sets")
                continue
            ref, stage = _from_ref(resolved)
            if ref and ref != "scratch" and ref not in stages and _ref_unpinned(ref):
                add(ins, "from-unpinned", f"FROM {ref}: name an exact tag (never latest) or a digest")
            if stage:
                stages.add(stage)
            continue
        if ins.op == "RUN":
            if _SWALLOW.search(ins.text):
                add(ins, "swallowed-failure", "`|| true` / `|| :` / `|| echo` hides a failed step; let it "
                                              "fail, or test the condition explicitly")
            for seg in _segments(ins.text):
                bad = _pip_unpinned(seg)
                if bad:
                    add(ins, "pip-unpinned", f"pip install of {', '.join(bad)} without ==version")
                if _gem_unpinned(seg):
                    add(ins, "gem-unpinned", "gem install without -v VERSION")
            if "git clone" in ins.text and not _HEX40.search(ins.text):
                add(ins, "git-unpinned", "git clone with no 40-hex commit to check out")
            if _FETCH.search(ins.text) and "sha256" not in ins.text.lower():
                add(ins, "fetch-unverified", "a download that is never checked against a SHA-256")
            continue
        if ins.op in ("ADD", "COPY"):
            toks = ins.text.split()
            flags = [t for t in toks if t.startswith("--")]
            args = [t for t in toks if not t.startswith("--")]
            if ins.op == "ADD" and any(a.startswith(("http://", "https://")) for a in args[:-1]) \
                    and not any(f.startswith("--checksum=sha256:") for f in flags):
                add(ins, "fetch-unverified", "ADD of a URL without --checksum=sha256:...")
            if context is not None and not any(f.startswith("--from=") for f in flags) and "<<" not in ins.text:
                for src in args[:-1]:
                    if src.startswith(("http://", "https://")) or any(c in src for c in "*?[$"):
                        continue
                    if src in staged:
                        continue
                    if not (context / src).exists():
                        add(ins, "copy-missing", f"{ins.op} source {src!r} is not in {image.context}")
    return out


# ------------------------------------------------------------------------------------- pins / lint

def requirement_pins(root: Path | None = None) -> dict[str, tuple[str, str]]:
    """{normalised name: (name as written, version)} of every pin in requirements.in."""
    p = (paths.repo_root() if root is None else Path(root)) / REQUIREMENTS_REL
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ImagesError(f"{p}: not found (the images' Python pins come from it)") from None
    out = {}
    for line in text.splitlines():
        m = _PIN.match(line)
        if m:
            out[normalise(m.group(1))] = (m.group(1), m.group(2))
    return out


def normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def staged_files(image: Image, root: Path | None = None) -> dict[str, str]:
    """{file name: text} written into the build context at build time: the image's `py` pins taken
    from requirements.in (one source of versions) and every pin there as pip constraints. Empty when
    the image installs no `py` names. ImagesError names a name requirements.in does not pin."""
    if not image.py:
        return {}
    pins = requirement_pins(root)
    missing = [n for n in image.py if normalise(n) not in pins]
    if missing:
        raise ImagesError(f"image {image.name!r}: py name(s) {missing} are not pinned in requirements.in")
    head = f"# generated by ctf toolchain build for {image.name} from requirements.in; do not edit\n"
    reqs = head + "".join(f"{pins[normalise(n)][0]}=={pins[normalise(n)][1]}\n" for n in image.py)
    cons = head + "".join(f"{w}=={v}\n" for w, v in sorted(pins.values(), key=lambda x: normalise(x[0])))
    return {STAGED_REQUIREMENTS: reqs, STAGED_CONSTRAINTS: cons}


def lint(images: Sequence[Image], root: Path | None = None) -> list[Finding]:
    """Every image's findings: missing files, unpinned py names, and lint_dockerfile."""
    root = paths.repo_root() if root is None else Path(root)
    out: list[Finding] = []
    for im in images:
        df, ctx = root / im.dockerfile, root / im.context
        if not ctx.is_dir():
            out.append(Finding(im.name, im.context, 0, "missing-file", "the build context folder is not there"))
            continue
        if not df.is_file():
            out.append(Finding(im.name, im.dockerfile, 0, "missing-file", "the Dockerfile is not there"))
            continue
        if ctx.resolve() not in df.resolve().parents:
            out.append(Finding(im.name, im.dockerfile, 0, "missing-file",
                               f"the Dockerfile is outside its context {im.context}"))
            continue
        try:
            staged = list(staged_files(im, root))
        except ImagesError as e:
            out.append(Finding(im.name, str(REQUIREMENTS_REL), 0, "py-unpinned", str(e)))
            staged = [STAGED_REQUIREMENTS, STAGED_CONSTRAINTS]
        out += lint_dockerfile(im, df.read_text(encoding="utf-8"), context=ctx, staged=staged)
    return out


def errors(findings: Sequence[Finding], images: Sequence[Image]) -> list[Finding]:
    """The findings that fail: every finding of a pinned image."""
    pinned = {i.name for i in images if i.pinned}
    return [f for f in findings if f.image in pinned]


# ------------------------------------------------------------------------------------------- hash

def _glob_rx(pattern: str) -> re.Pattern:
    """A .dockerignore pattern as a regex over a context-relative posix path, as Docker reads it: `*`
    and `?` stop at `/`, `**` spans folders, `[...]` is a class (`[!x]` negated)."""
    out, i, n = "", 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                i += 2
                if i < n and pattern[i] == "/":
                    i += 1
                out += ".*" if i >= n else "(?:.*/)?"
                continue
            out += "[^/]*"
        elif c == "?":
            out += "[^/]"
        elif c == "[" and "]" in pattern[i + 1:]:
            j = pattern.index("]", i + 1)
            body = pattern[i + 1:j]
            if body.startswith("!"):
                body = "^" + body[1:]
            out += "[" + body.replace("\\", "\\\\") + "]"
            i = j
        elif c == "\\" and i + 1 < n:
            i += 1
            out += re.escape(pattern[i])
        else:
            out += re.escape(c)
        i += 1
    return re.compile(out)


def dockerignore_rules(ctx: Path) -> list[tuple[bool, re.Pattern]]:
    """(is_exception, regex) per pattern of <ctx>/.dockerignore, in order; [] when there is none."""
    p = Path(ctx) / DOCKERIGNORE
    if not p.is_file():
        return []
    rules = []
    for line in p.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        neg = s.startswith("!")
        s = posixpath.normpath(s[1:].strip() if neg else s).lstrip("/")
        if s in ("", "."):
            continue
        rules.append((neg, _glob_rx(s)))
    return rules


def dockerignored(rel: str, rules: Sequence[tuple[bool, re.Pattern]]) -> bool:
    """Whether Docker leaves rel out of the context: the last pattern that matches rel or one of its
    parent folders decides (an `!` exception brings it back)."""
    parts = rel.split("/")
    prefixes = ["/".join(parts[:k]) for k in range(1, len(parts) + 1)]
    out = False
    for neg, rx in rules:
        if any(rx.fullmatch(p) for p in prefixes):
            out = not neg
    return out


def context_files(image: Image, root: Path | None = None) -> list[str]:
    """The context-relative posix paths of the files Docker is sent for the image: every file of the
    context except what its .dockerignore leaves out (the Dockerfile and .dockerignore always stay, as
    Docker sends them regardless). Sorted. Both content_hash and stage use this list."""
    root = paths.repo_root() if root is None else Path(root)
    ctx = root / image.context
    rules = dockerignore_rules(ctx)
    keep = {Path(image.dockerfile).relative_to(image.context).as_posix(), DOCKERIGNORE}
    out = []
    for p in ctx.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(ctx).as_posix()
        if rel in keep or not dockerignored(rel, rules):
            out.append(rel)
    return sorted(out)


def content_hash(image: Image, root: Path | None = None) -> str:
    """sha256 over everything the image is built from: each file Docker is sent (context_files: the
    context minus its .dockerignore, so a stray .DS_Store listed there never marks an image stale), the
    staged pin files, the build args (download URLs and hashes included), the tag and platform."""
    root = paths.repo_root() if root is None else Path(root)
    ctx = root / image.context
    h = hashlib.sha256()

    def feed(label: str, data: bytes) -> None:
        h.update(label.encode() + b"\0" + str(len(data)).encode() + b"\0" + data)

    feed("dockerfile", Path(image.dockerfile).relative_to(image.context).as_posix().encode())
    for rel in context_files(image, root):
        feed("file:" + rel, (ctx / rel).read_bytes())
    for name, text in sorted(staged_files(image, root).items()):
        feed("staged:" + name, text.encode())
    feed("args", json.dumps(image.build_args(), sort_keys=True).encode())
    feed("platform", (image.platform or "").encode())
    feed("tag", image.tag.encode())
    return h.hexdigest()


# ----------------------------------------------------------------------------------------- docker

def _is_stub(prog: str, path_env: str | None) -> bool:
    w = shutil.which(prog, path=path_env)
    if not w:
        return False
    try:
        with open(w, "rb") as fh:
            return STUB_MARKER.encode() in fh.read(STUB_MARKER_WINDOW)
    except OSError:
        return False


def docker_path(environ: Mapping[str, str] | None = None) -> str | None:
    """The docker on PATH, or None. Under CTF_TESTING (in environ or in this process's environment) a
    docker that is not a stub is ImagesError."""
    e = os.environ if environ is None else environ
    w = shutil.which("docker", path=e.get("PATH"))
    testing = _env.get_bool("CTF_TESTING", environ=e) or _env.get_bool("CTF_TESTING")
    if w and testing and not _is_stub("docker", e.get("PATH")):
        raise ImagesError(f"refused under CTF_TESTING: {w} is not a test stub (a stub carries "
                          f"{STUB_MARKER!r}); no test talks to a real docker")
    return w


def _call(run, argv, environ, timeout):
    try:
        p = run(list(argv), capture_output=True, text=True, env=dict(environ), timeout=timeout,
                stdin=subprocess.DEVNULL)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout:.0f} s"
    except OSError as ex:
        return 127, str(ex)


def status(images: Sequence[Image], *, root: Path | None = None, environ: Mapping[str, str] | None = None,
           run: Callable[..., Any] = subprocess.run) -> list[ImageStatus]:
    """Each image's local state through `docker image inspect` (a read): ok (its label is the current
    content hash), stale (another hash: rebuild), unlabelled (built outside `ctf toolchain build`, so
    its content is unknown), missing, or unknown (docker absent, or it did not answer)."""
    e = dict(os.environ if environ is None else environ)
    docker = docker_path(e)
    out = []
    for im in images:
        want = content_hash(im, root)
        build = ("`python -m ctf toolchain build --apply --only " + im.name + "`") if im.managed else im.built_by
        if docker is None:
            out.append(ImageStatus(im.name, im.tag, im.role, "unknown", "docker is not on PATH",
                                   "install Docker Desktop", want))
            continue
        rc, txt = _call(run, [docker, "image", "inspect", "--format", "{{json .Config.Labels}}", im.tag], e,
                        INSPECT_TIMEOUT)
        if rc != 0:
            if "no such image" in txt.lower():
                out.append(ImageStatus(im.name, im.tag, im.role, "missing", "not built here", build, want))
            else:
                out.append(ImageStatus(im.name, im.tag, im.role, "unknown",
                                       f"docker image inspect exited {rc}: {txt.strip()[:160]}",
                                       "start Docker Desktop", want))
            continue
        try:
            labels = json.loads(txt.strip().splitlines()[-1] if txt.strip() else "null") or {}
        except (json.JSONDecodeError, IndexError):
            out.append(ImageStatus(im.name, im.tag, im.role, "unknown", f"unreadable labels: {txt.strip()[:120]}",
                                   "", want))
            continue
        have = labels.get(LABEL) if isinstance(labels, dict) else None
        if not im.managed:
            out.append(ImageStatus(im.name, im.tag, im.role, "ok",
                                   f"present (built by {im.built_by}; not hash-labelled)", "", want, have))
        elif have is None:
            out.append(ImageStatus(im.name, im.tag, im.role, "unlabelled",
                                   "built outside `ctf toolchain build`: its content is not known to match",
                                   build, want, None))
        elif have != want:
            out.append(ImageStatus(im.name, im.tag, im.role, "stale",
                                   f"built from other files (label {have[:12]}, now {want[:12]})", build, want, have))
        else:
            out.append(ImageStatus(im.name, im.tag, im.role, "ok", "", "", want, have))
    return out


def plan_build(images: Sequence[Image], report: Sequence[ImageStatus] | None = None, *,
               root: Path | None = None, force: bool = False) -> list[BuildStep]:
    """What `apply_build` would do, per image: build (missing, stale, unlabelled or unknown; any with
    force), skip (fresh, or built by another tool), refused (a download with no sha256, or a pinned
    image with a lint finding: `lint` runs here, so `build --apply` never builds and labels an image
    that breaks a pinning rule). Writes nothing."""
    by = {s.name: s for s in (report or ())}
    out = []
    for im in images:
        if not im.managed:
            out.append(BuildStep(im.name, im.tag, "skip", f"built by {im.built_by}"))
            continue
        why_not = [f"download {d.name!r} has no sha256: compute it with `curl -fsSL {d.url} | shasum -a 256` "
                   f"and set it in {MANIFEST_REL}" for d in im.unlocked()]
        bad = errors(lint([im], root), [im])
        if bad:
            why_not.append(f"{len(bad)} lint finding(s) on a pinned image (`python -m ctf toolchain lint "
                           f"--only {im.name}`): " + "; ".join(f.render() for f in bad[:3]))
        if why_not:
            out.append(BuildStep(im.name, im.tag, "refused", "; ".join(why_not)))
            continue
        st = by.get(im.name)
        if st is not None and st.ok and not force:
            out.append(BuildStep(im.name, im.tag, "skip", "fresh: its label matches the current files"))
            continue
        want = st.want if st is not None else content_hash(im, root)
        argv = ["docker", "build"]
        if im.platform:
            argv += ["--platform", im.platform]
        argv += ["-t", im.tag, "-f", Path(im.dockerfile).relative_to(im.context).as_posix(),
                 "--label", f"{LABEL}={want}"]
        for k, v in sorted(im.build_args().items()):
            argv += ["--build-arg", f"{k}={v}"]
        argv.append(im.context)
        why = "forced" if force and st is not None and st.ok else (st.state if st is not None else "not inspected")
        out.append(BuildStep(im.name, im.tag, "build", why, tuple(argv)))
    return out


def stage(image: Image, dest: Path, root: Path | None = None) -> Path:
    """Copy the image's context files (context_files: what the hash covers) to dest (a new folder)
    and write its staged pin files there."""
    root = paths.repo_root() if root is None else Path(root)
    ctx = root / image.context
    dest = Path(dest)
    dest.mkdir(parents=True)
    for rel in context_files(image, root):
        (dest / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ctx / rel, dest / rel)
    for name, text in staged_files(image, root).items():
        (dest / name).write_text(text, encoding="utf-8")
    return dest


def apply_build(steps: Sequence[BuildStep], images: Sequence[Image], *, root: Path | None = None,
                environ: Mapping[str, str] | None = None,
                run: Callable[..., Any] = subprocess.run) -> list[BuildResult]:
    """Run each `build` step's docker build in a staged copy of its context (the staged pin files
    beside the Dockerfile). Skips and refusals are passed through; with no docker every build is
    `absent`. Under CTF_TESTING docker must be a stub (ImagesError before anything runs)."""
    e = dict(os.environ if environ is None else environ)
    docker = docker_path(e)
    by = {i.name: i for i in images}
    out = []
    for s in steps:
        if s.action != "build" or not s.argv:
            out.append(BuildResult(s, None, s.reason, s.action))
            continue
        if docker is None:
            out.append(BuildResult(s, None, "docker is not on PATH", "absent"))
            continue
        with tempfile.TemporaryDirectory(prefix="ctf-image-") as tmp:
            ctx = stage(by[s.image], Path(tmp) / "context", root)
            argv = [docker, *s.argv[1:-1], str(ctx)]
            rc, txt = _call(run, argv, e, None)
        out.append(BuildResult(s, rc, txt))
    return out


def run_argv(image: Image, cmd: Sequence[str], *, workdir: Path | None = None) -> list[str]:
    """`docker run` for one command in the image: no network, never a pull, every capability dropped;
    with workdir, that folder mounted at /work and used as the working directory."""
    argv = ["docker", "run", "--rm", "--network", "none", "--pull=never", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges"]
    if image.platform:
        argv += ["--platform", image.platform]
    if workdir is not None:
        argv += ["-v", f"{Path(workdir).resolve()}:/work", "-w", "/work"]
    return argv + [image.tag, *cmd]


def smoke(image: Image, *, environ: Mapping[str, str] | None = None,
          run: Callable[..., Any] = subprocess.run, timeout: float = SMOKE_TIMEOUT) -> list[SmokeResult]:
    """Run the image's smoke commands (its env-check), each in a fresh networkless container."""
    e = dict(os.environ if environ is None else environ)
    docker = docker_path(e)
    if docker is None:
        raise ImagesError("docker is not on PATH: cannot smoke-test an image")
    out = []
    for cmd in image.smoke:
        argv = [docker, *run_argv(image, cmd)[1:]]
        rc, txt = _call(run, argv, e, timeout)
        out.append(SmokeResult(image.name, tuple(cmd), rc, txt))
    return out


def problems(report: Sequence[ImageStatus], core_only: bool = False) -> list[ImageStatus]:
    return [s for s in report if not s.ok and (s.role == "core" or not core_only)]


__all__ = ["BuildResult", "BuildStep", "Download", "Finding", "Image", "ImageStatus", "ImagesError",
           "Instruction", "SmokeResult", "apply_build", "content_hash", "context_files", "docker_path",
           "dockerignore_rules", "dockerignored", "errors", "lint",
           "lint_dockerfile", "load", "manifest_path", "normalise", "parse", "parse_dockerfile", "plan_build",
           "problems", "requirement_pins", "run_argv", "select", "smoke", "stage", "staged_files", "status"]
