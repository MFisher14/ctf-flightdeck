"""Blind rehearsal corpus of past-CTF challenges (B-155).

Rehearsal (B-039) replays one wave against a synthetic board. This module rehearses against *real
past challenges* instead. For every indexed challenge present in the external corpus it:

1. stages the handout blind (the key, the replay spec and the strip globs removed; symlinks that
   leave the challenge or point at an answer, and any file holding the key verbatim, are refused);
2. names the engines the manifest router routes it to (checked against the entry's expect_engines);
3. for a live-service challenge, starts its declarative replay (ctf.livereplay: DNS, socat or web on
   127.0.0.1) and drives the spec's probe once as a **reachability check** (reported apart from the
   solve: the probe is the corpus author's, not an engine);
4. serves every staged challenge on the B-039 fake CTFd (ctf.fakectfd), with the replay endpoint as
   its `connection_info`, and runs the no-model intake (ctf.intake: download through the CTFd
   adapter, the B-013 sweep, the engines with an [intake] adapter through the Phase 0 runner) on it;
5. scores what the tooling produced (the sweep's flags and each engine run's own flags, per engine)
   against the challenge's key.

A flag that only the live service holds is therefore *not* solved unless tooling reaches it: the
report says so (the live-only solver gap is visible, never papered over by the probe). Nothing here
submits, and no challenge binary runs.

The corpus itself stays OUT of this repo: challenge files and flags live under a configured path
(ctf.paths.rehearsal_corpus_root, $CTF_REHEARSAL_CORPUS), exactly as the real-data corpus does. This
repo holds only the tooling and an index (corpus/rehearsal-index.toml) that names the challenges and
how to stage them, with no challenge bytes and no flags. `import_challenge` turns a cloned public
challenge folder into a corpus entry (answer files stripped) and prints its index stanza.

    from ctf import corpus
    idx = corpus.load_index()                     # [CorpusChallenge]; metadata only, from the repo
    root = paths.require_rehearsal_corpus()        # the external corpus (raises if unset/absent)
    rep = corpus.rehearse(profile, idx, root, Path(tmp))     # tmp must be empty
    print(rep.render())

Index entry (TOML, repo-side, no flags):

    [[challenge]]
    id = "csctf2025-dns-logs"          # [A-Za-z0-9][A-Za-z0-9._-]*: it names a folder
    name = "logs"
    category = "Forensics"
    description = "A DNS capture; the flag hides in a TXT record."
    path = "csctf2025/logs"            # subfolder under the corpus root (must stay inside it)
    stage = ["*"]                      # fnmatch globs to present blind (default ["*"] = all;
                                       #   fnmatch '*' spans '/', so "*.pcap" matches at any depth)
    strip = ["solution/**", "*.sol"]   # answer files never staged (fnmatch, plus key_file always)
    key_file = "flag.txt"              # the flag, read from the corpus to score; never staged
    expect_engines = ["forensics.pcap_dns"]   # engines the router should name (optional)
    service = "service.toml"           # a replay spec in the corpus (optional, for live challenges)

A `service.toml`/`.json` in the corpus holds the ctf.livereplay spec (kind dns|socat|web).
"""
from __future__ import annotations

import dataclasses
import fnmatch
import io
import json
import os
import re
import secrets
import shutil
import tomllib
import zipfile
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path

from . import flagfmt, livereplay, paths
from .event import EventProfile

INDEX_REL = Path("corpus") / "rehearsal-index.toml"
KEY_NEVER_STAGED = "the key file and strip globs are never staged (blind)"
_VALID_CATS_HINT = "a non-empty category string"
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
DEFAULT_ENGINE_BUDGET = 60.0
# fake-board request kinds a blind rehearsal must never cause: a hint spend, an unknown route, a
# request without the token, or a flag submission (nothing here submits)
BOARD_FORBIDDEN = ("hint", "unknown", "unauthenticated", "attempt")
# answer files a public challenge repo commonly carries; `import_challenge` never copies them
ANSWER_NAMES = ("solve*", "solution*", "solutions", "writeup*", "write-up*", "exploit*", "answer*",
                "*.sol", "sol.py", "flag_solver*", ".git")


class CorpusError(RuntimeError):
    """The corpus index or a staged challenge is malformed; the message says why."""


@dataclass(frozen=True)
class CorpusChallenge:
    id: str
    name: str
    category: str
    description: str = ""
    path: str = ""
    stage: tuple[str, ...] = ("*",)
    strip: tuple[str, ...] = ()
    key_file: str = "flag.txt"
    expect_engines: tuple[str, ...] = ()
    service: str | None = None             # corpus-relative replay spec file, or None

    def challenge_dir(self, corpus_root: Path) -> Path:
        rel = self.path or self.id
        base = Path(corpus_root).resolve()
        d = (base / rel).resolve()
        if d != base and base not in d.parents:
            raise CorpusError(f"challenge {self.id!r}: path {rel!r} escapes the corpus root")
        return d


# -------------------------------------------------------------------------------------- index

def _as_strlist(value, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise CorpusError(f"{where} must be a list of strings")
    return tuple(value)


def check_id(cid, where: str = "challenge") -> str:
    """A challenge id names a folder under the rehearsal workdir: letters, digits, '.', '_', '-',
    not starting with a dot or dash, and never '..'."""
    if not isinstance(cid, str) or not cid.strip():
        raise CorpusError(f"{where}: id must be a non-empty string")
    if not _ID_RE.match(cid) or ".." in cid:
        raise CorpusError(f"{where}: id {cid!r} must match {_ID_RE.pattern} with no '..' (it names a folder)")
    return cid


def parse_index(data: dict, *, src: str = "<index>") -> list[CorpusChallenge]:
    rows = data.get("challenge")
    if rows is None:
        raise CorpusError(f"{src}: no [[challenge]] entries")
    if not isinstance(rows, list):
        raise CorpusError(f"{src}: [challenge] must be a table array ([[challenge]])")
    out: list[CorpusChallenge] = []
    seen: set[str] = set()
    for i, row in enumerate(rows):
        where = f"{src}: challenge #{i + 1}"
        if not isinstance(row, dict):
            raise CorpusError(f"{where} is not a table")
        cid = check_id(row.get("id"), where)
        if cid in seen:
            raise CorpusError(f"{src}: duplicate challenge id {cid!r}")
        seen.add(cid)
        cat = row.get("category")
        if not isinstance(cat, str) or not cat.strip():
            raise CorpusError(f"{where} ({cid}): category must be {_VALID_CATS_HINT}")
        svc = row.get("service")
        if svc is not None and (not isinstance(svc, str) or not svc.strip()):
            raise CorpusError(f"{where} ({cid}): service must be a corpus-relative filename or omitted")
        key_file = row.get("key_file", "flag.txt")
        if not isinstance(key_file, str) or not key_file.strip():
            raise CorpusError(f"{where} ({cid}): key_file must be a non-empty string")
        out.append(CorpusChallenge(
            id=cid,
            name=str(row.get("name", cid)),
            category=cat,
            description=str(row.get("description", "")),
            path=str(row.get("path", "")),
            stage=_as_strlist(row.get("stage"), f"{where} ({cid}): stage") or ("*",),
            strip=_as_strlist(row.get("strip"), f"{where} ({cid}): strip"),
            key_file=key_file,
            expect_engines=_as_strlist(row.get("expect_engines"), f"{where} ({cid}): expect_engines"),
            service=svc,
        ))
    return out


def index_path() -> Path:
    return paths.repo_root() / INDEX_REL


def load_index(path: Path | None = None) -> list[CorpusChallenge]:
    """The committed corpus index (challenge metadata only). Raises CorpusError (named) when missing
    or malformed — never a silent empty list."""
    p = index_path() if path is None else Path(path)
    if not p.is_file():
        raise CorpusError(f"corpus index not found at {p}")
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise CorpusError(f"{p}: {e}") from None
    return parse_index(data, src=str(p))


# -------------------------------------------------------------------------------------- staging

def _matches(rel: str, globs) -> bool:
    return any(fnmatch.fnmatch(rel, g) for g in globs)


def _inside(p: Path, base: Path) -> bool:
    return p == base or base in p.parents


def _answer_paths(challenge: CorpusChallenge, cdir: Path) -> dict[Path, str]:
    out = {(cdir / challenge.key_file).resolve(): "the key file"}
    if challenge.service:
        out[(cdir / challenge.service).resolve()] = "the replay service spec"
    return out


def staged_members(challenge: CorpusChallenge, corpus_root: Path) -> list[Path]:
    """The files that staging would present, as paths relative to the challenge dir: every file under
    a `stage` glob, minus the `strip` globs, the key file and the service spec. Deterministic (sorted).

    Symlinks are never trusted: one that resolves outside the challenge folder, or onto the key or the
    service spec, raises CorpusError (strip it in the index); a symlinked directory is not descended
    and raises the same way unless a strip glob covers it."""
    cdir = challenge.challenge_dir(corpus_root)
    if not cdir.is_dir():
        raise CorpusError(f"challenge {challenge.id!r}: {cdir} is not a directory in the corpus")
    # the key and the replay service spec hold the answer; never stage either, however globs are written
    always = (challenge.key_file,) + ((challenge.service,) if challenge.service else ())
    strip = tuple(challenge.strip) + always
    answers = _answer_paths(challenge, cdir)
    out = []
    for dirpath, dirnames, filenames in os.walk(cdir, followlinks=False):
        d = Path(dirpath)
        for name in list(dirnames):
            sub = d / name
            if sub.is_symlink():
                dirnames.remove(name)
                rel = sub.relative_to(cdir).as_posix()
                if not (_matches(rel, strip) or _matches(rel + "/x", strip)):
                    raise CorpusError(f"challenge {challenge.id!r}: {rel} is a symlinked directory; "
                                      "staging never follows one (strip it or replace it with its files)")
        for name in filenames:
            f = d / name
            rel = f.relative_to(cdir).as_posix()
            if not _matches(rel, challenge.stage) or _matches(rel, strip):
                continue
            target = f.resolve()
            if f.is_symlink():
                if not _inside(target, cdir):
                    raise CorpusError(f"challenge {challenge.id!r}: {rel} is a symlink that escapes the "
                                      "challenge folder; staging never follows it (strip it)")
            if target in answers:
                raise CorpusError(f"challenge {challenge.id!r}: {rel} is a link to {answers[target]} and "
                                  f"would leak it ({KEY_NEVER_STAGED}; strip it)")
            if not target.is_file():
                continue                      # a dangling link or a socket/fifo: nothing to stage
            out.append(Path(rel))
    return sorted(out, key=lambda p: p.as_posix())


def stage(challenge: CorpusChallenge, corpus_root: Path, dest: Path) -> list[Path]:
    """Copy the staged members into `dest` (created; it must be absent or empty, so nothing left from
    an earlier run is scanned again). The key file, the service spec and the strip globs are never
    copied, so the staged tree is blind. Raises CorpusError when a member would leak the key: a copy of
    the key file under another name (its bytes equal the key) or a link to it. Returns the staged
    relative paths."""
    cdir = challenge.challenge_dir(corpus_root)
    dest = Path(dest)
    if dest.exists() and (not dest.is_dir() or any(dest.iterdir())):
        raise CorpusError(f"challenge {challenge.id!r}: staging folder {dest} is not empty "
                          "(stale files from an earlier run would be scanned again)")
    members = staged_members(challenge, corpus_root)
    key = _key_bytes(challenge, cdir)
    for rel in members:
        data = (cdir / rel).resolve().read_bytes()
        if key and data.strip() == key:
            raise CorpusError(f"challenge {challenge.id!r}: {rel.as_posix()} holds the key verbatim and "
                              f"would leak it ({KEY_NEVER_STAGED}; add it to strip)")
    dest.mkdir(parents=True, exist_ok=True)
    for rel in members:
        dst = dest / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile((cdir / rel).resolve(), dst)
    # guard: neither the key nor the service spec (both hold the answer) may reach the staged tree
    for answer in (challenge.key_file,) + ((challenge.service,) if challenge.service else ()):
        if (dest / answer).exists():
            raise CorpusError(f"challenge {challenge.id!r}: {answer} reached the staged tree ({KEY_NEVER_STAGED})")
    return members


def _key_bytes(challenge: CorpusChallenge, cdir: Path) -> bytes | None:
    kf = cdir / challenge.key_file
    if not kf.is_file():
        return None
    return kf.read_bytes().strip() or None


def read_key(challenge: CorpusChallenge, corpus_root: Path) -> str:
    """The flag for this challenge, read from the corpus key file. Raises CorpusError (named) when the
    key file is missing — the corpus cannot score without it (no silent pass)."""
    kf = challenge.challenge_dir(corpus_root) / challenge.key_file
    if not kf.is_file():
        raise CorpusError(f"challenge {challenge.id!r}: no key file at {kf} (set key_file / populate the corpus)")
    return kf.read_text(encoding="utf-8").strip()


def load_service_spec(challenge: CorpusChallenge, corpus_root: Path) -> dict:
    """The replay spec for a live-service challenge, read from the corpus (TOML or JSON)."""
    if not challenge.service:
        raise CorpusError(f"challenge {challenge.id!r} declares no service")
    spec_file = challenge.challenge_dir(corpus_root) / challenge.service
    if not spec_file.is_file():
        raise CorpusError(f"challenge {challenge.id!r}: service spec {spec_file} not found in the corpus")
    text = spec_file.read_text(encoding="utf-8")
    try:
        spec = json.loads(text) if spec_file.suffix == ".json" else tomllib.loads(text)
    except (tomllib.TOMLDecodeError, json.JSONDecodeError) as e:
        raise CorpusError(f"challenge {challenge.id!r}: bad service spec {spec_file.name}: {e}") from None
    if not isinstance(spec, dict) or spec.get("kind") not in livereplay.VALID_KINDS:
        raise CorpusError(f"challenge {challenge.id!r}: service spec needs kind in {livereplay.VALID_KINDS}")
    return spec


# -------------------------------------------------------------------------------------- scoring

SCORES = ("correct", "incorrect", "no-candidate", "no-key")


def score(candidates: list[str], key: str, ff: flagfmt.FlagFormat, notes: list[str] | None = None) -> str:
    """correct if any candidate matches the key (format-normalised), incorrect if candidates were
    found but none match, no-candidate if none were found. A value the event's flag format cannot
    normalise is compared stripped, and that is said in `notes` when a list is given."""
    if not candidates:
        return "no-candidate"

    def norm(s: str, what: str) -> str:
        try:
            return ff.normalize(s)
        except ValueError as e:
            if notes is not None:
                msg = f"{what} does not normalise under the event flag format ({e}); compared stripped"
                if msg not in notes:
                    notes.append(msg)
            return s.strip()
    want = norm(key, "the key")
    return "correct" if any(norm(c, f"candidate {c!r}") == want for c in candidates) else "incorrect"


# -------------------------------------------------------------------------------------- report

@dataclass
class EngineResult:
    """What one source of candidates produced on one challenge: an engine run by intake, or the sweep."""
    engine: str
    status: str                            # the run's status (ok | failed | timeout | error), or "sweep"
    flags: list[str]
    scored: str

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclass
class Outcome:
    id: str
    category: str
    name: str
    staged_files: int
    engines: list[str]                     # the engine ids the router names (routing, not a run)
    expect_engines: list[str]
    candidates: list[str]                  # every flag the tooling produced (sweep + engine runs)
    scored: str                            # the candidates against the key
    engine_results: list[EngineResult] = field(default_factory=list)   # per source, scored
    live: str | None = None                # the replay kind, or None for a static challenge
    live_reachable: bool = False           # the replay started and its probe ran
    live_endpoint: str | None = None
    live_published: bool = False           # intake saw the endpoint as the challenge's connection_info
    live_probe_has_key: bool | None = None  # the corpus probe's reply holds the key (replay fidelity)
    intake_status: str | None = None       # the intake SolverResult status (blocked = it could not run)
    notes: list[str] = field(default_factory=list)

    @property
    def engines_ok(self) -> bool:
        return set(self.expect_engines) <= set(self.engines)

    @property
    def passed(self) -> bool:
        if self.scored in ("incorrect", "no-key"):
            return False
        if not self.engines_ok:
            return False
        if self.intake_status in (None, "blocked"):
            return False
        if self.live is not None and not (self.live_reachable and self.live_published):
            return False
        return self.scored == "correct"

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["engines_ok"] = self.engines_ok
        d["passed"] = self.passed
        return d


@dataclass
class CorpusReport:
    slug: str
    corpus_root: Path
    outcomes: list[Outcome] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    hygiene: list[str] = field(default_factory=list)      # requests the fake board must never see

    @property
    def passed(self) -> bool:
        return bool(self.outcomes) and not self.hygiene and all(o.passed for o in self.outcomes)

    def engine_matrix(self) -> dict[str, dict[str, int]]:
        """Per engine: how many challenges expected it, how many of those the router named it on
        (`fired`), how many challenges it actually ran on, and on how many its own output held the key."""
        m: dict[str, dict[str, int]] = {}

        def row(e):
            return m.setdefault(e, {"expected": 0, "fired": 0, "ran": 0, "correct": 0})
        for o in self.outcomes:
            for e in o.expect_engines:
                r = row(e)
                r["expected"] += 1
                if e in o.engines:
                    r["fired"] += 1
            for er in o.engine_results:
                r = row(er.engine)
                r["ran"] += 1
                if er.scored == "correct":
                    r["correct"] += 1
        return m

    def render(self) -> str:
        out = [f"blind corpus rehearsal for {self.slug}, corpus {self.corpus_root}",
               f"  {len(self.outcomes)} challenge(s) staged, {len(self.skipped)} skipped"]
        for n in self.notes:
            out.append(f"  note: {n}")
        for h in self.hygiene:
            out.append(f"  BOARD the fake CTFd saw a request a blind rehearsal must not make: {h}")
        for s in self.skipped:
            out.append(f"  SKIP {s}")
        for o in self.outcomes:
            live = ""
            if o.live:
                live = (f" live={o.live}{'(reachable)' if o.live_reachable else '(UNREACHABLE)'}"
                        f"{'' if o.live_published else '(NOT PUBLISHED)'}")
            eng = "ok" if o.engines_ok else f"MISSING {sorted(set(o.expect_engines) - set(o.engines))}"
            flag = "PASS" if o.passed else "FAIL"
            out.append(f"  {flag} {o.id} [{o.category}] files={o.staged_files} "
                       f"routed({len(o.engines)})={eng} intake={o.intake_status} scored={o.scored}{live}")
            for er in o.engine_results:
                out.append(f"       {er.engine}: {er.status} flags={len(er.flags)} scored={er.scored}")
            for n in o.notes:
                out.append(f"       note: {n}")
        matrix = self.engine_matrix()
        if matrix:
            out.append("  per-engine (routed/expected, correct/ran): " + ", ".join(
                f"{e} {v['fired']}/{v['expected']} {v['correct']}/{v['ran']}" for e, v in sorted(matrix.items())))
        if not self.outcomes:
            out.append("  nothing was rehearsed: no indexed challenge is present in the corpus")
        out.append("CORPUS REHEARSAL PASSED" if self.passed else "CORPUS REHEARSAL FAILED")
        return "\n".join(out)

    def to_dict(self) -> dict:
        return {"slug": self.slug, "corpus_root": str(self.corpus_root), "passed": self.passed,
                "skipped": self.skipped, "notes": self.notes, "hygiene": self.hygiene, "engine_matrix": self.engine_matrix(),
                "outcomes": [o.to_dict() for o in self.outcomes]}


# -------------------------------------------------------------------------------------- rehearse

def _route(challenge: CorpusChallenge, files_dir: Path, root: Path | None) -> list[str]:
    """The engine ids the manifest router names for this challenge (best first), deduped. Engine ids
    are `lane.name` (Manifest.id), the same identifiers an index's expect_engines lists."""
    from .engines import router
    hits = router.route(challenge.category, challenge.description, files_dir, root=root)
    engines: list[str] = []
    for h in hits:
        if h.manifest.id not in engines:
            engines.append(h.manifest.id)
    return engines


def board_files(staged: Path, members: list[Path], cid: str) -> dict[str, bytes]:
    """The handout as the fake board serves it: the files as they are when all sit at the top level
    (CTFd file names have no folders), else one `<id>.zip` holding the staged tree, which the intake
    sweep unpacks."""
    if all(len(m.parts) == 1 for m in members):
        return {m.name: (staged / m).read_bytes() for m in members}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for m in members:
            z.write(staged / m, m.as_posix())
    return {f"{cid}.zip": buf.getvalue()}


@dataclass
class _Prepared:
    challenge: CorpusChallenge
    staged: Path
    members: list[Path]
    outcome: Outcome
    spec: dict | None = None


def _prepare(ch: CorpusChallenge, corpus_root: Path, staged: Path, root: Path | None) -> _Prepared:
    members = stage(ch, corpus_root, staged)
    o = Outcome(ch.id, ch.category, ch.name, len(members), _route(ch, staged, root), list(ch.expect_engines),
                [], "no-candidate")
    p = _Prepared(ch, staged, members, o)
    if ch.service:
        p.spec = load_service_spec(ch, corpus_root)
        o.live = p.spec["kind"]
    return p


def _probe(p: _Prepared, svc, key: str | None, ff) -> None:
    """The corpus author's probe, once: a reachability check, reported apart from the solve."""
    o = p.outcome
    try:
        data = livereplay.run_probe(svc, p.spec)
    except (livereplay.ReplayError, OSError) as e:
        o.notes.append(f"live service {o.live} did not answer its probe: {e}")
        return
    o.live_reachable = True
    if key is not None:
        o.live_probe_has_key = (key.encode("utf-8") in data
                                or score(ff.find_flags(data), key, ff) == "correct")


def _intake_into(o: Outcome, rep, key: str | None, ff) -> None:
    o.intake_status = rep.status
    if rep.error:
        o.notes.append(f"intake: {rep.error}")
    o.notes += [n for n in rep.notes if "FAILED" in n or "NOT" in n]
    sweep_flags = sorted(getattr(rep.sweep, "flags", None) or {})
    if rep.sweep is not None:
        o.engine_results.append(EngineResult("sweep", "sweep", sweep_flags,
                                             score(sweep_flags, key, ff, o.notes) if key else "no-key"))
    for run in rep.runs:
        flags = list(dict.fromkeys(run.flags))
        o.engine_results.append(EngineResult(run.engine, run.status, flags,
                                             score(flags, key, ff, o.notes) if key else "no-key"))
    o.candidates = list(rep.flags)


def rehearse(profile: EventProfile, index: list[CorpusChallenge], corpus_root: Path, workdir: Path,
             *, ids: list[str] | None = None, root: Path | None = None, engines: bool = True,
             engine_budget: float = DEFAULT_ENGINE_BUDGET, net_guard: str = "auto") -> CorpusReport:
    """Rehearse every indexed challenge present in the corpus (see the module docstring). `workdir`
    must be absent or empty. A challenge missing from the corpus is skipped with a reason (never a
    silent pass); an empty or all-skipped run does not pass. Raises CorpusError if a wanted id is
    unknown."""
    import requests

    from . import intake
    from .fakectfd import FakeChallenge, FakeCTFd
    from .platform.ctfd import CTFdAdapter

    corpus_root = Path(corpus_root)
    workdir = Path(workdir)
    if workdir.exists() and (not workdir.is_dir() or any(workdir.iterdir())):
        raise CorpusError(f"rehearsal folder {workdir} is not empty (stale files would be scanned again)")
    by_id = {c.id: c for c in index}
    if ids is not None:
        unknown = [i for i in ids if i not in by_id]
        if unknown:
            raise CorpusError(f"unknown challenge id(s) in index: {', '.join(unknown)}")
        wanted = [by_id[i] for i in ids]
    else:
        wanted = list(index)
    rep = CorpusReport(profile.slug, corpus_root)
    ff = flagfmt.for_profile(profile)
    prepared: list[_Prepared] = []
    for ch in wanted:
        cdir = ch.challenge_dir(corpus_root)
        if not cdir.is_dir():
            rep.skipped.append(f"{ch.id}: not in corpus ({cdir})")
            continue
        prepared.append(_prepare(ch, corpus_root, workdir / "staged" / ch.id, root))
    if not prepared:
        return rep
    keys: dict[str, str | None] = {}
    for p in prepared:
        try:
            keys[p.challenge.id] = read_key(p.challenge, corpus_root)
        except CorpusError as e:
            keys[p.challenge.id] = None
            p.outcome.notes.append(str(e))
    # brief_fetch off: a past event's brief names that event's hosts; a rehearsal never contacts them.
    opts = intake.Options(engines=engines, engine_budget=engine_budget, net_guard=net_guard, record=False,
                          root=root, brief_fetch=False)
    token = "corpus-" + secrets.token_hex(12)
    with ExitStack() as stack:
        board = []
        for n, p in enumerate(prepared, 1):
            endpoint = None
            if p.spec is not None:
                try:
                    svc = stack.enter_context(livereplay.start(p.spec))
                except (livereplay.ReplayError, OSError) as e:
                    p.outcome.notes.append(f"live service {p.outcome.live} did not start: {e}")
                else:
                    endpoint = svc.endpoint
                    p.outcome.live_endpoint = endpoint
                    _probe(p, svc, keys[p.challenge.id], ff)
            board.append(FakeChallenge(n, p.challenge.name, p.challenge.category,
                                       files=board_files(p.staged, p.members, p.challenge.id),
                                       description=p.challenge.description, connection_info=endpoint))
        fake = stack.enter_context(FakeCTFd(board, token=token))
        session = requests.Session()
        session.trust_env = False                    # loopback only: no proxy from the environment
        adapter = CTFdAdapter(fake.base_url, token=token, session=session, pacer_state_dir=workdir / "pace")
        for n, p in enumerate(prepared, 1):
            o = p.outcome
            irep = intake.intake_one(str(n), profile, adapter=adapter, workdir=workdir / "board", options=opts)
            key = keys[p.challenge.id]
            _intake_into(o, irep, key, ff)
            if o.live is not None and irep.challenge is not None:
                o.live_published = bool(o.live_endpoint) and irep.challenge.connection_info == o.live_endpoint
            if key is None:
                o.scored = "no-key"
                continue
            o.scored = score(o.candidates, key, ff, o.notes)
            if o.live is not None and o.scored == "no-candidate" and o.live_probe_has_key:
                o.notes.append("the flag is reachable only through the live service and no no-model engine "
                               "reached it (live-only solver gap)")
        bad = [r for r in fake.log if r.kind in BOARD_FORBIDDEN]
        rep.hygiene = [f"{r.method} {r.path} ({r.kind})" for r in bad]
    rep.outcomes = [p.outcome for p in prepared]
    return rep


# -------------------------------------------------------------------------------------- import

@dataclass
class ImportResult:
    dest: Path
    copied: list[str]
    stripped: list[str]
    links_skipped: list[str]
    stanza: str


def _is_answer(rel: str, extra: tuple[str, ...]) -> bool:
    parts = rel.lower().split("/")
    if any(fnmatch.fnmatch(part, pat) for part in parts for pat in ANSWER_NAMES):
        return True
    return _matches(rel, extra)


def _toml_str(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)


def import_challenge(src: Path, corpus_root: Path, cid: str, category: str, *, name: str | None = None,
                     description: str = "", key_file: str | None = None, service: str | None = None,
                     strip: tuple[str, ...] = (), expect_engines: tuple[str, ...] = ()) -> ImportResult:
    """Copy a cloned public challenge folder into `<corpus_root>/<cid>/` for the blind corpus.

    Answer files (ANSWER_NAMES at any depth, plus `strip` globs) are not copied; symlinks are never
    followed and are listed; nothing is executed. The key is read from `key_file` (relative to `src`,
    default `flag.txt`) and written to `<dest>/flag.txt`; a challenge with no key raises (the corpus
    cannot score it). `service` (relative to `src`) is copied to `<dest>/service.toml|.json`. The
    corpus root must lie outside this repository. Returns what was done and the index stanza (no flag)."""
    src = Path(src)
    corpus_root = Path(corpus_root).resolve()
    check_id(cid, "import")
    if not isinstance(category, str) or not category.strip():
        raise CorpusError(f"import {cid}: category must be {_VALID_CATS_HINT}")
    repo = paths.repo_root().resolve()
    if _inside(corpus_root, repo):
        raise CorpusError(f"import {cid}: the corpus root {corpus_root} is inside this repository; the corpus "
                          "stays outside it (set CTF_REHEARSAL_CORPUS to a folder elsewhere)")
    if not src.is_dir():
        raise CorpusError(f"import {cid}: source {src} is not a directory")
    if not corpus_root.is_dir():
        raise CorpusError(f"import {cid}: corpus root {corpus_root} is not a directory")
    dest = corpus_root / cid
    if dest.exists():
        raise CorpusError(f"import {cid}: {dest} already exists in the corpus")
    kf = src / (key_file or "flag.txt")
    if kf.is_symlink() or not kf.is_file():
        raise CorpusError(f"import {cid}: no key file at {kf} (pass --key-file; a symlink is not read)")
    key = kf.read_text(encoding="utf-8").strip()
    if not key:
        raise CorpusError(f"import {cid}: key file {kf} is empty")
    svc_src = None
    if service:
        svc_src = src / service
        if svc_src.is_symlink() or not svc_src.is_file():
            raise CorpusError(f"import {cid}: no service spec at {svc_src}")
    skip_exact = {kf.resolve()} | ({svc_src.resolve()} if svc_src else set())
    copied, stripped, links = [], [], []
    plan: list[tuple[Path, str]] = []
    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        d = Path(dirpath)
        for nm in sorted(dirnames):
            sub = d / nm
            rel = sub.relative_to(src).as_posix()
            if sub.is_symlink():
                links.append(rel)
                dirnames.remove(nm)
            elif _is_answer(rel, tuple(strip)):
                stripped.append(rel + "/")
                dirnames.remove(nm)
        for nm in sorted(filenames):
            f = d / nm
            rel = f.relative_to(src).as_posix()
            if f.is_symlink():
                links.append(rel)
            elif f.resolve() in skip_exact or _is_answer(rel, tuple(strip)):
                stripped.append(rel)
            elif f.is_file():
                plan.append((f, rel))
    for f, rel in plan:
        if f.read_bytes().strip() == key.encode("utf-8"):
            stripped.append(rel)              # a copy of the key under another name: never a handout
            continue
        out = dest / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(f, out)
        copied.append(rel)
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "flag.txt").write_text(key + "\n", encoding="utf-8")
    svc_name = None
    if svc_src is not None:
        svc_name = "service.json" if svc_src.suffix == ".json" else "service.toml"
        shutil.copyfile(svc_src, dest / svc_name)
    lines = ["[[challenge]]", f"id = {_toml_str(cid)}", f"name = {_toml_str(name or cid)}",
             f"category = {_toml_str(category)}", f"description = {_toml_str(description)}",
             f"path = {_toml_str(cid)}", 'key_file = "flag.txt"']
    if expect_engines:
        lines.append("expect_engines = [" + ", ".join(_toml_str(e) for e in expect_engines) + "]")
    if svc_name:
        lines.append(f"service = {_toml_str(svc_name)}")
    stanza = "\n".join(lines) + "\n"
    parse_index(tomllib.loads(stanza), src="import stanza")      # the stanza must load as written
    return ImportResult(dest, sorted(copied), sorted(stripped), sorted(links), stanza)
