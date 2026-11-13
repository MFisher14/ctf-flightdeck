"""The one path resolver: repo root, event profiles, the per-event workdir, the real-data corpus.

    repo_root()          the checkout this package lives in (a worktree resolves to itself)
    events_root()        <repo>/events
    event_dir(slug)      <repo>/events/<slug>             (the profile folder, committed)
    workdir(slug=None)   $CTF_WORKDIR, else ~/ctf-work/<event slug>   (runtime state, never committed)
    ensure_workdir(...)  workdir(), created
    realdata_root()      $CTF_REALDATA, else ~/2026-ctf-huntress/challenges/_realdata  (read-only)
    saved_challenges_root()  $CTF_REAL_CHALLENGES, else None: saved past-event attempts (read-only)
    rehearsal_corpus_root()  $CTF_REHEARSAL_CORPUS, else None: blind rehearsal corpus (read-only)
    geo_dataset_root()   $CTF_GEO_DATASET, else None: frozen OSINT geolocation dataset (read-only, B-113)
    factor_table_path()  $CTF_FACTOR_TABLE, else <realdata>/factor-table/factors.sqlite if present, else None
                         (the offline factor table, read-only, B-244)
    codex_home(environ)  $CODEX_HOME, else ~/.codex   (the Codex CLI's config folder; never written)
    gate_state(root)     $CTF_GATE_STATE, else <git common dir>/ctf-gate   (the regression gate, B-195)
    status_state(root)   $CTF_STATUS_STATE, else <git common dir>/ctf-status   (live status jobs, B-198)
    workreg_state(root)  $CTF_WORKREG_STATE, else <git common dir>/ctf-workreg  (build work registry, B-213)
    toolbox_dir(environ) $CTF_TOOLBOX_DIR, else ~/tools  (the binary toolbox's pinned clones, B-142)
    claude_home(environ) $CLAUDE_CONFIG_DIR, else ~/.claude  (Claude Code's config folder; never written)
    governor_state()     $CTF_GOVERNOR_STATE, else ~/ctf-work/_governor  (host-wide governor slots, B-176)
    wheelhouse_dir()     $CTF_WHEELHOUSE, else ~/ctf-work/_wheelhouse  (pre-downloaded wheels, B-188)
    slate_state()        $CTF_SLATE_STATE, else ~/ctf-work/_slate  (multi-event scheduler, B-214)

DEFAULT_REALDATA is the one place a source-repo path may appear in code (tests/test_no_home_paths.py
allows it here and nowhere else): every other module and test resolves a corpus through this file.

Every module that needs one of these calls this file; no module derives a workdir from
`__file__` or its own environment lookup (unit B-001a migrates the 17 old resolvers).

Nothing here creates a directory except ensure_workdir(), and nothing falls back silently: a
workdir with no CTF_WORKDIR and no resolvable event raises ctf.event.EventError naming why.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping

from . import env

_REPO = Path(__file__).resolve().parent.parent

DEFAULT_WORK_BASE = Path("~/ctf-work")
DEFAULT_REALDATA = Path("~/2026-ctf-huntress/challenges/_realdata")
DEFAULT_CODEX_HOME = Path("~/.codex")
DEFAULT_TOOLBOX_DIR = Path("~/tools")
DEFAULT_CLAUDE_HOME = Path("~/.claude")


def repo_root() -> Path:
    return _REPO


def events_root() -> Path:
    """<repo>/events, or $CTF_EVENTS_DIR: a folder of <slug>/event.toml profiles outside the checkout
    (the flightdeck adapter writes the profile of the board being played there; the pack itself may
    be mounted read-only)."""
    override = env.get("CTF_EVENTS_DIR")
    if override:
        return _resolve(override)
    return _REPO / "events"


def event_dir(slug: str) -> Path:
    if not slug or "/" in slug or slug.startswith("."):
        raise ValueError(f"bad event slug {slug!r}")
    return events_root() / slug


def _resolve(p: str | Path) -> Path:
    return Path(p).expanduser().resolve()


def workdir(slug: str | None = None) -> Path:
    """Where per-challenge runtime state lives. $CTF_WORKDIR wins (used verbatim). Otherwise
    ~/ctf-work/<slug>, where slug is the argument or the current event (ctf.event.current())."""
    override = env.get("CTF_WORKDIR")
    if override:
        return _resolve(override)
    if slug is None:
        from . import event  # local import: event imports paths
        slug = event.current().slug
    return _resolve(DEFAULT_WORK_BASE / slug)


def ensure_workdir(slug: str | None = None) -> Path:
    d = workdir(slug)
    d.mkdir(parents=True, exist_ok=True)
    return d


DEFAULT_LANES_BASE = Path("~/ctf-work/_lanes")


def lanes_root() -> Path:
    """Where Codex build-lane batches keep their checkouts, prompts, logs and results (B-179).
    $CTF_LANES_DIR wins; else ~/ctf-work/_lanes. Runtime state: never inside the repo."""
    return _resolve(env.get("CTF_LANES_DIR") or DEFAULT_LANES_BASE)


def realdata_root() -> Path:
    """The real-challenge corpus used by needs_realdata tests. Read-only: never write under it.
    Not checked for existence here; callers that need it use require_realdata()."""
    return _resolve(env.get("CTF_REALDATA") or DEFAULT_REALDATA)


def require_realdata() -> Path:
    p = realdata_root()
    if not p.is_dir():
        raise FileNotFoundError(f"real-data corpus not found at {p} (set CTF_REALDATA)")
    return p


def rehearsal_corpus_root() -> Path | None:
    """The blind rehearsal corpus (past challenges staged blind: challenge files, keys and replay
    service specs), read-only. Named only by $CTF_REHEARSAL_CORPUS: no default, never derived from
    realdata_root() or this checkout, so the corpus stays out of the repo (B-155).

    None when the variable is unset (the caller reports the corpus rehearsal as not run, naming the
    variable). Set to something that is not a directory: FileNotFoundError naming the variable, so a
    typo is never read as "no corpus"."""
    raw = env.get("CTF_REHEARSAL_CORPUS")
    if not raw:
        return None
    p = _resolve(raw)
    if not p.is_dir():
        raise FileNotFoundError(f"rehearsal corpus not found at {p} (CTF_REHEARSAL_CORPUS is set to {raw!r})")
    return p


def require_rehearsal_corpus() -> Path:
    """The blind rehearsal corpus, or FileNotFoundError naming CTF_REHEARSAL_CORPUS when it is unset."""
    p = rehearsal_corpus_root()
    if p is None:
        raise FileNotFoundError("rehearsal corpus not configured (set CTF_REHEARSAL_CORPUS)")
    return p


def saved_challenges_root() -> Path | None:
    """The saved past-event challenge attempts (<root>/day-NN/<lane>-.../, the Huntress `challenges/`
    layout), read-only, used by the carried check scripts' "saved" sections. Named only by
    $CTF_REAL_CHALLENGES: no default, never derived from realdata_root() or from this checkout.

    None when the variable is unset (the caller reports its saved section as not run, naming the
    variable). Set to something that is not a directory: FileNotFoundError naming the variable, so a
    typo is never read as "no saved attempts"."""
    raw = env.get("CTF_REAL_CHALLENGES")
    if not raw:
        return None
    p = _resolve(raw)
    if not p.is_dir():
        raise FileNotFoundError(f"saved challenges not found at {p} (CTF_REAL_CHALLENGES is set to {raw!r})")
    return p


def geo_dataset_root() -> Path | None:
    """The frozen OSINT geolocation dataset (brand POI directory, OSM extract, DEM tiles), read-only.
    Used by solvers/toolkits/osint_geolocate.py (B-113). Named only by $CTF_GEO_DATASET: no default,
    never derived from realdata_root() or this checkout, so the extracts stay out of the repo and out
    of the read-only source repos.

    None when the variable is unset (the caller reports the dataset as not configured, naming the
    variable). Set to something that is not a directory: FileNotFoundError naming the variable, so a
    typo is never read as "no dataset"."""
    raw = env.get("CTF_GEO_DATASET")
    if not raw:
        return None
    p = _resolve(raw)
    if not p.is_dir():
        raise FileNotFoundError(f"geo dataset not found at {p} (CTF_GEO_DATASET is set to {raw!r})")
    return p


def require_geo_dataset() -> Path:
    """The frozen geo dataset folder, or FileNotFoundError naming CTF_GEO_DATASET when it is unset."""
    p = geo_dataset_root()
    if p is None:
        raise FileNotFoundError(
            "OSINT geo dataset not configured (set CTF_GEO_DATASET to the frozen dataset folder: "
            "brands.json, osm.jsonl, dem.json or dem/*.hgt; it lives outside the repo)")
    return p


FACTOR_TABLE_REALDATA = ("factor-table", "factors.sqlite")


def factor_table_path() -> Path | None:
    """The offline FactorDB-style factor table (B-244): a SQLite file built by
    `solvers/common/factor_table.py build`, read-only at lookup. $CTF_FACTOR_TABLE names the file;
    unset, <realdata_root()>/factor-table/factors.sqlite is used when that file exists; else None
    (the caller says the table is not configured, naming the variable). $CTF_FACTOR_TABLE set to
    something that is not a file: FileNotFoundError naming the variable, so a typo is never read as
    "no table"."""
    raw = env.get("CTF_FACTOR_TABLE")
    if raw:
        p = _resolve(raw)
        if not p.is_file():
            raise FileNotFoundError(f"factor table not found at {p} (CTF_FACTOR_TABLE is set to {raw!r})")
        return p
    p = realdata_root().joinpath(*FACTOR_TABLE_REALDATA)
    return p if p.is_file() else None


def codex_home(environ: Mapping[str, str] | None = None) -> Path:
    """The Codex CLI's config folder: $CODEX_HOME (as the CLI reads it), else ~/.codex. Read-only for
    this repo: callers read single keys from its config.toml and never open its auth files."""
    e = os.environ if environ is None else environ
    raw = e.get("CODEX_HOME")
    return Path(raw).expanduser() if raw else DEFAULT_CODEX_HOME.expanduser()


def toolbox_dir(environ: Mapping[str, str] | None = None) -> Path:
    """Where the binary toolbox's pinned clones live (B-142, tools/toolbox.toml): $CTF_TOOLBOX_DIR,
    else ~/tools (setup.sh's folder). Not created here: `ctf toolbox install` clones into it."""
    raw = env.get("CTF_TOOLBOX_DIR", environ=environ)
    return _resolve(raw) if raw else _resolve(DEFAULT_TOOLBOX_DIR)


def claude_home(environ: Mapping[str, str] | None = None) -> Path:
    """Claude Code's config folder (session logs under projects/): $CLAUDE_CONFIG_DIR (as Claude Code
    reads it), else ~/.claude. Read-only for this repo: the usage ledger (B-193) reads session logs
    under it and nothing else."""
    e = os.environ if environ is None else environ
    raw = e.get("CLAUDE_CONFIG_DIR")
    return Path(raw).expanduser() if raw else DEFAULT_CLAUDE_HOME.expanduser()


def gate_state(root: Path | None = None) -> Path:
    """Where the regression gate (ctf.gate, B-195) keeps its inventory, warm results and batch records.
    $CTF_GATE_STATE wins (used verbatim). Otherwise <git common dir>/ctf-gate of the checkout, so every
    worktree of one repo shares warm results (they are keyed by exact content hash, so sharing is safe).
    Not created here. Raises FileNotFoundError naming CTF_GATE_STATE when the checkout has no .git."""
    return _common_state(root, "ctf-gate", "CTF_GATE_STATE", "the gate's state folder")


def status_state(root: Path | None = None) -> Path:
    """Where the live status surface (ctf.live, B-198) keeps its job records and last push.
    $CTF_STATUS_STATE wins (used verbatim). Otherwise <git common dir>/ctf-status, shared by every
    worktree so one status command sees every builder's jobs. Not created here. Raises
    FileNotFoundError naming CTF_STATUS_STATE when the checkout has no .git."""
    return _common_state(root, "ctf-status", "CTF_STATUS_STATE", "the status state folder")


def workreg_state(root: Path | None = None) -> Path:
    """Where the build-time work registry (ctf.workreg, B-213) keeps its registry, history and the
    idle-machine lock. $CTF_WORKREG_STATE wins (used verbatim). Otherwise <git common dir>/ctf-workreg, so
    every worktree of one repo (one per builder, B-147) sees the same agents, claims and lock. Not created
    here. Raises FileNotFoundError naming CTF_WORKREG_STATE when the checkout has no .git."""
    return _common_state(root, "ctf-workreg", "CTF_WORKREG_STATE", "the work registry's state folder")


def _common_state(root: Path | None, name: str, var: str, what: str) -> Path:
    override = env.get(var)
    if override:
        return _resolve(override)
    root = Path(root) if root else _REPO
    dotgit = root / ".git"
    if dotgit.is_dir():
        return (dotgit / name).resolve()
    if dotgit.is_file():
        text = dotgit.read_text(encoding="utf-8").strip()
        if text.startswith("gitdir:"):
            gitdir = Path(text[len("gitdir:"):].strip())
            gitdir = gitdir if gitdir.is_absolute() else (root / gitdir)
            common = gitdir / "commondir"
            if common.is_file():
                c = Path(common.read_text(encoding="utf-8").strip())
                return ((c if c.is_absolute() else gitdir / c) / name).resolve()
            return (gitdir / name).resolve()
    raise FileNotFoundError(f"no git directory at {dotgit}: set {var} to {what}")


DEFAULT_GOVERNOR_STATE = DEFAULT_WORK_BASE / "_governor"


def governor_state() -> Path:
    """Where the host resource governor (ctf.governor, B-176) keeps its host-wide slot leases, queue and
    RSS alerts. One per host, shared by every event and harness: $CTF_GOVERNOR_STATE wins (used
    verbatim), else ~/ctf-work/_governor. Not created here."""
    override = env.get("CTF_GOVERNOR_STATE")
    if override:
        return _resolve(override)
    return _resolve(DEFAULT_GOVERNOR_STATE)


DEFAULT_WHEELHOUSE = DEFAULT_WORK_BASE / "_wheelhouse"


def wheelhouse_dir() -> Path:
    """The pre-downloaded wheels of every pin (ctf.toolchain.wheels, B-188), for lanes with no network:
    $CTF_WHEELHOUSE wins (used verbatim), else ~/ctf-work/_wheelhouse. Not created here."""
    override = env.get("CTF_WHEELHOUSE")
    if override:
        return _resolve(override)
    return _resolve(DEFAULT_WHEELHOUSE)


DEFAULT_SLATE_STATE = DEFAULT_WORK_BASE / "_slate"


def slate_state() -> Path:
    """Where the multi-event scheduler (ctf.slate, B-214) keeps the slate (the events in play and the
    player's priorities), its change history and its admission queue. One per host, like the governor:
    $CTF_SLATE_STATE wins (used verbatim), else ~/ctf-work/_slate. Not created here."""
    override = env.get("CTF_SLATE_STATE")
    if override:
        return _resolve(override)
    return _resolve(DEFAULT_SLATE_STATE)
