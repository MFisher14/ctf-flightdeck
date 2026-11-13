"""Preflight doctor checks (B-039): smoke-test every dependency a wave needs, before the wave.

    from ctf import doctor
    checks = doctor.run_checks(profile)          # [Check], in the order below
    doctor.failed(checks)                        # the checks that block the wave

Wave 1 of CSCTF lost every Codex handoff to a model/config mismatch that no check caught, and the
carried `ctf doctor` had no Codex check, no router check and no event-profile check. These are them:

  profile        the event profile still validates from disk, its flag format compiles, the phase
                 (pre-event / in-event / post-event), and the generated CLAUDE.md / AGENTS.md match it
  categories     every announced category against the categories the engine router routes
                 (manifest [[routes]] category); an announced category with no route is reported with
                 the reason (B-189's profile ingest meets B-186's router here)
  router         the engine manifests load, every routed engine's entry file exists, the toolkit
                 registry loads with every registered toolkit present, and the triage identify pack loads
  codex-model    which model a handoff will run (CODEX_MODEL, else tools/codex_handoff.sh's default)
                 against the model the Codex config names: a handoff that silently overrides the
                 configured model is the wave-1 wrong-model class
  codex-smoke    ONE real Codex call through `tools/codex_handoff.sh --preflight` (the exact flags a
                 handoff uses). Under CTF_TESTING it refuses unless CODEX_BIN names a stub: set, not
                 the `codex` found on PATH, and carrying CODEX_STUB_MARKER near its top
  submit-dry-run the submit path with nothing sent: the policy gate (ctf.platform) around a dry-run
                 adapter, and the carried guarded_submit with allow=False, must accept a value in the
                 event format and refuse one that is not, as the event's submit_mode says
  compaction     the Claude/Codex compaction thresholds (B-032, ctf/compaction.py) parse, the installed
                 builds know the knob, nothing in the environment disables or moves it, and sessions
                 started by hand get it too (the Codex config is read, one key, only with Codex checks)
  instances      the instance plugin's status route answers for one visible challenge (a read; nothing
                 starts). The profile has no instance section until B-003, so without an explicit
                 plugin and challenge this is reported as not run, naming why
  toolbox        the binary toolbox (B-142, tools/toolbox.toml via ctf.toolbox.verify): each host tool
                 present, answering its version probe, with its runtime needs; a core problem is a warn
                 naming the tool (advisory: it blocks one archetype, not the wave)
  assets         (B-188) tools/assets.toml resolved (rockyou, john's helpers with 7z2john's Perl module,
                 SecLists, Ghidra): a core asset that is not ok is a warn naming it and its fix
  images         (B-188) tools/images.toml lints clean (a pinned image's finding fails) and each core
                 image is present and built from the current files (`docker image inspect`, a read);
                 docker absent is a warn, a non-stub docker under CTF_TESTING a skip. --no-toolbox skips
                 toolbox, assets and images together
  allowance     (B-171) the harness quota readings in the event workdir (`ctf quota scan` / `set`): fail
                 when no harness can take release work at the next release, warn on no reading, an
                 exhausted / probe / unmetered harness, an eaten release reserve or a stale reading
  failover       (B-170) the failover.rehearsal ledger records: warn until each direction (onto
                 Claude, onto Codex) has a live rehearsal that held, naming the lanes of one that did
                 not; fail when the ledger cannot be read

B-190 adds:

  token          the platform token is valid now (one live /users/me; never a cached answer) and when
                 it expires ($CTF_TOKEN_EXPIRES, else the account's /tokens list): warns when it
                 expires within TOKEN_WARN_HOURS or before the event ends. Not run under test without
                 an injected fake client
  brief-rules    every command and write the named briefs ask for, simulated (ctf/rulesim.py) against
                 the rules the agent will run under: the fence the launcher builds now, for Claude
                 Code (permission mode as launched) and Codex. A deny, or a prompt in a background
                 agent (which fails silently), blocks
  usage          the event ledger's spend and the challenges at their budget cap (the plan allowance
                 itself is B-171's `allowance` check above)
  power          battery or mains (macOS pmset, parsed by ctf.governor)
  capabilities   the capability self-test (ctf/sandboxinfo.py): is this process sandboxed, which
                 probes passed. A fail that needed a capability the sandbox cannot vouch for
                 (Check.needs: network, docker, ...) is relabelled "sandbox-only" (status skip)

Statuses: ok, warn, fail, skip (not run; the reason says why). Levels (LEVELS): a blocking check's
fail stops the wave; an advisory check (categories, usage, power, capabilities) never does. A skip is
never a pass: `ctf preflight --strict` and the pre-event gate in strict mode count it as a failure,
and so every warn and advisory or sandbox-only result.
"""
from __future__ import annotations

import datetime as _dt
import os
import re
import shutil
import subprocess
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from . import env as _env
from . import event as _event
from . import flagfmt, paths

STATUSES = ("ok", "warn", "fail", "skip")
HANDOFF_SCRIPT = Path("tools") / "codex_handoff.sh"
CODEX_MODES = ("fast", "deep", "cyber")
CODEX_SMOKE_TIMEOUT = 240.0            # the script's own alarm is CODEX_PREFLIGHT_TIMEOUT (180 s)
CODEX_STUB_MARKER = "ctf-codex-stub"   # under CTF_TESTING, CODEX_BIN must carry this (a test stub)
STUB_MARKER_WINDOW = 4096

# B-190: blocking versus advisory. A blocking check's fail stops the wave; an advisory check never
# does, whatever it reports (it is shown, and `--strict` still counts it). A check name not listed
# here is blocking: an unknown check is never quietly downgraded.
BLOCKING, ADVISORY = "blocking", "advisory"
LEVELS: dict[str, str] = {
    "profile": BLOCKING, "categories": ADVISORY, "router": BLOCKING, "codex-model": BLOCKING,
    "codex-smoke": BLOCKING, "submit-dry-run": BLOCKING, "instances": BLOCKING,
    "allowance": BLOCKING, "token": BLOCKING, "brief-rules": BLOCKING,
    "capabilities": ADVISORY, "usage": ADVISORY, "power": ADVISORY,
}


@dataclass(frozen=True)
class Check:
    name: str
    status: str            # ok | warn | fail | skip
    detail: str
    fix: str = ""
    level: str = ""        # blocking | advisory; "" = LEVELS[name], else blocking
    needs: tuple[str, ...] = ()     # capabilities this result depended on (ctf.sandboxinfo); set on a
                                    # fail an environment limit could cause, so a sandbox can be named
    sandbox_only: bool = False      # seen only inside a sandbox that could not vouch for `needs`

    def __post_init__(self):
        if self.status not in STATUSES:
            raise ValueError(f"check {self.name!r}: status {self.status!r} is not one of {STATUSES}")
        if not self.level:
            object.__setattr__(self, "level", LEVELS.get(self.name, BLOCKING))
        if self.level not in (BLOCKING, ADVISORY):
            raise ValueError(f"check {self.name!r}: level {self.level!r} is not blocking or advisory")

    @property
    def blocking(self) -> bool:
        return self.status == "fail" and self.level == BLOCKING and not self.sandbox_only

    def line(self) -> str:
        tag = " [sandbox-only]" if self.sandbox_only else (" [advisory]" if self.status == "fail"
                                                            and self.level == ADVISORY else "")
        s = f"{self.status.upper():<4}  {self.name}{tag}: {self.detail}"
        return s + (f"\n      fix: {self.fix}" if self.fix else "")

    def to_dict(self) -> dict:
        return {"name": self.name, "status": self.status, "detail": self.detail, "fix": self.fix,
                "level": self.level, "blocking": self.blocking, "sandbox_only": self.sandbox_only}


def failed(checks: list[Check], *, strict: bool = False) -> list[Check]:
    """The checks that block: blocking-level fails (not sandbox-only ones); with strict, every
    check that is not ok (warns, skips, advisory and sandbox-only results too)."""
    if strict:
        return [c for c in checks if c.status != "ok"]
    return [c for c in checks if c.blocking]


@dataclass(frozen=True)
class Split:
    blocking: tuple[Check, ...]       # blocking-level fails: the wave does not start
    advisory: tuple[Check, ...]       # warns, and fails of advisory-level checks
    not_run: tuple[Check, ...]        # skips, sandbox-only results among them
    ok: tuple[Check, ...]

    @property
    def sandbox_only(self) -> tuple[Check, ...]:
        return tuple(c for c in self.not_run if c.sandbox_only)


def split(checks: list[Check]) -> Split:
    b = tuple(c for c in checks if c.blocking)
    a = tuple(c for c in checks if c.status == "warn" or (c.status == "fail" and not c.blocking
                                                          and not c.sandbox_only))
    n = tuple(c for c in checks if c.status == "skip")
    o = tuple(c for c in checks if c.status == "ok")
    return Split(b, a, n, o)


def render(checks: list[Check], *, strict: bool = False, indent: str = "  ") -> list[str]:
    """The report lines: BLOCKING, ADVISORY, NOT RUN, OK sections, then one verdict line."""
    s = split(checks)
    out: list[str] = []
    for title, group in (("BLOCKING", s.blocking), ("ADVISORY", s.advisory), ("NOT RUN", s.not_run),
                         ("OK", s.ok)):
        if not group:
            continue
        out.append(f"{indent}{title} ({len(group)})")
        for c in group:
            out.append(indent * 2 + c.line().replace("\n", "\n" + indent * 2))
    bad = failed(checks, strict=strict)
    if not bad:
        verdict = "PREFLIGHT PASSED"
        extra = []
        if s.advisory:
            extra.append(f"{len(s.advisory)} advisory")
        if s.sandbox_only:
            extra.append(f"{len(s.sandbox_only)} sandbox-only result(s) not confirmed on the host")
        if extra:
            verdict += " (" + "; ".join(extra) + ")"
    else:
        verdict = (f"PREFLIGHT FAILED: {', '.join(c.name for c in bad)}"
                   + (" (strict: warn, skip and advisory count)" if strict else " (blocking)"))
    out.append(verdict)
    return out


# ---------------------------------------------------------------------------------------- profile

def check_profile(profile: _event.EventProfile, *, now: _dt.datetime | None = None,
                  events_root: Path | None = None) -> Check:
    notes, warns = [], []
    if profile.path is not None:
        try:
            _event.load_path(profile.path, expect_slug=profile.slug)
        except _event.EventError as e:
            return Check("profile", "fail", f"the profile no longer validates: {e}",
                         f"fix {profile.path}, then `python -m ctf event check {profile.slug}`")
    try:
        ff = flagfmt.for_profile(profile)
        ff.find_flags("")
    except Exception as e:  # a bad regex here is a dead submit path
        return Check("profile", "fail", f"flag format does not compile: {type(e).__name__}: {e}",
                     f"fix [flag] in the {profile.slug} profile")
    notes.append(f"flag format {ff.pattern}")
    if not ff.known:
        warns.append("flag prefixes are not known yet (prefixes = []): any word prefix matches")
    from .buildplan import phase_of
    ph = phase_of(profile, now)
    notes.append(f"phase {ph}")
    if ph == "post-event":
        warns.append("the event has ended (dates.end is past)")
    root = Path(events_root) if events_root is not None else paths.events_root()
    if profile.path is not None and Path(profile.path).parent == root / profile.slug:
        from . import eventrules
        try:
            probs = eventrules.check(profile, root / profile.slug)
        except eventrules.TemplateError as e:
            probs = [f"template: {e}"]
        if probs:
            warns.append("generated agent rules: " + "; ".join(probs))
    detail = f"{profile.slug} ({profile.name}): " + ", ".join(notes)
    if warns:
        fix = (f"`python -m ctf new-event {profile.slug} --regen`"
               if any(w.startswith("generated agent rules") for w in warns) else "")
        return Check("profile", "warn", detail + ". " + "; ".join(warns), fix)
    return Check("profile", "ok", detail)


# ---------------------------------------------------------------------------------------- categories

def routed_categories(manifests) -> dict[str, tuple[str, ...]]:
    """Canonical category -> ids of the active engines whose [[routes]] name it."""
    out: dict[str, set[str]] = {}
    for m in manifests:
        if m.status == "retired":
            continue
        for r in m.routes:
            for c in r.category:
                out.setdefault(c, set()).add(m.id)
    return {c: tuple(sorted(v)) for c, v in sorted(out.items())}


def category_routes(profile: _event.EventProfile, manifests) -> list[tuple[str, str, tuple[str, ...]]]:
    """[(announced category, the router's canonical spelling, engine ids)] in announcement order."""
    from .engines.router import canonical_category
    routed = routed_categories(manifests)
    return [(c, canonical_category(c), routed.get(canonical_category(c), ())) for c in profile.categories]


def check_categories(profile: _event.EventProfile, manifests=None) -> Check:
    if manifests is None:
        from .engines import manifest
        manifests = manifest.discover()
    if not profile.categories:
        return Check("categories", "warn",
                     f"no categories announced in the {profile.slug} profile: nothing to compare with "
                     "the router",
                     f"add `categories = [...]` to events/{profile.slug}/event.toml when they are announced")
    from .buildplan import canon_categories
    routed = routed_categories(manifests)
    rows = category_routes(profile, manifests)
    unrouted = []
    for announced, canon, engines in rows:
        if engines:
            continue
        hint = ""
        other = sorted(t for t in canon_categories(announced) if t in routed and t != canon)
        if other:
            hint = (f" (the router reads it as {canon!r}; the build plan reads it as "
                    f"{', '.join(other)}, which is routed: add an alias to ALIASES in ctf/triage.py)")
        unrouted.append(f"{announced!r}{hint}")
    n_ok = len(rows) - len(unrouted)
    if unrouted:
        return Check("categories", "warn",
                     f"{n_ok}/{len(rows)} announced categories have an engine route; no route for "
                     + ", ".join(unrouted),
                     "challenges in an unrouted category reach engines only by keyword or file routes; "
                     "add [[routes]] category to the engines that serve it (docs/BUILDING.md) or an alias")
    return Check("categories", "ok", f"all {len(rows)} announced categories have an engine route: "
                 + ", ".join(f"{a}->{c} ({len(e)})" for a, c, e in rows))


# ---------------------------------------------------------------------------------------- router

def check_router(root: Path | None = None) -> Check:
    from . import packs
    from .engines import manifest
    root = paths.repo_root() if root is None else Path(root)
    try:
        ms = manifest.discover(root)
    except manifest.ManifestError as e:
        return Check("router", "fail", f"engine manifests do not load: {e}",
                     "`python -m ctf engines lint` names every bad sidecar")
    active = [m for m in ms if m.status != "retired" and m.routes]
    if not active:
        return Check("router", "fail", f"no active engine with a route under {root}: the router routes nothing")
    missing = []
    for m in active:
        target = m.entry.target_file(root)
        if target is not None and not target.is_file():
            missing.append(f"{m.id} -> {target.relative_to(root) if target.is_relative_to(root) else target}")
    if missing:
        return Check("router", "fail", f"{len(missing)} routed engine(s) point at a file that is not there: "
                     + ", ".join(missing[:8]) + (" ..." if len(missing) > 8 else ""),
                     "restore the module or retire its manifest")
    try:
        reg = packs.toolkit_registry(root)
        n_toolkits = len(reg.entries())
    except packs.PackError as e:
        return Check("router", "fail", f"toolkit registry: {e}", "restore the toolkit file or its registry row")
    try:
        ident = packs.load_module("ctf_doctor_triage_pack", root / "solvers" / "common" / "triage.py",
                                  pack="solvers/common/triage.py", cache=False)
    except packs.PackError as e:
        return Check("router", "fail", f"triage identify pack: {e}")
    if not callable(getattr(ident, "identify", None)):
        return Check("router", "fail", "solvers/common/triage.py has no identify(): pulled files go unnamed")
    return Check("router", "ok", f"{len(ms)} manifests, {len(active)} routed engines (entry files present), "
                 f"{n_toolkits} registered toolkits, triage identify pack loads")


# ---------------------------------------------------------------------------------------- codex

def _environ(environ: Mapping[str, str] | None) -> dict[str, str]:
    return dict(os.environ if environ is None else environ)


def handoff_default_model(root: Path | None = None) -> str:
    """The model tools/codex_handoff.sh runs when CODEX_MODEL is unset (read from the script itself)."""
    script = (paths.repo_root() if root is None else Path(root)) / HANDOFF_SCRIPT
    try:
        text = script.read_text(encoding="utf-8")
    except OSError as e:
        raise RuntimeError(f"cannot read {script}: {e}") from None
    m = re.search(r'^default_model="([^"]+)"', text, re.M)
    if not m:
        raise RuntimeError(f"{script} has no `default_model=\"...\"` line: cannot tell which model a "
                           "handoff runs")
    return m.group(1)


def codex_config_model(environ: Mapping[str, str] | None = None) -> tuple[str | None, Path]:
    """(the `model` the Codex config names, the config path); model None when there is no config or
    no top-level model. A config that is not valid TOML raises ValueError naming it. Only `model` is
    read; nothing else from that folder is opened."""
    e = _environ(environ)
    cfg = paths.codex_home(e) / "config.toml"
    try:
        data = tomllib.loads(cfg.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, cfg
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as err:
        raise ValueError(f"{cfg} is not readable TOML: {type(err).__name__}") from None
    model = data.get("model")
    return (model if isinstance(model, str) and model else None), cfg


def check_codex_model(environ: Mapping[str, str] | None = None, *, root: Path | None = None,
                      mode: str = "fast") -> Check:
    e = _environ(environ)
    try:
        default = handoff_default_model(root)
    except RuntimeError as err:
        return Check("codex-model", "fail", str(err))
    var = "CODEX_CYBER_MODEL" if mode == "cyber" and e.get("CODEX_CYBER_MODEL") else "CODEX_MODEL"
    env_model = e.get(var) or None
    try:
        cfg_model, cfg_path = codex_config_model(e)
    except ValueError as err:
        return Check("codex-model", "fail", str(err), "fix the Codex config")
    if env_model:
        used, source = env_model, var
    else:
        used, source = default, f"{HANDOFF_SCRIPT} default"
    detail = f"handoffs ({mode}) run {used!r} ({source}); Codex config {cfg_path} names " + \
             (repr(cfg_model) if cfg_model else "no model")
    if cfg_model and cfg_model != used:
        if not env_model:
            return Check("codex-model", "fail",
                         detail + ": the handoff overrides the configured model with its built-in default "
                         "(the wave-1 dead-handoff class)",
                         f"export CODEX_MODEL={cfg_model} (or change the Codex config's model)")
        return Check("codex-model", "warn", detail + f": {var} differs from the config on purpose?")
    return Check("codex-model", "ok", detail)


def _real_codex_under_test(e: Mapping[str, str], root: Path) -> str:
    """Why CODEX_BIN in `e` could start the real Codex CLI ('' when it names a stub). Refused: unset;
    resolving to the same file as the `codex` on e's PATH; or resolving to a file that does not carry
    CODEX_STUB_MARKER in its first STUB_MARKER_WINDOW bytes (so the real CLI at an absolute path off
    PATH is refused too). A CODEX_BIN that resolves to nothing is let through: the handoff script then
    fails with "codex CLI not found" and nothing runs. A relative path resolves against `root`, the
    folder the script runs in."""
    raw = e.get("CODEX_BIN")
    if not raw:
        return "CODEX_BIN is not"
    path = e.get("PATH", os.defpath)
    real = shutil.which("codex", path=path)
    if os.sep in raw:
        cand = Path(raw).expanduser()
        cand = cand if cand.is_absolute() else Path(root) / cand
        mine = str(cand) if cand.is_file() else None
    else:
        mine = shutil.which(raw, path=path)
    if not mine:
        return ""
    if real and os.path.realpath(mine) == os.path.realpath(real):
        return f"CODEX_BIN ({raw}) is the codex on PATH ({real})"
    try:
        with open(mine, "rb") as fh:
            head = fh.read(STUB_MARKER_WINDOW)
    except OSError as err:
        return f"CODEX_BIN ({raw}) cannot be read to look for the stub marker ({err})"
    if CODEX_STUB_MARKER.encode() not in head:
        return (f"CODEX_BIN ({mine}) does not carry the stub marker {CODEX_STUB_MARKER!r} in its first "
                f"{STUB_MARKER_WINDOW} bytes")
    return ""


def check_codex_smoke(environ: Mapping[str, str] | None = None, *, root: Path | None = None,
                      mode: str = "fast", run: Callable[..., Any] = subprocess.run,
                      timeout: float = CODEX_SMOKE_TIMEOUT) -> Check:
    """One Codex call through the handoff script's --preflight (the flags a real handoff uses)."""
    if mode not in CODEX_MODES:
        return Check("codex-smoke", "fail", f"unknown codex mode {mode!r}; one of {CODEX_MODES}")
    e = _environ(environ)
    root = paths.repo_root() if root is None else Path(root)
    if _env.get_bool("CTF_TESTING", environ=e):
        why = _real_codex_under_test(e, root)
        if why:
            return Check("codex-smoke", "fail", f"CTF_TESTING is set and {why}: refusing a real Codex call "
                         "from a test", "point CODEX_BIN at a stub that is not the `codex` on PATH and "
                         f"carries the line `# {CODEX_STUB_MARKER}`")
    script = root / HANDOFF_SCRIPT
    if not script.is_file():
        return Check("codex-smoke", "fail", f"{script} is not there: no handoff path to test")
    try:
        p = run(["bash", str(script), "--preflight", "--mode", mode], cwd=str(root), env=e,
                capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return Check("codex-smoke", "fail", f"the Codex preflight call did not finish in {timeout:g}s",
                     needs=("network",))
    except OSError as err:
        return Check("codex-smoke", "fail", f"could not run {script}: {err}")
    if p.returncode == 0:
        return Check("codex-smoke", "ok", f"one Codex call ({mode}) answered PREFLIGHT_OK: "
                     + (p.stdout.strip().splitlines() or [""])[0][:160])
    tail = " | ".join((p.stderr or p.stdout or "").strip().splitlines()[-4:])[:400]
    fix = "see the hint lines; tools/codex_handoff.sh --preflight reproduces it"
    needs: tuple[str, ...] = ("network",)          # the call ran: a model call needs the network
    if "not found" in tail and "codex" in tail:
        fix = "install the Codex CLI or set CODEX_BIN"
        needs = ()                                 # a missing CLI is a host fact in any sandbox
    return Check("codex-smoke", "fail", f"the Codex preflight call failed (exit {p.returncode}): {tail}", fix,
                 needs=needs)


# ---------------------------------------------------------------------------------------- submit

def synth_flag(profile: _event.EventProfile, token: str = "0d0c7e57") -> str:
    """A value in the event's flag format (for dry runs and rehearsals; never submitted for real).
    Raises ValueError naming the body regex when no candidate body fits it."""
    ff = flagfmt.for_profile(profile)
    prefix = profile.flag.prefixes[0] if profile.flag.prefixes else "FLAG"
    hexes = token * 32
    bodies = [f"rehearsal_{token}", f"rehearsal{token}", token, token.upper()]
    bodies += [hexes[:n] for n in range(1, 129)] + ["a" * n for n in range(1, 65)] + ["1" * n for n in range(1, 65)]
    for body in bodies:
        cand = f"{prefix}{{{body}}}"
        if ff.is_flag(cand):
            return cand
    raise ValueError(f"cannot build a flag in the {profile.slug} format (prefix {prefix!r}, body regex "
                     f"{profile.flag.body!r}) for a dry run")


def not_a_flag(profile: _event.EventProfile) -> str:
    """A value that is not one flag in the event format."""
    return "not a flag: rehearsal dry run"


class DryRunAdapter:
    """A PlatformAdapter stand-in that sends nothing: it records submit calls and answers correct."""

    kind = "dry-run"

    def __init__(self):
        self.sent: list[tuple[str, str]] = []

    def list_challenges(self):
        return []

    def get_challenge(self, challenge_id):
        raise LookupError("dry run")

    def download_files(self, challenge_id, dest):
        return []

    def team_solves(self):
        return []

    def scoreboard(self):
        return []

    def submit(self, challenge_id, flag):
        from .platform.base import SubmitResult, SubmitStatus
        self.sent.append((challenge_id, flag))
        return SubmitResult(SubmitStatus.CORRECT, "dry run: nothing sent", sent=False)


def _expected_gate(profile: _event.EventProfile) -> str:
    if profile.manual:
        return "manual"
    return profile.rules.submit_mode            # auto | confirm


def check_submit_dry_run(profile: _event.EventProfile) -> Check:
    from .platform.policy import SubmitGate
    try:
        good = synth_flag(profile)
    except ValueError as e:
        return Check("submit-dry-run", "fail", str(e), f"fix [flag] body in the {profile.slug} profile")
    bad = not_a_flag(profile)
    problems, notes = [], []
    # 1. the policy gate (every new caller goes through it)
    dry = DryRunAdapter()
    gate = SubmitGate(dry, profile)
    r_bad = gate.submit("1", bad, provenance="doctor dry run", confirmed=True)
    if dry.sent or r_bad.sent:
        problems.append(f"gate sent a non-flag value {bad!r}")
    r_plain = gate.submit("1", good, provenance="doctor dry run")
    r_conf = gate.submit("1", good, provenance="doctor dry run", confirmed=True)
    sent = [f for _, f in dry.sent]
    want = _expected_gate(profile)
    if want == "manual":
        if sent:
            problems.append("gate sent a value on a manual event")
        notes.append("gate refuses every send (manual)")
    elif want == "confirm":
        if r_plain.status.value != "not_allowed":
            problems.append("gate sent an unconfirmed value in confirm mode")
        if sent != [good]:
            problems.append(f"gate did not send the confirmed well-formed value {good!r}")
        notes.append("gate needs confirmation, then sends")
    else:
        if sent != [good, good]:
            problems.append(f"gate refused a well-formed value {good!r}: {r_plain.message} / {r_conf.message}")
        notes.append("gate sends a well-formed value")
    # 2. the carried CTFd path (ctf.submit.guarded_submit), which the CLI and agents still use
    from .platform import legacy as _legacy
    if _legacy.refusal(profile, "guarded_submit", submit=True) is None:
        from . import client as _client
        from . import config as _config
        from . import submit as _submit
        from . import workspace as _ws
        with tempfile.TemporaryDirectory(prefix="ctf-doctor-") as td:
            cfg = _config.Config(base_url="http://127.0.0.1:9", token=None, team_id=None,
                                 workdir=Path(td), flags=flagfmt.for_profile(profile))
            c = _client.CTFd(cfg, profile=profile)        # no request is made: nothing is sent below
            ch = _ws.Challenge(cid=1, name="doctor", category="?", dir=Path(td) / "1-doctor")
            ch.dir.mkdir()
            rb = _submit.guarded_submit(c, ch, bad, provenance="doctor dry run", allow=False)
            rg = _submit.guarded_submit(c, ch, good, provenance="doctor dry run", allow=False)
            if rb.status != "bad-format" or rb.submitted:
                problems.append(f"guarded_submit did not refuse {bad!r} as bad-format ({rb.status})")
            if rg.status != "not-submitted" or rg.submitted:
                problems.append(f"guarded_submit refused the well-formed {good!r}: {rg.status} {rg.message}")
        notes.append("guarded_submit format guard agrees")
    else:
        why = str(_legacy.refusal(profile, "guarded_submit", submit=True)).split(": ", 1)[-1]
        notes.append(f"carried guarded_submit refuses this event ({why.split(';')[0].split(':')[0][:120]})")
    if problems:
        return Check("submit-dry-run", "fail", "; ".join(problems))
    return Check("submit-dry-run", "ok", f"submit_mode {profile.rules.submit_mode}, sample {good}: "
                 + "; ".join(notes) + "; nothing sent")


# ---------------------------------------------------------------------------------------- instances

def check_instances(profile: _event.EventProfile, instances_cfg: Mapping[str, Any] | None = None,
                    challenge_id: int | None = None, client=None) -> Check:
    """Probe the instance plugin's status route for one visible challenge (a read, nothing starts)."""
    if not instances_cfg:
        return Check("instances", "skip",
                     f"no instance plugin configured for {profile.slug}: the profile has no instances "
                     "section until B-003; route probe not run",
                     "`ctf preflight --instance-plugin docker_per_team --instance-challenge ID` probes "
                     "one by hand")
    if challenge_id is None:
        return Check("instances", "skip", "an instance plugin is configured but no challenge id was given "
                     "to probe", "pass --instance-challenge ID (a released challenge with an instance)")
    from . import instances as _inst
    try:
        if client is None:
            from . import client as _client
            client = _client.connect(profile=profile)
        inst = _inst.Instances.from_config(client, instances_cfg)
        info = inst.status(int(challenge_id))
    except Exception as e:  # the probe's whole point is to report what broke
        return Check("instances", "fail", f"instance status route for challenge {challenge_id}: "
                     f"{type(e).__name__}: {str(e)[:240]}", needs=_network_needs(e))
    if info.get("error") is not None:
        return Check("instances", "fail", f"plugin answered an error for challenge {challenge_id}: "
                     f"{str(info['error'])[:200]}")
    return Check("instances", "ok", f"status route answers for challenge {challenge_id}: "
                 f"connect {info.get('connect')!r}")


# ---------------------------------------------------------------------------------------- B-190 helpers

UTC = _dt.timezone.utc
TOKEN_WARN_HOURS = 12.0          # a token expiring sooner than this warns, whatever the event dates


def _network_needs(err: BaseException) -> tuple[str, ...]:
    """("network",) when `err` is a connection failure an environment (a sandbox) could cause."""
    import requests
    if isinstance(err, (requests.exceptions.ConnectionError, requests.exceptions.Timeout,
                        ConnectionError, TimeoutError)):
        return ("network",)
    return ()


def _under_test(e: Mapping[str, str]) -> bool:
    """CTF_TESTING or a running pytest, in the environ given or in this process's own (a test that
    hands in a bare environ is still a test)."""
    return any(_env.get_bool("CTF_TESTING", environ=x) or bool(x.get("PYTEST_CURRENT_TEST"))
               for x in (e, os.environ))


def _now(now: _dt.datetime | None) -> _dt.datetime:
    now = now or _dt.datetime.now(UTC)
    return now if now.tzinfo else now.replace(tzinfo=UTC)


def _parse_aware(raw: str, what: str) -> _dt.datetime:
    """ISO-8601 with a UTC offset (Z allowed). A naive value is refused: a silent zone guess shifts
    an expiry or a reset by hours."""
    try:
        when = _dt.datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"{what}={raw!r} is not an ISO-8601 time") from None
    if when.tzinfo is None:
        raise ValueError(f"{what}={raw!r} has no UTC offset (write e.g. 2026-11-10T09:00:00-05:00)")
    return when


def _ctfd_time(raw) -> _dt.datetime | None:
    """A CTFd API timestamp. CTFd stores UTC and serialises it without an offset, so a naive value
    is UTC here (the platform's convention, not a guess about the operator's zone)."""
    if not raw:
        return None
    try:
        when = _dt.datetime.fromisoformat(str(raw).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return when if when.tzinfo else when.replace(tzinfo=UTC)


def _hours(td: _dt.timedelta) -> str:
    h = td.total_seconds() / 3600
    return f"{h:.1f}h" if h < 48 else f"{h / 24:.1f} days"


# ---------------------------------------------------------------------------------------- token

def check_token(profile: _event.EventProfile, *, client=None, environ: Mapping[str, str] | None = None,
                now: _dt.datetime | None = None, warn_hours: float = TOKEN_WARN_HOURS) -> Check:
    """Is the platform token valid right now (one live /users/me, never a cached answer), and when
    does it expire: $CTF_TOKEN_EXPIRES when set, else the account's token list (/tokens)."""
    from .buildplan import _as_utc
    e = _environ(environ)
    if profile.manual:
        return Check("token", "skip", f"{profile.slug} is a manual event: no platform token is used")
    if profile.platform.kind != "ctfd":
        return Check("token", "skip", f"token check for platform kind {profile.platform.kind!r} is not "
                     "built (CTFd only)", "check the Game Master session by hand before the wave")
    if client is None:
        if _under_test(e):
            return Check("token", "skip", "not run under test without a fake platform client: no test "
                         "contacts a platform")
        from . import client as _client
        from . import config as _config
        try:
            cfg = _config.load()
        except _config.ConfigError as err:
            return Check("token", "fail", str(err))
        if not (cfg.token or cfg.cookie):
            return Check("token", "fail", "no platform token or session cookie",
                         "create an access token in the platform UI (Settings -> Access Tokens) and put it "
                         "in .ctf/token or $CTF_TOKEN")
        try:
            client = _client.connect(cfg, profile=profile)
        except Exception as err:  # named, never a traceback
            return Check("token", "fail", f"cannot build the platform client: {type(err).__name__}: {err}",
                         needs=_network_needs(err))
    auth = "token" if getattr(client.cfg, "token", None) else "cookie"
    try:
        me = client.me()
    except Exception as err:
        needs = _network_needs(err)
        if needs:
            return Check("token", "fail", f"the platform did not answer ({type(err).__name__}): the {auth} "
                         "could not be checked", "check the network and the platform URL", needs=needs)
        return Check("token", "fail", f"the platform refused the {auth} (expired or revoked?): "
                     f"{str(err)[:200]}", f"create a new {auth} in the platform UI and replace the old one "
                     "(.ctf/token or $CTF_TOKEN), then re-run")
    who = f"valid for user {me.get('name')!r}"
    now = _now(now)
    end = _as_utc(profile.end, end=True)
    declared = _env.get("CTF_TOKEN_EXPIRES", environ=e)
    lo = hi = None
    source = ""
    if declared:
        try:
            lo = hi = _parse_aware(declared, "CTF_TOKEN_EXPIRES")
        except ValueError as err:
            return Check("token", "warn", f"{who}; {err}", "fix CTF_TOKEN_EXPIRES or unset it")
        source = "CTF_TOKEN_EXPIRES"
        if hi <= now:
            return Check("token", "warn", f"{who}, but CTF_TOKEN_EXPIRES ({hi.isoformat()}) is past: the "
                         "value is stale", "set CTF_TOKEN_EXPIRES to the new token's expiry, or unset it")
    elif auth == "token" and callable(getattr(client, "tokens", None)):
        try:
            rows = client.tokens()
        except Exception as err:
            rows = None
            source = f"the token list is not readable ({type(err).__name__})"
        if rows is not None:
            # Ours works, so it is one of the unexpired ones; CTFd does not say which.
            exps = sorted(t for t in (_ctfd_time(r.get("expiration")) for r in rows if isinstance(r, dict))
                          if t is not None and t > now)
            if exps:
                lo, hi = exps[0], exps[-1]
                source = f"the account's token list ({len(exps)} unexpired)"
            else:
                source = "the account's token list shows no expiry"
    else:
        source = "a session cookie's expiry is not visible to the API"
    if hi is None:
        return Check("token", "ok", f"{who} ({auth}); expiry unknown: {source}",
                     "set CTF_TOKEN_EXPIRES (ISO-8601 with offset) to be warned before it expires")
    window = _dt.timedelta(hours=warn_hours)
    left = hi - now
    if left <= window:
        return Check("token", "warn", f"{who}; it expires in {_hours(left)} ({hi.isoformat()}, from {source})",
                     "create a new token now and replace the old one")
    if now <= end and hi < end:
        return Check("token", "warn", f"{who}; it expires {hi.isoformat()}, before the event ends "
                     f"({end.isoformat()}) (from {source})", "renew the token before it expires")
    if lo is not None and lo != hi and (lo - now <= window or (now <= end and lo < end)):
        # Ours is one of the unexpired tokens and CTFd does not say which: the earlier one may be ours.
        # Only CTF_TOKEN_EXPIRES (which sets lo == hi) settles it, so this warns, never a quiet ok.
        when = (f"in {_hours(lo - now)}" if lo - now <= window
                else f"before the event ends ({end.isoformat()})")
        return Check("token", "warn", f"{who}; another unexpired token on the account expires {when} "
                     f"({lo.isoformat()}); the latest expires {hi.isoformat()} (from {source}): if the "
                     "earlier one is ours it needs renewing",
                     "set CTF_TOKEN_EXPIRES to the expiry of the token in use, or delete the token you "
                     "do not use in the platform UI")
    return Check("token", "ok", f"{who}; expires {hi.isoformat()} ({_hours(left)} left; from {source})")


# ---------------------------------------------------------------------------------------- usage

def check_usage(profile: _event.EventProfile, *, workdir: Path | None = None) -> Check:
    """Pre-event usage: the event ledger's spend and the challenges at their budget cap. The plan
    allowance itself (quota readings, the release reserve) is B-171's `allowance` check."""
    from . import ledger as _ledger
    wd = Path(workdir) if workdir is not None else paths.workdir(profile.slug)
    if not _ledger.path(wd).is_file():
        return Check("usage", "ok", f"ledger: no spend recorded under {wd} (plan allowance: see the "
                     "allowance check)")
    from . import budget as _budget
    meter = _budget.LedgerMeter(profile, workdir=wd)
    rows = [meter.status(c) for c in meter.challenges()]
    total = sum(r.spent_usd for r in rows)
    detail = f"ledger: ${total:.2f} on {len(rows)} challenge(s)"
    capped = [r.challenge_id for r in rows if r.state == "at_cap"]
    if capped:
        return Check("usage", "warn", f"{len(capped)} challenge(s) at their budget cap: "
                     f"{', '.join(capped[:6])}{' ...' if len(capped) > 6 else ''}; {detail}",
                     "raise a cap (`python -m ctf budget`) or leave the capped challenge parked")
    return Check("usage", "ok", detail)


# ---------------------------------------------------------------------------------------- power

def check_power(*, run: Callable[..., Any] | None = None, system: str | None = None) -> Check:
    """Battery or mains (macOS `pmset -g batt`, parsed by ctf.governor). Advisory: being on battery
    never blocks a wave (the B-176 governor decides how many heavy agents the battery carries)."""
    import platform as _platform
    from .governor import GovernorError, parse_pmset_batt
    if (system or _platform.system()) != "Darwin":
        return Check("power", "skip", "the power source check reads macOS pmset; not macOS")
    exe = shutil.which("pmset")
    if not exe:
        return Check("power", "skip", "pmset is not on PATH: power source unknown")
    run = run or subprocess.run
    try:
        p = run([exe, "-g", "batt"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as err:
        return Check("power", "skip", f"pmset -g batt did not run: {err}")
    if p.returncode != 0:
        return Check("power", "skip", f"pmset -g batt failed (exit {p.returncode})")
    try:
        b = parse_pmset_batt(p.stdout or "")
    except GovernorError as err:
        return Check("power", "skip", str(err))
    if b.plugged is None:
        return Check("power", "skip", "pmset -g batt did not name the power source")
    if not b.present:
        return Check("power", "ok", "no battery (desktop), on mains")
    level = f", {b.percent:g}%" if b.percent is not None else ""
    if not b.plugged:
        return Check("power", "warn", f"on battery power{level}: a long wave may sleep or throttle",
                     "plug in before the wave (advisory: never blocks)")
    if b.charger_deficit:
        return Check("power", "warn", f"on the charger but discharging{level}: the load draws more than "
                     "the charger supplies", "use a stronger charger or run fewer heavy agents")
    return Check("power", "ok", f"on mains{level}" + (f", {b.state}" if b.state else ""))

# ---------------------------------------------------------------------------------------- capabilities

def check_capabilities(info) -> Check:
    """The capability self-test (ctf.sandboxinfo): says whether results here are host facts."""
    probed = ", ".join(f"{n} ok" for n in sorted(info.verified)) or "no probe passed"
    if not info.sandboxed:
        return Check("capabilities", "ok", f"not sandboxed ({probed}): results are host facts")
    unv = ", ".join(info.unverified(("network", "docker", "loopback", "tmp-write"))) or "nothing"
    return Check("capabilities", "warn", f"{info.summary()} ({probed}); unverified here: {unv}. A fail that "
                 "needed one of them is labelled sandbox-only, not a blocker",
                 "re-run `python -m ctf preflight` on the host, outside any agent sandbox, for host facts")


def label_sandbox_only(checks: list[Check], info) -> list[Check]:
    """Relabel each fail that depended on a capability this sandboxed process could not confirm:
    status skip, sandbox_only, the reason in front. Nothing changes on the host."""
    import dataclasses
    out = []
    for c in checks:
        unv = info.unverified(c.needs) if c.status == "fail" and c.needs else ()
        if unv:
            c = dataclasses.replace(
                c, status="skip", sandbox_only=True,
                detail=f"sandbox-only result (needs {', '.join(unv)}; {info.summary()}): {c.detail}",
                fix="re-run outside the sandbox to see whether it is a host fact"
                    + (f"; if it fails there: {c.fix}" if c.fix else ""))
        out.append(c)
    return out


# ---------------------------------------------------------------------------------------- brief rules

def default_fence(profile: _event.EventProfile):
    """The fence the launchers would build for this event right now (events/<slug>/fence.toml)."""
    from . import fence as _fence
    return _fence.from_config(_fence.load_config(profile.slug), slug=profile.slug)


def check_brief_rules(profile: _event.EventProfile, briefs, *, fence=None, claude_settings=None,
                      settings_source: str | None = None, harnesses=("claude", "codex"),
                      mode: str | None = None, background: bool = True,
                      brief_workdir: Path | None = None) -> Check:
    """Simulate every command and write each brief asks for against the rules the agent runs under
    (ctf.rulesim): the fence the launcher builds now, or a Claude settings file named explicitly.
    `mode` is the Claude permission mode (default: the launchers' rulesim.LAUNCH_PERMISSION_MODE).
    `brief_workdir` adds the briefs the launchers wrote under that event workdir
    (rulesim.launcher_briefs: <workdir>/*/codex_brief*.md, never a recursive search)."""
    from . import fence as _fence
    from . import rulesim
    mode = rulesim.LAUNCH_PERMISSION_MODE if mode is None else mode
    briefs = list(briefs or [])
    if not briefs and brief_workdir is None:
        return Check("brief-rules", "skip", "no briefs named to simulate",
                     "`ctf preflight --brief FILE|DIR` (or --all-briefs for the event workdir) before a wave")
    files: list[Path] = []
    for b in briefs:
        try:
            files.extend(rulesim.find_briefs(Path(b)))
        except FileNotFoundError as err:
            return Check("brief-rules", "fail", str(err))
    if brief_workdir is not None:
        try:
            files.extend(rulesim.launcher_briefs(Path(brief_workdir)))
        except FileNotFoundError as err:
            return Check("brief-rules", "fail", str(err))
    if not files:
        where = [f"*brief*.md under {b}" for b in briefs]
        if brief_workdir is not None:
            where.append(f"{rulesim.LAUNCHER_BRIEF_GLOB} under {brief_workdir}")
        return Check("brief-rules", "skip", f"no brief found: {'; '.join(where)}")
    try:
        f = fence if fence is not None else default_fence(profile)
    except _fence.FenceError as err:
        return Check("brief-rules", "fail", f"cannot build the fence the launcher uses: {err}")
    notes = []
    current = f.claude_settings()
    on_disk = f.workspace / _fence.FENCE_DIRNAME / _fence.CLAUDE_SETTINGS_NAME
    if claude_settings is None:
        claude_settings, src = current, "the fence's settings as the launcher writes them now"
        try:
            import json as _json
            if on_disk.is_file() and _json.loads(on_disk.read_text(encoding="utf-8")) != current:
                notes.append(f"{on_disk} is stale (the launcher rewrites it at launch)")
        except (OSError, ValueError):
            notes.append(f"{on_disk} is not readable JSON (the launcher rewrites it at launch)")
    else:
        src = settings_source or "the settings given"
        if claude_settings != current:
            notes.append(f"{src} differs from the fence's current settings")
    rules = []
    try:
        if "claude" in harnesses:
            rules.append(rulesim.ClaudeRules.from_settings(claude_settings, cwd=f.workspace, home=f.home,
                                                           mode=mode, source=src))
        if "codex" in harnesses:
            rules.append(rulesim.CodexRules.from_fence(f))
    except rulesim.RulesError as err:
        return Check("brief-rules", "fail", f"cannot read the rules: {err}")
    if not rules:
        return Check("brief-rules", "fail", f"no harness to simulate (asked for {harnesses!r})")
    rows: list[tuple[Path, Any]] = []
    empty = []
    for p in files:
        try:
            acts = rulesim.extract(rulesim.read_brief(p))
        except (OSError, rulesim.RulesError) as err:
            return Check("brief-rules", "fail", f"{p}: {err}")
        if not acts:
            empty.append(p.name)
        rows.extend((p, d) for d in rulesim.simulate(acts, rules))
    bad = [(p, d) for p, d in rows if d.verdict == "deny" or (d.verdict == "prompt" and background)]
    soft = [(p, d) for p, d in rows if d.verdict == "prompt" and not background]
    judged = [(p, d) for p, d in rows if d.verdict == "classifier"]
    who = " and ".join(r.label for r in rules)
    n_acts = len({(p, d.action) for p, d in rows})

    def fmt(items):
        return "; ".join(f"{p.name}:{d.action.line} {d.harness} {d.verdict} {d.action.kind} "
                         f"`{d.action.text[:70]}`: {d.reason}" for p, d in items[:6]) + \
            (f"; ... {len(items) - 6} more" if len(items) > 6 else "")
    tail = (" (" + "; ".join(notes) + ")") if notes else ""
    scope = (f"{n_acts} action(s) from {len(files)} brief(s) against {who}, rules from {src}; user and "
             f"managed Claude settings are not read{tail}")
    if bad:
        return Check("brief-rules", "fail", f"{len(bad)} refusal(s)"
                     + (" (a background agent fails on a prompt)" if any(d.verdict == "prompt" for _, d in bad)
                        else "") + f": {fmt(bad)}. {scope}",
                     "change the brief (absolute paths inside the workspace, allowed commands) or the "
                     "rules (events/<slug>/fence.toml, launcher --permission-mode), then re-run")
    if soft or judged or empty:
        parts = []
        if soft:
            parts.append(f"{len(soft)} prompt(s) an interactive session will see: {fmt(soft)}")
        if judged:
            parts.append(f"{len(judged)} action(s) left to the auto-mode classifier (approximate: not a "
                         f"prompt, but it may refuse them at run time): {fmt(judged)}")
        if empty:
            parts.append(f"no command or path found in {', '.join(empty[:6])}")
        return Check("brief-rules", "warn", "; ".join(parts) + f". {scope}")
    return Check("brief-rules", "ok", f"every action allowed: {scope}")


# ---------------------------------------------------------------------------------------- toolbox

def check_toolbox(environ: Mapping[str, str] | None = None, *, root: Path | None = None,
                  run: Callable[..., Any] = subprocess.run) -> Check:
    """The binary toolbox (B-142, tools/toolbox.toml): every tool present, answering its version
    probe, with its runtime needs. Advisory: a missing tool blocks one archetype, not the wave, so a
    core problem is a warn naming each tool (strict mode fails on it); an unreadable manifest fails."""
    from . import toolbox as _tb
    try:
        tools = _tb.load(_tb.manifest_path(root))
    except _tb.ToolboxError as e:
        return Check("toolbox", "fail", f"cannot read the toolbox manifest: {e}",
                     f"fix {_tb.MANIFEST_REL}")
    report = _tb.verify(tools, environ=environ, run=run)
    core = _tb.problems(report, core_only=True)
    opt = [s for s in _tb.problems(report) if s.role != "core"]
    n_ok = sum(1 for s in report if s.ok)
    detail = f"{n_ok}/{len(report)} ok"
    if core:
        detail += "; core: " + "; ".join(f"{s.name} {s.state} ({s.detail})" if s.detail else
                                         f"{s.name} {s.state}" for s in core)
    if opt:
        detail += "; optional: " + ", ".join(f"{s.name} {s.state}" for s in opt)
    if core:
        return Check("toolbox", "warn", detail,
                     "`python -m ctf toolbox install` lists the installs (a dry run); run them before the event")
    return Check("toolbox", "ok", detail)


def check_assets(environ: Mapping[str, str] | None = None, *, root: Path | None = None,
                 run: Callable[..., Any] = subprocess.run) -> Check:
    """The asset manifest (B-188, tools/assets.toml): every wordlist and install folder resolves.
    Advisory like the toolbox: a core asset that is not ok is a warn naming it; an unreadable manifest
    fails. `python -m ctf toolchain env` exports what resolved."""
    from .toolchain import assets as _as
    try:
        items = _as.load(_as.manifest_path(root))
    except _as.AssetsError as e:
        return Check("assets", "fail", f"cannot read the asset manifest: {e}", f"fix {_as.MANIFEST_REL}")
    report = _as.resolve(items, environ=environ, run=run)
    core = _as.problems(report, core_only=True)
    opt = [s for s in _as.problems(report) if s.role != "core"]
    detail = f"{sum(1 for s in report if s.ok)}/{len(report)} ok"
    if core:
        detail += "; core: " + "; ".join(f"{s.name} {s.state} ({s.detail})" for s in core)
    if opt:
        detail += "; optional: " + ", ".join(f"{s.name} {s.state}" for s in opt)
    if core:
        return Check("assets", "warn", detail, "; ".join(f"{s.name}: {s.fix}" for s in core if s.fix))
    return Check("assets", "ok", detail + "; export them with: eval \"$(python -m ctf toolchain env)\"")


def check_images(environ: Mapping[str, str] | None = None, *, root: Path | None = None,
                 run: Callable[..., Any] = subprocess.run) -> Check:
    """The pinned toolchain images (B-188, tools/images.toml): the manifest lints clean (a pinned
    image's finding fails), and each core image is present and fresh (`docker image inspect`, a read;
    a missing or stale core image is a warn). Docker absent is a warn; under CTF_TESTING a docker that
    is not a test stub makes the local part a skip."""
    from .toolchain import images as _im
    try:
        imgs = _im.load(_im.manifest_path(root))
        errs = _im.errors(_im.lint(imgs, root), imgs)
    except _im.ImagesError as e:
        return Check("images", "fail", f"cannot read the image manifest: {e}", f"fix {_im.MANIFEST_REL}")
    if errs:
        return Check("images", "fail", "lint: " + "; ".join(f.render() for f in errs[:5]),
                     "`python -m ctf toolchain lint` lists them; pin what it names")
    try:
        report = _im.status(imgs, root=root, environ=environ, run=run)
    except _im.ImagesError as e:
        return Check("images", "skip", f"lint ok; local images not inspected: {e}")
    if all(s.state == "unknown" for s in report) and report:
        return Check("images", "warn", f"lint ok; {report[0].detail}", report[0].fix)
    core = _im.problems(report, core_only=True)
    opt = [s for s in _im.problems(report) if s.role != "core"]
    detail = f"lint ok; {sum(1 for s in report if s.ok)}/{len(report)} images ok"
    if core:
        detail += "; core: " + "; ".join(f"{s.name} {s.state}" for s in core)
    if opt:
        detail += "; optional: " + ", ".join(f"{s.name} {s.state}" for s in opt)
    if core:
        return Check("images", "warn", detail, "`python -m ctf toolchain build` plans the builds (a dry run)")
    return Check("images", "ok", detail)


# ---------------------------------------------------------------------------------------- all

def run_checks(profile: _event.EventProfile, *, codex: bool = True, codex_mode: str = "fast",
               environ: Mapping[str, str] | None = None, root: Path | None = None,
               instances_cfg: Mapping[str, Any] | None = None, instance_challenge: int | None = None,
               client=None, now: _dt.datetime | None = None,
               run: Callable[..., Any] = subprocess.run, toolbox: bool = True, token: bool = True,
               briefs=None, fence=None, claude_settings=None, settings_source: str | None = None,
               harnesses=("claude", "codex"), permission_mode: str | None = None, background: bool = True,
               brief_workdir: Path | None = None,
               usage: bool = True, usage_workdir: Path | None = None, power: bool = True,
               power_run: Callable[..., Any] | None = None, sandbox=None) -> list[Check]:
    """Every check, in order: the B-039 ones (with B-032's compaction and B-142's toolbox), B-171's
    allowance, B-170's failover, then token, brief-rules, usage, power, capabilities (B-190).
    `usage_workdir` is the event workdir the allowance, failover and usage checks read (default: the
    event's). `sandbox` is a
    ctf.sandboxinfo.SandboxInfo (detected when None); a fail that needed a capability the sandbox could
    not vouch for is relabelled sandbox-only."""
    out = [check_profile(profile, now=now)]
    manifests = None
    try:
        from .engines import manifest
        manifests = manifest.discover(root)
    except Exception as e:
        out.append(Check("categories", "fail", f"cannot read the engine manifests: {e}"))
    if manifests is not None:
        out.append(check_categories(profile, manifests))
    out.append(check_router(root))
    from . import compaction
    out.append(Check("compaction", *compaction.preflight(environ, codex=codex)))
    if codex:
        out.append(check_codex_model(environ, root=root, mode=codex_mode))
        out.append(check_codex_smoke(environ, root=root, mode=codex_mode, run=run))
    else:
        out.append(Check("codex-smoke", "skip", "skipped (--no-codex): Codex handoffs are untested"))
    out.append(check_submit_dry_run(profile))
    out.append(check_instances(profile, instances_cfg, instance_challenge, client))
    if toolbox:
        out.append(check_toolbox(environ, root=root, run=run))
        out.append(check_assets(environ, root=root, run=run))
        out.append(check_images(environ, root=root, run=run))
    else:
        out.append(Check("toolbox", "skip", "skipped (--no-toolbox): the binary toolbox is unverified"))
        out.append(Check("assets", "skip", "skipped (--no-toolbox): the asset manifest is unresolved"))
        out.append(Check("images", "skip", "skipped (--no-toolbox): the toolchain images are unverified"))
    out.append(check_allowance(profile, workdir=usage_workdir, now=now))
    out.append(check_failover(profile, workdir=usage_workdir))
    if token:
        out.append(check_token(profile, client=client, environ=environ, now=now))
    else:
        out.append(Check("token", "skip", "skipped (--no-token): token validity and expiry unchecked"))
    out.append(check_brief_rules(profile, briefs, fence=fence, claude_settings=claude_settings,
                                 settings_source=settings_source, harnesses=harnesses,
                                 mode=permission_mode, background=background, brief_workdir=brief_workdir))
    if usage:
        out.append(check_usage(profile, workdir=usage_workdir))
    if power:
        out.append(check_power(run=power_run))
    if sandbox is None:
        from . import sandboxinfo
        sandbox = sandboxinfo.detect(environ)
    out.append(check_capabilities(sandbox))
    return label_sandbox_only(out, sandbox)


def check_allowance(profile: _event.EventProfile, *, workdir: Path | None = None,
                    now: _dt.datetime | None = None) -> Check:
    """B-171: is the next release funded? (ctf.quota.check; reads the stored readings, no session log.)"""
    from . import quota
    return quota.check(profile, workdir=workdir, now=now.timestamp() if now is not None else None)


def check_failover(profile: _event.EventProfile, *, workdir: Path | None = None) -> Check:
    """B-170: has each harness direction a live failover rehearsal that held? (ctf.failover.check)"""
    from . import failover
    return failover.check(profile, workdir=workdir)
