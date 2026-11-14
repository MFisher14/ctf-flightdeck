"""Scope-locked helper for per-team container instances (CTFd Docker plugin).

Some CSCTF challenges are Dockerized: the platform spins up a per-team instance you connect to, with a
small cap on how many may run at once (the organizers confirmed a limit exists but, as of 2026-11-05,
had not finalized the number — Discord: "yes, still negotiating"). Our `ctf/client.py` only reads
challenges and submits flags; it has no way to spawn/stop an instance, so today a human drives the CTFd
web UI by hand. This module closes that gap, under hard guards.

What it guarantees, regardless of which Docker plugin CSCTF runs:

  * SCOPE LOCK. It only ever acts on a challenge that is currently RELEASED and VISIBLE to our team
    (present in `ctfd.challenges()`). It refuses any other id by construction, so it can never touch the
    platform, the scoreboard, another squad's instance, or an unreleased challenge. CSCTF fair-play
    forbids exactly that; this makes it unreachable from here.
  * CAP. It tracks the instances we have spawned and refuses to exceed `max_running` (a courtesy guard
    so we never waste a request the plugin would reject anyway). The number is PARAMETERIZED because the
    organizers have not finalized it — default 3, override once it's known.
  * TEARDOWN. `stop()` frees the slot immediately; the wave discipline is spawn-only-while-working,
    tear-down-on-solve. `spawn()` of an already-running challenge returns its status, never a 2nd slot.
  * It never spends points: every call routes through the client's hint/unlock refusal, and it only hits
    the plugin's own container endpoints — never `/unlocks` or `/hints`.

  * A FAILED START TAKES NO SLOT. The live plugin answers a refused start ("Max containers (3)
    reached") with HTTP 400 and an `error` body. `spawn()` raises on that body instead of recording a
    phantom slot with a `None` host.

What is NOT hardcoded: the plugin's endpoint paths and response shape vary by plugin (CTFd-whale,
CTFd-owl, CTFd-Docker-Plugin, docker_per_team, ...). They come from the event's platform config
(`instances.endpoints` in the event profile) via `endpoints_from_config()`, which knows two named shapes:

  * `docker_per_team`: confirmed live at CSCTF 2026 (wave 1, 2026-11-06/07). Site-root paths,
    `POST /containers/api/{request,stop,renew,view_info}` with body `{"chal_id": N}`.
  * `ctfd_docker`: the pre-event template (`/api/v1/plugins/ctfd-docker/container?challenge_id=N`).
    NEVER confirmed live; probe it before relying on it.

There is no default shape: an Instances built without endpoints fails loudly with the reason. The
guards above do not depend on the wiring. Nothing here runs an untrusted artifact; it only asks the
platform to start/stop our own instance and reads back the connect string.

Known gap: the cap is per process. The plugin's slots are team-wide, so teammates' instances are
invisible here; the plugin's own 400 is the backstop, and that 400 now never takes a local slot.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping


class InstanceError(RuntimeError):
    pass


@dataclass(frozen=True)
class PluginEndpoints:
    """(HTTP method, path template) per action, and where to read the connect info in the response.

    `{cid}` in a template is replaced with the challenge id. `body_key` names the JSON field (if any)
    the plugin wants the challenge id under on a POST (e.g. CTFd-whale uses a query param, others a body
    field). `site_root` says whether paths hang off the site root (True) or the CTFd API base
    `/api/v1` (False). Build one from the event profile with `endpoints_from_config()`.
    """
    spawn: tuple[str, str]
    stop: tuple[str, str]
    renew: tuple[str, str]
    status: tuple[str, str]
    body_key: str | None = None
    site_root: bool = False
    # response field names to try, in order, when pulling the connect info back out
    host_keys: tuple[str, ...] = ("hostname", "host", "ip", "connect", "url")
    port_keys: tuple[str, ...] = ("port",)
    remaining_keys: tuple[str, ...] = ("remaining_time", "remaining", "expires", "timeout")
    error_keys: tuple[str, ...] = ("error", "errors", "message")


# Named plugin shapes an event profile can select with {"plugin": "<name>"}.
PLUGIN_SHAPES: dict[str, PluginEndpoints] = {
    # Confirmed live on CSCTF 2026 (docker_per_team plugin, wave 1): site-root paths, POST + {"chal_id": N}.
    "docker_per_team": PluginEndpoints(
        spawn=("POST", "/containers/api/request"),
        stop=("POST", "/containers/api/stop"),
        renew=("POST", "/containers/api/renew"),
        status=("POST", "/containers/api/view_info"),
        body_key="chal_id",
        site_root=True,
    ),
    # Pre-event template guess (CTFd-Docker-Plugin style, under /api/v1). Never confirmed live.
    "ctfd_docker": PluginEndpoints(
        spawn=("POST", "/plugins/ctfd-docker/container?challenge_id={cid}"),
        stop=("DELETE", "/plugins/ctfd-docker/container?challenge_id={cid}"),
        renew=("PATCH", "/plugins/ctfd-docker/container?challenge_id={cid}"),
        status=("GET", "/plugins/ctfd-docker/container?challenge_id={cid}"),
        body_key=None,
        site_root=False,
    ),
}

_ACTIONS = ("spawn", "stop", "renew", "status")
_TUPLE_FIELDS = ("host_keys", "port_keys", "remaining_keys", "error_keys")


def _route(name: str, value: Any) -> tuple[str, str]:
    if (not isinstance(value, (list, tuple)) or len(value) != 2
            or not all(isinstance(x, str) and x for x in value)):
        raise InstanceError(f"instances.endpoints.{name} must be [METHOD, PATH], got {value!r}")
    method, path = value
    if not path.startswith("/"):
        raise InstanceError(f"instances.endpoints.{name} path must start with '/', got {path!r}")
    return method.upper(), path


def endpoints_from_config(spec: Mapping[str, Any] | None) -> PluginEndpoints:
    """Build PluginEndpoints from the event profile's `instances.endpoints` section.

    `{"plugin": "docker_per_team"}` selects a named shape; any other key in the mapping overrides that
    field of the shape. Without `plugin`, all four routes (spawn/stop/renew/status) must be given.
    Missing or malformed config raises InstanceError naming the problem; there is no silent default.
    """
    if not spec:
        raise InstanceError(
            "no instance endpoints configured: set instances.endpoints in the event profile "
            f"(e.g. {{\"plugin\": \"docker_per_team\"}}; known shapes: {sorted(PLUGIN_SHAPES)})")
    if not isinstance(spec, Mapping):
        raise InstanceError(f"instances.endpoints must be a mapping, got {type(spec).__name__}")
    known = set(_ACTIONS) | set(_TUPLE_FIELDS) | {"plugin", "body_key", "site_root"}
    unknown = set(spec) - known
    if unknown:
        raise InstanceError(f"unknown instances.endpoints keys: {sorted(unknown)}")
    kw: dict[str, Any] = {}
    plugin = spec.get("plugin")
    if plugin is not None:
        if plugin not in PLUGIN_SHAPES:
            raise InstanceError(f"unknown instance plugin {plugin!r}; known shapes: {sorted(PLUGIN_SHAPES)}")
        base = PLUGIN_SHAPES[plugin]
        kw = {f: getattr(base, f) for f in base.__dataclass_fields__}
    else:
        missing = [a for a in _ACTIONS if a not in spec]
        if missing:
            raise InstanceError(
                f"instances.endpoints has no 'plugin' and is missing routes {missing}; give a plugin "
                f"name ({sorted(PLUGIN_SHAPES)}) or all of {list(_ACTIONS)}")
    for a in _ACTIONS:
        if a in spec:
            kw[a] = _route(a, spec[a])
    if "body_key" in spec:
        bk = spec["body_key"]
        if bk is not None and not (isinstance(bk, str) and bk):
            raise InstanceError(f"instances.endpoints.body_key must be a non-empty string or null, got {bk!r}")
        kw["body_key"] = bk
    if "site_root" in spec:
        if not isinstance(spec["site_root"], bool):
            raise InstanceError(f"instances.endpoints.site_root must be true/false, got {spec['site_root']!r}")
        kw["site_root"] = spec["site_root"]
    for f in _TUPLE_FIELDS:
        if f in spec:
            v = spec[f]
            if not isinstance(v, (list, tuple)) or not v or not all(isinstance(x, str) for x in v):
                raise InstanceError(f"instances.endpoints.{f} must be a non-empty list of strings, got {v!r}")
            kw[f] = tuple(v)
    return PluginEndpoints(**kw)


def _dig(body: Any, keys: tuple[str, ...]) -> Any:
    """First present key in `body` (or body['data']) among `keys`, else None."""
    for scope in (body, body.get("data") if isinstance(body, dict) else None):
        if isinstance(scope, dict):
            for k in keys:
                if scope.get(k) not in (None, ""):
                    return scope[k]
    return None


class Instances:
    def __init__(self, ctfd, *, endpoints: PluginEndpoints | None = None,
                 max_running: int | None = 3, transport: Callable[[str, str, dict | None], Any] | None = None):
        if endpoints is None:
            raise InstanceError(
                "Instances needs plugin endpoints from the event profile: use Instances.from_config(ctfd, "
                f"profile['instances']) or pass endpoints=endpoints_from_config(...) "
                f"(known shapes: {sorted(PLUGIN_SHAPES)})")
        if not isinstance(endpoints, PluginEndpoints):
            raise InstanceError(f"endpoints must be a PluginEndpoints, got {type(endpoints).__name__}")
        self.ctfd = ctfd
        self.ep = endpoints
        self.max_running = max_running          # None = no local cap (still bounded by the plugin)
        self._transport = transport or self._default_transport
        self._running: set[int] = set()         # cids we spawned and have not stopped (local cap truth)

    # ---- HTTP (routes through the client's session, auth, and hint refusal) ----------------------
    def _default_transport(self, method: str, path: str, json: dict | None) -> Any:
        c = self.ctfd
        c._refuse_if_hint(path)                 # defense in depth; plugin paths never match, but never spend points
        base = c.cfg.base_url if self.ep.site_root else c.api   # docker_per_team lives at site root
        r = c.s.request(method, base + path, json=json, timeout=c.cfg.request_timeout_s)
        return c._envelope(r, allow_status=(200, 400, 403, 429))  # 400 = "Max containers (3) reached"

    @classmethod
    def from_config(cls, ctfd, instances_cfg: Mapping[str, Any] | None, *,
                    transport: Callable[[str, str, dict | None], Any] | None = None) -> "Instances":
        """Build from the event profile's `instances` section: {"endpoints": {...}, "cap": N | null}.

        `cap` is required (null = no local cap) so an event never silently inherits another event's number.
        """
        if not instances_cfg or not isinstance(instances_cfg, Mapping):
            raise InstanceError("event profile has no `instances` section; this event has no instance "
                                "plugin configured, so instances cannot be started from here")
        if "cap" not in instances_cfg:
            raise InstanceError("event profile `instances.cap` is not set (use null for no local cap)")
        cap = instances_cfg["cap"]
        if cap is not None and (not isinstance(cap, int) or isinstance(cap, bool) or cap < 1):
            raise InstanceError(f"instances.cap must be a positive int or null, got {cap!r}")
        return cls(ctfd, endpoints=endpoints_from_config(instances_cfg.get("endpoints")),
                   max_running=cap, transport=transport)

    # ---- scope lock -------------------------------------------------------------------------------
    def _assert_in_scope(self, cid: int) -> None:
        if not isinstance(cid, int) or isinstance(cid, bool):
            raise InstanceError(f"challenge id must be an int, got {cid!r}")
        visible = {c.get("id") for c in self.ctfd.challenges()}
        if cid not in visible:
            raise InstanceError(
                f"challenge {cid} is not released/visible to our team — refusing (scope lock). "
                f"We only ever act on our own assigned, released challenges.")

    # ---- state ------------------------------------------------------------------------------------
    def running(self) -> list[int]:
        return sorted(self._running)

    @property
    def at_capacity(self) -> bool:
        return self.max_running is not None and len(self._running) >= self.max_running

    # ---- actions ----------------------------------------------------------------------------------
    def spawn(self, cid: int) -> dict:
        """Start (or re-read) our instance for challenge `cid`. Scope- and cap-guarded.

        Returns {cid, host, port, connect, remaining, raw}. Spawning a challenge already running returns
        its current status instead of taking a second slot.
        """
        self._assert_in_scope(cid)
        if cid in self._running:
            return self.status(cid)
        if self.at_capacity:
            raise InstanceError(
                f"at the instance cap ({self.max_running} running: {self.running()}). Stop one before "
                f"starting another — spawn only while actively working, tear down on solve.")
        body = self._call(self.ep.spawn, cid)
        err = self._error(body)
        if err is not None:
            # e.g. HTTP 400 "Max containers (3) reached" (teammates hold the slots): no slot is taken.
            raise InstanceError(f"plugin refused to start challenge {cid}: {err}")
        self._running.add(cid)
        return self._connection_info(cid, body)

    def status(self, cid: int) -> dict:
        self._assert_in_scope(cid)
        return self._connection_info(cid, self._call(self.ep.status, cid))

    def renew(self, cid: int) -> dict:
        self._assert_in_scope(cid)
        return self._connection_info(cid, self._call(self.ep.renew, cid))

    def stop(self, cid: int) -> dict:
        """Tear down our instance for `cid` and free the slot. Safe to call even if not tracked."""
        self._assert_in_scope(cid)
        try:
            body = self._call(self.ep.stop, cid)
        finally:
            self._running.discard(cid)          # free the slot even if the plugin already reaped it
        return {"cid": cid, "stopped": True, "raw": body}

    def stop_all(self) -> list[dict]:
        return [self.stop(cid) for cid in self.running()]

    # ---- internals --------------------------------------------------------------------------------
    def _call(self, action: tuple[str, str], cid: int) -> Any:
        method, template = action
        path = template.format(cid=cid)
        payload = {self.ep.body_key: cid} if self.ep.body_key else None
        return self._transport(method, path, payload)

    def _error(self, body: Any) -> Any:
        """The plugin's error message if `body` is a refusal, else None.

        A refusal is a body carrying an error key, or `success: false`. A message-only body with
        `success: true` is not an error.
        """
        if not isinstance(body, dict):
            return None
        failed = body.get("success") is False
        for k in self.ep.error_keys:
            v = body.get(k)
            if v not in (None, "", [], {}):
                if k == "error" or k == "errors" or failed:
                    return v
        return body if failed else None

    def _connection_info(self, cid: int, body: Any) -> dict:
        host = _dig(body, self.ep.host_keys)
        port = _dig(body, self.ep.port_keys)
        remaining = _dig(body, self.ep.remaining_keys)
        connect = host if (host and (port is None or str(port) in str(host))) else (
            f"{host}:{port}" if host and port else host)
        return {"cid": cid, "host": host, "port": port, "connect": connect,
                "remaining": remaining, "error": self._error(body), "raw": body}
