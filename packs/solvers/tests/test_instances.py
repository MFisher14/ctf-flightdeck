"""The container-instance helper's safety guards: scope lock, cap, teardown, connect-info extraction.

All offline — a fake CTFd (just `.challenges()`) and an injected transport that records calls and
returns canned plugin responses. No network, no real plugin. These lock the parts that must be correct
regardless of which Docker plugin an event runs. The `docker_per_team` endpoint shape asserted here is the
one confirmed live at CSCTF 2026 (wave 1); in master it is selected through the event profile's
`instances.endpoints`, never a module default.
"""
from __future__ import annotations

import pytest

from ctf import instances as _instances  # noqa: E402
from ctf.instances import (Instances, InstanceError, PLUGIN_SHAPES, PluginEndpoints,  # noqa: E402
                           endpoints_from_config)


class FakeCTFd:
    """Minimal stand-in: only `.challenges()` is used by the scope lock."""
    def __init__(self, visible_ids):
        self._ids = list(visible_ids)

    def challenges(self):
        return [{"id": i, "name": f"chal{i}"} for i in self._ids]


class RecordingTransport:
    """Records (method, path, json) and returns a canned response per path prefix."""
    def __init__(self, response=None):
        self.calls = []
        self.response = response if response is not None else {"success": True, "data": {}}

    def __call__(self, method, path, json):
        self.calls.append((method, path, json))
        return self.response


LIVE = endpoints_from_config({"plugin": "docker_per_team"})


def _mk(visible=(1, 2, 3), *, max_running=3, response=None):
    t = RecordingTransport(response)
    return Instances(FakeCTFd(visible), endpoints=LIVE, max_running=max_running, transport=t), t


# ---- scope lock -------------------------------------------------------------------------------------
def test_spawn_refuses_challenge_not_visible():
    inst, t = _mk(visible=(1, 2))
    with pytest.raises(InstanceError):
        inst.spawn(99)                       # 99 is not released to us
    assert t.calls == []                     # nothing hit the network


def test_spawn_refuses_non_int_id():
    inst, _ = _mk()
    for bad in ("1", 1.0, True, None):
        with pytest.raises(InstanceError):
            inst.spawn(bad)


def test_stop_and_status_also_scope_locked():
    inst, _ = _mk(visible=(1,))
    with pytest.raises(InstanceError):
        inst.stop(5)
    with pytest.raises(InstanceError):
        inst.status(5)


# ---- cap --------------------------------------------------------------------------------------------
def test_spawn_refuses_over_cap():
    inst, t = _mk(visible=(1, 2, 3, 4), max_running=3)
    for cid in (1, 2, 3):
        inst.spawn(cid)
    assert inst.at_capacity
    with pytest.raises(InstanceError):
        inst.spawn(4)                        # 4th would exceed the cap
    # only the 3 allowed spawns hit the transport
    assert sum(1 for m, _, _ in t.calls if m == "POST") == 3


def test_stop_frees_a_slot():
    inst, _ = _mk(visible=(1, 2, 3, 4), max_running=3)
    for cid in (1, 2, 3):
        inst.spawn(cid)
    inst.stop(2)
    assert inst.running() == [1, 3]
    inst.spawn(4)                            # now there's room
    assert inst.running() == [1, 3, 4]


def test_none_cap_allows_many():
    inst, _ = _mk(visible=tuple(range(10)), max_running=None)
    for cid in range(6):
        inst.spawn(cid)
    assert not inst.at_capacity
    assert inst.running() == list(range(6))


# ---- idempotence / tracking -------------------------------------------------------------------------
def test_spawn_twice_same_challenge_takes_one_slot():
    inst, t = _mk(visible=(1, 2, 3))
    inst.spawn(1)
    inst.spawn(1)                            # already running -> status, not a 2nd slot
    assert inst.running() == [1]
    assert sum(1 for _, path, _ in t.calls if path.endswith("/request")) == 1


def test_stop_untracked_is_safe_and_frees_nothing_extra():
    inst, _ = _mk(visible=(1, 2, 3))
    inst.spawn(1)
    inst.stop(2)                             # never spawned; should not error
    assert inst.running() == [1]


def test_stop_all_tears_down_everything():
    inst, _ = _mk(visible=(1, 2, 3))
    inst.spawn(1)
    inst.spawn(3)
    inst.stop_all()
    assert inst.running() == []


# ---- connection-info extraction ---------------------------------------------------------------------
def test_connection_info_parsed_from_data_block():
    resp = {"success": True, "data": {"hostname": "chal.example.ro", "port": 31337, "remaining_time": 3600}}
    inst, _ = _mk(visible=(1,), response=resp)
    info = inst.spawn(1)
    assert info["host"] == "chal.example.ro"
    assert info["port"] == 31337
    assert info["connect"] == "chal.example.ro:31337"
    assert info["remaining"] == 3600
    assert info["cid"] == 1


def test_connection_info_connect_string_without_separate_port():
    resp = {"success": True, "data": {"connect": "nc chal.example.ro 31337"}}
    inst, _ = _mk(visible=(1,), response=resp)
    info = inst.spawn(1)
    assert info["host"] == "nc chal.example.ro 31337"
    assert info["connect"] == "nc chal.example.ro 31337"


def test_spawn_passes_body_key_when_configured():
    ep = endpoints_from_config({"plugin": "docker_per_team"})
    t = RecordingTransport()
    inst = Instances(FakeCTFd((7,)), endpoints=ep, transport=t)
    inst.spawn(7)
    method, path, payload = t.calls[0]
    assert payload == {"chal_id": 7}
    assert path == "/containers/api/request"   # live plugin: cid travels in the body, not the path


def test_dig_helper_prefers_present_keys():
    assert _instances._dig({"data": {"port": 42}}, ("port",)) == 42
    assert _instances._dig({"data": {}}, ("port",)) is None
    assert _instances._dig("not a dict", ("port",)) is None


# ---- a refused start takes no slot (HTTP 400 "Max containers" reaches us as an error body) -----------
class ScriptedTransport:
    """Returns the next canned body per call, recording (method, path, json)."""
    def __init__(self, *bodies):
        self.calls = []
        self._bodies = list(bodies)

    def __call__(self, method, path, json):
        self.calls.append((method, path, json))
        return self._bodies.pop(0)


def test_spawn_400_max_containers_takes_no_slot():
    refused = {"error": "Max containers (3) reached"}
    t = ScriptedTransport(refused)
    inst = Instances(FakeCTFd((1, 2)), endpoints=LIVE, max_running=3, transport=t)
    with pytest.raises(InstanceError, match="Max containers"):
        inst.spawn(1)
    assert inst.running() == []              # no phantom slot
    assert not inst.at_capacity


def test_spawn_after_refusal_can_retry_and_then_records():
    ok = {"success": True, "data": {"hostname": "10.0.0.5", "port": 1337}}
    t = ScriptedTransport({"error": "Max containers (3) reached"}, ok)
    inst = Instances(FakeCTFd((1,)), endpoints=LIVE, max_running=3, transport=t)
    with pytest.raises(InstanceError):
        inst.spawn(1)
    info = inst.spawn(1)                     # a refused start must not short-circuit into status()
    assert inst.running() == [1]
    assert info["connect"] == "10.0.0.5:1337"
    assert [p for _, p, _ in t.calls] == ["/containers/api/request", "/containers/api/request"]


def test_spawn_success_false_takes_no_slot():
    t = ScriptedTransport({"success": False, "message": "challenge has no container", "data": {}})
    inst = Instances(FakeCTFd((1,)), endpoints=LIVE, transport=t)
    with pytest.raises(InstanceError, match="no container"):
        inst.spawn(1)
    assert inst.running() == []


def test_message_on_success_is_not_an_error():
    inst, _ = _mk(visible=(1,), response={"success": True, "message": "started",
                                          "data": {"hostname": "h", "port": 1}})
    info = inst.spawn(1)
    assert inst.running() == [1]
    assert info["error"] is None


def test_status_reports_plugin_error():
    inst, _ = _mk(visible=(1,), response={"error": "no running container"})
    assert inst.status(1)["error"] == "no running container"


# ---- endpoints come from the event profile, never a module default --------------------------------------
def test_instances_without_endpoints_fails_loudly():
    with pytest.raises(InstanceError, match="event profile"):
        Instances(FakeCTFd((1,)), transport=RecordingTransport())


def test_endpoints_from_config_missing_fails_loudly():
    for spec in (None, {}):
        with pytest.raises(InstanceError, match="no instance endpoints configured"):
            endpoints_from_config(spec)


def test_endpoints_from_config_unknown_plugin_and_keys():
    with pytest.raises(InstanceError, match="unknown instance plugin"):
        endpoints_from_config({"plugin": "ctfd_whale"})
    with pytest.raises(InstanceError, match="unknown instances.endpoints keys"):
        endpoints_from_config({"plugin": "docker_per_team", "spwan": ["POST", "/x"]})


def test_endpoints_from_config_explicit_routes_require_all_four():
    with pytest.raises(InstanceError, match="missing routes"):
        endpoints_from_config({"spawn": ["POST", "/c/start"]})
    ep = endpoints_from_config({"spawn": ["post", "/c/start"], "stop": ["POST", "/c/stop"],
                                "renew": ["POST", "/c/renew"], "status": ["GET", "/c/{cid}"],
                                "body_key": None, "site_root": True})
    assert ep.spawn == ("POST", "/c/start")
    assert ep.body_key is None and ep.site_root is True


def test_endpoints_from_config_bad_route_shape():
    with pytest.raises(InstanceError, match=r"\[METHOD, PATH\]"):
        endpoints_from_config({"plugin": "docker_per_team", "spawn": "POST /x"})
    with pytest.raises(InstanceError, match="must start with"):
        endpoints_from_config({"plugin": "docker_per_team", "stop": ["POST", "containers/stop"]})


def test_endpoints_from_config_plugin_with_override():
    ep = endpoints_from_config({"plugin": "docker_per_team", "renew": ["POST", "/containers/api/extend"]})
    assert ep.renew == ("POST", "/containers/api/extend")
    assert ep.spawn == PLUGIN_SHAPES["docker_per_team"].spawn
    assert ep.body_key == "chal_id"


def test_template_shape_puts_cid_in_query_and_no_body():
    t = RecordingTransport()
    inst = Instances(FakeCTFd((7,)), endpoints=endpoints_from_config({"plugin": "ctfd_docker"}), transport=t)
    inst.spawn(7)
    assert t.calls[0] == ("POST", "/plugins/ctfd-docker/container?challenge_id=7", None)


def test_from_config_requires_cap_and_applies_it():
    with pytest.raises(InstanceError, match="no `instances` section"):
        Instances.from_config(FakeCTFd((1,)), None)
    with pytest.raises(InstanceError, match="cap"):
        Instances.from_config(FakeCTFd((1,)), {"endpoints": {"plugin": "docker_per_team"}})
    with pytest.raises(InstanceError, match="cap"):
        Instances.from_config(FakeCTFd((1,)), {"endpoints": {"plugin": "docker_per_team"}, "cap": 0})
    inst = Instances.from_config(FakeCTFd((1, 2, 3)), {"endpoints": {"plugin": "docker_per_team"}, "cap": 2},
                                 transport=RecordingTransport())
    inst.spawn(1)
    inst.spawn(2)
    with pytest.raises(InstanceError, match="cap"):
        inst.spawn(3)


# ---- default transport: site-root vs API-base URL comes from the shape -------------------------------
class _Resp:
    status_code = 200


class _FakeSession:
    def __init__(self):
        self.urls = []

    def request(self, method, url, json=None, timeout=None):
        self.urls.append((method, url, json))
        return _Resp()


class _FakeClientCfg:
    base_url = "https://ctf.test"
    request_timeout_s = 5


class FakeClient(FakeCTFd):
    def __init__(self, visible):
        super().__init__(visible)
        self.cfg = _FakeClientCfg()
        self.api = self.cfg.base_url + "/api/v1"
        self.s = _FakeSession()
        self.allowed = []

    def _refuse_if_hint(self, path):
        pass

    def _envelope(self, r, allow_status=(200,)):
        self.allowed.append(allow_status)
        return {"success": True, "data": {"hostname": "h", "port": 2}}


@pytest.mark.parametrize("plugin,url", [
    ("docker_per_team", "https://ctf.test/containers/api/request"),
    ("ctfd_docker", "https://ctf.test/api/v1/plugins/ctfd-docker/container?challenge_id=4"),
])
def test_default_transport_base_url_follows_shape(plugin, url):
    c = FakeClient((4,))
    inst = Instances(c, endpoints=endpoints_from_config({"plugin": plugin}))
    inst.spawn(4)
    assert c.s.urls[0][1] == url
    assert 400 in c.allowed[0]               # the cap refusal must reach spawn() as a body, not an exception
