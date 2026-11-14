"""B-003: the event profile's [instances] section, and make_adapter reading it (plus renew)."""
from __future__ import annotations

import tomllib

import pytest

from ctf import event
from ctf.platform import ctfd, supports_instances
from ctf.platform.base import InstancesUnavailable
from platform_fixture_session import FakeSession, load

FX = load("ctfd_api.json")
BASE = FX["base_url"]

_BASE_TOML = f"""
slug = "demo"
name = "Demo"
[dates]
start = 2026-01-01T00:00:00Z
end = 2026-01-02T00:00:00Z
[platform]
kind = "ctfd"
base_url = "{BASE}"
[flag]
prefixes = ["CSCTF"]
[rules]
submit_mode = "auto"
flag_sharing = "allowed"
ai_on_platform = "allowed"
"""


def _profile(extra: str = "") -> event.EventProfile:
    return event.parse(tomllib.loads(_BASE_TOML + extra), src="<demo>")


# --------------------------------------------------------------------------------- parsing
def test_instances_section_parsed_with_plugin_shape():
    p = _profile('[instances]\ncap = 3\n[instances.endpoints]\nplugin = "docker_per_team"\n')
    assert p.instances is not None
    assert p.instances.cap == 3
    assert p.instances.as_config() == {"cap": 3, "endpoints": {"plugin": "docker_per_team"}}


def test_instances_cap_optional_means_no_local_cap():
    p = _profile('[instances]\n[instances.endpoints]\nplugin = "docker_per_team"\n')
    assert p.instances.cap is None


def test_no_instances_section_leaves_it_none():
    assert _profile().instances is None


def test_instances_bad_plugin_fails_loudly_at_load():
    with pytest.raises(event.EventError, match="unknown instance plugin"):
        _profile('[instances]\ncap = 2\n[instances.endpoints]\nplugin = "whale"\n')


def test_instances_missing_endpoints_fails():
    with pytest.raises(event.EventError, match="endpoints"):
        _profile("[instances]\ncap = 2\n")


def test_instances_cap_must_be_positive():
    with pytest.raises(event.EventError, match="cap"):
        _profile('[instances]\ncap = 0\n[instances.endpoints]\nplugin = "docker_per_team"\n')


def test_instances_rejects_unknown_key():
    with pytest.raises(event.EventError, match="instances"):
        _profile('[instances]\ncap = 2\nnope = 1\n[instances.endpoints]\nplugin = "docker_per_team"\n')


def test_instances_endpoints_do_not_alias_the_parsed_toml():
    data = tomllib.loads(_BASE_TOML + '[instances]\ncap = 3\n[instances.endpoints]\nplugin = "docker_per_team"\n'
                         'host_keys = ["hostname"]\n')
    raw = data["instances"]["endpoints"]
    p = event.parse(data, src="<demo>")
    raw["plugin"] = "ctfd_docker"                   # the caller mutates its parsed TOML after load
    raw["host_keys"].append("ip")
    assert p.instances.endpoints["plugin"] == "docker_per_team"
    assert tuple(p.instances.endpoints["host_keys"]) == ("hostname",)
    with pytest.raises(TypeError):
        p.instances.endpoints["plugin"] = "ctfd_docker"     # read-only on the profile itself
    cfg = p.instances.as_config()
    cfg["endpoints"]["plugin"] = "ctfd_docker"      # as_config hands out a fresh copy
    cfg["endpoints"]["host_keys"].append("ip")
    assert p.instances.as_config() == {"cap": 3, "endpoints": {"plugin": "docker_per_team",
                                                               "host_keys": ["hostname"]}}


def test_instances_cfg_copies_a_caller_dict():
    src = {"plugin": "docker_per_team"}
    cfg = event.InstancesCfg(cap=2, endpoints=src)
    src["plugin"] = "ctfd_docker"
    assert cfg.endpoints["plugin"] == "docker_per_team"
    assert cfg == event.InstancesCfg(cap=2, endpoints={"plugin": "docker_per_team"})


def test_profile_with_instances_dict_field_is_still_hashable():
    p = _profile('[instances]\ncap = 3\n[instances.endpoints]\nplugin = "docker_per_team"\n')
    assert isinstance(hash(p), int)     # the endpoints dict is excluded from the hash


# --------------------------------------------------------------------------------- make_adapter wiring
def _make(profile):
    return ctfd.make_adapter(profile, session=FakeSession(FX["routes"]),
                             anon_session=FakeSession(FX["routes"]),
                             environ={"CTF_TOKEN": "tok-test-value"})


def test_make_adapter_reads_instances_from_the_profile():
    p = _profile('[instances]\ncap = 3\n[instances.endpoints]\nplugin = "docker_per_team"\n')
    a = _make(p)
    assert isinstance(a, ctfd.CTFdInstanceAdapter) and supports_instances(a)
    assert a.start_instance("1").state == "running"


def test_make_adapter_without_instances_is_the_plain_adapter():
    a = _make(_profile())
    assert not supports_instances(a)
    with pytest.raises(InstancesUnavailable):
        a.start_instance("1")


def test_renew_instance_hits_the_renew_route():
    p = _profile('[instances]\ncap = 3\n[instances.endpoints]\nplugin = "docker_per_team"\n')
    a = _make(p)
    info = a.renew_instance("1")
    assert info.state == "running" and info.connection_info == "inst.ctf.example:31337"
    assert a._s.sent("POST", BASE + "/containers/api/renew")
