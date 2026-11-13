"""ctf.fence_launch.check_codex_extra: clap's attached short forms (-sVALUE, -s=VALUE, -cKEY=V,
-c=KEY=V) are the same arguments as the separate forms and must be refused the same way.
Found while verifying R-09: `-csandbox_mode=danger-full-access` passed the fence."""
from __future__ import annotations

import pytest

from ctf.fence_launch import LaunchError, check_codex_extra


@pytest.mark.parametrize("args, named", [
    (["-csandbox_mode=danger-full-access"], "sandbox_mode"),
    (["-c=sandbox_mode=danger-full-access"], "sandbox_mode"),
    (["-capproval_policy=never"], "approval_policy"),
    (["-c=service_tier = fast"], "service_tier"),
    (["-cpermissions.ctf_fence={}"], "permissions.ctf_fence"),
    (["-cdefault_permissions=other"], "default_permissions"),
])
def test_attached_config_overrides_of_the_fence_are_refused(args, named):
    with pytest.raises(LaunchError, match=f"refused codex override {named!r}"):
        check_codex_extra(args)


@pytest.mark.parametrize("arg, flag", [
    ("-sdanger-full-access", "-s"), ("-s=danger-full-access", "-s"),
    ("-anever", "-a"), ("-a=never", "-a"),
    ("-pfastprofile", "-p"), ("-Pother", "-P"), ("-C/elsewhere", "-C"),
])
def test_attached_short_flags_that_undo_the_fence_are_refused(arg, flag):
    with pytest.raises(LaunchError, match=f"refused codex argument {flag}:"):
        check_codex_extra([arg])


def test_an_attached_value_does_not_swallow_the_next_argument():
    # -cKEY=V carries its own value: the next argument is a flag of its own and is still checked
    with pytest.raises(LaunchError, match="refused codex argument -s:"):
        check_codex_extra(["-cmodel_reasoning_summary=none", "-s", "danger-full-access"])
    with pytest.raises(LaunchError, match="refused codex argument --yolo"):
        check_codex_extra(["--config=", "--yolo"])
