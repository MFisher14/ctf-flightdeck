"""Published-config and independent-state tests for the offline Kconfig profiler."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import wpgap_kconfig_profile as profiler  # noqa: E402


FIXTURE = REPO / "tests" / "fixtures" / "wpgap_kconfig_hardened_v1_7_2_rc5.config"
PUBLISHED_SHA256 = "74cac07f72886f909dcb40d98ab5d397649dc7666b36c5f724d736e35fd1fd01"


def states(profile: profiler.KernelProfile, name: str) -> tuple[str, str, str]:
    finding = profile.get(name)
    return finding.build_state, finding.runtime_state, finding.effective_state


def test_published_kernelctf_fixture_is_exact_and_profiles_without_runtime_inference():
    raw = FIXTURE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == PUBLISHED_SHA256
    assert len(raw.splitlines()) == 5194

    result = profiler.profile_kernel(raw.decode("utf-8"))
    assert result.config_symbol_count == 4212
    assert states(result, "forward_edge_cfi") == ("on", "unknown", "unknown")
    assert states(result, "x86_kernel_ibt") == ("on", "unknown", "unknown")
    assert states(result, "fineibt") == ("on", "unknown", "unknown")
    assert states(result, "kaslr") == ("on", "unknown", "unknown")
    assert states(result, "kpti") == ("on", "unknown", "unknown")

    assert states(result, "slab_virtual") == ("on", "not-applicable", "on")
    assert states(result, "kmalloc_partition_caches") == ("on", "not-applicable", "on")
    assert states(result, "typed_kmalloc_partitioning") == ("on", "not-applicable", "on")
    assert states(result, "slab_buckets") == ("on", "not-applicable", "on")
    assert states(result, "slab_merge_disabled") == ("on", "unknown", "unknown")
    assert states(result, "hardened_usercopy") == ("on", "unknown", "unknown")
    assert states(result, "init_on_alloc") == ("off", "unknown", "unknown")
    assert states(result, "init_on_free") == ("off", "unknown", "unknown")
    assert states(result, "randstruct") == ("off", "not-applicable", "off")

    assert states(result, "unprivileged_user_namespaces") == ("off", "not-applicable", "off")
    assert states(result, "io_uring") == ("off", "not-applicable", "off")
    assert states(result, "unprivileged_bpf") == ("on", "unknown", "unknown")
    assert "CONFIG_BPF_UNPRIV_DEFAULT_OFF=y" in result.get("unprivileged_bpf").evidence
    assert states(result, "bpf_jit_hardening") == ("on", "unknown", "unknown")
    assert states(result, "userfaultfd_kernel_faults") == ("on", "unknown", "unknown")

    assert states(result, "module_signature_enforcement") == ("on", "unknown", "unknown")
    assert states(result, "kernel_lockdown") == ("on", "unknown", "unknown")
    assert result.get("fuse").build_state == "on"
    assert result.get("nftables").build_state == "on"
    assert result.get("devmem").build_state == "off"
    assert result.get("kernel_tls").build_state == "off"
    assert result.get("crypto_user_aead").build_state == "off"
    assert result.get("af_unix_oob").build_state == "off"


@pytest.mark.parametrize(
    ("value", "expected"),
    [("0", "on"), ("1", "off"), ("2", "off")],
)
def test_unprivileged_bpf_runtime_sysctl_is_authoritative_not_config_default(value, expected):
    config = "\n".join((
        "CONFIG_BPF=y",
        "CONFIG_BPF_SYSCALL=y",
        "CONFIG_BPF_JIT=y",
        "CONFIG_BPF_UNPRIV_DEFAULT_OFF=y",
    ))
    missing = profiler.profile_kernel(config)
    assert states(missing, "unprivileged_bpf") == ("on", "unknown", "unknown")

    observed = profiler.profile_kernel(
        config, json.dumps({"kernel.unprivileged_bpf_disabled": int(value)})
    )
    assert states(observed, "unprivileged_bpf") == ("on", expected, expected)


def test_decisive_runtime_off_survives_an_incomplete_config_fragment():
    result = profiler.profile_kernel(
        "", "kernel.unprivileged_bpf_disabled=1\nkernel.io_uring_disabled=2"
    )
    assert states(result, "unprivileged_bpf") == ("unknown", "off", "off")
    assert states(result, "io_uring") == ("unknown", "off", "off")


@pytest.mark.parametrize(
    ("sysctl", "finding", "expected"),
    [
        ("kernel.io_uring_disabled=0", "io_uring", "on"),
        ("kernel.io_uring_disabled=1", "io_uring", "restricted"),
        ("kernel.io_uring_disabled=2", "io_uring", "off"),
        ("vm.unprivileged_userfaultfd=0", "userfaultfd_kernel_faults", "restricted"),
        ("vm.unprivileged_userfaultfd=1", "userfaultfd_kernel_faults", "on"),
    ],
)
def test_io_uring_and_userfaultfd_graded_runtime_states(sysctl, finding, expected):
    config = "CONFIG_IO_URING=y\nCONFIG_USERFAULTFD=y\n"
    result = profiler.profile_kernel(config, sysctl)
    assert result.get(finding).runtime_state == expected
    assert result.get(finding).effective_state == expected


def test_explicit_build_off_remains_not_applicable_despite_contradictory_sysctl():
    result = profiler.profile_kernel(
        "# CONFIG_IO_URING is not set\n# CONFIG_USERFAULTFD is not set\n",
        "kernel.io_uring_disabled=0\nvm.unprivileged_userfaultfd=1",
    )
    assert states(result, "io_uring") == ("off", "not-applicable", "off")
    assert states(result, "userfaultfd_kernel_faults") == ("off", "not-applicable", "off")


def test_user_namespace_gates_require_complete_positive_evidence():
    config = "CONFIG_USER_NS=y\n"
    assert states(
        profiler.profile_kernel(config, "user.max_user_namespaces=0"),
        "unprivileged_user_namespaces",
    ) == ("on", "off", "off")
    assert states(
        profiler.profile_kernel(config, "kernel.unprivileged_userns_clone=0"),
        "unprivileged_user_namespaces",
    ) == ("on", "off", "off")
    assert states(
        profiler.profile_kernel(config, "user.max_user_namespaces=1024"),
        "unprivileged_user_namespaces",
    ) == ("on", "unknown", "unknown")
    assert states(
        profiler.profile_kernel(
            config,
            "user.max_user_namespaces=1024\nkernel.unprivileged_userns_clone=1",
        ),
        "unprivileged_user_namespaces",
    ) == ("on", "on", "on")


def test_runtime_endgame_and_leak_facts_are_graded_not_overclaimed():
    config = "\n".join((
        "CONFIG_MODULES=y",
        "# CONFIG_STATIC_USERMODEHELPER is not set",
        'CONFIG_MODPROBE_PATH="/sbin/modprobe"',
        "CONFIG_COREDUMP=y",
        "CONFIG_KEXEC_FILE=y",
        "# CONFIG_KEXEC is not set",
        "CONFIG_KALLSYMS=y",
        "CONFIG_PRINTK=y",
        "CONFIG_PERF_EVENTS=y",
        "CONFIG_SECURITY_YAMA=y",
        "CONFIG_BPF_JIT=y",
        "CONFIG_LSM_MMAP_MIN_ADDR=0",
    ))
    facts = json.dumps({
        "kernel.modules_disabled": 0,
        "kernel.modprobe": "/sbin/modprobe",
        "kernel.core_pattern": "|/usr/libexec/core-helper %p",
        "kernel.kexec_load_disabled": 1,
        "kernel.kptr_restrict": 2,
        "kernel.dmesg_restrict": 1,
        "kernel.perf_event_paranoid": 2,
        "kernel.yama.ptrace_scope": 3,
        "net.core.bpf_jit_harden": 2,
        "vm.mmap_min_addr": 0,
    })
    result = profiler.profile_kernel(config, facts)
    assert states(result, "module_loading") == ("on", "restricted", "restricted")
    assert states(result, "modprobe_helper") == ("on", "restricted", "restricted")
    assert states(result, "core_pattern_pipe") == ("on", "on", "on")
    assert states(result, "kexec_loading") == ("on", "off", "off")
    assert states(result, "kptr_disclosure") == ("on", "off", "off")
    assert states(result, "unprivileged_dmesg") == ("on", "restricted", "restricted")
    assert states(result, "unprivileged_perf") == ("on", "restricted", "restricted")
    assert states(result, "yama_ptrace_restriction") == ("on", "on", "on")
    assert states(result, "bpf_jit_hardening") == ("on", "on", "on")
    assert states(result, "low_address_mmap") == ("on", "on", "on")


def test_low_mmap_floor_needs_both_runtime_and_lsm_evidence():
    unknown = profiler.profile_kernel("", "vm.mmap_min_addr=0")
    assert states(unknown, "low_address_mmap") == ("on", "unknown", "unknown")
    sysctl_floor = profiler.profile_kernel("", "vm.mmap_min_addr=65536")
    assert states(sysctl_floor, "low_address_mmap") == ("on", "restricted", "restricted")
    lsm_floor = profiler.profile_kernel(
        "CONFIG_LSM_MMAP_MIN_ADDR=32768\n", "vm.mmap_min_addr=0"
    )
    assert states(lsm_floor, "low_address_mmap") == ("on", "restricted", "restricted")


def test_empty_static_usermode_helper_path_decisively_disables_modprobe_route():
    config = "\n".join((
        "CONFIG_MODULES=y",
        "CONFIG_STATIC_USERMODEHELPER=y",
        'CONFIG_STATIC_USERMODEHELPER_PATH=""',
    ))
    result = profiler.profile_kernel(config, "kernel.modprobe=/tmp/ignored")
    assert states(result, "modprobe_helper") == ("on", "off", "off")


def test_cmdline_overrides_are_explicit_and_last_slab_token_wins():
    config = "\n".join((
        "CONFIG_CFI=y",
        "# CONFIG_CFI_PERMISSIVE is not set",
        "CONFIG_X86_KERNEL_IBT=y",
        "CONFIG_FINEIBT=y",
        "CONFIG_RANDOMIZE_BASE=y",
        "CONFIG_MITIGATION_PAGE_TABLE_ISOLATION=y",
        "CONFIG_RANDOMIZE_KSTACK_OFFSET=y",
        "# CONFIG_SLAB_MERGE_DEFAULT is not set",
        "# CONFIG_INIT_ON_ALLOC_DEFAULT_ON is not set",
        "CONFIG_INIT_ON_FREE_DEFAULT_ON=y",
        "CONFIG_HARDENED_USERCOPY=y",
        "CONFIG_HARDENED_USERCOPY_DEFAULT_ON=y",
        "CONFIG_MODULE_SIG=y",
        "# CONFIG_MODULE_SIG_FORCE is not set",
        "CONFIG_SECURITY_LOCKDOWN_LSM=y",
        "CONFIG_LOCK_DOWN_KERNEL_FORCE_NONE=y",
    ))
    cmdline = (
        "cfi=kcfi ibt=warn nokaslr pti=on randomize_kstack_offset=on "
        "slab_nomerge slab_merge init_on_alloc=1 init_on_free=0 "
        "hardened_usercopy=off module.sig_enforce=1 lockdown=confidentiality"
    )
    result = profiler.profile_kernel(config, "", cmdline)
    assert states(result, "forward_edge_cfi") == ("on", "on", "on")
    assert states(result, "fineibt") == ("on", "off", "off")
    assert states(result, "x86_kernel_ibt") == ("on", "restricted", "restricted")
    assert states(result, "kaslr") == ("on", "off", "off")
    assert states(result, "kpti") == ("on", "on", "on")
    assert states(result, "randomize_kstack_offset") == ("on", "on", "on")
    assert states(result, "slab_merge_disabled") == ("on", "off", "off")
    assert result.get("init_on_alloc").effective_state == "on"
    assert result.get("init_on_free").effective_state == "off"
    assert states(result, "hardened_usercopy") == ("on", "off", "off")
    assert result.get("module_signature_enforcement").effective_state == "on"
    assert result.get("kernel_lockdown").effective_state == "on"

    mitigations_off = profiler.profile_kernel(config, "", "mitigations=off")
    assert mitigations_off.get("kpti").effective_state == "off"


def test_legacy_aliases_do_not_conflate_random_and_typed_partitioning():
    result = profiler.profile_kernel(
        "CONFIG_CFI_CLANG=y\nCONFIG_RANDOM_KMALLOC_CACHES=y\n"
    )
    assert result.get("forward_edge_cfi").build_state == "on"
    assert states(result, "random_kmalloc_caches") == ("on", "not-applicable", "on")
    assert states(result, "typed_kmalloc_partitioning") == ("unknown", "unknown", "unknown")


def test_kconfig_parser_handles_real_forms_lowercase_symbol_and_absence():
    parsed = profiler.parse_kconfig(
        "\n".join((
            "CONFIG_BUILTIN=y",
            "CONFIG_DRIVER=m",
            "CONFIG_DISABLED=n",
            "# CONFIG_EXPLICIT is not set",
            "CONFIG_NUMBER=0x4000",
            'CONFIG_PATH="/sbin/\\\"helper"',
            "# CONFIG_SCSI_DC395x is not set",
        ))
    )
    assert parsed.state("CONFIG_BUILTIN") == "on"
    assert parsed.state("CONFIG_DRIVER") == "module"
    assert parsed.state("CONFIG_DISABLED") == "off"
    assert parsed.state("CONFIG_EXPLICIT") == "off"
    assert parsed.values["CONFIG_NUMBER"] == "0x4000"
    assert parsed.values["CONFIG_PATH"] == '/sbin/"helper'
    assert parsed.state("CONFIG_SCSI_DC395x") == "off"
    assert parsed.state("CONFIG_MISSING") == "unknown"


def test_sysctl_and_cmdline_parsers_normalize_without_filling_defaults():
    line_facts = profiler.parse_sysctl_facts(
        "/proc/sys/kernel/kptr_restrict=2\nvm/unprivileged_userfaultfd=0\n"
    )
    assert line_facts.values == {
        "kernel.kptr_restrict": "2",
        "vm.unprivileged_userfaultfd": "0",
    }
    json_facts = profiler.parse_sysctl_facts('{"kernel.io_uring_disabled": 1}')
    assert json_facts.values["kernel.io_uring_disabled"] == "1"

    command = profiler.parse_cmdline("quiet pti=off pti=on core=one")
    assert command.tokens == ("quiet", "pti=off", "pti=on", "core=one")
    assert command.has("quiet") and command.value("quiet") is None
    assert command.value("pti") == "on"
    assert command.value("missing") is None and not command.has("missing")


@pytest.mark.parametrize(
    ("function", "args"),
    [
        (profiler.parse_kconfig, (None,)),
        (profiler.parse_kconfig, ("CONFIG_BROKEN",)),
        (profiler.parse_kconfig, ("CONFIG_X=y\nCONFIG_X=y",)),
        (profiler.parse_kconfig, ('CONFIG_X="bad\\q"',)),
        (profiler.parse_kconfig, ("CONFIG_X=y\x00",)),
        (profiler.parse_sysctl_facts, (None,)),
        (profiler.parse_sysctl_facts, ("kernel.kptr_restrict",)),
        (profiler.parse_sysctl_facts, ('{"kernel.x": {"nested": 1}}',)),
        (profiler.parse_sysctl_facts, ('{"kernel.x": true}',)),
        (profiler.parse_sysctl_facts, ('{"kernel.x": 1, "kernel.x": 2}',)),
        (profiler.parse_cmdline, (None,)),
        (profiler.parse_cmdline, ('pti="unterminated',)),
        (profiler.parse_cmdline, ("bad/name=1",)),
        (profiler.profile_kernel, (None,)),
        (profiler.profile_kernel, ("CONFIG_BPF_SYSCALL=y", "kernel.unprivileged_bpf_disabled=9")),
        (profiler.KconfigFacts, (object(), {})),
        (profiler.SysctlFacts, (object(),)),
        (profiler.CmdlineFacts, ((), object())),
    ],
)
def test_malformed_public_inputs_raise_only_declared_error(function, args):
    with pytest.raises(profiler.WpgapKconfigError) as captured:
        function(*args)
    assert type(captured.value) is profiler.WpgapKconfigError


def test_oversized_input_fails_closed():
    with pytest.raises(profiler.WpgapKconfigError):
        profiler.parse_kconfig("A" * ((2 << 20) + 1))


def test_public_lookup_methods_fail_closed_on_malformed_names():
    config = profiler.parse_kconfig("CONFIG_X=y")
    cmdline = profiler.parse_cmdline("quiet")
    profile = profiler.profile_kernel("CONFIG_X=y")
    for call in (
        lambda: config.state([]),
        lambda: config.line([]),
        lambda: cmdline.has([]),
        lambda: cmdline.value([]),
        lambda: profile.get([]),
    ):
        with pytest.raises(profiler.WpgapKconfigError) as captured:
            call()
        assert type(captured.value) is profiler.WpgapKconfigError


def test_guarded_cli_success_help_and_failures(tmp_path, capsys):
    assert profiler.main(["--help"]) == 0
    capsys.readouterr()
    assert profiler.main([]) == 2
    assert "required" in capsys.readouterr().err
    assert profiler.main(42) == 2
    assert "malformed argv" in capsys.readouterr().err

    sysctls = tmp_path / "sysctl.json"
    sysctls.write_text('{"kernel.unprivileged_bpf_disabled": 2}', encoding="utf-8")
    code = profiler.main([
        str(FIXTURE),
        "--sysctl", str(sysctls),
        "--cmdline", "nokaslr slab_nomerge",
    ])
    assert code == 0
    rendered = json.loads(capsys.readouterr().out)
    assert rendered["schema"] == "wpgap-kconfig-profile-v1"
    assert rendered["offline"] is True and rendered["live_requests"] == 0
    by_name = {item["name"]: item for item in rendered["findings"]}
    assert by_name["unprivileged_bpf"]["effective_state"] == "off"
    assert by_name["kaslr"]["effective_state"] == "off"
    assert by_name["slab_merge_disabled"]["effective_state"] == "on"

    assert profiler.main([str(tmp_path / "missing.config")]) == 2
    captured = capsys.readouterr()
    assert "cannot read Kconfig" in captured.err
    assert "Traceback" not in captured.err

