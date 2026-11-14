"""Deterministic checks for the isolated offline memory-depth lane."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

import solvers.toolkits.memory_depth as memory_depth
from solvers.toolkits.memory_depth import (
    analyze_handles,
    analyze_injection,
    analyze_memory,
    analyze_process_crossview,
    build_memory_plan,
    credential_artifacts,
    installed_plugin_modules,
    parse_volatility_output,
    select_profile,
)


def _json_rows(rows: object, plugin: str, **kwargs):
    return parse_volatility_output(json.dumps(rows, separators=(",", ":")).encode(), plugin, **kwargs)


def _kinds(findings):
    return {finding.kind for finding in findings}


def test_installed_volatility_inventory_cross_check() -> None:
    inventory = installed_plugin_modules()
    assert isinstance(inventory, frozenset)
    assert {
        "windows.pslist",
        "windows.handles",
        "windows.malware.psxview",
        "windows.malware.malfind",
        "windows.registry.hashdump",
        "linux.pslist",
        "linux.malware.malfind",
        "linux.malware.process_spoofing",
        "mac.pslist",
        "mac.malfind",
    } <= inventory
    assert all("__init__" not in name and not name.endswith(".py") for name in inventory)


def test_profile_selection_all_platforms_and_declines() -> None:
    windows = select_profile(
        "windows",
        {
            "build": 19045,
            "arch": "amd64",
            "format": "crashdump",
            "pdb_guid": "00112233445566778899aabbccddeeff",
            "pdb_age": 2,
        },
    )
    assert windows is not None
    assert (windows.version, windows.architecture, windows.image_format) == (
        "Windows 10/Server 2016-2022",
        "x64",
        "windows-crashdump",
    )
    assert windows.symbol_hint == "ntkrnlmp.pdb/00112233445566778899AABBCCDDEEFF2"

    linux = select_profile(
        "linux",
        {
            "kernel_banner": "Linux version 6.8.12-ctf (builder@offline) x86_64",
            "format": "lime",
            "symbol_table": "symbols/linux-6.8.12-ctf.json.xz",
        },
    )
    assert linux is not None
    assert linux.version == "Linux 6.8.12-ctf"
    assert linux.symbol_hint.endswith("linux-6.8.12-ctf.json.xz")

    mac = select_profile(
        "darwin",
        {"banner": "Darwin Kernel Version 23.5.0: root:xnu arm64", "format": "raw"},
    )
    assert mac is not None
    assert (mac.os_family, mac.version, mac.architecture) == ("mac", "Darwin 23.5.0", "arm64")

    corrupt = (
        ("plan9", {"build": 19045, "arch": "x64"}),
        ("windows", {"arch": "x64"}),
        ("windows", {"build": "nineteen", "arch": "x64"}),
        ("windows", {"build": 19045, "arch": "mips"}),
        ("windows", {"build": 19045, "arch": "x64", "format": "lime"}),
        ("windows", {"build": 19045, "arch": "x64", "pdb_guid": "bad", "pdb_age": 1}),
        ("linux", {"banner": "not a kernel banner x86_64", "format": "lime"}),
        ("linux", {"banner": "Linux version 6.8 x86_64", "format": "lime"}),
        ("mac", {"banner": "Darwin Kernel Version nope x86_64"}),
        ("mac", {"banner": "Darwin Kernel Version 23.5.0 x86_64", "format": "elf-core"}),
        ("windows", {"Build": 19045, "build": 19046, "arch": "x64"}),
        ("windows", {"build": 19045, "arch": "x64\x00ignored"}),
    )
    for family, metadata in corrupt:
        assert select_profile(family, metadata) is None
    assert select_profile("windows", []) is None


@pytest.mark.parametrize(
    ("family", "metadata", "must_include"),
    [
        (
            "windows",
            {"build": 22631, "arch": "x64", "format": "raw"},
            {"windows.malware.psxview", "windows.handles", "windows.registry.lsadump"},
        ),
        (
            "linux",
            {"banner": "Linux version 6.6.31-lts x86_64", "format": "elf-core"},
            {"linux.pidhashtable", "linux.malware.malfind", "linux.malware.check_creds"},
        ),
        (
            "mac",
            {"banner": "Darwin Kernel Version 22.6.0 x86_64", "format": "vmware"},
            {"mac.proc_maps", "mac.malfind", "mac.lsof"},
        ),
    ],
)
def test_dependency_ordered_deep_plans(
    family: str, metadata: dict[str, object], must_include: set[str]
) -> None:
    plan = build_memory_plan(family, metadata)
    assert plan is not None
    assert plan.goals == ("handles", "injection", "credentials", "kernel")
    assert not plan.unavailable
    assert all(step.available for step in plan.steps)
    assert must_include <= {step.plugin for step in plan.steps}
    assert any(step.sensitive and step.phase == "credentials" for step in plan.steps)
    assert any("never invokes Volatility" in note for note in plan.notes)
    positions = {step.plugin: index for index, step in enumerate(plan.steps)}
    assert len(positions) == len(plan.steps)
    for step in plan.steps:
        assert all(dependency in positions for dependency in step.depends_on)
        assert all(positions[dependency] < positions[step.plugin] for dependency in step.depends_on)

    assert build_memory_plan(family, metadata, goals=()) is None
    assert build_memory_plan(family, metadata, goals=("handles", "execute")) is None
    assert build_memory_plan(family, metadata, goals="handles") is None
    assert build_memory_plan(family, metadata, goals=("handles",) * 17) is None


def test_json_jsonl_csv_renderer_normalization() -> None:
    json_records = _json_rows(
        [{"PID": 4, "PPID": 0, "ImageFileName": "System"}], "windows.pslist"
    )
    assert len(json_records) == 1
    assert (json_records[0].kind, json_records[0].pid, json_records[0].process) == (
        "process",
        4,
        "System",
    )

    rendered = {
        "columns": [{"name": "PID"}, {"name": "PPID"}, {"name": "Process"}],
        "rows": [[100, 4, "explorer.exe"], [200, 4, "hidden.exe"]],
    }
    renderer_records = _json_rows(rendered, "windows.psscan")
    assert [(row.pid, row.process) for row in renderer_records] == [
        (100, "explorer.exe"),
        (200, "hidden.exe"),
    ]

    jsonl = (
        b'{"PID":300,"PPID":4,"Process":"one.exe"}\n'
        b'{"PID":301,"PPID":4,"Process":"two.exe"}\n'
    )
    jsonl_records = parse_volatility_output(
        jsonl, "windows.psscan", format_hint="jsonl"
    )
    assert [row.pid for row in jsonl_records] == [300, 301]

    csv_data = (
        b"PID,Process,Handle,Type,GrantedAccess,Name\n"
        b"500,reader.exe,0x40,File,0x1,\\\\Device\\\\HarddiskVolume3\\\\data.txt\n"
    )
    csv_records = parse_volatility_output(csv_data, "windows.handles", format_hint="csv")
    assert len(csv_records) == 1
    assert (csv_records[0].pid, csv_records[0].address, csv_records[0].access) == (
        500,
        0x40,
        1,
    )


def test_tabular_and_json_row_caps_fail_closed_early(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(memory_depth, "MAX_ROWS", 2)
    rows = [
        {"PID": 100 + index, "PPID": 4, "Process": f"p{index}.exe"}
        for index in range(3)
    ]
    assert _json_rows(rows, "windows.pslist") == ()
    assert _json_rows({"rows": rows}, "windows.pslist") == ()
    jsonl = b"\n".join(json.dumps(row).encode() for row in rows) + b"\n"
    assert parse_volatility_output(jsonl, "windows.pslist", format_hint="jsonl") == ()
    csv_rows = b"PID,PPID,Process\n100,4,a.exe\n101,4,b.exe\n102,4,c.exe\n"
    assert parse_volatility_output(csv_rows, "windows.pslist", format_hint="csv") == ()

    # The exact limit remains valid; only the first excess row closes the parser.
    assert len(_json_rows(rows[:2], "windows.pslist")) == 2
    assert len(parse_volatility_output(
        b"PID,PPID,Process\n100,4,a.exe\n101,4,b.exe\n",
        "windows.pslist",
        format_hint="csv",
    )) == 2


def test_csv_header_dimensions_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(memory_depth, "MAX_FIELDS", 3)
    assert parse_volatility_output(
        b"PID,PPID,Process,Extra\n1,0,a.exe,x\n",
        "windows.pslist",
        format_hint="csv",
    ) == ()
    assert parse_volatility_output(
        ("PID,PPID," + "X" * 257 + "\n1,0,x\n").encode(),
        "windows.pslist",
        format_hint="csv",
    ) == ()
    assert parse_volatility_output(
        b"PID,PPID,Process," + b"x," * 10_000 + b"z\n",
        "windows.pslist",
        format_hint="csv",
    ) == ()
    assert parse_volatility_output(
        b"PID,PPID,Process\n1,0,a.exe," + b"x," * 10_000 + b"z\n",
        "windows.pslist",
        format_hint="csv",
    ) == ()
    quoted = parse_volatility_output(
        b'PID,PPID,Process\n1,0,"comma,name.exe"\n',
        "windows.pslist",
        format_hint="csv",
    )
    assert len(quoted) == 1 and quoted[0].process == "comma,name.exe"


def test_normalizer_declines_corrupt_or_ambiguous_input() -> None:
    bad_inputs = (
        b"",
        b"\x00corrupt",
        b"\xff\xfe",
        b"{",
        b"[]",
        b"{}",
        b"null",
        b'{"PID":"NaN","Process":"bad.exe"}',
        b'{"PID":1,"Process":"a.exe"}\n{"PID":2',
        b'{"PID":1,"PID":2,"Process":"duplicate.exe"}',
        b'{"PID":NaN,"Process":"nonfinite.exe"}',
        br'{"PID":1,"Process":"escaped\u0000nul.exe"}',
        b'[{"PID":1,"Process":"trailing.exe"},]',
    )
    for raw in bad_inputs:
        assert parse_volatility_output(raw, "windows.pslist") == ()
    assert _json_rows([{"PID": 1}], "windows.pslist") == ()
    assert _json_rows(
        [{"PID": 1, "Process": "bad.exe", "Start": "0x2000", "End": "0x1000"}],
        "windows.malware.malfind",
    ) == ()
    assert _json_rows([{"PID": 1, "Process": "a" * 17_000}], "windows.pslist") == ()
    assert parse_volatility_output(
        b"PID,Process,PPID\n1,bad.exe\n", "windows.pslist", format_hint="csv"
    ) == ()
    assert parse_volatility_output(
        b"PID,pid,Process\n1,1,bad.exe\n", "windows.pslist", format_hint="csv"
    ) == ()
    assert parse_volatility_output(
        b'[{"PID":1,"Process":"bad.exe"}]', "windows.not_installed"
    ) == ()
    assert parse_volatility_output(
        b'[{"PID":1,"Process":"bad.exe"}]', "windows.pslist", os_family="linux"
    ) == ()
    assert parse_volatility_output(
        b'[{"PID":1,"Process":"bad.exe"}]', "windows.pslist", format_hint="xml"
    ) == ()
    assert parse_volatility_output("not bytes", "windows.pslist") == ()
    deeply_nested = ('{"x":' + "[" * 1100 + "0" + "]" * 1100 + "}").encode()
    assert parse_volatility_output(deeply_nested, "windows.pslist") == ()


def test_process_cross_view_parent_and_name_analysis() -> None:
    active = _json_rows(
        [
            {"PID": 4, "PPID": 0, "ImageFileName": "System"},
            {"PID": 100, "PPID": 4, "ImageFileName": "explorer.exe"},
            {"PID": 300, "PPID": 999, "ImageFileName": "orphan.exe"},
        ],
        "windows.pslist",
    )
    scanned = _json_rows(
        [
            {"PID": 100, "PPID": 4, "Process": "renamed.exe"},
            {"PID": 200, "PPID": 4, "Process": "hidden.exe"},
        ],
        "windows.psscan",
    )
    cross_view = _json_rows(
        [
            {
                "PID": 250,
                "Process": "crossview.exe",
                "pslist": False,
                "psscan": True,
            }
        ],
        "windows.malware.psxview",
    )
    findings = analyze_process_crossview((*active, *scanned, *cross_view))
    assert {
        "scan-only-process",
        "cross-view-hidden-process",
        "pid-name-conflict",
        "orphan-parent",
    } <= _kinds(findings)
    assert any(finding.pid == 200 and finding.kind == "scan-only-process" for finding in findings)
    assert any(finding.pid == 250 and finding.confidence == 0.95 for finding in findings)

    benign_active = _json_rows(
        [
            {"PID": 4, "PPID": 0, "Process": "System"},
            {"PID": 100, "PPID": 4, "Process": "explorer.exe"},
        ],
        "windows.pslist",
    )
    benign_scan = _json_rows(
        [
            {"PID": 4, "PPID": 0, "Process": "System"},
            {"PID": 100, "PPID": 4, "Process": "explorer.exe"},
        ],
        "windows.psscan",
    )
    assert analyze_process_crossview((*benign_active, *benign_scan)) == ()
    assert analyze_process_crossview([object()]) == ()
    assert analyze_process_crossview([replace(active[0], kind="handle")]) == ()


def test_handle_target_access_and_sensitive_file_analysis() -> None:
    processes = _json_rows(
        [
            {"PID": 4, "PPID": 0, "Process": "System"},
            {"PID": 500, "PPID": 4, "Process": "collector.exe"},
            {"PID": 600, "PPID": 4, "Process": "lsass.exe"},
        ],
        "windows.pslist",
    )
    handles = _json_rows(
        [
            {
                "PID": 500,
                "Process": "collector.exe",
                "Handle": "0x40",
                "Type": "File",
                "GrantedAccess": "0x1",
                "Name": "\\\\Device\\\\HarddiskVolume3\\\\Windows\\\\System32\\\\config\\\\SAM",
            },
            {
                "PID": 500,
                "Process": "collector.exe",
                "Handle": "0x44",
                "Type": "Process",
                "GrantedAccess": "0x2a",
                "TargetPID": 600,
                "TargetProcess": "lsass.exe",
            },
            {
                "PID": 500,
                "Process": "collector.exe",
                "Handle": "0x48",
                "Type": "Token",
                "GrantedAccess": "0x22",
                "Name": "primary token",
            },
        ],
        "windows.handles",
    )
    findings = analyze_handles((*processes, *handles))
    assert _kinds(findings) == {
        "credential-file-handle",
        "injection-capable-handle",
        "token-duplicate-adjust-handle",
    }
    assert all(finding.pid == 500 and finding.process == "collector.exe" for finding in findings)

    benign = _json_rows(
        [
            {
                "PID": 500,
                "Process": "collector.exe",
                "Handle": "0x50",
                "Type": "File",
                "GrantedAccess": "0x1",
                "Name": "C:\\\\Temp\\\\ordinary.txt",
            },
            {
                "PID": 500,
                "Process": "collector.exe",
                "Handle": "0x54",
                "Type": "Process",
                "GrantedAccess": "0x10",
                "TargetPID": 600,
            },
            {
                "PID": 500,
                "Process": "collector.exe",
                "Handle": "0x58",
                "Type": "Thread",
                # These are PROCESS_VM_OPERATION/VM_WRITE/CREATE_THREAD bits, not a
                # thread-context mask, and must never produce the process-handle finding.
                "GrantedAccess": "0x2a",
                "TargetPID": 600,
                "TargetProcess": "lsass.exe",
            },
        ],
        "windows.handles",
    )
    assert analyze_handles((*processes, *benign)) == ()

    thread_hijack = _json_rows(
        [
            {
                "PID": 500,
                "Process": "collector.exe",
                "Handle": "0x5c",
                "Type": "Thread",
                "GrantedAccess": "0x12",
                "TargetPID": 600,
                "TargetProcess": "lsass.exe",
            }
        ],
        "windows.handles",
    )
    thread_findings = analyze_handles((*processes, *thread_hijack))
    assert _kinds(thread_findings) == {"thread-context-hijack-handle"}
    assert _json_rows([{"Process": "bad", "Type": "File", "Name": "/etc/shadow"}], "windows.handles") == ()
    assert analyze_handles(None) == ()


def test_privilege_capability_ptrace_and_global_file_rows() -> None:
    privileges = _json_rows(
        [
            {
                "PID": 500,
                "Process": "collector.exe",
                "Value": 20,
                "Privilege": "SeDebugPrivilege",
                "Attributes": "Present,Enabled,EnabledByDefault",
                "Description": "Debug programs",
            },
            {
                "PID": 501,
                "Process": "ordinary.exe",
                "Value": 20,
                "Privilege": "SeDebugPrivilege",
                "Attributes": "Present,Disabled",
                "Description": "Debug programs",
            },
        ],
        "windows.privileges",
    )
    capabilities = _json_rows(
        [
            {
                "Name": "debugger",
                "Tid": 42,
                "Pid": 42,
                "PPid": 1,
                "EUID": 1000,
                "cap_inheritable": "",
                "cap_permitted": "CAP_SYS_PTRACE,CAP_CHOWN",
                "cap_effective": "CAP_SYS_PTRACE,CAP_DAC_READ_SEARCH",
                "cap_bounding": "CAP_SYS_PTRACE,CAP_DAC_READ_SEARCH",
                "cap_ambient": "",
            }
        ],
        "linux.capabilities",
    )
    ptrace = _json_rows(
        [
            {
                "Process": "debugger",
                "PID": 42,
                "TID": 42,
                "Tracer TID": "N/A",
                "Tracee TID": 84,
                "Flags": "PT_PTRACED",
            }
        ],
        "linux.ptrace",
    )
    findings = analyze_handles((*privileges, *capabilities, *ptrace))
    assert _kinds(findings) == {
        "dangerous-enabled-privilege",
        "dangerous-effective-capability",
        "ptrace-relationship",
    }
    assert not any(finding.pid == 501 for finding in findings)

    files = _json_rows(
        [{"Address": "0xfffffff001234000", "File Path": "/private/etc/hosts"}],
        "mac.list_files",
    )
    assert len(files) == 1
    assert (files[0].kind, files[0].path) == ("file", "/private/etc/hosts")
    assert _json_rows(
        [{"Process": "bad", "PID": 1, "TID": 1, "Tracer TID": "broken", "Tracee TID": 2}],
        "linux.ptrace",
    ) == ()


def test_injection_module_thread_and_detector_analysis() -> None:
    process = _json_rows(
        [{"PID": 700, "PPID": 4, "Process": "bad.exe"}], "windows.pslist"
    )
    malfind = _json_rows(
        [
            {
                "PID": 700,
                "Process": "bad.exe",
                "Start": "0x1000",
                "End": "0x1fff",
                "Protection": "PAGE_EXECUTE_READWRITE",
                "Hexdump": "4d 5a 90 00",
            }
        ],
        "windows.malware.malfind",
    )
    thread = _json_rows(
        [
            {
                "PID": 700,
                "TID": 701,
                "Process": "bad.exe",
                "StartAddress": "0x1100",
            }
        ],
        "windows.threads",
    )
    unlinked = _json_rows(
        [
            {
                "Pid": 700,
                "Process": "bad.exe",
                "Base": "0x400000",
                "InLoad": False,
                "InInit": False,
                "InMem": True,
                "MappedPath": "C:\\\\Temp\\\\payload.dll",
            }
        ],
        "windows.malware.ldrmodules",
    )
    hollow = _json_rows(
        [{"PID": 700, "Process": "bad.exe", "Notes": "PEB image base mismatch"}],
        "windows.malware.hollowprocesses",
    )
    ghost = _json_rows(
        [
            {
                "PID": 700,
                "Process": "bad.exe",
                "Base": "0x500000",
                "FILE_OBJECT": "0xffff8000",
                "DeletePending": True,
                "DeleteOnClose": False,
                "Path": "C:\\\\Temp\\\\ghost.exe",
            }
        ],
        "windows.malware.processghosting",
    )
    suspicious_thread = _json_rows(
        [
            {
                "PID": 700,
                "TID": 702,
                "Process": "bad.exe",
                "Address": "0x600000",
                "VAD Path": "C:\\\\Temp\\\\odd.dll",
                "Note": "thread start is outside the expected image",
            }
        ],
        "windows.malware.suspicious_threads",
    )
    findings = analyze_injection(
        (*process, *malfind, *thread, *unlinked, *hollow, *ghost, *suspicious_thread)
    )
    assert {
        "private-executable-region",
        "thread-start-in-suspicious-region",
        "unlinked-module",
        "hollowprocesses-detector",
        "processghosting-detector",
        "suspicious_threads-detector",
    } <= _kinds(findings)

    benign_malfind = _json_rows(
        [
            {
                "PID": 700,
                "Process": "bad.exe",
                "Start": "0x7000",
                "End": "0x7fff",
                "Protection": "PAGE_READONLY",
                "Hexdump": "00 00 00 00",
            }
        ],
        "windows.malware.malfind",
    )
    assert analyze_injection((*process, *benign_malfind)) == ()
    assert analyze_injection(["not a record"]) == ()


def test_linux_mac_renderer_and_anomaly_coverage() -> None:
    linux_malfind = _json_rows(
        [
            {
                "PID": 42,
                "Process": "implant",
                "Start": "0x8000",
                "End": "0x8fff",
                "Path": "[anon]",
                "Protection": "rwxp",
                "Hexdump": "4d5a 9000",
            }
        ],
        "linux.malware.malfind",
    )
    mac_malfind = _json_rows(
        [
            {
                "PID": 52,
                "Process": "implantd",
                "Start": "0x9000",
                "End": "0x9fff",
                "Protection": "rwx",
                "Hexdump": "00 00",
            }
        ],
        "mac.malfind",
    )
    spoof_rows = _json_rows(
        [
            {
                "PID": 42,
                "PPID": 1,
                "Exe_Path": "/usr/bin/curl",
                "Cmdline_Basename": "kworker",
                "Comm": "kworker",
                "Cmdline_Spoofed": True,
                "Comm_Spoofed": True,
                "Exe_Deleted": False,
            },
            {
                "PID": 43,
                "PPID": 1,
                "Exe_Path": "/usr/bin/ssh",
                "Cmdline_Basename": "ssh",
                "Comm": "ssh",
                "Cmdline_Spoofed": False,
                "Comm_Spoofed": False,
                "Exe_Deleted": False,
            },
        ],
        "linux.malware.process_spoofing",
    )
    stack = _json_rows(
        [
            {
                "TID": 44,
                "Comm": "worker",
                "Position": 0,
                "Address": "0xa000",
                "Value": "0xb000",
                "Name": "frame",
                "Type": "user",
                "Module": "libc.so",
            }
        ],
        "linux.pscallstack",
    )
    assert stack[0].pid is None and stack[0].tid == 44
    assert _kinds(analyze_injection((*linux_malfind, *mac_malfind, *spoof_rows))) == {
        "private-executable-region",
        "process-spoofing-detector",
    }
    assert analyze_injection(spoof_rows[1:]) == ()

    creds_check = _json_rows(
        [{"CredVAddr": "0xffff888000001000", "PIDs": "42, 43"}],
        "linux.malware.check_creds",
    )
    assert len(creds_check) == 1 and creds_check[0].address == 0xFFFF888000001000


def test_credential_artifact_syntax_checks_and_declines() -> None:
    hashdump = _json_rows(
        [
            {
                "User": "alice",
                "rid": 1001,
                "lmhash": "aad3b435b51404eeaad3b435b51404ee",
                "nthash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            }
        ],
        "windows.registry.hashdump",
    )
    cachedump = _json_rows(
        [
            {
                "Username": "bob",
                "Domain": "LAB",
                "Domain name": "lab.local",
                "Hash": "11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00",
            }
        ],
        "windows.registry.cachedump",
    )
    dcc2 = _json_rows(
        [
            {
                "Username": "carol",
                "Hash": "$DCC2$10240#carol#0123456789abcdef0123456789abcdef",
            }
        ],
        "windows.registry.cachedump",
    )
    lsa = _json_rows(
        [{"Key": "DPAPI_SYSTEM", "Secret": "01 23 45 67 89 ab cd ef"}],
        "windows.registry.lsadump",
    )
    artifacts = credential_artifacts((*hashdump, *cachedump, *dcc2, *lsa))
    assert {artifact.kind for artifact in artifacts} == {
        "ntlm",
        "cached-domain-verifier",
        "dcc2",
        "lsa-secret-bytes",
    }
    assert any(
        artifact.account == "alice" and artifact.verifier == "31d6cfe0d16ae931b73c59d7e0c089c0"
        for artifact in artifacts
    )

    short = _json_rows(
        [{"User": "mallory", "nthash": "1234", "lmhash": "5678"}],
        "windows.registry.hashdump",
    )
    mismatch = _json_rows(
        [
            {
                "Username": "alice",
                "Hash": "$DCC2$10240#mallory#0123456789abcdef0123456789abcdef",
            }
        ],
        "windows.registry.cachedump",
    )
    assert credential_artifacts((*short, *mismatch)) == ()
    assert credential_artifacts([object()]) == ()
    assert _json_rows([{"User": "alice", "rid": 1001}], "windows.registry.hashdump") == ()


def test_combined_analysis_dedupes_and_declines_forged_records() -> None:
    processes = _json_rows(
        [
            {"PID": 4, "PPID": 0, "Process": "System"},
            {"PID": 900, "PPID": 4, "Process": "dropper.exe"},
        ],
        "windows.pslist",
    )
    malfind = _json_rows(
        [
            {
                "PID": 900,
                "Process": "dropper.exe",
                "Start": "0x10000",
                "End": "0x10fff",
                "Protection": "PAGE_EXECUTE_READWRITE",
                "Hexdump": "4d 5a",
            }
        ],
        "windows.malware.malfind",
    )
    findings = analyze_memory((*processes, *malfind, *malfind))
    assert [finding.kind for finding in findings].count("private-executable-region") == 1
    assert analyze_memory(None) == ()
    assert analyze_memory([replace(malfind[0], os_family="linux")]) == ()
    assert analyze_memory([replace(malfind[0], fields=(("pid", "not-an-int"),))]) == ()


def test_every_public_analyzer_declines_wrong_types_and_broken_generators() -> None:
    record = _json_rows(
        [{"PID": 4, "PPID": 0, "Process": "System"}], "windows.pslist"
    )[0]
    analyzers = (
        analyze_process_crossview,
        analyze_handles,
        analyze_injection,
        credential_artifacts,
        analyze_memory,
    )

    class BrokenIterator:
        def __iter__(self):
            raise RuntimeError("iterator construction failed")

    def broken_generator():
        yield record
        raise RuntimeError("iteration failed after a valid record")

    for analyzer in analyzers:
        assert analyzer(123) == ()
        assert analyzer([record, object()]) == ()
        assert analyzer(BrokenIterator()) == ()
        assert analyzer(broken_generator()) == ()
