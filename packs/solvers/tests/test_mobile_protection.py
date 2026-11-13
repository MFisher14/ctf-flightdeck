from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import zipfile

import pytest

from solvers.toolkits import mobile_protection as protection


SMALI = """.class public Lcom/example/Security;
.super Ljava/lang/Object;

.method public isRooted()Z
    .locals 2
    new-instance v0, Ljava/io/File;
    const-string v1, "/system/xbin/su"
    invoke-direct {v0, v1}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    invoke-virtual {v0}, Ljava/io/File;->exists()Z
    move-result v0
    return v0
.end method

.method public checkEnvironment()Z
    .locals 1
    invoke-static {}, Landroid/os/Debug;->isDebuggerConnected()Z
    move-result v0
    return v0
.end method

.method public checkServerTrusted()V
    .locals 1
    new-instance v0, Ljavax/net/ssl/SSLPeerUnverifiedException;
    throw v0
.end method
"""


def test_smali_plans_are_deterministic_non_overlapping_and_semantic():
    first = protection.plan_smali_patches(SMALI, path="Security.smali")
    second = protection.plan_smali_patches(SMALI, path="Security.smali")
    assert first == second
    assert {finding["method"] for finding in first["findings"]} == {
        "isRooted", "checkEnvironment", "checkServerTrusted",
    }
    patches = {patch["method"]: patch for patch in first["patches"]}
    assert patches["isRooted"]["replacement"][-2:] == ["    const/4 v0, 0x0", "    return v0"]
    assert patches["checkEnvironment"]["kind"] == "force-call-result-false"
    assert patches["checkEnvironment"]["replacement"] == ["    const/4 v0, 0x0"]
    assert patches["checkServerTrusted"]["replacement"] == ["    .locals 0", "    return-void"]
    spans = [(item["start_line"], item["end_line"]) for item in first["patches"]]
    assert all(left[1] < right[0] for left, right in zip(spans, spans[1:]))


def test_guarded_smali_application_selection_diff_and_stale_rejection():
    plan = protection.plan_smali_patches(SMALI, path="Security.smali")
    selected = {next(item["id"] for item in plan["patches"] if item["method"] == "isRooted")}
    result = protection.apply_smali_plan(SMALI, plan, selected_ids=selected)
    assert result["applied_ids"] == sorted(selected)
    assert "const/4 v0, 0x0" in result["patched_text"]
    assert "checkEnvironment()Z" in result["patched_text"]
    assert "--- Security.smali" in result["diff"] and "+++ Security.smali" in result["diff"]
    with pytest.raises(protection.ProtectionError, match="hash"):
        protection.apply_smali_plan(result["patched_text"], plan)
    with pytest.raises(protection.ProtectionError, match="absent"):
        protection.apply_smali_plan(SMALI, plan, selected_ids={"not-a-patch"})

    tampered = copy.deepcopy(plan)
    tampered["patches"][0]["replacement"][-2] = "    const/4 v0, 0x1"
    with pytest.raises(protection.ProtectionError, match="patch id"):
        protection.apply_smali_plan(SMALI, tampered)

    multi = protection.apply_smali_files({"Security.smali": SMALI}, [plan])
    assert multi["files"]["Security.smali"].count("const/4 v0, 0x0") >= 2
    assert multi["reports"][0]["path"] == "Security.smali"
    with pytest.raises(protection.ProtectionError, match="absent"):
        protection.apply_smali_files({}, [plan])


def test_ambiguous_boolean_and_annotation_are_analysis_only():
    source = """.class La;
.method public check()Z
    .annotation runtime Lx;
    .end annotation
    const-string v0, "TracerPid"
    const/4 v0, 0x1
    return v0
.end method
"""
    plan = protection.plan_smali_patches(source)
    assert plan["findings"][0]["categories"] == ["debugger"]
    assert plan["patches"] == [] and plan["ambiguous_findings"]

    numeric = """.class La;
.method public rootRiskScore()I
    .locals 1
    const-string v0, "magisk"
    const/4 v0, 0x2
    return v0
.end method
"""
    numeric_plan = protection.plan_smali_patches(numeric)
    assert numeric_plan["findings"] and numeric_plan["patches"] == []

    negative = numeric.replace("rootRiskScore()I", "isNotRooted()Z").replace("const/4 v0, 0x2", "const/4 v0, 0x0")
    negative_plan = protection.plan_smali_patches(negative)
    assert negative_plan["patches"][0]["replacement"][-2] == "    const/4 v0, 0x1"


def test_proguard_mapping_descriptor_and_stacktrace_reversal():
    mapping_text = """com.example.Security -> a.b:
    1:10:boolean isRooted(java.lang.String):20:29 -> a
    java.lang.String token -> b
com.example.Main -> c:
    void run() -> a
"""
    mapping = protection.parse_proguard_mapping(mapping_text)
    assert mapping["class_count"] == 2 and mapping["member_count"] == 3
    assert protection.deobfuscate_descriptor("La/b;", mapping) == "Lcom/example/Security;"
    trace = "java.lang.RuntimeException\n\tat a.b.a(Security.java:3)\n\tat c.a(Main.java:1)"
    restored = protection.deobfuscate_stacktrace(trace, mapping)
    assert "com.example.Security.isRooted(" in restored
    assert "com.example.Main.run(" in restored


def test_allatori_mapping_and_explicit_string_transform_chain():
    xml = """<allatori><class old="com.example.Secret" new="x">
      <method old="decrypt" new="a"/><field old="token" new="b"/>
    </class></allatori>"""
    mapping = protection.parse_obfuscation_mapping(xml)
    assert mapping["format"] == "allatori" and mapping["member_count"] == 2
    assert protection.deobfuscate_descriptor("Lx;", mapping) == "Lcom/example/Secret;"

    plaintext = b"CSCTF{static_transform}"
    encrypted = bytes(byte ^ (0x31 + index) & 0xFF for index, byte in enumerate(plaintext))
    encoded = base64.b64encode(encrypted[::-1])
    result = protection.transform_string(encoded, [
        {"op": "base64"}, {"op": "reverse"}, {"op": "xor-index", "key": 0x31},
    ])
    assert result["bytes"] == plaintext and result["text"] == plaintext.decode()
    assert [item["operation"] for item in result["trace"]] == ["base64", "reverse", "xor-index"]
    assert result["trace"][0]["input_sha256"] == hashlib.sha256(encoded).hexdigest()

    allatori_plain = "CSCTF{alternating}"
    encrypted_text = protection.recover_alternating_xor(allatori_plain, 0x31, 0x72)
    assert protection.recover_alternating_xor(encrypted_text, 0x31, 0x72) == allatori_plain
    with pytest.raises(protection.ProtectionError):
        protection.transform_string(b"x", [{"op": "execute"}])


def test_obfuscation_metrics_sdk_detection_and_decrypt_sites():
    files = {}
    for index, name in enumerate(("a", "b", "c", "d")):
        files[f"{name}.smali"] = f""".class public Lcom/guardsquare/dexguard/{name};
.super Ljava/lang/Object;
.method public {name}()V
    .locals 1
    const-string v0, "cipher"
    invoke-static {{v0}}, Lx;->a(Ljava/lang/String;)Ljava/lang/String;
    invoke-static {{v0}}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    return-void
.end method
.method public z()V
    .locals 0
    return-void
.end method
"""
    report = protection.detect_obfuscation(files)
    assert report["likely_obfuscated"] is True
    assert report["families"] == [{"family": "dexguard", "paths": sorted(files)}]
    assert len(report["string_decrypt_calls"]) == 4 and len(report["reflection_sites"]) == 4
    first = report["string_decrypt_calls"][0]
    assert first["literal"] == "cipher" and first["target"] == "Lx;->a(Ljava/lang/String;)Ljava/lang/String;"


def test_rasp_static_evidence_manifest_native_and_patch_plans():
    manifest = """<manifest xmlns:android="http://schemas.android.com/apk/res/android">
      <application android:debuggable="true" android:networkSecurityConfig="@xml/network_security_config"/>
    </manifest>"""
    native = {"lib/arm64-v8a/libguard.so": b"normal\x00TracerPid\x00frida-gum\x00/system/xbin/su\x00"}
    report = protection.analyze_rasp({"Security.smali": SMALI}, manifest=manifest, native_files=native)
    kinds = {item["kind"] for item in report["findings"]}
    assert {"smali-protection", "manifest-debuggable", "manifest-network-security-config",
            "native-protection"} <= kinds
    assert report["manifest"]["debuggable"] == "true"
    evidence = report["native"][0]["evidence"]
    assert {item["category"] for item in evidence} == {"root", "debugger", "hooking"}
    assert report["plans"][0]["patches"]


def test_protection_bundle_mapping_and_cli(tmp_path, capsys):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("smali/com/example/Security.smali", SMALI)
        archive.writestr("AndroidManifest.xml", "<manifest><application/></manifest>")
        archive.writestr("mapping.txt", "com.example.Security -> a:\n    boolean isRooted() -> a\n")
        archive.writestr("lib/arm64-v8a/libguard.so", b"TracerPid\x00")
    report = protection.inspect_protection_bundle(stream.getvalue())
    assert report["member_count"] == 4
    assert report["mappings"][0]["report"]["class_count"] == 1
    assert report["plans"][0]["path"].endswith("Security.smali")

    path = tmp_path / "Security.smali"
    path.write_text(SMALI)
    assert protection.main([str(path), "--apply"]) == 0
    cli = json.loads(capsys.readouterr().out)
    assert len(cli["application"]["applied_ids"]) == 3


def test_malformed_mapping_bundle_smali_and_plan_fail_closed():
    with pytest.raises(protection.ProtectionError):
        protection.parse_allatori_mapping("<broken")
    with pytest.raises(protection.ProtectionError):
        protection.plan_smali_patches(".method public broken()V")
    with pytest.raises(protection.ProtectionError):
        protection.inspect_protection_bundle(b"not zip")

    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("../escape.smali", SMALI)
    with pytest.raises(protection.ProtectionError, match="unsafe"):
        protection.inspect_protection_bundle(stream.getvalue())


def test_smali_prefixes_never_raise_low_level_exceptions():
    for cut in range(len(SMALI) + 1):
        fragment = SMALI[:cut]
        try:
            protection.plan_smali_patches(fragment)
        except protection.ProtectionError:
            pass
