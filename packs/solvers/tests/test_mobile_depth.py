"""Synthetic, offline tests for mobile payload planning and package triage."""
from __future__ import annotations

import io
import json
import plistlib
import sys
import zipfile
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "mobile-android"))
import mobile_depth as mobile  # noqa: E402


def _zip(members: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, body in members.items():
            archive.writestr(name, body)
    return stream.getvalue()


def test_exported_deep_link_and_component_payloads_are_ranked_not_sent():
    manifest = {
        "package": "ro.chronos.ctf",
        "components": [
            {"kind": "activity", "name": ".DeepLinkActivity", "exported": True,
             "permission": None, "filters": [{"actions": ["android.intent.action.VIEW"],
                                                "data": [{"scheme": "csctf", "host": "open",
                                                          "pathPrefix": "/admin"}]}]},
            {"kind": "receiver", "name": ".TokenReceiver", "exported": True,
             "filters": [{"actions": ["ro.chronos.DUMP"]}]},
            {"kind": "service", "name": ".Private", "exported": False, "filters": []},
        ],
    }
    got = mobile.build_exploit_intents(manifest, {"role": "admin", "debug": True})
    assert [item["kind"] for item in got] == ["deep-link", "broadcast-intent"]
    assert "csctf://open/admin" in got[0]["value"]
    assert "--es role admin" in got[0]["value"]
    assert "--ez debug true" in got[0]["value"]
    assert all("Private" not in item["value"] for item in got)


def test_smali_suggestions_are_method_local_and_do_not_modify_source():
    source = """
.class public Lcom/ctf/Checks;
.method public isRooted()Z
    .locals 1
    const-string v0, "/system/xbin/su"
    return v0
.end method
.method public checkServerTrusted()V
    .locals 1
    const-string v0, "CertificatePinner"
    return-void
.end method
"""
    before = source
    got = mobile.suggest_smali_patches(source)
    assert source == before
    assert [item["category"] for item in got] == ["tls-pinning", "root-check"]
    assert "return-void" in got[0]["value"]
    assert "const/4 v0, 0x0" in got[1]["value"]


def test_flutter_react_native_bundle_inventory_and_string_leads():
    blob = _zip({
        "assets/index.android.bundle": b"const endpoint='https://ctf.invalid/api'; const token='secret-token';",
        "lib/arm64-v8a/libapp.so": b"\x7fELF\x00CSCTF{synthetic_mobile_fixture}\x00",
        "assets/flutter_assets/AssetManifest.json": b"{}",
        "assets/config.json": b"{}",
    })
    result = mobile.extract_crossplatform(blob)
    assert result["frameworks"] == ["react-native", "flutter"]
    assert "assets/config.json" in result["assets"]
    assert any("CSCTF{synthetic_mobile_fixture}" in item["value"]
               for item in result["candidates"])


def test_android_and_ios_frida_generators_only_return_source():
    android = mobile.generate_frida_script({
        "platform": "android",
        "hooks": [{"class": "com.ctf.Checks", "method": "isAdmin", "return": True}],
    })
    assert "Java.perform" in android
    assert "com.ctf.Checks" in android
    assert "return true;" in android

    ios = mobile.generate_frida_script({
        "platform": "ios",
        "hooks": [{"class": "CTFChecker", "selector": "- verifyToken:"}],
    })
    assert "Interceptor.attach" in ios
    assert "CTFChecker" in ios


def test_ipa_plist_entitlements_and_binary_leads():
    info = {
        "CFBundleIdentifier": "ro.chronos.ios",
        "CFBundleDisplayName": "Chronos",
        "CFBundleExecutable": "Chronos",
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["csctf", "chronos"]}],
        "LSApplicationQueriesSchemes": ["otherapp"],
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
        "NSCameraUsageDescription": "scan codes",
    }
    entitlements = {"application-identifier": "TEAM.ro.chronos.ios",
                    "keychain-access-groups": ["TEAM.shared"]}
    ipa = _zip({
        "Payload/Chronos.app/Info.plist": plistlib.dumps(info),
        "Payload/Chronos.app/archived-entitlements.plist": plistlib.dumps(entitlements),
        "Payload/Chronos.app/Chronos": b"\xcf\xfa\xed\xfe\x00https://api.invalid/secret\x00",
    })
    result = mobile.triage_ipa(ipa)
    assert result["bundle_id"] == "ro.chronos.ios"
    assert result["url_schemes"] == ["csctf", "chronos"]
    assert result["ats"]["NSAllowsArbitraryLoads"] is True
    assert result["entitlements"][0]["values"]["keychain-access-groups"] == ["TEAM.shared"]
    assert any("https://api.invalid/secret" in item["value"] for item in result["candidates"])


def test_guarded_cli_manifest_json_and_garbage(tmp_path, capsys):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"package": "ctf.app", "components": []}), encoding="utf-8")
    assert mobile.main(["--json", "intent", str(manifest)]) == 0
    assert json.loads(capsys.readouterr().out) == {"candidates": []}
    assert mobile.main(["intent", str(manifest), "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"candidates": []}

    garbage = tmp_path / "bad.ipa"
    garbage.write_bytes(b"not a zip")
    assert mobile.main(["ios", str(garbage)]) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("mobile_depth: ")
    assert "Traceback" not in captured.err

