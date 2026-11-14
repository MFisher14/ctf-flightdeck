"""hashcrack: john-pipeline wrapper. Synthetic fixtures, no real cracking required.

The crack path (running john+zip2john against rockyou) is only exercised when those tools and a
rockyou wordlist are installed; otherwise we assert the emitted command plan is correct, which is the
helper's guaranteed-offline contract.
"""
import sys
import zipfile
import struct
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "solvers" / "toolkits"))
import hashcrack  # noqa: E402


def test_classify_zip(tmp_path):
    z = tmp_path / "secret.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("flag.txt", "CSCTF{nope}")
    assert hashcrack.classify(str(z)) == "zip"


def test_classify_shadow_and_passwd(tmp_path):
    shadow = tmp_path / "shadow"
    shadow.write_text(
        "root:$6$abcd$0123456789abcdef:19000:0:99999:7:::\n"
        "alice:$y$j9T$salt$hashhashhash:19000:0:99999:7:::\n"
    )
    passwd = tmp_path / "passwd"
    passwd.write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
    )
    assert hashcrack.classify(str(shadow)) == "shadow"
    assert hashcrack.classify(str(passwd)) == "passwd"


def test_classify_raw_hashes(tmp_path):
    h = tmp_path / "hashes.txt"
    h.write_text("5f4dcc3b5aa765d61d8327deb882cf99\n"
                 "6e6affcf3e6ad4d6e6a1234567890abcdef12345\n")
    assert hashcrack.classify(str(h)) == "hashes"


def test_plan_zip_emits_zip2john(tmp_path):
    z = tmp_path / "locked.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("a.txt", "x")
    p = hashcrack.plan([str(z)], rockyou="/usr/share/wordlists/rockyou.txt")
    assert p.kind == "archive"
    assert p.extractor == "zip2john"
    cmds = "\n".join(p.commands)
    assert "zip2john" in cmds
    assert "--wordlist=/usr/share/wordlists/rockyou.txt" in cmds
    assert "john --show" in cmds


def test_plan_shadow_pair_emits_unshadow(tmp_path):
    shadow = tmp_path / "shadow"
    shadow.write_text("bob:$6$s$h:19000:0:99999:7:::\n")
    passwd = tmp_path / "passwd"
    passwd.write_text("bob:x:1000:1000::/home/bob:/bin/sh\n")
    p = hashcrack.plan([str(passwd), str(shadow)], rockyou="/wl/rockyou.txt")
    assert p.kind == "shadow"
    assert p.unshadow is True
    assert p.commands[0].startswith("unshadow ")
    assert "longest" in " ".join(p.notes).lower()


def test_parse_show_archive_form():
    out = "locked.zip:school13\n\n1 password hash cracked, 0 left\n"
    cracked = hashcrack.parse_show(out)
    assert ("locked.zip", "school13") in cracked


def test_parse_show_unshadow_form_and_longest():
    out = (
        "alice:password1:1000:1000::/home/alice:/bin/bash\n"
        "bob:manchesterunited:1001:1001::/home/bob:/bin/bash\n"
        "carol:qwerty:1002:1002::/home/carol:/bin/bash\n"
    )
    cracked = hashcrack.parse_show(out)
    pws = {pw for _, pw in cracked}
    assert pws == {"password1", "manchesterunited", "qwerty"}
    assert hashcrack.longest(cracked) == "manchesterunited"


def test_parse_pot():
    pot = "$zip2john$...:school13\n$6$abc$def:hunter2\n"
    pairs = hashcrack.parse_pot(pot)
    assert ("$6$abc$def", "hunter2") in pairs
    assert pairs[0][1] == "school13"


def test_crack_plan_only_does_not_run(tmp_path):
    z = tmp_path / "x.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("a", "b")
    res = hashcrack.crack([str(z)], run=False)
    assert res.ran is False
    assert res.plan.kind == "archive"


def test_quoting_paths_with_spaces(tmp_path):
    z = tmp_path / "my archive.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("a", "b")
    p = hashcrack.plan([str(z)])
    # a path with a space must be quoted in the emitted command
    assert "'" in p.commands[0]


def test_real_crack_if_tools_present(tmp_path):
    """End-to-end only when john + zip2john + rockyou are installed. Cracks a zip whose password is a
    common rockyou word. Skipped (not failed) when the toolchain is absent."""
    john = hashcrack.find_tool("john")
    z2j = hashcrack.find_tool("zip2john")
    rock = hashcrack.find_rockyou()
    if not (john and z2j and rock):
        import pytest
        pytest.skip("john/zip2john/rockyou not all installed")
    # 'password' is in rockyou; build a real encrypted zip with the stdlib (ZipCrypto)
    z = tmp_path / "pw.zip"
    _make_encrypted_zip(z, b"CSCTF{x}", "password")
    res = hashcrack.crack([str(z)], run=True, timeout=60)
    assert res.ran is True
    assert any(pw == "password" for _, pw in res.cracked)


def _make_encrypted_zip(path, content, password):
    # Minimal traditional-ZipCrypto encrypted zip (stdlib zipfile cannot encrypt, so shell out to the
    # `zip` tool if available; otherwise skip the real-crack test by raising).
    import shutil
    import subprocess
    zc = shutil.which("zip")
    if not zc:
        import pytest
        pytest.skip("`zip` CLI not available to build an encrypted fixture")
    src = Path(path).parent / "flag.txt"
    src.write_bytes(content)
    subprocess.run([zc, "-P", password, "-j", str(path), str(src)], check=True,
                   capture_output=True)
