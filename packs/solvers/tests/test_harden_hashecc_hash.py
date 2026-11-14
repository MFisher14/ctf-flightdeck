"""Independent hash-format locks and bounded offline fuzz; no engine changes.

Oracles: hashlib/bcrypt; Hashcat's published example_hashes table (modes
500/1600/3200/5500/5600/19700); PKWARE APPNOTE, RAR technote, 7-Zip
7zFormat.txt signatures; Openwall John EXAMPLES and literal colon records.
https://hashcat.net/wiki/doku.php?id=example_hashes
https://www.openwall.com/john/doc/EXAMPLES.shtml
https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
https://www.rarlab.com/technote.htm
https://www.7-zip.org/recover.html

Neither hash module declares an exception type. Their fail-closed contract is
therefore clean return; discovered standard-library leaks are isolated xfails.
All subprocess boundaries are disabled unless explicitly replaced by a stub.
"""
import base64
import hashlib
import io
import json
import random
import shlex
import subprocess
import zipfile
from pathlib import Path
from types import SimpleNamespace

import bcrypt
import pytest

import hash_identify as hi
import hashcrack as hc

REAL_WHICH = hc.shutil.which


NETNTLM1 = (
    "u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:"
    "9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c"
)
NETNTLM2 = (
    "admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:"
    "5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e00000000"
    "52920b85f78d013c31cdb3b92f5d765c783030"
)
AES_TGS = (
    "$krb5tgs$18$user$realm$8efd91bb01cc69dd07e46009$"
    "7352410d6aafd72c64972a66058b02aa1c28ac580ba41137d5a170467f06f17faf"
    "5dfb3f95ecf4fad74821fdc7e63a3195573f45f962f86942cb24255e544ad8d051"
    "78d560f683a3f59ce94e82c8e724a3af0160be549b472dd83e6b80733ad349973"
    "885e9082617294c6cbbea92349671883eaf068d7f5dcfc0405d97fda27435082b"
    "82b24f3be27f06c19354bf32066933312c770424eb6143674756243c1bde78ee32"
    "94792dcc49008a1b54f32ec5d5695f899946d42a67ce2fb1c227cb1d2004c0"
)


@pytest.fixture(autouse=True)
def offline_environment(monkeypatch):
    """Prevent actual process execution and host-dependent tool discovery."""
    def forbidden(*args, **kwargs):
        pytest.fail("test attempted real subprocess execution")
    monkeypatch.setattr(hc.subprocess, "run", forbidden)
    monkeypatch.setattr(hc.shutil, "which", lambda name: None)
    monkeypatch.setattr(hc, "JOHN_SHARE_DIRS", [])
    monkeypatch.setattr(hc, "ROCKYOU_CANDIDATES", [])
    monkeypatch.delenv("ROCKYOU", raising=False)
    monkeypatch.delenv("WORDLIST", raising=False)


@pytest.mark.parametrize("algorithm,name,mode", [
    ("md5", "MD5", 0), ("sha1", "SHA-1", 100), ("sha224", "SHA-224", 1300),
    ("sha256", "SHA-256", 1400), ("sha384", "SHA-384", 10800),
    ("sha512", "SHA-512", 1700),
])
def test_hashlib_digest_identity(algorithm, name, mode):
    digest = hashlib.new(algorithm, b"CSCTF{independent_vector}").hexdigest()
    for text in (digest, digest.upper(), digest.encode("ascii")):
        result = hi.identify(text)
        assert any(row["name"] == name and row["hashcat_mode"] == mode for row in result)


@pytest.mark.parametrize("algorithm,name", [
    ("md5", "raw MD5/MD4/NTLM"), ("sha1", "raw SHA-1/RIPEMD-160"),
    ("sha224", "raw SHA-224"), ("sha256", "raw SHA-256/BLAKE2s"),
    ("sha384", "raw SHA-384"), ("sha512", "raw SHA-512/BLAKE2b"),
])
def test_base64_raw_digest_vectors(algorithm, name):
    raw = hashlib.new(algorithm, b"hashcat").digest()
    value = base64.b64encode(raw).decode("ascii")
    assert hi.identify(value)[0]["name"] == "base64-encoded " + name


@pytest.mark.parametrize("value,name,mode", [
    ("$1$ehAsHC4t$4IbK3fHS/H1YGtNYBrIEB1", "md5crypt", 500),
    ("$apr1$71850310$gh9m4xcAn3MGxogwX/ztb.", "Apache apr1 / md5apr1", 1600),
    ("$P$9d2OMJEOHyPg11MeSv46hashcatG.F1", "phpass (WordPress/phpBB)", 400),
    ("$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f", "Domain Cached Credentials 2 (mscash2)", 2100),
])
def test_hashcat_published_format_examples(value, name, mode):
    first = hi.identify(value)[0]
    assert (first["name"], first["hashcat_mode"], first["confidence"]) == (name, mode, "high")


def test_bcrypt_real_library_oracle():
    value = bcrypt.hashpw(b"CSCTF{synthetic}", b"$2b$04$abcdefghijklmnopqrstuu")
    assert bcrypt.checkpw(b"CSCTF{synthetic}", value)
    assert hi.identify(value)[0]["hashcat_mode"] == 3200


def test_ldap_sha_and_mysql_real_digest_constructions():
    digest = hashlib.sha1(b"hashcat").digest()
    ldap = "{SHA}" + base64.b64encode(digest).decode("ascii")
    mysql = "*" + hashlib.sha1(digest).hexdigest().upper()
    assert hi.identify(ldap)[0]["hashcat_mode"] == 101
    assert hi.identify(mysql)[0]["hashcat_mode"] == 300


def test_published_netntlm1_mode():
    assert hi.identify(NETNTLM1)[0]["hashcat_mode"] == 5500


def test_published_netntlm2_mode():
    assert hi.identify(NETNTLM2)[0]["hashcat_mode"] == 5600


def test_published_aes_tgs_mode():
    assert hi.identify(AES_TGS)[0]["hashcat_mode"] == 19700


def test_identify_empty_random_malformed_contract():
    rng = random.Random(0x48415348)
    corpus = [None, 17, [], {}, b"\xff", "", "\x00", "x" * 4097, "$", "$2b$", "==="]
    corpus += [rng.randbytes(n) for n in range(128)]
    corpus += [rng.randbytes(n).decode("latin1") for n in range(128)]
    for value in corpus:
        result = hi.identify(value)
        assert isinstance(result, list)
        assert len(result) <= 12


def test_identify_bad_top_contract():
    hi.identify(hashlib.md5(b"x").hexdigest(), top="2")


def test_identify_cli_vector_and_malformed(capsys, monkeypatch):
    digest = hashlib.sha256(b"CSCTF{cli}").hexdigest()
    assert hi.main([digest, "--json"]) == 0
    assert any(row["hashcat_mode"] == 1400 for row in json.loads(capsys.readouterr().out))
    monkeypatch.setattr(hi.sys, "stdin", io.StringIO(digest + "\n"))
    assert hi.main(["-"]) == 0
    assert "SHA-256" in capsys.readouterr().out
    assert hi.main([]) == 2
    assert hi.main(["--unexpected"]) == 2
    assert hi.main(["--help"]) == 0


def test_identify_cli_noninteger_exit(monkeypatch):
    def stop(*args, **kwargs):
        raise SystemExit("bad input")
    monkeypatch.setattr(hi.argparse.ArgumentParser, "parse_args", stop)
    assert hi.main([]) == 2


@pytest.fixture
def artifacts(tmp_path):
    files = {}
    for kind, payload in {
        "rar": bytes.fromhex("526172211A070100"),
        "7z": bytes.fromhex("377ABCAF271C0004"),
        "shadow": b"alice:$6$salt$opaque:19000:0:99999:7:::\n",
        "passwd": b"alice:x:1000:1000:Alice:/home/alice:/bin/sh\n",
        "hashes": (hashlib.sha256(b"CSCTF{fixture}").hexdigest() + "\n").encode(),
        "unknown": b"not a password database!\n",
    }.items():
        path = tmp_path / (kind + ".dat")
        path.write_bytes(payload)
        files[kind] = str(path)
    path = tmp_path / "zip.dat"
    with zipfile.ZipFile(path, "w") as archive:
        item = zipfile.ZipInfo("flag.txt", date_time=(2020, 1, 1, 0, 0, 0))
        archive.writestr(item, b"CSCTF{synthetic}")
    files["zip"] = str(path)
    return files


@pytest.mark.parametrize("kind", ["zip", "rar", "7z", "shadow", "passwd", "hashes", "unknown"])
def test_classify_independent_signatures_and_record_grammars(artifacts, kind):
    assert hc.classify(artifacts[kind]) == kind


def test_tool_discovery_and_wordlist_priority(tmp_path, monkeypatch):
    assert hc.find_tool("john") is None
    monkeypatch.setattr(hc.shutil, "which", lambda name: "/fixture/bin/john" if name == "john" else None)
    assert hc.find_tool("john") == "/fixture/bin/john"
    helper = tmp_path / "7z2john.pl"
    helper.write_text("# synthetic nonexecuted helper\n")
    monkeypatch.setattr(hc, "JOHN_SHARE_DIRS", [str(tmp_path)])
    assert hc.find_tool("7z2john.pl") == str(helper)
    first, second = tmp_path / "first.txt", tmp_path / "second.txt"
    first.write_text("synthetic\n")
    second.write_text("synthetic\n")
    monkeypatch.setenv("ROCKYOU", str(first))
    monkeypatch.setenv("WORDLIST", str(second))
    assert hc.find_rockyou() == str(first)
    monkeypatch.delenv("ROCKYOU")
    assert hc.find_rockyou() == str(second)
    monkeypatch.delenv("WORDLIST")
    monkeypatch.setattr(hc, "ROCKYOU_CANDIDATES", [str(first)])
    assert hc.find_rockyou() == str(first)


def test_find_tool_malformed_contract(monkeypatch):
    monkeypatch.setattr(hc.shutil, "which", REAL_WHICH)
    monkeypatch.setenv("PATH", "")
    hc.find_tool(None)


@pytest.mark.parametrize("kind,tool", [("zip", "zip2john"), ("rar", "rar2john"), ("7z", "7z2john.pl")])
def test_plan_archive_vector(artifacts, kind, tool):
    result = hc.plan([artifacts[kind]], rockyou="/fixture/words.txt")
    prefix = ["perl"] if kind == "7z" else []
    assert shlex.split(result.commands[0]) == prefix + [tool, artifacts[kind], ">", "hashes.john"]
    assert result.commands[1:] == ["john --wordlist=/fixture/words.txt hashes.john", "john --show hashes.john"]
    assert result.extractor == tool
    assert hc.paths_of(result, {kind: tool}) == artifacts[kind]
    assert hc.paths_of(result, {}) == ""
    assert "hashcrack plan: archive" in result.render()


def test_plan_shadow_hashes_unknown_and_dataclasses(artifacts):
    result = hc.plan([artifacts["passwd"], artifacts["shadow"]], rockyou="/fixture/words.txt")
    assert shlex.split(result.commands[0]) == ["unshadow", artifacts["passwd"], artifacts["shadow"], ">", "hashes.john"]
    assert result.unshadow is True
    single = hc.plan([artifacts["shadow"]], rockyou="/fixture/words.txt")
    assert shlex.split(single.commands[0]) == ["cp", artifacts["shadow"], "hashes.john"]
    raw = hc.plan([artifacts["hashes"]], rockyou="/fixture/words.txt")
    assert shlex.split(raw.commands[0]) == ["john", "--wordlist=/fixture/words.txt", artifacts["hashes"]]
    assert hc.plan([artifacts["unknown"]]).kind == "unknown"
    assert hc.Plan("unknown", [], None).render() == "hashcrack plan: unknown\n  commands:"
    wrapped = hc.Result(raw, False)
    assert (wrapped.ran, wrapped.cracked, wrapped.pot, wrapped.log, wrapped.missing) == (False, [], "", [], [])


def test_plan_quotes_output_hashfile(artifacts):
    result = hc.plan([artifacts["zip"]], rockyou="/fixture/words.txt", hashfile="my hashes.john")
    assert shlex.split(result.commands[0])[-1] == "my hashes.john"


def test_john_output_vectors():
    # Independently authored records follow Openwall's passwd/show grammar.
    shown = "archive.zip: CSCTF{spaces} \nalice:short:1000:1000::/home/alice:/bin/sh\n\n2 password hashes cracked, 0 left\n"
    expected = [("archive.zip", " CSCTF{spaces} "), ("alice", "short")]
    assert hc.parse_show(shown) == expected
    assert hc.longest(expected) == " CSCTF{spaces} "
    assert hc.longest([]) is None
    assert hc.parse_pot("$1$salt$opaque:CSCTF{colon:kept}\n$6$salt$opaque: leading trailing \n") == [
        ("$1$salt$opaque", "CSCTF{colon:kept}"), ("$6$salt$opaque", " leading trailing ")]


def test_show_password_content_is_not_summary():
    assert hc.parse_show("archive.zip:CSCTF{password hash}\n") == [("archive.zip", "CSCTF{password hash}")]


def test_show_empty_password():
    assert hc.parse_show("alice::1000:1000::/home/alice:/bin/sh\n") == [("alice", "")]


def test_plan_only_crack_report_and_cli(artifacts, capsys):
    result = hc.crack([artifacts["hashes"]], run=False)
    assert result.ran is False
    assert result.plan.kind == "hashes"
    assert result.missing == ["(run=False: plan only)"]
    unavailable = hc.crack([artifacts["zip"]], run=True)
    assert unavailable.ran is False
    assert set(unavailable.missing) == {"john", "rockyou.txt", "zip2john"}
    text = hc.report([artifacts["hashes"]])
    assert "hashcrack plan: hashes" in text and "plan only" in text
    assert hc.main([artifacts["hashes"]]) == 0
    assert "hashcrack plan: hashes" in capsys.readouterr().out
    assert hc.main([]) == 2
    assert hc.main(["--help"]) == 2
    assert hc.main([artifacts["hashes"] + ".absent"]) == 1


def test_crack_orchestration_uses_stubbed_processes(artifacts, monkeypatch):
    """Test wrapper only: both 'john' invocations are in-memory stubs."""
    calls = []
    monkeypatch.setattr(hc, "find_tool", lambda name: "/fixture/" + name)
    def run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(stdout="alice:CSCTF{stub}\n" if "--show" in argv else b"", returncode=0)
    monkeypatch.setattr(hc.subprocess, "run", run)
    result = hc.crack([artifacts["hashes"]], run=True, rockyou="/fixture/words.txt")
    assert result.ran is True
    assert result.cracked == [("alice", "CSCTF{stub}")]
    assert len(calls) == 2
    assert "--wordlist=/fixture/words.txt" in calls[0]
    assert "--show" in calls[1]


def test_crack_show_failure_contract(artifacts, monkeypatch):
    monkeypatch.setattr(hc, "find_tool", lambda name: "/fixture/" + name)
    def run(argv, **kwargs):
        if "--show" in argv:
            raise OSError("synthetic show failure")
        return SimpleNamespace(stdout=b"", returncode=0)
    monkeypatch.setattr(hc.subprocess, "run", run)
    hc.crack([artifacts["hashes"]], run=True, rockyou="/fixture/words.txt")


def test_hash_helpers_seeded_text_and_file_fuzz(tmp_path):
    rng = random.Random(0x43544346)
    target = tmp_path / "fuzz.bin"
    corpus = [b"", b"\x00", b"\xff", b":::", b"root:!::::::", b"$6$incomplete"]
    corpus += [rng.randbytes(size) for size in range(100)]
    for payload in corpus:
        target.write_bytes(payload)
        result = hc.classify(str(target))
        assert result in {"zip", "rar", "7z", "shadow", "passwd", "hashes", "unknown"}
        text = payload.decode("latin1")
        pairs = hc.parse_show(text)
        assert isinstance(pairs, list)
        assert isinstance(hc.parse_pot(text), list)
        assert hc.longest(pairs) is None or isinstance(hc.longest(pairs), str)
        assert hc.crack([str(target)], run=False).ran is False
        assert isinstance(hc.report([str(target)]), str)
    assert hc.classify(str(tmp_path / "missing")) == "unknown"
    assert hc.plan([]).kind == "unknown"
    assert hc.crack([], run=False).ran is False
    assert isinstance(hc.report([]), str)


@pytest.mark.parametrize("function,args", [
    pytest.param("classify", (None,), id="classify-none"),
    pytest.param("classify", ("\x00",), id="classify-nul"),
    pytest.param("plan", (None,), id="plan-none"),
    pytest.param("parse_show", (None,), id="show-none"),
    pytest.param("parse_pot", (None,), id="pot-none"),
    pytest.param("longest", ([1],), id="longest-bad-row"),
    pytest.param("crack", (None,), id="crack-none"),
    pytest.param("paths_of", (None, {}), id="paths-none"),
    pytest.param("report", (None,), id="report-none"),
    pytest.param("main", (None,), id="main-none"),
])
def test_hashcrack_malformed_public_input_contract(function, args):
    getattr(hc, function)(*args)

