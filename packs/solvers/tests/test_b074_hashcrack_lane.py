"""B-074: the hashcrack lane extensions -- hash-type disambiguation, the configured wordlist, and the
7z/rar/zip retry through archive_expand. Synthetic fixtures; the real john crack stays in
test_hashcrack.py. The 7z/rar retry needs 7-Zip and is marked so; the zip retry is pure-python.
"""
from pathlib import Path

import pytest

import hashcrack as hc


# ---- hash-type disambiguation: raw-MD5 vs NTLM (verify both) --------------------------------------

def test_md4_known_vectors():
    assert hc.md4(b"").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert hc.md4(b"abc").hex() == "a448017aaf21d8525fc10ae87aa6729d"


def test_ntlm_and_raw_md5_of_password():
    assert hc.ntlm("password") == "8846f7eaee8fb117ad06bdd830b7586c"   # the canonical NT hash
    assert hc.raw_md5("password") == "5f4dcc3b5aa765d61d8327deb882cf99"


def test_disambiguate_tells_the_two_32hex_formats_apart():
    md5_hash = hc.raw_md5("letmein")
    ntlm_hash = hc.ntlm("letmein")
    assert md5_hash != ntlm_hash                         # same length, different value
    assert hc.disambiguate(md5_hash, "letmein") == ["raw-md5"]
    assert hc.disambiguate(ntlm_hash, "letmein") == ["ntlm"]
    assert hc.disambiguate(md5_hash, "wrong") == []
    assert hc.disambiguate("not-a-hash", "letmein") == []


def test_verify_tags_a_harvested_plaintext_with_its_format():
    target = hc.ntlm("Octopus2024")
    assert hc.verify(target, ["nope", "Octopus2024", 123]) == [("Octopus2024", "ntlm")]


# ---- the configured wordlist, failing loudly -----------------------------------------------------

def _clear_wordlist_env(monkeypatch):
    # Clear the canonical names and the legacy spellings ctf.env still resolves, without naming the
    # legacy literals here (single-source rule: only ctf/env.py may spell HUNTRESS_*/CSCTF_*).
    for v in ("CTF_WORDLIST", "ROCKYOU", "WORDLIST", *hc.ctf_env.legacy_names("CTF_WORDLIST")):
        monkeypatch.delenv(v, raising=False)


def test_wordlist_missing_raises_with_a_named_reason(monkeypatch):
    _clear_wordlist_env(monkeypatch)
    monkeypatch.setattr(hc, "find_rockyou", lambda: None)
    with pytest.raises(hc.WordlistMissing) as e:
        hc.wordlist()
    assert "CTF_WORDLIST" in str(e.value)


def test_wordlist_uses_configured_path_outside_the_repo(monkeypatch, tmp_path):
    _clear_wordlist_env(monkeypatch)
    monkeypatch.setattr(hc.ctf_paths, "repo_root", lambda: tmp_path / "repo")
    wl = tmp_path / "rockyou.txt"
    wl.write_text("password\n123456\n")
    monkeypatch.setenv("CTF_WORDLIST", str(wl))
    assert hc.wordlist() == str(wl.resolve())


def test_wordlist_inside_the_repo_is_refused(monkeypatch, tmp_path):
    _clear_wordlist_env(monkeypatch)
    repo = tmp_path / "repo"
    (repo / "wordlists").mkdir(parents=True)
    wl = repo / "wordlists" / "rockyou.txt"
    wl.write_text("password\n")
    monkeypatch.setattr(hc.ctf_paths, "repo_root", lambda: repo)
    monkeypatch.setenv("CTF_WORDLIST", str(wl))
    with pytest.raises(hc.WordlistMissing) as e:
        hc.wordlist()
    assert "inside the repo" in str(e.value)


def test_wordlist_configured_but_absent_file_raises(monkeypatch, tmp_path):
    _clear_wordlist_env(monkeypatch)
    monkeypatch.setenv("CTF_WORDLIST", str(tmp_path / "does-not-exist.txt"))
    with pytest.raises(hc.WordlistMissing):
        hc.wordlist()


def test_find_rockyou_consults_ctf_wordlist(monkeypatch, tmp_path):
    _clear_wordlist_env(monkeypatch)
    wl = tmp_path / "wl.txt"
    wl.write_text("a\n")
    monkeypatch.setenv("CTF_WORDLIST", str(wl))
    assert hc.find_rockyou() == str(wl)


def test_find_rockyou_refuses_a_ctf_wordlist_inside_the_repo(monkeypatch, tmp_path):
    # The run path (plan()/crack()) goes through find_rockyou(); it must honor the outside-repo rule
    # that wordlist() enforces, so an in-repo CTF_WORDLIST is not returned here either. With no other
    # source configured it falls through to None rather than picking the committed-corpus path.
    _clear_wordlist_env(monkeypatch)
    monkeypatch.setattr(hc, "ROCKYOU_CANDIDATES", [])
    repo = tmp_path / "repo"
    (repo / "wordlists").mkdir(parents=True)
    wl = repo / "wordlists" / "rockyou.txt"
    wl.write_text("password\n")
    monkeypatch.setattr(hc.ctf_paths, "repo_root", lambda: repo)
    monkeypatch.setenv("CTF_WORDLIST", str(wl))
    assert hc.find_rockyou() is None


# ---- the zip/7z/rar retry through archive_expand -------------------------------------------------

def _aes_zip(path, password, member="flag.txt", content=b"CSCTF{inside}"):
    pyzipper = pytest.importorskip("pyzipper")
    with pyzipper.AESZipFile(str(path), "w", encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode("utf-8"))
        zf.writestr(member, content)


def test_retry_archive_recovers_a_zip_password_from_candidates(tmp_path):
    z = tmp_path / "locked.zip"
    _aes_zip(z, "Octopus2024")
    assert hc.retry_archive(str(z), candidates=["nope", "Octopus2024"]) == "Octopus2024"
    assert hc.retry_archive(str(z), candidates=["nope", "wrong"]) is None


def test_retry_archive_uses_the_harvested_store_when_no_candidates_given(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    import archive_passwords as ap
    ap.add("Octopus2024", source="harvest")
    z = tmp_path / "locked.zip"
    _aes_zip(z, "Octopus2024")
    assert hc.retry_archive(str(z)) == "Octopus2024"


def test_crack_falls_back_to_archive_retry_when_john_is_unavailable(monkeypatch, tmp_path):
    # john/extractor absent: crack() must still recover a password that a sibling note reveals.
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    monkeypatch.setattr(hc, "find_tool", lambda name: None)           # force the no-john path
    monkeypatch.setattr(hc, "find_rockyou", lambda: None)
    z = tmp_path / "handout.zip"
    _aes_zip(z, "Octopus2024")
    (tmp_path / "note.txt").write_text("the archive password is Octopus2024\n")
    res = hc.crack([str(z)], run=True)
    assert res.ran is True
    assert any(pw == "Octopus2024" for _, pw in res.cracked)


def test_manifest_declares_the_john_tools():
    import tomllib
    man = Path(__file__).resolve().parent.parent / "solvers" / "toolkits" / "hashcrack.manifest.toml"
    needs = tomllib.loads(man.read_text())["needs_tools"]
    for tool in ("john", "zip2john", "rar2john", "7z2john.pl", "unshadow"):
        assert tool in needs, f"{tool} not declared in needs_tools"
