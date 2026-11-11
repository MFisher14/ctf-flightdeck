"""The script importer: generated manifests for a folder of synthetic scripts, the scripts
never touched, re-runs idempotent, and every script left out listed with its reason."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ctf_flightdeck.l1.importer import NO_MAIN, NOT_EXECUTABLE, ImporterError, ImportReport, import_scripts, keywords_of
from ctf_flightdeck.l1.manifest import Entry, Route, discover, load
from ctf_flightdeck.l1.router import route
from ctf_flightdeck.l1.runner import run_engine

from l1_kit import FLAG, challenge, challenge_dir, run, tree, write_manifest

GEN = Path(".flightdeck") / "generated"


def script(folder: Path, rel: str, text: str, mode: int = 0o644) -> Path:
    path = folder / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)
    return path


MAIN = 'import sys\n\nif __name__ == "__main__":\n    print(open(sys.argv[1] + "/note.txt").read())\n'


@pytest.fixture
def scripts(tmp_path: Path) -> Path:
    s = tmp_path / "scripts"
    script(s, "crypto/solve_rsa-small.e.py", MAIN)
    script(s, "Forensics/carve_png.py", "if __name__=='__main__':\n    print('t{carved}')\n")
    script(s, "web/sqli-dump.sh", "#!/bin/sh\necho t{dumped}\n", 0o755)
    script(s, "reversing/xor_brute", "#!/usr/bin/env python3\nprint('t{xored}')\n", 0o700)
    script(s, "misc/helpers.py", "def helper():\n    return 1\n")  # a module, not a script
    script(s, "misc/notes.sh", "#!/bin/sh\necho not executable\n", 0o644)  # no executable bit
    script(s, "misc/data.bin", "\x7fELF not a script\n", 0o755)  # executable, but no #!
    script(s, "tools/solve.py", MAIN)  # no category, and "solve" is not a keyword
    script(s, "tools/exploit_main.sh", "#!/bin/sh\necho x\n", 0o755)  # neither
    script(s, "tools/zip_cracker.py", MAIN)  # a keyword but no category
    script(s, ".hidden/rsa.py", MAIN)
    script(s, "pwn/.dot_rsa.py", MAIN)
    return s


def test_every_script_gets_a_generated_manifest_and_the_rest_are_listed_with_a_reason(scripts):
    report = import_scripts(scripts)
    gen = scripts / GEN
    assert report.written == sorted([
        gen / "Forensics/carve_png.py.manifest.toml",
        gen / "crypto/solve_rsa-small.e.py.manifest.toml",
        gen / "reversing/xor_brute.manifest.toml",
        gen / "tools/zip_cracker.py.manifest.toml",
        gen / "web/sqli-dump.sh.manifest.toml",
    ])
    skipped = {path.relative_to(scripts).as_posix(): why for path, why in report.skipped}
    assert set(skipped) == {"tools/solve.py", "tools/exploit_main.sh", "misc/helpers.py", "misc/notes.sh"}
    for rel in ("tools/solve.py", "tools/exploit_main.sh"):
        assert "no category from its folder name and no keyword from its file name" in skipped[rel]
    assert skipped["misc/helpers.py"] == NO_MAIN and "write a manifest for it" in NO_MAIN
    assert skipped["misc/notes.sh"] == NOT_EXECUTABLE and "chmod +x" in NOT_EXECUTABLE
    # misc/data.bin (executable, no #! line) is not a script, and hidden files are not looked at

    rsa = load(gen / "crypto/solve_rsa-small.e.py.manifest.toml")
    assert rsa.id == "imported.crypto.solve_rsa-small.e.py"
    assert rsa.entry == Entry("cli", None, None, ("python3", "./crypto/solve_rsa-small.e.py"))
    assert (rsa.output, rsa.tags, rsa.timeout_seconds) == ("text", ("imported",), 60)
    assert rsa.routes == (Route(category=("cry",), keywords=("rsa", "small"), priority=20),)
    assert rsa.base == scripts

    carve = load(gen / "Forensics/carve_png.py.manifest.toml")
    assert carve.routes == (Route(category=("for",), keywords=("carve", "png"), priority=20),)
    sqli = load(gen / "web/sqli-dump.sh.manifest.toml")
    assert sqli.entry.argv == ("./web/sqli-dump.sh",) and sqli.routes[0].category == ("web",)
    xor = load(gen / "reversing/xor_brute.manifest.toml")
    assert xor.entry.argv == ("./reversing/xor_brute",) and xor.routes[0] == Route(("rev",), ("xor", "brute"), (), 20)
    zip_ = load(gen / "tools/zip_cracker.py.manifest.toml")
    assert zip_.routes[0] == Route((), ("zip", "cracker"), (), 20)


def test_the_scripts_are_never_touched(scripts):
    before = tree(scripts)
    import_scripts(scripts)
    import_scripts(scripts)
    after = {rel: info for rel, info in tree(scripts).items() if not rel.startswith(".flightdeck")}
    assert after == before


def test_re_running_the_import_gives_the_same_manifests_and_writes_only_under_generated(scripts):
    first = import_scripts(scripts)
    texts = {path: path.read_text() for path in first.written}
    outside = {rel: info for rel, info in tree(scripts).items() if not rel.startswith(".flightdeck/generated")}
    second = import_scripts(scripts)
    assert second == first
    assert {path: path.read_text() for path in second.written} == texts
    assert {rel: info for rel, info in tree(scripts).items() if not rel.startswith(".flightdeck/generated")} == outside


def test_a_manifest_for_a_script_that_is_gone_or_now_has_its_own_is_removed(scripts):
    first = import_scripts(scripts)
    gen = scripts / GEN
    (scripts / "web" / "sqli-dump.sh").unlink()
    write_manifest(scripts / "crypto", "rsa", """
        id = "my.rsa"
        entry = "cli:python3 solve_rsa-small.e.py"
        output = "text"
        [[routes]]
        category = ["cry"]
        priority = 80
        """)
    second = import_scripts(scripts)
    assert set(second.written) == set(first.written) - {gen / "web/sqli-dump.sh.manifest.toml", gen / "crypto/solve_rsa-small.e.py.manifest.toml"}
    assert not (gen / "web").exists() and not (gen / "crypto").exists()  # emptied folders go too
    reasons = dict(second.skipped)
    assert reasons[scripts / "crypto" / "solve_rsa-small.e.py"] == "already run by the manifest crypto/rsa.manifest.toml"
    assert sorted(m.id for m in discover(scripts))[0] == "imported.forensics.carve_png.py"
    assert "my.rsa" in {m.id for m in discover(scripts)}


def test_a_python_entry_sidecar_also_counts_as_the_scripts_own(scripts):
    write_manifest(scripts / "tools", "zip", 'id = "zip"\nentry = "zip_cracker.py:main"\n[[routes]]\nkeywords = ["zip"]\n')
    script(scripts, "tools/zip_cracker.py", MAIN + "\ndef main(d):\n    return None\n")
    report = import_scripts(scripts)
    assert dict(report.skipped)[scripts / "tools" / "zip_cracker.py"] == "already run by the manifest tools/zip.manifest.toml"


def test_imported_scripts_are_discovered_routed_and_run_from_the_folder(scripts, tmp_path):
    import_scripts(scripts)
    manifests = discover(scripts)
    handout = challenge_dir(tmp_path / "board", "tiny-rsa", {"note.txt": "n = 77, e = 3, t{small_e}\n"}, category="crypto")
    hits = route(manifests, challenge("Tiny RSA", category="cry", description="small exponent"), handout)
    assert [h.manifest.id for h in hits] == ["imported.crypto.solve_rsa-small.e.py"]
    result = run(run_engine(hits[0].manifest, handout, workdir=tmp_path / "work", flag_format=FLAG))
    assert (result.status, result.flags) == ("candidate", ("t{small_e}",))  # python3 ran the script on the copy
    xor = next(m for m in manifests if m.id == "imported.reversing.xor_brute")
    result = run(run_engine(xor, handout, workdir=tmp_path / "work", flag_format=FLAG))
    assert result.flags == ("t{xored}",)  # run through its own #! line


@pytest.mark.parametrize(
    "guard",
    [
        'if __name__ == "__main__" and len(sys.argv) > 1:',
        'if (__name__ == "__main__"):',
        "if(__name__=='__main__'):",
        'if "__main__" == __name__:',
        'if __name__ == "__main__" :  # run me',
    ],
)
def test_main_blocks_written_other_ways_are_scripts_too(tmp_path, guard):
    folder = tmp_path / "s"
    script(folder, "crypto/aes_ecb_oracle.py", f"import sys\n{guard}\n    print(sys.argv[1])\n")
    report = import_scripts(folder)
    assert [p.name for p in report.written] == ["aes_ecb_oracle.py.manifest.toml"] and report.skipped == []


def test_a_py_file_with_no_main_block_is_listed_with_what_to_do(tmp_path):
    folder = tmp_path / "s"
    top_level = script(folder, "crypto/xor_known_plaintext.py", "import sys\nprint(open(sys.argv[1]).read())\n")
    indented = script(folder, "crypto/vigenere_crack.py", 'def main():\n    if __name__ == "__main__":\n        pass\n')
    report = import_scripts(folder)
    assert report.written == []
    assert report.skipped == sorted([(top_level, NO_MAIN), (indented, NO_MAIN)])  # never dropped without a word


def test_a_script_at_the_top_takes_the_category_of_the_folder_itself(tmp_path):
    folder = tmp_path / "Crypto"
    script(folder, "solve.py", MAIN)
    report = import_scripts(folder)
    [path] = report.written
    m = load(path)
    assert m.routes[0].category == ("cry",) and m.entry.argv == ("python3", "./solve.py")


def test_symlinked_scripts_are_listed_and_not_imported(tmp_path):
    folder = tmp_path / "s"
    real = script(tmp_path / "elsewhere", "crypto/rsa_tool.py", MAIN)
    (folder / "crypto").mkdir(parents=True)
    os.symlink(real, folder / "crypto" / "rsa_link.py")
    os.symlink(tmp_path / "elsewhere", folder / "linked")  # a symlinked folder is not walked
    report = import_scripts(folder)
    assert report.written == []
    assert report.skipped == [(folder / "crypto" / "rsa_link.py", "a symlink; only regular files are imported")]


def test_names_that_could_break_a_manifest_are_escaped(tmp_path):
    folder = tmp_path / "s"
    nasty = 'rsa "quoted"\nid = "evil" -x.py'
    script(folder, f"crypto/{nasty}", MAIN)
    [path] = import_scripts(folder).written
    m = load(path)
    assert m.id.startswith("imported.crypto.rsa__quoted__id") and "evil" in m.id  # one id, not two
    assert m.entry.argv == ("python3", f"./crypto/{nasty}")
    assert m.routes[0].keywords == ("rsa", '"quoted"', '"evil"')


def test_ids_stay_unique_and_short(tmp_path):
    folder = tmp_path / "s"
    script(folder, "crypto/rsa .py", MAIN)  # both slug to imported.crypto.rsa_.py
    script(folder, "crypto/rsa_.py", MAIN)
    long = "crypto/" + "very_long_name_" * 10 + "rsa.py"
    script(folder, long, MAIN)
    ids = sorted(load(p).id for p in import_scripts(folder).written)
    assert len(set(ids)) == 3 and all(len(i) <= 100 for i in ids)
    assert "imported.crypto.rsa_.py" in ids and "imported.crypto.rsa_.py-2" in ids


@pytest.mark.parametrize(
    ("name", "words"),
    [
        ("solve_rsa_small_e.py", ("rsa", "small")),
        ("exploit-main.sh", ()),
        ("Base64-Layers.decoder.py", ("base64", "layers", "decoder")),
        ("aes128.py", ("aes128",)),  # three letters are enough
        ("2048_rsa.py", ("rsa",)),  # digits alone are not a word
        ("xor.bash", ("xor",)),  # the extension is not a keyword
        ("crack_zip", ("crack", "zip")),
        ("zip_zip.py", ("zip",)),
        ("a_b_cd.py", ()),
    ],
)
def test_keywords_come_from_the_file_names_words(name, words):
    assert keywords_of(name) == words


def test_folders_that_cannot_be_imported_into_are_errors(tmp_path):
    with pytest.raises(ImporterError, match="no such folder"):
        import_scripts(tmp_path / "missing")
    folder = tmp_path / "s"
    script(folder, "crypto/rsa.py", MAIN)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    os.symlink(elsewhere, folder / ".flightdeck")
    with pytest.raises(ImporterError, match="is a symlink"):
        import_scripts(folder)
    assert list(elsewhere.iterdir()) == []


def test_a_symlinked_folder_inside_generated_is_never_written_through(tmp_path):
    # .flightdeck and .flightdeck/generated are real folders here: the symlink is one level
    # down, where only _real_dirs looks
    folder = tmp_path / "s"
    script(folder, "crypto/xor_tool.py", MAIN)
    (folder / GEN).mkdir(parents=True)
    os.symlink(folder / "crypto", folder / GEN / "crypto")  # would land the manifest in the player's own crypto/
    before = tree(folder / "crypto")
    with pytest.raises(ImporterError, match=r"generated/crypto is a symlink"):
        import_scripts(folder)
    assert tree(folder / "crypto") == before


def test_scripts_in_a_challenge_or_a_workspace_inside_the_folder_are_never_wrapped(tmp_path):
    folder = tmp_path / "s"
    script(folder, "crypto/rsa_tool.py", MAIN)
    challenge = folder / "boards" / "evil"
    script(challenge, "chall.py", 'if __name__ == "__main__":\n    print("t{planted_chall}")\n')
    script(challenge, "challenge.json", '{"name": "Evil", "category": "crypto", "points": 1}')
    workspace = folder / "runs" / "20261111-000000" / "grep"
    script(workspace, "crypto/chall.py", MAIN)
    script(workspace, ".flightdeck/prepare.log", "copied 1 files\n")
    report = import_scripts(folder)
    assert [p.relative_to(folder / GEN).as_posix() for p in report.written] == ["crypto/rsa_tool.py.manifest.toml"]
    reasons = dict(report.skipped)
    assert reasons[challenge].startswith("a challenge folder (it has a challenge.json)")
    assert reasons[workspace].startswith("a flightdeck workspace, a copy of a challenge")
    assert set(reasons) == {challenge, workspace}


def test_a_folder_that_is_a_challenge_is_not_imported(tmp_path):
    folder = tmp_path / "chal"
    script(folder, "crypto/chall.py", MAIN)
    script(folder, "challenge.json", "{}")
    with pytest.raises(ImporterError, match="is a challenge folder"):
        import_scripts(folder)
    assert not (folder / ".flightdeck").exists()


def test_a_broken_manifest_of_the_players_stops_the_import(tmp_path):
    folder = tmp_path / "s"
    script(folder, "crypto/rsa.py", MAIN)
    write_manifest(folder, "broken", 'id = "x"\n')
    from ctf_flightdeck.l1.manifest import ManifestError

    with pytest.raises(ManifestError, match="entry: is missing"):
        import_scripts(folder)
    assert not (folder / ".flightdeck").exists()


def test_an_empty_folder_imports_nothing(tmp_path):
    (tmp_path / "e").mkdir()
    assert import_scripts(tmp_path / "e") == ImportReport([], [])
