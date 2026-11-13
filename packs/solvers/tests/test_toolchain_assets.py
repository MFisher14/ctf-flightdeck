"""B-188: the asset manifest (ctf/toolchain/assets.py, tools/assets.toml): resolve, check, export."""
from __future__ import annotations

import subprocess
import textwrap
import tomllib

import pytest

from ctf.toolchain import assets


def parse(text: str):
    return assets.parse(tomllib.loads(textwrap.dedent(text)), "t.toml")


def one(**kw) -> assets.Asset:
    base = dict(name="wl", kind="file", role="core", candidates=(), export=("CTF_ASSET_WL",))
    base.update(kw)
    return assets.Asset(**base)


def no_run(argv, **kw):
    raise AssertionError(f"no probe expected, got {argv}")


# ------------------------------------------------------------------------------- the real manifest

def test_real_manifest_exports_the_names_the_engines_read(tmp_path, monkeypatch):
    by = {a.name: a for a in assets.load()}
    assert {"rockyou", "john-share", "seclists", "ghidra"} <= set(by)
    assert "ROCKYOU" in by["rockyou"].export and by["rockyou"].role == "core"
    assert "GHIDRA_INSTALL_DIR" in by["ghidra"].export
    js = by["john-share"]
    assert "7z2john.pl" in js.contains and js.probe == ("perl", "-MCompress::Raw::Lzma", "-e", "1")
    # hashcrack (the engine the rockyou path drift broke) reads the exported name first
    import hashcrack
    wl = tmp_path / "rockyou.txt"
    wl.write_text("password\n")
    monkeypatch.setenv("ROCKYOU", str(wl))
    assert hashcrack.find_rockyou() == str(wl)


def test_real_rockyou_resolves_from_the_toolbox_folder(tmp_path):
    rock = next(a for a in assets.load() if a.name == "rockyou")
    f = tmp_path / "tb" / "wordlists" / "rockyou.txt"
    f.parent.mkdir(parents=True)
    with open(f, "wb") as fh:                                         # a sparse file of the full size
        fh.truncate(rock.min_bytes)
    s, = assets.resolve([rock], environ={"CTF_TOOLBOX_DIR": str(tmp_path / "tb"), "HOME": str(tmp_path)},
                        run=no_run)
    assert (s.state, s.path, s.source) == ("ok", str(f), "candidate")


# ------------------------------------------------------------------------------------------- parse

GOOD = """\
[[asset]]
name = "wl"
kind = "file"
candidates = ["/x"]
export = ["CTF_ASSET_WL"]
"""


def test_parse_reads_defaults():
    a, = parse(GOOD)
    assert (a.role, a.env, a.min_bytes, a.probe) == ("core", (), 0, ())


@pytest.mark.parametrize("extra, msg", [
    ('colour = "x"\n', "unknown key"),
    ('contains = ["a"]\n', "contains is for a dir"),
    ('min_bytes = -1\n', "non-negative"),
    ('min_bytes = true\n', "non-negative"),
    ('env = ["rockyou"]\n', "must match"),
    ('role = "vital"\n', "role must be"),
])
def test_parse_refuses_bad_fields(extra, msg):
    with pytest.raises(assets.AssetsError, match=msg):
        parse(GOOD + extra)


def test_parse_refuses_structural_problems():
    with pytest.raises(assets.AssetsError, match="export must name"):
        parse(GOOD.replace('export = ["CTF_ASSET_WL"]', "export = []"))
    with pytest.raises(assets.AssetsError, match="kind must be"):
        parse(GOOD.replace('"file"', '"link"'))
    with pytest.raises(assets.AssetsError, match="min_bytes is for a file"):
        parse(GOOD.replace('"file"', '"dir"') + "min_bytes = 3\n")
    with pytest.raises(assets.AssetsError, match="listed twice"):
        parse(GOOD + "\n" + GOOD)
    with pytest.raises(assets.AssetsError, match="exported by both"):
        parse(GOOD + "\n" + GOOD.replace('name = "wl"', 'name = "w2"'))
    with pytest.raises(assets.AssetsError, match="no \\[\\[asset\\]\\]"):
        parse("")


def test_load_and_select_name_what_is_wrong(tmp_path):
    with pytest.raises(assets.AssetsError, match="not found"):
        assets.load(tmp_path / "none.toml")
    items = parse(GOOD)
    with pytest.raises(assets.AssetsError, match="unknown asset"):
        assets.select(items, ["nope"])


# ----------------------------------------------------------------------------------------- resolve

def test_candidates_are_tried_in_order_with_toolbox_and_home(tmp_path):
    (tmp_path / "home" / "w.txt").parent.mkdir(parents=True)
    (tmp_path / "home" / "w.txt").write_text("h")
    (tmp_path / "tb" / "w.txt").parent.mkdir(parents=True)
    (tmp_path / "tb" / "w.txt").write_text("t")
    e = {"HOME": str(tmp_path / "home"), "CTF_TOOLBOX_DIR": str(tmp_path / "tb")}
    a = one(candidates=(str(tmp_path / "absent"), "{toolbox}/w.txt", "~/w.txt"))
    s, = assets.resolve([a], environ=e, run=no_run)
    assert s.path == str(tmp_path / "tb" / "w.txt")
    a = one(candidates=(str(tmp_path / "absent"), "~/w.txt", "{toolbox}/w.txt"))
    s, = assets.resolve([a], environ=e, run=no_run)
    assert s.path == str(tmp_path / "home" / "w.txt")


def test_a_glob_takes_its_highest_natural_match(tmp_path):
    for v in ("9.2", "10.1", "10.0"):
        (tmp_path / f"ghidra_{v}_PUBLIC" / "support").mkdir(parents=True)
        (tmp_path / f"ghidra_{v}_PUBLIC" / "support" / "analyzeHeadless").write_text("")
    a = one(kind="dir", candidates=(str(tmp_path / "ghidra_*_PUBLIC"),), contains=("support/analyzeHeadless",))
    s, = assets.resolve([a], environ={}, run=no_run)
    assert s.path == str(tmp_path / "ghidra_10.1_PUBLIC")


def test_an_override_wins_and_a_bad_override_is_broken_not_skipped(tmp_path):
    good = tmp_path / "cand.txt"
    good.write_text("x")
    mine = tmp_path / "mine.txt"
    mine.write_text("y")
    a = one(env=("CTF_ASSET_WL", "WORDLIST"), candidates=(str(good),))
    s, = assets.resolve([a], environ={"WORDLIST": str(mine)}, run=no_run)
    assert (s.state, s.path, s.source) == ("ok", str(mine), "env:WORDLIST")
    s, = assets.resolve([a], environ={"CTF_ASSET_WL": str(mine), "WORDLIST": str(good)}, run=no_run)
    assert s.source == "env:CTF_ASSET_WL"
    s, = assets.resolve([a], environ={"WORDLIST": str(tmp_path / "typo.txt")}, run=no_run)
    assert s.state == "broken" and "WORDLIST is set" in s.detail and "unset WORDLIST" in s.fix
    assert s.path == str(tmp_path / "typo.txt")                       # the candidate was not used instead


def test_size_contains_and_kind_make_a_found_path_broken_and_a_later_good_one_wins(tmp_path):
    short = tmp_path / "short.txt"
    short.write_text("abc")
    full = tmp_path / "full.txt"
    full.write_text("abcdefgh")
    a = one(candidates=(str(short),), min_bytes=5)
    s, = assets.resolve([a], environ={}, run=no_run)
    assert s.state == "broken" and "3 bytes" in s.detail and s.path == str(short)
    a = one(candidates=(str(short), str(full)), min_bytes=5)
    s, = assets.resolve([a], environ={}, run=no_run)
    assert (s.state, s.path) == ("ok", str(full))
    d = tmp_path / "d"
    d.mkdir()
    s, = assets.resolve([one(kind="dir", candidates=(str(d),), contains=("run/zip2john",))], environ={}, run=no_run)
    assert s.state == "broken" and "lacks run/zip2john" in s.detail
    s, = assets.resolve([one(kind="file", candidates=(str(d),))], environ={}, run=no_run)
    assert s.state == "broken" and "not a file" in s.detail
    s, = assets.resolve([one(kind="dir", candidates=(str(full),))], environ={}, run=no_run)
    assert s.state == "broken" and "not a folder" in s.detail


def test_with_several_broken_candidates_the_first_one_is_reported(tmp_path):
    first = tmp_path / "first.txt"
    first.write_text("ab")
    second = tmp_path / "second.txt"
    second.write_text("abc")
    s, = assets.resolve([one(candidates=(str(first), str(second)), min_bytes=5)], environ={}, run=no_run)
    assert (s.state, s.path) == ("broken", str(first)) and "2 bytes" in s.detail
    s, = assets.resolve([one(candidates=(str(second), str(first)), min_bytes=5)], environ={}, run=no_run)
    assert (s.state, s.path) == ("broken", str(second)) and "3 bytes" in s.detail


def test_the_probe_runs_on_the_found_path_and_its_failure_is_broken(tmp_path):
    d = tmp_path / "john"
    d.mkdir()
    seen = []

    def run(argv, **kw):
        seen.append((argv, kw.get("stdin"), kw.get("timeout")))
        return subprocess.CompletedProcess(argv, 2, "", "Can't locate Compress/Raw/Lzma.pm in @INC\n")
    a = one(kind="dir", candidates=(str(d),), probe=("perl", "-c", "{path}/7z2john.pl"))
    s, = assets.resolve([a], environ={}, run=run)
    assert seen == [(["perl", "-c", f"{d}/7z2john.pl"], subprocess.DEVNULL, assets.PROBE_TIMEOUT)]
    assert s.state == "broken" and "exited 2" in s.detail and "Lzma.pm" in s.detail

    def ok(argv, **kw):
        return subprocess.CompletedProcess(argv, 0, "", "")
    assert assets.resolve([a], environ={}, run=ok)[0].state == "ok"

    def slow(argv, **kw):
        raise subprocess.TimeoutExpired(argv, kw["timeout"])
    s, = assets.resolve([a], environ={}, run=slow)
    assert s.state == "broken" and "timed out" in s.detail

    def gone(argv, **kw):
        raise FileNotFoundError(2, "No such file", "perl")
    assert assets.resolve([a], environ={}, run=gone)[0].state == "broken"


def test_nothing_found_is_missing_with_the_fix(tmp_path):
    a = one(candidates=("{toolbox}/w.txt",), install="fetch it into {toolbox}/w.txt")
    s, = assets.resolve([a], environ={"CTF_TOOLBOX_DIR": str(tmp_path)}, run=no_run)
    assert s.state == "missing" and s.path is None
    assert s.fix == f"fetch it into {tmp_path.resolve()}/w.txt" and str(tmp_path.resolve()) in s.detail
    assert assets.problems([s], core_only=True) == [s]
    opt = assets.AssetStatus("o", "optional", "missing")
    assert assets.problems([opt], core_only=True) == [] and assets.problems([opt]) == [opt]


def test_exports_cover_only_ok_assets_under_every_name():
    a = one(name="a", export=("CTF_ASSET_A", "A"))
    b = one(name="b", export=("CTF_ASSET_B",))
    rep = [assets.AssetStatus("a", "core", "ok", "/p/a"), assets.AssetStatus("b", "core", "missing")]
    assert assets.exports([a, b], rep) == {"CTF_ASSET_A": "/p/a", "A": "/p/a"}


def test_render_env_quotes_for_a_posix_shell(tmp_path):
    text = assets.render_env({"A": "/p with space/it's"}, path_prepend=["/v env/bin"])
    out = subprocess.run(["sh", "-c", text + 'printf "%s|%s" "$A" "${PATH%%:*}"'], capture_output=True, text=True,
                         env={"PATH": "/usr/bin:/bin"})
    assert out.stdout == "/p with space/it's|/v env/bin", out.stderr
    assert assets.render_env({}) == ""


def test_status_rejects_an_unknown_state():
    with pytest.raises(ValueError, match="state"):
        assets.AssetStatus("a", "core", "fine")
