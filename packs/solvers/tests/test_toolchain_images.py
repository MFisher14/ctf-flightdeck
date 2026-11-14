"""B-188: the pinned toolchain images (ctf/toolchain/images.py, tools/images.toml, docker/toolkit, docker/sage).

Docker is never real here: every docker call goes to the stub in toolchain_stubs.py (it carries the
stub marker, so the CTF_TESTING guard lets it run), and a non-stub docker is shown to be refused.
"""
from __future__ import annotations

import os
import textwrap
from pathlib import Path

import pytest

from ctf import paths
from ctf.toolchain import images
from toolchain_stubs import calls, checkout, docker_stub, set_state

ROOT = paths.repo_root()


# ------------------------------------------------------------------------------- the real manifest

def test_real_manifest_lints_clean_for_every_pinned_image():
    imgs = images.load()
    findings = images.lint(imgs)
    assert images.errors(findings, imgs) == []
    # the unpinned ones are the three carried images, each with its reason, and they do have findings
    unpinned = sorted(i.name for i in imgs if not i.pinned)
    assert unpinned == ["analysis", "pwn", "pwn-multiarch"]
    assert {f.image for f in findings} == set(unpinned)


def test_real_manifest_has_the_toolkit_and_two_tagged_sage_images():
    by = {i.name: i for i in images.load()}
    tk = by["toolkit"]
    assert tk.managed and tk.pinned and tk.role == "core" and tk.tag == "ctf-toolkit:1"
    for mod in ("capstone", "lief", "pefile", "unicorn"):            # the Huntress ModuleNotFoundError set
        assert mod in tk.py
    staged = images.staged_files(tk)
    pins = images.requirement_pins()
    for name in tk.py:                                               # the image pins = the venv pins
        want = f"{pins[images.normalise(name)][0]}=={pins[images.normalise(name)][1]}\n"
        assert want in staged[images.STAGED_REQUIREMENTS]
    sages = sorted((i.version_of("sage"), i.tag) for i in by.values() if i.version_of("sage"))
    assert sages[0] == ("10.5", "ctf-sage:10.5") and len(sages) >= 2
    assert [i.name for i in by.values() if "sage" in i.default_for] != ["sage-10.5"]   # 10.5 is pinned, not default
    assert all(i.platform == "linux/amd64" for i in by.values() if i.version_of("sage"))


def test_real_toolkit_dockerfile_builds_john_from_the_checked_download_and_runs_its_envcheck():
    tk = next(i for i in images.load() if i.name == "toolkit")
    assert [d.name for d in tk.unlocked()] == ["john-jumbo"]         # a human records its sha256
    text = (ROOT / tk.dockerfile).read_text()
    assert "JOHN_SHA256" in text and "libcompress-raw-lzma-perl" in text and "ctf-envcheck" in text
    assert (ROOT / tk.context / "envcheck.sh").is_file()
    env_sh = (ROOT / tk.context / "envcheck.sh").read_text()
    for tool in ("tshark", "zsteg", "7z2john.pl", "Compress::Raw::Lzma", "capstone", "lief", "pefile", "unicorn"):
        assert tool in env_sh
    steps = images.plan_build([tk])
    assert steps[0].action == "refused" and "shasum -a 256" in steps[0].reason


def test_real_sage_dockerfile_checks_the_release_it_was_asked_for():
    df = (ROOT / "docker" / "sage" / "Dockerfile").read_text()
    ins = images.parse_dockerfile(df)
    assert [i.op for i in ins][:3] == ["ARG", "FROM", "ARG"]
    assert any(i.op == "RUN" and 'grep -F "SageMath version ${SAGE_TAG},"' in i.text for i in ins)
    sage = next(i for i in images.load() if i.name == "sage-10.5")
    assert images.lint([sage]) == []


# ------------------------------------------------------------------------------------- the manifest

GOOD = """\
[[image]]
name = "kit"
tag = "ctf-kit:1"
dockerfile = "docker/kit/Dockerfile"
context = "docker/kit"
smoke = [["kit-check"]]
"""


def parse(text: str):
    import tomllib
    return images.parse(tomllib.loads(textwrap.dedent(text)), "t.toml")


def test_parse_reads_a_minimal_image_with_defaults():
    im, = parse(GOOD)
    assert (im.role, im.managed, im.pinned, im.platform, im.smoke) == ("core", True, True, None, (("kit-check",),))


@pytest.mark.parametrize("extra, msg", [
    ('colour = "red"\n', "unknown key"),
    ('platform = "amd64"\n', "platform must look like"),
    ('managed = false\n', "needs built_by"),
    ('pinned = false\n', "needs unpinned_reason"),
    ('default_for = ["sage"]\n', "without a version"),
    ('managed = "no"\n', "must be true or false"),
    ('py = ["a", "a"]\n', "twice"),
])
def test_parse_refuses_bad_fields(extra, msg):
    with pytest.raises(images.ImagesError, match=msg):
        parse(GOOD + extra)


@pytest.mark.parametrize("old, new, msg", [
    ('tag = "ctf-kit:1"', 'tag = "ctf-kit:latest"', "never latest"),
    ('tag = "ctf-kit:1"', 'tag = "ctf-kit"', "explicit tag"),
    ('dockerfile = "docker/kit/Dockerfile"', 'dockerfile = "/abs/Dockerfile"', "repo-relative"),
    ('context = "docker/kit"', 'context = "../kit"', "repo-relative"),
    ('smoke = [["kit-check"]]', 'smoke = []', "at least one command"),
    ('name = "kit"', 'name = "Kit"', "name must match"),
])
def test_parse_refuses_bad_values(old, new, msg):
    with pytest.raises(images.ImagesError, match=msg):
        parse(GOOD.replace(old, new))


def test_parse_refuses_duplicates_and_two_defaults_and_bad_downloads():
    with pytest.raises(images.ImagesError, match="name 'kit' is used by two"):
        parse(GOOD + "\n" + GOOD.replace('"ctf-kit:1"', '"ctf-kit:2"'))
    with pytest.raises(images.ImagesError, match="tag 'ctf-kit:1' is used by two"):
        parse(GOOD + "\n" + GOOD.replace('name = "kit"', 'name = "kit2"'))
    two = (GOOD + 'versions = { sage = "1.0" }\ndefault_for = ["sage"]\n')
    with pytest.raises(images.ImagesError, match="default for 'sage'"):
        parse(two + "\n" + two.replace('name = "kit"', 'name = "k2"').replace('"ctf-kit:1"', '"ctf-kit:2"'))
    dl = GOOD + '[[image.download]]\nname = "x"\nurl = "{url}"\nsha256 = "{sha}"\narg = "{arg}"\n'
    with pytest.raises(images.ImagesError, match="https"):
        parse(dl.format(url="http://e.example/x", sha="", arg="X"))
    with pytest.raises(images.ImagesError, match="64 lower-case hex"):
        parse(dl.format(url="https://e.example/x", sha="ABC", arg="X"))
    with pytest.raises(images.ImagesError, match="arg must match"):
        parse(dl.format(url="https://e.example/x", sha="", arg="x"))
    im, = parse(dl.format(url="https://e.example/x", sha="a" * 64, arg="X"))
    assert im.build_args() == {"X_URL": "https://e.example/x", "X_SHA256": "a" * 64} and not im.unlocked()


def test_parse_refuses_an_empty_or_foreign_manifest():
    with pytest.raises(images.ImagesError, match="no \\[\\[image\\]\\] entries"):
        parse("")
    with pytest.raises(images.ImagesError, match="unknown top-level"):
        parse(GOOD + "\n[extra]\nx = 1\n")


def test_lint_names_a_missing_dockerfile_in_an_existing_context(tmp_path):
    root = checkout(tmp_path, GOOD, {"docker/kit/other.txt": "x"})
    f, = images.lint(images.load(root / "tools" / "images.toml"), root)
    assert (f.rule, f.path) == ("missing-file", "docker/kit/Dockerfile") and "Dockerfile is not there" in f.text


def test_load_names_a_missing_or_broken_manifest(tmp_path):
    with pytest.raises(images.ImagesError, match="not found"):
        images.load(tmp_path / "nope.toml")
    (tmp_path / "bad.toml").write_text("[[image]\n")
    with pytest.raises(images.ImagesError, match="not valid TOML"):
        images.load(tmp_path / "bad.toml")


def test_select_refuses_an_unknown_name():
    imgs = parse(GOOD)
    assert images.select(imgs, None) == imgs
    with pytest.raises(images.ImagesError, match="unknown image"):
        images.select(imgs, ["nope"])


# ------------------------------------------------------------------------------------- dockerfiles

def test_parse_dockerfile_joins_continuations_skips_comments_and_appends_heredocs():
    text = textwrap.dedent("""\
        # a comment
        FROM python:3.12-slim AS base

        RUN apt-get update \\
        # a comment inside the continuation
         && apt-get install -y tshark
        RUN python3 - <<'PY'
        print("body")
        PY
        COPY a.txt /a.txt
        """)
    ins = images.parse_dockerfile(text)
    assert [(i.line, i.op) for i in ins] == [(2, "FROM"), (4, "RUN"), (7, "RUN"), (10, "COPY")]
    assert "apt-get install -y tshark" in ins[1].text and "comment" not in ins[1].text
    assert 'print("body")' in ins[2].text


def lint_text(body: str, **kw) -> list[str]:
    im = images.Image(name="k", tag="k:1", dockerfile="d/Dockerfile", context="d", **kw)
    return [f.rule for f in images.lint_dockerfile(im, textwrap.dedent(body))]


@pytest.mark.parametrize("body, rules", [
    ("FROM python\n", ["from-unpinned"]),
    ("FROM python:latest\n", ["from-unpinned"]),
    ("FROM registry.example:5000/python\n", ["from-unpinned"]),      # the port is not a tag
    ("FROM python:3.12-slim\n", []),
    ("FROM python@sha256:" + "a" * 64 + "\n", []),
    ("FROM python:3.12 AS b\nFROM b\n", []),                          # an earlier stage
    ("FROM scratch\n", []),
    ("FROM --platform=linux/amd64 ubuntu:24.04\n", []),
    ("FROM img:${TAG}\n", ["arg-unset"]),
    ("ARG TAG=1.0\nFROM img:${TAG}\n", []),
    ("ARG TAG=latest\nFROM img:${TAG}\n", ["from-unpinned"]),
])
def test_lint_from_lines(body, rules):
    assert lint_text(body) == rules


def test_lint_from_uses_the_manifest_args():
    assert lint_text("ARG TAG\nFROM img:${TAG}\n", args=(("TAG", "10.5"),)) == []
    assert lint_text("ARG TAG\nFROM img:${TAG}\n", args=(("TAG", "latest"),)) == ["from-unpinned"]
    # the manifest's value is what the build passes, so it beats the ARG default either way
    assert lint_text("ARG TAG=latest\nFROM img:${TAG}\n", args=(("TAG", "10.5"),)) == []
    assert lint_text("ARG TAG=10.5\nFROM img:${TAG}\n", args=(("TAG", "latest"),)) == ["from-unpinned"]


@pytest.mark.parametrize("run, rules", [
    ("pip install requests", ["pip-unpinned"]),
    ("pip3 install requests==2.0 flask", ["pip-unpinned"]),
    ("python3 -m pip install requests==2.0", []),
    ("pip install -r /tmp/r.txt -c /tmp/c.txt", []),
    ("pip install --target=/x jsonpickle==4.1.4", []),
    ("pip install --target /x jsonpickle==4.1.4", []),
    ("pip install /tmp/sstv.tar.gz numpy==2.0", []),
    ("gem install zsteg", ["gem-unpinned"]),
    ("gem install --no-document zsteg -v 0.2.13", []),
    ("git clone https://github.com/x/y /opt/y", ["git-unpinned"]),
    ("git clone https://github.com/x/y /opt/y && git -C /opt/y checkout " + "0" * 40, []),
    ("curl -fsSL https://e.example/x -o /x", ["fetch-unverified"]),
    ("curl -fsSL https://e.example/x -o /x && echo 'ab  /x' | sha256sum -c", []),
    ("wget https://e.example/x", ["fetch-unverified"]),
    ("apt-get install -y curl ca-certificates", []),                  # a package named curl is no download
    ("make || true", ["swallowed-failure"]),
    ("make || echo failed", ["swallowed-failure"]),
    ("make || :", ["swallowed-failure"]),
    ("[ -x /a ] || exit 1", []),
])
def test_lint_run_lines(run, rules):
    assert lint_text(f"FROM python:3.12\nRUN {run}\n") == rules


def test_lint_reads_a_heredoc_download_with_its_check():
    body = "FROM python:3.12\nRUN python3 - <<'PY'\nimport urllib.request\nurllib.request.urlopen('https://e.example')\nPY\n"
    assert lint_text(body) == ["fetch-unverified"]
    checked = body.replace("PY\n", "assert hashlib.sha256(b'').hexdigest() == 'x'\nPY\n", 1).replace(
        "import urllib", "import hashlib, urllib")
    assert lint_text(checked) == []


def test_lint_copy_sources_against_the_context(tmp_path):
    ctx = tmp_path / "d"
    ctx.mkdir()
    (ctx / "here.sh").write_text("x")
    im = images.Image(name="k", tag="k:1", dockerfile="d/Dockerfile", context="d")
    body = ("FROM python:3.12 AS b\nFROM python:3.12\nCOPY here.sh /x\nCOPY gone.sh /y\nCOPY --from=b /opt /opt\n"
            "COPY toolchain-requirements.txt /tmp/\nADD https://e.example/f /f\n"
            "ADD --checksum=sha256:" + "a" * 64 + " https://e.example/g /g\n")
    fs = images.lint_dockerfile(im, body, context=ctx, staged=["toolchain-requirements.txt"])
    assert [(f.line, f.rule) for f in fs] == [(4, "copy-missing"), (7, "fetch-unverified")]


def test_lint_checks_files_and_py_pins(tmp_path):
    manifest = GOOD + 'py = ["capstone", "notpinned"]\n' + "\n" + GOOD.replace('"kit"', '"gone"').replace(
        '"ctf-kit:1"', '"ctf-gone:1"').replace("docker/kit", "docker/gone")
    root = checkout(tmp_path, manifest, {"docker/kit/Dockerfile": "FROM python:3.12\n"})
    imgs = images.load(root / "tools" / "images.toml")
    rules = sorted((f.image, f.rule) for f in images.lint(imgs, root))
    assert rules == [("gone", "missing-file"), ("kit", "py-unpinned")]
    outside = checkout(tmp_path / "o", GOOD.replace('dockerfile = "docker/kit/Dockerfile"',
                                                    'dockerfile = "docker/Dockerfile"'),
                       {"docker/Dockerfile": "FROM python:3.12\n", "docker/kit/x": "x"})
    f, = images.lint(images.load(outside / "tools" / "images.toml"), outside)
    assert f.rule == "missing-file" and "outside its context" in f.text


def test_errors_are_only_the_pinned_images_findings():
    fs = [images.Finding("a", "p", 1, "pip-unpinned", ""), images.Finding("b", "p", 1, "pip-unpinned", "")]
    a = images.Image(name="a", tag="a:1", dockerfile="a/D", context="a")
    b = images.Image(name="b", tag="b:1", dockerfile="b/D", context="b", pinned=False, unpinned_reason="carried")
    assert images.errors(fs, [a, b]) == [fs[0]]


@pytest.mark.parametrize("rule", images.RULES)
def test_every_rule_is_fatal_on_a_pinned_image_and_only_reported_on_an_unpinned_one(rule):
    a = images.Image(name="a", tag="a:1", dockerfile="a/D", context="a")
    b = images.Image(name="b", tag="b:1", dockerfile="b/D", context="b", pinned=False, unpinned_reason="carried")
    fa, fb = images.Finding("a", "a/D", 2, rule, "x"), images.Finding("b", "b/D", 2, rule, "x")
    assert images.errors([fa, fb], [a, b]) == [fa]


# ------------------------------------------------------------------------------------ staged + hash

PY_IMG = GOOD + 'py = ["lief", "capstone"]\n'


def test_staged_files_take_the_versions_from_requirements_in(tmp_path):
    root = checkout(tmp_path, PY_IMG, {"docker/kit/Dockerfile": "FROM python:3.12\n"})
    im, = images.load(root / "tools" / "images.toml")
    st = images.staged_files(im, root)
    assert st[images.STAGED_REQUIREMENTS].splitlines()[1:] == ["lief==1.0.0", "capstone==5.0.9"]
    assert st[images.STAGED_CONSTRAINTS].splitlines()[1:] == ["capstone==5.0.9", "lief==1.0.0", "requests==2.34.2"]
    assert images.staged_files(images.Image(name="n", tag="n:1", dockerfile="d/D", context="d"), root) == {}
    (root / "requirements.in").write_text("capstone==5.0.9\n")
    with pytest.raises(images.ImagesError, match=r"\['lief'\] are not pinned"):
        images.staged_files(im, root)


def test_content_hash_follows_the_files_args_and_pins_and_nothing_else(tmp_path):
    root = checkout(tmp_path, PY_IMG, {"docker/kit/Dockerfile": "FROM python:3.12\n", "docker/kit/e.sh": "a"})
    im, = images.load(root / "tools" / "images.toml")
    h0 = images.content_hash(im, root)
    assert images.content_hash(im, root) == h0
    os.utime(root / "docker/kit/e.sh", (1, 1))                       # a touch is not a change
    assert images.content_hash(im, root) == h0
    (root / "docker/kit/e.sh").write_text("b")
    h1 = images.content_hash(im, root)
    assert h1 != h0
    (root / "docker/kit/new.txt").write_text("")
    h2 = images.content_hash(im, root)
    assert h2 != h1
    (root / "requirements.in").write_text((root / "requirements.in").read_text().replace("1.0.0", "1.0.1"))
    h3 = images.content_hash(im, root)
    assert h3 != h2
    im2 = images.Image(**{**im.__dict__, "args": (("A", "1"),)})
    assert images.content_hash(im2, root) != h3
    im3 = images.Image(**{**im.__dict__, "platform": "linux/amd64"})
    assert images.content_hash(im3, root) != h3
    im4 = images.Image(**{**im.__dict__, "tag": "ctf-kit:2"})
    assert images.content_hash(im4, root) != h3


@pytest.mark.parametrize("pattern, path, hit", [
    ("**/.DS_Store", ".DS_Store", True),
    ("**/.DS_Store", "a/b/.DS_Store", True),
    (".DS_Store", "a/.DS_Store", False),                              # no ** : the top level only
    ("*.swp", "x.swp", True),
    ("*.swp", "sub/x.swp", False),                                    # * stops at /
    ("sub", "sub/deep/f.txt", True),                                  # a folder takes its contents
    ("/sub/*.txt", "sub/f.txt", True),                                # a leading / is the context root
    ("f?.txt", "f1.txt", True),
    ("f?.txt", "f12.txt", False),
    ("f[0-9].txt", "f3.txt", True),
    ("f[!0-9].txt", "f3.txt", False),
    ("f[!0-9].txt", "fa.txt", True),
    ("a.b", "aXb", False),                                            # . is literal
    ("logs/**", "logs/x/y.log", True),
])
def test_dockerignore_patterns_read_as_docker_reads_them(tmp_path, pattern, path, hit):
    (tmp_path / ".dockerignore").write_text(pattern + "\n")
    assert images.dockerignored(path, images.dockerignore_rules(tmp_path)) is hit


def test_dockerignore_last_match_wins_and_comments_are_skipped(tmp_path):
    (tmp_path / ".dockerignore").write_text("# notes\n\n*.md\n!KEEP.md\n")
    rules = images.dockerignore_rules(tmp_path)
    assert len(rules) == 2
    assert images.dockerignored("a.md", rules) and not images.dockerignored("KEEP.md", rules)
    assert images.dockerignore_rules(tmp_path / "none") == []


def test_content_hash_and_stage_leave_out_what_dockerignore_lists(tmp_path):
    root = checkout(tmp_path, GOOD, {"docker/kit/Dockerfile": "FROM python:3.12\nCOPY . /src\n",
                                     "docker/kit/e.sh": "a", "docker/kit/notes.md": "n", "docker/kit/KEEP.md": "k",
                                     "docker/kit/.dockerignore": "**/.DS_Store\n*.md\n!KEEP.md\nDockerfile\n"})
    im, = images.load(root / "tools" / "images.toml")
    ctx = root / "docker/kit"
    assert images.context_files(im, root) == [".dockerignore", "Dockerfile", "KEEP.md", "e.sh"]
    h0 = images.content_hash(im, root)
    (ctx / ".DS_Store").write_bytes(b"\0finder")                    # stray OS files: no rebuild
    (ctx / "sub").mkdir()
    (ctx / "sub" / ".DS_Store").write_bytes(b"\0finder")
    (ctx / "notes.md").write_text("edited")
    assert images.content_hash(im, root) == h0
    (ctx / "KEEP.md").write_text("edited")                           # the exception is still hashed
    h1 = images.content_hash(im, root)
    assert h1 != h0
    (ctx / ".dockerignore").write_text("**/.DS_Store\n")              # the ignore file is part of the build
    assert images.content_hash(im, root) != h1
    (ctx / ".dockerignore").write_text("**/.DS_Store\n*.md\n!KEEP.md\nDockerfile\n")
    dest = images.stage(im, tmp_path / "staged", root)
    got = sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file())
    assert got == [".dockerignore", "Dockerfile", "KEEP.md", "e.sh"]   # exactly what the hash covered


# ------------------------------------------------------------------------------- docker: status/build

TWO = GOOD + 'py = ["capstone"]\n' + """
[[image]]
name = "ext"
tag = "ctf-ext:1"
dockerfile = "docker/ext/Dockerfile"
context = "docker/ext"
role = "optional"
managed = false
built_by = "another tool"
smoke = [["ext-check"]]
"""


def two_root(tmp_path):
    return checkout(tmp_path, TWO, {"docker/kit/Dockerfile": "FROM python:3.12\nCOPY toolchain-requirements.txt /t/\n",
                                    "docker/kit/e.sh": "x", "docker/ext/Dockerfile": "FROM python:3.12\n"})


def test_status_reads_labels_through_docker_image_inspect(tmp_path):
    root = two_root(tmp_path)
    imgs = images.load(root / "tools" / "images.toml")
    want = images.content_hash(imgs[0], root)
    env = docker_stub(tmp_path, {"images": {"ctf-kit:1": {images.LABEL: want}, "ctf-ext:1": None}})
    rep = images.status(imgs, root=root, environ=env)
    assert [(s.name, s.state) for s in rep] == [("kit", "ok"), ("ext", "ok")]
    assert "not hash-labelled" in rep[1].detail
    assert calls(env)[0]["argv"] == ["image", "inspect", "--format", "{{json .Config.Labels}}", "ctf-kit:1"]
    set_state(env, {"images": {"ctf-kit:1": {images.LABEL: "0" * 64}}})
    rep = images.status(imgs, root=root, environ=env)
    assert [(s.name, s.state) for s in rep] == [("kit", "stale"), ("ext", "missing")]
    assert rep[0].have == "0" * 64 and rep[0].want == want and "--only kit" in rep[0].fix
    assert rep[1].fix == "another tool"
    set_state(env, {"images": {"ctf-kit:1": {"other": "x"}}})
    assert images.status(imgs, root=root, environ=env)[0].state == "unlabelled"
    set_state(env, {"images": {"ctf-kit:1": None}})                 # an image with no labels at all
    assert images.status(imgs, root=root, environ=env)[0].state == "unlabelled"
    set_state(env, {"down": True})
    s = images.status(imgs, root=root, environ=env)[0]
    assert s.state == "unknown" and "Cannot connect" in s.detail


def test_status_without_docker_is_unknown_never_ok(tmp_path):
    root = two_root(tmp_path)
    imgs = images.load(root / "tools" / "images.toml")
    rep = images.status(imgs, root=root, environ={"PATH": str(tmp_path / "empty"), "CTF_TESTING": "1"})
    assert {s.state for s in rep} == {"unknown"} and "not on PATH" in rep[0].detail
    assert images.problems(rep, core_only=True) == [rep[0]]
    assert images.problems(rep) == rep


def test_a_docker_that_is_not_a_stub_is_refused_under_testing(tmp_path):
    root = two_root(tmp_path)
    imgs = images.load(root / "tools" / "images.toml")
    env = docker_stub(tmp_path, {"images": {}}, marker=False)
    with pytest.raises(images.ImagesError, match="not a test stub"):
        images.status(imgs, root=root, environ=env)
    with pytest.raises(images.ImagesError, match="not a test stub"):
        images.smoke(imgs[0], environ=env)
    # CTF_TESTING in this process counts even when the environ handed in lacks it
    env.pop("CTF_TESTING")
    with pytest.raises(images.ImagesError, match="not a test stub"):
        images.docker_path(env)
    assert calls(env) == []


def test_plan_build_builds_what_is_not_fresh_and_never_what_another_tool_builds(tmp_path):
    root = two_root(tmp_path)
    imgs = images.load(root / "tools" / "images.toml")
    want = images.content_hash(imgs[0], root)
    fresh = [images.ImageStatus("kit", "ctf-kit:1", "core", "ok", want=want, have=want)]
    assert [(s.image, s.action) for s in images.plan_build(imgs, fresh, root=root)] == [("kit", "skip"), ("ext", "skip")]
    st, _ = images.plan_build(imgs, fresh, root=root, force=True)
    assert st.action == "build" and st.reason == "forced"
    stale = [images.ImageStatus("kit", "ctf-kit:1", "core", "stale", want=want, have="x")]
    st, ext = images.plan_build(imgs, stale, root=root)
    assert st.action == "build" and st.reason == "stale" and ext.reason == "built by another tool"
    assert st.argv == ("docker", "build", "-t", "ctf-kit:1", "-f", "Dockerfile", "--label", f"{images.LABEL}={want}",
                       "docker/kit")


def test_plan_build_passes_platform_and_build_args_and_refuses_unlocked_downloads(tmp_path):
    dl = ('platform = "linux/amd64"\nargs = {{ V = "10.5" }}\n[[image.download]]\nname = "src"\n'
          'url = "https://e.example/s.tgz"\nsha256 = "{sha}"\narg = "SRC"\n')
    root = checkout(tmp_path, GOOD + dl.format(sha="b" * 64), {"docker/kit/Dockerfile": "FROM python:3.12\n"})
    im, = images.load(root / "tools" / "images.toml")
    st, = images.plan_build([im], root=root)
    a = list(st.argv)
    assert a[2:4] == ["--platform", "linux/amd64"]
    assert [a[i + 1] for i, x in enumerate(a) if x == "--build-arg"] == [
        "SRC_SHA256=" + "b" * 64, "SRC_URL=https://e.example/s.tgz", "V=10.5"]
    root2 = checkout(tmp_path / "u", GOOD + dl.format(sha=""), {"docker/kit/Dockerfile": "FROM python:3.12\n"})
    im2, = images.load(root2 / "tools" / "images.toml")
    st2, = images.plan_build([im2], root=root2)
    assert st2.action == "refused" and st2.argv is None and "curl -fsSL https://e.example/s.tgz" in st2.reason


BAD_DF = "FROM python:3.12\nRUN pip install requests\n"


def test_plan_build_refuses_a_pinned_image_that_fails_lint_and_apply_never_builds_it(tmp_path):
    root = checkout(tmp_path, GOOD, {"docker/kit/Dockerfile": BAD_DF})
    im, = images.load(root / "tools" / "images.toml")
    st, = images.plan_build([im], root=root)
    assert st.action == "refused" and st.argv is None
    assert "1 lint finding(s)" in st.reason and "pip-unpinned" in st.reason and "--only kit" in st.reason
    # a fresh-looking label does not let it through either
    fresh = [images.ImageStatus("kit", "ctf-kit:1", "core", "ok", want="h", have="h")]
    assert images.plan_build([im], fresh, root=root)[0].action == "refused"
    env = docker_stub(tmp_path, {"images": {}})
    r, = images.apply_build([st], [im], root=root, environ=env)
    assert (r.reason, r.returncode) == ("refused", None)
    assert calls(env) == []
    # both reasons at once: an unlocked download and a lint finding
    dl = '[[image.download]]\nname = "src"\nurl = "https://e.example/s"\nsha256 = ""\narg = "SRC"\n'
    root2 = checkout(tmp_path / "2", GOOD + dl, {"docker/kit/Dockerfile": BAD_DF})
    st2, = images.plan_build(images.load(root2 / "tools" / "images.toml"), root=root2)
    assert st2.action == "refused" and "no sha256" in st2.reason and "pip-unpinned" in st2.reason


def test_plan_build_still_builds_an_unpinned_image_with_findings(tmp_path):
    root = checkout(tmp_path, GOOD + 'pinned = false\nunpinned_reason = "carried"\n',
                    {"docker/kit/Dockerfile": BAD_DF})
    im, = images.load(root / "tools" / "images.toml")
    assert images.lint([im], root) and images.plan_build([im], root=root)[0].action == "build"


def test_apply_build_stages_the_context_with_the_pin_files(tmp_path):
    root = two_root(tmp_path)
    imgs = images.load(root / "tools" / "images.toml")
    env = docker_stub(tmp_path, {"images": {}})
    steps = images.plan_build(imgs, images.status(imgs, root=root, environ=env), root=root)
    res = images.apply_build(steps, imgs, root=root, environ=env)
    assert [(r.step.image, r.reason, r.returncode) for r in res] == [("kit", "", 0), ("ext", "skip", None)]
    build, = [c for c in calls(env) if c["argv"][0] == "build"]
    assert build["context_files"] == ["Dockerfile", "e.sh", images.STAGED_CONSTRAINTS, images.STAGED_REQUIREMENTS]
    assert build["staged"][images.STAGED_REQUIREMENTS].endswith("capstone==5.0.9\n")
    assert f"{images.LABEL}={images.content_hash(imgs[0], root)}" in build["argv"]
    assert not (root / "docker/kit" / images.STAGED_REQUIREMENTS).exists()     # the checkout is never written
    set_state(env, {"images": {}, "build_rc": 7})
    r = images.apply_build(steps, imgs, root=root, environ=env)[0]
    assert r.returncode == 7 and r.reason == ""


def test_apply_build_without_docker_says_absent(tmp_path):
    root = two_root(tmp_path)
    imgs = images.load(root / "tools" / "images.toml")
    steps = images.plan_build(imgs, root=root)
    res = images.apply_build(steps, imgs, root=root, environ={"PATH": str(tmp_path / "none"), "CTF_TESTING": "1"})
    assert [r.reason for r in res] == ["absent", "skip"]


def test_smoke_runs_each_check_networkless_and_reports_failures(tmp_path):
    root = two_root(tmp_path)
    im = images.load(root / "tools" / "images.toml")[0]
    im = images.Image(**{**im.__dict__, "smoke": (("kit-check",), ("other", "fail"))})
    env = docker_stub(tmp_path, {"run_fail": "fail"})
    res = images.smoke(im, environ=env)
    assert [r.ok for r in res] == [True, False] and res[1].returncode == 3
    argv = calls(env)[0]["argv"]
    assert argv[:7] == ["run", "--rm", "--network", "none", "--pull=never", "--cap-drop", "ALL"]
    assert argv[-2:] == ["ctf-kit:1", "kit-check"]
    with pytest.raises(images.ImagesError, match="not on PATH"):
        images.smoke(im, environ={"PATH": str(tmp_path / "none"), "CTF_TESTING": "1"})


def test_run_argv_mounts_the_workdir_and_keeps_the_network_off(tmp_path):
    im = images.Image(name="s", tag="ctf-sage:10.5", dockerfile="d/D", context="d", platform="linux/amd64")
    a = images.run_argv(im, ["sage", "x.sage"], workdir=tmp_path)
    assert a[:5] == ["docker", "run", "--rm", "--network", "none"] and "--pull=never" in a
    assert a[a.index("--platform") + 1] == "linux/amd64"
    assert a[a.index("-v") + 1] == f"{tmp_path.resolve()}:/work" and a[-3:] == ["ctf-sage:10.5", "sage", "x.sage"]


def test_image_status_rejects_an_unknown_state():
    with pytest.raises(ValueError, match="state"):
        images.ImageStatus("a", "a:1", "core", "green")

