#!/usr/bin/env python3
"""Review tests of row 147 (tools/sandbox.py, solvers/toolkits/stego_tools.py): what the adversarial
review of 2026-10-08 broke and fixed. One check per defect.

  .venv/bin/python tests/test_stego_review.py

Part A needs no Docker (the docker CLI is a stand-in that writes down every call):
  A1  Rec is false when ok is False (its __bool__ and __repr__ were dead code inside _guard)
  A2  an argument wrapped in sandbox.Lit reaches the tool as written: the passphrase `flag{in}` was
      rewritten to `flag/drop/<call>/cover.jpg`
  A3  an input named '.', '..' or '' gets a file name (it raised IsADirectoryError, not SandboxDown)
  A4  run() reads its args once per container tried (a generator was empty on the second)
  A5  a program ended by a signal (SIGXFSZ at the container's file-size limit, 153) is 'not read'

Part B runs only when Docker answers and csctf-sandbox:2 is built (else one SKIP line), in a
container of its own (csctf-stego-review-<pid>-2). A failure is a reading only when the file was read:
  B1  steghide_extract and stegseek on a JPEG cut short say the cover was not read, not 'wrong passphrase'
  B2  a passphrase, a key and a script argument with {in} or {out} in them work as written
  B3  pdf_decrypt: a PDF that is not encrypted is not 'decrypted' by any password; a damaged one is
      not 'wrong password'; a wrong password is; the right one still opens it
  B4  codes(): one QR whose text has a line 'QR-Code:...' in it is ONE code; two codes are two;
      a binary code's bytes come back exact; a picture zbar cannot load is 'not read', not '0 codes'
  B5  exif() keeps exiftool's warning about data after IEND, and an empty file is not ok
  B6  zsteg on a file that is no PNG or BMP is 'not read', not '0 findings'
  B7  stegsnow's and outguess's notes say they prove nothing; a word with a line break is not a word
  B8  tsk icat: no inode is refused; a file's bytes come back exact, NULs and 0xff included

No platform request, no token (CTF_TOKEN is a dummy). Prints one line per check and `ok` at the end; exits 1 on the
first failure.

Under pytest the script runs once in a process of its own (its environment, fake docker CLI and the
sandbox module it imports never leak into other tests): test_part_a passes only when all eight Part A
checks print ok; test_part_b is reported as skipped (not run) when Docker or csctf-sandbox:2 is absent.

SH-15 (neither test contacts Docker; each uses a stand-in docker CLI of its own):
  test_part_b_probe_timeout                  sandbox.present on a probe that takes 6 s: SandboxDown at the
                                             stock 5 s PROBE_TIMEOUT, answered at 60 s
  test_part_b_waits_for_a_slow_daemon_probe  this script, whole, with a stand-in docker first on PATH that is
                                             slow at every daemon read Part B waits on (pre-check `version`
                                             11 s and `image inspect` 21 s, the image probe 6 s): Part B is
                                             not skipped, says it waits 60 s or more, gets past the probe
                                             (it raises sandbox.PROBE_TIMEOUT in its own process) and fails
                                             B0 only at the stand-in's refused `docker run`
"""
import atexit
import importlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


A_CHECKS = 8     # the "ok    A..." lines Part A prints when every one of its checks passes
B_WAIT_LINE = "ok    B0 a daemon read is waited for up to "   # ... "<seconds> s": Part B's own wait, as it reads it back


def _script_output(env=None):
    if env is None:
        env = {k: v for k, v in os.environ.items() if k != "PYTEST_CURRENT_TEST"}
    p = subprocess.run([sys.executable, str(Path(__file__).resolve())], capture_output=True, text=True,
                       timeout=1200, env=env, cwd=str(Path(__file__).resolve().parent.parent))
    return p.returncode, p.stdout + p.stderr


try:
    import pytest
except ImportError:  # a direct run needs no pytest
    pytest = None
else:
    @pytest.fixture(scope="module")
    def script_run():
        return _script_output()

    def test_part_a(script_run):
        code, out = script_run
        ok_a = [line for line in out.splitlines() if line.startswith("ok    A")]
        assert "FAIL  A" not in out and len(ok_a) == A_CHECKS, out[-4000:]

    def test_part_b(script_run):
        code, out = script_run
        skip = next((line for line in out.splitlines() if line.startswith("SKIP  B")), None)
        if skip is not None and code == 0:
            pytest.skip("Part B not run: " + skip[len("SKIP  B "):])
        assert code == 0 and out.rstrip().endswith("ok") and "ok    B9 stop removes the container" in out, out[-4000:]

    def _probe(fake_docker, probe_timeout, box):
        """Run the image probe (sandbox.present) once in a fresh interpreter against FAKE_DOCKER with
        sandbox.PROBE_TIMEOUT set to PROBE_TIMEOUT and BOX (a folder under the test's own tmp_path)
        as the sandbox folder. Returns the driver's parsed JSON verdict."""
        driver = str(Path(__file__).resolve().parent / "sh15_drivers.py")
        env = {k: v for k, v in os.environ.items() if k != "PYTEST_CURRENT_TEST"}
        p = subprocess.run([sys.executable, "-I", driver, str(fake_docker), str(probe_timeout), str(box)],
                           capture_output=True, text=True, timeout=300, env=env)
        assert p.returncode == 0, (p.stdout, p.stderr)
        return json.loads(p.stdout.strip().splitlines()[-1])

    def test_part_b_probe_timeout(tmp_path):
        """SH-15 proof, run where Docker is not used: a slow daemon probe (`docker image inspect`
        sleeping 6 s) is SandboxDown at the stock 5 s PROBE_TIMEOUT but answers at the 60 s Part B
        raises it to. Wall-clock is load-bearing here (the probe is a wait on another process, not
        CPU work): the 6 s sleep exceeds 5 s however loaded (a lower bound, safe under load), and
        clears 60 s with 54 s of slack. This is the exact call that failed B0 ('sandbox down: docker
        image did not answer within 5 s') before the fix."""
        fake = tmp_path / "docker"
        fake.write_text("\n".join([
            f"#!{sys.executable}",
            "import sys, time",
            "args = sys.argv[1:]",
            "if args and args[0] == 'image':",   # docker image inspect: the probe sandbox.present makes
            "    time.sleep(6)",                  # a daemon slow to answer under load
            "    print('sha256:11112222'); sys.exit(0)",
            "sys.exit(0)",
            "",
        ]))
        fake.chmod(0o755)
        down = _probe(fake, 5, tmp_path / "box5")
        assert down["outcome"] == "down" and "did not answer within 5 s" in down["reason"], down
        up = _probe(fake, 60, tmp_path / "box60")
        assert up == {"outcome": "up", "present": True}, up

    def test_part_b_waits_for_a_slow_daemon_probe(tmp_path):
        """SH-15, the fix line itself, run where Docker is not used: this script, whole, with a
        stand-in docker CLI first on PATH. Part A uses its own stand-in ($CTF_DOCKER); Part B drops
        that and finds `docker` on PATH, which here is the stand-in below. It is slow at every
        daemon read Part B waits on: 11 s over `version` and 21 s over `image inspect
        csctf-sandbox:2` (Part B's pre-check, which used to give up at 10 s and 20 s and print
        SKIP B), and 6 s over the probe sandbox.present makes (`image inspect --format`). It
        refuses `run`, so no container is ever started. With Part B's `sandbox.PROBE_TIMEOUT =
        60.0` the pre-check and the probe are waited for and B0 fails at the refused `docker run`.
        Without that line every read is back at the stock 5 s: here the pre-check gives up and
        Part B is skipped, and against a daemon that got past the pre-check B0 fails with 'docker
        image did not answer within 5 s', which is the flake. The size of the wait is pinned by
        the line Part B prints about it: 60 s or more (a 30 s wait outlasts every sleep here and
        is still closer to the flake than this item allows).
        Wall-clock is load-bearing (waits on another process), and every bound is a lower one:
        each sleep exceeds the old timeout it stands against however loaded, and the longest
        (21 s) clears 60 s with 39 s of slack."""
        log = tmp_path / "calls.jsonl"
        fake = tmp_path / "bin" / "docker"
        fake.parent.mkdir()
        fake.write_text("\n".join([
            f"#!{sys.executable}",
            "import json, sys, time",
            "args = sys.argv[1:]",
            f"with open({str(log)!r}, 'a') as f:",
            "    f.write(json.dumps(args) + '\\n')",
            "if args[:1] == ['version']:",                 # Part B's pre-check, slower than its old 10 s
            "    time.sleep(11)",
            "    print('0.0.0-standin'); sys.exit(0)",
            "if args[:2] == ['image', 'inspect']:",
            "    if args[-1] != 'csctf-sandbox:2':",       # only :2 is 'built' here
            "        sys.stderr.write('Error response from daemon: No such image: ' + args[-1] + '\\n'); sys.exit(1)",
            "    if '--format' in args:",                  # sandbox.present's probe:
            "        time.sleep(6)",                       # a daemon slow to answer under load
            "        print('sha256:15151515'); sys.exit(0)",
            "    time.sleep(21)",                          # Part B's pre-check, slower than its old 20 s
            "    print('[]'); sys.exit(0)",
            "if args[:1] == ['run']:",                     # no container, ever
            "    sys.stderr.write('docker: Error response from daemon: SH-15 stand-in starts no container\\n'); sys.exit(1)",
            "sys.stderr.write('Error response from daemon: No such container: x\\n'); sys.exit(1)",
            "",
        ]))
        fake.chmod(0o755)
        # No variable may point the sandbox at another docker CLI ($CTF_DOCKER or a legacy spelling).
        env = {k: v for k, v in os.environ.items() if k != "PYTEST_CURRENT_TEST" and not k.endswith("_DOCKER")}
        env["PATH"] = str(fake.parent) + os.pathsep + env.get("PATH", "")
        # The real docker CLI must not be what Part B finds: checked before anything is run.
        assert shutil.which("docker", path=env["PATH"]) == str(fake)
        code, out = _script_output(env)
        calls = [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []
        b0 = [line for line in out.splitlines() if "B0 it starts on the first call" in line]
        assert "SKIP  B" not in out and "ok    B0 a container of its own" in out, out[-4000:]
        # The size of the wait, as Part B itself reads it back from the sandbox module it uses.
        said = [line for line in out.splitlines() if line.startswith(B_WAIT_LINE)]
        assert len(said) == 1, out[-4000:]
        assert float(said[0][len(B_WAIT_LINE):].split()[0]) >= 60.0, said[0]
        assert code == 1 and len(b0) == 1 and b0[0].startswith("FAIL  B0"), out[-4000:]
        assert "did not answer within" not in out, b0[0]
        assert "docker run failed" in b0[0] and "SH-15 stand-in starts no container" in b0[0], b0[0]
        probes = [i for i, c in enumerate(calls) if c[:3] == ["image", "inspect", "--format"] and c[-1] == "csctf-sandbox:2"]
        runs = [i for i, c in enumerate(calls) if c[:2] == ["run", "-d"]]
        assert len(probes) == 1 and len(runs) == 1 and probes[0] < runs[0], calls
        assert calls[runs[0]][-1] == "csctf-sandbox:2" and "none" in calls[runs[0]], calls[runs[0]]
        # The two slow pre-check reads were both made, and before the probe.
        pre = [i for i, c in enumerate(calls) if c[:1] == ["version"] or c == ["image", "inspect", "csctf-sandbox:2"]]
        assert [calls[i][0] for i in pre[:2]] == ["version", "image"] and pre[1] < probes[0], calls


def main():
    T0 = time.monotonic()
    REPO = Path(__file__).resolve().parent.parent
    TOOLS = REPO / "tools"
    TMP = Path(tempfile.mkdtemp(prefix="test_stego_review_")).resolve()
    atexit.register(shutil.rmtree, TMP, ignore_errors=True)
    sys.dont_write_bytecode = True
    sys.path[:0] = [str(TOOLS), str(REPO / "solvers" / "toolkits"), str(REPO / "solvers" / "common"), str(REPO / "tests")]

    os.environ["CTF_TOKEN"] = "dummy-not-a-token-0123456789"
    os.environ["CTF_SANDBOX_DIR"] = str(TMP / "box")
    TEST_NAME = f"csctf-stego-review-{os.getpid()}"
    os.environ["CTF_SANDBOX_NAME"] = TEST_NAME
    os.environ.pop("CTF_SANDBOX_IMAGE", None)
    FAKE_LOG = TMP / "docker-calls.jsonl"


    def check(name, ok, detail=""):
        if ok:
            print(f"ok    {name}")
            return
        print(f"FAIL  {name}" + (f": {detail}" if detail != "" else ""))
        sys.exit(1)


    # The stand-in: every exec "runs" (exit FAKE_CODE, default 0) and is written down; nothing else is there.
    FAKE = TMP / "bin" / "docker"
    FAKE.parent.mkdir()
    FAKE.write_text("\n".join([
        f"#!{sys.executable}",
        "import json, os, sys",
        "args = sys.argv[1:]",
        f"with open({str(FAKE_LOG)!r}, \"a\") as f:",
        "    f.write(json.dumps({\"args\": args}) + \"\\n\")",
        "if args[0] == \"exec\":",
        "    if \"test\" in args:",
        "        sys.exit(0)",
        "    sys.exit(int(os.environ.get(\"FAKE_CODE\", \"0\")))",
        "if args[0] == \"image\":",
        "    print(\"sha256:22222222\"); sys.exit(0)",
        "sys.stderr.write(\"Error response from daemon: No such container: x\\n\"); sys.exit(1)",
        "",
    ]))
    FAKE.chmod(0o755)
    os.environ["CTF_DOCKER"] = str(FAKE)

    import sandbox          # noqa: E402
    import stego_tools as st   # noqa: E402
    import stego_fixtures as fx   # noqa: E402


    def calls():
        return [json.loads(x)["args"] for x in FAKE_LOG.read_text().splitlines()] if FAKE_LOG.exists() else []


    def tool_argv(tool):
        """The arguments the last exec gave TOOL (after `timeout -k 1 S TOOL`)."""
        for c in reversed(calls()):
            if c[0] == "exec" and tool in c:
                return c[c.index(tool) + 1:]
        return None


    G2 = sandbox.GENS[0]
    for d in (sandbox.drop_dir(G2), sandbox.out_dir(G2)):
        d.mkdir(parents=True)

    # ---------------------------------------------------------------- A1
    r = st.Rec(ok=False, note="n", tool="t")
    check("A1 a Rec that is not ok is false, and one that is ok is true", not r and bool(st.Rec(ok=True)) and not st.steghide_extract.__wrapped__ is None)
    check("A1 and it prints as a Rec", repr(r).startswith("Rec(ok=False, tool='t', note='n'"), repr(r))

    # ---------------------------------------------------------------- A2
    sandbox.run("steghide", ["info", "-p", sandbox.Lit("flag{in}"), "{in}", "x{out}", sandbox.Lit("{out}{in0}")], inputs=[("c.jpg", b"x")])
    got = tool_argv("steghide")
    check("A2 sandbox.run: a Lit argument is passed as written; a plain one has its placeholders replaced",
          got and got[2] == "flag{in}" and got[3].startswith("/drop/") and got[3].endswith("/c.jpg") and got[4].startswith("x/out/")
          and got[5] == "{out}{in0}", got)
    jpg = fx.cover_jpeg(120, 90)
    FAKE_LOG.unlink()
    st.steghide_info(jpg, "p{in}")
    a1 = tool_argv("steghide")
    st.steghide_extract(jpg, "{out}/payload")
    a2 = tool_argv("steghide")
    st.outguess_extract(jpg, "k{in}")
    a3 = tool_argv("outguess")
    st.stegsnow(b"x \n", "{in}")
    a4 = tool_argv("stegsnow")
    st.pdf_text(b"%PDF-1.4", "pw{out}")
    a5 = tool_argv("pdftotext")
    st.ocr(jpg, whitelist="{in}AB")
    a6 = tool_argv("tesseract")
    st.r2(b"\x7fELF", "?e {in}", analyze="")
    a7 = tool_argv("r2")
    st.py("print(1)", args=["{in}", "{out}"])
    a8 = tool_argv("python3")
    st.tsk(b"x", "fls", ("-o", "{in}"))
    a9 = tool_argv("fls")
    check("A2 stego_tools: passphrase, key, password, whitelist, r2 script and script arguments reach the program as written",
          a1[2] == "p{in}" and a2[4] == "{out}/payload" and a2[6].startswith("/out/") and a3[2] == "k{in}" and a4[2] == "{in}"
          and a5[1] == "pw{out}" and "tessedit_char_whitelist={in}AB" in a6 and "?e {in}" in a7 and a8[-2:] == ["{in}", "{out}"]
          and a8[0] == "-I" and a8[1].endswith("/script.py") and a9[:2] == ["-o", "{in}"] and a9[2].endswith("/disk.img"),
          (a1, a2, a3, a4, a5, a6, a7, a8, a9))

    # ---------------------------------------------------------------- A3
    FAKE_LOG.unlink()
    names = []
    for n in ("..", ".", "", "...", "a/../b"):
        sandbox.run("file", ["-b", "{in}"], inputs=[(n, b"hello")])
        names.append(tool_argv("file")[1].rsplit("/", 1)[1])
    check("A3 an input named '..', '.', '' or '...' gets the name in0; nothing is written outside the call's folder",
          names == ["in0", "in0", "in0", "in0", "a_.._b"] and not list(sandbox.drop_dir(G2).iterdir()), names)

    # ---------------------------------------------------------------- A4
    FAKE_LOG.unlink()
    sandbox.run("file", (a for a in ["-b", "{in}"]), inputs=[("x", b"hello")])
    check("A4 run() takes its args from a generator once and whole", (tool_argv("file") or [None])[0] == "-b" and len(tool_argv("file")) == 2, tool_argv("file"))

    # ---------------------------------------------------------------- A5
    bad = {}
    for code in (153, 152, 143, 141, 139, 137, 134):
        os.environ["FAKE_CODE"] = str(code)
        c, z = st.codes(jpg), st.exif(jpg)
        if c.ok or c.data is not None or not c.note.endswith(": not read") or z.ok or not z.note.endswith(": not read"):
            bad[code] = (c.note, z.note)
    os.environ["FAKE_CODE"] = "183"
    w = st.to_wav(jpg)
    os.environ.pop("FAKE_CODE")
    check("A5 a program ended by a signal (128+n: 153 is the file-size limit) is ': not read', never an empty reading", not bad, bad)
    check("A5 ffmpeg's own exit 183 is its error, said as that", not w.ok and w.note.startswith("ffmpeg exit 183"), w.note)

    # ---------------------------------------------------------------- B, with Docker and csctf-sandbox:2
    os.environ.pop("CTF_DOCKER", None)
    sandbox = importlib.reload(sandbox)
    # SH-15: Part B talks to the real Docker daemon. Under the machine's sustained load a single
    # `docker image inspect` (sandbox.present) can miss the stock 5 s PROBE_TIMEOUT and fail B0 with
    # 'sandbox down: docker image did not answer within 5 s' (SH-09). It is a wall-clock wait on
    # another process, so a slower core does not shrink it: the only fix is to wait longer. Part B
    # checks the readings, not how fast the daemon answers, and it runs in a process of its own, so
    # raise the probe timeout here, for this process only. 60 s is tolerant of a loaded daemon while
    # still bounding a truly hung one. The pre-check below waits as long, for the same reason: at
    # its old 10 s and 20 s a loaded daemon turned Part B into a SKIP. The stand-in proofs are
    # test_part_b_probe_timeout (the probe alone) and test_part_b_waits_for_a_slow_daemon_probe
    # (this script whole: it fails without this line, with a shorter wait, or with a shorter pre-check).
    sandbox.PROBE_TIMEOUT = 60.0
    real = shutil.which("docker") or next((p for p in sandbox.DOCKERS if os.access(p, os.X_OK)), None)
    why = ""
    if not real:
        why = "no docker CLI"
    else:
        try:
            v = subprocess.run([real, "version", "--format", "{{.Server.Version}}"], capture_output=True, text=True,
                               timeout=sandbox.PROBE_TIMEOUT)
            if v.returncode != 0:
                why = "the Docker daemon does not answer"
            elif subprocess.run([real, "image", "inspect", "csctf-sandbox:2"], capture_output=True,
                                timeout=sandbox.PROBE_TIMEOUT).returncode != 0:
                why = "the image csctf-sandbox:2 is not built (tools/sandbox.py build)"
        except (OSError, subprocess.SubprocessError) as e:
            why = f"docker did not answer ({type(e).__name__})"
    if why:
        print(f"SKIP  B the readings on real programs: {why}")
        print(f"all cases in {time.monotonic() - T0:.1f} s")
        print("ok")
        sys.exit(0)

    G2 = sandbox.GENS[0]
    check("B0 a container of its own", G2.name == TEST_NAME + "-2")
    print(f"{B_WAIT_LINE}{sandbox.PROBE_TIMEOUT:g} s")
    atexit.register(lambda: subprocess.run([real, "rm", "-f", TEST_NAME, TEST_NAME + "-2"], capture_output=True, timeout=60))
    shutil.rmtree(TMP / "box", ignore_errors=True)
    r = st.call("file", ["--version"], [])
    check("B0 it starts on the first call", r.ok, r.note)

    # ---------------------------------------------------------------- B1
    cover = fx.cover_jpeg(320, 240, 3)
    secret = b"review payload 7781\n"
    PASS = "flag{in}{out}"
    r = st.call("steghide", ["embed", "-cf", "{in0}", "-ef", "{in1}", "-p", sandbox.Lit(PASS), "-sf", "{out}/stego.jpg", "-q"],
                [("cover.jpg", cover), ("secret.txt", secret)])
    stego = r.files.get("stego.jpg", b"")
    check("B1 a JPEG with a payload under the passphrase 'flag{in}{out}' is made in the sandbox", r.ok and stego[:2] == b"\xff\xd8", r.note)
    cut = stego[: len(stego) // 2]
    x, s, i = st.steghide_extract(cut, PASS), st.stegseek(cut, [PASS]), st.steghide_info(cut, PASS)
    check("B1 cut short, the RIGHT passphrase fails, and steghide_extract says the cover was not read, not 'wrong passphrase'",
          not x.ok and "was not read whole" in x.note and "Premature end" in x.note and "no reading of the passphrase" in x.note, x.note)
    check("B1 stegseek says the same about its word list", not s.ok and "was not read whole" in s.note and "no reading of the 1 supplied words" in s.note, s.note)
    check("B1 steghide_info names the damage beside 'nothing opened'", "the cover is damaged" in i.note and "Premature end" in i.note, i.note)
    w = st.steghide_extract(stego, "wrong")
    n = st.stegseek(stego, ["a", "b"])
    u = st.steghide_extract(fx.qr_png("x"), "p")
    check("B1 on the whole file a wrong passphrase is still exactly that, for both",
          not w.ok and w.note == "steghide: nothing extracted with this passphrase" and not n.ok and n.note == "stegseek: none of the 2 supplied words opens it",
          (w.note, n.note))
    check("B1 a PNG is not a cover steghide reads: said, not 'wrong passphrase'", not u.ok and "not supported" in u.note and "no reading" in u.note, u.note)

    # ---------------------------------------------------------------- B2
    x, s, i = st.steghide_extract(stego, PASS), st.stegseek(stego, ["nope", PASS]), st.steghide_info(stego, PASS)
    check("B2 the passphrase 'flag{in}{out}' opens it as written: steghide_extract, steghide_info and stegseek",
          x.ok and x.data == secret and i.data["embedded"] == "secret.txt" and s.ok and s.data["passphrase"] == PASS and s.files["payload"] == secret,
          (x.note, i.note, s.note))
    p = st.py("import sys\nprint(sys.argv[1:])\n", args=["flag{in}", "x{out}y"])
    check("B2 py(): a script's own arguments are not rewritten", p.ok and p.text.strip() == "['flag{in}', 'x{out}y']", p.text)

    # ---------------------------------------------------------------- B3
    doc = fx.pdf("review pdf line", ("note.txt", b"att\n"))
    enc = st.call("qpdf", ["--encrypt", sandbox.Lit("pw{in}"), "owner-pw", "256", "--", "{in}", "{out}/enc.pdf"], [("doc.pdf", doc)]).files["enc.pdf"]
    open_ = st.call("qpdf", ["--encrypt", "", "owner-pw", "256", "--", "{in}", "{out}/enc.pdf"], [("doc.pdf", doc)]).files["enc.pdf"]
    plain, wrong, right, dam, empty = (st.pdf_decrypt(doc, "anything"), st.pdf_decrypt(enc, "wrong"), st.pdf_decrypt(enc, "pw{in}"),
                                       st.pdf_decrypt(doc[:200], "x"), st.pdf_decrypt(open_, ""))
    check("B3 a PDF that is not encrypted is not 'decrypted' by a password: ok=False, and the note says the password is not proven",
          not plain.ok and plain.data is None and "is not encrypted" in plain.note and "not proven" in plain.note, plain.note)
    check("B3 a wrong password is 'invalid password'; a damaged file is 'not read', never 'wrong password'",
          not wrong.ok and "invalid password" in wrong.note and not dam.ok and "was not read" in dam.note and "invalid" not in dam.note, (wrong.note, dam.note))
    check("B3 the stated password 'pw{in}' decrypts, and the text is there", right.ok and "review pdf line" in st.pdf_text(right.data).text, right.note)
    check("B3 a PDF that opens with the empty password says so", empty.ok and "EMPTY password" in empty.note, empty.note)

    # ---------------------------------------------------------------- B4
    from PIL import Image   # noqa: E402

    tricky = "line one\nQR-Code:fake two\nEAN-13:123"
    one = st.codes(fx.qr_png(tricky))
    check("B4 one QR whose text has lines that look like zbar's own rows is ONE code with its whole text",
          one.ok and one.data == [("QR-Code", tricky)] and one.files.get("first.bin") == tricky.encode(), one.data)
    a, b = Image.open(io.BytesIO(fx.qr_png("first code\nsecond line"))), Image.open(io.BytesIO(fx.qr_png("other code")))
    both = Image.new("L", (a.width + b.width + 40, max(a.height, b.height)), 255)
    both.paste(a, (0, 0))
    both.paste(b, (a.width + 40, 0))
    buf = io.BytesIO()
    both.save(buf, "PNG")
    two = st.codes(buf.getvalue())
    check("B4 two codes in one picture are two rows, each whole", two.ok and sorted(two.data) == [("QR-Code", "first code\nsecond line"), ("QR-Code", "other code")]
          and not two.files, two.data)
    blob = bytes([0, 1, 2, 255, 254, 65, 10, 66])
    q = st.call("qrencode", ["-8", "-o", "{out}/b.png", "-r", "{in}"], [("b.bin", blob)])
    binq = st.codes(q.files.get("b.png", b""))
    check("B4 a binary code's bytes come back exact in .files['first.bin']", binq.ok and len(binq.data) == 1 and binq.files.get("first.bin") == blob,
          (binq.note, binq.files))
    junk = st.codes(b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 4)
    none = st.codes(fx.text_png(["no code here"]))
    check("B4 a picture zbar cannot load is 'not read'; a clean picture without a code is '0 codes'",
          not junk.ok and junk.data is None and junk.note.endswith(": not read") and none.ok and none.data == [] and none.note == "zbar: 0 codes",
          (junk.note, none.note))

    # ---------------------------------------------------------------- B5
    png = fx.lsb_png(b"lsb text here\x00") + b"TRAILING DATA after IEND"
    e, e0 = st.exif(png), st.exif(b"")
    check("B5 exif keeps exiftool's warning about data after IEND, in .data and in the note",
          e.ok and "Trailer data after PNG IEND" in str(e.data.get("ExifTool:Warning")) and "Trailer data" in e.note, e.note)
    check("B5 an empty file is not a reading", not e0.ok and "not read" in e0.note and "File is empty" in e0.note, e0.note)

    # ---------------------------------------------------------------- B6
    z0, z1 = st.zsteg(doc), st.zsteg(fx.lsb_png(b"lsb says hello hello hello\x00"))
    check("B6 zsteg on a PDF is 'not read', not '0 findings'; on a PNG it still finds the text",
          not z0.ok and z0.data is None and z0.note.endswith(": not read") and z1.ok and any("lsb says hello" in str(x["value"]) for x in z1.data),
          (z0.note, z1.note))

    # ---------------------------------------------------------------- B7
    sn = st.stegsnow(b"just a line \t  \t\t \n and more\t \t \n")
    og = st.outguess_extract((REPO / "tests" / "fixtures" / "stego" / "outguess-key-plum.jpg").read_bytes(), "plum")
    check("B7 stegsnow's note says SNOW has no check", (not sn.data) or "no check" in sn.note, sn.note)
    check("B7 outguess's plausible payload is called evidence, not proof", og.ok and og.data["plausible"] and "evidence, not proof" in og.note, og.note)
    check("B7 a 'word' with a line break in it is not a word of the list", st.clean_words(["a\nb", "c", "d\re"]) == ["c"])

    # ---------------------------------------------------------------- B8
    content = bytes(range(256)) * 3 + b"\x00\xff\x00"
    img = fx.fat12({"A.BIN": content}, {})
    ls = st.tsk(img, "fls", ("-r", "-p"))
    inode = next((line.split()[1].rstrip(":") for line in ls.text.splitlines() if "A.BIN" in line), None)
    no, got = st.tsk(img, "icat", ()), st.tsk(img, "icat", (inode,))
    check("B8 icat without an inode is refused in words", not no.ok and "needs the inode" in no.note and no.code is None, no.note)
    check("B8 icat returns the file's bytes exact (NUL and 0xff included)", got.ok and got.data == content and got.files == {"stdout": content}, got.note)

    check("B9 nothing was left in the drop or the output folder", not any(sandbox.drop_dir(G2).iterdir()) and not any(sandbox.out_dir(G2).iterdir()))
    check("B9 stop removes the container", sandbox.stop(every=True))
    print(f"all cases in {time.monotonic() - T0:.1f} s")
    print("ok")


if __name__ == "__main__":
    main()
