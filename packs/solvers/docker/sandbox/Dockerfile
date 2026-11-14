# Backlog row 91: the sandbox image for hostile-format tools (tools/sandbox.py).
# Built locally only:  .venv/bin/python tools/sandbox.py build   (docker build -t csctf-sandbox:1 tools/sandbox)
# Nothing in it holds a token or reaches the network at run time: tools/sandbox.py starts the
# container with --network none, a read-only root, no home or repository mount, CPU, memory and
# process limits, a read-only drop (/drop) and one small writable output folder (/out).
FROM python:3.12-slim-trixie

ENV DEBIAN_FRONTEND=noninteractive PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1

# tshark, binwalk, 7-Zip (7z) and YARA from Debian; tshark is asked no debconf question.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends tshark binwalk 7zip yara file xz-utils \
 && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man

# upx from its own release, the same 5.2.1 the player installed with Homebrew (Debian's upx-ucl is
# 4.2.4, which may not unpack what a 5.x packer made), checked against its pinned SHA-256.
RUN python3 - <<'PY'
import hashlib, io, subprocess, tarfile, urllib.request
arch = subprocess.check_output(["dpkg", "--print-architecture"], text=True).strip()
sums = {"arm64": "a72d112c5970a904a31da0b9c84f919bc16b9a311787c12245508544a78c7d36",
        "amd64": "402162aad30af47e60dbd767fb2e64ca394ace9727ba1f40283641f1d1b91657"}
url = f"https://github.com/upx/upx/releases/download/v5.2.1/upx-5.2.1-{arch}_linux.tar.xz"
data = urllib.request.urlopen(url, timeout=120).read()
assert hashlib.sha256(data).hexdigest() == sums[arch], "upx release checksum mismatch"
with tarfile.open(fileobj=io.BytesIO(data), mode="r:xz") as tf:
    member = next(m for m in tf.getmembers() if m.name.endswith("/upx"))
    open("/usr/local/bin/upx", "wb").write(tf.extractfile(member).read())
PY
RUN chmod 755 /usr/local/bin/upx && upx --version | head -1

# Volatility 3 and oletools from PyPI, pinned.
RUN pip install volatility3==2.7.0 oletools==0.60.2

# Backlog row 167: the leftover-killing wrapper. tools/sandbox.py runs a tool through it as
# `csctf-run S TOOL ARGS`, which runs `timeout -k 1 S TOOL ARGS` in a new session (setsid, so a
# new process group) and kills the whole group when the call ends, so children the tool leaves
# behind (a 7z worker, a volatility subprocess) die instead of filling the container's pids limit.
# The exit status is passed through. tools/sandbox.py only uses it when it is present, so an older
# image without it still works; the build smoke-tests exit-code passthrough (and so setsid).
RUN printf '%s\n' \
    '#!/bin/sh' \
    'S=$1' 'shift' \
    'setsid timeout -k 1 "$S" "$@" &' \
    'pid=$!' \
    'trap "kill -TERM -$pid 2>/dev/null" EXIT HUP INT TERM' \
    'wait "$pid"; code=$?' \
    'kill -TERM -$pid 2>/dev/null' \
    'exit $code' \
    > /usr/local/bin/csctf-run \
 && chmod 755 /usr/local/bin/csctf-run \
 && csctf-run 3 sh -c 'exit 7'; [ "$?" = 7 ]

# The tools run as an unprivileged user; /drop is mounted read-only, /out is the only writable
# place besides a small /tmp.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin sandbox \
 && mkdir -p /drop /out && chown sandbox /out
USER sandbox
# The root is read-only at run time: every tool caches under the tmpfs /tmp.
ENV HOME=/tmp XDG_CACHE_HOME=/tmp/cache
WORKDIR /out
LABEL csctf.sandbox="row-91"
# The container only waits; every tool is run in it by `docker exec` (tools/sandbox.py run).
CMD ["sleep", "infinity"]
