# ctf-toolkit:1 (B-188): the pinned toolkit image. Everything agents reached for in play and found
# missing or broken: tshark, zsteg, john jumbo with a WORKING 7z2john (its Perl module
# Compress::Raw::Lzma), 7-Zip, and the Python RE/crypto stack (capstone, lief, pefile, unicorn,
# pyelftools, pycryptodome, z3, sympy, gmpy2, scapy, pwntools) at the master's own pins.
#
# Built only by `python -m ctf toolchain build --apply --only toolkit` (a human step), which:
#   - stages this folder plus toolchain-requirements.txt (the `py` names of tools/images.toml at their
#     requirements.in pins) and toolchain-constraints.txt (every requirements.in pin), so the image and
#     the host venv never disagree on a version;
#   - passes JOHN_URL / JOHN_SHA256 from tools/images.toml (the build refuses while the hash is empty);
#   - stamps the label org.ctf-tools.toolchain.hash, so an unchanged image is never rebuilt.
# Run it networkless like the sandbox images (`python -m ctf toolchain smoke toolkit` runs its env-check):
#   docker run --rm --network none --pull=never --cap-drop ALL -v "$PWD":/work -w /work ctf-toolkit:1 <tool>

# ---- john jumbo from its pinned source tarball, checked against the manifest's SHA-256 ---------------
FROM python:3.12-slim-trixie AS john
ARG JOHN_URL
ARG JOHN_SHA256
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential pkg-config yasm ca-certificates \
      libssl-dev zlib1g-dev libbz2-dev libgmp-dev libpcap-dev \
 && rm -rf /var/lib/apt/lists/*
RUN python3 - <<'PY'
import hashlib, io, os, tarfile, urllib.request
url, want = os.environ["JOHN_URL"], os.environ["JOHN_SHA256"]
assert want, "JOHN_SHA256 is empty: record the sha256 of the john tarball in tools/images.toml"
data = urllib.request.urlopen(url, timeout=300).read()
assert hashlib.sha256(data).hexdigest() == want, "john source checksum mismatch"
with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
    tf.extractall("/src", filter="data")
PY
# Portable build (no -march=native: the image runs on other hosts). GCC 14 turns some old C warnings
# into errors, which are relaxed back to warnings here; the build still fails on a real error.
RUN cd /src/john-*/src \
 && ./configure --disable-native-tests --disable-opencl \
      CFLAGS="-O2 -fcommon -Wno-error=implicit-function-declaration -Wno-error=incompatible-pointer-types -Wno-error=int-conversion" \
 && make -s -j"$(nproc)" \
 && cp -a ../run /opt/john \
 && test -x /opt/john/john && test -f /opt/john/7z2john.pl

# ---- the image -------------------------------------------------------------------------------------
FROM python:3.12-slim-trixie

ENV DEBIAN_FRONTEND=noninteractive PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1

# tshark (no setuid question), Ruby for zsteg, Perl with Compress::Raw::Lzma for 7z2john, 7-Zip, and
# the runtime libraries of the john build.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      tshark ruby perl libcompress-raw-lzma-perl 7zip xz-utils file binutils \
      libssl3t64 zlib1g libbz2-1.0 libgmp10 libpcap0.8t64 \
 && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man

# zsteg, pinned (the same version as csctf-sandbox:2).
RUN gem install --no-document zsteg -v 0.2.13 && command -v zsteg

# john and its *2john helpers onto PATH.
COPY --from=john /opt/john /opt/john
RUN ln -s /opt/john/john /usr/local/bin/john \
 && for f in /opt/john/*2john*; do ln -s "$f" /usr/local/bin/; done \
 && perl -c /opt/john/7z2john.pl

# The Python stack at the master's pins (staged by ctf toolchain build from requirements.in).
COPY toolchain-requirements.txt toolchain-constraints.txt /tmp/
RUN pip install -r /tmp/toolchain-requirements.txt -c /tmp/toolchain-constraints.txt \
 && rm -f /tmp/toolchain-requirements.txt /tmp/toolchain-constraints.txt

# The env-check every agent can run first; the build runs it, so a broken image never ships.
COPY envcheck.sh /usr/local/bin/ctf-envcheck
RUN chmod 755 /usr/local/bin/ctf-envcheck && ctf-envcheck

RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin toolkit && mkdir -p /work && chown toolkit /work
USER toolkit
ENV HOME=/tmp XDG_CACHE_HOME=/tmp/cache
WORKDIR /work
LABEL org.ctf-tools.image="toolkit"
CMD ["ctf-envcheck"]
