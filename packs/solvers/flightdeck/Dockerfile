# The image the pack's engines run in when lanes run in Docker (`flightdeck pack image` builds it).
# Debian trixie with Python 3.12 (the pack's pins need both: several have wheels only for its
# newer C library), the command-line tools the engines call most, what flightdeck's lane image
# has (so lanes can run in this image too: [l1] lane_tools), and the pack's Python
# environment at /opt/flightdeck-pack/venv. The pack itself is mounted read-only by flightdeck
# at run time, never copied in.
FROM ghcr.io/astral-sh/uv:0.11.2 AS uv
FROM python:3.12-slim-trixie
ARG LANE_IMAGE=unused
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update && apt-get install -y --no-install-recommends \
      bash coreutils file xxd bsdextrautils binutils unzip 7zip bzip2 xz-utils zstd sqlite3 \
      curl ca-certificates netcat-openbsd jq git \
      libimage-exiftool-perl binwalk tshark qpdf zbar-tools tesseract-ocr \
      mdbtools nasm upx-ucl john \
      libmagic1 libzbar0 libgmp10 libmpfr6 libmpc3 \
      build-essential pkg-config curl ca-certificates libgmp-dev libmpfr-dev libmpc-dev libssl-dev libffi-dev \
 && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man \
 && ln -s "$(command -v 7z)" /usr/local/bin/7zz
# Not in this image, and named by `flightdeck doctor` as missing: sage (several GB), and john's zip2john and
# rar2john (the jumbo build only; docker/toolkit builds it).
COPY --from=uv /uv /usr/local/bin/uv
COPY requirements.txt requirements.lock.txt maint/overrides.txt /tmp/pack/
# A few pins have no Linux wheel for every CPU and build from source with Rust (base2048 on arm64):
# the toolchain is there for the build only and is removed after it.
RUN curl --proto '=https' --tlsv1.2 -fsS https://sh.rustup.rs | sh -s -- -y --profile minimal --no-modify-path \
 && export PATH=/root/.cargo/bin:$PATH \
 && uv venv -p /usr/local/bin/python3.12 /opt/flightdeck-pack/venv \
 && uv pip install --no-cache -p /opt/flightdeck-pack/venv/bin/python \
      -r /tmp/pack/requirements.lock.txt -r /tmp/pack/requirements.txt --override /tmp/pack/overrides.txt \
 && rm -rf /tmp/pack /root/.cargo /root/.rustup
# A lane that runs in this image ([l1] lane_tools) gets the pack's Python, with its libraries, as python3.
ENV PATH=/opt/flightdeck-pack/venv/bin:$PATH
# A debugger and a decompiler, as flightdeck's own lane image has them (its lane/Dockerfile says
# why they come from where they do): gdb, with gdb-multiarch for a binary of another architecture,
# and radare2 6.2.4 with its r2ghidra plugin (`pdg`), each archive checked against its SHA-256.
# `binary.decompile_intake` finds r2 here, so it decompiles a native binary at intake and when a
# lane's model runs it. In layers of their own, after the Python environment: a change here
# rebuilds only these.
RUN apt-get update && apt-get install -y --no-install-recommends gdb gdb-multiarch \
 && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man
RUN set -eu; \
    arch=$(dpkg --print-architecture); \
    case "$arch" in \
      amd64) r2_sha=7019eedc0e0e87d1f53d6b8f5fc62b898567679c5efdce7fbfc557c9e7655e90; \
             plugin=x86-64; plugin_sha=344a7a2be1fb89d1780b0f5c9ee02c41255fec1cde90eb45bf3d313a43881b7a ;; \
      arm64) r2_sha=bbf48ee7bd5d8282f65a297dcabd34c9961a500e62d6b036679caab187b32ef1; \
             plugin=arm-64; plugin_sha=a8ac843c4e23e6cbf3c4e0975d84215f4706172109130fa0ee2229bc56faec26 ;; \
      *) echo "the pack image: radare2 6.2.4 is released for amd64 and arm64, not for $arch" >&2; exit 1 ;; \
    esac; \
    cd /tmp; \
    curl -fsSL -o radare2.deb "https://github.com/radareorg/radare2/releases/download/6.2.4/radare2_6.2.4_${arch}.deb"; \
    echo "$r2_sha  radare2.deb" | sha256sum -c -; \
    dpkg -i radare2.deb; \
    curl -fsSL -o r2ghidra.zip "https://github.com/radareorg/r2ghidra/releases/download/6.2.4/r2ghidra-6.2.4-linux-${plugin}.zip"; \
    echo "$plugin_sha  r2ghidra.zip" | sha256sum -c -; \
    plugins=$(r2 -H R2_LIBR_PLUGINS); \
    mkdir -p "$plugins" r2ghidra; \
    unzip -q r2ghidra.zip 'plugins/*' -d r2ghidra; \
    cp -R r2ghidra/plugins/. "$plugins"/; \
    rm -rf radare2.deb r2ghidra.zip r2ghidra; \
    r2 -q -c 'Lc' -- | grep -q ghidra

WORKDIR /work
