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
 && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man
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
WORKDIR /work
