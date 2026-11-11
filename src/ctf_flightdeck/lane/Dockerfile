# The lane image: what a lane's shell has inside its container.
# Built only when you run `flightdeck image build` (it pulls the base image and Debian packages).
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv \
      python3-requests python3-pycryptodome python3-pil python3-numpy python3-sympy \
      file xxd bsdextrautils binutils \
      unzip p7zip-full bzip2 xz-utils zstd \
      curl ca-certificates netcat-openbsd jq git sqlite3 \
      libimage-exiftool-perl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
