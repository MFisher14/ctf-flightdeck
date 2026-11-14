# The lane image: what a lane's shell has inside its container.
# Built only when you run `flightdeck image build` (it pulls the base image and Debian packages,
# and two release archives from github.com, each checked against its SHA-256 below).
# Debian 13: the decompiler's release build needs its C library (Debian 12's is too old for it).
FROM debian:trixie-slim

# gdb is the debugger; gdb-multiarch is the same debugger built to read a binary of any
# architecture (the image's own gdb reads only its own).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv \
      python3-requests python3-pycryptodome python3-pil python3-numpy python3-sympy \
      file xxd bsdextrautils binutils \
      unzip 7zip bzip2 xz-utils zstd \
      curl ca-certificates netcat-openbsd jq git sqlite3 \
      libimage-exiftool-perl \
      gdb gdb-multiarch \
 && rm -rf /var/lib/apt/lists/*

# The decompiler: radare2 with its r2ghidra plugin (Ghidra's decompiler as a native library, so
# no Java), `pdg` inside r2. Debian packages neither, so both come from their projects' own
# 6.2.4 releases, which exist for amd64 and arm64: the build stops, saying so, on any other
# architecture and on an archive that is not the one pinned here. The plugin and its processor
# files go to radare2's system plugin folder, so they are there whatever a lane's HOME is, and
# the last line fails the build unless r2 lists the plugin as loaded.
RUN set -eu; \
    arch=$(dpkg --print-architecture); \
    case "$arch" in \
      amd64) r2_sha=7019eedc0e0e87d1f53d6b8f5fc62b898567679c5efdce7fbfc557c9e7655e90; \
             plugin=x86-64; plugin_sha=344a7a2be1fb89d1780b0f5c9ee02c41255fec1cde90eb45bf3d313a43881b7a ;; \
      arm64) r2_sha=bbf48ee7bd5d8282f65a297dcabd34c9961a500e62d6b036679caab187b32ef1; \
             plugin=arm-64; plugin_sha=a8ac843c4e23e6cbf3c4e0975d84215f4706172109130fa0ee2229bc56faec26 ;; \
      *) echo "the lane image: radare2 6.2.4 is released for amd64 and arm64, not for $arch" >&2; exit 1 ;; \
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
