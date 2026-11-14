# Multi-architecture pwn / RE environment for CSCTF 2026 ("Total Warfare" -> embedded / router / PLC
# targets, which are frequently ARM, AArch64 or MIPS, not just x86-64). It extends the x86-64
# docker/pwn image with qemu-user-static emulation and cross-compilers for the RISC targets, so a
# non-x86 challenge binary can be RUN and DEBUGGED here (never on the host, never off the assigned
# target), and small test fixtures can be cross-compiled.
#
# Built for linux/amd64 and run on Apple Silicon under Docker's emulation; qemu-user-static then runs
# the ARM/AArch64/MIPS guest binaries on top. This Dockerfile is written here for the orchestrator to
# build; the solver itself (solvers/toolkits/pwn_exploit.py) is OFFLINE/STATIC and never needs it.
#
# Build (from repo root):  docker build --platform linux/amd64 -t csctf-pwn-multiarch:1 docker/pwn-multiarch
# Use (mount a challenge dir read-only, no network):
#   docker run --rm -it --platform linux/amd64 --network none \
#       -v "$PWD/workspace/<id>/files":/chal:ro csctf-pwn-multiarch:1
# Run an emulated guest binary (static):   qemu-aarch64-static ./chall      (or qemu-arm/qemu-mips/qemu-mipsel)
# Debug under gdb-multiarch:               qemu-aarch64-static -g 1234 ./chall  &  gdb-multiarch ./chall -ex 'target remote :1234'
# For heap/ptrace work you may also need:  --cap-add=SYS_PTRACE --security-opt seccomp=unconfined
FROM --platform=linux/amd64 ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive PIP_NO_CACHE_DIR=1 PIP_BREAK_SYSTEM_PACKAGES=1

# Base toolchain + qemu-user-static (registers binfmt handlers for arm/aarch64/mips/mipsel) +
# gdb-multiarch. file/binutils/elfutils/patchelf for triage; nasm/ruby for the usual helpers.
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-dev \
      gdb gdb-multiarch \
      qemu-user qemu-user-static \
      gcc g++ make file xxd bsdmainutils \
      binutils elfutils patchelf \
      libc6-dbg \
      ltrace strace \
      ruby \
      git curl ca-certificates unzip \
      nasm \
 && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man

# Cross toolchains for the RISC targets. Each is guarded with `|| true` so a cross package that is not
# in the Ubuntu archive (or a transient mirror miss) does not fail the whole image build -- the qemu
# emulation above is enough to RUN a prebuilt challenge binary even if a given cross-gcc is missing.
# gnueabihf (hard-float) is included alongside gnueabi because most modern ARM userlands are hard-float.
RUN apt-get update && ( apt-get install -y --no-install-recommends \
      gcc-arm-linux-gnueabi      g++-arm-linux-gnueabi      || true ) \
 && ( apt-get install -y --no-install-recommends \
      gcc-arm-linux-gnueabihf    g++-arm-linux-gnueabihf    || true ) \
 && ( apt-get install -y --no-install-recommends \
      gcc-aarch64-linux-gnu      g++-aarch64-linux-gnu      || true ) \
 && ( apt-get install -y --no-install-recommends \
      gcc-mips-linux-gnu         g++-mips-linux-gnu         || true ) \
 && ( apt-get install -y --no-install-recommends \
      gcc-mipsel-linux-gnu       g++-mipsel-linux-gnu       || true ) \
 && ( apt-get install -y --no-install-recommends \
      gcc-mips64-linux-gnuabi64  g++-mips64-linux-gnuabi64  || true ) \
 && ( apt-get install -y --no-install-recommends \
      gcc-mips64el-linux-gnuabi64 g++-mips64el-linux-gnuabi64 || true ) \
 && ( apt-get install -y --no-install-recommends \
      libc6-arm64-cross libc6-armel-cross libc6-armhf-cross \
      libc6-mips-cross libc6-mipsel-cross || true ) \
 && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man

# pwntools + the standard static ROP finders. pwntools pulls compatible capstone/unicorn/pyelftools
# itself (capstone brings the ARM/AArch64/MIPS disassemblers pwn_exploit.py's gadget finder uses), so
# we do not pin those. ROPgadget and ropper both understand the RISC targets for cross-checking.
RUN pip3 install --no-cache-dir \
      pwntools \
      ROPgadget \
      ropper

# one_gadget for libc shell gadgets; pwndbg for interactive debugging of the emulated guests.
RUN gem install --no-document one_gadget || true
RUN git clone --depth 1 https://github.com/pwndbg/pwndbg /opt/pwndbg \
 && cd /opt/pwndbg && ./setup.sh --update || true \
 && echo 'source /opt/pwndbg/gdbinit.py' > /root/.gdbinit || true

WORKDIR /chal
CMD ["/bin/bash"]
