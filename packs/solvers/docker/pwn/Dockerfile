# x86-64 Linux pwn / RE environment for CSCTF, built for linux/amd64 and run on Apple Silicon
# under Docker's emulation. It gives a real x86-64 userland plus qemu-user so a challenge binary
# can run and be debugged, and the usual exploitation toolchain.
#
# Build (from repo root):  docker build --platform linux/amd64 -t csctf-pwn:1 docker/pwn
# Use (mount a challenge dir read-only, no network):
#   docker run --rm -it --platform linux/amd64 --network none -v "$PWD/workspace/<id>/files":/chal:ro csctf-pwn:1
# For heap/debug work you may need:  --cap-add=SYS_PTRACE --security-opt seccomp=unconfined
FROM --platform=linux/amd64 ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive PIP_NO_CACHE_DIR=1 PIP_BREAK_SYSTEM_PACKAGES=1

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

# pwntools + the standard exploitation helpers. pwntools pulls compatible capstone/unicorn/pyelftools
# itself, so we don't pin those (a conflicting pin breaks the resolve). angr/symbolic execution runs on
# the host venv — it lifts x86-64 regardless of host arch — so it stays out of this emulated image.
RUN pip3 install --no-cache-dir \
      pwntools \
      ROPgadget \
      ropper

# one_gadget and pwndbg for debugging
RUN gem install --no-document one_gadget || true
RUN git clone --depth 1 https://github.com/pwndbg/pwndbg /opt/pwndbg \
 && cd /opt/pwndbg && ./setup.sh --update || true \
 && echo 'source /opt/pwndbg/gdbinit.py' > /root/.gdbinit || true

# Convenience: GEF as an alternative to pwndbg (comment the .gdbinit line above to switch)
RUN curl -fsSL https://raw.githubusercontent.com/hugsy/gef/main/gef.py -o /opt/gef.py || true

WORKDIR /chal
CMD ["/bin/bash"]
