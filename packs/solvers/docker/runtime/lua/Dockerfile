# ctf-runtime-lua:1 (B-242): the pinned Lua interpreters the Lua semantic adapter runs in: PUC Lua
# 5.1, 5.2, 5.3 and 5.4 and LuaJIT, side by side. Lua bytecode only loads on the VM version that made
# it, so the adapter picks the interpreter from the chunk header (and 5.4 for source).
#
# Built only by `python -m ctf toolchain build --apply --only runtime-lua` (a human step, needs the
# network), which stamps the label org.ctf-tools.toolchain.hash; tools/sandbox.py runtime_run refuses
# an image whose label is not the hash of the files in docker/runtime/. The build context is
# docker/runtime (the entry script and the self-test are shared by every ctf-runtime-* image).
#
# The interpreters are pinned too: apt reads the Debian archive as it was on the base image's own
# date (snapshot.debian.org, 20261104T000000Z, the date in the base tag), never the moving
# deb.debian.org, so a rebuild installs the same package versions. The snapshot's Release files are
# older than apt's validity window, hence Check-Valid-Until=false (the signatures are still checked).
#
# Run only by runtime_run: no network, no host mount, read-only root, every capability dropped, an
# unprivileged user, the request on stdin and the trace on stdout.
FROM debian:bookworm-20261104-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
ENV DEBIAN_FRONTEND=noninteractive HOME=/tmp
RUN printf '%s\n' \
      'Types: deb' \
      'URIs: http://snapshot.debian.org/archive/debian/20261104T000000Z' \
      'Suites: bookworm bookworm-updates' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      '' \
      'Types: deb' \
      'URIs: http://snapshot.debian.org/archive/debian-security/20261104T000000Z' \
      'Suites: bookworm-security' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      > /etc/apt/sources.list.d/debian.sources \
 && rm -f /etc/apt/sources.list \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends lua5.1 lua5.2 lua5.3 lua5.4 luajit \
 && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man
COPY lua/trace_runner.lua /opt/runner/trace_runner.lua
COPY selftest/selftest.lua /opt/selftest/selftest.lua
COPY entry.sh /usr/local/bin/ctf-runtime-entry
RUN chmod 755 /usr/local/bin/ctf-runtime-entry \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin runtime \
 && mkdir -p /work && chmod 1777 /work

# The self-test: every interpreter must run our own chunk through the runner and report the string
# the chunk builds. A broken image fails the build here.
USER 10001:10001
RUN for vm in lua5.1 lua5.2 lua5.3 lua5.4 luajit; do \
      "$vm" /opt/runner/trace_runner.lua --artifact /opt/selftest/selftest.lua --fuel 1000000 \
        | grep -q 'ctf-selftest-ok' || exit 1; \
    done
WORKDIR /work
LABEL org.ctf-tools.image="runtime-lua"
CMD ["/usr/local/bin/ctf-runtime-entry"]
