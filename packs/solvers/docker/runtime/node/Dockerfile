# ctf-runtime-node:<major> (B-242): one pinned Node.js per major line, for the JavaScript / V8
# cached-data semantic adapter. V8 only accepts cached data (a bytenode .jsc) made by the same V8, so
# tools/images.toml lists one image per Node line (20, 22, 24), each passing its own base image as
# NODE_REF (an exact tag and its digest); the adapter tries them newest first for a .jsc.
#
# Built only by `python -m ctf toolchain build --apply --only runtime-node-24` (a human step, needs the
# network), which stamps the label org.ctf-tools.toolchain.hash; tools/sandbox.py runtime_run refuses
# an image whose label is not the hash of the files in docker/runtime/ and its build args. The build
# context is docker/runtime (the entry script and the self-test are shared by every ctf-runtime-*
# image). The runner needs Node's built-in modules only: nothing is installed.
#
# Run only by runtime_run: no network, no host mount, read-only root, every capability dropped, an
# unprivileged user, the request on stdin and the trace on stdout.
ARG NODE_REF
FROM ${NODE_REF}
ENV NODE_ENV=production HOME=/tmp
COPY node/trace_runner.js /opt/runner/trace_runner.js
COPY selftest/selftest.js /opt/selftest/selftest.js
COPY entry.sh /usr/local/bin/ctf-runtime-entry
RUN chmod 755 /usr/local/bin/ctf-runtime-entry \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin runtime \
 && mkdir -p /work && chmod 1777 /work

# The self-test: the runner must run our own script and report the string it builds. A broken image
# fails the build here.
USER 10001:10001
RUN node /opt/runner/trace_runner.js --artifact /opt/selftest/selftest.js --fuel 1 --seconds 60 \
    | grep -q 'ctf-selftest-ok'
WORKDIR /work
LABEL org.ctf-tools.image="runtime-node"
CMD ["/usr/local/bin/ctf-runtime-entry"]
