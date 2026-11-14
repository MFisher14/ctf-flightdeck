# ctf-runtime-wasm:1 (B-242): the pinned, fuel-bounded WebAssembly runtime (wasmtime) the Wasm semantic
# adapter runs in.
#
# Built only by `python -m ctf toolchain build --apply --only runtime-wasm` (a human step, needs the
# network), which stages toolchain-requirements.txt (wasmtime at its requirements.in pin) and
# toolchain-constraints.txt, and stamps the label org.ctf-tools.toolchain.hash; tools/sandbox.py
# runtime_run refuses an image whose label is not the hash of the files in docker/runtime/. The build
# context is docker/runtime (the entry script and the self-test are shared by every ctf-runtime-* image).
#
# Run only by runtime_run: no network, no host mount, read-only root, every capability dropped, an
# unprivileged user, the request on stdin and the trace on stdout.
FROM python:3.12.16-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1 HOME=/tmp
COPY toolchain-requirements.txt toolchain-constraints.txt /tmp/
RUN pip install -r /tmp/toolchain-requirements.txt -c /tmp/toolchain-constraints.txt \
 && rm -f /tmp/toolchain-requirements.txt /tmp/toolchain-constraints.txt
COPY wasm/trace_runner.py /opt/runner/trace_runner.py
COPY selftest/selftest.wat /opt/selftest/selftest.wat
COPY entry.sh /usr/local/bin/ctf-runtime-entry
RUN chmod 755 /usr/local/bin/ctf-runtime-entry \
 && python3 -c "import wasmtime; open('/opt/selftest/selftest.wasm', 'wb').write(bytes(wasmtime.wat2wasm(open('/opt/selftest/selftest.wat').read())))" \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin runtime \
 && mkdir -p /work && chmod 1777 /work

# The self-test: the runner must run our own module and report the string it decodes in memory. A
# broken image fails the build here.
USER 10001:10001
RUN python3 -I /opt/runner/trace_runner.py --artifact /opt/selftest/selftest.wasm --fuel 1000000 \
    | grep -q 'ctf-selftest-ok'
WORKDIR /work
LABEL org.ctf-tools.image="runtime-wasm"
CMD ["/usr/local/bin/ctf-runtime-entry"]
