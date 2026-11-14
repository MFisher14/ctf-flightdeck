# ctf-runtime-python:<version> (B-242): one pinned CPython per minor version, for the cross-version
# .pyc semantic adapter. A .pyc is only read by the CPython that wrote it, so tools/images.toml lists
# one image per version (3.8 to 3.14), each passing its own base image as PYTHON_REF (an exact tag and
# its digest); the adapter picks the image from the .pyc magic number.
#
# Built only by `python -m ctf toolchain build --apply --only runtime-python-3.12` (a human step, needs
# the network), which stamps the label org.ctf-tools.toolchain.hash; tools/sandbox.py runtime_run
# refuses an image whose label is not the hash of the files in docker/runtime/ and its build args. The
# build context is docker/runtime (the entry script and the self-test are shared by every
# ctf-runtime-* image). The runner needs the standard library only: nothing is installed.
#
# Run only by runtime_run: no network, no host mount, read-only root, every capability dropped, an
# unprivileged user, the request on stdin and the trace on stdout.
ARG PYTHON_REF
FROM ${PYTHON_REF}
ENV PYTHONDONTWRITEBYTECODE=1 HOME=/tmp
COPY python/trace_runner.py /opt/runner/trace_runner.py
COPY selftest/selftest.py /opt/selftest/selftest.py
COPY entry.sh /usr/local/bin/ctf-runtime-entry
RUN chmod 755 /usr/local/bin/ctf-runtime-entry \
 && python3 -c "import py_compile; py_compile.compile('/opt/selftest/selftest.py', cfile='/opt/selftest/selftest.pyc', doraise=True)" \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin runtime \
 && mkdir -p /work && chmod 1777 /work

# The self-test: the runner must run our own .pyc (compiled by this very interpreter) and report the
# string the module builds. A broken image fails the build here.
USER 10001:10001
RUN python3 -I /opt/runner/trace_runner.py --artifact /opt/selftest/selftest.pyc --fuel 1000000 \
    | grep -q 'ctf-selftest-ok'
WORKDIR /work
LABEL org.ctf-tools.image="runtime-python"
CMD ["/usr/local/bin/ctf-runtime-entry"]
