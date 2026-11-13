# ctf-runtime-jvm:25 (B-242): the pinned JVM the Java class / jar semantic adapter runs in.
#
# Built only by `python -m ctf toolchain build --apply --only runtime-jvm` (a human step, needs the
# network), which stamps the label org.ctf-tools.toolchain.hash; tools/sandbox.py runtime_run refuses
# an image whose label is not the hash of the files in docker/runtime/. The build context is
# docker/runtime (the entry script and the self-test are shared by every ctf-runtime-* image).
#
# Run only by runtime_run: no network, no host mount, read-only root, every capability dropped, an
# unprivileged user, the request on stdin and the trace on stdout. JDK 25 reads every class file
# version up to 69; a class compiled by a later JDK is reported as the load error it is.
FROM eclipse-temurin:25.0.5_8-jdk-noble@sha256:80f67fb3d6f76e2d817d98a4cc2a9cf05f054d4e6adc5e2144bde671d722e63f
COPY jvm/TraceRunner.java /opt/runner/TraceRunner.java
COPY selftest/Selftest.java /opt/selftest/Selftest.java
COPY entry.sh /usr/local/bin/ctf-runtime-entry
RUN chmod 755 /usr/local/bin/ctf-runtime-entry \
 && javac -d /opt/runner /opt/runner/TraceRunner.java \
 && javac -d /opt/selftest /opt/selftest/Selftest.java \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin runtime \
 && mkdir -p /work && chmod 1777 /work

# The self-test: the runner must trace our own class and report the string its static initialiser
# builds. A broken image fails the build here.
USER 10001:10001
ENV HOME=/tmp
RUN java -XX:+UseSerialGC -Xmx256m -cp /opt/runner TraceRunner --artifact /opt/selftest/Selftest.class \
      --fuel 1 --seconds 60 | grep -q 'ctf-selftest-ok'
WORKDIR /work
LABEL org.ctf-tools.image="runtime-jvm"
CMD ["/usr/local/bin/ctf-runtime-entry"]
