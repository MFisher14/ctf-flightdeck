# ctf-runtime-dotnet:10 (B-242): the pinned .NET runtime the CIL semantic adapter runs in.
#
# Built only by `python -m ctf toolchain build --apply --only runtime-dotnet` (a human step, needs the
# network), which stamps the label org.ctf-tools.toolchain.hash; tools/sandbox.py runtime_run refuses
# an image whose label is not the hash of the files in docker/runtime/. The build context is
# docker/runtime (the entry script and the self-test are shared by every ctf-runtime-* image).
#
# Run only by runtime_run: no network, no host mount, read-only root, every capability dropped, an
# unprivileged user, the request on stdin and the trace on stdout.

# ---- compile the runner and the self-test assembly with the pinned SDK ---------------------------
FROM mcr.microsoft.com/dotnet/sdk:10.0.404-noble@sha256:fe0fd4e93bd2fbb47c883b7a6369e5c8d3db8bf01cdc5981f6ee35fbdf3ff4fb AS build
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
COPY dotnet/TraceRunner.cs dotnet/TraceRunner.csproj /src/runner/
COPY selftest/Selftest.cs selftest/Selftest.csproj /src/selftest/
RUN dotnet publish /src/runner/TraceRunner.csproj -c Release -o /opt/runner \
 && dotnet build /src/selftest/Selftest.csproj -c Release -o /opt/selftest

# ---- the runtime image: the shared framework only, no SDK ----------------------------------------
FROM mcr.microsoft.com/dotnet/runtime:10.0.15-noble@sha256:80a51954ac70925e5783cb1ed35129a4243dcb1cddef20066b67346e17db284d
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_EnableDiagnostics=0 DOTNET_gcServer=0 \
    DOTNET_TieredPGO=0 DOTNET_CLI_HOME=/tmp HOME=/tmp
COPY --from=build /opt/runner /opt/runner
COPY --from=build /opt/selftest/Selftest.dll /opt/selftest/Selftest.dll
COPY entry.sh /usr/local/bin/ctf-runtime-entry
RUN chmod 755 /usr/local/bin/ctf-runtime-entry \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin runtime \
 && mkdir -p /work && chmod 1777 /work

# The self-test: the runner must trace our own assembly and report the string its static constructor
# builds. A broken image fails the build here.
USER 10001:10001
RUN dotnet /opt/runner/TraceRunner.dll --artifact /opt/selftest/Selftest.dll --fuel 1 --seconds 60 \
    | grep -q 'ctf-selftest-ok'
WORKDIR /work
LABEL org.ctf-tools.image="runtime-dotnet"
CMD ["/usr/local/bin/ctf-runtime-entry"]
