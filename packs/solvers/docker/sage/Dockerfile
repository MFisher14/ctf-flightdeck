# ctf-sage:<version> (B-188): one SageMath image per tagged release, side by side. A crypto challenge
# once needed Sage 10.5 because a later release's E.gens() gave a self-consistent but wrong answer, so
# the version is picked from the challenge's own notes (`python -m ctf toolchain versions <dir>`), not
# "latest". tools/images.toml lists one entry per tag, each passing SAGE_TAG; the build fails unless
# the image really is that release.
#
# Built only by `python -m ctf toolchain build --apply --only sage-<version>` (a human step). Upstream
# publishes amd64 only: it runs under emulation on Apple Silicon.
#   docker run --rm --platform linux/amd64 --network none --pull=never -v "$PWD":/work -w /work \
#     ctf-sage:10.5 sage solve.sage
ARG SAGE_TAG
FROM sagemath/sagemath:${SAGE_TAG}
ARG SAGE_TAG
RUN sage --version | grep -F "SageMath version ${SAGE_TAG},"
LABEL org.ctf-tools.image="sage" org.ctf-tools.sage-version="${SAGE_TAG}"
