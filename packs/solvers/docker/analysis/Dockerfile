# csctf-analysis:1 — the reversing/symbolic-execution runtime image for the harnesses that
# solvers/binary/symbolic_harness.py and the lane-D concolic/firmware-emulation planners generate.
# Those engines only EMIT a plan + harness source (image_build_required=True); a human runs the
# generated harness inside THIS image. Build locally only:
#     docker build -t csctf-analysis:1 docker/analysis
# Run networkless, read-only root, like the other sandbox images (tools/sandbox.py conventions):
#     docker run --rm --pull=never --network none --read-only ... csctf-analysis:1
# It holds no token and reaches no network at run time.
FROM python:3.12-slim-trixie

ENV DEBIAN_FRONTEND=noninteractive PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# Build/runtime libs angr, unicorn, qiling and capstone/keystone need (angr builds some wheels).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential cmake pkg-config git \
      libffi-dev libssl-dev \
      file binutils \
 && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man

# Core symbolic/emulation stack. Let pip resolve a mutually-compatible set rather than pinning exact
# versions (angr, qiling and pwntools each constrain unicorn/capstone, so hard pins conflict). angr
# pulls claripy/pyvex/archinfo/cle; qiling pulls keystone-engine (no wheel on this platform — it builds
# libkeystone from source via cmake, installed above).
RUN pip install angr qiling pwntools capstone

# Triton's Python binding is not reliably pip-installable across platforms; add it best-effort so the
# image still builds (angr+qiling cover the generated harnesses). If the wheel is unavailable the
# build continues without Triton.
RUN pip install "triton-library==1.0" || echo "triton-library unavailable; angr/qiling stack is present"

# Smoke-check the stack imports at build time so a broken image never ships.
RUN python3 -c "import angr, qiling, capstone, unicorn; angr.Project; print('analysis stack OK:', angr.__version__)"

WORKDIR /work
CMD ["python3"]
