# ctf-qemu-boot:1 (B-131): QEMU (x86-64 system emulation, TCG) with OVMF and socat, for the disk-image
# boot harness (ctf/diskboot.py, `python -m ctf disk-boot`). A challenge that is a bootable disk set is
# booted here and looked at over QMP: screenshots and keystrokes, nothing else.
#
# Booting a challenge image runs challenge code, so the container is the boundary:
#   - `python -m ctf disk-boot start` (the operator's step) runs it with --network none, --read-only,
#     every capability dropped and no-new-privileges; QEMU itself gets `-nic none`;
#   - the handout is mounted read-only at /img and QEMU runs with -snapshot (its overlay goes to
#     $TMPDIR, which the harness points at /out/.snapshot);
#   - QMP listens on a Unix socket in the tmpfs /run/boot; the harness reaches it with
#     `docker exec -i <container> socat - UNIX-CONNECT:/run/boot/qmp.sock`, so no port is published.
#
# Built only by `python -m ctf toolchain build --apply --only qemu-boot` (a human step). The firmware
# files are copied to fixed names so the harness does not depend on the distribution's paths; the
# build fails when the package stops shipping them.
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends qemu-system-x86 qemu-utils ovmf socat \
 && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man

# OVMF under fixed names (the 4 MiB build; VARS is a template: -snapshot keeps it unwritten).
RUN mkdir -p /opt/ctf-boot \
 && cp /usr/share/OVMF/OVMF_CODE_4M.fd /opt/ctf-boot/OVMF_CODE.fd \
 && cp /usr/share/OVMF/OVMF_VARS_4M.fd /opt/ctf-boot/OVMF_VARS.fd \
 && chmod 0444 /opt/ctf-boot/OVMF_CODE.fd /opt/ctf-boot/OVMF_VARS.fd

# The env-check; the build runs it, so a broken image never ships.
COPY envcheck.sh /usr/local/bin/ctf-boot-envcheck
RUN chmod 755 /usr/local/bin/ctf-boot-envcheck && ctf-boot-envcheck

RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin boot \
 && mkdir -p /img /out /run/boot && chown boot /out /run/boot
USER boot
ENV HOME=/tmp
WORKDIR /out
LABEL org.ctf-tools.image="qemu-boot"
CMD ["ctf-boot-envcheck"]
