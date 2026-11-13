#!/bin/sh
# ctf-boot-envcheck (B-131): the boot image's own env-check. Every binary and firmware file the
# harness names, each missing one reported; exit 1 when any is missing. Run at build time and by
# `python -m ctf toolchain smoke qemu-boot`. It boots nothing.
fail=0
for b in qemu-system-x86_64 qemu-img socat; do
  command -v "$b" >/dev/null 2>&1 || { echo "MISSING binary $b"; fail=1; }
done
for f in /opt/ctf-boot/OVMF_CODE.fd /opt/ctf-boot/OVMF_VARS.fd; do
  [ -s "$f" ] || { echo "MISSING firmware $f"; fail=1; }
done
if [ "$fail" = 0 ]; then echo "ctf-qemu-boot env-check OK"; fi
exit "$fail"
