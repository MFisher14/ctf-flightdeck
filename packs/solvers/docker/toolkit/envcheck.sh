#!/bin/sh
# ctf-envcheck (B-188): the toolkit image's own env-check. Every binary and module the image promises,
# each missing one named; exit 1 when any is missing. Run at build time and by `ctf toolchain smoke`.
fail=0
for b in tshark zsteg john 7z 7z2john.pl zip2john rar2john python3 perl; do
  command -v "$b" >/dev/null 2>&1 || { echo "MISSING binary $b"; fail=1; }
done
perl -MCompress::Raw::Lzma -e 1 >/dev/null 2>&1 \
  || { echo "MISSING perl module Compress::Raw::Lzma (7z2john.pl needs it)"; fail=1; }
for m in capstone lief pefile unicorn elftools Crypto z3 sympy gmpy2 scapy pwnlib; do
  python3 -I -c "import importlib.util, sys; sys.exit(importlib.util.find_spec('$m') is None)" \
    || { echo "MISSING python module $m"; fail=1; }
done
if [ "$fail" = 0 ]; then echo "ctf-toolkit env-check OK"; fi
exit "$fail"
