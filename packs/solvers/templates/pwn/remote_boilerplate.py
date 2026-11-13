#!/usr/bin/env python3
"""CSCTF pwn template -- remote/local boilerplate (start here for any pwn challenge).

FILL-ME
  BINARY   : challenge ELF
  LIBC     : challenge libc (optional, for ret2libc)
  HOST,PORT: the assigned remote target (from the challenge page / `./csctf` client)

Run flags (pwntools args):
  python3 solve.py REMOTE        -> connect to HOST:PORT (the real target)
  python3 solve.py               -> local process (docker/pwn only)
  python3 solve.py GDB           -> local under gdb (docker/pwn, needs SYS_PTRACE)

SCOPE: only the squad's ASSIGNED target. No scanning, no flooding, no off-target connections. Run
everything in the docker/pwn image (csctf-pwn:1), never on the Mac.

Recon the binary first (offline, never runs it):
  .venv/bin/python solvers/toolkits/pwn.py BINARY
  .venv/bin/python solvers/toolkits/pwn_exploit.py BINARY --gadgets
"""
from pwn import *

# ---- FILL-ME -------------------------------------------------------------
BINARY = "./chall"
LIBC = ""                         # e.g. "./libc.so.6" (optional)
HOST, PORT = "CHALLENGE.HOST", 0
GDB_SCRIPT = """
# b *main
continue
"""
# --------------------------------------------------------------------------

context.binary = exe = ELF(BINARY, checksec=True)
libc = ELF(LIBC, checksec=False) if LIBC else None
context.terminal = ["tmux", "splitw", "-h"]   # if running under tmux in docker/pwn


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    if args.GDB:
        return gdb.debug(exe.path, gdbscript=GDB_SCRIPT)
    return process(exe.path)


def find_offset(maxlen=400):
    """Crash with a cyclic pattern and report the saved-RIP offset (local, docker/pwn only)."""
    io = process(exe.path)
    io.sendline(cyclic(maxlen, n=8))
    io.wait()
    core = io.corefile
    rip = core.read(core.rsp, 8)
    log.success("offset to saved RIP = %d", cyclic_find(rip, n=8))


def main():
    io = start()
    # ---- your exploit here ----
    io.interactive()      # look for the CSCTF{...} flag


if __name__ == "__main__":
    main()
