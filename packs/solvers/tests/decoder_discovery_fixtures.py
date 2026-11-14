#!/usr/bin/env python3
"""Builder of the synthetic native fixtures for tests/test_binary_decoder_discovery.py (B-166).

Each fixture is ONE small C file of our own, compiled by clang for x86-64 and AArch64 Linux and laid out
as a real shared object by the single-object linker in tests/native_image_fixtures.py (`link_so`: PT_LOAD
segments, PLT/GOT, RELATIVE relocations, DT_INIT). Nothing here is a challenge file, and nothing built
here is ever run on the host: the tests only read the images and emulate functions of them.

The plaintexts, keys and constants live in this file as Python values; the C tables are generated from
them, and the test file recomputes every expected value with its own Python model of each function, so a
compiler, linker or emulator mistake fails a test instead of passing silently.

Rebuild the committed fixtures (needs clang):

    .venv/bin/python -I -B tests/decoder_discovery_fixtures.py [--out tests/fixtures/decoder_discovery]
"""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import native_image_fixtures as nif  # noqa: E402  (the single-object ELF linker; test infrastructure)

OUT = HERE / "fixtures" / "decoder_discovery"
TARGETS = {"x86_64": "x86_64-linux-gnu", "arm64": "aarch64-linux-gnu"}

# ----------------------------------------------------------------------------------------- the values
FLAG = b"CSCTF{d3c0d3r_b0und_at_th3_c4ll_s1te}"
XOR_KEY = 0x5A                      # dd_xor_decode's key at the call site in main
MIX_M1 = 0x6F2B8A4D93C5E1B7         # arbitrary odd multipliers (no textbook or challenge constant)
MIX_M2 = 0xC3A5F18E7D2B964B
MIX_SEED = 0x1337
ROUND_ARGS = (0x10, 3)
WORD_INDEX = 2                      # dd_word's argument in main (the table is alpha, bravo, charlie, delta)

DECOY_A = b"CSCTF{th1s_0ne_is_a_d3c0y}"
DECOY_B = b"CSCTF{th1s_0ne_is_r34l}"
TWIN_SEED = 0x77

INOUT_PLAIN = b"caller filled this first"            # 24 bytes, what main stores before the call
INOUT_KEY = 0x42

STATE_FLAG = b"CSCTF{c0nstruct0r_pr3p4red_th3_t4ble}"
STATE_CTOR_KEY = 0xA7
STATE_BLOB = b"the quick brown fox jumps over the lazy dog"
STATE_BLOB_KEY = 0x33

LEAD_FLAG = b"CSCTF{th3_l34d_b0und_th3_k3y}"
LEAD_KEY = 0x5A

NEVER_FLAG = b"CSCTF{n0th1ng_c4lls_th1s_0ne}"
NEVER_KEY = 0x3C
LABEL = "omega"

PRINT_FLAG = b"CSCTF{pr1nt3d_by_th3_d3c0d3r}"     # B-166 fix round 1: decoders that print their output
PRINT_KEY = 0x29
PRINT_FMT_ARGS = (-42, 123456789012)               # dd_fmt's arguments in main
PRINT_MANY_ARG = 10                                # dd_many's argument in main


def enc_xor(plain, key):
    """What dd_xor_decode / dd_keyed undo: p[i] ^ ((key + 7 * i) & 0xff)."""
    return bytes(p ^ ((key + 7 * i) & 0xFF) for i, p in enumerate(plain))


def enc_state_table(plain):
    """The .data table before the constructor: ((p + 3 * i) & 0xff) ^ STATE_CTOR_KEY."""
    return bytes((((p + 3 * i) & 0xFF) ^ STATE_CTOR_KEY) for i, p in enumerate(plain))


def enc_state_blob(plain):
    """What dd_unmask undoes: p == ((c ^ k) - i) & 0xff, so c == ((p + i) & 0xff) ^ k."""
    return bytes((((p + i) & 0xFF) ^ STATE_BLOB_KEY) for i, p in enumerate(plain))


def enc_never(plain):
    """What dd_never_out / dd_never_ret undo: p[i] ^ ((NEVER_KEY + i) & 0xff)."""
    return bytes(p ^ ((NEVER_KEY + i) & 0xFF) for i, p in enumerate(plain))


def enc_print(plain):
    """What dd_print_flag / dd_putc_flag / dd_write_flag undo: p[i] ^ ((PRINT_KEY + i) & 0xff)."""
    return bytes(p ^ ((PRINT_KEY + i) & 0xFF) for i, p in enumerate(plain))


def c_bytes(data):
    return ", ".join("0x%02x" % b for b in data)


# ----------------------------------------------------------------------------------------- C sources
PRELUDE = r'''
#define HID __attribute__((visibility("hidden"), noinline))
int puts(const char *);
unsigned long strlen(const char *);
void *malloc(unsigned long);
void *memcpy(void *, const void *, unsigned long);

/* first in .text, so no decoder is the function a disassembler names after the (absent) entry point;
   nothing calls it and nothing marks it a decoder */
int dd_abi(void) { return 1; }
'''

DD_FLAG_C = PRELUDE + r'''
static const unsigned char ENC[%(n)d] = { %(enc)s };
static const char *const WORDS[4] = { "alpha", "bravo", "charlie", "delta" };

/* a buffer decoder: input pointer, length, key, output buffer (all bound at the call site in main) */
HID void dd_xor_decode(const unsigned char *in, unsigned long n, unsigned key, char *out) {
    for (unsigned long i = 0; i < n; i++) out[i] = (char)(in[i] ^ (unsigned char)(key + 7 * i));
    out[n] = 0;
}

/* an invertible word mixer (the B-026 lead shape): one integer in, one out */
HID unsigned long dd_mix(unsigned long x) {
    x ^= x >> 31; x *= %(m1)sUL; x ^= x >> 27; x *= %(m2)sUL; x ^= x >> 33;
    return x;
}

/* returns a pointer through a relocated pointer table */
HID const char *dd_word(int i) { return WORDS[i & 3]; }

/* reads a table through its pointer argument and returns an integer */
HID unsigned dd_sum(const unsigned char *p, unsigned long n) {
    unsigned h = 0x811c9dc5u;
    for (unsigned long i = 0; i < n; i++) h = ((h << 5) | (h >> 27)) ^ p[i];
    return h;
}

/* a looped per-character routine whose argument only exists at run time (never bound) */
HID int dd_checksum(const char *s) {
    int h = 7;
    while (*s) h = h * 31 + (unsigned char)*s++;
    return h;
}

/* default visibility: main reaches it through the PLT */
__attribute__((noinline)) unsigned long dd_round(unsigned long x, int k) {
    for (int i = 0; i < k; i++) x = (x ^ (unsigned long)i) * 0x100000001b3UL;
    return x;
}

/* reads a pointer the loader relocates (a writable global pointer to a string) */
const char *dd_label = "%(label)s";
HID unsigned dd_first(void) { return (unsigned char)dd_label[0]; }

/* hands its own argument on to strlen (through the PLT, a libc function the emulator models) */
HID unsigned long dd_len(const char *s) { return strlen(s) + 1; }

int main(int argc, char **argv) {
    char buf[64];
    dd_xor_decode(ENC, sizeof ENC, %(key)d, buf);
    puts(buf);
    unsigned long m = dd_mix(%(seed)dUL);
    puts(dd_word(%(word)d));
    return dd_checksum(argv[1]) + (int)m + (int)dd_round(%(r0)d, %(r1)d) + (int)dd_sum(ENC, sizeof ENC)
        + (int)dd_first() + (int)dd_len("hello, decoder");
}
'''

DD_DECOY_C = PRELUDE + r'''
static const unsigned char ENC_A[%(na)d] = { %(enc_a)s };
static const unsigned char ENC_B[%(nb)d] = { %(enc_b)s };

HID void dd_dec_a(const unsigned char *in, unsigned long n, char *out) {
    for (unsigned long i = 0; i < n; i++) out[i] = (char)(in[i] ^ 0x21);
    out[n] = 0;
}
HID void dd_dec_b(const unsigned char *in, unsigned long n, char *out) {
    for (unsigned long i = 0; i < n; i++) out[i] = (char)(in[i] - 13);
    out[n] = 0;
}
/* two different one-integer routines called with the SAME constant */
HID unsigned long dd_twin_a(unsigned long x) { x ^= x >> 7; x *= 0x9E5B3A71UL; return x ^ (x >> 11); }
HID unsigned long dd_twin_b(unsigned long x) { x += 0x1234567UL; x *= 0x85D1C3A9UL; return x ^ (x >> 13); }

int main(void) {
    char a[64], b[64];
    dd_dec_a(ENC_A, sizeof ENC_A, a);
    dd_dec_b(ENC_B, sizeof ENC_B, b);
    puts(a);
    puts(b);
    return (int)(dd_twin_a(%(twin)dUL) + dd_twin_b(%(twin)dUL));
}
'''

DD_INOUT_C = PRELUDE + r'''
static const unsigned char SEED[%(n)d] = { %(seed)s };

/* decodes in place: the caller's stack buffer is its INPUT as well as its output */
HID void dd_inplace(char *buf, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) buf[i] = (char)(buf[i] ^ %(key)d);
}

/* writes through one pointer and reads through the other: only meaningful when they alias */
HID int dd_alias(char *a, char *b) { a[0] = 'x'; return b[0]; }

/* returns a string it built on the heap */
HID char *dd_dup(unsigned k) {
    char *p = (char *)malloc(8);
    p[0] = 'h'; p[1] = 'e'; p[2] = 'a'; p[3] = 'p'; p[4] = (char)('0' + (k & 7)); p[5] = 0;
    return p;
}

/* returns a heap string whose text depends on the block's address */
HID char *dd_addr(void) {
    char *p = (char *)malloc(8);
    p[0] = (char)('a' + (((unsigned long)p >> 4) & 15)); p[1] = (char)('a' + (((unsigned long)p >> 8) & 15));
    p[2] = 0;
    return p;
}

int main(void) {
    char buf[32];
    for (int i = 0; i < %(n)d; i++) buf[i] = (char)SEED[i];
    buf[%(n)d] = 0;
    dd_inplace(buf, %(n)d);
    puts(buf);
    puts(dd_dup(3));
    puts(dd_addr());
    return dd_alias(buf, buf);
}
'''

DD_STATE_C = PRELUDE + r'''
static unsigned char TABLE[%(n)d] = { %(table)s };          /* .data: the constructor decrypts it */
static char OUT[64];                                          /* .bss */
static unsigned char BLOB[%(nb)d] = { %(blob)s };           /* .data: decoded in place through a pointer */

void dd_init(void) {                                          /* DT_INIT */
    for (int i = 0; i < %(n)d; i++) TABLE[i] ^= %(ckey)d;
}

/* no argument: fills a global buffer from the prepared table and returns it */
HID const char *dd_table_flag(void) {
    for (int i = 0; i < %(n)d; i++) OUT[i] = (char)(TABLE[i] - 3 * i);
    OUT[%(n)d] = 0;
    return OUT;
}

/* decodes a global buffer in place through its pointer argument */
HID void dd_unmask(unsigned char *p, unsigned long n, unsigned char k) {
    for (unsigned long i = 0; i < n; i++) p[i] = (unsigned char)((p[i] ^ k) - i);
}

/* three single-byte writes into a zero global: two close together, one far away (the array is
   external, so the compiler keeps every store) */
unsigned char dd_pad[128];
HID void dd_poke(void) { dd_pad[0] = 1; dd_pad[8] = 2; dd_pad[100] = 3; }

/* copies eight stack bytes it never wrote into a global: what the global then holds is undefined */
unsigned char dd_sink[8];
HID void dd_leak(void) { unsigned char tmp[8]; memcpy(dd_sink, tmp, sizeof tmp); }

int main(void) {
    puts(dd_table_flag());
    dd_unmask(BLOB, sizeof BLOB, %(bkey)d);
    puts((const char *)BLOB);
    dd_poke();
    dd_leak();
    return dd_pad[100] + dd_sink[0];
}
'''

DD_LEAD_C = PRELUDE + r'''
static const unsigned char ENC[%(n)d] = { %(enc)s };

/* the same decoder shape as dd_xor_decode, but main passes a key the call-site scan cannot bind */
HID void dd_keyed(const unsigned char *in, unsigned long n, unsigned key, char *out) {
    for (unsigned long i = 0; i < n; i++) out[i] = (char)(in[i] ^ (unsigned char)(key + 7 * i));
    out[n] = 0;
}

/* one integer in, one out; main only ever passes it a run-time value */
HID unsigned dd_late(unsigned k) {
    unsigned v = 0x9e3779b9u;
    for (unsigned i = 0; i < 16; i++) { v ^= k + i; v = (v << 5) | (v >> 27); v *= 0x01000193u; }
    return v;
}

/* nothing calls or references it: in a stripped image no symbol and no call target names it */
__attribute__((used, visibility("hidden"), noinline)) unsigned dd_orphan(unsigned k) {
    unsigned v = k ^ 0x5bd1e995u;
    for (unsigned i = 0; i < 4; i++) v = (v >> 3) ^ (v * 0x2545f491u);
    return v;
}

int main(int argc, char **argv) {
    char buf[64];
    volatile unsigned key = %(key)d;       /* stored to the stack, read back after another call */
    puts("decoding");
    dd_keyed(ENC, sizeof ENC, key, buf);
    puts(buf);
    return (int)dd_late((unsigned)argv[0][0] + (unsigned)argc);
}
'''


DD_NEVER_C = PRELUDE + r'''
static const unsigned char ENC[%(n)d] = { %(enc)s };
static char OUT[64];
unsigned dd_never_key = %(key)d;      /* an external, writable key: the compiler cannot fold the decode */

/* nothing calls either decoder: one fills its argument, one a global buffer it returns */
__attribute__((used, visibility("hidden"), noinline)) void dd_never_out(char *out) {
    for (int i = 0; i < %(n)d; i++) out[i] = (char)(ENC[i] ^ (unsigned char)(dd_never_key + i));
    out[%(n)d] = 0;
}
__attribute__((used, visibility("hidden"), noinline)) const char *dd_never_ret(void) {
    for (int i = 0; i < %(n)d; i++) OUT[i] = (char)(ENC[i] ^ (unsigned char)(dd_never_key + i));
    OUT[%(n)d] = 0;
    return OUT;
}

int main(void) { puts("nothing to see"); return 0; }
'''

# B-166 fix round 1: decoders that print their own output, and the printf shapes the emulator's captured
# sinks take or refuse.
DD_PRINT_C = PRELUDE + r'''
int printf(const char *, ...);
int putchar(int);
long write(int, const void *, unsigned long);

static const unsigned char ENC[%(n)d] = { %(enc)s };
unsigned dd_print_key = %(key)d;      /* an external, writable key: the compiler cannot fold the decode */

/* decodes and prints in one function: nothing comes back to the caller */
HID void dd_print_flag(void) {
    char buf[64];
    for (int i = 0; i < %(n)d; i++) buf[i] = (char)(ENC[i] ^ (unsigned char)(dd_print_key + i));
    buf[%(n)d] = 0;
    printf("flag: %%s\n", buf);
}

/* the same, one character at a time */
HID void dd_putc_flag(void) {
    for (int i = 0; i < %(n)d; i++) putchar(ENC[i] ^ (unsigned char)(dd_print_key + i));
    putchar('\n');
}

/* the same, through write(2) to standard error */
HID void dd_write_flag(void) {
    char buf[64];
    for (int i = 0; i < %(n)d; i++) buf[i] = (char)(ENC[i] ^ (unsigned char)(dd_print_key + i));
    write(2, buf, %(n)d);
}

/* every printf conversion the model takes, its integers bound at the call site */
HID int dd_fmt(int v, unsigned long w) {
    return printf("[%%5d|%%-4x|%%04X|%%c|%%.3s|%%hhd|%%lu|%%06d|%%%%]\n", v, 0xab, 0xbeefu, 'Z', "abcdef", 300, w, v);
}

/* more variadic arguments than argument registers: the rest are on the caller's stack */
HID int dd_many(int a) {
    return printf("%%d %%d %%d %%d %%d %%d %%d %%d|\n", a, a + 1, a + 2, a + 3, a + 4, a + 5, a + 6, a + 7);
}

/* a conversion the model refuses (an address) */
HID int dd_fmt_ptr(void) { return printf("%%p\n", (void *)&dd_print_key); }

/* stdio and write(2) on the same descriptor: the order depends on stdio's buffering */
HID void dd_mixed(void) { puts("a"); write(1, "b", 1); }

/* returns what puts returns: "a non-negative value" the C libraries choose differently */
HID int dd_puts_ret(void) { return puts("x"); }

/* a descriptor that is not standard output or standard error */
HID void dd_badfd(void) { write(3, "z", 1); }

/* standard output through write(2) alone */
HID void dd_write1(void) { write(1, "ok\n", 3); }

/* glibc's FORTIFY form: a flag before the format */
int __printf_chk(int, const char *, ...);
HID int dd_chk(int v) { return __printf_chk(1, "chk %%d\n", v); }

/* a looped decoder-like routine that calls an import the emulator neither models nor captures */
int rand(void);
HID int dd_rand_decode(int v) {
    int s = 0;
    for (int i = 0; i < v; i++) s ^= rand() + i * 7;
    return s;
}

/* prints an address: the text differs between the two layouts */
HID void dd_print_addr(void) { printf("%%lx\n", (unsigned long)&dd_print_key); }

int main(void) {
    dd_print_flag();
    dd_putc_flag();
    dd_write_flag();
    dd_fmt(%(v)d, %(w)dUL);
    dd_many(%(a)d);
    dd_fmt_ptr();
    dd_mixed();
    dd_badfd();
    dd_write1();
    dd_chk(%(a)d);
    dd_print_addr();
    dd_rand_decode(5);
    return dd_puts_ret();
}
'''

# Nothing decoder-like at all: one trivial function and a main that only prints.
DD_PLAIN_C = PRELUDE + r'''
/* called with a constant, but all it does is print through an import the emulator does not model */
HID void dd_show(int k) { puts(k ? "yes" : "no"); }

int main(void) { puts("hello"); dd_show(1); return 0; }
'''

# Hand-written call sites for the register tracker: each function sets up one or two calls to tk_sink
# (three integer arguments) in a shape the tests name.
DD_TRACK_X86_S = r'''
    .intel_syntax noprefix
    .text
    .globl tk_sink
    .hidden tk_sink
    .type tk_sink,@function
tk_sink:
    lea rax, [rdi + rsi]
    add rax, rdx
    ret
    .size tk_sink, .-tk_sink

    .globl tk_other
    .hidden tk_other
    .type tk_other,@function
tk_other:
    mov eax, 1
    ret
    .size tk_other, .-tk_other

    .globl tk_join
    .type tk_join,@function
tk_join:
    mov edi, 5
    mov edx, 9
    test esi, esi
    je 1f
    mov edi, 7
1:
    mov esi, 3
    call tk_sink
    ret
    .size tk_join, .-tk_join

    .globl tk_clobber
    .type tk_clobber,@function
tk_clobber:
    push rbx
    mov edi, 5
    mov ebx, 0x77
    call tk_other
    mov rsi, rbx
    mov edx, 1
    call tk_sink
    pop rbx
    ret
    .size tk_clobber, .-tk_clobber

    .globl tk_slot
    .type tk_slot,@function
tk_slot:
    sub rsp, 24
    mov dword ptr [rsp + 4], 0x2a
    mov qword ptr [rsp + 8], 0x10
    mov edi, dword ptr [rsp + 4]
    mov rsi, qword ptr [rsp + 8]
    lea rdx, [rsp + 16]
    call tk_sink
    mov edi, dword ptr [rsp + 4]
    mov esi, 2
    mov edx, 3
    call tk_sink
    add rsp, 24
    ret
    .size tk_slot, .-tk_slot

    .globl tk_overlap
    .type tk_overlap,@function
tk_overlap:
    sub rsp, 24
    mov qword ptr [rsp + 8], 0x10
    mov dword ptr [rsp + 12], 5
    mov rdi, qword ptr [rsp + 8]
    mov dword ptr [rsp], 7
    mov qword ptr [rsp + 16], 9
    add dword ptr [rsp + 16], 1
    mov rdx, qword ptr [rsp + 16]
    mov esi, dword ptr [rsp]
    call tk_sink
    add rsp, 24
    ret
    .size tk_overlap, .-tk_overlap

    .globl tk_arith
    .type tk_arith,@function
tk_arith:
    lea rax, [rip + tk_table]
    lea rdi, [rax + 8]
    mov esi, 0x1234
    add rsi, 0x20
    sub rsi, 0x10
    xor edx, edx
    call tk_sink
    mov rdi, qword ptr [rip + tk_global@GOTPCREL]
    mov ecx, 0xffffffff
    mov esi, ecx
    mov edx, 4
    mov dl, 1
    call tk_sink
    ret
    .size tk_arith, .-tk_arith

    .globl tk_tail
    .type tk_tail,@function
tk_tail:
    mov edi, 1
    mov esi, 2
    mov edx, 3
    jmp tk_sink
    .size tk_tail, .-tk_tail

    .globl tk_frame
    .type tk_frame,@function
tk_frame:
    sub rsp, 40
    lea rdi, [rsp + 8]
    sub rsp, 16
    mov esi, 1
    mov edx, 2
    call tk_sink
    add rsp, 56
    ret
    .size tk_frame, .-tk_frame

    .globl tk_wrap
    .type tk_wrap,@function
tk_wrap:
    sub rsp, 8
    mov edx, 1
    call tk_sink
    add rsp, 8
    ret
    .size tk_wrap, .-tk_wrap

    .globl tk_after
    .type tk_after,@function
tk_after:
    sub rsp, 8
    call tk_other
    add rax, rdi
    add rsp, 8
    ret
    .size tk_after, .-tk_after

    .globl tk_env
    .type tk_env,@function
tk_env:
    mov rax, qword ptr fs:[0x28]
    mov eax, 60
    syscall
    ret
    .size tk_env, .-tk_env

    .globl tk_tls
    .type tk_tls,@function
tk_tls:
    mov qword ptr fs:[0x28], 1
    xor eax, eax
    ret
    .size tk_tls, .-tk_tls

    .globl tk_unary_ok
    .type tk_unary_ok,@function
tk_unary_ok:
    mov rax, rdi
    xor rax, 9
    ret
    .size tk_unary_ok, .-tk_unary_ok

    .globl tk_unary_env
    .type tk_unary_env,@function
tk_unary_env:
    mov rax, rdi
    xor rax, 5
    syscall
    ret
    .size tk_unary_env, .-tk_unary_env

    .globl tk_unary_ind
    .type tk_unary_ind,@function
tk_unary_ind:
    sub rsp, 8
    mov rax, rdi
    xor rax, 7
    call rax
    add rsp, 8
    ret
    .size tk_unary_ind, .-tk_unary_ind

    .globl tk_unary_imp
    .type tk_unary_imp,@function
tk_unary_imp:
    sub rsp, 8
    xor rdi, 1
    call puts@PLT
    add rsp, 8
    ret
    .size tk_unary_imp, .-tk_unary_imp

    .globl tk_unary_noret
    .type tk_unary_noret,@function
tk_unary_noret:
    mov rax, rdi
    xor rax, 2
    ud2
    .size tk_unary_noret, .-tk_unary_noret

    .globl tk_unary_trunc
    .type tk_unary_trunc,@function
tk_unary_trunc:
    mov rax, rdi
    xor rax, 3
    ret
    .byte 0x06
    .size tk_unary_trunc, .-tk_unary_trunc

    .globl tk_last
    .type tk_last,@function
tk_last:
    mov edi, 4
    call tk_only
    ret
    .size tk_last, .-tk_last

    .globl tk_only
    .hidden tk_only
    .type tk_only,@function
tk_only:
    lea eax, [rdi + 2]
    ret
    .size tk_only, .-tk_only

# B-166 fix round 1: what a stack buffer holds at the call (vector stores of constants, integer stores)
    .globl tk_vec
    .type tk_vec,@function
tk_vec:
    sub rsp, 56
    movaps xmm0, xmmword ptr [rip + tk_vconst]
    movups xmmword ptr [rsp], xmm0
    pxor xmm1, xmm1
    movups xmmword ptr [rsp + 16], xmm1
    mov byte ptr [rsp + 32], 0x21
    lea rax, [rip + tk_table]
    mov qword ptr [rsp + 40], rax
    mov rdi, rsp
    mov esi, 1
    mov edx, 2
    call tk_sink
    movups xmmword ptr [rsp], xmm0
    mov rdi, rsp
    mov esi, 1
    mov edx, 2
    call tk_sink
    add rsp, 56
    ret
    .size tk_vec, .-tk_vec

    .globl tk_vec_flow
    .type tk_vec_flow,@function
tk_vec_flow:
    sub rsp, 40
    movaps xmm0, xmmword ptr [rip + tk_vconst]
    test esi, esi
    je 1f
1:
    movups xmmword ptr [rsp], xmm0
    mov rdi, rsp
    call tk_sink
    movaps xmm0, xmmword ptr [rip + tk_vconst]
    lea rax, [rip + 2f]
    jmp rax
2:
    movups xmmword ptr [rsp], xmm0
    mov rdi, rsp
    call tk_sink
    add rsp, 40
    ret
    .size tk_vec_flow, .-tk_vec_flow

    .globl tk_vec_clobber
    .type tk_vec_clobber,@function
tk_vec_clobber:
    sub rsp, 40
    movaps xmm0, xmmword ptr [rip + tk_vconst]
    paddb xmm0, xmm0
    movups xmmword ptr [rsp], xmm0
    movaps xmm1, xmmword ptr [rip + tk_vconst]
    movaps xmm1, xmmword ptr [rip + tk_vdata]
    movups xmmword ptr [rsp + 16], xmm1
    movups xmm2, xmmword ptr [rsp + 32]
    movups xmmword ptr [rsp + 32], xmm2
    mov rdi, rsp
    call tk_sink
    add rsp, 40
    ret
    .size tk_vec_clobber, .-tk_vec_clobber

    .globl tk_vec_far
    .type tk_vec_far,@function
tk_vec_far:
    sub rsp, 0x1100
    mov byte ptr [rsp], 1
    mov dword ptr [rsp + 0xff8], 7
    mov qword ptr [rsp + 0xffc], 5
    mov rdi, rsp
    call tk_sink
    mov dword ptr [rsp + 8], 1
    lea rdi, [rbp - 0x20]
    call tk_sink
    add rsp, 0x1100
    ret
    .size tk_vec_far, .-tk_vec_far

# functions that print and show exactly one kind of decoder structure (a loop, byte access, indexed access)
    .globl tk_pr_loop
    .type tk_pr_loop,@function
tk_pr_loop:
    mov ecx, 3
1:
    dec ecx
    jne 1b
    jmp puts@PLT
    .size tk_pr_loop, .-tk_pr_loop

    .globl tk_pr_byte
    .type tk_pr_byte,@function
tk_pr_byte:
    movzx eax, byte ptr [rsi]
    jmp puts@PLT
    .size tk_pr_byte, .-tk_pr_byte

    .globl tk_pr_table
    .type tk_pr_table,@function
tk_pr_table:
    mov eax, dword ptr [rsi + rdx*4]
    jmp puts@PLT
    .size tk_pr_table, .-tk_pr_table

    .globl tk_pr_none
    .type tk_pr_none,@function
tk_pr_none:
    mov eax, esi
    jmp puts@PLT
    .size tk_pr_none, .-tk_pr_none

    .section .rodata
    .p2align 4
tk_vconst:
    .ascii "sixteen byte str"
    .p2align 3
tk_table:
    .quad 1, 2, 3, 4

    .data
    .globl tk_global
    .p2align 3
    .type tk_global,@object
tk_global:
    .quad 0x1122334455667788
    .size tk_global, 8
    .p2align 4
tk_vdata:
    .ascii "writable, not k!"
'''

DD_TRACK_A64_S = r'''
    .text
    .globl tk_sink
    .hidden tk_sink
    .type tk_sink,%function
tk_sink:
    add x0, x0, x1
    add x0, x0, x2
    ret
    .size tk_sink, .-tk_sink

    .globl tk_other
    .hidden tk_other
    .type tk_other,%function
tk_other:
    mov w0, #1
    ret
    .size tk_other, .-tk_other

    .globl tk_movk
    .type tk_movk,%function
tk_movk:
    stp x29, x30, [sp, #-16]!
    mov x0, #0x5678
    movk x0, #0x1234, lsl #16
    movk x0, #0x9abc, lsl #32
    adrp x1, tk_table
    add x1, x1, :lo12:tk_table
    add x1, x1, #8
    mov x2, #0xffff
    movk x2, #0x7
    bl tk_sink
    ldp x29, x30, [sp], #16
    ret
    .size tk_movk, .-tk_movk

    .globl tk_movk_arg
    .type tk_movk_arg,%function
tk_movk_arg:
    movk x0, #0x12, lsl #16
    ret
    .size tk_movk_arg, .-tk_movk_arg

    .globl tk_join
    .type tk_join,%function
tk_join:
    stp x29, x30, [sp, #-16]!
    mov w0, #5
    mov w2, #9
    cbz x1, 1f
    mov w0, #7
1:
    mov w1, #3
    bl tk_sink
    ldp x29, x30, [sp], #16
    ret
    .size tk_join, .-tk_join

    .globl tk_clobber
    .type tk_clobber,%function
tk_clobber:
    stp x29, x30, [sp, #-32]!
    str x19, [sp, #16]
    mov w0, #5
    mov w19, #0x77
    bl tk_other
    mov x1, x19
    mov w2, #1
    bl tk_sink
    ldr x19, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
    .size tk_clobber, .-tk_clobber

    .globl tk_stack
    .type tk_stack,%function
tk_stack:
    sub sp, sp, #48
    str x30, [sp, #40]
    add x0, sp, #8
    mov w1, #1
    mov w2, #2
    bl tk_sink
    add x0, sp, #8
    sub sp, sp, #16
    mov w1, #1
    mov w2, #2
    bl tk_sink
    add sp, sp, #16
    ldr x30, [sp, #40]
    add sp, sp, #48
    ret
    .size tk_stack, .-tk_stack

    .globl tk_tail
    .type tk_tail,%function
tk_tail:
    mov w0, #1
    mov w1, #2
    mov w2, #3
    b tk_sink
    .size tk_tail, .-tk_tail

    .globl tk_wrap
    .type tk_wrap,%function
tk_wrap:
    mov w2, #1
    b tk_sink
    .size tk_wrap, .-tk_wrap

    .globl tk_after
    .type tk_after,%function
tk_after:
    stp x29, x30, [sp, #-16]!
    bl tk_other
    add x0, x0, x1
    ldp x29, x30, [sp], #16
    ret
    .size tk_after, .-tk_after

    .globl tk_env
    .type tk_env,%function
tk_env:
    mov x8, #93
    svc #0
    ret
    .size tk_env, .-tk_env

    .globl tk_sub
    .type tk_sub,%function
tk_sub:
    stp x29, x30, [sp, #-16]!
    mov x0, #0x40
    sub x0, x0, #0x10
    adrp x1, tk_table
    add x1, x1, :lo12:tk_table
    add x1, x1, #24
    sub x1, x1, #8
    mov w2, #0
    bl tk_sink
    ldp x29, x30, [sp], #16
    ret
    .size tk_sub, .-tk_sub

    .section .rodata
    .p2align 3
tk_table:
    .quad 1, 2, 3, 4
'''


# B-166 fix round 1: the stripped-image function-start scan. gp_main calls gp_fwd, gp_table, gp_odd, gp_tail
# and gp_after; nothing calls or references gp_lone or gp_lone2. Code after a `ret` that a forward branch
# reaches (gp_fwd), that may be a jump-table case (gp_table), or that is not 16-byte aligned (gp_odd, x86-64)
# belongs to the function before it and must not be split off; a tail jump to a function already known
# (gp_tail -> gp_after) does not stop a split.
DD_GAP_X86_S = r'''
    .intel_syntax noprefix
    .text
    .globl gp_main
    .type gp_main,@function
gp_main:
    push rbx
    mov edi, 1
    call gp_fwd
    call gp_table
    call gp_odd
    call gp_tail
    call gp_after
    pop rbx
    ret
    .size gp_main, .-gp_main

    .p2align 4
    .hidden gp_fwd
    .type gp_fwd,@function
gp_fwd:
    test edi, edi
    jne 2f
    mov eax, 1
    ret
    .p2align 4
2:
    lea eax, [rdi + 5]
    ret
    .size gp_fwd, .-gp_fwd

    .p2align 4
    .hidden gp_table
    .type gp_table,@function
gp_table:
    lea rax, [rip + 3f]
    jmp rax
    ret
    .p2align 4
3:
    mov eax, 7
    ret
    .size gp_table, .-gp_table

    .p2align 4
    .hidden gp_odd
    .type gp_odd,@function
gp_odd:
    mov eax, 2
    ret
    mov eax, 3
    ret
    .size gp_odd, .-gp_odd

    .p2align 4
    .hidden gp_tail
    .type gp_tail,@function
gp_tail:
    mov edi, 1
    jmp gp_after
    .size gp_tail, .-gp_tail

    .p2align 4
    .hidden gp_lone
    .type gp_lone,@function
gp_lone:
    lea eax, [rdi + rdi*2]
    xor eax, 0x55
    ret
    .size gp_lone, .-gp_lone

    .p2align 4
    .hidden gp_lone2
    .type gp_lone2,@function
gp_lone2:
    mov eax, 9
    ret
    .size gp_lone2, .-gp_lone2

    .p2align 4
    .hidden gp_after
    .type gp_after,@function
gp_after:
    lea eax, [rdi + 1]
    ret
    .size gp_after, .-gp_after
'''

DD_GAP_A64_S = r'''
    .text
    .globl gp_main
    .type gp_main,%function
gp_main:
    stp x29, x30, [sp, #-16]!
    mov w0, #1
    bl gp_fwd
    bl gp_table
    bl gp_tail
    bl gp_after
    ldp x29, x30, [sp], #16
    ret
    .size gp_main, .-gp_main

    .hidden gp_fwd
    .type gp_fwd,%function
gp_fwd:
    cbnz w0, 2f
    mov w0, #1
    ret
2:
    add w0, w0, #5
    ret
    .size gp_fwd, .-gp_fwd

    .hidden gp_table
    .type gp_table,%function
gp_table:
    adr x1, 3f
    br x1
    ret
3:
    mov w0, #7
    ret
    .size gp_table, .-gp_table

    .hidden gp_tail
    .type gp_tail,%function
gp_tail:
    mov w0, #1
    b gp_after
    .size gp_tail, .-gp_tail

    .hidden gp_lone
    .type gp_lone,%function
gp_lone:
    add w0, w0, w0, lsl #1
    eor w0, w0, #0xf0
    ret
    .size gp_lone, .-gp_lone

    .p2align 4
    .hidden gp_lone2
    .type gp_lone2,%function
gp_lone2:
    mov w0, #9
    ret
    .size gp_lone2, .-gp_lone2

    .hidden gp_after
    .type gp_after,%function
gp_after:
    add w0, w0, #1
    ret
    .size gp_after, .-gp_after
'''

# hand-written fixtures also linked with their section headers (so their symbol table) removed
ASM_STRIPPED = ("dd_gap_x86_64", "dd_gap_arm64")


def sources():
    """{fixture name: C source} with every table generated from the values above."""
    enc = enc_xor(FLAG, XOR_KEY)
    return {
        "dd_flag": DD_FLAG_C % dict(n=len(enc), enc=c_bytes(enc), m1=hex(MIX_M1), m2=hex(MIX_M2), key=XOR_KEY,
                                    seed=MIX_SEED, word=WORD_INDEX, r0=ROUND_ARGS[0], r1=ROUND_ARGS[1],
                                    label=LABEL),
        "dd_decoy": DD_DECOY_C % dict(na=len(DECOY_A), enc_a=c_bytes(bytes(p ^ 0x21 for p in DECOY_A)),
                                      nb=len(DECOY_B), enc_b=c_bytes(bytes((p + 13) & 0xFF for p in DECOY_B)),
                                      twin=TWIN_SEED),
        "dd_inout": DD_INOUT_C % dict(n=len(INOUT_PLAIN), key=INOUT_KEY,
                                      seed=c_bytes(bytes(p ^ INOUT_KEY for p in INOUT_PLAIN))),
        "dd_state": DD_STATE_C % dict(n=len(STATE_FLAG), table=c_bytes(enc_state_table(STATE_FLAG)),
                                      ckey=STATE_CTOR_KEY, nb=len(STATE_BLOB) + 1,
                                      blob=c_bytes(enc_state_blob(STATE_BLOB + b"\x00")), bkey=STATE_BLOB_KEY),
        "dd_lead": DD_LEAD_C % dict(n=len(LEAD_FLAG), enc=c_bytes(enc_xor(LEAD_FLAG, LEAD_KEY)), key=LEAD_KEY),
        "dd_never": DD_NEVER_C % dict(n=len(NEVER_FLAG), enc=c_bytes(enc_never(NEVER_FLAG)), key=NEVER_KEY),
        "dd_plain": DD_PLAIN_C,
        "dd_print": DD_PRINT_C % dict(n=len(PRINT_FLAG), enc=c_bytes(enc_print(PRINT_FLAG)), key=PRINT_KEY,
                                      v=PRINT_FMT_ARGS[0], w=PRINT_FMT_ARGS[1], a=PRINT_MANY_ARG),
    }


def asm_sources():
    """{fixture name: (architecture, assembly source)} of the hand-written tracker call sites."""
    return {"dd_track_x86_64": ("x86_64", DD_TRACK_X86_S), "dd_track_arm64": ("arm64", DD_TRACK_A64_S),
            "dd_gap_x86_64": ("x86_64", DD_GAP_X86_S), "dd_gap_arm64": ("arm64", DD_GAP_A64_S)}


# (fixture, architectures, link_so keyword arguments, output suffix)
BUILDS = (
    ("dd_flag", ("x86_64", "arm64"), {}, ""),
    ("dd_flag", ("x86_64",), {"strip_sections": True}, "_stripped"),
    ("dd_decoy", ("x86_64",), {}, ""),
    ("dd_inout", ("x86_64",), {}, ""),
    ("dd_state", ("x86_64", "arm64"), {"init_sym": "dd_init"}, ""),
    ("dd_lead", ("x86_64",), {"strip_sections": True}, "_stripped"),
    ("dd_lead", ("x86_64",), {}, ""),
    ("dd_never", ("x86_64", "arm64"), {}, ""),
    ("dd_plain", ("x86_64",), {}, ""),
    ("dd_print", ("x86_64", "arm64"), {}, ""),
)


def compile_obj(src, target, work, asm=False):
    c = Path(work) / ("src.s" if asm else "src.c")
    c.write_text(src)
    o = Path(work) / "out.o"
    flags = [] if asm else ["-O2", "-fPIC", "-fno-stack-protector", "-fno-asynchronous-unwind-tables",
                            "-fno-unwind-tables", "-fno-builtin", "-nostdlibinc"]
    cmd = ["clang", "-target", target] + flags + ["-c", str(c), "-o", str(o)]
    subprocess.run(cmd, check=True, capture_output=True)
    return o.read_bytes()


def build(out=OUT):
    """Compile and link every fixture into `out`; returns the paths written."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    work = tempfile.mkdtemp(prefix="ddfx-")
    made = []
    try:
        srcs = sources()
        for name, abis, link_kw, suffix in BUILDS:
            for abi in abis:
                obj = compile_obj(srcs[name], TARGETS[abi], work)
                p = out / ("%s_%s%s.so" % (name, abi, suffix))
                p.write_bytes(nif.link_so(obj, soname="lib%s.so" % name, **link_kw))
                made.append(p)
        for name, (abi, src) in asm_sources().items():
            obj = compile_obj(src, TARGETS[abi], work, asm=True)
            p = out / ("%s.so" % name)
            p.write_bytes(nif.link_so(obj, soname="lib%s.so" % name))
            made.append(p)
            if name in ASM_STRIPPED:
                p = out / ("%s_stripped.so" % name)
                p.write_bytes(nif.link_so(obj, soname="lib%s.so" % name, strip_sections=True))
                made.append(p)
        (out / "SOURCES.c").write_text("".join("/* %s.c */%s\n" % (n, s) for n, s in srcs.items()))
        (out / "SOURCES.s").write_text("".join("# %s.s%s\n" % (n, s) for n, (_abi, s) in asm_sources().items()))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return made


if __name__ == "__main__":
    dest = OUT
    if "--out" in sys.argv:
        dest = Path(sys.argv[sys.argv.index("--out") + 1])
    if not shutil.which("clang"):
        print("clang not found")
        sys.exit(1)
    for path in build(dest):
        print("wrote", path, path.stat().st_size)
