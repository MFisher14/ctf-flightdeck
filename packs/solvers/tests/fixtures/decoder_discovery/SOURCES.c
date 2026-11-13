/* dd_flag.c */
#define HID __attribute__((visibility("hidden"), noinline))
int puts(const char *);
unsigned long strlen(const char *);
void *malloc(unsigned long);
void *memcpy(void *, const void *, unsigned long);

/* first in .text, so no decoder is the function a disassembler names after the (absent) entry point;
   nothing calls it and nothing marks it a decoder */
int dd_abi(void) { return 1; }

static const unsigned char ENC[37] = { 0x19, 0x32, 0x2b, 0x3b, 0x30, 0x06, 0xe0, 0xb8, 0xf1, 0xa9, 0xc4, 0x94, 0xdc, 0xea, 0xde, 0xf3, 0xbf, 0xbf, 0xbc, 0x80, 0x87, 0x99, 0xab, 0x8f, 0x6a, 0x3a, 0x4f, 0x74, 0x2a, 0x49, 0x40, 0x6c, 0x49, 0x70, 0x3c, 0x2a, 0x2b };
static const char *const WORDS[4] = { "alpha", "bravo", "charlie", "delta" };

/* a buffer decoder: input pointer, length, key, output buffer (all bound at the call site in main) */
HID void dd_xor_decode(const unsigned char *in, unsigned long n, unsigned key, char *out) {
    for (unsigned long i = 0; i < n; i++) out[i] = (char)(in[i] ^ (unsigned char)(key + 7 * i));
    out[n] = 0;
}

/* an invertible word mixer (the B-026 lead shape): one integer in, one out */
HID unsigned long dd_mix(unsigned long x) {
    x ^= x >> 31; x *= 0x6f2b8a4d93c5e1b7UL; x ^= x >> 27; x *= 0xc3a5f18e7d2b964bUL; x ^= x >> 33;
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
const char *dd_label = "omega";
HID unsigned dd_first(void) { return (unsigned char)dd_label[0]; }

/* hands its own argument on to strlen (through the PLT, a libc function the emulator models) */
HID unsigned long dd_len(const char *s) { return strlen(s) + 1; }

int main(int argc, char **argv) {
    char buf[64];
    dd_xor_decode(ENC, sizeof ENC, 90, buf);
    puts(buf);
    unsigned long m = dd_mix(4919UL);
    puts(dd_word(2));
    return dd_checksum(argv[1]) + (int)m + (int)dd_round(16, 3) + (int)dd_sum(ENC, sizeof ENC)
        + (int)dd_first() + (int)dd_len("hello, decoder");
}

/* dd_decoy.c */
#define HID __attribute__((visibility("hidden"), noinline))
int puts(const char *);
unsigned long strlen(const char *);
void *malloc(unsigned long);
void *memcpy(void *, const void *, unsigned long);

/* first in .text, so no decoder is the function a disassembler names after the (absent) entry point;
   nothing calls it and nothing marks it a decoder */
int dd_abi(void) { return 1; }

static const unsigned char ENC_A[26] = { 0x62, 0x72, 0x62, 0x75, 0x67, 0x5a, 0x55, 0x49, 0x10, 0x52, 0x7e, 0x11, 0x4f, 0x44, 0x7e, 0x48, 0x52, 0x7e, 0x40, 0x7e, 0x45, 0x12, 0x42, 0x11, 0x58, 0x5c };
static const unsigned char ENC_B[23] = { 0x50, 0x60, 0x50, 0x61, 0x53, 0x88, 0x81, 0x75, 0x3e, 0x80, 0x6c, 0x3d, 0x7b, 0x72, 0x6c, 0x76, 0x80, 0x6c, 0x7f, 0x40, 0x41, 0x79, 0x8a };

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
    return (int)(dd_twin_a(119UL) + dd_twin_b(119UL));
}

/* dd_inout.c */
#define HID __attribute__((visibility("hidden"), noinline))
int puts(const char *);
unsigned long strlen(const char *);
void *malloc(unsigned long);
void *memcpy(void *, const void *, unsigned long);

/* first in .text, so no decoder is the function a disassembler names after the (absent) entry point;
   nothing calls it and nothing marks it a decoder */
int dd_abi(void) { return 1; }

static const unsigned char SEED[24] = { 0x21, 0x23, 0x2e, 0x2e, 0x27, 0x30, 0x62, 0x24, 0x2b, 0x2e, 0x2e, 0x27, 0x26, 0x62, 0x36, 0x2a, 0x2b, 0x31, 0x62, 0x24, 0x2b, 0x30, 0x31, 0x36 };

/* decodes in place: the caller's stack buffer is its INPUT as well as its output */
HID void dd_inplace(char *buf, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) buf[i] = (char)(buf[i] ^ 66);
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
    for (int i = 0; i < 24; i++) buf[i] = (char)SEED[i];
    buf[24] = 0;
    dd_inplace(buf, 24);
    puts(buf);
    puts(dd_dup(3));
    puts(dd_addr());
    return dd_alias(buf, buf);
}

/* dd_state.c */
#define HID __attribute__((visibility("hidden"), noinline))
int puts(const char *);
unsigned long strlen(const char *);
void *malloc(unsigned long);
void *memcpy(void *, const void *, unsigned long);

/* first in .text, so no decoder is the function a disassembler names after the (absent) entry point;
   nothing calls it and nothing marks it a decoder */
int dd_abi(void) { return 1; }

static unsigned char TABLE[37] = { 0xe4, 0xf1, 0xee, 0xfa, 0xf5, 0x2d, 0xd2, 0xe2, 0x21, 0x29, 0x35, 0x34, 0x3e, 0x2d, 0x39, 0xfa, 0x05, 0x35, 0x01, 0x0c, 0xc8, 0x08, 0xd1, 0x10, 0x0a, 0x08, 0x0a, 0x62, 0x1b, 0x2d, 0x1e, 0x76, 0x33, 0x62, 0x75, 0x69, 0x4e };          /* .data: the constructor decrypts it */
static char OUT[64];                                          /* .bss */
static unsigned char BLOB[44] = { 0x47, 0x5a, 0x54, 0x10, 0x46, 0x49, 0x5c, 0x59, 0x40, 0x1a, 0x5f, 0x4e, 0x48, 0xb7, 0x4f, 0x1c, 0x45, 0xb3, 0xb9, 0x00, 0x4d, 0xb9, 0xb0, 0xb4, 0xb8, 0x0a, 0xba, 0xa2, 0xb2, 0xbc, 0x0d, 0xa0, 0xbb, 0xb5, 0x71, 0xbc, 0xb6, 0xac, 0xac, 0x74, 0xbf, 0xab, 0xa2, 0x18 };           /* .data: decoded in place through a pointer */

void dd_init(void) {                                          /* DT_INIT */
    for (int i = 0; i < 37; i++) TABLE[i] ^= 167;
}

/* no argument: fills a global buffer from the prepared table and returns it */
HID const char *dd_table_flag(void) {
    for (int i = 0; i < 37; i++) OUT[i] = (char)(TABLE[i] - 3 * i);
    OUT[37] = 0;
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
    dd_unmask(BLOB, sizeof BLOB, 51);
    puts((const char *)BLOB);
    dd_poke();
    dd_leak();
    return dd_pad[100] + dd_sink[0];
}

/* dd_lead.c */
#define HID __attribute__((visibility("hidden"), noinline))
int puts(const char *);
unsigned long strlen(const char *);
void *malloc(unsigned long);
void *memcpy(void *, const void *, unsigned long);

/* first in .text, so no decoder is the function a disassembler names after the (absent) entry point;
   nothing calls it and nothing marks it a decoder */
int dd_abi(void) { return 1; }

static const unsigned char ENC[29] = { 0x19, 0x32, 0x2b, 0x3b, 0x30, 0x06, 0xf0, 0xe3, 0xa1, 0xc6, 0xcc, 0x94, 0x9a, 0xd1, 0xe3, 0xa1, 0xfa, 0xa4, 0xb6, 0xbb, 0xb9, 0x99, 0x9c, 0xc8, 0x5d, 0x62, 0x23, 0x6e, 0x63 };

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
    volatile unsigned key = 90;       /* stored to the stack, read back after another call */
    puts("decoding");
    dd_keyed(ENC, sizeof ENC, key, buf);
    puts(buf);
    return (int)dd_late((unsigned)argv[0][0] + (unsigned)argc);
}

/* dd_never.c */
#define HID __attribute__((visibility("hidden"), noinline))
int puts(const char *);
unsigned long strlen(const char *);
void *malloc(unsigned long);
void *memcpy(void *, const void *, unsigned long);

/* first in .text, so no decoder is the function a disassembler names after the (absent) entry point;
   nothing calls it and nothing marks it a decoder */
int dd_abi(void) { return 1; }

static const unsigned char ENC[29] = { 0x7f, 0x6e, 0x7d, 0x6b, 0x06, 0x3a, 0x2c, 0x73, 0x30, 0x2d, 0x77, 0x29, 0x2f, 0x16, 0x29, 0x7f, 0x20, 0x21, 0x3d, 0x10, 0x24, 0x39, 0x63, 0x20, 0x0b, 0x65, 0x38, 0x32, 0x25 };
static char OUT[64];
unsigned dd_never_key = 60;      /* an external, writable key: the compiler cannot fold the decode */

/* nothing calls either decoder: one fills its argument, one a global buffer it returns */
__attribute__((used, visibility("hidden"), noinline)) void dd_never_out(char *out) {
    for (int i = 0; i < 29; i++) out[i] = (char)(ENC[i] ^ (unsigned char)(dd_never_key + i));
    out[29] = 0;
}
__attribute__((used, visibility("hidden"), noinline)) const char *dd_never_ret(void) {
    for (int i = 0; i < 29; i++) OUT[i] = (char)(ENC[i] ^ (unsigned char)(dd_never_key + i));
    OUT[29] = 0;
    return OUT;
}

int main(void) { puts("nothing to see"); return 0; }

/* dd_plain.c */
#define HID __attribute__((visibility("hidden"), noinline))
int puts(const char *);
unsigned long strlen(const char *);
void *malloc(unsigned long);
void *memcpy(void *, const void *, unsigned long);

/* first in .text, so no decoder is the function a disassembler names after the (absent) entry point;
   nothing calls it and nothing marks it a decoder */
int dd_abi(void) { return 1; }

/* called with a constant, but all it does is print through an import the emulator does not model */
HID void dd_show(int k) { puts(k ? "yes" : "no"); }

int main(void) { puts("hello"); dd_show(1); return 0; }

/* dd_print.c */
#define HID __attribute__((visibility("hidden"), noinline))
int puts(const char *);
unsigned long strlen(const char *);
void *malloc(unsigned long);
void *memcpy(void *, const void *, unsigned long);

/* first in .text, so no decoder is the function a disassembler names after the (absent) entry point;
   nothing calls it and nothing marks it a decoder */
int dd_abi(void) { return 1; }

int printf(const char *, ...);
int putchar(int);
long write(int, const void *, unsigned long);

static const unsigned char ENC[29] = { 0x6a, 0x79, 0x68, 0x78, 0x6b, 0x55, 0x5f, 0x42, 0x00, 0x5c, 0x47, 0x07, 0x51, 0x69, 0x55, 0x41, 0x66, 0x4e, 0x53, 0x0f, 0x62, 0x5a, 0x0c, 0x23, 0x71, 0x26, 0x70, 0x36, 0x38 };
unsigned dd_print_key = 41;      /* an external, writable key: the compiler cannot fold the decode */

/* decodes and prints in one function: nothing comes back to the caller */
HID void dd_print_flag(void) {
    char buf[64];
    for (int i = 0; i < 29; i++) buf[i] = (char)(ENC[i] ^ (unsigned char)(dd_print_key + i));
    buf[29] = 0;
    printf("flag: %s\n", buf);
}

/* the same, one character at a time */
HID void dd_putc_flag(void) {
    for (int i = 0; i < 29; i++) putchar(ENC[i] ^ (unsigned char)(dd_print_key + i));
    putchar('\n');
}

/* the same, through write(2) to standard error */
HID void dd_write_flag(void) {
    char buf[64];
    for (int i = 0; i < 29; i++) buf[i] = (char)(ENC[i] ^ (unsigned char)(dd_print_key + i));
    write(2, buf, 29);
}

/* every printf conversion the model takes, its integers bound at the call site */
HID int dd_fmt(int v, unsigned long w) {
    return printf("[%5d|%-4x|%04X|%c|%.3s|%hhd|%lu|%06d|%%]\n", v, 0xab, 0xbeefu, 'Z', "abcdef", 300, w, v);
}

/* more variadic arguments than argument registers: the rest are on the caller's stack */
HID int dd_many(int a) {
    return printf("%d %d %d %d %d %d %d %d|\n", a, a + 1, a + 2, a + 3, a + 4, a + 5, a + 6, a + 7);
}

/* a conversion the model refuses (an address) */
HID int dd_fmt_ptr(void) { return printf("%p\n", (void *)&dd_print_key); }

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
HID int dd_chk(int v) { return __printf_chk(1, "chk %d\n", v); }

/* a looped decoder-like routine that calls an import the emulator neither models nor captures */
int rand(void);
HID int dd_rand_decode(int v) {
    int s = 0;
    for (int i = 0; i < v; i++) s ^= rand() + i * 7;
    return s;
}

/* prints an address: the text differs between the two layouts */
HID void dd_print_addr(void) { printf("%lx\n", (unsigned long)&dd_print_key); }

int main(void) {
    dd_print_flag();
    dd_putc_flag();
    dd_write_flag();
    dd_fmt(-42, 123456789012UL);
    dd_many(10);
    dd_fmt_ptr();
    dd_mixed();
    dd_badfd();
    dd_write1();
    dd_chk(10);
    dd_print_addr();
    dd_rand_decode(5);
    return dd_puts_ret();
}

