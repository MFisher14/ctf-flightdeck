/* B-241 Mach-O fixture source. tests/b241_fixture_asm.py --macho compiles it with the host cc (macOS) into
 * the committed b241_macho_*.dylib fixtures; nothing built from it is ever run on the host. It exercises what the
 * whole-image engine must get right for a Mach-O: a constructor, rebased pointer tables, libSystem calls
 * through stubs and the GOT, a sibling call, the stack protector's ___stack_chk_guard, and an import the
 * engine does not model. The expected values are an independent Python model in the test. Built as dylibs and,
 * with -DB241_EXECUTABLE, as PIE executables. */
#include <stdlib.h>
#include <string.h>

static const unsigned char SBOX[8] = {3, 1, 4, 1, 5, 9, 2, 6};
const char *b241_words[3] = {"alpha", "bravo", "charlie"};          /* rebased pointers, read at run time */
static volatile unsigned long long seed;                               /* set by the constructor (volatile: the
                                                                          compiler may not fold it away) */

__attribute__((constructor)) static void prepare(void) { seed = 0x9e3779b97f4a7c15ULL; }

__attribute__((noinline)) unsigned long long b241_round(unsigned long long x, int k) {
    for (int i = 0; i < k; i++) x = (x ^ SBOX[i & 7]) * 0x100000001b3ULL;
    return x;
}

unsigned long long b241_mix(const char *text, int k) {
    size_t n = strlen(text);
    char *copy = (char *)malloc(n + 1);
    if (!copy) return 0;
    memcpy(copy, text, n + 1);
    unsigned long long h = seed;
    for (size_t i = 0; i < n; i++) h = (h ^ (unsigned char)copy[i]) * 0x100000001b3ULL;
    free(copy);
    h = b241_round(h, k);
    return h + strlen(b241_words[n % 3]);
}

unsigned long long b241_seed(void) { return seed; }

int getpid(void);
int b241_pid(void) { return getpid(); }                                /* an import no model answers */

#ifdef B241_EXECUTABLE
/* The executable variants (b241_macho_*_exec_*): the same functions in an MH_EXECUTE image, whose __TEXT sits
 * above a __PAGEZERO segment, so every address the loader reads is relative to the Mach header, not zero. */
int main(int argc, char **argv) { return (int)b241_mix(argc > 1 ? argv[1] : "", argc); }
#endif
