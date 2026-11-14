/* kb2_jni.c */

#include <jni.h>
#include <string.h>
#include <stdlib.h>

static const unsigned char SBOX[16] = {0x3,0x1,0x4,0x1,0x5,0x9,0x2,0x6,0x5,0x3,0x5,0x8,0x9,0x7,0x9,0x3};
static const char HEX[] = "0123456789ABCDEF";
unsigned long long kb2_seed = 0x9e3779b97f4a7c15ULL;          /* .data, read through the GOT */
const char *const kb2_words[4] = {"alpha", "bravo", "charlie", "delta"};   /* .data.rel.ro, RELATIVE */
int (*const kb2_cmp)(const char *, const char *) = strcmp;      /* a GOT/ABS64 pointer to an import */

__attribute__((noinline)) unsigned long long kb2_round(unsigned long long x, int k) {
    for (int i = 0; i < k; i++) x = (x ^ SBOX[i & 15]) * 0x100000001b3ULL;
    return x;
}

__attribute__((noinline)) static unsigned long long kb2_op_rot(unsigned long long x) { return (x << 13) | (x >> 51); }
__attribute__((noinline)) static unsigned long long kb2_op_mul(unsigned long long x) { return x * 0x9e3779b97f4a7c15ULL; }
unsigned long long (*const kb2_ops[2])(unsigned long long) = {kb2_op_rot, kb2_op_mul};   /* RELATIVE to locals */

__attribute__((noinline)) static unsigned long long kb2_fold(const char *p, size_t n) {
    unsigned long long h = kb2_seed;
    for (size_t i = 0; i < n; i++) h = (h ^ (unsigned char)p[i]) * 0x100000001b3ULL;
    return h;
}

__attribute__((noinline)) int kb2_decode(unsigned char *buf, int n, int key) {
    int sum = 0;
    for (int i = 0; i < n; i++) { buf[i] = (unsigned char)(buf[i] ^ (key + 3 * i)); sum += buf[i]; }
    return sum;
}

JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mixString(JNIEnv *env, jclass cls, jstring s) {
    const char *p = (*env)->GetStringUTFChars(env, s, NULL);
    if (p == NULL) return 0;
    size_t n = strlen(p);
    size_t m = n < 47 ? n : 47;
    char buf[48];
    memset(buf, 0, sizeof buf);
    memcpy(buf, p, m);
    unsigned long long h = kb2_fold(buf, m);
    h = kb2_round(h, (int)(n & 31));
    h += strlen(kb2_words[n & 3]);
    h = kb2_ops[n & 1](h);
    (*env)->ReleaseStringUTFChars(env, s, p);
    return (jlong)h;
}

JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mixBytes(JNIEnv *env, jclass cls, jbyteArray a, jint key) {
    jsize n = (*env)->GetArrayLength(env, a);
    jbyte *e = (*env)->GetByteArrayElements(env, a, NULL);
    if (e == NULL) return 0;
    for (jsize i = 0; i < n; i++) e[i] = (jbyte)(e[i] ^ ((key + i) & 0xff));
    unsigned long long h = kb2_fold((const char *)e, (size_t)n);
    (*env)->ReleaseByteArrayElements(env, a, e, 0);
    return (jlong)h;
}

JNIEXPORT jstring JNICALL Java_com_huntress_kb2_NativeLab_encode(JNIEnv *env, jclass cls, jstring s) {
    const char *p = (*env)->GetStringUTFChars(env, s, NULL);
    if (p == NULL) return NULL;
    jsize ulen = (*env)->GetStringUTFLength(env, s);
    size_t n = strlen(p);
    char *out = (char *)malloc(8);
    if (out == NULL) return NULL;
    strcpy(out, "ANS");
    out = (char *)realloc(out, 24);
    char *dash = strchr("x-y", '-');
    strncpy(out + 3, dash, 1);
    unsigned long long h = kb2_round(kb2_fold(p, n), (int)ulen);
    for (int i = 0; i < 16; i++) out[4 + i] = HEX[(h >> (60 - 4 * i)) & 15];
    out[20] = 0;
    (*env)->ReleaseStringUTFChars(env, s, p);
    jstring r = (*env)->NewStringUTF(env, out);
    free(out);
    return r;
}

JNIEXPORT jbyteArray JNICALL Java_com_huntress_kb2_NativeLab_makeBytes(JNIEnv *env, jclass cls, jint n, jlong seed) {
    if (n < 0 || n > 64) return NULL;
    jbyteArray arr = (*env)->NewByteArray(env, n);
    unsigned char *buf = (unsigned char *)calloc((size_t)n, 1);
    unsigned long long x = (unsigned long long)seed;
    for (jint i = 0; i < n; i++) { x = x * 6364136223846793005ULL + 1442695040888963407ULL; buf[i] = (unsigned char)(x >> 56); }
    (*env)->SetByteArrayRegion(env, arr, 0, n, (const jbyte *)buf);
    free(buf);
    return arr;
}

JNIEXPORT jint JNICALL Java_com_huntress_kb2_NativeLab_sumInts(JNIEnv *env, jclass cls, jintArray a) {
    jsize n = (*env)->GetArrayLength(env, a);
    jint *e = (*env)->GetIntArrayElements(env, a, NULL);
    unsigned int acc = 0x811c9dc5u;
    for (jsize i = 0; i < n; i++) { acc = (acc << 5) | (acc >> 27); acc ^= (unsigned int)e[i]; }
    (*env)->ReleaseIntArrayElements(env, a, e, JNI_ABORT);
    return (jint)acc;
}

JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_regionHash(JNIEnv *env, jclass cls, jbyteArray a, jint off, jint len) {
    char tmp[32];
    char cpy[32];
    if (len < 0 || len > 32) return 0;
    (*env)->GetByteArrayRegion(env, a, off, len, (jbyte *)tmp);
    if ((*env)->ExceptionCheck(env)) return 0;
    memmove(cpy, tmp, (size_t)len);
    memmove(tmp + 1, tmp, (size_t)(len > 0 ? len - 1 : 0));
    unsigned long long h = kb2_fold(cpy, (size_t)len);
    if (len > 1 && memcmp(cpy + 1, tmp + 2, (size_t)(len - 2)) == 0) h ^= 0x5555;
    return (jlong)h;
}

JNIEXPORT jint JNICALL Java_com_huntress_kb2_NativeLab_compare(JNIEnv *env, jclass cls, jstring a, jstring b) {
    const char *pa = (*env)->GetStringUTFChars(env, a, NULL);
    const char *pb = (*env)->GetStringUTFChars(env, b, NULL);
    int c = kb2_cmp(pa, pb);
    int d = strncmp(pa, pb, 2);
    int r = (c < 0 ? 1 : (c > 0 ? 2 : 3)) * 10 + (d < 0 ? 1 : (d > 0 ? 2 : 3));
    r = r * 100 + (*env)->GetStringLength(env, a) + (*env)->GetStringUTFLength(env, b);
    (*env)->ReleaseStringUTFChars(env, a, pa);
    (*env)->ReleaseStringUTFChars(env, b, pb);
    return r;
}

JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_wide(JNIEnv *env, jclass cls, jint a, jlong b, jint c, jint d, jint e, jlong f) {
    return (jlong)((unsigned long long)b * 3 + (unsigned)a + (unsigned)c * 5 + (unsigned)d * 7 + (unsigned)e * 11 + (unsigned long long)f * 13);
}

JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_dispatch(JNIEnv *env, jclass cls, jint k, jlong x) {
    unsigned long long v = (unsigned long long)x;
    switch (k & 7) {
    case 0: v ^= 0x1111; break;
    case 1: v += 0x2222222222ULL; break;
    case 2: v = (v << 7) | (v >> 57); break;
    case 3: v *= 0x5bd1e995ULL; break;
    case 4: v -= 0x7777; break;
    case 5: v = ~v; break;
    case 6: v ^= v >> 29; break;
    default: v = v * 9 + 1; break;
    }
    return (jlong)v;
}

JNIEXPORT jint JNICALL Java_com_huntress_kb2_NativeLab_crc32(JNIEnv *env, jclass cls, jbyteArray a) {
    unsigned int table[256];
    for (unsigned int i = 0; i < 256; i++) {
        unsigned int c = i;
        for (int k = 0; k < 8; k++) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
        table[i] = c;
    }
    jsize n = (*env)->GetArrayLength(env, a);
    jbyte *e = (*env)->GetByteArrayElements(env, a, NULL);
    unsigned int crc = 0xFFFFFFFFu;
    for (jsize i = 0; i < n; i++) crc = table[(crc ^ (unsigned char)e[i]) & 0xFF] ^ (crc >> 8);
    (*env)->ReleaseByteArrayElements(env, a, e, JNI_ABORT);
    return (jint)(crc ^ 0xFFFFFFFFu);
}

JNIEXPORT void JNICALL Java_com_huntress_kb2_NativeLab_rc4(JNIEnv *env, jclass cls, jbyteArray data, jstring key) {
    unsigned char S[256];
    const char *k = (*env)->GetStringUTFChars(env, key, NULL);
    size_t kl = strlen(k);
    if (kl == 0) { (*env)->ReleaseStringUTFChars(env, key, k); return; }
    for (int i = 0; i < 256; i++) S[i] = (unsigned char)i;
    for (int i = 0, j = 0; i < 256; i++) {
        j = (j + S[i] + (unsigned char)k[i % kl]) & 0xFF;
        unsigned char t = S[i]; S[i] = S[j]; S[j] = t;
    }
    jsize n = (*env)->GetArrayLength(env, data);
    jbyte *e = (*env)->GetByteArrayElements(env, data, NULL);
    for (int x = 0, i = 0, j = 0; x < n; x++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        unsigned char t = S[i]; S[i] = S[j]; S[j] = t;
        e[x] = (jbyte)(e[x] ^ S[(S[i] + S[j]) & 0xFF]);
    }
    (*env)->ReleaseByteArrayElements(env, data, e, 0);
    (*env)->ReleaseStringUTFChars(env, key, k);
}

/* kb2_decoy.c */

#include <jni.h>
#include <string.h>
#include <stdlib.h>
int rand(void);
extern int foreign_counter;
static const char SECRET[] = "ANS-0F899F2B0D6E5B4B";

__attribute__((noinline)) int huntress_arena_length_accepts(int len, short tag) {
    return len > 0xffff && tag == (short)len;
}

JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Decoy_unmodelledImport(JNIEnv *env, jclass c, jlong x) { return x + rand(); }
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Decoy_findClass(JNIEnv *env, jclass c, jlong x) {
    return (*env)->FindClass(env, "java/lang/String") ? x : x + 1;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Decoy_uninitStack(JNIEnv *env, jclass c, jlong x) {
    volatile int arr[8];
    arr[0] = 1;
    return arr[(x & 7) | 1] + x;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Decoy_classValue(JNIEnv *env, jclass c, jlong x) { return x ^ (jlong)(long)c; }
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Decoy_envValue(JNIEnv *env, jclass c, jlong x) { return x + (jlong)(long)env; }
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Decoy_returnsAddr(JNIEnv *env, jclass c, jlong x) { return (jlong)(long)SECRET + x; }
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Decoy_spin(JNIEnv *env, jclass c, jlong x) {
    volatile long v = x | 1;
    while (v) v = v * 3 | 1;
    return v;
}
static long counter;
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Decoy_counter(JNIEnv *env, jclass c, jlong x) { counter++; return x + counter; }
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Decoy_smash(JNIEnv *env, jclass c, jlong x) {
    char buf[16];
    volatile int lim = 16 + (int)(x & 15) + 8;
    for (int i = 0; i < lim; i++) buf[i] = (char)x;
    return buf[3];
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Decoy_useAfterFree(JNIEnv *env, jclass c, jlong x) {
    char *volatile p = (char *)malloc(16);
    memset(p, 7, 16);
    free(p);
    return p[3] + x;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Decoy_writeRodata(JNIEnv *env, jclass c, jlong x) {
    char *volatile q = (char *)SECRET;
    q[0] = (char)x;
    return q[1];
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Decoy_libcData(JNIEnv *env, jclass c, jlong x) { return x + foreign_counter; }
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Decoy_mallocZero(JNIEnv *env, jclass c, jlong x) {
    char *volatile p = (char *)malloc(0);
    return p ? x : x + 1;
}
JNIEXPORT jint JNICALL Java_com_huntress_kb2_Decoy_memcmpMagnitude(JNIEnv *env, jclass c, jstring a, jstring b) {
    const char *pa = (*env)->GetStringUTFChars(env, a, NULL);
    const char *pb = (*env)->GetStringUTFChars(env, b, NULL);
    return memcmp(pa, pb, 3) * 3 + strcmp(pa, pb);
}
JNIEXPORT jint JNICALL Java_com_huntress_kb2_Decoy_isCopy(JNIEnv *env, jclass c, jbyteArray a) {
    jboolean cp = 9;
    jbyte *e = (*env)->GetByteArrayElements(env, a, &cp);
    (*env)->ReleaseByteArrayElements(env, a, e, JNI_ABORT);
    return 40 + cp;
}
JNIEXPORT jint JNICALL Java_com_huntress_kb2_Decoy_noRelease(JNIEnv *env, jclass c, jbyteArray a) {
    jbyte *e = (*env)->GetByteArrayElements(env, a, NULL);
    e[0] = (jbyte)(e[0] + 1);
    return 7;
}
JNIEXPORT jint JNICALL Java_com_huntress_kb2_Decoy_abortModified(JNIEnv *env, jclass c, jbyteArray a) {
    jbyte *e = (*env)->GetByteArrayElements(env, a, NULL);
    e[0] = (jbyte)(e[0] + 1);
    (*env)->ReleaseByteArrayElements(env, a, e, JNI_ABORT);
    return 7;
}
JNIEXPORT jstring JNICALL Java_com_huntress_kb2_Decoy_nativeEvidence(JNIEnv *env, jclass c, jint len) {
    if (huntress_arena_length_accepts(len, (short)len)) return (jstring)SECRET;
    return 0;
}
JNIEXPORT jstring JNICALL Java_com_huntress_kb2_Decoy_nullStr(JNIEnv *env, jclass c, jint len) { return 0; }
static unsigned int crc_table[256];
static int crc_ready;
JNIEXPORT jint JNICALL Java_com_huntress_kb2_Decoy_crcLazy(JNIEnv *env, jclass c, jint x) {
    if (!crc_ready) {
        for (unsigned int i = 0; i < 256; i++) {
            unsigned int v = i;
            for (int k = 0; k < 8; k++) v = (v & 1) ? 0xEDB88320u ^ (v >> 1) : v >> 1;
            crc_table[i] = v;
        }
        crc_ready = 1;
    }
    return (jint)crc_table[x & 0xFF];
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Decoy_badRegion(JNIEnv *env, jclass c, jbyteArray a) {
    char tmp[8];
    (*env)->GetByteArrayRegion(env, a, 2, 8, (jbyte *)tmp);
    return tmp[0];
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Decoy_sysc(JNIEnv *env, jclass c, jlong x) {
#if defined(__x86_64__)
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(39L) : "rcx", "r11", "memory");
    return r + x;
#else
    register long x8 __asm__("x8") = 172;
    register long x0 __asm__("x0");
    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8) : "memory");
    return x0 + x;
#endif
}

/* kb2_gate.c */

#include <jni.h>
static const char CODE[] = "ANS-0F899F2B0D6E5B4B";
__attribute__((noinline)) int huntress_arena_length_accepts(int len, short tag) {
    return len > 0xffff && tag == (short)len;
}
JNIEXPORT jstring JNICALL Java_com_huntress_kb2_Gate_nativeEvidence(JNIEnv *env, jclass c, jint len) {
    if (huntress_arena_length_accepts(len, (short)len)) return (jstring)CODE;
    return 0;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Gate_nativeShare(JNIEnv *env, jclass c, jlong seed, jint len) {
    if (!huntress_arena_length_accepts(len, (short)len)) return 0;
    unsigned long long x = (unsigned long long)seed ^ 0x4066a0203792c45ULL;
    x ^= x >> 31;
    x = (x << 45) | (x >> 19);
    return (jlong)(x * 0xb83e746c824e010dULL);
}
