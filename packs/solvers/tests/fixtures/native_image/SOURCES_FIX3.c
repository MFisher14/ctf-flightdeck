/* kb2_f3_res0.c */
#include <jni.h>
#include <string.h>
#include <stdlib.h>

JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *env, jclass c, jlong x) {
    const struct JNINativeInterface_ *t = *env;
    if (t->reserved0 != 0) return x ^ 0x1111;   /* an emulator's fake table: decoy leg */
    return x ^ 0x2222;                           /* a device: ART's table is NULL there */
}

/* kb2_f3_stride.c */
#include <jni.h>
#include <string.h>
#include <stdlib.h>

JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *env, jclass c, jlong x) {
    const struct JNINativeInterface_ *t = *env;
    long d = (const char *)t->GetStringUTFChars - (const char *)t->GetVersion;
    if (d == 16L * (169 - 4)) return x ^ 0x1111; /* a table of 16-byte trampolines: decoy leg */
    return x ^ 0x2222;
}

/* kb2_f3_honest.c */
#include <jni.h>
#include <string.h>
#include <stdlib.h>

static const unsigned char T[16] = {3,1,4,1,5,9,2,6,5,3,5,8,9,7,9,3};
__attribute__((noinline)) unsigned long helper(unsigned long x, const char *s) {
    unsigned long n = strlen(s);
    for (unsigned long i = 0; i < n; i++) x = (x ^ T[(x + i) & 15]) * 0x100000001B3UL;
    return x;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *env, jclass c, jlong x) {
    return (jlong)helper((unsigned long)x, "huntress");
}

/* kb2_f3_handles.c */
#include <jni.h>
#include <string.h>
#include <stdlib.h>

JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix2(JNIEnv *env, jclass c, jstring s) {
    jstring t = (*env)->NewStringUTF(env, "a");
    long d = (long)((char *)t - (char *)s);
    if (d == 0x10) return 0x1111;                /* an emulator's sequential handles: decoy leg */
    return 0x2222;
}

/* kb2_f3_heap.c */
#include <jni.h>
#include <string.h>
#include <stdlib.h>

JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *env, jclass c, jlong x) {
    char *a = malloc(16), *b = malloc(16);
    long d = b - a;
    free(b); free(a);
    if (d == 32) return x ^ 0x1111;
    return x ^ 0x2222;
}

/* kb2_f3_vmres.c */
#include <jni.h>
#include <string.h>
#include <stdlib.h>

static jlong realfn(JNIEnv *e, jclass c, jlong x) { return x ^ 0x2222; }
static jlong decoyfn(JNIEnv *e, jclass c, jlong x) { return x ^ 0x1111; }
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return -1;
    jclass cls = (*env)->FindClass(env, "com/huntress/kb2/NativeLab");
    if (!cls) return -1;
    JNINativeMethod m[1];
    m[0].name = "mix";
    m[0].signature = "(J)J";
    m[0].fnPtr = (*vm)->reserved0 ? (void *)decoyfn : (void *)realfn;
    if ((*env)->RegisterNatives(env, cls, m, 1) != 0) return -1;
    return JNI_VERSION_1_6;
}

/* kb2_f3_libcptr.c */
#include <jni.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned long (*lenfn)(const char *);
typedef void *(*cpyfn)(void *, const void *, unsigned long);
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *env, jclass c, jlong x) {
    volatile lenfn a = strlen;
    volatile cpyfn b = memcpy;
    long d = (const char *)b - (const char *)a;
    if (d == 16) return x ^ 0x1111;              /* adjacent 16-byte stubs: an emulator's trap table */
    return x ^ 0x2222;
}

/* kb2_f3_olhonest.c */
#include <jni.h>
#include <string.h>
#include <stdlib.h>

int getpid(void);
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    return getpid() > 0 ? JNI_VERSION_1_6 : JNI_VERSION_1_6;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix__J(JNIEnv *e, jclass c, jlong x) { return x * 7 + 5; }

/* kb2_f3_oldecoy.c */
#include <jni.h>
#include <string.h>
#include <stdlib.h>

int getpid(void);
static jlong realfn(JNIEnv *e, jclass c, jlong x) { return x ^ 0x2222; }
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    if (getpid() <= 0) return -1;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return -1;
    jclass cls = (*env)->FindClass(env, "com/huntress/kb2/NativeLab");
    JNINativeMethod m[1];
    m[0].name = "mix";
    m[0].signature = "(J)J";
    m[0].fnPtr = (void *)realfn;
    if ((*env)->RegisterNatives(env, cls, m, 1) != 0) return -1;
    return JNI_VERSION_1_6;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix__J(JNIEnv *e, jclass c, jlong x) { return x ^ 0x1111; }

/* kb2_f3_burnload.c */
#include <jni.h>
#include <string.h>
#include <stdlib.h>

static volatile unsigned long T[8192];
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    unsigned long s = 1UL;
    for (unsigned long i = 0; i < 100000000UL; i++) {
        s += T[i & 8191] + T[(i + 1) & 8191] + T[(i + 2) & 8191] + T[(i + 3) & 8191];
        s += T[(i + 4) & 8191] + T[(i + 5) & 8191] + T[(i + 6) & 8191] + T[(i + 7) & 8191];
    }
    return s == 12345 ? 0 : JNI_VERSION_1_6;
}

/* kb2_f3_burncall.c */
#include <jni.h>
#include <string.h>
#include <stdlib.h>

static volatile unsigned long T[8192];
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *env, jclass c, jlong x) {
    unsigned long s = (unsigned long)x;
    for (unsigned long i = 0; i < 100000000UL; i++) {
        s += T[i & 8191] + T[(i + 1) & 8191] + T[(i + 2) & 8191] + T[(i + 3) & 8191];
        s += T[(i + 4) & 8191] + T[(i + 5) & 8191] + T[(i + 6) & 8191] + T[(i + 7) & 8191];
    }
    return (jlong)s;
}

/* kb2_f3_reuse.c */
#include <jni.h>
#include <string.h>
#include <stdlib.h>
static void *keep(void *p) { __asm__ volatile("" : "+r"(p) : : "memory"); return p; }

JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *env, jclass c, jlong x) {
    char *a = keep(malloc(16));
    free(a);
    char *b = keep(malloc(16));
    int same = keep(a) == (void *)b;
    free(b);
    if (!same) return x ^ 0x1111;               /* a heap that never reuses: decoy leg */
    return x ^ 0x2222;
}

/* kb2_f3_rshrink.c */
#include <jni.h>
#include <string.h>
#include <stdlib.h>
static void *keep(void *p) { __asm__ volatile("" : "+r"(p) : : "memory"); return p; }

JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *env, jclass c, jlong x) {
    char *p = keep(malloc(32));
    char *g = keep(malloc(16));                 /* p is not the last block */
    char *q = keep(realloc(p, 8));
    int same = q == p;
    free(q); free(g);
    if (!same) return x ^ 0x1111;               /* a realloc that always moves: decoy leg */
    return x ^ 0x2222;
}

/* kb2_f3_rgrow.c */
#include <jni.h>
#include <string.h>
#include <stdlib.h>
static void *keep(void *p) { __asm__ volatile("" : "+r"(p) : : "memory"); return p; }

JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *env, jclass c, jlong x) {
    char *p = keep(malloc(17));
    char *g = keep(malloc(16));                 /* p is not the last block */
    char *q = keep(realloc(p, 24));             /* one 32-byte class on scudo and jemalloc */
    int same = q == p;
    free(q); free(g);
    if (!same) return x ^ 0x1111;
    return x ^ 0x2222;
}

/* kb2_f3_rlast.c */
#include <jni.h>
#include <string.h>
#include <stdlib.h>
static void *keep(void *p) { __asm__ volatile("" : "+r"(p) : : "memory"); return p; }

JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *env, jclass c, jlong x) {
    char *p = keep(malloc(17));
    char *q = keep(realloc(p, 24));
    int same = q == p;
    free(q);
    if (!same) return x ^ 0x1111;
    return x ^ 0x2222;
}

/* kb2_f3_hchurn.c */
#include <jni.h>
#include <string.h>
#include <stdlib.h>

JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *env, jclass c, jlong x) {
    unsigned long acc = (unsigned long)x;
    char *buf = malloc(4);
    unsigned long n = 0, cap = 4;
    for (int i = 0; i < 40; i++) {
        if (n + 1 > cap) { cap *= 2; buf = realloc(buf, cap); }
        buf[n++] = (char)('a' + (acc + i) % 26);
        char *tmp = malloc(8);
        tmp[0] = buf[n - 1];
        acc = acc * 31 + (unsigned char)tmp[0];
        free(tmp);
    }
    buf = realloc(buf, n);
    for (unsigned long i = 0; i < n; i++) acc ^= (unsigned long)(unsigned char)buf[i] << (i % 56);
    free(buf);
    return (jlong)acc;
}

