#!/usr/bin/env python3
"""Builder of the honest native fixtures for tests/test_day27_native_image_mobile.py (KB-2).

The machine has clang (with the AArch64 and x86-64 back ends) but no ELF linker (no ld.lld, no NDK), so
this file carries a SMALL, single-object ELF64 shared-object linker: it takes ONE relocatable object that
clang compiled (`-target <x86_64|aarch64>-linux-android21 -O2 -fPIC -fstack-protector-strong`) and lays
out a real `.so` the way lld does for `-shared`:

  * four PT_LOAD segments (R headers/dynamic tables, R+X .plt/.text, R .rodata, RW .data.rel.ro/.dynamic/
    .got | .got.plt/.data/.bss), PT_DYNAMIC, PT_GNU_RELRO and PT_GNU_STACK;
  * a PLT (x86-64 lazy PLT0/PLTn, AArch64 PLT0/PLTn) with R_*_JUMP_SLOT relocations for every call to a
    PREEMPTIBLE symbol (a default-visibility global defined here -- e.g. a sibling helper -- or an import
    such as strlen), exactly as lld routes them;
  * a GOT with R_*_GLOB_DAT for preemptible/imported data and R_*_RELATIVE for local addresses;
  * R_*_RELATIVE / R_*_64|ABS64 for pointers in .data.rel.ro / .data; the place itself holds 0 (as lld
    writes RELA places), so an emulator that forgot a relocation reads a NULL pointer and fails;
  * .dynsym/.dynstr/.hash and, unless stripped, full section headers and a .symtab with the local symbols.

It is TEST INFRASTRUCTURE ONLY (never imported by a solver). The expected value of every fixture function
is an independent Python model in the test file, so a linker mistake shows up as a failed test, never as a
silently passing one. Run it to rebuild the committed fixtures (needs clang and a JDK's jni.h):

    .venv/bin/python -I -B tests/native_image_fixtures.py [--out tests/fixtures/native_image]
"""
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "fixtures" / "native_image"

EM_X86_64 = 62
EM_AARCH64 = 183
PAGE = 0x1000

# ------------------------------------------------------------------------------------------- C sources
KB2_JNI_C = r'''
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
'''

KB2_DECOY_C = r'''
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
'''

# A Day-16-shaped library: the JNI symbol of the dex chain, a sibling gate called through the PLT and a
# .rodata code returned as a raw C pointer (the fixture generator's jstring shortcut).
KB2_GATE_C = r'''
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
'''

# Load-time code (the r2 round): a constructor that decrypts .data and builds a .bss table from a seed that
# DT_INIT sets first, a JNI_OnLoad that binds two methods with RegisterNatives (one of them ALSO exported as a
# decoy Java_ symbol a dlsym binding would pick), and decoy variants whose load phase ART would refuse or the
# model cannot prove. VARIANT: 0 the good library, 1 a constructor calling an unmodelled import, 2 a
# RegisterNatives of a method the dex does not declare, 3 a JNI_OnLoad returning a version ART refuses, 4 a
# FindClass of a class the dex does not define, 6 constructors only (no JNI_OnLoad).
KB2_LOAD_CODE = "ANS-6A1F3C9E0B7D2485"
KB2_LOAD_KEY = 0x5A
KB2_LOAD_C = r'''
#include <jni.h>
#ifndef VARIANT
#define VARIANT 0
#endif
int getpid(void);
extern int __cxa_atexit(void (*)(void *), void *, void *);
__attribute__((visibility("hidden"))) void *__dso_handle = &__dso_handle;

static unsigned char kb2_secret[21] = { @SECRET@ };
static unsigned long long kb2_table[8];
unsigned long long kb2_seed0 = 0x9999;   /* DT_INIT (kb2_init) sets it to 0x1234 before the constructor runs */
static int kb2_dtor_calls;

static void kb2_dtor(void *p) { kb2_dtor_calls++; (void)p; }

__attribute__((noinline, used)) void kb2_init(void) { kb2_seed0 = 0x1234; }

__attribute__((constructor)) static void kb2_ctor(void) {
#if VARIANT == 1
    kb2_seed0 ^= (unsigned long long)getpid();
#endif
    for (int i = 0; i < 21; i++) kb2_secret[i] ^= @KEY@;
    unsigned long long x = kb2_seed0;
    for (int i = 0; i < 8; i++) { x = x * 6364136223846793005ULL + 1442695040888963407ULL; kb2_table[i] = x; }
    volatile unsigned char pad[256];      /* leaves a pattern on the stack a later call could read uninitialised */
    for (int i = 0; i < 256; i++) pad[i] = (unsigned char)(i ^ 0x33);
    __cxa_atexit(kb2_dtor, 0, &__dso_handle);
}

/* Reads its own uninitialised stack: on a device, whatever ART's frames left; never the constructor's pattern. */
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Load_stackLeft(JNIEnv *env, jclass c, jlong x) {
    volatile unsigned char pad[256];
    return (jlong)pad[x & 255];
}

JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Load_ctorValue(JNIEnv *env, jclass c, jlong x) {
    unsigned long long h = 0xcbf29ce484222325ULL;
    for (int i = 0; i < 16; i++) h = (h ^ kb2_secret[i]) * 0x100000001b3ULL;
    return (jlong)(h ^ kb2_table[x & 7]);
}

JNIEXPORT jstring JNICALL Java_com_huntress_kb2_Load_ctorCode(JNIEnv *env, jclass c) {
    return (*env)->NewStringUTF(env, (const char *)kb2_secret);
}

/* The DECOY export: what a dlsym binding would run. JNI_OnLoad binds regMix to kb2_reg_mix instead. */
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Load_regMix(JNIEnv *env, jclass c, jlong x) { return x + 1; }

static jlong kb2_reg_mix(JNIEnv *env, jclass c, jlong x) {
    return (jlong)(((unsigned long long)x * 0x9e3779b97f4a7c15ULL) ^ kb2_table[1]);
}
static jstring kb2_reg_code(JNIEnv *env, jclass c) {
    return (*env)->NewStringUTF(env, (const char *)kb2_secret);
}

#if VARIANT != 6
static const JNINativeMethod KB2_METHODS[] = {
    {"regMix", "(J)J", (void *)kb2_reg_mix},
    {"regCode", "()Ljava/lang/String;", (void *)kb2_reg_code},
#if VARIANT == 2
    {"ghost", "(J)J", (void *)kb2_reg_mix},
#endif
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
#if VARIANT == 4
    jclass cls = (*env)->FindClass(env, "com/huntress/kb2/Missing");
#else
    jclass cls = (*env)->FindClass(env, "com/huntress/kb2/Load");
#endif
    if (cls == NULL) return JNI_ERR;
    if ((*env)->RegisterNatives(env, cls, KB2_METHODS, sizeof(KB2_METHODS) / sizeof(KB2_METHODS[0])) != JNI_OK)
        return JNI_ERR;
    (*env)->DeleteLocalRef(env, cls);
#if VARIANT == 3
    return JNI_VERSION_1_1;
#else
    return JNI_VERSION_1_6;
#endif
}
#endif
'''.replace("@SECRET@", ", ".join("0x%02x" % (b ^ KB2_LOAD_KEY) for b in KB2_LOAD_CODE.encode() + b"\x00")) \
   .replace("@KEY@", "0x%02x" % KB2_LOAD_KEY)
# Environment-dependent instructions (an emulator check reads them) must decline; the newly modelled JNI slots
# (GetVersion, ExceptionOccurred/Clear, DeleteLocalRef) must answer exactly; `plain` is the control.
KB2_ENV_C = r'''
#include <jni.h>
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Env_timing(JNIEnv *env, jclass c, jlong x) {
    volatile unsigned long long s = 0;
#if defined(__x86_64__)
    unsigned lo1, hi1, lo2, hi2;
    __asm__ volatile("rdtsc" : "=a"(lo1), "=d"(hi1));
    for (int i = 0; i < 100; i++) s += i;
    __asm__ volatile("rdtsc" : "=a"(lo2), "=d"(hi2));
    unsigned long long d = (((unsigned long long)hi2 << 32) | lo2) - (((unsigned long long)hi1 << 32) | lo1);
#else
    unsigned long long t1, t2;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(t1));
    for (int i = 0; i < 100; i++) s += i;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(t2));
    unsigned long long d = t2 - t1;
#endif
    return d > 100000 ? x ^ 0xdec0 : x;          /* "an emulator is slow": the decoy leg */
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Env_cpuflag(JNIEnv *env, jclass c, jlong x) {
#if defined(__x86_64__)
    unsigned a = 1, b, cc, d;
    __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "=c"(cc), "=d"(d));
    return ((cc >> 31) & 1) ? x ^ 0xdec0 : x;    /* the hypervisor bit */
#else
    unsigned long long midr;
    __asm__ volatile("mrs %0, midr_el1" : "=r"(midr));
    return midr == 0 ? x ^ 0xdec0 : x;
#endif
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Env_random(JNIEnv *env, jclass c, jlong x) {
    unsigned long long r;
#if defined(__x86_64__)
    unsigned char ok;
    __asm__ volatile("rdrand %0; setc %1" : "=r"(r), "=qm"(ok));
    return ok ? x + (r & 1) : x;
#else
    __asm__ volatile("mrs %0, s3_3_c2_c4_0" : "=r"(r));    /* RNDR */
    return x + (r & 1);
#endif
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Env_xcr(JNIEnv *env, jclass c, jlong x) {
#if defined(__x86_64__)
    unsigned lo, hi;
    __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
    return (lo & 4) ? x ^ 0xdec0 : x;            /* AVX state enabled? */
#else
    unsigned long long ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    return (ctr & 0xf) ? x ^ 0xdec0 : x;
#endif
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Env_plain(JNIEnv *env, jclass c, jlong x) {
    return (jlong)((unsigned long long)x * 3 + 1);
}
JNIEXPORT jint JNICALL Java_com_huntress_kb2_Env_jniMisc(JNIEnv *env, jclass c, jstring s) {
    jint v = (*env)->GetVersion(env);
    jthrowable t = (*env)->ExceptionOccurred(env);
    (*env)->ExceptionClear(env);
    jsize n = (*env)->GetStringUTFLength(env, s);
    (*env)->DeleteLocalRef(env, s);
    return v + (t == NULL ? 1000 : 0) + n;
}
JNIEXPORT jint JNICALL Java_com_huntress_kb2_Env_useAfterDelete(JNIEnv *env, jclass c, jstring s) {
    (*env)->DeleteLocalRef(env, s);
    return (*env)->GetStringUTFLength(env, s);
}
'''
LOAD_VARIANTS = (("kb2_load", 0, ("x86_64", "arm64")), ("kb2_load_ctoronly", 6, ("x86_64", "arm64")),
                 ("kb2_load_badctor", 1, ("x86_64",)), ("kb2_load_ghost", 2, ("x86_64",)),
                 ("kb2_load_badver", 3, ("x86_64",)), ("kb2_load_noclass", 4, ("x86_64",)))

# r3 (the fixer round of the first adversarial review of the KB-2 build): one small library per shape the review
# showed answered wrong, or answered where it should not, or slowly. Each is a real clang object linked by the
# mini-linker; `kb2_r3_triv_armv7a.o` is a 32-bit ARM OBJECT (no ELF32 linker here) that stands for the
# armeabi-v7a build of the same source: the engine cannot load it and must see that it exports the name.
R3_SOURCES = {
    # a constructor mallocs a counter; tick() steps it (the next call would see the change), peek() only reads it
    "kb2_r3_heap": r'''
#include <jni.h>
#include <stdlib.h>
static long long *kb2_ctr;
__attribute__((constructor)) static void kb2_ctor(void) { kb2_ctr = (long long *)malloc(8); *kb2_ctr = 5; }
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_tick(JNIEnv *e, jclass c, jlong x) {
    long long v = *kb2_ctr; *kb2_ctr = v * 7 + 1; return x + v;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_peek(JNIEnv *e, jclass c, jlong x) { return x + *kb2_ctr; }
''',
    # a decoy export the shipped reader's loose suffix match reads first (Aaa_*), beside the exact JNI names
    "kb2_r3_loose": r'''
#include <jni.h>
char *strrchr(const char *, int);
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Aaa_mix(JNIEnv *e, jclass c, jlong x) { return x * 3 + 0x1234; }
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *e, jclass c, jlong x) {
    const char *p = strrchr("zbcq", 'b'); return x ^ (long long)p[1] ^ 0x77;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Aaa_twin(JNIEnv *e, jclass c, jlong x) { return x * 3 + 0x1234; }
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_twin(JNIEnv *e, jclass c, jlong x) { return x * 7 + 5; }
''',
    # results that depend on an address: random on a device, so the two emulation layouts must not agree on them
    "kb2_r3_addr": r'''
#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
long long kb2_g = 7;
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_addr(JNIEnv *e, jclass c, jlong x) {
    uintptr_t a = (uintptr_t)&kb2_g;
    if (((a >> 12) & 0xffff) < 0x10) return x + 0x1111;     /* an emulator's round load address */
    return x + 0x2222;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_imageBits(JNIEnv *e, jclass c, jlong x) {
    return x + (jlong)(((uintptr_t)&kb2_g >> 12) & 0xffffff);
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_heapLow(JNIEnv *e, jclass c, jlong x) {
    char *p = (char *)malloc(16);
    if (!p) return 0;
    jlong r = x + (jlong)(((uintptr_t)p >> 4) & 0xff);
    free(p);
    return r;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_stackLow(JNIEnv *e, jclass c, jlong x) {
    volatile char buf[16];
    buf[0] = 1;
    return x + (jlong)(((uintptr_t)buf >> 4) & 0xff) + buf[0];
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_refBits(JNIEnv *e, jclass c, jlong x) {
    return x + (jlong)((uintptr_t)c & 0xfff);              /* ART's reference kind and index bits */
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_envLow(JNIEnv *e, jclass c, jlong x) {
    return x + (jlong)((uintptr_t)e & 0xfff);
}
/* a native that tells a NULL object from a non-NULL one (identical calls are evaluated once: never these two) */
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_isNull(JNIEnv *e, jclass c, jobject o) {
    return o == NULL ? 1 : 2;
}
''',
    # a modified elements buffer read back through GetByteArrayRegion before the release (pinned vs copied)
    "kb2_r3_pin": r'''
#include <jni.h>
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_pin(JNIEnv *env, jclass c, jbyteArray a) {
    jbyte *e = (*env)->GetByteArrayElements(env, a, NULL);
    if (!e) return 0;
    e[0] = (jbyte)(e[0] + 1);
    jbyte b[1];
    (*env)->GetByteArrayRegion(env, a, 0, 1, b);
    (*env)->ReleaseByteArrayElements(env, a, e, 0);
    return (jlong)(b[0] & 0xff) + 0x100;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_pinSet(JNIEnv *env, jclass c, jbyteArray a) {
    jbyte *e = (*env)->GetByteArrayElements(env, a, NULL);
    if (!e) return 0;
    jbyte v = 9;
    (*env)->SetByteArrayRegion(env, a, 0, 1, &v);
    jlong r = e[0];
    (*env)->ReleaseByteArrayElements(env, a, e, JNI_ABORT);
    return r + 0x200;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_pinTwice(JNIEnv *env, jclass c, jbyteArray a) {
    jbyte *e1 = (*env)->GetByteArrayElements(env, a, NULL);
    jbyte *e2 = (*env)->GetByteArrayElements(env, a, NULL);
    if (!e1 || !e2) return 0;
    e1[0] = 5;
    jlong r = e2[0];
    (*env)->ReleaseByteArrayElements(env, a, e2, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, a, e1, JNI_ABORT);
    return r + 0x300;
}
''',
    # a native inside its block budget that spends its time inside the modelled memcpy
    "kb2_r3_burn": r'''
#include <jni.h>
#include <stdlib.h>
#include <string.h>
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_burn(JNIEnv *e, jclass c, jlong x) {
    char *a = (char *)malloc(400000); char *b = (char *)malloc(400000);
    if (!a || !b) return 1;
    memset(b, (int)x, 400000);
    for (int i = 0; i < 4900; i++) memcpy(a, b, 400000);
    long long r = a[123] + x + 7; free(a); free(b); return r;
}
''',
    # the shipped readers' bread and butter: a pure transform (timing loops, the multi-ABI and constructor cases)
    "kb2_r3_triv": r'''
#include <jni.h>
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_inc(JNIEnv *e, jclass c, jlong x) { return x * 5 + 3; }
''',
    # a benign constructor the model cannot run (an unmodelled import), beside the same pure transform
    "kb2_r3_ctorlog": r'''
#include <jni.h>
int __android_log_print(int prio, const char *tag, const char *fmt, ...);
__attribute__((constructor)) static void kb2_hello(void) { __android_log_print(4, "kb2", "loaded"); }
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_inc(JNIEnv *e, jclass c, jlong x) { return x * 5 + 3; }
''',
    # a JNI_OnLoad that keeps a LOCAL reference in a global: ART frees it when JNI_OnLoad returns
    "kb2_r3_stale": r'''
#include <jni.h>
static jclass kb2_cls;
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *r) {
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    kb2_cls = (*env)->FindClass(env, "com/huntress/kb2/NativeLab");
    return kb2_cls ? JNI_VERSION_1_6 : JNI_ERR;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_stale(JNIEnv *env, jclass c, jlong x) {
    (*env)->DeleteLocalRef(env, kb2_cls);
    return x + 1;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_fresh(JNIEnv *env, jclass c, jlong x) { return x + 2; }
''',
    # two libraries exporting one JNI name with DIFFERENT bodies: dual_a and dual_b disagree, dual_a and dual_c
    # compute the same value with different code
    "kb2_r3_dual_a": r'''
#include <jni.h>
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_dual(JNIEnv *e, jclass c, jlong x) { return x + 1; }
''',
    "kb2_r3_dual_b": r'''
#include <jni.h>
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_dual(JNIEnv *e, jclass c, jlong x) { return x + 2; }
''',
    "kb2_r3_dual_c": r'''
#include <jni.h>
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_dual(JNIEnv *e, jclass c, jlong x) {
    volatile jlong y = x; return (y ^ 0) + 1;
}
''',
}

# fix round 1 (the adversarial review of e281f95): one small library per shape the review showed answered wrong,
# declined where 6aa5104 answered, or answered slowly. x86_64 only (the emulator-check fixtures read %rip).
FIX1_SOURCES = {
    # a JNI_OnLoad that logs (liblog is modelled now) beside a plain export: the load phase is read exactly
    "kb2_f1_onlog": r'''
#include <jni.h>
int __android_log_print(int prio, const char *tag, const char *fmt, ...);
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *r) {
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    __android_log_print(4, "kb2", "JNI_OnLoad %d", 6);
    return JNI_VERSION_1_6;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *e, jclass c, jlong x) { return x * 7 + 5; }
''',
    # the usual global-reference cache in JNI_OnLoad (NewGlobalRef is not modelled) beside a plain export
    "kb2_f1_onglob": r'''
#include <jni.h>
static jclass f1_cls;
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *r) {
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass c = (*env)->FindClass(env, "com/huntress/kb2/NativeLab");
    if (!c) return JNI_ERR;
    f1_cls = (jclass)(*env)->NewGlobalRef(env, c);
    return JNI_VERSION_1_6;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *e, jclass c, jlong x) { return x * 7 + 5; }
''',
    # a helper library: a JNI_OnLoad that logs, and no Java_ export at all
    "kb2_f1_helper": r'''
#include <jni.h>
int __android_log_print(int prio, const char *tag, const char *fmt, ...);
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *r) {
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    __android_log_print(4, "helper", "loaded");
    return JNI_VERSION_1_6;
}
''',
    # a helper library whose JNI_OnLoad caches a global reference (not modelled), and no Java_ export
    "kb2_f1_helperglob": r'''
#include <jni.h>
static jclass f1_cls;
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *r) {
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass c = (*env)->FindClass(env, "com/huntress/kb2/NativeLab");
    if (!c) return JNI_ERR;
    f1_cls = (jclass)(*env)->NewGlobalRef(env, c);
    return JNI_VERSION_1_6;
}
''',
    # a JNI_OnLoad that logs, then RegisterNatives mix to a function other than its decoy export
    "kb2_f1_onlogreg": r'''
#include <jni.h>
int __android_log_print(int prio, const char *tag, const char *fmt, ...);
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *e, jclass c, jlong x) { return x + 1; }
static jlong f1_mix(JNIEnv *e, jclass c, jlong x) { return x * 11 + 7; }
static const JNINativeMethod F1_METHODS[] = {{"mix", "(J)J", (void *)f1_mix}};
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *r) {
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    __android_log_print(4, "kb2", "registering %d", 1);
    jclass cls = (*env)->FindClass(env, "com/huntress/kb2/NativeLab");
    if (!cls) return JNI_ERR;
    if ((*env)->RegisterNatives(env, cls, F1_METHODS, 1) != JNI_OK) return JNI_ERR;
    return JNI_VERSION_1_6;
}
''',
    # natives whose result depends on liblog's result, or that hand it a NULL format: both decline
    "kb2_f1_logret": r'''
#include <jni.h>
int __android_log_print(int prio, const char *tag, const char *fmt, ...);
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_logged(JNIEnv *e, jclass c, jlong x) {
    return __android_log_print(4, "kb2", "x=%lld", x) < 0 ? x : x + 1;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_lognull(JNIEnv *e, jclass c, jlong x) {
    __android_log_print(4, "kb2", (const char *)0);
    return x + 2;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_logok(JNIEnv *e, jclass c, jlong x) {
    __android_log_print(4, (const char *)0, "x=%lld", x);
    return x + 3;
}
''',
    # an emulator check on the function's own code address (the single-function engine maps every function at
    # 0x400000): the emulator leg is cheap; the device leg calls an import nothing models (getpid)
    "kb2_f1_emu": r'''
#include <jni.h>
#include <stdint.h>
int getpid(void);
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_probe(JNIEnv *e, jclass c, jlong x) {
    uintptr_t pc;
    __asm__ volatile("lea 0(%%rip), %0" : "=r"(pc));
    if ((pc >> 20) == 0x4) return x ^ 0x1111;
    return (x ^ 0x2222) + (getpid() & 0);
}
''',
    # the same check beside another class's _probe export, listed first, that the shipped loose match bound
    "kb2_f1_emuloose": r'''
#include <jni.h>
#include <stdint.h>
int getpid(void);
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Aaa_probe(JNIEnv *e, jclass c, jlong x) { return x + getpid(); }
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_probe(JNIEnv *e, jclass c, jlong x) {
    uintptr_t pc;
    __asm__ volatile("lea 0(%%rip), %0" : "=r"(pc));
    if ((pc >> 20) == 0x4) return x ^ 0x1111;
    return (x ^ 0x2222) + (getpid() & 0);
}
''',
    # the same check whose device leg spins past the whole image's work budget
    "kb2_f1_emuspin": r'''
#include <jni.h>
#include <stdint.h>
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_probe(JNIEnv *e, jclass c, jlong x) {
    uintptr_t pc;
    __asm__ volatile("lea 0(%%rip), %0" : "=r"(pc));
    if ((pc >> 20) == 0x4) return x ^ 0x1111;
    volatile unsigned long long s = 0;
    for (unsigned long i = 0; i < 100000000UL; i++) s += i;
    return x ^ 0x2222;
}
''',
    # a jint native returning a negative value
    "kb2_f1_negint": r'''
#include <jni.h>
JNIEXPORT jint JNICALL Java_com_huntress_kb2_NativeLab_sign(JNIEnv *e, jclass c, jlong x) {
    return (jint)(x & 0xff) - 200;
}
''',
    # a constructor the model cannot run (C++ operator new, an import) beside the pure transform
    "kb2_f1_ctornew": r'''
#include <jni.h>
void *_Znwm(unsigned long);
static void *f1_p;
__attribute__((constructor)) static void f1_ctor(void) { f1_p = _Znwm(16); }
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_inc(JNIEnv *e, jclass c, jlong x) { return x * 5 + 3; }
''',
    # a constructor that spins through any work budget, and an unrelated export (a library no call binds)
    "kb2_f1_spin": r'''
#include <jni.h>
volatile unsigned long long f1_acc;
static const unsigned char F1_TAB[256] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
__attribute__((constructor)) static void f1_spin(void) {
    unsigned long long a = 0;
    for (unsigned long i = 0; i < 100000000UL; i++) { a += F1_TAB[i & 255]; f1_acc = a; }
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Other_noop(JNIEnv *e, jclass c, jlong x) { return x; }
''',
    # no JNI_OnLoad and no Java_ export: a constructor reaches the JavaVM through JNI_GetCreatedJavaVMs and registers
    # NativeLab.inc to a function of its own
    "kb2_f1_seekvm": r'''
#include <jni.h>
static jlong f1_inc(JNIEnv *e, jclass c, jlong x) { return x * 13 + 1; }
static const JNINativeMethod F1_M[] = {{"inc", "(J)J", (void *)f1_inc}};
__attribute__((constructor)) static void f1_seek(void) {
    JavaVM *vm = 0;
    jsize n = 0;
    if (JNI_GetCreatedJavaVMs(&vm, 1, &n) != JNI_OK || n < 1) return;
    JNIEnv *env = 0;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return;
    jclass cls = (*env)->FindClass(env, "com/huntress/kb2/NativeLab");
    if (cls) (*env)->RegisterNatives(env, cls, F1_M, 1);
}
''',
    # the app's native mix beside an unrelated native named like a framework call the chain makes (valueOf)
    "kb2_f1_valueof": r'''
#include <jni.h>
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *e, jclass c, jlong x) { return x * 7 + 5; }
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Codec_valueOf(JNIEnv *e, jclass c, jlong x) { return x ^ 0x5555; }
''',
}

FAKE_SYS = {
    "stdio.h": "#pragma once\n#include <stddef.h>\n",
    "string.h": ("#pragma once\n#include <stddef.h>\nsize_t strlen(const char*);\n"
                 "void *memcpy(void*,const void*,size_t);\nvoid *memmove(void*,const void*,size_t);\n"
                 "void *memset(void*,int,size_t);\nint memcmp(const void*,const void*,size_t);\n"
                 "int strcmp(const char*,const char*);\nint strncmp(const char*,const char*,size_t);\n"
                 "char *strcpy(char*,const char*);\nchar *strncpy(char*,const char*,size_t);\n"
                 "char *strchr(const char*,int);\n"),
    "stdlib.h": ("#pragma once\n#include <stddef.h>\nvoid *malloc(size_t);\nvoid *calloc(size_t,size_t);\n"
                 "void *realloc(void*,size_t);\nvoid free(void*);\n"),
}

# ------------------------------------------------------------------------------------------- ELF reading
SHT_SYMTAB, SHT_STRTAB, SHT_RELA, SHT_NOBITS = 2, 3, 4, 8
SHF_WRITE, SHF_ALLOC, SHF_EXEC = 1, 2, 4


def _parse_obj(data):
    assert data[:4] == b"\x7fELF" and data[4] == 2 and data[5] == 1, "ELF64 LE relocatable expected"
    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    assert e_type == 1, "ET_REL expected"
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3a)
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from("<IIQQQQIIQQ", data, o)
        secs.append(dict(idx=i, name_off=name, type=typ, flags=flags, offset=off, size=size, link=link,
                         info=info, align=max(align, 1), entsize=entsize))
    shstr = secs[e_shstrndx]
    for s in secs:
        st = shstr["offset"] + s["name_off"]
        s["name"] = data[st:data.index(b"\x00", st)].decode()
        s["data"] = b"" if s["type"] == SHT_NOBITS else data[s["offset"]:s["offset"] + s["size"]]
    syms = []
    symsec = next(s for s in secs if s["type"] == SHT_SYMTAB)
    strsec = secs[symsec["link"]]
    for k in range(symsec["size"] // 24):
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(
            "<IBBHQQ", data, symsec["offset"] + 24 * k)
        p = strsec["offset"] + st_name
        nm = data[p:data.index(b"\x00", p)].decode()
        syms.append(dict(name=nm, bind=st_info >> 4, type=st_info & 15, vis=st_other & 3, shndx=st_shndx,
                         value=st_value, size=st_size))
    relas = {}
    for s in secs:
        if s["type"] == SHT_RELA:
            ents = []
            for k in range(s["size"] // 24):
                r_off, r_info, r_add = struct.unpack_from("<QQq", data, s["offset"] + 24 * k)
                ents.append((r_off, r_info & 0xFFFFFFFF, r_info >> 32, r_add))
            relas[s["info"]] = ents
    return e_machine, secs, syms, relas


# ------------------------------------------------------------------------------------------- linker
def _align(x, a):
    return (x + a - 1) // a * a


def _sysv_hash(name):
    h = 0
    for ch in name.encode():
        h = ((h << 4) + ch) & 0xFFFFFFFF
        g = h & 0xF0000000
        if g:
            h ^= g >> 24
        h &= ~g & 0xFFFFFFFF
    return h


def link_so(obj, soname="libkb2.so", strip_sections=False, init_sym=None):
    """Link ONE relocatable ELF64 object into a shared object (see the module docstring). An `.init_array`
    section becomes DT_INIT_ARRAY / DT_INIT_ARRAYSZ (its pointers R_*_RELATIVE), and `init_sym` names the
    function DT_INIT points at (lld's -init=)."""
    mach, secs, syms, relas = _parse_obj(obj)
    x86 = mach == EM_X86_64
    assert mach in (EM_X86_64, EM_AARCH64)
    keep = [s for s in secs if (s["flags"] & SHF_ALLOC) and s["size"] and not s["name"].startswith(".eh_frame")
            and not s["name"].startswith(".note")]
    groups = {"text": [], "rodata": [], "relro": [], "data": [], "bss": []}
    for s in keep:
        if s["flags"] & SHF_EXEC:
            groups["text"].append(s)
        elif s["type"] == SHT_NOBITS:
            groups["bss"].append(s)
        elif s["flags"] & SHF_WRITE:
            groups["relro" if s["name"].startswith(".data.rel.ro") else "data"].append(s)
        else:
            groups["rodata"].append(s)

    def sym_defined(sm):
        return sm["shndx"] not in (0, 0xFFF1, 0xFFF2) and sm["shndx"] < 0xFF00

    def preemptible(sm):
        return sm["bind"] in (1, 2) and sm["vis"] == 0 and sm["type"] in (0, 1, 2)

    # pass 1: which symbols need a PLT entry / a GOT entry / a dynsym slot
    plt_syms, got_syms, dyn_imports, dyn_exports = [], [], [], []
    for sm in syms:
        if sm["bind"] in (1, 2) and sym_defined(sm) and sm["vis"] in (0, 3) and sm["name"]:
            dyn_exports.append(sm["name"])
    for tgt, ents in relas.items():
        if not any(s["idx"] == tgt for s in keep):
            continue
        for (r_off, rtype, symi, add) in ents:
            sm = syms[symi]
            name = sm["name"]
            pre = preemptible(sm) and (sm["shndx"] == 0 or sm["bind"] in (1, 2))
            if sm["shndx"] == 0 and name not in dyn_imports:
                dyn_imports.append(name)
            if (x86 and rtype == 4) or ((not x86) and rtype in (282, 283)):
                if pre and name not in plt_syms:
                    plt_syms.append(name)
            if (x86 and rtype in (9, 41, 42)) or ((not x86) and rtype in (311, 312)):
                key = (name if sm["type"] != 3 else "#sec%d" % sm["shndx"], symi)
                if key[0] not in [g[0] for g in got_syms]:
                    got_syms.append(key)
            if ((x86 and rtype == 1) or ((not x86) and rtype == 257)) and pre and sm["shndx"] != 0:
                pass   # an absolute pointer to a preemptible definition: a symbolic dynamic relocation
    dynsym_names = [""] + dyn_imports + [n for n in dyn_exports if n not in dyn_imports]
    dynstr = b"\x00"
    dynstr_off = {}
    for n in dynsym_names[1:] + [soname]:
        dynstr_off[n] = len(dynstr)
        dynstr += n.encode() + b"\x00"

    plt0 = 16 if x86 else 32
    plt_size = plt0 + 16 * len(plt_syms) if plt_syms else 0
    # layout ------------------------------------------------------------------------------------
    nph = 7
    hdr_end = 64 + 56 * nph
    dynsym_addr = _align(hdr_end, 8)
    dynstr_addr = dynsym_addr + 24 * len(dynsym_names)
    hash_addr = _align(dynstr_addr + len(dynstr), 8)
    nbucket = max(1, len(dynsym_names) | 1)
    hash_size = 4 * (2 + nbucket + len(dynsym_names))
    # dynamic relocations are counted after layout; reserve generously and fix sizes at the end
    rela_addr = _align(hash_addr + hash_size, 8)
    max_rel = 64 + sum(len(v) for v in relas.values())
    relaplt_addr = rela_addr + 24 * max_rel
    seg0_end = relaplt_addr + 24 * len(plt_syms)

    addr_of = {}
    text_addr = _align(seg0_end, PAGE)
    plt_addr = text_addr
    cur = plt_addr + plt_size
    for s in groups["text"]:
        cur = _align(cur, s["align"])
        addr_of[s["idx"]] = cur
        cur += s["size"]
    text_end = cur
    ro_addr = _align(text_end, PAGE)
    cur = ro_addr
    for s in groups["rodata"]:
        cur = _align(cur, s["align"])
        addr_of[s["idx"]] = cur
        cur += s["size"]
    ro_end = max(cur, ro_addr + 1)
    rw_addr = _align(ro_end, PAGE)
    cur = rw_addr
    for s in groups["relro"]:
        cur = _align(cur, s["align"])
        addr_of[s["idx"]] = cur
        cur += s["size"]
    dyn_addr = _align(cur, 8)
    ndyn = 24
    cur = dyn_addr + 16 * ndyn
    got_addr = cur
    cur += 8 * len(got_syms)
    relro_end = cur
    gotplt_addr = _align(cur, PAGE)          # lld pads so PT_GNU_RELRO ends on a page (bionic rounds it up)
    cur = gotplt_addr + (8 * (3 + len(plt_syms)) if plt_syms else 0)
    for s in groups["data"]:
        cur = _align(cur, s["align"])
        addr_of[s["idx"]] = cur
        cur += s["size"]
    file_end = cur
    for s in groups["bss"]:
        cur = _align(cur, s["align"])
        addr_of[s["idx"]] = cur
        cur += s["size"]
    mem_end = cur

    img = bytearray(file_end)
    for s in groups["text"] + groups["rodata"] + groups["relro"] + groups["data"]:
        img[addr_of[s["idx"]]:addr_of[s["idx"]] + s["size"]] = s["data"]

    def sym_addr(sm):
        if sm["type"] == 3:                       # STT_SECTION
            return addr_of[sm["shndx"]]
        if sym_defined(sm):
            return addr_of[sm["shndx"]] + sm["value"]
        return None

    dynidx = {n: i for i, n in enumerate(dynsym_names)}
    plt_of = {n: plt_addr + plt0 + 16 * i for i, n in enumerate(plt_syms)}
    got_of = {g[0]: got_addr + 8 * i for i, g in enumerate(got_syms)}
    R_REL = 8 if x86 else 1027
    R_GLOB = 6 if x86 else 1025
    R_JUMP = 7 if x86 else 1026
    R_ABS = 1 if x86 else 257
    dyn_rel = []
    for i, (gname, symi) in enumerate(got_syms):
        sm = syms[symi]
        a = sym_addr(sm)
        slot = got_addr + 8 * i
        if sm["shndx"] == 0 or (preemptible(sm) and sm["type"] != 3):
            dyn_rel.append((slot, R_GLOB, dynidx[sm["name"]], 0))
        else:
            dyn_rel.append((slot, R_REL, 0, a))

    def put32(p, v):
        struct.pack_into("<i", img, p, v)

    def patch_a64(p, fn):
        w = struct.unpack_from("<I", img, p)[0]
        struct.pack_into("<I", img, p, fn(w) & 0xFFFFFFFF)

    def adrp(w, target, P):
        imm = ((target & ~0xFFF) - (P & ~0xFFF)) >> 12
        assert -(1 << 20) <= imm < (1 << 20)
        imm &= (1 << 21) - 1
        return (w & 0x9F00001F) | ((imm & 3) << 29) | ((imm >> 2) << 5)

    def lo12(w, value, shift):
        return (w & ~(0xFFF << 10)) | ((((value & 0xFFF) >> shift) & 0xFFF) << 10)

    for tgt, ents in relas.items():
        if tgt not in addr_of:
            continue
        base = addr_of[tgt]
        for (r_off, rtype, symi, add) in ents:
            sm = syms[symi]
            P = base + r_off
            S = sym_addr(sm)
            pre = preemptible(sm) and sm["type"] != 3
            if x86:
                if rtype in (2, 4):              # PC32 / PLT32
                    t = plt_of[sm["name"]] if (rtype == 4 and sm["name"] in plt_of) else S
                    assert t is not None, "PC32 to an undefined symbol %s" % sm["name"]
                    put32(P, t + add - P)
                elif rtype in (9, 41, 42):       # GOTPCREL(X)
                    g = got_of[sm["name"] if sm["type"] != 3 else "#sec%d" % sm["shndx"]]
                    put32(P, g + add - P)
                elif rtype == 1:                 # R_X86_64_64 in data
                    if S is not None and not pre:
                        dyn_rel.append((P, R_REL, 0, S + add))
                    else:
                        dyn_rel.append((P, R_ABS, dynidx[sm["name"]], add))
                    struct.pack_into("<Q", img, P, 0)
                else:
                    raise ValueError("x86-64 relocation type %d not handled" % rtype)
            else:
                if rtype in (282, 283):          # JUMP26 / CALL26
                    t = plt_of.get(sm["name"]) if sm["name"] in plt_of else S + add
                    off = (t - P) >> 2
                    patch_a64(P, lambda w, o=off: (w & 0xFC000000) | (o & 0x3FFFFFF))
                elif rtype == 275:               # ADR_PREL_PG_HI21
                    assert S is not None
                    patch_a64(P, lambda w, t=S + add, p=P: adrp(w, t, p))
                elif rtype in (277, 278, 284, 285, 286, 299):
                    shift = {277: 0, 278: 0, 284: 1, 285: 2, 286: 3, 299: 4}[rtype]
                    patch_a64(P, lambda w, v=S + add, s=shift: lo12(w, v, s))
                elif rtype == 311:               # ADR_GOT_PAGE
                    g = got_of[sm["name"] if sm["type"] != 3 else "#sec%d" % sm["shndx"]]
                    patch_a64(P, lambda w, t=g, p=P: adrp(w, t, p))
                elif rtype == 312:               # LD64_GOT_LO12_NC
                    g = got_of[sm["name"] if sm["type"] != 3 else "#sec%d" % sm["shndx"]]
                    patch_a64(P, lambda w, v=g: lo12(w, v, 3))
                elif rtype == 257:               # ABS64
                    if S is not None and not pre:
                        dyn_rel.append((P, R_REL, 0, S + add))
                    else:
                        dyn_rel.append((P, R_ABS, dynidx[sm["name"]], add))
                    struct.pack_into("<Q", img, P, 0)
                else:
                    raise ValueError("AArch64 relocation type %d not handled" % rtype)
    assert len(dyn_rel) <= max_rel

    # PLT + .got.plt -------------------------------------------------------------------------------
    plt_rel = []
    if plt_syms:
        gp = gotplt_addr
        struct.pack_into("<Q", img, gp, dyn_addr)
        if x86:
            p0 = plt_addr
            img[p0:p0 + 16] = (b"\xff\x35" + struct.pack("<i", gp + 8 - (p0 + 6)) +
                               b"\xff\x25" + struct.pack("<i", gp + 16 - (p0 + 12)) + b"\x0f\x1f\x40\x00")
            for i, n in enumerate(plt_syms):
                pn = plt_of[n]
                slot = gp + 8 * (3 + i)
                img[pn:pn + 16] = (b"\xff\x25" + struct.pack("<i", slot - (pn + 6)) +
                                   b"\x68" + struct.pack("<I", i) + b"\xe9" + struct.pack("<i", p0 - (pn + 16)))
                struct.pack_into("<Q", img, slot, pn + 6)
                plt_rel.append((slot, R_JUMP, dynidx[n], 0))
        else:
            p0 = plt_addr
            t = gp + 16
            words = [0xA9BF7BF0, adrp(0x90000010, t, p0 + 4), lo12(0xF9400211, t, 3), lo12(0x91000210, t, 0),
                     0xD61F0220, 0xD503201F, 0xD503201F, 0xD503201F]
            img[p0:p0 + 32] = b"".join(struct.pack("<I", w) for w in words)
            for i, n in enumerate(plt_syms):
                pn = plt_of[n]
                slot = gp + 8 * (3 + i)
                words = [adrp(0x90000010, slot, pn), lo12(0xF9400211, slot, 3), lo12(0x91000210, slot, 0), 0xD61F0220]
                img[pn:pn + 16] = b"".join(struct.pack("<I", w) for w in words)
                struct.pack_into("<Q", img, slot, p0)
                plt_rel.append((slot, R_JUMP, dynidx[n], 0))

    # dynsym / dynstr / hash / relocation tables ---------------------------------------------------
    sym_by_name = {}
    for sm in syms:
        if sm["name"] and sm["bind"] in (1, 2):
            sym_by_name[sm["name"]] = sm
    for i, n in enumerate(dynsym_names):
        o = dynsym_addr + 24 * i
        if i == 0:
            img[o:o + 24] = b"\x00" * 24
            continue
        sm = sym_by_name[n]
        if sm["shndx"] == 0:
            struct.pack_into("<IBBHQQ", img, o, dynstr_off[n], (sm["bind"] << 4) | 0, 0, 0, 0, 0)
        else:
            shndx = 1 + [s["idx"] for s in keep].index(sm["shndx"]) if not strip_sections else 1
            struct.pack_into("<IBBHQQ", img, o, dynstr_off[n], (sm["bind"] << 4) | sm["type"], sm["vis"],
                             shndx, sym_addr(sm), sm["size"])
    img[dynstr_addr:dynstr_addr + len(dynstr)] = dynstr
    buckets = [0] * nbucket
    chains = [0] * len(dynsym_names)
    for i in range(1, len(dynsym_names)):
        b = _sysv_hash(dynsym_names[i]) % nbucket
        chains[i] = buckets[b]
        buckets[b] = i
    struct.pack_into("<II", img, hash_addr, nbucket, len(dynsym_names))
    struct.pack_into("<%dI" % nbucket, img, hash_addr + 8, *buckets)
    struct.pack_into("<%dI" % len(chains), img, hash_addr + 8 + 4 * nbucket, *chains)
    dyn_rel.sort(key=lambda r: (r[1] != R_REL, r[0]))
    for i, (off, typ, si, add) in enumerate(dyn_rel):
        struct.pack_into("<QQq", img, rela_addr + 24 * i, off, (si << 32) | typ, add)
    relaplt_addr = rela_addr + 24 * len(dyn_rel)
    for i, (off, typ, si, add) in enumerate(plt_rel):
        struct.pack_into("<QQq", img, relaplt_addr + 24 * i, off, (si << 32) | typ, add)

    dyn = [(4, hash_addr), (5, dynstr_addr), (6, dynsym_addr), (10, len(dynstr)), (11, 24),
           (14, dynstr_off[soname]), (7, rela_addr), (8, 24 * len(dyn_rel)), (9, 24),
           (0x6ffffff9, sum(1 for r in dyn_rel if r[1] == R_REL))]
    if plt_rel:
        dyn += [(3, gotplt_addr), (2, 24 * len(plt_rel)), (20, 7), (23, relaplt_addr)]
    inits = [s for s in keep if s["type"] == 14]           # SHT_INIT_ARRAY
    assert len(inits) <= 1, "one .init_array section expected"
    if inits:
        dyn += [(25, addr_of[inits[0]["idx"]]), (27, inits[0]["size"])]
    if init_sym is not None:
        sm = next(s for s in syms if s["name"] == init_sym and sym_defined(s))
        dyn.append((12, sym_addr(sm)))
    dyn.append((0, 0))
    assert len(dyn) <= ndyn
    for i, (tag, val) in enumerate(dyn):
        struct.pack_into("<QQ", img, dyn_addr + 16 * i, tag, val)

    # program headers ---------------------------------------------------------------------------
    phdrs = [
        (1, 4, 0, 0, seg0_end, seg0_end, PAGE),                                    # PT_LOAD R
        (1, 5, text_addr, text_addr, text_end - text_addr, text_end - text_addr, PAGE),   # R+X
        (1, 4, ro_addr, ro_addr, ro_end - ro_addr, ro_end - ro_addr, PAGE),         # R
        (1, 6, rw_addr, rw_addr, file_end - rw_addr, mem_end - rw_addr, PAGE),      # RW
        (2, 6, dyn_addr, dyn_addr, 16 * ndyn, 16 * ndyn, 8),                        # PT_DYNAMIC
        (0x6474E552, 4, rw_addr, rw_addr, relro_end - rw_addr, relro_end - rw_addr, 1),   # PT_GNU_RELRO
        (0x6474E551, 6, 0, 0, 0, 0, 16),                                            # PT_GNU_STACK
    ]
    for i, (pt, fl, off, va, fs, ms, al) in enumerate(phdrs):
        struct.pack_into("<IIQQQQQQ", img, 64 + 56 * i, pt, fl, off, va, va, fs, ms, al)

    # section headers (optional) -------------------------------------------------------------------
    shdrs = []
    shstr = b"\x00"

    def sh(name, typ, flags, addr, off, size, link=0, info=0, align=1, ent=0):
        nonlocal shstr
        no = len(shstr)
        shstr += name.encode() + b"\x00"
        shdrs.append((no, typ, flags, addr, off, size, link, info, align, ent))
        return len(shdrs) - 1
    extra = bytearray()
    if not strip_sections:
        sh("", 0, 0, 0, 0, 0)
        for s in keep:                                    # 1..len(keep): the input sections in place
            sh(s["name"], s["type"], s["flags"], addr_of[s["idx"]], addr_of[s["idx"]] if s["type"] != SHT_NOBITS
               else file_end, s["size"], align=s["align"], ent=s["entsize"])
        i_dynsym = sh(".dynsym", 11, SHF_ALLOC, dynsym_addr, dynsym_addr, 24 * len(dynsym_names), info=1,
                      align=8, ent=24)
        i_dynstr = sh(".dynstr", 3, SHF_ALLOC, dynstr_addr, dynstr_addr, len(dynstr))
        shdrs[i_dynsym] = shdrs[i_dynsym][:6] + (i_dynstr,) + shdrs[i_dynsym][7:]
        sh(".hash", 5, SHF_ALLOC, hash_addr, hash_addr, hash_size, link=i_dynsym, align=8, ent=4)
        sh(".rela.dyn", 4, SHF_ALLOC, rela_addr, rela_addr, 24 * len(dyn_rel), link=i_dynsym, align=8, ent=24)
        if plt_syms:
            sh(".plt", 1, SHF_ALLOC | SHF_EXEC, plt_addr, plt_addr, plt_size, align=16)
        sh(".dynamic", 6, SHF_ALLOC | SHF_WRITE, dyn_addr, dyn_addr, 16 * ndyn, link=i_dynstr, align=8, ent=16)
        if got_syms:
            sh(".got", 1, SHF_ALLOC | SHF_WRITE, got_addr, got_addr, 8 * len(got_syms), align=8, ent=8)
        if plt_syms:
            i_gotplt = sh(".got.plt", 1, SHF_ALLOC | SHF_WRITE, gotplt_addr, gotplt_addr, 8 * (3 + len(plt_syms)),
                          align=8, ent=8)
            sh(".rela.plt", 4, SHF_ALLOC | 0x40, relaplt_addr, relaplt_addr, 24 * len(plt_rel), link=i_dynsym,
               info=i_gotplt, align=8, ent=24)
        # .symtab with the locals (functions and objects) and every global, at their final addresses
        strtab = b"\x00"
        symtab = b"\x00" * 24
        locs = [sm for sm in syms if sm["bind"] == 0 and sm["type"] in (1, 2) and sm["name"] and sym_defined(sm)]
        globs = [sm for sm in syms if sm["bind"] in (1, 2) and sm["name"]]
        for sm in locs + globs:
            no = len(strtab)
            strtab += sm["name"].encode() + b"\x00"
            if sym_defined(sm):
                shn = 1 + [s["idx"] for s in keep].index(sm["shndx"])
                symtab += struct.pack("<IBBHQQ", no, (sm["bind"] << 4) | sm["type"], sm["vis"], shn,
                                      sym_addr(sm), sm["size"])
            else:
                symtab += struct.pack("<IBBHQQ", no, (sm["bind"] << 4), 0, 0, 0, 0)
        base_off = _align(file_end, 8)
        extra += b"\x00" * (base_off - file_end)
        st_off = base_off + len(extra) - (base_off - file_end)
        st_off = file_end + len(extra)
        extra += symtab
        i_strtab_off = file_end + len(extra)
        extra += strtab
        i_symtab = sh(".symtab", 2, 0, 0, st_off, len(symtab), info=1 + len(locs), align=8, ent=24)
        i_strtab = sh(".strtab", 3, 0, 0, i_strtab_off, len(strtab))
        shdrs[i_symtab] = shdrs[i_symtab][:6] + (i_strtab,) + shdrs[i_symtab][7:]
        i_shstr = sh(".shstrtab", 3, 0, 0, 0, 0)
        shstr_off = file_end + len(extra)
        extra += shstr
        shdrs[i_shstr] = shdrs[i_shstr][:4] + (shstr_off, len(shstr)) + shdrs[i_shstr][6:]
        while (file_end + len(extra)) % 8:
            extra += b"\x00"
        shoff = file_end + len(extra)
        for h in shdrs:
            extra += struct.pack("<IIQQQQIIQQ", *h)
        shnum, shstrndx = len(shdrs), i_shstr
    else:
        shoff, shnum, shstrndx = 0, 0, 0
    ehdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr += struct.pack("<HHIQQQIHHHHHH", 3, mach, 1, 0, 64, shoff, 0, 64, 56, len(phdrs), 64, shnum, shstrndx)
    img[0:64] = ehdr
    return bytes(img) + bytes(extra)


FIX2_SOURCES = {
    # the review of 4250749 (its adv_build.py): an emulator check on the legacy engine's fixed code base, a NULL-JNIEnv
    # test, and a plain step, for the delivery caps and the size / image-problem bounds (item b)
    "kb2_f2_probe": r"""
#include <jni.h>
#include <stdint.h>
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_step(JNIEnv *e, jclass c, jlong x) { return x + 1; }
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_probe(JNIEnv *e, jclass c, jlong x) {
    uintptr_t pc;
    __asm__ volatile("lea 0(%%rip), %0" : "=r"(pc));
    if ((pc >> 20) == 0x4) return x ^ 0x1111;     /* the single-function engine's fixed code base */
    return x ^ 0x2222;                            /* a device */
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_envchk(JNIEnv *e, jclass c, jlong x) {
    if (e == 0 || c == 0) return x ^ 0x3333;      /* a harness that passes a NULL JNIEnv / jclass */
    return x ^ 0x4444;                            /* a device: ART never passes NULL */
}
""",
    # two calls of ~11,000 blocks a run: the delivery's work total overspent before fix round 2 (item b)
    "kb2_f2_burn": r"""
#include <jni.h>
#include <stdint.h>
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_burn(JNIEnv *e, jclass c, jlong x) {
    unsigned long long h = (unsigned long long)x;
    for (int i = 0; i < 11000; i++) {
        h = h * 6364136223846793005ULL + 1442695040888963407ULL;
        __asm__ volatile("" : "+r"(h));
    }
    return (jlong)h;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_probe(JNIEnv *e, jclass c, jlong x) {
    uintptr_t pc;
    __asm__ volatile("lea 0(%%rip), %0" : "=r"(pc));
    if ((pc >> 20) == 0x4) return x ^ 0x1111;
    return x ^ 0x2222;
}
""",
    # a JNI_OnLoad that caches a global reference (not modelled) and THEN registers mix to another function (item c)
    "kb2_f2_reghide": r"""
#include <jni.h>
static jclass g_cls;
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *e, jclass c, jlong x) { return x * 7 + 5; }
static jlong f_real(JNIEnv *e, jclass c, jlong x) { return x * 11 + 7; }
static const JNINativeMethod M[] = {{"mix", "(J)J", (void *)f_real}};
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *r) {
    JNIEnv *env = 0;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass c = (*env)->FindClass(env, "com/huntress/kb2/NativeLab");
    if (!c) return JNI_ERR;
    g_cls = (jclass)(*env)->NewGlobalRef(env, c);
    if ((*env)->RegisterNatives(env, c, M, 1) != JNI_OK) return JNI_ERR;
    return JNI_VERSION_1_6;
}
""",
    # overloaded natives exported under their LONG JNI names, of an app class named like a framework class the dex VM
    # models by suffix (HexLong): the shipped reader asked about the long name ran Long.toHexString (the minor item)
    "kb2_f2_hexlong": r"""
#include <jni.h>
JNIEXPORT jstring JNICALL Java_com_huntress_kb2_HexLong_toHexString__J(JNIEnv *e, jclass c, jlong x) {
    return (*e)->NewStringUTF(e, "deadbeefcafebabe");
}
JNIEXPORT jstring JNICALL Java_com_huntress_kb2_HexLong_toHexString__I(JNIEnv *e, jclass c, jint x) {
    return (*e)->NewStringUTF(e, "0000000000000000");
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_HexLong_fold__J(JNIEnv *e, jclass c, jlong x) { return x * 3 + 4; }
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_HexLong_fold__I(JNIEnv *e, jclass c, jint x) { return x * 5 + 6; }
""",
    # the long-name jlong overload computed with other bytes (equal results): a second body of one machine
    "kb2_f2_hexlong2": r"""
#include <jni.h>
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_HexLong_fold__J(JNIEnv *e, jclass c, jlong x) {
    __asm__ volatile("nop");
    return x * 3 + 4;
}
""",
    # two libraries of one machine whose JNI_OnLoad each registers regOnly (equal results, different bytes): which
    # library a device loads decides the binding (the port onto so-ambig: decline)
    "kb2_f2_rega": r"""
#include <jni.h>
static jlong f_a(JNIEnv *e, jclass c, jlong x) { return x * 3 + 1; }
static const JNINativeMethod M[] = {{"regOnly", "(J)J", (void *)f_a}};
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *r) {
    JNIEnv *env = 0;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass c = (*env)->FindClass(env, "com/huntress/kb2/NativeLab");
    if (!c || (*env)->RegisterNatives(env, c, M, 1) != JNI_OK) return JNI_ERR;
    return JNI_VERSION_1_6;
}
""",
    "kb2_f2_regb": r"""
#include <jni.h>
static volatile int f2_tag = 2;
static jlong f_b(JNIEnv *e, jclass c, jlong x) { return x * 3 + 1; }
static const JNINativeMethod M[] = {{"regOnly", "(J)J", (void *)f_b}};
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *r) {
    JNIEnv *env = 0;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass c = (*env)->FindClass(env, "com/huntress/kb2/NativeLab");
    if (!c || (*env)->RegisterNatives(env, c, M, 1) != JNI_OK) return JNI_ERR;
    return f2_tag == 2 ? JNI_VERSION_1_6 : JNI_ERR;
}
""",
    # a second library exporting the registered method's exact name with other code
    "kb2_f2_regexp": r"""
#include <jni.h>
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_regOnly(JNIEnv *e, jclass c, jlong x) { return x * 5 + 2; }
""",
    # a native of a class under java/ (no app class may live there: ART's boot class loader owns the package)
    "kb2_f2_boot": r"""
#include <jni.h>
JNIEXPORT jlong JNICALL Java_java_lang_Evil_mix(JNIEnv *e, jclass c, jlong x) { return x * 7 + 5; }
""",
    # the exact JNI name of a class the delivery does not define (the bridge runs it as a framework method)
    "kb2_f2_ghost": r"""
#include <jni.h>
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Ghost_mix(JNIEnv *e, jclass c, jlong x) { return x * 7 + 5; }
""",
    # a JNI_OnLoad beside a 15 MiB .bss (the load phase's mapping is charged to the delivery's image-bytes budget)
    "kb2_f2_bigbss": r"""
#include <jni.h>
volatile char f2_big[15 << 20];
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *r) {
    JNIEnv *env = 0;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    f2_big[1000] = 1;
    f2_big[1000] = 0;
    return JNI_VERSION_1_6;
}
""",
}


_F3H = "#include <jni.h>\n#include <string.h>\n#include <stdlib.h>\n"
# an opaque barrier: the compiler may not fold a malloc / free pair or a pointer comparison away
_F3KEEP = "static void *keep(void *p) { __asm__ volatile(\"\" : \"+r\"(p) : : \"memory\"); return p; }\n"
FIX3_SOURCES = {
    # the review of 18ab31d (its adv_build.py): emulator checks the two layouts did not tell apart, each a decoy leg
    # (x ^ 0x1111) against the device's (x ^ 0x2222)
    "kb2_f3_res0": _F3H + r"""
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *env, jclass c, jlong x) {
    const struct JNINativeInterface_ *t = *env;
    if (t->reserved0 != 0) return x ^ 0x1111;   /* an emulator's fake table: decoy leg */
    return x ^ 0x2222;                           /* a device: ART's table is NULL there */
}
""",
    "kb2_f3_stride": _F3H + r"""
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *env, jclass c, jlong x) {
    const struct JNINativeInterface_ *t = *env;
    long d = (const char *)t->GetStringUTFChars - (const char *)t->GetVersion;
    if (d == 16L * (169 - 4)) return x ^ 0x1111; /* a table of 16-byte trampolines: decoy leg */
    return x ^ 0x2222;
}
""",
    "kb2_f3_honest": _F3H + r"""
static const unsigned char T[16] = {3,1,4,1,5,9,2,6,5,3,5,8,9,7,9,3};
__attribute__((noinline)) unsigned long helper(unsigned long x, const char *s) {
    unsigned long n = strlen(s);
    for (unsigned long i = 0; i < n; i++) x = (x ^ T[(x + i) & 15]) * 0x100000001B3UL;
    return x;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *env, jclass c, jlong x) {
    return (jlong)helper((unsigned long)x, "huntress");
}
""",
    "kb2_f3_handles": _F3H + r"""
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix2(JNIEnv *env, jclass c, jstring s) {
    jstring t = (*env)->NewStringUTF(env, "a");
    long d = (long)((char *)t - (char *)s);
    if (d == 0x10) return 0x1111;                /* an emulator's sequential handles: decoy leg */
    return 0x2222;
}
""",
    "kb2_f3_heap": _F3H + r"""
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *env, jclass c, jlong x) {
    char *a = malloc(16), *b = malloc(16);
    long d = b - a;
    free(b); free(a);
    if (d == 32) return x ^ 0x1111;
    return x ^ 0x2222;
}
""",
    "kb2_f3_vmres": _F3H + r"""
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
""",
    "kb2_f3_libcptr": _F3H + r"""
typedef unsigned long (*lenfn)(const char *);
typedef void *(*cpyfn)(void *, const void *, unsigned long);
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *env, jclass c, jlong x) {
    volatile lenfn a = strlen;
    volatile cpyfn b = memcpy;
    long d = (const char *)b - (const char *)a;
    if (d == 16) return x ^ 0x1111;              /* adjacent 16-byte stubs: an emulator's trap table */
    return x ^ 0x2222;
}
""",
    # two JNI_OnLoads that meet the same unmodelled import first (one +onload-unverified@import-getpid key): the donor
    # registers nothing, the decoy then registers mix to realfn; mix is exported by its LONG name in both
    "kb2_f3_olhonest": _F3H + r"""
int getpid(void);
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    return getpid() > 0 ? JNI_VERSION_1_6 : JNI_VERSION_1_6;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix__J(JNIEnv *e, jclass c, jlong x) { return x * 7 + 5; }
""",
    "kb2_f3_oldecoy": _F3H + r"""
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
""",
    # perf: a JNI_OnLoad that spins past its work budget, and an export that does
    "kb2_f3_burnload": _F3H + r"""
static volatile unsigned long T[8192];
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    unsigned long s = 1UL;
    for (unsigned long i = 0; i < 100000000UL; i++) {
        s += T[i & 8191] + T[(i + 1) & 8191] + T[(i + 2) & 8191] + T[(i + 3) & 8191];
        s += T[(i + 4) & 8191] + T[(i + 5) & 8191] + T[(i + 6) & 8191] + T[(i + 7) & 8191];
    }
    return s == 12345 ? 0 : JNI_VERSION_1_6;
}
""",
    "kb2_f3_burncall": _F3H + r"""
static volatile unsigned long T[8192];
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *env, jclass c, jlong x) {
    unsigned long s = (unsigned long)x;
    for (unsigned long i = 0; i < 100000000UL; i++) {
        s += T[i & 8191] + T[(i + 1) & 8191] + T[(i + 2) & 8191] + T[(i + 3) & 8191];
        s += T[(i + 4) & 8191] + T[(i + 5) & 8191] + T[(i + 6) & 8191] + T[(i + 7) & 8191];
    }
    return (jlong)s;
}
""",
    # the allocator's identity choices (beyond the review): a device's allocator hands a just-freed block of the same
    # size class back and keeps a block a realloc still fits; a bump heap does neither, in both runs alike
    "kb2_f3_reuse": _F3H + _F3KEEP + r"""
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *env, jclass c, jlong x) {
    char *a = keep(malloc(16));
    free(a);
    char *b = keep(malloc(16));
    int same = keep(a) == (void *)b;
    free(b);
    if (!same) return x ^ 0x1111;               /* a heap that never reuses: decoy leg */
    return x ^ 0x2222;
}
""",
    "kb2_f3_rshrink": _F3H + _F3KEEP + r"""
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *env, jclass c, jlong x) {
    char *p = keep(malloc(32));
    char *g = keep(malloc(16));                 /* p is not the last block */
    char *q = keep(realloc(p, 8));
    int same = q == p;
    free(q); free(g);
    if (!same) return x ^ 0x1111;               /* a realloc that always moves: decoy leg */
    return x ^ 0x2222;
}
""",
    "kb2_f3_rgrow": _F3H + _F3KEEP + r"""
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *env, jclass c, jlong x) {
    char *p = keep(malloc(17));
    char *g = keep(malloc(16));                 /* p is not the last block */
    char *q = keep(realloc(p, 24));             /* one 32-byte class on scudo and jemalloc */
    int same = q == p;
    free(q); free(g);
    if (!same) return x ^ 0x1111;
    return x ^ 0x2222;
}
""",
    "kb2_f3_rlast": _F3H + _F3KEEP + r"""
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *env, jclass c, jlong x) {
    char *p = keep(malloc(17));
    char *q = keep(realloc(p, 24));
    int same = q == p;
    free(q);
    if (!same) return x ^ 0x1111;
    return x ^ 0x2222;
}
""",
    # control: an honest native that churns the heap (a buffer grown by realloc, a scratch block freed and asked for
    # again): its value does not depend on any identity, so it is read
    "kb2_f3_hchurn": _F3H + r"""
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
""",
}
FIX3_ARM64 = ("kb2_f3_res0", "kb2_f3_stride", "kb2_f3_vmres", "kb2_f3_reuse", "kb2_f3_hchurn")   # also built for arm64


# ------------------------------------------------------------------------------------------- build
TARGETS = {"x86_64": "x86_64-linux-android21", "arm64": "aarch64-linux-android21"}


def _jni_include():
    for cand in sorted(Path("/Library/Java/JavaVirtualMachines").glob("*/Contents/Home/include")):
        if (cand / "jni.h").is_file():
            return cand
    for cand in (Path("/opt/homebrew/opt/openjdk/include"),):
        if (cand / "jni.h").is_file():
            return cand
    return None


def compile_obj(src, target, work, defines=()):
    inc = _jni_include()
    if inc is None:
        raise RuntimeError("no jni.h (a JDK) found")
    sysd = Path(work) / "sys"
    sysd.mkdir(exist_ok=True)
    for n, t in FAKE_SYS.items():
        (sysd / n).write_text(t)
    c = Path(work) / "src.c"
    c.write_text(src)
    o = Path(work) / "out.o"
    cmd = ["clang", "-target", target, "-O2", "-fPIC", "-fstack-protector-strong", "-fno-asynchronous-unwind-tables",
           "-fno-unwind-tables", "-fno-builtin", "-nostdlibinc", "-isystem", str(sysd), "-I", str(inc),
           "-I", str(inc / "darwin")] + ["-D%s" % d for d in defines] + ["-c", str(c), "-o", str(o)]
    subprocess.run(cmd, check=True, capture_output=True)
    return o.read_bytes()


def build_all(out=OUT):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    work = tempfile.mkdtemp(prefix="kb2fx-")
    made = []
    try:
        for name, src in (("kb2_jni", KB2_JNI_C), ("kb2_decoy", KB2_DECOY_C), ("kb2_gate", KB2_GATE_C)):
            for abi, target in TARGETS.items():
                obj = compile_obj(src, target, work)
                so = link_so(obj, soname="lib%s.so" % name)
                p = out / ("%s_%s.so" % (name, abi))
                p.write_bytes(so)
                made.append(p)
        obj = compile_obj(KB2_JNI_C, TARGETS["x86_64"], work)
        p = out / "kb2_jni_x86_64_stripped.so"
        p.write_bytes(link_so(obj, soname="libkb2_jni.so", strip_sections=True))
        made.append(p)
        made += build_load(out, work)
        made += build_r3(out, work)
        made += build_fix1(out, work)
        made += build_fix2(out, work)
        made += build_fix3(out, work)
        (out / "SOURCES.c").write_text("/* kb2_jni.c */\n" + KB2_JNI_C + "\n/* kb2_decoy.c */\n" + KB2_DECOY_C +
                                       "\n/* kb2_gate.c */\n" + KB2_GATE_C)
        (out / "SOURCES_LOAD.c").write_text(sources_r2())
        (out / "SOURCES_R3.c").write_text(sources_r3())
        (out / "SOURCES_FIX1.c").write_text(sources_fix1())
        (out / "SOURCES_FIX2.c").write_text(sources_fix2())
        (out / "SOURCES_FIX3.c").write_text(sources_fix3())
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return made


def sources_r2():
    return ("/* kb2_load*.c: -DVARIANT=n, see LOAD_VARIANTS in tests/native_image_fixtures.py */\n" + KB2_LOAD_C +
            "\n/* kb2_env.c */\n" + KB2_ENV_C)


def sources_r3():
    return "".join("/* %s.c */\n%s\n" % (name, src) for name, src in R3_SOURCES.items())


R3_ARM64 = ("kb2_r3_triv",)          # also built for arm64 (a benign x86_64 + arm64 pair)
R3_ARMV7A = "kb2_r3_triv"            # also compiled to a 32-bit ARM object (a library the engine cannot load)


def build_r3(out=OUT, work=None):
    """The r3 fixtures (R3_SOURCES; x86_64, plus R3_ARM64 for arm64 and R3_ARMV7A as an ELF32 ARM object)."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    own = work is None
    work = work or tempfile.mkdtemp(prefix="kb2fx-")
    made = []
    try:
        for name, src in R3_SOURCES.items():
            for abi in ("x86_64",) + (("arm64",) if name in R3_ARM64 else ()):
                obj = compile_obj(src, TARGETS[abi], work)
                p = out / ("%s_%s.so" % (name, abi))
                p.write_bytes(link_so(obj, soname="lib%s.so" % name[len("kb2_r3_"):]))
                made.append(p)
        p = out / ("%s_armv7a.o" % R3_ARMV7A)
        p.write_bytes(compile_obj(R3_SOURCES[R3_ARMV7A], "armv7a-linux-androideabi21", work))
        made.append(p)
    finally:
        if own:
            shutil.rmtree(work, ignore_errors=True)
    return made


def sources_fix1():
    return "".join("/* %s.c */\n%s\n" % (name, src) for name, src in FIX1_SOURCES.items())


def build_fix1(out=OUT, work=None):
    """The fix-round-1 fixtures (FIX1_SOURCES; x86_64)."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    own = work is None
    work = work or tempfile.mkdtemp(prefix="kb2fx-")
    made = []
    try:
        for name, src in FIX1_SOURCES.items():
            obj = compile_obj(src, TARGETS["x86_64"], work)
            p = out / ("%s_x86_64.so" % name)
            p.write_bytes(link_so(obj, soname="lib%s.so" % name[len("kb2_f1_"):]))
            made.append(p)
    finally:
        if own:
            shutil.rmtree(work, ignore_errors=True)
    return made


def sources_fix2():
    return "".join("/* %s.c */\n%s\n" % (name, src) for name, src in FIX2_SOURCES.items())


def build_fix2(out=OUT, work=None):
    """The fix-round-2 fixtures (FIX2_SOURCES; x86_64)."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    own = work is None
    work = work or tempfile.mkdtemp(prefix="kb2fx-")
    made = []
    try:
        for name, src in FIX2_SOURCES.items():
            obj = compile_obj(src, TARGETS["x86_64"], work)
            p = out / ("%s_x86_64.so" % name)
            p.write_bytes(link_so(obj, soname="lib%s.so" % name[len("kb2_f2_"):]))
            made.append(p)
    finally:
        if own:
            shutil.rmtree(work, ignore_errors=True)
    return made


def sources_fix3():
    return "".join("/* %s.c */\n%s\n" % (name, src) for name, src in FIX3_SOURCES.items())


def build_fix3(out=OUT, work=None):
    """The fix-round-3 fixtures (FIX3_SOURCES; x86_64, plus FIX3_ARM64 for arm64)."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    own = work is None
    work = work or tempfile.mkdtemp(prefix="kb2fx-")
    made = []
    try:
        for name, src in FIX3_SOURCES.items():
            for abi in ("x86_64",) + (("arm64",) if name in FIX3_ARM64 else ()):
                obj = compile_obj(src, TARGETS[abi], work)
                p = out / ("%s_%s.so" % (name, abi))
                p.write_bytes(link_so(obj, soname="lib%s.so" % name[len("kb2_f3_"):]))
                made.append(p)
    finally:
        if own:
            shutil.rmtree(work, ignore_errors=True)
    return made


def build_load(out=OUT, work=None):
    """The r2 fixtures: the load-time-code libraries (LOAD_VARIANTS, DT_INIT -> kb2_init) and kb2_env."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    own = work is None
    work = work or tempfile.mkdtemp(prefix="kb2fx-")
    made = []
    try:
        for name, variant, abis in LOAD_VARIANTS:
            for abi in abis:
                obj = compile_obj(KB2_LOAD_C, TARGETS[abi], work, defines=("VARIANT=%d" % variant,))
                p = out / ("%s_%s.so" % (name, abi))
                p.write_bytes(link_so(obj, soname="lib%s.so" % name, init_sym="kb2_init"))
                made.append(p)
        for abi in ("x86_64", "arm64"):
            obj = compile_obj(KB2_ENV_C, TARGETS[abi], work)
            p = out / ("kb2_env_%s.so" % abi)
            p.write_bytes(link_so(obj, soname="libkb2_env.so"))
            made.append(p)
    finally:
        if own:
            shutil.rmtree(work, ignore_errors=True)
    return made


if __name__ == "__main__":
    dest = OUT
    if "--out" in sys.argv:
        dest = Path(sys.argv[sys.argv.index("--out") + 1])
    if not shutil.which("clang"):
        print("clang not found")
        sys.exit(1)
    if "--load-only" in sys.argv:            # rebuild only the r2 fixtures (kb2_load*, kb2_env; the others unchanged)
        built = build_load(dest)
        (Path(dest) / "SOURCES_LOAD.c").write_text(sources_r2())
    elif "--r3-only" in sys.argv:            # rebuild only the r3 fixtures (kb2_r3_*; the others unchanged)
        built = build_r3(dest)
        (Path(dest) / "SOURCES_R3.c").write_text(sources_r3())
    elif "--fix1-only" in sys.argv:          # rebuild only the fix-round-1 fixtures (kb2_f1_*; the others unchanged)
        built = build_fix1(dest)
        (Path(dest) / "SOURCES_FIX1.c").write_text(sources_fix1())
    elif "--fix2-only" in sys.argv:          # rebuild only the fix-round-2 fixtures (kb2_f2_*; the others unchanged)
        built = build_fix2(dest)
        (Path(dest) / "SOURCES_FIX2.c").write_text(sources_fix2())
    elif "--fix3-only" in sys.argv:          # rebuild only the fix-round-3 fixtures (kb2_f3_*; the others unchanged)
        built = build_fix3(dest)
        (Path(dest) / "SOURCES_FIX3.c").write_text(sources_fix3())
    else:
        built = build_all(dest)
    for p in built:
        print("wrote", p, os.path.getsize(p))
