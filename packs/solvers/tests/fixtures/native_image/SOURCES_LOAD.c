/* kb2_load*.c: -DVARIANT=n, see LOAD_VARIANTS in tests/native_image_fixtures.py */

#include <jni.h>
#ifndef VARIANT
#define VARIANT 0
#endif
int getpid(void);
extern int __cxa_atexit(void (*)(void *), void *, void *);
__attribute__((visibility("hidden"))) void *__dso_handle = &__dso_handle;

static unsigned char kb2_secret[21] = { 0x1b, 0x14, 0x09, 0x77, 0x6c, 0x1b, 0x6b, 0x1c, 0x69, 0x19, 0x63, 0x1f, 0x6a, 0x18, 0x6d, 0x1e, 0x68, 0x6e, 0x62, 0x6f, 0x5a };
static unsigned long long kb2_table[8];
unsigned long long kb2_seed0 = 0x9999;   /* DT_INIT (kb2_init) sets it to 0x1234 before the constructor runs */
static int kb2_dtor_calls;

static void kb2_dtor(void *p) { kb2_dtor_calls++; (void)p; }

__attribute__((noinline, used)) void kb2_init(void) { kb2_seed0 = 0x1234; }

__attribute__((constructor)) static void kb2_ctor(void) {
#if VARIANT == 1
    kb2_seed0 ^= (unsigned long long)getpid();
#endif
    for (int i = 0; i < 21; i++) kb2_secret[i] ^= 0x5a;
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

/* kb2_env.c */

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
