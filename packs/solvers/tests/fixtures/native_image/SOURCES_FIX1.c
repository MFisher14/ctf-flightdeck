/* kb2_f1_onlog.c */

#include <jni.h>
int __android_log_print(int prio, const char *tag, const char *fmt, ...);
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *r) {
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    __android_log_print(4, "kb2", "JNI_OnLoad %d", 6);
    return JNI_VERSION_1_6;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *e, jclass c, jlong x) { return x * 7 + 5; }

/* kb2_f1_onglob.c */

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

/* kb2_f1_helper.c */

#include <jni.h>
int __android_log_print(int prio, const char *tag, const char *fmt, ...);
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *r) {
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    __android_log_print(4, "helper", "loaded");
    return JNI_VERSION_1_6;
}

/* kb2_f1_helperglob.c */

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

/* kb2_f1_onlogreg.c */

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

/* kb2_f1_logret.c */

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

/* kb2_f1_emu.c */

#include <jni.h>
#include <stdint.h>
int getpid(void);
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_probe(JNIEnv *e, jclass c, jlong x) {
    uintptr_t pc;
    __asm__ volatile("lea 0(%%rip), %0" : "=r"(pc));
    if ((pc >> 20) == 0x4) return x ^ 0x1111;
    return (x ^ 0x2222) + (getpid() & 0);
}

/* kb2_f1_emuloose.c */

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

/* kb2_f1_emuspin.c */

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

/* kb2_f1_negint.c */

#include <jni.h>
JNIEXPORT jint JNICALL Java_com_huntress_kb2_NativeLab_sign(JNIEnv *e, jclass c, jlong x) {
    return (jint)(x & 0xff) - 200;
}

/* kb2_f1_ctornew.c */

#include <jni.h>
void *_Znwm(unsigned long);
static void *f1_p;
__attribute__((constructor)) static void f1_ctor(void) { f1_p = _Znwm(16); }
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_inc(JNIEnv *e, jclass c, jlong x) { return x * 5 + 3; }

/* kb2_f1_spin.c */

#include <jni.h>
volatile unsigned long long f1_acc;
static const unsigned char F1_TAB[256] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
__attribute__((constructor)) static void f1_spin(void) {
    unsigned long long a = 0;
    for (unsigned long i = 0; i < 100000000UL; i++) { a += F1_TAB[i & 255]; f1_acc = a; }
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Other_noop(JNIEnv *e, jclass c, jlong x) { return x; }

/* kb2_f1_seekvm.c */

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

/* kb2_f1_valueof.c */

#include <jni.h>
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *e, jclass c, jlong x) { return x * 7 + 5; }
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Codec_valueOf(JNIEnv *e, jclass c, jlong x) { return x ^ 0x5555; }

