/* kb2_f2_probe.c */

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

/* kb2_f2_burn.c */

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

/* kb2_f2_reghide.c */

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

/* kb2_f2_hexlong.c */

#include <jni.h>
JNIEXPORT jstring JNICALL Java_com_huntress_kb2_HexLong_toHexString__J(JNIEnv *e, jclass c, jlong x) {
    return (*e)->NewStringUTF(e, "deadbeefcafebabe");
}
JNIEXPORT jstring JNICALL Java_com_huntress_kb2_HexLong_toHexString__I(JNIEnv *e, jclass c, jint x) {
    return (*e)->NewStringUTF(e, "0000000000000000");
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_HexLong_fold__J(JNIEnv *e, jclass c, jlong x) { return x * 3 + 4; }
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_HexLong_fold__I(JNIEnv *e, jclass c, jint x) { return x * 5 + 6; }

/* kb2_f2_hexlong2.c */

#include <jni.h>
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_HexLong_fold__J(JNIEnv *e, jclass c, jlong x) {
    __asm__ volatile("nop");
    return x * 3 + 4;
}

/* kb2_f2_rega.c */

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

/* kb2_f2_regb.c */

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

/* kb2_f2_regexp.c */

#include <jni.h>
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_regOnly(JNIEnv *e, jclass c, jlong x) { return x * 5 + 2; }

/* kb2_f2_boot.c */

#include <jni.h>
JNIEXPORT jlong JNICALL Java_java_lang_Evil_mix(JNIEnv *e, jclass c, jlong x) { return x * 7 + 5; }

/* kb2_f2_ghost.c */

#include <jni.h>
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Ghost_mix(JNIEnv *e, jclass c, jlong x) { return x * 7 + 5; }

/* kb2_f2_bigbss.c */

#include <jni.h>
volatile char f2_big[15 << 20];
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *r) {
    JNIEnv *env = 0;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    f2_big[1000] = 1;
    f2_big[1000] = 0;
    return JNI_VERSION_1_6;
}

