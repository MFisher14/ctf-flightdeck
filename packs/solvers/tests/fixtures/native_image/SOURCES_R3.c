/* kb2_r3_heap.c */

#include <jni.h>
#include <stdlib.h>
static long long *kb2_ctr;
__attribute__((constructor)) static void kb2_ctor(void) { kb2_ctr = (long long *)malloc(8); *kb2_ctr = 5; }
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_tick(JNIEnv *e, jclass c, jlong x) {
    long long v = *kb2_ctr; *kb2_ctr = v * 7 + 1; return x + v;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_peek(JNIEnv *e, jclass c, jlong x) { return x + *kb2_ctr; }

/* kb2_r3_loose.c */

#include <jni.h>
char *strrchr(const char *, int);
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Aaa_mix(JNIEnv *e, jclass c, jlong x) { return x * 3 + 0x1234; }
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_mix(JNIEnv *e, jclass c, jlong x) {
    const char *p = strrchr("zbcq", 'b'); return x ^ (long long)p[1] ^ 0x77;
}
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_Aaa_twin(JNIEnv *e, jclass c, jlong x) { return x * 3 + 0x1234; }
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_twin(JNIEnv *e, jclass c, jlong x) { return x * 7 + 5; }

/* kb2_r3_addr.c */

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

/* kb2_r3_pin.c */

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

/* kb2_r3_burn.c */

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

/* kb2_r3_triv.c */

#include <jni.h>
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_inc(JNIEnv *e, jclass c, jlong x) { return x * 5 + 3; }

/* kb2_r3_ctorlog.c */

#include <jni.h>
int __android_log_print(int prio, const char *tag, const char *fmt, ...);
__attribute__((constructor)) static void kb2_hello(void) { __android_log_print(4, "kb2", "loaded"); }
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_inc(JNIEnv *e, jclass c, jlong x) { return x * 5 + 3; }

/* kb2_r3_stale.c */

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

/* kb2_r3_dual_a.c */

#include <jni.h>
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_dual(JNIEnv *e, jclass c, jlong x) { return x + 1; }

/* kb2_r3_dual_b.c */

#include <jni.h>
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_dual(JNIEnv *e, jclass c, jlong x) { return x + 2; }

/* kb2_r3_dual_c.c */

#include <jni.h>
JNIEXPORT jlong JNICALL Java_com_huntress_kb2_NativeLab_dual(JNIEnv *e, jclass c, jlong x) {
    volatile jlong y = x; return (y ^ 0) + 1;
}

