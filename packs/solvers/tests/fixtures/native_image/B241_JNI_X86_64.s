    .intel_syntax noprefix
    .text
    # JNINativeInterface slots (jni.h)
    .set S_FindClass, 6
    .set S_PushLocalFrame, 19
    .set S_PopLocalFrame, 20
    .set S_NewGlobalRef, 21
    .set S_DeleteGlobalRef, 22
    .set S_DeleteLocalRef, 23
    .set S_IsSameObject, 24
    .set S_NewLocalRef, 25
    .set S_EnsureLocalCapacity, 26
    .set S_GetStringUTFLength, 168
    .set S_MonitorEnter, 217
    .set S_MonitorExit, 218
    .set S_GetJavaVM, 219
    .set S_NewWeakGlobalRef, 226
    .set S_DeleteWeakGlobalRef, 227
    .set S_GetObjectRefType, 232
    # JNIInvokeInterface slot
    .set V_GetEnv, 6

    # call JNIEnv slot \slot with env (kept in rbx) as the first argument; rsi/rdx set by the caller
    .macro JNI slot
    mov rdi, rbx
    mov rax, qword ptr [rbx]
    call qword ptr [rax + 8*\slot]
    .endm

    # every native: (JNIEnv* rdi, jclass rsi, jstring rdx [, jstring rcx])
    .macro ENTER
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi
    mov r12, rdx
    mov r13, rcx
    .endm
    .macro LEAVE
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
    .endm

start:
# ---------------------------------------------------------------- floating point
f_add:                          # (F, F) -> F
    addss xmm0, xmm1
    ret
    .balign 16, 0x90
d_mul:                          # (D, D) -> D
    mulsd xmm0, xmm1
    ret
    .balign 16, 0x90
mix:                            # (I a, F x, J b, D y) -> D = a + x + b + y
    cvtsi2sd xmm2, edx
    cvtss2sd xmm0, xmm0
    addsd xmm0, xmm2
    cvtsi2sd xmm2, rcx
    addsd xmm0, xmm2
    addsd xmm0, xmm1
    ret
    .balign 16, 0x90
f_to_int:                       # (F) -> I, truncating
    cvttss2si eax, xmm0
    ret
    .balign 16, 0x90
int_to_f:                       # (I) -> F
    cvtsi2ss xmm0, edx
    ret
    .balign 16, 0x90
f_upper:                        # returns bits 32..63 of the first vector register: not the argument
    pshufd xmm0, xmm0, 0x55
    ret
    .balign 16, 0x90
d_upper:                        # returns bits 64..127 of the first vector register
    movhlps xmm0, xmm0
    ret
    .balign 16, 0x90
f_unset:                        # returns a vector register no argument was passed in
    movaps xmm0, xmm3
    ret
    .balign 16, 0x90
f_nan:                          # 0.0 / 0.0
    xorps xmm0, xmm0
    divss xmm0, xmm0
    ret
    .balign 16, 0x90
f_inf:                          # x / 0.0
    xorps xmm1, xmm1
    divss xmm0, xmm1
    ret
    .balign 16, 0x90
f_rsqrt:
    rsqrtss xmm0, xmm0
    ret
    .balign 16, 0x90
i_fsin:                         # an x87 transcendental on the way to an int result
    fldz
    fsin
    fstp st(0)
    mov eax, 7
    ret
    .balign 16, 0x90
f_ninth:                        # the ninth float argument would be on the stack
    ret

# ---------------------------------------------------------------- reference lifecycle
    .balign 16, 0x90
ref_types:                      # type(s) + 10*type(global(s)) + 100*type(weak(s)) + 1000*type(NULL)
    ENTER
    mov rsi, r12
    JNI S_GetObjectRefType
    mov r14d, eax
    mov rsi, r12
    JNI S_NewGlobalRef
    mov r15, rax
    mov rsi, r15
    JNI S_GetObjectRefType
    imul eax, eax, 10
    add r14d, eax
    mov rsi, r15
    JNI S_DeleteGlobalRef
    mov rsi, r12
    JNI S_NewWeakGlobalRef
    mov r15, rax
    mov rsi, r15
    JNI S_GetObjectRefType
    imul eax, eax, 100
    add r14d, eax
    mov rsi, r15
    JNI S_DeleteWeakGlobalRef
    xor esi, esi
    JNI S_GetObjectRefType
    imul eax, eax, 1000
    add r14d, eax
    mov eax, r14d
    LEAVE

    .balign 16, 0x90
same:                           # same(s, global(s)) + 10*same(s, t) + 100*same(NULL, NULL) + 1000*same(s, NULL)
    ENTER
    mov rsi, r12
    JNI S_NewGlobalRef
    mov r15, rax
    mov rsi, r12
    mov rdx, r15
    JNI S_IsSameObject
    movzx r14d, al
    mov rsi, r12
    mov rdx, r13
    JNI S_IsSameObject
    movzx eax, al
    imul eax, eax, 10
    add r14d, eax
    xor esi, esi
    xor edx, edx
    JNI S_IsSameObject
    movzx eax, al
    imul eax, eax, 100
    add r14d, eax
    mov rsi, r12
    xor edx, edx
    JNI S_IsSameObject
    movzx eax, al
    imul eax, eax, 1000
    add r14d, eax
    mov rsi, r15
    JNI S_DeleteGlobalRef
    mov eax, r14d
    LEAVE

    .balign 16, 0x90
frame_keep:                     # Push; l = NewLocalRef(s); r = Pop(l); GetStringUTFLength(r)
    ENTER
    mov esi, 16
    JNI S_PushLocalFrame
    mov rsi, r12
    JNI S_NewLocalRef
    mov rsi, rax
    JNI S_PopLocalFrame
    mov rsi, rax
    JNI S_GetStringUTFLength
    LEAVE

    .balign 16, 0x90
frame_dead:                     # Push; l = NewLocalRef(s); Pop(NULL); GetStringUTFLength(l): l died with the frame
    ENTER
    mov esi, 16
    JNI S_PushLocalFrame
    mov rsi, r12
    JNI S_NewLocalRef
    mov r15, rax
    xor esi, esi
    JNI S_PopLocalFrame
    mov rsi, r15
    JNI S_GetStringUTFLength
    LEAVE

    .balign 16, 0x90
frame_outer:                    # l = NewLocalRef(s) BEFORE the frame; Push; Pop(NULL); GetStringUTFLength(l)
    ENTER
    mov rsi, r12
    JNI S_NewLocalRef
    mov r15, rax
    mov esi, 0
    JNI S_PushLocalFrame
    xor esi, esi
    JNI S_PopLocalFrame
    mov rsi, r15
    JNI S_GetStringUTFLength
    LEAVE

    .balign 16, 0x90
weak_use:                       # GetStringUTFLength(NewWeakGlobalRef(s)): a weak reference used unpromoted
    ENTER
    mov rsi, r12
    JNI S_NewWeakGlobalRef
    mov rsi, rax
    JNI S_GetStringUTFLength
    LEAVE

    .balign 16, 0x90
weak_promote:                   # GetStringUTFLength(NewLocalRef(NewWeakGlobalRef(s)))
    ENTER
    mov rsi, r12
    JNI S_NewWeakGlobalRef
    mov r15, rax
    mov rsi, r15
    JNI S_NewLocalRef
    mov rsi, rax
    JNI S_GetStringUTFLength
    mov r14d, eax
    mov rsi, r15
    JNI S_DeleteWeakGlobalRef
    mov eax, r14d
    LEAVE

    .balign 16, 0x90
weak_orphan:                    # w = weak(l = NewLocalRef(s)); DeleteLocalRef(l); DeleteLocalRef(s); NewLocalRef(w)
    ENTER
    mov rsi, r12
    JNI S_NewWeakGlobalRef
    mov r15, rax
    mov rsi, r12
    JNI S_DeleteLocalRef
    mov rsi, r15
    JNI S_NewLocalRef
    LEAVE

    .balign 16, 0x90
monitor_ok:
    ENTER
    mov rsi, r12
    JNI S_MonitorEnter
    mov r14d, eax
    mov rsi, r12
    JNI S_MonitorExit
    add eax, r14d
    add eax, 7
    LEAVE

    .balign 16, 0x90
monitor_leak:
    ENTER
    mov rsi, r12
    JNI S_MonitorEnter
    LEAVE

    .balign 16, 0x90
monitor_exit_only:
    ENTER
    mov rsi, r12
    JNI S_MonitorExit
    LEAVE

    .balign 16, 0x90
del_local_of_global:            # DeleteLocalRef(NewGlobalRef(s))
    ENTER
    mov rsi, r12
    JNI S_NewGlobalRef
    mov rsi, rax
    JNI S_DeleteLocalRef
    LEAVE

    .balign 16, 0x90
del_global_of_local:            # DeleteGlobalRef(s)
    ENTER
    mov rsi, r12
    JNI S_DeleteGlobalRef
    LEAVE

    .balign 16, 0x90
push_big:                       # PushLocalFrame(1000)
    ENTER
    mov esi, 1000
    JNI S_PushLocalFrame
    LEAVE

    .balign 16, 0x90
ensure_ok:                      # EnsureLocalCapacity(64) + 5
    ENTER
    mov esi, 64
    JNI S_EnsureLocalCapacity
    add eax, 5
    LEAVE

    .balign 16, 0x90
pop_only:                       # PopLocalFrame(NULL) with no frame
    ENTER
    xor esi, esi
    JNI S_PopLocalFrame
    LEAVE

    .balign 16, 0x90
get_vm:                         # GetJavaVM, then vm->GetEnv(vm, &env2, JNI_VERSION_1_6): env2 == env
    ENTER
    sub rsp, 16
    lea rsi, [rsp]
    JNI S_GetJavaVM
    mov r14d, eax
    mov rdi, qword ptr [rsp]
    lea rsi, [rsp + 8]
    mov edx, 0x10006
    mov rax, qword ptr [rdi]
    call qword ptr [rax + 8*V_GetEnv]
    add r14d, eax
    xor eax, eax
    cmp qword ptr [rsp + 8], rbx
    sete al
    add eax, r14d
    add rsp, 16
    LEAVE

# ---------------------------------------------------------------- the load phase
    .balign 16, 0x90
JNI_OnLoad:                     # (JavaVM* rdi, void*): cache a global reference to class a/B in GVAR
    push rbx
    sub rsp, 16
    lea rsi, [rsp]
    mov edx, 0x10006
    mov rax, qword ptr [rdi]
    call qword ptr [rax + 8*V_GetEnv]
    mov rbx, qword ptr [rsp]
    lea rsi, [rip + class_name]
    JNI S_FindClass
    mov qword ptr [rsp + 8], rax
    mov rsi, rax
    JNI S_NewGlobalRef
    mov qword ptr [rip + start + 0x1E00], rax
    mov rsi, qword ptr [rsp + 8]
    JNI S_DeleteLocalRef
    mov eax, 0x10006
    add rsp, 16
    pop rbx
    ret
class_name:
    .asciz "a/B"

    .balign 16, 0x90
use_loaded:                     # type(GVAR) + 10*same(GVAR, GVAR)
    ENTER
    mov rsi, qword ptr [rip + start + 0x1E00]
    JNI S_GetObjectRefType
    mov r14d, eax
    mov rsi, qword ptr [rip + start + 0x1E00]
    mov rdx, rsi
    JNI S_IsSameObject
    movzx eax, al
    imul eax, eax, 10
    add eax, r14d
    LEAVE

    .balign 16, 0x90
del_loaded:                     # DeleteGlobalRef(GVAR): the next call would find it gone
    ENTER
    mov rsi, qword ptr [rip + start + 0x1E00]
    JNI S_DeleteGlobalRef
    LEAVE

# ---------------------------------------------------------------- denials of the reference model (fix round 1)
    .balign 16, 0x90
weak_return:                    # return NewWeakGlobalRef(s): what the reference holds is the collector's choice
    ENTER
    mov rsi, r12
    JNI S_NewWeakGlobalRef
    LEAVE

    .balign 16, 0x90
push_deep:                      # (JNIEnv*, jclass, jint n >= 1): PushLocalFrame(1) n times, then 9
    ENTER
.Lpush_again:
    mov esi, 1
    JNI S_PushLocalFrame
    dec r12d
    jnz .Lpush_again
    mov eax, 9
    LEAVE

    .balign 16, 0x90
JNI_OnLoad_monitor:             # a JNI_OnLoad that returns holding the monitor of class a/B
    push rbx
    sub rsp, 16
    lea rsi, [rsp]
    mov edx, 0x10006
    mov rax, qword ptr [rdi]
    call qword ptr [rax + 8*V_GetEnv]
    mov rbx, qword ptr [rsp]
    lea rsi, [rip + class_name]
    JNI S_FindClass
    mov rsi, rax
    JNI S_MonitorEnter
    mov eax, 0x10006
    add rsp, 16
    pop rbx
    ret
