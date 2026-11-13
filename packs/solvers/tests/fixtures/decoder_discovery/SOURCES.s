# dd_track_x86_64.s
    .intel_syntax noprefix
    .text
    .globl tk_sink
    .hidden tk_sink
    .type tk_sink,@function
tk_sink:
    lea rax, [rdi + rsi]
    add rax, rdx
    ret
    .size tk_sink, .-tk_sink

    .globl tk_other
    .hidden tk_other
    .type tk_other,@function
tk_other:
    mov eax, 1
    ret
    .size tk_other, .-tk_other

    .globl tk_join
    .type tk_join,@function
tk_join:
    mov edi, 5
    mov edx, 9
    test esi, esi
    je 1f
    mov edi, 7
1:
    mov esi, 3
    call tk_sink
    ret
    .size tk_join, .-tk_join

    .globl tk_clobber
    .type tk_clobber,@function
tk_clobber:
    push rbx
    mov edi, 5
    mov ebx, 0x77
    call tk_other
    mov rsi, rbx
    mov edx, 1
    call tk_sink
    pop rbx
    ret
    .size tk_clobber, .-tk_clobber

    .globl tk_slot
    .type tk_slot,@function
tk_slot:
    sub rsp, 24
    mov dword ptr [rsp + 4], 0x2a
    mov qword ptr [rsp + 8], 0x10
    mov edi, dword ptr [rsp + 4]
    mov rsi, qword ptr [rsp + 8]
    lea rdx, [rsp + 16]
    call tk_sink
    mov edi, dword ptr [rsp + 4]
    mov esi, 2
    mov edx, 3
    call tk_sink
    add rsp, 24
    ret
    .size tk_slot, .-tk_slot

    .globl tk_overlap
    .type tk_overlap,@function
tk_overlap:
    sub rsp, 24
    mov qword ptr [rsp + 8], 0x10
    mov dword ptr [rsp + 12], 5
    mov rdi, qword ptr [rsp + 8]
    mov dword ptr [rsp], 7
    mov qword ptr [rsp + 16], 9
    add dword ptr [rsp + 16], 1
    mov rdx, qword ptr [rsp + 16]
    mov esi, dword ptr [rsp]
    call tk_sink
    add rsp, 24
    ret
    .size tk_overlap, .-tk_overlap

    .globl tk_arith
    .type tk_arith,@function
tk_arith:
    lea rax, [rip + tk_table]
    lea rdi, [rax + 8]
    mov esi, 0x1234
    add rsi, 0x20
    sub rsi, 0x10
    xor edx, edx
    call tk_sink
    mov rdi, qword ptr [rip + tk_global@GOTPCREL]
    mov ecx, 0xffffffff
    mov esi, ecx
    mov edx, 4
    mov dl, 1
    call tk_sink
    ret
    .size tk_arith, .-tk_arith

    .globl tk_tail
    .type tk_tail,@function
tk_tail:
    mov edi, 1
    mov esi, 2
    mov edx, 3
    jmp tk_sink
    .size tk_tail, .-tk_tail

    .globl tk_frame
    .type tk_frame,@function
tk_frame:
    sub rsp, 40
    lea rdi, [rsp + 8]
    sub rsp, 16
    mov esi, 1
    mov edx, 2
    call tk_sink
    add rsp, 56
    ret
    .size tk_frame, .-tk_frame

    .globl tk_wrap
    .type tk_wrap,@function
tk_wrap:
    sub rsp, 8
    mov edx, 1
    call tk_sink
    add rsp, 8
    ret
    .size tk_wrap, .-tk_wrap

    .globl tk_after
    .type tk_after,@function
tk_after:
    sub rsp, 8
    call tk_other
    add rax, rdi
    add rsp, 8
    ret
    .size tk_after, .-tk_after

    .globl tk_env
    .type tk_env,@function
tk_env:
    mov rax, qword ptr fs:[0x28]
    mov eax, 60
    syscall
    ret
    .size tk_env, .-tk_env

    .globl tk_tls
    .type tk_tls,@function
tk_tls:
    mov qword ptr fs:[0x28], 1
    xor eax, eax
    ret
    .size tk_tls, .-tk_tls

    .globl tk_unary_ok
    .type tk_unary_ok,@function
tk_unary_ok:
    mov rax, rdi
    xor rax, 9
    ret
    .size tk_unary_ok, .-tk_unary_ok

    .globl tk_unary_env
    .type tk_unary_env,@function
tk_unary_env:
    mov rax, rdi
    xor rax, 5
    syscall
    ret
    .size tk_unary_env, .-tk_unary_env

    .globl tk_unary_ind
    .type tk_unary_ind,@function
tk_unary_ind:
    sub rsp, 8
    mov rax, rdi
    xor rax, 7
    call rax
    add rsp, 8
    ret
    .size tk_unary_ind, .-tk_unary_ind

    .globl tk_unary_imp
    .type tk_unary_imp,@function
tk_unary_imp:
    sub rsp, 8
    xor rdi, 1
    call puts@PLT
    add rsp, 8
    ret
    .size tk_unary_imp, .-tk_unary_imp

    .globl tk_unary_noret
    .type tk_unary_noret,@function
tk_unary_noret:
    mov rax, rdi
    xor rax, 2
    ud2
    .size tk_unary_noret, .-tk_unary_noret

    .globl tk_unary_trunc
    .type tk_unary_trunc,@function
tk_unary_trunc:
    mov rax, rdi
    xor rax, 3
    ret
    .byte 0x06
    .size tk_unary_trunc, .-tk_unary_trunc

    .globl tk_last
    .type tk_last,@function
tk_last:
    mov edi, 4
    call tk_only
    ret
    .size tk_last, .-tk_last

    .globl tk_only
    .hidden tk_only
    .type tk_only,@function
tk_only:
    lea eax, [rdi + 2]
    ret
    .size tk_only, .-tk_only

# B-166 fix round 1: what a stack buffer holds at the call (vector stores of constants, integer stores)
    .globl tk_vec
    .type tk_vec,@function
tk_vec:
    sub rsp, 56
    movaps xmm0, xmmword ptr [rip + tk_vconst]
    movups xmmword ptr [rsp], xmm0
    pxor xmm1, xmm1
    movups xmmword ptr [rsp + 16], xmm1
    mov byte ptr [rsp + 32], 0x21
    lea rax, [rip + tk_table]
    mov qword ptr [rsp + 40], rax
    mov rdi, rsp
    mov esi, 1
    mov edx, 2
    call tk_sink
    movups xmmword ptr [rsp], xmm0
    mov rdi, rsp
    mov esi, 1
    mov edx, 2
    call tk_sink
    add rsp, 56
    ret
    .size tk_vec, .-tk_vec

    .globl tk_vec_flow
    .type tk_vec_flow,@function
tk_vec_flow:
    sub rsp, 40
    movaps xmm0, xmmword ptr [rip + tk_vconst]
    test esi, esi
    je 1f
1:
    movups xmmword ptr [rsp], xmm0
    mov rdi, rsp
    call tk_sink
    movaps xmm0, xmmword ptr [rip + tk_vconst]
    lea rax, [rip + 2f]
    jmp rax
2:
    movups xmmword ptr [rsp], xmm0
    mov rdi, rsp
    call tk_sink
    add rsp, 40
    ret
    .size tk_vec_flow, .-tk_vec_flow

    .globl tk_vec_clobber
    .type tk_vec_clobber,@function
tk_vec_clobber:
    sub rsp, 40
    movaps xmm0, xmmword ptr [rip + tk_vconst]
    paddb xmm0, xmm0
    movups xmmword ptr [rsp], xmm0
    movaps xmm1, xmmword ptr [rip + tk_vconst]
    movaps xmm1, xmmword ptr [rip + tk_vdata]
    movups xmmword ptr [rsp + 16], xmm1
    movups xmm2, xmmword ptr [rsp + 32]
    movups xmmword ptr [rsp + 32], xmm2
    mov rdi, rsp
    call tk_sink
    add rsp, 40
    ret
    .size tk_vec_clobber, .-tk_vec_clobber

    .globl tk_vec_far
    .type tk_vec_far,@function
tk_vec_far:
    sub rsp, 0x1100
    mov byte ptr [rsp], 1
    mov dword ptr [rsp + 0xff8], 7
    mov qword ptr [rsp + 0xffc], 5
    mov rdi, rsp
    call tk_sink
    mov dword ptr [rsp + 8], 1
    lea rdi, [rbp - 0x20]
    call tk_sink
    add rsp, 0x1100
    ret
    .size tk_vec_far, .-tk_vec_far

# functions that print and show exactly one kind of decoder structure (a loop, byte access, indexed access)
    .globl tk_pr_loop
    .type tk_pr_loop,@function
tk_pr_loop:
    mov ecx, 3
1:
    dec ecx
    jne 1b
    jmp puts@PLT
    .size tk_pr_loop, .-tk_pr_loop

    .globl tk_pr_byte
    .type tk_pr_byte,@function
tk_pr_byte:
    movzx eax, byte ptr [rsi]
    jmp puts@PLT
    .size tk_pr_byte, .-tk_pr_byte

    .globl tk_pr_table
    .type tk_pr_table,@function
tk_pr_table:
    mov eax, dword ptr [rsi + rdx*4]
    jmp puts@PLT
    .size tk_pr_table, .-tk_pr_table

    .globl tk_pr_none
    .type tk_pr_none,@function
tk_pr_none:
    mov eax, esi
    jmp puts@PLT
    .size tk_pr_none, .-tk_pr_none

    .section .rodata
    .p2align 4
tk_vconst:
    .ascii "sixteen byte str"
    .p2align 3
tk_table:
    .quad 1, 2, 3, 4

    .data
    .globl tk_global
    .p2align 3
    .type tk_global,@object
tk_global:
    .quad 0x1122334455667788
    .size tk_global, 8
    .p2align 4
tk_vdata:
    .ascii "writable, not k!"

# dd_track_arm64.s
    .text
    .globl tk_sink
    .hidden tk_sink
    .type tk_sink,%function
tk_sink:
    add x0, x0, x1
    add x0, x0, x2
    ret
    .size tk_sink, .-tk_sink

    .globl tk_other
    .hidden tk_other
    .type tk_other,%function
tk_other:
    mov w0, #1
    ret
    .size tk_other, .-tk_other

    .globl tk_movk
    .type tk_movk,%function
tk_movk:
    stp x29, x30, [sp, #-16]!
    mov x0, #0x5678
    movk x0, #0x1234, lsl #16
    movk x0, #0x9abc, lsl #32
    adrp x1, tk_table
    add x1, x1, :lo12:tk_table
    add x1, x1, #8
    mov x2, #0xffff
    movk x2, #0x7
    bl tk_sink
    ldp x29, x30, [sp], #16
    ret
    .size tk_movk, .-tk_movk

    .globl tk_movk_arg
    .type tk_movk_arg,%function
tk_movk_arg:
    movk x0, #0x12, lsl #16
    ret
    .size tk_movk_arg, .-tk_movk_arg

    .globl tk_join
    .type tk_join,%function
tk_join:
    stp x29, x30, [sp, #-16]!
    mov w0, #5
    mov w2, #9
    cbz x1, 1f
    mov w0, #7
1:
    mov w1, #3
    bl tk_sink
    ldp x29, x30, [sp], #16
    ret
    .size tk_join, .-tk_join

    .globl tk_clobber
    .type tk_clobber,%function
tk_clobber:
    stp x29, x30, [sp, #-32]!
    str x19, [sp, #16]
    mov w0, #5
    mov w19, #0x77
    bl tk_other
    mov x1, x19
    mov w2, #1
    bl tk_sink
    ldr x19, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
    .size tk_clobber, .-tk_clobber

    .globl tk_stack
    .type tk_stack,%function
tk_stack:
    sub sp, sp, #48
    str x30, [sp, #40]
    add x0, sp, #8
    mov w1, #1
    mov w2, #2
    bl tk_sink
    add x0, sp, #8
    sub sp, sp, #16
    mov w1, #1
    mov w2, #2
    bl tk_sink
    add sp, sp, #16
    ldr x30, [sp, #40]
    add sp, sp, #48
    ret
    .size tk_stack, .-tk_stack

    .globl tk_tail
    .type tk_tail,%function
tk_tail:
    mov w0, #1
    mov w1, #2
    mov w2, #3
    b tk_sink
    .size tk_tail, .-tk_tail

    .globl tk_wrap
    .type tk_wrap,%function
tk_wrap:
    mov w2, #1
    b tk_sink
    .size tk_wrap, .-tk_wrap

    .globl tk_after
    .type tk_after,%function
tk_after:
    stp x29, x30, [sp, #-16]!
    bl tk_other
    add x0, x0, x1
    ldp x29, x30, [sp], #16
    ret
    .size tk_after, .-tk_after

    .globl tk_env
    .type tk_env,%function
tk_env:
    mov x8, #93
    svc #0
    ret
    .size tk_env, .-tk_env

    .globl tk_sub
    .type tk_sub,%function
tk_sub:
    stp x29, x30, [sp, #-16]!
    mov x0, #0x40
    sub x0, x0, #0x10
    adrp x1, tk_table
    add x1, x1, :lo12:tk_table
    add x1, x1, #24
    sub x1, x1, #8
    mov w2, #0
    bl tk_sink
    ldp x29, x30, [sp], #16
    ret
    .size tk_sub, .-tk_sub

    .section .rodata
    .p2align 3
tk_table:
    .quad 1, 2, 3, 4

# dd_gap_x86_64.s
    .intel_syntax noprefix
    .text
    .globl gp_main
    .type gp_main,@function
gp_main:
    push rbx
    mov edi, 1
    call gp_fwd
    call gp_table
    call gp_odd
    call gp_tail
    call gp_after
    pop rbx
    ret
    .size gp_main, .-gp_main

    .p2align 4
    .hidden gp_fwd
    .type gp_fwd,@function
gp_fwd:
    test edi, edi
    jne 2f
    mov eax, 1
    ret
    .p2align 4
2:
    lea eax, [rdi + 5]
    ret
    .size gp_fwd, .-gp_fwd

    .p2align 4
    .hidden gp_table
    .type gp_table,@function
gp_table:
    lea rax, [rip + 3f]
    jmp rax
    ret
    .p2align 4
3:
    mov eax, 7
    ret
    .size gp_table, .-gp_table

    .p2align 4
    .hidden gp_odd
    .type gp_odd,@function
gp_odd:
    mov eax, 2
    ret
    mov eax, 3
    ret
    .size gp_odd, .-gp_odd

    .p2align 4
    .hidden gp_tail
    .type gp_tail,@function
gp_tail:
    mov edi, 1
    jmp gp_after
    .size gp_tail, .-gp_tail

    .p2align 4
    .hidden gp_lone
    .type gp_lone,@function
gp_lone:
    lea eax, [rdi + rdi*2]
    xor eax, 0x55
    ret
    .size gp_lone, .-gp_lone

    .p2align 4
    .hidden gp_lone2
    .type gp_lone2,@function
gp_lone2:
    mov eax, 9
    ret
    .size gp_lone2, .-gp_lone2

    .p2align 4
    .hidden gp_after
    .type gp_after,@function
gp_after:
    lea eax, [rdi + 1]
    ret
    .size gp_after, .-gp_after

# dd_gap_arm64.s
    .text
    .globl gp_main
    .type gp_main,%function
gp_main:
    stp x29, x30, [sp, #-16]!
    mov w0, #1
    bl gp_fwd
    bl gp_table
    bl gp_tail
    bl gp_after
    ldp x29, x30, [sp], #16
    ret
    .size gp_main, .-gp_main

    .hidden gp_fwd
    .type gp_fwd,%function
gp_fwd:
    cbnz w0, 2f
    mov w0, #1
    ret
2:
    add w0, w0, #5
    ret
    .size gp_fwd, .-gp_fwd

    .hidden gp_table
    .type gp_table,%function
gp_table:
    adr x1, 3f
    br x1
    ret
3:
    mov w0, #7
    ret
    .size gp_table, .-gp_table

    .hidden gp_tail
    .type gp_tail,%function
gp_tail:
    mov w0, #1
    b gp_after
    .size gp_tail, .-gp_tail

    .hidden gp_lone
    .type gp_lone,%function
gp_lone:
    add w0, w0, w0, lsl #1
    eor w0, w0, #0xf0
    ret
    .size gp_lone, .-gp_lone

    .p2align 4
    .hidden gp_lone2
    .type gp_lone2,%function
gp_lone2:
    mov w0, #9
    ret
    .size gp_lone2, .-gp_lone2

    .hidden gp_after
    .type gp_after,%function
gp_after:
    add w0, w0, #1
    ret
    .size gp_after, .-gp_after

